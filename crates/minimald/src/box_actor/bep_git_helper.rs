//! The git credential helper a GitHub grant box carries (BEP-015, Gatehouse
//! §6.4).
//!
//! git sends an `Authorization` header only when a credential helper gives
//! it a credential. A grant box holds no credential, only a sealed value
//! that the Box Egress Proxy substitutes. So the daemon writes a helper into
//! the box's home that answers with the sealed value as the password, for
//! the GitHub module's hosts only. git then sends `Basic` with the sealed
//! value in it, and the proxy puts the credential in its place
//! (`bep::forward::substitute`).
//!
//! The helper's configuration goes in a file of its own, which the box's
//! XDG git configuration includes. The daemon rewrites that file on every
//! start of the box, and adds the include line once. The box's own
//! `~/.gitconfig` is never touched, so a composition that ships one keeps
//! it.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// The minimal-owned directory under the box's home that holds the helper,
/// its configuration and its log. The same directory holds the per-attach
/// environment files.
pub(crate) const HELPER_DIR_REL: &str = ".local/state/minimal";

/// The helper script, relative to the box's home.
pub(crate) const HELPER_REL: &str = ".local/state/minimal/git-credential-minimal";

/// The git configuration that names the helper, relative to the box's home.
pub(crate) const HELPER_CONFIG_REL: &str = ".local/state/minimal/git-credential.gitconfig";

/// The helper's log, relative to the box's home: one line per answer,
/// naming the host and never the value.
pub(crate) const HELPER_LOG_REL: &str = ".local/state/minimal/git-credential.log";

/// The box's XDG git configuration, relative to its home. git reads it
/// beside `~/.gitconfig`.
pub(crate) const XDG_GIT_CONFIG_REL: &str = ".config/git/config";

/// The include line [`install`] adds to the XDG git configuration.
const INCLUDE_LINE: &str = "\tpath = ~/.local/state/minimal/git-credential.gitconfig";

/// The GitHub module's v1 host set, as `bep::module::GITHUB` holds it. The
/// daemon does not link the `bep` crate, so the hosts are repeated here.
/// The proxy admits a sealed value only for these hosts, so the helper
/// answers for no other.
pub(crate) const GRANT_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "uploads.github.com",
    "codeload.github.com",
];

/// What [`install`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Installed {
    /// The box has no GitHub grant, so it gets no helper.
    NoGrant,
    /// The sealed value holds a character a shell or git can read as code,
    /// so no helper is written.
    Refused,
    /// The helper and its configuration are in the box's home.
    Written,
}

/// Writes the git credential helper and its `credential.helper` lines into
/// the box home `home`, when the box holds a GitHub grant. The first
/// delivery's sealed value is the placeholder the helper answers with.
/// Every delivery is a GitHub grant, so any one of them is redeemed the
/// same way at the proxy.
///
/// # Errors
///
/// An I/O error from a write. The caller logs it: a box without the helper
/// still starts.
pub(crate) fn install(
    home: &Path,
    deliveries: &[boxes::SealedDelivery],
) -> std::io::Result<Installed> {
    let Some(delivery) = deliveries.first() else {
        return Ok(Installed::NoGrant);
    };
    if !is_inert(&delivery.sealed) {
        tracing::warn!(
            variable = %delivery.variable,
            "the sealed value holds characters outside its printed form; no git credential helper is written"
        );
        return Ok(Installed::Refused);
    }
    let dir = home.join(HELPER_DIR_REL);
    std::fs::create_dir_all(&dir)?;

    // The helper holds the sealed value, so only the box's user reads it.
    write_atomically(
        &home.join(HELPER_REL),
        helper_script(&delivery.sealed).as_bytes(),
        0o700,
    )?;
    write_atomically(
        &home.join(HELPER_CONFIG_REL),
        helper_config().as_bytes(),
        0o644,
    )?;
    include_helper_config(&home.join(XDG_GIT_CONFIG_REL))?;
    tracing::debug!(
        variable = %delivery.variable,
        hosts = ?GRANT_HOSTS,
        "wrote the git credential helper for the GitHub grant"
    );
    Ok(Installed::Written)
}

/// Whether `sealed` holds only the characters of a sealed value's printed
/// form (base64url segments and dots), so it is inert in the helper's
/// shell text.
fn is_inert(sealed: &str) -> bool {
    !sealed.is_empty()
        && sealed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The helper: a POSIX shell script that answers git's `get` for an
/// `https` request to a grant host, and stays silent for anything else, so
/// git asks its next helper or gives up.
fn helper_script(sealed: &str) -> String {
    let hosts = GRANT_HOSTS
        .iter()
        .flat_map(|host| [host.to_string(), format!("{host}:443")])
        .collect::<Vec<_>>()
        .join("|");
    format!(
        r#"#!/bin/sh
# Written by minimald for this box's GitHub grant. Edits are lost.
# It answers git with the box's sealed value, which the Box Egress Proxy
# replaces with the credential. The value is not a credential anywhere else.
[ "$1" = get ] || exit 0
protocol=
host=
while IFS= read -r line; do
  [ -z "$line" ] && break
  case "$line" in
    protocol=*) protocol=${{line#protocol=}} ;;
    host=*) host=${{line#host=}} ;;
  esac
done
[ "$protocol" = https ] || exit 0
case "$host" in
  {hosts}) ;;
  *) exit 0 ;;
esac
printf 'username=x-access-token\npassword=%s\n' '{sealed}'
printf '%s git-credential-minimal answered for host %s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$host" \
  >>"$HOME/{HELPER_LOG_REL}" 2>/dev/null
exit 0
"#
    )
}

/// The configuration that names the helper, one section per grant host,
/// so git asks the helper for those hosts only.
fn helper_config() -> String {
    let mut config =
        String::from("# Written by minimald for this box's GitHub grant. Edits are lost.\n");
    for host in GRANT_HOSTS {
        config.push_str(&format!(
            "[credential \"https://{host}\"]\n\thelper = \"!\\\"$HOME/{HELPER_REL}\\\"\"\n"
        ));
    }
    config
}

/// Adds the include of the helper's configuration to the git configuration
/// at `path`, once. Lines already in the file stay as they are.
fn include_helper_config(path: &Path) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    if existing.lines().any(|line| line == INCLUDE_LINE) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)?;
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    write!(file, "{separator}[include]\n{INCLUDE_LINE}\n")
}

/// Writes `body` to a sibling of `path` with mode `mode`, and renames it
/// over `path`, so a git that runs during a restart never reads half a
/// helper.
fn write_atomically(path: &Path, body: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(body)?;
        // The mode on `open` applies only to a new file, and the umask
        // narrows it. Set it outright.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}
