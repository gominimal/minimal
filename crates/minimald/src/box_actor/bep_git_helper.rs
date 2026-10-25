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
//! start of the box, and adds the include line once. A start without a
//! usable grant removes the helper and that file. The box's own
//! `~/.gitconfig` is never touched, so a composition that ships one keeps
//! it.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

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
    /// The box has no GitHub grant, so it gets no helper. A helper from an
    /// earlier start is removed.
    NoGrant,
    /// The sealed value holds a character a shell or git can read as code,
    /// so no helper is written. A helper from an earlier start is removed.
    Refused,
    /// The helper and its configuration are in the box's home.
    Written,
}

/// Writes the git credential helper and its `credential.helper` lines into
/// the box home `home`, when the box holds a GitHub grant. The first
/// delivery's sealed value is the placeholder the helper answers with.
/// The client builds a delivery only from a GitHub grant
/// (`sealed_deliveries` in `min box create`), so any one of them is
/// redeemed the same way at the proxy.
///
/// The box's user can write its home, so every directory and file under it
/// that this function writes must not be a symbolic link. A symbolic link
/// there is refused with an error, and nothing is written through it.
///
/// # Errors
///
/// An I/O error from a write, or a symbolic link on a path it writes. The
/// caller logs it: a box without the helper still starts.
pub(crate) fn install(
    home: &Path,
    deliveries: &[boxes::SealedDelivery],
) -> std::io::Result<Installed> {
    let Some(delivery) = deliveries.first() else {
        remove_helper(home)?;
        return Ok(Installed::NoGrant);
    };
    if !is_inert(&delivery.sealed) {
        tracing::warn!(
            variable = %delivery.variable,
            "the sealed value holds characters outside its printed form; no git credential helper is written"
        );
        remove_helper(home)?;
        return Ok(Installed::Refused);
    }
    let dir = made_dir(home, HELPER_DIR_REL)?;

    // The helper holds the sealed value, so only the box's user reads it.
    write_atomically(
        &dir,
        file_name(HELPER_REL),
        helper_script(&delivery.sealed).as_bytes(),
        0o700,
    )?;
    write_atomically(
        &dir,
        file_name(HELPER_CONFIG_REL),
        helper_config().as_bytes(),
        0o644,
    )?;
    let xdg_dir = made_dir(home, parent_rel(XDG_GIT_CONFIG_REL))?;
    include_helper_config(&xdg_dir.join(file_name(XDG_GIT_CONFIG_REL)))?;
    tracing::debug!(
        variable = %delivery.variable,
        hosts = ?GRANT_HOSTS,
        "wrote the git credential helper for the GitHub grant"
    );
    Ok(Installed::Written)
}

/// Removes the helper and its configuration that an earlier start wrote, so
/// a box that holds no usable grant has no helper that answers. The include
/// line stays: git ignores an include of a file that does not exist.
fn remove_helper(home: &Path) -> std::io::Result<()> {
    let Some(dir) = real_dir(home, HELPER_DIR_REL, false)? else {
        return Ok(());
    };
    for rel in [HELPER_REL, HELPER_CONFIG_REL] {
        match std::fs::remove_file(dir.join(file_name(rel))) {
            Ok(()) => tracing::debug!(file = rel, "removed a git credential helper file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// The last component of the home-relative path `rel`.
fn file_name(rel: &str) -> &str {
    rel.rsplit_once('/').map_or(rel, |(_, name)| name)
}

/// The home-relative path `rel` without its last component.
fn parent_rel(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// [`real_dir`] with `create`: the directory `home/rel`, made when absent.
fn made_dir(home: &Path, rel: &str) -> std::io::Result<PathBuf> {
    real_dir(home, rel, true)?
        .ok_or_else(|| std::io::Error::other(format!("{rel} was not created under the box home")))
}

/// The directory `home/rel`, after a check of each component under `home`:
/// each must be a directory and not a symbolic link. With `create`, a
/// component that does not exist is made. Without it, a component that does
/// not exist gives `None`.
fn real_dir(home: &Path, rel: &str, create: bool) -> std::io::Result<Option<PathBuf>> {
    let mut path = home.to_path_buf();
    for component in rel.split('/').filter(|component| !component.is_empty()) {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::other(format!(
                    "{} is a symbolic link",
                    path.display()
                )));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "{} is not a directory",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    Ok(Some(path))
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
/// at `path`, once. Lines already in the file stay as they are. The open
/// does not follow a symbolic link, and a file that is not a regular file
/// is refused.
fn include_helper_config(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut existing = String::new();
    file.read_to_string(&mut existing)?;
    if existing.lines().any(|line| line == INCLUDE_LINE) {
        return Ok(());
    }
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    write!(file, "{separator}[include]\n{INCLUDE_LINE}\n")
}

/// Writes `body` to a new file in `dir` with mode `mode`, and renames it
/// over `dir/name`, so a git that runs during a restart never reads half a
/// helper. The new file is made with `O_EXCL` and `O_NOFOLLOW`, so a file
/// or symbolic link that the box put at its name is not written through.
/// The rename replaces `dir/name` itself, also when it is a symbolic link.
fn write_atomically(dir: &Path, name: &str, body: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    // A file left at the name by an earlier run, or put there by the box.
    // `remove_file` removes a symbolic link, never its target.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(body)?;
        // The mode on `open` is narrowed by the umask. Set it outright.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, dir.join(name))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}
