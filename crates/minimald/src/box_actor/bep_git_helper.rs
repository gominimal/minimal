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
//! The helper must be git's sole helper for those hosts, so a `store` or
//! `cache` helper that the box configures never gets the sealed value. git
//! reads its command-scope configuration (`GIT_CONFIG_COUNT`) after every
//! configuration file. So the launch puts the entries of
//! [`launch_git_config_env`] in the box environment: for each host, an
//! empty `helper` that clears the list, and then the shipped helper. No git
//! configuration file in the box is touched. The daemon rewrites the helper
//! on every start of the box. A start without a usable grant removes it.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// The minimal-owned directory under the box's home that holds the helper,
/// its configuration and its log. The same directory holds the per-attach
/// environment files.
pub(crate) const HELPER_DIR_REL: &str = ".local/state/minimal";

/// The helper script, relative to the box's home.
pub(crate) const HELPER_REL: &str = ".local/state/minimal/git-credential-minimal";

/// A copy of the configuration that names the helper, relative to the
/// box's home. git does not read it: the launch sets the same entries in
/// the box environment. It is there for a person in the box to read.
pub(crate) const HELPER_CONFIG_REL: &str = ".local/state/minimal/git-credential.gitconfig";

/// The helper's log, relative to the box's home: one line per answer,
/// naming the host and never the value.
pub(crate) const HELPER_LOG_REL: &str = ".local/state/minimal/git-credential.log";

/// The hosts the helper answers for: the GitHub module's host set
/// (`bep::module::GITHUB`), each authority as git names it in a URL. The
/// port is left out when it is the HTTPS port. The proxy admits a sealed
/// value only for these authorities, so the helper answers for no other.
pub(crate) fn grant_hosts() -> Vec<String> {
    bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| {
            if authority.port == bep::module::HTTPS_PORT {
                authority.host.to_string()
            } else {
                format!("{}:{}", authority.host, authority.port)
            }
        })
        .collect()
}

/// The git configuration entries that make the shipped helper git's sole
/// helper for each grant host: an empty `helper`, which clears the helpers
/// that git read before it, and then the shipped helper.
fn helper_entries() -> Vec<(String, String)> {
    grant_hosts()
        .into_iter()
        .flat_map(|host| {
            let key = format!("credential.https://{host}.helper");
            [
                (key.clone(), String::new()),
                (key, format!("!\"$HOME/{HELPER_REL}\"")),
            ]
        })
        .collect()
}

/// The command-scope git configuration a launch puts in the environment of
/// the box with home `home` (BEP-015): `GIT_CONFIG_COUNT` and a
/// `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>` pair for each entry of
/// [`helper_entries`]. The pairs start at index `first`, so the entries that
/// the box environment already holds stay in front of them. Empty when the
/// box home holds no helper that [`install`] wrote, so a box without a
/// usable grant keeps its own helpers.
pub(crate) fn launch_git_config_env(home: &Path, first: usize) -> Vec<(String, String)> {
    if !is_installed(home) {
        return Vec::new();
    }
    let entries = helper_entries();
    let mut env = Vec::with_capacity(entries.len() * 2 + 1);
    for (offset, (key, value)) in entries.into_iter().enumerate() {
        let index = first + offset;
        env.push((format!("GIT_CONFIG_KEY_{index}"), key));
        env.push((format!("GIT_CONFIG_VALUE_{index}"), value));
    }
    let count = first + env.len() / 2;
    env.push(("GIT_CONFIG_COUNT".to_string(), count.to_string()));
    tracing::debug!(
        hosts = ?grant_hosts(),
        "set the git credential helper as the sole helper for the grant hosts"
    );
    env
}

/// Whether the box home `home` holds the helper as a regular file, under
/// directories that are not symbolic links.
fn is_installed(home: &Path) -> bool {
    let Ok(Some(dir)) = real_dir(home, HELPER_DIR_REL, false) else {
        return false;
    };
    std::fs::symlink_metadata(dir.join(file_name(HELPER_REL)))
        .is_ok_and(|meta| meta.file_type().is_file())
}

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

/// Writes the git credential helper and a readable copy of its
/// `credential.helper` entries into the box home `home`, when the box holds
/// a GitHub grant. [`launch_git_config_env`] gives git those entries. The first
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
    tracing::debug!(
        variable = %delivery.variable,
        hosts = ?grant_hosts(),
        "wrote the git credential helper for the GitHub grant"
    );
    Ok(Installed::Written)
}

/// Removes the helper and its configuration that an earlier start wrote, so
/// a box that holds no usable grant has no helper that answers.
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
    let hosts = bep::module::GITHUB
        .hosts
        .iter()
        .flat_map(|authority| {
            let with_port = format!("{}:{}", authority.host, authority.port);
            if authority.port == bep::module::HTTPS_PORT {
                vec![authority.host.to_string(), with_port]
            } else {
                vec![with_port]
            }
        })
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

/// The readable copy of [`helper_entries`], in git configuration syntax.
fn helper_config() -> String {
    let mut config = String::from(
        "# Written by minimald for this box's GitHub grant. Edits are lost.\n\
         # git reads these entries from GIT_CONFIG_COUNT in the box environment, not from this file.\n",
    );
    for (key, value) in helper_entries() {
        let (section, name) = key
            .strip_prefix("credential.")
            .and_then(|rest| rest.rsplit_once('.'))
            .unwrap_or(("", "helper"));
        let value = value.replace('\\', "\\\\").replace('"', "\\\"");
        config.push_str(&format!(
            "[credential \"{section}\"]\n\t{name} = \"{value}\"\n"
        ));
    }
    config
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
