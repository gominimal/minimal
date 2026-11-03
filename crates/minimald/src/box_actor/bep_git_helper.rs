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
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

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

/// The size in bytes above which the helper moves its log to
/// `git-credential.log.1`, over any older copy, before it appends. The two
/// files together stay near twice this size.
pub(crate) const HELPER_LOG_MAX_BYTES: u64 = 64 * 1024;

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
/// the box environment already holds stay in front of them. `sealed` is the
/// sealed values this launch places in the box environment. Empty when the
/// box home holds no helper that answers with one of them, so a box without
/// a usable grant keeps its own helpers. A helper that an earlier start
/// wrote, and that this start did not replace or remove, does not count.
pub(crate) fn launch_git_config_env<'a>(
    home: &Path,
    first: usize,
    sealed: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, String)> {
    if !holds_current_helper(home, sealed) {
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

/// The largest helper file that [`holds_current_helper`] reads.
const HELPER_READ_MAX_BYTES: u64 = 64 * 1024;

/// Whether the box home `home` holds, as a regular file under directories
/// that are not symbolic links, the helper that [`install`] writes for one
/// of the sealed values `sealed`.
fn holds_current_helper<'a>(home: &Path, sealed: impl IntoIterator<Item = &'a str>) -> bool {
    let Ok(Some(dir)) = real_dir(home, HELPER_DIR_REL, false) else {
        return false;
    };
    let Ok(body) = dir.read_file(file_name(HELPER_REL), HELPER_READ_MAX_BYTES) else {
        return false;
    };
    sealed
        .into_iter()
        .any(|value| is_inert(value) && body == helper_script(value).as_bytes())
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
/// An I/O error from a write, or a symbolic link on a path it writes. A
/// helper from an earlier start is then removed, so git sends no credential
/// for the grant hosts. The caller logs the error: the box still starts.
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
    if let Err(error) = write_helper(home, &delivery.sealed) {
        // Fail closed: a helper from an earlier start holds a value this
        // start did not confirm, so it must not answer. When the directory
        // is refused, [`launch_git_config_env`] does not find the helper.
        if let Err(remove_error) = remove_helper(home) {
            tracing::warn!(%remove_error, "removing the git credential helper after a failed write");
        }
        return Err(error);
    }
    tracing::debug!(
        variable = %delivery.variable,
        hosts = ?grant_hosts(),
        "wrote the git credential helper for the GitHub grant"
    );
    Ok(Installed::Written)
}

/// Writes the helper with the sealed value `sealed`, and its readable
/// configuration, into the box home `home`.
fn write_helper(home: &Path, sealed: &str) -> std::io::Result<()> {
    let dir = made_dir(home, HELPER_DIR_REL)?;
    // The helper holds the sealed value, so only the box's user reads it.
    dir.write_atomically(
        file_name(HELPER_REL),
        helper_script(sealed).as_bytes(),
        0o700,
    )?;
    dir.write_atomically(
        file_name(HELPER_CONFIG_REL),
        helper_config().as_bytes(),
        0o644,
    )
}

/// Removes the helper and its configuration that an earlier start wrote, so
/// a box that holds no usable grant has no helper that answers.
fn remove_helper(home: &Path) -> std::io::Result<()> {
    let Some(dir) = real_dir(home, HELPER_DIR_REL, false)? else {
        return Ok(());
    };
    for rel in [HELPER_REL, HELPER_CONFIG_REL] {
        match dir.unlink(file_name(rel)) {
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
fn made_dir(home: &Path, rel: &str) -> std::io::Result<DirFd> {
    real_dir(home, rel, true)?
        .ok_or_else(|| std::io::Error::other(format!("{rel} was not created under the box home")))
}

/// The directory `home/rel`, open, after a walk of each component under
/// `home`. Each component is opened relative to the one before it with
/// `O_NOFOLLOW`, so it must be a directory and not a symbolic link, and a
/// swap of a component after the walk does not move the open directory.
/// With `create`, a component that does not exist is made. Without it, a
/// component that does not exist gives `None`.
fn real_dir(home: &Path, rel: &str, create: bool) -> std::io::Result<Option<DirFd>> {
    // The home's own path is the daemon's, so it can hold a symbolic link.
    let mut dir = DirFd::open_home(home)?;
    let mut path = home.to_path_buf();
    for component in rel.split('/').filter(|component| !component.is_empty()) {
        path.push(component);
        let next = match dir.open_child(component) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                match dir.mkdir(component) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                dir.open_child(component)
            }
            next => next,
        };
        dir = match next {
            Ok(next) => next,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(std::io::Error::other(format!(
                    "{} is a symbolic link",
                    path.display()
                )));
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                return Err(std::io::Error::other(format!(
                    "{} is not a directory",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
    }
    Ok(Some(dir))
}

/// An open directory. Every file operation in it is relative to the open
/// directory, never to a path, so a symbolic link that the box puts on the
/// path after the open is not followed.
struct DirFd(std::os::fd::OwnedFd);

/// `name` as a C string. A name with a NUL byte is an error.
fn c_name(name: &str) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(name).map_err(std::io::Error::other)
}

/// The result of a libc call that returns `-1` on error.
fn check(ret: libc::c_int) -> std::io::Result<libc::c_int> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

impl DirFd {
    /// Opens the box home `home`.
    fn open_home(home: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(home)?;
        Ok(Self(file.into()))
    }

    /// Opens the directory `name` in this directory. A symbolic link gives
    /// `ELOOP`, and a file that is not a directory gives `ENOTDIR`.
    fn open_child(&self, name: &str) -> std::io::Result<Self> {
        let name = c_name(name)?;
        // SAFETY: `self.0` is an open descriptor and `name` is a valid C
        // string. A returned descriptor is new and owned by nobody else.
        let fd = check(unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: `fd` is the new descriptor from `openat` above.
        Ok(Self(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }))
    }

    /// Makes the directory `name` in this directory.
    fn mkdir(&self, name: &str) -> std::io::Result<()> {
        let name = c_name(name)?;
        // SAFETY: `self.0` is an open descriptor and `name` is a valid C string.
        check(unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o755) })?;
        Ok(())
    }

    /// Removes the entry `name`, which is not a directory, from this
    /// directory. A symbolic link is removed, never its target.
    fn unlink(&self, name: &str) -> std::io::Result<()> {
        let name = c_name(name)?;
        // SAFETY: `self.0` is an open descriptor and `name` is a valid C string.
        check(unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) })?;
        Ok(())
    }

    /// Reads at most `max` bytes of the regular file `name` in this
    /// directory. A symbolic link gives `ELOOP`. Anything that is not a
    /// regular file gives an error, and a FIFO does not block the open.
    fn read_file(&self, name: &str, max: u64) -> std::io::Result<Vec<u8>> {
        use std::io::Read as _;
        let name = c_name(name)?;
        // SAFETY: `self.0` is an open descriptor and `name` is a valid C
        // string. A returned descriptor is new and owned by nobody else.
        let fd = check(unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        })?;
        // SAFETY: `fd` is the new descriptor from `openat` above.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        let mut body = Vec::new();
        file.take(max).read_to_end(&mut body)?;
        Ok(body)
    }

    /// Writes `body` to a new file in this directory with mode `mode`, and
    /// renames it over `name`, so a git that runs during a restart never
    /// reads half a helper. The new file is made with `O_EXCL` and
    /// `O_NOFOLLOW`, so a file or symbolic link that the box put at its
    /// name is not written through. The rename replaces `name` itself, also
    /// when it is a symbolic link.
    fn write_atomically(&self, name: &str, body: &[u8], mode: u32) -> std::io::Result<()> {
        let tmp = format!(".{name}.{}.tmp", std::process::id());
        // A file left at the name by an earlier run, or put there by the box.
        match self.unlink(&tmp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let tmp_c = c_name(&tmp)?;
        let name_c = c_name(name)?;
        let written = (|| {
            // SAFETY: `self.0` is an open descriptor and `tmp_c` is a valid
            // C string. A returned descriptor is new and owned by nobody else.
            let fd = check(unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    tmp_c.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    libc::c_uint::from(mode as libc::mode_t),
                )
            })?;
            // SAFETY: `fd` is the new descriptor from `openat` above.
            let mut file = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
            file.write_all(body)?;
            // The mode on `openat` is narrowed by the umask. Set it outright.
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            // SAFETY: `self.0` is an open descriptor and both names are
            // valid C strings.
            check(unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    tmp_c.as_ptr(),
                    self.0.as_raw_fd(),
                    name_c.as_ptr(),
                )
            })?;
            Ok(())
        })();
        if written.is_err() {
            let _ = self.unlink(&tmp);
        }
        written
    }
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
log="$HOME/{HELPER_LOG_REL}"
if [ -f "$log" ] && [ "$(wc -c <"$log" 2>/dev/null || echo 0)" -gt {HELPER_LOG_MAX_BYTES} ]; then
  mv -f "$log" "$log.1" 2>/dev/null
fi
printf '%s git-credential-minimal answered for host %s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$host" \
  >>"$log" 2>/dev/null
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
