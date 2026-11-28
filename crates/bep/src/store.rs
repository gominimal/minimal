//! Secrets that `min secret` stores in the host's native store, by
//! identifier (BEP-050 to BEP-053).
//!
//! The native store is the macOS Keychain. Each secret is one generic
//! password item under [`SERVICE`], with the identifier as its account. The
//! item's access control names one trusted application: the proxy binary.
//! So the proxy reads the item without a prompt, and every other application,
//! `security` included, prompts (BEP-051).
//!
//! The proxy program creates each item itself, through `bep store-add`. A
//! login-keychain item also carries a partition, which comes from the program
//! that created it, and a reader must pass the partition as well as the
//! application list. An item that `/usr/bin/security` creates is in the
//! `apple-tool:` partition, so the proxy gets `errSecAuthFailed` although the
//! list names it.
//!
//! On Linux the native store is Secret Service, the store that already
//! holds the GitHub sign-in there. Each secret is one item with two
//! attributes: `service`, which is [`SERVICE`], and `id`, which is the
//! identifier. Its value is bytes of any kind. Secret Service has no access control per program, so every
//! program of the user reads an unlocked item, the proxy included. A store
//! reference still names the store [`NATIVE_STORE`], so one project file names
//! the same store on both hosts.
//!
//! Other hosts have no native store. [`HostStore`] there refuses every
//! operation, and says so.
//!
//! The proxy reads a value through [`ValueReader`], once for each request
//! that injects it, and keeps no copy (BEP-033). So a replaced value goes in
//! the next request (BEP-054), and a deleted or disabled item refuses it
//! (BEP-045).
//!
//! No function here writes a value to a file or to a log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

/// The keychain service of every item `min secret` stores.
pub const SERVICE: &str = "dev.minimal.secret";

/// The name of the host's native store, as `--store` and a store reference
/// write it.
pub const NATIVE_STORE: &str = "keychain";

/// The environment variable that names the proxy binary. The VM host daemon
/// reads the same variable to find the proxy it starts.
pub const PROXY_BIN_ENV: &str = "MINVMD_BEP_BIN";

/// The longest identifier a secret can have.
pub const MAX_ID_LEN: usize = 128;

/// The keychain service that holds the new value while `set` replaces an
/// item. The proxy reads no item under it, and a listing shows none.
pub const STAGING_SERVICE: &str = "dev.minimal.secret.staging";

/// The proxy binary: the path in [`PROXY_BIN_ENV`] when it is set and not
/// empty, else `bep` beside `minvmd`. `None` when the variable is unset or
/// empty and `minvmd` gives no path.
///
/// This is the one definition of the rule. `minvmd` starts the proxy from
/// it (`resolve_bep_binary` in `crates/minvmd/src/cmd/run.rs`), with
/// `minvmd` as its own `current_exe()`. `min secret` names the same program
/// in an item's access control, through [`proxy_binary_on_path`], with
/// `minvmd` as the first `minvmd` on `PATH`, which is the program that the
/// CLI's autospawn starts.
///
/// `minvmd` runs only when the variable does not give the path. Each
/// resolution logs one debug line that names the path.
#[must_use]
pub fn proxy_binary_path(
    env: Option<&std::ffi::OsStr>,
    minvmd: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    let path = match env.filter(|v| !v.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => minvmd()?.with_file_name("bep"),
    };
    tracing::debug!(proxy = %path.display(), "resolved the proxy binary path");
    Some(path)
}

/// Why [`proxy_binary_on_path`] gives no proxy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyLookupError {
    /// [`PROXY_BIN_ENV`] holds this relative path.
    RelativeEnv(PathBuf),
    /// The variable gives no path, and no executable `minvmd` is on `PATH`.
    NoMinvmd,
}

/// The proxy that a `minvmd` started from `path` starts, by
/// [`proxy_binary_path`]. `min secret` names this path in an item's access
/// control. `minvmd` is the first executable `minvmd` in an absolute entry
/// of `path`, which is the program that `Command::new("minvmd")` starts.
///
/// The access control trusts this path, so it is absolute. A relative
/// variable is refused, and an empty or relative `PATH` entry is skipped,
/// so a program in the current directory never becomes the trusted one.
/// The `minvmd` that is found takes the path that its `current_exe()`
/// gives: links resolved on Linux, as is on macOS. A proxy path that
/// exists comes back canonical, and one that does not comes back as is.
///
/// # Errors
///
/// [`ProxyLookupError`] when the variable is relative, or when it gives no
/// path and no `minvmd` is on `path`.
pub fn proxy_binary_on_path(
    env: Option<&std::ffi::OsStr>,
    path: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, ProxyLookupError> {
    let env = env.filter(|v| !v.is_empty());
    if let Some(env) = env.map(Path::new)
        && !env.is_absolute()
    {
        return Err(ProxyLookupError::RelativeEnv(env.to_path_buf()));
    }
    let proxy = proxy_binary_path(env, || find_on_path("minvmd", path).map(exe_path))
        .ok_or(ProxyLookupError::NoMinvmd)?;
    Ok(std::fs::canonicalize(&proxy).unwrap_or(proxy))
}

/// The path that `current_exe()` gives in a program started from `path`.
/// On Linux that path has its symbolic links resolved. On macOS
/// `current_exe()` is `_NSGetExecutablePath`, which gives the path that
/// started the program and can be the link itself.
fn exe_path(path: PathBuf) -> PathBuf {
    if cfg!(target_os = "macos") {
        path
    } else {
        std::fs::canonicalize(&path).unwrap_or(path)
    }
}

/// The first executable `name` in an absolute entry of `path`.
fn find_on_path(name: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Refuse a proxy binary that a user other than the current one or root
/// can change, since the item's access control trusts it.
///
/// `path` is a regular file, not a symbolic link, owned by the current user
/// or by root, and not writable by group or others. Every directory above
/// it, up to the root, is owned by the current user or by root and is not
/// writable by group or others, so nobody else can put a program in its
/// place. A directory above the parent with the sticky bit, such as `/tmp`,
/// can be writable. Pass the canonical path.
///
/// # Errors
///
/// [`StoreError::ProxyUnsafe`] that names the check that failed, or
/// [`StoreError::Refused`] when the file cannot be read.
#[cfg(unix)]
pub fn check_proxy_binary(path: &Path) -> Result<(), StoreError> {
    check_proxy_binary_as(path, effective_uid())
}

/// The effective user id of this process.
#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no argument, reads process state and cannot
    // fail.
    unsafe { libc::geteuid() }
}

/// [`check_proxy_binary`] for the user `uid`.
#[cfg(unix)]
fn check_proxy_binary_as(path: &Path, uid: u32) -> Result<(), StoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let unsafe_because = |reason: String| StoreError::ProxyUnsafe {
        path: path.to_path_buf(),
        reason,
    };
    let meta = std::fs::symlink_metadata(path).map_err(|e| StoreError::Refused {
        store: NATIVE_STORE,
        action: "read the proxy program",
        detail: format!("{}: {e}", path.display()),
    })?;
    if !meta.file_type().is_file() {
        return Err(unsafe_because("it is not a regular file".into()));
    }
    if meta.uid() != uid && meta.uid() != 0 {
        return Err(unsafe_because(format!(
            "it is owned by user id {}, not by you or root",
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(unsafe_because(format!(
            "group or others can write to it (mode {mode:04o})"
        )));
    }
    let Some(parent) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Err(unsafe_because("it has no parent directory".into()));
    };
    // Review finding 4369498404: someone who can change any directory above
    // the program can rename that directory and put another in its place.
    // So every directory up to the root passes the owner and mode rules.
    for dir in parent.ancestors().filter(|d| !d.as_os_str().is_empty()) {
        let dir_meta = std::fs::metadata(dir).map_err(|e| StoreError::Refused {
            store: NATIVE_STORE,
            action: "read the proxy program",
            detail: format!("{}: {e}", dir.display()),
        })?;
        let reason = directory_unsafe_because(
            dir,
            dir_meta.uid(),
            dir_meta.mode() & 0o7777,
            uid,
            dir == parent,
        );
        if let Some(reason) = reason {
            return Err(unsafe_because(reason));
        }
    }
    Ok(())
}

/// Why the directory `dir`, owned by `owner` with mode `mode`, lets someone
/// other than `uid` or root replace what is below it. `None` when it does
/// not.
///
/// The directory is owned by `uid` or by root, and group and others cannot
/// write to it. A directory above the parent can be writable when its
/// sticky bit is set, as on `/tmp`: there, only the owner of an entry can
/// rename or remove it, and the entry below passes the owner rule too.
#[cfg(unix)]
fn directory_unsafe_because(
    dir: &Path,
    owner: u32,
    mode: u32,
    uid: u32,
    parent: bool,
) -> Option<String> {
    if owner != uid && owner != 0 {
        return Some(format!(
            "its directory {} is owned by user id {owner}, not by you or root",
            dir.display()
        ));
    }
    let sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && (parent || !sticky) {
        return Some(format!(
            "group or others can write to its directory {} (mode {mode:04o})",
            dir.display()
        ));
    }
    None
}

/// [`check_proxy_binary`] on a host without Unix file modes: no check.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
pub fn check_proxy_binary(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Whether `id` is an identifier a secret can have: 1 to [`MAX_ID_LEN`]
/// ASCII letters, digits, `.`, `_` and `-`, not starting with `-`.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One stored secret, as a listing shows it. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemInfo {
    /// The identifier.
    pub id: String,
    /// Whether the item's access control carries the entry that `set`
    /// created for the proxy binary.
    pub proxy_access: bool,
}

/// An error from a secret store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store refused an operation.
    #[error("the {store} store refused to {action}: {detail}")]
    Refused {
        /// The store.
        store: &'static str,
        /// What was refused.
        action: &'static str,
        /// What the store said.
        detail: String,
    },
    /// This host has no native store.
    #[error(
        "This host has no secret store that `min secret` can use. `min secret` stores secrets in the macOS Keychain on macOS and in Secret Service on Linux."
    )]
    Unsupported,
    /// This process reached no D-Bus session bus, so it cannot tell whether
    /// the host has a Secret Service.
    #[error(
        "`min secret` keeps secrets in Secret Service on Linux, and this process reached no D-Bus session bus: {detail}. Run the command again in a login session where DBUS_SESSION_BUS_ADDRESS names a running session bus."
    )]
    NoSessionBus {
        /// Why no bus answered.
        detail: String,
    },
    /// The session bus answers, and no Secret Service is on it.
    #[error(
        "`min secret` keeps secrets in Secret Service on Linux, and the D-Bus session bus has no Secret Service: {detail}. Install a Secret Service provider such as GNOME Keyring (the `gnome-keyring` package), and run the command again in a login session that starts it."
    )]
    NoSecretService {
        /// What the bus said.
        detail: String,
    },
    /// The Secret Service keyring is locked.
    #[error(
        "`min secret` keeps secrets in Secret Service on Linux, and its keyring is locked: {detail}. Unlock the login keyring, then run the command again."
    )]
    KeyringLocked {
        /// What is locked.
        detail: String,
    },
    /// Secret Service gave no answer to a call that changes nothing. It
    /// refused nothing, and nothing says what it holds.
    #[error("`min secret` keeps secrets in Secret Service on Linux. {detail}.")]
    Unanswered {
        /// How long the call waited.
        detail: String,
    },
    /// A request to change an item did not end with an answer that settles
    /// it. The change can be made, not made, or made in part.
    #[error(
        "{detail}. Secret Service can still make the change, or it made a part of it. Run the command again."
    )]
    ChangeUnsettled {
        /// What happened to the request.
        detail: String,
    },
    /// A user other than the current one or root can change the proxy
    /// program, so the item's access control cannot trust it.
    #[error(
        "The Box Egress Proxy program {path} is not safe to trust, because {reason}. Only that program can read the stored secret without a prompt. Reinstall Minimal with its installer, or set {PROXY_BIN_ENV} to a `bep` program that only you or root can change, and run the command again."
    )]
    ProxyUnsafe {
        /// The proxy program.
        path: PathBuf,
        /// The check that failed.
        reason: String,
    },
    /// The identifier is not one that [`valid_id`] admits.
    #[error(
        "`{0}` is not a name a secret can have. Use 1 to {MAX_ID_LEN} letters, digits, `.`, `_` and `-`, not starting with `-`."
    )]
    InvalidId(String),
    /// `set` stored the new value, and then the keychain refused to remove
    /// the staging copy of it.
    #[error(
        "min secret set stored {id}, but a copy of the value remains in the keychain under {STAGING_SERVICE}: {cause}. Remove the copy with `security delete-generic-password -s {STAGING_SERVICE} -a {id}`."
    )]
    StagingLeft {
        /// The identifier.
        id: String,
        /// Why the delete failed.
        cause: Box<StoreError>,
    },
}

/// A store of secrets by identifier.
pub trait SecretStore {
    /// The store's name, as `--store` writes it.
    fn name(&self) -> &'static str;

    /// Store `value` under `id`, or replace the value held there. The item's
    /// access control lets `proxy` read it without a prompt, and no other
    /// application.
    ///
    /// # Errors
    ///
    /// When the store refuses the write.
    fn set(&self, id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError>;

    /// Every stored item, by identifier, with whether its access control
    /// admits `proxy`. Reads no value.
    ///
    /// # Errors
    ///
    /// When the store refuses the read.
    fn list(&self, proxy: &Path) -> Result<Vec<ItemInfo>, StoreError>;

    /// Remove the item under `id`. `false` when no such item was held.
    ///
    /// # Errors
    ///
    /// When the store refuses the delete.
    fn remove(&self, id: &str) -> Result<bool, StoreError>;

    /// Whether this host can use the store at all. `set` asks before it
    /// reads a value, so nobody types a secret that the store then refuses.
    ///
    /// # Errors
    ///
    /// When the host has no such store.
    fn check_available(&self) -> Result<(), StoreError> {
        Ok(())
    }

    /// Whether an item is stored under `id`. Reads no value and shows no
    /// prompt, so a creation can ask it before the proxy reads the value.
    ///
    /// # Errors
    ///
    /// When the store cannot tell without a prompt, or refuses the lookup.
    fn holds(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self.list(Path::new(""))?.iter().any(|item| item.id == id))
    }

    /// The store as a message names it, such as "the keychain store".
    fn place(&self) -> String {
        format!("the {} store", self.name())
    }

    /// Whether an item's access control names one program, the proxy, as
    /// a Keychain item's does. `false` for a store where every program of
    /// the user reads every item, as in Secret Service. Then no proxy path
    /// decides who reads an item.
    fn binds_program(&self) -> bool {
        true
    }
}

/// One item of a [`MemorySecretStore`].
#[derive(Debug)]
struct MemoryItem {
    value: Zeroizing<Vec<u8>>,
    trusted: Vec<PathBuf>,
}

/// A store held in memory, with the keychain's access-control model: an
/// item lists the applications that read it without a prompt. For tests.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    items: Mutex<BTreeMap<String, MemoryItem>>,
    reads: AtomicUsize,
}

impl MemorySecretStore {
    /// The value under `id`, as the proxy reads it.
    #[must_use]
    pub fn value(&self, id: &str) -> Option<Vec<u8>> {
        let g = self.items.lock().ok()?;
        g.get(id).map(|item| item.value.to_vec())
    }

    /// Whether `app` reads the item under `id` without a prompt.
    #[must_use]
    pub fn reads_without_prompt(&self, id: &str, app: &Path) -> bool {
        self.items
            .lock()
            .ok()
            .and_then(|g| g.get(id).map(|item| item.trusted.iter().any(|t| t == app)))
            .unwrap_or(false)
    }

    /// Replace the trusted applications of the item under `id`, as an
    /// edit in Keychain Access does.
    pub fn set_trusted(&self, id: &str, trusted: Vec<PathBuf>) {
        if let Ok(mut g) = self.items.lock()
            && let Some(item) = g.get_mut(id)
        {
            item.trusted = trusted;
        }
    }

    /// How many times a [`MemoryReader`] read a value from this store.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn lock(
        &self,
        action: &'static str,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, MemoryItem>>, StoreError> {
        self.items.lock().map_err(|_| StoreError::Refused {
            store: NATIVE_STORE,
            action,
            detail: "poisoned".into(),
        })
    }
}

impl SecretStore for MemorySecretStore {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    fn set(&self, id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
        self.lock("store the secret")?.insert(
            id.to_owned(),
            MemoryItem {
                value: Zeroizing::new(value.to_vec()),
                trusted: vec![proxy.to_path_buf()],
            },
        );
        Ok(())
    }

    fn list(&self, proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        Ok(self
            .lock("list the secrets")?
            .iter()
            .map(|(id, item)| ItemInfo {
                id: id.clone(),
                proxy_access: item.trusted.iter().any(|t| t == proxy),
            })
            .collect())
    }

    fn remove(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self.lock("remove the secret")?.remove(id).is_some())
    }
}

/// Why the proxy read no value for a store reference.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// No item is stored under the identifier: it was deleted.
    #[error("no secret is stored under {0}")]
    Deleted(String),
    /// The item exists, and its access control does not let the proxy read
    /// it without a prompt.
    #[error("the secret {0} does not let the Box Egress Proxy read it")]
    Disabled(String),
    /// The store failed or refused the read.
    #[error(transparent)]
    Store(StoreError),
}

/// The values of one store, as the proxy reads them for a request.
///
/// Each call reads the store again. An implementation keeps no copy of a
/// value, and writes none to a file or a log (BEP-033).
pub trait ValueReader: Send + Sync {
    /// The store's name, as a store reference writes it.
    fn name(&self) -> &'static str;

    /// The value stored under `id`, read now.
    ///
    /// # Errors
    ///
    /// [`ReadError::Deleted`] when no item is stored under `id`,
    /// [`ReadError::Disabled`] when the item does not let the proxy read
    /// it, and [`ReadError::Store`] when the store fails.
    fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError>;
}

/// A [`MemorySecretStore`] as the program `app` reads it. An item that does
/// not trust `app` is disabled for it. For tests.
#[derive(Debug, Clone)]
pub struct MemoryReader {
    /// The store.
    pub store: Arc<MemorySecretStore>,
    /// The program that reads.
    pub app: PathBuf,
}

impl ValueReader for MemoryReader {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        let items = self
            .store
            .lock("read the secret")
            .map_err(ReadError::Store)?;
        self.store.reads.fetch_add(1, Ordering::SeqCst);
        let item = items
            .get(id)
            .ok_or_else(|| ReadError::Deleted(id.to_owned()))?;
        if !item.trusted.iter().any(|t| t == &self.app) {
            return Err(ReadError::Disabled(id.to_owned()));
        }
        Ok(Zeroizing::new(item.value.to_vec()))
    }
}

/// The `bep` subcommand that stores one item, with the value on its
/// standard input.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const ADD_COMMAND: &str = "store-add";

/// The arguments that make the proxy program store `id` under `service`.
///
/// The value is not among them, so it never reaches a command line.
///
/// # Errors
///
/// When `id` is not one that [`valid_id`] admits.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn add_args<'a>(service: &str, id: &'a str) -> Result<Vec<&'a str>, StoreError> {
    if !valid_id(id) {
        return Err(StoreError::InvalidId(id.to_owned()));
    }
    let mut args = vec![ADD_COMMAND];
    if service == STAGING_SERVICE {
        args.push("--staging");
    }
    args.push(id);
    Ok(args)
}

/// Add an item under `service` and `id` as the running program, which is
/// the one way an item lands in the proxy's partition. The keychain names
/// the creating program as the one trusted application, so every other
/// application prompts. It refuses an item that is already held: an update
/// in place keeps the access control of the old item, so the caller removes
/// that item first.
///
/// # Errors
///
/// What the store said, when it refused the item.
pub fn add_as_this_program(service: &str, id: &str, value: &[u8]) -> Result<(), String> {
    if !valid_id(id) {
        return Err(StoreError::InvalidId(id.to_owned()).to_string());
    }
    host::add_as_this_program(service, id, value)
}

/// The secret items in the output of `security dump-keychain -a`: each
/// item under [`SERVICE`], by account, with whether the proxy can read it.
/// It can when an access-control entry that allows `decrypt` lists `proxy`
/// among its applications, and the item's partition list names `partition`,
/// the proxy's own. With no `partition`, no item is readable.
#[must_use]
pub fn parse_dump(dump: &str, proxy: &Path, partition: Option<&str>) -> Vec<ItemInfo> {
    parse_dump_service(dump, SERVICE, proxy, partition)
}

/// [`parse_dump`] for the items under `service`.
fn parse_dump_service(
    dump: &str,
    service: &str,
    proxy: &Path,
    partition: Option<&str>,
) -> Vec<ItemInfo> {
    let proxy = proxy.to_string_lossy();
    // `dump-keychain -a` lists every keychain in the search list, so one
    // identifier can appear more than once. Review finding 4369647108: the
    // copies merge. Review thread 4369745203: the identifier has proxy access
    // only when every copy grants it, because a copy without the proxy's
    // entry prompts the proxy.
    let mut items: BTreeMap<String, bool> = BTreeMap::new();
    for record in dump.split("\nkeychain: ") {
        let attr = |key: &str| {
            let prefix = format!("\"{key}\"<blob>=\"");
            record.lines().find_map(|l| {
                let rest = l.trim().strip_prefix(&prefix)?;
                Some(rest.strip_suffix('"')?.to_owned())
            })
        };
        if attr("svce").as_deref() != Some(service) {
            continue;
        }
        let Some(id) = attr("acct") else { continue };
        let mut entries = record.split("entry ").skip(1);
        let proxy_access = entries.clone().any(|entry| entry_admits(entry, &proxy))
            && partition.is_some_and(|name| entries.any(|entry| names_partition(entry, name)));
        items
            .entry(id)
            .and_modify(|access| *access &= proxy_access)
            .or_insert(proxy_access);
    }
    items
        .into_iter()
        .map(|(id, proxy_access)| ItemInfo { id, proxy_access })
        .collect()
}

/// Whether one access-control entry allows `decrypt` and lists `proxy`.
fn entry_admits(entry: &str, proxy: &str) -> bool {
    let mut decrypt = false;
    let mut listed = false;
    for line in entry.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("authorizations") {
            decrypt = rest.split_whitespace().any(|a| a == "decrypt");
        }
        // Applications print as `0: /path/to/app (OK)`.
        if let Some((index, rest)) = line.split_once(": ")
            && index.bytes().all(|b| b.is_ascii_digit())
            && !index.is_empty()
        {
            let path = rest.strip_suffix(" (OK)").unwrap_or(rest);
            listed |= path == proxy || is_bundle_of(path, proxy);
        }
    }
    decrypt && listed
}

/// Whether one access-control entry is the item's partition list and names
/// `partition`. A program outside the list cannot read the item, whatever the
/// application list says.
fn names_partition(entry: &str, partition: &str) -> bool {
    let mut lines = entry.lines().map(str::trim);
    lines.clone().any(|line| {
        line.strip_prefix("authorizations")
            .is_some_and(|rest| rest.split_whitespace().any(|a| a == "partition_id"))
    }) && lines.any(|line| {
        line.strip_prefix("description:")
            .is_some_and(|list| list.split(',').any(|name| name.trim() == partition))
    })
}

/// The keychain partition of a program, from what `codesign -dvvv` prints:
/// `teamid:<team>` for a team-signed program, else `cdhash:<hash>`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn signature_partition(display: &str) -> Option<String> {
    let value = |key: &str| display.lines().find_map(|line| line.strip_prefix(key));
    match value("TeamIdentifier=") {
        Some(team) if team != "not set" => Some(format!("teamid:{team}")),
        _ => value("CDHash=").map(|hash| format!("cdhash:{hash}")),
    }
}

/// Whether `path` is the bundle whose main program is `proxy`.
///
/// The keychain records a bundle's main program as the bundle, with the
/// bundle's requirement. It records any other program in the bundle under
/// that program's own path, with that program's requirement. So an entry
/// that names the bundle says nothing about another program inside it, and
/// only `<name>.app/Contents/MacOS/<name>`, the form `bep.app` ships in,
/// matches here. A bundle that names its main program differently reads as
/// not listed, which refuses the item.
fn is_bundle_of(path: &str, proxy: &str) -> bool {
    let name = path.rsplit('/').next().and_then(|n| n.strip_suffix(".app"));
    let program = proxy
        .strip_prefix(path)
        .and_then(|tail| tail.strip_prefix("/Contents/MacOS/"));
    name.is_some() && name == program
}

/// One access-control entry of a keychain item, as the Keychain Services
/// API reports it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AclEntry {
    /// The authorization tags, such as `ACLAuthorizationDecrypt`.
    authorizations: Vec<String>,
    /// The paths of the trusted applications whose programs pass the
    /// requirement the entry recorded. `None` is any application,
    /// which lists no program, as `dump-keychain` prints `<null>`.
    applications: Option<Vec<String>>,
    /// The entry's description. For the partition entry, the partition list.
    description: String,
}

/// The authorization that lets a program read the value.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const AUTH_DECRYPT: &str = "ACLAuthorizationDecrypt";
/// The authorization of the entry that holds the partition list.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const AUTH_PARTITION: &str = "ACLAuthorizationPartitionID";

/// Whether `proxy` can read the item held under one service and identifier,
/// from the access-control entries of each copy in the search list: `None`
/// when no copy is held. Every copy must admit the proxy, as in
/// [`parse_dump`]: a copy without the proxy's entry prompts it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn item_access(copies: &[Vec<AclEntry>], proxy: &Path, partition: Option<&str>) -> Option<bool> {
    if copies.is_empty() {
        return None;
    }
    let proxy = proxy.to_string_lossy();
    Some(copies.iter().all(|entries| {
        entries.iter().any(|entry| acl_admits(entry, &proxy))
            && partition
                .is_some_and(|name| entries.iter().any(|entry| acl_names_partition(entry, name)))
    }))
}

/// Whether one entry allows `decrypt` and lists `proxy`, as
/// [`entry_admits`] reads it from a dump.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn acl_admits(entry: &AclEntry, proxy: &str) -> bool {
    entry.authorizations.iter().any(|a| a == AUTH_DECRYPT)
        && entry.applications.as_ref().is_some_and(|apps| {
            apps.iter()
                .any(|path| path == proxy || is_bundle_of(path, proxy))
        })
}

/// Whether one entry is the partition list and names `partition`, as
/// [`names_partition`] reads it from a dump.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn acl_names_partition(entry: &AclEntry, partition: &str) -> bool {
    entry.authorizations.iter().any(|a| a == AUTH_PARTITION)
        && partition_names(&entry.description)
            .iter()
            .any(|name| name == partition)
}

/// The partitions a partition entry's description names. The API gives a
/// hex-encoded property list whose `Partitions` array holds them;
/// `dump-keychain` prints that list decoded, comma-separated, and either form
/// reads here.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn partition_names(description: &str) -> Vec<String> {
    let description = description.trim();
    match hex_decode(description).and_then(|bytes| String::from_utf8(bytes).ok()) {
        Some(plist) => plist
            .split("<string>")
            .skip(1)
            .filter_map(|rest| rest.split_once("</string>"))
            .map(|(name, _)| name.trim().to_owned())
            .collect(),
        None => description
            .split(',')
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect(),
    }
}

/// The bytes of an even-length hex string, or `None` for anything else.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// The keychain operations that [`set_item`] puts in order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
trait Keychain {
    /// Add an item under `service` and `id`, created by `proxy`, that names
    /// `proxy` as its one trusted application. On success, what the program
    /// printed as a warning.
    fn add(
        &self,
        service: &str,
        id: &str,
        value: &[u8],
        proxy: &Path,
    ) -> Result<String, StoreError>;

    /// Whether an item is held under `service` and `id`, and if so whether
    /// it admits `proxy`: `None` when none is held. Only that item is read,
    /// never the whole keychain.
    fn item(&self, service: &str, id: &str, proxy: &Path) -> Result<Option<bool>, StoreError>;

    /// Delete the item under `service` and `id`. `false` when none was held.
    fn delete(&self, service: &str, id: &str) -> Result<bool, StoreError>;
}

/// Store `value` under `id` with a fresh access control for `proxy`.
///
/// An update in place keeps the old item's access control, so a held item
/// is deleted and added again. The new value goes first into an item under
/// [`STAGING_SERVICE`], and is read back there. Only then does the old item
/// go. So when the keychain refuses the new item, the old one stays.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn set_item(kc: &impl Keychain, id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
    if kc.item(SERVICE, id, proxy)?.is_none() {
        return add_checked(kc, SERVICE, id, value, proxy);
    }
    // A failed run can leave a staged item behind. The add below refuses a
    // duplicate, so that item goes first.
    kc.delete(STAGING_SERVICE, id)?;
    if let Err(mut e) = add_checked(kc, STAGING_SERVICE, id, value, proxy) {
        if kc.delete(STAGING_SERVICE, id).is_err() {
            note_staging_left(&mut e, id);
        }
        return Err(e);
    }
    let result = match kc.delete(SERVICE, id) {
        // The old item is still held, so the error needs no addition.
        Err(e) => Err(e),
        Ok(_) => add_checked(kc, SERVICE, id, value, proxy).map_err(|mut e| {
            if let StoreError::Refused { detail, .. } = &mut e {
                detail.push_str(&format!(
                    ". The old value of {id} is removed. Run `min secret set {id}` again to store a value"
                ));
            }
            e
        }),
    };
    match (kc.delete(STAGING_SERVICE, id), result) {
        (Ok(_), result) => result,
        (Err(cause), Ok(())) => Err(StoreError::StagingLeft {
            id: id.to_owned(),
            cause: Box::new(cause),
        }),
        (Err(_), Err(mut e)) => {
            note_staging_left(&mut e, id);
            Err(e)
        }
    }
}

/// Add to `e` that a staging copy of the value for `id` can remain, and the
/// command that removes it.
fn note_staging_left(e: &mut StoreError, id: &str) {
    if let StoreError::Refused { detail, .. } = e {
        detail.push_str(&format!(
            ". A copy of the new value can remain in the keychain under {STAGING_SERVICE}. \
             Remove it with `security delete-generic-password -s {STAGING_SERVICE} -a {id}`"
        ));
    }
}

/// Add the item, then read it back with its access control.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn add_checked(
    kc: &impl Keychain,
    service: &str,
    id: &str,
    value: &[u8],
    proxy: &Path,
) -> Result<(), StoreError> {
    let warnings = kc.add(service, id, value, proxy)?;
    // The program can warn on stderr after a write that succeeded. So the
    // item itself, read back with its access control, decides the result.
    let mut detail = match kc.item(service, id, proxy) {
        Ok(Some(true)) => return Ok(()),
        Ok(_) if warnings.is_empty() => {
            "the keychain holds no item for it that the proxy can read".to_owned()
        }
        Ok(_) => warnings,
        // Review finding 4369498405: the add succeeded, so an item can hold
        // the value although the read-back failed. It goes as well.
        Err(e) => format!("the item was added, but reading it back failed: {e}"),
    };
    // Review finding 4369438788: an item whose access control the read-back
    // did not confirm holds the value, so it goes. A staged item that stays
    // is the caller's to report.
    if kc.delete(service, id).is_err() && service != STAGING_SERVICE {
        detail.push_str(&format!(
            ". The value can remain in the keychain under {service}. \
             Remove it with `security delete-generic-password -s {service} -a {id}`"
        ));
    }
    Err(StoreError::Refused {
        store: NATIVE_STORE,
        action: "store the secret",
        detail,
    })
}

/// The native store of this host: the macOS Keychain through
/// `/usr/bin/security` on macOS, and Secret Service on Linux. Other hosts
/// refuse every operation.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostStore;

impl SecretStore for HostStore {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    fn set(&self, id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
        host::set(id, value, proxy)
    }

    fn list(&self, proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        host::list(proxy)
    }

    fn remove(&self, id: &str) -> Result<bool, StoreError> {
        host::remove(id)
    }

    fn check_available(&self) -> Result<(), StoreError> {
        host::check_available()
    }

    fn holds(&self, id: &str) -> Result<bool, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::InvalidId(id.to_owned()));
        }
        host::holds(id)
    }

    /// Secret Service on Linux, where a store reference still names the
    /// store `keychain`. The keychain store elsewhere.
    fn place(&self) -> String {
        if cfg!(target_os = "linux") {
            "Secret Service".to_owned()
        } else {
            format!("the {NATIVE_STORE} store")
        }
    }

    fn binds_program(&self) -> bool {
        cfg!(target_os = "macos")
    }
}

impl ValueReader for HostStore {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    /// Reads the item in this process, so the keychain checks the item's
    /// access control against the running program: the proxy.
    fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        if !valid_id(id) {
            return Err(ReadError::Store(StoreError::InvalidId(id.to_owned())));
        }
        host::read(id)
    }
}

#[cfg(target_os = "macos")]
mod host {
    use super::{
        AclEntry, ItemInfo, Keychain, NATIVE_STORE, ReadError, SERVICE, StoreError, add_args,
        item_access, parse_dump, set_item, signature_partition,
    };
    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::data::{CFData, CFDataRef};
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework_sys::base::{SecAccessRef, SecKeychainItemRef};
    use std::io::{ErrorKind, Write as _};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use zeroize::Zeroizing;

    const SECURITY: &str = "/usr/bin/security";
    const CODESIGN: &str = "/usr/bin/codesign";
    /// `security` exits 44 when no item matches.
    const NOT_FOUND: i32 = 44;

    /// Run `program` to its exit, with `stdin` on its standard input.
    pub(super) fn run(
        program: &Path,
        action: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<std::process::Output, StoreError> {
        let refused = |detail: String| StoreError::Refused {
            store: NATIVE_STORE,
            action,
            detail,
        };
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| refused(e.to_string()))?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            // A program that exits without reading closes the pipe. Its exit
            // status and stderr say why, so they decide the message.
            match pipe.write_all(input) {
                Err(e) if e.kind() != ErrorKind::BrokenPipe => {
                    return Err(refused(e.to_string()));
                }
                _ => {}
            }
        }
        child.wait_with_output().map_err(|e| refused(e.to_string()))
    }

    fn refused(action: &'static str, stderr: &[u8]) -> StoreError {
        StoreError::Refused {
            store: NATIVE_STORE,
            action,
            detail: String::from_utf8_lossy(stderr).trim().to_owned(),
        }
    }

    /// The keychain through `/usr/bin/security`, and through the proxy
    /// program for an add.
    pub(super) struct SecurityTool;

    impl Keychain for SecurityTool {
        fn add(
            &self,
            service: &str,
            id: &str,
            value: &[u8],
            proxy: &Path,
        ) -> Result<String, StoreError> {
            let args = add_args(service, id)?;
            let out = run(proxy, "store the secret", &args, Some(value))?;
            if !out.status.success() {
                return Err(refused("store the secret", &out.stderr));
            }
            Ok(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }

        fn item(&self, service: &str, id: &str, proxy: &Path) -> Result<Option<bool>, StoreError> {
            let refused = |detail: String| StoreError::Refused {
                store: NATIVE_STORE,
                action: "read the secret's access control",
                detail,
            };
            // Every copy in the search list, as references: no value is read,
            // so the search asks for no access.
            let mut search = ItemSearchOptions::new();
            search
                .class(ItemClass::generic_password())
                .service(service)
                .account(id)
                .load_refs(true)
                .limit(Limit::All);
            let found = match search.search() {
                Ok(found) => found,
                Err(e) if e.code() == ITEM_NOT_FOUND => return Ok(None),
                Err(e) => return Err(refused(e.to_string())),
            };
            let mut copies = Vec::with_capacity(found.len());
            for result in found {
                let SearchResult::Ref(Reference::KeychainItem(item)) = result else {
                    return Err(refused(
                        "the keychain answered with something that is not an item".to_owned(),
                    ));
                };
                copies.push(acl_entries(&item).map_err(refused)?);
            }
            let partition = proxy_partition(proxy);
            Ok(item_access(&copies, proxy, partition.as_deref()))
        }

        fn delete(&self, service: &str, id: &str) -> Result<bool, StoreError> {
            delete(service, id)
        }
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        // `security-framework-sys` declares none of these. They are
        // deprecated with the file-based keychain they read, and that keychain
        // is the one these items live in.
        fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> i32;
        fn SecAccessCopyACLList(access: SecAccessRef, list: *mut CFArrayRef) -> i32;
        fn SecACLCopyAuthorizations(acl: CFTypeRef) -> CFArrayRef;
        fn SecACLCopyContents(
            acl: CFTypeRef,
            applications: *mut CFArrayRef,
            description: *mut CFStringRef,
            prompt_selector: *mut u16,
        ) -> i32;
        fn SecTrustedApplicationCopyData(application: CFTypeRef, data: *mut CFDataRef) -> i32;
        fn SecTrustedApplicationValidateWithPath(
            application: CFTypeRef,
            path: *const std::ffi::c_char,
        ) -> i32;
    }

    /// The message of a Security framework status.
    fn status_text(status: i32) -> String {
        security_framework::base::Error::from_code(status).to_string()
    }

    /// The access-control entries of one item.
    fn acl_entries(item: &SecKeychainItem) -> Result<Vec<AclEntry>, String> {
        let mut access: SecAccessRef = std::ptr::null_mut();
        // SAFETY: `item` holds a live reference, and `access` is an out
        // pointer the call fills with an owned reference on success.
        let status =
            unsafe { SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut access) };
        if status != 0 || access.is_null() {
            return Err(status_text(status));
        }
        // SAFETY: a Copy call returned `access`, so this takes its one
        // reference, which drops with `access`.
        let access = unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) };
        let mut list: CFArrayRef = std::ptr::null();
        // SAFETY: `access` is live for the call, and `list` is an out pointer
        // the call fills with an owned array on success.
        let status =
            unsafe { SecAccessCopyACLList(access.as_CFTypeRef() as SecAccessRef, &raw mut list) };
        if status != 0 || list.is_null() {
            return Err(status_text(status));
        }
        // SAFETY: a Copy call returned `list`, an array of `SecACLRef`.
        let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(list) };
        list.iter()
            .map(|acl| acl_entry(acl.as_CFTypeRef()))
            .collect()
    }

    /// One access-control entry.
    fn acl_entry(acl: CFTypeRef) -> Result<AclEntry, String> {
        // SAFETY: `acl` is an element of an array the caller holds.
        let tags = unsafe { SecACLCopyAuthorizations(acl) };
        let authorizations = if tags.is_null() {
            Vec::new()
        } else {
            // SAFETY: a Copy call returned `tags`, an array of `CFString`.
            let tags = unsafe { CFArray::<CFType>::wrap_under_create_rule(tags) };
            tags.iter()
                .filter_map(|tag| tag.downcast::<CFString>().map(|t| t.to_string()))
                .collect()
        };
        let mut applications: CFArrayRef = std::ptr::null();
        let mut description: CFStringRef = std::ptr::null();
        let mut prompt = 0u16;
        // SAFETY: `acl` is live for the call, and each out pointer is filled
        // with an owned reference or left null.
        let status = unsafe {
            SecACLCopyContents(
                acl,
                &raw mut applications,
                &raw mut description,
                &raw mut prompt,
            )
        };
        if status != 0 {
            return Err(status_text(status));
        }
        let description = if description.is_null() {
            String::new()
        } else {
            // SAFETY: a Copy call returned `description`.
            unsafe { CFString::wrap_under_create_rule(description) }.to_string()
        };
        let applications = if applications.is_null() {
            None
        } else {
            // SAFETY: a Copy call returned `applications`, an array of
            // `SecTrustedApplicationRef`.
            let list = unsafe { CFArray::<CFType>::wrap_under_create_rule(applications) };
            let mut paths = Vec::new();
            for app in list.iter() {
                if let Some(path) = application_path(app.as_CFTypeRef())? {
                    paths.push(path);
                }
            }
            Some(paths)
        };
        Ok(AclEntry {
            authorizations,
            applications,
            description,
        })
    }

    /// The path a trusted application names, as `dump-keychain` prints it.
    /// `None` when the program at that path fails the requirement the entry
    /// recorded, which `dump-keychain` prints as a failure status: the
    /// keychain would not trust that program, so the entry does not admit it.
    fn application_path(application: CFTypeRef) -> Result<Option<String>, String> {
        let mut data: CFDataRef = std::ptr::null();
        // SAFETY: `application` is an element of an array the caller holds,
        // and `data` is an out pointer filled with an owned reference.
        let status = unsafe { SecTrustedApplicationCopyData(application, &raw mut data) };
        if status != 0 || data.is_null() {
            return Err(status_text(status));
        }
        // SAFETY: a Copy call returned `data`.
        let data = unsafe { CFData::wrap_under_create_rule(data) };
        let bytes = data.bytes();
        // The path is a C string, with its terminating NUL.
        let path = bytes.split(|b| *b == 0).next().unwrap_or_default();
        let Ok(c_path) = std::ffi::CString::new(path) else {
            return Ok(None);
        };
        // SAFETY: `application` is live for the call, and `c_path` is a
        // NUL-terminated string that outlives it.
        let status = unsafe { SecTrustedApplicationValidateWithPath(application, c_path.as_ptr()) };
        if status != 0 {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(path).into_owned()))
    }

    pub(super) fn set(id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
        set_item(&SecurityTool, id, value, proxy)
    }

    pub(super) fn add_as_this_program(service: &str, id: &str, value: &[u8]) -> Result<(), String> {
        security_framework::os::macos::keychain::SecKeychain::default()
            .and_then(|keychain| keychain.add_generic_password(service, id, value))
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn check_available() -> Result<(), StoreError> {
        Ok(())
    }

    /// The partition that an item `proxy` creates lands in. `None` when its
    /// signature cannot be read, which reports no item as readable.
    pub(super) fn proxy_partition(proxy: &Path) -> Option<String> {
        let out = run(
            Path::new(CODESIGN),
            "read the proxy's signature",
            &["-dvvv", proxy.to_str()?],
            None,
        )
        .ok()?;
        if !out.status.success() {
            return None;
        }
        // `codesign` prints what it displays on stderr.
        signature_partition(&String::from_utf8_lossy(&out.stderr))
    }

    /// The output of `dump-keychain -a`.
    fn dump() -> Result<String, StoreError> {
        // `dump-keychain` without `-d` decrypts nothing, so it prints no
        // value and asks for no access.
        let out = run(
            Path::new(SECURITY),
            "list the secrets",
            &["dump-keychain", "-a"],
            None,
        )?;
        if !out.status.success() {
            return Err(refused("list the secrets", &out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub(super) fn list(proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        Ok(parse_dump(
            &dump()?,
            proxy,
            proxy_partition(proxy).as_deref(),
        ))
    }

    pub(super) fn remove(id: &str) -> Result<bool, StoreError> {
        delete(SERVICE, id)
    }

    /// Whether an item is stored under `id`. The search asks for a
    /// reference, not the value, and runs with prompts off, so a locked
    /// keychain answers `errSecInteractionNotAllowed` and shows no dialog.
    pub(super) fn holds(id: &str) -> Result<bool, StoreError> {
        let refused = |detail: String| StoreError::Refused {
            store: NATIVE_STORE,
            action: "find the secret",
            detail,
        };
        let _serial = NO_PROMPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _no_prompt =
            security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                .map_err(|e| refused(e.to_string()))?;
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(id)
            .load_refs(true)
            .limit(Limit::Max(1));
        match search.search() {
            Ok(found) => Ok(!found.is_empty()),
            Err(e) if e.code() == ITEM_NOT_FOUND => Ok(false),
            Err(e) => Err(refused(e.to_string())),
        }
    }

    /// The codes that mean the item does not let this program read it:
    /// `errSecAuthFailed`, `errSecNoAccessForItem` and `errSecUserCanceled`.
    const DENIED: [i32; 3] = [-25293, -25243, -128];
    /// `errSecInteractionNotAllowed`. With prompts off, a locked keychain
    /// and an item that does not trust the proxy both return it, so the
    /// read cannot say which cause it is.
    const INTERACTION_NOT_ALLOWED: i32 = -25308;
    /// `errSecItemNotFound`.
    const ITEM_NOT_FOUND: i32 = -25300;

    /// Serialises reads. The setting that turns off Keychain prompts is
    /// process-wide, so one read must not turn prompts back on while
    /// another read is in progress.
    static NO_PROMPT: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(super) fn read(id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        let _serial = NO_PROMPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // With prompts off, an item that does not let the proxy read it
        // returns `errSecInteractionNotAllowed` and does not block the
        // request on a dialog. The lock turns prompts back on when it drops.
        let _no_prompt =
            security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()
                .map_err(|e| {
                    ReadError::Store(StoreError::Refused {
                        store: NATIVE_STORE,
                        action: "read the secret",
                        detail: e.to_string(),
                    })
                })?;
        match security_framework::passwords::get_generic_password(SERVICE, id) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(e) if e.code() == ITEM_NOT_FOUND => Err(ReadError::Deleted(id.to_owned())),
            Err(e) if DENIED.contains(&e.code()) => {
                tracing::warn!(id, status = e.code(), "the keychain denied a stored secret");
                Err(ReadError::Disabled(id.to_owned()))
            }
            Err(e) if e.code() == INTERACTION_NOT_ALLOWED => {
                Err(ReadError::Store(StoreError::Refused {
                    store: NATIVE_STORE,
                    action: "read the secret",
                    detail: format!(
                        "the keychain is locked, or the secret {id} does not let the Box Egress Proxy read it without a prompt"
                    ),
                }))
            }
            Err(e) => Err(ReadError::Store(StoreError::Refused {
                store: NATIVE_STORE,
                action: "read the secret",
                detail: e.to_string(),
            })),
        }
    }

    fn delete(service: &str, id: &str) -> Result<bool, StoreError> {
        let out = run(
            Path::new(SECURITY),
            "remove the secret",
            &["delete-generic-password", "-s", service, "-a", id],
            None,
        )?;
        if out.status.code() == Some(NOT_FOUND) {
            return Ok(false);
        }
        if !out.status.success() {
            return Err(refused("remove the secret", &out.stderr));
        }
        Ok(true)
    }
}

/// The host's native store in a session where it cannot be reached, as
/// [`HostStore`] reads it there.
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) struct UnreachableHostStore;

#[cfg(all(test, not(target_os = "macos")))]
impl ValueReader for UnreachableHostStore {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        host::read_unreachable(id)
    }
}

/// The host's native store on a Secret Service that answers no read in the
/// time the proxy gives it.
#[cfg(all(test, target_os = "linux", feature = "secret-service"))]
pub(crate) struct UnansweredHostStore;

#[cfg(all(test, target_os = "linux", feature = "secret-service"))]
impl ValueReader for UnansweredHostStore {
    fn name(&self) -> &'static str {
        NATIVE_STORE
    }

    fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        host::read_unanswered(id)
    }
}

#[cfg(all(target_os = "linux", feature = "secret-service"))]
mod host {
    use super::{ItemInfo, ReadError, SERVICE, StoreError, valid_id};
    use crate::secret_items::{Cause, Items, SessionItems, TIMEOUT};
    use std::path::Path;
    use std::time::Duration;
    use zeroize::Zeroizing;

    /// The store's name in a refusal.
    const STORE: &str = "Secret Service";

    /// The attribute that holds the identifier. The `service` attribute
    /// holds [`SERVICE`].
    const ID: &str = "id";

    /// An attribute that no item carries. A search for it is one call that
    /// a Secret Service that runs answers with no match.
    const PROBE: &str = "dev.minimal.secret.probe";

    /// The longest that the proxy's read of a value waits for Secret
    /// Service. A request waits on a stuck provider no longer than this.
    pub(super) const READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// The items `min secret` keeps in Secret Service. Only `read` receives
    /// a value. A listing and a lookup of whether an item is held read the
    /// items' attributes, which Secret Service gives for a locked item too.
    #[derive(Debug, Clone)]
    pub(super) struct SecretItems<I> {
        items: I,
    }

    impl<I: Items> SecretItems<I> {
        pub(super) fn new(items: I) -> Self {
            Self { items }
        }

        /// Whether a Secret Service answers in this session.
        pub(super) fn check_available(&self) -> Result<(), StoreError> {
            self.items
                .attribute_values(&[("service", SERVICE), (PROBE, "absent")], ID)
                .map(|_| ())
                .map_err(|cause| failure("answer a lookup", cause))
        }

        /// Store `value` under `service` and `id`. Secret Service replaces
        /// the item whose attributes all match, so a held item is replaced
        /// in place, and a failed store leaves it as it was.
        pub(super) fn set(&self, service: &str, id: &str, value: &[u8]) -> Result<(), StoreError> {
            check_id(id)?;
            self.items
                .store(
                    &format!("Minimal secret {id}"),
                    &[("service", service), (ID, id)],
                    value,
                )
                .map_err(|cause| change_failure("store the secret", cause))
        }

        /// Every stored identifier. Every program of the user reads an
        /// unlocked item, so each one admits the proxy.
        pub(super) fn list(&self) -> Result<Vec<ItemInfo>, StoreError> {
            Ok(self
                .ids("list the secrets", None)?
                .into_iter()
                .map(|id| ItemInfo {
                    id,
                    proxy_access: true,
                })
                .collect())
        }

        /// Remove the item under `id`. `false` when none was held.
        pub(super) fn remove(&self, id: &str) -> Result<bool, StoreError> {
            check_id(id)?;
            self.items
                .clear(&[("service", SERVICE), (ID, id)])
                .map(|removed| removed > 0)
                .map_err(|cause| change_failure("remove the secret", cause))
        }

        /// Whether an item is stored under `id`, locked or not. Reads no
        /// value.
        pub(super) fn holds(&self, id: &str) -> Result<bool, StoreError> {
            check_id(id)?;
            Ok(!self.ids("find the secret", Some(id))?.is_empty())
        }

        /// The value under `id`, read now.
        pub(super) fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
            check_id(id).map_err(ReadError::Store)?;
            let action = "read the secret";
            match self.items.lookup(&[("service", SERVICE), (ID, id)]) {
                Ok(Some(value)) if value.is_empty() => Err(ReadError::Store(refused(
                    action,
                    format!("Secret Service returned no value for {id}"),
                ))),
                Ok(Some(value)) => Ok(value),
                Ok(None) => Err(ReadError::Deleted(id.to_owned())),
                Err(cause) => Err(ReadError::Store(failure(action, cause))),
            }
        }

        /// The stored identifiers, or the one `id` when it is stored, in
        /// order and each one once.
        fn ids(&self, action: &'static str, id: Option<&str>) -> Result<Vec<String>, StoreError> {
            let attributes: Vec<(&str, &str)> = std::iter::once(("service", SERVICE))
                .chain(id.map(|id| (ID, id)))
                .collect();
            let mut ids: Vec<String> = self
                .items
                .attribute_values(&attributes, ID)
                .map_err(|cause| failure(action, cause))?
                .into_iter()
                .filter(|id| valid_id(id))
                .collect();
            ids.dedup();
            Ok(ids)
        }
    }

    fn check_id(id: &str) -> Result<(), StoreError> {
        if valid_id(id) {
            Ok(())
        } else {
            Err(StoreError::InvalidId(id.to_owned()))
        }
    }

    fn refused(action: &'static str, detail: String) -> StoreError {
        StoreError::Refused {
            store: STORE,
            action,
            detail,
        }
    }

    /// The error for a Secret Service call that failed with `cause`.
    fn failure(action: &'static str, cause: Cause) -> StoreError {
        match cause {
            Cause::Locked(detail) => StoreError::KeyringLocked { detail },
            Cause::Unreachable(detail) => StoreError::NoSessionBus { detail },
            Cause::NoProvider(detail) => StoreError::NoSecretService { detail },
            // No answer is not a refusal.
            Cause::NoAnswer(_) => StoreError::Unanswered {
                detail: cause.to_string(),
            },
            cause => refused(action, cause.to_string()),
        }
    }

    /// [`failure`] for a call that changes an item. With no answer, the
    /// request may have been sent, and nothing says whether the change
    /// was made.
    fn change_failure(action: &'static str, cause: Cause) -> StoreError {
        match cause {
            Cause::NoAnswer(_) | Cause::Unsettled(_) => StoreError::ChangeUnsettled {
                detail: cause.to_string(),
            },
            cause => failure(action, cause),
        }
    }

    fn items() -> SecretItems<SessionItems> {
        SecretItems::new(SessionItems::within(TIMEOUT))
    }

    pub(super) fn read(id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        SecretItems::new(SessionItems::within(READ_TIMEOUT)).read(id)
    }

    /// [`read`] in a session whose bus address nothing listens on.
    #[cfg(test)]
    pub(super) fn read_unreachable(id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        SecretItems::new(SessionItems::within(READ_TIMEOUT).at("unix:path=/nonexistent/bus"))
            .read(id)
    }

    /// [`read`] when Secret Service gives no answer in [`READ_TIMEOUT`].
    #[cfg(test)]
    pub(super) fn read_unanswered(id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        let items = crate::secret_items::MemoryItems::default();
        items.set_failure(Some(Cause::NoAnswer(READ_TIMEOUT)));
        SecretItems::new(items).read(id)
    }

    pub(super) fn set(id: &str, value: &[u8], _proxy: &Path) -> Result<(), StoreError> {
        items().set(SERVICE, id, value)
    }

    pub(super) fn add_as_this_program(service: &str, id: &str, value: &[u8]) -> Result<(), String> {
        items().set(service, id, value).map_err(|e| e.to_string())
    }

    pub(super) fn list(_proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        items().list()
    }

    pub(super) fn remove(id: &str) -> Result<bool, StoreError> {
        items().remove(id)
    }

    pub(super) fn check_available() -> Result<(), StoreError> {
        items().check_available()
    }

    pub(super) fn holds(id: &str) -> Result<bool, StoreError> {
        items().holds(id)
    }
}

#[cfg(not(any(
    target_os = "macos",
    all(target_os = "linux", feature = "secret-service")
)))]
mod host {
    use super::{ItemInfo, ReadError, StoreError};
    use std::path::Path;
    use zeroize::Zeroizing;

    pub(super) fn read(_: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        Err(ReadError::Store(StoreError::Unsupported))
    }

    #[cfg(test)]
    pub(super) fn read_unreachable(id: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        read(id)
    }

    pub(super) fn set(_: &str, _: &[u8], _: &Path) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn add_as_this_program(_: &str, _: &str, _: &[u8]) -> Result<(), String> {
        Err(StoreError::Unsupported.to_string())
    }

    pub(super) fn list(_: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn remove(_: &str) -> Result<bool, StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn check_available() -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn holds(_: &str) -> Result<bool, StoreError> {
        Err(StoreError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// Items by service and account: the value, and whether the proxy reads
    /// it without a prompt.
    type FakeItems = BTreeMap<(String, String), (Vec<u8>, bool)>;

    /// A keychain in memory that refuses the add that `fail` names, or
    /// stores an item whose access control the proxy does not pass.
    #[derive(Default)]
    struct FakeKeychain {
        items: RefCell<FakeItems>,
        adds: Cell<usize>,
        /// The 1-based add that the keychain refuses.
        refuse_add: Option<usize>,
        /// The 1-based add that stores an item the proxy cannot read.
        lose_access_on: Option<usize>,
        staging_deletes: Cell<usize>,
        /// The 1-based delete under [`STAGING_SERVICE`] that the keychain
        /// refuses.
        refuse_staging_delete: Option<usize>,
        /// The 1-based add after which the read-back of the items fails.
        refuse_read_back_of: Option<usize>,
    }

    impl FakeKeychain {
        fn holding(id: &str, value: &[u8]) -> Self {
            let kc = Self::default();
            kc.items
                .borrow_mut()
                .insert((SERVICE.into(), id.into()), (value.to_vec(), true));
            kc
        }

        fn value(&self, service: &str, id: &str) -> Option<Vec<u8>> {
            self.items
                .borrow()
                .get(&(service.to_owned(), id.to_owned()))
                .map(|(v, _)| v.clone())
        }
    }

    impl Keychain for FakeKeychain {
        fn add(
            &self,
            service: &str,
            id: &str,
            value: &[u8],
            _proxy: &Path,
        ) -> Result<String, StoreError> {
            let n = self.adds.get() + 1;
            self.adds.set(n);
            if self.refuse_add == Some(n) {
                return Err(StoreError::Refused {
                    store: NATIVE_STORE,
                    action: "store the secret",
                    detail: "User canceled the operation.".into(),
                });
            }
            let key = (service.to_owned(), id.to_owned());
            let mut items = self.items.borrow_mut();
            assert!(!items.contains_key(&key), "duplicate add of {key:?}");
            items.insert(key, (value.to_vec(), self.lose_access_on != Some(n)));
            Ok(String::new())
        }

        fn item(&self, service: &str, id: &str, _proxy: &Path) -> Result<Option<bool>, StoreError> {
            if self.adds.get() > 0 && self.refuse_read_back_of == Some(self.adds.get()) {
                return Err(StoreError::Refused {
                    store: NATIVE_STORE,
                    action: "read the secret's access control",
                    detail: "The specified item could not be found in the keychain.".into(),
                });
            }
            Ok(self
                .items
                .borrow()
                .get(&(service.to_owned(), id.to_owned()))
                .map(|(_, access)| *access))
        }

        fn delete(&self, service: &str, id: &str) -> Result<bool, StoreError> {
            if service == STAGING_SERVICE {
                let n = self.staging_deletes.get() + 1;
                self.staging_deletes.set(n);
                if self.refuse_staging_delete == Some(n) {
                    return Err(StoreError::Refused {
                        store: NATIVE_STORE,
                        action: "remove the secret",
                        detail: "The user name or passphrase you entered is not correct.".into(),
                    });
                }
            }
            Ok(self
                .items
                .borrow_mut()
                .remove(&(service.to_owned(), id.to_owned()))
                .is_some())
        }
    }

    const PROXY: &str = "/opt/minimal/bin/bep";

    // Review finding 4369062269: a failed `set` never destroys a working
    // secret.
    #[test]
    fn secret_set_failure_keeps_the_old_secret() {
        let proxy = Path::new(PROXY);

        // The keychain refuses the new item: the old one stays.
        let kc = FakeKeychain {
            refuse_add: Some(1),
            ..FakeKeychain::holding("claude", b"old")
        };
        let err = set_item(&kc, "claude", b"new", proxy).expect_err("refused");
        assert!(err.to_string().contains("User canceled"), "{err}");
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"old"[..]));
        assert!(kc.value(STAGING_SERVICE, "claude").is_none());

        // The new item reads back without the proxy's access: the old one
        // stays.
        let kc = FakeKeychain {
            lose_access_on: Some(1),
            ..FakeKeychain::holding("claude", b"old")
        };
        let err = set_item(&kc, "claude", b"new", proxy).expect_err("refused");
        assert!(err.to_string().contains("no item for it"), "{err}");
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"old"[..]));
        assert!(kc.value(STAGING_SERVICE, "claude").is_none());

        // A replace that succeeds leaves one item, with the new value, and
        // no staged item.
        let kc = FakeKeychain::holding("claude", b"old");
        kc.items.borrow_mut().insert(
            (STAGING_SERVICE.into(), "claude".into()),
            (b"stale".to_vec(), true),
        );
        set_item(&kc, "claude", b"new", proxy).expect("stored");
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"new"[..]));
        assert!(kc.value(STAGING_SERVICE, "claude").is_none());
        assert_eq!(kc.items.borrow().len(), 1);

        // The keychain takes the staged item and then refuses the final
        // one: the error says that the old value is removed.
        let kc = FakeKeychain {
            refuse_add: Some(2),
            ..FakeKeychain::holding("claude", b"old")
        };
        let err = set_item(&kc, "claude", b"new", proxy).expect_err("refused");
        let text = err.to_string();
        assert!(
            text.contains("The old value of claude is removed"),
            "{text}"
        );
        assert!(text.contains("min secret set claude"), "{text}");
        assert!(kc.items.borrow().is_empty());

        // A first set stores the item directly.
        let kc = FakeKeychain::default();
        set_item(&kc, "claude", b"new", proxy).expect("stored");
        assert_eq!(kc.adds.get(), 1);
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"new"[..]));
    }

    // A set looks up only the item under its own service and identifier: an
    // item under another identifier, or a staged copy of this one, is not
    // the item it replaces, and stays as it was.
    #[test]
    fn set_item_looks_up_one_item_by_service_and_account() {
        let kc = FakeKeychain::holding("other", b"kept");
        kc.items.borrow_mut().insert(
            (STAGING_SERVICE.into(), "claude".into()),
            (b"staged".to_vec(), true),
        );
        assert_eq!(
            kc.item(SERVICE, "claude", Path::new(PROXY)).expect("read"),
            None
        );
        set_item(&kc, "claude", b"new", Path::new(PROXY)).expect("stored");
        // A first set: one add, with no staged copy made.
        assert_eq!(kc.adds.get(), 1);
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"new"[..]));
        assert_eq!(kc.value(SERVICE, "other").as_deref(), Some(&b"kept"[..]));
        assert_eq!(
            kc.value(STAGING_SERVICE, "claude").as_deref(),
            Some(&b"staged"[..])
        );
    }

    // Review finding 4369348719: a staging copy that the keychain does not
    // remove is reported, with the command that removes it.
    #[test]
    fn secret_set_reports_a_staging_copy_left_behind() {
        let proxy = Path::new(PROXY);
        let remedy = format!("security delete-generic-password -s {STAGING_SERVICE} -a claude");

        // The replace succeeds, and the cleanup after it is refused.
        let kc = FakeKeychain {
            refuse_staging_delete: Some(2),
            ..FakeKeychain::holding("claude", b"old")
        };
        let err = set_item(&kc, "claude", b"new", proxy).expect_err("reported");
        assert!(matches!(err, StoreError::StagingLeft { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("stored claude"), "{text}");
        assert!(text.contains("is not correct"), "{text}");
        assert!(text.contains(&remedy), "{text}");
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"new"[..]));
        assert_eq!(
            kc.value(STAGING_SERVICE, "claude").as_deref(),
            Some(&b"new"[..])
        );

        // The final add is refused, and so is the cleanup: the error names
        // both.
        let kc = FakeKeychain {
            refuse_add: Some(2),
            refuse_staging_delete: Some(2),
            ..FakeKeychain::holding("claude", b"old")
        };
        let text = set_item(&kc, "claude", b"new", proxy)
            .expect_err("refused")
            .to_string();
        assert!(
            text.contains("The old value of claude is removed"),
            "{text}"
        );
        assert!(text.contains(&remedy), "{text}");
    }

    // Review finding 4369438788: a first add that reads back without the
    // proxy's access leaves no item that holds the value.
    #[test]
    fn secret_set_first_add_without_proxy_access_leaves_no_item() {
        let kc = FakeKeychain {
            lose_access_on: Some(1),
            ..FakeKeychain::default()
        };
        let err = set_item(&kc, "claude", b"new", Path::new(PROXY)).expect_err("refused");
        assert!(err.to_string().contains("no item for it"), "{err}");
        assert!(!err.to_string().contains("can remain"), "{err}");
        assert!(kc.value(SERVICE, "claude").is_none());
        assert!(kc.items.borrow().is_empty());
    }

    // Review finding 4369498405: a read-back that fails after the add
    // leaves no item behind, and the old secret stays.
    #[test]
    fn secret_set_read_back_failure_removes_the_new_item() {
        let kc = FakeKeychain {
            refuse_read_back_of: Some(1),
            ..FakeKeychain::default()
        };
        let err = set_item(&kc, "claude", b"new", Path::new(PROXY)).expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("reading it back failed"), "{text}");
        assert!(!text.contains("can remain"), "{text}");
        assert!(kc.items.borrow().is_empty());

        let kc = FakeKeychain {
            refuse_read_back_of: Some(1),
            ..FakeKeychain::holding("claude", b"old")
        };
        let err = set_item(&kc, "claude", b"new", Path::new(PROXY)).expect_err("refused");
        assert!(err.to_string().contains("reading it back failed"), "{err}");
        assert_eq!(kc.value(SERVICE, "claude").as_deref(), Some(&b"old"[..]));
        assert!(kc.value(STAGING_SERVICE, "claude").is_none());
    }

    /// A proxy program `bep` in a fresh directory, with the file and
    /// directory modes given.
    #[cfg(unix)]
    fn proxy_with_modes(file: u32, dir: u32) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let bep = bin.join("bep");
        std::fs::write(&bep, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bep, std::fs::Permissions::from_mode(file)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(dir)).unwrap();
        (tmp, bep)
    }

    // Review finding 4369438785: the access control trusts only a proxy
    // that nobody but the current user or root can change.
    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_admits_a_private_program() {
        let (_tmp, bep) = proxy_with_modes(0o755, 0o755);
        check_proxy_binary(&bep).expect("admitted");
    }

    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_a_group_writable_file() {
        let (_tmp, bep) = proxy_with_modes(0o775, 0o755);
        let err = check_proxy_binary(&bep).expect_err("refused");
        let text = err.to_string();
        assert!(matches!(err, StoreError::ProxyUnsafe { .. }), "{text}");
        assert!(text.contains(&bep.display().to_string()), "{text}");
        assert!(text.contains("mode 0775"), "{text}");
        assert!(text.contains("Reinstall Minimal"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_a_world_writable_directory() {
        let (_tmp, bep) = proxy_with_modes(0o755, 0o777);
        let err = check_proxy_binary(&bep).expect_err("refused");
        let text = err.to_string();
        assert!(matches!(err, StoreError::ProxyUnsafe { .. }), "{text}");
        let dir = bep.parent().unwrap().display().to_string();
        assert!(
            text.contains(&format!("its directory {dir} (mode 0777)")),
            "{text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_another_owner() {
        if effective_uid() == 0 {
            // Root owns the file, and root is always admitted.
            return;
        }
        let (_tmp, bep) = proxy_with_modes(0o755, 0o755);
        let err = check_proxy_binary_as(&bep, effective_uid() + 1).expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("owned by user id"), "{text}");
    }

    // Review finding 4369498404: a directory that another user owns can
    // have the program replaced, at any level above it.
    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_a_parent_owned_by_another_user() {
        let uid = 1000;
        let dir = Path::new("/opt/minimal/bin");
        for parent in [true, false] {
            let reason =
                directory_unsafe_because(dir, uid + 1, 0o755, uid, parent).expect("refused");
            assert!(
                reason.contains("its directory /opt/minimal/bin is owned by user id 1001"),
                "{reason}"
            );
        }
        assert!(directory_unsafe_because(dir, uid, 0o755, uid, true).is_none());
        assert!(directory_unsafe_because(dir, 0, 0o755, uid, true).is_none());
        // A sticky directory above the parent, as `/tmp` is, is admitted.
        assert!(directory_unsafe_because(dir, 0, 0o1777, uid, false).is_none());
        assert!(directory_unsafe_because(dir, 0, 0o1777, uid, true).is_some());

        if effective_uid() == 0 {
            // Root can give the directory away, so the walk itself is
            // pinned too.
            let (_tmp, bep) = proxy_with_modes(0o755, 0o755);
            let bin = bep.parent().unwrap();
            let bin_c = std::ffi::CString::new(bin.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `bin_c` is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::chown(bin_c.as_ptr(), 12345, 0) }, 0);
            let err = check_proxy_binary(&bep).expect_err("refused");
            assert!(err.to_string().contains("owned by user id 12345"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_a_group_writable_grandparent() {
        use std::os::unix::fs::PermissionsExt as _;
        let (tmp, bep) = proxy_with_modes(0o755, 0o755);
        let grandparent = tmp.path();
        std::fs::set_permissions(grandparent, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = check_proxy_binary(&bep).expect_err("refused");
        let text = err.to_string();
        assert!(matches!(err, StoreError::ProxyUnsafe { .. }), "{text}");
        assert!(
            text.contains(&format!(
                "its directory {} (mode 0775)",
                grandparent.display()
            )),
            "{text}"
        );
        std::fs::set_permissions(grandparent, std::fs::Permissions::from_mode(0o700)).unwrap();
        check_proxy_binary(&bep).expect("admitted");
    }

    #[cfg(unix)]
    #[test]
    fn secret_proxy_check_refuses_a_symbolic_link() {
        let (tmp, bep) = proxy_with_modes(0o755, 0o755);
        let link = tmp.path().join("bin").join("link");
        std::os::unix::fs::symlink(&bep, &link).unwrap();
        let err = check_proxy_binary(&link).expect_err("refused");
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    // Review finding 4369348721: the arguments never carry an identifier that
    // `valid_id` refuses, and the value is not among them.
    #[test]
    fn add_args_refuse_an_invalid_id() {
        for id in ["a\" -A \"b", "claude -A", "", "-A"] {
            let err = add_args(SERVICE, id).expect_err("refused");
            assert!(matches!(err, StoreError::InvalidId(_)), "{id:?}: {err:?}");
            assert!(err.to_string().contains("is not a name a secret can have"));
        }
        assert_eq!(
            add_args(SERVICE, "claude").unwrap(),
            ["store-add", "claude"]
        );
        assert_eq!(
            add_args(STAGING_SERVICE, "claude").unwrap(),
            ["store-add", "--staging", "claude"]
        );
    }

    // An item from a build before `bep store-add` is in the partition of
    // Apple's tools. Its application list names the proxy, and the proxy's
    // read still fails with `errSecAuthFailed`, so a listing must not say the
    // proxy reads it. An item the proxy created is in the proxy's partition.
    #[test]
    fn a_listing_admits_only_the_proxys_own_partition() {
        let dump = |entry: &str| {
            format!(
                "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"claude\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 3 entries
    entry 0:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: dev.minimal.secret
        applications (1):
            0: {PROXY} (OK)
{entry}    entry 2:
        authorizations (1): change_acl
        don't-require-password
        description: dev.minimal.secret
        applications (0):
"
            )
        };
        let access = |list: &str, own: Option<&str>| {
            let entry = format!(
                "    entry 1:
        authorizations (1): partition_id
        don't-require-password
        description: {list}
        applications: <null>
"
            );
            parse_dump(&dump(&entry), Path::new(PROXY), own)[0].proxy_access
        };
        let team = Some("teamid:3G47C5HY64");
        let hash = Some("cdhash:a9ee3da6b0baa9708b950b24f8a999741f97d3b4");
        assert!(access("teamid:3G47C5HY64", team));
        assert!(access(
            "cdhash:a9ee3da6b0baa9708b950b24f8a999741f97d3b4",
            hash
        ));
        assert!(access("apple-tool:,teamid:3G47C5HY64", team));
        assert!(!access("apple-tool:", team));
        assert!(!access("apple-tool:,apple:", team));
        assert!(!access("teamid:AAAAAAAAAA", team));
        assert!(!access("teamid:3G47C5HY64", hash));
        assert!(!access("teamid:3G47C5HY64", None));
        // An item with no partition list does not name the proxy's partition.
        assert!(!parse_dump(&dump(""), Path::new(PROXY), team)[0].proxy_access);
    }

    fn acl(authorizations: &[&str], applications: Option<&[&str]>, description: &str) -> AclEntry {
        AclEntry {
            authorizations: authorizations.iter().map(|a| (*a).to_owned()).collect(),
            applications: applications.map(|apps| apps.iter().map(|a| (*a).to_owned()).collect()),
            description: description.to_owned(),
        }
    }

    /// The partition list as the API gives it: a hex-encoded property list.
    fn partition_plist(names: &[&str]) -> String {
        let strings: String = names
            .iter()
            .map(|n| format!("<string>{n}</string>"))
            .collect();
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Partitions</key><array>{strings}</array></dict></plist>"
        );
        xml.bytes().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn one_item_admits_the_proxy_only_with_decrypt_and_its_partition() {
        let proxy = Path::new("/opt/bep");
        let decrypt = acl(&[AUTH_DECRYPT], Some(&["/opt/bep"]), "dev.minimal.secret");
        let partition = acl(
            &[AUTH_PARTITION],
            None,
            &partition_plist(&["apple-tool:", "teamid:3G47C5HY64"]),
        );
        let held = vec![decrypt.clone(), partition.clone()];
        assert_eq!(item_access(&[], proxy, Some("teamid:3G47C5HY64")), None);
        assert_eq!(
            item_access(
                std::slice::from_ref(&held),
                proxy,
                Some("teamid:3G47C5HY64")
            ),
            Some(true)
        );
        // Another partition, no partition, or no decrypt entry for the proxy.
        assert_eq!(
            item_access(std::slice::from_ref(&held), proxy, Some("teamid:OTHER")),
            Some(false)
        );
        assert_eq!(
            item_access(std::slice::from_ref(&held), proxy, None),
            Some(false)
        );
        let other_app = acl(&[AUTH_DECRYPT], Some(&["/usr/bin/other"]), "");
        assert_eq!(
            item_access(
                &[vec![other_app, partition.clone()]],
                proxy,
                Some("teamid:3G47C5HY64")
            ),
            Some(false)
        );
        // Any application lists no program, as the dump reads `<null>`.
        let any_app = acl(&[AUTH_DECRYPT], None, "");
        assert_eq!(
            item_access(
                &[vec![any_app, partition.clone()]],
                proxy,
                Some("teamid:3G47C5HY64")
            ),
            Some(false)
        );
        // Every copy in the search list must admit the proxy.
        let no_partition = vec![decrypt.clone()];
        assert_eq!(
            item_access(
                &[held.clone(), no_partition],
                proxy,
                Some("teamid:3G47C5HY64")
            ),
            Some(false)
        );
        assert_eq!(
            item_access(&[held.clone(), held], proxy, Some("teamid:3G47C5HY64")),
            Some(true)
        );
    }

    #[test]
    fn one_item_admits_a_bundled_proxy() {
        let proxy = Path::new("/Applications/bep.app/Contents/MacOS/bep");
        let entries = vec![
            acl(
                &[AUTH_DECRYPT, "ACLAuthorizationEncrypt"],
                Some(&["/Applications/bep.app"]),
                "",
            ),
            acl(
                &[AUTH_PARTITION],
                None,
                &partition_plist(&["teamid:3G47C5HY64"]),
            ),
        ];
        assert_eq!(
            item_access(&[entries], proxy, Some("teamid:3G47C5HY64")),
            Some(true)
        );
    }

    #[test]
    fn a_partition_list_reads_hex_plist_or_plain_text() {
        assert_eq!(
            partition_names(&partition_plist(&["apple-tool:", "cdhash:abc"])),
            vec!["apple-tool:".to_owned(), "cdhash:abc".to_owned()]
        );
        assert_eq!(
            partition_names("teamid:3G47C5HY64, apple:"),
            vec!["teamid:3G47C5HY64".to_owned(), "apple:".to_owned()]
        );
        assert!(partition_names("").is_empty());
        assert_eq!(hex_decode("4a"), Some(vec![0x4a]));
        assert_eq!(hex_decode("4"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn a_signature_gives_the_partition_of_the_program() {
        assert_eq!(
            signature_partition("CDHash=a9ee\nSignature=adhoc\nTeamIdentifier=not set\n"),
            Some("cdhash:a9ee".to_owned())
        );
        assert_eq!(
            signature_partition("CDHash=a9ee\nTeamIdentifier=3G47C5HY64\n"),
            Some("teamid:3G47C5HY64".to_owned())
        );
        assert_eq!(
            signature_partition("code object is not signed at all\n"),
            None
        );
    }

    /// `codesign` on a real program. This test binary is signed ad hoc by the
    /// linker, so it is in a `cdhash:` partition.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_partition_of_a_real_program_comes_from_its_signature() {
        let exe = std::env::current_exe().expect("test binary path");
        let partition = host::proxy_partition(&exe).expect("a signature");
        let hash = partition.strip_prefix("cdhash:").expect("ad hoc signature");
        assert_eq!(hash.len(), 40, "{partition}");
        assert_eq!(host::proxy_partition(Path::new("/no/such/bep")), None);
    }

    // An installed proxy runs from a bundle, and the keychain records the
    // bundle: `dump-keychain -a` then prints the bundle's path, with the
    // requirement line under it, and never the inner binary. A listing must
    // still admit the bundle's own proxy, and neither a directory on its
    // path, another bundle, nor another program inside the bundle.
    #[test]
    fn secret_item_acl_admits_a_bundled_proxy() {
        let proxy = Path::new("/Users/me/.local/bin/bep.app/Contents/MacOS/bep");
        let dump = "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"claude\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 1 entries
    entry 0:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: Minimal secret claude
        applications (1):
            0: /Users/me/.local/bin/bep.app (OK)
            requirement: identifier \"dev.minimal.bep\" and anchor apple generic and certificate leaf[subject.CN] = \"Minimal\"
    entry 1:
        authorizations (1): partition_id
        description: teamid:3G47C5HY64
        applications: <null>
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"other\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 1 entries
    entry 0:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: Minimal secret other
        applications (1):
            0: /Applications/Other.app (OK)
    entry 1:
        authorizations (1): partition_id
        description: teamid:3G47C5HY64
        applications: <null>
keychain: \"/Users/me/Library/Keychains/login.keychain-db\"
class: \"genp\"
attributes:
    \"acct\"<blob>=\"partial\"
    \"svce\"<blob>=\"dev.minimal.secret\"
access: 1 entries
    entry 0:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        don't-require-password
        description: Minimal secret partial
        applications (1):
            0: /Users/me/.local/bin (OK)
    entry 1:
        authorizations (1): partition_id
        description: teamid:3G47C5HY64
        applications: <null>
";
        let own = Some("teamid:3G47C5HY64");
        assert_eq!(
            parse_dump(dump, proxy, own),
            vec![
                ItemInfo {
                    id: "claude".into(),
                    proxy_access: true
                },
                ItemInfo {
                    id: "other".into(),
                    proxy_access: false
                },
                ItemInfo {
                    id: "partial".into(),
                    proxy_access: false
                },
            ]
        );
        for other in ["helper", "nested/bep"] {
            let other = format!("/Users/me/.local/bin/bep.app/Contents/MacOS/{other}");
            assert!(
                parse_dump(dump, Path::new(&other), own)
                    .iter()
                    .all(|item| !item.proxy_access),
                "{other} is not the bundle's main program"
            );
        }
    }

    /// A proxy program that exits without reading the value, such as an older
    /// `bep` with no `store-add`, closes the pipe. Its exit status and stderr
    /// still reach the caller. The value is larger than a pipe's buffer, so
    /// the write always meets the closed pipe.
    #[cfg(target_os = "macos")]
    #[test]
    fn run_keeps_the_stderr_of_a_program_that_reads_no_input() {
        let out = host::run(
            Path::new("/bin/sh"),
            "store the secret",
            &["-c", "echo no such subcommand >&2; exit 3"],
            Some(&vec![0; 1 << 20]),
        )
        .expect("the program ran");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stderr, b"no such subcommand\n");
    }

    /// The BEP-051 leg on a real keychain: set, list, set again and remove
    /// on [`HostStore`]. Run it on a Mac with
    /// `cargo nextest run -p bep host_store_set_list_rm_round_trip --run-ignored only`.
    /// It names a copy of the built `bep` in a temporary directory as the
    /// proxy, so the access control is the one the proxy gets: an unsigned
    /// program at a path, not an Apple-signed one.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the login keychain of a real Mac"]
    fn host_store_set_list_rm_round_trip() {
        let store = HostStore;
        // Cargo names the built binary for this test when it can. Else the
        // binary is beside `deps/`, where this test binary is.
        let built = option_env!("CARGO_BIN_EXE_bep").map_or_else(
            || {
                let exe = std::env::current_exe().expect("test binary path");
                exe.parent()
                    .and_then(Path::parent)
                    .expect("target directory")
                    .join("bep")
            },
            PathBuf::from,
        );
        assert!(built.is_file(), "build `bep` first: {}", built.display());
        let dir = tempfile::tempdir().expect("temporary directory");
        let proxy_copy = dir.path().join("bep");
        std::fs::copy(&built, &proxy_copy).expect("copy of bep");
        let proxy_copy = std::fs::canonicalize(&proxy_copy).expect("canonical path");
        println!(
            "proxy: {} (copied from {})",
            proxy_copy.display(),
            built.display()
        );
        let proxy = proxy_copy.as_path();
        let id = format!("minimal-round-trip-{}", std::process::id());
        let mine = |items: Vec<ItemInfo>| -> Vec<ItemInfo> {
            items.into_iter().filter(|item| item.id == id).collect()
        };

        let one = |id: &str| host::SecurityTool.item(SERVICE, id, proxy).expect("item");
        assert_eq!(one(&id), None, "no item before the first set");

        let started = std::time::Instant::now();
        store.set(&id, b"first", proxy).expect("first set");
        println!("first set took {:?}", started.elapsed());
        assert_eq!(
            one(&id),
            Some(true),
            "the lookup of one item agrees with the add"
        );
        let items = mine(store.list(proxy).expect("list"));
        println!("after set: {items:?}");
        assert_eq!(
            items,
            vec![ItemInfo {
                id: id.clone(),
                proxy_access: true
            }]
        );

        // The proxy copy created the item, and this test is another program.
        // The keychain refuses it with prompts off, where it would ask.
        assert!(matches!(store.read(&id), Err(ReadError::Disabled(_))));

        let started = std::time::Instant::now();
        store.set(&id, b"second", proxy).expect("second set");
        println!("second set took {:?}", started.elapsed());
        assert_eq!(one(&id), Some(true));
        let items = mine(store.list(proxy).expect("list"));
        println!("after set again: {items:?}");
        assert_eq!(
            items,
            vec![ItemInfo {
                id: id.clone(),
                proxy_access: true
            }]
        );

        assert!(store.remove(&id).expect("remove"), "the item was held");
        let items = mine(store.list(proxy).expect("list"));
        println!("after remove: {items:?}");
        assert!(items.is_empty());
        assert_eq!(one(&id), None, "no item after remove");
        assert!(!store.remove(&id).expect("remove again"));
    }

    /// The read that `bep serve` makes, on an item the same program created:
    /// the keychain lets it past the partition and the application list.
    /// Run it on a Mac with
    /// `cargo nextest run -p bep host_store_reads_an_item_this_program_added --run-ignored only`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the login keychain of a real Mac"]
    fn host_store_reads_an_item_this_program_added() {
        let store = HostStore;
        let id = format!("minimal-own-item-{}", std::process::id());
        assert!(!store.holds(&id).expect("lookup"), "no item before the add");
        add_as_this_program(SERVICE, &id, b"value").expect("add");
        let held = store.holds(&id);
        let read = store.read(&id);
        assert!(store.remove(&id).expect("remove"), "the item was held");
        assert!(held.expect("lookup"), "the lookup finds the added item");
        assert_eq!(read.expect("read").as_slice(), b"value");
        assert!(!store.holds(&id).expect("lookup"), "no item after remove");
    }

    // A creation asks whether an item is stored, by identifier, and a
    // message names the store where it lives: Secret Service on Linux, and
    // the keychain store on macOS and in a store held in memory.
    #[test]
    fn store_holds_by_identifier_and_names_its_place() {
        let store = MemorySecretStore::default();
        assert!(!store.holds("claude").unwrap());
        store.set("claude", b"v", Path::new("/bep")).unwrap();
        assert!(store.holds("claude").unwrap());
        assert!(!store.holds("linear").unwrap());
        assert_eq!(store.place(), "the keychain store");
        assert!(matches!(
            HostStore.holds("-x"),
            Err(StoreError::InvalidId(_))
        ));
        let host = if cfg!(target_os = "linux") {
            "Secret Service"
        } else {
            "the keychain store"
        };
        assert_eq!(HostStore.place(), host);
    }

    // On Linux, `min secret` and the proxy's read use Secret Service: set,
    // list, read, replace and remove, by identifier, with no value in a
    // listing.
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    #[test]
    fn linux_native_store_is_secret_service() {
        use crate::secret_items::{Items as _, MemoryItems};

        let items = MemoryItems::default();
        let store = host::SecretItems::new(items.clone());
        store.check_available().expect("Secret Service answers");
        assert!(store.list().unwrap().is_empty());
        assert!(matches!(store.read("claude"), Err(ReadError::Deleted(id)) if id == "claude"));

        store.set(SERVICE, "claude", b"sk-ant-one\n").unwrap();
        store.set(SERVICE, "linear", b"lin-two").unwrap();
        assert_eq!(
            store.list().unwrap(),
            vec![
                ItemInfo {
                    id: "claude".into(),
                    proxy_access: true
                },
                ItemInfo {
                    id: "linear".into(),
                    proxy_access: true
                },
            ]
        );
        assert_eq!(store.read("claude").unwrap().as_slice(), b"sk-ant-one\n");
        assert!(store.holds("claude").unwrap());
        assert!(!store.holds("absent").unwrap());
        // Each item carries the two attributes that an item written before
        // carries, so a host's stored secrets read the same.
        assert_eq!(
            items
                .lookup(&[("service", SERVICE), ("id", "linear")])
                .unwrap()
                .unwrap()
                .as_slice(),
            b"lin-two"
        );

        // A replaced value is the one the next read returns (BEP-054).
        store.set(SERVICE, "claude", b"sk-ant-new").unwrap();
        assert_eq!(store.read("claude").unwrap().as_slice(), b"sk-ant-new");
        assert_eq!(items.len(), 2);

        assert!(store.remove("claude").unwrap());
        assert!(!store.remove("claude").unwrap(), "no item the second time");
        assert!(matches!(store.read("claude"), Err(ReadError::Deleted(_))));
        assert!(!store.holds("claude").unwrap(), "no item after remove");
        assert_eq!(store.list().unwrap().len(), 1);

        // A value is bytes: one that is not text, and one of 64 KiB, are
        // kept whole.
        let binary: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
        store.set(SERVICE, "linear", &binary).unwrap();
        assert_eq!(store.read("linear").unwrap().as_slice(), &binary[..]);

        // An item under another service is not one of the store's.
        items
            .store("other", &[("service", "dev.other"), ("id", "theirs")], b"v")
            .unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(!store.holds("theirs").unwrap());

        assert!(matches!(
            store.set(SERVICE, "--label=x", b"v"),
            Err(StoreError::InvalidId(_))
        ));
        assert!(matches!(store.remove("-x"), Err(StoreError::InvalidId(_))));
    }

    // A Linux host without a usable Secret Service gets a refusal that
    // names what to install or set up, and a locked keyring one that says
    // so. Neither shows a prompt.
    #[cfg(all(target_os = "linux", feature = "secret-service"))]
    #[test]
    fn linux_native_store_refusals_name_what_to_install() {
        use crate::secret_items::{Cause, MemoryItems};

        let items = MemoryItems::default();
        let store = host::SecretItems::new(items.clone());

        // No bus and no provider are two situations with two next steps.
        items.set_failure(Some(Cause::Unreachable(
            "no session bus answered: no such file".into(),
        )));
        let err = store.check_available().expect_err("unreachable");
        assert_eq!(
            err.to_string(),
            "`min secret` keeps secrets in Secret Service on Linux, and this process reached no D-Bus session bus: no session bus answered: no such file. Run the command again in a login session where DBUS_SESSION_BUS_ADDRESS names a running session bus."
        );
        assert!(matches!(store.list(), Err(StoreError::NoSessionBus { .. })));
        assert!(matches!(
            store.read("claude"),
            Err(ReadError::Store(StoreError::NoSessionBus { .. }))
        ));

        items.set_failure(Some(Cause::NoProvider("ServiceUnknown".into())));
        let err = store.check_available().expect_err("no provider");
        assert_eq!(
            err.to_string(),
            "`min secret` keeps secrets in Secret Service on Linux, and the D-Bus session bus has no Secret Service: ServiceUnknown. Install a Secret Service provider such as GNOME Keyring (the `gnome-keyring` package), and run the command again in a login session that starts it."
        );
        assert!(matches!(
            store.list(),
            Err(StoreError::NoSecretService { .. })
        ));
        assert!(matches!(
            store.read("claude"),
            Err(ReadError::Store(StoreError::NoSecretService { .. }))
        ));
        items.set_failure(None);

        // A locked keyring lists its items and says which are held. It
        // gives no value and takes no change, and a held item is never
        // read as deleted.
        store.set(SERVICE, "claude", b"v").unwrap();
        items.set_locked(true);
        store.check_available().expect("a locked keyring answers");
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.holds("claude").unwrap());
        let err = store.set(SERVICE, "claude", b"new").expect_err("locked");
        assert_eq!(
            err.to_string(),
            "`min secret` keeps secrets in Secret Service on Linux, and its keyring is locked: the default collection is locked. Unlock the login keyring, then run the command again."
        );
        assert!(matches!(
            store.read("claude"),
            Err(ReadError::Store(StoreError::KeyringLocked { .. }))
        ));
        assert!(matches!(
            store.remove("claude"),
            Err(StoreError::KeyringLocked { .. })
        ));
        assert!(matches!(store.read("absent"), Err(ReadError::Deleted(_))));
        items.set_locked(false);
        assert_eq!(store.read("claude").unwrap().as_slice(), b"v");

        // A Secret Service that does not answer in time is refused with
        // the time it was given, and the proxy's read is refused with it.
        assert_eq!(host::READ_TIMEOUT, std::time::Duration::from_secs(10));
        items.set_failure(Some(Cause::NoAnswer(host::READ_TIMEOUT)));
        let err = store.check_available().expect_err("timed out");
        assert_eq!(
            err.to_string(),
            "`min secret` keeps secrets in Secret Service on Linux. Secret Service did not answer in 10 s."
        );
        assert!(matches!(
            store.read("claude"),
            Err(ReadError::Store(StoreError::Unanswered { .. }))
        ));

        // A change with no answer may still be made, and the error says so.
        items.set_failure(Some(Cause::NoAnswer(std::time::Duration::from_secs(60))));
        let err = store.set(SERVICE, "claude", b"new").expect_err("no answer");
        assert_eq!(
            err.to_string(),
            "Secret Service did not answer in 60 s. Secret Service can still make the change, or it made a part of it. Run the command again."
        );
        // So does a removal that stopped part of the way.
        items.set_failure(Some(Cause::Unsettled(
            "Secret Service removed 1 of 2 matching items, and then: a matching item is locked"
                .into(),
        )));
        let err = store.remove("claude").expect_err("in part");
        assert!(matches!(err, StoreError::ChangeUnsettled { .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            "Secret Service removed 1 of 2 matching items, and then: a matching item is locked. Secret Service can still make the change, or it made a part of it. Run the command again."
        );
    }
}
