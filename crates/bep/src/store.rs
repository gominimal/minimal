//! Secrets that `min secret` stores in the host's native store, by
//! identifier (BEP-050 to BEP-053).
//!
//! The native store is the macOS Keychain. Each secret is one generic
//! password item under [`SERVICE`], with the identifier as its account. The
//! item's access control names one trusted application: the proxy binary.
//! So the proxy reads the item without a prompt, and every other application,
//! `security` included, prompts (BEP-051).
//!
//! Other hosts have no native store yet: the Linux default waits on the store
//! roster. [`HostStore`] there refuses every operation, and says so.
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

use zeroize::{Zeroize as _, Zeroizing};

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
        "This host has no secret store that `min secret` can use. `min secret` stores secrets only in the macOS Keychain."
    )]
    Unsupported,
    /// The proxy path cannot go in the item's access control.
    #[error(
        "The proxy path {0} contains a quote, a backslash or a line break, so the keychain cannot name it."
    )]
    ProxyPath(PathBuf),
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

/// The line that `security -i` reads to store `value` under `id` with
/// `proxy` as the one trusted application.
///
/// The value goes in hexadecimal (`-X`), so no character of it needs
/// quoting, and it goes on the tool's standard input, never on a command
/// line. `-T` names the proxy. Without `-A`, every other application
/// prompts. The line has no `-U`: an update in place keeps the access
/// control of the item held under `id`, so the caller removes that item
/// first. The caller zeroizes the line.
///
/// # Errors
///
/// When `proxy` holds a character that the line cannot quote.
pub fn keychain_add_line(id: &str, value: &[u8], proxy: &Path) -> Result<String, StoreError> {
    add_line(SERVICE, id, value, proxy)
}

/// [`keychain_add_line`] under `service`.
fn add_line(service: &str, id: &str, value: &[u8], proxy: &Path) -> Result<String, StoreError> {
    // `security -i` splits the line on spaces and quotes, so an `id` that
    // `valid_id` refuses can add options such as `-A`.
    if !valid_id(id) {
        return Err(StoreError::InvalidId(id.to_owned()));
    }
    let proxy_text = proxy.to_string_lossy();
    if proxy_text.contains(['"', '\\', '\n', '\r']) {
        return Err(StoreError::ProxyPath(proxy.to_path_buf()));
    }
    let mut hex = String::with_capacity(value.len() * 2);
    for b in value {
        hex.push(char::from(HEX[usize::from(b >> 4)]));
        hex.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    // `valid_id` admitted `id` above, so it needs no quoting.
    let line = format!(
        "add-generic-password -s {service} -a {id} -l \"Minimal secret {id}\" -T \"{proxy_text}\" -X {hex}\n"
    );
    hex.zeroize();
    Ok(line)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The secret items in the output of `security dump-keychain -a`: each
/// item under [`SERVICE`], by account, with whether an access-control entry
/// that allows `decrypt` lists `proxy` among its applications.
#[must_use]
pub fn parse_dump(dump: &str, proxy: &Path) -> Vec<ItemInfo> {
    parse_dump_service(dump, SERVICE, proxy)
}

/// [`parse_dump`] for the items under `service`.
fn parse_dump_service(dump: &str, service: &str, proxy: &Path) -> Vec<ItemInfo> {
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
        let proxy_access = record
            .split("entry ")
            .skip(1)
            .any(|entry| entry_admits(entry, &proxy));
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
            listed |= path == proxy;
        }
    }
    decrypt && listed
}

/// The keychain operations that [`set_item`] puts in order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
trait Keychain {
    /// Add an item under `service` and `id` that names `proxy` as its one
    /// trusted application. On success, what the tool printed as a warning.
    fn add(
        &self,
        service: &str,
        id: &str,
        value: &[u8],
        proxy: &Path,
    ) -> Result<String, StoreError>;

    /// The items under `service`, with whether each one admits `proxy`.
    fn items(&self, service: &str, proxy: &Path) -> Result<Vec<ItemInfo>, StoreError>;

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
    let held = kc.items(SERVICE, proxy)?.iter().any(|item| item.id == id);
    if !held {
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
    // `security -i` can exit 0 after a refused command, and it can warn on
    // stderr after a write that succeeded. So the item itself, read back
    // with its access control, decides the result.
    let mut detail = match kc.items(service, proxy) {
        Ok(items) if items.iter().any(|item| item.id == id && item.proxy_access) => {
            return Ok(());
        }
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
/// `/usr/bin/security`. Other hosts refuse every operation.
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
        ItemInfo, Keychain, NATIVE_STORE, ReadError, SERVICE, StoreError, add_line, parse_dump,
        parse_dump_service, set_item,
    };
    use std::io::Write as _;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use zeroize::{Zeroize as _, Zeroizing};

    const SECURITY: &str = "/usr/bin/security";
    /// `security` exits 44 when no item matches.
    const NOT_FOUND: i32 = 44;

    fn run(
        action: &'static str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Result<std::process::Output, StoreError> {
        let refused = |detail: String| StoreError::Refused {
            store: NATIVE_STORE,
            action,
            detail,
        };
        let mut cmd = Command::new(SECURITY);
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
            pipe.write_all(input.as_bytes())
                .map_err(|e| refused(e.to_string()))?;
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

    /// The keychain through `/usr/bin/security`.
    struct SecurityTool;

    impl Keychain for SecurityTool {
        fn add(
            &self,
            service: &str,
            id: &str,
            value: &[u8],
            proxy: &Path,
        ) -> Result<String, StoreError> {
            let mut line = add_line(service, id, value, proxy)?;
            let out = run("store the secret", &["-i"], Some(&line));
            line.zeroize();
            let out = out?;
            if !out.status.success() {
                return Err(refused("store the secret", &out.stderr));
            }
            Ok(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }

        fn items(&self, service: &str, proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
            let out = dump()?;
            Ok(parse_dump_service(&out, service, proxy))
        }

        fn delete(&self, service: &str, id: &str) -> Result<bool, StoreError> {
            delete(service, id)
        }
    }

    pub(super) fn set(id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
        set_item(&SecurityTool, id, value, proxy)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn check_available() -> Result<(), StoreError> {
        Ok(())
    }

    /// The output of `dump-keychain -a`.
    fn dump() -> Result<String, StoreError> {
        // `dump-keychain` without `-d` decrypts nothing, so it prints no
        // value and asks for no access.
        let out = run("list the secrets", &["dump-keychain", "-a"], None)?;
        if !out.status.success() {
            return Err(refused("list the secrets", &out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub(super) fn list(proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        Ok(parse_dump(&dump()?, proxy))
    }

    pub(super) fn remove(id: &str) -> Result<bool, StoreError> {
        delete(SERVICE, id)
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
            Err(e) if DENIED.contains(&e.code()) => Err(ReadError::Disabled(id.to_owned())),
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

#[cfg(not(target_os = "macos"))]
mod host {
    use super::{ItemInfo, ReadError, StoreError};
    use std::path::Path;
    use zeroize::Zeroizing;

    pub(super) fn read(_: &str) -> Result<Zeroizing<Vec<u8>>, ReadError> {
        Err(ReadError::Store(StoreError::Unsupported))
    }

    pub(super) fn set(_: &str, _: &[u8], _: &Path) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
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

        fn items(&self, service: &str, _proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
            if self.adds.get() > 0 && self.refuse_read_back_of == Some(self.adds.get()) {
                return Err(StoreError::Refused {
                    store: NATIVE_STORE,
                    action: "list the secrets",
                    detail: "The specified item could not be found in the keychain.".into(),
                });
            }
            Ok(self
                .items
                .borrow()
                .iter()
                .filter(|((s, _), _)| s == service)
                .map(|((_, id), (_, access))| ItemInfo {
                    id: id.clone(),
                    proxy_access: *access,
                })
                .collect())
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

    // Review finding 4369348721: the line that `security -i` parses never
    // carries an identifier that `valid_id` refuses.
    #[test]
    fn keychain_add_line_refuses_an_invalid_id() {
        let proxy = Path::new(PROXY);
        for id in ["a\" -A \"b", "claude -A", "", "-A"] {
            let err = keychain_add_line(id, b"v", proxy).expect_err("refused");
            assert!(matches!(err, StoreError::InvalidId(_)), "{id:?}: {err:?}");
            assert!(err.to_string().contains("is not a name a secret can have"));
        }
        keychain_add_line("claude", b"v", proxy).expect("valid");
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

        store.set(&id, b"first", proxy).expect("first set");
        let items = mine(store.list(proxy).expect("list"));
        println!("after set: {items:?}");
        assert_eq!(
            items,
            vec![ItemInfo {
                id: id.clone(),
                proxy_access: true
            }]
        );

        store.set(&id, b"second", proxy).expect("second set");
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
        assert!(!store.remove(&id).expect("remove again"));
    }
}
