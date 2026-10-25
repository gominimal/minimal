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
//! No function here writes a value to a file or to a log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

/// The proxy binary that an item's access control names: the path in
/// [`PROXY_BIN_ENV`] when it is set and not empty, else `bep` beside `exe`.
/// The VM host daemon resolves the proxy it starts in the same way.
#[must_use]
pub fn proxy_binary_path(env: Option<&std::ffi::OsStr>, exe: &Path) -> PathBuf {
    match env.filter(|v| !v.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => exe.with_file_name("bep"),
    }
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
    let proxy_text = proxy.to_string_lossy();
    if proxy_text.contains(['"', '\\', '\n', '\r']) {
        return Err(StoreError::ProxyPath(proxy.to_path_buf()));
    }
    let mut hex = String::with_capacity(value.len() * 2);
    for b in value {
        hex.push(char::from(HEX[usize::from(b >> 4)]));
        hex.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    // `id` is checked by `valid_id`, so it needs no quoting.
    let line = format!(
        "add-generic-password -s {SERVICE} -a {id} -l \"Minimal secret {id}\" -T \"{proxy_text}\" -X {hex}\n"
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
    let proxy = proxy.to_string_lossy();
    let mut items = Vec::new();
    for record in dump.split("\nkeychain: ") {
        let attr = |key: &str| {
            let prefix = format!("\"{key}\"<blob>=\"");
            record.lines().find_map(|l| {
                let rest = l.trim().strip_prefix(&prefix)?;
                Some(rest.strip_suffix('"')?.to_owned())
            })
        };
        if attr("svce").as_deref() != Some(SERVICE) {
            continue;
        }
        let Some(id) = attr("acct") else { continue };
        let proxy_access = record
            .split("entry ")
            .skip(1)
            .any(|entry| entry_admits(entry, &proxy));
        items.push(ItemInfo { id, proxy_access });
    }
    items.sort_by(|a, b| a.id.cmp(&b.id));
    items.dedup_by(|a, b| a.id == b.id);
    items
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
}

#[cfg(target_os = "macos")]
mod host {
    use super::{ItemInfo, NATIVE_STORE, SERVICE, StoreError, keychain_add_line, parse_dump};
    use std::io::Write as _;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use zeroize::Zeroize as _;

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

    pub(super) fn set(id: &str, value: &[u8], proxy: &Path) -> Result<(), StoreError> {
        let mut line = keychain_add_line(id, value, proxy)?;
        // An update in place keeps the old item's access control, so the
        // old item goes first and the new one carries a fresh one.
        if let Err(e) = remove(id) {
            line.zeroize();
            return Err(e);
        }
        let out = run("store the secret", &["-i"], Some(&line));
        line.zeroize();
        let out = out?;
        if !out.status.success() {
            return Err(refused("store the secret", &out.stderr));
        }
        // `security -i` can exit 0 after a refused command, and it can warn
        // on stderr after a write that succeeded. So the item itself, read
        // back with its access control, decides the result.
        let stored = list(proxy)?
            .iter()
            .any(|item| item.id == id && item.proxy_access);
        if !stored {
            let mut err = refused("store the secret", &out.stderr);
            if let StoreError::Refused { detail, .. } = &mut err
                && detail.is_empty()
            {
                *detail = "the keychain holds no item for it that the proxy can read".into();
            }
            return Err(err);
        }
        Ok(())
    }

    pub(super) fn list(proxy: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        // `dump-keychain` without `-d` decrypts nothing, so it prints no
        // value and asks for no access.
        let out = run("list the secrets", &["dump-keychain", "-a"], None)?;
        if !out.status.success() {
            return Err(refused("list the secrets", &out.stderr));
        }
        Ok(parse_dump(&String::from_utf8_lossy(&out.stdout), proxy))
    }

    pub(super) fn remove(id: &str) -> Result<bool, StoreError> {
        let out = run(
            "remove the secret",
            &["delete-generic-password", "-s", SERVICE, "-a", id],
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
    use super::{ItemInfo, StoreError};
    use std::path::Path;

    pub(super) fn set(_: &str, _: &[u8], _: &Path) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn list(_: &Path) -> Result<Vec<ItemInfo>, StoreError> {
        Err(StoreError::Unsupported)
    }

    pub(super) fn remove(_: &str) -> Result<bool, StoreError> {
        Err(StoreError::Unsupported)
    }
}
