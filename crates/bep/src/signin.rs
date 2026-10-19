//! The GitHub sign-in item: the one host keychain item that holds the
//! sign-in's token and refresh material (BEP-002), and its instance
//! identifier.
//!
//! The item has two parts. The secret is the token and the refresh token.
//! The metadata is the account, the instance identifier, the flow and the
//! two expiry times. The metadata holds no token, so `min auth status` reads
//! it without reading the secret (BEP-004).
//!
//! The instance identifier names one sign-in. A sign-in while no item is
//! held, or a sign-in to a different account, gets a new identifier. A
//! sign-in to the held item's account keeps it. A sign-in reference binds
//! the identifier, so a reference that a logout refused never names a later
//! sign-in.

use std::fmt;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use zeroize::Zeroize as _;

/// The keychain service name of the sign-in item.
pub const SERVICE: &str = "dev.minimal.github-sign-in";

/// The keychain account name of the sign-in item. The host holds one
/// sign-in item, so the name is fixed.
pub const ITEM_ACCOUNT: &str = "github";

/// The label a person sees for the item in the host keychain's own viewer.
pub const LABEL: &str = "Minimal GitHub sign-in";

/// The metadata version this file writes.
const METADATA_VERSION: &str = "v1";

/// The sign-in flow that produced an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The OAuth device flow. Its refresh needs no client secret.
    Device,
    /// The authorization-code flow with PKCE. Its refresh needs the
    /// published App's client secret.
    Browser,
}

impl Flow {
    /// The flow's name in the metadata and the logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Flow::Device => "device",
            Flow::Browser => "browser",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "device" => Some(Flow::Device),
            "browser" => Some(Flow::Browser),
            _ => None,
        }
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The token and refresh material of a sign-in. Debug output redacts both.
#[derive(Clone, PartialEq, Eq)]
pub struct Material {
    /// The GitHub user token.
    pub access_token: String,
    /// The GitHub refresh token.
    pub refresh_token: String,
}

impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Material { .. }")
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// The item's metadata: everything about the sign-in except the material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The signed-in GitHub account's login.
    pub account: String,
    /// The instance identifier, 32 lowercase hex digits.
    pub instance: String,
    /// The flow that produced the sign-in.
    pub flow: Flow,
    /// When the token expires, in Unix seconds.
    pub token_expires_at: u64,
    /// When the refresh material expires, in Unix seconds.
    pub refresh_expires_at: u64,
}

impl Metadata {
    /// The metadata as the item stores it: space-separated `key=value`
    /// pairs, in characters every host keychain prints without escaping.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{METADATA_VERSION} account={} instance={} flow={} token_expires_at={} refresh_expires_at={}",
            self.account, self.instance, self.flow, self.token_expires_at, self.refresh_expires_at
        )
    }

    /// Parse metadata that [`Metadata::encode`] wrote.
    ///
    /// # Errors
    ///
    /// [`SignInError::Corrupt`] when a field is missing or malformed.
    pub fn decode(s: &str) -> Result<Self, SignInError> {
        let mut parts = s.split_whitespace();
        if parts.next() != Some(METADATA_VERSION) {
            return Err(SignInError::Corrupt("metadata version"));
        }
        let (mut account, mut instance, mut flow, mut token, mut refresh) =
            (None, None, None, None, None);
        for part in parts {
            let Some((k, v)) = part.split_once('=') else {
                return Err(SignInError::Corrupt("metadata field"));
            };
            match k {
                "account" => account = Some(v.to_owned()),
                "instance" => instance = Some(v.to_owned()),
                "flow" => flow = Flow::parse(v),
                "token_expires_at" => token = v.parse().ok(),
                "refresh_expires_at" => refresh = v.parse().ok(),
                _ => {}
            }
        }
        Ok(Metadata {
            account: account
                .filter(|a| valid_account(a))
                .ok_or(SignInError::Corrupt("account"))?,
            instance: instance
                .filter(|i| valid_instance(i))
                .ok_or(SignInError::Corrupt("instance"))?,
            flow: flow.ok_or(SignInError::Corrupt("flow"))?,
            token_expires_at: token.ok_or(SignInError::Corrupt("token expiry"))?,
            refresh_expires_at: refresh.ok_or(SignInError::Corrupt("refresh expiry"))?,
        })
    }
}

/// A GitHub login: ASCII letters, digits and hyphens.
#[must_use]
pub fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 64
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_instance(instance: &str) -> bool {
    instance.len() == 32
        && instance
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The state of a held sign-in at a moment, as `min auth status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The token is live.
    Live,
    /// The token has expired and the refresh material has not. The proxy
    /// renews the sign-in on the next request that uses it.
    RenewsAtProxy,
    /// The token and the refresh material have expired. Only a new sign-in
    /// recovers it.
    Lapsed,
}

impl Metadata {
    /// The sign-in's standing at `now`, in Unix seconds.
    #[must_use]
    pub fn standing(&self, now: u64) -> Standing {
        if now < self.token_expires_at {
            Standing::Live
        } else if now < self.refresh_expires_at {
            Standing::RenewsAtProxy
        } else {
            Standing::Lapsed
        }
    }
}

/// A completed sign-in, before it is stored.
#[derive(Debug, Clone)]
pub struct Completed {
    /// The signed-in account's login.
    pub account: String,
    /// The flow that completed.
    pub flow: Flow,
    /// The token and refresh material.
    pub material: Material,
    /// When the token expires, in Unix seconds.
    pub token_expires_at: u64,
    /// When the refresh material expires, in Unix seconds.
    pub refresh_expires_at: u64,
}

/// What [`store_sign_in`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// The metadata now in the item.
    pub metadata: Metadata,
    /// True when the item got a new instance identifier.
    pub new_instance: bool,
}

/// An error from the sign-in item.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    /// The host keychain refused an operation, or is not present.
    #[error("the host keychain refused to {action}: {detail}")]
    Keychain {
        /// What was refused.
        action: &'static str,
        /// What the keychain said.
        detail: String,
    },
    /// The item is present but a field does not parse.
    #[error("the GitHub sign-in item in the host keychain is damaged ({0})")]
    Corrupt(&'static str),
    /// The host has no random source.
    #[error("no random source for the sign-in instance identifier")]
    Random,
    /// The account name is not a GitHub login.
    #[error("GitHub returned an account name that is not a GitHub login")]
    Account,
}

/// The host keychain, as the sign-in item uses it. One item, two parts.
pub trait Keychain {
    /// The item's metadata, when an item is held. Reads no secret.
    ///
    /// # Errors
    ///
    /// When the keychain refuses the read or the metadata is damaged.
    fn metadata(&self) -> Result<Option<Metadata>, SignInError>;

    /// The item's material, when an item is held.
    ///
    /// # Errors
    ///
    /// When the keychain refuses the read or the material is damaged.
    fn material(&self) -> Result<Option<Material>, SignInError>;

    /// Write the item: create it, or replace both parts in place.
    ///
    /// # Errors
    ///
    /// When the keychain refuses the write.
    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError>;
}

/// Store a completed sign-in in the one sign-in item (BEP-002).
///
/// A sign-in while no item is held, or to a different account, gets a new
/// instance identifier. A sign-in to the held item's account replaces the
/// material in place and keeps the identifier.
///
/// # Errors
///
/// When the keychain refuses the read or the write, or the random source
/// fails.
pub fn store_sign_in(
    keychain: &dyn Keychain,
    completed: &Completed,
) -> Result<Stored, SignInError> {
    if !valid_account(&completed.account) {
        return Err(SignInError::Account);
    }
    // A damaged item is replaced by a new instance: no reference can be
    // known to name it. Any other failure to read the item stops the
    // sign-in before the write, so a refused read never mints a new
    // instance over a held item.
    let held = match keychain.metadata() {
        Ok(held) => held,
        Err(SignInError::Corrupt(_)) => None,
        Err(e) => return Err(e),
    };
    let (instance, new_instance) = match held {
        Some(held) if held.account == completed.account => (held.instance, false),
        _ => (new_instance_id()?, true),
    };
    let metadata = Metadata {
        account: completed.account.clone(),
        instance,
        flow: completed.flow,
        token_expires_at: completed.token_expires_at,
        refresh_expires_at: completed.refresh_expires_at,
    };
    keychain.write(&metadata, &completed.material)?;
    Ok(Stored {
        metadata,
        new_instance,
    })
}

/// A fresh instance identifier: 128 random bits as lowercase hex. No earlier
/// item carries it, to the odds of a 128-bit collision.
///
/// # Errors
///
/// [`SignInError::Random`] when the host has no random source.
pub fn new_instance_id() -> Result<String, SignInError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| SignInError::Random)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A keychain held in memory. For tests, and for no host.
#[derive(Debug, Default)]
pub struct MemoryKeychain {
    item: Mutex<Option<(String, String)>>,
}

impl MemoryKeychain {
    /// The item's two parts as stored: the encoded metadata and the secret.
    #[must_use]
    pub fn raw(&self) -> Option<(String, String)> {
        self.item.lock().ok().and_then(|g| g.clone())
    }

    /// Delete the item, as a logout does.
    pub fn clear(&self) {
        if let Ok(mut g) = self.item.lock() {
            *g = None;
        }
    }
}

impl Keychain for MemoryKeychain {
    fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
        self.raw().map(|(m, _)| Metadata::decode(&m)).transpose()
    }

    fn material(&self) -> Result<Option<Material>, SignInError> {
        self.raw().map(|(_, s)| decode_secret(&s)).transpose()
    }

    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
        let secret = encode_secret(material)?;
        let mut g = self.item.lock().map_err(|_| SignInError::Keychain {
            action: "write the sign-in",
            detail: "poisoned".into(),
        })?;
        *g = Some((metadata.encode(), secret));
        Ok(())
    }
}

/// A token in characters every keychain command line carries unquoted.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// The secret as the item stores it: `v1 <token> <refresh token>`.
fn encode_secret(material: &Material) -> Result<String, SignInError> {
    if !valid_token(&material.access_token) || !valid_token(&material.refresh_token) {
        return Err(SignInError::Corrupt("material"));
    }
    Ok(format!(
        "{METADATA_VERSION} {} {}",
        material.access_token, material.refresh_token
    ))
}

fn decode_secret(secret: &str) -> Result<Material, SignInError> {
    let mut parts = secret.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(METADATA_VERSION), Some(access), Some(refresh), None)
            if valid_token(access) && valid_token(refresh) =>
        {
            Ok(Material {
                access_token: access.to_owned(),
                refresh_token: refresh.to_owned(),
            })
        }
        _ => Err(SignInError::Corrupt("material")),
    }
}

/// The host keychain of this machine: the login keychain through
/// `/usr/bin/security` on macOS, the Secret Service through `secret-tool`
/// elsewhere. Both keep the material out of every file this program writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostKeychain;

impl Keychain for HostKeychain {
    fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
        host::metadata()?.map(|m| Metadata::decode(&m)).transpose()
    }

    fn material(&self) -> Result<Option<Material>, SignInError> {
        host::secret()?.map(|s| decode_secret(&s)).transpose()
    }

    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
        let mut secret = encode_secret(material)?;
        let result = host::write(&metadata.encode(), &secret);
        secret.zeroize();
        result?;
        // Read the metadata back: a keychain command can exit 0 and store
        // nothing.
        if self.metadata()?.as_ref() != Some(metadata) {
            return Err(SignInError::Keychain {
                action: "write the sign-in",
                detail: "the item does not hold the new sign-in after the write".into(),
            });
        }
        Ok(())
    }
}

fn run(
    action: &'static str,
    mut cmd: Command,
    stdin: Option<&str>,
) -> Result<std::process::Output, SignInError> {
    let refused = |detail: String| SignInError::Keychain { action, detail };
    cmd.stdin(if stdin.is_some() {
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

#[cfg(target_os = "macos")]
mod host {
    use super::{ITEM_ACCOUNT, LABEL, SERVICE, SignInError, run};
    use std::process::Command;

    const SECURITY: &str = "/usr/bin/security";
    /// `security` exits 44 when no item matches.
    const NOT_FOUND: i32 = 44;

    pub(super) fn metadata() -> Result<Option<String>, SignInError> {
        let mut cmd = Command::new(SECURITY);
        cmd.args(["find-generic-password", "-s", SERVICE, "-a", ITEM_ACCOUNT]);
        let out = run("read the sign-in", cmd, None)?;
        if out.status.code() == Some(NOT_FOUND) {
            return Ok(None);
        }
        if !out.status.success() {
            return Err(refused("read the sign-in", &out.stderr));
        }
        // The attributes print as `    "icmt"<blob>="<comment>"`.
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().find_map(|l| {
            let rest = l.trim().strip_prefix("\"icmt\"<blob>=\"")?;
            Some(rest.strip_suffix('"')?.to_owned())
        }))
    }

    pub(super) fn secret() -> Result<Option<String>, SignInError> {
        let mut cmd = Command::new(SECURITY);
        cmd.args([
            "find-generic-password",
            "-s",
            SERVICE,
            "-a",
            ITEM_ACCOUNT,
            "-w",
        ]);
        let out = run("read the sign-in", cmd, None)?;
        if out.status.code() == Some(NOT_FOUND) {
            return Ok(None);
        }
        if !out.status.success() {
            return Err(refused("read the sign-in", &out.stderr));
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
    }

    pub(super) fn write(metadata: &str, secret: &str) -> Result<(), SignInError> {
        // `-U` updates the item in place when it exists. `-w` as the last
        // argument with no value reads the password from the terminal, so
        // the secret goes on `security -i`'s stdin, never on a command line.
        let line = format!(
            "add-generic-password -U -s {SERVICE} -a {ITEM_ACCOUNT} -l {} -j {} -w {}\n",
            quote(LABEL),
            quote(metadata),
            quote(secret)
        );
        // Every part is quoted, and none carries a quote or a backslash:
        // the label is fixed, and the metadata and the secret are written in
        // letters, digits, `=`, `_`, `-`, `.` and spaces.
        let mut cmd = Command::new(SECURITY);
        cmd.arg("-i");
        let out = run("write the sign-in", cmd, Some(&line))?;
        if !out.status.success() {
            return Err(refused("write the sign-in", &out.stderr));
        }
        Ok(())
    }

    fn quote(s: &str) -> String {
        format!("\"{s}\"")
    }

    fn refused(action: &'static str, stderr: &[u8]) -> SignInError {
        SignInError::Keychain {
            action,
            detail: String::from_utf8_lossy(stderr).trim().to_owned(),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod host {
    use super::{LABEL, SERVICE, SignInError, run};
    use std::process::Command;
    use zeroize::Zeroize as _;

    const SECRET_TOOL: &str = "secret-tool";

    /// The item's label: the fixed label, then the metadata. The item's one
    /// attribute is `service`, so every write matches the held item's
    /// attributes and `secret-tool store` replaces it in place.
    fn label(metadata: &str) -> String {
        format!("{LABEL}: {metadata}")
    }

    pub(super) fn metadata() -> Result<Option<String>, SignInError> {
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args(["search", "service", SERVICE]);
        let mut out = run("read the sign-in", cmd, None)?;
        // `secret-tool search` prints `label = <label>` and, on its own
        // line, `secret = <secret>`, and nothing when no item matches. Only
        // the label is kept, and the captured output is zeroized.
        let prefix = format!("label = {LABEL}: ");
        let found = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix(&prefix).map(str::to_owned));
        out.stdout.zeroize();
        if found.is_none() && !out.status.success() && !out.stderr.is_empty() {
            return Err(refused("read the sign-in", &out.stderr));
        }
        Ok(found)
    }

    pub(super) fn secret() -> Result<Option<String>, SignInError> {
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args(["lookup", "service", SERVICE]);
        let out = run("read the sign-in", cmd, None)?;
        if !out.status.success() {
            if out.stderr.is_empty() {
                return Ok(None);
            }
            return Err(refused("read the sign-in", &out.stderr));
        }
        Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
    }

    pub(super) fn write(metadata: &str, secret: &str) -> Result<(), SignInError> {
        // The Secret Service replaces the item whose attributes all match.
        // The one attribute is `service`, so the store replaces the held
        // item in place, and a failed store leaves the held item as it was.
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args([
            "store",
            &format!("--label={}", label(metadata)),
            "service",
            SERVICE,
        ]);
        let out = run("write the sign-in", cmd, Some(secret))?;
        if !out.status.success() {
            return Err(refused("write the sign-in", &out.stderr));
        }
        Ok(())
    }

    fn refused(action: &'static str, stderr: &[u8]) -> SignInError {
        SignInError::Keychain {
            action,
            detail: String::from_utf8_lossy(stderr).trim().to_owned(),
        }
    }
}
