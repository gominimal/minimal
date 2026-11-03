//! The GitHub sign-in item: the one host keychain item that holds the
//! sign-in's token and refresh material (BEP-002), and its instance
//! identifier.
//!
//! The item has two parts. The secret is the instance identifier, the token
//! and the refresh token. The metadata is the account, the instance
//! identifier, the flow and the two expiry times. The metadata is a
//! token-free copy for `min auth status`, which reads it without reading the
//! secret (BEP-004).
//!
//! The token item under [`SERVICE`] carries its own instance identifier, so
//! the item a reference resolves names its own instance. On Linux the two
//! parts are two stores, and they are not atomic. A torn write (token stored,
//! metadata store failed) therefore cannot put a new account's token under
//! an instance that an outstanding reference binds: the token names the new
//! instance, not the old one.
//!
//! Each backend keeps the metadata where a read of it returns no token:
//!
//! - macOS: the login keychain item under [`SERVICE`] holds the secret as
//!   its password and the metadata as its comment. `security
//!   find-generic-password` without `-w` prints the comment and no password.
//! - Linux and other hosts: the Secret Service holds two items. The item
//!   under [`SERVICE`] holds the secret, with the instance identifier. A
//!   second item under [`META_SERVICE`] holds the encoded metadata as its
//!   secret and no token.
//!   `secret-tool lookup` on [`META_SERVICE`] reads the metadata only.
//!
//! The instance identifier names one sign-in. A sign-in while no item is
//! held, or a sign-in to a different account, gets a new identifier. A
//! sign-in to the held item's account keeps it. A sign-in reference binds
//! the identifier, so a reference that a logout refused never names a later
//! sign-in.

use std::fmt;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use zeroize::{Zeroize as _, Zeroizing};

/// The keychain service name of the sign-in item.
pub const SERVICE: &str = "dev.minimal.github-sign-in";

/// The service name of the item that holds the metadata on hosts where the
/// keychain prints an item's secret with its attributes (the Secret
/// Service). Its secret is the encoded metadata, and it holds no token.
pub const META_SERVICE: &str = "dev.minimal.github-sign-in.meta";

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

/// The token and refresh material of a sign-in. Debug output redacts all of
/// it.
#[derive(Clone, PartialEq, Eq)]
pub struct Material {
    /// The instance identifier the token item carries. A read fills it from
    /// the item. A write ignores it and stores the metadata's identifier.
    pub instance: String,
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

/// A GitHub login: ASCII letters, digits, hyphens and underscores, at most
/// 64 characters. An Enterprise Managed User login on github.com has the
/// form `handle_shortcode`. None of these characters is a separator in
/// [`Metadata::encode`].
#[must_use]
pub fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 64
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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

/// How long before the token expires the proxy renews it, in seconds
/// (BEP-069).
pub const RENEW_WITHIN_SECS: u64 = 5 * 60;

impl Metadata {
    /// True when the token has expired at `now`, or expires within
    /// [`RENEW_WITHIN_SECS`] of it, so the proxy renews it before use
    /// (BEP-069).
    #[must_use]
    pub fn needs_renewal(&self, now: u64) -> bool {
        self.token_expires_at <= now.saturating_add(RENEW_WITHIN_SECS)
    }

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
    #[error(
        "The GitHub sign-in in the host keychain is damaged ({0}). Run `min auth login` to replace it."
    )]
    Corrupt(&'static str),
    /// GitHub returned a token in characters the item does not store. The
    /// check runs before the write, so the held item is unchanged.
    #[error(
        "GitHub returned a token in an unexpected form, so nothing was saved. Any sign-in held before is unchanged."
    )]
    Token,
    /// The host keychain's command-line tool is not installed.
    #[error("The host keychain tool `{tool}` is not installed. {install}")]
    MissingTool {
        /// The tool, as this program runs it.
        tool: &'static str,
        /// What to install, and what to run after it.
        install: &'static str,
    },
    /// The host has no random source.
    #[error("no random source for the sign-in instance identifier")]
    Random,
    /// The account name is not a GitHub login.
    #[error("GitHub returned an account name that is not a GitHub login")]
    Account,
}

/// The host keychain, as the sign-in item uses it. One sign-in, two parts.
/// Only the item under [`SERVICE`] holds the token.
pub trait Keychain {
    /// The item's metadata, when an item is held. Reads no token.
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

    /// Replace both parts of the held item in place, and create no item
    /// (BEP-069). The write happens only while the held item is the
    /// instance that `metadata` names. A logout that removed the item, or a
    /// sign-in that replaced it with a new instance, gives
    /// [`Updated::Gone`].
    ///
    /// The default checks the held metadata, then writes, with nothing
    /// between them. [`MemoryKeychain`] checks and writes under one lock.
    /// [`HostKeychain`] checks and writes under the item lock
    /// ([`lock_item`]), which `min auth logout` holds for its delete. The
    /// host keychain tools have no update-only write of their own.
    ///
    /// # Errors
    ///
    /// When the keychain refuses the read or the write.
    fn update(&self, metadata: &Metadata, material: &Material) -> Result<Updated, SignInError> {
        match self.metadata()? {
            Some(held) if held.instance == metadata.instance => {
                self.write(metadata, material)?;
                Ok(Updated::Written)
            }
            _ => Ok(Updated::Gone),
        }
    }
}

impl<T: Keychain + ?Sized> Keychain for Arc<T> {
    fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
        (**self).metadata()
    }

    fn material(&self) -> Result<Option<Material>, SignInError> {
        (**self).material()
    }

    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
        (**self).write(metadata, material)
    }

    fn update(&self, metadata: &Metadata, material: &Material) -> Result<Updated, SignInError> {
        (**self).update(metadata, material)
    }
}

/// What [`Keychain::update`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Updated {
    /// The held item now holds the new parts.
    Written,
    /// No item of that instance is held. Nothing was written.
    Gone,
}

/// The token and refresh material GitHub gave for a renewal. Debug output
/// redacts the tokens.
#[derive(Clone, PartialEq, Eq)]
pub struct Refreshed {
    /// The new GitHub user token.
    pub access_token: String,
    /// The new refresh token. GitHub revokes the old one.
    pub refresh_token: String,
    /// Seconds until the new token expires.
    pub expires_in: u64,
    /// Seconds until the new refresh token expires.
    pub refresh_token_expires_in: u64,
}

impl fmt::Debug for Refreshed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refreshed")
            .field("expires_in", &self.expires_in)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .finish_non_exhaustive()
    }
}

impl Drop for Refreshed {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Why GitHub gave no renewed token.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RefreshError {
    /// GitHub answered and refused the refresh token, with this error code.
    #[error("GitHub refused the refresh token: {0}")]
    Refused(String),
    /// The renewal did not complete: GitHub was not reached, its answer did
    /// not parse, or the proxy cannot send the request.
    #[error("the renewal did not complete: {0}")]
    Failed(String),
}

/// GitHub's token endpoint, as the proxy's renewal uses it (BEP-069).
pub trait TokenEndpoint: Send + Sync {
    /// Exchange `refresh_token` for a new token and refresh token. `flow`
    /// is the flow that produced the sign-in: a browser-flow sign-in renews
    /// under the App's client secret, a device-flow one without it.
    ///
    /// # Errors
    ///
    /// When GitHub refuses the refresh token or is not reached.
    fn refresh(&self, flow: Flow, refresh_token: &str) -> Result<Refreshed, RefreshError>;
}

/// The token endpoint of a proxy that has none. Every renewal fails, so an
/// expired token is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTokenEndpoint;

impl TokenEndpoint for NoTokenEndpoint {
    fn refresh(&self, _flow: Flow, _refresh_token: &str) -> Result<Refreshed, RefreshError> {
        Err(RefreshError::Failed(
            "this proxy has no GitHub token endpoint".into(),
        ))
    }
}

/// The token a renewal gave for substitution.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The token to substitute.
    pub token: Zeroizing<String>,
    /// True when this renewal got the token from GitHub and wrote it to the
    /// item. False when the held token was still good to use.
    pub renewed: bool,
    /// True when this renewal asked GitHub, or meant to, and got no new
    /// token, and the held token is given until it expires.
    pub failed: bool,
}

/// Why a renewal gave no token. Each one refuses the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RenewError {
    /// The token has expired and GitHub refused the renewal, or the refresh
    /// material expired too, or the item was not read.
    #[error("the GitHub sign-in needs a new sign-in")]
    SignInRequired,
    /// GitHub renewed the sign-in, but the item was not written. The renewed
    /// token is discarded.
    #[error("the renewed GitHub sign-in was not saved")]
    NotSaved,
    /// The item is gone, or holds another sign-in. The renewed token, if
    /// any, is discarded.
    #[error("the GitHub sign-in was removed")]
    Gone,
}

/// Renew the sign-in `instance` from its refresh material, when its token
/// has expired or expires within [`RENEW_WITHIN_SECS`] of `now` (BEP-069).
///
/// The function reads the item again first. When another renewal already
/// wrote a token with time to live, it gives that token and does not renew.
/// A renewed token is written to the item, update-only, before it is given
/// for first use. When the renewal fails and the held token has not expired
/// yet, the held token is given.
///
/// # Errors
///
/// [`RenewError`] when no token can be substituted.
pub fn renew(
    keychain: &dyn Keychain,
    endpoint: &dyn TokenEndpoint,
    instance: &str,
    now: u64,
) -> Result<Resolved, RenewError> {
    let metadata = match keychain.metadata() {
        Ok(Some(metadata)) if metadata.instance == instance => metadata,
        Ok(_) => return Err(RenewError::Gone),
        Err(error) => {
            tracing::warn!(%error, "the sign-in item was not read for its renewal");
            return Err(RenewError::SignInRequired);
        }
    };
    let material = match keychain.material() {
        Ok(Some(material)) if material.instance == instance => material,
        Ok(_) => return Err(RenewError::Gone),
        Err(error) => {
            tracing::warn!(%error, "the sign-in item was not read for its renewal");
            return Err(RenewError::SignInRequired);
        }
    };
    let held = |failed| Resolved {
        token: Zeroizing::new(material.access_token.clone()),
        renewed: false,
        failed,
    };
    let keep = || {
        if now < metadata.token_expires_at {
            Ok(held(true))
        } else {
            Err(RenewError::SignInRequired)
        }
    };
    if !metadata.needs_renewal(now) {
        return Ok(held(false));
    }
    if now >= metadata.refresh_expires_at {
        tracing::warn!(
            account = %metadata.account,
            refresh_expires_at = metadata.refresh_expires_at,
            "the GitHub sign-in was not renewed: its refresh material expired"
        );
        return keep();
    }
    let refreshed = match endpoint.refresh(metadata.flow, &material.refresh_token) {
        Ok(refreshed) => refreshed,
        Err(error) => {
            tracing::warn!(
                account = %metadata.account,
                %error,
                "GitHub did not renew the sign-in"
            );
            return keep();
        }
    };
    let renewed_metadata = Metadata {
        token_expires_at: now.saturating_add(refreshed.expires_in),
        refresh_expires_at: now.saturating_add(refreshed.refresh_token_expires_in),
        ..metadata.clone()
    };
    let renewed_material = Material {
        instance: instance.to_owned(),
        access_token: refreshed.access_token.clone(),
        refresh_token: refreshed.refresh_token.clone(),
    };
    match keychain.update(&renewed_metadata, &renewed_material) {
        Ok(Updated::Written) => {
            tracing::info!(
                account = %renewed_metadata.account,
                token_expires_at = renewed_metadata.token_expires_at,
                "renewed the GitHub sign-in at the proxy"
            );
            Ok(Resolved {
                token: Zeroizing::new(renewed_material.access_token.clone()),
                renewed: true,
                failed: false,
            })
        }
        Ok(Updated::Gone) => {
            tracing::warn!(
                account = %metadata.account,
                "the GitHub sign-in was removed during its renewal; the renewed token was discarded"
            );
            Err(RenewError::Gone)
        }
        Err(error) => {
            tracing::warn!(
                account = %metadata.account,
                %error,
                "the renewed GitHub sign-in was not saved; the renewed token was discarded"
            );
            Err(RenewError::NotSaved)
        }
    }
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

/// A keychain held in memory, in the Secret Service layout: one item under
/// [`SERVICE`] that holds the secret, and one under [`META_SERVICE`] that
/// holds the encoded metadata. For tests, and for no host.
#[derive(Debug, Default)]
pub struct MemoryKeychain {
    items: Mutex<Vec<(&'static str, String)>>,
}

impl MemoryKeychain {
    /// The secret of the item under `service`, as stored.
    #[must_use]
    pub fn item(&self, service: &str) -> Option<String> {
        let g = self.items.lock().ok()?;
        g.iter()
            .find(|(s, _)| *s == service)
            .map(|(_, v)| v.clone())
    }

    /// The sign-in's two parts as stored: the encoded metadata (the item
    /// under [`META_SERVICE`]) and the secret (the item under [`SERVICE`]).
    #[must_use]
    pub fn raw(&self) -> Option<(String, String)> {
        Some((self.item(META_SERVICE)?, self.item(SERVICE)?))
    }

    /// Delete both items, as a logout does.
    pub fn clear(&self) {
        if let Ok(mut g) = self.items.lock() {
            g.clear();
        }
    }

    fn store(&self, service: &'static str, secret: String) -> Result<(), SignInError> {
        let mut g = self.items.lock().map_err(|_| SignInError::Keychain {
            action: "write the sign-in",
            detail: "poisoned".into(),
        })?;
        g.retain(|(s, _)| *s != service);
        g.push((service, secret));
        Ok(())
    }
}

impl Keychain for MemoryKeychain {
    fn metadata(&self) -> Result<Option<Metadata>, SignInError> {
        self.item(META_SERVICE)
            .map(|m| Metadata::decode(&m))
            .transpose()
    }

    fn material(&self) -> Result<Option<Material>, SignInError> {
        self.item(SERVICE).map(|s| decode_secret(&s)).transpose()
    }

    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
        let secret = encode_secret(metadata, material)?;
        self.store(SERVICE, secret)?;
        self.store(META_SERVICE, metadata.encode())
    }

    fn update(&self, metadata: &Metadata, material: &Material) -> Result<Updated, SignInError> {
        let secret = encode_secret(metadata, material)?;
        let mut g = self.items.lock().map_err(|_| SignInError::Keychain {
            action: "write the sign-in",
            detail: "poisoned".into(),
        })?;
        // The check and the write hold one lock, so a `clear` either runs
        // before the check or after the write.
        let held = g
            .iter()
            .find(|(s, _)| *s == META_SERVICE)
            .map(|(_, m)| Metadata::decode(m))
            .transpose()?;
        let has_secret = g.iter().any(|(s, _)| *s == SERVICE);
        match held {
            Some(held) if has_secret && held.instance == metadata.instance => {
                g.retain(|(s, _)| *s != SERVICE && *s != META_SERVICE);
                g.push((SERVICE, secret));
                g.push((META_SERVICE, metadata.encode()));
                Ok(Updated::Written)
            }
            _ => Ok(Updated::Gone),
        }
    }
}

/// A token in characters every keychain command line carries unquoted.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// The secret as the item stores it:
/// `v1 <instance> <token> <refresh token>`. The instance is the metadata's,
/// so the token item names the instance it belongs to.
fn encode_secret(metadata: &Metadata, material: &Material) -> Result<String, SignInError> {
    if !valid_token(&material.access_token) || !valid_token(&material.refresh_token) {
        return Err(SignInError::Token);
    }
    Ok(format!(
        "{METADATA_VERSION} {} {} {}",
        metadata.instance, material.access_token, material.refresh_token
    ))
}

fn decode_secret(secret: &str) -> Result<Material, SignInError> {
    let mut parts = secret.split_whitespace();
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(METADATA_VERSION), Some(instance), Some(access), Some(refresh), None)
            if valid_instance(instance) && valid_token(access) && valid_token(refresh) =>
        {
            Ok(Material {
                instance: instance.to_owned(),
                access_token: access.to_owned(),
                refresh_token: refresh.to_owned(),
            })
        }
        _ => Err(SignInError::Corrupt("material")),
    }
}

/// Decode the secret a keychain tool printed, then zeroize the captured
/// output. The returned [`Material`] is the one copy that remains, and it
/// zeroizes itself on drop.
fn decode_captured(stdout: &mut Vec<u8>) -> Result<Material, SignInError> {
    // `from_utf8` borrows the buffer, so the decode makes no copy of it.
    let decoded = std::str::from_utf8(stdout)
        .map_err(|_| SignInError::Corrupt("material"))
        .and_then(|s| decode_secret(s.trim()));
    stdout.zeroize();
    decoded
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
        host::material()
    }

    fn write(&self, metadata: &Metadata, material: &Material) -> Result<(), SignInError> {
        let mut secret = encode_secret(metadata, material)?;
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

    fn update(&self, metadata: &Metadata, material: &Material) -> Result<Updated, SignInError> {
        // BEP-069: the check and the write happen under the item lock, so a
        // logout that holds it for its delete cannot fall between them.
        let _lock = lock_item()?;
        match self.metadata()? {
            Some(held) if held.instance == metadata.instance => {
                self.write(metadata, material)?;
                Ok(Updated::Written)
            }
            _ => Ok(Updated::Gone),
        }
    }
}

/// The file the item lock is held on: `~/.minimal/bep/sign-in.lock`. `None`
/// when no home directory is known.
#[must_use]
pub fn item_lock_path() -> Option<std::path::PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/sign-in.lock"))
}

/// The item lock, held until drop. It is an exclusive lock on a file, so it
/// holds across processes: the proxy's renewal and `min auth logout`.
#[derive(Debug)]
pub struct ItemLock {
    _file: std::fs::File,
}

/// Take the item lock at [`item_lock_path`], and wait while another process
/// holds it. The renewal holds it from its check to its write, and a logout
/// holds it for its delete, so a renewal never writes an item back after a
/// logout deleted it.
///
/// # Errors
///
/// When no home directory is known, or the lock file is not opened or not
/// locked.
pub fn lock_item() -> Result<ItemLock, SignInError> {
    let path = item_lock_path().ok_or_else(|| SignInError::Keychain {
        action: "lock the sign-in",
        detail: "no home directory is known".into(),
    })?;
    lock_item_at(&path)
}

/// Take the item lock on the file at `path`, created when missing.
///
/// # Errors
///
/// When the lock file is not opened or not locked.
pub fn lock_item_at(path: &std::path::Path) -> Result<ItemLock, SignInError> {
    let refused = |e: std::io::Error| SignInError::Keychain {
        action: "lock the sign-in",
        detail: format!("{}: {e}", path.display()),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(refused)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(refused)?;
    file.lock().map_err(refused)?;
    Ok(ItemLock { _file: file })
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
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SignInError::MissingTool {
                tool: host::TOOL,
                install: host::INSTALL,
            }
        } else {
            refused(e.to_string())
        }
    })?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())
            .map_err(|e| refused(e.to_string()))?;
    }
    child.wait_with_output().map_err(|e| refused(e.to_string()))
}

#[cfg(target_os = "macos")]
mod host {
    use super::{ITEM_ACCOUNT, LABEL, Material, SERVICE, SignInError, decode_captured, run};
    use std::process::Command;
    use zeroize::Zeroize as _;

    const SECURITY: &str = "/usr/bin/security";
    pub(super) const TOOL: &str = SECURITY;
    pub(super) const INSTALL: &str =
        "It is part of macOS. Restore it with a macOS reinstall, then run `min auth login` again.";
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

    pub(super) fn material() -> Result<Option<Material>, SignInError> {
        let mut cmd = Command::new(SECURITY);
        cmd.args([
            "find-generic-password",
            "-s",
            SERVICE,
            "-a",
            ITEM_ACCOUNT,
            "-w",
        ]);
        let mut out = run("read the sign-in", cmd, None)?;
        if out.status.code() == Some(NOT_FOUND) {
            out.stdout.zeroize();
            return Ok(None);
        }
        if !out.status.success() {
            out.stdout.zeroize();
            return Err(refused("read the sign-in", &out.stderr));
        }
        decode_captured(&mut out.stdout).map(Some)
    }

    pub(super) fn write(metadata: &str, secret: &str) -> Result<(), SignInError> {
        // `-U` updates the item in place when it exists. `-w` as the last
        // argument with no value reads the password from the terminal, so
        // the secret goes on `security -i`'s stdin, never on a command line.
        let mut line = format!(
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
        let out = run("write the sign-in", cmd, Some(&line));
        line.zeroize();
        let out = out?;
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
    use super::{LABEL, META_SERVICE, Material, SERVICE, SignInError, decode_captured, run};
    use std::process::Command;
    use zeroize::Zeroize as _;

    const SECRET_TOOL: &str = "secret-tool";
    pub(super) const TOOL: &str = SECRET_TOOL;
    pub(super) const INSTALL: &str = "Install it (the `libsecret-tools` package on Debian and Ubuntu, `libsecret` on Fedora and Arch), then run `min auth login` again.";

    /// The label of the item under [`META_SERVICE`].
    const META_LABEL: &str = "Minimal GitHub sign-in details";

    /// Read the metadata from the item under [`META_SERVICE`]. That item's
    /// secret is the encoded metadata, so the lookup returns no token.
    pub(super) fn metadata() -> Result<Option<String>, SignInError> {
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args(["lookup", "service", META_SERVICE]);
        let out = run("read the sign-in", cmd, None)?;
        if !out.status.success() {
            if out.stderr.is_empty() {
                return Ok(None);
            }
            return Err(refused("read the sign-in", &out.stderr));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let text = text.trim();
        Ok((!text.is_empty()).then(|| text.to_owned()))
    }

    pub(super) fn material() -> Result<Option<Material>, SignInError> {
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args(["lookup", "service", SERVICE]);
        let mut out = run("read the sign-in", cmd, None)?;
        if !out.status.success() {
            out.stdout.zeroize();
            if out.stderr.is_empty() {
                return Ok(None);
            }
            return Err(refused("read the sign-in", &out.stderr));
        }
        decode_captured(&mut out.stdout).map(Some)
    }

    /// Write the secret to the item under [`SERVICE`], then the metadata to
    /// the item under [`META_SERVICE`].
    pub(super) fn write(metadata: &str, secret: &str) -> Result<(), SignInError> {
        // A failed secret store leaves both held items as they were. A
        // failed metadata store after it leaves the old metadata, and the
        // read-back in `HostKeychain::write` reports the failed write. The
        // stored secret names its own new instance, so no reference bound
        // to the old instance resolves the new token.
        store(LABEL, SERVICE, secret)?;
        store(META_LABEL, META_SERVICE, metadata)
    }

    fn store(label: &str, service: &str, secret: &str) -> Result<(), SignInError> {
        // The Secret Service replaces the item whose attributes all match.
        // Each item's one attribute is `service`, so the store replaces the
        // held item in place, and a failed store leaves it as it was.
        let mut cmd = Command::new(SECRET_TOOL);
        cmd.args(["store", &format!("--label={label}"), "service", service]);
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

#[cfg(test)]
mod tests {
    use super::*;

    // BEP-069: the item lock excludes a second holder until the first drops
    // it, so a renewal's check and write never straddle a logout's delete.
    #[test]
    fn the_item_lock_excludes_a_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/sign-in.lock");
        let held = lock_item_at(&path).unwrap();
        let other = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(
            matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "a second holder takes the lock while the first holds it"
        );
        drop(held);
        other.try_lock().expect("the lock is free once dropped");
    }
}
