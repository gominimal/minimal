//! The proxy's control socket: client key registrations (BEP-063), and the
//! boxes the proxy serves (BEP-020, BEP-022).
//!
//! The control socket is a unix socket of its own, separate from the
//! listener that takes box connections ([`crate::listener`]). It is mode
//! `0600` in a `0700` directory, and the proxy also checks that the peer runs
//! as this process's user. The operator's own processes are the trust
//! boundary on an un-enrolled host (Gatehouse §6.2). The listener stays
//! closed to them (BEP-026).
//!
//! The protocol is one JSON object per line each way. A client registers its
//! handle-signing key before it delivers a handle signed under that key:
//!
//! ```text
//! > {"op":"register_client_key","key":"<SEC1 P-256 point, base64url, no padding>"}
//! < {"ok":true,"kid":"<RFC 7638 thumbprint>"}
//! ```
//!
//! The box's creator registers each box with its declared egress and its
//! address stance when it creates the box, and forgets the box when it
//! destroys it:
//!
//! ```text
//! > {"op":"register_box","box_id":"<id>","egress":["github.com","api.github.com:443"],"stance":"own_ip"}
//! < {"ok":true}
//! > {"op":"forget_box","box_id":"<id>"}
//! < {"ok":true}
//! ```
//!
//! The client records each member or store handle it mints for a box. The
//! box's creator revokes a live box at its destroy, before it forgets the
//! box (BEP-043, BEP-067):
//!
//! ```text
//! > {"op":"record_mint","box_id":"<id>","identifier":"github:<instance>"}
//! < {"ok":true}
//! > {"op":"revoke_box","box_id":"<id>"}
//! < {"ok":true}
//! ```
//!
//! Each of the two appends one record, of kind `mint` or `revocation`, to
//! the proxy's audit log, the log the proxy's decisions go to. The proxy is
//! the log's only writer. A revocation also goes into the revocations in
//! force ([`crate::revoke`]), which the redeemer reads at each request. A
//! second revocation of the same box appends no record.
//!
//! A box id is 32 hex digits, or a UUID with its hyphens. The proxy stores it
//! as 32 lowercase hex digits, the form the listener names the box by, and
//! refuses any other text.
//!
//! An egress authority is `host` or `host:port`, and a `host` with no port
//! is port 443. The registration goes into the [`crate::boxes::Boxes`] registry that the
//! redeemer reads at each request.
//!
//! The operator's `bep --rotate-signing` asks the serving proxy for a new
//! signing CA under the unchanged root and key identifier (BEP-061). The
//! reply names the fingerprint of the signing CA it replaced and of the one
//! now in use:
//!
//! ```text
//! > {"op":"rotate_signing"}
//! < {"ok":true,"old_fingerprint":"<hex>","new_fingerprint":"<hex>"}
//! ```
//!
//! The box's creator asks for the box ids the revocations in force name
//! before it gives a new box its id, so a minted id that a revocation holds
//! is refused (BEP-070). The list holds the revocations the proxy restored
//! from its audit log at start and each one recorded since:
//!
//! ```text
//! > {"op":"revoked_box_ids"}
//! < {"ok":true,"box_ids":["<id>"]}
//! ```
//!
//! A request the proxy cannot do gets `{"ok":false,"error":"<why>"}`, and the
//! connection stays open for the next line. The registered key goes into the
//! [`ClientKeys`] registry that the proxy verifies store handles under.
//!
//! A registered key also goes into a file beside the socket,
//! [`client_keys_path`], before the proxy replies. The next bind restores
//! every key in it, so a box created before a restart keeps redeeming its
//! store references after it (BEP-063). The file holds public keys only, one
//! line each, with the time the key was last registered. It is mode `0600`,
//! and the bind refuses a file that another user owns or that other users
//! can write. Each change writes a new file and renames it into place.
//!
//! The client keeps one key in its host keychain and registers it at each
//! box creation. A key that the registry already holds is not added again,
//! so the file holds one line for each client key, not one for each box.
//!
//! The socket's owner can revoke a key by its `kid`. A client whose keychain
//! refuses its key registers the replacement and revokes every other key in
//! one request, because the old key is out of its reach. This assumes one
//! client for each socket owner: the client keeps its key in one keychain
//! item with a fixed service and account, so one user has one client key.
//! A second client of the same user that replaces its key revokes the key
//! of the first, and the proxy does not tell the first. A revoked key leaves
//! the registry and the file before the proxy replies, so no store handle
//! signed under it verifies again, after a restart included:
//!
//! ```text
//! > {"op":"revoke_client_key","kid":"<kid>"}
//! < {"ok":true,"kid":"<kid>"}
//! > {"op":"replace_client_key","key":"<SEC1 P-256 point, base64url, no padding>"}
//! < {"ok":true,"kid":"<new kid>","revoked":["<kid>"]}
//! ```
//!
//! A registration can name the box that the client signs handles for under
//! the key. The proxy keeps each key's running boxes in the file, and a
//! `forget_box` ends the box's use of every key. A replacement does not
//! revoke a key that a running box uses. It retires the key: the key keeps
//! verifying until the last box that uses it is forgotten, and then the
//! proxy revokes it (the ruling on gominimal/arch#144):
//!
//! ```text
//! > {"op":"register_client_key","key":"<key>","box_id":"<id>"}
//! < {"ok":true,"kid":"<kid>"}
//! ```
//!
//! A box can end with no `forget_box`: a creation stopped before `minvmd`
//! recorded the box, a stopped `minvmd`, or a failed file write at the
//! forget. The file then keeps the box as a user of its key across
//! restarts. The box's creator sends every box id it still holds when it
//! starts the proxy. Each box that the file held at this start and that the
//! list leaves out ended, so it no longer uses its key, and a retired key
//! whose boxes all ended is revoked. An info log line names each `kid` that
//! no box uses after that. Until the list arrives, the proxy frees no key,
//! so a box created before a restart keeps redeeming:
//!
//! ```text
//! > {"op":"live_boxes","box_ids":["<id>"]}
//! < {"ok":true}
//! ```
//!
//! The registry is bounded ([`KeyBound`]): it holds at most a set count of
//! keys, and drops the key registered least recently that no running box
//! uses to stay inside it. When running boxes use every key, it refuses a
//! new key with [`KEYS_IN_USE`]. With an idle period set, it also drops a
//! key that no running box uses and nobody registered for that long.
//! `bep serve --max-client-keys <N>` sets the count, 16 by default
//! ([`KeyBound::DEFAULT_MAX_KEYS`]), and leaves the idle period unset. An
//! embedder sets another bound with [`Control::bind_with_key_bound`].

use std::collections::BTreeSet;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::{Decision, Kind, Mapping, Outcome};
use crate::boxes::{BoxRegistry, Boxes, Stance};
use crate::ca::{Ca, CaError, CaKey};
use crate::handle::{self, ClientKeys, parse_authority};
use crate::listener::bind_owner_only;
use crate::proxy::AuditWriter;
use crate::redeem::Authority;
use crate::redeemer::Revocations;

/// The longest request line the control socket reads.
pub const MAX_LINE_LEN: usize = 16 * 1024;

/// The client key registry the proxy verifies handles under, shared between
/// the control socket and the proxy.
pub type Registry = Arc<RwLock<ClientKeys>>;

/// One request line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Register a client's handle-signing key.
    RegisterClientKey {
        /// The SEC1 encoding of the P-256 public key, unpadded base64url.
        key: String,
        /// The box whose store handles or sign-in references the client
        /// signs under the key. The proxy keeps a key that a running box
        /// uses until the box is forgotten.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        box_id: Option<String>,
    },
    /// Register a box with its declared egress and its address stance. A
    /// second registration of the same box replaces the first.
    RegisterBox {
        /// The box id.
        box_id: String,
        /// The authorities the box's declared egress admits, each `host` or
        /// `host:port`.
        egress: Vec<String>,
        /// The box's address stance.
        stance: Stance,
    },
    /// Forget a box, at its destroy.
    ForgetBox {
        /// The box id.
        box_id: String,
    },
    /// Revoke a registered client key, so no handle signed under it
    /// verifies again.
    RevokeClientKey {
        /// The key's RFC 7638 thumbprint.
        kid: String,
    },
    /// Register a client's new handle-signing key, and revoke every other
    /// registered key. A client whose keychain refused its old key sends
    /// this, because it cannot name the old key.
    ReplaceClientKey {
        /// The SEC1 encoding of the new P-256 public key, unpadded
        /// base64url.
        key: String,
    },
    /// Record that the client minted a member or a store handle for a box.
    RecordMint {
        /// The box id.
        box_id: String,
        /// The member or store identifier, `<store>:<id>`.
        identifier: String,
    },
    /// Revoke every sealed value that names a box, at the destroy of the
    /// live box.
    RevokeBox {
        /// The box id.
        box_id: String,
    },
}

/// The request that names every box the box's creator still holds. It is a
/// type of its own, beside [`Request`], so a client that matches every
/// [`Request`] keeps its match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LiveBoxesRequest {
    /// Name every box that the box's creator still holds. Each box that the
    /// registrations file held at this start and that the list leaves out
    /// ended with no `forget_box`, so it no longer uses its key.
    LiveBoxes {
        /// The box ids.
        box_ids: Vec<String>,
    },
}

/// Frees the keys of the boxes that ended with no `forget_box`: each box
/// that `keys` held at its restore and that `box_ids` leaves out.
fn live_boxes(box_ids: &[String], registry: &RwLock<ClientKeys>, keys: &KeyFile) -> Reply {
    let Some(live) = box_ids
        .iter()
        .map(|id| normalise_box_id(id))
        .collect::<Option<BTreeSet<_>>>()
    else {
        return Reply::refused("a box id is not 32 hex digits");
    };
    match keys.reconcile(&live, registry) {
        Ok(_) => Reply::done(),
        Err(error) => Reply::refused(error),
    }
}

/// What the control socket writes into: the client keys, the boxes, the
/// revocations in force, and the audit log. The proxy's redeemer reads the
/// same registries, and its decisions go to the same log.
#[derive(Clone, Default)]
pub struct Records {
    /// The registered client keys.
    pub registry: Registry,
    /// The registered boxes.
    pub boxes: BoxRegistry,
    /// The box ids the revocations in force name.
    pub revocations: Revocations,
    /// The audit log the mint and revocation records go to. `None` keeps
    /// no record.
    pub audit: Option<Arc<dyn AuditWriter>>,
}

impl std::fmt::Debug for Records {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Records")
            .field("boxes", &self.boxes)
            .field("audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

/// One reply line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    /// Whether the proxy did the request.
    pub ok: bool,
    /// The registered key's `kid`, on a registration, or the revoked key's
    /// `kid`, on a revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The `kid` of each key a replacement revoked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
    /// Why the proxy did not do the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    fn done() -> Self {
        Self {
            ok: true,
            kid: None,
            revoked: Vec::new(),
            error: None,
        }
    }

    fn refused(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            kid: None,
            revoked: Vec::new(),
            error: Some(error.into()),
        }
    }

    fn with_kid(kid: String) -> Self {
        Self {
            kid: Some(kid),
            ..Self::done()
        }
    }
}

/// The operator's request to rotate the signing CA. It is a type of its own,
/// beside [`Request`], because only the serving proxy can do it:
/// [`handle_line`] has no CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RotationRequest {
    /// Issue a new signing CA under the unchanged root.
    RotateSigning,
}

/// The reply line to a [`RotationRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationReply {
    /// Whether the signing CA rotated.
    pub ok: bool,
    /// The fingerprint of the signing CA that the rotation replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_fingerprint: Option<String>,
    /// The fingerprint of the signing CA now in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_fingerprint: Option<String>,
    /// Why the signing CA did not rotate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RotationReply {
    fn refused(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            old_fingerprint: None,
            new_fingerprint: None,
            error: Some(error.into()),
        }
    }
}

/// The creator's request for the box ids the revocations in force name. It
/// is a type of its own, beside [`Request`], so a client that matches every
/// [`Request`] keeps its match, and [`Reply`] keeps its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RevocationsRequest {
    /// List the box ids the revocations in force name.
    RevokedBoxIds,
}

/// The reply line to a [`RevocationsRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedBoxIdsReply {
    /// Whether the proxy listed the revocations.
    pub ok: bool,
    /// The box ids the revocations in force name, each 32 lowercase hex
    /// digits: the ones restored from the audit log at start and the ones
    /// recorded since.
    #[serde(default)]
    pub box_ids: Vec<String>,
}

impl Records {
    /// The box ids the revocations in force name, as the reply to
    /// [`RevocationsRequest::RevokedBoxIds`].
    #[must_use]
    pub fn revoked_box_ids(&self) -> RevokedBoxIdsReply {
        let box_ids = self
            .revocations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        RevokedBoxIdsReply { ok: true, box_ids }
    }
}

/// The fingerprints of one signing CA rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    /// The fingerprint of the signing CA that the rotation replaced.
    pub old_fingerprint: String,
    /// The fingerprint of the signing CA now in use.
    pub new_fingerprint: String,
}

/// The serving proxy's CA, as the control socket rotates it.
pub trait RotateSigning: Send + Sync {
    /// Issues a new signing CA from `now` under the unchanged root and key
    /// identifier. The error is the reason, in words for the operator.
    ///
    /// # Errors
    ///
    /// Why the CA did not rotate. The current signing CA stays in use.
    fn rotate_signing(&self, now: SystemTime) -> Result<Rotated, String>;
}

impl<K: CaKey + Sync> RotateSigning for Mutex<Ca<'_, K>> {
    fn rotate_signing(&self, now: SystemTime) -> Result<Rotated, String> {
        let mut ca = self.lock().unwrap_or_else(PoisonError::into_inner);
        let old_fingerprint = crate::publish::certificate_fingerprint(ca.signing());
        // `Ca::renew_signing` writes the info line that names both
        // fingerprints, for this rotation and for a scheduled one.
        ca.renew_signing(now).map_err(|err| match err {
            CaError::RootExpired(at) => format!(
                "the root certificate expired at {at}. \
                 Run `bep --replace-key root` to make a new root key. \
                 Boxes created before then must be re-created"
            ),
            other => other.to_string(),
        })?;
        Ok(Rotated {
            old_fingerprint,
            new_fingerprint: crate::publish::certificate_fingerprint(ca.signing()),
        })
    }
}

/// The CA a control socket rotates, shared with the proxy that signs leaves
/// under it.
pub type Rotation = Arc<dyn RotateSigning>;

/// Rotates the signing CA of `ca` for one [`RotationRequest`]. The rotation
/// signs through the keychain, which can block or wait for a prompt, so it
/// runs on a blocking thread and never stalls a runtime thread.
async fn rotate(ca: Option<Rotation>) -> RotationReply {
    let Some(ca) = ca else {
        return RotationReply::refused("this proxy does not rotate its signing certificate");
    };
    let rotated = tokio::task::spawn_blocking(move || ca.rotate_signing(SystemTime::now())).await;
    match rotated {
        Ok(Ok(Rotated {
            old_fingerprint,
            new_fingerprint,
        })) => RotationReply {
            ok: true,
            old_fingerprint: Some(old_fingerprint),
            new_fingerprint: Some(new_fingerprint),
            error: None,
        },
        Ok(Err(error)) => {
            tracing::warn!(%error, "the signing CA did not rotate on request");
            RotationReply::refused(error)
        }
        Err(error) => {
            tracing::warn!(%error, "the signing CA did not rotate on request");
            RotationReply::refused("the rotation stopped before it finished")
        }
    }
}

/// Parses one declared egress authority, `host` or `host:port`. The
/// trailing dot of a fully qualified host comes off the host part, so
/// `github.com.:8443` registers as `github.com:8443`. `None` when the text
/// does not parse or the host is only dots.
fn parse_egress(text: &str) -> Option<Authority<String>> {
    let mut authority = parse_authority(text.trim())?;
    let host = authority.host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    authority.host = host.to_owned();
    Some(authority)
}

/// The box id in the form the listener names a box by: 32 lowercase hex
/// digits, [`crate::listener::box_id_text`]. Uppercase digits are lowered and
/// a hyphenated UUID loses its hyphens. `None` for any other text.
fn normalise_box_id(text: &str) -> Option<String> {
    let text = text.trim();
    let bytes = text.as_bytes();
    let digits: String = if bytes.len() == 36 && [8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-') {
        text.chars().filter(|&c| c != '-').collect()
    } else {
        text.to_owned()
    };
    (digits.len() == 32 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| digits.to_ascii_lowercase())
}

/// The file that keeps the client key registrations of the control socket
/// at `control`: the socket path with `.client-keys` added.
#[must_use]
pub fn client_keys_path(control: &Path) -> PathBuf {
    let mut name = control.as_os_str().to_owned();
    name.push(".client-keys");
    PathBuf::from(name)
}

/// How many client keys the registry holds, and how long a key that nobody
/// registers again stays in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBound {
    /// The most keys the registry holds. A new key past it drops the key
    /// registered least recently. Zero counts as one: the registry always
    /// takes the key that a client registers.
    pub max_keys: usize,
    /// How long a key stays after its last registration. `None` keeps it
    /// until the count drops it.
    pub idle: Option<Duration>,
}

impl KeyBound {
    /// The count [`KeyBound::default`] holds. The client keeps one key for
    /// each user, and a replacement revokes every other key, so the registry
    /// usually holds one. The count bounds the keys that other registrations
    /// on the socket can add.
    pub const DEFAULT_MAX_KEYS: usize = 16;
}

impl Default for KeyBound {
    fn default() -> Self {
        Self {
            max_keys: Self::DEFAULT_MAX_KEYS,
            idle: None,
        }
    }
}

/// The time now, in seconds since the epoch. A clock before the epoch
/// reads zero.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// One kept client key.
#[derive(Debug, Clone)]
struct Entry {
    /// The key as the request carried it: SEC1, unpadded base64url.
    key: String,
    kid: String,
    sec1: Vec<u8>,
    /// When the key was last registered, in seconds since the epoch.
    seen: u64,
    /// The running boxes whose handles are signed under the key. The bound
    /// never drops a key that a running box uses.
    boxes: BTreeSet<String>,
    /// Whether a replacement revoked the key while running boxes used it.
    /// A retired key stays until the last of those boxes is forgotten.
    retired: bool,
}

impl Entry {
    /// The entry for `key`, or `None` when it is not a P-256 key.
    fn parse(key: &str, seen: u64) -> Option<Self> {
        let sec1 = URL_SAFE_NO_PAD.decode(key).ok()?;
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
        Some(Self {
            key: key.to_owned(),
            kid: handle::kid(&verifying),
            sec1,
            seen,
            boxes: BTreeSet::new(),
            retired: false,
        })
    }

    /// Whether a running box uses the key.
    fn in_use(&self) -> bool {
        !self.boxes.is_empty()
    }
}

/// The start of the refusal of a registration that passes the bound when
/// running boxes use every registered key. The bound follows it.
pub const KEYS_IN_USE: &str =
    "every registered client key is in use by a running box, and the bound is ";

/// The bound that a refusal starting with [`KEYS_IN_USE`] names, or `None`
/// for any other refusal.
#[must_use]
pub fn keys_in_use_bound(error: &str) -> Option<usize> {
    error.strip_prefix(KEYS_IN_USE)?.trim().parse().ok()
}

/// Drops from `entries` each key that `bound` does not admit at `now`, and
/// returns the dropped `kid`s. The key `keep` and every key that a running
/// box uses are never dropped, so the entries can stay above the bound. A
/// warn line names each dropped key.
fn enforce(entries: &mut Vec<Entry>, bound: KeyBound, now: u64, keep: Option<&str>) -> Vec<String> {
    let mut dropped = Vec::new();
    if let Some(idle) = bound.idle {
        entries.retain(|entry| {
            let idle_for = now.saturating_sub(entry.seen);
            if Some(entry.kid.as_str()) == keep || entry.in_use() || idle_for < idle.as_secs() {
                return true;
            }
            tracing::warn!(
                kid = %entry.kid,
                idle_secs = idle_for,
                "dropped a client key that nobody registered within the idle period"
            );
            dropped.push(entry.kid.clone());
            false
        });
    }
    let max = bound.max_keys.max(1);
    while entries.len() > max {
        // The least recently registered key that no running box uses goes
        // first. A tie goes to the key that is earlier in the file.
        let Some((index, _)) = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| Some(entry.kid.as_str()) != keep && !entry.in_use())
            .min_by_key(|(_, entry)| entry.seen)
        else {
            break;
        };
        let entry = entries.remove(index);
        tracing::warn!(
            kid = %entry.kid,
            max_keys = max,
            "dropped the least recently registered client key to stay inside the registry's bound"
        );
        dropped.push(entry.kid);
    }
    dropped
}

/// Whether [`enforce`] drops none of `entries` at `now`. As there, the key
/// `keep` and every key that a running box uses are never dropped.
fn within(entries: &[Entry], bound: KeyBound, now: u64, keep: Option<&str>) -> bool {
    let droppable = |entry: &&Entry| Some(entry.kid.as_str()) != keep && !entry.in_use();
    (entries.len() <= bound.max_keys.max(1) || !entries.iter().any(|e| droppable(&e)))
        && bound.idle.is_none_or(|idle| {
            entries
                .iter()
                .filter(droppable)
                .all(|entry| now.saturating_sub(entry.seen) < idle.as_secs())
        })
}

/// Removes from `entries` each retired key that no running box uses, with
/// an info line that names it.
fn retire_unused(entries: &mut Vec<Entry>) {
    entries.retain(|entry| {
        if entry.retired && !entry.in_use() {
            tracing::info!(
                kid = %entry.kid,
                "revoked a replaced client key: the last box created under it ended"
            );
            return false;
        }
        true
    });
}

/// Makes `registry` hold exactly the keys of `entries`.
fn install(entries: &[Entry], registry: &RwLock<ClientKeys>) {
    let mut fresh = ClientKeys::new();
    for entry in entries {
        // An entry is a P-256 key by construction.
        let _ = fresh.register(&entry.sec1);
    }
    *registry.write().unwrap_or_else(PoisonError::into_inner) = fresh;
}

/// The registrations file: one kept key per line, as the request carried
/// it, then a space and the time it was last registered. A line with no
/// time is a key registered at the restore. A key that running boxes use
/// adds ` boxes=<id>,<id>`, and a key that a replacement retired adds
/// ` retired` before it.
#[derive(Debug)]
struct KeyFile {
    path: PathBuf,
    bound: KeyBound,
    /// The kept keys, in the file's order. The lock also orders the file
    /// writes.
    entries: Mutex<Vec<Entry>>,
    /// The time that `register` last wrote the file, or [`NEVER_WRITTEN`].
    written: AtomicU64,
    /// The boxes that the file held at the restore and that no `live_boxes`
    /// list has confirmed or freed yet. Only these can be stranded: a box
    /// registered since the start is one this process will see forgotten.
    from_start: Mutex<BTreeSet<String>>,
}

/// The value of [`KeyFile::written`] before `register` writes the file.
const NEVER_WRITTEN: u64 = u64::MAX;

impl KeyFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            bound: KeyBound::default(),
            entries: Mutex::new(Vec::new()),
            written: AtomicU64::new(NEVER_WRITTEN),
            from_start: Mutex::new(BTreeSet::new()),
        }
    }

    /// How long `register` waits after its last file write before a known
    /// key's new time is written: a minute, or a quarter of the idle period
    /// when that is shorter. A restart can lose this much of a key's
    /// registration time, and no more.
    fn seen_refresh(&self) -> Duration {
        let minute = Duration::from_secs(60);
        self.bound.idle.map_or(minute, |idle| minute.min(idle / 4))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers every key in the file into `registry`, inside the bound at
    /// `now`, and returns how many keys it registered. A missing file holds
    /// no keys. A line that is not a key is skipped with a warning.
    fn restore(&self, registry: &RwLock<ClientKeys>, now: u64) -> io::Result<usize> {
        let mut entries = self.lock();
        entries.clear();
        if let Some(mut file) = self.open()? {
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            for (number, line) in text.lines().enumerate() {
                let mut fields = line.split_whitespace();
                let Some(key) = fields.next() else { continue };
                let seen = fields.next().and_then(|t| t.parse().ok()).unwrap_or(now);
                let Some(mut entry) = Entry::parse(key, seen) else {
                    tracing::warn!(
                        path = %self.path.display(),
                        line = number + 1,
                        "skipped a client key registration that is not a P-256 key"
                    );
                    continue;
                };
                for field in fields {
                    if field == "retired" {
                        entry.retired = true;
                    } else if let Some(ids) = field.strip_prefix("boxes=") {
                        entry
                            .boxes
                            .extend(ids.split(',').filter_map(normalise_box_id));
                    }
                }
                match entries.iter_mut().find(|e| e.kid == entry.kid) {
                    Some(kept) => {
                        kept.seen = kept.seen.max(entry.seen);
                        kept.retired &= entry.retired;
                        kept.boxes.extend(entry.boxes);
                    }
                    None => entries.push(entry),
                }
            }
        }
        // A retired key whose boxes all ended is revoked.
        let before = entries.len();
        retire_unused(&mut entries);
        let retired = entries.len() != before;
        if !enforce(&mut entries, self.bound, now, None).is_empty() || retired {
            self.write(&entries)?;
        }
        install(&entries, registry);
        *self
            .from_start
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = entries
            .iter()
            .flat_map(|entry| entry.boxes.iter().cloned())
            .collect();
        Ok(entries.len())
    }

    /// Frees the keys of the boxes that ended with no `forget_box` (#2617):
    /// each box that the file held at the restore and that `live` does not
    /// hold. A retired key whose boxes all ended is revoked. Returns how
    /// many boxes it freed.
    fn reconcile(
        &self,
        live: &BTreeSet<String>,
        registry: &RwLock<ClientKeys>,
    ) -> Result<usize, String> {
        let mut entries = self.lock();
        let ended: BTreeSet<String> = {
            let mut from_start = self
                .from_start
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let ended = from_start.difference(live).cloned().collect();
            from_start.retain(|id| live.contains(id));
            ended
        };
        let mut freed = 0;
        for entry in entries.iter_mut() {
            let held = entry.boxes.len();
            entry.boxes.retain(|id| !ended.contains(id));
            if entry.boxes.len() == held {
                continue;
            }
            freed += held - entry.boxes.len();
            if !entry.in_use() {
                tracing::info!(
                    kid = %entry.kid,
                    ended = held,
                    "freed a client key: no box that used it still runs"
                );
            }
        }
        if freed == 0 {
            return Ok(0);
        }
        retire_unused(&mut entries);
        install(&entries, registry);
        self.write(&entries).map_err(|err| {
            tracing::error!(path = %self.path.display(), %err, "did not record the ended boxes of the client keys");
            self.written.store(NEVER_WRITTEN, Ordering::Relaxed);
            format!(
                "the proxy freed the keys of the ended boxes, but did not record the change, so they return after a restart: {err}"
            )
        })?;
        Ok(freed)
    }

    /// Applies the bound at `now` to the kept keys and to `registry`.
    fn sweep(&self, registry: &RwLock<ClientKeys>, now: u64) {
        let mut entries = self.lock();
        if enforce(&mut entries, self.bound, now, None).is_empty() {
            return;
        }
        install(&entries, registry);
        if let Err(err) = self.write(&entries) {
            tracing::error!(path = %self.path.display(), %err, "did not record the dropped client keys");
        }
    }

    /// [`KeyFile::register_for`], for no box.
    #[cfg(test)]
    fn register(
        &self,
        entry: Entry,
        registry: &RwLock<ClientKeys>,
        now: u64,
        replace: bool,
    ) -> Result<Vec<String>, String> {
        self.register_for(entry, registry, now, replace, None)
    }

    /// Keeps `entry` and registers it in `registry`, at `now`, as a key that
    /// the box `user` uses. With `replace`, every other key is revoked: the
    /// registry serves one client for each socket owner (see the module
    /// docs). A key that a running box uses is retired, not revoked: it
    /// stays until the last such box is forgotten ([`KeyFile::release`]).
    /// Returns the revoked `kid`s.
    ///
    /// A new key that passes the bound when running boxes use every other
    /// key is refused with [`KEYS_IN_USE`].
    fn register_for(
        &self,
        entry: Entry,
        registry: &RwLock<ClientKeys>,
        now: u64,
        replace: bool,
        user: Option<&str>,
    ) -> Result<Vec<String>, String> {
        let mut entries = self.lock();
        let kept = entries.iter().find(|e| e.kid == entry.kid);
        let known = kept.is_some();
        // A new user or a retired key changes what the file keeps.
        let unchanged = kept
            .is_some_and(|kept| !kept.retired && user.is_none_or(|user| kept.boxes.contains(user)));
        // A known key inside the bound changes only its time. The file
        // takes that time at the next write, and the write waits until the
        // last one is older than the refresh interval.
        let recent = Some(self.written.load(Ordering::Relaxed))
            .filter(|&last| last != NEVER_WRITTEN)
            .and_then(|last| now.checked_sub(last))
            .is_some_and(|since| since < self.seen_refresh().as_secs());
        if unchanged && !replace && recent && within(&entries, self.bound, now, Some(&entry.kid)) {
            if let Some(kept) = entries.iter_mut().find(|e| e.kid == entry.kid) {
                kept.seen = now;
            }
            return Ok(Vec::new());
        }
        let kid = entry.kid.clone();
        let mut next = entries.clone();
        let mut revoked = Vec::new();
        let mut retiring = Vec::new();
        if replace {
            next.retain_mut(|e| {
                if e.kid == kid {
                    return true;
                }
                if e.in_use() {
                    // The ruling on gominimal/arch#144: a replaced key keeps
                    // verifying until the boxes created under it end.
                    if !e.retired {
                        retiring.push((e.kid.clone(), e.boxes.len()));
                    }
                    e.retired = true;
                    return true;
                }
                revoked.push(e.kid.clone());
                false
            });
        }
        match next.iter_mut().find(|e| e.kid == kid) {
            Some(kept) => {
                kept.seen = now;
                // A key that a client registers again signs handles again.
                kept.retired = false;
                if let Some(user) = user {
                    kept.boxes.insert(user.to_owned());
                }
            }
            None => {
                let mut entry = Entry { seen: now, ..entry };
                if let Some(user) = user {
                    entry.boxes.insert(user.to_owned());
                }
                next.push(entry);
            }
        }
        enforce(&mut next, self.bound, now, Some(&kid));
        let max = self.bound.max_keys.max(1);
        if !known && next.len() > max {
            tracing::warn!(
                kid,
                max_keys = max,
                "refused a client key: running boxes use every registered key"
            );
            return Err(format!("{KEYS_IN_USE}{max}"));
        }
        if !known && !replace {
            // A new key is kept before it is registered, so a key the proxy
            // accepts is a key the next start restores.
            if let Err(err) = self.write(&next) {
                tracing::error!(path = %self.path.display(), %err, "did not keep a client key registration");
                return Err(format!("the proxy did not record the key: {err}"));
            }
            self.written.store(now, Ordering::Relaxed);
            *entries = next;
            install(&entries, registry);
            return Ok(revoked);
        }
        // A revocation takes effect in memory first, so a failed write
        // leaves no revoked key verifying in this process.
        *entries = next;
        install(&entries, registry);
        for gone in &revoked {
            tracing::info!(kid = %gone, replacement = %kid, "revoked a client key that the client replaced");
        }
        for (kept, boxes) in &retiring {
            tracing::info!(
                kid = %kept,
                replacement = %kid,
                boxes,
                "kept a replaced client key until the running boxes that use it end"
            );
        }
        match self.write(&entries) {
            Ok(()) => self.written.store(now, Ordering::Relaxed),
            Err(err) => {
                tracing::error!(path = %self.path.display(), %err, "did not record the client key change");
                if replace {
                    return Err(format!(
                        "the proxy revoked the other keys, but did not record the change, so they return after a restart: {err}"
                    ));
                }
                // A known key stays registered across a restart already. Only
                // its last registration time and the dropped keys are lost.
            }
        }
        Ok(revoked)
    }

    /// Revokes the key `kid`. Returns whether it was kept.
    fn revoke(&self, kid: &str, registry: &RwLock<ClientKeys>) -> Result<bool, String> {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|e| e.kid != kid);
        if entries.len() == before {
            return Ok(false);
        }
        install(&entries, registry);
        tracing::info!(kid, "revoked a client key");
        self.write(&entries).map_err(|err| {
            tracing::error!(path = %self.path.display(), %err, "did not record a client key revocation");
            format!(
                "the proxy revoked the key, but did not record the change, so it returns after a restart: {err}"
            )
        })?;
        Ok(true)
    }

    /// Records that the box `box_id` ended: no key is in use by it any more.
    /// A retired key that no running box uses then is revoked.
    fn release(&self, box_id: &str, registry: &RwLock<ClientKeys>) {
        let mut entries = self.lock();
        let mut changed = false;
        for entry in entries.iter_mut() {
            changed |= entry.boxes.remove(box_id);
        }
        if !changed {
            return;
        }
        let before = entries.len();
        retire_unused(&mut entries);
        // The end of the box takes effect in memory first, as a revocation
        // does in `replace`, so a failed write leaves no retired key
        // verifying in this process. A failed write leaves the ended box in
        // the file. The next registration then writes the file again. A
        // restart before a successful write restores the key as in use,
        // until the `live_boxes` list at that start frees it (#2617).
        if entries.len() != before {
            install(&entries, registry);
        }
        if let Err(err) = self.write(&entries) {
            tracing::error!(path = %self.path.display(), %err, "did not record the end of a box that uses a client key");
            // `register_for` skips the write of a known key only after a
            // recent successful write.
            self.written.store(NEVER_WRITTEN, Ordering::Relaxed);
        }
    }

    /// Opens the file for reading, without following a symlink, and checks
    /// the open handle: a regular file this user owns that no other user
    /// can write. A missing file is `None`.
    fn open(&self) -> io::Result<Option<std::fs::File>> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let meta = file.metadata()?;
        // SAFETY: geteuid reads the caller's effective uid. It has no side
        // effects and cannot fail.
        let own = unsafe { libc::geteuid() };
        if !meta.is_file() || meta.uid() != own || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} must be a file that belongs to this user and is writable by this user only",
                    self.path.display()
                ),
            ));
        }
        Ok(Some(file))
    }

    /// Writes `entries` to a new file at mode `0600`, syncs it, and renames
    /// it over the file, so a crash leaves the old list or the new one.
    fn write(&self, entries: &[Entry]) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut name = self.path.as_os_str().to_owned();
        name.push(".new");
        let staged = PathBuf::from(name);
        match std::fs::remove_file(&staged) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)?;
        let mut text = String::new();
        for entry in entries {
            text.push_str(&entry.key);
            text.push(' ');
            text.push_str(&entry.seen.to_string());
            if entry.retired {
                text.push_str(" retired");
            }
            if entry.in_use() {
                text.push_str(" boxes=");
                text.push_str(&entry.boxes.iter().cloned().collect::<Vec<_>>().join(","));
            }
            text.push('\n');
        }
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&staged, &self.path)?;
        if let Some(dir) = self.path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// Does one request line against the client key `registry` and the box
/// registry `boxes`. It keeps no revocation and writes no record, so it
/// refuses `record_mint` and `revoke_box` rather than reply that it did
/// them. A key registered here is held in memory only, and a client key
/// revocation is refused: [`Control`] keeps the keys across restarts and
/// can revoke them. The control socket does its lines through
/// [`Control`], which does both.
#[must_use]
pub fn handle_line(line: &str, registry: &RwLock<ClientKeys>, boxes: &Boxes) -> Reply {
    if let Ok(Request::RecordMint { .. } | Request::RevokeBox { .. }) =
        serde_json::from_str::<Request>(line)
    {
        return Reply::refused("this handler keeps no revocation and writes no record");
    }
    handle_request(line, registry, boxes, &Revocations::default(), None, None)
}

impl Records {
    /// Does one request line against these records.
    #[must_use]
    pub fn handle(&self, line: &str) -> Reply {
        self.handle_keeping(line, None)
    }

    /// Does one request line against these records, and keeps each new
    /// client key in `keys` before it is registered.
    fn handle_keeping(&self, line: &str, keys: Option<&KeyFile>) -> Reply {
        handle_request(
            line,
            &self.registry,
            &self.boxes,
            &self.revocations,
            self.audit.as_deref(),
            keys,
        )
    }
}

/// Appends one record of `kind` for `box_id` to `audit`. A mint carries its
/// identifier and `admit`, and a revocation carries no identifier and
/// `refuse`. A record names no upstream, since neither is a request. A
/// failed write is the caller's to log.
fn append(
    audit: Option<&dyn AuditWriter>,
    kind: Kind,
    box_id: &str,
    identifier: Option<String>,
) -> io::Result<()> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let outcome = match kind {
        Kind::Revocation => Outcome::Refuse,
        Kind::Decision | Kind::Mint => Outcome::Admit,
    };
    audit.try_write(&Decision {
        kind,
        box_id: box_id.to_owned(),
        authority: String::new(),
        identifier,
        // A mint or a revocation carries no handle.
        jti: String::new(),
        mapping: Mapping::ModuleUnmapped,
        outcome,
        marker: None,
    })
}

/// The entry for a key as a request carried it, or the refusal.
fn parse_key(key: &str) -> Result<Entry, Reply> {
    let key = key.trim();
    if URL_SAFE_NO_PAD.decode(key).is_err() {
        return Err(Reply::refused("the key is not unpadded base64url"));
    }
    Entry::parse(key, unix_now()).ok_or_else(|| Reply::refused("the key is not a P-256 public key"))
}

/// Does one request line, and keeps each new client key in `keys` before
/// it is registered.
fn handle_request(
    line: &str,
    registry: &RwLock<ClientKeys>,
    boxes: &Boxes,
    revocations: &Revocations,
    audit: Option<&dyn AuditWriter>,
    keys: Option<&KeyFile>,
) -> Reply {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(err) => return Reply::refused(format!("the request is not valid: {err}")),
    };
    match request {
        Request::RegisterClientKey { key, box_id } => {
            let entry = match parse_key(&key) {
                Ok(entry) => entry,
                Err(reply) => return reply,
            };
            let user = match box_id.as_deref().map(normalise_box_id) {
                None => None,
                Some(Some(user)) => Some(user),
                Some(None) => return Reply::refused("the box id is not 32 hex digits"),
            };
            let kid = entry.kid.clone();
            let known = registry
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&kid);
            match keys {
                Some(keys) => {
                    if let Err(error) =
                        keys.register_for(entry, registry, unix_now(), false, user.as_deref())
                    {
                        return Reply::refused(error);
                    }
                }
                None => {
                    let _ = registry
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .register(&entry.sec1);
                }
            }
            // One info line for each client key, not one for each box that
            // registers it again.
            if known {
                tracing::debug!(kid, "the client key is already registered");
            } else {
                tracing::info!(kid, "registered a client key");
            }
            Reply::with_kid(kid)
        }
        Request::ReplaceClientKey { key } => {
            let Some(keys) = keys else {
                return Reply::refused("this proxy keeps no key list, so it cannot revoke a key");
            };
            let entry = match parse_key(&key) {
                Ok(entry) => entry,
                Err(reply) => return reply,
            };
            let kid = entry.kid.clone();
            match keys.register_for(entry, registry, unix_now(), true, None) {
                Ok(revoked) => {
                    tracing::info!(
                        kid,
                        revoked = revoked.len(),
                        "registered a replacement client key"
                    );
                    Reply {
                        revoked,
                        ..Reply::with_kid(kid)
                    }
                }
                Err(error) => Reply::refused(error),
            }
        }
        Request::RevokeClientKey { kid } => {
            let Some(keys) = keys else {
                return Reply::refused("this proxy keeps no key list, so it cannot revoke a key");
            };
            let kid = kid.trim().to_owned();
            match keys.revoke(&kid, registry) {
                Ok(true) => Reply::with_kid(kid),
                Ok(false) => Reply::refused(format!("no client key with kid {kid} is registered")),
                Err(error) => Reply::refused(error),
            }
        }
        Request::RegisterBox {
            box_id,
            egress,
            stance,
        } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            let Some(egress) = egress
                .iter()
                .map(|a| parse_egress(a))
                .collect::<Option<Vec<_>>>()
            else {
                return Reply::refused("an egress authority is not `host` or `host:port`");
            };
            boxes.register(&box_id, egress, stance);
            Reply::done()
        }
        Request::ForgetBox { box_id } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            boxes.forget(&box_id);
            // The box ended, so the keys it used are free for the bound, and
            // a retired key it was the last user of is revoked.
            if let Some(keys) = keys {
                keys.release(&box_id, registry);
            }
            Reply::done()
        }
        Request::RecordMint { box_id, identifier } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            let identifier = identifier.trim();
            if identifier.is_empty() {
                return Reply::refused("the identifier is empty");
            }
            if let Err(err) = append(audit, Kind::Mint, &box_id, Some(identifier.to_owned())) {
                tracing::error!(
                    box_id,
                    identifier,
                    %err,
                    "lost a mint record: the audit log did not take it"
                );
            }
            Reply::done()
        }
        Request::RevokeBox { box_id } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            // BEP-071: the revocation names the box id alone. It is in force
            // before the record is written, so no request after this reply
            // redeems a value that names the box. A failed append leaves
            // the revocation in force until the proxy stops, and the reply
            // stays `ok` because it is in force. The error names the lost
            // record, since a restart cannot restore it from the log.
            if crate::revoke::record(revocations, &box_id) {
                match append(audit, Kind::Revocation, &box_id, None) {
                    Ok(()) => tracing::info!(
                        box_id,
                        "recorded a revocation: every sealed value naming the box is refused"
                    ),
                    Err(err) => tracing::error!(
                        box_id,
                        %err,
                        "lost a revocation record: the audit log did not take it, so the \
                         revocation is in force only until the proxy stops"
                    ),
                }
            }
            Reply::done()
        }
    }
}

/// The control socket.
pub struct Control {
    inner: UnixListener,
    records: Records,
    keys: Arc<KeyFile>,
    rotation: Option<Rotation>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control")
            .field("inner", &self.inner)
            .field("rotation", &self.rotation.is_some())
            .finish_non_exhaustive()
    }
}

impl Control {
    /// Binds the control socket at `path`, mode `0600` in a `0700`
    /// directory, and restores into `registry` every client key that
    /// [`client_keys_path`] keeps.
    ///
    /// # Errors
    ///
    /// The I/O error of the directory, the bind or the mode change, and of
    /// the registrations file's read. A registrations file that another
    /// user owns, or that other users can write, is a
    /// [`io::ErrorKind::PermissionDenied`] error.
    pub fn bind(path: &Path, registry: Registry, boxes: BoxRegistry) -> io::Result<Self> {
        Self::bind_with_key_bound(path, registry, boxes, KeyBound::default())
    }

    /// [`Control::bind`], with the client key registry bounded by `bound`
    /// in place of [`KeyBound::default`]. The restore applies `bound`, so a
    /// larger bound keeps each key the file holds inside it. The proxy
    /// binary does not call it, so its bound is the fixed default.
    ///
    /// # Errors
    ///
    /// As [`Control::bind`].
    pub fn bind_with_key_bound(
        path: &Path,
        registry: Registry,
        boxes: BoxRegistry,
        bound: KeyBound,
    ) -> io::Result<Self> {
        let inner = bind_owner_only(path)?;
        let keys = KeyFile {
            bound,
            ..KeyFile::new(client_keys_path(path))
        };
        let restored = keys.restore(&registry, unix_now())?;
        tracing::info!(
            restored,
            path = %keys.path.display(),
            "restored the client key registrations"
        );
        Ok(Self {
            inner,
            records: Records {
                registry,
                boxes,
                ..Records::default()
            },
            keys: Arc::new(keys),
            rotation: None,
        })
    }

    /// This control socket, with `revocations` as the revocations in force
    /// that `revoke_box` adds to. The redeemer reads the same set.
    #[must_use]
    pub fn with_revocations(mut self, revocations: Revocations) -> Self {
        self.records.revocations = revocations;
        self
    }

    /// This control socket, with `audit` as the log that `record_mint` and
    /// `revoke_box` append to. The proxy's decisions go to the same log.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditWriter>) -> Self {
        self.records.audit = Some(audit);
        self
    }

    /// Takes rotation requests for the signing CA of `ca`. Without it, the
    /// socket refuses each one.
    #[must_use]
    pub fn with_rotation(mut self, ca: Rotation) -> Self {
        self.rotation = Some(ca);
        self
    }

    /// Serves connections until the accept fails. With an idle period set,
    /// it also drops each idle key once a minute.
    ///
    /// # Errors
    ///
    /// The accept's I/O error.
    pub async fn run(self) -> io::Result<()> {
        let _sweeper = self.keys.bound.idle.map(|idle| {
            let keys = Arc::clone(&self.keys);
            let registry = Arc::clone(&self.records.registry);
            let period = idle.clamp(Duration::from_secs(1), Duration::from_secs(60));
            AbortOnDrop(tokio::spawn(async move {
                let mut ticks = tokio::time::interval(period);
                loop {
                    ticks.tick().await;
                    keys.sweep(&registry, unix_now());
                }
            }))
        });
        loop {
            let stream = crate::listener::accept(&self.inner, "control socket").await?;
            tokio::spawn(serve(
                stream,
                self.records.clone(),
                Arc::clone(&self.keys),
                self.rotation.clone(),
            ));
        }
    }
}

/// Aborts its task when dropped, so the idle sweep ends with the socket.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serves one control connection, line by line.
async fn serve(
    stream: UnixStream,
    records: Records,
    keys: Arc<KeyFile>,
    rotation: Option<Rotation>,
) {
    // SAFETY: geteuid reads the caller's effective uid. It has no side
    // effects and cannot fail.
    let own = unsafe { libc::geteuid() };
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == own => {}
        other => {
            tracing::warn!(
                peer_uid = other.ok().map(|c| c.uid()),
                "refused a control connection from another user"
            );
            return;
        }
    }
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut lines)
            .take(MAX_LINE_LEN as u64)
            .read_line(&mut line)
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if !line.ends_with('\n') && line.len() >= MAX_LINE_LEN {
            let _ = write_reply(&mut write, &Reply::refused("the request is too long")).await;
            return;
        }
        let written = if let Ok(RotationRequest::RotateSigning) = serde_json::from_str(&line) {
            write_reply(&mut write, &rotate(rotation.clone()).await).await
        } else if let Ok(RevocationsRequest::RevokedBoxIds) = serde_json::from_str(&line) {
            write_reply(&mut write, &records.revoked_box_ids()).await
        } else if let Ok(LiveBoxesRequest::LiveBoxes { box_ids }) = serde_json::from_str(&line) {
            write_reply(&mut write, &live_boxes(&box_ids, &records.registry, &keys)).await
        } else {
            write_reply(&mut write, &records.handle_keeping(&line, Some(&keys))).await
        };
        if written.is_err() {
            return;
        }
    }
}

async fn write_reply(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    reply: &impl Serialize,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(reply).map_err(io::Error::other)?;
    bytes.push(b'\n');
    write.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_host_loses_its_trailing_dot_before_the_port() {
        let want = |host: &str, port| {
            Some(Authority {
                host: host.to_owned(),
                port,
            })
        };
        assert_eq!(parse_egress("github.com.:8443"), want("github.com", 8443));
        assert_eq!(parse_egress(" GitHub.com. "), want("github.com", 443));
        assert_eq!(parse_egress("github.com"), want("github.com", 443));
        assert_eq!(parse_egress(".:443"), None);
        assert_eq!(parse_egress("."), None);
    }

    #[tokio::test]
    async fn control_socket_registers_a_client_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let registry = Registry::default();
        let control = Control::bind(&path, Arc::clone(&registry), BoxRegistry::default()).unwrap();
        tokio::spawn(control.run());

        let key = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let sec1 = key.verifying_key().to_sec1_bytes();
        let line = serde_json::to_string(&Request::RegisterClientKey {
            key: URL_SAFE_NO_PAD.encode(&sec1),
            box_id: None,
        })
        .unwrap();

        let stream = UnixStream::connect(&path).await.unwrap();
        let (read, mut write) = stream.into_split();
        write
            .write_all(format!("{line}\nnot json\n").as_bytes())
            .await
            .unwrap();
        let mut lines = BufReader::new(read).lines();
        let first: Reply =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        let kid = first.kid.expect("the registration names its kid");
        assert!(first.ok);
        assert!(registry.read().unwrap().contains(&kid));
        let second: Reply =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(!second.ok);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Serves a control socket at `path` on a task of its own, with a new
    /// key registry, as one start of the proxy does.
    fn start(path: &Path) -> (Registry, tokio::task::JoinHandle<io::Result<()>>) {
        let registry = Registry::default();
        let control = Control::bind(path, Arc::clone(&registry), BoxRegistry::default()).unwrap();
        (registry, tokio::spawn(control.run()))
    }

    /// Stops the proxy started by [`start`]: the listener is dropped and the
    /// socket refuses connections, as after the process ends.
    async fn stop(task: tokio::task::JoinHandle<io::Result<()>>) {
        task.abort();
        let _ = task.await;
    }

    /// Registers `key` over the control socket at `path`, and returns the
    /// reply.
    async fn register(path: &Path, key: &p256::ecdsa::SigningKey) -> Reply {
        let line = serde_json::to_string(&Request::RegisterClientKey {
            key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
            box_id: None,
        })
        .unwrap();
        let stream = UnixStream::connect(path).await.unwrap();
        let (read, mut write) = stream.into_split();
        write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
        let mut lines = BufReader::new(read).lines();
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap()
    }

    /// A store handle for box `sub`, signed under `key`.
    fn handle_under(key: &p256::ecdsa::SigningKey, sub: &str) -> String {
        handle::sign(
            key,
            &handle::Claims {
                sub: sub.to_owned(),
                node_id: "node".to_owned(),
                store: "keychain".to_owned(),
                id: "npm-token".to_owned(),
                upstream: vec!["registry.npmjs.org".to_owned()],
                inject: Some(handle::Inject::Header {
                    name: "Authorization".to_owned(),
                    prefix: Some("Bearer ".to_owned()),
                }),
                iat: 1,
                exp: u64::MAX,
                jti: "jti".to_owned(),
            },
        )
    }

    // BEP-063: a store handle minted before a restart verifies after it,
    // under the key registered before the restart.
    #[tokio::test]
    async fn client_key_registrations_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let key = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let jws = handle_under(&key, "box-before-restart");

        let (registry, first) = start(&path);
        let reply = register(&path, &key).await;
        assert!(reply.ok, "{reply:?}");
        // A second registration of the same key does not grow the file.
        assert!(register(&path, &key).await.ok);
        assert!(handle::verify(&jws, &registry.read().unwrap()).is_ok());
        stop(first).await;

        let (restored, second) = start(&path);
        let claims = handle::verify(&jws, &restored.read().unwrap()).unwrap();
        assert_eq!(claims.sub, "box-before-restart");
        assert!(restored.read().unwrap().contains(&reply.kid.unwrap()));
        let kept = std::fs::read_to_string(client_keys_path(&path)).unwrap();
        assert_eq!(kept.lines().count(), 1, "{kept}");
        stop(second).await;

        // A line that is not a key is skipped, and the keys around it stay.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(client_keys_path(&path))
            .unwrap();
        file.write_all(b"not a key\n").unwrap();
        // An interrupted write leaves a last line with no newline. The next
        // key starts a line of its own, and the next start restores it.
        file.write_all(b"torn").unwrap();
        drop(file);
        let (restored, third) = start(&path);
        assert!(handle::verify(&jws, &restored.read().unwrap()).is_ok());
        let next = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).unwrap();
        let next_reply = register(&path, &next).await;
        assert!(next_reply.ok, "{next_reply:?}");
        stop(third).await;
        let (restored, fourth) = start(&path);
        assert!(restored.read().unwrap().contains(&next_reply.kid.unwrap()));
        assert!(handle::verify(&jws, &restored.read().unwrap()).is_ok());
        stop(fourth).await;

        // A registrations file behind a symlink is refused at the bind.
        let other = tempfile::tempdir().unwrap();
        let linked = other.path().join("bep/control.sock");
        std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(client_keys_path(&path), client_keys_path(&linked)).unwrap();
        let err = Control::bind(&linked, Registry::default(), BoxRegistry::default()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");
    }

    // BEP-063: a second key registered with `register_client_key` goes in
    // beside the first, so handles under both verify, also after a restart.
    // A client that replaces its key revokes the old one with
    // `replace_client_key` (see `a_key_removal_survives_a_restart`).
    #[tokio::test]
    async fn a_client_key_this_program_is_refused_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let old = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let replacement = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let before = handle_under(&old, "box-before");

        let (_, first) = start(&path);
        assert!(register(&path, &old).await.ok);
        stop(first).await;

        let (registry, second) = start(&path);
        let after = handle_under(&replacement, "box-after");
        assert!(matches!(
            handle::verify(&after, &registry.read().unwrap()),
            Err(handle::VerifyError::UnknownKey)
        ));
        let reply = register(&path, &replacement).await;
        assert!(reply.ok, "{reply:?}");
        assert!(handle::verify(&after, &registry.read().unwrap()).is_ok());
        assert!(handle::verify(&before, &registry.read().unwrap()).is_ok());
        stop(second).await;

        let (restored, third) = start(&path);
        assert!(handle::verify(&after, &restored.read().unwrap()).is_ok());
        assert!(handle::verify(&before, &restored.read().unwrap()).is_ok());
        stop(third).await;
    }

    // BEP-063: the control socket and its registrations file belong to this
    // user at mode 0600, and the box listener is a socket of its own that
    // takes no control request.
    #[tokio::test]
    async fn control_socket_is_owner_only_and_separate_from_listener() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let listener_path = dir.path().join("bep/listener.sock");
        let (registry, control) = start(&path);
        let key = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        assert!(register(&path, &key).await.ok);

        // SAFETY: geteuid has no side effects and cannot fail.
        let own = unsafe { libc::geteuid() };
        for file in [path.clone(), client_keys_path(&path)] {
            let meta = std::fs::metadata(&file).unwrap();
            assert_eq!(meta.uid(), own, "{}", file.display());
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "{}",
                file.display()
            );
        }
        let parent = std::fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(parent.permissions().mode() & 0o777, 0o700);

        // The listener cannot take the control socket's path.
        let err = crate::listener::Listener::bind(
            &path,
            [0; crate::listener::TOKEN_LEN],
            Arc::new(crate::listener::PeerAttested),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);

        // A registration sent to the listener gets no reply and registers
        // nothing.
        let listener = crate::listener::Listener::bind(
            &listener_path,
            [1; crate::listener::TOKEN_LEN],
            Arc::new(crate::listener::PeerAttested),
        )
        .unwrap();
        let served = tokio::spawn(listener.run(|_, _| async {}));
        let other = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let line = serde_json::to_string(&Request::RegisterClientKey {
            key: URL_SAFE_NO_PAD.encode(other.verifying_key().to_sec1_bytes()),
            box_id: None,
        })
        .unwrap();
        let mut stream = UnixStream::connect(&listener_path).await.unwrap();
        let _ = stream.write_all(format!("{line}\n").as_bytes()).await;
        let mut answer = String::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_string(&mut answer),
        )
        .await;
        assert!(
            !matches!(&read, Ok(Ok(n)) if *n > 0 && answer.contains("\"ok\"")),
            "{answer}"
        );
        let other_kid = handle::kid(other.verifying_key());
        assert!(!registry.read().unwrap().contains(&other_kid));
        served.abort();
        stop(control).await;
    }
    /// Sends `request` over the control socket at `path`, and returns the
    /// reply.
    async fn ask(path: &Path, request: &Request) -> Reply {
        let line = serde_json::to_string(request).unwrap();
        let stream = UnixStream::connect(path).await.unwrap();
        let (read, mut write) = stream.into_split();
        write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
        let mut lines = BufReader::new(read).lines();
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap()
    }

    // BEP-063: the socket's owner revokes a key by its kid, and a handle
    // signed under it no longer verifies. The other keys stay.
    #[tokio::test]
    async fn a_revoked_client_key_no_longer_verifies_a_store_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let revoked = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let kept = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).unwrap();
        let (registry, task) = start(&path);
        let kid = register(&path, &revoked).await.kid.unwrap();
        assert!(register(&path, &kept).await.ok);
        let under_revoked = handle_under(&revoked, "box-a");
        let under_kept = handle_under(&kept, "box-b");
        assert!(handle::verify(&under_revoked, &registry.read().unwrap()).is_ok());

        let reply = ask(&path, &Request::RevokeClientKey { kid: kid.clone() }).await;
        assert!(reply.ok, "{reply:?}");
        assert_eq!(reply.kid.as_deref(), Some(kid.as_str()));
        assert!(matches!(
            handle::verify(&under_revoked, &registry.read().unwrap()),
            Err(handle::VerifyError::UnknownKey)
        ));
        assert!(handle::verify(&under_kept, &registry.read().unwrap()).is_ok());

        // A second revocation names the key it did not find.
        let again = ask(&path, &Request::RevokeClientKey { kid: kid.clone() }).await;
        assert!(!again.ok);
        assert!(again.error.unwrap().contains(&kid));

        // A socket with no key list refuses to revoke.
        let reply = handle_line(
            &serde_json::to_string(&Request::RevokeClientKey { kid }).unwrap(),
            &RwLock::new(ClientKeys::new()),
            &Boxes::default(),
        );
        assert!(!reply.ok);
        stop(task).await;
    }

    // BEP-063: a revoked key and a key a replacement revoked stay out of the
    // registry after a restart.
    #[tokio::test]
    async fn a_key_removal_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let revoked = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let old = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).unwrap();
        let replacement = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();

        let (_, first) = start(&path);
        let revoked_kid = register(&path, &revoked).await.kid.unwrap();
        let old_kid = register(&path, &old).await.kid.unwrap();
        let reply = ask(&path, &Request::RevokeClientKey { kid: revoked_kid }).await;
        assert!(reply.ok, "{reply:?}");
        stop(first).await;

        let (registry, second) = start(&path);
        assert!(matches!(
            handle::verify(&handle_under(&revoked, "box-a"), &registry.read().unwrap()),
            Err(handle::VerifyError::UnknownKey)
        ));
        assert!(registry.read().unwrap().contains(&old_kid));
        let reply = ask(
            &path,
            &Request::ReplaceClientKey {
                key: URL_SAFE_NO_PAD.encode(replacement.verifying_key().to_sec1_bytes()),
            },
        )
        .await;
        assert!(reply.ok, "{reply:?}");
        assert_eq!(reply.revoked, vec![old_kid.clone()]);
        stop(second).await;

        let (restored, third) = start(&path);
        let restored = restored.read().unwrap().clone();
        assert!(!restored.contains(&old_kid));
        assert!(matches!(
            handle::verify(&handle_under(&old, "box-b"), &restored),
            Err(handle::VerifyError::UnknownKey)
        ));
        assert!(handle::verify(&handle_under(&replacement, "box-c"), &restored).is_ok());
        let kept = std::fs::read_to_string(client_keys_path(&path)).unwrap();
        assert_eq!(kept.lines().count(), 1, "{kept}");
        stop(third).await;
    }

    // BEP-063: the bound that the embedder sets reaches the restore, so a
    // count larger than the default keeps every key the file holds.
    #[tokio::test]
    async fn a_larger_key_bound_keeps_every_key_the_file_holds() {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        let held = KeyBound::DEFAULT_MAX_KEYS + 4;
        let keys: Vec<String> = (1..=u8::try_from(held).unwrap())
            .map(|byte| {
                let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
                URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes())
            })
            .collect();
        let text: String = (unix_now() - 100..)
            .zip(&keys)
            .map(|(seen, key)| format!("{key} {seen}\n"))
            .collect();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(client_keys_path(&path))
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();

        let registry = Registry::default();
        let bound = KeyBound {
            max_keys: held * 2,
            idle: None,
        };
        let control = Control::bind_with_key_bound(
            &path,
            Arc::clone(&registry),
            BoxRegistry::default(),
            bound,
        )
        .unwrap();
        let registry = registry.read().unwrap();
        for key in &keys {
            let kid = Entry::parse(key, 0).unwrap().kid;
            assert!(registry.contains(&kid), "{kid} was dropped");
        }
        let kept = std::fs::read_to_string(client_keys_path(&path)).unwrap();
        assert_eq!(kept, text);
        drop(control);
    }

    // BEP-063: a known key that registers again soon after the last write
    // does not rewrite the registrations file. The next write keeps its time.
    #[test]
    fn a_key_removal_survives_a_restart_without_a_write_for_each_registration() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFile::new(dir.path().join("control.sock.client-keys"));
        let registry = RwLock::new(ClientKeys::new());
        let entry = |byte: u8| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                0,
            )
            .unwrap()
        };
        let (a, b) = (entry(1), entry(2));
        keys.register(a.clone(), &registry, 100, false).unwrap();
        let written = std::fs::read_to_string(&keys.path).unwrap();
        keys.register(a.clone(), &registry, 110, false).unwrap();
        assert_eq!(std::fs::read_to_string(&keys.path).unwrap(), written);

        keys.register(b.clone(), &registry, 120, false).unwrap();
        let kept = std::fs::read_to_string(&keys.path).unwrap();
        assert!(kept.contains(&format!("{} 110\n", a.key)), "{kept}");

        // Past the refresh interval, a known key writes its time again.
        keys.register(a.clone(), &registry, 200, false).unwrap();
        let kept = std::fs::read_to_string(&keys.path).unwrap();
        assert!(kept.contains(&format!("{} 200\n", a.key)), "{kept}");
    }

    // BEP-063: the registry never holds more keys than its count, and drops
    // a key nobody registered within the idle period, after a restart too.
    #[test]
    fn the_registry_never_holds_more_keys_than_its_bound() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFile {
            bound: KeyBound {
                max_keys: 2,
                idle: Some(Duration::from_secs(100)),
            },
            ..KeyFile::new(dir.path().join("control.sock.client-keys"))
        };
        let registry = RwLock::new(ClientKeys::new());
        let entry = |byte: u8| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                0,
            )
            .unwrap()
        };
        let (a, b, c) = (entry(1), entry(2), entry(3));
        keys.register(a.clone(), &registry, 10, false).unwrap();
        keys.register(b.clone(), &registry, 20, false).unwrap();
        // `a` registers again, so `b` is the least recently registered.
        keys.register(a.clone(), &registry, 30, false).unwrap();
        keys.register(c.clone(), &registry, 40, false).unwrap();
        let held = |registry: &RwLock<ClientKeys>| {
            let registry = registry.read().unwrap();
            [&a, &b, &c].map(|e| registry.contains(&e.kid))
        };
        assert_eq!(held(&registry), [true, false, true]);

        // Past the idle period of `a` only.
        keys.sweep(&registry, 135);
        assert_eq!(held(&registry), [false, false, true]);

        let restarted = KeyFile {
            bound: keys.bound,
            ..KeyFile::new(keys.path.clone())
        };
        let restored = RwLock::new(ClientKeys::new());
        assert_eq!(restarted.restore(&restored, 135).unwrap(), 1);
        assert_eq!(held(&restored), [false, false, true]);
        assert_eq!(restarted.restore(&restored, 1_000).unwrap(), 0);
        assert_eq!(held(&restored), [false, false, false]);
    }

    // BEP-063: the bound drops the least recently registered key that no
    // running box uses, and refuses a new key when running boxes use every
    // key. A forgotten box frees its key, and a restart keeps the use.
    #[test]
    fn the_registry_bound_never_drops_a_key_a_running_box_uses() {
        const BOX_X: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
        const BOX_Y: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f6";
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFile {
            bound: KeyBound {
                max_keys: 2,
                idle: None,
            },
            ..KeyFile::new(dir.path().join("control.sock.client-keys"))
        };
        let registry = RwLock::new(ClientKeys::new());
        let entry = |byte: u8| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                0,
            )
            .unwrap()
        };
        let (a, b, c, d) = (entry(1), entry(2), entry(3), entry(4));
        let held = |registry: &RwLock<ClientKeys>| {
            let registry = registry.read().unwrap();
            [&a, &b, &c, &d].map(|e| registry.contains(&e.kid))
        };

        // `a` is the least recently registered key, but box X uses it, so
        // the bound drops `b`.
        keys.register_for(a.clone(), &registry, 10, false, Some(BOX_X))
            .unwrap();
        keys.register(b.clone(), &registry, 20, false).unwrap();
        keys.register_for(c.clone(), &registry, 30, false, Some(BOX_Y))
            .unwrap();
        assert_eq!(held(&registry), [true, false, true, false]);

        // Running boxes use both keys, so a new key is refused and no key
        // is dropped.
        let error = keys.register(d.clone(), &registry, 40, false).unwrap_err();
        assert_eq!(keys_in_use_bound(&error), Some(2), "{error}");
        assert_eq!(held(&registry), [true, false, true, false]);

        // The use survives a restart.
        let restarted = KeyFile {
            bound: keys.bound,
            ..KeyFile::new(keys.path.clone())
        };
        let restored = RwLock::new(ClientKeys::new());
        assert_eq!(restarted.restore(&restored, 50).unwrap(), 2);
        let error = restarted
            .register(d.clone(), &restored, 50, false)
            .unwrap_err();
        assert_eq!(keys_in_use_bound(&error), Some(2), "{error}");

        // Box X ends, so `a` is free, and the bound drops it for `d`.
        restarted.release(BOX_X, &restored);
        restarted.register(d.clone(), &restored, 60, false).unwrap();
        assert_eq!(held(&restored), [false, false, true, true]);
    }

    // BEP-063: a key that a running box uses is never dropped, so it does
    // not take the bound out of the fast path of a known key.
    #[test]
    fn the_bound_check_skips_keys_in_use() {
        const BOX_X: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
        let entry = |byte: u8, seen: u64| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                seen,
            )
            .unwrap()
        };
        let bound = KeyBound {
            max_keys: 1,
            idle: Some(Duration::from_secs(100)),
        };
        let (mut a, b) = (entry(1, 0), entry(2, 500));
        a.boxes.insert(BOX_X.to_owned());
        // `a` is idle and above the count, but box X uses it.
        let entries = vec![a.clone(), b.clone()];
        assert!(within(&entries, bound, 550, Some(&b.kid)));
        // Without the use, `enforce` drops `a`.
        a.boxes.clear();
        let mut entries = vec![a, b.clone()];
        assert!(!within(&entries, bound, 550, Some(&b.kid)));
        enforce(&mut entries, bound, 550, Some(&b.kid));
        assert!(within(&entries, bound, 550, Some(&b.kid)));
    }

    // BEP-063: a replacement retires a key that a running box uses, and the
    // proxy revokes it when the last such box is forgotten.
    #[test]
    fn a_replaced_key_stays_until_its_last_box_is_forgotten() {
        const BOX_X: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyFile::new(dir.path().join("control.sock.client-keys"));
        let registry = RwLock::new(ClientKeys::new());
        let entry = |byte: u8| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                0,
            )
            .unwrap()
        };
        let (used, unused, replacement) = (entry(1), entry(2), entry(3));
        keys.register_for(used.clone(), &registry, 10, false, Some(BOX_X))
            .unwrap();
        keys.register(unused.clone(), &registry, 20, false).unwrap();
        let revoked = keys
            .register(replacement.clone(), &registry, 30, true)
            .unwrap();
        assert_eq!(revoked, vec![unused.kid.clone()]);
        let held = |registry: &RwLock<ClientKeys>| {
            let registry = registry.read().unwrap();
            [&used, &unused, &replacement].map(|e| registry.contains(&e.kid))
        };
        assert_eq!(held(&registry), [true, false, true]);

        // A forget of another box changes nothing.
        keys.release("0192f0c17a2b7c3d8e4fa0b1c2d3e4f6", &registry);
        assert_eq!(held(&registry), [true, false, true]);
        keys.release(BOX_X, &registry);
        assert_eq!(held(&registry), [false, false, true]);

        let restored = RwLock::new(ClientKeys::new());
        KeyFile::new(keys.path.clone())
            .restore(&restored, 40)
            .unwrap();
        assert_eq!(held(&restored), [false, false, true]);
    }

    // BEP-063 (#2617): a box that ended with no `forget_box` stays in the
    // registrations file, and a restart keeps its key in use. The
    // `live_boxes` list then frees it: a box the list leaves out ended, and
    // a retired key whose boxes all ended is revoked. The bound then counts
    // only the keys that running boxes use.
    #[test]
    fn a_stranded_box_frees_its_key_at_start() {
        const STRANDED: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
        const RUNNING: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f6";
        const RETIRED_BOX: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f7";
        let dir = tempfile::tempdir().unwrap();
        let bound = KeyBound {
            max_keys: 3,
            idle: None,
        };
        let keys = KeyFile {
            bound,
            ..KeyFile::new(dir.path().join("control.sock.client-keys"))
        };
        let registry = RwLock::new(ClientKeys::new());
        let entry = |byte: u8| {
            let key = p256::ecdsa::SigningKey::from_bytes(&[byte; 32].into()).unwrap();
            Entry::parse(
                &URL_SAFE_NO_PAD.encode(key.verifying_key().to_sec1_bytes()),
                0,
            )
            .unwrap()
        };
        let (retired, stranded, running, new) = (entry(1), entry(2), entry(3), entry(4));
        keys.register_for(retired.clone(), &registry, 10, false, Some(RETIRED_BOX))
            .unwrap();
        // The replacement retires `retired`: box RETIRED_BOX still uses it.
        keys.register_for(stranded.clone(), &registry, 20, true, Some(STRANDED))
            .unwrap();
        keys.register_for(running.clone(), &registry, 30, false, Some(RUNNING))
            .unwrap();
        // Running boxes use every key, so the bound refuses a new one.
        let error = keys
            .register(new.clone(), &registry, 40, false)
            .unwrap_err();
        assert_eq!(keys_in_use_bound(&error), Some(3), "{error}");
        let held = |registry: &RwLock<ClientKeys>| {
            let registry = registry.read().unwrap();
            [&retired, &stranded, &running, &new].map(|e| registry.contains(&e.kid))
        };
        assert_eq!(held(&registry), [true, true, true, false]);

        // The proxy restarts. Boxes STRANDED and RETIRED_BOX ended with no
        // `forget_box`, and the file still names them, so every key stays
        // in use until the list arrives.
        let restarted = KeyFile {
            bound,
            ..KeyFile::new(keys.path.clone())
        };
        let restored = RwLock::new(ClientKeys::new());
        assert_eq!(restarted.restore(&restored, 50).unwrap(), 3);
        assert_eq!(held(&restored), [true, true, true, false]);
        let error = restarted
            .register(new.clone(), &restored, 50, false)
            .unwrap_err();
        assert_eq!(keys_in_use_bound(&error), Some(3), "{error}");

        // The box's creator names box RUNNING alone.
        let line = format!(
            r#"{{"op":"live_boxes","box_ids":["{}"]}}"#,
            RUNNING.to_uppercase()
        );
        let LiveBoxesRequest::LiveBoxes { box_ids } = serde_json::from_str(&line).unwrap();
        let reply = live_boxes(&box_ids, &restored, &restarted);
        assert!(reply.ok, "{reply:?}");
        // The retired key is revoked, and the stranded box frees its key.
        assert_eq!(held(&restored), [false, true, true, false]);
        let file = std::fs::read_to_string(&keys.path).unwrap();
        assert!(!file.contains(STRANDED), "{file}");
        assert!(!file.contains(RETIRED_BOX), "{file}");
        assert!(file.contains(&format!("boxes={RUNNING}")), "{file}");

        // The bound counts only the key that box RUNNING uses, so a new key
        // passes it.
        restarted
            .register(new.clone(), &restored, 60, false)
            .unwrap();
        assert_eq!(held(&restored), [false, true, true, true]);
        // At the bound, the freed key is dropped and the used key stays.
        let fourth = entry(5);
        restarted
            .register(fourth.clone(), &restored, 70, false)
            .unwrap();
        assert_eq!(held(&restored), [false, false, true, true]);
        assert!(restored.read().unwrap().contains(&fourth.kid));

        // A box registered since the start is not one the list can strand.
        restarted
            .register_for(entry(6), &restored, 80, false, Some(STRANDED))
            .unwrap();
        let reply = live_boxes(&box_ids, &restored, &restarted);
        assert!(reply.ok, "{reply:?}");
        let file = std::fs::read_to_string(&keys.path).unwrap();
        assert!(file.contains(&format!("boxes={STRANDED}")), "{file}");
        assert!(file.contains(&format!("boxes={RUNNING}")), "{file}");

        // A list with an id that is not a box id is refused.
        let reply = live_boxes(&["not-a-box".to_owned()], &restored, &restarted);
        assert!(!reply.ok, "{reply:?}");
    }
}
