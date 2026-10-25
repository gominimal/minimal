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
//! A request the proxy cannot do gets `{"ok":false,"error":"<why>"}`, and the
//! connection stays open for the next line. The registered key goes into the
//! [`ClientKeys`] registry that the proxy verifies store handles under.
//!
//! A registered key also goes into a file beside the socket,
//! [`client_keys_path`], before the proxy replies. The next bind restores
//! every key in it, so a box created before a restart keeps redeeming its
//! store references after it (BEP-063). The file holds public keys only. It
//! is mode `0600`, and the bind refuses a file that another user owns or
//! that other users can write.
//!
//! The client keeps one key in its host keychain and registers it at each
//! box creation. A key that the registry already holds is not appended
//! again, so the file holds one line for each client key, not one for each
//! box. A client whose keychain refuses its key registers a replacement,
//! and the file then holds both keys. Nothing removes a line.

use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::SystemTime;

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
    /// The registered key's `kid`, on a registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Why the proxy did not do the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    fn done() -> Self {
        Self {
            ok: true,
            kid: None,
            error: None,
        }
    }

    fn refused(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            kid: None,
            error: Some(error.into()),
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

/// The registrations file: one registered key per line, as the request
/// carried it.
#[derive(Debug)]
struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    /// Registers every key in the file into `registry`, and returns how many
    /// keys it registered. A missing file holds no keys. A line that is not
    /// a key is skipped with a warning.
    fn restore(&self, registry: &RwLock<ClientKeys>) -> io::Result<usize> {
        let Some((mut file, _)) = self.open(false)? else {
            return Ok(0);
        };
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut registry = registry.write().unwrap_or_else(PoisonError::into_inner);
        let mut restored = 0;
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let registered = URL_SAFE_NO_PAD
                .decode(line)
                .ok()
                .and_then(|sec1| registry.register(&sec1).ok());
            match registered {
                Some(_) => restored += 1,
                None => tracing::warn!(
                    path = %self.path.display(),
                    line = number + 1,
                    "skipped a client key registration that is not a P-256 key"
                ),
            }
        }
        Ok(restored)
    }

    /// Opens the file once, without following a symlink, and checks the
    /// open handle: a regular file this user owns that no other user can
    /// write. With `create`, a missing file is made at mode `0600` and the
    /// handle appends. Without it, a missing file is `None`.
    fn open(&self, create: bool) -> io::Result<Option<(std::fs::File, std::fs::Metadata)>> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        if create {
            options.append(true).create(true).mode(0o600);
        }
        let file = match options.open(&self.path) {
            Ok(file) => file,
            Err(err) if !create && err.kind() == io::ErrorKind::NotFound => return Ok(None),
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
        Ok(Some((file, meta)))
    }

    /// Appends `key` to the file and syncs it, so the registration
    /// outlives this process. A file whose last line has no newline, as an
    /// interrupted write leaves it, gets one first, so the new key starts a
    /// line of its own.
    fn append(&self, key: &str) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        let Some((mut file, meta)) = self.open(true)? else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        let mut record = String::new();
        if meta.len() > 0 {
            let mut last = [0_u8];
            file.read_exact_at(&mut last, meta.len() - 1)?;
            if last[0] != b'\n' {
                record.push('\n');
            }
        }
        record.push_str(key);
        record.push('\n');
        file.write_all(record.as_bytes())?;
        file.sync_data()
    }
}

/// Does one request line against the client key `registry` and the box
/// registry `boxes`. It keeps no revocation and writes no record, so it
/// refuses `record_mint` and `revoke_box` rather than reply that it did
/// them. A key registered here is held in memory only: [`Control`] also
/// keeps it across restarts. The control socket does its lines through
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
        mapping: Mapping::ModuleUnmapped,
        outcome,
        marker: None,
    })
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
        Request::RegisterClientKey { key } => {
            let key = key.trim();
            let Ok(sec1) = URL_SAFE_NO_PAD.decode(key) else {
                return Reply::refused("the key is not unpadded base64url");
            };
            let Ok(verifying) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
                return Reply::refused("the key is not a P-256 public key");
            };
            let known = registry
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&handle::kid(&verifying));
            // The key is kept before it is registered, so a key the proxy
            // accepts is a key the next start restores. The file write and
            // its sync happen outside the registry lock, so handle checks do
            // not wait on the disk. Two connections that race on one new key
            // can both append it, and the restore registers it once.
            if let Some(keys) = keys
                && !known
                && let Err(err) = keys.append(key)
            {
                tracing::error!(path = %keys.path.display(), %err, "did not keep a client key registration");
                return Reply::refused(format!("the proxy did not record the key: {err}"));
            }
            let mut registry = registry.write().unwrap_or_else(PoisonError::into_inner);
            match registry.register(&sec1) {
                Ok(kid) => {
                    // One info line for each client key, not one for each
                    // box that registers it again.
                    if known {
                        tracing::debug!(kid, "the client key is already registered");
                    } else {
                        tracing::info!(kid, "registered a client key");
                    }
                    Reply {
                        ok: true,
                        kid: Some(kid),
                        error: None,
                    }
                }
                Err(_) => Reply::refused("the key is not a P-256 public key"),
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
        let inner = bind_owner_only(path)?;
        let keys = KeyFile {
            path: client_keys_path(path),
        };
        let restored = keys.restore(&registry)?;
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

    /// Serves connections until the accept fails.
    ///
    /// # Errors
    ///
    /// The accept's I/O error.
    pub async fn run(self) -> io::Result<()> {
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

    // BEP-063: a client whose keychain refused its key registers a
    // replacement. The proxy accepts it beside the old key, so handles under
    // both verify, also after a restart.
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
}
