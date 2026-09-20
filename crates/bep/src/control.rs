//! The control socket's audit submissions: how a client's own identity events
//! reach the log the proxy alone writes.
//!
//! The client never opens the audit log. It submits a mint or a revocation
//! over the proxy's control socket and the proxy appends it to the same chain
//! as its own decisions (BEP-067), so the head read, the append and the chain
//! advance stay one operation in one process and a client's record and a
//! proxy's decision can never share a predecessor. A decision is the proxy's
//! own account of a request it handled, so the socket does not take one.
//!
//! A revocation submission is more than a record: it is what puts a box's
//! sealed values, or every member of a module on this host, beyond redemption
//! (BEP-043, BEP-044). [`Revocations`] is that set, and appending the record
//! and putting the revocation in force are one operation ([`submit`]), so an
//! intake cannot record a revocation it then fails to enforce. The set is the
//! log's own projection — [`Revocations::in_log`] rebuilds it from the
//! retained records — so a proxy that restarts still refuses what was revoked
//! before it did.
//!
//! The socket carries the client's handle-signing key too: a store handle is
//! signed under a key of the client's, and the proxy verifies it under the
//! public half the client registers here at first use ([`ClientKey`],
//! [`ClientKeys`]). Both submissions are the operator's own processes talking
//! to the operator's own proxy, which is why the socket is theirs alone:
//! [`bind`] stands it up owned by the user the proxy runs as at mode
//! [`SOCKET_MODE`] inside a directory only that user may enter, and it is not
//! the redemption listener, which stays closed to everything that is not a box
//! attachment (BEP-026, BEP-063).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::Permissions;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use p256::PublicKey;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;

use crate::audit::{AuditError, Event, Kind, Log, Record};
use crate::keys::Fingerprint;
use crate::mint::EVERY_BOX;

/// What a client submits over the control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "submit", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Submission {
    /// An identity event of the client's, for the proxy to append to the audit
    /// log. The client names the record's fields; the chain field is the
    /// writer's alone.
    Audit(Event),
    /// The public half of the client's handle-signing key, for the proxy to
    /// verify store handles under (BEP-063).
    RegisterKey(ClientKey),
}

/// The public half of a client's handle-signing key, as a registration
/// carries it: the uncompressed SEC1 point of the P-256 key, hex.
///
/// The key itself never leaves the client's store — the proxy holds this half
/// to verify signatures with, and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientKey {
    /// The uncompressed SEC1 public point, hex.
    pub key: String,
}

impl ClientKey {
    /// The registration for `public`.
    #[must_use]
    pub fn of(public: &PublicKey) -> Self {
        Self {
            key: hex::encode(public.to_sec1_point(false).as_bytes()),
        }
    }

    /// The public key this registration carries.
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidClientKey`] when the field is not the hex of a
    /// P-256 point.
    pub fn public_key(&self) -> Result<PublicKey, ControlError> {
        let point = hex::decode(&self.key).map_err(|_| ControlError::InvalidClientKey)?;
        PublicKey::from_sec1_bytes(&point).map_err(|_| ControlError::InvalidClientKey)
    }
}

/// What the proxy answers a key registration with: the fingerprint it holds
/// the key under, and how many client keys it now holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    /// The registered key's fingerprint.
    pub key: String,
    /// How many client keys the proxy holds, the registration counted.
    pub keys: usize,
}

/// The client keys registered on this host: the public halves a store handle's
/// signature is verified under (BEP-063, BEP-064).
///
/// Registration is by fingerprint and idempotent: a client that registers the
/// same key on every run leaves one entry, and a client whose key was replaced
/// registers the new one beside it — a handle names the key it was signed
/// under, so an old key held here verifies nothing new.
#[derive(Debug, Clone, Default)]
pub struct ClientKeys {
    keys: BTreeMap<String, PublicKey>,
}

impl ClientKeys {
    /// No keys registered: a proxy that has just started.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `key` and answers with the fingerprint it is held under and
    /// the number of keys now held.
    ///
    /// # Errors
    ///
    /// [`ControlError::InvalidClientKey`] when the registration does not carry
    /// a P-256 point; nothing is registered then.
    pub fn register(&mut self, key: &ClientKey) -> Result<Registered, ControlError> {
        let public = key.public_key()?;
        let fingerprint = Fingerprint::of(&public).to_string();
        let held = self.keys.insert(fingerprint.clone(), public).is_some();
        tracing::info!(
            key = %fingerprint,
            keys = self.keys.len(),
            held,
            "registered a client's handle-signing key over the control socket"
        );
        Ok(Registered {
            key: fingerprint,
            keys: self.keys.len(),
        })
    }

    /// The registered key `fingerprint` names, as a handle's `key` claim
    /// spells it, or `None` when no such key is registered.
    #[must_use]
    pub fn holding(&self, fingerprint: &str) -> Option<&PublicKey> {
        self.keys.get(fingerprint)
    }

    /// How many keys are registered: what the support bundle's control-socket
    /// probe reports.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is registered, so no store handle verifies yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The longest a revocation may take to reach the decision, in seconds
/// (BEP-043, BEP-044).
///
/// The bound is met by construction rather than by a deadline anything waits
/// on: a submission puts the revocation in force in the same operation as the
/// append, and [`crate::redeem`] reads the set per request, so the next
/// request after the submission is already refused. The constant is what the
/// tests hold the intake to, so an intake that ever polled or cached would
/// have to state its own lag against it.
pub const REVOCATION_DEADLINE_SECS: u64 = 60;

/// The revocations in force on this host: what may no longer be redeemed,
/// whatever a sealed value's own expiry says (BEP-024).
///
/// A subject is a box name, from `min box stop` or `min box rm` of that box
/// (BEP-043), or a module, from `min auth logout` on this host (BEP-044). Both
/// are the names the sealed context carries, not the ids the decision interns:
/// the set outlives any one request, while the ids are minted per request by
/// the shell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    /// Box names every sealed value naming which is refused.
    boxes: BTreeSet<String>,
    /// Modules every member of which is refused on this host.
    modules: BTreeSet<String>,
}

impl Revocations {
    /// The revocations the log at `path` records, oldest first: the set a
    /// proxy starts from, so a restart refuses what was revoked before it.
    ///
    /// A log that is not there yet is no revocation at all — a host whose
    /// proxy has never run.
    ///
    /// # Errors
    ///
    /// [`AuditError::Read`] when the log cannot be read, or
    /// [`AuditError::Malformed`] when it holds a line that is no record.
    pub fn in_log(path: &Path) -> Result<Self, AuditError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(AuditError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let mut revocations = Self::default();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let record: Record =
                serde_json_lenient::from_str(line).map_err(|source| AuditError::Malformed {
                    path: path.to_path_buf(),
                    source,
                })?;
            revocations.record(&record);
        }
        Ok(revocations)
    }

    /// Whether nothing is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty() && self.modules.is_empty()
    }

    /// Puts what `record` revokes in force; a record of any other kind
    /// changes nothing.
    ///
    /// A revocation naming [`EVERY_BOX`] is the logout of a sign-in, so it
    /// covers the module its member identifier names rather than a box.
    pub fn record(&mut self, record: &Record) {
        if record.kind != Kind::Revocation {
            return;
        }
        if record.sub == EVERY_BOX {
            self.modules
                .insert(module_of(&record.credential).to_owned());
        } else {
            self.boxes.insert(record.sub.clone());
        }
    }

    /// Whether every sealed value naming `box_id` is refused (BEP-043).
    #[must_use]
    pub fn covers_box(&self, box_id: &str) -> bool {
        self.boxes.contains(box_id)
    }

    /// Whether every member of `module` on this host is refused (BEP-044).
    #[must_use]
    pub fn covers_module(&self, module: &str) -> bool {
        self.modules.contains(module)
    }
}

/// The module a member identifier belongs to: `github` of
/// `github:user-token`, the one spelling the mint and the listener both write.
fn module_of(credential: &str) -> &str {
    credential.split(':').next().unwrap_or(credential)
}

/// Why a submission was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The submission claims a kind only the proxy records.
    #[error(
        "a {0} record is the proxy's own account of a request; the control socket takes mint and revocation records"
    )]
    NotSubmittable(Kind),
    /// The submission is no audit submission, so it appends nothing.
    #[error("that submission is no audit submission; it appends no record")]
    NotAudit,
    /// A key registration did not carry a P-256 public point.
    #[error("the registration does not carry a P-256 public key")]
    InvalidClientKey,
    /// The control socket could not be stood up or described.
    #[error("the control socket {path}: {source}")]
    Socket {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The log refused the append.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Appends `submission` to `log`, the proxy's own and the only writable one,
/// and puts a revocation it carries into `revocations` — one operation, so
/// nothing is recorded as revoked that is not also refused from here on
/// (BEP-043, BEP-044).
///
/// # Errors
///
/// A [`ControlError`]: the submission is no audit submission, it claims a kind
/// only the proxy records, or the log refuses the append. A submission that is
/// refused changes neither the log nor the set.
pub fn submit(
    log: &mut Log,
    revocations: &mut Revocations,
    submission: &Submission,
) -> Result<Record, ControlError> {
    let Submission::Audit(event) = submission else {
        return Err(ControlError::NotAudit);
    };
    if event.kind == Kind::Decision {
        tracing::warn!(
            kind = %event.kind,
            box_id = %event.box_id,
            "refusing a control-socket submission of a record the proxy alone writes"
        );
        return Err(ControlError::NotSubmittable(event.kind));
    }
    tracing::info!(
        kind = %event.kind,
        box_id = %event.box_id,
        "appending a control-socket audit submission"
    );
    let record = log.append(event)?;
    revocations.record(&record);
    if record.kind == Kind::Revocation {
        tracing::info!(
            subject = %record.sub,
            credential = %record.credential,
            deadline_secs = REVOCATION_DEADLINE_SECS,
            "a revocation is in force; every request from here on reads it"
        );
    }
    Ok(record)
}

// ---------------------------------------------------------------------------
// The socket itself: the operator's own, and not the redemption listener
// (BEP-063).
// ---------------------------------------------------------------------------

/// The mode the control socket carries: its owner reads and writes it, nobody
/// else reaches it at all.
pub const SOCKET_MODE: u32 = 0o600;

/// The mode the directory holding the socket carries: only its owner may enter
/// it, so the socket is unreachable to anyone else for as long as it exists —
/// including in the instant between the bind and the socket's own mode.
pub const SOCKET_DIR_MODE: u32 = 0o700;

/// What the support bundle's control-socket probe reports: the socket's mode
/// and owner, never a submission and never a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketStatus {
    /// The socket's permission bits.
    pub mode: u32,
    /// The user id owning the socket.
    pub uid: u32,
}

impl SocketStatus {
    /// Whether the socket is the owner's alone: [`SOCKET_MODE`] exactly, so no
    /// group and no other bit is set.
    #[must_use]
    pub fn owner_only(&self) -> bool {
        self.mode == SOCKET_MODE
    }
}

/// Stands the proxy's control socket up at `path`: a Unix socket owned by the
/// user this process runs as, mode [`SOCKET_MODE`], inside a directory only
/// that user may enter (BEP-063).
///
/// It is the only intake for key registrations and audit submissions, and it is
/// not the redemption listener: that one serves box attachments over TCP and
/// takes no submission at all.
///
/// A socket file left behind by a proxy that is gone is replaced; a path held
/// by anything that is not a socket is left alone and the bind fails, rather
/// than unlinking a file the operator meant to keep.
///
/// # Errors
///
/// [`ControlError::Socket`] when the directory cannot be made, the stale socket
/// cannot be replaced, the bind fails, or the mode cannot be set.
pub fn bind(path: &Path) -> Result<UnixListener, ControlError> {
    let socket_error = |source| ControlError::Socket {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(socket_error)?;
        std::fs::set_permissions(parent, Permissions::from_mode(SOCKET_DIR_MODE))
            .map_err(socket_error)?;
    }
    if std::fs::symlink_metadata(path).is_ok_and(|held| held.file_type().is_socket()) {
        std::fs::remove_file(path).map_err(socket_error)?;
    }
    let listener = UnixListener::bind(path).map_err(socket_error)?;
    std::fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE)).map_err(socket_error)?;
    let status = status(path)?;
    tracing::info!(
        path = %path.display(),
        mode = format!("{:o}", status.mode),
        uid = status.uid,
        "the control socket is listening for key registrations and audit submissions"
    );
    Ok(listener)
}

/// The mode and owner of the control socket at `path`.
///
/// # Errors
///
/// [`ControlError::Socket`] when the path cannot be described.
pub fn status(path: &Path) -> Result<SocketStatus, ControlError> {
    let held = std::fs::metadata(path).map_err(|source| ControlError::Socket {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(SocketStatus {
        mode: held.permissions().mode() & 0o777,
        uid: held.uid(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use rustls::RootCertStore;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{TcpListener, TcpSocket, UnixStream};

    use super::*;
    use crate::audit::{Decision, Hash, Mapping};
    use crate::ca::{Authority, DeclaredUnion};
    use crate::keychain::{MemoryStore, PrivateKey as _};
    use crate::keys::Keys;
    use crate::listener::{Addressing, Config, Module, Proxy, Sender};
    use crate::upstream::Trust;

    fn event(kind: Kind) -> Event {
        Event {
            kind,
            box_id: "box-a1".to_owned(),
            authority: "api.github.com".to_owned(),
            credential: Some("github:user-token".to_owned()),
            mapping: Mapping::Unmapped,
            decision: Decision::Admit,
            marker: None,
        }
    }

    /// A client's mints and revocations join the proxy's own chain, and a
    /// client cannot submit a decision record at all.
    #[test]
    fn control_submissions_append_to_the_proxys_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path().join("audit.jsonl")).unwrap();
        let mut revocations = Revocations::default();
        let decided = log.append(&event(Kind::Decision)).unwrap();

        let minted = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Mint)),
        )
        .unwrap();
        assert_eq!(minted.kind, Kind::Mint);
        assert_eq!(minted.previous_hash, decided.line_hash());
        // A mint revokes nothing.
        assert!(revocations.is_empty());
        let revoked = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Revocation)),
        )
        .unwrap();
        assert_eq!(revoked.previous_hash, minted.line_hash());
        assert_ne!(revoked.previous_hash, Hash::ZERO);
        // The append and the set move together: the box is refused from here.
        assert!(revocations.covers_box("box-a1"));

        // A decision is the proxy's own: submitting one appends nothing.
        let refused = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Decision)),
        );
        assert!(matches!(
            refused,
            Err(ControlError::NotSubmittable(Kind::Decision))
        ));
        assert_eq!(log.head(), revoked.line_hash());
        assert_eq!(
            std::fs::read_to_string(log.path()).unwrap().lines().count(),
            3
        );
    }

    /// BEP-043 and BEP-044 as the set sees them: a revocation naming a box
    /// covers that box and no other, one naming every box covers the module
    /// its member identifier names, and the set a restarted proxy rebuilds
    /// from the log is the set it had.
    #[test]
    fn revocations_cover_the_box_or_the_whole_module() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        let mut revocations = Revocations::default();

        // A log that is not there yet revokes nothing.
        assert!(
            Revocations::in_log(&dir.path().join("never-ran.jsonl"))
                .unwrap()
                .is_empty()
        );

        // `min box rm box-a1`: that box, and nothing else.
        submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Revocation)),
        )
        .unwrap();
        assert!(revocations.covers_box("box-a1"));
        assert!(!revocations.covers_box("box-b2"));
        assert!(!revocations.covers_module("github"));

        // `min auth logout`: every member of the module on this host.
        let mut logout = event(Kind::Revocation);
        logout.box_id = EVERY_BOX.to_owned();
        submit(&mut log, &mut revocations, &Submission::Audit(logout)).unwrap();
        assert!(revocations.covers_module("github"));
        assert!(!revocations.covers_module("store"));
        // The wildcard subject is not a box name of its own.
        assert!(!revocations.covers_box(EVERY_BOX));

        // What a proxy that restarts reads back out of the log.
        assert_eq!(Revocations::in_log(&path).unwrap(), revocations);
    }

    /// The submission is one wire form, and it round-trips — both a client's
    /// audit record and the client key a store handle is verified under.
    #[test]
    fn control_submission_round_trips() {
        let submission = Submission::Audit(event(Kind::Mint));
        let wire = serde_json_lenient::to_string(&submission).unwrap();
        assert!(wire.contains(r#""submit":"audit""#), "{wire}");
        assert_eq!(
            serde_json_lenient::from_str::<Submission>(&wire).unwrap(),
            submission
        );

        let store = MemoryStore::new();
        let public = crate::mint::client_key(&store)
            .unwrap()
            .public_key()
            .unwrap();
        let registration = Submission::RegisterKey(ClientKey::of(&public));
        let wire = serde_json_lenient::to_string(&registration).unwrap();
        assert!(wire.contains(r#""submit":"register_key""#), "{wire}");
        assert_eq!(
            serde_json_lenient::from_str::<Submission>(&wire).unwrap(),
            registration
        );
        // A registration appends no record: it is no audit submission.
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path().join("audit.jsonl")).unwrap();
        assert!(matches!(
            submit(&mut log, &mut Revocations::default(), &registration),
            Err(ControlError::NotAudit)
        ));
        // And a registration that carries no P-256 point registers nothing.
        let mut keys = ClientKeys::new();
        assert!(matches!(
            keys.register(&ClientKey {
                key: "not-a-point".to_owned()
            }),
            Err(ControlError::InvalidClientKey)
        ));
        assert!(keys.is_empty());
    }

    /// BEP-063's socket: the proxy takes a key registration and an audit
    /// submission over a socket owned by the user it runs as, mode `0600`,
    /// inside a directory only that user may enter — and the redemption
    /// listener takes neither, even from a box it serves.
    #[tokio::test]
    async fn control_socket_is_owner_only_and_separate_from_listener() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("bep").join("control.sock");
        let listener = bind(&socket_path).unwrap();

        // Owner-only, and owned by the user this process runs as: the same
        // owner as a file the process has just written beside it.
        let ours = dir.path().join("owned-by-us");
        std::fs::write(&ours, b"").unwrap();
        let held = status(&socket_path).unwrap();
        assert!(held.owner_only(), "{held:?}");
        assert_eq!(held.mode, 0o600);
        assert_eq!(held.mode & 0o077, 0, "group and other reach it: {held:?}");
        assert_eq!(held.uid, std::fs::metadata(&ours).unwrap().uid());
        let parent = std::fs::metadata(socket_path.parent().unwrap()).unwrap();
        assert_eq!(parent.permissions().mode() & 0o777, SOCKET_DIR_MODE);

        // The proxy behind it, with its redemption listener on TCP and one box
        // attributed to the address the test connects from.
        let proxy = proxy_over(&dir.path().join("audit.jsonl"));
        let redemption = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redemption_addr = redemption.local_addr().unwrap();
        tokio::spawn(Arc::clone(&proxy.proxy).serve(redemption));
        serve_control(Arc::clone(&proxy.proxy), listener);

        // Over the control socket: the client's key is registered, and its
        // mint reaches the log the proxy alone writes.
        let store = MemoryStore::new();
        let public = crate::mint::client_key(&store)
            .unwrap()
            .public_key()
            .unwrap();
        let registered: Registered = serde_json_lenient::from_str(
            &exchange(
                &socket_path,
                &Submission::RegisterKey(ClientKey::of(&public)),
            )
            .await,
        )
        .unwrap();
        assert_eq!(registered.key, Fingerprint::of(&public).to_string());
        assert_eq!(registered.keys, 1);
        let minted: Record = serde_json_lenient::from_str(
            &exchange(&socket_path, &Submission::Audit(event(Kind::Mint))).await,
        )
        .unwrap();
        assert_eq!(minted.kind, Kind::Mint);
        assert_eq!(records(&proxy.log_path), 1);

        // The same two submissions to the redemption listener, from a source
        // it serves as a box: neither is taken, and the log is untouched.
        for submission in [
            Submission::RegisterKey(ClientKey::of(&public)),
            Submission::Audit(event(Kind::Mint)),
        ] {
            let answer = submit_over_tcp(&proxy, redemption_addr, &submission).await;
            assert!(
                serde_json_lenient::from_str::<Record>(&answer).is_err(),
                "the redemption listener answered a submission with a record: {answer}"
            );
            assert!(
                serde_json_lenient::from_str::<Registered>(&answer).is_err(),
                "the redemption listener registered a key: {answer}"
            );
            assert_eq!(
                records(&proxy.log_path),
                1,
                "a submission to the redemption listener reached the log: {answer}"
            );
        }
    }

    /// A proxy with its audit log, for the socket's sake: no module reachable,
    /// no upstream routed, and one box attributed per source the test adds.
    struct ProxyUnderTest {
        proxy: Arc<Proxy<MemoryStore>>,
        log_path: PathBuf,
        attachments: Arc<Mutex<HashMap<SocketAddr, Sender>>>,
    }

    fn proxy_over(log_path: &Path) -> ProxyUnderTest {
        let keys: &'static Keys<MemoryStore> =
            Box::leak(Box::new(Keys::open(MemoryStore::new()).unwrap()));
        let authority = Authority::open(keys, DeclaredUnion::of([["api.github.com"]])).unwrap();
        let log = Log::open(log_path).unwrap();
        let attachments = Arc::new(Mutex::new(HashMap::new()));
        let table = Arc::clone(&attachments);
        let config = Config {
            modules: vec![Module {
                id: "github".to_owned(),
                host_set: vec!["api.github.com:443".to_owned()],
                version: 1,
            }],
            store_authorities: Vec::new(),
            attachments: Arc::new(move |source: SocketAddr| {
                table.lock().unwrap().get(&source).cloned()
            }),
            trust: Trust::new(RootCertStore::empty()),
            resolver: Arc::new(|_: &str, _: u16| None),
        };
        ProxyUnderTest {
            proxy: Arc::new(Proxy::new(keys, authority, log, config).unwrap()),
            log_path: log_path.to_path_buf(),
            attachments,
        }
    }

    /// The accept loop behind the control socket: one JSON-line submission per
    /// connection, the proxy's answer back on the same line. A registration
    /// goes to the keys the proxy verifies handles under; an audit submission
    /// goes to the proxy's own intake.
    fn serve_control(proxy: Arc<Proxy<MemoryStore>>, listener: UnixListener) {
        let keys = Arc::new(Mutex::new(ClientKeys::new()));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let proxy = Arc::clone(&proxy);
                let keys = Arc::clone(&keys);
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut line = String::new();
                    BufReader::new(reader).read_line(&mut line).await.unwrap();
                    let reply = match serde_json_lenient::from_str::<Submission>(&line).unwrap() {
                        Submission::RegisterKey(key) => {
                            keys.lock().unwrap().register(&key).map(|registered| {
                                serde_json_lenient::to_string(&registered).unwrap()
                            })
                        }
                        submission => proxy
                            .submit(&submission)
                            .map(|record| serde_json_lenient::to_string(&record).unwrap()),
                    };
                    let reply = reply.unwrap_or_else(|error| format!(r#"{{"error":"{error}"}}"#));
                    writer
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                });
            }
        });
    }

    /// Submits over the control socket the way the client does: one JSON line
    /// out, one line back.
    async fn exchange(socket: &Path, submission: &Submission) -> String {
        let stream = UnixStream::connect(socket).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut line = serde_json_lenient::to_string(submission).unwrap();
        line.push('\n');
        writer.write_all(line.as_bytes()).await.unwrap();
        let mut reply = String::new();
        BufReader::new(reader).read_line(&mut reply).await.unwrap();
        reply.trim().to_owned()
    }

    /// Writes `submission` to the redemption listener from a source the proxy
    /// serves as a box, and reads whatever it answers.
    async fn submit_over_tcp(
        proxy: &ProxyUnderTest,
        addr: SocketAddr,
        submission: &Submission,
    ) -> String {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source = socket.local_addr().unwrap();
        proxy.attachments.lock().unwrap().insert(
            source,
            Sender {
                box_id: "box-a1".to_owned(),
                addressing: Addressing::OwnIp,
                egress: None,
            },
        );
        let mut stream = socket.connect(addr).await.unwrap();
        let mut line = serde_json_lenient::to_string(submission).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        // A listener that answers nothing is as much a refusal as one that
        // answers a 400, so the read is bounded rather than waited out.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut answer),
        )
        .await;
        String::from_utf8_lossy(&answer).into_owned()
    }

    /// The records the log holds.
    fn records(path: &Path) -> usize {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    }
}
