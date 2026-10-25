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
//! A request the proxy cannot do gets `{"ok":false,"error":"<why>"}`, and the
//! connection stays open for the next line. The registered key goes into the
//! [`ClientKeys`] registry that the proxy verifies store handles under.

use std::io;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::audit::{Decision, Kind, Mapping, Outcome};
use crate::boxes::{BoxRegistry, Boxes, Stance};
use crate::handle::{ClientKeys, parse_authority};
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

/// Does one request line against the client key `registry` and the box
/// registry `boxes`. It keeps no revocation and writes no record: a
/// `revoke_box` goes into a set that ends with the call. The control socket
/// does its lines through [`Records::handle`].
#[must_use]
pub fn handle_line(line: &str, registry: &RwLock<ClientKeys>, boxes: &Boxes) -> Reply {
    handle_request(line, registry, boxes, &Revocations::default(), None)
}

impl Records {
    /// Does one request line against these records.
    #[must_use]
    pub fn handle(&self, line: &str) -> Reply {
        handle_request(
            line,
            &self.registry,
            &self.boxes,
            &self.revocations,
            self.audit.as_deref(),
        )
    }
}

/// Appends one record of `kind` for `box_id` to `audit`. A mint carries its
/// identifier and `admit`, and a revocation carries no identifier and
/// `refuse`. A record names no upstream, since neither is a request.
fn append(audit: Option<&dyn AuditWriter>, kind: Kind, box_id: &str, identifier: Option<String>) {
    let Some(audit) = audit else {
        return;
    };
    let outcome = match kind {
        Kind::Revocation => Outcome::Refuse,
        Kind::Decision | Kind::Mint => Outcome::Admit,
    };
    audit.write(&Decision {
        kind,
        box_id: box_id.to_owned(),
        authority: String::new(),
        identifier,
        mapping: Mapping::ModuleUnmapped,
        outcome,
        marker: None,
    });
}

/// Does one request line.
fn handle_request(
    line: &str,
    registry: &RwLock<ClientKeys>,
    boxes: &Boxes,
    revocations: &Revocations,
    audit: Option<&dyn AuditWriter>,
) -> Reply {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(err) => return Reply::refused(format!("the request is not valid: {err}")),
    };
    match request {
        Request::RegisterClientKey { key } => {
            let Ok(sec1) = URL_SAFE_NO_PAD.decode(key.trim()) else {
                return Reply::refused("the key is not unpadded base64url");
            };
            let registered = registry
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .register(&sec1);
            match registered {
                Ok(kid) => {
                    tracing::info!(kid, "registered a client key");
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
            append(audit, Kind::Mint, &box_id, Some(identifier.to_owned()));
            Reply::done()
        }
        Request::RevokeBox { box_id } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            // BEP-071: the revocation names the box id alone. It is in force
            // before the record is written, so no request after this reply
            // redeems a value that names the box.
            if crate::revoke::record(revocations, &box_id) {
                append(audit, Kind::Revocation, &box_id, None);
                tracing::info!(
                    box_id,
                    "recorded a revocation: every sealed value naming the box is refused"
                );
            }
            Reply::done()
        }
    }
}

/// The control socket.
#[derive(Debug)]
pub struct Control {
    inner: UnixListener,
    records: Records,
}

impl Control {
    /// Binds the control socket at `path`, mode `0600` in a `0700`
    /// directory.
    ///
    /// # Errors
    ///
    /// The I/O error of the directory, the bind or the mode change.
    pub fn bind(path: &Path, registry: Registry, boxes: BoxRegistry) -> io::Result<Self> {
        Ok(Self {
            inner: bind_owner_only(path)?,
            records: Records {
                registry,
                boxes,
                ..Records::default()
            },
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

    /// Serves connections until the accept fails.
    ///
    /// # Errors
    ///
    /// The accept's I/O error.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let stream = crate::listener::accept(&self.inner, "control socket").await?;
            tokio::spawn(serve(stream, self.records.clone()));
        }
    }
}

/// Serves one control connection, line by line.
async fn serve(stream: UnixStream, records: Records) {
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
        let reply = records.handle(&line);
        if write_reply(&mut write, &reply).await.is_err() {
            return;
        }
    }
}

async fn write_reply(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    reply: &Reply,
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
}
