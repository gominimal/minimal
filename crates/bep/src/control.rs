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
//! The client appends a `mint` record for each member it mints, and the
//! box's creator appends a `revocation` record when it destroys a live box
//! (BEP-067, BEP-043). The proxy is the audit log's only writer, so both go
//! through this socket. A revocation is in force from its reply on
//! ([`crate::revoke`]):
//!
//! ```text
//! > {"op":"record_mint","box_id":"<id>","identifier":"github:<instance>"}
//! < {"ok":true}
//! > {"op":"record_revocation","box_id":"<id>"}
//! < {"ok":true}
//! ```
//!
//! A destroy sends `record_revocation` before `forget_box`, so no request
//! from the box finds it forgotten and not yet revoked.
//!
//! A box id is 32 hex digits, or a UUID with its hyphens. The proxy stores it
//! as 32 lowercase hex digits, the form the listener names the box by, and
//! refuses any other text.
//!
//! An egress authority is `host` or `host:port`, and a `host` with no port
//! is port 443. The registration goes into the [`Boxes`] registry that the
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

use crate::boxes::{BoxRegistry, Boxes, Stance};
use crate::handle::{ClientKeys, parse_authority};
use crate::listener::bind_owner_only;
use crate::proxy::AuditWriter;
use crate::redeem::Authority;
use crate::revoke::{self, Revocations};

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
}

/// One audit request line: a record that the proxy appends to its audit
/// log for a client (BEP-067). It is a type of its own beside [`Request`],
/// and the control socket reads a line as either one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RecordRequest {
    /// Append the `mint` record of one member the client minted.
    RecordMint {
        /// The box id the member names.
        box_id: String,
        /// The member's identifier, `<store>:<id>`.
        identifier: String,
    },
    /// Put a revocation of a destroyed live box in force, and append its
    /// `revocation` record (BEP-043).
    RecordRevocation {
        /// The destroyed box's id.
        box_id: String,
    },
}

/// The audit log and the revocations the control socket writes to.
#[derive(Clone, Default)]
pub struct Trail {
    audit: Option<Arc<dyn AuditWriter>>,
    revocations: Revocations,
}

impl std::fmt::Debug for Trail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trail")
            .field("audit", &self.audit.is_some())
            .finish_non_exhaustive()
    }
}

impl Trail {
    /// A trail that appends to `audit` and puts revocations in force in
    /// `revocations`, the set the redeemer reads.
    #[must_use]
    pub fn new(audit: Arc<dyn AuditWriter>, revocations: Revocations) -> Self {
        Self {
            audit: Some(audit),
            revocations,
        }
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
/// registry `boxes`, with no audit log: a record request is refused.
#[must_use]
pub fn handle_line(line: &str, registry: &RwLock<ClientKeys>, boxes: &Boxes) -> Reply {
    handle_line_with(line, registry, boxes, &Trail::default())
}

/// Does one record request against `trail`.
fn handle_record(request: RecordRequest, trail: &Trail) -> Reply {
    let Some(audit) = &trail.audit else {
        return Reply::refused("this proxy keeps no audit log");
    };
    match request {
        RecordRequest::RecordMint { box_id, identifier } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            let identifier = identifier.trim();
            if identifier.is_empty() {
                return Reply::refused("the member identifier is empty");
            }
            audit.write(&revoke::mint_record(&box_id, identifier));
            tracing::debug!(box_id, identifier, "recorded a mint");
            Reply::done()
        }
        RecordRequest::RecordRevocation { box_id } => {
            let Some(box_id) = normalise_box_id(&box_id) else {
                return Reply::refused("the box id is not 32 hex digits");
            };
            // In force before the record is written, so the next request
            // from the box is refused whatever the append does.
            if revoke::record(&trail.revocations, &box_id) {
                audit.write(&revoke::revocation_record(&box_id));
                tracing::info!(box_id, "recorded a revocation of a destroyed box");
            } else {
                tracing::debug!(box_id, "the box's revocation is already in force");
            }
            Reply::done()
        }
    }
}

/// Does one request line against the client key `registry`, the box
/// registry `boxes`, and the audit log and revocations of `trail`.
#[must_use]
pub fn handle_line_with(
    line: &str,
    registry: &RwLock<ClientKeys>,
    boxes: &Boxes,
    trail: &Trail,
) -> Reply {
    if let Ok(record) = serde_json::from_str::<RecordRequest>(line) {
        return handle_record(record, trail);
    }
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
    }
}

/// The control socket.
#[derive(Debug)]
pub struct Control {
    inner: UnixListener,
    registry: Registry,
    boxes: BoxRegistry,
    trail: Trail,
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
            registry,
            boxes,
            trail: Trail::default(),
        })
    }

    /// This socket, with `trail` as the audit log and the revocations its
    /// record requests write to. Without one, a record request is refused.
    #[must_use]
    pub fn with_trail(mut self, trail: Trail) -> Self {
        self.trail = trail;
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
            let registry = Arc::clone(&self.registry);
            let boxes = Arc::clone(&self.boxes);
            tokio::spawn(serve(stream, registry, boxes, self.trail.clone()));
        }
    }
}

/// Serves one control connection, line by line.
async fn serve(stream: UnixStream, registry: Registry, boxes: BoxRegistry, trail: Trail) {
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
        let reply = handle_line_with(&line, &registry, &boxes, &trail);
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
