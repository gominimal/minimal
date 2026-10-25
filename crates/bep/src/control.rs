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
//! A box id is 32 hex digits, or a UUID with its hyphens. The proxy stores it
//! as 32 lowercase hex digits, the form the listener names the box by, and
//! refuses any other text.
//!
//! An egress authority is `host` or `host:port`, and a `host` with no port
//! is port 443. The registration goes into the [`Boxes`] registry that the
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

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::boxes::{BoxRegistry, Boxes, Stance};
use crate::ca::{Ca, CaError, CaKey};
use crate::handle::{ClientKeys, parse_authority};
use crate::listener::bind_owner_only;
use crate::redeem::Authority;

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

/// Does one request line against the client key `registry` and the box
/// registry `boxes`.
#[must_use]
pub fn handle_line(line: &str, registry: &RwLock<ClientKeys>, boxes: &Boxes) -> Reply {
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
pub struct Control {
    inner: UnixListener,
    registry: Registry,
    boxes: BoxRegistry,
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
            rotation: None,
        })
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
            let registry = Arc::clone(&self.registry);
            let boxes = Arc::clone(&self.boxes);
            let rotation = self.rotation.clone();
            tokio::spawn(serve(stream, registry, boxes, rotation));
        }
    }
}

/// Serves one control connection, line by line.
async fn serve(
    stream: UnixStream,
    registry: Registry,
    boxes: BoxRegistry,
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
            write_reply(&mut write, &handle_line(&line, &registry, &boxes)).await
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
}
