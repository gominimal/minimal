//! The Stage 2 stand-in for Gatehouse's certificate plane, next to the
//! WebSocket peer in `examples/wg-peer.rs`: throwaway User and Host CAs
//! minted at startup, `/ssh/ca`, `/certify` (with the refusal cases the arch
//! vectors name, on request), no-op `/token` and `/mesh/bind`, `/decisions`.
//! All routes carry CORS headers so a page on another origin can call them.
//! Native only; nothing here is Gatehouse and nothing here persists.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Certificate, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::credential::Anchors;
use crate::rt;
use crate::testing::{DaemonAuth, generate_ed25519_key};

/// Which certificate `/certify` should mint: a good one, or one that fails a
/// specific check. Names follow the arch vectors' `invalid/` cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    Valid,
    /// A valid certificate for a different key than the one presented.
    OtherKey,
    /// Signed by a CA no daemon trusts.
    RogueCa,
    /// A host certificate offered as a user certificate.
    HostType,
    /// Carries a critical option no implementation knows.
    UnknownCritical,
    /// Valid, but its serial is on the revocation list.
    Revoked,
    Expired,
    NotYetValid,
    /// A byte of the signature flipped after signing.
    Tampered,
}

impl Case {
    pub fn parse(s: &str) -> Option<Case> {
        Some(match s {
            "valid" | "" => Case::Valid,
            "other-key" => Case::OtherKey,
            "rogue-ca" => Case::RogueCa,
            "host-type" => Case::HostType,
            "unknown-critical" => Case::UnknownCritical,
            "revoked" => Case::Revoked,
            "expired" => Case::Expired,
            "not-yet-valid" => Case::NotYetValid,
            "tampered" => Case::Tampered,
            _ => return None,
        })
    }

    pub const ALL: [&'static str; 9] = [
        "valid",
        "other-key",
        "rogue-ca",
        "host-type",
        "unknown-critical",
        "revoked",
        "expired",
        "not-yet-valid",
        "tampered",
    ];
}

/// Throwaway CAs. The revoked set is shared with the daemon's decision.
pub struct StubCa {
    user_ca: PrivateKey,
    host_ca: PrivateKey,
    rogue_ca: PrivateKey,
    next_serial: AtomicU64,
    pub revoked: Arc<Mutex<HashSet<u64>>>,
    pub trust_domain: String,
}

pub const EXCHANGE_TTL_SECS: u64 = 900;

impl StubCa {
    pub fn generate() -> Self {
        Self {
            user_ca: generate_ed25519_key(),
            host_ca: generate_ed25519_key(),
            rogue_ca: generate_ed25519_key(),
            next_serial: AtomicU64::new(1000),
            revoked: Arc::new(Mutex::new(HashSet::new())),
            trust_domain: "stub.minimal.dev".to_string(),
        }
    }

    pub fn user_ca_public(&self) -> String {
        self.user_ca.public_key().to_openssh().expect("openssh")
    }

    pub fn host_ca_public(&self) -> String {
        self.host_ca.public_key().to_openssh().expect("openssh")
    }

    pub fn rogue_ca_public(&self) -> String {
        self.rogue_ca.public_key().to_openssh().expect("openssh")
    }

    /// What a daemon trusts for user certificates.
    pub fn user_anchors(&self) -> Anchors {
        Anchors::from_openssh_lines([self.user_ca_public().as_str()]).expect("anchor")
    }

    /// What a client trusts for host certificates.
    pub fn host_anchors(&self) -> Anchors {
        Anchors::from_openssh_lines([self.host_ca_public().as_str()]).expect("anchor")
    }

    fn nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        getrandom::getrandom(&mut n).expect("os randomness");
        n
    }

    /// A Gatehouse-shaped user certificate (§5.3 key_id and extensions) for
    /// `public_key`, minted per `case`. Returns the OpenSSH certificate line,
    /// its serial and the key_id.
    pub fn mint_user_cert(
        &self,
        public_key: &PublicKey,
        username: &str,
        subject: &str,
        case: Case,
        now: u64,
    ) -> Result<MintedCert, String> {
        let serial = self.next_serial.fetch_add(1, Ordering::SeqCst);
        let (valid_after, valid_before) = match case {
            Case::Expired => (now - 3600, now - 60),
            Case::NotYetValid => (now + 3600, now + 3600 + EXCHANGE_TTL_SECS),
            _ => (now - 30, now + EXCHANGE_TTL_SECS),
        };
        let other_key = generate_ed25519_key();
        let key_data = match case {
            Case::OtherKey => other_key.public_key().key_data().clone(),
            _ => public_key.key_data().clone(),
        };
        let mut txn = [0u8; 8];
        getrandom::getrandom(&mut txn).map_err(|e| e.to_string())?;
        let key_id = format!(
            r#"{{"v":1,"sub":"{subject}","td":"{}","txn":"{}","chain":0}}"#,
            self.trust_domain,
            hex(&txn)
        );
        let mut b = Builder::new(Self::nonce(), key_data, valid_after, valid_before).map_err(|e| e.to_string())?;
        b.serial(serial).map_err(|e| e.to_string())?;
        b.cert_type(if case == Case::HostType { CertType::Host } else { CertType::User })
            .map_err(|e| e.to_string())?;
        b.key_id(key_id.clone()).map_err(|e| e.to_string())?;
        b.valid_principal(subject).map_err(|e| e.to_string())?;
        b.valid_principal(username).map_err(|e| e.to_string())?;
        b.extension("permit-pty", "").map_err(|e| e.to_string())?;
        b.extension("subject@gatehouse.dev", subject).map_err(|e| e.to_string())?;
        b.extension("scope@gatehouse.dev", "box:ssh").map_err(|e| e.to_string())?;
        if case == Case::UnknownCritical {
            b.critical_option("x-min-core-test@minimal.dev", "1").map_err(|e| e.to_string())?;
        }
        let ca = if case == Case::RogueCa { &self.rogue_ca } else { &self.user_ca };
        let cert = b.sign(ca).map_err(|e| e.to_string())?;
        let mut line = cert.to_openssh().map_err(|e| e.to_string())?;
        if case == Case::Tampered {
            line = tamper(&line)?;
        }
        if case == Case::Revoked {
            self.revoked.lock().unwrap().insert(serial);
        }
        Ok(MintedCert {
            certificate: line,
            serial,
            key_id,
            valid_after,
            valid_before,
        })
    }

    /// A host certificate on the daemon's own key, naming `principals`.
    pub fn mint_host_cert(&self, host_key: &PublicKey, principals: &[String], now: u64) -> Certificate {
        let serial = self.next_serial.fetch_add(1, Ordering::SeqCst);
        let mut b = Builder::new(Self::nonce(), host_key.key_data().clone(), now - 30, now + 30 * 24 * 3600)
            .expect("builder");
        b.serial(serial).expect("serial");
        b.cert_type(CertType::Host).expect("type");
        b.key_id(format!("host:{}", principals.first().cloned().unwrap_or_default()))
            .expect("key_id");
        for p in principals {
            b.valid_principal(p.clone()).expect("principal");
        }
        b.sign(&self.host_ca).expect("sign host cert")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Flip one byte inside the certificate's signature so it no longer verifies.
fn tamper(line: &str) -> Result<String, String> {
    let mut parts = line.splitn(3, ' ');
    let alg = parts.next().ok_or("cert line")?;
    let b64 = parts.next().ok_or("cert line")?;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    let n = bytes.len();
    bytes[n - 2] ^= 0x55;
    Ok(format!("{alg} {}", base64::engine::general_purpose::STANDARD.encode(bytes)))
}

#[derive(Clone, Debug, Serialize)]
pub struct MintedCert {
    pub certificate: String,
    pub serial: u64,
    pub key_id: String,
    pub valid_after: u64,
    pub valid_before: u64,
}

/// Everything the HTTP side needs.
pub struct Stub {
    pub ca: StubCa,
    pub daemon_auth: Arc<DaemonAuth>,
    /// Principal the host certificate carries, which clients must expect.
    pub host_principal: String,
    pub username: String,
    pub subject: String,
}

impl Stub {
    pub fn new(host_principal: &str) -> Self {
        let ca = StubCa::generate();
        let daemon_auth = Arc::new(DaemonAuth::new(ca.user_anchors(), ca.revoked.clone()));
        Self {
            ca,
            daemon_auth,
            host_principal: host_principal.to_string(),
            username: "dev".to_string(),
            subject: "u:stub:1".to_string(),
        }
    }
}

#[derive(Deserialize)]
struct CertifyRequest {
    public_key: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    ttl: Option<u64>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    case: Option<String>,
}

#[derive(Serialize)]
struct CertifyResponse {
    certificate: String,
    serial: u64,
    key_id: String,
    valid_after: u64,
    valid_before: u64,
    profile: String,
    username: String,
    case: String,
}

#[derive(Deserialize)]
struct MeshBindRequest {
    network: String,
    wg_pub: String,
}

/// Route one parsed request. Returns (status, JSON body).
pub fn route(stub: &Stub, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> (u16, String) {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let err = |status: u16, code: &str, detail: String| {
        (status, serde_json::json!({ "error": code, "detail": detail }).to_string())
    };
    match (method, path) {
        ("OPTIONS", _) => (204, String::new()),
        ("GET", "/health") => (200, serde_json::json!({ "ok": true }).to_string()),
        ("GET", "/ssh/ca") => (
            200,
            serde_json::json!({
                "user_ca": [stub.ca.user_ca_public()],
                "host_ca": [stub.ca.host_ca_public()],
                "known_hosts": format!("@cert-authority * {}", stub.ca.host_ca_public()),
                "host_principal": stub.host_principal,
                "trust_domain": stub.ca.trust_domain,
                "rogue_ca_for_tests": [stub.ca.rogue_ca_public()],
            })
            .to_string(),
        ),
        ("POST", "/certify") => {
            let req: CertifyRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return err(400, "invalid_request", e.to_string()),
            };
            let public_key = match PublicKey::from_openssh(req.public_key.trim()) {
                Ok(k) => k,
                Err(e) => return err(400, "invalid_public_key", e.to_string()),
            };
            let case = match Case::parse(req.case.as_deref().unwrap_or("valid")) {
                Some(c) => c,
                None => return err(400, "invalid_case", format!("known cases: {:?}", Case::ALL)),
            };
            let profile = req.profile.unwrap_or_else(|| "exchange".to_string());
            if profile != "exchange" {
                return err(400, "unsupported_profile", "the stub mints exchange-profile certs only".into());
            }
            if let Some(ttl) = req.ttl
                && ttl > EXCHANGE_TTL_SECS
            {
                return err(400, "ttl_too_long", format!("max {EXCHANGE_TTL_SECS}"));
            }
            let username = req.username.unwrap_or_else(|| stub.username.clone());
            match stub
                .ca
                .mint_user_cert(&public_key, &username, &stub.subject, case, rt::unix_now())
            {
                Ok(m) => (
                    200,
                    serde_json::to_string(&CertifyResponse {
                        certificate: m.certificate,
                        serial: m.serial,
                        key_id: m.key_id,
                        valid_after: m.valid_after,
                        valid_before: m.valid_before,
                        profile,
                        username,
                        case: format!("{case:?}"),
                    })
                    .expect("json"),
                ),
                Err(e) => err(500, "mint_failed", e),
            }
        }
        ("POST", "/token") => {
            if header("dpop").is_none() {
                return err(400, "invalid_dpop_proof", "DPoP header required".into());
            }
            (
                200,
                serde_json::json!({
                    "access_token": "stub-access-token",
                    "token_type": "DPoP",
                    "expires_in": 900,
                    "refresh_token": "stub-refresh-token",
                    "scope": "box:ssh",
                })
                .to_string(),
            )
        }
        ("POST", "/mesh/bind") => {
            let req: MeshBindRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return err(400, "invalid_request", e.to_string()),
            };
            (
                200,
                serde_json::json!({
                    "binding": "stub-mesh-binding",
                    "network": req.network,
                    "wg_pub": req.wg_pub,
                    "exp": rt::unix_now() + 8 * 3600,
                })
                .to_string(),
            )
        }
        ("GET", "/decisions") => (
            200,
            serde_json::to_string(&stub.daemon_auth.decisions()).expect("json"),
        ),
        _ => err(404, "not_found", format!("{method} {path}")),
    }
}

/// Serve one HTTP/1.1 request on `tcp` (the connection is closed after).
pub async fn handle_http(mut tcp: tokio::net::TcpStream, stub: &Stub) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let path = target.split('?').next().unwrap_or("/").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (status, json) = route(stub, &method, &path, &headers, &body);
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type, authorization, dpop\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Max-Age: 600\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    tcp.write_all(response.as_bytes()).await?;
    tcp.shutdown().await?;
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
