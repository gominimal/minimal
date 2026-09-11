//! The stub's HTTP API on the same listener as the WebSocket ingress: CORS,
//! `/ssh/ca`, `/certify` (valid and a refusal case), `/token`, `/mesh/bind`,
//! `/decisions`, and a WebSocket upgrade still reaching the mesh.

use std::net::Ipv4Addr;
use std::sync::Arc;

use boringtun::x25519::{PublicKey as WgPublic, StaticSecret};
use min_core::stub::Stub;
use min_core::testing::{PeerConfig, generate_ed25519_key, serve_connection};
use min_core::wg::WgConfig;
use russh::keys::Certificate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start() -> (String, Arc<Stub>) {
    let stub = Arc::new(Stub::new("10.90.0.1"));
    let host_key = generate_ed25519_key();
    let host_cert = stub
        .ca
        .mint_host_cert(&host_key.public_key(), &["10.90.0.1".to_string()], min_core::rt::unix_now());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let daemon_secret = StaticSecret::from([0x81u8; 32]);
    let tab_secret = StaticSecret::from([0x82u8; 32]);
    let stub2 = stub.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let peer = PeerConfig {
                wg: WgConfig {
                    private_key: daemon_secret.to_bytes(),
                    peer_public_key: WgPublic::from(&tab_secret).to_bytes(),
                    local_ip: Ipv4Addr::new(10, 90, 0, 1),
                    prefix_len: 24,
                    peer_ip: Ipv4Addr::new(10, 90, 0, 2),
                    persistent_keepalive_secs: None,
                    initiate: false,
                },
                host_key: host_key.clone(),
                host_cert: Some(host_cert.clone()),
                auth: Some(stub2.daemon_auth.clone()),
                session_socket: None,
            };
            let stub3 = stub2.clone();
            tokio::spawn(async move {
                let _ = serve_connection(tcp, peer, Some(stub3)).await;
            });
        }
    });
    (addr.to_string(), stub)
}

async fn http(addr: &str, method: &str, path: &str, extra_headers: &str, body: &str) -> (u16, Vec<(String, String)>, String) {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
        body.len()
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tcp.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("response");
    let mut lines = head.lines();
    let status: u16 = lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    (status, headers, body.to_string())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn routes_and_cors() {
    let (addr, stub) = start().await;

    let (status, headers, _) = http(&addr, "OPTIONS", "/certify", "Origin: http://sandbox-1:4323\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type, x-test-consent\r\n", "").await;
    assert_eq!(status, 204);
    assert_eq!(header(&headers, "access-control-allow-origin"), Some("*"));
    let allowed = header(&headers, "access-control-allow-headers").unwrap();
    assert!(allowed.contains("dpop") && allowed.contains("x-test-consent"), "{allowed}");

    let (status, headers, body) = http(&addr, "GET", "/ssh/ca", "", "").await;
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "access-control-allow-origin"), Some("*"));
    let ca: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ca["host_ca"][0].as_str().unwrap(), stub.ca.host_ca_public());
    assert_eq!(ca["user_ca"][0].as_str().unwrap(), stub.ca.user_ca_public());
    assert_eq!(ca["host_principal"], "10.90.0.1");

    let key = generate_ed25519_key();
    let pubkey = key.public_key().to_openssh().unwrap();
    let body = serde_json::json!({ "public_key": pubkey, "profile": "exchange", "ttl": 900 }).to_string();
    let (status, _, resp) = http(&addr, "POST", "/certify", "Authorization: DPoP stub\r\nDPoP: stub\r\n", &body).await;
    assert_eq!(status, 200, "{resp}");
    let minted: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let cert = Certificate::from_openssh(minted["certificate"].as_str().unwrap()).unwrap();
    assert_eq!(minted["username"], "dev");
    assert!(cert.valid_principals().iter().any(|p| p == "dev"));
    assert!(cert.key_id().contains(r#""td":"stub.minimal.dev""#));
    assert_eq!(cert.valid_before() - cert.valid_after(), 930);
    min_core::credential::verify_user_cert(&cert, &stub.ca.user_anchors(), "dev", min_core::rt::unix_now(), |_| false)
        .expect("the stub's own decision accepts what it mints");

    let body = serde_json::json!({ "public_key": pubkey, "case": "expired" }).to_string();
    let (status, _, resp) = http(&addr, "POST", "/certify", "", &body).await;
    assert_eq!(status, 200);
    let minted: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let cert = Certificate::from_openssh(minted["certificate"].as_str().unwrap()).unwrap();
    assert!(cert.valid_before() < min_core::rt::unix_now());

    let (status, _, resp) = http(&addr, "POST", "/certify", "", r#"{"public_key":"garbage"}"#).await;
    assert_eq!(status, 400);
    assert!(resp.contains("invalid_public_key"), "{resp}");

    let (status, _, resp) = http(&addr, "POST", "/token", "", r#"{"grant_type":"authorization_code"}"#).await;
    assert_eq!(status, 400, "{resp}");
    let (status, _, resp) = http(&addr, "POST", "/token", "DPoP: stub-proof\r\n", r#"{"grant_type":"authorization_code"}"#).await;
    assert_eq!(status, 200, "{resp}");
    assert!(resp.contains("\"token_type\":\"DPoP\""));

    let (status, _, resp) = http(&addr, "POST", "/mesh/bind", "", r#"{"network":"stub","wg_pub":"AAAA"}"#).await;
    assert_eq!(status, 200, "{resp}");
    assert!(resp.contains("stub-mesh-binding"));

    let (status, _, resp) = http(&addr, "GET", "/decisions", "", "").await;
    assert_eq!(status, 200);
    assert_eq!(resp, "[]");

    let (status, _, _) = http(&addr, "GET", "/nope", "", "").await;
    assert_eq!(status, 404);
}
