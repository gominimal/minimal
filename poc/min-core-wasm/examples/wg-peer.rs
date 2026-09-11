//! Stand-in for "minimald with a WireGuard-over-WebSocket ingress", so a
//! browser can be a mesh node against something real before the daemon has
//! the ingress. Per WebSocket connection: one boringtun `Tunn` (daemon role,
//! passive), one smoltcp stack listening on TCP/22 inside the tunnel, and the
//! fake-minimald russh server on the accepted socket. Prints the peer config
//! the page passes to `attach_mesh`.
//!
//!     cargo run --example wg-peer -- 127.0.0.1:7691 [/tmp/peer.json] [--auth stub | --session-socket <minimald.sock>]
//!
//! `--auth stub` (Stage 2): the daemon accepts certificate auth only, decided
//! by the core's `verify_user_cert` against a throwaway User CA; it presents
//! a host certificate from a throwaway Host CA; and the same listener serves
//! the stub's HTTP API (`/ssh/ca`, `/certify`, `/token`, `/mesh/bind`,
//! `/decisions`) with CORS. `--session-socket <path>` (Stage 3a): forward the
//! in-tunnel SSH stream to a real `minimald` on that socket instead of the
//! fake server, so the tab attaches to a real session; the page's sessionId
//! must then be a real session uuid. Throwaway: keys are generated at startup
//! and printed; nothing persists.

use std::net::Ipv4Addr;
use std::sync::Arc;

use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use min_core::stub::Stub;
use min_core::testing::{PeerConfig, host_key, serve_connection};
use min_core::wg::WgConfig;
use tokio::net::TcpListener;

const DAEMON_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 1);
const TAB_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 2);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::main]
async fn main() -> anyhow_lite::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let auth_stub = args.windows(2).any(|w| w[0] == "--auth" && w[1] == "stub");
    let session_socket = args
        .windows(2)
        .find(|w| w[0] == "--session-socket")
        .map(|w| std::path::PathBuf::from(&w[1]));
    if auth_stub && session_socket.is_some() {
        return Err("--auth stub terminates SSH here; --session-socket forwards it to a daemon: pick one".into());
    }
    let positional: Vec<&String> = {
        let mut out = Vec::new();
        let mut skip = false;
        for (i, a) in args.iter().enumerate() {
            if skip {
                skip = false;
                continue;
            }
            if a == "--auth" || a == "--session-socket" {
                skip = true;
                continue;
            }
            let _ = i;
            out.push(a);
        }
        out
    };
    let listen = positional.first().map(|s| s.to_string()).unwrap_or_else(|| "127.0.0.1:7691".to_string());
    let config_out = positional.get(1).map(|s| s.to_string());

    let daemon_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let tab_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let daemon_public = PublicKey::from(&daemon_secret);
    let tab_public = PublicKey::from(&tab_secret);
    let host_key = host_key();

    let stub = auth_stub.then(|| Arc::new(Stub::new(&DAEMON_IP.to_string())));
    let host_cert = stub.as_ref().map(|s| {
        s.ca.mint_host_cert(
            &host_key.public_key(),
            &[DAEMON_IP.to_string(), "wg-peer".to_string()],
            min_core::rt::unix_now(),
        )
    });

    let mut page_config = serde_json::json!({
        "wsUrl": format!("ws://{listen}"),
        "privateKey": b64(&tab_secret.to_bytes()),
        "peerPublicKey": b64(daemon_public.as_bytes()),
        "localIp": TAB_IP.to_string(),
        "peerIp": DAEMON_IP.to_string(),
        "prefixLen": 24,
        "sshPort": 22,
    });
    if let Some(s) = &stub {
        page_config["auth"] = serde_json::json!({
            "issuerUrl": format!("http://{listen}"),
            "username": s.username,
            "expectedHostPrincipal": s.host_principal,
            "hostCa": [s.ca.host_ca_public()],
        });
    }
    if let Some(p) = &session_socket {
        page_config["sessionSocket"] = serde_json::json!(p.display().to_string());
    }
    eprintln!(
        "wg-peer: listening on ws://{listen}{}; page config:\n{page_config:#}",
        if auth_stub {
            " (certificate auth, stub CA + HTTP API on the same port)".to_string()
        } else if let Some(p) = &session_socket {
            format!(" (forwarding in-tunnel SSH to minimald at {})", p.display())
        } else {
            String::new()
        }
    );
    if let Some(path) = config_out {
        std::fs::write(&path, page_config.to_string())?;
    }

    let listener = TcpListener::bind(&listen).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        let peer = PeerConfig {
            wg: WgConfig {
                private_key: daemon_secret.to_bytes(),
                peer_public_key: tab_public.to_bytes(),
                local_ip: DAEMON_IP,
                prefix_len: 24,
                peer_ip: TAB_IP,
                persistent_keepalive_secs: None,
                initiate: false,
            },
            host_key: host_key.clone(),
            host_cert: host_cert.clone(),
            auth: stub.as_ref().map(|s| s.daemon_auth.clone()),
            session_socket: session_socket.clone(),
        };
        let stub = stub.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(tcp, peer, stub).await {
                eprintln!("wg-peer: connection from {addr} ended: {e}");
            }
        });
    }
}

/// Minimal `anyhow` so the example adds no dependency.
mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
