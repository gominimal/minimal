//! Stand-in for "minimald with a WireGuard-over-WebSocket ingress", so a
//! browser can be a mesh node against something real before the daemon has
//! the ingress. Per WebSocket connection: one boringtun `Tunn` (daemon role,
//! passive), one smoltcp stack listening on TCP/22 inside the tunnel, and the
//! fake-minimald russh server on the accepted socket. Prints the peer config
//! the page passes to `attach_wg`.
//!
//!     cargo run --example wg-peer -- 127.0.0.1:7691
//!
//! Throwaway: keys are generated at startup and printed; nothing persists.

use std::net::Ipv4Addr;

use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use min_core::testing::{host_key, serve_wg_over_ws};
use min_core::wg::WgConfig;
use tokio::net::TcpListener;

const DAEMON_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 1);
const TAB_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 2);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::main]
async fn main() -> anyhow_lite::Result<()> {
    let listen = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7691".to_string());
    let daemon_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let tab_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let daemon_public = PublicKey::from(&daemon_secret);
    let tab_public = PublicKey::from(&tab_secret);

    let page_config = serde_json::json!({
        "wsUrl": format!("ws://{listen}"),
        "privateKey": b64(&tab_secret.to_bytes()),
        "peerPublicKey": b64(daemon_public.as_bytes()),
        "localIp": TAB_IP.to_string(),
        "peerIp": DAEMON_IP.to_string(),
        "prefixLen": 24,
        "sshPort": 22,
    });
    eprintln!("wg-peer: listening on ws://{listen}; page config:\n{page_config:#}");
    // Optional second argument: also write the config as JSON to a file, for
    // harnesses that cannot parse stderr (js/headless-check.mjs).
    if let Some(path) = std::env::args().nth(2) {
        std::fs::write(&path, page_config.to_string())?;
    }

    let host_key = host_key();
    let listener = TcpListener::bind(&listen).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        eprintln!("wg-peer: websocket from {addr}");
        let cfg = WgConfig {
            private_key: daemon_secret.to_bytes(),
            peer_public_key: tab_public.to_bytes(),
            local_ip: DAEMON_IP,
            prefix_len: 24,
            peer_ip: TAB_IP,
            persistent_keepalive_secs: None,
            initiate: false,
        };
        let host_key = host_key.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_wg_over_ws(tcp, cfg, host_key).await {
                eprintln!("wg-peer: connection from {addr} ended: {e}");
            }
        });
    }
}

/// Minimal `anyhow` so the example adds no dependency.
mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
