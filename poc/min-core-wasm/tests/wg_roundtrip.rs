//! Two in-process mesh nodes — each a boringtun `Tunn` plus a smoltcp stack —
//! cross-connected by in-memory datagram queues (what a WebSocket carries in
//! the browser). The "daemon" node listens on TCP/22 inside the tunnel and
//! runs the fake-minimald russh server on the accepted socket; the "tab" node
//! connects and runs the attach handshake through it. No sockets, no root.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use min_core::wg::{DatagramPipe, WgConfig, WgStack};
use min_core::{Attach, Event, Grid};
use russh::server;

use min_core::testing::{FakeMinimald, host_key};

const TAB_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 2);
const DAEMON_IP: Ipv4Addr = Ipv4Addr::new(10, 90, 0, 1);

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from([seed; 32]);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// Bring up both nodes; return the tab's stack and a stream on which the
/// daemon node has accepted the tab's TCP connection (russh server already
/// running on it).
fn mesh() -> (WgStack, WgStack) {
    let (tab_priv, tab_pub) = keypair(0x11);
    let (daemon_priv, daemon_pub) = keypair(0x22);
    let (tab_pipe, daemon_pipe) = DatagramPipe::pair(256);

    let (tab, tab_driver) = WgStack::new(
        WgConfig {
            private_key: tab_priv,
            peer_public_key: daemon_pub,
            local_ip: TAB_IP,
            prefix_len: 24,
            peer_ip: DAEMON_IP,
            persistent_keepalive_secs: Some(25),
            initiate: true,
        },
        tab_pipe,
    );
    let (daemon, daemon_driver) = WgStack::new(
        WgConfig {
            private_key: daemon_priv,
            peer_public_key: tab_pub,
            local_ip: DAEMON_IP,
            prefix_len: 24,
            peer_ip: TAB_IP,
            persistent_keepalive_secs: None,
            initiate: false,
        },
        daemon_pipe,
    );
    tokio::spawn(tab_driver);
    tokio::spawn(daemon_driver);
    (tab, daemon)
}

async fn next_text(reader: &mut min_core::Reader) -> String {
    match tokio::time::timeout(Duration::from_secs(10), reader.next()).await {
        Ok(Some(Event::Data(bytes))) => String::from_utf8(bytes.to_vec()).unwrap(),
        other => panic!("expected data, got {other:?}"),
    }
}

#[tokio::test]
async fn ssh_attach_through_the_tunnel() {
    let (tab, daemon) = mesh();

    // Daemon side: SSH server on TCP/22 inside the tunnel.
    let accepted = daemon.listen(22);
    let config = Arc::new(server::Config {
        keys: vec![host_key()],
        ..Default::default()
    });
    tokio::spawn(async move {
        let running = server::run_stream(config, accepted, FakeMinimald::default())
            .await
            .expect("server handshake over the tunnel");
        let _ = running.await;
    });

    // Tab side: TCP connect through WireGuard, then the min attach sequence.
    let stream = tab.connect(22);
    let attached = tokio::time::timeout(
        Duration::from_secs(10),
        Attach::connect(stream, "sess-wg", "xterm-256color", Grid { cols: 80, rows: 24 }),
    )
    .await
    .expect("attach did not time out")
    .expect("attach handshake through the tunnel");
    assert!(tab.handshaken(), "tab completed a WireGuard handshake");
    assert!(daemon.handshaken(), "daemon completed a WireGuard handshake");

    let (writer, mut reader) = attached.split();
    assert_eq!(next_text(&mut reader).await, "attached sess-wg 80x24\r\n");

    writer.write(b"hello\n").await.unwrap();
    assert_eq!(next_text(&mut reader).await, "echo hello\n");

    writer.resize(Grid { cols: 132, rows: 40 }).await.unwrap();
    assert_eq!(next_text(&mut reader).await, "resize 132x40\r\n");

    // Something bigger than one MTU, so TCP segmentation inside the tunnel
    // and the interface's reassembly are both exercised.
    let big = vec![b'x'; 20_000];
    let mut payload = big.clone();
    payload.push(b'\n');
    writer.write(&payload).await.unwrap();
    // The write arrives at the server as several SSH data chunks, and the
    // fake server prefixes each one, so strip the prefixes before comparing.
    let mut got = String::new();
    while got.replace("echo ", "").len() < big.len() + 1 {
        got.push_str(&next_text(&mut reader).await);
    }
    assert!(got.starts_with("echo "), "{}", &got[..20]);
    let body = got.replace("echo ", "");
    assert_eq!(body.len(), big.len() + 1);
    assert_eq!(body.trim_end().as_bytes(), &big[..]);

    writer.write(b"exit\n").await.unwrap();
    let mut seen = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(10), reader.next()).await {
        let is_close = matches!(event, Event::Closed);
        seen.push(format!("{event:?}"));
        if is_close {
            break;
        }
    }
    assert!(seen.iter().any(|e| e == "Exit(7)"), "{seen:?}");
    assert_eq!(seen.last().map(String::as_str), Some("Closed"), "{seen:?}");
}
