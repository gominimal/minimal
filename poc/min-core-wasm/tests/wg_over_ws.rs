//! The WebSocket framing end to end over a real loopback socket: the stand-in
//! daemon from `examples/wg-peer.rs` on one side, and on the other the same
//! client stack the browser runs, fed by a tokio-tungstenite client instead
//! of a `web_sys::WebSocket`. Proves the example and the frame-per-datagram
//! contract, natively.

use std::net::Ipv4Addr;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use min_core::testing::{host_key, serve_wg_over_ws, ws_datagram_client};
use min_core::wg::{WgConfig, WgStack};
use min_core::{Attach, Event, Grid};

#[tokio::test]
async fn attach_over_websocket_carried_wireguard() {
    let daemon_secret = StaticSecret::from([0x33u8; 32]);
    let tab_secret = StaticSecret::from([0x44u8; 32]);
    let daemon_public = PublicKey::from(&daemon_secret);
    let tab_public = PublicKey::from(&tab_secret);
    let daemon_ip = Ipv4Addr::new(10, 90, 0, 1);
    let tab_ip = Ipv4Addr::new(10, 90, 0, 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = host_key();
    let daemon_cfg = WgConfig {
        private_key: daemon_secret.to_bytes(),
        peer_public_key: tab_public.to_bytes(),
        local_ip: daemon_ip,
        prefix_len: 24,
        peer_ip: tab_ip,
        persistent_keepalive_secs: None,
        initiate: false,
    };
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = serve_wg_over_ws(tcp, daemon_cfg, key).await;
    });

    let pipe = ws_datagram_client(&format!("ws://{addr}")).await.unwrap();
    let (tab, driver) = WgStack::new(
        WgConfig {
            private_key: tab_secret.to_bytes(),
            peer_public_key: daemon_public.to_bytes(),
            local_ip: tab_ip,
            prefix_len: 24,
            peer_ip: daemon_ip,
            persistent_keepalive_secs: Some(25),
            initiate: true,
        },
        pipe,
    );
    tokio::spawn(driver);

    let attached = tokio::time::timeout(
        Duration::from_secs(10),
        Attach::connect(tab.connect(22), "sess-ws", "xterm-256color", Grid { cols: 100, rows: 30 }),
    )
    .await
    .expect("no timeout")
    .expect("attach over websocket-carried wireguard");
    let (writer, mut reader) = attached.split();
    let banner = match tokio::time::timeout(Duration::from_secs(10), reader.next()).await {
        Ok(Some(Event::Data(b))) => String::from_utf8(b.to_vec()).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(banner, "attached sess-ws 100x30\r\n");
    writer.write(b"ping\n").await.unwrap();
    let echo = match tokio::time::timeout(Duration::from_secs(10), reader.next()).await {
        Ok(Some(Event::Data(b))) => String::from_utf8(b.to_vec()).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(echo, "echo ping\n");
}

/// The WebSocket dies under an attached session: the SSH reader must end
/// within a couple of seconds, not hang until a TCP timeout.
#[tokio::test]
async fn dead_websocket_reaches_the_ssh_layer() {
    let daemon_secret = StaticSecret::from([0x55u8; 32]);
    let tab_secret = StaticSecret::from([0x66u8; 32]);
    let daemon_public = PublicKey::from(&daemon_secret);
    let tab_public = PublicKey::from(&tab_secret);
    let daemon_ip = Ipv4Addr::new(10, 90, 0, 1);
    let tab_ip = Ipv4Addr::new(10, 90, 0, 2);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = host_key();
    let daemon_cfg = WgConfig {
        private_key: daemon_secret.to_bytes(),
        peer_public_key: tab_public.to_bytes(),
        local_ip: daemon_ip,
        prefix_len: 24,
        peer_ip: tab_ip,
        persistent_keepalive_secs: None,
        initiate: false,
    };
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = serve_wg_over_ws(tcp, daemon_cfg, key).await;
    });

    let pipe = ws_datagram_client(&format!("ws://{addr}")).await.unwrap();
    let (tab, driver) = WgStack::new(
        WgConfig {
            private_key: tab_secret.to_bytes(),
            peer_public_key: daemon_public.to_bytes(),
            local_ip: tab_ip,
            prefix_len: 24,
            peer_ip: daemon_ip,
            persistent_keepalive_secs: Some(25),
            initiate: true,
        },
        pipe,
    );
    tokio::spawn(driver);
    let attached = tokio::time::timeout(
        Duration::from_secs(10),
        Attach::connect(tab.connect(22), "sess-dead", "xterm", Grid { cols: 80, rows: 24 }),
    )
    .await
    .unwrap()
    .unwrap();
    let (_writer, mut reader) = attached.split();
    assert!(matches!(reader.next().await, Some(Event::Data(_))), "banner");

    // Kill the daemon side outright: the WebSocket closes under the tunnel.
    server.abort();
    let started = std::time::Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), reader.next()).await {
            Ok(None) | Ok(Some(Event::Closed)) => break,
            Ok(Some(_)) => continue,
            Err(_) => panic!("reader still pending 5 s after the websocket died"),
        }
    }
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    assert!(tab.is_dead());
}
