//! Test doubles shared by the native tests and `examples/wg-peer.rs`: a russh
//! server that enforces the same preconditions `crates/minimald/src/connection.rs`
//! does (`shell` refused without a pty and `MINIMAL_SESSION_ID`), a throwaway
//! host key from `ssh-keygen`, and a duplex-pipe server. Never compiled for wasm.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use russh::keys::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

use crate::MINIMAL_SESSION_ID_ENV;
use crate::wg::{DatagramPipe, WgConfig, WgStack};

#[derive(Default)]
pub struct FakeMinimald {
    env: HashMap<ChannelId, HashMap<String, String>>,
    pty: HashSet<ChannelId>,
    grid: HashMap<ChannelId, (u32, u32)>,
}

impl server::Handler for FakeMinimald {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.env
            .entry(id)
            .or_default()
            .insert(name.to_string(), value.to_string());
        session.channel_success(id)
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty.insert(id);
        self.grid.insert(id, (cols, rows));
        session.channel_success(id)
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        let session_id = self
            .env
            .get(&id)
            .and_then(|env| env.get(MINIMAL_SESSION_ID_ENV))
            .cloned();
        match (self.pty.contains(&id), session_id) {
            (true, Some(session_id)) => {
                session.channel_success(id)?;
                let (cols, rows) = self.grid[&id];
                session.data(id, format!("attached {session_id} {cols}x{rows}\r\n"))
            }
            _ => session.channel_failure(id),
        }
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.grid.insert(id, (cols, rows));
        session.data(id, format!("resize {cols}x{rows}\r\n"))
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if data == b"exit\n" {
            // All three through the handle so they are queued in order; mixing
            // the async handle with the sync `Session` methods sends close first.
            let handle = session.handle();
            let _ = handle.exit_status_request(id, 7).await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
            return Ok(());
        }
        let mut echo = b"echo ".to_vec();
        echo.extend_from_slice(data);
        session.data(id, echo)
    }
}

pub fn host_key() -> PrivateKey {
    let dir = tempdir();
    let path = dir.join("host_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&path)
        .status()
        .expect("ssh-keygen on PATH");
    assert!(status.success(), "ssh-keygen failed");
    let pem = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    PrivateKey::from_openssh(pem).unwrap()
}

pub fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("min-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Client end of a pipe whose server end runs `FakeMinimald`.
pub fn serve() -> tokio::io::DuplexStream {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let config = Arc::new(server::Config {
        keys: vec![host_key()],
        ..Default::default()
    });
    tokio::spawn(async move {
        let running = server::run_stream(config, server_io, FakeMinimald::default())
            .await
            .expect("server handshake");
        let _ = running.await;
    });
    client_io
}


/// Serve one WireGuard-over-WebSocket peer on an accepted TCP connection:
/// one `Tunn` in the daemon role, a smoltcp stack listening on TCP/22 inside
/// the tunnel, and [`FakeMinimald`] on the accepted socket. One WireGuard
/// datagram per binary WebSocket frame, both directions.
pub async fn serve_wg_over_ws(
    tcp: tokio::net::TcpStream,
    cfg: WgConfig,
    host_key: PrivateKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    let ws = tokio_tungstenite::accept_async(tcp).await?;
    let (mut sink, mut source) = ws.split();
    let (to_network_tx, mut to_network_rx) = mpsc::channel::<Vec<u8>>(256);
    let (from_network_tx, from_network_rx) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = source.next().await {
            if let Message::Binary(bytes) = msg
                && from_network_tx.send(bytes.to_vec()).await.is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(datagram) = to_network_rx.recv().await {
            if sink.send(Message::Binary(datagram.into())).await.is_err() {
                break;
            }
        }
    });
    let (stack, driver) = WgStack::new(
        cfg,
        DatagramPipe {
            to_network: to_network_tx,
            from_network: from_network_rx,
        },
    );
    tokio::spawn(driver);
    let accepted = stack.listen(22);
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        ..Default::default()
    });
    let running = server::run_stream(config, accepted, FakeMinimald::default()).await?;
    running.await?;
    Ok(())
}

/// The client half of the same framing, for tests: a `DatagramPipe` over a
/// WebSocket client connection to `url`.
pub async fn ws_datagram_client(
    url: &str,
) -> Result<DatagramPipe, Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    let (ws, _) = tokio_tungstenite::connect_async(url).await?;
    let (mut sink, mut source) = ws.split();
    let (to_network_tx, mut to_network_rx) = mpsc::channel::<Vec<u8>>(256);
    let (from_network_tx, from_network_rx) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = source.next().await {
            if let Message::Binary(bytes) = msg
                && from_network_tx.send(bytes.to_vec()).await.is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(datagram) = to_network_rx.recv().await {
            if sink.send(Message::Binary(datagram.into())).await.is_err() {
                break;
            }
        }
    });
    Ok(DatagramPipe {
        to_network: to_network_tx,
        from_network: from_network_rx,
    })
}
