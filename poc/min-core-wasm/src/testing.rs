//! Test doubles shared by the native tests and `examples/wg-peer.rs`: a russh
//! server that enforces the same preconditions `crates/minimald/src/connection.rs`
//! does (`shell` refused without a pty and `MINIMAL_SESSION_ID`), a throwaway
//! host key from `ssh-keygen`, and a duplex-pipe server. Never compiled for wasm.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use russh::keys::{Certificate, PrivateKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use serde::Serialize;

use crate::MINIMAL_SESSION_ID_ENV;
use crate::credential::{Anchors, verify_user_cert};
use crate::rt;
use crate::wg::{DatagramPipe, WgConfig, WgStack};

/// What a daemon in certificate mode trusts and decides.
pub struct DaemonAuth {
    pub anchors: Anchors,
    pub revoked: Arc<Mutex<HashSet<u64>>>,
    decisions: Mutex<Vec<Decision>>,
}

/// One certificate decision, as `/decisions` reports it.
#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub at: u64,
    pub user: String,
    pub serial: u64,
    pub key_id: String,
    /// `"accepted"` or the refusal code.
    pub result: String,
}

impl DaemonAuth {
    pub fn new(anchors: Anchors, revoked: Arc<Mutex<HashSet<u64>>>) -> Self {
        Self {
            anchors,
            revoked,
            decisions: Mutex::new(Vec::new()),
        }
    }

    /// The daemon's decision function, the one `minimald` would run in
    /// `auth_openssh_certificate`.
    pub fn decide(&self, user: &str, cert: &Certificate) -> Result<(), String> {
        let revoked = self.revoked.clone();
        let result = verify_user_cert(cert, &self.anchors, user, rt::unix_now(), |serial| {
            revoked.lock().unwrap().contains(&serial)
        });
        let code = match &result {
            Ok(()) => "accepted".to_string(),
            Err(e) => e.code().to_string(),
        };
        self.decisions.lock().unwrap().push(Decision {
            at: rt::unix_now(),
            user: user.to_string(),
            serial: cert.serial(),
            key_id: cert.key_id().to_string(),
            result: code.clone(),
        });
        result.map_err(|_| code)
    }

    pub fn decisions(&self) -> Vec<Decision> {
        self.decisions.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub struct FakeMinimald {
    /// `None`: `auth_none` under local trust (today's UDS posture).
    /// `Some`: certificate auth only, decided by [`DaemonAuth`].
    auth: Option<Arc<DaemonAuth>>,
    env: HashMap<ChannelId, HashMap<String, String>>,
    pty: HashSet<ChannelId>,
    grid: HashMap<ChannelId, (u32, u32)>,
    /// Bytes since the last line end (`\n` or `\r`), per channel, so `exit`
    /// typed one keystroke at a time and finished with Enter is recognised.
    line: HashMap<ChannelId, Vec<u8>>,
}

impl FakeMinimald {
    pub fn with_auth(auth: Arc<DaemonAuth>) -> Self {
        Self {
            auth: Some(auth),
            ..Default::default()
        }
    }
}

impl server::Handler for FakeMinimald {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(match self.auth {
            None => Auth::Accept,
            Some(_) => Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
                partial_success: false,
            },
        })
    }

    async fn auth_openssh_certificate(&mut self, user: &str, certificate: &Certificate) -> Result<Auth, Self::Error> {
        Ok(match &self.auth {
            Some(auth) if auth.decide(user, certificate).is_ok() => Auth::Accept,
            _ => Auth::reject(),
        })
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
        // A terminal sends `\r` on Enter and there is no PTY line discipline
        // here to turn it into `\n`, so either byte ends a line.
        let line = self.line.entry(id).or_default();
        line.extend_from_slice(data);
        let mut exit = false;
        while let Some(end) = line.iter().position(|&b| b == b'\n' || b == b'\r') {
            let completed: Vec<u8> = line.drain(..=end).collect();
            if completed[..completed.len() - 1] == *b"exit" {
                exit = true;
            }
        }
        if exit {
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

/// A throwaway Ed25519 key from `ssh-keygen`.
pub fn generate_ed25519_key() -> PrivateKey {
    host_key()
}

pub fn host_key() -> PrivateKey {
    let dir = tempdir();
    let path = dir.join(format!("key_{}", std::process::id()));
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
    let dir = std::env::temp_dir().join(format!("min-core-test-{}-{}", std::process::id(), rt::now_ms()));
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


/// A stand-in daemon's identity and posture for one peer connection.
#[derive(Clone)]
pub struct PeerConfig {
    pub wg: WgConfig,
    pub host_key: PrivateKey,
    /// Presented to clients that offer certificate host-key algorithms.
    pub host_cert: Option<Certificate>,
    /// `Some`: certificate auth only.
    pub auth: Option<Arc<DaemonAuth>>,
    /// `Some`: instead of the fake server, forward the in-tunnel SSH byte
    /// stream to a real `minimald` on this Unix socket. The stand-in never
    /// terminates SSH on this path — it sees ciphertext only, like a relay —
    /// so the daemon authenticates the tab as it would any UDS client
    /// (`Auth::Local`, `auth_none`) and `MINIMAL_SESSION_ID` must name a real
    /// session on that daemon.
    pub session_socket: Option<std::path::PathBuf>,
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
    serve_peer_ws(
        tcp,
        PeerConfig {
            wg: cfg,
            host_key,
            host_cert: None,
            auth: None,
            session_socket: None,
        },
    )
    .await
}

/// One TCP connection on the stand-in's listener: a WebSocket upgrade is the
/// mesh ingress, anything else is the stub's HTTP API (when a stub is given).
pub async fn serve_connection(
    tcp: tokio::net::TcpStream,
    peer: PeerConfig,
    stub: Option<Arc<crate::stub::Stub>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sniff = [0u8; 2048];
    let n = tcp.peek(&mut sniff).await?;
    let head = String::from_utf8_lossy(&sniff[..n]).to_ascii_lowercase();
    if head.contains("upgrade: websocket") {
        return serve_peer_ws(tcp, peer).await;
    }
    match stub {
        Some(stub) => crate::stub::handle_http(tcp, &stub).await?,
        None => {}
    }
    Ok(())
}

pub async fn serve_peer_ws(
    tcp: tokio::net::TcpStream,
    peer: PeerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    let PeerConfig {
        wg: cfg,
        host_key,
        host_cert,
        auth,
        session_socket,
    } = peer;
    let ws = tokio_tungstenite::accept_async(tcp).await?;
    let (mut sink, mut source) = ws.split();
    let (to_network_tx, mut to_network_rx) = mpsc::channel::<Vec<u8>>(256);
    let (from_network_tx, from_network_rx) = mpsc::channel::<Vec<u8>>(256);
    // The pumps and the tunnel driver die with this future: if the caller's
    // task is aborted, the socket halves are dropped and the peer sees the
    // connection end, instead of orphaned tasks keeping it half-alive.
    let mut children = AbortOnDrop::default();
    children.spawn(async move {
        while let Some(Ok(msg)) = source.next().await {
            if let Message::Binary(bytes) = msg
                && from_network_tx.send(bytes.to_vec()).await.is_err()
            {
                break;
            }
        }
    });
    children.spawn(async move {
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
    children.spawn(driver);
    let mut accepted = stack.listen(22);
    if let Some(path) = session_socket {
        // Real daemon: splice the in-tunnel TCP stream onto its UDS.
        let mut unix = tokio::net::UnixStream::connect(&path).await?;
        let (a, b) = tokio::io::copy_bidirectional(&mut accepted, &mut unix).await?;
        log::debug!("session socket splice ended: {a} bytes to daemon, {b} bytes to tab");
        return Ok(());
    }
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        certificates: host_cert.into_iter().collect(),
        ..Default::default()
    });
    let handler = match auth {
        Some(auth) => FakeMinimald::with_auth(auth),
        None => FakeMinimald::default(),
    };
    let running = server::run_stream(config, accepted, handler).await?;
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

/// Tasks that are aborted when the owner is dropped.
#[derive(Default)]
struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    fn spawn(&mut self, fut: impl Future<Output = ()> + Send + 'static) {
        self.0.push(tokio::spawn(fut));
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}
