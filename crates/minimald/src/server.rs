use ::paths::DaemonAbsPath;
use russh::keys::key::safe_rng;
use russh::keys::{PrivateKey, ssh_key::Error as KeyError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::connection::Connection;
use crate::sessions;

/// The ed25519 host private key for the SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKey {
    /// Randomly-generated when needed.
    Ephemeral,
    /// An OpenSSH-formatted PEM private key.
    Raw(String),
    /// A path where an OpenSSH-formatted PEM private key should be stored,
    /// optionally created on first use.
    OnDisk {
        path: PathBuf,
        create_if_missing: bool,
    },
}

/// Global Configuration for the minimald server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub host_key: HostKey,
    pub minimal_state_dir: DaemonAbsPath,
    pub minimal_cache_dir: DaemonAbsPath,
}

impl Config {
    /// Returns the SSH host key to use.
    ///
    /// For [`HostKey`] variant `OnDisk{ create_on_missing: true, ..}`,
    /// a new key will be generated and written if the file does not exist.
    pub fn host_key(&self) -> Result<PrivateKey, KeyError> {
        match &self.host_key {
            HostKey::Ephemeral => {
                let key = PrivateKey::random(&mut safe_rng(), russh::keys::Algorithm::Ed25519)?;
                Ok(key)
            }
            HostKey::OnDisk {
                path,
                create_if_missing,
            } => match PrivateKey::read_openssh_file(path) {
                Ok(k) => Ok(k),
                Err(KeyError::Io(std::io::ErrorKind::NotFound)) => {
                    if *create_if_missing {
                        let key =
                            PrivateKey::random(&mut safe_rng(), russh::keys::Algorithm::Ed25519)?;
                        key.write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)?;
                        Ok(key)
                    } else {
                        Err(KeyError::Io(std::io::ErrorKind::NotFound))
                    }
                }
                Err(e) => Err(e),
            },
            HostKey::Raw(r) => Ok(PrivateKey::from_openssh(r.as_bytes())?),
        }
    }
}

/// A container for the state of the server.
#[derive(Debug)]
pub struct ServerState {
    config: Config,
    sessions: sessions::ManagerHandle,

    /// Memoized SSH host key, after first successful load.
    host_key: Option<PrivateKey>,
}

impl ServerState {
    pub async fn new(config: Config) -> Result<Self, std::io::Error> {
        let minimal_state_dir = config.minimal_state_dir.clone();
        let minimal_cache_dir = config.minimal_cache_dir.clone();
        Ok(Self {
            config,
            sessions: sessions::Manager::init(minimal_state_dir, minimal_cache_dir).await?,
            host_key: None,
        })
    }
}

/// A thread-safe handle to the server state.
#[derive(Clone, Debug)]
pub struct ServerStateHandle(Arc<Mutex<ServerState>>);

impl ServerStateHandle {
    /// Constructs a fresh handle wrapping a newly-initialized [`ServerState`].
    pub(crate) async fn new(config: Config) -> Result<Self, std::io::Error> {
        Ok(Self(Arc::new(Mutex::new(ServerState::new(config).await?))))
    }

    pub async fn host_key(&self) -> Result<PrivateKey, KeyError> {
        let mut s = self.0.lock().await;
        if let Some(hk) = &s.host_key {
            return Ok(hk.clone());
        }

        match s.config.host_key() {
            Ok(hk) => {
                s.host_key = Some(hk.clone());
                Ok(hk)
            }
            Err(e) => Err(e),
        }
    }

    /// Returns a handle to the sessions manager.
    pub async fn sessions_manager(&self) -> sessions::ManagerHandle {
        self.0.lock().await.sessions.clone()
    }
}

/// A transport that accepts byte-stream connections for the SSH server.
///
/// The russh stack is transport-agnostic, so any listener yielding an
/// async byte stream works: a [`UnixListener`] for the native UDS daemon
/// or a [`tokio_vsock::VsockListener`] for the in-VM (pid-1) guest.
pub trait Listener: Send {
    /// The accepted connection's byte stream.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Peer address, used only for logging.
    type Addr: std::fmt::Debug;

    /// Short transport name for log fields, e.g. `"uds"` / `"vsock"`.
    const TRANSPORT: &'static str;
    /// Whether peers on this transport are pre-authenticated as local
    /// ([`Auth::Local`]). Both the UDS and the host-mediated vsock
    /// transports are equally trusted, so both set this to `true`.
    const IS_LOCAL: bool;

    fn accept(&self) -> impl Future<Output = std::io::Result<(Self::Stream, Self::Addr)>> + Send;
}

impl Listener for UnixListener {
    type Stream = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    const TRANSPORT: &'static str = "uds";
    const IS_LOCAL: bool = true;

    async fn accept(&self) -> std::io::Result<(Self::Stream, Self::Addr)> {
        UnixListener::accept(self).await
    }
}

/// The AF_VSOCK transport, used by the in-VM (pid-1) guest: the host
/// registers the port via `krun_add_vsock_port2` and bridges client SSH
/// connections to it. The vsock peer is host-mediated (`net=none`) and as
/// trusted as the UDS peer, so accepted connections are treated as local
/// ([`Auth::Local`]), matching the UDS transport. Sessions are driven over
/// the bridged vsock stream directly, with no socat UDS relay in between.
///
/// Requires libkrun >= 1.19.0: on 1.18.1 the bridged vsock intermittently
/// stalled a full session (a multi-descriptor TX-chain bug in libkrun's vsock
/// device, fixed upstream by `0ecf4d5f7`); a socat relay was the prior
/// workaround.
#[cfg(target_os = "linux")]
impl Listener for tokio_vsock::VsockListener {
    type Stream = tokio_vsock::VsockStream;
    type Addr = tokio_vsock::VsockAddr;

    const TRANSPORT: &'static str = "vsock";
    const IS_LOCAL: bool = true;

    async fn accept(&self) -> std::io::Result<(Self::Stream, Self::Addr)> {
        tokio_vsock::VsockListener::accept(self).await
    }
}

/// A listening minimald server.
#[derive(Debug)]
pub struct Server;

impl Server {
    /// Launches minimald, accepting connections on the given listener and
    /// driving an SSH session over each until the listener errors.
    pub async fn run<L: Listener>(config: Config, listener: L) -> Result<(), std::io::Error> {
        let state = ServerStateHandle::new(config).await?;
        let russh_config = build_russh_config(&state)
            .await
            .map_err(std::io::Error::other)?;
        let mut session_set = JoinSet::new();

        loop {
            // Drain any completed sessions to prevent unbounded growth.
            while let Some(result) = session_set.try_join_next() {
                if let Err(e) = result {
                    tracing::error!(error = %e, "session task panicked");
                }
            }

            let (stream, peer) = listener.accept().await?;
            tracing::info!(?peer, transport = L::TRANSPORT, "accepted connection");
            let (_conn_hnd, session_fut) =
                Connection::from_stream(stream, russh_config.clone(), state.clone(), L::IS_LOCAL)
                    .await;
            // Log session errors instead of silently dropping the spawned
            // future, so a failed handshake is visible on any transport.
            session_set.spawn(async move {
                if let Err(e) = session_fut.await {
                    tracing::warn!(error = %e, transport = L::TRANSPORT, "session ended with error");
                }
            });
        }
    }
}

/// Builds the shared russh server config from the server state.
async fn build_russh_config(
    state: &ServerStateHandle,
) -> Result<Arc<russh::server::Config>, KeyError> {
    Ok(Arc::new(russh::server::Config {
        keys: vec![state.host_key().await?],
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        nodelay: true,
        ..Default::default()
    }))
}
