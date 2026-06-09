use ::paths::DaemonAbsPath;
use russh::keys::key::safe_rng;
use russh::keys::{PrivateKey, ssh_key::Error as KeyError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
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

/// A listening minimald server.
#[derive(Debug)]
pub struct Server {
    state: ServerStateHandle,
    listener: UnixListener,
}

impl Server {
    /// Launches minimald, listening for connections on the given UDS socket.
    pub async fn run_on_uds(config: Config, listener: UnixListener) -> Result<(), std::io::Error> {
        let state = ServerStateHandle::new(config).await?;
        Server { state, listener }.run().await
    }

    /// Launches minimald listening for connections on an AF_VSOCK port.
    ///
    /// Used by the in-VM (pid-1) guest: the host registers the port via
    /// `krun_add_vsock_port2` and bridges client SSH connections to it.
    /// The vsock peer is host-mediated (`net=none`) and as trusted as the
    /// UDS peer, so accepted connections are treated as local
    /// ([`Auth::Local`]), matching `run_on_uds`.
    ///
    /// NB: over libkrun's `krun_add_vsock_port2` bridge this *accepts*
    /// connections fine, but a full SSH session dies with "Protocol error: early
    /// eof" shortly after accept — the bridged vsock stream does not sustain a
    /// bidirectional session (a single short request/response works). The
    /// deployed guest therefore relays the bridge port through socat to a UDS and
    /// serves via `run_on_uds`; this direct path is kept as the building block /
    /// for a future bridge fix.
    #[cfg(target_os = "linux")]
    pub async fn run_on_vsock(config: Config, port: u32) -> Result<(), std::io::Error> {
        use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

        let state = ServerStateHandle::new(config).await?;
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        tracing::info!(port, "minimald listening on vsock");

        let russh_config = build_russh_config(&state).await;
        let mut session_set = JoinSet::new();
        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::info!(?peer, "accepted vsock connection");
            let (_conn_hnd, session_fut) =
                Connection::from_stream(stream, russh_config.clone(), state.clone(), true).await;
            // Log session errors instead of silently dropping the spawned
            // future, so a failed handshake on the vsock transport is visible.
            session_set.spawn(async move {
                if let Err(e) = session_fut.await {
                    tracing::warn!(error = %e, "vsock session ended with error");
                }
            });
        }
    }

    async fn run(self) -> Result<(), std::io::Error> {
        let russh_config = build_russh_config(&self.state).await;
        let mut session_set = JoinSet::new();
        loop {
            let (socket, _) = self.listener.accept().await?;
            let (_conn_hnd, session_fut) =
                Connection::from_socket(socket, russh_config.clone(), self.state.clone(), true)
                    .await;
            session_set.spawn(session_fut);
        }
    }
}

/// Builds the shared russh server config from the server state.
async fn build_russh_config(state: &ServerStateHandle) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        keys: vec![state.host_key().await.unwrap()],
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        nodelay: true,
        ..Default::default()
    })
}
