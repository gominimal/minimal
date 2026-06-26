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

/// Default install path for the gvproxy ("gvisor-tap-vsock") switch binary,
/// used when [`Config::gvproxy_bin`] is unset. The `GVPROXY_BIN` env var is
/// scoped to the `#[ignore]` netns proof and is never consulted by the daemon.
const DEFAULT_GVPROXY_BIN: &str = "/usr/lib/minimal/bin/gvproxy";

/// Global Configuration for the minimald server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub host_key: HostKey,
    pub minimal_state_dir: DaemonAbsPath,
    pub minimal_cache_dir: DaemonAbsPath,
    /// Path to the gvproxy binary backing the per-host `OwnIp` switch. Defaults
    /// to [`DEFAULT_GVPROXY_BIN`] when unset.
    #[serde(default)]
    pub gvproxy_bin: Option<PathBuf>,
    /// Whether this `minimald` runs inside a `minvmd` libkrun VM (DM1/3/4). When
    /// `true`, `OwnIp` PTasks attach to the **host** gvproxy (owned by `minvmd`)
    /// over a vsock shuttle instead of spawning gvproxy in-guest.
    /// `false` (DM2, native Linux) keeps the local-spawn + tap relay path.
    #[serde(default)]
    pub in_microvm: bool,
}

impl Config {
    /// Resolves the configured gvproxy binary path, falling back to the fixed
    /// install path when unset.
    fn gvproxy_bin_path(&self) -> PathBuf {
        self.gvproxy_bin
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_GVPROXY_BIN))
    }

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

    /// The daemon's TLS certificate authority, used by the HTTPS proxy and the
    /// `IssueClientCert` RPC. Generated once on daemon startup and held for the
    /// daemon's lifetime; clients must call `minimal login` again after a
    /// restart.
    #[cfg(feature = "networking-proxy")]
    pub cert_authority: Arc<crate::net::proxy::CertAuthority>,

    /// The running WireGuard mesh peer, when one is configured (Unit 4). Only
    /// present under the `networking-wg` feature; the `GetMeshStatus` RPC reads
    /// it through [`ServerStateHandle::mesh_status`].
    #[cfg(feature = "networking-wg")]
    mesh: Option<Arc<crate::net::wg::MeshHandle>>,
}

impl ServerState {
    pub async fn new(config: Config) -> Result<Self, std::io::Error> {
        let minimal_state_dir = config.minimal_state_dir.clone();
        let minimal_cache_dir = config.minimal_cache_dir.clone();
        // Construct the per-host switch once, here at daemon scope, so a single
        // gvproxy runs for the host and a single allocator never reuses an
        // address for the daemon's lifetime (R1.4/R1.6). Its config/socket/pid
        // live under a dedicated subdir of the daemon state dir. The shared
        // `Arc` is the single source of truth, injected into every per-launch
        // `SandboxLauncher` through the sessions manager.
        // DM1/3/4 (in a libkrun VM): attach `OwnIp` PTasks to the host gvproxy
        // (owned by `minvmd`) over a vsock shuttle. DM2 (native Linux): spawn +
        // own gvproxy locally.
        let transport = if config.in_microvm {
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            }
        } else {
            crate::net::SwitchTransport::LocalSpawn
        };
        let net_switch = Arc::new(Mutex::new(
            crate::net::GvproxySwitch::new(
                config.gvproxy_bin_path(),
                minimal_state_dir.as_utf8_path().join("gvproxy"),
            )
            .with_transport(transport),
        ));

        // Generate the TLS CA once at daemon startup so the HTTPS proxy and the
        // IssueClientCert RPC share the same trust anchor for the lifetime of
        // this daemon process.
        #[cfg(feature = "networking-proxy")]
        let cert_authority =
            Arc::new(crate::net::proxy::CertAuthority::generate().map_err(std::io::Error::other)?);

        Ok(Self {
            sessions: sessions::Manager::init(minimal_state_dir, minimal_cache_dir, net_switch)
                .await?,
            config,
            host_key: None,
            #[cfg(feature = "networking-proxy")]
            cert_authority,
            #[cfg(feature = "networking-wg")]
            mesh: None,
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

    /// Returns the daemon's TLS certificate authority (only with
    /// `networking-proxy` feature). Used by the `IssueClientCert` RPC handler.
    #[cfg(feature = "networking-proxy")]
    pub async fn cert_authority(&self) -> Arc<crate::net::proxy::CertAuthority> {
        Arc::clone(&self.0.lock().await.cert_authority)
    }

    /// Builds the current WireGuard mesh status for the `GetMeshStatus` RPC
    /// (R4.6). On a build without the `networking-wg` feature, or with no mesh
    /// configured, this reports `configured = false`.
    pub async fn mesh_status(&self) -> minimald_rpc::MeshStatus {
        #[cfg(feature = "networking-wg")]
        {
            let s = self.0.lock().await;
            // A populated mesh slot is not proof the mesh is live: the pump can
            // exit on a fatal socket error without clearing the slot, leaving a
            // frozen, stale snapshot. Treat a dead pump as unconfigured so
            // `GetMeshStatus` never advertises stale peer state.
            match s.mesh.as_deref() {
                Some(mesh) if mesh.is_alive() => crate::net::wg::status_response(Some(mesh)),
                _ => minimald_rpc::MeshStatus::unconfigured(),
            }
        }
        #[cfg(not(feature = "networking-wg"))]
        {
            minimald_rpc::MeshStatus::unconfigured()
        }
    }

    /// Installs a running mesh handle. Used by the daemon's mesh-join path and,
    /// in tests, to stand up a configured mesh for the `GetMeshStatus` RPC.
    #[cfg(feature = "networking-wg")]
    pub async fn set_mesh(&self, mesh: Arc<crate::net::wg::MeshHandle>) {
        self.0.lock().await.mesh = Some(mesh);
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
        // `config` is moved into the state below; capture the deployment-model
        // flag the proxy startup needs first.
        #[cfg(target_os = "linux")]
        let in_microvm = config.in_microvm;
        let state = ServerStateHandle::new(config).await?;

        // Start minimald's two host-side proxies (B5 egress :7654, B8 mTLS
        // :7655) for the server's lifetime and, in a microVM (DM1), publish them
        // on the macOS host loopback. minimald is Linux-only, and the PTask
        // hostname registry they route against only exists on Linux.
        #[cfg(target_os = "linux")]
        start_host_proxies(&state, in_microvm).await;

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
            let (_conn_hnd, session_fut) = match Connection::from_stream(
                stream,
                russh_config.clone(),
                state.clone(),
                L::IS_LOCAL,
            )
            .await
            {
                Ok(conn) => conn,
                Err(e) => {
                    // A handshake failure must not take the daemon down — in
                    // the guest minimald is pid-1. Drop this connection and
                    // keep accepting.
                    tracing::warn!(error = %e, transport = L::TRANSPORT, "SSH handshake failed; dropping connection");
                    continue;
                }
            };
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

/// Binds and serves minimald's two host-side proxies for the daemon's lifetime
/// and, in a microVM (DM1), publishes them on the macOS host loopback.
///
/// Both proxies route by `Host:` header through the sessions manager's shared
/// PTask hostname registry. In a microVM they bind the daemon's switch IP
/// ([`DEFAULT_SUBNET`](crate::net::DEFAULT_SUBNET)`.daemon_ip()`) so the host
/// gvproxy forward can reach them; on native Linux (DM2) they bind host loopback
/// directly. A bind failure warns and is skipped — the daemon keeps serving. The
/// serve loops run on detached tasks; this returns once the listeners are bound
/// and (DM1) exposed.
#[cfg(target_os = "linux")]
async fn start_host_proxies(state: &ServerStateHandle, in_microvm: bool) {
    use crate::net::proxy::{self, Router};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let registry = state.sessions_manager().await.hostnames();
    // DM1 (in-VM): bind 0.0.0.0 so the listener comes up regardless of whether
    // eth0 has finished coming up, then publish the port on the host loopback via
    // the gvproxy forwarder. DM2: bind host loopback directly, no host-expose.
    let bind_base: IpAddr = if in_microvm {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::LOCALHOST.into()
    };

    // B5 egress/DNS proxy (:7654), always.
    let egress_addr = SocketAddr::new(bind_base, proxy::EGRESS_PROXY_PORT);
    if proxy::bind_listener(egress_addr)
        .await
        .map(|listener| {
            let router = Router::new(registry.clone());
            tokio::spawn(async move {
                if let Err(error) = proxy::serve(listener, router).await {
                    tracing::error!(%error, "egress proxy accept loop exited");
                }
            })
        })
        .is_some()
        && in_microvm
    {
        // Only publish a port whose listener actually bound.
        expose_proxy_on_host(
            crate::net::DEFAULT_SUBNET.daemon_ip(),
            proxy::EGRESS_PROXY_PORT,
        )
        .await;
    }

    // B8 mTLS reverse proxy (:7655), under the networking-proxy feature.
    #[cfg(feature = "networking-proxy")]
    {
        let https_addr = SocketAddr::new(bind_base, proxy::HTTPS_PROXY_PORT);
        match state.cert_authority().await.build_server_config() {
            Ok(tls_config) => {
                if proxy::bind_listener(https_addr)
                    .await
                    .map(|listener| {
                        let router = Router::new(registry.clone());
                        tokio::spawn(async move {
                            if let Err(error) =
                                proxy::serve_https(listener, router, tls_config).await
                            {
                                tracing::error!(%error, "mTLS proxy accept loop exited");
                            }
                        })
                    })
                    .is_some()
                    && in_microvm
                {
                    expose_proxy_on_host(
                        crate::net::DEFAULT_SUBNET.daemon_ip(),
                        proxy::HTTPS_PROXY_PORT,
                    )
                    .await;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not build TLS config for the mTLS reverse proxy");
            }
        }
    }
}

/// Publishes a guest-side proxy bound on `daemon_ip:port` onto the macOS host's
/// loopback (`127.0.0.1:port`) via the host gvproxy forwarder, reached over the
/// vsock shuttle (DM1). Best-effort: warns and returns on failure, since the
/// host gvproxy may be absent.
#[cfg(target_os = "linux")]
async fn expose_proxy_on_host(daemon_ip: std::net::Ipv4Addr, port: u16) {
    use crate::net::policy::{ControlChannel, ExposeRequest, post_json};

    let control = ControlChannel::Vsock {
        cid: crate::net::VSOCK_HOST_CID,
        port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
    };
    let request = ExposeRequest {
        local: format!("127.0.0.1:{port}"),
        remote: format!("{daemon_ip}:{port}"),
        protocol: "tcp".to_string(),
    };
    if let Err(error) = post_json(&control, "/services/forwarder/expose", &request).await {
        tracing::warn!(
            %port,
            %error,
            "could not publish host-side proxy on the host loopback via gvproxy forwarder"
        );
    }
}
