use ::paths::DaemonAbsPath;
use russh::keys::key::safe_rng;
use russh::keys::{PrivateKey, ssh_key::Error as KeyError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
// The host-side proxies and their startup retry live behind the Linux gate
// with the `net` module they route against.
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

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
    /// Path to the gvproxy binary backing the per-host `OwnIp` switch. Defaults
    /// to the installed location (`switch::installed_gvproxy_bin`) when unset.
    #[serde(default)]
    pub gvproxy_bin: Option<PathBuf>,
    /// Whether this `minimald` runs inside a `minvmd` libkrun VM (DM1/3/4). When
    /// `true`, `OwnIp` PTasks attach to the **host** gvproxy (owned by `minvmd`)
    /// over a vsock shuttle instead of spawning gvproxy in-guest.
    /// `false` (DM2, native Linux) keeps the local-spawn + tap relay path.
    #[serde(default)]
    pub in_microvm: bool,
    /// Whether the guest boot path actually mounted the writable data volume
    /// at `minimal_state_dir`. Gates the shutdown quiesce (R2.1/R2.2): only a
    /// filesystem this daemon mounted may be synced and unmounted — the vsock
    /// transport alone doesn't imply one (a native `--vsock` daemon, or a
    /// microVM booted without a data volume, must never unmount its state dir).
    #[serde(default)]
    pub state_volume_mounted: bool,
}

impl Config {
    /// Resolves the configured gvproxy binary path, falling back to the
    /// installed location when unset: the user-local `bin/gvproxy-min` the
    /// curl|sh installer stamps, else the system-wide path. The `GVPROXY_BIN`
    /// env var is scoped to the `#[ignore]` netns proof and is never consulted
    /// by the daemon.
    fn gvproxy_bin_path(&self) -> PathBuf {
        self.gvproxy_bin
            .clone()
            .unwrap_or_else(::switch::installed_gvproxy_bin)
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

/// A one-shot closure that closes the daemon's file-log appender — reloading
/// its tracing layer off and dropping the worker guard, flushing buffered
/// records and releasing the file descriptor. Authored by the binary's
/// `DaemonLogger` (which owns the reload handle and the guard); owned here
/// and run once at shutdown via [`ServerStateHandle::release_log`], so no
/// process-global mutable state is needed. In the microVM this must precede
/// the volume quiesce — an open fd under the mountpoint defeats the clean
/// unmount and leaves a dirty ext4 journal.
pub struct DaemonLogRelease(Box<dyn FnOnce() + Send>);

impl DaemonLogRelease {
    /// Wraps the release action. Called by the binary's `DaemonLogger`.
    pub fn new(release: impl FnOnce() + Send + 'static) -> Self {
        Self(Box::new(release))
    }

    fn run(self) {
        (self.0)()
    }
}

impl std::fmt::Debug for DaemonLogRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DaemonLogRelease(..)")
    }
}

/// A container for the state of the server.
#[derive(Debug)]
pub struct ServerState {
    config: Config,
    sessions: sessions::ManagerHandle,
    daemon_id: String,

    /// Daemon-scoped mctx state (dirs, VCS, local cache, stdlib), built once
    /// at startup and shared with the sessions manager. Held here too so
    /// daemon-level work that belongs to no session — [`crate::maintenance`]'s
    /// cache clean — can reach the cache without a project mfile.
    daemon_ctx: Arc<mctx::DaemonContext>,

    /// The housekeeping actor, installed by [`Server::run`] once the state
    /// exists (the actor holds a handle to it, so it can't be built in
    /// [`ServerState::new`]). `None` before that, and for a state built
    /// directly in a unit test. Held here so that anything wanting a cache
    /// clean asks the one actor rather than starting its own.
    maintenance: Option<crate::maintenance::MaintenanceHandle>,

    /// Fired by the `Shutdown` RPC handler once the session manager has been
    /// torn down, telling [`Server::run`]'s accept loop to stop accepting,
    /// drain in-flight connections, and return so the process can exit.
    shutdown: CancellationToken,

    /// Closes the daemon's file-log appender at shutdown (before the volume
    /// quiesce in the microVM). `None` for a foreground run with no file log.
    log_release: Option<DaemonLogRelease>,

    /// Memoized SSH host key, after first successful load.
    host_key: Option<PrivateKey>,

    /// Why the host-side egress proxy is not reachable, if it is not. Set by
    /// [`start_host_proxies`] and read by the `ListSessions` RPC.
    ///
    /// Both failure paths land here, because they produce the same symptom
    /// from different places: on DM2 the bind itself fails, and on DM1 the
    /// bind succeeds inside the guest but publishing it on the host loopback
    /// does not. A fix that surfaced only the first would stay silent on
    /// macOS, which is the platform the failure was reported from.
    proxy_unavailable: Option<String>,

    /// Why the mTLS reverse proxy is not serving, if it is not. Kept apart
    /// from [`Self::proxy_unavailable`] so a client is not told its hostnames
    /// are broken when only TLS termination is. Never set without the
    /// `networking-proxy` feature, where there is no such proxy to lose.
    mtls_unavailable: Option<String>,

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
    pub async fn new(
        config: Config,
        log_release: Option<DaemonLogRelease>,
    ) -> Result<Self, std::io::Error> {
        let minimal_state_dir = config.minimal_state_dir.clone();
        let minimal_cache_dir = config.minimal_cache_dir.clone();
        let daemon_id = common::random_alphanumeric(5);
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
            crate::net::SwitchClient::new(
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

        // Build a daemon-scoped mctx config from what the daemon
        // knows today (dirs). Additional flags (offline, stdlib
        // override, num-parallel-builds) will thread through from
        // the CLI as follow-up work; today the defaults hold.
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(minimal_cache_dir.as_utf8_path())
            .with_state_dir(minimal_state_dir.as_utf8_path())
            .with_daemon_id(daemon_id.clone())
            .build()
            .map_err(|e| std::io::Error::other(format!("mctx config: {e}")))?;

        // Build the daemon-scoped mctx state once at startup: every session
        // stacks a per-session `Context` on it via `Context::from_daemon`.
        let daemon_ctx = Arc::new(
            mctx::DaemonContext::init(mctx_config)
                .map_err(|e| std::io::Error::other(format!("mctx daemon init: {e}")))?,
        );

        Ok(Self {
            sessions: sessions::Manager::init(
                minimal_state_dir,
                minimal_cache_dir,
                Arc::clone(&daemon_ctx),
                net_switch,
            )
            .await?,
            config,
            daemon_id,
            daemon_ctx,
            maintenance: None,
            shutdown: CancellationToken::new(),
            log_release,
            host_key: None,
            proxy_unavailable: None,
            mtls_unavailable: None,
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
    pub(crate) async fn new(
        config: Config,
        log_release: Option<DaemonLogRelease>,
    ) -> Result<Self, std::io::Error> {
        Ok(Self(Arc::new(Mutex::new(
            ServerState::new(config, log_release).await?,
        ))))
    }

    /// Runs and clears the daemon's file-log release (flushing records and
    /// closing the appender's fd), so a subsequent volume quiesce is not
    /// blocked by the open fd. A no-op after the first call, and for a
    /// foreground run with no file log. Called by the Shutdown RPC.
    pub async fn release_log(&self) {
        let release = self.0.lock().await.log_release.take();
        if let Some(release) = release {
            release.run();
        }
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

    /// Records why hostname routing is unavailable, so a client can be told.
    pub(crate) async fn set_proxy_unavailable(&self, reason: String) {
        self.0.lock().await.proxy_unavailable = Some(reason);
    }

    /// Why hostname routing is unavailable, or `None` if the proxy is up.
    pub(crate) async fn proxy_unavailable(&self) -> Option<String> {
        self.0.lock().await.proxy_unavailable.clone()
    }

    /// Clears the hostname-routing unavailability note: the proxy's startup
    /// retry bound and published it, so `ListSessions` stops reporting the
    /// reason and `min ls` stops printing the warning — without a daemon
    /// restart (NET-022).
    pub(crate) async fn clear_proxy_unavailable(&self) {
        self.0.lock().await.proxy_unavailable = None;
    }

    /// Records why the mTLS reverse proxy is not serving.
    #[cfg_attr(not(feature = "networking-proxy"), expect(dead_code))]
    pub(crate) async fn set_mtls_unavailable(&self, reason: String) {
        self.0.lock().await.mtls_unavailable = Some(reason);
    }

    /// Clears the mTLS unavailability note: the proxy's startup retry bound
    /// and published it.
    #[cfg_attr(not(feature = "networking-proxy"), expect(dead_code))]
    pub(crate) async fn clear_mtls_unavailable(&self) {
        self.0.lock().await.mtls_unavailable = None;
    }

    /// Why the mTLS reverse proxy is not serving, or `None` if it is.
    pub(crate) async fn mtls_unavailable(&self) -> Option<String> {
        self.0.lock().await.mtls_unavailable.clone()
    }

    /// Returns the daemon-scoped mctx state.
    pub(crate) async fn daemon_context(&self) -> Arc<mctx::DaemonContext> {
        Arc::clone(&self.0.lock().await.daemon_ctx)
    }

    /// Installs the housekeeping actor's handle. Called once by
    /// [`Server::run`] just after spawning it.
    pub(crate) async fn set_maintenance(&self, handle: crate::maintenance::MaintenanceHandle) {
        self.0.lock().await.maintenance = Some(handle);
    }

    /// The housekeeping actor, for a caller that wants a cache clean run.
    /// `None` on a state whose server never started it (unit tests).
    ///
    /// Going through the actor is the point: it is the one place a clean
    /// starts, so a requested one queues behind the periodic one instead of
    /// racing it.
    #[allow(dead_code)] // No manual trigger is wired to this yet.
    pub(crate) async fn maintenance(&self) -> Option<crate::maintenance::MaintenanceHandle> {
        self.0.lock().await.maintenance.clone()
    }

    /// Returns a clone of the server shutdown token. [`Server::run`]'s accept
    /// loop awaits [`CancellationToken::cancelled`] on it to leave the loop.
    pub(crate) async fn shutdown_token(&self) -> CancellationToken {
        self.0.lock().await.shutdown.clone()
    }

    /// Signals [`Server::run`] to stop accepting connections and drain. Called
    /// by the `Shutdown` RPC handler after the session manager has shut down.
    /// Idempotent: repeated calls (e.g. two `Shutdown` RPCs) are harmless.
    pub(crate) async fn trigger_shutdown(&self) {
        self.0.lock().await.shutdown.cancel();
    }

    /// Whether the boot path mounted the writable data volume at the state
    /// dir. The `Shutdown` RPC handler quiesces (syncs + unmounts) the state
    /// dir only when this daemon mounted it — never a host directory or a
    /// tmpfs it merely uses.
    pub(crate) async fn state_volume_mounted(&self) -> bool {
        self.0.lock().await.config.state_volume_mounted
    }

    /// The configured state dir (the quiesce target when in a microVM, and the
    /// root every diagnostic collector reads from).
    pub(crate) async fn minimal_state_dir(&self) -> DaemonAbsPath {
        self.0.lock().await.config.minimal_state_dir.clone()
    }

    /// Whether this daemon is the in-VM instance rather than a native one.
    /// Recorded in the diagnostic bundle's `meta.json` so a reader knows which
    /// of the two answered, and gates the guest-only gvproxy probe.
    pub(crate) async fn in_microvm(&self) -> bool {
        self.0.lock().await.config.in_microvm
    }

    /// Returns the daemon ID.
    pub async fn daemon_id(&self) -> String {
        self.0.lock().await.daemon_id.clone()
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

/// How long [`Server::run`] waits for in-flight connections to drain after a
/// [`Shutdown`](minimald_rpc::Shutdown) RPC before aborting the stragglers. The
/// shutdown-initiating client's own connection stays open until it disconnects,
/// so an unbounded wait could hang the process; this bounds it.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Monotonic id carried by each accepted connection's span, so a
/// connection's accept, channel bindings, and close correlate across the log.
static CONN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A listening minimald server.
#[derive(Debug)]
pub struct Server;

impl Server {
    /// Launches minimald, accepting connections on the given listener and
    /// driving an SSH session over each until the listener errors.
    pub async fn run<L: Listener>(
        config: Config,
        listener: L,
        log_release: Option<DaemonLogRelease>,
    ) -> Result<(), std::io::Error> {
        // `config` is moved into the state below; capture the deployment-model
        // flag the proxy startup needs first.
        #[cfg(target_os = "linux")]
        let in_microvm = config.in_microvm;
        let state = ServerStateHandle::new(config, log_release).await?;

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
        // Fired by the `Shutdown` RPC handler once the session manager is torn
        // down; ends the accept loop below so the daemon can exit gracefully.
        let shutdown = state.shutdown_token().await;

        // Housekeeping (cache clean) for the daemon's lifetime: periodic, plus
        // whatever asks the actor for one. It stops on the same token that ends
        // this loop. Installed on the state so every would-be trigger reaches
        // the same actor rather than starting a competing clean.
        let maintenance = crate::maintenance::spawn(state.clone(), shutdown.clone());
        state.set_maintenance(maintenance.clone()).await;

        loop {
            // Drain any completed sessions to prevent unbounded growth.
            while let Some(result) = session_set.try_join_next() {
                if let Err(e) = result {
                    tracing::error!(error = %e, "session task panicked");
                }
            }

            // A pending shutdown wins over a ready accept (`biased`), so we
            // never take on a new connection once shutdown has been requested.
            let (stream, peer) = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted?,
            };
            // One span per accepted connection: every record the connection
            // and its channels emit carries `conn`, so accept, channel
            // bindings, and close correlate across the log with a grep
            // instead of manual id fields on each line.
            let conn = CONN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let span = tracing::info_span!("conn", conn, transport = L::TRANSPORT);
            span.in_scope(|| tracing::info!(?peer, "accepted connection"));
            let from_stream =
                Connection::from_stream(stream, russh_config.clone(), state.clone(), L::IS_LOCAL);
            let (conn_hnd, session_fut) = match from_stream.instrument(span.clone()).await {
                Ok(conn) => conn,
                Err(e) => {
                    // A handshake failure must not take the daemon down — in
                    // the guest minimald is pid-1. Drop this connection and
                    // keep accepting.
                    span.in_scope(
                        || tracing::warn!(error = %e, "SSH handshake failed; dropping connection"),
                    );
                    continue;
                }
            };
            // Log session errors instead of silently dropping the spawned
            // future, so a failed handshake is visible on any transport.
            let reap_state = state.clone();
            session_set.spawn(
                async move {
                    match session_fut.await {
                        Ok(()) => tracing::info!("connection closed"),
                        Err(e) => {
                            // Abrupt hangups are how the CLI's oneshot RPC
                            // connections and Ctrl-C'd attaches normally end;
                            // framing them as errors makes routine traffic
                            // read like a transport incident during field
                            // analysis. Match on the rendered message: russh
                            // wraps the underlying io error, and this is log
                            // framing only.
                            let msg = e.to_string();
                            if msg.contains("early eof")
                                || msg.contains("Broken pipe")
                                || msg.contains("Disconnected")
                            {
                                tracing::info!(reason = %msg, "connection closed by peer");
                            } else {
                                tracing::warn!(error = %msg, "session ended with error");
                            }
                        }
                    }
                    // The connection is gone. Reap any session it created that
                    // never reached `Active` — a client that dropped
                    // mid-activation (Ctrl-C at the gating prompt, a crash, a
                    // network blip) would otherwise strand a `Pending` /
                    // `Materializing` session that holds its name hostage.
                    reap_unfinalized_sessions(&reap_state, conn_hnd.take_created_sessions().await)
                        .await;
                }
                .instrument(span),
            );
        }

        // Housekeeping has no client waiting on it and nothing to drain, so it
        // goes first — the token has already stopped it between passes; this
        // covers the case where it was mid-pass.
        maintenance.abort();

        // Shutdown requested: stop accepting (done — loop exited) and drain
        // in-flight connections. The initiating client's own connection stays
        // open until it disconnects, so bound the wait: after `SHUTDOWN_GRACE`,
        // abort whatever is left so `run` always returns and the process exits.
        tracing::info!(
            live = session_set.len(),
            "draining connections for shutdown"
        );
        let grace = tokio::time::sleep(SHUTDOWN_GRACE);
        tokio::pin!(grace);
        loop {
            tokio::select! {
                res = session_set.join_next() => match res {
                    None => break,
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "session task panicked while draining")
                    }
                    Some(Ok(())) => {}
                },
                () = &mut grace => {
                    tracing::warn!(
                        live = session_set.len(),
                        "shutdown grace elapsed; aborting remaining connections"
                    );
                    session_set.abort_all();
                    while session_set.join_next().await.is_some() {}
                    break;
                }
            }
        }
        Ok(())
    }
}

/// How often an otherwise-quiet connection is probed with an SSH keepalive.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Unanswered keepalives tolerated before the connection is torn down.
const KEEPALIVE_MAX: usize = 3;

/// Builds the shared russh server config from the server state.
async fn build_russh_config(
    state: &ServerStateHandle,
) -> Result<Arc<russh::server::Config>, KeyError> {
    Ok(Arc::new(russh::server::Config {
        keys: vec![state.host_key().await?],
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        nodelay: true,
        // Keepalives own deadness detection; the default 600s inactivity
        // reaper would kill healthy idle attaches, so it is explicitly off.
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Default::default()
    }))
}

/// Reap sessions a now-closed connection created but never finalized.
///
/// `ids` are the sessions [`CreateSession`](crate::rpc) allocated over
/// the connection. Only those still `Pending` (never got a
/// `SubmitVerdict`) or `Materializing` (never got a `FinalizeSession`)
/// are deleted — a client that dropped mid-activation (Ctrl-C at the
/// gating prompt, a crash, a network blip) would otherwise strand a
/// half-built session that holds its name hostage until the next daemon
/// restart. A finalized (`Active`) session is long-lived and must
/// survive the connection that created it, so it is left untouched.
/// Best-effort and never fatal: minimald is pid-1 in the guest.
async fn reap_unfinalized_sessions(state: &ServerStateHandle, ids: Vec<::sessions::SessionId>) {
    if ids.is_empty() {
        return;
    }
    let mngr = state.sessions_manager().await;
    for id in ids {
        // Re-read the status at teardown: a clean client abort already
        // deleted the record (`get_record` → `None`), and a finalized
        // session is `Active` — neither should be reaped here.
        let status = match mngr.get_record(sessions::SessionKeyPredicate::Id(id)).await {
            Ok(Some(record)) => record.status,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(
                    session_id = %id,
                    error = %e,
                    "could not read session status while reaping after connection close"
                );
                continue;
            }
        };
        if !matches!(
            status,
            ::sessions::SessionStatus::Pending | ::sessions::SessionStatus::Materializing
        ) {
            continue;
        }
        match mngr.delete_session(id).await {
            Ok(()) => tracing::info!(
                session_id = %id,
                ?status,
                "reaped unfinalized session after its connection closed"
            ),
            Err(e) => tracing::warn!(
                session_id = %id,
                error = %e,
                "failed to reap unfinalized session after connection close"
            ),
        }
    }
}

/// Binds and serves minimald's two host-side proxies for the daemon's lifetime
/// and, in a microVM (DM1), publishes them on the macOS host loopback.
///
/// Both proxies route by `Host:` header through the sessions manager's shared
/// PTask hostname registry. In a microVM they bind the daemon's switch IP
/// ([`DEFAULT_SUBNET`](crate::net::DEFAULT_SUBNET)`.daemon_ip()`) so the host
/// gvproxy forward can reach them; on native Linux (DM2) they bind host loopback
/// directly.
///
/// Each proxy's startup — the bind, and in a microVM the host-loopback
/// publish — runs on a detached task that retries with backoff until it
/// succeeds ([`drive_proxy_until_serving`], NET-021) and then clears the
/// unavailable note `min ls` warns from (NET-022). Nothing here is awaited:
/// a proxy whose port some other process holds must not hold the SSH accept
/// loop hostage — the daemon starts serving regardless, reports the reason on
/// its state, and the proxy comes up on its own once the address frees.
#[cfg(target_os = "linux")]
async fn start_host_proxies(state: &ServerStateHandle, in_microvm: bool) {
    use std::net::{IpAddr, Ipv4Addr};

    // DM1 (in-VM): bind 0.0.0.0 so the listener comes up regardless of whether
    // eth0 has finished coming up, then publish the port on the host loopback via
    // the gvproxy forwarder. DM2: bind host loopback directly, no host-expose.
    let bind_base: IpAddr = if in_microvm {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::LOCALHOST.into()
    };

    // B5 egress/DNS proxy (:7654), always. Both ways this can fail end with
    // `<name>.min.internal` not routing, so both are recorded on the
    // state where `ListSessions` can reach them — a daemon that keeps serving
    // without its proxy looks identical to a healthy one otherwise.
    let egress_addr = SocketAddr::new(bind_base, crate::net::proxy::EGRESS_PROXY_PORT);
    tokio::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress { addr: egress_addr },
        RetryBackoff::production(),
    ));

    // B8 mTLS reverse proxy (:7655), under the networking-proxy feature.
    #[cfg(feature = "networking-proxy")]
    {
        // Three ways this ends with nothing serving on :7655, and all three
        // were silent: the TLS config failing to build, the bind failing, and
        // the publish failing. The daemon carries on in every case, so only a
        // reported reason distinguishes "no mTLS proxy configured" from "the
        // mTLS proxy is broken". A TLS config that cannot build is not
        // retryable — the CA material does not change under the retry — so it
        // is reported once, here, and only the bind and publish retry.
        let https_addr = SocketAddr::new(bind_base, crate::net::proxy::HTTPS_PROXY_PORT);
        match state.cert_authority().await.build_server_config() {
            Ok(tls_config) => {
                tokio::spawn(drive_proxy_until_serving(
                    state.clone(),
                    HostProxyStartup::Mtls {
                        addr: https_addr,
                        tls_config,
                    },
                    RetryBackoff::production(),
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "could not build TLS config for the mTLS reverse proxy");
                state
                    .set_mtls_unavailable(format!(
                        "the daemon could not build a TLS config for the mTLS reverse \
                         proxy: {error}"
                    ))
                    .await;
            }
        }
    }
}

/// The retry schedule a host-side proxy's startup uses while its bind (or, in
/// a microVM, its host-loopback publish) keeps failing: each retry waits twice
/// as long as the one before, from `initial` up to `max`. Tests pass a
/// compressed schedule so a retry loop's worth of failures costs milliseconds
/// instead of seconds.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct RetryBackoff {
    initial: Duration,
    max: Duration,
}

#[cfg(target_os = "linux")]
impl RetryBackoff {
    /// Builds a schedule that doubles from `initial` and never waits longer
    /// than `max`.
    #[must_use]
    pub const fn new(initial: Duration, max: Duration) -> Self {
        Self { initial, max }
    }

    /// The daemon's schedule: the first retry 1 s after the failure, doubling
    /// to a 30 s ceiling. Fast enough that a port freed moments after boot is
    /// serving again in seconds; slow enough that a port held for good costs
    /// one warning per 30 s, not a spin.
    #[must_use]
    pub const fn production() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }

    /// The wait before retry `attempt` (0-based: the wait after the first
    /// failure), doubling from `initial` and capped at `max`.
    fn delay(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(30)).unwrap_or(u32::MAX);
        self.initial
            .checked_mul(factor)
            .unwrap_or(self.max)
            .min(self.max)
    }
}

/// Which host-side proxy a startup retry drives. The two differ in what serves
/// a bound listener and which state note a failure lands on; the retry loop
/// itself is shared.
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum HostProxyStartup {
    /// The B5 egress/DNS proxy: plain HTTP routing through the shared router.
    Egress { addr: SocketAddr },
    /// The B8 mTLS reverse proxy: the same routing behind TLS termination.
    #[cfg(feature = "networking-proxy")]
    Mtls {
        addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
    },
}

#[cfg(target_os = "linux")]
impl HostProxyStartup {
    /// The address the listener binds.
    fn addr(&self) -> SocketAddr {
        match self {
            Self::Egress { addr } => *addr,
            #[cfg(feature = "networking-proxy")]
            Self::Mtls { addr, .. } => *addr,
        }
    }

    /// The `component` log field this proxy's startup events carry, matching
    /// what its serve loop logs.
    fn component(&self) -> &'static str {
        match self {
            Self::Egress { .. } => "dns-proxy",
            #[cfg(feature = "networking-proxy")]
            Self::Mtls { .. } => "https-proxy",
        }
    }

    /// Spawns the serve loop for a bound listener. Runs for the daemon's
    /// lifetime; the startup retry never rebinds a bound-and-served listener.
    async fn spawn_serve(&self, state: &ServerStateHandle, listener: TcpListener) {
        #[cfg(feature = "networking-proxy")]
        use crate::net::proxy::serve_https;
        use crate::net::proxy::{Router, serve};

        let router = Router::new(state.sessions_manager().await.hostnames());
        match self {
            Self::Egress { .. } => {
                tokio::spawn(async move {
                    if let Err(error) = serve(listener, router).await {
                        tracing::error!(%error, "egress proxy accept loop exited");
                    }
                });
            }
            #[cfg(feature = "networking-proxy")]
            Self::Mtls { tls_config, .. } => {
                let tls_config = Arc::clone(tls_config);
                tokio::spawn(async move {
                    if let Err(error) = serve_https(listener, router, tls_config).await {
                        tracing::error!(%error, "mTLS proxy accept loop exited");
                    }
                });
            }
        }
    }

    /// Records a failure's reason-and-remedy report on the state note the
    /// `ListSessions` RPC serves (NET-020).
    async fn record_unavailable(&self, state: &ServerStateHandle, report: String) {
        match self {
            Self::Egress { .. } => state.set_proxy_unavailable(report).await,
            #[cfg(feature = "networking-proxy")]
            Self::Mtls { .. } => state.set_mtls_unavailable(report).await,
        }
    }

    /// Clears the failure note: bound and published, the proxy is serving.
    async fn clear_unavailable(&self, state: &ServerStateHandle) {
        match self {
            Self::Egress { .. } => state.clear_proxy_unavailable().await,
            #[cfg(feature = "networking-proxy")]
            Self::Mtls { .. } => state.clear_mtls_unavailable().await,
        }
    }
}

/// Drives the hostname-routing proxy (the B5 egress proxy — the listener
/// `*.min.internal` hostnames route through) to serving: binds `addr`,
/// retrying bind — and, in a microVM, the host-loopback publish — with
/// `retry`'s backoff until both succeed, then keeps serving and clears the
/// daemon's `proxy_unavailable` note so `min ls` stops warning (NET-021,
/// NET-022).
///
/// Detached for the daemon's lifetime by `start_host_proxies`; also spawned
/// directly by tests, which hold the address and watch the retry recover.
#[cfg(any(test, feature = "test-support"))]
#[cfg(target_os = "linux")]
pub async fn retry_hostname_proxy_until_serving(
    state: ServerStateHandle,
    addr: SocketAddr,
    retry: RetryBackoff,
) {
    drive_proxy_until_serving(state, HostProxyStartup::Egress { addr }, retry).await;
}

/// Drives one host-side proxy to serving, retrying with backoff (NET-021).
///
/// Two gates stand between daemon start and a serving proxy, in order: the
/// listener must bind, and — in a microVM (DM1), where the listener binds
/// inside the guest — the port must then be published on the host loopback via
/// the gvproxy forwarder. Each failed attempt logs one warning carrying the
/// failure's reason and remedy and the next retry delay, and records it on the
/// state note the `ListSessions` RPC serves, so `min ls` and
/// `min session activate` print it (NET-020). Once both gates pass the note is
/// cleared and — when any attempt failed — one info line marks the recovery
/// (NET-022): the warning disappears from `min ls` without a daemon restart.
///
/// The serve loop starts as soon as the listener binds and stays up while the
/// publish retries; the bind gate never runs again once it has passed, so a
/// bound-and-served listener is never dropped and rebound.
#[cfg(target_os = "linux")]
async fn drive_proxy_until_serving(
    state: ServerStateHandle,
    proxy: HostProxyStartup,
    retry: RetryBackoff,
) {
    let addr = proxy.addr();
    let component = proxy.component();
    // DM1 only: the bind happens in-guest, so the host loopback is reachable
    // only through the gvproxy forwarder's publish. DM2 binds host loopback
    // directly and has no second gate.
    let publish_port = state.in_microvm().await.then_some(addr.port());

    let mut bound = false;
    let mut attempt: u32 = 0;
    let mut failed_before = false;
    loop {
        if !bound {
            match crate::net::proxy::bind_listener(addr).await {
                Ok(listener) => {
                    proxy.spawn_serve(&state, listener).await;
                    bound = true;
                    if publish_port.is_none() {
                        break;
                    }
                }
                Err(failure) => {
                    let report = failure.reported();
                    let next_retry = retry.delay(attempt);
                    tracing::warn!(
                        component,
                        %addr,
                        status = "unavailable",
                        reason = %report,
                        next_retry = ?next_retry,
                        "host-side proxy could not bind its listener; retrying with backoff"
                    );
                    proxy.record_unavailable(&state, report).await;
                    failed_before = true;
                    attempt += 1;
                    tokio::time::sleep(next_retry).await;
                    continue;
                }
            }
        }
        // Bound and serving. Only the host-loopback publish can still be
        // pending: a bind success with no publish gate broke out above.
        let Some(port) = publish_port else {
            break;
        };
        match expose_proxy_on_host(crate::net::DEFAULT_SUBNET.daemon_ip(), port).await {
            None => break,
            Some(report) => {
                let next_retry = retry.delay(attempt);
                tracing::warn!(
                    component,
                    %port,
                    status = "unavailable",
                    %report,
                    next_retry = ?next_retry,
                    "host-side proxy could not publish on the host loopback; retrying with backoff"
                );
                proxy.record_unavailable(&state, report).await;
                failed_before = true;
                attempt += 1;
                tokio::time::sleep(next_retry).await;
            }
        }
    }

    if failed_before {
        tracing::info!(
            component,
            %addr,
            status = "recovered",
            "host-side proxy is serving after retrying"
        );
    }
    proxy.clear_unavailable(&state).await;
}

/// Upper bound on one host-loopback publish attempt in
/// [`expose_proxy_on_host`]. Deliberately far below `post_json`'s gvproxy
/// control timeout: the startup retry's failed attempts must not each cost the
/// full 5 s before the next try — when the forwarder control path is not
/// reachable over the shuttle in every deployment, a retry every 5 s would
/// spend nearly all its time waiting instead of checking. A reachable
/// forwarder answers in well under this bound.
#[cfg(target_os = "linux")]
const HOST_EXPOSE_PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Publishes a guest-side proxy bound on `daemon_ip:port` onto the macOS host's
/// loopback (`127.0.0.1:port`) via the host gvproxy forwarder, reached over the
/// vsock shuttle (DM1). Best-effort in that it never fails the daemon, since
/// the host gvproxy may be absent; capped at [`HOST_EXPOSE_PUBLISH_TIMEOUT`]
/// per attempt so a stalled forwarder cannot stretch the retry cadence.
///
/// Returns `Some(report)` when the publish did not happen — the reason and the
/// remedy as one text, which the startup retry logs with its next retry and
/// records on the state note for `min ls` / `min session activate` to print —
/// and `None` once published.
#[cfg(target_os = "linux")]
async fn expose_proxy_on_host(daemon_ip: std::net::Ipv4Addr, port: u16) -> Option<String> {
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
    match tokio::time::timeout(
        HOST_EXPOSE_PUBLISH_TIMEOUT,
        post_json(&control, "/services/forwarder/expose", &request),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(error)) => Some(format!(
            "the daemon could not publish port {port} on the host loopback via \
             the gvproxy forwarder: {error}. Remedy: check that the host \
             gvproxy (minvmd) is running and reachable over the shuttle"
        )),
        Err(_) => Some(format!(
            "publishing port {port} on the host loopback did not complete within \
             {HOST_EXPOSE_PUBLISH_TIMEOUT:?}. Remedy: check that the host \
             gvproxy (minvmd) is running and reachable over the shuttle"
        )),
    }
}

/// A [`Config`] rooted at `dir` (state and cache both), with an ephemeral host
/// key and no VM trappings — the daemon shape every unit test wants. Lives out
/// here rather than in `tests` so sibling modules' tests can build a
/// [`ServerStateHandle`] the same way.
#[cfg(test)]
pub(crate) fn test_config(dir: &std::path::Path) -> Config {
    let path = camino::Utf8PathBuf::from_path_buf(dir.to_path_buf()).unwrap();
    Config {
        host_key: HostKey::Ephemeral,
        minimal_state_dir: DaemonAbsPath::try_new(path.clone()).unwrap(),
        minimal_cache_dir: DaemonAbsPath::try_new(path).unwrap(),
        gvproxy_bin: None,
        in_microvm: false,
        state_volume_mounted: false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use minimald_rpc::{Shutdown, ShutdownRequest, ShutdownResponse};
    use tempfile::TempDir;

    use super::*;
    use crate::test_harness::connect_uds;

    /// A `Config` backed by a fresh tempdir, mirroring `TestServer::new`.
    fn test_config(dir: &TempDir) -> Config {
        super::test_config(dir.path())
    }

    /// The volume-log release must run exactly once no matter how many
    /// times the Shutdown path invokes it, and a harness-style `None`
    /// release must be a no-op.
    #[tokio::test]
    async fn log_release_runs_exactly_once() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let dir = TempDir::new().unwrap();
        let count = Arc::new(AtomicU32::new(0));
        let counted = count.clone();
        let release = DaemonLogRelease::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        let state = ServerStateHandle::new(test_config(&dir), Some(release))
            .await
            .unwrap();
        state.release_log().await;
        state.release_log().await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "one-shot, then a no-op");

        let none = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();
        none.release_log().await;
    }

    /// Binds a UDS in `dir` and spawns `Server::run` against it, returning the
    /// run task's join handle alongside the socket path clients dial.
    fn spawn_server(
        dir: &TempDir,
    ) -> (
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
        std::path::PathBuf,
    ) {
        let sock = dir.path().join("minimald.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let run = tokio::spawn(Server::run(test_config(dir), listener, None));
        (run, sock)
    }

    #[tokio::test]
    async fn shutdown_rpc_drives_run_to_return_once_the_client_disconnects() {
        let dir = TempDir::new().unwrap();
        let (run, sock) = spawn_server(&dir);

        {
            let mut client = connect_uds(&sock).await;
            let resp = client
                .call::<Shutdown>(&ShutdownRequest { force: false })
                .await;
            assert_eq!(resp, ShutdownResponse::ShuttingDown);
            // Dropping `client` closes the connection, so the drain sees the
            // last in-flight session finish and `run` returns without waiting
            // out the grace period.
        }

        let res = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run should return promptly once the client disconnects");
        assert!(res.unwrap().is_ok(), "run should return Ok after shutdown");
    }

    #[tokio::test]
    async fn shutdown_rpc_returns_even_if_the_initiating_client_lingers() {
        let dir = TempDir::new().unwrap();
        let (run, sock) = spawn_server(&dir);

        // Keep the client — and thus its connection — open past the shutdown.
        // The drain can't complete gracefully, so the grace period must elapse
        // and abort the straggler, guaranteeing `run` still returns.
        let mut client = connect_uds(&sock).await;
        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);

        let res = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(3), run)
            .await
            .expect("run must return after the grace period aborts lingering connections");
        assert!(res.unwrap().is_ok(), "run should return Ok after shutdown");
        drop(client);
    }

    /// A session left unfinalized when its creating connection closes —
    /// the state an interrupted `min session activate` (Ctrl-C at the gating
    /// prompt) leaves on the daemon — is reaped, while a finalized
    /// (`Active`) session created over that same connection survives.
    #[tokio::test]
    async fn dropping_a_connection_reaps_only_its_unfinalized_sessions() {
        use crate::test_harness::{create_configured_session, create_session_req};
        use minimald_rpc::{CreateSession, GetSessionRecord, GetSessionRecordRequest};

        let dir = TempDir::new().unwrap();
        let (run, sock) = spawn_server(&dir);

        // Connection A: create a Pending session (no ConfigureLoadout) AND a
        // fully-finalized Active session, then drop the connection.
        let (pending_id, active_id) = {
            let mut client = connect_uds(&sock).await;
            let pending = client
                .call::<CreateSession>(&create_session_req("interrupted", "/tmp"))
                .await
                .ok()
                .expect("create pending session")
                .id;
            let active = create_configured_session(&mut client, "finalized", "/tmp").await;
            (pending, active)
            // `client` dropped here → connection closes → the server's
            // per-connection task runs the teardown reap.
        };

        // The reap is asynchronous (it runs once the socket close is
        // observed), so poll a fresh connection until the Pending record is
        // gone. The Active record must remain throughout.
        let mut client = connect_uds(&sock).await;
        let mut reaped = false;
        for _ in 0..100 {
            let pending_gone = client
                .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(pending_id))
                .await
                .record
                .is_none();
            if pending_gone {
                reaped = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            reaped,
            "an unfinalized (Pending) session must be reaped when its creating connection closes",
        );
        assert!(
            client
                .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(active_id))
                .await
                .record
                .is_some(),
            "an Active session must survive the connection that created it",
        );

        let _ = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
    }

    /// A `MakeWriter` accumulating everything written into a shared buffer, so
    /// a test can assert on the structured fields a `tracing` event emitted.
    /// Local twin of the helper the `net::proxy` tests used before the bind
    /// failure's log line moved to the startup retry that owns the schedule.
    #[cfg(target_os = "linux")]
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(target_os = "linux")]
    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[cfg(target_os = "linux")]
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// The `next_retry=<delay>` values the startup retry's failure warnings
    /// carried, in the order they were logged.
    #[cfg(target_os = "linux")]
    fn logged_next_retries(log: &str) -> Vec<&str> {
        log.match_indices("next_retry=")
            .map(|(start, _)| {
                let rest = &log[start + "next_retry=".len()..];
                rest.split([' ', '\n', ',']).next().unwrap_or_default()
            })
            .collect()
    }

    /// The hostname proxy's startup retry keeps trying a held listen address:
    /// each failed bind warns once with the reason, the remedy, and the next
    /// (doubling, capped) retry delay and records the reason-and-remedy report
    /// on the state note (NET-021); once the address frees, the next attempt
    /// binds, the note clears, and the recovery is logged (NET-022) — no
    /// daemon restart anywhere.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn listener_retries_with_backoff() {
        // Hold an address so the startup retry's binds fail deterministically.
        let held = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = held.local_addr().unwrap();

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();
        // A compressed schedule: first retry 5 ms after the failure, doubling
        // to a 20 ms cap, so a loop's worth of failures costs milliseconds.
        let retrier = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress { addr },
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // Three failures are enough to see the doubling and the cap.
        let mut saw_three_warnings = false;
        for _ in 0..200 {
            if buf
                .contents()
                .matches("could not bind its listener")
                .count()
                >= 3
            {
                saw_three_warnings = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            saw_three_warnings,
            "expected three failure warnings while the address is held, got: {}",
            buf.contents()
        );
        let note = state
            .proxy_unavailable()
            .await
            .expect("a held address must be recorded as the unavailable note");
        assert!(
            note.contains("could not bind") && note.contains("Remedy"),
            "the note must carry the reason and the remedy, got: {note}"
        );

        // The retry delays double from the schedule's initial wait and cap at
        // its max: 5 ms, 10 ms, then 20 ms for as long as the address stays
        // held.
        let logged = buf.contents();
        let delays = logged_next_retries(&logged);
        assert_eq!(
            &delays[..3.min(delays.len())],
            &["5ms", "10ms", "20ms"][..3.min(delays.len())],
            "retry delays must grow with backoff and cap, got: {delays:?}"
        );
        assert!(
            delays.iter().skip(3).all(|d| *d == "20ms"),
            "retries past the cap must wait the cap, got: {delays:?}"
        );

        // Freeing the address lets the next attempt bind: the retry task
        // resolves, the note clears, and the recovery is on the log.
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), retrier)
            .await
            .expect("the retry must finish once the address frees")
            .expect("the retry task must not panic");
        assert!(
            state.proxy_unavailable().await.is_none(),
            "recovery must clear the unavailable note without a restart"
        );
        let logged = buf.contents();
        assert!(
            logged.contains(r#"status="recovered""#),
            "the recovery must be logged, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="reachable""#),
            "the successful bind must be logged as reachable, got: {logged}"
        );
    }
}
