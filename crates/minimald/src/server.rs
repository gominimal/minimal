use ::paths::DaemonAbsPath;
use russh::keys::key::safe_rng;
use russh::keys::{PrivateKey, ssh_key::Error as KeyError};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
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
    /// The port the host-side hostname proxy should listen on. `None` — the
    /// default — lets the daemon pick: the standard
    /// [`EGRESS_PROXY_PORT`](crate::net::proxy::EGRESS_PROXY_PORT) while it is
    /// free, else a free port, so a second daemon on the same machine keeps a
    /// working hostname surface (NET-024/NET-025/NET-027).
    #[serde(default)]
    pub hostname_proxy_port: Option<u16>,
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
    /// a new key will be generated and written if the file is missing — or
    /// present but unreadable, which a hard kill of the VM can leave behind.
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
                // Missing is the first-use case; any other failure means the
                // file is there but unusable — a zero-filled key an unflushed
                // write left behind a `kill -9` of the VMM, say. Either way a
                // `create_if_missing` daemon replaces it rather than refusing
                // to start. A permission error is the exception: the key may be
                // perfectly good and is not this process's to overwrite.
                Err(e)
                    if *create_if_missing
                        && !matches!(e, KeyError::Io(ErrorKind::PermissionDenied)) =>
                {
                    if !matches!(e, KeyError::Io(ErrorKind::NotFound)) {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "on-disk host key unreadable; regenerating"
                        );
                    }
                    let key = PrivateKey::random(&mut safe_rng(), russh::keys::Algorithm::Ed25519)?;
                    write_host_key_atomically(&key, path)?;
                    Ok(key)
                }
                Err(e) => Err(e),
            },
            HostKey::Raw(r) => Ok(PrivateKey::from_openssh(r.as_bytes())?),
        }
    }
}

/// Writes `key` to `path` as an OpenSSH PEM without ever exposing a partial
/// file: the bytes land in a sibling `<path>.tmp`, are flushed with
/// `sync_all`, and only then renamed over `path`. The parent directory is
/// synced afterwards so the rename itself survives a hard kill — a plain
/// create-and-write can be left zero-filled by ext4's delayed allocation,
/// which is exactly the corrupt key the read path above has to recover from.
fn write_host_key_atomically(key: &PrivateKey, path: &std::path::Path) -> Result<(), KeyError> {
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let written = (|| -> Result<(), std::io::Error> {
        let mut options = std::fs::File::options();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            // The mode `write_openssh_file` produced before.
            options.mode(0o600);
        }
        let mut file = options.write(true).create(true).truncate(true).open(&tmp)?;
        std::io::Write::write_all(&mut file, pem.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();

    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }

    // Durability of the rename only; the key bytes are already on disk.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
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

/// The hostname proxy's live listen port and how that port was decided.
///
/// Recorded once the listener binds, and read back by `ListSessions` so `min`
/// prints the port in use rather than assuming the default (NET-026), and by
/// the diagnostic bundle so a support archive says which port each daemon on
/// the machine took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostnameProxyPort {
    /// The port the proxy is serving on.
    pub port: u16,
    /// A stable token naming how the port was decided: `configured`, `default`
    /// or `selected` (see [`PortChoice`](crate::net::proxy::PortChoice)). A
    /// `&'static str` rather than the enum itself so this type — held on the
    /// server state, which every platform compiles — does not reach into the
    /// Linux-only `net` module.
    pub chosen: &'static str,
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

    /// The daemon-scoped gvproxy switch, whose `Arc` the sessions manager also
    /// holds. Kept here for what belongs to no session either: the hostname
    /// proxy reads the box declarations it carries, so a routed request is
    /// decided against what the target box declared (NET-069 to NET-071).
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

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

    /// The in-guest box zone of the daemon's switch (NET-072, NET-073), held
    /// here so the box-zone answerer can dump it beside the host's own zone.
    /// The switch itself is the sessions manager's; this is the one table it
    /// shares, behind the same `Arc` every box's relay reads.
    box_zone: Arc<crate::net::policy::BoxZone>,

    /// Why the host-side egress proxy is not reachable, if it is not. Set by
    /// [`start_host_proxies`] and read by the `ListSessions` RPC.
    ///
    /// Both failure paths land here, because they produce the same symptom
    /// from different places: on DM2 the bind itself fails, and on DM1 the
    /// bind succeeds inside the guest but publishing it on the host loopback
    /// does not. A fix that surfaced only the first would stay silent on
    /// macOS, which is the platform the failure was reported from.
    proxy_unavailable: Option<String>,

    /// The port the host-side hostname proxy is serving on, and how that port
    /// was decided. Set by [`start_host_proxies`] once the listener binds, and
    /// read by the `ListSessions` RPC and the diagnostic bundle. `None` before
    /// the bind, and on a state built directly in a unit test.
    hostname_proxy: Option<HostnameProxyPort>,

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

        let box_zone = net_switch.lock().await.box_zone();

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
                Arc::clone(&net_switch),
            )
            .await?,
            net_switch,
            config,
            daemon_id,
            daemon_ctx,
            maintenance: None,
            box_zone,
            shutdown: CancellationToken::new(),
            log_release,
            host_key: None,
            proxy_unavailable: None,
            hostname_proxy: None,
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

    /// The in-guest box zone of the daemon's switch, for the zone dump.
    pub(crate) async fn box_zone(&self) -> Arc<crate::net::policy::BoxZone> {
        Arc::clone(&self.0.lock().await.box_zone)
    }

    /// The daemon-scoped switch, for a test to register a running box on.
    #[cfg(test)]
    pub(crate) async fn net_switch(&self) -> Arc<Mutex<crate::net::SwitchClient>> {
        Arc::clone(&self.0.lock().await.net_switch)
    }

    /// The live box declarations, for the hostname proxy to decide requests
    /// against (NET-069 to NET-071).
    #[cfg(target_os = "linux")]
    pub(crate) async fn box_admissions(
        &self,
    ) -> Arc<std::sync::RwLock<crate::net::policy::BoxAdmissions>> {
        let switch = Arc::clone(&self.0.lock().await.net_switch);
        switch.lock().await.admissions()
    }

    /// Records why hostname routing is unavailable, so a client can be told.
    ///
    /// `pub` rather than `pub(crate)` because the test harness hands tests the
    /// state handle to set up daemon conditions their CLI cannot induce — a
    /// listener whose address is held being one of them.
    pub async fn set_proxy_unavailable(&self, reason: String) {
        self.0.lock().await.proxy_unavailable = Some(reason);
    }

    /// Withdraws the hostname-routing fault: the listener is serving again.
    ///
    /// The next `ListSessions` reads the cleared state, which is what makes the
    /// `min ls` warning disappear on recovery without a daemon restart.
    pub async fn clear_proxy_unavailable(&self) {
        self.0.lock().await.proxy_unavailable = None;
    }

    /// Why hostname routing is unavailable, or `None` if the proxy is up.
    pub(crate) async fn proxy_unavailable(&self) -> Option<String> {
        self.0.lock().await.proxy_unavailable.clone()
    }

    /// Records the port the hostname proxy bound and how it was decided, so
    /// `ListSessions` can hand it to `min` (NET-026) and the diagnostic bundle
    /// can name it.
    ///
    /// `pub` for the same reason as [`Self::set_proxy_unavailable`]: a test is
    /// handed the state handle to set up a daemon condition its CLI cannot
    /// induce — a bound proxy port, on a harness server that never ran
    /// [`Server::run`], being one of them.
    pub async fn set_hostname_proxy_port(&self, proxy: HostnameProxyPort) {
        self.0.lock().await.hostname_proxy = Some(proxy);
    }

    /// The port the hostname proxy is serving on and how it was decided, or
    /// `None` before the listener has bound.
    pub(crate) async fn hostname_proxy_port(&self) -> Option<HostnameProxyPort> {
        self.0.lock().await.hostname_proxy
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
        // flag and the configured proxy port the proxy startup needs first.
        #[cfg(target_os = "linux")]
        let in_microvm = config.in_microvm;
        #[cfg(target_os = "linux")]
        let hostname_proxy_port = config.hostname_proxy_port;
        let state = ServerStateHandle::new(config, log_release).await?;

        // Start minimald's host-side egress proxy (B5, :7654 by default) for the
        // server's lifetime and, in a microVM (DM1), publish it on the macOS host
        // loopback. minimald is Linux-only, and the PTask hostname registry it
        // routes against only exists on Linux.
        #[cfg(target_os = "linux")]
        start_host_proxies(&state, in_microvm, hostname_proxy_port).await;
        // The box-zone answerer (NET-006, NET-124..127) serves the host's own
        // lookups of `*.min.internal`. Native hosts only: in a microVM the
        // node's DNS layer answers the zone with switch addresses.
        #[cfg(target_os = "linux")]
        if !in_microvm {
            start_zone_answerer(&state).await;
            // The host-address classifier's tree (NET-078..NET-080): the
            // daemon enters its own leaf before any box exists, and writes
            // what the privileged install step needs.
            crate::net::host_cohort::native_daemon_start(
                state.minimal_state_dir().await.as_utf8_path().as_std_path(),
            );
        }

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

/// The host-side publish of the hostname proxy's port, behind a trait so the
/// two-VM port policy below can be exercised against a stand-in host.
///
/// Only a daemon in a microVM publishes: a native one binds the host loopback
/// itself and has nothing to hand to a forwarder.
#[cfg(target_os = "linux")]
trait HostPublish {
    /// Publishes `port` on the host loopback, returning why it did not happen.
    fn publish(&self, port: u16) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// The real publisher: the host gvproxy forwarder, over the vsock shuttle.
#[cfg(target_os = "linux")]
struct GvproxyForwarder;

#[cfg(target_os = "linux")]
impl HostPublish for GvproxyForwarder {
    async fn publish(&self, port: u16) -> Option<String> {
        expose_proxy_on_host(crate::net::DEFAULT_SUBNET.daemon_ip(), port).await
    }
}

/// A bound — and, in a VM, published — hostname proxy: the listener to serve,
/// and the fault to report when the host-side publish did not land.
#[cfg(target_os = "linux")]
struct ProxySurface {
    bound: crate::net::proxy::ProxyListener,
    unavailable: Option<String>,
}

/// How many host ports a VM's daemon tries before it reports the publish as
/// failed. The first collision is the other VM's daemon holding the port and
/// every retry asks the OS for a port it says is free, so a handful is already
/// generous; the bound is what stops a host with no forwarder at all from being
/// walked through ports.
#[cfg(target_os = "linux")]
const HOST_PUBLISH_PORT_TRIES: u32 = 4;

/// Whether a refused publish says the host loopback port is already published —
/// the two-VM case (NET-059), where another VM's daemon got there first — rather
/// than a fault that retrying the same port will clear (no host forwarder, a
/// control request that timed out).
#[cfg(target_os = "linux")]
fn host_port_already_published(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("already in use") || reason.contains("address in use")
}

/// Binds the hostname proxy's listener and, in a microVM, publishes its port on
/// the host loopback — taking a different port when that host port is already
/// published by another VM's daemon (NET-059).
///
/// A guest bind cannot collide with another VM's: each VM has a network of its
/// own, so both reach for the standard port and both get it. The collision
/// appears one step later, on the host loopback the port is published to, where
/// the second VM's publish is refused. Retrying it would leave that VM's box
/// names unreachable from the machine for as long as the first VM lives, so the
/// port is re-picked on both sides instead: the guest listener is rebound to a
/// free port and that port is published, keeping the port a client dials and the
/// port the daemon reports (NET-026) one number.
///
/// A configured port is never moved (NET-024): the operator named it, so a
/// refusal is reported and retried exactly as before.
#[cfg(target_os = "linux")]
async fn bind_and_publish_proxy<P: HostPublish>(
    bind_base: std::net::IpAddr,
    configured_port: Option<u16>,
    default_port: u16,
    in_microvm: bool,
    publisher: &P,
) -> Option<ProxySurface> {
    use crate::net::proxy::{self, PortChoice, ProxyListener};

    let mut bound =
        proxy::bind_proxy_listener_with_default(bind_base, configured_port, default_port).await?;
    if !in_microvm {
        return Some(ProxySurface {
            bound,
            unavailable: None,
        });
    }
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let Some(reason) = publisher.publish(bound.port).await else {
            return Some(ProxySurface {
                bound,
                unavailable: None,
            });
        };
        if configured_port.is_some()
            || !host_port_already_published(&reason)
            || attempt >= HOST_PUBLISH_PORT_TRIES
        {
            return Some(ProxySurface {
                bound,
                unavailable: Some(reason),
            });
        }
        tracing::warn!(
            component = "dns-proxy",
            port = bound.port,
            attempt,
            %reason,
            "another VM's daemon already publishes this port on the host loopback; taking another"
        );
        // Port 0: the OS hands back a free one. Assigning drops the listener
        // bound a moment ago, so nothing is left listening on a port no client
        // can reach.
        let listener = proxy::bind_listener(std::net::SocketAddr::new(bind_base, 0)).await?;
        let port = listener.local_addr().ok()?.port();
        bound = ProxyListener {
            listener,
            port,
            choice: PortChoice::Selected,
        };
    }
}

/// Binds and serves minimald's host-side egress proxy for the daemon's lifetime
/// and, in a microVM (DM1), publishes it on the macOS host loopback.
///
/// The proxy routes by `Host:` header through the sessions manager's shared
/// PTask hostname registry. In a microVM it binds the daemon's switch IP
/// ([`DEFAULT_SUBNET`](crate::net::DEFAULT_SUBNET)`.daemon_ip()`) so the host
/// gvproxy forward can reach it; on native Linux (DM2) it binds host loopback
/// directly. A bind failure warns and is skipped — the daemon keeps serving. The
/// serve loop runs on a detached task; this returns once the listener is bound
/// and (DM1) exposed.
///
/// `configured_port` is the operator's `--hostname-proxy-port`, bound as given;
/// `None` lets [`bind_proxy_listener`](crate::net::proxy::bind_proxy_listener)
/// prefer the default port and fall back to a free one, so two daemons on one
/// machine both keep routing. Either way the port that bound is recorded on the
/// state for `ListSessions` to hand to `min`.
#[cfg(target_os = "linux")]
async fn start_host_proxies(
    state: &ServerStateHandle,
    in_microvm: bool,
    configured_port: Option<u16>,
) {
    use crate::net::proxy::{self, Router};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let registry = state.sessions_manager().await.hostnames();
    let admissions = state.box_admissions().await;
    // DM1 (in-VM): bind 0.0.0.0 so the listener comes up regardless of whether
    // eth0 has finished coming up, then publish the port on the host loopback via
    // the gvproxy forwarder. DM2: bind host loopback directly, no host-expose.
    let bind_base: IpAddr = if in_microvm {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::LOCALHOST.into()
    };

    // B5 egress/DNS proxy, always. Both ways this can fail end with
    // `<name>.min.internal` not routing, so both are recorded on the
    // state where `ListSessions` can reach them — a daemon that keeps serving
    // without its proxy looks identical to a healthy one otherwise.
    match bind_and_publish_proxy(
        bind_base,
        configured_port,
        proxy::EGRESS_PROXY_PORT,
        in_microvm,
        &GvproxyForwarder,
    )
    .await
    {
        Some(ProxySurface { bound, unavailable }) => {
            let port = bound.port;
            state
                .set_hostname_proxy_port(HostnameProxyPort {
                    port,
                    chosen: bound.choice.as_str(),
                })
                .await;
            let router = Router::new(registry.clone(), Arc::clone(&admissions));
            tokio::spawn(async move {
                if let Err(error) = proxy::serve(bound.listener, router).await {
                    tracing::error!(%error, "egress proxy accept loop exited");
                }
            });
            if let Some(reason) = unavailable {
                state.set_proxy_unavailable(reason).await;
                // The listener is serving; only its host-side publish is
                // missing, so that alone is retried.
                let state = state.clone();
                tokio::spawn(async move {
                    publish_on_host_retrying(port).await;
                    state.clear_proxy_unavailable().await;
                });
            }
        }
        None => {
            // A configured port held by something else: reported and retried,
            // never swapped for another — an unconfigured daemon would have
            // selected a free port instead of landing here.
            let egress_addr = SocketAddr::new(
                bind_base,
                configured_port.unwrap_or(proxy::EGRESS_PROXY_PORT),
            );
            state
                .set_proxy_unavailable(format!(
                    "the daemon could not bind {egress_addr}; another process is \
                     holding it. Check with: lsof -nP -iTCP:{} -sTCP:LISTEN",
                    egress_addr.port()
                ))
                .await;
            recover_egress_listener(
                state.clone(),
                registry.clone(),
                admissions,
                egress_addr,
                in_microvm,
                if configured_port.is_some() {
                    proxy::PortChoice::Configured
                } else {
                    proxy::PortChoice::Default
                },
            );
        }
    }
}

/// Brings the host-side egress listener back after a failed bind, in the
/// background, and clears the fault report once hostnames route again.
///
/// Rebinds on the [`rebind_delay`](crate::net::proxy::rebind_delay) backoff, in
/// a microVM publishes the port on the host loopback the same way, and only then
/// withdraws the reason `ListSessions` is handing out — so `min ls` stops
/// warning exactly when `*.min.internal` works again, with no daemon restart
/// (R3.4 recovery).
#[cfg(target_os = "linux")]
fn recover_egress_listener(
    state: ServerStateHandle,
    registry: Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
    admissions: Arc<std::sync::RwLock<crate::net::policy::BoxAdmissions>>,
    addr: std::net::SocketAddr,
    in_microvm: bool,
    chosen: crate::net::proxy::PortChoice,
) {
    use crate::net::proxy::{self, Router};

    tokio::spawn(async move {
        let listener = proxy::bind_listener_retrying(addr).await;
        if in_microvm {
            publish_on_host_retrying(addr.port()).await;
        }
        state
            .set_hostname_proxy_port(HostnameProxyPort {
                port: addr.port(),
                chosen: chosen.as_str(),
            })
            .await;
        state.clear_proxy_unavailable().await;
        let router = Router::new(registry, admissions);
        if let Err(error) = proxy::serve(listener, router).await {
            tracing::error!(%error, "egress proxy accept loop exited");
        }
    });
}

/// Keeps asking the host gvproxy forwarder to publish `port` on the host
/// loopback until it accepts (DM1), on the same backoff a rebind uses.
///
/// A publish that never lands leaves a listener that is bound in the guest and
/// unreachable from the host — the DM1 half of the same fault — so it is retried
/// rather than reported once and left.
#[cfg(target_os = "linux")]
async fn publish_on_host_retrying(port: u16) {
    let mut attempt: u32 = 0;
    while let Some(reason) =
        expose_proxy_on_host(crate::net::DEFAULT_SUBNET.daemon_ip(), port).await
    {
        attempt += 1;
        let delay = crate::net::proxy::rebind_delay(attempt);
        tracing::warn!(
            component = "dns-proxy",
            port,
            attempt,
            retry_in_ms = delay.as_millis() as u64,
            %reason,
            "retrying the host-loopback publish for the egress proxy"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Opens the box-zone answerer's socket and serves the zone on a detached
/// task for the daemon's lifetime ([`crate::net::answerer`]). The socket is
/// the service manager's when one was passed, else a loopback bind. A socket
/// failure warns and is skipped: the daemon keeps serving, and names in the
/// zone keep routing through the proxies; only native resolution is lost.
#[cfg(target_os = "linux")]
async fn start_zone_answerer(state: &ServerStateHandle) {
    use crate::net::answerer;

    let listener = match answerer::listen().await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(
                %error,
                address = %answerer::BIND_ADDR,
                "could not open the box-zone answerer socket; `*.min.internal` will not \
                 resolve natively on this host. Check with: lsof -nP -iUDP:{}",
                answerer::ANSWERER_PORT
            );
            return;
        }
    };
    let zone = state.sessions_manager().await.published();
    // The steering table, for the names OUTSIDE the zone: a credentialed
    // hostname a live box steers is answered with the proxy's address, and
    // SERVFAIL while that listener is down (BEP-062). It is the same registry
    // the hostname proxy routes through.
    let steering = state.sessions_manager().await.hostnames();
    let box_zone = state.box_zone().await;
    let daemon_id = state.daemon_id().await;
    let dump_path =
        answerer::zone_dump_path(state.minimal_state_dir().await.as_utf8_path().as_std_path());
    tokio::spawn(async move {
        if let Err(error) =
            answerer::serve(listener, zone, steering, box_zone, daemon_id, dump_path).await
        {
            tracing::error!(%error, "box-zone answerer exited");
        }
    });
}

/// Upper bound on the best-effort host-loopback publish in
/// [`expose_proxy_on_host`]. Deliberately far below `post_json`'s gvproxy
/// control timeout: the publish is awaited on [`Server::run`]'s boot path
/// *before* the SSH accept loop starts serving. When the forwarder control
/// request does not complete promptly — it times out at the full 5 s even with a
/// host gvproxy present, since the forwarder control path is not reachable over
/// the shuttle in every deployment — the accept loop must not be held that long:
/// the cold `minimal ls` connect-retry deadline expires first and the first list
/// fails (`ssh connect: Disconnected`). A reachable forwarder answers in well
/// under this bound.
#[cfg(target_os = "linux")]
const HOST_EXPOSE_PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Publishes a guest-side proxy bound on `daemon_ip:port` onto the macOS host's
/// loopback (`127.0.0.1:port`) via the host gvproxy forwarder, reached over the
/// vsock shuttle (DM1). Best-effort in that it never fails the daemon, since
/// the host gvproxy may be absent. Capped at [`HOST_EXPOSE_PUBLISH_TIMEOUT`] so
/// it never stalls [`Server::run`]'s SSH accept loop.
///
/// Returns `Some(reason)` when the publish did not happen, so the caller can
/// tell a client rather than leaving the loss in the daemon log — on DM1 this
/// is the path a host process holding the port actually breaks.
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
        Ok(Err(error)) => {
            tracing::warn!(
                %port,
                %error,
                "could not publish host-side proxy on the host loopback via gvproxy forwarder"
            );
            Some(format!(
                "the daemon could not publish port {port} on the host loopback \
                 via the gvproxy forwarder: {error}"
            ))
        }
        Err(_) => {
            tracing::warn!(
                %port,
                timeout = ?HOST_EXPOSE_PUBLISH_TIMEOUT,
                "host-side proxy publish did not complete in time; continuing (best-effort)"
            );
            Some(format!(
                "publishing port {port} on the host loopback did not complete within \
                 {HOST_EXPOSE_PUBLISH_TIMEOUT:?}"
            ))
        }
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
        hostname_proxy_port: None,
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

    /// A `Config` whose host key lives at `path`.
    fn on_disk_key_config(
        dir: &TempDir,
        path: &std::path::Path,
        create_if_missing: bool,
    ) -> Config {
        Config {
            host_key: HostKey::OnDisk {
                path: path.to_path_buf(),
                create_if_missing,
            },
            ..test_config(dir)
        }
    }

    /// The names of every `*.tmp` sibling left in `dir`.
    fn stray_temp_files(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    /// A persisted host key left zero-filled by a hard kill of the VM (ext4
    /// delayed allocation drops the unflushed write) must not be fatal: a
    /// `create_if_missing` daemon replaces it and boots, and the key it
    /// returns is the one the next boot will read back.
    #[test]
    fn host_key_regenerates_a_corrupt_on_disk_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ssh_host_ed25519_key");
        std::fs::write(&path, [0u8; 256]).unwrap();
        assert!(
            PrivateKey::read_openssh_file(&path).is_err(),
            "the fixture must be unreadable before the call under test",
        );

        let key = on_disk_key_config(&dir, &path, true)
            .host_key()
            .expect("a corrupt on-disk key must be regenerated, not fatal");

        let reread = PrivateKey::read_openssh_file(&path)
            .expect("the replacement must be a readable OpenSSH key");
        assert_eq!(
            reread.public_key(),
            key.public_key(),
            "the key handed to the server must be the one persisted",
        );
    }

    /// The key file is only ever observable whole: the write goes through a
    /// sibling temp file that is renamed into place and never left behind.
    /// With `create_if_missing: false` a corrupt key is still an error and the
    /// bytes on disk are left exactly as they were.
    #[test]
    fn host_key_write_leaves_no_partial_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ssh_host_ed25519_key");

        let key = on_disk_key_config(&dir, &path, true)
            .host_key()
            .expect("a missing key must be generated");
        assert_eq!(
            PrivateKey::read_openssh_file(&path).unwrap().public_key(),
            key.public_key(),
        );
        let strays = stray_temp_files(dir.path());
        assert!(
            strays.is_empty(),
            "no temp sibling may survive the write: {strays:?}",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the private key must stay owner-only");
        }

        // A daemon that did not ask for creation still refuses a corrupt key,
        // and must not have touched it on the way out.
        let corrupt = dir.path().join("corrupt_host_key");
        std::fs::write(&corrupt, [0u8; 256]).unwrap();
        assert!(
            on_disk_key_config(&dir, &corrupt, false)
                .host_key()
                .is_err(),
            "create_if_missing: false must propagate the read failure",
        );
        assert_eq!(
            std::fs::read(&corrupt).unwrap(),
            vec![0u8; 256],
            "the key file must be left untouched",
        );
        let strays = stray_temp_files(dir.path());
        assert!(strays.is_empty(), "no temp sibling may be left: {strays:?}");
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

    /// This machine's loopback standing in for the host gvproxy's forwarder:
    /// `port` is published on `127.0.0.1` and relayed to `target` inside the VM
    /// that published it, or refused in the forwarder's own words when another
    /// VM already holds it. The host is shared by the two VMs below, which is
    /// what makes the second VM's publish fail the way it does on a real
    /// machine.
    #[cfg(target_os = "linux")]
    async fn publish_on_host_loopback(port: u16, target: std::net::SocketAddr) -> Option<String> {
        use std::net::Ipv4Addr;
        use tokio::net::{TcpListener, TcpStream};

        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => listener,
            Err(error) => return Some(format!("listen tcp 127.0.0.1:{port}: bind: {error}")),
        };
        tokio::spawn(async move {
            while let Ok((mut down, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut up) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
            }
        });
        None
    }

    /// One VM's publisher: the address inside that VM a published host port has
    /// to be relayed back to.
    #[cfg(target_os = "linux")]
    struct VmPublisher {
        guest: std::net::IpAddr,
    }

    #[cfg(target_os = "linux")]
    impl HostPublish for VmPublisher {
        async fn publish(&self, port: u16) -> Option<String> {
            publish_on_host_loopback(port, std::net::SocketAddr::new(self.guest, port)).await
        }
    }

    /// A box-host registry holding one box that carries its node's address, and
    /// the declarations a routed request is decided against. A host-address box
    /// declares no ports of its own, so every port a direct connection reaches
    /// routes — what a test about *names* wants.
    #[cfg(target_os = "linux")]
    fn box_named(
        name: &str,
    ) -> (
        Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
        Arc<std::sync::RwLock<crate::net::policy::BoxAdmissions>>,
    ) {
        use crate::net::dns::{DEFAULT_HOST_ID, HostnameRegistry};
        use crate::net::policy::{BoxAdmissions, BoxDeclaration};

        let registry = Arc::new(std::sync::RwLock::new(HostnameRegistry::new(
            DEFAULT_HOST_ID,
        )));
        registry
            .write()
            .unwrap()
            .register_host_net(::sessions::SessionId::nil(), name);
        let admissions = Arc::new(std::sync::RwLock::new(BoxAdmissions::new()));
        admissions.write().unwrap().declare(
            name,
            BoxDeclaration::for_host_address(crate::net::SwitchSubnet::default()),
        );
        (registry, admissions)
    }

    /// A loopback backend answering every connection with `200 OK`, standing in
    /// for the server inside a box. Returns the port it listens on.
    #[cfg(target_os = "linux")]
    async fn box_backend() -> u16 {
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpListener;

        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        port
    }

    /// One `GET` through the host's published port, carrying `authority` as its
    /// `Host:` header, and the raw response that came back.
    #[cfg(target_os = "linux")]
    async fn get_through_host(port: u16, authority: &str) -> String {
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut client = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// A free loopback port: bound only to learn a port the OS had free, then
    /// dropped. What the default hostname-proxy port stands in as, so the test
    /// never depends on whatever holds the standard one on this machine.
    #[cfg(target_os = "linux")]
    async fn free_port() -> u16 {
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// NET-059: with two VMs running, both VMs' box hostnames route through the
    /// host's hostname surface at the same time.
    ///
    /// Each VM's daemon binds its hostname proxy inside its own VM, where the
    /// standard port is always free, so the only place two VMs can collide is
    /// the host loopback they publish that port on. Both VMs are stood up here
    /// as their own addresses on this machine's loopback net, preferring one
    /// default port, against a shared host that holds each port once and relays
    /// it into the VM that published it — the forwarder's behaviour. The second
    /// VM's publish is refused, it takes another port, and a request to each
    /// published port then reaches that VM's own box and no other's.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_vms_hostnames_route_concurrently() {
        use crate::net::proxy::{self, Router};
        use std::net::{IpAddr, Ipv4Addr};

        let default_port = free_port().await;
        // Two VMs, each with an address of its own: inside a VM the daemon's
        // bind can never meet the other VM's.
        let alpha_guest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let beta_guest = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));

        let alpha = bind_and_publish_proxy(
            alpha_guest,
            None,
            default_port,
            true,
            &VmPublisher { guest: alpha_guest },
        )
        .await
        .expect("the first VM's daemon binds and publishes");
        let beta = bind_and_publish_proxy(
            beta_guest,
            None,
            default_port,
            true,
            &VmPublisher { guest: beta_guest },
        )
        .await
        .expect("the second VM's daemon binds and publishes");

        assert_eq!(
            alpha.unavailable, None,
            "the first VM's publish must land: {:?}",
            alpha.unavailable
        );
        assert_eq!(
            beta.unavailable, None,
            "the second VM must end up published too, not left reporting a held port: {:?}",
            beta.unavailable
        );
        assert_eq!(alpha.bound.port, default_port);
        assert_ne!(
            alpha.bound.port, beta.bound.port,
            "two VMs cannot share one host loopback port"
        );
        assert_eq!(
            beta.bound.choice,
            proxy::PortChoice::Selected,
            "the second VM's port was selected after the first one's was held"
        );

        // Each VM serves its own box's name, and only that one.
        let (alpha_registry, alpha_admissions) = box_named("alpha-web");
        let (beta_registry, beta_admissions) = box_named("beta-web");
        let alpha_port = alpha.bound.port;
        let beta_port = beta.bound.port;
        tokio::spawn(proxy::serve(
            alpha.bound.listener,
            Router::new(alpha_registry, alpha_admissions),
        ));
        tokio::spawn(proxy::serve(
            beta.bound.listener,
            Router::new(beta_registry, beta_admissions),
        ));

        // Both surfaces at once: one request per VM, in flight together, each
        // for its own box, both through the host's published ports.
        let backend = box_backend().await;
        let alpha_authority = format!("alpha-web.min.internal:{backend}");
        let beta_authority = format!("beta-web.min.internal:{backend}");
        let (alpha_answer, beta_answer) = tokio::join!(
            get_through_host(alpha_port, &alpha_authority),
            get_through_host(beta_port, &beta_authority),
        );
        assert!(
            alpha_answer.contains("200 OK"),
            "the first VM's box must route through the host: {alpha_answer}"
        );
        assert!(
            beta_answer.contains("200 OK"),
            "the second VM's box must route through the host at the same time: {beta_answer}"
        );

        // Two surfaces, not one: neither VM answers for the other's boxes.
        let crossed = get_through_host(alpha_port, &beta_authority).await;
        assert!(
            crossed.contains("502 Bad Gateway"),
            "a VM must not route another VM's box names: {crossed}"
        );
    }

    /// A publish refused because the host port is held is the one refusal a
    /// daemon answers by taking another port; every other refusal is retried on
    /// the port it has, so a host with no forwarder is not walked through ports.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_held_host_port_moves_the_proxy() {
        assert!(host_port_already_published(
            "the daemon could not publish port 7654 on the host loopback via the gvproxy \
             forwarder: listen tcp 127.0.0.1:7654: bind: Address already in use (os error 98)"
        ));
        assert!(host_port_already_published("expose failed: address in use"));
        assert!(!host_port_already_published(
            "publishing port 7654 on the host loopback did not complete within 1s"
        ));
        assert!(!host_port_already_published(
            "the daemon could not publish port 7654 on the host loopback via the gvproxy \
             forwarder: connection refused"
        ));
    }
}
