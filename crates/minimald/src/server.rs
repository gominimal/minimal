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
use std::net::{IpAddr, SocketAddr};
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
    /// The port the host-side hostname proxy must listen on, when this
    /// deployment pins one — the documented default clients' `HTTP(S)_PROXY`
    /// recipes assume is [`crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT`].
    ///
    /// `None` means the daemon takes that default first, so those recipes
    /// keep working on a quiet host, and only when it is busy asks the OS
    /// for a free port, publishing whichever port it got wherever a client
    /// needs it (NET-024/NET-025) — the report's `port_source` says which
    /// of the three happened ("configured", "default", "selected").
    #[serde(default)]
    pub hostname_proxy_port: Option<u16>,
    /// The port the box-zone answerer must listen on (UDP), when this
    /// deployment pins one — the documented default the host-resolver
    /// recipe assumes is [`crate::net::answerer::ANSWERER_PORT`]. `None`
    /// gives it the same default-then-select treatment
    /// [`Config::hostname_proxy_port`] documents.
    #[serde(default)]
    pub zone_answerer_port: Option<u16>,
    /// The third octet of the /24 inside the default switch /16
    /// ([`crate::net::DEFAULT_SUBNET`]) that this daemon's gvproxy switch
    /// draws its `OwnIp` PTask leases — and, keyed on the same octet, this
    /// daemon's slice of the reserved local range — from. `None` (the
    /// default) derives the octet from the daemon instance id, so two
    /// daemons on one machine take two different octets and with them two
    /// different switch /24s: their PTask leases can never collide. Their
    /// publish slices are disjoint only while the two octets stay
    /// incongruent modulo the reserved range's slice count — the
    /// wrap-around [`crate::sessions::LoopbackAllocator::for_slice_octet`]
    /// names, which a pair of derived octets falls into about one time in
    /// eight; two daemons that fall in share one slice until NET-010's
    /// host-global allocation arbitrates (NET-027's address half).
    /// A deployment — or a test that needs a deterministic pair — pins the
    /// octet instead; pinning it does not check what other daemons on the
    /// host hold, which is the host-global arbitration NET-010's allocation
    /// adds.
    ///
    /// Only a daemon that owns its gvproxy — a native host, DM2 — can honor
    /// this for its *switch*: a daemon in a microVM attaches to the host
    /// gvproxy `minvmd` owns, whose config the guest cannot change, so it
    /// carries that switch's default /16 whatever this field says (see
    /// [`switch_subnet_for`]). Its *slice* still follows the octet, derived
    /// when unpinned: the slice is the daemon's own state, not the switch's,
    /// so two VM daemons on one host draw from their own octets' slices —
    /// disjoint, save for the same wrap-around the paragraph above names.
    #[serde(default)]
    pub switch_subnet_octet: Option<u8>,
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

    /// The port the hostname proxy is actually listening on, once its
    /// startup retry has bound (and, in a microVM, published) it: the
    /// configured port when the deployment pinned one, the documented
    /// default when nobody did and it was free, else the OS-selected free
    /// port the fallback asked for (NET-024/NET-025). `None` until then —
    /// which is also what a client talking to a pre-discovery daemon sees —
    /// and on a state whose proxies were never started (unit-test states).
    hostname_proxy_port: Option<u16>,

    /// The port the box-zone answerer is actually listening on (UDP), once
    /// its startup has bound (and, in a microVM, published) it. Carries the
    /// same configured/default/selected story [`Self::hostname_proxy_port`]
    /// does; reported beside it so the host-resolver recipe can name the
    /// port to point at.
    zone_answerer_port: Option<u16>,

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
        // This daemon's slice octet — pinned by the deployment, else derived
        // from its instance id — names *both* halves of its address space:
        // the /24 a switch it owns runs on (a native host, DM2), and its
        // slice of the reserved local range. Keeping one octet for both is
        // what keeps the two aligned on a native host, where the octet is the
        // third octet of the switch's own /24, while letting a microVM daemon
        // — whose switch it does not own stays on the default /16 — still draw
        // from a slice of its own: two VM daemons on one host take two
        // distinct octets, and with them two different slices except where
        // the octets land congruent modulo the reserved range's slice count —
        // the wrap-around `LoopbackAllocator::for_slice_octet` names and the
        // start line below makes visible, which NET-010's host-global
        // allocation arbitrates (NET-027).
        let slice_octet = config
            .switch_subnet_octet
            .unwrap_or_else(|| octet_for_daemon_id(&daemon_id));
        // The subnet this daemon's switch carries — decided by who owns the
        // gvproxy it attaches to; see [`switch_subnet_for`].
        let switch_subnet = switch_subnet_for(config.in_microvm, slice_octet);
        let net_switch = Arc::new(Mutex::new(
            crate::net::SwitchClient::with_subnet(
                config.gvproxy_bin_path(),
                minimal_state_dir.as_utf8_path().join("gvproxy"),
                switch_subnet,
            )
            .with_transport(transport)
            // This switch belongs to *this* daemon instance: its `OwnIp`
            // DNS registrations carry the instance id as their host label,
            // so a second daemon on the same host registers its own names
            // instead of overwriting the first's records (NET-027).
            .with_host_id(daemon_id.clone()),
        ));
        // One line at daemon start naming the switch subnet this instance's
        // boxes lease on, the octet its published boxes' slice is keyed to,
        // and that slice of the reserved local range — the facts a reader of
        // two daemons' logs (a diagnostics bundle tails exactly this log)
        // compares: two lines with different `loopback_slice` ranges hold
        // disjoint halves of the machine, and two lines carrying the *same*
        // range are the wrap-around — octets congruent modulo the reserved
        // range's slice count index one slice — visible in the logs rather
        // than hidden, and arbitrated host-globally by NET-010's allocation
        // when it binds.
        let (slice_first, slice_last) =
            sessions::LoopbackAllocator::for_slice_octet(slice_octet).range();
        tracing::info!(
            daemon_id = %daemon_id,
            subnet = %switch_subnet,
            slice_octet = slice_octet,
            loopback_slice = %format!("{slice_first}-{slice_last}"),
            "gvproxy switch this daemon's boxes lease on; published boxes \
             will come from the slice this daemon's octet indexes"
        );

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
            hostname_proxy_port: None,
            zone_answerer_port: None,
            #[cfg(feature = "networking-wg")]
            mesh: None,
        })
    }
}

/// The subnet this daemon's [`SwitchClient`](crate::net::SwitchClient)
/// carries, decided by who owns the gvproxy it attaches to.
///
/// A daemon that owns its switch (DM2, a native host: it spawns gvproxy
/// from a config it renders itself) runs it on the /24 inside the default
/// switch /16 whose third octet is `octet` — the octet a deployment pins,
/// else the one its instance id derives — so two daemons on one machine take
/// two different /24s and with them two disjoint `OwnIp` PTask-lease ranges,
/// and keyed on the same octet two slices of the reserved local range that
/// are disjoint except across the wrap-around
/// [`crate::sessions::LoopbackAllocator::for_slice_octet`] names: octets
/// congruent modulo the range's slice count index one shared slice
/// (NET-027).
///
/// A daemon in a microVM (DM1/3/4) does **not** own its switch: it attaches
/// its boxes' taps to the host gvproxy `minvmd` owns, whose config the
/// guest can neither read nor change — `minvmd` renders it with
/// [`crate::net::DEFAULT_SUBNET`], the default /16. Every address the
/// guest derives from its switch must be one that gvproxy actually answers
/// at: an `OwnIp` box's lease *and* its gateway and DNS server (the
/// switch's `network + 1`, where gvproxy answers DNS), the resolver a
/// host-address box gets, and the legacy host literal
/// [`crate::net::switch`](crate::net::switch)'s relay watches
/// (the subnet's `broadcast - 1` — the /16's `100.64.255.254` is the
/// literal NET-004 names). A derived /24 here would point every box at
/// `100.64.<octet>.1` — an address no gvproxy answers — and the boxes in
/// the VM lose all egress, DNS first: the guest root tap
/// ([`crate::guest::bring_up_root_egress`]) is configured from the same
/// /16, so a microVM daemon carries that /16 whatever octet it was given —
/// the guest cannot move a switch it does not own onto another. Its
/// **slice** still follows the octet: the slice is the daemon's own state,
/// not the switch's, and keying it on the switch subnet would collapse
/// every VM on the host onto one shared slice of the reserved local range.
fn switch_subnet_for(in_microvm: bool, octet: u8) -> crate::net::SwitchSubnet {
    if in_microvm {
        return crate::net::DEFAULT_SUBNET;
    }
    switch_subnet_for_octet(octet)
}

/// The per-daemon switch subnet a native daemon's own gvproxy runs: the /24
/// inside the default switch /16 ([`crate::net::DEFAULT_SUBNET`]) whose
/// third octet `octet` names — see [`switch_subnet_for`] for who may take
/// one.
fn switch_subnet_for_octet(octet: u8) -> crate::net::SwitchSubnet {
    let [first, second, _, _] = crate::net::DEFAULT_SUBNET.network().octets();
    crate::net::SwitchSubnet::new(std::net::Ipv4Addr::new(first, second, octet, 0), 24)
        .expect("a /24 inside the default switch /16 is always a valid prefix")
}

/// The third octet a daemon instance id derives: FNV-1a over the id's bytes,
/// folded into `1..=254`. Deterministic per id, so two daemons with distinct
/// ids take distinct /24s in all but the id pairs that hash alike — a
/// collision the reserved-address arithmetic of the /24 keeps from ever
/// handing out the *same address twice within one daemon*, and which
/// NET-010's host-global allocation is the layer that arbitrates across
/// daemons.
fn octet_for_daemon_id(id: &str) -> u8 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in id.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // 1..=254, never 0 (the /16's own gateway sits at its network + 1) and
    // never 255 (the /16's own host alias and daemon address sit in its last
    // /24): a derived switch never reserves the same gateway, alias, or
    // daemon address the host gvproxy on a DM1 host already answers at.
    (hash % 254 + 1) as u8
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

    /// Records the port the hostname proxy actually listens on, once its
    /// startup has bound (and, in a microVM, published) it.
    pub(crate) async fn set_hostname_proxy_port(&self, port: u16) {
        self.0.lock().await.hostname_proxy_port = Some(port);
    }

    /// The port the hostname proxy listens on, or `None` while it is still
    /// coming up. Filled on the `ListSessions` and `CreateSession` replies
    /// so a client can print — and point `HTTP(S)_PROXY` at — the port this
    /// daemon is on (NET-026).
    pub(crate) async fn hostname_proxy_port(&self) -> Option<u16> {
        self.0.lock().await.hostname_proxy_port
    }

    /// Records the port the box-zone answerer actually listens on (UDP),
    /// once its startup has bound (and, in a microVM, published) it.
    pub(crate) async fn set_zone_answerer_port(&self, port: u16) {
        self.0.lock().await.zone_answerer_port = Some(port);
    }

    /// The port the box-zone answerer listens on (UDP), or `None` while it
    /// is still coming up. Filled beside [`Self::hostname_proxy_port`] on
    /// the `ListSessions` and `CreateSession` replies so a client can name
    /// the port to point the host resolver at.
    pub(crate) async fn zone_answerer_port(&self) -> Option<u16> {
        self.0.lock().await.zone_answerer_port
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
        // flag and the two port choices the proxy startup needs first.
        #[cfg(target_os = "linux")]
        let in_microvm = config.in_microvm;
        #[cfg(target_os = "linux")]
        let hostname_proxy_port = config.hostname_proxy_port;
        #[cfg(target_os = "linux")]
        let zone_answerer_port = config.zone_answerer_port;
        let state = ServerStateHandle::new(config, log_release).await?;

        // Start minimald's host-side egress proxy (B5, on its configured,
        // default, or OS-selected port) and the box-zone answerer beside it
        // for the server's lifetime, and in a microVM (DM1) publish them on
        // the macOS host loopback. minimald is Linux-only, and the PTask
        // hostname registry they route against only exists on Linux.
        #[cfg(target_os = "linux")]
        start_host_proxies(&state, in_microvm, hostname_proxy_port, zone_answerer_port).await;

        Self::serve(state, listener).await
    }

    /// The accept loop of [`Server::run`], from the state on: serve SSH
    /// connections off the listener until it errors or shutdown is
    /// requested, then drain. Split from `run` so a test can build the state
    /// itself — holding a handle to the hostname registry the running proxy
    /// routes against, which no RPC fills — start the same host proxies, and
    /// still drive the listener path a real daemon serves on.
    async fn serve<L: Listener>(
        state: ServerStateHandle,
        listener: L,
    ) -> Result<(), std::io::Error> {
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
        // abort whatever is left so `serve` always returns and the process exits.
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

/// Binds and serves minimald's host-side listeners — the egress proxy, and
/// beside it the box-zone answerer — for the daemon's lifetime and, in a
/// microVM (DM1), publishes them on the macOS host loopback.
///
/// The proxies route by `Host:` header through the sessions manager's shared
/// PTask hostname registry; the answerer serves the same registry as DNS,
/// answering `*.min.internal` for the host OS (NET-009). In a microVM they
/// bind the daemon's switch IP
/// ([`DEFAULT_SUBNET`](crate::net::DEFAULT_SUBNET)`.daemon_ip()`) so the host
/// gvproxy forward can reach them; on native Linux (DM2) they bind host
/// loopback directly.
///
/// Each startup — the bind, and in a microVM the host-loopback publish —
/// runs on a detached task that retries with backoff until it succeeds
/// ([`drive_proxy_until_serving`], [`drive_answerer_until_serving`], NET-021)
/// and then clears the unavailable note `min ls` warns from (NET-022).
/// Nothing here is awaited: a listener whose port some other process holds
/// must not hold the SSH accept loop hostage — the daemon starts serving
/// regardless, reports the reason on its state, and the listener comes up on
/// its own once the address frees.
#[cfg(target_os = "linux")]
async fn start_host_proxies(
    state: &ServerStateHandle,
    in_microvm: bool,
    hostname_proxy_port: Option<u16>,
    zone_answerer_port: Option<u16>,
) {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::net::answerer::{AnswerScope, ZoneAnswerer};

    // DM1 (in-VM): bind 0.0.0.0 so the listener comes up regardless of whether
    // eth0 has finished coming up, then publish the port on the host loopback via
    // the gvproxy forwarder. DM2: bind host loopback directly, no host-expose.
    let bind_base: IpAddr = if in_microvm {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::LOCALHOST.into()
    };

    // B5 egress/DNS proxy, always. The port is the one the deployment pinned
    // (NET-024); with none pinned it takes the documented default first and
    // only when that is busy asks the OS for a free one, so a second daemon
    // on the same host takes its own port instead of silently losing routing
    // (NET-025). The driver records the port it ended up on where the RPCs a
    // client discovers it from can read it.
    tokio::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base,
            port: ProxyPort::from_config(
                hostname_proxy_port,
                crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            ),
        },
        in_microvm,
        HostExpose::Shuttle,
        RetryBackoff::production(),
    ));

    // The box-zone answerer (UDP), beside the hostname proxy: the loopback
    // answerer the host's resolver is routed to for `*.min.internal`
    // (design §7.1, NET-009). Same bind rule as the proxies — and the same
    // configured/default/selected port treatment — and the same publish on a
    // VM host — over UDP, which is how the host resolver's datagrams travel.
    // The on-machine gate is the answerer's own: loopback peers natively,
    // and in a VM the host-local switch fabric the gvproxy forwarder rides
    // (NET-006).
    let answerer_scope = if in_microvm {
        AnswerScope::Microvm {
            subnet: crate::net::DEFAULT_SUBNET,
        }
    } else {
        AnswerScope::Native
    };
    let answerer = ZoneAnswerer::new(state.sessions_manager().await.hostnames(), answerer_scope);
    tokio::spawn(drive_answerer_until_serving(
        state.clone(),
        answerer,
        bind_base,
        ProxyPort::from_config(zone_answerer_port, crate::net::answerer::ANSWERER_PORT),
        in_microvm,
        HostExpose::Shuttle,
        RetryBackoff::production(),
    ));
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

/// How a host-side listener's port was chosen — the `port_source` field its
/// startup line and diagnostics-bundle answer carry, which is exactly the
/// question a reader of two daemons' logs asks: who chose this port?
///
/// "default" is the middle case a bare `None` config lands in on a quiet
/// host: nobody pinned a port, and the documented default one was free.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSource {
    /// The deployment's flag named the port.
    Configured,
    /// No port was configured and the documented default one was free.
    Default,
    /// The OS chose: no port was configured and the default was busy, a
    /// publish was refused and the port was re-picked, or the bind asked
    /// for port `0` outright.
    Selected,
}

#[cfg(target_os = "linux")]
impl PortSource {
    /// The word the startup line and the log grep see.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Default => "default",
            Self::Selected => "selected",
        }
    }

    /// The source a [`ProxyPort`] starts at, before any fallback relocates
    /// the bind.
    #[must_use]
    fn of(choice: ProxyPort) -> Self {
        match choice {
            ProxyPort::Pinned(0) => Self::Selected,
            ProxyPort::Pinned(_) => Self::Configured,
            ProxyPort::DefaultThenSelect { .. } => Self::Default,
        }
    }
}

/// Which port a host-side listener asks for, and what a busy one does — the
/// one policy both the hostname proxy and the box-zone answerer follow.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPort {
    /// Bind exactly this port. A busy one is a hard failure that keeps
    /// retrying with backoff and never silently moves the listener: the
    /// operator named the port, and `--hostname-proxy-port=7654` on a host
    /// whose 7654 is held must be told so, not routed around (NET-024).
    /// Port `0` is the OS-picks form: the kernel is asked for a free port,
    /// which cannot fail busy.
    Pinned(u16),
    /// Nobody pinned one (NET-025): bind the documented default first — the
    /// port every `HTTP(S)_PROXY` recipe assumes — and only when it is busy
    /// ask the OS for a free one, which the daemon then reports as
    /// "selected".
    DefaultThenSelect { default: u16 },
}

#[cfg(target_os = "linux")]
impl ProxyPort {
    /// The choice a config's `Option<u16>` makes: `Some` pins,
    /// `None` takes the default and falls back when busy.
    #[must_use]
    pub fn from_config(configured: Option<u16>, default: u16) -> Self {
        match configured {
            Some(port) => Self::Pinned(port),
            None => Self::DefaultThenSelect { default },
        }
    }

    /// The port the first bind asks for.
    #[must_use]
    fn first_port(self) -> u16 {
        match self {
            Self::Pinned(port) => port,
            Self::DefaultThenSelect { default } => default,
        }
    }

    /// Whether a failed bind should fall back to asking the OS for a free
    /// port: only the default-then-select choice — a pinned port's failure
    /// is the operator's to clear, and moving the listener would be the
    /// silent loss of routing the requirement rules out.
    #[must_use]
    fn reselects_when_busy(self) -> bool {
        matches!(self, Self::DefaultThenSelect { .. })
    }

    /// Whether a refused host-loopback publish should pick a fresh port
    /// rather than keep retrying the same one: any port the *guest* chose —
    /// the OS-selected one, or the documented default nobody pinned — is the
    /// daemon's to move; a port the operator pinned stays put (the publish
    /// retry is the remedy, and the report says so). Picking a fresh port
    /// is what lets two VMs on one host both come up when their
    /// guest-chosen ports collide (NET-027).
    ///
    /// "Refused" means the host port was actually taken
    /// ([`HostPublishFailure::port_taken`]) — a transient failure keeps the
    /// port and retries, so a daemon that boots before its host gvproxy does
    /// not move off its default.
    #[must_use]
    fn reselects_when_publish_refused(self) -> bool {
        !matches!(self, Self::Pinned(port) if port != 0)
    }
}

/// Which host-side proxy a startup retry drives. The one left differs only in
/// what serves a bound listener and which state note a failure lands on; the
/// retry loop itself is shared.
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum HostProxyStartup {
    /// The B5 egress/DNS proxy: plain HTTP routing through the shared
    /// router, on `port` at `bind_base`.
    Egress { bind_base: IpAddr, port: ProxyPort },
}

#[cfg(target_os = "linux")]
impl HostProxyStartup {
    /// The address base the listener binds: the port comes from
    /// [`Self::port_choice`], and can move under the retry's fallbacks while
    /// the base never does.
    fn bind_base(&self) -> IpAddr {
        match self {
            Self::Egress { bind_base, .. } => *bind_base,
        }
    }

    /// The port policy this startup follows.
    fn port_choice(&self) -> ProxyPort {
        match self {
            Self::Egress { port, .. } => *port,
        }
    }

    /// The `component` log field this proxy's startup events carry, matching
    /// what its serve loop logs.
    fn component(&self) -> &'static str {
        match self {
            Self::Egress { .. } => "dns-proxy",
        }
    }

    /// Spawns the serve loop for a bound listener. Runs for the daemon's
    /// lifetime; the startup retry never rebinds a bound-and-served listener
    /// — except the one case that must: a host publish that was refused on
    /// a guest-chosen port (see [`ProxyPort::reselects_when_publish_refused`]),
    /// which aborts the returned handle and rebinds elsewhere.
    async fn spawn_serve(
        &self,
        state: &ServerStateHandle,
        listener: TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        use crate::net::proxy::{Router, serve};

        let router = Router::new(state.sessions_manager().await.hostnames());
        match self {
            Self::Egress { .. } => tokio::spawn(async move {
                if let Err(error) = serve(listener, router).await {
                    tracing::error!(%error, "egress proxy accept loop exited");
                }
            }),
        }
    }

    /// Records a failure's reason-and-remedy report on the state note the
    /// `ListSessions` RPC serves (NET-020).
    async fn record_unavailable(&self, state: &ServerStateHandle, report: String) {
        match self {
            Self::Egress { .. } => state.set_proxy_unavailable(report).await,
        }
    }

    /// Clears the failure note: bound and published, the proxy is serving.
    async fn clear_unavailable(&self, state: &ServerStateHandle) {
        match self {
            Self::Egress { .. } => state.clear_proxy_unavailable().await,
        }
    }

    /// Reports the bound-and-published proxy on the state: the port the
    /// hostname proxy actually listens on is what the discovery fields of
    /// the `ListSessions` and `CreateSession` replies carry, so a client
    /// can find — and point `HTTP(S)_PROXY` at — this daemon's port
    /// (NET-026). The one info line beside it is the diagnostics-bundle
    /// answer to "which port is this daemon on, and who chose it": the
    /// bundle tails the daemon log, and two daemons on one host (NET-027)
    /// is exactly when the question gets asked.
    ///
    /// `source` is who chose the port — the flag, the documented default,
    /// or the OS — which is what the line and the reader of two daemons'
    /// logs want to know (see [`PortSource`]).
    async fn record_serving(&self, state: &ServerStateHandle, bound_port: u16, source: PortSource) {
        match self {
            Self::Egress { .. } => {
                tracing::info!(
                    component = self.component(),
                    port = bound_port,
                    port_source = source.as_str(),
                    status = "serving",
                    "hostname proxy is serving on its {} port",
                    source.as_str()
                );
                state.set_hostname_proxy_port(bound_port).await;
            }
        }
    }
}

/// Drives the hostname-routing proxy (the B5 egress proxy — the listener
/// `*.min.internal` hostnames route through) to serving: binds `addr`
/// (port `0` asks the OS for a free one), retrying with `retry`'s backoff
/// until it succeeds, then keeps serving and clears the daemon's
/// `proxy_unavailable` note so `min ls` stops warning (NET-021, NET-022).
///
/// Detached for the daemon's lifetime by `start_host_proxies`; also spawned
/// directly by tests, which hold the address and watch the retry recover.
/// The test path never publishes on a host loopback — the host gvproxy a
/// publish needs is a harness this helper's callers don't have.
#[cfg(any(test, feature = "test-support"))]
#[cfg(target_os = "linux")]
pub async fn retry_hostname_proxy_until_serving(
    state: ServerStateHandle,
    addr: SocketAddr,
    retry: RetryBackoff,
) {
    drive_proxy_until_serving(
        state,
        HostProxyStartup::Egress {
            bind_base: addr.ip(),
            port: ProxyPort::Pinned(addr.port()),
        },
        false,
        HostExpose::Shuttle,
        retry,
    )
    .await;
}

/// Drives the box-zone answerer to serving the same way
/// [`retry_hostname_proxy_until_serving`] drives the proxy: binds `addr`
/// (port `0` asks the OS for a free one) against the native scope and
/// records the port it landed on, so a test's RPC replies carry the answerer's
/// port beside the proxy's (`min ls` prints both).
///
/// The test path never publishes on a host loopback, for the same reason the
/// proxy helper's does not.
#[cfg(any(test, feature = "test-support"))]
#[cfg(target_os = "linux")]
pub async fn retry_zone_answerer_until_serving(
    state: ServerStateHandle,
    addr: SocketAddr,
    retry: RetryBackoff,
) {
    use crate::net::answerer::{AnswerScope, ZoneAnswerer};

    let answerer = ZoneAnswerer::new(
        state.sessions_manager().await.hostnames(),
        AnswerScope::Native,
    );
    drive_answerer_until_serving(
        state,
        answerer,
        addr.ip(),
        ProxyPort::Pinned(addr.port()),
        false,
        HostExpose::Shuttle,
        retry,
    )
    .await;
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
/// The port the listener ended up on — and who chose it, per the
/// [`ProxyPort`] policy — is recorded on the state for the RPC replies'
/// discovery field, and named in one startup info line (NET-025, NET-026).
///
/// The serve loop starts as soon as the listener binds and stays up while the
/// publish retries; the bind gate never runs again once it has passed, so a
/// bound-and-served listener is never dropped and rebound — with the one
/// exception [`ProxyPort::reselects_when_publish_refused`] names: a guest-
/// chosen port the host refused to publish is released and a fresh one
/// picked, because retrying a port the host will not take comes up never.
#[cfg(target_os = "linux")]
async fn drive_proxy_until_serving(
    state: ServerStateHandle,
    proxy: HostProxyStartup,
    publish_on_host: bool,
    expose: HostExpose,
    retry: RetryBackoff,
) {
    let component = proxy.component();
    let bind_base = proxy.bind_base();
    // Which port to ask for, and what a busy one does. The address the loop
    // binds can move under the two fallbacks below; the base never does.
    let choice = proxy.port_choice();
    let mut addr = SocketAddr::new(bind_base, choice.first_port());
    // The port the bind currently asks for: 0 means "OS, pick a free one"
    // (NET-025). The port the proxy *ended up* on can only be read off the
    // bound listener, because the chosen one lives there and nowhere else.
    let mut bound_port = addr.port();
    let mut source = PortSource::of(choice);
    // The serve task, kept so a refused host publish can abort it before the
    // rebind picks a fresh port — otherwise the old listener would keep
    // answering on a port nothing forwards to.
    let mut serve: Option<tokio::task::JoinHandle<()>> = None;

    let mut bound = false;
    let mut attempt: u32 = 0;
    let mut failed_before = false;
    loop {
        if !bound {
            match crate::net::proxy::bind_listener(addr).await {
                Ok(listener) => {
                    // Auto-selected ports are only discoverable here, off the
                    // bound socket — and the publish below needs the real one:
                    // forwarding port 0 forwards nothing.
                    match listener.local_addr() {
                        Ok(local) => {
                            bound_port = local.port();
                            serve = Some(proxy.spawn_serve(&state, listener).await);
                            bound = true;
                            if !publish_on_host {
                                break;
                            }
                        }
                        Err(error) => {
                            let report = format!(
                                "the proxy's listener bound but would not report its address: \
                                 {error}"
                            );
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
                Err(failure) => {
                    // Nobody pinned a port and the address is *busy*: fall
                    // back to asking the OS for a free one (NET-025) rather
                    // than retrying a port some other process owns — the one
                    // bind failure that relocates. Any other failure (an
                    // address that cannot be assigned, a permission the
                    // daemon lacks) keeps its address and retries (NET-021):
                    // it is not another daemon holding the port, and moving
                    // the listener would hide the report. The relocation
                    // is a warning, not an unavailability — the proxy is
                    // about to come up, one port over.
                    if choice.reselects_when_busy() && failure.is_addr_in_use() && addr.port() != 0
                    {
                        tracing::warn!(
                            component,
                            %addr,
                            "the default hostname-proxy port is busy; selecting a free one"
                        );
                        addr = SocketAddr::new(bind_base, 0);
                        source = PortSource::Selected;
                        continue;
                    }
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
        let Some(port) = publish_on_host.then_some(bound_port) else {
            break;
        };
        match expose
            .publish(crate::net::DEFAULT_SUBNET.daemon_ip(), port, "tcp")
            .await
        {
            None => break,
            Some(failure) => {
                // A guest-chosen port the host genuinely could not take:
                // release it and pick a fresh one instead of retrying a
                // publish that will never succeed. A pinned port stays put —
                // the operator named it, and the report is the remedy. A
                // *transient* failure — the shuttle not up yet at boot, a
                // stalled exchange — keeps the port and retries with the
                // existing backoff, so a daemon that starts before its host
                // gvproxy does not lose its default port (NET-021, NET-025).
                let next_retry = retry.delay(attempt);
                if choice.reselects_when_publish_refused() && failure.port_taken {
                    if let Some(serve) = serve.take() {
                        serve.abort();
                    }
                    bound = false;
                    addr = SocketAddr::new(bind_base, 0);
                    source = PortSource::Selected;
                    tracing::warn!(
                        component,
                        %port,
                        status = "unavailable",
                        %failure.report,
                        next_retry = ?next_retry,
                        "host-side proxy will pick a fresh port and bind again"
                    );
                } else {
                    tracing::warn!(
                        component,
                        %port,
                        status = "unavailable",
                        %failure.report,
                        next_retry = ?next_retry,
                        "host-side proxy could not publish on the host loopback; retrying with backoff"
                    );
                }
                proxy.record_unavailable(&state, failure.report).await;
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
    proxy.record_serving(&state, bound_port, source).await;
}

/// Drives the box-zone answerer to serving, the same two gates, the same
/// backoff and the same [`ProxyPort`] policy the routing proxies take
/// ([`drive_proxy_until_serving`], NET-021): binds at `bind_base` on `port`,
/// and — in a microVM (DM1), where the socket binds inside the guest —
/// publishes the port on the host loopback through the gvproxy forwarder's
/// **UDP** path, the transport the host resolver's datagrams travel on. Once
/// both gates pass, [`crate::net::answerer::serve`] runs for the daemon's
/// lifetime, and the port it ended up on — and who chose it — is recorded on
/// the state for the RPC replies to carry beside the proxy's.
///
/// The daemon log names the listener's address and port at start (the bind's
/// `reachable` event, the serving event here) and each failure warns once
/// with its reason, remedy and next retry. Unlike a routing proxy, the
/// answerer records no `min ls` note: a box's routing does not depend on it
/// (the proxies carry that), and its failures are the host's resolver config
/// to read in the log.
#[cfg(target_os = "linux")]
async fn drive_answerer_until_serving<T: crate::net::answerer::Zone>(
    state: ServerStateHandle,
    answerer: crate::net::answerer::ZoneAnswerer<T>,
    bind_base: IpAddr,
    port: ProxyPort,
    publish_on_host: bool,
    expose: HostExpose,
    retry: RetryBackoff,
) {
    const COMPONENT: &str = "zone-answerer";

    let mut addr = SocketAddr::new(bind_base, port.first_port());
    let mut source = PortSource::of(port);
    // The port the socket actually landed on — read off the bound socket, the
    // only place a chosen one lives — which the publish and the state's
    // discovery field both need: forwarding port 0 forwards nothing.
    let mut bound_port = addr.port();
    // The serve task, kept so a refused host publish can abort it before the
    // rebind picks a fresh port.
    let mut serve: Option<tokio::task::JoinHandle<()>> = None;
    let mut bound = false;

    let mut attempt: u32 = 0;
    let mut failed_before = false;
    loop {
        if !bound {
            match crate::net::answerer::bind_answerer(addr).await {
                Ok(socket) => match socket.local_addr() {
                    Ok(local) => {
                        // Serving from the moment the socket is bound, like
                        // the proxies: the publish can still retry behind it.
                        // The serve loop takes a clone; the registry inside is
                        // the daemon's one either way. The bound port — the
                        // only place a selected one lives — is what the
                        // publish below and the state's discovery field need.
                        bound_port = local.port();
                        let bound_addr = SocketAddr::new(bind_base, bound_port);
                        tracing::info!(
                            component = COMPONENT,
                            %bound_addr,
                            port = bound_port,
                            status = "listening",
                            "box-zone answerer is serving"
                        );
                        let serve_answerer = answerer.clone();
                        serve = Some(tokio::spawn(async move {
                            if let Err(error) =
                                crate::net::answerer::serve(socket, serve_answerer).await
                            {
                                tracing::error!(
                                    component = COMPONENT,
                                    %error,
                                    "box-zone answerer receive loop exited"
                                );
                            }
                        }));
                        bound = true;
                        if !publish_on_host {
                            break;
                        }
                    }
                    Err(error) => {
                        let report = format!(
                            "the answerer's socket bound but would not report its address: \
                             {error}"
                        );
                        let next_retry = retry.delay(attempt);
                        tracing::warn!(
                            component = COMPONENT,
                            %addr,
                            status = "unavailable",
                            reason = %report,
                            next_retry = ?next_retry,
                            "box-zone answerer could not bind its socket; retrying with backoff"
                        );
                        failed_before = true;
                        attempt += 1;
                        tokio::time::sleep(next_retry).await;
                        continue;
                    }
                },
                Err(failure) => {
                    // Nobody pinned a port and the address is *busy*: fall
                    // back to asking the OS for a free one (NET-025), the
                    // same relocation the routing proxies take — and the
                    // same rule that only a busy address relocates; every
                    // other bind failure keeps its address and retries
                    // (NET-021).
                    if port.reselects_when_busy() && failure.is_addr_in_use() && addr.port() != 0 {
                        tracing::warn!(
                            component = COMPONENT,
                            %addr,
                            "the default zone-answerer port is busy; selecting a free one"
                        );
                        addr = SocketAddr::new(bind_base, 0);
                        source = PortSource::Selected;
                        continue;
                    }
                    let report = failure.reported();
                    let next_retry = retry.delay(attempt);
                    tracing::warn!(
                        component = COMPONENT,
                        %addr,
                        status = "unavailable",
                        reason = %report,
                        next_retry = ?next_retry,
                        "box-zone answerer could not bind its socket; retrying with backoff"
                    );
                    failed_before = true;
                    attempt += 1;
                    tokio::time::sleep(next_retry).await;
                    continue;
                }
            }
        }
        // Bound and serving; only the host-loopback publish can still be
        // pending (a bind success with no publish gate broke out above).
        match expose
            .publish(crate::net::DEFAULT_SUBNET.daemon_ip(), bound_port, "udp")
            .await
        {
            None => break,
            Some(failure) => {
                // A guest-chosen port the host genuinely could not take:
                // pick a fresh one rather than retry the same publish forever,
                // the same release-and-rebind the routing proxies take. A
                // pinned port stays put, and a *transient* failure — the
                // shuttle not up yet at boot, a stalled exchange — keeps the
                // port and retries with the existing backoff, the same rule
                // the proxies follow (NET-021, NET-025).
                let next_retry = retry.delay(attempt);
                if port.reselects_when_publish_refused() && failure.port_taken {
                    if let Some(serve) = serve.take() {
                        serve.abort();
                    }
                    bound = false;
                    addr = SocketAddr::new(bind_base, 0);
                    source = PortSource::Selected;
                    tracing::warn!(
                        component = COMPONENT,
                        port = bound_port,
                        status = "unavailable",
                        %failure.report,
                        next_retry = ?next_retry,
                        "box-zone answerer will pick a fresh port and bind again"
                    );
                } else {
                    tracing::warn!(
                        component = COMPONENT,
                        %addr,
                        status = "unavailable",
                        %failure.report,
                        next_retry = ?next_retry,
                        "box-zone answerer could not publish on the host loopback; retrying with backoff"
                    );
                }
                failed_before = true;
                attempt += 1;
                tokio::time::sleep(next_retry).await;
            }
        }
    }

    if failed_before {
        tracing::info!(
            component = COMPONENT,
            %addr,
            status = "recovered",
            "box-zone answerer is serving after retrying"
        );
    }
    tracing::info!(
        component = COMPONENT,
        port = bound_port,
        port_source = source.as_str(),
        status = "serving",
        "box-zone answerer is serving on its {} port",
        source.as_str()
    );
    state.set_zone_answerer_port(bound_port).await;
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

/// A host-loopback publish that did not happen: the reason-and-remedy report
/// (which the startup retry logs with its next delay and records on the state
/// note a client prints), plus whether the host-side port was actually
/// refused — the only publish failure a guest-chosen port re-picks from.
///
/// Every other cause is *transient* — the shuttle not reachable, the host
/// forwarder not up yet at boot, an exchange that stalls past its bound — and
/// keeps the port it has: the retry comes on the same backoff (NET-021), so a
/// daemon that starts before its host gvproxy does not drift off the default
/// port nobody configured (NET-025) and stay there until it restarts.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct HostPublishFailure {
    /// The reason and the remedy as one text.
    report: String,
    /// Whether the forwarder was reached and refused to take the host-side
    /// port — on this endpoint, a host port some other process already
    /// holds — versus a failure that never got an answer from the forwarder.
    port_taken: bool,
}

/// Publishes a guest-side listener bound on `daemon_ip:port` — a routing
/// proxy, or the box-zone answerer (`protocol` says which transport) — onto
/// the macOS host's loopback (`127.0.0.1:port`) via the host gvproxy
/// forwarder, reached over the vsock shuttle (DM1). Best-effort in that it
/// never fails the daemon, since the host gvproxy may be absent; capped at
/// [`HOST_EXPOSE_PUBLISH_TIMEOUT`] per attempt so a stalled forwarder cannot
/// stretch the retry cadence.
///
/// Returns `Some(failure)` when the publish did not happen — its `report` is
/// the reason and remedy as one text, and its `port_taken` says whether the
/// host port is actually unusable (a taken one is the guest-chosen port's
/// cue to re-pick; a transient one keeps the port and retries) — and `None`
/// once published.
#[cfg(target_os = "linux")]
async fn expose_proxy_on_host(
    daemon_ip: std::net::Ipv4Addr,
    port: u16,
    protocol: &'static str,
) -> Option<HostPublishFailure> {
    publish_listener_on_control(
        &crate::net::policy::ControlChannel::Vsock {
            cid: crate::net::VSOCK_HOST_CID,
            port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
        },
        daemon_ip,
        port,
        protocol,
    )
    .await
}

/// [`expose_proxy_on_host`]'s publish, over whichever control channel the
/// forwarder is reached on: the vsock shuttle from inside a microVM, a unix
/// control socket on a native host — and, in a test, whichever stand-in the
/// classifier's two arms need. The control channel is the only thing the
/// caller picks; the request shape, the bound, the report, and the
/// taken-versus-transient classification are the same on every channel.
#[cfg(target_os = "linux")]
async fn publish_listener_on_control(
    control: &crate::net::policy::ControlChannel,
    daemon_ip: std::net::Ipv4Addr,
    port: u16,
    protocol: &'static str,
) -> Option<HostPublishFailure> {
    use crate::net::policy::{ExposeRequest, post_json};

    let request = ExposeRequest {
        local: format!("127.0.0.1:{port}"),
        remote: format!("{daemon_ip}:{port}"),
        protocol: protocol.to_string(),
    };
    match tokio::time::timeout(
        HOST_EXPOSE_PUBLISH_TIMEOUT,
        post_json(control, "/services/forwarder/expose", &request),
    )
    .await
    {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            // The forwarder answered and refused: it could not take the
            // host-side port (`post_json` folds an HTTP error status into one
            // io::Error whose text names it), which on this endpoint is a
            // host port some other process holds. Everything else reaching
            // this arm — a refused or unreachable shuttle, a socket error —
            // never got an answer at all, so the port may still be free.
            let port_taken = error.to_string().contains("returned HTTP");
            Some(HostPublishFailure {
                report: format!(
                    "the daemon could not publish port {port} on the host loopback via \
                     the gvproxy forwarder: {error}. Remedy: check that the host \
                     gvproxy (minvmd) is running and reachable over the shuttle"
                ),
                port_taken,
            })
        }
        Err(_) => Some(HostPublishFailure {
            report: format!(
                "publishing port {port} on the host loopback did not complete within \
                 {HOST_EXPOSE_PUBLISH_TIMEOUT:?}. Remedy: check that the host \
                 gvproxy (minvmd) is running and reachable over the shuttle"
            ),
            // A stalled exchange says nothing about the port; it is the
            // transient case by construction.
            port_taken: false,
        }),
    }
}

/// The host-loopback publish a startup driver gates its bound listener
/// behind. Production publishes through the gvproxy forwarder over the
/// vsock shuttle ([`HostExpose::Shuttle`]); a test stands a fixed answer in
/// ([`HostExpose::Fixed`]) so each half of the publish's failure space — a
/// host port actually taken, which re-picks, and a transient failure, which
/// must not — can be driven deterministically, no host gvproxy required.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
enum HostExpose {
    /// The daemon's publish: gvproxy's forwarder over the vsock shuttle.
    Shuttle,
    /// A test's stand-in that answers `answer` for every attempt.
    #[cfg(test)]
    Fixed(Option<HostPublishFailure>),
}

#[cfg(target_os = "linux")]
impl HostExpose {
    /// Runs one publish attempt for a listener bound on `daemon_ip:port`.
    async fn publish(
        &self,
        daemon_ip: std::net::Ipv4Addr,
        port: u16,
        protocol: &'static str,
    ) -> Option<HostPublishFailure> {
        match self {
            Self::Shuttle => expose_proxy_on_host(daemon_ip, port, protocol).await,
            #[cfg(test)]
            Self::Fixed(answer) => answer.clone(),
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
        state_volume_mounted: false,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        switch_subnet_octet: None,
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
        spawn_server_with(dir, test_config(dir))
    }

    /// [`spawn_server`] with an explicit [`Config`]: the tests that pin ports
    /// or flip the deployment model drive the flags' path through
    /// [`Server::run`] rather than around it.
    fn spawn_server_with(
        dir: &TempDir,
        config: Config,
    ) -> (
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
        std::path::PathBuf,
    ) {
        let sock = dir.path().join("minimald.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let run = tokio::spawn(Server::run(config, listener, None));
        (run, sock)
    }

    /// [`spawn_server_with`] with the built state handed back to the caller.
    /// The start path is the one `Server::run` takes — the same proxy startup
    /// against the config's port choices, then the real accept loop off the
    /// same listener — but the state stays reachable, for the tests that must
    /// fill the hostname registry the running proxy routes against: no RPC
    /// does, it is the session launch path that fills it.
    #[cfg(target_os = "linux")]
    async fn spawn_stateful_server_with(
        dir: &TempDir,
        config: Config,
    ) -> (
        ServerStateHandle,
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
        std::path::PathBuf,
    ) {
        let in_microvm = config.in_microvm;
        let hostname_proxy_port = config.hostname_proxy_port;
        let zone_answerer_port = config.zone_answerer_port;
        let state = ServerStateHandle::new(config, None).await.unwrap();
        start_host_proxies(&state, in_microvm, hostname_proxy_port, zone_answerer_port).await;
        let sock = dir.path().join("minimald.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let run = tokio::spawn(Server::serve(state.clone(), listener));
        (state, run, sock)
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
            HostProxyStartup::Egress {
                bind_base: addr.ip(),
                // Pinned: a configured port's bind failure is the operator's
                // to clear, never a relocation.
                port: ProxyPort::Pinned(addr.port()),
            },
            false,
            HostExpose::Shuttle,
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

    /// Spawns a backend on `addr` that answers every request with a `200 OK`
    /// whose body is `body`. Local twin of `net::proxy`'s one-shot helper,
    /// with a body so the two-daemon test can tell its backends apart — and
    /// with the address as a parameter, so two daemons' boxes can publish the
    /// same port on different addresses.
    #[cfg(target_os = "linux")]
    async fn spawn_backend_on(addr: std::net::SocketAddr, body: &'static str) {
        let backend = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    // `sock` drops here, closing the upstream side.
                });
            }
        });
    }

    /// Spawns a loopback backend (see [`spawn_backend_on`]) on a free port,
    /// returning the port it listens on.
    #[cfg(target_os = "linux")]
    async fn spawn_backend_saying(body: &'static str) -> u16 {
        use std::net::{IpAddr, Ipv4Addr};

        // Reserve then drop: the bind below re-takes the port for keeps.
        let port = {
            let bind = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            bind.local_addr().unwrap().port()
        };
        spawn_backend_on(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), body).await;
        port
    }

    /// Drives the hostname proxy with a `GET` carrying `Host: <authority>`
    /// and returns the raw response the client read back — the proxy's own
    /// test-facing shape, driven through the port a daemon's startup bound.
    #[cfg(target_os = "linux")]
    async fn proxy_get(proxy_addr: SocketAddr, authority: &str) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Waits until the state reports the port its hostname proxy ended up on.
    #[cfg(target_os = "linux")]
    async fn wait_for_proxy_port(state: &ServerStateHandle) -> u16 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(port) = state.hostname_proxy_port().await {
                    return port;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the hostname proxy must bind and report its port")
    }

    /// NET-024: a daemon configured with a hostname-proxy port listens on
    /// exactly that one — driven through the start path [`Server::run`] takes,
    /// so the flags a deployment passes are the ones proven. The startup
    /// binds the port rather than re-picking, both listeners' discovery
    /// fields (the proxy's and the answerer's) carry the configured ports to
    /// the RPC replies a client reads, the startup lines name the ports as
    /// configured, the proxy answers on that port — refusing a name no live
    /// box owns and routing one a live box owns — and the answerer replies
    /// from the port the host resolver would be pointed at.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_listens_on_configured_port() {
        use std::net::{IpAddr, Ipv4Addr};

        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::rr::RecordType;
        use minimald_rpc::ListSessions;

        use crate::net::answerer::encode_query;

        // Reserve free ports, then hand them to the daemon the way a pinned
        // deployment does: unheld, for its own binds.
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let answerer_port = probe.local_addr().unwrap().port();
        drop(probe);

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = TempDir::new().unwrap();
        let (state, run, sock) = spawn_stateful_server_with(
            &dir,
            Config {
                hostname_proxy_port: Some(port),
                zone_answerer_port: Some(answerer_port),
                ..test_config(&dir)
            },
        )
        .await;

        // The daemon reports its listeners once they are up — that report is
        // the discovery path a client takes, so this poll is the proof the
        // ports are the configured ones.
        let mut client = connect_uds(&sock).await;
        let resp = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let resp = client.call::<ListSessions>(&()).await;
                if resp.hostname_proxy_port.is_some() && resp.zone_answerer_port.is_some() {
                    return resp;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the daemon must report its listeners on the list reply");
        assert_eq!(
            resp.hostname_proxy_port,
            Some(port),
            "a configured port must be listened on, not re-picked"
        );
        assert_eq!(
            resp.zone_answerer_port,
            Some(answerer_port),
            "the answerer's configured port must be listened on, not re-picked"
        );

        // And it really is a listener there: the proxy answers on the
        // configured port (refusing a name no live box owns, which is its
        // answer for one), and the answerer replies over UDP from the same
        // port the resolver would be pointed at.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            "ghost.min.internal",
        )
        .await;
        assert!(
            routed.contains("502"),
            "the configured port must answer, got: {routed}"
        );

        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = encode_query("ghost.min.internal.", RecordType::A);
        let mut scratch = [0u8; 512];
        let mut reply = None;
        for _ in 0..200 {
            client
                .send_to(
                    &query,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), answerer_port),
                )
                .await
                .unwrap();
            if let Ok(Ok((bytes, _))) =
                tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut scratch))
                    .await
            {
                reply = Some(scratch[..bytes].to_vec());
                break;
            }
        }
        let bytes = reply.expect("the answerer must answer on its configured port");
        let message = Message::from_vec(&bytes).expect("the reply decodes");
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            message.answers.is_empty(),
            "a name no live box owns must answer NXDOMAIN, got: {bytes:?}"
        );

        // And a name a live box owns routes with a 200 through the same
        // configured port — the refusal above only means something once a
        // routed name is proved beside it.
        let backend = spawn_backend_saying("live").await;
        state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .register_host_net(::sessions::SessionId::nil(), "web");
        let authority = format!("web.min.internal:{backend}");
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &authority,
        )
        .await;
        assert!(
            routed.contains("200 OK"),
            "the configured port must route a live name, got: {routed}"
        );

        let logged = buf.contents();
        assert!(
            logged.contains(&format!("port={port}")),
            "the startup line must name the port, got: {logged}"
        );
        assert!(
            logged.contains(r#"port_source="configured""#),
            "the startup line must say the port was configured, got: {logged}"
        );
        run.abort();
    }

    /// NET-025: a daemon started without a configured port takes the
    /// documented default when it is free — and only when something on the
    /// host already holds it asks the OS for a free one, reporting the port it
    /// got. That is what lets a second daemon on the same host keep its names
    /// instead of silently losing routing: it relocates, it does not fail.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_auto_selects_free_port() {
        use std::net::{IpAddr, Ipv4Addr};

        // Hold the documented default so the fallback is observable: the
        // daemon's first bind must fail, its second must land elsewhere.
        let held = TcpListener::bind((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
        ))
        .await
        .ok();

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
        start_host_proxies(&state, false, None, None).await;

        let bound = wait_for_proxy_port(&state).await;
        assert_ne!(bound, 0, "port 0 is a request for a port, not an answer");
        assert_ne!(
            bound,
            crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            "a busy default must not be waited on or taken"
        );
        assert!(
            state.proxy_unavailable().await.is_none(),
            "a relocated default must not report the proxy unavailable"
        );

        // The picked port is a real listener, the relocation is said out
        // loud, and the startup line reports the port as selected.
        let backend = spawn_backend_saying("selected").await;
        state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .register_host_net(::sessions::SessionId::nil(), "web");
        let authority = format!("web.min.internal:{backend}");
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound),
            &authority,
        )
        .await;
        assert!(
            routed.contains("200 OK"),
            "the selected port must route a name, got: {routed}"
        );

        let logged = buf.contents();
        assert!(
            logged.contains("the default hostname-proxy port is busy"),
            "the busy default must be reported as the reason the daemon moved, got: {logged}"
        );
        assert!(
            logged.contains(&format!("port={bound}")),
            "the startup line must name the port, got: {logged}"
        );
        assert!(
            logged.contains(r#"port_source="selected""#),
            "the startup line must say the port was selected, got: {logged}"
        );
        drop(held);
    }

    /// NET-024's hard edge: a daemon *configured* with a port that is busy
    /// keeps retrying it with backoff rather than relocating — the operator
    /// named the port, and moving the listener would hide the loss the
    /// report is there to surface.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_busy_configured_port_is_not_relocated() {
        use std::net::{IpAddr, Ipv4Addr};

        // A free port this test holds for its whole lifetime: the daemon is
        // configured with it, and its bind must fail on it — deterministically,
        // whatever else on the box holds the documented default.
        let held = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let configured = held.local_addr().unwrap().port();

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
        let retrier = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::Pinned(configured),
            },
            false,
            HostExpose::Shuttle,
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // The bind keeps failing on the *same* address — no relocation line,
        // and the note stays, because a pinned port is the operator's to fix.
        let mut saw_two_failures = false;
        for _ in 0..200 {
            if buf
                .contents()
                .matches("could not bind its listener")
                .count()
                >= 2
            {
                saw_two_failures = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            saw_two_failures,
            "a busy configured port must keep failing loudly, got: {}",
            buf.contents()
        );
        assert!(
            !buf.contents().contains("selecting a free one"),
            "a configured port must not be relocated, got: {}",
            buf.contents()
        );
        assert!(
            state.proxy_unavailable().await.is_some(),
            "the busy configured port must stay reported as unavailable"
        );
        retrier.abort();
        drop(held);
    }

    /// NET-025's other edge: only a *busy* address relocates. Any other bind
    /// failure keeps the address it named and retries with backoff (NET-021),
    /// because it is not another daemon holding the port and moving the
    /// listener would hide the report. Driven with an address the host cannot
    /// assign — the shape a half-up or misconfigured interface gives — which
    /// fails with `EADDRNOTAVAIL` under glibc and musl alike, so this also
    /// holds for the musl guest build the busy-port predicate once missed.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_non_busy_bind_failure_keeps_its_address() {
        use std::net::{IpAddr, Ipv4Addr};

        // A free port stands in for the documented default, as in the other
        // retry tests: what fails here is the address, not the port.
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let default_port = probe.local_addr().unwrap().port();
        drop(probe);

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
        let retrier = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                // `192.0.2.1` is TEST-NET-1: no interface holds it, so every
                // bind fails `EADDRNOTAVAIL`, deterministically, root or not.
                bind_base: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: ProxyPort::DefaultThenSelect {
                    default: default_port,
                },
            },
            false,
            HostExpose::Shuttle,
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // At least two failed binds on the *same* address — no relocation
        // line, and the note stays, because the failure is not a busy port.
        let mut saw_two_failures = false;
        for _ in 0..200 {
            if buf
                .contents()
                .matches("could not bind its listener")
                .count()
                >= 2
            {
                saw_two_failures = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let logged = buf.contents();
        assert!(
            saw_two_failures,
            "a non-busy bind failure must keep retrying loudly, got: {logged}"
        );
        assert!(
            !logged.contains("selecting a free one"),
            "a bind failure that is not a busy port must not relocate, got: {logged}"
        );
        assert!(
            logged
                .matches(&format!("addr=192.0.2.1:{default_port}"))
                .count()
                >= 2,
            "the retries must keep the address the report names, got: {logged}"
        );
        assert!(
            state.proxy_unavailable().await.is_some(),
            "the bind failure must stay reported as unavailable"
        );
        assert!(
            state.hostname_proxy_port().await.is_none(),
            "a proxy that never bound must not report serving"
        );
        retrier.abort();
    }

    /// NET-027's publish half: a guest-chosen port the host *could not
    /// take* is released and a fresh one picked, not retried forever — two
    /// VMs on one host whose ports collide at the host's loopback are
    /// exactly the case the re-pick resolves. The refusal is driven through
    /// a fixed publish answer (`port_taken`), because the transient half of
    /// the publish's failure space — the arm that must not re-pick — is the
    /// next test's subject and needs the real path.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_refused_host_publish_picks_a_fresh_port() {
        use std::net::{IpAddr, Ipv4Addr};

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
        let retrier = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::DefaultThenSelect {
                    default: crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
                },
            },
            // The publish gate is the subject: every attempt here reports a
            // host port some other process holds.
            true,
            HostExpose::Fixed(Some(HostPublishFailure {
                report: "the gvproxy forwarder could not take 127.0.0.1 on the \
                         host: the port is held. Remedy: free the host port, or \
                         configure this daemon onto another"
                    .to_owned(),
                port_taken: true,
            })),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // The re-pick line names the port it gives up on; two of them with
        // different ports means the driver really is relocating, not retrying.
        let mut seen = std::collections::BTreeSet::new();
        let mut relocated = false;
        for _ in 0..400 {
            for port in refused_ports(&buf.contents()) {
                seen.insert(port);
            }
            if seen.len() >= 2 {
                relocated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            relocated,
            "a refused guest-chosen port must be re-picked, not retried; \
             ports refused so far: {seen:?}, log: {}",
            buf.contents()
        );
        assert!(
            state.hostname_proxy_port().await.is_none(),
            "a proxy whose publish keeps failing must not report serving"
        );
        retrier.abort();
    }

    /// NET-025's boot-time edge: a publish that fails for a *transient*
    /// reason — here, nothing answering the shuttle, the exact shape a
    /// daemon that starts before its host gvproxy (minvmd) is ready sees —
    /// must keep the port it bound, the default included, and keep
    /// retrying with backoff (NET-021). Only a host port genuinely taken
    /// re-picks; a transient failure that re-picked would move a VM daemon
    /// off its documented default at every boot race and leave it on a
    /// random port until the daemon restarts.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_transient_publish_failure_keeps_the_default_port() {
        use std::net::{IpAddr, Ipv4Addr};

        // A free port stands in for the documented default: a test cannot
        // hold the real one without racing every parallel process that
        // binds it (nextest runs one per test).
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let default_port = probe.local_addr().unwrap().port();
        drop(probe);

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
        tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::DefaultThenSelect {
                    default: default_port,
                },
            },
            // The publish gate rides the real shuttle path: with no host
            // gvproxy answering it, every attempt fails transiently — never
            // with a host port taken.
            true,
            HostExpose::Shuttle,
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // At least two failed publishes, each with the retry warning and
        // none with a re-pick.
        let mut saw_two_failures = false;
        for _ in 0..600 {
            if buf
                .contents()
                .matches("could not publish on the host loopback")
                .count()
                >= 2
            {
                saw_two_failures = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            saw_two_failures,
            "the transient publish failure must keep retrying, got: {}",
            buf.contents()
        );
        let logged = buf.contents();
        assert!(
            !logged.contains("will pick a fresh port"),
            "a transient publish failure must keep the port it bound, got: {logged}"
        );

        // The port it keeps is the one it named: the listener is bound and
        // serving behind the still-failing publish — exactly the state a VM
        // daemon is in while its host gvproxy comes up.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), default_port),
            "ghost.min.internal",
        )
        .await;
        assert!(
            routed.contains("502"),
            "the kept port must answer while the publish retries, got: {routed}"
        );
        assert!(
            state.proxy_unavailable().await.is_some(),
            "the publish failure must be reported as the unavailable note"
        );
        assert!(
            state.hostname_proxy_port().await.is_none(),
            "a proxy whose publish keeps failing must not report serving"
        );
    }

    /// Serves one gvproxy-shaped control channel at `path`: every request is
    /// read to its end-of-head marker and answered with `status` and `body`,
    /// the connection held open the way the real forwarder holds its
    /// keep-alive exchange (see `net::policy::post_json`).
    #[cfg(target_os = "linux")]
    async fn spawn_control_channel_answering(
        path: std::path::PathBuf,
        status: &'static str,
        body: &'static str,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    // `sock` stays alive to the end of this task only; the
                    // client reads its Content-Length and closes first.
                });
            }
        });
    }

    /// The publish classifier's *taken* arm: a forwarder that answers and
    /// refuses — it could not take the host-side port, which on this endpoint
    /// is a host port some other process holds — is the one publish failure a
    /// guest-chosen port re-picks from. Driven over a unix control channel
    /// standing in for the shuttle, answering with the HTTP error status
    /// `post_json` folds into an io::Error, so the arm is reached without a
    /// host gvproxy to answer.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_forwarder_refusal_classifies_the_host_port_as_taken() {
        let dir = TempDir::new().unwrap();
        let control = dir.path().join("gvproxy.sock");
        spawn_control_channel_answering(control.clone(), "409 Conflict", "port already in use")
            .await;

        let failure = publish_listener_on_control(
            &crate::net::policy::ControlChannel::Unix(control),
            std::net::Ipv4Addr::new(100, 64, 0, 2),
            7654,
            "tcp",
        )
        .await
        .expect("a refused publish must report a failure");

        assert!(
            failure.port_taken,
            "a forwarder that answered and refused has taken the host port, got: {}",
            failure.report
        );
        assert!(
            failure.report.contains("returned HTTP 409"),
            "the taken arm's report must name the status the forwarder answered with, got: {}",
            failure.report
        );
        assert!(
            failure.report.contains("Remedy:"),
            "the report must carry the remedy, got: {}",
            failure.report
        );
    }

    /// The publish classifier's *transient* arm: a forwarder that never
    /// answered — here, nothing listening where the control channel points,
    /// the exact shape a daemon that starts before its host gvproxy (minvmd)
    /// sees — says nothing about the host port, so it must not read as taken:
    /// a transient failure that re-picked would move a VM daemon off its
    /// documented default at every boot race.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_unreachable_forwarder_classifies_the_failure_as_transient() {
        let dir = TempDir::new().unwrap();
        // Nothing binds this path: the control channel points where no
        // forwarder is.
        let control = dir.path().join("absent.sock");

        let failure = publish_listener_on_control(
            &crate::net::policy::ControlChannel::Unix(control),
            std::net::Ipv4Addr::new(100, 64, 0, 2),
            7654,
            "tcp",
        )
        .await
        .expect("a failed publish must report a failure");

        assert!(
            !failure.port_taken,
            "a forwarder that never answered has not taken the host port, got: {}",
            failure.report
        );
        assert!(
            !failure.report.contains("returned HTTP"),
            "a failure that never got an answer must not be classified as a refusal, got: {}",
            failure.report
        );
        assert!(
            failure.report.contains("could not publish port 7654"),
            "the report must name the port and the failure, got: {}",
            failure.report
        );
    }

    /// The ports named by the re-pick warnings in `log` — the ones the driver
    /// released because the host refused to publish them.
    #[cfg(target_os = "linux")]
    fn refused_ports(log: &str) -> Vec<u16> {
        log.lines()
            .filter(|line| line.contains("will pick a fresh port"))
            .filter_map(|line| {
                let idx = line.find("port=")?;
                line[idx + "port=".len()..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|digits| digits.parse().ok())
            })
            .collect()
    }

    /// NET-002 beside NET-027: the registry a daemon builds — through its
    /// generated instance id, the way [`crate::ServerState::new`] builds it —
    /// still answers the `local` zone every daemon promised before instance
    /// ids existed, beside its own instance's zone.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn local_zone_routes_on_an_instance_scoped_registry() {
        use ::sessions::SessionId;

        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();
        let id = state.daemon_id().await;
        assert_ne!(
            id, "local",
            "a daemon's instance id is its own, not the shared label"
        );

        let registry = state.sessions_manager().await.hostnames();
        registry
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "web");

        // The two-label name, the instance's own three-label zone, and the
        // `local` zone a pre-instance name lives in all route; another
        // daemon's zone does not, and neither does an unknown session under
        // any of them.
        let read = registry.read().unwrap();
        assert!(read.resolve("web.min.internal:8080").is_some());
        assert!(
            read.resolve(&format!("web.{id}.min.internal:8080"))
                .is_some()
        );
        assert!(
            read.resolve("web.local.min.internal:8080").is_some(),
            "the local zone must keep routing on every daemon"
        );
        assert!(read.resolve("ghost.local.min.internal:8080").is_none());
        assert!(read.resolve("ghost.min.internal:8080").is_none());
    }

    /// NET-027: two daemons on one machine route both sets of names at the
    /// same time — including, each, the `local` zone NET-002 promised (which
    /// is a per-daemon zone now, answered from that daemon's own
    /// registration). The daemons are shaped the way two on one host really
    /// are: VM hosts (`in_microvm`), each box published on its own address,
    /// so both publish the **same** port and carry the **same** Host header —
    /// the only things that pick a backend are the name and which daemon's
    /// proxy the request goes through.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_daemons_route_hostnames_concurrently() {
        use std::collections::BTreeMap;
        use std::net::{IpAddr, Ipv4Addr};

        use ::sessions::SessionId;

        // `in_microvm` is what makes a daemon's registry route an own-IP box
        // to its reported address (a lease on the switch) rather than to the
        // one loopback address every native box would share — the shape two
        // daemons must take to publish the same port at the same time.
        let vm_host = |dir: &TempDir| Config {
            in_microvm: true,
            ..test_config(dir)
        };
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let a = ServerStateHandle::new(vm_host(&dir_a), None).await.unwrap();
        let b = ServerStateHandle::new(vm_host(&dir_b), None).await.unwrap();

        // Two daemon instances: distinct ids, or the names they mint below
        // would not be distinct either.
        let id_a = a.daemon_id().await;
        let id_b = b.daemon_id().await;
        assert_ne!(id_a, id_b, "two daemon instances must mint two host ids");

        // Neither daemon was configured with a port, so each drives its own
        // startup and ends up on its own.
        let auto = || SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let compressed = RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20));
        let (_, _) = tokio::join!(
            retry_hostname_proxy_until_serving(a.clone(), auto(), compressed),
            retry_hostname_proxy_until_serving(b.clone(), auto(), compressed),
        );
        let port_a = wait_for_proxy_port(&a).await;
        let port_b = wait_for_proxy_port(&b).await;
        assert_ne!(port_a, port_b, "two daemons must not land on one port");

        // Each daemon's `web` box, published at its own address on the same
        // port — the two "leases" the attach path would report. The external
        // port is 80 (a `Host:` header with no port routes as 80) and both
        // publish the same one: which box answers is decided by the name and
        // the proxy alone.
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let published = probe.local_addr().unwrap().port();
        drop(probe);
        let lease_a = Ipv4Addr::new(127, 0, 0, 1);
        let lease_b = Ipv4Addr::new(127, 0, 0, 2);
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_a), published), "daemon-a").await;
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_b), published), "daemon-b").await;

        let registry_a = a.sessions_manager().await.hostnames();
        let registry_b = b.sessions_manager().await.hostnames();
        registry_a.write().unwrap().report_own_address(
            SessionId::nil(),
            "web",
            lease_a,
            BTreeMap::from([(80, published)]),
        );
        registry_b.write().unwrap().report_own_address(
            SessionId::nil(),
            "web",
            lease_b,
            BTreeMap::from([(80, published)]),
        );

        // The two daemons' registries do not see each other's instance
        // zones — each answers its own instance's three-label form (and the
        // shared two-label and `local` forms, each from its own
        // registration), and not the other daemon's.
        let own_a = format!("web.{id_a}.min.internal");
        let own_b = format!("web.{id_b}.min.internal");
        assert!(
            registry_a.read().unwrap().resolve(&own_a).is_some(),
            "daemon A must answer its own instance's name"
        );
        assert!(
            registry_a.read().unwrap().resolve(&own_b).is_none(),
            "daemon A must not answer daemon B's name"
        );
        assert!(
            registry_b.read().unwrap().resolve(&own_b).is_some(),
            "daemon B must answer its own instance's name"
        );
        assert!(
            registry_b.read().unwrap().resolve(&own_a).is_none(),
            "daemon B must not answer daemon A's name"
        );

        // Both sets of names route at the same time, decided by the Host
        // header alone: the same authority through each daemon's proxy
        // reaches that daemon's own box, concurrently — and the deprecated
        // three-label forms (instance's own, and `local`) route to it too,
        // while the *other* daemon's instance form is refused with a 502
        // (the proxy serves it: "no live box owns this host").
        let proxy_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
        let proxy_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
        let (a_two_label, a_local, a_own, a_foreign, b_two_label, b_local, b_own, b_foreign) = tokio::join!(
            proxy_get(proxy_a, "web.min.internal"),
            proxy_get(proxy_a, "web.local.min.internal"),
            proxy_get(proxy_a, &own_a),
            proxy_get(proxy_a, &own_b),
            proxy_get(proxy_b, "web.min.internal"),
            proxy_get(proxy_b, "web.local.min.internal"),
            proxy_get(proxy_b, &own_b),
            proxy_get(proxy_b, &own_a),
        );
        assert!(a_two_label.contains("daemon-a"), "got: {a_two_label}");
        assert!(a_local.contains("daemon-a"), "got: {a_local}");
        assert!(a_own.contains("daemon-a"), "got: {a_own}");
        assert!(b_two_label.contains("daemon-b"), "got: {b_two_label}");
        assert!(b_local.contains("daemon-b"), "got: {b_local}");
        assert!(b_own.contains("daemon-b"), "got: {b_own}");
        assert!(
            a_foreign.contains("502"),
            "daemon A must refuse daemon B's instance name, got: {a_foreign}"
        );
        assert!(
            b_foreign.contains("502"),
            "daemon B must refuse daemon A's instance name, got: {b_foreign}"
        );
    }

    /// NET-027: two daemons on one machine draw their published boxes from
    /// their own slices of the reserved local range — a shared slice is a
    /// shared address space, the collision that has one daemon's published
    /// box answer a name the other daemon routed. Each daemon's slice is
    /// keyed to its own octet — configured onto two daemons here, derived
    /// from the instance id on a third — which on a native host is also the
    /// /24 its own gvproxy runs on, and each names the slice it draws from
    /// on its own start line, where a reader of two daemons' logs can
    /// compare the two.
    ///
    /// The comparison is honest about the wrap-around
    /// `LoopbackAllocator::for_slice_octet` names: octets congruent
    /// modulo the reserved range's slice count index one shared slice, so
    /// disjointness holds only between incongruent octets. The
    /// pinned pair (37/52) sits incongruent on purpose; the wrap's both arms
    /// are pinned below with ids chosen for their derived octets, and the
    /// deriving daemon's relation to the pinned pair follows the same
    /// predicate, not a promise of disjointness its random id cannot keep.
    ///
    /// The `in_microvm: true` pair is the primary case for exactly this
    /// keying: a VM daemon does not own its switch — its boxes tap the host
    /// gvproxy, on the default /16 every VM on the host shares — so a slice
    /// keyed on the switch *subnet* would put every VM on the machine on one
    /// slice. Keyed on the octet, the two VM daemons here hold the same two
    /// slices as their native twins on the same octets.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_daemons_draw_disjoint_loopback_slices() {
        use std::net::Ipv4Addr;

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // Two daemons pinned onto different /24s of the host switch, through
        // `Server::run` the way a deployment starts them.
        let dir_a = TempDir::new().unwrap();
        let (run_a, _sock_a) = spawn_server_with(
            &dir_a,
            Config {
                switch_subnet_octet: Some(37),
                ..test_config(&dir_a)
            },
        );
        let dir_b = TempDir::new().unwrap();
        let (run_b, _sock_b) = spawn_server_with(
            &dir_b,
            Config {
                switch_subnet_octet: Some(52),
                ..test_config(&dir_b)
            },
        );
        // And one that derives its /24 from its instance id — the default
        // path every unpinned daemon takes. Its state is held so the test can
        // name which start line is its own.
        let dir_c = TempDir::new().unwrap();
        let (state_c, run_c, _sock_c) = spawn_stateful_server_with(
            &dir_c,
            Config {
                switch_subnet_octet: None,
                ..test_config(&dir_c)
            },
        )
        .await;
        // Two VM daemons on the same octets as the native pair above: the
        // switch they attach to is the host's, so only the octet can tell
        // their slices apart. Built as `two_daemons_route_hostnames_concurrently`
        // builds its pair — the state alone, which is what logs the start
        // line.
        let vm_host = |dir: &TempDir, octet: Option<u8>| Config {
            in_microvm: true,
            switch_subnet_octet: octet,
            ..test_config(dir)
        };
        let dir_d = TempDir::new().unwrap();
        let state_d = ServerStateHandle::new(vm_host(&dir_d, Some(37)), None)
            .await
            .unwrap();
        let dir_e = TempDir::new().unwrap();
        let state_e = ServerStateHandle::new(vm_host(&dir_e, Some(52)), None)
            .await
            .unwrap();

        // The start lines are logged as each daemon comes up; wait for all
        // five before reading the slice back out of them.
        let logged = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let logged = buf.contents();
                if logged.matches("loopback_slice=").count() >= 5 {
                    return logged;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all five daemons must log the slice they draw from");

        // Each daemon's start line, found by the field that identifies the
        // daemon: the configured /24 for the two pinned ones, the instance id
        // for the deriving one.
        let id_c = state_c.daemon_id().await;
        let id_d = state_d.daemon_id().await;
        let id_e = state_e.daemon_id().await;
        let line_of = |marker: &str| {
            logged
                .lines()
                .find(|line| line.contains(marker) && line.contains("loopback_slice="))
                .unwrap_or_else(|| panic!("no start line carrying {marker}, got: {logged}"))
                .to_owned()
        };
        let line_a = line_of("subnet=100.64.37.0/24");
        let line_b = line_of("subnet=100.64.52.0/24");
        let line_c = line_of(&format!("daemon_id={id_c}"));
        let line_d = line_of(&format!("daemon_id={id_d}"));
        let line_e = line_of(&format!("daemon_id={id_e}"));

        // The `loopback_slice=` field is the first and last address of the
        // slice the daemon's published boxes come from.
        let slice_of = |line: &str| {
            let field = line
                .split_whitespace()
                .find(|f| f.starts_with("loopback_slice="))
                .unwrap_or_else(|| panic!("no loopback_slice field on {line}"))
                .strip_prefix("loopback_slice=")
                .unwrap();
            let (first, last) = field
                .split_once('-')
                .unwrap_or_else(|| panic!("loopback_slice is not a range: {field}"));
            (
                first
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| panic!("not an address: {first}")),
                last.parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| panic!("not an address: {last}")),
            )
        };
        let slice_a = slice_of(&line_a);
        let slice_b = slice_of(&line_b);
        let slice_c = slice_of(&line_c);
        let slice_d = slice_of(&line_d);
        let slice_e = slice_of(&line_e);

        // Octet 37 indexes slice 5 of the /24, octet 52 slice 4: two pinned
        // daemons announce two disjoint slices, not one shared start.
        assert_eq!(
            slice_a,
            (
                Ipv4Addr::new(127, 64, 0, 160),
                Ipv4Addr::new(127, 64, 0, 191)
            ),
            "a daemon on 100.64.37.0/24 must draw from that /24's slice"
        );
        assert_eq!(
            slice_b,
            (
                Ipv4Addr::new(127, 64, 0, 128),
                Ipv4Addr::new(127, 64, 0, 159)
            ),
            "a daemon on 100.64.52.0/24 must draw from that /24's slice"
        );
        assert!(
            slice_a.1 < slice_b.0 || slice_b.1 < slice_a.0,
            "two daemons' slices must be disjoint, got {slice_a:?} and {slice_b:?}"
        );

        // The deriving daemon's slice is exactly the one its own instance id
        // derives: the same id names the same /24 and the same slice, start
        // after start.
        let octet_c = octet_for_daemon_id(&id_c);
        assert_eq!(
            slice_c,
            sessions::LoopbackAllocator::for_slice_octet(octet_c).range(),
            "an unpinned daemon's slice must follow its derived octet"
        );

        // ...and its relation to the pinned pair is the wrap predicate, not a
        // promise of disjointness a random id cannot keep: disjoint from
        // every pinned octet its derived octet is incongruent to modulo the
        // reserved range's slice count, and equal to the one (if any) it is
        // congruent to — the wrap `LoopbackAllocator::for_slice_octet`
        // documents, walked here against a live daemon's own start line.
        for (pinned_name, pinned_octet, pinned_slice) in
            [("A", 37u8, slice_a), ("B", 52u8, slice_b)]
        {
            if u32::from(octet_c) % sessions::LOOPBACK_SLICES
                == u32::from(pinned_octet) % sessions::LOOPBACK_SLICES
            {
                assert_eq!(
                    slice_c, pinned_slice,
                    "the deriving daemon's octet {octet_c} is congruent to \
                     pinned daemon {pinned_name}'s {pinned_octet} modulo the \
                     slice count: the two share one slice — the wrap the docs \
                     name, which NET-010's allocation arbitrates"
                );
            } else {
                assert!(
                    slice_c.1 < pinned_slice.0 || pinned_slice.1 < slice_c.0,
                    "the deriving daemon's slice must be disjoint from pinned \
                     daemon {pinned_name}'s, got {slice_c:?} and {pinned_slice:?}"
                );
            }
        }

        // The VM pair keeps the host's switch — both start lines carry the
        // default /16, which no native daemon's does — and still draws from
        // the octet each was pinned to: the same slices as their native
        // twins, and *not* the one slice the shared switch's own third octet
        // (0) would index, which is what every VM on the host would have
        // announced when the slice followed the switch subnet.
        for line in [&line_d, &line_e] {
            assert!(
                line.contains("subnet=100.64.0.0/16"),
                "a VM daemon's switch stays on the host's default /16, got: {line}"
            );
        }
        assert_eq!(
            slice_d, slice_a,
            "a VM daemon pinned to octet 37 draws from that octet's slice, \
             not its switch's"
        );
        assert_eq!(
            slice_e, slice_b,
            "a VM daemon pinned to octet 52 draws from that octet's slice, \
             not its switch's"
        );
        let switch_shared_slice = sessions::LoopbackAllocator::for_slice_octet(0).range();
        assert_ne!(
            slice_d, switch_shared_slice,
            "two VM daemons must not share one slice of the reserved local range"
        );
        assert!(
            slice_d.1 < slice_e.0 || slice_e.1 < slice_d.0,
            "the two VM daemons' slices must be disjoint, got {slice_d:?} and {slice_e:?}"
        );

        // The wrap-around's both arms, pinned with ids chosen for their
        // derived octets rather than a live daemon's random one — the wrap is
        // a property of the octet arithmetic, so any id space reaches it;
        // here a fixed one, so the two pairs are stable whichever ids the
        // search finds. Searched, not hardcoded, so a re-keyed derivation
        // still yields a pair for each arm.
        let mut congruent = None;
        let mut incongruent = None;
        'ids: for i in 0..64u32 {
            for j in (i + 1)..64u32 {
                let (octet_i, octet_j) = (
                    octet_for_daemon_id(&i.to_string()),
                    octet_for_daemon_id(&j.to_string()),
                );
                if octet_i == octet_j {
                    // Two ids hashing to one octet is the id-collision case
                    // `octet_for_daemon_id`'s doc names — not the wrap.
                    continue;
                }
                if u32::from(octet_i) % sessions::LOOPBACK_SLICES
                    == u32::from(octet_j) % sessions::LOOPBACK_SLICES
                {
                    congruent.get_or_insert((i, octet_i, j, octet_j));
                } else {
                    incongruent.get_or_insert((i, octet_i, j, octet_j));
                }
                if congruent.is_some() && incongruent.is_some() {
                    break 'ids;
                }
            }
        }
        let (id_wa, octet_wa, id_wb, octet_wb) =
            congruent.expect("64 ids must derive one octet pair congruent mod 8");
        assert_eq!(
            sessions::LoopbackAllocator::for_slice_octet(octet_wa).range(),
            sessions::LoopbackAllocator::for_slice_octet(octet_wb).range(),
            "ids {id_wa} and {id_wb} derive octets {octet_wa} and {octet_wb}, \
             congruent modulo the slice count: two daemons that derived them \
             share one slice — the wrap the docs and the start line name, \
             which NET-010's allocation arbitrates"
        );
        let (id_ia, octet_ia, id_ib, octet_ib) =
            incongruent.expect("64 ids must derive one incongruent octet pair");
        let (first_ia, last_ia) = sessions::LoopbackAllocator::for_slice_octet(octet_ia).range();
        let (first_ib, last_ib) = sessions::LoopbackAllocator::for_slice_octet(octet_ib).range();
        assert!(
            last_ia < first_ib || last_ib < first_ia,
            "ids {id_ia} and {id_ib} derive octets {octet_ia} and {octet_ib}, \
             incongruent modulo the slice count: two daemons that derived \
             them must draw from disjoint slices, got {first_ia}..={last_ia} \
             and {first_ib}..={last_ib}"
        );

        run_a.abort();
        run_b.abort();
        run_c.abort();
    }

    /// NET-027: the /24 a daemon's id derives is stable — the same id names
    /// the same /24 start after start — and distinct ids name distinct ones
    /// often enough that two daemons on a host do not meet on one /24 by
    /// accident. Every derived octet stays inside the `100.64/16`: never
    /// the `0` of the /16's own gateway /24 nor the `255` of its host-alias
    /// and daemon-address /24, which the host switch keeps for itself.
    #[cfg(target_os = "linux")]
    #[test]
    fn derived_switch_octets_are_stable_and_in_range() {
        assert_eq!(octet_for_daemon_id("abc12"), 21);
        assert_eq!(
            octet_for_daemon_id("abc12"),
            21,
            "derivation must be stable"
        );
        assert_ne!(
            octet_for_daemon_id("abc12"),
            octet_for_daemon_id("abc13"),
            "near ids must not collapse onto one /24"
        );
        for id in ["aaaaa", "abc12", "abc13", "x9y8z", "zzzzz"] {
            let octet = octet_for_daemon_id(id);
            assert!(
                (1..=254).contains(&octet),
                "{id} derived {octet}, which is outside 1..=254"
            );
        }
    }

    /// NET-027: a configured third octet places the daemon's switch /24
    /// inside the host gvproxy's `100.64/16`, where its leases stay valid
    /// beside the host's own gateway, host-alias, and PTask reservations.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_configured_octet_places_the_switch_inside_the_host_s_16() {
        let subnet = switch_subnet_for_octet(200);
        assert_eq!(subnet.to_string(), "100.64.200.0/24");
        let octets = subnet.network().octets();
        assert_eq!(&octets[..2], &[100, 64], "the /24 must stay in 100.64/16");
        assert_eq!(octets[3], 0, "a /24's network address ends in 0");
    }

    /// The other half of the ownership rule [`switch_subnet_for`] states —
    /// the half the macOS e2e caught: a daemon in a microVM does not own its
    /// gvproxy (it attaches its boxes' taps to the one `minvmd` runs on the
    /// host, whose config renders the default /16), so the guest must carry
    /// that switch's subnet, never derive a /24 of its own. Every address a
    /// guest daemon derives from its switch must be one that switch answers
    /// at: the gateway is where a box's default route and DNS server live
    /// (a host-address box's resolver is the switch's DNS server, an
    /// own-IP box's tap carries the subnet's gateway and netmask), and a
    /// derived /24's gateway — `100.64.<octet>.1` — is an address no
    /// gvproxy answers, so every box in the VM lost egress, DNS first.
    /// Read off the daemon's own start line, which names the subnet its
    /// switch carries, with an octet pinned to show the pin cannot move a
    /// switch the guest does not own — while its slice still follows that
    /// octet, which is the daemon's own state and not the switch's.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_microvm_daemon_attaches_to_the_host_switch_s_own_subnet() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(
            Config {
                in_microvm: true,
                switch_subnet_octet: Some(37),
                ..test_config(&dir)
            },
            None,
        )
        .await
        .unwrap();

        let id = state.daemon_id().await;
        let logged = buf.contents();
        let line = logged
            .lines()
            .find(|l| l.contains("loopback_slice=") && l.contains(&format!("daemon_id={id}")))
            .unwrap_or_else(|| panic!("no start line for daemon {id}, got: {logged}"));
        assert!(
            line.contains("subnet=100.64.0.0/16"),
            "a microVM daemon must carry the host gvproxy's /16, got: {line}"
        );

        // The mapping's native arms beside it: a native daemon honors the
        // pin — it renders its own gvproxy's config — and an unpinned one
        // derives its /24 from its instance id (NET-027).
        assert_eq!(
            switch_subnet_for(false, 37).to_string(),
            "100.64.37.0/24",
            "a pinned native daemon owns its switch and takes the pinned /24"
        );
        assert_eq!(
            switch_subnet_for(false, octet_for_daemon_id(&id)),
            switch_subnet_for_octet(octet_for_daemon_id(&id)),
            "an unpinned native daemon derives its own /24"
        );
        // The octet the microVM daemon was pinned to does not reach its
        // switch, but it is still its own: the slice it draws from is keyed
        // on the octet, not the subnet (NET-027's address half).
        assert!(
            line.contains("loopback_slice=127.64.0.160-127.64.0.191"),
            "a microVM daemon pinned to octet 37 draws from that octet's \
             slice, not its switch's, got: {line}"
        );
        // And the address that broke the e2e follows: the /16's gateway is
        // where the host gvproxy answers DNS, and a native /24's is inside
        // the /16's span but is no switch's address.
        assert_eq!(
            crate::net::DEFAULT_SUBNET.dns_server().to_string(),
            "100.64.0.1",
            "the host switch's /16 answers DNS at its own gateway"
        );
    }

    /// The box-zone answerer starts beside the hostname proxy and serves the
    /// zone on loopback (NET-009): `drive_answerer_until_serving` binds the
    /// address, the log names the listener's address and port at start, and a
    /// real UDP exchange over the bound socket answers a box name with its
    /// local address.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn answerer_starts_and_serves_the_zone_on_loopback() {
        use std::net::{IpAddr, Ipv4Addr};

        use ::sessions::SessionId;
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, RecordType};

        use crate::net::answerer::{AnswerScope, ZoneAnswerer, encode_query};

        // A free port, handed to the driver the way startup hands it a fixed
        // one: bound and dropped, uncontended in a test binary.
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

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
        let hostnames = state.sessions_manager().await.hostnames();
        hostnames
            .write()
            .expect("registry lock")
            .register_host_net(SessionId::nil(), "web");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let answerer = ZoneAnswerer::new(hostnames, AnswerScope::Native);
        tokio::spawn(drive_answerer_until_serving(
            state.clone(),
            answerer,
            addr.ip(),
            ProxyPort::Pinned(port),
            false,
            HostExpose::Shuttle,
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        // Poll until the driver's bind lands, then do one real exchange.
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = encode_query("web.min.internal.", RecordType::A);
        let mut scratch = [0u8; 512];
        let mut reply = None;
        for _ in 0..200 {
            client.send_to(&query, addr).await.unwrap();
            if let Ok(Ok((bytes, _))) =
                tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut scratch))
                    .await
            {
                reply = Some(scratch[..bytes].to_vec());
                break;
            }
        }
        let bytes = reply.expect("the answerer must answer once the driver binds it");
        let reply = Message::from_vec(&bytes).expect("the reply decodes");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        let [answer] = &reply.answers[..] else {
            panic!("an A lookup on a held name answers once")
        };
        let RData::A(A(address)) = &answer.data else {
            panic!("the answer is an A record")
        };
        assert_eq!(*address, Ipv4Addr::LOCALHOST);

        // The daemon log names the answerer's listener address and port, the
        // state records the port for the discovery replies to carry, and the
        // serving line says who chose it.
        let logged = buf.contents();
        assert!(
            logged.contains("zone-answerer") && logged.contains(&format!("{addr}")),
            "the answerer's start must name its listener, got: {logged}"
        );
        assert!(
            logged.contains(r#"port_source="configured""#),
            "the answerer's serving line must name its port source, got: {logged}"
        );
        let reported = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if state.zone_answerer_port().await == Some(port) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            reported.is_ok(),
            "the answerer's bound port must be recorded on the state, got: {logged}"
        );
    }

    /// The answerer shares the hostname proxy's port policy (NET-025): a
    /// busy default is relocated — loudly — rather than failed, and the
    /// relocated port is the one the discovery field reports as selected.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn answerer_relocates_when_its_default_port_is_busy() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::net::answerer::{ANSWERER_PORT, AnswerScope, ZoneAnswerer};

        // Hold the answerer's documented default (UDP) for the whole test.
        // `.ok()`, not `unwrap`: the `Server::run` tests beside this one bind
        // the real defaults too, and nextest runs each test in its own
        // process, so another process may already hold it. Either holder
        // produces the same relocation; nothing here needs *this* process to
        // be the one holding it.
        let held = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, ANSWERER_PORT)).ok();

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
        let hostnames = state.sessions_manager().await.hostnames();
        let answerer = ZoneAnswerer::new(hostnames, AnswerScope::Native);
        tokio::spawn(drive_answerer_until_serving(
            state.clone(),
            answerer,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ProxyPort::DefaultThenSelect {
                default: ANSWERER_PORT,
            },
            false,
            HostExpose::Shuttle,
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        ));

        let reported = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(port) = state.zone_answerer_port().await {
                    return port;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the answerer must relocate and report its port");
        assert_ne!(
            reported, ANSWERER_PORT,
            "a busy default must not be waited on or taken"
        );

        let logged = buf.contents();
        assert!(
            logged.contains("the default zone-answerer port is busy"),
            "the busy default must be reported as the reason the answerer moved, got: {logged}"
        );
        assert!(
            logged.contains(r#"port_source="selected""#),
            "the serving line must say the port was selected, got: {logged}"
        );
        drop(held);
    }
}
