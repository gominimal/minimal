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

/// File name under the daemon's per-instance directory
/// ([`Config::daemon_identity_dir`]) that holds the stable identity from
/// which the switch octet is derived. Written once on first start and read on
/// every subsequent start, so the daemon's /24 stays the same across
/// restarts. Keyed per instance, so each `--instance-num` on one state root
/// hashes its own identity and keeps its own /24 whatever order the
/// instances start in.
const DAEMON_IDENTITY_FILE: &str = "daemon-identity";

/// Runtime directory for per-octet switch locks: the per-user
/// `XDG_RUNTIME_DIR`, else `/run` (writable for root). Each native daemon
/// holds an exclusive lock on `<RUNTIME_DIR>/minimald-switch-<octet>.lock`
/// for its lifetime, so a second daemon that would derive the same octet
/// detects the collision and re-derives. Daemons run by different users see
/// different runtime dirs, so they never see each other's locks.
#[cfg(target_os = "linux")]
fn switch_lock_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            // Fall back to /run on Linux when XDG_RUNTIME_DIR is unset
            // (e.g. under sudo or in a container).
            let run = std::path::PathBuf::from("/run");
            run.is_dir().then_some(run)
        })
}

/// Read the persisted daemon identity from `identity_dir`, or generate and
/// persist a new one. Returns the identity string used for octet derivation.
fn load_or_create_daemon_identity(identity_dir: &DaemonAbsPath) -> std::io::Result<String> {
    let path = identity_dir
        .as_utf8_path()
        .as_std_path()
        .join(DAEMON_IDENTITY_FILE);
    match std::fs::read_to_string(&path) {
        Ok(contents) if !contents.trim().is_empty() => return Ok(contents.trim().to_owned()),
        // An empty file (say, from a crash before the first write landed) is
        // regenerated like a missing one, so it cannot pin every start to the
        // per-start fallback.
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let identity = common::random_alphanumeric(5);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Write a sibling temp file, sync it, and rename it into place, so a
    // crash never leaves a truncated identity behind.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = std::fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut file, identity.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    // Sync the parent so the renamed entry itself survives a power loss.
    // Best effort: the identity is already in place for this start, and a
    // failure here only risks a new identity after a crash.
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
    }
    Ok(identity)
}

/// Try to acquire an exclusive lock for `octet` under `lock_dir`, the
/// runtime directory [`switch_lock_dir`] resolves. Returns `Ok(true)` when
/// the lock was acquired (the octet is free), `Ok(false)` when another daemon
/// holds it, and `Err` on I/O errors.
#[cfg(target_os = "linux")]
fn try_acquire_switch_octet(
    lock_dir: Option<&std::path::Path>,
    octet: u8,
) -> std::io::Result<bool> {
    let Some(dir) = lock_dir else {
        // No runtime directory available — can't detect overlaps, but
        // the daemon can still start.
        return Ok(true);
    };
    let _ = std::fs::create_dir_all(dir);
    let lock_path = dir.join(format!("minimald-switch-{octet}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        // Skip the guard's unlock on drop.
        Ok(guard) => std::mem::forget(guard),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(e) => return Err(e),
    }
    // The flock lives as long as its fd, so leak the file too: dropping it
    // would close the fd and release the lock at once. The lock is held for
    // the daemon's lifetime; the kernel releases it on process death.
    std::mem::forget(lock);
    Ok(true)
}

/// Derive a collision-free switch octet from `identity`. On the first
/// collision, appends a counter to the identity and re-hashes, logging a
/// warning. Gives up after 16 attempts (a hash collision across 16
/// consecutive counters is astronomically unlikely; 16 daemons on one
/// machine is the practical ceiling).
#[cfg(target_os = "linux")]
fn resolve_switch_octet(lock_dir: Option<&std::path::Path>, identity: &str) -> u8 {
    let octet = octet_for_daemon_id(identity);
    match try_acquire_switch_octet(lock_dir, octet) {
        Ok(true) => return octet,
        Ok(false) => {}
        // The lock dir is unusable (say, a non-root daemon falling back to
        // an unwritable /run): no lock can be taken for any octet, so say
        // so once and take the derived octet without collision detection.
        Err(e) => {
            tracing::warn!(
                error = %e,
                octet = octet,
                "switch octet collision detection unavailable: {e}",
            );
            return octet;
        }
    }
    // Collision: another daemon on this machine holds this octet.
    // Re-derive with a counter appended to the identity.
    for n in 1u32..16 {
        let candidate = format!("{identity}-{n}");
        let octet = octet_for_daemon_id(&candidate);
        if try_acquire_switch_octet(lock_dir, octet).unwrap_or(true) {
            tracing::warn!(
                identity = %identity,
                octet = octet,
                attempt = n,
                "switch octet collided with another daemon on this machine; \
                 re-derived to {octet}",
            );
            return octet;
        }
    }
    // Exhausted attempts — take the last octet anyway. The lock file
    // acquisition failed for all 16 attempts, which means either 16+
    // daemons are running or the runtime dir is unwritable. Log and
    // proceed; the answerer's lease record arbitrates published addresses
    // across daemons (NET-010).
    let octet = octet_for_daemon_id(identity);
    tracing::warn!(
        identity = %identity,
        octet = octet,
        "could not acquire a unique switch octet after 16 attempts; \
         proceeding with {octet} — published addresses are still \
         arbitrated by the answerer's lease record (NET-010)",
    );
    octet
}

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
    /// draws its `OwnIp` PTask leases from. `None` (the default) derives the
    /// octet from the daemon identity (persisted under
    /// [`Config::daemon_identity_dir`] when set, else the per-start instance
    /// id), so two daemons on one machine take two different octets and with
    /// them two different switch /24s: their PTask leases can never collide
    /// (NET-027's switch half).
    ///
    /// This octet no longer keys any *published* address: allocation in the
    /// reserved local range is host-global, arbitrated through the answerer's
    /// lease record (NET-010, design §7.1), which two daemons share whatever
    /// their octets are — so no wrap-around octet pair can hand two daemons
    /// one address between them, and pinning the octet pins only where the
    /// switch's leases sit.
    ///
    /// Only a daemon that owns its gvproxy — a native host, DM2 — can honor
    /// this at all: a daemon in a microVM attaches to the host gvproxy
    /// `minvmd` owns, whose config the guest cannot change, so it carries
    /// that switch's default /16 whatever this field says (see
    /// [`switch_subnet_for`]).
    #[serde(default)]
    pub switch_subnet_octet: Option<u8>,
    /// The per-instance directory (`providers/local-minimald<N>`) that holds
    /// the persisted daemon identity an unpinned native daemon derives its
    /// switch octet from (the `daemon-identity` file). `None` persists
    /// nothing and derives the octet from the per-start instance id.
    #[serde(default)]
    pub daemon_identity_dir: Option<DaemonAbsPath>,

    /// The daemon's opt-out of the deny-all egress default (NET-077). While
    /// the default is in force (see [`sessions::EGRESS_DEFAULT_PHASE`]), an
    /// own-address box created with no `egress` section reaches nothing
    /// outside itself (NET-074) and shows `deny all` in `min session policy`
    /// (NET-075). A deployment that cannot carry that in this release opts
    /// out, and its boxes keep the shipped allow-all default of 03-spec
    /// R2.1. Set by `minimald listen --egress-deny-all-opt-out`; a box that
    /// declares its own egress section is unaffected either way.
    #[serde(default)]
    pub deny_all_opt_out: bool,
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
        // live under `<state>/gvproxy/<daemon_id>/`, keyed per daemon instance
        // so two native daemons sharing a state root never unlink each
        // other's control socket or overwrite each other's config or pid
        // file. The shared `Arc` is the single source of truth, injected into
        // every per-launch `SandboxLauncher` through the sessions manager.
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
        // This daemon's switch octet — pinned by the deployment, else derived
        // from the persisted daemon identity on native Linux, or from the
        // per-start instance id in a microVM — names the /24 a switch it owns
        // runs on (a native host, DM2); a microVM daemon carries the host's
        // default /16 whatever this says (see [`switch_subnet_for`]). It names nothing
        // about published addresses: those are granted per host through the
        // answerer's lease record (NET-010, design §7.1), never keyed on the
        // daemon, so two daemons on one host cannot both start at one
        // address and no octet wrap-around can hand them one between them.
        //
        // On native Linux, the octet is derived from an identity persisted
        // in the daemon's instance dir (created once, reused on every start)
        // so the daemon's /24 — and with it every own-address box's switch
        // address and the host alias — stays fixed across restarts. A
        // per-octet lock in the runtime dir detects collisions with another
        // daemon on the same host and re-derives with a logged warning.
        let slice_octet = config.switch_subnet_octet.unwrap_or_else(|| {
            native_switch_octet(
                config.in_microvm,
                config.daemon_identity_dir.as_ref(),
                &daemon_id,
            )
        });
        // The subnet this daemon's switch carries — decided by who owns the
        // gvproxy it attaches to; see [`switch_subnet_for`].
        let switch_subnet = switch_subnet_for(config.in_microvm, slice_octet);
        // The port the hostname proxy's first bind asks for — the configured
        // (in a microVM, the host-handed) port, or the documented default —
        // is the node address's interim opening in every box's own-address
        // set (design §7.1). The OS-picks `0` names no port, so no opening.
        // An OS-picked port the bind lands on instead is not opened; the
        // proxy warns when it serves there (see gominimal/minimal#1952).
        #[cfg(target_os = "linux")]
        let hostname_proxy_port = ProxyPort::from_config(
            config.hostname_proxy_port,
            crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
        )
        .opening_port();
        #[cfg(not(target_os = "linux"))]
        let hostname_proxy_port = None;
        let net_switch = Arc::new(Mutex::new(
            crate::net::SwitchClient::with_subnet(
                config.gvproxy_bin_path(),
                minimal_state_dir
                    .as_utf8_path()
                    .join("gvproxy")
                    .join(&daemon_id),
                switch_subnet,
            )
            .with_transport(transport)
            // This switch belongs to *this* daemon instance: its `OwnIp`
            // DNS registrations carry the instance id as their host label,
            // so a second daemon on the same host registers its own names
            // instead of overwriting the first's records (NET-027).
            .with_host_id(daemon_id.clone())
            .with_hostname_proxy_port(hostname_proxy_port),
        ));
        // One line at daemon start naming the switch subnet this instance's
        // boxes lease on and the pool its published addresses are granted
        // from — the facts a reader of two daemons' logs (a diagnostics
        // bundle tails exactly this log) compares: the reserved local range
        // is the one pool every daemon on this host is granted through, the
        // answerer's lease record arbitrating (NET-010), so two daemons'
        // lines carry the *same* pool by design — what distinguishes them is
        // the switch, and their grants, not their ranges.
        tracing::info!(
            daemon_id = %daemon_id,
            subnet = %switch_subnet,
            slice_octet = slice_octet,
            reserved_loopback = %format!(
                "{first}-{last}",
                first = ::sessions::core::loopback::POOL_FIRST,
                last = ::sessions::core::loopback::POOL_LAST
            ),
            "gvproxy switch this daemon's boxes lease on; published boxes \
             are granted from this host's reserved local range"
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
                // Threaded into every session actor so the launcher and the
                // task path resolve the same effective egress the daemon
                // was started with (NET-074/NET-077).
                config.deny_all_opt_out,
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
/// two different /24s and with them two disjoint `OwnIp` PTask-lease ranges
/// (NET-027). Their *published* addresses share one pool however their
/// octets fall: the reserved local range is granted per host through the
/// answerer's lease record (NET-010), never keyed on the daemon's octet.
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
/// the guest cannot move a switch it does not own onto another.
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

/// The switch octet an unpinned daemon derives. On native Linux this is the
/// stable, collision-checked path: the octet comes from an identity persisted
/// in `identity_dir` (so restarts keep the same /24) and a per-octet lock
/// detects another daemon on the same host holding the same block,
/// re-deriving with a logged warning. A microVM daemon does not own
/// its switch, so it never persists an identity or takes a lock — it carries
/// the host's default /16 whatever octet this returns (see
/// [`switch_subnet_for`]). With no `identity_dir`, nothing is persisted or
/// locked and the octet comes from the per-start id.
fn native_switch_octet(
    in_microvm: bool,
    identity_dir: Option<&DaemonAbsPath>,
    daemon_id: &str,
) -> u8 {
    #[cfg(target_os = "linux")]
    {
        let Some(identity_dir) = identity_dir.filter(|_| !in_microvm) else {
            // A guest does not own its switch, so the octet is irrelevant to
            // the /16 it carries; and with no identity dir there is nothing
            // to persist. Derive from the per-start id as before — no
            // identity file, no lock.
            return octet_for_daemon_id(daemon_id);
        };
        let identity = load_or_create_daemon_identity(identity_dir).unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "could not load daemon identity; falling back to random per-start id",
            );
            daemon_id.to_owned()
        });
        resolve_switch_octet(switch_lock_dir().as_deref(), &identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (in_microvm, identity_dir);
        octet_for_daemon_id(daemon_id)
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

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077): the fact [`crate::rpc::serve_get_effective_session_policy`]
    /// resolves a session's effective egress against, so the answer a client
    /// gets reflects the daemon that is actually serving it.
    pub(crate) async fn deny_all_opt_out(&self) -> bool {
        self.0.lock().await.config.deny_all_opt_out
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
    // client discovers it from can read it. In a VM, the *publication* of
    // that port on the host loopback follows the same default-first rule and
    // walks to a host port of its own when the host already holds the
    // default — the bind itself never moves for a publish (NET-059).
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

    // The box-zone answerer (UDP), beside the hostname proxy — on a native
    // host only: the loopback answerer the host's resolver is routed to for
    // `*.min.internal` (design §7.1, NET-009). Same bind rule as the proxies
    // and the same configured/default/selected port treatment; the on-machine
    // gate is the answerer's own (loopback peers, NET-006).
    //
    // A daemon inside a microVM starts no answerer and publishes none
    // through the forwarder: on a VM-backed host the zone is the VM host
    // daemon's to answer — `minvmd`'s host answerer serves it on the host
    // loopback from the host-authored table (NET-138), the same semantics
    // over the same shared decision — and an in-guest answerer behind the
    // switch would only shadow it. The in-VM daemon's registry answers
    // nothing, `min ls` carries no answerer port for a VM session to point
    // a resolver at, and the hostname proxy above (which in-guest routing
    // does depend on) keeps serving exactly as before.
    if in_microvm {
        return;
    }
    let answerer = ZoneAnswerer::new(
        state.sessions_manager().await.hostnames(),
        AnswerScope::Native,
    );
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

    /// The port every box's own-address set opens at the node address for
    /// the interim hostname proxy (design §7.1): the first bind's port, or
    /// `None` for the OS-picks `0`, which names no port before the bind.
    #[must_use]
    fn opening_port(self) -> Option<u16> {
        Some(self.first_port()).filter(|port| *port != 0)
    }

    /// Whether a failed bind should fall back to asking the OS for a free
    /// port: only the default-then-select choice — a pinned port's failure
    /// is the operator's to clear, and moving the listener would be the
    /// silent loss of routing the requirement rules out.
    #[must_use]
    fn reselects_when_busy(self) -> bool {
        matches!(self, Self::DefaultThenSelect { .. })
    }

    /// Whether a refused host-loopback publish may take a host port of its
    /// own rather than keep proposing the bound one: any port the *guest*
    /// chose — the OS-selected one, or the documented default nobody
    /// pinned — is the daemon's to relocate on the host side; a port the
    /// operator pinned keeps proposing it (the publish retry is the
    /// remedy, and the report says so). Either way the walk moves the
    /// publication, never the bind: the listener keeps the port its own
    /// boxes reach it on.
    ///
    /// On a VM boot this is false by construction: minvmd hands each VM
    /// its own distinct node ports on the boot line
    /// ([`crate::guest::handed_proxy_port`], and the answerer's beside it),
    /// the daemon binds them as [`ProxyPort::Pinned`], and each VM's
    /// publication lands on the host at exactly the number it was handed —
    /// no two VMs contend for one host port, so the walk never runs on the
    /// VM path. What the walk covers is boots with no handed port — an
    /// older minvmd, a native run, a host that handed `0` — where two
    /// daemons can meet on the one documented default: the first holds it
    /// on the host loopback and the second's publication lands on the next
    /// rung beside it, so both VMs on one host publish (NET-059).
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
pub(crate) enum HostProxyStartup {
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
    /// lifetime: the startup retry never rebinds a bound-and-served
    /// listener — a host publish the host refuses moves the *publication*
    /// to a host port of its own (see
    /// [`ProxyPort::reselects_when_publish_refused`]) while the listener
    /// keeps the port it bound.
    async fn spawn_serve(
        &self,
        state: &ServerStateHandle,
        listener: TcpListener,
    ) -> tokio::task::JoinHandle<()> {
        use crate::net::proxy::{Router, serve};
        use crate::net::switch::proxied_request_verdict;

        // The verdict each proxied request is put to before the proxy dials
        // anything (NET-069 to NET-071): the same function the switch's relay
        // gates by, so a hostname-routing surface gives no reach a direct
        // connection would not, and a proxied refusal logs the same rule name
        // a direct one's drop does. Handed to the router here, where the
        // daemon's live registry is, so the routing core itself stays pure
        // over the registry's facts.
        let router = Router::new(
            state.sessions_manager().await.hostnames(),
            proxied_request_verdict,
        );
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

    /// Reports the bound-and-published proxy on the state: the port a
    /// client can reach — `reported_port` — is what the discovery fields of
    /// the `ListSessions` and `CreateSession` replies carry, so a client can
    /// find — and point `HTTP(S)_PROXY` at — this daemon's port (NET-026).
    /// That is the port the listener bound (`bound_port`) everywhere except
    /// a VM whose publication had to take a host port of its own (NET-059):
    /// there the published port is the one a host client can dial, and the
    /// boxes inside the VM keep reaching the bound one on the loopback they
    /// share with the daemon. The one info line beside it is the
    /// diagnostics-bundle answer to "which port is this daemon on, and who
    /// chose it": the bundle tails the daemon log, and two daemons on one
    /// host (NET-027) is exactly when the question gets asked.
    ///
    /// `source` is who chose the port — the flag, the documented default,
    /// or the OS — which is what the line and the reader of two daemons'
    /// logs want to know (see [`PortSource`]).
    async fn record_serving(
        &self,
        state: &ServerStateHandle,
        bound_port: u16,
        source: PortSource,
        reported_port: u16,
    ) {
        match self {
            Self::Egress { port, .. } => {
                tracing::info!(
                    component = self.component(),
                    port = bound_port,
                    port_source = source.as_str(),
                    status = "serving",
                    "hostname proxy is serving on its {} port",
                    source.as_str()
                );
                warn_if_proxy_opening_missed(port.opening_port(), bound_port);
                state.set_hostname_proxy_port(reported_port).await;
            }
        }
    }
}

/// Warns, once at the proxy's startup, when the port it bound is not the
/// port every box's own-address set opens at the node address (the
/// interim opening, design §7.1): an unpinned daemon that found the default
/// busy and took an OS-picked port, or a pinned `0`. Boxes on the switch
/// then cannot reach the proxy at all. Returns whether it warned.
#[cfg(target_os = "linux")]
fn warn_if_proxy_opening_missed(opening: Option<u16>, bound_port: u16) -> bool {
    if opening == Some(bound_port) {
        return false;
    }
    let opening = opening.map_or_else(|| "none".to_string(), |port| port.to_string());
    tracing::warn!(
        bound_port,
        opening_port = %opening,
        "hostname proxy bound port {bound_port} but the switch opening is at port \
         {opening}: own-address boxes cannot reach the hostname proxy; pin \
         hostname_proxy_port"
    );
    true
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

/// How far apart the host-side ports a VM's proxy publication proposes are.
/// The bound port is proposed first — a lone VM publishes on the documented
/// default the host's recipes assume — and each further VM on the host takes
/// the next rung up, a stride apart, so the rungs stay in the range a reader
/// of two daemons' logs recognises while it is the forwarder's refusal, not
/// the stride, that actually keeps two publications distinct: a rung the
/// host already holds is skipped exactly like the held default.
#[cfg(target_os = "linux")]
pub(crate) const HOST_PUBLISH_PORT_STRIDE: u32 = 1_000;

/// The next host-side port the publication may propose after `port` was
/// refused as taken: one stride further up, or `None` when the walk has no
/// rung left under [`u16::MAX`] — the caller then keeps the port it has and
/// lets the retry backoff answer for the failure instead.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn next_host_publish_port(port: u16) -> Option<u16> {
    u32::from(port)
        .checked_add(HOST_PUBLISH_PORT_STRIDE)
        .and_then(|next| u16::try_from(next).ok())
}

/// The vsock port the guest dials to hand the VM host daemon a report: the
/// boot-marker channel the `READY` and `MOUNT_FAILED` beacons already travel
/// — `guest.rs`'s private `BOOT_MARKER_PORT`, pinned here beside its twin
/// because the channel is the host's to own and the guest's to dial. The
/// hostname proxy's host-publish outcome rides it (T93): the VM host holds
/// the port's reservation, so the redraw-or-fail decision is the host's —
/// but only once it hears the publish failed, which is what this report
/// is.
#[cfg(target_os = "linux")]
const VM_HOST_MARKER_PORT: u32 = 7350;

/// The lines of one publish report: the verb, the port, and — when the boot
/// line handed one — the boot's publish generation, echoed so the VM host
/// can tell this boot's report from a killed boot's (T93). Without a
/// generation the report is the two lines an older host parses.
#[cfg(target_os = "linux")]
fn publish_report(verb: &str, port: u16, generation: Option<u64>) -> String {
    match generation {
        Some(generation) => format!("{verb}\n{port}\n{generation}\n"),
        None => format!("{verb}\n{port}\n"),
    }
}

/// Writes the `PROXY_SERVING\n<port>\n[<generation>\n]` report to the given
/// async writer. Factored out of [`report_proxy_serving`] so tests can
/// exercise the format with an in-memory writer, the twin of guest.rs's
/// `write_ready_beacon`.
#[cfg(target_os = "linux")]
async fn write_proxy_serving_report<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    port: u16,
    generation: Option<u64>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    writer
        .write_all(publish_report("PROXY_SERVING", port, generation).as_bytes())
        .await
}

/// Writes the `PROXY_PORT_HELD\n<port>\n[<generation>\n]` report — the
/// terminal address-in-use failure, naming the host port the host already
/// held — to the given async writer, factored out for tests like
/// [`write_proxy_serving_report`].
#[cfg(target_os = "linux")]
async fn write_proxy_port_held_report<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    port: u16,
    generation: Option<u64>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    writer
        .write_all(publish_report("PROXY_PORT_HELD", port, generation).as_bytes())
        .await
}

/// Hands one publish-outcome report to the VM host daemon over the
/// boot-marker channel: dials the host (CID 2) on [`VM_HOST_MARKER_PORT`],
/// writes the payload, and closes. Best-effort on purpose — the host bounds
/// its own watch and falls back to its own probes when no report arrives,
/// so a report that cannot be sent never stalls the boot — mirroring
/// guest.rs's `emit_marker`, with the same short dial retries for a vsock
/// device that can lag the boot.
#[cfg(target_os = "linux")]
async fn report_publish_outcome(payload: &[u8], label: &str) {
    use tokio::io::AsyncWriteExt;
    use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

    const MAX_ATTEMPTS: u32 = 5;
    const BACKOFF: Duration = Duration::from_millis(100);

    let addr = VsockAddr::new(VMADDR_CID_HOST, VM_HOST_MARKER_PORT);
    for attempt in 1..=MAX_ATTEMPTS {
        match VsockStream::connect(addr).await {
            Ok(mut stream) => {
                if let Err(error) = stream.write_all(payload).await {
                    tracing::warn!(
                        attempt,
                        error = %error,
                        report = label,
                        "the publish-outcome report could not be written"
                    );
                    return;
                }
                // Fully qualified: `VsockStream` also carries an inherent
                // sync `shutdown(&self, std::net::Shutdown)`, and the trait's
                // is the half-close the marker channel's reader expects.
                if let Err(error) = tokio::io::AsyncWriteExt::shutdown(&mut stream).await {
                    tracing::warn!(
                        attempt,
                        error = %error,
                        report = label,
                        "the publish-outcome report could not be closed"
                    );
                    return;
                }
                tracing::info!(
                    attempt,
                    report = label,
                    "handed the hostname proxy's publish outcome to the VM host daemon"
                );
                return;
            }
            Err(error) => {
                tracing::debug!(
                    attempt,
                    error = %error,
                    "the boot-marker channel is not up yet; retrying"
                );
                tokio::time::sleep(BACKOFF).await;
            }
        }
    }
    tracing::warn!(
        report = label,
        "the publish-outcome report could not be sent: the boot-marker channel never came up"
    );
}

/// Reports the hostname proxy's publication landing on `port`: one report
/// of the port the publication took ends the VM host's publish watch
/// without waiting out its bound.
#[cfg(target_os = "linux")]
async fn report_proxy_serving(port: u16) {
    let mut payload = Vec::new();
    let generation = crate::guest::handed_publish_generation();
    let _ = write_proxy_serving_report(&mut payload, port, generation).await;
    report_publish_outcome(&payload, "PROXY_SERVING").await;
}

/// Reports the hostname proxy's publication refused for address-in-use on
/// `port` — the terminal publish failure (T93): the VM host holds the
/// reservation, so the redraw-or-fail decision is the host's, and this
/// report is how it hears the failure instead of watching a retry it cannot
/// see.
#[cfg(target_os = "linux")]
async fn report_proxy_port_held(port: u16) {
    let mut payload = Vec::new();
    let generation = crate::guest::handed_publish_generation();
    let _ = write_proxy_port_held_report(&mut payload, port, generation).await;
    report_publish_outcome(&payload, "PROXY_PORT_HELD").await;
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
/// bound-and-served listener is never dropped and rebound — the one
/// exception [`ProxyPort::reselects_when_publish_refused`] names moved the
/// *bind*, and the walk that replaces it moves only the *publication*: a
/// host port the host refuses is left for the next proposal, one rung
/// further up, while the listener keeps the documented port this VM's own
/// boxes share its loopback on (NET-059).
///
/// The one publish failure that is *terminal* rather than retried: inside a
/// microVM, a host port the host already holds on the port the boot line
/// handed this daemon (a handed port has no rung of its own) is reported
/// to the VM host daemon over the boot-marker channel
/// ([`report_proxy_port_held`]) and the drive ends there — the VM host owns
/// the reservation, so it owns the retry, a redraw onto a fresh port, and
/// its fail-the-start decision needs the report, not silence backed by a
/// backoff the host never learns from (T93). Every other publish failure —
/// a transient one, a walk that exhausted its rungs — keeps the existing
/// backoff (NET-021).
#[cfg(target_os = "linux")]
pub(crate) async fn drive_proxy_until_serving(
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
    // The host-side port the publication proposes: the port the listener
    // actually landed on first — a lone VM publishes on the documented
    // default the host's recipes assume — and, once the host refuses that
    // one, whatever rung of its own the walk has stepped to. Reset to the
    // bound port whenever the walk gives up on a pass (see the publish
    // arm), so the next pass re-proposes the default before its rungs.
    let mut host_port = bound_port;
    // The port the publication was accepted on, once it was: the port a
    // client can reach, which is what the RPC discovery field carries.
    let mut published_port: Option<u16> = None;

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
                            // The publication proposes the port the listener
                            // actually landed on, so a relocated bind (a busy
                            // default, NET-025) publishes what it bound.
                            host_port = bound_port;
                            // The serve task runs for the daemon's lifetime;
                            // its handle is dropped on purpose — nothing ever
                            // aborts it, because nothing ever rebinds.
                            drop(proxy.spawn_serve(&state, listener).await);
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
        if !publish_on_host {
            break;
        }
        match expose
            .publish(
                crate::net::DEFAULT_SUBNET.daemon_ip(),
                bound_port,
                host_port,
                "tcp",
            )
            .await
        {
            None => {
                // The bundle's answer to "where on the host is this VM's
                // proxy published" — the diagnostics question two VMs on one
                // host exist to ask — naming the host port beside the guest
                // port the serving line below reports.
                tracing::info!(
                    component,
                    host_port,
                    guest_port = bound_port,
                    status = "published",
                    "hostname proxy is published on the host loopback"
                );
                published_port = Some(host_port);
                // The VM host daemon's watch for exactly this moment (T93):
                // one report of the port the publication landed on ends it
                // without waiting out the bound. This arm only runs on the
                // in-VM publish path — a native daemon has no host daemon to
                // tell. Sent in the background: the report's vsock dial can
                // take seconds per try, and the drive must record serving
                // without waiting on it.
                tokio::spawn(report_proxy_serving(host_port));
                break;
            }
            Some(failure) => {
                // The host already holds this port: publish on a host port
                // of this VM's own — the next rung up — instead of moving the
                // listener. The bind is the surface this VM's own boxes reach
                // on its loopback, at the documented port every recipe
                // assumes; the publication is the host's surface, and it is
                // the one two VMs contend for (NET-059). A pinned port has
                // no rung to walk to: the operator named it, and the retry
                // with the report is the remedy. A *transient* failure — the
                // shuttle not up yet at boot, a stalled exchange — keeps the
                // port it was proposing and retries with the existing
                // backoff, so a daemon that starts before its host gvproxy
                // does not move off its default (NET-021, NET-025).
                let walk = if failure.port_taken && choice.reselects_when_publish_refused() {
                    next_host_publish_port(host_port)
                } else {
                    None
                };
                let next_retry = retry.delay(attempt);
                if let Some(next) = walk {
                    tracing::warn!(
                        component,
                        host_port,
                        guest_port = bound_port,
                        status = "relocated",
                        "the host already holds this port; publishing on a port of its own"
                    );
                    host_port = next;
                    continue;
                }
                // The one publish failure that is terminal rather than
                // retried: inside a microVM, a host port the host already
                // holds on the port the boot line handed this daemon — a
                // handed port has no rung of its own — is the VM host's to
                // answer for, not this daemon's to out-wait. The VM host
                // holds the reservation and owns the retry (a redraw hands
                // a fresh port, or the start fails naming this one), and
                // the report is how it hears the failure; a backoff loop
                // here would leave the VM up with no hostname proxy, which
                // the host forbids. `publish_on_host` is the in-VM flag, so
                // the report has a listener exactly when it is sent; a
                // native daemon never reaches this arm at all.
                if publish_on_host && failure.port_taken && !choice.reselects_when_publish_refused()
                {
                    tracing::warn!(
                        component,
                        host_port,
                        guest_port = bound_port,
                        status = "port held",
                        %failure.report,
                        "the host holds the hostname proxy's port; reporting the terminal publish failure to the VM host daemon"
                    );
                    // Recorded first, reported in the background: the drive
                    // ends here and never waits on the report's vsock dial,
                    // which can take seconds per try.
                    proxy.record_unavailable(&state, failure.report).await;
                    tokio::spawn(report_proxy_port_held(host_port));
                    return;
                }
                // No rung left to walk to, a pinned port, or a transient
                // failure: keep the listener where it is, report the failure
                // on the state note `min ls` warns from, and let the backoff
                // answer for the retry — the walk starts over from the
                // bound port on the next pass.
                tracing::warn!(
                    component,
                    host_port,
                    guest_port = bound_port,
                    status = "unavailable",
                    %failure.report,
                    next_retry = ?next_retry,
                    "hostname proxy could not publish on the host loopback; retrying with backoff"
                );
                proxy.record_unavailable(&state, failure.report).await;
                host_port = bound_port;
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
    // The port the RPC discovery field carries is the port a client can
    // reach: the bound one, or — on a VM whose publication had to take a
    // host port of its own — the published one.
    let reported_port = published_port.unwrap_or(bound_port);
    proxy
        .record_serving(&state, bound_port, source, reported_port)
        .await;
}

/// Drives the box-zone answerer to serving, the same two gates, the same
/// backoff, the same [`ProxyPort`] policy and the same publication walk the
/// routing proxies take ([`drive_proxy_until_serving`], NET-021): binds at
/// `bind_base` on `port`, and — in a microVM (DM1), where the socket binds
/// inside the guest — publishes the port on the host loopback through the
/// gvproxy forwarder's **UDP** path, the transport the host resolver's
/// datagrams travel on. Once both gates pass,
/// [`crate::net::answerer::serve`] runs for the daemon's lifetime, and the
/// port it ended up on — and who chose it — is recorded on the state for the
/// RPC replies to carry beside the proxy's.
///
/// The daemon log names the listener's address and port at start (the bind's
/// `reachable` event, the serving event here) and each failure warns once
/// with its reason, remedy and next retry. The serving moment is also when
/// the daemon logs its half of NET-018's one observability line
/// ([`crate::rpc::log_live_name_surface`]): the answerer's bind is the
/// daemon's half of the native condition, so the bind's success is the
/// earliest moment that fact is true — and it is the daemon's moment,
/// logged whether or not any client ever asks. Unlike a routing proxy, the
/// answerer records no `min ls` note: a box's routing does not depend on it
/// (the proxies carry that), and its failures are the host's resolver config
/// to read in the log.
///
/// The serve loop starts as soon as the socket binds and stays up while the
/// publish retries; the bind gate never runs again once it has passed, so a
/// bound-and-served answerer is never dropped and rebound. The publish walk
/// only ever covers boots with no handed port — a native run with the port
/// unconfigured, or one that landed on `0` — where a host port the host
/// refuses is left for the next proposal, one rung further up
/// ([`next_host_publish_port`]), while the socket keeps the port it bound:
/// the same "publication walks, bind stays" rule the proxies follow. A
/// VM-hosted daemon never reaches this drive at all
/// ([`start_host_proxies`] returns before it), so the walk's in-VM leg has
/// no caller: the zone on a VM-backed host is the VM host daemon's host
/// answerer's to serve (NET-138), never a guest's.
#[cfg(target_os = "linux")]
pub(crate) async fn drive_answerer_until_serving<T: crate::net::answerer::Zone>(
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
    // The host-side port the publication proposes: the port the socket
    // actually landed on first — a lone VM publishes on the documented
    // default the host's recipes assume — and, once the host refuses that
    // one, whatever rung of its own the walk has stepped to. Reset to the
    // bound port whenever the walk gives up on a pass (see the publish arm),
    // so the next pass re-proposes the default before its rungs.
    let mut host_port = bound_port;
    // The port the publication was accepted on, once it was: the port the
    // host's resolver reaches, which is what the RPC discovery field carries.
    let mut published_port: Option<u16> = None;
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
                        // The publication proposes the port the socket
                        // actually landed on, so a relocated bind (a busy
                        // default, NET-025) publishes what it bound.
                        host_port = bound_port;
                        let bound_addr = SocketAddr::new(bind_base, bound_port);
                        tracing::info!(
                            component = COMPONENT,
                            %bound_addr,
                            port = bound_port,
                            status = "listening",
                            "box-zone answerer is serving"
                        );
                        let serve_answerer = answerer.clone();
                        // The serve task runs for the daemon's lifetime; its
                        // handle is dropped on purpose — nothing ever aborts
                        // it, because nothing ever rebinds: the walk below
                        // moves the *publication*, never the socket.
                        drop(tokio::spawn(async move {
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
            .publish(
                crate::net::DEFAULT_SUBNET.daemon_ip(),
                bound_port,
                host_port,
                "udp",
            )
            .await
        {
            None => {
                // The bundle's answer to "where on the host is this VM's
                // answerer published" — the same diagnostics question two VMs
                // on one host ask of the proxy — naming the host port beside
                // the guest port the serving line below reports.
                tracing::info!(
                    component = COMPONENT,
                    host_port,
                    guest_port = bound_port,
                    status = "published",
                    "box-zone answerer is published on the host loopback"
                );
                published_port = Some(host_port);
                break;
            }
            Some(failure) => {
                // The host already holds this port: publish on a host port of
                // this VM's own — the next rung up — instead of moving the
                // socket. The bind is the surface this VM's own boxes query
                // on its loopback, at the documented port the host's resolver
                // recipes assume; the publication is the host's surface, and
                // it is the one two VMs contend for (NET-059): each VM's
                // answerer serves its zone on a host port of its own, the
                // same walk the routing proxies take. A pinned port has no
                // rung to walk to: the operator named it, and the retry with
                // the report is the remedy. A *transient* failure — the
                // shuttle not up yet at boot, a stalled exchange — keeps the
                // port it was proposing and retries with the existing
                // backoff, so a daemon that starts before its host gvproxy
                // does not move off its default (NET-021, NET-025).
                let walk = if failure.port_taken && port.reselects_when_publish_refused() {
                    next_host_publish_port(host_port)
                } else {
                    None
                };
                let next_retry = retry.delay(attempt);
                if let Some(next) = walk {
                    tracing::warn!(
                        component = COMPONENT,
                        host_port,
                        guest_port = bound_port,
                        status = "relocated",
                        "the host already holds this port; publishing on a port of its own"
                    );
                    host_port = next;
                    continue;
                }
                // No rung left to walk to, a pinned port, or a transient
                // failure: keep the socket where it is, report the failure in
                // the log the host's resolver config is read from, and let the
                // backoff answer for the retry — the walk starts over from
                // the bound port on the next pass.
                tracing::warn!(
                    component = COMPONENT,
                    %addr,
                    status = "unavailable",
                    %failure.report,
                    next_retry = ?next_retry,
                    "box-zone answerer could not publish on the host loopback; retrying with backoff"
                );
                host_port = bound_port;
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
    // The port the RPC discovery field carries is the port the host's
    // resolver reaches: the bound one, or — on a VM whose publication had to
    // take a host port of its own (NET-059) — the published one.
    let reached_port = published_port.unwrap_or(bound_port);
    state.set_zone_answerer_port(reached_port).await;
    // NET-018's observability line, at the moment its fact can first be
    // true: the answerer's bind is the daemon's half of the native
    // surface, so this — the bind's success — is when a diagnostics
    // bundle's daemon-log tail can first read that half. The proxy half of
    // the line is read behind a settle window; see the function. The port
    // it names is the port the host's resolver reaches, the same one the
    // discovery field above carries, so a VM whose publication walked to a
    // host port of its own does not have its log point the host at a port
    // the host never sees.
    crate::rpc::log_live_name_surface(&state, reached_port).await;
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
/// refused — the only publish failure a guest-chosen port's publication
/// walks from.
///
/// Every other cause is *transient* — the shuttle not reachable, the host
/// forwarder not up yet at boot, an exchange that stalls past its bound — and
/// keeps the port it has: the retry comes on the same backoff (NET-021), so a
/// daemon that starts before its host gvproxy does not drift off the default
/// port nobody configured (NET-025) and stay there until it restarts.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct HostPublishFailure {
    /// The reason and the remedy as one text.
    report: String,
    /// Whether the forwarder was reached and refused to take the host-side
    /// port — on this endpoint, a host port some other process already
    /// holds — versus a failure that never got an answer from the forwarder.
    port_taken: bool,
}

/// Publishes a guest-side listener bound on `daemon_ip:port` — a routing
/// proxy, or the box-zone answerer (`protocol` says which transport) — onto
/// the macOS host's loopback (`127.0.0.1:host_port`) via the host gvproxy
/// forwarder, reached over the vsock shuttle (DM1). Best-effort in that it
/// never fails the daemon, since the host gvproxy may be absent; capped at
/// [`HOST_EXPOSE_PUBLISH_TIMEOUT`] per attempt so a stalled forwarder cannot
/// stretch the retry cadence.
///
/// `host_port` is the host-side port the publication proposes — the bound
/// port's own number while nobody else on the host holds it, and the rung a
/// refused publication walked to when someone does (NET-059).
///
/// Returns `Some(failure)` when the publish did not happen — its `report` is
/// the reason and remedy as one text, and its `port_taken` says whether the
/// host port is actually unusable (a taken one is the guest-chosen port's
/// cue to walk; a transient one keeps the port and retries) — and `None`
/// once published.
#[cfg(target_os = "linux")]
async fn expose_proxy_on_host(
    daemon_ip: std::net::Ipv4Addr,
    port: u16,
    host_port: u16,
    protocol: &'static str,
) -> Option<HostPublishFailure> {
    publish_listener_on_control(
        &crate::net::policy::ControlChannel::Vsock {
            cid: crate::net::VSOCK_HOST_CID,
            port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
        },
        daemon_ip,
        port,
        host_port,
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
    host_port: u16,
    protocol: &'static str,
) -> Option<HostPublishFailure> {
    use crate::net::policy::{ExposeRequest, post_json};

    let request = ExposeRequest {
        local: format!("127.0.0.1:{host_port}"),
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
                    "the daemon could not publish port {host_port} on the host loopback via \
                     the gvproxy forwarder: {error}. Remedy: check that the host \
                     gvproxy (minvmd) is running and reachable over the shuttle"
                ),
                port_taken,
            })
        }
        Err(_) => Some(HostPublishFailure {
            report: format!(
                "publishing port {host_port} on the host loopback did not complete within \
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
/// vsock shuttle ([`HostExpose::Shuttle`]); a test stands an answer in
/// ([`HostExpose::Fixed`], [`HostExpose::HeldPorts`]) so each half of the
/// publish's failure space — a host port actually taken, which walks to a
/// port of its own, and a transient failure, which must not — can be
/// driven deterministically, no host gvproxy required.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) enum HostExpose {
    /// The daemon's publish: gvproxy's forwarder over the vsock shuttle.
    Shuttle,
    /// A test's stand-in that answers `answer` for every attempt.
    #[cfg(test)]
    Fixed(Option<HostPublishFailure>),
    /// A test's stand-in forwarder that behaves like the real one on the one
    /// axis a port walk depends on: every host port it accepts is held from
    /// then on, and a later proposal of a held port is refused as taken — so
    /// two daemons publishing through one ledger cannot land on one host
    /// port, the contention two VMs put on a host's loopback (NET-059).
    #[cfg(test)]
    HeldPorts(std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u16>>>),
}

#[cfg(target_os = "linux")]
impl HostExpose {
    /// Runs one publish attempt for a listener bound on `daemon_ip:port`,
    /// proposing `host_port` as the host-side port the forwarder takes —
    /// the bound port's own number until a refusal walks the host side off
    /// it.
    async fn publish(
        &self,
        daemon_ip: std::net::Ipv4Addr,
        port: u16,
        host_port: u16,
        protocol: &'static str,
    ) -> Option<HostPublishFailure> {
        match self {
            Self::Shuttle => expose_proxy_on_host(daemon_ip, port, host_port, protocol).await,
            #[cfg(test)]
            Self::Fixed(answer) => answer.clone(),
            #[cfg(test)]
            Self::HeldPorts(held) => {
                let mut held = held.lock().expect("the test's ledger is never poisoned");
                if held.insert(host_port) {
                    None
                } else {
                    Some(HostPublishFailure {
                        report: format!(
                            "the gvproxy forwarder could not take 127.0.0.1:{host_port} on \
                             the host: the port is held by another publication. Remedy: \
                             let the publication take a port of its own"
                        ),
                        port_taken: true,
                    })
                }
            }
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
        daemon_identity_dir: None,
        // The default every unit-test daemon runs: the rollout phase this
        // build ships, not opted out.
        deny_all_opt_out: false,
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

    /// The interim node-address opening is compiled at the port the
    /// proxy's first bind asks for; when the bind lands elsewhere (an
    /// OS-picked port), the daemon says so once, naming both ports and the
    /// consequence, and says nothing when the ports agree
    /// (gominimal/minimal#1952).
    #[cfg(target_os = "linux")]
    #[test]
    fn proxy_opening_mismatch_warns_once_naming_both_ports() {
        let capture = crate::test_harness::captured_log();
        let line = "hostname proxy bound port 41913 but the switch opening is at port 7654: \
                    own-address boxes cannot reach the hostname proxy; pin hostname_proxy_port";

        assert!(!warn_if_proxy_opening_missed(Some(7654), 7654));
        assert!(
            !capture
                .contents()
                .contains("the switch opening is at port 7654"),
            "equal ports say nothing"
        );

        assert!(warn_if_proxy_opening_missed(Some(7654), 41913));
        let logged = capture.contents();
        assert_eq!(logged.matches(line).count(), 1, "one line: {logged}");
        assert!(logged.contains("WARN"), "a warn line: {logged}");
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

    /// T63 (NET-025, NET-138): a VM-hosted daemon binds the port its host
    /// handed it on the boot line, and selects none of its own. The handed
    /// port is read exactly the way pid-1 reads it — off the environment
    /// the kernel passes through — and the startup is driven the way a VM
    /// daemon's is: bind 0.0.0.0, publish behind the host-loopback gate, then
    /// record the bound port for the discovery reply to carry. With a handed
    /// port held busy, the startup keeps retrying that port and never
    /// re-picks: the host's box table names it, so a silent move would strand
    /// every client pointed at it.
    ///
    /// The handed port is the hostname proxy's alone: a VM-hosted daemon
    /// starts no zone answerer (NET-138 — the VM host daemon's host answerer
    /// owns the zone), so no answerer token exists to read or drive.
    ///
    /// The host-loopback publish is the `Fixed(None)` stand-in — the real
    /// gate's decisions are proven from the gate side (`minvmd`'s
    /// `switch_request_refused_and_logged`); what is under test here is the
    /// port policy the handed values feed.
    // Env is process state: nextest runs every test in its own process.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn vm_hosted_daemon_binds_handed_port() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::guest;

        // Reserve a free port, then write it onto the boot line the way
        // minvmd does: as a token the kernel hands pid-1 as an environment
        // variable.
        let probe = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let proxy_port = probe.local_addr().unwrap().port();
        drop(probe);
        unsafe {
            std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, proxy_port.to_string());
        }
        // What pid-1's CLI is built with: the handed port.
        assert_eq!(guest::handed_proxy_port().unwrap(), Some(proxy_port));

        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();

        // The VM startup shape: bind UNSPECIFIED, publish behind the
        // host-loopback gate, record the bound port. The compressed backoff
        // keeps a failed attempt cheap should the box be noisy.
        let retry = RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(100));
        tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: ProxyPort::from_config(
                    guest::handed_proxy_port().unwrap(),
                    crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
                ),
            },
            true,
            HostExpose::Fixed(None),
            retry,
        ));

        // Bound as handed, and reported on the discovery path the RPC
        // replies carry.
        assert_eq!(
            wait_for_proxy_port(&state).await,
            proxy_port,
            "the handed proxy port is bound, not re-picked"
        );

        // And it really is a listener on the handed port: the proxy answers
        // (a name no live box owns gets its refusal).
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
            "ghost.min.internal",
        )
        .await;
        assert!(routed.contains("502"), "the handed port answers: {routed}");

        // Selects none: with a handed port held, the startup keeps retrying
        // that port and never re-picks — the state stays portless while the
        // loop is alive. A fresh state, so the first phase's recorded port
        // cannot stand in for this one's.
        let probe = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let held = probe.local_addr().unwrap().port();
        unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, held.to_string()) };
        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();
        let drive = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: ProxyPort::from_config(
                    guest::handed_proxy_port().unwrap(),
                    crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
                ),
            },
            true,
            HostExpose::Fixed(None),
            RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(50)),
        ));
        // Several retries on the compressed backoff, then prove it stayed put.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !drive.is_finished(),
            "a busy handed port is retried, not abandoned"
        );
        assert_eq!(
            state.hostname_proxy_port().await,
            None,
            "a busy handed port is never re-picked"
        );
        drive.abort();
        drop(probe);
    }

    /// T65 (NET-009 on a VM host): a VM-hosted daemon starts no zone answerer
    /// and publishes none through the forwarder. The zone on a VM-backed host
    /// is the VM host daemon's to answer — `minvmd`'s host answerer serves it
    /// on the host loopback, from the host-authored table (NET-138) — so an
    /// in-guest answerer behind the switch would only shadow it. What must
    /// stay is the *other* half of `start_host_proxies`: the hostname proxy
    /// starts in a microVM exactly as before.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn vm_hosted_daemon_starts_no_answerer() {
        use std::net::{IpAddr, Ipv4Addr};

        use hickory_proto::rr::RecordType;

        use crate::net::answerer::encode_query;

        // A free UDP port the daemon is configured to put its answerer on —
        // the handed-answerer port a VM-hosted daemon used to bind before the
        // host answerer took the zone. Reserved here only to learn a free
        // number, then released: if the daemon starts an answerer despite its
        // deployment model, it is this port it binds and answers on, which is
        // exactly what the datagram below would find.
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let configured = probe.local_addr().unwrap().port();
        drop(probe);

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
                zone_answerer_port: Some(configured),
                ..test_config(&dir)
            },
            None,
        )
        .await
        .unwrap();

        // The real startup path, the way a VM-hosted `Server::run` takes it.
        start_host_proxies(&state, true, None, Some(configured)).await;

        // The positive control: the hostname proxy's half ran — its listen
        // address bindable line is the first thing the VM startup logs, well
        // before the host publish this harness has no gvproxy to answer. What
        // changed is the answerer, not the daemon's whole proxy half.
        let mut proxy_bound = false;
        for _ in 0..200 {
            if buf
                .contents()
                .contains("egress proxy listen address is bindable")
            {
                proxy_bound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            proxy_bound,
            "the hostname proxy must start in a microVM as before, got: {}",
            buf.contents()
        );

        // The answerer never does: no line of its component — not a bind, not
        // a retry, not a serving — and its discovery field, the one `min ls`
        // prints its ZONE ANSWERER line from, stays empty for a window the
        // native startup fills it in within its first bind attempt.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            state.zone_answerer_port().await,
            None,
            "a VM-hosted daemon reports no zone answerer: the host answerer owns the zone"
        );
        assert!(
            !buf.contents().contains("zone-answerer"),
            "no zone-answerer line may appear in a VM-hosted daemon's log, got: {}",
            buf.contents()
        );

        // And nothing listens for zone datagrams on the port it was
        // configured to take: a query sent there gets no reply at all — no
        // rcode, no error, nothing — which is the port's state a VM host's
        // host answerer finds when it takes it.
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        socket
            .send_to(
                &encode_query("web.min.internal.", RecordType::A),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), configured),
            )
            .unwrap();
        let mut reply = [0u8; 512];
        match socket.recv_from(&mut reply) {
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            outcome => panic!(
                "the daemon must answer nothing in the zone's place on a VM host, got: {outcome:?}"
            ),
        }

        // The same deployment model with nothing handed at all — no handed
        // boot token and no configured port, the state a VM boots in now the
        // handoff carries the proxy port only: an answerer that ran anyway
        // would take the documented default (7656) on the guest's wildcard.
        // Both of its outcomes are caught without this test binding that
        // port itself (a dev host may hold it): a bind that succeeded would
        // set the discovery claim, and one that failed would log its
        // component line — neither may appear.
        let dir = TempDir::new().unwrap();
        let unconfigured = ServerStateHandle::new(
            Config {
                in_microvm: true,
                zone_answerer_port: None,
                ..test_config(&dir)
            },
            None,
        )
        .await
        .unwrap();
        start_host_proxies(&unconfigured, true, None, None).await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            unconfigured.zone_answerer_port().await,
            None,
            "a VM-hosted daemon with nothing handed binds no answerer on the \
             default port either: the host answerer owns the zone (NET-138)"
        );
        assert!(
            !buf.contents().contains("zone-answerer"),
            "no zone-answerer line may appear for a VM-hosted daemon with \
             nothing handed, got: {}",
            buf.contents()
        );
    }

    /// T63 (NET-025): the pid-1 boot reads its handed port fail-closed and
    /// binds it before anything else answers. A token present but unusable
    /// is a surfaced boot error — the read is an `Err` naming the token and
    /// the value it carried, not a `None` the daemon would fall back from —
    /// and a handed port something already holds fails the probe bind, which
    /// is boot-fatal: the startup pid-1 would drive next is driven here and
    /// stays portless, the boot was over before it, never rescued by a
    /// re-pick.
    // Env is process state: nextest runs every test in its own process.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_broken_handoff_fails_the_boot_before_any_listener_comes_up() {
        use std::net::Ipv4Addr;

        use crate::guest;

        // A present token that carries no port: the surfaced error, not a
        // quiet absence.
        unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, "no-port-here") };
        let error = guest::handed_proxy_port()
            .expect_err("an unusable token is a surfaced boot error, not an absence");
        assert_eq!(error.token, guest::HANDED_PROXY_PORT_TOKEN);
        assert_eq!(error.value, "no-port-here");

        // A handed port something already holds — the way a stale daemon or
        // an unrelated process in the guest holds one: the probe bind fails
        // it, with the port named, and that is the boot's end.
        let held_listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let held = held_listener.local_addr().unwrap().port();
        unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, held.to_string()) };
        let proxy = guest::handed_proxy_port().unwrap();
        assert_eq!(proxy, Some(held));
        let error = guest::probe_handed_node_port(proxy)
            .expect_err("a held handed port cannot bind for the probe");
        assert!(
            error.to_string().contains(&held.to_string()),
            "the boot-fatal bind names the port it failed on, got: {error}"
        );

        // And no listener ever comes up from it: the startup pid-1 would
        // drive next, driven here, keeps retrying the held handed port and
        // never re-picks — the boot was over before it.
        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(test_config(&dir), None)
            .await
            .unwrap();
        let drive = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: ProxyPort::from_config(
                    guest::handed_proxy_port().unwrap(),
                    crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
                ),
            },
            true,
            HostExpose::Fixed(None),
            RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(50)),
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !drive.is_finished(),
            "the held handed port is retried, not abandoned"
        );
        assert_eq!(
            state.hostname_proxy_port().await,
            None,
            "a boot that failed its probe bind never publishes a listener"
        );
        drive.abort();
        drop(held_listener);
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
    /// NET-059's publish half, driven from the failure side: a host port the
    /// host will not give up is walked off — one rung of its own further up,
    /// the publication relocating and never the listener. The refusal is
    /// driven through a fixed publish answer (`port_taken`), because the
    /// transient half of the publish's failure space — the arm that must
    /// not walk — is the next test's subject and needs the real path.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_refused_host_publish_walks_ports_of_its_own() {
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
        let retrier = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::DefaultThenSelect {
                    default: default_port,
                },
            },
            // The publish gate is the subject: every attempt here reports a
            // host port some other publication holds.
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

        // The relocation line names the host port it gives up on; two of
        // them with different ports means the driver really is walking the
        // host side, not retrying one proposal.
        let mut seen = std::collections::BTreeSet::new();
        let mut walked = false;
        for _ in 0..400 {
            for port in refused_ports(&buf.contents()) {
                seen.insert(port);
            }
            if seen.len() >= 2 {
                walked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            walked,
            "a refused host port must be walked off, not retried; \
             host ports refused so far: {seen:?}, log: {}",
            buf.contents()
        );

        // And the walk never touches the listener: the bound port answers
        // for the whole walk — the in-guest surface this VM's own boxes
        // reach, at the documented default they were promised.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), default_port),
            "ghost.min.internal",
        )
        .await;
        assert!(
            routed.contains("502"),
            "the listener must keep its port while the publication walks, got: {routed}"
        );
        assert!(
            state.proxy_unavailable().await.is_some(),
            "a publish that exhausts its rungs must stay reported as unavailable"
        );
        assert!(
            state.hostname_proxy_port().await.is_none(),
            "a proxy whose publish keeps failing must not report serving"
        );
        retrier.abort();
    }

    /// NET-059's publish half, driven from the success side: the host already
    /// holds the bound port's number — another VM's publication — so this
    /// daemon's publication takes the next rung of its own, the port a
    /// client can reach is the rung it published on, and the listener keeps
    /// the documented default this VM's own boxes share its loopback on.
    /// The publication line beside the bind is the bundle's answer to which
    /// VM owns which host port.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_walked_publication_keeps_the_bind_and_reports_the_rung() {
        use std::net::{IpAddr, Ipv4Addr};

        // A free port stands in for the documented default, with a free rung
        // above it for the walk to land on.
        let (default_port, rung) = loop {
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let Some(rung) = next_host_publish_port(port) else {
                continue;
            };
            match std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, rung)) {
                Ok(rung_probe) => drop(rung_probe),
                Err(_) => continue,
            }
            break (port, rung);
        };

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

        // The forwarder's ledger with the default already held — the host
        // loopback as a second VM's daemon finds it.
        let held = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::from([
            default_port,
        ])));

        drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::DefaultThenSelect {
                    default: default_port,
                },
            },
            true,
            HostExpose::HeldPorts(held),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;

        // The port a client can reach is the rung the publication landed on.
        assert_eq!(
            state.hostname_proxy_port().await,
            Some(rung),
            "a refused publication must land on a host port of its own, log: {}",
            buf.contents()
        );

        // The listener never moved: the documented default still answers,
        // for the boxes that share this VM's loopback with the daemon.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), default_port),
            "ghost.min.internal",
        )
        .await;
        assert!(
            routed.contains("502"),
            "the bind must keep the documented port while the publication walks, got: {routed}"
        );

        // The publication is named in the log, with both ports: the
        // diagnostics-bundle answer to "where is this VM's proxy published".
        let logged = buf.contents();
        assert!(
            logged.contains("hostname proxy is published on the host loopback"),
            "the publication must be named in the log, got: {logged}"
        );
        assert!(
            logged.contains(&format!("host_port={rung}")),
            "the publication line must name the host port it landed on, got: {logged}"
        );
        assert!(
            logged.contains(&format!("guest_port={default_port}")),
            "the publication line must name the guest port beside it, got: {logged}"
        );
        assert!(
            state.proxy_unavailable().await.is_none(),
            "a publication that landed must clear the unavailable note"
        );
    }

    /// T93's terminal half of the publish policy: inside a microVM, a host
    /// port the host already holds — on the port the boot line handed this
    /// daemon, which has no rung of its own to walk to — is reported to the
    /// VM host daemon as a terminal publish failure naming the port, and the
    /// drive *ends* there: the VM host holds the reservation and owns the
    /// retry (a redraw hands a fresh port, or the start fails naming this
    /// one), so a backoff loop the host never learns from would leave the VM
    /// up with no hostname proxy. The unavailable note `min ls` warns from
    /// stays recorded, and serving is never claimed for a publication that
    /// did not happen.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_publish_in_use_is_reported_not_retried() {
        use std::net::{IpAddr, Ipv4Addr};

        // A free port stands in for the one the VM host handed down the boot
        // line, so the bind cannot race another process's listener.
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let handed = probe.local_addr().unwrap().port();
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
        let drive = tokio::spawn(drive_proxy_until_serving(
            state.clone(),
            HostProxyStartup::Egress {
                bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: ProxyPort::Pinned(handed),
            },
            // The in-VM flag: this drive is the one with a VM host daemon on
            // the other end of the boot-marker channel.
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

        // The drive must end on its own — the report is the terminal
        // failure, not a preface to another backoff the test would have to
        // abort. (The report is sent in the background, so the drive never
        // waits on its vsock dial, which on a host with no VM host daemon
        // can take seconds per try.)
        let drove = tokio::time::timeout(Duration::from_secs(8), drive).await;
        assert!(
            drove.is_ok(),
            "a taken hostname-proxy port must end the drive, not retry it \
             with backoff forever; log: {}",
            buf.contents()
        );

        // The terminal warning names the port it gives up on, exactly once,
        // and the backoff arm's retry line never runs.
        let log = buf.contents();
        assert_eq!(
            log.matches("reporting the terminal publish failure to the VM host daemon")
                .count(),
            1,
            "the taken port must be reported once as terminal, got: {log}"
        );
        assert!(
            log.contains(&format!("host_port={handed}")),
            "the terminal report must name the port the host holds, got: {log}"
        );
        assert!(
            !log.contains("retrying with backoff"),
            "a taken hostname-proxy port must not enter the backoff retry, got: {log}"
        );
        assert!(
            refused_ports(&log).is_empty(),
            "a handed port has no rung to walk to, got: {log}"
        );
        assert!(
            state.proxy_unavailable().await.is_some(),
            "the terminal failure must stay recorded as the unavailable note \
             min ls warns from"
        );
        assert!(
            state.hostname_proxy_port().await.is_none(),
            "a proxy whose publish failed must not report serving"
        );

        // And the listener keeps the port it was handed — the bind is this
        // VM's own surface; only the publication is the host's.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), handed),
            "ghost.min.internal",
        )
        .await;
        assert!(
            routed.contains("502"),
            "the handed bind must keep its port, got: {routed}"
        );
    }

    /// The two-line payloads the publish-outcome reports write, in the exact
    /// shape the VM host daemon's marker gate classifies — the twin of
    /// guest.rs's `write_ready_beacon` format test, because the gate on the
    /// host parses the same two lines the writer here formats.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn publish_outcome_reports_are_two_lines_naming_the_port() {
        async fn drain(mut reader: tokio::io::DuplexStream) -> String {
            let mut output = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut output)
                .await
                .unwrap();
            String::from_utf8(output).unwrap()
        }

        let port = 19_911u16;

        let (mut writer, reader) = tokio::io::duplex(4096);
        write_proxy_serving_report(&mut writer, port, None)
            .await
            .unwrap();
        drop(writer);
        assert_eq!(
            drain(reader).await,
            format!("PROXY_SERVING\n{port}\n"),
            "the PROXY_SERVING report must be two lines naming the port"
        );

        let (mut writer, reader) = tokio::io::duplex(4096);
        write_proxy_port_held_report(&mut writer, port, None)
            .await
            .unwrap();
        drop(writer);
        assert_eq!(
            drain(reader).await,
            format!("PROXY_PORT_HELD\n{port}\n"),
            "the PROXY_PORT_HELD report must be two lines naming the port"
        );

        // With the boot's publish generation handed, every report echoes it
        // on a third line (T93), the line the host keeps or drops it by.
        let (mut writer, reader) = tokio::io::duplex(4096);
        write_proxy_serving_report(&mut writer, port, Some(42))
            .await
            .unwrap();
        drop(writer);
        assert_eq!(drain(reader).await, format!("PROXY_SERVING\n{port}\n42\n"));

        let (mut writer, reader) = tokio::io::duplex(4096);
        write_proxy_port_held_report(&mut writer, port, Some(42))
            .await
            .unwrap();
        drop(writer);
        assert_eq!(
            drain(reader).await,
            format!("PROXY_PORT_HELD\n{port}\n42\n")
        );
    }

    /// NET-025's boot-time edge: a publish that fails for a *transient*
    /// reason — here, nothing answering the shuttle, the exact shape a
    /// daemon that starts before its host gvproxy (minvmd) is ready sees —
    /// must keep the port it bound, the default included, and keep
    /// retrying with backoff (NET-021). Only a host port genuinely taken
    /// walks; a transient failure that walked would move a VM daemon's
    /// publication off the default at every boot race and leave it on a
    /// random host port until the daemon restarts.
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
            !logged.contains("relocated"),
            "a transient publish failure must keep the port it bound, got: {logged}"
        );

        // The port the listener bound, as the publish warnings name it. The
        // probe's port is free only until the probe drops: a parallel test
        // can take it before the bind (an outgoing connection's ephemeral
        // port, say), and then NET-025 relocates the *bind* — its own tests
        // cover that — and nothing listens on the probed port. Follow the
        // listener to where it landed, and hold it to the probed port
        // whenever the bind did not relocate.
        let bound_port: u16 = logged
            .split("guest_port=")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|port| port.parse().ok())
            .unwrap_or_else(|| {
                panic!("the publish warning must name the bound port, got: {logged}")
            });
        if !logged.contains("selecting a free one") {
            assert_eq!(
                bound_port, default_port,
                "a bind that did not relocate must hold the default, got: {logged}"
            );
        }

        // The port it keeps is the one it bound: the listener is serving
        // behind the still-failing publish — exactly the state a VM daemon
        // is in while its host gvproxy comes up.
        let routed = proxy_get(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound_port),
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

        // The listener bound in-guest on 7654; the publication proposes the
        // next rung above it — the split this test's report names.
        let failure = publish_listener_on_control(
            &crate::net::policy::ControlChannel::Unix(control),
            std::net::Ipv4Addr::new(100, 64, 0, 2),
            7654,
            7654 + HOST_PUBLISH_PORT_STRIDE as u16,
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
            failure.report.contains(&format!(
                "could not publish port {}",
                7654 + HOST_PUBLISH_PORT_STRIDE
            )),
            "the taken arm's report must name the host port the publication proposed, got: {}",
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

    /// The host ports named by the publication's relocation warnings in
    /// `log` — the rungs the driver walked off because the host already
    /// held them.
    #[cfg(target_os = "linux")]
    fn refused_ports(log: &str) -> Vec<u16> {
        log.lines()
            .filter(|line| line.contains("publishing on a port of its own"))
            .filter_map(|line| {
                let rest = line.split_once("host_port=")?.1;
                rest.split(|c: char| !c.is_ascii_digit())
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

    /// NET-027's switch half beside NET-010's address half: two daemons on
    /// one machine take two different switch /24s — the pinned pair here, 37
    /// and 52 — while the addresses their published boxes are granted from
    /// are the *same* host-wide pool, the reserved local range the answerer's
    /// lease record arbitrates (design §7.1). Each daemon's start line
    /// carries both facts, so a reader of two daemons' logs (a diagnostics
    /// bundle tails exactly this log) sees what distinguishes them — the
    /// switch — and what cannot distinguish them: the pool is the host's,
    /// never the daemon's, so no octet pair, congruent modulo the slice
    /// count of the carve this line replaced or otherwise, can hand two
    /// daemons one address between them.
    ///
    /// The `in_microvm: true` daemon keeps the host's default /16 whatever
    /// octet it was pinned to (it does not own its switch) and still draws
    /// its published addresses from the same one pool.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_daemons_log_one_host_wide_loopback_pool() {
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
        // A VM daemon on the first pinned octet: the octet does not reach
        // its switch (the host gvproxy's /16 stays), and its published
        // addresses come from the same pool as both native daemons'.
        let dir_c = TempDir::new().unwrap();
        let state_c = ServerStateHandle::new(
            Config {
                in_microvm: true,
                switch_subnet_octet: Some(37),
                ..test_config(&dir_c)
            },
            None,
        )
        .await
        .unwrap();

        // The start lines are logged as each daemon comes up; wait for all
        // three before reading the pool back out of them.
        let logged = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let logged = buf.contents();
                if logged.matches("reserved_loopback=").count() >= 3 {
                    return logged;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all three daemons must log the pool their published boxes come from");

        // Each daemon's start line, found by the field that identifies the
        // daemon: the configured /24 for the two pinned ones, the host's /16
        // for the VM one.
        let id_c = state_c.daemon_id().await;
        let line_of = |marker: &str| {
            logged
                .lines()
                .find(|line| line.contains(marker) && line.contains("reserved_loopback="))
                .unwrap_or_else(|| panic!("no start line carrying {marker}, got: {logged}"))
                .to_owned()
        };
        let line_a = line_of("subnet=100.64.37.0/24");
        let line_b = line_of("subnet=100.64.52.0/24");
        let line_c = line_of("subnet=100.64.0.0/16");
        assert!(
            line_c.contains(&format!("daemon_id={id_c}")),
            "the /16 line is the VM daemon's own, got: {line_c}"
        );

        // Every daemon's line carries the same one pool: the answerer's
        // whole grantable range, first address to last, never a per-daemon
        // carve of it.
        for line in [&line_a, &line_b, &line_c] {
            assert!(
                line.contains("reserved_loopback=127.0.64.2-127.0.64.254"),
                "a daemon's published boxes come from this host's one pool, got: {line}"
            );
        }
        // And what distinguishes the daemons is their switches, not their
        // pools: two different /24s for the pinned pair.
        assert_ne!(
            line_a, line_b,
            "two daemons pinned to different octets take different switches"
        );

        run_a.abort();
        run_b.abort();
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

    /// A native daemon's switch octet is stable across restarts: the
    /// identity is persisted under the state root on first start and read
    /// back on subsequent starts, so the derived /24 stays the same. Each
    /// "start" uses its own lock dir, since the first start's lock is held
    /// for the life of this test process.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_switch_octet_is_stable_across_restarts() {
        let dir = TempDir::new().unwrap();
        let state_dir = DaemonAbsPath::try_new(
            camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
        )
        .unwrap();
        let start = |state_dir: &DaemonAbsPath| {
            let locks = TempDir::new().unwrap();
            let identity = load_or_create_daemon_identity(state_dir).unwrap();
            resolve_switch_octet(Some(locks.path()), &identity)
        };
        let first = start(&state_dir);
        let second = start(&state_dir);
        assert_eq!(
            first, second,
            "the switch octet must be stable across restarts"
        );
        assert!(
            (1..=254).contains(&first),
            "derived octet {first} is outside 1..=254"
        );
    }

    /// An empty identity file is regenerated and persisted rather than
    /// sending every start to the per-start fallback.
    #[test]
    fn empty_daemon_identity_file_is_regenerated() {
        let dir = TempDir::new().unwrap();
        let state_dir = DaemonAbsPath::try_new(
            camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
        )
        .unwrap();
        let path = dir.path().join(DAEMON_IDENTITY_FILE);
        std::fs::write(&path, "  \n").unwrap();
        let identity = load_or_create_daemon_identity(&state_dir).unwrap();
        assert!(!identity.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), identity);
        assert_eq!(
            load_or_create_daemon_identity(&state_dir).unwrap(),
            identity
        );
    }

    /// Two daemons on one machine that derive the same octet end up on
    /// different blocks: the first holds the per-octet lock, so the second
    /// re-derives.
    #[cfg(target_os = "linux")]
    #[test]
    fn colliding_daemons_end_up_on_different_octets() {
        let locks = TempDir::new().unwrap();
        let first = resolve_switch_octet(Some(locks.path()), "same-identity");
        let second = resolve_switch_octet(Some(locks.path()), "same-identity");
        assert_eq!(first, octet_for_daemon_id("same-identity"));
        assert_ne!(
            first, second,
            "a daemon whose octet is already held must re-derive to a different one"
        );
    }

    /// A microVM daemon never persists an identity: its octet is always
    /// derived from the per-start id, because the guest does not own its
    /// switch.
    #[cfg(target_os = "linux")]
    #[test]
    fn microvm_daemon_never_persists_identity() {
        let dir = TempDir::new().unwrap();
        let state_dir = DaemonAbsPath::try_new(
            camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
        )
        .unwrap();
        let first = native_switch_octet(true, Some(&state_dir), "per-start-id");
        let second = native_switch_octet(true, Some(&state_dir), "different-per-start-id");
        assert_ne!(
            first, second,
            "a microVM daemon must derive its octet from the per-start id, not a persisted identity"
        );
        // The identity file must not have been written.
        let identity_path = state_dir
            .as_utf8_path()
            .as_std_path()
            .join(DAEMON_IDENTITY_FILE);
        assert!(
            !identity_path.exists(),
            "a microVM daemon must not persist a daemon identity"
        );
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
    /// switch the guest does not own.
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
            .find(|l| l.contains("reserved_loopback=") && l.contains(&format!("daemon_id={id}")))
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
        // The published-address half the octet no longer touches: the pool a
        // daemon's boxes are granted from is the host's one pool, the same
        // for a VM daemon as for every native one, whatever octet either
        // carries (NET-010 — allocation is the answerer's, never the
        // daemon's).
        assert!(
            line.contains("reserved_loopback=127.0.64.2-127.0.64.254"),
            "a daemon's published boxes come from this host's one pool, \
             got: {line}"
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

    /// NET-059's publish half for the answerer, driven from the success
    /// side: the host already holds the bound port's number — another VM's
    /// publication — so this daemon's answerer publishes on the next rung of
    /// its own, the port the host's resolver reaches is the rung it landed
    /// on, and the socket keeps the documented default this VM's own boxes
    /// query its loopback on. The walk is the proxies' — the socket is never
    /// rebound — so both halves of the host's hostname surface follow one
    /// rule, and two VMs' answerers can serve their zones on one host at
    /// once, each on a port of its own.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_walked_answerer_publication_keeps_the_bind_and_reports_the_rung() {
        use std::net::{IpAddr, Ipv4Addr};

        use ::sessions::SessionId;
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::rr::RecordType;

        use crate::net::answerer::{AnswerScope, ZoneAnswerer, encode_query};

        // A free port stands in for the documented default, with a free rung
        // above it for the walk to land on.
        let (default_port, rung) = loop {
            let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let Some(rung) = next_host_publish_port(port) else {
                continue;
            };
            match std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, rung)) {
                Ok(rung_probe) => drop(rung_probe),
                Err(_) => continue,
            }
            break (port, rung);
        };

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

        // The forwarder's ledger with the default already held — the host
        // loopback as a second VM's daemon finds it.
        let held = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::from([
            default_port,
        ])));

        let answerer = ZoneAnswerer::new(hostnames, AnswerScope::Native);
        drive_answerer_until_serving(
            state.clone(),
            answerer,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            ProxyPort::DefaultThenSelect {
                default: default_port,
            },
            true,
            HostExpose::HeldPorts(held),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;

        // The port the host's resolver reaches is the rung the publication
        // landed on.
        assert_eq!(
            state.zone_answerer_port().await,
            Some(rung),
            "a refused answerer publication must land on a host port of its own, log: {}",
            buf.contents()
        );

        // The socket never moved: the documented default still answers a
        // real exchange — the in-guest surface this VM's own boxes reach, at
        // the port they were promised.
        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = encode_query("web.min.internal.", RecordType::A);
        let mut scratch = [0u8; 512];
        let mut reply = None;
        for _ in 0..200 {
            client
                .send_to(
                    &query,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), default_port),
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
        let bytes =
            reply.expect("the answerer must keep answering on the port it bound through the walk");
        let reply = Message::from_vec(&bytes).expect("the reply decodes");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);

        // The relocation and the publication are named in the log, with both
        // ports — the diagnostics answer to "where on the host is this VM's
        // answerer".
        let logged = buf.contents();
        assert!(
            logged.contains("relocated"),
            "a walked publication must say so, got: {logged}"
        );
        assert!(
            logged.contains("box-zone answerer is published on the host loopback"),
            "the publication must be named in the log, got: {logged}"
        );
        assert!(
            logged.contains(&format!("host_port={rung}")),
            "the publication line must name the host port it landed on, got: {logged}"
        );
        assert!(
            logged.contains(&format!("guest_port={default_port}")),
            "the publication line must name the guest port beside it, got: {logged}"
        );
    }
}
