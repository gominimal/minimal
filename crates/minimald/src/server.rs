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

use crate::box_manager;
use crate::connection::{Connection, ConnectionHandle};

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

    /// The daemon's opt-out of the deny-all egress default (NET-077). With
    /// the default in force (see [`boxes::EGRESS_DEFAULT_PHASE`]), an
    /// own-address box created with no `egress` section reaches nothing
    /// outside itself (NET-074) and shows `deny-all (default)` in
    /// `min session policy` (NET-075). A deployment that cannot carry that
    /// yet opts out, and its boxes keep the earlier allow-all default of
    /// 03-spec R2.1. Set by `minimald run --egress-deny-all-opt-out`. A box
    /// that declares its own egress section keeps its declared lists either
    /// way; the opt-out also keeps the earlier allow-all reading of a
    /// destination list the section left absent, which in force resolves to
    /// present and empty (`boxes::effective_egress`).
    #[serde(default)]
    pub deny_all_opt_out: bool,
    /// How the create gate learns the host's verdict on the unprivileged
    /// user namespace every session sandbox starts by unsharing (NET-141).
    /// Never persisted or handed in: the daemon binary decides it at start
    /// (live, or off under `MINIMALD_USERNS_GATE=off`), and the test harness
    /// fixes it per server.
    #[serde(skip)]
    pub user_namespace_gate: UsernsGate,
}

/// This daemon's own binary path, for the user-namespace remedy that names
/// it (the AppArmor profile attaches by path, so a source-built daemon needs
/// the loader pointed at this path, not the installed one). A placeholder
/// when the path cannot be read, so the remedy still shows its shape.
#[must_use]
pub fn this_daemon_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| "<path to this minimald>".to_string())
}

/// The verdict [`UsernsGate::Fixed`] carries, re-exported so the daemon
/// binary and the harness-driven tests name it without a `sandbox`
/// dependency of their own.
pub use sandbox::UsernsRestriction;

/// Where the create gate's user-namespace verdict comes from (NET-141).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsernsGate {
    /// Probe this process on every create — a few `/proc` reads — so a
    /// remedy applied to the running host (a sysctl made persistent) takes
    /// effect at the next create, with no restart. The production default.
    #[default]
    Live,
    /// Never refuse. The operator's escape hatch for a false positive, and
    /// the harness default: the harness runs unconfined on a restricted host
    /// without ever starting a sandbox, so a live probe there would refuse
    /// creates that are not about this gate at all.
    Off,
    /// Answer with this verdict, whatever the host says: the seam the gate's
    /// own tests refuse a create through.
    Fixed(UsernsRestriction),
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

    /// Run the release: the file layer off, the appender flushed and closed.
    /// Once, at shutdown ([`ServerStateHandle::release_log`]), or by a test of
    /// the binary's `DaemonLogger` that wants to read what the file holds.
    pub fn run(self) {
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
    sessions: box_manager::BoxManagerHandle,
    daemon_id: String,

    /// The daemon-scoped gvproxy switch, cloned beside the copy the sessions
    /// manager owns, so daemon-level startup work that runs after the manager
    /// took its copy — [`HostProxyStartup::record_bound`] — can update the
    /// switch's hostname-proxy port to the port the proxy actually bound.
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

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
        // gvproxy runs for the host and a single allocator hands each address
        // to one live attach at a time (R1.4/R1.6). Its config/socket/pid
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
        // When the bind lands elsewhere (an OS-chosen port, NET-025), the
        // opening is re-pointed to the port actually bound once the proxy is
        // bound (see `record_bound`). Every seed — a pinned port included —
        // is pending until that bind is recorded, and a box waits for it: a
        // pinned port never relocates (NET-024: a busy one is retried, not
        // moved), but while it retries another host process holds it, so an
        // opening compiled from the seed would let a box reach that foreign
        // process (design §7.1's parity rule). The pinned OS-picks `0` names
        // no port until bound, so it is marked pending without a seed, and a
        // box waits rather than reading "no port known" as "no proxy on this
        // host". On Linux a proxy bind is always pending (the daemon always
        // starts one).
        #[cfg(target_os = "linux")]
        let (hostname_proxy_port, hostname_proxy_pending) = (
            ProxyPort::from_config(
                config.hostname_proxy_port,
                crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            )
            .opening_port(),
            true,
        );
        #[cfg(not(target_os = "linux"))]
        let (hostname_proxy_port, hostname_proxy_pending) = (None, false);
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
            .with_hostname_proxy_port(hostname_proxy_port)
            .with_hostname_proxy_pending(hostname_proxy_pending),
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
                first = ::boxes::core::loopback::POOL_FIRST,
                last = ::boxes::core::loopback::POOL_LAST
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
            sessions: box_manager::BoxManager::init(
                minimal_state_dir,
                minimal_cache_dir,
                Arc::clone(&daemon_ctx),
                Arc::clone(&net_switch),
                // Threaded into every session actor so the launcher and the
                // task path resolve the same effective egress the daemon
                // was started with (NET-074/NET-077).
                config.deny_all_opt_out,
            )
            .await?,
            config,
            daemon_id,
            net_switch,
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
    pub async fn sessions_manager(&self) -> box_manager::BoxManagerHandle {
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

    /// The host's user-namespace verdict the create gate decides on
    /// (NET-141), per [`Config::user_namespace_gate`]: probed live from this
    /// process on each call, so nothing is cached across creates; the lock
    /// is held for the copy of the gate alone, never across the probe.
    pub(crate) async fn user_namespace_verdict(&self) -> Option<UsernsRestriction> {
        // Bound first so the guard is dropped before the probe runs; the
        // match scrutinee would otherwise hold it across the `/proc` reads.
        let gate = self.0.lock().await.config.user_namespace_gate;
        match gate {
            UsernsGate::Live => sandbox::user_namespaces_restriction(),
            UsernsGate::Off => None,
            UsernsGate::Fixed(restriction) => Some(restriction),
        }
    }

    /// Re-points the gate on a harness server: the seam the create-gate
    /// tests refuse a create through ([`UsernsGate::Fixed`]) and clear again
    /// ([`UsernsGate::Off`]), scoped to this server alone.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn set_user_namespace_gate(&self, gate: UsernsGate) {
        self.0.lock().await.config.user_namespace_gate = gate;
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

    /// Re-points the switch's node-address opening to the port the proxy
    /// actually bound — distinct from [`Self::hostname_proxy_port`], which
    /// carries the port a *client* dials. Boxes reach the bound port on the
    /// loopback they share with the daemon, so their own-address openings
    /// compile from it, not the configured port the daemon may have moved off.
    #[cfg(target_os = "linux")]
    pub(crate) async fn set_switch_hostname_proxy_port(&self, port: u16) {
        let switch = Arc::clone(&self.0.lock().await.net_switch);
        let stranded = switch.lock().await.set_hostname_proxy_port(Some(port));
        if stranded > 0 {
            tracing::warn!(
                port,
                stranded,
                "the hostname proxy now serves on port {port}, but {stranded} box(es) \
                 attached while it was not serving were compiled with no node-address \
                 opening (design §7.1); restart those sessions to reach the hostname proxy"
            );
        }
    }

    /// The port the hostname proxy listens on, or `None` while it is still
    /// coming up. Filled on the `ListSessions` and `CreateSession` replies
    /// so a client can print — and point `HTTP(S)_PROXY` at — the port this
    /// daemon is on (NET-026).
    pub(crate) async fn hostname_proxy_port(&self) -> Option<u16> {
        self.0.lock().await.hostname_proxy_port
    }

    /// The switch's hostname-proxy port — the node address's interim opening
    /// every box's own-address set compiles (design §7.1).
    #[cfg(test)]
    async fn switch_hostname_proxy_port(&self) -> Option<u16> {
        let switch = Arc::clone(&self.0.lock().await.net_switch);
        switch.lock().await.hostname_proxy_port()
    }

    /// The daemon's shared gvproxy switch, for tests that drive the
    /// attach path's serving transition against it.
    #[cfg(test)]
    async fn test_switch(&self) -> Arc<Mutex<crate::net::SwitchClient>> {
        Arc::clone(&self.0.lock().await.net_switch)
    }

    /// Records the port the box-zone answerer actually listens on (UDP),
    /// once its startup has bound (and, in a microVM, published) it.
    pub(crate) async fn set_zone_answerer_port(&self, port: u16) {
        self.0.lock().await.zone_answerer_port = Some(port);
    }

    /// Forgets the answerer's port: nothing this daemon can name answers
    /// for it now (a publish whose service bind could not be read).
    pub(crate) async fn clear_zone_answerer_port(&self) {
        self.0.lock().await.zone_answerer_port = None;
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

    /// The daemon's identity dir — the provider instance dir it runs under,
    /// whose canonical path is the node id its channel client publishes
    /// under (`main`'s `client_instance_dir`). `None` for a daemon with no
    /// identity dir configured (a harness server): its node id falls back
    /// to the state dir, unique to the instance all the same.
    pub(crate) async fn daemon_identity_dir(&self) -> Option<DaemonAbsPath> {
        self.0.lock().await.config.daemon_identity_dir.clone()
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

/// How long a freshly accepted connection may spend exchanging SSH id lines
/// before it is dropped. The id-line exchange is the only pre-auth step that
/// `russh::server::run_stream` awaits, so a client that connects and never
/// speaks would otherwise hold its task and socket forever. Later stalls in
/// KEX or auth run in russh's spawned session task, off the accept loop, and
/// are governed by keepalive rather than by this deadline.
const HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

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

        // Bring up the actor of every active session restored from the
        // store, so each one's box name routes from daemon start rather than
        // from the first RPC that names the session. Enqueued here, before
        // the accept loop opens, so the manager's mailbox orders it ahead of
        // every RPC the loop admits; only the answer is awaited off the
        // accept path.
        #[cfg(target_os = "linux")]
        {
            let resumed = state
                .sessions_manager()
                .await
                .enqueue_resume_active_sessions()
                .await;
            crate::traced::spawn(async move {
                if let Err(error) = resumed.await {
                    tracing::warn!(
                        %error,
                        "could not resume active sessions at daemon start; their names \
                         register when an RPC first names each session",
                    );
                }
            });
        }

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
            // The handshake runs in the spawned task, not here: awaiting it in
            // the loop would serialize accepts behind each client's id line,
            // so one slow or silent client could stall the whole daemon.
            let russh_config = russh_config.clone();
            let state = state.clone();
            let handshake_span = span.clone();
            session_set.spawn(
                async move {
                    let from_stream =
                        Connection::from_stream(stream, russh_config, state.clone(), L::IS_LOCAL);
                    let (conn_hnd, session_fut) =
                        match tokio::time::timeout(HANDSHAKE_DEADLINE, from_stream)
                            .instrument(handshake_span.clone())
                            .await
                        {
                            Ok(Ok(conn)) => conn,
                            Ok(Err(e)) => {
                                // A handshake failure must not take the daemon
                                // down — in the guest minimald is pid-1. Drop
                                // this connection and keep accepting.
                                handshake_span.in_scope(|| {
                                    tracing::warn!(
                                        error = %e,
                                        "SSH handshake failed; dropping connection"
                                    )
                                });
                                return;
                            }
                            Err(_) => {
                                handshake_span.in_scope(|| {
                                    tracing::warn!("SSH handshake timed out; dropping connection")
                                });
                                return;
                            }
                        };
                    // Log session errors instead of silently dropping the
                    // spawned future, so a failed handshake is visible on any
                    // transport.
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
                    close_connection(&state, &conn_hnd).await;
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

/// Wall-clock budget for tearing down a connection whose transport has
/// stopped making progress — a full keepalive cycle plus one interval, so
/// an otherwise-quiet but healthy attach (which answers each keepalive,
/// resetting the clock) is never reaped: a healthy idle attach sees a
/// keepalive every [`KEEPALIVE_INTERVAL`], long before this fires.
const INACTIVITY_TIMEOUT: std::time::Duration =
    KEEPALIVE_INTERVAL.saturating_mul(KEEPALIVE_MAX as u32 + 1);

/// Builds the shared russh server config from the server state.
async fn build_russh_config(
    state: &ServerStateHandle,
) -> Result<Arc<russh::server::Config>, KeyError> {
    Ok(Arc::new(russh::server::Config {
        keys: vec![state.host_key().await?],
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        nodelay: true,
        // Keepalives own deadness detection, so this must never reap an
        // idle-but-alive attach (the default 600s would). But russh bounds
        // every transport write by the inactivity timer, and with `None` a
        // wedged write parks the session loop forever — keepalives are
        // dispatched from that same loop, so they stop firing too and the
        // connection outlives every budget. Arming it at the keepalive
        // budget bounds a stuck transport without touching a healthy one.
        inactivity_timeout: Some(INACTIVITY_TIMEOUT),
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Default::default()
    }))
}

/// Finishes a connection that is gone. Reaps any session it created that
/// never reached `Active` — a client that dropped mid-activation (Ctrl-C at
/// the gating prompt, a crash, a network blip) would otherwise strand a
/// `Pending` / `Materializing` session that holds its name hostage — and only
/// then ends the connection's liveness.
///
/// The order is the point. A session's creator-only attach gate holds while
/// its creator's liveness does, so ending it before the reap would open the
/// gate on a `Draft` the reap is about to delete: an attach from another
/// connection landing in between would configure the half-uploaded workspace
/// and, if it reached `Active` before the reap read the status, leave the
/// session alive behind a layout conflict no retry clears. Held until the
/// reap is done, the gate refuses that attach, and what the reap leaves
/// behind is either gone or was never the creator's to finish.
async fn close_connection(state: &ServerStateHandle, conn: &ConnectionHandle) {
    let created = conn.take_created_sessions().await;
    #[cfg(test)]
    reap_seam::park(&created).await;
    reap_unfinalized_sessions(state, created).await;
    conn.release_liveness().await;
}

/// The test seam for the window between a closed connection's teardown
/// starting and its reap: a test holds one session id, and the teardown of
/// the connection that created it parks just before the reap until the test
/// lets it go. Keyed by session id, like the session actor's seams, so tests
/// running beside each other in one process never park each other's
/// teardowns.
#[cfg(test)]
mod reap_seam {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use ::boxes::SessionId;
    use tokio::sync::oneshot;

    type Hold = (oneshot::Sender<()>, oneshot::Receiver<()>);

    static HELD: Mutex<Option<HashMap<SessionId, Hold>>> = Mutex::new(None);

    /// Makes the teardown that would reap `id` park before its reap. The
    /// first half resolves once it has parked; sending on (or dropping) the
    /// second lets it go on.
    pub(super) fn hold(id: SessionId) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (parked, on_parked) = oneshot::channel();
        let (release, on_release) = oneshot::channel();
        HELD.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(id, (parked, on_release));
        (on_parked, release)
    }

    /// Parks for each of `ids` a test holds, until that test releases it.
    pub(super) async fn park(ids: &[SessionId]) {
        for id in ids {
            let held = HELD
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .and_then(|held| held.remove(id));
            if let Some((parked, on_release)) = held {
                let _ = parked.send(());
                let _ = on_release.await;
            }
        }
    }
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
#[tracing::instrument(level = "info", name = "sessions.reap_unfinalized", skip_all, fields(count = ids.len()))]
async fn reap_unfinalized_sessions(state: &ServerStateHandle, ids: Vec<::boxes::SessionId>) {
    if ids.is_empty() {
        return;
    }
    let mngr = state.sessions_manager().await;
    // Behind a VM host daemon the client's registration lease closed with
    // its connection, and the host withdrew the box's row on that close. A
    // session kept here would run with no row: its name would not resolve,
    // and the host could hand its addresses to another box. Nothing in the
    // VM can publish the row again, so here a finished session is reaped as
    // an unfinished one is. A native daemon has no such row, and keeps it.
    let keep_finished = !state.in_microvm().await;
    for id in ids {
        // Re-read the status at teardown: a clean client abort already
        // deleted the record (`get_record` → `None`), and a finalized
        // session is `Active` — neither should be reaped here.
        let status = match mngr.get_record(box_manager::BoxKeyPredicate::Id(id)).await {
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
            ::boxes::BoxState::Pending | ::boxes::BoxState::Materializing
        ) {
            continue;
        }
        // Only if still unfinished when the session gets to it: a finalize
        // already in flight ends first, and a session it finished is kept
        // (inbox#690's reap half) — on a native daemon; see above.
        let reaped = if keep_finished {
            mngr.delete_session_if_unfinalized(id).await
        } else {
            mngr.delete_session(id).await.map(Some)
        };
        match reaped {
            Ok(Some(_)) => tracing::info!(
                session_id = %id,
                ?status,
                "reaped unfinalized session after its connection closed"
            ),
            Ok(None) => tracing::info!(
                session_id = %id,
                "kept a session whose connection closed: it finished activating first"
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
/// ([`drive_proxy_until_serving`], NET-021) and then clears the unavailable
/// note `min ls` warns from (NET-022). Nothing here is awaited: a listener
/// whose port some other process holds must not hold the SSH accept loop
/// hostage — the daemon starts serving regardless, reports the reason on its
/// state, and the listener comes up on its own once the address frees.
///
/// The answerer's native startup is not a bind at all but the acquisition
/// ([`crate::net::answerer::acquire`], NET-122): the same detached rule, a
/// different decision — publish this daemon's rows into the manager-held
/// answerer over the machine-global channel, host the interim only while
/// nothing serves, never both — described at its own site.
#[cfg(target_os = "linux")]
async fn start_host_proxies(
    state: &ServerStateHandle,
    in_microvm: bool,
    hostname_proxy_port: Option<u16>,
    zone_answerer_port: Option<u16>,
) {
    use std::net::{IpAddr, Ipv4Addr};

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
    crate::traced::spawn(drive_proxy_until_serving(
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
    // `*.min.internal` (design §7.1, NET-009).
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
    // Native (NET-122): the zone is answered by the machine's *one*
    // answerer, and this daemon is its client before it is its host. The
    // acquisition below decides publish-or-host — publish this daemon's
    // rows into the manager-held `minzoned` service over the
    // machine-global channel when its channel answers, host the
    // single-operator interim itself only while no channel answers and
    // the hook port is free, never both — and its status cell feeds the
    // control socket beside it, the same door `minvmd`'s answerer serves
    // its own release handover on. The bind is the hook port the
    // deployment pinned (NET-024) or the answerer's documented default;
    // unlike the proxies there is no select-when-busy for the answerer
    // (the port is the address the host's resolver is routed to, and a
    // second one beside it answers nothing the first would not), so a
    // held hook port is a surfaced error, never a move.
    let answerer_status = crate::net::answerer::AnswererStatus::starting();
    if let Err(error) = crate::rpc::spawn_answerer_control(state, answerer_status.clone()).await {
        tracing::warn!(
            component = "zone-answerer",
            %error,
            "could not bind the answerer control socket; release and release-cancel requests \
             will not reach this daemon"
        );
    }
    let hook_port = zone_answerer_port.unwrap_or(crate::net::answerer::ANSWERER_PORT);
    crate::traced::spawn(crate::net::answerer::acquire(
        state.clone(),
        hook_port,
        answerer_status,
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
            Self::Egress { .. } => crate::traced::spawn(async move {
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
            Self::Egress { .. } => {
                tracing::info!(
                    component = self.component(),
                    port = bound_port,
                    port_source = source.as_str(),
                    status = "serving",
                    "hostname proxy is serving on its {} port",
                    source.as_str()
                );
                state.set_hostname_proxy_port(reported_port).await;
            }
        }
    }

    /// Points the switch's node-address opening at the port the listener
    /// bound, the moment it is bound and its serve loop spawned — before any
    /// host publication, which serves a *host* client, not this daemon's
    /// boxes: they reach the bound port on the loopback they share with the
    /// daemon, so a publish still retrying (or terminally refused) never
    /// holds a box's opening back. This is the switch's serving transition
    /// ([`crate::net::hostname_proxy_serving_port`] waits for it), and the
    /// one place it happens: the listener is never rebound.
    async fn record_bound(&self, state: &ServerStateHandle, bound_port: u16) {
        match self {
            Self::Egress { port, .. } => {
                note_switch_opening_moved(port.opening_port(), bound_port);
                // The switch's node-address opening follows the port this
                // daemon's boxes reach on the loopback they share with it —
                // the bound port — so an unpinned daemon whose default was
                // busy compiles its own-address boxes at the port it
                // actually landed on, not the configured one it moved off.
                state.set_switch_hostname_proxy_port(bound_port).await;
            }
        }
    }
}

/// Logs, once at the proxy's startup, when the port it bound is not the
/// port the switch's node-address opening was built with (design §7.1): an
/// unpinned daemon that found the default busy and took an OS-chosen port,
/// or a pinned `0`. The opening is re-pointed to the bound port, but a box
/// reads it once, when it attaches, so a box that attached before the proxy
/// was serving keeps the old opening until it reattaches or restarts.
/// Returns whether it logged.
#[cfg(target_os = "linux")]
fn note_switch_opening_moved(opening: Option<u16>, bound_port: u16) -> bool {
    if opening == Some(bound_port) {
        return false;
    }
    let opening = opening.map_or_else(|| "none".to_string(), |port| port.to_string());
    tracing::warn!(
        bound_port,
        opening_port = %opening,
        "hostname proxy bound port {bound_port}, not the switch opening's port \
         {opening}: boxes attached from now on compile the opening at port \
         {bound_port}; a box attached earlier cannot reach the hostname proxy \
         until it reattaches or restarts"
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
                            proxy.record_bound(&state, bound_port).await;
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
                crate::traced::spawn(report_proxy_serving(host_port));
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
                    crate::traced::spawn(report_proxy_port_held(host_port));
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
/// routing proxies take ([`drive_proxy_until_serving`], NET-021). Retained
/// for the test helpers that hold an address and watch the retry recover
/// ([`retry_zone_answerer_until_serving`], and the tests that drive it
/// directly): the daemon's own answerer start is the acquisition now
/// (NET-122, [`crate::net::answerer::acquire`]), which decides
/// publish-or-host over the machine-global channel instead of binding
/// unconditionally, so nothing in a production daemon's start reaches
/// this drive.
///
/// Binds at
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
#[cfg(any(test, feature = "test-support"))]
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
                        drop(crate::traced::spawn(async move {
                            if let Err(error) =
                                crate::net::answerer::serve(socket, serve_answerer).await
                            {
                                tracing::error!(
                                    component = COMPONENT,
                                    %error,
                                    "box-zone answerer receive loop exited"
                                );
                            }
                            // The answerer no longer serves: a carve-out that
                            // named its bind now names nothing (NET-079).
                            crate::net::classifier::clear_live_answerer();
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
    // The live bind a native table's resolver carve-out must name (NET-079):
    // the address and port the socket actually bound, beside the port the
    // RPC discovery field carries.
    crate::net::classifier::set_live_answerer(SocketAddr::new(bind_base, bound_port));
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
        // A unit-test daemon never starts a sandbox, and the host it runs on
        // may itself be restricted: the gate stays off unless a test fixes it.
        user_namespace_gate: UsernsGate::Off,
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "upstream's tests spawn plain tokio tasks; the traced-spawn rule is for request handling"
)]
mod tests;
