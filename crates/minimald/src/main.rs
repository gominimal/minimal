//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use paths::{CwdRelative, Daemon, DaemonAbsPath, sub_path};
use std::io::Write as _;
use tokio::{net::UnixListener, runtime::Builder};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use minimald::server::{Config, HostKey, Server};

#[cfg(target_os = "linux")]
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

/// Base AF_VSOCK port the guest relay listens on when in vsock mode.
///
/// The actual port is `DEFAULT_VSOCK_PORT_BASE` + `instance_num`.
#[cfg(target_os = "linux")]
const DEFAULT_VSOCK_PORT_BASE: u32 = 2222;

/// Env var `spawn_detached` sets on the child so `async_main` knows
/// its stdio has been redirected to `/dev/null` and needs to swap
/// the tracing writer over to a rolling log file.
const DETACHED_ENV: &str = "MINIMALD_DETACHED";

#[derive(Parser)]
#[command(name = "minimald", version = env!("CARGO_PKG_VERSION"), long_version = env!("LONG_VERSION"))]
#[command(about = "The Minimal daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

impl Cli {
    /// Returns the path to the minimal-dir (base directory for state)
    /// based on command-line arguments.
    pub fn minimal_state_dir(&self) -> DaemonAbsPath {
        match &self.global_args.minimal_state_dir {
            Some(p) => p
                .resolve()
                .expect("could not resolve --minimal-state-dir against the current directory"),
            None => paths::minimal_state_dir(),
        }
    }

    /// Returns the path to base directory for caching
    /// based on command-line arguments.
    pub fn minimal_cache_dir(&self) -> DaemonAbsPath {
        match &self.global_args.minimal_cache_dir {
            Some(p) => p
                .resolve()
                .expect("could not resolve --minimal-cache-dir against the current directory"),
            None => paths::minimal_cache_dir(),
        }
    }

    fn listen_args(&self) -> Option<&ListenArgs> {
        match &self.command {
            Command::Run(a) => Some(a),
            _ => None,
        }
    }

    fn instance_num(&self) -> u32 {
        self.listen_args().map(|a| a.instance_num).unwrap_or(0)
    }

    /// Returns the path to the directory containing sockets/info about this daemon for clients.
    pub fn client_instance_dir(&self) -> DaemonAbsPath {
        paths::provider_instance_dir(&self.minimal_state_dir(), self.instance_num())
    }

    /// Returns fragments of the command-line arguments which should be passed to an ssh invocation in
    /// order to connect to the UDS socket.
    ///
    /// The first argument is a list of SSH options and their values, the second is the name of
    /// the ssh server.
    pub fn ssh_args(&self) -> (Vec<(&'static str, String)>, String) {
        (
            vec![
                (
                    "ProxyCommand",
                    if cfg!(target_os = "macos") {
                        format!("nc -U {}", self.listen_on())
                    } else {
                        format!("socat - UNIX-CONNECT:{}", self.listen_on())
                    },
                ),
                (
                    "UserKnownHostsFile",
                    sub_path!(self.client_instance_dir(), "known_hosts")
                        .as_utf8_path()
                        .to_string(),
                ),
            ],
            format!("local-{}", self.instance_num()),
        )
    }

    /// Returns the path to the UDS socket we should listen on.
    pub fn listen_on(&self) -> DaemonAbsPath {
        self.client_instance_dir()
            .sub_path_unchecked(paths::SSH_SOCK_FILE)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the minimal daemon.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimal completions bash)"
    )]
    Completions(CompletionsArgs),
    /// Runs the minimald server in the foreground.
    Run(ListenArgs),
}

/// The arguments for the completions subcommand.
#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    shell: Shell,
}

/// Shared arguments for all subcommands.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Override the directory where state is stored (default: $XDG_STATE_DIR/minimal)
    #[arg(long, alias = "minimal_dir")]
    minimal_state_dir: Option<CwdRelative<Daemon>>,
    /// Override the directory where artifacts are cached (default: $XDG_CACHE_DIR/minimal)
    #[arg(long)]
    minimal_cache_dir: Option<CwdRelative<Daemon>>,

    /// Load the minimal standard library from the given path instead
    #[arg(long)]
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    stdlib_dir: Option<CwdRelative<Daemon>>,

    /// Configure the number of parallel builds
    #[arg(short, long, global = true)]
    num_parallel_builds: Option<usize>,
}

/// Arguments describing where minimald should listen for connections.
#[derive(Debug, Args)]
pub struct ListenArgs {
    /// Instance number for this minimald; determines client-relevant paths under
    /// `<minimal_state_dir>/providers/local-<instance-num>`.
    ///
    /// The SSH socket is accessible as `ssh.sock`.
    #[arg(long, default_value_t = 0)]
    instance_num: u32,

    /// Host the SSH socket over vsock instead of UDS.
    ///
    /// The vsock port will be `DEFAULT_VSOCK_PORT_BASE` + `instance_num`.
    #[arg(long, default_value_t = false)]
    vsock: bool,

    /// Mount `/dev`. Only useful if minimald is a VM's init process.
    #[arg(long, default_value_t = false)]
    #[clap(hide = true)]
    mount_dev: bool,

    /// Mounts the given device as the rootfs and pivot to it. This also mounts
    /// standard puesdo-filesystems in the / including proc, sys, dev, and run.
    #[arg(long)]
    #[clap(hide = true)]
    mount_rootfs: Option<String>,

    /// Device to format-on-first-boot + mount as the writable state volume at
    /// `/var/lib/minimal` when running as a microVM init (R1.5/R1.6). When set
    /// and the mount succeeds, cache + state are relocated onto it. Only useful
    /// as a VM init process; `None` leaves state on the tmpfs default.
    #[arg(long)]
    #[clap(hide = true)]
    mk_mount_state_volume: Option<String>,

    /// Daemonize: spawn minimald in a new session (setsid) and return once the
    /// SSH socket accepts connections, or an 8s timeout elapses. Used by the
    /// `minimal` CLI to auto-start a native (DM2) daemon on Linux.
    #[arg(long, default_value_t = false)]
    detach: bool,

    /// Path to the gvproxy ("gvisor-tap-vsock") binary backing the per-host
    /// `OwnIp` switch. Defaults to the fixed system install path when unset;
    /// point it at a local build to run own-IP (DM2) without a system install.
    #[arg(long)]
    gvproxy_bin: Option<std::path::PathBuf>,
}

/// An error at the top level of minimald.
#[derive(Debug)]
pub enum MainError {
    IO(std::io::Error, &'static str),
    Other(String),
}

impl From<russh::keys::ssh_key::Error> for MainError {
    fn from(value: russh::keys::ssh_key::Error) -> Self {
        Self::Other(format!("ssh key: {value}"))
    }
}
impl From<russh::keys::Error> for MainError {
    fn from(value: russh::keys::Error) -> Self {
        Self::Other(format!("ssh key: {value}"))
    }
}

/// Open (creating if absent) a lock file; only its fd matters, for flock.
fn open_lock_file(path: impl AsRef<std::path::Path>) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
}

fn main() -> Result<(), MainError> {
    let runtime = Builder::new_multi_thread()
        .thread_name("minimald-worker")
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async_main());

    // As the microVM's pid-1 we must not return: exiting init panics the guest
    // kernel and wedges the VM (#730). Take the VM down instead — a clean
    // shutdown (the `Shutdown` RPC drained the server) and a failed one alike,
    // since either way there is no init left to run. Diverges on success.
    #[cfg(target_os = "linux")]
    if is_minimal_microvm() {
        match &result {
            Ok(()) => tracing::info!("microVM init finished; shutting the VM down"),
            Err(e) => tracing::error!(error = ?e, "microVM init failed; shutting the VM down"),
        }
        let error = minimald::guest::shut_down_vm();
        // Unreachable in practice — `reboot(2)` only fails for a caller without
        // CAP_SYS_BOOT, and the microVM's pid-1 has it. But falling through to
        // `return result` would exit init and panic the guest kernel, which is
        // the wedge #730 is about; never trade one wedge for another. Park
        // instead, as the boot path's degraded arms do: the kernel stays alive
        // and idle (no panic-handler spin), the console keeps working, and
        // `minvmd stop`'s SIGTERM can still reap the VMM.
        tracing::error!(%error, "shutting the VM down failed; parking pid-1 (exiting it would panic the guest kernel)");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    result
}

/// Re-exec this binary in a new session (`setsid`) with `--detach` stripped, so
/// the child runs the foreground server fully detached from the caller's
/// controlling terminal, then poll the SSH socket until it accepts connections.
/// Mirrors `minvmd run --detach`.
fn spawn_detached(cli: &Cli) -> Result<(), MainError> {
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};

    const DETACH_TIMEOUT_SECS: u64 = 8;

    let exe = std::env::current_exe().map_err(|e| MainError::IO(e, "resolving current exe"))?;
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--detach")
        .collect();
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // Mark the child so `async_main` knows its stdio has been
        // null'd and can route tracing output to a log file instead.
        .env(DETACHED_ENV, "1");
    // SAFETY: setsid() is async-signal-safe. In the child it starts a new
    // session so the daemon outlives the CLI and is unaffected by SIGHUP when
    // the invoking shell exits.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| MainError::IO(e, "spawning detached minimald"))?;

    // Ready = socket connectable AND a native minimald holds the instance
    // lock. ssh.sock is shared with the minvmd bridge, so a bare connect can
    // be satisfied by a live peer backend while our child's bail goes to
    // /dev/null. A child exit surfaces as an error instead of a timeout.
    let sock = cli.listen_on();
    let sock_path = std::path::Path::new(sock.as_utf8_path().as_str());
    let lock_path = cli
        .client_instance_dir()
        .sub_path_unchecked(paths::MINIMALD_LOCK_FILE);
    let deadline = Instant::now() + Duration::from_secs(DETACH_TIMEOUT_SECS);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| MainError::IO(e, "polling detached minimald"))?
        {
            return Err(MainError::Other(format!(
                "detached minimald exited during startup ({status}); \
                 run without --detach to see the error"
            )));
        }
        if std::os::unix::net::UnixStream::connect(sock_path).is_ok()
            && lock_held(lock_path.as_utf8_path().as_std_path())
                .map_err(|e| MainError::IO(e, "probing instance lock"))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(MainError::Other(format!(
                "detached minimald did not start listening on {sock} within {DETACH_TIMEOUT_SECS}s"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether some process holds an exclusive advisory lock on `path`.
/// Read-only probe: a missing file means no holder.
fn lock_held(path: &std::path::Path) -> std::io::Result<bool> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match fd_lock::RwLock::new(file).try_read() {
        Ok(_guard) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e),
    }
}

/// Install the tracing subscriber. Foreground processes log to
/// stdout; detached daemons (marked by [`DETACHED_ENV`]) write to
/// `<state_dir>/logs/minimald.log`, daily-rotated. The returned
/// [`WorkerGuard`] must outlive the process — dropping it flushes
/// pending records and terminates the appender's worker thread.
///
/// [`WorkerGuard`]: tracing_appender::non_blocking::WorkerGuard
fn init_tracing(
    cli: &Cli,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>, MainError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    let detached = std::env::var_os(DETACHED_ENV).is_some();
    if !detached {
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(ot::StdoutWriter::new))
            .with(filter)
            .init();
        return Ok(None);
    }

    // Under `<state_dir>/logs/` so `<state_dir>` itself stays
    // dominated by the sockets, sessions, and providers it already
    // owns. `create_dir_all` is idempotent — subsequent daemon
    // starts don't churn.
    let log_dir = cli
        .minimal_state_dir()
        .as_utf8_path()
        .as_std_path()
        .join("logs");
    std::fs::create_dir_all(&log_dir)
        .map_err(|e| MainError::IO(e, "creating minimald log directory"))?;
    // Cap retained files so a long-running daemon doesn't accumulate
    // logs indefinitely. Two weeks is comfortably longer than the
    // usual "look at what happened yesterday" window and short enough
    // that the on-disk footprint stays bounded.
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("minimald.log")
        .max_log_files(14)
        .build(&log_dir)
        .map_err(|e| MainError::IO(std::io::Error::other(e), "building rolling log appender"))?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::registry()
        // ANSI colors only make sense on a terminal; a file logger
        // just gets noise from the escape sequences.
        .with(fmt::layer().with_ansi(false).with_writer(writer))
        .with(filter)
        .init();
    tracing::info!(
        log_dir = %log_dir.display(),
        "detached minimald: routing tracing output to daily-rotated log file",
    );
    Ok(Some(guard))
}

async fn async_main() -> Result<(), MainError> {
    // With `networking-proxy` on, both the `ring` (workspace rustls) and the
    // `aws-lc-rs` (google-cloud) providers are compiled in, so rustls cannot
    // auto-pick one and panics ("no process-level CryptoProvider") the first time
    // a config is built — e.g. when a session build reaches the remote-cache
    // HTTPS client, off the proxy's own install path. Install ring explicitly
    // here (idempotent; the proxy's later install no-ops). Without
    // networking-proxy only one provider is present and rustls auto-installs it.
    #[cfg(feature = "networking-proxy")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Use hardcoded configuration if we are the init process (`argv[0] == "/init"`), which
    // would indicate we are operating in a single-purpose micro-vm.
    //
    // If we are not the init process, we load our config from CLI args.
    let mut cli = if is_minimal_microvm() {
        Cli {
            command: Command::Run(ListenArgs {
                instance_num: 0,
                vsock: true,
                mount_dev: true,
                mount_rootfs: Some("/dev/vda".to_string()),
                mk_mount_state_volume: Some("/dev/vdb".to_string()),
                detach: false,
                // In-VM (DM1/3/4) the PTask attaches to the host gvproxy over the
                // vsock shuttle, so no in-guest gvproxy binary path is needed.
                gvproxy_bin: None,
            }),
            global_args: GlobalArgs {
                minimal_state_dir: Some(DaemonAbsPath::try_new("/run/minimal").unwrap().into()),
                minimal_cache_dir: Some(
                    DaemonAbsPath::try_new("/run/minimal/cache").unwrap().into(),
                ),
                num_parallel_builds: None,
                stdlib_dir: None,
            },
        }
    } else {
        Cli::parse()
    };

    // Handle non-{launch,run} commands.
    if let Command::Completions(CompletionsArgs { shell }) = cli.command {
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    // Initialize tracing. Foreground runs (or the parent-side of a
    // `--detach` re-exec) log to stdout. A child spawned by
    // `spawn_detached` has its stdio null'd — detectable via the
    // `MINIMALD_DETACHED` env var — so it routes tracing to a daily-
    // rotated log file under the state directory instead. `_log_guard`
    // is bound at function scope so the non-blocking appender's
    // worker survives for the daemon's entire lifetime; dropping it
    // would flush and terminate the appender prematurely.
    let _log_guard = init_tracing(&cli)?;

    let listen_args = cli.listen_args().unwrap();

    // Daemonize before doing any work: re-exec ourselves in a new session and
    // wait until the SSH socket is accepting connections, then return so the
    // caller (the `minimal` CLI autospawn) gets a clean ready/timeout result.
    if listen_args.detach {
        // `spawn_detached` polls `cli.listen_on()` (a UDS) for readiness, but a
        // `--vsock` child binds the vsock listener instead, so the UDS never
        // appears and the parent would always hit the 8s timeout while leaving a
        // detached child running. Reject the combination up front.
        if listen_args.vsock {
            return Err(MainError::Other(
                "--detach is only supported for Unix-socket listeners (not --vsock)".to_string(),
            ));
        }
        return spawn_detached(&cli);
    }

    // Handle setup specific to operating in a micro-vm.
    use minimald::guest;
    if listen_args.mount_dev {
        guest::mount_dev();
    }
    if let Some(root_dev) = &listen_args.mount_rootfs
        && let Err(e) = guest::enter_rootfs(root_dev)
    {
        tracing::warn!(error = %e, "no rootfs disk; initramfs READY-only");
        guest::mount_pseudo_filesystems();
        let _ = guest::emit_simple_ready_marker().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    // R1.5/R1.6: when the microVM config requested a data volume
    // (`mk_mount_state_volume`), format-on-first-boot + mount it and, on success,
    // relocate cache + state onto it so builds hardlinking from the cache stay on
    // one filesystem (the EXDEV fix). Relocation is gated on the mount succeeding:
    // pointing state at an unmounted /var/lib/minimal would land it on the
    // read-only rootfs.
    //
    // R2.4/R2.5: a mount failure is loud and terminal — emit MOUNT_FAILED
    // instead of READY and park. No code path substitutes the /run/minimal
    // tmpfs: session state is user data with no host copy, so a silent fallback
    // would serve a ghost READY over a VM that quietly loses everything on stop.
    let mut state_volume_mounted = false;
    if let Some(dev) = cli.listen_args().unwrap().mk_mount_state_volume.clone() {
        match guest::mount_state_volume(&dev, guest::STATE_VOLUME_MOUNTPOINT) {
            Ok(()) => {
                cli.global_args.minimal_state_dir = Some(
                    DaemonAbsPath::try_new(guest::STATE_VOLUME_MOUNTPOINT)
                        .unwrap()
                        .into(),
                );
                cli.global_args.minimal_cache_dir = Some(
                    DaemonAbsPath::try_new(format!("{}/cache", guest::STATE_VOLUME_MOUNTPOINT))
                        .unwrap()
                        .into(),
                );
                state_volume_mounted = true;
                tracing::info!(device = %dev, "cache + state relocated onto the data volume (/var/lib/minimal)");
            }
            // The MOUNT_FAILED beacon + park contract only makes sense with a
            // minvmd host watching the marker socket (the vsock transport);
            // a native daemon handed --mk-mount-state-volume must fail like
            // any other startup error instead of hanging forever.
            Err(e) if cli.listen_args().unwrap().vsock => {
                tracing::error!(error = %e, device = %dev, "data volume mount failed; refusing READY (R2.4)");
                if let Err(emit) = guest::emit_mount_failed_marker(&e.to_string()).await {
                    // The host will still fail this boot via its READY
                    // timeout; it just loses the mount-failure diagnosis.
                    tracing::error!(error = %emit, "emitting MOUNT_FAILED marker failed; host will see a READY timeout");
                }
                // Park like the no-rootfs degraded path above: exiting pid-1
                // tears the VMM down racing the host's marker read; the host
                // kills the child once it has consumed MOUNT_FAILED.
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            }
            Err(e) => {
                return Err(MainError::IO(e, "mounting the state volume"));
            }
        }
    }

    if let Err(e) = std::fs::create_dir_all(cli.minimal_state_dir())
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(MainError::IO(e, "creating minimal dir"));
    }

    // The host-key path lives under the instance dir; ensure it exists for
    // both the UDS and vsock paths.
    if let Err(e) = std::fs::create_dir_all(cli.client_instance_dir())
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(MainError::IO(e, "creating provider dir"));
    }

    // Single-instance guard, held for the daemon's lifetime (the kernel
    // releases it on death): a second minimald must not steal this
    // instance's socket.
    //
    // As the microVM's pid-1 the lock lives on the /run tmpfs, not the
    // provider dir: the provider dir sits on the persistent data volume, and
    // a lifetime-held write fd there pins the volume busy through the
    // shutdown quiesce (R2.1), leaving a dirty ext4 journal on every clean
    // stop. Nothing outside this boot reads the guest's lock (the host probes
    // its own provider dir), so boot-ephemeral tmpfs is the honest home for
    // it. Keyed on being the VM init — pid-1 owns its /run — NOT on the
    // `--vsock` flag: a native (possibly non-root) `--vsock` daemon may not
    // be able to write /run at all and keeps the provider-dir lock.
    let instance_lock_path = if is_minimal_microvm() {
        DaemonAbsPath::try_new(format!("/run/minimald-local-{}.lock", cli.instance_num()))
            .expect("static /run lock path is absolute")
    } else {
        cli.client_instance_dir()
            .sub_path_unchecked(paths::MINIMALD_LOCK_FILE)
    };
    let mut instance_lock = fd_lock::RwLock::new(
        open_lock_file(instance_lock_path)
            .map_err(|e| MainError::IO(e, "opening instance lock"))?,
    );
    let instance_guard = match instance_lock.try_write() {
        Ok(guard) => guard,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(MainError::Other(format!(
                "minimald local-{} is already running (instance lock held)",
                cli.instance_num()
            )));
        }
        Err(e) => return Err(MainError::IO(e, "acquiring instance lock")),
    };
    // Best-effort debug aid; the lock itself, not the contents, is authoritative.
    let _ = instance_guard
        .set_len(0)
        .and_then(|()| writeln!(&*instance_guard, "{}", std::process::id()));

    // A minvmd bridge binds the same ssh.sock; don't steal a live VM's socket.
    if lock_held(
        cli.client_instance_dir()
            .sub_path_unchecked(paths::MINVMD_LOCK_FILE)
            .as_utf8_path()
            .as_std_path(),
    )
    .map_err(|e| MainError::IO(e, "probing minvmd lock"))?
    {
        return Err(MainError::Other(format!(
            "a minvmd VM is serving local-{}'s socket; stop it first (`minvmd stop`)",
            cli.instance_num()
        )));
    }

    // Setup the server config (shared by the UDS and vsock transports).
    let config = Config {
        host_key: HostKey::OnDisk {
            path: sub_path!(cli.client_instance_dir(), "ssh_host_ed25519_key")
                .as_utf8_path()
                .into(),
            create_if_missing: true,
        },
        minimal_state_dir: cli.minimal_state_dir(),
        minimal_cache_dir: cli.minimal_cache_dir(),
        // Re-borrow `listen_args` fresh here (as the vsock branch below does):
        // the R1.6 relocation above takes `&mut cli`, which ends the original
        // `listen_args` borrow, so it cannot be held across that mutation.
        gvproxy_bin: cli.listen_args().unwrap().gvproxy_bin.clone(),
        // The vsock listen path is exactly the libkrun-VM (DM1/3/4) case: an
        // `OwnIp` PTask must attach to the host gvproxy over the vsock shuttle,
        // not spawn gvproxy in-guest. The UDS path is DM2.
        in_microvm: cli.listen_args().unwrap().vsock,
        state_volume_mounted,
    };
    // Ensure the SSH host key is accessible in a instance-specific known_hosts file.
    // R1.2: load once and reuse in the vsock beacon so there is no redundant disk read.
    let host_private_key = config.host_key()?;
    russh::keys::known_hosts::learn_known_hosts_path(
        &format!("local-{}", cli.instance_num()),
        22,
        host_private_key.public_key(),
        sub_path!(cli.client_instance_dir(), "known_hosts").as_utf8_path(),
    )?;

    // If we got this far we need to launch minimald.
    if !cli.listen_args().unwrap().vsock {
        // standard path, listening on UDS socket.
        //
        // The B5 host-side egress proxy (:7654) and B8 mTLS reverse proxy
        // (:7655) are bound and served by `Server::run` for both DM2 (here) and
        // DM1 (the vsock path below), so no separate startup bind happens here.

        if let Err(e) = std::fs::remove_file(cli.listen_on())
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(MainError::IO(e, "socket already in use"));
        }
        let listener = UnixListener::bind(cli.listen_on())
            .map_err(|e| MainError::IO(e, "listening to socket"))?;

        tracing::info!("Started listening on {}", cli.listen_on());
        let (opts, ssh_name) = cli.ssh_args();
        tracing::info!(
            "Run the following to debug the socket:\n\nssh \\\n\t{} \\\n\t{}",
            opts.into_iter()
                .map(|(n, v)| format!("-o '{n}={v}'"))
                .collect::<Vec<String>>()
                .join(" \\\n\t"),
            ssh_name,
        );
        // TODO: When we have a daemonize command, daemonize here.

        Server::run(config, listener)
            .await
            .map_err(|e| MainError::IO(e, "serving on UDS"))
    } else {
        // micro-vm path, listen on vsock
        //
        // Bind before emitting READY: the host treats READY as "the bridge is
        // connectable", so the listener must exist first. The backlog holds
        // early connections until `Server::run` starts accepting.
        let port_num = DEFAULT_VSOCK_PORT_BASE + cli.listen_args().unwrap().instance_num;
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port_num))
            .map_err(|e| MainError::IO(e, "binding vsock port"))?;
        tracing::info!("Started listening on vsock:{port_num}");

        if let Err(e) = guest::emit_ready_marker(host_private_key.public_key()).await {
            tracing::warn!(error = %e, "initramfs: READY marker failed");
        }

        // Bring up the daemon's own egress: a primary tap in the root netns
        // attached to the host gvproxy over the vsock shuttle. Held for the
        // server's lifetime (dropping `_egress` tears the relay down). Best
        // effort — if the host gvproxy is absent the daemon serves without
        // network, the prior behaviour.
        let _egress = match guest::bring_up_root_egress().await {
            Ok(relay) => Some(relay),
            Err(e) => {
                tracing::warn!(error = %e, "guest root egress unavailable; serving without network");
                None
            }
        };

        Server::run(config, listener)
            .await
            .map_err(|e| MainError::IO(e, "serving on guest vsock"))
    }
}

/// Whether this process is the microVM's init: the kernel runs the initramfs
/// `/init` (this binary) as pid-1.
///
/// Both halves are load-bearing, because this now also gates `reboot(2)` (see
/// [`minimald::guest::shut_down_vm`]). `argv[0]` is caller-controlled — a host
/// could run `exec -a init minimald`, and with `CAP_SYS_BOOT` that would reset
/// the machine on exit — so it cannot be trusted alone. pid-1 cannot be spoofed
/// from userspace, but a native daemon running as a container's init would
/// satisfy it, so it is not sufficient alone either. Only the microVM's init
/// satisfies both.
fn is_minimal_microvm() -> bool {
    is_microvm_init(std::process::id(), std::env::args_os().next().as_deref())
}

/// Pure form of [`is_minimal_microvm`], so the spoofing cases are testable —
/// neither a process's pid nor its `argv[0]` can be set from within a test.
fn is_microvm_init(pid: u32, argv0: Option<&std::ffi::OsStr>) -> bool {
    pid == 1
        && argv0
            .map(|a0| std::path::Path::new(a0).file_name() == Some(std::ffi::OsStr::new("init")))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::is_microvm_init;
    use std::ffi::OsStr;

    #[test]
    fn the_microvm_init_is_pid_1_named_init() {
        assert!(is_microvm_init(1, Some(OsStr::new("/init"))));
        assert!(is_microvm_init(1, Some(OsStr::new("init"))));
    }

    /// The guard gates `reboot(2)`: a host process that merely *claims* to be
    /// init (`exec -a init minimald`) must not reach it.
    #[test]
    fn a_spoofed_argv0_on_the_host_is_not_the_microvm_init() {
        assert!(!is_microvm_init(4242, Some(OsStr::new("/init"))));
        assert!(!is_microvm_init(4242, Some(OsStr::new("init"))));
    }

    /// pid-1 alone is not enough either: a native daemon can be a container's
    /// init, and it must keep exiting normally rather than resetting the box.
    #[test]
    fn pid_1_under_another_name_is_not_the_microvm_init() {
        assert!(!is_microvm_init(1, Some(OsStr::new("/usr/bin/minimald"))));
        assert!(!is_microvm_init(1, Some(OsStr::new("minimald"))));
        assert!(!is_microvm_init(1, None));
    }
}
