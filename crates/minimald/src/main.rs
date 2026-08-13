//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use paths::{CwdRelative, Daemon, DaemonAbsPath, sub_path};
use std::io::Write as _;
use tokio::{net::UnixListener, runtime::Builder};

use minimald::server::{Config, HostKey, Server};

mod logging;
use logging::{DaemonLogger, LogMode};

#[cfg(target_os = "linux")]
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

/// Base AF_VSOCK port the guest relay listens on when in vsock mode.
///
/// The actual port is `DEFAULT_VSOCK_PORT_BASE` + `instance_num`.
#[cfg(target_os = "linux")]
const DEFAULT_VSOCK_PORT_BASE: u32 = 2222;

/// Receive window installed on the guest's vsock listener, in bytes.
///
/// `virtio_transport_inc_rx_pkt` refuses an incoming packet — resetting the
/// connection and setting `sk_err` to `ENOBUFS` — when either the peer overruns
/// its credit (`buf_used + len > buf_alloc`) or the queued socket-buffer
/// overhead does (`(queue_len + 1) * SKB_TRUESIZE(0) > buf_alloc`). At the
/// 256 KiB default window the second ceiling lands at 455 queued skbs on arm64,
/// where `SKB_TRUESIZE(0)` is 576 bytes. libkrun clamps each read to the credit
/// still outstanding, so under receiver backpressure its packets shrink to
/// roughly 540 bytes — below that per-skb overhead — and a workspace upload
/// trips the overhead ceiling with kilobytes of window still unused.
///
/// 8 MiB is empirical headroom, not immunity. It does not change the ratio
/// between the two ceilings; it keeps a normal upload out of the credit-starved
/// tail where packets degenerate, and a larger upload or a slower reader can
/// still reach it. The real fix belongs in libkrun, which should not shrink a
/// packet below the per-skb overhead it costs to queue; this is the
/// consumer-side mitigation.
#[cfg(target_os = "linux")]
const VSOCK_RX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Env var `spawn_detached` sets on the child so `async_main` knows
/// its stdio has been redirected to `/dev/null` and needs to swap
/// the tracing writer over to a rolling log file.
const DETACHED_ENV: &str = "MINIMALD_DETACHED";

#[derive(Parser)]
#[command(name = "minimald", version = version::VERSION, long_version = version::LONG_VERSION)]
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
        paths::provider_instance_dir(
            &self.minimal_state_dir(),
            paths::ProviderKind::Minimald,
            self.instance_num(),
        )
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
            paths::provider_instance_name(paths::ProviderKind::Minimald, self.instance_num()),
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
        long_about = "Generate a shell tab-completion script for the minimal daemon.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimald completions bash)"
    )]
    Completions(CompletionsArgs),
    /// Runs the minimald server in the foreground.
    Run(ListenArgs),
    /// Internal: join a session's namespaces and run a program there.
    ///
    /// Not a supported command line — this is the daemon re-execing itself to
    /// power launching a process in existing namespaces.
    #[command(name = minimald::nsenter::SUBCOMMAND, hide = true)]
    Nsenter(minimald::nsenter::ShimArgs),
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
    #[clap(hide = true)]
    stdlib_dir: Option<CwdRelative<Daemon>>,

    /// Configure the number of parallel builds
    #[arg(short, long, global = true)]
    #[clap(hide = true)]
    num_parallel_builds: Option<usize>,
}

/// Arguments describing where minimald should listen for connections.
#[derive(Debug, Args)]
pub struct ListenArgs {
    /// Instance number for this minimald; determines client-relevant paths under
    /// `<minimal_state_dir>/providers/local-minimald<instance-num>`.
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

    /// Raise `RLIMIT_NOFILE`, soft and hard, to this many descriptors, which
    /// everything the daemon forks inherits. Only useful as a VM init process,
    /// where nothing else widens the kernel's 1024-fd default; `None` keeps the
    /// limits we were started with.
    #[arg(long)]
    #[clap(hide = true)]
    rlimit_nofile: Option<u64>,

    /// Vsock port to listen on for host time updates: 8-byte little-endian
    /// nanoseconds-since-epoch stamps, dialed in by the host half in `minvmd`
    /// (see `guest::run_timekeep_listener`). Only useful as a VM init process;
    /// `None` leaves the guest clock free-running.
    #[arg(long)]
    #[clap(hide = true)]
    timekeep_listener_port: Option<u32>,

    /// Daemonize: spawn minimald in a new session (setsid) and return once the
    /// SSH socket accepts connections, or an 8s timeout elapses. Used by the
    /// `min` CLI to auto-start a native daemon on Linux.
    #[arg(long, default_value_t = false)]
    detach: bool,

    /// Path to the gvproxy ("gvisor-tap-vsock") binary backing the per-host
    /// `OwnIp` switch. Defaults to the installed location when unset: the
    /// user-local `bin/gvproxy-min` the installer stamps, else the system
    /// install path. Point it at a local build to run own-IP without an
    /// install.
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

/// Flattens an error and its `source()` chain into one line, so a typed error
/// reaching [`MainError::Other`] keeps the context its variants carry.
fn error_chain(err: &dyn std::error::Error) -> String {
    std::iter::successors(err.source(), |e| e.source()).fold(err.to_string(), |mut acc, e| {
        acc.push_str(&format!(": {e}"));
        acc
    })
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
    // We re-exec to power some machinery for joining namespaces, do that before async/other-threads
    // are setup.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == minimald::nsenter::SUBCOMMAND)
    {
        let Command::Nsenter(args) = Cli::parse().command else {
            unreachable!(
                "argv[1] is {}, so clap parsed that subcommand",
                minimald::nsenter::SUBCOMMAND
            )
        };
        let code =
            minimald::nsenter::shim_main(args).map_err(|e| MainError::Other(error_chain(&e)))?;
        std::process::exit(code);
    }

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
    let cli = if is_minimal_microvm() {
        Cli {
            command: Command::Run(ListenArgs {
                instance_num: 0,
                vsock: true,
                mount_dev: true,
                mount_rootfs: Some("/dev/vda".to_string()),
                mk_mount_state_volume: Some("/dev/vdb".to_string()),
                detach: false,
                // No service manager above pid-1 to widen the kernel default.
                rlimit_nofile: Some(guest::DEFAULT_MICROVM_NOFILE_LIMIT),
                // Host time updates arrive on a vsock stream we listen on, from
                // minvmd. Always listen: the guest cannot see what the
                // host runs.
                timekeep_listener_port: Some(guest::TIMEKEEP_PORT),
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
    let mut cli = match cli.command {
        Command::Nsenter(_) => unreachable!("nsenter is intercepted before CLI args are parsed"),
        Command::Completions(CompletionsArgs { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            return Ok(());
        }
        _ => cli,
    };

    // Install tracing. A foreground run logs to stdout only. A detached
    // native daemon (stdio null'd, marked by `MINIMALD_DETACHED`) and the
    // microVM pid-1 both log to a daily-rotated file, wired up by
    // `logger.activate` once the log directory is final (below): immediately
    // for the native daemon, after the state volume mounts for the microVM.
    // The activation yields a release the server state runs at shutdown.
    let log_mode = if is_minimal_microvm() || std::env::var_os(DETACHED_ENV).is_some() {
        LogMode::File
    } else {
        LogMode::Console
    };
    let logger = DaemonLogger::install(log_mode)?;

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

    // Pin the path this daemon re-execs itself from as the `__nsenter` shim,
    // now, while the file is certainly still there. Resolved per-spawn instead,
    // `current_exe()` reads `/proc/self/exe`, which the kernel reports as a
    // dangling `<path> (deleted)` once the binary has been replaced — so every
    // lifecycle hook and in-session exec fails with `ENOENT` after any rebuild
    // of a running daemon. `just min` rebuilds `-p minimald` on every
    // invocation, so a dev daemon meets that the first time its source changes.
    // The path resolved here keeps naming whatever now lives at it.
    //
    // Not in the microVM: pid-1's own path is the initramfs `/init`, which is
    // unreachable after the rootfs switch, so the guest stages a runnable copy
    // and registers *that* (#1175). Registration is first-wins, so claiming it
    // here would lock the guest's out.
    if !is_minimal_microvm() {
        match std::env::current_exe() {
            Ok(exe) => minimald::nsenter::set_shim_exe(exe),
            // Non-fatal: without a registration each injection falls back to
            // resolving `current_exe()` itself, which is the prior behaviour.
            Err(e) => tracing::warn!(
                error = %e,
                "could not resolve this daemon's executable to register as the nsenter shim; \
                 in-session exec will re-resolve it per spawn",
            ),
        }
    }

    // Handle setup specific to operating in a micro-vm.
    use minimald::guest;
    // Before anything forks from us and inherits the limits. Best effort: the
    // kernel default is the prior behaviour, not a reason to refuse to boot.
    if let Some(limit) = listen_args.rlimit_nofile {
        match guest::raise_nofile_limit(limit) {
            Ok(effective) if effective >= limit => {
                tracing::debug!(nofile = effective, "raised the open-file limit");
            }
            Ok(effective) => tracing::warn!(
                requested = limit,
                effective,
                "the open-file limit could not be raised as far as requested; fd-hungry builds \
                 may fail with EMFILE"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                requested = limit,
                "could not raise the open-file limit; fd-hungry builds may fail with EMFILE"
            ),
        }
    }
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

    // The log directory is now final under `<state>/logs` — the native
    // daemon's from the start, the microVM's now that the state volume is
    // mounted and state relocated onto it, where `min bug`'s guest collector
    // reads it. Point the file log at it; the release is handed to the server
    // state and run at shutdown (in the microVM, before the quiesce — the
    // appender's write-open fd would otherwise hold the volume busy and
    // defeat the clean unmount). A foreground run's logger has no file and
    // yields `None`. A failure here must not wedge the daemon (pid-1 in the
    // microVM), so fall back to console-only.
    let log_dir = cli
        .minimal_state_dir()
        .as_utf8_path()
        .as_std_path()
        .join("logs");
    let log_release = match logger.activate(&log_dir) {
        Ok(release) => {
            if release.is_some() {
                tracing::info!(
                    log_dir = %log_dir.display(),
                    "routing tracing output to daily-rotated log file",
                );
            }
            release
        }
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "could not open the daemon log file; continuing with console logging only",
            );
            None
        }
    };

    // Adopt any pre-split `providers/local-<N>` dir into the kind-tagged scheme
    // before resolving our own instance dir, so an upgraded daemon reuses its
    // existing state instead of orphaning it.
    paths::migrate_legacy_provider_dirs(&cli.minimal_state_dir());

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
    let instance_name =
        paths::provider_instance_name(paths::ProviderKind::Minimald, cli.instance_num());
    let instance_lock_path = if is_minimal_microvm() {
        DaemonAbsPath::try_new(format!("/run/minimald-{instance_name}.lock"))
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
                "minimald {instance_name} is already running (instance lock held)"
            )));
        }
        Err(e) => return Err(MainError::IO(e, "acquiring instance lock")),
    };
    // Best-effort debug aid; the lock itself, not the contents, is authoritative.
    let _ = instance_guard
        .set_len(0)
        .and_then(|()| writeln!(&*instance_guard, "{}", std::process::id()));

    // Native minimald and minvmd now own distinct provider dirs
    // (`local-minimald<N>` vs `local-minvmd<N>`), so they no longer share a
    // socket. This stays as a defensive guard for the unusual case of a minvmd
    // instance pointed at *this* dir: don't steal a live VM's ssh.sock.
    if lock_held(
        cli.client_instance_dir()
            .sub_path_unchecked(paths::MINVMD_LOCK_FILE)
            .as_utf8_path()
            .as_std_path(),
    )
    .map_err(|e| MainError::IO(e, "probing minvmd lock"))?
    {
        return Err(MainError::Other(format!(
            "a minvmd VM is serving {instance_name}'s socket; stop it first (`minvmd stop`)"
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
    let known_hosts = sub_path!(cli.client_instance_dir(), "known_hosts");
    // `learn_known_hosts_path` appends unconditionally; drop any prior entry for
    // this host so repeated daemon spawns record one current key instead of
    // growing known_hosts without bound (#782). Best-effort: a prune failure
    // must not block startup.
    if let Err(e) = paths::prune_known_hosts_entries(
        known_hosts.as_utf8_path().as_std_path(),
        &instance_name,
        22,
    ) {
        tracing::warn!(error = %e, "failed to prune stale known_hosts entries");
    }
    russh::keys::known_hosts::learn_known_hosts_path(
        &instance_name,
        22,
        host_private_key.public_key(),
        known_hosts.as_utf8_path(),
    )?;

    // Preflight (advisory): every session sandbox starts by unsharing an
    // unprivileged user namespace, forked from this process with no exec in
    // between — so this process's own privileges and AppArmor label are what
    // the kernel will check. On a restricted host (stock Ubuntu 24.04+ with
    // an unconfined daemon) that denial otherwise surfaces only when the
    // first attach dies writing /proc/self/uid_map, with nothing useful in
    // this log. Warn once at startup instead, with the fix. The in-guest
    // microVM daemon runs as root, where no restriction binds, so this stays
    // silent on the vsock path.
    #[cfg(target_os = "linux")]
    if let Some(restriction) = sandbox2::user_namespaces_restriction() {
        let fix = match restriction {
            sandbox2::UsernsRestriction::ApparmorUnconfined => {
                // The loader lands under the installer's `data` prefix, which
                // resolves through $XDG_DATA_HOME exactly like
                // `paths::minimal_data_dir` — don't hardcode ~/.local/share.
                // A daemon at a path outside the profile's tunable (a custom
                // MINIMAL_BIN, a dev build) needs the binary attached too.
                format!(
                    "install minimald's AppArmor profile (one-time, needs root): sudo bash \
                     {data}/apparmor/install-apparmor-profile.sh --path {bin} (from a checkout: \
                     sudo scripts/install-apparmor-profile.sh --path {bin})",
                    data = paths::minimal_data_dir(),
                    bin = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.to_str().map(str::to_owned))
                        .unwrap_or_else(|| "<path to this minimald binary>".to_string()),
                )
            }
            sandbox2::UsernsRestriction::Disabled => {
                "re-enable user namespaces, e.g. sudo sysctl -w user.max_user_namespaces=15000"
                    .to_string()
            }
            // `UsernsRestriction` is #[non_exhaustive]; future variants get
            // the docs pointer until a matching remediation lands here.
            _ => "see the linux-host-setup doc".to_string(),
        };
        tracing::warn!(
            reason = %restriction,
            fix,
            docs = "https://docs.minimal.dev/reference/linux-host-setup",
            "sessions will fail to start: this host refuses the unprivileged user \
             namespace every session sandbox needs"
        );
    }

    // Track the host's wall clock, when configured.
    if let Some(port) = cli.listen_args().unwrap().timekeep_listener_port {
        tokio::spawn(async move {
            match guest::run_timekeep_listener(port).await {
                // `Infallible`: the listener only ever returns by failing.
                Ok(never) => match never {},
                Err(e) => tracing::warn!(
                    error = %e,
                    port,
                    "host time updates unavailable; the guest clock will drift",
                ),
            }
        });
    }

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

        Server::run(config, listener, log_release)
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

        // Widen the receive window before anything connects: `__vsock_create`
        // copies `buffer_size` from the listening socket onto every socket it
        // accepts, so this one call covers every session. Best effort — a
        // daemon with the default window is the old, buggy behaviour, not a
        // reason to refuse to boot.
        match set_vsock_rx_window(&listener, VSOCK_RX_WINDOW_BYTES) {
            Ok(effective) if effective >= VSOCK_RX_WINDOW_BYTES => {
                tracing::debug!(bytes = effective, "raised the vsock receive window");
            }
            Ok(effective) => tracing::warn!(
                requested = VSOCK_RX_WINDOW_BYTES,
                effective,
                "vsock receive window clamped below the requested size; large uploads may still \
                 fail with ENOBUFS"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "could not raise the vsock receive window; large uploads may fail with ENOBUFS"
            ),
        }

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

        Server::run(config, listener, log_release)
            .await
            .map_err(|e| MainError::IO(e, "serving on guest vsock"))
    }
}

/// Raises the AF_VSOCK receive window on `listener` to `bytes`, returning the
/// window the kernel actually installed.
///
/// Two things make this less obvious than a single `setsockopt`:
///
/// - `SO_VM_SOCKETS_BUFFER_MAX_SIZE` has to be raised first.
///   `vsock_update_buffer_size` clamps the requested size to `buffer_max_size`,
///   whose default is the same 256 KiB as the size itself, so setting the size
///   alone succeeds having changed nothing.
/// - A clamped request is not an error. `setsockopt` returns 0 either way, so
///   the caller only learns what it got by reading the value back.
///
/// Both options take a `u64` at level `AF_VSOCK`.
#[cfg(target_os = "linux")]
fn set_vsock_rx_window(listener: &VsockListener, bytes: u64) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd as _;

    /// `SO_VM_SOCKETS_BUFFER_SIZE`, `include/uapi/linux/vm_sockets.h`.
    const SO_VM_SOCKETS_BUFFER_SIZE: libc::c_int = 0;
    /// `SO_VM_SOCKETS_BUFFER_MAX_SIZE`, ditto.
    const SO_VM_SOCKETS_BUFFER_MAX_SIZE: libc::c_int = 2;

    let fd = listener.as_raw_fd();

    let set = |option: libc::c_int| {
        // SAFETY: `fd` is borrowed from `listener`, which outlives this call.
        // The option value is a live `u64` and the length passed is its own, so
        // the kernel reads exactly the bytes that back it.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::AF_VSOCK,
                option,
                std::ptr::from_ref(&bytes).cast(),
                size_of::<u64>() as libc::socklen_t,
            )
        };
        (rc == 0)
            .then_some(())
            .ok_or_else(std::io::Error::last_os_error)
    };

    set(SO_VM_SOCKETS_BUFFER_MAX_SIZE)?;
    set(SO_VM_SOCKETS_BUFFER_SIZE)?;

    let mut effective: u64 = 0;
    let mut len = size_of::<u64>() as libc::socklen_t;
    // SAFETY: `fd` as above. `effective` and `len` are live for the duration of
    // the call, and `len` describes the buffer the kernel writes into, which is
    // `effective` itself.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_BUFFER_SIZE,
            std::ptr::from_mut(&mut effective).cast(),
            &raw mut len,
        )
    };
    (rc == 0)
        .then_some(effective)
        .ok_or_else(std::io::Error::last_os_error)
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
