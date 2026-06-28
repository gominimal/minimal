//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use paths::{CwdRelative, Daemon, DaemonAbsPath, DaemonRelPath, sub_path};
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
            Some(p) => p.resolve().unwrap(),
            None => DaemonAbsPath::try_new(
                Utf8PathBuf::from_path_buf(
                    dirs::state_dir()
                        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".local/state"))
                        .join("minimal"),
                )
                .unwrap(),
            )
            .unwrap(),
        }
    }

    /// Returns the path to base directory for caching
    /// based on command-line arguments.
    pub fn minimal_cache_dir(&self) -> DaemonAbsPath {
        match &self.global_args.minimal_cache_dir {
            Some(p) => p.resolve().unwrap(),
            None => DaemonAbsPath::try_new(
                Utf8PathBuf::from_path_buf(
                    dirs::cache_dir()
                        .unwrap_or_else(|| dirs::home_dir().unwrap().join(".local/cache"))
                        .join("minimal"),
                )
                .unwrap(),
            )
            .unwrap(),
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
        let instance_num = self.instance_num();
        sub_path!(self.minimal_state_dir(), "providers")
            .join(&DaemonRelPath::try_new(format!("local-{instance_num}")).unwrap())
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
        sub_path!(self.client_instance_dir(), "ssh.sock")
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

/// Reset the process "dumpable" flag to 1 (see the call site for why). Process-
/// wide and inherited across `fork`, so calling it once before any sandbox is
/// spawned suffices. Linux-only; a no-op elsewhere.
fn restore_sandbox_dumpable() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 1)` takes no pointers and only sets the
        // calling process's dumpable flag to a valid value (1 = SUID_DUMP_USER).
        // It cannot fail for this argument, but we log rather than panic if it
        // somehow does, since a wrong dumpable state only degrades DM2 own-IP.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
        if rc != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "failed to set PR_SET_DUMPABLE; setcap'd host-native sandboxes may fail"
            );
        }
    }
}

fn main() -> Result<(), MainError> {
    let runtime = Builder::new_multi_thread()
        .thread_name("minimald-worker")
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async_main())
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
        .stderr(std::process::Stdio::null());
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
    cmd.spawn()
        .map_err(|e| MainError::IO(e, "spawning detached minimald"))?;

    let sock = cli.listen_on();
    let sock_path = std::path::Path::new(sock.as_utf8_path().as_str());
    let deadline = Instant::now() + Duration::from_secs(DETACH_TIMEOUT_SECS);
    loop {
        if std::os::unix::net::UnixStream::connect(sock_path).is_ok() {
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

async fn async_main() -> Result<(), MainError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(ot::StdoutWriter::new))
        .with(filter)
        .init();

    // Restore the "dumpable" flag so sandbox children can set up their user
    // namespace. When minimald is granted file capabilities (DM2: an unprivileged
    // host-native daemon `setcap`'d for own-IP tap/netns setup), gaining caps at
    // `execve` sets the process dumpable flag to `SUID_DUMP_ROOT`, which makes
    // `/proc/<pid>/{uid_map,gid_map,setgroups}` owned by root. A forked sandbox
    // (hakoniwa) inherits that flag and then fails to write its *own*
    // `/proc/self/uid_map` as the unprivileged real user — `EPERM` — breaking
    // every session, own-IP or not. Resetting dumpable to 1 re-owns those files
    // to the real uid so the unprivileged single-id self-mapping is permitted
    // again. A no-op (already 1) when minimald holds no file capabilities.
    restore_sandbox_dumpable();

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
        let _ = guest::emit_ready_marker().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
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
        gvproxy_bin: listen_args.gvproxy_bin.clone(),
        // The vsock listen path is exactly the libkrun-VM (DM1/3/4) case: an
        // `OwnIp` PTask must attach to the host gvproxy over the vsock shuttle,
        // not spawn gvproxy in-guest. The UDS path is DM2.
        in_microvm: listen_args.vsock,
    };
    // Ensure the SSH host key is accessible in a instance-specific known_hosts file.
    russh::keys::known_hosts::learn_known_hosts_path(
        &format!("local-{}", cli.instance_num()),
        22,
        config.host_key()?.public_key(),
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
        if let Err(e) = guest::emit_ready_marker().await {
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

        let port_num = DEFAULT_VSOCK_PORT_BASE + listen_args.instance_num;
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port_num))
            .map_err(|e| MainError::IO(e, "binding vsock port"))?;

        tracing::info!("Started listening on vsock:{port_num}");
        Server::run(config, listener)
            .await
            .map_err(|e| MainError::IO(e, "serving on guest vsock"))
    }
}

fn is_minimal_microvm() -> bool {
    std::env::args_os()
        .next()
        .map(|a0| std::path::Path::new(&a0).file_name() == Some(std::ffi::OsStr::new("init")))
        .unwrap_or(false)
}
