//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use paths::{CwdRelative, Daemon, DaemonAbsPath, DaemonRelPath, sub_path};
use tokio::net::UnixListener;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use minimald::server::{Config, HostKey, Server};

/// Default AF_VSOCK port the guest serves host-bridged SSH on (the boot-contract
/// bridge port the host registers via `krun_add_vsock_port2`).
const DEFAULT_VSOCK_PORT: u32 = 2222;

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
        match &self.global_args.minimal_dir {
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
        DaemonAbsPath::try_new(
            Utf8PathBuf::from_path_buf(
                dirs::cache_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap().join(".local/cache"))
                    .join("minimal"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// Returns the path to the directory containing sockets/info about this daemon for clients.
    pub fn client_instance_dir(&self) -> DaemonAbsPath {
        let instance_num = match &self.command {
            Command::Run(ListenArgs { instance_num, .. }) => *instance_num,
            _ => 0,
        };
        sub_path!(self.minimal_state_dir(), "providers")
            .join(&DaemonRelPath::try_new(format!("local-{instance_num}")).unwrap())
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
    /// Override the state directory used for operations (default: $XDG_STATE_DIR/minimal)
    #[arg(long)]
    minimal_dir: Option<CwdRelative<Daemon>>,
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

    /// Run as the in-VM (pid-1) guest: instead of a UDS socket, perform pid-1
    /// hygiene, emit the boot READY marker, and serve host-bridged SSH over
    /// AF_VSOCK. Implied when `MINIMALD_VSOCK_PORT` is set.
    #[arg(long)]
    guest: bool,

    /// AF_VSOCK port to serve on in `--guest` mode (the host-bridged SSH port).
    /// Defaults to the boot-contract bridge port; override for testing.
    #[arg(long, env = "MINIMALD_VSOCK_PORT", default_value_t = DEFAULT_VSOCK_PORT)]
    vsock_port: u32,
}

/// An error at the top level of minimald.
#[derive(Debug)]
pub enum MainError {
    IO(std::io::Error, &'static str),
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(ot::StdoutWriter::new))
        .with(filter)
        .init();

    let cli = Cli::parse();

    // Handle non-{launch,run} commands.
    if let Command::Completions(CompletionsArgs { shell }) = cli.command {
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    // Guest (in-VM, pid-1) mode: activated by `--guest` or MINIMALD_VSOCK_PORT.
    // Handled before the host-dependent state-dir resolution below — as pid-1
    // there is no HOME, so state/cache resolve to the mounted state disk
    // instead of `dirs::state_dir()`.
    #[cfg(target_os = "linux")]
    if let Command::Run(ListenArgs {
        guest, vsock_port, ..
    }) = &cli.command
        && (*guest || std::env::var_os("MINIMALD_VSOCK_PORT").is_some())
    {
        return run_guest(guest_config(), *vsock_port).await;
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
    };

    // If we got this far we need to launch minimald.
    //
    // Listen on the UDS socket.
    if let Err(e) = std::fs::remove_file(cli.listen_on())
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(MainError::IO(e, "socket already in use"));
    }
    let listener =
        UnixListener::bind(cli.listen_on()).map_err(|e| MainError::IO(e, "listening to socket"))?;
    tracing::info!("Started listening on {}", cli.listen_on());
    tracing::info!(
        "Run the following to debug the socket:\n\nssh -o ProxyCommand='socat - UNIX-CONNECT:{}' \\\n\t-o 'StrictHostKeyChecking=no' -o 'UserKnownHostsFile=/dev/null' \\\n\tlocal",
        cli.listen_on()
    );

    // TODO: When we have a daemonize command, daemonize here.

    match cli.command {
        Command::Completions(_) => unreachable!(),
        Command::Run(_) => Server::run_on_uds(config, listener),
    }
    .await
    .unwrap();

    Ok(())
}

/// Builds the guest (in-VM) server config with state + cache on the mounted
/// writable state disk. Independent of HOME/XDG, since as pid-1 neither is set
/// and the root image is read-only.
#[cfg(target_os = "linux")]
fn guest_config() -> Config {
    use minimald::guest::STATE_DISK_MOUNT;
    let state = DaemonAbsPath::try_new(Utf8PathBuf::from(STATE_DISK_MOUNT)).unwrap();
    let cache =
        DaemonAbsPath::try_new(Utf8PathBuf::from(format!("{STATE_DISK_MOUNT}/cache"))).unwrap();
    let provider =
        sub_path!(state, "providers").join(&DaemonRelPath::try_new("local-0".to_string()).unwrap());
    let host_key_path = sub_path!(provider, "ssh_host_ed25519_key");
    Config {
        host_key: HostKey::OnDisk {
            path: host_key_path.as_utf8_path().into(),
            create_if_missing: true,
        },
        minimal_state_dir: state,
        minimal_cache_dir: cache,
    }
}

/// Runs minimald as the in-VM (pid-1) guest: mounts the writable state disk,
/// performs pid-1 hygiene, emits the boot READY marker, then serves SSH over
/// the host-bridged vsock port.
#[cfg(target_os = "linux")]
async fn run_guest(config: Config, port: u32) -> Result<(), MainError> {
    use minimald::guest;

    // pid-1 hygiene: the kernel auto-mounts /dev (devtmpfs) but not /proc or /sys.
    guest::mount_pseudo_filesystems();
    // NB: no eager `waitpid(-1)` SIGCHLD reaper here — it races tokio's process
    // reaping and steals exec children's exit status (ECHILD -> wrong exit code).
    // tokio reaps its own children; reaping hakoniwa double-fork orphans needs a
    // tokio-compatible reaper and is deferred (spec: revisit if zombies bite).

    // Mount the writable state disk; minimald has nowhere to write its session
    // store or host key without it (the root image is read-only).
    guest::mount_state_disk(guest::STATE_DISK_DEVICE, guest::STATE_DISK_MOUNT)
        .map_err(|e| MainError::IO(e, "mounting state disk"))?;
    // Ensure the host-key (provider) and cache dirs exist on the fresh disk.
    let provider_dir = config
        .minimal_state_dir
        .as_utf8_path()
        .join("providers")
        .join("local-0");
    std::fs::create_dir_all(&provider_dir)
        .map_err(|e| MainError::IO(e, "creating provider dir"))?;
    std::fs::create_dir_all(config.minimal_cache_dir.as_utf8_path())
        .map_err(|e| MainError::IO(e, "creating cache dir"))?;

    // Serve over a UDS fronted by a socat vsock->UDS relay. A direct
    // tokio-vsock listener accepts the bridged connection but the SSH session
    // over it early-eofs (see guest::spawn_vsock_relay), so bind the UDS, start
    // the relay, then serve via the native UDS path. The UDS must live on the
    // writable data disk — the root (incl. /run) is ro.
    let guest_uds = format!("{}/minimald.sock", guest::STATE_DISK_MOUNT);
    let _ = std::fs::remove_file(&guest_uds);
    let listener =
        UnixListener::bind(&guest_uds).map_err(|e| MainError::IO(e, "binding guest UDS"))?;
    let _relay = guest::spawn_vsock_relay(port, &guest_uds)
        .map_err(|e| MainError::IO(e, "spawning vsock relay"))?;

    // Announce we have booted. Best-effort: log but do not abort serving.
    if let Err(e) = guest::emit_ready_marker().await {
        tracing::warn!(error = %e, "failed to emit boot READY marker");
    }

    Server::run_on_uds(config, listener)
        .await
        .map_err(|e| MainError::IO(e, "serving on guest UDS"))
}

/// Vsock guest mode is Linux-only; on other platforms it is unsupported.
#[cfg(not(target_os = "linux"))]
async fn run_guest(_config: Config, _port: u32) -> Result<(), MainError> {
    Err(MainError::IO(
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "vsock guest mode is only supported on Linux",
        ),
        "vsock guest mode",
    ))
}
