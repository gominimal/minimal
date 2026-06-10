//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use paths::{CwdRelative, Daemon, DaemonAbsPath, DaemonRelPath, sub_path};
use tokio::{net::UnixListener, runtime::Builder};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use minimald::server::{Config, HostKey, Server};

/// Default AF_VSOCK port the guest relay listens on (the boot-contract bridge
/// port the host registers via `krun_add_vsock_port2`).
#[cfg(target_os = "linux")]
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
            Command::Run(ListenArgs { instance_num }) => *instance_num,
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
}

/// An error at the top level of minimald.
#[derive(Debug)]
pub enum MainError {
    IO(std::io::Error, &'static str),
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

    // Run as the initramfs `/init` (pid-1 in the guest) — detect via argv[0]
    // basename (the kernel appends its own cmdline tokens to init's argv, so an
    // arg-count check is unreliable). Handle before clap, which requires a
    // subcommand.
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .next()
        .map(|a0| std::path::Path::new(&a0).file_name() == Some(std::ffi::OsStr::new("init")))
        .unwrap_or(false)
    {
        return run_initramfs().await;
    }

    let cli = Cli::parse();

    // Handle non-{launch,run} commands.
    if let Command::Completions(CompletionsArgs { shell }) = cli.command {
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
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

/// Builds a guest server config rooted at `base` (state, cache, host key).
///
/// `base` is the hardcoded absolute guest state root (`/run/minimal`); the path
/// newtype constructors below therefore cannot fail, so a failure is a broken
/// invariant rather than a recoverable error.
#[cfg(target_os = "linux")]
fn guest_config_at(base: &str) -> Config {
    let state = DaemonAbsPath::try_new(Utf8PathBuf::from(base))
        .expect("guest state root `base` is an absolute path");
    let cache = DaemonAbsPath::try_new(Utf8PathBuf::from(format!("{base}/cache")))
        .expect("guest cache dir under an absolute `base` is an absolute path");
    let provider = sub_path!(state, "providers").join(
        &DaemonRelPath::try_new("local-0".to_string()).expect("`local-0` is a valid relative path"),
    );
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

/// Run as the initramfs `/init` (pid-1) and serve a full session against the
/// GENERIC upstream rootfs — no minimald baked into the rootfs.
///
/// Mounts `/dev`, then mounts the upstream rootfs (`/dev/vda`) and chroots into
/// it so the userland (`/bin/sh`, libs) resolves. Session state lives on a tmpfs
/// (`/run/minimal`) — no data disk, no `mke2fs`. Emits READY, then serves SSH
/// directly over the host-bridged AF_VSOCK port (no socat relay). Falls back to
/// READY-only + idle if there is no rootfs disk.
///
/// Requires libkrun >= 1.19.0 on the host: 1.18.1's vsock device mis-handled
/// multi-descriptor TX chains from Linux 6.2+ guests, intermittently stalling a
/// direct session (fixed upstream by libkrun `0ecf4d5f7`).
#[cfg(target_os = "linux")]
async fn run_initramfs() -> Result<(), MainError> {
    use minimald::guest;

    // /dev in the initramfs first, so /dev/vda and /dev/vsock exist.
    guest::mount_dev();
    // NB: no eager `waitpid(-1)` SIGCHLD reaper — it races tokio's process
    // reaping and steals exec children's exit status (ECHILD -> wrong exit code).
    // tokio reaps its own children; reaping hakoniwa double-fork orphans needs a
    // tokio-compatible reaper and is deferred (spec: revisit if zombies bite).

    if let Err(e) = guest::enter_rootfs("/dev/vda", "/newroot") {
        tracing::warn!(error = %e, "no rootfs disk; initramfs READY-only");
        guest::mount_pseudo_filesystems();
        let _ = guest::emit_ready_marker().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    // Inside the upstream rootfs now. Session state on the tmpfs at /run/minimal.
    const BASE: &str = "/run/minimal";
    std::fs::create_dir_all(format!("{BASE}/providers/local-0"))
        .map_err(|e| MainError::IO(e, "creating provider dir"))?;
    std::fs::create_dir_all(format!("{BASE}/cache"))
        .map_err(|e| MainError::IO(e, "creating cache dir"))?;
    let config = guest_config_at(BASE);

    if let Err(e) = guest::emit_ready_marker().await {
        tracing::warn!(error = %e, "initramfs: READY marker failed");
    }
    tracing::info!("initramfs: serving session over vsock from upstream rootfs (tmpfs state)");
    Server::run_on_vsock(config, DEFAULT_VSOCK_PORT)
        .await
        .map_err(|e| MainError::IO(e, "serving on guest vsock"))
}
