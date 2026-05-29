//! The minimal daemon, an SSH server which hosts sessions and
//! task/sandbox executions within them.

use camino::Utf8PathBuf;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use sessions::paths::{DaemonAbsPath, DaemonRelPath};
use std::path::PathBuf;
use tokio::net::UnixListener;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use minimald::server::{Config, HostKey, Server};

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
            Some(d) => {
                if d.is_absolute() {
                    DaemonAbsPath::try_new(d.clone()).unwrap()
                } else {
                    DaemonAbsPath::from_cwd()
                        .unwrap()
                        .join(&DaemonRelPath::try_new(d).unwrap())
                }
            }
            None => DaemonAbsPath::try_new(
                Utf8PathBuf::from_path_buf(
                    dirs::state_dir()
                        .unwrap_or_else(|| PathBuf::from("~/.local/state"))
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
                    .unwrap_or_else(|| PathBuf::from("~/.local/cache"))
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
        self.minimal_state_dir()
            .sub_path("providers")
            .join(&DaemonRelPath::try_new(format!("local-{instance_num}")).unwrap())
    }

    /// Returns the path to the UDS socket we should listen on.
    pub fn listen_on(&self) -> DaemonAbsPath {
        self.client_instance_dir().sub_path("ssh.sock")
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
    minimal_dir: Option<Utf8PathBuf>,
    /// Load the minimal standard library from the given path instead
    #[arg(long)]
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    stdlib_dir: Option<Utf8PathBuf>,

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

    if let Err(e) = std::fs::create_dir_all(cli.minimal_state_dir())
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(MainError::IO(e, "creating minimal dir"));
    }

    // If we got this far we need to launch minimald.
    //
    // Ensure the socket's parent directory exists.
    let socket_path = cli.listen_on();
    if let Some(parent) = socket_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(MainError::IO(e, "creating provider dir"));
    }

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

    // Setup the server.
    let config = Config {
        host_key: HostKey::OnDisk {
            path: cli
                .client_instance_dir()
                .sub_path("ssh_host_ed25519_key")
                .as_utf8_path()
                .into(),
            create_if_missing: true,
        },
        minimal_state_dir: cli.minimal_state_dir(),
        minimal_cache_dir: cli.minimal_cache_dir(),
    };

    match cli.command {
        Command::Completions(_) => unreachable!(),
        Command::Run(_) => Server::run_on_uds(config, listener),
    }
    .await
    .unwrap();

    Ok(())
}
