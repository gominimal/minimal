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
        gvproxy_bin: None,
        // The vsock listen path is exactly the libkrun-VM (DM1/3/4) case: an
        // `OwnIp` PTask must attach to the host gvproxy over the vsock shuttle,
        // not spawn gvproxy in-guest (issue #572). The UDS path is DM2.
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
        // standard path, listening on UDS socket

        // DM2 (native-Linux host): bind the B5 host-side egress proxy listener
        // as a startup reachability check. PTask `*.min.internal` hostnames (Unit 3)
        // are resolved host-side and routed by `Host:` header through this proxy;
        // the host resolver is never consulted. A bind failure warns with a
        // remedy (this supersedes the former R3.4 systemd-resolved probe).
        let _ = minimald::net::proxy::bind_listener(minimald::net::proxy::DEFAULT_PROXY_ADDR).await;

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
