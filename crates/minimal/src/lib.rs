//! The minimal CLI which pairs/talks-with minimald.

use anyhow::{Context as _, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt as _;

pub mod autospawn;
pub mod client;
pub mod config;
pub mod dirs;
mod file_upload;
pub mod git_remote;
pub mod loadouts;

#[derive(Parser)]
#[command(name = "min", version = env!("CARGO_PKG_VERSION"), long_version = env!("LONG_VERSION"))]
#[command(about = "The Minimal CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten)]
    pub global_args: GlobalArgs,
}

#[derive(Subcommand)]
pub enum Command {
    /// List sessions
    Ls(LsArgs),
    /// Activate (create) a new session
    Activate(ActivateArgs),
    /// Attach to an existing session
    Attach(AttachArgs),
    /// Destroy (terminate) a session
    Destroy(DestroyArgs),
    /// Shut down the minimald daemon
    Stop(StopArgs),
    /// Session inspection subcommands
    Session(SessionArgs),
    /// Loadout management subcommands
    Loadout(LoadoutArgs),
    /// Print important directories and file paths for debugging
    Dirs,
    /// WireGuard mesh: join, leave, and inspect remote-access state
    #[cfg(feature = "remote-access")]
    Mesh(MeshArgs),
    /// Proxy stdio to a daemon UDS socket (used as an SSH ProxyCommand).
    #[command(hide = true)]
    Proxy(ProxyArgs),
    /// Forward a local TCP port to a remote address inside a PTask via SSH
    /// (R4.8, R4.9).
    ///
    /// Sets up an SSH `LocalForward` (`-L`) tunnel through the minimald SSH
    /// server so traffic sent to `<local-port>` on the host is relayed to
    /// `<remote-host>:<remote-port>` from inside the named PTask's network
    /// namespace. Useful when WireGuard (`networking-wg` feature) is
    /// unavailable (e.g., on corporate networks that block UDP).
    ///
    /// Examples:
    ///
    ///   # Forward host port 18080 to the webserver inside the "dev" session:
    ///   minimal ssh-forward dev 18080:127.0.0.1:80
    ///
    ///   # Then access it from the host:
    ///   curl http://localhost:18080/
    #[cfg(feature = "remote-access")]
    #[command(name = "ssh-forward", visible_alias = "forward")]
    SshForward(SshForwardArgs),
    /// Obtain an mTLS client certificate from minimald for use with the HTTPS
    /// reverse proxy (R4.4, R4.5).
    ///
    /// Connects to minimald, generates a fresh client certificate signed by
    /// the daemon's internal CA, and saves the certificate and private key to
    /// `~/.config/minimal/client.pem` / `~/.config/minimal/client.key`. Also
    /// saves the CA certificate to `~/.config/minimal/ca.pem` so tools like
    /// `curl` can trust the HTTPS proxy.
    ///
    /// Example:
    ///
    ///   minimal login
    ///   curl --cacert ~/.config/minimal/ca.pem \
    ///        --cert ~/.config/minimal/client.pem \
    ///        --key  ~/.config/minimal/client.key \
    ///        https://localhost:7655/
    Login(LoginArgs),
    /// Rename an existing session
    Rename(RenameArgs),
    /// Automatically initialize minimal configuration based on your source tree
    Init(InitArgs),
    /// Add a new tool or dependency
    Add(AddArgs),
    /// Refresh local checkouts of upstream packages & the standard library
    Update(UpdateArgs),
    /// Print CLI and daemon version information
    Version,
    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the minimal CLI.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(min completions bash)"
    )]
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Print the effective networking policy for a session as JSON
    Policy(PolicyArgs),
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Session identifier (UUID or session name)
    pub session: String,
}

#[derive(Debug, Args)]
pub struct LoadoutArgs {
    #[command(subcommand)]
    pub command: LoadoutCommand,
}

#[derive(Debug, Subcommand)]
pub enum LoadoutCommand {
    /// List loadouts from the user's config directory
    #[command(visible_alias = "ls")]
    List(LoadoutListArgs),
}

#[derive(Debug, Args)]
pub struct LoadoutListArgs {
    /// Override the loadouts directory (default:
    /// `<config>/minimal/loadouts` per platform, e.g. `~/.config/minimal/loadouts` on Linux)
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

/// WireGuard mesh subcommands for authenticated remote PTask access (UC7 /
/// UC2b). The mesh lets a laptop, or another host's PTasks, reach this host's
/// PTasks over an encrypted tunnel.
#[cfg(feature = "remote-access")]
#[derive(Debug, Args)]
pub struct MeshArgs {
    #[command(subcommand)]
    pub command: MeshCommand,
}

#[cfg(feature = "remote-access")]
#[derive(Debug, Subcommand)]
pub enum MeshCommand {
    /// Enrol this machine into a remote minimald's WireGuard mesh
    ///
    /// v1 uses manual key exchange: this records the target and prints the
    /// steps to swap public keys. Once enrolled you can reach the remote
    /// host's own-IP PTasks by their switch IPs over the tunnel.
    ///
    /// Example:
    ///
    ///   minimal mesh join mesh.example.com:51820
    #[command(verbatim_doc_comment)]
    Join(MeshJoinArgs),
    /// Leave the WireGuard mesh and drop this machine's local enrolment
    ///
    /// Removes the local enrolment record written by `minimal mesh join`.
    /// Peer entries on the remote minimald must be removed there (manual v1).
    ///
    /// Example:
    ///
    ///   minimal mesh leave
    #[command(verbatim_doc_comment)]
    Leave,
    /// Show this minimald's mesh status: public key, advertised subnets, peers
    ///
    /// Queries the local minimald for its WireGuard public key, the switch
    /// subnets it advertises to the mesh, and each peer's last handshake.
    ///
    /// Example:
    ///
    ///   minimal mesh status
    #[command(verbatim_doc_comment)]
    Status,
}

#[cfg(feature = "remote-access")]
#[derive(Debug, Args)]
pub struct MeshJoinArgs {
    /// Address of the remote minimald exposing the mesh (`host:port`)
    pub address: String,
}

/// Shared arguments all subcommands
///
/// The `Default` value is the no-flags invocation (no overrides, native
/// backend) — what a bare `min <cmd>` resolves to, and what indirect
/// entrypoints like the `git-remote-min` helper mode (which git invokes
/// without any of our flags) use.
#[derive(Debug, Default, Args)]
pub struct GlobalArgs {
    /// Use the given directory as the repository root, instead of the current
    /// working directory.
    #[arg(long, short = 'C')]
    pub repo_dir: Option<PathBuf>,
    /// Override the base directory used for operations (default: ~/.cache/minimal)
    #[arg(long)]
    pub minimal_dir: Option<PathBuf>,
    /// Override the user config directory. Everything under
    /// `<config_dir>/minimal/` (config.toml, loadouts/, ...) is
    /// resolved relative to this. Defaults to the platform's config
    /// dir — `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config` when
    /// that's unset). macOS uses `$HOME/.config` for consistency with
    /// state and cache dirs, not `~/Library/Application Support`.
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    /// Linux: run minimald inside the minvmd microVM (DM1) instead of natively
    /// on the host (DM2, the default). No effect on macOS, where minvmd is the
    /// only backend.
    #[arg(long, global = true)]
    pub minvmd: bool,
}

#[derive(Debug, Args)]
pub struct ActivateArgs {
    /// Optional session name
    #[arg(long, short)]
    pub name: Option<String>,
    /// Project path to activate (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: String,
    /// How to load project files into the session.
    #[arg(long, value_enum, default_value_t = SyncMode::Tarball)]
    pub sync: SyncMode,
    /// Network mode: no-net, host-net (default), or own-ip.
    #[arg(long, value_enum, default_value_t = CliNetworkMode::HostNet)]
    pub network: CliNetworkMode,
    /// Static ingress port mapping `EXT:INT[/PROTO]` (PROTO = tcp|udp, default
    /// tcp). Repeatable. Requires `--network own-ip`.
    #[arg(long = "ingress", value_name = "EXT:INT[/PROTO]")]
    pub ingress: Vec<String>,
    /// Apply the named loadout from `<config>/minimal/loadouts/<NAME>.toml`.
    /// Repeatable. If any `--loadout` is specified, defaults from
    /// `[loadouts].default_loadouts` in the client config are ignored.
    #[arg(long = "loadout", value_name = "NAME")]
    pub loadout: Vec<String>,
    /// Apply no loadouts at all — overrides both `--loadout` and the
    /// config's `default_loadouts`.
    #[arg(long, conflicts_with = "loadout")]
    pub no_loadouts: bool,
    /// Automatically attach after creation
    #[arg(long)]
    pub attach: bool,
}

/// Configuration for file sync during activation.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SyncMode {
    /// Stream a tarball of your project and unpack it into the session.
    Tarball,
    /// Do not populate the worktree of the session.
    None,
}

/// CLI surface for [`sessions::NetworkMode`]. A local `ValueEnum` keeps the
/// `sessions` crate free of a clap dependency.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum CliNetworkMode {
    NoNet,
    HostNet,
    OwnIp,
}

impl From<CliNetworkMode> for sessions::NetworkMode {
    fn from(m: CliNetworkMode) -> Self {
        match m {
            CliNetworkMode::NoNet => sessions::NetworkMode::NoNet,
            CliNetworkMode::HostNet => sessions::NetworkMode::HostNet,
            CliNetworkMode::OwnIp => sessions::NetworkMode::OwnIp,
        }
    }
}

/// Parse an `--ingress EXT:INT[/PROTO]` spec into a [`sessions::PortMapping`].
/// PROTO defaults to tcp; only tcp/udp are accepted (gvproxy's static forwarder
/// exposes no other transport).
fn parse_ingress_mapping(spec: &str) -> Result<sessions::PortMapping, anyhow::Error> {
    let (ports, proto) = match spec.split_once('/') {
        Some((ports, proto)) => (ports, parse_ingress_proto(proto)?),
        None => (spec, sessions::IpProto::Tcp),
    };
    let (ext, int) = ports
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("ingress '{spec}': expected EXT:INT[/PROTO]"))?;
    let external_port = ext
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("ingress '{spec}': invalid external port '{ext}'"))?;
    let internal_port = int
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("ingress '{spec}': invalid internal port '{int}'"))?;
    Ok(sessions::PortMapping {
        external_port,
        internal_port,
        proto,
    })
}

fn parse_ingress_proto(proto: &str) -> Result<sessions::IpProto, anyhow::Error> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(sessions::IpProto::Tcp),
        "udp" => Ok(sessions::IpProto::Udp),
        other => Err(anyhow::anyhow!(
            "ingress: unsupported protocol '{other}' (use tcp or udp)"
        )),
    }
}

#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Session identifier (UUID or session name)
    pub session: String,
    /// Command to exec in the session context (non-interactive)
    #[arg(long, short)]
    pub command: Option<String>,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    /// Output raw session IDs (one per line) for piping into scripts
    #[arg(long)]
    pub raw: bool,
    /// Output the full session list as JSON (pretty-printed)
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DestroyArgs {
    /// Session identifier (UUID or session name)
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    pub session: Option<String>,
    /// Destroy all sessions
    #[arg(long)]
    pub all: bool,
    /// Skip confirmation when destroying all sessions
    #[arg(long, short, requires = "all")]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// Force shutdown even if active sessions exist
    #[arg(long, short, default_value_t = false)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    /// Session identifier (UUID or session name)
    pub session: String,
    /// New name for the session
    pub new_name: String,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Skip confirmation, writing configuration based on auto-detection
    #[arg(long, short, default_value_t = false)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub kind: AddKind,

    /// Packages to add, space-separated
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = false, num_args = 0..)]
    pub packages: Vec<String>,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct AddKind {
    /// Add as a runtime dependency
    #[arg(long)]
    pub runtime: bool,
    /// Add as a build dependency
    #[arg(long)]
    pub build: bool,
    /// Add to a task's package list
    #[arg(long)]
    pub task: Option<String>,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// UDS socket path to connect to
    #[arg(long)]
    pub socket: Option<String>,
}

/// Arguments for `minimal ssh-forward`.
#[cfg(feature = "remote-access")]
#[derive(Debug, Args)]
pub struct SshForwardArgs {
    /// Session identifier (UUID or session name)
    pub session: String,
    /// Port-forward specification: `<local-port>:<remote-host>:<remote-port>`
    ///
    /// Example: `18080:127.0.0.1:80` to forward local port 18080 to port 80
    /// on the loopback address as seen from inside the session.
    #[arg(value_name = "LOCAL:REMOTE_HOST:REMOTE_PORT")]
    pub forward: String,
}

/// Arguments for `minimal login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Override the directory where client cert files are written
    /// (default: `~/.config/minimal/`).
    #[arg(long)]
    pub cert_dir: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    pub shell: Shell,
}

pub async fn run(cli: Cli) -> Result<(), anyhow::Error> {
    match cli.command {
        Command::Ls(args) => cmd_ls(&cli.global_args, args).await,
        Command::Activate(args) => cmd_activate(&cli.global_args, args).await,
        Command::Attach(args) => cmd_attach(&cli.global_args, args).await,
        Command::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
        Command::Stop(args) => cmd_stop(&cli.global_args, args).await,
        Command::Session(SessionArgs {
            command: SessionCommand::Policy(args),
        }) => cmd_session_policy(&cli.global_args, args).await,
        Command::Loadout(LoadoutArgs {
            command: LoadoutCommand::List(args),
        }) => loadouts::cmd_loadout_list(args, &cli.global_args),
        Command::Dirs => dirs::cmd_dirs(&cli.global_args),
        #[cfg(feature = "remote-access")]
        Command::Mesh(MeshArgs { command }) => match command {
            MeshCommand::Status => cmd_mesh_status(&cli.global_args).await,
            MeshCommand::Join(args) => cmd_mesh_join(&cli.global_args, args),
            MeshCommand::Leave => cmd_mesh_leave(&cli.global_args),
        },
        Command::Proxy(args) => cmd_proxy(&cli.global_args, args).await,
        #[cfg(feature = "remote-access")]
        Command::SshForward(args) => cmd_ssh_forward(&cli.global_args, args).await,
        Command::Login(args) => cmd_login(&cli.global_args, args).await,
        Command::Version => cmd_version(&cli.global_args).await,
        Command::Rename(args) => cmd_rename(&cli.global_args, args).await,
        Command::Init(args) => cmd_init(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Command::Add(args) => cmd_add(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Command::Update(args) => cmd_update(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Command::Completions(CompletionsArgs { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Connect to the daemon, resolving the socket path from global args.
pub async fn connect_daemon(global: &GlobalArgs) -> Result<client::Client, anyhow::Error> {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .context("Failed to resolve daemon socket path")?;

    client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")
}

/// A session reference parsed from a CLI string: either a UUID or a name.
/// Used to build the typed request enums both `GetSessionRecord` and
/// `GetSessionPolicy` expect.
enum SessionLookup {
    Id(sessions::SessionId),
    Name(String),
}

impl SessionLookup {
    /// Parse a user-supplied session string. If it parses as a UUID,
    /// the lookup is by ID; otherwise by name.
    fn parse(s: &str) -> Self {
        match sessions::SessionId::parse_str(s) {
            Ok(id) => Self::Id(id),
            Err(_) => Self::Name(s.to_string()),
        }
    }
}

impl From<SessionLookup> for minimald_rpc::GetSessionRecordRequest {
    fn from(l: SessionLookup) -> Self {
        match l {
            SessionLookup::Id(id) => Self::Id(id),
            SessionLookup::Name(n) => Self::Name(n),
        }
    }
}

impl From<SessionLookup> for minimald_rpc::GetSessionPolicyRequest {
    fn from(l: SessionLookup) -> Self {
        match l {
            SessionLookup::Id(id) => Self::Id(id),
            SessionLookup::Name(n) => Self::Name(n),
        }
    }
}

/// Resolve a session by UUID or name, returning its record.
///
/// Used by commands that need the full record before proceeding (destroy,
/// rename, attach, ssh-forward). If the string parses as a UUID, the session
/// is looked up by ID; otherwise by name. Bails if no session matches.
async fn resolve_session(
    client: &mut client::Client,
    session: &str,
) -> Result<sessions::Record, anyhow::Error> {
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let lookup: GetSessionRecordRequest = SessionLookup::parse(session).into();
    let resp = client
        .oneshot_rpc::<GetSessionRecord>(lookup)
        .await
        .context("GetSessionRecord RPC failed")?;
    match resp.record {
        Some(r) => Ok(r),
        None => bail!("No session found matching '{session}'"),
    }
}

/// Bidirectionally pipe stdio to a daemon UDS socket.
///
/// Intended for use as an SSH `ProxyCommand`: ssh writes to our stdin and
/// reads from our stdout, while we bridge both directions to the UDS.
pub async fn cmd_proxy(global: &GlobalArgs, args: ProxyArgs) -> Result<(), anyhow::Error> {
    let socket_path = match args.socket {
        Some(socket_path) => socket_path,
        None => {
            ensure_daemon(global)?;
            client::resolve_socket_path(global.minimal_dir.as_deref())
                .context("Failed to resolve daemon socket path")?
                .to_str()
                .unwrap()
                .to_string()
        }
    };

    let stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("connect to {}", socket_path))?;

    let (mut rx, mut tx) = stream.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let to_sock = async {
        tokio::io::copy(&mut stdin, &mut tx).await?;
        tx.shutdown().await
    };
    let from_sock = tokio::io::copy(&mut rx, &mut stdout);

    tokio::try_join!(to_sock, from_sock).context("proxy")?;
    Ok(())
}

/// Ensure the minimald daemon is running, autospawning it if necessary.
fn ensure_daemon(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    autospawn::ensure_daemon_running(global.minvmd, global.minimal_dir.as_deref())
        .context("Failed to ensure the minimald daemon is running")
}

/// Prompt the user with a yes/no question on stderr.
fn confirm(question: &str, default: bool) -> Result<bool, anyhow::Error> {
    let prompt = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {prompt} ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading stdin")?;
    let trimmed = input.trim();
    Ok(if trimmed.is_empty() {
        default
    } else {
        trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
    })
}

/// List sessions via the `ListSessions` RPC.
pub async fn cmd_ls(global: &GlobalArgs, args: LsArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::ListSessions;
    let resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;

    format_ls(&mut std::io::stdout(), &args, &resp)?;
    Ok(())
}

/// Format the session list for the given output mode. Split from
/// [`cmd_ls`] so integration tests can capture output into a buffer
/// instead of stdout.
pub fn format_ls(
    out: &mut impl std::io::Write,
    args: &LsArgs,
    resp: &minimald_rpc::ListSessionsResponse,
) -> Result<(), anyhow::Error> {
    if args.json {
        let json =
            serde_json::to_string_pretty(resp).context("Failed to serialize session list")?;
        writeln!(out, "{json}")?;
        return Ok(());
    }

    if resp.sessions.is_empty() {
        if !args.raw {
            writeln!(out, "No active sessions.")?;
        }
        return Ok(());
    }

    if args.raw {
        for entry in &resp.sessions {
            writeln!(out, "{}", entry.id)?;
        }
        return Ok(());
    }

    // Format as a table: ID, Name, Title, Last Activity.
    // Widths chosen to fit a standard 80-col terminal.
    writeln!(
        out,
        "{:<36}  {:<20}  {:<20}  LAST ACTIVITY",
        "SESSION ID", "NAME", "TITLE"
    )?;
    writeln!(out, "{:-<36}  {:-<20}  {:-<20}  {:-<24}", "", "", "", "")?;

    for entry in &resp.sessions {
        let id = entry.id.to_string();
        let name = entry.name.as_deref().unwrap_or("-");
        let (title, last_activity) = match &entry.attrs {
            Some(attrs) => {
                let title = attrs
                    .title
                    .as_ref()
                    .map(|t| t.value.as_str())
                    .unwrap_or("-");
                let last = attrs
                    .last_stdout
                    .or(attrs.last_stdin)
                    .map(|dt| {
                        let local = dt.with_timezone(&chrono::Local);
                        local.format("%Y-%m-%d %H:%M:%S").to_string()
                    })
                    .unwrap_or_else(|| "-".to_string());
                (title, last)
            }
            None => ("-", "-".to_string()),
        };
        writeln!(out, "{id:<36}  {name:<20}  {title:<20}  {last_activity}")?;
    }

    Ok(())
}

/// Default policy hook for `minimal activate`: auto-approves any
/// item whose provenance is [`Source::Project`] or
/// [`Source::Package`], and aborts on anything else.
///
/// Rationale: items reaching a hook are those the base
/// [`UserPolicy`] couldn't auto-decide — with today's `Source`
/// palette, that's exclusively project- and package-level
/// contributions. Both come from the mfile / graph the user
/// activated against, so activating the project implicitly
/// consents to what it declares. A future [`Source`] variant we
/// don't recognize hits the safe path (`Abort`) rather than
/// getting silently allowed.
///
/// Once `minimal activate` grows a real `--policy` / `--allow`
/// interface, this hook stays as the default when no explicit
/// policy is provided.
///
/// [`Source::Project`]: sessions::core::source::Source::Project
/// [`Source::Package`]: sessions::core::source::Source::Package
/// [`UserPolicy`]: sessions::core::policy::UserPolicy
struct ApproveProjectAndPackage;

/// Return per-item [`AllowOnce`] decisions when every source in
/// `sources` is a trusted daemon-side origin ([`Source::Project`]
/// or [`Source::Package`]). `None` on any other source, which the
/// caller maps to [`HookResult::Abort`].
///
/// [`AllowOnce`]: sessions::core::decision::ItemDecision::AllowOnce
/// [`Source::Project`]: sessions::core::source::Source::Project
/// [`Source::Package`]: sessions::core::source::Source::Package
/// [`HookResult::Abort`]: sessions::core::hooks::HookResult::Abort
fn decisions_for_trusted_sources<'a, I>(
    sources: I,
) -> Option<Vec<sessions::core::decision::ItemDecision>>
where
    I: IntoIterator<Item = &'a sessions::core::source::Source>,
{
    let mut decisions = Vec::new();
    for source in sources {
        match source {
            sessions::core::source::Source::Project { .. }
            | sessions::core::source::Source::Package { .. } => {
                decisions.push(sessions::core::decision::ItemDecision::AllowOnce);
            }
            _ => return None,
        }
    }
    Some(decisions)
}

impl sessions::core::hooks::PolicyHooks for ApproveProjectAndPackage {
    fn on_var_unapproved(
        &self,
        _policy: sessions::core::policy::VarsPolicy,
        items: &[sessions::core::hooks::Unapproved<'_, str>],
    ) -> sessions::core::hooks::HookResult<sessions::core::policy::VarsPolicy> {
        decisions_for_trusted_sources(items.iter().map(|u| u.source()))
            .map(sessions::core::hooks::HookResult::decided)
            .unwrap_or(sessions::core::hooks::HookResult::Abort)
    }

    fn on_patch_unapproved(
        &self,
        _policy: sessions::core::policy::PatchPolicy,
        items: &[sessions::core::hooks::Unapproved<'_, camino::Utf8Path>],
    ) -> sessions::core::hooks::HookResult<sessions::core::policy::PatchPolicy> {
        decisions_for_trusted_sources(items.iter().map(|u| u.source()))
            .map(sessions::core::hooks::HookResult::decided)
            .unwrap_or(sessions::core::hooks::HookResult::Abort)
    }
}

/// Phase 3 + final SubmitVerdict round-trip for a `Pending` session.
///
/// `policy` is the user's own [`UserPolicy`](sessions::core::policy::UserPolicy)
/// loaded from `user_policy.toml`; daemon-side pending items
/// (packages, projects) are gated against it here on the client.
async fn drive_pending_to_active(
    client: &mut client::Client,
    response: sessions::wire::request::ContributionResponse,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
) -> Result<sessions::SessionId, anyhow::Error> {
    use minimald_rpc::SubmitVerdict;
    use sessions::client::handler::handle_response;
    use sessions::wire::request::SessionStep;

    let session_id = response.session_id;

    let hooks = ApproveProjectAndPackage;
    let verdict = match handle_response(response, &[], policy, &hooks, options, &|name| {
        std::env::var(name)
    }) {
        Ok(v) => v,
        Err(e) => {
            send_abort(client, session_id).await;
            bail!("Composition gating failed: {e}");
        }
    };

    let resp = client
        .oneshot_rpc::<SubmitVerdict>(verdict)
        .await
        .context("SubmitVerdict RPC failed")?;
    let step = match resp {
        minimald_rpc::Errorable::Ok(s) => s,
        minimald_rpc::Errorable::Err { error } => {
            bail!("SubmitVerdict failed: {error}");
        }
    };
    match step {
        SessionStep::Active { id } => Ok(id),
        SessionStep::Fault { error } => {
            bail!("SubmitVerdict faulted: {error}");
        }
    }
}

/// Fire an `AbortSession` at the daemon for a `Pending` session the
/// client has decided not to finalize. A best-effort teardown.
async fn send_abort(client: &mut client::Client, session_id: sessions::SessionId) {
    use minimald_rpc::AbortSession;
    match client
        .oneshot_rpc::<AbortSession>(minimald_rpc::AbortSessionRequest { id: session_id })
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(_)) => {}
        Ok(minimald_rpc::Errorable::Err { error }) => {
            eprintln!("AbortSession failed: {error}");
        }
        Err(e) => {
            eprintln!("AbortSession RPC failed: {e}");
        }
    }
}

/// Whether the project already has a `minimal.toml`, in either the root
/// (`<project>/minimal.toml`) or `.minimal/`
/// (`<project>/.minimal/minimal.toml`) layout.
///
/// Uses [`mfile::File::from_dir`] — the same resolver the CLI loads config
/// with — rather than a naive `join(MFILE_NAME)`, so detection matches the
/// path the init writer would target and we never scaffold over a config
/// living under `.minimal/`. Any outcome other than [`mfile::Error::NotFound`]
/// (including a present-but-malformed file) counts as "exists".
fn project_has_mfile(project_path: &camino::Utf8Path) -> bool {
    !matches!(
        mfile::File::from_dir(project_path.as_std_path()),
        Err(mfile::Error::NotFound)
    )
}

/// Offer to initialize a `minimal.toml` at the project path when it has
/// none, on the way into an activation.
///
/// Purely an offer: a project without one still activates. The daemon never
/// reads this path — it is a path on the *client's* machine — and fabricates
/// a default shell-stack `minimal.toml` inside the session's own workspace
/// instead, so the session comes up either way. Scaffolding here is a
/// convenience for the interactive case (the project gets a real config it
/// can grow), not a precondition.
fn offer_mfile_scaffold(
    project_path: &camino::Utf8Path,
    global: &GlobalArgs,
) -> Result<(), anyhow::Error> {
    if project_has_mfile(project_path) {
        return Ok(());
    }

    eprintln!("\nNo {} found at {}.", mfile::MFILE_NAME, project_path);

    // `confirm` treats empty/EOF input as "yes", so on non-interactive
    // stdin (CI, pipes, agents) it would silently default this scaffold to
    // "yes" — and, when a config is discovered under `.minimal/`, the init
    // writer would clobber it. Only prompt on a real terminal; anywhere else
    // (and on a declined prompt) carry on without scaffolding.
    if !std::io::stdin().is_terminal() || !confirm("Would you like to create one?", true)? {
        eprintln!(
            "Continuing without one; the session gets a default environment. \
             Run 'minimal init' to give the project its own config."
        );
        return Ok(());
    }

    let config = if global.repo_dir.is_some() {
        build_config(global).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        let mut builder = mctx::ConfigBuilder::new();
        if let Some(dir) = &global.minimal_dir {
            builder = builder.with_state_dir(dir).with_cache_dir(dir);
        }
        builder
            .with_repo_dir(project_path.as_std_path())
            .build()
            .map_err(|e| anyhow::anyhow!("{e}"))?
    };
    run_init_flow(config, false)
}

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let project_path = std::fs::canonicalize(&args.path)
        .with_context(|| format!("Cannot resolve project path '{}'", args.path))?;

    let utf8_path = camino::Utf8PathBuf::from_path_buf(project_path)
        .map_err(|_| anyhow::anyhow!("Project path is not valid UTF-8"))?;
    let abs_path =
        paths::HostAbsPath::try_new(utf8_path.clone()).context("Invalid project path")?;

    offer_mfile_scaffold(&utf8_path, global)?;

    let mut port_mappings = Vec::with_capacity(args.ingress.len());
    for spec in &args.ingress {
        let mapping = parse_ingress_mapping(spec)?;
        port_mappings.push(mapping);
    }
    let policy = sessions::SessionPolicy {
        egress: None,
        ingress: (!port_mappings.is_empty()).then_some(sessions::IngressPolicy {
            port_mappings,
            dynamic_allowed_range: None,
        }),
    };

    // The daemon sources `username` from the authenticated SSH
    // connection context; the client doesn't send it.
    let config = minimald_rpc::SessionConfig {
        name: args.name.clone(),
        project_path: abs_path,
        network: args.network.into(),
        policy,
        attrs: Default::default(),
    };

    // Resolve and compose the loadouts BEFORE opening the daemon
    // connection: a missing loadout file or a malformed one should
    // fail loudly on the client side without ever touching the
    // daemon.
    let cfg = config::read_client_config(global)?;
    let user_policy = config::read_user_policy(global)?;
    let compose_options = loadouts::compose_options_from_config(&cfg);
    let selection = loadouts::LoadoutSelection::from_flags(&args.loadout, args.no_loadouts);
    let active = loadouts::resolve_active_loadouts(selection, &cfg, global)?;
    if !active.is_empty() {
        let names: Vec<&str> = active.iter().map(|l| l.name().as_ref()).collect();
        eprintln!("Applying loadouts: {}", names.join(", "));
    }
    let contribution =
        loadouts::compose_user_contribution(active, user_policy.clone(), compose_options)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
    };
    let resp = client
        .oneshot_rpc::<CreateSession>(CreateSessionRequest { config })
        .await
        .context("CreateSession RPC failed")?;

    // Surface the daemon's typed policy/network-mode validation error (e.g.
    // ingress on a non-own-ip session, privileged host port) rather than a
    // generic failure line.
    let created = match resp {
        minimald_rpc::Errorable::Ok(r) => r,
        minimald_rpc::Errorable::Err { error } => {
            bail!("CreateSession failed: {error}");
        }
    };
    let id = created.id;

    // The session exists but has no loadout yet; composing it is a second
    // round-trip because the daemon's composer reads the project config out
    // of the session's workspace, not from a path on this machine.
    let configured = client
        .oneshot_rpc::<ConfigureLoadout>(ConfigureLoadoutRequest {
            session_id: id,
            contribution,
        })
        .await
        .context("ConfigureLoadout RPC failed")?;
    let configured = match configured {
        minimald_rpc::Errorable::Ok(r) => r,
        minimald_rpc::Errorable::Err { error } => {
            bail!("ConfigureLoadout failed: {error}");
        }
    };
    // The daemon may finalize immediately (`Ready`) or ask the
    // client to gate items first (`Pending`).
    if let minimald_rpc::ConfigureLoadoutResponse::Pending { response } = configured {
        drive_pending_to_active(&mut client, response, user_policy, compose_options).await?;
    }

    // Upload the project directory to the daemon so the session
    // sandbox has the user's files available.
    match args.sync {
        SyncMode::None => {}
        SyncMode::Tarball => {
            eprintln!("Uploading project files...");
            client
                .upload_workspace_files(id, utf8_path.as_std_path())
                .await
                .context("Failed to upload project files")?;
        }
    };

    println!("{id}");

    if args.attach {
        // Chain into attach.
        let attach_args = AttachArgs {
            session: id.to_string(),
            command: None,
        };
        return cmd_attach(global, attach_args).await;
    }

    Ok(())
}

/// Shell-quote a string for safe interpolation into `sh -c`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Quote a path for use as an `ssh -o` option value.
///
/// ssh re-parses the value as a config line, splitting on whitespace to allow a
/// file list and honouring `\` escapes inside quotes. So the quotes carry a path
/// with spaces, and `\`/`"` must be escaped within them — unescaped, a `"`
/// resolves the option to the wrong file and a trailing `\` swallows the closing
/// quote, both of which make ssh reject the line outright.
fn ssh_opt_quote(path: &std::path::Path) -> String {
    // Backslashes first: escaping quotes introduces backslashes of its own.
    let escaped = path
        .display()
        .to_string()
        .replace('\\', r"\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// The `ssh` host-key options for attaching, given the `known_hosts` sitting
/// next to the daemon socket.
///
/// minvmd records the guest's host key there from the boot beacon, so when the
/// file is present we pin against it. A native minimald also writes this.
fn host_key_opts(known_hosts: &std::path::Path) -> [String; 2] {
    if known_hosts.is_file() {
        [
            "StrictHostKeyChecking=yes".to_string(),
            format!("UserKnownHostsFile={}", ssh_opt_quote(known_hosts)),
        ]
    } else {
        [
            "StrictHostKeyChecking=no".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
        ]
    }
}

/// Attach to an existing session. Both interactive and `--command` paths
/// shell out to `ssh` — the daemon's shell_request handler mints a PTY-backed
/// session shell, and ssh handles termios/PTY management for us.
pub async fn cmd_attach(global: &GlobalArgs, args: AttachArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    let record = resolve_session(&mut client, &args.session).await?;

    tracing::info!(
        session_id = %record.id,
        session_name = ?record.name,
        "found session"
    );

    // Shell out to ssh for both interactive and --command attachment.
    // ProxyCommand points at our own `proxy` subcommand so we don't
    // depend on socat or nc being installed.
    let exe = std::env::current_exe().context("cannot determine current exe")?;
    let proxy_cmd = format!(
        "{} proxy --socket {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&sock.display().to_string()),
    );

    let [strict, known_hosts_file] = host_key_opts(&sock.with_file_name(paths::KNOWN_HOSTS_FILE));

    let mut ssh = std::process::Command::new("ssh");
    ssh.env("MINIMAL_SESSION_ID", record.id.to_string()).args([
        "-o",
        "SendEnv=MINIMAL_SESSION_ID",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        &strict,
        "-o",
        &known_hosts_file,
    ]);

    // The interactive path opens the in-sandbox session shell via the daemon's
    // `shell_request`, which requires a PTY. Force one with `-tt` so the shell
    // works even when our stdin is not a tty (e.g. driven from a script for
    // automated networking tests); without it ssh skips the PTY and the daemon
    // rejects the shell. The `--command` path is a non-interactive exec and
    // needs no PTY.
    if args.command.is_none() {
        ssh.arg("-tt");
    }
    ssh.arg("local-0");

    // If a command was provided, pass it to ssh (non-interactive exec).
    // Otherwise, ssh opens an interactive shell via shell_request.
    if let Some(ref cmd) = args.command {
        ssh.arg(cmd);
    }

    let err = ssh.exec();
    // exec() only returns on failure
    bail!("failed to exec ssh: {err}");
}

/// Print the effective networking policy for a session as JSON.
pub async fn cmd_session_policy(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let lookup: GetSessionPolicyRequest = SessionLookup::parse(&args.session).into();

    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(lookup)
        .await
        .context("GetSessionPolicy RPC failed")?;

    match resp {
        minimald_rpc::Errorable::Ok(policy) => {
            let json = serde_json::to_string(&policy).context("Failed to serialize policy")?;
            println!("{json}");
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("{error}")
        }
    }
}

/// The local mesh-enrolment record path. `--minimal-dir` still wins for
/// the historical "everything lives under the state dir" workflow;
/// otherwise falls through to the loadout-subsystem's config dir
/// so `--config-dir` moves the mesh enrolment along with everything
/// else.
///
/// Not gated behind `remote-access`: it is a pure path helper the `dirs` debug
/// command surfaces regardless of whether the mesh commands are compiled in.
pub fn mesh_enrolment_path(global: &GlobalArgs) -> PathBuf {
    let base = match &global.minimal_dir {
        Some(dir) => dir.clone(),
        None => config::resolve_minimal_config_dir(global),
    };
    base.join("mesh-enrolment")
}

/// Show this minimald's WireGuard mesh status (R4.6): own public key, the
/// switch subnets it advertises, and each peer's last handshake.
#[cfg(feature = "remote-access")]
pub async fn cmd_mesh_status(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::GetMeshStatus;
    let resp = client
        .oneshot_rpc::<GetMeshStatus>(())
        .await
        .context("GetMeshStatus RPC failed")?;

    if !resp.configured {
        println!("No WireGuard mesh is configured on this minimald.");
        return Ok(());
    }

    println!(
        "public key:  {}",
        resp.own_public_key.as_deref().unwrap_or("-")
    );
    if resp.advertised_subnets.is_empty() {
        println!("advertised:  (none)");
    } else {
        println!("advertised:  {}", resp.advertised_subnets.join(", "));
    }

    if resp.peers.is_empty() {
        println!("peers:       (none)");
        return Ok(());
    }

    println!("peers:");
    println!("  {:<20}  {:<46}  LAST HANDSHAKE", "NAME", "PUBLIC KEY");
    for p in &resp.peers {
        let handshake = match p.last_handshake_secs {
            Some(secs) => format!("{secs}s ago"),
            None => "never".to_string(),
        };
        println!("  {:<20}  {:<46}  {handshake}", p.name, p.public_key);
    }

    Ok(())
}

/// Record this machine's enrolment into a remote minimald's mesh (R4.3, v1
/// manual key exchange) and print the steps to complete the key swap.
#[cfg(feature = "remote-access")]
pub fn cmd_mesh_join(global: &GlobalArgs, args: MeshJoinArgs) -> Result<(), anyhow::Error> {
    // Validate the endpoint at the point of entry so a typo never lands a bad
    // enrolment on disk for a later consumer to choke on. The CLI contract is
    // `host:port`; require a non-empty host and a parseable u16 port.
    let Some((host, port)) = args.address.rsplit_once(':') else {
        bail!("mesh join address must be host:port, e.g. mesh.example.com:51820")
    };
    if host.is_empty() || port.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
        bail!("mesh join address must include a non-empty host and a valid non-zero port");
    }

    let path = mesh_enrolment_path(global);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, format!("{}\n", args.address))
        .with_context(|| format!("writing {}", path.display()))?;

    println!(
        "Recorded mesh enrolment for {} at {}.",
        args.address,
        path.display()
    );
    println!();
    println!("v1 uses manual key exchange. To complete the join:");
    println!("  1. Run `minimal mesh status` on the remote host to read its public key.");
    println!("  2. Add this machine's WireGuard public key to the remote minimald's peers.");
    println!("  3. Add the remote's public key and endpoint to this machine's mesh config.");
    Ok(())
}

/// Drop this machine's local mesh enrolment (R4.3). Remote peer entries are
/// removed on the remote host (manual v1).
#[cfg(feature = "remote-access")]
pub fn cmd_mesh_leave(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let path = mesh_enrolment_path(global);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!(
                "Left the mesh; removed local enrolment at {}.",
                path.display()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No local mesh enrolment to remove.");
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Destroy (terminate) a session.
pub async fn cmd_destroy(global: &GlobalArgs, args: DestroyArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    if args.all {
        return destroy_all_sessions(&mut client, args.force).await;
    }

    let session = args
        .session
        .as_deref()
        .context("a session or --all is required")?;
    let record = resolve_session(&mut client, session).await?;

    destroy_session(&mut client, record.id, record.name.as_deref()).await
}

async fn destroy_all_sessions(
    client: &mut client::Client,
    force: bool,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::ListSessions;

    let sessions = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?
        .sessions;

    if sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    if !force {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to destroy all sessions without confirmation; pass --force")
        }
        if !confirm(&format!("Destroy all {} sessions?", sessions.len()), false)? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let session_count = sessions.len();
    let mut failures = 0;
    for session in sessions {
        if let Err(error) = destroy_session(client, session.id, session.name.as_deref()).await {
            failures += 1;
            eprintln!(
                "Failed to destroy session {} ({}): {error:#}",
                session.id,
                session.name.as_deref().unwrap_or("-")
            );
        }
    }

    if failures > 0 {
        bail!("failed to destroy {failures} of {session_count} sessions")
    }

    Ok(())
}

async fn destroy_session(
    client: &mut client::Client,
    id: sessions::SessionId,
    name: Option<&str>,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{DestroySession, DestroySessionRequest};

    let resp = client
        .oneshot_rpc::<DestroySession>(DestroySessionRequest { id })
        .await
        .context("DestroySession RPC failed")?;

    if resp.ok().is_some() {
        println!("Destroyed session {} ({})", id, name.unwrap_or("-"));
    } else {
        bail!("DestroySession returned an error from the daemon");
    }

    Ok(())
}

/// Shut down the minimald daemon via the `Shutdown` RPC.
///
/// A daemon that is already down is the goal state, not a failure: `stop` says
/// so and exits 0. Without the probe the only way to find that out is to fail
/// connecting to it, which reports a connect error (or a timeout, against a
/// stale socket) for a machine that is in exactly the state asked for. Note the
/// deliberate asymmetry with every other command: they call `ensure_daemon` and
/// autospawn, which for `stop` would mean booting a VM in order to shut it down.
pub async fn cmd_stop(global: &GlobalArgs, args: StopArgs) -> Result<(), anyhow::Error> {
    // Cheap and bounded (a state-file read, or a connect to a local socket that
    // refuses at once when nothing listens), so it runs inline rather than on
    // the blocking pool — unlike the shutdown wait below, which sleep-polls.
    if !autospawn::is_daemon_running(global.minvmd, global.minimal_dir.as_deref())
        .context("Failed to determine whether the daemon is running")?
    {
        println!("Daemon is not running.");
        return Ok(());
    }

    // Racy by nature: the daemon may go down between the probe and this connect
    // (or `--minvmd` may point the probe and the client at different backends),
    // so a connect failure is still a real error, not something to swallow.
    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{Shutdown, ShutdownRequest, ShutdownResponse};
    let resp = client
        .oneshot_rpc::<Shutdown>(ShutdownRequest { force: args.force })
        .await
        .context("Shutdown RPC failed")?;

    match resp {
        ShutdownResponse::ShuttingDown => {
            // Drop our connection before waiting: the daemon holds the shutdown
            // open for its drain grace period while a client is still attached,
            // and we are that client.
            drop(client);
            println!("Daemon is shutting down.");
            // The wait polls the lifecycle file on a sleep loop, so it goes on
            // the blocking pool rather than stalling an async worker for up to
            // 20s (rust-coding-standards: no blocking in an async context).
            let (use_minvmd, minimal_dir) = (global.minvmd, global.minimal_dir.clone());
            tokio::task::spawn_blocking(move || {
                autospawn::wait_for_daemon_stopped(use_minvmd, minimal_dir.as_deref())
            })
            .await
            .context("The wait for the daemon to stop panicked")?
            .context("Failed while waiting for the daemon to stop")?;
            Ok(())
        }
        ShutdownResponse::SessionsLive => {
            bail!("daemon has active sessions; pass --force to shut down anyway")
        }
    }
}

/// Rename an existing session via the `RenameSession` RPC.
///
/// Resolves the session by UUID or name (like `destroy`), then issues
/// the rename. The new name takes effect immediately in the live session.
pub async fn cmd_rename(global: &GlobalArgs, args: RenameArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{RenameSession, RenameSessionRequest};
    let record = resolve_session(&mut client, &args.session).await?;

    let resp = client
        .oneshot_rpc::<RenameSession>(RenameSessionRequest {
            id: record.id,
            new_name: args.new_name.clone(),
        })
        .await
        .context("RenameSession RPC failed")?;

    match resp {
        minimald_rpc::Errorable::Ok(_) => {
            println!(
                "Renamed session {} ({}) → {}",
                record.id,
                record.name.as_deref().unwrap_or("-"),
                args.new_name
            );
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("RenameSession failed: {error}")
        }
    }
}

/// Establish an SSH `LocalForward` tunnel from a local port to a remote
/// address inside the named PTask's network namespace (R4.8, R4.9).
///
/// The forward spec is `<local-port>:<remote-host>:<remote-port>`. The
/// command shells out to `ssh -L` (the same mechanism as `cmd_attach`).
/// The `-N` flag keeps the tunnel alive without opening an interactive
/// shell.
#[cfg(feature = "remote-access")]
pub async fn cmd_ssh_forward(
    global: &GlobalArgs,
    args: SshForwardArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .context("Failed to resolve daemon socket path")?;

    // Look up the session to validate it exists and to obtain its UUID for the
    // server-side auth gate (passed as the SSH username so `direct-tcpip` can
    // verify the session without a per-channel env handshake).
    let mut daemon_client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    let record = resolve_session(&mut daemon_client, &args.session).await?;

    // Validate the forward spec format: local:remote_host:remote_port.
    // We accept either `local_port:host:port` (3 components, last two joined by
    // the final colon) or the more compact form where host is an IPv4 address.
    let parts: Vec<&str> = args.forward.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!(
            "invalid forward spec {:?}: expected LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
            args.forward
        );
    }
    let local_port = parts[0];
    let remote_host = parts[1];
    let remote_port = parts[2];
    let forward_arg = format!("{local_port}:{remote_host}:{remote_port}");

    let exe = std::env::current_exe().context("cannot determine current exe")?;
    let proxy_cmd = format!(
        "{} proxy --socket {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&sock.display().to_string()),
    );

    let session_id = record.id.to_string();
    // Use `-N` (no command) so the foreground ssh keeps the tunnel alive after
    // `exec()` replaces this process. `-o ExitOnForwardFailure=yes` makes ssh
    // exit immediately if the local port cannot be bound rather than silently
    // succeeding without a tunnel.
    let mut ssh = std::process::Command::new("ssh");
    ssh.args([
        "-L",
        &forward_arg,
        "-N",
        "-l",
        &session_id,
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "local-0",
    ]);

    // exec() replaces the process, so this call only returns on failure.
    let err = std::os::unix::process::CommandExt::exec(&mut ssh);
    bail!("failed to exec ssh: {err}");
}

/// Obtain an mTLS client certificate from minimald (R4.4).
///
/// Calls the `IssueClientCert` RPC, which has minimald generate a key pair,
/// sign the certificate with its internal CA, and return both. The cert, key,
/// and CA cert are written to `<cert_dir>/{client.pem,client.key,ca.pem}`.
pub async fn cmd_login(global: &GlobalArgs, args: LoginArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    let subject_cn = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "minimal-client".to_string());

    use minimald_rpc::{IssueClientCert, IssueClientCertRequest};
    let resp = client
        .oneshot_rpc::<IssueClientCert>(IssueClientCertRequest { subject_cn })
        .await
        .context("IssueClientCert RPC failed")?;

    let cert_resp = match resp {
        minimald_rpc::Errorable::Ok(r) => r,
        minimald_rpc::Errorable::Err { error } => {
            bail!("IssueClientCert failed: {error}");
        }
    };

    // Determine the cert directory. Honors `--cert-dir` first, then
    // routes through the shared config-dir helper so `--config-dir`
    // moves the certs alongside `config.toml` and `loadouts/`.
    let cert_dir = match args.cert_dir {
        Some(d) => d,
        None => config::resolve_minimal_config_dir(global),
    };
    std::fs::create_dir_all(&cert_dir)
        .with_context(|| format!("cannot create cert dir {}", cert_dir.display()))?;

    let client_cert_path = cert_dir.join("client.pem");
    let client_key_path = cert_dir.join("client.key");
    let ca_cert_path = cert_dir.join("ca.pem");

    std::fs::write(&client_cert_path, cert_resp.cert_pem.as_bytes())
        .with_context(|| format!("writing {}", client_cert_path.display()))?;
    {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&client_key_path)
            .with_context(|| format!("writing {}", client_key_path.display()))?;
        f.write_all(cert_resp.key_pem.as_bytes())
            .with_context(|| format!("writing {}", client_key_path.display()))?;
    }
    std::fs::write(&ca_cert_path, cert_resp.ca_cert_pem.as_bytes())
        .with_context(|| format!("writing {}", ca_cert_path.display()))?;

    println!("Saved client certificate to {}", client_cert_path.display());
    println!("Saved client key to {}", client_key_path.display());
    println!("Saved CA certificate to {}", ca_cert_path.display());
    println!();
    println!(
        "To use the HTTPS proxy:\n  curl --cacert {} --cert {} --key {} https://localhost:7655/",
        ca_cert_path.display(),
        client_cert_path.display(),
        client_key_path.display(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Build-system commands (local, no daemon).
//
// These mirror the legacy `minimal` binary's `init`, `add`, and `update`
// subcommands. They operate directly against the local package graph,
// VCS checkouts, and `minimal.toml` — they do not go through minimald.
// -----------------------------------------------------------------------

/// Build an `mctx::Config` from the shared global args.
pub fn build_config(global: &GlobalArgs) -> Result<mctx::Config, mctx::Error> {
    let mut builder = mctx::ConfigBuilder::new();
    if let Some(dir) = &global.minimal_dir {
        builder = builder.with_state_dir(dir).with_cache_dir(dir);
    }
    if let Some(dir) = &global.repo_dir {
        builder = builder.with_repo_dir(dir);
    }
    Ok(builder.build()?)
}

/// Run the init flow for a given config: detect the project's stack,
/// generate a `minimal.toml`, show the plan, prompt for confirmation,
/// and write the file. Shared by `cmd_init` and the `cmd_activate`
/// missing-mfile prompt.
fn run_init_flow(config: mctx::Config, skip_confirm: bool) -> Result<(), anyhow::Error> {
    use op::ProjectOp as _;
    let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let plan = op::InitProject
        .run(&mut env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if !skip_confirm {
        eprintln!("\nWill create {}:\n", plan.toml_path.display());
        eprintln!("---");
        eprint!("{}", plan.content);
        eprintln!("---");
        eprintln!();
        if !confirm("Continue?", true)? {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    std::fs::write(&plan.toml_path, &plan.content)
        .with_context(|| format!("writing {}", plan.toml_path.display()))?;

    eprintln!("Created {}", plan.toml_path.display());

    Ok(())
}

/// Initialize a `minimal.toml` based on the source tree.
pub async fn cmd_init(global: &GlobalArgs, args: InitArgs) -> Result<(), mctx::Error> {
    let config = build_config(global)?;
    run_init_flow(config, args.yes).map_err(mctx::Error::Other)
}

/// Add packages as dependencies to the project's `minimal.toml`.
pub async fn cmd_add(global: &GlobalArgs, args: AddArgs) -> Result<(), mctx::Error> {
    let config = build_config(global)?;
    let mut ctx = mctx::Context::new(config)?;

    let graph = ctx.graph_from_package_names(args.packages.clone())?;

    match args.kind {
        AddKind { build: true, .. } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::BuildPackages,
        )?,
        AddKind { runtime: true, .. } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::RuntimePackages,
        )?,
        AddKind {
            task: Some(task), ..
        } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::TaskPackages { name: task },
        )?,
        _ => unreachable!(),
    }

    ctx.download_if_available(&graph, graph.top_levels.clone())
        .await?;

    Ok(())
}

/// Refresh local checkouts of upstream packages & the standard library.
pub async fn cmd_update(global: &GlobalArgs, _args: UpdateArgs) -> Result<(), mctx::Error> {
    use op::ProjectOp as _;
    let config = build_config(global)?;
    let mut ctx = mctx::Context::new(config)?;

    let mut env = ctx.project_setup();
    let report = op::UpdateProject.run(&mut env)?;

    if let Some(c) = &report.upstream {
        println!(
            "Upstream {}:{} updated from {} to {}",
            c.repo,
            c.branch,
            c.from.as_deref().unwrap_or("<unpinned>"),
            c.to,
        );
    }
    for c in &report.sideloads {
        println!(
            "Sideload {}:{} updated from {} to {}",
            c.repo,
            c.branch,
            c.from.as_deref().unwrap_or("<unpinned>"),
            c.to,
        );
    }

    // Re-initialize the context to pick up the updated minimal.toml, then
    // download any newly-reachable packages.
    ctx = ctx.cloned_reinit()?;
    let graph = ctx.graph_from_all_packages()?;
    let ensure_pkgs = ctx.scaffolding_packages()?;
    ctx.download_if_available(&graph, ensure_pkgs).await?;

    Ok(())
}

/// Print CLI and daemon version information.
///
/// Always shows the CLI version. If the daemon is reachable, also shows
/// the daemon version and stdlib version. Unlike other commands, this does
/// not autospawn the daemon — it is a lightweight diagnostic that should
/// report versions without starting a VM.
pub async fn cmd_version(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    println!("Client: minimal {}", env!("LONG_VERSION"));

    let sock = match client::resolve_socket_path(global.minimal_dir.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    let mut client = match client::Client::connect(&sock).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    use minimald_rpc::GetVersion;
    let resp = match client.oneshot_rpc::<GetVersion>(()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    println!("Server: minimald {}", resp.long_version);
    println!("Stdlib: {}", resp.stdlib_version);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A VM-backed provider dir carries the guest's recorded host key, so
    /// attach must verify against it rather than waive the check.
    #[test]
    fn host_key_opts_pin_to_an_adjacent_known_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts = tmp.path().join(paths::KNOWN_HOSTS_FILE);
        std::fs::write(&known_hosts, "local-0 ssh-ed25519 AAAA...\n").unwrap();

        let [strict, hosts_file] = host_key_opts(&known_hosts);
        assert_eq!(strict, "StrictHostKeyChecking=yes");
        assert_eq!(
            hosts_file,
            format!("UserKnownHostsFile=\"{}\"", known_hosts.display())
        );
    }

    /// ssh re-parses the option value as a config line, so the path must survive
    /// its quote and backslash handling intact. These expectations were checked
    /// against OpenSSH's own parser with `ssh -G`.
    #[test]
    fn ssh_opt_quote_escapes_backslashes_and_quotes() {
        let q = |s: &str| ssh_opt_quote(std::path::Path::new(s));

        assert_eq!(q("/state/known_hosts"), r#""/state/known_hosts""#);
        // A space is why we quote at all: ssh would otherwise read a file list.
        assert_eq!(q("/st ate/known_hosts"), r#""/st ate/known_hosts""#);
        assert_eq!(q(r#"/st"ate/known_hosts"#), r#""/st\"ate/known_hosts""#);
        assert_eq!(q(r"/st\ate/known_hosts"), r#""/st\\ate/known_hosts""#);
        // A trailing backslash must not escape the closing quote.
        assert_eq!(q(r"/state\"), r#""/state\\""#);
    }

    /// The assembled option for a state dir carrying every character ssh's
    /// parser treats specially.
    #[test]
    fn host_key_opts_pin_to_a_path_needing_escapes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(r#"sp ace q"uote back\slash"#);
        std::fs::create_dir_all(&dir).unwrap();
        let known_hosts = dir.join(paths::KNOWN_HOSTS_FILE);
        std::fs::write(&known_hosts, "local-0 ssh-ed25519 AAAA...\n").unwrap();

        let [strict, hosts_file] = host_key_opts(&known_hosts);
        assert_eq!(strict, "StrictHostKeyChecking=yes");
        assert!(
            hosts_file.contains(r#"q\"uote"#) && hosts_file.contains(r"back\\slash"),
            "path must reach ssh escaped, got: {hosts_file}"
        );
    }

    #[test]
    fn ingress_spec_defaults_to_tcp() {
        let m = parse_ingress_mapping("18080:80").unwrap();
        assert_eq!(m.external_port, 18080);
        assert_eq!(m.internal_port, 80);
        assert_eq!(m.proto, sessions::IpProto::Tcp);
    }

    #[test]
    fn ingress_spec_parses_explicit_proto() {
        let m = parse_ingress_mapping("5353:53/udp").unwrap();
        assert_eq!(m.external_port, 5353);
        assert_eq!(m.internal_port, 53);
        assert_eq!(m.proto, sessions::IpProto::Udp);
    }

    #[test]
    fn ingress_spec_rejects_malformed_and_bad_proto() {
        assert!(parse_ingress_mapping("18080").is_err());
        assert!(parse_ingress_mapping("notaport:80").is_err());
        assert!(parse_ingress_mapping("18080:80/icmp").is_err());
    }

    /// All-Project sources → one `AllowOnce` per item. Baseline
    /// happy path for the client's default hook.
    #[test]
    fn decisions_for_trusted_sources_allows_all_project() {
        let sources = [
            sessions::core::source::Source::Project {
                path: paths::HostPath::new("/proj"),
            },
            sessions::core::source::Source::Project {
                path: paths::HostPath::new("/proj"),
            },
        ];
        let d =
            decisions_for_trusted_sources(sources.iter()).expect("all Project → Some decisions");
        assert_eq!(d.len(), 2);
        assert!(
            d.iter()
                .all(|x| matches!(x, sessions::core::decision::ItemDecision::AllowOnce))
        );
    }

    /// All-Package sources → same as Project. Same posture: the
    /// package came from the mfile / graph the user activated
    /// against, so activation implicitly consents.
    #[test]
    fn decisions_for_trusted_sources_allows_all_package() {
        let sources = [
            sessions::core::source::Source::Package {
                name: "go".to_string(),
            },
            sessions::core::source::Source::Package {
                name: "postgres".to_string(),
            },
        ];
        let d =
            decisions_for_trusted_sources(sources.iter()).expect("all Package → Some decisions");
        assert_eq!(d.len(), 2);
    }

    /// A mix of trusted sources still allows; the helper is
    /// per-item and doesn't care whether the item is a Project or
    /// Package one.
    #[test]
    fn decisions_for_trusted_sources_allows_mixed_project_and_package() {
        let sources = [
            sessions::core::source::Source::Project {
                path: paths::HostPath::new("/proj"),
            },
            sessions::core::source::Source::Package {
                name: "go".to_string(),
            },
        ];
        let d = decisions_for_trusted_sources(sources.iter())
            .expect("Project+Package → Some decisions");
        assert_eq!(d.len(), 2);
    }

    /// A single UserLoadout-origin item mixed in aborts the whole
    /// batch. `UserLoadout` items shouldn't reach a hook — user
    /// items auto-decide against the base `UserPolicy` — so seeing
    /// one here is a caller bug and we abort defensively.
    #[test]
    fn decisions_for_trusted_sources_aborts_on_user_loadout() {
        let sources = [
            sessions::core::source::Source::Project {
                path: paths::HostPath::new("/proj"),
            },
            sessions::core::source::Source::UserLoadout {
                name: "dev".to_string(),
            },
        ];
        assert!(
            decisions_for_trusted_sources(sources.iter()).is_none(),
            "any UserLoadout source in the batch → None → Abort",
        );
    }

    /// An empty source list is `Some(vec![])`. `HookResult::decided(vec![])`
    /// is the shape the gate expects on the (unusual but legal) empty-
    /// batch call.
    #[test]
    fn decisions_for_trusted_sources_empty_yields_empty_decisions() {
        let sources: [sessions::core::source::Source; 0] = [];
        let d = decisions_for_trusted_sources(sources.iter()).expect("empty → Some(empty)");
        assert!(d.is_empty());
    }

    /// Regression: a config in the `.minimal/` layout must be detected so
    /// `activate` returns without prompting and never scaffolds over it.
    /// The old naive `join(MFILE_NAME)` check missed this path.
    #[test]
    fn project_has_mfile_detects_dot_minimal_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mfile_dir = dir.path().join(".minimal");
        std::fs::create_dir(&mfile_dir).unwrap();
        std::fs::write(
            mfile_dir.join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();

        let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        assert!(
            project_has_mfile(path),
            "config under .minimal/ must be detected",
        );
    }

    /// A project with no config in either layout is genuinely missing an
    /// mfile, so detection reports false and the caller falls through to
    /// the (tty-gated) prompt.
    #[test]
    fn project_has_mfile_false_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        assert!(!project_has_mfile(path));
    }
}
