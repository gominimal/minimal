//! The minimal CLI which pairs/talks-with minimald.

use anyhow::{Context as _, bail};
use clap::{ArgGroup, Args, Parser, Subcommand};
use clap_complete::Shell;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt as _;

mod attach;
pub mod autospawn;
pub mod client;
pub mod completion;
pub mod completions;
pub mod config;
pub mod diag;
pub mod dirs;
mod file_upload;
pub mod git_remote;
pub mod loadouts;
pub mod prompt;

#[derive(Parser)]
#[command(name = "min", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(
    about = "min, the Minimal session CLI — create, attach to, and manage sandboxed development sessions"
)]
#[command(subcommand_required = false)]
pub struct Cli {
    // Optional: a bare `min` (no subcommand) resolves or activates a session
    // for the current directory — see `cmd_default`. Keeps every named
    // subcommand reachable unchanged when one is supplied.
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub global_args: GlobalArgs,
}

#[derive(Subcommand)]
pub enum Command {
    /// List sessions
    //
    // Deliberate exception to the `<noun> <verb>` convention (documented in
    // docs/reference/cli.md): `min ls` is the highest-traffic command in the
    // CLI and keeps its bare top-level form. Not an oversight — do not move it
    // under `session`.
    Ls(LsArgs),
    /// Shut down the minimald daemon
    //
    // Stays top-level: it acts on the daemon backend, not on any session, and
    // it is the daemon-lifecycle command people reach for. Documented as a
    // deliberate exception in docs/reference/cli.md.
    Stop(StopArgs),
    /// Session management subcommands
    #[command(visible_alias = "sessions")]
    Session(SessionArgs),
    /// Loadout management subcommands
    #[command(visible_alias = "loadouts")]
    Loadout(LoadoutArgs),
    /// Print important directories and file paths for debugging
    Dirs,
    /// Collect a diagnostic bundle (logs, state, config) to send to the
    /// minimal dev team.
    ///
    /// Writes `minimal-diag-<timestamp>.tar.zst` to the current directory.
    /// Secret-shaped values (env vars, tokens) are redacted and session/
    /// project file contents are never included — only name/size listings.
    /// Works even when no daemon is running; never starts one.
    Bug(diag::BugArgs),
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
    ///   min ssh-forward dev 18080:127.0.0.1:80
    ///
    ///   # Then access it from the host:
    ///   curl http://localhost:18080/
    #[cfg(feature = "remote-access")]
    #[command(name = "ssh-forward", visible_alias = "forward")]
    SshForward(SshForwardArgs),
    /// Obtain an mTLS client certificate for the HTTPS reverse proxy
    ///
    /// Connects to minimald, generates a fresh client certificate signed by
    /// the daemon's internal CA, and saves the certificate and
    /// private key to `~/.config/minimal/client.pem` /
    /// `~/.config/minimal/client.key`. Also saves the CA certificate to
    /// `~/.config/minimal/ca.pem` so tools like `curl` can trust the HTTPS
    /// proxy.
    ///
    /// Example:
    ///
    ///   min login
    ///   curl --cacert ~/.config/minimal/ca.pem \
    ///        --cert ~/.config/minimal/client.pem \
    ///        --key  ~/.config/minimal/client.key \
    ///        https://localhost:7655/
    #[command(verbatim_doc_comment)]
    #[command(hide = true)]
    Login(LoginArgs),
    // `init`, `add`, and `update` are deliberate exceptions to the
    // `<noun> <verb>` convention (documented in docs/reference/cli.md): they
    // are passthroughs to the project-configuration commands of the same name
    // in `mip`, and keeping the spelling identical across the two CLIs is
    // worth more than the hierarchy. Do not move them under a noun.
    /// Automatically initialize minimal configuration based on your source tree
    Init(InitArgs),
    /// Add a new tool or dependency
    Add(AddArgs),
    /// Refresh local checkouts of upstream packages & the standard library
    Update(UpdateArgs),
    /// Print CLI and daemon version information
    Version,
    /// Demo the client's activity spinner (development aid).
    ///
    /// Draws the same build-hold-fade spinner used by the file-upload
    /// phases of `min session activate` so you can eyeball timing and layout
    /// without triggering a real upload. Stops after `--seconds` or
    /// on Ctrl-C, whichever comes first.
    #[command(hide = true)]
    Spin(SpinArgs),
    /// Print session-identifier completion candidates (used by the shell).
    ///
    /// The completion path a shell actually takes runs in-process (see
    /// `completion.rs`); this is the same candidate list on stdout, one
    /// `value<TAB>description` per line. It exists to be debugged by hand and
    /// scripted against, and to honour global args — `--provider`,
    /// `--minimal-dir` — that the in-process completer cannot see.
    ///
    /// Never starts a daemon and never fails: no daemon means no output.
    #[command(name = completion::COMPLETE_SESSION_STR, hide = true)]
    CompleteSessionStr(CompleteSessionStrArgs),
    /// Print or install the shell tab-completion integration
    #[command(
        visible_alias = "completion",
        long_about = "Print or install the shell tab-completion integration for the min CLI.\n\n   source <(min completions print bash)\n   min completions install"
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
    /// Activate (create) a new session
    Activate(ActivateArgs),
    /// Attach to an existing session
    Attach(AttachArgs),
    /// Destroy (terminate) a session
    Destroy(DestroyArgs),
    /// Rename an existing session
    Rename(RenameArgs),
    /// Print the effective networking policy for a session as JSON
    Policy(PolicyArgs),
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
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
    ///   min mesh join mesh.example.com:51820
    #[command(verbatim_doc_comment)]
    Join(MeshJoinArgs),
    /// Leave the WireGuard mesh and drop this machine's local enrolment
    ///
    /// Removes the local enrolment record written by `min mesh join`.
    /// Peer entries on the remote minimald must be removed there (manual v1).
    ///
    /// Example:
    ///
    ///   min mesh leave
    #[command(verbatim_doc_comment)]
    Leave,
    /// Show this minimald's mesh status: public key, advertised subnets, peers
    ///
    /// Queries the local minimald for its WireGuard public key, the switch
    /// subnets it advertises to the mesh, and each peer's last handshake.
    ///
    /// Example:
    ///
    ///   min mesh status
    #[command(verbatim_doc_comment)]
    Status,
}

#[cfg(feature = "remote-access")]
#[derive(Debug, Args)]
pub struct MeshJoinArgs {
    /// Address of the remote minimald exposing the mesh (`host:port`)
    pub address: String,
}

// Shared arguments for all subcommands.
//
// The `Default` value is the no-flags invocation (no overrides, native
// backend) — what a bare `min <cmd>` resolves to, and what indirect
// entrypoints like the `git-remote-min` helper mode (which git invokes
// without any of our flags) use.
//
// Deliberately NOT a doc comment: clap propagates a flattened struct's doc
// comment into the parent command's long_about, which would replace the
// top-level `min --help` description with this text.
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
    /// Select the daemon backend that hosts sessions. On Linux, `local-minimald`
    /// (the default) runs minimald on the host; `local-minvmd` runs it inside
    /// the minvmd microVM. No effect on macOS, where minvmd is the only
    /// backend.
    #[arg(long, global = true, value_name = "PROVIDER")]
    pub provider: Option<Provider>,
    /// Skip interactive prompts that need a terminal (e.g. the session
    /// picker shown by bare `min` or `min session attach` with no session argument).
    /// When a choice is ambiguous, the command errors with a list of
    /// candidates instead of opening a picker. Implied when stdin/stdout is
    /// not a terminal.
    #[arg(long, global = true, default_value_t = false)]
    pub no_input: bool,
}

impl GlobalArgs {
    /// Whether the minvmd microVM backend (DM1) is selected via
    /// `--provider local-minvmd`.
    pub fn use_minvmd(&self) -> bool {
        matches!(self.provider, Some(Provider::LocalMinvmd))
    }
}

#[derive(Debug, Args)]
pub struct ActivateArgs {
    /// Optional session name
    #[arg(long, short)]
    pub name: Option<String>,
    /// Project path to activate. Defaults to the directory set by
    /// `-C`/`--repo-dir`, or the current working directory when neither
    /// is given.
    pub path: Option<String>,
    /// How to load project files into the session.
    #[arg(long, value_enum, default_value_t = SyncMode::Tarball)]
    pub sync: SyncMode,
    /// Network mode: no-net, host-net (default), or own-ip.
    ///
    /// Hidden from `--help` while `own-ip` is not usable on an installed host:
    /// the daemon resolves a switch binary that no install ships yet
    /// (gominimal/minimal#980), so advertising the flag offers a mode that
    /// cannot work outside a dev checkout. Still accepted, and `host-net`
    /// remains the default, so nothing that passes it today breaks. Unhide,
    /// and restore the row in docs/reference/cli-min.md, once own-ip works
    /// from an install.
    #[arg(long, value_enum, default_value_t = CliNetworkMode::HostNet)]
    #[clap(hide = true)]
    pub network: CliNetworkMode,
    /// Static ingress port mapping `EXT:INT[/PROTO]` (PROTO = tcp|udp, default
    /// tcp). Repeatable. Requires `--network own-ip`.
    ///
    /// Hidden for the same reason as `--network`: it is only meaningful with
    /// `--network own-ip`.
    #[arg(long = "ingress", value_name = "EXT:INT[/PROTO]")]
    #[clap(hide = true)]
    pub ingress: Vec<String>,
    /// Apply the named loadout from `<config>/minimal/loadouts/<NAME>.toml`.
    /// Repeatable. If any `--loadout` is specified, defaults from
    /// `[loadouts].default_loadouts` in the client config are ignored.
    #[arg(long = "loadout", value_name = "NAME")]
    pub loadout: Vec<String>,
    /// Apply no loadouts at all (also skips the config's
    /// `default_loadouts`). Conflicts with `--loadout`.
    #[arg(long, conflicts_with = "loadout")]
    pub no_loadouts: bool,
    /// Fail instead of prompting when the daemon returns items the
    /// user policy can't auto-decide. Useful for CI and other
    /// non-interactive contexts — the error message includes a
    /// `user_policy.toml` snippet that would make the activation
    /// succeed. This mode is also selected implicitly when stdin
    /// isn't attached to a terminal.
    #[arg(long)]
    pub no_prompt: bool,
    /// Automatically attach after creation
    #[arg(long)]
    pub attach: bool,
}

/// Which daemon backend ("provider") hosts sessions.
///
/// On Linux the default is the host-native daemon (DM2); `local-minvmd` runs
/// `minimald` inside the minvmd microVM (DM1) instead. On macOS minvmd is the
/// only backend, so the choice has no effect there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    /// Linux: run minimald natively on the host (the default).
    LocalMinimald,
    /// Run minimald inside the minvmd microVM.
    LocalMinvmd,
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
    /// Session identifier (UUID or session name). When omitted, `min session attach`
    /// resolves a session from the current working directory (or the only
    /// existing session), and opens an interactive picker if the choice is
    /// ambiguous. See `--no-input` to skip the picker in scripts.
    #[arg(add = completion::session_completer())]
    pub session: Option<String>,
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
#[command(group(ArgGroup::new("target").args(["session", "all"]).required(true).multiple(false)))]
pub struct DestroyArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
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
    #[arg(add = completion::session_completer())]
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
    /// Add to sessions using the project
    #[arg(long)]
    pub session: bool,
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
pub struct SpinArgs {
    /// How long to keep the spinner visible before auto-exiting.
    /// Ctrl-C cuts it short.
    #[arg(long, default_value_t = 10)]
    pub seconds: u64,
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// UDS socket path to connect to
    #[arg(long)]
    pub socket: Option<String>,
}

/// Arguments for `min ssh-forward`.
#[cfg(feature = "remote-access")]
#[derive(Debug, Args)]
pub struct SshForwardArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Port-forward specification: `<local-port>:<remote-host>:<remote-port>`
    ///
    /// Example: `18080:127.0.0.1:80` to forward local port 18080 to port 80
    /// on the loopback address as seen from inside the session.
    #[arg(value_name = "LOCAL:REMOTE_HOST:REMOTE_PORT")]
    pub forward: String,
}

/// Arguments for `min login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Override the directory where client cert files are written
    /// (default: `~/.config/minimal/`).
    #[arg(long)]
    pub cert_dir: Option<PathBuf>,
}

/// Arguments for the hidden `min complete-session-str`.
#[derive(Debug, Args)]
pub struct CompleteSessionStrArgs {
    /// Only offer candidates starting with this prefix (default: all).
    pub prefix: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    #[command(subcommand)]
    pub command: CompletionsCommand,
}

#[derive(Debug, Subcommand)]
pub enum CompletionsCommand {
    /// Print the shell integration on stdout
    #[command(
        long_about = "Print the shell integration for a shell on stdout.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(min completions print bash)"
    )]
    Print(CompletionsPrintArgs),
    /// Write the shell integration into each shell's completion directory
    #[command(
        long_about = "Write the shell integration into each shell's user-level completion directory,\nand print every path written on stdout, one per line.\n\n   bash  ${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/min\n   zsh   ${XDG_DATA_HOME:-~/.local/share}/zsh/completions/_min\n   fish  ${XDG_CONFIG_HOME:-~/.config}/fish/completions/min.fish\n\nA shell that cannot be installed for (an unwritable shared directory, say) is\na warning on stderr, not a failure."
    )]
    Install(CompletionsInstallArgs),
}

#[derive(Debug, Args)]
pub struct CompletionsPrintArgs {
    /// The shell to print the integration for
    #[arg(value_parser)]
    pub shell: Shell,
}

#[derive(Debug, Args)]
pub struct CompletionsInstallArgs {
    /// Shells to install for (default: every supported shell)
    pub shells: Vec<completions::InstallShell>,
}

/// The process-wide trace context, minted once at command dispatch. The
/// root span carries its ids into every log line, and the SSH client sends
/// the same context to the daemon as a `TRACEPARENT` channel env request —
/// one grep joins host and guest records.
pub(crate) fn trace_context() -> &'static minimald_rpc::trace::TraceContext {
    static CONTEXT: std::sync::OnceLock<minimald_rpc::trace::TraceContext> =
        std::sync::OnceLock::new();
    CONTEXT.get_or_init(minimald_rpc::trace::TraceContext::mint)
}

pub async fn run(cli: Cli) -> Result<(), anyhow::Error> {
    use tracing::Instrument as _;
    let ctx = trace_context();
    let root = tracing::info_span!(
        "cmd",
        trace_id = %ctx.trace_id_hex(),
        span_id = %ctx.span_id_hex(),
    );
    run_command(cli).instrument(root).await
}

async fn run_command(cli: Cli) -> Result<(), anyhow::Error> {
    // Adopt any pre-split `providers/local-<N>` dirs into the kind-tagged scheme
    // once per invocation, before any command resolves a provider dir, so an
    // upgraded CLI finds an existing instance rather than orphaning it.
    client::migrate_legacy_provider_dirs(cli.global_args.minimal_dir.as_deref());

    match cli.command {
        // A bare `min` (no subcommand) resolves-or-activates and attaches. A
        // deliberate exception to the `<noun> <verb>` convention, documented
        // in docs/reference/cli.md — see `cmd_default`.
        None => cmd_default(&cli.global_args).await,
        Some(Command::Ls(args)) => cmd_ls(&cli.global_args, args).await,
        Some(Command::Stop(args)) => cmd_stop(&cli.global_args, args).await,
        Some(Command::Session(SessionArgs { command })) => match command {
            SessionCommand::Activate(args) => cmd_activate(&cli.global_args, args).await,
            SessionCommand::Attach(args) => cmd_attach(&cli.global_args, args).await,
            SessionCommand::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
            SessionCommand::Rename(args) => cmd_rename(&cli.global_args, args).await,
            SessionCommand::Policy(args) => cmd_session_policy(&cli.global_args, args).await,
        },
        Some(Command::Loadout(LoadoutArgs {
            command: LoadoutCommand::List(args),
        })) => loadouts::cmd_loadout_list(args, &cli.global_args),
        Some(Command::Dirs) => dirs::cmd_dirs(&cli.global_args),
        Some(Command::Bug(args)) => diag::cmd_bug(&cli.global_args, args).await,
        #[cfg(feature = "remote-access")]
        Some(Command::Mesh(MeshArgs { command })) => match command {
            MeshCommand::Status => cmd_mesh_status(&cli.global_args).await,
            MeshCommand::Join(args) => cmd_mesh_join(&cli.global_args, args),
            MeshCommand::Leave => cmd_mesh_leave(&cli.global_args),
        },
        Some(Command::Proxy(args)) => cmd_proxy(&cli.global_args, args).await,
        #[cfg(feature = "remote-access")]
        Some(Command::SshForward(args)) => cmd_ssh_forward(&cli.global_args, args).await,
        Some(Command::Login(args)) => cmd_login(&cli.global_args, args).await,
        Some(Command::Version) => cmd_version(&cli.global_args).await,
        Some(Command::Spin(args)) => cmd_spin(&cli.global_args, args).await,
        Some(Command::Init(args)) => cmd_init(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::Add(args)) => cmd_add(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::Update(args)) => cmd_update(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::CompleteSessionStr(args)) => {
            completion::cmd_complete_session_str(&cli.global_args, args).await
        }
        Some(Command::Completions(CompletionsArgs { command })) => match command {
            CompletionsCommand::Print(args) => completions::cmd_print(args.shell),
            CompletionsCommand::Install(args) => completions::cmd_install(&args.shells),
        },
    }
}

/// Whether to announce the resolved or freshly created session on stderr
/// before handing off to the interactive shell. Suppressed under `--no-input`
/// and when stderr is not a terminal, so scripted and CI callers — which read
/// the session id from stdout — see nothing extra.
fn should_announce_session(global: &GlobalArgs) -> bool {
    !global.no_input && std::io::stderr().is_terminal()
}

/// A one-line identity for a session in an attach/create confirmation: the
/// session name plus a short id in parentheses, or just the short id when the
/// session is unnamed. The short id is the leading block of the UUID — enough
/// to tell two same-named sessions built from the same directory apart without
/// the full 36-character id.
fn session_announce_label(id: &sessions::SessionId, name: Option<&str>) -> String {
    let id = id.to_string();
    let short = id.split('-').next().unwrap_or(&id);
    match name {
        Some(name) => format!("{name} ({short})"),
        None => short.to_string(),
    }
}

/// The default action for a bare `min` (no subcommand): get the operator into
/// a session for the current directory with the least ceremony.
///
/// - No sessions exist → [`cmd_activate`] a new one with `--attach`, so a
///   fresh `min` lands the user in a shell.
/// - A session built from the current directory exists → attach to it
///   (auto-resolve, or picker if ambiguous).
/// - Otherwise → attach to the only session, or open a picker over all.
///
/// Shares smart resolution with `min session attach` (no session arg) via
/// [`resolve_smart_attach`]; the only difference is the `NoSessions` case,
/// which activates here instead of erroring.
async fn cmd_default(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    match resolve_smart_attach(&mut client, global).await? {
        Some(entry) => {
            tracing::info!(
                session_id = %entry.id,
                session_name = ?entry.name,
                "bare `min`: attaching to resolved session"
            );
            // Drop the listing connection before shelling out; the ssh child
            // holds its own proxy connection to the daemon.
            drop(client);
            attach_to_session(&sock, entry.id, None).await
        }
        None => {
            // No sessions exist: activate a new one for the current directory
            // (or -C/--repo-dir if set) and chain into attach, mirroring
            // `min session activate --attach`. `cmd_activate` resolves the path from
            // `global.repo_dir` when no positional is given, matching the
            // attach side's `cwd_host_path(global)`. But refuse first when that
            // chained attach could never run: creating then failing orphans the
            // session (#1031).
            ensure_activate_on_empty_allowed(global.no_input, std::io::stdin().is_terminal())?;
            drop(client);
            let activate_args = ActivateArgs {
                name: None,
                path: None,
                sync: SyncMode::Tarball,
                network: CliNetworkMode::HostNet,
                ingress: Vec::new(),
                loadout: Vec::new(),
                no_loadouts: false,
                // A non-interactive caller (--no-input, CI, a script) can't
                // answer the activation policy prompt; `cmd_activate` already
                // falls back to the `--no-prompt` path when stderr isn't a
                // terminal, so mirror that here rather than forcing a hang.
                no_prompt: global.no_input || !can_prompt_interactively(),
                attach: true,
            };
            cmd_activate(global, activate_args).await
        }
    }
}

/// Connect to the daemon, resolving the socket path from global args.
pub async fn connect_daemon(global: &GlobalArgs) -> Result<client::Client, anyhow::Error> {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
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
            client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
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
    autospawn::ensure_daemon_running(global.use_minvmd(), global.minimal_dir.as_deref())
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

/// The environment variable a shell sets to ask `min` for completions.
///
/// clap_complete's default, named here because both ends have to agree: the
/// shim rendered by [`completions::cmd_print`] sets it, and the `CompleteEnv`
/// call in `main.rs` reads it.
pub const COMPLETE_VAR: &str = "COMPLETE";

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

    if !args.raw
        && let Some(pool) = &resp.resource_pool
    {
        let session_count = resp.sessions.len();
        let core_label = if pool.cpu_cores == 1 { "core" } else { "cores" };
        let session_label = if session_count == 1 {
            "session"
        } else {
            "sessions"
        };
        writeln!(
            out,
            "RESOURCE POOL:  {} CPU {} · {} memory · shared by {} {}",
            pool.cpu_cores,
            core_label,
            format_memory(pool.memory_bytes),
            session_count,
            session_label,
        )?;
        writeln!(out)?;
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

fn format_memory(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        let gib = bytes as f64 / GIB as f64;
        if bytes.is_multiple_of(GIB) {
            format!("{gib:.0} GiB")
        } else {
            format!("{gib:.1} GiB")
        }
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

/// Whether the operator can be prompted interactively. The prompt
/// renders on stderr (so stderr must be a terminal) and reads
/// keypresses from stdin (so stdin must be a terminal too). If
/// either side is redirected we take the `--no-prompt` path — going
/// interactive when stdin is a pipe just hangs `dialoguer` and then
/// aborts with a much less helpful error than the `--no-prompt`
/// snippet the operator actually wants to paste.
fn can_prompt_interactively() -> bool {
    dialoguer::console::user_attended() && dialoguer::console::user_attended_stderr()
}

/// Phase 3 gate: run the user policy + hooks over the daemon's
/// pending items and produce the wire verdict (plus the final
/// policy after any hook mutations). Does NOT talk to the daemon —
/// the caller decides whether to actually submit or abort.
///
/// `policy` is the user's own [`UserPolicy`](sessions::core::policy::UserPolicy)
/// loaded from `user_policy.toml`; daemon-side pending items
/// (packages, projects) are gated against it here on the client.
/// `hooks` decides what happens when the policy can't auto-decide an
/// item — see [`crate::prompt`] for the two implementations
/// (interactive prompt vs. `--no-prompt` collect-and-abort).
///
/// Split from [`submit_verdict_and_wait`] so `NoPromptHook` — which
/// fake-approves every item to keep both var and patch hooks firing
/// — can be intercepted between "verdict computed" and "verdict
/// submitted"; otherwise a `--no-prompt` run would submit a bogus
/// approval on the wire.
fn compute_verdict(
    response: sessions::wire::request::ContributionResponse,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
    hooks: &dyn sessions::core::hooks::PolicyHooks,
) -> Result<
    (
        sessions::wire::request::ContributionVerdict,
        sessions::core::policy::UserPolicy,
    ),
    sessions::core::compose::ComposeError,
> {
    sessions::client::handler::handle_response(response, &[], policy, hooks, options, &|name| {
        std::env::var(name)
    })
}

/// Ship the verdict to the daemon and wait for `Active`. Every
/// failure path in here has to `send_abort` first — the daemon is
/// parked in `Draft{pending}` and leaks the session slot otherwise.
async fn submit_verdict_and_wait(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    verdict: sessions::wire::request::ContributionVerdict,
) -> Result<sessions::SessionId, anyhow::Error> {
    use minimald_rpc::SubmitVerdict;
    use sessions::wire::request::SessionStep;

    let resp = match client.oneshot_rpc::<SubmitVerdict>(verdict).await {
        Ok(r) => r,
        Err(e) => {
            send_abort(client, session_id).await;
            return Err(e).context("SubmitVerdict RPC failed");
        }
    };
    let step = match resp {
        minimald_rpc::Errorable::Ok(s) => s,
        minimald_rpc::Errorable::Err { error } => {
            send_abort(client, session_id).await;
            bail!("SubmitVerdict failed: {error}");
        }
    };
    match step {
        SessionStep::Materialized { id } => Ok(id),
        SessionStep::Fault { error } => {
            send_abort(client, session_id).await;
            bail!("SubmitVerdict faulted: {error}");
        }
    }
}

/// The interactive-prompt caller's happy path: gate, then submit,
/// then return the finalized id + policy + the verdict that was
/// submitted. The verdict is returned so the caller can pick the
/// approved daemon-side patches out for upload — those files were
/// only surfaced during Phase 3 and won't otherwise be available
/// to the client-side upload step. Any gating failure aborts the
/// daemon-side session before propagating.
async fn drive_pending_to_active(
    client: &mut client::Client,
    response: sessions::wire::request::ContributionResponse,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
    hooks: &dyn sessions::core::hooks::PolicyHooks,
) -> Result<
    (
        sessions::SessionId,
        sessions::core::policy::UserPolicy,
        Vec<(std::path::PathBuf, paths::SandboxRelPath)>,
    ),
    anyhow::Error,
> {
    let session_id = response.session_id;
    let (verdict, final_policy) = match compute_verdict(response, policy, options, hooks) {
        Ok(v) => v,
        Err(e) => {
            send_abort(client, session_id).await;
            bail!("Composition gating failed: {e}");
        }
    };
    // Extract the approved-patch destinations before submit consumes
    // the verdict — avoids cloning the whole wire type (both vars
    // and patches Vecs plus their owned strings) just so the caller
    // can walk one field of it after the fact.
    let approved_patches: Vec<_> = approved_patches_from_verdict(&verdict).collect();
    let id = submit_verdict_and_wait(client, session_id, verdict).await?;
    Ok((id, final_policy, approved_patches))
}

/// Collect the sandbox destinations of every `Approved` patch
/// verdict — the daemon-side patches the client just approved and
/// now needs to upload. `Ignored`/`Denied` verdicts contribute
/// nothing to the composition, so they're not uploaded.
fn approved_patches_from_verdict(
    verdict: &sessions::wire::request::ContributionVerdict,
) -> impl Iterator<Item = (std::path::PathBuf, paths::SandboxRelPath)> + '_ {
    verdict.patches.iter().filter_map(|v| match v {
        sessions::wire::policy::WirePatchVerdict::Approved {
            host_path,
            destination,
            ..
        } => Some((
            host_path.as_utf8_path().as_std_path().to_path_buf(),
            destination.clone(),
        )),
        sessions::wire::policy::WirePatchVerdict::Ignored { .. }
        | sessions::wire::policy::WirePatchVerdict::Denied { .. } => None,
    })
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

/// Best-effort destroy for a `Materializing` session the client
/// couldn't finalize (patch upload failed, network blip, etc.).
/// Unlike `AbortSession`, `DestroySession` works on any status
/// past `Pending`. Errors are logged, not propagated — the caller
/// is already reporting a primary error.
///
/// Bounded by a hard timeout: the same network conditions that
/// caused the primary error (wedged daemon, half-open SSH channel,
/// a VM whose bridge accepted but whose guest never answered) can
/// make the RPC hang indefinitely, which would swallow the
/// operator-visible primary error we're supposed to be racing
/// back to `cmd_activate`.
async fn best_effort_destroy(client: &mut client::Client, session_id: sessions::SessionId) {
    /// Ceiling on how long we let a cleanup RPC run. Chosen well
    /// above a healthy `DestroySession` (single-digit milliseconds
    /// on a UDS) so the timeout only fires against pathologies.
    const DESTROY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    use minimald_rpc::DestroySession;
    let call = client
        .oneshot_rpc::<DestroySession>(minimald_rpc::DestroySessionRequest { id: session_id });
    match tokio::time::timeout(DESTROY_TIMEOUT, call).await {
        Ok(Ok(minimald_rpc::Errorable::Ok(_))) => {}
        Ok(Ok(minimald_rpc::Errorable::Err { error })) => {
            eprintln!("DestroySession failed while cleaning up: {error}");
        }
        Ok(Err(e)) => {
            eprintln!("DestroySession RPC failed while cleaning up: {e}");
        }
        Err(_) => {
            eprintln!(
                "DestroySession timed out after {DESTROY_TIMEOUT:?} while cleaning up \
                 session {session_id}; the session may still be present on the daemon \
                 (run `min session destroy {session_id}` to clean up manually)",
            );
        }
    }
}

/// Upload the composition's patches (if any) and finalize the
/// session. The session is `Materializing` at entry; `Active` on
/// success. On upload/finalize failure the session is left in
/// `Materializing` — the caller is responsible for destroying it.
async fn upload_and_finalize(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    patches: &[(std::path::PathBuf, paths::SandboxRelPath)],
) -> Result<(), anyhow::Error> {
    client
        .upload_patches(session_id, patches)
        .await
        .context("Failed to upload composition patches")?;

    use minimald_rpc::{FinalizeSession, FinalizeSessionRequest};
    let resp = client
        .oneshot_rpc::<FinalizeSession>(FinalizeSessionRequest { session_id })
        .await
        .context("FinalizeSession RPC failed")?;
    match resp {
        minimald_rpc::Errorable::Ok(_) => Ok(()),
        minimald_rpc::Errorable::Err { error } => {
            bail!("FinalizeSession failed: {error}");
        }
    }
}

/// Guard that tears down a half-built session if the user interrupts the
/// activation with Ctrl-C.
///
/// `dialoguer`/`console` re-raise SIGINT to this process on a Ctrl-C at
/// the composition-gating prompt (console `unix_term.rs`). With no
/// handler installed the default disposition kills `min` mid-prompt —
/// before the abort-cleanup that [`drive_pending_to_active`] runs — so
/// the daemon is left holding a `Pending` session that blocks its name.
/// [`arm_activation_interrupt`] installs a SIGINT handler (keeping the
/// process alive past console's re-raise) that best-effort
/// `AbortSession`s the in-flight session over a fresh connection — the
/// activation borrows the primary one — then exits. The daemon's
/// connection-close reap is the backstop if the abort can't be
/// delivered.
///
/// Dropping the guard cancels the handler, so a Ctrl-C after the session
/// is safely `Active` (e.g. during the `--attach` hand-off) no longer
/// tears it down.
struct ActivationInterrupt {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ActivationInterrupt {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn arm_activation_interrupt(
    global: &GlobalArgs,
    session_id: sessions::SessionId,
) -> ActivationInterrupt {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd());
    let task = tokio::spawn(async move {
        // Only the first Ctrl-C is intercepted; a second falls through to
        // the default disposition so a wedged cleanup can still be killed.
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\nAborting activation; cleaning up session {session_id}…");
        if let Ok(sock) = sock
            && let Ok(mut client) = client::Client::connect(&sock).await
        {
            use minimald_rpc::{AbortSession, AbortSessionRequest};
            let _ = client
                .oneshot_rpc::<AbortSession>(AbortSessionRequest { id: session_id })
                .await;
        }
        std::process::exit(130);
    });
    ActivationInterrupt { task }
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
    // writer would clobber it. Only prompt on a real terminal that hasn't
    // been told to skip prompts (--no-input); anywhere else (and on a
    // declined prompt) carry on without scaffolding.
    if global.no_input
        || !std::io::stdin().is_terminal()
        || !confirm("Would you like to create one?", true)?
    {
        eprintln!(
            "Continuing without one; the session gets a default environment. \
             Run 'min init' to give the project its own config."
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

/// Resolves the directory whose tree should be uploaded as the session
/// workspace, walking up from `dir` to the nearest `minimal.toml` and using
/// its repo root. Falls back to `dir` itself when no mfile is found, so a
/// project without one still activates — the daemon fabricates a default
/// config inside the session workspace. Any other mfile error (malformed
/// TOML, I/O) is propagated: a broken config in an ancestor should fail
/// loudly rather than silently uploading a subdir with no config.
fn resolve_upload_root(dir: &camino::Utf8Path) -> Result<camino::Utf8PathBuf, anyhow::Error> {
    match mfile::File::from_dir_recursive(dir.as_std_path()) {
        Ok(f) => match f.repo_path() {
            Some(root) => Ok(camino::Utf8PathBuf::from_path_buf(root.to_path_buf())
                .unwrap_or_else(|_| dir.to_path_buf())),
            None => Ok(dir.to_path_buf()),
        },
        Err(mfile::Error::NotFound) => Ok(dir.to_path_buf()),
        Err(e) => Err(anyhow::anyhow!(
            "found a broken {name} while walking up from {dir}: {e}",
            name = mfile::MFILE_NAME,
        )),
    }
}

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let effective_path = match (&args.path, &global.repo_dir) {
        (Some(p), _) => std::path::PathBuf::from(p),
        (None, Some(dir)) => dir.clone(),
        (None, None) => std::path::PathBuf::from("."),
    };

    let project_path = std::fs::canonicalize(&effective_path)
        .with_context(|| format!("Cannot resolve project path '{}'", effective_path.display()))?;

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
    let policy_path = config::user_policy_path(global);
    let user_policy = config::read_user_policy(global)?;
    let initial_policy = user_policy.clone();
    let compose_options = loadouts::compose_options_from_config(&cfg);
    let selection = loadouts::LoadoutSelection::from_flags(&args.loadout, args.no_loadouts);
    let active = loadouts::resolve_active_loadouts(selection, &cfg, global)?;
    if !active.is_empty() {
        let names: Vec<&str> = active.iter().map(|l| l.name().as_ref()).collect();
        eprintln!("Applying loadouts: {}", names.join(", "));
    }
    let (contribution, user_policy) =
        loadouts::compose_user_contribution(active, user_policy, compose_options)?;

    // Resolve the upload root before opening the daemon connection:
    // a malformed mfile in an ancestor should fail loudly before
    // we create a session on the daemon, so we don't leak a draft
    // session. Only needed for tarball sync — `--sync none` skips
    // the upload entirely (#770).
    let upload_root = match args.sync {
        SyncMode::None => None,
        SyncMode::Tarball => Some(resolve_upload_root(&utf8_path)?),
    };

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

    // From here the session exists on the daemon in an unfinalized state.
    // Arm a Ctrl-C guard so an interrupt during the (blocking) gating
    // prompt tears it down instead of orphaning it in `Pending` — see
    // [`ActivationInterrupt`]. Disarmed once the session is `Active`.
    let interrupt_guard = arm_activation_interrupt(global, id);

    // Upload the project directory to the daemon so the session
    // workspace holds the user's files — `ConfigureLoadout`'s compose
    // reads the mfile (and any local `packages/`, `stacks/`,
    // `profiles/` used by graph resolution) off that workspace, so it
    // has to run before `ConfigureLoadout`. `--sync none` opts out;
    // the daemon then composes against an empty workspace and the
    // caller is on their own for getting files there.
    match args.sync {
        SyncMode::None => {}
        SyncMode::Tarball => {
            // Upload from the project root — the directory the mfile
            // lives in — rather than wherever the user invoked us. This
            // matches the CLI's config-discovery walk: a user running
            // `minimal activate ./subdir` still uploads the whole
            // project. Falls back to `utf8_path` when no mfile is found
            // anywhere up the tree (#770).
            let upload_root = upload_root.expect("upload_root is set for SyncMode::Tarball above");
            if upload_root != utf8_path {
                eprintln!("Uploading from project root {upload_root} (resolved from {utf8_path})");
            }
            // Guard against accidentally uploading a non-VCS directory
            // (e.g. `~`): if the resolved project root is not a recognized
            // VCS root, warn and ask for confirmation before the recursive
            // upload. On non-interactive stdin (CI, pipes, agents) and under
            // `--no-prompt` we proceed without prompting — `--sync none`
            // remains available for explicit opt-out (#770).
            let should_upload = file_upload::is_vcs_root(upload_root.as_std_path())
                || args.no_prompt
                || global.no_input
                || !can_prompt_interactively()
                || confirm(
                    &format!(
                        "{upload_root} is not a version control repository root. \
                         Upload all files from this directory?"
                    ),
                    false,
                )?;
            if should_upload {
                client
                    .upload_workspace_files(id, upload_root.as_std_path())
                    .await
                    .context("Failed to upload project files")?;
            } else {
                eprintln!(
                    "Skipping file upload; the session will start with an \
                     empty workspace."
                );
            }
        }
    };

    // Collect the client-side patches (from loadouts, already gated
    // in Phase 1) *before* the wire contribution moves into the
    // ConfigureLoadout RPC. These land in the final Composition
    // whether the response is `Materialized` or `Pending`, so the
    // client is authoritative for them. Any daemon-side patches
    // that come back through a `Pending` response's `SubmitVerdict`
    // get appended below.
    let mut collected_patches: Vec<(std::path::PathBuf, paths::SandboxRelPath)> = contribution
        .patches
        .iter()
        .map(|p| {
            (
                p.patch.host_path.as_utf8_path().as_std_path().to_path_buf(),
                p.patch.destination.clone(),
            )
        })
        .collect();

    // The session exists but has no loadout yet; composing it is a
    // second round-trip because the daemon's composer reads the
    // project config out of the session's workspace, not from a path
    // on this machine.
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
    // client to gate items first (`Pending`). On the pending path
    // we run the user-policy prompt loop; on ready there's nothing
    // to gate.
    //
    // Decide up front whether we can prompt: `--no-prompt` forces
    // the abort path, and a non-TTY stderr triggers it implicitly
    // (a script or CI run should never expect to read a keypress).
    // Both fall through to `NoPromptHook`, which accumulates every
    // item it would have prompted for so we can print a
    // `user_policy.toml` snippet on the error path.
    if let minimald_rpc::ConfigureLoadoutResponse::Pending { response } = configured {
        let non_interactive = args.no_prompt || global.no_input || !can_prompt_interactively();
        if non_interactive {
            // NoPromptHook fake-approves every unapproved item so
            // handle_response finishes both the var and patch gates
            // and records everything in `summary`. If anything was
            // recorded, we abort *before* actually shipping the
            // verdict — the daemon must not see those fake
            // approvals. Only when `summary` is empty (every daemon-
            // sent item was already handled by the user's policy)
            // do we submit and let the session go Active.
            let session_id = response.session_id;
            let hooks = prompt::NoPromptHook::new();
            let verdict = match compute_verdict(response, user_policy, compose_options, &hooks) {
                Ok((verdict, _final_policy)) => verdict,
                Err(e) => {
                    send_abort(&mut client, session_id).await;
                    bail!("Composition gating failed: {e}");
                }
            };
            let summary = hooks.into_summary();
            if summary.count() > 0 {
                send_abort(&mut client, session_id).await;
                let count = summary.count();
                let snippet = summary.as_toml_snippet();
                bail!(
                    "{count} item{s} would require interactive approval, but \
                     --no-prompt was set (or stdin/stderr is not a terminal).\n\n\
                     Add the following to {}:\n\n{snippet}\n\
                     Then re-run this command.",
                    policy_path.display(),
                    s = if count == 1 { "" } else { "s" },
                );
            }
            collected_patches.extend(approved_patches_from_verdict(&verdict));
            submit_verdict_and_wait(&mut client, session_id, verdict).await?;
        } else {
            // The hook stashes policy mutations in interior
            // `RefCell`s so a `DenyPermanent` (which returns
            // `HookResult::Abort` and can't pipe an
            // `updated_policy` back through the composer) still
            // survives to `into_final_policy`. We save
            // unconditionally before propagating the result, so a
            // deny-and-abort still writes the rule.
            let hooks = prompt::InteractivePrompt::new(&policy_path, user_policy.clone());
            let result = drive_pending_to_active(
                &mut client,
                response,
                user_policy,
                compose_options,
                &hooks,
            )
            .await;
            if let Ok((_, _, ref approved)) = result {
                collected_patches.extend(approved.iter().cloned());
            }
            let final_policy = hooks.into_final_policy();
            if final_policy != initial_policy {
                // A `save_user_policy` failure is reported to
                // stderr and *doesn't* propagate: if the activation
                // itself also failed (`DenyPermanent` returns Err
                // and still wants its rule saved; a real
                // composition fault), `result?` below is what the
                // operator needs to see. Blindly `?`ing the save
                // would clobber that error with a spurious
                // "updating user_policy.toml" message that hides
                // the true failure.
                match prompt::save_user_policy(&policy_path, &final_policy) {
                    Ok(()) => eprintln!("Updated {}", policy_path.display()),
                    Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
                }
            }
            result?;
        }
    }

    // On the Ready path (loadouts auto-decided; no prompt fired)
    // `initial_policy` is only referenced inside the Pending branch
    // above, so it appears unused to the compiler. Explicit `_` to
    // squash the lint without dropping the useful name.
    let _ = initial_policy;

    // Upload composition patches and finalize the session. This
    // has to happen before attach is allowed — a Materializing
    // session isn't attachable, and the launcher reads patches
    // from `<workspace>/patches/`. Dedup by sandbox destination:
    // the composer's post-gate check guarantees any duplicates
    // are exact matches (same source), so collapsing is safe.
    collected_patches.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()));
    collected_patches.dedup_by(|a, b| a.1.as_str() == b.1.as_str());
    if let Err(e) = upload_and_finalize(&mut client, id, &collected_patches).await {
        // Best-effort teardown: the session is stuck in
        // Materializing on the daemon. Destroy it so the operator's
        // `min ls` doesn't fill with half-finalized sessions.
        best_effort_destroy(&mut client, id).await;
        return Err(e);
    }

    // The session is `Active` now — a Ctrl-C must no longer tear it down
    // (the attach hand-off below and the user's own session are fair game
    // for interrupts, but not this cleanup).
    drop(interrupt_guard);

    println!("{id}");

    if args.attach {
        // Chain into attach. Announce the freshly created session first: the
        // bare id printed to stdout above is the scripting contract, while this
        // stderr line tells an interactive operator which session they just
        // created and are entering.
        if should_announce_session(global) {
            eprintln!(
                "Created session {}",
                session_announce_label(&id, args.name.as_deref())
            );
        }
        let attach_args = AttachArgs {
            session: Some(id.to_string()),
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
///
/// When `args.session` is `None`, the session is resolved from the current
/// working directory (or the only existing session), opening an interactive
/// picker when the choice is ambiguous; see [`attach::resolve_for_attach`]
/// and [`resolve_smart_attach`].
pub async fn cmd_attach(global: &GlobalArgs, args: AttachArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    let (id, name) = match args.session {
        Some(ref s) => {
            let r = resolve_session(&mut client, s).await?;
            (r.id, r.name)
        }
        None => match resolve_smart_attach(&mut client, global).await? {
            Some(entry) => (entry.id, entry.name),
            None => bail!("no sessions exist; use 'min session activate' to create one"),
        },
    };

    tracing::info!(
        session_id = %id,
        session_name = ?name,
        "found session"
    );

    attach_to_session(&sock, id, args.command).await
}

/// Resolve a session to attach to when the user supplied no explicit session
/// reference. Lists sessions, matches against the current working directory,
/// and either attaches directly (unambiguous), opens the interactive picker
/// (ambiguous), or errors (ambiguous but non-interactive).
///
/// Returns `Ok(None)` when no sessions exist at all — the caller decides
/// whether that is an error (`min session attach`) or a cue to activate a new session
/// (bare `min`).
async fn resolve_smart_attach(
    client: &mut client::Client,
    global: &GlobalArgs,
) -> Result<Option<minimald_rpc::ListSessionsEntry>, anyhow::Error> {
    use minimald_rpc::ListSessions;

    let resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;
    let cwd = attach::cwd_host_path(global)?;
    match attach::resolve_for_attach(&resp.sessions, &cwd) {
        attach::SmartResolve::NoSessions => Ok(None),
        attach::SmartResolve::Attach(entry) => {
            // Unambiguous auto-resolve: the operator never chose this session,
            // so tell them which one they're landing in. The picker path below
            // needs no such line — the selection is its own confirmation.
            if should_announce_session(global) {
                eprintln!(
                    "Attaching to session {}",
                    session_announce_label(&entry.id, entry.name.as_deref())
                );
            }
            Ok(Some(entry))
        }
        attach::SmartResolve::Pick(cands) => {
            if global.no_input || !attach::can_pick_interactively() {
                bail!(attach::ambiguous_no_input_message(&cands, &cwd));
            }
            match attach::pick_session(&cands, &cwd)? {
                Some(entry) => Ok(Some(entry)),
                None => bail!("session selection cancelled"),
            }
        }
    }
}

/// Guard for bare `min` on an empty daemon: activating there chains straight
/// into an interactive attach, which needs a TTY on stdin. Under `--no-input`,
/// or when stdin is not a terminal, that attach can never succeed — so refuse
/// before creating anything, emitting the same message the explicit
/// `min session attach` produces, instead of creating a session and then
/// failing the attach guard, which leaves the session orphaned (#1031).
///
/// Pure in its inputs so both branches are unit-testable without a controlled
/// terminal.
fn ensure_activate_on_empty_allowed(
    no_input: bool,
    stdin_is_tty: bool,
) -> Result<(), anyhow::Error> {
    if no_input || !stdin_is_tty {
        bail!("no sessions exist; use 'min session activate' to create one");
    }
    Ok(())
}

/// Guard for the interactive attach path: the PTY-backed session shell must be
/// driven from a real terminal. When stdin is not a TTY there is nothing to
/// drive the remote shell and no EOF ever reaches it through the forced `-tt`
/// PTY, so ssh blocks indefinitely (#953). Fail fast with an actionable message
/// instead of hanging.
///
/// Pure in its `stdin_is_tty` input so both branches are unit-testable without
/// a controlled terminal.
fn ensure_interactive_attach_tty(stdin_is_tty: bool) -> Result<(), anyhow::Error> {
    if stdin_is_tty {
        Ok(())
    } else {
        bail!(
            "`min session attach` needs an interactive terminal, but stdin is not a TTY. \
             Run it from a terminal, or use `min session attach --command <cmd>` to run a \
             single command non-interactively."
        )
    }
}

/// Shell out to `ssh` to attach to `id`. Both the interactive (no `command`)
/// and `--command` (non-interactive exec) paths route through here; the
/// daemon's shell_request handler mints a PTY-backed shell, and ssh handles
/// termios/PTY management.
///
/// Split from [`cmd_attach`] so the bare-`min` default dispatch
/// ([`cmd_default`]) and the smart-resolution picker can attach without
/// re-resolving an entry they already hold.
async fn attach_to_session(
    sock: &std::path::Path,
    id: sessions::SessionId,
    command: Option<String>,
) -> Result<(), anyhow::Error> {
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
    // Pin the shell ssh uses to run the ProxyCommand. ssh launches a
    // ProxyCommand via `$SHELL -c` and execs `$SHELL` with no PATH lookup, so a
    // caller whose `$SHELL` is a bare name (`fish`) or points at a shell absent
    // from this context fails with "<shell>: No such file or directory" and the
    // transport dies at "banner exchange … Broken pipe". Our ProxyCommand is a
    // full-path `min proxy …` that needs nothing but a POSIX `sh`, so force the
    // always-present `/bin/sh` rather than inherit the user's interactive shell.
    ssh.env("SHELL", "/bin/sh");
    ssh.env("MINIMAL_SESSION_ID", id.to_string()).args([
        "-o",
        "SendEnv=MINIMAL_SESSION_ID",
        // Forward the user's locale and timezone into the session, mirroring a
        // conventional `SendEnv LANG LC_* TZ`. The daemon accepts only these
        // (its `AcceptEnv` allowlist) and folds them in below any loadout.
        // `TERM` needs no `SendEnv`: ssh always carries it in the PTY request.
        "-o",
        "SendEnv=LANG",
        "-o",
        "SendEnv=LC_*",
        "-o",
        "SendEnv=TZ",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        &strict,
        "-o",
        &known_hosts_file,
    ]);

    // The interactive path opens the in-sandbox session shell via the daemon's
    // `shell_request`, which requires a PTY. Force one with `-tt` so ssh
    // allocates it even when our stdin is a pty driven programmatically rather
    // than the controlling terminal (as scripts/e2e-attach-pty.py does);
    // without it ssh skips the PTY and the daemon rejects the shell. The
    // `--command` path is a non-interactive exec and needs no PTY.
    //
    // But `-tt` over a *non-terminal* stdin is a trap: ssh still forces the
    // remote PTY, yet the interactive shell reading it never sees an EOF from a
    // redirected local stdin (`< /dev/null`, a pipe), so the command blocks
    // forever (#953). Fail fast instead of hanging.
    if command.is_none() {
        ensure_interactive_attach_tty(std::io::stdin().is_terminal())?;
        ssh.arg("-tt");
    }
    // The SSH host identity must match the known_hosts entry the daemon wrote,
    // which it keys on the provider-instance name — the provider dir's basename
    // (`local-minimald<N>` / `local-minvmd<N>`). Derive it from the socket path
    // so the client and daemon can never disagree on the name.
    let host_alias = sock
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(|n| n.to_str())
        .context("daemon socket path has no provider-dir parent")?;
    ssh.arg(host_alias);

    // If a command was provided, pass it to ssh (non-interactive exec).
    // Otherwise, ssh opens an interactive shell via shell_request.
    if let Some(cmd) = command {
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
    println!("  1. Run `min mesh status` on the remote host to read its public key.");
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
    if !autospawn::is_daemon_running(global.use_minvmd(), global.minimal_dir.as_deref())
        .context("Failed to determine whether the daemon is running")?
    {
        println!("Daemon is not running.");
        return Ok(());
    }

    // Racy by nature: the daemon may go down between the probe and this connect
    // (or `--provider` may point the probe and the client at different backends),
    // so a connect failure is still a real error, not something to swallow.
    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{Shutdown, ShutdownRequest};
    let resp = client
        .oneshot_rpc::<Shutdown>(ShutdownRequest { force: args.force })
        .await
        .context("Shutdown RPC failed");

    // Drop our connection before waiting: the daemon holds the shutdown open
    // for its drain grace period while a client is still attached, and we are
    // that client.
    drop(client);

    let (use_minvmd, minimal_dir) = (global.use_minvmd(), global.minimal_dir.clone());
    let probe_dir = minimal_dir.clone();
    stop_outcome(
        resp,
        async move || {
            // The wait polls the lifecycle file on a sleep loop, so it goes on
            // the blocking pool rather than stalling an async worker for up to
            // 20s (rust-coding-standards: no blocking in an async context).
            tokio::task::spawn_blocking(move || {
                autospawn::wait_for_daemon_stopped(use_minvmd, minimal_dir.as_deref())
            })
            .await
            .context("The wait for the daemon to stop panicked")?
            .context("Failed while waiting for the daemon to stop")
        },
        async move || daemon_confirmed_stopped(use_minvmd, probe_dir).await,
    )
    .await
}

/// Whether the daemon can be *observed* to have stopped — the question the
/// failed-RPC arm of [`stop_outcome`] turns on.
///
/// The shutdown wait, then the liveness probe this command opened with. On a VM
/// backend the wait IS the observation — it polls the lifecycle state — but a
/// native minimald has no lifecycle file and its wait returns at once, saying
/// nothing, so only the probe can answer for that backend. Anything we cannot
/// read is not a confirmed stop.
///
/// Which makes the recovery a VM-backend one in practice: the native probe fires
/// once, immediately, and minimald keeps its listener bound through the 5s drain
/// grace it takes after its accept loop exits (minimald's `SHUTDOWN_GRACE`), so
/// a connect in that window still succeeds and reports "running". Native
/// therefore keeps today's fail-on-RPC-error behaviour — which is right for it:
/// a native daemon is not pid-1 and does not take the transport down with it, so
/// the lost reply this recovers from is not a failure mode it has.
async fn daemon_confirmed_stopped(use_minvmd: bool, minimal_dir: Option<PathBuf>) -> bool {
    // Both calls can sleep-poll, so they go on the blocking pool rather than
    // stalling an async worker (rust-coding-standards: no blocking in an async
    // context). A panicked probe observed nothing, which is not a confirmation.
    tokio::task::spawn_blocking(move || {
        autospawn::wait_for_daemon_stopped(use_minvmd, minimal_dir.as_deref()).is_ok()
            && !autospawn::is_daemon_running(use_minvmd, minimal_dir.as_deref()).unwrap_or(true)
    })
    .await
    .unwrap_or(false)
}

/// Decide what `min stop` reports, given how the `Shutdown` RPC ended, the wait
/// an accepted shutdown runs out, and — only when the RPC itself failed —
/// whether the daemon can nevertheless be confirmed down.
///
/// What `stop` promises is observable: the daemon is down. On a VM target the
/// daemon IS the guest's pid-1, so an accepted shutdown takes the SSH transport
/// down with it — as a *consequence of succeeding* — and the reply can be lost
/// before the client decodes it. Gating on the transport would report failure
/// for a stop that did exactly what was asked, so a failed RPC over a daemon
/// that did stop is a success. A daemon still there afterwards is a real
/// failure, and the RPC error — the one that explains what went wrong — is what
/// the user sees.
///
/// Only that failure arm probes. An accepted shutdown is judged by its wait
/// alone: the daemon acknowledges before it has finished going down, so asking
/// again there would race its own teardown and fail stops that worked.
///
/// `SessionsLive` is not a lost reply but an answer: the daemon refused, and is
/// going nowhere, so there is nothing to observe.
async fn stop_outcome<W, C>(
    resp: Result<minimald_rpc::ShutdownResponse, anyhow::Error>,
    wait_for_stopped: W,
    confirm_stopped: C,
) -> Result<(), anyhow::Error>
where
    W: AsyncFnOnce() -> Result<(), anyhow::Error>,
    C: AsyncFnOnce() -> bool,
{
    use minimald_rpc::ShutdownResponse;
    match resp {
        Ok(ShutdownResponse::ShuttingDown) => {
            println!("Daemon is shutting down.");
            wait_for_stopped().await
        }
        Ok(ShutdownResponse::SessionsLive) => {
            bail!("daemon has active sessions; pass --force to shut down anyway")
        }
        Err(rpc_err) => {
            if confirm_stopped().await {
                // Say what was suppressed. Exiting 0 over a failed RPC is only
                // sound because the daemon is observably down, and a silent
                // recovery would leave nothing — in a terminal or in a soak
                // log — to check that reading against. stderr, so it survives
                // the `>/dev/null` every scripted caller wraps `stop` in.
                eprintln!("warning: the shutdown RPC failed, but the daemon stopped: {rpc_err:#}");
                println!("Daemon is shutting down.");
                Ok(())
            } else {
                Err(rpc_err)
            }
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

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
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
    // Host-key checking is disabled here, so the alias is cosmetic; still derive
    // it from the provider dir (`local-minimald<N>` / `local-minvmd<N>`) to match
    // the rest of the CLI rather than hard-coding a name.
    let host_alias = sock
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(|n| n.to_str())
        .context("daemon socket path has no provider-dir parent")?;
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
        host_alias,
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
        AddKind { session: true, .. } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::SessionPackages,
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

/// Draw the client's activity spinner on stderr for `args.seconds`
/// (or until Ctrl-C), then clear it. Ticks the byte counter as it
/// runs so the `{bytes}` / `{bytes_per_sec}` placeholders in the
/// spinner template look alive instead of stuck at zero — makes it
/// easier to eyeball the animation next to realistic template
/// content.
pub async fn cmd_spin(_global: &GlobalArgs, args: SpinArgs) -> Result<(), anyhow::Error> {
    use std::time::Duration;
    let bar = client::add_spinner_bar("Spinner demo");
    let deadline = tokio::time::sleep(Duration::from_secs(args.seconds));
    tokio::pin!(deadline);
    // ~80 KB/s of fake throughput. Below indicatif's rate-average
    // window smoothing so the reported `{bytes_per_sec}` stays
    // legible instead of dancing every tick.
    let mut fake_throughput = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut deadline => break,
            _ = fake_throughput.tick() => bar.inc(4096),
        }
    }
    bar.finish_and_clear();
    Ok(())
}

/// Print CLI and daemon version information.
///
/// Always shows the CLI version. If the daemon is reachable, also shows
/// the daemon version and stdlib version. Unlike other commands, this does
/// not autospawn the daemon — it is a lightweight diagnostic that should
/// report versions without starting a VM.
pub async fn cmd_version(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    println!("Client: minimal {}", version::LONG_VERSION);

    let sock = match client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
    {
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

    /// Interactive attach over a non-terminal stdin must fail fast rather than
    /// force `ssh -tt` into an indefinite block (#953). A real terminal (or a
    /// pty driver) passes the guard so the shell can open.
    #[test]
    fn interactive_attach_requires_a_tty_on_stdin() {
        let err = ensure_interactive_attach_tty(false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a TTY") && err.contains("--command"),
            "expected an actionable non-TTY error, got: {err}"
        );
        ensure_interactive_attach_tty(true).expect("a real terminal must pass the guard");
    }

    /// Bare `min` on an empty daemon must refuse before creating a session when
    /// it could not follow through with the interactive attach — under
    /// `--no-input` or over a non-TTY stdin — so it never orphans a session
    /// (#1031). Only a plain interactive invocation proceeds to activate.
    #[test]
    fn bare_min_refuses_to_activate_on_empty_daemon_non_interactively() {
        let err = ensure_activate_on_empty_allowed(true, true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no sessions exist") && err.contains("min session activate"),
            "expected the explicit-verb refusal, got: {err}"
        );
        ensure_activate_on_empty_allowed(false, false)
            .expect_err("a non-TTY stdin must be refused even without --no-input");
        ensure_activate_on_empty_allowed(false, true)
            .expect("an interactive terminal without --no-input must be allowed to activate");
    }

    /// The attach/create confirmation prefers the session name and appends a
    /// short id so two same-named sessions built from the same directory are
    /// still distinguishable; an unnamed session falls back to the short id
    /// alone rather than the full 36-character UUID.
    #[test]
    fn session_announce_label_prefers_name_with_short_id() {
        let id = sessions::SessionId::parse_str("a1b2c3d4-0000-0000-0000-000000000000").unwrap();
        assert_eq!(session_announce_label(&id, Some("api")), "api (a1b2c3d4)");
        assert_eq!(session_announce_label(&id, None), "a1b2c3d4");
    }

    /// A VM-backed provider dir carries the guest's recorded host key, so
    /// attach must verify against it rather than waive the check.
    #[test]
    fn host_key_opts_pin_to_an_adjacent_known_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts = tmp.path().join(paths::KNOWN_HOSTS_FILE);
        std::fs::write(&known_hosts, "local-minimald0 ssh-ed25519 AAAA...\n").unwrap();

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
        std::fs::write(&known_hosts, "local-minimald0 ssh-ed25519 AAAA...\n").unwrap();

        let [strict, hosts_file] = host_key_opts(&known_hosts);
        assert_eq!(strict, "StrictHostKeyChecking=yes");
        assert!(
            hosts_file.contains(r#"q\"uote"#) && hosts_file.contains(r"back\\slash"),
            "path must reach ssh escaped, got: {hosts_file}"
        );
    }

    #[test]
    fn provider_local_minvmd_selects_the_vm_backend() {
        use clap::Parser as _;
        let cli = Cli::try_parse_from(["min", "--provider", "local-minvmd", "ls"]).unwrap();
        assert!(cli.global_args.use_minvmd());
    }

    #[test]
    fn provider_local_minimald_is_the_host_backend() {
        use clap::Parser as _;
        let cli = Cli::try_parse_from(["min", "--provider", "local-minimald", "ls"]).unwrap();
        assert!(!cli.global_args.use_minvmd());
    }

    #[test]
    fn no_provider_defaults_to_the_host_backend() {
        use clap::Parser as _;
        let cli = Cli::try_parse_from(["min", "ls"]).unwrap();
        assert!(!cli.global_args.use_minvmd());
    }

    /// `session destroy` must present `[SESSION]` and `--all` as mutually
    /// exclusive alternatives, one required. Regression for #1038: the error
    /// path used to hide `--all` and demand a session outright, yielding a
    /// usage line that could never parse.
    #[test]
    fn destroy_models_session_and_all_as_required_alternatives() {
        use clap::Parser as _;
        let parse = |args: &[&str]| Cli::try_parse_from(args);

        // Exactly one of a session or --all is required; both together conflict.
        assert!(parse(&["min", "session", "destroy", "web"]).is_ok());
        assert!(parse(&["min", "session", "destroy", "--all"]).is_ok());
        assert!(parse(&["min", "session", "destroy"]).is_err());
        assert!(parse(&["min", "session", "destroy", "--all", "web"]).is_err());

        // --force only makes sense with --all, and its error no longer hides
        // that --all is the alternative the bare error omitted.
        assert!(parse(&["min", "session", "destroy", "--all", "--force"]).is_ok());
        let bare = parse(&["min", "session", "destroy", "-f"])
            .err()
            .expect("-f without --all must fail to parse")
            .to_string();
        assert!(bare.contains("--all"), "usage must surface --all: {bare}");
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

    /// With no mfile anywhere up the tree, `resolve_upload_root` returns the
    /// input directory unchanged — the original activate behaviour.
    ///
    /// The temp dir is rooted directly in `$HOME` rather than `$TMPDIR`: the
    /// upward walk stops at `$HOME`, so this is the only placement where "no
    /// mfile up the tree" is guaranteed. Under `$TMPDIR` the walk escapes to
    /// whatever encloses it — with `TMPDIR` inside a checkout of this repo it
    /// finds the repo's own `minimal.toml` and the test fails.
    #[test]
    fn resolve_upload_root_returns_input_when_no_mfile() {
        let Some(home) = std::env::home_dir() else {
            return; // no HOME: no walk boundary to anchor the test to
        };
        let dir = tempfile::tempdir_in(&home).unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        assert_eq!(resolve_upload_root(path).unwrap(), path);
    }

    /// `resolve_upload_root` walks up to the nearest mfile and returns its
    /// repo root, so activating from a subdir still uploads the whole
    /// project. Covers both the root (`./minimal.toml`) and `.minimal/`
    /// layouts.
    #[test]
    fn resolve_upload_root_walks_up_to_mfile_root_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let subdir = root.join("nested/deep");
        std::fs::create_dir_all(&subdir).unwrap();

        assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
    }

    #[test]
    fn resolve_upload_root_walks_up_to_mfile_dot_minimal_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mfile_dir = dir.path().join(".minimal");
        std::fs::create_dir(&mfile_dir).unwrap();
        std::fs::write(
            mfile_dir.join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        let subdir = root.join("nested");
        std::fs::create_dir_all(&subdir).unwrap();

        assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
    }

    /// A malformed mfile is a real error, not a "not found": propagate it
    /// so the user sees the parse failure instead of silently uploading a
    /// subdir with no config and letting the daemon fabricate a default.
    #[test]
    fn resolve_upload_root_errors_on_malformed_mfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
        let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
        assert!(resolve_upload_root(path).is_err());
    }

    /// On a VM target the daemon is the guest's pid-1, so an accepted shutdown
    /// takes the SSH transport down with it and the reply can be lost on the
    /// way out. `stop` gates on the observable goal, not on the transport: a
    /// daemon that reached the stopped state is a stop that worked.
    #[tokio::test]
    async fn stop_succeeds_when_a_lost_reply_still_stopped_the_daemon() {
        stop_outcome(
            Err(anyhow::anyhow!("EOF while parsing a value")
                .context("decode response for shutdown")
                .context("Shutdown RPC failed")),
            async || Ok(()),
            async || true,
        )
        .await
        .expect("a daemon that reached the stopped state is a successful stop");
    }

    /// The other half of that judgement: a failed RPC over a daemon that is
    /// still there is a real failure, and the RPC's own error — context and all
    /// — is what the user needs.
    #[tokio::test]
    async fn stop_reports_the_rpc_error_when_the_daemon_is_still_running() {
        let err = stop_outcome(
            Err(anyhow::anyhow!("connection reset").context("Shutdown RPC failed")),
            async || Ok(()),
            async || false,
        )
        .await
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("Shutdown RPC failed") && chain.contains("connection reset"),
            "expected the original RPC error chain, got: {chain}"
        );
    }

    /// A refusal is an answer, not a lost reply: it keeps its own message and
    /// its non-zero exit, and observes nothing — the daemon it names is staying
    /// up on purpose.
    #[tokio::test]
    async fn stop_with_live_sessions_bails_without_waiting() {
        let observed = std::cell::Cell::new(false);
        let err = stop_outcome(
            Ok(minimald_rpc::ShutdownResponse::SessionsLive),
            async || {
                observed.set(true);
                Ok(())
            },
            async || {
                observed.set(true);
                true
            },
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "daemon has active sessions; pass --force to shut down anyway"
        );
        assert!(
            !observed.get(),
            "a refused shutdown has nothing to wait for"
        );
    }

    /// An acknowledged shutdown still has to finish, and its wait is the whole
    /// judgement: a daemon that never reaches a stopped state fails with the
    /// wait's own error, and the extra liveness probe — which exists only to
    /// judge a *failed* RPC — never races a teardown the daemon acknowledged.
    #[tokio::test]
    async fn stop_fails_when_an_accepted_shutdown_never_completes() {
        stop_outcome(
            Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
            async || Ok(()),
            async || false,
        )
        .await
        .expect("an acknowledged shutdown that completes is a successful stop");

        let probed = std::cell::Cell::new(false);
        let err = stop_outcome(
            Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
            async || Err(anyhow::anyhow!("the VM is still shutting down after 20s")),
            async || {
                probed.set(true);
                true
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("still shutting down"),
            "expected the wait's error, got: {err}"
        );
        assert!(
            !probed.get(),
            "an accepted shutdown is judged by its wait alone"
        );
    }

    /// The recovery's actual observation, not a stand-in for it: the real
    /// probe `cmd_stop` hands `stop_outcome`, run against a state dir no daemon
    /// ever ran in. Nothing is listening and no lifecycle is active, which is
    /// exactly the post-shutdown reading a lost reply has to be judged on, so
    /// it must confirm the stop.
    #[tokio::test]
    async fn the_real_probe_confirms_a_daemon_that_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            daemon_confirmed_stopped(true, Some(dir.path().to_path_buf())).await,
            "a state dir with no live daemon is a confirmed stop"
        );
    }

    /// The already-down fast path: against a state dir no daemon ever ran in,
    /// `stop` reports the goal state and exits 0 without connecting or
    /// spawning anything.
    #[tokio::test]
    async fn stop_is_a_no_op_when_the_daemon_is_already_down() {
        let dir = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: Some(dir.path().to_path_buf()),
            config_dir: None,
            provider: None,
            no_input: true,
        };

        cmd_stop(&global, StopArgs { force: false })
            .await
            .expect("an already-stopped daemon is the goal state, not an error");
    }
}
