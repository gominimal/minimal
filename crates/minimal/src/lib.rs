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
// The SSH client transport lives in the shared `minimal-client` crate (used
// by the TUI as well); re-exported here so internal `crate::client::...`
// paths and downstream users of `minimal::client` keep working.
pub use minimal_client as client;
pub mod completion;
pub mod completions;
pub mod config;
pub mod diag;
pub mod dirs;
use minimal_client::file_upload;
pub mod git_remote;
pub mod loadouts;
pub mod prompt;
pub mod task;
pub mod theme;
pub mod zed;

#[derive(Parser)]
#[command(name = "min", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(
    about = "min, the Minimal session CLI — create, attach to, and manage sandboxed development sessions"
)]
#[command(subcommand_required = false)]
pub struct Cli {
    // Optional: a bare `min` (no subcommand) routes into a session in a
    // terminal, and prints a read-only state report otherwise — see
    // `cmd_bare`. Keeps every named subcommand reachable unchanged when one
    // is supplied.
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
    // docs/reference/cli.md): `min session list` is the canonical spelling,
    // and `min ls` — the highest-traffic command in the CLI — keeps this bare
    // top-level form as its visible alias. Not an oversight — do not remove it.
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
    /// Task subcommands: run declared project tasks in ephemeral sessions
    #[command(visible_alias = "tasks")]
    Task(TaskArgs),
    /// Muscle-memory catch for the in-box `min run <task>`: always errors,
    /// naming the canonical `min task run <task>` (host) and
    /// `min session attach --command 'min task run <task>'` (in-box) forms.
    #[command(hide = true)]
    Run(RunArgs),
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
    /// Open the interactive session manager TUI (`dash`)
    ///
    /// Full-screen terminal UI for browsing, inspecting, and managing
    /// sessions across every running provider on the host (native minimald
    /// and the minvmd microVM). Requires a terminal.
    Dash,
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
    /// List sessions
    #[command(visible_alias = "ls")]
    List(LsArgs),
    /// Activate (create) a new session
    Activate(ActivateArgs),
    /// Attach to an existing session
    Attach(AttachArgs),
    /// Execute a command in an existing session
    Exec(ExecArgs),
    /// Destroy (terminate) a session
    Destroy(DestroyArgs),
    /// Rename an existing session
    Rename(RenameArgs),
    /// Print the effective networking policy for a session as JSON
    Policy(PolicyArgs),
    /// Register a session as an SSH remote in Zed's settings
    ///
    /// Upserts an entry into the `ssh_connections` array of Zed's
    /// `settings.json`, pointing it at this session over the same transport
    /// `min session attach` uses: our own `proxy` subcommand as an SSH
    /// `ProxyCommand`, with the session selected by `MINIMAL_SESSION_ID`.
    /// Re-running refreshes the entry in place.
    ///
    /// Rewriting the file re-renders it from parsed JSON, so comments and key
    /// ordering are not preserved; the previous contents are kept alongside as
    /// `settings.json.bak`. Use `--print` to emit just the entry instead.
    ///
    /// Example:
    ///
    ///   min session setup-zed my-box
    ///
    /// Hidden while the Zed integration settles: it still parses and runs, it
    /// just stays out of `min session --help` and shell completions.
    #[command(name = "setup-zed", verbatim_doc_comment)]
    #[command(hide = true)]
    SetupZed(SetupZedArgs),
    /// List the lifecycle hooks composed into a session, and where each
    /// was declared
    Hooks(HooksArgs),
}

#[derive(Debug, Args)]
pub struct SetupZedArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Zed settings file to edit (default: `~/.config/zed/settings.json`)
    #[arg(long, value_name = "FILE")]
    pub settings: Option<PathBuf>,
    /// Print the connection entry as JSON instead of editing any file
    #[arg(long)]
    pub print: bool,
}

/// Args for `min session hooks`.
#[derive(Debug, Args)]
pub struct HooksArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Emit the raw JSON the daemon returned instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Session identifier (UUID or session name).
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Command to execute in the session context
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
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

#[derive(Debug, Args)]
pub struct TaskArgs {
    #[command(subcommand)]
    pub command: TaskCommand,
}

#[derive(Debug, Subcommand)]
pub enum TaskCommand {
    /// Run a declared task in an ephemeral session
    ///
    /// Creates a session for the project (named `task-<task>-<hex>`),
    /// uploads the project like `min session activate`, runs the task
    /// inside it with output streamed to the terminal, exits with the
    /// task's exit code, and destroys the session afterwards. `--keep`
    /// retains the session as an attachable box instead. Ctrl-C tears the
    /// session down (or keeps it with `--keep`) and exits 130 without
    /// relaying the interrupt to the task itself. Tasks run
    /// non-interactively: pipe stdin to feed input; use `min session
    /// attach` for interactive work.
    Run(TaskRunArgs),
}

#[derive(Debug, Args)]
pub struct TaskRunArgs {
    /// Name of a task declared in the project's minimal.toml
    pub task: String,
    /// Project path. Defaults to the directory set by `-C`/`--repo-dir`,
    /// or the current working directory when neither is given.
    pub path: Option<String>,
    /// Keep the session after the task exits instead of destroying it
    #[arg(long)]
    pub keep: bool,
}

/// Arguments for the hidden top-level `run` catch. Everything after `run` is
/// swallowed (flags included) so any in-box spelling reaches the redirect
/// error in [`task::cmd_run`] instead of a clap parse error.
#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    pub rest: Vec<String>,
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
    #[arg(long, short = 'C', global = true)]
    pub repo_dir: Option<PathBuf>,
    /// Override the base directory for minimal's state (default: platform
    /// state dir).
    ///
    /// The session store, provider instances, and other on-disk state live
    /// under `<minimal_dir>/`. Defaults to `$XDG_STATE_HOME/minimal` on Linux
    /// (or `$HOME/.local/state/minimal` when that's unset); macOS also uses
    /// `$HOME/.local/state/minimal`.
    #[arg(long, global = true)]
    pub minimal_dir: Option<PathBuf>,
    /// Override the user config directory (default: platform config dir).
    ///
    /// Everything under `<config_dir>/minimal/` (config.toml, loadouts/,
    /// ...) is resolved relative to this. Defaults to the platform's config
    /// dir — `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config` when
    /// that's unset). macOS uses `$HOME/.config` for consistency with
    /// state and cache dirs, not `~/Library/Application Support`.
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    /// Select the daemon backend that hosts sessions.
    ///
    /// On Linux, `local-minimald` (the default) runs minimald on the host;
    /// `local-minvmd` runs it inside the minvmd microVM. No effect on macOS,
    /// where minvmd is the only backend.
    #[arg(long, global = true, value_name = "PROVIDER")]
    pub provider: Option<Provider>,
    /// Skip interactive prompts that need a terminal.
    ///
    /// Affects e.g. the session picker shown by `min session attach` with no
    /// session argument. When a choice is ambiguous, the command errors with a
    /// list of candidates instead of opening a picker. Implied when
    /// stdin/stdout is not a terminal.
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
    ///
    /// Defaults to `tarball`. Passing `--sync tarball` explicitly is also
    /// the escape hatch that uploads an empty directory or `$HOME`, which
    /// are otherwise skipped without a prompt.
    #[arg(long, value_enum)]
    pub sync: Option<SyncMode>,
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
    /// Run none of the session's lifecycle hooks, from either the
    /// loadouts or the project's `minimal.toml`.
    ///
    /// The choice is recorded on the session, so it also applies to the
    /// attach, detach, and destroy transitions later in its life — not
    /// just to this activation. Use it to bring up a session whose
    /// project declares hooks you have not reviewed.
    #[arg(long)]
    pub no_hooks: bool,
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
}

#[derive(Debug, Args)]
pub struct LsArgs {
    /// Output raw session IDs (one per line) for piping into scripts
    #[arg(long)]
    pub raw: bool,
    /// Output the full session list as JSON (pretty-printed). Conflicts
    /// with `--raw`.
    #[arg(long, conflicts_with = "raw")]
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
    /// Skip the destroy confirmation
    #[arg(long, short)]
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
    /// Overwrite an existing minimal.toml; without it, init refuses when one
    /// already exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,
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
        long_about = "Write the shell integration into each shell's user-level completion directory,\nand print every path written on stdout, one per line.\n\n   bash  ${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/min\n   zsh   ${XDG_DATA_HOME:-~/.local/share}/zsh/completions/_min\n   fish  ${XDG_CONFIG_HOME:-~/.config}/fish/completions/min.fish\n\nInstalling zsh completions also clears the compinit dump cache\n(${ZDOTDIR:-$HOME}/.zcompdump), when present, so compinit rebuilds it and picks\nup the new _min; the cleared path is reported on stderr.\n\nA shell that cannot be installed for (an unwritable shared directory, say) is\na warning on stderr, not a failure."
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

pub async fn run(cli: Cli) -> Result<(), anyhow::Error> {
    use tracing::Instrument as _;
    let ctx = minimal_client::trace_context();
    let root = tracing::info_span!(
        "cmd",
        trace_id = %ctx.trace_id_hex(),
        span_id = %ctx.span_id_hex(),
    );
    // Boxed: inlined, this dispatch match's deepest arm overruns rustc's
    // query depth (128) when computing the future's layout.
    Box::pin(run_command(cli)).instrument(root).await
}

async fn run_command(cli: Cli) -> Result<(), anyhow::Error> {
    // Adopt any pre-split `providers/local-<N>` dirs into the kind-tagged scheme
    // once per invocation, before any command resolves a provider dir, so an
    // upgraded CLI finds an existing instance rather than orphaning it.
    client::migrate_legacy_provider_dirs(cli.global_args.minimal_dir.as_deref());

    match cli.command {
        // A bare `min` (no subcommand) resolves-or-creates a session in a
        // terminal, and prints a read-only state report otherwise — see
        // `cmd_bare`.
        None => cmd_bare(&cli.global_args).await,
        Some(Command::Ls(args)) => cmd_ls(&cli.global_args, args).await,
        Some(Command::Stop(args)) => cmd_stop(&cli.global_args, args).await,
        Some(Command::Session(SessionArgs { command })) => match command {
            SessionCommand::List(args) => cmd_ls(&cli.global_args, args).await,
            SessionCommand::Activate(args) => cmd_activate(&cli.global_args, args).await,
            SessionCommand::Attach(args) => cmd_attach(&cli.global_args, args).await,
            SessionCommand::Exec(args) => cmd_exec(&cli.global_args, args).await,
            SessionCommand::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
            SessionCommand::Rename(args) => cmd_rename(&cli.global_args, args).await,
            SessionCommand::Policy(args) => cmd_session_policy(&cli.global_args, args).await,
            SessionCommand::SetupZed(args) => cmd_session_setup_zed(&cli.global_args, args).await,
            SessionCommand::Hooks(args) => cmd_session_hooks(&cli.global_args, args).await,
        },
        Some(Command::Loadout(LoadoutArgs {
            command: LoadoutCommand::List(args),
        })) => loadouts::cmd_loadout_list(args, &cli.global_args),
        Some(Command::Task(TaskArgs { command })) => match command {
            TaskCommand::Run(args) => task::cmd_task_run(&cli.global_args, args).await,
        },
        Some(Command::Run(args)) => task::cmd_run(&args),
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
        Some(Command::Dash) => cmd_dash(&cli.global_args).await,
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

/// Bounded retries when a freshly minted autogen name collides with an
/// existing session built from the same directory.
const AUTOGEN_NAME_RETRIES: u32 = 8;

/// Reduce a directory basename to the characters a session name should carry —
/// ASCII alphanumerics plus `-`, `_`, `.`, lowercased — dropping everything
/// else (spaces, unicode) so the minted handle is typable and clears
/// `validate_session_name`. Falls back to `session` when nothing survives.
fn sanitize_name_component(basename: &str) -> String {
    let filtered: String = basename
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if matches!(c, '-' | '_' | '.') {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    let trimmed = filtered.trim_matches(|c| matches!(c, '-' | '_' | '.'));
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Mint a typable session name `<dir-basename>-<hex>` from the project
/// directory. The caller supplies the hex so the format is unit-testable and
/// so a collision retry can re-mint with fresh entropy.
fn autogen_session_name(project_dir: &camino::Utf8Path, hex: &str) -> String {
    let base = sanitize_name_component(project_dir.file_name().unwrap_or("session"));
    format!("{base}-{hex}")
}

/// Four lowercase hex digits of per-call entropy, drawn from the stdlib
/// hasher's randomized seed — enough to disambiguate sessions from one
/// directory without pulling in an RNG dependency. Each call reseeds, so a
/// retry gets a fresh suffix.
fn random_hex4() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    let seed = RandomState::new().hash_one("minimal-session-name");
    format!("{:04x}", seed & 0xffff)
}

/// The daemon collapses the session-store `AlreadyExists` into a plain message
/// (see `serve_create_session` in `crates/minimald/src/rpc.rs`); match it so an
/// autogen name clash can be told apart from any other `CreateSession` failure.
fn is_name_collision(error: &str) -> bool {
    error.contains("already exists")
}

/// Whether a failed `CreateSession` should retry under a freshly minted name:
/// only autogen names (`autogen`), only on a name collision, and only within
/// the bounded budget. A user-supplied name never retries, so its collision
/// surfaces verbatim.
fn should_retry_autogen(autogen: bool, attempts: u32, error: &str) -> bool {
    autogen && attempts < AUTOGEN_NAME_RETRIES && is_name_collision(error)
}

/// The default action for a bare `min` (no subcommand).
///
/// In a terminal (stdin and stdout are both TTYs, the same predicate the
/// attach picker uses) it routes into a session: the smart resolution rules
/// of `min session attach` with no argument (cwd match → attach, only
/// session → attach, ambiguity → picker), and when no sessions exist at all
/// it creates one from the current directory and attaches — equivalent to
/// `min session activate --attach .`, except the `minimal.toml` scaffold
/// offer is never made on this path.
///
/// Without a terminal it prints a read-only state report on stderr and exits
/// 0 — see [`cmd_bare_non_tty`]. `min --help` is unaffected: clap handles the
/// flag before dispatch ever reaches here.
async fn cmd_bare(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    if !attach::can_pick_interactively() {
        return cmd_bare_non_tty(global).await;
    }

    ensure_daemon(global)?;
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;
    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    match resolve_smart_attach(&mut client, global).await? {
        SmartAttach::Attach(entry) => {
            tracing::info!(
                session_id = %entry.id,
                session_name = ?entry.name,
                "found session"
            );
            session_via_ssh(&sock, entry.id, vec![]).await
        }
        // Two ways to land on create-and-attach: no sessions exist at all
        // (first run), or the ambiguity picker's `+ Create a new session`
        // row was chosen. Both activate for the cwd exactly as
        // `min session activate --attach .` would (default sync, autogen
        // name) — but with the scaffold offer suppressed, unlike the same
        // picker row reached through `min session attach`: the one
        // keystroke into a session must not detour into config authoring.
        SmartAttach::CreateForCwd | SmartAttach::NoSessions => {
            drop(client);
            activate_session(global, bare_activate_args(), false).await
        }
    }
}

/// The `ActivateArgs` a bare `min` activates with when no sessions exist:
/// exactly `min session activate --attach .` — default sync, autogen name,
/// default network — leaving the path to the `-C`/cwd resolution
/// [`cmd_activate`] already performs for a missing path argument.
fn bare_activate_args() -> ActivateArgs {
    ActivateArgs {
        name: None,
        path: None,
        sync: None,
        network: CliNetworkMode::HostNet,
        ingress: Vec::new(),
        loadout: Vec::new(),
        no_loadouts: false,
        no_hooks: false,
        no_prompt: false,
        attach: true,
    }
}

/// The non-TTY twin of the bare-`min` router: a read-only state report on
/// stderr, then exit 0. Nothing is created and nothing is mutated; stdout
/// stays empty so a pipeline capturing it sees nothing. Listing sessions
/// requires the daemon, so this takes the same client path `min ls` does
/// (which may autospawn) — when that fails, the header plus the error reach
/// stderr and the command exits nonzero, as `min ls` would.
async fn cmd_bare_non_tty(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let cwd = attach::cwd_host_path(global)?;
    let home = std::env::home_dir().and_then(|h| camino::Utf8PathBuf::from_path_buf(h).ok());
    let cwd_display = display_with_home_tilde(cwd.as_utf8_path(), home.as_deref());

    let listed = async {
        ensure_daemon(global)?;
        let mut client = connect_daemon(global).await?;
        use minimald_rpc::ListSessions;
        client
            .oneshot_rpc::<ListSessions>(())
            .await
            .context("ListSessions RPC failed")
    }
    .await;

    match listed {
        Ok(resp) => {
            let has_mfile = project_has_mfile(cwd.as_utf8_path());
            eprint!(
                "{}",
                render_bare_status(&cwd_display, &resp.sessions, &cwd, has_mfile)
            );
            Ok(())
        }
        Err(e) => {
            // The header still identifies what this output is; `main` prints
            // the error itself after the bubble-up.
            eprintln!("{}", bare_status_header(&cwd_display));
            Err(e)
        }
    }
}

/// The first line of the non-TTY state report.
fn bare_status_header(cwd_display: &str) -> String {
    format!("No terminal: not attaching. State for {cwd_display}:")
}

/// Render the bare-`min` non-TTY state report: header, the cwd's session and
/// blueprint state, and the exact next commands. Pure, so the unit tests can
/// assert the lines verbatim.
fn render_bare_status(
    cwd_display: &str,
    entries: &[minimald_rpc::ListSessionsEntry],
    cwd: &paths::HostAbsPath,
    has_mfile: bool,
) -> String {
    let cwd_matches: Vec<&minimald_rpc::ListSessionsEntry> = entries
        .iter()
        .filter(|e| e.project_path.as_ref() == Some(cwd))
        .collect();

    let sessions = if entries.is_empty() {
        "none".to_string()
    } else if cwd_matches.is_empty() {
        format!("0 here ({} elsewhere)", entries.len())
    } else {
        let listed: Vec<String> = cwd_matches
            .iter()
            .take(2)
            .map(|e| format!("({}, {})", entry_handle(e), status_label(e.status)))
            .collect();
        format!("{} {}", cwd_matches.len(), listed.join(", "))
    };

    let blueprint = if has_mfile {
        format!("{} present", mfile::MFILE_NAME)
    } else {
        "none (min init to create one)".to_string()
    };

    let mut out = String::new();
    out.push_str(&bare_status_header(cwd_display));
    out.push('\n');
    out.push_str(&format!("  sessions: {sessions}\n"));
    out.push_str(&format!("  blueprint: {blueprint}\n"));
    out.push_str("Next:\n");
    match cwd_matches.first() {
        Some(e) => {
            out.push_str(&format!(
                "  min session attach --command 'min task run <task>' {}\n",
                entry_handle(e)
            ));
        }
        None => out.push_str("  min session activate --attach .\n"),
    }
    out.push_str("  min ls --json\n");
    out
}

/// A session's typable handle for the state report: its name, or the leading
/// UUID block when unnamed — the same short-id form the attach announcements
/// use.
fn entry_handle(entry: &minimald_rpc::ListSessionsEntry) -> String {
    match &entry.name {
        Some(name) => name.clone(),
        None => {
            let id = entry.id.to_string();
            id.split('-').next().unwrap_or(&id).to_string()
        }
    }
}

/// Abbreviate a home-prefixed path to `~`/`~/...` for display; any other
/// path renders absolute, unchanged.
fn display_with_home_tilde(path: &camino::Utf8Path, home: Option<&camino::Utf8Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) if rest.as_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{rest}"),
        None => path.to_string(),
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

impl From<SessionLookup> for minimald_rpc::GetSessionHooksRequest {
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

/// Open the session manager TUI.
///
/// The TUI probes both provider sockets itself; if neither daemon is
/// running, autospawn the default backend first so the dashboard has
/// something to show (mirroring what the flat subcommands do).
pub async fn cmd_dash(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let dir = global.minimal_dir.as_deref();
    let host_up = autospawn::is_daemon_running(false, dir).unwrap_or(false);
    let vm_up = autospawn::is_daemon_running(true, dir).unwrap_or(false);
    if !host_up && !vm_up {
        ensure_daemon(global)?;
    }
    // Compose the default loadout contribution up front, mirroring
    // cmd_activate: the TUI can't reach this crate's config/loadout
    // plumbing (it sits below), and an empty contribution would silently
    // skip `default_loadouts` and the user policy for sessions created
    // from the dashboard.
    let cfg = config::read_client_config(global)?;
    let user_policy = config::read_user_policy(global)?;
    let compose_options = loadouts::compose_options_from_config(&cfg);
    let active =
        loadouts::resolve_active_loadouts(loadouts::LoadoutSelection::Defaults, &cfg, global)?;
    // `true`: the dashboard has no `--no-hooks`, matching the `hooks_enabled`
    // the TUI sends on `CreateSession`.
    let (contribution, _user_policy) =
        loadouts::compose_user_contribution(active, user_policy, compose_options, true)?;
    minimal_tui::run(minimal_tui::DashOptions {
        minimal_dir: global.minimal_dir.clone(),
        contribution,
    })
    .await
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
        let json = serde_json_lenient::to_string_pretty(resp)
            .context("Failed to serialize session list")?;
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

    // Format as a table. The columns mirror the fields `--json` exposes so
    // the two surfaces present the same session attributes.
    writeln!(
        out,
        "{:<36}  {:<20}  {:<13}  {:<20}  {:<19}  PROJECT PATH",
        "SESSION ID", "NAME", "STATUS", "TITLE", "LAST ACTIVITY"
    )?;
    writeln!(
        out,
        "{:-<36}  {:-<20}  {:-<13}  {:-<20}  {:-<19}  {:-<24}",
        "", "", "", "", "", ""
    )?;

    for entry in &resp.sessions {
        let id = entry.id.to_string();
        let name = entry.name.as_deref().unwrap_or("-");
        let status = status_label(entry.status);
        let project_path = entry
            .project_path
            .as_ref()
            .map(paths::HostAbsPath::to_string)
            .unwrap_or_else(|| "-".to_string());
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
        writeln!(
            out,
            "{id:<36}  {name:<20}  {status:<13}  {title:<20}  {last_activity:<19}  {project_path}"
        )?;
    }

    Ok(())
}

/// Human-readable lifecycle status for the `ls` table, using the same
/// snake_case tokens the `--json` surface emits so the two agree.
fn status_label(status: sessions::SessionStatus) -> &'static str {
    match status {
        sessions::SessionStatus::Pending => "pending",
        sessions::SessionStatus::Materializing => "materializing",
        sessions::SessionStatus::Active => "active",
    }
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
/// interactive when stdin is a pipe just hangs the prompt and then
/// aborts with a much less helpful error than the `--no-prompt`
/// snippet the operator actually wants to paste.
fn can_prompt_interactively() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
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

/// Upload the composition's patches and external hook scripts (if
/// any) and finalize the session. The session is `Materializing` at
/// entry; `Active` on success. On upload/finalize failure the session
/// is left in `Materializing` — the caller is responsible for
/// destroying it.
///
/// Both uploads precede `FinalizeSession`, which gates on each
/// upload's ready-marker: a session must not become attachable while
/// either its patches or its hook scripts are still missing from the
/// daemon.
///
/// `hook_budget` is the summed declared timeout of the composition's
/// `on_activate` hooks, which the daemon runs inside `FinalizeSession`;
/// the call's deadline is extended by it so a hook declaring more than the
/// base RPC timeout is not cut short.
async fn upload_and_finalize(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    patches: &[(std::path::PathBuf, paths::SandboxRelPath)],
    hook_scripts: &[sessions::client::hookscripts::StagedScript],
    hook_budget: std::time::Duration,
) -> Result<(), anyhow::Error> {
    client
        .upload_patches(session_id, patches)
        .await
        .context("Failed to upload composition patches")?;

    client
        .upload_hook_scripts(session_id, hook_scripts)
        .await
        .context("Failed to upload lifecycle hook scripts")?;

    use minimald_rpc::{FinalizeSession, FinalizeSessionRequest};
    let resp = client
        .oneshot_rpc_with_hook_budget::<FinalizeSession>(
            FinalizeSessionRequest { session_id },
            hook_budget,
        )
        .await
        .context("FinalizeSession RPC failed")?;
    match resp {
        minimald_rpc::Errorable::Ok(ok) => {
            // An activate hook runs headlessly, so without this the only
            // trace of it is the daemon log. Say what ran — the user
            // agreed to let this code execute, and is owed the receipt.
            for hook in &ok.activate_hooks {
                match hook.description.as_deref() {
                    Some(d) => eprintln!("Ran activation hook from {}: {d}", hook.declared_by),
                    None => eprintln!("Ran activation hook from {}", hook.declared_by),
                }
            }
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("FinalizeSession failed: {error}");
        }
    }
}

/// Guard that tears down a half-built session if the user interrupts the
/// activation with Ctrl-C.
///
/// inquire (crossterm raw mode) captures a Ctrl-C at the
/// composition-gating prompt as an error return, so the abort-cleanup
/// that [`drive_pending_to_active`] runs gets to execute. During the
/// non-prompt phases (waiting on the daemon) a Ctrl-C is a plain
/// SIGINT, which would kill `min` before that cleanup, leaving the
/// daemon holding a `Pending` session that blocks its name.
/// [`arm_activation_interrupt`] installs a SIGINT handler that best-effort
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
    run_init_flow(config, false, false)
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
    activate_session(global, args, true).await
}

/// The activation flow shared by [`cmd_activate`] and the bare-`min` router.
/// `offer_scaffold` gates the `minimal.toml` scaffold offer: `cmd_activate`
/// keeps it (its long-standing behavior, unchanged), while bare `min`
/// suppresses it — that path must land in a session, never in a config
/// prompt. Everything else, including the session id on stdout, is
/// identical for both callers.
async fn activate_session(
    global: &GlobalArgs,
    args: ActivateArgs,
    offer_scaffold: bool,
) -> Result<(), anyhow::Error> {
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

    if offer_scaffold {
        offer_mfile_scaffold(&utf8_path, global)?;
    }

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

    // A session with no `--name` still deserves a typable handle, so mint
    // `<dir-basename>-<4 hex>` client-side; without it `min ls`, the attach
    // picker, and the create announcement fall back to a bare short id. A
    // user-supplied name is passed through untouched — including a collision,
    // which must surface as an error rather than be silently suffixed.
    let autogen = args.name.is_none();
    let session_name = args
        .name
        .clone()
        .unwrap_or_else(|| autogen_session_name(&utf8_path, &random_hex4()));

    // The daemon sources `username` from the authenticated SSH
    // connection context; the client doesn't send it.
    let config = minimald_rpc::SessionConfig {
        name: Some(session_name),
        project_path: abs_path,
        network: args.network.into(),
        policy,
        hooks_enabled: !args.no_hooks,
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
    if !active.loadouts.is_empty() {
        let names: Vec<&str> = active.loadouts.iter().map(|l| l.name().as_ref()).collect();
        eprintln!("Applying loadouts: {}", names.join(", "));
    }
    // The contribution carries the banner's loadout display list as a
    // first-class orientation field (the daemon seeds MINIMAL_LOADOUTS
    // from it in the launcher baseline). The banner's other dynamic
    // clause — blueprint presence — is a session-filesystem fact,
    // tested by the templates in-shell when they print.
    // Resolve the loadouts' external hook scripts before anything
    // touches the daemon: a mistyped path, a symlinked script, or a
    // missing loadout script directory should fail here, on this
    // machine, rather than after a session exists on the daemon.
    let hook_scripts =
        loadouts::stage_loadout_hook_scripts(&active, global, &utf8_path, !args.no_hooks)?;

    // Same idea for the *project's* hooks, which the daemon composes from
    // the uploaded mfile and which therefore never pass through the
    // staging above. Nothing here is uploaded — the project tree carries
    // its own scripts — but the checks a staging pass would have made are
    // still worth making on this machine, before a session exists.
    if !args.no_hooks {
        loadouts::check_project_hooks(&utf8_path)?;
    }

    // The daemon runs the composition's `on_activate` hooks inside
    // `FinalizeSession`; size that call's deadline to their summed declared
    // timeouts, computed here while the loadouts are still in hand.
    let finalize_hook_budget = loadouts::activate_hook_budget(&active, &utf8_path, !args.no_hooks);

    let (contribution, user_policy) =
        loadouts::compose_user_contribution(active, user_policy, compose_options, !args.no_hooks)?;

    // `--sync` defaults to tarball; `sync_explicit` records whether the
    // user actually typed the flag, which distinguishes a deliberate
    // `--sync tarball` (the escape hatch that force-uploads an empty dir
    // or `$HOME`) from the implicit default.
    let sync_explicit = args.sync.is_some();
    let sync_mode = args.sync.unwrap_or(SyncMode::Tarball);

    // Resolve the upload root before opening the daemon connection:
    // a malformed mfile in an ancestor should fail loudly before
    // we create a session on the daemon, so we don't leak a draft
    // session. Only needed for tarball sync — `--sync none` skips
    // the upload entirely (#770).
    let upload_root = match sync_mode {
        SyncMode::None => None,
        SyncMode::Tarball => Some(resolve_upload_root(&utf8_path)?),
    };

    // Skip the upload without prompting when the resolved root is an
    // empty directory or `$HOME` — unless the user asked for it with an
    // explicit `--sync tarball`, the escape hatch.
    let skip_empty_or_home = !sync_explicit
        && upload_root.as_ref().is_some_and(|root| {
            file_upload::is_empty_or_home(root.as_std_path(), std::env::home_dir().as_deref())
        });

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
    };
    // An autogen name can (rarely) collide with an existing session built
    // from the same directory; on the daemon's already-exists rejection,
    // re-mint the hex suffix and retry a bounded number of times. A
    // user-supplied name never retries — its collision, and any other failure
    // (e.g. a policy/network-mode validation error), surfaces unchanged.
    let mut config = config;
    let mut attempts = 0u32;
    let created = loop {
        let resp = client
            .oneshot_rpc::<CreateSession>(CreateSessionRequest {
                config: config.clone(),
            })
            .await
            .context("CreateSession RPC failed")?;
        match resp {
            minimald_rpc::Errorable::Ok(r) => break r,
            minimald_rpc::Errorable::Err { error } => {
                if should_retry_autogen(autogen, attempts, &error) {
                    attempts += 1;
                    config.name = Some(autogen_session_name(&utf8_path, &random_hex4()));
                    continue;
                }
                bail!("CreateSession failed: {error}");
            }
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
    match sync_mode {
        SyncMode::None => {}
        SyncMode::Tarball if skip_empty_or_home => {
            // An empty directory has nothing to sync, and `$HOME` is far
            // too much to ship on a stray confirmation keypress — and if
            // `$HOME` is itself a VCS root the old gate uploaded it with
            // no prompt at all. Skip both silently by default; a
            // deliberate `--sync tarball` (via `sync_explicit`) is the
            // escape hatch that still uploads them.
            eprintln!("Starting with an empty box (nothing here to sync)");
        }
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
            // (e.g. `~`). A VCS root uploads unconditionally. For a non-VCS
            // root an interactive caller gets the confirm (default No); a
            // headless caller (CI, pipes, agents, `--no-prompt`,
            // `--no-input`) can't be asked, so it skips the upload with a
            // warning rather than silently shipping a directory nobody
            // confirmed — `--sync tarball` (via `sync_explicit`) is the
            // escape hatch that force-uploads it anyway (#770).
            let headless = args.no_prompt || global.no_input || !can_prompt_interactively();
            let should_upload = match file_upload::upload_gate(
                file_upload::is_vcs_root(upload_root.as_std_path()),
                sync_explicit,
                headless,
            ) {
                file_upload::UploadGate::Upload => true,
                file_upload::UploadGate::SkipHeadless => {
                    eprintln!(
                        "warning: {upload_root} is not a version control repository root; \
                         skipping file upload (pass --sync tarball to upload anyway)"
                    );
                    false
                }
                file_upload::UploadGate::Prompt => confirm(
                    &format!(
                        "{upload_root} is not a version control repository root. \
                         Upload all files from this directory?"
                    ),
                    false,
                )?,
            };
            if should_upload {
                client
                    .upload_workspace_files(id, upload_root.as_std_path())
                    .await
                    .context("Failed to upload project files")?;
            } else if !headless {
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
    if let Err(e) = upload_and_finalize(
        &mut client,
        id,
        &collected_patches,
        &hook_scripts,
        finalize_hook_budget,
    )
    .await
    {
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
                session_announce_label(&id, config.name.as_deref())
            );
        }
        let attach_args = AttachArgs {
            session: Some(id.to_string()),
        };
        return cmd_attach(global, attach_args).await;
    }

    Ok(())
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
            SmartAttach::Attach(entry) => (entry.id, entry.name),
            SmartAttach::CreateForCwd => return activate_new_for_attach(global).await,
            SmartAttach::NoSessions => {
                bail!("no sessions exist; use 'min session activate' to create one")
            }
        },
    };

    tracing::info!(
        session_id = %id,
        session_name = ?name,
        "found session"
    );

    session_via_ssh(&sock, id, vec![]).await
}

/// Executes a command in an existing session.
///
/// The session is resolved using the provided predicate, and the connection
/// is provided by shelling out to `ssh`.
pub async fn cmd_exec(global: &GlobalArgs, args: ExecArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;

    let r = resolve_session(&mut client, &args.session).await?;
    tracing::info!(
        session_id = %r.id,
        session_name = ?r.name,
        "found session"
    );

    session_via_ssh(&sock, r.id, args.command).await
}

/// Resolve a session to attach to when the user supplied no explicit session
/// reference. Lists sessions, matches against the current working directory,
/// and either attaches directly (unambiguous), opens the interactive picker
/// (ambiguous), or errors (ambiguous but non-interactive).
///
/// Returns [`SmartAttach::NoSessions`] when no sessions exist at all, which
/// `min session attach` reports as an error pointing at `min session activate`.
async fn resolve_smart_attach(
    client: &mut client::Client,
    global: &GlobalArgs,
) -> Result<SmartAttach, anyhow::Error> {
    use minimald_rpc::ListSessions;

    let resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;
    let cwd = attach::cwd_host_path(global)?;
    match attach::resolve_for_attach(&resp.sessions, &cwd) {
        attach::SmartResolve::NoSessions => Ok(SmartAttach::NoSessions),
        attach::SmartResolve::Attach(entry) => {
            // Unambiguous auto-resolve: the operator never chose this session,
            // so tell them which one they're landing in. The picker path below
            // needs no such line — the selection is its own confirmation.
            if should_announce_session(global) {
                eprintln!(
                    "Attaching to session {}{}",
                    session_announce_label(&entry.id, entry.name.as_deref()),
                    attach::created_from_suffix(&entry, &cwd)
                );
            }
            Ok(SmartAttach::Attach(entry))
        }
        attach::SmartResolve::Pick(cands) => {
            if global.no_input || !attach::can_pick_interactively() {
                bail!(attach::ambiguous_no_input_message(&cands, &cwd));
            }
            match attach::pick_session(&cands, &cwd)? {
                Some(attach::Picked::Session(entry)) => Ok(SmartAttach::Attach(entry)),
                Some(attach::Picked::CreateNew) => Ok(SmartAttach::CreateForCwd),
                None => bail!("session selection cancelled"),
            }
        }
    }
}

/// Outcome of smart attach resolution when the user gave no explicit session.
enum SmartAttach {
    /// Attach to this resolved or picked session.
    Attach(minimald_rpc::ListSessionsEntry),
    /// The picker's create row was chosen: activate a fresh session for the
    /// cwd and attach, exactly as `min session activate --attach .` would.
    CreateForCwd,
    /// No sessions exist at all.
    NoSessions,
}

/// The picker's `+ Create a new session` arm: activate a fresh session for the
/// cwd and attach. A thin wrapper over [`cmd_activate`] with an autogen name
/// and default sync, so the create-then-attach path stays the one that
/// `min session activate --attach .` runs.
async fn activate_new_for_attach(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    // `Box::pin` breaks the async recursion cycle: `cmd_activate` chains into
    // `cmd_attach` (on `--attach`), which reaches back here — an unboxed cycle
    // is an infinitely sized future (E0733).
    Box::pin(cmd_activate(
        global,
        ActivateArgs {
            name: None,
            path: None,
            sync: None,
            network: CliNetworkMode::HostNet,
            ingress: Vec::new(),
            loadout: Vec::new(),
            no_loadouts: false,
            no_hooks: false,
            no_prompt: false,
            attach: true,
        },
    ))
    .await
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
             Run it from a terminal."
        )
    }
}

/// Shell out to `ssh` to attach to `id` or run a command.
///
/// Split from [`cmd_attach`] so the activate-then-attach chain and the
/// smart-resolution picker can attach without re-resolving an entry they
/// already hold.
async fn session_via_ssh(
    sock: &std::path::Path,
    id: sessions::SessionId,
    command: Vec<String>,
) -> Result<(), anyhow::Error> {
    // The command itself lives in minimal-client, shared with the dash TUI's
    // suspend-attach-resume flow.
    let mut ssh = minimal_client::attach::attach_command(sock, id, &command)?;

    // `-tt` over a *non-terminal* stdin is a trap: ssh still forces the
    // remote PTY, yet the interactive shell reading it never sees an EOF from a
    // redirected local stdin (`< /dev/null`, a pipe), so the command blocks
    // forever (#953). Fail fast instead of hanging.
    if command.is_empty() {
        ensure_interactive_attach_tty(std::io::stdin().is_terminal())?;
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
            let json =
                serde_json_lenient::to_string(&policy).context("Failed to serialize policy")?;
            println!("{json}");
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("{error}")
        }
    }
}

/// Register a session as an SSH remote in Zed's `settings.json`.
///
/// Zed drives its own `ssh` for remote projects, so the entry has to carry the
/// whole transport in `args`: the `ProxyCommand` onto the daemon socket, the
/// session selector, and the host-key options. See [`zed`] for why each is
/// there and how the upsert identifies an existing entry.
pub async fn cmd_session_setup_zed(
    global: &GlobalArgs,
    args: SetupZedArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut daemon_client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    let record = resolve_session(&mut daemon_client, &args.session).await?;

    // Pin the socket explicitly rather than leaning on `min proxy`'s own
    // resolution: Zed launches the ProxyCommand from its own environment, which
    // carries none of this invocation's `--minimal-dir` / provider selection.
    let exe = std::env::current_exe().context("cannot determine current exe")?;
    let proxy_command = format!(
        "{} proxy --socket {}",
        minimal_client::attach::shell_quote(&exe.display().to_string()),
        minimal_client::attach::shell_quote(&sock.display().to_string()),
    );

    // Same host identity as attach: the provider-instance alias the daemon
    // keyed its known_hosts entry on, derived from the socket path so the two
    // cannot disagree.
    let host = sock
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(|n| n.to_str())
        .context("daemon socket path has no provider-dir parent")?
        .to_string();

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .context("cannot determine the local username (neither USER nor LOGNAME is set)")?;

    let conn = zed::Connection {
        host,
        username,
        session_id: record.id.to_string(),
        proxy_command,
        host_key_opts: minimal_client::attach::host_key_opts(
            &sock.with_file_name(paths::KNOWN_HOSTS_FILE),
        ),
    };

    if args.print {
        println!(
            "{}",
            serde_json_lenient::to_string_pretty(&conn.entry())
                .context("Failed to serialize the Zed connection entry")?
        );
        return Ok(());
    }

    let path = match &args.settings {
        Some(p) => p.clone(),
        None => zed::default_settings_path()?,
    };

    let mut settings = zed::read_settings(&path)?;
    let outcome = zed::upsert(&mut settings, &conn)?;

    let name = record.name.as_deref().unwrap_or("-");
    if outcome == zed::Outcome::Unchanged {
        println!(
            "Zed already has session {} ({}) at {}",
            record.id,
            name,
            path.display()
        );
        return Ok(());
    }

    let backup = zed::write_settings(&path, &settings)?;
    let verb = if outcome == zed::Outcome::Inserted {
        "Added"
    } else {
        "Updated"
    };
    println!(
        "{} session {} ({}) in {}",
        verb,
        record.id,
        name,
        path.display()
    );
    if let Some(backup) = backup {
        println!(
            "Previous settings saved to {} (comments and key order are not preserved on rewrite)",
            backup.display()
        );
    }
    println!(
        "Open it from Zed's remote-project picker, under host {}",
        conn.host
    );

    Ok(())
}

/// `min session hooks`: list the lifecycle hooks composed into a
/// session, with the loadout or project that declared each.
///
/// Shows what will actually run, not what was asked for: the daemon
/// answers from the composition, which holds only the hooks that
/// survived the user-policy gate. A session activated with `--no-hooks`,
/// or one whose project was never allow-listed, lists nothing.
///
/// Rows are in setup order — project first, then loadouts in the order
/// they were applied. Teardown runs the reverse.
async fn cmd_session_hooks(global: &GlobalArgs, args: HooksArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{GetSessionHooks, GetSessionHooksRequest};
    let lookup: GetSessionHooksRequest = SessionLookup::parse(&args.session).into();
    let resp = client
        .oneshot_rpc::<GetSessionHooks>(lookup)
        .await
        .context("GetSessionHooks RPC failed")?;

    let hooks = match resp {
        minimald_rpc::Errorable::Ok(hooks) => hooks,
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    };

    if args.json {
        println!(
            "{}",
            serde_json_lenient::to_string(&hooks).context("Failed to serialize hooks")?
        );
        return Ok(());
    }

    if hooks.is_empty() {
        println!("No lifecycle hooks are composed into this session.");
        return Ok(());
    }

    // One row per *script*, not per hook: a hook may declare up to four,
    // and "when does this run" is the question the listing exists to
    // answer.
    for provenanced in &hooks {
        let hook = &provenanced.hook;
        let source = render_hook_source(&provenanced.source);
        for (event, script) in [
            ("on_activate", hook.on_activate.as_ref()),
            ("on_destroy", hook.on_destroy.as_ref()),
            ("on_attach", hook.on_attach.as_ref()),
            ("on_detach", hook.on_detach.as_ref()),
        ] {
            let Some(script) = script else { continue };
            let (kind, body, timeout) = render_hook_script(script);
            print!("{event:<12} {kind:<9} {timeout:>4}s  {source}");
            match hook.description.as_deref() {
                Some(d) => println!("  — {d}"),
                None => println!(),
            }
            println!("             {body}");
        }
    }
    Ok(())
}

/// Human-readable origin for a hook row.
fn render_hook_source(source: &sessions::wire::primitives::WireSource) -> String {
    use sessions::wire::primitives::WireSource;
    match source {
        WireSource::UserLoadout { name } => format!("loadout {name}"),
        WireSource::Project { path } => format!("project {path}"),
        WireSource::Package { name } => format!("package {name}"),
    }
}

/// `(kind, one-line body, timeout seconds)` for a hook script.
///
/// An inline body is collapsed to its first line so a multi-line script
/// cannot break the row alignment; the full text is available via
/// `--json`.
fn render_hook_script(
    script: &sessions::wire::primitives::WireHookScript,
) -> (&'static str, String, u64) {
    use sessions::wire::primitives::WireHookScript;
    match script {
        WireHookScript::Inline { body, timeout_secs } => {
            let first = body.lines().next().unwrap_or("").trim();
            let shown = if body.lines().count() > 1 {
                format!("{first} …")
            } else {
                first.to_string()
            };
            ("inline", shown, *timeout_secs)
        }
        WireHookScript::External { path, timeout_secs } => {
            ("external", path.as_str().to_string(), *timeout_secs)
        }
    }
}

/// The local mesh-enrolment record path. `--minimal-dir` still wins for
/// the historical "everything lives under the state dir" workflow;
/// otherwise falls through to the loadout-subsystem's config dir
/// so `--config-dir` moves the mesh enrolment along with everything
/// else.
///
/// Not gated behind `remote-access`: it is a pure path helper the `min bug`
/// diagnostic bundle captures regardless of whether the mesh commands are
/// compiled in.
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

    // Under --force the at-risk fetch is skipped outright — the gate is
    // bypassed regardless, so there is nothing to ask the daemon for.
    let at_risk = if args.force {
        AtRiskState::Clean
    } else {
        assess_at_risk(session_delta(&mut client, record.id).await)
    };
    match destroy_gate(
        args.force,
        &at_risk,
        global.no_input,
        std::io::stdin().is_terminal(),
    )? {
        DestroyGate::Proceed => {}
        DestroyGate::Confirm => {
            if let AtRiskState::Dirty(lines) = &at_risk {
                for line in lines {
                    println!("{line}");
                }
            }
            let label = record.name.as_deref().unwrap_or(session);
            if !confirm(
                &format!("Destroy session {label}? This permanently deletes all in-session files."),
                false,
            )? {
                println!("Aborted.");
                return Ok(());
            }
        }
    }

    destroy_session(&mut client, record.id, record.name.as_deref()).await
}

/// What the daemon's at-risk report means for the destroy gate.
///
/// The three-way split is deliberate: proven-clean destroys without a word,
/// proven-dirty gates with the listing, and unknowable gates without one —
/// an unreadable tree (stopped session, RPC failure) cannot prove dirt, but
/// it cannot prove cleanliness either, so the gate stays conservative.
#[derive(Debug, PartialEq, Eq)]
enum AtRiskState {
    /// Proven clean: everything committed and pushed, or nothing changed
    /// since activation. Destroy proceeds without a prompt.
    Clean,
    /// At-risk work, with the rendered listing lines to print above the
    /// confirm.
    Dirty(Vec<String>),
    /// The state could not be determined: gate, but without a listing.
    Unknowable,
}

/// Classifies the daemon's [`minimald_rpc::SessionDeltaResponse`] (or its
/// absence, on RPC failure/timeout) into the destroy gate's three-way
/// state, rendering the listing lines for the dirty arm.
fn assess_at_risk(resp: Option<minimald_rpc::SessionDeltaResponse>) -> AtRiskState {
    use minimald_rpc::SessionDeltaResponse as R;
    /// Cap on listing rows, matching the shell-exit prompt's.
    const ROWS_SHOWN: usize = 10;
    fn push_capped(rows: &[String], out: &mut Vec<String>) {
        for row in rows.iter().take(ROWS_SHOWN) {
            out.push(format!("  {row}"));
        }
        if rows.len() > ROWS_SHOWN {
            out.push(format!("  ... and {} more", rows.len() - ROWS_SHOWN));
        }
    }
    match resp {
        None | Some(R::Unavailable) => AtRiskState::Unknowable,
        Some(R::Vcs {
            uncommitted,
            unpushed_commits,
        }) => {
            if uncommitted.is_empty() && unpushed_commits == 0 {
                return AtRiskState::Clean;
            }
            let mut lines = Vec::new();
            if !uncommitted.is_empty() {
                let n = uncommitted.len();
                let s = if n == 1 { "" } else { "s" };
                lines.push(format!("{n} file{s} with uncommitted changes:"));
                push_capped(&uncommitted, &mut lines);
            }
            if unpushed_commits > 0 {
                let s = if unpushed_commits == 1 { "" } else { "s" };
                lines.push(format!(
                    "{unpushed_commits} commit{s} not pushed to any remote"
                ));
            }
            AtRiskState::Dirty(lines)
        }
        Some(R::ChangedSinceActivation { rows }) => {
            if rows.is_empty() {
                return AtRiskState::Clean;
            }
            let n = rows.len();
            // Honest wording for the non-VCS fallback: the activation
            // baseline cannot tell committed work from unsaved work.
            let (noun, verb) = if n == 1 {
                ("file", "differs")
            } else {
                ("files", "differ")
            };
            let mut lines = vec![format!(
                "{n} {noun} {verb} from activation (may include committed work):"
            )];
            push_capped(&rows, &mut lines);
            AtRiskState::Dirty(lines)
        }
    }
}

/// How a single-session destroy proceeds past its confirmation gate.
#[derive(Debug, PartialEq, Eq)]
enum DestroyGate {
    /// Destroy without prompting: `--force`, or the session is proven
    /// clean.
    Proceed,
    /// Prompt interactively (default No) before destroying.
    Confirm,
}

/// Decides whether a single-session destroy proceeds promptless, may
/// prompt, or must refuse — one match over (force, at-risk state,
/// interactivity).
fn destroy_gate(
    force: bool,
    at_risk: &AtRiskState,
    no_input: bool,
    stdin_is_terminal: bool,
) -> Result<DestroyGate, anyhow::Error> {
    let interactive = !no_input && stdin_is_terminal;
    match (force, at_risk, interactive) {
        // --force bypasses the gate; a proven-clean session has nothing to
        // lose, so no friction either — including headless.
        (true, _, _) | (false, AtRiskState::Clean, _) => Ok(DestroyGate::Proceed),
        // At-risk (or unknowable) work with a human present: ask.
        (false, _, true) => Ok(DestroyGate::Confirm),
        // The `--all` headless precedent: EOF must never read as consent.
        (false, _, false) => {
            bail!("refusing to destroy the session without confirmation; pass --force")
        }
    }
}

/// Best-effort fetch of the session's at-risk report for the destroy
/// confirm. Any failure — RPC error, timeout, a daemon predating the RPC —
/// reads as `None` (unknowable), and the confirm renders without a listing.
async fn session_delta(
    client: &mut client::Client,
    id: sessions::SessionId,
) -> Option<minimald_rpc::SessionDeltaResponse> {
    /// Client-side ceiling on the fetch. The daemon bounds each of its
    /// computations at 5 s; this sits just above so a slow-but-healthy
    /// answer still lands while a wedged daemon cannot stall the confirm.
    const SESSION_DELTA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};
    tokio::time::timeout(
        SESSION_DELTA_TIMEOUT,
        client.oneshot_rpc::<SessionDelta>(SessionDeltaRequest { id }),
    )
    .await
    .ok()?
    .ok()
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
        minimal_client::attach::shell_quote(&exe.display().to_string()),
        minimal_client::attach::shell_quote(&sock.display().to_string()),
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
fn run_init_flow(
    config: mctx::Config,
    skip_confirm: bool,
    force: bool,
) -> Result<(), anyhow::Error> {
    use op::ProjectOp as _;
    let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let plan = op::InitProject
        .run(&mut env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Overwriting an existing minimal.toml is destructive — no backup is
    // written — so require an explicit --force rather than let confirm() read
    // a non-TTY EOF as a silent "yes". Mirrors `min session destroy --all`,
    // which likewise refuses non-interactively and names the flag to proceed.
    let exists = plan.toml_path.exists();
    if exists && !force {
        bail!(
            "refusing to overwrite existing {} without confirmation; pass --force",
            plan.toml_path.display()
        );
    }

    if !skip_confirm {
        let verb = if exists { "overwrite" } else { "create" };
        eprintln!("\nWill {verb} {}:\n", plan.toml_path.display());
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

    eprintln!(
        "{} {}",
        if exists { "Updated" } else { "Created" },
        plan.toml_path.display()
    );

    Ok(())
}

/// Initialize a `minimal.toml` based on the source tree.
pub async fn cmd_init(global: &GlobalArgs, args: InitArgs) -> Result<(), mctx::Error> {
    let config = build_config(global)?;
    run_init_flow(config, args.yes, args.force).map_err(mctx::Error::Other)
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
    let mut ctx = match mctx::Context::new(config) {
        Ok(ctx) => ctx,
        // Point a user with no `minimal.toml` at `min init`, matching the hint
        // `min session activate` gives in the same situation.
        Err(e @ mctx::Error::MFile(mfile::Error::NotFound)) => {
            return Err(mctx::Error::Other(anyhow::anyhow!(
                "{e}\nRun 'min init' to give the project its own config."
            )));
        }
        Err(e) => return Err(e),
    };

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
            err.contains("not a TTY"),
            "expected an actionable non-TTY error, got: {err}"
        );
        ensure_interactive_attach_tty(true).expect("a real terminal must pass the guard");
    }

    /// The `Cli` command tree must stay well-formed: a malformed clap
    /// definition panics in `debug_assert`/render, not at parse time, so
    /// `min --help` (which bare `min` no longer prints, but which must keep
    /// working unchanged) stays renderable.
    #[test]
    fn cli_command_tree_stays_renderable() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    /// Entry constructor for the bare-`min` state-report tests.
    fn twin_entry(
        id: &str,
        name: Option<&str>,
        path: Option<&str>,
        status: sessions::SessionStatus,
    ) -> minimald_rpc::ListSessionsEntry {
        minimald_rpc::ListSessionsEntry {
            id: sessions::SessionId::parse_str(id).unwrap(),
            name: name.map(str::to_owned),
            project_path: path.map(|p| paths::HostAbsPath::try_new(p).unwrap()),
            status,
            attrs: None,
        }
    }

    /// One cwd-matching session: the report names it with its status, and the
    /// `Next:` attach line carries its real name — every line verbatim.
    #[test]
    fn bare_status_renders_a_cwd_session_verbatim() {
        let entries = vec![twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            Some("web"),
            Some("/w"),
            sessions::SessionStatus::Active,
        )];
        let cwd = paths::HostAbsPath::try_new("/w").unwrap();
        assert_eq!(
            render_bare_status("~/w", &entries, &cwd, true),
            "No terminal: not attaching. State for ~/w:\n\
             \x20 sessions: 1 (web, active)\n\
             \x20 blueprint: minimal.toml present\n\
             Next:\n\
             \x20 min session attach --command 'min task run <task>' web\n\
             \x20 min ls --json\n"
        );
    }

    /// No sessions anywhere and no blueprint: the report says so and the
    /// `Next:` lines become the create-and-attach pair — every line verbatim.
    #[test]
    fn bare_status_renders_the_empty_state_verbatim() {
        let cwd = paths::HostAbsPath::try_new("/w").unwrap();
        assert_eq!(
            render_bare_status("/w", &[], &cwd, false),
            "No terminal: not attaching. State for /w:\n\
             \x20 sessions: none\n\
             \x20 blueprint: none (min init to create one)\n\
             Next:\n\
             \x20 min session activate --attach .\n\
             \x20 min ls --json\n"
        );
    }

    /// Sessions exist but none for this cwd: counted as elsewhere, and the
    /// `Next:` lines still offer create-and-attach (attaching to another
    /// project's session is not the suggestion).
    #[test]
    fn bare_status_counts_elsewhere_sessions() {
        let entries = vec![
            twin_entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                Some("api"),
                Some("/other"),
                sessions::SessionStatus::Active,
            ),
            twin_entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                None,
                Some("/third"),
                sessions::SessionStatus::Pending,
            ),
        ];
        let cwd = paths::HostAbsPath::try_new("/w").unwrap();
        let out = render_bare_status("/w", &entries, &cwd, true);
        assert!(
            out.contains("  sessions: 0 here (2 elsewhere)\n"),
            "elsewhere count: {out}"
        );
        assert!(
            out.contains("  min session activate --attach .\n"),
            "no cwd session must suggest activate: {out}"
        );
        assert!(
            !out.contains("session attach --command"),
            "must not suggest attaching elsewhere: {out}"
        );
    }

    /// More than two cwd matches: the count is the full total, the listing
    /// stops at two, and an unnamed session shows its short id — which is
    /// also what the attach suggestion substitutes for the first match.
    #[test]
    fn bare_status_lists_at_most_two_cwd_sessions() {
        let entries = vec![
            twin_entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                None,
                Some("/w"),
                sessions::SessionStatus::Pending,
            ),
            twin_entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                Some("web"),
                Some("/w"),
                sessions::SessionStatus::Materializing,
            ),
            twin_entry(
                "019f5d0f-0a99-78b1-9165-0809440f0077",
                Some("spare"),
                Some("/w"),
                sessions::SessionStatus::Active,
            ),
        ];
        let cwd = paths::HostAbsPath::try_new("/w").unwrap();
        let out = render_bare_status("/w", &entries, &cwd, true);
        assert!(
            out.contains("  sessions: 3 (019f5d0f, pending), (web, materializing)\n"),
            "count-then-two listing: {out}"
        );
        assert!(
            !out.contains("spare"),
            "third session must not be listed: {out}"
        );
        assert!(
            out.contains("  min session attach --command 'min task run <task>' 019f5d0f\n"),
            "attach suggestion uses the first match's handle: {out}"
        );
    }

    /// `~` abbreviation: exactly under home, home itself, and a path outside
    /// home (which renders absolute, untouched).
    #[test]
    fn display_with_home_tilde_abbreviates_only_under_home() {
        fn p(s: &str) -> &camino::Utf8Path {
            camino::Utf8Path::new(s)
        }
        assert_eq!(
            display_with_home_tilde(p("/home/u/code/app"), Some(p("/home/u"))),
            "~/code/app"
        );
        assert_eq!(
            display_with_home_tilde(p("/home/u"), Some(p("/home/u"))),
            "~"
        );
        assert_eq!(
            display_with_home_tilde(p("/srv/app"), Some(p("/home/u"))),
            "/srv/app"
        );
        assert_eq!(display_with_home_tilde(p("/srv/app"), None), "/srv/app");
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

    /// A session created without `--name` gets a typable `<dir>-<hex>` handle:
    /// the basename is lowercased and stripped to the name alphabet, and the
    /// caller-supplied hex tails it.
    #[test]
    fn autogen_session_name_slugs_the_basename() {
        assert_eq!(
            autogen_session_name(camino::Utf8Path::new("/home/u/code/foo"), "9c1e"),
            "foo-9c1e"
        );
        // Disallowed characters are dropped and the rest lowercased.
        assert_eq!(
            autogen_session_name(camino::Utf8Path::new("/tmp/My Project!"), "4f2a"),
            "myproject-4f2a"
        );
        // A basename that sanitizes to nothing falls back to `session`.
        assert_eq!(
            autogen_session_name(camino::Utf8Path::new("/"), "0001"),
            "session-0001"
        );
    }

    /// Sanitization drops out-of-alphabet characters, trims leading/trailing
    /// separators, and falls back to `session` for an all-symbol basename, so
    /// the minted name always clears `validate_session_name`.
    #[test]
    fn sanitize_name_component_trims_and_falls_back() {
        assert_eq!(sanitize_name_component("--foo--"), "foo");
        assert_eq!(sanitize_name_component("café"), "caf");
        assert_eq!(sanitize_name_component("...."), "session");
        assert_eq!(sanitize_name_component("a\tb"), "ab");
    }

    /// The minted suffix is exactly four lowercase hex digits.
    #[test]
    fn random_hex4_is_four_lowercase_hex_digits() {
        let h = random_hex4();
        assert_eq!(h.len(), 4);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected four lowercase hex digits, got {h:?}"
        );
    }

    /// Only an autogen name retries on collision, and only within the bounded
    /// budget; a user-supplied name never retries, so its collision passes
    /// through, and a non-collision failure is never retried.
    #[test]
    fn autogen_collision_retry_is_bounded_and_skips_user_names() {
        let collision = "A session with that name already exists";
        assert!(should_retry_autogen(true, 0, collision));
        assert!(should_retry_autogen(
            true,
            AUTOGEN_NAME_RETRIES - 1,
            collision
        ));
        // Budget spent: stop retrying.
        assert!(!should_retry_autogen(true, AUTOGEN_NAME_RETRIES, collision));
        // A user-supplied name never retries — its collision surfaces verbatim.
        assert!(!should_retry_autogen(false, 0, collision));
        // A non-collision failure is never retried.
        assert!(!should_retry_autogen(true, 0, "CreateSession failed: boom"));
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

    /// `min session list` is the canonical `<noun> list` spelling of the
    /// flagship list command; `min ls` (top-level) and `min session ls`
    /// (noun-level) are visible aliases. All three parse to the same `LsArgs`,
    /// so `--raw`/`--json` reach the one `cmd_ls` implementation identically.
    #[test]
    fn session_list_spellings_all_reach_ls() {
        use clap::Parser as _;
        let ls_args = |args: &[&str]| -> LsArgs {
            match Cli::try_parse_from(args).unwrap().command {
                Some(Command::Ls(a))
                | Some(Command::Session(SessionArgs {
                    command: SessionCommand::List(a),
                })) => a,
                _ => panic!("expected an ls command for {args:?}"),
            }
        };

        for spelling in [
            ["min", "session", "list"].as_slice(),
            ["min", "session", "ls"].as_slice(),
            ["min", "ls"].as_slice(),
        ] {
            let a = ls_args(spelling);
            assert!(
                !a.raw && !a.json,
                "{spelling:?} must default both flags off"
            );
        }

        // `--raw`/`--json` are accepted on the canonical and the bare form alike.
        let canonical = ls_args(&["min", "session", "list", "--raw"]);
        assert!(canonical.raw && !canonical.json);
        let bare = ls_args(&["min", "ls", "--json"]);
        assert!(bare.json && !bare.raw);
    }

    /// `setup-zed` takes the session the way every other session verb does —
    /// `min session <verb> <session>`. The project path is not an option: it is
    /// always the in-box workspace root.
    #[test]
    fn setup_zed_parses_as_a_session_verb() {
        use clap::Parser as _;
        let setup_zed_args = |args: &[&str]| -> SetupZedArgs {
            match Cli::try_parse_from(args).unwrap().command {
                Some(Command::Session(SessionArgs {
                    command: SessionCommand::SetupZed(a),
                })) => a,
                _ => panic!("expected a setup-zed command for {args:?}"),
            }
        };

        let args = setup_zed_args(&["min", "session", "setup-zed", "my-box"]);
        assert_eq!(args.session, "my-box");
        assert!(!args.print);
        assert!(args.settings.is_none());

        let printing = setup_zed_args(&["min", "session", "setup-zed", "my-box", "--print"]);
        assert!(printing.print);

        // The project path is fixed, so there is no flag to set it.
        assert!(
            Cli::try_parse_from([
                "min",
                "session",
                "setup-zed",
                "my-box",
                "--path",
                "/elsewhere"
            ])
            .is_err(),
            "--path must not be accepted"
        );
    }

    /// Hidden for now: absent from `min session --help` and from the
    /// completions clap generates, while still parsing and running.
    #[test]
    fn setup_zed_is_hidden() {
        use clap::CommandFactory as _;
        let cli = Cli::command();
        let session = cli.find_subcommand("session").expect("session subcommand");
        let setup_zed = session
            .find_subcommand("setup-zed")
            .expect("setup-zed subcommand");
        assert!(setup_zed.is_hide_set(), "setup-zed must stay hidden");
        // The visible siblings are unaffected.
        assert!(!session.find_subcommand("attach").unwrap().is_hide_set());
    }

    /// `--raw` and `--json` select mutually exclusive output formats, so
    /// passing both must be rejected rather than silently letting one win.
    #[test]
    fn ls_raw_and_json_conflict() {
        use clap::Parser as _;
        assert!(Cli::try_parse_from(["min", "ls", "--raw", "--json"]).is_err());
    }

    /// `repo_dir` and `minimal_dir` are global, so they must be accepted after
    /// the subcommand — not just before it (#1039).
    #[test]
    fn repo_and_minimal_dir_are_accepted_after_the_subcommand() {
        use clap::Parser as _;
        let cli =
            Cli::try_parse_from(["min", "ls", "-C", "/tmp/x", "--minimal-dir", "/tmp/y"]).unwrap();
        let p = std::path::Path::new;
        assert_eq!(cli.global_args.repo_dir.as_deref(), Some(p("/tmp/x")));
        assert_eq!(cli.global_args.minimal_dir.as_deref(), Some(p("/tmp/y")));
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

        // --force skips the confirm on either target: --all, or — since the
        // single-session confirm landed — a bare session too.
        assert!(parse(&["min", "session", "destroy", "--all", "--force"]).is_ok());
        assert!(parse(&["min", "session", "destroy", "web", "--force"]).is_ok());
        assert!(parse(&["min", "session", "destroy", "web", "-f"]).is_ok());
        // ... but never stands in for the required target.
        assert!(parse(&["min", "session", "destroy", "-f"]).is_err());
    }

    /// The single-session destroy gate is dirty-only: `--force` and a
    /// proven-clean session proceed promptless in every mode (including
    /// headless); dirty and unknowable states prompt interactively and
    /// refuse headless, naming `--force` — EOF must never read as consent.
    #[test]
    fn destroy_gate_fires_only_for_dirty_or_unknowable_state() {
        let dirty = || AtRiskState::Dirty(vec!["1 file with uncommitted changes:".to_string()]);

        // --force proceeds promptless regardless of state or mode.
        for state in [AtRiskState::Clean, dirty(), AtRiskState::Unknowable] {
            assert_eq!(
                destroy_gate(true, &state, true, false).unwrap(),
                DestroyGate::Proceed
            );
        }

        // Proven clean proceeds without --force — even headless.
        for (no_input, tty) in [(false, true), (true, true), (false, false)] {
            assert_eq!(
                destroy_gate(false, &AtRiskState::Clean, no_input, tty).unwrap(),
                DestroyGate::Proceed
            );
        }

        // Dirty and unknowable prompt interactively...
        assert_eq!(
            destroy_gate(false, &dirty(), false, true).unwrap(),
            DestroyGate::Confirm
        );
        assert_eq!(
            destroy_gate(false, &AtRiskState::Unknowable, false, true).unwrap(),
            DestroyGate::Confirm
        );

        // ...and refuse headless (no tty, or --no-input), naming --force.
        for state in [dirty(), AtRiskState::Unknowable] {
            for (no_input, tty) in [(true, true), (false, false), (true, false)] {
                let err = destroy_gate(false, &state, no_input, tty)
                    .expect_err("headless without --force must refuse")
                    .to_string();
                assert!(err.contains("--force"), "error must name --force: {err}");
            }
        }
    }

    /// Classification of the daemon's at-risk report: proven-clean VCS
    /// state and an empty activation delta are `Clean`; uncommitted or
    /// unpushed work is `Dirty` with truthful headers; the fallback header
    /// admits it may include committed work; absent or `Unavailable`
    /// responses are `Unknowable`.
    #[test]
    fn assess_at_risk_classifies_clean_dirty_and_unknowable() {
        use minimald_rpc::SessionDeltaResponse as R;

        assert_eq!(assess_at_risk(None), AtRiskState::Unknowable);
        assert_eq!(
            assess_at_risk(Some(R::Unavailable)),
            AtRiskState::Unknowable
        );

        // Committed and pushed: proven clean.
        assert_eq!(
            assess_at_risk(Some(R::Vcs {
                uncommitted: vec![],
                unpushed_commits: 0
            })),
            AtRiskState::Clean
        );
        // Nothing changed since activation: clean in fallback mode too.
        assert_eq!(
            assess_at_risk(Some(R::ChangedSinceActivation { rows: vec![] })),
            AtRiskState::Clean
        );

        // Uncommitted files and unpushed commits both render.
        let lines = match assess_at_risk(Some(R::Vcs {
            uncommitted: vec!["M src/main.rs".to_string(), "A notes.md".to_string()],
            unpushed_commits: 2,
        })) {
            AtRiskState::Dirty(lines) => lines,
            other => panic!("expected Dirty, got {other:?}"),
        };
        assert_eq!(lines[0], "2 files with uncommitted changes:");
        assert!(lines.contains(&"  M src/main.rs".to_string()), "{lines:?}");
        assert_eq!(
            lines.last().unwrap(),
            "2 commits not pushed to any remote",
            "{lines:?}"
        );

        // Unpushed commits alone still gate, without a files header.
        let lines = match assess_at_risk(Some(R::Vcs {
            uncommitted: vec![],
            unpushed_commits: 1,
        })) {
            AtRiskState::Dirty(lines) => lines,
            other => panic!("expected Dirty, got {other:?}"),
        };
        assert_eq!(lines, vec!["1 commit not pushed to any remote".to_string()]);

        // The fallback header must not over-claim.
        let lines = match assess_at_risk(Some(R::ChangedSinceActivation {
            rows: vec!["A scratch.txt".to_string()],
        })) {
            AtRiskState::Dirty(lines) => lines,
            other => panic!("expected Dirty, got {other:?}"),
        };
        assert_eq!(
            lines,
            vec![
                "1 file differs from activation (may include committed work):".to_string(),
                "  A scratch.txt".to_string(),
            ]
        );
    }

    /// `min task run <task>` parses with `--keep` off by default; the flag
    /// and the optional path positional are accepted in any order.
    #[test]
    fn task_run_parses_task_keep_and_path() {
        use clap::Parser as _;
        let run_args = |args: &[&str]| -> TaskRunArgs {
            match Cli::try_parse_from(args).unwrap().command {
                Some(Command::Task(TaskArgs {
                    command: TaskCommand::Run(a),
                })) => a,
                _ => panic!("expected `task run` for {args:?}"),
            }
        };

        let a = run_args(&["min", "task", "run", "build"]);
        assert_eq!(a.task, "build");
        assert!(!a.keep);
        assert!(a.path.is_none());

        let a = run_args(&["min", "task", "run", "build", "--keep"]);
        assert!(a.keep);

        let a = run_args(&["min", "task", "run", "--keep", "build", "sub/dir"]);
        assert_eq!(a.task, "build");
        assert_eq!(a.path.as_deref(), Some("sub/dir"));
        assert!(a.keep);

        // The task name is required.
        assert!(Cli::try_parse_from(["min", "task", "run"]).is_err());
        assert!(Cli::try_parse_from(["min", "task"]).is_err());
    }

    /// The hidden top-level `run` swallows any spelling — flags included —
    /// so every muscle-memory invocation reaches the redirect error rather
    /// than a clap parse error; and it stays hidden from help.
    #[test]
    fn hidden_run_swallows_any_spelling_and_stays_hidden() {
        use clap::CommandFactory as _;
        use clap::Parser as _;

        match Cli::try_parse_from(["min", "run", "build", "--keep"])
            .unwrap()
            .command
        {
            Some(Command::Run(a)) => assert_eq!(a.rest, ["build", "--keep"]),
            _ => panic!("expected the hidden run catch"),
        }
        // A bare `min run` parses too; the redirect copy handles it.
        match Cli::try_parse_from(["min", "run"]).unwrap().command {
            Some(Command::Run(a)) => assert!(a.rest.is_empty()),
            _ => panic!("expected the hidden run catch"),
        }

        let cmd = Cli::command();
        let run = cmd
            .find_subcommand("run")
            .expect("the run subcommand must exist");
        assert!(run.is_hide_set(), "`min run` must stay hidden from help");
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
