//! `clap` argument definitions for the `min` CLI.

use clap::{ArgGroup, Args, Subcommand};
// Re-exported so the crate-root glob (`pub use cli::*`) keeps `Parser` in scope
// for tests that call `Cli::try_parse_from`, exactly as the old single-module
// layout did.
pub(crate) use clap::Parser;
use clap_complete::Shell;
use std::path::PathBuf;

use crate::completion;
use crate::completions;
use crate::diag;

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
    /// Network subcommands: bring a box's services to the laptop
    Net(NetArgs),
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
    /// Print that there is nothing to mint
    ///
    /// The HTTPS reverse proxy this verb once served is retired, so it
    /// issues nothing and writes nothing to disk. The verb stays as the
    /// future home of the sign-in that replaces it.
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
    /// Re-pin upstream & sideloads to their latest commits (not a self-update)
    ///
    /// Re-pins the project's `[upstream]` link (and any sideloads) in
    /// `minimal.toml` to the current head of each tracking branch, rewriting
    /// `locked_commit`, then refreshes the local checkouts to match. The
    /// standard library is embedded in the `min` binary and is only refreshed
    /// or verified locally — its commit is not re-pinned. This leaves
    /// `minimal.toml` modified in your working tree (a diff to commit),
    /// and the next `min session activate` materializes the new closure, which
    /// can take several minutes on the first activate.
    ///
    /// This does not update the `min` binary itself; reinstall it with the
    /// installer to do that.
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
    /// Run a declared task in an existing session
    ///
    /// The task runs in the named session's context, serviced by the daemon —
    /// the counterpart to `min task run <task>`, which composes a task session
    /// of its own instead of reusing one you already have.
    Run(SessionRunArgs),
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
    ///
    /// A single argument is a shell command, run by the session's shell with
    /// its pipes, globs and `$VAR` intact: `min session exec s 'echo $PWD'`.
    /// Several arguments are an argv, quoted so the session sees exactly the
    /// words you typed: `min session exec s sh -c 'echo A B'`.
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SessionRunArgs {
    /// Session identifier (UUID or session name).
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Name of a task declared in the session project's minimal.toml
    pub task: String,
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
    /// Talk to this named minvmd VM instead of the default one.
    ///
    /// A named VM keeps its own state directory, socket, and in-VM daemon
    /// under a per-name subdirectory of the provider dir, so several VMs can
    /// run side by side on one host. Refused on the native `local-minimald`
    /// backend, which hosts no VMs — named VMs need
    /// `--provider local-minvmd` — and no effect on the default VM's paths
    /// when the name is `default` or omitted.
    #[arg(long, global = true, value_name = "NAME")]
    pub vm: Option<String>,
}

impl GlobalArgs {
    /// Whether the minvmd microVM backend (DM1) is selected via
    /// `--provider local-minvmd`.
    pub fn use_minvmd(&self) -> bool {
        matches!(self.provider, Some(Provider::LocalMinvmd))
    }

    /// Publish `--vm` as this process's VM name so every provider dir the
    /// command resolves — socket, state dir, autospawn — names the same VM
    /// (NET-052). Called once at dispatch, before any path resolution; the
    /// default VM is untouched when the flag is absent (NET-053).
    ///
    /// # Errors
    ///
    /// [`anyhow::Error`] when the name breaks the naming rule
    /// ([`paths::validate_vm_name`]).
    pub fn publish_vm_name(&self) -> anyhow::Result<()> {
        match &self.vm {
            Some(vm) => {
                crate::client::set_vm_name(vm).map_err(|err| anyhow::anyhow!("--vm: {err}"))
            }
            None => Ok(()),
        }
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
    /// Network mode for the session: `none` gives the session no network
    /// (every socket it opens to a destination outside itself fails),
    /// `host_ip` shares the host's network namespace (the default), and
    /// `own_ip` gives the session an IP of its own on the host's switch, so
    /// `--ingress` can publish ports.
    ///
    /// The hyphenated spellings `no-net`, `host-net`, and `own-ip` are still
    /// accepted, but each prints a one-line hint naming the current spelling.
    #[arg(
        long,
        value_name = "none|host_ip|own_ip",
        value_parser = parse_network_mode,
        default_value = "host_ip"
    )]
    pub network: CliNetworkMode,
    /// Static ingress port mapping `EXT:INT[/PROTO]` (PROTO = tcp|udp, default
    /// tcp). Repeatable. Requires `--network own_ip`.
    #[arg(long = "ingress", value_name = "EXT:INT[/PROTO]")]
    pub ingress: Vec<String>,
    /// Allowed destination subnets in CIDR form (`egress.allow_subnets`),
    /// e.g. `10.0.0.0/8`. Repeatable; unset means allow-all subnets. Valid on
    /// an own-address (`--network own_ip`) or host-address
    /// (`--network host_ip`) box; a none box rejects the whole egress
    /// declaration.
    #[arg(long = "allow-subnets", value_name = "CIDR")]
    pub allow_subnets: Vec<String>,
    /// Allowed destination DNS hostnames (`egress.allow_dns_hosts`), e.g.
    /// `github.com`. Repeatable; unset means allow-all hosts.
    #[arg(long = "allow-dns-hosts", value_name = "HOST")]
    pub allow_dns_hosts: Vec<String>,
    /// Allowed outbound transport protocols (`egress.allow_protocols`):
    /// tcp, udp, or icmp. Repeatable; unset means allow all protocols.
    #[arg(long = "allow-protocols", value_name = "PROTO")]
    pub allow_protocols: Vec<String>,
    /// Denied destination subnets in CIDR form (`egress.deny_subnets`),
    /// subtracted from the allowed set. Repeatable; unset means nothing is
    /// denied.
    #[arg(long = "deny-subnets", value_name = "CIDR")]
    pub deny_subnets: Vec<String>,
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

/// CLI surface for [`sessions::NetworkMode`]. Parsed by hand in
/// [`parse_network_mode`] rather than derived from a `ValueEnum`: the hand
/// parser is what accepts the legacy hyphenated spellings with a rename hint,
/// which a derived enum cannot, and it keeps the `sessions` crate free of a
/// clap dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliNetworkMode {
    NoNet,
    HostNet,
    OwnIp,
}

/// Parses the `--network <none|host_ip|own_ip>` value (NET-037). The
/// hyphenated spellings `no-net`, `host-net`, and `own-ip` predate the
/// rename to the underscore forms and still parse to the same modes, each
/// printing a one-line hint naming the current spelling, so scripts and
/// muscle memory keep working through the rename window. Anything else is
/// a clap error.
pub(crate) fn parse_network_mode(raw: &str) -> Result<CliNetworkMode, String> {
    let mode = match raw {
        "none" | "no-net" => CliNetworkMode::NoNet,
        "host_ip" | "host-net" => CliNetworkMode::HostNet,
        "own_ip" | "own-ip" => CliNetworkMode::OwnIp,
        _ => {
            return Err("expected one of none, host_ip, own_ip (the hyphenated \
                 no-net, host-net, own-ip are accepted as legacy spellings)"
                .to_owned());
        }
    };
    if let Some(hint) = legacy_network_hint(raw) {
        eprintln!("{hint}");
    }
    Ok(mode)
}

/// The rename hint for a legacy `--network` spelling: one line naming the
/// spelling typed and the current one. `None` for a current spelling, so
/// only the old forms are announced.
pub(crate) fn legacy_network_hint(raw: &str) -> Option<String> {
    let current = match raw {
        "no-net" => "none",
        "host-net" => "host_ip",
        "own-ip" => "own_ip",
        _ => return None,
    };
    Some(format!(
        "note: --network {raw} still works for one release; \
         the current spelling is --network {current}"
    ))
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
pub(crate) fn parse_ingress_mapping(spec: &str) -> Result<sessions::PortMapping, anyhow::Error> {
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

pub(crate) fn parse_ingress_proto(proto: &str) -> Result<sessions::IpProto, anyhow::Error> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(sessions::IpProto::Tcp),
        "udp" => Ok(sessions::IpProto::Udp),
        other => Err(anyhow::anyhow!(
            "ingress: unsupported protocol '{other}' (use tcp or udp)"
        )),
    }
}

/// Parse an `--allow-protocols <PROTO>` spec into an [`sessions::IpProto`].
/// Egress rules name any transport the policy type carries, so unlike the
/// ingress parser (whose vocabulary is gvproxy's static forwarder's), icmp is
/// accepted here.
pub(crate) fn parse_egress_proto(proto: &str) -> Result<sessions::IpProto, anyhow::Error> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(sessions::IpProto::Tcp),
        "udp" => Ok(sessions::IpProto::Udp),
        "icmp" => Ok(sessions::IpProto::Icmp),
        other => Err(anyhow::anyhow!(
            "egress: unsupported protocol '{other}' (use tcp, udp, or icmp)"
        )),
    }
}

/// Parse a `net forward <LOCAL>:<PORT>` spec into its laptop-side listener
/// port and its box-side target port.
pub(crate) fn parse_forward_spec(spec: &str) -> Result<(u16, u16), anyhow::Error> {
    let (local, port) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("forward '{spec}': expected LOCAL:PORT"))?;
    let local_port = local
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("forward '{spec}': invalid local port '{local}'"))?;
    let box_port = port
        .parse::<u16>()
        .map_err(|_| anyhow::anyhow!("forward '{spec}': invalid box port '{port}'"))?;
    Ok((local_port, box_port))
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
pub struct NetArgs {
    #[command(subcommand)]
    pub command: NetCommand,
}

#[derive(Debug, Subcommand)]
pub enum NetCommand {
    /// Forward a box port to the laptop over the session
    ///
    /// Binds `localhost:<LOCAL>` and relays every accepted connection over
    /// the session's SSH channel to `127.0.0.1:<PORT>` inside the box, so a
    /// service running in the session answers on the laptop with nothing
    /// installed or configured on the remote side. Stays in the foreground
    /// and closes with the session.
    Forward(NetForwardArgs),
}

#[derive(Debug, Args)]
pub struct NetForwardArgs {
    /// Session identifier (UUID or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Ports to relay, as `<LOCAL>:<PORT>` — the laptop-side listener and
    /// the box-side port it forwards to (`8080:3000` answers on
    /// `localhost:8080` from port 3000 in the box)
    #[arg(value_name = "LOCAL:PORT")]
    pub spec: String,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// Force shutdown even if a session is mid-create or still holds a host handle (even a dead one)
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

/// Arguments for `min login`.
#[derive(Debug, Args)]
pub struct LoginArgs {}

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
