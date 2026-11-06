//! `clap` argument definitions for the `min` CLI.

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
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

/// Retired top-level verbs, each with the tip naming what replaced it.
const RETIRED_COMMANDS: &[(&str, &str)] = &[(
    "ssh-forward",
    "`min ssh-forward` was removed: forward a box port with \
     `min net forward <SESSION> <LOCAL>:<PORT>`",
)];

/// Adds a tip naming the replacement when `err` refuses a retired verb. The
/// parser still refuses the verb, with its usage; the tip says where it went.
pub fn with_retired_command_hint(mut err: clap::Error) -> clap::Error {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if err.kind() != ErrorKind::InvalidSubcommand {
        return err;
    }
    let tip = match err.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(verb)) => RETIRED_COMMANDS
            .iter()
            .find(|(retired, _)| *retired == verb.as_str())
            .map(|(_, tip)| tip),
        _ => None,
    };
    if let Some(tip) = tip {
        err.insert(
            ContextKind::Suggested,
            ContextValue::StyledStrs(vec![(*tip).to_owned().into()]),
        );
    }
    err
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
    /// Box subcommands: show what a box will get
    Box(BoxArgs),
    /// Host subcommands: the daemons on this machine that run boxes
    #[command(visible_alias = "hosts")]
    Host(HostArgs),
    /// Provider subcommands: the kinds of local host this machine runs
    #[command(visible_alias = "providers")]
    Provider(ProviderArgs),
    /// Finish the install on this host: every privileged step it still needs, in one run (`--show` names them, `--show --script` prints the script, `--undo` removes them)
    FinalizeInstall(FinalizeInstallArgs),
    /// Muscle-memory catch for the in-box `min run <task>`: always errors,
    /// naming the canonical `min task run <task>` (host) and
    /// `min session attach --command 'min task run <task>'` (in-box) forms.
    #[command(hide = true)]
    Run(RunArgs),
    /// Print important directories and file paths for debugging
    Dirs,
    /// Check this host for problems: today, that no record of the audit log
    /// was changed or removed
    ///
    /// Exits 0 when the audit log verifies or audit files are missing, and 6
    /// when a record was changed or removed.
    // BEP-049: whole-log verification of the audit chain is a `min doctor`
    // check, never a `min box audit` flag.
    Doctor,
    /// Collect a diagnostic bundle (logs, state, config) to send to the
    /// minimal dev team.
    ///
    /// Writes `minimal-diag-<timestamp>.tar.zst` to the current directory.
    /// Secret-shaped values (env vars, tokens) are redacted and session/
    /// project file contents are never included — only name/size listings.
    /// Works even when no daemon is running; never starts one.
    ///
    /// The same command as `min diag collect`, kept under its own name
    /// because it is what everyone already types and what every bug report
    /// asks for.
    Bug(diag::BugArgs),
    /// Collect diagnostic bundles and send them for diagnosis
    Diag(diag::DiagArgs),
    /// WireGuard mesh: join, leave, and inspect remote-access state
    #[cfg(feature = "remote-access")]
    Mesh(MeshArgs),
    /// Proxy stdio to a daemon UDS socket (used as an SSH ProxyCommand).
    #[command(hide = true)]
    Proxy(ProxyArgs),
    /// Sign in to GitHub, and show the sign-in that boxes use
    Auth(AuthArgs),
    /// Store, list and remove the secrets that boxes reference by name
    Secret(SecretArgs),
    // NET-109: `min login` is the alias for `min auth login`, so it takes
    // the same arguments and runs the same sign-in.
    /// Sign in to GitHub (the same as min auth login)
    ///
    /// Opens GitHub in your browser. With `--device`, or in a build with no
    /// browser sign-in, prints a code to enter at github.com instead. The
    /// token is kept in the host keychain and never written to a file.
    Login(AuthLoginArgs),
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
    /// on Ctrl-C, whichever comes first. Debug builds only.
    #[cfg(debug_assertions)]
    #[command(hide = true)]
    Spin(SpinArgs),
    /// Print the privileged command that installs this host's resolver,
    /// local range and box-name service (development aid).
    ///
    /// The command a session start's advisory prints, rendered without a
    /// daemon, so the service install can be tested on a host that cannot
    /// boot a VM. Debug builds only.
    #[cfg(debug_assertions)]
    #[command(name = "debug-answerer-command", hide = true)]
    DebugAnswererCommand,
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
    /// Print the effective networking policy for a session, as text or as
    /// one JSON document (`-o json`)
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
    /// Session identifier (UUID, unique id prefix, or session name)
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
    /// Session identifier (UUID, unique id prefix, or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Emit the raw JSON the daemon returned instead of a table
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Session identifier (UUID, unique id prefix, or session name).
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
    /// Session identifier (UUID, unique id prefix, or session name).
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Name of a task declared in the session project's minimal.toml
    pub task: String,
}

#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Session identifier (UUID, unique id prefix, or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Write one JSON document instead of text (the default)
    #[arg(short = 'o', long = "output", value_enum)]
    pub output: Option<PolicyOutputFormat>,
}

/// The rendering `min session policy` writes. One value today — `json`, the
/// machine-readable shape — beside the text default; an `output` enum rather
/// than a bare `--json` flag so a second format lands beside the first
/// instead of accreting flags.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum PolicyOutputFormat {
    /// One JSON document, `min/v1/session-policy`, with each live mapping's
    /// `pending` state carried
    Json,
}

/// The typed failure a machine-output run fails its walk into: the
/// `code`, `message` and `hint` of the one `min/v1/error` object the CLI's
/// `main` writes on stderr when the run ends non-zero. Keyed on the output
/// mode rather than on any one command — every command that takes `-o json`
/// fails into this, and `main`'s single machine-mode error emitter (keyed
/// the same way, in `main.rs`, shared by all of them) is the only thing
/// that turns one into bytes — so the next command that takes `-o json`
/// calls the mechanism directly: its walk names the failure kinds it can
/// tell apart and fails into this payload, with no sentinel of its own.
///
/// [`std::error::Error`] so the failure can ride the `anyhow` chain across
/// the library boundary to `main`, the way the task-status type does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineModeFailure {
    /// The failure's kind: a name a script branches on — the
    /// architecture's codes, `not_found` for a missing thing (with the
    /// kind of thing that was missing in the message and the hint),
    /// `daemon_unreachable`, `policy_unavailable` — never a single
    /// command's own spelling.
    code: &'static str,
    message: String,
    hint: String,
}

impl MachineModeFailure {
    /// One failure, from the three parts the error object carries.
    #[must_use]
    pub fn new(code: &'static str, message: String, hint: String) -> Self {
        Self {
            code,
            message,
            hint,
        }
    }

    /// The failure's kind — the `code` of the error object.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The message beside it: the same chain the text mode's error line
    /// carries.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The hint beside them: one line naming what to do about the failure,
    /// or the kind of thing that was missing.
    #[must_use]
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// The failure with an old-spelling hint added to its `hint` field, so
    /// the error object carries it and no separate line prints (BCLI-042).
    #[must_use]
    pub fn with_alias_hint(mut self, alias_hint: &str) -> Self {
        self.hint = if self.hint.is_empty() {
            alias_hint.to_owned()
        } else {
            format!("{}. {alias_hint}", self.hint)
        };
        self
    }
}

impl std::fmt::Display for MachineModeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the machine-mode error object on stderr says why: {} ({})",
            self.message, self.code
        )
    }
}

impl std::error::Error for MachineModeFailure {}

/// The context a machine-output command puts on a failure to write its own
/// document to stdout, so the machine-mode error path can tell that failure
/// (`output_failed`) from any other I/O error the run met on the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputWriteError;

impl std::fmt::Display for OutputWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to write the document to stdout")
    }
}

#[derive(Debug, Args)]
pub struct BoxArgs {
    #[command(subcommand)]
    pub command: BoxCommand,
}

#[derive(Debug, Subcommand)]
pub enum BoxCommand {
    /// Show how a project's box reaches GitHub through the local proxy:
    /// the proxy's root certificate fingerprint, each secret with its hosts,
    /// the steering mode and the UDP 443 stance
    Spec(BoxSpecArgs),
    /// Show what the local proxy recorded for one box: each request it
    /// admitted or refused, each secret minted for the box, and the box's
    /// revocation. A removed box's records stay readable by its id
    Audit(BoxAuditArgs),
    /// List the boxes of the current project, in any state: their id,
    /// name, type, parent, project and state, with how a stopped or exited
    /// box ended, and the provider and host each box runs on. `--all`
    /// lists the boxes of every project
    List(BoxListArgs),
    /// Show one box: its id, name, type, parent, project, state, how it
    /// ended, the identity it runs under, and its provider and host
    Show(BoxShowArgs),
    /// Stop a running box and keep it: its record, its events and its
    /// files stay until `min box rm` removes them. `--force` kills every
    /// process in the box at once, with no grace period
    Stop(BoxStopArgs),
    /// Remove a stopped or exited box: its record, its events and its
    /// files. A running box is refused unless `--force` is given, which
    /// stops the box at once and then removes it
    Rm(BoxRmArgs),
    /// Attach this terminal to a box's terminal. With no box named, attach
    /// to this project's running box that has a terminal, else to its only
    /// stopped or exited one, which starts again
    Attach(BoxAttachArgs),
    /// Run a command in a running box and exit with the command's exit
    /// code. `-t` gives the command a terminal, and `--detach` starts it
    /// and returns its exec id
    Exec(BoxExecArgs),
    /// Show what happened to a box: each event the daemon recorded for
    /// it, such as its creation, each start and stop, each exec and its
    /// exit, oldest first. A stopped or exited box keeps its events until
    /// `min box rm` removes it
    Events(BoxEventsArgs),
    /// Copy a file out of a box to this machine. A stopped or exited box
    /// keeps its files, so a copy from it works too
    Cp(BoxCpArgs),
    /// Give a box a new name. The box keeps its id, its state and its
    /// files. A name that a running box on the same host holds is refused
    Rename(BoxRenameArgs),
    /// Remove every stopped or exited box: its record, its events and its
    /// files. A running box is never removed. `--older-than` and `--parent`
    /// narrow what is removed. Off a terminal, `--yes` is required
    Prune(BoxPruneArgs),
}

// BOX-162 (BCLI-016): `min box events <box> | --parent <box> [-o jsonl] [--follow]`.
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("box_or_parent").required(true).args(["target", "parent"])))]
pub struct BoxEventsArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: Option<String>,
    /// Show the events of every child box of this box together, in time
    /// order, each event naming its box
    #[arg(long, value_name = "BOX")]
    pub parent: Option<String>,
    /// Write each event as one JSON object on its own line
    #[arg(short = 'o', long = "output", value_enum)]
    pub output: Option<BoxEventsOutputFormat>,
    /// Show the events so far, then keep showing new events as they
    /// happen, until the box is removed or the command is interrupted
    #[arg(short = 'f', long)]
    pub follow: bool,
}

/// The rendering `min box events` writes, beside the text default.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum BoxEventsOutputFormat {
    /// One JSON object for each event
    Jsonl,
}

// BOX-017 (BCLI-062): `min box cp <box>:<path> <local>`.
#[derive(Debug, Args)]
pub struct BoxCpArgs {
    /// The file to copy, as `<box>:<path>`. `<box>` is the box's id, the
    /// start of its id, or its name. A relative `<path>` is in the box's
    /// home directory, and `/workbench/<path>` is in its copy of the project
    #[arg(value_name = "BOX:PATH")]
    pub source: String,
    /// Where to write the file on this machine. An existing directory
    /// receives the file under its own name
    #[arg(value_name = "LOCAL")]
    pub destination: PathBuf,
}

#[derive(Debug, Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: HostCommand,
}

#[derive(Debug, Subcommand)]
pub enum HostCommand {
    /// List the local hosts: each daemon on this machine that runs boxes,
    /// with its provider and whether it is running
    #[command(visible_alias = "ls")]
    List,
    /// Show one local host: its provider, whether it is running, the socket
    /// `min` connects to and the daemon version
    Show(HostShowArgs),
    /// Stop each running box on a local host, then its daemon, and its VM
    /// on a VM host
    Stop(HostStopArgs),
}

// BCLI-048: `min host show <host>`.
#[derive(Debug, Args)]
pub struct HostShowArgs {
    /// The host, as `min host list` prints it (`local0`, `local-minvmd0`)
    pub host: String,
}

// BCLI-049: `min host stop <host> [--force]`.
#[derive(Debug, Args)]
pub struct HostStopArgs {
    /// The host, as `min host list` prints it (`local0`, `local-minvmd0`)
    pub host: String,
    /// Force-stop each box, and stop the daemon without waiting for it to
    /// shut down cleanly. On a VM host, the VM is stopped from this machine
    #[arg(long, short, default_value_t = false)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProviderArgs {
    #[command(subcommand)]
    pub command: ProviderCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProviderCommand {
    /// List the provider this command selects, with its hosts. `--all`
    /// lists every local provider on this machine
    #[command(visible_alias = "ls")]
    List(ProviderListArgs),
}

// BCLI-052: `min provider list [--all]`.
#[derive(Debug, Args)]
pub struct ProviderListArgs {
    /// List every local provider on this machine, not only the one this
    /// command selects
    #[arg(long)]
    pub all: bool,
}

// BOX-158 (BCLI-001, BCLI-051): `min box list [--all] [-o json]`.
#[derive(Debug, Args)]
pub struct BoxListArgs {
    /// List the boxes of every project, not only the boxes of the current
    /// project
    #[arg(long)]
    pub all: bool,
    /// Write the boxes as a JSON array, one object for each box, and
    /// nothing else
    #[arg(short = 'o', long = "output", value_enum)]
    pub output: Option<BoxListOutputFormat>,
}

/// The rendering `min box list` writes, beside the table default.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum BoxListOutputFormat {
    /// One JSON array of box objects
    Json,
}

// BOX-159 (BCLI-003): `min box show <box>`.
#[derive(Debug, Args)]
pub struct BoxShowArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: String,
}

// BOX-013 (BCLI-059): `min box stop <box> [--force]`.
#[derive(Debug, Args)]
pub struct BoxStopArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: String,
    /// Kill every process in the box at once, with no grace period
    #[arg(long)]
    pub force: bool,
}

// BCLI-068: `min box attach [<box>] [--exec <id>]`.
#[derive(Debug, Args)]
pub struct BoxAttachArgs {
    /// The box: its id, the start of its id, its name, or
    /// provider/host/name, as `min box list` prints them. Omit it to attach
    /// to this project's box
    pub target: Option<String>,
    /// Attach to a command that `min box exec -t` started in the box, by the
    /// exec id it printed. Needs a box
    #[arg(long = "exec", value_name = "EXEC_ID", requires = "target")]
    pub exec: Option<String>,
}

// BOX-019 (BCLI-060, BCLI-004): `min box rm <box> [--force]`.
#[derive(Debug, Args)]
pub struct BoxRmArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: String,
    /// Remove a running box too: stop it at once, then remove it
    #[arg(long)]
    pub force: bool,
}

// BOX-149 (BCLI-053): `min box exec <box> [-t|--detach] [--timeout <d>] -- <cmd>`.
#[derive(Debug, Args)]
pub struct BoxExecArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: String,
    /// Give the command a terminal and connect this terminal to it. The
    /// command's exec id is printed on stderr
    #[arg(short = 't', long = "tty", conflicts_with = "detach")]
    pub tty: bool,
    /// Start the command and return at once. Only the command's exec id is
    /// printed, on stdout
    #[arg(long)]
    pub detach: bool,
    /// Stop the command when it runs for longer than this: a number of
    /// seconds, or a number followed by s, m or h, such as 30s, 5m or 1h.
    /// The command then ends with exit code 124
    #[arg(long, value_name = "DURATION", value_parser = parse_exec_timeout)]
    pub timeout: Option<u64>,
    /// The command and its arguments, after `--`. The command runs as these
    /// words, with no shell
    #[arg(last = true, required = true, num_args = 1.., value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// Reads a `min box exec --timeout` value as whole seconds: a number of
/// seconds, or a number followed by `s`, `m` or `h`. Zero is refused, as the
/// daemon refuses a timeout of zero seconds (BOX-149).
pub(crate) fn parse_exec_timeout(raw: &str) -> Result<u64, String> {
    let refused = || {
        format!(
            "'{raw}' is not a timeout. Give a whole number of seconds, minutes or hours \
             that is more than zero, such as 30s, 5m or 1h."
        )
    };
    let (digits, scale) = match raw.char_indices().last() {
        Some((at, 's')) => (&raw[..at], 1),
        Some((at, 'm')) => (&raw[..at], 60),
        Some((at, 'h')) => (&raw[..at], 3600),
        _ => (raw, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }
    let count: u64 = digits.parse().map_err(|_| refused())?;
    match count.checked_mul(scale) {
        Some(secs) if secs > 0 => Ok(secs),
        _ => Err(refused()),
    }
}

/// Why `min box exec` ran no command in the box: `-t` without a terminal
/// (exit 2), the box is not running (BOX-149, exit 2), or its spec turns
/// exec off (BOX-153, exit 5). `target` is the box as the user named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxExecRefusal {
    /// `-t` ran with a stdin that is not a terminal, so nothing started.
    /// Exit 2.
    NoTerminal {
        /// The box as the user named it.
        target: String,
    },
    /// The box is not running. Exit 2.
    NotRunning {
        /// The box as the user named it.
        target: String,
        /// The box's state as its host names it, such as `stopped`.
        state: String,
    },
    /// The box's spec sets `[io] exec_enabled = false`. Exit 5.
    ExecDisabled {
        /// The box as the user named it.
        target: String,
    },
    /// The box's spec cannot be read, so exec stays off. Exit 5.
    SpecUnreadable {
        /// The box as the user named it.
        target: String,
    },
}

impl BoxExecRefusal {
    /// The exit code `min box exec` ends with on this refusal, from the
    /// architecture's exit-code table: 2 for the state, 5 for the spec.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoTerminal { .. } | Self::NotRunning { .. } => 2,
            Self::ExecDisabled { .. } | Self::SpecUnreadable { .. } => 5,
        }
    }

    /// The outcome the command's tracing event records.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::NoTerminal { .. } => "no terminal",
            Self::NotRunning { .. } => "not running",
            Self::ExecDisabled { .. } => "exec disabled",
            Self::SpecUnreadable { .. } => "spec unreadable",
        }
    }
}

impl std::fmt::Display for BoxExecRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTerminal { target } => write!(
                f,
                "Did not run the command in {target}: -t needs a terminal. \
                 Stdin is not a terminal. Run `min box exec {target} -- <command>` \
                 without -t, or run it from a terminal."
            ),
            // BOX-149, BCLI-053: the refusal names the box's state.
            Self::NotRunning { target, state } => write!(
                f,
                "{target} is {state}. Only a running box can run a command."
            ),
            Self::ExecDisabled { target } => write!(
                f,
                "{target} does not allow exec (its spec sets [io] exec_enabled = false)."
            ),
            Self::SpecUnreadable { target } => write!(
                f,
                "{target} does not allow exec: its spec cannot be read, so exec stays off."
            ),
        }
    }
}

impl std::error::Error for BoxExecRefusal {}

/// A command in a box that ran past its own timeout and was stopped
/// (BOX-149, BCLI-053). `min box exec` and the wait for an exec end with
/// exit 124 on it, and a machine-mode run answers it with `code =
/// "timeout"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxExecTimedOut {
    message: String,
    hint: String,
}

impl BoxExecTimedOut {
    /// The exit code, as `timeout(1)` gives it.
    pub const EXIT_CODE: u8 = 124;

    /// The `code` of the machine-mode error object.
    pub const CODE: &'static str = "timeout";

    /// The command `min box exec` ran in `target` with `--timeout`, after
    /// `secs` seconds.
    #[must_use]
    pub fn exec(target: &str, secs: u64) -> Self {
        Self {
            message: format!(
                "The command in {target} ran for longer than its timeout of {secs}s and was stopped."
            ),
            hint: "Run the command again with a longer --timeout.".to_string(),
        }
    }

    /// The exec `exec_id` in `target`, as a wait for it found it.
    #[must_use]
    pub fn waited(target: &str, exec_id: &str) -> Self {
        Self {
            message: format!(
                "Exec {exec_id} in {target} ran for longer than its timeout and was stopped."
            ),
            hint: String::new(),
        }
    }

    /// The hint of the machine-mode error object.
    #[must_use]
    pub fn hint(&self) -> &str {
        &self.hint
    }
}

impl std::fmt::Display for BoxExecTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BoxExecTimedOut {}

// BOX-010 (BCLI-058): `min box rename <box> <name>`.
#[derive(Debug, Args)]
pub struct BoxRenameArgs {
    /// The box: its id, the start of its id, or its name, as `min box list`
    /// prints them
    pub target: String,
    /// The new name for the box
    pub new_name: String,
}

// BOX-021 (BCLI-061, BCLI-005): `min box prune [--older-than <d>]
// [--parent <box>] [--yes]`.
#[derive(Debug, Args)]
pub struct BoxPruneArgs {
    /// Remove only the boxes that stopped or exited at least this long ago.
    /// Takes a whole number of days, hours, minutes or seconds, such as
    /// `7d`, `12h`, `30m` or `90s`
    #[arg(long, value_name = "AGE", value_parser = parse_box_age)]
    pub older_than: Option<std::time::Duration>,
    /// Remove only the child boxes of this box: its id, the start of its
    /// id, or its name
    #[arg(long, value_name = "BOX")]
    pub parent: Option<String>,
    /// Remove the boxes without asking first
    #[arg(long, short)]
    pub yes: bool,
}

/// Parses the `--older-than` age of `min box prune`: a whole number with a
/// `d`, `h`, `m` or `s` unit.
pub(crate) fn parse_box_age(arg: &str) -> Result<std::time::Duration, String> {
    let units: [(char, u64); 4] = [('d', 86_400), ('h', 3_600), ('m', 60), ('s', 1)];
    let invalid = || {
        format!(
            "`{arg}` is not an age. Use a whole number of days, hours, minutes or \
             seconds, such as 7d, 12h, 30m or 90s."
        )
    };
    let unit = arg.chars().last().ok_or_else(invalid)?;
    let (_, scale) = units
        .iter()
        .find(|(suffix, _)| *suffix == unit)
        .ok_or_else(invalid)?;
    let count: u64 = arg[..arg.len() - 1].parse().map_err(|_| invalid())?;
    let secs = count.checked_mul(*scale).ok_or_else(invalid)?;
    Ok(std::time::Duration::from_secs(secs))
}

// BEP-042: `min box audit <box|self> | --parent <box|self> [-o jsonl] [--follow]`.
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("box_or_parent").required(true).args(["target", "parent"])))]
pub struct BoxAuditArgs {
    /// The box: its id, or its name. A name reads the running box of that
    /// name, else the newest box created under it. `self` is the box this
    /// command runs in
    pub target: Option<String>,
    /// Show the records of every child box of this box (an id, a name or
    /// `self`) together, each record naming its box
    #[arg(long, value_name = "BOX")]
    pub parent: Option<String>,
    /// Write each record as one JSON line, as the proxy wrote it
    #[arg(short = 'o', long = "output", value_enum)]
    pub output: Option<BoxAuditOutputFormat>,
    /// Show the records so far, then keep showing new records as the proxy
    /// writes them, until interrupted
    #[arg(long)]
    pub follow: bool,
}

/// The rendering `min box audit` writes, beside the text default.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum BoxAuditOutputFormat {
    /// One JSON object for each record
    Jsonl,
}

#[derive(Debug, Args)]
pub struct BoxSpecArgs {
    /// The project directory whose minimal.toml declares the box
    /// (default: --repo-dir, or the current directory)
    pub path: Option<PathBuf>,
    // The same flag as `min session activate --network`, from the same
    // definition, so the preview is of the box that activation creates.
    #[arg(
        long,
        value_name = NETWORK_VALUE_NAME,
        value_parser = parse_network_mode,
        default_value = NETWORK_DEFAULT,
        help = NETWORK_HELP,
        long_help = NETWORK_LONG_HELP
    )]
    pub network: CliNetworkMode,
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
    /// Run a declared task in a task box
    ///
    /// Creates a box for the project (named `<task>-<n>`), uploads the
    /// project like `min session activate`, runs the task inside it, and
    /// exits with the task's exit code.
    ///
    /// The task runs without a terminal. This command does not pass its stdin
    /// to the task yet. The task's stdout is this command's stdout, and this
    /// command prints its own lines on stderr, beside the task's stderr. So
    /// `min task run query > out.csv` writes only the task's output.
    ///
    /// When the task ends, the box stays with its exit code: see it with
    /// `min box show <task>-<n>` and remove it with `min box rm <task>-<n>`.
    /// Ctrl-C stops the box as `min box stop` does, the box stays, and this
    /// command exits 130. For a task declared with `interactive = true`,
    /// Ctrl-C destroys its box instead. Use `min session attach` for
    /// interactive work.
    Run(TaskRunArgs),
}

#[derive(Debug, Args)]
pub struct TaskRunArgs {
    /// Name of a task declared in the project's minimal.toml
    pub task: String,
    /// Project path. Defaults to the directory set by `-C`/`--repo-dir`,
    /// or the current working directory when neither is given. A named
    /// option rather than a positional so that every positional after the
    /// task name is a task argument, never a project path.
    #[arg(long)]
    pub path: Option<String>,
    /// Arguments to the task, passed through to its declared `args`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    pub args: Vec<String>,
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
#[derive(Debug, Default, Clone, Args)]
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
    /// On Linux, `local` (the default) runs minimald on the host;
    /// `local-minvmd` runs it inside the minvmd microVM. No effect on macOS,
    /// where minvmd is the only backend. `min provider list --all` lists the
    /// providers on this machine.
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
    /// run side by side on one host. Refused on the native `local`
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

    /// Publish `--vm` as this process's VM name so every host dir the
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
#[command(
    // The egress rule flags as one named set, so a declaration that admits
    // no exceptions can conflict with them as a family: `--deny-all-egress`
    // names this group in `conflicts_with`, which is how it comes to
    // conflict with every `--allow-*`/`--deny-*` rule flag at parse without
    // the four rules becoming mutually exclusive with each other — they
    // still combine freely (`multiple`), the way the section they build
    // combines its dimensions. The one place the egress flags appear is
    // `ActivateArgs`, so this is the one shared definition.
    group(
        ArgGroup::new("egress-rules")
            .args(["allow_subnets", "allow_dns_hosts", "allow_protocols", "deny_subnets"])
            .required(false)
            .multiple(true)
    )
)]
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
    // The `--network` flag is shared with `min box spec`, so the two
    // cannot drift: see [`NETWORK_HELP`].
    #[arg(
        long,
        value_name = NETWORK_VALUE_NAME,
        value_parser = parse_network_mode,
        default_value = NETWORK_DEFAULT,
        help = NETWORK_HELP,
        long_help = NETWORK_LONG_HELP
    )]
    pub network: CliNetworkMode,
    /// Static ingress port mapping `EXT:INT[/PROTO]` (PROTO = tcp|udp, default
    /// tcp). Repeatable. Requires `--network own_ip`.
    #[arg(long = "ingress", value_name = "EXT:INT[/PROTO]")]
    pub ingress: Vec<String>,
    /// How the box's requests to publish a port while it runs are decided:
    /// `allow` publishes a port the box asks for with `min net expose` or
    /// listens on inside `--dynamic-range`, `ask` puts each request to the
    /// person attached to the box, and `deny`, the same as leaving the flag
    /// unset, refuses every request. Requires `--network own_ip`.
    #[arg(
        long = "dynamic-ingress",
        value_name = "allow|ask|deny",
        value_parser = parse_dynamic_ingress_mode
    )]
    pub dynamic_ingress: Option<boxes::DynamicIngress>,
    /// Port range `LO-HI`, both ends included, in which
    /// `--dynamic-ingress allow` accepts requests, e.g. `8000-8443`; a
    /// request outside it is refused. Requires `--dynamic-ingress`.
    #[arg(
        long = "dynamic-range",
        value_name = "LO-HI",
        value_parser = parse_dynamic_range,
        requires = "dynamic_ingress"
    )]
    pub dynamic_range: Option<(u16, u16)>,
    /// Allow outbound traffic to this destination subnet, in CIDR form,
    /// e.g. `10.0.0.0/8`. Repeatable. Once any egress flag is given, an
    /// `--allow-subnets` or `--allow-dns-hosts` list that is not given
    /// allows nothing, unless the host opts out: `--allow-dns-hosts
    /// github.com` alone reaches no address directly, and `--allow-subnets
    /// 0.0.0.0/0` writes allow-all out. The egress flags are accepted with
    /// `--network own_ip` and `--network host_ip`, and only `own_ip`
    /// enforces these rules: a `host_ip` box is refused at creation or, on
    /// a host that cannot filter it, runs with the rules unenforced.
    /// `--network none` rejects every egress flag. `min session policy`
    /// shows the rules a box ended up with.
    #[arg(long = "allow-subnets", value_name = "CIDR")]
    pub allow_subnets: Vec<String>,
    /// Allow outbound traffic to this DNS hostname, e.g. `github.com`.
    /// Repeatable. Given without `--allow-subnets`, the box reaches the
    /// named hosts by name and no address directly; see `--allow-subnets`.
    #[arg(long = "allow-dns-hosts", value_name = "HOST")]
    pub allow_dns_hosts: Vec<String>,
    /// Allow this outbound transport protocol: tcp, udp, or icmp.
    /// Repeatable; unset allows every protocol. Narrows what the other
    /// allow flags admit and admits nothing on its own.
    #[arg(long = "allow-protocols", value_name = "PROTO")]
    pub allow_protocols: Vec<String>,
    /// Deny outbound traffic to this destination subnet, in CIDR form,
    /// subtracted from what the allow flags admit. Repeatable; unset
    /// denies nothing.
    #[arg(long = "deny-subnets", value_name = "CIDR")]
    pub deny_subnets: Vec<String>,
    /// Declare deny-all egress: the box reaches no external address.
    /// Cannot be combined with the `--allow-*` or `--deny-subnets` flags.
    /// Unless the host opts out, a `--network own_ip` box with no egress
    /// rules already gets this by default. With `--network host_ip` it is
    /// enforced only on a host that can filter each box.
    #[arg(long = "deny-all-egress", conflicts_with = "egress-rules")]
    pub deny_all_egress: bool,
    /// Let the box reach the Box Egress Proxy, whatever its
    /// `--allow-*`/`--deny-*` rules say. Without this flag, everything the
    /// box sends to the proxy's address is dropped. Takes effect with
    /// `--network own_ip`, and with `--network host_ip` on a host that runs
    /// boxes in a VM.
    #[arg(long)]
    pub credentialed_upstream: bool,
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

/// Which daemon backend (box host) serves sessions, as `--provider` names it.
///
/// On Linux the default is the host-native daemon (DM2); `local-minvmd` runs
/// `minimald` inside the minvmd microVM (DM1) instead. On macOS minvmd is the
/// only backend, so the choice has no effect there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    /// Linux: run minimald natively on the host (the default).
    Local,
    /// Run minimald inside the minvmd microVM.
    LocalMinvmd,
    /// The old name of `local`.
    // BCLI-046: read as `local` for one release, with a hint on stderr
    // after the command ends.
    #[value(hide = true)]
    LocalMinimald,
}

/// Configuration for file sync during activation.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SyncMode {
    /// Stream a tarball of your project and unpack it into the session.
    Tarball,
    /// Do not populate the worktree of the session.
    None,
}

/// CLI surface for [`boxes::NetworkMode`]. Parsed by hand in
/// [`parse_network_mode`] rather than derived from a `ValueEnum`: the hand
/// parser is what accepts the legacy hyphenated spellings with a rename hint,
/// which a derived enum cannot, and it keeps the `boxes` crate free of a
/// clap dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliNetworkMode {
    NoNet,
    HostNet,
    OwnIp,
}

/// The `--network` value name, shared by `min session activate` and
/// `min box spec`.
pub(crate) const NETWORK_VALUE_NAME: &str = "none|host_ip|own_ip";

/// The `--network` default, shared by `min session activate` and `min box
/// spec`, so a preview with no flag is of a box created with no flag.
pub(crate) const NETWORK_DEFAULT: &str = "host_ip";

/// The first paragraph of the `--network` help, as a literal so that
/// [`NETWORK_LONG_HELP`] can extend it.
macro_rules! network_help {
    () => {
        "Network mode for the session: `none` gives the session no network (every socket it \
         opens to a destination outside itself fails), `host_ip` shares the host's network \
         namespace (the default), and `own_ip` gives the session its own IP address, so \
         `--ingress` can publish ports; unless the host opts out, an `own_ip` session with no \
         egress rules can reach no external address"
    };
}

/// The `--network` short help, shared by `min session activate` and `min
/// box spec`.
pub(crate) const NETWORK_HELP: &str = network_help!();

/// The `--network` long help: the short help and the legacy spellings.
pub(crate) const NETWORK_LONG_HELP: &str = concat!(
    network_help!(),
    ".\n\n",
    "The hyphenated spellings `no-net`, `host-net`, and `own-ip` are still accepted, but each \
     prints a one-line hint naming the current spelling."
);

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

impl From<CliNetworkMode> for boxes::NetworkMode {
    fn from(m: CliNetworkMode) -> Self {
        match m {
            CliNetworkMode::NoNet => boxes::NetworkMode::NoNet,
            CliNetworkMode::HostNet => boxes::NetworkMode::HostNet,
            CliNetworkMode::OwnIp => boxes::NetworkMode::OwnIp,
        }
    }
}

/// Parse an `--ingress EXT:INT[/PROTO]` spec into a [`boxes::PortMapping`].
/// PROTO defaults to tcp; only tcp/udp are accepted (gvproxy's static forwarder
/// exposes no other transport).
pub(crate) fn parse_ingress_mapping(spec: &str) -> Result<boxes::PortMapping, anyhow::Error> {
    let (ports, proto) = match spec.split_once('/') {
        Some((ports, proto)) => (ports, parse_ingress_proto(proto)?),
        None => (spec, boxes::IpProto::Tcp),
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
    if internal_port == 0 {
        anyhow::bail!(
            "ingress '{spec}': internal port 0 is reserved — choose an internal port >= 1"
        );
    }
    Ok(boxes::PortMapping {
        external_port,
        internal_port,
        proto,
    })
}

pub(crate) fn parse_ingress_proto(proto: &str) -> Result<boxes::IpProto, anyhow::Error> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(boxes::IpProto::Tcp),
        "udp" => Ok(boxes::IpProto::Udp),
        other => Err(anyhow::anyhow!(
            "ingress: unsupported protocol '{other}' (use tcp or udp)"
        )),
    }
}

/// Parse a `--dynamic-ingress <allow|ask|deny>` value (NET-043) into the
/// [`boxes::DynamicIngress`] stance the create request carries. The
/// snake_case spellings are the record's own — the same words
/// `min session policy` prints back — so what a person types to create the
/// box is what they read from it later. `deny` parses the same as an unset
/// flag reads: both are the deny-all default the policy module evaluates
/// them as, but spelling it is still meaningful — it makes the ingress
/// declaration, so `min session policy` shows the resolved row rather than
/// no ingress block at all.
pub(crate) fn parse_dynamic_ingress_mode(raw: &str) -> Result<boxes::DynamicIngress, String> {
    match raw {
        "allow" => Ok(boxes::DynamicIngress::Allow),
        "deny" => Ok(boxes::DynamicIngress::Deny),
        "ask" => Ok(boxes::DynamicIngress::Ask),
        other => Err(format!(
            "dynamic ingress: unknown mode '{other}' (expected allow, ask, or deny)"
        )),
    }
}

/// Parse a `--dynamic-range <lo>-<hi>` value (NET-043) into the inclusive
/// `(lo, hi)` pair the create request's `dynamic_allowed_range` carries.
/// A malformed value (no `-`, a non-numeric end, a port outside u16), an
/// inverted one (`hi` below `lo`), or a privileged one (`lo` below
/// [`boxes::MIN_DYNAMIC_INGRESS_PORT`]) is a create-time error here, at the flag,
/// rather than a daemon-side refusal after the box's directory exists: the
/// user sees what they typed named in the error, with no half-created
/// session behind it.
pub(crate) fn parse_dynamic_range(raw: &str) -> Result<(u16, u16), String> {
    let (lo, hi) = raw
        .split_once('-')
        .ok_or_else(|| format!("dynamic range '{raw}': expected LO-HI (e.g. 8000-8443)"))?;
    let lo = lo
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("dynamic range '{raw}': '{lo}' is not a valid port number"))?;
    let hi = hi
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("dynamic range '{raw}': '{hi}' is not a valid port number"))?;
    if hi < lo {
        return Err(format!(
            "dynamic range '{raw}': the upper end must not be below the lower end"
        ));
    }
    // The launch check's own bound and wording (`validate_policy`), so a
    // privileged range is refused here, at the flag, in the same words.
    if lo < boxes::MIN_DYNAMIC_INGRESS_PORT {
        return Err(format!(
            "dynamic range '{raw}': {}",
            boxes::PolicyError::PrivilegedDynamicRange { lo }
        ));
    }
    Ok((lo, hi))
}

/// Parse an `--allow-protocols <PROTO>` spec into an [`boxes::IpProto`].
/// Egress rules name any transport the policy type carries, so unlike the
/// ingress parser (whose vocabulary is gvproxy's static forwarder's), icmp is
/// accepted here.
pub(crate) fn parse_egress_proto(proto: &str) -> Result<boxes::IpProto, anyhow::Error> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(boxes::IpProto::Tcp),
        "udp" => Ok(boxes::IpProto::Udp),
        "icmp" => Ok(boxes::IpProto::Icmp),
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
    if box_port == 0 {
        anyhow::bail!("forward '{spec}': box port must be 1-65535");
    }
    Ok((local_port, box_port))
}

#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Session identifier (UUID, unique id prefix, or session name). When
    /// omitted, `min session attach` resolves a session from the current
    /// working directory (or the only existing session), and opens an interactive picker if the choice is
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
    /// Session identifier (UUID, unique id prefix, or session name)
    #[arg(add = completion::session_completer())]
    pub session: Option<String>,
    /// Destroy all sessions
    #[arg(long)]
    pub all: bool,
    /// Skip the destroy confirmation, and treat a session that is already destroyed as success
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
    /// Session identifier (UUID, unique id prefix, or session name)
    #[arg(add = completion::session_completer())]
    pub session: String,
    /// Ports to relay, as `<LOCAL>:<PORT>` — the laptop-side listener and
    /// the box-side port it forwards to (`8080:3000` answers on
    /// `localhost:8080` from port 3000 in the box)
    #[arg(value_name = "LOCAL:PORT")]
    pub spec: String,
}

#[derive(Debug, Args)]
pub struct FinalizeInstallArgs {
    /// Name what is missing on this host and run nothing
    #[arg(long)]
    pub show: bool,
    /// With --show, also print the script a run would execute, on stdout
    #[arg(long, requires = "show", conflicts_with = "json")]
    pub script: bool,
    /// With --show, print the report as JSON (schema `min/v1/finalize-install`); exits non-zero while any part is missing
    #[arg(long, requires = "show", conflicts_with = "undo")]
    pub json: bool,
    /// Remove everything the step installed on this host (with --show --script, print the removal script instead)
    #[arg(long)]
    pub undo: bool,
    /// The two contiguous connection-mark bits that egress enforcement uses, in hex (for example 0x0c000000). Use it when another firewall rule already uses the default bits. The boot service keeps the value
    #[arg(
        long,
        value_name = "MASK",
        value_parser = crate::cmd::parse_ct_mark_mask,
        conflicts_with = "undo"
    )]
    pub ct_mark_mask: Option<u32>,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// Force shutdown even if a session is mid-create or still holds a host handle (even a dead one).
    /// On a VM backend whose in-guest daemon does not answer, stops the VM from the host;
    /// data not yet flushed inside the VM can then be lost
    #[arg(long, short, default_value_t = false)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    /// Session identifier (UUID, unique id prefix, or session name)
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
    // BCLI-018: `<entry> --type <type>` appends one entry; each noun flag is
    // the same append with that noun as the type. The flags are checked by
    // hand in `cmd_init`, not with clap conflicts, so a conflict prints the
    // one message the task fixes.
    /// Name of the entry to append to minimal.toml (use with --type)
    #[arg(value_name = "ENTRY")]
    pub entry: Option<String>,
    /// Type of the entry to append: session, task, or a type from [box_types]
    #[arg(long = "type", value_name = "TYPE")]
    pub box_type: Option<String>,
    /// Append a session entry with this name (the same as <ENTRY> --type session)
    #[arg(long, value_name = "NAME")]
    pub session: Option<String>,
    /// Append a task entry with this name (the same as <ENTRY> --type task)
    #[arg(long, value_name = "NAME")]
    pub task: Option<String>,
    /// Append an agent entry with this name (the same as <ENTRY> --type agent)
    #[arg(long, value_name = "NAME")]
    pub agent: Option<String>,
    /// Append a service entry with this name (the same as <ENTRY> --type service)
    #[arg(long, value_name = "NAME")]
    pub service: Option<String>,
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

#[cfg(debug_assertions)]
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
    /// The `min` process this proxy serves (ssh's parent): the proxy exits,
    /// closing the daemon connection, once that process is gone.
    #[arg(long, hide = true)]
    pub owner: Option<u32>,
    /// A file the owner holds an exclusive `flock` on for its lifetime: the
    /// proxy exits the moment it can take that lock, which the kernel
    /// releases on any end of the owner, a SIGKILL included. The pid above
    /// is the fallback where no lock was handed.
    #[arg(long, hide = true)]
    pub owner_lock: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Sign in to GitHub and keep the sign-in in the host keychain
    ///
    /// Opens GitHub in your browser. With `--device`, or in a build with no
    /// browser sign-in, prints a code to enter at github.com instead. The
    /// token is kept in the host keychain and never written to a file.
    Login(AuthLoginArgs),
    /// Show whether you are signed in to GitHub, and when the token expires
    ///
    /// Never prints the token.
    Status,
    /// Sign out of GitHub and remove the sign-in from the host keychain
    ///
    /// Boxes created before the sign-out lose GitHub access at their next
    /// request, and their processes keep running. Also asks GitHub to revoke
    /// the sign-in. A later `min auth login` gives those boxes no access
    /// back.
    Logout,
}

#[derive(Debug, Args)]
pub struct AuthLoginArgs {
    /// Sign in with a code entered at github.com, not in this browser
    #[arg(long)]
    pub device: bool,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store a secret in the host keychain under a name
    ///
    /// Reads the value from the terminal, or from standard input when it is
    /// not a terminal. Prints only the name. Only the Box Egress Proxy reads
    /// the stored value without a prompt.
    Set(SecretSetArgs),
    /// List the stored secrets and the rules that use them
    ///
    /// Never prints a value.
    #[command(alias = "ls")]
    List(SecretListArgs),
    /// Remove a stored secret
    Rm(SecretRmArgs),
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    /// The name that box specs use for the secret
    pub id: String,
    /// The store to keep the secret in (default: the host keychain)
    #[arg(long)]
    pub store: Option<String>,
    // Neither of these fields carries a value into the store: each one is
    // here so that `set` refuses a value given on the command line with its
    // own message (BEP-050), not with a generic usage error.
    #[arg(hide = true)]
    pub value: Option<String>,
    #[arg(long = "env", alias = "from-env", value_name = "VAR", hide = true)]
    pub env: Option<String>,
    /// The host or host:port the secret is sent to; repeat for more than one.
    /// Writes the secret's rule to your config.toml
    #[arg(
        long,
        value_name = "HOST[:PORT]",
        conflicts_with = "preset",
        requires = "form"
    )]
    pub upstream: Vec<String>,
    /// The HTTP header that carries the secret
    #[arg(long, value_name = "NAME", group = "form", requires = "upstream")]
    pub header: Option<String>,
    /// Text sent before the secret in the header, such as "Bearer "
    #[arg(long, value_name = "TEXT", requires = "header")]
    pub prefix: Option<String>,
    /// Send the secret as this basic authentication field: user or password
    #[arg(long, value_name = "FIELD", group = "form", requires = "upstream")]
    pub basic_auth: Option<String>,
    /// Use the upstream and header of a known service: anthropic,
    /// anthropic-api-key, cloudflare, linear or sentry
    #[arg(long, value_name = "NAME", conflicts_with_all = ["header", "prefix", "basic_auth"])]
    pub preset: Option<String>,
    /// Replace a different rule for this secret without asking
    #[arg(long, short)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct SecretListArgs {
    /// The store to list (default: the host keychain)
    #[arg(long)]
    pub store: Option<String>,
}

#[derive(Debug, Args)]
pub struct SecretRmArgs {
    /// The name of the secret to remove
    pub id: String,
    /// The store that holds the secret (default: the host keychain)
    #[arg(long)]
    pub store: Option<String>,
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
