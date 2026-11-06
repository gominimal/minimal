//! `min task run <task>`: run a declared project task in an ephemeral
//! session.
//!
//! The activate→exec→end loop as one command: create a session for the
//! project (named `task-<task>-<hex>`), upload the project per the normal
//! activate rules, exec the canonical in-box `min task run <task>` over the
//! native SSH exec channel with the task's output streamed through, exit
//! with the task's exit code, and leave the session's end to the daemon —
//! it owns the box the run created, so it destroys it once the task's exit
//! status is on the wire (NET-131), whether or not this client is still
//! here.
//!
//! Deliberately composed from the same client/RPC primitives `cmd_activate`
//! uses (`BoxConfig`, `CreateSession`, the upload gates,
//! `ConfigureLoadout`, the gating hooks, `FinalizeSession`) rather than
//! refactored out of it: a few duplicated lines of glue keep
//! `cmd_activate`'s diff at zero.

use std::io::{IsTerminal as _, Read as _};

use anyhow::{Context as _, bail};
use tokio::io::AsyncWriteExt as _;
use tracing::Instrument as _;

use crate::{GlobalArgs, RunArgs, TaskRunArgs};

/// A task's non-zero exit status, carried as a typed error so `main.rs` can
/// downcast it and terminate with the task's own code instead of printing an
/// error — the git-remote helper's `ExitCode` precedent. The task's output
/// has already streamed through, so there is nothing left to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskExit(pub u8);

impl std::fmt::Display for TaskExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task exited with status {}", self.0)
    }
}

impl std::error::Error for TaskExit {}

/// Map the bridged exit status to the command result: a reported 0 is
/// success, a reported non-zero becomes the typed [`TaskExit`] main.rs
/// relays as the process exit code, clamped into `u8` the same way the
/// git-remote helper clamps its remote status. A channel that closed
/// WITHOUT reporting a status — a daemon or transport death mid-task —
/// fails closed as an ordinary error (printed to stderr, process exit 1)
/// rather than defaulting to success.
fn exit_outcome(code: Option<u32>) -> Result<(), anyhow::Error> {
    match code {
        Some(0) => Ok(()),
        Some(code) => Err(TaskExit(u8::try_from(code).unwrap_or(1)).into()),
        None => Err(anyhow::anyhow!(
            "task ended without reporting an exit status"
        )),
    }
}

/// The exec request a task run with no spec sends: the task, its declared
/// arguments, plus the owns-box flag (NET-131). The flag is what moves the
/// destroy off this client: the daemon ends the session once the task's
/// exit status is on the wire, whether or not this process is still there.
/// `cwd` is the invocation directory relative to the uploaded tree (see
/// [`task_run_cwd`]), where a task declaring `inherit_cwd` starts.
fn task_run_request(task: &str, args: &[String], cwd: String) -> minimald_rpc::exec::ExecRequest {
    minimald_rpc::exec::ExecRequest::TaskRun {
        task: task.to_string(),
        owns_box: true,
        args: args.to_vec(),
        cwd,
    }
}

/// The exec request of a task run whose task is its box's entrypoint (T43).
/// The daemon starts the entrypoint, relays its output and returns its exit
/// code. The task's arguments ride the entrypoint's argv, not the request,
/// and the run owns no box: the box ends when its entrypoint returns, and
/// keeps its record (BOX-038). `cwd` is as for [`task_run_request`]: the
/// entrypoint starts there, for a task that declares `inherit_cwd`.
fn entrypoint_run_request(task: &str, cwd: &str) -> minimald_rpc::exec::ExecRequest {
    minimald_rpc::exec::ExecRequest::TaskRun {
        task: task.to_string(),
        owns_box: false,
        args: Vec::new(),
        cwd: cwd.to_string(),
    }
}

/// The spec of the task box a run creates (BOX-068): the declared task's
/// spec, with the arguments the user typed after the task name appended to
/// its entrypoint, `min task run <task> <args...>`. `None` for an
/// interactive task, whose type denies a terminal.
fn task_box_spec(
    task: &str,
    declared: &mfile::Task,
    flags: mfile::spec::SpecFlags,
    args: &[String],
) -> Option<mfile::spec::BoxSpec> {
    let mut spec = mfile::spec::BoxSpec::for_task(task, declared, flags)?;
    // `--` ends the in-box run's own options, so an argument such as
    // `--path` reaches the task and not the in-box parser.
    if let mfile::spec::Entrypoint::Exec(argv) = &mut spec.entrypoint
        && !args.is_empty()
    {
        argv.push("--".to_string());
        argv.extend(args.iter().cloned());
    }
    Some(spec)
}

/// Asks the daemon to run the entrypoint of task box `id`, and returns the
/// channel that relays it: the task's output, then its exit code.
/// `task_env` holds the task's variables, resolved against this shell, for
/// the in-box `min task run` to read. `cwd` is where the entrypoint starts,
/// relative to the uploaded tree (see [`task_run_cwd`]). Empty is the root.
pub(crate) async fn open_task_box_run(
    client: &mut crate::client::Client,
    id: boxes::SessionId,
    task: &str,
    cwd: &str,
    task_env: &minimald_rpc::taskenv::TaskEnv,
) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
    client
        .open_session_exec_channel(id, &entrypoint_run_request(task, cwd).encode(), task_env)
        .await
}

/// The invocation directory relative to the upload root, `/`-separated:
/// `sub/inner` for a run started there, empty when the user is at the root.
/// The daemon starts a task that declares `inherit_cwd` at the same place
/// inside the uploaded tree.
fn task_run_cwd(upload_root: &camino::Utf8Path, invocation_dir: &camino::Utf8Path) -> String {
    invocation_dir
        .strip_prefix(upload_root)
        .map(|rel| {
            rel.components()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

/// The hidden top-level `min run` muscle-memory catch: always errors, naming
/// the canonical host spelling and the in-box form.
pub fn cmd_run(args: &RunArgs) -> Result<(), anyhow::Error> {
    bail!(run_alias_message(args.rest.first().map(String::as_str)))
}

/// The redirect copy for the hidden `min run`: substitutes the task name the
/// user typed (when there was one) so both spellings are copy-pasteable.
fn run_alias_message(task: Option<&str>) -> String {
    let task = task.unwrap_or("<task>");
    format!(
        "`min run` runs inside a session. On the host, use:\n\n  \
         min task run {task}\n\n\
         which runs the task in an ephemeral session; or run it in an \
         existing session:\n\n  \
         min session attach --command 'min task run {task}'"
    )
}

/// Look up `task` in the project's `minimal.toml`, walking up from `dir`
/// like the activate config discovery does, and return its declaration.
/// Errors name the fix: untrimmed name → the whitespace rejection; no
/// config → `min init`; unknown task → the declared list.
///
/// The declaration comes back rather than being discarded because the
/// client needs its `env_vars` to resolve them here — see
/// [`resolve_task_env`].
fn declared_task(dir: &camino::Utf8Path, task: &str) -> Result<mfile::Task, anyhow::Error> {
    // Rejected before any lookup: the daemon trims the task name out of the
    // exec command string, so a name with leading/trailing whitespace can
    // never round-trip into the box — even if minimal.toml declares it.
    if task.trim() != task {
        bail!(untrimmed_task_message(task));
    }
    let file = match mfile::File::from_dir_recursive(dir.as_std_path()) {
        Ok(f) => f,
        Err(mfile::Error::NotFound) => bail!(
            "no {name} found at {dir} (or any parent directory); \
             run `min init` to create one",
            name = mfile::MFILE_NAME,
        ),
        Err(e) => bail!(
            "found a broken {name} while resolving tasks: {e}",
            name = mfile::MFILE_NAME,
        ),
    };
    match file.task(task) {
        Some(t) => Ok(t),
        None => bail!(unknown_task_message(&file, task)),
    }
}

/// Resolve a task's declared `env_vars` against the invoking shell, so the
/// values reach the daemon already resolved.
///
/// `{ inherit = true }` means "take this from the invoking process", and
/// the only process that can honour it is this one. The daemon runs
/// elsewhere — on macOS, inside the microVM — so its `std::env::var` reads
/// the daemon's own environment, which the user's `export` never reaches
/// (#585). `[session.vars]` has always resolved here, at activation, which
/// is exactly why the two behaved differently in the same project.
///
/// Literal values are carried too, not just inherited ones: the daemon
/// applies one consistent set rather than resolving half of them itself.
///
/// A variable that is declared `inherit` but unset is refused here, naming
/// the task and the variable, instead of surfacing as the daemon's
/// `failed to spawn process` after a session has already been built.
///
/// # Policy
///
/// Every name goes through [`VarsPolicy::check`] with
/// [`Source::Project`] provenance, and the check happens *before* the
/// lookup. That ordering is the security property: resolving here reads
/// the user's own shell, so a `minimal.toml` naming
/// `env_vars.AWS_SECRET_ACCESS_KEY = { inherit = true }` would otherwise
/// hand a hostile project a real credential. A denied or unapproved name
/// never has its value read at all.
///
/// The full check applies, `allow` included — a task's `env_vars` are
/// declared by the project, and the project is exactly what the policy
/// exists to constrain. `[session.vars]` from the same file has always
/// been gated this way; a task's were the inconsistency.
///
/// - `deny` fails the run, naming the rule's file.
/// - `ignore` drops the name.
/// - `allow` carries it.
/// - anything else is referred to `hooks`, which prompts on a terminal
///   and refuses everywhere else.
///
/// A dropped name goes into [`TaskEnv::drop`] rather than simply being
/// left out. The daemon applies the resolved values by insertion, so a
/// name it is not told about keeps whatever `minimal.toml` declared —
/// which for an `inherit` entry means the daemon resolving it against its
/// own environment, exactly what the user asked not to happen.
///
/// An echo task resolves to nothing at all, whatever it declares. The daemon
/// answers one straight from the declaration and returns before it builds an
/// environment (`crates/minimald/src/exec.rs`), so its `env_vars` are read by
/// no one. Resolving them would fail a run that works today over a variable
/// the task has no use for, and gate one over a name it never sees.
///
/// [`VarsPolicy::check`]: boxes::core::policy::VarsPolicy::check
/// [`Source::Project`]: boxes::core::source::Source::Project
/// [`TaskEnv::drop`]: minimald_rpc::taskenv::TaskEnv::drop
fn resolve_task_env(
    task: &mfile::Task,
    task_name: &str,
    vars_policy: boxes::core::policy::VarsPolicy,
    policy_path: &std::path::Path,
    source: &boxes::core::source::Source,
    hooks: &dyn boxes::core::hooks::PolicyHooks,
    env: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<minimald_rpc::taskenv::TaskEnv, anyhow::Error> {
    use boxes::core::compose::NameVerdict;

    let mut resolved = minimald_rpc::taskenv::TaskEnv::default();
    if task.action.as_echo().is_some() {
        return Ok(resolved);
    }

    // Order comes off the map, which is a `BTreeMap` (#1319): which
    // variable a user is prompted about first, and which denial is
    // reported, are fixed by the declaration's own key order rather than
    // by a sort here.
    let names: Vec<&str> = task.vars.keys().map(String::as_str).collect();

    // The gate is `boxes`' own — the same three passes the session
    // composer runs, called with names alone so that no value is read
    // before the policy has spoken.
    let pairs: Vec<(&str, &boxes::core::source::Source)> =
        names.iter().map(|n| (*n, source)).collect();
    let (verdicts, _policy) =
        match boxes::core::compose::gate_names(&pairs, vars_policy, Some(hooks)) {
            Ok(out) => out,
            // The gate stops at the first denial and names it. Reported
            // here rather than relayed, so the operator gets the task, the
            // variable, and the file the rule lives in.
            Err(boxes::core::compose::ComposeError::Denied { what, .. }) => {
                bail!(denied_task_var_message(task_name, &what, policy_path))
            }
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("gating `env_vars` for task '{task_name}'"));
            }
        };

    let mut approved: Vec<&str> = Vec::new();
    for (name, verdict) in names.iter().zip(verdicts) {
        match verdict {
            NameVerdict::Allowed => approved.push(name),
            NameVerdict::Ignored => {
                resolved.drop.insert((*name).to_string());
            }
        }
    }

    // Only now is anything read out of this shell.
    for name in approved {
        let value = match &task.vars[name] {
            mfile::EnvVarValue::Value(v) => v.clone(),
            mfile::EnvVarValue::Inherit => env(name).map_err(|_| {
                anyhow::anyhow!(
                    "task '{task_name}' declares `env_vars.{name} = {{ inherit = true }}`, \
                     but {name} is not set in this shell; export it before running the task"
                )
            })?,
        };
        resolved.set.insert(name.to_string(), value);
    }
    Ok(resolved)
}

/// Gate a task's `env_vars` against the user policy and resolve them
/// against this shell ([`resolve_task_env`]), in the lane the terminal
/// allows: the interactive prompt on a real terminal, the collect-and-refuse
/// [`RefuseAndRecord`] anywhere else. Returns the resolved set and the
/// policy as the prompt left it, which the interactive lane has already
/// saved.
///
/// Shared by `min task run` and `min session run` (inbox#778), so the two
/// verbs pass one gate and print one refusal.
pub(crate) fn gate_task_env(
    global: &GlobalArgs,
    declared: &mfile::Task,
    task_name: &str,
    source: &boxes::core::source::Source,
    user_policy: boxes::core::policy::UserPolicy,
    policy_path: &std::path::Path,
    env: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<
    (
        minimald_rpc::taskenv::TaskEnv,
        boxes::core::policy::UserPolicy,
    ),
    anyhow::Error,
> {
    // Gated against `[vars]` on the way, `allow` included. Resolving here
    // reads the user's own shell, so the project naming a variable is the
    // project asking for its value — the same two lanes as an activate: the
    // interactive prompt on a real terminal, the collect-and-refuse
    // `NoPromptHook` anywhere else.
    let non_interactive = global.no_input || !crate::can_prompt_interactively();
    if non_interactive {
        let hooks = RefuseAndRecord::default();
        let task_env = resolve_task_env(
            declared,
            task_name,
            user_policy.vars().clone(),
            policy_path,
            source,
            &hooks,
            env,
        );
        // Checked before the result: the hook refused, so `task_env` is
        // the abort error and the names are the useful half of it.
        let refused = hooks.into_names();
        if !refused.is_empty() {
            let count = refused.len();
            let snippet = refused_vars_snippet(&refused);
            bail!(
                "task '{task_name}' declares {count} environment variable{s} that your \
                 policy does not allow, and stdin/stderr is not a terminal.\n\n\
                 Add the following to {path}:\n\n{snippet}\n\
                 Then re-run this command.",
                path = policy_path.display(),
                s = if count == 1 { "" } else { "s" },
            );
        }
        Ok((task_env?, user_policy))
    } else {
        let hooks = crate::prompt::InteractivePrompt::new(policy_path, user_policy.clone());
        let task_env = resolve_task_env(
            declared,
            task_name,
            user_policy.vars().clone(),
            policy_path,
            source,
            &hooks,
            env,
        );
        // Persist before propagating a refusal: a rule the user chose to
        // record is theirs whether or not this run goes on to fail.
        let after = hooks.into_final_policy();
        if after != user_policy {
            match crate::prompt::save_user_policy(policy_path, &after) {
                Ok(()) => eprintln!("Updated {}", policy_path.display()),
                Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
            }
        }
        Ok((task_env?, after))
    }
}

/// The `env_vars` of `task` for a `min session run` against a session built
/// from the project at `project_path`, gated and resolved here as
/// `min task run` does them ([`gate_task_env`]) (inbox#778).
///
/// The declaration is read from the project on this host, the only copy the
/// client can read. The daemon runs the task from the session's own copy,
/// taken at activation, so the two can differ. The daemon is told the
/// client resolved the task, and it then refuses an `inherit` this set does
/// not answer rather than reading its own environment for it. A project
/// with no `minimal.toml` here, or one that does not declare `task` (a task
/// a stack provides), yields an empty set for the same reason: the run goes
/// on, and only an `inherit` stops it.
pub(crate) fn session_run_task_env(
    global: &GlobalArgs,
    project_path: &camino::Utf8Path,
    task: &str,
    env: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<minimald_rpc::taskenv::TaskEnv, anyhow::Error> {
    // The daemon trims the name it is sent, so the lookup does too.
    let task = task.trim();
    let file = match mfile::File::from_dir_recursive(project_path.as_std_path()) {
        Ok(file) => file,
        Err(e) => {
            tracing::debug!(
                project = %project_path,
                error = %e,
                "no readable minimal.toml for the session's project on this host"
            );
            return Ok(minimald_rpc::taskenv::TaskEnv::default());
        }
    };
    let Some(declared) = file.task(task) else {
        return Ok(minimald_rpc::taskenv::TaskEnv::default());
    };
    let policy_path = crate::config::user_policy_path(global);
    let user_policy = crate::config::read_user_policy(global)?;
    let source = boxes::core::source::Source::Project {
        path: paths::HostPath::try_new(project_path.to_path_buf())
            .context("Invalid project path")?,
    };
    let (task_env, _) = gate_task_env(
        global,
        &declared,
        task,
        &source,
        user_policy,
        &policy_path,
        env,
    )?;
    ensure_carried_by_ssh(task, &task_env)?;
    Ok(task_env)
}

/// Refuses a resolved variable the ssh transport of `min session run`
/// cannot carry: ssh forwards a variable from its own environment, which
/// holds no name with `=` or a NUL, and no value with a NUL. `min task run`
/// sends its variables over the daemon's own channel and has no such limit.
fn ensure_carried_by_ssh(
    task: &str,
    task_env: &minimald_rpc::taskenv::TaskEnv,
) -> Result<(), anyhow::Error> {
    for (name, value) in &task_env.set {
        if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
            bail!(
                "task '{task}' declares `env_vars.{name:?}`, which `min session run` \
                 cannot carry into the session: an environment variable's name holds \
                 no `=` or NUL, and its value no NUL; use `min task run {task}`"
            );
        }
    }
    Ok(())
}

/// The non-interactive lane's hook: records what the policy could not
/// decide and then **refuses**.
///
/// [`NoPromptHook`](crate::prompt::NoPromptHook) cannot serve here. It
/// fake-approves every unapproved item with `AllowOnce` so an activate's
/// later hooks still fire and the operator's snippet lists every required
/// edit — safe there, because that caller only ever submits a verdict and
/// checks the summary before it does. This caller *reads values*, and an
/// `AllowOnce` reaches the lookup: the name's value would come out of the
/// user's shell before anyone checked the summary, which is the exact
/// ordering the gate exists to prevent. Refusing keeps the read from
/// happening at all; the caller formats the same snippet from `names`.
#[derive(Default)]
struct RefuseAndRecord {
    names: std::cell::RefCell<Vec<String>>,
}

impl RefuseAndRecord {
    fn into_names(self) -> Vec<String> {
        self.names.into_inner()
    }
}

impl boxes::core::hooks::PolicyHooks for RefuseAndRecord {
    fn on_var_unapproved(
        &self,
        _policy: boxes::core::policy::VarsPolicy,
        items: &[boxes::core::hooks::Unapproved<'_, str>],
    ) -> boxes::core::hooks::HookResult<boxes::core::policy::VarsPolicy> {
        let mut names = self.names.borrow_mut();
        for item in items {
            let name = item.item().to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        boxes::core::hooks::HookResult::Abort
    }

    fn on_patch_unapproved(
        &self,
        _policy: boxes::core::policy::PatchesPolicy,
        _items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
    ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
        unreachable!("task env resolution never gates patches")
    }
}

/// Format refused variable names as the `[vars] allow` snippet an
/// operator can paste, mirroring
/// [`UnapprovedSummary::as_toml_snippet`](crate::prompt::UnapprovedSummary::as_toml_snippet).
/// Emitted through `toml_edit` so a name needing TOML escaping still
/// produces a snippet that parses.
fn refused_vars_snippet(names: &[String]) -> String {
    let mut doc = toml_edit::DocumentMut::new();
    let mut vars = toml_edit::Table::new();
    let mut allow = toml_edit::Array::new();
    for name in names {
        allow.push(name.as_str());
    }
    vars.insert("allow", toml_edit::value(allow));
    doc.insert("vars", toml_edit::Item::Table(vars));
    doc.to_string()
}

/// The `[vars] deny` rejection body: names the task, the variable, and the
/// file the rule lives in, so the fix is reachable without guessing where
/// the policy is stored. Split out for unit tests.
fn denied_task_var_message(task_name: &str, name: &str, policy_path: &std::path::Path) -> String {
    format!(
        "task '{task_name}' declares `env_vars.{name}`, but {name} is denied by \
         `[vars] deny` in {path}; remove the declaration, or the deny rule if \
         this task should see it",
        path = policy_path.display(),
    )
}

/// The whitespace rejection body: the name is debug-quoted so the offending
/// whitespace is visible. Split out for unit tests.
fn untrimmed_task_message(task: &str) -> String {
    format!(
        "task name {task:?} has leading or trailing whitespace, which cannot \
         round-trip through the session exec channel; use {:?}",
        task.trim()
    )
}

/// The unknown-task error body: names the task and lists what IS declared,
/// in name order, so the fix is one copy-paste away. Split out for unit tests.
fn unknown_task_message(file: &mfile::File, task: &str) -> String {
    let names: Vec<&str> = file.iter_tasks().map(|(name, _)| name.as_str()).collect();
    if names.is_empty() {
        format!(
            "unknown task '{task}': {} declares no tasks",
            mfile::MFILE_NAME
        )
    } else {
        format!(
            "unknown task '{task}'; declared tasks: {}",
            names.join(", ")
        )
    }
}

/// What the first Ctrl-C of a task run does to its box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptEnds {
    /// A task box whose entrypoint is the task: the box is stopped as
    /// `min box stop` stops it (BOX-013), and keeps its record (BOX-038).
    Stop,
    /// An interactive task, which has no spec: the run owns its box, and
    /// the box is destroyed.
    Destroy,
}

/// The line the first Ctrl-C prints, before the box is stopped or
/// destroyed.
fn interrupt_line(ends: InterruptEnds, box_name: &str) -> String {
    match ends {
        InterruptEnds::Stop => format!("\nInterrupted. Stopping box {box_name}…"),
        InterruptEnds::Destroy => format!("\nInterrupted; destroying session {box_name}…"),
    }
}

/// Guard that ends the run's box if the user interrupts the run phase,
/// modeled on [`crate::arm_activation_interrupt`]: the primary connection
/// is parked in the exec bridge, so the handler works over a fresh
/// connection. The first Ctrl-C ends the box as `ends` says, releases the
/// name hold an attach or exec may have re-made for it
/// ([`release_task_name_hold`]), and the process exits 130.
///
/// A stop is the daemon's graceful stop: SIGTERM, the grace period, then
/// SIGKILL to what still runs. Its leg is bounded by the grace period plus
/// the 10-second cleanup ceiling of [`crate::best_effort_destroy`], which
/// bounds a destroy alone. A second Ctrl-C during either abandons the
/// cleanup and exits 130 at once: an unresponsive daemon can delay the
/// exit, never prevent it. Dropping the guard cancels the handler once the
/// normal end path has run.
///
/// The SIGINT is consumed on the host. It is not relayed into the box as
/// a SIGINT; a stop sends the box SIGTERM first.
struct TaskRunInterrupt {
    task: tokio::task::JoinHandle<()>,
    /// Set once the first Ctrl-C arrived. The handler then owns the exit.
    interrupted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TaskRunInterrupt {
    /// Waits forever once a Ctrl-C arrived, so the handler's exit 130 is
    /// the run's exit. A stop ends the box, and the run's channel then
    /// reports that end, which the run must not exit with.
    async fn yield_to_handler(&self) {
        if self.interrupted.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for TaskRunInterrupt {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn arm_task_run_interrupt(
    global: &GlobalArgs,
    box_id: boxes::SessionId,
    box_name: String,
    ends: InterruptEnds,
) -> TaskRunInterrupt {
    let sock =
        crate::client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd());
    let control_sock = crate::vm_host_control_sock(
        crate::daemon_host_kind(global),
        global.minimal_dir.as_deref(),
    );
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = interrupted.clone();
    let task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        eprintln!("{}", interrupt_line(ends, &box_name));
        // The interrupt may well mean the daemon is already wedged, so the
        // leg is bounded, and raced against a second Ctrl-C, which abandons
        // it and exits immediately. `ctrl_c()` keeps the process-wide
        // SIGINT handler installed, so without that race a second interrupt
        // would be silently swallowed.
        const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let bound = match ends {
            InterruptEnds::Stop => minimald_rpc::STOP_GRACE + CLEANUP_TIMEOUT,
            InterruptEnds::Destroy => CLEANUP_TIMEOUT,
        };
        let end_box = async {
            // Deliberately not version-gated: this is the recovery half of a
            // task run, and a cleanup blocked by a skew is exactly the orphaned
            // session the gate exists to prevent.
            if let Ok(sock) = sock
                && let Ok(mut client) = crate::client::Client::connect(&sock).await
            {
                match ends {
                    InterruptEnds::Stop => {
                        let _ = client
                            .oneshot_rpc::<minimald_rpc::StopBox>(minimald_rpc::StopBoxRequest {
                                id: box_id,
                                force: false,
                            })
                            .await;
                    }
                    InterruptEnds::Destroy => {
                        use minimald_rpc::{DestroySession, DestroySessionRequest};
                        let _ = client
                            .oneshot_rpc::<DestroySession>(DestroySessionRequest {
                                id: box_id,
                                only_if_unfinalized: false,
                            })
                            .await;
                    }
                }
            }
            // The run's own return never comes on this path, so the release
            // it owes is made here, inside the same bound. A stopped box
            // keeps its record until it is reaped (BOX-018), and a stop
            // that did not land leaves it running, so only a destroy
            // releases: the stopped box's reap releases its hold.
            if ends == InterruptEnds::Destroy {
                release_task_name_hold(control_sock, box_id, &box_name).await;
            }
        };
        tokio::select! {
            res = tokio::time::timeout(bound, end_box) => {
                if res.is_err() {
                    match ends {
                        InterruptEnds::Stop => eprintln!(
                            "Box {box_name} did not stop within {bound:?}. Run \
                             `min box stop {box_name}` to stop it."
                        ),
                        InterruptEnds::Destroy => eprintln!(
                            "DestroySession timed out after {bound:?}; the session may \
                             still be present (run `min session destroy {box_name}` to clean \
                             up manually)"
                        ),
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {}
        }
        std::process::exit(130);
    });
    TaskRunInterrupt { task, interrupted }
}

/// Bridge an acked exec channel to the caller's stdio, mirroring the
/// git-remote bridge: channel data streams to stdout, extended data
/// (stream 1) to stderr, and the remote exit status is captured. A channel
/// that closes without ever reporting one — a daemon or transport death
/// mid-task — yields `None`, which [`exit_outcome`] fails closed rather
/// than reading as success.
///
/// stdin is pumped into the channel only when it is NOT a terminal: a piped
/// stdin EOFs and half-closes the channel like the git helper's does, but a
/// terminal stdin never EOFs — and a blocking stdin read cannot be
/// cancelled once the task exits — so a terminal caller half-closes
/// immediately and a stdin-reading task sees EOF instead of hanging. The
/// upshot: tasks run non-interactively; stdin content reaches the task only
/// when piped. That is not just the cancellation constraint — the daemon's
/// exec channel has no PTY (only the shell path does), so interactive tasks
/// are structurally unsupported here anyway; interactive work belongs in
/// `min session attach`.
async fn bridge_exec(
    mut channel: russh::Channel<russh::client::Msg>,
) -> Result<Option<u32>, anyhow::Error> {
    let pump = if std::io::stdin().is_terminal() {
        channel.eof().await.context("half-close task stdin")?;
        None
    } else {
        let mut to_channel = channel.make_writer();
        // Read stdin on a detached thread, not `tokio::io::stdin()`: the
        // latter parks a blocking `read(0)` on tokio's blocking pool, which
        // `pump.abort()` cannot interrupt — so a piped stdin whose writer
        // stays open would hold the runtime open forever after the task
        // exits. A detached thread is abandoned on exit instead of awaited.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        // Both results are deliberately dropped: the remote side may close
        // the channel before consuming all our input, and that surfaces
        // through the channel loop below, not here.
        Some(tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if to_channel.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = to_channel.shutdown().await;
        }))
    };

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit_status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                stdout.write_all(&data).await.context("write task stdout")?;
                stdout.flush().await.context("flush task stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                stderr.write_all(&data).await.context("write task stderr")?;
                stderr.flush().await.context("flush task stderr")?;
            }
            russh::ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            _ => {}
        }
    }
    // The channel is closed; the pump can only be parked on an input read
    // whose result no longer matters.
    if let Some(pump) = pump {
        pump.abort();
    }
    Ok(exit_status)
}

/// The name the create of a task with no spec carries (BOX-163): the
/// task's name, cleaned as the daemon cleans a spec's entry. The daemon
/// sends a request name unchanged to its name check, so a `build_all` task
/// is sent as `build-all`.
fn interactive_task_box_name(task: &str) -> String {
    boxes::box_name::entry_box_name(task)
}

/// Run a declared task in an ephemeral session: create, upload, exec the
/// canonical in-box `min task run <task>`, relay its exit code, and let the
/// daemon end the session with the run (NET-131).
pub async fn cmd_task_run(global: &GlobalArgs, args: TaskRunArgs) -> Result<(), anyhow::Error> {
    // Same project-path resolution as `cmd_activate`: explicit path, then
    // `-C`/`--repo-dir`, then the cwd.
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

    // The task must be declared before anything touches the daemon: a typo'd
    // name fails instantly, listing what IS declared, without a session ever
    // existing.
    let declared = declared_task(&utf8_path, &args.task)?;

    // Read before `ensure_daemon` because the env resolution below is
    // gated on it: a malformed policy, or a variable the policy refuses,
    // must fail with no session built.
    let policy_path = crate::config::user_policy_path(global);
    let user_policy = crate::config::read_user_policy(global)?;

    // Resolve the task's `env_vars` here, against this shell, and carry the
    // values to the daemon on the exec channel (#585). Done alongside the
    // declared-task check, before `ensure_daemon`, so an unset inherited
    // variable also fails with no session built.
    let source = boxes::core::source::Source::Project {
        path: paths::HostPath::try_new(utf8_path.clone()).context("Invalid project path")?,
    };
    // The policy amended by the task-env gating: persisted to disk on the
    // interactive path, and carried into `prepare_activation_inputs` below as
    // an override, so composition and the pending gate run under the approved
    // rules even when that save failed.
    let (task_env, amended_policy) = gate_task_env(
        global,
        &declared,
        &args.task,
        &source,
        user_policy,
        &policy_path,
        |k| std::env::var(k),
    )?;

    crate::ensure_daemon(global)?;

    // Same default as an activate with no flags, matching the loadout
    // handling below: `min task run` has no `--no-hooks` of its own, so its
    // hooks behave like any other session's. The constructor turns them on.
    let mut request = minimald_rpc::CreateSessionRequest::new(
        String::new(),
        abs_path.clone(),
        boxes::NetworkMode::HostNet,
        boxes::BoxPolicy::default(),
    );
    // BOX-163: every task run is a fresh instance. The daemon names the box
    // `<task>-<n>` from the spec's entry, with the smallest `n` no retained
    // box uses. The client invents no name.
    request.config.name = None;
    request.fresh_instance = true;
    // The task box runs its task as its entrypoint and keeps its record
    // when the task returns (BOX-038). Every created box stores its spec
    // (BOX-068). An interactive task, which has no spec, takes the exec
    // channel. The box is marked at create, so a daemon restart before its
    // task starts destroys it rather than resuming it (NET-131). The daemon
    // clears the mark when the task box's entrypoint starts.
    let spec = task_box_spec(
        &args.task,
        &declared,
        crate::spec_flags(&request),
        &args.args,
    );
    let entrypoint_runs = spec.is_some();
    request.config.ends_with_run = true;
    // Refused by a daemon of another build before it allocates anything;
    // `None` under the skew override.
    request.must_match_version = minimal_client::version_assertion();
    // The record's type is the task verb's (BOX-001).
    request.config.creating_verb = minimald_rpc::CreatingVerb::Task;
    // BOX-068: the declared task's spec, with this command's settings. An
    // interactive task sends none: the task type denies a terminal.
    if let Some(spec) = &spec {
        crate::put_spec(&mut request, spec)?;
    } else {
        // With no spec to name it, the request carries the entry's name,
        // cleaned as the daemon cleans a spec's entry.
        request.config.name = Some(interactive_task_box_name(&args.task));
    }

    // Upload per the normal activate rules: tarball sync (the default), the
    // same empty/`$HOME` and non-VCS-root gates, no `--sync` escape hatch.
    let upload_root = crate::resolve_upload_root(&utf8_path)?;
    crate::stamp_project_root(&mut request, &upload_root)?;

    // Loadouts and user policy: the same defaults as an activate with no
    // loadout flags — the config's `default_loadouts` apply. Resolved before
    // the daemon connection so a broken loadout fails loudly client-side, and
    // through the same shared helper an activate uses so the staged hook
    // scripts and the finalize budget match. The helper gets the resolved
    // project root, not the directory `min task run` was invoked from, so a
    // task started in a subdirectory still finds the project's config.
    //
    // `HookPrep::StageOnly` keeps this path's own behaviour: a task's hooks
    // reach the daemon inside the uploaded mfile, and this command never
    // refused a project whose hook script the staging check rejects.
    let selection = crate::loadouts::LoadoutSelection::from_flags(&[], false);
    let inputs = crate::loadouts::prepare_activation_inputs(
        global,
        &upload_root,
        selection,
        crate::loadouts::HookPrep::StageOnly,
        Some(amended_policy),
    )?;
    inputs.announce_loadouts();

    let initial_policy = inputs.initial_policy;
    let compose_options = inputs.compose_options;
    let hook_scripts = inputs.hook_scripts;
    let finalize_hook_budget = inputs.hook_budget;
    let contribution = inputs.contribution;
    let user_policy = inputs.user_policy;
    // Sent only for a task that declares `inherit_cwd`; any other task
    // starts at the root of the uploaded tree.
    let task_cwd = if declared.inherit_cwd {
        task_run_cwd(&upload_root, &utf8_path)
    } else {
        String::new()
    };

    // Not `connect_daemon`: like `min session activate`, this creates a session
    // and the version gate rides on that `CreateSession` rather than on a
    // `GetVersion` ahead of it.
    let mut client = crate::connect_daemon_unchecked(global).await?;

    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    tracing::info!(
        task = %args.task,
        requested_name = ?request.config.name,
        fresh_instance = request.fresh_instance,
        "creating the task box as a fresh instance"
    );
    let resp = client
        .oneshot_rpc::<CreateSession>(request.clone())
        .await
        .map_err(|error| crate::session_rpc_failed(crate::SessionRpc::CreateSession, error))?;
    let created = match resp {
        minimald_rpc::Errorable::Ok(r) => r,
        minimald_rpc::Errorable::Err { error } => return Err(crate::create_refusal(error)),
    };
    // A daemon too old to know the field ignored it and echoes no version;
    // that silence is the skew. Caught here, before the upload and the
    // finalize, with the record still unfinalized and reapable.
    minimal_client::ensure_version_reported(created.daemon_version.as_deref())?;
    let id = created.id;
    // The task box is a `host_ip` box: its egress is admitted on the VM
    // host daemon before it runs anything (NET-085), or the host gate drops
    // every frame it sends outside the VM. The guard retires it on an early
    // return; the run's end retires it through `release_task_name_hold`.
    let mut host_ip_residency = crate::HostIpResidency::admit(
        crate::vm_host_control_sock(
            crate::daemon_host_kind(global),
            global.minimal_dir.as_deref(),
        ),
        id,
        request.config.network,
        request.config.policy.egress.as_ref(),
    )
    .await;
    // The daemon named the box `<task>-<n>`. A box whose name cannot be read
    // back goes by its id.
    let session_name = crate::daemon_box_name(&mut client, id)
        .await
        .unwrap_or_else(|| id.to_string());
    tracing::info!(session_id = %id, box_name = %session_name, "the daemon named the task box");

    // Until the session is Active, a Ctrl-C must abort the half-built
    // session exactly as during an activate.
    let interrupt_guard = crate::arm_activation_interrupt(global, id);

    let headless = global.no_input || !crate::can_prompt_interactively();
    let decision = crate::decide_workspace_upload(
        &upload_root,
        false,
        headless,
        std::env::home_dir().as_deref(),
    );
    // `min task run` has no `--sync` flags, so it warns rather than refuses:
    // an undeclared root starts empty, and a `$HOME` skip names the lifecycle
    // hooks it drops. The box still starts, as it did before the shared gate.
    crate::cli_workspace_upload(
        &mut client,
        id,
        &utf8_path,
        &upload_root,
        decision,
        crate::DroppedHooksPolicy::Warn,
    )
    .await?;

    // Client-side loadout patches land in the composition whether the
    // configure response is Materialized or Pending; daemon-side patches
    // approved through a Pending gate are appended below.
    let mut collected_patches = minimal_client::contribution_patch_uploads(&contribution);

    let configured = client
        .oneshot_rpc::<ConfigureLoadout>(ConfigureLoadoutRequest {
            session_id: id,
            contribution,
        })
        .await
        .map_err(|error| crate::session_rpc_failed(crate::SessionRpc::ConfigureLoadout, error))?;
    let configured = match configured {
        minimald_rpc::Errorable::Ok(r) => r,
        // Same failure, same wording as an activate: the user knows the
        // directory, not the daemon-side step that broke.
        minimald_rpc::Errorable::Err { error } => {
            bail!(crate::composition_failure_message(&utf8_path, &error));
        }
    };

    // Pending gating: the same two lanes as `cmd_activate` — the
    // interactive prompt on a real terminal, the collect-and-abort
    // `NoPromptHook` anywhere else (there is no `--no-prompt` flag here;
    // a non-TTY implies it).
    if let minimald_rpc::ConfigureLoadoutResponse::Pending { response } = configured {
        let non_interactive = global.no_input || !crate::can_prompt_interactively();
        if non_interactive {
            let session_id = response.session_id;
            let hooks = crate::prompt::NoPromptHook::new();
            let verdict =
                match crate::compute_verdict(response, user_policy, compose_options, &hooks) {
                    Ok((verdict, _final_policy)) => verdict,
                    Err(e) => {
                        crate::send_abort(&mut client, session_id).await;
                        bail!(crate::composition_failure_message(
                            &utf8_path,
                            &e.to_string()
                        ));
                    }
                };
            let summary = hooks.into_summary();
            if summary.count() > 0 {
                crate::send_abort(&mut client, session_id).await;
                let count = summary.count();
                let snippet = summary.as_toml_snippet();
                bail!(
                    "{count} item{s} would require interactive approval, but \
                     stdin/stderr is not a terminal.\n\n\
                     Add the following to {}:\n\n{snippet}\n\
                     Then re-run this command.",
                    policy_path.display(),
                    s = if count == 1 { "" } else { "s" },
                );
            }
            collected_patches.extend(crate::approved_patches_from_verdict(&verdict));
            crate::submit_verdict_and_wait(&mut client, session_id, verdict).await?;
        } else {
            let hooks = crate::prompt::InteractivePrompt::new(&policy_path, user_policy.clone());
            let result = crate::drive_pending_to_active(
                &mut client,
                response,
                user_policy,
                compose_options,
                &hooks,
                &utf8_path,
            )
            .await;
            if let Ok((_, _, ref approved)) = result {
                collected_patches.extend(approved.iter().cloned());
            }
            let final_policy = hooks.into_final_policy();
            if final_policy != initial_policy {
                match crate::prompt::save_user_policy(&policy_path, &final_policy) {
                    Ok(()) => eprintln!("Updated {}", policy_path.display()),
                    Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
                }
            }
            result?;
        }
    }
    let _ = initial_policy;

    minimal_client::dedup_patch_uploads(&mut collected_patches);
    if let Err(e) = crate::upload_and_finalize(
        &mut client,
        id,
        &collected_patches,
        &hook_scripts,
        finalize_hook_budget,
    )
    .await
    {
        // Unconditional: a task box is its run's own, and one whose finalize
        // completed after the client gave up has no exec whose end would
        // destroy it, so a kept box would be stranded. Only an activation's
        // cleanup keeps a finished session (inbox#690).
        crate::best_effort_destroy(&mut client, id, false).await;
        return Err(e);
    }

    // Active: from here an interrupt destroys the session rather than
    // aborting a draft.
    drop(interrupt_guard);
    let run_guard = arm_task_run_interrupt(
        global,
        id,
        session_name.clone(),
        if entrypoint_runs {
            InterruptEnds::Stop
        } else {
            InterruptEnds::Destroy
        },
    );

    if entrypoint_runs {
        eprintln!("Running task {} in box {session_name}...", args.task);
        // One span for the run, from the request to the exit code.
        let span = tracing::info_span!(
            "task_run",
            box_id = %id,
            box_name = %session_name,
            task = %args.task,
        );
        // What the run did with its box: only a box it removed gives up
        // its name hold and its egress ([`release_task_box_holds`]).
        let (outcome, end) = async {
            match open_task_box_run(&mut client, id, &args.task, &task_cwd, &task_env).await {
                Ok(channel) => {
                    let outcome = bridge_exec(channel).await;
                    run_guard.yield_to_handler().await;
                    let mut end = TaskBoxEnd::Keep;
                    if let Ok(exit) = outcome {
                        end = task_box_end(exit, || entrypoint_started(&mut client, id)).await;
                        match end {
                            TaskBoxEnd::Keep => {
                                eprintln!("{}", crate::kept_box_line(&session_name));
                            }
                            TaskBoxEnd::Remove => {
                                tracing::info!(
                                    box_id = %id,
                                    "the daemon did not start the task box's entrypoint; \
                                     removing the box"
                                );
                                crate::best_effort_destroy(&mut client, id, false).await;
                            }
                        }
                    }
                    (outcome, end)
                }
                // The exec never started, so no entrypoint ran: the box is
                // removed, as the client always removed it.
                Err(e) => {
                    crate::best_effort_destroy(&mut client, id, false).await;
                    (Err(e), TaskBoxEnd::Remove)
                }
            }
        }
        .instrument(span.clone())
        .await;
        span.in_scope(|| {
            tracing::info!(exit = ?outcome.as_ref().ok().copied().flatten(), "task run ended");
        });
        if let Some(residency) = host_ip_residency.as_mut() {
            residency.keep();
        }
        release_task_box_holds(
            end,
            crate::vm_host_control_sock(
                crate::daemon_host_kind(global),
                global.minimal_dir.as_deref(),
            ),
            id,
            &session_name,
        )
        .await;
        drop(run_guard);
        return exit_outcome(outcome?);
    }

    eprintln!("Running task {} in session {session_name}...", args.task);

    let outcome = match client
        .open_session_exec_channel(
            id,
            &task_run_request(&args.task, &args.args, task_cwd).encode(),
            &task_env,
        )
        .await
    {
        Ok(channel) => bridge_exec(channel).await,
        // The exec never started, so the daemon's owns-box destroy will
        // never fire either (NET-131 ends the box when the run's command
        // exits, and there is no run): resolve the box here, as the client
        // always did. A run that bridged leaves its box to the daemon.
        Err(e) => {
            // Finished (the exec never started): unconditional.
            crate::best_effort_destroy(&mut client, id, false).await;
            Err(e)
        }
    };

    // A run that bridged ends its own box from the daemon's side of the
    // exec's exit (NET-131) — destroying here too would race it and undo
    // the point of the flag: a client killed mid-run must strand nothing.
    if let Some(residency) = host_ip_residency.as_mut() {
        residency.keep();
    }
    release_task_name_hold(
        crate::vm_host_control_sock(
            crate::daemon_host_kind(global),
            global.minimal_dir.as_deref(),
        ),
        id,
        &session_name,
    )
    .await;
    drop(run_guard);

    exit_outcome(outcome?)
}

/// What a task run does with its box once the run's channel closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskBoxEnd {
    /// The box stays, with its record (BOX-038), or runs on (BOX-015).
    Keep,
    /// The daemon refused to start the entrypoint, so the box is removed.
    Remove,
}

/// Decides [`TaskBoxEnd`] from the exit status the run's channel reported.
///
/// The daemon reports a code only once the box's record keeps it, so a box
/// whose record still reads not started after a reported code never started
/// its entrypoint: the daemon refused the start, and the box is removed.
/// `started` reads the record, and only then. A channel that closed with no
/// status (a daemon or transport drop mid-run) says nothing about the
/// entrypoint, which can still run, so the box is kept and the record is
/// not read: a client that loses its run never ends the box (BOX-015).
async fn task_box_end<F, Fut>(exit: Option<u32>, started: F) -> TaskBoxEnd
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    match exit {
        None => TaskBoxEnd::Keep,
        Some(_) if started().await => TaskBoxEnd::Keep,
        Some(_) => TaskBoxEnd::Remove,
    }
}

/// Whether the task box's entrypoint ran: the box's record shows it ended,
/// as a box ends when its entrypoint returns (BOX-038). A box that is still
/// running, or still activating, never started it. A record the daemon
/// cannot read back counts as started, so the box is kept rather than
/// removed on a guess.
async fn entrypoint_started(client: &mut crate::client::Client, id: boxes::SessionId) -> bool {
    use boxes::core::record::RecordState;
    let reply = client
        .oneshot_rpc::<minimald_rpc::GetSessionRecord>(minimald_rpc::GetSessionRecordRequest::Id(
            id,
        ))
        .await;
    match reply {
        Ok(reply) => !matches!(
            reply.record.map(|record| record.state()),
            Some(Ok(RecordState::Pending
                | RecordState::Materializing
                | RecordState::Running))
        ),
        Err(error) => {
            tracing::warn!(box_id = %id, %error, "could not read the task box's state");
            true
        }
    }
}

/// Releases what a task box held on the VM host daemon once its run
/// ended, as `end` says: a removed box releases its name hold and its
/// `host_ip` egress ([`release_task_name_hold`]). A kept box releases
/// nothing. It may still run, because a run that lost its channel never
/// ends the box (BOX-015), or it ended and keeps its record until it is
/// reaped (BOX-018). Its reap releases both.
pub(crate) async fn release_task_box_holds(
    end: TaskBoxEnd,
    control_sock: Option<std::path::PathBuf>,
    id: boxes::SessionId,
    name: &str,
) {
    if end == TaskBoxEnd::Remove {
        release_task_name_hold(control_sock, id, name).await;
    }
}

/// Releases what a removed task run's box held on the VM host daemon,
/// best-effort: its name hold and its `host_ip` egress. A
/// `min session attach` or `min exec` into the running box re-makes a name
/// hold (`rehold_held_name_before_attach` cannot tell a task box apart),
/// and a destroy through the raw `DestroySession` RPC releases neither.
/// So a task box's run calls this after it destroyed its box itself
/// ([`release_task_box_holds`]), an interrupt that destroys the box calls
/// it, and so does a run whose box the daemon ends with the run (NET-131).
/// A task box the run keeps, running or ended, keeps both until its reap
/// releases them. The release is by the box's
/// `id`, so it frees only this box's hold, and a name nothing held is the
/// goal state already holding.
pub(crate) async fn release_task_name_hold(
    control_sock: Option<std::path::PathBuf>,
    id: boxes::SessionId,
    name: &str,
) {
    crate::release_held_box_name(control_sock, id, Some(name), None).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // BOX-038, T43: `min task run` creates a task box whose entrypoint is
    // the task, with the typed arguments on its argv. The run asks the
    // daemon for that entrypoint, owns no box, and returns the code the
    // daemon relays as its own. The box is kept, and the run says how to
    // remove it. The daemon half, which runs the entrypoint and relays its
    // code, needs the mock launcher of `minimald`'s own tests:
    // `until_complete_ends_on_entrypoint_return_without_client_*` there.
    #[test]
    fn task_run_returns_the_entrypoint_exit_code() {
        // An interactive task has no spec, so it keeps the exec path.
        let interactive = mfile::Task {
            interactive: true,
            ..mfile::Task::default()
        };
        assert!(task_box_spec("sh", &interactive, Default::default(), &[]).is_none());

        // The arguments ride the entrypoint's argv.
        let spec = task_box_spec(
            "check",
            &mfile::Task::default(),
            mfile::spec::SpecFlags::default(),
            &["--path".to_string(), "prod".to_string()],
        )
        .expect("a task that is not interactive has a spec");
        let argv = ["min", "task", "run", "check", "--", "--path", "prod"];
        assert_eq!(
            spec.entrypoint,
            mfile::spec::Entrypoint::Exec(argv.map(String::from).to_vec())
        );
        // The in-box run reads `--path` as the task's, not as its own flag.
        let cli = <crate::cli::Cli as clap::Parser>::try_parse_from(argv).expect("the argv parses");
        let Some(crate::cli::Command::Task(crate::cli::TaskArgs {
            command: crate::cli::TaskCommand::Run(run),
        })) = cli.command
        else {
            panic!("the argv is a task run");
        };
        assert_eq!(run.path, None);
        assert_eq!(run.args, ["--path", "prod"]);
        // A run with no arguments adds no separator.
        let spec = task_box_spec(
            "check",
            &mfile::Task::default(),
            mfile::spec::SpecFlags::default(),
            &[],
        )
        .expect("a task that is not interactive has a spec");
        assert_eq!(spec.entrypoint, mfile::spec::Entrypoint::for_task("check"));
        // The run sends no arguments and owns no box.
        assert_eq!(
            entrypoint_run_request("check", ""),
            minimald_rpc::exec::ExecRequest::TaskRun {
                task: "check".to_string(),
                owns_box: false,
                args: vec![],
                cwd: String::new(),
            }
        );
        // An `inherit_cwd` task's directory rides the request, where the
        // daemon starts the entrypoint.
        let minimald_rpc::exec::ExecRequest::TaskRun { cwd, .. } =
            entrypoint_run_request("check", "sub/inner")
        else {
            panic!("a task run request");
        };
        assert_eq!(cwd, "sub/inner");

        // The code the daemon relays is the run's: 0 is success, and any
        // other code is the process's exit code.
        assert!(exit_outcome(Some(0)).is_ok());
        let err = exit_outcome(Some(7)).unwrap_err();
        assert_eq!(err.downcast_ref::<TaskExit>(), Some(&TaskExit(7)));
        assert_eq!(
            crate::kept_box_line("check-1"),
            "Kept box check-1. Remove it with min box rm check-1."
        );
    }

    /// The hidden `min run` redirect names both canonical forms — the host
    /// `min task run <task>` and the in-box
    /// `min session attach --command 'min task run <task>'` — substituting
    /// the typed task name when there was one.
    #[test]
    fn run_alias_message_names_both_canonical_forms() {
        let msg = run_alias_message(Some("build"));
        assert!(msg.contains("min task run build"), "got: {msg}");
        assert!(
            msg.contains("min session attach --command 'min task run build'"),
            "got: {msg}"
        );

        let bare = run_alias_message(None);
        assert!(bare.contains("min task run <task>"), "got: {bare}");

        let err = cmd_run(&RunArgs {
            rest: vec!["build".into(), "--keep".into()],
        })
        .expect_err("the hidden run must always error");
        assert!(err.to_string().contains("min task run build"));
    }

    /// The unknown-task error lists the declared tasks sorted, or says none
    /// are declared, so the fix is one copy-paste away.
    #[test]
    fn unknown_task_message_lists_declared_tasks_sorted() {
        let file =
            mfile::File::from_toml_bytes(b"[tasks.b]\necho = 'x'\n\n[tasks.a]\necho = 'y'\n")
                .unwrap();
        let msg = unknown_task_message(&file, "c");
        assert!(msg.contains("unknown task 'c'"), "got: {msg}");
        assert!(msg.contains("declared tasks: a, b"), "got: {msg}");

        let none = mfile::File::from_toml_bytes(b"").unwrap();
        let msg = unknown_task_message(&none, "c");
        assert!(msg.contains("declares no tasks"), "got: {msg}");
    }

    /// A task name with leading/trailing whitespace is rejected before any
    /// config lookup — the daemon trims the exec command string, so such a
    /// name can never round-trip — with the name debug-quoted so the
    /// whitespace is visible.
    #[test]
    fn untrimmed_task_names_are_rejected() {
        let msg = untrimmed_task_message(" build ");
        assert!(msg.contains("\" build \""), "got: {msg}");
        assert!(msg.contains("whitespace"), "got: {msg}");
        assert!(msg.contains("\"build\""), "got: {msg}");

        // The rejection fires before the minimal.toml discovery: a path
        // that has no config still yields the whitespace error, not the
        // no-config one.
        let err = declared_task(camino::Utf8Path::new("/nonexistent-task-test"), "build ")
            .expect_err("an untrimmed name must be rejected");
        assert!(err.to_string().contains("whitespace"), "got: {err}");
    }

    /// BOX-163: a task with no spec sends its name cleaned, as the daemon
    /// cleans a spec's entry, so the daemon's name check accepts it.
    #[test]
    fn interactive_task_sends_its_name_cleaned() {
        assert_eq!(interactive_task_box_name("build_all"), "build-all");
    }

    /// Exit-status relay: a reported 0 is success; anything else downcasts
    /// to the typed `TaskExit`, clamped into `u8` like the git-remote
    /// helper's status.
    #[test]
    fn exit_outcome_relays_the_task_status() {
        exit_outcome(Some(0)).expect("exit 0 is success");

        let err = exit_outcome(Some(7)).unwrap_err();
        assert_eq!(err.downcast_ref::<TaskExit>(), Some(&TaskExit(7)));

        // Out-of-range statuses clamp to 1 rather than truncate.
        let err = exit_outcome(Some(300)).unwrap_err();
        assert_eq!(err.downcast_ref::<TaskExit>(), Some(&TaskExit(1)));
    }

    /// A channel that closed without ever reporting an exit status — a
    /// daemon or transport death mid-task — must fail closed: a diagnostic
    /// error (process exit 1 via main's error path), never the old
    /// default-to-0 false success, and not a silent `TaskExit`.
    #[test]
    fn exit_outcome_fails_closed_on_a_missing_status() {
        let err = exit_outcome(None).expect_err("a missing status is never success");
        assert!(
            err.to_string()
                .contains("task ended without reporting an exit status"),
            "got: {err}"
        );
        assert!(err.downcast_ref::<TaskExit>().is_none());
    }

    /// BOX-013, BOX-038: the first Ctrl-C of an entrypoint run says it stops
    /// the box. An interactive task's run still destroys its box, and says
    /// so.
    #[test]
    fn an_interrupted_entrypoint_run_says_it_stops_the_box() {
        assert_eq!(
            interrupt_line(InterruptEnds::Stop, "lint-1"),
            "\nInterrupted. Stopping box lint-1…"
        );
        assert_eq!(
            interrupt_line(InterruptEnds::Destroy, "lint-1"),
            "\nInterrupted; destroying session lint-1…"
        );
    }

    /// BOX-015: a run whose channel dropped mid-run, with no exit status,
    /// keeps its box even while the record reads running, and does not read
    /// the record to decide. A reported code with a record that never left
    /// running is the daemon's refusal, and only that removes the box.
    #[tokio::test]
    async fn a_task_box_run_that_loses_its_channel_keeps_the_box() {
        let mut read = false;
        let end = task_box_end(None, || {
            read = true;
            std::future::ready(false)
        })
        .await;
        assert_eq!(end, TaskBoxEnd::Keep, "a dropped channel keeps the box");
        assert!(!read, "a dropped channel does not read the record");

        assert_eq!(
            task_box_end(Some(3), || std::future::ready(true)).await,
            TaskBoxEnd::Keep,
            "an entrypoint that ended keeps its box"
        );
        assert_eq!(
            task_box_end(Some(125), || std::future::ready(false)).await,
            TaskBoxEnd::Remove,
            "a refused start removes the box"
        );
    }

    /// NET-131 from the client side: a `min task run` of a task with no
    /// spec sends the owns-box flag, which is what moves the destroy to the
    /// daemon — it ends the session once the task's exit status is on the
    /// wire, whether or not this client is still there. The daemon-backed half — the box actually
    /// ending — needs a live daemon and is covered by the `minimald` exec
    /// tests and the session e2e, not a unit test.
    #[test]
    fn task_run_leaves_destroy_to_daemon() {
        use minimald_rpc::exec::ExecRequest;

        // A normal run: the request names the box as the run's own.
        let req = task_run_request("build", &[], String::new());
        assert_eq!(
            req,
            ExecRequest::TaskRun {
                task: "build".to_string(),
                owns_box: true,
                args: vec![],
                cwd: String::new(),
            }
        );
        // The flag is carried, not inferred: it survives the wire.
        assert_eq!(ExecRequest::parse(&req.encode()), Ok(req));
    }

    /// `inherit_cwd` from the client side: the invocation directory is sent
    /// relative to the upload root — the tree the daemon unpacks at
    /// `/workbench` — and is empty when the user is at the root itself.
    #[test]
    fn task_run_cwd_is_relative_to_the_upload_root() {
        use camino::Utf8Path;

        let root = Utf8Path::new("/home/dev/project");
        assert_eq!(
            task_run_cwd(root, Utf8Path::new("/home/dev/project/sub/inner")),
            "sub/inner"
        );
        assert_eq!(task_run_cwd(root, root), "");

        // The cwd rides the request to the daemon intact.
        let req = task_run_request(
            "ic",
            &[],
            task_run_cwd(root, Utf8Path::new("/home/dev/project/sub")),
        );
        let minimald_rpc::exec::ExecRequest::TaskRun { cwd, .. } =
            minimald_rpc::exec::ExecRequest::parse(&req.encode()).unwrap()
        else {
            panic!("a task run must parse back as a task run");
        };
        assert_eq!(cwd, "sub");
    }

    /// The empty `[vars]` policy — a fresh install, where nothing is
    /// denied or ignored. The default for the resolution tests that are
    /// not about policy.
    fn no_vars_policy() -> boxes::core::policy::VarsPolicy {
        boxes::core::policy::VarsPolicy::empty()
    }

    /// Stand-in for the on-disk policy path, which only ever reaches the
    /// error message.
    fn policy_path_fixture() -> std::path::PathBuf {
        std::path::PathBuf::from("/cfg/minimal/user_policy.toml")
    }

    /// A policy that allows every name, for the resolution tests that are
    /// not about gating. An empty policy would refer everything to the
    /// hook, which is a different test.
    fn allow_all() -> boxes::core::policy::VarsPolicy {
        no_vars_policy().try_with_allow(["*"]).unwrap()
    }

    /// A task's `env_vars` always carry project provenance — the whole
    /// point of the gate is that the project is what it constrains.
    fn project_source() -> boxes::core::source::Source {
        boxes::core::source::Source::Project {
            path: paths::HostPath::try_new(camino::Utf8PathBuf::from("/home/dev/proj")).unwrap(),
        }
    }

    /// A hook that answers every referred name the same way, recording
    /// what it was asked about. Stands in for the interactive prompt.
    struct ScriptedHook {
        decision: boxes::core::decision::ItemDecision,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl ScriptedHook {
        fn new(decision: boxes::core::decision::ItemDecision) -> Self {
            Self {
                decision,
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl boxes::core::hooks::PolicyHooks for ScriptedHook {
        fn on_var_unapproved(
            &self,
            _policy: boxes::core::policy::VarsPolicy,
            items: &[boxes::core::hooks::Unapproved<'_, str>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::VarsPolicy> {
            self.asked
                .borrow_mut()
                .extend(items.iter().map(|i| i.item().to_string()));
            boxes::core::hooks::HookResult::decided(vec![self.decision; items.len()])
        }

        fn on_patch_unapproved(
            &self,
            _policy: boxes::core::policy::PatchesPolicy,
            _items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
            unreachable!("task env resolution never gates patches")
        }
    }

    /// A hook that refuses to be asked — for the cases where the policy
    /// must decide on its own.
    struct NeverAsked;

    impl boxes::core::hooks::PolicyHooks for NeverAsked {
        fn on_var_unapproved(
            &self,
            _policy: boxes::core::policy::VarsPolicy,
            items: &[boxes::core::hooks::Unapproved<'_, str>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::VarsPolicy> {
            panic!("the policy should have decided alone, was asked about {items:?}");
        }

        fn on_patch_unapproved(
            &self,
            _policy: boxes::core::policy::PatchesPolicy,
            _items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
            unreachable!("task env resolution never gates patches")
        }
    }

    /// Build a task declaration from TOML, for the env-resolution tests.
    fn task_from_toml(toml: &str) -> mfile::Task {
        mfile::File::from_toml_bytes(toml.as_bytes())
            .unwrap()
            .task("t")
            .expect("the fixture declares task `t`")
    }

    /// The heart of #585: `{ inherit = true }` resolves against the
    /// *invoking shell*, not the daemon. The resolver is handed the
    /// client's env and must read the value from it, so what travels to
    /// the daemon is a concrete value rather than an instruction the
    /// daemon would carry out against its own environment.
    #[test]
    fn inherit_resolves_against_the_supplied_client_env() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.ZZ_TASK_TOKEN = { inherit = true }\nexec = 'true'\n",
        );

        let out = resolve_task_env(
            &task,
            "t",
            allow_all(),
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |k| {
                assert_eq!(k, "ZZ_TASK_TOKEN");
                Ok("task-value-123".to_string())
            },
        )
        .expect("an exported variable resolves");

        assert_eq!(
            out.set.get("ZZ_TASK_TOKEN").map(String::as_str),
            Some("task-value-123")
        );
        assert!(out.drop.is_empty());
    }

    /// A declared-but-unset inherited variable fails client-side, naming
    /// the task and the variable, rather than reaching the daemon and
    /// surfacing as `failed to spawn process` once a session already
    /// exists.
    #[test]
    fn an_unset_inherited_var_fails_client_side_naming_the_fix() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.ZZ_TASK_TOKEN = { inherit = true }\nexec = 'true'\n",
        );

        let err = resolve_task_env(
            &task,
            "t",
            allow_all(),
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| Err(std::env::VarError::NotPresent),
        )
        .expect_err("an unset inherited variable must be refused");
        let msg = err.to_string();
        assert!(msg.contains("task 't'"), "names the task: {msg}");
        assert!(msg.contains("ZZ_TASK_TOKEN"), "names the variable: {msg}");
        assert!(msg.contains("export it"), "names the fix: {msg}");
    }

    /// Literal values are carried alongside inherited ones, so the daemon
    /// applies one consistent set instead of resolving half of them
    /// itself. An empty inherited value is a value, not an absence.
    #[test]
    fn literals_are_carried_and_empty_inherited_values_survive() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.LITERAL = 'fixed'\nenv_vars.EMPTY = { inherit = true }\nexec = 'true'\n",
        );

        let out = resolve_task_env(
            &task,
            "t",
            allow_all(),
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| Ok(String::new()),
        )
        .expect("resolves");
        assert_eq!(out.set.get("LITERAL").map(String::as_str), Some("fixed"));
        assert_eq!(out.set.get("EMPTY").map(String::as_str), Some(""));
    }

    /// A task declaring no `env_vars` sends nothing, which is the signal
    /// the daemon reads as "resolve this the old way" — so the change is
    /// inert for every task that does not inherit.
    #[test]
    fn a_task_without_env_vars_resolves_to_nothing() {
        let task = task_from_toml("[tasks.t]\nexec = 'true'\n");
        let out = resolve_task_env(
            &task,
            "t",
            no_vars_policy(),
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| panic!("no variable should be looked up"),
        )
        .expect("resolves");
        assert!(out.is_empty());
        assert!(out.set.is_empty() && out.drop.is_empty());
    }

    /// A `deny` rule is the user's emergency stop, and it reaches a task's
    /// `env_vars` too: the run fails naming the task, the variable, and the
    /// file the rule lives in, rather than shipping the value into the box.
    #[test]
    fn a_denied_var_fails_the_run_naming_the_policy_file() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.AWS_SECRET_ACCESS_KEY = { inherit = true }\nexec = 'true'\n",
        );
        let policy = no_vars_policy().try_with_deny(["AWS_*"]).unwrap();

        let err = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| panic!("a denied variable must never be read out of this shell"),
        )
        .expect_err("a denied variable must fail the run");

        let msg = err.to_string();
        assert!(msg.contains("task 't'"), "names the task: {msg}");
        assert!(
            msg.contains("AWS_SECRET_ACCESS_KEY"),
            "names the variable: {msg}"
        );
        assert!(msg.contains("[vars] deny"), "names the rule: {msg}");
        assert!(
            msg.contains("/cfg/minimal/user_policy.toml"),
            "names the policy file: {msg}"
        );
    }

    /// `deny` is checked before the lookup, and before `ignore`: a denied
    /// literal has no shell value to read, and a name matching both rules
    /// resolves as denied so a would-be rejection can't be hidden behind an
    /// ignore glob — the same precedence `VarsPolicy::check` applies.
    #[test]
    fn deny_beats_ignore_and_applies_to_literals() {
        let task = task_from_toml("[tasks.t]\nenv_vars.AWS_KEY = 'literal'\nexec = 'true'\n");
        let policy = no_vars_policy()
            .try_with_deny(["AWS_*"])
            .unwrap()
            .try_with_ignore(["AWS_*"])
            .unwrap();

        let err = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| panic!("no lookup happens for a literal"),
        )
        .expect_err("deny must win over ignore");
        assert!(err.to_string().contains("[vars] deny"));
    }

    /// `ignore` drops the variable silently and lets the task run — and it
    /// is applied before the lookup, so an ignored `inherit` need not be
    /// set at all. The unignored siblings are unaffected.
    #[test]
    fn an_ignored_var_is_dropped_without_being_looked_up() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.NOISY_DEBUG = { inherit = true }\n\
             env_vars.KEPT = { inherit = true }\nexec = 'true'\n",
        );
        let policy = no_vars_policy()
            .try_with_ignore(["NOISY_*"])
            .unwrap()
            .try_with_allow(["KEPT"])
            .unwrap();

        let out = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |k| {
                assert_eq!(k, "KEPT", "an ignored variable must not be looked up");
                Ok("kept-value".to_string())
            },
        )
        .expect("an unset but ignored variable is not an error");

        assert_eq!(out.set.get("KEPT").map(String::as_str), Some("kept-value"));
        assert!(!out.set.contains_key("NOISY_DEBUG"));
        assert_eq!(out.set.len(), 1);
        // Named on the drop list, not merely absent: the daemon applies
        // `set` by insertion, so a name it is not told about keeps the
        // declaration `minimal.toml` made for it.
        assert!(out.drop.contains("NOISY_DEBUG"));
        assert_eq!(out.drop.len(), 1);
    }

    /// A name the policy cannot decide is referred to the hook rather than
    /// carried. This is the mitigation: resolution reads the user's own
    /// shell, so a `minimal.toml` naming a credential is the project asking
    /// for that credential's value, and the project is what the policy
    /// exists to constrain. `[session.vars]` from the same file has always
    /// been gated this way.
    #[test]
    fn an_unlisted_var_is_referred_to_the_hook_not_carried() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.AWS_SECRET_ACCESS_KEY = { inherit = true }\nexec = 'true'\n",
        );
        // A non-empty allow set that does not cover the name.
        let policy = no_vars_policy()
            .try_with_allow(["SOMETHING_ELSE_*"])
            .unwrap();
        let hooks = ScriptedHook::new(boxes::core::decision::ItemDecision::AllowOnce);

        let out = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            |_| Ok("secret".to_string()),
        )
        .expect("the hook allowed it");

        assert_eq!(
            hooks.asked(),
            vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            "the unlisted name must reach the hook",
        );
        assert_eq!(
            out.set.get("AWS_SECRET_ACCESS_KEY").map(String::as_str),
            Some("secret"),
        );
    }

    /// The value of an unapproved name is never read out of the shell.
    /// Order matters as much as the verdict: a gate that resolved first
    /// and asked afterwards would already have the secret in hand.
    #[test]
    fn an_unapproved_var_is_never_read_from_the_shell() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.AWS_SECRET_ACCESS_KEY = { inherit = true }\nexec = 'true'\n",
        );
        let hooks = ScriptedHook::new(boxes::core::decision::ItemDecision::IgnoreOnce);

        let out = resolve_task_env(
            &task,
            "t",
            no_vars_policy(),
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            |_| panic!("an unapproved variable must never be read out of this shell"),
        )
        .expect("an ignored variable is not an error");

        assert_eq!(hooks.asked(), vec!["AWS_SECRET_ACCESS_KEY".to_string()]);
        assert!(out.set.is_empty());
        // Dropped by name, so the daemon removes the declaration rather
        // than resolving it against its own environment.
        assert!(out.drop.contains("AWS_SECRET_ACCESS_KEY"));
    }

    /// An empty policy — a fresh install — refers every declared name.
    /// Nothing is carried by default, which is what makes the allow list
    /// a real control rather than an opt-in one.
    #[test]
    fn an_empty_policy_refers_every_name() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.A = 'literal'\nenv_vars.B = { inherit = true }\nexec = 'true'\n",
        );
        let hooks = ScriptedHook::new(boxes::core::decision::ItemDecision::AllowOnce);

        resolve_task_env(
            &task,
            "t",
            no_vars_policy(),
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            |_| Ok("v".to_string()),
        )
        .expect("the hook allowed both");

        // Sorted, so the prompt order does not depend on HashMap iteration.
        assert_eq!(hooks.asked(), vec!["A".to_string(), "B".to_string()]);
    }

    /// The hook the non-interactive lane actually uses must refuse, not
    /// fake-approve. `NoPromptHook` returns `AllowOnce` for everything so
    /// an activate's later hooks still fire — harmless there, because that
    /// caller only submits a verdict, and fatal here, because this one
    /// reads values: the name's secret would leave the shell before anyone
    /// looked at the summary. Drives the real `RefuseAndRecord`, which the
    /// hand-rolled doubles above cannot stand in for.
    #[test]
    fn the_non_interactive_hook_refuses_before_anything_is_read() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.AWS_SECRET_ACCESS_KEY = { inherit = true }\n\
             env_vars.OTHER = { inherit = true }\nexec = 'true'\n",
        );
        let hooks = RefuseAndRecord::default();

        let err = resolve_task_env(
            &task,
            "t",
            no_vars_policy(),
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            |_| panic!("no value may be read out of the shell on the refusing path"),
        )
        .expect_err("a refusing hook must fail the run");

        // `{:#}` renders the whole anyhow chain: the gate's abort now
        // arrives wrapped in this call site's context, so the top-level
        // message alone would not say why the run stopped.
        let chain = format!("{err:#}");
        assert!(chain.contains("aborted"), "{chain}");
        assert!(
            chain.contains("env_vars"),
            "names the gate that failed: {chain}"
        );
        assert_eq!(
            hooks.into_names(),
            vec!["AWS_SECRET_ACCESS_KEY".to_string(), "OTHER".to_string()],
            "the refused names are what the caller's snippet is built from",
        );
    }

    /// The refusal snippet is the `[vars] allow` block an operator pastes,
    /// and stays valid TOML for a name that needs escaping.
    #[test]
    fn the_refusal_snippet_is_pasteable_toml() {
        let snippet = refused_vars_snippet(&["DEPLOY_TARGET".to_string()]);
        assert!(snippet.contains("[vars]"), "{snippet}");
        assert!(snippet.contains("DEPLOY_TARGET"), "{snippet}");
        let parsed: toml::Value = toml::from_str(&snippet).expect("snippet must parse");
        assert!(parsed.get("vars").is_some());
    }

    /// A denied name is reported even when an unlisted one sits beside
    /// it. Without the short-circuit the hook answers for the unlisted
    /// name first, and the non-interactive lane tells the operator to
    /// allow-list that one — never mentioning the denial they would hit
    /// on the very next run.
    #[test]
    fn a_denial_is_reported_even_beside_an_unlisted_name() {
        let task = task_from_toml(
            "[tasks.t]\nenv_vars.AWS_KEY = { inherit = true }\n\
             env_vars.ZZ_UNLISTED = { inherit = true }\nexec = 'true'\n",
        );
        let policy = no_vars_policy().try_with_deny(["AWS_*"]).unwrap();
        let hooks = RefuseAndRecord::default();

        let err = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            |_| panic!("nothing is read out of the shell"),
        )
        .expect_err("the denial must fail the run");

        let msg = err.to_string();
        assert!(msg.contains("AWS_KEY"), "names the denied variable: {msg}");
        assert!(msg.contains("[vars] deny"), "names the rule: {msg}");
        assert!(
            hooks.into_names().is_empty(),
            "the hook must not be consulted once a name is denied",
        );
    }

    /// An echo task's `env_vars` are read by nobody: the daemon answers it
    /// from the declaration and returns before it builds an environment. So
    /// an unset `inherit` on one must not fail the run — it ran fine before
    /// client-side resolution existed — and a denied name on one must not
    /// either, since the task never sees it.
    #[test]
    fn an_echo_task_resolves_to_nothing_whatever_it_declares() {
        let task = task_from_toml(
            "[tasks.t]\necho = 'hi'\nenv_vars.UNSET = { inherit = true }\n\
             env_vars.AWS_KEY = 'literal'\n",
        );
        // Pinned: were the fixture to stop parsing as an echo task, every
        // assertion below would still pass for the wrong reason.
        assert_eq!(task.action.as_echo(), Some("hi"));
        let policy = no_vars_policy().try_with_deny(["AWS_*"]).unwrap();

        let out = resolve_task_env(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            |_| panic!("an echo task looks nothing up"),
        )
        .expect("an echo task neither resolves nor denies");

        assert!(out.is_empty(), "nothing to send: {out:?}");
    }

    /// `cmd_task_run` rejects a task the project's minimal.toml does not
    /// declare *before* it ever touches the daemon: the declared-task guard
    /// runs on the resolved project path ahead of `ensure_daemon`, so an
    /// undeclared name errors client-side — naming the unknown task and the
    /// declared list — with no session created and no daemon required. This
    /// pins the entry-path contract of the command itself; the daemon-backed
    /// run/finalize legs need a live daemon and are covered by the session
    /// e2e, not a unit test.
    #[tokio::test]
    async fn cmd_task_run_rejects_an_undeclared_task_client_side() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            b"[tasks.build]\necho = 'x'\n",
        )
        .unwrap();

        let global = GlobalArgs {
            repo_dir: Some(project.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let args = TaskRunArgs {
            task: "deploy".into(),
            path: None,
            args: vec![],
        };

        let err = cmd_task_run(&global, args)
            .await
            .expect_err("an undeclared task must be rejected before the daemon");
        let msg = err.to_string();
        assert!(msg.contains("unknown task 'deploy'"), "got: {msg}");
        assert!(msg.contains("declared tasks: build"), "got: {msg}");
    }

    /// `cmd_task_run` resolves a task's `env_vars` against the invoking
    /// shell *before* it ever touches the daemon. With an empty policy and
    /// no terminal, a declared `{ inherit = true }` variable is refused by
    /// the non-interactive hook, so the run fails client-side — naming the
    /// task, the count, and the policy file to edit — with no session
    /// created and no daemon required. This pins the policy-rejection leg
    /// of the entry path; the daemon-backed run/finalize legs need a live
    /// daemon and are covered by the session e2e, not a unit test.
    #[tokio::test]
    async fn cmd_task_run_refuses_an_unapproved_inherited_var_client_side() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            b"[tasks.build]\nexec = 'true'\nenv_vars.ZZ_TASK_TOKEN = { inherit = true }\n",
        )
        .unwrap();

        // An empty `[vars]` policy, isolated from the developer's real
        // config, so the variable is always unapproved and the run always
        // reaches the refusal asserted below rather than the inherited
        // lookup a permissive developer policy would allow.
        let config = tempfile::tempdir().unwrap();
        let minimal_dir = config.path().join("minimal");
        std::fs::create_dir_all(&minimal_dir).unwrap();
        std::fs::write(minimal_dir.join("user_policy.toml"), "[vars]\n").unwrap();

        let global = GlobalArgs {
            repo_dir: Some(project.path().to_path_buf()),
            config_dir: Some(config.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let args = TaskRunArgs {
            task: "build".into(),
            path: None,
            args: vec![],
        };

        let err = cmd_task_run(&global, args)
            .await
            .expect_err("an unapproved inherited variable must be refused before the daemon");
        let msg = err.to_string();
        assert!(msg.contains("task 'build'"), "names the task: {msg}");
        assert!(
            msg.contains("1 environment variable"),
            "names the count: {msg}"
        );
        assert!(
            msg.contains("policy does not allow"),
            "names the gate: {msg}"
        );
    }

    /// A project on disk declaring `toml`, and a config dir whose
    /// `user_policy.toml` holds `policy`, isolated from the developer's own.
    fn session_run_fixture(
        toml: &str,
        policy: &str,
    ) -> (tempfile::TempDir, tempfile::TempDir, GlobalArgs) {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(mfile::MFILE_NAME), toml).unwrap();
        let config = tempfile::tempdir().unwrap();
        let minimal_dir = config.path().join("minimal");
        std::fs::create_dir_all(&minimal_dir).unwrap();
        std::fs::write(minimal_dir.join("user_policy.toml"), policy).unwrap();
        let global = GlobalArgs {
            config_dir: Some(config.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        (project, config, global)
    }

    fn utf8(dir: &tempfile::TempDir) -> &camino::Utf8Path {
        camino::Utf8Path::from_path(dir.path()).unwrap()
    }

    const SESSION_RUN_TOML: &str = "[tasks.t778]\nexec = 'true'\n\
        env_vars.X778 = { inherit = true }\nenv_vars.LIT778 = 'lit'\n";

    /// inbox#778: `min session run` resolves the task's `inherit` against
    /// this shell, as `min task run` does, and carries literals too, so the
    /// daemon never reads its own environment for the task.
    #[test]
    fn session_run_resolves_an_allowed_inherit_from_this_shell() {
        let (project, _config, global) =
            session_run_fixture(SESSION_RUN_TOML, "[vars]\nallow = [\"X778\", \"LIT778\"]\n");

        let out = session_run_task_env(&global, utf8(&project), "t778", |k| match k {
            "X778" => Ok("x-from-shell".to_string()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("an allowed, set inherit resolves");

        assert_eq!(
            out.set.get("X778").map(String::as_str),
            Some("x-from-shell")
        );
        assert_eq!(out.set.get("LIT778").map(String::as_str), Some("lit"));
        assert!(out.drop.is_empty());
    }

    /// inbox#778: the policy gate `min task run` passes applies to
    /// `min session run` too. With no terminal, a name the policy does not
    /// allow refuses the run naming the policy file, and nothing is read
    /// out of the shell.
    #[test]
    fn session_run_refuses_a_name_the_policy_does_not_allow() {
        let (project, config, global) =
            session_run_fixture(SESSION_RUN_TOML, "[vars]\nallow = [\"LIT778\"]\n");

        let err = session_run_task_env(&global, utf8(&project), "t778", |_| {
            panic!("no value may be read before the policy allows it")
        })
        .expect_err("an unallowed name must refuse the run");

        let msg = err.to_string();
        assert!(msg.contains("task 't778'"), "names the task: {msg}");
        assert!(
            msg.contains("policy does not allow"),
            "names the gate: {msg}"
        );
        assert!(msg.contains("X778"), "names the variable: {msg}");
        let policy = config.path().join("minimal").join("user_policy.toml");
        assert!(
            msg.contains(&policy.display().to_string()),
            "names the policy file: {msg}"
        );
    }

    /// The daemon trims the task name it is sent, so the lookup does too:
    /// a padded name still passes the gate rather than skipping it.
    #[test]
    fn session_run_gates_a_padded_task_name() {
        let (project, _config, global) = session_run_fixture(SESSION_RUN_TOML, "[vars]\n");
        let err = session_run_task_env(&global, utf8(&project), " t778 ", |_| {
            panic!("nothing is read")
        })
        .expect_err("the padded name is the same task");
        assert!(err.to_string().contains("policy does not allow"), "{err}");
    }

    /// A task the project on this host does not declare (one a stack
    /// provides, or one added to the session's copy only), and a project
    /// with no `minimal.toml` here, resolve to an empty set. The run goes
    /// on, and the daemon, told the client resolved it, refuses any
    /// `inherit` the task has rather than reading its own environment.
    #[test]
    fn session_run_resolves_nothing_for_a_task_this_host_does_not_declare() {
        let (project, _config, global) = session_run_fixture(SESSION_RUN_TOML, "[vars]\n");
        let out = session_run_task_env(&global, utf8(&project), "other", |_| {
            panic!("nothing is read")
        })
        .unwrap();
        assert!(out.is_empty(), "{out:?}");

        let empty = tempfile::tempdir().unwrap();
        let out =
            session_run_task_env(&global, utf8(&empty), "t778", |_| panic!("nothing is read"))
                .unwrap();
        assert!(out.is_empty(), "{out:?}");
    }

    /// A name or value ssh cannot carry is refused with the verb that can.
    #[test]
    fn session_run_refuses_a_var_ssh_cannot_carry() {
        let mut env = minimald_rpc::taskenv::TaskEnv::default();
        env.set.insert("OK".to_string(), "v".to_string());
        ensure_carried_by_ssh("t", &env).expect("a plain name is carried");
        env.set.insert("A=B".to_string(), "v".to_string());
        let err = ensure_carried_by_ssh("t", &env).expect_err("`=` cannot be carried");
        assert!(err.to_string().contains("min task run t"), "{err}");

        let mut env = minimald_rpc::taskenv::TaskEnv::default();
        env.set.insert("NUL".to_string(), "a\0b".to_string());
        ensure_carried_by_ssh("t", &env).expect_err("a NUL cannot be carried");
    }

    /// `cmd_task_run` resolves a task's `env_vars` against the invoking
    /// shell *before* it ever touches the daemon: an `{ inherit = true }`
    /// variable the policy allows but that is not set in this shell fails
    /// client-side — naming the task, the variable, and the fix — with no
    /// session created and no daemon required. This pins the unset-inherited
    /// leg of the entry path; the daemon-backed run/finalize legs need a
    /// live daemon and are covered by the session e2e, not a unit test.
    #[tokio::test]
    async fn cmd_task_run_rejects_an_unset_inherited_var_client_side() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(mfile::MFILE_NAME),
            b"[tasks.build]\nexec = 'true'\nenv_vars.ZZ_MINIMAL_TASK_RUN_UNSET_INHERITED = { inherit = true }\n",
        )
        .unwrap();

        // A policy that allows the variable, so the gate does not refuse it
        // and the unset-inherited lookup is what fails.
        let config = tempfile::tempdir().unwrap();
        let minimal_dir = config.path().join("minimal");
        std::fs::create_dir_all(&minimal_dir).unwrap();
        std::fs::write(
            minimal_dir.join("user_policy.toml"),
            "[vars]\nallow = [\"ZZ_MINIMAL_TASK_RUN_UNSET_INHERITED\"]\n",
        )
        .unwrap();

        let global = GlobalArgs {
            repo_dir: Some(project.path().to_path_buf()),
            config_dir: Some(config.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let args = TaskRunArgs {
            task: "build".into(),
            path: None,
            args: vec![],
        };

        let err = cmd_task_run(&global, args)
            .await
            .expect_err("an unset inherited variable must be rejected before the daemon");
        let msg = err.to_string();
        assert!(msg.contains("task 'build'"), "names the task: {msg}");
        assert!(
            msg.contains("ZZ_MINIMAL_TASK_RUN_UNSET_INHERITED"),
            "names the variable: {msg}"
        );
        assert!(msg.contains("export it"), "names the fix: {msg}");
    }
}
