//! `min task run <task>`: run a declared project task in an ephemeral
//! session.
//!
//! The activate→exec→destroy loop as one command: create a session for the
//! project (named `task-<task>-<hex>`), upload the project per the normal
//! activate rules, exec the canonical in-box `min task run <task>` over the
//! native SSH exec channel with the task's output streamed through, exit
//! with the task's exit code, and destroy the session afterwards — success,
//! failure, or Ctrl-C — unless `--keep` retains it as an attachable session.
//!
//! Deliberately composed from the same client/RPC primitives `cmd_activate`
//! uses (`SessionConfig`, `CreateSession`, the upload gates,
//! `ConfigureLoadout`, the gating hooks, `FinalizeSession`) rather than
//! refactored out of it: a few duplicated lines of glue keep
//! `cmd_activate`'s diff at zero.

use std::io::IsTerminal as _;

use anyhow::{Context as _, bail};
use tokio::io::AsyncWriteExt as _;

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

/// Mint the ephemeral session name `task-<task>-<hex>`: the task name is
/// reduced to the session-name alphabet by the same sanitizer the activate
/// autogen path uses, and the caller supplies the hex so a collision retry
/// can re-mint with fresh entropy.
fn task_session_name(task: &str, hex: &str) -> String {
    format!("task-{}-{hex}", crate::sanitize_name_component(task))
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
/// [`VarsPolicy::check`]: sessions::core::policy::VarsPolicy::check
/// [`Source::Project`]: sessions::core::source::Source::Project
/// [`TaskEnv::drop`]: minimald_rpc::taskenv::TaskEnv::drop
fn resolve_task_env(
    task: &mfile::Task,
    task_name: &str,
    vars_policy: sessions::core::policy::VarsPolicy,
    policy_path: &std::path::Path,
    source: &sessions::core::source::Source,
    hooks: &dyn sessions::core::hooks::PolicyHooks,
    env: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<minimald_rpc::taskenv::TaskEnv, anyhow::Error> {
    use sessions::core::compose::NameVerdict;

    let mut resolved = minimald_rpc::taskenv::TaskEnv::default();
    if task.action.as_echo().is_some() {
        return Ok(resolved);
    }

    // Order comes off the map, which is a `BTreeMap` (#1319): which
    // variable a user is prompted about first, and which denial is
    // reported, are fixed by the declaration's own key order rather than
    // by a sort here.
    let names: Vec<&str> = task.vars.keys().map(String::as_str).collect();

    // The gate is `sessions`' own — the same three passes the session
    // composer runs, called with names alone so that no value is read
    // before the policy has spoken.
    let pairs: Vec<(&str, &sessions::core::source::Source)> =
        names.iter().map(|n| (*n, source)).collect();
    let (verdicts, _policy) =
        match sessions::core::compose::gate_names(&pairs, vars_policy, Some(hooks)) {
            Ok(out) => out,
            // The gate stops at the first denial and names it. Reported
            // here rather than relayed, so the operator gets the task, the
            // variable, and the file the rule lives in.
            Err(sessions::core::compose::ComposeError::Denied { what, .. }) => {
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

impl sessions::core::hooks::PolicyHooks for RefuseAndRecord {
    fn on_var_unapproved(
        &self,
        _policy: sessions::core::policy::VarsPolicy,
        items: &[sessions::core::hooks::Unapproved<'_, str>],
    ) -> sessions::core::hooks::HookResult<sessions::core::policy::VarsPolicy> {
        let mut names = self.names.borrow_mut();
        for item in items {
            let name = item.item().to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        sessions::core::hooks::HookResult::Abort
    }

    fn on_patch_unapproved(
        &self,
        _policy: sessions::core::policy::PatchesPolicy,
        _items: &[sessions::core::hooks::Unapproved<'_, camino::Utf8Path>],
    ) -> sessions::core::hooks::HookResult<sessions::core::policy::PatchesPolicy> {
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
/// sorted, so the fix is one copy-paste away. Split out for unit tests.
fn unknown_task_message(file: &mfile::File, task: &str) -> String {
    let mut names: Vec<&str> = file.iter_tasks().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
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

/// Guard that resolves the ephemeral session if the user interrupts the run
/// phase, modeled on [`crate::arm_activation_interrupt`]: the primary
/// connection is parked in the exec bridge, so the handler works over a
/// fresh connection. Without `--keep` the first Ctrl-C best-effort
/// `DestroySession`s the box; with it the session is left alive and the
/// handler says how to reach it. Either way the process exits 130. The
/// destroy leg is bounded: the connect-and-destroy runs under the same
/// 10-second cleanup ceiling as [`crate::best_effort_destroy`], and a
/// second Ctrl-C during it abandons the cleanup and exits 130 immediately —
/// an unresponsive daemon can delay the exit, never prevent it. Dropping
/// the guard cancels the handler once the normal destroy/keep path has run.
///
/// Note the SIGINT is consumed on the host: it is NOT relayed into the box,
/// so — unlike interrupting a local command — the task itself gets no
/// chance to trap it and clean up; the box is torn down (or, with `--keep`,
/// abandoned) around it.
struct TaskRunInterrupt {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TaskRunInterrupt {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn arm_task_run_interrupt(
    global: &GlobalArgs,
    session_id: sessions::SessionId,
    session_name: String,
    keep: bool,
) -> TaskRunInterrupt {
    let sock =
        crate::client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd());
    let task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        if keep {
            eprintln!(
                "\nInterrupted; session {session_name} kept — attach with: \
                 min session attach {session_name}"
            );
            std::process::exit(130);
        }
        eprintln!("\nInterrupted; destroying session {session_name}…");
        // The whole connect-and-destroy is bounded by the same 10-second
        // cleanup ceiling as `best_effort_destroy` — the interrupt may well
        // mean the daemon is already wedged — and raced against a second
        // Ctrl-C, which abandons the cleanup and exits immediately.
        // `ctrl_c()` keeps the process-wide SIGINT handler installed, so
        // without that race a second interrupt would be silently swallowed.
        const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let destroy = async {
            // Deliberately not version-gated: this is the recovery half of a
            // task run, and a cleanup blocked by a skew is exactly the orphaned
            // session the gate exists to prevent.
            if let Ok(sock) = sock
                && let Ok(mut client) = crate::client::Client::connect(&sock).await
            {
                use minimald_rpc::{DestroySession, DestroySessionRequest};
                let _ = client
                    .oneshot_rpc::<DestroySession>(DestroySessionRequest { id: session_id })
                    .await;
            }
        };
        tokio::select! {
            res = tokio::time::timeout(CLEANUP_TIMEOUT, destroy) => {
                if res.is_err() {
                    eprintln!(
                        "DestroySession timed out after {CLEANUP_TIMEOUT:?}; the session may \
                         still be present (run `min session destroy {session_name}` to clean \
                         up manually)"
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => {}
        }
        std::process::exit(130);
    });
    TaskRunInterrupt { task }
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
/// terminal stdin never EOFs — and tokio's stdin is an uncancellable
/// blocking read that would hold the runtime open after the task exits — so
/// a terminal caller half-closes immediately and a stdin-reading task sees
/// EOF instead of hanging. The upshot: tasks run non-interactively; stdin
/// content reaches the task only when piped. That is not just the tokio
/// constraint — the daemon's exec channel has no PTY (only the shell path
/// does), so interactive tasks are structurally unsupported here anyway;
/// interactive work belongs in `min session attach`.
async fn bridge_exec(
    mut channel: russh::Channel<russh::client::Msg>,
) -> Result<Option<u32>, anyhow::Error> {
    let pump = if std::io::stdin().is_terminal() {
        channel.eof().await.context("half-close task stdin")?;
        None
    } else {
        let mut to_channel = channel.make_writer();
        // Both results are deliberately dropped: the remote side may close
        // the channel before consuming all our input, and that surfaces
        // through the channel loop below, not here.
        Some(tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let _ = tokio::io::copy(&mut stdin, &mut to_channel).await;
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

/// Run a declared task in an ephemeral session: create, upload, exec the
/// canonical in-box `min task run <task>`, relay its exit code, destroy —
/// or keep with `--keep`.
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
    //
    // Gated against `[vars]` on the way, `allow` included. Resolving here
    // reads the user's own shell, so the project naming a variable is the
    // project asking for its value — the same two lanes as an activate: the
    // interactive prompt on a real terminal, the collect-and-refuse
    // `NoPromptHook` anywhere else.
    let source = sessions::core::source::Source::Project {
        path: paths::HostPath::try_new(utf8_path.clone()).context("Invalid project path")?,
    };
    let non_interactive = global.no_input || !crate::can_prompt_interactively();
    let (task_env, user_policy) = if non_interactive {
        let hooks = RefuseAndRecord::default();
        let task_env = resolve_task_env(
            &declared,
            &args.task,
            user_policy.vars().clone(),
            &policy_path,
            &source,
            &hooks,
            |k| std::env::var(k),
        );
        // Checked before the result: the hook refused, so `task_env` is
        // the abort error and the names are the useful half of it.
        let refused = hooks.into_names();
        if !refused.is_empty() {
            let count = refused.len();
            let snippet = refused_vars_snippet(&refused);
            bail!(
                "task '{task}' declares {count} environment variable{s} that your \
                 policy does not allow, and stdin/stderr is not a terminal.\n\n\
                 Add the following to {path}:\n\n{snippet}\n\
                 Then re-run this command.",
                task = args.task,
                path = policy_path.display(),
                s = if count == 1 { "" } else { "s" },
            );
        }
        (task_env?, user_policy)
    } else {
        let hooks = crate::prompt::InteractivePrompt::new(&policy_path, user_policy.clone());
        let task_env = resolve_task_env(
            &declared,
            &args.task,
            user_policy.vars().clone(),
            &policy_path,
            &source,
            &hooks,
            |k| std::env::var(k),
        );
        // Persist before propagating a refusal: a rule the user chose to
        // record is theirs whether or not this run goes on to fail.
        let after = hooks.into_final_policy();
        if after != user_policy {
            match crate::prompt::save_user_policy(&policy_path, &after) {
                Ok(()) => eprintln!("Updated {}", policy_path.display()),
                Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
            }
        }
        (task_env?, after)
    };

    crate::ensure_daemon(global)?;

    let config = minimald_rpc::SessionConfig {
        name: Some(task_session_name(&args.task, &crate::random_hex4())),
        project_path: abs_path.clone(),
        network: sessions::NetworkMode::HostNet,
        policy: sessions::SessionPolicy::default(),
        // Same default as an activate with no flags, matching the
        // loadout handling below. `min task run` has no `--no-hooks` of
        // its own; a `--keep` session is attachable later, so its hooks
        // should behave like any other session's.
        hooks_enabled: true,
        attrs: Default::default(),
    };

    // Loadouts and user policy: the same defaults as an activate with no
    // loadout flags — the config's `default_loadouts` apply. Resolved before
    // the daemon connection so a broken loadout fails loudly client-side.
    let cfg = crate::config::read_client_config(global)?;
    let initial_policy = user_policy.clone();
    let compose_options = crate::loadouts::compose_options_from_config(&cfg);
    let selection = crate::loadouts::LoadoutSelection::from_flags(&[], false);
    let active = crate::loadouts::resolve_active_loadouts(selection, &cfg, global)?;
    if !active.loadouts.is_empty() {
        let names: Vec<&str> = active.loadouts.iter().map(|l| l.name().as_ref()).collect();
        eprintln!("Applying loadouts: {}", names.join(", "));
    }
    // Same pre-daemon staging as an activate, so a broken hook script
    // path fails here rather than after the ephemeral session exists.
    let hook_scripts = crate::loadouts::stage_loadout_hook_scripts(&active, &abs_path, true)?;

    // Same first-class orientation field as an activate: a `--keep`
    // task session is attachable later, and its banner should orient
    // too.
    // Size the later `FinalizeSession` deadline to the composition's
    // `on_activate` hook timeouts, read while the loadouts are still in hand.
    let finalize_hook_budget = crate::loadouts::activate_hook_budget(&active, &utf8_path, true);

    let (contribution, user_policy) =
        crate::loadouts::compose_user_contribution(active, user_policy, compose_options, true)?;

    // Upload per the normal activate rules: tarball sync (the default), the
    // same empty/`$HOME` and non-VCS-root gates, no `--sync` escape hatch.
    let upload_root = crate::resolve_upload_root(&utf8_path)?;
    let skip_empty_or_home = crate::file_upload::is_empty_or_home(
        upload_root.as_std_path(),
        std::env::home_dir().as_deref(),
    );

    // Not `connect_daemon`: like `min session activate`, this creates a session
    // and the version gate rides on that `CreateSession` rather than on a
    // `GetVersion` ahead of it.
    let mut client = crate::connect_daemon_unchecked(global).await?;

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
    };
    // The minted name can (rarely) collide; retry with fresh entropy on the
    // daemon's already-exists rejection, within the activate autogen budget.
    let mut config = config;
    let mut attempts = 0u32;
    let created = loop {
        let resp = client
            .oneshot_rpc::<CreateSession>(CreateSessionRequest {
                config: config.clone(),
                // Refused by a daemon of another build before it allocates
                // anything; `None` under the skew override.
                must_match_version: minimal_client::version_assertion(),
            })
            .await
            .context("CreateSession RPC failed")?;
        match resp {
            minimald_rpc::Errorable::Ok(r) => break r,
            minimald_rpc::Errorable::Err { error } => {
                if crate::should_retry_autogen(true, attempts, &error) {
                    attempts += 1;
                    config.name = Some(task_session_name(&args.task, &crate::random_hex4()));
                    continue;
                }
                bail!("CreateSession failed: {error}");
            }
        }
    };
    // A daemon too old to know the field ignored it and echoes no version;
    // that silence is the skew. Caught here, before the upload and the
    // finalize, with the record still unfinalized and reapable.
    minimal_client::ensure_version_reported(created.daemon_version.as_deref())?;
    let id = created.id;
    let session_name = config
        .name
        .clone()
        .expect("the task session is always named");

    // Until the session is Active, a Ctrl-C must abort the half-built
    // session exactly as during an activate.
    let interrupt_guard = crate::arm_activation_interrupt(global, id);

    if skip_empty_or_home {
        eprintln!("Starting with an empty box (nothing here to sync)");
    } else {
        if upload_root != utf8_path {
            eprintln!("Uploading from project root {upload_root} (resolved from {utf8_path})");
        }
        let headless = global.no_input || !crate::can_prompt_interactively();
        let should_upload = match crate::file_upload::upload_gate(
            crate::file_upload::is_vcs_root(upload_root.as_std_path()),
            false,
            crate::project_has_mfile(&upload_root),
            headless,
        ) {
            crate::file_upload::UploadGate::Upload => true,
            crate::file_upload::UploadGate::SkipHeadless => {
                eprintln!(
                    "{}",
                    crate::file_upload::skipped_upload_warning(upload_root.as_std_path())
                );
                false
            }
            crate::file_upload::UploadGate::Prompt => crate::confirm(
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
            eprintln!("Skipping file upload; the session will start with an empty workspace.");
        }
    }

    // Client-side loadout patches land in the composition whether the
    // configure response is Materialized or Pending; daemon-side patches
    // approved through a Pending gate are appended below.
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

    let configured = client
        .oneshot_rpc::<ConfigureLoadout>(ConfigureLoadoutRequest {
            session_id: id,
            contribution,
        })
        .await
        .context("ConfigureLoadout RPC failed")?;
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

    collected_patches.sort_by(|a, b| a.1.as_str().cmp(b.1.as_str()));
    collected_patches.dedup_by(|a, b| a.1.as_str() == b.1.as_str());
    if let Err(e) = crate::upload_and_finalize(
        &mut client,
        id,
        &collected_patches,
        &hook_scripts,
        finalize_hook_budget,
    )
    .await
    {
        crate::best_effort_destroy(&mut client, id).await;
        return Err(e);
    }

    // Active: from here an interrupt destroys (or, under `--keep`, keeps)
    // the session rather than aborting a draft.
    drop(interrupt_guard);
    let run_guard = arm_task_run_interrupt(global, id, session_name.clone(), args.keep);

    eprintln!("Running task {} in session {session_name}...", args.task);

    let outcome = match client
        .open_session_exec_channel(
            id,
            &minimald_rpc::exec::ExecRequest::TaskRun(args.task.clone()).encode(),
            &task_env,
        )
        .await
    {
        Ok(channel) => bridge_exec(channel).await,
        Err(e) => Err(e),
    };

    // Resolve the box — success, failure, or exec error alike — before the
    // exit code (or error) propagates.
    if args.keep {
        eprintln!("Session {session_name} kept — attach with: min session attach {session_name}");
    } else {
        crate::best_effort_destroy(&mut client, id).await;
    }
    drop(run_guard);

    exit_outcome(outcome?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The minted session name is `task-<task>-<hex>`, with the task name
    /// pushed through the same sanitizer as the activate autogen so it
    /// always clears `validate_session_name`.
    #[test]
    fn task_session_name_sanitizes_the_task_stem() {
        assert_eq!(task_session_name("build", "9c1e"), "task-build-9c1e");
        assert_eq!(task_session_name("My Task!", "4f2a"), "task-mytask-4f2a");
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

    /// The empty `[vars]` policy — a fresh install, where nothing is
    /// denied or ignored. The default for the resolution tests that are
    /// not about policy.
    fn no_vars_policy() -> sessions::core::policy::VarsPolicy {
        sessions::core::policy::VarsPolicy::empty()
    }

    /// Stand-in for the on-disk policy path, which only ever reaches the
    /// error message.
    fn policy_path_fixture() -> std::path::PathBuf {
        std::path::PathBuf::from("/cfg/minimal/user_policy.toml")
    }

    /// A policy that allows every name, for the resolution tests that are
    /// not about gating. An empty policy would refer everything to the
    /// hook, which is a different test.
    fn allow_all() -> sessions::core::policy::VarsPolicy {
        no_vars_policy().try_with_allow(["*"]).unwrap()
    }

    /// A task's `env_vars` always carry project provenance — the whole
    /// point of the gate is that the project is what it constrains.
    fn project_source() -> sessions::core::source::Source {
        sessions::core::source::Source::Project {
            path: paths::HostPath::try_new(camino::Utf8PathBuf::from("/home/dev/proj")).unwrap(),
        }
    }

    /// A hook that answers every referred name the same way, recording
    /// what it was asked about. Stands in for the interactive prompt.
    struct ScriptedHook {
        decision: sessions::core::decision::ItemDecision,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl ScriptedHook {
        fn new(decision: sessions::core::decision::ItemDecision) -> Self {
            Self {
                decision,
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl sessions::core::hooks::PolicyHooks for ScriptedHook {
        fn on_var_unapproved(
            &self,
            _policy: sessions::core::policy::VarsPolicy,
            items: &[sessions::core::hooks::Unapproved<'_, str>],
        ) -> sessions::core::hooks::HookResult<sessions::core::policy::VarsPolicy> {
            self.asked
                .borrow_mut()
                .extend(items.iter().map(|i| i.item().to_string()));
            sessions::core::hooks::HookResult::decided(vec![self.decision; items.len()])
        }

        fn on_patch_unapproved(
            &self,
            _policy: sessions::core::policy::PatchesPolicy,
            _items: &[sessions::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> sessions::core::hooks::HookResult<sessions::core::policy::PatchesPolicy> {
            unreachable!("task env resolution never gates patches")
        }
    }

    /// A hook that refuses to be asked — for the cases where the policy
    /// must decide on its own.
    struct NeverAsked;

    impl sessions::core::hooks::PolicyHooks for NeverAsked {
        fn on_var_unapproved(
            &self,
            _policy: sessions::core::policy::VarsPolicy,
            items: &[sessions::core::hooks::Unapproved<'_, str>],
        ) -> sessions::core::hooks::HookResult<sessions::core::policy::VarsPolicy> {
            panic!("the policy should have decided alone, was asked about {items:?}");
        }

        fn on_patch_unapproved(
            &self,
            _policy: sessions::core::policy::PatchesPolicy,
            _items: &[sessions::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> sessions::core::hooks::HookResult<sessions::core::policy::PatchesPolicy> {
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
        let hooks = ScriptedHook::new(sessions::core::decision::ItemDecision::AllowOnce);

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
        let hooks = ScriptedHook::new(sessions::core::decision::ItemDecision::IgnoreOnce);

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
        let hooks = ScriptedHook::new(sessions::core::decision::ItemDecision::AllowOnce);

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
            keep: false,
        };

        let err = cmd_task_run(&global, args)
            .await
            .expect_err("an undeclared task must be rejected before the daemon");
        let msg = err.to_string();
        assert!(msg.contains("unknown task 'deploy'"), "got: {msg}");
        assert!(msg.contains("declared tasks: build"), "got: {msg}");
    }
}
