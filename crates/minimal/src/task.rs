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
//! here — unless `--keep` retains it as an attachable session.
//!
//! Deliberately composed from the same client/RPC primitives `cmd_activate`
//! uses (`BoxConfig`, `CreateSession`, the upload gates,
//! `ConfigureLoadout`, the gating hooks, `FinalizeSession`) rather than
//! refactored out of it: a few duplicated lines of glue keep
//! `cmd_activate`'s diff at zero.

use std::io::{IsTerminal as _, Read as _};

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

/// The exec request a task run sends: the task, its declared arguments, plus
/// the owns-box flag — set unless `--keep` retains the session (NET-131). The
/// flag is what moves the destroy off this client: with it set, the daemon
/// ends the session once the task's exit status is on the wire, whether or
/// not this process is still there. `--keep` withholds it, because a kept
/// session is meant to outlive the run — its end stays with whoever holds it.
/// `cwd` is the invocation directory relative to the uploaded tree (see
/// [`task_run_cwd`]), where a task declaring `inherit_cwd` starts.
fn task_run_request(
    task: &str,
    args: &[String],
    keep: bool,
    cwd: String,
) -> minimald_rpc::exec::ExecRequest {
    minimald_rpc::exec::ExecRequest::TaskRun {
        task: task.to_string(),
        owns_box: !keep,
        args: args.to_vec(),
        cwd,
    }
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
    patch_paths: std::cell::RefCell<Vec<String>>,
}

impl RefuseAndRecord {
    fn recorded_names(&self) -> Vec<String> {
        self.names.borrow().clone()
    }

    fn recorded_patch_paths(&self) -> Vec<String> {
        self.patch_paths.borrow().clone()
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
        items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
    ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
        // Same record-and-refuse as the vars half: an unapproved patch
        // path must not reach the daemon's mount set, and the names land
        // in the operator's snippet instead.
        let mut paths = self.patch_paths.borrow_mut();
        for item in items {
            let path = item.item().to_string();
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        boxes::core::hooks::HookResult::Abort
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

/// Format refused patch paths as the `[patches] allow` snippet an
/// operator can paste — the patch-side sibling of
/// [`refused_vars_snippet`](fn@refused_vars_snippet), emitted through
/// `toml_edit` for the same escaping reason. Each path is written as a
/// pattern that matches only that path, as "allow always" records it, so a
/// `*`, `[` or `{` in a path neither widens the rule nor breaks the policy.
fn refused_patches_snippet(paths: &[String]) -> String {
    let mut doc = toml_edit::DocumentMut::new();
    let mut patches = toml_edit::Table::new();
    let mut allow = toml_edit::Array::new();
    for path in paths {
        allow.push(boxes::core::expansion::literal_policy_pattern(path));
    }
    patches.insert("allow", toml_edit::value(allow));
    doc.insert("patches", toml_edit::Item::Table(patches));
    doc.to_string()
}

/// Var lookup over the resolved task env plus the client's home: the
/// values a `[patches]` pattern's `$VAR` references expand against
/// client-side. Task vars are in because the task's own declarations can
/// name them; `HOME` is in because `~` in a pattern must expand to the
/// same directory the declared `~/` keys will.
struct TaskEnvLookup {
    vars: std::collections::BTreeMap<String, String>,
}

impl boxes::core::expansion::VarLookup for TaskEnvLookup {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }
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

/// The `[patches] deny` rejection body for a task patch: names the task,
/// the declared path, and the file the rule lives in. Split out for unit
/// tests.
fn denied_task_patch_message(task_name: &str, path: &str, policy_path: &std::path::Path) -> String {
    format!(
        "task '{task_name}' declares the patch path `{path}`, but it is \
         denied by `[patches] deny` in {policy}; remove the declaration, or \
         the deny rule if this task should mount it",
        policy = policy_path.display(),
    )
}

/// Gate a task's declared `patch.dir` / `patch.file` entries against
/// `[patches]`, the same two lanes as the `env_vars` gate above: the
/// interactive prompt on a real terminal, the collect-and-refuse
/// `RefuseAndRecord` anywhere else. Returns the verdict the daemon
/// applies: the raw declared keys the policy allowed, and those it
/// ignored, for the daemon to drop from the mount set. The daemon holds
/// no policy, mounts only allowed keys, and refuses a task whose patches
/// arrive with no verdict.
///
/// An echo task is gated like any other. The daemon answers one from the
/// declaration only when its session-workspace `minimal.toml` declares it
/// as an echo; a stack-provided echo task, or one whose workspace copy
/// differs, reaches the mount path and needs this verdict. A task that
/// declares no patches gets an empty verdict without a prompt.
fn resolve_task_patches(
    task: &mfile::Task,
    task_name: &str,
    patches_policy: boxes::core::policy::PatchesPolicy,
    policy_path: &std::path::Path,
    source: &boxes::core::source::Source,
    hooks: &dyn boxes::core::hooks::PolicyHooks,
    resolved_env: &minimald_rpc::taskenv::TaskEnv,
) -> Result<minimald_rpc::taskenv::PatchVerdict, anyhow::Error> {
    use boxes::core::compose::{TaskPatchEntry, gate_task_patch_paths};

    // The gate expands policy patterns through this lookup. A pattern
    // naming `$HOME` is the common case for patches, so the resolved
    // task vars share the lookup with the client's own home — the same
    // base the daemon expands `~/` keys against.
    let mut vars: std::collections::BTreeMap<String, String> = resolved_env.set.clone();
    if let Some(home) = std::env::var_os("HOME")
        && let Some(home) = home.to_str()
    {
        vars.insert("HOME".to_string(), home.to_string());
    }
    let lookup = TaskEnvLookup { vars };

    // Dir entries first, then files, each in declaration order — the
    // same order `to_fs_mappings` iterates when mounting.
    let mut entries: Vec<TaskPatchEntry<'_>> = Vec::new();
    for (key, setting) in &task.patch.dir {
        entries.push(TaskPatchEntry {
            declared: key,
            is_file: false,
            read_only: matches!(setting, mfile::PatchSetting::ReadOnly),
            source,
        });
    }
    for (key, setting) in &task.patch.file {
        entries.push(TaskPatchEntry {
            declared: key,
            is_file: true,
            read_only: matches!(setting, mfile::PatchSetting::ReadOnly),
            source,
        });
    }

    let home_fallback = std::env::var_os("HOME").and_then(|h| h.into_string().ok());
    let (verdicts, _policy) = match gate_task_patch_paths(
        &entries,
        patches_policy,
        Some(hooks),
        &lookup,
        home_fallback.as_deref(),
    ) {
        Ok(out) => out,
        Err(boxes::core::compose::ComposeError::Denied { what, .. }) => {
            bail!(denied_task_patch_message(task_name, &what, policy_path))
        }
        Err(boxes::core::compose::ComposeError::TaskPatchDotSegment { what, .. }) => {
            bail!(dot_segment_task_patch_message(task_name, &what))
        }
        Err(boxes::core::compose::ComposeError::TaskPatchUnchecked { what, gap, .. }) => {
            bail!(unchecked_task_patch_message(task_name, &what, &gap))
        }
        Err(boxes::core::compose::ComposeError::TaskPatchNotAbsolute { what, .. }) => {
            bail!(relative_task_patch_message(task_name, &what))
        }
        Err(boxes::core::compose::ComposeError::TaskPatchWritableDeny {
            what, pattern, ..
        }) => {
            bail!(writable_deny_task_patch_message(
                task_name,
                &what,
                &pattern,
                policy_path
            ))
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("gating `patch` for task '{task_name}'"));
        }
    };

    // Verdicts pair with `entries` in order, each naming its raw declared
    // key: an allowed one may mount, an ignored one the daemon removes. An
    // allowed one carries the kind and mode it was checked as, so the
    // daemon refuses a declaration that changed either since.
    let mut out = minimald_rpc::taskenv::PatchVerdict::default();
    for (entry, verdict) in entries.iter().zip(verdicts) {
        let key = entry.declared.to_string();
        match verdict {
            boxes::core::compose::NameVerdict::Allowed => {
                out.allow.insert(minimald_rpc::taskenv::AllowedPatch {
                    path: key,
                    is_file: entry.is_file,
                    read_only: entry.read_only,
                })
            }
            boxes::core::compose::NameVerdict::Ignored => {
                out.drop.insert(minimald_rpc::taskenv::DroppedPatch {
                    path: key,
                    is_file: entry.is_file,
                })
            }
        };
    }
    Ok(out)
}

/// The rejection body for a declared patch key holding a `.` or `..`
/// segment. Split out for unit tests.
fn dot_segment_task_patch_message(task_name: &str, path: &str) -> String {
    format!(
        "task '{task_name}' declares the patch path `{path}`, which holds a \
         `.` or `..` segment, so your [patches] policy cannot tell what it \
         mounts; declare the path it means without them"
    )
}

/// The rejection body for a declared patch key that is neither absolute
/// nor `~/`-rooted. Split out for unit tests.
fn relative_task_patch_message(task_name: &str, path: &str) -> String {
    format!(
        "task '{task_name}' declares the patch path `{path}`, which is not an \
         absolute path and does not start with `~/`, so your [patches] policy \
         cannot check it; declare the full path, starting with `/` or `~/`"
    )
}

/// The rejection body for a read-write patch directory that a `deny` rule
/// reaches into. Split out for unit tests.
fn writable_deny_task_patch_message(
    task_name: &str,
    path: &str,
    pattern: &str,
    policy_path: &std::path::Path,
) -> String {
    let next = if boxes::core::compose::deny_reaches_any_dir(pattern) {
        "This rule can match inside any directory, so declare the directory \"ro\""
    } else {
        "Declare the directory \"ro\", or declare a directory that leaves those paths out"
    };
    format!(
        "task '{task_name}' declares the read-write patch directory `{path}`. \
         The task can create files in it that the `[patches] deny` rule \
         `{pattern}` in {policy} forbids. {next}",
        policy = policy_path.display(),
    )
}

/// The rejection body for a declared patch directory whose files could
/// not all be checked against `[patches] deny`. Split out for unit tests.
fn unchecked_task_patch_message(
    task_name: &str,
    path: &str,
    gap: &boxes::core::compose::TaskPatchWalkGap,
) -> String {
    use boxes::core::compose::TaskPatchWalkGap;
    match gap {
        TaskPatchWalkGap::TooLarge { limit } => format!(
            "task '{task_name}': cannot check every file in patch directory {path} \
             against your [patches] deny rules: it holds more than {limit} entries. \
             Declare a smaller directory inside it, the part the task needs."
        ),
        TaskPatchWalkGap::Unreadable { dir, error } => format!(
            "task '{task_name}': cannot check patch directory {path} against your \
             [patches] deny rules: {dir} cannot be read ({error}). Make it readable, \
             or declare a directory that leaves it out."
        ),
        TaskPatchWalkGap::NotADirectory => format!(
            "task '{task_name}': patch directory {path} is a file, not a directory. \
             Declare it under patch.file instead."
        ),
    }
}

/// Why a policy refusal could not become a prompt, for the refusal text:
/// `--no-input` when the user set it, otherwise the terminal check.
fn no_prompt_reason(no_input: bool) -> &'static str {
    if no_input {
        "--no-input is set"
    } else {
        "stdin/stderr is not a terminal"
    }
}

/// The non-interactive lane of [`resolve_task_patches`]: gate against a
/// collect-and-refuse hook, and turn a refusal into the `[patches] allow`
/// snippet the operator pastes. The recorded paths are read before the
/// gate's own result, which is the abort error once the hook refused.
fn resolve_task_patches_non_interactive(
    task: &mfile::Task,
    task_name: &str,
    patches_policy: boxes::core::policy::PatchesPolicy,
    policy_path: &std::path::Path,
    source: &boxes::core::source::Source,
    resolved_env: &minimald_rpc::taskenv::TaskEnv,
    no_input: bool,
) -> Result<minimald_rpc::taskenv::PatchVerdict, anyhow::Error> {
    let hooks = RefuseAndRecord::default();
    let verdict = resolve_task_patches(
        task,
        task_name,
        patches_policy,
        policy_path,
        source,
        &hooks,
        resolved_env,
    );
    let refused = hooks.recorded_patch_paths();
    if !refused.is_empty() {
        let count = refused.len();
        let snippet = refused_patches_snippet(&refused);
        bail!(
            "task '{task_name}' declares {count} patch{es} that your policy does \
             not allow, and {reason}.\n\n\
             Add the following to {path}:\n\n{snippet}\n\
             Then re-run this command.",
            reason = no_prompt_reason(no_input),
            path = policy_path.display(),
            es = if count == 1 { "" } else { "es" },
        );
    }
    verdict
}

/// Gate a task's declared patches for `min session run`, which runs a task
/// in a session that already exists: the task as the session project's
/// `minimal.toml` declares it on this machine, through the same two lanes
/// as `min task run`, saving any rule the user records at the prompt.
///
/// A task this machine cannot find declared (one a stack provides, or a
/// project whose `minimal.toml` is gone) gets an empty verdict rather than
/// an error. The daemon still runs it when it declares no patches, and
/// refuses it when it does, since nothing here checked them. A
/// `minimal.toml` that cannot be read is a different case: its error is
/// returned, since it is the real cause of any refusal that follows.
pub(crate) fn gate_session_task_patches(
    global: &GlobalArgs,
    project_path: &camino::Utf8Path,
    task_name: &str,
) -> Result<minimald_rpc::taskenv::PatchVerdict, anyhow::Error> {
    let file = match mfile::File::from_dir_recursive(project_path.as_std_path()) {
        Ok(file) => file,
        Err(mfile::Error::NotFound) => return Ok(minimald_rpc::taskenv::PatchVerdict::default()),
        Err(e) => bail!(
            "cannot check the patch paths of task '{task_name}': the {name} for \
             {project_path} cannot be read: {e}",
            name = mfile::MFILE_NAME,
        ),
    };
    let Some(declared) = file.task(task_name) else {
        return Ok(minimald_rpc::taskenv::PatchVerdict::default());
    };
    if declared.patch.dir.is_empty() && declared.patch.file.is_empty() {
        return Ok(minimald_rpc::taskenv::PatchVerdict::default());
    }
    let policy_path = crate::config::user_policy_path(global);
    let user_policy = crate::config::read_user_policy(global)?;
    let source = boxes::core::source::Source::Project {
        path: paths::HostPath::try_new(project_path.to_path_buf())
            .context("Invalid project path")?,
    };
    // No env resolution on this lane: `min session run` leaves a task's
    // `env_vars` to the daemon, so only HOME feeds a pattern's `$VAR`.
    let resolved_env = minimald_rpc::taskenv::TaskEnv::default();
    if global.no_input || !crate::can_prompt_interactively() {
        return resolve_task_patches_non_interactive(
            &declared,
            task_name,
            user_policy.patches().clone(),
            &policy_path,
            &source,
            &resolved_env,
            global.no_input,
        );
    }
    let hooks = crate::prompt::InteractivePrompt::new(&policy_path, user_policy.clone());
    let verdict = resolve_task_patches(
        &declared,
        task_name,
        user_policy.patches().clone(),
        &policy_path,
        &source,
        &hooks,
        &resolved_env,
    );
    // Persist before propagating a refusal, as `min task run` does.
    let after = hooks.into_final_policy();
    if after != user_policy {
        match crate::prompt::save_user_policy(&policy_path, &after) {
            Ok(()) => eprintln!("Updated {}", policy_path.display()),
            Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
        }
    }
    verdict
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

/// Guard that resolves the ephemeral session if the user interrupts the run
/// phase, modeled on [`crate::arm_activation_interrupt`]: the primary
/// connection is parked in the exec bridge, so the handler works over a
/// fresh connection. Without `--keep` the first Ctrl-C best-effort
/// `DestroySession`s the box and releases the name hold an attach or exec
/// may have re-made for it ([`release_task_name_hold`]); with it the
/// session is left alive and the
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
    session_id: boxes::SessionId,
    session_name: String,
    keep: bool,
) -> TaskRunInterrupt {
    let sock =
        crate::client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd());
    let control_sock = crate::vm_host_control_sock(
        crate::daemon_provider_kind(global),
        global.minimal_dir.as_deref(),
    );
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
            // The run's own return never comes on this path, so the release
            // it owes is made here, inside the same bound.
            release_task_name_hold(control_sock, session_id, &session_name, false).await;
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

/// Run a declared task in an ephemeral session: create, upload, exec the
/// canonical in-box `min task run <task>`, relay its exit code, and let the
/// daemon end the session with the run (NET-131) — or keep it with `--keep`.
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
    let source = boxes::core::source::Source::Project {
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
        let refused = hooks.recorded_names();
        if !refused.is_empty() {
            let count = refused.len();
            let snippet = refused_vars_snippet(&refused);
            bail!(
                "task '{task}' declares {count} environment variable{s} that your \
                 policy does not allow, and {reason}.\n\n\
                 Add the following to {path}:\n\n{snippet}\n\
                 Then re-run this command.",
                reason = no_prompt_reason(global.no_input),
                task = args.task,
                path = policy_path.display(),
                s = if count == 1 { "" } else { "s" },
            );
        }
        let mut task_env = task_env?;
        task_env.patch = Some(resolve_task_patches_non_interactive(
            &declared,
            &args.task,
            user_policy.patches().clone(),
            &policy_path,
            &source,
            &task_env,
            global.no_input,
        )?);
        (task_env, user_policy)
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
        // Same lane for patches, against the same interactive hook, so a
        // rule the user records for a patch lands in the same policy
        // save as a rule recorded for a variable. Gated only once the
        // vars resolved; either error is held until after the save.
        let gated = task_env.and_then(|mut task_env| {
            task_env.patch = Some(resolve_task_patches(
                &declared,
                &args.task,
                user_policy.patches().clone(),
                &policy_path,
                &source,
                &hooks,
                &task_env,
            )?);
            Ok(task_env)
        });
        // Persist before propagating a refusal: a rule the user chose to
        // record is theirs whether or not this run goes on to fail.
        let after = hooks.into_final_policy();
        if after != user_policy {
            match crate::prompt::save_user_policy(&policy_path, &after) {
                Ok(()) => eprintln!("Updated {}", policy_path.display()),
                Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
            }
        }
        (gated?, after)
    };

    crate::ensure_daemon(global)?;

    let config = minimald_rpc::BoxConfig {
        name: Some(task_session_name(&args.task, &crate::random_hex4())),
        project_path: abs_path.clone(),
        network: boxes::NetworkMode::HostNet,
        policy: boxes::BoxPolicy::default(),
        task_addresses: Vec::new(),
        box_id: None,
        box_addresses: None,
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
    // Sent only for a task that declares `inherit_cwd`; any other task
    // starts at the root of the uploaded tree.
    let task_cwd = if declared.inherit_cwd {
        task_run_cwd(&upload_root, &utf8_path)
    } else {
        String::new()
    };
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
            .map_err(|error| crate::session_rpc_failed(crate::SessionRpc::CreateSession, error))?;
        match resp {
            minimald_rpc::Errorable::Ok(r) => break r,
            minimald_rpc::Errorable::Err { error } => {
                if crate::should_retry_autogen(true, attempts, &error) {
                    attempts += 1;
                    config.name = Some(task_session_name(&args.task, &crate::random_hex4()));
                    continue;
                }
                bail!("{error}");
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
            &task_run_request(&args.task, &args.args, args.keep, task_cwd).encode(),
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
            if !args.keep {
                crate::best_effort_destroy(&mut client, id).await;
            }
            Err(e)
        }
    };

    // A run that bridged ends its own box from the daemon's side of the
    // exec's exit (NET-131) — destroying here too would race it and undo
    // the point of the flag: a client killed mid-run must strand nothing.
    // `--keep` retains the session as an attachable box instead.
    if args.keep {
        eprintln!("Session {session_name} kept — attach with: min session attach {session_name}");
    }
    release_task_name_hold(
        crate::vm_host_control_sock(
            crate::daemon_provider_kind(global),
            global.minimal_dir.as_deref(),
        ),
        id,
        &session_name,
        args.keep,
    )
    .await;
    drop(run_guard);

    exit_outcome(outcome?)
}

/// Releases the name hold a finished run's session may carry on the VM
/// host daemon, best-effort. A task run holds no name of its own, but a
/// `min session attach` or `min exec` into its running session re-makes
/// one (`rehold_held_name_before_attach` cannot tell a task session
/// apart), and the daemon ends the session with the run, where no client
/// destroy releases it; an interrupted run's raw `DestroySession` releases
/// nothing either, so its handler calls this too. The release is by the
/// session's `id`, so it frees
/// only this session's hold, and a name nothing held is the goal state
/// already holding. `keep` withholds it: a kept session lives on, and its
/// destroy releases its hold.
pub(crate) async fn release_task_name_hold(
    control_sock: Option<std::path::PathBuf>,
    id: boxes::SessionId,
    name: &str,
    keep: bool,
) {
    if keep {
        return;
    }
    crate::release_held_box_name(control_sock, id, Some(name), None).await;
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

    /// NET-131 from the client side: a `min task run` that does not `--keep`
    /// sends the owns-box flag, which is what moves the destroy to the
    /// daemon — it ends the session once the task's exit status is on the
    /// wire, whether or not this client is still there. `--keep` withholds
    /// the flag, because a kept session is meant to outlive the run; its end
    /// stays with whoever holds it. The daemon-backed half — the box actually
    /// ending — needs a live daemon and is covered by the `minimald` exec
    /// tests and the session e2e, not a unit test.
    #[test]
    fn task_run_leaves_destroy_to_daemon() {
        use minimald_rpc::exec::ExecRequest;

        // A normal run: the request names the box as the run's own.
        let req = task_run_request("build", &[], false, String::new());
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
        assert_eq!(ExecRequest::parse(&req.encode()), Ok(req.clone()));

        // `--keep` keeps the box: no owns-box flag, nothing ends it here.
        let kept = task_run_request("build", &[], true, String::new());
        assert_eq!(
            kept,
            ExecRequest::TaskRun {
                task: "build".to_string(),
                owns_box: false,
                args: vec![],
                cwd: String::new(),
            }
        );
        assert_eq!(ExecRequest::parse(&kept.encode()), Ok(kept));
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
            false,
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
        /// Answers patch-path referrals the same way as names; `None`
        /// (the default) refuses them, standing in for the
        /// non-interactive lane's collect-and-refuse.
        patch_decision: Option<boxes::core::decision::ItemDecision>,
        asked_paths: std::cell::RefCell<Vec<String>>,
    }

    impl ScriptedHook {
        fn new(decision: boxes::core::decision::ItemDecision) -> Self {
            Self {
                decision,
                asked: std::cell::RefCell::new(Vec::new()),
                patch_decision: None,
                asked_paths: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn allowing_patches(mut self) -> Self {
            self.patch_decision = Some(boxes::core::decision::ItemDecision::AllowOnce);
            self
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }

        fn asked_paths(&self) -> Vec<String> {
            self.asked_paths.borrow().clone()
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
            items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
            match self.patch_decision {
                Some(d) => {
                    self.asked_paths
                        .borrow_mut()
                        .extend(items.iter().map(|i| i.item().to_string()));
                    boxes::core::hooks::HookResult::decided(vec![d; items.len()])
                }
                None => boxes::core::hooks::HookResult::Abort,
            }
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
            items: &[boxes::core::hooks::Unapproved<'_, camino::Utf8Path>],
        ) -> boxes::core::hooks::HookResult<boxes::core::policy::PatchesPolicy> {
            panic!("the policy should have decided alone, was asked about {items:?}");
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
            hooks.recorded_names(),
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
            hooks.recorded_names().is_empty(),
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

    /// A patch directory the deny probe could not finish is refused with
    /// the reason, and the refusal never suggests dropping a deny rule.
    #[test]
    fn an_unchecked_patch_directory_is_reported_with_the_reason() {
        use boxes::core::compose::TaskPatchWalkGap;
        let msg = unchecked_task_patch_message(
            "t",
            "/data",
            &TaskPatchWalkGap::TooLarge { limit: 100_000 },
        );
        assert_eq!(
            msg,
            "task 't': cannot check every file in patch directory /data against your \
             [patches] deny rules: it holds more than 100000 entries. Declare a smaller \
             directory inside it, the part the task needs."
        );
        let msg = unchecked_task_patch_message(
            "t",
            "/data",
            &TaskPatchWalkGap::Unreadable {
                dir: "/data/locked".to_owned(),
                error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
        );
        assert_eq!(
            msg,
            "task 't': cannot check patch directory /data against your [patches] deny \
             rules: /data/locked cannot be read (permission denied). Make it readable, or \
             declare a directory that leaves it out."
        );
        let msg = unchecked_task_patch_message("t", "/data", &TaskPatchWalkGap::NotADirectory);
        assert_eq!(
            msg,
            "task 't': patch directory /data is a file, not a directory. Declare it under \
             patch.file instead."
        );
    }

    /// A denied patch path is reported with the task, the declared path,
    /// and the policy file the rule lives in.
    #[test]
    fn a_denied_patch_is_reported_with_the_policy_file() {
        let msg = denied_task_patch_message("t", "/etc/secrets", &policy_path_fixture());
        assert!(msg.contains("task 't'"), "names the task: {msg}");
        assert!(msg.contains("/etc/secrets"), "names the path: {msg}");
        assert!(msg.contains("[patches] deny"), "names the rule: {msg}");
        assert!(
            msg.contains("user_policy.toml"),
            "names the policy file: {msg}"
        );
    }

    /// A declared patch the policy denies fails the gate client-side, and
    /// the hook is never consulted — the same short-circuit as a denied
    /// variable.
    #[test]
    fn a_denied_task_patch_fails_the_gate_before_the_hook() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\"/etc/passwd\" = \"ro\"\n",
        );
        // Pinned: the fixture must declare a patch, not just an exec.
        assert!(task.patch.file.contains_key("/etc/passwd"));
        let policy = boxes::core::policy::PatchesPolicy::default()
            .with_deny(vec!["/etc/passwd".to_string()]);

        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a denied patch must fail the gate");

        let msg = err.to_string();
        assert!(
            msg.contains("patch path `/etc/passwd`"),
            "names the declared path: {msg}"
        );
        assert!(msg.contains("[patches] deny"), "names the rule: {msg}");
    }

    /// The refusal snippet is the `[patches] allow` block an operator
    /// pastes, and stays valid TOML for a path that needs escaping.
    #[test]
    fn the_patch_refusal_snippet_is_pasteable_toml() {
        let snippet = refused_patches_snippet(&["/etc/secrets".to_string()]);
        assert!(snippet.contains("[patches]"), "{snippet}");
        assert!(snippet.contains("/etc/secrets"), "{snippet}");
        let parsed: toml::Value = toml::from_str(&snippet).expect("snippet must parse");
        assert!(parsed.get("patches").is_some());
    }

    /// The non-interactive patch hook refuses and records, the same
    /// contract as its vars half: nothing reaches the daemon's mount set,
    /// and the paths land in the snippet the caller builds.
    #[test]
    fn the_non_interactive_patch_hook_refuses_and_records() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\"/opt/tool/bin\" = \"ro\"\n",
        );
        let hooks = RefuseAndRecord::default();

        let err = resolve_task_patches(
            &task,
            "t",
            boxes::core::policy::PatchesPolicy::default(),
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a refusing hook must fail the run");

        let chain = format!("{err:#}");
        assert!(chain.contains("patch"), "names the gate: {chain}");
        assert_eq!(
            hooks.recorded_patch_paths(),
            vec!["/opt/tool/bin".to_string()],
            "the refused paths are what the caller's snippet is built from",
        );
    }

    /// The non-interactive lane surfaces the `[patches] allow` snippet,
    /// not the hook's abort: the recorded paths are read before the gate's
    /// own error is propagated.
    #[test]
    fn the_non_interactive_patch_refusal_carries_the_allow_snippet() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\"/opt/tool/bin\" = \"ro\"\n",
        );

        let err = resolve_task_patches_non_interactive(
            &task,
            "t",
            boxes::core::policy::PatchesPolicy::default(),
            &policy_path_fixture(),
            &project_source(),
            &minimald_rpc::taskenv::TaskEnv::default(),
            true,
        )
        .expect_err("an unapproved patch must fail the run");

        let msg = err.to_string();
        assert!(msg.contains("task 't' declares 1 patch "), "{msg}");
        assert!(msg.contains("[patches]"), "carries the snippet: {msg}");
        assert!(msg.contains("/opt/tool/bin"), "names the path: {msg}");
        assert!(msg.contains("user_policy.toml"), "names the file: {msg}");
        assert!(msg.contains("--no-input is set"), "names the cause: {msg}");
    }

    /// The refusal names what stopped the prompt: `--no-input` when the
    /// user set it, so a user at a terminal is not told it is missing.
    #[test]
    fn the_refusal_names_the_cause_of_no_prompt() {
        assert_eq!(no_prompt_reason(true), "--no-input is set");
        assert_eq!(no_prompt_reason(false), "stdin/stderr is not a terminal");
    }

    /// A declared key with a `..` segment is refused with a message that
    /// names the task and the path, before any policy decision.
    #[test]
    fn a_dot_dot_patch_key_is_refused_by_name() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\
             \"/tmp/../etc/shadow\" = \"rw\"\n",
        );
        let policy =
            boxes::core::policy::PatchesPolicy::default().with_allow(vec!["/tmp/**".to_string()]);

        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a `..` key must fail the gate");

        let msg = err.to_string();
        assert!(msg.contains("task 't'"), "{msg}");
        assert!(msg.contains("`/tmp/../etc/shadow`"), "{msg}");
        assert!(msg.contains("`..` segment"), "{msg}");
    }

    /// A relative key would be mounted against the daemon's working
    /// directory, where no rule reaches, so it is refused by name.
    #[test]
    fn a_relative_patch_key_is_refused_by_name() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.dir]\n\"root/.cache\" = \"rw\"\n",
        );
        let policy =
            boxes::core::policy::PatchesPolicy::default().with_allow(vec!["**".to_string()]);
        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a relative key must fail the gate");
        let msg = err.to_string();
        assert!(msg.contains("`root/.cache`"), "{msg}");
        assert!(msg.contains("start with `~/`"), "{msg}");
    }

    /// A read-write directory a deny rule reaches into is refused, naming
    /// the rule and the way out, even though the file does not exist yet.
    #[test]
    fn a_writable_directory_under_a_deny_is_refused_naming_the_rule() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.dir]\n\
             \"/nonexistent-min-test/home\" = \"rw\"\n",
        );
        let policy = boxes::core::policy::PatchesPolicy::default()
            .with_allow(vec!["/nonexistent-min-test/**".to_string()])
            .with_deny(vec!["/nonexistent-min-test/home/.ssh/**".to_string()]);
        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a writable directory under a deny must fail the gate");
        let msg = err.to_string();
        assert!(
            msg.contains("`/nonexistent-min-test/home/.ssh/**`"),
            "{msg}"
        );
        assert!(msg.contains("\"ro\""), "{msg}");
    }

    /// A deny rule with no fixed directory, such as `**/*.pem`, reaches
    /// into every read-write directory, so the refusal asks for "ro" only
    /// and does not suggest declaring another directory.
    #[test]
    fn a_writable_directory_under_a_deny_anywhere_asks_for_ro_only() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.dir]\n\
             \"/nonexistent-min-test/cache\" = \"rw\"\n",
        );
        let policy = boxes::core::policy::PatchesPolicy::default()
            .with_allow(vec!["/nonexistent-min-test/**".to_string()])
            .with_deny(vec!["**/*.pem".to_string()]);
        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a writable directory under a deny anywhere must fail the gate");
        let msg = err.to_string();
        assert!(msg.contains("`**/*.pem`"), "{msg}");
        assert!(msg.contains("can match inside any directory"), "{msg}");
        assert!(msg.contains("\"ro\""), "{msg}");
        assert!(!msg.contains("leaves those paths out"), "{msg}");
    }

    /// A glob metacharacter in a refused path is escaped in the snippet,
    /// so the rule matches that one path and the policy still loads.
    #[test]
    fn the_patch_refusal_snippet_escapes_glob_metacharacters() {
        let path = "/srv/a*b[1]{c,d}".to_string();
        let snippet = refused_patches_snippet(std::slice::from_ref(&path));
        let parsed: toml::Value = toml::from_str(&snippet).expect("snippet must parse");
        let rule = parsed["patches"]["allow"][0]
            .as_str()
            .expect("one rule")
            .to_owned();
        assert_ne!(rule, path, "{snippet}");
        let set = boxes::core::primitives::FileSet::try_new(rule.clone()).expect("rule compiles");
        assert!(set.is_match(&path), "{rule}");
        assert!(!set.is_match("/srv/aXb1c"), "{rule}");
    }

    /// `min session run` gates the task as the session project declares
    /// it: a task with no patches, or one this machine cannot find, gets
    /// an empty verdict; a declared patch the policy does not allow is
    /// refused non-interactively with the snippet.
    #[test]
    fn session_run_gates_the_project_tasks_patches() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        std::fs::write(
            dir.join(mfile::MFILE_NAME),
            "[tasks.plain]\nexec = 'true'\n\
             [tasks.mounts]\nexec = 'true'\n[tasks.mounts.patch.file]\n\
             \"/opt/tool/bin\" = \"ro\"\n",
        )
        .unwrap();
        let config = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            config_dir: Some(config.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };

        let empty = minimald_rpc::taskenv::PatchVerdict::default();
        assert_eq!(
            gate_session_task_patches(&global, dir, "plain").unwrap(),
            empty
        );
        assert_eq!(
            gate_session_task_patches(&global, dir, "from-a-stack").unwrap(),
            empty,
            "an undeclared task is left to the daemon, which refuses its patches"
        );
        let err = gate_session_task_patches(&global, dir, "mounts")
            .expect_err("an unapproved patch must fail the run");
        let msg = err.to_string();
        assert!(msg.contains("task 'mounts' declares 1 patch "), "{msg}");
        assert!(msg.contains("/opt/tool/bin"), "{msg}");
    }

    /// A broken `minimal.toml` is reported as the cause, not left for the
    /// daemon to refuse the task for a reason that hides it.
    #[test]
    fn session_run_reports_a_broken_project_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path()).unwrap();
        std::fs::write(dir.join(mfile::MFILE_NAME), "[tasks.t\n").unwrap();
        let config = tempfile::tempdir().unwrap();
        let global = GlobalArgs {
            config_dir: Some(config.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let err = gate_session_task_patches(&global, dir, "t")
            .expect_err("a broken minimal.toml must fail the run");
        let msg = err.to_string();
        assert!(msg.contains("task 't'"), "{msg}");
        assert!(msg.contains("cannot be read"), "{msg}");
    }

    /// An ignored patch path lands in the drop list the daemon removes
    /// from the mount set, keyed exactly as declared.
    #[test]
    fn an_ignored_task_patch_lands_in_the_drop_list() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\"/opt/tool/bin\" = \"ro\"\n\
             [tasks.t.patch.dir]\n\"/opt/cache\" = \"rw\"\n",
        );
        let policy =
            boxes::core::policy::PatchesPolicy::default().with_ignore(vec!["/opt/**".to_string()]);

        let verdict = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect("ignored entries drop, they do not fail");

        let expect: std::collections::BTreeSet<_> =
            [("/opt/tool/bin", true), ("/opt/cache", false)]
                .map(|(path, is_file)| minimald_rpc::taskenv::DroppedPatch {
                    path: path.to_string(),
                    is_file,
                })
                .into_iter()
                .collect();
        assert_eq!(
            verdict.drop, expect,
            "raw declared keys, verbatim, with their kind"
        );
        assert!(verdict.allow.is_empty(), "nothing ignored is allowed");
    }

    /// An echo task's patches are gated like any other task's: the daemon
    /// short-circuits only an echo its workspace `minimal.toml` declares,
    /// so a stack-provided one reaches the mount path and needs a verdict.
    #[test]
    fn an_echo_task_gates_its_patches_like_any_task() {
        let task = task_from_toml(
            "[tasks.t]\necho = 'hi'\n[tasks.t.patch.file]\n\"/etc/passwd\" = \"ro\"\n",
        );
        assert_eq!(task.action.as_echo(), Some("hi"));
        let policy = boxes::core::policy::PatchesPolicy::default()
            .with_deny(vec!["/etc/passwd".to_string()]);

        let err = resolve_task_patches(
            &task,
            "t",
            policy,
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect_err("a denied patch on an echo task must fail the run");
        assert!(err.to_string().contains("`/etc/passwd`"), "{err}");
    }

    /// An echo task that declares no patches gets an empty verdict and no
    /// prompt, so gating it costs nothing.
    #[test]
    fn an_echo_task_without_patches_gets_an_empty_verdict() {
        let task = task_from_toml("[tasks.t]\necho = 'hi'\n");
        assert_eq!(task.action.as_echo(), Some("hi"));

        let verdict = resolve_task_patches(
            &task,
            "t",
            boxes::core::policy::PatchesPolicy::default(),
            &policy_path_fixture(),
            &project_source(),
            &NeverAsked,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect("nothing to gate");

        assert_eq!(
            verdict,
            minimald_rpc::taskenv::PatchVerdict::default(),
            "nothing to send"
        );
    }

    /// The interactive lane's hook approves an undecided patch on the
    /// spot, and an approved patch is kept — it must not land in the
    /// drop list the daemon removes from the mount set.
    #[test]
    fn an_approved_task_patch_is_kept_out_of_the_drop_list() {
        let task = task_from_toml(
            "[tasks.t]\nexec = 'true'\n[tasks.t.patch.file]\n\"/opt/tool/bin\" = \"ro\"\n",
        );
        let hooks =
            ScriptedHook::new(boxes::core::decision::ItemDecision::AllowOnce).allowing_patches();

        let verdict = resolve_task_patches(
            &task,
            "t",
            boxes::core::policy::PatchesPolicy::default(),
            &policy_path_fixture(),
            &project_source(),
            &hooks,
            &minimald_rpc::taskenv::TaskEnv::default(),
        )
        .expect("an approved patch runs");

        assert_eq!(
            hooks.asked_paths(),
            vec!["/opt/tool/bin".to_string()],
            "the prompt was about the declared path"
        );
        assert!(verdict.drop.is_empty(), "an approved patch is not dropped");
        assert!(
            verdict.allows("/opt/tool/bin", true, true),
            "an approved patch is named as allowed, with its kind and mode, or the daemon \
             refuses it"
        );
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
            keep: false,
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
            keep: false,
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
