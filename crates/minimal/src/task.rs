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

/// Verify `task` is declared in the project's `minimal.toml`, walking up
/// from `dir` like the activate config discovery does. Errors name the fix:
/// untrimmed name → the whitespace rejection; no config → `min init`;
/// unknown task → the declared list.
fn check_task_declared(dir: &camino::Utf8Path, task: &str) -> Result<(), anyhow::Error> {
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
    if file.task(task).is_none() {
        bail!(unknown_task_message(&file, task));
    }
    Ok(())
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
    check_task_declared(&utf8_path, &args.task)?;

    crate::ensure_daemon(global)?;

    let config = minimald_rpc::SessionConfig {
        name: Some(task_session_name(&args.task, &crate::random_hex4())),
        project_path: abs_path,
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
    let policy_path = crate::config::user_policy_path(global);
    let user_policy = crate::config::read_user_policy(global)?;
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
    let hook_scripts =
        crate::loadouts::stage_loadout_hook_scripts(&active, global, &utf8_path, true)?;

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

    let mut client = crate::connect_daemon(global).await?;

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
            headless,
        ) {
            crate::file_upload::UploadGate::Upload => true,
            crate::file_upload::UploadGate::SkipHeadless => {
                eprintln!(
                    "warning: {upload_root} is not a version control repository root; \
                     skipping file upload"
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
        minimald_rpc::Errorable::Err { error } => {
            bail!("ConfigureLoadout failed: {error}");
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
                        bail!("Composition gating failed: {e}");
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
        .open_session_exec_channel(id, &format!("min task run {}", args.task))
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
        let err = check_task_declared(camino::Utf8Path::new("/nonexistent-task-test"), "build ")
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
}
