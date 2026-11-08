use super::*;

/// Whether the project already has a `minimal.toml`, in either the root
/// (`<project>/minimal.toml`) or `.minimal/`
/// (`<project>/.minimal/minimal.toml`) layout.
///
/// Uses [`mfile::File::from_dir`] — the same resolver the CLI loads config
/// with — rather than a naive `join(MFILE_NAME)`, so detection matches the
/// path the init writer would target and we never scaffold over a config
/// living under `.minimal/`. Any outcome other than [`mfile::Error::NotFound`]
/// (including a present-but-malformed file) counts as "exists".
pub(crate) fn project_has_mfile(project_path: &camino::Utf8Path) -> bool {
    !matches!(
        mfile::File::from_dir(project_path.as_std_path()),
        Err(mfile::Error::NotFound)
    )
}

/// Whether `--sync none` will silently discard a project config: true when a
/// `minimal.toml` is found walking up from `dir`. The notice is only worth
/// printing when there is a config to lose, so this mirrors
/// [`project_has_mfile`]'s "any outcome other than NotFound counts as
/// present" rule, but walks up the tree the way [`resolve_upload_root`] does.
pub(crate) fn sync_none_drops_project_config(dir: &camino::Utf8Path) -> bool {
    !matches!(
        mfile::File::from_dir_recursive(dir.as_std_path()),
        Err(mfile::Error::NotFound)
    )
}

/// The notice `min activate --sync none` prints, or `None` when there is no
/// project config up the tree for it to drop.
pub(crate) fn sync_none_notice(dir: &camino::Utf8Path) -> Option<&'static str> {
    sync_none_drops_project_config(dir).then_some(
        "--sync none: this project's minimal.toml is not sent; the session uses a default \
         project configuration (its packages, vars, patches and hooks are not applied)",
    )
}

/// Offer to initialize a `minimal.toml` at the project path when it has
/// none, on the way into an activation or a `min add`.
///
/// Purely an offer: declining or skipping returns `Ok` and leaves the
/// project untouched. `decline_notice`, when `Some`, is printed in that
/// case. `min session activate` passes the session-specific wording; `min
/// add` passes `None` and reports its own `min init` hint if the project
/// still has no config afterwards.
///
/// The daemon never reads this path — it is a path on the *client's*
/// machine — and fabricates a default shell-stack `minimal.toml` inside the
/// session's own workspace instead, so a session comes up either way.
/// Scaffolding here is a convenience for the interactive case (the project
/// gets a real config it can grow), not a precondition.
pub(crate) fn offer_mfile_scaffold(
    project_path: &camino::Utf8Path,
    global: &GlobalArgs,
    decline_notice: Option<&str>,
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
        if let Some(notice) = decline_notice {
            eprintln!("{notice}");
        }
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
    // stderr, unlike `cmd_init`: this scaffold runs inside `min activate`,
    // whose stdout is reserved for the bare session id that scripted callers
    // read (`id=$(min activate)`). A result line on stdout here would land
    // ahead of that id and corrupt the capture.
    // The legacy shape: session start reads packages from `[session]`, and
    // box creation does not read `[defaults.<type>]` yet. #2418 (BOX T21)
    // wires the expanded spec into box creation. When it lands, pass `true`
    // here and in `cmd_init`, and then remove the `entry_shape` parameter of
    // `run_init_flow`.
    if let Some(line) = run_init_flow(config, false, false, INIT_ENTRY_SHAPE)?.result_line() {
        eprintln!("{line}");
    }
    Ok(())
}

/// Resolves the directory whose tree should be uploaded as the session
/// workspace, walking up from `dir` to the nearest `minimal.toml` and using
/// its repo root. Falls back to `dir` itself when no mfile is found, so a
/// project without one still activates — the daemon fabricates a default
/// config inside the session workspace. Any other mfile error (malformed
/// TOML, I/O) is propagated: a broken config in an ancestor should fail
/// loudly rather than silently uploading a subdir with no config.
pub(crate) fn resolve_upload_root(
    dir: &camino::Utf8Path,
) -> Result<camino::Utf8PathBuf, anyhow::Error> {
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

/// Counts the lifecycle hooks declared in the project's `[session]` block
/// at `root`. Zero when there is no mfile there, no `[session]` block, or
/// the block declares none.
///
/// The project's hooks reach the daemon only inside the workspace tree
/// upload — the daemon composes them from the uploaded `minimal.toml` — so
/// this count is exactly what a skipped upload would silently discard. A
/// malformed mfile is already rejected by [`resolve_upload_root`] before
/// this runs, so any load error here can only mean "no readable hooks to
/// lose" and maps to zero rather than a second failure surface.
pub(crate) fn project_lifecycle_hook_count(root: &camino::Utf8Path) -> usize {
    match mfile::File::from_dir(root.as_std_path()) {
        Ok(file) => file.session.map_or(0, |s| s.lifecycle_hooks.len()),
        Err(_) => 0,
    }
}

/// What [`decide_workspace_upload`] decided to do about the workspace upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadDecision {
    /// Upload from the resolved root.
    Upload,
    /// Empty dir or `$HOME`: skip silently.
    SkipEmptyOrHome,
    /// Non-VCS, no `minimal.toml`, headless: skip with the shared warning.
    SkipUndeclared,
    /// Non-VCS, no `minimal.toml`, interactive: confirm before uploading.
    Confirm,
    /// The user answered that confirm with no: nothing is uploaded and the
    /// session starts on an empty workspace. Kept apart from
    /// [`Self::SkipUndeclared`], the *headless* skip, which is nobody's
    /// choice: a deliberate decline is never refused, and never reads as one.
    Declined,
}

/// The upload decision, resolved from inputs that need no TTY. [`resolve_upload_root`]
/// already ran, so this folds the empty/`$HOME` carve-out and
/// [`file_upload::upload_gate`] into one value the callers can act on: the
/// interactive `Confirm` case is resolved by the caller (the CLI prompts, the
/// dashboard asks its own UI), and nothing here touches the daemon.
///
/// `home` is the reader for `$HOME`, passed in rather than read here so the
/// carve-out is testable off this machine's own home directory.
pub(crate) fn decide_workspace_upload(
    root: &camino::Utf8Path,
    sync_explicit: bool,
    headless: bool,
    home: Option<&std::path::Path>,
) -> UploadDecision {
    // An empty box has nothing to sync, and `$HOME` — even when non-empty or
    // itself a VCS root — is far too much to bulk-upload on a stray keystroke.
    // A deliberate `--sync tarball` (`sync_explicit`) is the escape hatch that
    // still uploads both. A `$HOME` that is itself a declared project loses
    // its hooks here; the callers refuse over that count rather than let the
    // session come up without them.
    if !sync_explicit && file_upload::is_empty_or_home(root.as_std_path(), home) {
        return UploadDecision::SkipEmptyOrHome;
    }
    match file_upload::upload_gate(
        file_upload::is_vcs_root(root.as_std_path()),
        sync_explicit,
        project_has_mfile(root),
        headless,
    ) {
        file_upload::UploadGate::Upload => UploadDecision::Upload,
        file_upload::UploadGate::SkipHeadless => UploadDecision::SkipUndeclared,
        file_upload::UploadGate::Prompt => UploadDecision::Confirm,
    }
}

/// Which upload transport the caller wants: the CLI's spinner bar while the
/// tree streams, or the bar-free path a screen-owning caller (the `min dash`
/// TUI) needs. The bar reports wire bytes, not a fraction — there is no
/// percentage to render — so this is the only presentation the mechanism
/// still owns; the notices are the caller's to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadProgress {
    Bar,
    Quiet,
}

/// What [`run_workspace_upload`] did, for the caller to report in its own way:
/// the CLI renders it on stderr, the `min dash` TUI on its own screen. The
/// shared step prints nothing itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceUpload {
    /// The workspace tree was streamed to the daemon.
    Uploaded,
    /// An empty directory or `$HOME`: nothing to sync. `dropped_hooks` counts
    /// the lifecycle hooks declared at the root, because a `$HOME` that is
    /// itself a declared project has its `minimal.toml` skipped with the tree
    /// — and that file is the only thing that carries them to the daemon. The
    /// refusing callers will not create a session without them.
    SkippedEmptyOrHome { dropped_hooks: usize },
    /// An undeclared non-VCS root was not uploaded. It has no `minimal.toml`
    /// (a root that carries one uploads), so it declares no hooks and this
    /// skip cannot drop any: it warns, and never refuses.
    SkippedUndeclared,
    /// The interactive confirm was declined.
    Declined,
}

/// Runs [`UploadDecision`] against the daemon: resolves the interactive
/// `Confirm` through `ask`, then streams the workspace or reports the skip.
/// Pure mechanism — it prints nothing; `progress` picks the transport and the
/// caller renders the returned [`WorkspaceUpload`].
///
/// The upload's failure is returned to the caller, which owns the teardown
/// (`withdraw_box_row` for the CLI, `AbortSession` for the dashboard) — the
/// session exists on the daemon by the time this runs.
pub(crate) async fn run_workspace_upload(
    client: &mut client::Client,
    id: boxes::SessionId,
    root: &camino::Utf8Path,
    decision: UploadDecision,
    ask: impl FnOnce() -> Result<bool, anyhow::Error>,
    progress: UploadProgress,
) -> Result<WorkspaceUpload, anyhow::Error> {
    match decision {
        UploadDecision::SkipEmptyOrHome => Ok(WorkspaceUpload::SkippedEmptyOrHome {
            dropped_hooks: project_lifecycle_hook_count(root),
        }),
        UploadDecision::SkipUndeclared => Ok(WorkspaceUpload::SkippedUndeclared),
        UploadDecision::Confirm => {
            if ask()? {
                upload_workspace(client, id, root, progress).await
            } else {
                Ok(WorkspaceUpload::Declined)
            }
        }
        // The confirm was answered before this ran, by a caller that owns
        // the prompt (the `min dash` TUI); the answer needs no daemon.
        UploadDecision::Declined => Ok(WorkspaceUpload::Declined),
        UploadDecision::Upload => upload_workspace(client, id, root, progress).await,
    }
}

/// Streams the workspace tree, mapped onto [`WorkspaceUpload`] with the shared
/// failure context.
async fn upload_workspace(
    client: &mut client::Client,
    id: boxes::SessionId,
    root: &camino::Utf8Path,
    progress: UploadProgress,
) -> Result<WorkspaceUpload, anyhow::Error> {
    let result = match progress {
        UploadProgress::Bar => client.upload_workspace_files(id, root.as_std_path()).await,
        UploadProgress::Quiet => {
            client
                .upload_workspace_files_quiet(id, root.as_std_path())
                .await
        }
    };
    result
        .map(|()| WorkspaceUpload::Uploaded)
        .context("Failed to upload project files")
}

/// The notice that the upload root resolved above the invocation directory —
/// `min activate ./subdir` uploads the whole project — shared by the CLI
/// callers so the wording cannot drift. `None` when the two are the same.
pub(crate) fn resolved_upload_root_notice(
    invoked_from: &camino::Utf8Path,
    root: &camino::Utf8Path,
) -> Option<String> {
    (root != invoked_from)
        .then(|| format!("Uploading from project root {root} (resolved from {invoked_from})"))
}

/// The rule of [`report_upload_outcome`]'s refusal, split out for a caller
/// that words the refusal itself. Every other outcome passes — a
/// [`WorkspaceUpload::Declined`] is the user's own answer, never an accident
/// to refuse. `remedy` is the one part of the refusal each caller words for
/// itself; see [`CLI_DROPPED_HOOKS_REMEDY`]. A caller that has resolved its
/// decision but not yet created anything refuses through
/// [`refuse_dropped_hooks_before_create`] instead.
pub(crate) fn refuse_dropped_hooks(
    outcome: &WorkspaceUpload,
    root: &camino::Utf8Path,
    remedy: &str,
) -> Result<(), anyhow::Error> {
    match outcome {
        // The one skip that can cost hooks: a `$HOME` that is itself a
        // declared project, since home is never uploaded implicitly.
        WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks } if *dropped_hooks > 0 => {
            Err(dropped_hooks_error(root, *dropped_hooks, remedy))
        }
        WorkspaceUpload::Uploaded
        | WorkspaceUpload::SkippedEmptyOrHome { .. }
        | WorkspaceUpload::SkippedUndeclared
        | WorkspaceUpload::Declined => Ok(()),
    }
}

/// The refusal [`refuse_dropped_hooks`] applies, decided from the upload
/// decision alone and so available before the daemon holds anything. A caller
/// that resolves its decision in its plan step refuses the create there
/// instead of creating a session and tearing it down.
pub(crate) fn refuse_dropped_hooks_before_create(
    decision: UploadDecision,
    root: &camino::Utf8Path,
    remedy: &str,
) -> Result<(), anyhow::Error> {
    if decision != UploadDecision::SkipEmptyOrHome {
        return Ok(());
    }
    let dropped_hooks = project_lifecycle_hook_count(root);
    if dropped_hooks == 0 {
        return Ok(());
    }
    Err(dropped_hooks_error(root, dropped_hooks, remedy))
}

/// What a refusing CLI caller tells the user of a `$HOME` create: which of
/// the two upload flags they meant.
pub(crate) const CLI_DROPPED_HOOKS_REMEDY: &str = "Pass `--sync tarball` to upload the project (hooks included), or `--sync none` to start \
     without them deliberately";

/// What `min dash`, which owns neither flag, tells the user of the same
/// create: the command that does.
pub(crate) const DASH_DROPPED_HOOKS_REMEDY: &str =
    "Create the box from a terminal with `min session activate --sync tarball` instead";

/// The refusal for the skip that would drop the project's lifecycle hooks,
/// for the callers that refuse rather than start a box without them. `min
/// task run` has no upload flag to offer, so it prints the same facts as a
/// warning instead. `remedy` is the caller's own, because what can be done
/// about it differs by caller.
pub(crate) fn dropped_hooks_error(
    root: &camino::Utf8Path,
    dropped_hooks: usize,
    remedy: &str,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{root} is your home directory, so its file upload is being skipped \
         — but its {name} declares {dropped_hooks} lifecycle hook(s) that \
         reach the session only through that upload. They would be silently \
         dropped and never run. {remedy}.",
        name = mfile::MFILE_NAME,
    )
}

/// What a caller wants done when a skipped upload would drop the project's
/// lifecycle hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DroppedHooksPolicy {
    /// Refuse the activation with the CLI's upload remedy.
    Refuse,
    /// Warn with the count and continue.
    Warn,
    /// Say nothing about hooks: the caller already disabled them.
    Ignore,
}

/// Renders a [`WorkspaceUpload`] outcome on `err`, the sink its caller owns:
/// the CLI's stderr, or a buffer in a test. `policy` selects the caller's
/// treatment of the `$HOME` skip that would drop lifecycle hooks: activate
/// refuses unless `--no-hooks` disabled them; task run, which has no upload
/// flag to offer, warns with the count. `Ok(())` when the session may
/// proceed.
#[expect(
    clippy::let_underscore_must_use,
    reason = "a closed stderr has no reader left to tell; the outcome's own \
              result is the command's answer either way"
)]
pub(crate) fn report_upload_outcome(
    outcome: Result<WorkspaceUpload, anyhow::Error>,
    root: &camino::Utf8Path,
    policy: DroppedHooksPolicy,
    err: &mut impl std::io::Write,
) -> Result<(), anyhow::Error> {
    let outcome = outcome?;
    if policy == DroppedHooksPolicy::Refuse {
        refuse_dropped_hooks(&outcome, root, CLI_DROPPED_HOOKS_REMEDY)?;
    }
    match outcome {
        WorkspaceUpload::Uploaded => Ok(()),
        WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks } => {
            let _ = writeln!(err, "Starting with an empty box (nothing here to sync)");
            if dropped_hooks > 0 && policy == DroppedHooksPolicy::Warn {
                // Name the hooks so the warning does not read as a healthy
                // start. `Refuse` returned above, and `Ignore` belongs to a
                // caller that already disabled them.
                let _ = writeln!(
                    err,
                    "{dropped_hooks} lifecycle hook(s) declared in {} will not run: \
                     the file upload is skipped.",
                    root.join(mfile::MFILE_NAME)
                );
            }
            Ok(())
        }
        WorkspaceUpload::SkippedUndeclared => {
            let _ = writeln!(
                err,
                "{}",
                file_upload::skipped_upload_warning(root.as_std_path())
            );
            Ok(())
        }
        WorkspaceUpload::Declined => {
            let _ = writeln!(
                err,
                "Skipping file upload; the session will start with an empty workspace."
            );
            Ok(())
        }
    }
}

/// The CLI's whole workspace-upload step: the resolved-root notice, the
/// interactive confirm, the spinner-bar transport, and the outcome's stderr
/// lines. `decision` comes from the caller's plan step and `policy` is its
/// treatment of an empty-or-`$HOME` skip that would drop the project's
/// hooks. The failure is returned for the caller to tear the session down.
pub(crate) async fn cli_workspace_upload(
    client: &mut client::Client,
    id: boxes::SessionId,
    invoked_from: &camino::Utf8Path,
    root: &camino::Utf8Path,
    decision: UploadDecision,
    policy: DroppedHooksPolicy,
) -> Result<(), anyhow::Error> {
    // The resolved-root notice is CLI presentation, and precedes the upload
    // bar it explains.
    if decision != UploadDecision::SkipEmptyOrHome
        && let Some(notice) = resolved_upload_root_notice(invoked_from, root)
    {
        eprintln!("{notice}");
    }
    let outcome = run_workspace_upload(
        client,
        id,
        root,
        decision,
        || {
            confirm(
                &format!(
                    "{root} is not a version control repository root. \
                     Upload all files from this directory?"
                ),
                false,
            )
        },
        UploadProgress::Bar,
    )
    .await;
    report_upload_outcome(outcome, root, policy, &mut std::io::stderr())
}

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

/// What [`run_init_flow`] did. Returned rather than printed because the two
/// callers publish it on different streams: `min init` puts the line on
/// stdout — it is that command's whole scriptable result — while
/// `min activate`'s scaffold offer keeps it on stderr, where stdout carries
/// only the session id (see [`activate_box`]).
pub(crate) enum InitOutcome {
    /// The operator declined the confirmation; nothing was written.
    Declined,
    /// A `minimal.toml` was created at this path.
    Created(std::path::PathBuf),
    /// An existing `minimal.toml` at this path was overwritten.
    Updated(std::path::PathBuf),
}

impl InitOutcome {
    /// The one-line result to report, or `None` when nothing was written.
    fn result_line(&self) -> Option<String> {
        match self {
            Self::Declined => None,
            Self::Created(path) => Some(format!("Created {}", path.display())),
            Self::Updated(path) => Some(format!("Updated {}", path.display())),
        }
    }
}

/// Whether `min init` and the `min activate` scaffold write the entry shape.
/// `false` until #2418 (BOX T21): box creation still reads packages from
/// `[session]`, so an entry-shaped scaffold loses them at session start.
pub(crate) const INIT_ENTRY_SHAPE: bool = false;

/// Run the init flow for a given config: detect the project's stack,
/// generate a `minimal.toml`, show the plan, prompt for confirmation,
/// and write the file. Shared by `cmd_init` and the `cmd_activate`
/// missing-mfile prompt.
///
/// `entry_shape` writes the entry shape (BCLI-017) in place of the legacy
/// `[session]` shape. Both callers pass [`INIT_ENTRY_SHAPE`], which is
/// `false` until #2418 (BOX T21) makes box creation read
/// `[defaults.<type>]`. Then both callers pass `true` and the parameter is
/// removed.
pub(crate) fn run_init_flow(
    config: mctx::Config,
    skip_confirm: bool,
    force: bool,
    entry_shape: bool,
) -> Result<InitOutcome, anyhow::Error> {
    use op::ProjectOp as _;
    let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut plan = op::InitProject
        .run(&mut env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if entry_shape {
        plan.content = to_entry_shape(&plan.content)?;
    }

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
            return Ok(InitOutcome::Declined);
        }
    }

    // Whether the file existed under the lock, which decides Created vs
    // Updated, and whether the edit refused, so the refusal is not wrapped
    // in the "writing" context meant for I/O errors.
    let mut existed = exists;
    let mut refused = false;
    let written = mfile::File::edit_exclusively::<anyhow::Error>(&plan.toml_path, |content| {
        // The `exists` check above ran before the lock was taken, so a
        // concurrent writer (another `min add`/`min update` scaffolding
        // this file) may have created it since. Re-check under the lock:
        // clobbering it without --force is the same destructive overwrite
        // that check exists to prevent.
        existed = content.is_some();
        if existed && !force {
            refused = true;
            bail!(
                "refusing to overwrite existing {} without confirmation; pass --force",
                plan.toml_path.display()
            );
        }
        Ok(Some(plan.content.clone()))
    });
    match written {
        Err(e) if refused => return Err(e),
        written => written.with_context(|| format!("writing {}", plan.toml_path.display()))?,
    }

    Ok(if existed {
        InitOutcome::Updated(plan.toml_path)
    } else {
        InitOutcome::Created(plan.toml_path)
    })
}

/// The message `min init` prints when it gets more than one way to name the
/// entry's type. The task fixes this text.
pub const INIT_ONE_TYPE_FLAG: &str = "Pass one of --session, --task, --agent, --service or --type.";

/// The built-in types that `min init` can append an entry of.
const INIT_EXPANDED_TYPES: [&str; 2] = ["session", "task"];

/// The built-in types that this release refuses an entry of (BOX-063).
const INIT_REFUSED_TYPES: [&str; 4] = ["agent", "service", "build", "container-build"];

/// A refusal from `min init`: the text for the user and the exit code the
/// run ends with. Nothing is written when one is returned.
///
/// `cmd_init` returns it as the error, and `main.rs` `failure_exit_code`
/// ends the run with [`InitRefusal::code`], so the `cmd` span closes and
/// its outcome record reaches the spool first.
#[derive(Debug, PartialEq, Eq)]
pub struct InitRefusal {
    /// The exit code: 2 for a usage error, 3 for a type this release
    /// refuses or for a name or type that makes `minimal.toml` invalid, 1
    /// for anything else.
    pub code: u8,
    /// What was refused, why, and the next step.
    pub message: String,
}

impl InitRefusal {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for InitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InitRefusal {}

/// What one `min init` run does.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InitRequest {
    /// Write a new `minimal.toml` in the entry shape (BCLI-017).
    Scaffold,
    /// Append the entry `entry` of type `box_type` (BCLI-018).
    Append { entry: String, box_type: String },
}

/// Read the request from the arguments. A noun flag is the same request as
/// `<entry> --type <noun>`, and only one of the noun flags and `--type` can
/// be given.
pub(crate) fn init_request(args: &InitArgs) -> Result<InitRequest, InitRefusal> {
    let nouns: Vec<(&str, &String)> = [
        ("session", &args.session),
        ("task", &args.task),
        ("agent", &args.agent),
        ("service", &args.service),
    ]
    .into_iter()
    .filter_map(|(noun, name)| name.as_ref().map(|name| (noun, name)))
    .collect();
    if nouns.len() + usize::from(args.box_type.is_some()) > 1 {
        return Err(InitRefusal::usage(INIT_ONE_TYPE_FLAG));
    }
    let (entry, box_type) = match (&args.entry, &args.box_type, nouns.first()) {
        (None, None, None) => return Ok(InitRequest::Scaffold),
        (Some(entry), Some(box_type), None) => (entry.clone(), box_type.clone()),
        (None, None, Some((noun, name))) => ((*name).clone(), (*noun).to_owned()),
        (Some(entry), None, Some((noun, _))) => {
            return Err(InitRefusal::usage(format!(
                "Name the entry once. Run min init {entry} --type {noun}."
            )));
        }
        (Some(entry), None, None) => {
            return Err(InitRefusal::usage(format!(
                "Give the entry a type. Run min init {entry} --type <type>."
            )));
        }
        (None, Some(box_type), None) => {
            return Err(InitRefusal::usage(format!(
                "Name the entry to append. Run min init <entry> --type {box_type}."
            )));
        }
        (_, Some(_), Some(_)) => return Err(InitRefusal::usage(INIT_ONE_TYPE_FLAG)),
    };
    check_entry_name(&entry)?;
    Ok(InitRequest::Append { entry, box_type })
}

/// Refuse an entry name that no entry can take: `self`, or a name that is
/// not a DNS label (BOX-007, BOX-046). It runs before any file read, so a
/// refused name leaves `minimal.toml` unread and unchanged.
fn check_entry_name(entry: &str) -> Result<(), InitRefusal> {
    if entry == mfile::entry::RESERVED_ENTRY_NAME {
        return Err(InitRefusal {
            code: 3,
            message: format!(
                "min init did not add the entry {entry}: the name {entry} is reserved. \
                 Choose another name."
            ),
        });
    }
    if !mfile::entry::is_dns_safe(entry) {
        return Err(InitRefusal {
            code: 3,
            message: format!(
                "min init did not add the entry {entry:?}: an entry name must be 1 to 63 \
                 characters of a-z, 0-9 and -, and must not start or end with -. \
                 Choose another name."
            ),
        });
    }
    Ok(())
}

/// Rewrite the scaffold that the project initializer generates into the
/// entry shape (BCLI-017): the legacy `[session]` table becomes
/// `[defaults.session]`, the legacy `[defaults] state_key` becomes
/// `[defaults.task] state_key` (BOX-050, BOX-051), and the file declares
/// one session entry, `[boxes.dev]`.
pub(crate) fn to_entry_shape(legacy: &str) -> Result<String, anyhow::Error> {
    use toml_edit::{DocumentMut, Item, Table, value};
    let mut doc: DocumentMut = legacy
        .parse()
        .context("reading the generated minimal.toml")?;
    let state_key = doc
        .get_mut("defaults")
        .and_then(Item::as_table_mut)
        .and_then(|defaults| defaults.remove("state_key"));
    let session = doc.remove("session");

    let defaults = doc
        .entry("defaults")
        .or_insert(toml_edit::table())
        .as_table_mut()
        .context("the generated [defaults] is not a table")?;
    defaults.set_implicit(true);
    if let Some(Item::Table(mut session)) = session {
        session.decor_mut().clear();
        defaults.insert("session", Item::Table(session));
    }
    if let Some(state_key) = state_key {
        let mut task = Table::new();
        task.insert("state_key", state_key);
        defaults.insert("task", Item::Table(task));
    }

    let mut entry = Table::new();
    entry.insert("type", value("session"));
    let mut boxes = Table::new();
    boxes.set_implicit(true);
    boxes.insert("dev", Item::Table(entry));
    doc.insert("boxes", Item::Table(boxes));
    Ok(doc.to_string())
}

/// The built-in type that `box_type` resolves to, through the `extends`
/// chain of the file's `[box_types]` (BOX-059).
fn resolve_builtin_root(
    doc: &toml_edit::DocumentMut,
    entry: &str,
    box_type: &str,
) -> Result<String, InitRefusal> {
    let is_builtin =
        |name: &str| INIT_EXPANDED_TYPES.contains(&name) || INIT_REFUSED_TYPES.contains(&name);
    let mut current = box_type.to_owned();
    let mut seen: Vec<String> = Vec::new();
    while !is_builtin(&current) {
        if seen.contains(&current) {
            return Err(InitRefusal {
                code: 3,
                message: format!(
                    "min init did not add the entry {entry}: type {box_type} extends itself \
                     through [box_types] in minimal.toml. Fix the extends keys there."
                ),
            });
        }
        let declared = doc.get("box_types").and_then(|types| types.get(&current));
        let extends = declared
            .and_then(|ty| ty.get("extends"))
            .and_then(toml_edit::Item::as_str)
            .map(str::to_owned);
        match extends {
            Some(parent) => {
                seen.push(current);
                current = parent;
            }
            // A declared type with no `extends` is invalid minimal.toml:
            // exit 3, as for any other validation error.
            None if declared.is_some() => {
                return Err(InitRefusal {
                    code: 3,
                    message: format!(
                        "min init did not add the entry {entry}: [box_types.{current}] in \
                         minimal.toml has no extends key. Add extends = \"session\" or \
                         extends = \"task\" there."
                    ),
                });
            }
            None if seen.is_empty() => {
                return Err(InitRefusal::usage(format!(
                    "min init did not add the entry {entry}: {box_type} is not a built-in \
                     type or a [box_types] entry in minimal.toml. Use --type session or \
                     --type task."
                )));
            }
            None => {
                return Err(InitRefusal {
                    code: 3,
                    message: format!(
                        "min init did not add the entry {entry}: type {box_type} extends \
                         {current}, which is not a built-in type or a [box_types] entry \
                         in minimal.toml."
                    ),
                });
            }
        }
    }
    Ok(current)
}

/// Append the entry to the `minimal.toml` text, or refuse with the file
/// unchanged.
pub(crate) fn append_entry_text(
    content: &str,
    entry: &str,
    box_type: &str,
) -> Result<String, InitRefusal> {
    use toml_edit::{DocumentMut, Item, Table, value};
    let mut doc: DocumentMut = content.parse().map_err(|e| InitRefusal {
        code: 3,
        message: format!(
            "min init did not add the entry {entry}: minimal.toml does not parse: {e}"
        ),
    })?;

    // BOX-063: an entry whose type, or whose type's built-in root, is not
    // session or task is refused with exit 3.
    let root = resolve_builtin_root(&doc, entry, box_type)?;
    if INIT_REFUSED_TYPES.contains(&root.as_str()) {
        let what = if root == box_type {
            format!("type {box_type} is not supported yet")
        } else {
            format!("type {box_type} extends {root}, which is not supported yet")
        };
        return Err(InitRefusal {
            code: 3,
            message: format!(
                "min init did not add the entry {entry}: {what}. Support for it is \
                 tracked in gominimal/inbox#678. Use --type session or --type task."
            ),
        });
    }

    if mfile::entry::EntryTable::ALL
        .iter()
        .any(|table| doc.get(table.key()).and_then(|t| t.get(entry)).is_some())
    {
        return Err(InitRefusal {
            code: 3,
            message: format!(
                "minimal.toml already has an entry named {entry}. Choose another name."
            ),
        });
    }

    let boxes = doc
        .entry("boxes")
        .or_insert_with(|| {
            let mut boxes = Table::new();
            boxes.set_implicit(true);
            Item::Table(boxes)
        })
        .as_table_mut()
        .ok_or_else(|| InitRefusal {
            code: 3,
            message: format!(
                "min init did not add the entry {entry}: boxes in minimal.toml is not a table."
            ),
        })?;
    let mut table = Table::new();
    table.insert("type", value(box_type));
    boxes.insert(entry, Item::Table(table));
    Ok(doc.to_string())
}

/// The project's `minimal.toml`, found the way the other commands find it:
/// in `dir` and its ancestors when `search_ancestors` is set
/// (`MFileSearchStrategy::CurrentDirRecursive`), or in `dir` only for
/// `--repo-dir` (`MFileSearchStrategy::Override`). Both layouts in one
/// directory are refused, as `mfile` refuses them.
fn find_init_mfile(
    dir: &std::path::Path,
    search_ancestors: bool,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let found = if search_ancestors {
        mfile::File::from_dir_recursive(dir)
    } else {
        mfile::File::from_dir(dir)
    };
    match found {
        Ok(file) => file.file_path().cloned().ok_or_else(|| {
            anyhow::anyhow!("the minimal.toml found from {} has no path", dir.display())
        }),
        Err(mfile::Error::NotFound) => Err(InitRefusal {
            code: 1,
            message: format!(
                "No minimal.toml in {}{}. Run min init to create one, then append the entry.",
                dir.display(),
                if search_ancestors {
                    " or its parent directories"
                } else {
                    ""
                }
            ),
        }
        .into()),
        Err(mfile::Error::ConflictingLayouts(paths)) => Err(InitRefusal {
            code: 3,
            message: format!(
                "min init did not add the entry: the project has two minimal.toml files, {}. \
                 Remove one of them, then run the command again.",
                paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        }
        .into()),
        Err(e @ mfile::Error::IO(..)) => Err(anyhow::Error::new(e).context("reading minimal.toml")),
        // A file that does not parse or validate is invalid configuration:
        // exit 3, as the architecture's exit-code table fixes it.
        Err(e) => {
            let file = located_init_mfile(dir, search_ancestors)
                .map_or_else(|| "minimal.toml".to_string(), |p| p.display().to_string());
            Err(InitRefusal {
                code: 3,
                message: format!(
                    "min init did not add the entry: {file} is not valid. \
                     Fix the file, then run the command again.\n{}",
                    e.to_string().trim_end()
                ),
            }
            .into())
        }
    }
}

/// The `minimal.toml` path that [`find_init_mfile`] read, found by the
/// same search as `mfile::File::from_dir` and `from_dir_recursive`, so a
/// refusal can name a file whose parse error does not carry its path.
fn located_init_mfile(dir: &std::path::Path, search_ancestors: bool) -> Option<std::path::PathBuf> {
    let home = std::env::home_dir();
    let mut dir = dir;
    loop {
        for path in [
            dir.join(mfile::MFILE_NAME),
            dir.join(".minimal").join(mfile::MFILE_NAME),
        ] {
            if path.exists() {
                return Some(path);
            }
        }
        let parent = dir.parent()?;
        if !search_ancestors || home.as_deref() == Some(parent) {
            return None;
        }
        dir = parent;
    }
}

/// Append the entry to the project's `minimal.toml`, found from `dir` by
/// [`find_init_mfile`], under the file's edit lock, and return the path
/// written. A refusal comes back as an [`InitRefusal`] inside the error,
/// and leaves the file unchanged.
pub(crate) fn append_entry_in(
    dir: &std::path::Path,
    search_ancestors: bool,
    entry: &str,
    box_type: &str,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let path = find_init_mfile(dir, search_ancestors)?;
    mfile::File::edit_exclusively::<anyhow::Error>(&path, |content| {
        let Some(content) = content else {
            return Err(InitRefusal {
                code: 1,
                message: format!("{} was removed. Run min init to create it.", path.display()),
            }
            .into());
        };
        Ok(Some(append_entry_text(content, entry, box_type)?))
    })?;
    Ok(path)
}

/// `min init`: scaffold a `minimal.toml` in the entry shape, or append one
/// entry to it.
pub async fn cmd_init(global: &GlobalArgs, args: InitArgs) -> Result<(), mctx::Error> {
    let request = match init_request(&args) {
        Ok(request) => request,
        Err(refusal) => {
            tracing::info!(verb = "init", outcome = "refused", code = refusal.code);
            return Err(mctx::Error::Other(anyhow::Error::new(refusal)));
        }
    };
    let (entry, box_type) = match request {
        InitRequest::Scaffold => {
            let config = build_config(global)?;
            let outcome = run_init_flow(config, args.yes, args.force, INIT_ENTRY_SHAPE)
                .map_err(mctx::Error::Other)?;
            // The legacy shape has no `dev` entry, so `entry` is recorded only
            // when the entry shape is written.
            tracing::info!(
                verb = "init",
                shape = if INIT_ENTRY_SHAPE { "entry" } else { "legacy" },
                entry = INIT_ENTRY_SHAPE.then_some("dev"),
                outcome = if outcome.result_line().is_some() {
                    "written"
                } else {
                    "declined"
                },
            );
            // stdout: the result line is `min init`'s scriptable output, so it
            // survives `min init > audit.log` while the preview and prompt above
            // stay on stderr.
            if let Some(line) = outcome.result_line() {
                println!("{line}");
            }
            return Ok(());
        }
        InitRequest::Append { entry, box_type } => (entry, box_type),
    };
    // `--repo-dir` names the project root, as `MFileSearchStrategy::Override`
    // does. Without it the search walks up from the current directory.
    let (dir, search_ancestors) = match &global.repo_dir {
        Some(dir) => (dir.clone(), false),
        None => (
            std::env::current_dir()
                .context("reading the current directory")
                .map_err(mctx::Error::Other)?,
            true,
        ),
    };
    match append_entry_in(&dir, search_ancestors, &entry, &box_type) {
        Ok(path) => {
            tracing::info!(verb = "init", entry, box_type, outcome = "appended");
            println!("Added the {box_type} entry {entry} to {}", path.display());
            Ok(())
        }
        Err(e) => {
            match e.downcast_ref::<InitRefusal>() {
                Some(refusal) => tracing::info!(
                    verb = "init",
                    entry,
                    box_type,
                    outcome = "refused",
                    code = refusal.code
                ),
                None => tracing::info!(verb = "init", entry, box_type, outcome = "failed"),
            }
            Err(mctx::Error::Other(e))
        }
    }
}

/// Whether `min update` / `min add` should warm the host artifact cache after
/// moving a pin.
///
/// Only a native daemon reads the host cache. A VM-backed host caches on
/// its own guest data volume and never reads the host cache, so warming it
/// there spends bandwidth and disk on artifacts no session start reads — the
/// daemon re-fetches the whole closure on the next activate regardless.
pub(crate) fn should_warm_host_cache(use_minvmd: bool) -> bool {
    client::client_host_kind(use_minvmd) != paths::HostKind::Minvmd
}

/// Add packages as dependencies to the project's `minimal.toml`.
pub async fn cmd_add(global: &GlobalArgs, args: AddArgs) -> Result<(), mctx::Error> {
    let config = build_config(global)?;
    let mut ctx = match mctx::Context::new(config) {
        Ok(ctx) => ctx,
        // A project with no `minimal.toml` cannot take a dependency, so offer
        // the same scaffold `min session activate` does before failing with
        // the `min init` hint `min update` already gives.
        Err(mctx::Error::MFile(mfile::Error::NotFound)) => {
            let project_path = match &global.repo_dir {
                Some(dir) => camino::Utf8PathBuf::from_path_buf(dir.clone()).map_err(|_| {
                    mctx::Error::Other(anyhow::anyhow!("Project path is not valid UTF-8"))
                })?,
                None => {
                    let cwd = std::env::current_dir().map_err(|e| {
                        mctx::Error::IO("Getting current directory", std::path::PathBuf::new(), e)
                    })?;
                    camino::Utf8PathBuf::from_path_buf(cwd).map_err(|_| {
                        mctx::Error::Other(anyhow::anyhow!("Project path is not valid UTF-8"))
                    })?
                }
            };
            offer_mfile_scaffold(&project_path, global, None).map_err(mctx::Error::Other)?;
            match mctx::Context::new(build_config(global)?) {
                Ok(ctx) => ctx,
                Err(e @ mctx::Error::MFile(mfile::Error::NotFound)) => {
                    return Err(mctx::Error::Other(anyhow::anyhow!(
                        "{e}\nRun 'min init' to give the project its own config."
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };

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
        AddKind { session: true, .. } => {
            ctx.add_deps(
                &graph,
                graph.top_levels.clone(),
                mctx::AddDepMode::SessionPackages,
            )?;
            // The host-side add updates `minimal.toml`; unlike the
            // in-session helper it does not install into a running session.
            // Qualify the success line so it is not read as a live install.
            eprintln!(
                "Note: this updated minimal.toml; a running session is \
                 not modified. The package will be present in sessions \
                 activated after this change; to add it to an already-running \
                 session, run `min add --session` from inside that session."
            );
        }
        _ => unreachable!(),
    }

    if should_warm_host_cache(global.use_minvmd()) {
        ctx.download_if_available(&graph, graph.top_levels.clone())
            .await?;
    } else {
        eprintln!(
            "Note: packages are not downloaded now; they are downloaded the \
             next time you run `min session activate`."
        );
    }

    Ok(())
}

/// Re-pin `[upstream]` (and sideloads) to their branch heads and refresh the
/// local checkouts to match.
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

    let mut env = ctx.project_setup()?;
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
    for c in &report.skipped {
        println!("{}", c.skipped_message("min update"));
    }

    if report.repinned() {
        println!(
            "\nRe-pinned minimal.toml (a diff to commit). The next \
             'min session activate' materializes the new closure, which can \
             take several minutes on the first activate.\n\
             This did not update the 'min' binary; reinstall it with the \
             installer to do that."
        );
    } else if report.skipped.is_empty() {
        println!("Already up to date; no pins moved and minimal.toml is unchanged.");
    }

    // Re-initialize the context to pick up the updated minimal.toml, then
    // download any newly-reachable packages.
    ctx = ctx.cloned_reinit()?;
    let graph = ctx.graph_from_all_packages()?;
    let ensure_pkgs = ctx.scaffolding_packages()?;
    if should_warm_host_cache(global.use_minvmd()) {
        ctx.download_if_available(&graph, ensure_pkgs).await?;
    } else {
        eprintln!(
            "Note: packages are not downloaded now; they are downloaded the \
             next time you run `min session activate`."
        );
    }

    Ok(())
}

#[cfg(test)]
mod init_tests {
    use super::*;

    /// The scaffold the project initializer writes today, in the legacy
    /// shape (`op::project::init::generate_mfile`).
    const LEGACY_SCAFFOLD: &str = "# Generated by `min init`\n\n\
        [upstream] # Source of software & tooling\n\
        repo = \"https://github.com/gominimal/pkgs\"\n\
        locked_commit = \"abc123\"\n\n\
        [defaults]\n\
        state_key = \"dev\"\n\n\
        [session] # min session attach\n\
        packages = [\"base\", \"vim\", \"git\"]\n";

    fn init_args(argv: &[&str]) -> InitArgs {
        let cli = crate::Cli::try_parse_from(std::iter::once("min").chain(argv.iter().copied()))
            .expect("the arguments parse");
        match cli.command {
            Some(crate::Command::Init(args)) => args,
            _ => panic!("not an init command"),
        }
    }

    fn project(content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::write(dir.path().join(mfile::MFILE_NAME), content).expect("write minimal.toml");
        dir
    }

    fn read(dir: &tempfile::TempDir) -> String {
        std::fs::read_to_string(dir.path().join(mfile::MFILE_NAME)).expect("read minimal.toml")
    }

    /// Run `min init <argv>` as far as the file: the request, then the append.
    fn run(dir: &tempfile::TempDir, argv: &[&str]) -> Result<(), InitRefusal> {
        match init_request(&init_args(argv))? {
            InitRequest::Scaffold => panic!("expected an append"),
            InitRequest::Append { entry, box_type } => {
                append_entry_in(dir.path(), true, &entry, &box_type)
                    .map(|_| ())
                    .map_err(|e| e.downcast::<InitRefusal>().expect("a refusal"))
            }
        }
    }

    // BCLI-017
    #[test]
    fn init_scaffolds_entry_shape() {
        assert_eq!(
            init_request(&init_args(&["init"])),
            Ok(InitRequest::Scaffold)
        );
        let shaped = to_entry_shape(LEGACY_SCAFFOLD).expect("the scaffold converts");
        let doc: toml::Table = shaped.parse().expect("the scaffold parses");
        assert!(
            doc.get("session").is_none(),
            "no legacy [session]:\n{shaped}"
        );
        assert!(
            doc["defaults"].get("state_key").is_none(),
            "no legacy state_key:\n{shaped}"
        );
        assert_eq!(
            doc["boxes"]["dev"]["type"].as_str(),
            Some("session"),
            "{shaped}"
        );
        assert_eq!(
            doc["defaults"]["task"]["state_key"].as_str(),
            Some("dev"),
            "{shaped}"
        );
        assert_eq!(
            doc["defaults"]["session"]["packages"],
            toml::Value::Array(vec!["base".into(), "vim".into(), "git".into()]),
            "{shaped}"
        );
        assert_eq!(doc["upstream"]["locked_commit"].as_str(), Some("abc123"));
        assert!(shaped.starts_with("# Generated by `min init`"), "{shaped}");
        // The project loader still reads the scaffold.
        let dir = project(&shaped);
        mfile::File::from_dir(dir.path()).expect("the scaffold loads");
    }

    // Until #2418, `min init` with no flags writes the legacy `[session]`
    // shape, and `mfile::File` reads its packages from there.
    #[test]
    fn init_no_flags_writes_legacy_shape() {
        assert_eq!(
            init_request(&init_args(&["init"])),
            Ok(InitRequest::Scaffold)
        );
        const { assert!(!INIT_ENTRY_SHAPE, "min init writes the legacy shape") };
        let dir = project(LEGACY_SCAFFOLD);
        let file = mfile::File::from_dir(dir.path()).expect("the scaffold loads");
        let session = file.session.as_ref().expect("a [session] table");
        assert_eq!(session.packages, ["base", "vim", "git"]);
    }

    // BCLI-018
    #[test]
    fn init_entry_type_appends_one() {
        let dir = project(&to_entry_shape(LEGACY_SCAFFOLD).unwrap());
        let before: toml::Table = read(&dir).parse().unwrap();
        run(&dir, &["init", "build", "--type", "task"]).expect("the entry is appended");
        let after_text = read(&dir);
        let after: toml::Table = after_text.parse().unwrap();
        let boxes = after["boxes"].as_table().unwrap();
        assert_eq!(boxes.len(), 2, "{after_text}");
        assert_eq!(boxes["build"]["type"].as_str(), Some("task"));
        assert_eq!(boxes["dev"], before["boxes"]["dev"]);
        assert_eq!(
            after["upstream"], before["upstream"],
            "the rest of the file is kept"
        );
        assert!(
            after_text.starts_with("# Generated by `min init`"),
            "{after_text}"
        );

        // A project type rooted at session is accepted too.
        let dir = project("[box_types.web]\nextends = \"session\"\n");
        run(&dir, &["init", "site", "--type", "web"]).expect("the entry is appended");
        let after: toml::Table = read(&dir).parse().unwrap();
        assert_eq!(after["boxes"]["site"]["type"].as_str(), Some("web"));

        // A name that is already an entry is refused.
        let refusal = run(&dir, &["init", "site", "--type", "task"]).unwrap_err();
        assert_eq!(refusal.code, 3);
    }

    // BCLI-018: a [box_types] entry with no extends is invalid minimal.toml.
    #[test]
    fn init_box_type_without_extends_exit3_appends_nothing() {
        let original = "[box_types.web]\nimage = \"x\"\n\n[boxes.dev]\ntype = \"session\"\n";
        let dir = project(original);
        let refusal = run(&dir, &["init", "x", "--type", "web"]).unwrap_err();
        assert_eq!(refusal.code, 3, "{}", refusal.message);
        assert!(
            refusal.message.contains("[box_types.web]"),
            "{}",
            refusal.message
        );
        assert!(refusal.message.contains("extends"), "{}", refusal.message);
        assert_eq!(read(&dir), original, "the file is unchanged");

        // A type with no [box_types] entry at all stays a usage error.
        let refusal = run(&dir, &["init", "x", "--type", "api"]).unwrap_err();
        assert_eq!(refusal.code, 2, "{}", refusal.message);
        assert!(
            refusal
                .message
                .contains("is not a built-in type or a [box_types] entry"),
            "{}",
            refusal.message
        );
        assert_eq!(read(&dir), original, "the file is unchanged");
    }

    // BCLI-018, BOX-063
    #[test]
    fn init_refused_type_exit3_appends_nothing() {
        let original =
            "[box_types.reviewer]\nextends = \"agent\"\n\n[boxes.dev]\ntype = \"session\"\n";
        let dir = project(original);
        for ty in ["agent", "service", "build", "container-build", "reviewer"] {
            let refusal = run(&dir, &["init", "bot", "--type", ty]).unwrap_err();
            assert_eq!(refusal.code, 3, "{ty}: {}", refusal.message);
            assert!(refusal.message.contains(ty), "{}", refusal.message);
            assert!(
                refusal.message.contains("gominimal/inbox#678"),
                "{}",
                refusal.message
            );
            assert_eq!(read(&dir), original, "{ty}: the file is unchanged");
        }
        let refusal = run(&dir, &["init", "--agent", "bot"]).unwrap_err();
        assert_eq!(refusal.code, 3);
        assert_eq!(read(&dir), original);
    }

    // BCLI-018
    #[test]
    fn init_noun_flag_is_type_alias() {
        for noun in ["session", "task"] {
            let by_flag = project(LEGACY_SCAFFOLD);
            let by_type = project(LEGACY_SCAFFOLD);
            let flag = format!("--{noun}");
            run(&by_flag, &["init", flag.as_str(), "web"]).expect("appended by flag");
            run(&by_type, &["init", "web", "--type", noun]).expect("appended by type");
            assert_eq!(read(&by_flag), read(&by_type), "{noun}");
            assert_eq!(
                init_request(&init_args(&["init", flag.as_str(), "web"])),
                init_request(&init_args(&["init", "web", "--type", noun])),
            );
        }
        for noun in ["agent", "service"] {
            let flag = format!("--{noun}");
            assert_eq!(
                init_request(&init_args(&["init", flag.as_str(), "web"])),
                Ok(InitRequest::Append {
                    entry: "web".into(),
                    box_type: noun.into()
                }),
            );
        }
    }

    // BCLI-018, BOX-007, BOX-046: the name check runs before any file read.
    #[test]
    fn init_entry_name_invalid_exit3_appends_nothing() {
        let long = "a".repeat(64);
        let dir = project(LEGACY_SCAFFOLD);
        let empty = tempfile::tempdir().expect("a temp dir");
        for name in ["self", "My_Box", "-dev", long.as_str(), ""] {
            let task_flag = format!("--task={name}");
            for argv in [
                vec!["init", "--type", "session", "--", name],
                vec!["init", task_flag.as_str()],
            ] {
                let refusal = run(&dir, &argv).unwrap_err();
                assert_eq!(refusal.code, 3, "{argv:?}: {}", refusal.message);
                assert!(
                    refusal.message.contains(name),
                    "{argv:?}: names the value: {}",
                    refusal.message
                );
                assert_eq!(
                    read(&dir),
                    LEGACY_SCAFFOLD,
                    "{argv:?}: the file is unchanged"
                );
                // No minimal.toml: the name is refused before the file is looked for.
                assert_eq!(run(&empty, &argv).unwrap_err().code, 3, "{argv:?}");
            }
        }
        let refusal = run(&dir, &["init", "My_Box", "--type", "session"]).unwrap_err();
        assert!(
            refusal
                .message
                .contains("1 to 63 characters of a-z, 0-9 and -"),
            "states the rule: {}",
            refusal.message
        );
        run(&dir, &["init", "web-2", "--type", "session"]).expect("a DNS label is accepted");
    }

    // BCLI-018
    #[test]
    fn init_noun_flags_exclusive_exit2_appends_nothing() {
        let dir = project(LEGACY_SCAFFOLD);
        for argv in [
            &["init", "--session", "a", "--task", "b"][..],
            &["init", "--agent", "a", "--service", "b"],
            &[
                "init",
                "--session",
                "a",
                "--task",
                "b",
                "--agent",
                "c",
                "--service",
                "d",
            ],
            &["init", "--session", "a", "--type", "task"],
            &["init", "a", "--type", "task", "--service", "b"],
        ] {
            let refusal = run(&dir, argv).unwrap_err();
            assert_eq!(
                refusal,
                InitRefusal {
                    code: 2,
                    message: INIT_ONE_TYPE_FLAG.to_owned()
                },
                "{argv:?}"
            );
            assert_eq!(
                read(&dir),
                LEGACY_SCAFFOLD,
                "{argv:?}: the file is unchanged"
            );
        }
        assert_eq!(
            INIT_ONE_TYPE_FLAG,
            "Pass one of --session, --task, --agent, --service or --type."
        );
    }

    /// Run the append from `dir`, searching its ancestors as `min init` does
    /// without `--repo-dir`.
    fn append_from(dir: &std::path::Path, entry: &str) -> Result<std::path::PathBuf, InitRefusal> {
        append_entry_in(dir, true, entry, "task")
            .map_err(|e| e.downcast::<InitRefusal>().expect("a refusal"))
    }

    // BCLI-018: the append finds minimal.toml the way the other commands do.
    #[test]
    fn init_entry_type_appends_from_subdirectory() {
        let root = project(LEGACY_SCAFFOLD);
        let sub = root.path().join("src").join("bin");
        std::fs::create_dir_all(&sub).expect("create the subdirectory");
        let path = append_from(&sub, "worker").expect("the entry is appended");
        assert_eq!(path, root.path().join(mfile::MFILE_NAME));
        let after: toml::Table = read(&root).parse().unwrap();
        assert_eq!(after["boxes"]["worker"]["type"].as_str(), Some("task"));
        assert!(
            !sub.join(mfile::MFILE_NAME).exists(),
            "no file in the subdirectory"
        );
        assert!(
            !sub.join(".minimal").exists(),
            "no file in the subdirectory"
        );
        assert!(!root.path().join("src").join(mfile::MFILE_NAME).exists());
    }

    // BCLI-018: a minimal.toml that does not parse is invalid configuration,
    // exit 3, and the refusal names the file.
    #[test]
    fn init_invalid_mfile_exit3_appends_nothing() {
        const BROKEN: &str = "[boxes.dev\ntype = \"session\"\n";
        let root = project(BROKEN);
        let sub = root.path().join("src");
        std::fs::create_dir(&sub).expect("create the subdirectory");
        let file = root.path().join(mfile::MFILE_NAME);
        for dir in [root.path(), sub.as_path()] {
            let refusal = append_from(dir, "worker").unwrap_err();
            assert_eq!(refusal.code, 3, "{}", refusal.message);
            assert!(
                refusal
                    .message
                    .starts_with("min init did not add the entry"),
                "{}",
                refusal.message
            );
            assert!(
                refusal.message.contains(&file.display().to_string()),
                "{}",
                refusal.message
            );
            assert!(
                refusal.message.contains("invalid TOML"),
                "{}",
                refusal.message
            );
            assert_eq!(read(&root), BROKEN, "the file is unchanged");
        }
    }

    // BCLI-018: both layouts in one directory are refused, as mfile refuses them.
    #[test]
    fn init_conflicting_layouts_exit3_appends_nothing() {
        let root = project(LEGACY_SCAFFOLD);
        let dot = root.path().join(".minimal");
        std::fs::create_dir(&dot).expect("create .minimal");
        let dot_file = dot.join(mfile::MFILE_NAME);
        std::fs::write(&dot_file, LEGACY_SCAFFOLD).expect("write .minimal/minimal.toml");
        let sub = root.path().join("src");
        std::fs::create_dir(&sub).expect("create the subdirectory");
        for dir in [root.path(), sub.as_path()] {
            let refusal = append_from(dir, "worker").unwrap_err();
            assert_eq!(refusal.code, 3, "{}", refusal.message);
            let root_file = root.path().join(mfile::MFILE_NAME);
            for path in [&root_file, &dot_file] {
                assert!(
                    refusal.message.contains(&path.display().to_string()),
                    "{}",
                    refusal.message
                );
            }
            assert_eq!(read(&root), LEGACY_SCAFFOLD, "the root file is unchanged");
            assert_eq!(
                std::fs::read_to_string(&dot_file).unwrap(),
                LEGACY_SCAFFOLD,
                "the .minimal file is unchanged"
            );
        }
    }
}
