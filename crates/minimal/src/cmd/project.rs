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
    if let Some(line) = run_init_flow(config, false, false)?.result_line() {
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
pub(crate) enum UploadDecision {
    /// Upload from the resolved root.
    Upload,
    /// Empty dir or `$HOME`: skip silently.
    SkipEmptyOrHome,
    /// Non-VCS, no `minimal.toml`, headless: skip with the shared warning.
    SkipUndeclared,
    /// Non-VCS, no `minimal.toml`, interactive: confirm before uploading.
    Confirm,
}

/// The upload decision, resolved from inputs that need no TTY. [`resolve_upload_root`]
/// already ran, so this folds the empty/`$HOME` carve-out and
/// [`file_upload::upload_gate`] into one value the callers can act on: the
/// interactive `Confirm` case is resolved by the caller (the CLI prompts, the
/// dashboard asks its own UI), and nothing here touches the daemon.
pub(crate) fn decide_workspace_upload(
    root: &camino::Utf8Path,
    sync_explicit: bool,
    headless: bool,
) -> UploadDecision {
    // An empty box has nothing to sync, and `$HOME` — even when non-empty or
    // itself a VCS root — is far too much to bulk-upload on a stray keystroke.
    // A deliberate `--sync tarball` (`sync_explicit`) is the escape hatch that
    // still uploads both.
    if !sync_explicit
        && file_upload::is_empty_or_home(root.as_std_path(), std::env::home_dir().as_deref())
    {
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

/// Which upload progress presentation the caller wants: the CLI's spinner bar,
/// or the quiet path the `min dash` TUI owns its screen with. Under `Quiet`
/// the shared notices are suppressed too, so a background create never writes
/// over the TUI frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadProgress {
    Bar,
    Quiet,
}

/// What [`run_workspace_upload`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceUpload {
    /// The workspace tree was streamed to the daemon.
    Uploaded,
    /// The upload was skipped without asking (empty/`$HOME`, or headless on
    /// an undeclared non-VCS root).
    Skipped,
    /// The interactive confirm was declined.
    Declined,
}

/// Runs [`UploadDecision`] against the daemon: prints the shared notices,
/// prompts through `ask` only for [`UploadDecision::Confirm`], refuses when
/// `refuse_on_dropped_hooks` and a skip would drop project hooks, and uploads
/// via `client`. `progress` picks the bar or the quiet path.
///
/// The upload's failure is returned to the caller, which owns the teardown
/// (`withdraw_box_row` for the CLI, `AbortSession` for the dashboard) — the
/// session exists on the daemon by the time this runs.
#[allow(clippy::too_many_arguments)] // one home for a sequence three callers share; splitting the args would hide the flow
pub(crate) async fn run_workspace_upload(
    client: &mut client::Client,
    id: sessions::SessionId,
    invoked_from: &camino::Utf8Path,
    root: &camino::Utf8Path,
    decision: UploadDecision,
    ask: impl FnOnce() -> Result<bool, anyhow::Error>,
    refuse_on_dropped_hooks: bool,
    progress: UploadProgress,
) -> Result<WorkspaceUpload, anyhow::Error> {
    // The TUI owns its own screen, so only the CLI's bar mode prints the
    // notices; the wording still has one home here.
    let say = |line: &str| {
        if progress == UploadProgress::Bar {
            eprintln!("{line}");
        }
    };
    if decision == UploadDecision::SkipEmptyOrHome {
        say("Starting with an empty box (nothing here to sync)");
        return Ok(WorkspaceUpload::Skipped);
    }
    // Upload from the project root — the directory the mfile lives in — rather
    // than wherever the user invoked us, so `min activate ./subdir` still
    // uploads the whole project.
    if root != invoked_from {
        say(&format!(
            "Uploading from project root {root} (resolved from {invoked_from})"
        ));
    }
    match decision {
        UploadDecision::SkipUndeclared => {
            // Skipping the upload means the project's `minimal.toml` never
            // reaches the daemon, so any lifecycle hooks it declares are
            // discarded and never run. When the caller asked us to, refuse
            // loudly instead of exiting 0 on a session silently missing them.
            if refuse_on_dropped_hooks {
                let dropped_hooks = project_lifecycle_hook_count(root);
                if dropped_hooks > 0 {
                    bail!(
                        "{root} is not a version control repository root, so its \
                         file upload is being skipped — but its {name} declares \
                         {dropped_hooks} lifecycle hook(s) that reach the session only \
                         through that upload. They would be silently dropped and never \
                         run. Pass `--sync tarball` to upload the project (hooks \
                         included), or `--sync none` to start without them deliberately.",
                        name = mfile::MFILE_NAME,
                    );
                }
            }
            say(&file_upload::skipped_upload_warning(root.as_std_path()));
            Ok(WorkspaceUpload::Skipped)
        }
        UploadDecision::Confirm => {
            if ask()? {
                upload_workspace(client, id, root, progress).await
            } else {
                say("Skipping file upload; the session will start with an \
                     empty workspace.");
                Ok(WorkspaceUpload::Declined)
            }
        }
        UploadDecision::Upload => upload_workspace(client, id, root, progress).await,
        UploadDecision::SkipEmptyOrHome => unreachable!("handled above"),
    }
}

/// Streams the workspace tree, mapped onto [`WorkspaceUpload`] with the shared
/// failure context.
async fn upload_workspace(
    client: &mut client::Client,
    id: sessions::SessionId,
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
/// only the session id (see [`activate_session`]).
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

/// Run the init flow for a given config: detect the project's stack,
/// generate a `minimal.toml`, show the plan, prompt for confirmation,
/// and write the file. Shared by `cmd_init` and the `cmd_activate`
/// missing-mfile prompt.
pub(crate) fn run_init_flow(
    config: mctx::Config,
    skip_confirm: bool,
    force: bool,
) -> Result<InitOutcome, anyhow::Error> {
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
            return Ok(InitOutcome::Declined);
        }
    }

    std::fs::write(&plan.toml_path, &plan.content)
        .with_context(|| format!("writing {}", plan.toml_path.display()))?;

    Ok(if exists {
        InitOutcome::Updated(plan.toml_path)
    } else {
        InitOutcome::Created(plan.toml_path)
    })
}

/// Initialize a `minimal.toml` based on the source tree.
pub async fn cmd_init(global: &GlobalArgs, args: InitArgs) -> Result<(), mctx::Error> {
    let config = build_config(global)?;
    let outcome = run_init_flow(config, args.yes, args.force).map_err(mctx::Error::Other)?;
    // stdout: the result line is `min init`'s scriptable output, so it
    // survives `min init > audit.log` while the preview and prompt above
    // stay on stderr.
    if let Some(line) = outcome.result_line() {
        println!("{line}");
    }
    Ok(())
}

/// Whether `min update` / `min add` should warm the host artifact cache after
/// moving a pin.
///
/// Only a native daemon reads the host cache. A VM-backed provider caches on
/// its own guest data volume and never reads the host cache, so warming it
/// there spends bandwidth and disk on artifacts no session start reads — the
/// daemon re-fetches the whole closure on the next activate regardless.
pub(crate) fn should_warm_host_cache(use_minvmd: bool) -> bool {
    client::client_provider_kind(use_minvmd) != paths::ProviderKind::Minvmd
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
            "Note: not warming the host cache; the session daemon fetches the \
             closure into its own cache on the next `min session activate`."
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

    if report.upstream.is_some() || !report.sideloads.is_empty() {
        println!(
            "\nRe-pinned minimal.toml (a diff to commit). The next \
             'min session activate' materializes the new closure, which can \
             take several minutes on the first activate.\n\
             This did not update the 'min' binary; reinstall it with the \
             installer to do that."
        );
    } else {
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
            "Note: not warming the host cache; the session daemon fetches the \
             closure into its own cache on the next `min session activate`."
        );
    }

    Ok(())
}
