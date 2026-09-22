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
