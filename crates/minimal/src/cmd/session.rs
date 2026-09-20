use super::*;

/// Whether to announce the resolved or freshly created session on stderr
/// before handing off to the interactive shell. Suppressed under `--no-input`
/// and when stderr is not a terminal, so scripted and CI callers — which read
/// the session id from stdout — see nothing extra.
pub(crate) fn should_announce_session(global: &GlobalArgs) -> bool {
    !global.no_input && std::io::stderr().is_terminal()
}

/// A one-line identity for a session in an attach/create confirmation: the
/// session name plus a short id in parentheses, or just the short id when the
/// session is unnamed. The short id is the leading block of the UUID — enough
/// to tell two same-named sessions built from the same directory apart without
/// the full 36-character id.
pub(crate) fn session_announce_label(id: &sessions::SessionId, name: Option<&str>) -> String {
    let id = id.to_string();
    let short = id.split('-').next().unwrap_or(&id);
    match name {
        Some(name) => format!("{name} ({short})"),
        None => short.to_string(),
    }
}

/// The exact command the resolver advisory names: this very binary, run as
/// root. Spelled with the binary's full path because `sudo` resolves commands
/// through its own secure path, on which a user-installed `min` may not be.
pub(crate) fn resolver_setup_command(exe: &std::path::Path) -> String {
    format!("sudo {} net setup", exe.display())
}

/// Renders the resolver advisory for `advisory` (NET-122, NET-123): why
/// `<name>.min.internal` does not resolve natively on this host yet, what
/// that means for where boxes are published, and the one command that fixes
/// it. Writes nothing when there is nothing to advise.
///
/// A pointer only. It asks nothing and runs nothing privileged: the command
/// it names is the privileged step, and the person runs it when they choose.
/// It is printed at every session start until both halves are in place — a
/// host still on the `127.0.0.1` interim is told again each time.
pub(crate) fn write_resolver_advisory(
    out: &mut impl std::io::Write,
    advisory: &minimald_rpc::ResolverAdvisory,
    command: &str,
) -> std::io::Result<()> {
    let mut reasons = Vec::new();
    if !advisory.resolver_configured {
        reasons.push("the host resolver is not configured for the box zone".to_string());
    }
    if !advisory.range_present {
        let gap = advisory
            .range_gap
            .as_deref()
            .map(|gap| format!(" ({gap})"))
            .unwrap_or_default();
        reasons.push(format!(
            "the reserved local range {} is absent{gap}, so boxes are published at 127.0.0.1 \
             for now",
            minimald_rpc::RESERVED_RANGE
        ));
    }
    writeln!(
        out,
        "notice: <name>.{} does not resolve natively on this host yet: {}.",
        minimald_rpc::BOX_ZONE,
        reasons.join("; ")
    )?;
    writeln!(
        out,
        "notice: set it up once with (asks for your password; nothing here prompts):"
    )?;
    writeln!(out, "  {command}")
}

/// Renders the NET-018 notice: native resolution is fully in place, so
/// `<name>.min.internal` resolves without the proxy — and NET-019's other
/// half, that the proxy keeps serving anyway, for anything already pointed
/// at it. Shared by `min session activate` and `min ls` so both print the
/// exact same line.
pub(crate) fn write_native_surface_notice(out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "notice: <name>.{} resolves natively on this host; that is the live surface. \
         The hostname proxy keeps serving too, for anything already pointed at it.",
        minimald_rpc::BOX_ZONE
    )
}

/// Prints the resolver advisory on stderr: the daemon's when it sent one,
/// otherwise this host's own judgement. A daemon inside a microVM (every
/// daemon on macOS) or one that predates the field says nothing, and nothing
/// from the daemon must not read as nothing to do: the resolver hook and the
/// reserved range live on the host this binary runs on, so it reads them
/// itself ([`crate::net::host_resolution_advisory`]).
///
/// `None` after that merge means native resolution is fully in place
/// (NET-018): the positive notice prints instead of nothing.
fn advise_resolver(advisory: Option<&minimald_rpc::ResolverAdvisory>) {
    let merged = advisory
        .cloned()
        .or_else(crate::net::host_resolution_advisory);
    let mut stderr = std::io::stderr().lock();
    // A stderr write that fails is not worth failing the activation over.
    let _ = match &merged {
        Some(advisory) => {
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("min"));
            let command = resolver_setup_command(&exe);
            write_resolver_advisory(&mut stderr, advisory, &command)
        }
        None => write_native_surface_notice(&mut stderr),
    };
}

/// `min ls`'s NET-018 counterpart to [`advise_resolver`]: prints the native
/// surface notice once resolution is confirmed native, and nothing
/// otherwise — `ls` does not repeat the "how to fix it" advisory an
/// activation already gave. `name_surface` is the daemon's own judgement
/// (absent from a daemon inside a microVM, or one that predates the field),
/// with the same host self-check as `min session activate` falls back to.
pub(crate) fn advise_native_surface(name_surface: Option<minimald_rpc::NameSurface>) {
    let native = match name_surface {
        Some(minimald_rpc::NameSurface::Native) => true,
        Some(minimald_rpc::NameSurface::Proxy) => false,
        None => crate::net::host_resolution_advisory().is_none(),
    };
    if native {
        // A stderr write that fails is not worth failing the list over.
        let _ = write_native_surface_notice(&mut std::io::stderr().lock());
    }
}

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    activate_session(global, args, true).await
}

/// Tells the user which port this daemon's hostname proxy is serving on, as the
/// daemon reported it (NET-026), and nothing at all when it reported no port.
///
/// The port is discovered rather than assumed because it is not a constant: an
/// unconfigured daemon takes the standard port while it is free and a free port
/// otherwise, so on a machine running two daemons — a native one and a VM one —
/// the second one's names are reachable on a port only that daemon knows. A
/// daemon that reports nothing (it predates the field, or its listener has not
/// bound and it is warning about that instead) gets no line: printing a guessed
/// port would be worse than printing none.
pub fn write_hostname_proxy_port(
    out: &mut impl std::io::Write,
    port: Option<u16>,
) -> std::io::Result<()> {
    let Some(port) = port else {
        return Ok(());
    };
    writeln!(
        out,
        "box hostnames (*.min.internal) route through this daemon's proxy at 127.0.0.1:{port}"
    )
}

/// The activation flow shared by [`cmd_activate`] and the bare-`min` router.
/// `offer_scaffold` gates the `minimal.toml` scaffold offer: `cmd_activate`
/// keeps it (its long-standing behavior, unchanged), while bare `min`
/// suppresses it — that path must land in a session, never in a config
/// prompt. Everything else, including the session id on stdout, is
/// identical for both callers.
pub(crate) async fn activate_session(
    global: &GlobalArgs,
    args: ActivateArgs,
    offer_scaffold: bool,
) -> Result<(), anyhow::Error> {
    // NET-037: a legacy `--network` spelling still parses, but earns a
    // one-line hint naming the current spelling; nothing else about the
    // run differs.
    if let Some((old, new)) = args.network.legacy_hint() {
        crate::notice::legacy_spelling_hint(&mut std::io::stderr(), "--network", old, new);
    }

    // NET-076: while the deny-all default for an absent `egress` section is
    // announced but not yet in force, every activate says so — the change is
    // coming, and this box still reaches everything until it lands.
    announce_deny_all_default(&mut std::io::stderr(), sessions::DenyAllDefault::from_env());

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
        dynamic_ingress: args.dynamic_ingress.map(Into::into),
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
        project_path: abs_path.clone(),
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

    // Scaffold-offer a missing `minimal.toml` only after loadouts resolve:
    // a bad `--loadout` must error before anything prints, so the user is
    // never told the session is proceeding and then that it is not.
    if offer_scaffold {
        offer_mfile_scaffold(&utf8_path, global)?;
    }

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
    let hook_scripts = loadouts::stage_loadout_hook_scripts(&active, &abs_path, !args.no_hooks)?;

    // Same idea for the *project's* hooks, which the daemon composes from
    // the uploaded mfile and which therefore never pass through the
    // staging above. Nothing here is uploaded — the project tree carries
    // its own scripts — but the checks a staging pass would have made are
    // still worth making on this machine, before a session exists.
    if !args.no_hooks {
        loadouts::check_project_hooks(&abs_path)?;
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

    // Deliberately not `connect_daemon`: this path's version gate travels on
    // the `CreateSession` below rather than on a `GetVersion` sent ahead of it.
    // Activation is the hot path #1251's gate landed on, and it must not pay a
    // round trip for a check its own first RPC can make.
    let mut client = connect_daemon_unchecked(global).await?;

    // Warn before minting a second session for a path that already has one:
    // the duplicate leaves bare `min` from this directory ambiguous between
    // them. Advisory only — a listing failure (ordinary transport or
    // daemon-side error) must not block activation, so the duplicate check is
    // skipped on error. But `oneshot_rpc` reuses one `russh` handle, and a
    // transport-level listing failure can close the shared connection, which
    // would then break the `CreateSession` channel below; so on any listing
    // error, reconnect before creation. A benign daemon-side error leaves the
    // old connection usable and the reconnect is merely a no-op cost on the
    // rare failure path — the happy path still pays no extra round trip. The
    // hard version gate is unaffected: `CreateSession` below carries its own
    // `must_match_version`, so a version-skewed daemon is still refused there
    // even when this enumeration is skipped.
    match list_sessions_version_gated(&mut client).await {
        Ok(existing_sessions) => {
            if let Some(warning) =
                duplicate_session_warning(&existing_sessions.sessions, &config.project_path)
            {
                eprintln!("{warning}");
            }
            // NET-026: the port comes from the daemon we just connected to, not
            // from a constant here — a second daemon on this machine serves its
            // names on a port of its own.
            let _ = write_hostname_proxy_port(
                &mut std::io::stderr().lock(),
                existing_sessions.hostname_proxy_port,
            );
        }
        Err(_) => {
            // The listing failed. A transport-level closure can leave the
            // shared `russh` handle unusable, which would then break the
            // `CreateSession` channel below, so try to reconnect. But a
            // daemon-side listing error closes only the RPC channel and leaves
            // the SSH connection intact — so if the reconnect itself fails,
            // keep the original client and let `CreateSession` proceed on it
            // rather than aborting activation outright. `CreateSession` carries
            // its own hard version gate and surfaces a clear error if the
            // connection really is dead, so retaining the original client can
            // only help the daemon-side-error case and never regresses the
            // transport-closure case.
            if let Ok(reconnected) = connect_daemon_unchecked(global).await {
                client = reconnected;
            }
        }
    }

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
                // The version gate: a daemon of another build refuses this
                // call outright, before it has allocated anything to tear
                // down. `None` under the skew override, which is what lets an
                // operator proceed.
                must_match_version: version_assertion(),
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
    // The other half of the gate: a daemon old enough to predate
    // `must_match_version` ignored the assertion instead of answering it, and
    // says so by echoing no version at all. Being older than the field is
    // itself proof of a skew, so refuse here — still before the upload, the
    // loadout, and the finalize that #1251 died at, and with the session left
    // unfinalized for the daemon to reap when this connection drops.
    ensure_version_reported(created.daemon_version.as_deref())?;
    warn_if_hostname_routing_down(created.hostname_routing_unavailable.as_deref());
    advise_resolver(created.resolver_advisory.as_ref());
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
            // (e.g. `~`). A VCS root, or a directory carrying a
            // `minimal.toml` (a declared project), uploads unconditionally.
            // For an undeclared non-VCS root an interactive caller gets the
            // confirm (default No); a headless caller (CI, pipes, agents,
            // `--no-prompt`, `--no-input`) can't be asked, so it skips the
            // upload with a warning rather than silently shipping a directory
            // nobody confirmed — `--sync tarball` (via `sync_explicit`) is the
            // escape hatch that force-uploads it anyway (#770).
            let headless = args.no_prompt || global.no_input || !can_prompt_interactively();
            let should_upload = match file_upload::upload_gate(
                file_upload::is_vcs_root(upload_root.as_std_path()),
                sync_explicit,
                project_has_mfile(&upload_root),
                headless,
            ) {
                file_upload::UploadGate::Upload => true,
                file_upload::UploadGate::SkipHeadless => {
                    // Skipping the upload means the project's minimal.toml
                    // never reaches the daemon, so any lifecycle hooks it
                    // declares are discarded and never run. Refuse loudly
                    // instead of exiting 0 on a session silently missing
                    // them; the caller can force the upload or opt out on
                    // purpose.
                    let dropped_hooks = project_lifecycle_hook_count(&upload_root);
                    if dropped_hooks > 0 {
                        bail!(
                            "{upload_root} is not a version control repository root, so its \
                             file upload is being skipped — but its {name} declares \
                             {dropped_hooks} lifecycle hook(s) that reach the session only \
                             through that upload. They would be silently dropped and never \
                             run. Pass `--sync tarball` to upload the project (hooks \
                             included), or `--sync none` to start without them deliberately.",
                            name = mfile::MFILE_NAME,
                        );
                    }
                    eprintln!(
                        "{}",
                        file_upload::skipped_upload_warning(upload_root.as_std_path())
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
        // Bails before the `println!("{id}")` below: a session that cannot
        // compose never puts an id on stdout for a script to capture.
        minimald_rpc::Errorable::Err { error } => {
            bail!(composition_failure_message(&utf8_path, &error));
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
                    // The route an activation actually reaches today: the
                    // daemon routes project config back for gating, so a
                    // project it cannot compose surfaces here rather than as
                    // the `Errorable::Err` above.
                    bail!(composition_failure_message(&utf8_path, &e.to_string()));
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
                &utf8_path,
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

    // A named box is addressed by its name alone: with more than one VM on the
    // machine, the VM holding it is resolved from the name rather than from a
    // flag (NET-058). With no box named, the resolution below is the current
    // directory's, on this machine's default box host — where a bare `min`
    // creates one when it finds nothing.
    let sock = match args.session {
        Some(ref session) => resolve_box_host(global, session).await?.sock,
        None => client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
            .context("Failed to resolve daemon socket path")?,
    };

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    // Connects directly rather than through `connect_daemon` (it needs `sock`
    // for the ssh hand-off), so the gate is applied by hand — with no session
    // named, this path creates one, and a skewed activation is #1251 exactly.
    // Both arms below gate on the build the daemon reports on the lookup they
    // were already making, so the gate costs no round trip of its own.
    let (id, name) = match args.session {
        Some(ref s) => {
            let r = resolve_session_version_gated(&mut client, s).await?;
            (r.id, r.name)
        }
        None => match resolve_smart_attach(
            &list_sessions_version_gated(&mut client).await?.sessions,
            global,
        )? {
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

    session_via_ssh(&sock, id, None, global.config_dir.as_deref()).await
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
    // Gated by hand for the same reason as `cmd_attach`: this hands off into a
    // live session (the daemon mints the exec channel and runs the attach
    // hooks around it), which is not something to drive on a skewed pair. The
    // gate rides on the lookup's reply — no `GetVersion` ahead of it.
    let r = resolve_session_version_gated(&mut client, &args.session).await?;
    tracing::info!(
        session_id = %r.id,
        session_name = ?r.name,
        "found session"
    );

    session_via_ssh(
        &sock,
        r.id,
        minimal_client::attach::remote_command(&args.command),
        None,
    )
    .await
}

/// Runs a task declared by the session's project, in that session.
///
/// The daemon services this itself rather than handing it to the session's
/// shell, so the task composes against the session's context. Named on the wire
/// as [`minimald_rpc::exec::ExecRequest::TaskRun`]; nothing is inferred from the
/// text, which is what lets a task share a name with a program on `PATH`.
pub async fn cmd_session_run(
    global: &GlobalArgs,
    args: SessionRunArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    // Gated by hand for the same reason as `cmd_exec`: this hands off into a
    // live session, which is not something to drive on a skewed pair.
    let r = resolve_session_version_gated(&mut client, &args.session).await?;
    tracing::info!(
        session_id = %r.id,
        session_name = ?r.name,
        task = %args.task,
        "found session"
    );

    session_via_ssh(
        &sock,
        r.id,
        Some(minimald_rpc::exec::ExecRequest::TaskRun(args.task).encode()),
        None,
    )
    .await
}

/// Resolve a session to attach to when the user supplied no explicit session
/// reference. Matches an already-fetched session list against the current
/// working directory, and either attaches directly (unambiguous), opens the
/// interactive picker (ambiguous), or errors (ambiguous but non-interactive).
///
/// Takes the list rather than fetching it so its two callers can assert the
/// daemon's build off the `ListSessions` reply — before the picker blocks on a
/// human, not after.
///
/// Returns [`SmartAttach::NoSessions`] when no sessions exist at all, which
/// `min session attach` reports as an error pointing at `min session activate`.
pub(crate) fn resolve_smart_attach(
    sessions: &[minimald_rpc::ListSessionsEntry],
    global: &GlobalArgs,
) -> Result<SmartAttach, anyhow::Error> {
    let cwd = attach::cwd_host_path(global)?;
    match attach::resolve_for_attach(sessions, &cwd) {
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
            Ok(SmartAttach::Attach(Box::new(entry)))
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
pub(crate) enum SmartAttach {
    /// Attach to this resolved or picked session. Boxed so the outcome stays
    /// the size of its other two answers, which carry nothing.
    Attach(Box<minimald_rpc::ListSessionsEntry>),
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
pub(crate) async fn activate_new_for_attach(global: &GlobalArgs) -> Result<(), anyhow::Error> {
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
            dynamic_ingress: None,
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
pub(crate) fn ensure_interactive_attach_tty(stdin_is_tty: bool) -> Result<(), anyhow::Error> {
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
///
/// The interactive path (no `wire`) negotiates the configurable session
/// keys from `config_dir` so the daemon adopts the user's detach/forward
/// chord for that channel; the exec path (`wire` set) has no detach
/// and sends none.
pub(crate) async fn session_via_ssh(
    sock: &std::path::Path,
    id: sessions::SessionId,
    wire: Option<String>,
    config_dir: Option<&std::path::Path>,
) -> Result<(), anyhow::Error> {
    // The command itself lives in minimal-client, shared with the dash TUI's
    // suspend-attach-resume flow. The interactive path resolves the
    // session-key config from `config_dir` and forwards it per channel; the
    // exec path has no detach and passes `None`.
    let session_keys = if wire.is_none() {
        Some(minimal_client::attach::resolve_session_keys(config_dir)?)
    } else {
        None
    };
    let mut ssh =
        minimal_client::attach::attach_command(sock, id, wire.as_deref(), session_keys.as_ref())?;

    // `-tt` over a *non-terminal* stdin is a trap: ssh still forces the
    // remote PTY, yet the interactive shell reading it never sees an EOF from a
    // redirected local stdin (`< /dev/null`, a pipe), so the command blocks
    // forever (#953). Fail fast instead of hanging.
    if wire.is_none() {
        ensure_interactive_attach_tty(std::io::stdin().is_terminal())?;

        // The interactive path waits on ssh rather than `exec()`ing it, so this
        // process outlives the attach by the moment it takes to put the
        // terminal back. `minimald` sends unwind codes with every teardown it
        // initiates, but a transport that drops mid-session sends nothing at
        // all, and once ssh is gone this is the only process left that can
        // still reach the tty. So the guard stays armed for the duration and
        // is stood down only once ssh's exit proves the daemon was alive and
        // speaking — see `attach::client_must_unwind`. `min dash` already runs
        // the same command as a child while it is suspended.
        let mut unwind = attach::TerminalUnwind::arm();
        let status = match tokio::process::Command::from(ssh).status().await {
            Ok(status) => status,
            Err(e) => {
                // ssh never ran, so nothing of ours reached the terminal and
                // there is nothing to put back.
                unwind.disarm();
                return Err(e).context("failed to run ssh");
            }
        };
        if !attach::client_must_unwind(&status) {
            unwind.disarm();
        }
        let code = exit_code_of(status);
        drop(unwind);
        // Terminate with ssh's own status, exactly as the `exec()` this
        // replaced did: `min` has nothing of its own left to say after an
        // attach, and the guard above has already run.
        std::process::exit(code);
    }

    let err = ssh.exec();
    // exec() only returns on failure
    bail!("failed to exec ssh: {err}");
}

/// A child's exit status as this process's exit code, following the shell's
/// `128 + signal` convention for a signalled child. Reproduces what `exec()`
/// gave for free: the client's status *is* ssh's.
pub(crate) fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

/// Announce the deny-all default for an absent `egress` section while it is
/// announced but not yet in force (NET-076): the change is coming for a box with
/// an address of its own that declares no destinations, and the opt-out flag
/// keeps today's reach. Nothing is written once the window is in force — the
/// default is then the box's actual posture, which `min session policy` names
/// (NET-075) — or when the opt-out flag is already set, where nothing is coming.
///
/// Written through `out` rather than to stderr directly, so what activate prints
/// is assertable without capturing the process's stderr.
pub(crate) fn announce_deny_all_default(
    out: &mut impl std::io::Write,
    default: sessions::DenyAllDefault,
) {
    if default.window != sessions::DenyAllWindow::Announced || default.opted_out {
        return;
    }
    let _ = writeln!(
        out,
        "note: a coming release makes deny-all the default for a box with an \
         address of its own and no `egress` section — such a box will reach \
         nothing until it declares the destinations it needs; set {}=1 to keep \
         the current allow-all default",
        sessions::DENY_ALL_OPT_OUT_VAR
    );
}

/// The posture line `min session policy` writes beside the JSON when the box's
/// effective egress reaches nothing (NET-075). Deny-all is the one posture the
/// JSON states by omission — an `allow_subnets` list with no entry in it — so it
/// is named in words, while stdout stays the machine-readable policy. `None` for
/// a box that declares destinations, or declares no section at all.
pub(crate) fn egress_posture_line(policy: &sessions::SessionPolicy) -> Option<String> {
    policy
        .egress
        .as_ref()
        .is_some_and(sessions::EgressPolicy::is_deny_all)
        .then(|| {
            "egress: deny-all — this box declares no destination, so it reaches nothing \
             outside the resolver Minimal owns for it"
                .to_string()
        })
}

/// Print the effective networking policy for a session as JSON.
pub async fn cmd_session_policy(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<(), anyhow::Error> {
    let policy = session_policy(global, args).await?;
    println!("{}", policy_line(&policy)?);
    if let Some(line) = egress_posture_line(&policy) {
        eprintln!("{line}");
    }
    Ok(())
}

/// Ask the daemon for a session's effective networking policy and render it as
/// the JSON line [`cmd_session_policy`] prints: the egress rules the daemon
/// parsed — every field of the box's `egress` section, including the subnets it
/// denies — beside its ingress forwarding, and beside the node-plane baseline
/// set the host-side helper enumerates (NET-130): what the daemon's own traffic
/// may reach whatever the box declares, by category.
///
/// Split from the command so what the user reads is assertable without
/// capturing stdout.
pub async fn session_policy_json(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<String, anyhow::Error> {
    policy_line(&session_policy(global, args).await?)
}

/// Render `policy` as the JSON line shown: the box's policy with the node-plane
/// baseline set the host-side helper enumerates beside it (NET-130).
fn policy_line(policy: &sessions::SessionPolicy) -> Result<String, anyhow::Error> {
    /// The line as shown: the box's policy with the baseline set beside it.
    #[derive(serde::Serialize)]
    struct Shown<'a> {
        #[serde(flatten)]
        policy: &'a sessions::SessionPolicy,
        baseline: minvmd::net::BaselineSet,
    }

    serde_json_lenient::to_string(&Shown {
        policy,
        baseline: minvmd::net::BaselineSet::from_host_env(),
    })
    .context("Failed to serialize policy")
}

/// The policy the daemon holds for the session `args` names.
async fn session_policy(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<sessions::SessionPolicy, anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let lookup: GetSessionPolicyRequest = SessionLookup::parse(&args.session).into();

    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(lookup)
        .await
        .context("GetSessionPolicy RPC failed")?;

    match resp {
        minimald_rpc::Errorable::Ok(policy) => Ok(policy),
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
    // Gated: the record read here is baked into Zed's settings.json and
    // outlives the command, so it must not be sourced from a daemon the
    // operator is about to restart onto another build. The daemon names its
    // build on the lookup's own reply.
    let record = resolve_session_version_gated(&mut daemon_client, &args.session).await?;

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
pub(crate) async fn cmd_session_hooks(
    global: &GlobalArgs,
    args: HooksArgs,
) -> Result<(), anyhow::Error> {
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
pub(crate) fn render_hook_source(source: &sessions::wire::primitives::WireSource) -> String {
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
pub(crate) fn render_hook_script(
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
pub(crate) enum AtRiskState {
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
pub(crate) fn assess_at_risk(resp: Option<minimald_rpc::SessionDeltaResponse>) -> AtRiskState {
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
pub(crate) enum DestroyGate {
    /// Destroy without prompting: `--force`, or the session is proven
    /// clean.
    Proceed,
    /// Prompt interactively (default No) before destroying.
    Confirm,
}

/// Decides whether a single-session destroy proceeds promptless, may
/// prompt, or must refuse — one match over (force, at-risk state,
/// interactivity).
pub(crate) fn destroy_gate(
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
pub(crate) async fn session_delta(
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

pub(crate) async fn destroy_all_sessions(
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

pub(crate) async fn destroy_session(
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
    // Unchecked: stopping a version-skewed daemon is exactly what the version
    // gate tells the operator to do, so this command must never be gated by it.
    let mut client = connect_daemon_unchecked(global).await?;

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
pub(crate) async fn daemon_confirmed_stopped(
    use_minvmd: bool,
    minimal_dir: Option<PathBuf>,
) -> bool {
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
pub(crate) async fn stop_outcome<W, C>(
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

// ---------------------------------------------------------------------------
// Box hosts across the machine's VMs (NET-057, NET-058)

/// One box host on this machine: the VM it serves and the socket its daemon
/// answers on.
///
/// A machine can run several. A VM started with `minvmd --vm-name <name>` has
/// its own state directory, socket and box-host daemon under `vms/<name>/`,
/// while the `default` VM's socket is the provider instance dir's own. The
/// name is in the path, which is what lets the CLI find a box's VM from the
/// box's name alone rather than from a flag naming the VM (NET-058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoxHost {
    /// The VM whose box host this is — `default` for the unnamed one.
    pub(crate) vm: String,
    /// The daemon socket that serves it.
    pub(crate) sock: PathBuf,
}

/// Every box host on this machine: the `default` VM first, then each named VM
/// in name order.
///
/// A VM is here when its socket is present — the CLI addresses box hosts over
/// sockets, and a VM directory with none has no daemon to talk to. The
/// `default` VM leads so that on a machine with one box host the answer is the
/// socket the CLI always resolved, unchanged.
pub(crate) fn box_hosts(global: &GlobalArgs) -> Result<Vec<BoxHost>, anyhow::Error> {
    let provider_dir =
        client::resolve_provider_dir(global.minimal_dir.as_deref(), global.use_minvmd())
            .context("Failed to resolve the provider directory")?;
    let mut hosts = vec![BoxHost {
        vm: paths::DEFAULT_VM_NAME.to_string(),
        sock: provider_dir.join(paths::SSH_SOCK_FILE),
    }];
    // A missing `vms/` dir is a machine that has only ever run the default VM,
    // which is the ordinary case and not a fault.
    let mut named: Vec<BoxHost> = std::fs::read_dir(provider_dir.join(paths::VMS_SUBDIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let vm = entry.file_name().into_string().ok()?;
            // Only a directory `minvmd --vm-name` could have created: anything
            // else under `vms/` names no VM this CLI can address.
            paths::VmName::new(&vm).ok()?;
            let sock = entry.path().join(paths::SSH_SOCK_FILE);
            sock.exists().then_some(BoxHost { vm, sock })
        })
        .collect();
    named.sort_by(|a, b| a.vm.cmp(&b.vm));
    hosts.extend(named);
    Ok(hosts)
}

/// `ListSessions` against one VM's box host, every entry stamped with that VM.
///
/// The connection is deliberately not version-gated: this reads another VM's
/// listing rather than handing off into a session on it, and a VM running a
/// different build must still be *visible* — its boxes are what a listing is
/// for. The command that goes on to act on a box asserts the build on its own
/// connection to that box's host.
async fn list_one_vm(
    host: &BoxHost,
) -> Result<Vec<minimald_rpc::ListSessionsEntry>, anyhow::Error> {
    let mut client = client::Client::connect(&host.sock)
        .await
        .with_context(|| format!("Failed to connect to the box host of VM '{}'", host.vm))?;
    let resp = client
        .oneshot_rpc::<minimald_rpc::ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;
    Ok(resp
        .sessions
        .into_iter()
        .map(|mut entry| {
            entry.vm = Some(host.vm.clone());
            entry
        })
        .collect())
}

/// Adds the other VMs' boxes to `resp` and says which VM holds each box
/// (NET-057).
///
/// A machine with one box host is left exactly as it was: there is no VM to
/// tell apart, no entry is stamped, and the listing costs the one round trip it
/// always did. A VM whose box host does not answer is reported on stderr and
/// skipped — one VM being down must not take the whole listing with it. The
/// rest of the response (the daemon's version, its proxy port, its
/// hostname-routing fault) stays the primary box host's, which is the daemon
/// the command connected to.
pub(crate) async fn list_boxes_across_vms(
    global: &GlobalArgs,
    resp: &mut minimald_rpc::ListSessionsResponse,
) {
    let hosts = match box_hosts(global) {
        Ok(hosts) => hosts,
        Err(error) => {
            eprintln!("warning: could not look for other VMs' boxes: {error:#}");
            return;
        }
    };
    let Some((primary, others)) = hosts.split_first() else {
        return;
    };
    if others.is_empty() {
        return;
    }
    for entry in &mut resp.sessions {
        entry.vm = Some(primary.vm.clone());
    }
    for host in others {
        match list_one_vm(host).await {
            Ok(sessions) => resp.sessions.extend(sessions),
            Err(error) => eprintln!(
                "warning: could not list the boxes on VM '{}': {error:#}",
                host.vm
            ),
        }
    }
}

/// Whether `entry` is the box `lookup` names — by name, or by id.
fn entry_is(entry: &minimald_rpc::ListSessionsEntry, lookup: &SessionLookup) -> bool {
    match lookup {
        SessionLookup::Id(id) => entry.id == *id,
        SessionLookup::Name(name) => entry.name.as_deref() == Some(name.as_str()),
    }
}

/// The box host holding the box `session` names, resolved from the name alone
/// (NET-058).
///
/// With one box host on the machine nothing needs resolving: its socket is the
/// answer and no listing is fetched, so the single-VM path is unchanged. With
/// several, each VM's box host is asked whether it holds the name (or id) — the
/// box's name is its address, and no global flag names the VM. A name two VMs
/// both hold is reported as ambiguous, naming both, rather than resolved by an
/// order nobody chose.
pub(crate) async fn resolve_box_host(
    global: &GlobalArgs,
    session: &str,
) -> Result<BoxHost, anyhow::Error> {
    let hosts = box_hosts(global)?;
    if let [single] = &hosts[..] {
        return Ok(single.clone());
    }
    let lookup = SessionLookup::parse(session);
    let mut holders = Vec::new();
    for host in &hosts {
        match list_one_vm(host).await {
            Ok(sessions) => {
                if sessions.iter().any(|entry| entry_is(entry, &lookup)) {
                    holders.push(host.clone());
                }
            }
            // A VM that cannot be listed cannot be shown to hold the box. Said
            // at debug: the resolution below reports the outcome, and a VM that
            // is down is not itself an error when another VM holds the box.
            Err(error) => tracing::debug!(
                vm = %host.vm,
                error = %format!("{error:#}"),
                "could not ask a VM's box host which boxes it holds"
            ),
        }
    }
    match holders.as_slice() {
        [host] => {
            tracing::debug!(box_name = session, vm = %host.vm, "resolved the box to a VM");
            Ok(host.clone())
        }
        [] => bail!(
            "No box named '{session}' on any VM of this machine ({}); `min ls` lists every box \
             with the VM that holds it",
            vm_names(&hosts)
        ),
        many => bail!(
            "'{session}' names a box on more than one VM ({}); rename one so the name addresses \
             a single box",
            vm_names(many)
        ),
    }
}

/// The VMs' names, for a message that has to say which ones were looked at.
fn vm_names(hosts: &[BoxHost]) -> String {
    hosts
        .iter()
        .map(|host| host.vm.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// [`connect_daemon`] for a command that names a box: connects to the box host
/// that holds it, on whichever VM that is (NET-058), with the same build
/// assertion every acting command makes.
pub(crate) async fn connect_box_host(
    global: &GlobalArgs,
    session: &str,
) -> Result<client::Client, anyhow::Error> {
    let host = resolve_box_host(global, session).await?;
    let mut client = client::Client::connect(&host.sock)
        .await
        .with_context(|| format!("Failed to connect to the box host of VM '{}'", host.vm))?;
    ensure_version_match(&mut client).await?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimald::test_harness::{TestClient, TestServer, create_configured_session};

    /// Two VMs on one machine, each with its own box-host daemon: the `default`
    /// VM's on the provider dir's own socket, and a VM named `beta`'s under
    /// `vms/beta/` — the paths `minvmd --vm-name` lays down and the CLI looks
    /// for. The servers and the tempdir are held so the sockets stay live.
    struct TwoVms {
        _default_server: TestServer,
        _beta_server: TestServer,
        _dir: tempfile::TempDir,
        global: GlobalArgs,
        /// A connection to each VM's daemon, for creating that VM's boxes.
        on_default: TestClient,
        on_beta: TestClient,
    }

    async fn two_vms() -> TwoVms {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = dir.path().join("providers/local-minimald0");
        std::fs::create_dir_all(&provider).unwrap();
        let default_server = TestServer::new().await;
        default_server
            .listen_on_uds(&provider.join(paths::SSH_SOCK_FILE))
            .await;
        let beta_dir = provider.join(paths::VMS_SUBDIR).join("beta");
        std::fs::create_dir_all(&beta_dir).unwrap();
        let beta_server = TestServer::new().await;
        beta_server
            .listen_on_uds(&beta_dir.join(paths::SSH_SOCK_FILE))
            .await;
        let on_default = default_server.connect().await;
        let on_beta = beta_server.connect().await;
        TwoVms {
            _default_server: default_server,
            _beta_server: beta_server,
            global: GlobalArgs {
                minimal_dir: Some(dir.path().to_path_buf()),
                ..GlobalArgs::default()
            },
            _dir: dir,
            on_default,
            on_beta,
        }
    }

    /// The `ls` table as the operator reads it.
    fn ls_table(resp: &minimald_rpc::ListSessionsResponse) -> String {
        let mut out = Vec::new();
        format_ls(
            &mut out,
            &LsArgs {
                raw: false,
                json: false,
            },
            resp,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// NET-057: with two VMs running, the listing spans both VMs' box hosts and
    /// every box says which VM holds it — in the entries `--json` carries and
    /// in the table's own column. A single box host's listing is unchanged:
    /// there is no VM to tell apart, so no VM is claimed and no column appears.
    #[tokio::test]
    async fn ls_shows_vm_per_box() {
        let mut vms = two_vms().await;
        create_configured_session(&mut vms.on_default, "on-default", "/tmp").await;
        create_configured_session(&mut vms.on_beta, "on-beta", "/tmp").await;

        // What the command has in hand before it looks for other VMs: the boxes
        // of the one box host it connected to, naming no VM.
        let mut client = connect_daemon(&vms.global).await.unwrap();
        let mut resp = client
            .oneshot_rpc::<minimald_rpc::ListSessions>(())
            .await
            .unwrap();
        assert_eq!(
            resp.sessions.len(),
            1,
            "one box host lists only its own boxes"
        );
        assert!(resp.sessions[0].vm.is_none());
        assert!(
            !ls_table(&resp).contains("VM  "),
            "a listing naming no VM must not grow a VM column"
        );

        list_boxes_across_vms(&vms.global, &mut resp).await;

        let mut listed: Vec<(String, String)> = resp
            .sessions
            .iter()
            .map(|entry| {
                (
                    entry.name.clone().unwrap(),
                    entry.vm.clone().expect("every box names its VM"),
                )
            })
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            [
                ("on-beta".to_string(), "beta".to_string()),
                ("on-default".to_string(), "default".to_string()),
            ]
        );

        let table = ls_table(&resp);
        assert!(
            table.contains("VM  "),
            "no VM column in the table:\n{table}"
        );
        for (box_name, vm) in [("on-default", "default"), ("on-beta", "beta")] {
            let row = table
                .lines()
                .find(|line| line.contains(box_name))
                .unwrap_or_else(|| panic!("{box_name} is missing from the table:\n{table}"));
            assert!(
                row.starts_with(vm),
                "the row for {box_name} must name VM {vm}: {row:?}"
            );
        }
    }

    /// NET-058: with two VMs running, naming a box is enough to reach it —
    /// attach and `min net expose` resolve the VM from the box's name, with no
    /// global flag naming a VM anywhere. A name two VMs both hold is reported
    /// as the ambiguity it is rather than resolved by an order nobody chose.
    #[tokio::test]
    async fn box_name_resolves_vm_without_flag() {
        let mut vms = two_vms().await;
        create_configured_session(&mut vms.on_default, "web", "/tmp").await;
        let api = create_configured_session(&mut vms.on_beta, "api", "/tmp").await;
        create_configured_session(&mut vms.on_default, "twin", "/tmp").await;
        create_configured_session(&mut vms.on_beta, "twin", "/tmp").await;

        // Nothing selects a VM: the only thing named below is the box.
        assert!(vms.global.provider.is_none());
        let hosts = box_hosts(&vms.global).unwrap();
        assert_eq!(
            hosts
                .iter()
                .map(|host| host.vm.as_str())
                .collect::<Vec<_>>(),
            ["default", "beta"],
            "both VMs' box hosts are found from their sockets alone"
        );

        assert_eq!(
            resolve_box_host(&vms.global, "web").await.unwrap().vm,
            "default"
        );
        let resolved = resolve_box_host(&vms.global, "api").await.unwrap();
        assert_eq!(resolved.vm, "beta");
        assert_eq!(resolved.sock, hosts[1].sock);
        // By id too: `min session attach` and `min net expose` take either.
        assert_eq!(
            resolve_box_host(&vms.global, &api.to_string())
                .await
                .unwrap()
                .vm,
            "beta"
        );

        // And the connection a command acts through lands on that VM: the box
        // is there to be looked up, which it would not be on the other one.
        let mut client = connect_box_host(&vms.global, "api").await.unwrap();
        assert_eq!(resolve_session(&mut client, "api").await.unwrap().id, api);

        let ambiguous = format!(
            "{:#}",
            resolve_box_host(&vms.global, "twin").await.unwrap_err()
        );
        assert!(
            ambiguous.contains("default") && ambiguous.contains("beta"),
            "an ambiguous name must name both VMs: {ambiguous}"
        );
        let missing = format!(
            "{:#}",
            resolve_box_host(&vms.global, "ghost").await.unwrap_err()
        );
        assert!(
            missing.contains("ghost") && missing.contains("beta"),
            "a name no VM holds must say what was asked: {missing}"
        );
    }
}
