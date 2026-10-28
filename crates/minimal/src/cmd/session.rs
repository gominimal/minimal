use super::*;

// The other command families reach these helpers through `session::`.
pub(crate) use super::box_verbs::{
    advisory_host_reads, control_sock_beside, daemon_provider_kind, host_asks_box,
    vm_host_answerer_status_at,
};

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    activate_box(global, args, true).await
}

/// Attach to an existing session. Both interactive and `--command` paths
/// shell out to `ssh` — the daemon's shell_request handler mints a PTY-backed
/// session shell, and ssh handles termios/PTY management for us.
///
/// When `args.session` is `None`, the session is resolved from the current
/// working directory (or the only existing session), opening an interactive
/// picker when the choice is ambiguous; see [`attach::resolve_for_attach`]
/// and [`resolve_smart_attach`].
///
/// When `args.session` names a box, the name alone decides where to look
/// (NET-058): the selected VM's daemon first — the common case costs nothing
/// beyond the one lookup it always made — and, when that daemon does not know
/// the name, [`attach::resolve_box_vm`] resolves the VM that owns it across
/// every VM's socket, so no global flag is needed to reach a box on another
/// VM.
pub async fn cmd_attach(global: &GlobalArgs, args: AttachArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    // Connects directly rather than through `connect_daemon` (it needs `sock`
    // for the ssh hand-off), so the gate is applied by hand — with no session
    // named, this path creates one, and a skewed activation is #1251 exactly.
    // Both arms below gate on the build the daemon reports on the lookup they
    // were already making, so the gate costs no round trip of its own.
    let (id, name, sock) = match args.session {
        Some(ref s) => {
            let (record, sock) =
                resolve_attach_target_version_gated(global, &mut client, sock, s).await?;
            (record.id, record.name, sock)
        }
        None => match resolve_smart_attach(
            &list_sessions_version_gated(&mut client).await?.sessions,
            global,
        )? {
            SmartAttach::Attach(entry) => (entry.id, entry.name, sock),
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

    let host_asks = host_asks_box(global, name.as_deref());
    box_via_ssh(
        daemon_provider_kind(global),
        &sock,
        id,
        None,
        global.config_dir.as_deref(),
        host_asks.as_deref(),
    )
    .await
}

/// Executes a command in an existing session.
///
/// The session is resolved using the provided predicate, and the connection
/// is provided by shelling out to `ssh`.
pub async fn cmd_exec(global: &GlobalArgs, args: ExecArgs) -> Result<(), anyhow::Error> {
    // Pure client-side validation: refuse an oversized command before
    // autospawning a daemon or looking up the session.
    let wire = minimal_client::attach::checked_remote_command(&args.command)?;
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

    box_via_ssh(daemon_provider_kind(global), &sock, r.id, wire, None, None).await
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

    box_via_ssh(
        daemon_provider_kind(global),
        &sock,
        r.id,
        // No owns-box flag (NET-131): the task runs in a session someone
        // else keeps, so its end stays with whoever holds it.
        Some(
            minimald_rpc::exec::ExecRequest::TaskRun {
                task: args.task,
                owns_box: false,
                args: vec![],
                cwd: String::new(),
            }
            .encode(),
        ),
        None,
        None,
    )
    .await
}

/// Print the effective networking rules for a session.
pub async fn cmd_session_policy(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<(), anyhow::Error> {
    // `-o json` is the machine-readable rendering: one document on stdout,
    // one error object on stderr when the walk fails. A separate walk with
    // typed failures (below) rather than a flag threaded through the text
    // one, because *which* failure it was is part of what a script reads —
    // the text walk answers with a message only — and because the text
    // rendering is not touched at all.
    if args.output == Some(PolicyOutputFormat::Json) {
        return box_policy_as_json(global, &args.session).await;
    }

    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    // The effective reply carries only the rules, but the ingress block is
    // suppressed for host-address sessions (see [`format_policy`]), so the
    // command also resolves the record the policy rides on for its network
    // mode.
    let record = resolve_session(&mut client, &args.session).await?;
    // The follow-up lookups go by the resolved id, so a session named by an
    // id prefix reaches the same session they do.
    let box_id = record.id.to_string();

    // The daemon resolves the effective egress (NET-074/NET-077), because
    // the rollout phase and its opt-out are the daemon's own facts; built
    // here rather than through a `SessionLookup` conversion so the request
    // types stay the rpc crate's, where the wire contract lives.
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(&box_id) {
        SessionLookup::Id(id) => GetEffectiveSessionPolicyRequest::Id(id),
        SessionLookup::Name(n) => GetEffectiveSessionPolicyRequest::Name(n),
    };

    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(lookup)
        .await
        .context("GetEffectiveSessionPolicy RPC failed")?;

    // NET-079's per-box enforcement answers beside the rules, over its own
    // runtime-facts reply — never as a field on the policy, because the
    // policy struct is `deny_unknown_fields`: an older `min` would reject the
    // whole rules reply over a key it has no field for, so the fact rides a
    // separate reply the way live ingress does. A client that cannot get it
    // — an older daemon, a session mid-teardown — renders the rules with no
    // enforcement row, silently: the row is an optional fact beside the
    // declaration, and the same silence is what a session that is not
    // host-address already prints.
    let facts_lookup = match SessionLookup::parse(&box_id) {
        SessionLookup::Id(id) => minimald_rpc::GetSessionRuntimeFactsRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetSessionRuntimeFactsRequest::Name(n),
    };
    let facts = match client
        .oneshot_rpc::<minimald_rpc::GetSessionRuntimeFacts>(facts_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(facts)) => Some(facts),
        Ok(minimald_rpc::Errorable::Err { .. }) | Err(_) => None,
    };
    let host_ip_enforcement = facts.as_ref().and_then(|facts| facts.host_ip_enforcement);
    let shared_port_collisions = facts
        .as_ref()
        .map(|facts| facts.shared_port_collisions.clone())
        .unwrap_or_default();
    // (NET-044) — the rows that make a `min net expose` visible rather than
    // only permitted. Fetched through the text walk's own degrade of the
    // shared fetch: warn on stderr and print no section — the JSON
    // rendering below degrades differently, saying the unknown in the
    // document instead.
    let live = fetch_live_ingress_degrading(&mut client, &box_id).await;

    match resp {
        minimald_rpc::Errorable::Ok(policy) => {
            // The fabric the display builds the baseline set from: the
            // microVM backend's run path builds its registry and the
            // helper's enumeration from the default plan, so that is the
            // plan the display can name for it. Keyed on the backend this
            // command actually talks to — `client_provider_kind`, the same
            // key `resolve_socket_path` turns on — not on `use_minvmd()`,
            // which is true only under an explicit `--provider
            // local-minvmd`: on macOS that kind is `Minvmd` without the
            // flag, minvmd being the only backend there. The native
            // daemon's own per-daemon switch is a plan the reply does not
            // carry — and it has no host-side gate the set would describe —
            // so that arm passes `None` and the block is left out rather
            // than printed from a plan the session does not attach to.
            let fabric = (daemon_provider_kind(global) == paths::ProviderKind::Minvmd)
                .then_some(switch::SwitchSubnet::default());
            let mut out = std::io::stdout();
            format_policy(
                &mut out,
                &policy,
                record.network,
                host_ip_enforcement,
                &shared_port_collisions,
                fabric,
            )?;
            write_live_ingress(&mut out, &live)?;
            if let Some(facts) = &facts {
                write_unaudited_listen_ports(
                    &mut out,
                    &facts.unaudited_listen_ports,
                    facts.audit_log.as_deref(),
                )?;
            }
            out.flush().context("Failed to write policy")?;
            Ok(())
        }
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

    // Same host identity as attach: the alias the daemon keyed its
    // known_hosts entry on, derived from the socket path so the two
    // cannot disagree.
    let host = sock
        .parent()
        .and_then(paths::ssh_host_alias)
        .context("daemon socket path has no provider-dir parent")?;

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
pub async fn cmd_session_hooks(global: &GlobalArgs, args: HooksArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;

    // Resolve first, like every other session command, so a missing session
    // is named in the error; then ask for the hooks of the record that
    // resolved, so both calls target the same session.
    let record = resolve_session(&mut client, &args.session).await?;

    use minimald_rpc::{GetSessionHooks, GetSessionHooksRequest};
    let resp = client
        .oneshot_rpc::<GetSessionHooks>(GetSessionHooksRequest::Id(record.id))
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

/// Destroy (terminate) a session.
pub async fn cmd_destroy(global: &GlobalArgs, args: DestroyArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    if args.all {
        return destroy_all_boxes(global, &mut client, args.force).await;
    }

    let box_name = args
        .session
        .as_deref()
        .context("a session or --all is required")?;
    let record = resolve_session(&mut client, box_name).await?;

    // Under --force the at-risk fetch is skipped outright — the gate is
    // bypassed regardless, so there is nothing to ask the daemon for.
    let at_risk = if args.force {
        AtRiskState::Clean
    } else {
        assess_at_risk(box_delta(&mut client, record.id).await)
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
            let label = record.name.as_deref().unwrap_or(box_name);
            if !confirm(
                &format!("Destroy session {label}? This permanently deletes all in-session files."),
                false,
            )? {
                println!("Aborted.");
                return Ok(());
            }
        }
    }

    destroy_box(
        &mut client,
        global,
        record.id,
        record.name.as_deref(),
        record.box_addresses,
        args.force,
    )
    .await
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
    // so a connect failure is still a real error for a native backend. On a VM
    // backend the connect failing is the wedged-guest symptom itself, so
    // `--force` falls back to stopping the VM from the host rather than leaving
    // the only recovery a hand-killed VMM.
    // Unchecked: stopping a version-skewed daemon is exactly what the version
    // gate tells the operator to do, so this command must never be gated by it.
    let mut client = match connect_daemon_unchecked(global).await {
        Ok(client) => client,
        Err(connect_err) => {
            if daemon_provider_kind(global) != paths::ProviderKind::Minvmd {
                return Err(connect_err);
            }
            // The VM may have gone down between the probe and the connect:
            // that is the goal state, not a wedged guest to stop from the
            // host. Same cheap state-file read as the probe above.
            if !autospawn::is_daemon_running(global.use_minvmd(), global.minimal_dir.as_deref())
                .unwrap_or(true)
            {
                println!("Daemon is not running.");
                return Ok(());
            }
            // The CLI never reached the guest, so `minvmd stop`'s own guest
            // Shutdown is still worth its bounded 5 s connect attempt.
            return if args.force {
                stop_wedged_vm_from_host(global.minimal_dir.clone(), true).await
            } else {
                Err(wedged_vm_unreachable(
                    connect_err,
                    global.minimal_dir.as_deref(),
                ))
            };
        }
    };

    // The guest acknowledges Shutdown only after it has drained every session
    // and quiesced its volume, which is unbounded real work. On a VM backend a
    // failed RPC can end in a host-side kill, so the guest gets the same
    // budget `minvmd stop` gives it before signalling the VMM: a healthy guest
    // still draining past the generic RPC deadline must not be killed sooner
    // than minvmd itself would kill it. A native daemon keeps the generic
    // deadline (a zero extra budget).
    let drain_budget = if daemon_provider_kind(global) == paths::ProviderKind::Minvmd {
        minvmd::cmd::stop::GUEST_SHUTDOWN_TIMEOUT.saturating_sub(client::RPC_TIMEOUT)
    } else {
        std::time::Duration::ZERO
    };
    use minimald_rpc::{Shutdown, ShutdownRequest};
    let resp = client
        .oneshot_rpc_with_hook_budget::<Shutdown>(
            ShutdownRequest { force: args.force },
            drain_budget,
        )
        .await
        .context("Shutdown RPC failed");

    // A wedged guest can fail the Shutdown RPC as surely as the connect, and
    // `stop_outcome` only recovers a failed RPC when the daemon is observably
    // down. On a VM backend with `--force`, a daemon that cannot be confirmed
    // down is stopped from the host instead — the same fallback the connect
    // error takes, reached by the same evidence.
    let resp = match resp {
        Err(rpc_err)
            if daemon_provider_kind(global) == paths::ProviderKind::Minvmd
                && !daemon_confirmed_stopped(global.use_minvmd(), global.minimal_dir.clone())
                    .await =>
        {
            if !args.force {
                return Err(wedged_vm_unreachable(
                    rpc_err,
                    global.minimal_dir.as_deref(),
                ));
            }
            // The guest has just been asked to shut down and was given the
            // full drain budget to acknowledge. Asking again would only add
            // up to two more minutes of waiting before the host-side stop.
            return stop_wedged_vm_from_host(global.minimal_dir.clone(), false).await;
        }
        resp => resp,
    };

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
            // A `host_ip` box holds its name in the zone (NODATA) in place
            // of a row: the hold moves with the name, so the old name no box
            // owns answers NXDOMAIN again and the new one is the one the
            // destroy releases.
            if holds_name(&record) {
                let control_sock = vm_host_control_sock(
                    daemon_provider_kind(global),
                    global.minimal_dir.as_deref(),
                );
                release_held_box_name(
                    control_sock.clone(),
                    record.id,
                    record.name.as_deref(),
                    None,
                )
                .await;
                hold_box_name_with_vm_host(control_sock, &args.new_name, Some(record.id), true)
                    .await;
            }
            println!(
                "Renamed session {} ({}) → {}",
                record.id,
                record.name.as_deref().unwrap_or("-"),
                args.new_name
            );
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("{error}")
        }
    }
}
