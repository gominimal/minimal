use super::*;

// The other command families reach these helpers through `session::`.
pub(crate) use super::box_verbs::{
    advisory_host_reads, control_sock_beside, daemon_host_kind, host_asks_box,
    vm_host_answerer_status_at,
};

/// Every host port the VM's hostname proxy serves on, the preferred first
/// (NET-154), read from the VM host daemon's control socket at `sock_path`
/// beside [`vm_host_answerer_status_at`]'s read and under the same bound.
/// Empty — nothing to add to what the daemon's own listing reports — when
/// there is no socket, the deadline passes, or the daemon predates the read
/// and refuses it: `min ls` then prints the one port it always printed.
pub(crate) async fn vm_host_proxy_ports_at(sock_path: Option<std::path::PathBuf>) -> Vec<u16> {
    use minimal_client::box_registration::{BOX_CONTROL_TIMEOUT, control_request_with_vm_host};
    let Some(sock_path) = sock_path else {
        return Vec::new();
    };
    let read = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        control_request_with_vm_host(&sock_path, minimald_rpc::BoxControlRequest::ProxyPorts),
    )
    .await;
    match read {
        Ok(Ok(minimald_rpc::BoxControlReply::ProxyPorts { proxy_ports })) => proxy_ports,
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    activate_box(global, args, true)
        .await
        .map_err(activate_refusal)
}

/// `min session start [<entry>]`: create a box from a session entry and
/// attach this terminal to it, or print its id and return (BCLI-029).
pub async fn cmd_session_start(
    global: &GlobalArgs,
    args: SessionStartArgs,
) -> Result<(), anyhow::Error> {
    start_entry(global, args.into()).await
}

/// The entry `min session start` starts (BCLI-071): the typed session
/// entry, else the session entry named `default`, else the project's only
/// session entry. The count includes the implicit `default` session entry.
///
/// The lookups of an explicit entry come first, in the order of
/// `pick_session_entry` (`boxes/create.rs`): a typed project entry, then
/// with no entry typed a project session entry named `default`.
///
/// # Errors
///
/// [`SessionEntryUndecided::TypeUnresolved`] when the typed entry's own
/// type is unresolved, or from [`start_candidates`] when the pick depends
/// on the implicit `default` or on the session count: an entry of a project
/// Box Type can be a session. Else a [`StartEntryRefusal`] when no session
/// entry can be picked.
pub(crate) fn pick_session_start_entry(
    entries: &[mfile::entry::BoxEntry],
    typed: Option<&str>,
) -> Result<mfile::entry::BoxEntry, anyhow::Error> {
    if let Some(typed) = typed {
        if let Some(entry) = entries.iter().find(|entry| entry.name == typed) {
            return if is_session_entry(entry) {
                Ok(entry.clone())
            } else if type_unresolved(entry) {
                Err(type_unresolved_refusal(entry).into())
            } else {
                Err(StartEntryRefusal::NotSession {
                    entry: entry.name.clone(),
                    box_type: entry.box_type.clone(),
                }
                .into())
            };
        }
        if typed != mfile::entry::DEFAULT_ENTRY_NAME {
            return Err(StartEntryRefusal::Unknown {
                verb: StartVerb::Session,
                entry: typed.to_string(),
                entries: listed_entries(entries)
                    .into_iter()
                    .filter(is_session_entry)
                    .map(|entry| entry.name)
                    .collect(),
            }
            .into());
        }
    } else if let Some(default) = entries
        .iter()
        .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME && is_session_entry(entry))
    {
        return Ok(default.clone());
    }
    // Only the implicit `default` or the session count is left to decide.
    let candidates = start_candidates(entries)?;
    pick_session_candidate(entries, &candidates, typed).map_err(Into::into)
}

/// The pick of [`pick_session_start_entry`] from the `candidates` that
/// [`start_candidates`] gives for `entries`.
fn pick_session_candidate(
    entries: &[mfile::entry::BoxEntry],
    candidates: &[mfile::entry::BoxEntry],
    typed: Option<&str>,
) -> Result<mfile::entry::BoxEntry, StartEntryRefusal> {
    let sessions: Vec<&mfile::entry::BoxEntry> =
        candidates.iter().filter(|e| is_session_entry(e)).collect();
    let names = || sessions.iter().map(|entry| entry.name.clone()).collect();
    if let Some(typed) = typed {
        return match candidates.iter().find(|entry| entry.name == typed) {
            Some(entry) if is_session_entry(entry) => Ok(entry.clone()),
            Some(entry) => Err(StartEntryRefusal::NotSession {
                entry: entry.name.clone(),
                box_type: entry.box_type.clone(),
            }),
            None => Err(StartEntryRefusal::Unknown {
                verb: StartVerb::Session,
                entry: typed.to_string(),
                entries: names(),
            }),
        };
    }
    if let Some(default) = sessions
        .iter()
        .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME)
    {
        return Ok((*default).clone());
    }
    match sessions.as_slice() {
        [only] => Ok((*only).clone()),
        // No session entry and no implicit `default`: an entry of another
        // type holds the name `default` (BOX-165).
        [] => Err(StartEntryRefusal::DefaultBlocked {
            box_type: entries
                .iter()
                .find(|entry| entry.name == mfile::entry::DEFAULT_ENTRY_NAME)
                .and_then(|entry| entry.box_type.clone()),
        }),
        _ => Err(StartEntryRefusal::Several {
            verb: StartVerb::Session,
            entries: names(),
        }),
    }
}

/// The error `min session activate` ends with (NET-144). When the daemon
/// refused the activation because a declared host port is already in use,
/// the refusal's own text replaces the whole chain: it names the port, its
/// holder and the next step, and the stage and RPC context around it add
/// nothing a person can act on. The activate cleanup has already destroyed
/// the box by then. Any other error passes through as it is.
pub(crate) fn activate_refusal(error: anyhow::Error) -> anyhow::Error {
    let refusal = error
        .chain()
        .find_map(|cause| minimald_rpc::PortInUseRefusal::find_in(&cause.to_string()));
    match refusal {
        Some(refusal) => anyhow::anyhow!("{refusal}"),
        None => error,
    }
}

/// `min session attach [<box>]`: `min box attach` that sees only boxes of
/// type session (BCLI-032). A named box resolves among the session boxes,
/// and with none named the project's session box with a terminal is the
/// one. A stopped or exited box resumes as the attach starts (BCLI-007).
pub async fn cmd_attach(global: &GlobalArgs, args: AttachArgs) -> Result<(), anyhow::Error> {
    cmd_session_attach(global, args.session.as_deref()).await
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
    // gate rides on the lookup's reply — no `GetVersion` ahead of it. The name
    // alone decides where to look (NET-058), as it does for attach: a box on
    // another VM is reached over that VM's socket, with no global flag.
    let example = format!("session exec {} <command>", args.session);
    let (r, sock) = resolve_named_box_version_gated(
        global,
        &mut client,
        sock,
        &args.session,
        "Running in",
        &example,
    )
    .await?;
    tracing::info!(
        session_id = %r.id,
        session_name = ?r.name,
        "found session"
    );

    box_via_ssh(daemon_host_kind(global), &sock, r.id, wire, None, None).await
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
    // live session, which is not something to drive on a skewed pair. The name
    // alone decides where to look (NET-058), as for exec.
    let example = format!("session run {} {}", args.session, args.task);
    let (r, sock) = resolve_named_box_version_gated(
        global,
        &mut client,
        sock,
        &args.session,
        "Running the task in",
        &example,
    )
    .await?;
    tracing::info!(
        session_id = %r.id,
        session_name = ?r.name,
        task = %args.task,
        "found session"
    );

    // The task's `env_vars`, gated against the user policy and resolved
    // against this shell, as `min task run` resolves them (inbox#778). The
    // daemon's environment is not the caller's, so it is never asked.
    let task_env = crate::task::session_run_task_env(
        global,
        r.project_path.as_utf8_path(),
        &args.task,
        |k| std::env::var(k),
    )?;

    task_via_ssh(
        daemon_host_kind(global),
        &sock,
        r.id,
        // No owns-box flag (NET-131): the task runs in a session someone
        // else keeps, so its end stays with whoever holds it.
        minimald_rpc::exec::ExecRequest::TaskRun {
            task: args.task,
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        }
        .encode(),
        &task_env,
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

    let client = connect_daemon(global).await?;

    // The effective reply carries only the rules, but the ingress block is
    // suppressed for host-address sessions (see [`format_policy`]), so the
    // command also resolves the record the policy rides on for its network
    // mode. The name alone decides which VM is asked (NET-058): a box on
    // another VM is read from that VM's daemon, with no global flag.
    let example = format!("session policy {}", args.session);
    let (mut client, record) =
        resolve_box_on_any_vm(global, client, &args.session, &example).await?;
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
            // command actually talks to — `client_host_kind`, the same
            // key `resolve_socket_path` turns on — not on `use_minvmd()`,
            // which is true only under an explicit `--provider
            // local-minvmd`: on macOS that kind is `Minvmd` without the
            // flag, minvmd being the only backend there. The native
            // daemon's own per-daemon switch is a plan the reply does not
            // carry — and it has no host-side gate the set would describe —
            // so that arm passes `None` and the block is left out rather
            // than printed from a plan the session does not attach to.
            let host_kind = daemon_host_kind(global);
            let fabric =
                (host_kind == paths::HostKind::Minvmd).then_some(switch::SwitchSubnet::default());
            // NET-160: the host exposures row turns on the host kind itself,
            // not on `fabric`.
            let native_host = host_kind == paths::HostKind::Minimald;
            let mut out = std::io::stdout();
            format_policy_on_host(
                &mut out,
                &policy,
                record.network,
                host_ip_enforcement,
                &shared_port_collisions,
                fabric,
                native_host,
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
    // The name alone decides which VM destroys the box (NET-058).
    let example = format!("session destroy {box_name}");
    let (mut client, record) = resolve_box_on_any_vm(global, client, box_name, &example).await?;

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
        record.box_id,
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
            if daemon_host_kind(global) != paths::HostKind::Minvmd {
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
    let drain_budget = if daemon_host_kind(global) == paths::HostKind::Minvmd {
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
            if daemon_host_kind(global) == paths::HostKind::Minvmd
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
            // The VM host keeps the box under the name it was registered
            // by until it is told: a `host_ip` box's zone hold (NODATA) and
            // an own-address box's row both move with the name, so the old
            // name answers NXDOMAIN again and the new one is the one the
            // box answers under and the destroy releases (#1116).
            let control_sock =
                vm_host_control_sock(daemon_host_kind(global), global.minimal_dir.as_deref());
            rename_box_with_vm_host(control_sock, &record, &args.new_name).await;
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

// BCLI-030: the type nouns' `list`, `stop` and `rm` are the `min box`
// verbs, filtered to one Box Type. `min session` passes the session type,
// and `min task` the task type.

/// `min session list` and `min task list`: `min box list`, with only the
/// boxes of `box_type`. `verb` is the command as the person typed it, for
/// the log.
pub(crate) async fn cmd_typed_box_list(
    global: &GlobalArgs,
    args: BoxListArgs,
    box_type: &str,
    verb: &'static str,
) -> Result<(), anyhow::Error> {
    let scope = if args.all {
        None
    } else {
        let cwd = crate::attach::cwd_host_path(global)?;
        Some(box_list_scope(cwd.as_ref())?)
    };
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let request = TypedBoxList {
        box_type,
        verb,
        project_root: scope,
        output: args.output,
    };
    typed_box_list_on_hosts(hosts, request, &mut out, &mut err).await
}

/// What one typed listing asks for: the Box Type, the verb for the log,
/// the project (every project when `None`) and the rendering.
pub(crate) struct TypedBoxList<'a> {
    pub(crate) box_type: &'a str,
    pub(crate) verb: &'static str,
    pub(crate) project_root: Option<paths::HostAbsPath>,
    pub(crate) output: Option<BoxListOutputFormat>,
}

/// The typed listing over the local `hosts`: the `min box list` table, or
/// its JSON array, with only the boxes of the requested type. A host that
/// does not answer is named on `err`, and the list goes on without it. The
/// selected host that does not answer ends the command, as it does for
/// `min box list`.
pub(crate) async fn typed_box_list_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    request: TypedBoxList<'_>,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> Result<(), anyhow::Error> {
    let TypedBoxList {
        box_type,
        verb,
        project_root,
        output,
    } = request;
    let mut listed = Vec::new();
    for host in hosts {
        let records = match read_host_boxes(&host).await? {
            Ok(records) => records,
            Err(why) if host.selected => {
                tracing::info!(verb, outcome = "error", host = %host.host, "{why}");
                bail!("{why}");
            }
            Err(why) => {
                tracing::info!(verb, outcome = "host unreachable", host = %host.host, "{why}");
                writeln!(err, "{}", unreachable_host_line(&host.host))?;
                continue;
            }
        };
        listed.extend(
            records
                .into_iter()
                .filter(|entry| entry.box_type.as_deref() == Some(box_type))
                .filter(|entry| {
                    project_root
                        .as_ref()
                        .is_none_or(|root| entry.project_root.as_ref() == Some(root))
                })
                .map(|record| ListedBox {
                    provider: host.provider.to_string(),
                    host: host.host.clone(),
                    record,
                }),
        );
    }
    tracing::info!(verb, outcome = "ok", boxes = listed.len());
    let mut out = out;
    match output {
        Some(BoxListOutputFormat::Json) => render_box_list_json(&mut out, &listed)?,
        None => render_box_list(&mut out, &listed, project_root.is_some())?,
    }
    Ok(())
}

/// Resolves the address `address` over `hosts` among the boxes of
/// `box_type` only, so a type noun never reaches a box of another type.
/// An address that only a box of another type holds is refused as one
/// that no box holds. The verb, the box id and the outcome go to the log.
pub(crate) async fn resolve_box_of_type(
    mut hosts: Vec<crate::cmd::list::LocalHost>,
    address: &str,
    box_type: &str,
    verb: &'static str,
) -> Result<ResolvedBox, anyhow::Error> {
    if let BoxAddress::Qualified { provider, host, .. } = parse_box_address(address) {
        hosts.retain(|h| h.provider == provider && h.host == host);
    }
    let mut listings = Vec::with_capacity(hosts.len());
    for host in hosts {
        let boxes = read_host_boxes(&host).await.inspect_err(|err| {
            tracing::info!(verb, outcome = "error", host = %host.host, "{err:#}");
        })?;
        let boxes = boxes.map(|records| {
            records
                .into_iter()
                .filter(|entry| entry.box_type.as_deref() == Some(box_type))
                .collect()
        });
        listings.push(HostListing { host, boxes });
    }
    match resolve_box_address(address, &listings) {
        Ok(resolved) => {
            tracing::info!(
                verb,
                box_id = %resolved.box_id,
                host = %resolved.host.host,
                outcome = "resolved"
            );
            Ok(resolved)
        }
        Err(refusal) => {
            tracing::info!(verb, address, box_type, outcome = "refused", "{refusal}");
            Err(refusal.into())
        }
    }
}

/// `min session stop` and `min task stop`: `min box stop`, with the box
/// resolved among the boxes of `box_type` only.
pub(crate) async fn cmd_typed_box_stop(
    global: &GlobalArgs,
    args: BoxStopArgs,
    box_type: &str,
    verb: &'static str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    let stopped = typed_box_stop_on_hosts(hosts, &mut out, &args, box_type, verb).await?;
    // As `min box stop` does: the VM host daemon retires the stopped box's
    // `host_ip` egress rules. A stop of one exec leaves the box running.
    if let Some(stopped) = stopped {
        let control_sock = box_host_control_sock(&stopped.host);
        retire_stopped_box_with_vm_host(control_sock, stopped.box_id).await;
    }
    Ok(())
}

/// The typed stop over the local `hosts`. With `--exec`, stops that one
/// command and returns `None`. Else stops the box and returns it.
pub(crate) async fn typed_box_stop_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    out: &mut impl std::io::Write,
    args: &BoxStopArgs,
    box_type: &str,
    verb: &'static str,
) -> Result<Option<ResolvedBox>, anyhow::Error> {
    let target = args.target.as_str();
    let resolved = resolve_box_of_type(hosts, target, box_type, verb).await?;
    let box_id = resolved.box_id;
    let stopped = async {
        match args.exec.as_deref() {
            // The exec stop reads only the host that keeps the box, and
            // takes the box's full id. A full id matches only that box, so
            // a name or id prefix of a box of another type is never read.
            Some(exec) => {
                exec_id_arg(target, exec)?;
                let host = vec![resolved.host.clone()];
                let full_id = box_id.to_string();
                box_stop_exec_on_hosts(host, out, &full_id, exec).await?;
                Ok(None)
            }
            None => {
                let mut client = gated_box_host_client(&resolved.host).await?;
                stop_listed_box(&mut client, out, box_id, target, args.force).await?;
                Ok(Some(resolved))
            }
        }
    }
    .await;
    let outcome = if stopped.is_ok() { "ok" } else { "error" };
    tracing::info!(verb, box_id = %box_id, outcome);
    stopped
}

/// `min session rm` and `min task rm`: `min box rm`, with the box resolved
/// among the boxes of `box_type` only.
pub(crate) async fn cmd_typed_box_rm(
    global: &GlobalArgs,
    args: BoxRmArgs,
    box_type: &str,
    verb: &'static str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let (host, removed) = typed_box_rm_on_hosts(hosts, &args, box_type, verb).await?;
    // The same cleanup as `min box rm`: withdraw the box's row on the VM
    // host daemon, or release the name it held.
    let control_sock = box_host_control_sock(&host);
    let name = removed.name.as_deref();
    let row_id = removed.box_addresses.and(removed.box_id);
    withdraw_box_row(control_sock.clone(), name, removed.box_addresses, row_id).await;
    release_held_box_name(control_sock, removed.id, name, removed.box_addresses).await;
    writeln!(std::io::stdout().lock(), "Removed {}.", args.target)?;
    Ok(())
}

/// The typed removal over the local `hosts`. Returns the host that kept
/// the box and the box it removed. Prints nothing.
pub(crate) async fn typed_box_rm_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    args: &BoxRmArgs,
    box_type: &str,
    verb: &'static str,
) -> Result<(crate::cmd::list::LocalHost, RemovedBox), anyhow::Error> {
    let target = args.target.as_str();
    let ResolvedBox { host, box_id } = resolve_box_of_type(hosts, target, box_type, verb).await?;
    let removed = async {
        let mut client = gated_box_host_client(&host).await?;
        rm_listed_box(&mut client, box_id, target, args.force).await
    }
    .await;
    let outcome = if removed.is_ok() { "ok" } else { "error" };
    tracing::info!(verb, box_id = %box_id, outcome);
    Ok((host, removed?))
}

#[cfg(test)]
mod tests {
    use super::activate_refusal;

    /// NET-144: the daemon's refusal reaches the person as its own text,
    /// with the port and the holder named, whatever context the
    /// activation wrapped around it on the way up.
    #[test]
    fn activate_refusal_names_port_and_holder() {
        for (holder, first_line) in [
            (
                minimald_rpc::PortHolder::Box("web".to_string()),
                "Port 8080 is already in use on this machine by box web.",
            ),
            (
                minimald_rpc::PortHolder::Host,
                "Port 8080 is already in use on this machine by another program on this machine.",
            ),
        ] {
            let refusal = minimald_rpc::PortInUseRefusal {
                port: 8080,
                box_port: 80,
                holder,
            };
            let from_daemon = anyhow::anyhow!("could not finish activating the session: {refusal}")
                .context("Finalize failed");
            let printed = format!("{:#}", activate_refusal(from_daemon));
            assert_eq!(
                printed,
                format!(
                    "{first_line}\nChoose another host port in --ingress (for example \
                     --ingress 8081:80) or in [network] ingress in minimal.toml."
                )
            );
            assert_eq!(
                minimald_rpc::PortInUseRefusal::find_in(&printed),
                Some(refusal),
                "the text reads back as the same refusal"
            );
        }
        let other = activate_refusal(anyhow::anyhow!("something else failed"));
        assert_eq!(
            format!("{other:#}"),
            "something else failed",
            "any other error passes through"
        );
    }
}
