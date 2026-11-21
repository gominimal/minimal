use super::*;

// The other command families reach these helpers through `session::`.
pub(crate) use super::box_verbs::{
    advisory_host_reads, control_sock_beside, host_asks_box, vm_host_answerer_status_at,
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

/// The records of `box_type` in `project_root`, every project when `None`.
/// A typed listing shows boxes of its type only, so the build boxes a
/// record carries are left out: `min box list` shows them.
fn typed_records(
    records: Vec<minimald_rpc::BoxListingEntry>,
    box_type: &str,
    project_root: Option<&paths::HostAbsPath>,
) -> Vec<minimald_rpc::BoxListingEntry> {
    records
        .into_iter()
        .filter(|entry| entry.box_type.as_deref() == Some(box_type))
        .filter(|entry| project_root.is_none_or(|root| entry.project_root.as_ref() == Some(root)))
        .map(|mut entry| {
            entry.build_boxes.clear();
            entry
        })
        .collect()
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
            typed_records(records, box_type, project_root.as_ref())
                .into_iter()
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
        None if listed.is_empty() => {
            writeln!(
                out,
                "{}",
                empty_typed_list(box_type, project_root.is_some())
            )?;
        }
        None => render_box_list(&mut out, &listed, project_root.is_some())?,
    }
    Ok(())
}

/// The line a typed listing prints when no box of `box_type` matches: for
/// the current project when `scoped`, else for the local hosts. It names
/// the type, so a project with boxes of another type does not read as
/// empty.
pub(crate) fn empty_typed_list(box_type: &str, scoped: bool) -> String {
    if scoped {
        format!(
            "This project has no {box_type} boxes. \
             Run `min {box_type} list --all` to list the {box_type} boxes of every project."
        )
    } else {
        format!("No {box_type} boxes on this machine.")
    }
}

/// Resolves the address `address` over `hosts` among the boxes of
/// `box_type` only, so a type noun never reaches a box of another type.
/// An address that only a box of another type holds is refused as one
/// that no box holds. A box on a stopped VM is refused with the command
/// that starts the VM, as every `min box` verb refuses it (BCLI-002,
/// NET-058). The verb, the box id and the outcome go to the log.
pub(crate) async fn resolve_box_of_type(
    hosts: Vec<crate::cmd::list::LocalHost>,
    address: &str,
    box_type: &str,
    verb: &'static str,
) -> Result<ResolvedBox, anyhow::Error> {
    resolve_box_over(hosts, address, Some(box_type), verb).await
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
            // The exec stop goes to the box this type resolved, with no
            // second lookup, so a box of another type that holds the same
            // name is never reached. The line names the typed address.
            Some(exec) => {
                box_stop_exec_in_resolved(&resolved, out, target, exec, verb).await?;
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

    /// BOX-210: `min session list` and `min task list` show boxes of their
    /// type only, so a session's running build boxes are not rows there.
    #[test]
    fn a_typed_listing_leaves_out_build_boxes() {
        let entry = |box_type: &str| minimald_rpc::BoxListingEntry {
            build_boxes: vec![minimald_rpc::RunningBuildBox {
                package: "claude-code".to_string(),
                egress: None,
                granted: false,
                no_network: false,
            }],
            box_id: boxes::SessionId::mint(),
            name: None,
            box_type: Some(box_type.to_string()),
            parent: None,
            project_root: None,
            state: "running".to_string(),
            reason: None,
            exit_code: None,
            signal: None,
            pty_enabled: true,
            lifetime: None,
        };
        let typed = super::typed_records(vec![entry("session"), entry("task")], "session", None);
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].box_type.as_deref(), Some("session"));
        assert!(typed[0].build_boxes.is_empty());
    }

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
