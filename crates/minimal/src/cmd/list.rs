use super::*;

/// The default action for a bare `min` (no subcommand).
///
/// In a terminal (stdin and stdout are both TTYs, the same predicate the
/// attach picker uses) it routes into a session: the smart resolution rules
/// of `min session attach` with no argument (cwd match → attach, only
/// session → attach, ambiguity → picker), and when no sessions exist at all
/// it creates one from the current directory and attaches — equivalent to
/// `min session activate --attach .`, except the `minimal.toml` scaffold
/// offer is never made on this path.
///
/// Without a terminal it prints a read-only state report on stderr and exits
/// 0 — see [`cmd_bare_non_tty`]. `min --help` is unaffected: clap handles the
/// flag before dispatch ever reaches here.
pub(crate) async fn cmd_bare(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    if !attach::can_pick_interactively() {
        return cmd_bare_non_tty(global).await;
    }

    ensure_daemon(global)?;
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;
    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    // Connects directly rather than through `connect_daemon` (it needs `sock`
    // for the attach hand-off), so the gate is applied by hand — this path can
    // end in an activation just as `min session activate` does. It rides on the
    // `ListSessions` this path had to send anyway; nothing here spends a round
    // trip on the version alone.
    let listed = list_sessions_version_gated(&mut client).await?;

    match resolve_smart_attach(&listed.sessions, global)? {
        SmartAttach::Attach(entry) => {
            tracing::info!(
                session_id = %entry.id,
                session_name = ?entry.name,
                "found session"
            );
            session_via_ssh(&sock, entry.id, None, global.config_dir.as_deref()).await
        }
        // Two ways to land on create-and-attach: no sessions exist at all
        // (first run), or the ambiguity picker's `+ Create a new session`
        // row was chosen. Both activate for the cwd exactly as
        // `min session activate --attach .` would (default sync, autogen
        // name) — but with the scaffold offer suppressed, unlike the same
        // picker row reached through `min session attach`: the one
        // keystroke into a session must not detour into config authoring.
        SmartAttach::CreateForCwd | SmartAttach::NoSessions => {
            drop(client);
            activate_session(global, bare_activate_args(), false).await
        }
    }
}

/// The `ActivateArgs` a bare `min` activates with when no sessions exist:
/// exactly `min session activate --attach .` — default sync, autogen name,
/// default network — leaving the path to the `-C`/cwd resolution
/// [`cmd_activate`] already performs for a missing path argument.
pub(crate) fn bare_activate_args() -> ActivateArgs {
    ActivateArgs {
        name: None,
        path: None,
        sync: None,
        network: CliNetworkMode::HostNet,
        ingress: Vec::new(),
        allow_subnets: Vec::new(),
        allow_dns_hosts: Vec::new(),
        allow_protocols: Vec::new(),
        deny_subnets: Vec::new(),
        loadout: Vec::new(),
        no_loadouts: false,
        no_hooks: false,
        no_prompt: false,
        attach: true,
    }
}

/// The non-TTY twin of the bare-`min` router: a read-only state report on
/// stderr, then exit 0. Nothing is created and nothing is mutated; stdout
/// stays empty so a pipeline capturing it sees nothing. Listing sessions
/// requires the daemon, so this takes the same client path `min ls` does
/// (which may autospawn) — when that fails, the header plus the error reach
/// stderr and the command exits nonzero, as `min ls` would.
pub(crate) async fn cmd_bare_non_tty(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let cwd = attach::cwd_host_path(global)?;
    let home = std::env::home_dir().and_then(|h| camino::Utf8PathBuf::from_path_buf(h).ok());
    let cwd_display = display_with_home_tilde(cwd.as_utf8_path(), home.as_deref());

    let listed = async {
        ensure_daemon(global)?;
        let mut client = connect_daemon(global).await?;
        use minimald_rpc::ListSessions;
        client
            .oneshot_rpc::<ListSessions>(())
            .await
            .context("ListSessions RPC failed")
    }
    .await;

    match listed {
        Ok(resp) => {
            let has_mfile = project_has_mfile(cwd.as_utf8_path());
            eprint!(
                "{}",
                render_bare_status(&cwd_display, &resp.sessions, &cwd, has_mfile)
            );
            Ok(())
        }
        Err(e) => {
            // The header still identifies what this output is; `main` prints
            // the error itself after the bubble-up.
            eprintln!("{}", bare_status_header(&cwd_display));
            Err(e)
        }
    }
}

/// The first line of the non-TTY state report.
pub(crate) fn bare_status_header(cwd_display: &str) -> String {
    format!("No terminal: not attaching. State for {cwd_display}:")
}

/// Render the bare-`min` non-TTY state report: header, the cwd's session and
/// blueprint state, and the exact next commands. Pure, so the unit tests can
/// assert the lines verbatim.
pub(crate) fn render_bare_status(
    cwd_display: &str,
    entries: &[minimald_rpc::ListSessionsEntry],
    cwd: &paths::HostAbsPath,
    has_mfile: bool,
) -> String {
    let cwd_matches: Vec<&minimald_rpc::ListSessionsEntry> = entries
        .iter()
        .filter(|e| e.project_path.as_ref() == Some(cwd))
        .collect();

    let sessions = if entries.is_empty() {
        "none".to_string()
    } else if cwd_matches.is_empty() {
        format!("0 here ({} elsewhere)", entries.len())
    } else {
        let listed: Vec<String> = cwd_matches
            .iter()
            .take(2)
            .map(|e| format!("({}, {})", entry_handle(e), status_label(e.status)))
            .collect();
        format!("{} {}", cwd_matches.len(), listed.join(", "))
    };

    let blueprint = if has_mfile {
        format!("{} present", mfile::MFILE_NAME)
    } else {
        "none (min init to create one)".to_string()
    };

    let mut out = String::new();
    out.push_str(&bare_status_header(cwd_display));
    out.push('\n');
    out.push_str(&format!("  sessions: {sessions}\n"));
    out.push_str(&format!("  blueprint: {blueprint}\n"));
    out.push_str("Next:\n");
    match cwd_matches.first() {
        Some(e) => {
            out.push_str(&format!(
                "  min session attach --command 'min task run <task>' {}\n",
                entry_handle(e)
            ));
        }
        None => out.push_str("  min session activate --attach .\n"),
    }
    out.push_str("  min ls --json\n");
    out
}

/// A session's typable handle for the state report: its name, or the leading
/// UUID block when unnamed — the same short-id form the attach announcements
/// use.
pub(crate) fn entry_handle(entry: &minimald_rpc::ListSessionsEntry) -> String {
    match &entry.name {
        Some(name) => name.clone(),
        None => {
            let id = entry.id.to_string();
            id.split('-').next().unwrap_or(&id).to_string()
        }
    }
}

/// Warn when the daemon already tracks a session for `target`.
///
/// Activating a path that already has a session mints a second, independent
/// one; bare `min` from that directory is then ambiguous between them. The
/// activation still proceeds — this only surfaces the foot-gun the caller
/// would otherwise hit silently, and points at `attach` as the way to reuse
/// the existing session. Pure, so the message is unit-testable.
pub(crate) fn duplicate_session_warning(
    entries: &[minimald_rpc::ListSessionsEntry],
    target: &paths::HostAbsPath,
) -> Option<String> {
    // When several sessions track the same path, prefer an `Active` one: it is
    // the only status `attach` accepts, so recommending it (rather than the
    // first match, which may be `Pending`/`Materializing`) points the user at a
    // session they can actually reuse. Fall back to the first match when none is
    // active, so the "still being created; wait" guidance still fires.
    let existing = entries
        .iter()
        .filter(|e| e.project_path.as_ref() == Some(target))
        .find(|e| e.status == sessions::SessionStatus::Active)
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.project_path.as_ref() == Some(target))
        })?;
    let handle = entry_handle(existing);
    let lead = format!(
        "warning: a session already exists for this path ({handle}); activating \
         creates a second one, leaving bare `min` here ambiguous between them."
    );
    // Only point at `attach` for a session it will actually accept. Attach
    // refuses anything not yet `Active` (see `sessions::SessionStatus`), so for
    // a `Pending`/`Materializing` duplicate the reuse command would fail
    // immediately — say to wait instead. When we do suggest it, use a key
    // `SessionLookup::parse` can resolve: a name matches by name and the full id
    // parses as a UUID, but the short unnamed handle would parse as a
    // nonexistent name and the attach lookup would miss.
    match existing.status {
        sessions::SessionStatus::Active => {
            let key = existing
                .name
                .clone()
                .unwrap_or_else(|| existing.id.to_string());
            Some(format!(
                "{lead} To reuse it instead: min session attach {key}"
            ))
        }
        _ => Some(format!(
            "{lead} The existing session is still being created; wait for it to \
             become active, then reuse it instead of creating a second."
        )),
    }
}

/// Abbreviate a home-prefixed path to `~`/`~/...` for display; any other
/// path renders absolute, unchanged.
pub(crate) fn display_with_home_tilde(
    path: &camino::Utf8Path,
    home: Option<&camino::Utf8Path>,
) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) if rest.as_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{rest}"),
        None => path.to_string(),
    }
}

/// Open the session manager TUI.
///
/// The TUI probes both provider sockets itself; if neither daemon is
/// running, autospawn the default backend first so the dashboard has
/// something to show (mirroring what the flat subcommands do).
pub async fn cmd_dash(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let dir = global.minimal_dir.as_deref();
    let host_up = autospawn::is_daemon_running(false, dir).unwrap_or(false);
    let vm_up = autospawn::is_daemon_running(true, dir).unwrap_or(false);
    if !host_up && !vm_up {
        ensure_daemon(global)?;
    }
    // Compose the default loadout contribution up front, mirroring
    // cmd_activate: the TUI can't reach this crate's config/loadout
    // plumbing (it sits below), and an empty contribution would silently
    // skip `default_loadouts` and the user policy for sessions created
    // from the dashboard.
    let cfg = config::read_client_config(global)?;
    let user_policy = config::read_user_policy(global)?;
    let compose_options = loadouts::compose_options_from_config(&cfg);
    let active =
        loadouts::resolve_active_loadouts(loadouts::LoadoutSelection::Defaults, &cfg, global)?;
    // `true`: the dashboard has no `--no-hooks`, matching the `hooks_enabled`
    // the TUI sends on `CreateSession`.
    let (contribution, _user_policy) =
        loadouts::compose_user_contribution(active, user_policy, compose_options, true)?;
    minimal_tui::run(minimal_tui::DashOptions {
        minimal_dir: global.minimal_dir.clone(),
        config_dir: global.config_dir.clone(),
        contribution,
    })
    .await
}

/// List sessions via the `ListSessions` RPC.
pub async fn cmd_ls(global: &GlobalArgs, args: LsArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::ListSessions;
    let mut resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;

    // The daemon cannot probe git (on macOS it runs in the minvmd guest),
    // so fill each session's git context host-side before formatting.
    minimal_client::fill_git_info(&mut resp.sessions).await;

    // On stderr, and outside `format_ls`: every output mode should carry a
    // fault this severe — `--raw` most of all, since a script parsing bare ids
    // is exactly what will go on using hostnames that no longer resolve — and
    // stdout stays clean for the parser either way.
    warn_if_hostname_routing_down(resp.hostname_routing_unavailable.as_deref(), "min ls");
    warn_if_mtls_proxy_down(resp.mtls_proxy_unavailable.as_deref());
    format_ls(&mut std::io::stdout(), &args, &resp)?;
    Ok(())
}

/// The warning `min ls` and `min session activate` print when the daemon
/// reports hostname routing down: the daemon's reason and remedy for the
/// failed bind or publish, plus what recovery looks like from here — the
/// daemon retries with backoff and clears the warning on its own once the
/// listener recovers (NET-020, NET-022). `command` names the command the
/// warning rides on: re-running it shows the warning while the listener is
/// still down and nothing once it has recovered, so the recovery sentence
/// tells the user to re-run the command they are already in, not some other
/// one. Pure, so tests can assert the wording without capturing stderr.
#[must_use]
pub fn hostname_routing_warning(reason: &str, command: &str) -> String {
    format!(
        "warning: session hostnames will not route: {reason}. The daemon retries \
         with backoff and clears this warning on its own once the listener \
         recovers; run `{command}` again to check."
    )
}

/// Tells the user that `<name>.local.min.internal` will not resolve, and why,
/// and what clears it.
///
/// The daemon keeps serving without its host-side proxy, so nothing else the
/// user sees is different: sessions activate, exec works, the list prints. The
/// only other trace is a `warn!` in the daemon log, which is not where someone
/// watching curl fail is looking (gominimal/inbox#560). The daemon's report
/// carries the reason and the remedy for the cause (a held port, a failed
/// publish); the recovery is the daemon's job now — it retries with backoff
/// and the warning goes away by itself, so the remedy says to check again
/// rather than to restart anything. `command` names the command this runs
/// from, so the recovery sentence fits it — `min ls` on the list, `min
/// session activate` at activation.
pub(crate) fn warn_if_hostname_routing_down(reason: Option<&str>, command: &str) {
    if let Some(reason) = reason {
        eprintln!("{}", hostname_routing_warning(reason, command));
    }
}

/// Tells the user the mTLS reverse proxy is not serving, and why.
///
/// Kept separate from [`warn_if_hostname_routing_down`] so the two faults read
/// as what they are: hostnames failing to resolve and TLS termination being
/// absent are different problems with different fixes.
pub(crate) fn warn_if_mtls_proxy_down(reason: Option<&str>) {
    if let Some(reason) = reason {
        eprintln!("warning: the mTLS reverse proxy is not serving: {reason}");
    }
}

/// Format the session list for the given output mode. Split from
/// [`cmd_ls`] so integration tests can capture output into a buffer
/// instead of stdout.
pub fn format_ls(
    out: &mut impl std::io::Write,
    args: &LsArgs,
    resp: &minimald_rpc::ListSessionsResponse,
) -> Result<(), anyhow::Error> {
    if args.json {
        let json = serde_json_lenient::to_string_pretty(resp)
            .context("Failed to serialize session list")?;
        writeln!(out, "{json}")?;
        return Ok(());
    }

    if !args.raw
        && let Some(pool) = &resp.resource_pool
    {
        let session_count = resp.sessions.len();
        let core_label = if pool.cpu_cores == 1 { "core" } else { "cores" };
        let session_label = if session_count == 1 {
            "session"
        } else {
            "sessions"
        };
        writeln!(
            out,
            "RESOURCE POOL:  {} CPU {} · {} memory · shared by {} {}",
            pool.cpu_cores,
            core_label,
            format_memory(pool.memory_bytes),
            session_count,
            session_label,
        )?;
        writeln!(out)?;
    }

    if resp.sessions.is_empty() {
        if !args.raw {
            writeln!(out, "No active sessions.")?;
        }
        return Ok(());
    }

    if args.raw {
        for entry in &resp.sessions {
            writeln!(out, "{}", entry.id)?;
        }
        return Ok(());
    }

    // Format as a table. The columns mirror the fields `--json` exposes so
    // the two surfaces present the same session attributes.
    writeln!(
        out,
        "{:<36}  {:<20}  {:<13}  {:<20}  {:<19}  PROJECT PATH",
        "SESSION ID", "NAME", "STATUS", "TITLE", "LAST ACTIVITY"
    )?;
    writeln!(
        out,
        "{:-<36}  {:-<20}  {:-<13}  {:-<20}  {:-<19}  {:-<24}",
        "", "", "", "", "", ""
    )?;

    for entry in &resp.sessions {
        let id = entry.id.to_string();
        let name = entry.name.as_deref().unwrap_or("-");
        let status = status_label(entry.status);
        let project_path = entry
            .project_path
            .as_ref()
            .map(paths::HostAbsPath::to_string)
            .unwrap_or_else(|| "-".to_string());
        let (title, last_activity) = match &entry.attrs {
            Some(attrs) => {
                let title = attrs
                    .title
                    .as_ref()
                    .map(|t| t.value.as_str())
                    .unwrap_or("-");
                let last = attrs
                    .last_stdout
                    .or(attrs.last_stdin)
                    .map(|dt| {
                        let local = dt.with_timezone(&chrono::Local);
                        local.format("%Y-%m-%d %H:%M:%S").to_string()
                    })
                    .unwrap_or_else(|| "-".to_string());
                (title, last)
            }
            None => ("-", "-".to_string()),
        };
        writeln!(
            out,
            "{id:<36}  {name:<20}  {status:<13}  {title:<20}  {last_activity:<19}  {project_path}"
        )?;
    }

    Ok(())
}

/// Human-readable lifecycle status for the `ls` table, using the same
/// snake_case tokens the `--json` surface emits so the two agree.
pub(crate) fn status_label(status: sessions::SessionStatus) -> &'static str {
    match status {
        sessions::SessionStatus::Pending => "pending",
        sessions::SessionStatus::Materializing => "materializing",
        sessions::SessionStatus::Active => "active",
    }
}

pub(crate) fn format_memory(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        let gib = bytes as f64 / GIB as f64;
        if bytes.is_multiple_of(GIB) {
            format!("{gib:.0} GiB")
        } else {
            format!("{gib:.1} GiB")
        }
    } else {
        format!("{} MiB", bytes / MIB)
    }
}
