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

/// One VM's `ListSessions` reply with the VM it came from: the pairing
/// [`ls_listings`] produces and [`format_ls_across_vms`] renders. The
/// attribution is the client's — a daemon knows only its own boxes, so the
/// wire reply carries no VM of its own.
pub struct VmListing {
    /// The VM the reply came from, as `--vm` accepts it.
    pub vm: String,
    /// That VM's daemon reply.
    pub resp: minimald_rpc::ListSessionsResponse,
    /// That VM's VM-host control socket, beside the ssh socket the listing
    /// reached it on (NET-138): the socket `cmd_ls` reads this VM's own
    /// zone-answerer state from. `None` on the native backend, which hosts
    /// no VM host daemon — nothing to read, so nothing is read.
    pub control_sock: Option<std::path::PathBuf>,
}

/// List sessions across every VM the CLI can see (NET-057): each running VM
/// contributes its own boxes, and the listing carries the VM per box.
///
/// [`minimal_client::enumerate_vm_sockets`] is the set: the default VM plus
/// every named one. An explicit `--vm` narrows the listing to that VM alone —
/// the operator named where to look. A VM that is not running hosts no boxes,
/// so it contributes nothing and no word is spent on it; a VM that answers
/// badly is skipped with a warning, unless it is the VM this process selected
/// — that one was just ensured, so a failure there is the failure to report
/// (and a skewed one is refused there, as `min ls` always has). Nothing
/// enumerable — the native backend, which hosts no VMs — falls back to the
/// selected provider's daemon, exactly the listing `min ls` has always
/// printed.
pub(crate) async fn ls_listings(global: &GlobalArgs) -> Result<Vec<VmListing>, anyhow::Error> {
    let mut vms = client::enumerate_vm_sockets(global.minimal_dir.as_deref(), global.use_minvmd())?;
    if let Some(pinned) = global.vm.as_deref() {
        vms.retain(|vm| vm.vm == pinned);
    }
    let selected = client::vm_name();
    let mut listings = Vec::new();
    for vm in vms {
        // The selected VM gets the gate `min ls` has always applied
        // (`connect_daemon`'s); the others are listable ungated, for the same
        // reason the dashboard lists them ungated — a listing is read-only,
        // and a skewed VM is precisely one whose boxes an operator still
        // needs to see.
        let gate = vm.vm == selected;
        // A VM that is not running hosts no boxes: an absent socket is "no
        // boxes here", not a fault. The selected VM is exempt even so — it is
        // up ([`ensure_daemon`] saw to it), but on the VM backend its bridge
        // UDS can appear a beat after the `vm-up` line, which is exactly the
        // race [`Client::connect`]'s retry window absorbs, so it is connected
        // through rather than skipped. Skipping it would silently drop the
        // operator's own boxes from the listing and print another VM's as the
        // whole picture.
        if !vm.sock.exists() && !gate {
            continue;
        }
        // The control socket this VM's own answerer state is read from
        // (NET-138), beside the ssh socket this listing reached it on — the
        // same dir the registration and the withdrawal find it in.
        let control_sock = crate::cmd::session::control_sock_beside(&vm.sock);
        if gate {
            listings.push(VmListing {
                vm: vm.vm,
                resp: list_selected_vm(&vm.sock).await?,
                control_sock,
            });
        } else {
            match list_other_vm(&vm.sock).await {
                Ok(Some(resp)) => listings.push(VmListing {
                    vm: vm.vm,
                    resp,
                    control_sock,
                }),
                Ok(None) => {}
                Err(e) => eprintln!("warning: skipping VM {}: {e:#}", vm.vm),
            }
        }
    }
    if listings.is_empty() {
        let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
            .context("Failed to resolve daemon socket path")?;
        listings.push(VmListing {
            vm: selected.to_string(),
            resp: list_selected_vm(&sock).await?,
            // The native backend reaches here with no VM host daemon to
            // read a state from; a VM backend falls back to the selected
            // VM's own dir, where its control socket sits.
            control_sock: fallback_control_sock(global, &sock),
        });
    }
    Ok(listings)
}

/// The VM-host control socket the fallback listing pairs with its one entry
/// (NET-138), keyed on the backend the daemon connection resolves through —
/// the same rule [`hostname_proxy_start_vm`] states — and never on
/// [`GlobalArgs::use_minvmd`]: the flag is how Linux asks for the VM host,
/// while macOS reaches it with no flag at all, so a gate keyed on the flag
/// would find no control socket for exactly the host whose every invocation
/// is VM-backed, and the one entry `min ls` falls back to there would carry
/// no answerer state to read. `sock` is the daemon socket the listing
/// already resolved; the control socket sits beside it, in the same provider
/// dir.
#[must_use]
pub fn fallback_control_sock(
    global: &GlobalArgs,
    sock: &std::path::Path,
) -> Option<std::path::PathBuf> {
    (super::session::daemon_provider_kind(global) == paths::ProviderKind::Minvmd)
        .then(|| super::session::control_sock_beside(sock))
        .flatten()
}

/// The selected daemon's `ListSessions` reply, from its socket, gated as `min
/// ls` has always been: connect with [`Client::connect`]'s retry window — the
/// VM is this process's own, and that window is what absorbs its bridge UDS
/// appearing late — then assert the daemon's build, then ask.
async fn list_selected_vm(
    sock: &std::path::Path,
) -> Result<minimald_rpc::ListSessionsResponse, anyhow::Error> {
    let mut client = client::Client::connect(sock)
        .await
        .with_context(|| format!("Failed to connect to the daemon at {}", sock.display()))?;
    client::ensure_version_match(&mut client).await?;
    let mut resp = list_sessions_from(&mut client).await?;
    minimal_client::fill_git_info(&mut resp.sessions).await;
    Ok(resp)
}

/// One unselected VM's `ListSessions` reply, or `None` when that VM is not
/// running.
///
/// This VM is nobody's selection, so it gets no retry window and no full-dead
/// line stack: a stopped VM leaves its `ssh.sock` on disk, and a listing
/// spanning every VM on the host cannot spend [`Client::connect`]'s ~2 s
/// retry plus the handshake and RPC deadlines on each one it passes. One
/// probe attempt ([`Client::probe`]), and the RPC that follows it, both under
/// the short [`client::PROBE_TIMEOUT`] leash — a wedged VM holds the listing
/// for 4 s, not ~72 s. "Not running" — the stale socket of a VM that is down,
/// or a path that vanished since the caller looked — is the answer, not a
/// fault: `Ok(None)`, no warning. [`fill_git_info`] stays outside the leash:
/// it walks git on the host, one repo probe per box, and a VM with many boxes
/// has nothing to do with the daemon's reachability.
async fn list_other_vm(
    sock: &std::path::Path,
) -> Result<Option<minimald_rpc::ListSessionsResponse>, anyhow::Error> {
    #[expect(
        clippy::map_err_ignore,
        reason = "the elapsed marker carries nothing the message lacks"
    )]
    let reply = tokio::time::timeout(client::PROBE_TIMEOUT, async {
        let mut client = match client::Client::probe(sock).await {
            Ok(client) => client,
            Err(client::ProbeRefusal::NotRunning) => return Ok(None),
            Err(client::ProbeRefusal::Unreachable(e)) => {
                return Err(e.context(format!(
                    "Failed to connect to the daemon at {}",
                    sock.display()
                )));
            }
        };
        let resp = list_sessions_from(&mut client)
            .await
            .context("ListSessions RPC failed")?;
        Ok(Some(resp))
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "daemon at {} did not answer within {:?}",
            sock.display(),
            client::PROBE_TIMEOUT
        )
    })??;
    let Some(mut resp) = reply else {
        return Ok(None);
    };
    minimal_client::fill_git_info(&mut resp.sessions).await;
    Ok(Some(resp))
}

/// The `ListSessions` RPC itself, shared by the selected and the probed
/// callers. The daemon cannot probe git (on macOS it runs in the minvmd
/// guest), so the caller fills each session's git context host-side.
async fn list_sessions_from(
    client: &mut client::Client,
) -> Result<minimald_rpc::ListSessionsResponse, anyhow::Error> {
    use minimald_rpc::ListSessions;
    client.oneshot_rpc::<ListSessions>(()).await
}

/// List sessions via the `ListSessions` RPC.
pub async fn cmd_ls(global: &GlobalArgs, args: LsArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let listings = ls_listings(global).await?;

    // On stderr, and outside the formatters: every output mode should carry a
    // fault this severe — `--raw` most of all, since a script parsing bare ids
    // is exactly what will go on using hostnames that no longer resolve — and
    // stdout stays clean for the parser either way. With more than one VM
    // listed the fault is per daemon, so each warning names the VM it is on;
    // one listing keeps the single-VM wording every consumer of `min ls` has
    // always read.
    for listing in &listings {
        if let Some(reason) = listing.resp.hostname_routing_unavailable.as_deref() {
            if listings.len() == 1 {
                warn_if_hostname_routing_down(Some(reason), "min ls");
            } else {
                eprintln!(
                    "VM {}: {}",
                    listing.vm,
                    hostname_routing_warning(reason, "min ls")
                );
            }
        }
    }

    // NET-018's verdict — which surface a box name resolves through on
    // this host — from the one function both verbs share (`resolver`), one
    // verdict per VM. The verdict is the VM's, not the host's alone: each
    // VM's daemon publishes its answerer on a host port of its own
    // (NET-059), and the host's resolver hook routes the zone to one
    // answerer, so the VM it routes to answers natively while a sibling
    // VM's names answer through its proxy. The three facts each verdict
    // reads are this host's resolver hook (with the stub-bypass blocker
    // that says whether host lookups consult what the hook configures),
    // that VM's answerer-bound report, and the reserved range on this
    // host's own loopback; native DNS is live only when all three hold.
    // Nothing prints when a VM's daemon reports its answerer not bound —
    // the port lines below already tell that story. The detection runs
    // only in the modes that can print the verdict: `--json` and `--raw`
    // are machine-readable-only and never carry the line, so they pay no
    // resolver read. The answerer is bound on every current daemon, so
    // every human-mode list does read the host — the line is this verb's
    // status, so it stays where the user looks for it — but at the list's
    // own deadline, not the session start's: the read runs under the same
    // one-second deadline this list's own host-side subprocess probes
    // carry (the git probes above), paid once for every VM's verdict
    // together, so a wedged systemd-resolved costs `min ls` that one
    // second — never the ten its queries could add, and never one per
    // VM — and the verdict a slow read loses is the proxy's, the arm
    // that cannot strand the user (NET-019 keeps the proxy serving). The
    // daemon's own view of this host's resolver is not a thing that
    // exists, so the host's half is the host's to read.
    // NET-138: on a VM-backed host the answerer whose surface this is is
    // the VM host daemon's — every VM's in-VM daemon starts none, so each
    // reply reports no answerer and the facts come from the host. Each
    // listed VM's status is read over its own minvmd control socket, beside
    // the ssh socket the listing reached it on, never through the in-VM
    // daemon (a guest relaying a host fact is forgeable from inside the
    // escape boundary), and the liveness proof is this CLI's own A query at
    // the port that read named. The status decides that VM's own verdict
    // and its own `ZONE ANSWERER` row — a VM whose minvmd holds the port
    // is named there, and a sibling registered with another daemon says
    // who holds it, so no row speaks with another VM's state. Read in the
    // modes that can print them, like the detection below it: `--json` and
    // `--raw` are machine-readable-only and pay no host read, socket or
    // query either one.
    let vm_answerers: Vec<Option<minimald_rpc::ZoneAnswererStatus>> = if args.json || args.raw {
        Vec::new()
    } else {
        let mut read = Vec::with_capacity(listings.len());
        for listing in &listings {
            read.push(
                crate::cmd::session::vm_host_answerer_status_at(listing.control_sock.clone()).await,
            );
        }
        read
    };
    let mut surfaces = if args.json || args.raw {
        Vec::new()
    } else {
        crate::resolver::live_name_surfaces(
            listings
                .iter()
                .map(|listing| (listing.resp.zone_answerer_port, listing.resp.answerer_bound)),
        )
        .await
    };
    // One verdict per VM from that VM's own status, over the verdict its
    // daemon's report would have decided: the read that cannot be made —
    // no control socket, the deadline, a daemon that predates the verb —
    // keeps the silence a daemon-report verdict is, for that VM alone.
    for (index, status) in vm_answerers.iter().enumerate() {
        if let Some(status) = status
            && let Some(slot) = surfaces.get_mut(index)
        {
            *slot = crate::resolver::vm_host_name_surface(*status).await;
        }
    }
    format_ls_across_vms(
        &mut std::io::stdout(),
        &args,
        &listings,
        &surfaces,
        &vm_answerers,
    )?;
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

/// The session-start twin of `min ls`'s routing line (NET-026 on the activate
/// surface): one line telling the operator the port this daemon's
/// `<name>.min.internal` names route through — the address a PAC file or an
/// `HTTP(S)_PROXY` export has to point at, which is not a constant on a host
/// where a port was taken.
///
/// That is the case the line exists for: a VM whose proposed host port the
/// host already held walks to a host port of its own (NET-059) — a boot with
/// no handed port, since a handed one is pinned and keeps proposing the port
/// it was given — and a native daemon whose default is busy asks the OS for a
/// free one (NET-025). Either way the port the recipes assume is not the one
/// in use, so a walked port must never be a log line alone: the daemon
/// reports the port it is *reachable* on, and the session that just started
/// prints it here beside the routing line `min ls` prints for the same VM.
///
/// `vm` is the VM the line names: the selected one on the VM backend, where
/// each VM publishes its own proxy on the host and the name is which port is
/// whose on a two-VM host. `None` on the native backend, which hosts no VMs,
/// so the line reads exactly as `min ls`'s single-daemon routing line does.
#[must_use]
pub fn hostname_proxy_start_line(vm: Option<&str>, port: u16) -> String {
    match vm {
        Some(vm) => format!(
            "HOSTNAME PROXY:  VM {vm} listening on 127.0.0.1:{port} · \
             <name>.min.internal routes through it"
        ),
        None => format!(
            "HOSTNAME PROXY:  listening on 127.0.0.1:{port} · \
             <name>.min.internal routes through it"
        ),
    }
}

/// The VM a session-start routing line names: the selected VM on the VM
/// backend, where the session that just started landed on one VM of several
/// and its proxy port is that VM's, and nothing on the native backend, whose
/// one daemon hosts no VMs to name.
///
/// Keyed on the provider kind the daemon connection resolves through — the
/// same rule [`super::session::daemon_provider_kind`] states — and never on
/// `use_minvmd()`: the flag is how Linux asks for the VM host, while macOS
/// reaches it with no flag at all, and a start line that keyed on the flag
/// would name no VM for exactly the host whose every invocation is
/// VM-backed.
#[must_use]
pub fn hostname_proxy_start_vm(global: &GlobalArgs) -> Option<&'static str> {
    hostname_proxy_vm(super::session::daemon_provider_kind(global))
}

/// [`hostname_proxy_start_vm`]'s gate as a fact about the backend kind, so
/// the tests can drive the macOS combination the flag cannot express:
/// `Minvmd` with no provider flag at all.
#[must_use]
pub fn hostname_proxy_vm(kind: paths::ProviderKind) -> Option<&'static str> {
    (kind == paths::ProviderKind::Minvmd).then(client::vm_name)
}

/// Format the session list for the given output mode. Split from
/// [`cmd_ls`] so integration tests can capture output into a buffer
/// instead of stdout.
///
/// `surface` is NET-018's verdict — which surface a box name resolves
/// through on this host, as [`cmd_ls`] computed it from the one function
/// both verbs share — printed on the `NAME SURFACE` line when the daemon's
/// answerer is bound at all.
///
/// `vm_answerer` is the machine's zone-answerer state on a VM-backed host
/// (NET-138), as [`cmd_ls`] read it from the VM host daemon's control
/// socket: when the daemon behind this list reports no answerer of its own
/// — a VM-backed host's daemon starts none — the `ZONE ANSWERER` line
/// prints from it instead, saying the zone is answered by the VM host
/// daemon and naming the holder. `None`, the native shape, prints the
/// daemon's own line exactly as before.
pub fn format_ls(
    out: &mut impl std::io::Write,
    args: &LsArgs,
    resp: &minimald_rpc::ListSessionsResponse,
    surface: Option<crate::resolver::LiveSurface>,
    vm_answerer: Option<minimald_rpc::ZoneAnswererStatus>,
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

    // NET-026: say where this daemon's names route from — the TCP proxy an
    // `HTTP(S)_PROXY` export points at, and beside it the UDP answerer the
    // host's resolver would be pointed at for the same zone. Both ports
    // travel on the reply because a daemon that auto-selected is on
    // OS-chosen ones, and the addresses are what the exports need —
    // especially on a machine running two daemons. Absent while the daemon
    // is still bringing a listener up, or from a daemon too old to carry the
    // field: nothing to print for it then. `--raw` and `--json` stay
    // machine-readable-only, so a port line never lands in a pipeline.
    if !args.raw {
        if let Some(port) = resp.hostname_proxy_port {
            writeln!(
                out,
                "HOSTNAME PROXY:  listening on 127.0.0.1:{port} · <name>.min.internal routes through it"
            )?;
        }
        // The VM host daemon's line is computed once here, because the
        // blank line below rides on what printed, not on what was read:
        // the pre-acquisition state prints no line and forces no blank one.
        let vm_answerer_line = vm_answerer.and_then(crate::resolver::vm_host_answerer_line);
        if let Some(answerer) = resp.zone_answerer_port {
            writeln!(
                out,
                "ZONE ANSWERER:   listening on 127.0.0.1:{answerer} (UDP) · point the host's resolver at it for *.min.internal"
            )?;
        } else if let Some(line) = &vm_answerer_line {
            writeln!(out, "ZONE ANSWERER:   {line}")?;
        }
        // NET-018: say which of the two surfaces is live — the one verdict
        // both verbs share ([`resolver::live_name_surfaces`]). `None` — the
        // daemon's answerer not bound — prints nothing: the two port lines
        // above already tell that story, and the advisory the activation
        // path prints (NET-122) says how to get from one surface to the
        // other. `--raw` and `--json` stay machine-readable-only, as for
        // the ports.
        if let Some(surface) = surface {
            writeln!(
                out,
                "NAME SURFACE:    {}",
                crate::resolver::name_surface_line(surface, resp.hostname_proxy_port)
            )?;
        }
        if resp.hostname_proxy_port.is_some()
            || resp.zone_answerer_port.is_some()
            || vm_answerer_line.is_some()
        {
            writeln!(out)?;
        }
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
        let [id, name, status, title, last_activity, project_path] = session_cells(entry);
        writeln!(
            out,
            "{id:<36}  {name:<20}  {status:<13}  {title:<20}  {last_activity:<19}  {project_path}"
        )?;
    }

    Ok(())
}

/// The cells of one session row — id, name, status, title, last activity,
/// project path — shared by the single-VM table ([`format_ls`]) and the
/// multi-VM one ([`format_ls_across_vms`]), so the two surfaces present the
/// same session attributes.
fn session_cells(entry: &minimald_rpc::ListSessionsEntry) -> [String; 6] {
    let id = entry.id.to_string();
    let name = entry.name.as_deref().unwrap_or("-").to_string();
    let status = status_label(entry.status).to_string();
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
                .unwrap_or("-")
                .to_string();
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
        None => ("-".to_string(), "-".to_string()),
    };
    [id, name, status, title, last_activity, project_path]
}

/// The width of the VM column in the multi-VM table: enough for the default
/// VM's name plus a space, so the common host reads evenly.
const VM_COLUMN_WIDTH: usize = 8;

/// Format the listing across every VM [`ls_listings`] gathered (NET-057).
///
/// One VM listed is [`format_ls`] verbatim — the output every consumer of
/// `min ls` has always read, `--json` included, with NET-018's name-surface
/// verdict on the line `format_ls` prints when that VM's daemon reports its
/// answerer bound (`surfaces` carries one verdict per listing, as
/// [`cmd_ls`] computed them). More than one adds the VM per box: a VM
/// column in the table, the VM inside each `--json` session entry, and
/// each VM's routing facts (NET-026's discovery lines) prefixed with the
/// VM they belong to, because on a two-VM host each VM's proxy publishes
/// on a host port of its own (NET-059) — NET-018's verdict included, per
/// VM: the host's resolver hook routes the zone to one VM's answerer, so
/// each VM's line says which of the two surfaces its own names answer
/// through.
///
/// `vm_answerers` is one zone-answerer state (NET-138) per listing, as
/// [`cmd_ls`] read each listed VM's own from that VM's control socket: that
/// VM's `ZONE ANSWERER` line prints from it when the VM's own daemon reports
/// no answerer, as [`format_ls`] does for a single VM. A shorter slice than
/// the listings — a machine mode reads nothing, and a caller that computed
/// nothing — leaves the VMs it does not cover with no line.
pub fn format_ls_across_vms(
    out: &mut impl std::io::Write,
    args: &LsArgs,
    listings: &[VmListing],
    surfaces: &[Option<crate::resolver::LiveSurface>],
    vm_answerers: &[Option<minimald_rpc::ZoneAnswererStatus>],
) -> Result<(), anyhow::Error> {
    // The verdict of the listing at `index`, `None` when the caller passed
    // none for it — a machine mode never prints the line, and a direct
    // caller may have computed nothing.
    let surface_at = |index: usize| surfaces.get(index).copied().flatten();
    // The host answerer's state for the listing at `index`, `None` when no
    // read was made for that VM — a machine mode reads nothing, and a
    // socket or daemon that did not answer keeps the same silence.
    let answerer_at = |index: usize| vm_answerers.get(index).copied().flatten();
    if let [only] = listings {
        return format_ls(out, args, &only.resp, surface_at(0), answerer_at(0));
    }
    if listings.is_empty() {
        // `cmd_ls` always lists the selected VM, so this is only reachable
        // from a direct caller; render it as the empty listing it is.
        return format_ls(
            out,
            args,
            &minimald_rpc::ListSessionsResponse {
                resource_pool: None,
                sessions: Vec::new(),
                daemon_version: None,
                hostname_routing_unavailable: None,
                hostname_proxy_port: None,
                zone_answerer_port: None,
                answerer_bound: false,
            },
            None,
            None,
        );
    }

    if args.json {
        // One object, not one per VM: the top-level shape `min ls --json` has
        // always printed, so a consumer parsing `.sessions` keeps working on a
        // multi-VM host — it finds every VM's boxes in that one array, each
        // entry carrying the VM it lives on (the attribution NET-057 adds to
        // the table, on the surface a pipeline reads). The facts the
        // single-VM object carries per daemon — resource pool, the routing
        // ports, the build — cannot sit at the top level once there are
        // several, so each VM keeps its own object under `vms`, named by
        // `"vm"` the same way.
        let mut sessions = Vec::new();
        let mut vms = Vec::new();
        for listing in listings {
            let reply = serde_json_lenient::to_value(&listing.resp)
                .context("Failed to serialize session list")?;
            let mut object = match reply {
                serde_json_lenient::Value::Object(map) => map,
                other => anyhow::bail!("session list did not serialize to an object: {other}"),
            };
            let vm = serde_json_lenient::Value::String(listing.vm.clone());
            // The sessions move into the one array with the VM inside each;
            // the rest of the reply stays as that VM's own object.
            let vm_sessions = object
                .remove("sessions")
                .unwrap_or(serde_json_lenient::Value::Array(Vec::new()));
            if let serde_json_lenient::Value::Array(entries) = vm_sessions {
                for mut entry in entries {
                    if let serde_json_lenient::Value::Object(map) = &mut entry {
                        map.insert("vm".to_string(), vm.clone());
                    }
                    sessions.push(entry);
                }
            }
            object.insert("vm".to_string(), vm);
            vms.push(serde_json_lenient::Value::Object(object));
        }
        let json = serde_json_lenient::json!({
            "sessions": sessions,
            "vms": vms,
        });
        let json = serde_json_lenient::to_string_pretty(&json)
            .context("Failed to serialize session list")?;
        writeln!(out, "{json}")?;
        return Ok(());
    }

    if !args.raw {
        // Each VM's own facts, one line each, named by the VM they belong
        // to — the same words the single-VM listing prints for them.
        let mut facts = 0;
        for (index, listing) in listings.iter().enumerate() {
            if let Some(pool) = &listing.resp.resource_pool {
                let session_count = listing.resp.sessions.len();
                let core_label = if pool.cpu_cores == 1 { "core" } else { "cores" };
                let session_label = if session_count == 1 {
                    "session"
                } else {
                    "sessions"
                };
                writeln!(
                    out,
                    "RESOURCE POOL:  {vm:<width$} {cores} CPU {core_label} · {memory} · shared by {count} {session_label}",
                    vm = listing.vm,
                    width = VM_COLUMN_WIDTH,
                    cores = pool.cpu_cores,
                    memory = format_memory(pool.memory_bytes),
                    count = session_count,
                )?;
                facts += 1;
            }
            if let Some(port) = listing.resp.hostname_proxy_port {
                writeln!(
                    out,
                    "HOSTNAME PROXY:  {vm:<width$} listening on 127.0.0.1:{port} · <name>.min.internal routes through it",
                    vm = listing.vm,
                    width = VM_COLUMN_WIDTH,
                )?;
                facts += 1;
            }
            if let Some(answerer) = listing.resp.zone_answerer_port {
                writeln!(
                    out,
                    "ZONE ANSWERER:   {vm:<width$} listening on 127.0.0.1:{answerer} (UDP) · point the host's resolver at it for *.min.internal",
                    vm = listing.vm,
                    width = VM_COLUMN_WIDTH,
                )?;
                facts += 1;
            } else if let Some(line) =
                answerer_at(index).and_then(crate::resolver::vm_host_answerer_line)
            {
                writeln!(
                    out,
                    "ZONE ANSWERER:   {vm:<width$} {line}",
                    vm = listing.vm,
                    width = VM_COLUMN_WIDTH,
                )?;
                facts += 1;
            }
            // NET-018: say which of the two surfaces is live for this VM —
            // the one verdict both verbs share, this VM's own, as `cmd_ls`
            // computed it. `None` — this VM's daemon reporting its answerer
            // not bound, or a caller that computed nothing — prints
            // nothing: the port lines above already tell that story, and
            // the advisory the activation path prints (NET-122) says how to
            // get from one surface to the other. `--raw` and `--json` stay
            // machine-readable-only, as for the ports.
            if let Some(surface) = surface_at(index) {
                writeln!(
                    out,
                    "NAME SURFACE:    {vm:<width$} {}",
                    crate::resolver::name_surface_line(surface, listing.resp.hostname_proxy_port),
                    vm = listing.vm,
                    width = VM_COLUMN_WIDTH,
                )?;
                facts += 1;
            }
        }
        if facts > 0 {
            writeln!(out)?;
        }
    }

    let any_sessions = listings
        .iter()
        .any(|listing| !listing.resp.sessions.is_empty());
    if !any_sessions {
        if !args.raw {
            writeln!(out, "No active sessions.")?;
        }
        return Ok(());
    }

    if args.raw {
        // Bare ids only — one per box, across every VM.
        for listing in listings {
            for entry in &listing.resp.sessions {
                writeln!(out, "{}", entry.id)?;
            }
        }
        return Ok(());
    }

    // Format as a table, the single-VM columns with the VM each box lives on
    // leading them (NET-057: the listing shows the VM per box).
    writeln!(
        out,
        "{:<vm_width$}  {:<36}  {:<20}  {:<13}  {:<20}  {:<19}  PROJECT PATH",
        "VM",
        "SESSION ID",
        "NAME",
        "STATUS",
        "TITLE",
        "LAST ACTIVITY",
        vm_width = VM_COLUMN_WIDTH,
    )?;
    writeln!(
        out,
        "{:<vm_width$}  {:-<36}  {:-<20}  {:-<13}  {:-<20}  {:-<19}  {:-<24}",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        vm_width = VM_COLUMN_WIDTH,
    )?;
    for listing in listings {
        for entry in &listing.resp.sessions {
            let [id, name, status, title, last_activity, project_path] = session_cells(entry);
            writeln!(
                out,
                "{:<vm_width$}  {id:<36}  {name:<20}  {status:<13}  {title:<20}  {last_activity:<19}  {project_path}",
                listing.vm,
                vm_width = VM_COLUMN_WIDTH,
            )?;
        }
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
