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

/// Create a new session via the `CreateSession` RPC.
pub async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), anyhow::Error> {
    activate_session(global, args, true).await
}

// The box registration exchange with the VM host daemon (T66) — the
// register, its lease, the withdrawal and the resume — is the client
// library's, shared with `min dash` so the two front-ends cannot drift.
pub(crate) use minimal_client::box_registration::withdraw_box_row;
use minimal_client::box_registration::{
    BOX_CONTROL_TIMEOUT, control_request_with_vm_host, finalize_holding_lease,
    register_box_reminting_autogen, resume_box_row,
};
#[cfg(test)]
use minimal_client::box_registration::{
    RegisteredWithVmHost, register_box_for_activation, register_box_with_vm_host,
};

/// The provider kind this invocation's daemon connection resolves through:
/// `client_provider_kind`, the same key the socket resolution itself and the
/// fabric display turn on. Every gate that decides whether the host is
/// VM-backed keys on this and never on `use_minvmd()` — the flag is the
/// linux-only way to *ask* for the VM host, while macOS has no native
/// backend, so a flagless invocation there is minvmd-backed all the same
/// and the flag's own reading would leave exactly that host with no box
/// registration, no control socket to withdraw through, and a start line
/// that names no VM (NET-081's macOS half).
pub(crate) fn daemon_provider_kind(global: &GlobalArgs) -> paths::ProviderKind {
    client::client_provider_kind(global.use_minvmd())
}

/// The VM host daemon's control socket, when the daemon this invocation
/// talks to is minvmd-backed (T66): it sits beside the ssh socket in the
/// provider dir the daemon connection resolves through, so the client
/// finds both by the same rule — named VMs included, since the resolution
/// reads the same process-global VM name.
///
/// Keyed on the provider kind — [`daemon_provider_kind`], the rule the
/// fabric display already uses — never on `use_minvmd()` alone: the flag is
/// how Linux asks for the VM host, and macOS reaches it with no flag at
/// all, so the destroy and Ctrl-C withdrawals must resolve their socket for
/// the kind, or a macOS box's row would stay published when its session
/// goes.
///
/// Silent by design: an invocation that owes nothing — no VM host, an
/// unresolvable dir — asks for nothing, and the withdrawal's own warning is
/// the one that names the row left published.
pub(crate) fn vm_host_control_sock(
    kind: paths::ProviderKind,
    minimal_dir: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    if kind != paths::ProviderKind::Minvmd {
        return None;
    }
    let ssh_sock = client::resolve_socket_path(minimal_dir, true).ok()?;
    control_sock_beside(&ssh_sock)
}

/// The control socket beside an ssh socket a client already resolved (T66's
/// rule, one definition for every caller): the VM host daemon serves both
/// from the same provider dir, so the socket a listing or an activation
/// reached a VM on is the one to find that VM's control socket beside.
pub(crate) fn control_sock_beside(ssh_sock: &std::path::Path) -> Option<std::path::PathBuf> {
    ssh_sock
        .parent()
        .map(|dir| dir.join(minvmd::control::CONTROL_SOCK_FILE))
}

/// The host reads `min net setup` decides its script from (NET-122): this
/// host's resolver detection and its answerer service step, read together,
/// with the control sockets the step asks to release the hook port recorded
/// for the render.
pub(crate) async fn advisory_host_reads(
    global: &GlobalArgs,
) -> (
    (
        crate::resolver::Hook,
        Option<String>,
        crate::resolver::RangeStep,
    ),
    crate::resolver::AnswererStep,
) {
    let (detection, answerer_step) = tokio::join!(
        crate::resolver::session_detection(),
        crate::resolver::read_answerer_step()
    );
    // The daemons the step asks to release the hook port: this CLI's
    // own state dir's — its VM host daemons, default VM and named VMs
    // alike, or its native daemon — never another state dir's.
    let controls = match daemon_provider_kind(global) {
        paths::ProviderKind::Minvmd => {
            client::enumerate_vm_sockets(global.minimal_dir.as_deref(), true)
                .unwrap_or_default()
                .iter()
                .filter_map(|vm| control_sock_beside(&vm.sock))
                .map(|sock| sock.display().to_string())
                .collect()
        }
        paths::ProviderKind::Minimald => {
            client::resolve_socket_path(global.minimal_dir.as_deref(), false)
                .ok()
                .and_then(|sock| control_sock_beside(&sock))
                .into_iter()
                .map(|sock| sock.display().to_string())
                .collect()
        }
    };
    crate::resolver::set_handover_controls(controls);
    (detection, answerer_step)
}

/// The machine's zone-answerer state, read from the VM host daemon's
/// control socket (NET-138) — the read-only status verb, over the same
/// socket the box rows ride, so the posture (a 0600 socket in the provider
/// dir, the connection's own reach) is the one every other verb is served
/// under.
///
/// Never read through the in-VM daemon: a guest relaying a host fact is
/// forgeable from inside the escape boundary, so the CLI asks the host
/// daemon that owns the fact. `None` — nothing to surface — when this
/// invocation is not on a VM-backed host, the socket is not there, the
/// deadline passes, or the daemon predates the verb and refuses the line:
/// each is the same honest silence a daemon still bringing its answerer up
/// gets, and the verbs print nothing they cannot prove. Whether the
/// invocation is on a VM-backed host is [`daemon_provider_kind`]'s to say,
/// the rule every VM-backed gate keys on — never `use_minvmd()` alone
/// (NET-081's macOS half).
pub(crate) async fn vm_host_answerer_status(
    global: &GlobalArgs,
) -> Option<minimald_rpc::AnswererStatusReply> {
    vm_host_answerer_status_at(vm_host_control_sock(
        daemon_provider_kind(global),
        global.minimal_dir.as_deref(),
    ))
    .await
}

/// [`vm_host_answerer_status`]'s read over one control socket the caller
/// resolved itself: the same bounded read, the same silence rules, over any
/// VM host daemon's socket — `min ls` reads each listed VM's own state
/// beside the ssh socket its listing reached that VM on (NET-057's
/// enumeration), so the socket is the caller's to name.
pub(crate) async fn vm_host_answerer_status_at(
    sock_path: Option<std::path::PathBuf>,
) -> Option<minimald_rpc::AnswererStatusReply> {
    let sock_path = sock_path?;
    let read = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        control_request_with_vm_host(&sock_path, minimald_rpc::BoxControlRequest::AnswererStatus),
    )
    .await;
    match read {
        Ok(Ok(minimald_rpc::BoxControlReply::Status(status))) => Some(status),
        // Any other reply — a refusal from a daemon that predates the verb,
        // a line that did not parse — is a daemon that cannot answer the
        // question; say nothing rather than guessing the machine's state.
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => None,
    }
}

/// The interim's own start line (NET-138): who answers this VM's box zone,
/// under the label the session's other facts print beside. Every session
/// start on a VM-backed host prints it — TTY and non-TTY, before the
/// advisory and the verdict — because the interim is a fact about the
/// machine the session is about to rely on: which VM host daemon answers
/// the zone decides where the names resolve from, and a start that said
/// nothing left the holder discoverable only from `min ls`. The same line
/// `min ls` prints for the state ([`crate::resolver::vm_host_answerer_line`]),
/// so the two surfaces name one holder the same way. Pure, so the test
/// asserts the wording without capturing stderr.
///
/// `None` for the pre-acquisition state — a daemon still bringing its
/// answerer up has nothing to name yet, and the start prints nothing for
/// it, exactly as `min ls` does.
#[must_use]
pub(crate) fn vm_host_answerer_start_line(
    status: minimald_rpc::ZoneAnswererStatus,
) -> Option<String> {
    crate::resolver::vm_host_answerer_line(status).map(|line| format!("zone answerer: {line}"))
}

/// Releases the zone hold a destroyed session's activation made, when the
/// session registered no row (`box_addresses` is `None` — a `host_ip` box
/// holds its name in place of a row): the destroy-side twin of the hold
/// [`activate_session`] makes once the session is active. Best-effort and
/// warn-only like the hold; a name no hold kept is the goal state already
/// holding, so a `none` box's release changes nothing. The release names
/// the session `id`, so it frees only that session's hold, never a newer
/// session's under the same name.
pub(crate) async fn release_held_box_name(
    control_sock: Option<std::path::PathBuf>,
    id: sessions::SessionId,
    name: Option<&str>,
    box_addresses: Option<sessions::BoxAddresses>,
) {
    if box_addresses.is_some() {
        return;
    }
    let Some(name) = name else { return };
    hold_box_name_with_vm_host(control_sock, name, Some(id), false).await;
}

/// A session's record by its `id`, bounded by [`BOX_CONTROL_TIMEOUT`]:
/// `None` once the session is gone. An interactive attach on a VM-backed
/// host reads it twice — before the attach, for the pair the box's row was
/// registered with, and after, to tell whether the attach ended in a
/// daemon-side destroy ([`release_held_name_after_attach`]).
async fn attached_session_record(
    sock: &std::path::Path,
    id: sessions::SessionId,
) -> anyhow::Result<Option<sessions::Record>> {
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    tokio::time::timeout(BOX_CONTROL_TIMEOUT, async {
        let mut client = client::Client::connect(sock).await?;
        let resp = client
            .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::Id(id))
            .await
            .context("GetSessionRecord RPC failed")?;
        anyhow::Ok(resp.record)
    })
    .await
    .map_err(|_| anyhow::anyhow!("no session lookup answer within {BOX_CONTROL_TIMEOUT:?}"))?
}

/// Releases what a session held on the VM host daemon once an interactive
/// attach on a VM-backed host has ended with the session gone: the
/// shell-exit prompt's Delete destroys the session daemon-side, so neither
/// `min session attach` nor `activate --attach` passes through
/// [`destroy_session`], and this is the release that destroy would have
/// made — the row's withdrawal (T66) for a box that registered one, whose
/// pair `box_addresses` was read off the record before the attach, and the
/// name hold's release for one that did not. The lookup and the release
/// are both by the session's `id`: a session still there — a detach, a
/// Keep — keeps its row and its hold, a newer session that took the name
/// keeps its own, and a hold a rename moved to another name is freed with
/// its session. Best-effort: a lookup that fails or times out releases
/// nothing, and a session that held nothing (a `none` box) is the goal
/// state already holding.
///
/// A destroy no client of this host issues — the daemon's own reap — still
/// leaves the hold until the VM host daemon restarts: holds carry no
/// liveness signal of their own.
pub(crate) async fn release_held_name_after_attach(
    sock: &std::path::Path,
    id: sessions::SessionId,
    name: &str,
    box_addresses: Option<sessions::BoxAddresses>,
) {
    match attached_session_record(sock, id).await {
        Ok(None) => match box_addresses {
            // The record carries no box id, so the pair is the proof.
            Some(addresses) => {
                let (ssh_sock, box_name) = (sock.to_path_buf(), name.to_string());
                let _ = tokio::task::spawn_blocking(move || {
                    minimal_client::attach::withdraw_box_row_beside(
                        &ssh_sock, &box_name, addresses, None,
                    )
                })
                .await;
            }
            None => {
                hold_box_name_with_vm_host(control_sock_beside(sock), name, Some(id), false).await;
            }
        },
        Ok(Some(_)) => {}
        Err(error) => tracing::debug!(
            box = %name,
            error = %format!("{error:#}"),
            "could not tell whether the attached session is gone; its row and name hold stay"
        ),
    }
}

/// Holds or releases a `host_ip` box's name on the VM host daemon, by
/// `hold`, best-effort: the hold is the interim that answers the name
/// NODATA where an unheld name answers NXDOMAIN — the \[proposed\] pre-alias
/// interim of the architecture's deployment-and-egress-gateway ruling
/// (§7.1: the name stays in-zone, answered as absent) — and the release
/// ends the interim with the session that bought it. A daemon that predates the
/// verbs refuses them and the session goes on exactly as it did before —
/// the name answers NXDOMAIN there, which is never a state a session
/// fails over. Both carry the session `id` the hold is for, so a release
/// frees only that session's hold.
async fn hold_box_name_with_vm_host(
    control_sock: Option<std::path::PathBuf>,
    name: &str,
    id: Option<sessions::SessionId>,
    hold: bool,
) {
    let request = minimald_rpc::HoldBoxNameRequest {
        name: name.to_string(),
        session_id: id,
    };
    let (verb, operation) = if hold {
        (
            minimald_rpc::BoxControlRequest::HoldBoxName(request),
            "hold",
        )
    } else {
        (
            minimald_rpc::BoxControlRequest::ReleaseBoxName(request),
            "release",
        )
    };
    let Some(sock_path) = control_sock else {
        return;
    };
    let sent = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        control_request_with_vm_host(&sock_path, verb),
    )
    .await;
    let failure = match sent {
        Ok(Ok(minimald_rpc::BoxControlReply::NameHeld { .. })) => None,
        Ok(Ok(other)) => Some(format!("another verb's reply: {other:?}")),
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some(format!("no answer within {BOX_CONTROL_TIMEOUT:?}")),
    };
    if let Some(reason) = failure {
        tracing::warn!(
            box = %name,
            operation,
            "the box name {operation} could not be made ({reason}); the name \
             answers as it did before"
        );
    }
}

/// The session-start line for a box the activation registered with the VM
/// host daemon (T66): the one line the start output owes the registration,
/// naming the VM host daemon the row lives on and the switch address the box
/// was handed — the facts a bundle's CLI transcript then answers without
/// reaching for the daemon's log, and the one line the host that reaches the
/// VM host daemon with no provider flag at all (NET-081's macOS half) has to
/// show for its own boxes.
///
/// `vm` is the VM host the line names, by the same rule
/// [`hostname_proxy_start_line`] names the proxy's: the selected VM on the VM
/// backend, `None` on a backend that hosts no VMs. A registered box only ever
/// exists on the former, so the `None` shape is the defensive one, mirroring
/// the sibling start line's.
#[must_use]
pub fn box_registered_start_line(
    vm: Option<&str>,
    name: &str,
    addresses: &sessions::BoxAddresses,
) -> String {
    match vm {
        Some(vm) => format!(
            "BOX REGISTRATION:  box '{name}' registered with the VM host daemon on VM '{vm}' · \
             switch address {}",
            addresses.switch_address
        ),
        None => format!(
            "BOX REGISTRATION:  box '{name}' registered with the VM host daemon · \
             switch address {}",
            addresses.switch_address
        ),
    }
}

/// The activation flow shared by [`cmd_activate`] and the bare-`min` router.
/// `offer_scaffold` gates the `minimal.toml` scaffold offer: `cmd_activate`
/// keeps it (its long-standing behavior, unchanged), while bare `min`
/// suppresses it — that path must land in a session, never in a config
/// prompt. Everything else, including the session id on stdout, is
/// identical for both callers.
/// Refuses a dynamic ingress declaration on a box that is not `own_ip`:
/// only an own-IP box has a published address a runtime publish could
/// apply to, so a stance or range on a `host_ip` or `none` box would be a
/// declaration `min session policy` shows and nothing ever honours. The
/// CLI reference documents the flags as requiring `--network own_ip`.
fn refuse_dynamic_ingress_off_own_ip(
    network: crate::cli::CliNetworkMode,
    mode: Option<sessions::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> Result<(), anyhow::Error> {
    if network != crate::cli::CliNetworkMode::OwnIp && (mode.is_some() || range.is_some()) {
        anyhow::bail!(
            "--dynamic-ingress and --dynamic-range need --network own_ip: only an own-IP box \
             has a published address to apply them to"
        );
    }
    Ok(())
}

/// Refuses a static ingress mapping on a box that is not `own_ip`: only an
/// own-IP box has a published address a static forwarder could apply to, so
/// a mapping on a `host_ip` or `none` box would be recorded and shown with
/// no publish surface to honour it. The CLI reference documents the flag as
/// requiring `--network own_ip`.
fn refuse_ingress_off_own_ip(
    network: crate::cli::CliNetworkMode,
    has_ingress: bool,
) -> Result<(), anyhow::Error> {
    if network != crate::cli::CliNetworkMode::OwnIp && has_ingress {
        anyhow::bail!(
            "--ingress needs --network own_ip: only an own-IP box has a published \
             address to apply it to"
        );
    }
    Ok(())
}

pub(crate) async fn activate_session(
    global: &GlobalArgs,
    args: ActivateArgs,
    offer_scaffold: bool,
) -> Result<(), anyhow::Error> {
    // Before anything is created, and before the daemon is spawned (a cold
    // VM boot), since both are argument errors: a dynamic declaration needs
    // an own-IP box. Every stance stands on a VM-backed host: an `ask` there is
    // answered by the human attached on the host (NET-045).
    refuse_dynamic_ingress_off_own_ip(args.network, args.dynamic_ingress, args.dynamic_range)?;
    // A static mapping needs an own-IP box too: only it has a published
    // address a static forwarder could apply to.
    refuse_ingress_off_own_ip(args.network, !args.ingress.is_empty())?;
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
    let mut allow_protocols = Vec::with_capacity(args.allow_protocols.len());
    for spec in &args.allow_protocols {
        allow_protocols.push(parse_egress_proto(spec)?);
    }
    // Any egress flag makes the declaration; a field with no values stays
    // `None` — its allow-all/none-denied default — so `--deny-subnets` alone
    // records an allow-all policy that denies one range. `--deny-all-egress`
    // is the whole declaration on its own: it maps to
    // `sessions::EgressPolicy::deny_all()`, every allow list present and
    // empty, rather than to four absent lists — a deny-all box declared by
    // flag must read in the record exactly like one declared by file, which
    // is the shape the host-address classifier decides its verdict on
    // (NET-079) and the one `min session policy` names `deny-all`. The parse
    // conflict (`cli.rs`) keeps it from combining with a rule flag, so the
    // arms cannot both run.
    let egress = if args.deny_all_egress {
        Some(sessions::EgressPolicy::deny_all())
    } else {
        let has_egress = !args.allow_subnets.is_empty()
            || !allow_protocols.is_empty()
            || !args.allow_dns_hosts.is_empty()
            || !args.deny_subnets.is_empty();
        has_egress.then_some(sessions::EgressPolicy {
            allow_subnets: (!args.allow_subnets.is_empty())
                .then(|| normalize_subnets(&args.allow_subnets)),
            allow_dns_hosts: (!args.allow_dns_hosts.is_empty())
                .then(|| args.allow_dns_hosts.clone()),
            allow_protocols: (!allow_protocols.is_empty()).then_some(allow_protocols),
            deny_subnets: (!args.deny_subnets.is_empty())
                .then(|| normalize_subnets(&args.deny_subnets)),
        })
    };
    // NET-043: any dynamic declaration makes the ingress policy too — a
    // stance alone (with no range, no static mapping) still names how
    // dynamic requests are decided, and a range without a stance cannot
    // reach the create (the flag requires its mode). Nothing set keeps
    // `None`: the deny-all default, which the policy module evaluates the
    // same as an explicit deny.
    let has_ingress =
        !port_mappings.is_empty() || args.dynamic_ingress.is_some() || args.dynamic_range.is_some();
    let policy = sessions::SessionPolicy {
        egress,
        ingress: has_ingress.then_some(sessions::IngressPolicy {
            port_mappings,
            dynamic_allowed_range: args.dynamic_range,
            dynamic_ingress: args.dynamic_ingress,
        }),
        // NET-134: the lane is the box's own declaration, never a default —
        // a box that did not ask for a credentialed upstream keeps every
        // frame it sends to the proxy's address refused at the host-side
        // gate, whatever its egress rules say.
        credentialed_upstream: args
            .credentialed_upstream
            .then(sessions::CredentialedUpstream::default),
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

    let network: sessions::NetworkMode = args.network.into();

    // The daemon sources `username` from the authenticated SSH
    // connection context; the client doesn't send it. `box_addresses`
    // lands just before the create (T66): the registration is the last
    // fallible client-side step, so a loadout, policy, or hook failure
    // between here and there never strands a row on the host.
    let mut config = minimald_rpc::SessionConfig {
        name: Some(session_name),
        project_path: abs_path.clone(),
        network,
        policy,
        task_addresses: Vec::new(),
        box_id: None,
        box_addresses: None,
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
    // `--sync none` never sends a `minimal.toml`, so offering to create
    // one there would only write a file the session then ignores.
    if offer_scaffold && !matches!(args.sync, Some(SyncMode::None)) {
        offer_mfile_scaffold(
            &utf8_path,
            global,
            Some(
                "Continuing without one; the session gets a default environment. \
                 Run 'min init' to give the project its own config.",
            ),
        )?;
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

    // T66: an own-address box on a VM-backed host registers with the VM host
    // daemon just before the create — the host allocates the box's switch
    // and loopback addresses into the table its egress gate decides by and
    // hands them back, and the create request carries them so the in-VM
    // daemon attaches with the handed switch address instead of drawing its
    // own. A `host_ip` box shares the node's own row, so it registers no
    // row of its own — its name is held in the zone instead (NODATA) once
    // the session is active, below — and a `none` box, or a native daemon
    // with no box table, registers nothing and attaches as it always has.
    // A registration that cannot be made ends the activation here, with its
    // cause: no session exists yet to clean up, and a box that went on to
    // create unregistered would run with no host-side row to decide its
    // egress by, so this is the one failure that never falls back. Past
    // here, the row exists and every later failure owes it its creator's
    // withdrawal (T66): the sites below send it. The control socket is
    // resolved once, here, and the withdrawals ride on it.
    let kind = daemon_provider_kind(global);
    let control_sock = vm_host_control_sock(kind, global.minimal_dir.as_deref());
    // An autogen name can collide with a live box's row the same way it
    // can with a session (the row stays live until its session's destroy):
    // the registration's refusal re-mints it within the same budget the
    // create's collision retry below spends.
    let mut attempts = 0u32;
    let mut registered = register_box_reminting_autogen(
        kind,
        global.minimal_dir.as_deref(),
        config.network,
        config
            .name
            .as_mut()
            .expect("the session name is minted before the create"),
        &config.policy,
        autogen,
        &mut attempts,
        || autogen_session_name(&utf8_path, &random_hex4()),
    )
    .await?;
    // The registration is the client's record of the box: the addresses
    // the create carries, and the id the host minted for it (NET-133).
    config.box_addresses = registered
        .as_ref()
        .map(|registration| registration.addresses);
    config.task_addresses = registered
        .as_ref()
        .map(|registration| registration.task_addresses.clone())
        .unwrap_or_default();
    config.box_id = registered
        .as_ref()
        .and_then(|registration| registration.box_id);

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
    };
    // An autogen name can (rarely) collide with an existing session built
    // from the same directory; on the daemon's already-exists rejection,
    // re-mint the hex suffix and retry a bounded number of times. A
    // user-supplied name never retries — its collision, and any other failure
    // (e.g. a policy/network-mode validation error), surfaces unchanged.
    // `attempts` carries over from the registration's own collision retry.
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
            .await;
        let resp = match resp {
            Ok(resp) => resp,
            // A transport failure abandons the activation and the row its
            // registration bought: the create never happened, so no session
            // holds the pair (T66).
            Err(error) => {
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
                return Err(error.context("CreateSession RPC failed"));
            }
        };
        match resp {
            minimald_rpc::Errorable::Ok(r) => break r,
            minimald_rpc::Errorable::Err { error } => {
                if should_retry_autogen(autogen, attempts, &error) {
                    attempts += 1;
                    // The row the first attempt bought is this attempt's to
                    // leave behind: its creator withdraws it before
                    // re-registering under the re-minted name (T66) — it was
                    // bought for a session this create never made.
                    withdraw_box_row(
                        control_sock.clone(),
                        config.name.as_deref(),
                        config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                    // The abandoned row's lease goes with it, uncommitted.
                    drop(registered.take());
                    config.name = Some(autogen_session_name(&utf8_path, &random_hex4()));
                    // A registered box's row carries the name it was
                    // registered under (T66), so the re-mint re-registers;
                    // the abandoned row is withdrawn above, by its id, which
                    // returns its addresses to the host's hand-out books,
                    // and the retry leaves no row behind. The re-registration can itself fail —
                    // the plan can be exhausted by then — and that failure
                    // ends the retry loop the same way the first one would
                    // have, with its cause. The first registration's id is
                    // discarded with its row: ids are never freed or
                    // reused, so the re-registration is a new creation, and
                    // the host mints it a new id, which replaces the record
                    // (NET-133).
                    registered = register_box_reminting_autogen(
                        kind,
                        global.minimal_dir.as_deref(),
                        config.network,
                        config.name.as_mut().expect("just re-minted"),
                        &config.policy,
                        autogen,
                        &mut attempts,
                        || autogen_session_name(&utf8_path, &random_hex4()),
                    )
                    .await?;
                    config.box_addresses = registered
                        .as_ref()
                        .map(|registration| registration.addresses);
                    config.task_addresses = registered
                        .as_ref()
                        .map(|registration| registration.task_addresses.clone())
                        .unwrap_or_default();
                    config.box_id = registered
                        .as_ref()
                        .and_then(|registration| registration.box_id);
                    continue;
                }
                // A create failure that is not a retryable autogen collision
                // abandons the activation and its row the same way.
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
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
    if let Err(error) = ensure_version_reported(created.daemon_version.as_deref()) {
        // A skewed daemon's refusal abandons the unfinalized session and its
        // row; the withdrawal rides out with the error (T66).
        withdraw_box_row(
            control_sock.clone(),
            config.name.as_deref(),
            config.box_addresses,
            registered
                .as_ref()
                .and_then(|registration| registration.box_id),
        )
        .await;
        return Err(error);
    }
    // The registration's own half of the session-start output (T66): one line
    // naming the VM host daemon the box's row lives on and the switch address
    // it was handed, beside the `tracing::info!` line the same registration
    // writes. The line is the one a bundle reads off the CLI transcript to say
    // whether this box has a host row — which is the question the host that
    // reaches the VM host daemon with no provider flag at all (NET-081's macOS
    // half) otherwise answers nowhere in its own output. A box that registered
    // nothing — a native host, a host-ip box sharing the node's own row, a
    // `none` box with no switch address — prints nothing: it has no row to
    // name. Keyed on the provider kind the registration itself keyed on, never
    // on `use_minvmd()`, so the flagless VM-backed host prints it too.
    if let Some(addresses) = config.box_addresses.as_ref() {
        eprintln!(
            "{}",
            box_registered_start_line(
                hostname_proxy_vm(kind),
                config.name.as_deref().unwrap_or("-"),
                addresses,
            )
        );
    }
    warn_if_hostname_routing_down(
        created.hostname_routing_unavailable.as_deref(),
        "min session activate",
    );
    // NET-122/NET-123/NET-138: the naming lines, printed once per session
    // start — after the create, and re-surfaced when the daemon reports this
    // session at the 127.0.0.1 interim because its session-start bind
    // probe found the reserved range absent. The advisory only ever names
    // the command that points the host's resolver at the answerer; running
    // it (and any privilege prompt it carries) is the user's act, never the
    // session start's. One read of this host's resolver state decides the
    // advisory and the surface verdict below it, so the two lines cannot
    // disagree about one host.
    //
    // On a VM-backed host the answerer is the VM host daemon's (NET-138):
    // the in-VM daemon starts none, so the port and the bound proof come
    // from the host — the state read over minvmd's control socket (never
    // through the in-VM daemon, because a guest relaying a host fact is
    // forgeable from inside the escape boundary) and this CLI's own A
    // query for the host's row at the port that read named, the proof the
    // answerer is live rather than merely reported held. A native host
    // keeps the daemon's own report. `held_no_channel` is the machine fact
    // that ends the question: a port held by a process no channel reaches
    // means this VM's names are not answered on the host whatever this
    // host's hook and range say, so neither is read and the warning says
    // the fact instead of the advisory.
    let (vm_answerer, answerer_port, answerer_bound, held_no_channel, proxy_down) =
        match vm_host_answerer_status(global).await {
            Some(reply) => {
                let read = crate::resolver::host_answerer_read(reply.clone()).await;
                (
                    Some(reply),
                    read.port,
                    read.answerer_bound,
                    read.held_no_channel,
                    read.proxy_down,
                )
            }
            None => (
                None,
                created.zone_answerer_port,
                created.answerer_bound,
                false,
                None,
            ),
        };
    // The proxy and surface lines below never name the reported port as
    // serving while the reply carries a proxy-down sibling, and its cause
    // prints exactly once: folded into a Proxy verdict's NAME SURFACE line
    // (`ProxyNotServing`), or on a line of its own beside a Native verdict
    // or no verdict — never both, and never beside a "still serves" or
    // "routes through it".
    let proxy_down_sibling = vm_answerer
        .as_ref()
        .and_then(|reply| reply.proxy_down.as_ref());
    let serving_proxy_port =
        crate::resolver::serving_proxy_port(created.hostname_proxy_port, proxy_down_sibling);
    // The other routing fact the create reply carries: the port this daemon's
    // hostnames route through, printed where the session started — the same
    // fact `min ls` prints on its routing line. NET-026's discovery on this
    // surface; and the report a port has to carry when it is *not* the one the
    // recipes assume — a VM whose host port the host already held walked to
    // one of its own (NET-059), a native daemon whose default was busy asked
    // the OS for a free one (NET-025) — so a walked port is never a log line
    // alone. Absent while the proxy is still coming up, or from a daemon that
    // predates the field: nothing to print for it then, exactly as in `min
    // ls`. Not printed beside a proxy-down sibling either: the VM host
    // daemon's verdict is that the proxy is not serving, and the cause
    // names itself below.
    if let Some(port) = serving_proxy_port {
        eprintln!(
            "{}",
            hostname_proxy_start_line(hostname_proxy_start_vm(global), port)
        );
    }
    // The interim itself, named at every session start on a VM-backed host
    // — TTY and non-TTY, ahead of the warning, the advisory and the verdict
    // below — because who answers the zone is the machine fact the names
    // this session is about to rely on rest on, and a holder another VM's
    // minvmd took is otherwise discoverable only from `min ls`. The
    // pre-acquisition state prints nothing: nothing is held yet to name.
    // The reply's two facts are two lines: the answerer's state renders
    // from the answerer field — even while the proxy is down or its
    // publish unconfirmed, because the sibling cause no longer displaces
    // the state — and the proxy's publish outcome, when the reply carries
    // one, names itself once below, with the surface verdict.
    if let Some(reply) = &vm_answerer
        && let Some(line) = vm_host_answerer_start_line(reply.answerer.clone())
    {
        eprintln!("{line}");
    }
    if held_no_channel && let Some(answerer_port) = answerer_port {
        // NET-138's warning, at every session start — TTY and non-TTY: it
        // rides stderr unconditionally, because the first lookup that
        // fails is the one it explains, and a piped activate is as owed
        // the fact as an interactive one.
        eprintln!(
            "{}",
            crate::resolver::port_held_no_channel_warning(answerer_port)
        );
        // The verdict is the proxy's by the status's own word, without
        // reading the hook or the range: both could only misreport native
        // for a port no daemon answers, and the arm that cannot strand the
        // user is the proxy's (NET-019 keeps it serving). Logged as the
        // same session-start record the native arm logs, with the fact
        // that decided it.
        let surface = crate::resolver::surface_beside_proxy_down(
            crate::resolver::LiveSurface::Proxy,
            proxy_down_sibling,
        );
        tracing::info!(
            surface = ?surface,
            held_no_channel = true,
            answerer_bound = false,
            answerer_port = answerer_port,
            "session start decided the live name surface for this host"
        );
        eprintln!(
            "{}",
            crate::resolver::name_surface_line(surface, serving_proxy_port)
        );
    } else if answerer_port.is_none()
        && let Some((port, cause)) = proxy_down
    {
        // T93: the VM host daemon's own verdict on the hostname proxy's
        // publication — a terminal publish failure, named with the port it
        // is about and its cause instead of a bare "not serving" — printed
        // at every session start, TTY and non-TTY alike, because the names
        // this session is about to rely on are the ones the line says
        // cannot resolve. No host read runs in this arm — no detection, no
        // liveness query, no range probe — because the status is the VM
        // host daemon's answer on the proxy's publication, and no host
        // probe can move it. Reached only when the answerer is not
        // decidable — the pre-acquisition state, or the old daemon's
        // substituting state — because a reply that carries both an
        // answerer verdict and the sibling cause has its surface decided
        // by the answerer arm below: the cause has already named the
        // proxy's half on the line of its own above, and the answerer's
        // half is the detection's to read.
        let surface = crate::resolver::LiveSurface::ProxyNotServing { port, cause };
        tracing::info!(
            surface = ?surface,
            "session start decided the live name surface for this host"
        );
        eprintln!(
            "{}",
            crate::resolver::name_surface_line(surface, created.hostname_proxy_port)
        );
    } else if let Some(answerer_port) = answerer_port {
        // NET-018: name the live surface at the moment the user is about to
        // rely on the names — decided in the one function both verbs share
        // (`resolver`), from this host's detection: its hook (and the
        // stub-bypass blocker that says whether its lookups consult what the
        // hook configures), the answerer-bound proof this start holds — the
        // daemon's report on a native host, this CLI's own query on a
        // VM-backed one — and the reserved range on this host's own
        // loopback. `None` — the answerer not bound — prints the proxy's
        // line: there is no native surface to name. A proxy-down sibling
        // folds into a Proxy surface (`ProxyNotServing`) and otherwise
        // prints on a line of its own, ahead of the surface's. The proxy's
        // half is said with the native arm either way (NET-019): the
        // `HTTP(S)_PROXY` recipes this activation prints keep working beside
        // native DNS, so nothing already captured goes stale.
        //
        // Host DNS is opt-in (NET-122): the start never prints the
        // privileged step. While the host is not set up the proxy is the
        // live surface, and its line names `min net setup`, which prints or
        // runs the step from its own reads of the host.
        let detection = crate::resolver::session_detection().await;
        let surface_verdict = crate::resolver::live_name_surface_with_range_at(
            &detection,
            Some(answerer_port),
            answerer_bound,
        )
        .await
        .map(|verdict| crate::resolver::LiveSurfaceVerdict {
            surface: crate::resolver::surface_beside_proxy_down(
                verdict.surface,
                proxy_down_sibling,
            ),
            ..verdict
        });
        // With no verdict the proxy is the live surface, folded with the
        // sibling the same way, so the cause still prints exactly once.
        let unbound_surface = crate::resolver::surface_beside_proxy_down(
            crate::resolver::LiveSurface::Proxy,
            proxy_down_sibling,
        );
        if let Some(line) = crate::resolver::proxy_down_line_beside(
            Some(
                surface_verdict
                    .as_ref()
                    .map_or(&unbound_surface, |verdict| &verdict.surface),
            ),
            proxy_down_sibling,
        ) {
            eprintln!("{line}");
        }
        if let Some(verdict) = surface_verdict {
            // The host-side record of that verdict, the half the daemon's own
            // log cannot make: a daemon can name only the answerer *it* binds
            // (see the daemon's `log_live_name_surface`), so the surface this
            // host's own reads decided — and the three facts behind it, with
            // the range as the one fact only this read holds — is logged here,
            // at the start that printed it, beside the daemon's line. `min`
            // filters at `warn` unless `RUST_LOG` is set, so the line is visible
            // under `RUST_LOG=info`. Logged, never printed: the line
            // below is the user's. `min ls` does not log its verdict — a list
            // re-reads the host every run, and the record that matters is the
            // one at the starts that rely on the names.
            tracing::info!(
                surface = ?verdict.surface,
                hook_routes = detection.0.routes(answerer_port),
                blocker = ?detection.1,
                answerer_bound = answerer_bound,
                range_present = ?verdict.range_present,
                range_unit_state = ?detection.2.state,
                range_unit_check = ?detection.2.failed_check,
                hostname_proxy_down = ?proxy_down,
                "session start decided the live name surface for this host, \
                 with the range unit's state beside it"
            );
            eprintln!(
                "{}",
                crate::resolver::start_name_surface_line(Some(verdict.surface), serving_proxy_port)
            );
        } else {
            // The answerer is reported but not bound yet: no native surface
            // to name, so the proxy is the live one, and its line carries the
            // `min net setup` pointer NET-122 owes every start on a host not
            // set up — or, beside a proxy-down sibling, the cause instead.
            tracing::info!(
                surface = ?unbound_surface,
                answerer_bound = false,
                answerer_port = answerer_port,
                hostname_proxy_down = ?proxy_down,
                "session start decided the live name surface for this host"
            );
            eprintln!(
                "{}",
                crate::resolver::start_name_surface_line(Some(unbound_surface), serving_proxy_port)
            );
        }
    }
    let id = created.id;

    // NET-079: the host's verdict on whether it can decide a host-address
    // box's egress per box, spelled by the daemon — the side that read the
    // host — and printed verbatim, so the terminal, the daemon's log line
    // for this same create, and the start all say the same thing. The
    // advisory names the cause, the state it leaves the box in, and, when
    // the missing privileged step is the cause, the exact command that
    // installs it; it is never a prompt, and never load-bearing for the
    // start either (see [`print_classifier_advisory`]). Printed after the
    // session exists and before the work on it, like the notice below it,
    // so a host that cannot decide per box is named at the start that
    // runs there and not only in a log the person was not reading.
    print_classifier_advisory(&mut std::io::stderr(), &created);

    // The in-force note (NET-074): one line naming the default an
    // own-address session that declared no egress now has, and how to
    // declare reach. Scoped to the box the default binds — an own-address
    // session with no egress section — on a daemon that has not opted out
    // (NET-077): the opt-out is the daemon's own fact, so it is read off the
    // create reply above, and an opted-out daemon's box keeps allow-all and
    // needs no note. Printed after the session exists and before the work
    // on it, so it is not lost above a failed activate's output.
    if config.network == minimald_rpc::NetworkMode::OwnIp
        && config.policy.egress.is_none()
        && created.deny_all_opt_out != Some(true)
        && let Some(note) = deny_all_default_notice(sessions::EGRESS_DEFAULT_PHASE)
    {
        eprintln!("{note}");
    }

    // When a subnet flag carries host bits (e.g. `--deny-subnets 10.0.0.1/8`),
    // the enforcement layer reads it as the masked network (`10.0.0.0/8`).
    // Print a one-line notice naming the normalized form so the user knows
    // how their entry is read, rather than discovering it through a mismatch.
    // The notice is computed from the original flags, not the stored policy:
    // the policy now holds the normalized form, so reading it back would
    // print nothing.
    for entry in &args.allow_subnets {
        if let Some(normalized) = sessions::normalized_cidr(entry) {
            eprintln!("--allow-subnets {entry} is read as {normalized}");
        }
    }
    for entry in &args.deny_subnets {
        if let Some(normalized) = sessions::normalized_cidr(entry) {
            eprintln!("--deny-subnets {entry} is read as {normalized}");
        }
    }

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
        SyncMode::None => {
            // `--sync none` skips the upload, so the daemon composes against
            // an empty workspace and the project's `minimal.toml` — packages,
            // vars, patches, hooks — is silently dropped. Say so when there
            // is a config to lose, so the default-config session is not a
            // surprise.
            if let Some(notice) = sync_none_notice(&utf8_path) {
                eprintln!("{notice}");
            }
        }
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
                let uploaded = client
                    .upload_workspace_files(id, upload_root.as_std_path())
                    .await;
                if let Err(error) = uploaded {
                    // The upload failed: the activation is abandoned, and the
                    // row its registration bought goes with it (T66).
                    withdraw_box_row(
                        control_sock.clone(),
                        config.name.as_deref(),
                        config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
                    return Err(error.context("Failed to upload project files"));
                }
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
        .await;
    let configured = match configured {
        // A transport failure abandons the activation and its row (T66).
        Err(error) => {
            withdraw_box_row(
                control_sock.clone(),
                config.name.as_deref(),
                config.box_addresses,
                registered
                    .as_ref()
                    .and_then(|registration| registration.box_id),
            )
            .await;
            return Err(error.context("ConfigureLoadout RPC failed"));
        }
        Ok(configured) => configured,
    };
    let configured = match configured {
        minimald_rpc::Errorable::Ok(r) => r,
        // Bails before the `println!("{id}")` below: a session that cannot
        // compose never puts an id on stdout for a script to capture.
        minimald_rpc::Errorable::Err { error } => {
            // The session cannot compose and is abandoned with its row (T66).
            withdraw_box_row(
                control_sock.clone(),
                config.name.as_deref(),
                config.box_addresses,
                registered
                    .as_ref()
                    .and_then(|registration| registration.box_id),
            )
            .await;
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
                    // The session is aborted and its row withdrawn (T66):
                    // the path failed after registering.
                    withdraw_box_row(
                        control_sock.clone(),
                        config.name.as_deref(),
                        config.box_addresses,
                        registered
                            .as_ref()
                            .and_then(|registration| registration.box_id),
                    )
                    .await;
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
                // The session is aborted and its row withdrawn (T66): the
                // path failed after registering.
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
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
            let submitted = submit_verdict_and_wait(&mut client, session_id, verdict).await;
            if let Err(error) = submitted {
                // The verdict never landed: the activation is abandoned with
                // its row (T66).
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
                return Err(error);
            }
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
            if result.is_err() {
                // The activation failed after registering: its row is
                // withdrawn with it (T66).
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
                    registered
                        .as_ref()
                        .and_then(|registration| registration.box_id),
                )
                .await;
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
    // The registration's lease is held across the finalize and committed
    // only once the session is active: until then an activation that dies
    // leaves the VM host daemon to withdraw the row on the lease's close.
    let lease = registered
        .as_mut()
        .and_then(|registration| registration.lease.take());
    if let Err(e) = finalize_holding_lease(
        lease,
        upload_and_finalize(
            &mut client,
            id,
            &collected_patches,
            &hook_scripts,
            finalize_hook_budget,
        ),
    )
    .await
    {
        // Best-effort teardown: the session is stuck in
        // Materializing on the daemon. Destroy it so the operator's
        // `min ls` doesn't fill with half-finalized sessions, and
        // withdraw the row the registration bought with it (T66).
        best_effort_destroy(&mut client, id).await;
        withdraw_box_row(
            control_sock.clone(),
            config.name.as_deref(),
            config.box_addresses,
            registered
                .as_ref()
                .and_then(|registration| registration.box_id),
        )
        .await;
        return Err(e);
    }

    // The session is `Active` now — a Ctrl-C must no longer tear it down
    // (the attach hand-off below and the user's own session are fair game
    // for interrupts, but not this cleanup).
    drop(interrupt_guard);

    // The `host_ip` interim: the box shares the node's own row, so its name
    // is held in the zone with no row behind it and answers NODATA instead
    // of NXDOMAIN (best-effort, warned within the helper). Held only now
    // the session is active, so an activation that dies or fails earlier
    // — its unfinalized session reaped with the connection — leaves no
    // hold behind; the destroy releases it ([`release_held_box_name`]).
    // Only this activate/destroy pair holds: `min task run` (task.rs) mints
    // an ephemeral, auto-generated host_ip session through raw
    // `CreateSession`/`DestroySession` RPCs and never passes through here,
    // so its name is neither held nor released — a task box's name is not
    // meant to be reached, and widening the interim to that path is a
    // design ruling for the name-registry work, not a change a review
    // pass may make in passing.
    if kind == paths::ProviderKind::Minvmd
        && config.network == sessions::NetworkMode::HostNet
        && let Some(name) = config.name.as_deref()
    {
        hold_box_name_with_vm_host(control_sock.clone(), name, Some(id), true).await;
    }

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
    session_via_ssh(
        &sock,
        id,
        None,
        global.config_dir.as_deref(),
        host_asks.as_deref(),
    )
    .await
}

/// Resolve a named attach target to its record and the socket the hand-off
/// runs over — the target `min session attach` lands in when the name alone
/// decides where to look (NET-058).
///
/// The selected VM's daemon is asked first (`client`, reached over `sock`):
/// the common case — a box on the VM the operator is already on — costs
/// nothing beyond the one lookup the command always made, and its answer is
/// gated on the reply that lookup was already making. When that daemon does
/// not know the name, [`attach::resolve_box_vm`] resolves the VM that owns it
/// across every VM's socket, so no global flag is needed to reach a box on
/// another VM — the resolution gates the owning daemon on the very reply that
/// named the box, so a skewed VM cannot be reached through it. Nothing found
/// anywhere returns the selected VM's own error — the "no session found" it
/// computed, or its skew — as the more useful of the two answers.
pub(crate) async fn resolve_attach_target_version_gated(
    global: &GlobalArgs,
    client: &mut client::Client,
    sock: std::path::PathBuf,
    name: &str,
) -> Result<(sessions::Record, std::path::PathBuf), anyhow::Error> {
    match resolve_session_version_gated(client, name).await {
        Ok(record) => Ok((record, sock)),
        Err(selected) => match attach::resolve_box_vm(global, name).await? {
            Some(resolved) => {
                // The operator never chose the VM the way they chose the
                // session, so tell them which one they're landing in.
                if should_announce_session(global) {
                    eprintln!(
                        "Attaching to session {} on VM {}",
                        session_announce_label(
                            &resolved.record.id,
                            resolved.record.name.as_deref()
                        ),
                        resolved.vm
                    );
                }
                Ok((resolved.record, resolved.sock))
            }
            None => Err(selected),
        },
    }
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

    session_via_ssh(&sock, r.id, wire, None, None).await
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
    /// Attach to this resolved or picked session. Boxed: the entry is far
    /// larger than the other arms, which carry nothing.
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
            dynamic_range: None,
            allow_subnets: Vec::new(),
            allow_dns_hosts: Vec::new(),
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
            deny_all_egress: false,
            credentialed_upstream: false,
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
///
/// `host_asks_for` names the box whose pending asks the interactive attach
/// answers on a VM-backed host (NET-045): the attach subscribes on the VM
/// host daemon's control socket beside `sock` and renders each ask's dialog
/// while the relay is suspended. `None` on a native host, where the
/// session's own binding asks, and for every exec channel.
pub(crate) async fn session_via_ssh(
    sock: &std::path::Path,
    id: sessions::SessionId,
    wire: Option<String>,
    config_dir: Option<&std::path::Path>,
    host_asks_for: Option<&str>,
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

    // The session's record, read before the attach or the exec on a
    // VM-backed host — one with a VM host daemon's control socket beside
    // `sock` — for the pair its box's row was registered with. A lookup
    // that fails reads as no row, and says so: the row is then not asked
    // back, and the in-VM daemon's own row check decides the launch.
    let record = match control_sock_beside(sock).filter(|control| control.exists()) {
        Some(_) => match attached_session_record(sock, id).await {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(
                    "could not read the session's record ({error:#}); its box row \
                     is not asked back first"
                );
                None
            }
        },
        None => None,
    };
    // A VM host that cannot be reached fails the attach or the exec
    // closed (#1790); one that answers late or refuses is a warn line, and
    // the attach or the exec goes on (NET-138).
    resume_box_row(sock, record.as_ref()).await?;

    if wire.is_none() {
        let stdin_is_tty = std::io::stdin().is_terminal();
        let host_asks = host_asks_for
            .and_then(|name| control_sock_beside(sock).map(|control| (control, name.to_string())));
        // The pair the box's row was registered with, read before the
        // attach: an attach that ends in a daemon-side destroy leaves no
        // record to read it from, and the row is still this client's to
        // withdraw.
        let box_addresses = match host_asks_for {
            Some(_) => record.and_then(|record| record.box_addresses),
            None => None,
        };
        // The relay blocks its thread until ssh exits, so it runs off the
        // runtime's workers.
        let code = tokio::task::spawn_blocking(move || {
            interactive_attach(ssh, stdin_is_tty, attach::TerminalUnwind::arm, |ssh| {
                minimal_client::attach::run_interactive_attach(
                    ssh,
                    subscribe_host_asks(host_asks).map(minimal_client::attach::HostAsks::into_hook),
                )
            })
        })
        .await
        .context("the interactive attach's thread failed")??;
        // The attach may have ended in the shell-exit prompt's Delete, a
        // destroy made daemon-side: withdraw the row an own-address box
        // registered, or release the name a `host_ip` box held.
        if let Some(name) = host_asks_for {
            release_held_name_after_attach(sock, id, name, box_addresses).await;
        }
        // Terminate with ssh's own status, exactly as the `exec()` this
        // replaced did: `min` has nothing of its own left to say after an
        // attach, and the unwind guard has already run.
        std::process::exit(code);
    }

    // The exec path spawns ssh with stdout piped so this process can relay
    // it. When the local reader closes (e.g. `head -1`), the write to
    // stdout fails with BrokenPipe; we kill ssh and exit 141 (128+SIGPIPE)
    // rather than leaving the remote process running indefinitely (#815).
    //
    // Unlike the `exec()` this replaced, `min` is now ssh's parent, so a
    // signal sent only to this PID (`kill <pid>`, a supervisor reaping its
    // direct child) would orphan ssh with its stdout closed and the remote
    // command running on. Catch the termination signals and take ssh down
    // with us. The handlers go in before the spawn so there is no window.
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    ssh.stdout(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(ssh)
        .spawn()
        .context("failed to spawn ssh")?;
    let ssh_stdout = child.stdout.take().context("ssh stdout not piped")?;
    let mut local_stdout = tokio::io::stdout();
    let signo = tokio::select! {
        relayed = relay_exec_stdout(ssh_stdout, &mut local_stdout) => match relayed {
            Ok(()) => {
                // ssh stdout closed cleanly; wait for the child and propagate
                // its exit status.
                let status = child.wait().await.context("ssh exited")?;
                std::process::exit(exit_code_of(status));
            }
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                // Local reader closed; kill ssh and exit 141.
                kill_ssh(&mut child).await;
                std::process::exit(141);
            }
            Err(e) => {
                // Any other relay failure leaves ssh with nobody reading its
                // output; stop it so the remote command does not outlive us.
                kill_ssh(&mut child).await;
                return Err(e).context("relaying ssh stdout");
            }
        },
        _ = sigterm.recv() => SignalKind::terminate().as_raw_value(),
        _ = sighup.recv() => SignalKind::hangup().as_raw_value(),
        _ = sigint.recv() => SignalKind::interrupt().as_raw_value(),
    };
    kill_ssh(&mut child).await;
    std::process::exit(128 + signo);
}

/// Subscribe an interactive attach to its box's pending asks on the VM host
/// daemon (NET-045), from the control socket and the box's name. A
/// subscription that cannot be made leaves the attach as it is: the box's
/// asks are then refused at the host for want of an attached client, and
/// the reason is said here.
fn subscribe_host_asks(
    target: Option<(std::path::PathBuf, String)>,
) -> Option<minimal_client::attach::HostAsks> {
    let (control, name) = target?;
    match minimal_client::attach::HostAsks::subscribe(&control, &name) {
        Ok(asks) => Some(asks),
        Err(error) => {
            tracing::warn!(box = %name, error = %format!("{error:#}"), "could not subscribe to the box's asks");
            eprintln!(
                "warning: this attach cannot answer box '{name}' asking to publish a port: \
                 {error:#}"
            );
            None
        }
    }
}

/// The box an interactive attach answers asks for (NET-045): its name, on a
/// VM-backed host only.
pub(crate) fn host_asks_box(global: &GlobalArgs, name: Option<&str>) -> Option<String> {
    (daemon_provider_kind(global) == paths::ProviderKind::Minvmd)
        .then_some(name)
        .flatten()
        .map(str::to_string)
}

/// Kill the exec path's ssh child and reap it.
async fn kill_ssh(child: &mut tokio::process::Child) {
    // A failed kill means ssh has already exited, so there is nothing left
    // to stop; record it and carry on to this process's own exit.
    if let Err(e) = child.kill().await {
        tracing::debug!(error = %e, "ssh kill failed; it had already exited");
    }
}

/// The interactive attach, from the terminal check to ssh's exit code.
///
/// `-tt` over a *non-terminal* stdin is a trap: ssh still forces the remote
/// PTY, yet the interactive shell reading it never sees an EOF from a
/// redirected local stdin (`< /dev/null`, a pipe), so the command blocks
/// forever (#953). So the refusal comes first, before the relay opens any
/// pty or touches the terminal.
///
/// Then `relay` runs ssh through the client-owned terminal relay
/// ([`minimal_client::attach::run_interactive_attach`]), which has put the
/// terminal's termios back by the time it returns. Only then does the
/// unwind guard get its say, so its codes reach the real terminal (never
/// the relay's pty) in the termios the user started with. `minimald` sends
/// unwind codes with every teardown it initiates, but a transport that
/// drops mid-session sends nothing at all, and once ssh is gone this is the
/// only process left that can still reach the tty. So the guard stays
/// armed for the duration and is stood down only once ssh's exit proves
/// the daemon was alive and speaking: see `attach::client_must_unwind`.
pub(crate) fn interactive_attach<W: std::io::Write>(
    ssh: std::process::Command,
    stdin_is_tty: bool,
    arm_unwind: impl FnOnce() -> attach::TerminalUnwind<W>,
    relay: impl FnOnce(std::process::Command) -> Result<std::process::ExitStatus, anyhow::Error>,
) -> Result<i32, anyhow::Error> {
    ensure_interactive_attach_tty(stdin_is_tty)?;
    let mut unwind = arm_unwind();
    let status = match relay(ssh) {
        Ok(status) => status,
        Err(e) => {
            // ssh never ran (or the relay never took the terminal), so
            // nothing of the session reached the terminal and there is
            // nothing to put back.
            unwind.disarm();
            return Err(e).context("failed to run ssh");
        }
    };
    if !attach::client_must_unwind(&status) {
        unwind.disarm();
    }
    let code = exit_code_of(status);
    drop(unwind);
    Ok(code)
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

/// Relay a reader's bytes to a writer until the reader reaches EOF. Returns
/// `BrokenPipe` when the writer's far end closes first, so the caller can
/// kill the child whose output it was relaying (#815).
pub(crate) async fn relay_exec_stdout<R, W>(mut from: R, to: &mut W) -> Result<(), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
    }
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
        return session_policy_as_json(global, &args.session).await;
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
    let session = record.id.to_string();

    // The daemon resolves the effective egress (NET-074/NET-077), because
    // the rollout phase and its opt-out are the daemon's own facts; built
    // here rather than through a `SessionLookup` conversion so the request
    // types stay the rpc crate's, where the wire contract lives.
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(&session) {
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
    let facts_lookup = match SessionLookup::parse(&session) {
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
    let live = fetch_live_ingress_degrading(&mut client, &session).await;

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

/// The one-line note `min session activate` prints for an own-address box
/// that declares no egress while the deny-all default is in force
/// (NET-074): the default the box now has, and the flags that declare its
/// reach. `None` under [`sessions::EgressDefaultPhase::Announced`]: the
/// announcement that phase printed (NET-076) is retired with it, and an
/// absent section still allows all there, so there is nothing to note.
///
/// The opt-out half of the scope is the caller's to check: the daemon, not
/// the client, knows whether it set its opt-out (NET-077), so
/// [`activate_session`] reads it off the create reply and stays silent for
/// a box the default does not bind.
pub fn deny_all_default_notice(phase: sessions::EgressDefaultPhase) -> Option<&'static str> {
    match phase {
        sessions::EgressDefaultPhase::Announced => None,
        sessions::EgressDefaultPhase::InForce => Some(
            "egress: deny-all (default for an own-ip box with no egress section); declare \
             reach with the --allow-subnets, --allow-dns-hosts and --allow-protocols flags",
        ),
    }
}

/// The classifier advisory a create reply carries (NET-079), as the line
/// the activation prints: this host's cause in words for why it cannot
/// decide a host-address box's egress verdict per box, the state that
/// leaves the box in, and — when the missing privileged step is the cause —
/// the exact command that installs it. The daemon spelled it, because the
/// daemon is the side that read the host; the start prints it verbatim, so
/// the terminal, the daemon's own log line for the same create, and the
/// start all say the same thing. A reply that carries no advisory — from a
/// host that decides per box, or from a daemon that predates the field —
/// writes nothing: no line to print then, the way the other create-reply
/// facts read.
///
/// A writer over the reply rather than a string out of it, so the render
/// the start drives and the render a test drives are the same code — the
/// test pins the bytes the terminal gets, not an accessor's echo of the
/// field it read. The advisory is never a prompt: it names what a person
/// may run, and running it — and any privilege prompt it carries — is the
/// person's act, never the session start's, so the activation prints it
/// and goes on without waiting for an answer.
pub fn write_classifier_advisory(
    out: &mut impl std::io::Write,
    created: &minimald_rpc::CreateSessionResponse,
) -> std::io::Result<()> {
    if let Some(advisory) = created.classifier_advisory.as_deref() {
        writeln!(out, "{advisory}")?;
    }
    Ok(())
}

/// [`write_classifier_advisory`] as the start drives it: the render over
/// the person's own stderr, best-effort. The advisory qualifies a session
/// the daemon has already created — it never gates one — so a note that
/// cannot print must not fail the activation that carried it: a stderr
/// closed by the person running the start, or a reader gone before the
/// note landed (the broken pipe `min version | head -1` taught this CLI
/// to expect), is the person's pipe to manage, and the write's error is
/// logged and left, never propagated — the activation goes on to the
/// session's work the way it already does for a reply that carries no
/// advisory at all. Logged at `debug`, because a person whose stderr
/// cannot take the note cannot read a louder line about it either.
pub fn print_classifier_advisory(
    out: &mut impl std::io::Write,
    created: &minimald_rpc::CreateSessionResponse,
) {
    if let Err(error) = write_classifier_advisory(out, created) {
        tracing::debug!(%error, "the classifier advisory did not print");
    }
}

/// Render a session's effective policy as its rules: the egress the gate
/// enforces (NET-074/NET-075) — a declared section's dimensions each
/// resolved to its list or its default (`allow-all`; `deny subnets` reads
/// `(none)` when nothing is denied), the declared deny-all section by name
/// (`deny-all` — every list empty would otherwise read as blankness, which
/// is nothing, never a verdict), or, for a box that declared no egress
/// at all, the default its daemon resolved to (`deny-all` once the deny-all
/// default is in force; `allow-all` behind the opt-out or before it),
/// marked as a default and not as a declaration on the row itself —
/// `deny-all (default)`, `allow-all (default)` — so a box the rollout
/// silenced and a box that declared the same verdict never read the same;
/// the declared deny-all row carries no mark, because the box chose it.
/// Both spell with the requirement's own hyphenated tokens. The egress
/// rows carry NET-079's per-box enforcement when the daemon
/// reported one: a host-address box's verdict is decided on the host's
/// cgroup tree, so the egress block that says what the box may reach also
/// says whether this host can decide that per box — `none` beside a
/// declaration that then describes the box's posture, not its fact: the
/// state the box actually runs in. An own-address box, a none box, and a
/// reply that carries no state say nothing there — the row a render prints
/// from silence would be the decided-looking one a daemon that predates
/// the fact never sent — the
/// node-plane baseline set the helper enumerates beside it (NET-130: the
/// categories the in-VM daemon's own registry and cache fetches are to
/// reach, one row a category's subnets, headed by the posture the
/// host-side gate decides those fetches under — announced, the shipped
/// posture, the run path's allow-all interim node row still decides them
/// and the set binds nothing yet; in force, the set decides them whatever
/// the box's own declaration resolves to, so it is what a deny-all box
/// reads beside), and the ingress mappings spelled out.
/// `network` is the session's network mode. `host_ip_enforcement` is the
/// per-box egress state the daemon's runtime-facts reply carried (NET-079):
/// the box's own launch record lowered by the host's current fact, spelled
/// in the machine's own words (`per_box`/`none`, the same spellings the
/// record, the listing, and the daemon's log line carry), never an invented
/// prose of its own. `None` — a session that is not host-address, or a
/// daemon that predates the reply — prints no row at all. `fabric` is the
/// switch plan the
/// session's own-address surface leaves its frames on — the plan the
/// host-side helper builds this enumeration from, named where the CLI knows
/// it: the microVM backend's run path builds its registry and this set from
/// the default plan, so the command passes that. A backend with no helper
/// beside its switch — the native daemon's own per-daemon switch, whose
/// plan the reply does not carry and which has no host-side gate the set
/// would describe — passes `None`, and the block is omitted there rather
/// than printed from a plan the session does not attach to. The modes
/// without a surface to describe are held to the TUI's detail pane: a none
/// box has no network at all, so it prints the pane's one-line note in
/// place of both blocks (`allow-all` egress would claim a reach a box with
/// no network does not have), and a host-address session shares its host's
/// namespace, so it has no per-session ingress policy — the block is
/// omitted entirely, and with it the baseline set, which is a
/// switch-fabric surface and has nothing to describe there either.
/// Shared by `min session policy`'s printer and the integration
/// tests that pin the rendering (NET-061, NET-075).
pub fn format_policy(
    out: &mut impl std::io::Write,
    effective: &sessions::EffectiveSessionPolicy,
    network: sessions::NetworkMode,
    host_ip_enforcement: Option<sessions::HostIpEnforcement>,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
    fabric: Option<switch::SwitchSubnet>,
) -> Result<(), anyhow::Error> {
    // A none box has no network, so it can carry no egress or ingress
    // declaration at all — nothing the blocks print would describe anything
    // real (the same case the TUI's detail pane replaces with this note).
    if network == sessions::NetworkMode::NoNet {
        writeln!(out, "No network policy (NoNet)")?;
        // A lane the box declared is still shown, marked as not in effect:
        // the view states what was declared (NET-134).
        if effective.credentialed_upstream.is_some() {
            writeln!(
                out,
                "  {}",
                sessions::CredentialedUpstream::policy_row(network)
            )?;
        }
        return Ok(());
    }
    writeln!(out, "egress")?;
    if let Some(label) = effective.egress.summary_label() {
        // A verdict by name rather than as rows: the defaults marked as
        // defaults, and the declared deny-all section unmarked — every list
        // empty would render as blankness, which reads as nothing, the one
        // rendering this block must never print (NET-075's "never
        // nothing"). The mark is the difference between a verdict the box
        // chose and the one the rollout chose for it, and the JSON document
        // carries the same distinction as `source`. The label is the
        // `sessions` crate's, shared with the TUI's detail pane.
        writeln!(out, "  {label}")?;
    } else if let sessions::EffectiveEgress::Declared(egress) = &effective.egress {
        write_rules(out, "subnets", egress.allow_subnets.as_ref(), "allow-all")?;
        write_rules(
            out,
            "dns hosts",
            egress.allow_dns_hosts.as_ref(),
            "allow-all",
        )?;
        match &egress.allow_protocols {
            None => writeln!(out, "  protocols  allow-all")?,
            Some(protos) => writeln!(
                out,
                "  protocols  {}",
                protos
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )?,
        }
        write_rules(out, "deny subnets", egress.deny_subnets.as_ref(), "(none)")?;
    }
    // NET-079's per-box enforcement, as the egress block's closing row: a
    // host-address box's verdict is decided on the host's cgroup tree, so
    // this is the row that says whether the rules above are decided per box
    // at all — and a `deny-all` printed beside an enforcement of `none` is
    // the honest rendering, the posture the box declared beside the state it
    // actually runs in, rather than a verdict that looks decided and is not.
    // The value is the runtime-facts reply's, in the machine spelling: the
    // row a person reads here names the same fact the record's
    // `host_ip_enforcement` field and the daemon's log line carry, so the
    // three surfaces agree by construction. Printed only when the daemon
    // reported a state — `None`, for a session that is not host-address, or
    // from a daemon too old to answer the facts reply, prints nothing
    // rather than a row silence never carried.
    if let Some(enforcement) = host_ip_enforcement {
        writeln!(out, "  per-box enforcement  {}", enforcement.machine_str())?;
    }
    // The credentialed-upstream lane (NET-134), as the egress block's last
    // declared row: a laned box's frames to the box egress proxy's
    // listener are admitted on the credential the proxy itself checks —
    // the one destination the rows above never decide — so the row states
    // the lane beside rules that do not bound it, and names the listener
    // as the lane's whole reach: everything else to the proxy's address
    // stays refused. Printed only when the policy carries the lane;
    // `None`, the declaration every policy without one holds, is no lane,
    // and a row for it would claim one — silence says the box runs without
    // the credential, under its egress rules alone. The lane is admitted at
    // the switch's gate, which only own-address boxes sit behind, but a
    // declaration in another mode is still shown: the row carries a
    // `(not in effect: <mode> box)` mark there rather than hiding what the
    // box declared. The text is shared with the `min dash` detail pane.
    if effective.credentialed_upstream.is_some() {
        writeln!(
            out,
            "  {}",
            sessions::CredentialedUpstream::policy_row(network)
        )?;
    }
    // The node-plane baseline set, beside the box's rules (NET-130): the
    // helper's built-in enumeration of the categories the in-VM daemon's own
    // traffic may reach, one row per category under its name. A
    // switch-fabric surface, so it is the own-address modes that carry it —
    // and only where a fabric the helper gates is named: the enumeration is
    // built the way the host-side gate builds it, from the fabric's own
    // address plan, and no fabric named means no set to show. The posture
    // the gate decides the daemon's own fetches under is spelled beside the
    // set, the way the daemon's start-up line spells it: announced — the
    // shipped posture — the run path's allow-all interim node row still
    // decides those fetches, so the rows name what the set will bound, not
    // what bounds them today.
    if network == sessions::NetworkMode::OwnIp
        && let Some(fabric) = fabric
    {
        let baseline = minvmd::net::NodePlaneBaseline::built_in(fabric);
        writeln!(
            out,
            "node-plane baseline set (helper enumeration) — {}",
            baseline.phase().as_str()
        )?;
        for entry in baseline.entries() {
            writeln!(
                out,
                "  {}  {}",
                entry.category().as_str(),
                entry.endpoints().join(", ")
            )?;
        }
    }
    // Ingress is an own-address surface: the switch's static forwarder is the
    // only per-session ingress minimald applies, and a host-address box
    // shares its host's namespace, so there is no per-session ingress policy
    // to show for it — "deny-all" there would claim a deny-rule exists.
    if network != sessions::NetworkMode::HostNet {
        writeln!(out, "ingress")?;
        // The dynamic row is the resolved stance, printed whether or not
        // anything was declared (NET-043): an absent setting is the deny the
        // policy module evaluates it as, and this render is where a person
        // reads which stance a box runs under — silence would read as
        // "unset" where there is no unset, only deny. The static half
        // keeps its own deny-all line: it describes the declared mappings,
        // not the dynamic stance. An absent setting carries the `(default)`
        // mark the egress row uses, so it never reads as an explicit deny.
        let dynamic_ingress = match effective
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_ingress)
        {
            Some(mode) => mode.to_string(),
            None => format!("{} (default)", sessions::DynamicIngress::Deny),
        };
        let dynamic_range = effective
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_allowed_range);
        match &effective.ingress {
            None => writeln!(out, "  deny-all")?,
            Some(ingress) => {
                if ingress.port_mappings.is_empty()
                    && ingress.dynamic_allowed_range.is_none()
                    && ingress.dynamic_ingress.is_none()
                {
                    writeln!(out, "  deny-all")?;
                }
                for mapping in &ingress.port_mappings {
                    // NET-129: a declared port another box at the same shared
                    // loopback address holds is served by that box — this
                    // box's attach yielded the forward (first-come) — so the
                    // row says whose it is rather than reading as this box's
                    // own. Every other declared row prints as before; an
                    // empty list, or one a client too old to fetch could not
                    // pass, marks nothing.
                    let held_by = shared_port_collisions
                        .iter()
                        .find(|c| c.port == mapping.external_port)
                        .map(|c| format!(" (held by {})", c.held_by));
                    match held_by {
                        Some(mark) => writeln!(
                            out,
                            "  {}  :{} → :{}{}",
                            mapping.proto, mapping.external_port, mapping.internal_port, mark
                        )?,
                        None => writeln!(
                            out,
                            "  {}  :{} → :{}",
                            mapping.proto, mapping.external_port, mapping.internal_port
                        )?,
                    }
                }
            }
        }
        if let Some((lo, hi)) = dynamic_range {
            writeln!(out, "  dynamic ports  {lo}–{hi}")?;
        }
        writeln!(out, "  dynamic ingress  {dynamic_ingress}")?;
    }
    Ok(())
}

/// The ports the box published at runtime, listed beside the declaration
/// (NET-044): one row a publish — the address its forward is bound on, and
/// the in-box port it forwards to — shaped like the declared mapping rows
/// above it, so the two read as one surface: what the box declared, and what
/// it went on to publish. A current daemon admits every runtime publish at
/// the box's relay gate as it binds it (NET-044), so its rows carry no
/// caveat. A row marked pending comes only from an older daemon whose gate
/// did not admit runtime publishes, and says so rather than reading as
/// reachable. A row from a daemon older than the `pending` field — one that
/// could not classify the port either way — says *unknown* and why, never
/// the reachable reading a missing state must not default itself into. A
/// box that published nothing prints no section: an empty header would
/// claim a distinction between "nothing published" and "nothing
/// publishable" the listing has no way to draw — the declaration above
/// already says what is permitted, and silence says the box used none of it.
///
/// Shared by `min session policy`'s printer and the tests that pin the
/// rendering, the way [`format_policy`] is.
pub fn write_live_ingress(
    out: &mut impl std::io::Write,
    live: &[minimald_rpc::LiveMapping],
) -> Result<(), anyhow::Error> {
    if live.is_empty() {
        return Ok(());
    }
    writeln!(out, "live ingress (published at runtime)")?;
    for mapping in live {
        let reachability = match mapping.pending {
            Some(true) => "  (pending; not yet reachable)",
            Some(false) => "",
            // A reply from a daemon that predates the field: the state is
            // unknown, not reachable — the row says both.
            None => "  (unknown; daemon predates this field)",
        };
        writeln!(
            out,
            "  {}  {} → :{}{}",
            mapping.proto, mapping.local, mapping.internal_port, reachability
        )?;
    }
    Ok(())
}

/// The warnings `min session policy` prints for the permitted listening
/// ports the daemon left unpublished because their audit record could not
/// be written (NET-046 fails closed): a listen-publish is driven by the
/// box's own listener, with no caller to answer, so this line is where the
/// failure reaches the user. One line per port; nothing when the list is
/// empty.
pub fn write_unaudited_listen_ports(
    out: &mut impl std::io::Write,
    ports: &[u16],
    audit_log: Option<&str>,
) -> Result<(), anyhow::Error> {
    let audit_log = audit_log.map_or_else(
        || "the audit log".to_string(),
        |path| format!("the audit log {path}"),
    );
    for port in ports {
        writeln!(
            out,
            "warning: port {port} is permitted but not published: {audit_log} cannot be written"
        )?;
    }
    Ok(())
}

/// The schema string of the document `min session policy -o json` writes:
/// the stamp a client checks before it reads anything else, held as a
/// constant so the renderer and the tests that pin the document cite one
/// spelling. The failure's object carries its own stamp (`min/v1/error`),
/// held beside the emitter that writes it, in `main`.
pub const POLICY_JSON_SCHEMA: &str = "min/v1/session-policy";

/// The ingress block as the document carries it: the declared policy, or
/// `deny_all` where the text rendering writes that reading — the same
/// decision its "deny-all" line makes, so the document never claims rules
/// the box never declared. Tagged by `kind` so a client branches on one
/// field, with the declared policy's own keys flattened beside it. The
/// `dynamic_ingress` key is the resolved stance in both variants (NET-043):
/// the deny an absent setting evaluates as, never a null a parser would
/// have to default itself — the document and the text rendering answer
/// "which stance does this box run under" identically.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyIngressJson<'a> {
    /// Nothing is set, and the switch's default state is the deny: a claim
    /// about the switch, not about declared rules.
    DenyAll {
        /// The dynamic stance the box runs under, resolved — deny, the
        /// evaluation an absent setting takes (NET-043).
        dynamic_ingress: sessions::DynamicIngress,
        /// Always `default` here: a box that declared a stance is
        /// `declared`, whatever the stance.
        dynamic_ingress_source: &'static str,
    },
    /// The declared policy, carried as the wire's own shape.
    Declared(PolicyDeclaredIngressJson<'a>),
}

impl<'a> PolicyIngressJson<'a> {
    /// The document's form of the block [`format_policy`] prints: the same
    /// empty→deny-all reading, so a box that declared nothing does not read
    /// as carrying an empty declaration beside a box that denied everything
    /// on purpose.
    fn from_effective(policy: Option<&'a sessions::IngressPolicy>) -> Self {
        match policy {
            None => Self::DenyAll {
                dynamic_ingress: sessions::DynamicIngress::Deny,
                dynamic_ingress_source: "default",
            },
            Some(ingress)
                if ingress.port_mappings.is_empty()
                    && ingress.dynamic_allowed_range.is_none()
                    && ingress.dynamic_ingress.is_none() =>
            {
                Self::DenyAll {
                    dynamic_ingress: sessions::DynamicIngress::Deny,
                    dynamic_ingress_source: "default",
                }
            }
            Some(ingress) => Self::Declared(PolicyDeclaredIngressJson {
                port_mappings: &ingress.port_mappings,
                dynamic_allowed_range: ingress.dynamic_allowed_range,
                dynamic_ingress: ingress
                    .dynamic_ingress
                    .unwrap_or(sessions::DynamicIngress::Deny),
                dynamic_ingress_source: if ingress.dynamic_ingress.is_some() {
                    "declared"
                } else {
                    "default"
                },
            }),
        }
    }
}

/// The declared policy as the document carries it: the wire's own keys,
/// with `dynamic_ingress` resolved to the stance the box runs under rather
/// than the raw `None` the record stores.
#[derive(serde::Serialize)]
struct PolicyDeclaredIngressJson<'a> {
    port_mappings: &'a [sessions::PortMapping],
    dynamic_allowed_range: Option<(u16, u16)>,
    dynamic_ingress: sessions::DynamicIngress,
    /// `declared` when the box set a stance, `default` when the resolved
    /// deny is the absent setting's — the text rendering's `(default)` mark,
    /// as a field, the way the egress block's `source` carries it.
    dynamic_ingress_source: &'static str,
}

/// The egress block as the document carries it: the posture the gate
/// enforces, by the name the text rendering prints (`deny-all`,
/// `allow-all`), and which of the two ways it came about — `default`, the
/// rollout's resolution of a section the box never declared (NET-074), or
/// `declared`, the box's own section (NET-075) — so a consumer reading the
/// document never recomputes the default rule to tell a declared deny-all
/// from the default's identical verdict: the mark the text rendering puts
/// on the row, as a field. A declaration that admits something has no
/// single name, so its rows ride under `rules` with
/// `effective: "rules"` — the same lists the text rendering prints as its
/// dimension rows.
#[derive(serde::Serialize)]
struct PolicyEgressJson<'a> {
    /// The posture's name: `deny-all` or `allow-all` when the verdict has
    /// one, `rules` when the declaration's own rows say it.
    effective: &'static str,
    /// `default` for the rollout's resolution of an absent section,
    /// `declared` for the box's own.
    source: &'static str,
    /// The declared section, carried exactly when the box declared one —
    /// the shape the strict record holds, empty lists and all, so a
    /// declared deny-all is reconstructable from the document alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<&'a sessions::EgressPolicy>,
}

impl<'a> PolicyEgressJson<'a> {
    /// The document's form of the block [`format_policy`] prints: the same
    /// named verdicts, the same declaration-versus-default distinction the
    /// `(default)` mark carries, so the text and the document say one
    /// thing about a box's egress.
    fn from_effective(egress: &'a sessions::EffectiveEgress) -> Self {
        match egress {
            sessions::EffectiveEgress::DenyAll => Self {
                effective: "deny-all",
                source: "default",
                rules: None,
            },
            sessions::EffectiveEgress::AllowAll => Self {
                effective: "allow-all",
                source: "default",
                rules: None,
            },
            // The declared deny-all section keeps its name — the four
            // present-and-empty lists it would print as blankness — and its
            // `rules` ride beside the name the way every declaration's do.
            sessions::EffectiveEgress::Declared(section) => Self {
                effective: if section.admits_nothing() {
                    "deny-all"
                } else {
                    "rules"
                },
                source: "declared",
                rules: Some(section),
            },
        }
    }
}

/// The node-plane baseline set the helper enumerates (NET-130), as the
/// document carries it: owned rows, because the enumeration is built inside
/// the render and the wire has no shape for it. The text rendering prints
/// the same rows, so the two list the same set.
#[derive(serde::Serialize)]
struct PolicyBaselineJson {
    phase: &'static str,
    entries: Vec<PolicyBaselineEntryJson>,
}

/// One category row of the baseline set.
#[derive(serde::Serialize)]
struct PolicyBaselineEntryJson {
    category: &'static str,
    endpoints: Vec<String>,
}

/// One `min/v1/session-policy` document: the effective policy's parts, each
/// named as a parser reads them. The blocks the text rendering prints carry
/// over as keys, and the ones it suppresses are left out entirely rather
/// than nulled, so a key's absence is itself the claim (a host-address box
/// shares its host's namespace and has no per-session ingress; a none box
/// has no policy at all) — [`format_policy`]'s shape decisions restated for
/// a machine.
///
/// The live mappings ride as the wire's own rows, `pending` included, since
/// carrying that state is half of what the mode is for: a published port
/// the relay gate has not admitted yet must not read as reachable to
/// something parsing this.
#[derive(serde::Serialize)]
struct PolicyJson<'a> {
    schema: &'static str,
    network: sessions::NetworkMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<PolicyEgressJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingress: Option<PolicyIngressJson<'a>>,
    /// The credentialed-upstream lane (NET-134), carried only when the
    /// policy declares one — the same gate as the text rendering's row,
    /// restated for a machine: a box without the lane has no key, so a
    /// client cannot mistake an absent lane for a null one.
    #[serde(skip_serializing_if = "Option::is_none")]
    credentialed_upstream: Option<PolicyCredentialedUpstreamJson<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_plane_baseline: Option<PolicyBaselineJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_ingress: Option<LiveIngressJson>,
    /// The permitted listening ports the daemon left unpublished because
    /// their audit record could not be written (NET-046) — the text
    /// rendering's warning lines, for a machine. Absent when there are none.
    #[serde(skip_serializing_if = "<[u16]>::is_empty")]
    unaudited_listen_ports: &'a [u16],
    /// NET-129: the declared ports this box yields because another box at
    /// the same shared loopback address holds them, as the wire's own rows
    /// (`port`, and the holding box as `held_by`) — the text rendering's
    /// "(held by …)" marks. Omitted when empty, the reading a daemon that
    /// predates the fact, or a facts fetch that failed, also leaves.
    #[serde(skip_serializing_if = "no_shared_port_collisions")]
    shared_port_collisions: &'a [minimald_rpc::SharedPortCollision],
}

/// Serde helper: leave [`PolicyJson::shared_port_collisions`] out when empty.
fn no_shared_port_collisions(rows: &&[minimald_rpc::SharedPortCollision]) -> bool {
    rows.is_empty()
}

/// A declared credentialed-upstream lane as the document carries it: the
/// declaration as declared, plus `effective`, whether the box's network
/// mode admits the lane (own-address only) — the machine form of the text
/// row's `(not in effect: …)` mark.
#[derive(serde::Serialize)]
struct PolicyCredentialedUpstreamJson<'a> {
    #[serde(flatten)]
    lane: &'a sessions::CredentialedUpstream,
    effective: bool,
}

impl<'a> PolicyCredentialedUpstreamJson<'a> {
    fn from_effective(
        effective: &'a sessions::EffectiveSessionPolicy,
        network: sessions::NetworkMode,
    ) -> Option<Self> {
        effective.credentialed_upstream.as_ref().map(|lane| Self {
            lane,
            effective: sessions::CredentialedUpstream::in_effect(network),
        })
    }
}

/// The live rows as the document carries them — the two states a client
/// must be able to tell apart, because each says a different thing about
/// the box: the rows the wire served, `pending` included — an empty list
/// is a claim about the box, that it published nothing — or `null`, the
/// view the daemon could not serve, which is no claim at all: the box may
/// have published anything, so an unavailability must never read as a
/// publish count of zero. (The third state is the key's absence, which
/// [`write_policy_json`] decides from the mode: a box with no network has
/// no live-ingress surface.)
#[derive(serde::Serialize)]
#[serde(untagged)]
enum LiveIngressJson {
    /// The daemon could not serve the view — an older build without the
    /// subsystem, a session mid-teardown. The same `null` a pre-field
    /// `pending` row reads as: unknown, never empty.
    Unavailable,
    /// The rows the wire served.
    Rows(Vec<minimald_rpc::LiveMapping>),
}

/// The document renderer `min session policy -o json` goes through — the
/// JSON-side counterpart of [`format_policy`], taking the same inputs the
/// command walks for so the two renderings describe the same policy: the
/// live rows arrive as the fetch's own result, served or failed, because
/// which of the two it was is part of what the document says. Shared with
/// the tests that pin the document, the way [`format_policy`] is.
pub fn write_policy_json(
    out: &mut impl std::io::Write,
    effective: &sessions::EffectiveSessionPolicy,
    network: sessions::NetworkMode,
    fabric: Option<switch::SwitchSubnet>,
    live: Result<Vec<minimald_rpc::LiveMapping>, String>,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
) -> Result<(), anyhow::Error> {
    write_policy_json_noting(
        out,
        effective,
        network,
        fabric,
        live,
        shared_port_collisions,
        &[],
    )
}

/// [`write_policy_json`], with the permitted listening ports the daemon left
/// unpublished because their audit record could not be written (NET-046)
/// carried as `unaudited_listen_ports` — the key a machine reads the
/// fail-closed listen-publish from, the way a person reads the text
/// rendering's warning lines.
pub fn write_policy_json_noting(
    out: &mut impl std::io::Write,
    effective: &sessions::EffectiveSessionPolicy,
    network: sessions::NetworkMode,
    fabric: Option<switch::SwitchSubnet>,
    live: Result<Vec<minimald_rpc::LiveMapping>, String>,
    shared_port_collisions: &[minimald_rpc::SharedPortCollision],
    unaudited_listen_ports: &[u16],
) -> Result<(), anyhow::Error> {
    // A none box has no policy to describe; the text rendering's one-line
    // note is prose for a person, so the document carries the schema, the
    // mode, and a declared lane (marked not in effect) alone, and every
    // other key's absence says why.
    let document = if network == sessions::NetworkMode::NoNet {
        PolicyJson {
            schema: POLICY_JSON_SCHEMA,
            network,
            egress: None,
            ingress: None,
            // A declared lane is still carried, marked not in effect.
            credentialed_upstream: PolicyCredentialedUpstreamJson::from_effective(
                effective, network,
            ),
            node_plane_baseline: None,
            live_ingress: None,
            unaudited_listen_ports: &[],
            shared_port_collisions: &[],
        }
    } else {
        // The baseline set is a switch-fabric surface, held to the same
        // gate as the text rendering's block: own-address modes, and a
        // fabric the helper gates named (NET-130).
        let node_plane_baseline = if network == sessions::NetworkMode::OwnIp
            && let Some(fabric) = fabric
        {
            let baseline = minvmd::net::NodePlaneBaseline::built_in(fabric);
            Some(PolicyBaselineJson {
                phase: baseline.phase().as_str(),
                entries: baseline
                    .entries()
                    .iter()
                    .map(|entry| PolicyBaselineEntryJson {
                        category: entry.category().as_str(),
                        endpoints: entry.endpoints().to_vec(),
                    })
                    .collect(),
            })
        } else {
            None
        };
        PolicyJson {
            schema: POLICY_JSON_SCHEMA,
            network,
            egress: Some(PolicyEgressJson::from_effective(&effective.egress)),
            // Ingress is an own-address surface — the text rendering's gate:
            // a host-address box shares its host's namespace, so a key there
            // would claim a per-session policy that does not exist.
            ingress: (network != sessions::NetworkMode::HostNet)
                .then(|| PolicyIngressJson::from_effective(effective.ingress.as_ref())),
            // The lane rides the document the way the text rendering prints
            // it: only when declared, so the key's absence is the no-lane
            // claim. Carried in every mode; `effective` says whether this
            // mode admits it, since the switch is the only place it is.
            credentialed_upstream: PolicyCredentialedUpstreamJson::from_effective(
                effective, network,
            ),
            node_plane_baseline,
            // The wire's own rows, `pending` included — an empty list is a
            // claim about the box (it published nothing), which is what the
            // key is for; the modes without a surface leave it out instead.
            // A fetch that failed is neither of those, so it must not
            // collapse into the first: the box may have published anything,
            // and the run cannot warn about it in prose either (a `-o
            // json` run's stderr is the error object's alone), so the
            // document says the state itself — `null`, the unknown — and
            // the why goes nowhere.
            live_ingress: Some(match live {
                Ok(rows) => LiveIngressJson::Rows(rows),
                Err(_) => LiveIngressJson::Unavailable,
            }),
            unaudited_listen_ports,
            // Ingress's own gate: a host-address box has no per-session
            // ingress, so it yields nothing a key could claim.
            shared_port_collisions: if network == sessions::NetworkMode::HostNet {
                &[]
            } else {
                shared_port_collisions
            },
        }
    };
    let encoded =
        serde_json_lenient::to_string(&document).context("encoding the session-policy document")?;
    writeln!(out, "{encoded}").context("writing the session-policy document")?;
    Ok(())
}

/// Why a `-o json` walk failed, tagged where the kinds can be told apart —
/// the tag carries this walk's own knowledge: the `code` the failure answers
/// with (the architecture's names, so a script branches on one vocabulary
/// across every machine-output command) and the hint naming the remedy, or
/// the kind of thing that was missing.
enum PolicyJsonFailure {
    /// No daemon to ask: the autospawn, the connection, or an RPC the daemon
    /// never answered.
    DaemonUnreachable(String),
    /// The daemon answered, but nothing matches the selector.
    SessionNotFound(String),
    /// The session resolved, but its effective policy could not be read.
    PolicyUnavailable(String),
}

impl PolicyJsonFailure {
    /// The failure as the machine-mode error object carries it — the
    /// generic payload every `-o json` command fails into (see
    /// [`MachineModeFailure`]), this walk's kinds mapped onto it.
    fn machine_failure(&self) -> MachineModeFailure {
        match self {
            Self::DaemonUnreachable(message) => MachineModeFailure::new(
                "daemon_unreachable",
                message.clone(),
                "the daemon may be down or mid-restart; try again, and check \
                 that --minimal-dir and --vm name the instance you meant"
                    .to_string(),
            ),
            // The architecture's code for a missing thing, with the kind —
            // a session — in the message (from the shared resolver, which
            // already names it) and in the hint beside it.
            Self::SessionNotFound(message) => MachineModeFailure::new(
                "not_found",
                message.clone(),
                "no session by that name or id exists; `min ls` lists the \
                 sessions there are"
                    .to_string(),
            ),
            Self::PolicyUnavailable(message) => MachineModeFailure::new(
                "policy_unavailable",
                message.clone(),
                "the session resolved but its effective policy could not be \
                 read — the daemon may be mid-restart; try again"
                    .to_string(),
            ),
        }
    }
}

/// The live-ingress fetch itself: the ports the box published at runtime
/// (NET-044) — the rows that make a `min net expose` visible rather than
/// only permitted — as the wire served them, or the failure as its
/// message. Built through `SessionLookup::parse` rather than a conversion
/// so the request types stay the rpc crate's, where the wire contract
/// lives.
///
/// A view of live state, not a fact the listing stands on, so both walks
/// degrade rather than fail — and the failure comes back rather than being
/// printed here, because the two renderings degrade differently and only
/// one of them may say it in prose: the text walk warns on stderr
/// ([`fetch_live_ingress_degrading`]), while a `-o json` run's stderr is
/// the error object's alone, so its document says the view is unknown
/// instead (see [`write_policy_json`]) — an unavailability must never read
/// as a claim that the box published nothing.
async fn fetch_live_ingress(
    client: &mut client::Client,
    session: &str,
) -> Result<Vec<minimald_rpc::LiveMapping>, String> {
    let live_lookup = match SessionLookup::parse(session) {
        SessionLookup::Id(id) => minimald_rpc::GetLiveIngressRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetLiveIngressRequest::Name(n),
    };
    match client
        .oneshot_rpc::<minimald_rpc::GetLiveIngress>(live_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(live)) => Ok(live),
        Ok(minimald_rpc::Errorable::Err { error }) => {
            Err(format!("live port mappings are unavailable: {error}"))
        }
        Err(error) => Err(format!("live port mappings are unavailable: {error:#}")),
    }
}

/// The text walk's degrade of [`fetch_live_ingress`]: against a daemon
/// that cannot serve the rows — an older build without the subsystem, a
/// session mid-teardown — the declaration still renders, with a warning
/// that the live rows are unavailable rather than a claim that nothing is
/// published. Prose for a person, so stderr is where it goes, and this is
/// the one rendering that may put it there.
async fn fetch_live_ingress_degrading(
    client: &mut client::Client,
    session: &str,
) -> Vec<minimald_rpc::LiveMapping> {
    fetch_live_ingress(client, session)
        .await
        .unwrap_or_else(|warning| {
            eprintln!("warning: {warning}");
            Vec::new()
        })
}

/// The walk behind the JSON rendering: the same three steps as the text
/// walk — resolve the record, read the effective policy, list the live
/// mappings — with each failure tagged where the kinds can be told apart,
/// since the error document's `code` is a contract. The live fetch comes
/// back as its own result rather than degraded here, because the two
/// renderings degrade differently (see [`fetch_live_ingress`]): the
/// document says the unknown itself, so nothing is printed for it on a
/// stderr the error object has alone.
async fn session_policy_json_inputs(
    global: &GlobalArgs,
    session: &str,
) -> Result<
    (
        sessions::Record,
        sessions::EffectiveSessionPolicy,
        Result<Vec<minimald_rpc::LiveMapping>, String>,
        Vec<u16>,
        Vec<minimald_rpc::SharedPortCollision>,
    ),
    PolicyJsonFailure,
> {
    ensure_daemon(global)
        .map_err(|error| PolicyJsonFailure::DaemonUnreachable(format!("{error:#}")))?;
    let mut client = connect_daemon(global)
        .await
        .map_err(|error| PolicyJsonFailure::DaemonUnreachable(format!("{error:#}")))?;

    // The record the ingress key is gated on, resolved through the same
    // lookup the text walk uses, with the failure kinds told apart where
    // they can be: an RPC the daemon never answered is no daemon to ask;
    // a lookup that answered with nothing is the not-found itself.
    let resp = get_session_record(&mut client, session)
        .await
        .map_err(|error| match error.downcast_ref::<AmbiguousIdPrefix>() {
            Some(ambiguous) => PolicyJsonFailure::SessionNotFound(ambiguous.to_string()),
            None => PolicyJsonFailure::DaemonUnreachable(format!("{error:#}")),
        })?;
    let record = named_record(resp.record, session)
        .map_err(|error| PolicyJsonFailure::SessionNotFound(error.to_string()))?;
    // By the resolved id, as the text walk does.
    let session = &record.id.to_string();

    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(session) {
        SessionLookup::Id(id) => GetEffectiveSessionPolicyRequest::Id(id),
        SessionLookup::Name(n) => GetEffectiveSessionPolicyRequest::Name(n),
    };
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(lookup)
        .await
        .map_err(|error| PolicyJsonFailure::PolicyUnavailable(format!("{error:#}")))?;

    let live = fetch_live_ingress(&mut client, session).await;
    // The listen publishes the audit log refused (NET-046) and the yielded
    // shared-address ports (NET-129), from the runtime facts the text walk
    // reads them from. Optional facts: a daemon that cannot answer — an older
    // build, a session mid-teardown — leaves both keys out, as a box with
    // nothing to say does.
    let facts_lookup = match SessionLookup::parse(session) {
        SessionLookup::Id(id) => minimald_rpc::GetSessionRuntimeFactsRequest::Id(id),
        SessionLookup::Name(n) => minimald_rpc::GetSessionRuntimeFactsRequest::Name(n),
    };
    let (unaudited_listen_ports, shared_port_collisions) = match client
        .oneshot_rpc::<minimald_rpc::GetSessionRuntimeFacts>(facts_lookup)
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(facts)) => {
            (facts.unaudited_listen_ports, facts.shared_port_collisions)
        }
        Ok(minimald_rpc::Errorable::Err { .. }) | Err(_) => (Vec::new(), Vec::new()),
    };

    match resp {
        minimald_rpc::Errorable::Ok(policy) => Ok((
            record,
            policy,
            live,
            unaudited_listen_ports,
            shared_port_collisions,
        )),
        minimald_rpc::Errorable::Err { error } => {
            Err(PolicyJsonFailure::PolicyUnavailable(error.to_string()))
        }
    }
}

/// The `-o json` rendering: the walk's inputs as one `min/v1/session-policy`
/// document on stdout, or the failure's one `min/v1/error` object on stderr
/// and a non-zero exit — never a document beside a plain-text error line,
/// so a client parses exactly one thing. The walk never writes the object
/// itself: it fails into the generic [`MachineModeFailure`] payload, which
/// `main`'s machine-mode error emitter — keyed on the output mode, shared
/// by every command that takes `-o json` — writes, so the error path is
/// one mechanism rather than a per-command one.
async fn session_policy_as_json(global: &GlobalArgs, session: &str) -> Result<(), anyhow::Error> {
    let (record, policy, live, unaudited_listen_ports, shared_port_collisions) =
        match session_policy_json_inputs(global, session).await {
            Ok(inputs) => inputs,
            Err(failure) => return Err(failure.machine_failure().into()),
        };
    // The fabric the baseline set builds from — keyed the same way the text
    // rendering keys it (see the comment in [`cmd_session_policy`]): the
    // backend this command actually talks to, with no fabric named for the
    // native daemon's per-daemon switch.
    let fabric = (daemon_provider_kind(global) == paths::ProviderKind::Minvmd)
        .then_some(switch::SwitchSubnet::default());
    let mut out = std::io::stdout();
    write_policy_json_noting(
        &mut out,
        &policy,
        record.network,
        fabric,
        live,
        &shared_port_collisions,
        &unaudited_listen_ports,
    )
    .context(OutputWriteError)?;
    out.flush().context(OutputWriteError)?;
    Ok(())
}

/// The normalized form of each subnet flag entry, so the stored policy
/// holds the masked network the enforcement layer reads (`10.0.0.1/8` →
/// `10.0.0.0/8`). Entries that are already normalized, invalid, or IPv6 are
/// kept verbatim: `normalized_cidr` yields `None` for those, and the
/// enforcement layer's own reading of them is unchanged.
fn normalize_subnets(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| sessions::normalized_cidr(entry).unwrap_or_else(|| entry.clone()))
        .collect()
}

/// One egress rule row: the CIDR or hostname list, or the default the policy
/// resolves to when the dimension is unset.
fn write_rules(
    out: &mut impl std::io::Write,
    label: &str,
    rules: Option<&Vec<String>>,
    default: &str,
) -> Result<(), anyhow::Error> {
    match rules {
        None => writeln!(out, "  {label}  {default}")?,
        Some(rules) => writeln!(out, "  {label}  {}", rules.join(", "))?,
    }
    Ok(())
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
        return destroy_all_sessions(global, &mut client, args.force).await;
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

    destroy_session(
        &mut client,
        global,
        record.id,
        record.name.as_deref(),
        record.box_addresses,
    )
    .await
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
    global: &GlobalArgs,
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
        // The record carries the pair the box's registration handed back
        // (T66), which the destroy-side withdrawal presents; a session that
        // registered no box holds none, and the withdrawal stays silent for
        // it. A record the daemon cannot answer destroys the session all the
        // same — nothing is left on this path to withdraw the row by.
        let box_addresses = get_session_record(client, &session.id.to_string())
            .await
            .ok()
            .and_then(|resp| resp.record)
            .and_then(|record| record.box_addresses);
        if let Err(error) = destroy_session(
            client,
            global,
            session.id,
            session.name.as_deref(),
            box_addresses,
        )
        .await
        {
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
    global: &GlobalArgs,
    id: sessions::SessionId,
    name: Option<&str>,
    box_addresses: Option<sessions::BoxAddresses>,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{DestroySession, DestroySessionRequest};

    let resp = client
        .oneshot_rpc::<DestroySession>(DestroySessionRequest { id })
        .await
        .context("DestroySession RPC failed")?;

    if let Some(resp) = resp.ok() {
        println!("Destroyed session {} ({})", id, name.unwrap_or("-"));
        // A failed `on_destroy` hook does not stop the destroy, so it is a
        // warning rather than an error: the session is gone either way.
        for failure in &resp.hook_failures {
            let (head, output) = failure.split_once('\n').unwrap_or((failure, ""));
            eprintln!("warning: on_destroy hook {head}; the session was destroyed anyway");
            if !output.is_empty() {
                eprintln!("{output}");
            }
        }
        // The session is gone; the row its activation bought outlives it on
        // the VM host daemon, and its creator withdraws it here (T66) —
        // presenting the pair the registration handed back. Best-effort: a
        // withdrawal that cannot be made leaves the row published and warns
        // rather than failing a destroy that already succeeded.
        // A box that registered no row held its name in the zone instead
        // (`host_ip`); the same destroy releases it, best-effort the same
        // way.
        let control_sock =
            vm_host_control_sock(daemon_provider_kind(global), global.minimal_dir.as_deref());
        withdraw_box_row(control_sock.clone(), name, box_addresses, None).await;
        release_held_box_name(control_sock, id, name, box_addresses).await;
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
            // A `host_ip` box holds its name in the zone (NODATA) in place
            // of a row: the hold moves with the name, so the old name no box
            // owns answers NXDOMAIN again and the new one is the one the
            // destroy releases.
            if record.network == sessions::NetworkMode::HostNet && record.box_addresses.is_none() {
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
            bail!("RenameSession failed: {error}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::{
        CredentialedUpstream, DynamicIngress, EffectiveEgress, EffectiveSessionPolicy,
        IngressPolicy, IpProto, NetworkMode, PortMapping,
    };

    #[test]
    fn normalize_subnets_masks_host_bits_and_keeps_the_rest() {
        assert_eq!(
            normalize_subnets(&["10.0.0.1/8".to_string(), "192.168.1.5/24".to_string()]),
            vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()]
        );
        assert_eq!(
            normalize_subnets(&[
                "10.0.0.0/8".to_string(),
                "fd00::1/8".to_string(),
                "not-a-cidr".to_string(),
            ]),
            vec![
                "10.0.0.0/8".to_string(),
                "fd00::1/8".to_string(),
                "not-a-cidr".to_string()
            ]
        );
    }

    #[test]
    fn dynamic_ingress_needs_own_ip() {
        use crate::cli::CliNetworkMode::{HostNet, NoNet, OwnIp};
        for network in [HostNet, NoNet] {
            for (mode, range) in [
                (Some(DynamicIngress::Allow), Some((8000, 8443))),
                (Some(DynamicIngress::Deny), None),
                (None, Some((8000, 8443))),
            ] {
                let error = refuse_dynamic_ingress_off_own_ip(network, mode, range)
                    .expect_err("a dynamic declaration off own_ip is refused");
                assert!(
                    error.to_string().contains("need --network own_ip"),
                    "{error}"
                );
            }
            refuse_dynamic_ingress_off_own_ip(network, None, None)
                .expect("no dynamic declaration is never refused");
        }
        refuse_dynamic_ingress_off_own_ip(OwnIp, Some(DynamicIngress::Allow), Some((8000, 8443)))
            .expect("an own-IP box keeps its dynamic declaration");
    }

    #[test]
    fn ingress_needs_own_ip() {
        use crate::cli::CliNetworkMode::{HostNet, NoNet, OwnIp};
        for network in [HostNet, NoNet] {
            refuse_ingress_off_own_ip(network, true)
                .expect_err("an ingress mapping off own_ip is refused");
            refuse_ingress_off_own_ip(network, false).expect("no ingress mapping is never refused");
        }
        refuse_ingress_off_own_ip(OwnIp, true).expect("an own-IP box keeps its ingress mapping");
    }

    /// A host-side ask stand: the real VM host daemon's control server and
    /// guest door over a real registry, in a provider dir the CLI resolves
    /// the control socket in (NET-045).
    struct AskStand {
        _dir: tempfile::TempDir,
        global: GlobalArgs,
        control: std::path::PathBuf,
        guest: std::path::PathBuf,
        registry: minvmd::box_registry::BoxRegistry,
    }

    impl AskStand {
        fn start() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let provider_dir = dir.path().join("providers").join("local-minvmd0");
            std::fs::create_dir_all(&provider_dir).unwrap();
            let control = provider_dir.join("control.sock");
            let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
            let answerer =
                minvmd::net::answerer::AnswererStatus::allocating_for_tests("ask-test-node");
            let _server = minvmd::control::spawn(
                control.clone(),
                registry.clone(),
                answerer.clone(),
                minvmd::control::ProxyPublishStatus::default(),
            )
            .expect("the control server binds its socket");
            let guest = minvmd::control::spawn_guest_reports_door(
                &control,
                registry.clone(),
                answerer,
                minvmd::control::ProxyPublishStatus::default(),
            )
            .expect("the guest door binds its socket");
            let global = GlobalArgs {
                provider: Some(Provider::LocalMinvmd),
                minimal_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            };
            Self {
                _dir: dir,
                global,
                control,
                guest,
                registry,
            }
        }

        /// Register `name` the way the activation does, with `stance` over
        /// 3000-3999.
        async fn register(&self, name: &str, stance: DynamicIngress) -> RegisteredWithVmHost {
            let policy = sessions::SessionPolicy {
                egress: None,
                ingress: Some(IngressPolicy {
                    port_mappings: vec![],
                    dynamic_allowed_range: Some((3000, 3999)),
                    dynamic_ingress: Some(stance),
                }),
                credentialed_upstream: None,
            };
            register_box_for_activation(
                paths::ProviderKind::Minvmd,
                self.global.minimal_dir.as_deref(),
                NetworkMode::OwnIp,
                name,
                &policy,
            )
            .await
            .expect("the real control server answers the registration")
            .expect("an own-address box on a VM-backed host registers")
        }

        /// The guest's ask for `port`, its reply read on a thread.
        fn guest_ask(
            &self,
            web: &RegisteredWithVmHost,
            port: u16,
        ) -> std::sync::mpsc::Receiver<minimald_rpc::BoxControlReply> {
            use std::io::{BufRead as _, Write as _};
            let mut stream = std::os::unix::net::UnixStream::connect(&self.guest).unwrap();
            let mut line = serde_json_lenient::to_string(
                &minimald_rpc::BoxControlRequest::AdmitAsk(minimald_rpc::AdmitAskRequest {
                    switch_address: web.addresses.switch_address,
                    port,
                    proto: sessions::IpProto::Tcp,
                }),
            )
            .unwrap();
            line.push('\n');
            stream.write_all(line.as_bytes()).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stream);
                let mut reply = String::new();
                if reader.read_line(&mut reply).is_ok() && !reply.trim().is_empty() {
                    let _ = tx.send(serde_json_lenient::from_str(reply.trim()).unwrap());
                }
            });
            rx
        }
    }

    /// The relay as the ask loop sees it: every suspend and resume, in
    /// order, reported on a channel.
    struct RecordingTerminal(std::sync::mpsc::Sender<&'static str>);

    impl minimal_client::attach::AskTerminal for RecordingTerminal {
        fn suspend_for_ask(&self) -> Result<(), anyhow::Error> {
            let _ = self.0.send("suspend");
            Ok(())
        }

        fn resume_after_ask(&self) {
            let _ = self.0.send("resume");
        }

        fn ask_cancelled(&self) -> bool {
            false
        }
    }

    /// Serve `asks` on a thread with `dialog`, reporting the terminal's
    /// suspend and resume, and the offer each dialog was built from.
    fn serve_asks(
        asks: minimal_client::attach::HostAsks,
        dialog: fn(&minimald_rpc::PendingAskOffer) -> minimald_rpc::AskAnswer,
    ) -> (
        std::sync::mpsc::Receiver<&'static str>,
        std::sync::mpsc::Receiver<minimald_rpc::PendingAskOffer>,
    ) {
        let (events, events_rx) = std::sync::mpsc::channel();
        let (offers, offers_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            asks.serve(&RecordingTerminal(events), |offer, _| {
                let _ = offers.send(offer.clone());
                minimal_client::ask_dialog::AskDialogEnd::Answered(dialog(offer))
            });
        });
        (events_rx, offers_rx)
    }

    const ASK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

    /// An ask create stands on a VM-backed host (NET-045): T94's refusal is
    /// gone, and the registration hands the host row the ask stance — as it
    /// does allow and deny — so the host holds the stance the human is
    /// asked under.
    #[tokio::test]
    async fn vm_backed_dynamic_ask_create_accepted() {
        let stand = AskStand::start();
        for (name, stance) in [
            ("asker", DynamicIngress::Ask),
            ("allower", DynamicIngress::Allow),
            ("denier", DynamicIngress::Deny),
        ] {
            let _held = stand.register(name, stance).await;
            let row = stand
                .registry
                .row_by_name(name)
                .expect("the registration published the row");
            assert_eq!(
                row.dynamic_ingress(),
                stance,
                "{name}'s row holds its stance"
            );
            assert_eq!(row.dynamic_range(), Some((3000, 3999)));
        }
        refuse_dynamic_ingress_off_own_ip(
            crate::cli::CliNetworkMode::OwnIp,
            Some(DynamicIngress::Ask),
            Some((3000, 3999)),
        )
        .expect("an own-IP ask create is not refused");
        assert_eq!(
            minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE,
            minvmd::control::CONTROL_SOCK_FILE,
            "the dash finds the control socket the VM host daemon binds"
        );
    }

    /// The attached client renders the offer the host pushed — built from
    /// the host row — suspends the relay for it, records the yes through
    /// the host door, and resumes; the guest's held ask is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_records_ask_yes_through_host_door() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let asks = tokio::task::spawn_blocking({
            let control = stand.control.clone();
            move || minimal_client::attach::HostAsks::subscribe(&control, "web")
        })
        .await
        .unwrap()
        .expect("the attach subscribes by the row's box id");
        let (events, offers) = serve_asks(asks, |_| minimald_rpc::AskAnswer::Yes);

        let reply = stand.guest_ask(&web, 3000);
        let offer = offers.recv_timeout(ASK_WAIT).expect("the dialog is shown");
        assert_eq!(offer.name, "web");
        assert_eq!(Some(offer.box_id), web.box_id);
        assert_eq!(
            minimal_client::ask_dialog::ask_dialog_lead_in(&offer),
            "web asks to publish port 3000/tcp."
        );
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(
            matches!(
                outcome,
                minimald_rpc::AskAdmitOutcome::Admitted { port: 3000, .. }
            ),
            "the recorded yes admits the ask: {outcome:?}"
        );
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "resume");
        let row = stand.registry.row_by_name("web").unwrap();
        assert_eq!(row.runtime_port_numbers(), vec![3000]);
    }

    /// Two attaches are offered one ask; the first records a no while the
    /// second's dialog is still up. The second's late yes is told the ask
    /// was already denied, and admits nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_attach_answer_admits_nothing() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let subscribe = || {
            let control = stand.control.clone();
            tokio::task::spawn_blocking(move || {
                minimal_client::attach::HostAsks::subscribe(&control, "web")
            })
        };
        let first = subscribe()
            .await
            .unwrap()
            .expect("the first attach subscribes");
        let second = subscribe()
            .await
            .unwrap()
            .expect("the second attach subscribes");
        // The second dialog is up before the first answers, and answers
        // only once the first's no is recorded.
        let (shown, shown_rx) = std::sync::mpsc::channel::<()>();
        let (first_done, first_done_rx) = std::sync::mpsc::channel::<()>();
        let (first_offers, first_offers_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (events, _) = std::sync::mpsc::channel();
            first.serve(&RecordingTerminal(events), |offer, _| {
                let _ = shown_rx.recv();
                let _ = first_offers.send(offer.clone());
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::No)
            });
        });
        let (events, events_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            second.serve(&RecordingTerminal(events), |_, _| {
                let _ = shown.send(());
                let _ = first_done_rx.recv();
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::Yes)
            });
        });
        let reply = stand.guest_ask(&web, 3000);
        first_offers_rx
            .recv_timeout(ASK_WAIT)
            .expect("the first dialog is shown");
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(matches!(
            outcome,
            minimald_rpc::AskAdmitOutcome::Refused {
                reason: minimald_rpc::AskRefused::Denied,
                ..
            }
        ));
        first_done.send(()).unwrap();
        assert_eq!(events_rx.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events_rx.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the late dialog resumes the relay"
        );
        assert!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers()
                .is_empty(),
            "the late yes admitted nothing"
        );
    }

    /// Two attaches are offered one ask; the first answers yes while the
    /// second's dialog is still up and unanswered. The host's dismissal takes
    /// the second dialog down by itself: it records nothing, and its relay
    /// resumes without anyone pressing a key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overtaken_dialog_is_dismissed_and_relay_resumes() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let subscribe = || {
            let control = stand.control.clone();
            tokio::task::spawn_blocking(move || {
                minimal_client::attach::HostAsks::subscribe(&control, "web")
            })
        };
        let first = subscribe()
            .await
            .unwrap()
            .expect("the first attach subscribes");
        let second = subscribe()
            .await
            .unwrap()
            .expect("the second attach subscribes");
        // The first answers only once the second's dialog is up.
        let (shown, shown_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let (events, _) = std::sync::mpsc::channel();
            first.serve(&RecordingTerminal(events), |_, _| {
                let _ = shown_rx.recv();
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::Yes)
            });
        });
        let (ends, ends_rx) = std::sync::mpsc::channel();
        let (events, events_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            second.serve(&RecordingTerminal(events), |_, watch| {
                let _ = shown.send(());
                watch.wait_dismissed();
                let _ = ends.send(());
                minimal_client::ask_dialog::AskDialogEnd::Dismissed
            });
        });
        let reply = stand.guest_ask(&web, 3000);
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(
            matches!(
                outcome,
                minimald_rpc::AskAdmitOutcome::Admitted { port: 3000, .. }
            ),
            "the first attach's yes admits the ask: {outcome:?}"
        );
        ends_rx
            .recv_timeout(ASK_WAIT)
            .expect("the overtaken dialog is dismissed without an answer");
        assert_eq!(events_rx.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events_rx.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the dismissed dialog resumes the relay"
        );
        assert_eq!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers(),
            vec![3000],
            "the one yes admitted the port once"
        );
    }

    /// Ctrl-C at the dialog is a no: the client records no through the host
    /// door, nothing is admitted, and the relay resumes. Escape and a closed
    /// input are a no the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ctrl_c_at_ask_dialog_records_no_and_relay_resumes() {
        let keys = |keys: &[u8]| minimal_client::ask_dialog::AskSelector::default().feed(keys);
        assert_eq!(keys(b"\x03"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x1b"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x04"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x1b[B\r"), Some(minimald_rpc::AskAnswer::Yes));

        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let asks = tokio::task::spawn_blocking({
            let control = stand.control.clone();
            move || minimal_client::attach::HostAsks::subscribe(&control, "web")
        })
        .await
        .unwrap()
        .expect("the attach subscribes");
        let (events, offers) = serve_asks(asks, |_| {
            minimal_client::ask_dialog::AskSelector::default()
                .feed(b"\x03")
                .expect("Ctrl-C ends the dialog")
        });
        let reply = stand.guest_ask(&web, 3000);
        offers.recv_timeout(ASK_WAIT).expect("the dialog is shown");
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert_eq!(
            outcome,
            minimald_rpc::AskAdmitOutcome::Refused {
                ask_id: match outcome {
                    minimald_rpc::AskAdmitOutcome::Refused { ask_id, .. }
                    | minimald_rpc::AskAdmitOutcome::Admitted { ask_id, .. } => ask_id,
                },
                reason: minimald_rpc::AskRefused::Denied,
                cause: None,
            },
            "Ctrl-C records a no"
        );
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the relay resumes after the dialog"
        );
        assert!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers()
                .is_empty()
        );
    }

    #[test]
    fn format_policy_dynamic_ingress_allow_prints_row_not_deny_all() {
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(DynamicIngress::Allow),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  dynamic ingress  allow"),
            "dynamic ingress row must be printed: {rendered}"
        );
        assert!(
            !rendered.contains("  deny-all"),
            "a policy with an explicit dynamic ingress setting must not print 'deny-all': {rendered}"
        );
    }

    #[test]
    fn format_policy_dynamic_ingress_prints_beside_static_mapping() {
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(DynamicIngress::Ask),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :80"),
            "static mapping must still render: {rendered}"
        );
        assert!(
            rendered.contains("  dynamic ingress  ask"),
            "dynamic ingress row must render alongside mapping: {rendered}"
        );
    }

    #[test]
    fn format_policy_egress_rows_default_when_unset() {
        // A declared-but-empty section: the strict shape the daemon handed
        // down before NET-074, which still arrives as `Declared` when the
        // session or the box opted out of the default — and so keeps
        // printing the per-dimension defaults, not `deny-all`.
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::default()),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("egress\n"), "{rendered}");
        assert!(rendered.contains("  allow-all\n"), "{rendered}");
        assert!(rendered.contains("ingress\n"), "{rendered}");
        assert!(rendered.contains("  deny-all\n"), "{rendered}");
    }

    /// A declared deny-all section renders by name (NET-075): every allow
    /// list present and empty is the verdict `deny-all`, and the rows it
    /// would print otherwise are four blanks — a rendering that reads as
    /// nothing, the one this block must never produce. The name is the
    /// requirement's literal token, and it is bare: the `(default)` mark is
    /// the one distinction between a verdict the box declared and the same
    /// verdict the rollout resolved an absent section to, so the declared
    /// row carries none and the default's carries it — asserted here as
    /// the difference between the two renders, in the text and in the JSON
    /// document, whose `source` field carries the same distinction for a
    /// machine. On a host-address box the row sits beside the per-box
    /// enforcement value (T73): declared deny-all beside `per_box` is the
    /// enforced posture, and beside `none` the box's posture beside the
    /// state it runs in.
    #[test]
    fn policy_shows_declared_deny_all() {
        let declared = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: None,
        };

        // Own-address: the name, and no dimension rows — never blankness.
        let mut out = Vec::new();
        format_policy(&mut out, &declared, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all\n"),
            "a declared deny-all box must show the deny-all name: {rendered}"
        );
        for row in ["  subnets", "  dns hosts", "  protocols", "  deny subnets"] {
            assert!(
                !rendered.contains(row),
                "the deny-all verdict must not render as dimension rows: {rendered}"
            );
        }
        assert!(
            !rendered.contains("deny-all (default)"),
            "a declared deny-all is a declaration, never a default, so its \
             row carries no mark: {rendered}"
        );

        // The same verdict the in-force default resolves an absent section
        // to, and the two rows differ by the mark alone: the declared row is
        // what the box chose, the marked row what the rollout chose for a
        // box that declared nothing (NET-075's "marked as a default and not
        // as a declaration" is the mark's own half of the pair).
        let defaulted = EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &defaulted, NetworkMode::OwnIp, None, &[], None).unwrap();
        let default_rendered = String::from_utf8(out).unwrap();
        assert!(
            default_rendered.contains("egress\n  deny-all (default)\n"),
            "a box the rollout resolved to deny-all shows the name, marked \
             as the default: {default_rendered}"
        );
        assert_ne!(
            rendered, default_rendered,
            "the declared and the default renders must differ — the mark is \
             the difference between them"
        );

        // The JSON document carries the same distinction (NET-075): the
        // verdict's name in `effective`, its origin in `source`, so a
        // consumer never recomputes the default rule to tell a declared
        // deny-all from the default's identical verdict. The declared
        // section rides with its name, empty lists and all, the shape the
        // strict record holds; the default's carries no `rules`, because
        // the box declared nothing to carry.
        let egress_of = |policy: &EffectiveSessionPolicy| {
            let mut out = Vec::new();
            write_policy_json(
                &mut out,
                policy,
                NetworkMode::OwnIp,
                None,
                Ok(Vec::new()),
                &[],
            )
            .unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()["egress"]
                .clone()
        };
        let declared_json = egress_of(&declared);
        assert_eq!(
            declared_json["effective"], "deny-all",
            "the document names the declared verdict by the same token: {declared_json}"
        );
        assert_eq!(
            declared_json["source"], "declared",
            "a declared verdict says where it came from: {declared_json}"
        );
        assert_eq!(
            declared_json["rules"]["allow_subnets"],
            serde_json_lenient::Value::Array(Vec::new()),
            "the declared section rides with its name, present-and-empty \
             lists and all: {declared_json}"
        );
        let default_json = egress_of(&defaulted);
        assert_eq!(
            default_json["effective"], "deny-all",
            "the default's verdict is the same name: {default_json}"
        );
        assert_eq!(
            default_json["source"], "default",
            "the rollout's resolution says so, so no consumer recomputes it: {default_json}"
        );
        assert!(
            default_json.get("rules").is_none(),
            "a box that declared nothing carries no section to carry: {default_json}"
        );
        assert_ne!(
            declared_json, default_json,
            "a declared deny-all and the default's never read the same in \
             the document"
        );

        // Host-address: the same name beside the per-box enforcement value.
        let mut out = Vec::new();
        format_policy(
            &mut out,
            &declared,
            NetworkMode::HostNet,
            Some(sessions::HostIpEnforcement::PerBox),
            &[],
            None,
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all\n  per-box enforcement  per_box\n"),
            "the deny-all row sits beside the per-box enforcement value: {rendered}"
        );

        // A section that allows something is not deny-all and keeps its
        // rows: one allowed subnet makes the verdict "10.0.0.0/8 and
        // nothing else", not deny-all, so it must not collapse to the name.
        let not_deny_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                allow_dns_hosts: Some(vec![]),
                allow_protocols: Some(vec![]),
                deny_subnets: None,
            }),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &not_deny_all, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  subnets  10.0.0.0/8"),
            "a section that allows a subnet keeps its rows: {rendered}"
        );
        assert!(
            !rendered.contains("egress\n  deny-all\n"),
            "an allow-listed section is not deny-all and must not read as it: {rendered}"
        );
        // And in the document it is the one shape that carries rows rather
        // than a name: the verdict is the lists, spelled as the text
        // rendering spells them.
        let not_deny_all_json = egress_of(&not_deny_all);
        assert_eq!(
            not_deny_all_json["effective"], "rules",
            "a declaration that admits something has no name; its rows are \
             the verdict: {not_deny_all_json}"
        );
        assert_eq!(
            not_deny_all_json["rules"]["allow_subnets"][0], "10.0.0.0/8",
            "the named subnet rides the declared section: {not_deny_all_json}"
        );
    }

    #[test]
    fn format_policy_prints_the_effective_default_for_a_bare_own_ip_box() {
        // NET-075: once the deny-all default is in force, a box that
        // declared no egress prints the posture the gate enforces, not the
        // absent section — by name, marked as the default it is.
        let deny_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &deny_all, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all (default)\n"),
            "a bare own-address box must show deny-all, marked as the \
             default: {rendered}"
        );
        assert!(
            !rendered.contains("allow-all"),
            "deny-all must not also print the allow-all default row: {rendered}"
        );
        // The opt-out keeps the shipped default, so that box still reads
        // allow-all (NET-077), under the same mark.
        let allow_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &allow_all, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  allow-all (default)\n"),
            "an opted-out bare box must show allow-all: {rendered}"
        );
    }

    /// NET-079's per-box enforcement row in the policy render: printed as
    /// the egress block's closing row when the daemon reported a state over
    /// the runtime-facts reply, in the machine spelling the record and the
    /// daemon's log line carry — and printed from silence never, because a
    /// row made of nothing would be the decided-looking one a daemon that
    /// predates the reply never sent. The requirement's own case is the
    /// first: a deny-all declaration beside an enforcement of `none` is the
    /// state the box actually runs in, not a verdict that looks decided and
    /// is not.
    #[test]
    fn policy_render_carries_the_enforcement_row_when_the_host_reported_it() {
        let unenforced = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(
            &mut out,
            &unenforced,
            NetworkMode::HostNet,
            Some(sessions::HostIpEnforcement::None),
            &[],
            None,
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny-all\n  per-box enforcement  none\n"),
            "a deny-all declaration beside an enforcement of none is the \
             state the box runs in, got: {rendered}"
        );

        // The decided host's own spelling rides the same row.
        let enforced = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(
            &mut out,
            &enforced,
            NetworkMode::HostNet,
            Some(sessions::HostIpEnforcement::PerBox),
            &[],
            None,
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  per-box enforcement  per_box\n"),
            "a host that decides per box says so in the machine spelling, \
             got: {rendered}"
        );

        // No state reported, no row — the same silence an own-address box
        // reads (its own render never carries the state at all), and the one
        // a daemon too old to answer the facts reply leaves the caller with.
        let silent = EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &silent, NetworkMode::HostNet, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            !rendered.contains("per-box enforcement"),
            "no state reported means no row, got: {rendered}"
        );
    }

    /// NET-134's lane in the policy render: a box that declared a
    /// credentialed upstream prints the row — the one destination its
    /// egress rules never decide, named as the lane's whole reach — while
    /// a box that declared none prints nothing, the same silence a
    /// lane-less box always read, so the render cannot claim a lane the
    /// box does not run. The document carries the same distinction for a
    /// machine: the key only when the lane exists, never nulled. A mode
    /// the lane has no effect in still shows the declaration, marked.
    #[test]
    fn policy_render_carries_the_credentialed_upstream_row_when_declared() {
        let laned = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: Some(CredentialedUpstream::default()),
        };
        let mut out = Vec::new();
        format_policy(&mut out, &laned, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains(
                "egress\n  deny-all\n  credentialed upstream  box egress proxy listener\n"
            ),
            "a laned box must print the lane beside its rules, got: {rendered}"
        );

        // The same policy without the lane prints no row: silence is the
        // no-lane claim, not a lane that reads as undeclared.
        let unlaned = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
            ingress: None,
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &unlaned, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            !rendered.contains("credentialed upstream"),
            "a box that declared no lane must print no lane row, got: {rendered}"
        );

        // The document carries the lane the same way: a key only when
        // declared, absent otherwise — never `null`, which a client could
        // not tell from a lane it failed to read.
        let json_of = |policy: &EffectiveSessionPolicy| {
            let mut out = Vec::new();
            write_policy_json(
                &mut out,
                policy,
                NetworkMode::OwnIp,
                None,
                Ok(Vec::new()),
                &[],
            )
            .unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()
        };
        let laned_json = json_of(&laned);
        assert_eq!(
            laned_json["credentialed_upstream"],
            serde_json_lenient::json!({ "effective": true }),
            "the document carries the lane as a key when it is declared: {laned_json}"
        );
        let unlaned_json = json_of(&unlaned);
        assert!(
            unlaned_json.get("credentialed_upstream").is_none(),
            "a box without a lane carries no key, got: {unlaned_json}"
        );

        // A host-address box sits behind no switch gate, so a declared
        // lane there is admitted nowhere — but the view still shows what
        // the box declared, marked as not in effect on both surfaces.
        let mut out = Vec::new();
        format_policy(&mut out, &laned, NetworkMode::HostNet, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains(
                "  credentialed upstream  box egress proxy listener \
                 (not in effect: host_ip box)\n"
            ),
            "a host-address box must show its declared lane, marked, got: {rendered}"
        );
        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &laned,
            NetworkMode::HostNet,
            None,
            Ok(Vec::new()),
            &[],
        )
        .unwrap();
        let host_json: serde_json_lenient::Value = serde_json_lenient::from_slice(&out).unwrap();
        assert_eq!(
            host_json["credentialed_upstream"],
            serde_json_lenient::json!({ "effective": false }),
            "a host-address box carries its declared lane as not in effect, got: {host_json}"
        );

        // A none box keeps the declaration visible the same way.
        let mut out = Vec::new();
        format_policy(&mut out, &laned, NetworkMode::NoNet, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("(not in effect: none box)"),
            "a none box must show its declared lane, marked, got: {rendered}"
        );
        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &laned,
            NetworkMode::NoNet,
            None,
            Ok(Vec::new()),
            &[],
        )
        .unwrap();
        let none_json: serde_json_lenient::Value = serde_json_lenient::from_slice(&out).unwrap();
        assert_eq!(
            none_json["credentialed_upstream"],
            serde_json_lenient::json!({ "effective": false }),
            "a none box carries its declared lane as not in effect, got: {none_json}"
        );
    }

    /// The create reply the activation reads, with only the fields this
    /// test's lines depend on set: an id and a version to satisfy the skew
    /// gate, the classifier advisory, and the enforcement the same create
    /// recorded.
    fn create_reply(
        advisory: Option<&str>,
        host_ip_enforcement: Option<&str>,
    ) -> minimald_rpc::CreateSessionResponse {
        minimald_rpc::CreateSessionResponse {
            id: sessions::SessionId::nil(),
            daemon_version: Some("0.7.0".to_string()),
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            answerer_bound: false,
            interim_loopback: false,
            deny_all_opt_out: None,
            classifier_advisory: advisory.map(str::to_string),
            host_ip_enforcement: host_ip_enforcement.map(str::to_string),
        }
    }

    /// NET-079: the advisory a create reply carries is the line the
    /// activation prints, verbatim — with the exact command that installs
    /// the classifier's privileged step when the step is the cause, spelled
    /// by the daemon so the command the terminal shows is the one that ends
    /// it — and it is never a prompt: no question in the line, nothing for
    /// the start to wait on. A cause no command ends still names the cause
    /// and never an install. A host that decides per box, or a daemon that
    /// predates the field, prints nothing at all.
    ///
    /// The render itself is driven here, with a buffer, the way
    /// [`format_policy`]'s tests drive that render — the same writer the
    /// start drives, so what this pins is the bytes the terminal gets, not
    /// an accessor's echo of the field it read: the advisory the daemon
    /// spelled, the newline that ends it, the command as the last line
    /// with nothing after it.
    #[test]
    fn activate_prints_classifier_advisory() {
        // The reply a step-missing host sends: the daemon's own spelling,
        // with the command on the last line so the thing a person copies
        // is the command, verbatim.
        let step_missing = create_reply(
            Some(
                "note: this host cannot decide a host-address box's egress verdict \
                 per box: the classifier's privileged step is not installed on this \
                 host. While it cannot, its host-address boxes run unenforced — \
                 whatever the boxes' declarations say. Install the classifier's \
                 privileged step with:\n  run: curl -fsSLO \
                 https://raw.githubusercontent.com/gominimal/minimal/main/scripts/\
                 install-host-classifier.sh && sudo bash ./install-host-classifier.sh \
                 --user runner --cohort-address 10.0.0.0/16 --node-plane-address \
                 10.0.1.0/24",
            ),
            Some("none"),
        );
        let mut out = Vec::new();
        write_classifier_advisory(&mut out, &step_missing).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.starts_with(
                "note: this host cannot decide a host-address box's egress verdict \
                 per box: the classifier's privileged step is not installed on this \
                 host. While it cannot, its host-address boxes run unenforced — \
                 whatever the boxes' declarations say."
            ),
            "the start prints the daemon's spelling verbatim, so the log, the \
             reply, and the terminal cannot disagree, got: {rendered}"
        );
        assert!(
            rendered.ends_with(
                "  run: curl -fsSLO https://raw.githubusercontent.com/gominimal/\
                 minimal/main/scripts/install-host-classifier.sh && sudo bash \
                 ./install-host-classifier.sh --user runner --cohort-address \
                 10.0.0.0/16 --node-plane-address 10.0.1.0/24\n"
            ),
            "the missing privileged step is the cause, so the render carries \
             the exact command that installs it, on the last line with \
             nothing after it: {rendered}"
        );
        assert!(
            !rendered.contains('?'),
            "the advisory names what a person may run; it never asks: {rendered}"
        );

        // A host that cannot confine: the cause is still named, and no
        // install can end it, so the line names none.
        let cannot_confine = create_reply(
            Some(
                "note: this host cannot decide a host-address box's egress verdict \
                 per box: no cgroup2 mount with nsdelegate covers the classifier \
                 tree, so a box could migrate out of its leaf. While it cannot, \
                 its host-address boxes run unenforced — whatever the boxes' \
                 declarations say.",
            ),
            Some("none"),
        );
        let mut out = Vec::new();
        write_classifier_advisory(&mut out, &cannot_confine).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("no cgroup2 mount with nsdelegate covers the classifier tree"),
            "the advisory must name this cause in words too: {rendered}"
        );
        assert!(
            rendered.ends_with("declarations say.\n"),
            "no command ends this cause, so the advisory must end with the \
             state it named: {rendered}"
        );
        assert!(
            !rendered.contains("install-host-classifier"),
            "no command ends this cause, so the advisory must name none: {rendered}"
        );
        assert!(
            !rendered.contains('?'),
            "the advisory names what a person may run; it never asks: {rendered}"
        );

        // A host that decides per box, or a daemon that predates the field:
        // nothing to print, the way the other create-reply facts read — the
        // render writes not one byte.
        let decided = create_reply(None, Some("per_box"));
        let mut out = Vec::new();
        write_classifier_advisory(&mut out, &decided).unwrap();
        assert!(
            out.is_empty(),
            "a decided host's create carries no advisory, so its start prints \
             none, got: {:?}",
            String::from_utf8_lossy(&out)
        );
        let pre_field = create_reply(None, None);
        let mut out = Vec::new();
        write_classifier_advisory(&mut out, &pre_field).unwrap();
        assert!(
            out.is_empty(),
            "a daemon that predates the field carries no advisory, so its \
             start prints none, got: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    /// A writer whose reader has gone away, as a piped stderr whose tool
    /// exited — or a closed one (`2>&-`) — leaves the start's stderr: the
    /// broken pipe `min version | head -1` taught this CLI to expect.
    struct ClosedPipe;

    impl std::io::Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// NET-079: the advisory's print is best-effort, never load-bearing.
    /// The note qualifies a session the daemon has already created — it
    /// never gates one — so a start whose stderr cannot take it goes on
    /// to the session's work instead of failing over a line it could not
    /// say. The `?` this replaced made the note's own write failure the
    /// activation's error, after the create it follows had already made
    /// the session.
    #[test]
    fn classifier_advisory_print_is_best_effort() {
        let step_missing = create_reply(
            Some(
                "note: this host cannot decide a host-address box's egress verdict \
                 per box: the classifier's privileged step is not installed on this \
                 host. While it cannot, its host-address boxes run unenforced.",
            ),
            Some("none"),
        );

        // A writer that takes the note gets the render's own bytes — the
        // delegation is the whole print, so the start's line is the one the
        // tests above pinned.
        let mut printed = Vec::new();
        print_classifier_advisory(&mut printed, &step_missing);
        let mut rendered = Vec::new();
        write_classifier_advisory(&mut rendered, &step_missing).unwrap();
        assert_eq!(
            printed, rendered,
            "the print must carry exactly the bytes the render writes"
        );

        // A writer whose reader is gone is logged and left: the print
        // returns — no panic, no error for the start to fail on — the same
        // way a reply that carries no advisory prints nothing and goes on.
        print_classifier_advisory(&mut ClosedPipe, &step_missing);
    }

    /// NET-044: the ports a box published at runtime are listed beside the
    /// declaration — one row a publish, naming the bound address and the
    /// in-box port — and a box that published nothing prints no live section
    /// at all, so the declaration stands alone rather than beside an empty
    /// header.
    #[test]
    fn policy_shows_live_mappings() {
        let live = vec![minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(false),
        }];

        // Beside the declaration: the declared dynamic surface first, then
        // the publish that used it.
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some((3000, 3999)),
                dynamic_ingress: Some(DynamicIngress::Allow),
            }),
            credentialed_upstream: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None, &[], None).unwrap();
        write_live_ingress(&mut out, &live).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        let (declared, live_rows) = rendered
            .split_once("live ingress (published at runtime)\n")
            .expect("the live section follows the declaration");
        assert!(
            declared.contains("  dynamic ports  3000–3999"),
            "the declared dynamic surface still renders: {rendered}"
        );
        assert!(
            live_rows.contains("  tcp  127.0.64.21:3000 → :3000\n"),
            "the live mapping names its bound address and in-box port: {rendered}"
        );

        // Every publish gets its row, in publish order.
        let mut out = Vec::new();
        write_live_ingress(
            &mut out,
            &[
                minimald_rpc::LiveMapping {
                    local: "127.0.64.21:3000".to_string(),
                    internal_port: 3000,
                    proto: IpProto::Tcp,
                    pending: Some(false),
                },
                minimald_rpc::LiveMapping {
                    local: "127.0.64.21:5353".to_string(),
                    internal_port: 5353,
                    proto: IpProto::Udp,
                    pending: Some(false),
                },
            ],
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  127.0.64.21:3000 → :3000\n")
                && rendered.contains("  udp  127.0.64.21:5353 → :5353\n"),
            "one row a publish: {rendered}"
        );

        // Nothing published: no section, not an empty header.
        let mut out = Vec::new();
        write_live_ingress(&mut out, &[]).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "",
            "a box that published nothing prints no live section"
        );
    }

    /// A listen-publish the audit log refused (NET-046) reaches the user
    /// as one warning line per port in `min session policy`, naming the
    /// log; an empty list prints nothing.
    #[test]
    fn unaudited_listen_ports_print_one_warning_per_port() {
        let mut out = Vec::new();
        write_unaudited_listen_ports(&mut out, &[3000, 3001], Some("/state/audit/decisions.log"))
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "warning: port 3000 is permitted but not published: \
             the audit log /state/audit/decisions.log cannot be written\n\
             warning: port 3001 is permitted but not published: \
             the audit log /state/audit/decisions.log cannot be written\n",
        );

        let mut out = Vec::new();
        write_unaudited_listen_ports(&mut out, &[], None).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "",
            "nothing refused, nothing said"
        );

        // The `-o json` document carries the same ports for a machine, and
        // leaves the key out when there are none.
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        };
        let document = |ports: &[u16]| {
            let mut out = Vec::new();
            write_policy_json_noting(
                &mut out,
                &policy,
                NetworkMode::OwnIp,
                None,
                Ok(Vec::new()),
                &[],
                ports,
            )
            .unwrap();
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&out).unwrap()
        };
        assert_eq!(
            document(&[3000])["unaudited_listen_ports"],
            serde_json_lenient::json!([3000])
        );
        assert!(
            document(&[]).get("unaudited_listen_ports").is_none(),
            "no refused listen, no key"
        );
    }

    /// NET-129: a declared port another box at the same shared loopback
    /// address holds is served by that box, so the declared row says whose
    /// it is rather than reading as this box's own. The mark names the
    /// holding box; a row whose port nobody else holds prints as before;
    /// an empty list marks nothing.
    #[test]
    fn policy_marks_a_yielded_shared_address_port() {
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![
                    PortMapping {
                        proto: IpProto::Tcp,
                        external_port: 8080,
                        internal_port: 8080,
                    },
                    PortMapping {
                        proto: IpProto::Udp,
                        external_port: 5353,
                        internal_port: 5353,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            credentialed_upstream: None,
        };
        let collisions = vec![minimald_rpc::SharedPortCollision {
            port: 8080,
            held_by: "first.min.internal".to_string(),
        }];

        let mut out = Vec::new();
        format_policy(
            &mut out,
            &policy,
            NetworkMode::OwnIp,
            None,
            &collisions,
            None,
        )
        .unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :8080 (held by first.min.internal)\n"),
            "the yielded port's row names the box that holds it: {rendered}"
        );
        assert!(
            rendered.contains("  udp  :5353 → :5353\n"),
            "a port no other box holds prints unmarked: {rendered}"
        );

        // The `-o json` document carries the same rows, so a parser can tell
        // the yielded mapping from one this box serves; with none, the key
        // is absent.
        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &policy,
            NetworkMode::OwnIp,
            None,
            Ok(Vec::new()),
            &collisions,
        )
        .unwrap();
        let document = String::from_utf8(out).unwrap();
        assert!(
            document.contains(
                r#""shared_port_collisions":[{"port":8080,"held_by":"first.min.internal"}]"#
            ),
            "the document names the yielded port and its holder: {document}"
        );
        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &policy,
            NetworkMode::OwnIp,
            None,
            Ok(Vec::new()),
            &[],
        )
        .unwrap();
        let document = String::from_utf8(out).unwrap();
        assert!(
            !document.contains("shared_port_collisions"),
            "no yields, no key: {document}"
        );

        // No collisions, no marks: the same declaration renders as before.
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None, &[], None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  :8080 → :8080\n"),
            "an empty collision list marks nothing: {rendered}"
        );
    }

    /// A daemon older than NET-044's gate admission bound a runtime mapping
    /// without admitting its port at the box's relay gate, so its row is a
    /// fact with a caveat. Both
    /// surfaces `min session policy` reads say it: the rendered text marks
    /// the row pending rather than letting it read as reachable, and the
    /// mapping's JSON — the shape any client of the RPC reads, and the data
    /// these rows render — carries the state with it.
    #[test]
    fn policy_shows_pending_live_mapping() {
        let pending = minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(true),
        };
        let admitted = minimald_rpc::LiveMapping {
            local: "127.0.64.21:5353".to_string(),
            internal_port: 5353,
            proto: IpProto::Udp,
            pending: Some(false),
        };

        // The text: the pending row says so — bound, but the box's gate has
        // not admitted the port yet — and the admitted row reads as reachable.
        let mut out = Vec::new();
        write_live_ingress(&mut out, &[pending.clone(), admitted.clone()]).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  tcp  127.0.64.21:3000 → :3000  (pending; not yet reachable)\n"),
            "a mapping the gate has not admitted reads as pending: {rendered}"
        );
        assert!(
            rendered.contains("  udp  127.0.64.21:5353 → :5353\n"),
            "a mapping the gate admitted reads as reachable, with no caveat: {rendered}"
        );

        // The JSON: the mapping's own shape carries the state, so a client
        // reading the wire can tell the two apart without the renderer.
        let pending_json = serde_json_lenient::to_string(&pending).unwrap();
        assert!(
            pending_json.contains("\"pending\":true"),
            "the pending mapping's JSON says so: {pending_json}"
        );
        let admitted_json = serde_json_lenient::to_string(&admitted).unwrap();
        assert!(
            admitted_json.contains("\"pending\":false"),
            "the admitted mapping's JSON says so: {admitted_json}"
        );
    }

    /// A reply from a daemon that predates the `pending` field carries no
    /// `pending` key, and that absence must not fail open into the reachable
    /// reading: the row decodes as `None` — unknown — the text row says
    /// unknown and why, and the JSON document carries `null`, so nothing
    /// parsing either surface reads a runtime publish as reachable that the
    /// daemon could not classify.
    #[test]
    fn policy_marks_a_pre_field_pending_reply_unknown() {
        let encoded = serde_json_lenient::to_string(&minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(false),
        })
        .unwrap();
        // The key, removed: the shape a daemon older than the field writes.
        let mut object: serde_json_lenient::Value = serde_json_lenient::from_str(&encoded).unwrap();
        object
            .as_object_mut()
            .expect("a mapping encodes as an object")
            .remove("pending");
        let pre_field = serde_json_lenient::to_string(&object).unwrap();
        let decoded: minimald_rpc::LiveMapping = serde_json_lenient::from_str(&pre_field).unwrap();
        assert_eq!(
            decoded.pending, None,
            "a reply from a pre-field daemon decodes as unknown: {pre_field}"
        );

        // The text row: unknown, and why — never the bare row of a
        // reachable mapping.
        let mut out = Vec::new();
        write_live_ingress(&mut out, std::slice::from_ref(&decoded)).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains(
                "  tcp  127.0.64.21:3000 → :3000  (unknown; daemon predates this field)\n"
            ),
            "a mapping the daemon could not classify reads as unknown, not as reachable: {rendered}"
        );

        // The JSON document: the unknown state rides as `null`, so a client
        // parsing it branches on absence of the fact, not on a guess.
        let json = serde_json_lenient::to_string(&decoded).unwrap();
        assert!(
            json.contains("\"pending\":null"),
            "the document carries the unknown state as null, not as a bool: {json}"
        );
    }

    /// The walk's failure kinds map onto the machine-mode error payload:
    /// the architecture's codes — `not_found` for a missing thing, with
    /// the kind of thing that was missing (a session) in the message and
    /// the hint, never a policy-specific spelling — beside the message and
    /// the hint the object carries. The one-object shape the payload
    /// becomes on stderr is pinned beside the emitter that writes it, in
    /// `main`'s own tests, since writing it is the emitter's job now.
    #[test]
    fn policy_json_failures_map_to_the_machine_mode_payload() {
        let missing =
            PolicyJsonFailure::SessionNotFound("No session found matching 'gone'".to_string())
                .machine_failure();
        assert_eq!(
            missing.code(),
            "not_found",
            "a missing session is the architecture's not-found code, not a \
             policy spelling"
        );
        assert!(
            missing.message().contains("session"),
            "the message names the kind of thing that was missing: {}",
            missing.message()
        );
        assert!(
            missing.hint().contains("session"),
            "the hint names the kind of thing that was missing: {}",
            missing.hint()
        );

        // The other two kinds keep their own codes, the same vocabulary.
        assert_eq!(
            PolicyJsonFailure::DaemonUnreachable(String::new())
                .machine_failure()
                .code(),
            "daemon_unreachable",
        );
        assert_eq!(
            PolicyJsonFailure::PolicyUnavailable(String::new())
                .machine_failure()
                .code(),
            "policy_unavailable",
        );
    }

    /// Spawns a stand-in VM host control server at `sock_path`: answers
    /// every registration with `reply` (one JSON line, newline appended),
    /// recording each request line it received. Mirrors the line protocol
    /// [`minvmd::control`](minvmd::control) serves, from the server side.
    async fn fake_vm_host(
        sock_path: std::path::PathBuf,
        reply: String,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let seen = std::sync::Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => return,
                };
                let mut lines = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                if lines.read_line(&mut line).await.is_err() {
                    return;
                }
                seen.lock().unwrap().push(line.trim().to_string());
                let mut writer = lines.into_inner();
                if writer.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
                if writer.write_all(b"\n").await.is_err() {
                    return;
                }
            }
        });
        requests
    }

    /// T66: an own-address box on a VM-backed host registers with the VM
    /// host daemon over its control socket — the request carries the box's
    /// name, its expanded ingress ports, and its egress policy; the reply
    /// hands back the two addresses the create request then carries — and
    /// the decision about whether to register at all is the activation's:
    /// only a minvmd-backed host with an own-address box registers, and a
    /// refusal is an error carrying its reason, the one the activation
    /// ends with rather than creating the box unregistered.
    #[tokio::test]
    async fn activate_registers_box_with_vm_host() {
        let policy = sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                allow_dns_hosts: None,
                allow_protocols: Some(vec![IpProto::Tcp]),
                deny_subnets: None,
            }),
            ingress: Some(IngressPolicy {
                port_mappings: vec![
                    PortMapping {
                        external_port: 8080,
                        internal_port: 80,
                        proto: IpProto::Tcp,
                    },
                    PortMapping {
                        external_port: 5432,
                        internal_port: 5432,
                        proto: IpProto::Tcp,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            credentialed_upstream: None,
        };

        // The successful shape, driven the way the activation drives it:
        // through `register_box_for_activation`, whose socket resolution
        // lands on the provider dir the daemon connection uses — here the
        // stand-in bound where a real minvmd's control socket would be.
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let requests = fake_vm_host(
            sock_path.clone(),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let global = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let handed = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            global.minimal_dir.as_deref(),
            NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .expect("a registration that cannot be made is the activation's error")
        .expect("an own-address box on a VM-backed host registers");
        assert_eq!(
            handed.addresses.switch_address,
            std::net::Ipv4Addr::new(100, 64, 0, 2)
        );
        assert_eq!(
            handed.addresses.loopback_address,
            std::net::Ipv4Addr::new(127, 0, 64, 0)
        );
        {
            // The lock is scoped: holding a std MutexGuard across the awaits
            // below is exactly what the await-holding-lock lint names.
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one registration, one request");
            let request: minimald_rpc::BoxControlRequest =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
            let minimald_rpc::BoxControlRequest::Register(request) = request else {
                panic!("a registration is carried by the register verb");
            };
            assert_eq!(request.name, "web");
            assert!(
                request.hold,
                "the activation holds its registration as a lease"
            );
            assert_eq!(request.ingress_ports, vec![8080, 5432]);
            assert_eq!(request.egress.as_ref(), policy.egress.as_ref());
            assert!(
                !seen[0].contains("box_id"),
                "the client never presents a box id; the host mints it: {}",
                seen[0]
            );
        }

        // Every other shape of activation registers nothing: a native
        // daemon has no box table, a host-ip box shares the node's own row.
        // Neither touches a socket, so neither needs a dir.
        assert!(
            register_box_for_activation(
                paths::ProviderKind::Minimald,
                None,
                NetworkMode::OwnIp,
                "web",
                &policy,
            )
            .await
            .expect("a native host answers the activation, not the control socket")
            .is_none(),
            "a native daemon hosts no box table to register on"
        );
        assert!(
            register_box_for_activation(
                paths::ProviderKind::Minvmd,
                global.minimal_dir.as_deref(),
                NetworkMode::HostNet,
                "web",
                &policy,
            )
            .await
            .expect("a host-ip box registers nothing, and that is no failure")
            .is_none(),
            "a host-ip box shares the node's own row and registers nothing"
        );

        // The refusal shape: a daemon that answers with a reason produces an
        // error naming it — the cause the activation ends with at session
        // start, never a box created unregistered.
        let refused_dir = tempfile::TempDir::new().unwrap();
        let refused_path = refused_dir.path().join("control.sock");
        let _refused_requests = fake_vm_host(
            refused_path.clone(),
            r#"{"error":"the switch's address plan is exhausted; no box address remains"}"#
                .to_string(),
        )
        .await;
        let refused = register_box_with_vm_host(
            &refused_path,
            minimald_rpc::RegisterBoxRequest {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
                hold: false,
                task_slots: 0,
            },
        )
        .await
        .expect_err("a refused registration is an error");
        assert!(
            refused.to_string().contains("address plan is exhausted"),
            "the refusal surfaces with its reason: {refused}"
        );
    }

    /// NET-138: an own-address activation asks the VM host for its box's
    /// task addresses in the same registration, and is handed them back for
    /// the create to carry, so the in-VM daemon draws nothing for a task
    /// run either.
    #[tokio::test]
    async fn activation_registers_task_slots_for_own_ip_box() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let requests = fake_vm_host(
            provider_dir.join("control.sock"),
            r#"{"switch_address":"100.64.128.0","loopback_address":"127.0.64.0","box_id":"0123456789abcdef0123456789abcdef","task_addresses":["100.64.128.1","100.64.128.2"]}"#
                .to_string(),
        )
        .await;
        let handed = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            Some(dir.path()),
            NetworkMode::OwnIp,
            "web",
            &sessions::SessionPolicy::default(),
        )
        .await
        .expect("the registration is answered")
        .expect("an own-address box on a VM-backed host registers");
        assert_eq!(
            handed.task_addresses,
            vec![
                std::net::Ipv4Addr::new(100, 64, 128, 1),
                std::net::Ipv4Addr::new(100, 64, 128, 2),
            ],
            "the task addresses the host handed come back for the create"
        );
        let seen = requests.lock().unwrap();
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::Register(request) = request else {
            panic!("a registration is carried by the register verb");
        };
        assert_eq!(
            request.task_slots,
            minimald_rpc::TASK_SLOTS_PER_BOX,
            "the activation asks for its box's task addresses"
        );
    }

    /// The CLI and `min dash` register a box through one exchange: the
    /// activation's registration, resolved by provider kind, and the
    /// dashboard's, resolved beside the ssh socket it holds, put the same
    /// request line on the same control socket — so the two front-ends
    /// cannot drift in what they declare or hold.
    #[tokio::test]
    async fn cli_and_dash_register_through_one_exchange() {
        let policy = sessions::SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            credentialed_upstream: None,
        };
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let requests = fake_vm_host(
            provider_dir.join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let cli = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            Some(dir.path()),
            NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .expect("the CLI's registration is answered")
        .expect("an own-address box on a VM-backed host registers");
        let ssh_sock = client::resolve_socket_path(Some(dir.path()), true).unwrap();
        let dash = minimal_client::box_registration::register_box_beside(
            &ssh_sock,
            NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .expect("the dashboard's registration is answered")
        .expect("the dashboard finds the control socket beside its ssh socket");
        assert_eq!(cli.addresses, dash.addresses);
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 2, "one registration from each front-end");
        assert_eq!(
            seen[0], seen[1],
            "both front-ends send the one request line"
        );
    }

    /// NET-138: before an attach or an exec the CLI asks the VM host daemon
    /// beside the daemon's ssh socket for the box's row back, through the
    /// client library the dashboard's attach resumes through — one resume
    /// line naming the box and the pair off its record. A record with no
    /// row asks nothing.
    #[tokio::test]
    async fn cli_attach_resumes_the_box_through_the_shared_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let requests = fake_vm_host(
            dir.path().join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0","box_id":"07070707070707070707070707070707"}"#
                .to_string(),
        )
        .await;
        let addresses = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        let mut record = sessions::Record {
            id: sessions::SessionId::nil(),
            name: Some("web".to_string()),
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network: NetworkMode::OwnIp,
            policy: sessions::SessionPolicy {
                egress: None,
                ingress: None,
                credentialed_upstream: None,
            },
            status: sessions::SessionStatus::default(),
            hooks_enabled: true,
            task_addresses: Vec::new(),
            box_addresses: Some(addresses),
            host_ip_enforcement: None,
            box_id: None,
            host_row_bound: false,
            attrs: Default::default(),
        };
        let ssh_sock = dir.path().join("ssh.sock");
        resume_box_row(&ssh_sock, Some(&record))
            .await
            .expect("the VM host answers the resume");
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one resume before the attach");
            let request: minimald_rpc::BoxControlRequest =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
            let minimald_rpc::BoxControlRequest::ResumeBox(request) = request else {
                panic!("the row is asked back by the resume verb");
            };
            assert_eq!(request.name, "web");
            assert_eq!(request.switch_address, addresses.switch_address);
            assert_eq!(request.loopback_address, addresses.loopback_address);
        }

        record.box_addresses = None;
        resume_box_row(&ssh_sock, Some(&record))
            .await
            .expect("a session with no row asks nothing");
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "a session with no row asks nothing"
        );
    }

    /// NET-045/NET-138: the host-side registration carries the box's
    /// dynamic-ingress grant — the stance and the range — from the same
    /// create inputs the session record holds, so the host-side row holds
    /// every runtime port report against the grant the box was created
    /// with, never against one the guest could bring with its report. A
    /// declaration that carries no grant carries nothing, and the host's
    /// row fills the deny default in: nothing is permitted.
    #[tokio::test]
    async fn registration_carries_dynamic_ingress_grant() {
        let granted = sessions::SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: Some((3000, 3999)),
                dynamic_ingress: Some(sessions::DynamicIngress::Ask),
            }),
            credentialed_upstream: None,
        };
        let ungranted = sessions::SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            credentialed_upstream: None,
        };

        for (policy, name) in [(granted, "granted"), (ungranted, "ungranted")] {
            let dir = tempfile::TempDir::new().unwrap();
            let provider_dir = dir.path().join("providers").join("local-minvmd0");
            std::fs::create_dir_all(&provider_dir).unwrap();
            let sock_path = provider_dir.join("control.sock");
            let requests = fake_vm_host(
                sock_path.clone(),
                r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
            )
            .await;
            let global = GlobalArgs {
                provider: Some(Provider::LocalMinvmd),
                minimal_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            };
            register_box_for_activation(
                paths::ProviderKind::Minvmd,
                global.minimal_dir.as_deref(),
                NetworkMode::OwnIp,
                name,
                &policy,
            )
            .await
            .expect("the registration is answered")
            .expect("an own-address box on a VM-backed host registers");
            let seen = requests.lock().unwrap();
            let request: minimald_rpc::BoxControlRequest =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
            let minimald_rpc::BoxControlRequest::Register(request) = request else {
                panic!("a registration is carried by the register verb");
            };
            // The grant rides the same create inputs the session record
            // holds: the policy's own stance and range, verbatim.
            assert_eq!(
                request.dynamic_ingress,
                policy.ingress.as_ref().unwrap().dynamic_ingress,
                "the registration carries the stance the create inputs hold"
            );
            assert_eq!(
                request.dynamic_allowed_range,
                policy.ingress.as_ref().unwrap().dynamic_allowed_range,
                "the registration carries the range the create inputs hold"
            );
        }
    }

    /// NET-133/BEP-070: the CLI, the row and the attachment carry one id per
    /// box. The registration presents no id, so the host mints one for this
    /// creation and the reply returns it — and the id the CLI then records
    /// is the id the published row's attachment carries, the one a delivered
    /// connection is attributed by. The autospawn retry's shape — the row
    /// withdrawn, then a re-registration — is a new creation: the reply
    /// carries a new id, never the first one, and the CLI's record, the new
    /// row and the new attachment all agree on it.
    #[tokio::test]
    async fn attachment_carries_the_registered_box_id() {
        let policy = sessions::SessionPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None,
        };

        // The real host tables and the real control server the daemon boots
        // beside them — a registry feeding real attachments — so the id the
        // CLI holds is compared against the attachment a real registration
        // issued, not a stand-in's reply.
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let subnet = switch::SwitchSubnet::default();
        let attachments = minvmd::bep_attach::Attachments::new();
        let registry = minvmd::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());
        let _server = minvmd::control::spawn(
            sock_path.clone(),
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("session-test-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");
        let global = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };

        // The first registration: the request carries no id, the host
        // mints one for this creation, and the reply returns it.
        let first = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            global.minimal_dir.as_deref(),
            NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .expect("the real control server answers the registration")
        .expect("an own-address box on a VM-backed host registers");
        let id = first
            .box_id
            .expect("the daemon's reply returned the box's own id");
        assert_ne!(
            id.to_bytes(),
            [0u8; 16],
            "the id is the box's own minted UUIDv7, never the all-zero non-id"
        );

        // The attachment the registration issued carries that id, and so
        // does the row the reply speaks for: the CLI, the row and the
        // attachment hold the one id per box.
        let attachment = attachments
            .by_source(first.addresses.switch_address.octets())
            .expect("the registration issued the box's attachment");
        assert_eq!(
            id,
            minimald_rpc::BoxId::from_bytes(attachment.box_id()),
            "the id the CLI holds is the id the attachment carries"
        );
        let row = registry
            .table()
            .by_source(first.addresses.switch_address.octets())
            .expect("the registration published the row the reply speaks for");
        assert_eq!(
            id,
            minimald_rpc::BoxId::from_bytes(row.box_id()),
            "the id the CLI holds is the id the row holds"
        );

        // The autospawn retry's shape: the row is withdrawn — its creator
        // presents the pair and the id it was handed — and the
        // re-registration under the re-minted name is a new creation the
        // host mints a new id for.
        withdraw_box_row(
            Some(sock_path.clone()),
            Some("web"),
            Some(first.addresses),
            Some(id),
        )
        .await;
        let again = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            global.minimal_dir.as_deref(),
            NetworkMode::OwnIp,
            "web-again",
            &policy,
        )
        .await
        .expect("the real control server answers the re-registration")
        .expect("the re-registration registers under the re-minted name");
        let new_id = again
            .box_id
            .expect("the daemon's reply returned the new box's own id");
        assert_ne!(
            new_id, id,
            "the re-registration is a new box with a new id: ids are never reused"
        );
        assert_ne!(
            again.addresses.switch_address, first.addresses.switch_address,
            "the recreation draws a never-drawn address before any returned one"
        );

        // The CLI's record, the new row and the new attachment agree on the
        // new id; the first id is held nowhere.
        let reattached = attachments
            .by_source(again.addresses.switch_address.octets())
            .expect("the re-registration issued the box's attachment");
        assert_eq!(
            new_id,
            minimald_rpc::BoxId::from_bytes(reattached.box_id()),
            "the id the CLI records is the id the new attachment carries"
        );
        let new_row = registry
            .table()
            .by_source(again.addresses.switch_address.octets())
            .expect("the re-registration published the row the reply speaks for");
        assert_eq!(
            new_id,
            minimald_rpc::BoxId::from_bytes(new_row.box_id()),
            "the id the CLI records is the id the new row holds"
        );
        assert!(
            !attachments.holds_id(id.to_bytes()),
            "the withdrawn box's id is held by no attachment"
        );
    }

    /// The VM host daemon refuses a registration whose name folds to a
    /// live row's, and that refusal reads as a name collision: an autogen
    /// name re-mints and registers again under the fresh name, within the
    /// shared budget, while a user-supplied name surfaces the refusal —
    /// naming the held spelling — unchanged. Driven against the real
    /// control server so a rewording of the daemon's refusal cannot
    /// silently break the retry.
    #[tokio::test]
    async fn autogen_registration_reminted_on_a_held_name() {
        let policy = sessions::SessionPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None,
        };
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
        let _server = minvmd::control::spawn(
            sock_path,
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("session-test-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");
        let minimal_dir = Some(dir.path());

        let mut held = "Proj-9c1e".to_string();
        let mut attempts = 0u32;
        // Bound for the test's life: the registration's lease holds the
        // row, and dropping it would withdraw the row.
        let _held_box = register_box_reminting_autogen(
            paths::ProviderKind::Minvmd,
            minimal_dir,
            NetworkMode::OwnIp,
            &mut held,
            &policy,
            true,
            &mut attempts,
            || unreachable!("a free name registers on the first try"),
        )
        .await
        .expect("the first box registers")
        .expect("an own-address box on a VM-backed host registers");
        assert_eq!(attempts, 0);

        // An autogen name folding to the live row's re-mints and registers.
        let mut name = "proj-9c1e".to_string();
        let registered = register_box_reminting_autogen(
            paths::ProviderKind::Minvmd,
            minimal_dir,
            NetworkMode::OwnIp,
            &mut name,
            &policy,
            true,
            &mut attempts,
            || "proj-77aa".to_string(),
        )
        .await
        .expect("the held autogen name is re-minted, not fatal")
        .expect("the re-minted name registers");
        assert_eq!(
            name, "proj-77aa",
            "the activation carries the re-minted name"
        );
        assert_eq!(attempts, 1, "the re-mint spent one attempt of the budget");
        assert_eq!(
            registry
                .row_by_name("proj-77aa")
                .expect("the re-minted name holds a row")
                .switch_addr(),
            registered.addresses.switch_address,
        );

        // A user-supplied name never re-mints: the refusal surfaces, naming
        // the spelling the live row holds.
        let mut user = "PROJ-9C1E".to_string();
        let refused = register_box_reminting_autogen(
            paths::ProviderKind::Minvmd,
            minimal_dir,
            NetworkMode::OwnIp,
            &mut user,
            &policy,
            false,
            &mut 0,
            || unreachable!("a user-supplied name is never re-minted"),
        )
        .await
        .expect_err("a user-supplied held name is refused");
        let refused = format!("{refused:#}");
        assert!(
            refused.contains("a box named Proj-9c1e already exists"),
            "the refusal names the held spelling: {refused}"
        );
        assert_eq!(user, "PROJ-9C1E", "the user's name is left as given");
    }

    /// Against the real control server: a registration the activation
    /// holds and drops uncommitted is withdrawn by the VM host daemon, so
    /// its name registers again at once; one committed after its session
    /// went active keeps its row past the lease's close.
    #[tokio::test]
    async fn activation_lease_withdraws_uncommitted_and_keeps_committed() {
        let policy = sessions::SessionPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None,
        };
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
        let _server = minvmd::control::spawn(
            sock_path,
            registry.clone(),
            minvmd::net::answerer::AnswererStatus::allocating_for_tests("session-test-node"),
            minvmd::control::ProxyPublishStatus::default(),
        )
        .expect("the control server binds its socket");
        let minimal_dir = Some(dir.path());
        let policy = &policy;
        let register = move || {
            register_box_for_activation(
                paths::ProviderKind::Minvmd,
                minimal_dir,
                NetworkMode::OwnIp,
                "web",
                policy,
            )
        };

        let dropped = register()
            .await
            .expect("the box registers")
            .expect("an own-address box on a VM-backed host registers");
        assert!(
            dropped.lease.is_some(),
            "the registration is held as a lease"
        );
        assert!(registry.row_by_name("web").is_some());
        drop(dropped);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while registry.row_by_name("web").is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "an uncommitted lease's close withdraws its row"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut kept = register()
            .await
            .expect("the withdrawn name registers again at once")
            .expect("an own-address box on a VM-backed host registers");
        kept.lease
            .take()
            .expect("the registration is held as a lease")
            .commit()
            .await;
        drop(kept);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            registry.row_by_name("web").is_some(),
            "a committed lease keeps its row past the close"
        );
    }

    /// NET-138's status read: the machine's zone-answerer state is read
    /// from the VM host daemon's control socket — the read-only verb, the
    /// one request that names no row — and every way that read cannot be
    /// made is the same silence: a native host has no VM host daemon to
    /// ask, an absent socket no daemon to answer, and a daemon that
    /// predates the verb refuses the line it cannot parse. The verbs print
    /// nothing from a silence; this pins that they get one.
    #[tokio::test]
    async fn the_answerer_status_is_read_from_the_vm_host_alone() {
        // The served shape: the state parses back as itself over the line
        // protocol the registrations ride — built with the wire types so
        // the reply cannot drift from what the daemon sends.
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let reply = serde_json_lenient::to_string(&minimald_rpc::BoxControlReply::Status(
            minimald_rpc::AnswererStatusReply {
                answerer: minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 },
                proxy_down: None,
            },
        ))
        .expect("the status reply serializes");
        let requests = fake_vm_host(sock_path.clone(), reply).await;
        let global = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(
            vm_host_answerer_status(&global).await,
            Some(minimald_rpc::AnswererStatusReply {
                answerer: minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 },
                proxy_down: None,
            }),
            "the reply the daemon answered is the reply the read returns"
        );
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one status read, one request");
            let request: minimald_rpc::BoxControlRequest =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
            assert!(
                matches!(request, minimald_rpc::BoxControlRequest::AnswererStatus),
                "the read is the read-only verb, naming no row: {}",
                seen[0]
            );
        }

        // A native host asks nothing: there is no VM host daemon to read
        // the machine's state from.
        let native = GlobalArgs::default();
        assert_eq!(
            vm_host_answerer_status(&native).await,
            None,
            "a native host has no VM host daemon to ask"
        );

        // A VM-backed host with no socket is the same silence.
        let absent_dir = tempfile::TempDir::new().unwrap();
        let absent = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(absent_dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(
            vm_host_answerer_status(&absent).await,
            None,
            "no socket answers, so no state is claimed"
        );

        // And a daemon that predates the verb refuses the line it cannot
        // parse — the wire's version corner, answered with the same
        // silence rather than a guessed state.
        let old_dir = tempfile::TempDir::new().unwrap();
        let old_provider = old_dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&old_provider).unwrap();
        let _old_requests = fake_vm_host(
            old_provider.join("control.sock"),
            r#"{"error":"unknown verb"}"#.to_string(),
        )
        .await;
        let old = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(old_dir.path().to_path_buf()),
            ..Default::default()
        };
        assert_eq!(
            vm_host_answerer_status(&old).await,
            None,
            "a refusal from a daemon that predates the verb is silence, not a state"
        );
    }

    /// NET-138's interim, surfaced at every session start: the line names
    /// who answers the zone under the `zone answerer:` label — this VM's
    /// minvmd when it holds the port, the machine's other holder when this
    /// VM's table is registered with it — and the pre-acquisition state
    /// prints nothing, exactly as its `min ls` line does.
    #[test]
    fn session_start_names_the_zone_answerer_at_every_start() {
        let holder =
            vm_host_answerer_start_line(minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 })
                .expect("a holder is a state to name");
        assert_eq!(
            holder,
            "zone answerer: answered by the VM host daemon \
             (single-operator interim) · this VM's minvmd holds it on \
             127.0.0.1:7656 (UDP) · point the host's resolver at it for \
             *.min.internal",
            "the start line names this VM's minvmd as the holder"
        );
        let registered =
            vm_host_answerer_start_line(minimald_rpc::ZoneAnswererStatus::Registered {
                port: 7_656,
            })
            .expect("a registered table is a state to name");
        assert_eq!(
            registered,
            "zone answerer: answered by the VM host daemon \
             (single-operator interim) · another VM host daemon holds it on \
             127.0.0.1:7656 (UDP); this VM's table is registered with it · \
             point the host's resolver at it for *.min.internal",
            "the start line names the holder this VM's table answers through"
        );
        assert_eq!(
            vm_host_answerer_start_line(minimald_rpc::ZoneAnswererStatus::Starting),
            None,
            "the pre-acquisition state prints nothing at session start"
        );
    }

    /// T66's destroy side: the client holding a destroyed session's record
    /// withdraws the row its activation registered — one withdraw request
    /// naming the pair the registration handed back — and a session that
    /// registered no box (no pair, no name, no VM host) sends nothing at
    /// all.
    #[tokio::test]
    async fn destroy_sends_the_withdraw() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let requests = fake_vm_host(
            sock_path.clone(),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let global = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let box_id = minimald_rpc::BoxId::from_bytes([7; 16]);
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        // The withdrawal the destroy side owes: the pair comes off the
        // session record, the control socket off the provider dir the
        // daemon connection resolves through — reached by the provider kind,
        // the flag-independent rule, exactly as the destroy does.
        withdraw_box_row(
            vm_host_control_sock(paths::ProviderKind::Minvmd, global.minimal_dir.as_deref()),
            Some("web"),
            Some(handed),
            Some(box_id),
        )
        .await;
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one withdrawal, one request");
            let request: minimald_rpc::BoxControlRequest =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type");
            let minimald_rpc::BoxControlRequest::Withdraw(request) = request else {
                panic!("a withdrawal is carried by the withdraw verb");
            };
            assert_eq!(request.name, "web");
            assert_eq!(request.switch_address, handed.switch_address);
            assert_eq!(request.loopback_address, handed.loopback_address);
            assert_eq!(
                request.box_id,
                Some(box_id),
                "a withdrawal that holds the id names it"
            );
        }

        // And a session that registered nothing owes nothing: no pair, no
        // name, no VM host — each sends nothing, on the same socket.
        withdraw_box_row(
            vm_host_control_sock(paths::ProviderKind::Minvmd, global.minimal_dir.as_deref()),
            Some("web"),
            None,
            None,
        )
        .await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no pair on the record, no withdrawal"
        );
        withdraw_box_row(
            vm_host_control_sock(paths::ProviderKind::Minvmd, global.minimal_dir.as_deref()),
            None,
            Some(handed),
            None,
        )
        .await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no name on the record, no withdrawal"
        );
        withdraw_box_row(
            vm_host_control_sock(paths::ProviderKind::Minimald, None),
            Some("web"),
            Some(handed),
            None,
        )
        .await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no VM host to withdraw from, no withdrawal"
        );
    }

    /// The `host_ip` interim's destroy side: a destroyed session that
    /// registered no row releases the name its activation held — one
    /// release request naming it — while a session with a row releases
    /// nothing (its row's withdrawal is its whole debt), and a failed
    /// activation's withdrawal of a row-less box sends nothing at all: the
    /// name may be a live session's (an autogen collision), so only the
    /// destroy of the session that held it may release it. The hold itself
    /// is the hold verb, and the marker reply is quiet.
    #[tokio::test]
    async fn destroy_releases_a_held_name_and_a_failed_activation_does_not() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let sock_path = provider_dir.join("control.sock");
        let requests = fake_vm_host(
            sock_path.clone(),
            r#"{"name":"web","held":false}"#.to_string(),
        )
        .await;
        let control_sock = || vm_host_control_sock(paths::ProviderKind::Minvmd, Some(dir.path()));
        let decode = |line: &str| -> minimald_rpc::BoxControlRequest {
            serde_json_lenient::from_str(line).expect("the request is the wire type")
        };

        // A failed activation's withdrawal of a row-less box: nothing sent.
        withdraw_box_row(control_sock(), Some("web"), None, None).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "a row-less withdrawal never releases a name a live session may hold"
        );

        // The activation's hold, once the session is active.
        let id = sessions::SessionId::nil();
        hold_box_name_with_vm_host(control_sock(), "web", Some(id), true).await;
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one hold, one request");
            let minimald_rpc::BoxControlRequest::HoldBoxName(request) = decode(&seen[0]) else {
                panic!("a hold is carried by the hold verb");
            };
            assert_eq!(request.name, "web");
        }

        // The destroy of a session with a row releases nothing.
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        release_held_box_name(control_sock(), id, Some("web"), Some(handed)).await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "a row's box holds no name"
        );

        // The destroy of a row-less session releases its name.
        release_held_box_name(control_sock(), id, Some("web"), None).await;
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 2, "one release, one request");
            let minimald_rpc::BoxControlRequest::ReleaseBoxName(request) = decode(&seen[1]) else {
                panic!("a held name's release is carried by the release verb");
            };
            assert_eq!(request.name, "web");
            assert_eq!(
                request.session_id,
                Some(id),
                "the release names its session"
            );
        }

        // No name, or no VM host: nothing sent.
        release_held_box_name(control_sock(), id, None, None).await;
        release_held_box_name(None, id, Some("web"), None).await;
        assert_eq!(requests.lock().unwrap().len(), 2, "nothing to release by");
    }

    /// The `host_ip` hold's attach-exit side: the shell-exit prompt's
    /// Delete destroys the session daemon-side, so the attach's own exit is
    /// where the name is released — one release request naming it and its
    /// session once the session is gone, and nothing while it is still
    /// there (a detach or a Keep).
    #[tokio::test]
    async fn an_attach_that_ends_with_the_session_gone_releases_its_held_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let requests = fake_vm_host(
            dir.path().join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"name":"web","held":false}"#.to_string(),
        )
        .await;
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&ssh_sock).await;
        let project = tempfile::TempDir::new().unwrap();
        let mut daemon = server.connect().await;
        let id = minimald::test_harness::create_configured_session(
            &mut daemon,
            "web",
            project.path().to_str().unwrap(),
        )
        .await;

        // The attach ended with the session still there: nothing released.
        release_held_name_after_attach(&ssh_sock, id, "web", None).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "a session still holding the name keeps its hold"
        );

        // The Delete choice destroyed it daemon-side: the name is released.
        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest { id })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => panic!("the destroy failed: {error}"),
        }
        release_held_name_after_attach(&ssh_sock, id, "web", None).await;
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 1, "one release, one request");
        let minimald_rpc::BoxControlRequest::ReleaseBoxName(request) =
            serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type")
        else {
            panic!("a gone session's name is released by the release verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(
            request.session_id,
            Some(id),
            "the release names the session, so it frees only that session's hold"
        );
    }

    /// T66's attach-exit side: an own-address box whose attach ended in the
    /// shell-exit prompt's Delete has its row withdrawn by the attach's own
    /// exit, with the pair read off the record before the attach — one
    /// withdraw request naming the box and the pair, with no box id, which
    /// the record does not carry — and nothing while the session is still
    /// there.
    #[tokio::test]
    async fn an_attach_that_ends_with_the_session_gone_withdraws_its_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let requests = fake_vm_host(
            dir.path().join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&ssh_sock).await;
        let project = tempfile::TempDir::new().unwrap();
        let mut daemon = server.connect().await;
        let id = minimald::test_harness::create_configured_session(
            &mut daemon,
            "web",
            project.path().to_str().unwrap(),
        )
        .await;
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };

        release_held_name_after_attach(&ssh_sock, id, "web", Some(handed)).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "a session still there keeps its row"
        );

        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest { id })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => panic!("the destroy failed: {error}"),
        }
        release_held_name_after_attach(&ssh_sock, id, "web", Some(handed)).await;
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 1, "one withdrawal, one request");
        let minimald_rpc::BoxControlRequest::Withdraw(request) =
            serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type")
        else {
            panic!("a gone session's row is withdrawn by the withdraw verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(request.switch_address, handed.switch_address);
        assert_eq!(request.loopback_address, handed.loopback_address);
        assert_eq!(request.box_id, None, "the record carries no box id");
    }

    /// The macOS shape of every VM-backed gate (NET-081's other half): the
    /// provider flag is how Linux *asks* for the VM host, so on a host where
    /// minvmd is the only backend the flag is unset even though every
    /// invocation is VM-backed. Each gate therefore keys on the provider kind
    /// the daemon connection resolves through — `client_provider_kind`,
    /// which folds that platform in — and never on the flag's own reading:
    /// a flagless macOS activation would otherwise register no box, resolve
    /// no control socket to withdraw through, and name no VM on its start
    /// line.
    ///
    /// The rule is stated as an expectation about the kinds, each gate is
    /// then driven by kind — the combination the flag cannot express — and
    /// the activation path itself is driven flagless, end to end, the way a
    /// host with no native backend runs it: on such a host the registration,
    /// the start line, and the create's carried addresses all happen with no
    /// flag at all, which is exactly what a gate that read the flag would
    /// skip.
    #[tokio::test]
    async fn vm_backed_gates_key_on_the_provider_kind_not_the_flag() {
        // The premise, then the rule as an expectation about the kinds rather
        // than about the rule's own implementation: a flagless invocation
        // reads `use_minvmd` as false on every host, and the kind it resolves
        // through is minvmd exactly on a host with no native backend to fall
        // back to.
        let flagless = GlobalArgs::default();
        assert!(
            !flagless.use_minvmd(),
            "no provider flag, no flag reading: the premise of the macOS shape"
        );
        let flagless_kind = if cfg!(target_os = "macos") {
            paths::ProviderKind::Minvmd
        } else {
            paths::ProviderKind::Minimald
        };
        assert_eq!(
            daemon_provider_kind(&flagless),
            flagless_kind,
            "a flagless invocation is VM-backed exactly where minvmd is the \
             only backend"
        );
        let flagged = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            ..Default::default()
        };
        assert!(
            flagged.use_minvmd(),
            "--provider local-minvmd is the flag's own reading"
        );
        assert_eq!(
            daemon_provider_kind(&flagged),
            paths::ProviderKind::Minvmd,
            "--provider local-minvmd asks for the VM host by name"
        );

        // The registration gate, driven by kind on one provider dir: the
        // minvmd kind registers through the control socket sitting beside
        // the ssh socket, the native kind asks for nothing from it.
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let requests = fake_vm_host(
            provider_dir.join("control.sock"),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let policy = sessions::SessionPolicy::default();
        let handed = register_box_for_activation(
            paths::ProviderKind::Minvmd,
            Some(dir.path()),
            NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .expect("a minvmd-backed own-address box registers")
        .expect("the registration hands addresses back");
        assert_eq!(
            handed.addresses.switch_address,
            std::net::Ipv4Addr::new(100, 64, 0, 2)
        );
        assert!(
            register_box_for_activation(
                paths::ProviderKind::Minimald,
                Some(dir.path()),
                NetworkMode::OwnIp,
                "web",
                &policy,
            )
            .await
            .expect("the native kind registers nothing, and that is no failure")
            .is_none(),
            "the native backend hosts no box table to register on"
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "only the minvmd kind asked the VM host for a row"
        );

        // The control-socket gate the destroy and Ctrl-C withdrawals resolve
        // through, and the start line's VM name: both read the kind.
        assert_eq!(
            vm_host_control_sock(paths::ProviderKind::Minvmd, Some(dir.path())),
            Some(provider_dir.join("control.sock")),
            "a minvmd-backed host's control socket sits beside its ssh socket"
        );
        assert!(
            vm_host_control_sock(paths::ProviderKind::Minimald, Some(dir.path())).is_none(),
            "the native backend has no control socket to withdraw through"
        );
        assert_eq!(
            hostname_proxy_vm(paths::ProviderKind::Minvmd),
            Some(client::vm_name()),
            "a minvmd-backed host names its VM on the start line"
        );
        assert_eq!(
            hostname_proxy_vm(paths::ProviderKind::Minimald),
            None,
            "the native backend hosts no VMs to name"
        );

        // The activation path, driven flagless — no provider flag anywhere —
        // against the same stand-ins the refused-registration test uses,
        // resolved the way the invocation itself resolves
        // them: a VM host daemon recorded as running behind the provider dir
        // the flagless kind names, and a real daemon behind the ssh socket in
        // the dir that same kind resolves the daemon connection through. On a
        // host with no native backend the two are one dir, and the
        // registration, the start line, and the create's carried addresses
        // all happen with the flag unset; on a host with a native backend the
        // same invocation asks the VM host for nothing, and any gate that
        // reached for the VM host anyway would be seen here asking.
        let state = tempfile::TempDir::new().unwrap();
        let vm_provider_dir = client::resolve_provider_dir(Some(state.path()), true).unwrap();
        std::fs::create_dir_all(&vm_provider_dir).unwrap();
        let vm_state = minvmd::state::StateDir::new(vm_provider_dir.clone()).unwrap();
        vm_state
            .write_state(&minvmd::state::State {
                lifecycle: minvmd::lifecycle::Lifecycle::Running,
                ..minvmd::state::State::stopped()
            })
            .unwrap();
        let _alive = vm_state.try_acquire_alive_lock().unwrap();
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        let requests = fake_vm_host(
            vm_provider_dir.join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"switch_address":"100.64.0.2","loopback_address":"127.0.64.0"}"#.to_string(),
        )
        .await;
        let server = minimald::test_harness::TestServer::new().await;
        let ssh_sock =
            client::resolve_socket_path(Some(state.path()), flagless.use_minvmd()).unwrap();
        std::fs::create_dir_all(ssh_sock.parent().expect("the ssh socket has a parent")).unwrap();
        server.listen_on_uds(&ssh_sock).await;

        let project = tempfile::TempDir::new().unwrap();
        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let args = ActivateArgs {
            name: Some("gate-web".to_string()),
            path: Some(project.path().to_str().unwrap().to_string()),
            network: CliNetworkMode::OwnIp,
            sync: Some(SyncMode::None),
            no_loadouts: true,
            no_prompt: true,
            attach: false,
            ..bare_activate_args()
        };
        activate_session(&global, args, false).await.expect(
            "a flagless activation reaches a session on the backend its kind \
             resolves to",
        );

        // The row: asked for on the VM host the flagless kind resolved to, or
        // not asked for at all — the kind's own answer, never the flag's.
        assert_eq!(
            requests.lock().unwrap().len(),
            usize::from(flagless_kind == paths::ProviderKind::Minvmd),
            "the flagless activation asked the VM host for a row exactly when \
             its provider kind is minvmd"
        );
        // And the create's half: the pair a minvmd-backed registration handed
        // back travels to the daemon on the create request, so the record the
        // daemon holds names it; a native host's record carries no pair at
        // all, because nothing was registered to hand it one.
        let mut after = server.connect().await;
        let record = after
            .call::<minimald_rpc::GetSessionRecord>(&minimald_rpc::GetSessionRecordRequest::Name(
                "gate-web".to_string(),
            ))
            .await
            .record
            .expect("the flagless activation created the session");
        assert_eq!(
            record.box_addresses,
            (flagless_kind == paths::ProviderKind::Minvmd).then_some(handed),
            "the create carried the addresses the registration handed back, \
             or nothing when nothing was registered"
        );
    }

    /// The failure half of NET-081's registration: a VM host daemon that
    /// refuses the box's registration ends the activation with the refusal's
    /// cause — the session does not start with the box unregistered — and no
    /// session is left behind. The full activation is driven through
    /// `activate_session`, so the path proven is the user's: the refusal
    /// surfaces as the session-start error, not as a warning beside a box
    /// that created anyway.
    #[tokio::test]
    async fn registration_failure_is_surfaced_at_session_start() {
        // The state dir: a VM host daemon recorded as Running with its alive
        // lock held (so the activation's autospawn sees one and spawns
        // nothing), its control socket refusing every registration, and a
        // real daemon behind the ssh socket the activation connects to — so
        // the create is one refusal away from succeeding when the
        // registration goes first.
        let state = tempfile::TempDir::new().unwrap();
        let provider_dir = state.path().join("providers").join("local-minvmd0");
        let state_dir = minvmd::state::StateDir::new(provider_dir.clone()).unwrap();
        state_dir
            .write_state(&minvmd::state::State {
                lifecycle: minvmd::lifecycle::Lifecycle::Running,
                ..minvmd::state::State::stopped()
            })
            .unwrap();
        let _alive = state_dir.try_acquire_alive_lock().unwrap();
        let requests = fake_vm_host(
            provider_dir.join("control.sock"),
            r#"{"error":"the switch's address plan is exhausted; no box address remains"}"#
                .to_string(),
        )
        .await;
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&provider_dir.join("ssh.sock")).await;

        // A project directory with nothing special about it: the activation
        // is refused at the registration, before any of the loadout or
        // upload steps that would need one.
        let project = tempfile::TempDir::new().unwrap();
        let global = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            minimal_dir: Some(state.path().to_path_buf()),
            no_input: true,
            ..Default::default()
        };
        let args = ActivateArgs {
            name: Some("web".to_string()),
            path: Some(project.path().to_str().unwrap().to_string()),
            network: CliNetworkMode::OwnIp,
            no_prompt: true,
            attach: false,
            ..bare_activate_args()
        };
        let error = activate_session(&global, args, false)
            .await
            .expect_err("a refused registration ends the activation");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("registering the box with the VM host daemon failed"),
            "the error names what failed: {rendered}"
        );
        assert!(
            rendered.contains("address plan is exhausted"),
            "the error carries the daemon's cause: {rendered}"
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "the refusal answered exactly one registration"
        );

        // And the session did not fall back to running unregistered: the
        // daemon behind the ssh socket holds no session at all.
        let mut client = server.connect().await;
        let listed = client.call::<minimald_rpc::ListSessions>(&()).await;
        assert!(
            listed.sessions.is_empty(),
            "no session was created for the unregistered box"
        );
    }
}
