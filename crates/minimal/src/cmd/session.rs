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

/// How long a box control request — a registration, or the withdrawal of
/// the row a registration bought — may take before this invocation gives
/// up on it. The control socket answers with map writes and an allocation,
/// so healthy is milliseconds; the bound exists so a hung VM host daemon
/// cannot hang the activation or destroy the user asked for.
const BOX_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One control-socket exchange with the VM host daemon (T66): one JSON
/// line in — the verb's request — and one line out — the untagged reply
/// the verb is answered with.
///
/// The control socket lives beside the ssh socket in the minvmd
/// provider-instance dir — the dir the daemon connection resolves through.
/// A refusal (an exhausted address plan, a malformed declaration, a pair
/// that is not the row's) surfaces here as an error naming the reason; the
/// caller degrades a failed registration to a warning rather than failing
/// the activation, and a failed withdrawal to one rather than failing the
/// destroy it rides on.
async fn control_request_with_vm_host(
    sock_path: &std::path::Path,
    request: minimald_rpc::BoxControlRequest,
) -> anyhow::Result<minimald_rpc::BoxControlReply> {
    use tokio::io::AsyncBufReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    let mut stream = tokio::net::UnixStream::connect(sock_path)
        .await
        .with_context(|| {
            format!(
                "connecting to the VM host daemon's box control socket at {}",
                sock_path.display()
            )
        })?;
    let mut line =
        serde_json_lenient::to_string(&request).context("serializing the box control request")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .await
        .context("writing the box control request")?;
    let mut reply = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut reply)
        .await
        .context("reading the box control reply")?;
    if reply.trim().is_empty() {
        anyhow::bail!(
            "the VM host daemon closed its control socket without answering the box control request"
        );
    }
    let reply: minimald_rpc::BoxControlReply = serde_json_lenient::from_str(reply.trim())
        .with_context(|| {
            format!("the VM host daemon's box control reply did not parse: {reply}")
        })?;
    Ok(reply)
}

/// Registers an own-address box with the VM host daemon over its control
/// socket (T66), returning the addresses it handed back.
async fn register_box_with_vm_host(
    sock_path: &std::path::Path,
    request: minimald_rpc::RegisterBoxRequest,
) -> anyhow::Result<sessions::BoxAddresses> {
    match control_request_with_vm_host(
        sock_path,
        minimald_rpc::BoxControlRequest::Register(request),
    )
    .await?
    {
        minimald_rpc::BoxControlReply::Addresses(addresses) => Ok(addresses),
        minimald_rpc::BoxControlReply::Error { error } => {
            anyhow::bail!("the VM host daemon refused the box registration: {error}")
        }
    }
}

/// The VM host daemon's control socket, when this invocation can reach one
/// (T66): it sits beside the ssh socket in the provider dir the daemon
/// connection resolves through, so the client finds both by the same rule
/// — named VMs included, since the resolution reads the same process-global
/// VM name.
///
/// Silent by design: an invocation that owes nothing — no VM host, an
/// unresolvable dir — asks for nothing, and the withdrawal's own warning is
/// the one that names the row left published.
pub(crate) fn vm_host_control_sock(global: &GlobalArgs) -> Option<std::path::PathBuf> {
    if !global.use_minvmd() {
        return None;
    }
    let ssh_sock = client::resolve_socket_path(global.minimal_dir.as_deref(), true).ok()?;
    ssh_sock
        .parent()
        .map(|dir| dir.join(minvmd::control::CONTROL_SOCK_FILE))
}

/// Withdraws the box's host row (T66) when the session that registered it
/// is gone — destroyed, or an activation that failed after registering:
/// the row has no holder left, so its creator presents the pair the
/// registration handed back and the daemon stops the pair's addresses
/// admitting anything.
///
/// Always quiet when it owes nothing: a session that registered no box — a
/// native host, a host-ip box sharing the node's own row, a refused
/// registration — withdraws nothing and says nothing. A withdrawal that
/// cannot be made — no control socket, a daemon that predates the verb and
/// refuses the line, the deadline — leaves the row published and warns
/// rather than failing the destroy or the activation error it rides on;
/// the daemon restarting between registration and withdrawal answers the
/// withdrawal as already gone, which is the goal state either way.
pub(crate) async fn withdraw_box_row(
    control_sock: Option<std::path::PathBuf>,
    name: Option<&str>,
    box_addresses: Option<sessions::BoxAddresses>,
) {
    let Some(name) = name else { return };
    let Some(addresses) = box_addresses else {
        return;
    };
    let Some(sock_path) = control_sock else {
        tracing::warn!(
            box = %name,
            "cannot resolve the VM host daemon's control socket; the box's \
             host row stays published until the daemon next restarts"
        );
        return;
    };
    let request = minimald_rpc::WithdrawBoxRequest {
        name: name.to_string(),
        switch_address: addresses.switch_address,
        loopback_address: addresses.loopback_address,
    };
    let withdrawn = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        control_request_with_vm_host(
            &sock_path,
            minimald_rpc::BoxControlRequest::Withdraw(request),
        ),
    )
    .await;
    match withdrawn {
        Ok(Ok(reply)) => match reply {
            // The daemon answers the withdrawal with the pair it went by; a
            // pair back that is not the pair asked is a daemon speaking
            // another protocol's answer — the row asked for is not
            // withdrawn, so say so.
            minimald_rpc::BoxControlReply::Addresses(handed) if handed == addresses => {
                tracing::debug!(box = %name, "withdrew the box's host row");
            }
            minimald_rpc::BoxControlReply::Addresses(handed) => {
                tracing::warn!(
                    box = %name,
                    switch_address = %handed.switch_address,
                    "the VM host daemon answered the withdrawal with a different \
                     address pair; the row asked for stays published"
                );
            }
            minimald_rpc::BoxControlReply::Error { error } => {
                tracing::warn!(
                    box = %name,
                    %error,
                    "the VM host daemon refused the box row withdrawal; the row \
                     stays published"
                );
            }
        },
        Ok(Err(error)) => {
            tracing::warn!(
                box = %name,
                %error,
                "the box row withdrawal failed; the row stays published"
            );
        }
        Err(_) => {
            tracing::warn!(
                after = ?BOX_CONTROL_TIMEOUT,
                box = %name,
                "the VM host daemon did not answer the box row withdrawal in \
                 time; the row stays published"
            );
        }
    }
}

/// Registers this activation's box with the VM host daemon, when there is
/// one to register with (T66), returning the addresses it handed back —
/// `None` when there is nothing to register or the registration could not
/// be made.
///
/// The box this activation creates is registerable only on a minvmd-backed
/// host, and only when it is an own-address box: a `host_ip` box shares the
/// node's own row in the host table, and a `none` box has no switch address
/// at all — both register nothing and attach exactly as they always have.
///
/// A registration that cannot be made — no control socket (a supervisor
/// predating it), a refusal, the deadline — degrades to a warning and
/// `None`, never to a failed activation: the box still creates, but
/// unregistered. No host-side row holds it, so its frames run unattributed
/// — the egress gate's announced interim admits what it admits — until the
/// gate's per-box default is in force, which then fails closed for the box
/// (#1790). The warning says so.
async fn register_box_for_activation(
    global: &GlobalArgs,
    network: sessions::NetworkMode,
    name: &str,
    policy: &sessions::SessionPolicy,
) -> Option<sessions::BoxAddresses> {
    if !global.use_minvmd() || network != sessions::NetworkMode::OwnIp {
        return None;
    }
    // The control socket sits beside the ssh socket in the provider dir the
    // daemon connection resolves through, so the client finds both by the
    // same rule — named VMs included, since the resolution reads the same
    // process-global VM name.
    let ssh_sock = match client::resolve_socket_path(global.minimal_dir.as_deref(), true) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(
                %error,
                "cannot resolve the VM host provider dir; the box registration \
                 is skipped and the box runs unregistered — its frames \
                 unattributed — until the egress gate's per-box default is in \
                 force (fail-closed then; #1790)"
            );
            return None;
        }
    };
    let Some(sock_path) = ssh_sock
        .parent()
        .map(|dir| dir.join(minvmd::control::CONTROL_SOCK_FILE))
    else {
        tracing::warn!(
            "no provider dir resolved for the ssh socket; the box registration \
             is skipped and the box runs unregistered — its frames \
             unattributed — until the egress gate's per-box default is in \
             force (fail-closed then; #1790)"
        );
        return None;
    };
    // The declaration, as this activation expanded it: the ingress rules
    // reduced to the external ports they admit — the shape the host row
    // holds — and the egress policy verbatim.
    let request = minimald_rpc::RegisterBoxRequest {
        name: name.to_string(),
        ingress_ports: policy
            .ingress
            .as_ref()
            .map(|ingress| {
                ingress
                    .port_mappings
                    .iter()
                    .map(|mapping| mapping.external_port)
                    .collect()
            })
            .unwrap_or_default(),
        egress: policy.egress.clone(),
    };
    let registration = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        register_box_with_vm_host(&sock_path, request),
    )
    .await;
    match registration {
        Ok(Ok(addresses)) => {
            tracing::debug!(
                box = %name,
                switch_address = %addresses.switch_address,
                loopback_address = %addresses.loopback_address,
                "VM host daemon handed the box its addresses"
            );
            Some(addresses)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                %error,
                "the box registration failed; the box runs unregistered — its \
                 frames unattributed — until the egress gate's per-box default \
                 is in force (fail-closed then; #1790)"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                after = ?BOX_CONTROL_TIMEOUT,
                "the VM host daemon did not answer the box registration in time; \
                 the box runs unregistered — its frames unattributed — until \
                 the egress gate's per-box default is in force (fail-closed \
                 then; #1790)"
            );
            None
        }
    }
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
    // records an allow-all policy that denies one range.
    let has_egress = !args.allow_subnets.is_empty()
        || !allow_protocols.is_empty()
        || !args.allow_dns_hosts.is_empty()
        || !args.deny_subnets.is_empty();
    let egress = has_egress.then_some(sessions::EgressPolicy {
        allow_subnets: (!args.allow_subnets.is_empty()).then(|| args.allow_subnets.clone()),
        allow_dns_hosts: (!args.allow_dns_hosts.is_empty()).then(|| args.allow_dns_hosts.clone()),
        allow_protocols: (!allow_protocols.is_empty()).then_some(allow_protocols),
        deny_subnets: (!args.deny_subnets.is_empty()).then(|| args.deny_subnets.clone()),
    });
    let policy = sessions::SessionPolicy {
        egress,
        ingress: (!port_mappings.is_empty()).then_some(sessions::IngressPolicy {
            port_mappings,
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        }),
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
    if offer_scaffold {
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
    // own. Every other shape of activation — a host-ip box sharing the
    // node's own row, a none box with no switch address, a native daemon
    // with no box table — registers nothing and attaches as it always has.
    // This is the last fallible client-side step, so a failure from here on
    // owes the row its creator's withdrawal (T66): the sites below send it.
    // The control socket is resolved once, here, and the withdrawals ride
    // on it.
    let control_sock = vm_host_control_sock(global);
    config.box_addresses = register_box_for_activation(
        global,
        config.network,
        config
            .name
            .as_deref()
            .expect("the session name is minted before the create"),
        &config.policy,
    )
    .await;

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
    };
    // An autogen name can (rarely) collide with an existing session built
    // from the same directory; on the daemon's already-exists rejection,
    // re-mint the hex suffix and retry a bounded number of times. A
    // user-supplied name never retries — its collision, and any other failure
    // (e.g. a policy/network-mode validation error), surfaces unchanged.
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
                    )
                    .await;
                    config.name = Some(autogen_session_name(&utf8_path, &random_hex4()));
                    // A registered box's row carries the name it was
                    // registered under (T66), so the re-mint re-registers;
                    // the abandoned row's addresses stay spent by design
                    // (the host's cursors never regress), but its
                    // admissions are withdrawn above, and the retry leaves
                    // no row behind.
                    config.box_addresses = register_box_for_activation(
                        global,
                        config.network,
                        config.name.as_deref().expect("just re-minted"),
                        &config.policy,
                    )
                    .await;
                    continue;
                }
                // A create failure that is not a retryable autogen collision
                // abandons the activation and its row the same way.
                withdraw_box_row(
                    control_sock.clone(),
                    config.name.as_deref(),
                    config.box_addresses,
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
        )
        .await;
        return Err(error);
    }
    warn_if_hostname_routing_down(
        created.hostname_routing_unavailable.as_deref(),
        "min session activate",
    );
    // NET-122/NET-123: the naming advisory, printed once per session start —
    // after the create, and re-surfaced when the daemon reports this session
    // at the 127.0.0.1 interim because its session-start bind probe found
    // the reserved range absent. It only ever names the command that
    // points the host's resolver at the answerer; running it (and any
    // privilege prompt it carries) is the user's act, never the session
    // start's. One read of this host's resolver state decides both this and
    // the surface verdict below it, so the two lines cannot disagree about
    // one host.
    //
    // Both lines are the answerer's port's to print: the advisory has no
    // command to name without one, the verdict no answerer whose surface to
    // decide, so a create that reports none — the answerer still coming up,
    // or a daemon that predates the field — prints neither and reads
    // nothing. That keeps the no-port activate the zero-cost start it was
    // before either line read this host: the detection below is two
    // `resolvectl` queries under a five-second bound, and a wedged
    // systemd-resolved must not be waited out for lines that cannot print
    // from it.
    if let Some(answerer_port) = created.zone_answerer_port {
        let detection = crate::resolver::session_detection().await;
        let name_advisory = crate::resolver::session_advisory_at(
            &detection,
            Some(answerer_port),
            created.interim_loopback,
        );
        if let Some(advisory) = &name_advisory {
            eprintln!("{advisory}");
        }
        // NET-018: name the live surface at the moment the user is about to
        // rely on the names — decided in the one function both verbs share
        // (`resolver`), from the same detection the advisory read: this
        // host's hook (and the stub-bypass blocker that says whether its
        // lookups consult what the hook configures), the daemon's
        // answerer-bound report, and the reserved range on this host's own
        // loopback. `None` — the answerer not bound — prints nothing: no
        // native surface to name, and the ports and the advisory above
        // have told the proxy's story. The proxy's half is said with the
        // native arm either way (NET-019): the `HTTP(S)_PROXY` recipes
        // this activation prints keep working beside native DNS, so
        // nothing already captured goes stale.
        if let Some(verdict) = crate::resolver::live_name_surface_with_range_at(
            &detection,
            Some(answerer_port),
            created.answerer_bound,
        )
        .await
        {
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
                answerer_bound = created.answerer_bound,
                range_present = ?verdict.range_present,
                "session start decided the live name surface for this host"
            );
            eprintln!(
                "{}",
                crate::resolver::name_surface_line(verdict.surface, created.hostname_proxy_port)
            );
        }
    }
    let id = created.id;

    // The coming-change notice (NET-076), printed while the deny-all egress
    // default is announced but not yet in force. Scoped to the box it would
    // change — an own-address session that declared no egress — on a daemon
    // that has not opted out of the change (NET-077): the opt-out is the
    // one rollout fact this side cannot know, so it is read off the create
    // reply above, and a daemon that has already set the flag has already
    // taken the remedy the notice names. Silent once the phase turns (see
    // [`deny_all_default_notice`]). Printed after the session exists and
    // before the work on it, so the warning is not lost above a failed
    // activate's output.
    if config.network == minimald_rpc::NetworkMode::OwnIp
        && config.policy.egress.is_none()
        && created.deny_all_opt_out != Some(true)
        && let Some(notice) = deny_all_default_notice(sessions::EGRESS_DEFAULT_PHASE)
    {
        eprintln!("{notice}");
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
        // `min ls` doesn't fill with half-finalized sessions, and
        // withdraw the row the registration bought with it (T66).
        best_effort_destroy(&mut client, id).await;
        withdraw_box_row(
            control_sock.clone(),
            config.name.as_deref(),
            config.box_addresses,
        )
        .await;
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
        // No owns-box flag (NET-131): the task runs in a session someone
        // else keeps, so its end stays with whoever holds it.
        Some(
            minimald_rpc::exec::ExecRequest::TaskRun {
                task: args.task,
                owns_box: false,
            }
            .encode(),
        ),
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
            Ok(SmartAttach::Attach(entry))
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
    /// Attach to this resolved or picked session.
    Attach(minimald_rpc::ListSessionsEntry),
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
            allow_subnets: Vec::new(),
            allow_dns_hosts: Vec::new(),
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
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

/// Print the effective networking rules for a session.
pub async fn cmd_session_policy(
    global: &GlobalArgs,
    args: PolicyArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    // The effective reply carries only the rules, but the ingress block is
    // suppressed for host-address sessions (see [`format_policy`]), so the
    // command also resolves the record the policy rides on for its network
    // mode.
    let record = resolve_session(&mut client, &args.session).await?;

    // The daemon resolves the effective egress (NET-074/NET-077), because
    // the rollout phase and its opt-out are the daemon's own facts; built
    // here rather than through a `SessionLookup` conversion so the request
    // types stay the rpc crate's, where the wire contract lives.
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let lookup = match SessionLookup::parse(&args.session) {
        SessionLookup::Id(id) => GetEffectiveSessionPolicyRequest::Id(id),
        SessionLookup::Name(n) => GetEffectiveSessionPolicyRequest::Name(n),
    };

    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(lookup)
        .await
        .context("GetEffectiveSessionPolicy RPC failed")?;

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
            let fabric = (client::client_provider_kind(global.use_minvmd())
                == paths::ProviderKind::Minvmd)
                .then_some(switch::SwitchSubnet::default());
            let mut out = std::io::stdout();
            format_policy(&mut out, &policy, record.network, fabric)?;
            out.flush().context("Failed to write policy")?;
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("{error}")
        }
    }
}

/// The coming-change notice `min session activate` prints while the
/// deny-all egress default is announced but not yet in force (NET-076):
/// what changes for an own-address box that declares no egress, and how a
/// deployment keeps the shipped default while it moves. `None` in every
/// other phase — once the default is in force the change is no longer
/// coming, and a box that reaches nothing needs no note about it.
///
/// The opt-out half of the scope is the caller's to check: the daemon, not
/// the client, knows whether it set `--egress-deny-all-opt-out` (NET-077),
/// so [`activate_session`] reads it off the create reply and stays silent
/// for a deployment the change is not coming for.
pub fn deny_all_default_notice(phase: sessions::EgressDefaultPhase) -> Option<&'static str> {
    match phase {
        sessions::EgressDefaultPhase::Announced => Some(
            "Heads-up: the next release denies all external reach for an own-address \
             session that declares no egress. Declare what the session needs with the \
             activate egress flags, or start the daemon with \
             --egress-deny-all-opt-out to keep this default.",
        ),
        sessions::EgressDefaultPhase::InForce => None,
    }
}

/// Render a session's effective policy as its rules: the egress the gate
/// enforces (NET-074/NET-075) — a declared section's dimensions each
/// resolved to its list or its default (`allow all`; `deny subnets` reads
/// `(none)` when nothing is denied), or, for a box that declared no egress
/// at all, the default its daemon resolved to (`deny all` once the deny-all
/// default is in force; `allow all` behind the opt-out or before it) — the
/// node-plane baseline set the helper enumerates beside it (NET-130: the
/// categories the in-VM daemon's own registry and cache fetches are to
/// reach, one row a category's subnets, headed by the posture the
/// host-side gate decides those fetches under — announced, the shipped
/// posture, the run path's allow-all interim node row still decides them
/// and the set binds nothing yet; in force, the set decides them whatever
/// the box's own declaration resolves to, so it is what a deny-all box
/// reads beside), and the ingress mappings spelled out.
/// `network` is the session's network mode. `fabric` is the switch plan the
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
/// place of both blocks (`allow all` egress would claim a reach a box with
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
    fabric: Option<switch::SwitchSubnet>,
) -> Result<(), anyhow::Error> {
    // A none box has no network, so it can carry no egress or ingress
    // declaration at all — nothing the blocks print would describe anything
    // real (the same case the TUI's detail pane replaces with this note).
    if network == sessions::NetworkMode::NoNet {
        writeln!(out, "No network policy (NoNet)")?;
        return Ok(());
    }
    writeln!(out, "egress")?;
    match &effective.egress {
        sessions::EffectiveEgress::DenyAll => writeln!(out, "  deny all")?,
        sessions::EffectiveEgress::AllowAll => writeln!(out, "  allow all")?,
        sessions::EffectiveEgress::Declared(egress) => {
            write_rules(out, "subnets", egress.allow_subnets.as_ref(), "allow all")?;
            write_rules(
                out,
                "dns hosts",
                egress.allow_dns_hosts.as_ref(),
                "allow all",
            )?;
            match &egress.allow_protocols {
                None => writeln!(out, "  protocols  allow all")?,
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
    // to show for it — "deny all" there would claim a deny-rule exists.
    if network != sessions::NetworkMode::HostNet {
        writeln!(out, "ingress")?;
        match &effective.ingress {
            None => writeln!(out, "  deny all")?,
            Some(ingress) => {
                if ingress.port_mappings.is_empty()
                    && ingress.dynamic_allowed_range.is_none()
                    && ingress.dynamic_ingress.is_none()
                {
                    writeln!(out, "  deny all")?;
                }
                for mapping in &ingress.port_mappings {
                    writeln!(
                        out,
                        "  {}  :{} → :{}",
                        mapping.proto, mapping.external_port, mapping.internal_port
                    )?;
                }
                if let Some((lo, hi)) = ingress.dynamic_allowed_range {
                    writeln!(out, "  dynamic ports  {lo}–{hi}")?;
                }
                if let Some(mode) = ingress.dynamic_ingress {
                    writeln!(out, "  dynamic ingress  {mode}")?;
                }
            }
        }
    }
    Ok(())
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

    if resp.ok().is_some() {
        println!("Destroyed session {} ({})", id, name.unwrap_or("-"));
        // The session is gone; the row its activation bought outlives it on
        // the VM host daemon, and its creator withdraws it here (T66) —
        // presenting the pair the registration handed back. Best-effort: a
        // withdrawal that cannot be made leaves the row published and warns
        // rather than failing a destroy that already succeeded.
        withdraw_box_row(vm_host_control_sock(global), name, box_addresses).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::{
        DynamicIngress, EffectiveEgress, EffectiveSessionPolicy, IngressPolicy, IpProto,
        NetworkMode, PortMapping,
    };

    #[test]
    fn format_policy_dynamic_ingress_allow_prints_row_not_deny_all() {
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: Some(IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(DynamicIngress::Allow),
            }),
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("  dynamic ingress  allow"),
            "dynamic ingress row must be printed: {rendered}"
        );
        assert!(
            !rendered.contains("  deny all"),
            "a policy with an explicit dynamic ingress setting must not print 'deny all': {rendered}"
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
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None).unwrap();
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
        // printing the per-dimension defaults, not `deny all`.
        let policy = EffectiveSessionPolicy {
            egress: EffectiveEgress::Declared(sessions::EgressPolicy::default()),
            ingress: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &policy, NetworkMode::OwnIp, None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("egress\n"), "{rendered}");
        assert!(rendered.contains("  allow all\n"), "{rendered}");
        assert!(rendered.contains("ingress\n"), "{rendered}");
        assert!(rendered.contains("  deny all\n"), "{rendered}");
    }

    #[test]
    fn format_policy_prints_the_effective_default_for_a_bare_own_ip_box() {
        // NET-075: once the deny-all default is in force, a box that
        // declared no egress prints the posture the gate enforces, not the
        // absent section.
        let deny_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &deny_all, NetworkMode::OwnIp, None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  deny all\n"),
            "a bare own-address box must show deny-all: {rendered}"
        );
        assert!(
            !rendered.contains("allow all"),
            "deny-all must not also print the allow-all default row: {rendered}"
        );
        // The opt-out keeps the shipped default, so that box still reads
        // allow-all (NET-077).
        let allow_all = EffectiveSessionPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
        };
        let mut out = Vec::new();
        format_policy(&mut out, &allow_all, NetworkMode::OwnIp, None).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert!(
            rendered.contains("egress\n  allow all\n"),
            "an opted-out bare box must show allow-all: {rendered}"
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
    /// refusal surfaces as a sentence, not a failed activation.
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
        let handed = register_box_for_activation(&global, NetworkMode::OwnIp, "web", &policy)
            .await
            .expect("the registration is answered with addresses");
        assert_eq!(
            handed.switch_address,
            std::net::Ipv4Addr::new(100, 64, 0, 2)
        );
        assert_eq!(
            handed.loopback_address,
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
            assert_eq!(request.ingress_ports, vec![8080, 5432]);
            assert_eq!(request.egress.as_ref(), policy.egress.as_ref());
        }

        // Every other shape of activation registers nothing: a native
        // daemon has no box table, a host-ip box shares the node's own row.
        // Neither touches a socket, so a plain global (no provider, no
        // dir) suffices.
        let native = GlobalArgs::default();
        assert!(
            register_box_for_activation(&native, NetworkMode::OwnIp, "web", &policy)
                .await
                .is_none(),
            "a native daemon hosts no box table to register on"
        );
        let vm_host = GlobalArgs {
            provider: Some(Provider::LocalMinvmd),
            ..Default::default()
        };
        assert!(
            register_box_for_activation(&vm_host, NetworkMode::HostNet, "web", &policy)
                .await
                .is_none(),
            "a host-ip box shares the node's own row and registers nothing"
        );

        // The refusal shape: a daemon that answers with a reason produces an
        // error naming it — what the activation warns on and continues
        // from, never a failed create.
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
            },
        )
        .await
        .expect_err("a refused registration is an error");
        assert!(
            refused.to_string().contains("address plan is exhausted"),
            "the refusal surfaces with its reason: {refused}"
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
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        // The withdrawal the destroy side owes: the pair comes off the
        // session record, the control socket off the provider dir the
        // daemon connection resolves through.
        withdraw_box_row(vm_host_control_sock(&global), Some("web"), Some(handed)).await;
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
        }

        // And a session that registered nothing owes nothing: no pair, no
        // name, no VM host — each sends nothing, on the same socket.
        withdraw_box_row(vm_host_control_sock(&global), Some("web"), None).await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no pair on the record, no withdrawal"
        );
        withdraw_box_row(vm_host_control_sock(&global), None, Some(handed)).await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no name on the record, no withdrawal"
        );
        let native = GlobalArgs::default();
        withdraw_box_row(vm_host_control_sock(&native), Some("web"), Some(handed)).await;
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "no VM host to withdraw from, no withdrawal"
        );
    }
}
