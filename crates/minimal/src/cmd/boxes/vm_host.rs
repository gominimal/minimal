//! The session commands' exchange with the VM host daemon: its control
//! socket, the box row and the held box name.

use super::*;

// The box registration exchange with the VM host daemon (T66) — the
// register, its lease, the withdrawal and the resume — is the client
// library's, shared with `min dash` so the two front-ends cannot drift.
pub(crate) use minimal_client::box_registration::withdraw_box_row;
use minimal_client::box_registration::{BOX_CONTROL_TIMEOUT, control_request_with_vm_host};
#[cfg(test)]
use minimal_client::box_registration::{
    register_box_for_activation, register_box_reminting_autogen, register_box_with_vm_host,
    resume_box_row,
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
/// reached a VM on is the one to find that VM's control socket beside. A
/// native minimald serves its answerer control socket (`minimald`'s
/// `rpc::ANSWERER_CONTROL_SOCK_FILE`, the same file name) beside its ssh
/// socket too, answering the same status verb.
pub(crate) fn control_sock_beside(ssh_sock: &std::path::Path) -> Option<std::path::PathBuf> {
    ssh_sock
        .parent()
        .map(|dir| dir.join(minvmd::control::CONTROL_SOCK_FILE))
}

/// The control sockets of this state dir's running VM host daemons, for the
/// release the finalize-install script asks each daemon for. The enumeration
/// spans every VM that ever ran (NET-057), and a stopped VM's socket files
/// stay behind after its daemon exits, so a file's presence says nothing
/// about liveness: a control socket is kept only when a connection to it
/// succeeds at render time. A refused connection (a leftover file with no
/// listener) or a missing file is a daemon that is not running; it cannot
/// hold the hook port, so the script does not ask it to release it. Each
/// connection is bounded by [`client::PROBE_TIMEOUT`]: a daemon that does
/// not accept within it is skipped rather than stalling the render.
///
/// The probe runs when the script is rendered, not when it runs. A VM
/// started in between is not in the list, so if its daemon holds the hook
/// port then, the service start reports that it cannot take the port and
/// prints the remedy. Listing every enumerated VM instead would make the
/// release fail on any stopped VM's unreachable control socket.
pub(crate) async fn running_vm_controls(minimal_dir: Option<&std::path::Path>) -> Vec<String> {
    let mut running = Vec::new();
    let vms = client::enumerate_vm_sockets(minimal_dir, true).unwrap_or_default();
    for control in vms.iter().filter_map(|vm| control_sock_beside(&vm.sock)) {
        let probe = tokio::net::UnixStream::connect(&control);
        if let Ok(Ok(_)) = tokio::time::timeout(client::PROBE_TIMEOUT, probe).await {
            running.push(control.display().to_string());
        }
    }
    running
}

/// The host reads `min finalize-install` decides its script from (NET-122): this
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
    // own state dir's — its running VM host daemons or its native
    // daemon — never another state dir's.
    let controls = match daemon_provider_kind(global) {
        paths::ProviderKind::Minvmd => running_vm_controls(global.minimal_dir.as_deref()).await,
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
/// VM host daemon's socket or a native minimald's answerer control socket,
/// which answers the same status verb — `min ls` reads each listed VM's own
/// state beside the ssh socket its listing reached that VM on (NET-057's
/// enumeration), and the native fallback listing's beside its daemon's, so
/// the socket is the caller's to name.
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
    crate::resolver::vm_host_answerer_line(status).map(|line| format!("DNS service: {line}"))
}

/// Releases the zone hold a destroyed session's activation made, when the
/// session registered no row (`box_addresses` is `None` — a `host_ip` box
/// holds its name in place of a row): the destroy-side twin of the hold
/// [`activate_box`] makes once the session is active. Best-effort and
/// warn-only like the hold; a name no hold kept is the goal state already
/// holding, so a `none` box's release changes nothing. The release names
/// the session `id`, so it frees only that session's hold, never a newer
/// session's under the same name.
pub(crate) async fn release_held_box_name(
    control_sock: Option<std::path::PathBuf>,
    id: boxes::SessionId,
    name: Option<&str>,
    box_addresses: Option<boxes::BoxAddresses>,
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
pub(super) async fn attached_box_record(
    sock: &std::path::Path,
    id: boxes::SessionId,
) -> anyhow::Result<Option<boxes::Record>> {
    box_record_by(sock, minimald_rpc::GetSessionRecordRequest::Id(id)).await
}

/// A session's record by `request`, bounded by [`BOX_CONTROL_TIMEOUT`]:
/// `None` when no session answers to it.
async fn box_record_by(
    sock: &std::path::Path,
    request: minimald_rpc::GetSessionRecordRequest,
) -> anyhow::Result<Option<boxes::Record>> {
    use minimald_rpc::GetSessionRecord;
    tokio::time::timeout(BOX_CONTROL_TIMEOUT, async {
        let mut client = client::Client::connect(sock).await?;
        let resp = client
            .oneshot_rpc::<GetSessionRecord>(request)
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
/// [`destroy_box`], and this is the release that destroy would have
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
/// A destroy no client of this host issues — the daemon's own reap —
/// releases nothing: the in-VM daemon sends no hold verb. That hold, like
/// one whose release was lost, stands until the VM host daemon's next
/// restart, after which it is dropped unless a client's attach or exec
/// re-makes it. The hold blocks nothing meanwhile — a
/// registration under the name is checked against rows and creations,
/// never holds, and a new session's hold of the name takes it over — so
/// all it keeps is the name answering NODATA, not NXDOMAIN.
pub(crate) async fn release_held_name_after_attach(
    sock: &std::path::Path,
    id: boxes::SessionId,
    name: &str,
    box_addresses: Option<boxes::BoxAddresses>,
) {
    match attached_box_record(sock, id).await {
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

/// Re-sends the name hold an interactive attach or exec on a VM-backed
/// host depends on, best-effort, before the attach or the exec passes.
/// A VM host daemon restarts quickly and holds lived only in its memory
/// before they were persisted, so a hold this session bought — or a hold
/// a persisted registry failed to carry, its write a warn line — may be
/// gone by the time the attach lands; the re-hold is idempotent, so it
/// remakes the hold and the name answers NODATA through the attach
/// either way. Only a named `host_ip` session without a box row needs
/// it: a box that registered a row owns its name through the row, which
/// `resume_box_row` re-sends, and a `none` or `own_ip` session holds
/// nothing.
///
/// The record was read before the hold, so a destroy another client
/// issues in between can release the session's holds first and leave
/// this one standing for a session that is gone — until the VM host
/// daemon's next restart, which drops a reloaded hold nothing re-makes.
/// The session is looked up again once the hold
/// is made, and a session gone by then has the hold undone: a destroy
/// that lands after that lookup releases it itself. A live session that
/// took the name over in between had its hold taken over by this one, so
/// the undo hands the hold back to it rather than releasing the name; with
/// no such session, the hold is released by the gone session's id; a name
/// lookup that fails tells neither, and the hold is left as made. A hold the
/// VM host daemon did not make — one that predates the verbs, or did not
/// answer — leaves nothing to undo, so neither the second lookup nor the
/// release is made.
pub(crate) async fn rehold_held_name_before_attach(
    sock: &std::path::Path,
    id: boxes::SessionId,
    record: Option<&boxes::Record>,
) {
    let Some(record) = record else {
        return;
    };
    if record.network != boxes::NetworkMode::HostNet {
        return;
    }
    if record.box_addresses.is_some() {
        return;
    }
    let Some(name) = record.name.as_deref() else {
        return;
    };
    if !hold_box_name_with_vm_host(control_sock_beside(sock), name, Some(id), true).await {
        return;
    }
    if let Ok(None) = attached_box_record(sock, id).await {
        let by_name = box_record_by(
            sock,
            minimald_rpc::GetSessionRecordRequest::Name(name.to_string()),
        )
        .await;
        match rehold_undo(id, by_name) {
            Some((holder, hold)) => {
                hold_box_name_with_vm_host(control_sock_beside(sock), name, Some(holder), hold)
                    .await;
            }
            None => tracing::debug!(
                box = %name,
                "could not tell who answers to the name now; the re-hold stays"
            ),
        }
    }
}

/// The undo of a re-hold made for session `id`, found gone since, from the
/// lookup of its name (`by_name`): the session to send the verb for and
/// whether the verb is a hold. A live `host_ip` session without a row that
/// answers to the name now is handed the hold back; no such session, and
/// the hold is released by `id`. A lookup that failed tells neither, so
/// nothing is undone (`None`): a release there could take the name from a
/// live session, and a hold left standing blocks nothing.
fn rehold_undo(
    id: boxes::SessionId,
    by_name: anyhow::Result<Option<boxes::Record>>,
) -> Option<(boxes::SessionId, bool)> {
    let taken_over_by = by_name.ok()?.filter(|other| {
        other.id != id
            && other.network == boxes::NetworkMode::HostNet
            && other.box_addresses.is_none()
    });
    Some(taken_over_by.map_or((id, false), |other| (other.id, true)))
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
/// frees only that session's hold. Returns whether the VM host daemon
/// answered the verb: `false` for no VM host daemon to ask, a refusal, or
/// no answer.
pub(crate) async fn hold_box_name_with_vm_host(
    control_sock: Option<std::path::PathBuf>,
    name: &str,
    id: Option<boxes::SessionId>,
    hold: bool,
) -> bool {
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
        return false;
    };
    let sent = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        control_request_with_vm_host(&sock_path, verb),
    )
    .await;
    // The reply's fields are not checked against the request: minvmd
    // builds `NameHeld` from the request itself — `hold_box_name` answers
    // `{name: request.name, held: true}` and `release_box_name` answers
    // `{name: request.name, held: false}`, unconditionally
    // (crates/minvmd/src/control.rs) — so a reply naming another name or
    // state cannot come from a VM host daemon that answered this request;
    // it would be a protocol bug on that side, which a client-side check
    // would not repair. Any other verb's reply, a refusal, or no answer
    // is reported as a failure below.
    let failure = match sent {
        Ok(Ok(minimald_rpc::BoxControlReply::NameHeld { .. })) => None,
        Ok(Ok(other)) => Some(format!("another verb's reply: {other:?}")),
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some(format!("no answer within {BOX_CONTROL_TIMEOUT:?}")),
    };
    if let Some(reason) = &failure {
        tracing::warn!(
            box = %name,
            operation,
            "the box name {operation} could not be made ({reason}); the name \
             answers as it did before"
        );
    }
    failure.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::{IngressPolicy, IpProto, NetworkMode, PortMapping};

    /// The finalize-install script's controls span only the VM host daemons
    /// whose daemon is listening: a stopped VM's state dir is still
    /// enumerated (NET-057) and its socket files stay behind after its
    /// daemon exits, so a leftover file with no listener is skipped, and a
    /// daemon that cannot hold the hook port is not asked to release it.
    #[tokio::test]
    async fn running_vm_controls_skip_a_stopped_named_vm() {
        let base = tempfile::tempdir().unwrap();
        let provider = base.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider).unwrap();
        // A running named VM: its bridge and control sockets are listening,
        // so its daemon's control socket is asked for the release.
        let alpha = provider.join("alpha");
        std::fs::create_dir_all(&alpha).unwrap();
        let _alpha_bridge = std::os::unix::net::UnixListener::bind(alpha.join("ssh.sock")).unwrap();
        let _alpha_control =
            std::os::unix::net::UnixListener::bind(alpha.join("control.sock")).unwrap();
        // A stopped named VM that ran: both socket files remain, but nothing
        // listens behind them, so its daemon's control socket is not asked.
        let beta = provider.join("beta");
        std::fs::create_dir_all(&beta).unwrap();
        drop(std::os::unix::net::UnixListener::bind(beta.join("ssh.sock")).unwrap());
        drop(std::os::unix::net::UnixListener::bind(beta.join("control.sock")).unwrap());
        assert!(beta.join("ssh.sock").exists() && beta.join("control.sock").exists());
        assert_eq!(
            running_vm_controls(Some(base.path())).await,
            vec![alpha.join("control.sock").display().to_string()]
        );
    }

    /// A stopped default VM is skipped the same way: the default VM is always
    /// enumerated, so only a listener on its control socket would put its
    /// daemon in the script, and on a host where only a named VM runs there
    /// is none.
    #[tokio::test]
    async fn running_vm_controls_skip_a_stopped_default_vm() {
        let base = tempfile::tempdir().unwrap();
        let provider = base.path().join("providers").join("local-minvmd0");
        let gamma = provider.join("gamma");
        std::fs::create_dir_all(&gamma).unwrap();
        let _gamma_bridge = std::os::unix::net::UnixListener::bind(gamma.join("ssh.sock")).unwrap();
        let _gamma_control =
            std::os::unix::net::UnixListener::bind(gamma.join("control.sock")).unwrap();
        // The default VM ran once and stopped: its socket files remain in
        // the provider dir with no listener behind them.
        drop(std::os::unix::net::UnixListener::bind(provider.join("ssh.sock")).unwrap());
        drop(std::os::unix::net::UnixListener::bind(provider.join("control.sock")).unwrap());
        assert_eq!(
            running_vm_controls(Some(base.path())).await,
            vec![gamma.join("control.sock").display().to_string()]
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
        let policy = boxes::BoxPolicy {
            egress: Some(boxes::EgressPolicy {
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
            &boxes::BoxPolicy::default(),
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
        let policy = boxes::BoxPolicy {
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
        let addresses = boxes::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        let mut record = boxes::Record {
            id: boxes::SessionId::nil(),
            name: Some("web".to_string()),
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network: NetworkMode::OwnIp,
            policy: boxes::BoxPolicy {
                egress: None,
                ingress: None,
                credentialed_upstream: None,
            },
            status: boxes::BoxState::default(),
            hooks_enabled: true,
            task_addresses: Vec::new(),
            box_addresses: Some(addresses),
            host_ip_enforcement: None,
            box_id: None,
            host_row_bound: false,
            bound_ports: std::collections::BTreeSet::new(),
            sealed_deliveries: Vec::new(),
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
        let granted = boxes::BoxPolicy {
            egress: None,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: Some((3000, 3999)),
                dynamic_ingress: Some(boxes::DynamicIngress::Ask),
            }),
            credentialed_upstream: None,
        };
        let ungranted = boxes::BoxPolicy {
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
        let policy = boxes::BoxPolicy {
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
        let policy = boxes::BoxPolicy {
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
        let policy = boxes::BoxPolicy {
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
    /// who answers box names under the `DNS service:` label — this VM's
    /// host daemon when it holds the port, another VM host daemon when
    /// this VM's table is registered with it — and the pre-acquisition
    /// state prints nothing, exactly as its `min ls` line does.
    #[test]
    fn session_start_names_the_zone_answerer_at_every_start() {
        let holder =
            vm_host_answerer_start_line(minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 })
                .expect("a holder is a state to name");
        assert_eq!(
            holder,
            "DNS service: this VM's host daemon answers its box names on \
             127.0.0.1:7656 (UDP)",
            "the start line names this VM's host daemon as the holder"
        );
        let registered =
            vm_host_answerer_start_line(minimald_rpc::ZoneAnswererStatus::Registered {
                port: 7_656,
            })
            .expect("a registered table is a state to name");
        assert_eq!(
            registered,
            "DNS service: another VM host daemon answers this VM's box names \
             on 127.0.0.1:7656 (UDP)",
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
        let handed = boxes::BoxAddresses {
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
        let id = boxes::SessionId::nil();
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
        let handed = boxes::BoxAddresses {
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

    /// A finished task run releases the hold an attach or exec into its
    /// session may have re-made: one release naming the session and its
    /// id, since the daemon ends that session with no client destroy to
    /// release it. A kept session's hold is left for its destroy.
    #[tokio::test]
    async fn a_finished_task_run_releases_its_sessions_name_hold() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider_dir = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider_dir).unwrap();
        let requests = fake_vm_host(
            provider_dir.join("control.sock"),
            r#"{"name":"task-build-9c1e","held":false}"#.to_string(),
        )
        .await;
        let control_sock = || vm_host_control_sock(paths::ProviderKind::Minvmd, Some(dir.path()));
        let id = boxes::SessionId::nil();

        crate::task::release_task_name_hold(control_sock(), id, "task-build-9c1e", true).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "a kept session keeps its hold"
        );

        crate::task::release_task_name_hold(control_sock(), id, "task-build-9c1e", false).await;
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 1, "one release, one request");
        let minimald_rpc::BoxControlRequest::ReleaseBoxName(request) =
            serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type")
        else {
            panic!("the run's end is carried by the release verb");
        };
        assert_eq!(request.name, "task-build-9c1e");
        assert_eq!(
            request.session_id,
            Some(id),
            "the release names its session"
        );
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
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest {
                id,
                only_if_unfinalized: false,
            })
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

    /// The `host_ip` hold's attach side: a session's record is read before
    /// the attach or the exec on a VM-backed host, and its name hold —
    /// which a VM host daemon restart may have dropped — is re-made
    /// idempotently first: one hold request naming it and its session. A
    /// record the lookup did not give, or one that owns a row or holds no
    /// name, sends nothing; a session destroyed between the record's read
    /// and the hold has the hold released again.
    #[tokio::test]
    async fn an_attach_reholds_its_held_name_first() {
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
        let record = attached_box_record(&ssh_sock, id)
            .await
            .expect("the lookup does not fail")
            .expect("the session's record is read");
        assert_eq!(record.name.as_deref(), Some("web"));
        assert_eq!(record.network, boxes::NetworkMode::HostNet);
        assert!(record.box_addresses.is_none());

        // A record that is not there: nothing to re-hold by.
        rehold_held_name_before_attach(&ssh_sock, id, None).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "no record read, no hold re-made"
        );

        // The session's own hold, re-made before the attach.
        rehold_held_name_before_attach(&ssh_sock, id, Some(&record)).await;
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "one hold, one request");
            let minimald_rpc::BoxControlRequest::HoldBoxName(request) =
                serde_json_lenient::from_str(&seen[0]).expect("the request is the wire type")
            else {
                panic!("the re-hold is carried by the hold verb");
            };
            assert_eq!(request.name, "web");
            assert_eq!(
                request.session_id,
                Some(id),
                "the re-hold names the session, so it frees only that session's hold"
            );
        }

        // A destroy that lands between the record's read and the re-hold:
        // the hold is made for a session that is gone, and released again
        // by its id once the second lookup finds no session.
        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest {
                id,
                only_if_unfinalized: false,
            })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => panic!("the destroy failed: {error}"),
        }
        rehold_held_name_before_attach(&ssh_sock, id, Some(&record)).await;
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 3, "a hold, then its release");
        let minimald_rpc::BoxControlRequest::ReleaseBoxName(request) =
            serde_json_lenient::from_str(&seen[2]).expect("the request is the wire type")
        else {
            panic!("a gone session's re-hold is undone by the release verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(request.session_id, Some(id));
    }

    /// A destroy, then a new session under the same name, both landing
    /// between the record's read and the re-hold: the gone session's hold
    /// took the name over from the live one, so the undo hands it back to
    /// the live session by its id rather than releasing the name.
    #[tokio::test]
    async fn a_gone_sessions_rehold_hands_the_name_back_to_its_new_holder() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let requests = fake_vm_host(
            dir.path().join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"name":"web","held":true}"#.to_string(),
        )
        .await;
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&ssh_sock).await;
        let project = tempfile::TempDir::new().unwrap();
        let mut daemon = server.connect().await;
        let gone = minimald::test_harness::create_configured_session(
            &mut daemon,
            "web",
            project.path().to_str().unwrap(),
        )
        .await;
        let record = attached_box_record(&ssh_sock, gone)
            .await
            .expect("the lookup does not fail")
            .expect("the session's record is read");
        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest {
                id: gone,
                only_if_unfinalized: false,
            })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => panic!("the destroy failed: {error}"),
        }
        let live = minimald::test_harness::create_configured_session(
            &mut daemon,
            "web",
            project.path().to_str().unwrap(),
        )
        .await;

        rehold_held_name_before_attach(&ssh_sock, gone, Some(&record)).await;
        let seen = requests.lock().unwrap();
        let holds: Vec<_> = seen
            .iter()
            .map(|line| {
                match serde_json_lenient::from_str::<minimald_rpc::BoxControlRequest>(line)
                    .expect("the request is the wire type")
                {
                    minimald_rpc::BoxControlRequest::HoldBoxName(request) => {
                        (request.name, request.session_id)
                    }
                    other => panic!("only holds are sent: {other:?}"),
                }
            })
            .collect();
        assert_eq!(
            holds,
            vec![
                ("web".to_string(), Some(gone)),
                ("web".to_string(), Some(live)),
            ],
            "the gone session's re-hold, then the name handed back to the live one"
        );
    }

    /// The undo of a gone session's re-hold, by what the lookup of its name
    /// gave: a release by its id when no session answers to the name, and
    /// nothing at all when the lookup failed — a release there could free
    /// the name a live session holds.
    #[test]
    fn a_failed_name_lookup_undoes_no_rehold() {
        let id = boxes::SessionId::nil();
        assert_eq!(rehold_undo(id, Ok(None)), Some((id, false)));
        assert_eq!(
            rehold_undo(id, Err(anyhow::anyhow!("no answer"))),
            None,
            "a lookup that failed releases nothing"
        );
    }

    /// A re-hold the VM host daemon does not make — one that predates the
    /// hold verbs and refuses them — leaves nothing to undo: no second
    /// lookup and no release follow it, even for a session gone by then.
    #[tokio::test]
    async fn a_refused_rehold_is_not_undone() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let requests = fake_vm_host(
            dir.path().join(minvmd::control::CONTROL_SOCK_FILE),
            r#"{"error":"unknown verb"}"#.to_string(),
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
        let record = attached_box_record(&ssh_sock, id)
            .await
            .expect("the lookup does not fail")
            .expect("the session's record is read");
        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest {
                id,
                only_if_unfinalized: false,
            })
            .await
        {
            minimald_rpc::Errorable::Ok(_) => {}
            minimald_rpc::Errorable::Err { error } => panic!("the destroy failed: {error}"),
        }

        rehold_held_name_before_attach(&ssh_sock, id, Some(&record)).await;
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 1, "the refused hold, and nothing after it");
        assert!(matches!(
            serde_json_lenient::from_str::<minimald_rpc::BoxControlRequest>(&seen[0])
                .expect("the request is the wire type"),
            minimald_rpc::BoxControlRequest::HoldBoxName(_)
        ));
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
        let handed = boxes::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };

        release_held_name_after_attach(&ssh_sock, id, "web", Some(handed)).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "a session still there keeps its row"
        );

        match daemon
            .call::<minimald_rpc::DestroySession>(&minimald_rpc::DestroySessionRequest {
                id,
                only_if_unfinalized: false,
            })
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
        let policy = boxes::BoxPolicy::default();
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
        let handed = boxes::BoxAddresses {
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
        activate_box(&global, args, false).await.expect(
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
    /// `activate_box`, so the path proven is the user's: the refusal
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
        let error = activate_box(&global, args, false)
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
