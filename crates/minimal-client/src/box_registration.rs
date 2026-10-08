//! An own-address box's registration with the VM host daemon (T66,
//! NET-133, NET-138), shared by the `min` CLI and `min dash` so the two
//! front-ends register, hold, commit, withdraw and resume a box's host row
//! the same way: one control-socket exchange per verb, the registration's
//! lease held until the session is active, the creator's withdrawal on
//! every failure after the row exists, and the resume before an attach or
//! an exec. Prompts and rendering stay with the front-ends; every line this
//! module writes is a log line.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// How long a box control request — a registration, or the withdrawal of
/// the row a registration bought — may take before this invocation gives
/// up on it. The control socket answers with map writes and an allocation,
/// so healthy is milliseconds; the bound exists so a hung VM host daemon
/// cannot hang the activation or destroy the user asked for.
pub const BOX_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One control-socket exchange with the VM host daemon (T66): one JSON
/// line in — the verb's request — and one line out — the untagged reply
/// the verb is answered with.
///
/// The control socket lives beside the ssh socket in the minvmd
/// provider-instance dir — the dir the daemon connection resolves through.
/// A refusal (an exhausted address plan, a malformed declaration, a pair
/// that is not the row's) surfaces here as an error naming the reason; a
/// failed registration fails the activation it was for — the session does
/// not start with the box unregistered — while a failed withdrawal
/// degrades to a warning rather than failing the destroy it rides on.
pub async fn control_request_with_vm_host(
    sock_path: &Path,
    request: minimald_rpc::BoxControlRequest,
) -> anyhow::Result<minimald_rpc::BoxControlReply> {
    control_exchange_with_vm_host(sock_path, request)
        .await
        .map(|(reply, _stream)| reply)
}

/// [`control_request_with_vm_host`] that hands the connection back beside
/// the reply, for a verb whose connection outlives its one exchange — the
/// held registration's lease ([`BoxLease`]).
async fn control_exchange_with_vm_host(
    sock_path: &Path,
    request: minimald_rpc::BoxControlRequest,
) -> anyhow::Result<(minimald_rpc::BoxControlReply, tokio::net::UnixStream)> {
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
    // The daemon writes nothing past its one reply line until the client
    // writes again, so the reader buffers nothing the connection still owes.
    tokio::io::BufReader::new(&mut stream)
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
    Ok((reply, stream))
}

/// A held registration's lease ([`minimald_rpc::RegisterBoxRequest::hold`]):
/// the connection the registration was answered on, kept open while the
/// activation runs. Dropping it uncommitted — an activation that fails, is
/// interrupted, or dies — closes the connection, and the VM host daemon
/// withdraws the row on that close, so a row whose activation never went
/// active does not hold its name until the daemon restarts. [`Self::commit`]
/// keeps the row once the session is active.
#[derive(Debug)]
pub struct BoxLease {
    stream: tokio::net::UnixStream,
}

impl BoxLease {
    /// Commit the lease: write the one commit line and close, so the row
    /// stays when the connection does. A commit that cannot be written is
    /// a daemon that already closed the lease — one that predates leases
    /// and answered one-shot, or one that went away — and is logged, not
    /// fatal: the session is already active.
    pub async fn commit(mut self) {
        use tokio::io::AsyncWriteExt as _;
        let line = format!("{}\n", minimald_rpc::REGISTRATION_COMMIT_LINE);
        match tokio::time::timeout(BOX_CONTROL_TIMEOUT, self.stream.write_all(line.as_bytes()))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "could not commit the box's registration lease");
            }
            Err(_) => tracing::debug!(
                "the box's registration lease commit did not complete in {BOX_CONTROL_TIMEOUT:?}"
            ),
        }
    }
}

/// Run `finalize` — the step that makes the session active — with the
/// registration's lease held across it, and commit the lease only when it
/// succeeds. A failure drops the lease uncommitted, so the VM host daemon
/// withdraws the row with the activation.
pub async fn finalize_holding_lease<T>(
    lease: Option<BoxLease>,
    finalize: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let finalized = finalize.await;
    if finalized.is_ok()
        && let Some(lease) = lease
    {
        lease.commit().await;
    }
    finalized
}

/// What a successful registration with the VM host daemon hands the
/// activating client back (T66, NET-133): the addresses the create request
/// carries, and the box's own id when the daemon's reply named one — the
/// id the host minted for this creation, which the published row holds and
/// its attachment carries. This is the client's record of that id; the
/// client never sends one. A reply that carries no id — from a daemon that
/// predates ids — is still a successful registration: the client simply
/// records no id, and the row and its attachment name the box host-side as
/// ever.
#[derive(Debug)]
pub struct RegisteredWithVmHost {
    /// The addresses the create request carries, so the in-VM daemon
    /// attaches with the handed switch address instead of drawing its own.
    pub addresses: sessions::BoxAddresses,
    /// The box's own id the reply returned — 32 hex digits on the wire,
    /// the one spelling the row, the attachment and a diagnostic all name
    /// it by — or `None` when the answering daemon predates ids.
    pub box_id: Option<minimald_rpc::BoxId>,
    /// The task addresses filed with the box (NET-138), which the create
    /// request carries so the box's task runs attach at them instead of
    /// drawing; empty from a daemon that predates them.
    pub task_addresses: Vec<std::net::Ipv4Addr>,
    /// The registration's lease, held until the session is active and
    /// committed then; `None` from a daemon that predates ids, which
    /// predates leases too and answered one-shot.
    pub lease: Option<BoxLease>,
}

/// Registers an own-address box with the VM host daemon over its control
/// socket (T66), returning what it handed back.
pub async fn register_box_with_vm_host(
    sock_path: &Path,
    request: minimald_rpc::RegisterBoxRequest,
) -> anyhow::Result<RegisteredWithVmHost> {
    let (reply, stream) = control_exchange_with_vm_host(
        sock_path,
        minimald_rpc::BoxControlRequest::Register(request),
    )
    .await?;
    match reply {
        // The answer a daemon this build boots beside sends: the addresses
        // beside the id the published row holds, on the connection a held
        // registration keeps as its lease.
        minimald_rpc::BoxControlReply::Registered(web) => Ok(RegisteredWithVmHost {
            addresses: sessions::BoxAddresses {
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            },
            box_id: Some(web.box_id),
            task_addresses: web.task_addresses,
            lease: Some(BoxLease { stream }),
        }),
        // A daemon that predates ids answers with the bare pair the
        // registration has always been answered with.
        minimald_rpc::BoxControlReply::Addresses(addresses) => Ok(RegisteredWithVmHost {
            addresses,
            box_id: None,
            task_addresses: Vec::new(),
            lease: None,
        }),
        minimald_rpc::BoxControlReply::Error { error } => {
            anyhow::bail!("the VM host daemon refused the box registration: {error}")
        }
        // The reply shapes are disjoint, so this arm is a daemon speaking
        // another verb's answer to a register — not an address pair either
        // way, so the registration did not happen.
        minimald_rpc::BoxControlReply::Status(status) => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with its \
                 answerer status {status:?}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::Row(row) => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with the box \
                 row {row:?}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::NoRow { name, .. } => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with the no-row \
                 marker for {name:?}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::RowStanding { switch_address, .. } => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with the row-standing \
                 read for {switch_address}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::NameHeld { name, .. } => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with the name-hold \
                 marker for {name:?}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::PortRecorded { port, .. } => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with the port \
                 report {port}; the registration did not happen"
            )
        }
        minimald_rpc::BoxControlReply::AnswererRelease { .. } => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with an \
                 answerer release reply; the registration did not happen"
            )
        }
        other @ (minimald_rpc::BoxControlReply::AsksSubscribed { .. }
        | minimald_rpc::BoxControlReply::PendingAskOffer(_)
        | minimald_rpc::BoxControlReply::PendingAskDismissed { .. }
        | minimald_rpc::BoxControlReply::AskAnswerRecorded { .. }
        | minimald_rpc::BoxControlReply::AskAdmit(_)
        | minimald_rpc::BoxControlReply::AskAlreadyEnded { .. }) => {
            anyhow::bail!(
                "the VM host daemon answered the box registration with an ask \
                 verb's reply {other:?}; the registration did not happen"
            )
        }
    }
}

/// Withdraws the box's host row (T66) when the session that registered it
/// is gone — destroyed, or an activation that failed after registering:
/// the row has no holder left, so its creator presents the pair the
/// registration handed back and the daemon stops the pair's addresses
/// admitting anything.
///
/// Always quiet when it owes nothing: a session that registered no box — a
/// native host, a host-ip box sharing the node's own row, a refused
/// registration — withdraws nothing and says nothing. In particular it
/// never releases a held `host_ip` name: an activation that failed holds
/// none (the hold is made only once the session is active), and the name
/// may be a live session's — an autogen collision is exactly that — so
/// only the destroy of the session that held it releases it. A withdrawal
/// that cannot be made — no control socket, a daemon that predates the
/// verb and refuses the line, the deadline — leaves the row published and
/// warns rather than failing the destroy or the activation error it rides
/// on; the daemon restarting between registration and withdrawal answers
/// the withdrawal as already gone, which is the goal state either way.
/// `box_id` is the id the registration handed back beside the pair, where
/// the caller still holds it — an activation failing after it registered —
/// so the withdrawal removes only that box; a destroy, reading the pair
/// from the session record, has none and passes `None`.
pub async fn withdraw_box_row(
    control_sock: Option<PathBuf>,
    name: Option<&str>,
    box_addresses: Option<sessions::BoxAddresses>,
    box_id: Option<minimald_rpc::BoxId>,
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
    // The exchange itself is the client library's, shared with the
    // dashboard's destroy and the after-attach release; it blocks, so it
    // runs off the runtime under this side's own deadline.
    let box_name = name.to_string();
    let withdrawn = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            crate::attach::withdraw_box_row_at(&sock_path, &box_name, addresses, box_id)
        }),
    )
    .await;
    if withdrawn.is_err() {
        tracing::warn!(
            after = ?BOX_CONTROL_TIMEOUT,
            box = %name,
            "the VM host daemon did not answer the box row withdrawal in \
             time; the row stays published"
        );
    }
}

/// Asks the VM host daemon beside `sock` for the session's box row back
/// before an attach or an exec runs in the box (NET-138): the box's host
/// may have ended and stayed down past the daemon's detach grace, or the
/// daemon may have restarted under the session, and the in-VM daemon
/// relaunches a box's host only while the host's row stands for it. The
/// creator — this client, presenting the name and the pair `record`
/// carries — is the one side that may ask; the daemon reinstates the row
/// from its own record of the registration. Best-effort, bounded by
/// [`BOX_CONTROL_TIMEOUT`], and silent for a session with no box row (a
/// native host, a `host_ip` or `none` box).
pub async fn resume_box_row(sock: &Path, record: Option<&sessions::Record>) {
    let Some(control_sock) = control_sock_beside(sock) else {
        return;
    };
    let Some((name, addresses)) =
        record.and_then(|record| Some((record.name.clone()?, record.box_addresses?)))
    else {
        return;
    };
    let box_name = name.clone();
    let resumed = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            crate::attach::resume_box_row_at(&control_sock, &box_name, addresses, None)
        }),
    )
    .await;
    if resumed.is_err() {
        tracing::warn!(
            after = ?BOX_CONTROL_TIMEOUT,
            box = %name,
            "the VM host daemon did not answer the box row resume in time"
        );
    }
}

/// Registers this activation's box with the VM host daemon, when the daemon
/// this invocation talks to is minvmd-backed (T66), returning what it handed
/// back — `Ok(None)` when there is nothing to register.
///
/// The box this activation creates is registerable only when the daemon
/// connection resolves through minvmd — `kind`, the CLI's provider kind, never
/// `use_minvmd()`: the flag is how Linux asks for the VM host, and macOS
/// reaches it with no flag at all, so keying on the flag would leave a macOS
/// box with no row and its declared egress applied nowhere — and only when
/// it is an own-address box: a `host_ip` box shares the node's own row in
/// the host table, and a `none` box has no switch address at all — both
/// register nothing and attach exactly as they always have. A `host_ip`
/// box's name is held in the zone instead (best-effort, NODATA rather than
/// NXDOMAIN), but only once its session is active.
///
/// The box's own id comes back with it (NET-133): the request carries no
/// id, the host mints one for this creation, and the reply returns the id
/// the published row holds, which the client records — so the CLI, the row
/// and the attachment all carry the one id per box: the id a delivered
/// connection is attributed by. Every registration is a new creation with a
/// new id, the autospawn retry's re-registration included. A daemon that
/// predates ids answers with the bare pair; that registration succeeded
/// too, and the client records no id.
///
/// A registration that cannot be made — an unresolvable provider dir, a
/// refusal, the deadline — fails the activation with its cause rather than
/// degrading to a warning: a box that went on to create unregistered would
/// run with no host-side row holding it (NET-138), its frames unattributed
/// and its declared egress decided by no row the host gate (NET-081) reads,
/// so the session does not start half-admitted. The error is the one line
/// session start owes this failure.
pub async fn register_box_for_activation(
    kind: paths::ProviderKind,
    minimal_dir: Option<&Path>,
    network: sessions::NetworkMode,
    name: &str,
    policy: &sessions::SessionPolicy,
) -> anyhow::Result<Option<RegisteredWithVmHost>> {
    if kind != paths::ProviderKind::Minvmd || network != sessions::NetworkMode::OwnIp {
        return Ok(None);
    }
    // The control socket sits beside the ssh socket in the provider dir the
    // daemon connection resolves through, so the client finds both by the
    // same rule — named VMs included, since the resolution reads the same
    // process-global VM name.
    let ssh_sock = crate::resolve_socket_path(minimal_dir, true)
        .context("resolving the VM host provider dir to register the box's host row")?;
    let sock_path = control_sock_beside(&ssh_sock)
        .ok_or_else(|| anyhow::anyhow!("no provider dir resolved for the ssh socket"))?;
    register_box_at(&sock_path, name, policy).await.map(Some)
}

/// Registers an own-address box under `name` with the VM host daemon whose
/// control socket a dashboard reached the daemon beside (T66): the
/// dashboard's half of [`register_box_for_activation`], keyed on the socket
/// it already holds rather than on the provider kind. A daemon with no
/// control socket beside its ssh socket is a native host, which keeps its
/// own allocator, and a box that is not own-address has no row to register:
/// both answer `Ok(None)`, and the create goes ahead as it always has.
pub async fn register_box_beside(
    ssh_sock: &Path,
    network: sessions::NetworkMode,
    name: &str,
    policy: &sessions::SessionPolicy,
) -> anyhow::Result<Option<RegisteredWithVmHost>> {
    if network != sessions::NetworkMode::OwnIp {
        return Ok(None);
    }
    let Some(sock_path) = control_sock_beside(ssh_sock).filter(|sock| sock.exists()) else {
        return Ok(None);
    };
    register_box_at(&sock_path, name, policy).await.map(Some)
}

/// The control socket beside an ssh socket a client already resolved (T66's
/// rule, one definition for every caller): the VM host daemon serves both
/// from the same provider dir.
pub fn control_sock_beside(ssh_sock: &Path) -> Option<PathBuf> {
    ssh_sock
        .parent()
        .map(|dir| dir.join(crate::attach::VM_HOST_CONTROL_SOCK_FILE))
}

/// The registration exchange both front-ends make, on the control socket
/// `sock_path`: the box's declaration in, held as a lease, bounded by
/// [`BOX_CONTROL_TIMEOUT`], with the failure the activation ends with.
async fn register_box_at(
    sock_path: &Path,
    name: &str,
    policy: &sessions::SessionPolicy,
) -> anyhow::Result<RegisteredWithVmHost> {
    // The declaration, as this activation expanded it: the ingress rules
    // reduced to the external ports they admit — the shape the host row
    // holds — and the egress policy verbatim. No box id: the host mints
    // one for this creation (NET-133).
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
        credentialed_upstream: policy.credentialed_upstream.clone(),
        // The dynamic-ingress grant (NET-045, NET-138), from the same
        // create inputs the session record holds: the stance and the range
        // the host-side row holds every runtime port report against — the
        // half of the grant the host decides by, never something the guest
        // could bring with its report. Absent fields carry the deny
        // default the host's row fills in: nothing is permitted.
        dynamic_ingress: policy
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_ingress),
        dynamic_allowed_range: policy
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_allowed_range),
        // The row is held as a lease until the session is active: an
        // activation that dies before then — an interrupt, a crash, a
        // withdrawal that never lands — leaves no row holding its name.
        hold: true,
        // The task addresses the box's task runs attach at, filed with the
        // box so the in-VM daemon draws nothing for a task (NET-138).
        task_slots: minimald_rpc::TASK_SLOTS_PER_BOX,
    };
    let registration = tokio::time::timeout(
        BOX_CONTROL_TIMEOUT,
        register_box_with_vm_host(sock_path, request),
    )
    .await;
    match registration {
        Ok(Ok(web)) => {
            tracing::info!(
                box = %name,
                box_id = %web
                    .box_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                switch_address = %web.addresses.switch_address,
                loopback_address = %web.addresses.loopback_address,
                "registered the box with the VM host daemon; its addresses are \
                 the host table's to decide by"
            );
            Ok(web)
        }
        Ok(Err(error)) => Err(error.context(
            "registering the box with the VM host daemon failed; the session \
             does not start with the box unregistered",
        )),
        Err(_) => Err(anyhow::anyhow!(
            "the VM host daemon did not answer the box registration in \
             {BOX_CONTROL_TIMEOUT:?}; the session does not start with the box \
             unregistered"
        )),
    }
}

/// [`register_box_for_activation`] for an activation whose session name may
/// be autogen. The VM host daemon refuses a registration whose name folds
/// to one a live row already holds; for an autogen `name` that refusal is a
/// name collision like the create's, so the name is re-minted with `remint`
/// and registered again, within the bounded budget
/// ([`crate::session_name::should_retry_autogen`]) the `CreateSession`
/// collision retry spends — `attempts` is shared with
/// it. A refused registration publishes no row, so nothing is withdrawn
/// between attempts. A user-supplied name, any other failure, and a spent
/// budget surface the error unchanged. The refusal is matched across the
/// whole error chain: the daemon's reason is its innermost cause.
#[allow(clippy::too_many_arguments)]
pub async fn register_box_reminting_autogen(
    kind: paths::ProviderKind,
    minimal_dir: Option<&Path>,
    network: sessions::NetworkMode,
    name: &mut String,
    policy: &sessions::SessionPolicy,
    autogen: bool,
    attempts: &mut u32,
    remint: impl FnMut() -> String,
) -> anyhow::Result<Option<RegisteredWithVmHost>> {
    let target = VmHost::Provider { kind, minimal_dir };
    reminting_autogen(target, network, name, policy, autogen, attempts, remint).await
}

/// [`register_box_beside`] for a dashboard create whose session name may be
/// autogen, re-minting a held autogen name exactly as
/// [`register_box_reminting_autogen`] does for the CLI's activation.
pub async fn register_box_beside_reminting_autogen(
    ssh_sock: &Path,
    network: sessions::NetworkMode,
    name: &mut String,
    policy: &sessions::SessionPolicy,
    autogen: bool,
    attempts: &mut u32,
    remint: impl FnMut() -> String,
) -> anyhow::Result<Option<RegisteredWithVmHost>> {
    let target = VmHost::Beside(ssh_sock);
    reminting_autogen(target, network, name, policy, autogen, attempts, remint).await
}

/// Where a registration finds the VM host daemon's control socket: by the
/// provider kind the CLI's daemon connection resolves through
/// ([`register_box_for_activation`]), or beside the ssh socket a dashboard
/// already holds ([`register_box_beside`]).
#[derive(Clone, Copy)]
enum VmHost<'a> {
    Provider {
        kind: paths::ProviderKind,
        minimal_dir: Option<&'a Path>,
    },
    Beside(&'a Path),
}

/// The re-mint loop both registrations share: register under `name` on
/// `target`, and on a refusal that reads as an autogen name collision
/// within the budget, re-mint the name and register again.
async fn reminting_autogen(
    target: VmHost<'_>,
    network: sessions::NetworkMode,
    name: &mut String,
    policy: &sessions::SessionPolicy,
    autogen: bool,
    attempts: &mut u32,
    mut remint: impl FnMut() -> String,
) -> anyhow::Result<Option<RegisteredWithVmHost>> {
    loop {
        let registered = match target {
            VmHost::Provider { kind, minimal_dir } => {
                register_box_for_activation(kind, minimal_dir, network, name, policy).await
            }
            VmHost::Beside(ssh_sock) => register_box_beside(ssh_sock, network, name, policy).await,
        };
        match registered {
            Err(error)
                if crate::session_name::should_retry_autogen(
                    autogen,
                    *attempts,
                    &format!("{error:#}"),
                ) =>
            {
                *attempts += 1;
                *name = remint();
            }
            registered => return registered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registration's lease is held across the finalize — the daemon
    /// sees neither a byte nor a close while it runs — and committed only
    /// when it succeeds: one commit line, then the close. A failed finalize
    /// closes the lease with no commit, the close the daemon withdraws on.
    #[tokio::test]
    async fn finalize_holding_lease_commits_only_on_success() {
        use tokio::io::AsyncReadExt as _;

        async fn lease_pair(
            listener: &tokio::net::UnixListener,
            sock_path: &std::path::Path,
        ) -> (BoxLease, tokio::net::UnixStream) {
            let (client, accepted) = tokio::join!(
                tokio::net::UnixStream::connect(sock_path),
                listener.accept()
            );
            (
                BoxLease {
                    stream: client.expect("the lease connects"),
                },
                accepted.expect("the daemon side accepts").0,
            )
        }

        /// Whether the daemon side has seen nothing — no byte, no close —
        /// within a short wait.
        async fn untouched(daemon: &mut tokio::net::UnixStream) -> bool {
            let mut buf = [0u8; 16];
            tokio::time::timeout(std::time::Duration::from_millis(50), daemon.read(&mut buf))
                .await
                .is_err()
        }

        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let (lease, mut daemon) = lease_pair(&listener, &sock_path).await;
        let finalized = finalize_holding_lease(Some(lease), async {
            assert!(
                untouched(&mut daemon).await,
                "the lease is held, uncommitted, while the finalize runs"
            );
            Ok(7)
        })
        .await
        .expect("the finalize succeeds");
        assert_eq!(finalized, 7);
        let mut seen = String::new();
        daemon.read_to_string(&mut seen).await.unwrap();
        assert_eq!(
            seen,
            format!("{}\n", minimald_rpc::REGISTRATION_COMMIT_LINE),
            "a finalized session commits its lease, then closes it"
        );

        let (lease, mut daemon) = lease_pair(&listener, &sock_path).await;
        let failed = finalize_holding_lease(Some(lease), async {
            assert!(
                untouched(&mut daemon).await,
                "the lease is held, uncommitted, while the finalize runs"
            );
            Err::<(), _>(anyhow::anyhow!("finalize failed"))
        })
        .await;
        assert!(failed.is_err(), "the finalize's failure surfaces unchanged");
        let mut seen = String::new();
        daemon.read_to_string(&mut seen).await.unwrap();
        assert!(
            seen.is_empty(),
            "a failed finalize closes the lease uncommitted, got {seen:?}"
        );

        finalize_holding_lease(None, async { Ok(()) })
            .await
            .expect("a registration with no lease finalizes as ever");
    }
}
