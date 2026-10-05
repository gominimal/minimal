//! The VM host daemon's box control socket (T66) — the one host-side door a
//! client has to the box table ([`crate::box_registry`], NET-138).
//!
//! On a minvmd-backed host, `min session activate` registers every
//! own-address box here before it creates the session: it writes one
//! [`minimald_rpc::BoxControlRequest`] line asking `register`, the daemon
//! allocates the box's switch and loopback addresses into the table — the
//! row the host-side egress gate decides every frame by — and answers with
//! the addresses the create request then carries, so the in-VM daemon
//! attaches with the handed address instead of drawing its own. The same
//! client withdraws the row when the session is destroyed or the activation
//! fails after registering: one line asking `withdraw`, answered with the
//! pair echoed back. One connection, one request line in, one reply line
//! out.
//!
//! The socket also serves the read-only status read: a line asking
//! `answerer_status` answers the machine's zone-answerer state (see
//! [`minimald_rpc::ZoneAnswererStatus`]) — the host fact the CLI surfaces at
//! session start and on `min ls`, read here rather than through the in-VM
//! daemon because a guest relaying a host fact is forgeable from inside the
//! escape boundary. The same read answers the hostname proxy's publish
//! outcome (T93): when the supervisor reached a cause that names why the
//! proxy is not serving, the reply carries it (see
//! [`ProxyPublishStatus`]), so the CLI's surfaces say *why*, not just that.
//! The read touches no row and mutates nothing. The read-only row verb
//! (`read_row`, NET-138) is the same shape again: one live box's row — its
//! switch address, its derived egress allow-list, its declared and
//! runtime-admitted ports — answered for a name a live box holds, and the
//! no-row marker for one nothing holds. A destroyed box's row answers
//! nothing, because a withdrawn row is gone, not archived.
//!
//! Two doors, because two peers (NET-138). The host's control socket takes
//! the registrations, their withdrawals, and both read-only verbs; the
//! second door — [`GUEST_CONTROL_SOCK_FILE`] — is the in-VM daemon's
//! control channel, bridged to the guest over vsock at
//! [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] (bound by T94 together with
//! that bridge; this module serves its verbs but binds no socket for it
//! yet), and it takes the port reports alone: `admit_port`, the guest's report that one of its boxes published
//! a runtime port, and `withdraw_port`, its withdrawal. The verb decides
//! which door answers it, never the peer: a registration that arrives on
//! the guest's channel is refused the same way a port report that arrives
//! on the host's is, because the host control socket's owner-only file
//! mode is the read's access control and the box table's, and the guest
//! channel's grant check — the stance, range, cap and rate the row's
//! host-side registration holds — is the report's. Every admit and
//! withdraw report answers one log line naming the box, the port, the
//! reporting source and the outcome; every recorded admission appends a
//! host-side copy to the daemon's own audit log
//! (`audit/box-admissions.log`, in the same state dir the sockets live in).
//!
//! The ask verbs (NET-045) split across the doors the same way. The guest
//! door takes `admit_ask`, the in-VM daemon's report that an expose was
//! decided `ask`: the ask is recorded pending under an id this daemon
//! mints, and the connection is held until the ask ends. The host socket
//! takes `subscribe_asks`, an attached client's subscription to one row's
//! asks by the row's box id, over which the offers and dismissals are
//! pushed, and `record_ask_answer`, the client's answer. A guest can raise
//! a question but never answer one. Both held verbs run on threads of their
//! own, so a door's other connections never wait behind a human. Every ask
//! event appends one line to the same audit log.
//!
//! The socket lives beside the daemon's ssh socket in the provider-instance
//! dir and is created with the same 0700-dir / 0600-socket posture the
//! bridge socket gets ([`crate::sock`]): only the same user may reach the
//! box table. The serving shape mirrors [`crate::net::HostGvproxy::spawn`]
//! — a dedicated OS thread off the supervisor's runtime — because both are
//! long-lived host services whose failures must not take the daemon down
//! with them: a failed registration answers the client with the reason and
//! keeps serving, and a client that never reaches the socket (a supervisor
//! predating this module) still activates, handed no addresses — with the
//! egress gate dropping its frames under the unregistered rule (NET-085).
//!
//! The v1 posture, stated: the trust is the uid. The bind tightens the
//! provider dir to 0700 when the daemon owns it, refuses one it does not
//! own, and sets the socket to 0600; every connection's peer uid is then
//! checked against the daemon's own (`SO_PEERCRED` on Linux, `getpeereid`
//! on macOS) and a foreign uid is dropped unanswered. Within the
//! single-operator host profile any same-uid writer is accepted: a uid
//! check cannot tell the activating client's registrations apart from
//! another process running as the same user. If box rows ever have to
//! come only from the host-side creator, a per-boot token minted by that
//! creator is the pattern to use; this socket does not build one. Requests
//! are served serially, one connection at a time, each read bounded by a
//! 30-second timeout. That is what v1 ships, not a design endpoint.
//!
//! A box whose row is gone — never registered, or withdrawn at destroy —
//! is dropped by the gate's unregistered rule unconditionally (NET-085);
//! the flip that lands with the last row source (T66's follow-up) decides
//! only what the publish half admits, not a change this socket makes.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use minimald_rpc::{
    AdmitPortRequest, BoxAddresses, BoxControlReply, BoxControlRequest, BoxRow, IpProto,
    PortReportSource, ProxyDownCause, ReadRowRequest, RegisterBoxRequest, RegisteredBox,
    WithdrawBoxRequest, WithdrawPortRequest, ZoneAnswererStatus,
};

use crate::box_registry::{BoxRegistry, ClientBoxSpec};
use crate::net::answerer::AnswererStatus;

/// The control socket's file name inside the provider-instance dir, beside
/// `paths::SSH_SOCK_FILE`. Deliberately not in the `paths` crate: that crate
/// is shared with consumers that have no box table, and this name only
/// means something where `minvmd` supervises one.
pub const CONTROL_SOCK_FILE: &str = "control.sock";

/// The in-VM daemon's control channel's file name, beside the control
/// socket in the same provider-instance dir: the door the port reports
/// (NET-138) arrive on, bridged to the guest over vsock at
/// [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] — the one channel from inside
/// the microVM that answers, because a report the grant refused must be
/// refused *to the reporter* for the publish to unwind.
pub const GUEST_CONTROL_SOCK_FILE: &str = "guest-control.sock";

/// The env the supervisor hands the VMM child the guest report door's path
/// under (T94): the child is the process that owns the libkrun context, so
/// only it can register the door's vsock port — and it registers the port
/// exactly when the env names a door the supervisor bound, which is how the
/// door is bound only once the bridge is up. The name lives here, beside
/// the door it names, because the child only reads it.
pub const GUEST_REPORT_SOCK_ENV: &str = "MINVMD_GUEST_REPORT_SOCK";

/// The audit log the daemon appends its host-side copy of each recorded
/// admission to, relative to the provider dir the sockets live in — the
/// daemon's own audit log, beside the state it keeps for the VM it
/// serves.
const AUDIT_LOG_RELATIVE_PATH: &str = "audit/box-admissions.log";

/// The audit copy's timestamp shape: Unix seconds, the same spelling the
/// daemon's own persisted state carries (`minvmd.toml`'s `started_at`), so
/// every timestamp a bundle collects from this daemon reads one way.
///
/// A clock before the epoch answers `0`: the audit copy is best-effort —
/// its loss is a warn line, never a failed report — and a timestamp that
/// could not be taken is not a reason to lose the admission it names.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Which socket a request arrived on (NET-138): the door is the verb's
/// access control. [`ControlDoor::Host`] is the host's own control socket,
/// whose owner-only file mode is every row operation's and the read-only
/// row verb's gate; [`ControlDoor::GuestReports`] is the in-VM daemon's
/// channel, where the grant the row's registration holds — not the peer —
/// decides what a report may record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlDoor {
    /// The host's control socket, in the provider dir beside the ssh
    /// socket: registrations, withdrawals, and both read-only verbs.
    Host,
    /// The in-VM daemon's control channel: the port reports alone. Bound
    /// by the supervisor for the vsock bridge at
    /// [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] (T94,
    /// [`spawn_guest_reports_door`]); before the bridge hands the door
    /// over, no report can reach it, and the tests drive it directly.
    GuestReports,
}

/// How long the server waits for a registration's one request line before
/// dropping the connection. Generous against a slow starter; a hung client
/// must not pin the serving thread — connections are served one at a
/// time — forever.
const REGISTER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the guest door waits for the in-VM daemon to close its end
/// after its reply is written. The wait is the G-N8 workaround's other
/// half, so the bound only ends a client that read its reply and never
/// closed: a wedged reporter cannot pin the door's serial accept loop the
/// way an honest one never does.
const GUEST_REPORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest request line the server will read. A registration carries a
/// name, a port list, and a policy; anything past this bound is not one.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// How many times one VM start may ask the guest to publish the hostname
/// proxy (T93): the first boot plus every redraw an address-in-use publish
/// forced. A constant, not a configuration: the bound exists to end a start
/// whose every drawn port is taken — a host where a start cannot find one
/// free port in three draws is a host whose problem the operator must see,
/// not one a longer sequence of retries would paper over.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) const PUBLISH_TRIES: usize = 3;

/// How [`decide_publish`] names whoever kept a port from publishing (T93):
/// the one fact the host side can vouch for. The kernel says a bind is
/// refused, not who refused it — the guest's own log tail is where the
/// taker's own identity, if anywhere, is said.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) const HELD_BY_ANOTHER_PROCESS: &str = "another process on the host";

/// What the supervisor learned about the publish of the hostname-proxy port
/// it reserved (T93): the guest's report over the boot-marker channel — the
/// one control path from inside a microVM to the VM host daemon — or, when
/// no report arrived inside the watch, the supervisor's own probe of the
/// port. The guest's voice is the one that can say the port was *taken*
/// (a bind that refused the publish is a fact the publish saw and a connect
/// probe cannot attribute), which is why nothing here decides anything
/// until the report or the probe says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) enum GuestPublish {
    /// The guest published the hostname proxy: it is serving on the port.
    Serving {
        /// The published port, as the guest handed it back.
        port: u16,
    },
    /// The guest's publish was refused for address-in-use: the port is
    /// taken, and the guest has stopped retrying (the terminal report,
    /// never a backoff).
    PortHeld {
        /// The port the publish could not take.
        port: u16,
    },
    /// No report arrived inside the watch: the supervisor's own probe of
    /// the port, and of who holds it, is the whole outcome.
    NoReport {
        /// The port the watch was about — the one this start reserved.
        port: u16,
        /// Who the supervisor found on the port ([`NoReportHolder`]).
        holder: NoReportHolder,
    },
}

/// Who the supervisor found on the reserved port when the publish watch
/// expired without the guest's report (T93) — the identification that lets
/// a missing report be decided instead of guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) enum NoReportHolder {
    /// The port answers and its holder is a process this supervisor spawned
    /// for this VM — the forwarder that carries the guest's publish (the
    /// host switch) or the VMM child — matched by pid: the publish landed
    /// and only the report was late.
    OwnForwarder,
    /// The port answers and its holder is a process this supervisor did not
    /// spawn: the port is taken exactly as a refused publish says it is.
    Foreign,
    /// The port answers but the host would not name its holder (a listener
    /// of another user, a host this cannot read), and the guest's report did
    /// not come inside the grace either. Ambiguity alone never redraws.
    Unknown,
    /// Nothing answers on the port: no publish the host can see.
    NotAnswering,
}

/// [`NoReportHolder`] from the probe's facts: whether the port answered,
/// the pid of the listener the host named (if it named one), and the pids
/// this supervisor spawned for this VM.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn classify_no_report_holder(
    answers: bool,
    holder_pid: Option<u32>,
    own_pids: &[u32],
) -> NoReportHolder {
    match (answers, holder_pid) {
        (false, _) => NoReportHolder::NotAnswering,
        (true, Some(pid)) if own_pids.contains(&pid) => NoReportHolder::OwnForwarder,
        (true, Some(_)) => NoReportHolder::Foreign,
        (true, None) => NoReportHolder::Unknown,
    }
}

/// What the supervisor does with what it learned about the publish (T93):
/// [`decide_publish`]'s verdict, composed of facts the reservation and the
/// port's origin already hold.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) enum PublishDecision {
    /// The VM may come up: the proxy published — the guest said so, or the
    /// port's holder is this VM's own forwarder.
    Up,
    /// The VM may come up, but its publish is unconfirmed: no report came
    /// and the port is either silent or held by a process the host would
    /// not name. The status read says so ([`ProxyDownCause::PublishUnconfirmed`])
    /// until the guest's late report clears it.
    UpUnconfirmed {
        /// The port whose publish is unconfirmed.
        port: u16,
    },
    /// A drawn port with tries left: release the old reservation, draw
    /// again under the same reservation discipline, and ask the guest to
    /// publish again.
    Redraw {
        /// The port to draw past — the one the publish could not take.
        port: u16,
    },
    /// The start fails, naming the port and the holder: a drawn port whose
    /// draws ran out, or the operator's pin, which never redraws. The cause
    /// is the wire fact the CLI's `min ls` and session-start surfaces name.
    FailStart {
        /// The port the publish could not take.
        port: u16,
        /// How the holder is named — [`HELD_BY_ANOTHER_PROCESS`].
        holder: &'static str,
        /// Why the proxy is not serving, for the control-socket read.
        cause: ProxyDownCause,
    },
}

/// What one learned publish outcome means for the start (T93), given
/// whether the port was drawn or the operator's pin and how many publish
/// tries the start has spent.
///
/// The arms, said plainly:
///
/// - The guest reported serving: [`PublishDecision::Up`], whatever the
///   origin or the count — a boot that landed is a boot that landed.
/// - The guest reported the port taken, or no report came and the port's
///   holder is another process ([`NoReportHolder::Foreign`]): a drawn port
///   redraws while tries remain ([`PUBLISH_TRIES`]) and then fails
///   [`ProxyDownCause::RedrawsRanOut`]; a pin fails at once,
///   [`ProxyDownCause::PortHeld`], naming the port and the holder. A VM
///   never stays up with no hostname proxy: a proxyless VM answers nothing
///   this task's surfaces promise, and the pin's whole point is the
///   operator named the port.
/// - No report came and the port's holder is this VM's own forwarder
///   ([`NoReportHolder::OwnForwarder`]): the publish landed and the report
///   was late — [`PublishDecision::Up`].
/// - No report came and the port's holder could not be named
///   ([`NoReportHolder::Unknown`], after the watch's grace for the report),
///   or nothing answers on the port ([`NoReportHolder::NotAnswering`]):
///   [`PublishDecision::UpUnconfirmed`] — the VM comes up, but its publish
///   is shown as unconfirmed, never as serving. Ambiguity alone never
///   redraws.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn decide_publish(
    drawn: bool,
    tries_used: usize,
    outcome: GuestPublish,
) -> PublishDecision {
    let port = match outcome {
        GuestPublish::Serving { .. }
        | GuestPublish::NoReport {
            holder: NoReportHolder::OwnForwarder,
            ..
        } => return PublishDecision::Up,
        GuestPublish::NoReport {
            port,
            holder: NoReportHolder::Unknown | NoReportHolder::NotAnswering,
        } => return PublishDecision::UpUnconfirmed { port },
        GuestPublish::PortHeld { port }
        | GuestPublish::NoReport {
            port,
            holder: NoReportHolder::Foreign,
        } => port,
    };
    if !drawn {
        // The operator's pin never redraws: the first refusal is the
        // start's, naming the port and the holder.
        PublishDecision::FailStart {
            port,
            holder: HELD_BY_ANOTHER_PROCESS,
            cause: ProxyDownCause::PortHeld,
        }
    } else if tries_used < PUBLISH_TRIES {
        PublishDecision::Redraw { port }
    } else {
        PublishDecision::FailStart {
            port,
            holder: HELD_BY_ANOTHER_PROCESS,
            cause: ProxyDownCause::RedrawsRanOut,
        }
    }
}

/// The hostname proxy's publish state for this VM (T93) — the host fact the
/// CLI's `min ls` row and session-start message read to *name why* the proxy
/// is not serving, in the same read that already carries the answerer's
/// state. Held by the supervisor, written when a start fails on the publish
/// — a supervisor about to stop, whose fact outlives it exactly as long as
/// the socket does — or when the VM came up with its publish unconfirmed,
/// the one entry a later report clears ([`Self::confirm`]).
///
/// Shaped like [`AnswererStatus`] — a cloneable cell behind one mutex,
/// read on the serving thread — because that is the pattern the status
/// read already serves under.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Clone, Default)]
pub struct ProxyPublishStatus(Arc<Mutex<Option<(u16, ProxyDownCause)>>>);

#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
impl ProxyPublishStatus {
    /// The empty cell a start begins with: no cause to name.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record why the proxy is not serving — the decision that failed the
    /// start, carrying the port and the cause.
    pub(crate) fn set_down(&self, port: u16, cause: ProxyDownCause) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((port, cause));
    }

    /// Record that the proxy's publish on `port` is unconfirmed: the VM came
    /// up with no report from the guest and no holder the host could vouch
    /// for ([`PublishDecision::UpUnconfirmed`]).
    pub(crate) fn set_unconfirmed(&self, port: u16) {
        self.set_down(port, ProxyDownCause::PublishUnconfirmed);
    }

    /// Clear an unconfirmed publish on `port` — the guest's late report said
    /// it is serving. Any other recorded cause stays: only the state the
    /// report answers is the report's to clear.
    pub(crate) fn confirm(&self, port: u16) {
        let mut cell = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *cell == Some((port, ProxyDownCause::PublishUnconfirmed)) {
            *cell = None;
        }
    }

    /// The status to serve the read-only verb with: the proxy-down cause
    /// when the supervisor wrote one, or `None` to let the answerer's state
    /// answer as it always did.
    pub(crate) fn down(&self) -> Option<ZoneAnswererStatus> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .map(|(port, cause)| ZoneAnswererStatus::ProxyNotServing { port, cause })
    }
}

/// Resolve the control socket's path: `<provider dir>/control.sock`, the
/// dir the CLI resolves the ssh socket under, so the client finds both by
/// the same rule.
pub fn resolve_control_sock() -> std::io::Result<PathBuf> {
    Ok(crate::state::provider_dir().join(CONTROL_SOCK_FILE))
}

/// Bind the control socket at `sock_path` and serve box control requests
/// — registrations, their withdrawals, both read-only verbs — against
/// `boxes` on a dedicated thread, whose handle the caller holds for as
/// long as the daemon lives.
///
/// The in-VM daemon's report channel ([`GUEST_CONTROL_SOCK_FILE`]) is not
/// bound here: the supervisor binds it as the vsock bridge's other half
/// ([`spawn_guest_reports_door`]), so the door exists exactly when a
/// running VM is handed it at
/// [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`] (7352). Until a bridge hands
/// the door over, a report reaching the host's socket is refused as the
/// wrong door.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; only the accept loop moves to
/// its thread. The socket gets the bridge socket's posture: path-length
/// check (libkrun aborts on over-long socket paths), a 0700 parent dir, a
/// stale socket removed, and 0600 on the socket itself.
pub fn spawn(
    sock_path: PathBuf,
    boxes: BoxRegistry,
    answerer: AnswererStatus,
    proxy_publish: ProxyPublishStatus,
) -> std::io::Result<JoinHandle<()>> {
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    if let Some(parent) = sock_path.parent() {
        crate::sock::restrict_owned_dir(parent)?;
        crate::sock::verify_provider_dir_ownership(parent)?;
    }
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    // The audit copy's path, kept under the state dir the socket lives in;
    // only the guest door appends to it, but every door carries it so the
    // signature is one.
    let audit_path = audit_log_path(&sock_path);
    std::thread::Builder::new()
        .name("minvmd-control".to_string())
        .spawn(move || {
            accept_loop(
                listener,
                boxes,
                answerer,
                proxy_publish,
                ControlDoor::Host,
                &audit_path,
            )
        })
}

/// Bind the in-VM daemon's report door (T94, NET-138) at
/// [`GUEST_CONTROL_SOCK_FILE`] beside `control_sock_path` and serve the
/// port-report verbs on it against `boxes` on a dedicated thread, answering
/// the door's bound path so the caller hands the VMM child the same socket
/// it registered the vsock port at [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`]
/// for — the bridge's two halves, one step.
///
/// The door is the port reports' alone: the admit-port and withdraw-port
/// verbs answer on it and nothing else does, so the grant a row's
/// registration holds — never the peer, whose uid the socket posture
/// already gates — decides what a report records. It serves one connection
/// at a time on its own thread beside the host socket's thread, and never
/// closes a connection first: after its reply is written it waits for the
/// reporter's close, because the KVM shuttle drops a server-initiated
/// close's still-buffered reply bytes on the way to the guest (G-N8).
///
/// The bind runs the control socket's own posture — path-length check,
/// 0700 parent dir, ownership verified, stale socket removed, 0600 on the
/// socket — and happens on the calling thread, so a bind failure surfaces
/// to the supervisor's startup handling rather than inside a thread the
/// supervisor cannot reach. One info line at the bind says the door stands
/// behind its bridge: the observability half of the report channel.
pub fn spawn_guest_reports_door(
    control_sock_path: &Path,
    boxes: BoxRegistry,
    answerer: AnswererStatus,
    proxy_publish: ProxyPublishStatus,
) -> std::io::Result<PathBuf> {
    let sock_path = control_sock_path.with_file_name(GUEST_CONTROL_SOCK_FILE);
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    if let Some(parent) = sock_path.parent() {
        crate::sock::restrict_owned_dir(parent)?;
        crate::sock::verify_provider_dir_ownership(parent)?;
    }
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    let audit_path = audit_log_path(&sock_path);
    tracing::info!(
        sock = %sock_path.display(),
        vsock_port = minimald_rpc::VM_HOST_BOX_REPORT_PORT,
        "bound the guest report door; the in-VM daemon's port reports reach the \
         host-held grant over the vsock bridge"
    );
    std::thread::Builder::new()
        .name("minvmd-guest-control".to_string())
        .spawn(move || {
            accept_loop(
                listener,
                boxes,
                answerer,
                proxy_publish,
                ControlDoor::GuestReports,
                &audit_path,
            )
        })
        // The door's bound path is the handle the caller pairs with the
        // bridge; the thread keeps the socket open for the daemon's life.
        .map(|_| sock_path)
}

/// Accept and serve box control requests until the daemon exits. One
/// connection at a time per door: a request is a row's map write or
/// removal, served serially so the table sees its requests in arrival
/// order — and the status and row reads ride the same serial turn. The
/// two doors are served on two threads, so a report the grant refuses
/// never waits behind a registration.
fn accept_loop(
    listener: UnixListener,
    boxes: BoxRegistry,
    answerer: AnswererStatus,
    proxy_publish: ProxyPublishStatus,
    door: ControlDoor,
    audit_path: &Path,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) =
                    serve_connection(stream, &boxes, &answerer, &proxy_publish, door, audit_path)
                {
                    tracing::debug!(error = %error, "box control connection failed");
                }
            }
            Err(error) => tracing::debug!(error = %error, "control socket accept failed"),
        }
    }
}

/// Serve one request: read the line, dispatch the verb, answer.
fn serve_connection(
    stream: UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    proxy_publish: &ProxyPublishStatus,
    door: ControlDoor,
    audit_path: &Path,
) -> std::io::Result<()> {
    let mut stream = stream;
    stream.set_read_timeout(Some(REGISTER_READ_TIMEOUT))?;

    // Check the peer's credentials: only the daemon's own uid may reach
    // the box table. The 0600 socket mode is the primary gate; this is
    // defense in depth against a mis-moded file or a group- or
    // world-writable provider directory. The kernel captures the peer's
    // credentials at connect time, so a descriptor a same-uid connector
    // passes on still carries that connector's uid.
    //
    // One exception, and only for the answerer handover's two verbs:
    // root — the privileged step that installs the answerer service runs
    // as root and asks this daemon to release the hook port. Every other
    // verb stays the daemon's own uid's.
    let uid = match peer_uid(&stream) {
        Ok(uid) => uid,
        Err(error) => {
            tracing::debug!(%error, "control-socket peer check failed");
            return Ok(());
        }
    };
    let root_peer = is_root_peer(uid);
    if !root_peer && let Err(error) = check_peer_uid(uid) {
        tracing::debug!(%error, "control-socket peer check failed");
        return Ok(());
    }

    let Some(line) = read_request_line(&mut stream)? else {
        // EOF before any byte: a client that connected and left. Nothing to
        // answer, nothing to log past the connection level.
        return Ok(());
    };
    let request = match parse_request(&line) {
        Ok(request) => request,
        Err(error) => {
            let error = error.to_string();
            tracing::debug!(error = %error, "box control request did not parse");
            return write_reply(&mut stream, &BoxControlReply::Error { error });
        }
    };
    if root_peer && !root_may_ask(&request) {
        tracing::warn!(
            peer_uid = uid,
            "refused a control-socket request from root: root may only release the \
             answerer or cancel a release"
        );
        return Ok(());
    }
    // The ask verbs hold their connection open for as long as the ask or
    // the subscription lives (NET-045), so each runs on a thread of its
    // own: a door serves its other connections one at a time, and an ask
    // waiting on a human must not hold a report or a registration behind
    // it.
    match (&request, door) {
        (BoxControlRequest::AdmitAsk(ask), ControlDoor::GuestReports) => {
            let ask = *ask;
            return spawn_ask_thread(
                stream,
                "minvmd-guest-ask",
                boxes,
                audit_path,
                move |s, b, a| {
                    serve_guest_ask(s, b, a, ask);
                },
            );
        }
        (BoxControlRequest::SubscribeAsks(subscribe), ControlDoor::Host) => {
            let box_id = subscribe.box_id;
            return spawn_ask_thread(
                stream,
                "minvmd-ask-client",
                boxes,
                audit_path,
                move |s, b, a| {
                    serve_ask_subscription(s, b, a, box_id);
                },
            );
        }
        _ => {}
    }
    let served = serve_request(
        &mut stream,
        boxes,
        answerer,
        proxy_publish,
        door,
        audit_path,
        request,
    );
    // The guest door never closes a connection first (G-N8): on the KVM
    // libkrun shuttle a server-initiated close drops the reply's
    // still-buffered bytes on their way to the guest, and the in-VM daemon
    // reads an immediate EOF with nothing in it — the answer a report's
    // unwind depends on, lost to the close that carried it. So the door
    // holds the connection open until the reporter, which has its reply,
    // closes from its side. The host socket's peers are on the same host,
    // not behind a shuttle, and close as they always did.
    if door == ControlDoor::GuestReports {
        drain_until_peer_closes(&mut stream);
    }
    served
}

/// Wait for the peer's close on a guest-door connection whose reply was
/// already written: read until EOF — the reporter closing its end, which
/// it does once it has the reply — or until the drain bound ends a client
/// that never closes, so a wedged reporter cannot pin the door's serial
/// accept loop. Bytes past the request line, if any, are discarded: the
/// door's protocol is one line each way.
fn drain_until_peer_closes(stream: &mut UnixStream) {
    if let Err(error) = stream.set_read_timeout(Some(GUEST_REPORT_DRAIN_TIMEOUT)) {
        // Without the bound a reporter that never closes would pin the
        // door's serial accept loop, so a timeout that cannot be set ends
        // the drain here: the reply is already written, and the peer's
        // close ends the connection all the same.
        tracing::debug!(error = %error, "the guest report drain could not arm its bound");
        return;
    }
    let mut sink = [0u8; 1024];
    loop {
        match std::io::Read::read(stream, &mut sink) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Whether `peer_uid` is root connecting to a daemon that is not root's:
/// the one foreign uid the answerer handover's verbs admit.
fn is_root_peer(peer_uid: u32) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    peer_uid == 0 && unsafe { libc::geteuid() } != 0
}

/// The verbs root may ask: the answerer handover's release and its cancel,
/// nothing that reads or writes the box table.
fn root_may_ask(request: &BoxControlRequest) -> bool {
    matches!(
        request,
        BoxControlRequest::ReleaseAnswerer | BoxControlRequest::ReleaseAnswererCancel
    )
}

/// Dispatch one parsed request to its verb and write its one reply line.
///
/// The verb dispatch is where the wire's parse refusal pays off: a line
/// that names no verb this build knows never reaches the table at all, so
/// a skewed client cannot make a withdraw look like a register (the
/// [`minimald_rpc::BoxControlRequest`] docs carry that corner). The
/// read-only verbs — the answerer's status and the row read — touch no row
/// and mutate nothing: they answer the state the acquisition loop last
/// wrote and the table the registrations filled, under the same socket
/// posture every verb here is served under (the v1 trust is the uid: the
/// 0600 socket plus the peer-credential check every connection passes
/// before its line is read).
///
/// The door is the verb's access control (NET-138): registrations,
/// withdrawals and both reads answer only on the host's socket, whose
/// owner-only file mode is the row read's gate, and the port reports
/// answer only on the in-VM daemon's channel, where the grant the row's
/// registration holds decides. A verb on the wrong door is refused with
/// its reason — never parsed into the other door's posture, because the
/// peer a door serves is exactly what the verb decides what it may do.
fn serve_request(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    proxy_publish: &ProxyPublishStatus,
    door: ControlDoor,
    audit_path: &Path,
    request: BoxControlRequest,
) -> std::io::Result<()> {
    match (request, door) {
        (BoxControlRequest::Register(request), ControlDoor::Host) => {
            register_and_reply(stream, boxes, answerer, request)
        }
        (BoxControlRequest::Withdraw(request), ControlDoor::Host) => {
            withdraw_and_reply(stream, boxes, answerer, request)
        }
        (BoxControlRequest::AnswererStatus, ControlDoor::Host) => {
            // The read-only status answers the host facts the CLI's
            // surfaces read (T93): why the hostname proxy is not serving
            // when the supervisor reached a cause that names it, and
            // otherwise the answerer's state as it always did — the
            // proxy-down cause is the exception, not a new shape.
            let reply = match proxy_publish.down() {
                Some(status) => BoxControlReply::Status(status),
                None => BoxControlReply::Status(answerer.get()),
            };
            write_reply(stream, &reply)
        }
        (BoxControlRequest::ReadRow(request), ControlDoor::Host) => {
            read_row_and_reply(stream, boxes, request)
        }
        (BoxControlRequest::RecordAskAnswer(request), ControlDoor::Host) => {
            record_ask_answer_and_reply(stream, boxes, audit_path, request)
        }
        (BoxControlRequest::AdmitPort(request), ControlDoor::GuestReports) => {
            admit_report_and_reply(stream, boxes, audit_path, request)
        }
        (BoxControlRequest::WithdrawPort(request), ControlDoor::GuestReports) => {
            withdraw_report_and_reply(stream, boxes, request)
        }
        (BoxControlRequest::ReleaseAnswerer, ControlDoor::Host) => {
            let reply = answerer.release();
            tracing::info!(
                acted = reply.acted,
                "answer to a release request: {}",
                reply.detail
            );
            write_reply(
                stream,
                &BoxControlReply::AnswererRelease {
                    acted: reply.acted,
                    detail: reply.detail,
                },
            )
        }
        (BoxControlRequest::ReleaseAnswererCancel, ControlDoor::Host) => {
            let reply = answerer.release_cancel();
            tracing::info!(
                acted = reply.acted,
                "answer to a release-cancel request: {}",
                reply.detail
            );
            write_reply(
                stream,
                &BoxControlReply::AnswererRelease {
                    acted: reply.acted,
                    detail: reply.detail,
                },
            )
        }
        // The verb does not answer on this door: a registration or a read
        // that arrives on the in-VM daemon's channel, or a port report
        // that arrives on the host's socket, is refused naming the door
        // that serves it — one warn line per refusal, because a verb on
        // the wrong door is a client built against another posture, not a
        // frame to drop silently.
        (request, door) => refused_wrong_door(stream, &request, door),
    }
}

/// Refuse a verb that arrived on a door that does not serve it (NET-138):
/// one warn line and one error reply naming where the verb is served, so
/// a client that dialed the wrong socket learns the door's rule rather
/// than a generic refusal.
fn refused_wrong_door(
    stream: &mut UnixStream,
    request: &BoxControlRequest,
    door: ControlDoor,
) -> std::io::Result<()> {
    let verb = request_verb(request);
    let (error, serves) = match door {
        ControlDoor::Host => (
            format!(
                "the {verb} verb is served on the in-VM daemon's control channel, \
                 not the host's control socket"
            ),
            "the host's control socket",
        ),
        ControlDoor::GuestReports => (
            format!(
                "the {verb} verb is served on the host's control socket, not the \
                 in-VM daemon's control channel"
            ),
            "the in-VM daemon's control channel",
        ),
    };
    tracing::warn!(
        verb = %verb,
        door = %serves,
        "refused a box control verb on the door that does not serve it"
    );
    write_reply(stream, &BoxControlReply::Error { error })
}

/// The verb's own name, as a wrong-door refusal names it: the one spelling
/// the tagged wire carries.
fn request_verb(request: &BoxControlRequest) -> &'static str {
    match request {
        BoxControlRequest::Register(_) => "register",
        BoxControlRequest::Withdraw(_) => "withdraw",
        BoxControlRequest::AnswererStatus => "answerer_status",
        BoxControlRequest::AdmitPort(_) => "admit_port",
        BoxControlRequest::WithdrawPort(_) => "withdraw_port",
        BoxControlRequest::ReadRow(_) => "read_row",
        BoxControlRequest::ReleaseAnswerer => "release_answerer",
        BoxControlRequest::ReleaseAnswererCancel => "release_answerer_cancel",
        BoxControlRequest::AdmitAsk(_) => "admit_ask",
        BoxControlRequest::RecordAskAnswer(_) => "record_ask_answer",
        BoxControlRequest::SubscribeAsks(_) => "subscribe_asks",
    }
}

/// Check that the peer on `stream` has the same uid as the daemon.
///
/// On Linux this reads `SO_PEERCRED`; on macOS it calls `getpeereid`.
/// A peer with a different uid is refused — the 0600 socket mode is the
/// primary gate, and this is defense in depth.
///
/// The refusal is logged once per distinct foreign uid (per process
/// lifetime) so a persistent misconfiguration does not flood the log.
#[cfg(test)]
fn check_peer_credentials(stream: &UnixStream) -> std::io::Result<()> {
    check_peer_uid(peer_uid(stream)?)
}

/// Admit `peer_uid` only when it is the daemon's own effective uid; the
/// decision half of the connection's peer check, apart from the socket.
fn check_peer_uid(peer_uid: u32) -> std::io::Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let my_uid = unsafe { libc::geteuid() };
    if peer_uid == my_uid {
        return Ok(());
    }
    // Log the refusal once per distinct foreign uid.
    static SEEN: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
    let first = {
        let mut seen = SEEN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.get_or_insert_with(HashSet::new).insert(peer_uid)
    };
    if first {
        tracing::warn!(
            peer_uid,
            daemon_uid = my_uid,
            "refused control-socket connection from a different uid"
        );
    } else {
        tracing::debug!(
            peer_uid,
            daemon_uid = my_uid,
            "refused control-socket connection from a different uid"
        );
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("peer uid {peer_uid} does not match daemon uid {my_uid}"),
    ))
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt with SO_PEERCRED reads the peer's pid/uid/gid
    // from the kernel; the kernel fills `cred` and `len` on success.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: getpeereid reads the peer's effective uid and gid from the
    // kernel and writes both through the pointers unconditionally — a null
    // gid pointer faults on macOS — so both point at live locals.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(euid)
}

/// Read one line (terminated by `\n`) of the box control request. A
/// connection that closes before sending a line reads as no request; a line
/// past [`MAX_REQUEST_LINE`] is refused.
///
/// The slices are cut at `read`, the byte count `read()` reported filling
/// `buf` with, or at `newline`, an index `position` found inside
/// `buf[..read]` — so neither range can be out of bounds.
#[expect(
    clippy::indexing_slicing,
    reason = "cut at `read`, the byte count `read()` reported, or at `newline`, an index `position` found inside `buf[..read]`"
)]
fn read_request_line(stream: &mut UnixStream) -> std::io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                // A partial line at EOF — a client that died mid-write.
                // Still answerable with a parse refusal, so hand what
                // arrived back rather than hanging the slot on a timeout.
                Ok(Some(String::from_utf8_lossy(&line).into_owned()))
            };
        }
        if let Some(newline) = buf[..read].iter().position(|byte| *byte == b'\n') {
            line.extend_from_slice(&buf[..newline]);
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        line.extend_from_slice(&buf[..read]);
        if line.len() > MAX_REQUEST_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("box control request exceeded {MAX_REQUEST_LINE} bytes without a newline"),
            ));
        }
    }
}

fn parse_request(line: &str) -> Result<BoxControlRequest, serde_json_lenient::Error> {
    serde_json_lenient::from_str(line)
}

/// Allocate the box into the table and write the reply — the addresses and
/// the box id on success, the reason on a refusal. One info line per
/// registration names the box, its id, both addresses and the declared
/// egress the row carries: the diagnostic a bundle's VM host daemon log is
/// read for.
///
/// The box's published address is the machine answerer's to hand out
/// (design §7.1), asked for before the row is filled: a node never
/// self-assigns one, so two state dirs' boxes never share an address.
fn register_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    request: RegisterBoxRequest,
) -> std::io::Result<()> {
    // The declaration as the row received it; `null` for a box with no
    // egress section. A plain struct of strings serialises infallibly.
    let declared_egress = serde_json_lenient::to_string(&request.egress).unwrap_or_default();
    // The request carries no id: the registry mints the box's own UUIDv7
    // for this creation (BEP-070), and the reply hands back the id the
    // published row holds — the one the client records.
    let spec = ClientBoxSpec {
        name: request.name.clone(),
        ingress_ports: request.ingress_ports,
        egress: request.egress,
        credentialed_upstream: request.credentialed_upstream,
        // The dynamic-ingress grant (NET-045, NET-138), from the same
        // create inputs the session record holds: the stance and range the
        // row holds every runtime port report against.
        dynamic_ingress: request.dynamic_ingress,
        dynamic_allowed_range: request.dynamic_allowed_range,
    };
    let loopback_addr = match answerer.allocate(&request.name) {
        Ok(address) => address,
        Err(reason) => {
            tracing::warn!(
                box = %request.name,
                %reason,
                "box registration refused: the zone answerer handed out no address"
            );
            return write_reply(
                stream,
                &BoxControlReply::Error {
                    error: format!("the zone answerer could not allocate a box address: {reason}"),
                },
            );
        }
    };
    let reply = match boxes.register_client_box_at(spec, loopback_addr) {
        Ok(record) => {
            tracing::info!(
                box = %record.name(),
                box_id = %crate::bep_attach::BoxIdText(&record.box_id()),
                switch_address = %record.switch_addr(),
                loopback_address = %record.loopback_addr(),
                egress = %declared_egress,
                "registered box with the VM host daemon; addresses allocated"
            );
            BoxControlReply::Registered(RegisteredBox {
                switch_address: record.switch_addr(),
                loopback_address: record.loopback_addr(),
                box_id: minimald_rpc::BoxId::from_bytes(record.box_id()),
            })
        }
        Err(error) => {
            // The address goes back: no row holds it.
            answerer.release_address(&request.name);
            tracing::debug!(
                box = %request.name,
                error = %error,
                "box registration refused"
            );
            BoxControlReply::Error {
                error: error.to_string(),
            }
        }
    };
    write_reply(stream, &reply)
}

/// Remove the row the request's pair proves its client created, and write
/// the reply — the pair echoed back on success, the reason on a refusal.
/// One info line per withdrawal names the box and both addresses, mirroring
/// the registration's; a withdrawal that finds no row is the goal state
/// already holding (already withdrawn, or the daemon restarted since) and
/// is a debug line, not an error.
fn withdraw_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    request: WithdrawBoxRequest,
) -> std::io::Result<()> {
    let reply = match boxes.withdraw_client_box(
        &request.name,
        request.switch_address,
        request.loopback_address,
    ) {
        Ok(withdrawn) => {
            // The box is gone, so its published address returns to the
            // machine's range — the answerer's release is idempotent.
            answerer.release_address(&request.name);
            if withdrawn.is_some() {
                tracing::info!(
                    box = %request.name,
                    switch_address = %request.switch_address,
                    loopback_address = %request.loopback_address,
                    "withdrew the box's host row; its addresses admit nothing"
                );
            } else {
                tracing::debug!(
                    box = %request.name,
                    switch_address = %request.switch_address,
                    "no host row held at the withdrawn switch address; already withdrawn"
                );
            }
            BoxControlReply::Addresses(BoxAddresses {
                switch_address: request.switch_address,
                loopback_address: request.loopback_address,
            })
        }
        Err(error) => {
            tracing::debug!(
                box = %request.name,
                switch_address = %request.switch_address,
                error = %error,
                "box row withdrawal refused"
            );
            BoxControlReply::Error {
                error: error.to_string(),
            }
        }
    };
    write_reply(stream, &reply)
}

fn write_reply(stream: &mut UnixStream, reply: &BoxControlReply) -> std::io::Result<()> {
    let mut line = serde_json_lenient::to_string(reply).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("box control reply did not serialize: {error}"),
        )
    })?;
    line.push('\n');
    stream.write_all(line.as_bytes())
}

/// Serve the in-VM daemon's admit report (NET-138, NET-045): record the
/// reported port inside the grant the row's host-side registration holds,
/// answer the row it recorded into, and write the host-side audit copy.
/// One info line per recorded report and one warn line per refusal name
/// the box, the port, the reporting source and the outcome — the lines a
/// diagnostic bundle's daemon log tail is read for.
///
/// The refusal answers `Error` with the grant's own sentence, so the
/// guest's publish unwinds on the check that refused it: nothing was
/// recorded, and the in-VM mapping is the caller's to take down.
fn admit_report_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    audit_path: &Path,
    request: AdmitPortRequest,
) -> std::io::Result<()> {
    let source = source_text(request.source);
    let reply = match boxes.admit_runtime_port(
        request.switch_address,
        request.port,
        request.proto,
        std::time::Instant::now(),
    ) {
        Ok(record) => {
            tracing::info!(
                box = %record.name(),
                switch_address = %request.switch_address,
                port = request.port,
                proto = %request.proto,
                source = %source,
                "recorded the box's runtime-admitted port in the host-held grant"
            );
            append_audit_copy(audit_path, &record, &request);
            BoxControlReply::PortRecorded {
                port: request.port,
                proto: request.proto,
            }
        }
        Err(refusal) => {
            // Every refusal against the grant is a warn line, the box named
            // where the row exists and the address standing in for it where
            // nothing does.
            tracing::warn!(
                switch_address = %request.switch_address,
                port = request.port,
                proto = %request.proto,
                source = %source,
                reason = %refusal,
                "refused the in-VM daemon's port report against the host-held grant"
            );
            BoxControlReply::Error {
                error: refusal.to_string(),
            }
        }
    };
    write_reply(stream, &reply)
}

/// Serve the in-VM daemon's withdrawal report (NET-138): remove the
/// reported port from the row's runtime set. Never refused — the cap and
/// the rate are the admit path's bounds — and answered with the same
/// `PortRecorded` reply whether the port was held or not, because a row
/// that holds nothing the report names is already the report's goal
/// state. One info line per report, the same shape the admit path's
/// answers with.
fn withdraw_report_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: WithdrawPortRequest,
) -> std::io::Result<()> {
    let source = source_text(request.source);
    let row = boxes.withdraw_runtime_port(request.switch_address, request.port, request.proto);
    match &row {
        Some(record) => tracing::info!(
            box = %record.name(),
            switch_address = %request.switch_address,
            port = request.port,
            proto = %request.proto,
            source = %source,
            "withdrew the box's runtime-admitted port from the host-held grant"
        ),
        None => tracing::info!(
            switch_address = %request.switch_address,
            port = request.port,
            proto = %request.proto,
            source = %source,
            "no live row holds the withdrawn port; the grant's goal state already holds"
        ),
    }
    write_reply(
        stream,
        &BoxControlReply::PortRecorded {
            port: request.port,
            proto: request.proto,
        },
    )
}

/// Serve the read-only row verb (NET-138): the live row the asked-for name
/// resolves to under the identity rule — a box's id on the host is its
/// name, exact, and liveness is the table's own fact — answered with its
/// switch address, its derived egress allow-list, and its declared and
/// runtime-admitted ports. A name no live box holds answers the no-row
/// marker: a withdrawn row is gone, not archived, so a destroyed box's
/// last row can never be read. The verb changes no state and writes no
/// log line; the socket it answers on — the host's, whose owner-only file
/// mode is its access control — is the verb's whole posture.
fn read_row_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: ReadRowRequest,
) -> std::io::Result<()> {
    let reply = match boxes.row_by_name(&request.name) {
        Some(record) => BoxControlReply::Row(BoxRow {
            name: record.name().to_string(),
            box_id: minimald_rpc::BoxId::from_bytes(record.box_id()),
            switch_address: record.switch_addr(),
            egress_allow_list: record.egress_allow_list().to_vec(),
            declared_ports: record.admitted_ports().to_vec(),
            runtime_ports: record.runtime_port_numbers(),
        }),
        None => BoxControlReply::NoRow {
            name: request.name.clone(),
            no_row: true,
        },
    };
    write_reply(stream, &reply)
}

/// The reporting source as a log line names it: the one spelling the
/// diagnostics name the three reporting sides by.
fn source_text(source: PortReportSource) -> &'static str {
    match source {
        PortReportSource::Expose => "expose",
        PortReportSource::Ask => "ask",
        PortReportSource::Listen => "listen",
    }
}

/// The audit copy's path, derived from the control socket's own dir: the
/// provider-instance dir is this daemon's state for the VM it serves, so
/// the log lives beside the sockets and the persisted state it speaks for.
fn audit_log_path(sock_path: &Path) -> PathBuf {
    match sock_path.parent() {
        Some(dir) => dir.join(AUDIT_LOG_RELATIVE_PATH),
        None => PathBuf::from(AUDIT_LOG_RELATIVE_PATH),
    }
}

/// One recorded admission's host-side audit copy (NET-138): the same event
/// the info line says, in the shape a tail and a diagnostic bundle's copy
/// both parse — one JSON object per line, JSONL like the in-VM daemon's
/// own audit log, so both ends of the report channel write the same form.
#[derive(serde::Serialize)]
struct AdmittedPortAudit {
    /// When the report was recorded: Unix seconds.
    ts: u64,
    /// The box the port was recorded for — its name.
    #[serde(rename = "box")]
    box_name: String,
    /// The row the port recorded into — its switch address, the key the
    /// report carried.
    switch_address: Ipv4Addr,
    /// The recorded port.
    port: u16,
    /// The protocol the port was published under.
    proto: IpProto,
    /// Which side of the in-VM daemon reported it.
    source: PortReportSource,
}

/// Append one recorded admission's host-side copy to the daemon's audit
/// log. Best-effort by design: the report itself was already recorded —
/// the row holds the port — so a copy that cannot be written is a warn
/// line, never a failed report and never a rollback of the admission the
/// grant already admitted. The parent dirs are created when absent (the
/// first admission on a fresh state dir), and the append is a plain
/// one-line write, since this file is host-side state the guest cannot
/// reach. The file is created owner-only (0600), the posture the sockets
/// beside it carry: it names every box and port a guest admitted.
fn append_audit_copy(
    path: &Path,
    record: &Arc<crate::box_registry::BoxRecord>,
    request: &AdmitPortRequest,
) {
    append_audit_line(
        path,
        &AdmittedPortAudit {
            ts: unix_now_secs(),
            box_name: record.name().to_string(),
            switch_address: request.switch_address,
            port: request.port,
            proto: request.proto,
            source: request.source,
        },
    );
}

/// Append one JSON line to the daemon's owner-only audit log: the shared
/// half of the admission copy and the ask records.
fn append_audit_line(path: &Path, line: &impl serde::Serialize) {
    let Ok(json) = serde_json_lenient::to_string(line) else {
        // A plain struct of primitives serializes; this arm is unreachable
        // in practice and costs nothing to keep honest.
        tracing::warn!("an audit line did not serialize");
        return;
    };
    let written = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        // One write per line: the ask threads append concurrently, and a
        // line written in two pieces could interleave with another's.
        file.write_all(format!("{json}\n").as_bytes())
    })();
    if let Err(error) = written {
        tracing::warn!(
            %error,
            path = %path.display(),
            "an audit line could not be appended to the host-side audit log"
        );
    }
}

/// Run one ask verb's connection on a thread of its own (NET-045): the ask
/// or the subscription holds the connection open, so it must not hold the
/// door's serial accept loop with it. A thread that cannot be spawned is
/// answered on the spot with the reason, and the connection closes.
fn spawn_ask_thread(
    mut stream: UnixStream,
    name: &str,
    boxes: &BoxRegistry,
    audit_path: &Path,
    serve: impl FnOnce(UnixStream, &BoxRegistry, &Path) + Send + 'static,
) -> std::io::Result<()> {
    let thread_stream = stream.try_clone()?;
    let boxes = boxes.clone();
    let audit_path = audit_path.to_path_buf();
    match std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || serve(thread_stream, &boxes, &audit_path))
    {
        Ok(_) => Ok(()),
        Err(error) => {
            tracing::warn!(%error, thread = %name, "could not start an ask verb's thread");
            write_reply(
                &mut stream,
                &BoxControlReply::Error {
                    error: format!("the VM host daemon could not serve the ask verb: {error}"),
                },
            )
        }
    }
}

/// Watch a held connection for its peer's close on a thread of its own and
/// run `on_close` once it comes (NET-045): the close is how a guest
/// withdraws its ask and how a host client detaches. Answers the receiving
/// end of a signal sent when the close is seen. A connection with no read
/// bound — the ask verbs hold theirs for as long as the human takes — is
/// read until EOF or an error; bytes past the request line are discarded.
fn watch_peer_close(
    stream: &UnixStream,
    on_close: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::sync::mpsc::Receiver<()>> {
    let mut watched = stream.try_clone()?;
    watched.set_read_timeout(None)?;
    let (closed, closed_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("minvmd-ask-watch".to_string())
        .spawn(move || {
            let mut sink = [0u8; 256];
            loop {
                match watched.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            on_close();
            let _ = closed.send(());
        })?;
    Ok(closed_rx)
}

/// When the last queue-full warn line was written: the line is rate-limited
/// to one per [`QUEUE_FULL_WARN_EVERY`], because a guest asking in a loop
/// must not flood the daemon's log; the refusals in between are debug
/// lines, and every one is audited.
static QUEUE_FULL_WARNED: Mutex<Option<std::time::Instant>> = Mutex::new(None);

/// The queue-full warn line's rate limit.
const QUEUE_FULL_WARN_EVERY: Duration = Duration::from_secs(10);

/// Serve the in-VM daemon's ask (NET-045) on its own thread: record it
/// pending, hold the connection until the ask ends, and answer the end.
///
/// The ask ends only by a recorded answer on the host door or by a
/// cancellation: the guest closing its connection (its withdrawal), the
/// row's withdrawal, or the last attached client's detach. Nothing here
/// waits on a timer for it. The end is written to the guest as its reply
/// and as one audit line; then, as on every guest-door connection, the
/// door waits for the guest's close before dropping its end (G-N8).
fn serve_guest_ask(
    mut stream: UnixStream,
    boxes: &BoxRegistry,
    audit_path: &Path,
    request: minimald_rpc::AdmitAskRequest,
) {
    let (reply, outcome) = std::sync::mpsc::channel();
    let recorded =
        match boxes.record_ask(request.switch_address, request.port, request.proto, reply) {
            Ok(recorded) => recorded,
            Err(refusal) => {
                log_ask_refusal(&refusal, &request);
                audit_ask(
                    audit_path,
                    AskAudit::new(refused_text(refusal.reason), refusal.ask_id)
                        .with_facts(refusal.facts.as_ref())
                        .with_request(&request),
                );
                let _ = write_reply(
                    &mut stream,
                    &BoxControlReply::AskAdmit(minimald_rpc::AskAdmitOutcome::Refused {
                        ask_id: refusal.ask_id,
                        reason: refusal.reason,
                    }),
                );
                drain_until_peer_closes(&mut stream);
                return;
            }
        };
    let ask_id = recorded.ask_id;
    tracing::info!(
        %ask_id,
        box = %recorded.facts.name,
        box_id = %crate::bep_attach::BoxIdText(&recorded.facts.box_id),
        port = recorded.facts.port,
        proto = %recorded.facts.proto,
        "recorded a pending ask from the in-VM daemon"
    );
    if let Some(offered) = &recorded.offered {
        log_and_audit_offer(audit_path, offered);
    }
    // The guest's close is its withdrawal: it cancels the ask when it comes
    // first, and is the drain's end when it comes after the reply.
    let watcher_boxes = boxes.clone();
    let watcher_audit = audit_path.to_path_buf();
    let closed = match watch_peer_close(&stream, move || {
        if let Some(ended) = watcher_boxes.cancel_ask(ask_id) {
            tracing::info!(
                %ask_id,
                box = %ended.facts.name,
                port = ended.facts.port,
                dismissed = ended.dismissed,
                "cancelled a pending ask: the in-VM daemon withdrew it"
            );
            if let Some(offered) = &ended.offered_next {
                log_and_audit_offer(&watcher_audit, offered);
            }
        }
    }) {
        Ok(closed) => closed,
        Err(error) => {
            // Without the watcher a withdrawn ask would stay offered, so the
            // ask is cancelled now rather than left with no way to end.
            tracing::warn!(%ask_id, %error, "could not watch the asking connection");
            let _ = boxes.cancel_ask(ask_id);
            std::sync::mpsc::channel().1
        }
    };
    // The book sends every ask's end exactly once; a closed channel means
    // the registry itself went away, which is the daemon's stop.
    let outcome = outcome
        .recv()
        .unwrap_or(minimald_rpc::AskAdmitOutcome::Refused {
            ask_id,
            reason: minimald_rpc::AskRefused::Cancelled,
        });
    audit_ask(
        audit_path,
        AskAudit::new(outcome_text(&outcome), ask_id).with_facts(Some(&recorded.facts)),
    );
    let _ = write_reply(&mut stream, &BoxControlReply::AskAdmit(outcome));
    if closed.recv_timeout(GUEST_REPORT_DRAIN_TIMEOUT).is_err() {
        // A guest that holds its end past the drain bound is ended here,
        // which also releases the watcher's read.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Serve an attached host client's subscription to one row's pending asks
/// (NET-045) on its own thread: register it by the row's box id, answer the
/// subscription, then write every offer and dismissal the book pushes until
/// the client detaches. The detach — the client's close — ends the
/// subscription, and the last detach for a box cancels its pending asks.
fn serve_ask_subscription(
    mut stream: UnixStream,
    boxes: &BoxRegistry,
    _audit_path: &Path,
    box_id: minimald_rpc::BoxId,
) {
    let box_id = box_id.to_bytes();
    let (pushes, pushed) = std::sync::mpsc::channel();
    let Some((subscriber, standing)) = boxes.subscribe_asks(box_id, pushes) else {
        tracing::info!(
            box_id = %crate::bep_attach::BoxIdText(&box_id),
            "refused an ask subscription: no live row holds the box id"
        );
        let _ = write_reply(
            &mut stream,
            &BoxControlReply::Error {
                error: format!(
                    "no live box row holds box id {}; there are no asks to subscribe to",
                    crate::bep_attach::BoxIdText(&box_id)
                ),
            },
        );
        return;
    };
    tracing::info!(
        box_id = %crate::bep_attach::BoxIdText(&box_id),
        subscriber,
        "a host client attached to the box's pending asks"
    );
    if let Some(offered) = standing {
        tracing::info!(
            ask_id = %offered.ask_id,
            subscriber,
            "offered the box's open ask to the newly attached client"
        );
    }
    let detach = {
        let boxes = boxes.clone();
        move || unsubscribe_and_log(&boxes, box_id, subscriber)
    };
    let closed = watch_peer_close(&stream, detach);
    let acked = write_reply(
        &mut stream,
        &BoxControlReply::AsksSubscribed {
            subscribed: true,
            box_id: minimald_rpc::BoxId::from_bytes(box_id),
        },
    );
    if closed.is_err() || acked.is_err() {
        unsubscribe_and_log(boxes, box_id, subscriber);
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return;
    }
    // The detach drops the book's sending end, which ends this loop.
    for push in pushed {
        if write_reply(&mut stream, &push).is_err() {
            unsubscribe_and_log(boxes, box_id, subscriber);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            break;
        }
    }
}

/// End one client's subscription and log the asks the detach cancelled.
/// Idempotent: a second call for the same subscriber finds nothing to end.
fn unsubscribe_and_log(boxes: &BoxRegistry, box_id: crate::bep_attach::BoxId, subscriber: u64) {
    let cancelled = boxes.unsubscribe_asks(box_id, subscriber);
    tracing::info!(
        box_id = %crate::bep_attach::BoxIdText(&box_id),
        subscriber,
        cancelled = cancelled.len(),
        "a host client detached from the box's pending asks"
    );
    for ended in cancelled {
        tracing::info!(
            ask_id = %ended.ask_id,
            box = %ended.facts.name,
            port = ended.facts.port,
            "cancelled a pending ask: the last attached client detached"
        );
    }
}

/// Serve a host client's recorded answer (NET-045): end the pending ask it
/// names with the answer, and answer the client. The ask's outcome line
/// and audit record are the guest's serving thread's, which receives the
/// end; this door logs the answer and audits the row's next offer when one
/// takes the answered ask's place. An answer for an id the book does not
/// hold — unknown, cancelled, or already answered — records nothing, is
/// audited as refused, and answers an error.
fn record_ask_answer_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    audit_path: &Path,
    request: minimald_rpc::RecordAskAnswerRequest,
) -> std::io::Result<()> {
    let ask_id = request.ask_id;
    let reply = match boxes.record_ask_answer(ask_id, request.answer) {
        Ok(ended) => {
            tracing::info!(
                %ask_id,
                answer = %answer_text(request.answer),
                box = %ended.facts.name,
                port = ended.facts.port,
                proto = %ended.facts.proto,
                outcome = %outcome_text(&ended.outcome),
                dismissed = ended.dismissed,
                "recorded the attached client's answer to a pending ask; the first answer wins"
            );
            if let Some(offered) = &ended.offered_next {
                log_and_audit_offer(audit_path, offered);
            }
            BoxControlReply::AskAnswerRecorded {
                ask_id,
                recorded: true,
            }
        }
        Err(()) => {
            tracing::warn!(
                %ask_id,
                "refused an ask answer: no pending ask holds the id (unknown, cancelled or \
                 already answered)"
            );
            audit_ask(audit_path, AskAudit::new("refused_unknown_id", ask_id));
            BoxControlReply::Error {
                error: format!(
                    "no pending ask holds id {ask_id}: it is unknown, cancelled or already \
                     answered"
                ),
            }
        }
    };
    write_reply(stream, &reply)
}

/// Log an offer — how many attached clients it reached — and audit it.
fn log_and_audit_offer(audit_path: &Path, offered: &crate::box_registry::AskOffered) {
    tracing::info!(
        ask_id = %offered.ask_id,
        box = %offered.facts.name,
        port = offered.facts.port,
        proto = %offered.facts.proto,
        clients = offered.offered_to,
        "offered a pending ask to the box's attached clients"
    );
    let mut line = AskAudit::new("offered", offered.ask_id).with_facts(Some(&offered.facts));
    line.offered_to = Some(offered.offered_to);
    audit_ask(audit_path, line);
}

/// Log a refused ask: a warn line per refusal, except a full queue, whose
/// warn is rate-limited ([`QUEUE_FULL_WARNED`]).
fn log_ask_refusal(
    refusal: &crate::box_registry::AskRecordRefusal,
    request: &minimald_rpc::AdmitAskRequest,
) {
    let warn = refusal.reason != minimald_rpc::AskRefused::QueueFull || {
        let mut last = QUEUE_FULL_WARNED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::time::Instant::now();
        let due = last.is_none_or(|at| now.duration_since(at) >= QUEUE_FULL_WARN_EVERY);
        if due {
            *last = Some(now);
        }
        due
    };
    let box_name = refusal.facts.as_ref().map(|facts| facts.name.as_str());
    if warn {
        tracing::warn!(
            ask_id = %refusal.ask_id,
            box = ?box_name,
            switch_address = %request.switch_address,
            port = request.port,
            proto = %request.proto,
            reason = %refused_text(refusal.reason),
            "refused the in-VM daemon's ask"
        );
    } else {
        tracing::debug!(
            ask_id = %refusal.ask_id,
            box = ?box_name,
            port = request.port,
            reason = %refused_text(refusal.reason),
            "refused the in-VM daemon's ask"
        );
    }
}

/// An answer as a log line names it.
fn answer_text(answer: minimald_rpc::AskAnswer) -> &'static str {
    match answer {
        minimald_rpc::AskAnswer::Yes => "yes",
        minimald_rpc::AskAnswer::No => "no",
        minimald_rpc::AskAnswer::NoTty => "no_tty",
    }
}

/// An ask's end as its audit line names it.
fn outcome_text(outcome: &minimald_rpc::AskAdmitOutcome) -> &'static str {
    match outcome {
        minimald_rpc::AskAdmitOutcome::Admitted { .. } => "yes",
        minimald_rpc::AskAdmitOutcome::Refused { reason, .. } => refused_text(*reason),
    }
}

/// A refused ask's end as its audit line names it: the human's no and the
/// render that found no terminal by their own names, a cancellation as
/// such, and every refusal the host made for the ask by its reason.
fn refused_text(reason: minimald_rpc::AskRefused) -> &'static str {
    match reason {
        minimald_rpc::AskRefused::Denied => "no",
        minimald_rpc::AskRefused::NoTty => "no_tty",
        minimald_rpc::AskRefused::Cancelled => "cancelled",
        minimald_rpc::AskRefused::NoClient => "refused_no_client",
        minimald_rpc::AskRefused::QueueFull => "refused_queue_full",
        minimald_rpc::AskRefused::NoRow => "refused_no_row",
        minimald_rpc::AskRefused::StanceNotAsk => "refused_stance_not_ask",
        minimald_rpc::AskRefused::OutsideGrant => "refused_outside_grant",
    }
}

/// One ask event's line in the daemon's owner-only audit log (NET-045):
/// the record of the event, beside the admission copies, in the same JSONL
/// form. It names the ask by its host-minted id and the box by its host
/// row — its id and name — with the row key, the port and the protocol,
/// and carries no text the guest supplied.
#[derive(serde::Serialize)]
struct AskAudit {
    /// When the event happened: Unix seconds.
    ts: u64,
    /// Always `ask`: what sets these lines apart from the admission copies.
    event: &'static str,
    /// What happened: `offered`, `yes`, `no`, `no_tty`, `cancelled`, or a
    /// `refused_` reason.
    outcome: &'static str,
    /// The ask's host-minted id.
    ask_id: String,
    /// The row's box id; absent when no row is held at the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    box_id: Option<String>,
    /// The row's box name; absent when no row is held at the address.
    #[serde(rename = "box", skip_serializing_if = "Option::is_none")]
    box_name: Option<String>,
    /// The row key the ask named.
    #[serde(skip_serializing_if = "Option::is_none")]
    switch_address: Option<Ipv4Addr>,
    /// The port the ask named.
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    /// The protocol the ask named.
    #[serde(skip_serializing_if = "Option::is_none")]
    proto: Option<IpProto>,
    /// How many attached clients an offer reached.
    #[serde(skip_serializing_if = "Option::is_none")]
    offered_to: Option<usize>,
}

impl AskAudit {
    fn new(outcome: &'static str, ask_id: minimald_rpc::AskId) -> Self {
        Self {
            ts: unix_now_secs(),
            event: "ask",
            outcome,
            ask_id: ask_id.to_string(),
            box_id: None,
            box_name: None,
            switch_address: None,
            port: None,
            proto: None,
            offered_to: None,
        }
    }

    /// The host row's facts, when there are any.
    fn with_facts(mut self, facts: Option<&crate::box_registry::AskFacts>) -> Self {
        if let Some(facts) = facts {
            self.box_id = Some(crate::bep_attach::BoxIdText(&facts.box_id).to_string());
            self.box_name = Some(facts.name.clone());
            self.switch_address = Some(facts.switch_address);
            self.port = Some(facts.port);
            self.proto = Some(facts.proto);
        }
        self
    }

    /// The request's row key, port and protocol, where no row supplied
    /// them: numbers the refusal is about, never text.
    fn with_request(mut self, request: &minimald_rpc::AdmitAskRequest) -> Self {
        self.switch_address.get_or_insert(request.switch_address);
        self.port.get_or_insert(request.port);
        self.proto.get_or_insert(request.proto);
        self
    }
}

/// Append one ask event's audit line.
fn audit_ask(path: &Path, line: AskAudit) {
    append_audit_line(path, &line);
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixStream as TestStream;
    use std::sync::OnceLock;
    use std::time::Duration;

    use minimald_rpc::{
        BoxControlReply, BoxControlRequest, RegisterBoxRequest, WithdrawBoxRequest,
        ZoneAnswererStatus,
    };
    use switch::SwitchSubnet;

    use crate::box_registry::{AllocationError, PENDING_ASKS_PER_ROW};
    use crate::net::egress_gate::test_support::CaptureWriter;

    use super::*;

    /// The default switch subnet, the plan the registries below are built
    /// for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// A process-global log capture. The server serves on its own OS
    /// thread, so the thread-local captures the crate's other tests install
    /// do not see its lines; the global default is installed once per
    /// process and shadowed by those thread-local ones wherever they exist.
    static SERVER_LOG: OnceLock<CaptureWriter> = OnceLock::new();

    fn server_capture() -> &'static CaptureWriter {
        SERVER_LOG.get_or_init(|| {
            let capture = CaptureWriter::default();
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(capture.clone())
                    .with_ansi(false)
                    .finish(),
            )
            .expect("no other test in this binary installs a process-wide subscriber");
            capture
        })
    }

    /// Spawns the control server on a temp path over a fresh registry and
    /// returns (path, handle keeping the server thread identified, the
    /// registry the server serves — the same rows a gate the test brings up
    /// later shares — and the answerer status the read-only verb answers
    /// from, the same cell the daemon's acquisition loop writes). The
    /// proxy-publish cell is the same cell a supervisor writes a
    /// proxy-down cause into (T93), empty at the bind. The thread
    /// outlives the test the way a daemon's does; the temp dir's drop after
    /// the test closes the test's view of the socket.
    fn spawn_server(
        dir: &std::path::Path,
    ) -> std::io::Result<(
        PathBuf,
        JoinHandle<()>,
        BoxRegistry,
        AnswererStatus,
        ProxyPublishStatus,
    )> {
        let sock_path = dir.join(CONTROL_SOCK_FILE);
        let boxes = BoxRegistry::new(SUBNET);
        let answerer = AnswererStatus::allocating_for_tests("control-test-node");
        let proxy_publish = ProxyPublishStatus::new();
        let handle = spawn(
            sock_path.clone(),
            boxes.clone(),
            answerer.clone(),
            proxy_publish.clone(),
        )?;
        // Wait until the socket accepts rather than racing the bind.
        for _ in 0..500 {
            if TestStream::connect(&sock_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        spawn_guest_door(&sock_path, &boxes, &answerer, &proxy_publish)?;
        Ok((sock_path, handle, boxes, answerer, proxy_publish))
    }

    /// Serves [`ControlDoor::GuestReports`] on the guest door beside
    /// `sock_path`, through the same production bind the supervisor calls
    /// behind the vsock bridge — posture, audit path, drain and all — so the
    /// per-door verb enforcement runs the runtime's own door.
    fn spawn_guest_door(
        sock_path: &std::path::Path,
        boxes: &BoxRegistry,
        answerer: &AnswererStatus,
        proxy_publish: &ProxyPublishStatus,
    ) -> std::io::Result<()> {
        spawn_guest_reports_door(
            sock_path,
            boxes.clone(),
            answerer.clone(),
            proxy_publish.clone(),
        )
        .map(|_| ())
    }

    /// A client that writes the request and reads the reply line back,
    /// mirroring the CLI's control helper.
    fn control(
        sock_path: &std::path::Path,
        request: &BoxControlRequest,
    ) -> std::io::Result<BoxControlReply> {
        let mut stream = TestStream::connect(sock_path)?;
        let mut line = serde_json_lenient::to_string(request).map_err(|error| {
            std::io::Error::other(format!("request did not serialize: {error}"))
        })?;
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        let mut reader = BufReader::new(stream);
        let mut reply = String::new();
        reader.read_line(&mut reply)?;
        serde_json_lenient::from_str(reply.trim())
            .map_err(|error| std::io::Error::other(format!("reply did not parse: {error}")))
    }

    /// A client that registers a box, wrapping the registration into the
    /// wire envelope.
    fn register(
        sock_path: &std::path::Path,
        request: &RegisterBoxRequest,
    ) -> std::io::Result<BoxControlReply> {
        control(sock_path, &BoxControlRequest::Register(request.clone()))
    }

    /// The registered box the daemon hands back — both addresses and the
    /// box's own id — panicked into the test when the reply is a refusal or
    /// a status instead.
    fn handed(reply: BoxControlReply) -> RegisteredBox {
        match reply {
            other @ (BoxControlReply::AsksSubscribed { .. }
            | BoxControlReply::PendingAskOffer(_)
            | BoxControlReply::PendingAskDismissed { .. }
            | BoxControlReply::AskAnswerRecorded { .. }
            | BoxControlReply::AskAdmit(_)) => {
                panic!("a box verb is never answered with an ask verb's reply, got {other:?}")
            }
            BoxControlReply::Registered(web) => web,
            BoxControlReply::Addresses(addresses) => {
                panic!(
                    "a registration is answered with the registered box, got bare addresses {addresses:?}"
                )
            }
            BoxControlReply::Error { error } => {
                panic!("a valid request is answered with the registered box, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!(
                    "a registration is answered with the registered box, got the status {status:?}"
                )
            }
            BoxControlReply::Row(row) => {
                panic!("a registration is answered with the registered box, got a row read {row:?}")
            }
            BoxControlReply::NoRow { name, .. } => {
                panic!(
                    "a registration is answered with the registered box, told no row is held for {name:?}"
                )
            }
            BoxControlReply::PortRecorded { port, proto } => {
                panic!(
                    "a registration is answered with the registered box, got a port report's \
                     reply for {port}/{proto:?}"
                )
            }
            BoxControlReply::AnswererRelease { detail, .. } => {
                panic!("a box verb is never answered with a release reply, got {detail}")
            }
        }
    }

    /// The end-to-end shape of the layer: the activating client registers
    /// over the control socket, the host allocates the box's switch and
    /// loopback addresses into its table and hands them back, allocations
    /// advance without reuse, a refusal names its reason, and the server
    /// keeps serving past one. The registration's one info line names the
    /// box and both addresses — the line a bundle's VM host daemon log is
    /// read for.
    #[test]
    fn box_addresses_allocated_on_host_and_handed_to_daemon() {
        let capture = server_capture();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, _answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");

        // The first registration is handed the hand-out run's first switch
        // address — the plan's PTask run above the daemon's self-allocation
        // reserve, mirrored from `minimald::net::self_allocation_run` — and
        // the first published loopback address.
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: vec![8080, 9090],
                    egress: Some(sessions::EgressPolicy {
                        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                        allow_dns_hosts: None,
                        deny_subnets: None,
                    }),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("first registration is answered"),
        );
        assert_eq!(
            web.switch_address,
            Ipv4Addr::new(100, 64, 127, 255),
            "the first box takes the hand-out run's first address, above the \
             daemon's reserve"
        );
        assert_eq!(
            web.loopback_address,
            Ipv4Addr::new(127, 0, 64, 2),
            "the first box takes the lowest box address the machine's answerer hands out \
             (design §7.1): never the range's network address or .1"
        );
        assert_eq!(
            web.box_id,
            minimald_rpc::BoxId::from_bytes(
                registry
                    .table()
                    .by_source(web.switch_address.octets())
                    .expect("the registration published the row the reply speaks for")
                    .box_id()
            ),
            "the reply carries the id the published row holds — the box's own id"
        );
        assert_ne!(
            web.box_id,
            minimald_rpc::BoxId::from_bytes([0u8; 16]),
            "the id is a minted UUIDv7, never the all-zero non-id"
        );

        // The registration's one info line names the box, its id, both
        // addresses it handed back, and the declared egress the row carries.
        let log = capture.contents();
        assert!(
            log.contains("registered box with the VM host daemon; addresses allocated"),
            "one info line per registration names the event: {log}"
        );
        assert!(
            log.contains("box=web")
                && log.contains(&format!("switch_address={}", web.switch_address))
                && log.contains(&format!("loopback_address={}", web.loopback_address)),
            "the info line names the box and the addresses it handed back: {log}"
        );
        assert!(
            log.contains(&format!("box_id={}", web.box_id)),
            "the info line carries the box's own id in the one spelling a tail reads: {log}"
        );
        assert!(
            log.contains(r#""allow_subnets":["10.0.0.0/8"]"#)
                && log.contains(r#""allow_protocols":["tcp"]"#),
            "the info line carries the declared egress allow-list: {log}"
        );

        // The second registration takes the next address on both runs —
        // sequential allocation, no reuse — and mints the next box its own
        // id: one id per creation, never shared.
        let db = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "db".to_string(),
                    ingress_ports: vec![5432],
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("second registration is answered"),
        );
        assert_ne!(
            db.box_id, web.box_id,
            "the second box is created as its own identity, not the first's"
        );
        assert_eq!(
            db.switch_address,
            Ipv4Addr::new(100, 64, 128, 0),
            "the second box takes the hand-out run's next address, never the first again"
        );
        assert_eq!(
            db.loopback_address,
            Ipv4Addr::new(127, 0, 64, 3),
            "the second box takes the answerer's next free box address"
        );

        // A malformed request is answered with the reason, not a hang.
        let mut stream = TestStream::connect(&sock_path).expect("socket accepts");
        stream.write_all(b"this is not json\n").expect("write");
        let mut reader = BufReader::new(stream);
        let mut reply = String::new();
        reader.read_line(&mut reply).expect("reply read");
        let refused: BoxControlReply =
            serde_json_lenient::from_str(reply.trim()).expect("error reply parses");
        assert!(
            matches!(refused, BoxControlReply::Error { .. }),
            "a malformed request is answered with the reason, got {refused:?}"
        );

        // And the server keeps serving after a refusal.
        handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "cache".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("server still serves after a refused request"),
        );
    }

    /// The registry-level behaviour the socket fronts: a registration fills
    /// the row the gate reads from the client's expanded spec, at the
    /// addresses the reply would carry — asserted here at the verdict level
    /// the gate decides by, not the field level.
    #[test]
    fn client_registration_fills_the_row_the_gate_reads() {
        let registry = BoxRegistry::new(SUBNET);
        let table = registry.table();
        let record = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: vec![8080],
                egress: Some(sessions::EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has addresses to allocate");

        let row = table
            .by_source(record.switch_addr().octets())
            .expect("the registration filled the row the gate reads");
        assert_eq!(row.name(), "web");
        assert_eq!(row.switch_addr(), record.switch_addr());
        assert_eq!(row.loopback_addr(), record.loopback_addr());
        assert_eq!(row.admitted_ports(), [8080]);
        // The compiled rules are the gate's decision surface: a TCP frame to
        // an allowed subnet is admitted, and one to a disallowed one is not.
        let frame = crate::net::egress_gate::test_support::ipv4_frame(
            record.switch_addr().octets(),
            6,
            [10, 0, 0, 1],
            80,
        );
        let summary = sessions::core::egress::summarize(&frame);
        let verdict = sessions::core::egress::verdict(&summary, row.egress());
        assert!(
            matches!(verdict, sessions::core::egress::FrameVerdict::Admit),
            "the compiled policy admits what the declaration allows, got {verdict:?}"
        );
        let outside = crate::net::egress_gate::test_support::ipv4_frame(
            record.switch_addr().octets(),
            6,
            [203, 0, 113, 7],
            443,
        );
        let outside_summary = sessions::core::egress::summarize(&outside);
        assert!(
            matches!(
                sessions::core::egress::verdict(&outside_summary, row.egress()),
                sessions::core::egress::FrameVerdict::Drop(_)
            ),
            "the compiled policy drops what the declaration does not allow"
        );
    }

    /// An unplanned subnet serves no loopback slice: an explicit
    /// registration still works there (it brings its own addresses), a
    /// client-driven one is refused with the reason — never a panic, never
    /// a fabricated address.
    #[test]
    fn client_registration_on_an_unplanned_subnet_is_refused() {
        let unplanned = SwitchSubnet::new(Ipv4Addr::new(10, 0, 1, 0), 24).expect("valid");
        let registry = BoxRegistry::new(unplanned);
        let error = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect_err("an unplanned subnet has no slice to allocate from");
        assert!(
            matches!(error, AllocationError::UnplannedSubnet(_)),
            "the refusal names the cause, got {error:?}"
        );
        assert!(
            registry.table().is_empty(),
            "a refused registration publishes no row"
        );
    }

    /// The withdrawal round-trip the destroyed session's client drives
    /// (T66): it registers the box, presents the pair the registration
    /// handed back to prove it is the row's creator, and the daemon removes
    /// the row from its table — at both addresses. What the gate then
    /// decides at the withdrawn switch address is unconditional: the
    /// unregistered drop (NET-085) refuses the frame — the row's rules
    /// ended with the row — so no flip of the per-box default changes it.
    #[tokio::test]
    async fn host_row_withdrawn_on_destroy() {
        use crate::net::egress_gate::test_support;

        let capture = server_capture();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, _answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");

        // The registering client holds the pair the registration hands
        // back — the destroy-side proof it is the row's creator.
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: vec![8080],
                    egress: Some(sessions::EgressPolicy {
                        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                        allow_dns_hosts: None,
                        deny_subnets: None,
                    }),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("the registration is answered"),
        );
        let row = registry
            .table()
            .by_source(web.switch_address.octets())
            .expect("the registration published the row the gate reads");
        assert_eq!(row.loopback_addr(), web.loopback_address);

        // The withdrawal round-trips and is answered with the pair echoed
        // back, and the table holds no row at either address after it.
        let reply = control(
            &sock_path,
            &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                name: "web".to_string(),
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
        )
        .expect("the withdrawal is answered");
        match reply {
            other @ (BoxControlReply::AsksSubscribed { .. }
            | BoxControlReply::PendingAskOffer(_)
            | BoxControlReply::PendingAskDismissed { .. }
            | BoxControlReply::AskAnswerRecorded { .. }
            | BoxControlReply::AskAdmit(_)) => {
                panic!("a box verb is never answered with an ask verb's reply, got {other:?}")
            }
            BoxControlReply::Addresses(echoed) => {
                assert!(
                    echoed.switch_address == web.switch_address
                        && echoed.loopback_address == web.loopback_address,
                    "the withdrawal echoes the pair it went by: {echoed:?}"
                );
            }
            BoxControlReply::Registered(..) => {
                panic!("a withdrawal echoes the pair it went by, never a registered box")
            }
            BoxControlReply::Error { error } => {
                panic!("the creator's withdrawal is answered with the pair, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!("a withdrawal is answered with the pair, got the status {status:?}")
            }
            BoxControlReply::Row(..) => {
                panic!("a withdrawal echoes the pair it went by, never a row")
            }
            BoxControlReply::NoRow { .. } => {
                panic!("a withdrawal echoes the pair it went by, never a no-row marker")
            }
            BoxControlReply::PortRecorded { .. } => {
                panic!("a withdrawal echoes the pair it went by, never a port report")
            }
            BoxControlReply::AnswererRelease { detail, .. } => {
                panic!("a box verb is never answered with a release reply, got {detail}")
            }
        }
        assert!(
            registry
                .table()
                .by_source(web.switch_address.octets())
                .is_none(),
            "the withdrawn switch address publishes no row"
        );
        assert!(
            registry
                .table()
                .rows()
                .iter()
                .all(|row| row.loopback_addr() != web.loopback_address),
            "the withdrawn loopback address publishes no row either"
        );

        // One info line per withdrawal, mirroring the registration's.
        let log = capture.contents();
        assert!(
            log.contains("withdrew the box's host row; its addresses admit nothing"),
            "one info line names the withdrawal: {log}"
        );
        assert!(
            log.contains("box=web")
                && log.contains(&format!("switch_address={}", web.switch_address))
                && log.contains(&format!("loopback_address={}", web.loopback_address)),
            "the info line names the box and both addresses: {log}"
        );

        // A row is its creator's to withdraw, so a live row whose proof
        // does not match is refused with the reason and stays published:
        // another box's name at this row's address, and the right name with
        // a loopback the registration did not hand back.
        let db = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "db".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("the marker box is registered"),
        );
        for (name, loopback, needle) in [
            ("web", db.loopback_address, "held by box"),
            ("db", Ipv4Addr::LOCALHOST, "carries loopback address"),
        ] {
            let refused = control(
                &sock_path,
                &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                    name: name.to_string(),
                    switch_address: db.switch_address,
                    loopback_address: loopback,
                }),
            )
            .expect("the withdrawal is answered");
            match refused {
                other @ (BoxControlReply::AsksSubscribed { .. }
                | BoxControlReply::PendingAskOffer(_)
                | BoxControlReply::PendingAskDismissed { .. }
                | BoxControlReply::AskAnswerRecorded { .. }
                | BoxControlReply::AskAdmit(_)) => {
                    panic!("a box verb is never answered with an ask verb's reply, got {other:?}")
                }
                BoxControlReply::Error { error } => {
                    assert!(
                        error.contains(needle),
                        "the refusal names why the pair is not this row's ({needle}): {error}"
                    );
                }
                BoxControlReply::Addresses(..) => {
                    panic!("a foreign pair's withdrawal must be refused, got addresses")
                }
                BoxControlReply::Registered(..) => {
                    panic!("a foreign pair's withdrawal must be refused, got a registered box")
                }
                BoxControlReply::Status(status) => {
                    panic!("a withdrawal must be refused, got the status {status:?}")
                }
                BoxControlReply::Row(..) => {
                    panic!("a foreign pair's withdrawal must be refused, got a row")
                }
                BoxControlReply::NoRow { .. } => {
                    panic!("a foreign pair's withdrawal must be refused, got a no-row marker")
                }
                BoxControlReply::PortRecorded { .. } => {
                    panic!("a foreign pair's withdrawal must be refused, got a port report")
                }
                BoxControlReply::AnswererRelease { detail, .. } => {
                    panic!("a box verb is never answered with a release reply, got {detail}")
                }
            }
        }
        assert!(
            registry
                .table()
                .by_source(db.switch_address.octets())
                .is_some(),
            "a refused withdrawal leaves the row published"
        );

        // No row at the address is the goal state either way, so withdrawing
        // the same pair again is answered the same way.
        let again = control(
            &sock_path,
            &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                name: "web".to_string(),
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
        )
        .expect("the repeat withdrawal is answered");
        match again {
            other @ (BoxControlReply::AsksSubscribed { .. }
            | BoxControlReply::PendingAskOffer(_)
            | BoxControlReply::PendingAskDismissed { .. }
            | BoxControlReply::AskAnswerRecorded { .. }
            | BoxControlReply::AskAdmit(_)) => {
                panic!("a box verb is never answered with an ask verb's reply, got {other:?}")
            }
            BoxControlReply::Addresses(echoed) => {
                assert!(
                    echoed.switch_address == web.switch_address
                        && echoed.loopback_address == web.loopback_address,
                    "the repeat withdrawal echoes the pair too: {echoed:?}"
                );
            }
            BoxControlReply::Registered(..) => {
                panic!("a repeat withdrawal echoes the pair, never a registered box")
            }
            BoxControlReply::Error { error } => {
                panic!("no row at the address is success, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!("a repeat withdrawal echoes the pair, got the status {status:?}")
            }
            BoxControlReply::Row(..) => {
                panic!("a repeat withdrawal echoes the pair, never a row")
            }
            BoxControlReply::NoRow { .. } => {
                panic!("a repeat withdrawal echoes the pair, never a no-row marker")
            }
            BoxControlReply::PortRecorded { .. } => {
                panic!("a repeat withdrawal echoes the pair, never a port report")
            }
            BoxControlReply::AnswererRelease { detail, .. } => {
                panic!("a box verb is never answered with a release reply, got {detail}")
            }
        }

        // A line that names no verb this build knows is refused at the
        // parse, never reaching the table — the tagged wire's corner.
        let mut stream = TestStream::connect(&sock_path).expect("socket accepts");
        stream
            .write_all(b"{\"verb\":\"retire\",\"name\":\"web\"}\n")
            .expect("write the unknown-verb line");
        let mut reply = String::new();
        BufReader::new(stream)
            .read_line(&mut reply)
            .expect("reply read");
        let refused: BoxControlReply =
            serde_json_lenient::from_str(reply.trim()).expect("error reply parses");
        assert!(
            matches!(refused, BoxControlReply::Error { .. }),
            "an unknown verb is refused, got {refused:?}"
        );
        assert!(
            registry
                .table()
                .by_source(db.switch_address.octets())
                .is_some(),
            "a refused line publishes nothing and removes nothing"
        );

        // The gate shares the registry's table, as production does: the
        // unregistered drop (NET-085) refuses the withdrawn address's frame —
        // the row's rules ended with the row — while a published box's frame
        // is the marker that proves nothing else slipped. No phase reaches
        // this, so the shipped gate is the whole proof.
        let marker = test_support::ipv4_frame(db.switch_address.octets(), 6, [10, 1, 2, 3], 80);
        let from_withdrawn =
            test_support::ipv4_frame(web.switch_address.octets(), 6, [10, 1, 2, 3], 80);
        let mut h = test_support::gate_over(registry.clone()).await;
        test_support::send_frame(&mut h.guest, &from_withdrawn).await;
        test_support::send_frame(&mut h.guest, &marker).await;
        let seen = test_support::expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the gate drops the withdrawn address's frame and passes the \
             published box's"
        );
        test_support::expect_silence(&mut h.switch).await;
        test_support::wait_for_log(&h.log, "egress-unregistered-source").await;
        let logged = h.log.contents();
        assert!(
            logged.contains(&format!("source={}", web.switch_address)),
            "the drop line names the withdrawn source, got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "the withdrawn address is in-plan, so its drop is the \
             unregistered rule's, got: {logged}"
        );
    }

    /// The read-only verb: the socket answers the answerer's state — the
    /// last state the daemon's acquisition loop wrote, starting with the
    /// pre-acquisition `starting` — over the same connection shape every
    /// other verb is served on, and the read leaves the table untouched:
    /// rows published before it are still published after, and a
    /// registration still answers addresses around it.
    #[test]
    fn answerer_state_is_read_over_the_control_socket() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");

        // Before the acquisition loop's first pass, the read answers the
        // pre-acquisition state — the one the CLI treats as "nothing to
        // say yet" rather than a verdict.
        let reply = control(&sock_path, &BoxControlRequest::AnswererStatus)
            .expect("the status read is answered");
        assert_eq!(
            reply,
            BoxControlReply::Status(ZoneAnswererStatus::Starting),
            "the read answers the cell the daemon starts with"
        );

        // Every state the acquisition loop can leave the machine's
        // answerer in answers verbatim, on the same socket, one request
        // line in and one reply line out.
        let port = 7_656;
        for state in [
            ZoneAnswererStatus::Holder { port },
            ZoneAnswererStatus::Registered { port },
            ZoneAnswererStatus::ManagerHeld { port },
            ZoneAnswererStatus::PortHeldNoChannel { port },
        ] {
            answerer.set(state.clone());
            let reply = control(&sock_path, &BoxControlRequest::AnswererStatus)
                .expect("the status read is answered");
            assert_eq!(
                reply,
                BoxControlReply::Status(state),
                "the read answers the state the loop last wrote"
            );
        }

        // The read mutates nothing: a row published before it is still
        // published after, and the next registration is still answered
        // with the registered box.
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("a registration still answers around the read"),
        );
        assert!(
            registry
                .table()
                .by_source(web.switch_address.octets())
                .is_some(),
            "the read-only verb leaves the row the registration published"
        );
    }

    /// The drawn port's story (T93): a guest that reports its publish was
    /// refused for address-in-use redraws the port under the reservation
    /// while tries remain, the tries are the constant's (the first boot
    /// plus every redraw), and the refusal that outlasts them fails the
    /// start naming the port and the holder — the cause the status read
    /// then serves over this socket, for the CLI's surfaces to name.
    #[test]
    fn publish_in_use_redraws_then_fails_named() {
        let port = 19_911;
        let held = GuestPublish::PortHeld { port };

        // A serving publish is up, whatever the tries or the origin: a
        // boot that landed is a boot that landed.
        assert_eq!(
            decide_publish(true, 1, GuestPublish::Serving { port }),
            PublishDecision::Up,
            "a serving publish never fails the start"
        );

        // The first two publishes that find the port taken redraw: the
        // first boot's refusal and the first redraw's, each naming the port
        // the publish could not take.
        for tries_used in 1..PUBLISH_TRIES {
            assert_eq!(
                decide_publish(true, tries_used, held),
                PublishDecision::Redraw { port },
                "a drawn port with tries left redraws, at try {tries_used}"
            );
        }

        // The third try's refusal exhausts them: the start fails, naming
        // the port and the holder, with the cause the CLI names.
        match decide_publish(true, PUBLISH_TRIES, held) {
            PublishDecision::FailStart {
                port: named,
                holder,
                cause,
            } => {
                assert_eq!(named, port, "the failure names the port");
                assert_eq!(
                    holder, HELD_BY_ANOTHER_PROCESS,
                    "the failure names the holder"
                );
                assert_eq!(
                    cause,
                    ProxyDownCause::RedrawsRanOut,
                    "the cause is the draws'"
                );
            }
            other => panic!("the draws ran out: the start fails, got {other:?}"),
        }
    }

    /// No report, and the port's holder is this VM's own forwarder — the
    /// pid the supervisor spawned: the publish landed and the report was
    /// late, so the VM is up, confirmed, whatever the origin or the tries.
    #[test]
    fn no_report_with_own_forwarder_holding_is_up() {
        let own = [4_242, 4_243];
        let holder = classify_no_report_holder(true, Some(4_243), &own);
        assert_eq!(holder, NoReportHolder::OwnForwarder);
        for drawn in [true, false] {
            for tries_used in 1..=PUBLISH_TRIES {
                assert_eq!(
                    decide_publish(
                        drawn,
                        tries_used,
                        GuestPublish::NoReport {
                            port: 19_913,
                            holder
                        }
                    ),
                    PublishDecision::Up,
                    "own forwarder holding is a late report (drawn={drawn}, try {tries_used})"
                );
            }
        }
    }

    /// No report, and another process holds the port: exactly the refused
    /// publish's story — a drawn port redraws within the tries and then
    /// fails with the draws' cause; a pin fails at once, the held port's.
    #[test]
    fn no_report_with_foreign_holder_redraws_drawn_and_fails_pinned() {
        let port = 19_914;
        let holder = classify_no_report_holder(true, Some(9_999), &[4_242]);
        assert_eq!(holder, NoReportHolder::Foreign);
        let outcome = GuestPublish::NoReport { port, holder };
        for tries_used in 1..PUBLISH_TRIES {
            assert_eq!(
                decide_publish(true, tries_used, outcome),
                PublishDecision::Redraw { port },
                "a drawn port held by another process redraws at try {tries_used}"
            );
        }
        assert_eq!(
            decide_publish(true, PUBLISH_TRIES, outcome),
            PublishDecision::FailStart {
                port,
                holder: HELD_BY_ANOTHER_PROCESS,
                cause: ProxyDownCause::RedrawsRanOut,
            },
            "the draws run out like a refused publish's"
        );
        for tries_used in 1..=PUBLISH_TRIES {
            assert_eq!(
                decide_publish(false, tries_used, outcome),
                PublishDecision::FailStart {
                    port,
                    holder: HELD_BY_ANOTHER_PROCESS,
                    cause: ProxyDownCause::PortHeld,
                },
                "a pin held by another process fails at once, at try {tries_used}"
            );
        }
    }

    /// No report and a holder the host would not name, or no listener at
    /// all: the VM is up, unconfirmed — ambiguity never redraws, never
    /// fails, and never claims serving.
    #[test]
    fn no_report_unknown_or_silent_is_up_unconfirmed() {
        let port = 19_915;
        assert_eq!(
            classify_no_report_holder(true, None, &[4_242]),
            NoReportHolder::Unknown
        );
        assert_eq!(
            classify_no_report_holder(false, Some(4_242), &[4_242]),
            NoReportHolder::NotAnswering,
            "a silent port is not attributed to anyone"
        );
        for holder in [NoReportHolder::Unknown, NoReportHolder::NotAnswering] {
            for drawn in [true, false] {
                for tries_used in 1..=PUBLISH_TRIES {
                    assert_eq!(
                        decide_publish(drawn, tries_used, GuestPublish::NoReport { port, holder }),
                        PublishDecision::UpUnconfirmed { port },
                        "{holder:?} is up, unconfirmed (drawn={drawn}, try {tries_used})"
                    );
                }
            }
        }
    }

    /// The unconfirmed state rides the status read until the guest's late
    /// report confirms the port, and a confirm never clears a terminal
    /// cause or another port's state.
    #[test]
    fn unconfirmed_publish_rides_the_read_until_confirmed() {
        let port = 19_916;
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _boxes, answerer, proxy_publish) =
            spawn_server(dir.path()).expect("server binds");
        answerer.set(ZoneAnswererStatus::Holder { port: 7_656 });
        proxy_publish.set_unconfirmed(port);
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::ProxyNotServing {
                port,
                cause: ProxyDownCause::PublishUnconfirmed,
            }),
            "an unconfirmed publish is what the read answers"
        );
        proxy_publish.confirm(port + 1);
        assert_eq!(
            proxy_publish.down(),
            Some(ZoneAnswererStatus::ProxyNotServing {
                port,
                cause: ProxyDownCause::PublishUnconfirmed,
            }),
            "another port's report confirms nothing"
        );
        proxy_publish.confirm(port);
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::Holder { port: 7_656 }),
            "the late report clears it; the answerer's state answers again"
        );
        proxy_publish.set_down(port, ProxyDownCause::PortHeld);
        proxy_publish.confirm(port);
        assert_eq!(
            proxy_publish.down(),
            Some(ZoneAnswererStatus::ProxyNotServing {
                port,
                cause: ProxyDownCause::PortHeld,
            }),
            "a confirm never clears a terminal cause"
        );
        // A late refusal after an unconfirmed start: the VM stays up, and the
        // read carries the holder over the wire so the CLI can name it.
        let late = ProxyDownCause::PortHeldAfterStart {
            holder: Some("pid 4242 (python3)".to_string()),
        };
        proxy_publish.set_unconfirmed(port);
        proxy_publish.set_down(port, late.clone());
        proxy_publish.confirm(port);
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::ProxyNotServing { port, cause: late }),
            "a late refusal rides the read with its holder, and a confirm never clears it"
        );
    }

    /// The operator's pin's story (T93): the first address-in-use publish
    /// fails the start — never a redraw, whatever the tries left — naming
    /// the port and the holder, and the cause the status read then serves
    /// over this socket is the held port's, so the CLI's surfaces name why
    /// the proxy is not serving instead of a bare "not serving".
    #[test]
    fn configured_proxy_port_in_use_fails_named_without_redraw() {
        let port = 19_912;
        let held = GuestPublish::PortHeld { port };

        // No try count changes the pin's story: every refusal is the
        // start's, from the first.
        for tries_used in 1..=PUBLISH_TRIES {
            match decide_publish(false, tries_used, held) {
                PublishDecision::FailStart {
                    port: named,
                    holder,
                    cause,
                } => {
                    assert_eq!(named, port, "the failure names the pinned port");
                    assert_eq!(
                        holder, HELD_BY_ANOTHER_PROCESS,
                        "the failure names the holder"
                    );
                    assert_eq!(cause, ProxyDownCause::PortHeld, "the cause is the holder's");
                }
                other => panic!("the pin never redraws at try {tries_used}, got {other:?}"),
            }
        }

        // And the failure's cause rides the read-only verb the CLI's
        // surfaces read: once the supervisor writes it, the status read
        // answers the port and the cause, not the answerer's state.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _boxes, answerer, proxy_publish) =
            spawn_server(dir.path()).expect("server binds");
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::Starting),
            "before any cause, the read answers the answerer's state as it always did"
        );
        proxy_publish.set_down(port, ProxyDownCause::PortHeld);
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::ProxyNotServing {
                port,
                cause: ProxyDownCause::PortHeld,
            }),
            "the read answers the cause the supervisor reached, naming the port"
        );
        answerer.set(ZoneAnswererStatus::Holder { port: 7_656 });
        assert_eq!(
            control(&sock_path, &BoxControlRequest::AnswererStatus).expect("the read is answered"),
            BoxControlReply::Status(ZoneAnswererStatus::ProxyNotServing {
                port,
                cause: ProxyDownCause::PortHeld,
            }),
            "the cause outranks the answerer's state while the supervisor holds it"
        );
    }

    /// A connection from the daemon's own uid passes the peer-credential
    /// check, read off a real socket (`SO_PEERCRED` / `getpeereid`).
    #[test]
    fn control_socket_admits_own_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        assert_eq!(peer_uid(&server).unwrap(), unsafe { libc::geteuid() });
        check_peer_credentials(&server).expect("own uid is admitted");
    }

    /// A peer uid other than the daemon's is refused. The decision is
    /// tested apart from the socket so it runs without root, which is the
    /// only way to connect under a second uid.
    #[test]
    fn control_socket_refuses_foreign_uid() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let foreign = unsafe { libc::geteuid() }.wrapping_add(1);
        let err = check_peer_uid(foreign).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        // A repeat refusal (logged at debug, not warn) still refuses.
        let err = check_peer_uid(foreign).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// Root is admitted for the answerer handover's two verbs and nothing
    /// else: the privileged step runs as root and asks a release, and no
    /// other verb is root's to ask of the operator's daemon.
    #[test]
    fn root_may_only_release_the_answerer() {
        assert!(root_may_ask(&BoxControlRequest::ReleaseAnswerer));
        assert!(root_may_ask(&BoxControlRequest::ReleaseAnswererCancel));
        assert!(!root_may_ask(&BoxControlRequest::AnswererStatus));
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        assert_eq!(is_root_peer(0), me != 0);
        assert!(!is_root_peer(me.wrapping_add(1).max(1)));
    }

    /// The bind tightens a provider dir the daemon owns but `StateDir::new`
    /// created under the umask (0755), rather than refusing every existing
    /// install, and then serves on it.
    #[test]
    fn bind_tightens_an_owned_provider_dir_to_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("local-minvmd0");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (sock_path, _handle, _boxes, _answerer, _proxy_publish) = spawn_server(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(TestStream::connect(&sock_path).is_ok());
    }

    /// A box registered with the grant — the allow stance and its range — and
    /// one admit report recorded through the guest door: the read-only row
    /// verb answers the row's switch address, its derived egress allow-list
    /// and its declared and runtime-admitted ports, the report answers one
    /// info line naming the box, the port, the source and the outcome, and
    /// the recorded admission's host-side copy lands in the daemon's own
    /// audit log (NET-138).
    #[test]
    fn read_row_reports_switch_address_allow_list_and_ports() {
        let capture = server_capture();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _registry, _answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");
        let guest_sock_path = sock_path.with_file_name(GUEST_CONTROL_SOCK_FILE);
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: vec![8080, 9090],
                    egress: Some(sessions::EgressPolicy {
                        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                        allow_dns_hosts: None,
                        deny_subnets: None,
                    }),
                    credentialed_upstream: None,
                    dynamic_ingress: Some(sessions::DynamicIngress::Allow),
                    dynamic_allowed_range: Some((3000, 3999)),
                },
            )
            .expect("the registration is answered"),
        );

        // The box's runtime publication, reported on the door the guest
        // owns, within the grant the registration carried.
        let recorded = control(
            &guest_sock_path,
            &BoxControlRequest::AdmitPort(AdmitPortRequest {
                switch_address: web.switch_address,
                port: 3000,
                proto: sessions::IpProto::Tcp,
                source: PortReportSource::Expose,
            }),
        )
        .expect("the report is answered");
        assert!(
            matches!(
                recorded,
                BoxControlReply::PortRecorded {
                    port: 3000,
                    proto: sessions::IpProto::Tcp
                }
            ),
            "a report within the grant is answered with the recorded port, got {recorded:?}"
        );

        // The read-only row verb: everything the host holds about the box.
        let read = control(
            &sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the read is answered");
        let BoxControlReply::Row(row) = read else {
            panic!("a live box's name answers its row, got {read:?}");
        };
        assert_eq!(row.name, "web");
        assert_eq!(
            row.switch_address, web.switch_address,
            "the row answers with the switch address the registration handed back"
        );
        assert_eq!(
            row.egress_allow_list,
            vec!["10.0.0.0/8".to_string()],
            "the allow-list is the declaration's own spelling: {row:?}"
        );
        assert_eq!(row.declared_ports, vec![8080, 9090]);
        assert_eq!(
            row.runtime_ports,
            vec![3000],
            "the recorded report is the row's one runtime port: {row:?}"
        );

        // One info line per recorded report: the box, the port, the
        // reporting source and the outcome.
        let log = capture.contents();
        assert!(
            log.contains("recorded the box's runtime-admitted port in the host-held grant"),
            "the recorded report's line names the outcome: {log}"
        );
        assert!(
            log.contains("box=web")
                && log.contains("port=3000")
                && log.contains("source=expose")
                && log.contains(&format!("switch_address={}", web.switch_address)),
            "the info line names the box, the port, the source and the row key: {log}"
        );

        // The host-side audit copy: one JSON line in the daemon's own audit
        // log, naming the box, the row key, the port, the protocol and the
        // source.
        let audit = std::fs::read_to_string(dir.path().join(AUDIT_LOG_RELATIVE_PATH))
            .expect("the audit copy exists beside the sockets");
        assert!(
            audit.contains(r#""box":"web""#)
                && audit.contains(r#""port":3000"#)
                && audit.contains(r#""proto":"tcp""#)
                && audit.contains(r#""source":"expose""#)
                && audit.contains(&format!(r#""switch_address":"{}""#, web.switch_address)),
            "the audit line names the box, the row key, the port, the protocol and the \
             source: {audit}"
        );
    }

    /// The host-side audit copy is created owner-only (0600): it names
    /// every box and port a guest admitted, so it carries the posture the
    /// sockets beside it do.
    #[test]
    fn audit_copy_created_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = audit_log_path(&dir.path().join(CONTROL_SOCK_FILE));
        let registry = BoxRegistry::new(SUBNET);
        let record = registry.register(crate::box_registry::BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
        ));
        append_audit_copy(
            &path,
            &record,
            &AdmitPortRequest {
                switch_address: record.switch_addr(),
                port: 3000,
                proto: sessions::IpProto::Tcp,
                source: PortReportSource::Expose,
            },
        );
        let mode = std::fs::metadata(&path)
            .expect("the audit copy was created")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the audit copy is owner-only, got {mode:o}");
    }

    /// The doors are the verb's access control (NET-138): the read-only row
    /// verb is refused on the in-VM daemon's channel and an admit report is
    /// refused on the host's socket — each refusal naming the door that
    /// serves the verb — and neither refusal leaves a fact behind: the row
    /// read over the host door carries no runtime port a refused report
    /// named.
    #[test]
    fn read_row_refused_on_guest_channel() {
        let capture = server_capture();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _registry, _answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");
        let guest_sock_path = sock_path.with_file_name(GUEST_CONTROL_SOCK_FILE);
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: Some(sessions::DynamicIngress::Allow),
                    dynamic_allowed_range: Some((3000, 3999)),
                },
            )
            .expect("the registration is answered"),
        );

        // The row read on the guest door: refused, naming the host's
        // control socket as the verb's own door.
        let refused = control(
            &guest_sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the wrong-door request is still answered");
        assert!(
            matches!(&refused, BoxControlReply::Error { error } if error.contains("the host's control socket")),
            "the guest channel refuses the row read naming the door that serves it, got {refused:?}"
        );

        // A port report on the host door: refused the same way, and the
        // port it named is not recorded.
        let refused = control(
            &sock_path,
            &BoxControlRequest::AdmitPort(AdmitPortRequest {
                switch_address: web.switch_address,
                port: 3000,
                proto: sessions::IpProto::Tcp,
                source: PortReportSource::Listen,
            }),
        )
        .expect("the wrong-door request is still answered");
        assert!(
            matches!(&refused, BoxControlReply::Error { error } if error.contains("the in-VM daemon's control channel")),
            "the host socket refuses the report naming the door that serves it, got {refused:?}"
        );
        assert!(
            !dir.path().join(AUDIT_LOG_RELATIVE_PATH).exists(),
            "a refused report writes no audit copy"
        );

        // The row read over its own door still answers, with no runtime
        // port the refused report named — the refusal recorded nothing.
        let read = control(
            &sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the read is answered");
        let BoxControlReply::Row(row) = read else {
            panic!("the row read still answers over its own door, got {read:?}");
        };
        assert!(
            row.runtime_ports.is_empty(),
            "a report the wrong door refused records nothing: {row:?}"
        );

        // Both wrong-door refusals are warn lines: a client speaking a verb
        // on the wrong socket is a posture mismatch to see, not a silent
        // drop.
        let log = capture.contents();
        assert!(
            log.matches("refused a box control verb on the door that does not serve it")
                .count()
                >= 2,
            "each wrong-door refusal is one warn line: {log}"
        );
    }

    /// Liveness is the table's own fact (NET-138): a live box's name answers
    /// its row, and once the session that registered it is destroyed — its
    /// client's withdrawal, the pair proof — the same read answers no row,
    /// never the destroyed box's last row. A name nothing ever held answers
    /// the same marker.
    #[test]
    fn read_row_absent_for_destroyed_name() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _registry, _answerer, _proxy_publish) =
            spawn_server(dir.path()).expect("server binds");
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: vec![8080],
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
            )
            .expect("the registration is answered"),
        );
        let read = control(
            &sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the read is answered");
        assert!(
            matches!(&read, BoxControlReply::Row(row) if row.name == "web"),
            "a live box's name answers its row, got {read:?}"
        );

        // The destroyed session's client withdrawal: the pair the
        // registration handed back.
        let withdrawn = control(
            &sock_path,
            &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                name: "web".to_string(),
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
        )
        .expect("the withdrawal is answered");
        assert!(
            matches!(withdrawn, BoxControlReply::Addresses(_)),
            "the pair proof withdraws the row it created, got {withdrawn:?}"
        );

        // The same read: no row — the row is gone, not archived.
        let read = control(
            &sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the read is answered");
        assert_eq!(
            read,
            BoxControlReply::NoRow {
                name: "web".to_string(),
                no_row: true
            },
            "a destroyed box's name answers the marker, never its last row"
        );

        // And a name nothing ever held answers the same marker.
        let never = control(
            &sock_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "ghost".to_string(),
            }),
        )
        .expect("the read is answered");
        assert_eq!(
            never,
            BoxControlReply::NoRow {
                name: "ghost".to_string(),
                no_row: true
            },
            "a name no live box holds answers no row"
        );
    }

    // ---------------------------------------------------------------------
    // Pending asks (NET-045)
    // ---------------------------------------------------------------------

    use minimald_rpc::{
        AdmitAskRequest, AskAdmitOutcome, AskAnswer, AskId, AskRefused, PendingAskOffer,
        RecordAskAnswerRequest, SubscribeAsksRequest,
    };

    /// How long a test waits for a reply it expects.
    const ASK_WAIT: Duration = Duration::from_secs(5);

    /// How long a test watches for a reply it expects never to come.
    const ASK_QUIET: Duration = Duration::from_millis(300);

    /// The first port of the ask boxes' allowed range.
    const ASK_PORT: u16 = 3000;

    /// A daemon, its two doors, and its registry, for the ask tests.
    struct AskHost {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        host: PathBuf,
        guest: PathBuf,
        boxes: BoxRegistry,
    }

    impl AskHost {
        fn start() -> Self {
            let dir = tempfile::TempDir::new().expect("temp dir");
            let (host, _server, boxes, _answerer, _proxy) =
                spawn_server(dir.path()).expect("server binds");
            Self {
                dir: dir.path().to_path_buf(),
                guest: host.with_file_name(GUEST_CONTROL_SOCK_FILE),
                host,
                boxes,
                _dir: dir,
            }
        }

        /// Register `name` with the ask stance over `[ASK_PORT, ASK_PORT + 999]`.
        fn register_ask_box(&self, name: &str) -> RegisteredBox {
            handed(
                register(
                    &self.host,
                    &RegisterBoxRequest {
                        name: name.to_string(),
                        ingress_ports: Vec::new(),
                        egress: None,
                        credentialed_upstream: None,
                        dynamic_ingress: Some(sessions::DynamicIngress::Ask),
                        dynamic_allowed_range: Some((ASK_PORT, ASK_PORT + 999)),
                    },
                )
                .expect("the registration is answered"),
            )
        }

        /// Record `answer` for `ask_id` on the host door.
        fn answer(&self, ask_id: AskId, answer: AskAnswer) -> BoxControlReply {
            control(
                &self.host,
                &BoxControlRequest::RecordAskAnswer(RecordAskAnswerRequest { ask_id, answer }),
            )
            .expect("the answer is answered")
        }

        /// The runtime ports the row named `name` holds.
        fn runtime_ports(&self, name: &str) -> Vec<u16> {
            match control(
                &self.host,
                &BoxControlRequest::ReadRow(ReadRowRequest {
                    name: name.to_string(),
                }),
            )
            .expect("the read is answered")
            {
                BoxControlReply::Row(row) => row.runtime_ports,
                other => panic!("the row read answers a row, got {other:?}"),
            }
        }

        fn audit(&self) -> String {
            std::fs::read_to_string(self.dir.join(AUDIT_LOG_RELATIVE_PATH)).unwrap_or_default()
        }
    }

    /// One held connection writing a request line and reading reply lines.
    struct Held {
        reader: BufReader<TestStream>,
    }

    impl Held {
        fn open(sock: &std::path::Path, request: &BoxControlRequest) -> Self {
            let mut stream = TestStream::connect(sock).expect("the door accepts");
            let mut line = serde_json_lenient::to_string(request).expect("serialize");
            line.push('\n');
            stream
                .write_all(line.as_bytes())
                .expect("the request is written");
            Self::from_stream(stream)
        }

        fn from_stream(stream: TestStream) -> Self {
            Self {
                reader: BufReader::new(stream),
            }
        }

        /// The next reply line, or `None` when none arrives inside `wait`.
        fn next_within(&mut self, wait: Duration) -> Option<BoxControlReply> {
            self.reader
                .get_ref()
                .set_read_timeout(Some(wait))
                .expect("the read bound is set");
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => None,
                Ok(_) => Some(serde_json_lenient::from_str(line.trim()).expect("reply parses")),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    None
                }
                Err(error) => panic!("the held connection failed: {error}"),
            }
        }

        fn next(&mut self) -> BoxControlReply {
            self.next_within(ASK_WAIT)
                .expect("a reply arrives on the held connection")
        }
    }

    /// An attached host client, subscribed to the row holding `box_id`.
    fn attach_client(host: &AskHost, web: &RegisteredBox) -> Held {
        let mut client = Held::open(
            &host.host,
            &BoxControlRequest::SubscribeAsks(SubscribeAsksRequest { box_id: web.box_id }),
        );
        match client.next() {
            BoxControlReply::AsksSubscribed { box_id, .. } => assert_eq!(box_id, web.box_id),
            other => panic!("the subscription is acknowledged, got {other:?}"),
        }
        client
    }

    /// The guest's ask for `port` on the row at `web`'s switch address.
    fn guest_ask(host: &AskHost, web: &RegisteredBox, port: u16) -> Held {
        Held::open(
            &host.guest,
            &BoxControlRequest::AdmitAsk(AdmitAskRequest {
                switch_address: web.switch_address,
                port,
                proto: sessions::IpProto::Tcp,
            }),
        )
    }

    fn expect_offer(client: &mut Held) -> PendingAskOffer {
        match client.next() {
            BoxControlReply::PendingAskOffer(offer) => offer,
            other => panic!("an attached client is offered the ask, got {other:?}"),
        }
    }

    fn expect_outcome(guest: &mut Held) -> AskAdmitOutcome {
        match guest.next() {
            BoxControlReply::AskAdmit(outcome) => outcome,
            other => panic!("the guest's ask is answered with its end, got {other:?}"),
        }
    }

    fn refused(outcome: AskAdmitOutcome) -> AskRefused {
        match outcome {
            AskAdmitOutcome::Refused { reason, .. } => reason,
            AskAdmitOutcome::Admitted { .. } => panic!("the ask was admitted, not refused"),
        }
    }

    /// A recorded yes admits exactly the ask it answers: the guest's held
    /// ask is answered admitted only after the attached client's yes, and
    /// the port joins the row's runtime set.
    #[test]
    fn ask_yes_recorded_by_client_admits() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut client);
        assert_eq!(offer.port, ASK_PORT);
        assert!(
            guest.next_within(ASK_QUIET).is_none(),
            "the guest waits for the human's answer"
        );
        assert!(host.runtime_ports("web").is_empty(), "nothing admitted yet");

        assert_eq!(
            host.answer(offer.ask_id, AskAnswer::Yes),
            BoxControlReply::AskAnswerRecorded {
                ask_id: offer.ask_id,
                recorded: true
            }
        );
        assert_eq!(
            expect_outcome(&mut guest),
            AskAdmitOutcome::Admitted {
                ask_id: offer.ask_id,
                port: ASK_PORT,
                proto: sessions::IpProto::Tcp
            }
        );
        assert_eq!(host.runtime_ports("web"), vec![ASK_PORT]);
    }

    /// Under ask, nothing the guest sends admits a port: its own admit
    /// report is refused, and its ask stays unadmitted until a client
    /// records an answer.
    #[test]
    fn ask_admit_without_client_record_refused() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let report = control(
            &host.guest,
            &BoxControlRequest::AdmitPort(AdmitPortRequest {
                switch_address: web.switch_address,
                port: ASK_PORT,
                proto: sessions::IpProto::Tcp,
                source: PortReportSource::Ask,
            }),
        )
        .expect("the report is answered");
        assert!(
            matches!(&report, BoxControlReply::Error { error } if error.contains("ask")),
            "a guest's admit report under ask is refused: {report:?}"
        );

        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        expect_offer(&mut client);
        assert!(guest.next_within(ASK_QUIET).is_none());
        assert!(
            host.runtime_ports("web").is_empty(),
            "an ask with no recorded answer admits nothing"
        );
    }

    /// The guest door refuses an answer: a guest can raise a question but
    /// never answer one, and the ask stays pending for the client.
    #[test]
    fn record_ask_answer_refused_on_guest_door() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut client);

        let forged = control(
            &host.guest,
            &BoxControlRequest::RecordAskAnswer(RecordAskAnswerRequest {
                ask_id: offer.ask_id,
                answer: AskAnswer::Yes,
            }),
        )
        .expect("the forged answer is answered");
        assert!(
            matches!(&forged, BoxControlReply::Error { error }
                if error.contains("host's control socket")),
            "the guest door refuses an answer: {forged:?}"
        );
        assert!(
            guest.next_within(ASK_QUIET).is_none(),
            "the ask is still pending"
        );
        assert!(host.runtime_ports("web").is_empty());

        // The guest door does not serve a subscription either.
        let subscribe = control(
            &host.guest,
            &BoxControlRequest::SubscribeAsks(SubscribeAsksRequest { box_id: web.box_id }),
        )
        .expect("the subscription is answered");
        assert!(matches!(subscribe, BoxControlReply::Error { .. }));

        host.answer(offer.ask_id, AskAnswer::No);
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::Denied);
    }

    /// An ask with no attached client is refused at once, and leaves
    /// nothing pending.
    #[test]
    fn pending_ask_without_attached_client_refused() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::NoClient);
        assert_eq!(host.boxes.pending_ask_count(), 0);
        assert!(host.runtime_ports("web").is_empty());
    }

    /// An answer for an id the host never minted, already answered, or
    /// cancelled is refused and admits nothing.
    #[test]
    fn record_for_unknown_or_consumed_ask_id_refused() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let unknown = host.answer(AskId::from_bytes([7; 16]), AskAnswer::Yes);
        assert!(
            matches!(unknown, BoxControlReply::Error { .. }),
            "{unknown:?}"
        );

        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut client);
        host.answer(offer.ask_id, AskAnswer::Yes);
        assert!(matches!(
            expect_outcome(&mut guest),
            AskAdmitOutcome::Admitted { .. }
        ));
        let replayed = host.answer(offer.ask_id, AskAnswer::Yes);
        assert!(
            matches!(replayed, BoxControlReply::Error { .. }),
            "a consumed id is refused: {replayed:?}"
        );

        // A cancelled id: the guest withdraws its ask, then a yes arrives.
        let guest = guest_ask(&host, &web, ASK_PORT + 1);
        let offer = loop {
            match client.next() {
                BoxControlReply::PendingAskOffer(offer) => break offer,
                BoxControlReply::PendingAskDismissed { .. } => {}
                other => panic!("unexpected push {other:?}"),
            }
        };
        drop(guest);
        assert!(matches!(
            client.next(),
            BoxControlReply::PendingAskDismissed { .. }
        ));
        let late = host.answer(offer.ask_id, AskAnswer::Yes);
        assert!(matches!(late, BoxControlReply::Error { .. }), "{late:?}");
        assert_eq!(host.runtime_ports("web"), vec![ASK_PORT]);
    }

    /// Every attached client is offered the ask; the first answer wins and
    /// the other dialogs are dismissed, their late answers refused.
    #[test]
    fn ask_offered_to_all_clients_first_answer_wins() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut first = attach_client(&host, &web);
        let mut second = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut first);
        assert_eq!(expect_offer(&mut second), offer);

        host.answer(offer.ask_id, AskAnswer::No);
        for client in [&mut first, &mut second] {
            assert_eq!(
                client.next(),
                BoxControlReply::PendingAskDismissed {
                    ask_id: offer.ask_id,
                    dismissed: true
                }
            );
        }
        let late = host.answer(offer.ask_id, AskAnswer::Yes);
        assert!(matches!(late, BoxControlReply::Error { .. }), "{late:?}");
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::Denied);
        assert!(host.runtime_ports("web").is_empty());
    }

    /// One ask per row is offered at a time behind a bounded queue; past
    /// the bound an ask is refused at once, and answering the front offers
    /// the next.
    #[test]
    fn pending_ask_queue_bound_refuses_past_it() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut client = attach_client(&host, &web);
        let ports: Vec<u16> = (0..PENDING_ASKS_PER_ROW)
            .map(|offset| ASK_PORT + u16::try_from(offset).expect("small"))
            .collect();
        let mut held: Vec<Held> = ports
            .iter()
            .map(|port| guest_ask(&host, &web, *port))
            .collect();
        // The asks race to the queue, so the front is whichever landed
        // first.
        let front = expect_offer(&mut client);
        assert!(ports.contains(&front.port));
        // Wait for every queued ask to land before asking past the bound.
        let until = std::time::Instant::now() + ASK_WAIT;
        while host.boxes.pending_ask_count() < PENDING_ASKS_PER_ROW {
            assert!(std::time::Instant::now() < until, "the asks never queued");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            client.next_within(ASK_QUIET).is_none(),
            "only the front ask is offered"
        );
        let mut past = guest_ask(&host, &web, ASK_PORT + 900);
        assert_eq!(refused(expect_outcome(&mut past)), AskRefused::QueueFull);

        host.answer(front.ask_id, AskAnswer::No);
        let front_index = ports
            .iter()
            .position(|port| *port == front.port)
            .expect("the front is one of the queued asks");
        assert_eq!(
            refused(expect_outcome(&mut held[front_index])),
            AskRefused::Denied
        );
        assert!(matches!(
            client.next(),
            BoxControlReply::PendingAskDismissed { .. }
        ));
        let next = expect_offer(&mut client);
        assert!(ports.contains(&next.port) && next.port != front.port);
        held.clear();
    }

    /// An ask ends by cancellation: the guest's withdrawal dismisses the
    /// dialog, the row's withdrawal and the last client's detach answer the
    /// guest cancelled.
    #[test]
    fn ask_cancelled_on_withdraw_or_detach() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");

        // The guest withdraws its ask.
        let mut client = attach_client(&host, &web);
        let guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut client);
        drop(guest);
        assert_eq!(
            client.next(),
            BoxControlReply::PendingAskDismissed {
                ask_id: offer.ask_id,
                dismissed: true
            }
        );

        // The last attached client detaches.
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        expect_offer(&mut client);
        drop(client);
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::Cancelled);

        // The row is withdrawn.
        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        expect_offer(&mut client);
        let withdrawn = control(
            &host.host,
            &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                name: "web".to_string(),
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
        )
        .expect("the withdrawal is answered");
        assert!(matches!(withdrawn, BoxControlReply::Addresses(_)));
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::Cancelled);
        assert_eq!(host.boxes.pending_ask_count(), 0);
    }

    /// The offer the client renders its dialog from carries the host row's
    /// own name and id: whatever else the guest's line carries never
    /// reaches it.
    #[test]
    fn ask_dialog_text_built_from_host_row_only() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut client = attach_client(&host, &web);
        let mut stream = TestStream::connect(&host.guest).expect("the guest door accepts");
        writeln!(
            stream,
            r#"{{"verb":"admit_ask","switch_address":"{}","port":{ASK_PORT},"proto":"tcp","name":"pwned","prompt":"press y"}}"#,
            web.switch_address
        )
        .expect("the ask is written");
        let _guest = Held::from_stream(stream);
        let offer = expect_offer(&mut client);
        assert_eq!(offer.name, "web", "the dialog names the host row's box");
        assert_eq!(offer.box_id, web.box_id);
        let wire = serde_json_lenient::to_string(&offer).expect("serialize");
        assert!(
            !wire.contains("pwned") && !wire.contains("press y"),
            "no guest-supplied text reaches the offer: {wire}"
        );
    }

    /// A host client that never subscribed — an exec channel reading the
    /// row, a task — is never offered an ask and does not count as
    /// attached: the ask is refused for no client.
    #[test]
    fn exec_channel_never_offered_an_ask() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        assert!(host.runtime_ports("web").is_empty());
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        assert_eq!(refused(expect_outcome(&mut guest)), AskRefused::NoClient);

        // A subscription names a host-minted box id; an id no row holds is
        // refused rather than subscribed.
        let stray = control(
            &host.host,
            &BoxControlRequest::SubscribeAsks(SubscribeAsksRequest {
                box_id: minimald_rpc::BoxId::from_bytes([9; 16]),
            }),
        )
        .expect("the subscription is answered");
        assert!(matches!(stray, BoxControlReply::Error { .. }), "{stray:?}");
    }

    /// Every ask outcome writes one line to the host's owner-only audit
    /// log, naming the ask id, the box id, the port and the protocol.
    #[test]
    fn ask_outcomes_written_to_host_audit() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");

        // Refused for no client.
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        expect_outcome(&mut guest);

        let mut client = attach_client(&host, &web);
        for answer in [AskAnswer::Yes, AskAnswer::No, AskAnswer::NoTty] {
            let mut guest = guest_ask(&host, &web, ASK_PORT + 10);
            let offer = expect_offer(&mut client);
            host.answer(offer.ask_id, answer);
            expect_outcome(&mut guest);
            assert!(matches!(
                client.next(),
                BoxControlReply::PendingAskDismissed { .. }
            ));
        }
        // Cancelled by the guest's withdrawal.
        let guest = guest_ask(&host, &web, ASK_PORT + 20);
        let cancelled = expect_offer(&mut client);
        drop(guest);
        client.next();
        // Refused for an unknown id.
        host.answer(AskId::from_bytes([3; 16]), AskAnswer::Yes);

        let until = std::time::Instant::now() + ASK_WAIT;
        let audit = loop {
            let audit = host.audit();
            if audit.contains(&format!(
                r#""outcome":"cancelled","ask_id":"{}""#,
                cancelled.ask_id
            )) {
                break audit;
            }
            assert!(
                std::time::Instant::now() < until,
                "audit incomplete: {audit}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        for outcome in [
            "refused_no_client",
            "offered",
            "yes",
            "no",
            "no_tty",
            "cancelled",
            "refused_unknown_id",
        ] {
            assert!(
                audit.contains(&format!(r#""event":"ask","outcome":"{outcome}""#)),
                "the audit records {outcome}: {audit}"
            );
        }
        let box_id = format!(r#""box_id":"{}""#, web.box_id);
        for line in audit
            .lines()
            .filter(|line| !line.contains("refused_unknown_id"))
        {
            assert!(
                line.contains(&box_id) && line.contains(r#""proto":"tcp""#),
                "each ask line names the box id and the protocol: {line}"
            );
        }
        let mode = std::fs::metadata(host.dir.join(AUDIT_LOG_RELATIVE_PATH))
            .expect("the audit log exists")
            .permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600
        );
    }

    /// No timer answers an ask: past the door's own drain bound it is
    /// still pending, and the human's answer still decides it.
    #[test]
    fn pending_ask_has_no_timeout() {
        let host = AskHost::start();
        let web = host.register_ask_box("web");
        let mut client = attach_client(&host, &web);
        let mut guest = guest_ask(&host, &web, ASK_PORT);
        let offer = expect_offer(&mut client);
        assert!(
            guest
                .next_within(GUEST_REPORT_DRAIN_TIMEOUT + Duration::from_secs(1))
                .is_none(),
            "nothing answers the ask while the human has not"
        );
        assert_eq!(host.boxes.pending_ask_count(), 1);
        host.answer(offer.ask_id, AskAnswer::Yes);
        assert!(matches!(
            expect_outcome(&mut guest),
            AskAdmitOutcome::Admitted { .. }
        ));
    }
}
