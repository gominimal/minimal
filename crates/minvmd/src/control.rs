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
//! the registrations, their withdrawals, and both read-only verbs; beside
//! it the daemon binds a second socket — [`GUEST_CONTROL_SOCK_FILE`] — the
//! in-VM daemon's control channel, bridged to the guest over vsock at
//! [`minimald_rpc::VM_HOST_BOX_REPORT_PORT`], and it takes the port reports
//! alone: `admit_port`, the guest's report that one of its boxes published
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
    /// The in-VM daemon's control channel: the port reports alone.
    GuestReports,
}

/// How long the server waits for a registration's one request line before
/// dropping the connection. Generous against a slow starter; a hung client
/// must not pin the serving thread — connections are served one at a
/// time — forever.
const REGISTER_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
/// long as the daemon lives, and bind the in-VM daemon's report channel
/// beside it: a second socket in the same dir (see
/// [`GUEST_CONTROL_SOCK_FILE`]), served on its own thread, that carries
/// the port reports alone (NET-138).
///
/// Both binds happen on the calling thread so their failure surfaces to
/// the supervisor's own startup error handling; only the accept loops
/// move to their threads. Both sockets get the bridge socket's posture:
/// path-length check (libkrun aborts on over-long socket paths), a 0700
/// parent dir, a stale socket removed, and 0600 on the socket itself —
/// the guest door's peer is the same-uid bridge that connects it to the
/// vsock, so the uid check holds for it exactly as it does for the host's
/// own client. The report thread lives with the process like the
/// withdrawal drainer does; the handle this returns is the host door's.
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
    // The in-VM daemon's report channel: same dir, same posture, served on
    // its own thread so a report can never hold a registration's turn (and
    // the reverse — the serial doors never share a serving slot).
    let guest_sock_path = sock_path.with_file_name(GUEST_CONTROL_SOCK_FILE);
    crate::sock::check_uds_path_len(&guest_sock_path)?;
    crate::sock::remove_stale_socket(&guest_sock_path)?;
    let guest_listener = UnixListener::bind(&guest_sock_path)?;
    crate::sock::enforce_socket_permissions(&guest_sock_path)?;
    // The audit copy's path, kept under the state dir the sockets live in;
    // only the guest door appends to it, but both doors carry it so the
    // signature is one.
    let audit_path = audit_log_path(&sock_path);
    let guest_audit_path = audit_path.clone();
    let guest_boxes = boxes.clone();
    let guest_answerer = answerer.clone();
    let guest_publish = proxy_publish.clone();
    let guest_spawned = std::thread::Builder::new()
        .name("minvmd-guest-control".to_string())
        .spawn(move || {
            accept_loop(
                guest_listener,
                guest_boxes,
                guest_answerer,
                guest_publish,
                ControlDoor::GuestReports,
                &guest_audit_path,
            )
        });
    if let Err(error) = guest_spawned {
        // A daemon that cannot serve its guest channel is a daemon whose
        // boxes cannot publish a runtime port: the start says so rather
        // than coming up half-bridged.
        return Err(std::io::Error::other(format!(
            "could not spawn the in-VM daemon's control channel: {error}"
        )));
    }
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
    if let Err(error) = check_peer_credentials(&stream) {
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
    serve_request(
        &mut stream,
        boxes,
        answerer,
        proxy_publish,
        door,
        audit_path,
        request,
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
            register_and_reply(stream, boxes, request)
        }
        (BoxControlRequest::Withdraw(request), ControlDoor::Host) => {
            withdraw_and_reply(stream, boxes, request)
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
        (BoxControlRequest::AdmitPort(request), ControlDoor::GuestReports) => {
            admit_report_and_reply(stream, boxes, audit_path, request)
        }
        (BoxControlRequest::WithdrawPort(request), ControlDoor::GuestReports) => {
            withdraw_report_and_reply(stream, boxes, request)
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
fn check_peer_credentials(stream: &UnixStream) -> std::io::Result<()> {
    check_peer_uid(peer_uid(stream)?)
}

/// Admit `peer_uid` only when it is the daemon's own effective uid; the
/// decision half of [`check_peer_credentials`], apart from the socket.
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
fn register_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
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
    let reply = match boxes.register_client_box(spec) {
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
    request: WithdrawBoxRequest,
) -> std::io::Result<()> {
    let reply = match boxes.withdraw_client_box(
        &request.name,
        request.switch_address,
        request.loopback_address,
    ) {
        Ok(withdrawn) => {
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
/// reach.
fn append_audit_copy(
    path: &Path,
    record: &Arc<crate::box_registry::BoxRecord>,
    request: &AdmitPortRequest,
) {
    let line = AdmittedPortAudit {
        ts: unix_now_secs(),
        box_name: record.name().to_string(),
        switch_address: request.switch_address,
        port: request.port,
        proto: request.proto,
        source: request.source,
    };
    let Ok(json) = serde_json_lenient::to_string(&line) else {
        // A plain struct of primitives serializes; this arm is unreachable
        // in practice and costs nothing to keep honest.
        tracing::warn!("the recorded admission's audit copy did not serialize");
        return;
    };
    let written = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{json}")
    })();
    if let Err(error) = written {
        tracing::warn!(
            %error,
            path = %path.display(),
            "the recorded admission could not be copied to the host-side audit log"
        );
    }
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

    use crate::box_registry::AllocationError;
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
        let answerer = AnswererStatus::starting();
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
        Ok((sock_path, handle, boxes, answerer, proxy_publish))
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
            switch::AddressPlan::default()
                .loopback_slice_for_switch(SUBNET)
                .expect("the default subnet is planned")
                .first(),
            "the first box takes the first address of the slice the host switch publishes at"
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
            Ipv4Addr::from(
                u32::from(
                    switch::AddressPlan::default()
                        .loopback_slice_for_switch(SUBNET)
                        .expect("the default subnet is planned")
                        .first()
                ) + 1
            ),
            "the second box takes the next published loopback address"
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

    /// A box registered with the grant — the ask stance and its range — and
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
                    dynamic_ingress: Some(sessions::DynamicIngress::Ask),
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
                source: PortReportSource::Ask,
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
                && log.contains("source=ask")
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
                && audit.contains(r#""source":"ask""#)
                && audit.contains(&format!(r#""switch_address":"{}""#, web.switch_address)),
            "the audit line names the box, the row key, the port, the protocol and the \
             source: {audit}"
        );
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
}
