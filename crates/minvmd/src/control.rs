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
//! escape boundary. The read touches no row and mutates nothing.
//!
//! The second read the host socket serves is the row read
//! ([`minimald_rpc::ReadRowRequest`]): one box's row by its name, for
//! `minvmd status --row` — the switch address the registration handed back,
//! the derived egress allow-list, and the declared and runtime port sets. It
//! is read-only the same way the answerer status is: no row is touched, and
//! its only access control is the socket's own owner-only posture.
//!
//! A second socket sits beside this one — the in-VM daemon's channel
//! ([`minimald_rpc::GUEST_CONTROL_SOCK_FILE`], bridged over vsock by the VM
//! host on [`minimald_rpc::VSOCK_VM_HOST_CONTROL_PORT`]) — and it is the only
//! door the runtime report verbs are served on: the in-VM daemon's
//! `admit_port` and `withdraw_port` lines (NET-138's report half), each one
//! fixed, size-bounded report carrying the row key, the port, the protocol
//! and the reporting source. The host table decides them against the grant
//! the row holds from its registration — the stance and range the creating
//! client declared, never whatever the box now claims — and one info line
//! per recorded admission or withdrawal, one warn line per refused report,
//! says the decision, with the box, the port, the reporting source and the
//! outcome in it. Each recorded admission also lands in the daemon's own
//! audit log beside the socket, the host-side copy NET-138 asks for.
//! Splitting the two doors is the trust boundary: the registering client
//! writes rows, the in-VM daemon reports runtime publications, and neither
//! may speak through the other's door — a report arriving on the host
//! socket is refused, and so is a row read arriving on the guest channel.
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
use std::io::{BufRead as _, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use minimald_rpc::{
    AdmitPortRequest, BoxAddresses, BoxControlReply, BoxControlRequest, BoxPortReport, BoxRow,
    BoxRowReport, ReadRowRequest, RegisterBoxRequest, RegisteredBox, WithdrawBoxRequest,
    WithdrawPortRequest,
};

use crate::box_registry::{BoxRegistry, ClientBoxSpec};
use crate::net::answerer::AnswererStatus;

/// The control socket's file name inside the provider-instance dir, beside
/// `paths::SSH_SOCK_FILE`. Deliberately not in the `paths` crate: that crate
/// is shared with consumers that have no box table, and this name only
/// means something where `minvmd` supervises one.
pub const CONTROL_SOCK_FILE: &str = "control.sock";

/// The daemon's audit log for runtime admissions, beside the control
/// sockets in the provider dir: one JSON line per recorded admission, the
/// host-side copy NET-138 asks for — the same facts the one info line
/// carries, spelled the same way, at the host where the box's runtime
/// publications were recorded rather than only inside the VM that reported
/// them.
const ADMISSIONS_LOG_FILE: &str = "admissions.log";

/// How long the server waits for a registration's one request line before
/// dropping the connection. Generous against a slow starter; a hung client
/// must not pin the serving thread — connections are served one at a
/// time — forever.
const REGISTER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest request line the server will read. A registration carries a
/// name, a port list, and a policy; anything past this bound is not one.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// Resolve the control socket's path: `<provider dir>/control.sock`, the
/// dir the CLI resolves the ssh socket under, so the client finds both by
/// the same rule.
pub fn resolve_control_sock() -> std::io::Result<PathBuf> {
    Ok(crate::state::provider_dir().join(CONTROL_SOCK_FILE))
}

/// Resolve the in-VM daemon's channel beside a control socket
/// ([`GUEST_CONTROL_SOCK_FILE`]): the file this daemon binds beside its own
/// control socket, and the file an in-VM daemon — or a native seam that
/// stands for one — resolves beside the switch control socket it already
/// holds. `None` only for a path with no parent, which no socket the daemon
/// binds has.
pub fn guest_control_sock_beside(sock_path: &Path) -> Option<PathBuf> {
    sock_path
        .parent()
        .map(|dir| dir.join(minimald_rpc::GUEST_CONTROL_SOCK_FILE))
}

/// Read one box's row over the control socket (the client half of the
/// read-only row verb): one [`minimald_rpc::ReadRowRequest`] line in, one
/// [`BoxControlReply`] line out — the row the name resolves to, or no row
/// held. The client the status subcommand is, this stays synchronous and
/// bounded: one connect, one write, one read under the registration's own
/// read timeout, because a status read is a tail's question and must never
/// hang the tail on a daemon that never answers.
pub fn read_row(sock_path: &Path, name: &str) -> std::io::Result<BoxControlReply> {
    let request = BoxControlRequest::ReadRow(ReadRowRequest {
        name: name.to_string(),
    });
    let mut line = serde_json_lenient::to_string(&request).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the row read did not serialize: {error}"),
        )
    })?;
    line.push('\n');
    let mut stream = UnixStream::connect(sock_path)?;
    stream.set_read_timeout(Some(REGISTER_READ_TIMEOUT))?;
    stream.write_all(line.as_bytes())?;
    let mut reader = std::io::BufReader::new(stream);
    let mut reply = String::new();
    reader.read_line(&mut reply)?;
    if reply.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the VM host daemon closed the control socket without a reply",
        ));
    }
    serde_json_lenient::from_str(reply.trim()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the row read's reply did not parse: {error}"),
        )
    })
}

/// Bind the control socket at `sock_path` and serve box control requests
/// — registrations, their withdrawals, the answerer-status read, and the
/// read-only row read — against `boxes` on a dedicated thread, whose handle
/// the caller holds for as long as the daemon lives.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; only the accept loop moves to
/// the thread. The socket gets the bridge socket's posture: path-length
/// check (libkrun aborts on over-long socket paths), a 0700 parent dir, a
/// stale socket removed, and 0600 on the socket itself.
///
/// The in-VM daemon's channel is bound in the same call, beside the
/// control socket in the same dir and with the same posture, and serves
/// the runtime report verbs (NET-138) on its own dedicated thread — the
/// one door those verbs are served on. Best effort, deliberately: a host
/// whose guest channel cannot bind still serves its registering clients
/// and reads, said as one warn line, because the supervisor's host
/// service is not the thing a report channel's bind failure should take
/// down. Each recorded admission the channel serves is also appended to
/// the daemon's own audit log in the same dir
/// ([`ADMISSIONS_LOG_FILE`]).
pub fn spawn(
    sock_path: PathBuf,
    boxes: BoxRegistry,
    answerer: AnswererStatus,
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
    // The in-VM daemon's channel beside it: same dir, same posture, its
    // own serving thread, and its own audit log to append to. The clone
    // here is the registry's shared state — rows, cursors, channels — so
    // the report verbs decide against the same table the host socket
    // fills.
    if let Some(guest_path) = guest_control_sock_beside(&sock_path) {
        match bind_guest_channel(&guest_path) {
            Ok(listener) => {
                let boxes = boxes.clone();
                let answerer = answerer.clone();
                let audit_log = guest_path.parent().map(|dir| dir.join(ADMISSIONS_LOG_FILE));
                // Detached by design: the host handle the caller holds is
                // the service the daemon was asked for, and a report
                // channel that outlives the join the supervisor makes is
                // the process exiting.
                let _ = std::thread::Builder::new()
                    .name("minvmd-guest-control".to_string())
                    .spawn(move || {
                        accept_loop(listener, boxes, answerer, Channel::Guest, audit_log);
                    });
            }
            Err(error) => {
                tracing::warn!(
                    guest_control_sock = %guest_path.display(),
                    error = %error,
                    "the in-VM daemon's control channel did not bind; runtime port \
                     reports will not be served until the daemon restarts"
                );
            }
        }
    }
    std::thread::Builder::new()
        .name("minvmd-control".to_string())
        .spawn(move || accept_loop(listener, boxes, answerer, Channel::Host, None))
}

/// Bind the in-VM daemon's channel at `guest_path` with the control
/// socket's own posture.
fn bind_guest_channel(guest_path: &Path) -> std::io::Result<UnixListener> {
    crate::sock::remove_stale_socket(guest_path)?;
    let listener = UnixListener::bind(guest_path)?;
    crate::sock::enforce_socket_permissions(guest_path)?;
    Ok(listener)
}

/// Which of the daemon's two control sockets a request arrived on: the host
/// control socket the activating client reaches, or the in-VM daemon's
/// channel beside it. The verbs a channel serves are the channel's own —
/// the registering client's door serves rows and their reads, the
/// in-VM daemon's door serves the runtime reports — so a host client that
/// could write a row's runtime set through the host socket, or a box that
/// could read host rows through the guest channel, would each be a second
/// writer for a table that has one (NET-138's boundary is per door, not per
/// request).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Channel {
    /// The host control socket: the registering client's door.
    Host,
    /// The in-VM daemon's channel: the reporting door.
    Guest,
}

/// The refusal sentence for a request that arrived on the channel that
/// does not serve its verb, naming both.
fn refused_on_channel(channel: Channel, verb: &str) -> String {
    let arrived_on = match channel {
        Channel::Host => "the host control socket",
        Channel::Guest => "the in-VM daemon's channel",
    };
    format!("the VM host daemon serves the {verb} verb on its other socket, not on {arrived_on}")
}

/// Accept and serve box control requests until the daemon exits. One
/// connection at a time: a request is a row's map write or removal, served
/// serially so the table sees its requests in arrival order — and the
/// reads ride the same serial turn.
fn accept_loop(
    listener: UnixListener,
    boxes: BoxRegistry,
    answerer: AnswererStatus,
    channel: Channel,
    audit_log: Option<PathBuf>,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) =
                    serve_connection(stream, &boxes, &answerer, channel, audit_log.as_deref())
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
    channel: Channel,
    audit_log: Option<&Path>,
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
    serve_request(&mut stream, boxes, answerer, audit_log, request, channel)
}

/// Dispatch one parsed request to its verb and write its one reply line.
///
/// The verb dispatch is where the wire's parse refusal pays off: a line
/// that names no verb this build knows never reaches the table at all, so
/// a skewed client cannot make a withdraw look like a register (the
/// [`minimald_rpc::BoxControlRequest`] docs carry that corner). The
/// read-only verbs — the answerer's status, and the row read — touch no
/// row and mutate nothing: they answer what the table or the acquisition
/// loop last wrote, under the same socket posture every verb here is
/// served under (the v1 trust is the uid: the 0600 socket plus the
/// peer-credential check every connection passes before its line is
/// read). The runtime report verbs are the guest channel's alone, and the
/// row read is the host socket's alone, each refused on the other's door
/// ([`Channel`]).
fn serve_request(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    audit_log: Option<&Path>,
    request: BoxControlRequest,
    channel: Channel,
) -> std::io::Result<()> {
    match (channel, request) {
        (Channel::Host, BoxControlRequest::Register(request)) => {
            register_and_reply(stream, boxes, request)
        }
        (Channel::Host, BoxControlRequest::Withdraw(request)) => {
            withdraw_and_reply(stream, boxes, request)
        }
        (Channel::Host, BoxControlRequest::AnswererStatus) => {
            let reply = BoxControlReply::Status(answerer.get());
            write_reply(stream, &reply)
        }
        (Channel::Host, BoxControlRequest::ReadRow(request)) => {
            read_row_and_reply(stream, boxes, request)
        }
        // A report is the in-VM daemon's to send, never the host client's:
        // the host socket is the registering door, and a host client that
        // could write a row's runtime set through it would be a second
        // writer for the table's report half.
        (
            Channel::Host,
            request @ (BoxControlRequest::AdmitPort(_) | BoxControlRequest::WithdrawPort(_)),
        ) => {
            let reply = BoxControlReply::Error {
                error: refused_on_channel(channel, verb_name(&request)),
            };
            write_reply(stream, &reply)
        }
        (Channel::Guest, BoxControlRequest::AdmitPort(request)) => {
            admit_port_and_reply(stream, boxes, audit_log, request)
        }
        (Channel::Guest, BoxControlRequest::WithdrawPort(request)) => {
            withdraw_port_and_reply(stream, boxes, request)
        }
        // The guest channel serves the reports and nothing else: a row read
        // is a host fact, and one read through the guest's door would be
        // forgeable from inside the escape boundary — the same reason the
        // answerer status is read on the host socket alone.
        (
            Channel::Guest,
            request @ (BoxControlRequest::Register(_)
            | BoxControlRequest::Withdraw(_)
            | BoxControlRequest::AnswererStatus
            | BoxControlRequest::ReadRow(_)),
        ) => {
            let reply = BoxControlReply::Error {
                error: refused_on_channel(channel, verb_name(&request)),
            };
            write_reply(stream, &reply)
        }
    }
}

/// The name a request's verb carries, for the refusal sentence that names
/// the verb it will not serve on the channel it arrived on.
fn verb_name(request: &BoxControlRequest) -> &'static str {
    match request {
        BoxControlRequest::Register(_) => "register",
        BoxControlRequest::Withdraw(_) => "withdraw",
        BoxControlRequest::AnswererStatus => "answerer status",
        BoxControlRequest::AdmitPort(_) => "admit port",
        BoxControlRequest::WithdrawPort(_) => "withdraw port",
        BoxControlRequest::ReadRow(_) => "read row",
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
    //
    // The runtime grant crosses with the rest of the declaration (NET-138):
    // the stance and range the row holds, so every admit report the in-VM
    // daemon later sends is checked against the grant the creating client
    // declared here — never against whatever the box later claims.
    let spec = ClientBoxSpec {
        name: request.name.clone(),
        ingress_ports: request.ingress_ports,
        egress: request.egress,
        credentialed_upstream: request.credentialed_upstream,
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

/// Serve the in-VM daemon's admit report (NET-138): check it against the
/// grant the row holds from its registration and record it, or refuse with
/// the sentence that names why. One info line per recorded admission — the
/// box, the port, the reporting source, the outcome — one warn line per
/// refused report, and one audit line appended beside the socket for every
/// recorded admission: the host-side copy the requirement asks for, so the
/// host that recorded the admission holds the record of it too.
fn admit_port_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    audit_log: Option<&Path>,
    request: AdmitPortRequest,
) -> std::io::Result<()> {
    let reply = match boxes.admit_runtime_port(request.switch_address, request.port) {
        Ok(record) => {
            tracing::info!(
                box = %record.name(),
                switch_address = %request.switch_address,
                port = request.port,
                protocol = %request.protocol,
                source = %request.source,
                "recorded a runtime admission in the box's row"
            );
            if let Some(path) = audit_log {
                append_admission(path, &record, &request);
            }
            BoxControlReply::PortReport(BoxPortReport::Recorded { port: request.port })
        }
        Err(error) => {
            // The refusal names what the report arrived on, since a row that
            // is not held cannot name its own box back: the address the
            // report keyed is the one fact both halves of it share.
            tracing::warn!(
                switch_address = %request.switch_address,
                port = request.port,
                source = %request.source,
                error = %error,
                "refused a runtime admission report against the host-held grant"
            );
            BoxControlReply::Error {
                error: error.to_string(),
            }
        }
    };
    write_reply(stream, &reply)
}

/// Serve the in-VM daemon's withdraw report (NET-138): end the runtime
/// admission the row held, whatever the row's own bounds say about new
/// ones. One info line per withdrawal that removed a port, a debug line for
/// the idempotent repeat and the no-row case — both are the report's goal
/// state already holding — and `released` back either way: no withdrawal
/// report is ever refused by the cap or the rate.
fn withdraw_port_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: WithdrawPortRequest,
) -> std::io::Result<()> {
    let reply = match boxes.withdraw_runtime_port(request.switch_address, request.port) {
        Some((record, removed)) if removed => {
            tracing::info!(
                box = %record.name(),
                switch_address = %request.switch_address,
                port = request.port,
                source = %request.source,
                "ended a runtime admission in the box's row"
            );
            BoxControlReply::PortReport(BoxPortReport::Released { port: request.port })
        }
        Some((record, _)) => {
            tracing::debug!(
                box = %record.name(),
                switch_address = %request.switch_address,
                port = request.port,
                source = %request.source,
                "a runtime admission report ended a port the row did not hold; already released"
            );
            BoxControlReply::PortReport(BoxPortReport::Released { port: request.port })
        }
        None => {
            tracing::debug!(
                switch_address = %request.switch_address,
                port = request.port,
                source = %request.source,
                "a runtime admission report named no live row; its ports went with the row"
            );
            BoxControlReply::PortReport(BoxPortReport::Released { port: request.port })
        }
    };
    write_reply(stream, &reply)
}

/// Serve the read-only row read (NET-138): the live row the box's name
/// resolves to — the address the registration handed back, the derived
/// egress allow-list, and the declared and runtime port sets — or no row
/// held, never a destroyed box's last row. The verb changes no state; its
/// only access control is the host socket it is served on
/// ([`Channel`]).
fn read_row_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: ReadRowRequest,
) -> std::io::Result<()> {
    let reply = match boxes.row_by_name(&request.name) {
        Some(record) => {
            tracing::debug!(
                box = %record.name(),
                switch_address = %record.switch_addr(),
                "served the row read for a live box"
            );
            BoxControlReply::Row(BoxRowReport {
                row: Some(BoxRow {
                    switch_address: record.switch_addr(),
                    egress_allow_list: record.egress_allow_list().map(<[String]>::to_vec),
                    declared_ports: record.admitted_ports().to_vec(),
                    runtime_ports: record.runtime_ports(),
                }),
            })
        }
        None => {
            tracing::debug!(
                box = %request.name,
                "the row read named no live box; no row is held"
            );
            BoxControlReply::Row(BoxRowReport { row: None })
        }
    };
    write_reply(stream, &reply)
}

/// Append one recorded admission to the daemon's own audit log beside the
/// control socket: one JSON line carrying the same facts the info line
/// names — the box, its row key, the port, the protocol, the reporting
/// source, and the instant of the recording — with the host's millisecond
/// clock, because the line's reader is a tail, not a daemon. Best effort:
/// the admission is recorded in the row either way, and a log the daemon
/// cannot write is one warn line, never a failed report.
fn append_admission(
    path: &Path,
    record: &crate::box_registry::BoxRecord,
    request: &AdmitPortRequest,
) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis())
        .unwrap_or_default();
    let line = serde_json_lenient::json!({
        "ts": ts,
        "box": record.name(),
        "switch_address": request.switch_address.to_string(),
        "port": request.port,
        "protocol": request.protocol.to_string(),
        "source": request.source.to_string(),
        "outcome": "recorded",
    });
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        writeln!(file, "{line}")
    };
    if let Err(error) = write() {
        tracing::warn!(
            audit_log = %path.display(),
            error = %error,
            "the runtime admission could not be appended to the host-side audit log"
        );
    }
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

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixStream as TestStream;
    use std::sync::OnceLock;
    use std::time::Duration;

    use minimald_rpc::{
        BoxControlReply, BoxControlRequest, RegisterBoxRequest, ReportSource, WithdrawBoxRequest,
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
    /// from, the same cell the daemon's acquisition loop writes). The thread
    /// outlives the test the way a daemon's does; the temp dir's drop after
    /// the test closes the test's view of the socket.
    fn spawn_server(
        dir: &std::path::Path,
    ) -> std::io::Result<(PathBuf, JoinHandle<()>, BoxRegistry, AnswererStatus)> {
        let sock_path = dir.join(CONTROL_SOCK_FILE);
        let boxes = BoxRegistry::new(SUBNET);
        let answerer = AnswererStatus::starting();
        let handle = spawn(sock_path.clone(), boxes.clone(), answerer.clone())?;
        // Wait until the socket accepts rather than racing the bind.
        for _ in 0..500 {
            if TestStream::connect(&sock_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok((sock_path, handle, boxes, answerer))
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
            BoxControlReply::PortReport(report) => {
                panic!(
                    "a registration is answered with the registered box, got a port report {report:?}"
                )
            }
            BoxControlReply::Row(row) => {
                panic!("a registration is answered with the registered box, got a row read {row:?}")
            }
        }
    }

    /// Waits until the in-VM daemon's channel accepts beside the control
    /// socket, with the same bounded retry [`spawn_server`] makes for the
    /// host socket: the channel is bound in the same call, on its own
    /// thread, and a test must not race the bind.
    fn guest_channel(sock_path: &std::path::Path) -> PathBuf {
        let guest_path =
            guest_control_sock_beside(sock_path).expect("the control socket sits in a dir");
        for _ in 0..500 {
            if TestStream::connect(&guest_path).is_ok() {
                return guest_path;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!(
            "the in-VM daemon's channel never accepted at {}",
            guest_path.display()
        );
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
        let (sock_path, _server, registry, _answerer) =
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
        let (sock_path, _server, registry, _answerer) =
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
            BoxControlReply::PortReport(report) => {
                panic!("a withdrawal is answered with the pair, got a port report {report:?}")
            }
            BoxControlReply::Row(row) => {
                panic!("a withdrawal is answered with the pair, got a row read {row:?}")
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
                BoxControlReply::PortReport(report) => {
                    panic!("a withdrawal must be refused, got a port report {report:?}")
                }
                BoxControlReply::Row(row) => {
                    panic!("a withdrawal must be refused, got a row read {row:?}")
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
            BoxControlReply::PortReport(report) => {
                panic!("a repeat withdrawal echoes the pair, got a port report {report:?}")
            }
            BoxControlReply::Row(row) => {
                panic!("a repeat withdrawal echoes the pair, got a row read {row:?}")
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
        let (sock_path, _server, registry, answerer) =
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
            answerer.set(state);
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

    /// NET-138's report half over the real sockets: the in-VM daemon's
    /// channel answers an admit report with `recorded` when the row's
    /// registration holds the grant the report is inside — and one info
    /// line plus one audit line say the recording at the host, naming the
    /// box, the port, the reporting source and the outcome each — while
    /// the same report through the host socket is refused on the door it
    /// is not served on, and a withdraw report through the channel ends
    /// the admission the same way.
    #[test]
    fn admit_report_recorded_within_host_grant() {
        let capture = server_capture();
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, _answerer) =
            spawn_server(dir.path()).expect("server binds");
        let guest_path = guest_channel(&sock_path);

        // The row that holds the grant: the stance and range the
        // registration carried are what the report is checked against.
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
                    dynamic_ingress: Some(sessions::DynamicIngress::Allow),
                    dynamic_allowed_range: Some((9_000, 9_099)),
                },
            )
            .expect("the registration is answered"),
        );

        // The in-VM daemon's report of a runtime publication, spoken
        // through the channel that serves it: recorded, and the row holds
        // the port beside its declaration.
        let reply = control(
            &guest_path,
            &BoxControlRequest::AdmitPort(AdmitPortRequest {
                switch_address: web.switch_address,
                port: 9_000,
                protocol: sessions::IpProto::Tcp,
                source: ReportSource::Expose,
            }),
        )
        .expect("the report channel answers");
        assert_eq!(
            reply,
            BoxControlReply::PortReport(BoxPortReport::Recorded { port: 9_000 }),
            "a report inside the grant the row holds is recorded"
        );
        let row = registry
            .table()
            .by_source(web.switch_address.octets())
            .expect("the registration published the row");
        assert_eq!(
            row.runtime_ports(),
            [9_000],
            "the recorded report put the port in the row's runtime set"
        );

        // One info line for the recording, and one audit line beside the
        // socket: the same facts, spelled the same way, at the host.
        let log = capture.contents();
        assert!(
            log.contains("recorded a runtime admission in the box's row"),
            "one info line per recorded admission: {log}"
        );
        assert!(
            log.contains("box=web")
                && log.contains("port=9000")
                && log.contains("source=expose")
                && log.contains("protocol=tcp")
                && log.contains(&format!("switch_address={}", web.switch_address)),
            "the info line names the box, the port, the reporting source and \
             the outcome: {log}"
        );
        let audit = std::fs::read_to_string(dir.path().join(ADMISSIONS_LOG_FILE))
            .expect("each recorded admission is copied to the host-side audit log");
        assert!(
            audit.contains(r#""box":"web""#)
                && audit.contains(r#""port":9000"#)
                && audit.contains(r#""source":"expose""#)
                && audit.contains(r#""outcome":"recorded""#)
                && audit.contains(&format!(r#""switch_address":"{}""#, web.switch_address)),
            "the audit copy carries the same facts the info line does: {audit}"
        );
        assert!(
            !audit.contains(r#""outcome":"released""#),
            "only recorded admissions are copied — a withdraw report is not a \
             recording: {audit}"
        );

        // The same report through the host socket is refused on the door it
        // does not belong to, and records nothing.
        let reply = control(
            &sock_path,
            &BoxControlRequest::AdmitPort(AdmitPortRequest {
                switch_address: web.switch_address,
                port: 9_001,
                protocol: sessions::IpProto::Tcp,
                source: ReportSource::Listen,
            }),
        )
        .expect("the host socket answers the misdirected report");
        assert_eq!(
            reply,
            BoxControlReply::Error {
                error: "the VM host daemon serves the admit port verb on its other \
                        socket, not on the host control socket"
                    .to_string()
            },
            "a report through the registering client's door is refused"
        );
        assert_eq!(
            row.runtime_ports(),
            [9_000],
            "the refused report recorded nothing in the row"
        );

        // The withdrawal of the same admission, through the channel: ended,
        // the row's runtime set empty again.
        let reply = control(
            &guest_path,
            &BoxControlRequest::WithdrawPort(WithdrawPortRequest {
                switch_address: web.switch_address,
                port: 9_000,
                protocol: sessions::IpProto::Tcp,
                source: ReportSource::Expose,
            }),
        )
        .expect("the report channel answers the withdrawal");
        assert_eq!(
            reply,
            BoxControlReply::PortReport(BoxPortReport::Released { port: 9_000 }),
            "a withdraw report is never refused by the row's bounds"
        );
        assert!(
            row.runtime_ports().is_empty(),
            "the withdrawal emptied the row's runtime set"
        );
        let log = capture.contents();
        assert!(
            log.contains("ended a runtime admission in the box's row"),
            "one info line per withdrawal: {log}"
        );
    }

    /// The read-only row read over the host socket, end to end through the
    /// status client's own helper: the live row the box's name resolves to,
    /// carrying the switch address the registration handed back, the derived
    /// egress allow-list — the declaration's own strings, `null` for a box
    /// that declared no egress section, the allow-all default — and the
    /// declared and runtime port sets, the runtime one earned by the reports
    /// the channel recorded. A name no live box holds answers no row, and
    /// the read mutates nothing.
    #[test]
    fn read_row_reports_switch_address_allow_list_and_ports() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, _answerer) =
            spawn_server(dir.path()).expect("server binds");
        let guest_path = guest_channel(&sock_path);

        // Two rows: one with a declared egress list, declared ports and a
        // grant its reports earn inside; one with no egress section at all,
        // whose derived allow-list is the allow-all default.
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: vec![8080, 9090],
                    egress: Some(sessions::EgressPolicy {
                        allow_protocols: None,
                        allow_subnets: Some(vec![
                            "10.0.0.0/8".to_string(),
                            "172.16.0.0/12".to_string(),
                        ]),
                        allow_dns_hosts: None,
                        deny_subnets: None,
                    }),
                    credentialed_upstream: None,
                    dynamic_ingress: Some(sessions::DynamicIngress::Ask),
                    dynamic_allowed_range: Some((9_000, 9_099)),
                },
            )
            .expect("the registration is answered"),
        );
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
            .expect("the registration is answered"),
        );
        for port in [9_000u16, 9_005] {
            let reply = control(
                &guest_path,
                &BoxControlRequest::AdmitPort(AdmitPortRequest {
                    switch_address: web.switch_address,
                    port,
                    protocol: sessions::IpProto::Tcp,
                    source: ReportSource::Listen,
                }),
            )
            .expect("the report channel answers");
            assert_eq!(
                reply,
                BoxControlReply::PortReport(BoxPortReport::Recorded { port }),
                "the report is inside the grant the row holds"
            );
        }

        // The web row: every field the read serves, from the address the
        // registration handed back to the ports the reports earned.
        let web_row = match read_row(&sock_path, "web").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("a live box's name answers with its row, got {reply:?}"),
        };
        let row = web_row.row.expect("a live box's row is held");
        assert_eq!(row.switch_address, web.switch_address);
        assert_eq!(
            row.egress_allow_list,
            Some(vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]),
            "the derived allow-list is the declaration's own strings"
        );
        assert_eq!(row.declared_ports, [8080, 9090]);
        assert_eq!(row.runtime_ports, [9_000, 9_005]);

        // The db row: no egress section, no report — the allow-list is the
        // allow-all default's null, the runtime set empty.
        let db_row = match read_row(&sock_path, "db").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("a live box's name answers with its row, got {reply:?}"),
        };
        let row = db_row.row.expect("a live box's row is held");
        assert_eq!(row.switch_address, db.switch_address);
        assert_eq!(
            row.egress_allow_list, None,
            "a box with no egress section derives no allow-list"
        );
        assert_eq!(row.declared_ports, [5432]);
        assert!(
            row.runtime_ports.is_empty(),
            "a box that reported nothing admits only what its declaration named"
        );

        // A name no live box holds answers no row — never an error; the read
        // is served.
        let absent = match read_row(&sock_path, "ghost").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("an absent name answers with its row read, got {reply:?}"),
        };
        assert_eq!(absent.row, None, "no live box is held under the name");

        // The read mutates nothing: both rows still stand, and the runtime
        // set still holds what the reports earned.
        let row = registry
            .table()
            .by_source(web.switch_address.octets())
            .expect("the read left the row published");
        assert_eq!(row.runtime_ports(), [9_000, 9_005]);
        assert!(
            registry
                .table()
                .by_source(db.switch_address.octets())
                .is_some(),
            "the read left the other row published too"
        );
    }

    /// The read-only row read is the host socket's alone: the same line the
    /// status subcommand sends, arriving on the in-VM daemon's channel, is
    /// refused on the door it does not belong to — a host fact read through
    /// the guest's door would be forgeable from inside the escape boundary,
    /// the same reason the answerer status is — and the refusal answers
    /// with the box's row untouched.
    #[test]
    fn read_row_refused_on_guest_channel() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, registry, _answerer) =
            spawn_server(dir.path()).expect("server binds");
        let guest_path = guest_channel(&sock_path);
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

        let reply = control(
            &guest_path,
            &BoxControlRequest::ReadRow(ReadRowRequest {
                name: "web".to_string(),
            }),
        )
        .expect("the guest channel answers the misdirected read");
        assert_eq!(
            reply,
            BoxControlReply::Error {
                error: "the VM host daemon serves the read row verb on its other socket, \
                        not on the in-VM daemon's channel"
                    .to_string()
            },
            "the row read is refused on the reporting door"
        );
        assert!(
            registry
                .table()
                .by_source(web.switch_address.octets())
                .is_some(),
            "the refused read touched no row"
        );
    }

    /// A destroyed box's name answers no row (NET-138): the withdrawal
    /// removed the row, so the read reports the live table's truth and
    /// never a destroyed box's last row. The same name registered again
    /// resolves to the live registration's row.
    #[test]
    fn read_row_absent_for_destroyed_name() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let (sock_path, _server, _registry, _answerer) =
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

        // While the box lives, its name resolves to its row.
        let reply = match read_row(&sock_path, "web").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("a live box's name answers with its row, got {reply:?}"),
        };
        let row = reply.row.expect("the live box's row is held");
        assert_eq!(row.switch_address, web.switch_address);
        assert_eq!(row.declared_ports, [8080]);

        // The destroy's withdrawal, spoken as the activating client spells
        // it: the pair the registration handed back.
        let reply = control(
            &sock_path,
            &BoxControlRequest::Withdraw(WithdrawBoxRequest {
                name: "web".to_string(),
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
        )
        .expect("the withdrawal is answered");
        assert_eq!(
            reply,
            BoxControlReply::Addresses(BoxAddresses {
                switch_address: web.switch_address,
                loopback_address: web.loopback_address,
            }),
            "the withdrawal echoes the pair back"
        );

        // The destroyed box's name answers no row — the read is served, and
        // the answer is the table's truth.
        let reply = match read_row(&sock_path, "web").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("an absent name answers with its row read, got {reply:?}"),
        };
        assert_eq!(
            reply.row, None,
            "a destroyed box's name holds no row — the row went with the withdrawal"
        );

        // The name is free again: a box registered under it resolves to the
        // live registration's row, never the destroyed one's.
        let again = handed(
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
            .expect("the re-registration is answered"),
        );
        let reply = match read_row(&sock_path, "web").expect("the row read is answered") {
            BoxControlReply::Row(report) => report,
            reply => panic!("a live box's name answers with its row, got {reply:?}"),
        };
        let row = reply.row.expect("the re-registered box's row is held");
        assert_eq!(
            row.switch_address, again.switch_address,
            "the name resolves to the live registration's row"
        );
        assert_ne!(
            row.switch_address, web.switch_address,
            "the spent address is not handed out again"
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
        let (sock_path, _handle, _boxes, _answerer) = spawn_server(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(TestStream::connect(&sock_path).is_ok());
    }
}
