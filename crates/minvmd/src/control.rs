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
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use minimald_rpc::{
    BoxAddresses, BoxControlReply, BoxControlRequest, RegisterBoxRequest, WithdrawBoxRequest,
};

use crate::box_registry::{BoxRegistry, ClientBoxSpec};
use crate::net::answerer::AnswererStatus;

/// The control socket's file name inside the provider-instance dir, beside
/// `paths::SSH_SOCK_FILE`. Deliberately not in the `paths` crate: that crate
/// is shared with consumers that have no box table, and this name only
/// means something where `minvmd` supervises one.
pub const CONTROL_SOCK_FILE: &str = "control.sock";

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

/// Bind the control socket at `sock_path` and serve box control requests
/// — registrations, their withdrawals, and the answerer-status read —
/// against `boxes` on a dedicated thread, whose handle the caller holds for
/// as long as the daemon lives.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; only the accept loop moves to
/// the thread. The socket gets the bridge socket's posture: path-length
/// check (libkrun aborts on over-long socket paths), a 0700 parent dir, a
/// stale socket removed, and 0600 on the socket itself.
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
    std::thread::Builder::new()
        .name("minvmd-control".to_string())
        .spawn(move || accept_loop(listener, boxes, answerer))
}

/// Accept and serve box control requests until the daemon exits. One
/// connection at a time: a request is a row's map write or removal, served
/// serially so the table sees its requests in arrival order — and the
/// status read rides the same serial turn.
fn accept_loop(listener: UnixListener, boxes: BoxRegistry, answerer: AnswererStatus) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, &boxes, &answerer) {
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
    serve_request(&mut stream, boxes, answerer, request)
}

/// Dispatch one parsed request to its verb and write its one reply line.
///
/// The verb dispatch is where the wire's parse refusal pays off: a line
/// that names no verb this build knows never reaches the table at all, so
/// a skewed client cannot make a withdraw look like a register (the
/// [`minimald_rpc::BoxControlRequest`] docs carry that corner). The one
/// read-only verb — the answerer's status — touches no row and mutates
/// nothing: it answers the state the acquisition loop last wrote, under
/// the same socket posture every verb here is served under (the v1 trust
/// is the uid: the 0600 socket plus the peer-credential check every
/// connection passes before its line is read).
fn serve_request(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    answerer: &AnswererStatus,
    request: BoxControlRequest,
) -> std::io::Result<()> {
    match request {
        BoxControlRequest::Register(request) => register_and_reply(stream, boxes, request),
        BoxControlRequest::Withdraw(request) => withdraw_and_reply(stream, boxes, request),
        BoxControlRequest::AnswererStatus => {
            let reply = BoxControlReply::Status(answerer.get());
            write_reply(stream, &reply)
        }
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

/// Allocate the box into the table and write the reply — the addresses on
/// success, the reason on a refusal. One info line per registration names
/// the box, both addresses and the declared egress the row carries: the
/// diagnostic a bundle's VM host daemon log is read for.
fn register_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: RegisterBoxRequest,
) -> std::io::Result<()> {
    // The declaration as the row received it; `null` for a box with no
    // egress section. A plain struct of strings serialises infallibly.
    let declared_egress = serde_json_lenient::to_string(&request.egress).unwrap_or_default();
    let spec = ClientBoxSpec {
        name: request.name.clone(),
        ingress_ports: request.ingress_ports,
        egress: request.egress,
        credentialed_upstream: request.credentialed_upstream,
    };
    let reply = match boxes.register_client_box(spec) {
        Ok(record) => {
            tracing::info!(
                box = %record.name(),
                switch_address = %record.switch_addr(),
                loopback_address = %record.loopback_addr(),
                egress = %declared_egress,
                "registered box with the VM host daemon; addresses allocated"
            );
            BoxControlReply::Addresses(BoxAddresses {
                switch_address: record.switch_addr(),
                loopback_address: record.loopback_addr(),
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

    /// The registered box's two addresses, asserted as the reply the daemon
    /// hands back.
    fn handed(reply: BoxControlReply) -> BoxAddresses {
        match reply {
            BoxControlReply::Addresses(addresses) => addresses,
            BoxControlReply::Error { error } => {
                panic!("a valid request is answered with addresses, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!("a registration is answered with addresses, got the status {status:?}")
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
        let (sock_path, _server, _boxes, _answerer) =
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

        // The registration's one info line names the box, both addresses
        // it handed back, and the declared egress the row carries.
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
            log.contains(r#""allow_subnets":["10.0.0.0/8"]"#)
                && log.contains(r#""allow_protocols":["tcp"]"#),
            "the info line carries the declared egress allow-list: {log}"
        );

        // The second registration takes the next address on both runs —
        // sequential allocation, no reuse.
        let db = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "db".to_string(),
                    ingress_ports: vec![5432],
                    egress: None,
                    credentialed_upstream: None,
                },
            )
            .expect("second registration is answered"),
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
                assert_eq!(echoed, web, "the withdrawal echoes the pair it went by");
            }
            BoxControlReply::Error { error } => {
                panic!("the creator's withdrawal is answered with the pair, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!("a withdrawal is answered with the pair, got the status {status:?}")
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
                BoxControlReply::Status(status) => {
                    panic!("a withdrawal must be refused, got the status {status:?}")
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
                assert_eq!(echoed, web, "the repeat withdrawal echoes the pair too");
            }
            BoxControlReply::Error { error } => {
                panic!("no row at the address is success, refused with {error}")
            }
            BoxControlReply::Status(status) => {
                panic!("a repeat withdrawal echoes the pair, got the status {status:?}")
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
        // with addresses.
        let web = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "web".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
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
