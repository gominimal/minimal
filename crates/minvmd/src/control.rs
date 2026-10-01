//! The VM host daemon's box-registration control socket (T66) — the one
//! host-side door a client has to the box table ([`crate::box_registry`],
//! NET-138).
//!
//! On a minvmd-backed host, `min session activate` registers every
//! own-address box here before it creates the session: it writes one
//! [`minimald_rpc::RegisterBoxRequest`] line, the daemon allocates the box's
//! switch and loopback addresses into the table — the row the host-side
//! egress gate decides every frame by — and answers with the
//! [`minimald_rpc::RegisterBoxAddresses`] the create request then carries,
//! so the in-VM daemon attaches with the handed address instead of drawing
//! its own. One connection, one request line in, one reply line out.
//!
//! The socket lives beside the daemon's ssh socket in the provider-instance
//! dir and is created with the same 0700-dir / 0600-socket posture the
//! bridge socket gets ([`crate::sock`]): only the same user may reach the
//! box table. The serving shape mirrors [`crate::net::HostGvproxy::spawn`]
//! — a dedicated OS thread off the supervisor's runtime — because both are
//! long-lived host services whose failures must not take the daemon down
//! with them: a failed registration answers the client with the reason and
//! keeps serving, and a client that never reaches the socket (a supervisor
//! predating this module) still activates, handed no addresses, under the
//! egress gate's announced interim.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use minimald_rpc::{RegisterBoxAddresses, RegisterBoxReply, RegisterBoxRequest};

use crate::box_registry::{BoxRegistry, ClientBoxSpec};

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

/// Bind the control socket at `sock_path` and serve box registrations
/// against `boxes` on a dedicated thread, whose handle the caller holds for
/// as long as the daemon lives.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; only the accept loop moves to
/// the thread. The socket gets the bridge socket's posture: path-length
/// check (libkrun aborts on over-long socket paths), a 0700 parent dir, a
/// stale socket removed, and 0600 on the socket itself.
pub fn spawn(sock_path: PathBuf, boxes: BoxRegistry) -> std::io::Result<JoinHandle<()>> {
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    std::thread::Builder::new()
        .name("minvmd-control".to_string())
        .spawn(move || accept_loop(listener, boxes))
}

/// Accept and serve registrations until the daemon exits. One connection at
/// a time: a registration is two map writes and one allocation, served
/// serially so the table sees its registrations in arrival order.
fn accept_loop(listener: UnixListener, boxes: BoxRegistry) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, &boxes) {
                    tracing::debug!(error = %error, "box registration connection failed");
                }
            }
            Err(error) => tracing::debug!(error = %error, "control socket accept failed"),
        }
    }
}

/// Serve one registration: read the request line, allocate, answer.
fn serve_connection(stream: UnixStream, boxes: &BoxRegistry) -> std::io::Result<()> {
    let mut stream = stream;
    stream.set_read_timeout(Some(REGISTER_READ_TIMEOUT))?;
    let Some(line) = read_request_line(&mut stream)? else {
        // EOF before any byte: a client that connected and left. Nothing to
        // answer, nothing to log past the connection level.
        return Ok(());
    };
    let request = match parse_request(&line) {
        Ok(request) => request,
        Err(error) => {
            let error = error.to_string();
            tracing::debug!(error = %error, "box registration request did not parse");
            return write_reply(&mut stream, &RegisterBoxReply::Error { error });
        }
    };
    register_and_reply(&mut stream, boxes, request)
}

/// Read one line (terminated by `\n`) of the registration request. A
/// connection that closes before sending a line reads as no request; a line
/// past [`MAX_REQUEST_LINE`] is refused.
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
                format!(
                    "box registration request exceeded {MAX_REQUEST_LINE} bytes without a newline"
                ),
            ));
        }
    }
}

fn parse_request(line: &str) -> Result<RegisterBoxRequest, serde_json_lenient::Error> {
    serde_json_lenient::from_str(line)
}

/// Allocate the box into the table and write the reply — the addresses on
/// success, the reason on a refusal. One info line per registration names
/// the box and both addresses: the diagnostic a bundle's VM host daemon log
/// is read for.
fn register_and_reply(
    stream: &mut UnixStream,
    boxes: &BoxRegistry,
    request: RegisterBoxRequest,
) -> std::io::Result<()> {
    let spec = ClientBoxSpec {
        name: request.name.clone(),
        ingress_ports: request.ingress_ports,
        egress: request.egress,
    };
    let reply = match boxes.register_client_box(spec) {
        Ok(record) => {
            tracing::info!(
                box = %record.name(),
                switch_address = %record.switch_addr(),
                loopback_address = %record.loopback_addr(),
                "registered box with the VM host daemon; addresses allocated"
            );
            RegisterBoxReply::Addresses(RegisterBoxAddresses {
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
            RegisterBoxReply::Error {
                error: error.to_string(),
            }
        }
    };
    write_reply(stream, &reply)
}

fn write_reply(stream: &mut UnixStream, reply: &RegisterBoxReply) -> std::io::Result<()> {
    let mut line = serde_json_lenient::to_string(reply).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("box registration reply did not serialize: {error}"),
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

    use minimald_rpc::RegisterBoxRequest;
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

    /// Spawns the control server on a temp path and returns (path, handle
    /// keeping the server thread identified). The thread outlives the test
    /// the way a daemon's does; the temp dir's drop after the test closes
    /// the test's view of the socket.
    fn spawn_server(dir: &std::path::Path) -> std::io::Result<(PathBuf, JoinHandle<()>)> {
        let sock_path = dir.join(CONTROL_SOCK_FILE);
        let handle = spawn(sock_path.clone(), BoxRegistry::new(SUBNET))?;
        // Wait until the socket accepts rather than racing the bind.
        for _ in 0..500 {
            if TestStream::connect(&sock_path).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok((sock_path, handle))
    }

    /// A client that writes the request and reads the reply line back,
    /// mirroring the CLI's registration helper.
    fn register(
        sock_path: &std::path::Path,
        request: &RegisterBoxRequest,
    ) -> std::io::Result<RegisterBoxReply> {
        let mut stream = TestStream::connect(sock_path)?;
        let mut line = serde_json_lenient::to_string(request).expect("request serializes");
        line.push('\n');
        stream.write_all(line.as_bytes())?;
        let mut reader = BufReader::new(stream);
        let mut reply = String::new();
        reader.read_line(&mut reply)?;
        serde_json_lenient::from_str(reply.trim())
            .map_err(|error| std::io::Error::other(format!("reply did not parse: {error}")))
    }

    /// The registered box's two addresses, asserted as the reply the daemon
    /// hands back.
    fn handed(reply: RegisterBoxReply) -> RegisterBoxAddresses {
        match reply {
            RegisterBoxReply::Addresses(addresses) => addresses,
            RegisterBoxReply::Error { error } => {
                panic!("a valid registration is answered with addresses, refused with {error}")
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
        let (sock_path, _server) = spawn_server(dir.path()).expect("server binds");

        // The first registration is handed the plan's first lease address
        // and the first published loopback address.
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
                },
            )
            .expect("first registration is answered"),
        );
        assert_eq!(
            web.switch_address,
            Ipv4Addr::from(SUBNET.first_ptask()),
            "the first box takes the plan's first lease address"
        );
        assert_eq!(
            web.loopback_address,
            switch::AddressPlan::default()
                .loopback_slice_for_switch(SUBNET)
                .expect("the default subnet is planned")
                .first(),
            "the first box takes the first address of the slice the host switch publishes at"
        );

        // The registration's one info line names the box and both addresses
        // it handed back.
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

        // The second registration takes the next address on both runs —
        // sequential allocation, no reuse.
        let db = handed(
            register(
                &sock_path,
                &RegisterBoxRequest {
                    name: "db".to_string(),
                    ingress_ports: vec![5432],
                    egress: None,
                },
            )
            .expect("second registration is answered"),
        );
        assert_eq!(
            db.switch_address,
            Ipv4Addr::from(SUBNET.first_ptask() + 1),
            "the second box takes the plan's next lease address, never the first again"
        );
        assert_eq!(
            db.loopback_address,
            Ipv4Addr::from(u32::from(
                switch::AddressPlan::default()
                    .loopback_slice_for_switch(SUBNET)
                    .expect("the default subnet is planned")
                    .first()
            ) + 1),
            "the second box takes the next published loopback address"
        );

        // A malformed request is answered with the reason, not a hang.
        let mut stream = TestStream::connect(&sock_path).expect("socket accepts");
        stream.write_all(b"this is not json\n").expect("write");
        let mut reader = BufReader::new(stream);
        let mut reply = String::new();
        reader.read_line(&mut reply).expect("reply read");
        let refused: RegisterBoxReply =
            serde_json_lenient::from_str(reply.trim()).expect("error reply parses");
        assert!(
            matches!(refused, RegisterBoxReply::Error { .. }),
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
}
