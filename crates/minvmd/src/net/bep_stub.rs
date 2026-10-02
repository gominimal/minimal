//! The stand-in for the Box Egress Proxy's own acceptor (NET-132, T69) —
//! test and e2e only, never a production surface.
//!
//! The pool in `switch::bep_host` delivers a box's connection by dialing
//! the proxy's unix socket and writing the per-boot token, then a fixed
//! header naming the box's own switch address. The proxy that owns that
//! socket is a later task; until it lands, something has to sit at the end
//! of the delivery so the e2e lane and the unit tests can read what the
//! pool actually presents. This module is that something: it binds the
//! proxy socket path the supervisor names, presents the same refusals the
//! proxy is promised to, and answers one line naming the source it saw —
//! the same line shape the switch crate's pool tests accept, so both sides
//! of the delivery speak one answer format.
//!
//! A stand-in must not be a hole. The socket gets the bridge-socket posture
//! ([`crate::sock`]): a 0700 parent dir and 0600 on the socket itself, so
//! only the same user can reach it at all. Every connection then proves,
//! in order, what the pool's delivery is supposed to carry: the peer's uid
//! against the daemon's own, then — where the kernel names the peer's
//! process, which Linux does — that pid against the host daemon's, then
//! the per-boot token, then the delivery header's version. Any mismatch is
//! refused and audited: the connection is closed without an answer, one
//! warn line records the reason, and the connection is never presented as
//! a box. A same-uid host process that finds the socket's path can know
//! neither the daemon's pid nor the token minted for this boot, so it can
//! reach the stand-in but never arrive through it.
//!
//! The supervisor ([`crate::cmd::run`]) starts the stand-in only when
//! `MINVMD_BEP_STUB` is set in its environment — the e2e lane sets it for
//! its daemon and nothing else does — and hands the same per-boot token it
//! wired into the peer over the start-up channel this module receives.
//! Nothing on a production boot ever listens at the proxy socket path: a
//! box's connection to the proxy's address is reset there, exactly as an
//! acceptor that is down is specified to answer (NET-132).

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;

use switch::bep_host::{DELIVERY_HEADER_LEN, DELIVERY_HEADER_VERSION, DeliveryHeader, TOKEN_LEN};

/// How long one connection may take to present its token and header. The
/// pool writes both in one go, so this bound only catches a connection that
/// is stalling; it must not let one hold the serving thread forever.
const PRESENT_TIMEOUT: Duration = Duration::from_secs(30);

/// The start-up facts the supervisor hands the stand-in over the channel it
/// receives at [`spawn`]: the per-boot token minted for this boot — the same
/// bytes wired into the peer — and the host daemon's pid, the process the
/// pool's deliveries are supposed to come from.
pub struct StubStart {
    /// The token every delivered connection presents first.
    pub token: [u8; TOKEN_LEN],
    /// The host daemon's pid; on Linux a connection from any other process
    /// is refused before it presents anything.
    pub daemon_pid: u32,
}

/// What the stand-in holds for its caller: the handle of the serving thread
/// — held for its lifetime, never joined; it ends with the process — and
/// the two records the tests read, shared with every connection it serves.
pub struct BepStub {
    /// The answer lines sent, one per accepted connection.
    presented: Arc<Mutex<Vec<String>>>,
    /// The refusal reasons audited, one per refused connection.
    refusals: Arc<Mutex<Vec<&'static str>>>,
    /// The serving thread; dropped without joining, so the thread runs
    /// until the process exits.
    _thread: JoinHandle<()>,
}

impl BepStub {
    /// The answer lines the stand-in sent, in the order it sent them.
    pub fn presented(&self) -> Vec<String> {
        self.presented
            .lock()
            .expect("the presented lock is never held across a panic, so it cannot be poisoned")
            .clone()
    }

    /// The reasons the stand-in refused connections for, in arrival order.
    pub fn refusals(&self) -> Vec<&'static str> {
        self.refusals
            .lock()
            .expect("the refusals lock is never held across a panic, so it cannot be poisoned")
            .clone()
    }
}

/// Bind the stand-in acceptor at `sock_path` — the proxy socket path the
/// supervisor names — and serve until the process exits, reading its
/// start-up facts (the token, the daemon's pid) from `start`.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; the accept loop moves to the
/// thread, in the shape of [`crate::control::spawn`]. The socket gets the
/// bridge-socket posture: path-length check, a 0700 parent dir, a stale
/// socket removed, and 0600 on the socket itself.
///
/// # Errors
///
/// Returns the I/O error if the socket path is too long, its parent dir
/// cannot be prepared, a stale file cannot be removed, the bind fails, or
/// the permissions cannot be enforced.
pub fn spawn(sock_path: PathBuf, start: Receiver<StubStart>) -> std::io::Result<BepStub> {
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    let presented: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let refusals: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let thread_presented = Arc::clone(&presented);
    let thread_refusals = Arc::clone(&refusals);
    let thread = std::thread::Builder::new()
        .name("minvmd-bep-stub".to_string())
        .spawn(move || {
            // The supervisor hands the start facts once it has minted the
            // token; a channel closed before then is a supervisor that went
            // away, and there is nothing left to serve.
            let Ok(start) = start.recv() else {
                return;
            };
            let shared = Arc::new(Shared {
                token: start.token,
                daemon_pid: start.daemon_pid,
                daemon_uid: daemon_uid(),
                presented: thread_presented,
                refusals: thread_refusals,
            });
            // One thread per connection: a presentation that stalls must
            // not hold up the next box's delivery behind it.
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let shared = Arc::clone(&shared);
                        let _conn = std::thread::Builder::new()
                            .name("minvmd-bep-stub-conn".to_string())
                            .spawn(move || serve_connection(stream, &shared));
                    }
                    Err(error) => {
                        tracing::debug!(error = %error, "box egress proxy stand-in accept failed")
                    }
                }
            }
        })?;
    Ok(BepStub {
        presented,
        refusals,
        _thread: thread,
    })
}

/// The facts every served connection is checked against, and the records
/// it is audited into.
struct Shared {
    /// The per-boot token a delivered connection must present first.
    token: [u8; TOKEN_LEN],
    /// The host daemon's pid: the only process the pool's deliveries come
    /// from, so on Linux any other pid is refused.
    daemon_pid: u32,
    /// The daemon's own uid: the peer's uid is checked against it before
    /// anything is read.
    daemon_uid: u32,
    /// The answer lines sent, one per accepted connection.
    presented: Arc<Mutex<Vec<String>>>,
    /// The refusal reasons audited, one per refused connection.
    refusals: Arc<Mutex<Vec<&'static str>>>,
}

/// Which credential proof a connection failed, or `None` when it passed:
/// the peer's uid first — only the same user may hold a connection to a
/// 0600 socket, so a mismatch names a socket that is not this daemon's —
/// then, where the kernel names the peer's process, that pid against the
/// host daemon's: a same-uid host process is refused before it presents a
/// byte, never on its bytes' merits.
fn credential_refusal(
    peer_uid: u32,
    peer_pid: Option<u32>,
    daemon_uid: u32,
    daemon_pid: u32,
) -> Option<&'static str> {
    if peer_uid != daemon_uid {
        return Some("uid");
    }
    if let Some(pid) = peer_pid
        && pid != daemon_pid
    {
        return Some("pid");
    }
    None
}

/// The daemon's own uid: the peer's uid is checked against it.
fn daemon_uid() -> u32 {
    // SAFETY: getuid() reads the calling user's real uid; it has no side
    // effects and cannot fail.
    unsafe { libc::getuid() }
}

/// The peer's credentials, the kernel's own answer for who holds the other
/// end of `stream`: its uid, and its pid where the platform names one —
/// Linux does. `SO_PEERCRED` is decided at connect time, so nothing the
/// peer writes can influence what this reads.
#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `size_of::<ucred>()` bytes into
    // `cred`, whose length is passed alongside it; the fd is the stream's
    // own and stays valid for the borrow's life.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The pid the kernel reports is the peer's process's; zero is only the
    // placeholder this read was seeded with, and no process holds it.
    Ok((
        cred.uid,
        (cred.pid > 0).then(|| u32::try_from(cred.pid).unwrap_or(0)),
    ))
}

/// Off Linux the kernel offers no stable way to read the peer's
/// credentials, so the stand-in has none to check: the 0600 socket already
/// bounds who may connect to the same user, and the per-boot token decides
/// what that user may present. The uid handed back is the daemon's own, so
/// the credential refusal is vacuous rather than a refusal of everything.
#[cfg(not(target_os = "linux"))]
fn peer_credentials(_stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    Ok((daemon_uid(), None))
}

/// Serve one presented connection: check the credentials, read the token,
/// then the header, and answer the one line naming the source — or refuse
/// and audit, closing the connection without an answer, so nothing refused
/// is ever presented as a box.
fn serve_connection(mut stream: UnixStream, shared: &Shared) {
    if let Err(error) = stream.set_read_timeout(Some(PRESENT_TIMEOUT)) {
        tracing::debug!(error = %error, "box egress proxy stand-in could not arm its read bound");
        return;
    }
    // The credentials are read at accept, before any byte of the
    // presentation: a foreign process is refused on what it is, not on what
    // it says.
    let (peer_uid, peer_pid) = match peer_credentials(&stream) {
        Ok(cred) => cred,
        Err(error) => {
            tracing::warn!(error = %error, "box egress proxy stand-in could not read peer credentials");
            audit(shared, "credentials");
            return;
        }
    };
    if let Some(reason) =
        credential_refusal(peer_uid, peer_pid, shared.daemon_uid, shared.daemon_pid)
    {
        audit(shared, reason);
        return;
    }
    // The token first: the proof the connection belongs to this boot.
    let mut token = [0u8; TOKEN_LEN];
    if stream.read_exact(&mut token).is_err() {
        audit(shared, "short");
        return;
    }
    if token != shared.token {
        audit(shared, "token");
        return;
    }
    // Then the fixed header, and its version first of all.
    let mut head = [0u8; DELIVERY_HEADER_LEN];
    if stream.read_exact(&mut head).is_err() {
        audit(shared, "short");
        return;
    }
    if head[0] != DELIVERY_HEADER_VERSION {
        audit(shared, "version");
        return;
    }
    let header = DeliveryHeader::parse(&head)
        .expect("the header slice is exactly DELIVERY_HEADER_LEN bytes long");
    let line = format!("source={} destination={}\n", header.source, header.destination);
    if stream.write_all(line.as_bytes()).is_err() {
        return;
    }
    tracing::debug!(
        source = %header.source,
        destination = %header.destination,
        "box egress proxy stand-in answered a delivered connection"
    );
    shared
        .presented
        .lock()
        .expect("the presented lock is never held across a panic, so it cannot be poisoned")
        .push(line);
}

/// Refuse one connection for `reason`: audit it and close it without an
/// answer, so the refusal carries no bytes a caller could mistake for a
/// box being presented.
fn audit(shared: &Shared, reason: &'static str) {
    tracing::warn!(
        reason,
        "box egress proxy stand-in refused a connection; nothing is presented from it"
    );
    shared
        .refusals
        .lock()
        .expect("the refusals lock is never held across a panic, so it cannot be poisoned")
        .push(reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::Path;

    use switch::bep_host::test_util::{FIRST_CLIENT_PORT, TestLane};
    use switch::bep_host::{BepWire, DEFAULT_PER_SOURCE_CAP, PROXY_PORT};
    use switch::SwitchSubnet;

    /// The source address a hand-made presentation claims: a box's address
    /// on the plan's lease run, the kind of address a host process would
    /// have to steal to be mistaken for a box.
    fn claimed_source() -> Ipv4Addr {
        Ipv4Addr::from(SwitchSubnet::default().first_ptask())
    }

    /// Present `token` and a header with `version` to the stand-in at `sock`
    /// the way the pool's delivery writes one — token first, then the fixed
    /// header — and return whatever it answered before closing. A close
    /// with no answer reads as empty however the kernel reports it: a
    /// refusal that stops reading mid-presentation closes on unread bytes,
    /// which the kernel reports to the peer as a reset, and the refusal's
    /// meaning — nothing was answered — is the same either way.
    fn present(sock: &Path, token: &[u8], version: u8) -> Vec<u8> {
        let mut stream = UnixStream::connect(sock).expect("the stand-in's socket accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a read timeout on the presentation");
        let mut head = vec![version];
        head.extend_from_slice(&[0u8; 16]); // the box id, zero until T44
        head.extend_from_slice(&claimed_source().octets());
        head.extend_from_slice(&40_000u16.to_be_bytes());
        head.extend_from_slice(&[100, 64, 255, 252]); // the proxy's address
        head.extend_from_slice(&PROXY_PORT.to_be_bytes());
        assert_eq!(head.len(), DELIVERY_HEADER_LEN);
        let mut bytes = token.to_vec();
        bytes.extend_from_slice(&head);
        stream.write_all(&bytes).expect("token then header");
        let mut answer = Vec::new();
        match stream.read_to_end(&mut answer) {
            Ok(_) => answer,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => answer,
            Err(error) => panic!("the stand-in closed its connection unexpectedly: {error}"),
        }
    }

    /// Poll `what` until it holds `reason`, or fail the test: the audit is
    /// written before the connection closes, so the poll needs only the
    /// serving thread's scheduling, not a window.
    fn await_refusal(stub: &BepStub, reason: &str) {
        for _ in 0..100 {
            if stub.refusals().contains(&reason) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("no connection was refused for {reason}: {:?}", stub.refusals());
    }

    /// NET-132/T69: a same-uid host process without this boot's token — or
    /// with the token but the wrong header version, or from a process that
    /// is not the host daemon — is refused and audited, and never arrives
    /// as a box: the stand-in presents nothing to any of them.
    #[test]
    fn host_process_never_arrives_from_a_box_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("bep-stub.sock");
        let token = [0xa7u8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
            })
            .expect("the supervisor hands the start facts over the channel");

        // The socket carries the bridge-socket posture: 0600, so only the
        // same user can reach it at all.
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&sock).expect("socket"));
        assert_eq!(mode & 0o777, 0o600, "the stand-in's socket is mode 0600");

        // A same-uid host process with the wrong token: the per-boot token
        // is the proof of belonging to this boot, and it does not hold it.
        let answer = present(&sock, &[0u8; TOKEN_LEN], DELIVERY_HEADER_VERSION);
        assert!(answer.is_empty(), "a wrong token is answered with nothing");
        await_refusal(&stub, "token");

        // The right token with the wrong header version: refused for the
        // version, never answered.
        let answer = present(&sock, &token, 0);
        assert!(answer.is_empty(), "a wrong version is answered with nothing");
        await_refusal(&stub, "version");

        // Nothing so far was presented as a box.
        assert!(
            stub.presented().is_empty(),
            "no refused connection was presented as a box"
        );

        // A same-uid host process that is not the host daemon: the pid
        // check refuses it before it presents anything, token or not. The
        // stand-in here claims a foreign daemon — init stands in for one —
        // so this test process is the foreign one.
        let foreign_sock = dir.path().join("bep-stub-foreign.sock");
        let (foreign_tx, foreign_rx) = std::sync::mpsc::channel();
        let foreign = spawn(foreign_sock.clone(), foreign_rx).expect("the stand-in binds its socket");
        foreign_tx
            .send(StubStart {
                token,
                daemon_pid: 1,
            })
            .expect("the supervisor hands the start facts over the channel");
        let answer = present(&foreign_sock, &token, DELIVERY_HEADER_VERSION);
        assert!(answer.is_empty(), "a foreign process is answered with nothing");
        await_refusal(&foreign, "pid");
        assert!(
            foreign.presented().is_empty(),
            "a foreign process was never presented as a box"
        );

        // The uid check decides before anything is read, so a foreign user
        // is refused on the credential alone — no socket on this host can
        // be held as that user to prove it end to end, and the decision is
        // the fact to pin.
        let uid = daemon_uid();
        assert_eq!(credential_refusal(uid, None, uid, std::process::id()), None);
        assert_eq!(
            credential_refusal(uid.wrapping_add(1), None, uid, std::process::id()),
            Some("uid")
        );
        assert_eq!(
            credential_refusal(uid, Some(2), uid, 3),
            Some("pid"),
            "a same-uid process that is not the daemon is refused for its pid"
        );
        assert_eq!(credential_refusal(uid, Some(3), uid, 3), None);
    }

    /// NET-132/T69: a delivered connection arrives at the proxy's unix
    /// socket from the box's own switch address — the delivery header's
    /// source — with this boot's token ahead of it, and the stand-in's
    /// answer names that source back to the box. Two boxes deliver at once
    /// and each is named by its own address, never each other's; the pool
    /// behind them is partitioned by the rows the registry holds, so each
    /// box's share is the per-source cap.
    #[tokio::test]
    async fn delivered_connection_arrives_from_the_boxs_switch_address() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let registry = crate::box_registry::BoxRegistry::new(subnet);

        // The supervisor wires the peer before any client box exists: the
        // node's own row is the one fact the host can name at boot.
        registry.register_node_namespace();
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_sock = dir.path().join("bep-stub.sock");
        let token = [0x5au8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(proxy_sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
            })
            .expect("the supervisor hands the start facts over the channel");

        let wire = BepWire::new(proxy_sock, token);
        assert_eq!(
            wire.per_source_cap(),
            DEFAULT_PER_SOURCE_CAP,
            "the supervisor names the default per-source cap"
        );
        let boxes = Arc::new(crate::cmd::run::RegisteredBoxes::new(registry.table()));
        let mut lane = TestLane::new(subnet, wire, boxes);
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            DEFAULT_PER_SOURCE_CAP,
            "the node's one row holds one share"
        );

        // The two client boxes register the way the activating client
        // registers them (T66): rows the host allocates, from the plan's
        // hand-out run, and the pool grows a share per row.
        let box_a = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-a".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
            })
            .expect("the plan has a switch address to hand out");
        let box_b = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-b".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
            })
            .expect("the plan has a second switch address to hand out");
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            3 * DEFAULT_PER_SOURCE_CAP,
            "every row the registry holds adds its share of the per-source cap"
        );

        // A box rides the lane at the address its row holds, the way a
        // guest attaches with the address it was handed.
        lane.add_box(box_a.switch_addr());
        lane.add_box(box_b.switch_addr());
        drive(&mut lane, 1).await;
        lane.boxes_mut()[0].arp_for(proxy_ip);
        lane.boxes_mut()[1].arp_for(proxy_ip);
        drive(&mut lane, 3).await;

        let flow_a = lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        let flow_b = lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut lane, 40).await;

        // Each box's answer names its own switch address as the source of
        // the connection that reached the acceptor — the identity the
        // delivery header carries, not the acceptor's guess.
        let answer_a = read_flow(&mut lane, 0, flow_a, 8).await;
        let answer_b = read_flow(&mut lane, 1, flow_b, 8).await;
        let expected_a = format!(
            "source={}:{} destination={}:{}\n",
            box_a.switch_addr(),
            FIRST_CLIENT_PORT,
            proxy_ip,
            PROXY_PORT
        );
        let expected_b = format!(
            "source={}:{} destination={}:{}\n",
            box_b.switch_addr(),
            FIRST_CLIENT_PORT,
            proxy_ip,
            PROXY_PORT
        );
        assert_eq!(
            String::from_utf8_lossy(&answer_a),
            expected_a,
            "box A's connection arrived from its own switch address"
        );
        assert_eq!(
            String::from_utf8_lossy(&answer_b),
            expected_b,
            "box B's connection arrived from its own switch address"
        );

        // The stand-in answered both — and audited nothing: no host process
        // reached the acceptor alongside the boxes' deliveries.
        assert!(stub.refusals().is_empty(), "no refusal was audited");
        let presented = stub.presented();
        assert_eq!(presented.len(), 2, "one answer per delivered connection");
        assert!(presented.contains(&expected_a), "box A was presented once");
        assert!(presented.contains(&expected_b), "box B was presented once");
    }

    /// Drive the lane for `rounds` turns, letting the delivery tasks run
    /// between them.
    async fn drive(lane: &mut TestLane, rounds: usize) {
        for _ in 0..rounds {
            lane.step().await;
        }
    }

    /// Read what a flow has received so far, driving the lane while it
    /// stays empty.
    async fn read_flow(lane: &mut TestLane, box_idx: usize, flow: usize, rounds: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..rounds {
            {
                let box_stack = &mut lane.boxes_mut()[box_idx];
                let mut buf = [0u8; 4096];
                loop {
                    let n = box_stack.recv(flow, &mut buf);
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
            lane.step().await;
        }
        out
    }
}
