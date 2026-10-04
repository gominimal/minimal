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
//! Beyond the credentials and the token, the stand-in is the proxy's
//! attribution rule too (NET-133): it holds the host's attachment table
//! ([`crate::bep_attach`]) and attributes a connection only to a live box
//! that table holds an attachment for — a header whose source address
//! resolves to nothing is refused, whatever else it says — and a box id the
//! header carries is cross-checked against the attachment the source
//! resolved to. One id names one box (BEP-070), and the mint cannot make
//! zero, so a zero id is a header that was never filled from its
//! attachment: it is refused and audited like a mismatch, exactly as the
//! pool writes it.
//!
//! The supervisor ([`crate::cmd::run`]) starts the stand-in only when
//! `MINVMD_BEP_STUB` is set in its environment — the e2e lane sets it for
//! its daemon and nothing else does — and hands the same per-boot token it
//! wired into the peer over the start-up channel this module receives.
//! Nothing on a production boot ever listens at the proxy socket path: a
//! box's connection to the proxy's address is reset there, exactly as an
//! acceptor that is down is specified to answer (NET-132).

use std::io::{Read, Write};
// Both peer-credential reads ask the kernel over the stream's own fd —
// `SO_PEERCRED` on Linux, `getpeereid` off it — so the import is ungated.
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;

use switch::bep_host::{DELIVERY_HEADER_LEN, DELIVERY_HEADER_VERSION, DeliveryHeader, TOKEN_LEN};

use crate::bep_attach::Attachments;

/// How long one connection may take to present its token and header. The
/// pool writes both in one go, so this bound only catches a connection that
/// is stalling; it must not let one hold the serving thread forever.
const PRESENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the delivery header names the source a flow is presented from:
/// bytes 17..21, the box's switch address, per the fixed layout
/// [`DeliveryHeader`] documents. Read straight off the wire bytes because
/// the type that owns the layout keeps its address as the switch crate's
/// private stack type, which this crate sees no value of.
const SOURCE_OCTETS_START: usize = 17;

/// The start-up facts the supervisor hands the stand-in over the channel it
/// receives at [`spawn`]: the per-boot token minted for this boot — the same
/// bytes wired into the peer — the host daemon's pid, the process the
/// pool's deliveries are supposed to come from, and the proxy's attachment
/// table, the stand-in's own facts about which boxes are attached
/// (NET-133).
pub struct StubStart {
    /// The token every delivered connection presents first.
    pub token: [u8; TOKEN_LEN],
    /// The host daemon's pid; on Linux a connection from any other process
    /// is refused before it presents anything.
    pub daemon_pid: u32,
    /// The host's attachment table, fed by the box registry: what the
    /// stand-in attributes a delivered connection by.
    pub attachments: Attachments,
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
                attachments: start.attachments,
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
    /// The host's attachment table: what a delivered connection is
    /// attributed by (NET-133), looked up through and never written.
    attachments: Attachments,
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

/// Whether `presented` is this boot's token, decided in time independent
/// of where the two first differ: the token is a shared secret, and a
/// byte-at-a-time comparison would leak how many leading bytes a guess
/// got right through the moment the refusal closes the connection — a
/// channel a same-uid host process could read across guesses. Both
/// arrays are the fixed [`TOKEN_LEN`], so the fold runs over every byte
/// every time and only the accumulation of their differences decides.
fn token_matches(presented: &[u8; TOKEN_LEN], expected: &[u8; TOKEN_LEN]) -> bool {
    let mut diff = 0u8;
    for byte in 0..TOKEN_LEN {
        diff |= presented[byte] ^ expected[byte];
    }
    diff == 0
}

/// The source address a delivered header names, as the octets the
/// attachment table is keyed by: the box's switch address, the source the
/// flow is presented from, at [`SOURCE_OCTETS_START`] in the fixed layout
/// [`DeliveryHeader`] documents.
fn source_octets(head: &[u8; DELIVERY_HEADER_LEN]) -> [u8; 4] {
    let mut octets = [0u8; 4];
    for (dst, src) in octets.iter_mut().zip(head.iter().skip(SOURCE_OCTETS_START)) {
        *dst = *src;
    }
    octets
}

/// The peer's credentials, the kernel's own answer for who holds the other
/// end of `stream`: its uid, and its pid where the platform names one —
/// Linux does. `SO_PEERCRED` is decided at connect time, so nothing the
/// peer writes can influence what this reads.
#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
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

/// Off Linux the kernel offers one credential fact for a connected unix
/// socket: the peer's uid, read with `getpeereid`. It comes with no pid,
/// so the pid check is vacuous there — naming the peer's process is
/// `SO_PEERCRED`'s, a Linux extra — but the uid check is real: a 0600
/// socket in a 0700 dir bounds who may *connect*, and this bounds what
/// the stand-in believes about the one who did, the same user this
/// process runs as and no other.
#[cfg(not(target_os = "linux"))]
fn peer_credentials(stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    let mut uid = libc::uid_t::default();
    let mut gid = libc::gid_t::default();
    // SAFETY: getpeereid writes the peer's uid and gid into the two
    // locals; the fd is the stream's own and stays valid for the
    // borrow's life.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((uid, None))
}

/// Serve one presented connection: check the credentials, read the token,
/// then the header, attribute the connection to the live box the
/// attachment table holds for the header's source — cross-checking the box
/// id the header carries against it — and answer the one line naming the
/// source; anything the presentation fails is refused and audited, closing
/// the connection without an answer, so nothing refused is ever presented
/// as a box.
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
    if !token_matches(&token, &shared.token) {
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
    // The proxy's attribution rule (NET-133): a delivered connection
    // belongs to a live box the attachment table holds one for, resolved
    // by the source the flow is presented from. A source that resolves to
    // nothing is not a box this proxy knows — refused, audited, never
    // presented, whatever else its header says.
    let Some(attachment) = shared.attachments.by_source(source_octets(&head)) else {
        audit(shared, "no_attachment");
        return;
    };
    // A box id the header carries is cross-checked against the attachment
    // the source resolved to: a mismatch names a header claiming another
    // box's identity, and nothing about it is presented. One id names one
    // box (BEP-070), and the mint cannot make zero, so a zero id is a
    // header that was never filled from its attachment — refused and
    // audited exactly like a mismatch, which is also how the pool writes it.
    if header.box_id != attachment.box_id() {
        audit(shared, "box_id");
        return;
    }
    let line = format!(
        "source={} destination={}\n",
        header.source, header.destination
    );
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

    use switch::SwitchSubnet;
    use switch::bep_host::test_util::{FIRST_CLIENT_PORT, State, TestLane};
    use switch::bep_host::{BepWire, DEFAULT_PER_SOURCE_CAP, PROXY_PORT};

    /// The source address a hand-made presentation claims: a box's address
    /// on the plan's lease run, the kind of address a host process would
    /// have to steal to be mistaken for a box.
    fn claimed_source() -> Ipv4Addr {
        Ipv4Addr::from(SwitchSubnet::default().first_ptask())
    }

    /// Present `token` and a header with `version`, `box_id` and `source` to
    /// the stand-in at `sock` the way the pool's delivery writes one — token
    /// first, then the fixed header — and return whatever it answered before
    /// closing. A close with no answer reads as empty however the kernel
    /// reports it: a refusal that stops reading mid-presentation closes on
    /// unread bytes, which the kernel reports to the peer as a reset, and
    /// the refusal's meaning — nothing was answered — is the same either
    /// way.
    fn present(
        sock: &Path,
        token: &[u8],
        version: u8,
        box_id: &[u8; 16],
        source: Ipv4Addr,
    ) -> Vec<u8> {
        let mut stream = UnixStream::connect(sock).expect("the stand-in's socket accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a read timeout on the presentation");
        let mut head = vec![version];
        head.extend_from_slice(box_id);
        head.extend_from_slice(&source.octets());
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
        panic!(
            "no connection was refused for {reason}: {:?}",
            stub.refusals()
        );
    }

    /// NET-132/T69: a same-uid host process without this boot's token — or
    /// with the token but the wrong header version, or (on Linux, where the
    /// kernel names the peer's process) from a process that is not the host
    /// daemon — is refused and audited, and never arrives as a box: the
    /// stand-in presents nothing to any of them.
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
                attachments: Attachments::new(),
            })
            .expect("the supervisor hands the start facts over the channel");

        // The socket carries the bridge-socket posture: 0600, so only the
        // same user can reach it at all.
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&sock).expect("socket"));
        assert_eq!(mode & 0o777, 0o600, "the stand-in's socket is mode 0600");

        // A same-uid host process with the wrong token: the per-boot token
        // is the proof of belonging to this boot, and it does not hold it.
        // Its header carries a minted id — the shape a box's header holds —
        // so nothing about the token refusal depends on what the id says.
        let answer = present(
            &sock,
            &[0u8; TOKEN_LEN],
            DELIVERY_HEADER_VERSION,
            &crate::bep_attach::mint_box_id(),
            claimed_source(),
        );
        assert!(answer.is_empty(), "a wrong token is answered with nothing");
        await_refusal(&stub, "token");

        // The right token with the wrong header version: refused for the
        // version, never answered.
        let answer = present(
            &sock,
            &token,
            0,
            &crate::bep_attach::mint_box_id(),
            claimed_source(),
        );
        assert!(
            answer.is_empty(),
            "a wrong version is answered with nothing"
        );
        await_refusal(&stub, "version");

        // Nothing so far was presented as a box.
        assert!(
            stub.presented().is_empty(),
            "no refused connection was presented as a box"
        );

        // A same-uid host process that is not the host daemon: the pid check
        // refuses it before it presents anything, token or not. Naming the
        // peer's process is `SO_PEERCRED`'s, a Linux socket option, so this
        // leg of the proof runs only there: off Linux the stand-in has no
        // pid to check (see `peer_credentials`) and the token is the whole
        // of what a same-uid process must hold. The stand-in here claims a
        // foreign daemon — init stands in for one — so this test process is
        // the foreign one.
        #[cfg(target_os = "linux")]
        {
            let foreign_sock = dir.path().join("bep-stub-foreign.sock");
            let (foreign_tx, foreign_rx) = std::sync::mpsc::channel();
            let foreign =
                spawn(foreign_sock.clone(), foreign_rx).expect("the stand-in binds its socket");
            foreign_tx
                .send(StubStart {
                    token,
                    daemon_pid: 1,
                    attachments: Attachments::new(),
                })
                .expect("the supervisor hands the start facts over the channel");
            let answer = present(
                &foreign_sock,
                &token,
                DELIVERY_HEADER_VERSION,
                &crate::bep_attach::mint_box_id(),
                claimed_source(),
            );
            assert!(
                answer.is_empty(),
                "a foreign process is answered with nothing"
            );
            await_refusal(&foreign, "pid");
            assert!(
                foreign.presented().is_empty(),
                "a foreign process was never presented as a box"
            );
        }

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

        // Off Linux the kernel still names the peer's uid — `getpeereid`
        // — and the stand-in reads it: this process's own uid, the fact
        // the uid check runs on there. No pid comes with it, so the pid
        // check is the Linux extra it has always been.
        #[cfg(not(target_os = "linux"))]
        {
            let stream = UnixStream::connect(&sock).expect("the stand-in's socket accepts");
            let (peer_uid, peer_pid) =
                peer_credentials(&stream).expect("the kernel names the peer's uid");
            assert_eq!(
                peer_uid,
                daemon_uid(),
                "getpeereid names this process's own uid"
            );
            assert_eq!(peer_pid, None, "no pid is named off Linux");
        }
    }

    /// NET-132/T69: a delivered connection arrives at the proxy's unix
    /// socket from the box's own switch address — the delivery header's
    /// source — with this boot's token ahead of it, and the stand-in's
    /// answer names that source back to the box. Two boxes deliver at
    /// once and each is named by its own address, never each other's; the
    /// pool behind them is partitioned by the box rows the registry
    /// holds, so each box's share is the per-source cap — and the node
    /// namespace's row, which is not a box, buys no share: the daemon
    /// address it holds is refused like any source no row speaks from.
    #[tokio::test]
    async fn delivered_connection_arrives_from_the_boxs_switch_address() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let attachments = Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());

        // The supervisor wires the peer before any client box exists: the
        // node's own row is the one fact the host can name at boot, holding
        // the default port pair it hands the guest when nothing overrides it
        // (cmd/run.rs resolves the same pair at VM boot). It is the guest's
        // own root netns, not a box, so it buys no share in the pool: the
        // partition the delivery runs under is by boxes alone.
        registry.register_node_namespace(7654);
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_sock = dir.path().join("bep-stub.sock");
        let token = [0x5au8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(proxy_sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
                attachments: attachments.clone(),
            })
            .expect("the supervisor hands the start facts over the channel");

        let wire = BepWire::new(proxy_sock, token);
        assert_eq!(
            wire.per_source_cap(),
            DEFAULT_PER_SOURCE_CAP,
            "the supervisor names the default per-source cap"
        );
        let boxes = Arc::new(crate::box_registry::RegisteredBoxes::new(
            registry.table(),
            attachments.clone(),
        ));
        let mut lane = TestLane::new(subnet, wire, boxes);
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            0,
            "the node namespace's row is not a box: it holds no share"
        );

        // The two client boxes register the way the activating client
        // registers them (T66): rows the host allocates, from the plan's
        // hand-out run, and the pool grows a share per box row.
        let box_a = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-a".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
            })
            .expect("the plan has a switch address to hand out");
        let box_b = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "box-b".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
            })
            .expect("the plan has a second switch address to hand out");
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            2 * DEFAULT_PER_SOURCE_CAP,
            "the two boxes' rows hold one share each; the node's adds none"
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

        // A connection from the daemon address — the address the node
        // namespace's row holds — is reset: the source holds no share, so
        // the pool's screen refuses it before any listener answers, and
        // the daemon's own tap can never arrive through the boxes'
        // delivery. Nothing about it was presented.
        let daemon_ip = subnet.daemon_ip();
        lane.add_box(daemon_ip);
        drive(&mut lane, 1).await;
        lane.boxes_mut()[2].arp_for(proxy_ip);
        drive(&mut lane, 3).await;
        let from_daemon = lane.boxes_mut()[2].connect(proxy_ip, PROXY_PORT);
        drive(&mut lane, 40).await;
        assert_eq!(
            lane.boxes()[2].flow_state(from_daemon),
            State::Closed,
            "a connection from the daemon address was reset"
        );
        let presented = stub.presented();
        assert_eq!(
            presented.len(),
            2,
            "nothing from the daemon address was presented as a box"
        );
        assert_eq!(
            lane.pool_len(),
            2 * DEFAULT_PER_SOURCE_CAP,
            "the refused connection took no share away from the boxes"
        );
    }

    /// NET-078/NET-133: a host-address box still delivers as the cohort. The
    /// host's own address outside the box host — the cohort address
    /// host-address boxes arrive from — is a row like a box's when the host
    /// published one there: its registration issues the cohort's attachment,
    /// the pool grows it a share like any box row's, and a delivered
    /// connection from it carries the cohort's own id, which is the shape
    /// the cross-check answers. The node namespace stays excluded beside it:
    /// no share, no attachment, and nothing delivered from it.
    #[tokio::test]
    async fn host_address_box_still_delivers_as_cohort() {
        use switch::bep_host::BepBoxSource;

        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let cohort_ip = subnet.host_alias();
        let attachments = Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());

        // The node's own row, as run.rs publishes it at boot: not a box, so
        // no share and no attachment — pinned by the pool's count below. The
        // host's row at the cohort address is published the way the host
        // publishes one: an explicit registration at its own address, a row
        // like a box's, outside the run boxes are handed from.
        registry.register_node_namespace(7654);
        let cohort = registry.register(crate::box_registry::BoxRegistration::new(
            "host",
            cohort_ip,
            Ipv4Addr::LOCALHOST,
        ));

        // The cohort's attachment: issued by its registration, naming the
        // cohort by the id its row holds — the id a delivery from the
        // cohort address arrives as — while the node namespace's row
        // bought none.
        let attachment = attachments
            .by_source(cohort_ip.octets())
            .expect("the cohort row issued the cohort's attachment");
        assert_eq!(
            attachment.box_id(),
            cohort.box_id(),
            "the cohort's attachment carries the id its row holds"
        );
        assert_ne!(
            attachment.box_id(),
            [0u8; 16],
            "the cohort's id is a minted UUIDv7, never the all-zero non-id"
        );
        assert!(
            attachments.by_source(subnet.daemon_ip().octets()).is_none(),
            "the node namespace is not a box and no cohort either: its row buys \
             no attachment"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_sock = dir.path().join("bep-stub.sock");
        let token = [0x5au8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(proxy_sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
                attachments: attachments.clone(),
            })
            .expect("the supervisor hands the start facts over the channel");

        let wire = BepWire::new(proxy_sock, token);
        let boxes = Arc::new(crate::box_registry::RegisteredBoxes::new(
            registry.table(),
            attachments.clone(),
        ));
        let mut lane = TestLane::new(subnet, wire, boxes.clone());
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            DEFAULT_PER_SOURCE_CAP,
            "the cohort row holds a share like a box's; the node's adds none"
        );
        assert_eq!(
            boxes.box_id_for_source(cohort_ip),
            Some(attachment.box_id()),
            "the pool's id lookup resolves the cohort address to the cohort's \
             attachment, never to a bare row"
        );
        assert_eq!(
            boxes.box_id_for_source(subnet.daemon_ip()),
            None,
            "the node namespace resolves to nothing: the one shape the pool's \
             no-attachment abort is for"
        );

        // A connection rides the lane from the cohort address, the way the
        // host's own traffic arrives — and it is delivered and answered,
        // attributed to the cohort's id by the cross-check.
        lane.add_box(cohort_ip);
        drive(&mut lane, 1).await;
        lane.boxes_mut()[0].arp_for(proxy_ip);
        drive(&mut lane, 3).await;
        let flow = lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut lane, 40).await;
        let answer = read_flow(&mut lane, 0, flow, 8).await;
        assert_eq!(
            String::from_utf8_lossy(&answer),
            format!(
                "source={}:{} destination={}:{}\n",
                cohort_ip, FIRST_CLIENT_PORT, proxy_ip, PROXY_PORT
            ),
            "the cohort's connection was delivered and answered, arriving as \
             the cohort from its own address"
        );
        assert!(
            stub.refusals().is_empty(),
            "the cohort's delivery was refused for nothing"
        );
        assert_eq!(
            stub.presented().len(),
            1,
            "one answer, attributed to the cohort's id"
        );

        // The node namespace stays excluded: its address holds no share, so
        // the pool's screen refuses its connection before any listener
        // answers — and nothing from it was presented as the cohort.
        lane.add_box(subnet.daemon_ip());
        drive(&mut lane, 1).await;
        lane.boxes_mut()[1].arp_for(proxy_ip);
        drive(&mut lane, 3).await;
        let from_daemon = lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut lane, 40).await;
        assert_eq!(
            lane.boxes()[1].flow_state(from_daemon),
            State::Closed,
            "a connection from the node namespace's address was reset"
        );
        assert_eq!(
            stub.presented().len(),
            1,
            "nothing from the node namespace was presented as the cohort"
        );
    }

    /// NET-133/T44: a box's attachment reaches the proxy before its first
    /// connection. The attachment is issued host-side, by the registration
    /// that publishes the box's row, and issued **ahead** of the row: the
    /// box-egress pool grows the box's share within a turn of the row, and a
    /// delivered connection can only exist through a share — so the
    /// attachment is ahead of everything that could carry the box's first
    /// connection. Pinned as the ordering itself: the attachment is held the
    /// moment the registration returns, while the pool still holds no
    /// socket for the box, and the first connection the box then makes is
    /// delivered and answered, attributed by the attachment that was there
    /// before it.
    #[tokio::test]
    async fn proxy_attachment_given_before_first_connection() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let attachments = Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());

        // The node's own row, as run.rs publishes it at boot: not a box, so
        // no share and no attachment — pinned by the pool's emptiness below.
        registry.register_node_namespace(7654);
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_sock = dir.path().join("bep-stub.sock");
        let token = [0x5au8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(proxy_sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
                attachments: attachments.clone(),
            })
            .expect("the supervisor hands the start facts over the channel");

        let wire = BepWire::new(proxy_sock, token);
        let boxes = Arc::new(crate::box_registry::RegisteredBoxes::new(
            registry.table(),
            attachments.clone(),
        ));
        let mut lane = TestLane::new(subnet, wire, boxes);
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            0,
            "the node namespace's row is not a box: it holds no share"
        );

        // The box is created: registered host-side, the way the activating
        // client's registration does (T66).
        let box_row = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
            })
            .expect("the plan has a switch address to hand out");

        // The attachment is in the proxy's table with the registration —
        // ahead of the pool's own turn for the box, so ahead of any socket
        // the box's first connection could ride.
        let attachment = attachments
            .by_source(box_row.switch_addr().octets())
            .expect("the registration issued the box's attachment");
        assert_eq!(attachment.switch_addr(), box_row.switch_addr());
        assert_eq!(attachment.loopback_addr(), box_row.loopback_addr());
        assert_eq!(
            attachment.box_id(),
            box_row.box_id(),
            "the attachment carries the box's own id, the one its row holds"
        );
        assert_ne!(
            attachment.box_id(),
            [0u8; 16],
            "the attachment names the box, never the all-zero non-id"
        );
        assert_eq!(
            lane.pool_len(),
            0,
            "the pool holds no socket for the box yet: the attachment is \
             ahead of the box's first connection"
        );

        // The share arrives only after, by the row the attachment led.
        drive(&mut lane, 2).await;
        assert_eq!(
            lane.pool_len(),
            DEFAULT_PER_SOURCE_CAP,
            "the box's share arrives after its attachment, by its row"
        );

        // And the first connection is delivered and answered.
        lane.add_box(box_row.switch_addr());
        drive(&mut lane, 1).await;
        lane.boxes_mut()[0].arp_for(proxy_ip);
        drive(&mut lane, 3).await;
        let flow = lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut lane, 40).await;
        let answer = read_flow(&mut lane, 0, flow, 8).await;
        assert_eq!(
            String::from_utf8_lossy(&answer),
            format!(
                "source={}:{} destination={}:{}\n",
                box_row.switch_addr(),
                FIRST_CLIENT_PORT,
                proxy_ip,
                PROXY_PORT
            ),
            "the box's first connection was delivered and answered"
        );
        assert!(
            stub.refusals().is_empty(),
            "the box's first connection was refused for nothing"
        );
    }

    /// NET-133/T44: a delivered header's box id is cross-checked against the
    /// acceptor's own facts, and a mismatch is refused and audited — never
    /// presented as a box. The facts are the host's attachment table: the
    /// attachment the header's source resolved to, issued by the box's
    /// registration, and an id naming another box is refused whatever the
    /// header's credentials were. One id names one box (BEP-070) and the
    /// mint cannot make zero, so an all-zero id is not a claim an acceptor
    /// answers: it is a header that was never filled from its attachment,
    /// refused and audited exactly like a mismatch. And a source the table
    /// holds no attachment for is not a box at all: the node namespace's row
    /// is not one, and an ended box's attachment is gone with its row, so
    /// its values are refused from the moment the host observed the end,
    /// even though the box's revocation was never recorded.
    #[test]
    fn mismatched_box_id_in_delivery_header_is_refused() {
        let subnet = SwitchSubnet::default();
        let attachments = Attachments::new();
        let registry = crate::box_registry::BoxRegistry::new(subnet)
            .feeding_proxy_attachments(attachments.clone());

        // The guest node's row — the namespace the host publishes at boot —
        // and one client box, registered the way the activating client
        // registers one (T66).
        registry.register_node_namespace(7654);
        let box_row = registry
            .register_client_box(crate::box_registry::ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
            })
            .expect("the plan has a switch address to hand out");

        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("bep-stub.sock");
        let token = [0x5au8; TOKEN_LEN];
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(sock.clone(), start_rx).expect("the stand-in binds its socket");
        start_tx
            .send(StubStart {
                token,
                daemon_pid: std::process::id(),
                attachments: attachments.clone(),
            })
            .expect("the supervisor hands the start facts over the channel");

        // The acceptor's own fact: the attachment the box's registration
        // issued, keyed by the address the box's connections arrive from,
        // naming the box by the id its row holds.
        let attachment = attachments
            .by_source(box_row.switch_addr().octets())
            .expect("the box's registration issued its attachment");
        assert_eq!(
            attachment.box_id(),
            box_row.box_id(),
            "the attachment carries the box's own id, the one its row holds"
        );
        assert_ne!(
            attachment.box_id(),
            [0u8; 16],
            "the attachment names the box, never the all-zero non-id"
        );
        assert!(
            attachments.by_source(subnet.daemon_ip().octets()).is_none(),
            "the node namespace is not a box: its row buys no attachment"
        );

        // The box's own id is answered: the cross-check passes, and the
        // answer names the box's address as the connection's source.
        let answer = present(
            &sock,
            &token,
            DELIVERY_HEADER_VERSION,
            &attachment.box_id(),
            box_row.switch_addr(),
        );
        assert!(
            String::from_utf8_lossy(&answer)
                .starts_with(&format!("source={}", box_row.switch_addr())),
            "the box's own id is answered, naming the box's address"
        );
        assert_eq!(stub.presented().len(), 1, "one answer so far");

        // Another box's id is a mismatch: refused, audited, never presented.
        let mut other = attachment.box_id();
        other[0] ^= 0xff;
        let answer = present(
            &sock,
            &token,
            DELIVERY_HEADER_VERSION,
            &other,
            box_row.switch_addr(),
        );
        assert!(
            answer.is_empty(),
            "a mismatched box id is answered with nothing"
        );
        await_refusal(&stub, "box_id");
        assert_eq!(
            stub.presented().len(),
            1,
            "the mismatched header presented no box"
        );

        // An all-zero id is refused and audited exactly like a mismatch
        // (BEP-070): one id names one box, the mint cannot make zero, and a
        // zero id is a header that was never filled from its attachment —
        // the pool writes that shape only when no attachment named the box,
        // and nothing about it is presented.
        let answer = present(
            &sock,
            &token,
            DELIVERY_HEADER_VERSION,
            &[0u8; 16],
            box_row.switch_addr(),
        );
        assert!(
            answer.is_empty(),
            "an all-zero box id is answered with nothing"
        );
        assert!(
            stub.refusals()
                .iter()
                .filter(|reason| **reason == "box_id")
                .count()
                >= 2,
            "the all-zero id was audited for the box_id reason, like the mismatch: {:?}",
            stub.refusals()
        );
        assert_eq!(
            stub.presented().len(),
            1,
            "the all-zero id presented no box"
        );

        // A source no attachment holds is not a box: the node namespace's
        // address — a row the host publishes, but not a box — is refused
        // outright, id or not.
        let answer = present(
            &sock,
            &token,
            DELIVERY_HEADER_VERSION,
            &attachment.box_id(),
            subnet.daemon_ip(),
        );
        assert!(
            answer.is_empty(),
            "a source with no attachment is answered with nothing"
        );
        await_refusal(&stub, "no_attachment");
        assert_eq!(
            stub.presented().len(),
            1,
            "nothing unattached was presented as a box"
        );

        // The box ends — its creator withdraws it, the way a destroy does —
        // and its attachment goes with its row: the same presentation, the
        // box's own id from its own address, is refused now.
        assert!(
            registry
                .withdraw_client_box("web", box_row.switch_addr(), box_row.loopback_addr())
                .expect("the withdrawing client is the row's creator")
                .is_some(),
            "the row was published"
        );
        assert!(
            attachments
                .by_source(box_row.switch_addr().octets())
                .is_none(),
            "the box's end retired its attachment with its row"
        );
        let answer = present(
            &sock,
            &token,
            DELIVERY_HEADER_VERSION,
            &attachment.box_id(),
            box_row.switch_addr(),
        );
        assert!(
            answer.is_empty(),
            "an ended box's values are answered with nothing, revocation \
             recorded or not"
        );
        await_refusal(&stub, "no_attachment");
        assert_eq!(
            stub.presented().len(),
            1,
            "the ended box presented nothing more"
        );
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
