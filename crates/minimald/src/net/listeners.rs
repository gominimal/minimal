//! Listen-published ingress (NET-016, NET-017): the ports a box publishes
//! because its processes listen on them.
//!
//! A declaration's forwards are static — bound at publish, held until the
//! box stops (NET-121) — but a port a permit range names has no forward to
//! hold: it exists to the processes inside the box alone, so the story's
//! shape is the kernel's socket table's. This module reads the box's
//! listening sockets through its leader's `/proc` entry — one table per
//! network namespace, so it names every listening socket in the box,
//! whichever of its processes holds it — polls and diffs them, and:
//!
//! * **publishes** each new listening port the shared verdict permits
//!   ([`SessionGate::listen_verdict`], the pure decision in
//!   `sessions::core::egress` the Kani harness exhausts): a forward bound at
//!   the box's own address, at the port the process listens on — no
//!   translation, the same number on both sides, exactly as a declaration's
//!   mapping publishes its external port (NET-010) — and the port admitted
//!   at the box's ingress gate for as long as the listener holds it;
//! * **leaves unpublished** every listening port the rules do not permit,
//!   so a connection to it is refused at the box's address (NET-014) and
//!   never forwarded by a listener nobody declared;
//! * **withdraws** each published port whose listener closed: the gate
//!   refuses it first — terminating the connections the publication held at
//!   both ends, the same end a revoked declared forwarder's connections come
//!   to — and the forward comes down after (NET-017).
//!
//! The watcher owns only the runtime-published set. A declared port is
//! never its to publish — its forward was bound before the box's name was
//! even registered — and never its to withdraw: a withdrawal applies only to
//! the runtime-published set (NET-081's sub-requirement), which is why the
//! two halves are tracked apart all the way down to the gate.
//!
//! Polling, not a socket-diagnostic netlink socket or an inotify watch, is
//! the honest read here: `/proc/<pid>/net/tcp` emits no change notification
//! there is to subscribe to, and a process inside the box can bind without
//! the daemon ever being told — the table *is* the notification, and reading
//! it on an interval is the only way the daemon has of learning a listener
//! exists. The interval ([`LISTEN_POLL_INTERVAL`]) is a person-facing
//! number: a server a developer starts is published inside the second they
//! finish typing its port.
//!
//! One info line per publication and per withdrawal — each naming the port,
//! the box, and whether the rules permitted it — so the diagnostics
//! bundle's daemon log tail reads the whole surface (the observability
//! contract of the story this module implements).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use sessions::SessionId;
use sessions::core::egress::ListenVerdict;

use super::policy::{ControlChannel, ExposedMapping, expose_mapping, unexpose_mapping};
use super::switch::SessionGate;

/// How often the watcher reads the box's socket table: often enough that a
/// listener a person starts is published before they look for it, rare
/// enough that one box's watcher is not a load on the daemon — one small
/// `/proc` read per box per quarter second.
const LISTEN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Everything a box's listener watcher needs, gathered by the launch that
/// attached the box: its name (each publication's line names the box), its
/// switch lease (the address a publication's forward delivers to), the
/// published address the forward binds — the box's own address (NET-010),
/// wherever it was granted, read back the same way the attach path reads
/// it — the gvproxy control channel the forwarder verbs ride, and the box's
/// session gate, which holds the shared permit decision
/// ([`SessionGate::listen_verdict`]) and the admission a published port is
/// given through.
pub struct ListenPlan {
    /// The box's name, as the daemon's own session lines name it.
    box_name: String,
    /// The box's address on the switch — where a publication's forward
    /// delivers.
    lease: Ipv4Addr,
    /// The box's published address (NET-010) — where a publication binds.
    published: Ipv4Addr,
    /// The gvproxy control channel: `expose` to publish, `unexpose` to
    /// withdraw.
    control: ControlChannel,
    /// The box's session gate: the permit decision and the admission.
    gate: Arc<SessionGate>,
}

impl ListenPlan {
    /// Assembles the plan from the facts its launch holds. The gate must be
    /// the one the box's relay registered — the gate the connections a
    /// publication forwards are admitted by on their way through the
    /// relay.
    #[must_use]
    pub fn new(
        box_name: String,
        lease: Ipv4Addr,
        published: Ipv4Addr,
        control: ControlChannel,
        gate: Arc<SessionGate>,
    ) -> Self {
        Self {
            box_name,
            lease,
            published,
            control,
            gate,
        }
    }
}

/// The plans launches have built and hosts have not taken: the handoff from
/// a session's launcher (which holds the lease, the switch and the gate the
/// attach registered) to the host about to run the box, keyed by the
/// session id both hold. A launch stages its plan as its last act, the host
/// takes it as its first — [`Host::build`](crate::session_host::Host::build)
/// — so the plan never rides a struct every launcher would have to name,
/// and a mock launch that stages nothing starts no watcher at all.
///
/// The take is destructive on purpose: a plan belongs to the one host that
/// runs its box, and a reattach's launch stages a fresh one. A build that
/// never takes its plan — a cancelled launch — leaves one entry behind,
/// replaced the next time the same session launches, and holding no
/// descriptor; the table is bounded by the sessions that exist.
static STAGED_PLANS: LazyLock<Mutex<HashMap<SessionId, ListenPlan>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Leaves the plan a launch built for the host about to run its box,
/// replacing any a cancelled build left behind.
pub(crate) fn stage_listen_plan(session_id: SessionId, plan: ListenPlan) {
    STAGED_PLANS
        .lock()
        .expect("staged listen-plan lock poisoned")
        .insert(session_id, plan);
}

/// Takes the plan staged for `session_id` — once, so the host that runs the
/// box owns its box's publications and a second host cannot stop its
/// watcher.
pub(crate) fn take_listen_plan(session_id: SessionId) -> Option<ListenPlan> {
    STAGED_PLANS
        .lock()
        .expect("staged listen-plan lock poisoned")
        .remove(&session_id)
}

/// The running watcher: what a host holds for its box's lifetime, stopped by
/// [`Self::stop`] at session end. Stopping is the one other thing the
/// watcher does — its loop polls, and everything it published comes down
/// before `stop` returns, so no runtime-published forward outlives its box.
pub struct ListenWatcher {
    /// Signals the loop out of its poll cycle. The withdrawal that follows
    /// is the stop's own work, and the loop's last.
    stop: watch::Sender<bool>,
    /// The loop task: it ends after withdrawing everything, so awaiting it
    /// *is* awaiting the withdrawal.
    task: tokio::task::JoinHandle<()>,
}

impl ListenWatcher {
    /// Starts the box's watcher: a loop that reads the listening sockets of
    /// the process tree `leader` leads — the box's leader, whose `/proc`
    /// entry names the whole box's network namespace — and keeps the
    /// box's publications in step with them. The first poll happens at
    /// once, so a listener that outlived a previous host is published
    /// before a person can look for it.
    #[must_use]
    pub fn start(plan: ListenPlan, leader: u32) -> Self {
        let (stop, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut state = WatchState::new(plan);
            loop {
                state.poll(leader).await;
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(LISTEN_POLL_INTERVAL) => {}
                }
            }
            // The stop's own work: everything the box's processes published
            // comes down here, before the stopper's teardown continues.
            state.withdraw_all().await;
        });
        Self { stop, task }
    }

    /// Stops the watcher and withdraws every port it still publishes — the
    /// gate refusing each first, the switch's forward second — so that when
    /// this returns, no port the box's processes published by listening is
    /// published any more. The declared forwards are not this call's:
    /// they come down with the attachment's own teardown (NET-121).
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        if let Err(join) = self.task.await {
            tracing::warn!(
                error = %join,
                "the listen-publication watcher ended without withdrawing everything"
            );
        }
    }
}

/// The watcher's own state: what the box's processes were listening on at
/// the last read, and which of those the watcher published. `forwards` is
/// exactly the runtime-published set (NET-081's sub-requirement's own set):
/// a declared port is never in it, and a port the rules did not permit
/// never enters it.
struct WatchState {
    plan: ListenPlan,
    /// The listening ports the last read named — published or not, so the
    /// diff knows an appearance from a persistence.
    listening: HashSet<u16>,
    /// The forwards standing for the ports the watcher published.
    forwards: HashMap<u16, ExposedMapping>,
}

impl WatchState {
    fn new(plan: ListenPlan) -> Self {
        Self {
            plan,
            listening: HashSet::new(),
            forwards: HashMap::new(),
        }
    }

    /// One poll: read the box's listening sockets, publish what appeared,
    /// withdraw what closed.
    async fn poll(&mut self, leader: u32) {
        let listening = match listening_ports(leader) {
            Ok(listening) => listening,
            Err(e) => {
                // The leader's entry is gone or unreadable — the box's
                // shell has exited, and the host stops the watcher with
                // the session. Keep the last diff rather than publishing
                // or withdrawing on a table that could not be read: the
                // stop withdraws everything still standing.
                tracing::debug!(
                    session = %self.plan.box_name,
                    leader,
                    error = %e,
                    "reading the box's listening sockets"
                );
                return;
            }
        };
        // The diff is taken before anything mutates, so a publication made
        // here cannot be seen by the withdrawal beside it.
        let appeared: Vec<u16> = listening.difference(&self.listening).copied().collect();
        let disappeared: Vec<u16> = self.listening.difference(&listening).copied().collect();
        for port in appeared {
            self.open(port).await;
        }
        for port in disappeared {
            self.close(port, "listener closed").await;
        }
        self.listening = listening;
    }

    /// NET-016: one listening port appeared. The shared verdict decides
    /// what the appearance is worth before anything is bound.
    async fn open(&mut self, port: u16) {
        match self.plan.gate.listen_verdict(port) {
            ListenVerdict::Publish => {
                // The forward binds before the gate admits — the order the
                // declaration's own apply holds (NET-121), so a port is
                // never admitted while nothing answers for it, and a bind
                // that fails admits nothing (the failure is already said,
                // one warn at the bind): the next poll sees the port still
                // unpublished and tries again.
                if let Ok(mapping) = expose_mapping(
                    &self.plan.control,
                    self.plan.published,
                    self.plan.lease,
                    port,
                )
                .await
                {
                    self.plan.gate.admit_published(port);
                    self.forwards.insert(port, mapping);
                    tracing::info!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        "published a listening port on the box's address"
                    );
                }
            }
            // A declaration names the port: its forward was bound at
            // publish and is held until the box stops (NET-121), so there
            // is nothing to publish — and when the listener closes, nothing
            // to withdraw (NET-081's sub-requirement). The declaration's
            // own bind lines already name the port.
            ListenVerdict::Declared => {}
            ListenVerdict::Deny => {
                tracing::info!(
                    session = %self.plan.box_name,
                    port,
                    verdict = "not permitted",
                    "left a listening port unpublished"
                );
            }
        }
    }

    /// NET-017: one published listening port closed — or the box stopped,
    /// which closes all of them at once. The gate refuses the port first,
    /// terminating the connections the publication held at both ends, so no
    /// new connection crosses the gap between a listener already gone and a
    /// forward still bound; the forward comes down after. The order a
    /// revoked declared forwarder's own `revoke` holds (NET-121).
    async fn close(&mut self, port: u16, reason: &'static str) {
        let Some(mapping) = self.forwards.remove(&port) else {
            // Never published by the watcher: a declared port, whose
            // forward is the declaration's (NET-121), or one the rules did
            // not permit, whose publication never existed.
            return;
        };
        let terminated = self.plan.gate.withdraw_published(port);
        match unexpose_mapping(&self.plan.control, &mapping).await {
            Ok(()) => tracing::info!(
                session = %self.plan.box_name,
                host = %self.plan.published,
                port,
                terminated,
                reason,
                "withdrew a listening port from the box's address"
            ),
            Err(_) => {
                // The unexpose failed and said so. The gate already refuses
                // the port, so nothing reaches the box through the forward
                // left standing; keep it in the published set so this
                // stop's last pass tries it again rather than leaving it
                // for the switch's lifetime.
                self.forwards.insert(port, mapping);
            }
        }
    }

    /// Stops the box's whole runtime-published surface: every forward still
    /// standing, withdrawn in the same order a listener's closing takes.
    async fn withdraw_all(&mut self) {
        let ports: Vec<u16> = self.forwards.keys().copied().collect();
        for port in ports {
            self.close(port, "box stopped").await;
        }
    }
}

/// The TCP ports a listening socket holds in the network namespace `leader`'s
/// `/proc` entry names — the box's, read through its leader: the kernel's
/// socket tables are per-network-namespace, so one process's entry names
/// every listening socket in the box, whichever of its processes holds it.
/// Both tables are read — a server bound on the IPv6 any address accepts
/// IPv4 connections, and its row lives in `tcp6`.
///
/// # Errors
///
/// Any read failure, so a caller decides what an unreadable table means
/// rather than silently acting on half of one.
fn listening_ports(leader: u32) -> io::Result<HashSet<u16>> {
    let entry = Path::new("/proc").join(leader.to_string());
    let mut ports = read_listening(&entry.join("net/tcp"), false)?;
    ports.extend(read_listening(&entry.join("net/tcp6"), true)?);
    Ok(ports)
}

/// One kernel socket table's listening ports: every row in state `0A`
/// (`TCP_LISTEN`) whose local address an IPv4 forward can deliver to. The
/// first line is the table's header.
fn read_listening(table: &Path, v6: bool) -> io::Result<HashSet<u16>> {
    let text = std::fs::read_to_string(table)?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|line| listen_port(line, v6))
        .collect())
}

/// The port of one listening row of the kernel's socket table, or `None`
/// for any other row: the header, a truncated row, a socket in any state
/// but `TCP_LISTEN` — an established or time-wait socket is a connection,
/// not a listener — or, in the v6 table, an address no IPv4 forward can
/// deliver to.
fn listen_port(line: &str, v6: bool) -> Option<u16> {
    let mut fields = line.split_whitespace();
    // `sl:` — the table's index column, always first.
    fields.next()?;
    let local = fields.next()?;
    // `rem_address`, then `st`.
    fields.next()?;
    if fields.next()? != "0A" {
        return None;
    }
    let (address, port) = local.rsplit_once(':')?;
    if v6 && !serves_v4(address) {
        return None;
    }
    u16::from_str_radix(port, 16).ok()
}

/// Whether a `tcp6` row's address can answer an IPv4 connection: the
/// dual-stack any (`::`), which accepts IPv4 by mapping, or a mapped
/// address (`::ffff:a.b.c.d`). A listener on any other v6 address cannot be
/// reached at the box's IPv4 lease, so publishing it would bind a forward
/// that dials a box with nothing listening for it — it is not a publication
/// the story owes. The kernel prints each 32-bit word little-endian, so the
/// marker reads `FFFF0000` and the mapped any reads as four zero words.
fn serves_v4(address: &str) -> bool {
    if address.len() != 32 {
        return false;
    }
    address.bytes().all(|b| b == b'0')
        || (address.starts_with("0000000000000000") && &address[16..24] == "FFFF0000")
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use crate::net::SwitchSubnet;

    use super::*;

    /// One request the fake forwarder served: the verb's path and the
    /// `local`/`remote` pair its body carried.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Served {
        path: String,
        local: String,
        remote: String,
    }

    /// The `name` field of a JSON request body, spelled as the serializer
    /// wrote it.
    fn field_of(body: &[u8], name: &str) -> String {
        let text = String::from_utf8_lossy(body);
        text.split(&format!("\"{name}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_string()
    }

    /// Reads one control request off `sock`: its head up to the end-of-head
    /// marker, then exactly its `Content-Length` body — the mirror of
    /// `post_json`'s keep-alive framing, so the fake forwarder never blocks
    /// reading past what the watcher sent. Returns the request's path and
    /// body.
    async fn read_request(sock: &mut UnixStream) -> (String, Vec<u8>) {
        let mut buf = Vec::with_capacity(256);
        let mut scratch = [0u8; 512];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                break i;
            }
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake forwarder must receive the request head");
            assert!(n > 0, "the watcher closed before sending its head");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let path = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        let len: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake forwarder must receive the request body");
            assert!(n > 0, "the watcher closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        (path, buf[head_end..head_end + len].to_vec())
    }

    /// A gvproxy-shaped control channel at `path`: every request is read in
    /// full, answered `200`, and recorded as its verb, `local` and
    /// `remote`. The channel the real switch's forwarder verbs ride, with
    /// its binds recorded instead of performed — what the proofs here read
    /// is the request the watcher made, because the switch's behaviour is
    /// `policy`'s own to prove. The server ends when the test drops its
    /// receiver.
    fn spawn_forwarder(path: PathBuf) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<Served>) {
        let listener = UnixListener::bind(&path).expect("the control socket binds");
        let (tx, rx) = mpsc::channel(64);
        let handle = tokio::spawn(async move {
            // Sequential on purpose: the watcher publishes and withdraws one
            // port at a time, awaited, so one connection served at a time is
            // its shape.
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (path, body) = read_request(&mut sock).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .expect("the fake forwarder must answer");
                let served = Served {
                    path,
                    local: field_of(&body, "local"),
                    remote: field_of(&body, "remote"),
                };
                if tx.send(served).await.is_err() {
                    return;
                }
            }
        });
        (handle, rx)
    }

    /// A bound, listening TCP socket in this process — the stand-in for the
    /// server a box's process runs: the watcher reads the kernel's socket
    /// table, and the test's own process is a leader whose table the port is
    /// genuinely in.
    fn listening_socket() -> TcpListener {
        TcpListener::bind(("127.0.0.1", 0)).expect("an ephemeral loopback port binds")
    }

    /// The port a bound listener holds.
    fn port_of(listener: &TcpListener) -> u16 {
        listener
            .local_addr()
            .expect("a bound socket has an address")
            .port()
    }

    /// The box's lease on the test switch.
    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    /// The box's published address (NET-010).
    const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 64, 0, 9);

    /// The box's ingress declaration: nothing statically mapped, a permit
    /// range covering exactly `port`, and the stance that lets listening
    /// publish (NET-016).
    fn permit_policy(port: u16) -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: Some((port, port)),
                dynamic_ingress: Some(sessions::DynamicIngress::Allow),
            }),
            egress: None,
        }
    }

    /// The box's watcher, started against a fake gvproxy control channel
    /// bound at a fresh socket, with its gate answering the given policy.
    /// Returns the watcher, the gate, and the fake's served-request
    /// receiver.
    fn started_watcher(
        dir: &tempfile::TempDir,
        policy: &sessions::SessionPolicy,
    ) -> (
        ListenWatcher,
        Arc<SessionGate>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let gate = Arc::new(SessionGate::for_session(
            "listen-box".into(),
            LEASE,
            policy,
            SwitchSubnet::default(),
        ));
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            Arc::clone(&gate),
        );
        // This process is the leader: its own `/proc` entry is the table the
        // watcher reads, and the sockets the test binds are in it.
        let watcher = ListenWatcher::start(plan, std::process::id());
        (watcher, gate, server, served)
    }

    /// Awaits the fake forwarder's next record, or fails the proof: nothing
    /// the watcher does should take past this bound — one poll interval for
    /// the work, and the bound is a person's patience, not the poll's.
    async fn next_served(served: &mut mpsc::Receiver<Served>) -> Served {
        tokio::time::timeout(Duration::from_secs(10), served.recv())
            .await
            .expect("the watcher acts within the bound")
            .expect("the fake forwarder stays alive")
    }

    /// Awaits `what` until it holds, or fails the proof: the fake serves
    /// its record *before* the watcher takes the step the proof reads next
    /// (the gate's admission follows the bind, the withdrawal's unexpose
    /// follows the refusal), so a served record alone does not order them.
    async fn soon(mut what: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the watcher did not reach the awaited state in the bound"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Every record the fake forwarder holds that the test has not read:
    /// called after the watcher has stopped, so the set is complete.
    fn drained(served: &mut mpsc::Receiver<Served>) -> Vec<Served> {
        let mut records = Vec::new();
        while let Ok(served) = served.try_recv() {
            records.push(served);
        }
        records
    }

    /// NET-016: a process in the box listens on a permitted port and the
    /// port is published — a forward bound at the box's own address, at the
    /// port the process listens on (NET-010: the same number on both sides,
    /// no translation), delivering to the box's lease at that same number —
    /// and admitted at the box's ingress gate, with no ingress declaration
    /// involved anywhere.
    #[tokio::test]
    async fn listen_publishes_permitted_port() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        assert!(
            !gate.admits_tcp(port),
            "nothing is published before the listener is seen"
        );
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(
            published.remote,
            format!("{LEASE}:{port}"),
            "the port is published at its own number, delivered at its own number"
        );
        // The admission is the step after the bind the record names, so it
        // is awaited, not assumed: the gate admits a port only once
        // something answers for it.
        soon(|| gate.admits_tcp(port)).await;

        // The stop withdraws what it published: the port's publication ends
        // with the watcher, exactly as the story ends it with the box.
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// NET-016's sub-requirement: a listener on a port the rules do not
    /// permit is never published — no forward, no admission — while a
    /// permitted listener beside it publishes, so the proof's silence is
    /// the watcher's own decision and not a loop that never ran.
    #[tokio::test]
    async fn listen_on_undeclared_port_not_published() {
        let permitted = listening_socket();
        let port = port_of(&permitted);
        let declined = listening_socket();
        let other = port_of(&declined);
        assert_ne!(port, other, "two bound sockets hold two ports");
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        // The permitted listener publishes: this is the control that the
        // poll ran and read both sockets.
        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;
        assert!(
            !gate.admits_tcp(other),
            "a port the rules do not permit is never admitted"
        );

        // The other listener, seen in the same poll, publishes nothing: no
        // request ever names it — across the stop's own withdrawal too, so
        // the silence is the watcher's decision and not a drained record.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records
                .iter()
                .all(|served| served.local != format!("{PUBLISHED}:{other}")),
            "no request ever names the port the rules do not permit: {records:?}"
        );
        server.abort();
    }

    /// NET-017: the listener closes and the port's publication is withdrawn
    /// — the forward comes down, the gate stops admitting — and a fresh
    /// listener on the same port (the restart every server makes) is
    /// published again.
    #[tokio::test]
    async fn listener_close_withdraws_publication() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes. The next poll sees the port gone and
        // withdraws the publication.
        drop(listener);
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(
            !gate.admits_tcp(port),
            "the port's admission went with its listener"
        );

        // A fresh listener on the same port publishes it again: the
        // withdrawal held nothing back.
        let restarted = std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("a closed listener leaves its port free to rebind");
        let republished = next_served(&mut served).await;
        assert_eq!(republished.path, "/services/forwarder/expose");
        assert_eq!(republished.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        drop(restarted);
        watcher.stop().await;
        let last = next_served(&mut served).await;
        assert_eq!(last.path, "/services/forwarder/unexpose");
        server.abort();
    }

    /// The kernel socket table's rows read as the watcher reads them: a
    /// listener's port, and only a listener's — an established socket is a
    /// connection, not a publication — from either table, and from the v6
    /// table only where the address can answer an IPv4 connection.
    #[test]
    fn socket_rows_read_their_listening_port() {
        // The v4 table: header, a listener on 127.0.0.1:8080
        // (`0100007F:1F90`), an established socket at the same port, and a
        // row too short to read.
        let v4 = "  sl  local_address  rem_address   st\n\
                  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n\
                  1: 0100007F:1F90 0100007F:9C4A 01 00000000:00000000\n\
                  2: 0100007F";
        let ports: HashSet<u16> = v4
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, false))
            .collect();
        assert_eq!(ports, HashSet::from([8080]));

        // The v6 table: the dual-stack any (`::`), a v4-mapped listener,
        // and a pure v6 address no IPv4 forward can deliver to.
        let v6 = "  sl  local_address  rem_address   st\n\
                  0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n\
                  1: 0000000000000000FFFF00000100007F:2328 00000000000000000000000000000000:0000 0A\n\
                  2: 00000000000000000000000100000000:2329 00000000000000000000000000000000:0000 0A\n";
        let ports: HashSet<u16> = v6
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, true))
            .collect();
        assert_eq!(ports, HashSet::from([8080, 9000]));
        assert!(
            !serves_v4("00000000000000000000000100000000"),
            "a pure v6 address"
        );
        assert!(
            serves_v4("00000000000000000000000000000000"),
            "the dual-stack any"
        );
    }

    /// The leader's process entry names its own listening sockets, and stops
    /// naming them when they close: the table the watcher's whole story
    /// reads, proved against the real kernel rather than a fixture.
    #[test]
    fn the_leader_entry_names_its_own_listeners() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let ports = listening_ports(std::process::id()).expect("this process's entry is readable");
        assert!(
            ports.contains(&port),
            "a bound listener is in the leader's table"
        );
        drop(listener);
        let ports = listening_ports(std::process::id()).expect("this process's entry is readable");
        assert!(
            !ports.contains(&port),
            "a closed listener leaves the leader's table"
        );
    }
}
