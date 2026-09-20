//! NET-085 — a root process inside the VM reaches no further than the
//! resident union.
//!
//! On a VM-backed host the guest's word is not the last one on what leaves
//! the VM: libkrun dials `minvmd`'s own socket, and every frame is decided
//! outside the VM by its source address ([`HostFilter`], NET-081). This
//! harness plays the escape that filter exists for. It stands the real relay
//! up — the socket libkrun dials, a stand-in switch on the upstream socket,
//! and the daemon's record of two resident boxes behind the policy feed — and
//! then acts as a process that has root inside the VM: it opens the shuttle
//! connection itself and writes frames wearing source addresses it has no
//! right to.
//!
//! Root inside the VM can forge any source address, so the harness spoofs
//! each one that matters: another resident box's lease, an address no box
//! holds (announced to the switch's DNS first, the way the guest daemon
//! announces a real lease), and the daemon's own node address. At each it
//! aims five destinations: one declared by each resident box, the baseline
//! set's resolver, and two destinations no resident box declared.
//!
//! The bound NET-085 states is what the harness proves: of everything the
//! spoofer sent while wearing a box's address, only frames to destinations in
//! the union of the resident boxes' declared egress plus the baseline set
//! reached the switch; wearing an address no box holds it reached nothing at
//! all, not even a destination inside the union; and its own announcement
//! bought it no rules, so the union stays the resident boxes'. The union is
//! read off the filter's own resident table rather than restated here, and
//! the baseline member is read off [`BaselineSet`].
//!
//! Not covered: the daemon's node address. Node-plane traffic is admitted by
//! address — the baseline set's registry and cache are names, pinned by the
//! node's DNS layer, not by address in the filter — so a spoofer wearing the
//! node address is bounded there and not here. The harness sends that row too
//! and records what happened, which is where to look if the node-plane bound
//! ever moves into the filter.

use std::collections::BTreeMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use minvmd::net::{BaselineCategory, BaselineSet, HostFilter, HostRules, SwitchSubnet};
use sessions::EgressPolicy;
use sessions::core::net_verdict::{
    self, EgressRules, FrameSummary, IPPROTO_TCP, IPPROTO_UDP, Verdict,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing_subscriber::fmt::MakeWriter;

/// The first resident box's lease: the address the spoofing process itself
/// wears legitimately.
const ALPHA: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
/// The second resident box's lease: the address NET-085's spoofer forges.
const BETA: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 6);
/// An address no box holds, which the root process announces as its own.
const ROGUE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 99);

const ETH_HDR: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// An Ethernet/IPv4 frame with a minimal transport header and `tag` as its
/// payload, so an admitted frame can be traced back to the attempt that sent
/// it.
fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, dst_port: u16, tag: u8) -> Vec<u8> {
    let mut f = vec![0u8; ETH_HDR];
    f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 64, proto, 0, 0,
    ]);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&[0u8; 16]);
    f.push(tag);
    f
}

/// One frame with the 2-byte little-endian length prefix the shuttle uses.
fn framed(frame: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(frame.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(frame);
    out
}

/// A box that declared `allow` and nothing else.
fn policy(allow: &[&str]) -> EgressPolicy {
    EgressPolicy {
        allow_subnets: Some(allow.iter().map(ToString::to_string).collect()),
        ..EgressPolicy::default()
    }
}

/// The index just past the `\r\n\r\n` that ends an HTTP head.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// A stand-in for gvproxy on the upstream socket: it answers the guest's
/// control requests the way the switch does and forwards every frame of a
/// `POST /connect` stream down the channel, so the harness sees exactly what
/// left the VM.
fn stand_in_switch(sock: &Path) -> mpsc::UnboundedReceiver<Vec<u8>> {
    let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind stand-in switch");
    listener.set_nonblocking(true).unwrap();
    let listener = UnixListener::from_std(listener).unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while find_header_end(&head).is_none() {
                    if conn.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                if head.starts_with(b"POST /connect") {
                    loop {
                        let mut len = [0u8; 2];
                        if conn.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut frame = vec![0u8; usize::from(u16::from_le_bytes(len))];
                        if conn.read_exact(&mut frame).await.is_err() || tx.send(frame).is_err() {
                            return;
                        }
                    }
                }
                // A control request (the lease announcement): answer 200 and
                // stay open until the filter closes the connection.
                let _ = conn
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let mut sink = [0u8; 1024];
                while conn.read(&mut sink).await.is_ok_and(|n| n > 0) {}
            });
        }
    });
    rx
}

/// The tag of the next frame to reach the stand-in switch, or `None` if none
/// arrives.
async fn recv_tag(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Option<u8> {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .ok()
        .flatten()
        .map(|f| *f.last().unwrap())
}

/// Announce `label` at `lease` on the relay, as the guest daemon does when it
/// attaches a box (`POST /services/dns/add`).
async fn announce(listen: &Path, label: &str, lease: Ipv4Addr) {
    let body =
        format!(r#"{{"name":"min.internal.","records":[{{"name":"{label}","ip":"{lease}"}}]}}"#);
    let mut guest = UnixStream::connect(listen).await.unwrap();
    guest
        .write_all(
            format!(
                "POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut resp = [0u8; 64];
    let n = guest.read(&mut resp).await.unwrap();
    assert!(
        resp[..n].starts_with(b"HTTP/1.1 200"),
        "announcement of {label} was not answered: {:?}",
        String::from_utf8_lossy(&resp[..n])
    );
}

/// A `MakeWriter` accumulating the filter's `tracing` output, so the harness
/// can show the line that dropped or admitted each spoofed frame.
#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A source address the root process forges on the shuttle.
struct Spoof {
    who: &'static str,
    src: Ipv4Addr,
    /// Whether the union bound applies to this source: it does to every claim
    /// on the box plane, whether or not a box holds the address. It does not
    /// to the daemon's node address, whose destinations the DNS layer bounds.
    union_bound: bool,
    /// Which of the five destinations this source is expected to reach, in
    /// `targets` order. Written out rather than derived from the rules, so the
    /// expectation states the bound independently of the filter.
    admits: [bool; 5],
}

/// A destination the spoofer aims at.
struct Target {
    what: &'static str,
    dst: Ipv4Addr,
    proto: u8,
    port: u16,
}

/// NET-085: a root process inside the VM that spoofs another box's address
/// reaches only destinations in the union of the resident boxes' declared
/// egress plus the node-plane baseline set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_escape_bounded_to_resident_union() {
    let log = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("this harness owns the process' subscriber");

    let subnet = SwitchSubnet::default();
    let node = subnet.daemon_ip();
    let resolver = subnet.dns_server();
    // Short socket paths: a UNIX socket under macOS's default TMPDIR would
    // overflow `sun_path`.
    let tmp = tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("isolated socket dir");
    let upstream = tmp.path().join("up.sock");
    let listen = tmp.path().join("sw.sock");
    let mut at_switch = stand_in_switch(&upstream);

    // The daemon's record of what is resident in the VM: two boxes, each
    // declaring a different destination range. The root process is not in it.
    let mut feed = BTreeMap::new();
    feed.insert("alpha".to_string(), Some(policy(&["10.0.0.0/8"])));
    feed.insert("beta".to_string(), Some(policy(&["192.168.0.0/16"])));
    let filter = HostFilter::spawn(listen.clone(), upstream, HostRules::new(subnet), feed)
        .expect("host filter on the socket libkrun dials");

    // Two real lease announcements, then the root process announcing an
    // address of its own to buy itself rules.
    for (label, lease) in [("alpha", ALPHA), ("beta", BETA), ("rogue", ROGUE)] {
        announce(&listen, label, lease).await;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let rules = loop {
        let rules = filter.rules();
        if rules.boxes().count() == 2 || Instant::now() > deadline {
            break rules;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let resident: Vec<(Ipv4Addr, EgressRules)> =
        rules.boxes().map(|(lease, r)| (lease, r.clone())).collect();

    let targets = [
        Target {
            what: "10.1.2.3:443 (alpha declared)",
            dst: Ipv4Addr::new(10, 1, 2, 3),
            proto: IPPROTO_TCP,
            port: 443,
        },
        Target {
            what: "192.168.5.6:443 (beta declared)",
            dst: Ipv4Addr::new(192, 168, 5, 6),
            proto: IPPROTO_TCP,
            port: 443,
        },
        Target {
            what: "resolver:53 (baseline set)",
            dst: resolver,
            proto: IPPROTO_UDP,
            port: 53,
        },
        Target {
            what: "93.184.216.34:443 (declared by nobody)",
            dst: Ipv4Addr::new(93, 184, 216, 34),
            proto: IPPROTO_TCP,
            port: 443,
        },
        Target {
            what: "172.16.9.9:8080 (declared by nobody)",
            dst: Ipv4Addr::new(172, 16, 9, 9),
            proto: IPPROTO_TCP,
            port: 8080,
        },
    ];
    let spoofs = [
        Spoof {
            // Its own address: bounded by its own declaration.
            who: "alpha's own lease",
            src: ALPHA,
            union_bound: true,
            admits: [true, false, true, false, false],
        },
        Spoof {
            // NET-085's case: bounded by the box whose address it wears.
            who: "beta's lease (spoofed)",
            src: BETA,
            union_bound: true,
            admits: [false, true, true, false, false],
        },
        Spoof {
            // No box holds it, so it reaches nothing at all.
            who: "rogue, no box's address",
            src: ROGUE,
            union_bound: true,
            admits: [false, false, false, false, false],
        },
        Spoof {
            // Node-plane traffic, admitted by address (see the module note).
            who: "the daemon's node address",
            src: node,
            union_bound: false,
            admits: [true, true, true, true, true],
        },
    ];
    assert_eq!(
        targets.len(),
        spoofs[0].admits.len(),
        "each spoof's expectation must cover every destination"
    );

    // The escape: one shuttle connection, every spoofed frame on it.
    let mut guest = UnixStream::connect(&listen).await.unwrap();
    guest.write_all(CONNECT_REQUEST).await.unwrap();
    let mut attempts = Vec::new();
    for (i, spoof) in spoofs.iter().enumerate() {
        for (j, target) in targets.iter().enumerate() {
            let tag = u8::try_from(i * targets.len() + j + 1).unwrap();
            let frame = ipv4_frame(spoof.src, target.dst, target.proto, target.port, tag);
            guest.write_all(&framed(&frame)).await.unwrap();
            attempts.push((tag, i, j));
        }
    }
    // A frame that is certainly admitted, sent last. The relay decides frames
    // in order, so its arrival means every attempt above has been decided —
    // a drop produces nothing to wait for.
    const SENTINEL: u8 = 255;
    let last = ipv4_frame(
        ALPHA,
        targets[0].dst,
        targets[0].proto,
        targets[0].port,
        SENTINEL,
    );
    guest.write_all(&framed(&last)).await.unwrap();
    let mut arrived = Vec::new();
    loop {
        let tag = recv_tag(&mut at_switch)
            .await
            .expect("the sentinel frame must reach the stand-in switch");
        if tag == SENTINEL {
            break;
        }
        arrived.push(tag);
    }
    // The refusal of the rogue announcement is logged off the request path.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !log.contents().contains("lease announced for no known box") && Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let drops = filter.drops();
    let log_text = log.contents();

    // Diagnostics: every attempt with its outcome, then the helper's drop
    // counters per rule and per source address, so the bound can be read off.
    println!("spoofed egress attempts:");
    for (tag, i, j) in &attempts {
        let outcome = if arrived.contains(tag) {
            "ADMITTED"
        } else {
            "dropped"
        };
        println!(
            "  [{tag:>3}] {:<26} -> {:<40} {outcome}",
            spoofs[*i].who, targets[*j].what
        );
    }
    println!("drops by rule:");
    for (rule, n) in &drops.by_rule {
        println!("  {rule:<16} {n}");
    }
    println!("drops by source address:");
    for (source, n) in &drops.by_source {
        println!("  {source:<16} {n}");
    }
    println!("host-side filter log:\n{log_text}");

    // The union the bound names, read off the filter's own resident table: a
    // destination is in it when some resident box may reach it from its own
    // lease. The baseline set's resolver is in every box's rules as the one
    // carve-out, and is the set's own member.
    assert_eq!(resident.len(), 2, "two boxes resident: {resident:?}");
    let leases: Vec<Ipv4Addr> = resident.iter().map(|(lease, _)| *lease).collect();
    assert_eq!(
        leases,
        vec![ALPHA, BETA],
        "the rogue announcement must buy no rules"
    );
    let in_union = |t: &Target| {
        resident.iter().any(|(lease, rules)| {
            net_verdict::frame_verdict(
                &FrameSummary {
                    src: *lease,
                    dst: t.dst,
                    proto: t.proto,
                    dst_port: Some(t.port),
                },
                rules,
            ) == Verdict::Admit
        })
    };
    let baseline = BaselineSet::enumerate_with(|_| None, subnet);
    assert_eq!(
        baseline
            .members(BaselineCategory::Resolver)
            .collect::<Vec<_>>(),
        [format!("{resolver}:53")],
        "the resolver destination is the baseline set's own member"
    );

    // Every attempt landed where the table says, and nothing a box address
    // carried past the union reached the switch.
    for (tag, i, j) in &attempts {
        let (spoof, target) = (&spoofs[*i], &targets[*j]);
        let admitted = arrived.contains(tag);
        assert_eq!(
            admitted, spoof.admits[*j],
            "{} -> {}: admitted={admitted}",
            spoof.who, target.what
        );
        if spoof.union_bound && admitted {
            assert!(
                in_union(target),
                "escape past the resident union: {} reached {}",
                spoof.who,
                target.what
            );
        }
    }
    // Stated the other way round, as the requirement states it: no box
    // address reached a destination outside the union, and the address no box
    // holds reached nothing at all — not even the destinations inside it.
    for (tag, i, j) in &attempts {
        let (spoof, target) = (&spoofs[*i], &targets[*j]);
        if spoof.union_bound && !in_union(target) {
            assert!(
                !arrived.contains(tag),
                "{} reached {}, outside the union",
                spoof.who,
                target.what
            );
        }
        if spoof.src == ROGUE {
            assert!(
                !arrived.contains(tag),
                "an address no box holds reached {}",
                target.what
            );
        }
    }
    // Nothing else arrived, and what did arrive came in the order it was sent:
    // the relay admitted exactly what each spoof expects, so a filter that
    // dropped every frame — or one that leaked a later frame past an earlier
    // drop — fails here.
    let expected: Vec<u8> = attempts
        .iter()
        .filter(|(_, i, j)| spoofs[*i].admits[*j])
        .map(|(tag, _, _)| *tag)
        .collect();
    assert_eq!(arrived, expected);

    // The counters the diagnostics print: three of alpha's five attempts and
    // three of beta's tripped a box rule (six), all five of rogue's tripped
    // the unknown-source rule, and the node row was admitted whole.
    assert_eq!(drops.by_rule.get("allow_subnets"), Some(&6));
    assert_eq!(drops.by_rule.get("unknown-source"), Some(&5));
    assert_eq!(drops.by_source.get(&ALPHA), Some(&3));
    assert_eq!(drops.by_source.get(&BETA), Some(&3));
    assert_eq!(drops.by_source.get(&ROGUE), Some(&5));
    assert_eq!(drops.by_source.get(&node), None);
    assert_eq!(drops.total(), 11);

    // The log the diagnostics print: the rules each resident box was entered
    // under, the refusal that kept the rogue announcement out of the union,
    // and one drop line per rule (the filter warns once per rule per minute).
    for needle in [
        "host-side rules entered for box",
        "label=alpha",
        "label=beta",
        "lease announced for no known box",
        "label=rogue",
        "rule=\"unknown-source\"",
        "source=Some(100.64.0.99)",
        "rule=\"allow_subnets\"",
    ] {
        assert!(
            log_text.contains(needle),
            "{needle} missing from the filter's log:\n{log_text}"
        );
    }

    drop(guest);
    filter.stop();
}
