//! UC7 — remote PTask-to-PTask over the WireGuard mesh tunnel (R4.2).
//!
//! This is proof artifact 1 of the Unit 4 task. It stands up two `minimald`
//! WireGuard peers in two separate Linux network namespaces joined by a veth
//! pair, completes a handshake via manual key exchange, and asserts that an IP
//! packet for one peer's advertised switch subnet, injected on the other peer,
//! crosses the encrypted tunnel between the namespaces and is decrypted on the
//! destination peer's tunnel sink.
//!
//! It is `#[ignore]` and gated on `MINIMAL_NETNS_TESTS=1`: it needs root (to
//! create namespaces and a veth pair, and to `setns`), so it runs only in the
//! privileged netns CI lane (`ci-netns.yml`), never in the default
//! `cargo test` gate. The whole file compiles to nothing unless the
//! `networking-wg` feature is enabled.
//!
//! Scope note: this harness exercises the mesh tunnel data path end-to-end
//! across two real network namespaces — the transport that carries UC7. Wiring
//! the tunnel sink into a live gvproxy switch so a literal `TCP connect` between
//! two `minimald`-managed PTasks traverses it is the follow-up that completes
//! the full six-hop UC7 path (spec R4.2); it builds directly on the data path
//! asserted here.

#![cfg(feature = "networking-wg")]

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::Duration;

use minimald::net::wg::{Ipv4Cidr, Keypair, MeshConfig, PeerConfig, start_with_socket};
use tokio::sync::mpsc;

/// The two namespaces and the veth addresses used to join them.
const NS_A: &str = "minimald_mesh_a";
const NS_B: &str = "minimald_mesh_b";
const VETH_A_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
const VETH_B_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
const WG_PORT: u16 = 51_820;

/// Advertised "switch" subnets each side routes for (one `/32` host each).
const A_SWITCH: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const B_SWITCH: Ipv4Addr = Ipv4Addr::new(100, 65, 0, 2);

fn run(args: &[&str]) -> std::io::Result<()> {
    let status = Command::new(args[0]).args(&args[1..]).status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "command failed ({status}): {}",
            args.join(" ")
        )));
    }
    Ok(())
}

/// Creates the two namespaces and the veth pair joining them.
fn setup_namespaces() -> std::io::Result<()> {
    run(&["ip", "netns", "add", NS_A])?;
    run(&["ip", "netns", "add", NS_B])?;
    run(&[
        "ip", "link", "add", "veth_a", "type", "veth", "peer", "name", "veth_b",
    ])?;
    run(&["ip", "link", "set", "veth_a", "netns", NS_A])?;
    run(&["ip", "link", "set", "veth_b", "netns", NS_B])?;
    run(&[
        "ip",
        "netns",
        "exec",
        NS_A,
        "ip",
        "addr",
        "add",
        &format!("{VETH_A_IP}/24"),
        "dev",
        "veth_a",
    ])?;
    run(&[
        "ip",
        "netns",
        "exec",
        NS_B,
        "ip",
        "addr",
        "add",
        &format!("{VETH_B_IP}/24"),
        "dev",
        "veth_b",
    ])?;
    run(&[
        "ip", "netns", "exec", NS_A, "ip", "link", "set", "veth_a", "up",
    ])?;
    run(&[
        "ip", "netns", "exec", NS_B, "ip", "link", "set", "veth_b", "up",
    ])?;
    run(&["ip", "netns", "exec", NS_A, "ip", "link", "set", "lo", "up"])?;
    run(&["ip", "netns", "exec", NS_B, "ip", "link", "set", "lo", "up"])?;
    Ok(())
}

fn teardown_namespaces() {
    let _ = run(&["ip", "netns", "del", NS_A]);
    let _ = run(&["ip", "netns", "del", NS_B]);
}

/// Binds a UDP socket on `addr:port` inside the named network namespace by
/// `setns`-ing this thread to it for the duration of the bind, then restoring
/// the original namespace. Socket namespace membership is fixed at creation, so
/// the returned socket stays in the target namespace.
fn bind_in_netns(ns: &str, addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let original = std::fs::File::open("/proc/self/ns/net")?;
    let target = std::fs::File::open(format!("/var/run/netns/{ns}"))?;

    // SAFETY: setns(fd, CLONE_NEWNET) moves the calling thread into the network
    // namespace referenced by the open nsfs fd. Both fds are valid open files
    // for the duration of these calls; the original is restored before return.
    let enter = unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
    if enter != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let socket = std::net::UdpSocket::bind(addr);
    // SAFETY: restore the original network namespace regardless of bind outcome.
    let restored = unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) };
    if restored != 0 {
        return Err(std::io::Error::last_os_error());
    }
    socket
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires root + two network namespaces; runs in the netns CI lane"]
async fn remote_ptask_packet_crosses_the_mesh_tunnel() {
    if std::env::var("MINIMAL_NETNS_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping: set MINIMAL_NETNS_TESTS=1 (and run as root) to exercise UC7");
        return;
    }

    teardown_namespaces(); // clear any leftovers from a prior run
    setup_namespaces().expect("namespace + veth setup (needs root)");

    let a_kp = Keypair::generate();
    let b_kp = Keypair::generate();
    let a_pub = a_kp.public();
    let b_pub = b_kp.public();

    let a_sock = bind_in_netns(NS_A, SocketAddr::from((VETH_A_IP, WG_PORT)))
        .expect("bind WireGuard socket in namespace A");
    let b_sock = bind_in_netns(NS_B, SocketAddr::from((VETH_B_IP, WG_PORT)))
        .expect("bind WireGuard socket in namespace B");

    let (a_sink_tx, _a_sink_rx) = mpsc::channel::<Vec<u8>>(8);
    let (b_sink_tx, mut b_sink_rx) = mpsc::channel::<Vec<u8>>(8);

    // A advertises its switch host and points at B's veth endpoint; B mirrors.
    let a_cfg = MeshConfig {
        keypair: a_kp,
        listen_port: WG_PORT,
        advertised_subnets: vec![Ipv4Cidr::new(A_SWITCH, 32).unwrap()],
        peers: vec![PeerConfig {
            name: "b".to_string(),
            public_key: b_pub,
            endpoint: Some(SocketAddr::from((VETH_B_IP, WG_PORT))),
            allowed_ips: vec![Ipv4Cidr::new(B_SWITCH, 32).unwrap()],
        }],
    };
    let b_cfg = MeshConfig {
        keypair: b_kp,
        listen_port: WG_PORT,
        advertised_subnets: vec![Ipv4Cidr::new(B_SWITCH, 32).unwrap()],
        peers: vec![PeerConfig {
            name: "a".to_string(),
            public_key: a_pub,
            endpoint: Some(SocketAddr::from((VETH_A_IP, WG_PORT))),
            allowed_ips: vec![Ipv4Cidr::new(A_SWITCH, 32).unwrap()],
        }],
    };

    let a = start_with_socket(a_cfg, a_sock, a_sink_tx).expect("start mesh A");
    let b = start_with_socket(b_cfg, b_sock, b_sink_tx).expect("start mesh B");

    // Wait for the handshake to complete across the veth.
    let handshook = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if a.peers().iter().any(|p| p.last_handshake_secs.is_some())
                && b.peers().iter().any(|p| p.last_handshake_secs.is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    let result = if handshook.is_err() {
        Err("handshake across namespaces did not complete".to_string())
    } else {
        let packet = minimald::net::wg::ipv4_test_packet(A_SWITCH, B_SWITCH, b"uc7");
        a.send_outbound(packet.clone())
            .expect("queue outbound packet");
        match tokio::time::timeout(Duration::from_secs(10), b_sink_rx.recv()).await {
            Ok(Some(got)) if got == packet => Ok(()),
            Ok(Some(_)) => Err("tunneled packet did not match what was sent".to_string()),
            Ok(None) => Err("tunnel sink closed before delivery".to_string()),
            Err(_) => Err("timed out waiting for the tunneled packet".to_string()),
        }
    };

    teardown_namespaces();
    result.expect("UC7 packet must cross the mesh tunnel");
}
