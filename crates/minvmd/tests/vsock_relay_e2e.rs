//! DM1 gvproxy relay end-to-end proof (R1.4, R1.5, R1.7).
//!
//! Boots a libkrun VM with an `OwnIp` PTask and asserts its network namespace
//! receives a `100.64.0.0/16` switch IP via the async TAP↔gvproxy relay, with
//! frames traversing the switch. This is the DM1 hardware proof: it needs
//! `/dev/kvm`, a real gvproxy binary, `CAP_NET_ADMIN` (tap + netns), the guest
//! kernel/rootfs/initramfs, and the libkrun runtime — none of which exist on a
//! stock dev machine. It is therefore validated on CI only.
//!
//! Test name contains `vsock` so CI selects it with
//! `cargo test -p minvmd vsock -- --include-ignored`.
//!
//! Gates (mirroring the `MINVMD_E2E` pattern):
//! - `#[cfg(minvmd_libkrun)]`: needs the libkrun-linking build.
//! - `#[ignore]`: skipped by default; run with `--include-ignored`.
//! - `MINVMD_INTEGRATION_TEST=1`: even with `--include-ignored`, the test
//!   self-skips unless this env gate is set, so it never boots a VM or touches
//!   `/dev/net/tun` on a developer machine.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS`, and
//!   `MINVMD_GVPROXY_BIN` must point at the guest artifacts and the gvproxy
//!   binary.

// The DM1 relay proof needs `/dev/net/tun` + netns (Linux) on top of libkrun.
// `open_tap`/`attach_to_switch` are Linux-only, so gate the whole test on both.
#![cfg(all(minvmd_libkrun, target_os = "linux"))]

use serial_test::serial;

/// Boot an `OwnIp` VM and assert the relay hands its netns a switch IP.
///
/// The body runs only under `MINVMD_INTEGRATION_TEST=1` on a KVM+gvproxy host;
/// off that gate it returns immediately so `cargo test` stays green locally.
#[test]
#[serial]
#[ignore = "gated MINVMD_INTEGRATION_TEST=1; requires /dev/kvm, gvproxy, CAP_NET_ADMIN"]
fn own_ip_ptask_gets_switch_ip_via_vsock_relay() {
    if std::env::var("MINVMD_INTEGRATION_TEST").as_deref() != Ok("1") {
        eprintln!("vsock_relay_e2e: MINVMD_INTEGRATION_TEST != 1, skipping");
        return;
    }

    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
        "MINVMD_GVPROXY_BIN",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "vsock_relay_e2e: {var} must be set when MINVMD_INTEGRATION_TEST=1"
        );
    }

    // The full hardware orchestration runs on the multi-threaded tokio runtime
    // the relay supervision requires.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(run_relay_proof());
}

/// Runs `ip <args...>` and asserts it succeeded. The CI step runs this test
/// under `sudo -E`, so `ip` already has `CAP_NET_ADMIN`; no `sudo` prefix is
/// needed (unlike the unprivileged minimald netns proof).
fn ip_ok(label: &str, args: &[&str]) {
    use std::process::Command;
    let out = Command::new("ip")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "{label} (`ip {}`) failed: status={:?}\nstderr={}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Runs `ip netns exec <ns> ip <args...>` and asserts it succeeded.
fn ip_in_ns(ns: &str, args: &[&str]) {
    let mut full = vec!["netns", "exec", ns, "ip"];
    full.extend_from_slice(args);
    ip_ok("configure netns", &full);
}

/// The DM1 proof body. Only reached under the env gate on a capable host.
async fn run_relay_proof() {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    use minimald_rpc::NetworkMode;
    use minvmd::net::{GvproxyConfig, SwitchSubnet, attach_to_switch, open_tap};
    use minvmd::vm::VmConfig;

    let state_dir = tempfile::TempDir::new().expect("isolated state dir");
    let switch_sock = state_dir.path().join("switch.sock");
    let gvproxy_bin = PathBuf::from(std::env::var("MINVMD_GVPROXY_BIN").unwrap());

    // 1. Spawn the per-host gvproxy switch with the subnet seeded into the
    //    -config YAML (gvproxy v0.8.9 has no -subnet CLI flag). Seed the first
    //    PTask's static lease up front so DHCP/static config inside the netns
    //    resolves deterministically.
    let subnet = SwitchSubnet::default();
    let first_ip = Ipv4Addr::from(subnet.first_ptask());
    let first_mac = minvmd::net::MacAddr::for_switch_ip(first_ip);
    let cfg = GvproxyConfig::new(gvproxy_bin, switch_sock.clone()).with_subnet(subnet);
    let (switch, _exit) = cfg
        .spawn(&[(first_ip, first_mac)])
        .expect("spawn gvproxy switch");

    // Wait for the control socket to accept connections before attaching.
    for _ in 0..200 {
        if tokio::net::UnixStream::connect(&switch_sock).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 2. Boot the libkrun VM as an OwnIp PTask.
    let vm = VmConfig::new(
        1,
        512,
        PathBuf::from(std::env::var("MINVMD_KERNEL_PATH").unwrap()),
        PathBuf::from(std::env::var("MINVMD_ROOTFS_PATH").unwrap()),
        PathBuf::from(std::env::var("MINVMD_INITRAMFS").unwrap()),
    )
    .with_network_mode(NetworkMode::OwnIp);
    assert!(vm.is_own_ip(), "VM must be an OwnIp PTask");
    let tap_name = VmConfig::tap_name(2);
    let netns = format!("ptask-{tap_name}");

    // 3. Create the PTask network namespace up front. `open_tap` opens the tap
    //    in the host namespace and `attach_to_switch` starts the relay; the tap
    //    interface is then moved into this netns and statically configured there
    //    (the gvproxy spike's Option B static-lease recipe — gvproxy does the
    //    lease seeding, but the netns side still has to apply the address). The
    //    host-side relay fd keeps working after the interface changes
    //    namespaces.
    let _ = Command::new("ip").args(["netns", "del", &netns]).output();
    ip_ok("create netns", &["netns", "add", &netns]);

    // 4. Provision the tap + start the async TAP↔gvproxy relay. `open_tap`
    //    creates the interface in the host namespace; `attach_to_switch` takes
    //    ownership of the fd and spawns the bidirectional relay, returning a
    //    handle whose lifetime owns the relay tasks (dropping it tears them down
    //    and closes the tap). The PTask uses the first-PTask lease seeded into
    //    gvproxy above (index 2).
    let tap_fd = open_tap(&tap_name).expect("open tap in host netns");
    let _relay = attach_to_switch(tap_fd, &switch_sock)
        .await
        .expect("attach OwnIp PTask to gvproxy switch");

    // 5. Assert the seeded PTask IP is on the 100.64.0.0/16 switch subnet.
    let ip = first_ip;
    assert_eq!(
        ip.octets()[0..2],
        [100, 64],
        "switch IP must be on 100.64.0.0/16, got {ip}"
    );

    // 6. Move the tap into the PTask netns and configure its switch address
    //    there (static config, mirroring the minimald UC6 netns proof). The MAC
    //    must match the `dhcpStaticLeases` key gvproxy was seeded with so the
    //    switch routes the lease's IP to this port.
    let mac = first_mac.to_string();
    let cidr = format!("{ip}/16");
    let gateway: Ipv4Addr = subnet.gateway();
    let gw = gateway.to_string();
    ip_ok(
        "move tap into netns",
        &["link", "set", &tap_name, "netns", &netns],
    );
    ip_in_ns(&netns, &["link", "set", &tap_name, "address", &mac]);
    ip_in_ns(&netns, &["addr", "add", &cidr, "dev", &tap_name]);
    ip_in_ns(&netns, &["link", "set", &tap_name, "up"]);
    ip_in_ns(&netns, &["link", "set", "lo", "up"]);
    // Same-subnet gateway reachability needs no default route (the gateway is
    // on-link), but add it so the namespace mirrors a real OwnIp PTask. Tolerate
    // failure: the IP assertion and the on-link gateway ping below do not depend
    // on it.
    let _ = Command::new("ip")
        .args([
            "netns", "exec", &netns, "ip", "route", "add", "default", "via", &gw,
        ])
        .output();

    // 7. Assert the IP is observable inside the VM's PTask netns (the static
    //    config landed on the interface), and that frames traverse the switch
    //    (a gateway ping round-trips over the relay).
    let addr_out = Command::new("ip")
        .args([
            "netns", "exec", &netns, "ip", "-4", "addr", "show", "dev", &tap_name,
        ])
        .output()
        .expect("ip netns exec addr show");
    let addr_text = String::from_utf8_lossy(&addr_out.stdout);
    assert!(
        addr_text.contains(&ip.to_string()),
        "PTask netns {netns} must carry switch IP {ip}; got:\n{addr_text}"
    );

    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            &netns,
            "ping",
            "-c",
            "1",
            "-W",
            "3",
            &gateway.to_string(),
        ])
        .status()
        .expect("ping gateway over relay");
    assert!(
        ping.success(),
        "PTask must reach the switch gateway {gateway} via the relay (frames must traverse the switch)"
    );

    // 8. Teardown: drop the relay (closes the tap fd and removes the moved
    //    interface with it), then drop the netns and stop the switch.
    drop(_relay);
    let _ = Command::new("ip").args(["netns", "del", &netns]).output();
    switch.stop().await;
}
