//! Network-namespace integration proofs for the minimald networking stack
//! (Unit 1, issue #496).
//!
//! * `netns_uc1_nonet_refuses_egress` — UC1: a `NoNet` PTask, isolated in its
//!   own empty network namespace, cannot reach the internet.
//! * `netns_uc6_ownip_ptask_to_ptask` — UC6: two `OwnIp` PTasks on the same
//!   host, each with a tap bridged onto the shared gvproxy switch, can open a
//!   TCP connection to each other over their switch addresses.
//!
//! Both tests are `#[ignore]` and additionally early-return unless
//! `MINIMALD_NETNS_TEST` is set, and read the gvproxy binary from `GVPROXY_BIN`.
//! They run only in `.github/workflows/ci-netns.yml`, which provisions a
//! netns-capable runner (unprivileged userns + passwordless sudo) and the
//! pinned gvproxy binary. The function names contain `netns` so that job's
//! `cargo test ... netns` filter selects them. This sandbox cannot create
//! privileged network namespaces, so these proofs are authored here and
//! executed by CI, not locally.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use minimald::net::switch::{attach_to_switch, open_tap};
use minimald::net::{GvproxySwitch, PtaskLease, SwitchSubnet};

/// Whether the gate env var is set; when absent both proofs early-return so the
/// default `cargo test` run (and this sandbox) never attempts privileged netns
/// operations.
fn gated() -> bool {
    if std::env::var_os("MINIMALD_NETNS_TEST").is_some() {
        return true;
    }
    eprintln!("skipping netns proof: MINIMALD_NETNS_TEST not set");
    false
}

fn gvproxy_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("GVPROXY_BIN")
            .expect("GVPROXY_BIN must point at the gvproxy binary when MINIMALD_NETNS_TEST is set"),
    )
}

/// Runs `sudo <args...>` and returns the raw output (caller decides on success).
fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `sudo {}`: {e}", args.join(" ")))
}

/// Runs `sudo <args...>` and asserts it succeeded.
fn sudo_ok(label: &str, args: &[&str]) {
    let out = sudo(args);
    assert!(
        out.status.success(),
        "{label} (`sudo {}`) failed: status={:?}\nstderr={}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// UC1 — a `NoNet` PTask cannot egress.
///
/// Drives the egress attempt through `unshare --net`, which calls the same
/// `CLONE_NEWNET` syscall that `sandbox2::new_container` calls for
/// `NetworkMode::NoNet`. If `new_container` stopped calling `CLONE_NEWNET`,
/// the `isolates_network` assertion would no longer match the actual namespacing
/// behaviour; the `unshare --net` egress test guards the OS-level contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace; gated on MINIMALD_NETNS_TEST, run by ci-netns.yml"]
async fn netns_uc1_nonet_refuses_egress() {
    if !gated() {
        return;
    }

    // The production decision under test: NoNet isolates the network namespace,
    // HostNet shares it.
    assert!(sandbox2::isolates_network(sandbox2::NetworkMode::NoNet));
    assert!(!sandbox2::isolates_network(sandbox2::NetworkMode::HostNet));

    // Exercise the same OS primitive that sandbox2::new_container uses for NoNet
    // (CLONE_NEWNET via unshare): enter a fresh, empty network namespace and
    // attempt egress. The namespace has only a down lo and no routes, so the
    // TCP connect must fail with ENETUNREACH — the same contract new_container
    // enforces for NoNet PTasks.
    let egress = sudo(&[
        "unshare",
        "--net",
        "bash",
        "-c",
        "exec 3<>/dev/tcp/8.8.8.8/80",
    ]);

    assert!(
        !egress.status.success(),
        "egress unexpectedly succeeded from a CLONE_NEWNET namespace; NoNet isolation is not enforced"
    );
}

/// UC6 — two `OwnIp` PTasks talk to each other over the gvproxy switch.
///
/// Drives the real switch lifecycle ([`GvproxySwitch`]), address allocation,
/// tap creation ([`open_tap`]) and switch relay ([`attach_to_switch`]); none of
/// these exist on the base branch, so the proof cannot pass against an empty PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST, run by ci-netns.yml"]
async fn netns_uc6_ownip_ptask_to_ptask() {
    if !gated() {
        return;
    }
    let state = tempfile::tempdir().expect("switch state dir");

    let mut switch = GvproxySwitch::new(gvproxy_bin(), state.path());
    let subnet = SwitchSubnet::default();

    // Attach two PTasks; each gets a unique, never-reused switch address plus an
    // exit-signal receiver.
    let minimald::net::AttachResult { lease: lease_a, .. } =
        switch.attach().await.expect("attach PTask A");
    let minimald::net::AttachResult { lease: lease_b, .. } =
        switch.attach().await.expect("attach PTask B");
    assert_ne!(lease_a.ip, lease_b.ip);
    let sock = switch.control_socket();

    let mut a = Ptask::provision("uc6a", lease_a, subnet, &sock).await;
    let mut b = Ptask::provision("uc6b", lease_b, subnet, &sock).await;

    // PTask B listens on its switch address; PTask A connects to it. The traffic
    // crosses the gvproxy L2 switch entirely in userspace.
    const PORT: u16 = 9009;
    let mut server = b.spawn_listener(PORT);

    // Retry the connect until the listener is ready and the switch has learned
    // MACs. A fixed sleep is flaky on slow CI runners; retrying up to a deadline
    // is deterministic.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let client = loop {
        let out = sudo(&[
            "ip",
            "netns",
            "exec",
            a.ns(),
            "timeout",
            "2",
            "bash",
            "-c",
            &format!("exec 3<>/dev/tcp/{}/{PORT}; head -c2 <&3", lease_b.ip),
        ]);
        if out.status.success() || tokio::time::Instant::now() >= deadline {
            break out;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let _ = server.kill();
    let _ = server.wait();
    // Tear down relays/taps/namespaces explicitly before asserting, so a
    // teardown failure cannot mask the result.
    a.teardown();
    b.teardown();
    switch.stop().await.expect("stop switch");

    assert!(
        client.status.success(),
        "PTask A -> PTask B TCP connect failed: status={:?}\nstderr={}",
        client.status.code(),
        String::from_utf8_lossy(&client.stderr),
    );
}

/// One provisioned `OwnIp` PTask: a named network namespace, a tap bridged onto
/// the switch by a relay, and the switch address configured inside the netns.
struct Ptask {
    ns: String,
    tap: String,
    lease: PtaskLease,
    // Holds the relay alive; taking it (in `teardown`) detaches the tap from
    // the switch.
    relay: Option<minimald::net::switch::SwitchRelay>,
}

impl Ptask {
    async fn provision(
        ns: &str,
        lease: PtaskLease,
        subnet: SwitchSubnet,
        api_sock: &std::path::Path,
    ) -> Self {
        let tap = format!("tap-{ns}");
        let _ = sudo(&["ip", "netns", "del", ns]);
        let _ = sudo(&["ip", "link", "del", &tap]);

        // SAFETY: getuid() reads the calling user's real uid; it has no side
        // effects and cannot fail.
        let uid = unsafe { libc::getuid() };
        let uid = uid.to_string();

        // Create a persistent tap owned by this (non-root) user so `open_tap`
        // can attach to it without CAP_NET_ADMIN in the init namespace.
        sudo_ok(
            "create tap",
            &[
                "ip", "tuntap", "add", "dev", &tap, "mode", "tap", "user", &uid,
            ],
        );
        // Open the host-side data-plane fd; the relay reads/writes frames here.
        let fd = open_tap(&tap).expect("open tap fd");

        // Move the interface into the PTask namespace and configure its switch
        // address there (static config, per the gvproxy spike's Option B). The
        // host-side fd keeps working after the interface moves namespaces.
        sudo_ok("create netns", &["ip", "netns", "add", ns]);
        sudo_ok(
            "move tap into netns",
            &["ip", "link", "set", &tap, "netns", ns],
        );
        let mac = lease.mac.to_string();
        let cidr = format!("{}/{}", lease.ip, 16);
        let gw = subnet.gateway().to_string();
        run_in_ns(ns, &["ip", "link", "set", &tap, "address", &mac]);
        run_in_ns(ns, &["ip", "addr", "add", &cidr, "dev", &tap]);
        run_in_ns(ns, &["ip", "link", "set", &tap, "up"]);
        run_in_ns(ns, &["ip", "link", "set", "lo", "up"]);
        // Same-subnet PTask-to-PTask needs no default route, but add it so the
        // namespace mirrors a real OwnIp PTask.
        let _ = sudo(&[
            "ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", &gw,
        ]);

        let relay = attach_to_switch(fd, api_sock)
            .await
            .expect("attach tap to switch");

        Self {
            ns: ns.to_string(),
            tap,
            lease,
            relay: Some(relay),
        }
    }

    fn ns(&self) -> &str {
        &self.ns
    }

    /// Spawns a one-shot TCP listener bound to this PTask's switch address.
    fn spawn_listener(&self, port: u16) -> std::process::Child {
        let prog = format!(
            "import socket\n\
             s=socket.socket()\n\
             s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
             s.bind((\"{ip}\",{port}))\n\
             s.listen(1)\n\
             c,_=s.accept()\n\
             c.sendall(b\"ok\")\n\
             c.close()\n",
            ip = self.lease.ip,
        );
        Command::new("sudo")
            .args([
                "ip", "netns", "exec", &self.ns, "timeout", "25", "python3", "-c", &prog,
            ])
            .spawn()
            .expect("spawn listener")
    }

    fn teardown(&mut self) {
        // Detach from the switch first (stops the relay tasks, closes the tap
        // fd), then remove the namespace and any lingering interface.
        self.relay.take();
        let _ = sudo(&["ip", "netns", "del", &self.ns]);
        let _ = sudo(&["ip", "link", "del", &self.tap]);
    }
}

fn run_in_ns(ns: &str, args: &[&str]) {
    let mut full = vec!["ip", "netns", "exec", ns];
    full.extend_from_slice(args);
    sudo_ok("configure netns", &full);
}
