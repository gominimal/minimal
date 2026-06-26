//! Network-namespace integration proofs for the minimald networking stack
//! (Unit 1, issue #496).
//!
//! * `netns_uc1_nonet_refuses_egress` — UC1: a `NoNet` PTask, isolated in its
//!   own empty network namespace, cannot reach the internet.
//! * `netns_uc6_ownip_ptask_to_ptask` — UC6: two `OwnIp` PTasks on the same
//!   host, each with a tap bridged onto the shared gvproxy switch, can open a
//!   TCP connection to each other over their switch addresses.
//!
//! UC6 drives the **production** switch-attach wiring rather than a hand-rolled
//! `ip netns` sequence: each PTask's namespace is created by the same
//! `CLONE_NEWNET` `unshare` that `sandbox2::new_container` performs for `OwnIp`,
//! identified by the holder process's PID exactly as the live launcher
//! identifies a sandbox child's netns, and the tap is moved+configured by the
//! production [`minimald::net::switch::tap_netns_commands`] (the same commands
//! `SandboxLauncher` runs, here wrapped in `sudo` for the unprivileged runner).
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

use minimald::net::switch::{attach_to_switch, open_tap, tap_netns_commands};
use minimald::net::{PtaskLease, SwitchClient, SwitchSubnet};

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
/// Drives the real switch lifecycle ([`SwitchClient`]), address allocation,
/// tap creation ([`open_tap`]) and switch relay ([`attach_to_switch`]); none of
/// these exist on the base branch, so the proof cannot pass against an empty PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST, run by ci-netns.yml"]
async fn netns_uc6_ownip_ptask_to_ptask() {
    if !gated() {
        return;
    }
    let state = tempfile::tempdir().expect("switch state dir");

    let mut switch = SwitchClient::new(gvproxy_bin(), state.path());
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let a_pid = a.pid().to_string();
    let client = loop {
        let out = sudo(&[
            "nsenter",
            "-t",
            &a_pid,
            "-n",
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

/// R2.3 / R2.4-static — a static ingress port mapping applied at launch via
/// `POST /services/forwarder/expose` on the switch control socket makes a
/// listener inside an `OwnIp` PTask reachable from the host, and `unexpose` on
/// exit removes it.
///
/// Drives the production [`minimald::net::policy::apply_ingress`] /
/// [`remove_ingress`](minimald::net::policy::remove_ingress) against a live
/// gvproxy switch; neither exists on the base branch, so this cannot pass
/// against an empty PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST, run by ci-netns.yml"]
async fn netns_ingress_static_port_mapping_exposes_then_unexposes() {
    if !gated() {
        return;
    }
    use minimald::net::policy::{ControlChannel, apply_ingress, remove_ingress};
    use sessions::{IngressPolicy, IpProto, PortMapping};

    const INTERNAL: u16 = 80;
    const EXTERNAL: u16 = 18080;

    let state = tempfile::tempdir().expect("switch state dir");
    let mut switch = SwitchClient::new(gvproxy_bin(), state.path());
    let subnet = SwitchSubnet::default();

    let minimald::net::AttachResult { lease, .. } = switch.attach().await.expect("attach PTask");
    let sock = switch.control_socket();
    let mut ptask = Ptask::provision("ingress", lease, subnet, &sock).await;

    // A listener inside the PTask, bound to its switch address on the internal
    // port the forward targets.
    let mut server = ptask.spawn_listener(INTERNAL);

    // Apply the static ingress forward at "launch": host :EXTERNAL -> PTask:INTERNAL.
    let ingress = IngressPolicy {
        port_mappings: vec![PortMapping {
            external_port: EXTERNAL,
            internal_port: INTERNAL,
            proto: IpProto::Tcp,
        }],
        dynamic_allowed_range: None,
    };
    let control = ControlChannel::Unix(sock.clone());
    let exposed = apply_ingress(&control, lease.ip, &ingress)
        .await
        .expect("apply ingress");

    // From the host, connect to 127.0.0.1:EXTERNAL; gvproxy forwards the
    // connection into the PTask's listener over the switch. Retry until the
    // listener is up and the forward is installed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let reached = loop {
        // Bound each probe with `timeout` so a connect that succeeds but then
        // stalls on the read cannot hang past the overall retry deadline.
        let out = Command::new("timeout")
            .args([
                "2s",
                "bash",
                "-c",
                &format!("exec 3<>/dev/tcp/127.0.0.1/{EXTERNAL}; head -c2 <&3"),
            ])
            .output()
            .expect("spawn host connect");
        if out.status.success() || tokio::time::Instant::now() >= deadline {
            break out;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let _ = server.kill();
    let _ = server.wait();

    // Remove the forward on exit and confirm it is gone: a fresh host connect to
    // the same port must now fail.
    remove_ingress(&control, &exposed).await;
    let after_unexpose = Command::new("timeout")
        .args([
            "2s",
            "bash",
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{EXTERNAL}"),
        ])
        .output()
        .expect("spawn post-unexpose host connect");

    ptask.teardown();
    switch.stop().await.expect("stop switch");

    assert!(
        reached.status.success(),
        "host -> exposed ingress port failed: status={:?}\nstderr={}",
        reached.status.code(),
        String::from_utf8_lossy(&reached.stderr),
    );
    assert!(
        !after_unexpose.status.success(),
        "ingress forward still reachable after unexpose; teardown did not remove it",
    );
}

/// One provisioned `OwnIp` PTask: a PID-identified network namespace (held by a
/// `sleep` process in a fresh `CLONE_NEWNET` namespace, exactly as the live
/// launcher targets a sandbox child's netns by PID), a tap bridged onto the
/// switch by a relay, and the switch address configured inside the netns by the
/// production [`tap_netns_commands`].
struct Ptask {
    /// PID of the process holding the PTask's network namespace
    /// (`/proc/<pid>/ns/net`). Killing it tears the namespace down.
    netns_pid: u32,
    /// The `sudo unshare --net …` wrapper process, reaped on teardown.
    holder: std::process::Child,
    tap: String,
    lease: PtaskLease,
    // Holds the relay alive; taking it (in `teardown`) detaches the tap from
    // the switch.
    relay: Option<minimald::net::switch::SwitchRelay>,
}

impl Ptask {
    async fn provision(
        name: &str,
        lease: PtaskLease,
        subnet: SwitchSubnet,
        api_sock: &std::path::Path,
    ) -> Self {
        let tap = format!("tap-{name}");
        let _ = sudo(&["ip", "link", "del", &tap]);

        // Create the PTask's network namespace the way the production path does:
        // a process that `unshare`s `CLONE_NEWNET` (the same syscall
        // `sandbox2::new_container` issues for OwnIp) and then lingers, so its
        // PID identifies `/proc/<pid>/ns/net` for the move/config below.
        let (netns_pid, holder) = spawn_netns_holder();

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
        // The fd keeps working after the interface moves namespaces below.
        let fd = open_tap(&tap).expect("open tap fd");

        // Drive the PRODUCTION move/configure commands (move the tap into the
        // PTask's netns by PID, set its MAC/address/route and bring it and `lo`
        // up there) — the exact argv `SandboxLauncher` execs, here run under
        // `sudo` because this runner is unprivileged.
        for argv in tap_netns_commands(&tap, netns_pid, lease, subnet) {
            let strs: Vec<&str> = argv.iter().map(String::as_str).collect();
            sudo_ok("configure PTask tap", &strs);
        }

        let relay = attach_to_switch(fd, api_sock)
            .await
            .expect("attach tap to switch");

        Self {
            netns_pid,
            holder,
            tap,
            lease,
            relay: Some(relay),
        }
    }

    fn pid(&self) -> u32 {
        self.netns_pid
    }

    /// Spawns a one-shot TCP listener bound to this PTask's switch address,
    /// inside the PTask's netns (entered by PID via `nsenter`).
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
        let pid = self.netns_pid.to_string();
        Command::new("sudo")
            .args([
                "nsenter", "-t", &pid, "-n", "timeout", "25", "python3", "-c", &prog,
            ])
            .spawn()
            .expect("spawn listener")
    }

    fn teardown(&mut self) {
        // Detach from the switch first (stops the relay tasks, closes the tap
        // fd), then kill the namespace holder (which destroys the netns and the
        // tap inside it) and remove any interface left in the host namespace.
        self.relay.take();
        let _ = sudo(&["kill", &self.netns_pid.to_string()]);
        let _ = self.holder.kill();
        let _ = self.holder.wait();
        let _ = sudo(&["ip", "link", "del", &self.tap]);
    }
}

/// Spawns a long-lived process in a fresh network namespace (the same
/// `CLONE_NEWNET` `sandbox2::new_container` unshares for `OwnIp`/`NoNet`) and
/// returns its host PID plus the wrapper handle. `/proc/<pid>/ns/net` is the
/// PTask netns the production launcher targets.
fn spawn_netns_holder() -> (u32, std::process::Child) {
    use std::io::BufRead;

    let mut child = Command::new("sudo")
        .args(["unshare", "--net", "bash", "-c", "echo $$; exec sleep 600"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn netns holder");
    let stdout = child.stdout.as_mut().expect("netns holder stdout");
    let mut line = String::new();
    std::io::BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read netns holder pid");
    // `echo $$` then `exec sleep` keeps the same PID, so this is the netns
    // holder's host PID.
    let netns_pid: u32 = line.trim().parse().expect("parse netns holder pid");
    (netns_pid, child)
}
