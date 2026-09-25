//! Network-namespace integration proofs for the minimald networking stack
//! (issue #496).
//!
//! * `netns_nonet_refuses_egress` — a no-network task, isolated in its own
//!   empty network namespace, cannot reach the internet.
//! * `netns_ownip_ptask_to_ptask` — two own-IP tasks on the same host, each
//!   with a tap bridged onto the shared gvproxy switch, can open a TCP
//!   connection to each other over their switch addresses.
//! * `netns_ingress_static_port_mapping_exposes_then_unexposes` — a static
//!   ingress mapping makes a listener inside an own-IP task reachable from the
//!   host, then removes it on exit.
//! * `network_none_blocks_all_outside_sockets` — a none box, launched through
//!   the production sandbox and its socket-family filter, cannot create any
//!   socket that reaches outside it, `AF_VSOCK` included.
//! * `network_none_attach_works` — a none box launched the way the session
//!   host launches it, session leader and pty included, keeps its terminal
//!   and still accepts an injected process.
//!
//! The own-IP proofs drive the **production** switch-attach wiring rather than a
//! hand-rolled `ip netns` sequence: each task's namespace is created by the same
//! `CLONE_NEWNET` `unshare` that `sandbox2::new_container` performs for own-IP
//! tasks, identified by the holder process's PID exactly as the live launcher
//! identifies a sandbox child's netns, and the tap is moved+configured by the
//! production [`minimald::net::switch::tap_netns_commands`]. Those commands
//! create a tap device and configure interfaces/routes inside the namespace,
//! which needs `CAP_NET_ADMIN`; the daemon holds it in production, so the proof
//! wraps each command in `sudo` on the unprivileged CI runner.
//!
//! Every proof here early-returns unless `MINIMALD_NETNS_TEST` is set, so the
//! default `cargo test` run (and this sandbox) never attempts privileged netns
//! operations; the three netns/gvproxy tests are additionally `#[ignore]`,
//! while the two none-box proofs are not, so the surveyed nextest lines can
//! name them. The own-IP proofs read the gvproxy binary from `GVPROXY_BIN`,
//! and the none-box proofs compile their socket probe with `gcc` — a gated
//! host that lacks either fails the proof rather than skipping it into a
//! false green. Auto-discovered by the native lane's `minimald-root-integration`
//! job via its `_root_integration` binary-name suffix
//! (`-E 'binary(/_root_integration$/)'`) — ubuntu-latest
//! with unprivileged userns + sudo for netns/tap and a userspace gvproxy switch,
//! no KVM; a new `crates/minimald/tests/*_root_integration.rs` joins that job with no
//! workflow edit. To run locally you need a netns-capable host (unprivileged
//! userns + sudo), gcc to build the socket probes, and a pinned gvproxy
//! (scripts/fetch-gvproxy.sh):
//! `MINIMALD_NETNS_TEST=1 GVPROXY_BIN=... cargo test -p minimald --test netns_root_integration -- --include-ignored`
#![cfg(target_os = "linux")]

use sandbox2::NetPlan;
use sandbox2::Network as _;
use sandbox2::config::{Config, SandboxMapped};

use std::path::{Path, PathBuf};
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

/// C source for a tiny static probe that checks which socket families a
/// process may create.  When run with no arguments it asserts `AF_UNIX` is
/// allowed and `AF_INET`, `AF_INET6`, and `AF_VSOCK` are refused with
/// `EAFNOSUPPORT`.  With argument `hold` it reports its working directory and
/// `SHELL` on stdout, then sleeps forever so the sandbox stays alive for
/// attach tests; with argument `attach` it checks that `AF_UNIX` is still
/// usable inside an injected process and reports the same two lines.
const SOCKET_PROBE_C: &str = r#"
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Two lines on stdout: the cwd hakoniwa chdir'd to and the SHELL it exported,
 * both of which the seccomp closure must carry across its command swap. */
static void report(void) {
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd)) { perror("getcwd"); _exit(30); }
    const char *shell = getenv("SHELL");
    printf("cwd=%s\nshell=%s\n", cwd, shell ? shell : "");
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "hold") == 0) {
        report();
        while (1) sleep(60);
    }

    if (argc > 1 && strcmp(argv[1], "attach") == 0) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { perror("AF_UNIX after attach"); return 20; }
        close(fd);

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) { close(fd); fprintf(stderr, "AF_INET after attach unexpectedly succeeded\n"); return 21; }
        if (errno != EAFNOSUPPORT) { fprintf(stderr, "AF_INET after attach wrong errno %d\n", errno); return 22; }

        fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (fd >= 0) { close(fd); fprintf(stderr, "AF_VSOCK after attach unexpectedly succeeded\n"); return 23; }
        if (errno != EAFNOSUPPORT) { fprintf(stderr, "AF_VSOCK after attach wrong errno %d\n", errno); return 24; }

        report();
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("AF_UNIX"); return 1; }
    close(fd);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) { close(fd); fprintf(stderr, "AF_INET unexpectedly succeeded\n"); return 2; }
    if (errno != EAFNOSUPPORT) { fprintf(stderr, "AF_INET wrong errno %d\n", errno); return 3; }

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd >= 0) { close(fd); fprintf(stderr, "AF_INET6 unexpectedly succeeded\n"); return 4; }
    if (errno != EAFNOSUPPORT) { fprintf(stderr, "AF_INET6 wrong errno %d\n", errno); return 5; }

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd >= 0) { close(fd); fprintf(stderr, "AF_VSOCK unexpectedly succeeded\n"); return 6; }
    if (errno != EAFNOSUPPORT) { fprintf(stderr, "AF_VSOCK wrong errno %d\n", errno); return 7; }

    return 0;
}
"#;

/// Compile the socket-family probe statically and return its path.
///
/// Panics when no C compiler is on `PATH` instead of skipping: this proof is
/// only reached behind `MINIMALD_NETNS_TEST`, so a host that sets the gate is
/// a host that promised to run it, and a skip here would be a vacuous green on
/// a security proof — the same shape the CI job's own fail-fast netns check
/// exists to prevent.
fn compile_socket_probe(base: &Path) -> PathBuf {
    let src = base.join("socket_probe.c");
    let bin = base.join("socket_probe");
    std::fs::write(&src, SOCKET_PROBE_C).expect("writing socket probe source");
    let status = Command::new("gcc")
        .args(["-static", "-o"])
        .arg(&bin)
        .arg(&src)
        .status();
    let status = match status {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            panic!(
                "gcc not found: the netns proofs are gated on \
                 MINIMALD_NETNS_TEST, so this host promised to run them; \
                 install a C compiler (build-essential on Ubuntu) rather \
                 than letting a security proof pass without asserting \
                 anything (spawn error: {e})"
            );
        }
        Err(e) => panic!("spawning gcc to compile socket probe: {e}"),
    };
    assert!(
        status.success(),
        "gcc failed to compile socket probe: {status:?}"
    );
    bin
}

/// Create a minimal rootfs directory containing the static probe at
/// `/usr/bin/probe`.  The sandbox layer symlinks `/bin -> /usr/bin` when
/// `/bin` is absent, so `/usr/bin` must exist.  `usr/lib` is also present so the
/// layer can create the `usr/lib64 -> lib` symlink.
fn probe_rootfs(dir: &Path, probe: &Path) {
    let usr_bin = dir.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin).expect("create rootfs usr/bin dir");
    std::fs::copy(probe, usr_bin.join("probe")).expect("copy probe into rootfs");
    std::fs::create_dir_all(dir.join("usr").join("lib")).expect("create rootfs usr/lib dir");
    // An empty /etc satisfies hakoniwa's rootfs setup without forcing a host
    // /etc bind that could trip over locked mount flags in restricted CI
    // runners.
    std::fs::create_dir_all(dir.join("etc")).expect("create rootfs etc dir");
}

/// The `minimald` binary under test, used as the namespace-joining shim.
fn shim() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_minimald"))
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

/// The session id and controlling-terminal number of `pid`, from
/// `/proc/<pid>/stat` (fields 6 and 7).  Read from outside the sandbox as the
/// process's owner, so no privilege is needed.
fn proc_session_and_tty(pid: u32) -> (u32, i32) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_else(|e| panic!("reading /proc/{pid}/stat for the launch-path check: {e}"));
    // The comm field (2) is parenthesised and may itself contain a ')', so the
    // parse starts after the last one.  What follows it is:
    // state(0) ppid(1) pgrp(2) session(3) tty_nr(4).
    let after_comm = stat
        .rsplit_once(')')
        .expect("/proc/<pid>/stat always carries a parenthesised comm field")
        .1;
    let fields: Vec<&str> = after_comm.split_ascii_whitespace().collect();
    let session: u32 = fields[3].parse().expect("the session field is a number");
    let tty_nr: i32 = fields[4].parse().expect("the tty_nr field is a number");
    (session, tty_nr)
}

/// NET-038. A none box refuses every socket family that reaches outside the
/// sandbox, `AF_VSOCK` included.  The test builds a real sandbox with an
/// isolated `NetPlan`, installs the production socket-family filter, and runs
/// a static probe inside that asserts `AF_INET`, `AF_INET6`, and `AF_VSOCK`
/// all fail with `EAFNOSUPPORT` while `AF_UNIX` still works.
///
/// The plan comes from the production provider, not the `NetPlan::none()`
/// constructor: `network_for(NetworkMode::NoNet)` maps every no-net consumer
/// to `sandbox2::NoNet` — a `--network none` session's box and a no-net
/// task's sandbox alike, since `task_network` goes through the same mapping —
/// so this proof runs the exact plan a no-net task's sandbox is built with
/// and pins that the task path is sealed like the session path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_none_blocks_all_outside_sockets() {
    if !gated() {
        return;
    }

    let rootfs_tmp = tempfile::tempdir_in("/tmp").expect("rootfs temp dir under /tmp");
    let probe = compile_socket_probe(rootfs_tmp.path());
    let source = rootfs_tmp.path().join("rootfs-src");
    probe_rootfs(&source, &probe);

    let no_net = sandbox2::NoNet
        .plan()
        .await
        .expect("the production NoNet provider plans do not fail");
    assert!(
        no_net.blocks_outside_sockets(),
        "the NoNet provider must seal every consumer it plans, tasks included"
    );

    let config = Config::new("none-sockets")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(no_net);
    // Build the sandbox in /tmp rather than the default (/home is a read-only
    // ext4 bind with locked nosuid, which breaks the unprivileged remounts
    // hakoniwa does inside the user namespace).
    let tmp = tempfile::tempdir_in("/tmp").expect("sandbox temp dir under /tmp");
    let mut sandbox = config
        .build(tmp.path().join("sandbox"), ())
        .await
        .expect("building none-box sandbox");
    let plan = sandbox.built_in_plan();
    let container = sandbox
        .new_container(&plan)
        .expect("building none-box container");

    let mut child = sandbox
        .command(
            &container,
            "/usr/bin/probe",
            [""; 0],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("building probe command")
        .spawn()
        .expect("spawning probe in none box");
    let status = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || child.wait()),
    )
    .await
    .expect("waiting for probe timed out")
    .expect("spawn_blocking join")
    .expect("waiting for probe");
    assert!(
        status.success(),
        "probe in none box did not report all outside sockets blocked: {status:?}"
    );
}

/// NET-039. A none box stays attachable.  The test launches a long-lived none
/// box the way the session host launches a real one — `set_session_leader()`
/// before the command is built, a pty slave on the box's stdin — injects a
/// second process into its namespaces with the production nsenter shim, and
/// verifies that the injected process can still create an `AF_UNIX` socket —
/// the local family the minenv socket and `min` helper rely on.
///
/// Driving the session-leader runctl is what makes this a launch-path proof:
/// the none-box launch swaps the built command for a seccomp closure, and if
/// that swap ever dropped `Runctl::NewSession`, every none box would start
/// without a controlling terminal and attach would break — so the box's
/// process is asserted to come out of the swap as its own session leader
/// holding the pty as its controlling terminal.
///
/// Both processes also report their working directory and `SHELL`: the
/// none-box launch swaps the built command for a seccomp closure, and the
/// session host names the shell on the command *after* `Sandbox::command`
/// returns, so a swap that dropped either would start every none box in `/`
/// with no `SHELL`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_none_attach_works() {
    if !gated() {
        return;
    }
    use minimald::nsenter::{Injection, session_leader_pid};
    use minimald::session_host::{Pty, WinSize};
    use std::io::BufRead as _;

    /// What the session host would set: the shell that is actually running.
    const PROBE_SHELL: &str = "/usr/bin/probe";

    let rootfs_tmp = tempfile::tempdir_in("/tmp").expect("rootfs temp dir under /tmp");
    let probe = compile_socket_probe(rootfs_tmp.path());
    let source = rootfs_tmp.path().join("rootfs-src");
    probe_rootfs(&source, &probe);

    let config = Config::new("none-attach")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(NetPlan::none());
    let tmp = tempfile::tempdir_in("/tmp").expect("sandbox temp dir under /tmp");
    let mut sandbox = config
        .build(tmp.path().join("sandbox"), ())
        .await
        .expect("building none-box sandbox");
    let plan = sandbox.built_in_plan();
    let mut container = sandbox
        .new_container(&plan)
        .expect("building none-box container");
    // The session host's own sequence (session_host.rs:2207): the box becomes
    // its own session leader *before* `Sandbox::command` builds the command
    // whose program the seccomp closure swap replaces, so the swap is what has
    // to carry the runctl to the child hakoniwa forks.
    container.set_session_leader();

    let expected_cwd = sandbox.command_cwd().expect("resolving sandbox cwd");
    let expected_report = vec![
        format!("cwd={expected_cwd}"),
        format!("shell={PROBE_SHELL}"),
    ];

    let mut hold = sandbox
        .command(
            &container,
            "/usr/bin/probe",
            ["hold"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("building hold command");
    // Set after `command()` returns, exactly as the session host sets `SHELL`.
    hold.env("SHELL", PROBE_SHELL);
    // The terminal the launch hands the box, on stdin — the fd hakoniwa's
    // `TIOCSCTTY` acts on, so `Runctl::NewSession` can make it the box's
    // controlling terminal.  A real session wires stdout and stderr to the
    // same slave (session_host.rs:2256-2260); stdout stays a pipe here so the
    // report below arrives byte-exact, and the box's stdin — the one the
    // terminal dance needs — is the part this proof exercises.  The pair
    // outlives the box: closing the master while the box runs would SIGHUP it.
    let pty = Pty::open(WinSize {
        rows: 24,
        cols: 80,
        xpixel: 0,
        ypixel: 0,
    })
    .expect("opening the launch-path pty");
    hold.stdin(hakoniwa::Stdio::from(
        pty.dup_slave_fd()
            .expect("duplicating the launch-path pty slave"),
    ));
    hold.stdout(hakoniwa::Stdio::MakePipe);
    let mut child = hold.spawn().expect("spawning hold process in none box");

    let hold_stdout = child.stdout.take().expect("hold process stdout pipe");
    let hold_report = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            std::io::BufReader::new(hold_stdout)
                .lines()
                .take(2)
                .collect::<Result<Vec<String>, _>>()
                .expect("reading the hold process report")
        }),
    )
    .await
    .expect("hold process report timed out")
    .expect("spawn_blocking join");
    if hold_report != expected_report {
        // The hold process is gone — its stdout reached EOF — so say how it
        // died, not just what failed to arrive.  A launch that never reached
        // the program (a host that cannot build the sandbox exits 125 in
        // hakoniwa's mount setup, before any seccomp or exec) reads
        // differently here from a launch that started the program without
        // its cwd or `SHELL`, and the difference is the first thing to check.
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || child.wait()),
        )
        .await
        .expect("waiting for the silent hold process timed out")
        .expect("spawn_blocking join")
        .expect("waiting for the silent hold process");
        panic!(
            "the none-box launch lost the command's cwd or SHELL across the \
             seccomp closure swap: expected {expected_report:?}, got \
             {hold_report:?}; the hold process exited with {status:?}"
        );
    }

    let leader =
        session_leader_pid(child.id()).expect("resolving the none box's session leader pid");

    // The launch-path half of NET-039: hakoniwa runs `setsid()` and
    // `TIOCSCTTY` in the box's own process, driven by the container's runctl
    // set before the command was built — so the process the injection targets
    // must be its own session leader holding the pty as its controlling
    // terminal, exactly the state an attach hands a client.  A closure swap
    // that dropped the runctl, or the stdio the terminal dance acts on, fails
    // here instead of leaving every none box terminal-less.
    let (session, tty_nr) = proc_session_and_tty(leader);
    assert_eq!(
        session, leader,
        "the none-box launch lost Runctl::NewSession across the seccomp \
         closure swap: the box's process is not its own session leader, so \
         an attach would find no session to hand a terminal to"
    );
    assert_ne!(
        tty_nr, 0,
        "the none-box launch acquired no controlling terminal: hakoniwa's \
         TIOCSCTTY needs the pty slave on the box's stdin, so a swap that \
         dropped the stdio or the session-leader runctl would start the box \
         without a terminal"
    );

    let mut env = sandbox.command_env();
    env.insert("SHELL".to_string(), PROBE_SHELL.to_string());
    let injection = Injection::new(leader, "/usr/bin/probe", ["attach"])
        .with_shim(shim())
        .with_cwd(expected_cwd)
        .with_env(env)
        .seal_none_box();
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            injection
                .command()
                .expect("building injection command")
                .output()
                .expect("running injected attach probe")
        }),
    )
    .await
    .expect("injected attach probe timed out")
    .expect("spawn_blocking join");

    let _ = child.kill();
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || child.wait()),
    )
    .await
    .expect("waiting for hold process timed out")
    .expect("spawn_blocking join")
    .expect("waiting for hold process");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "attach probe in none box failed: status={:?}\nstderr={stderr}",
        output.status.code(),
    );
    let attach_report: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        attach_report, expected_report,
        "the injected process did not start in the box's cwd with its SHELL (stderr={stderr})"
    );
}

/// A no-network task cannot reach the internet.
///
/// Drives the egress attempt through `unshare --net`, which calls the same
/// `CLONE_NEWNET` syscall that `sandbox2::new_container` calls for an
/// isolating plan. If `new_container` stopped calling `CLONE_NEWNET`, the
/// `isolates_netns` assertion would no longer match the actual namespacing
/// behaviour; the `unshare --net` egress test guards the OS-level contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a network namespace; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn netns_nonet_refuses_egress() {
    if !gated() {
        return;
    }

    // The production decision under test: `NoNet` plans an isolated network
    // namespace, `HostNet` a shared one.
    assert!(sandbox2::NoNet.plan().await.unwrap().isolates_netns());
    assert!(!sandbox2::HostNet.plan().await.unwrap().isolates_netns());

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

/// Two own-IP tasks reach each other over the gvproxy switch.
///
/// Drives the real switch lifecycle ([`SwitchClient`]), address allocation,
/// tap creation ([`open_tap`]) and switch relay ([`attach_to_switch`]); none of
/// these exist on the base branch, so the proof cannot pass against an empty PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn netns_ownip_ptask_to_ptask() {
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

    let mut a = Ptask::provision("peer-a", lease_a, subnet, &sock).await;
    let mut b = Ptask::provision("peer-b", lease_b, subnet, &sock).await;

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
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
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
        dynamic_ingress: None,
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

        let relay = attach_to_switch(fd, api_sock, None, subnet)
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
