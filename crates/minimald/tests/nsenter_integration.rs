//! Proof that a process injected into a session's sandbox lands in *all* of the
//! sandbox's namespaces — the PID namespace included.
//!
//! The PID namespace is the whole point of the exercise. hakoniwa's
//! `Child::id()` is the container supervisor, which unshared the sandbox's
//! namespaces but never entered the PID namespace it created (see
//! [`minimald::nsenter`]), so joining namespaces off that PID silently leaves a
//! process in the host's PID namespace while putting it under a `/proc` mounted
//! from the sandbox's. `injected_process_joins_every_namespace` asserts the
//! difference directly: the injected process's PID namespace must match the
//! session program's and must *not* match the supervisor's.
//!
//! The container is built the way `sandbox2::new_container` builds one, minus
//! the network isolation — the proof is about process structure, and a netns
//! would drag the switch wiring in with it.
//!
//! `#[ignore]`, and additionally early-returns unless `MINIMALD_NSENTER_TEST` is
//! set, so neither a plain `cargo test` run nor the ignored-test sweep attempts
//! namespace work on a host that may not allow it. Needs unprivileged user
//! namespaces (no root, unlike the netns proofs), a kernel with
//! `CONFIG_PROC_CHILDREN`, and `setns` pidfd support (Linux 5.8+):
//! `MINIMALD_NSENTER_TEST=1 cargo test -p minimald --test nsenter_integration -- --include-ignored`
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use minimald::nsenter::{Injection, session_leader_pid};

/// Whether the gate env var is set; when absent the proofs early-return so the
/// default test run never unshares anything.
fn gated() -> bool {
    if std::env::var_os("MINIMALD_NSENTER_TEST").is_some() {
        return true;
    }
    eprintln!("skipping nsenter proof: MINIMALD_NSENTER_TEST not set");
    false
}

/// The `minimald` binary under test, which doubles as the namespace-joining
/// shim. Cargo builds and points at it for integration tests of this package.
fn shim() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_minimald"))
}

/// A sandbox holding a long-lived program, shaped like a session's.
///
/// `isolate_network` mirrors the choice `sandbox2::new_container` makes from the
/// session's network mode: a `HostNet` session stays in the daemon's network
/// namespace, a `NoNet`/`OwnIp` one gets its own.
fn sandbox(isolate_network: bool) -> hakoniwa::Child {
    let mut container = hakoniwa::Container::new();
    container
        .rootfs("/")
        .expect("bind-mounting the host rootfs")
        .devfsmount("/dev")
        .tmpfsmount("/tmp")
        .unshare(hakoniwa::Namespace::Cgroup)
        .unshare(hakoniwa::Namespace::Uts);
    if isolate_network {
        container.unshare(hakoniwa::Namespace::Network);
    }
    // No `Runctl::NewSession`: a real session claims the PTY as its controlling
    // terminal, and there is no TTY on this pipe to claim.

    let mut command = container.command("/bin/sleep");
    command
        .args(["60"])
        .stdout(hakoniwa::Stdio::piped())
        .stderr(hakoniwa::Stdio::piped());
    command.spawn().expect("spawning the sandboxed program")
}

fn ns_of(pid: u32, kind: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/{kind}"))
        .unwrap_or_else(|e| panic!("reading /proc/{pid}/ns/{kind}: {e}"))
        .to_string_lossy()
        .into_owned()
}

#[test]
#[ignore = "unshares namespaces; gated on MINIMALD_NSENTER_TEST"]
fn injected_process_joins_every_namespace() {
    if !gated() {
        return;
    }

    let mut sandboxed = sandbox(false);
    let supervisor = sandboxed.id();
    let leader = session_leader_pid(supervisor).expect("resolving the session program's pid");

    // Ask the injected process where it ended up, from inside. `/tmp` stands in
    // for a session's `/workbench`: this container has no session layout, but
    // it does have hakoniwa's tmpfs there, so the path exists only inside the
    // sandbox's mount namespace — which is the point.
    let output = Injection::new(
        leader,
        "/bin/sh",
        [
            "-c",
            "readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt; echo $$; pwd; echo \"$SESSION_MARKER\"",
        ],
    )
    .with_shim(shim())
    .with_cwd("/tmp")
    .with_env(BTreeMap::from([(
        "SESSION_MARKER".to_string(),
        "from-the-session".to_string(),
    )]))
    .command()
    .expect("building the injected command")
    .output()
    .expect("running the injected command");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let reported: Vec<&str> = stdout.lines().collect();

    let leader_pid_ns = ns_of(leader, "pid");
    let leader_mnt_ns = ns_of(leader, "mnt");
    let supervisor_pid_ns = ns_of(supervisor, "pid");
    let own_pid_ns = ns_of(std::process::id(), "pid");

    let _ = sandboxed.kill();
    let _ = sandboxed.wait();

    assert!(
        output.status.success(),
        "injected command failed: {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    let [pid_ns, mnt_ns, inner_pid, cwd, marker] = reported.as_slice() else {
        panic!("expected five lines from the injected process, got {reported:?} (stderr: {stderr})")
    };

    assert_eq!(
        *pid_ns, leader_pid_ns,
        "injected process is not in the session's PID namespace"
    );
    assert_eq!(
        *mnt_ns, leader_mnt_ns,
        "injected process is not in the session's mount namespace"
    );

    // The claim this whole module exists for: joining off the supervisor's PID
    // would have left the process in the host's PID namespace.
    assert_eq!(
        supervisor_pid_ns, own_pid_ns,
        "the container supervisor was expected to share our PID namespace"
    );
    assert_ne!(
        *pid_ns, supervisor_pid_ns,
        "the session's PID namespace must differ from the supervisor's"
    );

    // Neither of these rides along with the namespaces; both are set explicitly
    // by the injection and would otherwise be the container root and the
    // daemon's environment.
    assert_eq!(*cwd, "/tmp", "injected process did not start in `with_cwd`");
    assert_eq!(
        *marker, "from-the-session",
        "injected process did not get `with_env`"
    );

    // Being *in* the namespace is what makes the sandbox's /proc coherent: the
    // process sees a namespace-local PID, not its host one.
    let inner: u32 = inner_pid.parse().expect("the shell reported its pid");
    assert!(
        inner < 1024,
        "expected a namespace-local pid, got {inner} (looks like a host pid)"
    );
}

/// A network-isolated session is the case the joined set has to *widen* for.
/// The same code must also not widen for a `HostNet` session, where asking for
/// the network namespace would be an EPERM rather than a no-op — that half is
/// covered by `injected_process_joins_every_namespace`, whose sandbox shares
/// the daemon's network namespace.
#[test]
#[ignore = "unshares namespaces; gated on MINIMALD_NSENTER_TEST"]
fn injected_process_joins_an_isolated_network_namespace() {
    if !gated() {
        return;
    }

    let mut sandboxed = sandbox(true);
    let leader = session_leader_pid(sandboxed.id()).expect("resolving the session program's pid");

    let output = Injection::new(leader, "/bin/sh", ["-c", "readlink /proc/self/ns/net"])
        .with_shim(shim())
        .command()
        .expect("building the injected command")
        .output()
        .expect("running the injected command");

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let leader_net_ns = ns_of(leader, "net");
    let own_net_ns = ns_of(std::process::id(), "net");

    let _ = sandboxed.kill();
    let _ = sandboxed.wait();

    assert!(
        output.status.success(),
        "injected command failed: {:?}\nstderr: {stderr}",
        output.status
    );
    assert_eq!(
        stdout, leader_net_ns,
        "injected process is not in the session's network namespace"
    );
    assert_ne!(
        leader_net_ns, own_net_ns,
        "this sandbox was supposed to have its own network namespace"
    );
}

#[test]
#[ignore = "unshares namespaces; gated on MINIMALD_NSENTER_TEST"]
fn injected_exit_status_reaches_the_caller() {
    if !gated() {
        return;
    }

    let mut sandboxed = sandbox(false);
    let leader = session_leader_pid(sandboxed.id()).expect("resolving the session program's pid");

    let status = Injection::new(leader, "/bin/sh", ["-c", "exit 42"])
        .with_shim(shim())
        .command()
        .expect("building the injected command")
        .status()
        .expect("running the injected command");

    let _ = sandboxed.kill();
    let _ = sandboxed.wait();

    assert_eq!(
        status.code(),
        Some(42),
        "the shim must report the injected program's exit code, not its own"
    );
}

/// Whether `pid` exists and is not a reaped-but-unwaited zombie.
fn still_running(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // `state` is the field after the parenthesised comm, which can itself
    // contain spaces — split on the last ')' rather than by whitespace.
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest).unwrap_or("");
    !after_comm
        .split_whitespace()
        .next()
        .is_some_and(|s| s == "Z")
}

/// Killing the shim must take the process it injected with it.
///
/// The shim is the injected process's parent but sits outside the session's PID
/// namespace, so nothing about the namespaces makes the two die together. When
/// a client drops its exec channel the daemon kills the shim, and without this
/// the command it asked for keeps running in the session — holding the stdio
/// pipes nobody is reading any more — until the session itself ends.
#[test]
#[ignore = "unshares namespaces; gated on MINIMALD_NSENTER_TEST"]
fn killing_the_shim_kills_the_injected_process() {
    if !gated() {
        return;
    }

    let mut sandboxed = sandbox(false);
    let leader = session_leader_pid(sandboxed.id()).expect("resolving the session program's pid");

    let mut shim = Injection::new(leader, "/bin/sleep", ["120"])
        .with_shim(shim())
        .command()
        .expect("building the injected command")
        .spawn()
        .expect("spawning the injected command");

    // The shim's sole child is the injected process, the same way the container
    // supervisor's sole child is the session program.
    let injected = {
        let mut found = None;
        for _ in 0..100 {
            if let Ok(pid) = session_leader_pid(shim.id()) {
                found = Some(pid);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        found.expect("the shim should have spawned the injected process")
    };
    assert!(still_running(injected), "the injected process should be up");

    shim.kill().expect("killing the shim");
    shim.wait().expect("reaping the shim");

    // The kill is asynchronous on the injected side: the kernel delivers its
    // death signal once the shim is actually gone.
    let mut alive = true;
    for _ in 0..100 {
        if !still_running(injected) {
            alive = false;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let _ = sandboxed.kill();
    let _ = sandboxed.wait();
    assert!(
        !alive,
        "the injected process outlived the shim that was killed"
    );
}
