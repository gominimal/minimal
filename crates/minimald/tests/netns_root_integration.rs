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
//! * `injected_process_lacks_cap_net_raw` — a process injected into a box
//!   execs with the box's credentials: the box uid and gid, `no_new_privs`,
//!   and the same empty capability sets the box's own processes exec with,
//!   so joining a running box cannot open a raw socket either.
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
//! name them. The injected-process capability proof is the exception: it needs
//! no sudo, no gvproxy and no network namespace, only the unprivileged user
//! namespace every sandbox starts by unsharing, so it is gated on the host
//! allowing that instead — and skips, with the reason, on a host (stock Ubuntu
//! 24.04) that would deny it, rather than fail the lane that cannot run it.
//! The own-IP proofs read the gvproxy binary from `GVPROXY_BIN`,
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
//!
//! A failing run of that CI job reports an exit code and nothing else unless
//! the failing proof names itself: nextest captures what a test prints and
//! indents it four spaces in the step log, which hides `::error` workflow
//! commands from the Actions annotation parser, and the step log itself is
//! admin-only besides. So the first line of every proof past its gates is
//! `announce_to_the_runner`, which says the proof started and, on the panic
//! that fails it, posts proof, site and reason through the one stream that is
//! neither captured nor indented — reaching the parser as an annotation on
//! the check run that every reader of the pull request can see.
#![cfg(target_os = "linux")]

use sandbox2::NetPlan;
use sandbox2::Network as _;
use sandbox2::config::{BOX_FORBIDDEN_CAPABILITIES, BOX_GID, BOX_UID, Config, SandboxMapped};

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use minimald::net::switch::{SessionGate, attach_to_switch, open_tap, tap_netns_commands};
use minimald::net::{PtaskLease, SwitchClient, SwitchSubnet};
use sessions::SessionPolicy;

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

/// One line straight into the log stream nextest prints to. What a proof prints
/// itself never reaches the Actions annotation parser: nextest captures each
/// test's stdout and stderr and indents them four spaces in the step log, and
/// the parser only reads a command that starts a line. Nextest forks this proof
/// from its per-binary fork server, so `/proc/<ppid>/fd/1` is that server's own
/// stdout — the stream nextest prints to unindented, and the one the parser does
/// read. Best effort in every direction: away from the CI runner, or where the
/// path will not open, nothing is written and every proof behaves exactly as it
/// did without this.
fn tell_the_runner(line: &str) {
    if std::env::var("GITHUB_ACTIONS").ok().as_deref() != Some("true") {
        return;
    }
    // SAFETY: getppid() reads the calling process's parent pid; it has no side
    // effects and cannot fail.
    let ppid = unsafe { libc::getppid() };
    if let Ok(mut log) = std::fs::File::create(format!("/proc/{ppid}/fd/1")) {
        let _written = writeln!(log, "{line}");
    }
}

/// Announces `proof` on the CI runner, so a failing run of the lane names the
/// proof that failed. Two lines of insurance: a start line — a run that dies
/// without a panic (a hang, a proof the slow-timeout kills) still names the
/// last proof that began, to whoever reads the step log — and a panic hook,
/// installed once, that posts the proof's name, panic site and reason as an
/// `::error` workflow command the runner turns into an annotation on the check
/// run. The step log holds the full detail but is admin-only; the annotation is
/// the part every reader of the pull request can see. The hook chains the one
/// before it, so nextest still reports the failure exactly as it did.
fn announce_to_the_runner(proof: &str) {
    // Nextest runs each test in a process of its own, so a process-wide name
    // names this proof on whichever thread the panic comes from — the test
    // thread or a runtime worker the proof spawned onto.
    static RUNNING_PROOF: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    static HOOK: std::sync::Once = std::sync::Once::new();
    let _named = RUNNING_PROOF.set(proof.to_owned());
    HOOK.call_once(|| {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let proof = RUNNING_PROOF
                .get()
                .map(String::as_str)
                .unwrap_or("an unnamed proof");
            let payload = info.payload();
            let reason = if let Some(reason) = payload.downcast_ref::<&str>() {
                (*reason).to_string()
            } else if let Some(reason) = payload.downcast_ref::<String>() {
                reason.clone()
            } else {
                "a panic carrying no message".to_string()
            };
            let reason: String = reason
                .replace(['\r', '\n'], " ")
                .chars()
                .take(512)
                .collect();
            if let Some(location) = info.location() {
                tell_the_runner(&format!(
                    "::error file={},line={},title={proof}::netns proof failed: {reason}",
                    location.file(),
                    location.line(),
                ));
            } else {
                tell_the_runner(&format!(
                    "::error title={proof}::netns proof failed: {reason}"
                ));
            }
            previous_hook(info);
        }));
    });
    tell_the_runner(&format!("minimald netns proof started: {proof}"));
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
#include <netinet/in.h>
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

    /* The identity and capability sets the process exec'd with, then the one
     * capability-dependent operation: a raw socket, which NET-083 is about,
     * and a stream socket, which needs no capability and therefore still
     * works. One `key: value` line per fact, parsed by the caller. */
    if (argc > 1 && strcmp(argv[1], "caps") == 0) {
        FILE *status = fopen("/proc/self/status", "r");
        if (!status) { perror("fopen /proc/self/status"); return 30; }
        char line[256];
        while (fgets(line, sizeof line, status)) {
            if (strncmp(line, "Uid:", 4) == 0 || strncmp(line, "Gid:", 4) == 0 ||
                strncmp(line, "Cap", 3) == 0 || strncmp(line, "NoNewPrivs:", 11) == 0) {
                fputs(line, stdout);
            }
        }
        fclose(status);

        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        printf("raw_socket_errno: %d\n", fd >= 0 ? 0 : errno);
        if (fd >= 0) close(fd);

        fd = socket(AF_INET, SOCK_STREAM, 0);
        printf("stream_socket_errno: %d\n", fd >= 0 ? 0 : errno);
        if (fd >= 0) close(fd);
        fflush(stdout);
        return 0;
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
/// Panics when no C compiler is on `PATH` instead of skipping: every proof
/// that reaches this is on a host that promised to run it (the netns proofs by
/// setting `MINIMALD_NETNS_TEST`, the capability proof by allowing the
/// unprivileged user namespace its gate checks), and a skip here would be a
/// vacuous green on a security proof — the same shape the CI job's own
/// fail-fast netns check exists to prevent.
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
    announce_to_the_runner("network_none_blocks_all_outside_sockets");

    let rootfs_tmp =
        tempfile::tempdir_in(proof_base_dir()).expect("rootfs temp dir under the target tmp");
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
    // Build the sandbox under the target directory rather than the default
    // (`/home` here can be a read-only ext4 bind with locked nosuid, and
    // `/tmp` a `nosuid,nodev` tmpfs; both break the unprivileged remounts
    // hakoniwa does inside the user namespace — see `proof_base_dir`).
    let tmp =
        tempfile::tempdir_in(proof_base_dir()).expect("sandbox temp dir under the target tmp");
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
    announce_to_the_runner("network_none_attach_works");
    use minimald::nsenter::{Injection, session_leader_pid};
    use minimald::session_host::{Pty, WinSize};
    use std::io::{BufRead as _, Read as _};

    /// What the session host would set: the shell that is actually running.
    const PROBE_SHELL: &str = "/usr/bin/probe";

    let rootfs_tmp =
        tempfile::tempdir_in(proof_base_dir()).expect("rootfs temp dir under the target tmp");
    let probe = compile_socket_probe(rootfs_tmp.path());
    let source = rootfs_tmp.path().join("rootfs-src");
    probe_rootfs(&source, &probe);

    let config = Config::new("none-attach")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(NetPlan::none());
    let tmp =
        tempfile::tempdir_in(proof_base_dir()).expect("sandbox temp dir under the target tmp");
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
    // Both report streams are the proof's own pipes, not its inherited ones:
    // the hold program is the supervisor's child, so it can outlive the
    // supervisor when its parent-death signal does not land, and a process
    // holding the test's streams past the proof's exit is what the lane's
    // leak window fails with no message of the proof's own.
    hold.stdout(hakoniwa::Stdio::MakePipe);
    hold.stderr(hakoniwa::Stdio::MakePipe);
    let mut child = hold.spawn().expect("spawning hold process in none box");

    let hold_stdout = child.stdout.take().expect("hold process stdout pipe");
    let mut hold_stderr = child.stderr.take().expect("hold process stderr pipe");
    let mut guard = LiveBox::new(child);
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
        let end = guard.stop();
        let mut stderr = Vec::new();
        let _drained = hold_stderr.read_to_end(&mut stderr);
        panic!(
            "the none-box launch lost the command's cwd or SHELL across the \
             seccomp closure swap: expected {expected_report:?}, got \
             {hold_report:?}; the hold process exited with {end:?}\nstderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    let leader =
        session_leader_pid(guard.child_id()).expect("resolving the none box's session leader pid");
    guard.holds(leader);

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

    // Stop the box the way the capability proof does — the supervisor first,
    // then the program it holds — so the proof returns having left no process
    // of the box's behind.
    let _stopped = guard.stop();

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

/// Where the proofs that build a box build it: the cargo target directory,
/// never `/tmp`.
///
/// `/tmp` works on the CI lane's runners, but a host whose `/tmp` is a
/// `nosuid,nodev` tmpfs cannot host a box at all: a bind remount inside a user
/// namespace may only repeat flags the underlying mount already has, and
/// hakoniwa's read-only remount asks for `MS_RDONLY|MS_NOSUID` without
/// `nodev`, so a bind whose source carries a locked `nodev` is refused. The
/// capability proof is gated on the user namespace alone, so it has to run on
/// such hosts; the none-box proofs go through the same place so a host that
/// can run one can run all of them. The target directory sits on the
/// checkout's own filesystem, which carries no such lock, and is ignored by
/// git like everything under `target/`.
fn proof_base_dir() -> PathBuf {
    // The target directory this build uses; cargo points test targets at its
    // own tmp through CARGO_TARGET_DIR, and a checkout that lets cargo
    // default has one at its root.
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(|dir| PathBuf::from(dir).join("tmp"))
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp"));
    std::fs::create_dir_all(&target).expect("creating the target tmp dir");
    target
}

/// The credential state a process must exec with, read from the probe's
/// report: the box uid and gid in every id field, `no_new_privs` set, every
/// capability set exec clears empty, and the bounding set — the one set an
/// exec does not clear — holding none of the capabilities no box may hold.
fn assert_box_credentials(report: &BTreeMap<String, String>, what: &str) {
    // The box uid and gid in every id field the status file reports (real,
    // effective, saved, fs): a box process is never root inside its own user
    // namespace, which is what makes exec clear the capability sets at all.
    for (key, expected) in [("Uid", BOX_UID), ("Gid", BOX_GID)] {
        let value = reported(report, key, what);
        let fields: Vec<&str> = value.split_ascii_whitespace().collect();
        assert_eq!(
            fields.len(),
            4,
            "{what}: {key} must carry the real, effective, saved and fs ids: {value}"
        );
        for field in &fields {
            let not_a_number = format!("{what}: {key} field {field} is not a number");
            let id: u32 = field.parse().expect(&not_a_number);
            assert_eq!(
                id, expected,
                "{what}: the process must exec as the box uid/gid {expected} in every \
                 {key} field: {value}"
            );
        }
    }

    assert_eq!(
        reported(report, "NoNewPrivs", what),
        "1",
        "{what}: the no_new_privs bit must be set, so no file capability or \
         setuid bit can restore a privilege"
    );

    // The sets exec clears: empty by construction, whatever the credentials
    // the joining process arrived with.
    for set in ["CapPrm", "CapEff", "CapInh", "CapAmb"] {
        let mask = capability_mask(report, set, what);
        assert_eq!(
            mask, 0,
            "{what}: {set} must be empty — the process execs as the \
             unprivileged box uid with no_new_privs set, so exec clears it"
        );
    }

    // The bounding set, the one set exec does not clear: it must hold none of
    // the capabilities no box may hold. A capability left in it is one a file
    // capability in the box could hand back.
    let mask = capability_mask(report, "CapBnd", what);
    for cap in BOX_FORBIDDEN_CAPABILITIES {
        assert_eq!(
            mask & (1 << cap.number),
            0,
            "{what}: CapBnd must not hold {} (bit {}): the bounding set \
             survives exec, so a capability left in it is one a file \
             capability in the box could restore",
            cap.name,
            cap.number
        );
    }
}

/// The probe's report: one entry per `key: value` line it printed.
fn parse_report(stdout: &str) -> BTreeMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// The probe's report line for `key`, or a panic naming what never arrived: a
/// report that does not show up is the failure to show, not a mystery, so the
/// panic carries the report that did arrive, whatever shape it is in.
fn reported<'a>(report: &'a BTreeMap<String, String>, key: &str, what: &str) -> &'a str {
    let never_arrived = format!("{what}: the probe did not report {key}: {report:?}");
    report.get(key).expect(&never_arrived)
}

/// The errno the probe reported for `key`, e.g. `raw_socket_errno`.
fn reported_errno(report: &BTreeMap<String, String>, key: &str, what: &str) -> i32 {
    let not_a_number = format!("{what}: {key} is not a number");
    reported(report, key, what).parse().expect(&not_a_number)
}

/// One capability-set mask from the probe's report, e.g. `CapBnd:
/// 000001ffffffffff`.
fn capability_mask(report: &BTreeMap<String, String>, set: &str, what: &str) -> u64 {
    let value = reported(report, set, what);
    let no_mask = format!("{what}: {set} must carry one hex mask: {value}");
    let mask = value.split_ascii_whitespace().next().expect(&no_mask);
    let not_a_mask = format!("{what}: {set} is not a hex mask: {mask}");
    u64::from_str_radix(mask, 16).expect(&not_a_mask)
}

/// A box a proof holds up for an injection, stopped on every exit path.
///
/// hakoniwa's supervisor is the proof's own child and the program it holds
/// dies from the supervisor's `PDEATHSIG`, so a proof that fails between
/// spawning the box and its own cleanup — a launch that never reports, an
/// injection that does not answer — leaves a live box behind in the proof's
/// process group, and the runner reports the process it found still running
/// instead of the assertion that actually failed. `LiveBox` stops the box on
/// drop as well as on request, so every exit path ends with the box gone:
/// SIGKILL reaches the supervisor, `wait` reaps it, and the program — not the
/// proof's child, so nothing else reaps it — is given a moment to take its
/// `PDEATHSIG` before the proof returns.
struct LiveBox {
    child: hakoniwa::Child,
    /// The program the injection targets, once the box has reported; only
    /// then can stopping the box wait for the program to be gone.
    leader: Option<i32>,
}

impl LiveBox {
    fn new(child: hakoniwa::Child) -> Self {
        Self {
            child,
            leader: None,
        }
    }

    /// Records the pid the injection is aimed at, so `stop` can tell the
    /// program is gone rather than merely the supervisor that ran it. Held as
    /// the `i32` `libc::kill` takes: a Linux pid always fits one.
    fn holds(&mut self, leader: u32) {
        self.leader = Some(i32::try_from(leader).expect("the program pid fits an i32"));
    }

    /// The supervisor's pid, which the session leader is looked up from.
    fn child_id(&self) -> u32 {
        self.child.id()
    }

    /// Stops the box and waits out what it held. Safe to call twice: hakoniwa
    /// ignores `kill` on an already-reaped child and `wait` returns the status
    /// it collected, so the drop after an explicit stop is a no-op.
    fn stop(&mut self) -> hakoniwa::Result<hakoniwa::ExitStatus> {
        let _signalled = self.child.kill();
        let status = self.child.wait()?;
        if let Some(leader) = self.leader {
            let program = format!("/proc/{leader}");
            // The program is the supervisor's child, not this proof's, so it
            // dies from the supervisor's PDEATHSIG and nothing here reaps it.
            // Signal it directly as well: a host where that death signal did
            // not survive the launch must not be able to leave the proof a
            // live process, which is the one failure the lane reports with no
            // message of the proof's own.
            // SAFETY: `kill` is an async-signal-safe syscall taking a pid this
            // proof created and a valid signal; it reports ESRCH when the
            // program is already gone, which is the state being asked for, so
            // the return value carries nothing to act on.
            let _already_gone = unsafe { libc::kill(leader, libc::SIGKILL) };
            // The signal has usually landed before the loop is reached; the
            // loop exists so a scheduling hiccup cannot turn a passing proof
            // into a live process left behind.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while Path::new(&program).exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if Path::new(&program).exists() {
                eprintln!("warning: program {leader} outlived the box that ran it");
            }
        }
        Ok(status)
    }
}

impl Drop for LiveBox {
    fn drop(&mut self) {
        // Best effort: a stop that fails is reported by whatever failure made
        // the proof drop the box mid-flight.
        let _stopped = self.stop();
    }
}

/// NET-083, the injected-process half: a process a client attaches into a
/// running box — the `nsenter` shim, joined to the box's namespaces — execs
/// with the box's credentials, so joining a box is not a way around the
/// posture every box process already execs with.
///
/// The box is an *open* one (a host plan, no socket-family filter), so the
/// only thing that can refuse the injected process a raw socket is the missing
/// capability: the refusal this proof pins is the one NET-083 is about. The
/// hold process keeps the box alive for the injection and reports first,
/// which is also how the proof tells a launch that never reached the program
/// (exit 125 in hakoniwa's mount setup, no report) from one that did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_process_lacks_cap_net_raw() {
    if let Some(reason) = sandbox2::user_namespaces_restriction() {
        eprintln!(
            "skipping injected_process_lacks_cap_net_raw: this host denies the \
             unprivileged user namespace every sandbox starts by unsharing: \
             {reason}"
        );
        return;
    }
    announce_to_the_runner("injected_process_lacks_cap_net_raw");
    use minimald::nsenter::{Injection, session_leader_pid};
    use std::io::{BufRead as _, Read as _};

    let proofs = proof_base_dir();
    let no_base_dir = format!("base temp dir under {}", proofs.display());
    let base = tempfile::tempdir_in(&proofs).expect(&no_base_dir);
    let probe = compile_socket_probe(base.path());
    let source = base.path().join("rootfs-src");
    probe_rootfs(&source, &probe);

    let config = Config::new("caps-inject")
        .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
        .with_dns(false)
        .with_plan(NetPlan::host());
    let no_sandbox_dir = format!("sandbox temp dir under {}", proofs.display());
    let sandbox_base = tempfile::tempdir_in(&proofs).expect(&no_sandbox_dir);
    let mut sandbox = config
        .build(sandbox_base.path().join("sandbox"), ())
        .await
        .expect("building the open-box sandbox");
    let plan = sandbox.built_in_plan();
    let container = sandbox
        .new_container(&plan)
        .expect("building the open-box container");

    let mut hold = sandbox
        .command(
            &container,
            "/usr/bin/probe",
            ["hold"],
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("building hold command");
    hold.stdout(hakoniwa::Stdio::MakePipe);
    hold.stderr(hakoniwa::Stdio::MakePipe);
    let mut child = hold.spawn().expect("spawning hold process in open box");

    // The hold report is what proves the launch reached the program the
    // injection is aimed at; a host that cannot build the box exits 125 in
    // hakoniwa's mount setup, before any report.
    let hold_stdout = child.stdout.take().expect("hold process stdout pipe");
    // The box's launch path — hakoniwa's setup, the program it execs — says
    // on stderr what went wrong when it goes wrong, so the proof takes the
    // stream to say it in its own failure instead of leaving it in the log's
    // margin.
    let mut hold_stderr = child.stderr.take().expect("hold process stderr pipe");
    let mut guard = LiveBox::new(child);
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
    if !hold_report
        .first()
        .is_some_and(|line| line.starts_with("cwd="))
    {
        // Stop the box before saying why, so the failure names how the launch
        // ended and what the box printed, not only the absence of a report.
        let end = guard.stop();
        let mut stderr = Vec::new();
        let _drained = hold_stderr.read_to_end(&mut stderr);
        panic!(
            "the hold process did not report: {hold_report:?}\nstatus: {end:?}\nstderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    let leader =
        session_leader_pid(guard.child_id()).expect("resolving the open box's program pid");
    guard.holds(leader);

    let injection = Injection::new(leader, "/usr/bin/probe", ["caps"])
        .with_shim(shim())
        .with_cwd(sandbox.command_cwd().expect("resolving sandbox cwd"))
        .with_env(sandbox.command_env());
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            injection
                .command()
                .expect("building injection command")
                .output()
                .expect("running injected capability probe")
        }),
    )
    .await
    .expect("injected capability probe timed out")
    .expect("spawn_blocking join");

    // Stop the box the proof no longer needs: SIGKILL to the supervisor —
    // which the program dies from — then the reap. The wait after the signal
    // cannot hang, the supervisor being the proof's own child, and it hands
    // the program the moment it needs to be gone before the proof returns;
    // the rest of the proof asserts over output already collected.
    let _stopped = guard.stop();

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "capability probe injected into an open box failed: status={:?}\nstderr={stderr}",
        output.status.code(),
    );
    let report = parse_report(&String::from_utf8_lossy(&output.stdout));
    assert_box_credentials(&report, "the injected process");

    // The capability-dependent operation itself. An open box's network is the
    // host's and carries no family filter, so a raw socket refused with
    // anything but EPERM is a capability that survived the join.
    let raw = reported_errno(&report, "raw_socket_errno", "the injected process");
    assert_eq!(
        raw,
        libc::EPERM,
        "the injected process's raw socket attempt must be refused for lack \
         of the capability, not by a filter or a missing network"
    );
    let stream = reported_errno(&report, "stream_socket_errno", "the injected process");
    assert_eq!(
        stream, 0,
        "the injected process must still be able to open an ordinary socket: \
         the box's posture denies capabilities, not networking"
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
    announce_to_the_runner("netns_nonet_refuses_egress");

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
/// Both relays are gated by their box's policy the way a session's own attach is
/// (A declares no egress — allow-all, the shipped default; B declares the
/// listener's port inbound), so the connection also proves the egress verdict
/// admits a declared peer and the inbound gate admits a declared port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs netns + gvproxy; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn netns_ownip_ptask_to_ptask() {
    if !gated() {
        return;
    }
    announce_to_the_runner("netns_ownip_ptask_to_ptask");
    use sessions::{IngressPolicy, IpProto, PortMapping};

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

    // PTask A declares nothing — allow-all egress (the shipped default), no
    // inbound listeners. PTask B declares the port its listener sits on inbound,
    // which is what the inbound gate needs to admit A's connection.
    const PORT: u16 = 9009;
    let mut a = Ptask::provision("peer-a", lease_a, subnet, &sock, &SessionPolicy::default()).await;
    let b_policy = SessionPolicy {
        ingress: Some(IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: PORT,
                internal_port: PORT,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        }),
        egress: None,
    };
    let mut b = Ptask::provision("peer-b", lease_b, subnet, &sock, &b_policy).await;

    // PTask B listens on its switch address; PTask A connects to it. The traffic
    // crosses the gvproxy L2 switch entirely in userspace.
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
    announce_to_the_runner("netns_ingress_static_port_mapping_exposes_then_unexposes");
    use minimald::net::policy::{ControlChannel, apply_ingress, remove_ingress};
    use sessions::{IngressPolicy, IpProto, PortMapping};

    const INTERNAL: u16 = 80;
    const EXTERNAL: u16 = 18080;

    let state = tempfile::tempdir().expect("switch state dir");
    let mut switch = SwitchClient::new(gvproxy_bin(), state.path());
    let subnet = SwitchSubnet::default();

    let minimald::net::AttachResult { lease, .. } = switch.attach().await.expect("attach PTask");
    let sock = switch.control_socket();

    // The relay is gated the way a session's own attach is, and the forward
    // targets the PTask's `INTERNAL` listener — so the inbound gate must see
    // that port declared or the proof's own gate would drop the connection it
    // exists to expose.
    let gate_policy = SessionPolicy {
        ingress: Some(IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: EXTERNAL,
                internal_port: INTERNAL,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        }),
        egress: None,
    };
    let mut ptask = Ptask::provision("ingress", lease, subnet, &sock, &gate_policy).await;

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
    /// Provisions the PTask and attaches its tap to the switch through a relay
    /// gated by `policy` — the same gating a session's own attach applies
    /// (egress verdict on the outbound leg, inbound default-block on the
    /// other), so the proofs exercise the enforcement the production path
    /// ships rather than the daemon's own ungated relay.
    async fn provision(
        name: &str,
        lease: PtaskLease,
        subnet: SwitchSubnet,
        api_sock: &std::path::Path,
        policy: &SessionPolicy,
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

        let gate = SessionGate::for_session(lease.ip.to_string(), lease.ip, policy, subnet);
        let relay = attach_to_switch(fd, api_sock, Some(gate), lease.ip, subnet)
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
