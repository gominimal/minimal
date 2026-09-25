//! Named VMs (NET-052..NET-056): a VM named with `--vm` gets its own state
//! directory, socket, and daemon under a per-name subdirectory of the provider
//! directory, the default VM's paths are unchanged, stopping one VM leaves the
//! other running, and reaping is scoped to this checkout's VMs.
//!
//! These tests run on hosts with or without libkrun — every lane. A VM's
//! *identity* is host-side state `minvmd` resolves before the hypervisor is ever
//! reached, so the tests drive the real binary and the real lock/state
//! machinery rather than a booted VM. Where a live "daemon" is needed it is a
//! real child process holding the VM's alive lock and named as `vmm_pid` in the
//! VM's state file — exactly what `run`/`boot` leave behind for every
//! host-side observer (`status`, `stop`, the CLI's probes).
//!
//! Being a `*_integration.rs` harness, the VM lanes replay it from a nextest
//! archive on a machine that did not build it (`--workspace-remap`, see
//! ci-macos.yml/ci-linux-kvm.yml), so no path baked at build time exists
//! there: the binary comes from [`minvmd_bin`]'s `MINVMD_BIN`, and the reap
//! script travels inside the harness ([`REAP_SCRIPT`]).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use minvmd::lifecycle::Lifecycle;
use minvmd::state::{State, StateDir};
use paths::{DaemonAbsPath, ProviderKind, SSH_SOCK_FILE};

/// The `minvmd` binary under test: `MINVMD_BIN` when set — the VM lanes' split
/// build/test runners, where the absolute path baked by `CARGO_BIN_EXE_minvmd`
/// does not exist — else the compile-time cargo-built path (the same contract
/// every other `*_integration` harness follows).
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// The `scripts/reap-vms.sh` under test, embedded at compile time: the VM lanes
/// replay this harness from an archive on a machine whose checkout is not at
/// this build's paths, and the script is what `reap_scoped_per_checkout`
/// exercises.
const REAP_SCRIPT: &str = include_str!("../../../scripts/reap-vms.sh");

/// Run the `minvmd` binary under test ([`minvmd_bin`]) against a
/// `--minimal-state-dir` base. `RUST_LOG` is dropped so the default `info`
/// filter applies and these tests observe the info lines every install gets.
fn run_minvmd(base: &Path, args: &[&str]) -> BinRun {
    let out = Command::new(minvmd_bin())
        .arg("--minimal-state-dir")
        .arg(base)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawning minvmd");
    BinRun {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// One `minvmd` invocation: its exit status and both output streams. In the
/// foreground, tracing writes to stdout and errors to stderr — a single
/// assertion often spans both, so [`BinRun::output`] joins them.
struct BinRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl BinRun {
    fn output(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// The state directory a VM named `vm` owns under `base` (NET-054): the
/// per-name subdirectory of the provider dir for a named VM, the provider dir
/// itself for the default VM.
fn provider_dir(base: &Path, vm: &str) -> PathBuf {
    let base = DaemonAbsPath::try_new(base.to_str().expect("tempdir path is UTF-8"))
        .expect("tempdir path is absolute");
    minvmd::state::provider_dir_for(&base, vm)
}

/// The provider instance dir under `base`, by the pre-named-VMs spelling.
fn provider_instance_dir(base: &Path) -> PathBuf {
    let base = DaemonAbsPath::try_new(base.to_str().expect("tempdir path is UTF-8"))
        .expect("tempdir path is absolute");
    paths::provider_instance_dir(&base, ProviderKind::Minvmd, 0)
        .as_utf8_path()
        .as_std_path()
        .to_path_buf()
}

/// The host-side half of a live VM: a `Running` state file whose `vmm_pid` is
/// a real process, and that process holding the VM's alive lock alone — the
/// shape of a running daemon every host-side observer sees. Dropping it makes
/// the holder die (but never signals a pid that has already been reaped and
/// may have been recycled).
struct LiveVm {
    state_dir: StateDir,
    pid: libc::pid_t,
    reaped: Arc<AtomicBool>,
}

fn live_vm(base: &Path, vm: &str) -> LiveVm {
    let state_dir = StateDir::new(provider_dir(base, vm)).expect("opening the VM's state dir");
    let lock = state_dir
        .try_acquire_alive_lock()
        .expect("probing the alive lock")
        .expect("a fresh VM's alive lock is free");

    let mut cmd = Command::new("sleep");
    cmd.arg("300");
    lock.inherit_into(&mut cmd);
    let mut child = cmd.spawn().expect("spawning the lock-holding child");
    // The holder alone keeps the lock: this process's fd closes, so the VM's
    // daemon is exactly the child — when `stop` kills it, the alive lock reads
    // released, as it does when a real supervisor dies.
    drop(lock);

    state_dir
        .write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(child.id()),
            started_at: Some(0),
            ..State::stopped()
        })
        .expect("writing Running state");

    // Reap the holder from a side thread the moment anything kills it: `stop`
    // polls liveness with kill(pid, 0), and a zombie still answers that, so an
    // unreaped holder would ride out stop's whole 5 s SIGTERM window.
    let pid = libc::pid_t::try_from(child.id()).expect("pid fits pid_t");
    let reaped = Arc::new(AtomicBool::new(false));
    {
        let reaped = Arc::clone(&reaped);
        std::thread::spawn(move || {
            let _ = child.wait();
            reaped.store(true, Ordering::Release);
        });
    }

    LiveVm {
        state_dir,
        pid,
        reaped,
    }
}

impl LiveVm {
    /// The VM's state directory.
    fn dir(&self) -> &Path {
        self.state_dir.dir()
    }
}

impl Drop for LiveVm {
    fn drop(&mut self) {
        if self.reaped.load(Ordering::Acquire) {
            return; // already dead and reaped; the pid may have been recycled
        }
        // SAFETY: kill(2) to this process's own child, which is still the pid
        // the state file names.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }
}

// ── NET-052 ───────────────────────────────────────────────────────────────────

#[test]
fn named_vm_has_own_state_socket_daemon() {
    let base = tempfile::tempdir().unwrap();
    let alpha = provider_dir(base.path(), "alpha");
    let default = provider_dir(base.path(), paths::DEFAULT_VM_NAME);

    // The daemon resolves the named VM's own state directory: `status` acts
    // on it (creating it; a never-booted VM reports "stopped", exit 1), and it
    // alone — the default VM's directory is not disturbed.
    let status = run_minvmd(base.path(), &["--vm", "alpha", "status"]);
    assert_eq!(
        status.status.code(),
        Some(1),
        "a never-booted VM is not running: {}",
        status.output()
    );
    assert!(
        alpha.is_dir(),
        "the named VM must own its own state directory"
    );
    // The default VM's *files* are untouched: its state directory is the
    // provider dir the named VM nests under, so the directory exists as a
    // parent, but nothing of the default VM's own was written.
    assert!(
        !default.join("minvmd.toml").exists(),
        "acting on a named VM must not write the default VM's state"
    );

    // Its own socket: the bridge socket the named VM's daemon serves lives in
    // its own state directory, not the default VM's.
    assert_ne!(
        alpha.join(SSH_SOCK_FILE),
        default.join(SSH_SOCK_FILE),
        "a named VM's socket must not collide with the default VM's"
    );

    // Its own daemon: two VMs can each have a live daemon at once. The alive
    // lock is the single mutual-exclusion primitive, so with one shared state
    // directory two daemons cannot coexist — holding both is the named VM's
    // daemon being its own.
    let _alpha_vm = live_vm(base.path(), "alpha");
    let _default_vm = live_vm(base.path(), paths::DEFAULT_VM_NAME);
    assert!(
        _alpha_vm.state_dir.daemon_alive().unwrap(),
        "alpha's daemon must be alive"
    );
    assert!(
        _default_vm.state_dir.daemon_alive().unwrap(),
        "the default VM's daemon must be alive at the same time"
    );
    // While the exclusion itself still holds per VM: a second daemon for the
    // *same* VM cannot start.
    assert!(
        _alpha_vm
            .state_dir
            .try_acquire_alive_lock()
            .unwrap()
            .is_none(),
        "a second daemon for one VM must still be excluded"
    );

    // One info line per VM start names the VM and its state directory
    // (observability): the line is logged before the hypervisor is reached, so
    // it appears on this libkrun-less host too (where the start then reports
    // it cannot boot).
    let start = run_minvmd(base.path(), &["--vm", "alpha", "run"]);
    assert!(
        start.output().contains("starting VM"),
        "a VM start must be logged: {}",
        start.output()
    );
    assert!(
        start.output().contains("vm=alpha")
            && start.output().contains(&alpha.display().to_string()),
        "the start line must name the VM and its state directory: {}",
        start.output()
    );
}

// ── NET-053 ───────────────────────────────────────────────────────────────────

#[test]
fn default_vm_paths_unchanged() {
    let base = tempfile::tempdir().unwrap();
    let state =
        DaemonAbsPath::try_new(base.path().to_str().unwrap()).expect("tempdir path is absolute");
    let default = minvmd::state::provider_dir_for(&state, paths::DEFAULT_VM_NAME);

    // The default VM's directory is the provider instance dir itself, named or
    // not — the pre-named-VMs resolution, byte for byte.
    assert_eq!(
        default,
        paths::provider_instance_dir(&state, ProviderKind::Minvmd, 0)
            .as_utf8_path()
            .as_std_path()
    );
    assert_eq!(minvmd::state::provider_dir_for(&state, "default"), default);

    // Every runtime file keeps its name and place directly in the provider
    // dir — none moved into a per-name subdirectory:
    let sd = StateDir::open_existing(default.clone());
    let files = [
        sd.state_path(),
        sd.lock_path(),
        sd.alive_lock_path(),
        sd.dir().join(paths::MINIMALD_LOCK_FILE),
        sd.dir().join(SSH_SOCK_FILE),
        sd.dir().join(paths::KNOWN_HOSTS_FILE),
        sd.dir().join("config.toml"),
        sd.dir().join("data-vol.raw"),
        sd.dir().join("boot.log"),
        sd.dir().join("run.log"),
    ];
    for file in &files {
        assert_eq!(
            file.parent().unwrap(),
            default,
            "the default VM's {} must stay in the provider dir",
            file.display()
        );
    }

    // And the binary agrees: with no `--vm` and with `--vm default`, the state
    // directory it creates is the provider dir, never a `default/` subdir.
    run_minvmd(base.path(), &["status"]);
    assert!(default.is_dir());
    assert!(
        !default.join("default").exists(),
        "`--vm default` must not create a per-name subdirectory"
    );
    run_minvmd(base.path(), &["--vm", "default", "status"]);
    assert!(
        !default.join("default").exists(),
        "the default VM's layout must not change when it is named"
    );
}

// ── NET-054 ───────────────────────────────────────────────────────────────────

#[test]
fn named_vm_under_per_name_subdirectory() {
    let base = tempfile::tempdir().unwrap();

    // A named VM's state sits in a per-name subdirectory of the provider
    // directory.
    assert_eq!(
        provider_dir(base.path(), "alpha"),
        provider_instance_dir(base.path()).join("alpha")
    );

    // The binary places it there: `--vm alpha` provisions exactly that
    // subdirectory, and nothing at the provider dir's own level.
    run_minvmd(base.path(), &["--vm", "alpha", "status"]);
    let alpha = provider_instance_dir(base.path()).join("alpha");
    assert!(
        alpha.is_dir(),
        "the named VM's state must live in {alpha:?}"
    );
    assert!(
        !provider_instance_dir(base.path())
            .join("minvmd.toml")
            .exists(),
        "the named VM must not act on the provider dir itself"
    );

    // A name outside the allowlist never resolves anywhere: each of these
    // would otherwise reach outside the provider dir, or shadow the provider
    // dir's own entries (`guest`). In a fresh state dir, a rejected name
    // creates nothing at all.
    let fresh = tempfile::tempdir().unwrap();
    let over_long = "a".repeat(25);
    for bad in [
        "a/b",
        "..",
        ".",
        "a b",
        "Alpha",
        "guest",
        over_long.as_str(),
    ] {
        let rejected = run_minvmd(fresh.path(), &["--vm", bad, "status"]);
        assert_ne!(
            rejected.status.code(),
            Some(0),
            "`--vm {bad}` must be rejected"
        );
        assert!(
            rejected.stderr.contains("invalid VM name"),
            "the rejection must name the problem: {}",
            rejected.output()
        );
    }
    // A leading `-` is refused by the allowlist too. Clap reads a separate
    // `--vm <name>` token starting with `-` as flags, so the value form is
    // the one that reaches the validator.
    let rejected = run_minvmd(fresh.path(), &["--vm=-alpha", "status"]);
    assert_ne!(
        rejected.status.code(),
        Some(0),
        "`--vm -alpha` must be rejected"
    );
    assert!(
        rejected.stderr.contains("invalid VM name"),
        "the rejection must name the problem: {}",
        rejected.output()
    );
    assert!(
        !fresh.path().join("providers").exists(),
        "a rejected name must not create any directory"
    );
}

// ── NET-055 ───────────────────────────────────────────────────────────────────

#[test]
fn stop_one_vm_leaves_other_running() {
    let base = tempfile::tempdir().unwrap();
    let _alpha = live_vm(base.path(), "alpha");
    let _default = live_vm(base.path(), paths::DEFAULT_VM_NAME);

    // Stop the named VM only.
    let stop = run_minvmd(base.path(), &["--vm", "alpha", "stop"]);
    assert!(
        stop.status.success(),
        "stopping the named VM must succeed: {}",
        stop.output()
    );

    // The one-per-stop line (NET-055) belongs to the witness that observes
    // the VM die — the `run` supervisor, or a foreground `boot` — so a real
    // stop's line lands in that witness's log, never on the CLI's stdout.
    // This libkrun-less harness cannot run a supervisor, so what it pins
    // here is the CLI-side invariant that keeps the line one-per-stop: the
    // CLI never emits it itself, so a supervised stop is not logged twice.
    assert!(
        !stop.output().contains("stopping VM"),
        "the stop CLI must not log the one-per-stop line; the supervisor \
         watching the VMM child exit is its only witness: {}",
        stop.output()
    );

    // And a stop that stops nothing logs no stop line either: "stopping VM"
    // for a VM that is already down would be a stop that never happened.
    let noop = run_minvmd(base.path(), &["--vm", "beta", "stop"]);
    assert!(
        noop.status.success(),
        "stopping a never-booted VM must succeed: {}",
        noop.output()
    );
    assert!(
        noop.output().contains("minvmd is not running"),
        "the no-op branch is the one under test: {}",
        noop.output()
    );
    assert!(
        !noop.output().contains("stopping VM"),
        "a no-op stop must not log a stop line: {}",
        noop.output()
    );

    // The stop dialed *alpha's* socket, the named VM's own: the best-effort
    // guest RPC fails by naming the bridge socket it tried.
    assert!(
        stop.output().contains("connect to minimald at"),
        "the guest shutdown attempt must name the socket it dialed: {}",
        stop.output()
    );
    assert!(
        stop.output()
            .contains(&_alpha.dir().join(SSH_SOCK_FILE).display().to_string()),
        "stopping alpha must dial alpha's socket, not another VM's: {}",
        stop.output()
    );

    // The named VM is stopped: its state file says so and its daemon is gone.
    assert_eq!(
        _alpha.state_dir.read_state().unwrap().lifecycle,
        Lifecycle::Stopped,
        "the stopped VM's state must be reset"
    );
    assert!(
        !_alpha.state_dir.daemon_alive().unwrap(),
        "the stopped VM's daemon must be down"
    );

    // Every other VM is untouched: still running, still holding its daemon.
    assert_eq!(
        _default.state_dir.read_state().unwrap().lifecycle,
        Lifecycle::Running,
        "stopping one VM must leave the other VM's state alone"
    );
    assert!(
        _default.state_dir.daemon_alive().unwrap(),
        "the other VM's daemon must keep running"
    );
}

// ── NET-056 ───────────────────────────────────────────────────────────────────

#[test]
fn reap_scoped_per_checkout() {
    let tmp = tempfile::tempdir().unwrap();

    // A stand-in checkout: its own copy of the reap script, so the ROOT the
    // script derives is this directory and the recorded patterns prove the
    // scoping rather than asserting on the real checkout's path. Written from
    // the embedded copy because the VM lanes replay this harness on a machine
    // where no path baked at build time exists.
    let checkout = tmp.path().join("a-checkout");
    std::fs::create_dir_all(checkout.join("scripts")).unwrap();
    let script = checkout.join("scripts/reap-vms.sh");
    std::fs::write(&script, REAP_SCRIPT).unwrap();
    set_executable(&script);

    // Stub `pkill` and `sudo` on a PATH in front of the real coreutils: they
    // record the patterns they were asked to match and never signal anything,
    // so the real pkill is unreachable from this test.
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = tmp.path().join("pkill.log");
    let stub = |name: &str, recorded: &str| {
        let path = bin.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"{recorded} $*\" >> \"$PKILL_LOG\"\nexit 0\n"
            ),
        )
        .unwrap();
        set_executable(&path);
    };
    stub("pkill", "pkill");
    stub("sudo", "sudo");

    let run_reap = |args: &[&str]| {
        Command::new("bash")
            .arg(checkout.join("scripts/reap-vms.sh"))
            .args(args)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("PKILL_LOG", &log)
            .output()
            .expect("running the reap script")
    };
    let recorded = || std::fs::read_to_string(&log).unwrap_or_default();
    let root = checkout.display().to_string();

    // Bare invocation: every VM this checkout spawned is in reach — the
    // default VM's and any named VM's, whose cmdlines carry only an appended
    // `--vm <name>` — and every pattern is pinned to this checkout's path, so
    // a parallel checkout's VMs (or the system's gvproxy) are not.
    let out = run_reap(&[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = recorded();
    assert_eq!(
        lines.lines().count(),
        4,
        "two patterns, each user-side and once via sudo: {lines}"
    );
    for line in lines.lines() {
        assert!(
            line.contains(&root),
            "every pattern must be pinned to this checkout's path, never a bare name: {line}"
        );
    }
    for expected in [
        format!("pkill -f {root}/.*minvmd"),
        format!("pkill -f {root}/.*gvproxy"),
        format!("sudo -n pkill -f {root}/.*minvmd"),
        format!("sudo -n pkill -f {root}/.*gvproxy"),
    ] {
        assert!(
            lines.lines().any(|l| l == expected),
            "missing pattern {expected:?} in:\n{lines}"
        );
    }

    // By name: the patterns pin the same checkout *and* the one named VM —
    // minvmd processes by their `--vm alpha` argument, the VM's gvproxy
    // switch by its per-name socket directory — leaving every other VM of
    // this checkout running.
    std::fs::remove_file(&log).unwrap();
    let out = run_reap(&["--vm", "alpha"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = recorded();
    for expected in [
        format!("pkill -f {root}/.*minvmd.*--vm[= ]alpha( |$)"),
        format!("sudo -n pkill -f {root}/.*minvmd.*--vm[= ]alpha( |$)"),
        format!("pkill -f {root}/.*gvproxy.*local-minvmd[0-9]+/alpha/"),
        format!("sudo -n pkill -f {root}/.*gvproxy.*local-minvmd[0-9]+/alpha/"),
    ] {
        assert!(
            lines.lines().any(|l| l == expected),
            "missing pattern {expected:?} in:\n{lines}"
        );
    }

    // A name with ERE metacharacters is quoted, not interpreted.
    std::fs::remove_file(&log).unwrap();
    let out = run_reap(&["--vm", "a.b+c"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = recorded();
    assert!(
        lines.contains("--vm[= ]a\\.b\\+c( |$)"),
        "a VM name must be matched literally, not as a regex: {lines}"
    );

    // A `--vm` without a name is a usage error, not a reap of everything.
    let out = run_reap(&["--vm"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage"),
        "the usage error must say how to call the script: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Mark `path` executable (0700): the stub commands and the copied script must
/// be runnable by the test.
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms).unwrap();
}
