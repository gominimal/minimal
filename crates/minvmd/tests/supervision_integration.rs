//! Supervision / restart / dirty-kill proof: boot a real microVM and exercise
//! the supervised lifecycle paths that `resource_vm_integration` (single
//! boot→stop) and `scripts/minvmd-lifecycle.sh` (single detach→Running→stop)
//! do not cover:
//!
//! - **Restart cycle** — a clean `stop` leaves state such that the next
//!   `run --detach` boots cleanly again (guards the `Stopped → Running`
//!   re-entry in `cmd/run.rs` and the `minvmd.toml` reset in `cmd/stop.rs`).
//! - **Dirty-kill repair** — SIGKILL the running VMM out from under the
//!   supervisor (the "leaked/killed boot" footgun); `status` must then repair
//!   the stale `Running` record to `Stopped` (`state.rs` `read_repaired`,
//!   "daemon is gone; repairing state to Stopped"), and a subsequent
//!   `run --detach` must boot cleanly rather than trip an "already running".
//!
//! NOT covered here: the SIGTERM→SIGKILL *escalation* branch in
//! `cmd/stop.rs` (the 5 s timeout path). Triggering it needs a guest that
//! ignores SIGTERM, which a black-box harness cannot arrange without a
//! fault-injection hook; it stays a unit-level concern.
//!
//! Gates (identical to `resource_vm_integration`): `#[cfg(minvmd_libkrun)]`,
//! `#[ignore]`, `MINVMD_E2E=1`, and the three image env vars. As a
//! `*_integration.rs` harness it is auto-discovered by both VM lanes'
//! filterset, so it runs on Linux/KVM **and** the self-hosted macOS/HVF lane.

#![cfg(minvmd_libkrun)]

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serial_test::serial;

/// The minvmd binary under test: `MINVMD_BIN` when set (CI's split build/test
/// runners), else the compile-time cargo-built path.
fn minvmd_bin() -> OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// Isolated state dir under `/tmp`: macOS's `$TMPDIR` is deep enough that a
/// provider socket beneath a default tempdir would overflow `sun_path` (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// Run `minvmd <args>` isolated to `state` (both `HOME` and `XDG_STATE_HOME`),
/// capturing output. Bounded by a hard `SUBPROC_TIMEOUT`: every subcommand here
/// is quick (`run --detach` carries its own `--timeout`; `status`/`stop` return
/// in seconds), so a subprocess that overruns the cap means a wedged daemon.
/// `Command::output()` would block forever there — past the polling deadlines,
/// so the test would hang CI instead of failing — so we spawn, poll `try_wait`,
/// and SIGKILL past the deadline to fail fast. Output stays small (status JSON),
/// well under the pipe buffer, so reading after exit cannot deadlock.
const SUBPROC_TIMEOUT: Duration = Duration::from_secs(120);

fn minvmd(state: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(minvmd_bin())
        .args(args)
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        .env_remove("MINVMD_VM_RAM_MIB")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning minvmd");
    let deadline = Instant::now() + SUBPROC_TIMEOUT;
    loop {
        if child.try_wait().expect("polling minvmd").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("minvmd {args:?} did not exit within {SUBPROC_TIMEOUT:?} (wedged daemon?)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collecting minvmd output")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

/// Boot the supervised VM (detached) and poll `status` until Running; returns
/// the running status JSON (which carries `vmm_pid`). Panics past the deadline.
fn boot_to_running(sd: &Path) -> serde_json::Value {
    let run = minvmd(sd, &["run", "--detach", "--timeout", "60"]);
    assert!(
        run.status.success(),
        "run --detach failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    // `run --detach` returns once the host UDS accepts (opened early in VM
    // setup), slightly ahead of the Starting->Running transition. Generous
    // deadline for a slow cold boot on the mac lane.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let v = json(&minvmd(sd, &["status", "--json"]));
        if v["state"] == "running" && v["vmm_pid"].is_number() {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "VM never reached Running; last status: {v}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Poll `status` until it reports Stopped; panics past the deadline. Used both
/// after a clean `stop` and after a dirty kill (where the supervisor's own
/// cleanup and/or `read_repaired` converge the record to Stopped).
fn poll_until_stopped(sd: &Path, deadline: Duration) {
    let end = Instant::now() + deadline;
    loop {
        let v = json(&minvmd(sd, &["status", "--json"]));
        if v["state"] == "stopped" {
            return;
        }
        assert!(
            Instant::now() < end,
            "state never converged to Stopped; last status: {v}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// SIGKILL a pid via `/bin/kill` (portable across Linux and macOS; avoids a
/// libc dev-dep). SIGKILL — not SIGTERM — because a VMM inside
/// `krun_start_enter` ignores SIGTERM.
fn kill9(pid: i64) {
    let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun + kernel/rootfs/initramfs"]
fn supervised_restart_cycle_and_dirty_kill_repair() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("supervision_integration: MINVMD_E2E != 1, skipping");
        return;
    }
    for var in [
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "supervision_integration: {var} must be set when MINVMD_E2E=1"
        );
    }

    let state = short_state_dir();
    let sd = state.path();

    // Tear the detached daemon down even if an assertion panics mid-test.
    struct Stopper<'a>(&'a Path);
    impl Drop for Stopper<'_> {
        fn drop(&mut self) {
            let _ = minvmd(self.0, &["stop"]);
        }
    }
    let _stopper = Stopper(sd);

    // ── Phase 1: clean restart cycle ─────────────────────────────────────────
    // Boot, confirm Running, clean stop, confirm Stopped.
    boot_to_running(sd);
    let stop1 = minvmd(sd, &["stop"]);
    assert!(
        stop1.status.success(),
        "first stop failed: {}",
        String::from_utf8_lossy(&stop1.stderr)
    );
    let after1 = json(&minvmd(sd, &["status", "--json"]));
    assert_eq!(
        after1["state"], "stopped",
        "status after first stop: {after1}"
    );

    // ── Phase 2: boot again (restart after a clean stop), then dirty-kill ─────
    // The second boot on the same state dir proves the re-entry path; capture
    // the live VMM pid so we can kill it out from under the supervisor.
    let running = boot_to_running(sd);
    let vmm_pid = running["vmm_pid"]
        .as_i64()
        .unwrap_or_else(|| panic!("running status missing numeric vmm_pid: {running}"));
    kill9(vmm_pid);

    // The record still says Running with a now-dead pid. `status` must repair
    // it to Stopped (either via the supervisor's own child.wait cleanup or
    // `read_repaired` detecting the gone daemon). Give it a moment to converge.
    poll_until_stopped(sd, Duration::from_secs(30));

    // ── Phase 3: boot cleanly after the dirty kill ───────────────────────────
    // A stale Running record must NOT wedge the next boot into "already
    // running"; a fresh detach must reach Running again.
    boot_to_running(sd);
    let stop3 = minvmd(sd, &["stop"]);
    assert!(
        stop3.status.success(),
        "final stop failed: {}",
        String::from_utf8_lossy(&stop3.stderr)
    );
    let after3 = json(&minvmd(sd, &["status", "--json"]));
    assert_eq!(
        after3["state"], "stopped",
        "status after final stop: {after3}"
    );
}
