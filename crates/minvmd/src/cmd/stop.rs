//! `minvmd stop` subcommand (R4.4, R2.3).
//!
//! Reads `vmm_pid` from `minvmd.toml`, asks the in-VM minimald to shut down
//! (drain sessions + quiesce the data volume) over the bridge UDS, then sends
//! `SIGTERM` to the VMM child, waits up to 5 s, escalates to `SIGKILL` on
//! timeout, then resets `minvmd.toml` to `Stopped`.
//!
//! The command is idempotent: if the daemon is already stopped (or has never
//! been provisioned), it returns successfully with no action. Stale active
//! state from a dead daemon is repaired to `Stopped`.
//!
//! Everything it reads and signals belongs to one VM's state dir (the
//! `--vm-name` one), so stopping one VM leaves every other VM on the host
//! running.

use anyhow::{Context as _, Result};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Run the `stop` subcommand.
pub fn run() -> Result<()> {
    run_with_state_dir(StateDir::default_path(), true)
}

/// `quiesce_guest` gates the Shutdown RPC (R2.3): production passes `true`;
/// unit tests pass `false` so they never reach a live daemon's bridge socket.
fn run_with_state_dir(dir: std::path::PathBuf, quiesce_guest: bool) -> Result<()> {
    let state_dir = StateDir::new(dir).context("opening state dir")?;

    // ── Phase 1: read current state under lock ───────────────────────────────
    let vmm_pid = {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        if !state.lifecycle.is_active() {
            tracing::info!("minvmd is not running");
            return Ok(()); // idempotent: already stopped
        }
        if !state_dir.daemon_alive().context("probing alive lock")? {
            // Dead daemon left active state behind; nothing to signal.
            state_dir
                .write_state(&State::stopped())
                .context("repairing stale state")?;
            tracing::info!("minvmd was not running; cleared stale state");
            return Ok(());
        }
        if state.lifecycle == Lifecycle::Stopping {
            tracing::info!("minvmd is already stopping");
            return Ok(()); // idempotent: stop already in progress
        }

        state.vmm_pid // may be None during Starting before pid is written
    };

    // ── Phase 2: quiesce the guest, then signal the VMM child (lock NOT held) ─
    // Releasing the lock during the wait allows concurrent `status` reads.
    match vmm_pid {
        Some(pid) => {
            if quiesce_guest {
                shutdown_guest_best_effort();
            }
            signal_and_wait(pid)?
        }
        None => {
            tracing::warn!("daemon is active but vmm_pid is absent; cleaning up state");
        }
    }

    // ── Phase 3: reset state to Stopped (under lock) ─────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state")?;
    }

    tracing::info!(
        vm = %crate::state::vm_name(),
        state_dir = %state_dir.dir().display(),
        "minvmd stopped"
    );
    Ok(())
}

/// R2.3: ask the in-VM minimald (over the vsock bridge UDS) to drain sessions
/// and quiesce the data volume before the VMM is signalled, so a clean stop
/// leaves a clean ext4 journal. Best-effort: on any failure — guest already
/// gone, bridge down, timeout — SIGTERM proceeds and the journal replay
/// backstop bounds the damage.
fn shutdown_guest_best_effort() {
    // Two deadlines, because they bound different things. The connect
    // deadline is short: libkrun accepts the bridge UDS connect even when the
    // guest is wedged, so a completed SSH handshake is the only proof of a
    // live daemon — a broken VM must not stall the user's recovery command.
    // The RPC deadline is long: the handler force-drains every session
    // (sandbox teardown, process kills — unbounded real work) and then
    // quiesces (10 s guest-side ceiling) before it acknowledges; giving up
    // mid-drain would SIGTERM the VMM with a dirty journal, defeating the
    // point of the call.
    const GUEST_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const GUEST_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    match crate::sock::resolve_uds_path()
        .map_err(anyhow::Error::from)
        .and_then(|uds| {
            crate::rpc_client::shutdown_guest(&uds, GUEST_CONNECT_TIMEOUT, GUEST_SHUTDOWN_TIMEOUT)
        }) {
        Ok(resp) => tracing::info!(?resp, "guest acknowledged Shutdown RPC"),
        Err(e) => {
            tracing::warn!(error = %e, "guest Shutdown RPC failed; proceeding with SIGTERM")
        }
    }
}

/// Send `SIGTERM` to `pid`; wait up to 5 s; escalate to `SIGKILL` on timeout.
fn signal_and_wait(pid: u32) -> Result<()> {
    use std::time::{Duration, Instant};

    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| anyhow::anyhow!("invalid vmm_pid {pid} in state"))?;
    if pid_t <= 0 {
        return Err(anyhow::anyhow!("invalid vmm_pid {pid} in state"));
    }

    // SAFETY: kill(pid, SIGTERM) delivers SIGTERM to the named process. The pid
    // was stored in minvmd.toml by the `run` supervisor that created the VMM
    // child; it may have already exited (ESRCH), which is handled below.
    let r = unsafe { libc::kill(pid_t, libc::SIGTERM) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Process does not exist; nothing to signal.
            tracing::debug!(pid, "vmm process already gone (ESRCH)");
            return Ok(());
        }
        return Err(anyhow::anyhow!("SIGTERM to pid {pid}: {err}"));
    }

    tracing::debug!(pid, "SIGTERM sent; waiting up to 5s");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: kill(pid, 0) checks for process existence without delivering
        // a signal. Errors other than ESRCH are ignored as best-effort.
        let alive = unsafe { libc::kill(pid_t, 0) == 0 };
        if !alive {
            break;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                pid,
                "vmm process did not exit after SIGTERM; sending SIGKILL"
            );
            // SAFETY: SIGKILL is a forced termination with no side effects
            // beyond killing the named process. The pid originated from our
            // own supervised VMM child.
            unsafe { libc::kill(pid_t, libc::SIGKILL) };
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::Lifecycle;
    use crate::state::State;

    fn make_state_dir(tmp: &tempfile::TempDir) -> StateDir {
        StateDir::new(tmp.path().to_path_buf()).expect("StateDir::new")
    }

    #[test]
    fn stop_is_noop_when_not_provisioned() {
        let tmp = tempfile::tempdir().unwrap();
        // No state file — should be a no-op.
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
    }

    #[test]
    fn stop_is_noop_when_already_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).unwrap();
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        // State should still be Stopped.
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_is_noop_when_already_stopping() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Stopping,
            vmm_pid: Some(999_999_999),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        // Hold the alive lock so Stopping counts as a live daemon.
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        // The live daemon owns the transition; state is untouched.
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopping);
    }

    #[test]
    fn stop_repairs_stale_active_state_without_signalling() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Running per the state file, but no alive-lock holder: the daemon is
        // dead. `stop` must repair to Stopped without touching the pid (which
        // may have been recycled).
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(std::process::id()), // a live pid that must NOT be signalled
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_with_no_pid_in_state_still_resets_to_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: None,
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    /// A stand-in VMM: a `sleep` child holding `sd`'s alive lock, recorded in
    /// `sd` as the running daemon's `vmm_pid`, exactly as `run` records the
    /// real one. Returns its pid, its supervisor (a thread that reaps it the
    /// moment it exits, as the real `run` supervisor does — otherwise the
    /// zombie would still answer `kill(pid, 0)` and `stop` would sit out its
    /// full SIGTERM grace), and the lock.
    fn fake_running_vm(
        sd: &StateDir,
    ) -> (
        u32,
        std::thread::JoinHandle<std::process::ExitStatus>,
        crate::state::AliveLock,
    ) {
        let lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        lock.inherit_into(&mut cmd);
        let mut child = cmd.spawn().expect("spawn sleep");
        let pid = child.id();
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(pid),
            started_at: Some(1),
            ..State::stopped()
        })
        .unwrap();
        let supervisor = std::thread::spawn(move || child.wait().expect("wait"));
        (pid, supervisor, lock)
    }

    /// Poll for up to 5 s; `true` once `done()` holds.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if done() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn stop_one_vm_leaves_other_running() {
        use paths::VmName;
        let tmp = tempfile::tempdir().unwrap();
        let base = paths::DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap();
        let default_dir = crate::state::provider_dir_for(&base, &VmName::default());
        let alpha_dir = crate::state::provider_dir_for(&base, &VmName::new("alpha").unwrap());
        let default_sd = StateDir::new(default_dir.clone()).unwrap();
        let alpha_sd = StateDir::new(alpha_dir.clone()).unwrap();

        // Two VMs up on one host: the default one and a named one nested
        // under its provider dir.
        let (default_pid, default_vm, _default_lock) = fake_running_vm(&default_sd);
        let (_alpha_pid, alpha_vm, alpha_lock) = fake_running_vm(&alpha_sd);

        // Stop the named VM only.
        run_with_state_dir(alpha_dir, false).unwrap();
        drop(alpha_lock);

        assert_eq!(alpha_sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
        assert!(
            eventually(|| alpha_vm.is_finished()),
            "the stopped VM's VMM is gone"
        );
        assert!(!alpha_vm.join().unwrap().success(), "signalled, not exited");

        // The other VM is untouched: still Running, its VMM alive, its lock held.
        let s = default_sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Running);
        assert_eq!(s.vmm_pid, Some(default_pid));
        assert!(
            !default_vm.is_finished(),
            "the other VM's VMM must still be running"
        );
        assert!(default_sd.daemon_alive().unwrap());

        // And the converse: stopping the default VM leaves nothing of the
        // named VM's (already Stopped) state disturbed — its dir persists.
        run_with_state_dir(default_dir, false).unwrap();
        assert!(eventually(|| default_vm.is_finished()));
        default_vm.join().unwrap();
        assert_eq!(
            default_sd.read_state().unwrap().lifecycle,
            Lifecycle::Stopped
        );
        assert!(alpha_sd.state_path().exists());
    }

    /// `scripts/reap-vms.sh` kills only the VM host processes of the checkout
    /// it is run from: a leftover from another checkout survives it. The
    /// script scopes its `pkill -f` by the absolute checkout path in the
    /// cmdline, which is what a real minvmd / `__krun-vmm` carries (they
    /// re-exec via `current_exe()`), so a shell script at
    /// `<checkout>/target/debug/minvmd` that idles until signalled stands in
    /// for one (its cmdline is `/bin/sh <that path>`).
    #[test]
    fn reap_scoped_per_checkout() {
        use std::os::unix::fs::PermissionsExt as _;
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/reap-vms.sh")
            .canonicalize()
            .expect("scripts/reap-vms.sh exists");

        // Two fake checkouts, each with a "minvmd" whose cmdline carries the
        // checkout path; the script under test is installed into the first.
        let spawn_vm = |root: &std::path::Path| {
            let bin = root.join("target/debug");
            std::fs::create_dir_all(&bin).unwrap();
            let fake = bin.join("minvmd");
            // Idle in a child so SIGTERM (what `pkill` sends) is handled
            // promptly and takes the child down too; `exec sleep` would
            // replace the cmdline the reaper matches on.
            std::fs::write(
                &fake,
                "#!/bin/sh\ntrap 'kill $! 2>/dev/null; exit 0' TERM\nsleep 30 &\nwait\n",
            )
            .unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::process::Command::new(&fake)
                .spawn()
                .expect("spawn fake minvmd")
        };
        let mine = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mine = mine.path().canonicalize().unwrap();
        let other = other.path().canonicalize().unwrap();
        std::fs::create_dir_all(mine.join("scripts")).unwrap();
        std::fs::copy(&script, mine.join("scripts/reap-vms.sh")).unwrap();
        let mut my_vm = spawn_vm(&mine);
        let mut other_vm = spawn_vm(&other);

        let status = std::process::Command::new("bash")
            .arg(mine.join("scripts/reap-vms.sh"))
            .status()
            .expect("run reap-vms.sh");
        assert!(status.success(), "reap-vms.sh exited {status}");

        assert!(
            eventually(|| my_vm.try_wait().unwrap().is_some()),
            "this checkout's VM host process must be reaped"
        );
        assert!(
            other_vm.try_wait().unwrap().is_none(),
            "another checkout's VM host process must survive"
        );
        // SIGTERM, not `kill()` (SIGKILL): the stand-in's trap takes its
        // `sleep` child down with it, so nothing outlives the test.
        // SAFETY: signalling our own child by the pid we spawned.
        unsafe { libc::kill(other_vm.id() as libc::pid_t, libc::SIGTERM) };
        other_vm.wait().unwrap();
    }

    #[test]
    fn stop_rejects_pid_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(0),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        assert!(run_with_state_dir(tmp.path().to_path_buf(), false).is_err());
    }

    #[test]
    fn stop_rejects_pid_exceeding_pid_t_max() {
        // u32::MAX > i32::MAX; try_from must fail rather than silently wrapping.
        if libc::pid_t::try_from(u32::MAX).is_ok() {
            // On a platform where pid_t is wider than i32, skip this guard.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(u32::MAX),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        assert!(run_with_state_dir(tmp.path().to_path_buf(), false).is_err());
    }
}
