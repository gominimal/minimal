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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Bound on the connect half of a guest-shutdown ask: libkrun accepts the
/// bridge UDS connect even when the guest is wedged, and a broken VM must
/// not stall the stop.
pub(crate) const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the RPC half of a guest-shutdown ask: the handler force-drains
/// every session and quiesces before it acknowledges.
pub(crate) const GUEST_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the signal-stop path waits for the supervisor's own teardown
/// to write `Stopped` after the VMM child dies.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) const SIGNAL_STOPPED_BOUND: Duration = Duration::from_secs(10);

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
                let uds = crate::sock::resolve_uds_path().map_err(anyhow::Error::from);
                match uds {
                    Ok(uds) => shutdown_guest_best_effort(&uds),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "resolving bridge UDS path failed; proceeding with SIGTERM"
                    ),
                }
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

    tracing::info!("minvmd stopped");
    Ok(())
}

/// R2.3: ask the in-VM minimald (over the vsock bridge UDS) to drain sessions
/// and quiesce the data volume before the VMM is signalled, so a clean stop
/// leaves a clean ext4 journal. Best-effort: on any failure — guest already
/// gone, bridge down, timeout — SIGTERM proceeds and the journal replay
/// backstop bounds the damage.
fn shutdown_guest_best_effort(uds_path: &Path) {
    // Two deadlines, because they bound different things. The connect
    // deadline is short: libkrun accepts the bridge UDS connect even when the
    // guest is wedged, so a completed SSH handshake is the only proof of a
    // live daemon — a broken VM must not stall the user's recovery command.
    // The RPC deadline is long: the handler force-drains every session
    // (sandbox teardown, process kills — unbounded real work) and then
    // quiesces (10 s guest-side ceiling) before it acknowledges; giving up
    // mid-drain would SIGTERM the VMM with a dirty journal, defeating the
    // point of the call.
    match crate::rpc_client::shutdown_guest(uds_path, GUEST_CONNECT_TIMEOUT, GUEST_SHUTDOWN_TIMEOUT)
    {
        Ok(resp) => tracing::info!(?resp, "guest acknowledged Shutdown RPC"),
        Err(e) => {
            tracing::warn!(error = %e, "guest Shutdown RPC failed; proceeding with SIGTERM")
        }
    }
}

/// Send `SIGTERM` to `pid`; wait up to 5 s; escalate to `SIGKILL` on timeout.
pub(crate) fn signal_and_wait(pid: u32) -> Result<()> {
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

/// Graceful stop as the `run` supervisor's signal watcher runs it: quiesce
/// the guest over the bridge UDS, signal the recorded VMM child, then wait
/// for the supervisor's own teardown to write the `Stopped` state.
///
/// This is the signal-side twin of `run_with_state_dir`: the same quiesce
/// (so the data volume's ext4 journal stays clean, informed by #705) and
/// the same SIGTERM→SIGKILL escalation, but driven from the stop-signal
/// thread where the main thread cannot be joined — the lifecycle record
/// is the only shared witness that its teardown finished. On any error the
/// caller falls back to dying by the signal as before, so the process
/// still terminates.
///
/// `stopped_bound` bounds the final wait; tests pass tighter bounds than
/// production's [`SIGNAL_STOPPED_BOUND`].
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn graceful_stop_from_signal(
    state_dir_path: PathBuf,
    stopped_bound: Duration,
) -> Result<()> {
    let state_dir = StateDir::new(state_dir_path.clone())
        .with_context(|| format!("opening state dir: {}", state_dir_path.display()))?;

    // Snapshot the lifecycle under the read lock only: the quiesce, the
    // signal, and the Stopped wait all run without it, exactly as `stop`
    // releases the lock during its waits. A `Running` state with a pid is
    // the only case this path owns — every other transition belongs to
    // `stop` — and the pid guard keeps a recycled pid from being
    // signalled.
    let vmm_pid = {
        let lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.read().context("acquiring lifecycle read lock")?;
        let state = state_dir.read_state().context("reading state")?;
        match (state.lifecycle, state.vmm_pid) {
            (Lifecycle::Running, Some(pid)) => pid,
            _ => bail!(
                "refusing signal stop: lifecycle is {:?}, vmm pid is {:?}",
                state.lifecycle,
                state.vmm_pid
            ),
        }
    };

    // Same best-effort quiesce as `stop`: a failure here logs and falls
    // through to the signal, so a wedged guest cannot stall termination.
    // The UDS is the same `<state dir>/ssh.sock` the CLI resolves for the
    // default provider dir (R3.2), computed from the passed state dir.
    let uds_path = state_dir_path.join(paths::SSH_SOCK_FILE);
    shutdown_guest_best_effort(&uds_path);

    signal_and_wait(vmm_pid).context("stopping VMM after signal")?;

    // The supervisor's main thread watches the same child and writes
    // `Stopped` once it has reaped it; poll for that record, bounded.
    let deadline = Instant::now() + stopped_bound;
    loop {
        let state = state_dir.read_state().context("reading state")?;
        if matches!(state.lifecycle, Lifecycle::Stopped) {
            tracing::info!("supervisor teardown finished; signal stop complete");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "supervisor did not write Stopped within {:?} of the VMM dying",
                stopped_bound
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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

    #[test]
    fn signal_and_wait_reaps_a_spawned_process() {
        // A real child that ignores nothing: SIGTERM must end it within the
        // 5s grace, so signal_and_wait returns Ok without escalating. The
        // reaper thread matters: an unreaped child stays a zombie, and
        // kill(pid, 0) succeeds on a zombie — the poll would wait out the
        // whole grace. Reaping is what makes the pid observably gone (the
        // supervisor's main thread plays this role in production).
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let reaper = std::thread::spawn(move || {
            let status = child.wait().expect("wait");
            assert!(!status.success(), "sleep must not exit successfully");
        });
        let started = std::time::Instant::now();
        signal_and_wait(pid).expect("signal_and_wait");
        reaper.join().expect("reaper thread");
        // The reaped pid must have been observed gone well inside the 5s
        // grace — the poll's fast path, not the SIGKILL escalation.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "signal_and_wait should observe the reaped pid quickly, took {:?}",
            started.elapsed()
        );
        // kill(pid, 0) must now report ESRCH.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(r, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn signal_stop_refuses_when_not_running_with_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Stopped: nothing to stop.
        sd.write_state(&State::stopped()).unwrap();
        let err = graceful_stop_from_signal(tmp.path().to_path_buf(), SIGNAL_STOPPED_BOUND)
            .expect_err("must refuse a Stopped state");
        assert!(err.to_string().contains("refusing signal stop"));

        // Running but no pid: the signal path owns no child to signal.
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: None,
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let err = graceful_stop_from_signal(tmp.path().to_path_buf(), SIGNAL_STOPPED_BOUND)
            .expect_err("must refuse a Running state with no pid");
        assert!(err.to_string().contains("refusing signal stop"));
    }

    #[test]
    fn signal_stop_quiesces_signals_and_waits_for_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // The "VMM child": a real process the helper will SIGTERM. Its
        // death is what the supervisor's main thread would observe.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(pid),
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();

        // The "supervisor main thread": observes the child's death, then
        // writes the Stopped state, exactly as run's teardown does after
        // reaping the VMM child. (The bridge UDS is absent here, so the
        // quiesce half fails fast and logs — proving the fall-through.)
        let sd_dir = sd.dir().to_path_buf();
        let watcher = std::thread::spawn(move || {
            let status = child.wait().expect("wait for signalled child");
            assert!(!status.success());
            let sd = StateDir::new(sd_dir).expect("StateDir::new");
            sd.write_state(&State::stopped()).expect("write Stopped");
        });

        // The bound must cover the quiesce attempt (fast: no socket), the
        // 5s signal grace, and the teardown write — 30s is generous.
        graceful_stop_from_signal(tmp.path().to_path_buf(), Duration::from_secs(30))
            .expect("graceful stop");

        let state = sd.read_state().unwrap();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert_eq!(state.vmm_pid, None);
        watcher.join().expect("watcher thread");
    }
}
