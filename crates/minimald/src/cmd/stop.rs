//! `minimald stop` subcommand.
//!
//! Reads `daemon_pid` from `state.toml`, sends `SIGTERM` to the daemon child,
//! waits up to 5 s, escalates to `SIGKILL` on timeout, then removes `daemon.pid`
//! and resets `state.toml` to `Stopped`.
//!
//! The command is idempotent: if the daemon is already stopped (or has never
//! been provisioned), it returns successfully with no action.

use anyhow::{Context as _, Result};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Run the `stop` subcommand.
pub fn run() -> Result<()> {
    run_with_state_dir(StateDir::default_path())
}

fn run_with_state_dir(dir: std::path::PathBuf) -> Result<()> {
    let state_dir = StateDir::new(dir).context("opening state dir")?;

    // ── Phase 1: read current state under lock ───────────────────────────────
    let daemon_pid = {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        match state.lifecycle {
            Lifecycle::Stopped | Lifecycle::NotProvisioned => {
                tracing::info!("minimald is not running");
                return Ok(()); // idempotent: already stopped
            }
            Lifecycle::Stopping => {
                tracing::info!("minimald is already stopping");
                return Ok(()); // idempotent: stop already in progress
            }
            _ => {}
        }

        state.daemon_pid // may be None during Starting before pid is written
    };

    // ── Phase 2: signal the daemon child (lock NOT held) ─────────────────────
    // Releasing the lock during the wait allows concurrent `status` reads.
    match daemon_pid {
        Some(pid) => signal_and_wait(pid)?,
        None => {
            tracing::warn!("daemon is active but daemon_pid is absent; cleaning up state");
        }
    }

    // ── Phase 3: reset state to Stopped (under lock) ─────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let _ = std::fs::remove_file(state_dir.daemon_pid_path());
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state")?;
    }

    tracing::info!("minimald stopped");
    Ok(())
}

/// Send `SIGTERM` to `pid`; wait up to 5 s; escalate to `SIGKILL` on timeout.
fn signal_and_wait(pid: u32) -> Result<()> {
    use std::time::{Duration, Instant};

    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| anyhow::anyhow!("invalid daemon_pid {pid} in state"))?;
    if pid_t <= 0 {
        return Err(anyhow::anyhow!("invalid daemon_pid {pid} in state"));
    }

    // SAFETY: kill(pid, SIGTERM) delivers SIGTERM to the named process. The pid
    // was stored in state.toml by the `run` supervisor that created the daemon
    // child; it may have already exited (ESRCH), which is handled below.
    let r = unsafe { libc::kill(pid_t, libc::SIGTERM) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Process does not exist; nothing to signal.
            tracing::debug!(pid, "daemon process already gone (ESRCH)");
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
                "daemon process did not exit after SIGTERM; sending SIGKILL"
            );
            // SAFETY: SIGKILL is a forced termination with no side effects
            // beyond killing the named process. The pid originated from our
            // own supervised daemon child.
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
        // No state.toml — should be a no-op.
        run_with_state_dir(tmp.path().to_path_buf()).unwrap();
    }

    #[test]
    fn stop_is_noop_when_already_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).unwrap();
        run_with_state_dir(tmp.path().to_path_buf()).unwrap();
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
            daemon_pid: Some(999_999_999),
            started_at: None,
        })
        .unwrap();
        // Should return Ok without error, even with a non-existent pid.
        run_with_state_dir(tmp.path().to_path_buf()).unwrap();
    }

    #[test]
    fn stop_cleans_up_running_state_with_nonexistent_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Use a PID that cannot exist (pid 0 is the kernel scheduler on Unix).
        // signal_and_wait will get ESRCH and skip the wait.
        // We use a large synthetic PID that won't collide with real processes
        // in the test runner.
        let fake_pid = 999_998u32; // likely ESRCH in CI
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            daemon_pid: Some(fake_pid),
            started_at: Some(0),
        })
        .unwrap();
        // Write a daemon.pid file too.
        std::fs::write(sd.daemon_pid_path(), format!("{fake_pid}\n")).unwrap();

        // stop must not error even when the process is gone (ESRCH).
        run_with_state_dir(tmp.path().to_path_buf()).unwrap();

        // State must be Stopped and daemon.pid must be removed.
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
        assert!(
            !sd.daemon_pid_path().exists(),
            "daemon.pid must be removed"
        );
    }

    #[test]
    fn stop_with_no_pid_in_state_still_resets_to_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            daemon_pid: None,
            started_at: None,
        })
        .unwrap();
        run_with_state_dir(tmp.path().to_path_buf()).unwrap();
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_rejects_pid_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            daemon_pid: Some(0),
            started_at: None,
        })
        .unwrap();
        assert!(run_with_state_dir(tmp.path().to_path_buf()).is_err());
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
            daemon_pid: Some(u32::MAX),
            started_at: None,
        })
        .unwrap();
        assert!(run_with_state_dir(tmp.path().to_path_buf()).is_err());
    }
}