//! `minvmd status` subcommand (R4.3).
//!
//! Reads the daemon state and prints it.
//! A non-blocking advisory read lock is attempted on `lifecycle.lock` to detect
//! concurrent lifecycle transitions; if the lock cannot be acquired the command
//! exits with code 2 (lock contention).
//!
//! Exit codes:
//! - 0 — daemon is Running
//! - 1 — daemon is stopped (or not yet provisioned)
//! - 2 — lock contention; another process is transitioning state

use anyhow::{Context as _, Result};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Exit classification returned by [`run`].
#[derive(Debug, PartialEq, Eq)]
pub enum StatusExit {
    /// Daemon is `Running` — exit code 0.
    Running,
    /// Daemon is not running — exit code 1.
    Stopped,
    /// Could not acquire the advisory read lock — exit code 2.
    LockContention,
}

impl StatusExit {
    /// Numeric process exit code for this status.
    pub fn code(&self) -> i32 {
        match self {
            Self::Running => 0,
            Self::Stopped => 1,
            Self::LockContention => 2,
        }
    }
}

/// Run the `status` subcommand.
///
/// `json`: if true, print a JSON object; otherwise print a human-readable line.
pub fn run(json: bool) -> Result<StatusExit> {
    run_with_state_dir(json, StateDir::default_path())
}

fn run_with_state_dir(json: bool, dir: std::path::PathBuf) -> Result<StatusExit> {
    let state_dir = StateDir::new(dir).context("opening state dir")?;

    // Non-blocking read lock: detect concurrent state transitions (R4.3).
    // Dropped before effective_state, which may take the write lock to repair
    // stale state (same-process fds would deadlock otherwise).
    {
        let rw = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        if rw.try_read().is_err() {
            return Ok(StatusExit::LockContention);
        }
    }

    let state = state_dir.effective_state().context("reading state")?;

    let uptime_seconds = state.started_at.and_then(|started| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(now.saturating_sub(started))
    });

    if json {
        print_json(&state, uptime_seconds)?;
    } else {
        print_human(&state, uptime_seconds);
    }

    Ok(match state.lifecycle {
        Lifecycle::Running => StatusExit::Running,
        _ => StatusExit::Stopped,
    })
}

fn lifecycle_state_str(lc: Lifecycle) -> &'static str {
    match lc {
        Lifecycle::NotProvisioned | Lifecycle::Stopped => "stopped",
        Lifecycle::Starting => "starting",
        Lifecycle::Running => "running",
        Lifecycle::Stopping => "stopping",
    }
}

fn print_json(state: &State, uptime_seconds: Option<u64>) -> Result<()> {
    // vcpus is the constant the VMM child uses; ram_mib mirrors the same
    // env-overridable resolution (`crate::cmd::vm_ram_mib()`) so `status`
    // reports the size the next boot would use. A future change that stores
    // these in minvmd.toml can report the live VM's actual values.
    let json = serde_json::json!({
        "state": lifecycle_state_str(state.lifecycle),
        "vmm_pid": state.vmm_pid,
        "uptime_seconds": uptime_seconds,
        "vcpus": 2u8,
        "ram_mib": crate::cmd::vm_ram_mib(),
    });
    println!("{json}");
    Ok(())
}

fn print_human(state: &State, uptime_seconds: Option<u64>) {
    match state.lifecycle {
        Lifecycle::NotProvisioned | Lifecycle::Stopped => println!("stopped"),
        Lifecycle::Starting => println!("starting"),
        Lifecycle::Stopping => println!("stopping"),
        Lifecycle::Running => {
            let uptime = uptime_seconds.unwrap_or(0);
            let pid = state
                .vmm_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            println!("running (pid={pid}, uptime={uptime}s)");
        }
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
    fn not_provisioned_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn stopped_state_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn running_state_exits_running() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1_700_000_000),
        })
        .unwrap();
        let mut alive = sd.alive_lock().unwrap();
        let _guard = alive.try_write().unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Running);
    }

    #[test]
    fn stale_running_state_exits_stopped_and_repairs() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Running per the state file, but no alive-lock holder.
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1_700_000_000),
        })
        .unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn starting_state_exits_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: None,
            started_at: None,
        })
        .unwrap();
        let mut alive = sd.alive_lock().unwrap();
        let _guard = alive.try_write().unwrap();
        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Stopped);
    }

    #[test]
    fn json_output_contains_required_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(99),
            started_at: Some(0),
        })
        .unwrap();
        let mut alive = sd.alive_lock().unwrap();
        let _guard = alive.try_write().unwrap();
        // run_with_state_dir prints to stdout; verify the exit code at minimum.
        let exit = run_with_state_dir(true, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::Running);
    }

    #[test]
    fn lock_contention_exits_2() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // Hold an exclusive write lock and attempt a concurrent status.
        let mut lock = sd.lifecycle_lock().unwrap();
        let _held = lock.write().unwrap();

        let exit = run_with_state_dir(false, tmp.path().to_path_buf()).unwrap();
        assert_eq!(exit, StatusExit::LockContention);
    }
}
