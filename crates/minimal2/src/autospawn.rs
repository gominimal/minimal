//! Auto-spawn logic for minvmd on macOS (R4.5).
//!
//! On macOS, checks the minvmd state before connecting to the UDS. If minvmd
//! is not running, spawns `minvmd run --detach` and waits for the UDS to become
//! available.
//!
//! On Linux, this module is a no-op.

use std::io;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

/// Default timeout in seconds to wait for the UDS when spawning minvmd (R4.5).
#[cfg(target_os = "macos")]
const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 8;

/// Poll interval while waiting for a shutting-down minvmd to reach a terminal
/// state before deciding whether to spawn.
#[cfg(target_os = "macos")]
const STOPPING_POLL_MS: u64 = 100;

/// Max time to wait for an in-progress `minvmd stop` (SIGTERM → SIGKILL, ~5 s)
/// to finish before giving up with a clear error.
#[cfg(target_os = "macos")]
const STOPPING_WAIT_SECS: u64 = 6;

/// Check if minvmd needs to be spawned, and spawn it if necessary.
///
/// On macOS (R4.5):
/// - Reads the minvmd state from `state.toml`
/// - If not running, spawns `minvmd run --detach` with a timeout
/// - Returns an error if spawn fails
///
/// On Linux, this is a no-op since minvmd does not exist on Linux.
#[cfg(target_os = "macos")]
pub fn ensure_minvmd_running() -> io::Result<()> {
    let state_dir = minvmd::state::StateDir::new(minvmd::state::StateDir::default_path())?;

    // Read current state (R4.5: check state.toml before connecting)
    let state = state_dir.read_state()?;

    // If already running or starting, no need to spawn
    match state.lifecycle {
        minvmd::lifecycle::Lifecycle::Running | minvmd::lifecycle::Lifecycle::Starting => {
            tracing::debug!("minvmd already running or starting");
            return Ok(());
        }
        minvmd::lifecycle::Lifecycle::Stopping => {
            // `minvmd stop` can take up to ~5 s (SIGTERM → SIGKILL escalation),
            // so a fixed short sleep usually leaves the daemon still Stopping.
            // Spawning then would make the new `minvmd run` bail on its own
            // Stopping guard, surfacing an opaque 8 s UDS timeout. Instead poll
            // until it reaches a terminal state, re-reading on each tick.
            tracing::info!("minvmd is stopping; waiting for it to finish");
            let deadline = Instant::now() + Duration::from_secs(STOPPING_WAIT_SECS);
            loop {
                thread::sleep(Duration::from_millis(STOPPING_POLL_MS));
                match state_dir.read_state()?.lifecycle {
                    // Something else restarted it in the meantime.
                    minvmd::lifecycle::Lifecycle::Running
                    | minvmd::lifecycle::Lifecycle::Starting => return Ok(()),
                    // Shutdown completed; fall through to spawn.
                    minvmd::lifecycle::Lifecycle::Stopped
                    | minvmd::lifecycle::Lifecycle::NotProvisioned => break,
                    _ if Instant::now() >= deadline => {
                        return Err(io::Error::other(
                            "minvmd is still stopping after waiting; try again shortly",
                        ));
                    }
                    // Still stopping (or a future state); keep polling.
                    _ => continue,
                }
            }
        }
        minvmd::lifecycle::Lifecycle::Stopped | minvmd::lifecycle::Lifecycle::NotProvisioned => {
            // Not running; will spawn below
        }
        // Lifecycle is #[non_exhaustive]; treat any future state conservatively
        // as "not running" and fall through to spawn.
        _ => {}
    }

    // Not running; spawn minvmd run --detach with timeout (R4.5)
    tracing::info!(
        "spawning minvmd run --detach with timeout {}",
        DEFAULT_SPAWN_TIMEOUT_SECS
    );
    let output = Command::new("minvmd")
        .arg("run")
        .arg("--detach")
        .arg("--timeout")
        .arg(DEFAULT_SPAWN_TIMEOUT_SECS.to_string())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to spawn minvmd: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "minvmd run --detach failed: {}",
            stderr
        )));
    }

    tracing::info!("minvmd spawned successfully");
    Ok(())
}

/// On Linux, auto-spawn is a no-op since minvmd is not available.
#[cfg(target_os = "linux")]
pub fn ensure_minvmd_running() -> io::Result<()> {
    tracing::debug!("ensure_minvmd_running is a no-op on Linux");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    fn test_autospawn_noop_on_linux() {
        // On Linux, ensure_minvmd_running should be a no-op and always succeed
        let result = super::ensure_minvmd_running();
        assert!(
            result.is_ok(),
            "ensure_minvmd_running should always succeed on Linux"
        );
    }
}
