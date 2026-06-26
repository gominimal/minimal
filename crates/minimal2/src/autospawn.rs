//! Auto-spawn logic for minvmd (R4.5).
//!
//! Before connecting to the minvmd UDS, the CLI reads `state.toml`. If minvmd is
//! not running it spawns `minvmd run --detach` and waits (with a timeout) for the
//! UDS to become available. This runs on both macOS (Hypervisor.framework) and
//! Linux (KVM); on any other target it is a no-op.

use std::io;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::thread;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use minvmd::lifecycle::Lifecycle;

/// Default timeout in seconds to wait for the UDS when spawning minvmd (R4.5).
///
/// A cold VM boot (kernel bring-up + the in-VM minimald init: mount,
/// pivot_root, networking) was observed at ~22–28s before the bridge socket
/// accepts, and is slower under host load, so the default carries margin above
/// minvmd's own READY wait. This is an upper bound — the spawn returns as soon
/// as the UDS is ready — so it only costs time on a genuinely slow/failed boot.
/// Override with [`SPAWN_TIMEOUT_ENV`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 75;

/// Environment variable overriding [`DEFAULT_SPAWN_TIMEOUT_SECS`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
const SPAWN_TIMEOUT_ENV: &str = "MINIMAL_SPAWN_TIMEOUT_SECS";

/// The minvmd UDS-readiness wait, overridable via [`SPAWN_TIMEOUT_ENV`]. A
/// non-numeric, empty, or zero value falls back to [`DEFAULT_SPAWN_TIMEOUT_SECS`]
/// — a zero timeout would give the boot no readiness window.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn spawn_timeout_secs() -> u64 {
    std::env::var(SPAWN_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(DEFAULT_SPAWN_TIMEOUT_SECS)
}

/// Poll interval while waiting for a shutting-down minvmd to reach a terminal
/// state before deciding whether to spawn.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const STOPPING_POLL_MS: u64 = 100;

/// Max time to wait for an in-progress `minvmd stop` (SIGTERM → SIGKILL, ~5 s)
/// to finish before giving up with a clear error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const STOPPING_WAIT_SECS: u64 = 6;

/// What to do given the lifecycle read from `state.toml`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// minvmd is already up (or coming up); nothing to do.
    AlreadyRunning,
    /// minvmd is shutting down; wait for it to reach a terminal state first.
    WaitForStopping,
    /// minvmd is not running; spawn it.
    Spawn,
}

/// Pure mapping from a lifecycle state to the action the CLI should take. Kept
/// separate from the I/O so it can be exhaustively unit-tested. `Lifecycle` is
/// `#[non_exhaustive]`, so any future state is treated conservatively as "spawn".
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn classify(lifecycle: Lifecycle) -> Decision {
    match lifecycle {
        Lifecycle::Running | Lifecycle::Starting => Decision::AlreadyRunning,
        Lifecycle::Stopping => Decision::WaitForStopping,
        Lifecycle::Stopped | Lifecycle::NotProvisioned => Decision::Spawn,
        _ => Decision::Spawn,
    }
}

/// Check whether minvmd needs to be spawned, and spawn it if necessary (R4.5).
///
/// - Reads the minvmd state from `state.toml`.
/// - If already running/starting, returns immediately.
/// - If stopping, waits for the shutdown to finish, then spawns.
/// - Otherwise spawns `minvmd run --detach` with a timeout.
///
/// On targets with no minvmd backend this is a no-op (see below).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn ensure_minvmd_running() -> io::Result<()> {
    let state_dir = minvmd::state::StateDir::new(minvmd::state::StateDir::default_path())?;

    // Read current state (R4.5: check state.toml before connecting).
    match classify(state_dir.read_state()?.lifecycle) {
        Decision::AlreadyRunning => {
            tracing::debug!("minvmd already running or starting");
            return Ok(());
        }
        Decision::WaitForStopping => {
            // `minvmd stop` can take up to ~5 s (SIGTERM → SIGKILL escalation),
            // so a fixed short sleep usually leaves the daemon still Stopping.
            // Spawning then would make the new `minvmd run` bail on its own
            // Stopping guard, surfacing an opaque 8 s UDS timeout. Instead poll
            // until it reaches a terminal state, re-reading on each tick.
            tracing::info!("minvmd is stopping; waiting for it to finish");
            let deadline = Instant::now() + Duration::from_secs(STOPPING_WAIT_SECS);
            loop {
                thread::sleep(Duration::from_millis(STOPPING_POLL_MS));
                match classify(state_dir.read_state()?.lifecycle) {
                    // Something else restarted it in the meantime.
                    Decision::AlreadyRunning => return Ok(()),
                    // Shutdown completed; fall through to spawn.
                    Decision::Spawn => break,
                    Decision::WaitForStopping if Instant::now() >= deadline => {
                        return Err(io::Error::other(
                            "minvmd is still stopping after waiting; try again shortly",
                        ));
                    }
                    // Still stopping; keep polling.
                    Decision::WaitForStopping => continue,
                }
            }
        }
        Decision::Spawn => {
            // Not running; will spawn below.
        }
    }

    // Not running; spawn minvmd run --detach with timeout (R4.5).
    let timeout_secs = spawn_timeout_secs();
    tracing::info!("spawning minvmd run --detach with timeout {timeout_secs}");
    let output = Command::new("minvmd")
        .arg("run")
        .arg("--detach")
        .arg("--timeout")
        .arg(timeout_secs.to_string())
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

/// On targets without a minvmd backend (e.g. Windows), auto-spawn is a no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn ensure_minvmd_running() -> io::Result<()> {
    tracing::debug!("ensure_minvmd_running is a no-op on this platform");
    Ok(())
}

#[cfg(test)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests {
    use super::{Decision, classify};
    use minvmd::lifecycle::Lifecycle;

    #[test]
    fn running_or_starting_needs_no_spawn() {
        assert_eq!(classify(Lifecycle::Running), Decision::AlreadyRunning);
        assert_eq!(classify(Lifecycle::Starting), Decision::AlreadyRunning);
    }

    #[test]
    fn stopped_or_not_provisioned_spawns() {
        assert_eq!(classify(Lifecycle::Stopped), Decision::Spawn);
        assert_eq!(classify(Lifecycle::NotProvisioned), Decision::Spawn);
    }

    #[test]
    fn stopping_waits_for_terminal_state() {
        assert_eq!(classify(Lifecycle::Stopping), Decision::WaitForStopping);
    }
}
