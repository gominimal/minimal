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

/// Default timeout in seconds to wait for the UDS when spawning minvmd (R4.5).
#[cfg(target_os = "macos")]
const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 8;

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
