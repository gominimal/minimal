//! Network configuration and gvproxy process management (R1.1, R1.2).
//!
//! Defines the `NetworkMode` type (gvproxy vs. TSI), resolves the network
//! mode from the `MINVMD_NETMODE` env var, and manages gvproxy child process
//! spawn and lifecycle.

use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The two supported outbound network transport modes for `minvmd`-managed VMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Use gvproxy (containers/gvisor-tap-vsock) as the userspace network stack.
    /// This is the default and supports ~200+ concurrent outbound connections.
    GvProxy,
    /// Use libkrun's built-in TSI (Transport Socket Interface) shim.
    /// Fallback mode with a ~62-concurrent-connection cap.
    Tsi,
}

/// Resolve the network mode from the `MINVMD_NETMODE` environment variable.
///
/// Returns `NetworkMode::GvProxy` when the var is unset or set to `"gvproxy"`;
/// returns `NetworkMode::Tsi` when set to `"tsi"`. Any other value logs a
/// warning and falls back to `NetworkMode::GvProxy`.
pub fn resolve_net_mode() -> NetworkMode {
    match std::env::var("MINVMD_NETMODE").as_deref() {
        Ok("tsi") => {
            tracing::debug!("MINVMD_NETMODE=tsi: using TSI network mode");
            NetworkMode::Tsi
        }
        Ok("gvproxy") | Err(std::env::VarError::NotPresent) => {
            tracing::debug!("MINVMD_NETMODE=gvproxy (default): using gvproxy network mode");
            NetworkMode::GvProxy
        }
        Ok(other) => {
            tracing::warn!(
                value = %other,
                "MINVMD_NETMODE has unknown value, falling back to gvproxy"
            );
            NetworkMode::GvProxy
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!("MINVMD_NETMODE is not valid UTF-8, falling back to gvproxy");
            NetworkMode::GvProxy
        }
    }
}

/// Resolve the path to the gvproxy binary.
///
/// Returns the value of `MINVMD_GVPROXY_PATH` if set; otherwise returns
/// `"gvproxy"` (resolved via `PATH` by the OS when spawned).
pub fn gvproxy_bin() -> PathBuf {
    match std::env::var("MINVMD_GVPROXY_PATH") {
        Ok(path) => {
            tracing::debug!(path = %path, "using MINVMD_GVPROXY_PATH");
            PathBuf::from(path)
        }
        Err(_) => {
            tracing::debug!("MINVMD_GVPROXY_PATH unset, searching PATH for gvproxy");
            PathBuf::from("gvproxy")
        }
    }
}

/// Spawn the gvproxy child process.
///
/// Spawns the gvproxy binary (resolved via `gvproxy_bin()`) with the argument
/// `--fd <net_fd>`. Sets `stdin`, `stdout`, and `stderr` to `Stdio::null()`
/// (gvproxy logs over the FD, not stdio).
///
/// The caller is responsible for ensuring the `net_fd` end of the socketpair
/// does **not** have `FD_CLOEXEC` set before this call so it survives the spawn.
///
/// # Arguments
///
/// * `net_fd` — the file descriptor number of one end of the socketpair,
///   passed to gvproxy via `--fd`.
///
/// # Returns
///
/// Returns `Ok(Child)` with the spawned gvproxy process handle on success.
/// The caller is responsible for reaping the child.
///
/// Returns `Err` with a clear message when the gvproxy binary is not found.
pub fn spawn_gvproxy(net_fd: RawFd) -> anyhow::Result<Child> {
    let gvproxy_path = gvproxy_bin();

    let mut cmd = Command::new(&gvproxy_path);
    cmd.arg("--fd")
        .arg(net_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd.spawn().map_err(|e| {
        anyhow::anyhow!(
            "failed to spawn gvproxy from {}: {e}",
            gvproxy_path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Serialise all tests that mutate MINVMD_NETMODE / MINVMD_GVPROXY_PATH so
    // they don't race when `cargo test` runs them in parallel. Mutating
    // process-global env vars is `unsafe` on the 2024 edition.
    static NETMODE_LOCK: Mutex<()> = Mutex::new(());
    static GVPROXY_PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_net_mode_unset_defaults_to_gvproxy() {
        let _g = NETMODE_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
    }

    #[test]
    fn resolve_net_mode_gvproxy() {
        let _g = NETMODE_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "gvproxy") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn resolve_net_mode_tsi() {
        let _g = NETMODE_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "tsi") };
        assert_eq!(resolve_net_mode(), NetworkMode::Tsi);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn resolve_net_mode_invalid_falls_back_to_gvproxy() {
        let _g = NETMODE_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "invalid") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn gvproxy_bin_from_env() {
        let _g = GVPROXY_PATH_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_GVPROXY_PATH", "/custom/path/to/gvproxy") };
        assert_eq!(gvproxy_bin(), PathBuf::from("/custom/path/to/gvproxy"));
        unsafe { std::env::remove_var("MINVMD_GVPROXY_PATH") };
    }

    #[test]
    fn gvproxy_bin_unset_defaults_to_gvproxy() {
        let _g = GVPROXY_PATH_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("MINVMD_GVPROXY_PATH") };
        assert_eq!(gvproxy_bin(), PathBuf::from("gvproxy"));
    }

    #[test]
    fn spawn_gvproxy_returns_error_when_binary_not_found() {
        let _g = GVPROXY_PATH_LOCK.lock().unwrap();
        // Use a binary path that definitely does not exist.
        unsafe { std::env::set_var("MINVMD_GVPROXY_PATH", "/nonexistent/gvproxy") };
        let result = spawn_gvproxy(3);
        unsafe { std::env::remove_var("MINVMD_GVPROXY_PATH") };
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to spawn gvproxy"),
            "error message: {err_msg}"
        );
    }
}
