//! Transport-agnostic gvproxy process management.
//!
//! gvproxy (containers/gvisor-tap-vsock) is a userspace network stack. Both
//! network paths in this workspace spawn it the same way — `gvproxy --fd <n>`,
//! where `<n>` is the file descriptor gvproxy reads and writes Ethernet frames
//! on — but they source that fd differently:
//!
//! - **macOS VM path** (`minvmd`): `<n>` is one end of a `socketpair`; the other
//!   end is handed to libkrun via `krun_set_passt_fd`. One gvproxy per VM.
//! - **Linux per-sandbox path** (`sandbox2`): `<n>` is the tap fd from
//!   hakoniwa's `Child::rustslirp_tapfd` after configuring the container with
//!   `Network::RustSlirp`. One gvproxy per sandbox.
//!
//! This crate owns only the parts that are identical across both: locating the
//! binary and spawning it with the fd. The fd handoff and lifecycle ownership
//! stay with each caller.

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Resolve the gvproxy binary path.
///
/// Returns the value of the `env_override` environment variable if set;
/// otherwise returns `"gvproxy"` (resolved via `PATH` by the OS at spawn).
/// `env_override` lets each caller keep its own override variable name
/// (e.g. `MINVMD_GVPROXY_PATH`).
#[must_use]
pub fn gvproxy_bin(env_override: &str) -> PathBuf {
    match std::env::var(env_override) {
        Ok(path) => {
            tracing::debug!(var = %env_override, path = %path, "using gvproxy path override");
            PathBuf::from(path)
        }
        Err(_) => {
            tracing::debug!(var = %env_override, "gvproxy path override unset, searching PATH");
            PathBuf::from("gvproxy")
        }
    }
}

/// Spawn the gvproxy child process.
///
/// Spawns `bin` with the argument `--fd <net_fd>`. Sets `stdin`, `stdout`, and
/// `stderr` to `Stdio::null()` (gvproxy logs over the fd, not stdio).
///
/// The caller is responsible for ensuring `net_fd` does **not** have
/// `FD_CLOEXEC` set before this call so it survives the spawn, and for reaping
/// the returned child.
///
/// Returns `Err` with a clear message when the binary is not found.
#[must_use = "the spawned child must be reaped"]
pub fn spawn_gvproxy(bin: impl AsRef<Path>, net_fd: RawFd) -> anyhow::Result<Child> {
    let bin = bin.as_ref();

    Command::new(bin)
        .arg("--fd")
        .arg(net_fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn gvproxy from {}: {e}", bin.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Serialise every test that mutates the environment behind a single lock.
    // `set_var`/`remove_var` mutate process-global state (and are `unsafe` on
    // the 2024 edition), so distinct per-variable locks would still let two
    // tests touch the environment concurrently. One lock covers all of them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn gvproxy_bin_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("GVPROXY_TEST_PATH", "/custom/path/to/gvproxy") };
        assert_eq!(
            gvproxy_bin("GVPROXY_TEST_PATH"),
            PathBuf::from("/custom/path/to/gvproxy")
        );
        unsafe { std::env::remove_var("GVPROXY_TEST_PATH") };
    }

    #[test]
    fn gvproxy_bin_unset_defaults_to_gvproxy() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("GVPROXY_TEST_PATH") };
        assert_eq!(gvproxy_bin("GVPROXY_TEST_PATH"), PathBuf::from("gvproxy"));
    }

    #[test]
    fn spawn_gvproxy_returns_error_when_binary_not_found() {
        let result = spawn_gvproxy("/nonexistent/gvproxy", 3);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to spawn gvproxy"),
            "error message: {err_msg}"
        );
    }
}
