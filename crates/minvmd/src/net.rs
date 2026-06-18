//! Network mode selection for `minvmd`-managed VMs (R1.1, R1.2).
//!
//! Defines the `NetworkMode` type (gvproxy vs. TSI) and resolves it from the
//! `MINVMD_NETMODE` env var. TSI is a libkrun feature with no analogue on other
//! transports, so the mode selection lives here rather than in the shared
//! [`gvproxy`] crate. The transport-agnostic gvproxy spawn/lookup helpers come
//! from that crate; `gvproxy_bin` below wraps the lookup with `minvmd`'s own
//! override variable.

use std::path::PathBuf;

#[doc(inline)]
pub use gvproxy::spawn_gvproxy;

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
#[must_use]
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

/// Resolve the path to the gvproxy binary from `MINVMD_GVPROXY_PATH`.
///
/// Defaults to `"gvproxy"` (resolved via `PATH` at spawn) when the variable is
/// unset. Thin wrapper over [`gvproxy::gvproxy_bin`] that binds `minvmd`'s
/// override variable name.
#[must_use]
pub fn gvproxy_bin() -> PathBuf {
    gvproxy::gvproxy_bin("MINVMD_GVPROXY_PATH")
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
    fn resolve_net_mode_unset_defaults_to_gvproxy() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
    }

    #[test]
    fn resolve_net_mode_gvproxy() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "gvproxy") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn resolve_net_mode_tsi() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "tsi") };
        assert_eq!(resolve_net_mode(), NetworkMode::Tsi);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn resolve_net_mode_invalid_falls_back_to_gvproxy() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_NETMODE", "invalid") };
        assert_eq!(resolve_net_mode(), NetworkMode::GvProxy);
        unsafe { std::env::remove_var("MINVMD_NETMODE") };
    }

    #[test]
    fn gvproxy_bin_from_env() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_GVPROXY_PATH", "/custom/path/to/gvproxy") };
        assert_eq!(gvproxy_bin(), PathBuf::from("/custom/path/to/gvproxy"));
        unsafe { std::env::remove_var("MINVMD_GVPROXY_PATH") };
    }

    #[test]
    fn gvproxy_bin_unset_defaults_to_gvproxy() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("MINVMD_GVPROXY_PATH") };
        assert_eq!(gvproxy_bin(), PathBuf::from("gvproxy"));
    }
}
