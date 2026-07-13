use std::collections::BTreeMap;

pub mod channel_progress;
pub mod connection;
pub mod env;
mod exec;
#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
pub mod net;
pub mod rpc;
pub mod server;
mod session;
pub mod session_host;
mod sessions;
mod sftp;
#[cfg(any(test, feature = "test-support"))]
pub mod test_harness;

/// Env var that the client must set (via `env_request`) before the SFTP
/// subsystem request, naming which session the SFTP channel attaches to.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Represents the parameters of a requested PTY.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RequestedPty {
    char_sizes: (u32, u32),
    pixel_sizes: (u32, u32),
    term: String,
    modes: Vec<(russh::Pty, u32)>,
}

/// Represents the currently configured parameters for a channel being created.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ChannelConfig {
    pub(crate) env_vars: BTreeMap<String, String>,
    pub(crate) pty: Option<RequestedPty>,
}

#[cfg(test)]
mod e2e_naming_convention {
    //! Guards the root-e2e auto-discovery contract. The native lane's
    //! `minimald-root-e2e` job selects harnesses by binary-name suffix
    //! (`-E 'binary(/_root_e2e$/)'`) instead of a hardcoded `--test` list, so a
    //! new `crates/minimald/tests/*_root_e2e.rs` runs with no workflow edit. A
    //! root harness whose name lacks the suffix would silently drop out of that
    //! job; this unit test (runs in `core-tests`) fails loudly instead.

    /// Files intentionally NOT auto-discovered: `mesh_uc7` is the mothballed
    /// WireGuard UC7 proof (feature `networking-wg`, off by default, no CI lane
    /// runs it), so it deliberately keeps a non-convention name.
    const ALLOWLIST: &[&str] = &["mesh_uc7.rs"];

    #[test]
    fn every_integration_test_binary_ends_in_e2e() {
        let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let offenders: Vec<String> = std::fs::read_dir(&tests_dir)
            .expect("minimald/tests directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
            .filter_map(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            // `_root_e2e.rs` also ends in `_e2e.rs`, so both variants pass.
            .filter(|name| !name.ends_with("_e2e.rs") && !ALLOWLIST.contains(&name.as_str()))
            .collect();
        assert!(
            offenders.is_empty(),
            "every integration test in crates/minimald/tests/ must end in `_e2e.rs` \
             (root harnesses in `_root_e2e.rs`) so the native lane auto-discovers it, \
             or be added to ALLOWLIST if deliberately un-run; offenders: {offenders:?}"
        );
    }
}
