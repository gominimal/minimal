//! `minvmd` — the host daemon that brings up a Linux microVM via libkrun,
//! supervises its lifecycle, and bridges a host UDS to a vsock port inside the
//! VM so the `minimal` CLI can talk to `minimald` transparently.
//!
//! The real (libkrun-linking) implementation is gated on the `minvmd_libkrun`
//! cfg emitted by the build script: always set on macOS (Hypervisor.framework),
//! and set on Linux when libkrun is installed (KVM). Without it the crate
//! compiles to a runtime-bailing stub so stock Linux CI — which has no libkrun —
//! stays green. The `krun` module links libkrun and so compiles only under that
//! cfg; the portable surface (errors, state, image resolution) compiles
//! everywhere.

pub mod cmd;
pub mod config;
pub mod error;
pub mod image;
pub mod lifecycle;
pub mod metrics;
pub mod net;
pub(crate) mod rpc_client;
pub mod sock;
pub mod state;
pub mod vm;
pub mod volume;

#[cfg(minvmd_libkrun)]
pub mod krun;

pub use error::VmError;

/// Env marker set on the re-exec'd child by `run --detach`. When present,
/// the process routes tracing output to the size-rotated
/// `<state_dir>/logs/minvmd.log` instead of stdout — a detached supervisor's
/// stdout goes nowhere, and field diagnostics (`min bug`) need the history
/// on disk. Lives here (not `main.rs`) because the detach spawn in
/// `cmd::run` sets it and the binary entry point reads it.
pub const DETACHED_ENV: &str = "MINVMD_DETACHED";

/// Rotate the daemon log at this size; with [`LOG_KEEP_FILES`] retained
/// archives this bounds a daemon's log footprint to ~60 MiB.
pub const LOG_ROTATE_SIZE_MB: u64 = 10;
/// Rotated archives kept on disk (`minvmd.log.1` newest … `.5` oldest).
pub const LOG_KEEP_FILES: u64 = 5;

/// The size-rotated, retention-bounded file appender both daemon log paths
/// use (minvmd here; minimald mirrors the same scheme on the data volume).
/// Rotated files shift logrotate-style: the live file keeps the bare name,
/// `.1` is the most recently rotated.
pub fn build_log_roller(
    dir: &std::path::Path,
    filename: &str,
) -> Result<logroller::LogRoller, logroller::LogRollerError> {
    roller_with(
        dir,
        filename,
        logroller::RotationSize::MB(LOG_ROTATE_SIZE_MB),
        LOG_KEEP_FILES,
    )
}

fn roller_with(
    dir: &std::path::Path,
    filename: &str,
    size: logroller::RotationSize,
    keep: u64,
) -> Result<logroller::LogRoller, logroller::LogRollerError> {
    logroller::LogRollerBuilder::new(dir, std::path::Path::new(filename))
        .rotation(logroller::Rotation::SizeBased(size))
        .max_keep_files(keep)
        // Archive publication happens on a background thread; graceful
        // shutdown joins it on drop, so releasing the appender (before a
        // volume unmount, or at process exit) leaves no `.pending.` orphans.
        .graceful_shutdown(true)
        .build()
}

#[cfg(test)]
mod log_rotation {
    use std::io::Write as _;

    #[test]
    fn writing_past_the_threshold_rotates_and_prunes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut roller = super::roller_with(
            tmp.path(),
            "minvmd.log",
            logroller::RotationSize::Bytes(64),
            2,
        )
        .unwrap();
        for i in 0..20 {
            writeln!(roller, "record {i:02} padding-to-force-rotation").unwrap();
        }
        drop(roller);

        let mut names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["minvmd.log", "minvmd.log.1", "minvmd.log.2"],
            "live file plus exactly max_keep_files rotated archives"
        );
    }
}

#[cfg(test)]
mod integration_naming_convention {
    //! Guards the integration-test auto-discovery contract. The KVM and macOS
    //! lanes select these harnesses by binary-name suffix —
    //! `binary(/_integration$/)` for the non-root step, `binary(/_root_integration$/)`
    //! for the root step — instead of an explicit per-test list, so a new
    //! `crates/minvmd/tests/*_integration.rs` file runs with no workflow edit. A
    //! harness whose name lacks the suffix would silently drop out of every VM
    //! lane; this normal unit test (runs in `core-tests`, no libkrun needed)
    //! fails loudly instead. Shared, non-harness helpers live in subdirectories
    //! (e.g. `tests/common/mod.rs`) and are excluded here because they are not
    //! top-level `*.rs` files.
    //!
    //! When to reach for which:
    //! - `*_integration.rs` (add `_root` → `*_root_integration.rs` if it needs
    //!   `CAP_NET_ADMIN`): a component/subsystem proof that needs real resources
    //!   a unit test can't provide — boot a microVM, round-trip the vsock bridge,
    //!   drive the libkrun FFI, check a real ext4 volume. Scope is one component;
    //!   drop the file in `tests/` and the target lane runs it, no CI edit.
    //! - A full-system, user's-eye proof that drives the `minimal` CLI end to end
    //!   is NOT an integration harness — those live as scripts under `scripts/`
    //!   (e.g. `session-e2e.sh`) and are wired per lane.

    #[test]
    fn every_integration_test_binary_ends_in_integration() {
        let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let offenders: Vec<String> = std::fs::read_dir(&tests_dir)
            .expect("minvmd/tests directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
            .filter_map(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            // `_root_integration.rs` also ends in `_integration.rs`, so both variants pass.
            .filter(|name| !name.ends_with("_integration.rs"))
            .collect();
        assert!(
            offenders.is_empty(),
            "every integration test in crates/minvmd/tests/ must end in `_integration.rs` \
             (root harnesses in `_root_integration.rs`) so the VM lanes auto-discover it; \
             offenders: {offenders:?}"
        );
    }
}
