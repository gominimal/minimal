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
pub mod error;
pub mod image;
pub mod lifecycle;
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
/// the process routes tracing output to the daily-rotated
/// `<state_dir>/logs/minvmd.log.<date>` instead of stdout — a detached
/// supervisor's stdout goes nowhere, and field diagnostics (`min bug`) need
/// the history on disk. Lives here (not `main.rs`) because the detach spawn
/// in `cmd::run` sets it and the binary entry point reads it.
pub const DETACHED_ENV: &str = "MINVMD_DETACHED";

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
