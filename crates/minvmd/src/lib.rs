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

#[cfg(test)]
mod e2e_naming_convention {
    //! Guards the VM e2e auto-discovery contract (N7). The KVM lane selects
    //! harnesses by binary-name suffix — `binary(/_e2e$/)` for the non-root
    //! step, `binary(/_root_e2e$/)` for the root step — instead of an explicit
    //! per-test list, so a new `crates/minvmd/tests/*_e2e.rs` file runs with no
    //! workflow edit. A harness whose name lacks the suffix would silently drop
    //! out of every VM lane; this normal unit test (runs in `core-tests`, no
    //! libkrun needed) fails loudly instead. Shared, non-harness helpers live
    //! in subdirectories (e.g. `tests/common/mod.rs`) and are excluded here
    //! because they are not top-level `*.rs` files.

    #[test]
    fn every_integration_test_binary_ends_in_e2e() {
        let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let offenders: Vec<String> = std::fs::read_dir(&tests_dir)
            .expect("minvmd/tests directory must exist")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
            .filter_map(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
            // `_root_e2e.rs` also ends in `_e2e.rs`, so both variants pass.
            .filter(|name| !name.ends_with("_e2e.rs"))
            .collect();
        assert!(
            offenders.is_empty(),
            "every integration test in crates/minvmd/tests/ must end in `_e2e.rs` \
             (root harnesses in `_root_e2e.rs`) so the VM lanes auto-discover it; \
             offenders: {offenders:?}"
        );
    }
}
