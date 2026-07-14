//! libkrun FFI bring-up smoke test.
//!
//! Drives the safe wrappers end-to-end via the `krun_smoke_child` helper
//! binary. The helper runs in a child process because `krun_start_enter`
//! does not return on success — it `exit()`s with the guest workload's exit
//! code, which would tear down the test harness if called in-process.
//!
//! Gates:
//! - `#[cfg(target_os = "macos")]`: libkrun is macOS-only; the Linux build
//!   compiles this file to an empty crate so CI stays green.
//! - `#[ignore]`: skipped by default (run with `cargo test -- --include-ignored`).
//! - `MINVMD_E2E=1`: even with `--include-ignored`, the test self-skips
//!   unless the env var is set, so a Mac dev box can `cargo test` without
//!   spinning up libkrun.
//!
//! Two execution paths:
//! - **FFI bring-up only** (default): the child drives create_ctx →
//!   set_vm_config → set_exec and exits 0. Verifies the FFI surface plus
//!   RAII Drop. This is the path that proves the safe wrappers are sound
//!   without needing a kernel or rootfs.
//! - **Full start_enter** (when `MINVMD_KERNEL_PATH` and
//!   `MINVMD_ROOTFS_PATH` are both set): the child additionally configures
//!   the kernel and rootfs and calls `start_enter`. The dedicated boot
//!   end-to-end test exercises this path with the READY-marker round-trip;
//!   here we accept any clean exit code (0 / 2 / 125 / 126 / 127) as
//!   evidence the FFI made it across the boundary without a panic.

#![cfg(target_os = "macos")]

use std::process::Command;

/// Markers the helper must print before any branch.
const BRING_UP_MARKERS: &[&str] = &[
    "STAGE: create_ctx ok",
    "STAGE: set_vm_config ok",
    "STAGE: set_exec ok",
];

#[test]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun"]
fn krun_smoke_bring_up() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("krun_smoke: MINVMD_E2E != 1, skipping");
        return;
    }

    let exe = env!("CARGO_BIN_EXE_krun_smoke_child");
    let output = Command::new(exe)
        .output()
        .expect("spawning krun_smoke_child helper binary");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    eprintln!("--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}");

    let code = output
        .status
        .code()
        .expect("child must exit with a code, not a signal");

    // Bring-up surface markers are required on every run.
    for marker in BRING_UP_MARKERS {
        assert!(
            stderr.contains(marker),
            "missing bring-up marker {marker:?} in child stderr (exit code {code})\n--- stderr ---\n{stderr}",
        );
    }

    let kernel_set = std::env::var("MINVMD_KERNEL_PATH").is_ok();
    let rootfs_set = std::env::var("MINVMD_ROOTFS_PATH").is_ok();

    if kernel_set && rootfs_set {
        // Full path: helper called start_enter. Accept the libkrun-defined
        // exit code set per the function's own error-code documentation.
        assert!(
            stderr.contains("STAGE: start_enter"),
            "missing start_enter marker (full path)\n--- stderr ---\n{stderr}",
        );
        assert!(
            matches!(code, 0 | 2 | 125 | 126 | 127),
            "unexpected child exit code {code} on full path; expected 0 | 2 | 125 | 126 | 127",
        );
    } else {
        // Bring-up only: helper must signal it skipped start_enter and
        // exit 0 (RAII Drop cleaned up the context).
        assert!(
            stderr.contains("STAGE: skip_start_enter"),
            "missing skip_start_enter marker (bring-up path)\n--- stderr ---\n{stderr}",
        );
        assert_eq!(
            code, 0,
            "bring-up path must exit 0; got {code}\n--- stderr ---\n{stderr}",
        );
    }
}
