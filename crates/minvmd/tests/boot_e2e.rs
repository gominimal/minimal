//! Boot end-to-end test: READY-marker round-trip (R2.4).
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]`: skipped by default; run with `cargo test -- --include-ignored`.
//! - `MINVMD_E2E=1`: even with `--include-ignored`, the test self-skips unless
//!   this env var is set (prevents accidental VM boot on a dev machine without
//!   a kernel and rootfs).
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, and `MINVMD_INITRAMFS` must be
//!   set to the paths of the `virtio-linux` kernel image, the `minvmd-rootfs`
//!   ext4 disk image, and the minimald initramfs cpio respectively.
//!
//! The test spawns `minvmd boot --foreground`, waits up to 10 s for the
//! `vm-up` marker on stdout, then kills the child. A `vm-up` line confirms
//! that the guest's `/init` (minimald) wrote `READY\n` to the vsock marker port
//! and the parent received it (R2.4).

#![cfg(minvmd_libkrun)]

use serial_test::serial;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// `<tempdir>/minimal/providers/local-0/*.sock` would overflow sun_path (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, and rootfs"]
fn boot_e2e_ready_marker_round_trip() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("boot_e2e: MINVMD_E2E != 1, skipping");
        return;
    }

    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "boot_e2e: {var} must be set when MINVMD_E2E=1"
        );
    }

    let state_dir = short_state_dir();

    let exe = env!("CARGO_BIN_EXE_minvmd");
    let mut child = Command::new(exe)
        .args(["boot", "--foreground"])
        .env("XDG_STATE_HOME", state_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawning minvmd boot --foreground");

    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line.trim() == "vm-up" {
                let _ = tx.send(true);
                return;
            }
        }
        let _ = tx.send(false);
    });

    let got_vm_up = rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false);

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        got_vm_up,
        "boot_e2e: did not receive 'vm-up' within 10 s; \
         check that the guest rootfs writes READY\\n to vsock port {}",
        minvmd::cmd::VSOCK_MARKER_PORT,
    );
}
