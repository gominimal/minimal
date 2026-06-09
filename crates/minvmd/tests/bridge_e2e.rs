//! Bridge end-to-end test: concurrent UDS↔vsock round-trips (R3.3, R3.4).
//!
//! Gates:
//! - `#[cfg(target_os = "macos")]`: libkrun is macOS-only.
//! - `#[ignore]`: skipped by default; run with `cargo test -- --include-ignored`.
//! - `MINVMD_E2E=1`: even with `--include-ignored`, the test self-skips unless
//!   this env var is set (prevents accidental VM boot on a dev machine without
//!   a kernel and rootfs).
//! - `MINVMD_KERNEL_PATH` and `MINVMD_ROOTFS_PATH` must point to the kernel
//!   image and the `minvmd-rootfs` ext4 disk image respectively.
//!
//! The test boots a VM via `minvmd boot --foreground`, waits up to 15 s for
//! `vm-up` on stdout, then opens 5 concurrent host UDS connections to the
//! minimald bridge socket. Each writes a distinct payload and reads back
//! exactly that many bytes (via `read_exact`). All 5 must succeed (R3.3, R3.4).
//!
//! The UDS is isolated per-run via a `tempfile::TempDir` set as
//! `XDG_RUNTIME_DIR`, so concurrent test runs on the same machine don't share
//! a socket path.

#![cfg(target_os = "macos")]

use serial_test::serial;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const CONCURRENT: usize = 5;
const BOOT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, and rootfs"]
fn bridge_e2e_concurrent_round_trip() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("bridge_e2e: MINVMD_E2E != 1, skipping");
        return;
    }

    for var in &["MINVMD_KERNEL_PATH", "MINVMD_ROOTFS_PATH"] {
        assert!(
            std::env::var(var).is_ok(),
            "bridge_e2e: {var} must be set when MINVMD_E2E=1"
        );
    }

    let runtime_dir = tempfile::TempDir::new().expect("creating isolated runtime dir");
    let state_dir = tempfile::TempDir::new().expect("creating isolated state dir");
    let sock_path = runtime_dir.path().join("minimal/minimald.sock");

    let exe = env!("CARGO_BIN_EXE_minvmd");
    let mut child = Command::new(exe)
        .args(["boot", "--foreground"])
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawning minvmd boot --foreground");

    // Wait for vm-up, signalling that the READY marker round-trip completed.
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

    let got_vm_up = rx.recv_timeout(BOOT_TIMEOUT).unwrap_or(false);
    if !got_vm_up {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "bridge_e2e: did not receive 'vm-up' within {} s; \
             check that the guest rootfs writes READY\\n to vsock port {} \
             and that MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH are correct",
            BOOT_TIMEOUT.as_secs(),
            minvmd::cmd::VSOCK_MARKER_PORT,
        );
    }

    // The guest stub sends READY before exec-ing the vsock 2222 listener.
    // Brief sleep to reduce initial connection failures; the per-connection
    // retry loop below handles races if socat is not yet listening.
    std::thread::sleep(Duration::from_millis(200));

    // Open 5 concurrent host UDS connections; each writes a distinct payload
    // and reads it back through the libkrun UDS↔vsock bridge (R3.3, R3.4).
    let handles: Vec<_> = (0..CONCURRENT)
        .map(|i| {
            let path = sock_path.clone();
            std::thread::spawn(move || -> Result<(), String> {
                let payload = format!("BRIDGE_PAYLOAD_{i}\n");

                // Retry briefly in case the guest's socat listener is not yet up.
                let mut stream = {
                    let mut last_err = None;
                    let mut conn = None;
                    for _ in 0..10 {
                        match UnixStream::connect(&path) {
                            Ok(s) => {
                                conn = Some(s);
                                break;
                            }
                            Err(e) => {
                                last_err = Some(e);
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                    match conn {
                        Some(s) => s,
                        None => return Err(format!("connect: {}", last_err.unwrap())),
                    }
                };

                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| format!("set_read_timeout: {e}"))?;

                stream
                    .write_all(payload.as_bytes())
                    .map_err(|e| format!("write: {e}"))?;

                // Read back exactly as many bytes as we sent. This avoids
                // relying on write-side shutdown propagation through the
                // UDS↔vsock bridge; cat echoes data as it arrives, so
                // read_exact is sufficient and never blocks waiting for EOF.
                let mut got = vec![0u8; payload.len()];
                stream
                    .read_exact(&mut got)
                    .map_err(|e| format!("read_exact: {e}"))?;

                if got == payload.as_bytes() {
                    Ok(())
                } else {
                    Err(format!(
                        "payload mismatch: expected {payload:?}, got {:?}",
                        String::from_utf8_lossy(&got)
                    ))
                }
            })
        })
        .collect();

    let results: Vec<Result<(), String>> = handles
        .into_iter()
        .map(|h| {
            h.join()
                .unwrap_or_else(|_| Err("thread panicked".to_string()))
        })
        .collect();

    let _ = child.kill();
    let _ = child.wait();

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "bridge_e2e: connection {i} failed round-trip: {:?}",
            result
        );
    }
}
