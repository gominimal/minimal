//! minimald session end-to-end: a real client reaches minimald's SSH server
//! over the libkrun bridge (Stage 2).
//!
//! This is the reliable counterpart to ad-hoc `ssh`/`socat`/`nc` testing, which
//! does NOT round-trip the libkrun host-UDS↔vsock bridge (even the socat-echo
//! stub returns nothing via the CLI, while `bridge_e2e`'s Rust `UnixStream` +
//! `read_exact` passes). So we validate the session path the same way: a Rust
//! `UnixStream` to the bridge UDS, then an SSH banner exchange with the in-guest
//! minimald (russh) server. A `SSH-2.0-*` banner back proves the full path
//! host UDS → libkrun bridge → guest vsock → minimald SSH.
//!
//! Gates:
//! - `#[cfg(target_os = "macos")]`: libkrun is macOS-only.
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH` + `MINVMD_ROOTFS_PATH` must point to the kernel and a
//!   rootfs with `minimald` baked in at `/sbin/minimald` plus the
//!   `/sbin/minimald-init` wrapper. The test sets `MINVMD_EXEC` to that wrapper.
//!
//! Scope: this proves the transport reaches minimald's SSH server. A full
//! authenticated `CreateSession` + exec round-trip (an in-process russh client)
//! is a follow-up that builds on this.

#![cfg(target_os = "macos")]

use serial_test::serial;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const BOOT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, and a minimald rootfs"]
fn minimald_ssh_banner_over_bridge() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("minimald_session_e2e: MINVMD_E2E != 1, skipping");
        return;
    }
    for var in &["MINVMD_KERNEL_PATH", "MINVMD_ROOTFS_PATH"] {
        assert!(
            std::env::var(var).is_ok(),
            "minimald_session_e2e: {var} must be set when MINVMD_E2E=1"
        );
    }

    let runtime_dir = tempfile::TempDir::new().expect("creating isolated runtime dir");
    let state_dir = tempfile::TempDir::new().expect("creating isolated state dir");
    let sock_path = runtime_dir.path().join("minimal/minimald.sock");

    let exe = env!("CARGO_BIN_EXE_minvmd");
    let mut child = Command::new(exe)
        .args(["boot", "--foreground"])
        // Run minimald as the guest init (the wrapper execs `minimald run --guest`).
        .env("MINVMD_EXEC", "/sbin/minimald-init")
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawning minvmd boot --foreground");

    // Wait for vm-up — minimald emitted its READY marker.
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

    if !rx.recv_timeout(BOOT_TIMEOUT).unwrap_or(false) {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "minimald_session_e2e: no 'vm-up' within {} s; is minimald baked into the rootfs \
             at /sbin/minimald(-init) and MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH correct?",
            BOOT_TIMEOUT.as_secs(),
        );
    }

    // minimald binds the UDS + starts the vsock relay around READY; retry the
    // whole exchange a few times to absorb a startup race (a closed connection
    // before the relay/listener is fully wired up).
    std::thread::sleep(Duration::from_millis(500));
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=8 {
        result = ssh_banner_exchange(&sock_path);
        if result.is_ok() {
            break;
        }
        eprintln!("attempt {attempt}: {result:?}");
        std::thread::sleep(Duration::from_millis(400));
    }

    let _ = child.kill();
    let _ = child.wait();

    let banner = result.unwrap_or_else(|e| panic!("minimald_session_e2e: {e}"));
    assert!(
        banner.starts_with("SSH-2.0"),
        "expected an SSH-2.0 banner from minimald, got {banner:?}"
    );
    eprintln!("minimald_session_e2e: got server banner {banner:?}");
}

/// Connect to the bridge UDS, send a client SSH id string, and read the
/// server's id string (the first CRLF-terminated line). Returns the banner.
fn ssh_banner_exchange(sock_path: &std::path::Path) -> Result<String, String> {
    let mut stream = {
        let mut conn = None;
        let mut last_err = None;
        for _ in 0..20 {
            match UnixStream::connect(sock_path) {
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
        conn.ok_or_else(|| format!("connect to bridge UDS: {}", last_err.unwrap()))?
    };
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("set_read_timeout: {e}"))?;

    // RFC 4253: each side sends its identification string on connect.
    stream
        .write_all(b"SSH-2.0-minvmd_e2e\r\n")
        .map_err(|e| format!("write client id: {e}"))?;

    // Read the server id line (bytes up to LF), tolerant of pre-banner lines.
    let mut reader = BufReader::new(stream);
    for _ in 0..10 {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("read server id: {e}"))?;
        if n == 0 {
            return Err("connection closed before any SSH banner".into());
        }
        let line = line.trim_end().to_string();
        if line.starts_with("SSH-") {
            return Ok(line);
        }
        // SSH servers may emit informational lines before the id string; skip.
    }
    Err("no SSH banner within the first lines".into())
}
