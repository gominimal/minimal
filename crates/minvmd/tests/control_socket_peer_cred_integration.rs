//! Peer-credential and provider-directory verification tests for the
//! minvmd control socket.
//!
//! These tests exercise the peer-uid check on every control-socket
//! connection and the provider-directory ownership/mode verification at
//! bind time. They need a running minvmd daemon (which requires libkrun
//! and a kernel/rootfs), so they are gated behind the same env vars as
//! the other VM integration tests.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun.
//! - `#[ignore]`: skipped by default; run with `cargo test -- --include-ignored`.
//! - `MINVMD_E2E=1`: self-skips unless set.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must be set.

#![cfg(minvmd_libkrun)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serial_test::serial;

fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

fn require_e2e_env() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("control_socket_peer_cred: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        if std::env::var(var).is_err() {
            eprintln!("control_socket_peer_cred: {var} not set, skipping");
            return false;
        }
    }
    true
}

/// Resolve the control socket path for a state dir.
fn control_sock_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir
        .join("minimal")
        .join("providers")
        .join("local-minvmd0")
        .join("control.sock")
}

/// Write a register request and read the reply.
fn register_box(sock_path: &std::path::Path, name: &str) -> String {
    let mut stream = UnixStream::connect(sock_path).expect("connect to control socket");
    let request =
        format!(r#"{{"verb":"register","name":"{name}","ingress_ports":[],"egress":null}}"#);
    stream
        .write_all(format!("{request}\n").as_bytes())
        .expect("write request");
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .expect("read reply");
    reply
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel, and rootfs"]
fn control_socket_admits_own_uid() {
    if !require_e2e_env() {
        return;
    }
    let state_dir = short_state_dir();
    let mut child = Command::new(minvmd_bin())
        .env("XDG_STATE_HOME", state_dir.path())
        .arg("boot")
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("minvmd boot starts");

    let sock_path = control_sock_path(state_dir.path());
    for _ in 0..1000 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sock_path.exists(), "control socket was not created");

    let reply = register_box(&sock_path, "web");
    assert!(
        reply.contains("switch_address"),
        "own-uid connection is served, got: {reply}"
    );

    child.kill().expect("kill minvmd");
    child.wait().expect("reap minvmd");
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel, rootfs, and sudo"]
fn control_socket_refuses_foreign_uid() {
    if !require_e2e_env() {
        return;
    }
    // Check that sudo -u nobody works.
    let status = Command::new("sudo")
        .args(["-u", "nobody", "--", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: sudo -u nobody not available on this runner");
            return;
        }
    }

    let state_dir = short_state_dir();
    let mut child = Command::new(minvmd_bin())
        .env("XDG_STATE_HOME", state_dir.path())
        .arg("boot")
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("minvmd boot starts");

    let sock_path = control_sock_path(state_dir.path());
    for _ in 0..1000 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(sock_path.exists(), "control socket was not created");

    // Connect as nobody — the peer uid differs from the daemon's.
    let output = Command::new("sudo")
        .args([
            "-u",
            "nobody",
            "--",
            "python3",
            "-c",
            &format!(
                "import socket; \
                 s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); \
                 s.connect('{}'); \
                 s.sendall(b'{{\"verb\":\"register\",\"name\":\"evil\",\"ingress_ports\":[],\"egress\":null}}\\n'); \
                 try: \
                     reply = s.makefile().readline(); \
                     print(reply, end=''); \
                 except Exception as e: \
                     print('REFUSED:' + str(e))",
                sock_path.display(),
            ),
        ])
        .output()
        .expect("sudo connect as nobody");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty() || stdout.contains("REFUSED"),
        "foreign-uid connection must be refused, got: {stdout}"
    );

    // The daemon still serves own-uid connections after a refusal.
    let reply = register_box(&sock_path, "legit");
    assert!(
        reply.contains("switch_address"),
        "own-uid connection still served after a foreign-uid refusal, got: {reply}"
    );

    child.kill().expect("kill minvmd");
    child.wait().expect("reap minvmd");
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel, and rootfs"]
fn bind_refuses_provider_dir_not_owned_or_not_0700() {
    if !require_e2e_env() {
        return;
    }
    let state_dir = short_state_dir();
    let provider_dir = state_dir
        .path()
        .join("minimal")
        .join("providers")
        .join("local-minvmd0");
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(&provider_dir)
        .expect("create provider dir");

    // Set mode 0755 — not 0700.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&provider_dir, std::fs::Permissions::from_mode(0o755))
        .expect("set perms");

    let output = Command::new(minvmd_bin())
        .env("XDG_STATE_HOME", state_dir.path())
        .arg("boot")
        .arg("--foreground")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("minvmd boot starts")
        .wait_with_output()
        .expect("minvmd exits");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "minvmd must refuse to start with a mis-moded provider dir"
    );
    assert!(
        stderr.contains("0755") || stderr.contains("expected 0700"),
        "error must name the actual mode, got: {stderr}"
    );
}
