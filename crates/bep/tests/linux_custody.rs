//! The `bep` binary on a Linux host with nowhere to keep its keys (BEP-088).
//!
//! `bep_on_linux_with_no_store_prints_the_refusal` starts `bep` with no TPM
//! tools on `PATH` and a session bus address that nothing listens on, as on
//! a headless host without a TPM. The start must print the refusal that
//! says the host has no usable TPM and no keyring, exit non-zero, and
//! publish no identity file.
//!
//! `bep_with_no_bus_address_uses_the_bus_in_the_runtime_dir` starts `bep`
//! with no bus address in its environment, and checks where it looks.

#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;

/// The refusal that `bep` prints when neither the TPM nor Secret Service
/// can hold a key.
const NO_STORE: &str = "The proxy did not start: this host has no usable TPM and no unlocked Secret Service keyring, so the proxy has nowhere to keep its keys.";

// BEP-088
#[test]
fn bep_on_linux_with_no_store_prints_the_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let config = dir.path().join("config");
    let bin = dir.path().join("bin");
    for d in [&home, &config, &bin] {
        fs::create_dir_all(d).expect("mkdir");
    }
    // No `tpm2-tools` are on `PATH`, so no TPM can make a key. Nothing
    // listens on the session bus address, so no Secret Service answers.
    let out = Command::new(env!("CARGO_BIN_EXE_bep"))
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("PATH", &bin)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
        .env("RUST_LOG", "info")
        .output()
        .expect("run bep");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The `bep` output of the refused start, for whoever reads a failure.
    eprintln!("bep exit: {:?}\nbep stderr:\n{stderr}", out.status.code());

    assert!(!out.status.success(), "bep started:\n{stderr}");
    assert!(
        stderr.lines().any(|line| line == NO_STORE),
        "no refusal line in:\n{stderr}"
    );
    assert!(
        !stderr.contains("only on macOS"),
        "the refusal names the wrong host:\n{stderr}"
    );
    assert!(
        !home.join(".minimal/bep/identity.json").exists(),
        "bep published an identity:\n{stderr}"
    );
}

// A proxy that inherits no `DBUS_SESSION_BUS_ADDRESS`, as one that a daemon
// started outside a desktop session does, still looks for Secret Service:
// on the user's bus, at `$XDG_RUNTIME_DIR/bus`.
#[test]
fn bep_with_no_bus_address_uses_the_bus_in_the_runtime_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let config = dir.path().join("config");
    let bin = dir.path().join("bin");
    let runtime = dir.path().join("runtime");
    for d in [&home, &config, &bin, &runtime] {
        fs::create_dir_all(d).expect("mkdir");
    }
    let bus = std::os::unix::net::UnixListener::bind(runtime.join("bus")).expect("bind");
    bus.set_nonblocking(true).expect("nonblocking");
    let mut bep = Command::new(env!("CARGO_BIN_EXE_bep"))
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("PATH", &bin)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run bep");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let connected = loop {
        if bus.accept().is_ok() {
            break true;
        }
        if std::time::Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    // The bus here says nothing, so the proxy would wait on it.
    bep.kill().expect("stop bep");
    bep.wait().expect("reap bep");
    assert!(
        connected,
        "bep did not connect to the bus in XDG_RUNTIME_DIR"
    );
}
