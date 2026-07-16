//! Resource-monitoring VM end-to-end proof (#747): boot a real microVM and
//! verify the live status surface that no unit or process-mode test can reach,
//! because it needs an actual running VMM process.
//!
//! Proves, in one boot:
//! - a `config set --ram-mib` persisted **before** boot is consumed at that
//!   boot — the running VM's `status --json` reports it (R2.5/R2.6);
//! - `status --json` on a live VM carries host-visible resource `metrics`
//!   (numeric CPU / resident / disk-I/O, R9.1) and a `warnings` array (R9.9).
//!
//! Gates (identical to `boot_integration`): `#[cfg(minvmd_libkrun)]` (needs
//! libkrun), `#[ignore]` (run with `--run-ignored`), `MINVMD_E2E=1`, and the
//! three image env vars. Being a `*_integration.rs` harness it is auto-discovered
//! by both VM lanes' filterset, so it runs on Linux/KVM **and** the self-hosted
//! macOS/HVF lane — unlike `scripts/minvmd-lifecycle.sh`, which is KVM-only.

#![cfg(minvmd_libkrun)]

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serial_test::serial;

/// The minvmd binary under test: `MINVMD_BIN` when set (CI's split build/test
/// runners), else the compile-time cargo-built path.
fn minvmd_bin() -> OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// Isolated state dir under `/tmp`: macOS's `$TMPDIR` is deep enough that a
/// provider socket beneath a default tempdir would overflow `sun_path` (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// Run `minvmd <args>` isolated to `state` (both `HOME` and `XDG_STATE_HOME`,
/// belt-and-braces per `boot_integration`), capturing output. `MINVMD_VM_RAM_MIB`
/// is cleared so an ambient override can never mask the persisted config here.
fn minvmd(state: &Path, args: &[&str]) -> Output {
    Command::new(minvmd_bin())
        .args(args)
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        .env_remove("MINVMD_VM_RAM_MIB")
        .output()
        .expect("spawning minvmd")
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null)
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun + kernel/rootfs/initramfs"]
fn resource_metrics_and_config_consumed_at_boot() {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("resource_vm_integration: MINVMD_E2E != 1, skipping");
        return;
    }
    for var in [
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "resource_vm_integration: {var} must be set when MINVMD_E2E=1"
        );
    }

    let state = short_state_dir();
    let sd = state.path();

    // Tear the detached daemon down even if an assertion panics mid-test.
    struct Stopper<'a>(&'a Path);
    impl Drop for Stopper<'_> {
        fn drop(&mut self) {
            let _ = minvmd(self.0, &["stop"]);
        }
    }
    let _stopper = Stopper(sd);

    // 1. Persist a distinctive, MMIO-hole-safe RAM that differs from the arch
    //    default (2048 x86_64 / 4096 aarch64), so a running report of 3072 is
    //    unambiguous proof the persisted value — not the default — was used.
    let set = minvmd(sd, &["config", "set", "--ram-mib", "3072"]);
    assert!(
        set.status.success(),
        "config set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let show = json(&minvmd(sd, &["config", "show", "--json"]));
    assert_eq!(show["ram_mib"], 3072, "config show: {show}");
    assert_eq!(show["ram_mib_source"], "config", "config show: {show}");

    // 2. Boot the supervised VM (detached).
    let run = minvmd(sd, &["run", "--detach", "--timeout", "60"]);
    assert!(
        run.status.success(),
        "run --detach failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    // 3. `run --detach` returns once the host UDS accepts (opened early in VM
    //    setup), slightly ahead of the Starting->Running transition. Poll status
    //    for Running; generous deadline for a slow cold boot on the mac lane.
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        let v = json(&minvmd(sd, &["status", "--json"]));
        if v["state"] == "running" && v["vmm_pid"].is_number() {
            break v;
        }
        assert!(
            Instant::now() < deadline,
            "VM never reached Running; last status: {v}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    // 4. The live VM must report the persisted RAM (R2.5/R2.6) and live metrics
    //    (R9.1) + a warnings array (R9.9). cpu_percent and the disk counters can
    //    legitimately be 0 on an idle VM, so require numeric, not positive; a
    //    live VMM process always has resident_bytes > 0.
    assert_eq!(
        status["ram_mib"], 3072,
        "running VM must report the persisted ram_mib: {status}"
    );
    assert!(status["vcpus"].is_number(), "vcpus: {status}");
    let m = &status["metrics"];
    assert!(
        m.is_object(),
        "metrics must be an object while running: {status}"
    );
    assert!(m["cpu_percent"].is_number(), "cpu_percent: {status}");
    assert!(
        m["resident_bytes"].as_u64().is_some_and(|b| b > 0),
        "resident_bytes must be > 0: {status}"
    );
    assert!(
        m["disk_read_bytes"].is_number(),
        "disk_read_bytes: {status}"
    );
    assert!(
        m["disk_written_bytes"].is_number(),
        "disk_written_bytes: {status}"
    );
    assert!(
        status["warnings"].is_array(),
        "warnings must be an array: {status}"
    );

    // 5. Explicit stop, then confirm Stopped (the Stopper drop is a backstop).
    let stop = minvmd(sd, &["stop"]);
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let after = json(&minvmd(sd, &["status", "--json"]));
    assert_eq!(after["state"], "stopped", "status after stop: {after}");
}
