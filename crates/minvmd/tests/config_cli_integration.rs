//! `minvmd config` / `status --json` CLI end-to-end tests (#747, R2.3–R2.5,
//! R1.3).
//!
//! These drive the real `minvmd` binary against an isolated `XDG_STATE_HOME` and
//! need no VM, so — unlike the boot harness — they are neither `#[ignore]`d nor
//! `MINVMD_E2E`-gated and run on every lane. They prove the config surface and
//! the `status --json` schema through the actual CLI, including that a persisted
//! value is what the boot path's `effective_ram_mib()` would read (surfaced as
//! `ram_mib_source: "config"` by `config show`).

use std::process::Command;

/// The minvmd binary under test: `MINVMD_BIN` when set (CI's split build/test
/// runners), else the compile-time cargo-built path.
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// Run `minvmd <args>` with an isolated state dir; returns (success, stdout, stderr).
fn run(state_home: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(minvmd_bin())
        .args(args)
        .env("XDG_STATE_HOME", state_home)
        // Ensure no ambient override leaks into the effective-value resolution.
        .env_remove("MINVMD_VM_RAM_MIB")
        .env_remove("MINVMD_VM_VCPUS")
        .output()
        .expect("spawn minvmd");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn set_then_show_reports_persisted_value_and_source() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let (ok, _out, err) = run(tmp.path(), &["config", "set", "--ram-mib", "3072"]);
    assert!(ok, "config set must succeed; stderr: {err}");

    let (ok, out, err) = run(tmp.path(), &["config", "show", "--json"]);
    assert!(ok, "config show must succeed; stderr: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    assert_eq!(v["ram_mib"], 3072, "persisted value must be reported");
    assert_eq!(
        v["ram_mib_source"], "config",
        "a persisted value's source is config"
    );
    // vcpus was not set, so it falls back to the default.
    assert_eq!(v["vcpus_source"], "default");
}

#[test]
fn set_merges_without_clobbering_the_other_field() {
    let tmp = tempfile::tempdir().expect("tempdir");
    run(tmp.path(), &["config", "set", "--ram-mib", "2048"]);
    run(tmp.path(), &["config", "set", "--vcpus", "3"]);

    let (_ok, out, _err) = run(tmp.path(), &["config", "show", "--json"]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(
        v["ram_mib"], 2048,
        "earlier ram_mib must survive a later set"
    );
    assert_eq!(v["vcpus"], 3);
}

#[test]
fn invalid_values_are_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let (ok, _out, err) = run(tmp.path(), &["config", "set", "--vcpus", "0"]);
    assert!(!ok, "zero vcpus must be rejected");
    assert!(err.contains("at least 1"), "stderr: {err}");

    let (ok, _out, err) = run(tmp.path(), &["config", "set", "--ram-mib", "100"]);
    assert!(!ok, "sub-floor ram must be rejected");
    assert!(err.contains("at least 512"), "stderr: {err}");
}

#[test]
fn status_json_schema_when_stopped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // No daemon running → status exits 1 (stopped) but still prints JSON.
    let (_ok, out, _err) = run(tmp.path(), &["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("valid JSON");
    for key in [
        "state",
        "vmm_pid",
        "uptime_seconds",
        "vcpus",
        "ram_mib",
        "metrics",
    ] {
        assert!(v.get(key).is_some(), "status --json missing {key}: {out}");
    }
    assert_eq!(v["state"], "stopped");
    assert!(v["metrics"].is_null(), "metrics null when stopped");
}
