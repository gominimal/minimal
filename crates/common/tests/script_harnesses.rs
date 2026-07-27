//! Convention-discovered gate that runs the `scripts/*_test.sh` harnesses.
//!
//! Sibling of [`shell_lint`](./shell_lint.rs), which only *lints* `scripts/`.
//! A harness that no lane runs is not a gate: `just test-linkage` was the only
//! executable proof of `rewrite-linux-linkage.sh`'s RUNPATH logic, and `just
//! ci` does not include it, `ci-shell-installer.yml` hardcodes install.sh, and
//! `shell_lint` only drives shellcheck — so a regression that dropped the
//! `$ORIGIN/../lib` entry would have been green on all five required
//! aggregators and surfaced only as `libkrun.so.1: cannot open shared object
//! file` on users' machines.
//!
//! Widening the frozen workflow YAML is not an option (CODEOWNER-gated), so
//! this hangs the harness off the workspace test suite the always-running Linux
//! lanes already execute — the reviewed-code extension point CI schedules over
//! (docs/ci-strategy.md §10).
//!
//! `install_test.sh` is deliberately NOT run here: `ci-shell-installer.yml`
//! already runs it under three shells, and duplicating it would double a
//! multi-minute job for no added coverage.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/common; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/common")
        .to_path_buf()
}

/// Runs one harness and asserts it exits zero, surfacing its output on failure.
///
/// The harnesses stub every external tool they need, so this holds on any host
/// — including macOS, where `rewrite-linux-linkage.sh` itself can never run.
fn run_harness(name: &str) {
    let root = repo_root();
    let harness = root.join("scripts").join(name);
    assert!(harness.is_file(), "missing script harness: {name}");

    let output = Command::new("bash")
        .arg(&harness)
        .current_dir(&root)
        .output()
        .unwrap_or_else(|e| panic!("failed to run scripts/{name}: {e}"));

    assert!(
        output.status.success(),
        "scripts/{name} failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn rewrite_linux_linkage_harness_passes() {
    run_harness("rewrite-linux-linkage_test.sh");
}
