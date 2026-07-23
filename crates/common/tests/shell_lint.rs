//! Convention-discovered gate that shellchecks every script under `scripts/`.
//!
//! The frozen `ci-shell-installer.yml` shellcheck job only lints `install.sh`
//! and `install_test.sh`; every other shell script was unchecked, so a PR
//! touching one reported a misleading "skipping" shellcheck context (#899).
//! Widening that job would mean editing `.github/workflows/`, which is frozen
//! and CODEOWNER-gated. Instead this test drives `scripts/lint-shell.sh`, so
//! the workspace test suite — which the always-running Linux CI lanes run on
//! any `crates/**` or `scripts/**` change — lints the whole directory. This is
//! the reviewed-code extension point CI schedules over (docs/ci-strategy.md
//! §10): a new *kind* of check added through code, never through YAML.
//!
//! When shellcheck is not installed the test skips with a message rather than
//! failing, matching the harness's own lenient default and the repo's
//! self-skip-locally convention. The primary Linux lane (ubuntu-latest) ships
//! shellcheck, so the gate runs for real and fails on findings there.

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

#[test]
fn all_scripts_pass_shellcheck() {
    if Command::new("shellcheck")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("shellcheck not installed — skipping all_scripts_pass_shellcheck");
        return;
    }

    let root = repo_root();
    let harness = root.join("scripts/lint-shell.sh");
    // We already confirmed shellcheck is on PATH above, so run --strict: if the
    // harness can't find it (a PATH mismatch, not a genuine absence) that is a
    // hard failure, never a silent green.
    let output = Command::new("bash")
        .arg(&harness)
        .arg("--strict")
        .current_dir(&root)
        .output()
        .expect("failed to run scripts/lint-shell.sh");

    assert!(
        output.status.success(),
        "scripts/lint-shell.sh reported shellcheck findings\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
