//! Convention-discovered gate that runs every `scripts/*_test.sh` harness.
//!
//! The release/publishing scripts this repo grew (semver resolution, the
//! version assertion, the staged-version lookup, the packaging renderer, the
//! AUR and Homebrew publishers) are shell, and no frozen workflow schedules
//! their harnesses. This test is the extension point the repo documents for
//! exactly that shape (docs/ci-strategy.md §10; the reviewed precedent is
//! `crates/common/tests/shell_lint.rs` driving `scripts/lint-shell.sh`): the
//! workspace suite runs on any `crates/**` or `scripts/**` change in the
//! always-on Linux lanes, so a new `*_test.sh` under `scripts/` is picked up
//! by convention and a harness that stops passing fails the PR — without
//! editing `.github/workflows/`.
//!
//! Each harness owns its own skip logic for tools it needs (the repo's
//! self-skip-locally convention — see the resolve harness's git guard), so
//! this runner only dispatches them and fails on a non-zero exit. `just
//! test-shell` runs the same set locally.

use std::path::{Path, PathBuf};
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
fn all_script_test_harnesses_pass() {
    let scripts_dir = repo_root().join("scripts");

    let mut harnesses = Vec::new();
    for entry in std::fs::read_dir(&scripts_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", scripts_dir.display()))
    {
        // An unreadable entry is a broken gate, not one harness fewer: fail
        // loudly instead of silently passing a subset of the suite.
        let path = entry
            .unwrap_or_else(|e| {
                panic!(
                    "cannot enumerate an entry of {}: {e}",
                    scripts_dir.display()
                )
            })
            .path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("_test.sh"))
        {
            harnesses.push(path);
        }
    }
    harnesses.sort();

    assert!(
        !harnesses.is_empty(),
        "no scripts/*_test.sh harnesses found — the convention-discovered shell gate found nothing to run"
    );

    let mut failures = Vec::new();
    for harness in &harnesses {
        let name = harness.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let output = Command::new(declared_interpreter(harness))
            .arg(harness)
            .current_dir(repo_root())
            .output()
            .unwrap_or_else(|e| panic!("cannot run {}: {e}", harness.display()));

        if output.status.success() {
            println!("{name}: ok");
        } else {
            failures.push(format!(
                "{name} failed ({}):\n{}{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "shell test harnesses failed:\n{}",
        failures.join("\n---\n")
    );
}

/// The harness's own declared interpreter, not a hardcoded bash:
/// install_test.sh is a POSIX-sh harness (the shell-installer lane proves it
/// under dash), and running it under bash would not test that contract.
fn declared_interpreter(script: &Path) -> &'static str {
    let first = std::fs::read_to_string(script)
        .ok()
        .and_then(|first| first.lines().next().map(str::to_owned))
        .unwrap_or_default();
    let bin = first
        .strip_prefix("#!")
        .unwrap_or("")
        .split_whitespace()
        .next_back()
        .unwrap_or("");
    if bin.rsplit('/').next_back() == Some("sh") {
        "sh"
    } else {
        "bash"
    }
}
