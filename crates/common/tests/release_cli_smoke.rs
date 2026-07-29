//! Convention-discovered gate for the CLI invocations the release job makes.
//!
//! `release.yml`'s "Generate completions" step runs `mip` / `min` / `minimald`
//! against the binaries it just built, but only on a `workflow_dispatch`
//! release — so a breaking CLI change clears every PR gate and only surfaces
//! when someone cuts a release, an hour of build time in, taking the GCS
//! upload, the GitHub Release and `stage-installer` with it (#1035; the
//! `completions <shell>` → `completions print <shell>` split shipped that way
//! for twenty days, #1009/#1034).
//!
//! Gating the release job from inside itself would mean editing
//! `.github/workflows/`, which is frozen and CODEOWNER-gated. Instead this test
//! drives `scripts/release-cli-smoke.sh`, which reads those invocations back
//! out of the workflow and replays them against the debug binaries — so the
//! workspace suite the always-running Linux lanes execute is the pre-merge
//! gate. This is the reviewed-code extension point CI schedules over
//! (docs/ci-strategy.md §10): a new *kind* of check added through code, never
//! through YAML.

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

/// The directory cargo built this test into (`<target>/<profile>/deps/..`),
/// which is also where the binaries under test land. Derived rather than
/// assumed so a custom `CARGO_TARGET_DIR` or profile still resolves — cargo
/// does not export either to the test process.
fn bin_dir() -> PathBuf {
    std::env::current_exe()
        .expect("test binary path")
        .parent()
        .and_then(|deps| deps.parent())
        .expect("<target>/<profile> two levels above the test binary")
        .to_path_buf()
}

#[test]
fn release_job_cli_invocations_still_work() {
    let root = repo_root();
    // `--build`: under the workspace suite the binaries are already there and
    // this is a no-op, but a bare `cargo test -p common` has not built them —
    // build rather than skip, so the gate can never quietly cover nothing.
    let output = Command::new("bash")
        .arg(root.join("scripts/release-cli-smoke.sh"))
        .arg("--build")
        .env("BIN_DIR", bin_dir())
        .current_dir(&root)
        .output()
        .expect("failed to run scripts/release-cli-smoke.sh");

    assert!(
        output.status.success(),
        "scripts/release-cli-smoke.sh failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
