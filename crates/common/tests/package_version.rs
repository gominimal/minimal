//! Convention-discovered lint: the workspace `package.version` must be the
//! declared NEXT release.
//!
//! `crates/version` builds every dev version on `package.version`
//! (`0.6.0-dev.<N>.g<sha>`) and a release build bakes it in verbatim as
//! `MINIMAL_RELEASE_VERSION`, so a stale value names a version that already
//! shipped. `scripts/next-version.sh --check` asserts it is strictly greater
//! than the newest `v*` tag and at least what the Conventional Commits since
//! the last release require (`feat:` -> minor, otherwise patch; no major while
//! 0.x). This test drives that script from the workspace suite — the
//! reviewed-code extension point CI schedules over (docs/ci-strategy.md §10),
//! like `shell_lint.rs` — so drift fails at the PR that introduces it rather
//! than at the release.
//!
//! The derivation needs the tags and the history back to the last release.
//! On a shallow or tagless clone (the hosted PR lanes check out at depth 1
//! without tags) it self-skips with a message, matching the repo's
//! self-skip-locally convention; it runs for real on any full-history
//! checkout, and `just check-version` (part of `just ci`) is the local proof.

use std::path::PathBuf;
use std::process::Command;

/// The workspace root, from this crate's manifest dir.
fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/common; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/common")
        .to_path_buf()
}

/// `git <args>` in the repo root: trimmed stdout, or `None` when git fails or is absent.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo_root())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[test]
fn package_version_is_the_declared_next_release() {
    let Some(shallow) = git(&["rev-parse", "--is-shallow-repository"]) else {
        eprintln!(
            "git unavailable or not a repository — skipping package_version_is_the_declared_next_release"
        );
        return;
    };
    if shallow == "true" {
        eprintln!(
            "shallow clone (no history back to the last release) — skipping \
             package_version_is_the_declared_next_release; `just check-version` on a full checkout is the proof"
        );
        return;
    }
    if git(&["tag", "-l", "v[0-9]*"])
        .unwrap_or_default()
        .is_empty()
    {
        eprintln!(
            "no v* tags fetched — skipping package_version_is_the_declared_next_release; \
             `just check-version` on a full checkout is the proof"
        );
        return;
    }

    let script = repo_root().join("scripts").join("next-version.sh");
    let output = Command::new("bash")
        .arg(&script)
        .arg("--check")
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", script.display()));

    assert!(
        output.status.success(),
        "scripts/next-version.sh --check failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
}
