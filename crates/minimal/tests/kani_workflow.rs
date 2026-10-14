//! The Kani lane is path-scoped inside its frozen workflow: the `changes`
//! job runs the proofs on a pull request only when a listed prefix changed.
//! The Box Egress Proxy crate carries proofs of its own (docs/specs/24), so
//! a pull request touching only `crates/bep/**` must run the lane. This is
//! the plan's check for gominimal/minimal#1510: the frozen filter names the
//! crate, so no proof in it can go green by never being run.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/minimal; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/minimal")
        .to_path_buf()
}

/// The workflow's path and its `- "crates/..."` filter lines, trimmed.
fn kani_filter_lines() -> (PathBuf, Vec<String>) {
    let path = repo_root().join(".github/workflows/ci-kani.yml");
    let workflow =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let lines = workflow
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("- \"crates/"))
        .map(str::to_owned)
        .collect();
    (path, lines)
}

#[test]
fn kani_workflow_filter_names_bep_crate() {
    let (path, filter_lines) = kani_filter_lines();
    assert!(
        filter_lines.iter().any(|l| l == "- \"crates/bep/**\""),
        "the kani path filter in {} does not name crates/bep/**; found: {filter_lines:?}",
        path.display()
    );
}

/// The telemetry crate and the VM host daemon carry Kani harnesses of their
/// own (the switches' opt-in and endpoint rules and the spool prune plan;
/// the guest boot line's token writer and budget). The lane's runner,
/// `scripts/kani.sh`, must prove them with a harness count, so none can go
/// green by never being run.
///
/// This count is checked only when the lane runs. The workflow's path
/// filter does not name `crates/mlog/**` or `crates/minvmd/**`, so a pull
/// request that changes only one of their harnesses merges without a proof
/// run, and the lane finds the break on the next push to `main`. It runs on
/// a pull request only when `scripts/kani.sh`, `Cargo.toml`, `Cargo.lock` or
/// a listed crate changes. Workflows are frozen for this series: adding the
/// two crates to the filter is a workflow change a maintainer owns, tracked
/// in minimal#2075, and this test then gains a filter check like
/// `kani_workflow_filter_names_bep_crate`. Spec: TEL-001, TEL-002, TEL-004,
/// TEL-017 (their Kani proofs).
#[test]
fn kani_runner_proves_the_telemetry_crates() {
    let path = repo_root().join("scripts/kani.sh");
    let runner =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let expects: Vec<&str> = runner
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("expect "))
        .collect();
    for crate_name in ["mlog", "minvmd"] {
        assert!(
            expects.iter().any(|l| {
                let mut words = l.split_whitespace();
                words.next() == Some("expect")
                    && words.next() == Some(crate_name)
                    && words
                        .next()
                        .is_some_and(|n| n.parse::<u32>().is_ok_and(|n| n > 0))
            }),
            "{} does not expect a positive harness count for {crate_name}; found: {expects:?}",
            path.display()
        );
    }
}

/// One runaway harness cannot take the runner.
/// With `KANI_MEM_MAX` unset, the CI case, since the workflow sets none,
/// `scripts/kani.sh` caps each crate's `cargo kani` at 14G, and only an
/// explicit `KANI_MEM_MAX=off` runs without a ceiling. The runner's guard
/// block is run as written, under `sh` with no `systemd-run` on `PATH` (the
/// `ulimit` path a GitHub-hosted runner takes), and reports the ceiling it
/// chose.
#[test]
fn kani_runner_caps_memory_when_unset() {
    let path = repo_root().join("scripts/kani.sh");
    let runner =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (_, from_guard) = runner
        .split_once("# The memory guard, decided once")
        .unwrap_or_else(|| panic!("{} has no memory guard block", path.display()));
    let (guard, _) = from_guard
        .split_once("\n# `cargo kani` on one crate")
        .expect("the guard block ends before kani_crate");
    let empty_path = tempfile::TempDir::new().unwrap();
    let decide = |max: Option<&str>| {
        let mut sh = std::process::Command::new("/bin/sh");
        sh.env_clear()
            .env("PATH", empty_path.path())
            .arg("-c")
            .arg(format!(
                "set -eu\n# The memory guard{guard}\necho \"guard=$kani_guard kib=$kani_mem_kib\""
            ));
        if let Some(max) = max {
            sh.env("KANI_MEM_MAX", max);
        }
        let out = sh.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    assert_eq!(decide(None), "guard=ulimit kib=14680064", "unset: 14G");
    assert_eq!(decide(Some("8G")), "guard=ulimit kib=8388608");
    assert_eq!(decide(Some("off")), "guard= kib=", "off: no ceiling");
}
