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

#[test]
fn kani_workflow_filter_names_bep_crate() {
    let path = repo_root().join(".github/workflows/ci-kani.yml");
    let workflow =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let filter_lines: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("- \"crates/"))
        .collect();
    assert!(
        filter_lines.contains(&"- \"crates/bep/**\""),
        "the kani path filter in {} does not name crates/bep/**; found: {filter_lines:?}",
        path.display()
    );
}
