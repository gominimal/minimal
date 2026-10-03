//! The VM harnesses' gvproxy provisioning (`common::gvproxy_bin`): under
//! `MINVMD_E2E=1` only the pinned switch is accepted, outside it an explicit
//! `MINVMD_GVPROXY_BIN` is used as given.
//!
//! The digest checks need no VM and run on every lane. The `_integration`
//! suffix puts the ignored fetch case on the VM lanes too, where it provisions
//! the switch ahead of the harnesses that boot with it.

mod common;

use std::io::Write;

use common::{resolve_gvproxy, workspace_root};

fn not_gvproxy() -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("creating a temp file");
    f.write_all(b"not the pinned gvproxy")
        .expect("writing the temp file");
    f
}

#[test]
#[should_panic(expected = "gvproxy SHA-256 mismatch")]
fn e2e_rejects_an_unpinned_gvproxy() {
    let bin = not_gvproxy();
    resolve_gvproxy(true, Some(bin.path().to_path_buf()), &workspace_root());
}

#[test]
fn outside_e2e_an_explicit_gvproxy_is_used_unchecked() {
    let bin = not_gvproxy();
    let got = resolve_gvproxy(false, Some(bin.path().to_path_buf()), &workspace_root());
    assert_eq!(got.as_deref(), Some(bin.path()));
}

#[test]
fn outside_e2e_without_a_gvproxy_the_harness_skips() {
    assert_eq!(resolve_gvproxy(false, None, &workspace_root()), None);
}

/// The fetch path end to end: downloads the pinned binary (network) unless
/// the cache already holds it, then checks its digest.
#[test]
#[ignore = "gated MINVMD_E2E=1; downloads the pinned gvproxy when MINVMD_GVPROXY_BIN is unset"]
fn e2e_provisions_the_pinned_gvproxy() {
    if !common::e2e() {
        common::skip_or_fail("gvproxy_pin_integration", "MINVMD_E2E != 1");
        return;
    }
    let bin = common::gvproxy_bin().expect("MINVMD_E2E=1 always yields a switch");
    eprintln!(
        "gvproxy_pin_integration: pinned gvproxy at {}",
        bin.display()
    );
}
