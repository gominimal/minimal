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

/// The switch cache is keyed on the pinned digest: a binary cached under an
/// earlier pin of the same `version` is not reused, and the new pin's switch
/// is fetched beside it.
#[test]
fn a_switch_cached_under_an_earlier_pin_is_fetched_again() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = tempfile::tempdir().expect("creating a stub workspace");
    let cache = tempfile::tempdir().expect("creating a cache root");
    let scripts = workspace.path().join("scripts");
    std::fs::create_dir_all(&scripts).expect("creating the stub scripts dir");
    let script = scripts.join("fetch-gvproxy.sh");
    // A stub fetch that writes the bytes `switch` names to its destination.
    let stub_fetch = |switch: &str| {
        std::fs::write(
            &script,
            format!("#!/bin/sh\nprintf '%s' '{switch}' > \"$1\"\nchmod +x \"$1\"\n"),
        )
        .expect("writing the stub fetch script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("making the stub fetch script executable");
    };
    let pin = |sha256: &str| common::GvproxyLock {
        version: "v0.9.0".to_owned(),
        asset: "gvproxy-linux-amd64",
        sha256: sha256.to_owned(),
    };

    stub_fetch("unpatched switch");
    let earlier = common::fetch_cached_in(cache.path(), workspace.path(), &pin("aaaa"));
    assert_eq!(
        std::fs::read_to_string(&earlier).expect("reading the earlier switch"),
        "unpatched switch"
    );

    stub_fetch("patched switch");
    let current = common::fetch_cached_in(cache.path(), workspace.path(), &pin("bbbb"));
    assert_ne!(
        earlier, current,
        "a new pin of the same version gets its own cache entry"
    );
    assert_eq!(
        std::fs::read_to_string(&current).expect("reading the current switch"),
        "patched switch",
        "the switch cached under the earlier pin was fetched again, not reused"
    );

    // The same pin again reuses its cached switch without a fetch.
    stub_fetch("a fetch that must not run");
    let again = common::fetch_cached_in(cache.path(), workspace.path(), &pin("bbbb"));
    assert_eq!(again, current);
    assert_eq!(
        std::fs::read_to_string(&again).expect("reading the cached switch"),
        "patched switch"
    );
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

/// The env var the switch path comes in on, built so this file's own source
/// does not hold the literal the guard below looks for.
const GVPROXY_ENV: &str = concat!("MINVMD_", "GVPROXY_BIN");

/// Whether `source` reads [`GVPROXY_ENV`] with `std::env::var` or `var_os`,
/// either by the literal or through a `const` that holds it. Whitespace is
/// removed first, so a call split over lines still matches. Setting the
/// variable on a child (`.env(..)`) is not a read.
fn reads_gvproxy_env(source: &str) -> bool {
    let flat: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    let literal = format!("\"{GVPROXY_ENV}\"");
    let mut names = vec![literal.clone()];
    // `const NAME: &str = "MINVMD_GVPROXY_BIN";` with its whitespace removed.
    let mut rest = flat.as_str();
    while let Some(at) = rest.find(&format!(":&str={literal};")) {
        let head = &rest[..at];
        let name = head
            .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        if head.ends_with(&format!("const{name}")) && !name.is_empty() {
            names.push(name.to_owned());
        }
        rest = &rest[at + 1..];
    }
    names.iter().any(|name| {
        ["var(", "var_os("]
            .iter()
            .any(|call| flat.contains(&format!("{call}{name})")))
    })
}

/// Every VM harness takes the gvproxy switch from `common::gvproxy_bin`, which
/// fetches the pinned switch on a VM lane. A harness that reads the variable
/// itself skips there, because the lanes do not export it.
#[test]
fn vm_harnesses_take_the_switch_from_the_common_helper() {
    // The detector itself, on the shapes a harness can take.
    assert!(reads_gvproxy_env(&format!(
        "std::env::var_os(\n    \"{GVPROXY_ENV}\",\n)"
    )));
    assert!(reads_gvproxy_env(&format!(
        "const GV: &str = \"{GVPROXY_ENV}\";\nlet x = std::env::var(GV);"
    )));
    assert!(!reads_gvproxy_env(&format!(
        "cmd.env(\"{GVPROXY_ENV}\", gvproxy);\nlet g = common::gvproxy_bin();"
    )));

    let dir = workspace_root().join("crates/minvmd/tests");
    let this_file = std::path::Path::new(file!())
        .file_name()
        .expect("file!() names a file")
        .to_owned();
    let mut checked = Vec::new();
    let mut offenders = Vec::new();
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
    {
        let path = entry.expect("reading a tests dir entry").path();
        if path.extension().is_none_or(|ext| ext != "rs")
            || path.file_name() == Some(this_file.as_os_str())
        {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        if reads_gvproxy_env(&source) {
            offenders.push(path.display().to_string());
        }
        checked.push(path);
    }
    assert!(
        checked
            .iter()
            .any(|p| p.ends_with("egress_allowlist_integration.rs")),
        "the guard found no harnesses under {}: checked {checked:?}",
        dir.display()
    );
    assert!(
        offenders.is_empty(),
        "these harnesses read {GVPROXY_ENV} themselves; take the switch from \
         common::gvproxy_bin() instead: {offenders:?}"
    );
}
