#![no_main]

//! Fuzz `archive::normalize_within_root` — the containment primitive two
//! crates now depend on.
//!
//! `common::archive` uses it for tar entry paths and link targets, and
//! `op::materialize` for raw-file outputs ("both `../../etc/shadow` and
//! `/../../etc/shadow` land here"). Each trusts the same contract, so a gap
//! here is a gap in both at once — and neither re-checks the result.
//!
//! Fuzzed directly rather than only through `archive_extract` because it is a
//! pure function: no tempdir, no extraction, so it runs orders of magnitude
//! faster and can explore path shapes a tar header cannot even encode.
//!
//! The contract, as the callers rely on it: a returned path is relative,
//! contains no `..`, and stays under any root it is joined onto.

use std::path::{Component, Path, PathBuf};

use libfuzzer_sys::fuzz_target;

use common::archive::normalize_within_root;

/// Lexically resolves `.`/`..` and reports whether the path leaves `root`.
fn escapes(path: &Path, root: &Path) -> bool {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    !out.starts_with(root)
}

/// Roots of different shapes: a trailing component that is a prefix of another
/// (`/srv/work` vs `/srv/workbench`) is where a string-prefix containment check
/// would wrongly pass, so keep one of each around.
const ROOTS: [&str; 4] = ["/dest", "/srv/work", "/a/b/c", "/"];

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Bound the input: path handling is linear, and a megabyte of slashes
    // tells us nothing a hundred bytes does not.
    if s.len() > 4096 {
        return;
    }

    let Some(normalized) = normalize_within_root(Path::new(s)) else {
        // Rejection is always a safe answer; nothing to check.
        return;
    };

    // 1. The result must be relative. An absolute path joined onto a root
    //    replaces it outright, which is the footgun the callers rely on this
    //    function to have already removed.
    assert!(
        normalized.is_relative(),
        "normalize_within_root returned an absolute path: input={s:?} out={normalized:?}",
    );

    // 2. No `..` may survive. Callers join the result and then check nothing —
    //    `minimald`'s uploader and `op::materialize` both do exactly that.
    assert!(
        !normalized
            .components()
            .any(|c| matches!(c, Component::ParentDir)),
        "normalize_within_root left a `..` component: input={s:?} out={normalized:?}",
    );

    // 3. The property the callers actually depend on: joined onto any root,
    //    the result stays under it.
    for root in ROOTS {
        let joined = Path::new(root).join(&normalized);
        assert!(
            !escapes(&joined, Path::new(root)),
            "escaped {root:?}: input={s:?} out={normalized:?} joined={joined:?}",
        );
    }

    // 4. Idempotent: normalizing an already-normalized path is a no-op. It is
    //    a fixpoint by construction, and a caller normalizing twice (as the
    //    hardlink path effectively does) must not get a different answer.
    let again = normalize_within_root(&normalized)
        .expect("an already-normalized path must still be accepted");
    assert_eq!(
        again, normalized,
        "normalize_within_root is not idempotent: input={s:?}",
    );
});
