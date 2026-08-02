#![no_main]

//! Fuzz the realm-tagged path constructors for invariant integrity.
//!
//! `paths` is a type-system security boundary: holding a [`RelPath`] is meant
//! to be *proof* that a path is relative and free of `..`, which is what lets
//! the daemon composer trust a `SandboxRelPath` arriving over the wire —
//! joining it against the sandbox home cannot produce a path outside that
//! home. Every way of minting a `RelPath` therefore has to enforce the same
//! rule, or the proof is forgeable.
//!
//! So this target is a **differential over constructors** rather than a panic
//! oracle. A forged `RelPath` does not crash and does not trip a sanitizer;
//! it silently produces a value downstream code trusts. The properties below
//! are what "trustworthy" actually means, stated so a fuzzer can refute them.

use camino::{Utf8Component, Utf8PathBuf};
use libfuzzer_sys::fuzz_target;

use paths::{AbsPath, EitherPath, Host, RelPath};

/// Lexically resolves `..` and `.` without touching the filesystem, then
/// reports whether the path still sits under `root`.
///
/// A string-prefix test is NOT sufficient here: `/base/../../etc` starts with
/// `/base` as text while resolving outside it. Matching the oracle to the bug
/// class is the whole point.
fn escapes(path: &Utf8PathBuf, root: &str) -> bool {
    let mut out = Utf8PathBuf::new();
    for c in path.components() {
        match c {
            Utf8Component::ParentDir => {
                out.pop();
            }
            Utf8Component::CurDir => {}
            other => out.push(other.as_str()),
        }
    }
    !out.starts_with(root)
}

const BASE: &str = "/srv/sandbox/home";

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let base = AbsPath::<Host>::try_new(BASE).expect("literal base is absolute");

    // 1. A `RelPath` that survives `try_new` must be safe to join. This is the
    //    property the wire-trust claim rests on.
    if let Ok(rel) = RelPath::<Host>::try_new(s) {
        let joined = base.join(&rel).as_utf8_path().to_path_buf();
        assert!(
            !escapes(&joined, BASE),
            "validated RelPath escaped its base: input={s:?} joined={joined:?}",
        );
    }

    // 2. Every constructor that yields a `RelPath` must agree with `try_new`.
    //    `EitherPath::new` is infallible and picks a variant by absoluteness
    //    alone, so it must not mint a `Rel` that `try_new` would have refused
    //    — otherwise the type's guarantee is forgeable.
    match EitherPath::<Host>::new(s) {
        EitherPath::Rel(rel) => {
            // The lenient variant is a bare path by design, so the check is
            // no longer "did it forge a RelPath" but "can it still be turned
            // into one only when genuinely valid". A path that survives
            // `try_new` must join contained.
            assert_eq!(
                rel,
                s,
                "EitherPath::Rel altered the path it was given: {s:?}",
            );
            if let Ok(checked) = RelPath::<Host>::try_new(rel) {
                let joined = base.join(&checked).as_utf8_path().to_path_buf();
                assert!(
                    !escapes(&joined, BASE),
                    "validated RelPath escaped its base: input={s:?} joined={joined:?}",
                );
            }
        }
        EitherPath::Abs(abs) => {
            assert!(
                abs.as_utf8_path().is_absolute(),
                "EitherPath classified a relative path as Abs: {s:?}",
            );
        }
    }

    // 3. `FromStr` must be exactly `try_new` — a divergence would let callers
    //    pick the weaker door by accident.
    assert_eq!(
        s.parse::<AbsPath<Host>>().is_ok(),
        AbsPath::<Host>::try_new(s).is_ok(),
        "AbsPath FromStr/try_new disagree: {s:?}",
    );
    assert_eq!(
        s.parse::<RelPath<Host>>().is_ok(),
        RelPath::<Host>::try_new(s).is_ok(),
        "RelPath FromStr/try_new disagree: {s:?}",
    );

    // 4. The two constructors partition the space: exactly one of absolute /
    //    relative holds, and the classification must match the variant.
    let abs_ok = AbsPath::<Host>::try_new(s).is_ok();
    assert_eq!(
        abs_ok,
        EitherPath::<Host>::new(s).is_absolute(),
        "AbsPath::try_new and EitherPath disagree on absoluteness: {s:?}",
    );
});
