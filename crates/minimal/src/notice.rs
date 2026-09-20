//! One-line advisory notices for input the CLI still accepts but no
//! longer prefers.

use std::io::Write;

/// Advise that `flag` was given the legacy spelling `old`, which parses
/// exactly like the current spelling `new` — nothing else about the run
/// differs. Written through `out` rather than directly to stderr, so
/// callers (and tests) don't have to go through the process's real stderr.
pub fn legacy_spelling_hint(out: &mut impl Write, flag: &str, old: &str, new: &str) {
    let _ = writeln!(
        out,
        "note: `{flag} {old}` is a legacy spelling; use `{flag} {new}` instead"
    );
}
