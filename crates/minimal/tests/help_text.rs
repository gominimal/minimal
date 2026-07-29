//! CI guard: internal spec identifiers must never reach `min --help` output.
//!
//! clap's derive macro publishes `///` doc comments verbatim as help text, so a
//! spec reference written for a reviewer — deployment-model codes (`DM1`),
//! requirement IDs (`R4.4`), use-case IDs (`UC7`), functional/non-functional
//! requirement IDs (`FR3`, `NFR2`), or the retired `PTask` vocabulary — becomes
//! product copy with no step in between where anyone would notice. This test
//! renders the long help for the root command and every subcommand recursively
//! and fails on any such identifier, so the convention "internal spec IDs go in
//! `//` comments, never `///`, on any type clap derives from" is enforced
//! rather than merely remembered. See gominimal/minimal#1013.

use clap::CommandFactory as _;
use minimal::Cli;

/// Renders the long help of `cmd` and every (transitive) subcommand, returning
/// `(name, help_text)` pairs. Long help is what `--help` prints, so it carries
/// the full doc-comment body where spec IDs hide; hidden subcommands (e.g.
/// `login`) are included because `min <cmd> --help` still renders them.
fn help_pages(cmd: &mut clap::Command, out: &mut Vec<(String, String)>) {
    out.push((
        cmd.get_name().to_string(),
        cmd.render_long_help().to_string(),
    ));
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        if let Some(sub) = cmd.find_subcommand_mut(&name) {
            help_pages(sub, out);
        }
    }
}

/// Scans `text` for internal spec identifiers and returns each match. Matches
/// are bounded by non-alphanumeric characters so ordinary prose (`FROM`,
/// `microVM`) never trips the guard:
///
///   * `DM<n>`, `UC<n>`, `FR<n>`, `NFR<n>` — one or more trailing digits;
///   * `R<n>.<n>` — requirement IDs with a dotted minor;
///   * `PTask` — retired vocabulary (superseded by `sandbox` / `taskspec`).
fn spec_ids(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let n = b.len();
    let alnum = |i: usize| i < n && b[i].is_ascii_alphanumeric();
    let mut hits = Vec::new();
    let mut i = 0;
    while i < n {
        let at_boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if at_boundary {
            if let Some(end) = spec_id_at(b, i) {
                debug_assert!(!alnum(end), "match must end on a boundary");
                hits.push(text[i..end].to_string());
                i = end;
                continue;
            }
        }
        i += 1;
    }
    hits
}

/// If a spec identifier begins at `i`, returns the index just past it (which is
/// guaranteed to sit on a trailing word boundary); otherwise `None`.
fn spec_id_at(b: &[u8], i: usize) -> Option<usize> {
    let n = b.len();
    let ends_ok = |j: usize| j >= n || !b[j].is_ascii_alphanumeric();

    if b[i..].starts_with(b"PTask") {
        let j = i + b"PTask".len();
        if ends_ok(j) {
            return Some(j);
        }
    }

    // NFR before FR so `NFR2` is reported whole; either way the leading-`N`
    // boundary keeps `FR` from matching inside it.
    for prefix in [b"NFR".as_slice(), b"FR", b"DM", b"UC"] {
        if b[i..].starts_with(prefix) {
            let start = i + prefix.len();
            let mut j = start;
            while j < n && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && ends_ok(j) {
                return Some(j);
            }
        }
    }

    // R<digits>.<digits>
    if b[i] == b'R' {
        let mut j = i + 1;
        let major = j;
        while j < n && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > major && j < n && b[j] == b'.' {
            j += 1;
            let minor = j;
            while j < n && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > minor && ends_ok(j) {
                return Some(j);
            }
        }
    }

    None
}

#[test]
fn no_internal_spec_ids_in_help() {
    let mut root = Cli::command();
    let mut pages = Vec::new();
    help_pages(&mut root, &mut pages);

    let mut failures = Vec::new();
    for (name, help) in &pages {
        let ids = spec_ids(help);
        if !ids.is_empty() {
            failures.push(format!("`min {name} --help` leaks {ids:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "internal spec identifiers found in rendered help — move them to `//` \
         comments (see gominimal/minimal#1013):\n{}",
        failures.join("\n"),
    );
}

#[test]
fn spec_id_scanner_matches_known_forms_only() {
    // Positive: every identifier class the guard must catch.
    assert_eq!(spec_ids("microVM (DM1)."), vec!["DM1"]);
    assert_eq!(spec_ids("internal CA (R4.4, R4.5)"), vec!["R4.4", "R4.5"]);
    assert_eq!(spec_ids("access (UC7 / UC3)"), vec!["UC7", "UC3"]);
    // A letter-suffixed use-case ID (`UC2b`) has no trailing boundary after the
    // digit, so — like the issue's `\bUC\d+\b` — it is deliberately not matched.
    assert!(spec_ids("remote (UC2b) access").is_empty());
    assert_eq!(spec_ids("named PTask via SSH"), vec!["PTask"]);
    assert_eq!(spec_ids("see FR3 and NFR12"), vec!["FR3", "NFR12"]);
    // Negative: ordinary prose must never match.
    assert!(spec_ids("FROM the daemon, run RUN, a microVM backend").is_empty());
}
