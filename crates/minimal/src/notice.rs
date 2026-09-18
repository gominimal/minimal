//! Compatibility notices for CLI flags whose spellings changed.
//!
//! A spelling change is invisible to the parser: a clap alias resolves to the
//! same value as the current spelling, so the only record of what the
//! developer actually typed is the process's own command line. These notices
//! are matched against that command line, so a diagnostic bundle that
//! captured it can be tied back to the hint the developer saw. `--network` is
//! the first flag to use this.

/// Legacy `--network` spellings and their current replacements, kept in the
/// order the hints are emitted.
const LEGACY_NETWORK_SPELLINGS: &[(&str, &str)] = &[
    ("no-net", "none"),
    ("host-net", "host_ip"),
    ("own-ip", "own_ip"),
];

/// The hints for every legacy `--network` spelling present in `argv`, one per
/// spelling, each naming its current replacement.
///
/// Both the `--network <value>` and the `--network=<value>` forms are
/// matched. The returned vector follows the declaration order above, so a
/// command line that spells the flag several ways (unusual, but possible with
/// a repeatable value) names the replacements in a stable order.
pub(crate) fn legacy_network_hints(argv: &[String]) -> Vec<String> {
    let mut hints = Vec::new();
    for (legacy, current) in LEGACY_NETWORK_SPELLINGS {
        let separate = argv.iter().enumerate().any(|(i, arg)| {
            arg == "--network" && argv.get(i + 1).is_some_and(|value| value == legacy)
        });
        let joined = format!("--network={legacy}");
        let uses_joined = argv.iter().any(|arg| arg == &joined);
        if separate || uses_joined {
            hints.push(format!(
                "note: --network {legacy} is deprecated; use --network {current}"
            ));
        }
    }
    hints
}

/// Print the legacy `--network` spelling hints for this process's own command
/// line to stderr.
///
/// Called once on the activation path, before any daemon work: the hint is a
/// parse-time notice, and the parse has already accepted the legacy spelling.
pub(crate) fn emit_legacy_network_hints() {
    let argv: Vec<String> = std::env::args().collect();
    for hint in legacy_network_hints(&argv) {
        eprintln!("{hint}");
    }
}
