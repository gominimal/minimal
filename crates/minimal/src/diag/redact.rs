//! CLI-side redaction policy: which env-var values may leave the machine.
//!
//! The mechanics — the key-based rules, the TOML/JSON walkers, and the
//! process-env masking — live in [`diagnostics::redact`] so the daemon
//! applies the same behavior; what belongs to the CLI is only this policy:
//! the allowlist of env names whose values are safe and useful verbatim.

/// Env vars whose *values* are safe and useful to include verbatim. Everything
/// else is reported by name only.
///
/// `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, and `COLORTERM` join `TERM` because
/// a rendering complaint (#950) is answered by the emulator, not the termcap
/// name: Terminal.app, iTerm2, and Ghostty disagree about wide glyphs and
/// truecolor while all reporting `xterm-256color`. Each names a program, never
/// the user or their work.
const ENV_VALUE_ALLOWLIST_EXACT: &[&str] = &[
    "RUST_LOG",
    "HOME",
    "SHELL",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "COLORTERM",
    "PATH",
];
const ENV_VALUE_ALLOWLIST_PREFIXES: &[&str] = &["XDG_", "MINIMAL_", "MINVMD_", "MINIMALD_"];

/// Returns true when the named env var's value may be captured verbatim.
/// A sensitive-shaped name always loses to the allowlist — `MINIMAL_AUTH_TOKEN`
/// matches the project prefix but must never leave the machine.
pub fn is_env_value_allowlisted(name: &str) -> bool {
    diagnostics::redact::is_env_value_allowlisted(
        name,
        ENV_VALUE_ALLOWLIST_EXACT,
        ENV_VALUE_ALLOWLIST_PREFIXES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_allowlist_covers_expected_names() {
        for name in [
            "RUST_LOG",
            "XDG_STATE_HOME",
            "MINIMAL_BIN",
            "MINVMD_KERNEL_PATH",
            "MINIMALD_DETACHED",
            "HOME",
            "PATH",
            "TERM",
            "TERM_PROGRAM",
            "TERM_PROGRAM_VERSION",
            "COLORTERM",
        ] {
            assert!(is_env_value_allowlisted(name), "{name} should be allowed");
        }
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "LANG",
            "USER",
            "MINIMAL_AUTH_TOKEN",
            "MINIMALD_API_KEY",
            "MINVMD_PASSWORD",
            "MINIMALIST_THING",
        ] {
            assert!(!is_env_value_allowlisted(name), "{name} must not be");
        }
    }

    /// The terminal-identity names are an exact-match widening, not a `TERM`
    /// prefix: a var that merely starts with the same letters stays masked.
    #[test]
    fn terminal_identity_is_allowlisted_by_name_not_by_prefix() {
        for name in ["TERMINAL_EMULATOR", "TERM_SESSION_ID", "TERM_TOKEN"] {
            assert!(!is_env_value_allowlisted(name), "{name} must not be");
        }
    }
}
