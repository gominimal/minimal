//! Session names the front-ends mint: the autogen `<dir-basename>-<hex>`
//! handle an unnamed activation gets, and the bounded retry that re-mints it
//! when it collides with a live session or a live box row. Shared by the
//! `min` CLI and `min dash`, so an autogen name is spelled and retried the
//! same way from either.

/// Bounded retries when a freshly minted autogen name collides with an
/// existing session built from the same directory.
pub const AUTOGEN_NAME_RETRIES: u32 = 8;

/// Longest component [`sanitize_name_component`] returns, so a minted
/// `task-<component>-<hex>` (the longest wrapper) stays inside the 63-octet
/// DNS label `validate_session_name` requires.
const NAME_COMPONENT_MAX: usize = 48;

/// Reduce a directory basename to the characters a session name may carry —
/// ASCII alphanumerics, lowercased, with `-`, `_` and `.` each mapped to `-` —
/// dropping everything else (spaces, unicode) and capping the length, so the
/// minted handle is typable and is a single DNS label that clears
/// `validate_session_name`. Falls back to `session` when nothing survives.
pub fn sanitize_name_component(basename: &str) -> String {
    let filtered: String = basename
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if matches!(c, '-' | '_' | '.') {
                Some('-')
            } else {
                None
            }
        })
        .take(NAME_COMPONENT_MAX)
        .collect();
    let trimmed = filtered.trim_matches('-');
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Mint a typable session name `<dir-basename>-<hex>` from the project
/// directory. The caller supplies the hex so the format is unit-testable and
/// so a collision retry can re-mint with fresh entropy.
pub fn autogen_session_name(project_dir: &camino::Utf8Path, hex: &str) -> String {
    let base = sanitize_name_component(project_dir.file_name().unwrap_or("session"));
    format!("{base}-{hex}")
}

/// Four lowercase hex digits of per-call entropy, drawn from the stdlib
/// hasher's randomized seed — enough to disambiguate sessions from one
/// directory without pulling in an RNG dependency. Each call reseeds, so a
/// retry gets a fresh suffix.
pub fn random_hex4() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    let seed = RandomState::new().hash_one("minimal-session-name");
    format!("{:04x}", seed & 0xffff)
}

/// The daemon collapses the session-store `AlreadyExists` into a plain message
/// (see `serve_create_session` in `crates/minimald/src/rpc.rs`); match it so an
/// autogen name clash can be told apart from any other `CreateSession` failure.
pub fn is_name_collision(error: &str) -> bool {
    error.contains("already exists")
}

/// Whether a failed `CreateSession` should retry under a freshly minted name:
/// only autogen names (`autogen`), only on a name collision, and only within
/// the bounded budget. A user-supplied name never retries, so its collision
/// surfaces verbatim.
pub fn should_retry_autogen(autogen: bool, attempts: u32, error: &str) -> bool {
    autogen && attempts < AUTOGEN_NAME_RETRIES && is_name_collision(error)
}
