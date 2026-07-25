//! [`SecretString`]: the single carrier type for GitHub token material.
//!
//! The security model (spec R6) says a token lives only in the daemon and never
//! enters a sandbox, log, or diagnostic bundle. This type enforces the parts of
//! that a type *can* enforce:
//!
//! * `Debug` and `Display` render `[REDACTED:gh]`, so a token cannot leak
//!   through a formatting call, a `tracing` field, or a diagnostic dump.
//! * The inner bytes are zeroized on drop, so a freed token does not linger in
//!   memory.
//! * There is deliberately **no** `serde` derive here. Serialization of a stored
//!   token is the job of a future `store` module that will opt in explicitly;
//!   until then, a raw `String` token — or a `#[derive(Serialize)]` on a
//!   token-bearing struct — is a review-rejectable pattern, because the only
//!   sanctioned carrier is this type and it will not serialize by accident.
//!
//! Reading the plaintext is intentionally awkward: the sole accessor is
//! [`SecretString::expose_secret`], named so that every read site is greppable
//! in review.

use std::fmt;

use zeroize::Zeroize;

/// The redaction marker rendered by both `Debug` and `Display`.
pub const REDACTED: &str = "[REDACTED:gh]";

/// A string whose contents are secret (a GitHub user or refresh token).
///
/// Construct with [`SecretString::new`]; read with
/// [`SecretString::expose_secret`]. Never logged, never serialized.
#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps secret material.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Borrows the plaintext. The name makes every read site greppable; use it
    /// only where the plaintext is genuinely required (e.g. building an
    /// authenticated request in the daemon).
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A `From<String>` for ergonomic construction; still routes through the newtype.
impl From<String> for SecretString {
    fn from(secret: String) -> Self {
        Self::new(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_redact() {
        let secret = SecretString::new("ghu_supersecrettoken");
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        // The plaintext appears in neither rendering.
        assert!(!format!("{secret} {secret:?}").contains("supersecret"));
    }

    #[test]
    fn expose_secret_returns_plaintext() {
        let secret = SecretString::new("ghu_token");
        assert_eq!(secret.expose_secret(), "ghu_token");
    }
}
