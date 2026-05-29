//! User-readable error wrapper.
//!
//! minvmd is a standalone bin that owns its own `main` and prints its own
//! errors, so it carries a small local error type rather than depending on a
//! shared one.
//!
//! Use `anyhow::Error::from(UserFacing::new("message"))` for errors that should
//! be printed verbatim to the user. For internal/system errors, propagate with
//! bare `?`.

use std::fmt;

#[derive(Debug)]
pub struct UserFacing {
    message: String,
}

impl UserFacing {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    // Accessor for the message. No caller downcasts to read it yet, so it is
    // currently unused.
    #[allow(dead_code)]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for UserFacing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UserFacing {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_just_the_message() {
        let e = UserFacing::new("session not found: foo");
        assert_eq!(e.to_string(), "session not found: foo");
    }
}
