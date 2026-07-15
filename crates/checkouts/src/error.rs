//! Error types for the checkouts crate.

use std::fmt;

/// Errors that can occur when managing git repository checkouts.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occurred.
    IO(std::io::Error),

    /// A git command failed to execute successfully.
    GitCommandFailed {
        /// The git command that failed
        command: String,
        /// The stderr output from the failed command
        stderr: String,
        /// How the process terminated (`std::process::ExitStatus`, rendered):
        /// an exit code (`exit status: N`) or a signal (`signal: 9 (SIGKILL)`).
        /// Distinguishes a git-reported failure from an externally killed
        /// process — a signal kill leaves only whatever git wrote before dying,
        /// which can be a misleadingly benign line (e.g. a templates warning).
        status: String,
    },

    /// The repository path is invalid (e.g., contains invalid UTF-8) or for a different remote.
    InvalidPath,

    /// A generic error with a custom message.
    Other(String),

    /// Failed to read the statefile.
    StatefileInvalid(serde_json::Error),

    /// The manager is in offline mode and the requested checkout would require a
    /// network operation (clone of an unknown remote, or fetch of a known remote).
    /// Caller asked for a ref we'd need to download, but `--no-fetch` is set.
    OfflineCacheMiss { remote: String },
}

impl Error {
    /// Creates a new error with a custom message.
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(e) => write!(f, "I/O error: {}", e),
            Error::GitCommandFailed {
                command,
                stderr,
                status,
            } => {
                write!(f, "git command '{command}' failed ({status}): {stderr}")
            }
            Error::InvalidPath => write!(f, "invalid path"),
            Error::Other(e) => write!(f, "other: {}", e),
            Error::StatefileInvalid(e) => write!(f, "statefile invalid: {}", e),
            Error::OfflineCacheMiss { remote } => write!(
                f,
                "offline cache miss for git remote {remote} — \
                 --offline is set; pre-populate the vcs/ cache or remove the flag"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(e) => Some(e),
            Error::StatefileInvalid(e) => Some(e),
            _ => None,
        }
    }
}
