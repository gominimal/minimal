//! Error types for the checkouts crate.

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
    },

    /// The git binary was not found in PATH.
    GitNotFound,

    /// The repository path is invalid (e.g., contains invalid UTF-8) or for a different remote.
    InvalidPath,

    /// The repository is not in a clean state (has uncommitted changes).
    DirtyWorkingDirectory,

    /// The specified git reference (branch, tag, or commit) was not found.
    RefNotFound(String),

    /// A generic error with a custom message.
    Other(String),

    /// Failed to read the statefile.
    StatefileInvalid(serde_json::Error),
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
