//! Error types for the checkouts crate.

/// Errors that can occur when managing git repository checkouts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),

    /// A git command failed to execute successfully.
    #[error("git command '{command}' failed ({status}): {stderr}")]
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
    #[error("invalid path")]
    InvalidPath,

    /// A generic error with a custom message.
    #[error("other: {0}")]
    Other(String),

    /// Failed to read the statefile.
    #[error("statefile invalid: {0}")]
    StatefileInvalid(#[source] serde_json_lenient::Error),

    /// The manager is in offline mode and the requested checkout would require a
    /// network operation (clone of an unknown remote, or fetch of a known remote).
    /// Caller asked for a ref we'd need to download, but `--no-fetch` is set.
    #[error(
        "offline cache miss for git remote {remote} — \
         --offline is set; pre-populate the vcs/ cache or remove the flag"
    )]
    OfflineCacheMiss { remote: String },
}

impl Error {
    /// Creates a new error with a custom message.
    pub fn other<S: Into<String>>(msg: S) -> Self {
        Error::Other(msg.into())
    }
}
