//! Error types for the op crate.

use std::fmt;

use cache::CacheErr;

/// Error type for the op crate.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occurred.
    IO(std::io::Error),
    /// An error interacting with the Cache occurred.
    Cache(CacheErr),
    /// A generic error with a custom message.
    Other(String),
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

impl From<CacheErr> for Error {
    fn from(e: CacheErr) -> Self {
        Self::Cache(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(e) => write!(f, "i/o error: {}", e),
            Error::Cache(e) => write!(f, "cache error: {}", e),
            Error::Other(e) => write!(f, "other: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(e) => Some(e),
            Error::Cache(e) => Some(e),
            _ => None,
        }
    }
}
