//! Error types for the orchestrator crate.

use std::fmt;

use cache::CacheErr;
use graph::{DepGraph, PlanErr};

/// Error type for the orchestrator crate.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// An I/O error occurred.
    IO(std::io::Error),
    /// An error interacting with the Cache occurred.
    Cache(CacheErr),
    /// An error during planning occurred.
    Plan(DepGraph, PlanErr),
    /// Other errors.
    Other(anyhow::Error),
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

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

impl From<op::Error> for Error {
    fn from(value: op::Error) -> Self {
        match value {
            op::Error::Cache(ce) => Self::Cache(ce),
            op::Error::IO(e) => Self::IO(e),
            op::Error::Other(e) => Self::Other(e),
            op::Error::Plan(g, e) => Self::Plan(g, e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(e) => write!(f, "i/o error: {}", e),
            Error::Cache(e) => write!(f, "cache error: {}", e),
            Error::Plan(_, e) => write!(f, "plan error: {:?}", e),
            Error::Other(e) => write!(f, "other: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(e) => Some(e),
            Error::Cache(e) => Some(e),
            Error::Plan(_, e) => Some(e),
            _ => None,
        }
    }
}
