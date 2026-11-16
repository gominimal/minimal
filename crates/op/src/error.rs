//! Error types for the op crate.

use graph::{Graph, PlanErr};
use lcache::CacheErr;

/// Error type for the op crate.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// An I/O error occurred.
    #[error("i/o error: {0}")]
    IO(#[from] std::io::Error),
    /// An error interacting with the Cache occurred. The `CacheErr` is in the
    /// message and is not the `source()`, so `{:#}` prints it once.
    #[error("cache error: {0}")]
    Cache(CacheErr),
    /// An error during planning occurred.
    #[error("plan error: {1:?}")]
    Plan(Graph, #[source] PlanErr),
    /// An error occurred during the setup or execution of a sandbox.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] sandbox::Error),
    #[error("other: {0}")]
    Other(anyhow::Error),
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

impl From<oci_spec::OciSpecError> for Error {
    fn from(e: oci_spec::OciSpecError) -> Self {
        Self::Other(e.into())
    }
}

impl From<serde_json_lenient::Error> for Error {
    fn from(e: serde_json_lenient::Error) -> Self {
        Self::Other(e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache error reads once in a chain printed with `{:#}`: not
    /// "cache error: not found: not found".
    #[test]
    fn a_cache_error_prints_its_cause_once() {
        let e = Error::Cache(CacheErr::NotFound);
        assert!(std::error::Error::source(&e).is_none());
        assert_eq!(
            format!("{:#}", anyhow::Error::from(e).context("reading foo")),
            "reading foo: cache error: not found"
        );
    }
}
