//! Error types for the orchestrator crate.

use graph::{BuildSpecRef, Graph, PlanErr};
use lcache::CacheErr;

/// Error type for the orchestrator crate.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// An I/O error occurred.
    #[error("i/o error: {0}")]
    IO(#[from] std::io::Error),
    /// An error interacting with the Cache occurred.
    #[error("cache error: {0}")]
    Cache(#[from] CacheErr),
    /// An error during planning occurred.
    #[error("plan error: {1:?}")]
    Plan(Graph, #[source] PlanErr),
    /// An error occurred building a specific package.
    #[error("`{0}` failed to build: {1}")]
    BuildFailed(String, #[source] op::Error),
    /// A generic error occurred during the setup or execution of a sandbox.
    #[error("sandbox error: {0}")]
    Sandbox(#[from] sandbox::Error),
    /// The remote index lists the spec but the store no longer has its
    /// artifact (a dangling hit): the plan trusted the index and scheduled a
    /// cache fill with no build behind it. The caller re-plans with the spec
    /// masked out of every cache, which turns the fill into a build.
    #[error("the remote cache lists {0:?} but no longer has its artifact")]
    DanglingCacheHit(BuildSpecRef),
    /// Other errors.
    #[error("other: {0}")]
    Other(anyhow::Error),
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
            op::Error::Sandbox(e) => Self::Sandbox(e),
        }
    }
}
