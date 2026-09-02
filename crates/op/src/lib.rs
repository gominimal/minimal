//! Home for complicated operations using the minimal graph, such as builds or constructing cache objects.
#![allow(clippy::result_large_err)]

use std::path::PathBuf;

use graph::Graph;
use lcache::{Cache, LocalDir, PendingDir};

mod error;
pub use error::Error;

/// Standard options and configuration needed for most operations.
pub struct Options<'a> {
    pub cache: Cache<LocalDir>,
    pub graph: &'a Graph,
    pub exec_base: PathBuf,
    pub ot: Option<OpTracker>,
    pub daemon_id: Option<String>,
}

/// Describes an operation which is configured and ready to be executed.
pub trait Runnable {
    type Result: Sized + Send + Sync;
    fn run(
        &mut self,
        opts: &Options,
    ) -> impl std::future::Future<Output = Result<Self::Result, Error>> + Send;
}

/// A materialized source, either a file, directory tree, or pending cache dir passed into the operation.
#[derive(Debug)]
pub enum Materialized {
    File(PathBuf),
    TempDir(tempfile::TempDir),
    Given(PendingDir),
}

mod subsets;
use ot::OpTracker;
pub use subsets::SubsetBuild;

mod cache_clean;
pub use cache_clean::{CleanCache, CleanEvent, CleanReport, StaleKind};

pub mod notices;
pub use notices::{NoticeFile, SourceNotices};
mod sources;
pub use sources::{SourceFetcher, SourceLoad};
mod specs;
pub use specs::{SpecBuild, SpecBuildResult};

mod oci_image;

mod materialize;
pub use materialize::{Materialize, MaterializeEvent, OutputSpec, Report, Sink};

mod patched;
pub use patched::{PatchedBuild, PatchedBuildResult};

mod standalone_test;
pub use standalone_test::{StandaloneTest, StandaloneTestError};

mod task_env;
pub use task_env::{CaptureWriter, TaskEnv};

mod project;
pub use project::{
    InitPlan, InitProject, ProjectEnv, ProjectOp, RevChange, UpdateProject, UpdateReport,
};

/// Constructs the "sandbox execution is only supported on Linux" error.
#[cfg(not(target_os = "linux"))]
pub fn sandbox_unsupported() -> Error {
    Error::Other(anyhow::anyhow!(
        "sandbox execution is only supported on Linux"
    ))
}
