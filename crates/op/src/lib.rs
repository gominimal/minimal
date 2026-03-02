//! Implements operations using the minimal graph, such as builds or constructing cache objects.
#![allow(clippy::result_large_err)]

use std::path::PathBuf;

use cache::{Cache, LocalDir, PendingDir};
use graph::Graph;

mod error;
pub use error::Error;

/// Standard options and configuration needed for most operations.
pub struct Options<'a> {
    pub cache: Cache<LocalDir>,
    pub graph: &'a Graph,
    pub exec_base: PathBuf,
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

#[allow(dead_code)]
pub mod remote_build;

mod subsets;
pub use subsets::SubsetBuild;

mod sources;
pub use sources::{SourceFetcher, SourceLoad};
mod specs;
pub use specs::{SpecBuild, SpecBuildResult};

mod oci_image;
pub use oci_image::OciImageCreate;

mod standalone_test;
pub use standalone_test::StandaloneTest;
