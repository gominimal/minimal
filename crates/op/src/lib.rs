//! Implements operations using the minimal graph, such as builds or constructing cache objects.

use std::path::PathBuf;

use cache::{Cache, LocalDir};
use graph::DepGraph;

mod error;
pub use error::Error;

/// Standard options and configuration needed for most operations.
pub struct Options<'a> {
    pub cache: Cache<LocalDir>,
    pub graph: &'a DepGraph,
    pub exec_base: PathBuf,
}

/// Describes an operation which is configured and ready to be executed.
pub trait Runnable {
    type Result: Sized + Send + Sync;
    fn run(&mut self, opts: &Options) -> Result<Self::Result, Error>;
}

mod subsets;
pub use subsets::SubsetBuild;
