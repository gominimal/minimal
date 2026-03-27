use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::{Mutex, MutexGuard};

/// The resources shared across workspaces.
#[derive(Debug)]
pub struct SharedResources {
    pub(crate) vcs: checkouts::ManagerHandle,
    pub(crate) cache: mctx::Cache,
    pub(crate) stdlib_dir: PathBuf,
    pub(crate) minimal_dir: PathBuf,
}

impl SharedResources {
    pub fn new<P: AsRef<Path>>(minimal_dir: P) -> Result<Self, mctx::Error> {
        let config = mctx::ConfigBuilder::new()
            .with_state_dir(minimal_dir.as_ref().to_path_buf())
            .build()
            .map_err(mctx::Error::Config)?;

        let (vcs, cache, stdlib_dir) = mctx::Context::sub_setup(&config)?;
        Ok(Self {
            vcs,
            cache,
            stdlib_dir,
            minimal_dir: minimal_dir.as_ref().to_path_buf(),
        })
    }

    pub fn into_handle(self) -> SharedResourcesHandle {
        SharedResourcesHandle(Arc::new(Mutex::new(self)))
    }
}

/// A thread-safe handle to [SharedResources].
#[derive(Debug, Clone)]
pub struct SharedResourcesHandle(Arc<Mutex<SharedResources>>);

impl SharedResourcesHandle {
    /// Takes the lock, allowing mutable access to [SharedResources].
    ///
    /// Drop the result as quickly as possible to yield the lock for other async tasks.
    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, SharedResources> {
        self.0.lock().await
    }
}
