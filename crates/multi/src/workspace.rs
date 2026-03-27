use common::repo_spec::Repo;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::TempDir;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::shared_resources::SharedResourcesHandle;

/// Describes where the files that initially populated a workspace
/// came from.
#[derive(Debug)]
pub enum Origin {
    /// Theres no initial files in the workspace, or they were loaded piecewise.
    Ephemeral,
    /// The initial files were a checkout of some git repo.
    #[allow(dead_code)]
    GitCheckout(Repo),
}

/// A ready-to-use working set of files.
#[derive(Debug)]
pub struct Workspace {
    /// A unique id that identifies this workspace.
    pub(crate) id: Uuid,
    /// The base directory where the files for this worktree are located.
    pub(crate) worktree_dir: PathBuf,
    /// How the base directory was initially populated.
    #[allow(dead_code)]
    pub(crate) files_origin: Origin,

    /// Held to prevent cleanup until the env is dropped.
    #[allow(dead_code)]
    temps: Vec<TempDir>,
}

/// Creation API
impl Workspace {
    /// Creates a new workspace based on the files in the given tempdir.
    ///
    /// The tempdir will be deleted when the workspace is cleaned up.
    pub async fn new_from_tempdir(
        dir: TempDir,
        _shared: SharedResourcesHandle,
    ) -> Result<Self, mctx::Error> {
        // let sl = shared.lock().await;
        // let context = Context::new(
        //     mctx::ConfigBuilder::new()
        //         .with_repo_dir(dir.path().to_path_buf())
        //         .with_state_dir(sl.minimal_dir.clone())
        //         .with_vcs_manager(sl.vcs.clone())
        //         .build()
        //         .unwrap(),
        // )?;

        Ok(Self {
            id: Uuid::new_v4(),
            worktree_dir: dir.path().to_path_buf(),
            files_origin: Origin::Ephemeral,
            temps: vec![dir],
        })
    }
    /// Creates a new workspace using the given path as the base directory.
    ///
    /// The caller is responsible for maintaining the given path for the life of
    /// the workspace.
    pub async fn new_from_path<P: AsRef<Path>>(
        dir: P,
        _shared: SharedResourcesHandle,
    ) -> Result<Self, mctx::Error> {
        Ok(Self {
            id: Uuid::new_v4(),
            worktree_dir: dir.as_ref().to_path_buf(),
            files_origin: Origin::Ephemeral,
            temps: vec![],
        })
    }

    pub fn into_handle(self) -> WorkspaceHandle {
        WorkspaceHandle(Arc::new(Mutex::new(self)))
    }
}

/// A thread-safe handle to a workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceHandle(Arc<Mutex<Workspace>>);

impl WorkspaceHandle {
    /// Takes the lock, allowing mutable access to [Workspace].
    ///
    /// Drop the result as quickly as possible to yield the lock for other async tasks.
    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, Workspace> {
        self.0.lock().await
    }
}

impl WorkspaceHandle {
    pub async fn id(&self) -> Uuid {
        self.lock().await.id
    }

    pub async fn path(&self) -> PathBuf {
        self.lock().await.worktree_dir.clone()
    }
}
