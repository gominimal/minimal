//! A manager of workspaces (files), environments (configured sandboxes), and the
//! things running in them.
//!
//! Object model:
//!  * Workspaces. A filetree made available in an environment.
//!  * Environments. A configured (sandbox-based) system you can run things in, that
//!    operating primarily off a workspace.
//!  * Task. Something presently running in an environment.
//!
//! Ownership:
//!  * Overall, all three objects are heap allocated and access is mediated via handles which
//!    implement reference counting and interior mutability via locking.
//!  * The [Manager] is responsible for creating workspaces/environments, and owning a top-level
//!    handle to them so they are accessible via methods on [Manager].

use common::repo_spec::Repo;
use generational_arena::{Arena, Index};
use std::{collections::HashMap, path::Path};
use uuid::Uuid;

mod shared_resources;
use shared_resources::{SharedResources, SharedResourcesHandle};

mod environment;

pub mod mux;

mod tasks;

mod workspace;
use workspace::{Workspace, WorkspaceHandle};

use crate::environment::EnvironmentHandle;

/// Manager of a set of workspaces and environments.
#[derive(Debug)]
pub struct Manager {
    shared: SharedResourcesHandle,

    workspaces: Arena<WorkspaceHandle>,
    workspace_by_uuid: HashMap<Uuid, Index>,

    environments: Arena<EnvironmentHandle>,
    environments_by_uuid: HashMap<Uuid, Index>,
}

impl Manager {
    /// Creates a new manager, using the provided minimal dir to store state.
    pub fn new<P: AsRef<Path>>(minimal_dir: P) -> Result<Self, mctx::Error> {
        let shared = SharedResources::new(minimal_dir)?.into_handle();

        Ok(Self {
            shared,
            workspaces: Arena::new(),
            workspace_by_uuid: HashMap::new(),
            environments: Arena::new(),
            environments_by_uuid: HashMap::new(),
        })
    }

    /// Returns the workspace with the specified uuid.
    pub fn workspace(&self, uuid: &Uuid) -> Option<WorkspaceHandle> {
        self.workspace_by_uuid
            .get(uuid)
            .map(|idx| self.workspaces.get(*idx).unwrap().clone())
    }
    fn save_workspace(&mut self, workspace: Workspace) -> (Uuid, WorkspaceHandle) {
        let uuid = workspace.id;
        let h = workspace.into_handle();
        let idx = self.workspaces.insert(h.clone());
        self.workspace_by_uuid.insert(uuid, idx);
        (uuid, h)
    }
    /// Creates an empty workspace.
    pub async fn empty_workspace(&mut self) -> Result<(Uuid, WorkspaceHandle), mctx::Error> {
        let shared = self.shared.clone();
        let tmpdir = shared
            .lock()
            .await
            .cache
            .temp_dir()
            .map_err(|e| mctx::Error::IO("temp dir", "".into(), e))?;
        Ok(self.save_workspace(Workspace::new_from_tempdir(tmpdir, shared).await?))
    }
    /// Creates an environment backed by the given workspace.
    pub fn new_environment(&mut self, workspace: WorkspaceHandle) -> (Uuid, EnvironmentHandle) {
        let env = environment::Environment::new_from_workspace(workspace, self.shared.clone());
        let uuid = env.id;
        let handle = env.into_handle();
        let idx = self.environments.insert(handle.clone());
        self.environments_by_uuid.insert(uuid, idx);
        (uuid, handle)
    }

    /// Creates a workspace based on some git ref.
    pub async fn git_derived_workspace(
        &mut self,
        base: Repo,
    ) -> Result<(Uuid, WorkspaceHandle), mctx::Error> {
        todo!("git_derived_workspace: {:?}", base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn manager_create_workspace() {
        let base = TempDir::new().unwrap();
        let mut manager = Manager::new(base.path()).unwrap();

        let (empty_uuid, empty_hnd) = manager.empty_workspace().await.unwrap();
        assert_eq!(empty_hnd.lock().await.id, empty_uuid);
        assert_eq!(
            manager.workspace(&empty_uuid).unwrap().lock().await.id,
            empty_uuid
        );
    }

    /// Copies all files from `src` into `dst`, preserving directory structure.
    fn copy_dir_recursive(src: &Path, dst: &Path) {
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let dest_path = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                std::fs::create_dir_all(&dest_path).unwrap();
                copy_dir_recursive(&entry.path(), &dest_path);
            } else {
                std::fs::copy(entry.path(), dest_path).unwrap();
            }
        }
    }

    #[tokio::test]
    #[ignore] // Requires Linux namespaces (not available in CI / GitHub Actions).
    async fn task_smoketest() {
        let state = TempDir::new().unwrap();
        let mut manager = Manager::new(state.path()).unwrap();

        // Create the workspace and copy fakerepo + fakepkgs into it,
        // preserving the relative path layout (fakerepo's minimal.toml
        // references `dir = "../fakepkgs"`).
        let (_ws_uuid, ws) = manager.empty_workspace().await.unwrap();
        let ws_dir = ws.path().await;
        let testdata =
            Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../mctx/testdata");
        copy_dir_recursive(&testdata.join("fakerepo"), &ws_dir);
        let fakepkgs_dst = ws_dir.parent().unwrap().join("fakepkgs");
        std::fs::create_dir_all(&fakepkgs_dst).unwrap();
        copy_dir_recursive(&testdata.join("fakepkgs"), &fakepkgs_dst);

        // Create an environment backed by the workspace.
        let (_env_uuid, env_handle) = manager.new_environment(ws);

        // Spawn the task — this resolves the minimal.toml, builds packages,
        // and constructs the sandboxed Env.
        let task_handle = env_handle
            .new_named_task("task-smoketest".into(), None)
            .await
            .unwrap();

        // Verify the task was created with the right state.
        let task = task_handle.lock().await;
        assert!(!task.id.is_nil());
        drop(task);
    }

    /// Tests that bytes written via [`Task::send_input`] reach the child's
    /// stdin and are echoed back through the PTY.
    ///
    /// Uses a `cat` task (reads stdin, writes to stdout) so the round-trip is:
    ///   send_input → PTY master → child stdin → cat → child stdout → PTY → screen
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Linux namespaces.
    async fn task_stdin_echo() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init()
            .ok();

        use crate::mux::WinSize;

        let state = TempDir::new().unwrap();
        let mut manager = Manager::new(state.path()).unwrap();

        // Set up workspace with fakerepo + fakepkgs.
        let (_ws_uuid, ws) = manager.empty_workspace().await.unwrap();
        let ws_dir = ws.path().await;
        let testdata =
            Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../mctx/testdata");
        copy_dir_recursive(&testdata.join("fakerepo"), &ws_dir);
        let fakepkgs_dst = ws_dir.parent().unwrap().join("fakepkgs");
        std::fs::create_dir_all(&fakepkgs_dst).unwrap();
        copy_dir_recursive(&testdata.join("fakepkgs"), &fakepkgs_dst);

        // Create environment and start the cat-stdin task.
        let (_env_uuid, env_handle) = manager.new_environment(ws);
        let task_handle = env_handle
            .new_named_task("cat-stdin".into(), None)
            .await
            .unwrap();

        let size = WinSize {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        };
        task_handle.start(size).await.unwrap();

        // Send a known string to stdin. Retry briefly in case the child
        // hasn't finished exec yet (send_input returns Closed if the task
        // already transitioned out of Running).
        const MARKER: &str = "hello-from-stdin-test";
        for _ in 0..20 {
            let task = task_handle.lock().await;
            if task
                .send_input(format!("{}\n", MARKER).into_bytes())
                .is_ok()
            {
                break;
            }
            drop(task);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Poll the screen until the marker appears (or timeout).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let task = task_handle.lock().await;
            let screen = task.screen().expect("screen should exist after start");
            let contents = screen.lock().unwrap().screen().contents();
            if contents.contains(MARKER) {
                break;
            }
            drop(task);
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "timed out waiting for marker on screen, last contents: {}",
                    contents
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Send Ctrl-D (EOF) so cat exits cleanly.
        {
            let task = task_handle.lock().await;
            task.send_input(vec![0x04]).unwrap();
        }

        // Wait for the task to finish.
        tokio::time::timeout(std::time::Duration::from_secs(30), task_handle.wait())
            .await
            .expect("task did not finish within timeout");
    }

    /// Exercises the full Task + Driver lifecycle:
    ///   Ready → start() → Running → (driver finishes) → Finished
    ///
    /// Verifies state transitions, screen capture, broadcast output, and exit code.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore] // Requires Linux namespaces.
    async fn task_driver_lifecycle() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init()
            .ok();

        use crate::mux::WinSize;
        use crate::tasks::TaskState;

        let state = TempDir::new().unwrap();
        let mut manager = Manager::new(state.path()).unwrap();

        // Set up workspace with fakerepo + fakepkgs.
        let (_ws_uuid, ws) = manager.empty_workspace().await.unwrap();
        let ws_dir = ws.path().await;
        let testdata =
            Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../mctx/testdata");
        copy_dir_recursive(&testdata.join("fakerepo"), &ws_dir);
        let fakepkgs_dst = ws_dir.parent().unwrap().join("fakepkgs");
        std::fs::create_dir_all(&fakepkgs_dst).unwrap();
        copy_dir_recursive(&testdata.join("fakepkgs"), &fakepkgs_dst);

        // Create environment
        let (_env_uuid, env_handle) = manager.new_environment(ws);
        // Create task - corresponds to the print-date task in fakerepo/minimal.toml
        let task_handle = env_handle
            .new_named_task("print-date".into(), None)
            .await
            .unwrap();

        // Tasks that have not been started are in the ready state
        {
            let task = task_handle.lock().await;
            assert!(
                matches!(task.state(), TaskState::Ready { .. }),
                "expected Ready, got {:?}",
                task.state()
            );
            assert!(task.screen().is_none(), "no screen before start");
        }

        // Start
        let size = WinSize {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        };
        task_handle.start(size).await.unwrap();

        // Subscribe to live output while the task is running.
        let maybe_sub = task_handle.subscribe().await;

        // If we subscribed before completion, drain the broadcast channel
        // (blocks until the driver finishes and drops the sender).
        let broadcast_bytes = if let Some(sub) = maybe_sub {
            let mut rx = sub.rx;
            let mut collected = sub.initial_state;
            loop {
                match rx.recv().await {
                    Ok(chunk) => collected.extend_from_slice(&chunk),
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            Some(collected)
        } else {
            None
        };

        // Wait for the driver to finish.
        tokio::time::timeout(std::time::Duration::from_secs(30), task_handle.wait())
            .await
            .expect("task did not finish within timeout");

        let task = task_handle.lock().await;
        let exit_code = match task.state() {
            TaskState::Finished { exit_status } => exit_status.code,
            other => panic!("expected Finished, got {:?}", other),
        };
        assert_eq!(exit_code, 0, "task should exit successfully");

        // Screen should contain the date output (which always has colons in the time).
        let screen = task.screen().expect("screen should outlive the task");
        let contents = screen.lock().unwrap().screen().contents();
        assert!(
            contents.contains(':'),
            "date output should contain a colon: {}",
            contents
        );

        // If we subscribed, the broadcast should have delivered output too.
        if let Some(bytes) = broadcast_bytes {
            assert!(!bytes.is_empty(), "broadcast should deliver output bytes");
        }
    }
}
