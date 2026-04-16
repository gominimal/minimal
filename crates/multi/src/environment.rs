//! The execution environment.
use std::{collections::BTreeMap, sync::Arc};

use graph::Graph;
use mctx::Context;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::{
    shared_resources::SharedResourcesHandle,
    tasks::{Task, TaskHandle},
    workspace::WorkspaceHandle,
};

/// The source of configuration for an environment.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigSource {
    /// Load configuration from the `minimal.toml` in the workspace.
    Workspace,
    /// Use the provided graph.
    #[allow(dead_code)]
    Graph(Graph),
}

/// A configured execution environment / sandbox.
pub struct Environment {
    /// A unique id that identifies this environment.
    pub(crate) id: Uuid,
    /// Where the configuration of the environment comes from.
    config_source: ConfigSource,
    /// The base set of files this environment works with.
    workspace: WorkspaceHandle,

    /// The tasks spawned off this environment.
    tasks: BTreeMap<Uuid, TaskHandle>,

    #[allow(dead_code)] // Held to keep the shared state alive.
    shared: SharedResourcesHandle,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("id", &self.id)
            .field("config_source", &self.config_source)
            .field("workspace", &self.workspace)
            .field("tasks", &self.tasks)
            .finish_non_exhaustive()
    }
}

impl Environment {
    pub(crate) fn new_from_workspace(
        workspace: WorkspaceHandle,
        shared: SharedResourcesHandle,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            config_source: ConfigSource::Workspace,
            workspace,
            tasks: BTreeMap::new(),
            shared,
        }
    }

    pub(crate) fn into_handle(self) -> EnvironmentHandle {
        EnvironmentHandle(Arc::new(Mutex::new(self)))
    }
}

/// A thread-safe handle to an environment.
#[derive(Debug, Clone)]
pub struct EnvironmentHandle(Arc<Mutex<Environment>>);

impl EnvironmentHandle {
    /// Takes the lock, allowing mutable access to an [Environment].
    ///
    /// Drop the result as quickly as possible to yield the lock for other async tasks.
    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, Environment> {
        self.0.lock().await
    }

    /// Spawns a task by name, building a fresh Context/Graph and Env for it.
    ///
    /// The task must be declared in the `minimal.toml` loaded by this environment.
    pub async fn new_named_task(
        &self,
        name: String,
        task_args: Option<&std::collections::HashMap<String, args::Arg>>,
    ) -> Result<TaskHandle, mctx::Error> {
        let (graph, ctx) = self.build_new().await?;
        let shared = self.0.lock().await.shared.clone();

        let task = Task::new_named(name, task_args, graph, ctx, self.clone(), shared).await?;
        let id = task.id;
        let handle = task.into_handle();

        self.0.lock().await.tasks.insert(id, handle.clone());

        Ok(handle)
    }

    /// Constructs and returns a Context and Graph to be used to build sandboxes.
    pub async fn build_new(&self) -> Result<(Graph, Context), mctx::Error> {
        let s = self.0.lock().await;
        let workspace = s.workspace.clone();
        match &s.config_source {
            ConfigSource::Workspace => {
                let shared = s.shared.clone();
                drop(s);
                let (minimal_dir, vcs) = {
                    let sl = shared.lock().await;
                    (sl.minimal_dir.clone(), sl.vcs.clone())
                };

                let mut context = Context::new(
                    mctx::ConfigBuilder::new()
                        .with_repo_dir(workspace.path().await)
                        .with_state_dir(minimal_dir)
                        .with_vcs_manager(vcs.clone())
                        .build()
                        .unwrap(),
                )?;
                Ok((context.graph_from_all_packages()?, context))
            }
            ConfigSource::Graph(_g) => {
                let shared = s.shared.clone();
                drop(s);
                let (minimal_dir, vcs, cache, stdlib_dir) = {
                    let sl = shared.lock().await;
                    (
                        sl.minimal_dir.clone(),
                        sl.vcs.clone(),
                        sl.cache.clone(),
                        sl.stdlib_dir.clone(),
                    )
                };

                let mut context = Context::new_from_parts(
                    mctx::ConfigBuilder::new()
                        .with_repo_dir(workspace.path().await)
                        .with_state_dir(minimal_dir)
                        .with_vcs_manager(vcs.clone())
                        .build()
                        .unwrap(),
                    mfile::File::synthetic(mfile::LinkConfig::Git {
                        repo: "https://github.com/gominimal/pkgs".to_string(),
                        branch: Some("main".to_string()),
                        locked_commit: None,
                    }),
                    vcs,
                    cache,
                    stdlib_dir,
                );
                Ok((context.graph_from_all_packages()?, context))
            }
        }
    }
}
