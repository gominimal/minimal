use std::sync::Arc;

use cache::{Cache, LocalDir};
use common::SpecHash;
use graph::{BuildSpecRef, DepGraph, ExecPlan, SubsetInput};
use tokio::{
    sync::{RwLock, RwLockReadGuard},
    task::JoinSet,
};

mod state;
use state::{DeliverableRef, DeliverableState, State, StateHandle};

mod traits;
use traits::Backend;

/// The shared state used heavily everywhere.
#[derive(Debug)]
pub struct Shared {
    graph: DepGraph,
    cache: Cache<LocalDir>,
}

/// An async / task-friendly wrapper around state used everywhere.
#[derive(Debug, Clone)]
struct SharedHandle(Arc<RwLock<Shared>>);

impl SharedHandle {
    fn new(shared: Shared) -> Self {
        Self(Arc::new(RwLock::new(shared)))
    }

    pub async fn graph(&self) -> RwLockReadGuard<'_, DepGraph> {
        RwLockReadGuard::map(self.0.read().await, |s| &s.graph)
    }
}

/// Manages the materialization of some built artifacts end-to-end.
pub struct Orchestrator<B: Backend> {
    pub top_levels: Vec<BuildSpecRef>,
    pub backend: B,
}

impl<B: Backend> Orchestrator<B> {
    async fn run(&mut self, shared: Shared) -> Result<(), crate::Error> {
        let state = State::<B>::from_plan(
            &shared.graph,
            ExecPlan::with_toplevels((), &shared.graph, &self.top_levels),
        )?
        .into_handle();
        let shared_hnd = SharedHandle::new(shared);

        let mut pending: JoinSet<()> = JoinSet::new();
        while !state.done().await {
            // Spawn tasks for all runnables
            for dr in state.runnables().await.into_iter() {
                let mut deliverable = state.lock_for_deliverable(&dr).await;
                assert!(matches!(deliverable.state, DeliverableState::Pending));

                // Spawn a task for the corresponding deliverable type
                let abort_handle = match &deliverable.inner {
                    state::DeliverableInner::Build {
                        bsr,
                        spec_hash,
                        full_build: _,
                        dependencies,
                    } => pending.spawn(
                        OrchestratedBuild {
                            shared_hnd: shared_hnd.clone(),
                            state_hnd: state.clone(),
                            deliverable: dr,

                            bsr: *bsr,
                            spec_hash: spec_hash.clone(),
                            dependencies: dependencies.clone(),
                        }
                        .run(),
                    ),
                    state::DeliverableInner::CacheFill { bsr, spec_hash } => pending.spawn(
                        OrchestratedCacheFill {
                            shared_hnd: shared_hnd.clone(),
                            state_hnd: state.clone(),
                            deliverable: dr,

                            bsr: *bsr,
                            spec_hash: spec_hash.clone(),
                        }
                        .run(),
                    ),
                    state::DeliverableInner::Subset {
                        subset,
                        spec_hash,
                        build,
                    } => pending.spawn(
                        OrchestratedSubset {
                            shared_hnd: shared_hnd.clone(),
                            state_hnd: state.clone(),
                            deliverable: dr,

                            subset: subset.clone(),
                            spec_hash: spec_hash.clone(),
                            build: *build,
                        }
                        .run(),
                    ),
                };
                deliverable.state = DeliverableState::InProgress(abort_handle);
                drop(deliverable);
            }

            while let Some(task_result) = pending.join_next().await {
                println!("task joined: {:?}", task_result);
            }
        }

        pending.join_all().await;
        todo!()
    }
}

struct OrchestratedBuild<B: Backend> {
    shared_hnd: SharedHandle,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    bsr: BuildSpecRef,
    spec_hash: SpecHash,
    dependencies: Vec<DeliverableRef>,
}

impl<B: Backend> OrchestratedBuild<B> {
    async fn run(self) -> () {
        todo!()
    }
}

struct OrchestratedCacheFill<B: Backend> {
    shared_hnd: SharedHandle,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    bsr: BuildSpecRef,
    spec_hash: SpecHash,
}

impl<B: Backend> OrchestratedCacheFill<B> {
    async fn run(self) -> () {
        todo!()
    }
}

struct OrchestratedSubset<B: Backend> {
    shared_hnd: SharedHandle,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    subset: SubsetInput,
    build: DeliverableRef,
    spec_hash: SpecHash,
}

impl<B: Backend> OrchestratedSubset<B> {
    async fn run(self) -> () {
        todo!()
    }
}
