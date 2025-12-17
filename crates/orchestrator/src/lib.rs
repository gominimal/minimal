//! The orchestration module performs the operations necessary to make some given software (i.e. build-specs) runnable.
//!
//! The primary type here is [Orchestrator], which is parameterized by a [Backend]. The intention is that
//! different backends can be used for local builds vs remote builds and other architectural variants, while all
//! the main/control logic stays the same.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use cache::{Cache, LocalDir};
use common::SpecHash;
use graph::{BinProvider, BuildSpecRef, DepGraph, ExecPlan, SubsetInput};
use tokio::{
    sync::{RwLock, RwLockReadGuard},
    task::{JoinSet, yield_now},
};

mod local_backend;
pub use local_backend::LocalBackend;

mod state;
pub use state::{
    Deliverable, DeliverableInner, DeliverableRef, DeliverableState, State, StateHandle,
};

mod traits;
pub use traits::{Artifact, Backend};

mod error;
pub use error::Error;

/// The shared state used heavily everywhere.
///
/// This structure exists so it can be wrapped up in something that is tokio async friendly and
/// passed around as needed. Namely, a [SharedHandle].
#[derive(Debug)]
pub struct Shared<B: Backend> {
    pub graph: DepGraph,
    pub cache: Cache<LocalDir>,
    pub backend: B,
}

/// An async / task-friendly wrapper around state used everywhere.
#[derive(Debug)]
pub struct SharedHandle<B: Backend>(pub(crate) Arc<RwLock<Shared<B>>>);

impl<B: Backend> Clone for SharedHandle<B> {
    fn clone(&self) -> Self {
        SharedHandle(self.0.clone())
    }
}

impl<B: Backend> SharedHandle<B> {
    pub(crate) fn new(shared: Shared<B>) -> Self {
        Self(Arc::new(RwLock::new(shared)))
    }

    /// Takes a lock and returns &[DepGraph].
    ///
    /// Make sure to drop as soon as possible to release the lock.
    pub async fn graph(&self) -> RwLockReadGuard<'_, DepGraph> {
        RwLockReadGuard::map(self.0.read().await, |s| &s.graph)
    }

    /// Access the inner shared state.
    #[inline]
    pub fn inner(&self) -> &Arc<RwLock<Shared<B>>> {
        &self.0
    }
}

/// Manages the materialization of some built artifacts end-to-end.
pub struct Orchestrator<B: Backend> {
    pub top_levels: Vec<BuildSpecRef>,
    pub backend: B,
    pub graph: DepGraph,
    pub cache: Cache<LocalDir>,
}

impl<B: Backend> Orchestrator<B> {
    /// Executes the build.
    pub async fn run<BP: BinProvider>(self, bp: BP) -> Result<Vec<B::Artifact>, Error> {
        let shared = Shared {
            graph: self.graph.clone(),
            cache: self.cache.clone(),
            backend: self.backend,
        };
        let state = State::from_plan(
            &shared.graph,
            ExecPlan::with_toplevels(bp, &shared.graph, &self.top_levels),
        )?;

        Self::run_impl(state, shared).await
    }

    async fn run_impl(state: State<B>, shared: Shared<B>) -> Result<Vec<B::Artifact>, Error> {
        let state = state.into_handle();
        let shared_hnd = SharedHandle::new(shared);

        let mut pending: JoinSet<Result<(), (DeliverableRef, Error)>> = JoinSet::new();
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

            if let Some(task_result) = pending.join_next().await {
                match task_result {
                    Ok(r) => match r {
                        Ok(()) => {}
                        Err((dr, e)) => {
                            tracing::error!(
                                "{:?} construction failed: {}",
                                state.lock_for_deliverable(&dr).await.inner,
                                e
                            );
                            pending.abort_all();
                            return Err(e);
                        }
                    },
                    Err(e) => {
                        if e.is_cancelled() {
                            tracing::warn!("execution for a deliverable was cancelled: {}", e);
                        } else {
                            tracing::error!("execution for a deliverable panicked! {}", e);
                        }
                        pending.abort_all();
                        return Err(Error::Other(e.into()));
                    }
                }
            }
            yield_now().await;
        }

        while let Some(task_result) = pending.join_next().await {
            match task_result {
                Ok(r) => match r {
                    Ok(()) => {}
                    Err((dr, e)) => {
                        tracing::error!(
                            "{:?} construction failed: {}",
                            state.lock_for_deliverable(&dr).await.inner,
                            e
                        );
                        pending.abort_all();
                        return Err(e);
                    }
                },
                Err(e) => {
                    if e.is_cancelled() {
                        tracing::warn!("execution for a deliverable was cancelled: {}", e);
                    } else {
                        tracing::error!("execution for a deliverable panicked! {}", e);
                    }
                    pending.abort_all();
                    return Err(Error::Other(e.into()));
                }
            }
        }

        Ok(state
            .into_inner()
            .unwrap()
            .s
            .deliverables
            .into_iter()
            .map(|d| match d.state {
                DeliverableState::Complete(a) => a,
                _ => unreachable!(),
            })
            .collect())
    }
}

/// Adapter encapsulating the state needed when calling out to the generic backend for a build.
struct OrchestratedBuild<B: Backend> {
    shared_hnd: SharedHandle<B>,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    bsr: BuildSpecRef,
    spec_hash: SpecHash,
    dependencies: Vec<DeliverableRef>,
}

impl<B: Backend> OrchestratedBuild<B> {
    async fn run(mut self) -> Result<(), (DeliverableRef, Error)> {
        let d = self.deliverable;
        let r = B::build(
            d,
            self.bsr,
            self.spec_hash,
            self.dependencies,
            &mut self.shared_hnd,
            &mut self.state_hnd,
        )
        .await
        .map_err(|e| (d, e))?;

        let mut d = self.state_hnd.lock_for_deliverable(&d).await;
        d.state = DeliverableState::Complete(r);
        drop(d);
        Ok(())
    }
}

/// Adapter encapsulating the state needed when calling out to the generic backend for a cache fetch.
struct OrchestratedCacheFill<B: Backend> {
    shared_hnd: SharedHandle<B>,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    bsr: BuildSpecRef,
    spec_hash: SpecHash,
}

impl<B: Backend> OrchestratedCacheFill<B> {
    async fn run(mut self) -> Result<(), (DeliverableRef, Error)> {
        let d = self.deliverable;
        let r = B::cache_hydrate(
            d,
            self.bsr,
            self.spec_hash,
            &mut self.shared_hnd,
            &mut self.state_hnd,
        )
        .await
        .map_err(|e| (d, e))?;

        let mut d = self.state_hnd.lock_for_deliverable(&d).await;
        d.state = DeliverableState::Complete(r);
        drop(d);
        Ok(())
    }
}

/// Adapter encapsulating the state needed when calling out to the generic backend for materializing a subset.
struct OrchestratedSubset<B: Backend> {
    shared_hnd: SharedHandle<B>,
    state_hnd: StateHandle<B>,
    deliverable: DeliverableRef,

    subset: SubsetInput,
    build: DeliverableRef,
    spec_hash: SpecHash,
}

impl<B: Backend> OrchestratedSubset<B> {
    async fn run(mut self) -> Result<(), (DeliverableRef, Error)> {
        let d = self.deliverable;
        let r = B::materialize_subset(
            d,
            self.subset,
            self.build,
            self.spec_hash,
            &mut self.shared_hnd,
            &mut self.state_hnd,
        )
        .await
        .map_err(|e| (d, e))?;

        let mut d = self.state_hnd.lock_for_deliverable(&d).await;
        d.state = DeliverableState::Complete(r);
        drop(d);
        Ok(())
    }
}
