//! The orchestration module performs the operations necessary to make some given software (i.e. build-specs) runnable.
//!
//! The primary type here is [Orchestrator], which is parameterized by a [Backend]. The intention is that
//! different backends can be used for local builds vs remote builds and other architectural variants, while all
//! the main/control logic stays the same.
#![recursion_limit = "256"]
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use common::SpecHash;
use graph::{BinProvider, BuildSpecRef, ExecPlan, Graph, SubsetInput};
use lcache::{Cache, LocalDir};
use tokio::{
    sync::{RwLock, RwLockReadGuard, Semaphore},
    task::{JoinSet, yield_now},
};

mod local_backend;
pub use local_backend::{BuildEvent, BuildEventInner, LocalBackend};

mod render;
pub use render::{BuildLine, BuildLineKind, BuildRenderer};

mod state;
pub use state::{Deliverable, DeliverableInner, DeliverableState, State, StateHandle};

mod ids;
pub use ids::DeliverableRef;

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
    pub graph: Graph,
    pub cache: Cache<LocalDir>,
    pub backend: B,
    pub daemon_id: Option<String>,
    pub fetch_semaphore: Semaphore,
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
    pub async fn graph<'a>(&'a self) -> RwLockReadGuard<'a, Graph> {
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
    pub backend: B,
    pub graph: Graph,
    pub cache: Cache<LocalDir>,
    pub daemon_id: Option<String>,
}

impl<B: Backend> Orchestrator<B> {
    /// Executes the build.
    pub async fn run<BP: BinProvider>(self, bp: BP) -> (Vec<B::Artifact>, Result<(), Error>) {
        let shared = Shared {
            graph: self.graph.clone(),
            cache: self.cache.clone(),
            daemon_id: self.daemon_id.clone(),
            backend: self.backend,
            fetch_semaphore: Semaphore::new(8),
        };
        let state = match State::from_plan(
            &shared.graph,
            ExecPlan::with_toplevels(bp, &shared.graph, &shared.graph.top_levels),
        ) {
            Ok(s) => s,
            Err(e) => {
                return (vec![], Err(e));
            }
        };

        match Self::run_impl(state, shared).await {
            Ok(v) => (v, Ok(())),
            Err((state_hnd, e)) => (
                state_hnd
                    .into_inner()
                    .unwrap()
                    .s
                    .deliverables
                    .into_iter()
                    .filter_map(|d| match d.state {
                        DeliverableState::Complete(a) => Some(a),
                        _ => None,
                    })
                    .collect(),
                Err(e),
            ),
        }
    }

    async fn run_impl(
        state: State<B>,
        shared: Shared<B>,
    ) -> Result<Vec<B::Artifact>, (StateHandle<B>, Error)> {
        let state_hnd = state.into_handle();
        let shared_hnd = SharedHandle::new(shared);

        let mut pending: JoinSet<Result<(), (DeliverableRef, Error)>> = JoinSet::new();
        // A JoinSet task starts with no current span: without this every build,
        // cache fill and package fetch (`materialize`) began a trace of its own,
        // cut off from the activation that asked for it.
        let span = tracing::Span::current();
        // Cache fills whose artifact the store no longer has (dangling hits).
        // Such a fill fails only itself and what depends on it; everything
        // else runs to completion, and the whole set goes back to the caller
        // at once, so a retention sweep that left N dangling specs costs one
        // extra pass, not N, and no in-flight build is aborted for it.
        let mut dangling: Vec<BuildSpecRef> = Vec::new();
        while !state_hnd.done().await {
            let mut s = state_hnd.lock().await;
            let mut runnables = s.runnable().map(|(dr, _)| dr).collect::<Vec<_>>();
            // Sort runnables by the ones which unblock the largest number of tasks first.
            runnables.sort_by(|a, b| {
                s.get(a)
                    .unwrap()
                    .depended_on_by
                    .cmp(&s.get(b).unwrap().depended_on_by)
                    .reverse()
            });
            // Spawn tasks for all runnables
            for dr in runnables.into_iter() {
                let deliverable = s.get_mut(&dr).unwrap();
                assert!(matches!(deliverable.state, DeliverableState::Pending));

                // Spawn a task for the corresponding deliverable type
                let abort_handle = match &deliverable.inner {
                    state::DeliverableInner::Build {
                        bsr,
                        spec_hash,
                        full_build: _,
                        cost: _,
                        dependencies,
                    } => pending.spawn(tracing::Instrument::instrument(
                        OrchestratedBuild {
                            shared_hnd: shared_hnd.clone(),
                            state_hnd: state_hnd.clone(),
                            deliverable: dr,

                            bsr: *bsr,
                            spec_hash: spec_hash.clone(),
                            dependencies: dependencies.clone(),
                        }
                        .run(),
                        span.clone(),
                    )),
                    state::DeliverableInner::CacheFill { bsr, spec_hash } => {
                        pending.spawn(tracing::Instrument::instrument(
                            OrchestratedCacheFill {
                                shared_hnd: shared_hnd.clone(),
                                state_hnd: state_hnd.clone(),
                                deliverable: dr,

                                bsr: *bsr,
                                spec_hash: spec_hash.clone(),
                            }
                            .run(),
                            span.clone(),
                        ))
                    }
                    state::DeliverableInner::Subset {
                        subset,
                        spec_hash,
                        build,
                    } => pending.spawn(tracing::Instrument::instrument(
                        OrchestratedSubset {
                            shared_hnd: shared_hnd.clone(),
                            state_hnd: state_hnd.clone(),
                            deliverable: dr,

                            subset: subset.clone(),
                            spec_hash: spec_hash.clone(),
                            build: *build,
                        }
                        .run(),
                        span.clone(),
                    )),
                };
                deliverable.state = DeliverableState::InProgress(abort_handle);
            }
            drop(s);

            if let Some(task_result) = pending.join_next().await {
                match task_result {
                    Ok(r) => match r {
                        Ok(()) => {}
                        Err((dr, Error::DanglingCacheHit(hits))) => {
                            tracing::warn!(
                                "{}: the remote cache lists it but the store no longer has it; it will be built after this pass",
                                state_hnd
                                    .lock_for_deliverable(&dr)
                                    .await
                                    .inner
                                    .display(&*shared_hnd.graph().await),
                            );
                            dangling.extend(hits);
                        }
                        Err((dr, e)) => {
                            tracing::error!(
                                "{} construction failed: {}",
                                state_hnd
                                    .lock_for_deliverable(&dr)
                                    .await
                                    .inner
                                    .display(&*shared_hnd.graph().await),
                                e
                            );
                            pending.abort_all();
                            while pending.join_next().await.is_some() {}
                            return Err((state_hnd, e));
                        }
                    },
                    Err(e) => {
                        if e.is_cancelled() {
                            tracing::warn!("execution for a deliverable was cancelled: {}", e);
                        } else {
                            tracing::error!("execution for a deliverable panicked! {}", e);
                        }
                        pending.abort_all();
                        while pending.join_next().await.is_some() {}
                        return Err((state_hnd, Error::Other(e.into())));
                    }
                }
            } else if !dangling.is_empty() {
                // nothing in flight and nothing runnable without the dangling
                // fills: everything else is complete, hand the set back
                return Err((state_hnd, Error::DanglingCacheHit(dangling)));
            }
            yield_now().await;
        }

        while let Some(task_result) = pending.join_next().await {
            match task_result {
                Ok(r) => match r {
                    Ok(()) => {}
                    Err((dr, e)) => {
                        tracing::error!(
                            "{} construction failed: {}",
                            state_hnd
                                .lock_for_deliverable(&dr)
                                .await
                                .inner
                                .display(&*shared_hnd.graph().await),
                            e
                        );
                        pending.abort_all();
                        while pending.join_next().await.is_some() {}
                        return Err((state_hnd, e));
                    }
                },
                Err(e) => {
                    if e.is_cancelled() {
                        tracing::warn!("execution for a deliverable was cancelled: {}", e);
                    } else {
                        tracing::error!("execution for a deliverable panicked! {}", e);
                    }
                    pending.abort_all();
                    while pending.join_next().await.is_some() {}
                    return Err((state_hnd, Error::Other(e.into())));
                }
            }
        }

        Ok(state_hnd
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

#[cfg(test)]
mod dangling_tests {
    use super::*;
    use crate::ids::DeliverableRef;
    use decode::Layer;
    use graph::{BinProvider, BuildSpecRef, Graph, MaskingBinProvider, SubsetInput};
    use indoc::indoc;
    use lcache::{Cache, LocalDir};
    use std::collections::HashSet;

    /// Every cache fill is a dangling hit; every build succeeds.
    #[derive(Debug)]
    struct Dangle;

    impl Backend for Dangle {
        type Artifact = ();
        async fn build(
            _: DeliverableRef,
            _: BuildSpecRef,
            _: SpecHash,
            _: Vec<DeliverableRef>,
            _: &mut SharedHandle<Self>,
            _: &mut StateHandle<Self>,
        ) -> Result<(), Error> {
            Ok(())
        }
        async fn cache_hydrate(
            _: DeliverableRef,
            bsr: BuildSpecRef,
            _: SpecHash,
            _: &mut SharedHandle<Self>,
            _: &mut StateHandle<Self>,
        ) -> Result<(), Error> {
            Err(Error::DanglingCacheHit(vec![bsr]))
        }
        async fn materialize_subset(
            _: DeliverableRef,
            _: SubsetInput,
            _: DeliverableRef,
            _: SpecHash,
            _: &mut SharedHandle<Self>,
            _: &mut StateHandle<Self>,
        ) -> Result<(), Error> {
            unreachable!("no subsets in this graph")
        }
    }

    /// The index lists exactly these specs.
    #[derive(Debug)]
    struct Listed(HashSet<BuildSpecRef>);

    impl BinProvider for Listed {
        fn exists(&self, bsr: &BuildSpecRef) -> bool {
            self.0.contains(bsr)
        }
    }

    fn graph() -> Graph {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let a = { name = \"a\", build_deps = [], cmd = \"\" } | BuildSpec in
                let b = { name = \"b\", build_deps = [], cmd = \"\" } | BuildSpec in
                { name = \"top\", build_deps = [a, b], cmd = \"\" } | BuildSpec
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed")
        });
        Graph::new().ingest(layer).unwrap()
    }

    fn orchestrator(graph: &Graph, dir: &std::path::Path) -> Orchestrator<Dangle> {
        Orchestrator {
            backend: Dangle,
            graph: graph.clone(),
            cache: Cache::<LocalDir>::at_dir(dir).unwrap(),
            daemon_id: None,
        }
    }

    /// Two leaves the index lists but the store no longer has: one pass
    /// reports BOTH as dangling (not the first alone), and a second pass
    /// with them masked builds everything.
    #[tokio::test]
    async fn one_pass_learns_every_dangling_spec_and_the_masked_pass_builds() {
        let g = graph();
        let dir = tempfile::tempdir().unwrap();
        let leaves: HashSet<BuildSpecRef> = g
            .iter()
            .filter(|(_, b)| b.name != "top")
            .map(|(bsr, _)| bsr)
            .collect();
        assert_eq!(leaves.len(), 2);

        let (built, result) = orchestrator(&g, dir.path())
            .run(Listed(leaves.clone()))
            .await;
        let Err(Error::DanglingCacheHit(hits)) = result else {
            panic!("expected the dangling set, got {result:?}")
        };
        assert_eq!(
            hits.iter().copied().collect::<HashSet<_>>(),
            leaves,
            "both fills reported in one pass"
        );
        assert!(built.is_empty(), "nothing could complete without the fills");

        let masked = MaskingBinProvider::new(Listed(leaves), hits);
        let (built, result) = orchestrator(&g, dir.path()).run(masked).await;
        result.unwrap();
        assert_eq!(built.len(), 3, "a, b and top built");
    }
}
