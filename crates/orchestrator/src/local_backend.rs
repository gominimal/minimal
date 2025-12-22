use std::path::PathBuf;

use crate::{
    Backend, Deliverable, DeliverableInner, DeliverableRef, DeliverableState, Orchestrator,
    SharedHandle, StateHandle,
};
use cache::{
    Cache, CacheErr, DirCacheEntry, EntryMeta, LocalDir, MetaInner, PendingDir, RemoteCache,
};
use common::SpecHash;
use either::Either;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::{BinProvider, BuildSpecRef, DepGraph, SubsetInput};
use op::{Runnable, SourceFetcher};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use crate::Error;

/// A type which implements [Backend] by building everything locally.
#[derive(Debug)]
pub struct LocalBackend<SF: SourceFetcher + 'static> {
    pub(crate) sf: SF,
    pub(crate) output_base: PathBuf,
    pub(crate) remote_cache: Option<RemoteCache<GcsStorage>>,
    pub(crate) build_semaphore: Semaphore,
}

impl<SF: SourceFetcher> Backend for LocalBackend<SF> {
    type Artifact = Either<(PendingDir, EntryMeta), DirCacheEntry<LocalDir>>;

    async fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        _spec_hash: SpecHash,
        dependencies: Vec<DeliverableRef>,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        let (dep_paths, breaker_build) = {
            let s = state_hnd.lock().await;
            let dep_paths: Vec<PathBuf> = dependencies
                .into_iter()
                .map(|dr| match s.get(&dr).unwrap() {
                    Deliverable {
                        inner: _,
                        state: DeliverableState::Complete(a),
                    } => match a {
                        Either::Left((pd, _meta)) => pd.path().to_path_buf(),
                        Either::Right(c) => c.path().to_path_buf(),
                    },
                    _ => unreachable!(),
                })
                .collect();
            let breaker_build =
                if let DeliverableInner::Build { full_build, .. } = s.get(&dr).unwrap().inner {
                    !full_build
                } else {
                    unreachable!()
                };
            drop(s);

            (dep_paths, breaker_build)
        };

        let shared_hnd2 = shared_hnd.clone();
        let artifact = spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let permit = shared.backend.build_semaphore.acquire().await.unwrap();
            let mut b = op::SpecBuild {
                override_deps: Some(dep_paths.into_iter().collect()),
                spec: &bsr,
                remote_fetcher: &shared.backend.sf,
            };

            let res = b
                .run(&op::Options {
                    cache: shared.cache.clone(),
                    graph: &shared.graph,
                    exec_base: shared.backend.output_base.clone(),
                })
                .await;
            drop(permit);
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await?;

        {
            let shared = shared_hnd.inner().read().await;
            let build = shared.graph.get(&bsr).unwrap();
            Ok(Either::Left((
                artifact.outputs,
                EntryMeta {
                    breaker_build,
                    inner: MetaInner::Spec(build.name.clone()),
                    origin: Some(build.from.as_ref().clone()),
                    build_ms: Some(artifact.build_ms),
                    ..Default::default()
                },
            )))
        }
    }

    async fn cache_hydrate(
        _dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        // Check local cache
        {
            let s = shared_hnd.inner().read().await;
            let cache_res = s.cache.read_dir(&spec_hash);
            drop(s);
            if let Ok(cd) = cache_res {
                return Ok(Either::Right(cd));
            }
        }

        let shared_hnd2 = shared_hnd.clone();
        spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let res = if let Some(remote_cache) = shared.backend.remote_cache.as_ref() {
                let build = shared.graph.get(&bsr).unwrap();
                let (fetch_time, pending_dir) = remote_cache
                    .materialize(&spec_hash, &shared.cache, build.name.as_str())
                    .await
                    .map_err(|e| Error::Other(e.into()))?;

                Ok(Either::Left((
                    pending_dir,
                    EntryMeta {
                        inner: MetaInner::Spec(build.name.clone()),
                        fetched: true,
                        fetch_ms: Some(fetch_time.as_millis() as usize),
                        origin: Some(build.from.as_ref().clone()),
                        ..Default::default()
                    },
                )))
            } else {
                Err(Error::Cache(CacheErr::NotFound))
            };
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await
    }

    async fn materialize_subset(
        _dr: DeliverableRef,
        subset: SubsetInput,
        build: DeliverableRef,
        _spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        let (build_dir, build_bsr) = {
            let deliverable = state_hnd.lock_for_deliverable(&build).await;
            (
                if let DeliverableState::Complete(ref a) = deliverable.state {
                    match a {
                        Either::Left((pd, _meta)) => pd.path().to_path_buf(),
                        Either::Right(cd) => cd.path().to_path_buf(),
                    }
                } else {
                    return Err(Error::Cache(CacheErr::NotFound));
                },
                match deliverable.inner {
                    DeliverableInner::Build { bsr, .. } => bsr,
                    DeliverableInner::CacheFill { bsr, .. } => bsr,
                    _ => unreachable!(),
                },
            )
        };

        let shared_hnd2 = shared_hnd.clone();
        let subset2 = subset.clone();
        let pending_dir = spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let res = op::SubsetBuild {
                from_dir: Some(build_dir),
                subset: &subset2,
            }
            .run(&op::Options {
                cache: shared.cache.clone(),
                graph: &shared.graph,
                exec_base: shared.backend.output_base.clone(),
            })
            .await;
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await?;

        let shared = shared_hnd.inner().read().await;
        let build_origin = shared.graph.get(&build_bsr).unwrap().from.clone();
        let subset_spec = subset.as_spec(&shared.graph);
        drop(shared);

        Ok(Either::Left((
            pending_dir,
            EntryMeta {
                inner: MetaInner::Subset(subset_spec),
                origin: Some(build_origin.as_ref().clone()),
                ..Default::default()
            },
        )))
    }
}

impl<SF: SourceFetcher> LocalBackend<SF> {
    /// Creates a new orchestrator for local builds.
    pub fn new_orchestrator(
        top_levels: Vec<BuildSpecRef>,
        output_base: PathBuf,
        remote_cache: Option<RemoteCache<GcsStorage>>,
        sf: SF,
        num_concurrent_builds: usize,
        graph: DepGraph,
        cache: Cache<LocalDir>,
    ) -> Result<Orchestrator<Self>, Error> {
        Ok(Orchestrator {
            top_levels,
            backend: LocalBackend::<SF> {
                output_base,
                remote_cache,
                sf,
                build_semaphore: Semaphore::new(num_concurrent_builds),
            },
            graph,
            cache,
        })
    }

    /// Executes a local build with the orchestrator.
    pub async fn run_local_build<BP: BinProvider>(
        orch: Orchestrator<Self>,
        bp: BP,
    ) -> Result<Vec<(PendingDir, EntryMeta)>, Error> {
        let result = orch.run(bp).await?;

        Ok(result
            .into_iter()
            .filter_map(|a| match a {
                // We don't actually want to store breaker builds, they are just a stepping stone.
                Either::Left((
                    _pd,
                    EntryMeta {
                        breaker_build: true,
                        ..
                    },
                )) => None,
                Either::Left((pd, meta)) => Some((pd, meta)),
                Either::Right(_cache_dir) => None,
            })
            .collect())
    }
}
