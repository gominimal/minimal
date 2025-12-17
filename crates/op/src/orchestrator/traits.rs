use std::path::PathBuf;

use cache::{CacheErr, DirCacheEntry, EntryMeta, LocalDir, MetaInner, PendingDir, RemoteCache};
use common::SpecHash;
use either::Either;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::{BuildSpecRef, SubsetInput};

use super::state::{Deliverable, DeliverableRef, DeliverableState};
use super::{SharedHandle, StateHandle};
use crate::orchestrator::state::DeliverableInner;
use crate::{Error, Runnable};

/// A structure describing a constructed deliverable. For instance, this might
/// be a PendingDir for local builds.
pub trait Artifact: std::fmt::Debug + Send {}

impl<A: Artifact, B: Artifact> Artifact for Either<A, B> {}

// For tests.
impl Artifact for () {}

/// An implementation of the core functions needed by the orchestrator.
pub trait Backend: Sized + Send + Sync + std::fmt::Debug + 'static {
    /// Describes a constructed deliverable.
    type Artifact: Artifact;

    /// Performs a build using the given dependencies.
    fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        dependencies: Vec<DeliverableRef>,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> impl Future<Output = Result<Self::Artifact, Error>> + Send;

    /// Fetches something from a cache.
    fn cache_hydrate(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> impl Future<Output = Result<Self::Artifact, Error>> + Send;

    /// Builds a subset.
    fn materialize_subset(
        dr: DeliverableRef,
        subset: SubsetInput,
        build: DeliverableRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> impl Future<Output = Result<Self::Artifact, Error>> + Send;
}

// For tests.
impl Backend for () {
    type Artifact = ();

    async fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        _dependencies: Vec<DeliverableRef>,
        _shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        panic!(
            "B::build({:?}, {:?}, {:?}) called during test",
            dr, bsr, spec_hash
        )
    }

    async fn cache_hydrate(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        _shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        panic!(
            "B::cache_hydrate({:?}, {:?}, {:?}) called during test",
            dr, bsr, spec_hash
        )
    }

    async fn materialize_subset(
        dr: DeliverableRef,
        subset: SubsetInput,
        build: DeliverableRef,
        spec_hash: SpecHash,
        _shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        panic!(
            "B::materialize_subset({:?}, {:?}, {:?}, {:?}) called during test",
            dr, subset, build, spec_hash
        )
    }
}

/// A type which implements [Backend] by building everything locally.
#[derive(Debug)]
pub struct LocalBackend<SF: crate::SourceFetcher + 'static> {
    pub(crate) sf: SF,
    pub(crate) output_base: PathBuf,
    pub(crate) remote_cache: Option<RemoteCache<GcsStorage>>,
}

impl Artifact for (PendingDir, EntryMeta) {}
impl Artifact for DirCacheEntry<LocalDir> {}

impl<SF: crate::SourceFetcher> Backend for LocalBackend<SF> {
    type Artifact = Either<(PendingDir, EntryMeta), DirCacheEntry<LocalDir>>;

    async fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        _spec_hash: SpecHash,
        dependencies: Vec<DeliverableRef>,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        let dep_paths = {
            let s = state_hnd.lock().await;
            let out: Vec<PathBuf> = dependencies
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
            drop(s);
            out
        };

        let breaker_build = {
            if let DeliverableInner::Build { full_build, .. } =
                &state_hnd.lock_for_deliverable(&dr).await.inner
            {
                !full_build
            } else {
                unreachable!()
            }
        };

        let shared = shared_hnd.0.read().await;
        let mut b = crate::SpecBuild {
            override_deps: Some(dep_paths.into_iter().collect()),
            spec: &bsr,
            remote_fetcher: &shared.backend.sf,
        };
        let artifact = b
            .run(&crate::Options {
                cache: shared.cache.clone(),
                graph: &shared.graph,
                exec_base: shared.backend.output_base.clone(),
            })
            .await?;
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

    async fn cache_hydrate(
        _dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        // Check local cache
        if let Ok(cd) = shared_hnd.0.read().await.cache.read_dir(&spec_hash) {
            return Ok(Either::Right(cd));
        }

        let shared = shared_hnd.0.read().await;
        if let Some(remote_cache) = shared.backend.remote_cache.as_ref() {
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
        }
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

        let shared = shared_hnd.0.read().await;
        let build = shared.graph.get(&build_bsr).unwrap();
        let pending_dir = crate::SubsetBuild {
            from_dir: Some(build_dir),
            subset: &subset,
        }
        .run(&crate::Options {
            cache: shared.cache.clone(),
            graph: &shared.graph,
            exec_base: shared.backend.output_base.clone(),
        })
        .await?;

        Ok(Either::Left((
            pending_dir,
            EntryMeta {
                inner: MetaInner::Subset(subset.as_spec(&shared.graph)),
                origin: Some(build.from.as_ref().clone()),
                ..Default::default()
            },
        )))
    }
}
