use std::path::PathBuf;

use cache::{CacheErr, DirCacheEntry, LocalDir, PendingDir, RemoteCache};
use common::SpecHash;
use either::Either;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::{BuildSpecRef, SubsetInput};

use super::state::{Deliverable, DeliverableRef, DeliverableState};
use super::{SharedHandle, StateHandle};
use crate::{Error, Runnable};

/// A structure describing a constructed deliverable. For instance, this might
/// be a PendingDir for local builds.
pub(crate) trait Artifact: std::fmt::Debug + Send {}

impl<A: Artifact, B: Artifact> Artifact for Either<A, B> {}

// For tests.
impl Artifact for () {}

/// An implementation of the core functions needed by the orchestrator.
pub(crate) trait Backend: Sized + Send + Sync + std::fmt::Debug + 'static {
    /// Describes a constructed deliverable.
    type Artifact: Artifact;

    fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        dependencies: Vec<DeliverableRef>,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> impl Future<Output = Result<Self::Artifact, Error>> + Send;

    fn cache_hydrate(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> impl Future<Output = Result<Self::Artifact, Error>> + Send;

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

impl Artifact for PendingDir {}
impl Artifact for DirCacheEntry<LocalDir> {}

impl<SF: crate::SourceFetcher> Backend for LocalBackend<SF> {
    type Artifact = Either<PendingDir, DirCacheEntry<LocalDir>>;

    async fn build(
        _dr: DeliverableRef,
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
                        Either::Left(pd) => pd.path().to_path_buf(),
                        Either::Right(c) => c.path().to_path_buf(),
                    },
                    _ => unreachable!(),
                })
                .collect();
            drop(s);
            out
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
        drop(shared);

        Ok(Either::Left(artifact.outputs))
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

        let build = shared_hnd.graph().await.get(&bsr).unwrap().clone();

        let shared = shared_hnd.0.read().await;
        if let Some(remote_cache) = shared.backend.remote_cache.as_ref() {
            let (_fetch_time, pending_dir) = remote_cache
                .materialize(&spec_hash, &shared.cache, build.name.as_str())
                .await
                .map_err(|e| Error::Other(e.into()))?;
            drop(shared);

            Ok(Either::Left(pending_dir))
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
        let build_dir = if let DeliverableState::Complete(ref a) =
            state_hnd.lock_for_deliverable(&build).await.state
        {
            match a {
                Either::Left(a) => a.path().to_path_buf(),
                Either::Right(a) => a.path().to_path_buf(),
            }
        } else {
            return Err(Error::Cache(CacheErr::NotFound));
        };

        let shared = shared_hnd.0.read().await;
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

        Ok(Either::Left(pending_dir))
    }
}
