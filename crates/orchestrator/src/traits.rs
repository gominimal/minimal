use cache::{DirCacheEntry, EntryMeta, LocalDir, PendingDir};
use common::SpecHash;
use graph::{BuildSpecRef, SubsetInput};

use super::state::DeliverableRef;
use super::{SharedHandle, StateHandle};
use crate::Error;

/// A structure describing a constructed deliverable. For instance, this might
/// be a PendingDir for local builds.
pub trait Artifact: std::fmt::Debug + Send {}

impl<A: Artifact, B: Artifact> Artifact for either::Either<A, B> {}

// For tests.
impl Artifact for () {}

// Common artifact types
impl Artifact for (PendingDir, EntryMeta) {}
impl Artifact for DirCacheEntry<LocalDir> {}

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
