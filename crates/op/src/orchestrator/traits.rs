use cache::{DirCacheEntry, LocalDir, PendingDir};
use either::Either;

/// A structure describing a constructed deliverable. For instance, this might
/// be a PendingDir for local builds.
pub(crate) trait Artifact: Sized + std::fmt::Debug + Send {}

impl<A: Artifact, B: Artifact> Artifact for Either<A, B> {}

// For tests.
impl Artifact for () {}

/// An implementation of the core functions needed by the orchestrator.
pub(crate) trait Backend: std::fmt::Debug + 'static {
    /// Describes a constructed deliverable.
    type Artifact: Artifact;
}

// For tests.
impl Backend for () {
    type Artifact = ();
}

/// A type which implements [Backend] by building everything locally.
#[derive(Debug)]
pub struct LocalBackend;

impl Artifact for PendingDir {}
impl Artifact for DirCacheEntry<LocalDir> {}

impl Backend for LocalBackend {
    type Artifact = Either<PendingDir, DirCacheEntry<LocalDir>>;
}
