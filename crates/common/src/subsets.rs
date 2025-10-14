use crate::SpecHash;

/// Description of a subset.
///
/// A subset is a subset of the build artifacts from other builds, bundled together.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SubsetSpec {
    inner: Vec<(SpecHash, Vec<String>)>,
}

impl SubsetSpec {
    /// Returns the SpecHashes of builds this subset is composed from.
    pub fn depends_on(&self) -> impl Iterator<Item = &SpecHash> {
        self.inner.iter().map(|e| &e.0)
    }
}
