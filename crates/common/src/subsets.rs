use crate::SpecHash;

/// Exact summary of a subset.
///
/// A subset is a subset of the build artifacts from other builds, bundled together.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SubsetSpec {
    /// inner MUST be sorted: by spec hash, then by output name.
    inner: Vec<(SpecHash, Vec<String>)>,
}

impl SubsetSpec {
    /// Returns the SpecHashes of builds this subset is composed from.
    pub fn depends_on(&self) -> impl Iterator<Item = &SpecHash> {
        self.inner.iter().map(|e| &e.0)
    }

    /// Constructs a new subset spec, for a subset which collects a subset of the
    /// outputs from a single build-spec.
    pub fn new_single(spec_hash: &SpecHash, mut outputs: Vec<String>) -> Self {
        outputs.sort();
        outputs.dedup();

        Self {
            inner: vec![(spec_hash.clone(), outputs)],
        }
    }

    pub fn iter_components(&self) -> impl Iterator<Item = &(SpecHash, Vec<String>)> {
        self.inner.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_sorted() {
        let ss = SubsetSpec::new_single(
            &SpecHash::from_hex("48d0229ccc7973402752c4a62a5d09875c5db3c426d316555207106200000000")
                .unwrap(),
            vec!["zAbc".to_string(), "abc".to_string()],
        );

        let outputs = ss.iter_components().next().unwrap().1.clone();
        assert!(outputs.is_sorted());
    }
}
