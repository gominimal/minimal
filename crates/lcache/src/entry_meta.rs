//! Metadata for cache entries.

use common::{SpecHash, SpecOrigin, SubsetSpec};
use std::fmt::Display;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::CacheErr;
use crate::fs::{DirEntry, FileSystem};

/// Metadata specific to the object being cached.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum MetaInner {
    Spec(String),       // name
    Subset(SubsetSpec), // (build-spec, output-names), both sorted
}

impl MetaInner {
    pub fn spec_name(&self) -> Option<&String> {
        match self {
            MetaInner::Spec(sn) => Some(sn),
            _ => None,
        }
    }
}

impl Display for MetaInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaInner::Spec(n) => write!(f, "package {}", n),
            MetaInner::Subset(s) => write!(
                f,
                "subset of {} with outputs [{}]",
                s.depends_on()
                    .map(|h| h.0.to_hex())
                    .collect::<Vec<_>>()
                    .join(","),
                s.iter_components()
                    .flat_map(|c| &c.1)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        }
    }
}

/// Metadata associated with a cache entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EntryMeta {
    pub inner: MetaInner,
    pub fetched: bool,
    #[serde(default)]
    pub breaker_build: bool,

    #[serde(default)]
    pub fetch_ms: Option<usize>,
    #[serde(default)]
    pub build_ms: Option<usize>,

    pub epoch_millis: u128,
    pub origin: Option<SpecOrigin>,
}

impl Default for EntryMeta {
    fn default() -> Self {
        EntryMeta {
            inner: MetaInner::Spec("".to_string()),
            fetched: false,
            breaker_build: false,
            fetch_ms: None,
            build_ms: None,
            epoch_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            origin: None,
        }
    }
}

impl EntryMeta {
    /// Writes this metadata to the cache filesystem for the given hash.
    pub fn write<FS: FileSystem>(&self, fs: &FS, hash: &SpecHash) -> Result<(), CacheErr> {
        let hash_hex = hash.0.to_hex();
        let dir_hex = hash.as_bytes()[0];
        fs.mkdir(format!("meta/{:02x}", dir_hex)).ok(); //ignore error

        let f = fs.open_write(format!(
            "meta/{:02x}/{}.json",
            dir_hex,
            &hash_hex.as_str()[2..]
        ))?;
        serde_json_lenient::to_writer(f, self).map_err(std::io::Error::from)?;
        Ok(())
    }

    /// Reads metadata from the cache filesystem for the given hash.
    pub fn read<FS: FileSystem>(fs: &FS, hash: &SpecHash) -> Result<Self, CacheErr> {
        let hash_hex = hash.0.to_hex();
        let dir_hex = hash.as_bytes()[0];

        let f = fs.open_read(format!(
            "meta/{:02x}/{}.json",
            dir_hex,
            &hash_hex.as_str()[2..]
        ))?;
        serde_json_lenient::from_reader(f).map_err(|e| CacheErr::IO(std::io::Error::from(e)))
    }

    /// Reads metadata from a file handle.
    pub(crate) fn read_from<R: Read>(reader: R) -> Result<Self, CacheErr> {
        serde_json_lenient::from_reader(reader).map_err(|e| CacheErr::IO(std::io::Error::from(e)))
    }

    /// Lists all metadata entries in the cache that match a given spec name.
    ///
    /// Returns a vector of tuples containing (hash_hex, epoch_millis) sorted by recency.
    pub fn find_build_by_name<FS: FileSystem>(
        fs: &FS,
        name: &str,
    ) -> Result<Vec<(String, u128)>, CacheErr> {
        let mut candidates = Vec::new();

        for dir in fs.read_dir("meta")? {
            let leading_hex = dir
                .path()?
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();

            for e in fs.read_dir(dir.path()?)? {
                let f = fs.open_read(e.path()?)?;
                let entry = match Self::read_from(f) {
                    Ok(entry) => entry,
                    Err(e) => {
                        warn!(
                            "Skipping cache metadata entry that failed to parse: {:?}",
                            e
                        );
                        continue;
                    }
                };

                match entry.inner {
                    MetaInner::Subset(_) => {}
                    MetaInner::Spec(spec_name) => {
                        if spec_name == name {
                            let p = e.path()?;
                            let hash_hex = leading_hex.to_owned()
                                + p.file_name()
                                    .and_then(|n| n.to_str())
                                    .and_then(|s| s.strip_suffix(".json"))
                                    .ok_or_else(|| {
                                        CacheErr::IO(std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            "invalid metadata filename",
                                        ))
                                    })?;

                            candidates.push((hash_hex, entry.epoch_millis));
                        }
                    }
                }
            }
        }

        // Sort by recency (most recent first)
        candidates.sort_by(|a, b| a.1.cmp(&b.1).reverse());
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_smoketest() {
        // format as of 2025-10-28
        assert_eq!(
            serde_json_lenient::from_str::<EntryMeta>(
                "{\"inner\":{\"Spec\":\"setuptools\"},\"fetched\":true,\"epoch_millis\":1760653637323}"
            ).unwrap(),
            EntryMeta {
                fetched: true,
                breaker_build: false,
                fetch_ms: None,
                build_ms: None,
                epoch_millis: 1760653637323,
                inner: MetaInner::Spec("setuptools".to_string()),
                origin: None,
            }
        )
    }
}
