//! Metadata for cache entries.

use common::SpecHash;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::CacheErr;
use crate::fs::{DirEntry, FileSystem};

/// Metadata associated with a cache entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntryMeta {
    pub spec_name: String,
    pub fetched: bool,
    pub epoch_millis: u128,
}

impl Default for EntryMeta {
    fn default() -> Self {
        EntryMeta {
            spec_name: "".to_string(),
            fetched: false,
            epoch_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        }
    }
}

impl EntryMeta {
    /// Writes this metadata to the cache filesystem for the given hash.
    pub fn write<FS: FileSystem>(&self, fs: &FS, hash: &SpecHash) -> Result<(), CacheErr> {
        let hash_hex = hash.0.to_hex();
        let f = fs.open_write(format!("meta/{}.json", hash_hex))?;
        serde_json::to_writer(f, self).map_err(std::io::Error::from)?;
        Ok(())
    }

    /// Reads metadata from the cache filesystem for the given hash.
    pub fn read<FS: FileSystem>(fs: &FS, hash: &SpecHash) -> Result<Self, CacheErr> {
        let hash_hex = hash.0.to_hex();
        let f = fs.open_read(format!("meta/{}.json", hash_hex))?;
        serde_json::from_reader(f).map_err(|e| CacheErr::IO(std::io::Error::from(e)))
    }

    /// Reads metadata from a file handle.
    pub fn read_from<R: Read>(reader: R) -> Result<Self, CacheErr> {
        serde_json::from_reader(reader).map_err(|e| CacheErr::IO(std::io::Error::from(e)))
    }

    /// Lists all metadata entries in the cache that match a given spec name.
    ///
    /// Returns a vector of tuples containing (hash_hex, epoch_millis) sorted by recency.
    pub fn find_by_name<FS: FileSystem>(
        fs: &FS,
        name: &str,
    ) -> Result<Vec<(String, u128)>, CacheErr> {
        let mut candidates = Vec::new();

        for e in fs.read_dir("meta")? {
            let f = fs.open_read(e.path()?)?;
            let entry: EntryMeta = Self::read_from(f)?;
            if entry.spec_name == name {
                let p = e.path()?;
                let hash_hex = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|s| s.strip_suffix(".json"))
                    .ok_or_else(|| {
                        CacheErr::IO(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid metadata filename",
                        ))
                    })?
                    .to_ascii_lowercase();

                candidates.push((hash_hex, entry.epoch_millis));
            }
        }

        // Sort by recency (most recent first)
        candidates.sort_by(|a, b| a.1.cmp(&b.1).reverse());
        Ok(candidates)
    }
}
