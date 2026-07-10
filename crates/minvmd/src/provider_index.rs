//! Host-side session → volume-image index (spec R3.4).
//!
//! Sessions persist on a VM's data volume and outlive the VM process, but
//! their only record used to live *inside* the ext4 image — invisible to the
//! host. The `ProviderIndex` maps each `SessionId` (UUIDv7, globally unique —
//! no two VMs may share one) to the volume image that holds it and the vm id
//! that last served it, so future multi-VM routing (#311) can dispatch
//! `attach`/`activate` to the right place. This module only creates and
//! maintains the map; routing itself is out of scope.
//!
//! The index is *derived* state: the volume images remain the source of
//! truth, and the `run` supervisor's poller rebuilds entries from the live
//! VM. A missing or corrupt file therefore loads as empty rather than
//! failing (mirroring the R3.1 posture for the in-guest session index).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sessions::SessionId;

/// Where a session lives: the volume image that holds its state and the VM
/// that last served it. The session id is the map key only, never repeated
/// here (R3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeEntry {
    /// Host path of the raw ext4 volume image holding the session.
    pub image_path: PathBuf,
    /// Identifier of the VM instance that last served the session
    /// (`local-<n>`; single-instance today).
    pub vm_id: String,
}

/// Failure modes of [`ProviderIndex`] persistence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderIndexError {
    /// The index file exists but could not be read.
    #[error("reading provider index {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The index could not be written (tmp create, write, fsync, or rename).
    #[error("writing provider index {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The in-memory map could not be serialized (broken invariant —
    /// `BTreeMap<SessionId, VolumeEntry>` always serializes).
    #[error("serializing provider index")]
    Serialize(#[from] serde_json::Error),
}

/// Persistent JSON map of session id → [`VolumeEntry`], stored at
/// [`crate::state::StateDir::session_index_path`].
#[derive(Debug)]
pub struct ProviderIndex {
    path: PathBuf,
    sessions: BTreeMap<SessionId, VolumeEntry>,
}

impl ProviderIndex {
    /// Load the index at `path`. Missing file → empty index; a corrupt file
    /// is logged and treated as empty (derived data — the poller rebuilds
    /// it). Only a genuine read error fails.
    pub fn load(path: PathBuf) -> Result<Self, ProviderIndexError> {
        let sessions = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(map) => map,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %path.display(),
                        "corrupt provider index; starting empty (poller rebuilds it)",
                    );
                    BTreeMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(source) => {
                return Err(ProviderIndexError::Read {
                    path: path.clone(),
                    source,
                });
            }
        };
        Ok(Self { path, sessions })
    }

    /// Insert (or replace) the entry for `id`, returning the previous entry.
    /// Replacing an entry that names a *different* VM is logged: session ids
    /// are globally unique, so ownership moving between VMs is noteworthy.
    pub fn insert(&mut self, id: SessionId, entry: VolumeEntry) -> Option<VolumeEntry> {
        let prev = self.sessions.insert(id, entry);
        if let Some(prev) = &prev
            && prev.vm_id != self.sessions[&id].vm_id
        {
            tracing::warn!(
                session = %id,
                from = %prev.vm_id,
                to = %self.sessions[&id].vm_id,
                "provider index entry changed owning VM",
            );
        }
        prev
    }

    /// Look up the entry for `id`.
    #[must_use]
    pub fn get_by_session(&self, id: &SessionId) -> Option<&VolumeEntry> {
        self.sessions.get(id)
    }

    /// Remove the entry for `id`, returning it if present.
    pub fn remove(&mut self, id: &SessionId) -> Option<VolumeEntry> {
        self.sessions.remove(id)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (&SessionId, &VolumeEntry)> {
        self.sessions.iter()
    }

    /// Write the index atomically (tmp → fsync → rename), matching the
    /// `StateDir::write_state` pattern.
    pub fn flush(&self) -> Result<(), ProviderIndexError> {
        let write_err = |source| ProviderIndexError::Write {
            path: self.path.clone(),
            source,
        };
        let serialized = serde_json::to_vec_pretty(&self.sessions)?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(write_err)?;
            f.write_all(&serialized).map_err(write_err)?;
            f.sync_all().map_err(write_err)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(write_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(image: &str, vm: &str) -> VolumeEntry {
        VolumeEntry {
            image_path: PathBuf::from(image),
            vm_id: vm.to_string(),
        }
    }

    #[test]
    fn round_trips_through_flush_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("session_index.json");

        let id_a = SessionId::parse_str("019f0000-0000-7000-8000-00000000000a").unwrap();
        let id_b = SessionId::parse_str("019f0000-0000-7000-8000-00000000000b").unwrap();
        let mut index = ProviderIndex::load(path.clone()).unwrap();
        assert!(index.get_by_session(&id_a).is_none());

        index.insert(id_a, entry("/vols/a.raw", "local-0"));
        index.insert(id_b, entry("/vols/a.raw", "local-0"));
        index.flush().unwrap();

        let reloaded = ProviderIndex::load(path.clone()).unwrap();
        assert_eq!(
            reloaded.get_by_session(&id_a),
            Some(&entry("/vols/a.raw", "local-0"))
        );
        assert_eq!(reloaded.iter().count(), 2);
        assert!(
            !path.with_extension("json.tmp").exists(),
            "atomic flush must leave no tmp residue"
        );
    }

    #[test]
    fn remove_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("session_index.json");
        let id = SessionId::parse_str("019f0000-0000-7000-8000-00000000000c").unwrap();

        let mut index = ProviderIndex::load(path.clone()).unwrap();
        index.insert(id, entry("/vols/a.raw", "local-0"));
        index.flush().unwrap();
        assert_eq!(index.remove(&id), Some(entry("/vols/a.raw", "local-0")));
        index.flush().unwrap();

        let reloaded = ProviderIndex::load(path).unwrap();
        assert!(reloaded.get_by_session(&id).is_none());
    }

    #[test]
    fn missing_and_corrupt_files_load_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("absent.json");
        assert_eq!(ProviderIndex::load(missing).unwrap().iter().count(), 0);

        let corrupt = tmp.path().join("corrupt.json");
        std::fs::write(&corrupt, b"{ not json").unwrap();
        let index = ProviderIndex::load(corrupt.clone()).unwrap();
        assert_eq!(index.iter().count(), 0);

        // And it recovers: a flush replaces the corrupt file with valid JSON.
        index.flush().unwrap();
        let reread: BTreeMap<SessionId, VolumeEntry> =
            serde_json::from_slice(&std::fs::read(&corrupt).unwrap()).unwrap();
        assert!(reread.is_empty());
    }
}
