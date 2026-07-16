//! Persisted per-VM resource configuration (#747, R9.4).
//!
//! User-set resource parameters (vcpu count, RAM MiB) live in `config.toml` in
//! the provider-instance dir, **separate** from the runtime [`State`](crate::state::State):
//! `State::stopped()` and `StartingGuard` reset runtime state on every stop or
//! crash, so config kept there would be silently wiped. This file is written
//! only by `minvmd config set` and read at boot and by `minvmd status` /
//! `minvmd config show`.
//!
//! Writes are atomic (tmp → fsync → rename) via
//! [`crate::state::atomic_write_toml`], the same primitive that persists
//! `minvmd.toml`.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Persisted resource parameters. A `None` field means "unset — use the
/// built-in default"; an explicit value overrides the default (but is itself
/// overridden by the matching environment variable at resolution time, see
/// [`crate::cmd::effective_ram_mib`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResourceConfig {
    /// Persisted vcpu count, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u8>,
    /// Persisted guest RAM in MiB, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ram_mib: Option<u32>,
}

impl ResourceConfig {
    /// Path to `config.toml` within `dir` (the provider-instance dir).
    #[must_use]
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("config.toml")
    }

    /// Read the persisted config from `dir`. A missing file is not an error —
    /// it yields the all-`None` default (every parameter falls back to its
    /// built-in default).
    pub fn read(dir: &Path) -> io::Result<Self> {
        match std::fs::read_to_string(Self::path(dir)) {
            Ok(s) => toml::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist this config to `config.toml` in `dir` atomically.
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        crate::state::atomic_write_toml(&Self::path(dir), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn missing_file_reads_as_default() {
        let tmp = temp_dir();
        let cfg = ResourceConfig::read(tmp.path()).expect("read");
        assert_eq!(cfg, ResourceConfig::default());
        assert!(cfg.vcpus.is_none() && cfg.ram_mib.is_none());
    }

    #[test]
    fn round_trips_through_toml() {
        let tmp = temp_dir();
        let cfg = ResourceConfig {
            vcpus: Some(4),
            ram_mib: Some(6144),
        };
        cfg.write(tmp.path()).expect("write");
        let read_back = ResourceConfig::read(tmp.path()).expect("read");
        assert_eq!(read_back, cfg);
    }

    #[test]
    fn partial_config_round_trips() {
        // Only ram_mib set; vcpus stays None (falls back to default at boot).
        let tmp = temp_dir();
        let cfg = ResourceConfig {
            vcpus: None,
            ram_mib: Some(3072),
        };
        cfg.write(tmp.path()).expect("write");
        assert_eq!(ResourceConfig::read(tmp.path()).expect("read"), cfg);
    }

    #[test]
    fn write_is_atomic_and_leaves_no_tmp() {
        let tmp = temp_dir();
        let cfg = ResourceConfig {
            vcpus: Some(2),
            ram_mib: None,
        };
        cfg.write(tmp.path()).expect("write");
        let target = ResourceConfig::path(tmp.path());
        assert!(target.exists(), "config.toml must exist");
        assert!(
            !target.with_extension("toml.tmp").exists(),
            "tmp sibling must not survive the atomic rename"
        );
    }
}
