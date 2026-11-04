//! The client's `[host-exposures]` table: the ports on the host's loopback
//! that boxes can reach at `host.min.internal` (NET-159, NET-161).
//!
//! Each entry names one exposure:
//!
//! ```toml
//! [host-exposures.postgres]
//! port = 5432
//! proto = "tcp"   # optional, `tcp` when absent
//! ```
//!
//! [`HostExposuresFile`] holds the table of one `config.toml` and reads it
//! again when the file changes, so each decision reads the current table.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Deserialize;

/// The transport of one host exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposureProto {
    /// TCP: the protocol of an entry that names none.
    #[default]
    Tcp,
    /// UDP.
    Udp,
}

impl ExposureProto {
    /// The IPv4 protocol number of this transport.
    #[must_use]
    pub fn ip_protocol(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// One `[host-exposures.<name>]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostExposure {
    /// The port on the host's loopback.
    pub port: u16,
    /// The transport. `tcp` when the entry names none.
    #[serde(default)]
    pub proto: ExposureProto,
}

/// The whole `[host-exposures]` table, by entry name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostExposures {
    entries: BTreeMap<String, HostExposure>,
}

impl HostExposures {
    /// Whether an entry opens `port` over the IPv4 protocol `ip_protocol`.
    #[must_use]
    pub fn opens(&self, ip_protocol: u8, port: u16) -> bool {
        self.entries
            .values()
            .any(|entry| entry.port == port && entry.proto.ip_protocol() == ip_protocol)
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &HostExposure)> {
        self.entries
            .iter()
            .map(|(name, entry)| (name.as_str(), entry))
    }
}

/// A `[host-exposures]` table that was not read.
#[derive(Debug, thiserror::Error)]
pub enum HostExposuresError {
    /// The file exists and was not read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The read error.
        source: std::io::Error,
    },
    /// The file, or its `[host-exposures]` table, does not parse.
    #[error("{path}: the [host-exposures] table is not valid: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The parse error.
        source: toml::de::Error,
    },
    /// An entry names port 0.
    #[error("{path}: [host-exposures.{name}] names port 0")]
    PortZero {
        /// The file.
        path: PathBuf,
        /// The entry.
        name: String,
    },
}

/// The one part of `config.toml` this module reads. Every other section is
/// ignored here, and the config's own reader checks it.
#[derive(Deserialize)]
struct TableOnly {
    #[serde(default, rename = "host-exposures")]
    host_exposures: BTreeMap<String, HostExposure>,
}

/// Parses the `[host-exposures]` table out of the text of a `config.toml`.
/// `path` names the file in an error.
///
/// # Errors
///
/// [`HostExposuresError::Parse`] when the text or the table does not parse,
/// and [`HostExposuresError::PortZero`] when an entry names port 0.
pub fn parse_host_exposures(text: &str, path: &Path) -> Result<HostExposures, HostExposuresError> {
    let table: TableOnly = toml::from_str(text).map_err(|source| HostExposuresError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some((name, _)) = table
        .host_exposures
        .iter()
        .find(|(_, entry)| entry.port == 0)
    {
        return Err(HostExposuresError::PortZero {
            path: path.to_path_buf(),
            name: name.clone(),
        });
    }
    Ok(HostExposures {
        entries: table.host_exposures,
    })
}

/// Reads the `[host-exposures]` table of the `config.toml` at `path`. A
/// missing file is an empty table.
///
/// # Errors
///
/// See [`HostExposuresError`].
pub fn read_host_exposures(path: &Path) -> Result<HostExposures, HostExposuresError> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_host_exposures(&text, path),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(HostExposures::default())
        }
        Err(source) => Err(HostExposuresError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// What identifies one version of the file: a changed file has a changed
/// stamp. `None` is a file that does not exist.
type Stamp = Option<(SystemTime, u64, u64)>;

fn stamp(path: &Path) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len(), meta.ino()))
}

/// The `[host-exposures]` table of one `config.toml`, read again each time
/// the file changes.
#[derive(Debug)]
pub struct HostExposuresFile {
    path: PathBuf,
    state: Mutex<(Option<Stamp>, Arc<HostExposures>)>,
}

impl HostExposuresFile {
    /// The table of the `config.toml` at `path`. Nothing is read until the
    /// first [`Self::current`].
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new((None, Arc::new(HostExposures::default()))),
        }
    }

    /// The file this table is read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current table. The file is read again when its modification
    /// time, length or inode changed since the last read. A table that does
    /// not read is an empty one, so a broken file opens no exposure, and
    /// the failure is logged.
    pub fn current(&self) -> Arc<HostExposures> {
        let now = stamp(&self.path);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.0 == Some(now) {
            return Arc::clone(&state.1);
        }
        let table = match read_host_exposures(&self.path) {
            Ok(table) => table,
            Err(error) => {
                tracing::warn!(%error, "host exposures not loaded; no port is exposed");
                HostExposures::default()
            }
        };
        tracing::debug!(
            path = %self.path.display(),
            entries = table.len(),
            "host exposures table reloaded"
        );
        *state = (Some(now), Arc::new(table));
        Arc::clone(&state.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_without_proto_is_tcp_and_other_sections_are_ignored() {
        let text = "[secrets]\nacknowledge = true\n\n\
                    [host-exposures.db]\nport = 5432\n\n\
                    [host-exposures.dns]\nport = 5353\nproto = \"udp\"\n";
        let table = parse_host_exposures(text, Path::new("config.toml")).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.opens(6, 5432));
        assert!(!table.opens(17, 5432));
        assert!(table.opens(17, 5353));
        assert!(!table.opens(6, 5353));
    }

    #[test]
    fn a_bad_entry_is_refused() {
        let path = Path::new("config.toml");
        assert!(parse_host_exposures("[host-exposures.x]\nport = 0\n", path).is_err());
        assert!(
            parse_host_exposures("[host-exposures.x]\nport = 1\nproto = \"icmp\"\n", path).is_err()
        );
        assert!(
            parse_host_exposures("[host-exposures.x]\nport = 1\nhost = \"a\"\n", path).is_err()
        );
    }

    #[test]
    fn the_file_is_read_again_when_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let file = HostExposuresFile::new(path.clone());
        assert!(
            file.current().is_empty(),
            "a missing file is an empty table"
        );
        std::fs::write(&path, "[host-exposures.web]\nport = 8080\n").unwrap();
        assert!(file.current().opens(6, 8080));
        std::fs::write(&path, "# no exposures any more\n").unwrap();
        assert!(file.current().is_empty());
        std::fs::write(&path, "[host-exposures.web\n").unwrap();
        assert!(file.current().is_empty(), "a broken file exposes nothing");
    }
}
