//! The client's `[host-exposures]` table: the ports on the host's loopback
//! that boxes can reach at `host.min.internal` (NET-159, NET-161).
//!
//! Each entry names one exposure, in either TOML spelling of a table:
//!
//! ```toml
//! [host-exposures.postgres]
//! port = 5432
//! proto = "tcp"   # optional, `tcp` when absent
//!
//! [host-exposures]
//! vite = { port = 5173 }
//! ```
//!
//! This is the one reader of the table. The native session daemon and the
//! VM host daemon both read it here, so a bad entry is handled one way: an
//! entry that is not a table with a port from 1 to 65535 and an optional
//! `proto` of `tcp` or `udp` is skipped, the other entries stand, and the
//! daemon log names the skipped entry. A file that does not parse, or a
//! `host-exposures` key that is not a table, opens no exposure.
//!
//! [`HostExposuresFile`] holds the table of one `config.toml` and reads it
//! again when the file changes, so each decision reads the current table.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

/// The key of the table in `config.toml`.
pub const HOST_EXPOSURES_TABLE: &str = "host-exposures";

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
    /// The port on the host's loopback, never 0.
    pub port: u16,
    /// The transport. `tcp` when the entry names none.
    #[serde(default)]
    pub proto: ExposureProto,
}

/// One entry the reader skipped because it is not an exposure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    /// The entry's name.
    pub name: String,
    /// The entry's value, as TOML.
    pub value: String,
    /// Why it is not an exposure.
    pub reason: String,
}

/// The whole `[host-exposures]` table, by entry name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostExposures {
    entries: BTreeMap<String, HostExposure>,
    skipped: Vec<SkippedEntry>,
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

    /// The entries the reader skipped, by name.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedEntry] {
        &self.skipped
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
    /// The file does not parse as TOML.
    #[error("{path} is not valid TOML: {source}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The parse error.
        source: toml::de::Error,
    },
    /// The `host-exposures` key holds a value that is not a table.
    #[error("{path}: host-exposures is not a table")]
    NotATable {
        /// The file.
        path: PathBuf,
    },
}

/// One entry's value as an exposure, or why it is not one.
fn entry_exposure(value: &toml::Value) -> Result<HostExposure, String> {
    let entry: HostExposure = value
        .clone()
        .try_into()
        .map_err(|error| error.to_string())?;
    if entry.port == 0 {
        return Err("port 0 is not a port".to_string());
    }
    Ok(entry)
}

/// Parses the `[host-exposures]` table out of the text of a `config.toml`.
/// `path` names the file in an error. Every other section is ignored here,
/// and the config's own reader checks it. An entry that is not an exposure
/// is skipped, and [`HostExposures::skipped`] lists it.
///
/// # Errors
///
/// [`HostExposuresError::Parse`] when the text does not parse, and
/// [`HostExposuresError::NotATable`] when `host-exposures` is not a table.
pub fn parse_host_exposures(text: &str, path: &Path) -> Result<HostExposures, HostExposuresError> {
    let doc: toml::Table = toml::from_str(text).map_err(|source| HostExposuresError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let Some(table) = doc.get(HOST_EXPOSURES_TABLE) else {
        return Ok(HostExposures::default());
    };
    let Some(table) = table.as_table() else {
        return Err(HostExposuresError::NotATable {
            path: path.to_path_buf(),
        });
    };
    let mut exposures = HostExposures::default();
    for (name, value) in table {
        match entry_exposure(value) {
            Ok(entry) => {
                exposures.entries.insert(name.clone(), entry);
            }
            Err(reason) => exposures.skipped.push(SkippedEntry {
                name: name.clone(),
                value: value.to_string(),
                reason,
            }),
        }
    }
    Ok(exposures)
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
/// stamp. The change time is in it because a write always sets it, and a
/// restore of an older modification time (`touch -r`) does not reset it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
    dev: u64,
    ino: u64,
    ctime: i64,
    ctime_nsec: i64,
}

/// The stamp of the file, `None` for a file that does not exist.
type Stamp = Option<FileStamp>;

/// How close to a read a modification time must be for the stamp alone not
/// to prove the file unchanged. An edit inside one timestamp tick that keeps
/// the length keeps the stamp too, and some filesystems tick once in two
/// seconds.
const RACY_WINDOW: Duration = Duration::from_secs(2);

/// Whether a file with stamp `stamp`, read at `read_at`, can have changed
/// since without a change to its stamp. A modification time after the read
/// (a clock that stepped back, or a future mtime) proves nothing about the
/// tick, so it is racy until `confirmed`: one more read found the same stamp
/// and the same text. Without that, every lookup reads the whole file again.
fn racy(stamp: Stamp, read_at: SystemTime, confirmed: bool) -> bool {
    let Some(stamp) = stamp else {
        return false;
    };
    match read_at.duration_since(stamp.modified) {
        Ok(age) => age < RACY_WINDOW,
        Err(_) => !confirmed,
    }
}

/// What one read of the file found.
#[derive(Debug, PartialEq, Eq)]
enum Body {
    /// No file.
    Missing,
    /// The file exists and the read failed, with the error.
    Unread(String),
    /// The file's text, whether or not it parses.
    Text(String),
}

/// One read of the file: its stamp, when it was read, what it held and the
/// table it gave.
#[derive(Debug)]
struct Loaded {
    stamp: Stamp,
    read_at: SystemTime,
    /// A read after this one's found the same stamp and the same text.
    confirmed: bool,
    body: Body,
    table: Arc<HostExposures>,
}

fn stamp(path: &Path) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: meta.modified().ok()?,
        len: meta.len(),
        dev: meta.dev(),
        ino: meta.ino(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    })
}

/// The `[host-exposures]` table of one `config.toml`, read again each time
/// the file changes.
#[derive(Debug)]
pub struct HostExposuresFile {
    path: PathBuf,
    state: Mutex<Option<Loaded>>,
}

impl HostExposuresFile {
    /// The table of the `config.toml` at `path`. Nothing is read until the
    /// first [`Self::current`].
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(None),
        }
    }

    /// The file this table is read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current table. The file is read again when its modification
    /// time, change time, length, device or inode changed since the last
    /// read, or when its
    /// modification time is too close to the last read to prove it
    /// unchanged. A read that finds what the last one found keeps the table,
    /// the same `Arc`, and logs nothing. A table that does not read is an
    /// empty one, so a broken file opens no exposure. The log says each
    /// failure and each skipped entry once for each new version of the file.
    pub fn current(&self) -> Arc<HostExposures> {
        let now = stamp(&self.path);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(loaded) = state.as_ref()
            && loaded.stamp == now
            && !racy(loaded.stamp, loaded.read_at, loaded.confirmed)
        {
            return Arc::clone(&loaded.table);
        }
        let read_at = SystemTime::now();
        let body = match std::fs::read_to_string(&self.path) {
            Ok(text) => Body::Text(text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Body::Missing,
            Err(error) => Body::Unread(error.to_string()),
        };
        if let Some(loaded) = state.as_mut()
            && loaded.body == body
        {
            loaded.confirmed = loaded.stamp == now;
            loaded.stamp = now;
            loaded.read_at = read_at;
            return Arc::clone(&loaded.table);
        }
        let table = match &body {
            Body::Missing => HostExposures::default(),
            Body::Unread(error) => {
                tracing::warn!(
                    config = %self.path.display(),
                    %error,
                    "could not read the client config, so host.min.internal has no host exposure"
                );
                HostExposures::default()
            }
            Body::Text(text) => match parse_host_exposures(text, &self.path) {
                Ok(table) => {
                    for skipped in table.skipped() {
                        tracing::warn!(
                            config = %self.path.display(),
                            table = HOST_EXPOSURES_TABLE,
                            entry = %skipped.name,
                            value = %skipped.value,
                            reason = %skipped.reason,
                            "skipped a host exposure that is not {{ proto = \"tcp\" or \"udp\", \
                             port = 1 to 65535 }}"
                        );
                    }
                    table
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "could not parse the client config, so host.min.internal has no host \
                         exposure"
                    );
                    HostExposures::default()
                }
            },
        };
        tracing::debug!(
            path = %self.path.display(),
            entries = table.len(),
            "host exposures table reloaded"
        );
        let table = Arc::new(table);
        *state = Some(Loaded {
            stamp: now,
            read_at,
            confirmed: false,
            body,
            table: Arc::clone(&table),
        });
        table
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
        let inline = "[host-exposures]\nvite = { port = 5173 }\n";
        let table = parse_host_exposures(inline, Path::new("config.toml")).unwrap();
        assert!(table.opens(6, 5173), "the inline spelling reads the same");
    }

    /// A bad entry is skipped and named, and the good entries beside it
    /// stand. A file that does not parse, or a key that is not a table, is
    /// an error.
    #[test]
    fn a_bad_entry_is_skipped() {
        let path = Path::new("config.toml");
        let table = parse_host_exposures(
            "[host-exposures]\n\
             good = { port = 8080 }\n\
             zero = { port = 0 }\n\
             icmp = { port = 1, proto = \"icmp\" }\n\
             extra = { port = 1, host = \"a\" }\n\
             big = { port = 70000 }\n\
             bare = 8080\n",
            path,
        )
        .unwrap();
        assert_eq!(table.len(), 1);
        assert!(table.opens(6, 8080));
        let mut skipped: Vec<&str> = table.skipped().iter().map(|s| s.name.as_str()).collect();
        skipped.sort_unstable();
        assert_eq!(skipped, ["bare", "big", "extra", "icmp", "zero"]);
        assert!(parse_host_exposures("host-exposures = 8080\n", path).is_err());
        assert!(parse_host_exposures("not toml [", path).is_err());
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

    /// A broken file read again with the same text keeps the table it gave,
    /// so the parse and its log line do not repeat for each frame.
    #[test]
    fn a_broken_file_is_parsed_once_for_each_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[host-exposures.web\n").unwrap();
        let file = HostExposuresFile::new(path);
        let first = file.current();
        assert!(first.is_empty());
        assert!(
            Arc::ptr_eq(&first, &file.current()),
            "the same broken text keeps its table"
        );
    }

    #[test]
    fn an_edit_that_keeps_the_stamp_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[host-exposures.web]\nport = 8080\n").unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let file = HostExposuresFile::new(path.clone());
        assert!(file.current().opens(6, 8080));
        // The same length and inode, and the modification time put back:
        // an edit inside one timestamp tick.
        std::fs::write(&path, "[host-exposures.web]\nport = 8081\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        let table = file.current();
        assert!(!table.opens(6, 8080), "the removed port is closed");
        assert!(table.opens(6, 8081), "the new port is open");
    }

    /// An edit that keeps the length and restores an old modification time,
    /// as `touch -r` does, still changes the change time, so it is read.
    #[test]
    fn an_edit_that_restores_an_old_mtime_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let old = SystemTime::now() - Duration::from_secs(3600);
        let set_old = |path: &Path| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        };
        std::fs::write(&path, "[host-exposures.web]\nport = 8080\n").unwrap();
        set_old(&path);
        let file = HostExposuresFile::new(path.clone());
        assert!(file.current().opens(6, 8080));
        // Some kernels keep a coarse change time, so let one tick pass.
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(&path, "[host-exposures.web]\nport = 8081\n").unwrap();
        set_old(&path);
        let table = file.current();
        assert!(!table.opens(6, 8080), "the removed port is closed");
        assert!(table.opens(6, 8081), "the new port is open");
    }

    /// A modification time after the read is racy for one more read only.
    /// When that read finds the same stamp and text, the stamp is proof.
    #[test]
    fn a_future_mtime_is_proof_after_one_confirming_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[host-exposures.web]\nport = 8080\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(3600))
            .unwrap();
        let file = HostExposuresFile::new(path);
        let first = file.current();
        let confirmed = |file: &HostExposuresFile| {
            file.state
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|loaded| loaded.confirmed)
        };
        assert!(!confirmed(&file), "the first read proves nothing");
        assert!(Arc::ptr_eq(&first, &file.current()));
        assert!(confirmed(&file), "the second read confirms the stamp");
        let loaded = file.state.lock().unwrap().as_ref().unwrap().read_at;
        assert!(Arc::ptr_eq(&first, &file.current()));
        assert_eq!(
            file.state.lock().unwrap().as_ref().unwrap().read_at,
            loaded,
            "a confirmed stamp is not read again"
        );
    }
}
