//! The host exposures: the ports at which a box reaches the host through
//! `host.min.internal`, read from the `[host-exposures]` table of the client
//! `config.toml` (design §7.1, NET-156, NET-158).
//!
//! The design holds the host alias default-deny except explicitly
//! configured host exposures. The table names each exposure by a key of the
//! user's choice, and the value is a port or an inclusive port range:
//!
//! ```toml
//! [host-exposures]
//! dev-server = 8080
//! vite = "3000-3999"
//! ```
//!
//! The gate decides each flow by the current table. The handle re-reads the
//! file when its stat changes, as `bep serve` does for
//! `[secret-store-rules]`, so an entry added opens its port and an entry
//! removed closes it, with no restart. The handle stats the file at most
//! once per [`RECHECK`], because the gate asks at every frame to the alias.
//!
//! The reader fails closed. A missing file, a file that does not parse, or a
//! table that is not a table gives no exposure, and the alias stays closed
//! at every port. An entry whose value is not a port from 1 to 65535 or a
//! low-high range is skipped, and the daemon log names it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// The table of the client `config.toml` that names the host exposures.
pub(crate) const HOST_EXPOSURES_TABLE: &str = "host-exposures";

/// The longest time a changed table waits before the gate decides by it:
/// the handle stats the file at most once in this interval.
pub(crate) const RECHECK: Duration = Duration::from_secs(1);

/// One exposure as an inclusive port range, `(lo, hi)`.
pub(crate) type PortRange = (u16, u16);

/// A shared handle on the current host-exposure table. Clones share one
/// table, so the gate and the start-up line read the same ports.
#[derive(Clone)]
pub struct HostExposures {
    inner: Arc<Inner>,
}

struct Inner {
    /// The `config.toml` the table is read from, `None` for a fixed table.
    path: Option<PathBuf>,
    /// The least time between two stats of the file.
    recheck: Duration,
    state: Mutex<State>,
}

struct State {
    /// The stat of the file version the ports came from.
    stamp: Option<Stamp>,
    /// When the handle last looked at the file, `None` before the first look.
    checked: Option<Instant>,
    /// The ports the current table opens.
    ports: Arc<[PortRange]>,
}

/// The stat of one file version: an edit changes at least one field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    /// The inode change time, the inode and the device: an edit that keeps
    /// the length and the modification time still sets the change time, and
    /// a file replaced by a rename gets a new inode.
    #[cfg(unix)]
    unix: (i64, i64, u64, u64),
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let unix = {
        use std::os::unix::fs::MetadataExt as _;
        (meta.ctime(), meta.ctime_nsec(), meta.dev(), meta.ino())
    };
    Some(Stamp {
        modified: meta.modified().ok(),
        len: meta.len(),
        #[cfg(unix)]
        unix,
    })
}

impl HostExposures {
    /// The table of the user-level client `config.toml` in the default
    /// config dir, the file `bep serve` reads its rules from. With no
    /// config dir (no absolute `XDG_CONFIG_HOME` and no home directory)
    /// there is no table, and the alias stays closed.
    #[must_use]
    pub fn client_config() -> Self {
        let path = client_config_path();
        match &path {
            Some(path) => tracing::info!(
                config = %path.display(),
                table = HOST_EXPOSURES_TABLE,
                "reading the host exposures from the client config"
            ),
            None => tracing::warn!(
                table = HOST_EXPOSURES_TABLE,
                "found no XDG_CONFIG_HOME and no home directory, so host.min.internal \
                 has no host exposure"
            ),
        }
        match path {
            Some(path) => Self::at(path, RECHECK),
            None => Self::fixed(Vec::new()),
        }
    }

    /// The table of the `config.toml` at `path`, re-read when the file
    /// changes, with at least `recheck` between two stats of it.
    #[must_use]
    pub fn at(path: PathBuf, recheck: Duration) -> Self {
        Self::new(Some(path), recheck, Vec::new())
    }

    /// A table that no file backs: `ports` and nothing else, for the life of
    /// the handle.
    #[must_use]
    pub fn fixed(ports: Vec<PortRange>) -> Self {
        Self::new(None, Duration::ZERO, ports)
    }

    fn new(path: Option<PathBuf>, recheck: Duration, ports: Vec<PortRange>) -> Self {
        Self {
            inner: Arc::new(Inner {
                path,
                recheck,
                state: Mutex::new(State {
                    stamp: None,
                    checked: None,
                    ports: ports.into(),
                }),
            }),
        }
    }

    /// The ports the current table opens. The handle re-reads the file
    /// first when the recheck interval passed and the file's stat changed.
    #[must_use]
    pub(crate) fn current(&self) -> Arc<[PortRange]> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(path) = &self.inner.path else {
            return Arc::clone(&state.ports);
        };
        let now = Instant::now();
        let due = state
            .checked
            .is_none_or(|checked| now.duration_since(checked) >= self.inner.recheck);
        if due {
            let first = state.checked.is_none();
            state.checked = Some(now);
            let current = stamp(path);
            if first || current != state.stamp {
                let ports: Arc<[PortRange]> = read_table(path).into();
                if first || ports != state.ports {
                    tracing::info!(
                        config = %path.display(),
                        host_exposure_ports = %render(&ports),
                        "read the host exposures for host.min.internal"
                    );
                }
                state.ports = ports;
                state.stamp = current;
            }
        }
        Arc::clone(&state.ports)
    }

    /// The current table as the daemon log spells it: one `lo-hi` term per
    /// range, a bare port for a single-port term, and `(none)` for no
    /// exposure.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        render(&self.current())
    }
}

impl std::fmt::Debug for HostExposures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostExposures")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

/// Two handles are equal when they share one table.
impl PartialEq for HostExposures {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for HostExposures {}

fn render(ports: &[PortRange]) -> String {
    if ports.is_empty() {
        return "(none)".to_string();
    }
    ports
        .iter()
        .map(|&(lo, hi)| {
            if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The user-level `config.toml` in the default config dir, or `None` when
/// neither an absolute `XDG_CONFIG_HOME` nor a home directory names it.
fn client_config_path() -> Option<PathBuf> {
    // `paths` takes an absolute `XDG_CONFIG_HOME` first, and stops the
    // process when it then finds no home directory. Check the same order.
    let xdg = std::env::var_os("XDG_CONFIG_HOME").is_some_and(|dir| Path::new(&dir).is_absolute());
    if !xdg {
        std::env::home_dir()?;
    }
    Some(paths::minimal_config_dir_with_override(None).join("config.toml"))
}

/// Reads the table of the file at `path`, failing closed: a missing or
/// unparseable file is no exposure.
fn read_table(path: &Path) -> Vec<PortRange> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            tracing::warn!(
                config = %path.display(),
                %error,
                "could not read the client config, so host.min.internal has no host exposure"
            );
            return Vec::new();
        }
    };
    match parse_table(&text) {
        Ok(ports) => ports,
        Err(error) => {
            tracing::warn!(
                config = %path.display(),
                %error,
                "could not parse the client config, so host.min.internal has no host exposure"
            );
            Vec::new()
        }
    }
}

/// Parses the `[host-exposures]` table of one `config.toml` text. No table
/// is no exposure. An entry that is not a port or a range is skipped with a
/// log line that names it.
fn parse_table(text: &str) -> Result<Vec<PortRange>, toml::de::Error> {
    let doc: toml::Table = toml::from_str(text)?;
    let Some(table) = doc.get(HOST_EXPOSURES_TABLE) else {
        return Ok(Vec::new());
    };
    let Some(table) = table.as_table() else {
        tracing::warn!(
            table = HOST_EXPOSURES_TABLE,
            "the host-exposures key in the client config is not a table, so \
             host.min.internal has no host exposure"
        );
        return Ok(Vec::new());
    };
    let mut ports: Vec<PortRange> = table
        .iter()
        .filter_map(|(name, value)| {
            let range = entry_range(value);
            if range.is_none() {
                tracing::warn!(
                    table = HOST_EXPOSURES_TABLE,
                    entry = %name,
                    value = %value,
                    "skipped a host exposure that is not a port from 1 to 65535 or a \
                     low-high port range"
                );
            }
            range
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// One entry's value as a range: an integer port, or a string that holds a
/// port (`"8080"`) or an inclusive low-high range (`"3000-3999"`).
fn entry_range(value: &toml::Value) -> Option<PortRange> {
    let port = |n: i64| u16::try_from(n).ok().filter(|&p| p != 0);
    let text_port = |text: &str| text.trim().parse::<u16>().ok().filter(|&p| p != 0);
    match value {
        toml::Value::Integer(n) => port(*n).map(|p| (p, p)),
        toml::Value::String(text) => match text.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (text_port(lo)?, text_port(hi)?);
                (lo <= hi).then_some((lo, hi))
            }
            None => text_port(text).map(|p| (p, p)),
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HostExposures, parse_table};
    use std::time::Duration;

    #[test]
    fn host_exposures_table_parses_ports_and_ranges() {
        let ports = parse_table(
            "[host-exposures]\ndev = 8080\nvite = \"3000-3999\"\nweb = \" 4200 \"\n\
             zero = 0\nbig = 70000\nreversed = \"4000-3000\"\nword = \"nope\"\nlist = [1]\n",
        )
        .unwrap();
        assert_eq!(ports, vec![(3000, 3999), (4200, 4200), (8080, 8080)]);
        assert!(parse_table("[other]\nx = 1\n").unwrap().is_empty());
        assert!(parse_table("host-exposures = 8080\n").unwrap().is_empty());
        assert!(parse_table("not toml [").is_err());
    }

    #[test]
    fn host_exposures_follow_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let exposures = HostExposures::at(path.clone(), Duration::ZERO);
        assert!(exposures.current().is_empty(), "no file is no exposure");
        std::fs::write(&path, "[host-exposures]\ndev = 8080\n").unwrap();
        assert_eq!(&*exposures.current(), &[(8080, 8080)]);
        std::fs::write(&path, "[host-exposures]\n").unwrap();
        assert!(exposures.current().is_empty(), "a removed entry closes");
        std::fs::write(&path, "broken [").unwrap();
        assert!(exposures.current().is_empty(), "a broken file fails closed");
    }
}
