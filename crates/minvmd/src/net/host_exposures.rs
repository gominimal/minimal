//! The host exposures: the ports at which a box reaches the host through
//! `host.min.internal`, read from the `[host-exposures]` table of the client
//! `config.toml` (design §7.1, NET-156, NET-158).
//!
//! The design holds the host alias default-deny except explicitly
//! configured host exposures. The table names each exposure by a key of the
//! user's choice. The value is an inline table with a port and a protocol,
//! and the protocol defaults to `tcp`:
//!
//! ```toml
//! [host-exposures]
//! postgres = { proto = "tcp", port = 5432 }
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
//! at every port. An entry that is not an inline table with a port from 1 to
//! 65535 and a protocol of `tcp` or `udp` is skipped, and the daemon log
//! names it. An entry at a port that a Minimal listener holds is refused at
//! load, and the daemon log names the entry and the holder.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use boxes::core::egress::{IPPROTO_TCP, IPPROTO_UDP};

/// The table of the client `config.toml` that names the host exposures.
pub(crate) const HOST_EXPOSURES_TABLE: &str = "host-exposures";

/// The longest time a changed table waits before the gate decides by it:
/// the handle stats the file at most once in this interval.
pub(crate) const RECHECK: Duration = Duration::from_secs(1);

/// One port set as inclusive port ranges, `(lo, hi)`: the baseline set's
/// own openings at the alias.
pub(crate) type PortRange = (u16, u16);

/// One host exposure: the IP protocol and the port a table entry opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostExposure {
    /// The IP protocol number: [`IPPROTO_TCP`] or [`IPPROTO_UDP`].
    pub(crate) protocol: u8,
    pub(crate) port: u16,
}

impl HostExposure {
    /// A TCP exposure at `port`.
    #[must_use]
    pub const fn tcp(port: u16) -> Self {
        Self {
            protocol: IPPROTO_TCP,
            port,
        }
    }

    /// A UDP exposure at `port`.
    #[must_use]
    pub const fn udp(port: u16) -> Self {
        Self {
            protocol: IPPROTO_UDP,
            port,
        }
    }

    /// Whether a frame with this IP protocol and destination port matches.
    #[must_use]
    pub(crate) fn admits(self, protocol: u8, port: u16) -> bool {
        self.protocol == protocol && self.port == port
    }
}

/// The ports a Minimal listener holds on the host, each with the listener
/// that holds it. The table refuses an entry at one of these ports at load
/// (design §7.1), for either protocol: an exposure there hands a box the
/// listener in place of a service of the user's.
pub(crate) const LISTENER_PORTS: [(u16, &str); 3] = [
    // `cmd/run.rs` `NODE_DEFAULT_PROXY_PORT`: the hostname proxy.
    (7654, "the hostname proxy"),
    (crate::net::answerer::DEFAULT_ANSWERER_PORT, "the answerer"),
    (switch::bep_host::PROXY_PORT, "the Box Egress Proxy"),
];

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
    /// The exposures the current table opens.
    ports: Arc<[HostExposure]>,
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
    pub fn fixed(ports: Vec<HostExposure>) -> Self {
        Self::new(None, Duration::ZERO, ports)
    }

    fn new(path: Option<PathBuf>, recheck: Duration, ports: Vec<HostExposure>) -> Self {
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

    /// The exposures the current table opens. The handle re-reads the file
    /// first when the recheck interval passed and the file's stat changed.
    /// The stat and the read run outside the lock, so a slow disk stalls
    /// only the frame that found the recheck due, never the other callers.
    #[must_use]
    pub(crate) fn current(&self) -> Arc<[HostExposure]> {
        let Some(path) = &self.inner.path else {
            return Arc::clone(&self.lock().ports);
        };
        let (first, known) = {
            let mut state = self.lock();
            let now = Instant::now();
            let due = state
                .checked
                .is_none_or(|checked| now.duration_since(checked) >= self.inner.recheck);
            if !due {
                return Arc::clone(&state.ports);
            }
            // Mark the check as taken before the IO, so the callers that
            // come in the meantime keep the current table and do not stat.
            let first = state.checked.is_none();
            state.checked = Some(now);
            (first, state.stamp.clone())
        };
        let current = stamp(path);
        if !first && current == known {
            return Arc::clone(&self.lock().ports);
        }
        let ports: Arc<[HostExposure]> = read_table(path).into();
        let mut state = self.lock();
        if first || ports != state.ports {
            tracing::info!(
                config = %path.display(),
                host_exposure_ports = %render(&ports),
                "read the host exposures for host.min.internal"
            );
        }
        state.ports = Arc::clone(&ports);
        state.stamp = current;
        ports
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The current table as the daemon log spells it: one `proto/port` term
    /// per exposure, and `(none)` for no exposure.
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

fn render(ports: &[HostExposure]) -> String {
    if ports.is_empty() {
        return "(none)".to_string();
    }
    ports
        .iter()
        .map(|exposure| {
            let proto = if exposure.protocol == IPPROTO_UDP {
                "udp"
            } else {
                "tcp"
            };
            format!("{proto}/{}", exposure.port)
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
fn read_table(path: &Path) -> Vec<HostExposure> {
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
/// is no exposure. An entry that is not an exposure is skipped, and an entry
/// at a Minimal listener's port is refused. Each one gets a log line that
/// names it.
fn parse_table(text: &str) -> Result<Vec<HostExposure>, toml::de::Error> {
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
    let mut ports: Vec<HostExposure> = table
        .iter()
        .filter_map(|(name, value)| {
            let Some(exposure) = entry_exposure(value) else {
                tracing::warn!(
                    table = HOST_EXPOSURES_TABLE,
                    entry = %name,
                    value = %value,
                    "skipped a host exposure that is not {{ proto = \"tcp\" or \"udp\", \
                     port = 1 to 65535 }}"
                );
                return None;
            };
            if let Some(holder) = listener_holding(exposure.port) {
                tracing::warn!(
                    table = HOST_EXPOSURES_TABLE,
                    entry = %name,
                    port = exposure.port,
                    holder,
                    "refused a host exposure at a port that a Minimal listener holds"
                );
                return None;
            }
            Some(exposure)
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// The Minimal listener that holds `port` on the host, if one does.
fn listener_holding(port: u16) -> Option<&'static str> {
    LISTENER_PORTS
        .iter()
        .find(|&&(held, _)| held == port)
        .map(|&(_, holder)| holder)
}

/// One entry's value as an exposure: the inline table
/// `{ proto = "tcp", port = N }`, where `proto` is `tcp` or `udp` and
/// defaults to `tcp`. Any other key or form is not an exposure.
fn entry_exposure(value: &toml::Value) -> Option<HostExposure> {
    let entry = value.as_table()?;
    if entry.keys().any(|key| key != "proto" && key != "port") {
        return None;
    }
    let port = entry
        .get("port")?
        .as_integer()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&port| port != 0)?;
    match entry.get("proto").map(toml::Value::as_str) {
        None | Some(Some("tcp")) => Some(HostExposure::tcp(port)),
        Some(Some("udp")) => Some(HostExposure::udp(port)),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HostExposure, HostExposures, LISTENER_PORTS, parse_table};
    use std::time::Duration;

    #[test]
    fn host_exposures_table_parses_the_inline_table_form() {
        let ports = parse_table(
            "[host-exposures]\n\
             postgres = { proto = \"tcp\", port = 5432 }\n\
             vite = { port = 5173 }\n\
             dns = { proto = \"udp\", port = 5353 }\n\
             bare = 8080\n\
             range = \"3000-3999\"\n\
             text = \"4200\"\n\
             zero = { port = 0 }\n\
             big = { port = 70000 }\n\
             icmp = { proto = \"icmp\", port = 1 }\n\
             extra = { port = 9000, host = \"x\" }\n\
             noport = { proto = \"tcp\" }\n",
        )
        .unwrap();
        assert_eq!(
            ports,
            vec![
                HostExposure::tcp(5173),
                HostExposure::tcp(5432),
                HostExposure::udp(5353),
            ]
        );
        assert!(parse_table("[other]\nx = 1\n").unwrap().is_empty());
        assert!(parse_table("host-exposures = 8080\n").unwrap().is_empty());
        assert!(parse_table("not toml [").is_err());
    }

    #[test]
    fn host_exposures_table_refuses_a_listener_port() {
        for (port, _) in LISTENER_PORTS {
            for proto in ["tcp", "udp"] {
                let text =
                    format!("[host-exposures]\nx = {{ proto = \"{proto}\", port = {port} }}\n");
                assert!(
                    parse_table(&text).unwrap().is_empty(),
                    "{proto} port {port} is a Minimal listener's"
                );
            }
        }
    }

    #[test]
    fn host_exposures_follow_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let exposures = HostExposures::at(path.clone(), Duration::ZERO);
        assert!(exposures.current().is_empty(), "no file is no exposure");
        std::fs::write(&path, "[host-exposures]\ndev = { port = 8080 }\n").unwrap();
        assert_eq!(&*exposures.current(), &[HostExposure::tcp(8080)]);
        std::fs::write(&path, "[host-exposures]\n").unwrap();
        assert!(exposures.current().is_empty(), "a removed entry closes");
        std::fs::write(&path, "broken [").unwrap();
        assert!(exposures.current().is_empty(), "a broken file fails closed");
    }
}
