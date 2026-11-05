//! The host exposures: the ports at which a box reaches the host through
//! `host.min.internal`, read from the `[host-exposures]` table of the client
//! `config.toml` (design §7.1, NET-159, NET-161, NET-162).
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
//! The gate decides each flow by the current table (NET-161). The handle
//! re-reads the file when its stat changes, as `bep serve` does for
//! `[secret-store-rules]`, so an entry added opens its port and an entry
//! removed closes it, with no restart. The handle stats the file at most
//! once per [`RECHECK`], because the gate asks at every frame to the alias.
//!
//! Minimal's own listeners are never exposures (NET-162). The gate hands
//! the handle the listeners that hold a port at each decision
//! ([`Holder`]). An entry at such a port is refused when the table loads,
//! and an entry whose port a listener binds later is shadowed from that
//! decision on. The daemon log names the entry and the listener, once.
//!
//! The file is read through the shared reader in `client-config`
//! ([`HostExposuresFile`]), the one the native session daemon reads it
//! through, so both daemons handle a bad entry one way. The reader fails
//! closed. A missing file, a file that does not parse, or a table that is
//! not a table gives no exposure, and the alias stays closed at every port.
//! An entry that is not a table with a port from 1 to 65535 and a protocol
//! of `tcp` or `udp` is skipped, and the daemon log names it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use boxes::core::egress::{IPPROTO_TCP, IPPROTO_UDP};
use client_config::host_exposures::{HOST_EXPOSURES_TABLE, HostExposuresFile};

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

/// One table entry: the name the user gave it and the exposure it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) exposure: HostExposure,
}

/// One of Minimal's own listeners or sockets on the host, with the ports
/// it holds (NET-162). An entry at a held port is never an exposure: it
/// hands a box the listener in place of a service of the user's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Holder {
    /// The ports the listener holds, inclusive.
    pub(crate) ports: PortRange,
    /// The IP protocol it holds them for, `None` for both.
    pub(crate) protocol: Option<u8>,
    /// The listener as the daemon log names it.
    pub(crate) name: &'static str,
}

impl Holder {
    /// Whether this listener holds the port that `exposure` opens.
    #[must_use]
    pub(crate) fn holds(&self, exposure: HostExposure) -> bool {
        self.holds_port(exposure.protocol, exposure.port)
    }

    /// Whether this listener holds `port` for `protocol`.
    #[must_use]
    pub(crate) fn holds_port(&self, protocol: u8, port: u16) -> bool {
        let (lo, hi) = self.ports;
        lo <= port && port <= hi && self.protocol.is_none_or(|held| held == protocol)
    }
}

/// The hostname proxy, as the daemon log names it.
pub(crate) const HOSTNAME_PROXY: &str = "the hostname proxy";
/// The box-name answerer, as the daemon log names it.
pub(crate) const ANSWERER: &str = "the box-name answerer";
/// The node-local Box Egress Proxy, as the daemon log names it.
pub(crate) const BOX_EGRESS_PROXY: &str = "the Box Egress Proxy";
/// A node-plane baseline endpoint at the alias, as the daemon log names it.
pub(crate) const BASELINE_ENDPOINT: &str = "a node-plane baseline endpoint at host.min.internal";

/// Minimal's own listeners and sockets that hold a port at the host alias,
/// as the gate knows them at one flow (NET-162):
///
/// - the hostname proxy at each port in `hostname_proxy`: the node row's
///   assigned port, an operator's pin or a drawn fallback;
/// - the box-name answerer at the port each VM-backed node reserves for it;
/// - the node-local Box Egress Proxy at its listener's port;
/// - the node-plane baseline endpoints at `baseline_alias_ports`, over the
///   protocol the baseline fetches with.
#[must_use]
pub(crate) fn minimal_listeners(
    hostname_proxy: &[u16],
    baseline_alias_ports: &[PortRange],
    baseline_protocol: u8,
) -> Vec<Holder> {
    let mut held: Vec<Holder> = hostname_proxy
        .iter()
        .map(|&port| Holder {
            ports: (port, port),
            protocol: None,
            name: HOSTNAME_PROXY,
        })
        .collect();
    let answerer = crate::net::answerer::DEFAULT_ANSWERER_PORT;
    held.push(Holder {
        ports: (answerer, answerer),
        protocol: None,
        name: ANSWERER,
    });
    let proxy = switch::bep_host::PROXY_PORT;
    held.push(Holder {
        ports: (proxy, proxy),
        protocol: None,
        name: BOX_EGRESS_PROXY,
    });
    held.extend(baseline_alias_ports.iter().map(|&ports| Holder {
        ports,
        protocol: Some(baseline_protocol),
        name: BASELINE_ENDPOINT,
    }));
    held
}

/// A shared handle on the current host-exposure table. Clones share one
/// table, so the gate and the start-up line read the same ports.
#[derive(Clone)]
pub struct HostExposures {
    inner: Arc<Inner>,
}

struct Inner {
    /// The `config.toml` the table is read from, `None` for a fixed table.
    file: Option<HostExposuresFile>,
    /// The least time between two stats of the file.
    recheck: Duration,
    state: Mutex<State>,
}

struct State {
    /// The table the shared reader gave for the entries, so a read that
    /// gives the same table changes nothing.
    table: Option<Arc<client_config::host_exposures::HostExposures>>,
    /// When the handle last looked at the file, `None` before the first look.
    checked: Option<Instant>,
    /// The entries of the current table, each in the accepted form.
    entries: Arc<[Entry]>,
    /// The listeners the last decision held the entries against.
    held: Vec<Holder>,
    /// The exposures the current table opens: the entries no listener holds.
    open: Arc<[HostExposure]>,
    /// The entries the log already named as refused or shadowed, each with
    /// its holder, so the log names each one once while the holder stays.
    reported: Vec<(String, HostExposure, &'static str)>,
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
    /// the handle. Each entry is named by its `proto/port` term.
    #[must_use]
    pub fn fixed(ports: Vec<HostExposure>) -> Self {
        let entries = ports
            .into_iter()
            .map(|exposure| Entry {
                name: render(&[exposure]),
                exposure,
            })
            .collect();
        Self::new(None, Duration::ZERO, entries)
    }

    fn new(path: Option<PathBuf>, recheck: Duration, entries: Vec<Entry>) -> Self {
        let open: Arc<[HostExposure]> = entries.iter().map(|entry| entry.exposure).collect();
        Self {
            inner: Arc::new(Inner {
                file: path.map(HostExposuresFile::new),
                recheck,
                state: Mutex::new(State {
                    table: None,
                    checked: None,
                    entries: entries.into(),
                    held: Vec::new(),
                    open,
                    reported: Vec::new(),
                }),
            }),
        }
    }

    /// The exposures the current table opens while the listeners in `held`
    /// hold their ports. The handle re-reads the file first when the
    /// recheck interval passed and the file's stat changed.
    ///
    /// An entry at a held port is not opened. When the entry is new in a
    /// load, the log says the load refused it. When the entry was open
    /// before, the log says the listener shadows it. Each says it once while
    /// the listener holds the port, and names the entry and the listener.
    #[must_use]
    pub(crate) fn current(&self, held: &[Holder]) -> Arc<[HostExposure]> {
        let loaded = self.reload();
        let mut state = self.lock();
        if loaded.is_none() && state.held == held {
            return Arc::clone(&state.open);
        }
        let before: Arc<[Entry]> = match loaded {
            Some(entries) => std::mem::replace(&mut state.entries, entries),
            None => Arc::clone(&state.entries),
        };
        let entries = Arc::clone(&state.entries);
        let mut open = Vec::with_capacity(entries.len());
        let mut reported = Vec::new();
        for entry in entries.iter() {
            let Some(holder) = held.iter().find(|holder| holder.holds(entry.exposure)) else {
                open.push(entry.exposure);
                continue;
            };
            let key = (entry.name.clone(), entry.exposure, holder.name);
            if !state.reported.contains(&key) {
                let (proto, port) = (proto_name(entry.exposure), entry.exposure.port);
                if before.contains(entry) {
                    tracing::warn!(
                        table = HOST_EXPOSURES_TABLE,
                        entry = %entry.name,
                        proto,
                        port,
                        holder = holder.name,
                        "a Minimal listener now holds the port of a host exposure, so \
                         boxes no longer reach it at host.min.internal"
                    );
                } else {
                    tracing::warn!(
                        table = HOST_EXPOSURES_TABLE,
                        entry = %entry.name,
                        proto,
                        port,
                        holder = holder.name,
                        "refused a host exposure at a port that a Minimal listener holds"
                    );
                }
            }
            reported.push(key);
        }
        state.reported = reported;
        state.held = held.to_vec();
        state.open = open.into();
        Arc::clone(&state.open)
    }

    /// Asks the shared reader for the table when the recheck interval
    /// passed, and returns the entries when its table changed. The reader
    /// runs outside this handle's lock, so a slow disk stalls only the frame
    /// that found the recheck due, never the other callers.
    fn reload(&self) -> Option<Arc<[Entry]>> {
        let file = self.inner.file.as_ref()?;
        let (first, known) = {
            let mut state = self.lock();
            let now = Instant::now();
            let due = state
                .checked
                .is_none_or(|checked| now.duration_since(checked) >= self.inner.recheck);
            if !due {
                return None;
            }
            // Mark the check as taken before the IO, so the callers that
            // come in the meantime keep the current table and do not stat.
            let first = state.checked.is_none();
            state.checked = Some(now);
            (first, state.table.clone())
        };
        let table = file.current();
        if !first
            && known
                .as_ref()
                .is_some_and(|known| Arc::ptr_eq(known, &table))
        {
            return None;
        }
        let entries: Arc<[Entry]> = entries_of(&table).into();
        let mut state = self.lock();
        state.table = Some(table);
        if first || entries != state.entries {
            let ports: Vec<HostExposure> = entries.iter().map(|entry| entry.exposure).collect();
            tracing::info!(
                config = %file.path().display(),
                host_exposure_ports = %render(&ports),
                "read the host exposures for host.min.internal"
            );
        }
        Some(entries)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The current table as the daemon log spells it: one `proto/port` term
    /// per exposure the last decision opened, and `(none)` for no exposure.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        let held = self.lock().held.clone();
        render(&self.current(&held))
    }
}

impl std::fmt::Debug for HostExposures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostExposures")
            .field(
                "path",
                &self.inner.file.as_ref().map(HostExposuresFile::path),
            )
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

fn proto_name(exposure: HostExposure) -> &'static str {
    if exposure.protocol == IPPROTO_UDP {
        "udp"
    } else {
        "tcp"
    }
}

fn render(ports: &[HostExposure]) -> String {
    if ports.is_empty() {
        return "(none)".to_string();
    }
    ports
        .iter()
        .map(|&exposure| format!("{}/{}", proto_name(exposure), exposure.port))
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

/// The entries of one table the shared reader gave, each in the accepted
/// form, in the order of their exposure and then their name. The listeners
/// are held against the entries at each decision
/// ([`HostExposures::current`]), not here.
fn entries_of(table: &client_config::host_exposures::HostExposures) -> Vec<Entry> {
    let mut entries: Vec<Entry> = table
        .iter()
        .map(|(name, entry)| Entry {
            name: name.to_string(),
            exposure: HostExposure {
                protocol: entry.proto.ip_protocol(),
                port: entry.port,
            },
        })
        .collect();
    entries.sort_unstable_by(|a, b| (a.exposure, &a.name).cmp(&(b.exposure, &b.name)));
    entries
}

#[cfg(test)]
mod tests {
    use super::{HostExposure, HostExposures, client_config_path, entries_of};
    use std::time::Duration;

    /// The entries of `text`, read by the shared reader.
    fn parse_table(
        text: &str,
    ) -> Result<Vec<super::Entry>, client_config::host_exposures::HostExposuresError> {
        client_config::host_exposures::parse_host_exposures(
            text,
            std::path::Path::new("config.toml"),
        )
        .map(|table| entries_of(&table))
    }

    fn exposures_of(entries: &[super::Entry]) -> Vec<HostExposure> {
        entries.iter().map(|entry| entry.exposure).collect()
    }

    /// NET-159: the host exposures come from the `[host-exposures]` table of
    /// the client `config.toml` alone. Each entry names one exposure, its
    /// port and its protocol, and `proto` defaults to `tcp`. The handle
    /// reads the file at the client config's path and follows it.
    #[test]
    fn host_exposures_read_from_client_config() {
        let entries = parse_table(
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
            exposures_of(&entries),
            vec![
                HostExposure::tcp(5173),
                HostExposure::tcp(5432),
                HostExposure::udp(5353),
            ]
        );
        assert_eq!(entries[0].name, "vite", "each entry keeps its name");
        assert!(parse_table("[other]\nx = 1\n").unwrap().is_empty());
        assert!(
            parse_table("host-exposures = 8080\n").is_err(),
            "a key that is not a table reads as no table, and the alias stays closed"
        );
        assert!(parse_table("not toml [").is_err());

        // The file is the client config: `config.toml` in the config dir.
        if let Some(path) = client_config_path() {
            assert_eq!(
                path,
                paths::minimal_config_dir_with_override(None).join("config.toml")
            );
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let exposures = HostExposures::at(path.clone(), Duration::ZERO);
        assert!(exposures.current(&[]).is_empty(), "no file is no exposure");
        std::fs::write(
            &path,
            "[secrets]\n\n[host-exposures]\ndev = { port = 8080 }\n",
        )
        .unwrap();
        assert_eq!(&*exposures.current(&[]), &[HostExposure::tcp(8080)]);
        std::fs::write(&path, "[host-exposures]\n").unwrap();
        assert!(exposures.current(&[]).is_empty(), "a removed entry closes");
        std::fs::write(&path, "broken [").unwrap();
        assert!(
            exposures.current(&[]).is_empty(),
            "a broken file fails closed"
        );
    }
}
