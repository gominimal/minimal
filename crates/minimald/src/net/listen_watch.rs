//! Port-on-listen: a box's ports publish themselves as processes in it begin
//! listening, and unpublish themselves when those listeners close (NET-016,
//! NET-017).
//!
//! A port a declaration names is bound before the box's name is registered and
//! held until the box stops (NET-121), so nothing here touches it. A port no
//! declaration names cannot be bound ahead of a listener, so for those the
//! publication follows the listener: this watcher reads the box's listening
//! ports, asks the box's own rules about each one
//! ([`ingress_permit_verdict`]), and publishes the permitted ones on the box's
//! address — a port the rules do not permit is never published, whatever
//! listens on it.
//!
//! The decision is the pure one in `sessions`; this module only observes and
//! applies it. What it observes comes through [`Listeners`], so the watcher is
//! driven in tests by a fixed observation and in production by
//! [`ProcListeners`], which reads the socket table of the network namespace
//! the box unshared and names the pid holding each listener from the box's own
//! open descriptors.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use sessions::core::net_verdict::{
    IPPROTO_TCP, IngressRules, ListenPublication, ingress_permit_verdict,
};
use tokio_util::sync::CancellationToken;

use super::publish::PublishTable;

/// How often a watched box's listening ports are re-read. A listener is
/// published within one interval of opening, and its publication withdrawn
/// within one interval of closing.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How many of a box's processes are walked when naming the pid behind a
/// listener. A bound rather than an unbounded walk: the map is a convenience
/// for the published-port table, never a reason to spend the daemon's time.
const PID_WALK_LIMIT: usize = 512;

/// One listening socket inside a box: the port it listens on, and the pid
/// holding it as the daemon sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// The box's own port number.
    pub port: u16,
    /// The pid of the process holding the listener, daemon-side.
    pub pid: u32,
}

/// Where a box's listening ports are read from.
pub trait Listeners: Send + 'static {
    /// The box's listening ports right now.
    ///
    /// # Errors
    ///
    /// The I/O error from reading the box's socket table. A box that has gone
    /// away errors rather than reporting no listener, so the watcher stops
    /// instead of reading an empty table as "every listener closed".
    fn observe(&self) -> io::Result<Vec<Listener>>;
}

/// The watcher on one box's listening ports: the box's rules, the table its
/// ports are published in, and what this watcher has published so far.
pub struct ListenWatch {
    session_name: String,
    /// The box's ingress rules, read box-side — the spelling a process in the
    /// box listens on ([`IngressRules::for_box_listeners`]).
    rules: IngressRules,
    published: Arc<RwLock<PublishTable>>,
    /// The ports this watcher published, with the pid each was published for.
    listened: BTreeMap<u16, u32>,
    /// Ports already refused, so a port the rules do not permit is accounted
    /// for once rather than on every pass.
    refused: BTreeSet<u16>,
}

impl ListenWatch {
    /// A watcher on `session_name`'s box, publishing into `published`.
    #[must_use]
    pub fn new(
        session_name: String,
        rules: IngressRules,
        published: Arc<RwLock<PublishTable>>,
    ) -> Self {
        Self {
            session_name,
            rules,
            published,
            listened: BTreeMap::new(),
            refused: BTreeSet::new(),
        }
    }

    /// One pass over what the box is listening on: publishes each permitted
    /// port no declaration names and no earlier pass published (NET-016), and
    /// withdraws every publication whose listener is gone (NET-017).
    ///
    /// A port the rules do not permit is left unpublished and noticed once,
    /// with the rule it failed; a port a declaration names is already
    /// published with a forwarder of its own (NET-121), so it is left alone.
    pub fn reconcile(&mut self, seen: &[Listener]) {
        let mut table = self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner);

        for listener in seen {
            if self.listened.contains_key(&listener.port) {
                continue;
            }
            match ingress_permit_verdict(&self.rules, IPPROTO_TCP, listener.port) {
                ListenPublication::Publish => {
                    if table.publish_listened(&self.session_name, listener.port, listener.pid) {
                        self.listened.insert(listener.port, listener.pid);
                    }
                }
                // Bound and published before the box's name was registered.
                ListenPublication::Declared => {}
                ListenPublication::Unpermitted => {
                    if self.refused.insert(listener.port) {
                        tracing::info!(
                            session = %self.session_name,
                            port = listener.port,
                            pid = listener.pid,
                            permitted = false,
                            "left a listening port unpublished: the box's ingress rules do not \
                             permit it"
                        );
                    }
                }
            }
        }

        let closed: Vec<u16> = self
            .listened
            .keys()
            .copied()
            .filter(|port| !seen.iter().any(|l| l.port == *port))
            .collect();
        for port in closed {
            table.withdraw_listened(&self.session_name, port);
            self.listened.remove(&port);
        }
        self.refused
            .retain(|port| seen.iter().any(|l| l.port == *port));
    }

    /// Watches the box until `cancel` fires or its socket table can no longer
    /// be read — which is how the box going away ends the watch.
    ///
    /// The publications this watcher made are withdrawn on the way out, so a
    /// cancelled watch leaves no listened port published behind it. A box
    /// withdrawn from the table altogether has already taken them with it.
    pub async fn run(mut self, source: impl Listeners, cancel: CancellationToken) {
        let mut ticks = tokio::time::interval(POLL_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = ticks.tick() => {}
            }
            match source.observe() {
                Ok(seen) => self.reconcile(&seen),
                Err(error) => {
                    tracing::debug!(
                        session = %self.session_name,
                        %error,
                        "stopped watching the box's listening ports"
                    );
                    break;
                }
            }
        }
        self.reconcile(&[]);
    }
}

/// The rules a box in `mode` meets its own listeners with, or `None` when no
/// listener in it could publish anything.
///
/// Port-on-listen is an own-address box's permit range: NET-016 covers the
/// ports a permit range allows and no declaration names (NET-121), and an
/// ingress declaration is own-address only — launch validation refuses one
/// anywhere else — so a permit range exists nowhere else either. An
/// own-address box without a range permits only what its declaration names,
/// and those ports are bound and published before its name is, so there is
/// nothing for a watch to add. A `none` box has no network to publish on.
///
/// A box that carries the host's address is not watched: it shares the host's
/// network namespace, so its socket table is the node's and holds the host's
/// own listeners — the daemon's, the answerer's, every sibling box's bound
/// forwarder — which `/proc` gives no way to tell from "a process in it". Its
/// own listeners answer at the node's address already (NET-129), so the watch
/// would add nothing but other processes' ports published under the box's
/// name.
#[must_use]
pub fn watched_rules(
    mode: sessions::NetworkMode,
    ingress: Option<&sessions::IngressPolicy>,
) -> Option<IngressRules> {
    match mode {
        sessions::NetworkMode::OwnIp
            if ingress.is_some_and(|i| i.dynamic_allowed_range.is_some()) =>
        {
            Some(IngressRules::for_box_listeners(ingress))
        }
        _ => None,
    }
}

/// A watch running for a live box, ended with it: it wraps the box's own
/// network teardown so the watch stops, and its publications are withdrawn,
/// before the box's network goes away.
pub struct WatchGuard {
    inner: Option<Box<dyn sandbox2::NetGuard>>,
    cancel: CancellationToken,
    watching: tokio::task::JoinHandle<()>,
}

impl WatchGuard {
    /// Starts the watch on the box `container_pid` supervises and wraps
    /// `inner`, the box's own network teardown, in the guard that ends it.
    ///
    /// `inner` comes back as it was when nothing in the box could publish a
    /// port ([`watched_rules`]) — no watch is started and nothing polls.
    pub fn start(
        session_name: &str,
        mode: sessions::NetworkMode,
        ingress: Option<&sessions::IngressPolicy>,
        container_pid: u32,
        published: Arc<RwLock<PublishTable>>,
        inner: Option<Box<dyn sandbox2::NetGuard>>,
    ) -> Option<Box<dyn sandbox2::NetGuard>> {
        let Some(rules) = watched_rules(mode, ingress) else {
            return inner;
        };
        let cancel = CancellationToken::new();
        let watch = ListenWatch::new(session_name.to_string(), rules, published);
        let watching = tokio::spawn(watch.run(ProcListeners::new(container_pid), cancel.clone()));
        tracing::info!(
            session = %session_name,
            container_pid,
            "watching the box's listening ports; permitted ones publish themselves"
        );
        Some(Box::new(Self {
            inner,
            cancel,
            watching,
        }))
    }
}

impl sandbox2::NetGuard for WatchGuard {
    fn teardown(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            // Stopped first, and awaited: the watch withdraws what it
            // published as it ends, so nothing it published outlives the box.
            self.cancel.cancel();
            let _ = self.watching.await;
            if let Some(inner) = self.inner {
                inner.teardown().await;
            }
        })
    }
}

/// A box's listening ports as `/proc` shows them: the socket table of the
/// network namespace the box unshared, read through the container
/// supervisor's `/proc` entry, joined with the box's own open descriptors to
/// name the pid holding each listener.
///
/// A listener whose pid cannot be named — a descriptor the daemon may not read
/// — is attributed to the box's supervisor rather than dropped: the
/// publication is the point, and the pid is what the published-port table adds
/// to it.
pub struct ProcListeners {
    proc_root: PathBuf,
    /// The pid of the box's container supervisor, whose `/proc` entry names
    /// the namespace the box's sockets live in.
    container_pid: u32,
}

impl ProcListeners {
    /// The listeners of the box supervised by `container_pid`.
    #[must_use]
    pub fn new(container_pid: u32) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            container_pid,
        }
    }

    /// The same, reading a `/proc` rooted elsewhere: what the tests drive.
    #[cfg(test)]
    fn rooted_at(proc_root: PathBuf, container_pid: u32) -> Self {
        Self {
            proc_root,
            container_pid,
        }
    }

    /// The pids of the box's processes: its supervisor and the descendants
    /// `/proc/<pid>/task/<pid>/children` names, breadth-first and bounded.
    fn box_pids(&self) -> Vec<u32> {
        let mut pids = vec![self.container_pid];
        let mut next = 0;
        while next < pids.len() && pids.len() < PID_WALK_LIMIT {
            let pid = pids[next];
            next += 1;
            let children = self
                .proc_root
                .join(pid.to_string())
                .join("task")
                .join(pid.to_string())
                .join("children");
            let Ok(listed) = std::fs::read_to_string(children) else {
                continue;
            };
            for child in listed.split_whitespace().filter_map(|p| p.parse().ok()) {
                if !pids.contains(&child) {
                    pids.push(child);
                }
            }
        }
        pids
    }

    /// The pid holding each socket inode, read off the open descriptors of the
    /// box's processes. A descriptor that cannot be read is skipped.
    fn socket_owners(&self, pids: &[u32]) -> HashMap<u64, u32> {
        let mut owners = HashMap::new();
        for &pid in pids {
            let Ok(fds) = std::fs::read_dir(self.proc_root.join(pid.to_string()).join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                if let Some(inode) = socket_inode(&target.to_string_lossy()) {
                    owners.entry(inode).or_insert(pid);
                }
            }
        }
        owners
    }
}

impl Listeners for ProcListeners {
    fn observe(&self) -> io::Result<Vec<Listener>> {
        let net = self
            .proc_root
            .join(self.container_pid.to_string())
            .join("net");
        // IPv4 first, and strictly: its absence means the box's `/proc` entry
        // is gone, which ends the watch. A box with IPv6 disabled has no
        // `tcp6` table at all, so that one is read only if it is there.
        let mut sockets = listening_sockets(&std::fs::read_to_string(net.join("tcp"))?);
        if let Ok(table6) = std::fs::read_to_string(net.join("tcp6")) {
            sockets.extend(listening_sockets(&table6));
        }
        let owners = self.socket_owners(&self.box_pids());
        Ok(sockets
            .into_iter()
            .map(|(port, inode)| Listener {
                port,
                pid: owners.get(&inode).copied().unwrap_or(self.container_pid),
            })
            .collect())
    }
}

/// The `(port, socket inode)` of every listening row in a `/proc/net/tcp`
/// table: state `0A` is `TCP_LISTEN`, and the port is the hex half of the
/// local address. Every other row — an established connection, a socket in
/// teardown — carries no listener.
fn listening_sockets(table: &str) -> Vec<(u16, u64)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl, local_address, rem_address, st, ..., inode.
            let (local, state, inode) = (
                fields.get(1)?,
                *fields.get(3)?,
                fields.get(9)?.parse::<u64>().ok()?,
            );
            if state != "0A" {
                return None;
            }
            let port = u16::from_str_radix(local.split_once(':')?.1, 16).ok()?;
            Some((port, inode))
        })
        .collect()
}

/// The inode a `socket:[12345]` descriptor target names.
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::publish::{ForwarderState, PortOrigin, PublishedPort};
    use sessions::{IngressPolicy, IpProto, NetworkMode, PortMapping, SessionId};

    const BOX: &str = "web";

    /// A table holding `BOX`, published as an own-address box with `declared`
    /// as the box-side ports its declaration named.
    fn table_holding_box(declared: &[u16]) -> Arc<RwLock<PublishTable>> {
        let mut table = PublishTable::default();
        table
            .publish(SessionId::nil(), BOX, NetworkMode::OwnIp, declared)
            .expect("the reserved range has an address free");
        table.set_running(BOX, true);
        Arc::new(RwLock::new(table))
    }

    /// An ingress declaration: a permit range, plus a TCP mapping per declared
    /// port (host-side and box-side the same, as a box publishes its own port
    /// numbers).
    fn ingress(range: Option<(u16, u16)>, declared: &[u16]) -> IngressPolicy {
        IngressPolicy {
            port_mappings: declared
                .iter()
                .map(|&port| PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto: IpProto::Tcp,
                })
                .collect(),
            dynamic_allowed_range: range,
        }
    }

    fn watch(published: &Arc<RwLock<PublishTable>>, ingress: &IngressPolicy) -> ListenWatch {
        ListenWatch::new(
            BOX.to_string(),
            IngressRules::for_box_listeners(Some(ingress)),
            Arc::clone(published),
        )
    }

    /// The published-port table for `BOX`, as a diagnostics bundle reads it.
    fn ports_of(published: &RwLock<PublishTable>) -> Vec<PublishedPort> {
        let table = published.read().unwrap();
        let entries = table.entries();
        let entry = entries
            .iter()
            .find(|e| e.hostname == "web.min.internal")
            .expect("the box is published");
        entry.forwarders.clone()
    }

    /// The port numbers the zone publishes for `BOX`.
    fn zone_ports(published: &RwLock<PublishTable>) -> Vec<u16> {
        let table = published.read().unwrap();
        table
            .entries()
            .iter()
            .find(|e| e.hostname == "web.min.internal")
            .expect("the box is published")
            .ports
            .clone()
    }

    /// NET-016: a process listening on a port the box's permit range allows
    /// and no declaration names has that port published on the box's address,
    /// with the listener's pid, and no `--ingress` mapping was typed for it. A
    /// port the declaration already named keeps the publication it was bound
    /// with (NET-121) rather than being published a second time.
    #[test]
    fn listen_publishes_permitted_port() {
        let published = table_holding_box(&[8080]);
        let ingress = ingress(Some((9000, 9100)), &[8080]);
        let mut watch = watch(&published, &ingress);

        watch.reconcile(&[
            Listener {
                port: 9090,
                pid: 4321,
            },
            Listener {
                port: 8080,
                pid: 4322,
            },
        ]);

        assert_eq!(
            ports_of(&published),
            vec![
                PublishedPort {
                    port: 8080,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Declared,
                    admitted: None,
                },
                PublishedPort {
                    port: 9090,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Listened { pid: 4321 },
                    admitted: None,
                },
            ],
        );
        assert_eq!(
            zone_ports(&published),
            vec![8080, 9090],
            "the box's own port numbers, the listened one among them"
        );

        // The same observation again publishes nothing new: the port is
        // published once, for the listener that opened it.
        watch.reconcile(&[Listener {
            port: 9090,
            pid: 4321,
        }]);
        assert_eq!(
            ports_of(&published)
                .iter()
                .filter(|p| p.port == 9090)
                .count(),
            1
        );
    }

    /// NET-016's failure case: a listener on a port the box's rules do not
    /// permit is left unpublished — every port outside the permit range, and
    /// every port at all for a box that declared no range. Nothing partial is
    /// left behind: the zone publishes exactly what the declaration named.
    #[test]
    fn listen_on_undeclared_port_not_published() {
        for (range, unpermitted) in [
            (Some((9000, 9100)), vec![0, 1, 8999, 9101, 22, 65_535, 3000]),
            (None, vec![0, 22, 3000, 9090, 65_535]),
        ] {
            let published = table_holding_box(&[8080]);
            let ingress = ingress(range, &[8080]);
            let mut watch = watch(&published, &ingress);

            let seen: Vec<Listener> = unpermitted
                .iter()
                .map(|&port| Listener { port, pid: 77 })
                .collect();
            watch.reconcile(&seen);

            assert_eq!(
                ports_of(&published),
                vec![PublishedPort {
                    port: 8080,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Declared,
                    admitted: None,
                }],
                "a port the rules do not permit stays unpublished (range {range:?})"
            );
            assert_eq!(zone_ports(&published), vec![8080]);
        }
    }

    /// NET-017: when the listener behind a published port closes, its
    /// publication is withdrawn — the port leaves the zone and the
    /// published-port table — while the ports the declaration named stay
    /// published, since their forwarders are held until the box stops
    /// (NET-121).
    #[test]
    fn listener_close_withdraws_publication() {
        let published = table_holding_box(&[8080]);
        let ingress = ingress(Some((9000, 9100)), &[8080]);
        let mut watch = watch(&published, &ingress);

        watch.reconcile(&[
            Listener {
                port: 9090,
                pid: 4321,
            },
            Listener {
                port: 9091,
                pid: 4321,
            },
        ]);
        assert_eq!(zone_ports(&published), vec![8080, 9090, 9091]);

        // The server on 9090 exits; the one on 9091 is still listening.
        watch.reconcile(&[Listener {
            port: 9091,
            pid: 4321,
        }]);
        assert_eq!(zone_ports(&published), vec![8080, 9091]);
        assert_eq!(
            ports_of(&published),
            vec![
                PublishedPort {
                    port: 8080,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Declared,
                    admitted: None,
                },
                PublishedPort {
                    port: 9091,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Listened { pid: 4321 },
                    admitted: None,
                },
            ],
        );

        // Both close: only the declared port is left published.
        watch.reconcile(&[]);
        assert_eq!(zone_ports(&published), vec![8080]);
        assert_eq!(
            ports_of(&published),
            vec![PublishedPort {
                port: 8080,
                state: ForwarderState::Direct,
                origin: PortOrigin::Declared,
                admitted: None,
            }],
        );

        // A listener that opens again is published again, for its new pid.
        watch.reconcile(&[Listener {
            port: 9090,
            pid: 9999,
        }]);
        assert_eq!(
            ports_of(&published)
                .into_iter()
                .find(|p| p.port == 9090)
                .map(|p| p.origin),
            Some(PortOrigin::Listened { pid: 9999 }),
        );
    }

    /// Only a box a listener could publish a port in is watched: an
    /// own-address box that declared a permit range, and nothing else. An
    /// own-address box with no range permits nothing beyond what its
    /// declaration already published, a `none` box has no network to publish
    /// on, and a host-address box shares the host's network namespace — its
    /// socket table is the node's, so a watch on it would publish the host's
    /// own listeners under the box's name.
    #[test]
    fn only_a_box_that_could_publish_is_watched() {
        let ranged = ingress(Some((9000, 9100)), &[8080]);
        let declared_only = ingress(None, &[8080]);

        assert_eq!(
            watched_rules(NetworkMode::OwnIp, Some(&ranged)),
            Some(IngressRules::for_box_listeners(Some(&ranged)))
        );
        assert_eq!(
            watched_rules(NetworkMode::OwnIp, Some(&declared_only)),
            None
        );
        assert_eq!(watched_rules(NetworkMode::OwnIp, None), None);
        assert_eq!(watched_rules(NetworkMode::NoNet, None), None);
        assert_eq!(watched_rules(NetworkMode::HostNet, None), None);
        assert_eq!(
            watched_rules(NetworkMode::HostNet, Some(&ranged)),
            None,
            "a host-address box is never watched, whatever it is handed: its \
             socket table is the node's"
        );
    }

    /// The `/proc` reader takes the listening rows of a socket table and
    /// nothing else: an established connection carries no listener, and the
    /// port and socket inode are read off the row the kernel writes.
    #[test]
    fn proc_table_lists_listening_sockets_only() {
        let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000  00000000  1000        0 41001 1 0000 100
   1: 0100007F:238C 0100007F:C9B2 01 00000000:00000000 00:00000000  00000000  1000        0 41002 1 0000 100
   2: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000  00000000  1000        0 41003 1 0000 100
";
        assert_eq!(
            listening_sockets(table),
            vec![(8080, 41_001), (9090, 41_003)]
        );
        assert!(listening_sockets("").is_empty());
        assert_eq!(socket_inode("socket:[41001]"), Some(41_001));
        assert_eq!(socket_inode("/dev/null"), None);
    }

    /// The `/proc`-backed source reads the namespace's socket table through
    /// the supervisor's entry and names each listener's pid from the open
    /// descriptors of the box's own processes; a socket no descriptor claims is
    /// attributed to the supervisor.
    #[test]
    fn proc_listeners_name_the_pid_holding_each_listener() {
        let root = tempfile::tempdir().expect("a temp dir");
        let proc = root.path().to_path_buf();
        let write = |path: std::path::PathBuf, body: &str| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        };
        write(
            proc.join("100").join("net").join("tcp"),
            "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000  00000000  1000        0 41001 1 0000 100
   1: 0100007F:238C 00000000:0000 0A 00000000:00000000 00:00000000  00000000  1000        0 41002 1 0000 100
",
        );
        write(
            proc.join("100").join("task").join("100").join("children"),
            "101 ",
        );
        write(
            proc.join("101").join("task").join("101").join("children"),
            "",
        );
        let fds = proc.join("101").join("fd");
        std::fs::create_dir_all(&fds).unwrap();
        std::os::unix::fs::symlink("socket:[41001]", fds.join("3")).unwrap();

        let mut seen = ProcListeners::rooted_at(proc, 100)
            .observe()
            .expect("the table is readable");
        seen.sort_by_key(|l| l.port);
        assert_eq!(
            seen,
            vec![
                Listener {
                    port: 8080,
                    pid: 101
                },
                Listener {
                    port: 9100,
                    pid: 100
                },
            ]
        );
    }
}
