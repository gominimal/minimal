//! The published-box table: the box zone the host answerer serves, and the
//! address each box is published at (NET-010 to NET-013, NET-128, NET-129).
//!
//! A box is published when its session is finalised and withdrawn when it is
//! destroyed, so its name answers for that whole span whether or not a client
//! is attached (NET-011 to NET-013). Where a box is published depends on its
//! address mode:
//!
//! - An own-address or `none` box gets a host loopback address of its own,
//!   leased from the reserved local range by the host-wide
//!   [`LoopbackAllocator`], and its ports are published at the box's own
//!   port numbers (NET-010). The lease lasts from finalize to destroy, so the
//!   name answers the address even while the box is not running.
//! - A host-address box shares its node's published loopback address
//!   (`127.0.0.1` on a native node; NET-129), at its own port numbers. Two
//!   such boxes publishing the same port collide: the collision is reported
//!   at session start (a warn line) and in listings, and neither port is
//!   translated. While a shared-address box is not running its name answers
//!   NODATA (NET-128): the name stays in the zone, so the host resolver
//!   caches no name-wide negative for it.
//!
//! The table is separate from the proxy's
//! [`HostnameRegistry`](super::dns::HostnameRegistry): that one routes a
//! `Host:` header to where the proxy forwards, this one says what a native
//! lookup of the name answers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, PoisonError, RwLock};

use serde::Serialize;
use sessions::core::loopback_alloc::{LoopbackAllocator, RangeExhausted};
use sessions::{NetworkMode, SessionId};
use tokio::sync::Notify;

use super::dns::HOSTNAME_SUFFIX;

/// Which address a box is published at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressKind {
    /// A loopback address of the box's own, leased from the reserved range.
    Own,
    /// The node's published loopback address, shared with every other
    /// host-address box on the node.
    Shared,
}

/// Two boxes on one shared address publishing the same port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortCollision {
    pub port: u16,
    /// The other box's name.
    pub with: String,
}

/// What [`PublishTable::publish`] settled for a box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// The box's name in the zone: `<name>.min.internal`.
    pub hostname: String,
    pub address: Ipv4Addr,
    pub kind: AddressKind,
    /// The box's own port numbers, published untranslated.
    pub ports: Vec<u16>,
    /// The ports another box on the same shared address also publishes.
    pub collisions: Vec<PortCollision>,
}

/// One published box, as the zone dump and listings see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishedBox {
    pub hostname: String,
    pub session_id: SessionId,
    pub address: Ipv4Addr,
    pub kind: AddressKind,
    /// The lease state the answerer acts on: an own-address box holds its
    /// address either way; a shared-address box answers only while running.
    pub running: bool,
    pub ports: Vec<u16>,
    pub collisions: Vec<PortCollision>,
}

/// What the zone answers for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A box holds the name and it answers `address`.
    Address(IpAddr),
    /// A box holds the name but answers no address right now: a
    /// shared-address box that is not running (NET-128). NODATA.
    Held,
    /// No box holds the name (NET-012, NET-125). NXDOMAIN.
    Unknown,
}

/// The read side of the zone, for the answerer.
pub trait Zone: Send + Sync + 'static {
    /// What `name` (lower-cased, no trailing dot) answers.
    fn lookup(&self, name: &str) -> Lookup;
}

#[derive(Debug, Clone)]
struct Entry {
    session_id: SessionId,
    address: Ipv4Addr,
    kind: AddressKind,
    ports: Vec<u16>,
    running: bool,
}

/// The table of published boxes: the host-wide address allocator plus every
/// live publication, keyed by hostname.
#[derive(Debug)]
pub struct PublishTable {
    /// The node's own published loopback address, which every host-address
    /// box mirrors (NET-129).
    node_address: Ipv4Addr,
    allocator: LoopbackAllocator,
    boxes: HashMap<String, Entry>,
    /// Pinged after every change so the answerer can rewrite its zone dump
    /// without polling.
    changes: Arc<Notify>,
}

impl Default for PublishTable {
    /// A table for a native node, whose address is `127.0.0.1`.
    fn default() -> Self {
        Self::new(Ipv4Addr::LOCALHOST)
    }
}

/// The zone name for a session name: `<name>.min.internal`, lower-cased as
/// DNS names are compared.
fn hostname(session_name: &str) -> String {
    format!("{session_name}.{HOSTNAME_SUFFIX}").to_ascii_lowercase()
}

impl PublishTable {
    /// An empty table for a node published at `node_address`.
    #[must_use]
    pub fn new(node_address: Ipv4Addr) -> Self {
        Self {
            node_address,
            allocator: LoopbackAllocator::new(),
            boxes: HashMap::new(),
            changes: Arc::new(Notify::new()),
        }
    }

    /// The node's published loopback address.
    #[must_use]
    pub fn node_address(&self) -> Ipv4Addr {
        self.node_address
    }

    /// A handle notified after every change to the table. `notify_one`
    /// stores a permit when nobody is waiting, so a change is never lost
    /// between two waits.
    #[must_use]
    pub fn changes(&self) -> Arc<Notify> {
        Arc::clone(&self.changes)
    }

    /// Publishes `session_name`'s box: leases it an address of its own for
    /// an own-address or `none` box, or mirrors the node's address for a
    /// host-address box, and records `ports` (the box's own port numbers)
    /// untranslated. A box already published under the name is withdrawn
    /// first, so a re-publish never leaks a lease.
    ///
    /// Logs one info line for the lease and one warn line per shared-address
    /// port collision.
    ///
    /// # Errors
    ///
    /// [`RangeExhausted`] when an own address is needed and the reserved
    /// range has none free.
    pub fn publish(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        mode: NetworkMode,
        ports: &[u16],
    ) -> Result<Publication, RangeExhausted> {
        let hostname = hostname(session_name);
        self.withdraw(session_name);
        let (address, kind) = match mode {
            NetworkMode::HostNet => (self.node_address, AddressKind::Shared),
            _ => (self.allocator.allocate()?, AddressKind::Own),
        };
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();
        self.boxes.insert(
            hostname.clone(),
            Entry {
                session_id,
                address,
                kind,
                ports: ports.clone(),
                running: false,
            },
        );
        self.changes.notify_one();
        tracing::info!(
            session_id = %session_id,
            hostname = %hostname,
            address = %address,
            kind = ?kind,
            ?ports,
            "leased a published address to a box"
        );
        let collisions = self.collisions_of(&hostname);
        for collision in &collisions {
            tracing::warn!(
                hostname = %hostname,
                port = collision.port,
                with = %collision.with,
                address = %address,
                "two boxes on the shared address publish the same port; neither is translated"
            );
        }
        Ok(Publication {
            hostname,
            address,
            kind,
            ports,
            collisions,
        })
    }

    /// Withdraws `session_name`'s box, releasing its own address if it held
    /// one. Returns the address it was published at, or `None` when nothing
    /// was published under the name. Logs one info line for a released
    /// lease.
    pub fn withdraw(&mut self, session_name: &str) -> Option<Ipv4Addr> {
        let hostname = hostname(session_name);
        let entry = self.boxes.remove(&hostname)?;
        if entry.kind == AddressKind::Own {
            self.allocator.release(entry.address);
        }
        self.changes.notify_one();
        tracing::info!(
            session_id = %entry.session_id,
            hostname = %hostname,
            address = %entry.address,
            kind = ?entry.kind,
            "released a box's published address"
        );
        Some(entry.address)
    }

    /// Records whether `session_name`'s box is running. Returns `false` when
    /// nothing is published under the name.
    pub fn set_running(&mut self, session_name: &str, running: bool) -> bool {
        let Some(entry) = self.boxes.get_mut(&hostname(session_name)) else {
            return false;
        };
        if entry.running != running {
            entry.running = running;
            self.changes.notify_one();
        }
        true
    }

    /// The ports `hostname`'s box shares with other boxes on the same shared
    /// address. Empty for an own-address box: nothing else is at its address.
    fn collisions_of(&self, hostname: &str) -> Vec<PortCollision> {
        let Some(entry) = self.boxes.get(hostname) else {
            return Vec::new();
        };
        if entry.kind != AddressKind::Shared {
            return Vec::new();
        }
        let mut collisions: Vec<PortCollision> = self
            .boxes
            .iter()
            .filter(|(other, e)| other.as_str() != hostname && e.kind == AddressKind::Shared)
            .flat_map(|(other, e)| {
                e.ports
                    .iter()
                    .filter(|port| entry.ports.contains(port))
                    .map(|port| PortCollision {
                        port: *port,
                        with: other.clone(),
                    })
            })
            .collect();
        collisions.sort_by(|a, b| (a.port, &a.with).cmp(&(b.port, &b.with)));
        collisions
    }

    /// Every published box, by hostname, with its collisions marked.
    pub fn entries(&self) -> Vec<PublishedBox> {
        let mut boxes: Vec<PublishedBox> = self
            .boxes
            .iter()
            .map(|(hostname, e)| PublishedBox {
                hostname: hostname.clone(),
                session_id: e.session_id,
                address: e.address,
                kind: e.kind,
                running: e.running,
                ports: e.ports.clone(),
                collisions: self.collisions_of(hostname),
            })
            .collect();
        boxes.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        boxes
    }
}

impl Zone for PublishTable {
    fn lookup(&self, name: &str) -> Lookup {
        match self.boxes.get(name) {
            None => Lookup::Unknown,
            Some(e) if e.kind == AddressKind::Shared && !e.running => Lookup::Held,
            Some(e) => Lookup::Address(IpAddr::V4(e.address)),
        }
    }
}

// The daemon shares the table behind an `RwLock` (the session actors publish
// and withdraw under `&mut self`; the answerer only reads it, synchronously).
impl Zone for RwLock<PublishTable> {
    fn lookup(&self, name: &str) -> Lookup {
        // A poisoned lock is recovered rather than answered NXDOMAIN: the
        // table holds no cross-field invariant a panicked writer could
        // half-break, and a silent NXDOMAIN would be cached name-wide.
        self.read()
            .unwrap_or_else(PoisonError::into_inner)
            .lookup(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// NET-010: each own-address or `none` box is published at a loopback
    /// address of its own from the reserved range, at its own port numbers,
    /// so two boxes listening on the same port answer at two addresses.
    #[test]
    fn each_box_gets_own_loopback_address() {
        let mut table = PublishTable::default();
        let web = table
            .publish(SessionId::nil(), "web", NetworkMode::OwnIp, &[3000])
            .unwrap();
        let api = table
            .publish(
                SessionId::nil(),
                "api",
                NetworkMode::OwnIp,
                &[3000, 3000, 80],
            )
            .unwrap();
        let quiet = table
            .publish(SessionId::nil(), "quiet", NetworkMode::NoNet, &[])
            .unwrap();

        for published in [&web, &api, &quiet] {
            assert_eq!(published.kind, AddressKind::Own);
            assert!(LoopbackAllocator::in_range(published.address));
            assert!(published.collisions.is_empty(), "{published:?}");
        }
        assert_ne!(web.address, api.address);
        assert_ne!(api.address, quiet.address);
        assert_ne!(web.address, quiet.address);
        assert_eq!(web.ports, vec![3000]);
        assert_eq!(api.ports, vec![80, 3000], "own port numbers, deduplicated");

        assert_eq!(
            table.lookup("web.min.internal"),
            Lookup::Address(IpAddr::V4(web.address))
        );
        assert_eq!(
            table.lookup("api.min.internal"),
            Lookup::Address(IpAddr::V4(api.address))
        );
        // An own address answers whether or not the box runs.
        assert!(table.set_running("web", true));
        assert!(table.set_running("web", false));
        assert_eq!(
            table.lookup("web.min.internal"),
            Lookup::Address(IpAddr::V4(web.address))
        );

        // Withdrawing releases the lease; a later box may take the address,
        // but never while the first is live.
        assert_eq!(table.withdraw("web"), Some(web.address));
        assert_eq!(table.lookup("web.min.internal"), Lookup::Unknown);
        let again = table
            .publish(SessionId::nil(), "again", NetworkMode::OwnIp, &[])
            .unwrap();
        assert_eq!(again.address, web.address);
        assert_ne!(again.address, api.address);
    }

    /// NET-129: a host-address box answers its node's published loopback
    /// address at its own port numbers — `127.0.0.1` on a native node, the
    /// node's allocated address on a VM node.
    #[test]
    fn host_ip_box_answers_node_loopback_address() {
        for node in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 64, 9)] {
            let mut table = PublishTable::new(node);
            let shared = table
                .publish(SessionId::nil(), "shared", NetworkMode::HostNet, &[8080])
                .unwrap();
            assert_eq!(shared.kind, AddressKind::Shared);
            assert_eq!(shared.address, node);
            assert_eq!(shared.ports, vec![8080]);
            assert!(table.set_running("shared", true));
            assert_eq!(
                table.lookup("shared.min.internal"),
                Lookup::Address(IpAddr::V4(node))
            );
            // Its lease is the node's, so withdrawing releases nothing from
            // the range and the next own-address box still gets the first
            // free address.
            assert_eq!(table.withdraw("shared"), Some(node));
            let own = table
                .publish(SessionId::nil(), "own", NetworkMode::OwnIp, &[])
                .unwrap();
            assert_eq!(own.address, Ipv4Addr::new(127, 0, 64, 1));
        }
    }

    /// NET-128: a shared-address box that is not running answers NODATA —
    /// the name is held, so the resolver caches no name-wide negative — and
    /// answers the address again once it runs.
    #[test]
    fn stopped_shared_address_box_is_nodata() {
        let mut table = PublishTable::default();
        table
            .publish(SessionId::nil(), "shared", NetworkMode::HostNet, &[])
            .unwrap();
        assert_eq!(table.lookup("shared.min.internal"), Lookup::Held);
        assert!(table.set_running("shared", true));
        assert_eq!(
            table.lookup("shared.min.internal"),
            Lookup::Address(v4(127, 0, 0, 1))
        );
        assert!(table.set_running("shared", false));
        assert_eq!(table.lookup("shared.min.internal"), Lookup::Held);
        assert!(!table.set_running("ghost", true), "nothing published");
        assert_eq!(table.lookup("ghost.min.internal"), Lookup::Unknown);
    }

    /// NET-129: two boxes on one shared address publishing the same port are
    /// reported — at publish, and in every listing — and neither port is
    /// translated. An own-address box on the same port collides with nothing.
    #[test]
    fn shared_address_port_collision_reported_not_translated() {
        let mut table = PublishTable::default();
        let first = table
            .publish(
                SessionId::nil(),
                "first",
                NetworkMode::HostNet,
                &[3000, 9229],
            )
            .unwrap();
        assert!(first.collisions.is_empty(), "nothing to collide with yet");
        let own = table
            .publish(SessionId::nil(), "own", NetworkMode::OwnIp, &[3000])
            .unwrap();
        assert!(own.collisions.is_empty(), "its own address: no collision");
        let second = table
            .publish(
                SessionId::nil(),
                "second",
                NetworkMode::HostNet,
                &[3000, 4000],
            )
            .unwrap();

        // Reported at session start, naming the port and the other box.
        assert_eq!(
            second.collisions,
            vec![PortCollision {
                port: 3000,
                with: "first.min.internal".to_string()
            }]
        );
        // Neither port is translated: both boxes still publish 3000 at the
        // one shared address.
        assert_eq!(first.address, second.address);
        assert_eq!(first.ports, vec![3000, 9229]);
        assert_eq!(second.ports, vec![3000, 4000]);

        // Marked in the listing for both boxes, and for neither other.
        let entries = table.entries();
        let by_name = |name: &str| {
            entries
                .iter()
                .find(|e| e.hostname == format!("{name}.min.internal"))
                .unwrap()
        };
        assert_eq!(
            by_name("first").collisions,
            vec![PortCollision {
                port: 3000,
                with: "second.min.internal".to_string()
            }]
        );
        assert_eq!(by_name("second").collisions.len(), 1);
        assert!(by_name("own").collisions.is_empty());

        // Gone once one side withdraws.
        table.withdraw("first");
        assert!(table.entries().iter().all(|e| e.collisions.is_empty()));
    }
}
