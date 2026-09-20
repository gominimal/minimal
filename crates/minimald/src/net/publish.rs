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
//!
//! A box's declared ports are bound before its name is registered (NET-121):
//! the caller [leases](PublishTable::lease) the address first, binds a
//! [`Forwarders`] set on it, and only then [registers](PublishTable::register)
//! the name — so a name never answers ahead of the ports it promises, and a
//! connection to a declared port nothing is listening on yet is refused by the
//! box rather than timed out at the host (NET-014).
//!
//! A port no declaration names cannot be bound ahead of a listener, so there
//! the publication follows the listener instead: a process in the box that
//! begins listening on a port the box's rules permit has that port
//! [published](PublishTable::publish_listened) at the box's own number
//! (NET-016), and closing the listener
//! [withdraws](PublishTable::withdraw_listened) it (NET-017). The
//! published-port table marks each entry with its [`PortOrigin`], so a
//! diagnostics bundle says which ports a declaration named and which a
//! listener published, with the listener's pid; a port published by
//! `min net expose` carries the [`DynamicIngress`] decision that admitted it.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use serde::Serialize;
use sessions::core::loopback_alloc::{LoopbackAllocator, RangeExhausted};
use sessions::{DynamicIngress, IpProto, NetworkMode, SessionId};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

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

/// How a declared port is answered at the box's published address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAnswer {
    /// A forwarder bound on the box's own address, sending what it accepts to
    /// this upstream — the host-side forward the box's switch publishes for
    /// the port.
    Forwarded(SocketAddr),
    /// Published with no forwarder interposed: on a shared address the box's
    /// own listeners answer its port numbers, so binding there would take the
    /// port from the box itself, and a UDP mapping's datagrams are carried by
    /// the switch forward rather than by a connection-oriented forwarder.
    Direct,
}

/// One port a box's ingress declaration names: the box's own port number, as
/// the zone publishes it, and how the box answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredPort {
    /// The box's own port number.
    pub port: u16,
    /// How the port is answered at the box's published address.
    pub answer: PortAnswer,
}

/// How a port mapped to host port `external_port` is answered at a box
/// published at a `kind` address: forwarded to the host-side port the switch
/// publishes for it on an own address over TCP, and answered directly
/// everywhere else — on a shared address the box's own listeners answer its
/// port numbers, so binding there would take the port from the box itself,
/// and a UDP mapping's datagrams are carried by the switch forward rather
/// than by a connection-oriented forwarder.
#[must_use]
pub fn port_answer(kind: AddressKind, proto: IpProto, external_port: u16) -> PortAnswer {
    match (kind, proto) {
        (AddressKind::Own, IpProto::Tcp) => {
            PortAnswer::Forwarded(SocketAddr::from((Ipv4Addr::LOCALHOST, external_port)))
        }
        _ => PortAnswer::Direct,
    }
}

/// What holds a published port, as the published-port table shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwarderState {
    /// A forwarder is bound on the box's address and holding it.
    Bound,
    /// The port's ingress was revoked: its forwarder is unbound and the
    /// connections it held were terminated.
    Revoked,
    /// The box's own listener answers the port; no forwarder was interposed.
    Direct,
}

/// Why a port is published: the box's declaration named it, or a process in
/// the box began listening on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortOrigin {
    /// An ingress declaration names the port, so its forwarder was bound
    /// before the box's name was registered (NET-121).
    Declared,
    /// A process in the box began listening on the port and the box's rules
    /// permit it, so it was published then (NET-016). Carries the listener's
    /// pid as the daemon sees it.
    Listened { pid: u32 },
}

/// One published port and what holds it: the published-port table the
/// diagnostics bundle carries, where a revoked port stays visible as the
/// revocation that closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PublishedPort {
    /// The box's own port number.
    pub port: u16,
    /// What holds it.
    pub state: ForwarderState,
    /// Whether a declaration named the port or a listener published it.
    pub origin: PortOrigin,
    /// The dynamic ingress decision that admitted the port, for one published
    /// at runtime by `min net expose` (NET-044); `None` for a declared or
    /// listened port.
    pub admitted: Option<DynamicIngress>,
}

/// A declared port whose forwarder could not bind (NET-121). Reported with the
/// reason; nothing is substituted for it — not another port, not another
/// address, and not the box's name.
#[derive(Debug)]
pub struct BindFailure {
    /// The declared port whose forwarder could not bind.
    pub port: u16,
    /// The box's published address, which the forwarder would have bound on.
    pub address: Ipv4Addr,
    /// Why the bind failed.
    pub error: io::Error,
}

impl fmt::Display for BindFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not bind the forwarder for declared port {} on {}: {}",
            self.port, self.address, self.error
        )
    }
}

/// One bound forwarder: the accept loop owning the listener and every
/// connection through it, and the token that ends both.
#[derive(Debug)]
struct Forwarder {
    port: u16,
    cancel: CancellationToken,
    serving: JoinHandle<()>,
}

impl Drop for Forwarder {
    /// Unbinds the port and ends its connections when the publication goes
    /// away without an explicit revocation — the box stopped, the name was
    /// re-published, or a later port in the same set failed to bind. The
    /// accept loop owns the listener and the connection tasks, so cancelling
    /// it releases both.
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A box's declared ports, with a forwarder bound for each one a forwarder is
/// interposed on (NET-121).
///
/// A box is registered in the table with this in hand, so no name is
/// registered before its declared ports are bound. The set holds its
/// forwarders until it is dropped — at withdraw, when the box stops — or until
/// a port's ingress is [revoked](PublishTable::revoke_port).
#[derive(Debug, Default)]
pub struct Forwarders {
    /// The forwarders bound, one per [`PortAnswer::Forwarded`] port.
    bound: Vec<Forwarder>,
    /// Every declared port and what holds it, in port order.
    ports: Vec<PublishedPort>,
}

impl Forwarders {
    /// Binds a forwarder on `address` for each declared port answered by one,
    /// in port order, and records the rest as published directly.
    ///
    /// A held port is reported, never swapped for another: no second address
    /// and no OS-chosen port is tried, and the forwarders already bound are
    /// released before the failure returns, so a half-bound box is never
    /// published.
    ///
    /// Logs one info line per bind and one error line per failed bind, each
    /// naming the port.
    ///
    /// # Errors
    ///
    /// [`BindFailure`] for the first declared port whose forwarder cannot
    /// bind, carrying the reason.
    pub async fn bind(address: Ipv4Addr, declared: &[DeclaredPort]) -> Result<Self, BindFailure> {
        let mut declared = declared.to_vec();
        declared.sort_unstable_by_key(|d| d.port);
        declared.dedup_by_key(|d| d.port);

        let mut forwarders = Self::default();
        for DeclaredPort { port, answer } in declared {
            let PortAnswer::Forwarded(upstream) = answer else {
                forwarders.ports.push(PublishedPort {
                    port,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Declared,
                    admitted: None,
                });
                continue;
            };
            let listener = match TcpListener::bind(SocketAddr::new(IpAddr::V4(address), port)).await
            {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::error!(
                        %address,
                        port,
                        %error,
                        "could not bind a declared port's forwarder"
                    );
                    // `forwarders` drops here, unbinding what it had bound.
                    return Err(BindFailure {
                        port,
                        address,
                        error,
                    });
                }
            };
            let cancel = CancellationToken::new();
            let serving = tokio::spawn(serve_forward(listener, upstream, port, cancel.clone()));
            tracing::info!(
                %address,
                port,
                %upstream,
                "bound a declared port's forwarder"
            );
            forwarders.bound.push(Forwarder {
                port,
                cancel,
                serving,
            });
            forwarders.ports.push(PublishedPort {
                port,
                state: ForwarderState::Bound,
                origin: PortOrigin::Declared,
                admitted: None,
            });
        }
        Ok(forwarders)
    }

    /// Marks every port in the set as admitted by `decision`: what a set bound
    /// for a `min net expose` request carries into the published-port table,
    /// so a dynamic entry shows the decision that admitted it.
    #[must_use]
    pub fn admitted_by(mut self, decision: DynamicIngress) -> Self {
        for published in &mut self.ports {
            published.admitted = Some(decision);
        }
        self
    }

    /// Adds `other`'s forwarders and ports to this set, keeping the ports in
    /// port order. A port already in the set is left as it was and `other`'s
    /// forwarder for it is dropped, which unbinds it.
    fn extend(&mut self, other: Self) {
        let Self { mut bound, ports } = other;
        for published in ports {
            if self.ports.iter().any(|p| p.port == published.port) {
                continue;
            }
            self.ports.push(published);
            if let Some(index) = bound.iter().position(|f| f.port == published.port) {
                self.bound.push(bound.remove(index));
            }
        }
        self.ports.sort_unstable_by_key(|p| p.port);
        // What is left in `bound` forwards a port this set already held; it
        // drops here, which unbinds it.
    }

    /// Takes `port` out of the set altogether — its forwarder, if one is
    /// bound, and its listing — as if it had never been published. What a
    /// failed dynamic publication is rolled back with, so no partial mapping
    /// is left (NET-047). Returns the teardown to await, or `None` when no
    /// forwarder was bound for the port.
    fn remove(&mut self, port: u16) -> Option<Unbinding> {
        self.ports.retain(|p| p.port != port);
        self.take(port)
    }

    /// The declared ports of a box whose published address answers them
    /// itself, with no forwarder interposed: a host-address box, and the
    /// `127.0.0.1` interim (NET-123), where every box shares the one address.
    #[must_use]
    pub fn direct(ports: &[u16]) -> Self {
        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();
        Self {
            bound: Vec::new(),
            ports: ports
                .into_iter()
                .map(|port| PublishedPort {
                    port,
                    state: ForwarderState::Direct,
                    origin: PortOrigin::Declared,
                    admitted: None,
                })
                .collect(),
        }
    }

    /// The box's own port numbers, in order: what the zone publishes.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        self.ports.iter().map(|p| p.port).collect()
    }

    /// Every declared port with what holds it, for the published-port table.
    #[must_use]
    pub fn published(&self) -> Vec<PublishedPort> {
        self.ports.clone()
    }

    /// Unbinds every forwarder in the set and waits until each is: the
    /// rollback of a set bound for a request that was then refused, so
    /// nothing of it is left at the address once the refusal is answered
    /// (NET-047). A drop would unbind them too, but only once their accept
    /// loops observe it.
    pub async fn unbind(mut self) {
        for port in self.ports() {
            if let Some(unbinding) = self.take(port) {
                unbinding.finished().await;
            }
        }
    }

    /// Cancels the forwarder bound for `port` and takes it out of the set,
    /// which unbinds the port and terminates the connections it held. The half
    /// a revocation and a withdrawal share.
    fn take(&mut self, port: u16) -> Option<Unbinding> {
        let index = self.bound.iter().position(|f| f.port == port)?;
        let forwarder = self.bound.remove(index);
        // Cancelled here, not left to the drop: [`Unbinding::finished`] waits
        // for the accept loop, which only ends once it is cancelled.
        forwarder.cancel.cancel();
        Some(Unbinding(forwarder))
    }

    /// Revokes `port`'s ingress: unbinds its forwarder, terminates the
    /// connections it held, and marks the port revoked in the published-port
    /// table. Returns the teardown to await, or `None` when no bound forwarder
    /// held the port.
    fn revoke(&mut self, port: u16) -> Option<Unbinding> {
        let unbinding = self.take(port)?;
        for published in &mut self.ports {
            if published.port == port {
                published.state = ForwarderState::Revoked;
            }
        }
        tracing::info!(
            port,
            "revoked a declared port's ingress: unbound its forwarder and ended its connections"
        );
        Some(unbinding)
    }

    /// Lists `port` as published because a process in the box began listening
    /// on it (NET-016), in port order and with no forwarder interposed: the
    /// box's own listener is what answers it, at the box's own port number.
    ///
    /// `false` when the port is already published — a declaration names it, or
    /// an earlier listener published it — which leaves what holds it alone.
    fn add_listened(&mut self, port: u16, pid: u32) -> bool {
        if self.ports.iter().any(|p| p.port == port) {
            return false;
        }
        let at = self.ports.partition_point(|p| p.port < port);
        self.ports.insert(
            at,
            PublishedPort {
                port,
                state: ForwarderState::Direct,
                origin: PortOrigin::Listened { pid },
                admitted: None,
            },
        );
        true
    }

    /// Takes a listened port back out, as its listener closes (NET-017).
    ///
    /// `false` when no listened publication holds the port: a declared port is
    /// never withdrawn here, because its forwarder is held for as long as the
    /// box runs whether anything is listening behind it or not (NET-121).
    fn remove_listened(&mut self, port: u16) -> bool {
        let Some(index) = self
            .ports
            .iter()
            .position(|p| p.port == port && matches!(p.origin, PortOrigin::Listened { .. }))
        else {
            return false;
        };
        self.ports.remove(index);
        true
    }

    /// Unbinds every forwarder the box holds, as the box stops. The ports stay
    /// listed as they were — nothing revoked them, the box went away — and
    /// each unbind is logged with its port.
    fn unbind_all(&mut self) -> Vec<Unbinding> {
        let ports: Vec<u16> = self.bound.iter().map(|f| f.port).collect();
        ports
            .into_iter()
            .filter_map(|port| {
                let unbinding = self.take(port)?;
                tracing::info!(port, "unbound a declared port's forwarder with its box");
                Some(unbinding)
            })
            .collect()
    }
}

/// A revoked forwarder's teardown, handed back so the caller can wait for the
/// port to be unbound with the table's lock released.
#[derive(Debug)]
#[must_use]
pub struct Unbinding(Forwarder);

impl Unbinding {
    /// Waits until the forwarder's accept loop has ended, which is when its
    /// listener is unbound and the connections it held are dropped.
    pub async fn finished(mut self) {
        let _ = (&mut self.0.serving).await;
    }
}

/// What withdrawing a box released: the address it was published at, and the
/// teardown of the forwarders it held.
#[derive(Debug)]
pub struct Withdrawn {
    /// The address the box was published at.
    pub address: Ipv4Addr,
    unbinding: Vec<Unbinding>,
}

impl Withdrawn {
    /// Waits until every forwarder the box held is unbound, so a box
    /// re-published at the address just released never races the listeners of
    /// the publication that held it.
    pub async fn finished(self) {
        for unbinding in self.unbinding {
            unbinding.finished().await;
        }
    }
}

/// Serves one declared port's forwarder: accepts on `listener` and sends each
/// connection to `upstream`, until `cancel` fires.
///
/// Cancellation drops the listener, which unbinds the port, and the set of
/// connection tasks, which terminates every connection the forwarder held.
async fn serve_forward(
    listener: TcpListener,
    upstream: SocketAddr,
    port: u16,
    cancel: CancellationToken,
) {
    let mut held = JoinSet::new();
    loop {
        // Reap the connections that finished on their own, so a long-lived
        // forwarder holds only live ones.
        while held.try_join_next().is_some() {}
        tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((client, peer)) => {
                    held.spawn(forward_connection(client, upstream, port, peer));
                }
                Err(error) => {
                    tracing::warn!(
                        port,
                        %error,
                        "a declared port's forwarder stopped accepting"
                    );
                    break;
                }
            },
        }
    }
}

/// Forwards one accepted connection to the box.
///
/// A box with nothing listening on the port refuses the connect, and the
/// refusal is passed straight on by closing the connection rather than holding
/// it open, so a client sees the box refuse rather than a host-side timeout
/// (NET-014).
async fn forward_connection(
    mut client: TcpStream,
    upstream: SocketAddr,
    port: u16,
    peer: SocketAddr,
) {
    match TcpStream::connect(upstream).await {
        Ok(mut box_side) => {
            if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut box_side).await {
                tracing::debug!(port, %peer, %error, "a forwarded connection ended with an error");
            }
        }
        Err(error) => {
            tracing::debug!(
                port,
                %peer,
                %upstream,
                %error,
                "the box refused a connection to a declared port"
            );
        }
    }
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
    /// Each published port with what holds it: the forwarder bound for it, the
    /// revocation that closed it, or the box's own listener.
    pub forwarders: Vec<PublishedPort>,
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

#[derive(Debug)]
struct Entry {
    session_id: SessionId,
    address: Ipv4Addr,
    kind: AddressKind,
    ports: Vec<u16>,
    running: bool,
    /// The box's declared-port forwarders, held for as long as the entry is:
    /// dropping it unbinds them (NET-121).
    forwarders: Forwarders,
}

/// The address a box will be published at, leased before its name is
/// registered so its declared ports can be bound on it first (NET-121).
///
/// Spent by [`PublishTable::register`], or handed back by
/// [`PublishTable::release`] when a forwarder cannot bind.
#[derive(Debug)]
#[must_use]
pub struct Lease {
    address: Ipv4Addr,
    kind: AddressKind,
}

impl Lease {
    /// The leased address, which the box's forwarders bind on.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Whether the address is the box's own or its node's shared one, which
    /// decides whether a forwarder is interposed on its ports at all.
    #[must_use]
    pub fn kind(&self) -> AddressKind {
        self.kind
    }
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
        self.withdraw(session_name);
        let lease = self.lease(mode)?;
        Ok(self.insert(session_id, session_name, lease, Forwarders::direct(ports)))
    }

    /// Publishes `session_name`'s box at `interim`, the `127.0.0.1` the host
    /// falls back to while the reserved local range is absent (NET-123).
    /// Every box shares that one address whatever its mode, so it is
    /// published as a shared-address box: the same port-collision rule and
    /// the same running gate apply, and nothing is leased from the range.
    pub fn publish_interim(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        interim: Ipv4Addr,
        ports: &[u16],
    ) -> Publication {
        self.withdraw(session_name);
        let lease = self.lease_interim(interim);
        self.insert(session_id, session_name, lease, Forwarders::direct(ports))
    }

    /// Leases the address a box in `mode` will be published at — one of its
    /// own for an own-address or `none` box, its node's for a host-address box
    /// — without registering any name for it.
    ///
    /// The lease comes first so the box's declared ports can be bound on the
    /// address before its name is registered (NET-121). The caller spends it
    /// with [`Self::register`], or hands it back with [`Self::release`] when a
    /// forwarder cannot bind.
    ///
    /// # Errors
    ///
    /// [`RangeExhausted`] when an own address is needed and the reserved
    /// range has none free.
    pub fn lease(&mut self, mode: NetworkMode) -> Result<Lease, RangeExhausted> {
        Ok(match mode {
            NetworkMode::HostNet => Lease {
                address: self.node_address,
                kind: AddressKind::Shared,
            },
            _ => Lease {
                address: self.allocator.allocate()?,
                kind: AddressKind::Own,
            },
        })
    }

    /// Leases `interim`, the `127.0.0.1` every box shares while the reserved
    /// local range is absent (NET-123), as a shared address.
    pub fn lease_interim(&mut self, interim: Ipv4Addr) -> Lease {
        Lease {
            address: interim,
            kind: AddressKind::Shared,
        }
    }

    /// Hands a lease back unspent, releasing an own address to the range. What
    /// a caller does when its box's declared ports could not be bound, so no
    /// name is registered for it.
    pub fn release(&mut self, lease: Lease) {
        if lease.kind == AddressKind::Own {
            self.allocator.release(lease.address);
        }
    }

    /// Registers `session_name`'s box at `lease`, with the forwarders already
    /// bound for its declared ports (NET-121), and records those ports (the
    /// box's own port numbers) untranslated. A box already published under the
    /// name is withdrawn first, so a re-publish never leaks a lease and never
    /// leaves the old publication's forwarders bound.
    ///
    /// Logs one info line for the publication and one warn line per
    /// shared-address port collision.
    pub fn register(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        lease: Lease,
        forwarders: Forwarders,
    ) -> Publication {
        self.withdraw(session_name);
        self.insert(session_id, session_name, lease, forwarders)
    }

    /// Where `session_name`'s box is published: its address and the kind of
    /// address it is, or `None` when nothing is published under the name. What
    /// a dynamic publication binds its forwarder on before the port is added.
    #[must_use]
    pub fn published_at(&self, session_name: &str) -> Option<(Ipv4Addr, AddressKind)> {
        let entry = self.boxes.get(&hostname(session_name))?;
        Some((entry.address, entry.kind))
    }

    /// Adds `forwarders`, already bound on the box's address, to
    /// `session_name`'s publication: the ports they hold join the ports the
    /// zone publishes for the box. A port the box already publishes is left
    /// as it was. Returns `false` — dropping the forwarders, which unbinds
    /// them — when nothing is published under the name any more.
    pub fn add_ports(&mut self, session_name: &str, forwarders: Forwarders) -> bool {
        let hostname = hostname(session_name);
        let Some(entry) = self.boxes.get_mut(&hostname) else {
            return false;
        };
        let added = forwarders.ports();
        entry.forwarders.extend(forwarders);
        entry.ports = entry.forwarders.ports();
        self.changes.notify_one();
        tracing::info!(
            session_id = %entry.session_id,
            hostname = %hostname,
            address = %entry.address,
            ports = ?added,
            "published ports at a box's address"
        );
        true
    }

    /// Takes `port` out of `session_name`'s publication as if it had never
    /// been published: unbinds its forwarder and drops its listing. The
    /// rollback of a dynamic publication whose record could not be written
    /// (NET-047). Returns the teardown to await with this table's lock
    /// released, or `None` when no forwarder was bound for the port.
    pub fn remove_port(&mut self, session_name: &str, port: u16) -> Option<Unbinding> {
        let entry = self.boxes.get_mut(&hostname(session_name))?;
        let unbinding = entry.forwarders.remove(port);
        entry.ports = entry.forwarders.ports();
        self.changes.notify_one();
        unbinding
    }

    /// Revokes a declared port's ingress on `session_name`'s box: unbinds its
    /// forwarder and terminates the connections it holds, leaving the port in
    /// the published-port table marked as the revocation that closed it.
    ///
    /// Returns the teardown for the caller to await with this table's lock
    /// released, or `None` when no bound forwarder held the port.
    pub fn revoke_port(&mut self, session_name: &str, port: u16) -> Option<Unbinding> {
        let entry = self.boxes.get_mut(&hostname(session_name))?;
        let unbinding = entry.forwarders.revoke(port)?;
        self.changes.notify_one();
        Some(unbinding)
    }

    /// Publishes `port` on `session_name`'s box because the process `pid` in it
    /// began listening there and the box's ingress rules permit the port
    /// (NET-016). The port is published at the box's own number, with no
    /// forwarder interposed: the listener behind it is what answers.
    ///
    /// `false` when nothing is published under the name, or when the port is
    /// published already — a declaration names it (its forwarder was bound
    /// before the name, NET-121), or an earlier listener published it.
    ///
    /// Logs one info line naming the port, the box and that the box's rules
    /// permitted it.
    pub fn publish_listened(&mut self, session_name: &str, port: u16, pid: u32) -> bool {
        let hostname = hostname(session_name);
        let Some(entry) = self.boxes.get_mut(&hostname) else {
            return false;
        };
        if !entry.forwarders.add_listened(port, pid) {
            return false;
        }
        entry.ports = entry.forwarders.ports();
        self.changes.notify_one();
        tracing::info!(
            hostname = %hostname,
            port,
            pid,
            permitted = true,
            "published a port a process in the box began listening on"
        );
        true
    }

    /// Withdraws a listened port from `session_name`'s box as its listener
    /// closes (NET-017).
    ///
    /// `false` when nothing is published under the name or no listened
    /// publication holds the port; a declared port is never withdrawn here,
    /// since its forwarder is held until the box stops (NET-121).
    ///
    /// Logs one info line naming the port and the box.
    pub fn withdraw_listened(&mut self, session_name: &str, port: u16) -> bool {
        let hostname = hostname(session_name);
        let Some(entry) = self.boxes.get_mut(&hostname) else {
            return false;
        };
        if !entry.forwarders.remove_listened(port) {
            return false;
        }
        entry.ports = entry.forwarders.ports();
        self.changes.notify_one();
        tracing::info!(
            hostname = %hostname,
            port,
            "withdrew a listened port's publication: its listener closed"
        );
        true
    }

    /// Records the publication and logs it, the tail every publish path
    /// shares.
    fn insert(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        lease: Lease,
        forwarders: Forwarders,
    ) -> Publication {
        let hostname = hostname(session_name);
        let Lease { address, kind } = lease;
        let ports = forwarders.ports();
        self.boxes.insert(
            hostname.clone(),
            Entry {
                session_id,
                address,
                kind,
                ports: ports.clone(),
                running: false,
                forwarders,
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
        Publication {
            hostname,
            address,
            kind,
            ports,
            collisions,
        }
    }

    /// Withdraws `session_name`'s box, releasing its own address if it held
    /// one and unbinding the forwarders it held for its declared ports — a
    /// forwarder is held until the box stops and no longer (NET-121). Returns
    /// what it released, or `None` when nothing was published under the name.
    /// Logs one info line for a released lease.
    ///
    /// The forwarders are cancelled here and torn down by their own tasks; a
    /// caller about to re-publish at the address just released awaits
    /// [`Withdrawn::finished`] first, so the new bind does not race the old
    /// listeners.
    pub fn withdraw(&mut self, session_name: &str) -> Option<Withdrawn> {
        let hostname = hostname(session_name);
        let mut entry = self.boxes.remove(&hostname)?;
        if entry.kind == AddressKind::Own {
            self.allocator.release(entry.address);
        }
        let unbinding = entry.forwarders.unbind_all();
        self.changes.notify_one();
        tracing::info!(
            session_id = %entry.session_id,
            hostname = %hostname,
            address = %entry.address,
            kind = ?entry.kind,
            "released a box's published address"
        );
        Some(Withdrawn {
            address: entry.address,
            unbinding,
        })
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
                forwarders: e.forwarders.published(),
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
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        assert_eq!(
            table.withdraw("web").map(|withdrawn| withdrawn.address),
            Some(web.address)
        );
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
            assert_eq!(
                table.withdraw("shared").map(|withdrawn| withdrawn.address),
                Some(node)
            );
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

    /// A loopback backend standing in for the box's own listener, echoing
    /// everything sent to it: what a declared port's forwarder reaches while
    /// the box is listening.
    async fn echo_backend() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => {
                                if stream.write_all(&buf[..read]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        address
    }

    /// Connects until `address:port` refuses, which an unbound port does at
    /// once. A forwarder's teardown runs in its own task, so an unbind is
    /// followed by the refusal rather than containing it.
    async fn wait_until_refused(address: Ipv4Addr, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect((address, port)).await {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => return,
                outcome => assert!(
                    Instant::now() < deadline,
                    "{address}:{port} still answers: {outcome:?}"
                ),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// NET-121. Revoking a declared port's ingress unbinds its forwarder and
    /// terminates the connection it held, and the port stays in the
    /// published-port table as the revocation that closed it.
    #[tokio::test]
    async fn ingress_revocation_unbinds_forwarder_and_terminates_connections() {
        const PORT: u16 = 18_310;

        let upstream = echo_backend().await;
        let mut table = PublishTable::default();
        let lease = table.lease(NetworkMode::OwnIp).unwrap();
        let address = lease.address();
        let forwarders = Forwarders::bind(
            address,
            &[DeclaredPort {
                port: PORT,
                answer: PortAnswer::Forwarded(upstream),
            }],
        )
        .await
        .expect("the declared port binds");
        table.register(SessionId::nil(), "web", lease, forwarders);

        // A connection through the forwarder reaches the box.
        let mut held = TcpStream::connect((address, PORT)).await.unwrap();
        held.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        held.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        // Revoking unbinds the port and ends the connection it held.
        table
            .revoke_port("web", PORT)
            .expect("the port had a forwarder")
            .finished()
            .await;
        let ended = tokio::time::timeout(Duration::from_secs(5), held.read(&mut echoed))
            .await
            .expect("the connection the forwarder held ends");
        match ended {
            Ok(0) => {}
            Ok(passed) => panic!("the revoked forwarder passed {passed} more bytes"),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}"),
        }
        wait_until_refused(address, PORT).await;

        // The table shows the revocation that closed the port, and the box
        // keeps the name it was published under.
        assert_eq!(
            table.entries()[0].forwarders,
            vec![PublishedPort {
                port: PORT,
                state: ForwarderState::Revoked,
                origin: PortOrigin::Declared,
                admitted: None
            }]
        );
        assert_eq!(
            table.lookup("web.min.internal"),
            Lookup::Address(IpAddr::V4(address))
        );
        assert!(
            table.revoke_port("web", PORT).is_none(),
            "nothing left to revoke"
        );
    }

    /// NET-121. A declared port whose forwarder cannot bind is reported with
    /// the reason, and nothing is substituted for it: no other port, no other
    /// address, and no name — the forwarders already bound for the box are
    /// released rather than left standing for a box nothing resolves.
    #[tokio::test]
    async fn failed_forwarder_bind_is_reported_not_substituted() {
        const ROLLED_BACK: u16 = 18_311;
        const TAKEN: u16 = 18_312;

        let upstream = echo_backend().await;
        let mut table = PublishTable::default();
        let lease = table.lease(NetworkMode::OwnIp).unwrap();
        let address = lease.address();
        // Something else already holds one of the two declared ports.
        let squatter = TcpListener::bind((address, TAKEN)).await.unwrap();

        let failure = Forwarders::bind(
            address,
            &[
                DeclaredPort {
                    port: ROLLED_BACK,
                    answer: PortAnswer::Forwarded(upstream),
                },
                DeclaredPort {
                    port: TAKEN,
                    answer: PortAnswer::Forwarded(upstream),
                },
            ],
        )
        .await
        .expect_err("the held port cannot be bound");

        // Reported with the port and the reason.
        assert_eq!(failure.port, TAKEN);
        assert_eq!(failure.address, address);
        assert_eq!(failure.error.kind(), io::ErrorKind::AddrInUse);
        let reported = failure.to_string();
        assert!(reported.contains(&TAKEN.to_string()), "{reported}");
        assert!(reported.contains(&failure.error.to_string()), "{reported}");

        // No name is published for the box and no substitute address answers
        // for it; the lease goes back to the range unspent.
        table.release(lease);
        assert_eq!(table.lookup("web.min.internal"), Lookup::Unknown);
        assert!(table.entries().is_empty());
        assert_eq!(table.lease(NetworkMode::OwnIp).unwrap().address(), address);

        // Nor is the port that did bind left standing, while the port that
        // failed is still only the squatter's.
        wait_until_refused(address, ROLLED_BACK).await;
        assert_eq!(
            squatter.local_addr().unwrap(),
            SocketAddr::new(IpAddr::V4(address), TAKEN)
        );
    }

    /// NET-014. A port the box has not published refuses the connection, and
    /// refuses it at once rather than leaving it to time out, while the
    /// declared port beside it is bound and carries the connection through to
    /// the box.
    #[tokio::test]
    async fn unpublished_port_connection_refused() {
        const DECLARED: u16 = 18_313;
        const UNPUBLISHED: u16 = 18_314;

        let upstream = echo_backend().await;
        let mut table = PublishTable::default();
        let lease = table.lease(NetworkMode::OwnIp).unwrap();
        let address = lease.address();
        let forwarders = Forwarders::bind(
            address,
            &[DeclaredPort {
                port: DECLARED,
                answer: PortAnswer::Forwarded(upstream),
            }],
        )
        .await
        .expect("the declared port binds");
        let published = table.register(SessionId::nil(), "web", lease, forwarders);
        assert_eq!(published.ports, vec![DECLARED]);

        // The declared port is bound, and carries bytes to the box.
        let mut declared = TcpStream::connect((address, DECLARED))
            .await
            .expect("the declared port is bound");
        declared.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        declared.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        // The port the box never published answers nothing: a refusal, taken
        // far inside the time a timeout would need.
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect((address, UNPUBLISHED)),
        )
        .await
        .expect("the connect settles rather than timing out");
        let error = outcome.expect_err("an unpublished port answers nothing");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refused after {:?}",
            started.elapsed()
        );
    }
}
