//! In-memory PTask hostname registry: the host-side routing table for the B5
//! egress proxy (Unit 3, UC2a) on the native-Linux (DM2) path.
//!
//! ## `*.min.internal` + host-side egress proxy
//!
//! Open Question 1 of the networking spec is settled in favour of the spec's B5
//! model (re-scoped 2026-06-23, superseding spike #485's systemd-resolved
//! finding): a PTask's box name is `<session>.min.internal`, and both
//! resolution and routing stay **host-side**. The host resolver is never
//! consulted and `minimald` writes nothing to it — `*.min.internal` (the TLD is
//! an opaque label) is mapped internally by the host-side egress proxy
//! ([`super::proxy`]), which routes each incoming request to the right PTask by
//! its `Host:` header. This registry is the lookup table that proxy consults —
//! [`HostnameRegistry::resolve`] is the routing decision for a `Host:` header.
//! Because resolution is host-side, the no-systemd sandbox (hakoniwa) and
//! microVM (libkrun) runtimes never resolve anything, and the TLD choice is
//! irrelevant to correctness.
//!
//! The registry still answers for the former three-label zone
//! `<session>.<host-id>.min.internal` (default host id `local`), resolving it
//! to the same entry with a deprecation notice (NET-002), for one release.
//!
//! The registry is also the box zone's table of record. The zone answerer
//! ([`super::answerer`]) serves host-OS resolution (NET-009) from
//! [`HostnameRegistry::zone_entry`], which says held-without-A apart from
//! absent: a name a box or node holds is NODATA — never NXDOMAIN, since
//! negative caching is name-wide and NXDOMAIN would poison a live box's name
//! — while a name nothing holds is NXDOMAIN (NET-124, NET-125). The address a
//! held name may answer with is gated by [`is_host_answerable`] (NET-127).
//! [`HostnameRegistry::zone_table`] renders the same view for the daemon's
//! state dump.
//!
//! A route is where a request to the name forwards:
//!
//! - A `HostNet` PTask's listeners are on host loopback, so its name routes
//!   there (R3.6).
//! - An `OwnIp` PTask (R3.1) depends on where the daemon sits relative to the
//!   gvproxy switch. On a VM host (DM1/3/4) the daemon holds its own tap on the
//!   switch, so the name routes **straight to the box's lease** (NET-001), with
//!   the box's ingress declaration carried as an external→internal port map so
//!   a URL naming a published port reaches the internal one behind it. A URL
//!   naming a port the declaration does not publish routes nowhere: the proxy
//!   refuses it (the box has not published it), matching the ingress gate that
//!   denies an inbound SYN to any undeclared port on the switch too. On a
//!   native host (DM2) the daemon is off the switch and the name keeps the
//!   **published-loopback** model: the box's gvproxy forwarder binds
//!   `127.0.0.1:<external>` → `lease:<internal>`, and the client selects the
//!   published external port. Either way the `OwnIp` name registers only once
//!   the attach path has reported the lease — a box with no lease has no
//!   address to route to.
//!
//! Covers R3.5 (structured register/deregister tracing) and R3.6 (`HostNet`
//! registration). The former systemd-resolved startup probe (R3.4) is removed by
//! the re-scope; an egress-proxy reachability check
//! ([`super::proxy::bind_listener`]) replaces it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Serialize;
use sessions::core::egress::EgressRules;
#[cfg(target_os = "linux")]
use sessions::core::loopback::LoopbackAllocator;
use sessions::{SessionId, SessionPolicy};
#[cfg(target_os = "linux")]
use std::time::Duration;

use super::SwitchSubnet;

/// The DNS suffix every PTask box name carries (see the module docs).
pub const HOSTNAME_SUFFIX: &str = "min.internal";

/// Whether `name` is a box-zone name — the zone apex itself or any name under
/// it (NET-072). `name` is an already-normalized qname: lowercased, no root
/// dot, exactly what [`super::dns_gate`]'s gate asks about. Mirrors the
/// answerer's zone-suffix match so both layers cannot drift.
#[must_use]
pub fn is_zone_name(name: &str) -> bool {
    name == HOSTNAME_SUFFIX
        || name
            .strip_suffix(HOSTNAME_SUFFIX)
            .is_some_and(|stem| stem.ends_with('.'))
}

/// Default `<host-id>` of the deprecated three-label zone: a stable short name
/// for this `minimald` instance. The host-id is configurable; this is the value
/// used when none is configured.
pub const DEFAULT_HOST_ID: &str = "local";

/// The reserved local range published box addresses come from on the host:
/// `127.0.64.0/24` (design §7.1), as network address and prefix. Loopback
/// space, so it never leaves the machine, with one address per published box
/// (NET-010's host-global allocation). Kept as a pair rather than a CIDR type
/// — the only question asked of it is membership, which
/// [`is_host_answerable`] answers with octet math.
///
/// Re-exported from the `switch` crate, which owns the range — the default
/// address plan publishes boxes from it — so the zone's answers and the
/// published addresses are the one definition and cannot drift.
pub use ::switch::RESERVED_LOCAL_RANGE;

/// The TTL every box-zone answer carries, and the ceiling on it (NET-126):
/// 15 s, short enough that a box published a moment ago is found without
/// reloading the host resolver. Also the `minimum` the zone's SOA reports for
/// negatives, so the host resolver caches them at all (NET-124): an
/// uncacheable negative stalls every lookup on a macOS host, not only the
/// zone's.
pub const ANSWER_TTL_SECS: u32 = 15;

/// Whether `addr` is one an A answer in the box zone may carry when the lookup
/// originates on the host OS (NET-127): an address from the reserved local
/// range, `127.0.0.1` itself, or one of the node's own addresses.
///
/// `node` is the set of addresses this daemon's host publishes at. Today the
/// daemon holds none — a native node's boxes mirror `127.0.0.1` and a VM
/// node's publish from the reserved range (NET-129) — so the set travels empty
/// from every caller; the guard is where a node's own addresses will land when
/// that changes. Anything else — a box's switch lease, an address another host
/// holds — is not answerable from the host, and a name held only there answers
/// NODATA rather than leaking the address.
#[must_use]
pub fn is_host_answerable(addr: Ipv4Addr, node: &[Ipv4Addr]) -> bool {
    if addr == Ipv4Addr::LOCALHOST || node.contains(&addr) {
        return true;
    }
    in_reserved_local_range(addr)
}

/// Whether `addr` falls in the reserved local range [`RESERVED_LOCAL_RANGE`].
fn in_reserved_local_range(addr: Ipv4Addr) -> bool {
    let (network, prefix) = RESERVED_LOCAL_RANGE;
    let host_bits = 32 - u32::from(prefix);
    // A /0 range would mean "every address"; the shift below needs a network
    // part to keep.
    if host_bits >= 32 {
        return true;
    }
    let mask = u32::MAX << host_bits;
    u32::from(network) & mask == u32::from(addr) & mask
}

/// A registered PTask box name of the form `<session>.min.internal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Builds the two-label box name for a PTask. DNS names are
    /// case-insensitive, so the rendered form is lower-cased to keep lookups
    /// stable.
    fn for_ptask(session_name: &str) -> Self {
        Self(format!("{session_name}.{HOSTNAME_SUFFIX}").to_ascii_lowercase())
    }

    /// The hostname as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a box name routes: the upstream socket a request forwards on, and the
/// session that owns the name — what a request "resolved to", which the proxy's
/// refusal logs carry for the diagnostics bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    target: Target,
    session: String,
    /// The ports a request to this name may name (NET-069, NET-071): the
    /// external ports the target's ingress declaration publishes. `None` only
    /// for a host-address box, whose direct connections no surface gates, so a
    /// proxied request to it gates nothing either; `Some(…)` for every
    /// own-address target, from the declaration of record
    /// ([`super::switch::declared_request_ports`] at registration, or the
    /// applied external→internal map the attach path reports) — empty when the
    /// box declares no ingress, which is the own-IP deny-all posture, never an
    /// open gate. Carried on the route, not read from the policy at request
    /// time, so the target's declaration decides it on both halves of the
    /// proxy's verdict and the relay's port gate stays the one derivation
    /// ([`super::switch::declared_ingress_ports`]).
    declared: Option<BTreeSet<u16>>,
}

/// The upstream a [`Route`] forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Host loopback at `address`: a `HostNet` box's listeners, which sit on
    /// its node's published address (R3.6, NET-129) — and, on a native host,
    /// an `OwnIp` box's published-loopback forwarder, where the requested
    /// port is the published external one and `address` is the host loopback
    /// address a creator handed the box's own ports to publish at (NET-010).
    Loopback { address: Ipv4Addr },
    /// An `OwnIp` box at its lease on the switch (a VM host): the daemon is on
    /// the switch, so a request reaches the box itself instead of the guest
    /// loopback. `ports` is the box's ingress declaration as an
    /// external→internal map, so a URL naming a published port reaches the
    /// internal one behind it; a port outside the map routes nowhere — the box
    /// has not published it, and the ingress gate denies an inbound SYN to any
    /// undeclared port on the switch besides (NET-001).
    Lease {
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    },
}

impl Route {
    /// A route to host loopback at `address`, owned by `session`, gating the
    /// ports a request may name on `declared` (see [`Route::declared`]).
    pub(crate) fn loopback(
        session: impl Into<String>,
        address: Ipv4Addr,
        declared: Option<BTreeSet<u16>>,
    ) -> Self {
        Self {
            target: Target::Loopback { address },
            session: session.into(),
            declared,
        }
    }

    /// A route to an `OwnIp` box at `lease`, owned by `session`, carrying the
    /// box's ingress declaration as an external→internal port map. The map's
    /// external keys *are* the declared ports: the translation and the port
    /// gate are one declaration, so a request the route forwards is a
    /// request the declaration published (NET-069).
    pub(crate) fn lease(
        session: impl Into<String>,
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    ) -> Self {
        Self {
            target: Target::Lease {
                lease,
                ports: ports.clone(),
            },
            session: session.into(),
            declared: Some(declared_keys(&ports)),
        }
    }

    /// The ports a request to this name may name (NET-069): the external ports
    /// the target's ingress declaration publishes, or `None` when the target
    /// declares no ingress at all — no gate to honour, the verdict a direct
    /// connection to it gets (NET-071).
    #[must_use]
    pub fn declared_ports(&self) -> Option<&BTreeSet<u16>> {
        self.declared.as_ref()
    }

    /// The upstream socket a request for `port` forwards to, or `None` when
    /// this route does not carry that port: a port the target's ingress did
    /// not publish has no upstream — the proxy refuses the request rather
    /// than dialing a port the target's ingress gate would drop, whose silent
    /// SYN drop is a connect hang instead of a refusal (NET-001, NET-014,
    /// NET-069). A route with no gate at all (`None`, a host-address box)
    /// forwards any port: its direct connections are ungated, so its proxied
    /// requests are too — while an own-address route with an empty set is a
    /// deny-all gate, the posture of a box that declared no ingress (NET-071).
    #[must_use]
    pub fn upstream(&self, port: u16) -> Option<SocketAddr> {
        if let Some(declared) = self.declared_ports()
            && !declared.contains(&port)
        {
            return None;
        }
        match &self.target {
            Target::Loopback { address } => Some(SocketAddr::new(IpAddr::V4(*address), port)),
            Target::Lease { lease, ports } => {
                let internal = ports.get(&port).copied()?;
                Some(SocketAddr::new(IpAddr::V4(*lease), internal))
            }
        }
    }

    /// The session that owns the name — what a request to it resolved to.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The IPv4 address the name routes at: the host loopback address its
    /// published ports bind on, or the box's lease on the switch. Every
    /// route's address is IPv4 — the switch fabric is, and so is the host
    /// loopback a host-address box's listeners sit on — which is what lets
    /// the caller's egress verdict, an IPv4 frame decision, be asked about
    /// it directly (NET-070). Also the address the R3.5 tracing events
    /// carry.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        match &self.target {
            Target::Loopback { address } => *address,
            Target::Lease { lease, .. } => *lease,
        }
    }

    /// Moves this route from `from` to `to` — the registry's half of a node
    /// address that was granted after the routes citing it were registered
    /// ([`HostnameRegistry::set_node_address`]). Only a host-loopback route
    /// answering exactly the old address moves: a box's lease is not a
    /// host-loopback fact and never carries the node's address, and a box's
    /// own granted address is not the node's either.
    pub(crate) fn repoint(&mut self, from: Ipv4Addr, to: Ipv4Addr) {
        if let Target::Loopback { address } = &mut self.target
            && *address == from
        {
            *address = to;
        }
    }

    /// The A answer this route's name carries in the box zone when the lookup
    /// originates on the host OS (NET-127): the route's address when it is one
    /// the host may be told, `None` when it is not. A box's switch lease, which
    /// routes requests inside the fabric, is not reachable from the host OS, so
    /// a name held only there answers NODATA, never NXDOMAIN — the box exists,
    /// and a name-wide negative would poison it (NET-124, NET-128).
    ///
    /// `node` is the set of addresses this daemon's host publishes at (see
    /// [`is_host_answerable`]).
    #[must_use]
    pub fn zone_address(&self, node: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        let addr = self.address();
        is_host_answerable(addr, node).then_some(addr)
    }
}

/// The declared ports of an applied external→internal map: its keys.
fn declared_keys(ports: &BTreeMap<u16, u16>) -> BTreeSet<u16> {
    ports.keys().copied().collect()
}

/// A live registration: the box name minted for a session, plus the stable
/// `SessionId` carried in its R3.5 tracing events. The id is captured at
/// registration so `deregister` (keyed by the mutable session name) emits the
/// same stable identifier the `registered` event did.
#[derive(Debug, Clone)]
struct Registration {
    id: SessionId,
    hostname: Hostname,
}

/// The lease an `OwnIp` box attached with, kept by the stable `SessionId`: the
/// attach path reports it once, and every later registration of the session's
/// name (spawn, finalize, rename) routes against it until the session ends.
#[derive(Debug, Clone)]
struct OwnAddress {
    lease: Ipv4Addr,
    /// The box's ingress declaration as an external→internal port map.
    ports: BTreeMap<u16, u16>,
}

/// The publish state of an own-address box, by stable session id (NET-010):
/// the host loopback address it leased from the reserved local range, and the
/// ports its ingress declaration publishes on it — the inputs of the
/// same-address collision check ([`HostnameRegistry::publish_own_address`],
/// NET-129). Held by id, never by name, so the box keeps its address across a
/// rename and the attach path can read it back without the session's current
/// name.
#[derive(Debug, Clone)]
struct OwnPublished {
    /// The host loopback address the box's ports are published at.
    address: Ipv4Addr,
    /// The external ports the box's declaration publishes on it.
    ports: BTreeSet<u16>,
}

/// A same-address port collision a publish found (NET-129): a port two boxes
/// would both answer at on one shared address. Intrinsic to the mode — the
/// boxes were told to publish at the same place — so it is *reported*, at
/// session start and in the daemon log, and neither port is translated: the
/// declarations of record stand, and the collision is what the operator reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedPortCollision {
    /// The port both boxes publish at.
    pub port: u16,
    /// The session whose box held the port first — the collision's other
    /// half, named for the report.
    pub other: String,
}

/// One own-address publish standing at the `127.0.0.1` interim (NET-123
/// §7.1), as the present landing's sweep reads it: the box's stable id, the
/// name its ports re-register under, the ports its declaration publishes,
/// and the hand a creator gave it — `None` for a box nobody handed an
/// address, which is the box the sweep grants a pool address to.
#[derive(Debug, Clone)]
pub struct InterimPublish {
    /// The session whose box owns the publish.
    pub session: SessionId,
    /// The box name the move re-registers.
    pub name: String,
    /// The ports the box's declaration publishes.
    pub ports: BTreeSet<u16>,
    /// The loopback address a creator handed the box, if one did: the
    /// move's target for a handed box — its own hand, never a fresh grant.
    pub hand: Option<Ipv4Addr>,
}

/// Who a proxied request came from (NET-070): the live session the request's
/// peer address names, at the switch lease its box holds, with the compiled
/// egress rules its own outbound frames are decided by — the same rules a
/// request from it is put to, exactly as a direct connection from it would be
/// ([`super::switch::proxied_request_verdict`]). Named by the
/// lease-to-session map ([`HostnameRegistry::by_lease`]), so only a box on the
/// switch is ever a caller: a host-side client has no declaration to honour
/// and no gate of its own on a direct connection either.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The switch lease the caller's box holds: the address its proxied
    /// connections come from, and the address a refusal log names it by.
    lease: Ipv4Addr,
    /// The caller's session name, for the refusal log.
    name: String,
    /// The caller's compiled egress rules, as the relay decides its own
    /// frames by ([`super::switch::compiled_egress`]) — compiled at the join
    /// with this lease, so the verdict's source check (NET-084) reads the
    /// frame a request stands for as the box's own.
    egress: EgressRules,
}

impl Caller {
    /// The switch lease the caller's box holds.
    #[must_use]
    pub fn lease(&self) -> Ipv4Addr {
        self.lease
    }

    /// The caller's session name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The caller's compiled egress rules — what its own outbound frames are
    /// decided by, and what a request from it is put to.
    #[must_use]
    pub fn egress(&self) -> &EgressRules {
        &self.egress
    }
}

/// The name and egress declaration of a live session, kept by stable id
/// ([`HostnameRegistry::callers`]) until its lease joins onto them and either
/// ends. The declaration is held uncompiled: the lease that completes it
/// arrives by a different path than the registration does, so the rules are
/// compiled at the join ([`HostnameRegistry::caller_at`]) — with the lease that
/// names the caller, through the same [`super::switch::compiled_egress`] the
/// relay's gate compiles its own rules by — and the two surfaces can never
/// disagree about whose frame a request from that lease stands for.
#[derive(Debug, Clone)]
struct CallerFacts {
    name: String,
    /// The caller's policy as launch recorded it — the egress half is what a
    /// request from it is put to; the ingress half is not read here.
    policy: SessionPolicy,
    /// The switch the box's relay is attached to, whose resolver its egress
    /// carve-out is keyed to (NET-079).
    subnet: SwitchSubnet,
}

/// What the box zone holds for a name, as the answerer answers from it. The
/// distinction a negative turns on: **held-without-A is not absent.** A box or
/// node that holds a name without a host-answerable address gets NODATA (an
/// empty NOERROR), never NXDOMAIN — negative caching is name-wide, and
/// NXDOMAIN would poison the name the box already owns (NET-124, NET-128).
/// Only a name nothing holds is NXDOMAIN (NET-125).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneEntry {
    /// No box or node holds the name: NXDOMAIN (NET-125).
    Absent,
    /// A box or node holds the name.
    Held {
        /// The session that owns it (its owner in the zone table).
        owner: String,
        /// The A answer a host-OS lookup gets (NET-127), or `None` when the
        /// name is held at an address the host may not be told: NODATA.
        address: Option<Ipv4Addr>,
    },
}

/// One row of the box-zone table the daemon's state dump carries (NET-006's
/// "which names does this daemon hold"): the name, the A address it answers at
/// on the host — `null` when held without one, so the table reports the box
/// exists without claiming it is published on the host — and the session that
/// owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZoneRow {
    /// The full `<name>.min.internal` name.
    pub name: String,
    /// The host-answerable A address, if the name has one.
    pub address: Option<Ipv4Addr>,
    /// The session that owns the name.
    pub owner: String,
}

/// An in-memory registry of live PTask box names, owned by the sessions manager
/// (one per `minimald`). It maps each live PTask's box name to the route a
/// host-side proxy forwards its requests on, and tracks the reverse (session →
/// box name) so a name is withdrawn when its session exits.
#[derive(Debug)]
pub struct HostnameRegistry {
    /// The `<host-id>` labels of the deprecated three-label zones this
    /// registry still answers for (NET-002): the daemon's own id first — so
    /// a second daemon beside the first can hold a zone of its own
    /// (NET-027) — and `local` after it, because the pre-instance world
    /// promised every daemon's boxes that label and a name like
    /// `web.local.min.internal` keeps routing while it lives (see
    /// [`host_ids_for`]).
    host_ids: Vec<String>,
    /// Whether the daemon sits on the gvproxy switch (a VM host): an `OwnIp`
    /// box's route then targets its lease; on a native host it keeps the
    /// published-loopback model.
    on_switch: bool,
    /// The host loopback address this node's `HostNet` boxes answer at
    /// (R3.6, NET-129): the address the answerer's record holds for the node,
    /// which its boxes' listeners are forwarded to. Default `127.0.0.1` — a
    /// native node's address is the host loopback itself, and it asks for
    /// nothing.
    node: Ipv4Addr,
    /// Published own-address state, by stable session id (NET-010): the
    /// address and ports an `OwnIp` box's declaration publishes at, from
    /// finalize until destroy. Only what a creator handed: the daemon has no
    /// address of its own to stand in with — the shared-address interim this
    /// table once recorded beside it is gone with that default.
    own_published: HashMap<SessionId, OwnPublished>,
    /// The loopback address a creator handed each own-address box, by stable
    /// session id (T66, NET-123 §7.1): recorded at the box's registration
    /// whether the publish lands at it or at the `127.0.0.1` interim — a
    /// hand the pending verdict had not vouched for is the one publish that
    /// can be standing at the interim while an address the box owns exists
    /// — so a present landing's sweep moves a handed box standing at the
    /// interim back to its **own hand**, never to a grant drawn from the
    /// pool: the hand is the host-side table's row, an address this
    /// daemon's book never owned, and "a hand is only ever replaced by
    /// `127.0.0.1`" is the rule that keeps the publish and the attach
    /// path's forwards (which name the hand as their `local`) at one
    /// address. Dropped with the publish at
    /// [`Self::unpublish_own_address`].
    hands: HashMap<SessionId, Ipv4Addr>,
    /// Sessions whose box has stopped (NET-128): its name stays *held* —
    /// answered, not absent, so a stopped box is never mistaken for one that
    /// never existed — but a name it shares with the node answers NODATA, so
    /// the node's own listener at that port keeps answering and the stopped
    /// box is not silently impersonated by it.
    stopped: HashSet<SessionId>,
    /// box name → the route a host-side proxy forwards its requests on.
    by_host: HashMap<Hostname, Route>,
    /// session name → its live registration, for withdrawal on exit.
    by_session: HashMap<String, Registration>,
    /// Reported `OwnIp` leases, by stable session id (see [`OwnAddress`]).
    own: HashMap<SessionId, OwnAddress>,
    /// The name and egress declaration of every live session, by stable id
    /// — the facts that check a proxied request's *caller* (NET-070).
    /// Recorded by [`Self::register_caller`] at hostname registration, before
    /// the box has a lease, so the join is ready the moment it attaches.
    callers: HashMap<SessionId, CallerFacts>,
    /// The lease-to-session map that names a caller (NET-070): the switch
    /// address a proxied request's peer resolves to a session with. Reserved
    /// switch addresses never appear in it — the switch hands a PTask a lease
    /// inside its lease range, never one of its own reserved addresses (the
    /// gateway, the host alias, the daemon) — so a peer at a reserved address
    /// is never misread as a box.
    by_lease: HashMap<Ipv4Addr, SessionId>,
}

/// The `<host-id>` labels one daemon answers for: its own instance id, and
/// `local` — the label of the pre-instance zone, which every daemon keeps
/// answering so a `<name>.local.min.internal` that routed before the ids
/// existed still routes (NET-002, NET-027). The same pair is what
/// [`register_dns_name`](crate::net::policy::register_dns_name) publishes
/// into the gvproxy zone, so the DNS side and the routing side answer for
/// the same names.
#[must_use]
pub fn host_ids_for(host_id: &str) -> Vec<String> {
    let mut ids = vec![host_id.to_string()];
    if host_id != DEFAULT_HOST_ID {
        ids.push(DEFAULT_HOST_ID.to_string());
    }
    ids
}

impl HostnameRegistry {
    /// Creates an empty registry whose deprecated three-label zones use the
    /// given `<host-id>` (plus `local` — see [`host_ids_for`]), and which
    /// routes `OwnIp` boxes by whether the daemon sits on the gvproxy switch
    /// (`on_switch` — a VM host).
    #[must_use]
    pub fn new(host_id: impl Into<String>, on_switch: bool) -> Self {
        Self {
            host_ids: host_ids_for(&host_id.into()),
            on_switch,
            node: Ipv4Addr::LOCALHOST,
            own_published: HashMap::new(),
            hands: HashMap::new(),
            stopped: HashSet::new(),
            by_host: HashMap::new(),
            by_session: HashMap::new(),
            own: HashMap::new(),
            callers: HashMap::new(),
            by_lease: HashMap::new(),
        }
    }

    /// Sets the node's host loopback address — the address the answerer's
    /// record holds for this node (NET-129) — and returns the registry, for
    /// the sessions manager to build its registry with at init, after it has
    /// asked. `HostNet` boxes answer at it.
    #[must_use]
    pub fn with_node_address(mut self, node: Ipv4Addr) -> Self {
        self.node = node;
        self
    }

    /// Sets the node's host loopback address once the answerer granted it —
    /// the half of [`Self::with_node_address`] a daemon whose range verdict
    /// landed *after* its registry was built needs (a microVM daemon: its
    /// probe is a walk through the host's forwarder, and the daemon does not
    /// hold its accept loop for it, so the registry opens on the interim and
    /// the walk hands the node its address when it answers).
    ///
    /// Every route the **old** address answers is re-pointed at the new one,
    /// not just the field: a host-address box registered while the node was
    /// still on the interim would otherwise keep answering the interim for
    /// its lifetime. Those are exactly the routes whose address is the node's
    /// — a box's own handed address is never repointed by a fact about the
    /// node — so that is the rule. Nothing else about a route moves: the
    /// ports a request may name are the box's own declaration, not a fact
    /// about where it publishes.
    pub fn set_node_address(&mut self, node: Ipv4Addr) {
        let was = std::mem::replace(&mut self.node, node);
        if was == node {
            return;
        }
        tracing::info!(
            from = %was,
            to = %node,
            action = "node-loopback-address",
            "the node's own loopback address was granted; the names it answers move with it"
        );
        for route in self.by_host.values_mut() {
            route.repoint(was, node);
        }
    }

    /// Returns the node's host loopback address as the registry currently
    /// holds it.
    #[must_use]
    pub fn node_address(&self) -> Ipv4Addr {
        self.node
    }

    /// Registers `session_name`'s box name routing it along `route`, and
    /// returns the name. Emits the R3.5 `registered` tracing event.
    /// `session_id` is the stable, unique identifier carried in that event for
    /// log correlation; `session_name` is the registry key (mutable, and
    /// reusable after the session exits), so both are emitted.
    fn register(&mut self, session_id: SessionId, session_name: &str, route: Route) -> Hostname {
        let hostname = Hostname::for_ptask(session_name);
        let address = route.address();
        self.by_session.insert(
            session_name.to_string(),
            Registration {
                id: session_id,
                hostname: hostname.clone(),
            },
        );
        self.by_host.insert(hostname.clone(), route);
        tracing::info!(
            session_id = %session_id,
            session_name,
            hostname = %hostname,
            ip = %address,
            action = "registered",
            "registered PTask hostname"
        );
        hostname
    }

    /// Registers a `HostNet` PTask, routing its box name to this node's host
    /// loopback address (R3.6, NET-129) — the address the daemon leased for
    /// itself, which its boxes' forwarded listeners sit on. The route gates no
    /// port: a host-address box has no ingress declaration — launch validation
    /// rejects one on every network mode but `own_ip` — and a direct
    /// connection to it is ungated, so the proxy gates nothing either
    /// (NET-071).
    pub fn register_host_net(&mut self, session_id: SessionId, session_name: &str) -> Hostname {
        self.register(
            session_id,
            session_name,
            Route::loopback(session_name, self.node, None),
        )
    }

    /// Registers an `OwnIp` PTask's box name at the address its declaration
    /// publishes on (NET-010, NET-011): the host loopback address a creator
    /// handed the box and its record published — never one the daemon chose,
    /// because it has no default to publish at. On a VM host the route targets
    /// the box's switch lease as soon as the attach path has reported one
    /// ([`Self::report_own_address`], R3.1, NET-001); before that, and on a
    /// native host always, it targets the published address, so **the name is
    /// held from finalize to destroy** whether or not a client is attached.
    /// A box nobody handed an address registers nothing: `None`, the name
    /// absent until the creator's hand publishes one. `declared` is the
    /// session's own ingress declaration as the ports a request may name
    /// ([`super::switch::declared_request_ports`]) — a plain set, because an
    /// own-address box is always gated and a declaration of none is the
    /// deny-all posture, not an open gate; this is the half of the route that
    /// keeps the proxy's refusals identical to the direct connection's on a
    /// native host's published-loopback routes (NET-069, NET-071). The
    /// session actor calls this at spawn, finalize, and rename; the attach
    /// path reports the lease with [`Self::report_own_address`] as soon as
    /// the box attaches.
    pub fn register_own_ip(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        declared: BTreeSet<u16>,
    ) -> Option<Hostname> {
        self.own_route(session_id, session_name, declared)
            .map(|route| self.register(session_id, session_name, route))
    }

    /// Records the facts that check this session as the *caller* of a proxied
    /// request (NET-070): its name and its egress declaration, as launch
    /// recorded it, over the switch its own relay is attached to — so the
    /// rules a request from it is put to are the ones its own outbound frames
    /// are decided by, exactly as a direct connection from it would be. The
    /// declaration is held uncompiled and the rules are built at the join
    /// ([`Self::caller_at`]): recorded here at hostname registration, before
    /// the box has a lease, and completed by the lease that names it once the
    /// attach path reports one ([`Self::report_own_address`], which maps the
    /// lease onto the stable id).
    pub fn register_caller(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        policy: &SessionPolicy,
        subnet: SwitchSubnet,
    ) {
        self.callers.insert(
            session_id,
            CallerFacts {
                name: session_name.to_string(),
                policy: policy.clone(),
                subnet,
            },
        );
    }

    /// The live caller at `lease`, if one is (NET-070): the session whose box
    /// holds that lease, with its name and its compiled egress rules — built
    /// here, from the declaration recorded at registration and the `lease`
    /// that names it, by the same compilation the relay's gate makes
    /// ([`super::switch::compiled_egress`]), so the caller's rules carry the
    /// lease a request from it is put to as the one source its frames may
    /// carry (NET-084) and the two surfaces decide by one rule set (NET-071).
    /// `None` when the lease names no session — which is what a host-side
    /// caller (the developer's browser, the daemon's own lanes) is, and what a
    /// host-address session is too: neither has a box on the switch, and
    /// neither's egress is gated on a direct connection either.
    #[must_use]
    pub fn caller_at(&self, lease: Ipv4Addr) -> Option<Caller> {
        let id = self.by_lease.get(&lease)?;
        let facts = self.callers.get(id)?;
        Some(Caller {
            lease,
            name: facts.name.clone(),
            egress: super::switch::compiled_egress(Some(&facts.policy), facts.subnet, lease),
        })
    }

    /// The own-address publishes standing inside the reserved local range, as
    /// `(session id, session_name, address, ports)` — the boxes an **absent**
    /// verdict landing moves onto the `127.0.0.1` interim (NET-123): a hand
    /// the pending window vouched for by its provenance rather than by a
    /// measurement, or a grant a recorded namespace holds, each now naming
    /// an address the publish surface cannot bind, so every forward the box
    /// would bind there fails with `EADDRNOTAVAIL`. The name rides along
    /// because the move re-registers the box's route at the interim; a
    /// publish whose session holds no registered name (a stopped box, one
    /// whose name another session took over) is not listed — its next
    /// finalize is the moment its ask runs again, through the verdict-gated
    /// reads the session actor makes.
    #[must_use]
    pub fn own_publishes_in_reserved_range(
        &self,
    ) -> Vec<(SessionId, String, Ipv4Addr, BTreeSet<u16>)> {
        self.own_published
            .iter()
            .filter(|(_, own)| in_reserved_local_range(own.address))
            .filter_map(|(id, own)| {
                self.by_session
                    .iter()
                    .find(|(_, registration)| registration.id == *id)
                    .map(|(name, _)| (*id, name.clone(), own.address, own.ports.clone()))
            })
            .collect()
    }

    /// The own-address publishes standing at the `127.0.0.1` interim
    /// (NET-123 §7.1) — the boxes a **present** verdict landing moves off it.
    /// The interim is the ask's own answer for a verdict that had not
    /// landed, never an address the box owns, so the landing that replaces
    /// the verdict is the one moment those asks upgrade — to the box's own
    /// hand for a box a creator handed one (never a grant from the pool: a
    /// hand is only ever replaced by `127.0.0.1`), to a grant for a box
    /// nobody handed an address. Each row carries the hand with it, so the
    /// sweep's move needs no second read. A box whose publish the landing
    /// misses, because it was stopped across the landing, asks again at its
    /// next finalize, which does not short-circuit on the interim either.
    #[must_use]
    pub fn interim_own_publishes(&self) -> Vec<InterimPublish> {
        self.own_published
            .iter()
            .filter(|(_, own)| own.address == Ipv4Addr::LOCALHOST)
            .filter_map(|(id, own)| {
                let (name, _) = self
                    .by_session
                    .iter()
                    .find(|(_, registration)| registration.id == *id)?;
                Some(InterimPublish {
                    session: *id,
                    name: name.clone(),
                    ports: own.ports.clone(),
                    hand: self.hands.get(id).copied(),
                })
            })
            .collect()
    }

    /// Records the loopback address a creator handed this own-address box
    /// (T66, NET-123 §7.1) — called at every registration that finds a hand
    /// on the box's record, whatever address the publish lands at, because
    /// the hand is the box's own address whether it is standing at it or
    /// waiting on the interim for the verdict that vouches for it. The
    /// present landing's sweep reads it through
    /// [`Self::interim_own_publishes`] to move a handed box back to its own
    /// hand instead of drawing it a grant; it is dropped with the publish at
    /// [`Self::unpublish_own_address`].
    pub fn record_own_hand(&mut self, session_id: SessionId, address: Ipv4Addr) {
        self.hands.insert(session_id, address);
    }

    /// Whether `session_name` is still registered **to `session_id`** — the
    /// re-check a present landing's publish runs under the write lock before
    /// it re-registers the name (names are first-writer-owned, so a box that
    /// died inside the landing's window must not have its name re-claimed
    /// over the next box that takes it). Gated by id rather than the name
    /// alone, exactly as [`Self::withdraw_own_name`] gates its withdrawal.
    #[must_use]
    pub fn name_held_by(&self, session_id: SessionId, session_name: &str) -> bool {
        self.by_session
            .get(session_name)
            .is_some_and(|registration| registration.id == session_id)
    }

    /// Reports the lease an `OwnIp` box attached with (from the attach path)
    /// and registers the session's box name against it now, so the name routes
    /// exactly when the box is reachable. On a VM host the lease is the route;
    /// on a native host the route still needs the published address a creator
    /// handed — no address, no registration (`None`, the name absent). The
    /// lease is kept by the stable `session_id` — a later rename re-registers
    /// against the same lease without a fresh report — until
    /// [`Self::forget_own_address`] drops it at session end. Reporting also
    /// joins the lease onto the session's caller facts ([`Self::by_lease`]),
    /// so a proxied request from this box is checked against its own egress
    /// declaration (NET-070); the applied external→internal map the attach
    /// path hands over is the route's declared set here — the declaration of
    /// record in translation form.
    pub fn report_own_address(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    ) -> Option<Hostname> {
        // Retire the session's previous lease from the caller map, if it had
        // one: a re-attach takes a new lease and the old one must not name a
        // session that no longer holds it.
        if let Some(old) = self.own.get(&session_id) {
            self.by_lease.remove(&old.lease);
        }
        let own = OwnAddress {
            lease,
            ports: ports.clone(),
        };
        self.by_lease.insert(lease, session_id);
        // Recorded before the route is derived from it, so the route this
        // registration installs already targets the lease it is reporting:
        // [`Self::own_route`] reads the box's lease from this map, and a box
        // that has just attached holds one — the first report is exactly the
        // moment a VM host's route turns from the published address onto the
        // lease, not the one case that misses it. On a native host the same
        // re-registration needs the published address a creator handed —
        // `None` leaves the name absent, the shape no-address attach leaves
        // behind.
        self.own.insert(session_id, own);
        self.own_route(session_id, session_name, declared_keys(&ports))
            .map(|route| self.register(session_id, session_name, route))
    }

    /// Drops an ended session's lease fact — and its caller fact with it. The
    /// route itself was already withdrawn by [`Self::deregister`]; this keeps
    /// the registry from outliving the box it pointed at, so a later session
    /// reusing the stable id — or the name — cannot route at a dead address,
    /// and its address cannot name a caller that is gone. Not called by
    /// `deregister` itself: a rename withdraws and re-registers against the
    /// same lease.
    pub fn forget_own_address(&mut self, session_id: SessionId) {
        if let Some(own) = self.own.remove(&session_id) {
            self.by_lease.remove(&own.lease);
        }
        self.callers.remove(&session_id);
        self.stopped.remove(&session_id);
    }

    /// Publishes an `OwnIp` box's ingress declaration at `address` (NET-010):
    /// the host loopback address a creator handed the box — its record's grant
    /// or the address the VM activation handed — with the external ports its
    /// declaration names: the box's own port numbers, never translated.
    /// Recorded by stable id from finalize until destroy, so the name answers
    /// with no client attached (NET-011) and the box keeps its address across a
    /// rename or a re-attach. The daemon never calls this with an address of
    /// its own choosing: only a creator's hand reaches a publish.
    ///
    /// Two boxes handed one address — the shared-address mode — collide on
    /// every port both name (NET-129). The collision is intrinsic to the
    /// mode: the boxes were told to publish at the same place, so it is
    /// **reported**, never fixed by translating a port. One warn line here for
    /// the daemon log per collision, and the list returned for the
    /// session-start report.
    pub fn publish_own_address(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        address: Ipv4Addr,
        ports: BTreeSet<u16>,
    ) -> Vec<SharedPortCollision> {
        let collisions = self.own_address_collisions(session_id, address, &ports);
        for collision in &collisions {
            tracing::warn!(
                session_id = %session_id,
                session_name,
                address = %address,
                port = collision.port,
                other = %collision.other,
                action = "shared-address-port-collision",
                "two boxes publish one port at a shared loopback address"
            );
        }
        self.own_published
            .insert(session_id, OwnPublished { address, ports });
        collisions
    }

    /// The collision list between `session_id`/address/ports and every other
    /// recorded own-address publish sharing the same address and a port.
    fn own_address_collisions(
        &self,
        session_id: SessionId,
        address: Ipv4Addr,
        ports: &BTreeSet<u16>,
    ) -> Vec<SharedPortCollision> {
        self.own_published
            .iter()
            .filter(|(other, own)| **other != session_id && own.address == address)
            .flat_map(|(other, own)| {
                let other_name = self
                    .by_session
                    .values()
                    .find(|registration| registration.id == *other)
                    .map(|registration| registration.hostname.to_string())
                    .unwrap_or_else(|| other.to_string());
                own.ports
                    .intersection(ports)
                    .map(move |port| SharedPortCollision {
                        port: *port,
                        other: other_name.clone(),
                    })
            })
            .collect()
    }

    /// The address a session's box publishes at, if it has one — for the
    /// session actor to keep across a rename or re-register without leasing a
    /// second address for the same box (NET-010).
    #[must_use]
    pub fn published_own_address(&self, session_id: SessionId) -> Option<Ipv4Addr> {
        self.own_published.get(&session_id).map(|own| own.address)
    }

    /// Withdraws a destroyed box's publish and returns the address it held,
    /// for the session actor to release into the allocator (NET-010) — the
    /// lease's other half, at the same place the release is logged. A box
    /// whose publish is gone stops answering at the address: its name is
    /// withdrawn by [`Self::deregister`] in the same deregister. The box's
    /// recorded hand goes with the publish: a landing's sweep must not find
    /// a hand for a box that no longer exists.
    pub fn unpublish_own_address(&mut self, session_id: SessionId) -> Option<Ipv4Addr> {
        self.stopped.remove(&session_id);
        self.hands.remove(&session_id);
        self.own_published
            .remove(&session_id)
            .map(|own| own.address)
    }

    /// Marks a box's host as running: its name answers at its address — the
    /// state every box is in from finalize, so a caller that never saw a stop
    /// changes nothing (NET-011).
    pub fn mark_running(&mut self, session_id: SessionId) {
        if self.stopped.remove(&session_id) {
            tracing::info!(
                session_id = %session_id,
                action = "name-answers",
                "a stopped box's name answers again"
            );
        }
    }

    /// Marks a box's host as stopped (NET-128). The name stays **held** — a
    /// stopped box is never mistaken for one that never existed, so the zone
    /// never says NXDOMAIN for it — but a name it shares with the node answers
    /// NODATA while it is stopped, so the node's own listener at that port is
    /// not silently impersonated by a dead box's declaration. A box at its own
    /// address keeps answering A: that address answers for it alone, and a
    /// client connecting there is told where the box would be.
    pub fn mark_stopped(&mut self, session_id: SessionId) {
        if self.stopped.insert(session_id) {
            tracing::info!(
                session_id = %session_id,
                action = "name-nodata-at-node-address",
                "a stopped box's shared-address name answers NODATA"
            );
        }
    }

    /// The route an `OwnIp` box's name follows: straight to the lease on a VM
    /// host once the box holds one (the daemon is on the switch, NET-001) —
    /// and, before that, at the address the box's declaration publishes on, so
    /// the name is held from finalize (NET-011). On a native host the route
    /// targets **only** the published address (NET-010): the host loopback
    /// address a creator handed this box and its record published — and
    /// nothing else, because the daemon has no default to publish at. A box
    /// nobody handed an address has no route: `None`, the name answers
    /// `Absent` until the creator's hand publishes one, rather than at an
    /// address nobody chose for it. `declared` is the ports-a-request-may-name
    /// set, always a gate for an own-address box — empty when the box declares
    /// no ingress; on a lease route the applied map carries it already, so the
    /// translation and the gate stay one declaration.
    fn own_route(
        &self,
        session_id: SessionId,
        session_name: &str,
        declared: BTreeSet<u16>,
    ) -> Option<Route> {
        if self.on_switch
            && let Some(own) = self.own.get(&session_id)
        {
            return Some(Route::lease(session_name, own.lease, own.ports.clone()));
        }
        self.published_own_address(session_id)
            .map(|address| Route::loopback(session_name, address, Some(declared)))
    }

    /// Withdraws `session_name`'s box name, returning it if one was registered.
    /// Emits the R3.5 `deregistered` tracing event only when an entry is
    /// actually removed, so calling it for an unregistered session is a silent
    /// no-op. The event carries the same stable `session_id` the matching
    /// `registered` event did, and formats `ip` with `Display` to match it.
    pub fn deregister(&mut self, session_name: &str) -> Option<Hostname> {
        let Registration { id, hostname } = self.by_session.remove(session_name)?;
        let route = self
            .by_host
            .remove(&hostname)
            .expect("by_host is kept in sync with by_session by register");
        tracing::info!(
            session_id = %id,
            session_name,
            hostname = %hostname,
            ip = %route.address(),
            action = "deregistered",
            "deregistered PTask hostname"
        );
        Some(hostname)
    }

    /// Withdraws `session_name`'s box name **only if it is still this
    /// session's own registration** — the half of a failed attach that
    /// un-does the name finalize registered (NET-121: a bind that failed is
    /// reported, and the name that says "reachable here" is never left
    /// standing over the ports that are not). Gated by id rather than the
    /// name alone: the same `session_name` is reusable, and a rename that has
    /// already re-registered — or a later session that has taken the name —
    /// must not have its registration withdrawn by this session's failure.
    pub fn withdraw_own_name(&mut self, session_id: SessionId, session_name: &str) {
        let ours = self
            .by_session
            .get(session_name)
            .is_some_and(|registration| registration.id == session_id);
        if !ours {
            return;
        }
        let _ = self.deregister(session_name);
    }

    /// Resolves a `Host:` header to the route a host-side proxy forwards the
    /// request on, or `None` if no live PTask owns that name.
    ///
    /// This is the registry/proxy contract: the per-PTask routing decision is
    /// made here, by hostname. The deprecated three-label form
    /// `<name>.<host-id>.min.internal` resolves to the same entry as
    /// `<name>.min.internal` (NET-002), with a deprecation notice naming the
    /// two-label form — one info line per deprecated three-label request,
    /// routed or not; a refused one is also named by the proxy's refusal warn
    /// line. The header's optional `:port` suffix is ignored and matching is
    /// case-insensitive, matching how a real `Host:` header arrives.
    #[must_use]
    pub fn resolve(&self, host_header: &str) -> Option<Route> {
        let host = host_component(host_header).to_ascii_lowercase();
        let mut route = self.by_host.get(&Hostname(host.clone())).cloned();
        if route.is_none()
            && let Some(two_label) = self.legacy_two_label(&host)
        {
            tracing::info!(
                component = "dns-proxy",
                host,
                two_label,
                "deprecated three-label hostname; use the two-label form"
            );
            route = self.by_host.get(&Hostname(two_label)).cloned();
        }
        route
    }

    /// The two-label name a deprecated three-label one maps to, when `host` is
    /// of the `<name>.<host-id>.min.internal` form (NET-002). The `<host-id>`
    /// label must be one of this registry's own — the daemon's instance id or
    /// `local`: a dotted session name (e.g. `my.app`) renders the two-label
    /// name `my.app.<host-id>.min.internal`, and a suffix match alone would
    /// strip the wrong label. A name that is both a live session's two-label
    /// name and a legacy form is unambiguous only while that session is live —
    /// exact lookups win, so a live dotted name routes to itself and only
    /// falls back to the legacy reading once it is withdrawn.
    fn legacy_two_label(&self, host: &str) -> Option<String> {
        self.host_ids
            .iter()
            .find_map(|id| {
                let legacy_suffix = format!(".{id}.{HOSTNAME_SUFFIX}");
                host.strip_suffix(&legacy_suffix)
                    .filter(|name| !name.is_empty())
            })
            .map(|name| format!("{name}.{HOSTNAME_SUFFIX}"))
    }

    /// The A answer a live route's name carries in the box zone, with the
    /// per-box state applied. The address is the one the box's declaration
    /// publishes at (NET-010) — the host loopback address a creator handed the
    /// box — gate-checked the same way a route's own address is (NET-127).
    ///
    /// A box that is **stopped on a shared address** answers `None` (NET-128):
    /// its name stays held, so the zone never says NXDOMAIN for a box that
    /// exists, but the node's own listener at that port must not answer for a
    /// dead box. A box on its own address keeps answering A — the address
    /// answers for it alone, and the lookup says where the box would be.
    fn zone_answer(&self, route: &Route, node: &[Ipv4Addr]) -> Option<Ipv4Addr> {
        let Some(id) = self
            .by_session
            .get(route.session())
            .map(|registration| registration.id)
        else {
            return route.zone_address(node);
        };
        let address = self
            .own_published
            .get(&id)
            .map(|own| is_host_answerable(own.address, node).then_some(own.address))
            .unwrap_or_else(|| route.zone_address(node));
        if self.stopped.contains(&id) && address.is_some_and(|a| a == self.node) {
            return None;
        }
        address
    }

    /// What the box zone holds for a full zone name (`<name>.min.internal`,
    /// or its deprecated three-label form): the held/absent distinction
    /// [`ZoneEntry`] documents, which is the difference between NODATA and
    /// NXDOMAIN in the answerer's reply (NET-124, NET-125). Matching is the
    /// same case-insensitive lookup — with the same deprecated three-label
    /// fallback — that [`Self::resolve`] routes by (NET-002), so a name
    /// answers exactly while it routes.
    ///
    /// `node` is the set of addresses this daemon's host publishes at (see
    /// [`is_host_answerable`], NET-127).
    #[must_use]
    pub fn zone_entry(&self, host: &str, node: &[Ipv4Addr]) -> ZoneEntry {
        let host = host.to_ascii_lowercase();
        let entry = |route: &Route| ZoneEntry::Held {
            owner: route.session().to_string(),
            address: self.zone_answer(route, node),
        };
        match self.by_host.get(&Hostname(host.clone())) {
            Some(route) => entry(route),
            None => self
                .legacy_two_label(&host)
                .and_then(|two_label| self.by_host.get(&Hostname(two_label)))
                .map_or(ZoneEntry::Absent, entry),
        }
    }

    /// Every live name in the zone as a [`ZoneRow`] — the zone table the
    /// daemon's state dump carries, one row per live name in name order. The
    /// address column is the box's state as a lookup sees it (NET-010,
    /// NET-128): the A answer a host-OS lookup gets — the box's own address
    /// where it has one — or `None` when the name is held at an address the
    /// host may not be told, or at a shared address by a box that is stopped.
    ///
    /// `node` is the set of addresses this daemon's host publishes at (see
    /// [`is_host_answerable`]).
    #[must_use]
    pub fn zone_table(&self, node: &[Ipv4Addr]) -> Vec<ZoneRow> {
        let mut rows: Vec<ZoneRow> = self
            .by_host
            .iter()
            .map(|(name, route)| ZoneRow {
                name: name.as_str().to_string(),
                owner: route.session().to_string(),
                address: self.zone_answer(route, node),
            })
            .collect();
        rows.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        rows
    }
}

/// Extracts the host of a `Host:` header, stripping an optional `:port` suffix.
///
/// Handles both the common `name:port` form and the bracketed IPv6 literal
/// form (`[::1]:8080`), where the port follows the closing bracket rather than
/// the first colon. The registry only ever holds `*.min.internal` names, so an
/// IPv6 literal never routes; parsing it correctly keeps a naive split-on-first-
/// colon from silently truncating `[::1]` to `[`. Shared with [`super::proxy`],
/// which splits the same authority into host and port.
pub(crate) fn host_component(host_header: &str) -> &str {
    if host_header.starts_with('[') {
        // IPv6 literal: the host is everything up to and including the closing
        // bracket; any `:port` follows it.
        host_header
            .find(']')
            .map_or(host_header, |close| &host_header[..=close])
    } else {
        // `name` or `name:port`: the host ends at the first colon.
        host_header.split(':').next().unwrap_or(host_header)
    }
}

// ---------------------------------------------------------------------------
// The answerer's lease record (NET-010): the host-global arbitration.
//
// Allocation in the reserved local range is host-global (design §7.1): one
// owned set per host, arbitrated through the answerer's authenticated
// channel, and no daemon self-assigns. The record below is this host's
// answerer-side half of that: which namespace — a box or the node — holds
// which granted address, written by every node daemon on the host through
// this one type, and read back by each of them on start so a restarted
// daemon re-derives its live grants rather than starting from an empty
// table. "No daemon asks another" holds the way the design means it: a
// daemon's only peer conversation is with the answerer's record, never with
// another daemon.
//
// A bounded interim, stated plainly. This record arbitrates the daemons that
// share one state root — however many native node daemons run beside each
// other on one host, it is their one answerer and no two of them ever hold
// one address. It does **not** arbitrate across roots, and the design's
// LocalVM condition — one owned set per host, whatever the guest — is
// unmet here: a microVM guest's state root is the guest's own, so a second
// root on the same host keeps a second record the first cannot read. Each
// grants from its own pool and neither record names the other's grant, which
// is exactly the cross-root collision NET-010 cannot tolerate. The design's
// authenticated channel — grants written only by owning node daemons
// through it — holds here for the single-operator case this interim covers
// in that writing the record already means holding the filesystem identity
// the daemon state root is protected by. Closing the cross-root half needs
// the host-side answerer as the one arbiter over every root's allocation,
// not a per-root file. That work is outside this change and is filed as
// #1772: the host answerer as the one arbiter over every root's
// allocation, serving the design's authenticated channel (design §7.1,
// the answerer as the arbiter, "cross-node collisions reported at session
// start"). Until it lands the collision report
// ([`LoopbackLeaseBook::unrecorded_publishes`]) is the half this record can
// do on its own: the kernel's socket table is the one list of addresses that
// is global to the whole host whatever record granted them, and every
// reserved-range address a live publish holds that this record does not name
// is reported — once at this daemon's start, and again at every session
// start on it, like a port collision, so a grant a second root's daemon
// makes after this one booted is still reported.

/// The answerer's record of granted addresses, under the daemon's state
/// root — the one directory every daemon instance on this host shares
/// (`minimal_state_dir`; the session store under it is shared the same way,
/// which is what makes a box's session id a host-global key below).
#[cfg(target_os = "linux")]
const LEASE_RECORD_FILE: &str = "loopback-leases.json";

/// The lock file serializing every read-modify-write of the lease record:
/// a plain advisory lock, so two daemons on one host asking at the same
/// moment still hand out two different addresses rather than both reading
/// the same free bit. The lock is per record file, held for one
/// read-modify-write — never across an await, never for a daemon's
/// lifetime.
#[cfg(target_os = "linux")]
const LEASE_LOCK_FILE: &str = "loopback-leases.lock";

/// Who a granted address belongs to: the namespace the answerer budgets one
/// address per (design §7.1 — the budget is per published namespace, a box
/// or a node, never per daemon).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseNamespace {
    /// One box, by the session's stable id — the identifier the session
    /// store keys records by, unique across every daemon instance on the
    /// host, and stable across the daemon restarts a resumed session
    /// survives. *Not* the session's name, which a user may reuse for the
    /// next box the moment this one exits.
    Box { session: SessionId },
    /// The node itself: the one address its host-address boxes answer at and
    /// publish on (NET-129). A native node already owns the host loopback and
    /// asks for nothing; a VM node holds one for its lifetime — granted at its
    /// first daemon's start and re-answered to every daemon the node restarts,
    /// because the node's identity on the host does not change with its
    /// daemon, so its grant is never swept. The state root the node's daemon
    /// runs from is the node for keying it: a guest's root is the guest's own,
    /// so two co-resident VMs hold two grants in two records — the host-side
    /// channel across them is the minvmd answerer's to carry, not this
    /// record's.
    Node,
}

/// One line of the answerer's record: a namespace, the address it holds,
/// and when that was granted.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
struct LeaseEntry {
    namespace: LeaseNamespace,
    address: Ipv4Addr,
    /// The grant's stamp, in Unix seconds — the clock
    /// [`LoopbackLeaseBook::release_dead_boxes`] guards the start sweep
    /// with, so a grant another daemon made while this one was starting is
    /// never read as dead. `#[serde(default)]` keeps a record written
    /// before the field existed reading as stamped at the epoch: older than
    /// every daemon now running, which the sweep treats as unguarded
    /// liveness decides it — the sweep's behaviour before the guard, safe
    /// for the same reason, since no daemon running now granted it.
    #[serde(default)]
    granted_at: u64,
}

/// What asking the answerer for an address comes back with.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackGrant {
    /// The address the namespace holds — granted now, or already in the
    /// record: a namespace that already holds one is answered with it, which
    /// is how a resumed session takes its address back after a restart
    /// without ever holding it in memory.
    Granted(Ipv4Addr),
    /// Every address the answerer may grant on this host is held: the
    /// published-namespace budget is spent. The asker reports it and is
    /// granted nothing — never a reserved-range address another namespace on
    /// this host holds.
    PoolSpent,
    /// The verdict over the reserved local range has not landed yet: the
    /// probe that produces it — on a microVM daemon, the forwarder-conducted
    /// walk [`crate::sessions::Manager::init`] defers so the accept loop is
    /// never held for it — is still running, so nothing has yet vouched for
    /// an address of the range. Every ask is answered this way, one for a
    /// namespace the record already names too: the box publishes on the
    /// interim, its recorded line is kept, and the present landing's re-ask
    /// answers with that line, so a box resumed inside the window gets its
    /// address back (NET-013) without ever standing at it unvouched.
    RangePending,
    /// The reserved local range is not bindable on this host (NET-123's
    /// absent verdict): no address from it can be published, so none is
    /// granted.
    RangeAbsent,
    /// The answerer's record could not be read or written. Grants are
    /// **withheld**: a daemon that guessed would risk granting an address
    /// another namespace already holds — the one failure NET-010 cannot
    /// tolerate — where a withheld grant costs one box its published address.
    RecordUnavailable,
}

#[cfg(target_os = "linux")]
impl LoopbackGrant {
    /// The address a box's declaration publishes at, given this ask's answer
    /// (NET-123): the granted one where the answerer's record names or grants
    /// it, and the `127.0.0.1` interim where the host's publish surface
    /// cannot bind the range — the absent verdict's own arm, and the pending
    /// window's, where nothing has vouched for an address of the range so
    /// none is spent. The interim is recorded as the box's own publish — the
    /// name routes at it and the attach binds its forwards at it — but it is
    /// the surface's answer, never an address the box owns, so it cannot
    /// outstay the window that made it: the walk's landing re-points every
    /// box standing on it when its verdict lands (a present landing re-asks
    /// the grant, an absent one keeps it), and a finalize that finds the box
    /// standing on the interim asks again rather than answering from the
    /// record.
    ///
    /// `None` — publishing nothing, so the attach of a box that declared
    /// ingress fails with "no published address handed" — for the two
    /// answers that are faults rather than facts about the surface: a spent
    /// pool and an unreadable record. Those are reported, never substituted:
    /// standing a box at an address the answerer did not grant would be the
    /// silent fallback NET-121 forbids, and the interim is not one — it is the
    /// surface's own answer about what it can bind.
    #[must_use]
    pub fn publishable_address(self) -> Option<Ipv4Addr> {
        match self {
            LoopbackGrant::Granted(address) => Some(address),
            LoopbackGrant::RangePending | LoopbackGrant::RangeAbsent => Some(Ipv4Addr::LOCALHOST),
            LoopbackGrant::PoolSpent | LoopbackGrant::RecordUnavailable => None,
        }
    }
}

/// The verdict over the reserved local range on this host — NET-123's bind
/// probe's answer, as it stands **right now**, which is why it is a state and
/// not a fact. A daemon that can bind on its own publish surface has the
/// answer before the book opens; a daemon inside a microVM does not, because
/// the surface its publishes bind on is the *host's* loopback, a machine the
/// guest can only measure through the forwarder-conducted walk
/// [`crate::sessions::Manager::init`] defers rather than holding its accept
/// loop for. The book opens holding whichever state the opening daemon is in
/// and the walk applies its own when it lands.
///
/// The state is what a grant waits on, and the one thing that decides whether
/// a namespace the record does not name may be handed an address: a recorded
/// namespace is answered whatever the state, because the address it holds was
/// vouched for by the verdict that granted it (NET-013 — a box resumed while
/// the probe is still walking finds its address waiting, whether the same
/// daemon or a restarted one answers).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeVerdict {
    /// The probe that produces the verdict is still walking: nothing has
    /// vouched for an address of the range yet, so no new one is granted —
    /// the asker publishes on the interim — while a recorded namespace keeps
    /// the address it already holds.
    Pending,
    /// The range binds on the publish surface: grants proceed.
    Present,
    /// The range does not bind (NET-123's absent verdict): no address from it
    /// can be published, so no namespace is granted one, recorded or not.
    Absent,
}

#[cfg(target_os = "linux")]
impl RangeVerdict {
    /// The discriminant the book's atomic verdict holds: one `u8` per state,
    /// so the verdict moves through one store rather than a swap.
    fn key(self) -> u8 {
        match self {
            RangeVerdict::Pending => 0,
            RangeVerdict::Present => 1,
            RangeVerdict::Absent => 2,
        }
    }

    /// The state a stored discriminant names. Only [`Self::key`]'s three
    /// values are ever stored; the fallback reads as the interim state, which
    /// is also the one that grants nothing to a namespace the record does not
    /// name, so a value that cannot have been written still fails safe.
    fn from_key(key: u8) -> Self {
        match key {
            1 => RangeVerdict::Present,
            2 => RangeVerdict::Absent,
            _ => RangeVerdict::Pending,
        }
    }
}

/// The answerer's channel a daemon grants and releases through: the durable
/// half of [`RESERVED_LOCAL_RANGE`]'s allocation, one record per host,
/// guarded by its own lock file, spent through the pure allocator
/// ([`sessions::core::loopback::LoopbackAllocator`]) the injectivity proof
/// covers.
///
/// Every method is a synchronous read-modify-write under the lock file, so a
/// book handle can be shared behind an `Arc` without a second mutex, and two
/// daemons on one host — or two handles in one process, in a test — are
/// serialized by the file system rather than by each other.
///
/// The record's shape is a list of `{"namespace": …, "address": …}` lines,
/// written staged-then-renamed like every other record under the state root
/// (a crash mid-write leaves the last complete record, never a partial
/// one), read leniently, and versioned by its field set: an unknown field is
/// ignored, so a future format can add to it without invalidating a record a
/// live daemon still reads. A record that cannot be parsed withholds grants
/// (see [`LoopbackGrant::RecordUnavailable`]); a record that is simply
/// missing is a host's first boot, and reads as empty.
///
/// Within one state root this record *is* the arbitration: every native node
/// daemon on that root asks it for a lease, and its lock file serializes the
/// asks so no two namespaces receive the same address. Across roots and across
/// the `minvmd` boundary, the host answerer of #1772 is the arbiter, and this
/// book is the per-root cache it will write through. See the module comment
/// for the bound this interim has and the work that closes the cross-root gap.
///
/// The book also carries the half NET-123 §7.1 asks of a registration that
/// holds a hand the verdict has not vouched for: a bounded wait for the
/// verdict to land ([`LoopbackLeaseBook::await_vouch_for`]), so the name
/// publishes once at its final address rather than moving under a live
/// session's clients.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct LoopbackLeaseBook {
    /// The record file, `<state root>/<LEASE_RECORD_FILE>`.
    record: camino::Utf8PathBuf,
    /// The staged sibling the record is written through, before its rename.
    staging: camino::Utf8PathBuf,
    /// The lock file's open handle, held for the book's lifetime so the
    /// flock is one `open()` per daemon, not one per grant. Behind a
    /// `Mutex` because `fd_lock`'s `write` API takes `&mut` — the mutex
    /// serializes books sharing one process, the flock inside it books
    /// sharing one host.
    ///
    /// The handle is **read-only**: `flock` asks the kernel about the file
    /// rather than through it, so the lock holds with no write access, and
    /// a write-open descriptor on the state volume is one the quiesce
    /// contract forbids at shutdown — a live write-open fd at unmount time
    /// is what defeats the journal's clean-replay check and wedges the
    /// volume read-only on the next boot. That contract is also why the
    /// field is an `Option`: [`LoopbackLeaseBook::close`] — called from the
    /// manager's shutdown arm, beside the cache's read-tracker release —
    /// takes the handle and drops it, so the daemon's stop leaves the state
    /// volume with no descriptor the book holds open.
    lock: std::sync::Mutex<Option<fd_lock::RwLock<std::fs::File>>>,
    /// The verdict over the reserved local range on this host, as it stands
    /// right now: the daemon-start bind probe's (NET-123), applied once at
    /// start — or, on a host whose publish surface the probe can only reach
    /// through the forwarder, once that walk lands, by
    /// [`LoopbackLeaseBook::set_range_verdict`]. A landed absent verdict gates
    /// every ask ([`LoopbackGrant::RangeAbsent`]: the addresses this book
    /// would grant are not publishable, so none is spent); a pending one
    /// answers every ask with the interim ([`LoopbackGrant::RangePending`]),
    /// so no box is published at an address nothing has vouched for — a box
    /// the record already names keeps its line, and the present landing
    /// restores it to that address (NET-013).
    verdict: std::sync::atomic::AtomicU8,
    /// The verdict's landing, broadcast to the registrations waiting on it
    /// ([`LoopbackLeaseBook::await_vouch_for`]): the atomic above is the
    /// zero-latency read the synchronous paths (the grant, the vouch) take,
    /// and this is the wake-up the one async path takes, so a registration
    /// holding an unvouched hand is woken by the landing rather than polling
    /// for it. Seeded with the verdict the book opens on and moved beside
    /// the atomic by [`LoopbackLeaseBook::set_range_verdict`], so the two
    /// never disagree.
    verdict_landing: tokio::sync::watch::Sender<RangeVerdict>,
    /// The moment this book opened — the daemon's start, for the one book a
    /// daemon opens — which [`Self::hand_verdict_deadline`] is counted from.
    opened_at: std::time::Instant,
    /// The daemon's one verdict deadline, in milliseconds after
    /// `opened_at`: [`HAND_VERDICT_WAIT`] at open. Every registration that
    /// waits in [`LoopbackLeaseBook::await_vouch_for`] races this same
    /// instant, so waiters started at different moments all return together
    /// when the verdict lands or the deadline passes, and the waits never
    /// add up. An atomic because the wait is async and the setter is
    /// test-only.
    hand_verdict_deadline: std::sync::atomic::AtomicU64,
}

/// How long after the daemon starts — after its lease book opens — a box's
/// first finalize holding an unvouched hand may wait for the range verdict
/// to land (NET-123 §7.1). It is one deadline for the whole daemon, not a
/// per-call wait: the deferred walk starts with the daemon, so a verdict
/// that has not landed this long after the start is not one a session's
/// start should be held for, and every waiter is answered by the same
/// instant. A verdict that lands inside it publishes the hand; one that
/// does not publishes the `127.0.0.1` interim, which the present landing's
/// sweep upgrades to the hand it then vouches for. Test-only code moves
/// the deadline ([`LoopbackLeaseBook::reset_hand_verdict_deadline`]) so the
/// expiry shape is proven without paying it.
#[cfg(target_os = "linux")]
pub(crate) const HAND_VERDICT_WAIT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
impl LoopbackLeaseBook {
    /// Opens this host's book under `state_root`, binding its lock file.
    ///
    /// `verdict` is the state the reserved local range's probe stands in as
    /// this book opens: [`RangeVerdict::Present`] or [`RangeVerdict::Absent`]
    /// where the probe has answered — a native daemon's own loopback is its
    /// publish surface, so it reads the answer before it gets here — and
    /// [`RangeVerdict::Pending`] where it has not, the microVM daemon's
    /// shape, whose walk is deferred so its accept loop is never held for it.
    /// See [`LoopbackGrant::RangePending`] for how the pending state answers
    /// an ask. The book's opening also starts the daemon's one verdict
    /// deadline ([`HAND_VERDICT_WAIT`]).
    ///
    /// # Errors
    ///
    /// Propagates the failure to create or open the lock file — the one
    /// artefact the book cannot run without, since without it two daemons
    /// cannot arbitrate.
    pub fn open(state_root: &paths::DaemonAbsPath, verdict: RangeVerdict) -> std::io::Result<Self> {
        let record = state_root
            .sub_path_unchecked(LEASE_RECORD_FILE)
            .as_utf8_path()
            .to_path_buf();
        let staging = camino::Utf8PathBuf::from(format!("{record}.tmp"));
        let lock_path = state_root
            .sub_path_unchecked(LEASE_LOCK_FILE)
            .as_utf8_path()
            .to_path_buf();
        // Created once, then reopened read-only with the creating handle
        // dropped at once. The lock file is opened — not locked: the flock
        // is taken per read-modify-write, so two daemons on one host
        // serialize per grant rather than for their lifetimes. And the
        // handle the book keeps for its lifetime is read-only on purpose:
        // `flock` needs no write access, and this is the one fd the book
        // holds open across its life, so it must not be the write-open
        // descriptor on the state volume that defeats the quiesce contract
        // at shutdown — see the field's doc and [`Self::close`].
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path.as_std_path())?;
        let lock = std::fs::File::open(lock_path.as_std_path()).map(fd_lock::RwLock::new)?;
        let (verdict_landing, _) = tokio::sync::watch::channel(verdict);
        Ok(Self {
            record,
            staging,
            lock: std::sync::Mutex::new(Some(lock)),
            verdict: std::sync::atomic::AtomicU8::new(verdict.key()),
            verdict_landing,
            opened_at: std::time::Instant::now(),
            hand_verdict_deadline: std::sync::atomic::AtomicU64::new(
                HAND_VERDICT_WAIT.as_millis() as u64
            ),
        })
    }

    /// Closes the book's lock-file handle, so a daemon shutting down leaves
    /// the state volume with no descriptor the book holds open — the same
    /// quiesce contract the cache's read-tracker release serves in the
    /// manager's shutdown arm, which calls this beside it.
    ///
    /// After a close every method answers as over a closed book: grants
    /// withhold ([`LoopbackGrant::RecordUnavailable`]), and releases,
    /// sweeps, and collision reports report nothing — which is the
    /// shutdown-time answer anyway, since the manager stops every session
    /// before it closes the book. Closing an already-closed book is a
    /// no-op.
    pub fn close(&self) {
        drop(self.lock.lock().ok().and_then(|mut held| held.take()));
    }

    /// The verdict over the reserved local range on this host, as it stands
    /// right now — what every grant is gated on.
    ///
    /// An interior read rather than a field because the verdict is not always
    /// known when the book opens: a daemon inside a microVM can only measure
    /// its publish surface through the host's forwarder, and that walk takes
    /// long enough that the daemon must not hold its accept loop for it (see
    /// [`crate::sessions::Manager::init`]), so the book opens on the pending
    /// verdict and the walk applies its own when it lands.
    fn verdict(&self) -> RangeVerdict {
        RangeVerdict::from_key(self.verdict.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Applies the bind probe's verdict over the reserved local range, when
    /// the book opened before the probe that produced it could answer.
    ///
    /// The one transition this exists for is the deferred forwarder-conducted
    /// walk of a microVM daemon ([`crate::net::policy::probe_publish_surface`]):
    /// the book opens holding the pending verdict — so nothing is *freshly*
    /// granted at an address nothing has vouched for — and the walk, once it
    /// has an answer, applies it here. Only the verdict moves: no grant is
    /// made or taken back by this call, and a book that already holds the
    /// verdict it is asked for changes nothing. The move is broadcast beside
    /// the store, so a registration waiting on
    /// [`Self::await_vouch_for`] is woken by it.
    pub fn set_range_verdict(&self, verdict: RangeVerdict) {
        self.verdict
            .store(verdict.key(), std::sync::atomic::Ordering::Release);
        // `send_replace` — not `send`: a watch `send` with no receiver
        // subscribed is dropped on the floor by the channel itself, and a
        // landing often arrives while nothing waits on it (no session, or
        // every box standing on the interim), so the registration that
        // subscribes afterwards must still read the verdict that landed.
        self.verdict_landing.send_replace(verdict);
    }

    /// The daemon's one verdict deadline, as an instant: the moment the book
    /// opened plus [`HAND_VERDICT_WAIT`] (or the instant a test moved it to).
    fn hand_verdict_deadline(&self) -> std::time::Instant {
        self.opened_at
            + std::time::Duration::from_millis(
                self.hand_verdict_deadline
                    .load(std::sync::atomic::Ordering::Acquire),
            )
    }

    /// Waits for the verdict to vouch for `address`, bounded by the daemon's
    /// one verdict deadline (NET-123 §7.1) — the path a handed box's first
    /// finalize takes when the verdict it must be vouched by has not landed
    /// yet.
    ///
    /// A verdict already landed answers at once: **present** vouches for an
    /// address of the range, **absent** does not, and an address outside the
    /// range needs no verdict either way. Only a **pending** verdict waits,
    /// and only until the deadline — the same instant for every waiter,
    /// counted from the daemon's start ([`HAND_VERDICT_WAIT`]), so waiters
    /// never add up and all return together. A walk that has not answered by
    /// then is answered as "not vouched", so the caller publishes the
    /// `127.0.0.1` interim rather than holding the session's start for a
    /// probe the landing sweep will settle the moment it lands. A waiter
    /// woken late re-reads the verdict before the deadline decides, so a
    /// verdict landing in the same instant as the bound is still answered by
    /// the verdict, not by the clock.
    pub async fn await_vouch_for(&self, address: Ipv4Addr) -> bool {
        if !in_reserved_local_range(address) {
            return true;
        }
        let deadline = tokio::time::Instant::from_std(self.hand_verdict_deadline());
        let mut landing = self.verdict_landing.subscribe();
        loop {
            match *landing.borrow_and_update() {
                RangeVerdict::Present => return true,
                RangeVerdict::Absent => return false,
                RangeVerdict::Pending => {}
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                // The bound spent and the verdict still walking: answered as
                // not vouched, so the caller publishes the interim — the
                // landing's sweep upgrades it when the walk finally lands.
                return false;
            }
            if tokio::time::timeout_at(deadline, landing.changed())
                .await
                .is_err()
            {
                return false;
            }
        }
    }

    /// Moves the daemon's one verdict deadline to `millis` from now, so a
    /// test drives the expiry shape without paying the real deadline, or
    /// holds a window open long enough to tell "waited" from "did not".
    ///
    /// Test-only: no production path changes a deadline it is itself bounded
    /// by, and one that did would want a message, not a setter.
    #[cfg(test)]
    pub fn reset_hand_verdict_deadline(&self, millis: u64) {
        let from_open = self.opened_at.elapsed().as_millis() as u64;
        self.hand_verdict_deadline
            .store(from_open + millis, std::sync::atomic::Ordering::Release);
    }

    /// How many registrations are parked in [`Self::await_vouch_for`] right
    /// now: the subscribers of the verdict's landing broadcast. The book's
    /// own receiver is dropped at open, so every receiver counted is a
    /// waiter.
    ///
    /// Test-only: a test polls it before landing a verdict, so the landing
    /// provably answers a waiter rather than a registration that has not
    /// begun to wait.
    #[cfg(test)]
    pub fn verdict_waiters(&self) -> usize {
        self.verdict_landing.receiver_count()
    }

    /// Whether `address` may be published as a box's own under the verdict
    /// this book holds (NET-123 §7.1): the gate a handed address goes
    /// through before it stands in for a lease.
    ///
    /// An address outside the reserved local range needs no vouching — the
    /// hand that carried it chose it — while one from the range is
    /// publishable only once the host's publish surface has *measured* the
    /// range bindable. The measurement is the one this book holds: the
    /// daemon-start probe's on a native host, the forwarder-conducted walk's
    /// on a microVM one — and **only a landed present verdict vouches**. A
    /// pending one does not, because the VM host daemon hands slice
    /// addresses of the range without measuring the host's loopback at all
    /// — the root fix is the host daemon measuring before it hands (#1818),
    /// this gate the interim until it lands — so a hand's provenance (the
    /// host-side table row, which a resumed box keeps its address on,
    /// NET-013) is not a measurement, and a box that published it verbatim
    /// inside the window would bind its declared ports at an address the
    /// surface may refuse at every bind: `EADDRNOTAVAIL` on a stock macOS
    /// host, exactly the refusal the verdict exists to keep a box from
    /// publishing at. A box's first finalize therefore waits for the
    /// verdict ([`Self::await_vouch_for`]) before it gives up on the hand,
    /// bounded by the daemon's one verdict deadline, and publishes the
    /// interim only when the wait answers unvouched — an absent verdict, or
    /// a walk that has not landed by the deadline; every other registration
    /// reads the gate as it stands. With the verdict against it the hand
    /// publishes nothing and the box stands at the interim — and the gate
    /// reads the record the same way it reads the hand: a publish standing at an
    /// unvouched address asks again rather than standing at it, so no box
    /// holds an address a landed verdict contradicts.
    #[must_use]
    pub fn vouches_for(&self, address: Ipv4Addr) -> bool {
        !in_reserved_local_range(address) || self.verdict() == RangeVerdict::Present
    }

    /// Grants `namespace` an address from the host's pool, or answers with
    /// the one it already holds.
    ///
    /// The whole grant is one read-modify-write under the record's lock:
    /// read the record, restore the allocator from the addresses it names,
    /// lease the lowest free address (never the answerer's own), write the
    /// record back with the new line. A record that cannot be read or
    /// written withholds the grant rather than risking an address another
    /// namespace holds.
    ///
    /// The ask is idempotent by namespace, which is what lets a caller ask
    /// before taking its own registry lock: two paths asking for the same
    /// namespace — a rename racing a finalize — are both answered with the
    /// one address, the second by the line the first wrote.
    ///
    /// Only a **landed present** verdict lets the ask reach the record. A
    /// landed absent one answers [`LoopbackGrant::RangeAbsent`] (NET-123: an
    /// address the publish surface cannot bind is not grantable, to a
    /// namespace that holds one any more than to one that does not), and a
    /// pending one answers [`LoopbackGrant::RangePending`] — for a namespace
    /// the record names too: the verdict that granted that address was an
    /// earlier daemon's, and nothing has measured this daemon's surface yet,
    /// so no reserved-range address publishes under anything but a landed
    /// present. The record is left as it is, so the resumed box's line
    /// survives the window and the present landing's re-ask answers with it
    /// (NET-013).
    pub fn grant(&self, namespace: LeaseNamespace) -> LoopbackGrant {
        match self.verdict() {
            RangeVerdict::Present => {}
            RangeVerdict::Absent => return LoopbackGrant::RangeAbsent,
            RangeVerdict::Pending => return LoopbackGrant::RangePending,
        }
        let Ok(mut held) = self.lock.lock() else {
            return LoopbackGrant::RecordUnavailable;
        };
        let Some(lock) = held.as_mut() else {
            // The book was closed for shutdown: nothing more is granted.
            return LoopbackGrant::RecordUnavailable;
        };
        let Ok(_flock) = lock.write() else {
            return LoopbackGrant::RecordUnavailable;
        };
        let Ok(mut entries) = self.read() else {
            return LoopbackGrant::RecordUnavailable;
        };
        // The namespace may already hold an address — a resumed session
        // asking again after a restart, or a re-finalize. Answering with the
        // recorded one is what keeps a box's address stable across the
        // restart, and costs no second line in the record.
        if let Some(address) = entry_address(&entries, namespace) {
            // A stale or hand-edited record can map two namespaces to one
            // address. Refusing a recorded namespace would strand its resumed
            // box, so the grant stands and the duplicate is warned about at
            // the moment it would otherwise go unnoticed.
            if let Some(other) = namespace_holding(&entries, address, namespace) {
                tracing::warn!(
                    namespace = ?namespace,
                    other_namespace = ?other,
                    ip = %address,
                    action = "loopback-grant-collision",
                    "a recorded namespace shares its address with another namespace; \
                     granting rather than stranding it",
                );
            }
            return LoopbackGrant::Granted(address);
        }
        // The pool the record's addresses are drawn against: the pure
        // allocator's restore ignores anything outside it, so a stale or
        // hand-edited record can only narrow what a grant may take.
        let mut owned = LoopbackAllocator::restore(entries.iter().map(|entry| entry.address));
        let Some(address) = owned.lease() else {
            return LoopbackGrant::PoolSpent;
        };
        entries.push(LeaseEntry {
            namespace,
            address,
            granted_at: unix_now_secs(),
        });
        // A failed write leaves the record as it was, so the namespace's
        // address stays unrecorded and the next ask grants a fresh one — the
        // failed grant leaks nothing. The caller must not publish an address
        // the record does not name.
        if self.write(&entries).is_err() {
            return LoopbackGrant::RecordUnavailable;
        }
        LoopbackGrant::Granted(address)
    }

    /// Returns the address `namespace` holds to the pool, and reports which
    /// address that was.
    ///
    /// `None` — and no change — when the namespace holds nothing this
    /// record names, or when the record cannot be read: a release that
    /// cannot see the record cannot rewrite it, and leaving the line in
    /// place only costs one address, where removing it blind could free one
    /// another namespace now holds.
    #[must_use]
    pub fn release(&self, namespace: LeaseNamespace) -> Option<Ipv4Addr> {
        let Ok(mut held) = self.lock.lock() else {
            return None;
        };
        let lock = held.as_mut()?;
        let _flock = lock.write().ok()?;
        let mut entries = self.read().ok()?;
        let index = entries
            .iter()
            .position(|entry| entry.namespace == namespace)?;
        let address = entries.remove(index).address;
        self.write(&entries).ok()?;
        Some(address)
    }

    /// Re-derives the record from the sessions that are still live: every
    /// box whose session is gone from `live` loses its grant, and the
    /// addresses it freed come back.
    ///
    /// The start-time half of the record's durability: a daemon that restarts
    /// does not start from an empty table — it adopts every live box's line
    /// as it re-registers their names — but a box whose session was destroyed
    /// while no daemon was running must not keep its address, or a host that
    /// cycles its boxes would run the pool down without a live box on it.
    /// `live` is the session store's set of ids, which is shared by every
    /// daemon on the host the same way this record is, so the sweep is the
    /// answerer's own view of liveness, not one daemon's.
    ///
    /// `daemon_start` is the moment this daemon began starting, in the Unix
    /// seconds the record stamps grants with, and it bounds the sweep: a
    /// line stamped at or after it is one some daemon granted while this one
    /// was starting — the race the liveness snapshot alone cannot see, since
    /// another daemon's fresh grant is for a session this daemon read the
    /// store before — so the sweep leaves such lines to liveness, and
    /// nothing is freed that a live neighbour may just have handed out. A
    /// line stamped before it predates this daemon, so no daemon granted it
    /// while this one was starting, and liveness alone decides it. A line
    /// with no stamp — a record written before the field existed — reads as
    /// stamped at the epoch: old, so the sweep decides it, which is the
    /// guardless behaviour and is safe for the same reason.
    ///
    /// Returns the addresses it freed, for the start line that reports them;
    /// a record it could not read or write sweeps nothing and answers empty,
    /// since grants are withheld for the same failure.
    #[must_use]
    pub fn release_dead_boxes(
        &self,
        live: &BTreeSet<SessionId>,
        daemon_start: u64,
    ) -> Vec<Ipv4Addr> {
        let Ok(mut held) = self.lock.lock() else {
            return Vec::new();
        };
        let Some(lock) = held.as_mut() else {
            return Vec::new();
        };
        let Ok(_flock) = lock.write() else {
            return Vec::new();
        };
        let mut entries = match self.read() {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(
                    record = %self.record,
                    error = %error,
                    "the answerer's lease record could not be read at start; grants are withheld",
                );
                return Vec::new();
            }
        };
        let before = entries.len();
        let freed: Vec<Ipv4Addr> = entries
            .iter()
            .filter(|entry| match entry.namespace {
                // The node's grant is for the node's lifetime, not a
                // session's: never swept, whatever liveness says.
                LeaseNamespace::Node => false,
                LeaseNamespace::Box { session } => {
                    !live.contains(&session) && entry.granted_at < daemon_start
                }
            })
            .map(|entry| entry.address)
            .collect();
        entries.retain(|entry| match entry.namespace {
            LeaseNamespace::Node => true,
            LeaseNamespace::Box { session } => {
                live.contains(&session) || entry.granted_at >= daemon_start
            }
        });
        if entries.len() == before || self.write(&entries).is_err() {
            // Nothing swept, or the sweep could not be written back: either
            // way the record stands, and the next start sweeps again.
            return Vec::new();
        }
        freed
    }

    /// The reserved-range addresses a live publish is holding on this host
    /// that this record does not name — the cross-record collision report
    /// (NET-010, design §7.1: reported at session start, like a port
    /// collision).
    ///
    /// A publish is a listener: a box's gvproxy holds one bind at
    /// `address:port` for every port it publishes, from finalize until it
    /// exits. The kernel's table of listening sockets is therefore the one
    /// list of what is actually published that is global to the whole host
    /// whatever record file granted each bind — which is what makes this the
    /// second root's check: two state roots on one host keep two records,
    /// the second daemon grants `.2` again, neither record names the other's
    /// grant, and `EADDRINUSE` never tells either daemon (the collision is
    /// on the address, not a port) — but both binds are in the one kernel
    /// table this reads. An address this record does name is the record's
    /// own grant, reported by nobody; an address with a listener the record
    /// does not name is reported, for the start line the manager logs and
    /// the operator acts on.
    ///
    /// Reading the record under its lock keeps the report from firing on
    /// this host's own mid-grant boxes: the grant writes the record's line
    /// before the box publishes, so a listener on an unnamed address is
    /// never a grant still between the write and the publish — and the lock
    /// is held across the socket-table read too, so the record's view and
    /// the table's are one moment: a peer that grants and publishes between
    /// two unlocked reads would appear in the older record as absent and in
    /// the newer table as listening, and be reported once as a collision
    /// that is not one. In a microVM
    /// guest the socket table is the guest's own network namespace, so no
    /// host-side publish appears and this answers empty — the same LocalVM
    /// boundary the record has (see the module comment): the cross-root
    /// report across co-resident guests is the host-side answerer's to
    /// carry.
    ///
    /// Reports nothing — like the sweep — when the book is closed for
    /// shutdown or the record cannot be read: the sweep already logged the
    /// latter's advisory, and a report that cannot see the record must not
    /// guess what it names.
    #[must_use]
    pub fn unrecorded_publishes(&self) -> Vec<Ipv4Addr> {
        let Ok(mut held) = self.lock.lock() else {
            return Vec::new();
        };
        let Some(lock) = held.as_mut() else {
            return Vec::new();
        };
        let Ok(_flock) = lock.write() else {
            return Vec::new();
        };
        let Ok(entries) = self.read() else {
            return Vec::new();
        };
        let recorded: BTreeSet<Ipv4Addr> = entries.iter().map(|entry| entry.address).collect();
        // The flock is still held here — see the doc above: the record's view
        // and the kernel's are one moment, or a peer's grant that lands
        // between the two reads is reported as a collision it is not.
        listening_reserved_range_addresses()
            .filter(|address| !recorded.contains(address))
            .collect()
    }

    /// Reads the record, or `Err` when it cannot be trusted: a missing file
    /// is a host's first boot and reads as empty; anything else that cannot
    /// be parsed withholds.
    fn read(&self) -> std::io::Result<Vec<LeaseEntry>> {
        match std::fs::read(&self.record) {
            Ok(bytes) => {
                // Empty (or whitespace-only, for a file someone touched):
                // nothing granted, rather than a parse failure.
                if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
                    return Ok(Vec::new());
                }
                serde_json_lenient::from_slice(&bytes).map_err(std::io::Error::other)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    /// Writes the record staged-then-renamed, so a crash mid-write leaves
    /// the last complete record rather than a partial one — the same
    /// crash-safety every other record under the state root is written with.
    fn write(&self, entries: &[LeaseEntry]) -> std::io::Result<()> {
        let file = std::fs::File::create(&self.staging)?;
        serde_json_lenient::to_writer(&file, &entries)?;
        file.sync_all()?;
        drop(file);
        #[cfg(target_os = "linux")]
        common::renameat2::renameat2_cwd(self.staging.as_std_path(), self.record.as_std_path(), 0)?;
        #[cfg(not(target_os = "linux"))]
        std::fs::rename(&self.staging, &self.record)?;
        Ok(())
    }
}

/// The address `namespace` holds in the record, if any.
#[cfg(target_os = "linux")]
fn entry_address(entries: &[LeaseEntry], namespace: LeaseNamespace) -> Option<Ipv4Addr> {
    entries
        .iter()
        .find(|entry| entry.namespace == namespace)
        .map(|entry| entry.address)
}

/// The first namespace other than `exclude` that holds `address` in the
/// record, if any — the other half of a duplicate-address collision.
#[cfg(target_os = "linux")]
fn namespace_holding(
    entries: &[LeaseEntry],
    address: Ipv4Addr,
    exclude: LeaseNamespace,
) -> Option<LeaseNamespace> {
    entries
        .iter()
        .find(|entry| entry.namespace != exclude && entry.address == address)
        .map(|entry| entry.namespace)
}

/// One warn line for `address`, a reserved local address a live publish
/// holds on this host that no grant in this daemon's record names
/// (NET-010) — the line both collision reports emit, the daemon's start and
/// a session's, so the two say the same thing the same way and a
/// diagnostics bundle's daemon-log tail reads them as one report.
#[cfg(target_os = "linux")]
pub(crate) fn warn_publish_collision(address: Ipv4Addr) {
    tracing::warn!(
        ip = %address,
        action = "loopback-publish-collision",
        "a live publish holds a reserved local address no grant in \
         this state root's record names; another state root's daemon \
         may be publishing at it",
    );
}

/// The wall clock the record stamps grants with, in Unix seconds — the same
/// clock a daemon stamps its own start with (the stamp the manager passes
/// to [`LoopbackLeaseBook::release_dead_boxes`]), so the sweep's
/// [`LeaseEntry::granted_at`] guard compares like with like. `0` on a host
/// whose clock reports a moment before the epoch: the stamp of "older than
/// any daemon now running", which the sweep reads as sweepable.
///
/// One clock for both stamps is the whole contract, so this is the only
/// definition — the daemon-start stamp and the grant stamp must never come
/// from two clocks, or the guard's "at or after this daemon's start" is
/// measured against a start that means something else.
#[cfg(target_os = "linux")]
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The reserved local range's addresses that a listening socket holds on
/// this host right now, read from the kernel's socket tables — the one list
/// of what is published that is global to the whole host, whatever record
/// file granted each bind. See [`LoopbackLeaseBook::unrecorded_publishes`]
/// for what the list is for; the tables are this host's own network
/// namespace, which in a microVM guest is the guest's.
#[cfg(target_os = "linux")]
fn listening_reserved_range_addresses() -> impl Iterator<Item = Ipv4Addr> {
    let mut seen = BTreeSet::new();
    for (table, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(table) else {
            // The table itself missing — a kernel with it disabled — reads
            // as "nothing is published", not as a failure to look: there is
            // nothing to report either way.
            continue;
        };
        // The first line is the table's header.
        for line in text.lines().skip(1) {
            let Some(address) = listen_local_v4(line, v6) else {
                continue;
            };
            if in_reserved_local_range(address) {
                seen.insert(address);
            }
        }
    }
    seen.into_iter()
}

/// The local IPv4 address of one line of the kernel's socket table, or
/// `None` for any other line: the header, a truncated row, a socket in any
/// state but `TCP_LISTEN` — an established or time-wait socket at an
/// in-range address is a client of a publish, not a publish — or a v6
/// address that is not the v4-mapped shape, which names no IPv4 address.
#[cfg(target_os = "linux")]
fn listen_local_v4(line: &str, v6: bool) -> Option<Ipv4Addr> {
    let mut fields = line.split_whitespace();
    // `sl:` — the table's index column, always first.
    fields.next()?;
    let local = fields.next()?;
    // `rem_address`, then `st`: `0A` is `TCP_LISTEN`.
    let _remote = fields.next()?;
    if fields.next()? != "0A" {
        return None;
    }
    let word = if v6 {
        // Four little-endian 32-bit words. Only the v4-mapped shape names an
        // IPv4 address: two zero words, the `::ffff:0:0/96` marker
        // (`0xFFFF0000` printed little-endian), then the address in the
        // last word. `get` reads every slice out of bounds as `None`, so a
        // short or malformed row is skipped, never panicked on.
        if local.get(..16) != Some("0000000000000000")
            || local.get(16..24) != Some("FFFF0000")
            || local.get(32..33) != Some(":")
        {
            return None;
        }
        local.get(24..32)?
    } else {
        // The one little-endian word, then the port.
        if local.get(8..9) != Some(":") {
            return None;
        }
        local.get(..8)?
    };
    // The kernel prints each 32-bit word little-endian, so the address is
    // the byte-swapped word: `0100007F` reads as `127.0.0.1`.
    Some(Ipv4Addr::from(
        u32::from_str_radix(word, 16).ok()?.swap_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lease an attach path would report, with an `18080:8080` ingress
    /// declaration behind it.
    fn leased_ports() -> BTreeMap<u16, u16> {
        BTreeMap::from([(18080, 8080)])
    }

    /// NET-072's name boundary: the zone the gate carves out of the
    /// infrastructure deny set is the zone's own apex and the names under it —
    /// never a name that merely carries the zone's words. The matcher mirrors
    /// the answerer's `in_zone` suffix match, so the two layers cannot drift
    /// apart on a lookalike.
    #[test]
    fn is_zone_name_matches_the_zone_apex_and_its_names_only() {
        assert!(is_zone_name(HOSTNAME_SUFFIX), "the apex is the zone");
        assert!(is_zone_name("web.min.internal"), "a box name is the zone");
        assert!(
            is_zone_name("host.min.internal"),
            "the host record is the zone"
        );
        assert!(
            is_zone_name("web.local.min.internal"),
            "the deprecated three-label form is the zone too (NET-002)"
        );
        // Lookalikes are not: the zone's words inside a longer name, or glued
        // to a label without the separating dot.
        assert!(!is_zone_name("min.internal.example.com"));
        assert!(!is_zone_name("web.min.internal.example.com"));
        assert!(!is_zone_name("webmin.internal"));
        assert!(!is_zone_name("example.com"));
        assert!(!is_zone_name(""), "no name is no zone");
    }

    /// Proof artifact 1 (registry/proxy contract): registering a `HostNet`
    /// PTask makes the host-side proxy route its `Host:` header to `127.0.0.1`;
    /// deregistering withdraws it so the proxy no longer routes it. `*.min.internal`
    /// is synthesized to loopback statically by the resolver, so this asserts the
    /// registry/proxy routing contract, not a `getaddrinfo` lifecycle.
    #[test]
    fn host_net_registration_routes_by_host_header_then_withdraws() {
        let mut reg = HostnameRegistry::new("dev", false);

        let hostname = reg.register_host_net(SessionId::nil(), "myservice");
        assert_eq!(hostname.as_str(), "myservice.min.internal");

        // The host-side proxy routes a request by its `Host:` header to the PTask
        // — with or without the `:port` a real header carries.
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(
            reg.resolve("myservice.min.internal")
                .map(|r| r.upstream(8080)),
            Some(Some(loopback))
        );
        assert_eq!(
            reg.resolve("myservice.min.internal:8080")
                .map(|r| r.upstream(8080)),
            Some(Some(loopback))
        );
        assert_eq!(
            reg.resolve("myservice.min.internal")
                .map(|r| r.session().to_string()),
            Some("myservice".to_string())
        );

        // After the session exits the entry is gone and the proxy no longer
        // routes it.
        let removed = reg
            .deregister("myservice")
            .expect("hostname was registered");
        assert_eq!(removed.as_str(), "myservice.min.internal");
        assert_eq!(reg.resolve("myservice.min.internal"), None);
    }

    /// An `OwnIp` box's name is **held from finalize**, before any client
    /// attaches (NET-011, NET-013): it registers at the address its creator
    /// handed — the published address the registry kept for it (NET-010) —
    /// and at nothing else, because the daemon has no address of its own to
    /// stand in with: a box nobody handed an address registers no name at
    /// all. The attach path's report carries the lease the box attached with
    /// (NET-001); on a native host (off the switch) the route keeps the
    /// published-loopback model — the requested port is the published
    /// external one (R3.1) — and the session's re-registration carries the
    /// same declared ports the attach path's map applied (NET-069). The
    /// lease and the publish are both kept by the stable session id, so a
    /// rename re-registers without a fresh report or a fresh address, and
    /// only the session's end drops them.
    #[test]
    fn own_ip_name_is_held_from_finalize_at_the_published_address() {
        let mut reg = HostnameRegistry::new("dev", false);

        // A box nobody handed an address registers no name: no default
        // publish exists to stand in — the name is absent, not answered at
        // an address nobody chose for it.
        assert_eq!(
            reg.register_own_ip(id("1"), "bare", declared_ports()),
            None,
            "no address handed, no registration"
        );
        assert_eq!(reg.resolve("bare.min.internal"), None, "the name is absent");
        assert_eq!(
            reg.zone_entry("bare.min.internal", &[]),
            ZoneEntry::Absent,
            "a lookup says NXDOMAIN, the honest answer for a name nothing routes"
        );

        // Finalize, with no client attached: the creator's hand has published
        // the box's address (T66's registration handed it), and the
        // registration that follows holds the name at exactly that address.
        let own = Ipv4Addr::new(127, 0, 64, 9);
        assert!(
            reg.publish_own_address(SessionId::nil(), "web", own, declared_ports())
                .is_empty(),
            "a box on its own address collides with nothing"
        );
        let hostname = reg
            .register_own_ip(SessionId::nil(), "web", declared_ports())
            .expect("the name is held at finalize");
        assert_eq!(hostname.as_str(), "web.min.internal");
        let route = reg.resolve("web.min.internal").expect("the name routes");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(own), 18080))
        );
        assert_eq!(
            route.upstream(9000),
            None,
            "a port outside the declaration routes nowhere, attached or not"
        );
        assert_eq!(route.session(), "web");

        // The attach path reports the lease with the box's ingress
        // declaration. On a native host the route keeps the published address:
        // the published external port is carried in the URL, and the
        // forwarder sits on the box's own address at that same published
        // port.
        let hostname = reg
            .report_own_address(SessionId::nil(), "web", Ipv4Addr::LOCALHOST, leased_ports())
            .expect("the report registers the name at the published address");
        assert_eq!(hostname.as_str(), "web.min.internal");
        let route = reg
            .resolve("web.min.internal")
            .expect("routes after the report");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(own), 18080))
        );
        assert_eq!(route.session(), "web");

        // A rename withdraws and re-registers against the same lease and the
        // same published address, passing the session's declared ports as the
        // session actor does.
        reg.deregister("web");
        assert!(
            reg.register_own_ip(SessionId::nil(), "web", declared_ports())
                .is_some()
        );
        let route = reg
            .resolve("web.min.internal")
            .expect("routes after the re-registration");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(own), 18080)),
            "the re-registration carries the same declared ports and address"
        );

        // At session end the publish and the lease fact are dropped with the
        // name: nothing of the destroyed box's routes or addresses survives.
        assert_eq!(
            reg.unpublish_own_address(SessionId::nil()),
            Some(own),
            "the destroy path gets the address back to release into the allocator"
        );
        reg.forget_own_address(SessionId::nil());
        assert_eq!(
            reg.deregister("web").map(|h| h.as_str().to_string()),
            Some("web.min.internal".to_string())
        );
        assert_eq!(reg.resolve("web.min.internal"), None);
    }

    /// The declared ingress ports of [`leased_ports`] as the session actor
    /// passes them ([`crate::net::switch::declared_request_ports`] over the
    /// session's policy): the published external ports.
    fn declared_ports() -> BTreeSet<u16> {
        BTreeSet::from([18080])
    }

    /// The loopback a published-loopback route targets.
    fn loopback_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// On a VM host (the daemon on the switch) an `OwnIp` box's name routes
    /// straight to its lease, translating the published external port through
    /// the ingress declaration's external→internal map; a port the declaration
    /// does not publish — an unrelated one or the internal number behind the
    /// map — routes nowhere (NET-001), matching the ingress gate that denies
    /// an inbound SYN to any undeclared port on the switch.
    #[test]
    fn own_ip_on_a_vm_host_routes_to_the_lease_through_the_ingress_map() {
        let mut reg = HostnameRegistry::new("dev", true);
        let lease = std::net::Ipv4Addr::new(100, 64, 0, 7);
        reg.report_own_address(SessionId::nil(), "web", lease, leased_ports());

        let route = reg.resolve("web.min.internal:18080").expect("routes");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(lease), 8080))
        );
        assert_eq!(route.session(), "web");

        // A port the ingress declaration does not publish routes nowhere — both
        // an unrelated port and the box's internal port number behind the map.
        assert_eq!(route.upstream(9000), None, "unrelated port is unpublished");
        assert_eq!(
            route.upstream(8080),
            None,
            "the internal port behind the map is not itself addressable"
        );
    }

    /// A session id from a literal UUID, distinct per test: the registry holds
    /// publish and lease state by id, so two boxes in one registry must have
    /// two ids — sharing [`SessionId::nil`] would fake a collision and a
    /// shared publish.
    fn id(last: &str) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-00000000000{last}"))
            .expect("a literal uuid")
    }

    /// NET-129: a host-address box answers its name with its **node's**
    /// published host-loopback address — `127.0.0.1` on a native node, one
    /// allocated address per VM node — at the box's own port numbers, which a
    /// `HostNet` route never gates and never translates.
    #[test]
    fn host_ip_box_answers_node_loopback_address() {
        // A native node: the node address is the host loopback itself, and a
        // host-address box's name answers there.
        let mut native = HostnameRegistry::new("dev", false);
        native.register_host_net(id("1"), "web");
        assert_eq!(
            native.zone_entry("web.min.internal", &[]),
            ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(Ipv4Addr::LOCALHOST),
            }
        );
        let route = native
            .resolve("web.min.internal:8080")
            .expect("a host-address box's name routes");
        assert_eq!(
            route.upstream(8080),
            Some(SocketAddr::new(loopback_addr(), 8080)),
            "the box's own port number, at the node's address, ungated"
        );

        // A VM node: the node holds one allocated address of its own, and its
        // host-address boxes answer at it.
        let node = Ipv4Addr::new(127, 0, 64, 200);
        let mut vm = HostnameRegistry::new("dev", true).with_node_address(node);
        vm.register_host_net(id("2"), "web");
        assert_eq!(
            vm.zone_entry("web.min.internal", &[]),
            ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(node),
            },
            "a host-address box answers with its node's published address"
        );
        let route = vm
            .resolve("web.min.internal:8080")
            .expect("a host-address box's name routes");
        assert_eq!(
            route.upstream(8080),
            Some(SocketAddr::new(IpAddr::V4(node), 8080)),
            "the box's own port number at the node's allocated address"
        );
        assert_eq!(
            route.upstream(9090),
            Some(SocketAddr::new(IpAddr::V4(node), 9090)),
            "a host-address route gates no port, so no port is translated"
        );
    }

    /// NET-129's other half: a node address that lands **after** the registry
    /// was built — the shape of a microVM daemon, whose range verdict comes
    /// back from a walk the daemon does not hold its accept loop for, so the
    /// registry opens on the interim — takes the names that answered the
    /// interim with it: a host-address box, whose route was always the node's.
    /// An own-address box's route never moves with it: its address was
    /// **handed**, and a fact about the node is not a fact about the box.
    #[test]
    fn a_late_node_address_re_points_the_names_the_interim_answered() {
        let node = Ipv4Addr::new(127, 0, 64, 200);
        let mut reg = HostnameRegistry::new("dev", true);
        // The interim the registry opens on: the host loopback — the address
        // a host-address box answers until the node's grant lands.
        reg.register_host_net(id("1"), "shared");
        // An own-address box at an address its creator handed, and one at
        // its own lease.
        let handed = Ipv4Addr::new(127, 0, 64, 9);
        reg.publish_own_address(id("2"), "handed", handed, declared_ports());
        reg.register_own_ip(id("2"), "handed", declared_ports());
        let lease = Ipv4Addr::new(100, 64, 0, 7);
        reg.report_own_address(id("3"), "leased", lease, leased_ports());

        reg.set_node_address(node);

        assert_eq!(
            reg.zone_entry("shared.min.internal", &[]),
            ZoneEntry::Held {
                owner: "shared".to_string(),
                address: Some(node),
            },
            "the host-address box answers the node's granted address, not the interim it opened on"
        );
        assert_eq!(
            reg.resolve("shared.min.internal:8080")
                .expect("a host-address box's name routes")
                .upstream(8080),
            Some(SocketAddr::new(IpAddr::V4(node), 8080)),
            "the proxy forwards a host-address box at the granted address too"
        );
        assert_eq!(
            reg.resolve("handed.min.internal:18080")
                .expect("a handed box's name routes")
                .upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(handed), 18080)),
            "a handed address is used exactly as handed: the node's grant \
             never moves it"
        );
        assert_eq!(
            reg.resolve("leased.min.internal:18080")
                .expect("a leased box's name routes")
                .upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(lease), 8080)),
            "a box at its own lease keeps it: its address was never the node's"
        );
    }

    /// NET-128: a box stopped on a **shared address** answers NODATA — held, so
    /// the zone never says NXDOMAIN for a box that exists — because the
    /// node's own listener at that port must not answer for a dead box. A box
    /// on an address of its own keeps answering A while it is stopped: the
    /// address answers for it alone, and a lookup says where the box would be.
    #[test]
    fn stopped_shared_address_box_is_nodata() {
        let node = Ipv4Addr::new(127, 0, 64, 200);
        let mut reg = HostnameRegistry::new("dev", false).with_node_address(node);
        let shared = id("1");
        let own = id("2");
        let port = BTreeSet::from([8080u16]);

        // One box publishing on the node's shared address, one on an address
        // of its own — both registered from finalize, as the session actor
        // does.
        reg.publish_own_address(shared, "shared", node, port.clone());
        reg.register_own_ip(shared, "shared", port.clone());
        let own_address = Ipv4Addr::new(127, 0, 64, 9);
        reg.publish_own_address(own, "own", own_address, port.clone());
        reg.register_own_ip(own, "own", port);

        // Both answer while they run.
        let ZoneEntry::Held {
            address: shared_address,
            ..
        } = reg.zone_entry("shared.min.internal", &[])
        else {
            panic!("a registered box's name is held");
        };
        assert_eq!(shared_address, Some(node));
        let ZoneEntry::Held {
            address: own_address,
            ..
        } = reg.zone_entry("own.min.internal", &[])
        else {
            panic!("a registered box's name is held");
        };
        assert_eq!(own_address, Some(Ipv4Addr::new(127, 0, 64, 9)));

        // The hosts exit: both names stay held — never absent, so neither is
        // negatively cached — but the shared one answers NODATA while the
        // node's own listener at the port must not speak for the dead box.
        reg.mark_stopped(shared);
        reg.mark_stopped(own);
        assert_eq!(
            reg.zone_entry("shared.min.internal", &[]),
            ZoneEntry::Held {
                owner: "shared".to_string(),
                address: None,
            },
            "a stopped shared-address box answers NODATA, not the node's address"
        );
        assert_eq!(
            reg.zone_entry("own.min.internal", &[]),
            ZoneEntry::Held {
                owner: "own".to_string(),
                address: Some(Ipv4Addr::new(127, 0, 64, 9)),
            },
            "a stopped box on its own address keeps answering A"
        );

        // The same view in the zone table the state dump carries: name order
        // puts `own` first, so `shared` is the row that pops first.
        let mut rows = reg.zone_table(&[]);
        assert_eq!(rows.len(), 2, "both names stay in the zone: {rows:?}");
        assert_eq!(
            rows.pop().expect("the shared box's row").address,
            None,
            "the zone table reports the shared-address box as held without an A answer"
        );
        assert_eq!(
            rows.pop().expect("the own box's row").address,
            Some(Ipv4Addr::new(127, 0, 64, 9))
        );

        // Running again answers again — the stop is a state, not an end.
        reg.mark_running(shared);
        assert_eq!(
            reg.zone_entry("shared.min.internal", &[]),
            ZoneEntry::Held {
                owner: "shared".to_string(),
                address: Some(node),
            }
        );
    }

    /// NET-129: two boxes publishing at one shared address that name the same
    /// port are **reported** — each collision once, naming both boxes and the
    /// port — and neither port is translated: the declarations of record
    /// stand, at the port numbers the boxes asked for. The collision is
    /// intrinsic to the mode — the boxes were told to publish at the same
    /// place — so nothing remaps around it.
    #[test]
    fn shared_address_port_collision_reported_not_translated() {
        let node = Ipv4Addr::new(127, 0, 64, 200);
        let mut reg = HostnameRegistry::new("dev", false).with_node_address(node);
        let first = id("1");
        let second = id("2");

        // Finalize publishes and registers the first box: 8080 and 9090 on the
        // node's shared address.
        let first_ports = BTreeSet::from([8080u16, 9090]);
        assert!(
            reg.publish_own_address(first, "first", node, first_ports.clone())
                .is_empty(),
            "the first box at a port collides with nothing"
        );
        reg.register_own_ip(first, "first", first_ports.clone());
        assert!(
            reg.publish_own_address(first, "first", node, first_ports.clone())
                .is_empty(),
            "a box does not collide with its own re-published declaration"
        );

        // A second box at the same address naming 8080 too: the collision is
        // reported against the first box's name, once, with the port — and
        // its own port is not translated, so its declaration still names 8080.
        let second_ports = BTreeSet::from([8080u16]);
        assert_eq!(
            reg.publish_own_address(second, "second", node, second_ports.clone()),
            vec![SharedPortCollision {
                port: 8080,
                other: "first.min.internal".to_string(),
            }],
            "one collision, naming the box that held the port and the port itself"
        );
        reg.register_own_ip(second, "second", second_ports.clone());

        // Neither port is translated: each box's route forwards at the port
        // its own declaration names, on the shared address.
        let first_route = reg
            .resolve("first.min.internal")
            .expect("the first box's name routes");
        assert_eq!(
            first_route.upstream(8080),
            Some(SocketAddr::new(IpAddr::V4(node), 8080))
        );
        assert_eq!(
            first_route.upstream(9090),
            Some(SocketAddr::new(IpAddr::V4(node), 9090)),
            "the first box keeps the port the collision did not touch"
        );
        let second_route = reg
            .resolve("second.min.internal")
            .expect("the second box's name routes");
        assert_eq!(
            second_route.upstream(8080),
            Some(SocketAddr::new(IpAddr::V4(node), 8080)),
            "the second box's port is published at the number it asked for"
        );
        assert_eq!(
            second_route.upstream(9090),
            None,
            "and it does not inherit the other box's port either"
        );

        // A third box at an address of its own names the same port with no
        // collision at all (NET-010): different address, no shared port.
        let third = id("3");
        let own_address = Ipv4Addr::new(127, 0, 64, 9);
        assert!(
            reg.publish_own_address(third, "third", own_address, second_ports)
                .is_empty(),
            "the same port on a different address is not a collision"
        );
    }

    /// The deprecated three-label form resolves to the same entry as the
    /// two-label one (NET-002). Matching keys on the `<host-id>` label, so a
    /// dotted session name is not stripped at the wrong label.
    #[test]
    fn legacy_three_label_resolves_to_the_same_entry() {
        let mut reg = HostnameRegistry::new("local", false);
        reg.register_host_net(SessionId::nil(), "web");

        let legacy = reg
            .resolve("web.local.min.internal")
            .expect("legacy form routes");
        assert_eq!(legacy.session(), "web");
        assert_eq!(
            reg.resolve("web.min.internal"),
            Some(legacy),
            "both forms resolve to the same entry"
        );

        // With an `:port` suffix, as a real header carries.
        assert!(reg.resolve("web.local.min.internal:8080").is_some());
        // An unknown session's legacy form does not route.
        assert_eq!(reg.resolve("ghost.local.min.internal"), None);
        // The bare `<host-id>.min.internal` is not a legacy session name.
        assert_eq!(reg.resolve("local.min.internal"), None);
    }

    /// Port stripping handles both the common `name:port` form and the
    /// bracketed IPv6 literal form, where the port follows the closing bracket.
    /// The registry never holds an IPv6 literal, so this guards the parse from
    /// silently truncating `[::1]` to `[` at the first colon.
    #[test]
    fn host_component_strips_port_including_bracketed_ipv6() {
        assert_eq!(host_component("svc.min.internal"), "svc.min.internal");
        assert_eq!(host_component("svc.min.internal:8080"), "svc.min.internal");
        assert_eq!(host_component("[::1]:8080"), "[::1]");
        assert_eq!(host_component("[::1]"), "[::1]");
    }

    /// Deregistering a session that was never registered is a silent no-op, so
    /// the manager can call it unconditionally on session teardown.
    #[test]
    fn deregister_unknown_session_is_a_noop() {
        let mut reg = HostnameRegistry::new("dev", false);
        assert_eq!(reg.deregister("ghost"), None);
    }

    // The answerer's lease record (NET-010): the host-global arbitration.

    /// A tempdir turned into a state root two books can share, the way two
    /// daemon instances on one host share the daemon state dir.
    #[cfg(target_os = "linux")]
    fn lease_root(tmp: &tempfile::TempDir) -> paths::DaemonAbsPath {
        paths::DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap()
    }

    /// A book open on `state_root` with the range present, the verdict a
    /// Linux daemon's bind probe always returns.
    #[cfg(target_os = "linux")]
    fn lease_book(state_root: &paths::DaemonAbsPath) -> LoopbackLeaseBook {
        LoopbackLeaseBook::open(state_root, RangeVerdict::Present)
            .expect("opening the lease record")
    }

    /// A distinct session id, so each box namespace in a test is its own.
    #[cfg(target_os = "linux")]
    fn session_id(millis: u128) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-{millis:012}")).unwrap()
    }

    /// The record the answerer holds over one host: two daemons asking over
    /// the same state root — the two gvproxy instances one host runs — never
    /// hold one address, and neither is ever granted the answerer's own
    /// (design §7.1: 127.0.64.1 is the answerer's, and no lease may include
    /// it).
    #[cfg(target_os = "linux")]
    #[test]
    fn two_daemons_on_one_host_never_share_a_granted_address() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        // Two books over the one record: two daemon instances, each with its
        // own open handle, serialized by the record's lock file rather than
        // by any memory they share (they share none).
        let daemon_a = lease_book(&state_root);
        let daemon_b = lease_book(&state_root);

        // Interleaved asks, the adversarial order: each daemon asks while
        // the other holds grants the first must have seen.
        let a1 = daemon_a.grant(LeaseNamespace::Box {
            session: session_id(1),
        });
        let b1 = daemon_b.grant(LeaseNamespace::Box {
            session: session_id(2),
        });
        let a2 = daemon_a.grant(LeaseNamespace::Box {
            session: session_id(3),
        });
        let b2 = daemon_b.grant(LeaseNamespace::Box {
            session: session_id(4),
        });
        let grants = [a1, b1, a2, b2];
        let addresses: Vec<Ipv4Addr> = grants
            .iter()
            .map(|grant| match grant {
                LoopbackGrant::Granted(address) => *address,
                other => panic!("a fresh host grants every namespace: {other:?}"),
            })
            .collect();
        let distinct: BTreeSet<_> = addresses.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            addresses.len(),
            "two daemons on one host hold one address between them: {addresses:?}"
        );
        for address in &addresses {
            assert_ne!(
                *address,
                sessions::core::loopback::ANSWERER_ADDRESS,
                "the answerer's own address was granted"
            );
            assert!(
                in_reserved_local_range(*address),
                "{address} is not from the reserved local range"
            );
        }
    }

    /// The grant a namespace already holds is answered with it — a resumed
    /// session's ask after a daemon restart — so a box's address is stable
    /// across the restart, and neither the record nor the pool is spent
    /// twice on one namespace.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_grant_survives_a_daemon_restart_and_answers_the_same_address() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let namespace = LeaseNamespace::Box {
            session: session_id(5),
        };

        // The daemon that first granted, then the one that starts after it —
        // the same session resuming on the second.
        let first = lease_book(&state_root);
        let granted = match first.grant(namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a fresh host grants the box: {other:?}"),
        };
        drop(first);
        let restarted = lease_book(&state_root);
        match restarted.grant(namespace) {
            LoopbackGrant::Granted(address) => assert_eq!(
                address, granted,
                "the resumed box did not get its recorded address back"
            ),
            other => panic!("the record survives the restart: {other:?}"),
        }

        // And the namespace holds exactly one line in the record: the
        // re-ask spent nothing.
        let entries = restarted.read().expect("the record the restart re-opened");
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.namespace == namespace)
                .count(),
            1,
            "the resumed box spent a second grant"
        );

        // Releasing on the restarted daemon returns the recorded address to
        // the pool, and the next box's ask takes it — not a fresh one.
        assert_eq!(restarted.release(namespace), Some(granted));
        let next = match restarted.grant(LeaseNamespace::Box {
            session: session_id(6),
        }) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("the freed address is grantable: {other:?}"),
        };
        assert_eq!(next, granted, "the released address is the lowest free");
    }

    /// The pool the answerer may grant is the range's usable addresses minus
    /// its own `.1` — and when that budget is spent, `PoolSpent` rather than
    /// the answerer's address or anything outside the range; releasing makes
    /// room again.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_spent_pool_reports_spent_rather_than_granting_the_answerer_s_address() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);

        let mut granted = BTreeSet::new();
        for millis in 1..=sessions::core::loopback::POOL_LEN {
            let namespace = LeaseNamespace::Box {
                session: session_id(u128::from(millis)),
            };
            match book.grant(namespace) {
                LoopbackGrant::Granted(address) => {
                    assert_ne!(
                        address,
                        sessions::core::loopback::ANSWERER_ADDRESS,
                        "no lease may include the answerer's own address"
                    );
                    assert!(granted.insert(address), "{address} granted twice");
                }
                other => panic!("the host's budget covers every namespace: {other:?}"),
            }
        }

        // The budget is spent: the node's ask — the next namespace, a
        // different kind than every box before it — reports the spent pool,
        // never an address that would break the property.
        assert_eq!(book.grant(LeaseNamespace::Node), LoopbackGrant::PoolSpent);

        // Releasing one box makes room for exactly the next ask.
        let released = session_id(1);
        assert!(
            book.release(LeaseNamespace::Box { session: released })
                .is_some(),
            "the box's grant is in the record"
        );
        match book.grant(LeaseNamespace::Node) {
            LoopbackGrant::Granted(address) => assert!(
                granted.contains(&address),
                "{address} is one of the released addresses"
            ),
            other => panic!("the released address is grantable: {other:?}"),
        }
    }

    /// A `daemon_start` stamp that is strictly after every grant the calling
    /// test has already made: the start of a daemon whose liveness snapshot
    /// — read from the store as it began — predates none of them, so the
    /// sweep decides those lines on liveness alone.
    #[cfg(target_os = "linux")]
    fn a_later_daemon_start() -> u64 {
        unix_now_secs() + 1
    }

    /// This process's open file descriptors whose path lies under `dir`, as
    /// `(fd, flags, path)`: the flags are the descriptor's status flags in
    /// octal, whose low two bits are the access mode — `00` `O_RDONLY`,
    /// `01` `O_WRONLY`, `02` `O_RDWR`.
    #[cfg(target_os = "linux")]
    fn fds_under(dir: &std::path::Path) -> Vec<(u32, u32, String)> {
        let mut held: Vec<(u32, u32, String)> = std::fs::read_dir("/proc/self/fd")
            .expect("the kernel always serves its fd table")
            .flatten()
            .filter_map(|entry| {
                let fd = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                let target = std::fs::read_link(entry.path()).ok()?;
                if !target.starts_with(dir) {
                    return None;
                }
                let flags = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
                    .ok()
                    .and_then(|info| {
                        info.lines().find_map(|line| {
                            line.strip_prefix("flags:").and_then(|rest| {
                                // Octal, as printed: a decimal read of
                                // `0100002` would take the low bits from the
                                // eights digit, and `& 0o3` from it.
                                u32::from_str_radix(rest.trim(), 8).ok()
                            })
                        })
                    })
                    .unwrap_or(0);
                Some((fd, flags, target.to_string_lossy().into_owned()))
            })
            .collect();
        held.sort();
        held
    }

    /// The start-time sweep: a box whose session is gone from the store
    /// loses its grant, and a live box — even one another daemon instance
    /// owns — keeps it. The node's grant is not a box's and is never swept.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_start_sweep_frees_only_dead_boxes_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);
        let dead = session_id(1);
        let live = session_id(2);
        let dead_namespace = LeaseNamespace::Box { session: dead };
        let live_namespace = LeaseNamespace::Box { session: live };
        let dead_address = match book.grant(dead_namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a fresh host grants the box: {other:?}"),
        };
        let live_address = match book.grant(live_namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a fresh host grants the box: {other:?}"),
        };
        let node_address = match book.grant(LeaseNamespace::Node) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("the node grants after the boxes: {other:?}"),
        };

        // The store's live set names the live box alone.
        let live_ids = BTreeSet::from([live]);
        let freed = book.release_dead_boxes(&live_ids, a_later_daemon_start());
        assert_eq!(
            freed,
            vec![dead_address],
            "only the destroyed box's grant is swept"
        );

        // The live box keeps its grant; the freed address is grantable
        // again; the node keeps its own line, un-swept.
        assert_eq!(
            book.grant(live_namespace),
            LoopbackGrant::Granted(live_address)
        );
        assert_eq!(
            book.grant(LeaseNamespace::Box {
                session: session_id(3)
            }),
            LoopbackGrant::Granted(dead_address),
            "the swept address is the lowest free"
        );
        assert_eq!(
            book.grant(LeaseNamespace::Node),
            LoopbackGrant::Granted(node_address),
            "the node's grant is not a box's, and is never swept"
        );

        // An empty store sweeps every box — a host whose sessions were all
        // destroyed while no daemon was running starts with the whole pool.
        let swept: BTreeSet<Ipv4Addr> = book
            .release_dead_boxes(&BTreeSet::new(), a_later_daemon_start())
            .into_iter()
            .collect();
        assert_eq!(
            swept,
            BTreeSet::from([dead_address, live_address]),
            "every box's grant goes, the node's stays"
        );
    }

    /// The sweep's race guard: a grant another daemon made while this one
    /// was starting is not this sweep's to free, however stale the liveness
    /// snapshot this daemon took — the snapshot was read from the store
    /// before the granting session ever appeared in it. The stamp bounds
    /// the sweep; the next daemon, starting after the grant, is the one
    /// whose sweep liveness alone decides it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_start_sweep_spares_a_grant_made_as_this_daemon_was_starting() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);
        let namespace = LeaseNamespace::Box {
            session: session_id(1),
        };
        let granted = match book.grant(namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a fresh host grants the box: {other:?}"),
        };
        // This daemon started the same second the peer granted: everything
        // it stamps at or after its start is not its sweep's to free.
        let daemon_start = book
            .read()
            .expect("the record the grant wrote")
            .first()
            .expect("the grant wrote one line")
            .granted_at;
        let live: BTreeSet<SessionId> = BTreeSet::new();
        assert_eq!(
            book.release_dead_boxes(&live, daemon_start),
            Vec::<Ipv4Addr>::new(),
            "a grant made while this daemon was starting is not read as dead"
        );
        assert_eq!(
            book.grant(namespace),
            LoopbackGrant::Granted(granted),
            "the spared grant still answers the same address"
        );

        // The next daemon starts after the grant: nothing of the guard
        // protects it, and liveness alone decides.
        assert_eq!(
            book.release_dead_boxes(&live, daemon_start + 1),
            vec![granted],
            "the next daemon's start predates nothing, and sweeps it"
        );
        assert_eq!(
            book.read().unwrap(),
            Vec::new(),
            "the swept line is gone from the record"
        );
    }

    /// A record written before the stamp existed — the format a daemon on
    /// the previous release leaves behind — still parses, its lines read as
    /// stamped at the epoch, and the sweep decides them on liveness alone,
    /// the guardless behaviour.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_from_before_grants_were_stamped_still_sweeps() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let record = state_root.sub_path_unchecked(LEASE_RECORD_FILE);
        let live = session_id(1);
        let dead = session_id(2);
        // Two lines of the old field set: a live box's and a dead box's,
        // hand-written in the shape the previous release wrote.
        let pre_stamp_record = format!(
            concat!(
                r#"[{{"namespace":{{"box":{{"session":"{}"}}}},"#,
                r#""address":"127.0.64.2"}},"#,
                r#"{{"namespace":{{"box":{{"session":"{}"}}}},"#,
                r#""address":"127.0.64.3"}}]"#
            ),
            live, dead
        );
        std::fs::write(record.as_utf8_path(), pre_stamp_record).unwrap();
        let book = lease_book(&state_root);
        let entries = book.read().unwrap();
        assert_eq!(entries.len(), 2, "the pre-stamp record parses");
        assert!(
            entries.iter().all(|entry| entry.granted_at == 0),
            "a pre-stamp line reads as stamped at the epoch"
        );
        // Re-granting a pre-stamp line answers the recorded address, keeping
        // the box stable across the release that added the stamp.
        assert_eq!(
            book.grant(LeaseNamespace::Box { session: live }),
            LoopbackGrant::Granted(sessions::core::loopback::POOL_FIRST)
        );
        // A daemon started now — after the epoch, whenever that was —
        // sweeps the pre-stamp lines on liveness alone.
        let freed = book.release_dead_boxes(&BTreeSet::from([live]), a_later_daemon_start());
        assert_eq!(freed, vec![std::net::Ipv4Addr::new(127, 0, 64, 3)]);
    }

    /// The cross-record collision report: a live publish holding a
    /// reserved-range address this record does not name is reported, and one
    /// the record does name is not — this record's own grant, whatever it is
    /// publishing. Both binds sit in the one kernel table the whole host
    /// shares, which is what makes this the check a second state root cannot
    /// dodge by keeping its own record.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_publish_the_record_does_not_name_is_reported_at_start() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);
        let recorded = match book.grant(LeaseNamespace::Node) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a fresh host grants the node: {other:?}"),
        };

        // One publish at the recorded address, one at an address no line of
        // this record names — the shape a second state root's daemon
        // publishes at, having granted it from its own record.
        let recorded_listener =
            std::net::TcpListener::bind((recorded, 0)).expect("the recorded address binds");
        let foreign = std::net::Ipv4Addr::new(127, 0, 64, 250);
        let foreign_listener =
            std::net::TcpListener::bind((foreign, 0)).expect("the unrecorded address binds");

        let reported = book.unrecorded_publishes();
        assert!(
            reported.contains(&foreign),
            "the unrecorded publish is reported: {reported:?}"
        );
        assert!(
            !reported.contains(&recorded),
            "the record's own publish is not: {reported:?}"
        );

        // Neither the answerer's own address — never grantable, and not this
        // report's to question — nor a client of a publish is one: a
        // connected socket at an in-range address holds no listener.
        drop(recorded_listener);
        drop(foreign_listener);
    }

    /// The quiesce contract: the state volume must not carry a live
    /// write-open descriptor across the daemon's stop — the fd the journal's
    /// clean-replay check trips over. The book's one held-open descriptor is
    /// the lock file, opened read-only, and `close` — the call the
    /// manager's shutdown arm makes beside the cache's read-tracker
    /// release — drops it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_closed_book_holds_no_file_descriptor_on_the_state_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);
        let namespace = LeaseNamespace::Box {
            session: session_id(1),
        };
        assert_eq!(
            book.grant(namespace),
            LoopbackGrant::Granted(sessions::core::loopback::POOL_FIRST)
        );

        // One fd, the lock file, and it is read-only — the low two bits of
        // its status flags are the access mode, `00` `O_RDONLY`. `flock`
        // asks the kernel about the file, not through it, so the record's
        // lock holds anyway.
        let held = fds_under(tmp.path());
        assert_eq!(
            held.len(),
            1,
            "the book holds one descriptor over the state volume: {held:?}"
        );
        let (_, flags, _) = &held[0];
        assert_eq!(
            flags & 0o3,
            0,
            "the lock file's descriptor is opened read-only: {flags:o}"
        );

        // The shutdown arm's close leaves none, and a second close is a
        // no-op.
        book.close();
        book.close();
        assert!(
            fds_under(tmp.path()).is_empty(),
            "after the shutdown-arm close, the state volume carries no descriptor the book holds"
        );

        // Over a closed book every answer is the closed-book answer: grants
        // withhold, and releases, sweeps, and collision reports report
        // nothing. The record on disk stands as the grants left it.
        assert_eq!(
            book.grant(LeaseNamespace::Box {
                session: session_id(2)
            }),
            LoopbackGrant::RecordUnavailable
        );
        assert_eq!(book.release(namespace), None);
        assert!(
            book.release_dead_boxes(&BTreeSet::new(), a_later_daemon_start())
                .is_empty()
        );
        assert!(book.unrecorded_publishes().is_empty());
        assert_eq!(book.read().unwrap().len(), 1, "the record stands");
    }

    /// An absent reserved local range grants nothing — NET-123's interim:
    /// the addresses the book would grant are not bindable, so no namespace
    /// is ever handed one it cannot publish.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_absent_range_grants_nothing_and_publishes_on_the_interim() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = LoopbackLeaseBook::open(&state_root, RangeVerdict::Absent).unwrap();
        assert_eq!(book.grant(LeaseNamespace::Node), LoopbackGrant::RangeAbsent);
        assert_eq!(
            book.grant(LeaseNamespace::Box {
                session: session_id(1)
            }),
            LoopbackGrant::RangeAbsent
        );
        // The record stays empty: an absent range spends nothing.
        assert_eq!(book.read().unwrap(), Vec::new());
    }

    /// The verdict a book opens on while the probe that produces it is still
    /// walking — a microVM daemon's shape, the one daemon whose publish surface
    /// it cannot bind on itself and whose walk it must not hold its accept loop
    /// for. Grants for namespaces the record does not name are withheld — the
    /// interim, never a guess at an address — until the verdict lands and is
    /// applied, and then the same ask grants; a verdict the book already holds,
    /// applied again, spends nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_book_opens_interim_until_the_range_verdict_lands() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let namespace = LeaseNamespace::Node;
        let book = LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap();
        assert_eq!(book.grant(namespace), LoopbackGrant::RangePending);
        // The pending window spends nothing: the walk's verdict has not said
        // an address is publishable, so the record is not written to either.
        assert_eq!(book.read().unwrap(), Vec::new());

        // The walk lands, present: the book un-withholds, and the node's ask —
        // the one the walk itself makes — is answered from the same record any
        // later ask reads.
        book.set_range_verdict(RangeVerdict::Present);
        let granted = match book.grant(namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("the landed verdict lets the same ask grant: {other:?}"),
        };
        assert_eq!(granted, sessions::core::loopback::POOL_FIRST);

        // And applying the verdict a second time changes nothing: the walk
        // lands once, and a book that already holds it is not re-opened.
        book.set_range_verdict(RangeVerdict::Present);
        assert_eq!(
            book.grant(namespace),
            LoopbackGrant::Granted(granted),
            "the namespace still holds the address the first landed verdict granted"
        );
    }

    /// The pending window publishes no reserved-range address, not even a
    /// recorded one, and takes no resumed box's address away from it either
    /// (NET-013): a daemon that restarts inside its walk window — the shape a
    /// VM host's is, where an attach right after `min up` brings a live box's
    /// actor up before the forwarder-conducted walk has answered — answers
    /// the resumed box's ask with the interim, because nothing has measured
    /// this daemon's surface yet, but keeps the record's line, so the present
    /// landing's re-ask answers with the very address the box held. A fresh
    /// ask is answered the same way and spends nothing, and a landed absent
    /// verdict refuses a recorded namespace too.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pending_verdict_withholds_every_grant_and_keeps_the_recorded_line() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let namespace = LeaseNamespace::Box {
            session: session_id(1),
        };

        // The box's own daemon, on a host whose verdict has landed: its grant
        // is the line the record carries across the restart.
        let first = lease_book(&state_root);
        let recorded = match first.grant(namespace) {
            LoopbackGrant::Granted(address) => address,
            other => panic!("a present range grants the box its address: {other:?}"),
        };
        assert_eq!(recorded, sessions::core::loopback::POOL_FIRST);
        let fresh = LeaseNamespace::Box {
            session: session_id(2),
        };

        // The restarted daemon, whose walk has not landed: the same ask the
        // resume path makes is answered with the interim — no reserved-range
        // address publishes under anything but a landed present — and so is a
        // box the record does not name.
        let restarted = LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap();
        assert_eq!(
            restarted.grant(namespace),
            LoopbackGrant::RangePending,
            "a resumed box publishes the interim while the verdict is pending"
        );
        assert_eq!(
            restarted.grant(fresh),
            LoopbackGrant::RangePending,
            "a namespace the record does not name waits for the verdict"
        );
        assert_eq!(
            restarted.read().unwrap(),
            first.read().unwrap(),
            "the pending window spends nothing and drops nothing: the record \
             carries the one line it held"
        );

        // The walk lands present: both asks grant now, and the resumed box
        // gets back the address its line kept through the window.
        restarted.set_range_verdict(RangeVerdict::Present);
        assert_eq!(
            restarted.grant(namespace),
            LoopbackGrant::Granted(recorded),
            "the landed verdict restores a recorded namespace's address"
        );
        // The next address up: the one the allocator hands a fresh ask over a
        // pool whose lowest address is taken.
        let [a, b, c, d] = recorded.octets();
        let next_up = std::net::Ipv4Addr::new(a, b, c, d + 1);
        assert_eq!(
            restarted.grant(fresh),
            LoopbackGrant::Granted(next_up),
            "the landed verdict grants the fresh ask the next address up"
        );

        // A landed absent verdict is the one that refuses everything: an
        // address the publish surface cannot bind is not grantable to a
        // namespace that holds one any more than to one that does not.
        restarted.set_range_verdict(RangeVerdict::Absent);
        assert_eq!(
            restarted.grant(namespace),
            LoopbackGrant::RangeAbsent,
            "a landed absent verdict refuses a recorded namespace too"
        );
        assert_eq!(
            restarted.grant(LeaseNamespace::Node),
            LoopbackGrant::RangeAbsent
        );
    }

    /// The verdict gate a VM host daemon's hand goes through (NET-123 §7.1):
    /// the hand names a slice address of the reserved local range without
    /// measuring the loopback it binds on, so the guest's verdict decides
    /// whether it is publishable — and **only a landed verdict does**: a
    /// present one vouches, a pending one does not (the hand's provenance —
    /// the host-side table row a resumed box keeps its address on,
    /// NET-013 — is a fact about who chose the address, not a measurement
    /// of the surface it binds on), and an absent one is the surface's own
    /// answer against it. An address outside the range needs no vouching at
    /// all. The registration path that meets an unvouched hand waits for
    /// the verdict to land rather than publishing either address — that
    /// wait is the test below this one.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_landed_present_verdict_vouches_for_a_handed_range_address() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let handed = sessions::core::loopback::POOL_FIRST;

        // A native daemon's book: its own loopback answered before it opened.
        let present = lease_book(&state_root);
        assert!(
            present.vouches_for(handed),
            "a present range vouches for the hand"
        );

        // A microVM daemon's book inside the walk's window: nothing has
        // measured the surface yet, and provenance is not a measurement, so
        // the hand is not publishable until the walk answers.
        let pending = LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap();
        assert!(
            !pending.vouches_for(handed),
            "a pending verdict has not vouched for the hand, however it was chosen"
        );

        // The walk lands absent — the stock-macOS shape, where no alias of
        // the range binds — and the same hand is still not publishable: the
        // box that publishes it verbatim would bind its declared ports at an
        // address every bind refuses.
        pending.set_range_verdict(RangeVerdict::Absent);
        assert!(
            !pending.vouches_for(handed),
            "a landed absent verdict overrules the hand: the surface cannot bind it"
        );

        // An address outside the reserved range is not the surface's to
        // vouch for: a hand that names the interim needs no verdict.
        assert!(
            pending.vouches_for(Ipv4Addr::LOCALHOST),
            "an address outside the reserved range needs no vouching"
        );
    }

    /// The wait an unvouched hand takes (NET-123 §7.1): a registration
    /// holding a hand the verdict has not vouched for waits for the verdict
    /// to land, bounded by the daemon's one verdict deadline — a present
    /// verdict landing inside the bound vouches for the hand, an absent one
    /// refuses it at once, and a verdict that never lands has the deadline
    /// answered as "not vouched" so the caller publishes the interim
    /// instead of holding the session's start forever. The deadline here is
    /// moved to tens of milliseconds away so the expiry is proven without
    /// the real deadline's five seconds.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unvouched_hand_waits_for_the_verdict_and_is_answered_by_the_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let handed = sessions::core::loopback::POOL_FIRST;

        // A pending book whose deadline is far off: the hand is unvouched,
        // the verdict lands inside the bound, and the wait answers with the
        // verdict, not with the clock.
        let pending = std::sync::Arc::new(
            LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap(),
        );
        pending.reset_hand_verdict_deadline(30_000);
        let waiting = {
            let pending = std::sync::Arc::clone(&pending);
            tokio::spawn(async move { pending.await_vouch_for(handed).await })
        };
        // Landed only once the waiter is parked, so the landing is what
        // answers it — not a verdict it read before it began to wait.
        while pending.verdict_waiters() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        pending.set_range_verdict(RangeVerdict::Present);
        assert!(
            waiting.await.unwrap(),
            "a verdict that lands inside the bound vouches for the hand"
        );

        // An absent verdict answers at once, with no wait to spend.
        let absent = LoopbackLeaseBook::open(&state_root, RangeVerdict::Absent).unwrap();
        assert!(
            !absent.await_vouch_for(handed).await,
            "a landed absent verdict answers the wait with 'not vouched' at once"
        );

        // A verdict that never lands: the bound is spent and answered as
        // "not vouched", so the caller publishes the interim rather than
        // waiting for a walk that is not walking.
        let never = LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap();
        // Taken before the deadline is set, and the bar a few milliseconds
        // short of it: the deadline is kept to the millisecond.
        let started = std::time::Instant::now();
        never.reset_hand_verdict_deadline(50);
        assert!(
            !never.await_vouch_for(handed).await,
            "a verdict that never lands is answered by the bound, not vouched"
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(45),
            "the bound is what the expiry answer waited on"
        );
        assert!(
            never.await_vouch_for(Ipv4Addr::LOCALHOST).await,
            "an address outside the reserved range never waits at all"
        );
    }

    /// The deadline is the daemon's, not each waiter's (NET-123 §7.1):
    /// registrations that begin to wait at different moments all race the
    /// one instant, so a late waiter is answered when the first one is —
    /// not a whole wait after it began — and N waiters never cost N waits.
    /// A landing likewise answers every waiter at once.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_hand_waiter_races_the_one_daemon_deadline() {
        const WAITERS: usize = 4;
        const STAGGER: std::time::Duration = std::time::Duration::from_millis(150);
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let handed = sessions::core::loopback::POOL_FIRST;

        // A deadline the waiters are staggered across: the last one begins
        // to wait well after the first, with less than a whole wait left.
        let never = std::sync::Arc::new(
            LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap(),
        );
        let wait = STAGGER * u32::try_from(WAITERS).unwrap();
        never.reset_hand_verdict_deadline(u64::try_from(wait.as_millis()).unwrap());
        let started = std::time::Instant::now();
        let mut waiters = Vec::new();
        for _ in 0..WAITERS {
            let book = std::sync::Arc::clone(&never);
            waiters.push(tokio::spawn(async move {
                let began = std::time::Instant::now();
                let vouched = book.await_vouch_for(handed).await;
                (vouched, began.elapsed())
            }));
            tokio::time::sleep(STAGGER / 2).await;
        }
        let mut last_waited = std::time::Duration::ZERO;
        for waiter in waiters {
            let (vouched, waited) = waiter.await.unwrap();
            assert!(!vouched, "a deadline that passes answers 'not vouched'");
            last_waited = waited;
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < wait * 2,
            "every waiter returned by the one deadline ({wait:?}), not one wait \
             each after it began: took {elapsed:?}"
        );
        assert!(
            last_waited < wait,
            "the last waiter was answered by the shared deadline, not a whole wait \
             after it began: waited {last_waited:?}"
        );

        // A landing answers every parked waiter at once.
        let pending = std::sync::Arc::new(
            LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap(),
        );
        pending.reset_hand_verdict_deadline(30_000);
        let waiters: Vec<_> = (0..WAITERS)
            .map(|_| {
                let book = std::sync::Arc::clone(&pending);
                tokio::spawn(async move { book.await_vouch_for(handed).await })
            })
            .collect();
        while pending.verdict_waiters() < WAITERS {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let landed = std::time::Instant::now();
        pending.set_range_verdict(RangeVerdict::Present);
        for waiter in waiters {
            assert!(
                waiter.await.unwrap(),
                "the landing vouches for every waiter"
            );
        }
        assert!(
            landed.elapsed() < std::time::Duration::from_secs(10),
            "the landing answered the waiters, not the deadline"
        );
    }

    /// What each grant answer means for the box's publish (NET-123): the two
    /// answers that are facts about the publish surface — the range absent,
    /// the verdict still walking — publish the box on the `127.0.0.1`
    /// interim, the one address a host can listen on whatever its loopback
    /// carries, while the two that are faults — a spent pool, an unreadable
    /// record — publish nothing, so the attach of a box that declared
    /// ingress fails rather than standing it at an address nobody granted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_surface_withheld_grant_publishes_the_interim_and_a_fault_publishes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);

        // The absent range: the ask is answered with the surface's verdict,
        // and the publish a box makes of it is the interim.
        let absent = LoopbackLeaseBook::open(&state_root, RangeVerdict::Absent).unwrap();
        let withheld = absent.grant(LeaseNamespace::Box {
            session: session_id(1),
        });
        assert_eq!(withheld, LoopbackGrant::RangeAbsent);
        assert_eq!(
            withheld.publishable_address(),
            Some(Ipv4Addr::LOCALHOST),
            "an absent range publishes the box on the interim"
        );

        // The pending window: the same interim, for the same reason —
        // nothing has vouched for an address of the range, so none is spent.
        let pending = LoopbackLeaseBook::open(&state_root, RangeVerdict::Pending).unwrap();
        let walking = pending.grant(LeaseNamespace::Box {
            session: session_id(2),
        });
        assert_eq!(walking, LoopbackGrant::RangePending);
        assert_eq!(
            walking.publishable_address(),
            Some(Ipv4Addr::LOCALHOST),
            "the pending window publishes the box on the interim"
        );

        // A grant publishes exactly what the record names.
        let present = LoopbackLeaseBook::open(&state_root, RangeVerdict::Present).unwrap();
        let granted = present.grant(LeaseNamespace::Box {
            session: session_id(3),
        });
        assert_eq!(
            granted.publishable_address(),
            Some(sessions::core::loopback::POOL_FIRST),
            "a granted address is the box's publish"
        );

        // The faults publish nothing: a spent pool, and a record the
        // answerer cannot read or write.
        assert_eq!(
            LoopbackGrant::PoolSpent.publishable_address(),
            None,
            "a spent pool never stands the box at an address"
        );
        assert_eq!(
            LoopbackGrant::RecordUnavailable.publishable_address(),
            None,
            "an unreadable record never stands the box at an address"
        );
    }

    /// A stale record holding two namespaces on one address answers both
    /// with the recorded address rather than stranding the second: a
    /// recorded namespace is granted, never refused. The grant emits the
    /// `loopback-grant-collision` warn for the duplicate; that warn is not
    /// asserted here.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_duplicate_address_in_the_record_is_granted_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let first = session_id(1);
        let second = session_id(2);
        let address = sessions::core::loopback::POOL_FIRST;
        // A stale or hand-edited record with two namespaces on one address.
        let corrupted = format!(
            concat!(
                r#"[{{"namespace":{{"box":{{"session":"{}"}}}},"address":"{}","#,
                r#""granted_at":1}},"#,
                r#"{{"namespace":{{"box":{{"session":"{}"}}}},"address":"{}","#,
                r#""granted_at":2}}]"#
            ),
            first, address, second, address
        );
        let record = state_root.sub_path_unchecked(LEASE_RECORD_FILE);
        std::fs::write(record.as_utf8_path(), corrupted).unwrap();

        let book = lease_book(&state_root);
        // Both recorded namespaces are answered with the address the record
        // holds, and the second ask is not refused (which would strand it).
        assert_eq!(
            book.grant(LeaseNamespace::Box { session: first }),
            LoopbackGrant::Granted(address)
        );
        assert_eq!(
            book.grant(LeaseNamespace::Box { session: second }),
            LoopbackGrant::Granted(address)
        );
    }

    /// A record that cannot be trusted withholds grants rather than guessing:
    /// the one failure NET-010 cannot tolerate is two namespaces on one
    /// address, and a record that will not parse could name one either way.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreadable_record_withholds_grants_rather_than_guessing() {
        let tmp = tempfile::tempdir().unwrap();
        let state_root = lease_root(&tmp);
        let book = lease_book(&state_root);
        let namespace = LeaseNamespace::Box {
            session: session_id(1),
        };
        assert_eq!(
            book.grant(namespace),
            LoopbackGrant::Granted(sessions::core::loopback::POOL_FIRST)
        );

        // A hand-corrupted record: a grant may not proceed over it.
        std::fs::write(
            state_root
                .sub_path_unchecked(LEASE_RECORD_FILE)
                .as_utf8_path(),
            "{not json",
        )
        .unwrap();
        assert_eq!(
            book.grant(LeaseNamespace::Box {
                session: session_id(2)
            }),
            LoopbackGrant::RecordUnavailable
        );
        // And a release over it frees nothing, rather than rewriting the
        // record blind.
        assert_eq!(book.release(namespace), None);

        // An empty file is a first boot, not a corruption.
        std::fs::write(
            state_root
                .sub_path_unchecked(LEASE_RECORD_FILE)
                .as_utf8_path(),
            "",
        )
        .unwrap();
        assert_eq!(
            book.grant(LeaseNamespace::Box {
                session: session_id(3)
            }),
            LoopbackGrant::Granted(sessions::core::loopback::POOL_FIRST),
            "an empty record reads as a fresh host"
        );
    }
}
