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
use sessions::{SessionId, SessionPolicy};

use super::SwitchSubnet;

/// The DNS suffix every PTask box name carries (see the module docs).
pub const HOSTNAME_SUFFIX: &str = "min.internal";

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
    /// address the box's own ports are published at (NET-010) — its own, or
    /// the node's when the reserved local range is absent (NET-123's interim).
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
    /// (R3.6, NET-129): the address the daemon leased from its slice of the
    /// reserved local range when it started, which its boxes' listeners are
    /// forwarded to. Default `127.0.0.1` — a native host's node address is the
    /// host loopback itself.
    node: Ipv4Addr,
    /// Published own-address state, by stable session id (NET-010): the
    /// address and ports an `OwnIp` box's declaration publishes at, from
    /// finalize until destroy.
    own_published: HashMap<SessionId, OwnPublished>,
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
            stopped: HashSet::new(),
            by_host: HashMap::new(),
            by_session: HashMap::new(),
            own: HashMap::new(),
            callers: HashMap::new(),
            by_lease: HashMap::new(),
        }
    }

    /// Sets the node's host loopback address — the address the daemon leased
    /// from its slice for itself (NET-129) — and returns the registry, for
    /// the sessions manager to build its registry with at init, after it has
    /// leased. `HostNet` boxes answer at it; an own-address box that asked for
    /// the shared node address publishes on it too.
    #[must_use]
    pub fn with_node_address(mut self, node: Ipv4Addr) -> Self {
        self.node = node;
        self
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
    /// publishes on (NET-010, NET-011): the box's own host loopback address
    /// where it has one — leased from the reserved local range at finalize
    /// ([`Self::publish_own_address`]) — or the node's shared address until it
    /// does. On a VM host the route targets the box's switch lease as soon as
    /// the attach path has reported one ([`Self::report_own_address`], R3.1,
    /// NET-001); before that, and on a native host always, it targets the
    /// published address, so **the name is held from finalize to destroy**
    /// whether or not a client is attached. `declared` is the session's own
    /// ingress declaration as the ports a request may name
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
        let route = self.own_route(session_id, session_name, declared);
        Some(self.register(session_id, session_name, route))
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

    /// Reports the lease an `OwnIp` box attached with (from the attach path)
    /// and registers the session's box name against it now, so the name routes
    /// exactly when the box is reachable. The lease is kept by the stable
    /// `session_id` — a later rename re-registers against the same lease
    /// without a fresh report — until [`Self::forget_own_address`] drops it at
    /// session end. Reporting also joins the lease onto the session's caller
    /// facts ([`Self::by_lease`]), so a proxied request from this box is
    /// checked against its own egress declaration (NET-070); the applied
    /// external→internal map the attach path hands over is the route's
    /// declared set here — the declaration of record in translation form.
    pub fn report_own_address(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    ) -> Hostname {
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
        let route = self.own_route(session_id, session_name, declared_keys(&ports));
        self.own.insert(session_id, own);
        self.register(session_id, session_name, route)
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
    /// the host loopback address the session leased for the box from the
    /// daemon's slice of the reserved local range, with the external ports its
    /// declaration names — the box's own port numbers, never translated.
    /// Recorded by stable id from finalize until destroy, so the name answers
    /// with no client attached (NET-011) and the box keeps its address across a
    /// rename or a re-attach.
    ///
    /// Two boxes publishing at one address — the shared-address mode — collide
    /// on every port both name (NET-129). The collision is intrinsic to the
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
        let collisions: Vec<_> = self
            .own_published
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
                    .intersection(&ports)
                    .map(move |port| SharedPortCollision {
                        port: *port,
                        other: other_name.clone(),
                    })
            })
            .collect();
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
    /// withdrawn by [`Self::deregister`] in the same deregister.
    pub fn unpublish_own_address(&mut self, session_id: SessionId) -> Option<Ipv4Addr> {
        self.stopped.remove(&session_id);
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
    /// always targets the published address (NET-010): the box's own leased
    /// address where the reserved local range gave it one, the node's shared
    /// address where it did not (NET-123's interim), and the host loopback
    /// where nothing published yet — the pre-instance published-loopback
    /// model, which is what the answerer's fixtures and the proxy's
    /// translation still exercise. `declared` is the ports-a-request-may-name
    /// set, always a gate for an own-address box — empty when the box declares
    /// no ingress; on a lease route the applied map carries it already, so the
    /// translation and the gate stay one declaration.
    fn own_route(
        &self,
        session_id: SessionId,
        session_name: &str,
        declared: BTreeSet<u16>,
    ) -> Route {
        if self.on_switch
            && let Some(own) = self.own.get(&session_id)
        {
            return Route::lease(session_name, own.lease, own.ports.clone());
        }
        Route::loopback(
            session_name,
            self.published_or_node(session_id),
            Some(declared),
        )
    }

    /// The host loopback address an `OwnIp` box's declaration publishes on
    /// (NET-010): its own leased address where finalize published one, else
    /// the node's shared address (NET-123's interim). What the attach path
    /// binds the box's forwards at — read, not re-derived, so the forwards and
    /// the name answer at the one address the registry holds for the box.
    pub(crate) fn published_or_node(&self, session_id: SessionId) -> Ipv4Addr {
        self.own_published
            .get(&session_id)
            .map(|own| own.address)
            .unwrap_or(self.node)
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
    /// publishes at (NET-010) — its own leased address where the reserved
    /// local range gave it one, the node's shared address where it did not —
    /// gate-checked the same way a route's own address is (NET-127).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A lease an attach path would report, with an `18080:8080` ingress
    /// declaration behind it.
    fn leased_ports() -> BTreeMap<u16, u16> {
        BTreeMap::from([(18080, 8080)])
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
    /// attaches (NET-011, NET-013): it registers at the address the box's
    /// declaration publishes on — the node's shared address until finalize's
    /// publish leases the box one of its own (NET-010), the box's own address
    /// from then on. The attach path's report carries the lease the box
    /// attached with (NET-001); on a native host (off the switch) the route
    /// keeps the published-loopback model — the requested port is the
    /// published external one (R3.1) — and the session's re-registration
    /// carries the same declared ports the attach path's map applied
    /// (NET-069). The lease and the publish are both kept by the stable
    /// session id, so a rename re-registers without a fresh report or a fresh
    /// address, and only the session's end drops them.
    #[test]
    fn own_ip_name_is_held_from_finalize_at_the_published_address() {
        let mut reg = HostnameRegistry::new("dev", false);

        // Finalize, with no client attached and no address leased yet: the
        // name is held at the node's shared address — the interim for a host
        // whose daemon has not leased the box one of its own (NET-123).
        let hostname = reg
            .register_own_ip(SessionId::nil(), "web", declared_ports())
            .expect("the name is held at finalize");
        assert_eq!(hostname.as_str(), "web.min.internal");
        let route = reg.resolve("web.min.internal").expect("the name routes");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(loopback_addr(), 18080))
        );
        assert_eq!(
            route.upstream(9000),
            None,
            "a port outside the declaration routes nowhere, attached or not"
        );

        // Finalize's publish leases the box its own address (NET-010), and the
        // re-registration that follows it moves the name there — still with no
        // client attached.
        let own = Ipv4Addr::new(127, 64, 0, 9);
        assert!(
            reg.publish_own_address(SessionId::nil(), "web", own, declared_ports())
                .is_empty(),
            "a box on its own address collides with nothing"
        );
        reg.register_own_ip(SessionId::nil(), "web", declared_ports())
            .expect("re-registered at the box's own address");
        let route = reg
            .resolve("web.min.internal")
            .expect("the name routes at its own address");
        assert_eq!(
            route.upstream(18080),
            Some(SocketAddr::new(IpAddr::V4(own), 18080)),
            "the name answers at the box's own address at its own port number"
        );
        assert_eq!(route.session(), "web");

        // The attach path reports the lease with the box's ingress
        // declaration. On a native host the route keeps the published address:
        // the published external port is carried in the URL, and the
        // forwarder sits on the box's own address at that same published
        // port.
        let hostname =
            reg.report_own_address(SessionId::nil(), "web", Ipv4Addr::LOCALHOST, leased_ports());
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
        let node = Ipv4Addr::new(127, 64, 0, 200);
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

    /// NET-128: a box stopped on a **shared address** answers NODATA — held, so
    /// the zone never says NXDOMAIN for a box that exists — because the
    /// node's own listener at that port must not answer for a dead box. A box
    /// on an address of its own keeps answering A while it is stopped: the
    /// address answers for it alone, and a lookup says where the box would be.
    #[test]
    fn stopped_shared_address_box_is_nodata() {
        let node = Ipv4Addr::new(127, 64, 0, 200);
        let mut reg = HostnameRegistry::new("dev", false).with_node_address(node);
        let shared = id("1");
        let own = id("2");
        let port = BTreeSet::from([8080u16]);

        // One box publishing on the node's shared address, one on an address
        // of its own — both registered from finalize, as the session actor
        // does.
        reg.publish_own_address(shared, "shared", node, port.clone());
        reg.register_own_ip(shared, "shared", port.clone());
        let own_address = Ipv4Addr::new(127, 64, 0, 9);
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
        assert_eq!(own_address, Some(Ipv4Addr::new(127, 64, 0, 9)));

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
                address: Some(Ipv4Addr::new(127, 64, 0, 9)),
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
            Some(Ipv4Addr::new(127, 64, 0, 9))
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
        let node = Ipv4Addr::new(127, 64, 0, 200);
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
        let own_address = Ipv4Addr::new(127, 64, 0, 9);
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
}
