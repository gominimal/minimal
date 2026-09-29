//! The frame-level egress verdict (NET-062, NET-063, NET-064, NET-084).
//!
//! One pure decision — admit or drop — over an owned frame summary and an
//! owned rule set, deliberately separate from the relay loop that applies
//! it (spec NET, Tiers): the daemon's relay summarizes each frame, asks for
//! the verdict, and on a drop simply does not write the frame on. Nothing
//! here knows about sockets, tasks, or clocks, which is what lets the Kani
//! harness below exhaust the decision.
//!
//! What the verdict encodes:
//!
//! * **The source must be the box's lease** — a frame whose source address
//!   (an IPv4 frame's IPv4 source, an ARP frame's sender protocol address)
//!   is not the lease the relay was attached with is rejected before any
//!   family or rule is consulted (NET-084). No box may speak from an
//!   address but its own.
//! * **ARP is admitted** — address resolution on the shared L2 switch is a
//!   declared path for every box; the gateway's MAC must be learnable for
//!   any egress at all to work. An ARP frame from the lease, that is: its
//!   sender address is a source like any other, and a foreign one is
//!   rejected by the lease check above.
//! * **IPv6 is dropped** — v1 declares no IPv6 admission path anywhere
//!   (guest IPv6 disabled, NET-082; AAAA answered NODATA, NET-136), so an
//!   IPv6 frame is dropped as a family rather than matched against rules.
//! * **Every other `EtherType` is dropped** — an undeclared family, VLAN tags
//!   included: admitting by default would hand any encapsulation a path
//!   around the rules.
//! * **IPv4 is decided by the box's rules** — `allow_protocols`, then
//!   `deny_subnets`, then `allow_subnets` (a `None` dimension allows all, a
//!   `Some([])` one allows nothing) — with one carve-out: a UDP datagram to
//!   the resolver Minimal owns for the box, at that resolver's address and
//!   port, is admitted under any declaration including deny-all (NET-079,
//!   NET-134), because a box that cannot resolve cannot use an allow list
//!   of names either.
//!
//! The rules are compiled once per box at attach
//! ([`EgressRules::from_policy`]); the per-frame work is [`summarize`] plus
//! [`verdict`], both allocation-free.
//!
//! Beside the frame verdict sits its name-level counterpart, the DNS
//! rebinding intersection (NET-066, NET-067): the pure decision of which
//! addresses a name *resolved to* may ever be admitted for a box, once the
//! box's denies and the infrastructure deny set are subtracted. The relay
//! (not this module) holds the admission window; what lives here is the
//! arithmetic the window stores the results of, kept pure and free of
//! resolver I/O so the NET-067 harness can exhaust it.

use crate::{EgressPolicy, IpProto};

/// Ethernet II header length: destination MAC (6) + source MAC (6) + `EtherType` (2).
const ETH_HDR: usize = 14;
/// `EtherType` for ARP.
const ETHERTYPE_ARP: u16 = 0x0806;
/// `EtherType` for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// `EtherType` for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// The port DNS is served on: the resolver carve-out's port (NET-079).
const DNS_PORT: u16 = 53;

/// Which L2 family a frame belongs to — the first fact the verdict needs,
/// because three of the four families are decided without any rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFamily {
    /// ARP: address resolution, a declared path for every box.
    Arp,
    /// IPv4: the one family the rules decide.
    Ipv4,
    /// IPv6: no v1 admission path exists, so it is dropped as a family
    /// (NET-082, NET-136).
    Ipv6,
    /// An `EtherType` v1 declares no admission path for, carried raw — VLAN
    /// tags (0x8100) included, since a VLAN-tagged IPv4 frame is not an
    /// IPv4 frame to this header reader.
    UndeclaredFamily(u16),
    /// Too short to carry the header the family decision, the rule match or
    /// the lease check reads: below 14 bytes there is not even an
    /// `EtherType`, an IPv4-ethertype frame below 34 bytes has no readable
    /// IPv4 header, and an ARP frame too short to carry four bytes of
    /// sender protocol address at the `hlen` its header declares has no
    /// readable source. Never admitted — an unreadable frame
    /// cannot be a declared one, and an unattributable one cannot be the
    /// lease's (NET-084).
    Truncated,
}

/// The facts of one frame the egress verdict decides on, extracted by
/// [`summarize`] and owned outright: no borrow of the frame survives the
/// extraction, so the decision is a pure function of this value plus the
/// box's [`EgressRules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSummary {
    family: FrameFamily,
    /// The source address the frame carries: an IPv4 frame's header
    /// source, or an ARP frame's sender protocol address — read whatever
    /// protocol type the frame claims for it — the address the lease check
    /// (NET-084) compares against the box's lease. `None` when the frame
    /// carries no readable one: IPv6, an undeclared family, or a frame too
    /// short to read.
    src: Option<[u8; 4]>,
    /// The IPv4 destination address, when the frame carries one.
    dst: Option<[u8; 4]>,
    /// The IPv4 protocol number, when the frame carries one.
    proto: Option<u8>,
    /// The L4 destination port, or `0` when there is none to read — a
    /// non-first fragment or a truncated L4 header. `0` can never equal
    /// [`DNS_PORT`], so the missing port fails the resolver carve-out
    /// closed rather than opening it.
    dst_port: u16,
}

impl FrameSummary {
    /// The frame's family.
    #[must_use]
    pub fn family(&self) -> FrameFamily {
        self.family
    }

    /// The source address the frame carries — an IPv4 frame's header
    /// source, or an ARP frame's sender protocol address, whatever
    /// protocol the frame claims for it (the address the lease check
    /// reads). `None` when the frame carries no readable one.
    #[must_use]
    pub fn source(&self) -> Option<[u8; 4]> {
        self.src
    }

    /// The IPv4 destination address, when the frame carries one.
    #[must_use]
    pub fn destination(&self) -> Option<[u8; 4]> {
        self.dst
    }

    /// The IPv4 protocol number, when the frame carries one.
    #[must_use]
    pub fn protocol(&self) -> Option<u8> {
        self.proto
    }

    /// The L4 destination port, `0` when the frame carries none readable.
    #[must_use]
    pub fn destination_port(&self) -> u16 {
        self.dst_port
    }
}

/// Extracts the verdict's inputs from one Ethernet II frame. Pure and
/// allocation-free: every read is bounds-checked before it happens, so a
/// truncated or hostile frame yields [`FrameFamily::Truncated`] (or a
/// family with no address) rather than an out-of-bounds read.
#[must_use]
pub fn summarize(frame: &[u8]) -> FrameSummary {
    let none = |family| FrameSummary {
        family,
        src: None,
        dst: None,
        proto: None,
        dst_port: 0,
    };
    if frame.len() < ETH_HDR {
        return none(FrameFamily::Truncated);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let family = match ethertype {
        ETHERTYPE_ARP => {
            // ARP: the sender protocol address is the frame's source — the
            // address the lease check (NET-084) compares. It sits `hlen`
            // bytes of sender hardware into the ARP payload, behind 8 bytes
            // of fixed header, and the check reads four bytes of it, so the
            // offset is bounds-checked before it is used. The protocol type
            // the frame claims for the address is not consulted: an ARP
            // claiming a protocol other than IPv4 must be no way to
            // announce an address unchecked, so the slot is the source
            // whatever the frame claims to speak. A frame too short to
            // carry four bytes of sender address at its own `hlen` has no
            // readable source: it cannot be attributed to the lease, so it
            // is truncated rather than admitted.
            if frame.len() < ETH_HDR + 8 {
                return none(FrameFamily::Truncated);
            }
            let hlen = frame[ETH_HDR + 4] as usize;
            let spa = ETH_HDR + 8 + hlen;
            if frame.len() < spa + 4 {
                return none(FrameFamily::Truncated);
            }
            return FrameSummary {
                family: FrameFamily::Arp,
                src: Some([frame[spa], frame[spa + 1], frame[spa + 2], frame[spa + 3]]),
                dst: None,
                proto: None,
                dst_port: 0,
            };
        }
        ETHERTYPE_IPV6 => return none(FrameFamily::Ipv6),
        ETHERTYPE_IPV4 => FrameFamily::Ipv4,
        _ => return none(FrameFamily::UndeclaredFamily(ethertype)),
    };
    // IPv4: the fixed 20-byte header carries the source, destination and
    // protocol.
    let ip = &frame[ETH_HDR..];
    if ip.len() < 20 {
        return none(FrameFamily::Truncated);
    }
    // IHL is the header length in 32-bit words; the L4 destination port
    // sits at its end, on a first fragment only. Anything else means no
    // readable port, and `dst_port == 0` keeps the carve-out closed.
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let dst_port = if ihl >= 20 && frag_offset == 0 && ip.len() >= ihl + 4 {
        u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]])
    } else {
        0
    };
    FrameSummary {
        family,
        src: Some([ip[12], ip[13], ip[14], ip[15]]),
        dst: Some([ip[16], ip[17], ip[18], ip[19]]),
        proto: Some(ip[9]),
        dst_port,
    }
}

/// An IPv4 subnet as declared in an egress rule: an address and a prefix
/// length, both owned. Parsed from the same `a.b.c.d/n` spelling
/// [`EgressPolicy`] validates at launch, so every entry that reaches
/// [`EgressRules::from_policy`] parses.
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// The network address, in wire byte order.
    addr: [u8; 4],
    /// The prefix length, `0..=32`.
    prefix: u8,
}

impl Ipv4Cidr {
    /// Parses `a.b.c.d/n` (prefix at most `/32`). Returns `None` for
    /// anything else — a bare address, a too-long prefix, or an IPv6 CIDR,
    /// which can never match: IPv6 frames are dropped as a family before
    /// any rule is consulted.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let addr = addr.parse::<std::net::Ipv4Addr>().ok()?;
        Some(Self {
            addr: addr.octets(),
            prefix,
        })
    }

    /// Whether `ip` falls inside this subnet. Panic-free for any `prefix`
    /// the type can hold — the shift is guarded at both ends — so an
    /// arbitrary (proof-symbolic) CIDR cannot fault the match.
    #[must_use]
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = match self.prefix {
            0 => 0,
            32.. => u32::MAX,
            p => u32::MAX << (32 - p),
        };
        (u32::from_be_bytes(ip) & mask) == (u32::from_be_bytes(self.addr) & mask)
    }

    /// The single-address `/32` of one address: the shape the infrastructure
    /// deny set holds a gateway's own addresses in, so they are named
    /// individually rather than only through the plane that contains them.
    #[must_use]
    pub fn exact(addr: [u8; 4]) -> Self {
        Self { addr, prefix: 32 }
    }
}

/// A box's compiled egress rules: the three declaration dimensions of an
/// [`EgressPolicy`], owned and matchable, plus the addresses the verdict is
/// keyed to — the resolver the carve-out admits, and the box's lease, the
/// one source its frames may carry.
///
/// Each dimension is `None` to allow all and `Some(list)` to allow exactly
/// the listed entries — so a deny-all declaration is `Some(vec![])` on
/// every dimension, and the carve-out is what keeps a deny-all box
/// resolving.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressRules {
    /// Allowed IPv4 protocol numbers; `None` allows all.
    allow_protocols: Option<Vec<u8>>,
    /// Allowed destination subnets; `None` allows all.
    allow_subnets: Option<Vec<Ipv4Cidr>>,
    /// Denied destination subnets, subtracted from the allowed set; `None`
    /// denies nothing.
    deny_subnets: Option<Vec<Ipv4Cidr>>,
    /// The address of the resolver Minimal owns for this box (the switch
    /// gateway), which the carve-out admits at [`DNS_PORT`] under any
    /// declaration.
    resolver: [u8; 4],
    /// The box's lease on the switch — the one source address its frames
    /// may carry, which the verdict rejects any other of (NET-084). Known
    /// when the box is attached, the same moment the policy is compiled.
    lease: [u8; 4],
}

impl EgressRules {
    /// Assembles a rule set from its dimensions. The shape the Kani proof
    /// and [`EgressRules::from_policy`] share.
    #[must_use]
    pub fn new(
        allow_protocols: Option<Vec<u8>>,
        allow_subnets: Option<Vec<Ipv4Cidr>>,
        deny_subnets: Option<Vec<Ipv4Cidr>>,
        resolver: [u8; 4],
        lease: [u8; 4],
    ) -> Self {
        Self {
            allow_protocols,
            allow_subnets,
            deny_subnets,
            resolver,
            lease,
        }
    }

    /// Compiles a session's egress policy into rules. An absent policy is
    /// allow-all on every dimension (the shipped default, 03-spec R2.1;
    /// NET-074 changes it once the deny-all default is in force), and a
    /// declared dimension keeps only the entries the launch-time validation
    /// already checked parse. `resolver` is the switch gateway's address,
    /// the resolver this box's carve-out is keyed to, and `lease` the box's
    /// own address on the switch — the source its frames must carry
    /// (NET-084).
    #[must_use]
    pub fn from_policy(policy: Option<&EgressPolicy>, resolver: [u8; 4], lease: [u8; 4]) -> Self {
        let Some(policy) = policy else {
            return Self::new(None, None, None, resolver, lease);
        };
        let allow_protocols: Option<Vec<u8>> = policy
            .allow_protocols
            .as_ref()
            .map(|list| list.iter().map(|proto| wire_number(*proto)).collect());
        let subnets = |entries: &Option<Vec<String>>| -> Option<Vec<Ipv4Cidr>> {
            entries.as_ref().map(|list| {
                list.iter()
                    .filter_map(|cidr| Ipv4Cidr::parse(cidr))
                    .collect()
            })
        };
        Self::new(
            allow_protocols,
            subnets(&policy.allow_subnets),
            subnets(&policy.deny_subnets),
            resolver,
            lease,
        )
    }

    /// The address of the resolver this box's carve-out is keyed to.
    #[must_use]
    pub fn resolver(&self) -> [u8; 4] {
        self.resolver
    }

    /// The compiled `allow_subnets`, `None` when the dimension allows all —
    /// the one dimension the rebinding intersection also reads, as the
    /// RFC 1918 exemption's signal (NET-067): private space is admitted for
    /// a name only where the box's own address declaration covers it.
    #[must_use]
    pub fn allow_subnets(&self) -> Option<&[Ipv4Cidr]> {
        self.allow_subnets.as_deref()
    }

    /// The compiled `deny_subnets`, `None` when nothing is denied — the
    /// deny half the rebinding intersection subtracts from every resolved
    /// answer before anything is admitted (NET-067).
    #[must_use]
    pub fn deny_subnets(&self) -> Option<&[Ipv4Cidr]> {
        self.deny_subnets.as_deref()
    }

    /// The box's lease — the one source address its frames may carry.
    #[must_use]
    pub fn lease(&self) -> [u8; 4] {
        self.lease
    }
}

/// An [`IpProto`]'s IPv4 wire number (TCP 6, UDP 17, ICMP 1). Exhaustive
/// on purpose: a future `IpProto` variant must name its own wire number
/// here — or fail to compile — rather than silently falling into an
/// allow list under a wrong number.
fn wire_number(proto: IpProto) -> u8 {
    match proto {
        IpProto::Tcp => 6,
        IpProto::Udp => IPPROTO_UDP,
        IpProto::Icmp => 1,
    }
}

/// The egress verdict for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVerdict {
    /// The frame is declared: write it on.
    Admit,
    /// The frame is not declared: drop it, without answering (NET-062 — a
    /// drop is not a reset).
    Drop(DropReason),
}

/// Why a frame was dropped, carrying what the rate-limited warning names
/// (the destination, the protocol, the rule) so the relay can log the drop
/// without re-deriving any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The frame's source is not the lease the relay was attached with — a
    /// spoofed or foreign source, rejected before any family or rule is
    /// consulted (NET-084).
    ForeignSource {
        /// The source address the frame carried.
        src: [u8; 4],
        /// The lease the frame's source had to be.
        lease: [u8; 4],
    },
    /// IPv6: dropped as a family, no v1 admission path (NET-082, NET-136).
    Ipv6,
    /// An `EtherType` no admission path is declared for, carried raw.
    UndeclaredFamily(u16),
    /// Too short to read the header a rule match needs. Never declared.
    Truncated,
    /// The L4 protocol is not among `allow_protocols`.
    UndeclaredProtocol {
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
    /// The destination is in `deny_subnets`.
    DeniedSubnet {
        /// The frame's IPv4 destination address.
        dst: [u8; 4],
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
    /// The destination is not in `allow_subnets`.
    UndeclaredSubnet {
        /// The frame's IPv4 destination address.
        dst: [u8; 4],
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
}

impl DropReason {
    /// The rule that dropped the frame: the rate-limit key and the
    /// warning's `rule_matched` field (NET-062).
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::ForeignSource { .. } => "egress-foreign-source",
            Self::Ipv6 => "egress-ipv6",
            Self::UndeclaredFamily(_) => "egress-undeclared-ethertype",
            Self::Truncated => "egress-truncated-ipv4",
            Self::UndeclaredProtocol { .. } => "egress-undeclared-protocol",
            Self::DeniedSubnet { .. } => "egress-denied-subnet",
            Self::UndeclaredSubnet { .. } => "egress-undeclared-subnet",
        }
    }

    /// The frame's IPv4 destination address, when the drop carries one.
    #[must_use]
    pub fn destination(&self) -> Option<[u8; 4]> {
        match self {
            Self::ForeignSource { .. }
            | Self::Ipv6
            | Self::UndeclaredFamily(_)
            | Self::Truncated
            | Self::UndeclaredProtocol { .. } => None,
            Self::DeniedSubnet { dst, .. } | Self::UndeclaredSubnet { dst, .. } => Some(*dst),
        }
    }

    /// The frame's IPv4 protocol number, when the drop carries one.
    #[must_use]
    pub fn protocol(&self) -> Option<u8> {
        match self {
            Self::UndeclaredProtocol { proto }
            | Self::DeniedSubnet { proto, .. }
            | Self::UndeclaredSubnet { proto, .. } => Some(*proto),
            Self::ForeignSource { .. }
            | Self::Ipv6
            | Self::UndeclaredFamily(_)
            | Self::Truncated => None,
        }
    }
}

/// NET-084: whether a frame's source is foreign — an address other than the
/// `lease` the relay was attached with. `Some(reason)` when the frame must
/// be rejected; `None` when it carries the lease, or no readable source at
/// all — an IPv6 or undeclared-family frame, or a truncated one, none of
/// which `verdict` admits either way. An IPv4 frame's source is its header
/// source address; an ARP frame's is its sender protocol address, read
/// whatever protocol type the frame claims for it — so a foreign address
/// cannot be announced by address resolution either, least of all by an
/// ARP dressed up as another protocol.
#[must_use]
pub fn foreign_source(summary: &FrameSummary, lease: [u8; 4]) -> Option<DropReason> {
    let src = summary.src?;
    (src != lease).then_some(DropReason::ForeignSource { src, lease })
}

/// The admit-or-drop decision for one frame summary against one box's rules
/// — the pure function NET-062, NET-063, NET-064, and NET-084 all reduce
/// to, and the one the Kani harness exhausts.
///
/// Order of the checks is part of the contract: the lease check comes
/// first, so a frame from a foreign source is rejected whatever family or
/// destination it carries (NET-084); the resolver carve-out then comes
/// before the rules, so a box that denies the resolver's own subnet still
/// resolves (NET-079); `deny_subnets` then carves out of what the allows
/// admit; and a drop never depends on the rule lists being sorted.
#[must_use]
pub fn verdict(summary: &FrameSummary, rules: &EgressRules) -> FrameVerdict {
    if let Some(reason) = foreign_source(summary, rules.lease) {
        return FrameVerdict::Drop(reason);
    }
    match summary.family {
        FrameFamily::Arp => FrameVerdict::Admit,
        FrameFamily::Ipv6 => FrameVerdict::Drop(DropReason::Ipv6),
        FrameFamily::UndeclaredFamily(ethertype) => {
            FrameVerdict::Drop(DropReason::UndeclaredFamily(ethertype))
        }
        FrameFamily::Truncated => FrameVerdict::Drop(DropReason::Truncated),
        FrameFamily::Ipv4 => verdict_ipv4(summary, rules),
    }
}

/// The IPv4 half of the verdict: the carve-out, then the three declared
/// dimensions. `summary`'s address and protocol are read only after the
/// [`FrameFamily::Truncated`] case has been ruled out, so both are `Some`
/// here.
fn verdict_ipv4(summary: &FrameSummary, rules: &EgressRules) -> FrameVerdict {
    let Some(dst) = summary.dst else {
        return FrameVerdict::Drop(DropReason::Truncated);
    };
    let Some(proto) = summary.proto else {
        return FrameVerdict::Drop(DropReason::Truncated);
    };
    // NET-079 / NET-134: the resolver Minimal owns for the box is the one
    // carve-out from a deny-all verdict — at its address and port, whatever
    // the rules say, because no box can be denied its own resolution.
    if proto == IPPROTO_UDP && dst == rules.resolver && summary.dst_port == DNS_PORT {
        return FrameVerdict::Admit;
    }
    if let Some(allow) = &rules.allow_protocols
        && !allow.contains(&proto)
    {
        return FrameVerdict::Drop(DropReason::UndeclaredProtocol { proto });
    }
    if let Some(deny) = &rules.deny_subnets
        && deny.iter().any(|cidr| cidr.contains(dst))
    {
        return FrameVerdict::Drop(DropReason::DeniedSubnet { dst, proto });
    }
    if let Some(allow) = &rules.allow_subnets
        && !allow.iter().any(|cidr| cidr.contains(dst))
    {
        return FrameVerdict::Drop(DropReason::UndeclaredSubnet { dst, proto });
    }
    FrameVerdict::Admit
}

/// The infrastructure deny set of the DNS rebinding intersection (design
/// §5.3, NET-067): the ranges an allowed name's answer may never be admitted
/// into, whatever the box's own rules say — the fabric's own space and the
/// ranges that stand for the host, not destinations.
///
/// Two classes, because one of them is conditional:
///
/// * **Fixed** — link-local and the metadata services living in it, loopback
///   space, the whole `100.64.0.0/10` plane the switch fabric draws its
///   subnets from (so no answer can ever name a box, the gateway, or the
///   daemon itself), and the gateway's own two addresses: the answerer's (the
///   resolver the box's carve-out is keyed to, NET-079) and the helper's (the
///   deprecated host-alias literal, NET-004), each held as a `/32` so both
///   are named individually rather than only through the plane containing
///   them. Refused under every declaration.
/// * **RFC 1918** — private space, refused *unless the box's
///   `egress.allow_subnets` covers the answer*: a developer who wants a name
///   to reach the LAN says so by allowing the range, so a name rule cannot
///   become a way around leaving it undeclared.
///
/// Owned outright — no borrow of the policy survives the attach — which is
/// what keeps [`rebinding_admits`] a pure function over owned addresses and
/// CIDRs, separate from resolver I/O, as the NET-067 harness requires.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InfrastructureDenySet {
    /// Ranges refused under every declaration.
    fixed: Vec<Ipv4Cidr>,
    /// RFC 1918 space, refused unless `allow_subnets` covers the answer.
    rfc1918: Vec<Ipv4Cidr>,
}

impl InfrastructureDenySet {
    /// The set for one box's attach: the always-refused ranges, plus the
    /// gateway's `resolver` (where the box's own queries are answered) and
    /// `host_alias` (the helper's address) as `/32`s.
    ///
    /// Both gateway addresses lie inside the plane today; they are named
    /// individually so the set still refuses them if the plane is ever
    /// renumbered out from under them.
    ///
    /// # Panics
    ///
    /// Never: every range is a constant that parses.
    #[must_use]
    pub fn new(resolver: [u8; 4], host_alias: [u8; 4]) -> Self {
        // Every constant parses; the parses exist so the set's contents are
        // spelled as ranges, not as byte arrays.
        let cidr = |s: &'static str| Ipv4Cidr::parse(s).expect("a constant CIDR parses");
        Self {
            fixed: vec![
                // Link-local, and the metadata services living in it.
                cidr("169.254.0.0/16"),
                // Loopback space.
                cidr("127.0.0.0/8"),
                // The plane the switch fabric draws subnets from.
                cidr("100.64.0.0/10"),
                Ipv4Cidr::exact(resolver),
                Ipv4Cidr::exact(host_alias),
            ],
            rfc1918: vec![
                cidr("10.0.0.0/8"),
                cidr("172.16.0.0/12"),
                cidr("192.168.0.0/16"),
            ],
        }
    }
}

/// Why the rebinding intersection refused one resolved address, carrying the
/// rule its rate-limited warning is keyed to (mirroring [`DropReason::rule`],
/// the frame verdict's naming discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebindingRefusal {
    /// The answer lies in the box's `deny_subnets`: a declared deny is
    /// subtractive from every admission path, a name rule included.
    DeniedSubnet,
    /// The answer lies in the infrastructure deny set: a fixed range, or
    /// RFC 1918 the box's `allow_subnets` does not cover.
    Infrastructure,
}

impl RebindingRefusal {
    /// The rule that refused the answer: the rate-limit key and the warning's
    /// `rule_matched` field (NET-067).
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::DeniedSubnet => "dns-rebinding-denied-subnet",
            Self::Infrastructure => "dns-rebinding-infrastructure",
        }
    }
}

/// The DNS rebinding intersection's decision for one resolved address
/// (NET-066, NET-067): admitted — `Ok(())` — exactly when nothing refuses
/// it, where RFC 1918 is the one infrastructure class an `allow_subnets`
/// entry exempts.
///
/// Pure over owned addresses and CIDRs, and deliberately separate from any
/// resolver: the daemon hands this function the addresses a resolver already
/// returned and learns which of them may ever be admitted, which is what
/// lets the Kani harness exhaust the decision without a socket in sight.
///
/// The order of the checks is part of the contract: the box's own denies
/// first — a declared deny outranks every allowance — then the fixed
/// infrastructure ranges, then RFC 1918 under its `allow_subnets` exemption.
/// An undeclared `allow_subnets` (`None`, allow-all) counts as covering the
/// answer: the box's address dimension is open, so the name path opens with
/// it rather than refusing answers the box can already reach.
///
/// # Errors
///
/// [`RebindingRefusal`] — never an I/O or parse failure; the answer is
/// refused exactly when a deny or the infrastructure set names it.
pub fn rebinding_admits(
    answer: [u8; 4],
    allow: Option<&[Ipv4Cidr]>,
    deny: Option<&[Ipv4Cidr]>,
    infrastructure: &InfrastructureDenySet,
) -> Result<(), RebindingRefusal> {
    if let Some(denied) = deny
        && denied.iter().any(|cidr| cidr.contains(answer))
    {
        return Err(RebindingRefusal::DeniedSubnet);
    }
    if infrastructure
        .fixed
        .iter()
        .any(|cidr| cidr.contains(answer))
    {
        return Err(RebindingRefusal::Infrastructure);
    }
    if infrastructure
        .rfc1918
        .iter()
        .any(|cidr| cidr.contains(answer))
        && !allow.is_none_or(|list| list.iter().any(|cidr| cidr.contains(answer)))
    {
        return Err(RebindingRefusal::Infrastructure);
    }
    Ok(())
}

/// [`rebinding_intersection`]'s split of one name's resolved addresses:
/// which may be admitted, and which are refused with the reason to log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebindingSplit {
    /// The addresses that may be admitted for the admission window, in the
    /// order the answer carried them.
    pub admitted: Vec<[u8; 4]>,
    /// The refused addresses, each with the rule that refused it, in the
    /// order the answer carried them.
    pub refused: Vec<([u8; 4], RebindingRefusal)>,
}

/// Splits one name's resolved addresses by [`rebinding_admits`]: the
/// addresses that may be admitted for the admission window, and the
/// refusals to log — each refused address with its reason, in the order the
/// answer carried them. This is the set-shaped wrapper the daemon calls
/// once per DNS reply; the decision itself stays per-address, which is the
/// shape the harness proves.
#[must_use]
pub fn rebinding_intersection(
    answers: &[[u8; 4]],
    allow: Option<&[Ipv4Cidr]>,
    deny: Option<&[Ipv4Cidr]>,
    infrastructure: &InfrastructureDenySet,
) -> RebindingSplit {
    let mut split = RebindingSplit {
        admitted: Vec::with_capacity(answers.len()),
        refused: Vec::with_capacity(answers.len()),
    };
    for answer in answers {
        match rebinding_admits(*answer, allow, deny, infrastructure) {
            Ok(()) => split.admitted.push(*answer),
            Err(reason) => split.refused.push((*answer, reason)),
        }
    }
    split
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The switch gateway's address, the resolver every rule set below is
    /// keyed to (the default switch subnet's gateway).
    const RESOLVER: [u8; 4] = [100, 64, 0, 1];

    /// The lease every rule set below is compiled with — the one source
    /// address the frames below may carry (NET-084).
    const LEASE: [u8; 4] = [100, 64, 0, 9];

    /// IPv4 protocol number for TCP, for the frames below.
    const IPPROTO_TCP: u8 = 6;

    /// A deny-all rule set: every dimension declared, nothing listed.
    fn deny_all() -> EgressRules {
        EgressRules::new(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
            RESOLVER,
            LEASE,
        )
    }

    /// An Ethernet II frame carrying `ethertype` and `payload`.
    fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETH_HDR + payload.len());
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// An ARP payload for `spa`: a full Ethernet/IPv4 ARP request, whose
    /// sender protocol address is the source the lease check reads.
    fn arp_payload(spa: [u8; 4]) -> Vec<u8> {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        arp.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype: IPv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&1u16.to_be_bytes()); // oper: request
        arp.extend_from_slice(&[0x52, 0x54, 0x00, 0x40, 0x00, 0x09]); // sender MAC
        arp.extend_from_slice(&spa); // sender protocol address
        arp.extend_from_slice(&[0; 6]); // target MAC (unread)
        arp.extend_from_slice(&RESOLVER); // target protocol address
        arp
    }

    /// An IPv4 packet payload: a header for `proto` carrying `frag_offset`
    ///'s low 13 bits, followed by `l4`.
    fn ip_payload(proto: u8, src: [u8; 4], dst: [u8; 4], frag_offset: u16, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20 + l4.len()];
        ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
        ip[6..8].copy_from_slice(&frag_offset.to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        ip[20..].copy_from_slice(l4);
        ip
    }

    /// An L4 header whose destination port is `port` (the source port is a
    /// fixed ephemeral).
    fn l4(port: u16) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&40000u16.to_be_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out
    }

    /// An IPv4 frame for `proto` from the lease to `dst`:`port`.
    fn ipv4_frame(proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        ipv4_frame_from(LEASE, proto, dst, port)
    }

    /// An IPv4 frame for `proto` from `src` to `dst`:`port`.
    fn ipv4_frame_from(src: [u8; 4], proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        eth_frame(ETHERTYPE_IPV4, &ip_payload(proto, src, dst, 0, &l4(port)))
    }

    fn admits(frame: &[u8], rules: &EgressRules) -> bool {
        matches!(verdict(&summarize(frame), rules), FrameVerdict::Admit)
    }

    /// NET-062's property from the family side: the three families decided
    /// without rules behave identically under allow-all and deny-all.
    #[test]
    fn families_decided_without_rules() {
        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE));
        assert!(
            admits(&arp, &allow_all) && admits(&arp, &deny_all()),
            "ARP is a declared path for every box"
        );
        let ipv6 = eth_frame(ETHERTYPE_IPV6, &[0u8; 40]);
        assert!(
            !admits(&ipv6, &allow_all) && !admits(&ipv6, &deny_all()),
            "IPv6 has no admission path under any declaration"
        );
        for ethertype in [0x8100, 0x88A2, 0x0000] {
            let undeclared = eth_frame(ethertype, &[0u8; 8]);
            let why = match verdict(&summarize(&undeclared), &allow_all) {
                FrameVerdict::Drop(DropReason::UndeclaredFamily(et)) => et,
                other => panic!("expected an undeclared family, got {other:?}"),
            };
            assert_eq!(why, ethertype);
            assert!(
                !admits(&undeclared, &allow_all),
                "ethertype {ethertype:#06x} is not a declared path"
            );
        }
        // Below the Ethernet header there is not even a family to read.
        assert_eq!(
            summarize(&[0u8; 13]).family,
            FrameFamily::Truncated,
            "a frame shorter than an Ethernet header is truncated"
        );
    }

    /// NET-084: a frame whose source is not the box's lease is rejected —
    /// an IPv4 frame carrying another address in its header, or an ARP frame
    /// whose sender protocol address is another box's — whatever family,
    /// destination or declaration it carries; the same frame from the lease
    /// is admitted; and an ARP frame too short to carry its sender address
    /// has no readable source and is truncated rather than admitted.
    #[test]
    fn foreign_source_is_rejected_whatever_it_carries() {
        // Under a declaration that allows everything, the destination is
        // not what drops this frame: the source is.
        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let spoofed = ipv4_frame_from([203, 0, 113, 7], IPPROTO_TCP, [10, 1, 2, 3], 443);
        assert_eq!(
            verdict(&summarize(&spoofed), &allow_all),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );
        // The same frame from the lease is the declared thing it looks like.
        assert!(admits(
            &ipv4_frame(IPPROTO_TCP, [10, 1, 2, 3], 443),
            &allow_all
        ));

        // The resolver carve-out does not rescue a foreign source either:
        // deny-all admits DNS to the resolver, from the lease only.
        let dns = ipv4_frame_from([203, 0, 113, 7], IPPROTO_UDP, RESOLVER, DNS_PORT);
        assert_eq!(
            verdict(&summarize(&dns), &deny_all()),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );
        assert!(admits(
            &ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT),
            &deny_all()
        ));

        // ARP is a declared path — from the lease. A frame announcing
        // another box's address as its sender is a foreign source too.
        let arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE));
        assert!(admits(&arp, &deny_all()), "the lease's own ARP resolves");
        assert_eq!(summarize(&arp).source(), Some(LEASE));
        let arp_spoof = eth_frame(ETHERTYPE_ARP, &arp_payload([203, 0, 113, 7]));
        assert_eq!(
            verdict(&summarize(&arp_spoof), &deny_all()),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );

        // An ARP frame too short to carry its sender protocol address has
        // no readable source: it cannot be attributed to the lease, so it
        // is truncated — never admitted. (The sender address sits 14 bytes
        // into the ARP payload, behind the 8-byte fixed header and the
        // 6-byte sender hardware address; 14 payload bytes stop short of
        // it.)
        let short_arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE)[..14]);
        assert_eq!(summarize(&short_arp).family, FrameFamily::Truncated);
        assert!(!admits(&short_arp, &allow_all));
    }

    /// The sender protocol address slot is an ARP frame's source whatever
    /// protocol the frame claims for it (NET-084): an ARP announcing a
    /// foreign address under a protocol type other than IPv4 — or under an
    /// unexpected `hlen` or `plen` — is a foreign source like any other,
    /// rejected and named the same way; an ARP whose slot carries the lease
    /// is the declared family whatever it claims; and one too short to
    /// carry four bytes of sender address at its own `hlen` is truncated,
    /// never admitted.
    #[test]
    fn arp_source_is_read_whatever_protocol_the_frame_claims() {
        /// An ARP payload claiming `ptype`, `hlen` and `plen`, whose sender
        /// protocol address is `spa` — sitting `hlen` bytes of sender
        /// hardware into the payload, and the `hlen` hardware bytes are
        /// emitted so the address really is where the header says.
        fn arp_claiming(ptype: u16, hlen: u8, plen: u8, spa: &[u8]) -> Vec<u8> {
            let mut arp = Vec::new();
            arp.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
            arp.extend_from_slice(&ptype.to_be_bytes()); // ptype: as claimed
            arp.push(hlen);
            arp.push(plen);
            arp.extend_from_slice(&1u16.to_be_bytes()); // oper: request
            let mac = [0x52u8, 0x54, 0x00, 0x40, 0x00, 0x09];
            arp.extend(mac.iter().cycle().take(usize::from(hlen))); // sender hardware address
            arp.extend_from_slice(spa); // sender protocol address
            arp
        }

        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let foreign = [203, 0, 113, 7];

        // An ARP claiming a protocol type other than IPv4, carrying a
        // foreign address in its sender protocol address slot, is a
        // foreign source like any other: the slot is the source whatever
        // the frame claims to speak.
        let odd = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 6, 4, &foreign));
        assert_eq!(summarize(&odd).family, FrameFamily::Arp);
        assert_eq!(summarize(&odd).source(), Some(foreign));
        assert_eq!(
            verdict(&summarize(&odd), &allow_all),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: foreign,
                lease: LEASE,
            })
        );

        // An unexpected `hlen` moves the slot, and the read follows it.
        let shifted = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 8, 4, &foreign));
        assert_eq!(summarize(&shifted).source(), Some(foreign));

        // A `plen` other than four hides nothing either: the four bytes the
        // lease check reads are the first four of the slot the frame
        // declares.
        let wide = eth_frame(
            ETHERTYPE_ARP,
            &arp_claiming(
                0x1234,
                6,
                6,
                &[foreign[0], foreign[1], foreign[2], foreign[3], 9, 9],
            ),
        );
        assert_eq!(summarize(&wide).source(), Some(foreign));

        // An ARP whose slot carries the lease is the declared family
        // whatever protocol it claims: it announces the box's own address,
        // which is what its ordinary ARP announces anyway.
        let own = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 6, 4, &LEASE));
        assert!(
            admits(&own, &deny_all()),
            "the lease's own ARP resolves under a foreign protocol type too"
        );

        // Too short to carry four bytes of sender address at its own
        // `hlen`: no readable source, so truncated rather than admitted.
        let long_hlen = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x0800, 200, 4, &[]));
        assert_eq!(summarize(&long_hlen).family, FrameFamily::Truncated);
        assert!(!admits(&long_hlen, &allow_all));
    }

    /// NET-079's carve-out: a deny-all box still reaches the resolver
    /// Minimal owns for it, at that resolver's address and port — and
    /// nothing else, not even the resolver on another port.
    #[test]
    fn deny_all_still_reaches_the_resolver() {
        let rules = deny_all();
        assert!(
            admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT), &rules),
            "DNS to the resolver is the one carve-out from a deny-all verdict"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, 54), &rules),
            "the carve-out is by port too"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_TCP, RESOLVER, DNS_PORT), &rules),
            "and by protocol"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_UDP, [100, 64, 0, 2], DNS_PORT), &rules),
            "a neighbouring address is not the resolver"
        );
        // The carve-out precedes the deny: a box that denies the resolver's
        // own subnet still resolves.
        let denied_subnet = EgressRules::new(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(vec![Ipv4Cidr {
                addr: [100, 64, 0, 0],
                prefix: 16,
            }]),
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT), &denied_subnet),
            "the carve-out comes before the deny rules"
        );
    }

    /// NET-064: UDP is dropped when only TCP is allowed — and TCP to a
    /// declared subnet still completes (NET-063).
    #[test]
    fn udp_is_dropped_when_only_tcp_is_allowed() {
        let rules = EgressRules::new(
            Some(vec![IPPROTO_TCP]),
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            None,
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_TCP, [10, 1, 2, 3], 80), &rules),
            "TCP to a declared subnet is admitted"
        );
        let udp = ipv4_frame(IPPROTO_UDP, [10, 1, 2, 3], 53);
        assert!(!admits(&udp, &rules));
        assert_eq!(
            verdict(&summarize(&udp), &rules),
            FrameVerdict::Drop(DropReason::UndeclaredProtocol { proto: IPPROTO_UDP })
        );
        // ICMP is undeclared here too: "only TCP" means only TCP.
        assert!(!admits(&ipv4_frame(1, [10, 1, 2, 3], 0), &rules));
    }

    /// NET-062: a destination the rules do not allow is dropped, and the
    /// drop names the rule that fired.
    #[test]
    fn undeclared_destination_drops_with_its_rule() {
        let rules = EgressRules::new(
            None,
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            None,
            RESOLVER,
            LEASE,
        );
        let denied = ipv4_frame(IPPROTO_TCP, [203, 0, 113, 7], 443);
        assert_eq!(
            verdict(&summarize(&denied), &rules),
            FrameVerdict::Drop(DropReason::UndeclaredSubnet {
                dst: [203, 0, 113, 7],
                proto: 6,
            })
        );
        // A deny rule subtracts from the allow: the same box, denied one
        // /24 inside its allowed /8, drops inside that /24 only.
        let subtractive = EgressRules::new(
            None,
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            Some(vec![Ipv4Cidr {
                addr: [10, 6, 6, 0],
                prefix: 24,
            }]),
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_TCP, [10, 7, 7, 7], 80), &subtractive),
            "the allow holds outside the denied /24"
        );
        let inside = ipv4_frame(IPPROTO_TCP, [10, 6, 6, 7], 80);
        assert_eq!(
            verdict(&summarize(&inside), &subtractive),
            FrameVerdict::Drop(DropReason::DeniedSubnet {
                dst: [10, 6, 6, 7],
                proto: 6,
            })
        );
    }

    /// The absent-policy default (03-spec R2.1): no rules declared means
    /// everything is admitted — the posture NET-074 replaces when the
    /// deny-all default comes into force.
    #[test]
    fn absent_policy_allows_all() {
        let rules = EgressRules::from_policy(None, RESOLVER, LEASE);
        assert!(admits(
            &ipv4_frame(IPPROTO_UDP, [203, 0, 113, 7], 9999),
            &rules
        ));
        assert!(admits(&ipv4_frame(IPPROTO_TCP, [192, 0, 2, 1], 80), &rules));
    }

    /// `from_policy` compiles each declared dimension and keeps the absent
    /// ones allow-all; `allow_dns_hosts` is not a frame-level rule (it is
    /// the proxy's, NET-066) and compiles to nothing here. The lease is
    /// carried beside the rules: the box's own address on the switch, the
    /// source the verdict checks every frame against (NET-084).
    #[test]
    fn from_policy_compiles_the_declared_dimensions() {
        let policy = EgressPolicy {
            allow_protocols: Some(vec![IpProto::Tcp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: Some(vec!["github.com".to_string()]),
            deny_subnets: None,
        };
        let rules = EgressRules::from_policy(Some(&policy), RESOLVER, LEASE);
        assert_eq!(
            rules,
            EgressRules::new(
                Some(vec![IPPROTO_TCP]),
                Some(vec![Ipv4Cidr {
                    addr: [10, 0, 0, 0],
                    prefix: 8,
                }]),
                None,
                RESOLVER,
                LEASE,
            )
        );
        assert_eq!(rules.resolver(), RESOLVER);
        assert_eq!(rules.lease(), LEASE);
    }

    /// `Ipv4Cidr::parse` accepts exactly the spelling the launch-time
    /// validation accepts for IPv4, and nothing an IPv4 rule can never
    /// match.
    #[test]
    fn cidr_parse_accepts_the_validated_spelling() {
        assert_eq!(
            Ipv4Cidr::parse("10.0.0.0/8"),
            Some(Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            })
        );
        assert!(
            Ipv4Cidr::parse("10.0.0.0/33").is_none(),
            "prefix beyond /32"
        );
        assert!(
            Ipv4Cidr::parse("10.0.0.0").is_none(),
            "a bare address is not a CIDR"
        );
        assert!(
            Ipv4Cidr::parse("fe80::/64").is_none(),
            "IPv6 never reaches a rule match"
        );
        assert!(Ipv4Cidr::parse("10.0.0.0/x").is_none());
    }

    /// The prefix match: a CIDR contains its whole prefix and nothing else,
    /// and the degenerate prefixes behave (/0 everything, /32 one address).
    #[test]
    fn cidr_contains_covers_the_prefix() {
        let eight = Ipv4Cidr {
            addr: [10, 0, 0, 0],
            prefix: 8,
        };
        assert!(eight.contains([10, 255, 1, 2]));
        assert!(!eight.contains([11, 0, 0, 0]));
        let everything = Ipv4Cidr {
            addr: [0, 0, 0, 0],
            prefix: 0,
        };
        assert!(everything.contains([203, 0, 113, 7]));
        let one = Ipv4Cidr {
            addr: [10, 1, 2, 3],
            prefix: 32,
        };
        assert!(one.contains([10, 1, 2, 3]));
        assert!(!one.contains([10, 1, 2, 4]));
        // Host bits in the declared address are ignored, as validation
        // normalizing would expect.
        let sloppy = Ipv4Cidr {
            addr: [10, 6, 6, 7],
            prefix: 24,
        };
        assert!(sloppy.contains([10, 6, 6, 200]));
    }

    /// The summary a frame yields: the port is read from the L4 header a
    /// first fragment carries, and only then.
    #[test]
    fn summarize_reads_the_port_only_from_a_first_fragment() {
        let first = ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT);
        assert_eq!(summarize(&first).destination_port(), DNS_PORT);
        assert_eq!(summarize(&first).protocol(), Some(IPPROTO_UDP));
        assert_eq!(summarize(&first).destination(), Some(RESOLVER));
        assert_eq!(summarize(&first).source(), Some(LEASE));

        // A later fragment: the offset bits are set, so there is no L4
        // header to read — and the missing port keeps the carve-out closed.
        let mut later = ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT);
        later[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());
        let summary = summarize(&later);
        assert_eq!(summary.destination_port(), 0);
        assert!(
            !admits(&later, &deny_all()),
            "a fragment with no readable port is not DNS"
        );

        // An L4 header shorter than its ports cannot be read either.
        let short_l4 = eth_frame(
            ETHERTYPE_IPV4,
            &ip_payload(IPPROTO_UDP, LEASE, RESOLVER, 0, &[0u8; 2]),
        );
        assert_eq!(summarize(&short_l4).destination_port(), 0);

        // An IPv4-ethertype frame too short for its IPv4 header.
        let short_ip = eth_frame(ETHERTYPE_IPV4, &[0u8; 10]);
        assert_eq!(summarize(&short_ip).family, FrameFamily::Truncated);
    }

    /// The default switch's host alias, the helper's address the
    /// infrastructure deny set holds beside the resolver.
    const HOST_ALIAS: [u8; 4] = [100, 64, 255, 254];

    /// Compiles a CIDR list, the way [`EgressRules::from_policy`] does, for
    /// the intersection tests below.
    fn cidrs(entries: &[&str]) -> Vec<Ipv4Cidr> {
        entries
            .iter()
            .map(|cidr| Ipv4Cidr::parse(cidr).expect("a declared CIDR parses"))
            .collect()
    }

    /// NET-066/NET-067: the intersection admits exactly the resolved
    /// addresses that no deny and no infrastructure range refuses — a
    /// declared deny first, the fixed ranges under every declaration, and
    /// RFC 1918 only where the box's own `allow_subnets` covers the answer.
    #[test]
    fn rebinding_intersection_admits_only_clean_answers() {
        let infrastructure = InfrastructureDenySet::new(RESOLVER, HOST_ALIAS);
        let admit = |answer: [u8; 4], allow: Option<&[Ipv4Cidr]>, deny: Option<&[Ipv4Cidr]>| {
            rebinding_admits(answer, allow, deny, &infrastructure)
        };

        // A public answer is admitted with no declarations at all (NET-066).
        admit([140, 82, 121, 3], None, None).unwrap();

        // The box's own denies are subtracted from every name (NET-067).
        let deny = cidrs(&["203.0.113.0/24"]);
        assert_eq!(
            admit([203, 0, 113, 7], None, Some(deny.as_slice())),
            Err(RebindingRefusal::DeniedSubnet)
        );

        // The fixed infrastructure ranges are refused under every
        // declaration — link-local and the metadata services in it, loopback,
        // the plane, and the gateway's own two addresses.
        for refused in [
            [169, 254, 169, 254], // metadata, in link-local
            [127, 0, 0, 1],       // loopback
            [100, 64, 0, 9],      // the plane (a box's lease)
            RESOLVER,             // the answerer's own address
            HOST_ALIAS,           // the helper's own address
        ] {
            assert_eq!(
                admit(refused, None, None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} is infrastructure, refused under every declaration"
            );
            // And an explicit allow does not exempt them: the exemption is
            // RFC 1918's alone.
            let allow_all = cidrs(&["0.0.0.0/0"]);
            assert_eq!(
                admit(refused, Some(allow_all.as_slice()), None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} stays refused even where allow_subnets covers it"
            );
        }

        // RFC 1918 is admitted only where `allow_subnets` covers the answer:
        // an open dimension covers it (the address dimension is open, so the
        // name path opens with it), an allow-all entry covers it, an empty
        // one does not, and a different private range does not.
        let private = [10, 1, 2, 3];
        admit(private, None, None).unwrap();
        let allow_all = cidrs(&["0.0.0.0/0"]);
        admit(private, Some(allow_all.as_slice()), None).unwrap();
        let allow_lan = cidrs(&["10.0.0.0/8"]);
        admit(private, Some(allow_lan.as_slice()), None).unwrap();
        let allow_none = cidrs(&[]);
        assert_eq!(
            admit(private, Some(allow_none.as_slice()), None),
            Err(RebindingRefusal::Infrastructure),
            "a deny-all address declaration refuses private answers"
        );
        let allow_other_private = cidrs(&["192.168.0.0/16"]);
        assert_eq!(
            admit(private, Some(allow_other_private.as_slice()), None),
            Err(RebindingRefusal::Infrastructure),
            "a different private range is not a covering"
        );
    }

    /// [`rebinding_intersection`] — the set-shaped wrapper the relay calls per
    /// reply: it splits the answer set exactly (nothing dropped, nothing
    /// duplicated, order preserved), each refusal carrying its reason.
    #[test]
    fn rebinding_intersection_splits_the_answer_set() {
        let infrastructure = InfrastructureDenySet::new(RESOLVER, HOST_ALIAS);
        let answers = [
            [140, 82, 121, 3], // admitted: public
            [203, 0, 113, 7],  // refused: the box's deny
            [10, 1, 2, 3],     // refused: RFC 1918, uncovered
            [169, 254, 1, 1],  // refused: fixed infrastructure
            [140, 82, 121, 4], // admitted: public
        ];
        let allow = cidrs(&[]);
        let deny = cidrs(&["203.0.113.0/24"]);
        let split = rebinding_intersection(
            &answers,
            Some(allow.as_slice()),
            Some(deny.as_slice()),
            &infrastructure,
        );
        assert_eq!(
            split.admitted,
            [[140, 82, 121, 3], [140, 82, 121, 4]],
            "the admitted addresses, in the order the answer carried them"
        );
        assert_eq!(
            split.refused,
            [
                ([203, 0, 113, 7], RebindingRefusal::DeniedSubnet),
                ([10, 1, 2, 3], RebindingRefusal::Infrastructure),
                ([169, 254, 1, 1], RebindingRefusal::Infrastructure),
            ]
        );
    }

    /// The subnet accessors the rebinding intersection reads: they surface
    /// the compiled dimensions of the policy, and stay `None` where the
    /// policy left the dimension open.
    #[test]
    fn subnet_accessors_expose_the_compiled_dimensions() {
        let policy = EgressPolicy {
            allow_protocols: None,
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
        };
        let rules = EgressRules::from_policy(Some(&policy), RESOLVER, LEASE);
        let allow = rules.allow_subnets().expect("allow_subnets compiled");
        assert_eq!(allow.len(), 1);
        assert!(allow[0].contains([10, 200, 0, 1]));
        assert!(!allow[0].contains([192, 168, 0, 1]));
        let deny = rules.deny_subnets().expect("deny_subnets compiled");
        assert_eq!(deny.len(), 1);
        assert!(deny[0].contains([192, 168, 0, 1]));

        let open = EgressRules::from_policy(None, RESOLVER, LEASE);
        assert!(open.allow_subnets().is_none() && open.deny_subnets().is_none());
    }
}

/// The frame-level admit-or-drop harness NET-016, NET-062, NET-064,
/// NET-069, NET-070, NET-081's failure case and NET-084 share (spec NET,
/// Tiers): exhaustive over every value the decision reads — the fragment
/// offset, the source, the protocol, the destination and the L4 destination
/// port of an IPv4 frame, plus the lease the source must be — under rule
/// lists of zero or two rules per dimension, at an unwind bound of 6 (the
/// `[u8; 4]` address comparisons lower to a 4-trip `memcmp` loop; see the
/// harness).
///
/// The module also carries the rebinding intersection's harness (NET-067,
/// [`kani_rebinding_intersection_admits_no_denied_address`]), which shares
/// [`two_cidrs`] and its pinning rationale and runs at the tighter bound 4
/// its own doc explains.
///
/// The scope is deliberate. This module's first form was exhaustive over a
/// fully symbolic 40-byte header and rule lists of symbolic *length*, and
/// its solve outlived the CI lane — one 60-minute job timeout, then two
/// runs cancelled nine minutes in (gominimal/minimal#1700) — because CBMC
/// unwound each rule scan without being able to see it end. The harness
/// below pins what the decision never reads and keeps every list at a
/// concrete length; what is pinned, and why each pin is sound, is
/// documented there.
///
/// Run: `cargo kani -p sessions` (or `./scripts/kani.sh`). Kani pinned at
/// 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        DNS_PORT, ETH_HDR, ETHERTYPE_IPV4, EgressRules, FrameFamily, FrameVerdict, IPPROTO_UDP,
        InfrastructureDenySet, Ipv4Cidr, rebinding_admits, rebinding_intersection, summarize,
        verdict,
    };

    /// One dimension's rules under every declaration the compile can
    /// produce: `None` (the dimension is undeclared, so it allows all),
    /// `Some(vec![])` (declared empty, so it allows nothing — the deny-all
    /// box the resolver carve-out must still resolve), or `Some` of two
    /// fully symbolic rules.
    ///
    /// Every arm carries a CONCRETE length, and that is the point: a list
    /// of symbolic element count is what made this proof unaffordable (see
    /// the module doc), because CBMC unwound each scan without being able
    /// to read its trip count off the code. Two rules is what catches a
    /// scan that reads only one element or stops one short of the end; a
    /// third adds no failure shape.
    fn two_protocols() -> Option<Vec<u8>> {
        match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, _) => None,
            (true, false) => Some(Vec::new()),
            (true, true) => Some(Vec::from([kani::any::<u8>(), kani::any::<u8>()])),
        }
    }

    /// [`two_protocols`] for a CIDR dimension: subnets fully symbolic,
    /// prefix lengths included, so the proof also covers the out-of-range
    /// prefixes [`Ipv4Cidr::contains`] must survive — its shift is guarded
    /// at both ends.
    fn two_cidrs() -> Option<Vec<Ipv4Cidr>> {
        match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, _) => None,
            (true, false) => Some(Vec::new()),
            (true, true) => Some(Vec::from([
                kani::any::<Ipv4Cidr>(),
                kani::any::<Ipv4Cidr>(),
            ])),
        }
    }

    /// A frame is admitted exactly when it is declared: stated as an iff so
    /// neither arm can silently become unreachable (the rcache harness
    /// pattern). The declared half is restated over the same summary and
    /// rules — the lease first (NET-084: the source is the lease), then the
    /// resolver carve-out (NET-079), then the three declared dimensions
    /// conjunctively — so a verdict that checks in a different order, or
    /// that reads `None` as deny-all, fails here.
    ///
    /// The unwind bound is 6, with one loop to spare over the longest
    /// this proof unwinds: comparing `[u8; 4]` addresses lowers to
    /// CBMC's builtin `memcmp`, a 4-trip loop, so a bound of 4 fails an
    /// unwinding assertion even though every loop the harness itself
    /// writes (the rule scans in `verdict` and below, over lists of at
    /// most two rules) has exited by its third check. The bound has to
    /// clear every trip the compiler generates, not only the ones the
    /// source shows; the lease check's source comparison is one more of
    /// those `memcmp`s, not a longer one.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_frame_verdict_admits_nothing_undeclared() {
        // One 54-byte Ethernet frame — a 14-byte header and a 40-byte IPv4
        // region, 20 bytes of IPv4 header plus 20 of L4 — the shape the
        // relay hands the verdict for every IPv4 packet it forwards.
        //
        // Symbolic: the fragment offset, the source, the protocol, the
        // destination and the L4 destination port — every value the
        // decision reads — and the lease, beside the rules, that the source
        // is checked against (NET-084's property is over every frame and
        // every lease).
        //
        // Pinned to constants: the EtherType (IPv4, the one family the
        // rules decide; the families decided without rules each have their
        // own pinned-frame unit test) and the version/IHL (4/5, the
        // 20-byte header every real guest emits, which is what puts the
        // L4 port at a readable offset). A fragment with no readable port
        // — the case that must keep the carve-out closed — is still in the
        // proof, via the symbolic fragment offset.
        //
        // Pinned to zero: the two MACs and every byte of the L4 around the
        // port, which the decision never reads and CBMC would otherwise
        // pay for bit by bit.
        let frag: u16 = kani::any();
        let proto: u8 = kani::any();
        let src: [u8; 4] = kani::any();
        let dst: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let mut frame = [0u8; ETH_HDR + 40];
        let ethertype = ETHERTYPE_IPV4.to_be_bytes();
        frame[12] = ethertype[0];
        frame[13] = ethertype[1];
        let ip = ETH_HDR;
        frame[ip] = 0x45; // version 4, IHL 5
        let frag_bytes = frag.to_be_bytes();
        frame[ip + 6] = frag_bytes[0]; // flags + fragment offset
        frame[ip + 7] = frag_bytes[1];
        frame[ip + 9] = proto;
        frame[ip + 12] = src[0]; // the IPv4 source address
        frame[ip + 13] = src[1];
        frame[ip + 14] = src[2];
        frame[ip + 15] = src[3];
        frame[ip + 16] = dst[0];
        frame[ip + 17] = dst[1];
        frame[ip + 18] = dst[2];
        frame[ip + 19] = dst[3];
        let port_bytes = port.to_be_bytes();
        frame[ip + 22] = port_bytes[0]; // the L4 destination port
        frame[ip + 23] = port_bytes[1];

        let summary = summarize(&frame);
        assert!(matches!(summary.family(), FrameFamily::Ipv4));

        let resolver: [u8; 4] = kani::any();
        let lease: [u8; 4] = kani::any();
        let rules = EgressRules::new(two_protocols(), two_cidrs(), two_cidrs(), resolver, lease);

        let admitted = matches!(verdict(&summary, &rules), FrameVerdict::Admit);

        let declared = match (summary.source(), summary.destination(), summary.protocol()) {
            (Some(src), Some(dst), Some(proto)) => {
                let lease = src == rules.lease();
                let resolver = proto == IPPROTO_UDP
                    && dst == rules.resolver()
                    && summary.destination_port() == DNS_PORT;
                let protocols = rules
                    .allow_protocols
                    .as_ref()
                    .is_none_or(|list| list.contains(&proto));
                let denied = rules
                    .deny_subnets
                    .as_ref()
                    .is_some_and(|list| list.iter().any(|cidr| cidr.contains(dst)));
                let allowed = rules
                    .allow_subnets
                    .as_ref()
                    .is_none_or(|list| list.iter().any(|cidr| cidr.contains(dst)));
                lease && (resolver || (protocols && !denied && allowed))
            }
            // No readable IPv4 header is never a declared frame.
            _ => false,
        };
        assert_eq!(admitted, declared);
    }

    /// NET-067's property, the rebinding half: **for every resolved answer
    /// set and every allow, deny, and infrastructure-deny CIDR set, the
    /// admitted set contains no denied address** — proved in two parts that
    /// share one set of rule lists:
    ///
    /// * the per-address decision, restated as an iff over one fully
    ///   symbolic answer so neither arm can silently become unreachable (the
    ///   rcache harness pattern) — this is the exhaustive half, over every
    ///   IPv4 answer there is;
    /// * the set-shaped wrapper, over an answer set of two symbolic
    ///   addresses, asserting the split loses nothing (the counts match the
    ///   oracle) and that every address the wrapper admitted passes the
    ///   oracle — so no cross-answer coupling (admit one because another is
    ///   clean) and no loss can hide.
    ///
    /// Every CIDR set rides [`two_cidrs`]: `None`, empty, or two symbolic
    /// rules — **two** per set, one tighter than the tier text's "at most
    /// 4", for the same reason [`two_protocols`] pins two: two rules is
    /// what catches a scan that reads only one element or stops one short
    /// of the end, and a third adds no failure shape while it multiplies
    /// CBMC's search. Both halves of the infrastructure set ride it too,
    /// so a set-shaped hole that only opens at three or more rules is
    /// outside this proof's bound — stated here rather than left to be
    /// read off the tier text.
    ///
    /// The unwind bound is 4. No loop this proof unwinds runs past its third
    /// check: the set scans walk lists of at most two CIDRs, the answer-set
    /// loop walks two answers, and — unlike the frame-verdict harness, whose
    /// `[u8; 4]` comparisons lower to a 4-trip `memcmp` — every comparison
    /// here is [`Ipv4Cidr::contains`]'s u32 mask arithmetic, so there is no
    /// address-equality loop to buy extra trips for. (The wrapper's `Vec`s
    /// are pre-sized to the answer count, so no growth copy enters the proof
    /// either.)
    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_rebinding_intersection_admits_no_denied_address() {
        let allow = two_cidrs();
        let deny = two_cidrs();
        let infrastructure = InfrastructureDenySet {
            fixed: two_cidrs().unwrap_or_default(),
            rfc1918: two_cidrs().unwrap_or_default(),
        };
        // The oracle's one question, restated over CIDR math alone: may this
        // answer be admitted — not denied by the box, not in a fixed
        // infrastructure range, and not in RFC 1918 that `allow_subnets`
        // does not cover?
        let admissible = |answer: [u8; 4]| {
            let denied = deny
                .as_deref()
                .is_some_and(|list| list.iter().any(|cidr| cidr.contains(answer)));
            let fixed = infrastructure
                .fixed
                .iter()
                .any(|cidr| cidr.contains(answer));
            let rfc1918 = infrastructure
                .rfc1918
                .iter()
                .any(|cidr| cidr.contains(answer));
            let covers = allow
                .as_deref()
                .is_none_or(|list| list.iter().any(|cidr| cidr.contains(answer)));
            !denied && !fixed && (!rfc1918 || covers)
        };

        // Part one: the per-address decision, iff the oracle, over every
        // IPv4 answer.
        let answer: [u8; 4] = kani::any();
        let admitted =
            rebinding_admits(answer, allow.as_deref(), deny.as_deref(), &infrastructure).is_ok();
        assert_eq!(admitted, admissible(answer));

        // Part two: the wrapper over a two-answer set — the split is exact,
        // and everything it admitted passes the oracle.
        let answers = [kani::any::<[u8; 4]>(), kani::any::<[u8; 4]>()];
        let split =
            rebinding_intersection(&answers, allow.as_deref(), deny.as_deref(), &infrastructure);
        let expected: usize = answers.iter().filter(|a| admissible(**a)).count();
        assert_eq!(split.admitted.len(), expected);
        assert_eq!(split.refused.len(), answers.len() - expected);
        for address in &split.admitted {
            assert!(
                admissible(*address),
                "the admitted set holds an address the oracle denies"
            );
        }
        for (address, _) in &split.refused {
            assert!(!admissible(*address), "an admissible answer was refused");
        }
    }
}
