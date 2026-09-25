//! The frame-level egress verdict (NET-062, NET-063, NET-064).
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
//! * **ARP is admitted** — address resolution on the shared L2 switch is a
//!   declared path for every box; the gateway's MAC must be learnable for
//!   any egress at all to work.
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
    /// Too short to carry the header the family decision or the rule match
    /// reads: below 14 bytes there is not even an `EtherType`, and an
    /// IPv4-ethertype frame below 34 bytes has no readable IPv4 header.
    /// Never admitted — an unreadable frame cannot be a declared one.
    Truncated,
}

/// The facts of one frame the egress verdict decides on, extracted by
/// [`summarize`] and owned outright: no borrow of the frame survives the
/// extraction, so the decision is a pure function of this value plus the
/// box's [`EgressRules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSummary {
    family: FrameFamily,
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
        dst: None,
        proto: None,
        dst_port: 0,
    };
    if frame.len() < ETH_HDR {
        return none(FrameFamily::Truncated);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let family = match ethertype {
        ETHERTYPE_ARP => return none(FrameFamily::Arp),
        ETHERTYPE_IPV6 => return none(FrameFamily::Ipv6),
        ETHERTYPE_IPV4 => FrameFamily::Ipv4,
        _ => return none(FrameFamily::UndeclaredFamily(ethertype)),
    };
    // IPv4: the fixed 20-byte header carries the destination and protocol.
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
}

/// A box's compiled egress rules: the three declaration dimensions of an
/// [`EgressPolicy`], owned and matchable, plus the address of the resolver
/// the carve-out admits.
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
    ) -> Self {
        Self {
            allow_protocols,
            allow_subnets,
            deny_subnets,
            resolver,
        }
    }

    /// Compiles a session's egress policy into rules. An absent policy is
    /// allow-all on every dimension (the shipped default, 03-spec R2.1;
    /// NET-074 changes it once the deny-all default is in force), and a
    /// declared dimension keeps only the entries the launch-time validation
    /// already checked parse. `resolver` is the switch gateway's address,
    /// the resolver this box's carve-out is keyed to.
    #[must_use]
    pub fn from_policy(policy: Option<&EgressPolicy>, resolver: [u8; 4]) -> Self {
        let Some(policy) = policy else {
            return Self::new(None, None, None, resolver);
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
        )
    }

    /// The address of the resolver this box's carve-out is keyed to.
    #[must_use]
    pub fn resolver(&self) -> [u8; 4] {
        self.resolver
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
            Self::Ipv6
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
            Self::Ipv6 | Self::UndeclaredFamily(_) | Self::Truncated => None,
        }
    }
}

/// The admit-or-drop decision for one frame summary against one box's rules
/// — the pure function NET-062, NET-063, and NET-064 all reduce to, and
/// the one the Kani harness exhausts.
///
/// Order of the IPv4 checks is part of the contract: the resolver
/// carve-out comes first, so a box that denies the resolver's own subnet
/// still resolves (NET-079); `deny_subnets` then carves out of what the
/// allows admit; and a drop never depends on the rule lists being sorted.
#[must_use]
pub fn verdict(summary: &FrameSummary, rules: &EgressRules) -> FrameVerdict {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The switch gateway's address, the resolver every rule set below is
    /// keyed to (the default switch subnet's gateway).
    const RESOLVER: [u8; 4] = [100, 64, 0, 1];

    /// IPv4 protocol number for TCP, for the frames below.
    const IPPROTO_TCP: u8 = 6;

    /// A deny-all rule set: every dimension declared, nothing listed.
    fn deny_all() -> EgressRules {
        EgressRules::new(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
            RESOLVER,
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

    /// An IPv4 packet payload: a header for `proto` carrying `frag_offset`
    ///'s low 13 bits, followed by `l4`.
    fn ip_payload(proto: u8, dst: [u8; 4], frag_offset: u16, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20 + l4.len()];
        ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
        ip[6..8].copy_from_slice(&frag_offset.to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&[192, 168, 1, 2]); // src, unread by the verdict
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

    /// An IPv4 frame for `proto` to `dst`:`port`.
    fn ipv4_frame(proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        eth_frame(ETHERTYPE_IPV4, &ip_payload(proto, dst, 0, &l4(port)))
    }

    fn admits(frame: &[u8], rules: &EgressRules) -> bool {
        matches!(verdict(&summarize(frame), rules), FrameVerdict::Admit)
    }

    /// NET-062's property from the family side: the three families decided
    /// without rules behave identically under allow-all and deny-all.
    #[test]
    fn families_decided_without_rules() {
        let allow_all = EgressRules::from_policy(None, RESOLVER);
        let arp = eth_frame(ETHERTYPE_ARP, &[0u8; 28]);
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
        let rules = EgressRules::from_policy(None, RESOLVER);
        assert!(admits(
            &ipv4_frame(IPPROTO_UDP, [203, 0, 113, 7], 9999),
            &rules
        ));
        assert!(admits(&ipv4_frame(IPPROTO_TCP, [192, 0, 2, 1], 80), &rules));
    }

    /// `from_policy` compiles each declared dimension and keeps the absent
    /// ones allow-all; `allow_dns_hosts` is not a frame-level rule (it is
    /// the proxy's, NET-066) and compiles to nothing here.
    #[test]
    fn from_policy_compiles_the_declared_dimensions() {
        let policy = EgressPolicy {
            allow_protocols: Some(vec![IpProto::Tcp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: Some(vec!["github.com".to_string()]),
            deny_subnets: None,
        };
        let rules = EgressRules::from_policy(Some(&policy), RESOLVER);
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
            )
        );
        assert_eq!(rules.resolver(), RESOLVER);
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
            &ip_payload(IPPROTO_UDP, RESOLVER, 0, &[0u8; 2]),
        );
        assert_eq!(summarize(&short_l4).destination_port(), 0);

        // An IPv4-ethertype frame too short for its IPv4 header.
        let short_ip = eth_frame(ETHERTYPE_IPV4, &[0u8; 10]);
        assert_eq!(summarize(&short_ip).family, FrameFamily::Truncated);
    }
}

/// The frame-level admit-or-drop harness NET-016, NET-062, NET-064,
/// NET-069, NET-070, NET-081's failure case and NET-084 share (spec NET,
/// Tiers): exhaustive over a 40-byte IPv4+L4 header and at most 4 rules per
/// dimension, at an unwind bound of 4.
///
/// Run: `cargo kani -p sessions` (or `./scripts/kani.sh`). Kani pinned at
/// 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        DNS_PORT, ETH_HDR, ETHERTYPE_IPV4, EgressRules, FrameFamily, FrameVerdict, IPPROTO_UDP,
        summarize, verdict,
    };

    /// At most 4 symbolic rules of one dimension: `None` (allow-all) is
    /// itself symbolic, so the proof covers both the undeclared dimension
    /// and the declared one.
    fn bounded_protocols() -> Option<Vec<u8>> {
        if !kani::any() {
            return None;
        }
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let mut list = Vec::with_capacity(4);
        for i in 0..4 {
            if i < n {
                list.push(kani::any());
            }
        }
        Some(list)
    }

    /// [`bounded_protocols`] for a CIDR dimension.
    fn bounded_cidrs() -> Option<Vec<super::Ipv4Cidr>> {
        if !kani::any() {
            return None;
        }
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let mut list = Vec::with_capacity(4);
        for i in 0..4 {
            if i < n {
                list.push(kani::any());
            }
        }
        Some(list)
    }

    /// A frame is admitted exactly when it is declared: stated as an iff so
    /// neither arm can silently become unreachable (the rcache harness
    /// pattern). The declared half is restated over the same summary and
    /// rules — the resolver carve-out first (NET-079), then the three
    /// declared dimensions conjunctively — so a verdict that checks in a
    /// different order, or that reads `None` as deny-all, fails here.
    #[kani::proof]
    fn kani_frame_verdict_admits_nothing_undeclared() {
        // The 40-byte IPv4+L4 region of an Ethernet frame — a 20-byte IPv4
        // header plus 20 bytes of L4 — fully symbolic, under a fixed IPv4
        // EtherType: every header shape the relay can hand the verdict.
        let ip_l4: [u8; 40] = kani::any();
        let mut frame = [0u8; ETH_HDR + 40];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[ETH_HDR..].copy_from_slice(&ip_l4);

        let summary = summarize(&frame);
        assert!(matches!(summary.family(), FrameFamily::Ipv4));

        let rules = EgressRules::new(
            bounded_protocols(),
            bounded_cidrs(),
            bounded_cidrs(),
            kani::any(),
        );

        let admitted = matches!(verdict(&summary, &rules), FrameVerdict::Admit);

        let declared = match (summary.destination(), summary.protocol()) {
            (Some(dst), Some(proto)) => {
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
                resolver || (protocols && !denied && allowed)
            }
            // No readable IPv4 header is never a declared frame.
            _ => false,
        };
        assert_eq!(admitted, declared);
    }
}
