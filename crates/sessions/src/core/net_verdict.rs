//! The egress verdict for one frame leaving an own-address box.
//!
//! One pure function, [`frame_verdict`], decides every IPv4 frame on the
//! egress relay from an owned [`FrameSummary`] and owned [`EgressRules`]:
//! a frame whose source is not the box's lease is rejected (NET-084), a
//! transport the rules do not allow is dropped (NET-064), a destination the
//! rules do not allow is dropped (NET-062), and everything the rules allow is
//! admitted (NET-063). The relay loop in `minimald` only applies the verdict;
//! it never reasons about the rules itself. Keeping the decision free of I/O
//! and bounded in size is what lets the Kani harness below exhaust it.
//!
//! The one carve-out from a deny-all verdict is the resolver Minimal owns for
//! the box, by address and port (design §4.1): a deny-all box still resolves
//! exactly the names that resolver holds and reaches nothing else.

use std::fmt;
use std::net::Ipv4Addr;

use crate::{EgressPolicy, IpProto};

/// IPv4 protocol number for ICMP.
pub const IPPROTO_ICMP: u8 = 1;
/// IPv4 protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

/// The [`IpProto`] an IPv4 protocol number names, or `None` for a transport
/// the rules cannot name (and so can never allow).
#[must_use]
pub fn ip_proto(proto: u8) -> Option<IpProto> {
    match proto {
        IPPROTO_TCP => Some(IpProto::Tcp),
        IPPROTO_UDP => Some(IpProto::Udp),
        IPPROTO_ICMP => Some(IpProto::Icmp),
        _ => None,
    }
}

/// An IPv4 prefix (`network/prefix-len`) as written in `allow_subnets` and
/// `deny_subnets`. Host bits below the prefix are zeroed on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: u32,
    prefix: u8,
}

impl Cidr {
    /// A prefix of `prefix` bits over `addr`, or `None` for a prefix length
    /// above 32.
    #[must_use]
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Self {
            network: u32::from(addr) & Self::mask(prefix),
            prefix,
        })
    }

    /// Parses `<addr>/<prefix-len>` for IPv4 only. An IPv6 prefix (accepted by
    /// launch validation) yields `None`: it can match no frame on the IPv4-only
    /// switch, so it neither allows nor denies anything here.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        Self::new(addr, prefix)
    }

    /// Whether `ip` lies within this prefix.
    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix) == self.network
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }
}

/// What the verdict needs to know about one IPv4 frame: its addresses, its
/// transport and, for a first fragment carrying a TCP/UDP header, the
/// destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSummary {
    /// Source address; must be the box's lease for the frame to be admitted.
    pub src: Ipv4Addr,
    /// Destination address, matched against the subnet rules.
    pub dst: Ipv4Addr,
    /// IPv4 protocol number.
    pub proto: u8,
    /// Destination port when the frame carries a TCP/UDP header; `None` for a
    /// later fragment, another transport, or a header cut short.
    pub dst_port: Option<u16>,
}

/// Summarizes an IPv4 packet (the IP header onward, no link-layer header), or
/// `None` when it is not one: too short for an IPv4 header, not version 4, or
/// an IHL past the bytes given. Length-checked at every step so a truncated or
/// hostile packet yields `None` rather than an out-of-bounds read.
#[must_use]
pub fn summarize_ipv4(packet: &[u8]) -> Option<FrameSummary> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let proto = packet[9];
    // A non-zero fragment offset (low 13 bits of bytes 6–7) is a later
    // fragment with no transport header at `ihl`.
    let first_fragment = u16::from_be_bytes([packet[6], packet[7]]).trailing_zeros() >= 13;
    let l4 = &packet[ihl..];
    let dst_port =
        (first_fragment && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && l4.len() >= 4)
            .then(|| u16::from_be_bytes([l4[2], l4[3]]));
    Some(FrameSummary {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        proto,
        dst_port,
    })
}

/// An address and port: the resolver carve-out's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// The rules one box's egress is decided on, owned and already parsed, so the
/// verdict does no string handling and no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRules {
    /// The box's switch lease: the only source address it may send from.
    pub lease: Ipv4Addr,
    /// Destinations the box declared; `None` allows every destination.
    pub allow_subnets: Option<Vec<Cidr>>,
    /// Destinations refused whatever `allow_subnets` says.
    pub deny_subnets: Vec<Cidr>,
    /// Transports the box declared; `None` allows every transport.
    pub allow_protocols: Option<Vec<IpProto>>,
    /// The resolver Minimal owns for the box: reachable over TCP or UDP under
    /// a deny-all `allow_subnets`, by this address and port only.
    pub resolver: Option<Endpoint>,
}

impl EgressRules {
    /// The rules for a box leased `lease`, from its declared `policy` (an
    /// absent section allows every destination and transport) and the
    /// resolver carve-out. Subnet entries that are not IPv4 prefixes are
    /// skipped: launch validation already refused malformed ones, and an IPv6
    /// prefix matches nothing on this switch.
    #[must_use]
    pub fn for_box(
        lease: Ipv4Addr,
        policy: Option<&EgressPolicy>,
        resolver: Option<Endpoint>,
    ) -> Self {
        let cidrs = |entries: &[String]| -> Vec<Cidr> {
            entries.iter().filter_map(|s| Cidr::parse(s)).collect()
        };
        Self {
            lease,
            allow_subnets: policy.and_then(|p| p.allow_subnets.as_deref()).map(cidrs),
            deny_subnets: policy
                .and_then(|p| p.deny_subnets.as_deref())
                .map(cidrs)
                .unwrap_or_default(),
            allow_protocols: policy.and_then(|p| p.allow_protocols.clone()),
            resolver,
        }
    }

    /// Whether `frame` is addressed to the resolver carve-out.
    fn reaches_resolver(&self, frame: &FrameSummary) -> bool {
        self.resolver.is_some_and(|r| {
            frame.dst == r.ip
                && frame.dst_port == Some(r.port)
                && (frame.proto == IPPROTO_TCP || frame.proto == IPPROTO_UDP)
        })
    }
}

/// The rule a dropped frame tripped, named as the `rule` a warning carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropRule {
    /// The source address is not the box's lease (NET-084).
    Source,
    /// The transport is not in `allow_protocols` (NET-064).
    Protocol,
    /// The destination is in `deny_subnets`.
    DeniedSubnet,
    /// The destination is in neither `allow_subnets` nor the carve-out
    /// (NET-062).
    Undeclared,
}

impl DropRule {
    /// The rule's name as it appears in a warning's `rule_matched` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source-not-lease",
            Self::Protocol => "allow_protocols",
            Self::DeniedSubnet => "deny_subnets",
            Self::Undeclared => "allow_subnets",
        }
    }
}

impl fmt::Display for DropRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verdict on one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the frame to the switch.
    Admit,
    /// Do not forward it, and do not answer it: the connection is dropped,
    /// never reset.
    Drop(DropRule),
}

/// Decides `frame` under `rules`. Pure: the same inputs always give the same
/// verdict, and nothing else is consulted.
///
/// A frame is admitted only when every declared condition holds: its source
/// is the lease, its transport is allowed, its destination is not denied, and
/// its destination is declared (or is the resolver carve-out). The first
/// failing condition, in that order, names the rule.
#[must_use]
pub fn frame_verdict(frame: &FrameSummary, rules: &EgressRules) -> Verdict {
    if frame.src != rules.lease {
        return Verdict::Drop(DropRule::Source);
    }
    if let Some(allowed) = &rules.allow_protocols
        && !ip_proto(frame.proto).is_some_and(|p| allowed.contains(&p))
    {
        return Verdict::Drop(DropRule::Protocol);
    }
    if rules.deny_subnets.iter().any(|c| c.contains(frame.dst)) {
        return Verdict::Drop(DropRule::DeniedSubnet);
    }
    if let Some(allowed) = &rules.allow_subnets
        && !allowed.iter().any(|c| c.contains(frame.dst))
        && !rules.reaches_resolver(frame)
    {
        return Verdict::Drop(DropRule::Undeclared);
    }
    Verdict::Admit
}

/// Bounded verification of [`frame_verdict`] (NET-062, NET-064, NET-084):
/// exhaustive over every 40-byte IPv4+L4 header, every lease, at most four
/// allow and four deny prefixes, every protocol set and every carve-out. The
/// harness restates the rules' declared conditions independently of the
/// function and checks them in both directions: an admitted frame satisfies
/// every one, and a dropped frame really trips the rule named.
///
/// Run: `cargo kani -p sessions` (or `just kani`). Kani pinned at 0.68.0 in
/// CI; the count of harnesses in this crate is asserted by `scripts/kani.sh`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The rule-count bound: at most this many prefixes per list. The unwind
    /// bound below is one more than this, for each loop's exit check.
    const RULES: usize = 4;

    fn any_cidrs() -> Vec<Cidr> {
        let n: usize = kani::any();
        kani::assume(n <= RULES);
        let raw: [(u32, u8); RULES] = kani::any();
        let mut cidrs = Vec::with_capacity(RULES);
        for (addr, prefix) in raw.iter().take(n) {
            kani::assume(*prefix <= 32);
            cidrs.push(Cidr::new(Ipv4Addr::from(*addr), *prefix).unwrap());
        }
        cidrs
    }

    fn any_protocols() -> Vec<IpProto> {
        let (tcp, udp, icmp): (bool, bool, bool) = kani::any();
        let mut protocols = Vec::with_capacity(3);
        if tcp {
            protocols.push(IpProto::Tcp);
        }
        if udp {
            protocols.push(IpProto::Udp);
        }
        if icmp {
            protocols.push(IpProto::Icmp);
        }
        protocols
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn kani_frame_verdict_admits_nothing_undeclared() {
        let header: [u8; 40] = kani::any();
        let Some(frame) = summarize_ipv4(&header) else {
            return;
        };
        let rules = EgressRules {
            lease: Ipv4Addr::from(kani::any::<u32>()),
            allow_subnets: if kani::any() { Some(any_cidrs()) } else { None },
            deny_subnets: any_cidrs(),
            allow_protocols: if kani::any() {
                Some(any_protocols())
            } else {
                None
            },
            resolver: if kani::any() {
                Some(Endpoint {
                    ip: Ipv4Addr::from(kani::any::<u32>()),
                    port: kani::any(),
                })
            } else {
                None
            },
        };

        // The declared conditions, restated here rather than read back from
        // the function under proof.
        let source_is_lease = frame.src == rules.lease;
        let protocol_allowed = rules
            .allow_protocols
            .as_ref()
            .is_none_or(|p| ip_proto(frame.proto).is_some_and(|x| p.contains(&x)));
        let denied = rules.deny_subnets.iter().any(|c| c.contains(frame.dst));
        let resolver = rules.resolver.is_some_and(|r| {
            frame.dst == r.ip
                && frame.dst_port == Some(r.port)
                && (frame.proto == IPPROTO_TCP || frame.proto == IPPROTO_UDP)
        });
        let declared = rules
            .allow_subnets
            .as_ref()
            .is_none_or(|a| a.iter().any(|c| c.contains(frame.dst)) || resolver);

        match frame_verdict(&frame, &rules) {
            Verdict::Admit => {
                assert!(source_is_lease);
                assert!(protocol_allowed);
                assert!(!denied);
                assert!(declared);
            }
            Verdict::Drop(DropRule::Source) => assert!(!source_is_lease),
            Verdict::Drop(DropRule::Protocol) => assert!(!protocol_allowed),
            Verdict::Drop(DropRule::DeniedSubnet) => assert!(denied),
            Verdict::Drop(DropRule::Undeclared) => assert!(!declared),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const RESOLVER: Endpoint = Endpoint {
        ip: Ipv4Addr::new(100, 64, 0, 1),
        port: 53,
    };

    /// A first-fragment IPv4 packet with a minimal transport header.
    fn packet(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, dst_port: u16) -> Vec<u8> {
        let mut p = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, proto, 0, 0,
        ];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    fn summary(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, dst_port: u16) -> FrameSummary {
        summarize_ipv4(&packet(src, dst, proto, dst_port)).expect("a well-formed packet")
    }

    fn policy(allow: &[&str], deny: &[&str], protocols: Option<Vec<IpProto>>) -> EgressPolicy {
        EgressPolicy {
            allow_subnets: Some(allow.iter().map(ToString::to_string).collect()),
            allow_dns_hosts: None,
            allow_protocols: protocols,
            deny_subnets: Some(deny.iter().map(ToString::to_string).collect()),
        }
    }

    #[test]
    fn summarize_reads_addresses_transport_and_port() {
        let s = summary(LEASE, Ipv4Addr::new(93, 184, 216, 34), IPPROTO_TCP, 443);
        assert_eq!(s.src, LEASE);
        assert_eq!(s.dst, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(s.proto, IPPROTO_TCP);
        assert_eq!(s.dst_port, Some(443));
    }

    #[test]
    fn summarize_rejects_short_and_non_v4_and_reads_fragments_without_a_port() {
        let full = packet(LEASE, RESOLVER.ip, IPPROTO_UDP, 53);
        for cut in [0, 10, 19] {
            assert!(summarize_ipv4(&full[..cut]).is_none(), "len {cut}");
        }
        let mut v6 = full.clone();
        v6[0] = 0x65;
        assert!(summarize_ipv4(&v6).is_none());
        let mut long_ihl = full.clone();
        long_ihl[0] = 0x4f; // IHL 60 bytes, past the packet
        assert!(summarize_ipv4(&long_ihl).is_none());
        // A later fragment carries no transport header: addresses only.
        let mut later = full;
        later[7] = 0x10;
        let s = summarize_ipv4(&later).unwrap();
        assert_eq!(
            (s.src, s.dst, s.proto, s.dst_port),
            (LEASE, RESOLVER.ip, IPPROTO_UDP, None)
        );
    }

    #[test]
    fn cidr_parses_v4_only_and_contains_by_prefix() {
        let net = Cidr::parse("10.1.2.3/8").unwrap();
        assert!(net.contains(Ipv4Addr::new(10, 200, 0, 1)));
        assert!(!net.contains(Ipv4Addr::new(11, 0, 0, 1)));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(LEASE));
        assert_eq!(
            Cidr::parse("1.2.3.4/32").unwrap(),
            Cidr::new(Ipv4Addr::new(1, 2, 3, 4), 32).unwrap()
        );
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("fd00::/8").is_none());
        assert!(Cidr::parse("1.2.3.4").is_none());
    }

    #[test]
    fn absent_policy_admits_everything_from_the_lease() {
        let rules = EgressRules::for_box(LEASE, None, Some(RESOLVER));
        let anywhere = summary(LEASE, Ipv4Addr::new(93, 184, 216, 34), IPPROTO_UDP, 5000);
        assert_eq!(frame_verdict(&anywhere, &rules), Verdict::Admit);
    }

    #[test]
    fn source_other_than_lease_is_rejected_whatever_the_rules() {
        let rules = EgressRules::for_box(LEASE, None, Some(RESOLVER));
        let spoofed = summary(Ipv4Addr::new(100, 64, 0, 5), RESOLVER.ip, IPPROTO_UDP, 53);
        assert_eq!(
            frame_verdict(&spoofed, &rules),
            Verdict::Drop(DropRule::Source)
        );
    }

    #[test]
    fn udp_is_dropped_when_only_tcp_is_allowed() {
        let rules = EgressRules::for_box(
            LEASE,
            Some(&policy(&["0.0.0.0/0"], &[], Some(vec![IpProto::Tcp]))),
            Some(RESOLVER),
        );
        let udp = summary(LEASE, Ipv4Addr::new(1, 1, 1, 1), IPPROTO_UDP, 53);
        assert_eq!(
            frame_verdict(&udp, &rules),
            Verdict::Drop(DropRule::Protocol)
        );
        // Even to the resolver: the transport rule is universal (NET-064).
        let dns = summary(LEASE, RESOLVER.ip, IPPROTO_UDP, 53);
        assert_eq!(
            frame_verdict(&dns, &rules),
            Verdict::Drop(DropRule::Protocol)
        );
        let tcp = summary(LEASE, Ipv4Addr::new(1, 1, 1, 1), IPPROTO_TCP, 443);
        assert_eq!(frame_verdict(&tcp, &rules), Verdict::Admit);
    }

    #[test]
    fn undeclared_destination_is_dropped_and_declared_one_admitted() {
        let rules = EgressRules::for_box(
            LEASE,
            Some(&policy(&["10.0.0.0/8"], &[], None)),
            Some(RESOLVER),
        );
        let outside = summary(LEASE, Ipv4Addr::new(93, 184, 216, 34), IPPROTO_TCP, 443);
        assert_eq!(
            frame_verdict(&outside, &rules),
            Verdict::Drop(DropRule::Undeclared)
        );
        let inside = summary(LEASE, Ipv4Addr::new(10, 3, 4, 5), IPPROTO_TCP, 443);
        assert_eq!(frame_verdict(&inside, &rules), Verdict::Admit);
    }

    #[test]
    fn deny_beats_allow() {
        let rules = EgressRules::for_box(
            LEASE,
            Some(&policy(&["10.0.0.0/8"], &["10.9.0.0/16"], None)),
            None,
        );
        let denied = summary(LEASE, Ipv4Addr::new(10, 9, 1, 1), IPPROTO_TCP, 80);
        assert_eq!(
            frame_verdict(&denied, &rules),
            Verdict::Drop(DropRule::DeniedSubnet)
        );
        let allowed = summary(LEASE, Ipv4Addr::new(10, 8, 1, 1), IPPROTO_TCP, 80);
        assert_eq!(frame_verdict(&allowed, &rules), Verdict::Admit);
    }

    #[test]
    fn deny_all_reaches_only_the_resolver_by_address_and_port() {
        let rules = EgressRules::for_box(LEASE, Some(&policy(&[], &[], None)), Some(RESOLVER));
        let dns = summary(LEASE, RESOLVER.ip, IPPROTO_UDP, 53);
        assert_eq!(frame_verdict(&dns, &rules), Verdict::Admit);
        let dns_tcp = summary(LEASE, RESOLVER.ip, IPPROTO_TCP, 53);
        assert_eq!(frame_verdict(&dns_tcp, &rules), Verdict::Admit);
        // Same address, another port: not the carve-out.
        let gateway_http = summary(LEASE, RESOLVER.ip, IPPROTO_TCP, 80);
        assert_eq!(
            frame_verdict(&gateway_http, &rules),
            Verdict::Drop(DropRule::Undeclared)
        );
        // A later fragment to the resolver carries no port to match on.
        let fragment = FrameSummary {
            dst_port: None,
            ..dns
        };
        assert_eq!(
            frame_verdict(&fragment, &rules),
            Verdict::Drop(DropRule::Undeclared)
        );
        // No carve-out configured: deny-all is deny-all.
        let bare = EgressRules::for_box(LEASE, Some(&policy(&[], &[], None)), None);
        assert_eq!(
            frame_verdict(&dns, &bare),
            Verdict::Drop(DropRule::Undeclared)
        );
    }

    #[test]
    fn for_box_skips_prefixes_that_match_nothing_here() {
        let rules = EgressRules::for_box(
            LEASE,
            Some(&policy(
                &["fd00::/8", "10.0.0.0/8"],
                &["2001:db8::/32"],
                None,
            )),
            None,
        );
        assert_eq!(rules.allow_subnets.as_ref().map(Vec::len), Some(1));
        assert!(rules.deny_subnets.is_empty());
    }

    mod property {
        use super::*;
        use proptest::prelude::*;

        fn arb_cidrs() -> impl Strategy<Value = Vec<Cidr>> {
            proptest::collection::vec((any::<u32>(), 0u8..=32), 0..=4).prop_map(|raw| {
                raw.into_iter()
                    .map(|(a, p)| Cidr::new(Ipv4Addr::from(a), p).unwrap())
                    .collect()
            })
        }

        fn arb_protocols() -> impl Strategy<Value = Vec<IpProto>> {
            any::<[bool; 3]>().prop_map(|[tcp, udp, icmp]| {
                [
                    (tcp, IpProto::Tcp),
                    (udp, IpProto::Udp),
                    (icmp, IpProto::Icmp),
                ]
                .into_iter()
                .filter_map(|(on, p)| on.then_some(p))
                .collect()
            })
        }

        proptest! {
            /// The proptest twin of `kani_frame_verdict_admits_nothing_undeclared`,
            /// under the ordinary test run: an admitted frame satisfies every
            /// declared condition, and a drop names a rule the frame trips.
            /// The header is biased toward parseable, lease-sourced frames so
            /// the admit arm is exercised, not only the early drops.
            #[test]
            fn frame_verdict_admits_nothing_undeclared(
                mut header in any::<[u8; 40]>(),
                well_formed in proptest::bool::weighted(0.8),
                from_lease in proptest::bool::weighted(0.7),
                lease in any::<u32>(),
                allow in proptest::option::of(arb_cidrs()),
                deny in arb_cidrs(),
                protocols in proptest::option::of(arb_protocols()),
                resolver in proptest::option::of((any::<u32>(), any::<u16>())),
            ) {
                if well_formed {
                    header[0] = 0x45;
                }
                let lease = Ipv4Addr::from(lease);
                if from_lease {
                    header[12..16].copy_from_slice(&lease.octets());
                }
                let Some(frame) = summarize_ipv4(&header) else { return Ok(()); };
                let rules = EgressRules {
                    lease,
                    allow_subnets: allow,
                    deny_subnets: deny,
                    allow_protocols: protocols,
                    resolver: resolver.map(|(ip, port)| Endpoint { ip: Ipv4Addr::from(ip), port }),
                };

                let source_is_lease = frame.src == rules.lease;
                let protocol_allowed = rules
                    .allow_protocols
                    .as_ref()
                    .is_none_or(|p| ip_proto(frame.proto).is_some_and(|x| p.contains(&x)));
                let denied = rules.deny_subnets.iter().any(|c| c.contains(frame.dst));
                let reaches_resolver = rules.resolver.is_some_and(|r| {
                    frame.dst == r.ip
                        && frame.dst_port == Some(r.port)
                        && (frame.proto == IPPROTO_TCP || frame.proto == IPPROTO_UDP)
                });
                let declared = rules
                    .allow_subnets
                    .as_ref()
                    .is_none_or(|a| a.iter().any(|c| c.contains(frame.dst)) || reaches_resolver);

                match frame_verdict(&frame, &rules) {
                    Verdict::Admit => {
                        prop_assert!(source_is_lease);
                        prop_assert!(protocol_allowed);
                        prop_assert!(!denied);
                        prop_assert!(declared);
                    }
                    Verdict::Drop(DropRule::Source) => prop_assert!(!source_is_lease),
                    Verdict::Drop(DropRule::Protocol) => prop_assert!(!protocol_allowed),
                    Verdict::Drop(DropRule::DeniedSubnet) => prop_assert!(denied),
                    Verdict::Drop(DropRule::Undeclared) => prop_assert!(!declared),
                }
            }
        }
    }
}
