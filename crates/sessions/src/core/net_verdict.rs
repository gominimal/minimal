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

use crate::{EgressPolicy, IngressPolicy, IpProto};

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
    /// The target box did not declare the port asked for (NET-069).
    UndeclaredPort,
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
            Self::UndeclaredPort => "ingress.port_mappings",
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

/// The ports one box declared inbound, as the surface deciding a connection to
/// it reads them.
///
/// A box with an address of its own declares them in `ingress.port_mappings`.
/// Each pair carries a host-side port and a box-side port; a hostname-routing
/// surface on the host dials the host-side one (it is the port gvproxy
/// publishes, and so the port a direct connection from the host reaches), while
/// the relay's switch-side gate sees the box-side twin of the same
/// declaration. One declaration, read where each surface meets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRules {
    /// The declared `(transport, port)` pairs, in the spelling the surface
    /// reading them meets: host-side for [`Self::for_own_address`], box-side
    /// for [`Self::for_box_listeners`]. `None` for a box that
    /// carries the host's address: ingress declarations are own-address only
    /// (launch validation refuses them elsewhere), so such a box declares
    /// nothing of its own and a direct connection reaches its listeners like
    /// any other process on the host.
    declared: Option<Vec<(IpProto, u16)>>,
    /// The inclusive port range the box permits beyond its declaration, from
    /// `ingress.dynamic_allowed_range`: ports a process in the box may have
    /// published by listening on one (NET-016). `None` permits nothing the
    /// declaration does not name.
    permitted: Option<(u16, u16)>,
}

impl IngressRules {
    /// The rules for a box with an address of its own, from its declared
    /// `ingress`. An absent section declares no port at all, which is the
    /// deny-all default: nothing inbound is admitted.
    #[must_use]
    pub fn for_own_address(ingress: Option<&IngressPolicy>) -> Self {
        Self {
            declared: Some(
                ingress
                    .map(|i| {
                        i.port_mappings
                            .iter()
                            .map(|m| (m.proto, m.external_port))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            permitted: ingress.and_then(|i| i.dynamic_allowed_range),
        }
    }

    /// The same declaration read box-side: each mapping's internal port, which
    /// is the port a process in the box listens on, rather than the host-side
    /// port a connection from the host dials. What the listen-publication
    /// decision reads, since it meets the declaration where the box's own
    /// listeners do (NET-016).
    #[must_use]
    pub fn for_box_listeners(ingress: Option<&IngressPolicy>) -> Self {
        Self {
            declared: Some(
                ingress
                    .map(|i| {
                        i.port_mappings
                            .iter()
                            .map(|m| (m.proto, m.internal_port))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            permitted: ingress.and_then(|i| i.dynamic_allowed_range),
        }
    }

    /// The rules for a box that carries the host's address: it declares no
    /// ingress of its own, and every port a direct connection reaches is one a
    /// hostname-routing surface may reach too (NET-071).
    #[must_use]
    pub fn for_host_address() -> Self {
        Self {
            declared: None,
            permitted: None,
        }
    }

    /// Adds `port` over `proto` to what an own-address box declares: a port
    /// published at runtime by a dynamic ingress request is admitted like a
    /// declared one from then on. A host-address box declares nothing of its
    /// own, so this leaves it as it is.
    pub fn declare(&mut self, proto: IpProto, port: u16) {
        if let Some(declared) = &mut self.declared
            && !declared.contains(&(proto, port))
        {
            declared.push((proto, port));
        }
    }

    /// Takes `port` over `proto` back out of what the box declares: the
    /// rollback of a dynamic publication that did not complete.
    pub fn retract(&mut self, proto: IpProto, port: u16) {
        if let Some(declared) = &mut self.declared {
            declared.retain(|d| *d != (proto, port));
        }
    }

    /// Whether the box declared `port` for the transport `proto` names (an IPv4
    /// protocol number).
    ///
    /// Only TCP and UDP carry a port, and a declaration is about a port, so any
    /// other transport is admitted for none — which is also what keeps the
    /// decision the same whether it is taken on a frame (where a portless
    /// transport carries no port to read) or on a request's stated facts.
    #[must_use]
    pub fn admits(&self, proto: u8, port: u16) -> bool {
        let carries_a_port = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
        match &self.declared {
            None => carries_a_port,
            Some(declared) => {
                carries_a_port && ip_proto(proto).is_some_and(|p| declared.contains(&(p, port)))
            }
        }
    }

    /// Whether a declaration names `port` for the transport `proto` names. A
    /// box that carries the host's address declares nothing of its own, so it
    /// names no port.
    #[must_use]
    pub fn declares(&self, proto: u8, port: u16) -> bool {
        let carries_a_port = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
        self.declared.as_ref().is_some_and(|declared| {
            carries_a_port && ip_proto(proto).is_some_and(|p| declared.contains(&(p, port)))
        })
    }

    /// Whether the box's rules permit inbound on `port`: a port its
    /// declaration names, or one inside the permit range it declared. A box
    /// that carries the host's address permits every port that carries one, as
    /// its own listeners answer them at the host's address already.
    ///
    /// Only TCP and UDP carry a port, so any other transport is permitted for
    /// none — the same rule [`Self::admits`] applies.
    #[must_use]
    pub fn permits(&self, proto: u8, port: u16) -> bool {
        let carries_a_port = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
        let in_range = self
            .permitted
            .is_some_and(|(low, high)| low <= port && port <= high);
        carries_a_port && (self.declared.is_none() || in_range || self.declares(proto, port))
    }
}

/// What a box's ingress rules say about a port a process in it has begun
/// listening on (NET-016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenPublication {
    /// The rules permit the port and no declaration names it: publish it on
    /// the box's address.
    Publish,
    /// A declaration names the port, so it was bound and published before the
    /// box's name was registered (NET-121) and the listener adds nothing.
    Declared,
    /// The rules do not permit the port: leave it unpublished.
    Unpermitted,
}

/// Decides one listening port of a box: whether it is published because the
/// box's rules permit it and no declaration names it (NET-016).
///
/// Pure, like the frame verdict: the rules and the port decide, and nothing
/// about the process that opened the listener does. A port the rules do not
/// permit is never published, whatever listens on it.
///
/// A box that carries the host's address permits every port that carries one,
/// so these rules answer `Publish` for each. Whether such a box's listeners are
/// read at all is the daemon's decision and not the verdict's: a host-address
/// box shares the host's socket table, where the host's own listeners cannot be
/// told from the box's.
#[must_use]
pub fn ingress_permit_verdict(rules: &IngressRules, proto: u8, port: u16) -> ListenPublication {
    if rules.declares(proto, port) {
        return ListenPublication::Declared;
    }
    if rules.permits(proto, port) {
        return ListenPublication::Publish;
    }
    ListenPublication::Unpermitted
}

/// One request a hostname-routing surface is asked to carry: who asked, the box
/// the name resolved to, and the port and transport asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxiedRequest {
    /// The caller's own address — a box's switch lease, which is what
    /// attributes the request to that box (NET-084).
    pub caller: Ipv4Addr,
    /// The target box's own address: what the direct connection would dial,
    /// not the address the surface forwards to.
    pub target: Ipv4Addr,
    /// The port asked for.
    pub port: u16,
    /// IPv4 protocol number of the transport asked for.
    pub proto: u8,
}

impl ProxiedRequest {
    /// The frame the direct connection would open with: from the caller's own
    /// address to the target box's, carrying the port asked for. Deciding on
    /// this frame rather than on the one the surface itself would send is what
    /// keeps the caller's rules the caller's, not the surface's.
    #[must_use]
    pub fn as_frame(&self) -> FrameSummary {
        FrameSummary {
            src: self.caller,
            dst: self.target,
            proto: self.proto,
            dst_port: Some(self.port),
        }
    }
}

/// Decides the connection `frame` opens: the caller's egress rules, then the
/// target's declared ports — the two legs the relay applies, in the order it
/// applies them (NET-073). A frame with no port carries no declared port to
/// match, so it is refused like one to a port nobody declared.
///
/// `caller` is `None` for a caller whose rules are not this decision's to
/// apply: a process on the host, or a host-address cohort sharing the host's
/// address (NET-078), whose declaration is enforced inside the box (NET-079).
#[must_use]
pub fn direct_verdict(
    frame: &FrameSummary,
    caller: Option<&EgressRules>,
    target: &IngressRules,
) -> Verdict {
    if let Some(rules) = caller
        && let Verdict::Drop(rule) = frame_verdict(frame, rules)
    {
        return Verdict::Drop(rule);
    }
    match frame.dst_port {
        Some(port) if target.admits(frame.proto, port) => Verdict::Admit,
        _ => Verdict::Drop(DropRule::UndeclaredPort),
    }
}

/// Decides `request` as the direct connection it stands in for (NET-069 to
/// NET-071): the same function, on the frame that connection would carry.
/// Going through a hostname-routing surface changes the bytes' path, never the
/// decision, so the surface has no reach a direct connection would not have.
#[must_use]
pub fn proxied_verdict(
    request: &ProxiedRequest,
    caller: Option<&EgressRules>,
    target: &IngressRules,
) -> Verdict {
    direct_verdict(&request.as_frame(), caller, target)
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
            // The frame verdict names egress rules only; the port declaration
            // is the ingress leg's, applied by `direct_verdict`.
            Verdict::Drop(DropRule::UndeclaredPort) => panic!("not an egress rule"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortMapping;

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

    /// An ingress policy declaring each `(host-side port, transport)` pair,
    /// forwarding to the same port inside the box.
    fn ingress(mappings: &[(u16, IpProto)]) -> IngressPolicy {
        IngressPolicy {
            port_mappings: mappings
                .iter()
                .map(|&(port, proto)| PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto,
                })
                .collect(),
            dynamic_allowed_range: None,
        }
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

    /// A box with an address of its own admits exactly the ports it declared;
    /// one that carries the host's address declares none of its own and admits
    /// every port a direct connection to it would reach (NET-069, NET-071).
    #[test]
    fn declared_ports_decide_an_own_address_box_but_not_a_host_address_one() {
        let declared = ingress(&[(18080, IpProto::Tcp), (15353, IpProto::Udp)]);
        let own = IngressRules::for_own_address(Some(&declared));
        assert!(own.admits(IPPROTO_TCP, 18080));
        assert!(own.admits(IPPROTO_UDP, 15353));
        // The declared port on another transport is not declared.
        assert!(!own.admits(IPPROTO_UDP, 18080));
        assert!(!own.admits(IPPROTO_TCP, 9999));
        // A transport with no port has no declared port to match.
        assert!(!own.admits(IPPROTO_ICMP, 18080));
        // No `ingress` section at all: the deny-all default.
        assert!(!IngressRules::for_own_address(None).admits(IPPROTO_TCP, 18080));
        // The host's address: any port, as a direct connection reaches it.
        assert!(IngressRules::for_host_address().admits(IPPROTO_TCP, 9999));
        assert!(!IngressRules::for_host_address().admits(IPPROTO_ICMP, 9999));
    }

    /// NET-069, NET-070: a request through a hostname-routing surface is
    /// refused exactly as the direct connection it stands in for — for a port
    /// the target did not declare, and for a caller whose own rules deny the
    /// target — and each refusal names the rule it tripped.
    #[test]
    fn a_proxied_request_is_refused_like_the_direct_connection() {
        const TARGET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 12);
        let target = IngressRules::for_own_address(Some(&ingress(&[(18080, IpProto::Tcp)])));
        let reaches =
            EgressRules::for_box(LEASE, Some(&policy(&["100.64.0.0/10"], &[], None)), None);
        let denies = EgressRules::for_box(LEASE, Some(&policy(&["10.0.0.0/8"], &[], None)), None);
        let asking = |port| ProxiedRequest {
            caller: LEASE,
            target: TARGET,
            port,
            proto: IPPROTO_TCP,
        };

        assert_eq!(
            proxied_verdict(&asking(18080), Some(&reaches), &target),
            Verdict::Admit
        );
        assert_eq!(
            proxied_verdict(&asking(9999), Some(&reaches), &target),
            Verdict::Drop(DropRule::UndeclaredPort)
        );
        // The caller's rules do not allow the target's address: refused with the
        // egress rule a direct connection would have tripped.
        assert_eq!(
            proxied_verdict(&asking(18080), Some(&denies), &target),
            Verdict::Drop(DropRule::Undeclared)
        );
        // A caller whose rules are not the surface's to apply: the target's
        // declaration alone decides.
        assert_eq!(
            proxied_verdict(&asking(18080), None, &target),
            Verdict::Admit
        );
        assert_eq!(
            proxied_verdict(&asking(9999), None, &target),
            Verdict::Drop(DropRule::UndeclaredPort)
        );
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

        fn arb_mappings() -> impl Strategy<Value = Vec<PortMapping>> {
            proptest::collection::vec(
                (
                    any::<u16>(),
                    prop_oneof![Just(IpProto::Tcp), Just(IpProto::Udp)],
                ),
                0..=4,
            )
            .prop_map(|raw| {
                raw.into_iter()
                    .map(|(port, proto)| PortMapping {
                        external_port: port,
                        internal_port: port,
                        proto,
                    })
                    .collect()
            })
        }

        proptest! {
            /// NET-071: for every network mode, every rule set and every
            /// request, the verdict a hostname-routing surface reaches is the
            /// verdict the direct connection reaches. The surface decides on the
            /// request's stated facts; the direct leg decides on the frame that
            /// connection carries, read off the wire the way the relay reads it.
            /// Ports are drawn from a small set so a declared one is asked for
            /// often enough to exercise the admit arm.
            #[test]
            fn proxy_verdict_equals_direct_verdict_property(
                caller in any::<u32>(),
                target_address in any::<u32>(),
                port in prop_oneof![Just(0u16), Just(80), Just(443), Just(18080), any::<u16>()],
                proto in prop_oneof![
                    Just(IPPROTO_TCP),
                    Just(IPPROTO_UDP),
                    Just(IPPROTO_ICMP),
                    any::<u8>(),
                ],
                host_address in any::<bool>(),
                mappings in arb_mappings(),
                caller_is_a_box in proptest::bool::weighted(0.8),
                other_lease in any::<u32>(),
                from_lease in proptest::bool::weighted(0.7),
                allow in proptest::option::of(arb_cidrs()),
                deny in arb_cidrs(),
                protocols in proptest::option::of(arb_protocols()),
            ) {
                let caller = Ipv4Addr::from(caller);
                let target_address = Ipv4Addr::from(target_address);
                let rules = EgressRules {
                    lease: if from_lease { caller } else { Ipv4Addr::from(other_lease) },
                    allow_subnets: allow,
                    deny_subnets: deny,
                    allow_protocols: protocols,
                    resolver: None,
                };
                let caller_rules = caller_is_a_box.then_some(&rules);
                let target = if host_address {
                    IngressRules::for_host_address()
                } else {
                    IngressRules::for_own_address(Some(&IngressPolicy {
                        port_mappings: mappings,
                        dynamic_allowed_range: None,
                    }))
                };

                let request = ProxiedRequest { caller, target: target_address, port, proto };
                let direct = summarize_ipv4(&packet(caller, target_address, proto, port))
                    .expect("a well-formed packet");
                prop_assert_eq!(
                    proxied_verdict(&request, caller_rules, &target),
                    direct_verdict(&direct, caller_rules, &target)
                );
            }
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
                    Verdict::Drop(DropRule::UndeclaredPort) => {
                        unreachable!("the frame verdict names egress rules only")
                    }
                }
            }
        }

        proptest! {
            /// NET-016 and its failure case: for every box and every port, the
            /// listen-publication verdict publishes only a port the box's own
            /// rules permit and no declaration names — so a port the rules do
            /// not permit is never published, whatever listens on it. The
            /// permit range is drawn unordered, as a reversed one reaches the
            /// decision the same way; the conditions are restated here from
            /// the declaration itself, independently of `IngressRules`.
            #[test]
            fn ingress_permit_verdict_admits_nothing_undeclared(
                mappings in arb_mappings(),
                range in proptest::option::of((any::<u16>(), any::<u16>())),
                host_address in proptest::bool::weighted(0.2),
                port in prop_oneof![Just(0u16), Just(3000), Just(9090), any::<u16>()],
                proto in prop_oneof![
                    Just(IPPROTO_TCP),
                    Just(IPPROTO_UDP),
                    Just(IPPROTO_ICMP),
                    any::<u8>(),
                ],
            ) {
                let policy = IngressPolicy {
                    port_mappings: mappings,
                    dynamic_allowed_range: range,
                };
                let rules = if host_address {
                    IngressRules::for_host_address()
                } else {
                    IngressRules::for_box_listeners(Some(&policy))
                };

                let carries_a_port = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
                let named = !host_address
                    && carries_a_port
                    && policy.port_mappings.iter().any(|m| {
                        m.internal_port == port && ip_proto(proto) == Some(m.proto)
                    });
                let in_range = !host_address
                    && range.is_some_and(|(low, high)| low <= port && port <= high);
                let permitted = carries_a_port && (host_address || named || in_range);

                match ingress_permit_verdict(&rules, proto, port) {
                    ListenPublication::Publish => {
                        prop_assert!(permitted);
                        prop_assert!(!named);
                    }
                    ListenPublication::Declared => prop_assert!(named),
                    ListenPublication::Unpermitted => prop_assert!(!permitted),
                }
            }
        }
    }
}
