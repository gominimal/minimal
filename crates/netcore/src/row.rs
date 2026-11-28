//! The decision for a frame from a registered row, as far as it can be made
//! without any table: the switch's own addresses, the infrastructure ranges,
//! the proxy lane, and the row's declared rules.
//!
//! Layer 3 of the crate, from policy to rules. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The decision is a table. [`row_spec`] is that table, written as a
//! specification: the arms in the order they are tried, each with its
//! condition. [`decide_row`] is proved to return exactly what the table says,
//! so the properties below are proved once, of the table.
//!
//! THEOREM V2: `decide_row` returns `row_spec`: the first arm whose condition
//! holds.
//!
//! THEOREMS about the table, for every plan, row and frame:
//!   V3  a frame to 169.254.0.0/16 or 127.0.0.0/8 is never admitted;
//!   V4  a frame to the gateway is admitted only as TCP or UDP to port 53;
//!   V5  a frame to the proxy's address is admitted only on the lane: a row
//!       that declares a credentialed upstream, TCP, port 8118 or 443;
//!   V6  a frame to the host alias is admitted only when the alias is open to
//!       this row for this frame;
//!   V7  a frame to a private address (10/8, 172.16/12, 192.168/16) other
//!       than the alias is admitted only when the row's allowed subnets cover
//!       it;
//!   V8  a frame the row's denied subnets cover is admitted only by an arm
//!       that does not read the row's subnet lists: ARP, the lane or the
//!       resolver.
//!
//! Not here: replies to inbound flows, refusals, DNS admissions and box
//! names. Those read tables. A reply or a refusal is tried before this table
//! (J1); a DNS admission or a box name can only turn
//! [`RowArm::UndeclaredSubnet`] into an admit.
//! Whether the alias is open is an input: it depends on host exposures.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_contains, spec_gateway, spec_host_alias, spec_proxy_peer, spec_shared, wf};

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROTO_TCP: u8 = 6;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROTO_UDP: u8 = 17;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const DNS_PORT: u16 = 53;
/// The proxy's listener, and the port a steered TLS connection arrives on.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROXY_PORT: u16 = 8118;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const PROXY_TLS_PORT: u16 = 443;

/// An IPv4 block as a rule names it. A prefix of 32 or more is one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Cidr {
    pub addr: u32,
    pub prefix: u8,
}

/// What a registered row declared. `None` is "no list": every protocol, or
/// every subnet. An empty list is "none of them".
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct RowRules {
    pub allow_protocols: Option<Vec<u8>>,
    pub deny: Vec<Cidr>,
    pub allow_subnets: Option<Vec<Cidr>>,
    /// The row declares a credentialed upstream, so it may use the proxy lane.
    pub laned: bool,
}

/// Where a frame is going, as far as the rules read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Dest {
    /// An ARP packet: it has no destination the rules read.
    Arp,
    /// An IPv4 datagram. `port` is the destination port of a TCP or UDP first
    /// fragment with a whole header, and 0 for anything else.
    V4 { dst: u32, proto: u8, port: u16 },
}

/// The arms of the decision, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum RowArm {
    /// Admit: ARP from the row's own address.
    Arp,
    /// Drop: the gateway, at anything but TCP or UDP port 53.
    ControlSurface,
    /// Drop: 169.254.0.0/16 or 127.0.0.0/8.
    InfraFixed,
    /// Drop: the host alias, not open to this row for this frame.
    AliasClosed,
    /// Drop: 100.64.0.0/10 outside the switch's own block.
    InfraPlane,
    /// Drop: a private address the row's allowed subnets do not cover.
    InfraPrivate,
    /// Admit: the proxy lane.
    LaneAdmit,
    /// Drop: the proxy's address, off the lane.
    LaneRefuse,
    /// Admit: UDP to the resolver at port 53.
    Resolver,
    /// Drop: a protocol the row did not declare.
    UndeclaredProtocol,
    /// Drop: a subnet the row denied.
    DeniedSubnet,
    /// Drop, unless a reply, a DNS admission or a box name lifts it: a subnet
    /// the row did not allow.
    UndeclaredSubnet,
    /// Admit: the row's rules allow it.
    Rules,
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn mask_of(prefix: u8) -> u32 {
    if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        0xffff_ffffu32
    } else {
        0xffff_ffffu32 << (32 - prefix as u32)
    }
}

pub open spec fn cidr_contains(c: Cidr, a: u32) -> bool {
    a & mask_of(c.prefix) == c.addr & mask_of(c.prefix)
}

/// Some block of `s` contains `a`.
pub open spec fn covers(s: Seq<Cidr>, a: u32) -> bool {
    exists|i: int| 0 <= i < s.len() && cidr_contains(#[trigger] s[i], a)
}

pub open spec fn allow_covers(allow: Option<Vec<Cidr>>, a: u32) -> bool {
    match allow {
        None => true,
        Some(v) => covers(v@, a),
    }
}

pub open spec fn has_proto(s: Seq<u8>, p: u8) -> bool {
    exists|i: int| 0 <= i < s.len() && #[trigger] s[i] == p
}

pub open spec fn proto_allowed(allow: Option<Vec<u8>>, p: u8) -> bool {
    match allow {
        None => true,
        Some(v) => has_proto(v@, p),
    }
}

/// 169.254.0.0/16 or 127.0.0.0/8.
pub open spec fn in_fixed(a: u32) -> bool {
    a >> 16 == 0xa9feu32 || a >> 24 == 127u32
}

/// 100.64.0.0/10.
pub open spec fn in_plane(a: u32) -> bool {
    a >> 22 == 0x191u32
}

/// 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.
pub open spec fn in_private(a: u32) -> bool {
    a >> 24 == 10u32 || a >> 20 == 0xac1u32 || a >> 16 == 0xc0a8u32
}

pub open spec fn dns_at(proto: u8, port: u16) -> bool {
    (proto == PROTO_TCP || proto == PROTO_UDP) && port == DNS_PORT
}

pub open spec fn on_lane(laned: bool, proto: u8, port: u16) -> bool {
    laned && proto == PROTO_TCP && (port == PROXY_PORT || port == PROXY_TLS_PORT)
}

pub open spec fn admits(arm: RowArm) -> bool {
    arm == RowArm::Arp || arm == RowArm::LaneAdmit || arm == RowArm::Resolver || arm == RowArm::Rules
}

/// The decision table.
pub open spec fn row_spec(plan: Plan, rules: RowRules, alias_open: bool, d: Dest) -> RowArm {
    match d {
        Dest::Arp => RowArm::Arp,
        Dest::V4 { dst, proto, port } => {
            let gateway = dst as int == spec_gateway(plan);
            let alias = dst as int == spec_host_alias(plan);
            if gateway && !dns_at(proto, port) {
                RowArm::ControlSurface
            } else if in_fixed(dst) {
                RowArm::InfraFixed
            } else if alias && !alias_open {
                RowArm::AliasClosed
            } else if !alias && in_plane(dst) && !spec_contains(plan, dst as int) {
                RowArm::InfraPlane
            } else if !alias && in_private(dst) && !allow_covers(rules.allow_subnets, dst) {
                RowArm::InfraPrivate
            } else if dst as int == spec_proxy_peer(plan) {
                if on_lane(rules.laned, proto, port) {
                    RowArm::LaneAdmit
                } else {
                    RowArm::LaneRefuse
                }
            } else if proto == PROTO_UDP && gateway && port == DNS_PORT {
                RowArm::Resolver
            } else if !proto_allowed(rules.allow_protocols, proto) {
                RowArm::UndeclaredProtocol
            } else if covers(rules.deny@, dst) {
                RowArm::DeniedSubnet
            } else if !allow_covers(rules.allow_subnets, dst) {
                RowArm::UndeclaredSubnet
            } else {
                RowArm::Rules
            }
        },
    }
}

/// V3.
pub proof fn theorem_v3(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        in_fixed(dst),
    ensures
        !admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),
{
}

/// V4.
pub proof fn theorem_v4(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        dns_at(proto, port),
{
}

/// V4, the other half: a frame to the gateway that is not DNS is refused by
/// the control surface and by no other arm.
pub proof fn theorem_v4_named(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        !dns_at(proto, port),
    ensures
        row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port }) == RowArm::ControlSurface,
{
}

/// V5.
pub proof fn theorem_v5(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        wf(plan),
        dst as int == spec_proxy_peer(plan),
        admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port }) == RowArm::LaneAdmit,
        on_lane(rules.laned, proto, port),
{
}

/// V6.
pub proof fn theorem_v6(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_host_alias(plan),
        admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        alias_open,
{
}

/// V7.
pub proof fn theorem_v7(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        in_private(dst),
        dst as int != spec_host_alias(plan),
        admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),
    ensures
        allow_covers(rules.allow_subnets, dst),
{
}

/// A block inside 100.64.0.0/10 holds only addresses of that range: for such a
/// plan the plane arm refuses exactly the shared range outside the block.
pub proof fn theorem_shared_block(plan: Plan, a: u32)
    requires
        wf(plan),
        spec_shared(plan),
        spec_contains(plan, a as int),
    ensures
        in_plane(a),
{
    // The two hypotheses put `a` between the range's ends; the shift is a
    // fact about the bits of such a number.
    assert(0x6440_0000u32 <= a && a <= 0x647f_ffffu32 ==> a >> 22 == 0x191u32) by (bit_vector);
}

/// V8.
pub proof fn theorem_v8(plan: Plan, rules: RowRules, alias_open: bool, dst: u32, proto: u8, port: u16)
    requires
        covers(rules.deny@, dst),
    ensures
        row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port }) != RowArm::Rules,
{
}

/// V9: a row that declares no protocol and has no lane. Its table admits an
/// ARP packet and a UDP datagram to the resolver at port 53, and nothing
/// else; and it never answers `UndeclaredSubnet`, the one arm a lift is
/// tried for, so nothing lifts a frame of such a row.
pub proof fn theorem_v9_no_protocol_admits_only_the_resolver(plan: Plan, rules: RowRules, alias_open: bool, d: Dest)
    requires
        rules.allow_protocols is Some,
        rules.allow_protocols->0@.len() == 0,
        !rules.laned,
    ensures
        admits(row_spec(plan, rules, alias_open, d)) ==> match d {
            Dest::Arp => true,
            Dest::V4 { dst, proto, port } => proto == PROTO_UDP && port == DNS_PORT
                && dst as int == spec_gateway(plan)
                && row_spec(plan, rules, alias_open, d) == RowArm::Resolver,
        },
        row_spec(plan, rules, alias_open, d) != RowArm::UndeclaredSubnet,
        row_spec(plan, rules, alias_open, d) != RowArm::Rules,
        row_spec(plan, rules, alias_open, d) != RowArm::LaneAdmit,
{
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == mask_of(prefix),
))]
fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        0xffff_ffffu32
    } else {
        0xffff_ffffu32 << (32 - prefix as u32)
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == cidr_contains(c, a),
))]
fn contains(c: Cidr, a: u32) -> bool {
    let m = mask(c.prefix);
    a & m == c.addr & m
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == covers(list@, a),
))]
pub(crate) fn any_covers(list: &[Cidr], a: u32) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= list.len(),
            forall|j: int| 0 <= j < i ==> !cidr_contains(#[trigger] list@[j], a),
        decreases list.len() - i,
    ))]
    while i < list.len() {
        if contains(list[i], a) {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == has_proto(list@, p),
))]
fn any_proto(list: &[u8], p: u8) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= list.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] list@[j] != p,
        decreases list.len() - i,
    ))]
    while i < list.len() {
        if list[i] == p {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == allow_covers(rules.allow_subnets, a),
))]
pub(crate) fn allowed_subnet(rules: &RowRules, a: u32) -> bool {
    match &rules.allow_subnets {
        None => true,
        Some(list) => any_covers(list.as_slice(), a),
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == proto_allowed(rules.allow_protocols, p),
))]
pub(crate) fn allowed_proto(rules: &RowRules, p: u8) -> bool {
    match &rules.allow_protocols {
        None => true,
        Some(list) => any_proto(list.as_slice(), p),
    }
}

/// The arm that decides a frame from a registered row. V2.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
    ensures
        r == row_spec(*plan, *rules, alias_open, d),
))]
pub fn decide_row(plan: &Plan, rules: &RowRules, alias_open: bool, d: Dest) -> RowArm {
    let (dst, proto, port) = match d {
        Dest::Arp => return RowArm::Arp,
        Dest::V4 { dst, proto, port } => (dst, proto, port),
    };
    let gateway = dst == plan.gateway();
    let alias = dst == plan.host_alias();
    let dns = (proto == PROTO_TCP || proto == PROTO_UDP) && port == DNS_PORT;
    if gateway && !dns {
        return RowArm::ControlSurface;
    }
    if dst >> 16 == 0xa9feu32 || dst >> 24 == 127u32 {
        return RowArm::InfraFixed;
    }
    if alias && !alias_open {
        return RowArm::AliasClosed;
    }
    if !alias && dst >> 22 == 0x191u32 && !plan.contains(dst) {
        return RowArm::InfraPlane;
    }
    let private = dst >> 24 == 10u32 || dst >> 20 == 0xac1u32 || dst >> 16 == 0xc0a8u32;
    if !alias && private && !allowed_subnet(rules, dst) {
        return RowArm::InfraPrivate;
    }
    // A private address that passed the arm above is covered by the allowed
    // subnets: the list is not read a second time for it.
    let covered = !alias && private;
    if dst == plan.proxy_peer() {
        if rules.laned && proto == PROTO_TCP && (port == PROXY_PORT || port == PROXY_TLS_PORT) {
            return RowArm::LaneAdmit;
        }
        return RowArm::LaneRefuse;
    }
    if proto == PROTO_UDP && gateway && port == DNS_PORT {
        return RowArm::Resolver;
    }
    if !allowed_proto(rules, proto) {
        return RowArm::UndeclaredProtocol;
    }
    if any_covers(rules.deny.as_slice(), dst) {
        return RowArm::DeniedSubnet;
    }
    if !covered && !allowed_subnet(rules, dst) {
        return RowArm::UndeclaredSubnet;
    }
    RowArm::Rules
}

/// Whether an arm admits the frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == admits(arm),
))]
pub fn arm_admits(arm: RowArm) -> bool {
    match arm {
        RowArm::Arp => true,
        RowArm::LaneAdmit => true,
        RowArm::Resolver => true,
        RowArm::Rules => true,
        RowArm::ControlSurface => false,
        RowArm::InfraFixed => false,
        RowArm::AliasClosed => false,
        RowArm::InfraPlane => false,
        RowArm::InfraPrivate => false,
        RowArm::LaneRefuse => false,
        RowArm::UndeclaredProtocol => false,
        RowArm::DeniedSubnet => false,
        RowArm::UndeclaredSubnet => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 100.64.0.0/24: gateway .1, proxy .252, node .253, host alias .254.
    const NET: u32 = 0x6440_0000;
    const GW: u32 = NET + 1;
    const PROXY: u32 = NET + 252;
    const ALIAS: u32 = NET + 254;
    const PUBLIC: u32 = 0xcb00_7107;

    fn plan() -> Plan {
        Plan::new(NET, 24).unwrap()
    }

    fn open() -> RowRules {
        RowRules {
            allow_protocols: None,
            deny: Vec::new(),
            allow_subnets: None,
            laned: false,
        }
    }

    fn v4(dst: u32, proto: u8, port: u16) -> Dest {
        Dest::V4 { dst, proto, port }
    }

    #[test]
    fn arp_is_admitted_whatever_the_rules() {
        let mut r = open();
        r.allow_subnets = Some(Vec::new());
        assert_eq!(decide_row(&plan(), &r, false, Dest::Arp), RowArm::Arp);
    }

    #[test]
    fn the_gateway_answers_dns_and_nothing_else() {
        let p = plan();
        assert_eq!(
            decide_row(&p, &open(), false, v4(GW, 17, 53)),
            RowArm::Resolver
        );
        assert_eq!(decide_row(&p, &open(), false, v4(GW, 6, 53)), RowArm::Rules);
        assert_eq!(
            decide_row(&p, &open(), false, v4(GW, 6, 80)),
            RowArm::ControlSurface
        );
        assert_eq!(
            decide_row(&p, &open(), false, v4(GW, 1, 0)),
            RowArm::ControlSurface
        );
        assert_eq!(
            decide_row(&p, &open(), false, v4(GW, 17, 0)),
            RowArm::ControlSurface
        );
    }

    #[test]
    fn a_deny_all_row_still_reaches_the_resolver_over_udp_only() {
        let p = plan();
        let mut r = open();
        r.allow_subnets = Some(Vec::new());
        assert_eq!(decide_row(&p, &r, false, v4(GW, 17, 53)), RowArm::Resolver);
        assert_eq!(
            decide_row(&p, &r, false, v4(GW, 6, 53)),
            RowArm::UndeclaredSubnet
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PUBLIC, 6, 443)),
            RowArm::UndeclaredSubnet
        );
    }

    #[test]
    fn link_local_and_loopback_are_never_admitted() {
        let p = plan();
        assert_eq!(
            decide_row(&p, &open(), true, v4(0xa9fe_a9fe, 6, 80)),
            RowArm::InfraFixed
        );
        assert_eq!(
            decide_row(&p, &open(), true, v4(0x7f00_0001, 6, 80)),
            RowArm::InfraFixed
        );
    }

    #[test]
    fn the_alias_is_decided_by_its_opening_alone() {
        let p = plan();
        assert_eq!(
            decide_row(&p, &open(), false, v4(ALIAS, 6, 8080)),
            RowArm::AliasClosed
        );
        assert_eq!(
            decide_row(&p, &open(), true, v4(ALIAS, 6, 8080)),
            RowArm::Rules
        );
    }

    #[test]
    fn the_plane_outside_the_own_block_is_refused() {
        let p = plan();
        assert_eq!(
            decide_row(&p, &open(), false, v4(0x6441_0005, 6, 80)),
            RowArm::InfraPlane
        );
        assert_eq!(
            decide_row(&p, &open(), false, v4(NET + 9, 6, 80)),
            RowArm::Rules
        );
    }

    #[test]
    fn a_private_address_needs_an_allowed_subnet_that_covers_it() {
        let p = plan();
        let ten = 0x0a01_0203;
        assert_eq!(
            decide_row(&p, &open(), false, v4(ten, 6, 80)),
            RowArm::Rules
        );
        let mut r = open();
        r.allow_subnets = Some(vec![Cidr {
            addr: 0xcb00_7100,
            prefix: 24,
        }]);
        assert_eq!(
            decide_row(&p, &r, false, v4(ten, 6, 80)),
            RowArm::InfraPrivate
        );
        r.allow_subnets = Some(vec![Cidr {
            addr: 0x0a00_0000,
            prefix: 8,
        }]);
        assert_eq!(decide_row(&p, &r, false, v4(ten, 6, 80)), RowArm::Rules);
        assert_eq!(
            decide_row(&p, &r, false, v4(0xac10_0001, 6, 80)),
            RowArm::InfraPrivate
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(0xc0a8_0001, 6, 80)),
            RowArm::InfraPrivate
        );
    }

    #[test]
    fn the_proxy_admits_only_a_laned_row_on_tcp_at_its_two_ports() {
        let p = plan();
        assert_eq!(
            decide_row(&p, &open(), false, v4(PROXY, 6, 8118)),
            RowArm::LaneRefuse
        );
        let mut r = open();
        r.laned = true;
        r.allow_subnets = Some(Vec::new());
        assert_eq!(
            decide_row(&p, &r, false, v4(PROXY, 6, 8118)),
            RowArm::LaneAdmit
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PROXY, 6, 443)),
            RowArm::LaneAdmit
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PROXY, 6, 80)),
            RowArm::LaneRefuse
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PROXY, 17, 443)),
            RowArm::LaneRefuse
        );
    }

    #[test]
    fn protocol_then_deny_then_allow() {
        let p = plan();
        let mut r = open();
        r.allow_protocols = Some(vec![6]);
        r.deny = vec![Cidr {
            addr: 0xcb00_7100,
            prefix: 24,
        }];
        r.allow_subnets = Some(vec![Cidr { addr: 0, prefix: 0 }]);
        assert_eq!(
            decide_row(&p, &r, false, v4(PUBLIC, 17, 443)),
            RowArm::UndeclaredProtocol
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PUBLIC, 6, 443)),
            RowArm::DeniedSubnet
        );
        assert_eq!(
            decide_row(&p, &r, false, v4(PUBLIC + 0x100, 6, 443)),
            RowArm::Rules
        );
        r.allow_subnets = Some(vec![Cidr {
            addr: PUBLIC,
            prefix: 32,
        }]);
        assert_eq!(
            decide_row(&p, &r, false, v4(PUBLIC + 0x100, 6, 443)),
            RowArm::UndeclaredSubnet
        );
    }

    #[test]
    fn a_prefix_of_zero_is_everything_and_of_thirty_two_or_more_is_one_address() {
        assert!(contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 0
            },
            0xffff_ffff
        ));
        assert!(contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 32
            },
            0x0102_0304
        ));
        assert!(!contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 32
            },
            0x0102_0305
        ));
        assert!(contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 40
            },
            0x0102_0304
        ));
        assert!(contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 31
            },
            0x0102_0305
        ));
        assert!(!contains(
            Cidr {
                addr: 0x0102_0304,
                prefix: 31
            },
            0x0102_0306
        ));
    }

    #[test]
    fn only_four_arms_admit() {
        assert!(arm_admits(RowArm::Arp) && arm_admits(RowArm::LaneAdmit));
        assert!(arm_admits(RowArm::Resolver) && arm_admits(RowArm::Rules));
        assert!(!arm_admits(RowArm::UndeclaredSubnet) && !arm_admits(RowArm::ControlSurface));
    }
}
