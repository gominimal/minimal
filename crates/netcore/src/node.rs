//! The decision for a frame from the node itself, while its baseline is in
//! force.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The node is the in-VM daemon. It declares no rules of its own: what it may
//! reach is a baseline the host holds. Like a row, it is decided by a table,
//! [`node_spec`], and [`decide_node`] is proved equal to it.
//!
//! THEOREM NV1: `decide_node` returns `node_spec`: the first arm whose
//! condition holds.
//!
//! THEOREMS about the table, for every plan, baseline and frame:
//!   NV2  a frame to the proxy's address is never admitted: the node has no
//!        lane;
//!   NV3  a frame to 169.254.0.0/16 or 127.0.0.0/8 is never admitted;
//!   NV4  a frame to the gateway is admitted only as TCP or UDP to port 53;
//!   NV5  a frame to the host alias is admitted only when the alias is open
//!        to the node for this frame;
//!   NV6  a frame to a private address other than the alias is admitted only
//!        when the baseline's subnets cover it;
//!   NV7  anything else is admitted only to an address `dst_is_row` marks as
//!        a registered row's (the gate computes it from its rows:
//!        `gate::dst_is_row`) other than the node's own, to the resolver, or
//!        to a baseline subnet.
//!
//! THEOREM NJ1: `judge_node` returns the first of: a reply on a live inbound
//! flow, the refusal of a noted connect, the stateless arm, and, for
//! [`NodeArm::Unpinned`] only, a DNS admission, which is tried only for TCP
//! to port 443 and only through the DNS tables it is handed, whose owner must
//! be the frame's source; that they are the node's own is GE1's.
//!
//! THEOREM NJ3: a DNS admission lifts a frame of the node only when the arm
//! is `Unpinned` and the frame is TCP to port 443 ([`fetch_shaped`], which
//! [`is_fetch_shaped`] returns).
//!
//! THEOREM NJ2, for a frame without ports (a fragment that is not the first,
//! or a protocol that has none): it is never a reply or a refusal, never to
//! the resolver and never lifted by a DNS admission; to the gateway and to
//! the proxy's address it is refused; to the host alias it is refused unless
//! the alias is open, which [`crate::alias`] never says of a frame without
//! ports (AO2); no table changes. What still admits it reads the address
//! only: a registered row's address, a baseline subnet.
//!
//! Two things differ from a row's decision: the proxy's address is tested
//! before the infrastructure arms here and after them for a row;
//! and a registered row's address is open to the node on every protocol and
//! port.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::flow::{Conversation, TCP};
use crate::judge::{BoxTables, Sent, SentKind};
#[cfg(verus_keep_ghost)]
use crate::judge::{
    dest_of_sent, flows_missed, lemma_refused_reply_missed, notes_same, owners_same, pin_ok,
    pins_same, proto_of, refusal_ok, reply_ok, tinv,
};
use crate::notes::Segment;
#[cfg(verus_keep_ghost)]
use crate::pins::owner_of;
use crate::pins::{Egress, Transport};
use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_contains, spec_gateway, spec_host_alias, spec_node, spec_proxy_peer, wf};
use crate::row::{Cidr, DNS_PORT, Dest, PROTO_TCP, PROTO_UDP, any_covers};
#[cfg(verus_keep_ghost)]
use crate::row::{covers, dns_at, in_fixed, in_plane, in_private};
use crate::time::Instant;

/// The one port a DNS admission opens for the node: TLS.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const NODE_FETCH_PORT: u16 = 443;

/// The arms of the node's decision, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum NodeArm {
    /// Admit: ARP from the node's own address.
    Arp,
    /// Drop: the gateway, at anything but TCP or UDP port 53.
    ControlSurface,
    /// Drop: the proxy's address.
    ProxyRefuse,
    /// Drop: 169.254.0.0/16 or 127.0.0.0/8.
    InfraFixed,
    /// Drop: the host alias, not open to the node for this frame.
    AliasClosed,
    /// Drop: 100.64.0.0/10 outside the switch's own block.
    InfraPlane,
    /// Drop: a private address the baseline does not cover.
    InfraPrivate,
    /// Admit: the host alias, open.
    AliasOpen,
    /// Admit: a registered row's address, not the node's own.
    Sibling,
    /// Admit: UDP to the resolver at port 53.
    Resolver,
    /// Admit: a baseline subnet covers the destination.
    Baseline,
    /// Drop, unless a DNS admission lifts it: nothing above applied.
    Unpinned,
}

/// How a frame from the node was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum NodeJudged {
    /// Admit: a reply on a live inbound flow.
    ReplyFlow,
    /// Admit: the refusal of a noted connect.
    Refusal,
    /// The stateless arm decided, and nothing lifted it.
    Node(NodeArm),
    /// Admit: a DNS admission lifted `Unpinned`.
    Pinned(Egress),
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn node_admits(arm: NodeArm) -> bool {
    arm == NodeArm::Arp || arm == NodeArm::AliasOpen || arm == NodeArm::Sibling
        || arm == NodeArm::Resolver || arm == NodeArm::Baseline
}

/// The result admits the frame.
pub open spec fn node_judged_ok(j: NodeJudged) -> bool {
    match j {
        NodeJudged::ReplyFlow => true,
        NodeJudged::Refusal => true,
        NodeJudged::Node(arm) => node_admits(arm),
        NodeJudged::Pinned(e) => e != Egress::Refused,
    }
}

/// The decision table. `dst_is_row` says some registered row holds the
/// destination address.
pub open spec fn node_spec(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, d: Dest) -> NodeArm {
    match d {
        Dest::Arp => NodeArm::Arp,
        Dest::V4 { dst, proto, port } => {
            let gateway = dst as int == spec_gateway(plan);
            let alias = dst as int == spec_host_alias(plan);
            if gateway && !dns_at(proto, port) {
                NodeArm::ControlSurface
            } else if dst as int == spec_proxy_peer(plan) {
                NodeArm::ProxyRefuse
            } else if in_fixed(dst) {
                NodeArm::InfraFixed
            } else if alias && !alias_open {
                NodeArm::AliasClosed
            } else if !alias && in_plane(dst) && !spec_contains(plan, dst as int) {
                NodeArm::InfraPlane
            } else if !alias && in_private(dst) && !covers(baseline, dst) {
                NodeArm::InfraPrivate
            } else if alias {
                NodeArm::AliasOpen
            } else if dst as int != spec_node(plan) && dst_is_row {
                NodeArm::Sibling
            } else if proto == PROTO_UDP && gateway && port == DNS_PORT {
                NodeArm::Resolver
            } else if covers(baseline, dst) {
                NodeArm::Baseline
            } else {
                NodeArm::Unpinned
            }
        },
    }
}

/// NV2.
pub proof fn theorem_nv2(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_proxy_peer(plan),
    ensures
        !node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
{
}

/// NV3.
pub proof fn theorem_nv3(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        in_fixed(dst),
    ensures
        !node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
{
}

/// NV4.
pub proof fn theorem_nv4(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
    ensures
        dns_at(proto, port),
{
}

/// NV4, the other half: a frame to the gateway that is not DNS is refused by
/// the control surface and by no other arm.
pub proof fn theorem_nv4_named(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_gateway(plan),
        !dns_at(proto, port),
    ensures
        node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port }) == NodeArm::ControlSurface,
{
}

/// NV5.
pub proof fn theorem_nv5(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int == spec_host_alias(plan),
        node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
    ensures
        alias_open,
{
}

/// NV6.
pub proof fn theorem_nv6(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        in_private(dst),
        dst as int != spec_host_alias(plan),
        node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
    ensures
        covers(baseline, dst),
{
}

/// NV7.
pub proof fn theorem_nv7(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, dst: u32, proto: u8, port: u16)
    requires
        dst as int != spec_host_alias(plan),
        node_admits(node_spec(plan, baseline, alias_open, dst_is_row, Dest::V4 { dst, proto, port })),
    ensures
        (dst_is_row && dst as int != spec_node(plan))
            || (proto == PROTO_UDP && dst as int == spec_gateway(plan) && port == DNS_PORT)
            || covers(baseline, dst),
{
}

/// The frame has the shape the node's DNS admission is for: TCP to port 443.
pub open spec fn fetch_shaped(s: Sent) -> bool {
    &&& proto_of(s) == PROTO_TCP
    &&& match dest_of_sent(s) {
        Dest::V4 { dst, proto, port } => port == NODE_FETCH_PORT,
        Dest::Arp => false,
    }
}

/// The node's DNS admission applies: TCP to port 443, through the node's own
/// tables, with a live flow or a live window.
pub open spec fn node_pin_lift(t: BoxTables, s: Sent, now_ms: u64) -> bool {
    &&& proto_of(s) == PROTO_TCP
    &&& match dest_of_sent(s) {
        Dest::V4 { dst, proto, port } => port == NODE_FETCH_PORT,
        Dest::Arp => false,
    }
    &&& owner_of(t.pins) == s.src
    &&& pin_ok(t.pins, s, now_ms)
}

/// What `judge_node` promises of its result and of the tables before and after.
pub open spec fn node_post(plan: Plan, baseline: Seq<Cidr>, alias_open: bool, dst_is_row: bool, before: BoxTables, after: BoxTables, sent: Sent, now_ms: u64, r: NodeJudged) -> bool {
    match r {
        NodeJudged::ReplyFlow => {
            &&& reply_ok(plan, before.flows, sent, now_ms)
            &&& crate::flow::reply_post(before.flows, after.flows, crate::judge::conv_of(sent), crate::judge::flags_of(sent), now_ms, true)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        NodeJudged::Refusal => {
            &&& !reply_ok(plan, before.flows, sent, now_ms)
            &&& refusal_ok(plan, before.notes, sent, now_ms)
            &&& crate::notes::refusal_post(before.notes, after.notes, crate::judge::seg_of(sent), now_ms, true)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& pins_same(after.pins, before.pins)
        },
        NodeJudged::Node(arm) => {
            &&& !reply_ok(plan, before.flows, sent, now_ms)
            &&& !refusal_ok(plan, before.notes, sent, now_ms)
            &&& arm == node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent))
            &&& arm == NodeArm::Unpinned ==> !node_pin_lift(before, sent, now_ms)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        NodeJudged::Pinned(e) => {
            &&& !reply_ok(plan, before.flows, sent, now_ms)
            &&& !refusal_ok(plan, before.notes, sent, now_ms)
            &&& node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent)) == NodeArm::Unpinned
            &&& node_pin_lift(before, sent, now_ms)
            &&& e != Egress::Refused
            &&& crate::pins::egress_post(before.pins, after.pins, crate::judge::dst_of(sent), crate::judge::transport_of(sent), now_ms, e)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
        },
    }
}

/// NJ3.
pub proof fn theorem_nj3_the_node_lift_is_for_fetches(
    plan: Plan,
    baseline: Seq<Cidr>,
    alias_open: bool,
    dst_is_row: bool,
    before: BoxTables,
    after: BoxTables,
    sent: Sent,
    now_ms: u64,
    r: NodeJudged,
)
    requires
        node_post(plan, baseline, alias_open, dst_is_row, before, after, sent, now_ms, r),
        r is Pinned,
    ensures
        fetch_shaped(sent),
        node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent)) == NodeArm::Unpinned,
{
}

/// NJ2.
pub proof fn theorem_nj2_no_port_opening_admits_a_frame_without_ports(
    plan: Plan,
    baseline: Seq<Cidr>,
    alias_open: bool,
    dst_is_row: bool,
    before: BoxTables,
    after: BoxTables,
    sent: Sent,
    now_ms: u64,
    r: NodeJudged,
)
    requires
        crate::judge::portless(sent),
        node_post(plan, baseline, alias_open, dst_is_row, before, after, sent, now_ms, r),
    ensures
        r != NodeJudged::ReplyFlow,
        r != NodeJudged::Refusal,
        r != NodeJudged::Node(NodeArm::Resolver),
        !(r is Pinned),
        crate::judge::dst_of(sent) as int == spec_gateway(plan) ==> !node_judged_ok(r),
        crate::judge::dst_of(sent) as int == spec_proxy_peer(plan) ==> !node_judged_ok(r),
        crate::judge::dst_of(sent) as int == spec_host_alias(plan) && !alias_open ==> !node_judged_ok(r),
        crate::flow::table(after.flows) == crate::flow::table(before.flows),
        notes_same(after.notes, before.notes),
        pins_same(after.pins, before.pins),
{
}

} // verus!

/// Whether the frame has the shape the node's DNS admission is for. A caller
/// that still holds the node's tables itself asks this before it lets a DNS
/// admission lift `NodeArm::Unpinned`, and holds no port number. NJ3.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == fetch_shaped(*sent),
))]
pub fn is_fetch_shaped(sent: &Sent) -> bool {
    match sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { proto, l4, .. } => match l4 {
            Some(x) => proto == PROTO_TCP && x.dport == NODE_FETCH_PORT,
            None => false,
        },
    }
}

/// The arm that decides a frame from the node. NV1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
    ensures
        r == node_spec(*plan, baseline@, alias_open, dst_is_row, d),
))]
pub fn decide_node(
    plan: &Plan,
    baseline: &[Cidr],
    alias_open: bool,
    dst_is_row: bool,
    d: Dest,
) -> NodeArm {
    let (dst, proto, port) = match d {
        Dest::Arp => return NodeArm::Arp,
        Dest::V4 { dst, proto, port } => (dst, proto, port),
    };
    let gateway = dst == plan.gateway();
    let alias = dst == plan.host_alias();
    let dns = (proto == PROTO_TCP || proto == PROTO_UDP) && port == DNS_PORT;
    if gateway && !dns {
        return NodeArm::ControlSurface;
    }
    if dst == plan.proxy_peer() {
        return NodeArm::ProxyRefuse;
    }
    if dst >> 16 == 0xa9feu32 || dst >> 24 == 127u32 {
        return NodeArm::InfraFixed;
    }
    if alias && !alias_open {
        return NodeArm::AliasClosed;
    }
    if !alias && dst >> 22 == 0x191u32 && !plan.contains(dst) {
        return NodeArm::InfraPlane;
    }
    let private = dst >> 24 == 10u32 || dst >> 20 == 0xac1u32 || dst >> 16 == 0xc0a8u32;
    let covered = any_covers(baseline, dst);
    if !alias && private && !covered {
        return NodeArm::InfraPrivate;
    }
    if alias {
        return NodeArm::AliasOpen;
    }
    if dst != plan.node() && dst_is_row {
        return NodeArm::Sibling;
    }
    if proto == PROTO_UDP && gateway && port == DNS_PORT {
        return NodeArm::Resolver;
    }
    if covered {
        return NodeArm::Baseline;
    }
    NodeArm::Unpinned
}

/// Decides a frame from the node. `t` must be the node's own tables. NJ1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        node_post(*plan, baseline@, alias_open, dst_is_row, *old(t), *final(t), sent, now.ms, r),
))]
pub fn judge_node(
    plan: &Plan,
    baseline: &[Cidr],
    alias_open: bool,
    dst_is_row: bool,
    t: &mut BoxTables,
    sent: Sent,
    now: Instant,
) -> NodeJudged {
    let (dst, proto, l4) = match sent.kind {
        SentKind::Arp => {
            return NodeJudged::Node(decide_node(
                plan,
                baseline,
                alias_open,
                dst_is_row,
                Dest::Arp,
            ));
        }
        SentKind::V4 { dst, proto, l4 } => (dst, proto, l4),
    };
    if let Some(x) = l4 {
        if dst != plan.proxy_peer() {
            let c = Conversation {
                proto,
                client: dst,
                client_port: x.dport,
                box_addr: sent.src,
                box_port: x.sport,
            };
            if t.flows.reply(c, x.flags, now) {
                #[cfg(verus_keep_ghost)]
                proof! {
                    crate::judge::lemma_reply_answers(
                        *plan, old(t).flows, t.flows, sent, now.ms, true,
                    );
                }
                return NodeJudged::ReplyFlow;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_refused_reply_missed(*plan, old(t).flows, t.flows, sent, now.ms);
                crate::judge::lemma_reply_answers(
                    *plan, old(t).flows, t.flows, sent, now.ms, false,
                );
            }
            if proto == TCP {
                let s = Segment {
                    client: dst,
                    client_port: x.dport,
                    box_addr: sent.src,
                    box_port: x.sport,
                    flags: x.flags,
                    seq: x.seq,
                    ack: x.ack,
                    payload_len: x.payload_len,
                };
                if t.notes.refusal(s, now) {
                    return NodeJudged::Refusal;
                }
            }
        }
    }
    let port = match l4 {
        Some(x) => x.dport,
        None => 0,
    };
    let arm = decide_node(
        plan,
        baseline,
        alias_open,
        dst_is_row,
        Dest::V4 { dst, proto, port },
    );
    match arm {
        NodeArm::Unpinned => {}
        _ => return NodeJudged::Node(arm),
    }
    if proto == PROTO_TCP && port == NODE_FETCH_PORT && t.pins.owner() == sent.src {
        let transport = match l4 {
            Some(x) => Some(Transport {
                proto,
                sport: x.sport,
                dport: x.dport,
                flags: x.flags,
            }),
            None => None,
        };
        let e = t.pins.egress(dst, transport, now);
        match e {
            Egress::Refused => {}
            _ => return NodeJudged::Pinned(e),
        }
    }
    NodeJudged::Node(arm)
}

/// Whether a result admits the frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == node_judged_ok(j),
))]
pub fn node_judged_admits(j: NodeJudged) -> bool {
    match j {
        NodeJudged::ReplyFlow => true,
        NodeJudged::Refusal => true,
        NodeJudged::Node(arm) => match arm {
            NodeArm::Arp => true,
            NodeArm::ControlSurface => false,
            NodeArm::ProxyRefuse => false,
            NodeArm::InfraFixed => false,
            NodeArm::AliasClosed => false,
            NodeArm::InfraPlane => false,
            NodeArm::InfraPrivate => false,
            NodeArm::AliasOpen => true,
            NodeArm::Sibling => true,
            NodeArm::Resolver => true,
            NodeArm::Baseline => true,
            NodeArm::Unpinned => false,
        },
        NodeJudged::Pinned(e) => match e {
            Egress::Refused => false,
            Egress::ByFlow => true,
            Egress::Retained => true,
            Egress::Window => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{ACK, Flows, Inbound, SYN, Windows};
    use crate::judge::SentL4;
    use crate::notes::Notes;
    use crate::pins::{Admitted, Asked, Limits, Pins};
    use crate::time::Span;

    // 100.64.0.0/24: gateway .1, proxy .252, node .253, host alias .254.
    const NET: u32 = 0x6440_0000;
    const GW: u32 = NET + 1;
    const PROXY: u32 = NET + 252;
    const NODE: u32 = NET + 253;
    const ALIAS: u32 = NET + 254;
    const REGISTRY: u32 = 0xcb00_7107;

    fn plan() -> Plan {
        Plan::new(NET, 24).unwrap()
    }

    fn baseline() -> Vec<Cidr> {
        vec![Cidr {
            addr: 0xc633_6400,
            prefix: 24,
        }]
    }

    fn v4(dst: u32, proto: u8, port: u16) -> Dest {
        Dest::V4 { dst, proto, port }
    }

    fn tables() -> BoxTables {
        let windows = Windows {
            tcp_idle_ms: 300_000,
            tcp_closing_ms: 120_000,
            tcp_closed_ms: 5_000,
            udp_unreplied_ms: 30_000,
            udp_replied_ms: 300_000,
            evict_after_ms: None,
        };
        let limits = Limits {
            asked_cap: 4,
            asked_per_name: 2,
            admitted_cap: 8,
            admitted_per_name: 2,
            flows_cap: 4,
            flows_per_destination: 2,
            query_ms: 30_000,
            window_ms: 300_000,
            idle_ms: 86_400_000,
        };
        BoxTables {
            flows: Flows::new(NODE, 4, windows, Span { ms: 1_000 }).unwrap(),
            notes: Notes::new(NODE, 4, 2, Span { ms: 5_000 }).unwrap(),
            pins: Pins::new(NODE, limits).unwrap(),
        }
    }

    #[test]
    fn the_node_has_no_lane() {
        let (p, b) = (plan(), baseline());
        assert_eq!(
            decide_node(&p, &b, true, true, v4(PROXY, 6, 8118)),
            NodeArm::ProxyRefuse
        );
    }

    #[test]
    fn the_gateway_answers_dns_and_the_resolver_is_udp() {
        let (p, b) = (plan(), baseline());
        assert_eq!(
            decide_node(&p, &b, false, false, v4(GW, 17, 53)),
            NodeArm::Resolver
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(GW, 6, 53)),
            NodeArm::Unpinned
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(GW, 6, 80)),
            NodeArm::ControlSurface
        );
    }

    #[test]
    fn a_registered_row_is_open_on_any_port_and_the_node_itself_is_not_a_sibling() {
        let (p, b) = (plan(), baseline());
        assert_eq!(
            decide_node(&p, &b, false, true, v4(NET + 7, 1, 0)),
            NodeArm::Sibling
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(NET + 7, 6, 80)),
            NodeArm::Unpinned
        );
        assert_eq!(
            decide_node(&p, &b, false, true, v4(NODE, 6, 80)),
            NodeArm::Unpinned
        );
    }

    #[test]
    fn the_alias_is_decided_by_its_opening_and_then_admitted_outright() {
        let (p, b) = (plan(), baseline());
        assert_eq!(
            decide_node(&p, &b, false, false, v4(ALIAS, 6, 443)),
            NodeArm::AliasClosed
        );
        assert_eq!(
            decide_node(&p, &b, true, false, v4(ALIAS, 6, 443)),
            NodeArm::AliasOpen
        );
    }

    #[test]
    fn the_baseline_decides_everything_else() {
        let (p, b) = (plan(), baseline());
        assert_eq!(
            decide_node(&p, &b, false, false, v4(0xc633_6407, 6, 22)),
            NodeArm::Baseline
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(REGISTRY, 6, 443)),
            NodeArm::Unpinned
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(0x0a00_0001, 6, 443)),
            NodeArm::InfraPrivate
        );
        assert_eq!(
            decide_node(&p, &b, false, false, v4(0xa9fe_a9fe, 6, 80)),
            NodeArm::InfraFixed
        );
        assert_eq!(decide_node(&p, &b, false, false, Dest::Arp), NodeArm::Arp);
    }

    #[test]
    fn a_frame_on_an_expired_record_meets_the_node_arm_and_removes_the_record() {
        let (p, b, mut t) = (plan(), baseline(), tables());
        let opening = Conversation {
            proto: TCP,
            client: GW,
            client_port: 40000,
            box_addr: NODE,
            box_port: 8080,
        };
        assert_eq!(
            t.flows.inbound(opening, SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        let answer = Sent {
            src: NODE,
            kind: SentKind::V4 {
                dst: GW,
                proto: TCP,
                l4: Some(SentL4 {
                    sport: 8080,
                    dport: 40000,
                    flags: ACK,
                    seq: 0,
                    ack: 1,
                    payload_len: 0,
                }),
            },
        };
        assert_eq!(
            judge_node(
                &p,
                &b,
                false,
                false,
                &mut t,
                answer,
                Instant { ms: 300_000 }
            ),
            NodeJudged::Node(NodeArm::ControlSurface)
        );
        assert_eq!(t.flows.len(), 0);
    }

    #[test]
    fn a_dns_admission_lifts_only_tcp_to_port_443() {
        let (p, b, mut t) = (plan(), baseline(), tables());
        assert_eq!(t.pins.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let token = t.pins.answer(0, 7, 5000, 0).unwrap();
        assert_eq!(t.pins.admit(&token, REGISTRY), Admitted::New);
        let frame = |proto: u8, dport: u16| Sent {
            src: NODE,
            kind: SentKind::V4 {
                dst: REGISTRY,
                proto,
                l4: Some(SentL4 {
                    sport: 50000,
                    dport,
                    flags: SYN,
                    seq: 0,
                    ack: 0,
                    payload_len: 0,
                }),
            },
        };
        assert_eq!(
            judge_node(
                &p,
                &b,
                false,
                false,
                &mut t,
                frame(6, 443),
                Instant { ms: 1 }
            ),
            NodeJudged::Pinned(Egress::Retained)
        );
        assert_eq!(
            judge_node(
                &p,
                &b,
                false,
                false,
                &mut t,
                frame(6, 80),
                Instant { ms: 1 }
            ),
            NodeJudged::Node(NodeArm::Unpinned)
        );
        assert_eq!(
            judge_node(
                &p,
                &b,
                false,
                false,
                &mut t,
                frame(17, 443),
                Instant { ms: 1 }
            ),
            NodeJudged::Node(NodeArm::Unpinned)
        );
    }
}
