//! Deciding a frame without holding the whole gate.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! [`crate::gate::Gate`] owns every box's tables, so a caller that uses it
//! holds one lock for every box. This module is the part of a frame's
//! decision that reads the configuration and writes nothing: which box the
//! frame belongs to, and what its judge needs besides that box's tables. A
//! caller keeps the configuration and each box's tables under its own locks,
//! calls [`Config::egress_for`] or [`Config::ingress_for`] with the
//! configuration shared, and then calls the judge the result names
//! ([`crate::judge::judge_row`], [`crate::node::judge_node`],
//! [`crate::cohort::judge_cohort`], [`crate::ingress::observe`]) with that
//! one box's tables.
//!
//! THEOREM SP1, for every configuration, gate and frame: when the
//! configuration is the gate's ([`is_config_of`]),
//!   (a) `egress_for` and `ingress_for` change nothing, and name the route,
//!       the lifts, the alias state and the row that GE1 and GI1 say
//!       `Gate::egress` and `Gate::ingress` decide with;
//!   (b) not stated as a theorem, and shown by example in two of the gate's
//!       unit checks: the judge they name, run on that gate's tables for
//!       that box, is the judge `Gate::egress` runs, and for a frame toward
//!       a guest the one `Gate::ingress` runs when the caller passes
//!       `observe` the `published` that the gate's ledger gives
//!       (`Ledger::dials` at the frame's destination and port, L1;
//!       `gate::port_published`).
//!
//! [`Config::egress_first`] and [`Config::ingress_first`] take the frame's
//! bytes and do the whole of that part in one call: read the frame, refuse
//! what is no frame or has a short transport header, route it, and for a
//! frame a guest sent give the arm its rules give. A caller that uses them
//! reads no byte of the frame to decide and orders no step itself.
//!
//! THEOREM EP1, for every configuration and byte string: `egress_first`
//! returns what [`crate::frame::parse_frame`], [`crate::route::frame_of`],
//! `egress_for` and the decision table of the routed source give, in that
//! order ([`first_of`]); `ingress_first` what `parse_frame`,
//! [`crate::ingress::received_of`] and `ingress_for` give. The facts are
//! ones the reader may report of those bytes ([`read_of`]): a datagram is
//! not answered as "no frame".
//!
//! THEOREM EP3: a row that declares no subnet and no DNS host is given the
//! resolver's arm only for a whole query that asks only about names in the
//! zone ([`crate::dnsq`], DQ2), and so is a cohort none of whose members
//! declares either. The node is not narrowed, and nothing but a UDP datagram
//! to the resolver at port 53 is: TCP to the resolver, a fragment and every
//! other destination are decided by the tables as for any row. That a
//! zone-only query is not handed on by the resolver, whatever its type, is
//! registry row NC39 (probed on the pinned switch), not a theorem.
//!
//! THEOREM EP2, for a row, the node and the cohort: whatever the judge
//! returns for the frame, a stateless result is the arm of the routed
//! source's decision table, which is the arm `egress_first` gave unless that
//! was `RowDns` or `CohortDns`; and the judge admits only as a reply, as a
//! refusal, by an arm that admits, or by a lift of the one arm a lift may
//! turn (an undeclared subnet for a row, `Unpinned` for the node, `NeedsPin`
//! for the cohort). So a caller that still holds a box's tables itself may
//! admit a frame the arm drops only in those ways.
//!
//! The judges and [`crate::gate::Gate::egress`] do not know the zone rule:
//! they take a frame, not its bytes, and for a frame `egress_first` gave
//! `RowDns` or `CohortDns` they answer the resolver's arm or a member's
//! admit. A caller acts on `RowDns` and `CohortDns` as drops and does not
//! ask a judge about that frame. Nothing here makes it.
//!
//! The configuration changes only through its own operations
//! ([`Config::register`], [`Config::retire_at`], [`Config::restate_at`],
//! [`Config::rename_at`], [`Config::set_members`], [`Config::set_alias`],
//! [`Config::adopt_baseline`]), so a caller keeps it in step with its
//! registry by calling the one that matches each change, and builds no part
//! of it by hand.
//!
//! THEOREM CF1, for every configuration and every operation: a sound
//! configuration stays sound (one declaration a registered row, in row
//! order), and the operation changes what its contract names and nothing
//! else: `register` adds a row after every row there is, or changes nothing;
//! `retire_at` removes the row at an address and its declaration together,
//! moving later rows down by one; `restate_at` replaces a row's declaration
//! in place, so no other row's index moves; `rename_at` changes one name.
//!
//! A routed row is named by its index at the moment of the call. The
//! address it holds is the frame's source address (RT1), which no later
//! operation changes for that frame: a caller that keeps a box's tables
//! under a lock of its own finds them by that address, not by the index.
//!
//! What it does not say: that the configuration is still the gate's when the
//! judge runs (a row retired and its address registered again in between),
//! that the tables handed to the judge are the named box's, that the
//! `published` passed to `observe` is the ledger's (the configuration holds
//! no ledger), or anything
//! about two frames decided at once. Those are the caller's (registry rows
//! NC20 to NC24).

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::alias::alias_spec;
use crate::alias::{AliasSource, AliasState, alias_open};
use crate::cohort::{CohortArm, Member, decide_cohort};
#[cfg(verus_keep_ghost)]
use crate::cohort::{CohortJudged, cohort_judged_ok, cohort_post, cohort_spec};
#[cfg(verus_keep_ghost)]
use crate::dnsq::spec_zone_query;
use crate::dnsq::zone_query;
#[cfg(verus_keep_ghost)]
use crate::frame::facts_sound;
use crate::frame::{Facts, L4, Reason, parse_frame};
use crate::gate::Stray;
#[cfg(verus_keep_ghost)]
use crate::gate::{
    Gate, alias_for, alias_of, baseline_of, box_name_spec, dst_is_row, ginv, lemma_target_is,
    lifts_of, listed, members_of, pair_of, row_asks, rows_view, sources_of, target_of, to_cohort,
    to_node,
};
use crate::ingress::Received;
#[cfg(verus_keep_ghost)]
use crate::ingress::received_spec;
use crate::ingress::{Heard, received_of};
use crate::judge::{BoxNameRule, Lifts, SentKind, sent_dst};
#[cfg(verus_keep_ghost)]
use crate::judge::{box_rule, dest_of_sent, dst_of, lemma_box_rule_own};
use crate::node::{NodeArm, decide_node};
#[cfg(verus_keep_ghost)]
use crate::node::{NodeJudged, node_admits, node_judged_ok, node_post, node_spec};
use crate::origin::{CohortSpelling, Sources};
#[cfg(verus_keep_ghost)]
use crate::origin::{
    allocatable, first_at, in_force_of, is_cohort, is_node, plan_of, registered, rows_of, sinv,
    spelling_of,
};
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_cohort, spec_host_alias, spec_node};
use crate::policy::Rules;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
#[cfg(verus_keep_ghost)]
use crate::route::frame_spec;
use crate::route::{Frame, Route, Said, frame_of, route};
#[cfg(verus_keep_ghost)]
use crate::route::{at_control_surface, stray, v4};
#[cfg(verus_keep_ghost)]
use crate::row::allow_covers;
use crate::row::{Cidr, Dest, RowArm, allowed_subnet, decide_row};
#[cfg(verus_keep_ghost)]
use crate::row::{admits, row_spec};

/// What a row declared: everything of a row but its tables.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct RowDecl {
    pub rules: Rules,
    pub resolves_names: bool,
    pub alias_by_name: bool,
    pub name_id: u32,
    pub task_row: bool,
    pub names_boxes: Vec<u32>,
}

/// Everything a frame's decision reads and never writes.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Config {
    pub sources: Sources,
    pub decls: Vec<RowDecl>,
    pub baseline: Vec<Cidr>,
    pub members: Vec<Member>,
    pub alias: AliasState,
}

/// What a frame a guest sent needs before its box's tables are touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct EgressFor {
    /// Which decision, and for `Route::Row` which row.
    pub route: Route,
    /// The lifts, for a row's frame.
    pub lifts: Lifts,
    /// Whether the alias is open to this source for this frame.
    pub alias_open: bool,
    /// For the node's frame: whether a registered row holds the destination.
    pub to_row: bool,
}

/// Whose tables a frame toward a guest belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum IngressFor {
    NotARow,
    Row(usize),
    Node,
    Cohort,
}

/// What the stateless part of the decision says of a frame a guest sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Arm {
    /// Drop: the source is no row, not the node and not the cohort.
    Refused(Stray),
    /// The row at this index, and the arm its rules give.
    Row(usize, RowArm),
    /// Drop: the row at this index declares no subnet and no DNS host, and
    /// what it sent the resolver is not a whole query for names in the zone.
    RowDns(usize),
    Node(NodeArm),
    Cohort(CohortArm),
    /// Drop: no member of the cohort declares a subnet or a DNS host, and
    /// what was sent the resolver is not a whole query for names in the zone.
    CohortDns,
}

/// What the bytes of a frame a guest sent come to before any table is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum First {
    /// Drop: neither an IPv4 datagram nor an ARP packet, and why.
    NotAFrame(Reason),
    /// Drop: TCP or UDP on a first fragment without a whole header.
    ShortHeader,
    /// A frame, the facts it was made from, what its judge needs besides the
    /// box's tables, and the arm.
    Frame {
        frame: Frame,
        facts: Facts,
        with: EgressFor,
        arm: Arm,
    },
}

#[cfg(verus_keep_ghost)]
verus! {

/// Rules that allow no subnet, declared by a box that names no DNS host:
/// nothing it could ask the resolver about lies outside the zone.
pub open spec fn names_nothing(r: crate::row::RowRules, resolves_names: bool) -> bool {
    r.allow_subnets is Some && r.allow_subnets->0@.len() == 0 && !resolves_names
}

/// No member of the cohort declares a subnet or a DNS host.
pub open spec fn none_names(ms: Seq<Member>) -> bool {
    forall|k: int| 0 <= k < ms.len() ==> names_nothing(rules_of((#[trigger] ms[k]).rules), ms[k].resolves_names)
}

/// A UDP datagram to the resolver at port 53.
pub open spec fn to_resolver(plan: crate::plan::Plan, d: Dest) -> bool {
    match d {
        Dest::Arp => false,
        Dest::V4 { dst, proto, port } => proto == crate::row::PROTO_UDP && port == crate::row::DNS_PORT
            && dst as int == crate::plan::spec_gateway(plan),
    }
}

/// The payload of a UDP datagram that is whole in this frame.
pub open spec fn whole_udp_payload(b: Seq<u8>, facts: Facts) -> Option<Seq<u8>> {
    match facts {
        Facts::V4(v) => match v.l4 {
            L4::Udp { sport, dport, payload_at, payload_len } => if !v.more_fragments
                && payload_at + payload_len <= b.len() {
                Some(b.subrange(payload_at as int, payload_at + payload_len))
            } else {
                None
            },
            _ => None,
        },
        _ => None,
    }
}

/// The frame carries a whole DNS query that asks only about names below the
/// apex (DQ2).
pub open spec fn zone_only(b: Seq<u8>, facts: Facts, apex: Seq<u8>) -> bool {
    match whole_udp_payload(b, facts) {
        Some(p) => spec_zone_query(p, apex),
        None => false,
    }
}

/// The arm of the routed source's decision table, with nothing read from
/// any table. `zone` says the frame is a whole query for zone names only; it
/// is read only at the resolver, for a row that names nothing and for a
/// cohort none of whose members does.
pub open spec fn arm_spec(c: Config, f: Frame, w: EgressFor, zone: bool) -> Arm {
    let plan = plan_of(c.sources);
    match w.route {
        Route::ControlSurface => Arm::Refused(Stray::ControlSurface),
        Route::Unregistered => Arm::Refused(Stray::Unregistered),
        Route::Unknown => Arm::Refused(Stray::Unknown),
        Route::Row(i) => {
            let rules = rules_of(c.decls@[i as int].rules);
            let a = row_spec(plan, rules, w.alias_open, dest_of_sent(f.sent));
            if a == RowArm::Resolver && names_nothing(rules, c.decls@[i as int].resolves_names) && !zone {
                Arm::RowDns(i)
            } else {
                Arm::Row(i, a)
            }
        },
        Route::Node => Arm::Node(node_spec(plan, c.baseline@, w.alias_open, w.to_row, dest_of_sent(f.sent))),
        Route::Cohort => {
            let a = cohort_spec(plan, c.members@, w.alias_open, dest_of_sent(f.sent));
            if a == CohortArm::Member && to_resolver(plan, dest_of_sent(f.sent)) && none_names(c.members@)
                && !zone {
                Arm::CohortDns
            } else {
                Arm::Cohort(a)
            }
        },
    }
}

/// EP3 for a row that declares no subnet and no DNS host: the resolver's
/// arm is given only for a whole query that asks only about names in the
/// zone.
pub proof fn theorem_ep3_a_row_that_names_nothing_asks_only_for_zone_names(
    c: Config,
    f: Frame,
    w: EgressFor,
    zone: bool,
    i: usize,
)
    requires
        w.route == Route::Row(i),
        names_nothing(rules_of(c.decls@[i as int].rules), c.decls@[i as int].resolves_names),
    ensures
        match arm_spec(c, f, w, zone) {
            Arm::Row(j, a) => j == i && (a == RowArm::Resolver ==> zone),
            Arm::RowDns(j) => j == i && !zone,
            Arm::Refused(_) => false,
            Arm::Node(_) => false,
            Arm::Cohort(_) => false,
            Arm::CohortDns => false,
        },
{
}

/// EP3 for a cohort none of whose members declares a subnet or a DNS host:
/// a datagram to the resolver is admitted by a member's rules only as a
/// whole query that asks only about names in the zone.
pub proof fn theorem_ep3_a_cohort_that_names_nothing_asks_only_for_zone_names(
    c: Config,
    f: Frame,
    w: EgressFor,
    zone: bool,
)
    requires
        w.route == Route::Cohort,
        none_names(c.members@),
    ensures
        match arm_spec(c, f, w, zone) {
            Arm::Cohort(a) => (a == CohortArm::Member && to_resolver(plan_of(c.sources), dest_of_sent(f.sent)))
                ==> zone,
            Arm::CohortDns => !zone,
            Arm::Refused(_) => false,
            Arm::Row(_, _) => false,
            Arm::RowDns(_) => false,
            Arm::Node(_) => false,
        },
{
}

/// The facts are ones the reader may report of these bytes (P2, and that a
/// datagram is reported as one and an ARP packet as one): "no frame" is not
/// an answer for a frame.
pub open spec fn read_of(b: Seq<u8>, facts: Facts) -> bool {
    &&& facts_sound(b, facts)
    &&& crate::frame::is_v4_datagram(b) ==> crate::frame::is_v4(facts)
    &&& crate::frame::is_arp_packet(b) ==> crate::frame::is_arp(facts)
}

/// EP1 for a frame a guest sent: `r` is what these bytes and facts come to
/// under `c`, with the zone's apex `apex`.
pub open spec fn first_of(c: Config, b: Seq<u8>, facts: Facts, apex: Seq<u8>, r: First) -> bool {
    match r {
        First::NotAFrame(why) => facts == Facts::Other(why),
        First::ShortHeader => frame_spec(facts) == Said::ShortHeader,
        First::Frame { frame, facts: carried, with, arm } => {
            &&& carried == facts
            &&& frame_spec(facts) == Said::Frame(frame)
            &&& cinv(c) ==> egress_for_post(c, frame, with)
            &&& !cinv(c) ==> with == egress_unroutable()
            &&& arm == arm_spec(c, frame, with, zone_only(b, facts, apex))
        },
    }
}

/// EP1 for a frame toward a guest: only a whole transport header names a
/// box's tables.
pub open spec fn toward_of(c: Config, facts: Facts, carried: Facts, h: Heard, w: IngressFor) -> bool {
    &&& carried == facts
    &&& h == received_spec(facts)
    &&& match h {
        Heard::Transport(r) => ingress_for_post(c, r, w),
        _ => w == IngressFor::NotARow,
    }
}

/// EP2 for a row.
pub proof fn theorem_ep2_a_row_is_admitted_by_its_arm_or_a_named_way(
    plan: crate::plan::Plan,
    rules: crate::row::RowRules,
    lifts: Lifts,
    alias_open: bool,
    before: crate::judge::BoxTables,
    after: crate::judge::BoxTables,
    sent: crate::judge::Sent,
    now_ms: u64,
    r: crate::judge::Judged,
)
    requires
        crate::judge::row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, r),
    ensures
        ({
            let a = row_spec(plan, rules, alias_open, dest_of_sent(sent));
            &&& r matches crate::judge::Judged::Row(x) ==> x == a
            &&& crate::judge::judged_ok(r) ==> r is ReplyFlow || r is Refusal || admits(a)
                || a == RowArm::UndeclaredSubnet
        }),
{
}

/// EP2 for the node.
pub proof fn theorem_ep2_the_node_is_admitted_by_its_arm_or_a_named_way(
    plan: crate::plan::Plan,
    baseline: Seq<Cidr>,
    alias_open: bool,
    dst_is_row: bool,
    before: crate::judge::BoxTables,
    after: crate::judge::BoxTables,
    sent: crate::judge::Sent,
    now_ms: u64,
    r: NodeJudged,
)
    requires
        node_post(plan, baseline, alias_open, dst_is_row, before, after, sent, now_ms, r),
    ensures
        ({
            let a = node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent));
            &&& r matches NodeJudged::Node(x) ==> x == a
            &&& node_judged_ok(r) ==> r is ReplyFlow || r is Refusal || node_admits(a)
                || a == NodeArm::Unpinned
        }),
{
}

/// EP2 for the cohort.
pub proof fn theorem_ep2_the_cohort_is_admitted_by_its_arm_or_a_named_way(
    plan: crate::plan::Plan,
    members: Seq<Member>,
    alias_open: bool,
    node_before: crate::judge::BoxTables,
    node_after: crate::judge::BoxTables,
    pins_before: crate::pins::Pins,
    pins_after: crate::pins::Pins,
    sent: crate::judge::Sent,
    now_ms: u64,
    r: CohortJudged,
)
    requires
        cohort_post(plan, members, alias_open, node_before, node_after, pins_before, pins_after, sent, now_ms, r),
    ensures
        ({
            let a = cohort_spec(plan, members, alias_open, dest_of_sent(sent));
            &&& r matches CohortJudged::Cohort(x) ==> x == a
            &&& cohort_judged_ok(r) ==> r is ReplyFlow || r is Refusal
                || crate::cohort::cohort_admits(a) || a == CohortArm::NeedsPin
        }),
{
}

/// The configuration is sound: one declaration per registered row.
pub open spec fn cinv(c: Config) -> bool {
    sinv(c.sources) && c.decls@.len() == rows_of(c.sources).len()
}

/// What `egress_for` answers for a configuration that is not sound: the
/// frame is from no source a decision is held for.
pub open spec fn egress_unroutable() -> EgressFor {
    EgressFor {
        route: Route::Unknown,
        lifts: Lifts { resolves_names: false, alias_by_name: false, box_name: BoxNameRule::Silent, box_name_dst: 0 },
        alias_open: false,
        to_row: false,
    }
}

/// The declaration is the row's.
pub open spec fn is_decl_of(d: RowDecl, st: crate::gate::RowState) -> bool {
    &&& d.rules == st.rules
    &&& d.resolves_names == st.resolves_names
    &&& d.alias_by_name == st.alias_by_name
    &&& d.name_id == st.name_id
    &&& d.task_row == st.task_row
    &&& d.names_boxes@ == st.names_boxes@
}

/// Everything of a configuration but its rows and their declarations.
pub open spec fn rest_same(now: Config, before: Config) -> bool {
    &&& plan_of(now.sources) == plan_of(before.sources)
    &&& in_force_of(now.sources) == in_force_of(before.sources)
    &&& spelling_of(now.sources) == spelling_of(before.sources)
    &&& now.baseline@ == before.baseline@
    &&& now.members@ == before.members@
    &&& now.alias == before.alias
}

/// The rows and their declarations are as they were.
pub open spec fn rows_same(now: Config, before: Config) -> bool {
    rows_of(now.sources) == rows_of(before.sources) && now.decls@ == before.decls@
}

/// `now` is `before` with one field changed: the name.
pub open spec fn decl_renamed(now: RowDecl, before: RowDecl, name_id: u32) -> bool {
    &&& now.name_id == name_id
    &&& now.rules == before.rules
    &&& now.resolves_names == before.resolves_names
    &&& now.alias_by_name == before.alias_by_name
    &&& now.task_row == before.task_row
    &&& now.names_boxes == before.names_boxes
}

/// The configuration is the gate's.
pub open spec fn is_config_of(c: Config, g: Gate) -> bool {
    &&& c.sources == sources_of(g)
    &&& c.baseline@ == baseline_of(g)
    &&& c.members@ == members_of(g)
    &&& c.alias == alias_of(g)
    &&& c.decls@.len() == rows_view(g).len()
    &&& forall|i: int| 0 <= i < c.decls@.len() ==> is_decl_of(#[trigger] c.decls@[i], rows_view(g)[i])
}

/// What `route` promises of its result.
pub open spec fn routed(sources: Sources, f: Frame, r: Route) -> bool {
    match r {
        Route::Cohort => is_cohort(sources, f.sent.src, v4(f), f.dscp),
        Route::Node => is_node(sources, f.sent.src, v4(f), f.dscp),
        Route::Row(i) => {
            &&& !is_cohort(sources, f.sent.src, v4(f), f.dscp)
            &&& !is_node(sources, f.sent.src, v4(f), f.dscp)
            &&& i < rows_of(sources).len()
            &&& rows_of(sources)[i as int] == f.sent.src
            &&& first_at(rows_of(sources), f.sent.src, i as int)
        },
        Route::ControlSurface => {
            &&& stray(sources, f)
            &&& at_control_surface(plan_of(sources), dest_of_sent(f.sent))
        },
        Route::Unregistered => {
            &&& stray(sources, f)
            &&& !at_control_surface(plan_of(sources), dest_of_sent(f.sent))
            &&& allocatable(sources, f.sent.src)
        },
        Route::Unknown => {
            &&& stray(sources, f)
            &&& !at_control_surface(plan_of(sources), dest_of_sent(f.sent))
            &&& !allocatable(sources, f.sent.src)
        },
    }
}

/// The box-name rule for a frame from row `i`, read from the configuration.
pub open spec fn box_name_of(c: Config, i: int, f: Frame) -> BoxNameRule {
    let addrs = rows_of(c.sources);
    match f.sent.kind {
        SentKind::Arp => BoxNameRule::Silent,
        SentKind::V4 { dst, proto, l4 } => {
            if c.decls@[i].names_boxes@.len() == 0 {
                BoxNameRule::Silent
            } else if dst as int == spec_node(plan_of(c.sources)) {
                BoxNameRule::Silent
            } else if !registered(addrs, dst) {
                BoxNameRule::Silent
            } else if dst == f.sent.src {
                BoxNameRule::Silent
            } else if c.decls@[target_of(addrs, dst)].task_row {
                BoxNameRule::Refused
            } else if listed(c.decls@[i].names_boxes@, c.decls@[target_of(addrs, dst)].name_id) {
                BoxNameRule::Allowed
            } else {
                BoxNameRule::Refused
            }
        },
    }
}

pub open spec fn lifts_for(c: Config, i: int, f: Frame) -> Lifts {
    Lifts {
        resolves_names: c.decls@[i].resolves_names,
        alias_by_name: c.decls@[i].alias_by_name,
        box_name: box_name_of(c, i, f),
        box_name_dst: dst_of(f.sent),
    }
}

/// SP1, for the frame judged: the box-name rule `egress_for` returns is the
/// rule computed for that frame.
pub proof fn theorem_sp1_the_rule_is_this_frames(c: Config, i: int, f: Frame)
    ensures
        box_rule(lifts_for(c, i, f), f.sent) == box_name_of(c, i, f),
{
    lemma_box_rule_own(lifts_for(c, i, f), f.sent);
}

/// How row `i` asks for the alias.
pub open spec fn row_source(c: Config, i: int) -> AliasSource {
    AliasSource::Box {
        names_host: c.decls@[i].alias_by_name || allow_covers(
            rules_of(c.decls@[i].rules).allow_subnets,
            spec_host_alias(plan_of(c.sources)) as u32,
        ),
    }
}

/// Some registered row holds the frame's destination.
pub open spec fn dst_registered(c: Config, f: Frame) -> bool {
    match f.sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => registered(rows_of(c.sources), dst),
    }
}

/// What `egress_for` promises.
pub open spec fn egress_for_post(c: Config, f: Frame, r: EgressFor) -> bool {
    &&& routed(c.sources, f, r.route)
    &&& match r.route {
        Route::Row(i) => {
            &&& r.lifts == lifts_for(c, i as int, f)
            &&& r.alias_open == alias_spec(c.alias, row_source(c, i as int), pair_of(f))
        },
        Route::Node => {
            &&& r.alias_open == alias_spec(c.alias, AliasSource::Node, pair_of(f))
            &&& r.to_row == dst_registered(c, f)
        },
        Route::Cohort => r.alias_open == alias_spec(c.alias, AliasSource::Cohort, pair_of(f)),
        _ => true,
    }
}

/// What `ingress_for` promises: the tables `Gate::ingress` would write.
pub open spec fn ingress_for_post(c: Config, r: Received, w: IngressFor) -> bool {
    let s = c.sources;
    let at_node = in_force_of(s) && r.dst as int == spec_node(plan_of(s));
    let at_cohort = in_force_of(s) && spelling_of(s) == CohortSpelling::OwnAddress
        && r.dst as int == spec_cohort(plan_of(s));
    match w {
        IngressFor::Node => at_node,
        IngressFor::Cohort => !at_node && at_cohort,
        IngressFor::Row(i) => {
            &&& !at_node
            &&& !at_cohort
            &&& i < rows_of(s).len()
            &&& rows_of(s)[i as int] == r.dst
            &&& first_at(rows_of(s), r.dst, i as int)
        },
        IngressFor::NotARow => !at_node && !at_cohort && !registered(rows_of(s), r.dst),
    }
}

/// SP1 (a), for a frame a guest sent: what the configuration says of row `i`
/// and of this frame is what the gate says.
pub proof fn theorem_sp1_egress_reads_the_gates(c: Config, g: Gate, f: Frame, i: int, who: AliasSource, r: Route)
    requires
        is_config_of(c, g),
        ginv(g),
        0 <= i < rows_view(g).len(),
    ensures
        routed(c.sources, f, r) == routed(sources_of(g), f, r),
        box_name_of(c, i, f) == box_name_spec(g, i, f),
        lifts_for(c, i, f) == lifts_of(g, i, f),
        row_source(c, i) == row_asks(g, rows_view(g)[i]),
        alias_spec(c.alias, who, pair_of(f)) == alias_for(g, who, f),
        dst_registered(c, f) == dst_is_row(g, f),
        c.decls@[i].rules == rows_view(g)[i].rules,
        c.baseline@ == baseline_of(g),
        c.members@ == members_of(g),
{
    reveal(crate::gate::rows_bound);
    reveal(crate::gate::box_name_spec);
    assert(is_decl_of(c.decls@[i], rows_view(g)[i]));
    match f.sent.kind {
        SentKind::Arp => {},
        SentKind::V4 { dst, proto, l4 } => {
            let addrs = rows_of(c.sources);
            if registered(addrs, dst) {
                let t = target_of(addrs, dst);
                assert(is_decl_of(c.decls@[t], rows_view(g)[t]));
            }
        },
    }
}

/// SP1 (a), for a frame toward a guest: the tables the configuration names
/// are the ones `Gate::ingress` writes.
pub proof fn theorem_sp1_ingress_reads_the_gates(c: Config, g: Gate, r: Received, w: IngressFor)
    requires
        is_config_of(c, g),
        ginv(g),
        ingress_for_post(c, r, w),
    ensures
        match w {
            IngressFor::Node => to_node(g, r),
            IngressFor::Cohort => !to_node(g, r) && to_cohort(g, r),
            IngressFor::Row(i) => {
                &&& !to_node(g, r)
                &&& !to_cohort(g, r)
                &&& i < rows_view(g).len()
                &&& rows_of(sources_of(g))[i as int] == r.dst
                &&& first_at(rows_of(sources_of(g)), r.dst, i as int)
            },
            IngressFor::NotARow => !to_node(g, r) && !to_cohort(g, r) && !registered(rows_of(sources_of(g)), r.dst),
        },
{
    reveal(crate::gate::rows_bound);
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Config {
    /// What the box-name rule says of a frame from row `i`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            cinv(*self),
            i < self.decls@.len(),
        ensures
            r == box_name_of(*self, i as int, f),
    ))]
    fn box_name(&self, i: usize, f: Frame) -> BoxNameRule {
        let dst = match f.sent.kind {
            SentKind::Arp => return BoxNameRule::Silent,
            SentKind::V4 { dst, .. } => dst,
        };
        if self.decls[i].names_boxes.is_empty() {
            return BoxNameRule::Silent;
        }
        if dst == self.sources.plan().node() {
            return BoxNameRule::Silent;
        }
        let t = match self.sources.index_of(dst) {
            Some(t) => t,
            None => return BoxNameRule::Silent,
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_target_is(rows_of(self.sources), dst, t as int);
        }
        if dst == f.sent.src {
            return BoxNameRule::Silent;
        }
        if self.decls[t].task_row {
            return BoxNameRule::Refused;
        }
        let id = self.decls[t].name_id;
        let mut k: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i < self.decls@.len(),
                k <= self.decls@[i as int].names_boxes@.len(),
                forall|j: int| 0 <= j < k ==> self.decls@[i as int].names_boxes@[j] != id,
                // What was settled before the loop: only whether the name is listed is still open.
                box_name_of(*self, i as int, f) == (if listed(self.decls@[i as int].names_boxes@, id) {
                    BoxNameRule::Allowed
                } else {
                    BoxNameRule::Refused
                }),
            decreases self.decls@[i as int].names_boxes@.len() - k,
        ))]
        while k < self.decls[i].names_boxes.len() {
            if self.decls[i].names_boxes[k] == id {
                #[cfg(verus_keep_ghost)]
                proof! {
                    // This entry is the witness that the name is listed.
                    assert(self.decls@[i as int].names_boxes@[k as int] == id);
                }
                return BoxNameRule::Allowed;
            }
            k += 1;
        }
        BoxNameRule::Refused
    }

    /// Which decision a frame a guest sent gets, and what its judge needs
    /// besides the box's tables. Reads the configuration; writes nothing.
    /// A configuration without one declaration for each registered row
    /// routes nothing: every frame is from an unknown source. SP1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
        ensures
            cinv(*self) ==> egress_for_post(*self, f, r),
            !cinv(*self) ==> r == egress_unroutable(),
    ))]
    pub fn egress_for(&self, f: Frame) -> EgressFor {
        let plan = self.sources.plan();
        let pair = match f.sent.kind {
            SentKind::Arp => None,
            SentKind::V4 { proto, l4, .. } => match l4 {
                Some(x) => Some((proto, x.dport)),
                None => None,
            },
        };
        let quiet = Lifts {
            resolves_names: false,
            alias_by_name: false,
            box_name: BoxNameRule::Silent,
            box_name_dst: 0,
        };
        if self.decls.len() != self.sources.len() {
            return EgressFor {
                route: Route::Unknown,
                lifts: quiet,
                alias_open: false,
                to_row: false,
            };
        }
        let r = route(&self.sources, f);
        match r {
            Route::Row(i) => {
                let lifts = Lifts {
                    resolves_names: self.decls[i].resolves_names,
                    alias_by_name: self.decls[i].alias_by_name,
                    box_name: self.box_name(i, f),
                    box_name_dst: sent_dst(&f.sent),
                };
                let who = AliasSource::Box {
                    names_host: self.decls[i].alias_by_name
                        || allowed_subnet(self.decls[i].rules.get(), plan.host_alias()),
                };
                EgressFor {
                    route: r,
                    lifts,
                    alias_open: alias_open(&self.alias, who, pair),
                    to_row: false,
                }
            }
            Route::Node => {
                let to_row = match f.sent.kind {
                    SentKind::Arp => false,
                    SentKind::V4 { dst, .. } => self.sources.holds(dst),
                };
                EgressFor {
                    route: r,
                    lifts: quiet,
                    alias_open: alias_open(&self.alias, AliasSource::Node, pair),
                    to_row,
                }
            }
            Route::Cohort => EgressFor {
                route: r,
                lifts: quiet,
                alias_open: alias_open(&self.alias, AliasSource::Cohort, pair),
                to_row: false,
            },
            _ => EgressFor {
                route: r,
                lifts: quiet,
                alias_open: false,
                to_row: false,
            },
        }
    }

    /// Whose tables a frame toward a guest belongs to. Reads the
    /// configuration's sources and nothing else of it; writes nothing. SP1.
    #[cfg_attr(verus_keep_ghost, verus_spec(w =>
        requires
            sinv(self.sources),
        ensures
            ingress_for_post(*self, r, w),
    ))]
    pub fn ingress_for(&self, r: Received) -> IngressFor {
        let plan = self.sources.plan();
        if self.sources.node_in_force() && r.dst == plan.node() {
            return IngressFor::Node;
        }
        if self.sources.node_in_force() && r.dst == plan.cohort() {
            match self.sources.spelling() {
                CohortSpelling::NodeWithMark => {}
                CohortSpelling::OwnAddress => return IngressFor::Cohort,
            }
        }
        match self.sources.index_of(r.dst) {
            Some(i) => IngressFor::Row(i),
            None => IngressFor::NotARow,
        }
    }
}

/// What the stateless arms read of a frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == dest_of_sent(f.sent),
))]
fn dest(f: &Frame) -> Dest {
    match f.sent.kind {
        SentKind::Arp => Dest::Arp,
        SentKind::V4 { dst, proto, l4 } => Dest::V4 {
            dst,
            proto,
            port: match l4 {
                Some(x) => x.dport,
                None => 0,
            },
        },
    }
}

/// Whether the arm is the resolver's.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == (a == RowArm::Resolver),
))]
fn is_resolver(a: RowArm) -> bool {
    match a {
        RowArm::Resolver => true,
        RowArm::Arp => false,
        RowArm::ControlSurface => false,
        RowArm::InfraFixed => false,
        RowArm::AliasClosed => false,
        RowArm::InfraPlane => false,
        RowArm::InfraPrivate => false,
        RowArm::LaneAdmit => false,
        RowArm::LaneRefuse => false,
        RowArm::UndeclaredProtocol => false,
        RowArm::DeniedSubnet => false,
        RowArm::UndeclaredSubnet => false,
        RowArm::Rules => false,
    }
}

/// Whether the cohort's arm is a member's admit.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == (a == CohortArm::Member),
))]
fn is_member(a: CohortArm) -> bool {
    match a {
        CohortArm::Member => true,
        CohortArm::Arp => false,
        CohortArm::ControlSurface => false,
        CohortArm::NoMember => false,
        CohortArm::LaneAdmit => false,
        CohortArm::LaneRefuse => false,
        CohortArm::AliasClosed => false,
        CohortArm::NeedsPin => false,
        CohortArm::Infrastructure => false,
        CohortArm::Unbounded => false,
    }
}

/// Whether the destination is the resolver, as UDP at port 53.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires crate::plan::wf(*plan),
    ensures r == to_resolver(*plan, d),
))]
fn resolver_datagram(plan: &crate::plan::Plan, d: Dest) -> bool {
    match d {
        Dest::Arp => false,
        Dest::V4 { dst, proto, port } => {
            proto == crate::row::PROTO_UDP && port == crate::row::DNS_PORT && dst == plan.gateway()
        }
    }
}

/// Whether no member declares a subnet or a DNS host.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == none_names(members@),
))]
fn no_member_names(members: &[Member]) -> bool {
    let mut k: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            k <= members@.len(),
            forall|j: int| 0 <= j < k ==> names_nothing(rules_of((#[trigger] members@[j]).rules), members@[j].resolves_names),
        decreases members@.len() - k,
    ))]
    while k < members.len() {
        let names = match &members[k].rules.get().allow_subnets {
            Some(v) => !v.as_slice().is_empty() || members[k].resolves_names,
            None => true,
        };
        if names {
            return false;
        }
        k += 1;
    }
    true
}

/// Whether the frame carries a whole DNS query that asks only about names
/// below the apex. A fragment of a datagram is not a whole query.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == zone_only(b@, *facts, apex@),
))]
fn whole_zone_query(b: &[u8], facts: &Facts, apex: &[u8]) -> bool {
    match facts {
        Facts::V4(v) => {
            if v.more_fragments {
                return false;
            }
            match v.l4 {
                L4::Udp {
                    payload_at,
                    payload_len,
                    ..
                } => {
                    let at = payload_at as usize;
                    let end = at + payload_len as usize;
                    if end > b.len() {
                        return false;
                    }
                    zone_query(&b[at..end], apex)
                }
                L4::Tcp { .. } => false,
                L4::NoPorts => false,
                L4::LaterFragment => false,
                L4::ShortHeader => false,
            }
        }
        Facts::Arp { .. } => false,
        Facts::Other(_) => false,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Config {
    /// The whole of a decision that reads no table, for the bytes of a frame
    /// a guest sent: what the frame is, where it is routed, what its judge
    /// needs, and the arm its rules give. For a row that declares no subnet
    /// and no DNS host, and for a cohort none of whose members does, a
    /// datagram to the resolver passes only as a whole query for names below
    /// `apex` (the zone's name on the wire); an apex that is no name passes
    /// none. Reads the configuration; writes nothing. EP1, EP3.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
        ensures
            exists|facts: Facts| #[trigger] read_of(b@, facts) && first_of(*self, b@, facts, apex@, r),
    ))]
    pub fn egress_first(&self, b: &[u8], apex: &[u8]) -> First {
        let facts = parse_frame(b);
        #[cfg(verus_keep_ghost)]
        proof! {
            // The witness for the `exists`: the facts the reader returned.
            assert(read_of(b@, facts));
        }
        match facts {
            Facts::Other(why) => {
                return First::NotAFrame(why);
            }
            Facts::Arp { .. } => {}
            Facts::V4(_) => {}
        }
        let frame = match frame_of(&facts) {
            Said::Frame(f) => f,
            Said::ShortHeader => {
                return First::ShortHeader;
            }
            // Not reached: `frame_of` says this of `Facts::Other` alone.
            Said::NotAFrame => {
                return First::ShortHeader;
            }
        };
        let with = self.egress_for(frame);
        let plan = self.sources.plan();
        let d = dest(&frame);
        let arm = match with.route {
            Route::ControlSurface => Arm::Refused(Stray::ControlSurface),
            Route::Unregistered => Arm::Refused(Stray::Unregistered),
            Route::Unknown => Arm::Refused(Stray::Unknown),
            Route::Row(i) => {
                let rules = self.decls[i].rules.get();
                let a = decide_row(&plan, rules, with.alias_open, d);
                let nothing = match &rules.allow_subnets {
                    Some(v) => v.as_slice().is_empty() && !self.decls[i].resolves_names,
                    None => false,
                };
                if nothing && is_resolver(a) && !whole_zone_query(b, &facts, apex) {
                    Arm::RowDns(i)
                } else {
                    Arm::Row(i, a)
                }
            }
            Route::Node => Arm::Node(decide_node(
                &plan,
                self.baseline.as_slice(),
                with.alias_open,
                with.to_row,
                d,
            )),
            Route::Cohort => {
                let a = decide_cohort(&plan, self.members.as_slice(), with.alias_open, d);
                if is_member(a)
                    && resolver_datagram(&plan, d)
                    && no_member_names(self.members.as_slice())
                    && !whole_zone_query(b, &facts, apex)
                {
                    Arm::CohortDns
                } else {
                    Arm::Cohort(a)
                }
            }
        };
        First::Frame {
            frame,
            facts,
            with,
            arm,
        }
    }

    /// What the bytes of a frame toward a guest come to, and whose tables
    /// see it: a box's only for a whole transport header. Reads the
    /// configuration; writes nothing. EP1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
        ensures
            exists|facts: Facts| #[trigger] read_of(b@, facts) && toward_of(*self, facts, r.2, r.0, r.1),
    ))]
    pub fn ingress_first(&self, b: &[u8]) -> (Heard, IngressFor, Facts) {
        let facts = parse_frame(b);
        #[cfg(verus_keep_ghost)]
        proof! {
            // The witness for the `exists`: the facts the reader returned.
            assert(read_of(b@, facts));
        }
        let heard = received_of(&facts);
        let whose = match heard {
            Heard::Transport(r) => self.ingress_for(r),
            _ => IngressFor::NotARow,
        };
        (heard, whose, facts)
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Config {
    /// Adds a row at `addr` with this declaration, after every row there is.
    /// `false`, and nothing changes, when a row already holds `addr` or
    /// `addr` is not an address a row may hold. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            cinv(*old(self)),
        ensures
            cinv(*final(self)),
            rest_same(*final(self), *old(self)),
            r == (!registered(rows_of(old(self).sources), addr)
                && crate::origin::holdable(plan_of(old(self).sources), spelling_of(old(self).sources), addr)),
            r ==> rows_of(final(self).sources) == rows_of(old(self).sources).push(addr)
                && final(self).decls@ == old(self).decls@.push(d),
            !r ==> rows_same(*final(self), *old(self)),
    ))]
    pub fn register(&mut self, addr: u32, d: RowDecl) -> bool {
        if !self.sources.add(addr) {
            return false;
        }
        self.decls.push(d);
        true
    }

    /// Removes the row at `addr` and hands its declaration back. Later rows
    /// move down by one. `None`, and nothing changes, when no row holds
    /// `addr`. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            cinv(*old(self)),
        ensures
            cinv(*final(self)),
            rest_same(*final(self), *old(self)),
            match r {
                Some(d) => exists|i: int| {
                    &&& 0 <= i < old(self).decls@.len()
                    &&& #[trigger] rows_of(old(self).sources)[i] == addr
                    &&& d == old(self).decls@[i]
                    &&& rows_of(final(self).sources) == rows_of(old(self).sources).remove(i)
                    &&& final(self).decls@ == old(self).decls@.remove(i)
                },
                None => !registered(rows_of(old(self).sources), addr) && rows_same(*final(self), *old(self)),
            },
            !registered(rows_of(final(self).sources), addr),
    ))]
    pub fn retire_at(&mut self, addr: u32) -> Option<RowDecl> {
        match self.sources.index_of(addr) {
            Some(i) => {
                self.sources.remove(i);
                Some(self.decls.remove(i))
            }
            None => None,
        }
    }

    /// Replaces the declaration of the row at `addr`, in place, and hands
    /// the old one back: no row's index moves. `None`, and nothing changes,
    /// when no row holds `addr`. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            cinv(*old(self)),
        ensures
            cinv(*final(self)),
            rest_same(*final(self), *old(self)),
            rows_of(final(self).sources) == rows_of(old(self).sources),
            match r {
                Some(prev) => exists|i: int| {
                    &&& 0 <= i < old(self).decls@.len()
                    &&& #[trigger] rows_of(old(self).sources)[i] == addr
                    &&& prev == old(self).decls@[i]
                    &&& final(self).decls@ == old(self).decls@.update(i, d)
                },
                None => !registered(rows_of(old(self).sources), addr) && rows_same(*final(self), *old(self)),
            },
    ))]
    pub fn restate_at(&mut self, addr: u32, d: RowDecl) -> Option<RowDecl> {
        match self.sources.index_of(addr) {
            Some(i) => {
                let prev = self.decls.remove(i);
                self.decls.insert(i, d);
                Some(prev)
            }
            None => None,
        }
    }

    /// Changes the name of the row at `addr`. `false`, and nothing changes,
    /// when no row holds `addr`. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            cinv(*old(self)),
        ensures
            cinv(*final(self)),
            rest_same(*final(self), *old(self)),
            rows_of(final(self).sources) == rows_of(old(self).sources),
            final(self).decls@.len() == old(self).decls@.len(),
            r == registered(rows_of(old(self).sources), addr),
            !r ==> rows_same(*final(self), *old(self)),
            r ==> exists|i: int| {
                &&& 0 <= i < old(self).decls@.len()
                &&& #[trigger] rows_of(old(self).sources)[i] == addr
                &&& decl_renamed(final(self).decls@[i], old(self).decls@[i], name_id)
                &&& forall|k: int| 0 <= k < old(self).decls@.len() && k != i
                    ==> #[trigger] final(self).decls@[k] == old(self).decls@[k]
            },
    ))]
    pub fn rename_at(&mut self, addr: u32, name_id: u32) -> bool {
        match self.sources.index_of(addr) {
            Some(i) => {
                let mut d = self.decls.remove(i);
                d.name_id = name_id;
                self.decls.insert(i, d);
                true
            }
            None => false,
        }
    }

    /// Replaces the cohort's members. Nothing else changes. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        ensures
            final(self).members@ == members@,
            final(self).sources == old(self).sources,
            final(self).decls == old(self).decls,
            final(self).baseline == old(self).baseline,
            final(self).alias == old(self).alias,
    ))]
    pub fn set_members(&mut self, members: Vec<Member>) {
        self.members = members;
    }

    /// Replaces what is known of the host alias: the node's baseline ports
    /// there, the product's own listeners, the exposure table. Nothing else
    /// changes. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        ensures
            final(self).alias == alias,
            final(self).sources == old(self).sources,
            final(self).decls == old(self).decls,
            final(self).baseline == old(self).baseline,
            final(self).members == old(self).members,
    ))]
    pub fn set_alias(&mut self, alias: AliasState) {
        self.alias = alias;
    }

    /// Adopts the node's baseline and says whether it is in force. The rows
    /// and their declarations do not change. CF1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            cinv(*old(self)),
        ensures
            cinv(*final(self)),
            in_force_of(final(self).sources) == in_force,
            plan_of(final(self).sources) == plan_of(old(self).sources),
            spelling_of(final(self).sources) == spelling_of(old(self).sources),
            rows_same(*final(self), *old(self)),
            final(self).baseline@ == baseline@,
            final(self).members == old(self).members,
            final(self).alias == old(self).alias,
    ))]
    pub fn adopt_baseline(&mut self, in_force: bool, baseline: Vec<Cidr>) {
        self.sources.set_in_force(in_force);
        self.baseline = baseline;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Plan;
    use crate::policy::{Abilities, Declared, Enforced, Net, Section, effective};

    // 100.64.0.0/24: the gateway is .1.
    const NET: u32 = 0x6440_0000;
    const BOX: u32 = NET + 7;
    const APEX: &[u8] = b"\x03min\x08internal\x00";
    const INSIDE: &[u8] = b"\x03web\x03min\x08internal\x00";
    const OUTSIDE: &[u8] = b"\x07example\x03org\x00";

    /// Rules through the one road: these allowed subnets, nothing denied.
    fn rules(allow: Vec<Cidr>) -> Rules {
        let d = Declared {
            allow_subnets: Section::Listed(allow.into_iter().map(Net::V4).collect()),
            deny_subnets: Section::Listed(Vec::new()),
            allow_protocols: Section::Absent,
            laned: false,
            host_address: false,
        };
        let host = Abilities {
            per_box_host_address: true,
        };
        match effective(&d, &host).enforced() {
            Enforced::Whole(e) => e.rules(),
            Enforced::Part(_) => panic!("every block is kept"),
        }
    }

    fn decl(allow: Vec<Cidr>, resolves_names: bool) -> RowDecl {
        RowDecl {
            rules: rules(allow),
            resolves_names,
            alias_by_name: false,
            name_id: 1,
            task_row: false,
            names_boxes: Vec::new(),
        }
    }

    fn plan() -> Plan {
        Plan::new(NET, 24).unwrap()
    }

    /// A configuration with one row at `BOX`.
    fn config(d: RowDecl) -> Config {
        Config {
            sources: Sources::new(plan(), vec![BOX], true, CohortSpelling::NodeWithMark).unwrap(),
            decls: vec![d],
            baseline: Vec::new(),
            members: Vec::new(),
            alias: AliasState {
                node_ports: Vec::new(),
                held: Vec::new(),
                exposures: Vec::new(),
            },
        }
    }

    /// A DNS query for `name`, of this type, class IN.
    fn query(name: &[u8], kind: u16) -> Vec<u8> {
        let mut d = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        d.extend_from_slice(name);
        d.extend_from_slice(&kind.to_be_bytes());
        d.extend_from_slice(&[0, 1]);
        d
    }

    /// An Ethernet frame carrying a whole UDP datagram to port 53.
    fn to_port_53(src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let total = u16::try_from(20 + 8 + payload.len()).unwrap();
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src.to_be_bytes());
        f.extend_from_slice(&dst.to_be_bytes());
        f.extend_from_slice(&[0x9c, 0x40, 0, 53]);
        f.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn arm_of(c: &Config, frame: &[u8]) -> Arm {
        match c.egress_first(frame, APEX) {
            First::Frame { arm, .. } => arm,
            other => panic!("no frame: {other:?}"),
        }
    }

    #[test]
    fn a_row_that_names_nothing_reaches_the_resolver_only_with_a_zone_query() {
        let c = config(decl(Vec::new(), false));
        let gateway = plan().gateway();
        for kind in [1, 28, 65] {
            assert_eq!(
                arm_of(&c, &to_port_53(BOX, gateway, &query(INSIDE, kind))),
                Arm::Row(0, RowArm::Resolver)
            );
        }
        assert_eq!(
            arm_of(&c, &to_port_53(BOX, gateway, &query(OUTSIDE, 1))),
            Arm::RowDns(0)
        );
        assert_eq!(
            arm_of(&c, &to_port_53(BOX, gateway, &query(APEX, 1))),
            Arm::RowDns(0)
        );
        assert_eq!(
            arm_of(&c, &to_port_53(BOX, gateway, b"not a query")),
            Arm::RowDns(0)
        );
    }

    #[test]
    fn a_row_that_declares_a_dns_host_or_a_subnet_is_not_narrowed() {
        let gateway = plan().gateway();
        let outside = to_port_53(BOX, gateway, &query(OUTSIDE, 1));
        let names = config(decl(Vec::new(), true));
        assert_eq!(arm_of(&names, &outside), Arm::Row(0, RowArm::Resolver));
        let reaches = config(decl(
            vec![Cidr {
                addr: 0xcb00_7100,
                prefix: 24,
            }],
            false,
        ));
        assert_eq!(arm_of(&reaches, &outside), Arm::Row(0, RowArm::Resolver));
    }

    #[test]
    fn bytes_that_are_no_frame_are_refused_and_reach_no_tables() {
        let c = config(decl(Vec::new(), false));
        assert_eq!(
            c.egress_first(&[0u8; 5], APEX),
            First::NotAFrame(Reason::Short)
        );
        let (heard, whose, _) = c.ingress_first(&[0u8; 5]);
        assert_eq!(heard, Heard::Malformed(Reason::Short));
        assert_eq!(whose, IngressFor::NotARow);
    }

    #[test]
    fn the_configuration_changes_only_by_its_operations() {
        let other = NET + 9;
        let mut c = config(decl(Vec::new(), false));
        assert!(c.register(other, decl(Vec::new(), true)));
        assert!(!c.register(other, decl(Vec::new(), true)));
        assert!(!c.register(NET + 1, decl(Vec::new(), true)));
        assert_eq!(c.decls.len(), 2);
        // A restate replaces in place: the other row keeps its index.
        assert!(c.restate_at(BOX, decl(Vec::new(), true)).is_some());
        assert!(c.decls[0].resolves_names);
        assert_eq!(c.sources.index_of(other), Some(1));
        assert!(c.restate_at(NET + 11, decl(Vec::new(), true)).is_none());
        assert!(c.rename_at(other, 42));
        assert_eq!(c.decls[1].name_id, 42);
        assert_eq!(c.decls[0].name_id, 1);
        assert!(!c.rename_at(NET + 11, 7));
        // A retire moves later rows down by one, with their declarations.
        assert!(c.retire_at(BOX).is_some());
        assert_eq!(c.sources.index_of(other), Some(0));
        assert_eq!(c.decls.len(), 1);
        assert_eq!(c.decls[0].name_id, 42);
        assert!(c.retire_at(BOX).is_none());
    }
}
