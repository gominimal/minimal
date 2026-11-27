//! The whole decision for a frame from a registered row: the three tables
//! and the stateless arms, in the order the gate tries them.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! 1. A reply to an inbound flow, or the refusal of a noted connect, is
//!    admitted before anything else is read. Not toward the proxy's address.
//! 2. Otherwise the stateless arms decide ([`crate::row`]).
//! 3. If they say "a subnet the row did not allow", and only then, three
//!    things can still admit the frame: a DNS admission, the host alias
//!    named in the row's DNS hosts, or a box name the row may reach.
//!
//! THEOREM J1, for every plan, row, tables and frame:
//!   (a) `judge_row` returns the first of these that applies, in that order:
//!       each arm of the contract states its condition and that every
//!       earlier one failed;
//!   (b) a lift (DNS admission, alias by name, box name) is returned only
//!       when the stateless arms returned `UndeclaredSubnet`. No lift turns
//!       any other drop into an admit;
//!   (c) each result changes at most one table besides the reply table,
//!       from which a reply lookup that does not admit removes the frame's
//!       own record when it has expired; a refusal lookup that does not
//!       admit changes nothing. A reply
//!       changes the flow table, a refusal the notes, a DNS admission the
//!       DNS tables; every other result changes nothing more;
//!   (d) a frame to the proxy's address is never admitted as a reply or a
//!       refusal;
//!   (e) no table admits a frame for a box other than its own: the flow and
//!       note tables refuse a frame that names another box, and a DNS
//!       admission lifts only when the DNS tables' owner is the frame's source.
//!
//! THEOREM J2, for a frame without ports (a fragment that is not the first,
//! or a protocol that has none): it is never a reply or a refusal, never on
//! the proxy lane and never to the resolver; to the gateway and to the
//! proxy's address it is refused; to the host alias it is refused unless the
//! alias is open, which [`crate::alias`] never says of a frame without ports
//! (AO2); a DNS admission admits it by the destination's window alone and
//! records no flow; the reply table and the notes are as they were. What
//! still admits it reads the address and the protocol only: the row's rules,
//! a DNS admission's window, the alias by name once open, a box name.
//!
//! Whether the alias is open, whether the row resolves names, whether it
//! names the host, and what the box-name rule says are inputs here: they
//! depend on host exposures and on other rows, and [`crate::gate`] computes
//! them.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::flow::{Conversation, Flows, TCP};
#[cfg(verus_keep_ghost)]
use crate::flow::{conv_key, finv, is_flow_proto, live};
use crate::notes::{Notes, Segment};
#[cfg(verus_keep_ghost)]
use crate::notes::{is_refusal_shape, ninv, noted_live, refusal_key};
use crate::pins::{Egress, Pins, Transport};
#[cfg(verus_keep_ghost)]
use crate::pins::{flow_live, owner_of, pinv, same_limits};
use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_host_alias, spec_proxy_peer, wf};
use crate::policy::Rules;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
#[cfg(verus_keep_ghost)]
use crate::pool::live_key;
#[cfg(verus_keep_ghost)]
use crate::row::RowRules;
#[cfg(verus_keep_ghost)]
use crate::row::row_spec;
use crate::row::{Dest, RowArm, decide_row};
use crate::time::Instant;

/// The transport facts of a TCP or UDP first fragment the box sent. For UDP,
/// `flags`, `seq` and `ack` are 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct SentL4 {
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum SentKind {
    Arp,
    V4 {
        dst: u32,
        proto: u8,
        l4: Option<SentL4>,
    },
}

/// A frame a box sent, as far as the decision reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Sent {
    /// The source address, already matched to the row.
    pub src: u32,
    pub kind: SentKind,
}

/// What the box-name rule says of this frame's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum BoxNameRule {
    /// The rule does not apply.
    Silent,
    /// The destination is a box the row names.
    Allowed,
    /// The destination is a box the row does not name.
    Refused,
}

/// The inputs to the three lifts. [`crate::gate::Gate::egress`] computes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Lifts {
    /// The row declares DNS hosts.
    pub resolves_names: bool,
    /// The row's DNS hosts name the host alias.
    pub alias_by_name: bool,
    pub box_name: BoxNameRule,
    /// The destination the box-name rule was computed for. The rule is read
    /// only for a frame to that destination.
    pub box_name_dst: u32,
}

/// One row's three tables.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct BoxTables {
    pub flows: Flows,
    pub notes: Notes,
    pub pins: Pins,
}

/// How a frame from a registered row was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Judged {
    /// Admit: a reply on a live inbound flow.
    ReplyFlow,
    /// Admit: the refusal of a noted connect.
    Refusal,
    /// The stateless arm decided, and nothing lifted it.
    Row(RowArm),
    /// Admit: a DNS admission lifted an undeclared subnet.
    Pinned(Egress),
    /// Admit: the host alias, named in the row's DNS hosts.
    AliasByName,
    /// Admit: a box the row names.
    BoxName,
    /// Drop: a box the row does not name.
    BoxNameRefused,
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn tinv(t: BoxTables) -> bool {
    finv(t.flows) && ninv(t.notes) && pinv(t.pins)
}

/// The tables still belong to the same box.
pub open spec fn owners_same(now: BoxTables, before: BoxTables) -> bool {
    &&& crate::flow::box_of(now.flows) == crate::flow::box_of(before.flows)
    &&& crate::notes::box_of(now.notes) == crate::notes::box_of(before.notes)
    &&& owner_of(now.pins) == owner_of(before.pins)
}

pub open spec fn flows_same(now: Flows, before: Flows) -> bool {
    crate::flow::table(now) == crate::flow::table(before) && crate::flow::same_frame(now, before)
        && crate::flow::stamp_same(now, before)
}

/// The reply table after a reply lookup that did not admit, or none: the
/// frame's own expired record is gone when the lookup was made, and nothing
/// else changed.
pub open spec fn flows_missed(plan: Plan, after: Flows, before: Flows, s: Sent, now_ms: u64) -> bool {
    &&& crate::flow::same_frame(after, before)
    &&& crate::flow::stamp_same(after, before)
    &&& if answer_eligible(plan, s) {
        crate::flow::missed(after, before, conv_of(s), now_ms)
    } else {
        crate::flow::table(after) == crate::flow::table(before)
    }
}

/// A reply lookup that did not admit leaves the reply table as `flows_missed`
/// says.
pub proof fn lemma_refused_reply_missed(plan: Plan, before: Flows, after: Flows, s: Sent, now_ms: u64)
    requires
        answer_eligible(plan, s),
        crate::flow::reply_post(before, after, conv_of(s), flags_of(s), now_ms, false),
    ensures
        flows_missed(plan, after, before, s, now_ms),
{
    reveal(crate::flow::reply_post);
}

/// Whether a reply lookup admitted is whether the frame's own record was
/// live: what judges outside this module read of `reply_post`.
pub proof fn lemma_reply_answers(
    plan: Plan,
    before: Flows,
    after: Flows,
    s: Sent,
    now_ms: u64,
    r: bool,
)
    requires
        answer_eligible(plan, s),
        crate::flow::reply_post(before, after, conv_of(s), flags_of(s), now_ms, r),
    ensures
        r == reply_ok(plan, before, s, now_ms),
        crate::flow::same_frame(after, before),
{
    reveal(crate::flow::reply_post);
}

pub open spec fn notes_same(now: Notes, before: Notes) -> bool {
    crate::notes::table(now) == crate::notes::table(before) && crate::notes::same_frame(now, before)
}

pub open spec fn pins_same(now: Pins, before: Pins) -> bool {
    &&& crate::pins::asked(now) == crate::pins::asked(before)
    &&& crate::pins::admitted(now) == crate::pins::admitted(before)
    &&& crate::pins::flows(now) == crate::pins::flows(before)
    &&& same_limits(now, before)
}

/// What the stateless arms read of the frame.
pub open spec fn dest_of_sent(s: Sent) -> Dest {
    match s.kind {
        SentKind::Arp => Dest::Arp,
        SentKind::V4 { dst, proto, l4 } => Dest::V4 {
            dst,
            proto,
            port: match l4 {
                Some(x) => x.dport,
                None => 0u16,
            },
        },
    }
}

/// The frame has ports and is not addressed to the proxy.
pub open spec fn answer_eligible(plan: Plan, s: Sent) -> bool {
    match s.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => l4.is_some() && dst as int != spec_proxy_peer(plan),
    }
}

/// The frame as a conversation between its destination, the client, and the box.
pub open spec fn conv_of(s: Sent) -> Conversation {
    match s.kind {
        SentKind::V4 { dst, proto, l4: Some(x) } => Conversation {
            proto,
            client: dst,
            client_port: x.dport,
            box_addr: s.src,
            box_port: x.sport,
        },
        _ => Conversation { proto: 0, client: 0, client_port: 0, box_addr: 0, box_port: 0 },
    }
}

pub open spec fn seg_of(s: Sent) -> Segment {
    match s.kind {
        SentKind::V4 { dst, proto, l4: Some(x) } => Segment {
            client: dst,
            client_port: x.dport,
            box_addr: s.src,
            box_port: x.sport,
            flags: x.flags,
            seq: x.seq,
            ack: x.ack,
            payload_len: x.payload_len,
        },
        _ => Segment {
            client: 0,
            client_port: 0,
            box_addr: 0,
            box_port: 0,
            flags: 0,
            seq: 0,
            ack: 0,
            payload_len: 0,
        },
    }
}

pub open spec fn proto_of(s: Sent) -> u8 {
    match s.kind {
        SentKind::Arp => 0u8,
        SentKind::V4 { dst, proto, l4 } => proto,
    }
}

/// What the box-name rule says of this frame: what the lifts carry when
/// they were computed for its destination, and nothing otherwise.
pub open spec fn box_rule(lifts: Lifts, s: Sent) -> BoxNameRule {
    box_rule_at(lifts, dst_of(s))
}

/// The box-name rule for a frame to `dst`. Opaque: the judge and its
/// lemmas pass it on without reading it; `box_ruled` and the two lemmas
/// below reveal it.
#[verifier::opaque]
pub open spec fn box_rule_at(lifts: Lifts, dst: u32) -> BoxNameRule {
    if lifts.box_name_dst == dst {
        lifts.box_name
    } else {
        BoxNameRule::Silent
    }
}

/// The rule computed for a frame's own destination is the rule the lifts
/// carry.
pub proof fn lemma_box_rule_own(lifts: Lifts, s: Sent)
    requires
        lifts.box_name_dst == dst_of(s),
    ensures
        box_rule(lifts, s) == lifts.box_name,
{
    reveal(box_rule_at);
}

/// A rule computed for another destination says nothing of this frame, and
/// no rule admits by name unless the lifts carry `Allowed`.
pub proof fn lemma_box_rule_other(lifts: Lifts, s: Sent)
    ensures
        lifts.box_name_dst != dst_of(s) ==> box_rule(lifts, s) == BoxNameRule::Silent,
        box_rule(lifts, s) == BoxNameRule::Allowed ==> lifts.box_name == BoxNameRule::Allowed && lifts.box_name_dst == dst_of(s),
{
    reveal(box_rule_at);
}

/// What the lift stage returns for a frame to `dst` that the rules gave
/// `arm`: the alias by name, else what the box-name rule says.
pub open spec fn lift_spec(plan: Plan, lifts: Lifts, dst: u32, arm: RowArm) -> Judged {
    if dst as int == spec_host_alias(plan) && lifts.alias_by_name {
        Judged::AliasByName
    } else {
        box_judged(box_rule_at(lifts, dst), arm)
    }
}

/// The lift stage's result is the row's decision: `lemma_lifted`, read at
/// the value `lift_spec` gives.
proof fn lemma_lift_judged(
    plan: Plan,
    rules: RowRules,
    lifts: Lifts,
    alias_open: bool,
    before: BoxTables,
    mid: BoxTables,
    now: BoxTables,
    s: Sent,
    now_ms: u64,
    dst: u32,
    arm: RowArm,
)
    requires
        at_lifts(plan, rules, lifts, alias_open, before, now, s, now_ms) || (at_rules(plan, before, mid, s, now_ms)
            && liftable(plan, rules, alias_open, s) && !(lifts.resolves_names && owner_of(mid.pins) == s.src)
            && now == mid),
        dst == dst_of(s),
        arm == RowArm::UndeclaredSubnet,
    ensures
        row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, lift_spec(plan, lifts, dst, arm)),
        owners_same(now, before),
{
    lemma_lifted(plan, rules, lifts, alias_open, before, mid, now, s, now_ms);
}

/// J1, the box name: a frame is admitted by name only under a rule that says
/// `Allowed` and was computed for that frame's destination.
pub proof fn theorem_j1_box_name_is_for_this_destination(
    plan: Plan,
    rules: RowRules,
    lifts: Lifts,
    alias_open: bool,
    before: BoxTables,
    after: BoxTables,
    sent: Sent,
    now_ms: u64,
)
    requires
        row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, Judged::BoxName),
    ensures
        lifts.box_name == BoxNameRule::Allowed,
        lifts.box_name_dst == dst_of(sent),
{
    lemma_box_rule_other(lifts, sent);
}

/// What the last lift returns: the box-name rule's result, or the arm the
/// rules gave when the rule is silent.
pub open spec fn box_judged(rule: BoxNameRule, arm: RowArm) -> Judged {
    match rule {
        BoxNameRule::Allowed => Judged::BoxName,
        BoxNameRule::Refused => Judged::BoxNameRefused,
        BoxNameRule::Silent => Judged::Row(arm),
    }
}

pub open spec fn dst_of(s: Sent) -> u32 {
    match s.kind {
        SentKind::Arp => 0u32,
        SentKind::V4 { dst, proto, l4 } => dst,
    }
}

pub open spec fn transport_of(s: Sent) -> Option<Transport> {
    match s.kind {
        SentKind::V4 { dst, proto, l4: Some(x) } => Some(Transport {
            proto,
            sport: x.sport,
            dport: x.dport,
            flags: x.flags,
        }),
        _ => None,
    }
}

/// The frame's TCP flags; 0 when it has no ports.
pub open spec fn flags_of(s: Sent) -> u8 {
    match s.kind {
        SentKind::V4 { dst, proto, l4: Some(x) } => x.flags,
        _ => 0u8,
    }
}

/// The frame is a reply on a live inbound flow of this box.
pub open spec fn reply_ok(plan: Plan, flows: Flows, s: Sent, now_ms: u64) -> bool {
    &&& answer_eligible(plan, s)
    &&& conv_of(s).box_addr == crate::flow::box_of(flows)
    &&& is_flow_proto(conv_of(s).proto)
    &&& live(crate::flow::table(flows), conv_of(s).client, conv_key(conv_of(s)), now_ms)
}

/// The frame is the refusal of a connect this box has noted.
pub open spec fn refusal_ok(plan: Plan, notes: Notes, s: Sent, now_ms: u64) -> bool {
    &&& answer_eligible(plan, s)
    &&& proto_of(s) == TCP
    &&& seg_of(s).box_addr == crate::notes::box_of(notes)
    &&& is_refusal_shape(seg_of(s))
    &&& noted_live(crate::notes::table(notes), seg_of(s).client, refusal_key(seg_of(s)), now_ms, seg_of(s).ack)
}

/// A DNS admission covers the frame: a live flow to it, or a live window.
pub open spec fn pin_ok(pins: Pins, s: Sent, now_ms: u64) -> bool {
    flow_live(crate::pins::flows(pins), dst_of(s), transport_of(s), now_ms)
        || live_key(crate::pins::admitted(pins), dst_of(s) as u64, now_ms)
}

/// The frame is addressed to the host alias and the row names it.
pub open spec fn alias_lift(plan: Plan, lifts: Lifts, s: Sent) -> bool {
    dst_of(s) as int == spec_host_alias(plan) && lifts.alias_by_name
}

/// The stateless arms were not reached first by a reply or a refusal.
pub open spec fn reaches_rules(plan: Plan, t: BoxTables, s: Sent, now_ms: u64) -> bool {
    !reply_ok(plan, t.flows, s, now_ms) && !refusal_ok(plan, t.notes, s, now_ms)
}

/// The stateless arms said "undeclared subnet": the one drop a lift may turn.
pub open spec fn liftable(plan: Plan, rules: RowRules, alias_open: bool, s: Sent) -> bool {
    row_spec(plan, rules, alias_open, dest_of_sent(s)) == RowArm::UndeclaredSubnet
}

pub open spec fn pin_lift(lifts: Lifts, pins: Pins, s: Sent, now_ms: u64) -> bool {
    lifts.resolves_names && owner_of(pins) == s.src && pin_ok(pins, s, now_ms)
}

/// The result admits the frame.
pub open spec fn judged_ok(j: Judged) -> bool {
    match j {
        Judged::ReplyFlow => true,
        Judged::Refusal => true,
        Judged::Row(arm) => crate::row::admits(arm),
        Judged::Pinned(e) => e != Egress::Refused,
        Judged::AliasByName => true,
        Judged::BoxName => true,
        Judged::BoxNameRefused => false,
    }
}

/// What `judge_row` promises of its result and of the tables before and after.
pub open spec fn row_post(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, after: BoxTables, sent: Sent, now_ms: u64, r: Judged) -> bool {
    match r {
        Judged::ReplyFlow => {
            &&& reply_ok(plan, before.flows, sent, now_ms)
            &&& crate::flow::reply_post(before.flows, after.flows, conv_of(sent), flags_of(sent), now_ms, true)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Judged::Refusal => {
            &&& !reply_ok(plan, before.flows, sent, now_ms)
            &&& refusal_ok(plan, before.notes, sent, now_ms)
            &&& crate::notes::refusal_post(before.notes, after.notes, seg_of(sent), now_ms, true)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& pins_same(after.pins, before.pins)
        },
        Judged::Row(arm) => {
            &&& reaches_rules(plan, before, sent, now_ms)
            &&& arm == row_spec(plan, rules, alias_open, dest_of_sent(sent))
            &&& arm == RowArm::UndeclaredSubnet ==> {
                &&& !pin_lift(lifts, before.pins, sent, now_ms)
                &&& !alias_lift(plan, lifts, sent)
                &&& box_rule(lifts, sent) == BoxNameRule::Silent
            }
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Judged::Pinned(e) => {
            &&& reaches_rules(plan, before, sent, now_ms)
            &&& liftable(plan, rules, alias_open, sent)
            &&& pin_lift(lifts, before.pins, sent, now_ms)
            &&& e != Egress::Refused
            &&& crate::pins::egress_post(before.pins, after.pins, dst_of(sent), transport_of(sent), now_ms, e)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
        },
        Judged::AliasByName => {
            &&& reaches_rules(plan, before, sent, now_ms)
            &&& liftable(plan, rules, alias_open, sent)
            &&& !pin_lift(lifts, before.pins, sent, now_ms)
            &&& alias_lift(plan, lifts, sent)
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Judged::BoxName => {
            &&& reaches_rules(plan, before, sent, now_ms)
            &&& liftable(plan, rules, alias_open, sent)
            &&& !pin_lift(lifts, before.pins, sent, now_ms)
            &&& !alias_lift(plan, lifts, sent)
            &&& box_rule(lifts, sent) == BoxNameRule::Allowed
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Judged::BoxNameRefused => {
            &&& reaches_rules(plan, before, sent, now_ms)
            &&& liftable(plan, rules, alias_open, sent)
            &&& !pin_lift(lifts, before.pins, sent, now_ms)
            &&& !alias_lift(plan, lifts, sent)
            &&& box_rule(lifts, sent) == BoxNameRule::Refused
            &&& flows_missed(plan, after.flows, before.flows, sent, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
    }
}

/// Whatever the result, the tables still belong to the same box: every arm of
/// `row_post` either leaves a table as it was or states that table's own
/// guarantee, which includes its owner.
pub proof fn lemma_row_post_keeps_owners(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, after: BoxTables, sent: Sent, now_ms: u64, r: Judged)
    requires
        wf(plan),
        tinv(before),
        tinv(after),
        row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, r),
    ensures
        owners_same(after, before),
{
    reveal(crate::flow::reply_post);
}

/// The frame is an IPv4 datagram without ports: a fragment that is not the
/// first, or a protocol that has none.
pub open spec fn portless(s: Sent) -> bool {
    match s.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => l4 is None,
    }
}

/// J2.
pub proof fn theorem_j2_no_port_opening_admits_a_frame_without_ports(
    plan: Plan,
    rules: RowRules,
    lifts: Lifts,
    alias_open: bool,
    before: BoxTables,
    after: BoxTables,
    sent: Sent,
    now_ms: u64,
    r: Judged,
)
    requires
        portless(sent),
        row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, r),
    ensures
        r != Judged::ReplyFlow,
        r != Judged::Refusal,
        r != Judged::Row(RowArm::LaneAdmit),
        r != Judged::Row(RowArm::Resolver),
        dst_of(sent) as int == crate::plan::spec_gateway(plan) ==> !judged_ok(r),
        dst_of(sent) as int == spec_proxy_peer(plan) ==> !judged_ok(r),
        dst_of(sent) as int == spec_host_alias(plan) && !alias_open ==> !judged_ok(r),
        r matches Judged::Pinned(e) ==> e == Egress::Window
            && crate::pins::flows(after.pins) == crate::pins::flows(before.pins),
        crate::flow::table(after.flows) == crate::flow::table(before.flows),
        notes_same(after.notes, before.notes),
{
}

/// The stateless arms are reached, and the tables are as every result after
/// them leaves them, but for the DNS tables when a DNS admission is made.
/// Proof text only: opaque, so that the paths of `judge_row` carry it whole.
#[verifier::opaque]
spec fn at_rules(plan: Plan, before: BoxTables, now: BoxTables, s: Sent, now_ms: u64) -> bool {
    &&& reaches_rules(plan, before, s, now_ms)
    &&& flows_missed(plan, now.flows, before.flows, s, now_ms)
    &&& notes_same(now.notes, before.notes)
    &&& now.pins == before.pins
}

/// The stateless arms said "undeclared subnet", no DNS admission lifted it,
/// and the tables are as every later result leaves them. Proof text only.
#[verifier::opaque]
spec fn at_lifts(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, now: BoxTables, s: Sent, now_ms: u64) -> bool {
    &&& reaches_rules(plan, before, s, now_ms)
    &&& liftable(plan, rules, alias_open, s)
    &&& !pin_lift(lifts, before.pins, s, now_ms)
    &&& flows_missed(plan, now.flows, before.flows, s, now_ms)
    &&& notes_same(now.notes, before.notes)
    &&& pins_same(now.pins, before.pins)
}

/// An ARP frame: the stateless arms decide, and no table changes.
proof fn lemma_judged_arp(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, t: BoxTables, s: Sent, now_ms: u64)
    requires
        s.kind == SentKind::Arp,
    ensures
        row_post(plan, rules, lifts, alias_open, t, t, s, now_ms, Judged::Row(row_spec(plan, rules, alias_open, Dest::Arp))),
        owners_same(t, t),
{
}

/// The reply lookup admitted the frame: `ReplyFlow`.
proof fn lemma_judged_reply(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, after: BoxTables, s: Sent, now_ms: u64)
    requires
        answer_eligible(plan, s),
        crate::flow::reply_post(before.flows, after.flows, conv_of(s), flags_of(s), now_ms, true),
        after.notes == before.notes,
        after.pins == before.pins,
    ensures
        row_post(plan, rules, lifts, alias_open, before, after, s, now_ms, Judged::ReplyFlow),
        owners_same(after, before),
{
    reveal(crate::flow::reply_post);
}

/// The reply lookup did not admit the frame and the refusal lookup did: `Refusal`.
proof fn lemma_judged_refusal(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, after: BoxTables, s: Sent, now_ms: u64)
    requires
        answer_eligible(plan, s),
        proto_of(s) == TCP,
        crate::flow::reply_post(before.flows, after.flows, conv_of(s), flags_of(s), now_ms, false),
        crate::notes::refusal_post(before.notes, after.notes, seg_of(s), now_ms, true),
        after.pins == before.pins,
    ensures
        row_post(plan, rules, lifts, alias_open, before, after, s, now_ms, Judged::Refusal),
        owners_same(after, before),
{
    reveal(crate::flow::reply_post);
}

/// A frame with ports, not to the proxy, that neither lookup admitted reaches
/// the stateless arms.
proof fn lemma_answers_refused(plan: Plan, before: BoxTables, now: BoxTables, s: Sent, now_ms: u64)
    requires
        answer_eligible(plan, s),
        crate::flow::reply_post(before.flows, now.flows, conv_of(s), flags_of(s), now_ms, false),
        proto_of(s) == TCP ==> crate::notes::refusal_post(before.notes, now.notes, seg_of(s), now_ms, false),
        proto_of(s) != TCP ==> now.notes == before.notes,
        now.pins == before.pins,
    ensures
        at_rules(plan, before, now, s, now_ms),
{
    reveal(crate::flow::reply_post);
    reveal(at_rules);
}

/// The stateless arms decided `arm`, reached after both lookups refused or
/// with no lookup made: the result when `arm` is not "undeclared subnet".
proof fn lemma_rules_arm(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, now: BoxTables, s: Sent, now_ms: u64, arm: RowArm)
    requires
        at_rules(plan, before, now, s, now_ms) || (!answer_eligible(plan, s) && now == before),
        arm == row_spec(plan, rules, alias_open, dest_of_sent(s)),
    ensures
        at_rules(plan, before, now, s, now_ms),
        arm == RowArm::UndeclaredSubnet ==> liftable(plan, rules, alias_open, s),
        arm != RowArm::UndeclaredSubnet ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::Row(arm)),
        owners_same(now, before),
{
    reveal(at_rules);
}

/// The DNS tables were asked, `mid` being the tables before: `Pinned(e)`
/// unless they refused, the lift stage if they did.
proof fn lemma_judged_pins(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, mid: BoxTables, now: BoxTables, s: Sent, now_ms: u64, e: Egress)
    requires
        at_rules(plan, before, mid, s, now_ms),
        liftable(plan, rules, alias_open, s),
        lifts.resolves_names,
        owner_of(mid.pins) == s.src,
        crate::pins::egress_post(mid.pins, now.pins, dst_of(s), transport_of(s), now_ms, e),
        now.flows == mid.flows,
        now.notes == mid.notes,
    ensures
        e != Egress::Refused ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::Pinned(e)),
        e == Egress::Refused ==> at_lifts(plan, rules, lifts, alias_open, before, now, s, now_ms),
        owners_same(now, before),
{
    reveal(at_rules);
    reveal(at_lifts);
}

/// The lift stage, reached with the DNS tables refusing or not asked (`mid`
/// being the tables then): the alias by name, else what the box-name rule says.
proof fn lemma_lifted(plan: Plan, rules: RowRules, lifts: Lifts, alias_open: bool, before: BoxTables, mid: BoxTables, now: BoxTables, s: Sent, now_ms: u64)
    requires
        at_lifts(plan, rules, lifts, alias_open, before, now, s, now_ms) || (at_rules(plan, before, mid, s, now_ms)
            && liftable(plan, rules, alias_open, s) && !(lifts.resolves_names && owner_of(mid.pins) == s.src)
            && now == mid),
    ensures
        alias_lift(plan, lifts, s) ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::AliasByName),
        !alias_lift(plan, lifts, s) && box_rule(lifts, s) == BoxNameRule::Allowed
            ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::BoxName),
        !alias_lift(plan, lifts, s) && box_rule(lifts, s) == BoxNameRule::Refused
            ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::BoxNameRefused),
        !alias_lift(plan, lifts, s) && box_rule(lifts, s) == BoxNameRule::Silent
            ==> row_post(plan, rules, lifts, alias_open, before, now, s, now_ms, Judged::Row(RowArm::UndeclaredSubnet)),
        owners_same(now, before),
{
    reveal(at_rules);
    reveal(at_lifts);
    assert(at_lifts(plan, rules, lifts, alias_open, before, now, s, now_ms));
}

} // verus!

/// Decides a frame from a registered row. `t` must be that row's tables.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        row_post(*plan, rules_of(*rules), lifts, alias_open, *old(t), *final(t), sent, now.ms, r),
))]
pub fn judge_row(
    plan: &Plan,
    rules: &Rules,
    lifts: Lifts,
    alias_open: bool,
    t: &mut BoxTables,
    sent: Sent,
    now: Instant,
) -> Judged {
    let rules = rules.get();
    let (dst, proto, l4) = match sent.kind {
        SentKind::Arp => {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_judged_arp(*plan, *rules, lifts, alias_open, *old(t), sent, now.ms);
            }
            return Judged::Row(decide_row(plan, rules, alias_open, Dest::Arp));
        }
        SentKind::V4 { dst, proto, l4 } => (dst, proto, l4),
    };
    // 1. A reply or a refusal, before anything else is read.
    if let Some(x) = l4 {
        if dst != plan.proxy_peer() {
            let c = Conversation {
                proto,
                client: dst,
                client_port: x.dport,
                box_addr: sent.src,
                box_port: x.sport,
            };
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(answer_eligible(*plan, sent) && c == conv_of(sent) && x.flags == flags_of(sent)
                    && proto == proto_of(sent));
            }
            if t.flows.reply(c, x.flags, now) {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_judged_reply(*plan, *rules, lifts, alias_open, *old(t), *t, sent, now.ms);
                }
                return Judged::ReplyFlow;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_refused_reply_missed(*plan, old(t).flows, t.flows, sent, now.ms);
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
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(s == seg_of(sent));
                }
                if t.notes.refusal(s, now) {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_judged_refusal(*plan, *rules, lifts, alias_open, *old(t), *t, sent, now.ms);
                    }
                    return Judged::Refusal;
                }
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_answers_refused(*plan, *old(t), *t, sent, now.ms);
            }
        }
    }
    // 2. The stateless arms.
    let port = match l4 {
        Some(x) => x.dport,
        None => 0,
    };
    let arm = decide_row(plan, rules, alias_open, Dest::V4 { dst, proto, port });
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(dest_of_sent(sent) == Dest::V4 { dst, proto, port } && dst_of(sent) == dst);
        lemma_rules_arm(*plan, *rules, lifts, alias_open, *old(t), *t, sent, now.ms, arm);
    }
    match arm {
        RowArm::UndeclaredSubnet => {}
        _ => return Judged::Row(arm),
    }
    // 3. The three lifts, for an undeclared subnet only.
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost mid: BoxTables = *t;
    }
    if lifts.resolves_names && t.pins.owner() == sent.src {
        let transport = match l4 {
            Some(x) => Some(Transport {
                proto,
                sport: x.sport,
                dport: x.dport,
                flags: x.flags,
            }),
            None => None,
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(transport == transport_of(sent));
        }
        let e = t.pins.egress(dst, transport, now);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_judged_pins(*plan, *rules, lifts, alias_open, *old(t), mid, *t, sent, now.ms, e);
        }
        match e {
            Egress::Refused => {}
            _ => return Judged::Pinned(e),
        }
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_lift_judged(*plan, *rules, lifts, alias_open, *old(t), mid, *t, sent, now.ms, dst, arm);
    }
    lift(plan, lifts, dst, arm)
}

/// The lift stage: the alias by name, else what the box-name rule says.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        wf(*plan),
    ensures
        r == lift_spec(*plan, lifts, dst, arm),
))]
fn lift(plan: &Plan, lifts: Lifts, dst: u32, arm: RowArm) -> Judged {
    if dst == plan.host_alias() && lifts.alias_by_name {
        return Judged::AliasByName;
    }
    box_ruled(lifts, dst, arm)
}

/// The last lift: what the box-name rule says of a frame to `dst`.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == box_judged(box_rule_at(lifts, dst), arm),
))]
fn box_ruled(lifts: Lifts, dst: u32, arm: RowArm) -> Judged {
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(box_rule_at);
    }
    let rule = if lifts.box_name_dst == dst {
        lifts.box_name
    } else {
        BoxNameRule::Silent
    };
    match rule {
        BoxNameRule::Allowed => Judged::BoxName,
        BoxNameRule::Refused => Judged::BoxNameRefused,
        BoxNameRule::Silent => Judged::Row(arm),
    }
}

/// The destination of a sent frame, 0 for ARP.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == dst_of(*s),
))]
pub fn sent_dst(s: &Sent) -> u32 {
    match s.kind {
        SentKind::Arp => 0,
        SentKind::V4 { dst, .. } => dst,
    }
}

/// Whether a result admits the frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == judged_ok(j),
))]
pub fn judged_admits(j: Judged) -> bool {
    match j {
        Judged::ReplyFlow => true,
        Judged::Refusal => true,
        Judged::Row(arm) => crate::row::arm_admits(arm),
        Judged::Pinned(e) => match e {
            Egress::Refused => false,
            Egress::ByFlow => true,
            Egress::Retained => true,
            Egress::Window => true,
        },
        Judged::AliasByName => true,
        Judged::BoxName => true,
        Judged::BoxNameRefused => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{ACK, Inbound, RST, SYN, Windows};
    use crate::notes::Noted;
    use crate::pins::{Admitted, Asked, Limits};
    use crate::policy::{Abilities, Declared, Enforced, Net, Section, effective};
    use crate::row::{Cidr, RowRules};
    use crate::time::Span;

    // 100.64.0.0/24: gateway .1, proxy .252, node .253, host alias .254.
    const NET: u32 = 0x6440_0000;
    const BOX: u32 = NET + 7;
    const PROXY: u32 = NET + 252;
    const ALIAS: u32 = NET + 254;
    const CLIENT: u32 = NET + 1;
    const PUBLIC: u32 = 0xcb00_7107;

    fn plan() -> Plan {
        Plan::new(NET, 24).unwrap()
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
            flows: Flows::new(BOX, 4, windows, Span { ms: 1_000 }).unwrap(),
            notes: Notes::new(BOX, 4, 2, Span { ms: 5_000 }).unwrap(),
            pins: Pins::new(BOX, limits).unwrap(),
        }
    }

    fn deny_all() -> Rules {
        made(RowRules {
            allow_protocols: None,
            deny: Vec::new(),
            allow_subnets: Some(Vec::new()),
            laned: false,
        })
    }

    /// Rules through the one road: a declaration, enforced whole.
    fn made(r: RowRules) -> Rules {
        let net = |c: &Cidr| Net::V4(*c);
        let d = Declared {
            allow_subnets: match &r.allow_subnets {
                None => Section::Listed(vec![Net::V4(Cidr { addr: 0, prefix: 0 })]),
                Some(v) => Section::Listed(v.iter().map(net).collect()),
            },
            deny_subnets: Section::Listed(r.deny.iter().map(net).collect()),
            allow_protocols: match &r.allow_protocols {
                None => Section::Absent,
                Some(v) => Section::Listed(v.clone()),
            },
            laned: r.laned,
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

    const QUIET: Lifts = Lifts {
        resolves_names: false,
        alias_by_name: false,
        box_name: BoxNameRule::Silent,
        box_name_dst: 0,
    };

    fn tcp(dst: u32, sport: u16, dport: u16, flags: u8, seq: u32, ack: u32) -> Sent {
        Sent {
            src: BOX,
            kind: SentKind::V4 {
                dst,
                proto: TCP,
                l4: Some(SentL4 {
                    sport,
                    dport,
                    flags,
                    seq,
                    ack,
                    payload_len: 0,
                }),
            },
        }
    }

    #[test]
    fn a_deny_all_row_answers_the_client_that_connected_and_nobody_else() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        // The client of a published port is the gateway: without a record
        // its answer dies at the control surface, whatever the rules say.
        let answer = tcp(CLIENT, 8080, 40000, SYN | ACK, 0, 1);
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, answer, Instant { ms: 1 }),
            Judged::Row(RowArm::ControlSurface)
        );
        let opening = Conversation {
            proto: TCP,
            client: CLIENT,
            client_port: 40000,
            box_addr: BOX,
            box_port: 8080,
        };
        assert_eq!(
            t.flows.inbound(opening, SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, answer, Instant { ms: 1 }),
            Judged::ReplyFlow
        );
        let elsewhere = tcp(CLIENT, 8080, 40001, SYN | ACK, 0, 1);
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, elsewhere, Instant { ms: 1 }),
            Judged::Row(RowArm::ControlSurface)
        );
    }

    #[test]
    fn a_frame_on_an_expired_record_meets_the_rules_and_removes_the_record() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        let opening = Conversation {
            proto: TCP,
            client: CLIENT,
            client_port: 40000,
            box_addr: BOX,
            box_port: 8080,
        };
        assert_eq!(
            t.flows.inbound(opening, SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        let answer = tcp(CLIENT, 8080, 40000, ACK, 0, 1);
        assert_eq!(
            judge_row(
                &p,
                &r,
                QUIET,
                false,
                &mut t,
                answer,
                Instant { ms: 300_000 }
            ),
            Judged::Row(RowArm::ControlSurface)
        );
        assert_eq!(t.flows.len(), 0);
    }

    #[test]
    fn a_noted_connect_is_refused_once_and_a_second_reset_meets_the_rules() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        let connect = Segment {
            client: CLIENT,
            client_port: 40000,
            box_addr: BOX,
            box_port: 9,
            flags: SYN,
            seq: 100,
            ack: 0,
            payload_len: 0,
        };
        assert_eq!(
            t.notes.note_connect(connect, Instant { ms: 0 }),
            Noted::Noted
        );
        let reset = tcp(CLIENT, 9, 40000, RST | ACK, 0, 101);
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, reset, Instant { ms: 1 }),
            Judged::Refusal
        );
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, reset, Instant { ms: 2 }),
            Judged::Row(RowArm::ControlSurface)
        );
    }

    #[test]
    fn a_reply_record_never_admits_a_frame_to_the_proxy() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        let opening = Conversation {
            proto: TCP,
            client: PROXY,
            client_port: 40000,
            box_addr: BOX,
            box_port: 8080,
        };
        assert_eq!(
            t.flows.inbound(opening, SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        let answer = tcp(PROXY, 8080, 40000, SYN | ACK, 0, 1);
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, answer, Instant { ms: 1 }),
            Judged::Row(RowArm::LaneRefuse)
        );
    }

    #[test]
    fn a_dns_admission_lifts_an_undeclared_subnet_and_nothing_else() {
        let (p, mut t) = (plan(), tables());
        assert_eq!(t.pins.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let token = t.pins.answer(0, 7, 5000, 0).unwrap();
        assert_eq!(t.pins.admit(&token, PUBLIC), Admitted::New);
        let names = Lifts {
            resolves_names: true,
            alias_by_name: false,
            box_name: BoxNameRule::Silent,
            box_name_dst: 0,
        };
        let frame = tcp(PUBLIC, 50000, 443, SYN, 0, 0);
        assert_eq!(
            judge_row(
                &p,
                &deny_all(),
                names,
                false,
                &mut t,
                frame,
                Instant { ms: 1 }
            ),
            Judged::Pinned(Egress::Retained)
        );
        assert_eq!(
            judge_row(
                &p,
                &deny_all(),
                QUIET,
                false,
                &mut t,
                tcp(PUBLIC, 50001, 443, SYN, 0, 0),
                Instant { ms: 1 }
            ),
            Judged::Row(RowArm::UndeclaredSubnet)
        );
        // A denied subnet is not lifted by the same admission.
        let denying = made(RowRules {
            allow_protocols: None,
            deny: vec![Cidr {
                addr: PUBLIC,
                prefix: 32,
            }],
            allow_subnets: Some(Vec::new()),
            laned: false,
        });
        assert_eq!(
            judge_row(
                &p,
                &denying,
                names,
                false,
                &mut t,
                tcp(PUBLIC, 50002, 443, SYN, 0, 0),
                Instant { ms: 1 }
            ),
            Judged::Row(RowArm::DeniedSubnet)
        );
    }

    #[test]
    fn the_alias_and_box_name_lifts_come_after_the_dns_admission() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        let by_name = Lifts {
            resolves_names: true,
            alias_by_name: true,
            box_name: BoxNameRule::Refused,
            box_name_dst: NET + 9,
        };
        let to_alias = tcp(ALIAS, 50000, 8080, SYN, 0, 0);
        assert_eq!(
            judge_row(&p, &r, by_name, true, &mut t, to_alias, Instant { ms: 1 }),
            Judged::AliasByName
        );
        assert_eq!(
            judge_row(&p, &r, by_name, false, &mut t, to_alias, Instant { ms: 1 }),
            Judged::Row(RowArm::AliasClosed)
        );
        let to_box = tcp(NET + 9, 50000, 8080, SYN, 0, 0);
        assert_eq!(
            judge_row(&p, &r, by_name, false, &mut t, to_box, Instant { ms: 1 }),
            Judged::BoxNameRefused
        );
        let allowed = Lifts {
            resolves_names: false,
            alias_by_name: false,
            box_name: BoxNameRule::Allowed,
            box_name_dst: NET + 9,
        };
        assert_eq!(
            judge_row(&p, &r, allowed, false, &mut t, to_box, Instant { ms: 1 }),
            Judged::BoxName
        );
        // The rule was computed for another destination: it says nothing of this frame.
        let elsewhere = tcp(NET + 10, 50000, 8080, SYN, 0, 0);
        assert_eq!(
            judge_row(&p, &r, allowed, false, &mut t, elsewhere, Instant { ms: 1 }),
            Judged::Row(RowArm::UndeclaredSubnet)
        );
    }

    #[test]
    fn arp_and_frames_without_ports_skip_the_tables() {
        let (p, r, mut t) = (plan(), deny_all(), tables());
        let arp = Sent {
            src: BOX,
            kind: SentKind::Arp,
        };
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, arp, Instant { ms: 1 }),
            Judged::Row(RowArm::Arp)
        );
        let icmp = Sent {
            src: BOX,
            kind: SentKind::V4 {
                dst: PUBLIC,
                proto: 1,
                l4: None,
            },
        };
        assert_eq!(
            judge_row(&p, &r, QUIET, false, &mut t, icmp, Instant { ms: 1 }),
            Judged::Row(RowArm::UndeclaredSubnet)
        );
    }

    #[test]
    fn only_the_refused_box_name_and_the_dropping_arms_drop() {
        assert!(judged_admits(Judged::ReplyFlow) && judged_admits(Judged::Refusal));
        assert!(judged_admits(Judged::Pinned(Egress::Window)));
        assert!(judged_admits(Judged::AliasByName) && judged_admits(Judged::BoxName));
        assert!(!judged_admits(Judged::BoxNameRefused));
        assert!(!judged_admits(Judged::Row(RowArm::UndeclaredSubnet)));
        assert!(judged_admits(Judged::Row(RowArm::Rules)));
    }
}
