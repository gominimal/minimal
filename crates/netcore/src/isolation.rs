//! A decision is settled by what the deciding box's tables hold.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! GE1 says `Gate::egress` hands a frame's decision the rules and tables of
//! the frame's source and no other's, and each judge's guarantee is stated of
//! those tables alone. This module adds that the guarantee leaves no choice:
//! two runs of a judge on the same frame at the same instant, with the same
//! rules, from tables that hold the same records, reach the same kind of
//! result, and so both admit or both refuse. Nothing another box's tables
//! hold, and nothing about how a table keeps its records, can turn one into
//! the other.
//!
//! THEOREM IS1, for every plan, rule set, frame, instant and pair of runs:
//!   (a) [`theorem_is1_row`]: two results that each satisfy a row's
//!       guarantee from tables with the same holdings are of the same kind
//!       ([`same_kind`]) and admit alike;
//!   (b) [`theorem_is1_node`]: the same for the node;
//!   (c) [`theorem_is1_cohort`]: the same for the cohort, over the node's
//!       tables and the cohort's DNS tables.
//!
//! Two results of the same kind are equal, except that two DNS admissions
//! may differ in whether a flow was recorded, and both admit; one goes by a
//! live flow exactly when the other does.
//!
//! THEOREM IS2 (every admit has its reason), for every result that satisfies
//! a judge's guarantee and admits the frame, one of these holds:
//!   (a) [`theorem_is2_row`]: the row's stateless table admits it; or it is a
//!       reply on a live record of this box's own reply table; or the refusal
//!       of a connect this box's own notes hold; or the stateless table said
//!       "undeclared subnet" and the row's own DNS tables cover the frame, or
//!       the row names the host alias, or the box-name rule allows it;
//!   (b) [`theorem_is2_node`], (c) [`theorem_is2_cohort`]: the same for the
//!       node and the cohort, whose one lift is their own DNS tables.
//! So a box whose tables hold nothing ([`holds_nothing`]) is admitted exactly
//! what its rules and names admit: [`theorem_is2_row_from_nothing`].
//!
//! What it does not say: that two gates route a frame to the same judge
//! (RT1 says the route is a function of the frame and the configuration), or
//! that the tables after the two runs hold the same records.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::cohort::{
    CohortArm, CohortJudged, Member, cohort_admits, cohort_judged_ok, cohort_pin_lift, cohort_post,
    cohort_spec,
};
#[cfg(verus_keep_ghost)]
use crate::judge::{
    BoxNameRule, BoxTables, Judged, Lifts, Sent, alias_lift, box_rule, dest_of_sent, judged_ok,
    liftable, pin_lift, refusal_ok, reply_ok, row_post,
};
#[cfg(verus_keep_ghost)]
use crate::node::{
    NodeArm, NodeJudged, node_admits, node_judged_ok, node_pin_lift, node_post, node_spec,
};
#[cfg(verus_keep_ghost)]
use crate::pins::{Egress, Pins};
#[cfg(verus_keep_ghost)]
use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::row::{Cidr, RowRules, admits, row_spec};

#[cfg(verus_keep_ghost)]
verus! {

/// Two sets of DNS tables belong to one address and hold the same flows and
/// the same admitted addresses.
pub open spec fn same_pins_held(a: Pins, b: Pins) -> bool {
    &&& crate::pins::owner_of(a) == crate::pins::owner_of(b)
    &&& crate::pins::flows(a) == crate::pins::flows(b)
    &&& crate::pins::admitted(a) == crate::pins::admitted(b)
}

/// Two boxes' tables belong to one address and hold the same records.
pub open spec fn same_holdings(a: BoxTables, b: BoxTables) -> bool {
    &&& crate::flow::box_of(a.flows) == crate::flow::box_of(b.flows)
    &&& crate::flow::table(a.flows) == crate::flow::table(b.flows)
    &&& crate::notes::box_of(a.notes) == crate::notes::box_of(b.notes)
    &&& crate::notes::table(a.notes) == crate::notes::table(b.notes)
    &&& same_pins_held(a.pins, b.pins)
}

/// The same result, or two DNS admissions of which both or neither went by a
/// live flow.
pub open spec fn same_kind(a: Judged, b: Judged) -> bool {
    a == b || (a is Pinned && b is Pinned
        && (a == Judged::Pinned(Egress::ByFlow)) == (b == Judged::Pinned(Egress::ByFlow)))
}

/// The same result, or two DNS admissions of which both or neither went by a
/// live flow.
pub open spec fn same_node_kind(a: NodeJudged, b: NodeJudged) -> bool {
    a == b || (a is Pinned && b is Pinned
        && (a == NodeJudged::Pinned(Egress::ByFlow)) == (b == NodeJudged::Pinned(Egress::ByFlow)))
}

/// The same result, or two DNS admissions of which both or neither went by a
/// live flow.
pub open spec fn same_cohort_kind(a: CohortJudged, b: CohortJudged) -> bool {
    a == b || (a is Pinned && b is Pinned
        && (a == CohortJudged::Pinned(Egress::ByFlow)) == (b == CohortJudged::Pinned(Egress::ByFlow)))
}

/// IS1 (a).
pub proof fn theorem_is1_row(
    plan: Plan,
    rules: RowRules,
    lifts: Lifts,
    alias_open: bool,
    b1: BoxTables,
    a1: BoxTables,
    b2: BoxTables,
    a2: BoxTables,
    sent: Sent,
    now_ms: u64,
    r1: Judged,
    r2: Judged,
)
    requires
        same_holdings(b1, b2),
        row_post(plan, rules, lifts, alias_open, b1, a1, sent, now_ms, r1),
        row_post(plan, rules, lifts, alias_open, b2, a2, sent, now_ms, r2),
    ensures
        same_kind(r1, r2),
        judged_ok(r1) == judged_ok(r2),
{
}

/// IS1 (b).
pub proof fn theorem_is1_node(
    plan: Plan,
    baseline: Seq<Cidr>,
    alias_open: bool,
    dst_is_row: bool,
    b1: BoxTables,
    a1: BoxTables,
    b2: BoxTables,
    a2: BoxTables,
    sent: Sent,
    now_ms: u64,
    r1: NodeJudged,
    r2: NodeJudged,
)
    requires
        same_holdings(b1, b2),
        node_post(plan, baseline, alias_open, dst_is_row, b1, a1, sent, now_ms, r1),
        node_post(plan, baseline, alias_open, dst_is_row, b2, a2, sent, now_ms, r2),
    ensures
        same_node_kind(r1, r2),
        node_judged_ok(r1) == node_judged_ok(r2),
{
}

/// IS1 (c).
pub proof fn theorem_is1_cohort(
    plan: Plan,
    members: Seq<Member>,
    alias_open: bool,
    b1: BoxTables,
    a1: BoxTables,
    p1: Pins,
    q1: Pins,
    b2: BoxTables,
    a2: BoxTables,
    p2: Pins,
    q2: Pins,
    sent: Sent,
    now_ms: u64,
    r1: CohortJudged,
    r2: CohortJudged,
)
    requires
        same_holdings(b1, b2),
        same_pins_held(p1, p2),
        cohort_post(plan, members, alias_open, b1, a1, p1, q1, sent, now_ms, r1),
        cohort_post(plan, members, alias_open, b2, a2, p2, q2, sent, now_ms, r2),
    ensures
        same_cohort_kind(r1, r2),
        cohort_judged_ok(r1) == cohort_judged_ok(r2),
{
}

/// The tables hold no record of any kind that can admit a frame.
pub open spec fn holds_nothing(t: BoxTables) -> bool {
    &&& crate::flow::table(t.flows).len() == 0
    &&& crate::notes::table(t.notes).len() == 0
    &&& crate::pins::flows(t.pins).len() == 0
    &&& crate::pins::admitted(t.pins).len() == 0
}

/// IS2 (a).
pub proof fn theorem_is2_row(
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
        row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, r),
        judged_ok(r),
    ensures
        admits(row_spec(plan, rules, alias_open, dest_of_sent(sent)))
            || reply_ok(plan, before.flows, sent, now_ms)
            || refusal_ok(plan, before.notes, sent, now_ms)
            || (liftable(plan, rules, alias_open, sent) && (pin_lift(lifts, before.pins, sent, now_ms)
            || alias_lift(plan, lifts, sent) || box_rule(lifts, sent) == BoxNameRule::Allowed)),
{
}

/// IS2 (b).
pub proof fn theorem_is2_node(
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
        node_judged_ok(r),
    ensures
        node_admits(node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent)))
            || reply_ok(plan, before.flows, sent, now_ms)
            || refusal_ok(plan, before.notes, sent, now_ms)
            || (node_spec(plan, baseline, alias_open, dst_is_row, dest_of_sent(sent)) == NodeArm::Unpinned
            && node_pin_lift(before, sent, now_ms)),
{
}

/// IS2 (c).
pub proof fn theorem_is2_cohort(
    plan: Plan,
    members: Seq<Member>,
    alias_open: bool,
    before: BoxTables,
    after: BoxTables,
    pins_before: Pins,
    pins_after: Pins,
    sent: Sent,
    now_ms: u64,
    r: CohortJudged,
)
    requires
        cohort_post(plan, members, alias_open, before, after, pins_before, pins_after, sent, now_ms, r),
        cohort_judged_ok(r),
    ensures
        cohort_admits(cohort_spec(plan, members, alias_open, dest_of_sent(sent)))
            || reply_ok(plan, before.flows, sent, now_ms)
            || refusal_ok(plan, before.notes, sent, now_ms)
            || (cohort_spec(plan, members, alias_open, dest_of_sent(sent)) == CohortArm::NeedsPin
            && cohort_pin_lift(pins_before, sent, now_ms)),
{
}

/// IS2 for a row whose tables hold nothing: it is admitted what its rules
/// admit, and beyond them only the host alias by name or a box name.
pub proof fn theorem_is2_row_from_nothing(
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
        holds_nothing(before),
        row_post(plan, rules, lifts, alias_open, before, after, sent, now_ms, r),
        judged_ok(r),
    ensures
        admits(row_spec(plan, rules, alias_open, dest_of_sent(sent)))
            || (liftable(plan, rules, alias_open, sent) && (alias_lift(plan, lifts, sent)
            || box_rule(lifts, sent) == BoxNameRule::Allowed)),
{
}

} // verus!
