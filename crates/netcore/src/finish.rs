//! The second half of a decision, for a caller that holds one box's tables.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! [`crate::split::Config::egress_first`] says, from a frame's bytes, what
//! the frame is, which box decides it and what that box's judge needs
//! besides its tables. This module is the rest: handed that answer whole and
//! the box's tables, it runs the judge with the rules, the lifts, the
//! baseline or the members of the configuration itself. A caller passes no
//! rule, no lift and no index of its own, and reads no field of the frame.
//!
//! THEOREM FN1, for a row, the node and the cohort:
//!   (a) handed a frame whose arm is its own kind's, a call returns that
//!       kind's judge's result, and the tables change, as the judge
//!       guarantees for the configuration's own rules, lifts, alias state,
//!       baseline or members ([`crate::judge::row_post`],
//!       [`crate::node::node_post`], [`crate::cohort::cohort_post`]);
//!   (b) handed anything else, a call changes no table and returns the drop
//!       the first half already was (what is no frame, a short transport
//!       header, a stray source, the DNS refusal of a row or of the cohort),
//!       or, for a frame of another kind, `Misrouted`: never another box's
//!       decision;
//!   (c) a row's call handed tables whose owner is not the row's address
//!       changes nothing and returns `Misrouted`;
//!   (d) no call admits a frame it did not hand to a judge
//!       ([`outcome_admits`] is false of every drop).
//!
//! THEOREM FN2: `finish_ingress` records a frame toward a box as
//! [`crate::ingress::observe`] guarantees, with the proxy's address taken
//! from the configuration's plan; what is not a TCP or UDP first fragment
//! with a whole header reaches no table.
//!
//! THEOREM SP2, the two halves are the gate's decision: for a gate and a
//! configuration that is the gate's ([`crate::split::is_config_of`]), a
//! frame the first half routes to a row, the node or the cohort, and any
//! result and tables that satisfy what the second half guarantees when run
//! on the gate's own tables for that box, the result and the tables satisfy
//! the clause of [`crate::gate::Gate::egress`]'s guarantee for that route.
//! With IS1 (a result that satisfies a judge's guarantee is settled by what
//! the tables hold) the two-step decision is the gate's. This closes what
//! SP1 leaves "shown by example".
//!
//! THEOREM FN3: `tables_for` gives the three empty tables of one owner
//! address, sound, or nothing; `empty` gives a sound configuration with no
//! row, no member, no baseline and the alias open nowhere.
//!
//! Not here: that the tables are locked, and the configuration read, for the
//! length of both halves. That is the caller's, and is why the two halves
//! speak of one configuration.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::alias::AliasState;
#[cfg(verus_keep_ghost)]
use crate::cohort::cohort_post;
use crate::cohort::{CohortJudged, cohort_judged_admits, judge_cohort};
use crate::flow::{Flows, Windows};
use crate::frame::Reason;
use crate::gate::Stray;
#[cfg(verus_keep_ghost)]
use crate::ingress::seen_post;
use crate::ingress::{Heard, Seen, observe};
use crate::judge::{BoxTables, Judged, judge_row, judged_admits};
#[cfg(verus_keep_ghost)]
use crate::judge::{owners_same, pins_same, row_post, tinv};
#[cfg(verus_keep_ghost)]
use crate::node::node_post;
use crate::node::{NodeJudged, judge_node, node_judged_admits};
use crate::notes::Notes;
use crate::origin::Sources;
#[cfg(verus_keep_ghost)]
use crate::origin::{plan_of, rows_of, sinv};
use crate::pins::Pins;
#[cfg(verus_keep_ghost)]
use crate::pins::{owner_of, pinv};
#[cfg(verus_keep_ghost)]
use crate::plan::spec_proxy_peer;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
#[cfg(verus_keep_ghost)]
use crate::split::cinv;
use crate::split::{Arm, Config, First};
use crate::time::{Instant, Span};

/// The sizes and windows of one box's three tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct TableLimits {
    /// The reply table's windows and how many records it holds.
    pub windows: Windows,
    pub flows_cap: usize,
    /// How long the reply table waits between sweeps at its capacity.
    pub sweep: Span,
    /// The refusal notes: how many, how many for one client, and for how
    /// long.
    pub notes_cap: usize,
    pub notes_per_client: usize,
    pub note_window: Span,
    /// The DNS tables.
    pub pins: crate::pins::Limits,
}

/// How a frame a guest sent ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Outcome {
    /// Drop: neither an IPv4 datagram nor an ARP packet, and why.
    NotAFrame(Reason),
    /// Drop: TCP or UDP on a first fragment without a whole header.
    ShortHeader,
    /// Drop: the source is no row, not the node and not the cohort.
    Refused(Stray),
    /// Drop: the row at this index may ask the resolver only about names in
    /// the zone, and this was not such a query.
    RowDns(usize),
    /// Drop: the same for the cohort.
    CohortDns,
    /// Drop: the frame was handed to a call that is not its kind's, or with
    /// tables that are not its box's. No judge was asked.
    Misrouted,
    /// The row at this index, as its judge decided.
    Row(usize, Judged),
    /// The node, as its judge decided.
    Node(NodeJudged),
    /// The cohort, as its judge decided.
    Cohort(CohortJudged),
}

#[cfg(verus_keep_ghost)]
verus! {

/// What the first half comes to when no judge is asked: its own drop, or
/// `Misrouted` for a frame some judge decides.
pub open spec fn unjudged(first: First) -> Outcome {
    match first {
        First::NotAFrame(why) => Outcome::NotAFrame(why),
        First::ShortHeader => Outcome::ShortHeader,
        First::Frame { frame: _, facts: _, with: _, arm } => match arm {
            Arm::Refused(s) => Outcome::Refused(s),
            Arm::RowDns(i) => Outcome::RowDns(i),
            Arm::CohortDns => Outcome::CohortDns,
            Arm::Row(_, _) => Outcome::Misrouted,
            Arm::Node(_) => Outcome::Misrouted,
            Arm::Cohort(_) => Outcome::Misrouted,
        },
    }
}

/// The first half names the row at `i` of this configuration, and `t` are
/// tables whose reply records belong to that row's address.
pub open spec fn rows_frame(c: Config, first: First, t: BoxTables, i: int) -> bool {
    &&& first matches First::Frame { frame: _, facts: _, with: _, arm: Arm::Row(j, _) }
    &&& j as int == i
    &&& 0 <= i < c.decls@.len()
    &&& i < rows_of(c.sources).len()
    &&& crate::flow::box_of(t.flows) == rows_of(c.sources)[i]
}

pub open spec fn nodes_frame(first: First) -> bool {
    first matches First::Frame { frame: _, facts: _, with: _, arm: Arm::Node(_) }
}

pub open spec fn cohorts_frame(first: First) -> bool {
    first matches First::Frame { frame: _, facts: _, with: _, arm: Arm::Cohort(_) }
}

/// FN1 (d): the outcome admits the frame.
pub open spec fn outcome_admits_spec(o: Outcome) -> bool {
    match o {
        Outcome::Row(_, j) => crate::judge::judged_ok(j),
        Outcome::Node(j) => crate::node::node_judged_ok(j),
        Outcome::Cohort(j) => crate::cohort::cohort_judged_ok(j),
        _ => false,
    }
}

/// SP2 for a row: what `finish_row` guarantees, on the gate's own tables for
/// the row the first half named, is what `Gate::egress` guarantees of
/// `Decision::Row`.
pub proof fn theorem_sp2_a_rows_decision_is_the_gates(
    c: Config,
    g: crate::gate::Gate,
    f: crate::route::Frame,
    w: crate::split::EgressFor,
    i: usize,
    after: BoxTables,
    j: Judged,
    now_ms: u64,
)
    requires
        crate::split::is_config_of(c, g),
        crate::gate::ginv(g),
        crate::split::egress_for_post(c, f, w),
        w.route == crate::route::Route::Row(i),
        row_post(plan_of(c.sources), rules_of(c.decls@[i as int].rules), w.lifts, w.alias_open,
            crate::gate::rows_view(g)[i as int].tables, after, f.sent, now_ms, j),
    ensures
        i < crate::gate::rows_view(g).len(),
        rows_of(crate::gate::sources_of(g))[i as int] == f.sent.src,
        crate::origin::first_at(rows_of(crate::gate::sources_of(g)), f.sent.src, i as int),
        !crate::origin::is_cohort(crate::gate::sources_of(g), f.sent.src, crate::route::v4(f), f.dscp),
        !crate::origin::is_node(crate::gate::sources_of(g), f.sent.src, crate::route::v4(f), f.dscp),
        row_post(
            plan_of(crate::gate::sources_of(g)),
            rules_of(crate::gate::rows_view(g)[i as int].rules),
            crate::gate::lifts_of(g, i as int, f),
            crate::gate::alias_for(g, crate::gate::row_asks(g, crate::gate::rows_view(g)[i as int]), f),
            crate::gate::rows_view(g)[i as int].tables,
            after,
            f.sent,
            now_ms,
            j,
        ),
{
    reveal(crate::gate::rows_bound);
    crate::split::theorem_sp1_egress_reads_the_gates(c, g, f, i as int, crate::split::row_source(c, i as int), w.route);
}

/// SP2 for the node.
pub proof fn theorem_sp2_the_nodes_decision_is_the_gates(
    c: Config,
    g: crate::gate::Gate,
    f: crate::route::Frame,
    w: crate::split::EgressFor,
    after: BoxTables,
    j: NodeJudged,
    now_ms: u64,
)
    requires
        crate::split::is_config_of(c, g),
        crate::gate::ginv(g),
        crate::split::egress_for_post(c, f, w),
        w.route == crate::route::Route::Node,
        node_post(plan_of(c.sources), c.baseline@, w.alias_open, w.to_row,
            crate::gate::node_of(g), after, f.sent, now_ms, j),
    ensures
        crate::origin::is_node(crate::gate::sources_of(g), f.sent.src, crate::route::v4(f), f.dscp),
        node_post(
            plan_of(crate::gate::sources_of(g)),
            crate::gate::baseline_of(g),
            crate::gate::alias_for(g, crate::alias::AliasSource::Node, f),
            crate::gate::dst_is_row(g, f),
            crate::gate::node_of(g),
            after,
            f.sent,
            now_ms,
            j,
        ),
{
}

/// SP2 for the cohort.
pub proof fn theorem_sp2_the_cohorts_decision_is_the_gates(
    c: Config,
    g: crate::gate::Gate,
    f: crate::route::Frame,
    w: crate::split::EgressFor,
    after: BoxTables,
    pins_after: Pins,
    j: CohortJudged,
    now_ms: u64,
)
    requires
        crate::split::is_config_of(c, g),
        crate::gate::ginv(g),
        crate::split::egress_for_post(c, f, w),
        w.route == crate::route::Route::Cohort,
        cohort_post(plan_of(c.sources), c.members@, w.alias_open,
            crate::gate::cohort_tables(g), after, crate::gate::cohort_pins_of(g), pins_after, f.sent, now_ms, j),
    ensures
        crate::origin::is_cohort(crate::gate::sources_of(g), f.sent.src, crate::route::v4(f), f.dscp),
        cohort_post(
            plan_of(crate::gate::sources_of(g)),
            crate::gate::members_of(g),
            crate::gate::alias_for(g, crate::alias::AliasSource::Cohort, f),
            crate::gate::cohort_tables(g),
            after,
            crate::gate::cohort_pins_of(g),
            pins_after,
            f.sent,
            now_ms,
            j,
        ),
{
}

/// FN1 (b), (d): what no judge was asked about is not admitted.
pub proof fn theorem_fn1_a_drop_admits_nothing(first: First)
    ensures
        !outcome_admits_spec(unjudged(first)),
{
}

} // verus!

/// Whether the outcome admits the frame. FN1 (d).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == outcome_admits_spec(o),
))]
pub fn outcome_admits(o: Outcome) -> bool {
    match o {
        Outcome::Row(_, j) => judged_admits(j),
        Outcome::Node(j) => node_judged_admits(j),
        Outcome::Cohort(j) => cohort_judged_admits(j),
        Outcome::NotAFrame(_) => false,
        Outcome::ShortHeader => false,
        Outcome::Refused(_) => false,
        Outcome::RowDns(_) => false,
        Outcome::CohortDns => false,
        Outcome::Misrouted => false,
    }
}

/// What the first half comes to when no judge is asked.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == unjudged(first),
))]
fn dropped(first: First) -> Outcome {
    match first {
        First::NotAFrame(why) => Outcome::NotAFrame(why),
        First::ShortHeader => Outcome::ShortHeader,
        First::Frame { arm, .. } => match arm {
            Arm::Refused(s) => Outcome::Refused(s),
            Arm::RowDns(i) => Outcome::RowDns(i),
            Arm::CohortDns => Outcome::CohortDns,
            Arm::Row(_, _) => Outcome::Misrouted,
            Arm::Node(_) => Outcome::Misrouted,
            Arm::Cohort(_) => Outcome::Misrouted,
        },
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Config {
    /// Finishes the decision of a frame from a registered row. `t` are that
    /// row's tables. FN1 (a), (b), (c).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
            tinv(*old(t)),
        ensures
            tinv(*final(t)),
            owners_same(*final(t), *old(t)),
            match first {
                First::Frame { frame, facts: _, with, arm: Arm::Row(i, _) } => {
                    if rows_frame(*self, first, *old(t), i as int) {
                        &&& r matches Outcome::Row(k, j)
                        &&& k == i
                        &&& row_post(plan_of(self.sources), rules_of(self.decls@[i as int].rules),
                            with.lifts, with.alias_open, *old(t), *final(t), frame.sent, now.ms, j)
                    } else {
                        *final(t) == *old(t) && r == Outcome::Misrouted
                    }
                },
                _ => *final(t) == *old(t) && r == unjudged(first),
            },
    ))]
    pub fn finish_row(&self, first: First, t: &mut BoxTables, now: Instant) -> Outcome {
        match first {
            First::Frame {
                frame,
                with,
                arm: Arm::Row(i, _),
                ..
            } => {
                if i >= self.decls.len() || i >= self.sources.len() {
                    return Outcome::Misrouted;
                }
                if t.flows.box_addr() != self.sources.address(i) {
                    return Outcome::Misrouted;
                }
                let plan = self.sources.plan();
                let j = judge_row(
                    &plan,
                    &self.decls[i].rules,
                    with.lifts,
                    with.alias_open,
                    t,
                    frame.sent,
                    now,
                );
                Outcome::Row(i, j)
            }
            _ => dropped(first),
        }
    }

    /// Finishes the decision of a frame from the node. `t` are the node's
    /// own tables. FN1 (a), (b).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
            tinv(*old(t)),
        ensures
            tinv(*final(t)),
            owners_same(*final(t), *old(t)),
            match first {
                First::Frame { frame, facts: _, with, arm: Arm::Node(_) } => {
                    &&& r matches Outcome::Node(j)
                    &&& node_post(plan_of(self.sources), self.baseline@, with.alias_open, with.to_row,
                        *old(t), *final(t), frame.sent, now.ms, j)
                },
                _ => *final(t) == *old(t) && r == unjudged(first),
            },
    ))]
    pub fn finish_node(&self, first: First, t: &mut BoxTables, now: Instant) -> Outcome {
        match first {
            First::Frame {
                frame,
                with,
                arm: Arm::Node(_),
                ..
            } => {
                let plan = self.sources.plan();
                let j = judge_node(
                    &plan,
                    self.baseline.as_slice(),
                    with.alias_open,
                    with.to_row,
                    t,
                    frame.sent,
                    now,
                );
                Outcome::Node(j)
            }
            _ => dropped(first),
        }
    }

    /// Finishes the decision of a frame from the cohort. `node` are the
    /// tables that hold the cohort's reply records and notes (the node's
    /// where the two share an address, the cohort's own otherwise); `pins`
    /// are the cohort's own DNS tables. FN1 (a), (b).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
            tinv(*old(node)),
            pinv(*old(pins)),
        ensures
            tinv(*final(node)),
            pinv(*final(pins)),
            owners_same(*final(node), *old(node)),
            owner_of(*final(pins)) == owner_of(*old(pins)),
            match first {
                First::Frame { frame, facts: _, with, arm: Arm::Cohort(_) } => {
                    &&& r matches Outcome::Cohort(j)
                    &&& cohort_post(plan_of(self.sources), self.members@, with.alias_open,
                        *old(node), *final(node), *old(pins), *final(pins), frame.sent, now.ms, j)
                },
                _ => *final(node) == *old(node) && *final(pins) == *old(pins) && r == unjudged(first),
            },
    ))]
    pub fn finish_cohort(
        &self,
        first: First,
        node: &mut BoxTables,
        pins: &mut Pins,
        now: Instant,
    ) -> Outcome {
        match first {
            First::Frame {
                frame,
                with,
                arm: Arm::Cohort(_),
                ..
            } => {
                let plan = self.sources.plan();
                let j = judge_cohort(
                    &plan,
                    self.members.as_slice(),
                    with.alias_open,
                    node,
                    pins,
                    frame.sent,
                    now,
                );
                Outcome::Cohort(j)
            }
            _ => dropped(first),
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Config {
    /// Finishes a frame toward a box: `heard` is what
    /// [`Config::ingress_first`] returned for it, `t` the tables of the box
    /// it named, `published` whether a forward dials that box at the
    /// frame's destination port. `None`: the frame reaches no table. FN2.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(self.sources),
            tinv(*old(t)),
        ensures
            tinv(*final(t)),
            owners_same(*final(t), *old(t)),
            pins_same(final(t).pins, old(t).pins),
            match heard {
                Heard::Transport(x) => {
                    &&& r matches Some(s)
                    &&& seen_post(spec_proxy_peer(plan_of(self.sources)), *old(t), *final(t), x, published, now.ms, s)
                },
                _ => r is None && *final(t) == *old(t),
            },
    ))]
    pub fn finish_ingress(
        &self,
        heard: Heard,
        t: &mut BoxTables,
        published: bool,
        now: Instant,
    ) -> Option<Seen> {
        match heard {
            Heard::Transport(x) => {
                let plan = self.sources.plan();
                Some(observe(plan.proxy_peer(), t, x, published, now))
            }
            _ => None,
        }
    }
}

/// The three empty tables of the box at `addr`, or `None` when a limit is
/// one a table refuses. FN3.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Some(t) => {
                &&& tinv(t)
                &&& crate::flow::box_of(t.flows) == addr
                &&& crate::notes::box_of(t.notes) == addr
                &&& owner_of(t.pins) == addr
                &&& crate::flow::table(t.flows).len() == 0
                &&& crate::notes::table(t.notes).len() == 0
                &&& crate::pins::asked(t.pins).len() == 0
                &&& crate::pins::admitted(t.pins).len() == 0
                &&& crate::pins::flows(t.pins).len() == 0
            },
            None => true,
        },
))]
pub fn tables_for(addr: u32, l: TableLimits) -> Option<BoxTables> {
    let flows = match Flows::new(addr, l.flows_cap, l.windows, l.sweep) {
        Some(x) => x,
        None => {
            return None;
        }
    };
    let notes = match Notes::new(addr, l.notes_cap, l.notes_per_client, l.note_window) {
        Some(x) => x,
        None => {
            return None;
        }
    };
    let pins = match Pins::new(addr, l.pins) {
        Some(x) => x,
        None => {
            return None;
        }
    };
    Some(BoxTables { flows, notes, pins })
}

/// A configuration with no row, no member and no baseline entry, over
/// sources that hold no row, with the alias's state as the caller gives it:
/// which ports the host's own listeners hold there is the caller's to say,
/// and this function makes no state of its own for it. FN3.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        sinv(sources),
        rows_of(sources).len() == 0,
    ensures
        cinv(r),
        r.sources == sources,
        r.decls@.len() == 0,
        r.baseline@.len() == 0,
        r.members@.len() == 0,
        r.alias == alias,
))]
pub fn empty(sources: Sources, alias: AliasState) -> Config {
    Config {
        sources,
        decls: Vec::new(),
        baseline: Vec::new(),
        members: Vec::new(),
        alias,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_no_frame_is_dropped_by_every_call_and_admits_nothing() {
        let first = First::ShortHeader;
        assert_eq!(dropped(first), Outcome::ShortHeader);
        assert!(!outcome_admits(dropped(first)));
        assert!(!outcome_admits(Outcome::Misrouted));
        assert!(!outcome_admits(Outcome::RowDns(0)));
        assert!(!outcome_admits(Outcome::CohortDns));
    }
}
