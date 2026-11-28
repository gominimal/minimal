//! The host gate's per-frame decision, both directions, over one state.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! [`Gate`] holds everything the decision reads: the sources, every row's
//! rules and tables, the node's tables and baseline, the cohort's members and
//! DNS tables, the ledger of published forwards and the host alias's state.
//! [`Gate::egress`] routes a frame a guest sent by its source and runs that
//! source's decision on that source's state. [`Gate::ingress`] records what a
//! frame toward a guest does, in the tables of the box it is addressed to.
//! [`Gate::register`] and [`Gate::retire`] add and remove rows;
//! [`Gate::publish`], [`Gate::retract`] and [`Gate::set_alias`] are the only
//! other ways the state changes. Nothing is told to the gate per frame but
//! the frame and the time.
//!
//! THEOREM GE1, for every gate and every frame a guest sent:
//!   (a) a frame from row `i` is decided with row `i`'s rules and tables, and
//!       those tables belong to the frame's source address; the node's and
//!       the cohort's frames are decided with tables that belong to theirs;
//!   (b) the result carries the guarantee of the decision that made it
//!       (J1, NJ1 or CJ1), about that state before and after;
//!   (c) nothing else changes: a row frame leaves every other row, the node
//!       and the cohort as they were; a node or cohort frame leaves every
//!       row as it was; a stray changes nothing; a frame its source's
//!       decision refuses changes nothing but removing the frame's own
//!       expired record from that source's reply table, and a frame it
//!       admits other than as a reply changes that table no further;
//!   (d) a frame from a source that is no row, not the node and not the
//!       cohort is refused, and [`Decision::admits`] is false of it.
//!
//! THEOREM GI1, for every gate and every frame toward a guest:
//!   (a) a frame to the node's address, while its baseline is in force, is
//!       recorded in the node's tables; one to the cohort's own address,
//!       under that spelling, in the cohort's; any other in the tables of
//!       the first row holding the destination address; a frame to no row
//!       is delivered and nothing is recorded;
//!   (b) the result carries IG1 about those tables, with "published" read
//!       from the gate's own ledger;
//!   (c) no table turns the frame away as another box's;
//!   (d) nothing else changes.
//!
//! THEOREM GR1, for every gate:
//!   (a) `register` adds one row after the others and `retire` removes one;
//!       neither changes any other row, the node, the cohort, the ledger or
//!       the alias;
//!   (b) a registered row's tables belong to its address and hold nothing,
//!       whatever they held when they were handed in;
//!   (c) tables that hold nothing admit nothing (`theorem_fresh_admits_nothing`):
//!       no record of a row that held an address before admits a frame of
//!       the row registered there after.
//!
//! THEOREM GC1, for every gate: `clear_at` and `clear_node` empty the named
//! tables of one row, or of the node, and change nothing else: the row stays,
//! its rules and name stay, the tables keep their owner and settings, and a
//! cleared DNS table's epoch is raised.
//!
//! THEOREM GD0, for every gate:
//!   (a) a gate starts with every DNS table empty, whatever the tables it
//!       was built from held, so an admission enters a gate only through the
//!       gate's own answer operation;
//!   (b) `dns_ask` records a question in the table the query's source and
//!       mark name (`ask_route`), as `Pins::ask` promises, and changes
//!       nothing else; a query from no row, not the node and not the cohort
//!       is recorded nowhere;
//!   (c) `dns_expire` removes expired questions of one table and nothing
//!       else: no admission, no flow, no other table.
//!
//! THEOREM GD1, for every gate and every DNS reply addressed to `dst`:
//!   (a) the reply is offered to the table an unmarked query from `dst`
//!       would be recorded in (`answer_own`), and, under the mark spelling
//!       at the node's address, to the cohort's table as well, in every
//!       phase of the baseline: a reply carries no mark, so both may have
//!       asked. Every table a question can be recorded in for a source is
//!       offered the replies to that source;
//!   (b) each table offered a name and addresses changes as `Pins::resolve`
//!       promises of that name and those addresses, its own; a table offered
//!       no name, or not offered, is as it was;
//!   (c) nothing else changes: no reply record, no note, no other row, no
//!       ledger entry, and never the cohort's own tables' DNS part;
//!   (d) so an address is admitted in a table only if that table held a
//!       live question for the name that table was given.
//!
//! THEOREM GB1, for every gate:
//!   (a) `adopt_baseline` sets the baseline's phase and entries and empties
//!       the node's DNS tables, in both places a node's question can be
//!       recorded: the node's own tables, and the row at the node's address
//!       if there is one. What the node resolved under the old baseline
//!       lifts nothing under the new one;
//!   (b) it leaves the cohort's DNS tables as they were: an address a
//!       host-address box resolved before the baseline came into force is
//!       still admitted after;
//!   (c) `clear_cohort_dns` empties the cohort's DNS tables and nothing else;
//!   (d) neither changes a reply record, a note, another row, the ledger or
//!       the alias state.
//!
//! The caller adopts a baseline exactly when its phase or its entries
//! change: adopting the same baseline again would empty the node's DNS
//! tables.
//!
//! The gate is not shown the query. That it was a DNS query to the plan's
//! resolver, that `egress` admitted it and that it was sent on are the
//! caller's.
//!
//! "Published" asks whether some forward dials the destination address at
//! the destination port.
//!
//! The cohort's reply records and notes live where its address does. Under
//! [`CohortSpelling::NodeWithMark`] the cohort sends from the node's address
//! and the two share the node's tables. Under
//! [`CohortSpelling::OwnAddress`] the cohort has its own tables: `ingress`
//! records a frame to the cohort's address there, `egress` answers from
//! there, and neither touches the node's. Its DNS tables are its own under
//! both.
//!
//! What arrives at the cohort's address is the return half of connections a
//! host-address box opened, and strays. A connection *to* a host-address box
//! is dialled at the node's address, and its replies leave from there
//! unmarked: they are the node's frames under either spelling, recorded in
//! and answered from the node's tables.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::alias::alias_spec;
use crate::alias::{AliasSource, AliasState, alias_open};
use crate::cohort::{CohortJudged, Member, cohort_judged_admits, judge_cohort};
#[cfg(verus_keep_ghost)]
use crate::cohort::{cohort_judged_ok, cohort_post};
use crate::ingress::{Received, Seen, observe, seen_delivers};
#[cfg(verus_keep_ghost)]
use crate::ingress::{delivers, for_this_box, seen_post};
use crate::judge::{
    BoxNameRule, BoxTables, Judged, Lifts, SentKind, judge_row, judged_admits, sent_dst,
};
#[cfg(verus_keep_ghost)]
use crate::judge::{Sent, owners_same};
#[cfg(verus_keep_ghost)]
use crate::judge::{box_rule, dest_of_sent, dst_of, judged_ok, lemma_box_rule_own, row_post, tinv};
use crate::ledger::{Forward, Ledger, Published};
#[cfg(verus_keep_ghost)]
use crate::ledger::{dials, dials_in, linv, lview, publish_post, retract_post, same_caps};
use crate::node::{NodeJudged, judge_node, node_judged_admits};
#[cfg(verus_keep_ghost)]
use crate::node::{node_judged_ok, node_post};
use crate::origin::{CohortSpelling, Sources};
#[cfg(verus_keep_ghost)]
use crate::origin::{
    allocatable, first_at, in_force_of, is_cohort, is_node, plan_of, registered, rows_of, sinv,
    spelling_of,
};
use crate::pins::{Admits, Asked, Pins};
#[cfg(verus_keep_ghost)]
use crate::pins::{ask_post, expire_questions_post, owner_of, pinv, resolve_post};
#[cfg(verus_keep_ghost)]
use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_cohort, spec_contains, spec_host_alias, spec_node, spec_proxy_peer};
use crate::policy::Rules;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
use crate::rebind::floor;
#[cfg(verus_keep_ghost)]
use crate::rebind::{floor_ok, floored};
use crate::route::{Frame, Route, route};
#[cfg(verus_keep_ghost)]
use crate::route::{at_control_surface, stray, v4};
#[cfg(verus_keep_ghost)]
use crate::row::allow_covers;
use crate::row::{Cidr, allowed_subnet};
use crate::time::Instant;

/// One registered row: what it declared, and its tables.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct RowState {
    pub rules: Rules,
    /// The row declares DNS hosts.
    pub resolves_names: bool,
    /// The row's DNS hosts name the host alias.
    pub alias_by_name: bool,
    /// The row's own box name, as a number the shell assigns: two rows have
    /// the same number exactly when they have the same canonical name.
    pub name_id: u32,
    /// The row is a task sandbox's, not a box's own lease. No name covers it.
    pub task_row: bool,
    /// The box names the row's DNS hosts list, as the shell's numbers.
    pub names_boxes: Vec<u32>,
    pub tables: BoxTables,
}

/// One of the gate's DNS tables: the row's at an address, the node's, or the
/// cohort's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum DnsTable {
    Row(u32),
    Node,
    Cohort,
}

/// What a DNS reply did, and how many of its addresses failed the floor and
/// were dropped before any table saw them. A caller that filtered as the
/// product does sees zero for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Floored {
    pub answered: DnsAnswered,
    pub own_dropped: usize,
    pub cohort_dropped: usize,
}

/// What a DNS reply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct DnsAnswered {
    /// Under the mark spelling, at the node's address: what the cohort's
    /// table did with the reply. `None` when it was not offered, was given
    /// no name, or held no such question.
    pub cohort_at_node: Option<Admits>,
    /// The destination's own table, if it has one.
    pub own_table: Option<DnsTable>,
    /// What that table did with the reply. `None` when there is no such
    /// table, it was given no name, or it held no such question.
    pub own: Option<Admits>,
}

/// Why a frame was refused before any decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Stray {
    ControlSurface,
    Unregistered,
    Unknown,
}

/// What a frame toward a guest did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Arrived {
    /// Deliver; nothing recorded: no row holds the destination address.
    NotARow,
    /// For the row at this index.
    Row(usize, Seen),
    /// For the node.
    Node(Seen),
    /// For the cohort, at its own address.
    Cohort(Seen),
}

/// The gate's answer for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Decision {
    /// Drop: the source is no row, not the node and not the cohort.
    Refused(Stray),
    /// Decided as the row at this index.
    Row(usize, Judged),
    Node(NodeJudged),
    Cohort(CohortJudged),
}

/// Which of a target's tables to empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Which {
    /// The reply records and the notes.
    Records,
    /// The DNS tables.
    Dns,
    /// All three.
    All,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Gate {
    sources: Sources,
    rows: Vec<RowState>,
    node: BoxTables,
    cohort: BoxTables,
    baseline: Vec<Cidr>,
    members: Vec<Member>,
    cohort_pins: Pins,
    ledger: Ledger,
    alias: AliasState,
}

#[cfg(verus_keep_ghost)]
verus! {

pub closed spec fn sources_of(g: Gate) -> Sources { g.sources }
pub closed spec fn rows_view(g: Gate) -> Seq<RowState> { g.rows@ }
pub closed spec fn node_of(g: Gate) -> BoxTables { g.node }
pub closed spec fn cohort_of(g: Gate) -> BoxTables { g.cohort }
pub closed spec fn baseline_of(g: Gate) -> Seq<Cidr> { g.baseline@ }
pub closed spec fn members_of(g: Gate) -> Seq<Member> { g.members@ }
pub closed spec fn cohort_pins_of(g: Gate) -> Pins { g.cohort_pins }
pub closed spec fn ledger_of(g: Gate) -> Ledger { g.ledger }
pub closed spec fn alias_of(g: Gate) -> AliasState { g.alias }

/// The three tables belong to `addr`.
pub open spec fn owned_by(t: BoxTables, addr: u32) -> bool {
    &&& crate::flow::box_of(t.flows) == addr
    &&& crate::notes::box_of(t.notes) == addr
    &&& owner_of(t.pins) == addr
}

/// A row's tables are sound and belong to `addr`.
pub open spec fn row_bound(st: RowState, addr: u32) -> bool {
    tinv(st.tables) && owned_by(st.tables, addr)
}

/// Every row's tables are sound and belong to that row's address.
#[verifier::opaque]
pub open spec fn rows_bound(states: Seq<RowState>, addrs: Seq<u32>) -> bool {
    &&& states.len() == addrs.len()
    &&& forall|i: int| 0 <= i < states.len() ==> row_bound(#[trigger] states[i], addrs[i])
}

/// The address host-address boxes send from.
pub open spec fn cohort_addr(s: Sources) -> int {
    match spelling_of(s) {
        CohortSpelling::NodeWithMark => spec_node(plan_of(s)),
        CohortSpelling::OwnAddress => spec_cohort(plan_of(s)),
    }
}

/// The node's tables belong to the node's address; the cohort's own tables
/// and its DNS tables to the address the cohort sends from.
pub open spec fn shared_bound(node: BoxTables, cohort: BoxTables, cohort_pins: Pins, s: Sources) -> bool {
    &&& crate::flow::box_of(cohort.flows) as int == cohort_addr(s)
    &&& crate::notes::box_of(cohort.notes) as int == cohort_addr(s)
    &&& owner_of(cohort.pins) as int == cohort_addr(s)
    &&& crate::flow::box_of(node.flows) as int == spec_node(plan_of(s))
    &&& crate::notes::box_of(node.notes) as int == spec_node(plan_of(s))
    &&& owner_of(node.pins) as int == spec_node(plan_of(s))
    &&& owner_of(cohort_pins) as int == cohort_addr(s)
}

pub open spec fn ginv(g: Gate) -> bool {
    &&& sinv(sources_of(g))
    &&& rows_bound(rows_view(g), rows_of(sources_of(g)))
    &&& shared_bound(node_of(g), cohort_of(g), cohort_pins_of(g), sources_of(g))
    &&& tinv(node_of(g))
    &&& tinv(cohort_of(g))
    &&& pinv(cohort_pins_of(g))
    &&& linv(ledger_of(g))
}

/// The tables that hold the cohort's reply records and notes: the node's
/// under the mark spelling, where the two share an address; the cohort's own
/// under its own address.
pub open spec fn cohort_tables(g: Gate) -> BoxTables {
    match spelling_of(sources_of(g)) {
        CohortSpelling::NodeWithMark => node_of(g),
        CohortSpelling::OwnAddress => cohort_of(g),
    }
}

/// The other of the two: a cohort frame never touches it.
pub open spec fn cohort_spare(g: Gate) -> BoxTables {
    match spelling_of(sources_of(g)) {
        CohortSpelling::NodeWithMark => cohort_of(g),
        CohortSpelling::OwnAddress => node_of(g),
    }
}

/// The frame is addressed to the cohort's own address while the baseline is
/// in force. Never under the mark spelling: the cohort has no address of its
/// own there.
pub open spec fn to_cohort(g: Gate, r: Received) -> bool {
    in_force_of(sources_of(g)) && spelling_of(sources_of(g)) == CohortSpelling::OwnAddress
        && r.dst as int == spec_cohort(plan_of(sources_of(g)))
}

/// The tables hold no record at all.
pub open spec fn fresh(t: BoxTables) -> bool {
    &&& crate::flow::table(t.flows).len() == 0
    &&& crate::notes::table(t.notes).len() == 0
    &&& crate::pins::asked(t.pins).len() == 0
    &&& crate::pins::admitted(t.pins).len() == 0
    &&& crate::pins::flows(t.pins).len() == 0
}

/// Tables with no record admit nothing: no reply, no refusal, no DNS lift.
/// A row registered at an address another row held before starts here, so
/// nothing the earlier row recorded admits a frame of the later one.
pub proof fn theorem_fresh_admits_nothing(plan: Plan, t: BoxTables, sent: Sent, now_ms: u64)
    requires
        fresh(t),
    ensures
        !crate::judge::reply_ok(plan, t.flows, sent, now_ms),
        !crate::judge::refusal_ok(plan, t.notes, sent, now_ms),
        !crate::judge::pin_ok(t.pins, sent, now_ms),
{
}

/// Everything but the registered rows is as it was.
pub open spec fn only_rows_changed(now: Gate, before: Gate) -> bool {
    &&& plan_of(sources_of(now)) == plan_of(sources_of(before))
    &&& in_force_of(sources_of(now)) == in_force_of(sources_of(before))
    &&& spelling_of(sources_of(now)) == spelling_of(sources_of(before))
    &&& node_of(now) == node_of(before)
    &&& cohort_of(now) == cohort_of(before)
    &&& baseline_of(now) == baseline_of(before)
    &&& members_of(now) == members_of(before)
    &&& cohort_pins_of(now) == cohort_pins_of(before)
    &&& ledger_of(now) == ledger_of(before)
    &&& alias_of(now) == alias_of(before)
}

/// The reply records and the notes are gone, the reply table is as one that
/// has not swept, and the two tables' settings are kept.
pub open spec fn records_cleared(now: BoxTables, before: BoxTables) -> bool {
    &&& crate::flow::table(now.flows).len() == 0
    &&& crate::flow::throttle_of(now.flows).last_ms.is_none()
    &&& crate::notes::table(now.notes).len() == 0
    &&& crate::flow::same_frame(now.flows, before.flows)
    &&& crate::notes::same_frame(now.notes, before.notes)
}

/// The DNS tables are empty, their settings kept, their epoch raised.
pub open spec fn dns_cleared(now: BoxTables, before: BoxTables) -> bool {
    &&& crate::pins::asked(now.pins).len() == 0
    &&& crate::pins::admitted(now.pins).len() == 0
    &&& crate::pins::flows(now.pins).len() == 0
    &&& crate::pins::same_sizes(now.pins, before.pins)
    &&& crate::pins::epoch_of(before.pins) < u64::MAX ==> crate::pins::epoch_of(now.pins) > crate::pins::epoch_of(before.pins)
}

/// GC1: the named tables are emptied and the others are as they were.
pub open spec fn cleared(now: BoxTables, before: BoxTables, which: Which) -> bool {
    match which {
        Which::Records => records_cleared(now, before) && crate::judge::pins_same(now.pins, before.pins),
        Which::Dns => {
            &&& dns_cleared(now, before)
            &&& crate::judge::flows_same(now.flows, before.flows)
            &&& crate::judge::notes_same(now.notes, before.notes)
        },
        Which::All => records_cleared(now, before) && dns_cleared(now, before),
    }
}

/// GC1: clearing the records leaves the DNS tables as they were, so an
/// admission that was live is still live.
pub proof fn lemma_cleared_records_keeps_dns(now: BoxTables, before: BoxTables)
    requires
        cleared(now, before, Which::Records),
    ensures
        crate::judge::pins_same(now.pins, before.pins),
{
}

/// `now` is `before` with the row at `i` gone, and that row was `st`.
pub open spec fn retired_at(now: Gate, before: Gate, st: RowState, i: int) -> bool {
    &&& 0 <= i < rows_view(before).len()
    &&& st == rows_view(before)[i]
    &&& rows_of(sources_of(now)) == rows_of(sources_of(before)).remove(i)
    &&& rows_view(now) == rows_view(before).remove(i)
}

/// `now` is `before` with one field changed: the name.
pub open spec fn renamed(now: RowState, before: RowState, name_id: u32) -> bool {
    &&& now.name_id == name_id
    &&& now.rules == before.rules
    &&& now.resolves_names == before.resolves_names
    &&& now.alias_by_name == before.alias_by_name
    &&& now.task_row == before.task_row
    &&& now.names_boxes == before.names_boxes
    &&& now.tables == before.tables
}

/// The row `now` is `st` as declared, with tables that hold nothing.
pub open spec fn registered_as(now: RowState, st: RowState) -> bool {
    &&& now.rules == st.rules
    &&& now.resolves_names == st.resolves_names
    &&& now.alias_by_name == st.alias_by_name
    &&& now.name_id == st.name_id
    &&& now.task_row == st.task_row
    &&& now.names_boxes == st.names_boxes
    &&& owners_same(now.tables, st.tables)
    &&& crate::flow::same_frame(now.tables.flows, st.tables.flows)
    &&& crate::notes::same_frame(now.tables.notes, st.tables.notes)
    &&& crate::pins::same_sizes(now.tables.pins, st.tables.pins)
    &&& crate::pins::epoch_of(st.tables.pins) < u64::MAX ==> crate::pins::epoch_of(now.tables.pins) > crate::pins::epoch_of(st.tables.pins)
    &&& fresh(now.tables)
}

/// The DNS tables are emptied and everything else about the tables is kept.
pub open spec fn tables_reset(now: BoxTables, before: BoxTables) -> bool {
    owners_same(now, before) && cleared(now, before, Which::Dns)
}

/// The row is as it was declared, with its DNS tables emptied.
pub open spec fn row_reset(now: RowState, before: RowState) -> bool {
    &&& now.rules == before.rules
    &&& now.resolves_names == before.resolves_names
    &&& now.alias_by_name == before.alias_by_name
    &&& now.name_id == before.name_id
    &&& now.task_row == before.task_row
    &&& now.names_boxes == before.names_boxes
    &&& tables_reset(now.tables, before.tables)
}

/// The DNS tables hold nothing; their settings are kept and their epoch raised.
pub open spec fn pins_cleared(now: Pins, before: Pins) -> bool {
    &&& crate::pins::asked(now).len() == 0
    &&& crate::pins::admitted(now).len() == 0
    &&& crate::pins::flows(now).len() == 0
    &&& crate::pins::same_sizes(now, before)
    &&& crate::pins::epoch_of(before) < u64::MAX ==> crate::pins::epoch_of(now) > crate::pins::epoch_of(before)
}

/// What a new gate holds of the state it was built from: everything, with
/// every DNS table emptied.
pub open spec fn started(g: Gate, rows: Seq<RowState>, node: BoxTables, cohort: BoxTables, cohort_pins: Pins) -> bool {
    &&& rows_view(g).len() == rows.len()
    &&& forall|i: int| 0 <= i < rows.len() ==> row_reset(#[trigger] rows_view(g)[i], rows[i])
    &&& tables_reset(node_of(g), node)
    &&& tables_reset(cohort_of(g), cohort)
    &&& pins_cleared(cohort_pins_of(g), cohort_pins)
}

/// GD0 (a): in a new gate no DNS table lifts a frame, whatever the tables
/// it was built from held.
pub proof fn theorem_gd0_a_new_gate_lifts_nothing(g: Gate, rows: Seq<RowState>, node: BoxTables, cohort: BoxTables, cohort_pins: Pins, sent: Sent, now_ms: u64, i: int)
    requires
        started(g, rows, node, cohort, cohort_pins),
        0 <= i < rows.len(),
    ensures
        !crate::judge::pin_ok(rows_view(g)[i].tables.pins, sent, now_ms),
        !crate::judge::pin_ok(node_of(g).pins, sent, now_ms),
        !crate::judge::pin_ok(cohort_pins_of(g), sent, now_ms),
{
    theorem_reset_admits_no_lift(rows_view(g)[i].tables, rows[i].tables, sent, now_ms);
    theorem_reset_admits_no_lift(node_of(g), node, sent, now_ms);
}

/// GD0 (a): tables whose DNS part was reset lift nothing.
pub proof fn theorem_reset_admits_no_lift(now: BoxTables, before: BoxTables, sent: Sent, now_ms: u64)
    requires
        tables_reset(now, before),
    ensures
        !crate::judge::pin_ok(now.pins, sent, now_ms),
{
}

/// The table a DNS query from `src` is recorded in. Under the mark spelling
/// a marked query from the node's address is the cohort's in every phase,
/// and an unmarked one is the node's while its baseline is in force. Under
/// the cohort's own address the mark is not read. Any other source is a
/// row's, if a row holds it.
pub open spec fn ask_route(s: Sources, src: u32, marked: bool) -> Option<DnsTable> {
    let node = src as int == spec_node(plan_of(s));
    let row = if registered(rows_of(s), src) { Some(DnsTable::Row(src)) } else { None };
    match spelling_of(s) {
        CohortSpelling::NodeWithMark => {
            if node && marked {
                Some(DnsTable::Cohort)
            } else if node && in_force_of(s) {
                Some(DnsTable::Node)
            } else {
                row
            }
        },
        CohortSpelling::OwnAddress => {
            if in_force_of(s) && src as int == spec_cohort(plan_of(s)) {
                Some(DnsTable::Cohort)
            } else if in_force_of(s) && node {
                Some(DnsTable::Node)
            } else {
                row
            }
        },
    }
}

/// The index of the row that holds `a`. Rows hold distinct addresses, so
/// there is one.
pub open spec fn row_index(rows: Seq<u32>, a: u32) -> int {
    choose|i: int| 0 <= i < rows.len() && rows[i] == a
}

/// The table `t` names exists in this gate.
pub open spec fn has_table(g: Gate, t: DnsTable) -> bool {
    match t {
        DnsTable::Row(a) => registered(rows_of(sources_of(g)), a),
        _ => true,
    }
}

/// The DNS tables `t` names.
pub open spec fn pins_at(g: Gate, t: DnsTable) -> Pins {
    match t {
        DnsTable::Row(a) => rows_view(g)[row_index(rows_of(sources_of(g)), a)].tables.pins,
        DnsTable::Node => node_of(g).pins,
        DnsTable::Cohort => cohort_pins_of(g),
    }
}

/// Nothing in the gate changed.
pub open spec fn unchanged(now: Gate, before: Gate) -> bool {
    &&& same_setup(now, before)
    &&& rows_view(now) == rows_view(before)
    &&& node_of(now) == node_of(before)
    &&& cohort_of(now) == cohort_of(before)
    &&& cohort_pins_of(now) == cohort_pins_of(before)
    &&& ledger_of(now) == ledger_of(before)
}

/// Nothing changed but the DNS tables `t` names: every other row, the reply
/// records and notes of the named one, the other two shared tables, the
/// cohort's own tables, the ledger and the setup are as they were.
pub open spec fn only_dns_changed(now: Gate, before: Gate, t: DnsTable) -> bool {
    &&& same_setup(now, before)
    &&& cohort_of(now) == cohort_of(before)
    &&& ledger_of(now) == ledger_of(before)
    &&& match t {
        DnsTable::Row(a) => {
            let i = row_index(rows_of(sources_of(before)), a);
            &&& node_of(now) == node_of(before)
            &&& cohort_pins_of(now) == cohort_pins_of(before)
            &&& only_row_changed(rows_view(now), rows_view(before), i)
            &&& rows_view(now)[i].tables.flows == rows_view(before)[i].tables.flows
            &&& rows_view(now)[i].tables.notes == rows_view(before)[i].tables.notes
        },
        DnsTable::Node => {
            &&& rows_view(now) == rows_view(before)
            &&& cohort_pins_of(now) == cohort_pins_of(before)
            &&& node_of(now).flows == node_of(before).flows
            &&& node_of(now).notes == node_of(before).notes
        },
        DnsTable::Cohort => {
            &&& rows_view(now) == rows_view(before)
            &&& node_of(now) == node_of(before)
        },
    }
}

/// GD0 (b): under the mark spelling a marked query from the node's address
/// is the cohort's whatever the baseline's phase.
pub proof fn theorem_marked_node_query_is_the_cohorts(s: Sources, src: u32)
    requires
        spelling_of(s) == CohortSpelling::NodeWithMark,
        src as int == spec_node(plan_of(s)),
    ensures
        ask_route(s, src, true) == Some(DnsTable::Cohort),
{
}

/// GD0 (b): a question is recorded in a row's table only for a query from
/// that row's address, and never while the node or the cohort answers for
/// that address.
pub proof fn theorem_row_question_is_the_rows_own(s: Sources, src: u32, marked: bool, a: u32)
    requires
        ask_route(s, src, marked) == Some(DnsTable::Row(a)),
    ensures
        a == src,
        registered(rows_of(s), src),
        !(in_force_of(s) && src as int == spec_node(plan_of(s))),
{
}

/// The destination's own table for a reply: the one an unmarked query from
/// that address is recorded in.
pub open spec fn answer_own(s: Sources, dst: u32) -> Option<DnsTable> {
    ask_route(s, dst, false)
}

/// The reply is also offered to the cohort's table: under the mark spelling
/// the cohort asks from the node's address, in every phase.
pub open spec fn answer_cohort_too(s: Sources, dst: u32) -> bool {
    spelling_of(s) == CohortSpelling::NodeWithMark && dst as int == spec_node(plan_of(s))
}

/// Nothing changed but the DNS tables a reply was offered to.
pub open spec fn only_dns_of(now: Gate, before: Gate, cohort_too: bool, own: Option<DnsTable>) -> bool {
    &&& same_setup(now, before)
    &&& cohort_of(now) == cohort_of(before)
    &&& ledger_of(now) == ledger_of(before)
    &&& !(cohort_too || own == Some(DnsTable::Cohort)) ==> cohort_pins_of(now) == cohort_pins_of(before)
    &&& match own {
        Some(DnsTable::Node) => {
            &&& node_of(now).flows == node_of(before).flows
            &&& node_of(now).notes == node_of(before).notes
        },
        _ => node_of(now) == node_of(before),
    }
    &&& match own {
        Some(DnsTable::Row(a)) => {
            let i = row_index(rows_of(sources_of(before)), a);
            &&& only_row_changed(rows_view(now), rows_view(before), i)
            &&& rows_view(now)[i].tables.flows == rows_view(before)[i].tables.flows
            &&& rows_view(now)[i].tables.notes == rows_view(before)[i].tables.notes
        },
        _ => rows_view(now) == rows_view(before),
    }
}

/// What one table did with a reply it was offered: `Pins::resolve` of the
/// name and addresses it was given, or nothing when it was given no name.
pub open spec fn offered(now: Pins, before: Pins, name: Option<u32>, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>) -> bool {
    match name {
        Some(n) => resolve_post(before, now, n, txid, port, addrs, now_ms, r),
        None => r.is_none() && now == before,
    }
}

/// What `dns_answer` promises of its result and of the gate before and after.
pub open spec fn answered_post(
    before: Gate,
    after: Gate,
    dst: u32,
    txid: u16,
    port: u16,
    own_name: Option<u32>,
    own_addrs: Seq<u32>,
    cohort_name: Option<u32>,
    cohort_addrs: Seq<u32>,
    now_ms: u64,
    r: DnsAnswered,
) -> bool {
    let s = sources_of(before);
    &&& r.own_table == answer_own(s, dst)
    &&& only_dns_of(after, before, answer_cohort_too(s, dst), answer_own(s, dst))
    &&& if answer_cohort_too(s, dst) {
        offered(cohort_pins_of(after), cohort_pins_of(before), cohort_name, txid, port, cohort_addrs, now_ms, r.cohort_at_node)
    } else {
        r.cohort_at_node.is_none()
    }
    &&& match answer_own(s, dst) {
        Some(DnsTable::Cohort) => offered(pins_at(after, DnsTable::Cohort), pins_at(before, DnsTable::Cohort), cohort_name, txid, port, cohort_addrs, now_ms, r.own),
        Some(t) => offered(pins_at(after, t), pins_at(before, t), own_name, txid, port, own_addrs, now_ms, r.own),
        None => r.own.is_none(),
    }
}

/// GD1 (a): the table a query is recorded in is offered the replies to that
/// query's source, whatever the mark and the baseline's phase.
pub proof fn theorem_gd1_a_answer_reaches_the_asked_table(s: Sources, src: u32, marked: bool, t: DnsTable)
    requires
        ask_route(s, src, marked) == Some(t),
    ensures
        answer_own(s, src) == Some(t) || (t == DnsTable::Cohort && answer_cohort_too(s, src)),
{
}

/// GD1 (a): the two tables a reply at the node's address may be offered to
/// are never the same table.
pub proof fn theorem_gd1_a_offered_tables_differ(s: Sources, dst: u32)
    requires
        answer_cohort_too(s, dst),
    ensures
        answer_own(s, dst) != Some(DnsTable::Cohort),
{
}

/// GD1 (b): a table offered a reply with no name is as it was: no question
/// consumed, no address admitted.
pub proof fn theorem_gd1_b_unnamed_table_is_untouched(now: Pins, before: Pins, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>)
    requires
        offered(now, before, None, txid, port, addrs, now_ms, r),
    ensures
        r.is_none(),
        crate::pins::asked(now) == crate::pins::asked(before),
        crate::pins::admitted(now) == crate::pins::admitted(before),
{
}

/// GD1 (d): from the answer operation's guarantee alone, an entry a table's
/// admissions did not hold before is there because that table held a live
/// question for the name it was given, and is under that name and among
/// the addresses it was given.
pub proof fn theorem_gd1_d_admitted_by_its_own_question(now: Pins, before: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>, j: int)
    requires
        offered(now, before, Some(name), txid, port, addrs, now_ms, r),
        0 <= j < crate::pins::admitted(now).len(),
        !crate::pool::holds(crate::pins::admitted(before), crate::pins::admitted(now)[j].row, crate::pins::admitted(now)[j].key),
    ensures
        crate::flow::live(crate::pins::asked(before), name, crate::pins::question_key(txid, port), now_ms),
        crate::pins::admitted(now)[j].row == name,
        crate::pins::listed(addrs, crate::pins::admitted(now)[j].key),
{
    crate::pins::theorem_gd_a_admitted_only_by_its_question(before, now, name, txid, port, addrs, now_ms, r, j);
}

/// What `dns_answer` promises: `answered_post` of the two lists with every
/// address that fails the gate's own plan's floor removed, and the counts
/// of what was removed.
pub open spec fn floored_post(
    before: Gate,
    after: Gate,
    dst: u32,
    txid: u16,
    port: u16,
    own_name: Option<u32>,
    own_addrs: Seq<u32>,
    cohort_name: Option<u32>,
    cohort_addrs: Seq<u32>,
    now_ms: u64,
    r: Floored,
) -> bool {
    let plan = plan_of(sources_of(before));
    &&& answered_post(before, after, dst, txid, port, own_name, floored(plan, offered_list(own_addrs)), cohort_name, floored(plan, offered_list(cohort_addrs)), now_ms, r.answered)
    &&& r.own_dropped + floored(plan, offered_list(own_addrs)).len() == own_addrs.len()
    &&& r.cohort_dropped + floored(plan, offered_list(cohort_addrs)).len() == cohort_addrs.len()
}

/// The addresses of an answer the gate looks at: all of them, or none when
/// there are more than a count the tables can number.
pub open spec fn offered_list(addrs: Seq<u32>) -> Seq<u32> {
    if addrs.len() > u16::MAX {
        Seq::<u32>::empty()
    } else {
        addrs
    }
}

/// GD2 (a): an entry a DNS table's admitted addresses did not hold before a
/// reply is one of the reply's addresses, and that address passes the floor:
/// it is not in 100.64.0.0/10, not in the plan's block, and not in a range
/// no name may name.
pub proof fn theorem_gd2_a_admitted_addresses_pass_the_floor(plan: Plan, now: Pins, before: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>, j: int)
    requires
        offered(now, before, Some(name), txid, port, floored(plan, addrs), now_ms, r),
        0 <= j < crate::pins::admitted(now).len(),
        !crate::pool::holds(crate::pins::admitted(before), crate::pins::admitted(now)[j].row, crate::pins::admitted(now)[j].key),
    ensures
        exists|i: int| 0 <= i < addrs.len() && addrs[i] as u64 == crate::pins::admitted(now)[j].key
            && floor_ok(plan, addrs[i]),
{
    theorem_gd1_d_admitted_by_its_own_question(now, before, name, txid, port, floored(plan, addrs), now_ms, r, j);
    let f = floored(plan, addrs);
    let k = choose|k: int| 0 <= k < f.len() && f[k] as u64 == crate::pins::admitted(now)[j].key;
    crate::rebind::theorem_floored_members(plan, addrs, k);
    let i = choose|i: int| 0 <= i < addrs.len() && addrs[i] == f[k];
    assert(addrs[i] as u64 == crate::pins::admitted(now)[j].key && floor_ok(plan, addrs[i]));
}

/// GD2 (b): an address that passes the floor is no address of the plan's
/// block: no box's lease, nor the gateway, the node, the proxy, the
/// cohort's address or the host alias. For every plan.
pub proof fn theorem_gd2_b_the_floor_excludes_the_block(plan: Plan, a: u32)
    requires
        crate::plan::wf(plan),
        floor_ok(plan, a),
    ensures
        !spec_contains(plan, a as int),
        a as int != spec_node(plan),
        a as int != spec_host_alias(plan),
        a as int != spec_proxy_peer(plan),
        a as int != spec_cohort(plan),
        a as int != crate::plan::spec_gateway(plan),
        a >> 22 != 0x191u32,
{
    // The five addresses lie inside the block, and the floor excludes the
    // whole block.
    crate::plan::lemma_reserved_inside(plan);
}

/// What `adopt_baseline` promises of the gate before and after.
pub open spec fn adopted(now: Gate, before: Gate, in_force: bool, baseline: Seq<Cidr>) -> bool {
    let s = sources_of(before);
    &&& plan_of(sources_of(now)) == plan_of(s)
    &&& rows_of(sources_of(now)) == rows_of(s)
    &&& spelling_of(sources_of(now)) == spelling_of(s)
    &&& in_force_of(sources_of(now)) == in_force
    &&& baseline_of(now) == baseline
    &&& members_of(now) == members_of(before)
    &&& alias_of(now) == alias_of(before)
    &&& ledger_of(now) == ledger_of(before)
    &&& cohort_of(now) == cohort_of(before)
    &&& cohort_pins_of(now) == cohort_pins_of(before)
    &&& tables_reset(node_of(now), node_of(before))
    &&& rows_view(now).len() == rows_view(before).len()
    &&& forall|k: int| 0 <= k < rows_view(before).len() ==> if rows_of(s)[k] as int == spec_node(plan_of(s)) {
        row_reset(#[trigger] rows_view(now)[k], rows_view(before)[k])
    } else {
        rows_view(now)[k] == rows_view(before)[k]
    }
}

/// GB1 (a): after a baseline is adopted, nothing the node resolved before
/// lifts a frame, in either place its questions are recorded.
pub proof fn theorem_gb1_a_adopting_empties_the_nodes_dns(now: Gate, before: Gate, in_force: bool, baseline: Seq<Cidr>, sent: Sent, now_ms: u64, k: int)
    requires
        adopted(now, before, in_force, baseline),
        0 <= k < rows_view(before).len(),
        rows_of(sources_of(before))[k] as int == spec_node(plan_of(sources_of(before))),
    ensures
        !crate::judge::pin_ok(node_of(now).pins, sent, now_ms),
        !crate::judge::pin_ok(rows_view(now)[k].tables.pins, sent, now_ms),
{
    theorem_reset_admits_no_lift(node_of(now), node_of(before), sent, now_ms);
    theorem_reset_admits_no_lift(rows_view(now)[k].tables, rows_view(before)[k].tables, sent, now_ms);
}

/// GB1 (b): adopting a baseline changes no DNS admission of the cohort.
pub proof fn theorem_gb1_b_adopting_keeps_the_cohorts_dns(now: Gate, before: Gate, in_force: bool, baseline: Seq<Cidr>, sent: Sent, now_ms: u64)
    requires
        adopted(now, before, in_force, baseline),
    ensures
        crate::judge::pin_ok(cohort_pins_of(now), sent, now_ms) == crate::judge::pin_ok(cohort_pins_of(before), sent, now_ms),
{
}

/// What is never changed by a decision.
pub open spec fn same_setup(now: Gate, before: Gate) -> bool {
    &&& sources_of(now) == sources_of(before)
    &&& baseline_of(now) == baseline_of(before)
    &&& members_of(now) == members_of(before)
    &&& alias_of(now) == alias_of(before)
    &&& rows_view(now).len() == rows_view(before).len()
}

/// Every row but `i` is as it was, and row `i` kept its declaration.
pub open spec fn only_row_changed(now: Seq<RowState>, before: Seq<RowState>, i: int) -> bool {
    &&& now.len() == before.len()
    &&& forall|k: int| 0 <= k < now.len() && k != i ==> #[trigger] now[k] == before[k]
    &&& now[i].rules == before[i].rules
    &&& now[i].resolves_names == before[i].resolves_names
    &&& now[i].alias_by_name == before[i].alias_by_name
    &&& now[i].name_id == before[i].name_id
    &&& now[i].task_row == before[i].task_row
    &&& now[i].names_boxes == before[i].names_boxes
}

/// The lifts a row's frame is decided with.
pub open spec fn lifts_of(g: Gate, i: int, f: Frame) -> Lifts {
    Lifts {
        resolves_names: rows_view(g)[i].resolves_names,
        alias_by_name: rows_view(g)[i].alias_by_name,
        box_name: box_name_spec(g, i, f),
        box_name_dst: dst_of(f.sent),
    }
}

/// BN1, for the frame judged: the box-name rule the gate judges a frame with
/// is the rule computed for that frame.
pub proof fn theorem_bn1_the_rule_is_this_frames(g: Gate, i: int, f: Frame)
    ensures
        box_rule(lifts_of(g, i, f), f.sent) == box_name_spec(g, i, f),
{
    lemma_box_rule_own(lifts_of(g, i, f), f.sent);
}

/// The list names `id`.
pub open spec fn listed(names: Seq<u32>, id: u32) -> bool {
    exists|k: int| 0 <= k < names.len() && names[k] == id
}

/// The first row holding `a`.
pub open spec fn target_of(addrs: Seq<u32>, a: u32) -> int {
    choose|t: int| 0 <= t < addrs.len() && addrs[t] == a && first_at(addrs, a, t)
}

/// The first row holding an address is the one a search from the front finds.
pub proof fn lemma_target_is(addrs: Seq<u32>, a: u32, t: int)
    requires
        0 <= t < addrs.len(),
        addrs[t] == a,
        first_at(addrs, a, t),
    ensures
        target_of(addrs, a) == t,
{
    let u = choose|u: int| 0 <= u < addrs.len() && addrs[u] == a && first_at(addrs, a, u);
    if u < t {
        assert(addrs[u] != a);
    } else if t < u {
        assert(addrs[t] != a);
    }
}

/// `dns_answer` after the cohort's step, when the destination's own table
/// is not touched: there is none, or it was given no name.
proof fn lemma_answered_untouched(g0: Gate, g1: Gate, g2: Gate, dst: u32, txid: u16, port: u16, own_name: Option<u32>, own_addrs: Seq<u32>, cohort_name: Option<u32>, cohort_addrs: Seq<u32>, now_ms: u64, r: DnsAnswered)
    requires
        ginv(g1),
        same_setup(g1, g0),
        rows_view(g1) == rows_view(g0),
        node_of(g1) == node_of(g0),
        cohort_of(g1) == cohort_of(g0),
        ledger_of(g1) == ledger_of(g0),
        if answer_cohort_too(sources_of(g0), dst) {
            offered(cohort_pins_of(g1), cohort_pins_of(g0), cohort_name, txid, port, cohort_addrs, now_ms, r.cohort_at_node)
        } else {
            r.cohort_at_node.is_none() && cohort_pins_of(g1) == cohort_pins_of(g0)
        },
        r.own_table == answer_own(sources_of(g0), dst),
        r.own.is_none(),
        match r.own_table {
            None => true,
            Some(DnsTable::Cohort) => cohort_name.is_none(),
            Some(_) => own_name.is_none(),
        },
        answer_cohort_too(sources_of(g0), dst) ==> answer_own(sources_of(g0), dst) != Some(DnsTable::Cohort),
        sources_of(g2) == sources_of(g1),
        baseline_of(g2) == baseline_of(g1),
        members_of(g2) == members_of(g1),
        alias_of(g2) == alias_of(g1),
        cohort_of(g2) == cohort_of(g1),
        ledger_of(g2) == ledger_of(g1),
        rows_view(g2) == rows_view(g1),
        node_of(g2) == node_of(g1),
        cohort_pins_of(g2) == cohort_pins_of(g1),
    ensures
        ginv(g2),
        answered_post(g0, g2, dst, txid, port, own_name, own_addrs, cohort_name, cohort_addrs, now_ms, r),
{
}

/// `dns_answer` after the cohort's step, when the destination's own table
/// is the cohort's (its own address, the baseline in force).
proof fn lemma_answered_cohort(g0: Gate, g1: Gate, g2: Gate, dst: u32, txid: u16, port: u16, own_name: Option<u32>, own_addrs: Seq<u32>, cohort_name: Option<u32>, cohort_addrs: Seq<u32>, now_ms: u64, r: DnsAnswered, n: u32)
    requires
        ginv(g1),
        same_setup(g1, g0),
        rows_view(g1) == rows_view(g0),
        node_of(g1) == node_of(g0),
        cohort_of(g1) == cohort_of(g0),
        ledger_of(g1) == ledger_of(g0),
        if answer_cohort_too(sources_of(g0), dst) {
            offered(cohort_pins_of(g1), cohort_pins_of(g0), cohort_name, txid, port, cohort_addrs, now_ms, r.cohort_at_node)
        } else {
            r.cohort_at_node.is_none() && cohort_pins_of(g1) == cohort_pins_of(g0)
        },
        r.own_table == answer_own(sources_of(g0), dst),
        r.own_table == Some(DnsTable::Cohort),
        cohort_name == Some(n),
        !answer_cohort_too(sources_of(g0), dst),
        sources_of(g2) == sources_of(g1),
        baseline_of(g2) == baseline_of(g1),
        members_of(g2) == members_of(g1),
        alias_of(g2) == alias_of(g1),
        cohort_of(g2) == cohort_of(g1),
        ledger_of(g2) == ledger_of(g1),
        rows_view(g2) == rows_view(g1),
        node_of(g2) == node_of(g1),
        pinv(cohort_pins_of(g2)),
        resolve_post(cohort_pins_of(g1), cohort_pins_of(g2), n, txid, port, cohort_addrs, now_ms, r.own),
    ensures
        ginv(g2),
        answered_post(g0, g2, dst, txid, port, own_name, own_addrs, cohort_name, cohort_addrs, now_ms, r),
{
}

/// `dns_answer` after the cohort's step, when the destination's own table
/// is the node's.
proof fn lemma_answered_node(g0: Gate, g1: Gate, g2: Gate, dst: u32, txid: u16, port: u16, own_name: Option<u32>, own_addrs: Seq<u32>, cohort_name: Option<u32>, cohort_addrs: Seq<u32>, now_ms: u64, r: DnsAnswered, n: u32)
    requires
        ginv(g1),
        same_setup(g1, g0),
        rows_view(g1) == rows_view(g0),
        node_of(g1) == node_of(g0),
        cohort_of(g1) == cohort_of(g0),
        ledger_of(g1) == ledger_of(g0),
        if answer_cohort_too(sources_of(g0), dst) {
            offered(cohort_pins_of(g1), cohort_pins_of(g0), cohort_name, txid, port, cohort_addrs, now_ms, r.cohort_at_node)
        } else {
            r.cohort_at_node.is_none() && cohort_pins_of(g1) == cohort_pins_of(g0)
        },
        r.own_table == answer_own(sources_of(g0), dst),
        r.own_table == Some(DnsTable::Node),
        own_name == Some(n),
        sources_of(g2) == sources_of(g1),
        baseline_of(g2) == baseline_of(g1),
        members_of(g2) == members_of(g1),
        alias_of(g2) == alias_of(g1),
        cohort_of(g2) == cohort_of(g1),
        ledger_of(g2) == ledger_of(g1),
        rows_view(g2) == rows_view(g1),
        cohort_pins_of(g2) == cohort_pins_of(g1),
        tinv(node_of(g2)),
        owners_same(node_of(g2), node_of(g1)),
        node_of(g2).flows == node_of(g1).flows,
        node_of(g2).notes == node_of(g1).notes,
        resolve_post(node_of(g1).pins, node_of(g2).pins, n, txid, port, own_addrs, now_ms, r.own),
    ensures
        ginv(g2),
        answered_post(g0, g2, dst, txid, port, own_name, own_addrs, cohort_name, cohort_addrs, now_ms, r),
{
}

/// `dns_answer` after the cohort's step, when the destination's own table
/// is row `i`'s, the row that holds `dst`.
proof fn lemma_answered_row(g0: Gate, g1: Gate, g2: Gate, dst: u32, txid: u16, port: u16, own_name: Option<u32>, own_addrs: Seq<u32>, cohort_name: Option<u32>, cohort_addrs: Seq<u32>, now_ms: u64, r: DnsAnswered, n: u32, i: int)
    requires
        ginv(g1),
        same_setup(g1, g0),
        rows_view(g1) == rows_view(g0),
        node_of(g1) == node_of(g0),
        cohort_of(g1) == cohort_of(g0),
        ledger_of(g1) == ledger_of(g0),
        if answer_cohort_too(sources_of(g0), dst) {
            offered(cohort_pins_of(g1), cohort_pins_of(g0), cohort_name, txid, port, cohort_addrs, now_ms, r.cohort_at_node)
        } else {
            r.cohort_at_node.is_none() && cohort_pins_of(g1) == cohort_pins_of(g0)
        },
        r.own_table == answer_own(sources_of(g0), dst),
        r.own_table == Some(DnsTable::Row(dst)),
        own_name == Some(n),
        0 <= i < rows_view(g1).len(),
        rows_of(sources_of(g0))[i] == dst,
        sources_of(g2) == sources_of(g1),
        baseline_of(g2) == baseline_of(g1),
        members_of(g2) == members_of(g1),
        alias_of(g2) == alias_of(g1),
        cohort_of(g2) == cohort_of(g1),
        ledger_of(g2) == ledger_of(g1),
        node_of(g2) == node_of(g1),
        cohort_pins_of(g2) == cohort_pins_of(g1),
        rows_view(g2) == rows_view(g1).update(i, rows_view(g2)[i]),
        rows_view(g2)[i].rules == rows_view(g1)[i].rules,
        rows_view(g2)[i].resolves_names == rows_view(g1)[i].resolves_names,
        rows_view(g2)[i].alias_by_name == rows_view(g1)[i].alias_by_name,
        rows_view(g2)[i].name_id == rows_view(g1)[i].name_id,
        rows_view(g2)[i].task_row == rows_view(g1)[i].task_row,
        rows_view(g2)[i].names_boxes == rows_view(g1)[i].names_boxes,
        tinv(rows_view(g2)[i].tables),
        owners_same(rows_view(g2)[i].tables, rows_view(g1)[i].tables),
        rows_view(g2)[i].tables.flows == rows_view(g1)[i].tables.flows,
        rows_view(g2)[i].tables.notes == rows_view(g1)[i].tables.notes,
        resolve_post(rows_view(g1)[i].tables.pins, rows_view(g2)[i].tables.pins, n, txid, port, own_addrs, now_ms, r.own),
    ensures
        ginv(g2),
        answered_post(g0, g2, dst, txid, port, own_name, own_addrs, cohort_name, cohort_addrs, now_ms, r),
{
    reveal(rows_bound);
    let rows = rows_of(sources_of(g0));
    // Rows hold distinct addresses, so `i` is the row `row_index` names.
    let k = row_index(rows, dst);
    assert(rows[k] == dst);
    if k < i {
        assert(rows[k] != rows[i]);
    } else if i < k {
        assert(rows[i] != rows[k]);
    }
    assert forall|j: int| 0 <= j < rows_view(g2).len() implies row_bound(#[trigger] rows_view(g2)[j], rows_of(sources_of(g2))[j]) by {
        if j != i {
            assert(rows_view(g2)[j] == rows_view(g1)[j]);
        }
    }
}

/// A sound gate has one row of tables per row address.
proof fn lemma_rows_len(g: Gate)
    requires
        ginv(g),
    ensures
        rows_view(g).len() == rows_of(sources_of(g)).len(),
{
    reveal(rows_bound);
}

/// A sound gate's row `i` has sound tables.
proof fn lemma_row_sound(g: Gate, i: int)
    requires
        ginv(g),
        0 <= i < rows_of(sources_of(g)).len(),
    ensures
        tinv(rows_view(g)[i].tables),
{
    reveal(rows_bound);
}

/// `dns_ask` when the query is the cohort's: only the cohort's DNS tables
/// changed, by `Pins::ask`.
proof fn lemma_asked_cohort(
    g0: Gate,
    g2: Gate,
    src: u32,
    marked: bool,
    name: u32,
    txid: u16,
    port: u16,
    now_ms: u64,
    asked: Asked,
)
    requires
        ginv(g0),
        ask_route(sources_of(g0), src, marked) == Some(DnsTable::Cohort),
        same_setup(g2, g0),
        rows_view(g2) == rows_view(g0),
        node_of(g2) == node_of(g0),
        cohort_of(g2) == cohort_of(g0),
        ledger_of(g2) == ledger_of(g0),
        pinv(cohort_pins_of(g2)),
        ask_post(cohort_pins_of(g0), cohort_pins_of(g2), name, txid, port, now_ms, asked),
    ensures
        ginv(g2),
        only_dns_changed(g2, g0, DnsTable::Cohort),
        ask_post(pins_at(g0, DnsTable::Cohort), pins_at(g2, DnsTable::Cohort), name, txid, port,
            now_ms, asked),
{
}

/// `dns_ask` when the query is the node's: only the node's DNS tables
/// changed.
proof fn lemma_asked_node(
    g0: Gate,
    g2: Gate,
    src: u32,
    marked: bool,
    name: u32,
    txid: u16,
    port: u16,
    now_ms: u64,
    asked: Asked,
)
    requires
        ginv(g0),
        ask_route(sources_of(g0), src, marked) == Some(DnsTable::Node),
        same_setup(g2, g0),
        rows_view(g2) == rows_view(g0),
        cohort_of(g2) == cohort_of(g0),
        ledger_of(g2) == ledger_of(g0),
        cohort_pins_of(g2) == cohort_pins_of(g0),
        tinv(node_of(g2)),
        owners_same(node_of(g2), node_of(g0)),
        node_of(g2).flows == node_of(g0).flows,
        node_of(g2).notes == node_of(g0).notes,
        ask_post(node_of(g0).pins, node_of(g2).pins, name, txid, port, now_ms, asked),
    ensures
        ginv(g2),
        only_dns_changed(g2, g0, DnsTable::Node),
        ask_post(pins_at(g0, DnsTable::Node), pins_at(g2, DnsTable::Node), name, txid, port,
            now_ms, asked),
{
}

/// `dns_ask` when the query is row `i`'s, the row that holds `a`: only that
/// row's DNS tables changed.
proof fn lemma_asked_row(
    g0: Gate,
    g2: Gate,
    src: u32,
    marked: bool,
    a: u32,
    name: u32,
    txid: u16,
    port: u16,
    now_ms: u64,
    asked: Asked,
    i: int,
)
    requires
        ginv(g0),
        ask_route(sources_of(g0), src, marked) == Some(DnsTable::Row(a)),
        0 <= i < rows_view(g0).len(),
        rows_of(sources_of(g0))[i] == a,
        same_setup(g2, g0),
        node_of(g2) == node_of(g0),
        cohort_of(g2) == cohort_of(g0),
        ledger_of(g2) == ledger_of(g0),
        cohort_pins_of(g2) == cohort_pins_of(g0),
        rows_view(g2) == rows_view(g0).update(i, rows_view(g2)[i]),
        rows_view(g2)[i].rules == rows_view(g0)[i].rules,
        rows_view(g2)[i].resolves_names == rows_view(g0)[i].resolves_names,
        rows_view(g2)[i].alias_by_name == rows_view(g0)[i].alias_by_name,
        rows_view(g2)[i].name_id == rows_view(g0)[i].name_id,
        rows_view(g2)[i].task_row == rows_view(g0)[i].task_row,
        rows_view(g2)[i].names_boxes == rows_view(g0)[i].names_boxes,
        tinv(rows_view(g2)[i].tables),
        owners_same(rows_view(g2)[i].tables, rows_view(g0)[i].tables),
        rows_view(g2)[i].tables.flows == rows_view(g0)[i].tables.flows,
        rows_view(g2)[i].tables.notes == rows_view(g0)[i].tables.notes,
        ask_post(rows_view(g0)[i].tables.pins, rows_view(g2)[i].tables.pins, name, txid, port,
            now_ms, asked),
    ensures
        ginv(g2),
        only_dns_changed(g2, g0, DnsTable::Row(a)),
        ask_post(pins_at(g0, DnsTable::Row(a)), pins_at(g2, DnsTable::Row(a)), name, txid, port,
            now_ms, asked),
{
    reveal(rows_bound);
    let rows = rows_of(sources_of(g0));
    // Rows hold distinct addresses, so `i` is the row `row_index` names.
    let k = row_index(rows, a);
    assert(rows[k] == a);
    if k < i {
        assert(rows[k] != rows[i]);
    } else if i < k {
        assert(rows[i] != rows[k]);
    }
    assert forall|j: int| 0 <= j < rows_view(g2).len()
        implies row_bound(#[trigger] rows_view(g2)[j], rows_of(sources_of(g2))[j]) by {
        if j != i {
            assert(rows_view(g2)[j] == rows_view(g0)[j]);
        }
    }
}

/// Reading one row's bound out of the opaque `rows_bound`.
pub proof fn lemma_rows_bound_at(states: Seq<RowState>, addrs: Seq<u32>, i: int)
    requires
        rows_bound(states, addrs),
        0 <= i < addrs.len(),
    ensures
        states.len() == addrs.len(),
        row_bound(states[i], addrs[i]),
        forall|st: RowState| row_bound(st, addrs[i]) ==> #[trigger] rows_bound(states.update(i, st), addrs),
{
    reveal(rows_bound);
    assert forall|st: RowState| row_bound(st, addrs[i]) implies #[trigger] rows_bound(states.update(i, st), addrs) by {
        assert forall|j: int| 0 <= j < states.len() implies row_bound(#[trigger] states.update(i, st)[j], addrs[j]) by {
            if j != i {
                assert(states.update(i, st)[j] == states[j]);
            }
        }
    }
}

/// What the box-name rule says of a frame from row `i`: nothing, unless the
/// row lists box names and the frame is addressed to another registered row
/// that is not the node; then it is allowed exactly when that row is a box's
/// own lease whose name the source lists.
#[verifier::opaque]
pub open spec fn box_name_spec(g: Gate, i: int, f: Frame) -> BoxNameRule {
    let addrs = rows_of(sources_of(g));
    match f.sent.kind {
        SentKind::Arp => BoxNameRule::Silent,
        SentKind::V4 { dst, proto, l4 } => {
            if rows_view(g)[i].names_boxes@.len() == 0 {
                BoxNameRule::Silent
            } else if dst as int == spec_node(plan_of(sources_of(g))) {
                BoxNameRule::Silent
            } else if !registered(addrs, dst) {
                BoxNameRule::Silent
            } else if dst == f.sent.src {
                BoxNameRule::Silent
            } else if rows_view(g)[target_of(addrs, dst)].task_row {
                BoxNameRule::Refused
            } else if listed(rows_view(g)[i].names_boxes@, rows_view(g)[target_of(addrs, dst)].name_id) {
                BoxNameRule::Allowed
            } else {
                BoxNameRule::Refused
            }
        },
    }
}

/// The frame is addressed to the node while its baseline is in force.
pub open spec fn to_node(g: Gate, r: Received) -> bool {
    in_force_of(sources_of(g)) && r.dst as int == spec_node(plan_of(sources_of(g)))
}

/// The frame's protocol and destination port, when it has ports.
pub open spec fn pair_of(f: Frame) -> Option<(u8, u16)> {
    match f.sent.kind {
        SentKind::V4 { dst, proto, l4: Some(x) } => Some((proto, x.dport)),
        _ => None,
    }
}

/// How a row asks for the alias: as a box that names the host by name or by
/// an allowed subnet that covers the alias.
pub open spec fn row_asks(g: Gate, st: RowState) -> AliasSource {
    AliasSource::Box {
        names_host: st.alias_by_name || allow_covers(
            rules_of(st.rules).allow_subnets,
            spec_host_alias(plan_of(sources_of(g))) as u32,
        ),
    }
}

/// Whether the alias is open to `who` for this frame, by the gate's own state.
pub open spec fn alias_for(g: Gate, who: AliasSource, f: Frame) -> bool {
    alias_spec(alias_of(g), who, pair_of(f))
}

/// The ledger holds a forward that dials the frame's destination address at
/// its destination port.
pub open spec fn port_published(g: Gate, r: Received) -> bool {
    dials(lview(ledger_of(g)), r.dst, r.l4.dport)
}

/// Nothing but the ledger changed.
pub open spec fn only_ledger_changed(now: Gate, before: Gate) -> bool {
    &&& same_setup(now, before)
    &&& rows_view(now) == rows_view(before)
    &&& node_of(now) == node_of(before)
    &&& cohort_of(now) == cohort_of(before)
    &&& cohort_pins_of(now) == cohort_pins_of(before)
    &&& same_caps(ledger_of(now), ledger_of(before))
}

/// The reply records of `proto` at `port` are gone from the tables; their
/// notes, their DNS tables, the reply table's settings and the instant of its
/// last sweep are as they were.
pub open spec fn tables_port_ended(now: BoxTables, before: BoxTables, proto: u8, port: u16) -> bool {
    &&& now.notes == before.notes
    &&& now.pins == before.pins
    &&& crate::flow::same_frame(now.flows, before.flows)
    &&& crate::flow::stamp_same(now.flows, before.flows)
    &&& crate::flow::port_ended(crate::flow::table(now.flows), crate::flow::table(before.flows), proto, port)
}

/// Tables that belong to `addr` have the port ended; any others are as they were.
pub open spec fn ended_if_owned(now: BoxTables, before: BoxTables, addr: u32, proto: u8, port: u16) -> bool {
    if crate::flow::box_of(before.flows) == addr {
        tables_port_ended(now, before, proto, port)
    } else {
        now == before
    }
}

/// The port is ended in every reply table that belongs to `addr`: the node's,
/// the cohort's, and the first row holding `addr`. Nothing else changed,
/// the ledger apart.
pub open spec fn port_ended_at(now: Gate, before: Gate, addr: u32, proto: u8, port: u16) -> bool {
    &&& same_setup(now, before)
    &&& cohort_pins_of(now) == cohort_pins_of(before)
    &&& ended_if_owned(node_of(now), node_of(before), addr, proto, port)
    &&& ended_if_owned(cohort_of(now), cohort_of(before), addr, proto, port)
    &&& if registered(rows_of(sources_of(before)), addr) {
        exists|i: int| {
            &&& 0 <= i < rows_view(before).len()
            &&& rows_of(sources_of(before))[i] == addr
            &&& first_at(rows_of(sources_of(before)), addr, i)
            &&& only_row_changed(rows_view(now), rows_view(before), i)
            &&& tables_port_ended(rows_view(now)[i].tables, rows_view(before)[i].tables, proto, port)
        }
    } else {
        rows_view(now) == rows_view(before)
    }
}

/// A retraction ends its port's reply records: it removed a forward, and no
/// forward left dials that address and port in that protocol.
pub open spec fn retraction_ends(after: Ledger, r: Option<Forward>) -> bool {
    match r {
        Some(e) => !dials_in(lview(after), e.addr, e.inside, e.proto),
        None => false,
    }
}

/// What `Gate::retract` promises beyond the ledger's own guarantee.
pub open spec fn retracted(before: Gate, after: Gate, r: Option<Forward>) -> bool {
    match r {
        Some(e) => if retraction_ends(ledger_of(after), r) {
            port_ended_at(after, before, e.addr, e.proto, e.inside)
        } else {
            only_ledger_changed(after, before)
        },
        None => only_ledger_changed(after, before),
    }
}

/// GP1 (a): after a retraction that ends its port, no reply table of that
/// address holds a record at that protocol and port, for any client.
pub proof fn theorem_gp1_a_retracted_port_holds_no_record(before: Gate, after: Gate, e: Forward, client: u32, cp: u16, i: int)
    requires
        ginv(before),
        retracted(before, after, Some(e)),
        !dials_in(lview(ledger_of(after)), e.addr, e.inside, e.proto),
    ensures
        crate::flow::box_of(node_of(before).flows) == e.addr ==> !crate::pool::holds(
            crate::flow::table(node_of(after).flows), client, crate::flow::key_of(e.proto, cp, e.inside)),
        crate::flow::box_of(cohort_of(before).flows) == e.addr ==> !crate::pool::holds(
            crate::flow::table(cohort_of(after).flows), client, crate::flow::key_of(e.proto, cp, e.inside)),
        0 <= i < rows_view(before).len() && rows_of(sources_of(before))[i] == e.addr
            && first_at(rows_of(sources_of(before)), e.addr, i) ==> !crate::pool::holds(
            crate::flow::table(rows_view(after)[i].tables.flows), client, crate::flow::key_of(e.proto, cp, e.inside)),
{
    reveal(rows_bound);
    if crate::flow::box_of(node_of(before).flows) == e.addr {
        crate::flow::theorem_g6j_ended_port_holds_no_record(
            crate::flow::table(node_of(after).flows), crate::flow::table(node_of(before).flows), e.proto, e.inside, client, cp);
    }
    if crate::flow::box_of(cohort_of(before).flows) == e.addr {
        crate::flow::theorem_g6j_ended_port_holds_no_record(
            crate::flow::table(cohort_of(after).flows), crate::flow::table(cohort_of(before).flows), e.proto, e.inside, client, cp);
    }
    if 0 <= i < rows_view(before).len() && rows_of(sources_of(before))[i] == e.addr
        && first_at(rows_of(sources_of(before)), e.addr, i) {
        let w = choose|w: int| {
            &&& 0 <= w < rows_view(before).len()
            &&& rows_of(sources_of(before))[w] == e.addr
            &&& first_at(rows_of(sources_of(before)), e.addr, w)
            &&& only_row_changed(rows_view(after), rows_view(before), w)
            &&& tables_port_ended(rows_view(after)[w].tables, rows_view(before)[w].tables, e.proto, e.inside)
        };
        // Two first rows at one address are the same row.
        assert(w == i);
        crate::flow::theorem_g6j_ended_port_holds_no_record(
            crate::flow::table(rows_view(after)[i].tables.flows), crate::flow::table(rows_view(before)[i].tables.flows), e.proto, e.inside, client, cp);
    }
}

/// GP1 (b): while another forward still dials the address and port in the
/// same protocol, a retraction changes nothing but the ledger.
pub proof fn theorem_gp1_b_standing_forward_keeps_the_records(before: Gate, after: Gate, e: Forward)
    requires
        retracted(before, after, Some(e)),
        dials_in(lview(ledger_of(after)), e.addr, e.inside, e.proto),
    ensures
        only_ledger_changed(after, before),
{
}

/// GP1 (c): a retraction never touches a table of another address, a note,
/// or a DNS table.
pub proof fn theorem_gp1_c_other_tables_are_untouched(before: Gate, after: Gate, r: Option<Forward>, k: int)
    requires
        ginv(before),
        retracted(before, after, r),
        0 <= k < rows_view(before).len(),
    ensures
        rows_view(after).len() == rows_view(before).len(),
        cohort_pins_of(after) == cohort_pins_of(before),
        node_of(after).notes == node_of(before).notes && node_of(after).pins == node_of(before).pins,
        cohort_of(after).notes == cohort_of(before).notes && cohort_of(after).pins == cohort_of(before).pins,
        rows_view(after)[k].tables.notes == rows_view(before)[k].tables.notes,
        rows_view(after)[k].tables.pins == rows_view(before)[k].tables.pins,
        r.is_some() && rows_of(sources_of(before))[k] != r.unwrap().addr ==> rows_view(after)[k] == rows_view(before)[k],
        r.is_some() && crate::flow::box_of(node_of(before).flows) != r.unwrap().addr ==> node_of(after) == node_of(before),
        r.is_some() && crate::flow::box_of(cohort_of(before).flows) != r.unwrap().addr ==> cohort_of(after) == cohort_of(before),
{
}

/// Some row holds the frame's destination.
pub open spec fn dst_is_row(g: Gate, f: Frame) -> bool {
    match f.sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => registered(rows_of(sources_of(g)), dst),
    }
}

/// The decision admits the frame.
pub open spec fn decision_admits(d: Decision) -> bool {
    match d {
        Decision::Refused(_) => false,
        Decision::Row(_, j) => judged_ok(j),
        Decision::Node(j) => node_judged_ok(j),
        Decision::Cohort(j) => cohort_judged_ok(j),
    }
}

/// The frame is delivered.
pub open spec fn arrived_delivers(a: Arrived) -> bool {
    match a {
        Arrived::NotARow => true,
        Arrived::Row(_, s) => delivers(s),
        Arrived::Node(s) => delivers(s),
        Arrived::Cohort(s) => delivers(s),
    }
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Gate {
    /// A gate over these sources and this state. `None` unless there is one
    /// state per registered row, each row's tables belong to that row's
    /// address, the node's tables to the node's, and the cohort's DNS tables
    /// to the address the cohort sends from. Every DNS table it is given is
    /// emptied: a gate starts with no question and no admission. GD0 (a).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(sources),
            forall|i: int| 0 <= i < rows@.len() ==> tinv((#[trigger] rows@[i]).tables),
            tinv(node),
            tinv(cohort),
            pinv(cohort_pins),
            linv(ledger),
        ensures
            match r {
                Some(g) => {
                    &&& ginv(g)
                    &&& sources_of(g) == sources
                    &&& started(g, rows@, node, cohort, cohort_pins)
                    &&& baseline_of(g) == baseline@
                    &&& members_of(g) == members@
                    &&& ledger_of(g) == ledger
                    &&& alias_of(g) == alias
                },
                None => !rows_bound(rows@, rows_of(sources)) || !shared_bound(node, cohort, cohort_pins, sources),
            },
    ))]
    pub fn new(
        sources: Sources,
        rows: Vec<RowState>,
        node: BoxTables,
        cohort: BoxTables,
        baseline: Vec<Cidr>,
        members: Vec<Member>,
        cohort_pins: Pins,
        ledger: Ledger,
        alias: AliasState,
    ) -> Option<Gate> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        if rows.len() != sources.len() {
            return None;
        }
        let node_addr = sources.plan().node();
        let cohort_from = match sources.spelling() {
            CohortSpelling::NodeWithMark => node_addr,
            CohortSpelling::OwnAddress => sources.plan().cohort(),
        };
        if node.flows.box_addr() != node_addr
            || node.notes.box_addr() != node_addr
            || node.pins.owner() != node_addr
            || cohort.flows.box_addr() != cohort_from
            || cohort.notes.box_addr() != cohort_from
            || cohort.pins.owner() != cohort_from
            || cohort_pins.owner() != cohort_from
        {
            return None;
        }
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= rows.len(),
                rows@.len() == rows_of(sources).len(),
                shared_bound(node, cohort, cohort_pins, sources),
                forall|k: int| 0 <= k < rows@.len() ==> tinv((#[trigger] rows@[k]).tables),
                forall|k: int| 0 <= k < i ==> row_bound(#[trigger] rows@[k], rows_of(sources)[k]),
            decreases rows.len() - i,
        ))]
        while i < rows.len() {
            #[cfg(verus_keep_ghost)]
            proof! {
                reveal(rows_bound);
            }
            let addr = sources.address(i);
            if rows[i].tables.flows.box_addr() != addr
                || rows[i].tables.notes.box_addr() != addr
                || rows[i].tables.pins.owner() != addr
            {
                return None;
            }
            i += 1;
        }
        let mut rows = rows;
        let mut node = node;
        let mut cohort = cohort;
        let mut cohort_pins = cohort_pins;
        reset_rows(&mut rows);
        clear_tables(&mut node, Which::Dns);
        clear_tables(&mut cohort, Which::Dns);
        cohort_pins.clear();
        Some(Gate {
            sources,
            rows,
            node,
            cohort,
            baseline,
            members,
            cohort_pins,
            ledger,
            alias,
        })
    }

    /// The table a query from `src` is recorded in, if any.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*self),
        ensures
            r == ask_route(sources_of(*self), src, marked),
    ))]
    fn ask_table(&self, src: u32, marked: bool) -> Option<DnsTable> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        let plan = self.sources.plan();
        let node = src == plan.node();
        let in_force = self.sources.node_in_force();
        let to_cohort = match self.sources.spelling() {
            CohortSpelling::NodeWithMark => node && marked,
            CohortSpelling::OwnAddress => in_force && src == plan.cohort(),
        };
        if to_cohort {
            return Some(DnsTable::Cohort);
        }
        if node && in_force {
            return Some(DnsTable::Node);
        }
        match self.sources.index_of(src) {
            Some(_) => Some(DnsTable::Row(src)),
            None => None,
        }
    }

    /// Records the DNS question `(name, txid, port)` of a query the box at
    /// `src` sent, `marked` when it carried the cohort's mark. The table is
    /// the gate's choice (`ask_route`). `None`, and nothing changes, when
    /// the source is no row, not the node and not the cohort. GD0 (b).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            match r {
                Some((t, asked)) => {
                    &&& ask_route(sources_of(*old(self)), src, marked) == Some(t)
                    &&& only_dns_changed(*final(self), *old(self), t)
                    &&& ask_post(pins_at(*old(self), t), pins_at(*final(self), t), name, txid, port, now.ms, asked)
                },
                None => {
                    &&& ask_route(sources_of(*old(self)), src, marked).is_none()
                    &&& unchanged(*final(self), *old(self))
                },
            },
    ))]
    pub fn dns_ask(
        &mut self,
        src: u32,
        marked: bool,
        name: u32,
        txid: u16,
        port: u16,
        now: Instant,
    ) -> Option<(DnsTable, Asked)> {
        // The gate as the query found it.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost g0: Gate = *self;
            let ghost mut gi: int = -1;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_rows_len(*self);
        }
        let t = self.ask_table(src, marked)?;
        let asked = match t {
            DnsTable::Cohort => self.cohort_pins.ask(name, txid, port, now),
            DnsTable::Node => ask_in(&mut self.node, name, txid, port, now.ms),
            DnsTable::Row(a) => {
                // `ask_table` named a row that holds `a`.
                let i = self.sources.index_of(a)?;
                #[cfg(verus_keep_ghost)]
                proof! {
                    gi = i as int;
                    lemma_row_sound(*self, gi);
                }
                let st = &mut self.rows[i];
                ask_in(&mut st.tables, name, txid, port, now.ms)
            }
        };
        // One lemma per table the query could reach, each given only that
        // path's facts.
        #[cfg(verus_keep_ghost)]
        proof! {
            match t {
                DnsTable::Cohort => {
                    lemma_asked_cohort(g0, *self, src, marked, name, txid, port, now.ms, asked);
                },
                DnsTable::Node => {
                    lemma_asked_node(g0, *self, src, marked, name, txid, port, now.ms, asked);
                },
                DnsTable::Row(a) => {
                    lemma_asked_row(g0, *self, src, marked, a, name, txid, port, now.ms, asked, gi);
                },
            }
        }
        Some((t, asked))
    }

    /// A reply from the resolver addressed to `dst` that answers the question
    /// `(txid, port)`. Every address that fails the floor is dropped first,
    /// for both tables, whatever the caller filtered; the rest is
    /// `dns_answer_given`. A list of more than 65,535 addresses, which no
    /// DNS message can carry, is dropped whole and counted as dropped. GD2.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            floored_post(*old(self), *final(self), dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now.ms, r),
    ))]
    pub fn dns_answer(
        &mut self,
        dst: u32,
        txid: u16,
        port: u16,
        own_name: Option<u32>,
        own_addrs: &[u32],
        cohort_name: Option<u32>,
        cohort_addrs: &[u32],
        now: Instant,
    ) -> Floored {
        let plan = self.sources.plan();
        let none: Vec<u32> = Vec::new();
        let own_in = if own_addrs.len() > u16::MAX as usize {
            none.as_slice()
        } else {
            own_addrs
        };
        let cohort_in = if cohort_addrs.len() > u16::MAX as usize {
            none.as_slice()
        } else {
            cohort_addrs
        };
        let own = floor(&plan, own_in);
        let cohort = floor(&plan, cohort_in);
        let answered = self.dns_answer_given(
            dst,
            txid,
            port,
            own_name,
            own.as_slice(),
            cohort_name,
            cohort.as_slice(),
            now.ms,
        );
        Floored {
            answered,
            own_dropped: own_addrs.len() - own.len(),
            cohort_dropped: cohort_addrs.len() - cohort.len(),
        }
    }

    /// The reply, with the addresses as given. `own_name` and `own_addrs` are the name's number and
    /// the answer's addresses as the destination's own table declares and
    /// filters them; `cohort_name` and `cohort_addrs` the same for the
    /// cohort's table. `None` for a name: that table does not declare it,
    /// and is not touched. The gate chooses the tables (`answer_own`,
    /// `answer_cohort_too`); each that holds the question consumes it and
    /// admits its own addresses. GD1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
            own_addrs@.len() <= u16::MAX,
            cohort_addrs@.len() <= u16::MAX,
        ensures
            ginv(*final(self)),
            answered_post(*old(self), *final(self), dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now_ms, r),
    ))]
    fn dns_answer_given(
        &mut self,
        dst: u32,
        txid: u16,
        port: u16,
        own_name: Option<u32>,
        own_addrs: &[u32],
        cohort_name: Option<u32>,
        cohort_addrs: &[u32],
        now_ms: u64,
    ) -> DnsAnswered {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        // The gate as the reply found it.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost g0: Gate = *self;
            let ghost mut gi: int = -1;
        }
        let cohort_too = match self.sources.spelling() {
            CohortSpelling::NodeWithMark => dst == self.sources.plan().node(),
            CohortSpelling::OwnAddress => false,
        };
        let cohort_at_node = if cohort_too {
            match cohort_name {
                Some(n) => {
                    self.cohort_pins
                        .resolve(n, txid, port, cohort_addrs, Instant { ms: now_ms })
                }
                None => None,
            }
        } else {
            None
        };
        // The gate after the cohort's table was offered the reply, if it was:
        // only the cohort's DNS tables may differ, and the gate is sound.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost g1: Gate = *self;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(same_setup(g1, g0) && rows_view(g1) == rows_view(g0) && node_of(g1) == node_of(g0)
                && cohort_of(g1) == cohort_of(g0) && ledger_of(g1) == ledger_of(g0));
            assert(cohort_too == answer_cohort_too(sources_of(g0), dst));
            assert(if cohort_too {
                offered(cohort_pins_of(g1), cohort_pins_of(g0), cohort_name, txid, port, cohort_addrs@, now_ms, cohort_at_node)
            } else {
                cohort_at_node.is_none() && cohort_pins_of(g1) == cohort_pins_of(g0)
            });
            assert(ginv(g1));
        }
        let own_table = self.ask_table(dst, false);
        let own = match own_table {
            None => None,
            Some(DnsTable::Cohort) => match cohort_name {
                Some(n) => {
                    self.cohort_pins
                        .resolve(n, txid, port, cohort_addrs, Instant { ms: now_ms })
                }
                None => None,
            },
            Some(DnsTable::Node) => match own_name {
                Some(n) => resolve_in(&mut self.node, n, txid, port, own_addrs, now_ms),
                None => None,
            },
            Some(DnsTable::Row(a)) => match own_name {
                Some(n) => match self.sources.index_of(a) {
                    Some(i) => {
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            gi = i as int;
                        }
                        let st = &mut self.rows[i];
                        resolve_in(&mut st.tables, n, txid, port, own_addrs, now_ms)
                    }
                    // `ask_table` named a row that holds `a`.
                    None => None,
                },
                None => None,
            },
        };
        // One lemma per table the reply's own part could reach, each given
        // only that path's facts.
        #[cfg(verus_keep_ghost)]
        proof! {
            let s = sources_of(g0);
            let r = DnsAnswered { cohort_at_node, own_table, own };
            if cohort_too {
                theorem_gd1_a_offered_tables_differ(s, dst);
            }
            match own_table {
                Some(DnsTable::Cohort) if cohort_name.is_some() => {
                    lemma_answered_cohort(g0, g1, *self, dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now_ms, r, cohort_name.unwrap());
                },
                Some(DnsTable::Node) if own_name.is_some() => {
                    lemma_answered_node(g0, g1, *self, dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now_ms, r, own_name.unwrap());
                },
                Some(DnsTable::Row(a)) if own_name.is_some() => {
                    lemma_answered_row(g0, g1, *self, dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now_ms, r, own_name.unwrap(), gi);
                },
                _ => {
                    lemma_answered_untouched(g0, g1, *self, dst, txid, port, own_name, own_addrs@, cohort_name, cohort_addrs@, now_ms, r);
                },
            }
        }
        DnsAnswered {
            cohort_at_node,
            own_table,
            own,
        }
    }

    /// The node's baseline changed: its phase, its entries, or both. The
    /// node's DNS tables are emptied, in its own tables and in the row at the
    /// node's address if there is one; the cohort's are kept. GB1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            adopted(*final(self), *old(self), in_force, baseline@),
    ))]
    pub fn adopt_baseline(&mut self, in_force: bool, baseline: Vec<Cidr>) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        let node_addr = self.sources.plan().node();
        self.sources.set_in_force(in_force);
        self.baseline = baseline;
        clear_tables(&mut self.node, Which::Dns);
        if let Some(i) = self.sources.index_of(node_addr) {
            let st = &mut self.rows[i];
            clear_tables(&mut st.tables, Which::Dns);
        }
    }

    /// Empties the cohort's DNS tables: the cohort's record changed. Nothing
    /// else changes. GB1 (c).
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            same_setup(*final(self), *old(self)),
            rows_view(*final(self)) == rows_view(*old(self)),
            node_of(*final(self)) == node_of(*old(self)),
            cohort_of(*final(self)) == cohort_of(*old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
            pins_cleared(cohort_pins_of(*final(self)), cohort_pins_of(*old(self))),
    ))]
    pub fn clear_cohort_dns(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        self.cohort_pins.clear();
    }

    /// Removes expired questions from the table `t` names, at most `budget`,
    /// and returns how many. No admission and no flow is removed: an expired
    /// admission stays until its own name answers again. `None`, and nothing
    /// changes, when `t` names a row no address holds. GD0 (c).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            match r {
                Some(n) => {
                    &&& has_table(*old(self), t)
                    &&& only_dns_changed(*final(self), *old(self), t)
                    &&& expire_questions_post(pins_at(*old(self), t), pins_at(*final(self), t), now.ms, budget, n)
                },
                None => !has_table(*old(self), t) && unchanged(*final(self), *old(self)),
            },
    ))]
    pub fn dns_expire(&mut self, t: DnsTable, now: Instant, budget: usize) -> Option<usize> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        match t {
            DnsTable::Cohort => Some(self.cohort_pins.expire_questions(now, budget)),
            DnsTable::Node => Some(expire_in(&mut self.node, now.ms, budget)),
            DnsTable::Row(a) => match self.sources.index_of(a) {
                Some(i) => {
                    let st = &mut self.rows[i];
                    Some(expire_in(&mut st.tables, now.ms, budget))
                }
                None => None,
            },
        }
    }

    /// What the box-name rule says of a frame from row `i`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*self),
            i < rows_view(*self).len(),
        ensures
            r == box_name_spec(*self, i as int, f),
    ))]
    fn box_name(&self, i: usize, f: Frame) -> BoxNameRule {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
            reveal(box_name_spec);
        }
        let dst = match f.sent.kind {
            SentKind::Arp => return BoxNameRule::Silent,
            SentKind::V4 { dst, .. } => dst,
        };
        if self.rows[i].names_boxes.is_empty() {
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
        if self.rows[t].task_row {
            return BoxNameRule::Refused;
        }
        let id = self.rows[t].name_id;
        let mut k: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i < self.rows@.len(),
                k <= self.rows@[i as int].names_boxes@.len(),
                forall|j: int| 0 <= j < k ==> self.rows@[i as int].names_boxes@[j] != id,
                // What was settled before the loop: only whether the name is listed is still open.
                box_name_spec(*self, i as int, f) == (if listed(self.rows@[i as int].names_boxes@, id) {
                    BoxNameRule::Allowed
                } else {
                    BoxNameRule::Refused
                }),
            decreases self.rows@[i as int].names_boxes@.len() - k,
        ))]
        while k < self.rows[i].names_boxes.len() {
            if self.rows[i].names_boxes[k] == id {
                #[cfg(verus_keep_ghost)]
                proof! {
                    // This entry is the witness that the name is listed.
                    assert(self.rows@[i as int].names_boxes@[k as int] == id);
                }
                return BoxNameRule::Allowed;
            }
            k += 1;
        }
        BoxNameRule::Refused
    }

    /// Decides one frame a guest sent. GE1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            same_setup(*final(self), *old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
            decision_admits(r) ==> !stray(sources_of(*old(self)), f),
            match r {
                Decision::Refused(s) => {
                    &&& stray(sources_of(*old(self)), f)
                    &&& match s {
                        Stray::ControlSurface => at_control_surface(plan_of(sources_of(*old(self))), dest_of_sent(f.sent)),
                        Stray::Unregistered => {
                            &&& !at_control_surface(plan_of(sources_of(*old(self))), dest_of_sent(f.sent))
                            &&& allocatable(sources_of(*old(self)), f.sent.src)
                        },
                        Stray::Unknown => {
                            &&& !at_control_surface(plan_of(sources_of(*old(self))), dest_of_sent(f.sent))
                            &&& !allocatable(sources_of(*old(self)), f.sent.src)
                        },
                    }
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                    &&& node_of(*final(self)) == node_of(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                    &&& cohort_pins_of(*final(self)) == cohort_pins_of(*old(self))
                },
                Decision::Row(i, j) => {
                    &&& i < rows_view(*old(self)).len()
                    &&& rows_of(sources_of(*old(self)))[i as int] == f.sent.src
                    &&& first_at(rows_of(sources_of(*old(self))), f.sent.src, i as int)
                    &&& !is_cohort(sources_of(*old(self)), f.sent.src, v4(f), f.dscp)
                    &&& !is_node(sources_of(*old(self)), f.sent.src, v4(f), f.dscp)
                    &&& owned_by(rows_view(*old(self))[i as int].tables, f.sent.src)
                    &&& row_post(
                        plan_of(sources_of(*old(self))),
                        rules_of(rows_view(*old(self))[i as int].rules),
                        lifts_of(*old(self), i as int, f),
                        alias_for(*old(self), row_asks(*old(self), rows_view(*old(self))[i as int]), f),
                        rows_view(*old(self))[i as int].tables,
                        rows_view(*final(self))[i as int].tables,
                        f.sent,
                        now.ms,
                        j,
                    )
                    &&& only_row_changed(rows_view(*final(self)), rows_view(*old(self)), i as int)
                    &&& node_of(*final(self)) == node_of(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                    &&& cohort_pins_of(*final(self)) == cohort_pins_of(*old(self))
                },
                Decision::Node(j) => {
                    &&& is_node(sources_of(*old(self)), f.sent.src, v4(f), f.dscp)
                    &&& owned_by(node_of(*old(self)), f.sent.src)
                    &&& node_post(
                        plan_of(sources_of(*old(self))),
                        baseline_of(*old(self)),
                        alias_for(*old(self), AliasSource::Node, f),
                        dst_is_row(*old(self), f),
                        node_of(*old(self)),
                        node_of(*final(self)),
                        f.sent,
                        now.ms,
                        j,
                    )
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                    &&& cohort_pins_of(*final(self)) == cohort_pins_of(*old(self))
                },
                Decision::Cohort(j) => {
                    &&& is_cohort(sources_of(*old(self)), f.sent.src, v4(f), f.dscp)
                    &&& owner_of(cohort_pins_of(*old(self))) == f.sent.src
                    &&& owned_by(cohort_tables(*old(self)), f.sent.src)
                    &&& cohort_post(
                        plan_of(sources_of(*old(self))),
                        members_of(*old(self)),
                        alias_for(*old(self), AliasSource::Cohort, f),
                        cohort_tables(*old(self)),
                        cohort_tables(*final(self)),
                        cohort_pins_of(*old(self)),
                        cohort_pins_of(*final(self)),
                        f.sent,
                        now.ms,
                        j,
                    )
                    &&& crate::judge::pins_same(node_of(*final(self)).pins, node_of(*old(self)).pins)
                    &&& crate::judge::pins_same(cohort_of(*final(self)).pins, cohort_of(*old(self)).pins)
                    &&& cohort_spare(*final(self)) == cohort_spare(*old(self))
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                },
            },
    ))]
    pub fn egress(&mut self, f: Frame, now: Instant) -> Decision {
        let plan = self.sources.plan();
        let pair = match f.sent.kind {
            SentKind::Arp => None,
            SentKind::V4 { proto, l4, .. } => match l4 {
                Some(x) => Some((proto, x.dport)),
                None => None,
            },
        };
        match route(&self.sources, f) {
            Route::ControlSurface => Decision::Refused(Stray::ControlSurface),
            Route::Unregistered => Decision::Refused(Stray::Unregistered),
            Route::Unknown => Decision::Refused(Stray::Unknown),
            Route::Row(i) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rows_bound_at(rows_view(*self), rows_of(sources_of(*self)), i as int);
                }
                let lifts = Lifts {
                    resolves_names: self.rows[i].resolves_names,
                    alias_by_name: self.rows[i].alias_by_name,
                    box_name: self.box_name(i, f),
                    box_name_dst: sent_dst(&f.sent),
                };
                let who = AliasSource::Box {
                    names_host: self.rows[i].alias_by_name
                        || allowed_subnet(self.rows[i].rules.get(), plan.host_alias()),
                };
                let open = alias_open(&self.alias, who, pair);
                let st = &mut self.rows[i];
                let j = judge_row(&plan, &st.rules, lifts, open, &mut st.tables, f.sent, now);
                Decision::Row(i, j)
            }
            Route::Node => {
                let to_row = match f.sent.kind {
                    SentKind::Arp => false,
                    SentKind::V4 { dst, .. } => self.sources.holds(dst),
                };
                let open = alias_open(&self.alias, AliasSource::Node, pair);
                let j = judge_node(
                    &plan,
                    self.baseline.as_slice(),
                    open,
                    to_row,
                    &mut self.node,
                    f.sent,
                    now,
                );
                Decision::Node(j)
            }
            Route::Cohort => {
                let open = alias_open(&self.alias, AliasSource::Cohort, pair);
                let j = match self.sources.spelling() {
                    CohortSpelling::NodeWithMark => judge_cohort(
                        &plan,
                        self.members.as_slice(),
                        open,
                        &mut self.node,
                        &mut self.cohort_pins,
                        f.sent,
                        now,
                    ),
                    CohortSpelling::OwnAddress => judge_cohort(
                        &plan,
                        self.members.as_slice(),
                        open,
                        &mut self.cohort,
                        &mut self.cohort_pins,
                        f.sent,
                        now,
                    ),
                };
                Decision::Cohort(j)
            }
        }
    }

    /// Records what one frame toward a guest does, in the tables of the box
    /// it is addressed to. Whether its port is published is read from the
    /// gate's own ledger: some forward dials that address at that port,
    /// whatever the forward's protocol. GI1.
    #[cfg_attr(verus_keep_ghost, verus_spec(a =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            same_setup(*final(self), *old(self)),
            cohort_pins_of(*final(self)) == cohort_pins_of(*old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
            match a {
                Arrived::NotARow => {
                    &&& !to_node(*old(self), r)
                    &&& !to_cohort(*old(self), r)
                    &&& !registered(rows_of(sources_of(*old(self))), r.dst)
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                    &&& node_of(*final(self)) == node_of(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                },
                Arrived::Row(i, s) => {
                    &&& !to_node(*old(self), r)
                    &&& !to_cohort(*old(self), r)
                    &&& i < rows_view(*old(self)).len()
                    &&& rows_of(sources_of(*old(self)))[i as int] == r.dst
                    &&& first_at(rows_of(sources_of(*old(self))), r.dst, i as int)
                    &&& seen_post(
                        spec_proxy_peer(plan_of(sources_of(*old(self)))),
                        rows_view(*old(self))[i as int].tables,
                        rows_view(*final(self))[i as int].tables,
                        r,
                        port_published(*old(self), r),
                        now.ms,
                        s,
                    )
                    &&& for_this_box(s)
                    &&& only_row_changed(rows_view(*final(self)), rows_view(*old(self)), i as int)
                    &&& node_of(*final(self)) == node_of(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                },
                Arrived::Node(s) => {
                    &&& to_node(*old(self), r)
                    &&& seen_post(
                        spec_proxy_peer(plan_of(sources_of(*old(self)))),
                        node_of(*old(self)),
                        node_of(*final(self)),
                        r,
                        port_published(*old(self), r),
                        now.ms,
                        s,
                    )
                    &&& for_this_box(s)
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                    &&& cohort_of(*final(self)) == cohort_of(*old(self))
                },
                Arrived::Cohort(s) => {
                    &&& !to_node(*old(self), r)
                    &&& to_cohort(*old(self), r)
                    &&& seen_post(
                        spec_proxy_peer(plan_of(sources_of(*old(self)))),
                        cohort_of(*old(self)),
                        cohort_of(*final(self)),
                        r,
                        port_published(*old(self), r),
                        now.ms,
                        s,
                    )
                    &&& for_this_box(s)
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                    &&& node_of(*final(self)) == node_of(*old(self))
                },
            },
    ))]
    pub fn ingress(&mut self, r: Received, now: Instant) -> Arrived {
        #[cfg(verus_keep_ghost)]
        proof! {
            assert forall|p: int, b: BoxTables, a: BoxTables, pb: bool, s: crate::ingress::Seen|
                #[trigger] seen_post(p, b, a, r, pb, now.ms, s)
                    && crate::flow::box_of(b.flows) == r.dst
                    && crate::notes::box_of(b.notes) == r.dst implies for_this_box(s) by {
                crate::ingress::lemma_seen_post_this_box(p, b, a, r, pb, now.ms, s);
            }
        }
        let published = self.ledger.dials(r.dst, r.l4.dport);
        let plan = self.sources.plan();
        let proxy = plan.proxy_peer();
        if self.sources.node_in_force() && r.dst == plan.node() {
            return Arrived::Node(observe(proxy, &mut self.node, r, published, now));
        }
        if self.sources.node_in_force() && r.dst == plan.cohort() {
            match self.sources.spelling() {
                CohortSpelling::NodeWithMark => {}
                CohortSpelling::OwnAddress => {
                    return Arrived::Cohort(observe(proxy, &mut self.cohort, r, published, now));
                }
            }
        }
        match self.sources.index_of(r.dst) {
            Some(i) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rows_bound_at(rows_view(*self), rows_of(sources_of(*self)), i as int);
                }
                let st = &mut self.rows[i];
                Arrived::Row(i, observe(proxy, &mut st.tables, r, published, now))
            }
            None => Arrived::NotARow,
        }
    }

    /// Registers a row at `addr`, after every row there is. Its tables are
    /// emptied first, whatever they held: a row starts with no reply record,
    /// no note and no DNS admission. `false`, and nothing changes, when the
    /// tables do not belong to `addr`, a row already holds `addr`, or `addr`
    /// is not an address a row may hold (a lease, or the node's). The ledger is not touched: a forward
    /// that already dials `addr` counts as published for the new row.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
            tinv(st.tables),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            r == (owned_by(st.tables, addr)
                && !registered(rows_of(sources_of(*old(self))), addr)
                && crate::origin::holdable(plan_of(sources_of(*old(self))), spelling_of(sources_of(*old(self))), addr)),
            r ==> {
                &&& rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self))).push(addr)
                &&& rows_view(*final(self)).len() == rows_view(*old(self)).len() + 1
                &&& forall|k: int| 0 <= k < rows_view(*old(self)).len() ==> #[trigger] rows_view(*final(self))[k] == rows_view(*old(self))[k]
                &&& registered_as(rows_view(*final(self))[rows_view(*old(self)).len() as int], st)
            },
            !r ==> {
                &&& rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self)))
                &&& rows_view(*final(self)) == rows_view(*old(self))
            },
    ))]
    pub fn register(&mut self, addr: u32, st: RowState) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        let mut st = st;
        if st.tables.flows.box_addr() != addr
            || st.tables.notes.box_addr() != addr
            || st.tables.pins.owner() != addr
        {
            return false;
        }
        if !self.sources.add(addr) {
            return false;
        }
        st.tables.flows.clear();
        st.tables.notes.clear();
        st.tables.pins.clear();
        self.rows.push(st);
        true
    }

    /// Retires the row at `i` and hands it back. Later rows move down by
    /// one. The ledger is not touched: the caller retracts the row's
    /// forwards.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
            i < rows_view(*old(self)).len(),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            r == rows_view(*old(self))[i as int],
            rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self))).remove(i as int),
            rows_view(*final(self)) == rows_view(*old(self)).remove(i as int),
    ))]
    pub(crate) fn retire(&mut self, i: usize) -> RowState {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        self.sources.remove(i);
        self.rows.remove(i)
    }

    /// The index of the row at `addr`, if a row holds it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*self),
        ensures
            match r {
                Some(i) => i < rows_view(*self).len() && rows_of(sources_of(*self))[i as int] == addr,
                None => !registered(rows_of(sources_of(*self)), addr),
            },
    ))]
    pub fn row_at(&self, addr: u32) -> Option<usize> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        self.sources.index_of(addr)
    }

    /// Retires the row at `addr`, if a row holds it, and hands it back.
    /// Afterwards no row holds `addr`. GR1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            !registered(rows_of(sources_of(*final(self))), addr),
            match r {
                Some(st) => {
                    &&& registered(rows_of(sources_of(*old(self))), addr)
                    &&& exists|i: int| rows_of(sources_of(*old(self)))[i] == addr && retired_at(*final(self), *old(self), st, i)
                },
                None => {
                    &&& !registered(rows_of(sources_of(*old(self))), addr)
                    &&& rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self)))
                    &&& rows_view(*final(self)) == rows_view(*old(self))
                },
            },
    ))]
    pub fn retire_at(&mut self, addr: u32) -> Option<RowState> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        match self.sources.index_of(addr) {
            Some(i) => Some(self.retire(i)),
            None => None,
        }
    }

    /// Empties the named tables of the row at `addr`, keeping the row: a
    /// relay that carried it ended. `false`, and nothing changes, when no
    /// row holds `addr`. GC1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self))),
            r == registered(rows_of(sources_of(*old(self))), addr),
            !r ==> rows_view(*final(self)) == rows_view(*old(self)),
            r ==> exists|i: int| {
                &&& 0 <= i < rows_view(*old(self)).len()
                &&& rows_of(sources_of(*old(self)))[i] == addr
                &&& only_row_changed(rows_view(*final(self)), rows_view(*old(self)), i)
                &&& cleared(rows_view(*final(self))[i].tables, rows_view(*old(self))[i].tables, which)
            },
    ))]
    pub fn clear_at(&mut self, addr: u32, which: Which) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        match self.sources.index_of(addr) {
            Some(i) => {
                let st = &mut self.rows[i];
                clear_tables(&mut st.tables, which);
                true
            }
            None => false,
        }
    }

    /// Empties the named tables of the node. Nothing else changes. GC1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            same_setup(*final(self), *old(self)),
            rows_view(*final(self)) == rows_view(*old(self)),
            cohort_of(*final(self)) == cohort_of(*old(self)),
            cohort_pins_of(*final(self)) == cohort_pins_of(*old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
            cleared(node_of(*final(self)), node_of(*old(self)), which),
    ))]
    pub fn clear_node(&mut self, which: Which) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        clear_tables(&mut self.node, which);
    }

    /// Gives the row at `i` another name. Its rules and its tables are
    /// kept, and no other row changes: a row that lists the old name no
    /// longer reaches this one, and a row that lists the new one does.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
            i < rows_view(*old(self)).len(),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self))),
            rows_view(*final(self)).len() == rows_view(*old(self)).len(),
            renamed(rows_view(*final(self))[i as int], rows_view(*old(self))[i as int], name_id),
            forall|k: int| 0 <= k < rows_view(*old(self)).len() && k != i ==> #[trigger] rows_view(*final(self))[k] == rows_view(*old(self))[k],
    ))]
    pub(crate) fn rename(&mut self, i: usize, name_id: u32) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        set_name(&mut self.rows[i], name_id);
    }

    /// Gives the row at `addr` another name, as `rename`. `false`, and
    /// nothing changes, when no row holds `addr`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            only_rows_changed(*final(self), *old(self)),
            rows_of(sources_of(*final(self))) == rows_of(sources_of(*old(self))),
            rows_view(*final(self)).len() == rows_view(*old(self)).len(),
            r == registered(rows_of(sources_of(*old(self))), addr),
            !r ==> rows_view(*final(self)) == rows_view(*old(self)),
            r ==> exists|i: int| 0 <= i < rows_view(*old(self)).len()
                && rows_of(sources_of(*old(self)))[i] == addr
                && renamed(rows_view(*final(self))[i], rows_view(*old(self))[i], name_id)
                && forall|k: int| 0 <= k < rows_view(*old(self)).len() && k != i
                    ==> #[trigger] rows_view(*final(self))[k] == rows_view(*old(self))[k],
    ))]
    pub fn rename_at(&mut self, addr: u32, name_id: u32) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        match self.sources.index_of(addr) {
            Some(i) => {
                self.rename(i, name_id);
                true
            }
            None => false,
        }
    }

    /// Replaces what the gate knows of the host alias: the node's baseline
    /// ports there, the product's own listeners, the exposure table. Changes
    /// nothing else.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            alias_of(*final(self)) == alias,
            sources_of(*final(self)) == sources_of(*old(self)),
            rows_view(*final(self)) == rows_view(*old(self)),
            node_of(*final(self)) == node_of(*old(self)),
            cohort_of(*final(self)) == cohort_of(*old(self)),
            baseline_of(*final(self)) == baseline_of(*old(self)),
            members_of(*final(self)) == members_of(*old(self)),
            cohort_pins_of(*final(self)) == cohort_pins_of(*old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
    ))]
    pub fn set_alias(&mut self, alias: AliasState) {
        self.alias = alias;
    }

    /// Replaces the cohort's members: the host-address boxes resident now,
    /// each with its rules. Nothing else changes; the cohort's DNS tables
    /// are emptied by `clear_cohort_dns` when its record changes. GM1.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            members_of(*final(self)) == members@,
            sources_of(*final(self)) == sources_of(*old(self)),
            rows_view(*final(self)) == rows_view(*old(self)),
            node_of(*final(self)) == node_of(*old(self)),
            cohort_of(*final(self)) == cohort_of(*old(self)),
            baseline_of(*final(self)) == baseline_of(*old(self)),
            alias_of(*final(self)) == alias_of(*old(self)),
            cohort_pins_of(*final(self)) == cohort_pins_of(*old(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
    ))]
    pub fn set_members(&mut self, members: Vec<Member>) {
        self.members = members;
    }

    /// The tables of the row at `addr`, of the node, or the cohort's own, to
    /// read. `None` when no row holds `addr`. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*self),
        ensures
            match t {
                DnsTable::Node => r.is_some() && *r.unwrap() == node_of(*self),
                DnsTable::Cohort => r.is_some() && *r.unwrap() == cohort_of(*self),
                DnsTable::Row(a) => if registered(rows_of(sources_of(*self)), a) {
                    r.is_some() && *r.unwrap() == rows_view(*self)[target_of(rows_of(sources_of(*self)), a)].tables
                } else {
                    r.is_none()
                },
            },
    ))]
    pub fn tables_at(&self, t: DnsTable) -> Option<&BoxTables> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        match t {
            DnsTable::Node => Some(&self.node),
            DnsTable::Cohort => Some(&self.cohort),
            DnsTable::Row(a) => match self.sources.index_of(a) {
                Some(i) => {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_target_is(rows_of(self.sources), a, i as int);
                    }
                    Some(&self.rows[i].tables)
                }
                None => None,
            },
        }
    }

    /// Applies a publish to the gate's ledger. Changes nothing else.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            only_ledger_changed(*final(self), *old(self)),
            publish_post(ledger_of(*old(self)), ledger_of(*final(self)), f, r),
    ))]
    pub fn publish(&mut self, f: Forward) -> Published {
        self.ledger.publish(f)
    }

    /// Retracts a listener's forward from the gate's ledger and hands it
    /// back. If no forward left dials the same address and port in the same
    /// protocol, the reply records at that protocol and port end with it, in
    /// every reply table of that address. Nothing else changes. GP1.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            retract_post(ledger_of(*old(self)), ledger_of(*final(self)), la, lp, r),
            retracted(*old(self), *final(self), r),
    ))]
    pub fn retract(&mut self, la: u32, lp: u16) -> Option<Forward> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        let r = self.ledger.retract(la, lp);
        if let Some(e) = r {
            let dialled = self.ledger.dials_in(e.addr, e.inside, e.proto);
            if !dialled {
                self.end_port_at(e.addr, e.proto, e.inside);
            }
        }
        r
    }

    /// Ends the reply records of `proto` at `port` in every reply table that
    /// belongs to `addr`.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ginv(*old(self)),
        ensures
            ginv(*final(self)),
            ledger_of(*final(self)) == ledger_of(*old(self)),
            port_ended_at(*final(self), *old(self), addr, proto, port),
    ))]
    fn end_port_at(&mut self, addr: u32, proto: u8, port: u16) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(rows_bound);
        }
        if self.node.flows.box_addr() == addr {
            end_tables_port(&mut self.node, proto, port);
        }
        if self.cohort.flows.box_addr() == addr {
            end_tables_port(&mut self.cohort, proto, port);
        }
        if let Some(i) = self.sources.index_of(addr) {
            let st = &mut self.rows[i];
            end_tables_port(&mut st.tables, proto, port);
        }
    }
}

/// Ends the reply records of `proto` at `port` in one box's tables.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        tables_port_ended(*final(t), *old(t), proto, port),
))]
fn end_tables_port(t: &mut BoxTables, proto: u8, port: u16) {
    let _ = t.flows.end_port(proto, port);
}

/// Empties the named tables and no other. GC1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        cleared(*final(t), *old(t), which),
))]
fn clear_tables(t: &mut BoxTables, which: Which) {
    match which {
        Which::Records => {
            t.flows.clear();
            t.notes.clear();
        }
        Which::Dns => {
            t.pins.clear();
        }
        Which::All => {
            t.flows.clear();
            t.notes.clear();
            t.pins.clear();
        }
    }
}

/// Empties every row's DNS tables and nothing else.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires
        forall|k: int| 0 <= k < old(rows)@.len() ==> tinv((#[trigger] old(rows)@[k]).tables),
    ensures
        final(rows)@.len() == old(rows)@.len(),
        forall|k: int| 0 <= k < old(rows)@.len() ==> tinv((#[trigger] final(rows)@[k]).tables)
            && row_reset(final(rows)@[k], old(rows)@[k]),
))]
fn reset_rows(rows: &mut Vec<RowState>) {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= rows@.len(),
            rows@.len() == old(rows)@.len(),
            forall|k: int| 0 <= k < i ==> tinv((#[trigger] rows@[k]).tables) && row_reset(rows@[k], old(rows)@[k]),
            forall|k: int| i <= k < rows@.len() ==> (#[trigger] rows@[k]) == old(rows)@[k],
            forall|k: int| 0 <= k < old(rows)@.len() ==> tinv((#[trigger] old(rows)@[k]).tables),
        decreases rows.len() - i,
    ))]
    while i < rows.len() {
        let st = &mut rows[i];
        clear_tables(&mut st.tables, Which::Dns);
        i += 1;
    }
}

/// Records a question in one box's DNS tables and touches nothing else of
/// that box.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        final(t).flows == old(t).flows,
        final(t).notes == old(t).notes,
        ask_post(old(t).pins, final(t).pins, name, txid, port, now_ms, r),
))]
fn ask_in(t: &mut BoxTables, name: u32, txid: u16, port: u16, now_ms: u64) -> Asked {
    t.pins.ask(name, txid, port, Instant { ms: now_ms })
}

/// Offers a reply to one box's DNS tables and touches nothing else of that
/// box.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        tinv(*old(t)),
        addrs@.len() <= u16::MAX,
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        final(t).flows == old(t).flows,
        final(t).notes == old(t).notes,
        resolve_post(old(t).pins, final(t).pins, name, txid, port, addrs@, now_ms, r),
))]
fn resolve_in(
    t: &mut BoxTables,
    name: u32,
    txid: u16,
    port: u16,
    addrs: &[u32],
    now_ms: u64,
) -> Option<Admits> {
    t.pins
        .resolve(name, txid, port, addrs, Instant { ms: now_ms })
}

/// Expires questions in one box's DNS tables and touches nothing else of
/// that box.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        final(t).flows == old(t).flows,
        final(t).notes == old(t).notes,
        expire_questions_post(old(t).pins, final(t).pins, now_ms, budget, r),
))]
fn expire_in(t: &mut BoxTables, now_ms: u64, budget: usize) -> usize {
    t.pins.expire_questions(Instant { ms: now_ms }, budget)
}

/// Sets a row's name and nothing else.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures
        renamed(*final(st), *old(st), name_id),
))]
fn set_name(st: &mut RowState, name_id: u32) {
    st.name_id = name_id;
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Decision {
    /// Whether the frame is admitted. False of every refusal.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == decision_admits(*self),
    ))]
    pub fn admits(&self) -> bool {
        match *self {
            Decision::Refused(_) => false,
            Decision::Row(_, j) => judged_admits(j),
            Decision::Node(j) => node_judged_admits(j),
            Decision::Cohort(j) => cohort_judged_admits(j),
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Arrived {
    /// Whether the frame is delivered.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == arrived_delivers(*self),
    ))]
    pub fn delivers(&self) -> bool {
        match *self {
            Arrived::NotARow => true,
            Arrived::Row(_, s) => seen_delivers(s),
            Arrived::Node(s) => seen_delivers(s),
            Arrived::Cohort(s) => seen_delivers(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cohort::CohortArm;
    use crate::flow::{Flows, Windows};
    use crate::judge::{Sent, SentL4};
    use crate::node::NodeArm;
    use crate::notes::Notes;
    use crate::origin::{BOX_COHORT_DSCP, CohortSpelling};
    use crate::pins::Limits;
    use crate::plan::Plan;
    use crate::policy::{Abilities, Declared, Enforced, Net, Section, effective};
    use crate::row::{RowArm, RowRules};
    use crate::time::Span;

    // 100.64.0.0/24: gateway .1, node .253.
    const NET: u32 = 0x6440_0000;
    const NODE: u32 = NET + 253;
    const PUBLIC: u32 = 0xcb00_7107;

    fn tables(owner: u32) -> BoxTables {
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
            flows: Flows::new(owner, 4, windows, Span { ms: 1_000 }).unwrap(),
            notes: Notes::new(owner, 4, 2, Span { ms: 5_000 }).unwrap(),
            pins: Pins::new(owner, limits).unwrap(),
        }
    }

    fn row(owner: u32, allow: Option<Vec<Cidr>>) -> RowState {
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
        RowState {
            rules: made(RowRules {
                allow_protocols: None,
                deny: Vec::new(),
                allow_subnets: allow,
                laned: false,
            }),
            resolves_names: false,
            alias_by_name: false,
            name_id: owner,
            task_row: false,
            names_boxes: Vec::new(),
            tables: tables(owner),
        }
    }

    fn gate(owners: [u32; 2]) -> Option<Gate> {
        gate_with(owners, NODE, NODE)
    }

    fn gate_with(owners: [u32; 2], node_owner: u32, cohort_owner: u32) -> Option<Gate> {
        gate_spelled(
            owners,
            node_owner,
            cohort_owner,
            CohortSpelling::NodeWithMark,
        )
    }

    fn gate_spelled(
        owners: [u32; 2],
        node_owner: u32,
        cohort_owner: u32,
        spelling: CohortSpelling,
    ) -> Option<Gate> {
        // A refusal here would read as the gate's own, so each is a panic.
        let Ok(plan) = Plan::new(NET, 24) else {
            panic!("the plan is refused");
        };
        let Some(sources) = Sources::new(plan, vec![NET + 7, NET + 9], true, spelling) else {
            panic!("the sources are refused");
        };
        let limits = Limits {
            asked_cap: 1,
            asked_per_name: 1,
            admitted_cap: 1,
            admitted_per_name: 1,
            flows_cap: 1,
            flows_per_destination: 1,
            query_ms: 1,
            window_ms: 1,
            idle_ms: 1,
        };
        let Some(pins) = Pins::new(cohort_owner, limits) else {
            panic!("the limits are refused");
        };
        Gate::new(
            sources,
            vec![row(owners[0], None), row(owners[1], Some(Vec::new()))],
            tables(node_owner),
            tables(cohort_owner),
            Vec::new(),
            Vec::new(),
            pins,
            Ledger::new(8, 8),
            AliasState {
                node_ports: Vec::new(),
                held: Vec::new(),
                exposures: vec![crate::alias::Exposure {
                    proto: 6,
                    port: 5432,
                }],
            },
        )
    }

    fn tcp(src: u32, dst: u32, dscp: u8) -> Frame {
        Frame {
            sent: Sent {
                src,
                kind: SentKind::V4 {
                    dst,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 50000,
                        dport: 443,
                        flags: 0x02,
                        seq: 0,
                        ack: 0,
                        payload_len: 0,
                    }),
                },
            },
            dscp,
        }
    }

    #[test]
    fn tables_that_belong_to_another_row_are_refused_at_construction() {
        assert!(gate([NET + 7, NET + 9]).is_some());
        assert!(gate([NET + 9, NET + 7]).is_none());
        assert!(gate([NET + 7, NET + 7]).is_none());
    }

    #[test]
    fn node_or_cohort_tables_that_belong_to_another_address_are_refused_at_construction() {
        let rows = [NET + 7, NET + 9];
        assert!(gate_with(rows, NODE, NODE).is_some());
        assert!(gate_with(rows, NET + 7, NODE).is_none());
        assert!(gate_with(rows, NODE, NET + 7).is_none());
        // Under the mark spelling the cohort sends from the node's address,
        // not from the plan's cohort address.
        let cohort = Plan::new(NET, 24).unwrap().cohort();
        assert!(gate_with(rows, NODE, cohort).is_none());
    }

    #[test]
    fn under_its_own_address_the_cohort_has_its_own_tables() {
        use crate::flow::Inbound;
        let cohort = Plan::new(NET, 24).unwrap().cohort();
        let rows = [NET + 7, NET + 9];
        // The cohort's tables must belong to the cohort's address, not the node's.
        assert!(gate_spelled(rows, NODE, NODE, CohortSpelling::OwnAddress).is_none());
        let mut g = gate_spelled(rows, NODE, cohort, CohortSpelling::OwnAddress).unwrap();
        let forward = Forward {
            listener_addr: 0x7f00_4001,
            listener_port: 8080,
            addr: cohort,
            inside: 8080,
            proto: 6,
            by: crate::ledger::Applier::Row,
        };
        assert_eq!(g.publish(forward), Published::Noted);
        let connect = Received {
            src: NET + 1,
            dst: cohort,
            proto: 6,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        assert_eq!(
            g.ingress(connect, Instant { ms: 0 }),
            Arrived::Cohort(Seen::Flow(Inbound::Opened))
        );
        let answer = |src: u32| Frame {
            sent: Sent {
                src,
                kind: SentKind::V4 {
                    dst: NET + 1,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 8080,
                        dport: 40000,
                        flags: 0x12,
                        seq: 0,
                        ack: 1,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        // The cohort answers from its own record; the node, which received
        // nothing, has none.
        assert_eq!(
            g.egress(answer(cohort), Instant { ms: 1 }),
            Decision::Cohort(CohortJudged::ReplyFlow)
        );
        assert_eq!(
            g.egress(answer(NODE), Instant { ms: 1 }),
            Decision::Node(NodeJudged::Node(NodeArm::ControlSurface))
        );
    }

    #[test]
    fn a_row_registered_at_a_reused_address_starts_with_no_records() {
        use crate::flow::Inbound;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let forward = Forward {
            listener_addr: 0x7f00_4009,
            listener_port: 8080,
            addr: NET + 9,
            inside: 8080,
            proto: 6,
            by: crate::ledger::Applier::Row,
        };
        assert_eq!(g.publish(forward), Published::Noted);
        let connect = Received {
            src: NET + 1,
            dst: NET + 9,
            proto: 6,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        assert_eq!(
            g.ingress(connect, Instant { ms: 0 }),
            Arrived::Row(1, Seen::Flow(Inbound::Opened))
        );
        let answer = Frame {
            sent: Sent {
                src: NET + 9,
                kind: SentKind::V4 {
                    dst: NET + 1,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 8080,
                        dport: 40000,
                        flags: 0x12,
                        seq: 0,
                        ack: 1,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        // The row leaves and a row arrives at the same address, handed the
        // very tables the first one left behind.
        let left = g.retire(1);
        assert_eq!(
            g.egress(answer, Instant { ms: 1 }),
            Decision::Refused(Stray::ControlSurface)
        );
        assert!(g.register(NET + 9, left));
        assert_eq!(
            g.egress(answer, Instant { ms: 1 }),
            Decision::Row(1, Judged::Row(RowArm::ControlSurface))
        );
        // Tables that belong to another address are not registered; nor is a
        // second row at a held address, nor a row at the gateway's.
        assert!(!g.register(NET + 11, row(NET + 12, None)));
        assert!(!g.register(NET + 9, row(NET + 9, None)));
        assert!(!g.register(NET + 1, row(NET + 1, None)));
        assert!(g.register(NET + 11, row(NET + 11, None)));
    }

    #[test]
    fn clearing_a_rows_records_keeps_the_row_and_ends_its_replies() {
        use crate::flow::Inbound;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let forward = Forward {
            listener_addr: 0x7f00_4009,
            listener_port: 8080,
            addr: NET + 9,
            inside: 8080,
            proto: 6,
            by: crate::ledger::Applier::Row,
        };
        assert_eq!(g.publish(forward), Published::Noted);
        let connect = Received {
            src: NET + 1,
            dst: NET + 9,
            proto: 6,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        let answer = Frame {
            sent: Sent {
                src: NET + 9,
                kind: SentKind::V4 {
                    dst: NET + 1,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 8080,
                        dport: 40000,
                        flags: 0x12,
                        seq: 0,
                        ack: 1,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        assert_eq!(
            g.ingress(connect, Instant { ms: 0 }),
            Arrived::Row(1, Seen::Flow(Inbound::Opened))
        );
        // Clearing the DNS tables leaves the reply record; clearing the records ends it.
        assert!(g.clear_at(NET + 9, Which::Dns));
        assert_eq!(
            g.egress(answer, Instant { ms: 1 }),
            Decision::Row(1, Judged::ReplyFlow)
        );
        assert!(g.clear_at(NET + 9, Which::Records));
        assert_eq!(
            g.egress(answer, Instant { ms: 2 }),
            Decision::Row(1, Judged::Row(RowArm::ControlSurface))
        );
        // The row is still there, and an address no row holds clears nothing.
        assert_eq!(g.row_at(NET + 9), Some(1));
        assert!(!g.clear_at(NET + 11, Which::All));
        g.clear_node(Which::All);
    }

    #[test]
    fn a_refused_source_is_not_admitted_and_a_frame_to_no_row_is_delivered() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let stray = g.egress(tcp(NET + 8, PUBLIC, 0), Instant { ms: 0 });
        assert_eq!(stray, Decision::Refused(Stray::Unregistered));
        assert!(!stray.admits());
        assert!(
            g.egress(tcp(NET + 7, PUBLIC, 0), Instant { ms: 0 })
                .admits()
        );
        assert!(
            !g.egress(tcp(NET + 9, PUBLIC, 0), Instant { ms: 0 })
                .admits()
        );
        assert!(Arrived::NotARow.delivers());
        assert!(!Decision::Row(0, Judged::Pinned(crate::pins::Egress::Refused)).admits());
    }

    #[test]
    fn a_frame_toward_a_box_is_recorded_in_that_boxs_tables_and_answered_from_them() {
        use crate::flow::Inbound;
        use crate::ingress::Received;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        for addr in [NET + 9, NODE] {
            let forward = Forward {
                listener_addr: 0x7f00_4000 + (addr & 0xff),
                listener_port: 8080,
                addr,
                inside: 8080,
                proto: 6,
                by: crate::ledger::Applier::Row,
            };
            assert_eq!(g.publish(forward), Published::Noted);
        }
        let from_gateway = |dst: u32| Received {
            src: NET + 1,
            dst,
            proto: 6,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        assert_eq!(
            g.ingress(from_gateway(NET + 9), Instant { ms: 0 }),
            Arrived::Row(1, Seen::Flow(Inbound::Opened))
        );
        assert_eq!(
            g.ingress(from_gateway(NET + 8), Instant { ms: 0 }),
            Arrived::NotARow
        );
        assert_eq!(
            g.ingress(from_gateway(NODE), Instant { ms: 0 }),
            Arrived::Node(Seen::Flow(Inbound::Opened))
        );
        // The deny-all row answers its client; the other row, which received
        // nothing, has no record to answer from.
        let answer = |src: u32| Frame {
            sent: Sent {
                src,
                kind: SentKind::V4 {
                    dst: NET + 1,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 8080,
                        dport: 40000,
                        flags: 0x12,
                        seq: 0,
                        ack: 1,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        assert_eq!(
            g.egress(answer(NET + 9), Instant { ms: 1 }),
            Decision::Row(1, Judged::ReplyFlow)
        );
        assert_eq!(
            g.egress(answer(NET + 7), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::ControlSurface))
        );
    }

    #[test]
    fn a_port_stops_opening_records_when_its_forward_is_retracted() {
        use crate::flow::Inbound;
        use crate::ingress::Received;
        use crate::notes::Noted;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let connect = |sport: u16| Received {
            src: NET + 1,
            dst: NET + 7,
            proto: 6,
            l4: SentL4 {
                sport,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        // Nothing published: the connect is noted, no record opens.
        assert_eq!(
            g.ingress(connect(1), Instant { ms: 0 }),
            Arrived::Row(0, Seen::Noted(Noted::Noted))
        );
        let forward = Forward {
            listener_addr: 0x7f00_4007,
            listener_port: 18080,
            addr: NET + 7,
            inside: 8080,
            proto: 6,
            by: crate::ledger::Applier::Row,
        };
        assert_eq!(g.publish(forward), Published::Noted);
        assert_eq!(
            g.ingress(connect(2), Instant { ms: 0 }),
            Arrived::Row(0, Seen::Flow(Inbound::Opened))
        );
        assert_eq!(g.retract(0x7f00_4007, 18080), Some(forward));
        assert_eq!(
            g.ingress(connect(3), Instant { ms: 0 }),
            Arrived::Row(0, Seen::Noted(Noted::Noted))
        );
    }

    #[test]
    fn a_retraction_ends_the_ports_reply_records_unless_another_forward_still_dials_it() {
        use crate::flow::Inbound;
        use crate::ingress::Received;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let connect = |proto: u8, flags: u8| Received {
            src: NET + 1,
            dst: NET + 7,
            proto,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        let answer = |proto: u8, flags: u8| Frame {
            sent: Sent {
                src: NET + 7,
                kind: SentKind::V4 {
                    dst: NET + 1,
                    proto,
                    l4: Some(SentL4 {
                        sport: 8080,
                        dport: 40000,
                        flags,
                        seq: 0,
                        ack: 1,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        let forward = |listener_port: u16, proto: u8| Forward {
            listener_addr: 0x7f00_4007,
            listener_port,
            addr: NET + 7,
            inside: 8080,
            proto,
            by: crate::ledger::Applier::Row,
        };
        // Two TCP listeners and one UDP listener dial the same inside port.
        assert_eq!(g.publish(forward(18080, 6)), Published::Noted);
        assert_eq!(g.publish(forward(18081, 6)), Published::Noted);
        assert_eq!(g.publish(forward(18082, 17)), Published::Noted);
        assert_eq!(
            g.ingress(connect(6, 0x02), Instant { ms: 0 }),
            Arrived::Row(0, Seen::Flow(Inbound::Opened))
        );
        assert_eq!(
            g.ingress(connect(17, 0), Instant { ms: 0 }),
            Arrived::Row(0, Seen::Flow(Inbound::Opened))
        );
        assert_eq!(
            g.egress(answer(6, 0x12), Instant { ms: 1 }),
            Decision::Row(0, Judged::ReplyFlow)
        );
        // One TCP listener goes; the other still dials the port: the record stays.
        assert_eq!(g.retract(0x7f00_4007, 18080), Some(forward(18080, 6)));
        assert_eq!(
            g.egress(answer(6, 0x10), Instant { ms: 2 }),
            Decision::Row(0, Judged::ReplyFlow)
        );
        // The last TCP listener goes. The UDP forward does not keep the TCP
        // record, and the UDP record is untouched.
        assert_eq!(g.retract(0x7f00_4007, 18081), Some(forward(18081, 6)));
        assert_eq!(
            g.egress(answer(6, 0x10), Instant { ms: 3 }),
            Decision::Row(0, Judged::Row(RowArm::ControlSurface))
        );
        assert_eq!(
            g.egress(answer(17, 0), Instant { ms: 3 }),
            Decision::Row(0, Judged::ReplyFlow)
        );
        // A retraction of a listener nothing holds changes nothing.
        assert_eq!(g.retract(0x7f00_4007, 18080), None);
        assert_eq!(
            g.egress(answer(17, 0), Instant { ms: 4 }),
            Decision::Row(0, Judged::ReplyFlow)
        );
    }

    #[test]
    fn the_alias_opens_at_an_exposure_to_a_row_that_names_the_host_and_to_no_other() {
        let alias = NET + 254;
        let to_alias = |src: u32, dport: u16| Frame {
            sent: Sent {
                src,
                kind: SentKind::V4 {
                    dst: alias,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 50000,
                        dport,
                        flags: 0x02,
                        seq: 0,
                        ack: 0,
                        payload_len: 0,
                    }),
                },
            },
            dscp: 0,
        };
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        // Row 0 allows every subnet, so it names the host; row 1 allows none.
        assert_eq!(
            g.egress(to_alias(NET + 7, 5432), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::Rules))
        );
        assert_eq!(
            g.egress(to_alias(NET + 7, 5433), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::AliasClosed))
        );
        assert_eq!(
            g.egress(to_alias(NET + 9, 5432), Instant { ms: 1 }),
            Decision::Row(1, Judged::Row(RowArm::AliasClosed))
        );
        // The exposure table changes under a running gate.
        g.set_alias(AliasState {
            node_ports: Vec::new(),
            held: Vec::new(),
            exposures: Vec::new(),
        });
        assert_eq!(
            g.egress(to_alias(NET + 7, 5432), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::AliasClosed))
        );
    }

    #[test]
    fn a_row_that_lists_box_names_reaches_the_boxes_it_names_and_no_other_row() {
        let plan = Plan::new(NET, 24).unwrap();
        let sources = Sources::new(
            plan,
            vec![NET + 7, NET + 9, NET + 10],
            true,
            CohortSpelling::NodeWithMark,
        )
        .unwrap();
        // Row 0 allows no subnet and names the box whose number is NET + 9.
        let mut naming = row(NET + 7, Some(Vec::new()));
        naming.names_boxes = vec![NET + 9];
        let mut task = row(NET + 10, None);
        task.task_row = true;
        task.name_id = NET + 9;
        let mut g = Gate::new(
            sources,
            vec![naming, row(NET + 9, None), task],
            tables(NODE),
            tables(NODE),
            Vec::new(),
            Vec::new(),
            Pins::new(
                NODE,
                Limits {
                    asked_cap: 1,
                    asked_per_name: 1,
                    admitted_cap: 1,
                    admitted_per_name: 1,
                    flows_cap: 1,
                    flows_per_destination: 1,
                    query_ms: 1,
                    window_ms: 1,
                    idle_ms: 1,
                },
            )
            .unwrap(),
            Ledger::new(8, 8),
            AliasState {
                node_ports: Vec::new(),
                held: Vec::new(),
                exposures: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 9, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::BoxName)
        );
        // A task sandbox's address is no box's lease, whatever its number.
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 10, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::BoxNameRefused)
        );
        // An address no row holds: the rule is silent and the rules decide.
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 11, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::UndeclaredSubnet))
        );
        // A row that lists no names is not judged by names at all.
        assert_eq!(
            g.egress(tcp(NET + 9, NET + 7, 0), Instant { ms: 1 }),
            Decision::Row(1, Judged::Row(RowArm::Rules))
        );
        // Renamed, the box is no longer the one row 0 names; named back, it is.
        assert_eq!(g.row_at(NET + 9), Some(1));
        assert!(g.rename_at(NET + 9, 77));
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 9, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::BoxNameRefused)
        );
        assert!(g.rename_at(NET + 9, NET + 9));
        // No row holds this address: nothing is renamed.
        assert!(!g.rename_at(NET + 11, 5));
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 9, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::BoxName)
        );
        assert_eq!(
            g.egress(tcp(NET + 7, NET + 9, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::BoxName)
        );
        // Retired by address: later rows move down, and the address is no row's.
        assert!(g.retire_at(NET + 7).is_some());
        assert_eq!(g.row_at(NET + 9), Some(0));
        assert!(g.retire_at(NET + 7).is_none() && g.row_at(NET + 7).is_none());
    }

    #[test]
    fn each_row_is_decided_by_its_own_rules() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert_eq!(
            g.egress(tcp(NET + 7, PUBLIC, 0), Instant { ms: 1 }),
            Decision::Row(0, Judged::Row(RowArm::Rules))
        );
        assert_eq!(
            g.egress(tcp(NET + 9, PUBLIC, 0), Instant { ms: 1 }),
            Decision::Row(1, Judged::Row(RowArm::UndeclaredSubnet))
        );
    }

    #[test]
    fn a_question_is_recorded_in_the_table_its_source_and_mark_name() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert_eq!(
            g.dns_ask(NET + 7, false, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Row(NET + 7), Asked::Recorded))
        );
        // The mark is not read for a row's address.
        assert_eq!(
            g.dns_ask(NET + 9, true, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Row(NET + 9), Asked::Recorded))
        );
        // The node's address: marked is the cohort's, unmarked the node's.
        assert_eq!(
            g.dns_ask(NODE, true, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Cohort, Asked::Recorded))
        );
        assert_eq!(
            g.dns_ask(NODE, false, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Node, Asked::Recorded))
        );
        // The same question again in the same table is a refresh there.
        assert_eq!(
            g.dns_ask(NODE, false, 0, 7, 5000, Instant { ms: 1 }),
            Some((DnsTable::Node, Asked::Refreshed))
        );
        assert_eq!(
            g.dns_ask(NET + 8, false, 0, 7, 5000, Instant { ms: 0 }),
            None
        );
    }

    #[test]
    fn a_reply_is_offered_to_the_tables_its_destination_names() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let admitted = |n| {
            Some(Admits {
                admitted: n,
                refused: 0,
            })
        };
        // A row's reply goes to that row's table and to no other.
        assert!(
            g.dns_ask(NET + 7, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        let r = g
            .dns_answer(
                NET + 7,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                Some(0),
                &[PUBLIC],
                Instant { ms: 1 },
            )
            .answered;
        assert_eq!(r.own_table, Some(DnsTable::Row(NET + 7)));
        assert_eq!(r.own, admitted(1));
        assert_eq!(r.cohort_at_node, None);
        // The question was consumed.
        let r = g
            .dns_answer(
                NET + 7,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                None,
                &[],
                Instant { ms: 2 },
            )
            .answered;
        assert_eq!(r.own, None);
        // A reply to an address no row holds reaches no table.
        let r = g
            .dns_answer(
                NET + 8,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                Some(0),
                &[PUBLIC],
                Instant { ms: 2 },
            )
            .answered;
        assert_eq!((r.own_table, r.own, r.cohort_at_node), (None, None, None));
    }

    // At the node's address both tables may hold the question, and
    // each admits the addresses it was given.
    #[test]
    fn at_the_nodes_address_each_table_admits_its_own_list() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert_eq!(
            g.dns_ask(NODE, false, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Node, Asked::Recorded))
        );
        assert_eq!(
            g.dns_ask(NODE, true, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Cohort, Asked::Recorded))
        );
        let r = g
            .dns_answer(
                NODE,
                7,
                5000,
                Some(0),
                &[PUBLIC, PUBLIC + 1],
                Some(0),
                &[PUBLIC + 2],
                Instant { ms: 0 },
            )
            .answered;
        assert_eq!(r.own_table, Some(DnsTable::Node));
        assert_eq!(
            r.own,
            Some(Admits {
                admitted: 2,
                refused: 0
            })
        );
        assert_eq!(
            r.cohort_at_node,
            Some(Admits {
                admitted: 1,
                refused: 0
            })
        );
        // Both questions were consumed.
        let r = g
            .dns_answer(
                NODE,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                Some(0),
                &[PUBLIC],
                Instant { ms: 0 },
            )
            .answered;
        assert_eq!((r.own, r.cohort_at_node), (None, None));
    }

    // A table that does not declare the name is not touched: its question
    // stays for an answer that does name it.
    #[test]
    fn a_table_given_no_name_keeps_its_question() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert!(
            g.dns_ask(NODE, true, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        let r = g
            .dns_answer(NODE, 7, 5000, None, &[], None, &[], Instant { ms: 0 })
            .answered;
        assert_eq!((r.own, r.cohort_at_node), (None, None));
        let r = g
            .dns_answer(
                NODE,
                7,
                5000,
                None,
                &[],
                Some(0),
                &[PUBLIC],
                Instant { ms: 0 },
            )
            .answered;
        assert_eq!(
            r.cohort_at_node,
            Some(Admits {
                admitted: 1,
                refused: 0
            })
        );
    }

    // The cohort's table takes a reply while the baseline is only announced, and the address it
    // admitted is still admitted once the baseline is in force.
    #[test]
    fn what_the_cohort_resolved_while_announced_is_admitted_in_force() {
        let plan = Plan::new(NET, 24).unwrap();
        let sources = Sources::new(
            plan,
            vec![NET + 7, NET + 9],
            false,
            CohortSpelling::NodeWithMark,
        )
        .unwrap();
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
        let member = Member {
            rules: row(NODE, Some(Vec::new())).rules,
            resolves_names: true,
        };
        let mut g = Gate::new(
            sources,
            vec![row(NET + 7, None), row(NET + 9, Some(Vec::new()))],
            tables(NODE),
            tables(NODE),
            Vec::new(),
            vec![member],
            Pins::new(NODE, limits).unwrap(),
            Ledger::new(8, 8),
            AliasState {
                node_ports: Vec::new(),
                held: Vec::new(),
                exposures: Vec::new(),
            },
        )
        .unwrap();
        let syn = tcp(NODE, PUBLIC, BOX_COHORT_DSCP);
        // t0: a marked query from the node's address is the cohort's, though
        // the baseline is not in force.
        assert_eq!(
            g.dns_ask(NODE, true, 0, 7, 5000, Instant { ms: 0 }),
            Some((DnsTable::Cohort, Asked::Recorded))
        );
        // t1: the reply. No row holds the node's address, so the cohort's
        // table is the only one offered it.
        let r = g
            .dns_answer(
                NODE,
                7,
                5000,
                None,
                &[],
                Some(0),
                &[PUBLIC],
                Instant { ms: 1_000 },
            )
            .answered;
        assert_eq!(
            r.cohort_at_node,
            Some(Admits {
                admitted: 1,
                refused: 0
            })
        );
        assert_eq!(r.own_table, None);
        // While announced the node's address is no source the gate knows.
        assert!(!g.egress(syn, Instant { ms: 1_500 }).admits());
        // t2: the baseline comes into force.
        g.adopt_baseline(true, Vec::new());
        // t3 < t1 + the window: the marked SYN is the cohort's and is lifted
        // by the admission made before.
        assert!(g.egress(syn, Instant { ms: 61_000 }).admits());
        // The cohort's record changes: its admissions go.
        g.clear_cohort_dns();
        assert!(!g.egress(syn, Instant { ms: 62_000 }).admits());
    }

    // Adopting a baseline empties what the node itself resolved.
    #[test]
    fn adopting_a_baseline_empties_the_nodes_dns_tables() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert!(
            g.dns_ask(NODE, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        assert!(
            g.dns_ask(NET + 7, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        g.adopt_baseline(true, Vec::new());
        // The node's question is gone; the row's is not.
        let r = g
            .dns_answer(
                NODE,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                None,
                &[],
                Instant { ms: 1 },
            )
            .answered;
        assert_eq!(r.own, None);
        let r = g
            .dns_answer(
                NET + 7,
                7,
                5000,
                Some(0),
                &[PUBLIC],
                None,
                &[],
                Instant { ms: 1 },
            )
            .answered;
        assert_eq!(
            r.own,
            Some(Admits {
                admitted: 1,
                refused: 0
            })
        );
    }

    #[test]
    fn a_dns_answer_never_admits_an_address_of_the_plane_or_the_block() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert!(
            g.dns_ask(NET + 7, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        // A sibling's lease, the gateway, the plane outside the block, loopback:
        // all dropped before the table sees them. The public address is admitted.
        let r = g.dns_answer(
            NET + 7,
            7,
            5000,
            Some(0),
            &[NET + 9, NET + 1, 0x6463_0001, 0x7f00_0001, PUBLIC],
            None,
            &[],
            Instant { ms: 1 },
        );
        assert_eq!(r.own_dropped, 4);
        assert_eq!(r.cohort_dropped, 0);
        assert_eq!(
            r.answered.own,
            Some(Admits {
                admitted: 1,
                refused: 0
            })
        );
        // An answer of nothing but floored addresses consumes the question and admits nothing.
        assert!(
            g.dns_ask(NET + 7, false, 0, 8, 5000, Instant { ms: 2 })
                .is_some()
        );
        let r = g.dns_answer(
            NET + 7,
            8,
            5000,
            Some(0),
            &[NET + 9],
            None,
            &[],
            Instant { ms: 3 },
        );
        assert_eq!(r.own_dropped, 1);
        assert_eq!(
            r.answered.own,
            Some(Admits {
                admitted: 0,
                refused: 0
            })
        );
    }

    /// The configuration of the gate `gate(owners)` builds, made again from the same parts.
    fn config(owners: [u32; 2]) -> crate::split::Config {
        let decl = |st: RowState| crate::split::RowDecl {
            rules: st.rules,
            resolves_names: st.resolves_names,
            alias_by_name: st.alias_by_name,
            name_id: st.name_id,
            task_row: st.task_row,
            names_boxes: st.names_boxes,
        };
        crate::split::Config {
            sources: Sources::new(
                Plan::new(NET, 24).unwrap(),
                vec![NET + 7, NET + 9],
                true,
                CohortSpelling::NodeWithMark,
            )
            .unwrap(),
            decls: vec![
                decl(row(owners[0], None)),
                decl(row(owners[1], Some(Vec::new()))),
            ],
            baseline: Vec::new(),
            members: Vec::new(),
            alias: AliasState {
                node_ports: Vec::new(),
                held: Vec::new(),
                exposures: vec![crate::alias::Exposure {
                    proto: 6,
                    port: 5432,
                }],
            },
        }
    }

    // SP1 by example: for a run of frames in both directions, deciding with
    // the configuration and one box's tables gives what the whole gate gives.
    #[test]
    fn plan_then_judge_decides_as_the_whole_gate_does() {
        use crate::cohort::judge_cohort;
        use crate::ingress::Received;
        use crate::judge::judge_row;
        use crate::node::judge_node;
        use crate::split::IngressFor;
        let owners = [NET + 7, NET + 9];
        let mut whole = gate(owners).unwrap();
        let mut parts = gate(owners).unwrap();
        let cfg = config(owners);
        let plan = Plan::new(NET, 24).unwrap();
        let v4 =
            |src: u32, dst: u32, proto: u8, sport: u16, dport: u16, flags: u8, dscp: u8| Frame {
                sent: Sent {
                    src,
                    kind: SentKind::V4 {
                        dst,
                        proto,
                        l4: Some(SentL4 {
                            sport,
                            dport,
                            flags,
                            seq: 0,
                            ack: 1,
                            payload_len: 0,
                        }),
                    },
                },
                dscp,
            };
        let toward = |dst: u32, proto: u8, sport: u16, dport: u16, flags: u8| Received {
            src: NET + 1,
            dst,
            proto,
            l4: SentL4 {
                sport,
                dport,
                flags,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        assert_eq!(
            whole.publish(Forward {
                listener_addr: 0x7f00_4007,
                listener_port: 18080,
                addr: NET + 7,
                inside: 8080,
                proto: 6,
                by: crate::ledger::Applier::Row,
            }),
            Published::Noted
        );
        assert_eq!(
            parts.publish(Forward {
                listener_addr: 0x7f00_4007,
                listener_port: 18080,
                addr: NET + 7,
                inside: 8080,
                proto: 6,
                by: crate::ledger::Applier::Row,
            }),
            Published::Noted
        );
        let inbound = [
            toward(NET + 7, 6, 40000, 8080, 0x02),
            toward(NET + 9, 6, 40001, 8080, 0x02),
            toward(NODE, 6, 40002, 22, 0x02),
            toward(NET + 99, 6, 40003, 80, 0x02),
        ];
        for (n, r) in inbound.iter().enumerate() {
            let now = n as u64;
            let want = whole.ingress(*r, Instant { ms: now });
            let published = parts.ledger.dials(r.dst, r.l4.dport);
            let proxy = plan.proxy_peer();
            let got = match cfg.ingress_for(*r) {
                IngressFor::NotARow => Arrived::NotARow,
                IngressFor::Node => Arrived::Node(observe(
                    proxy,
                    &mut parts.node,
                    *r,
                    published,
                    Instant { ms: now },
                )),
                IngressFor::Cohort => Arrived::Cohort(observe(
                    proxy,
                    &mut parts.cohort,
                    *r,
                    published,
                    Instant { ms: now },
                )),
                IngressFor::Row(i) => Arrived::Row(
                    i,
                    observe(
                        proxy,
                        &mut parts.rows[i].tables,
                        *r,
                        published,
                        Instant { ms: now },
                    ),
                ),
            };
            assert_eq!(got, want, "inbound frame {n}");
        }
        let outbound = [
            v4(NET + 7, NET + 1, 6, 8080, 40000, 0x12, 0), // a reply on the record just opened
            v4(NET + 9, NET + 1, 6, 8080, 40001, 0x14, 0), // a refusal of the noted connect
            v4(NET + 7, PUBLIC, 6, 50000, 443, 0x02, 0),   // the row's rules
            v4(NET + 9, PUBLIC, 6, 50000, 443, 0x02, 0),   // a row that allows nothing
            v4(NET + 7, NET + 9, 6, 50000, 443, 0x02, 0),  // box to box
            v4(NET + 7, NET + 254, 6, 50000, 5432, 0x02, 0), // the alias at an exposure
            v4(NODE, PUBLIC, 6, 50000, 443, 0x02, 0),      // the node
            v4(NODE, NET + 7, 6, 50000, 8080, 0x02, 0),    // the node to a row
            v4(NODE, PUBLIC, 6, 50000, 443, 0x02, BOX_COHORT_DSCP), // the cohort, by its mark
            v4(NET + 50, PUBLIC, 6, 50000, 443, 0x02, 0),  // a lease nothing holds
            v4(PUBLIC, NET + 1, 6, 50000, 443, 0x02, 0),   // not ours at all
        ];
        for (n, f) in outbound.iter().enumerate() {
            let now = 10 + n as u64;
            let want = whole.egress(*f, Instant { ms: now });
            let p = cfg.egress_for(*f);
            let got = match p.route {
                Route::ControlSurface => Decision::Refused(Stray::ControlSurface),
                Route::Unregistered => Decision::Refused(Stray::Unregistered),
                Route::Unknown => Decision::Refused(Stray::Unknown),
                Route::Row(i) => Decision::Row(
                    i,
                    judge_row(
                        &plan,
                        &cfg.decls[i].rules,
                        p.lifts,
                        p.alias_open,
                        &mut parts.rows[i].tables,
                        f.sent,
                        Instant { ms: now },
                    ),
                ),
                Route::Node => Decision::Node(judge_node(
                    &plan,
                    cfg.baseline.as_slice(),
                    p.alias_open,
                    p.to_row,
                    &mut parts.node,
                    f.sent,
                    Instant { ms: now },
                )),
                Route::Cohort => Decision::Cohort(judge_cohort(
                    &plan,
                    cfg.members.as_slice(),
                    p.alias_open,
                    &mut parts.node,
                    &mut parts.cohort_pins,
                    f.sent,
                    Instant { ms: now },
                )),
            };
            assert_eq!(got, want, "outbound frame {n}");
        }
    }

    #[test]
    fn the_tables_can_be_read_and_the_members_replaced_without_changing_a_decision() {
        use crate::flow::Conversation;
        use crate::ingress::Received;
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        let forward = Forward {
            listener_addr: 0x7f00_4007,
            listener_port: 18080,
            addr: NET + 7,
            inside: 8080,
            proto: 6,
            by: crate::ledger::Applier::Row,
        };
        assert_eq!(g.publish(forward), Published::Noted);
        let syn = Received {
            src: NET + 1,
            dst: NET + 7,
            proto: 6,
            l4: SentL4 {
                sport: 40000,
                dport: 8080,
                flags: 0x02,
                seq: 0,
                ack: 0,
                payload_len: 0,
            },
        };
        let _ = g.ingress(syn, Instant { ms: 0 });
        let c = Conversation {
            proto: 6,
            client: NET + 1,
            client_port: 40000,
            box_addr: NET + 7,
            box_port: 8080,
        };
        let row = g.tables_at(DnsTable::Row(NET + 7)).unwrap();
        assert!(row.flows.has_live(c, Instant { ms: 1 }));
        assert!(!row.flows.has_live(c, Instant { ms: 300_000 }));
        assert!(!row.notes.has_live(NET + 1, 40000, 8080, Instant { ms: 1 }));
        assert!(
            !g.tables_at(DnsTable::Row(NET + 9))
                .unwrap()
                .flows
                .has_live(c, Instant { ms: 1 })
        );
        assert!(g.tables_at(DnsTable::Row(NET + 50)).is_none());
        assert!(g.tables_at(DnsTable::Node).is_some());
        // A question is visible in the table it was recorded in.
        assert!(
            g.dns_ask(NET + 7, false, 3, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        let row = g.tables_at(DnsTable::Row(NET + 7)).unwrap();
        assert!(row.pins.asked_live(3, 7, 5000, Instant { ms: 1 }));
        assert!(!row.pins.asked_live(3, 8, 5000, Instant { ms: 1 }));
        assert!(!row.pins.admitted_live(PUBLIC, Instant { ms: 1 }));
        // Replacing the members with an empty list changes no row's reply decision.
        g.set_members(Vec::new());
        assert!(
            g.tables_at(DnsTable::Row(NET + 7))
                .unwrap()
                .flows
                .has_live(c, Instant { ms: 1 })
        );
    }

    #[test]
    fn expiring_questions_names_one_table() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert!(
            g.dns_ask(NET + 7, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        assert!(
            g.dns_ask(NET + 9, false, 0, 7, 5000, Instant { ms: 0 })
                .is_some()
        );
        assert_eq!(
            g.dns_expire(DnsTable::Row(NET + 7), Instant { ms: u64::MAX }, 8),
            Some(1)
        );
        assert_eq!(
            g.dns_expire(DnsTable::Row(NET + 7), Instant { ms: u64::MAX }, 8),
            Some(0)
        );
        assert_eq!(
            g.dns_expire(DnsTable::Row(NET + 9), Instant { ms: u64::MAX }, 8),
            Some(1)
        );
        assert_eq!(
            g.dns_expire(DnsTable::Node, Instant { ms: u64::MAX }, 8),
            Some(0)
        );
        assert_eq!(
            g.dns_expire(DnsTable::Cohort, Instant { ms: u64::MAX }, 8),
            Some(0)
        );
        assert_eq!(
            g.dns_expire(DnsTable::Row(NET + 8), Instant { ms: u64::MAX }, 8),
            None
        );
    }

    #[test]
    fn the_node_the_cohort_and_strays_each_get_their_own_answer() {
        let mut g = gate([NET + 7, NET + 9]).unwrap();
        assert_eq!(
            g.egress(tcp(NODE, NET + 7, 0), Instant { ms: 1 }),
            Decision::Node(NodeJudged::Node(NodeArm::Sibling))
        );
        assert_eq!(
            g.egress(tcp(NODE, PUBLIC, 0), Instant { ms: 1 }),
            Decision::Node(NodeJudged::Node(NodeArm::Unpinned))
        );
        assert_eq!(
            g.egress(tcp(NODE, PUBLIC, BOX_COHORT_DSCP), Instant { ms: 1 }),
            Decision::Cohort(CohortJudged::Cohort(CohortArm::NoMember))
        );
        assert_eq!(
            g.egress(tcp(NET + 8, PUBLIC, 0), Instant { ms: 1 }),
            Decision::Refused(Stray::Unregistered)
        );
        assert_eq!(
            g.egress(tcp(0x0a00_0001, PUBLIC, 0), Instant { ms: 1 }),
            Decision::Refused(Stray::Unknown)
        );
    }

    #[test]
    fn a_configuration_short_of_a_declaration_routes_nothing() {
        let mut cfg = config([NET + 7, NET + 9]);
        let f = tcp(NET + 7, PUBLIC, 0);
        assert_eq!(cfg.egress_for(f).route, Route::Row(0));
        let _ = cfg.decls.pop();
        assert_eq!(cfg.egress_for(f).route, Route::Unknown);
    }
}
