//! Whose frame is this? The first step of the host gate's decision.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! Every frame a guest sends is put in exactly one class by its source
//! address, before any rule is read: the host-address cohort, the node, a
//! registered row, a lease nobody registered, or an address that can be
//! nobody's. Each class is then decided by its own rules.
//!
//! THEOREM V1, for every source and every set of rows:
//!   (a) `origin` returns exactly one class, and the class is determined by
//!       the plan, the rows, whether the node's baseline is in force, and how
//!       the cohort is spelled: each arm of the contract states its condition
//!       and the conditions do not overlap;
//!   (b) `Row(i)` names the first row holding the source address, and is
//!       never returned for the node or the cohort while the baseline is in
//!       force;
//!   (c) `Unregistered` and `Unknown` are returned only for an address no row
//!       holds, and differ only in whether the plan could lease it.
//!   (d) at most one row holds an address, and every row's address is one
//!       the plan could lease or the node's: never the gateway, the proxy's,
//!       the alias, the block's network or broadcast address, or (under its
//!       own address) the cohort's (`theorem_rows_are_leases`).
//!
//! The cohort is spelled two ways: a host-address box sends from the node's
//! address with a mark in the IPv4 header, or from an address the plan
//! reserves for the cohort. Both are here; which one applies is one value in
//! [`Sources`].

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_cohort, spec_leasable, spec_node, wf};

/// The mark a guest's classifier writes into the IPv4 DSCP field of a
/// host-address box's frames.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BOX_COHORT_DSCP: u8 = 0b11_0111;

/// How host-address boxes are told apart from the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum CohortSpelling {
    /// The node's address with the DSCP mark. The plan's cohort address is
    /// then an ordinary lease.
    NodeWithMark,
    /// The plan's cohort address. The mark is not read.
    OwnAddress,
}

/// The class of a frame's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Origin {
    /// The frame carries no readable source address.
    NoSource,
    /// A host-address box.
    Cohort,
    /// The node itself.
    Node,
    /// The registered row at this index.
    Row(usize),
    /// An address the plan could lease that no row holds.
    Unregistered,
    /// Any other address: one of the switch's own, or outside the block.
    Unknown,
}

/// What the classification reads: the plan, the registered addresses in row
/// order, whether the node's baseline is in force, and the cohort's spelling.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Sources {
    plan: Plan,
    rows: Vec<u32>,
    node_in_force: bool,
    spelling: CohortSpelling,
}

#[cfg(verus_keep_ghost)]
verus! {

pub closed spec fn plan_of(s: Sources) -> Plan { s.plan }
pub closed spec fn rows_of(s: Sources) -> Seq<u32> { s.rows@ }
pub closed spec fn in_force_of(s: Sources) -> bool { s.node_in_force }
pub closed spec fn spelling_of(s: Sources) -> CohortSpelling { s.spelling }

/// No address is held by two rows.
pub open spec fn distinct(rows: Seq<u32>) -> bool {
    forall|i: int, j: int| 0 <= i < j < rows.len() ==> rows[i] != rows[j]
}

/// A row may hold `a`: an address the plan could lease, or the node's.
pub open spec fn holdable(plan: Plan, spelling: CohortSpelling, a: u32) -> bool {
    ||| spec_leasable(plan, a as int)
    ||| a as int == spec_node(plan)
    ||| (spelling == CohortSpelling::NodeWithMark && a as int == spec_cohort(plan))
}

/// Every row holds an address a row may hold, and no two hold the same one.
pub open spec fn rows_ok(plan: Plan, spelling: CohortSpelling, rows: Seq<u32>) -> bool {
    &&& distinct(rows)
    &&& forall|i: int| 0 <= i < rows.len() ==> holdable(plan, spelling, #[trigger] rows[i])
}

pub open spec fn sinv(s: Sources) -> bool {
    wf(plan_of(s)) && rows_ok(plan_of(s), spelling_of(s), rows_of(s))
}

/// Some row holds `a`.
pub open spec fn registered(rows: Seq<u32>, a: u32) -> bool {
    exists|i: int| 0 <= i < rows.len() && rows[i] == a
}

/// No row before `i` holds `a`.
pub open spec fn first_at(rows: Seq<u32>, a: u32, i: int) -> bool {
    forall|j: int| 0 <= j < i ==> rows[j] != a
}

pub open spec fn marked(is_v4: bool, dscp: u8) -> bool {
    is_v4 && dscp == BOX_COHORT_DSCP
}

/// The source is a host-address box.
pub open spec fn is_cohort(s: Sources, a: u32, is_v4: bool, dscp: u8) -> bool {
    in_force_of(s) && match spelling_of(s) {
        CohortSpelling::NodeWithMark => a as int == spec_node(plan_of(s)) && marked(is_v4, dscp),
        CohortSpelling::OwnAddress => a as int == spec_cohort(plan_of(s)),
    }
}

/// The source is the node.
pub open spec fn is_node(s: Sources, a: u32, is_v4: bool, dscp: u8) -> bool {
    in_force_of(s) && a as int == spec_node(plan_of(s)) && !is_cohort(s, a, is_v4, dscp)
}

/// The plan could lease `a` to a box or a task. Under [`CohortSpelling::NodeWithMark`]
/// the plan's cohort address is a lease like any other.
pub open spec fn allocatable(s: Sources, a: u32) -> bool {
    spec_leasable(plan_of(s), a as int) || match spelling_of(s) {
        CohortSpelling::NodeWithMark => a as int == spec_cohort(plan_of(s)),
        CohortSpelling::OwnAddress => false,
    }
}

/// The address of a source, when there is one.
pub open spec fn addr_of(src: Option<u32>) -> u32 {
    match src {
        Some(a) => a,
        None => 0,
    }
}

/// V1 (c): no row holds one of the switch's own addresses except the node's,
/// and under its own address the cohort's is not a row's either.
pub proof fn theorem_rows_are_leases(s: Sources, i: int)
    requires
        sinv(s),
        0 <= i < rows_of(s).len(),
    ensures
        rows_of(s)[i] as int != crate::plan::spec_network(plan_of(s)),
        rows_of(s)[i] as int != crate::plan::spec_gateway(plan_of(s)),
        rows_of(s)[i] as int != crate::plan::spec_proxy_peer(plan_of(s)),
        rows_of(s)[i] as int != crate::plan::spec_host_alias(plan_of(s)),
        rows_of(s)[i] as int != crate::plan::spec_broadcast(plan_of(s)),
        spelling_of(s) == CohortSpelling::OwnAddress ==> rows_of(s)[i] as int != spec_cohort(plan_of(s)),
{
    let plan = plan_of(s);
    let a = rows_of(s)[i];
    // The row's address is one a row may hold; the plan's own addresses are
    // in order and apart from every lease (A1).
    assert(holdable(plan, spelling_of(s), a));
    crate::plan::theorem_a1(plan);
    assert(crate::plan::spec_leasable(plan, a as int) ==> !crate::plan::spec_reserved(plan, a as int));
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Sources {
    /// `rows` are the registered addresses, in row order. `None` unless each
    /// is an address a row may hold and no two are the same.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            wf(plan),
        ensures
            match r {
                Some(s) => {
                    &&& sinv(s)
                    &&& plan_of(s) == plan
                    &&& rows_of(s) == rows@
                    &&& in_force_of(s) == node_in_force
                    &&& spelling_of(s) == spelling
                },
                None => !rows_ok(plan, spelling, rows@),
            },
    ))]
    pub fn new(
        plan: Plan,
        rows: Vec<u32>,
        node_in_force: bool,
        spelling: CohortSpelling,
    ) -> Option<Sources> {
        let mut s = Sources {
            plan,
            rows: Vec::new(),
            node_in_force,
            spelling,
        };
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= rows.len(),
                sinv(s),
                plan_of(s) == plan,
                in_force_of(s) == node_in_force,
                spelling_of(s) == spelling,
                rows_of(s) == rows@.take(i as int),
            decreases rows.len() - i,
        ))]
        while i < rows.len() {
            if !s.add(rows[i]) {
                return None;
            }
            i += 1;
        }
        Some(s)
    }

    /// The address plan.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == plan_of(*self),
    ))]
    pub fn plan(&self) -> Plan {
        self.plan
    }

    /// How many rows are registered.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == rows_of(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// The address of the row at `i`. For the gate, which holds the bound.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires i < rows_of(*self).len(),
        ensures r == rows_of(*self)[i as int],
    ))]
    pub(crate) fn address(&self, i: usize) -> u32 {
        self.rows[i]
    }

    /// Whether the node's baseline is in force.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == in_force_of(*self),
    ))]
    pub fn node_in_force(&self) -> bool {
        self.node_in_force
    }

    /// Sets whether the node's baseline is in force. The plan, the rows and
    /// the spelling are as they were.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        ensures
            in_force_of(*final(self)) == in_force,
            plan_of(*final(self)) == plan_of(*old(self)),
            rows_of(*final(self)) == rows_of(*old(self)),
            spelling_of(*final(self)) == spelling_of(*old(self)),
    ))]
    pub fn set_in_force(&mut self, in_force: bool) {
        self.node_in_force = in_force;
    }

    /// How host-address boxes are told apart from the node.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == spelling_of(*self),
    ))]
    pub fn spelling(&self) -> CohortSpelling {
        self.spelling
    }

    /// Adds a row holding `a`, after every row there is. `false`, and nothing
    /// changes, when a row already holds `a` or `a` is not an address a row
    /// may hold.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            plan_of(*final(self)) == plan_of(*old(self)),
            in_force_of(*final(self)) == in_force_of(*old(self)),
            spelling_of(*final(self)) == spelling_of(*old(self)),
            r == (!registered(rows_of(*old(self)), a)
                && holdable(plan_of(*old(self)), spelling_of(*old(self)), a)),
            r ==> rows_of(*final(self)) == rows_of(*old(self)).push(a),
            !r ==> rows_of(*final(self)) == rows_of(*old(self)),
    ))]
    pub fn add(&mut self, a: u32) -> bool {
        let may = self.plan.is_leasable(a)
            || a == self.plan.node()
            || match self.spelling {
                CohortSpelling::NodeWithMark => a == self.plan.cohort(),
                CohortSpelling::OwnAddress => false,
            };
        if !may || self.holds(a) {
            return false;
        }
        self.rows.push(a);
        true
    }

    /// Removes the row at `i`. Later rows move down by one.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
            i < rows_of(*old(self)).len(),
        ensures
            sinv(*final(self)),
            plan_of(*final(self)) == plan_of(*old(self)),
            in_force_of(*final(self)) == in_force_of(*old(self)),
            spelling_of(*final(self)) == spelling_of(*old(self)),
            rows_of(*final(self)) == rows_of(*old(self)).remove(i as int),
    ))]
    pub(crate) fn remove(&mut self, i: usize) {
        let _ = self.rows.remove(i);
    }

    /// The first row holding `a`, if any does.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(i) => i < rows_of(*self).len() && rows_of(*self)[i as int] == a
                    && first_at(rows_of(*self), a, i as int),
                None => !registered(rows_of(*self), a),
            },
    ))]
    pub fn index_of(&self, a: u32) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.rows.len(),
                forall|j: int| 0 <= j < i ==> self.rows@[j] != a,
            decreases self.rows.len() - i,
        ))]
        while i < self.rows.len() {
            if self.rows[i] == a {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Whether some registered row holds `a`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == registered(rows_of(*self), a),
    ))]
    pub fn holds(&self, a: u32) -> bool {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.rows.len(),
                forall|j: int| 0 <= j < i ==> self.rows@[j] != a,
            decreases self.rows.len() - i,
        ))]
        while i < self.rows.len() {
            if self.rows[i] == a {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The class of a frame whose source address is `src`. `is_v4` and `dscp`
    /// are the frame's family and DSCP field; they are read only to tell a
    /// marked frame from the node's own.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            match r {
                Origin::NoSource => src.is_none(),
                Origin::Cohort => src.is_some() && is_cohort(*self, addr_of(src), is_v4, dscp),
                Origin::Node => src.is_some() && is_node(*self, addr_of(src), is_v4, dscp),
                Origin::Row(i) => {
                    &&& src.is_some()
                    &&& !is_cohort(*self, addr_of(src), is_v4, dscp)
                    &&& !is_node(*self, addr_of(src), is_v4, dscp)
                    &&& i < rows_of(*self).len()
                    &&& rows_of(*self)[i as int] == addr_of(src)
                    &&& first_at(rows_of(*self), addr_of(src), i as int)
                },
                Origin::Unregistered => {
                    &&& src.is_some()
                    &&& !is_cohort(*self, addr_of(src), is_v4, dscp)
                    &&& !is_node(*self, addr_of(src), is_v4, dscp)
                    &&& !registered(rows_of(*self), addr_of(src))
                    &&& allocatable(*self, addr_of(src))
                },
                Origin::Unknown => {
                    &&& src.is_some()
                    &&& !is_cohort(*self, addr_of(src), is_v4, dscp)
                    &&& !is_node(*self, addr_of(src), is_v4, dscp)
                    &&& !registered(rows_of(*self), addr_of(src))
                    &&& !allocatable(*self, addr_of(src))
                },
            },
    ))]
    pub fn origin(&self, src: Option<u32>, is_v4: bool, dscp: u8) -> Origin {
        let a = match src {
            Some(a) => a,
            None => return Origin::NoSource,
        };
        if self.node_in_force {
            match self.spelling {
                CohortSpelling::NodeWithMark => {
                    if a == self.plan.node() {
                        if is_v4 && dscp == BOX_COHORT_DSCP {
                            return Origin::Cohort;
                        }
                        return Origin::Node;
                    }
                }
                CohortSpelling::OwnAddress => {
                    if a == self.plan.cohort() {
                        return Origin::Cohort;
                    }
                    if a == self.plan.node() {
                        return Origin::Node;
                    }
                }
            }
        }
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.rows.len(),
                forall|j: int| 0 <= j < i ==> self.rows@[j] != a,
                src == Some(a),
                !is_cohort(*self, a, is_v4, dscp),
                !is_node(*self, a, is_v4, dscp),
            decreases self.rows.len() - i,
        ))]
        while i < self.rows.len() {
            if self.rows[i] == a {
                return Origin::Row(i);
            }
            i += 1;
        }
        let could_lease = self.plan.is_leasable(a)
            || match self.spelling {
                CohortSpelling::NodeWithMark => a == self.plan.cohort(),
                CohortSpelling::OwnAddress => false,
            };
        if could_lease {
            Origin::Unregistered
        } else {
            Origin::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 100.64.0.0/24: gateway .1, leases .2 to .250, cohort .251, proxy .252,
    // node .253, host alias .254.
    const NET: u32 = 0x6440_0000;
    const NODE: u32 = NET + 253;
    const COHORT: u32 = NET + 251;

    fn sources(in_force: bool, spelling: CohortSpelling) -> Sources {
        let plan = Plan::new(NET, 24).unwrap();
        Sources::new(plan, vec![NET + 7, NODE, NET + 9], in_force, spelling).unwrap()
    }

    #[test]
    fn rows_are_one_per_address_at_a_lease_or_the_nodes() {
        let plan = Plan::new(NET, 24).unwrap();
        let mark = CohortSpelling::NodeWithMark;
        let own = CohortSpelling::OwnAddress;
        assert!(Sources::new(plan, vec![NET + 7, NODE], true, mark).is_some());
        assert!(Sources::new(plan, vec![NET + 7, NET + 7], true, mark).is_none());
        // The gateway, the alias and an address outside the block are not rows.
        assert!(Sources::new(plan, vec![plan.gateway()], true, mark).is_none());
        assert!(Sources::new(plan, vec![plan.host_alias()], true, mark).is_none());
        assert!(Sources::new(plan, vec![0x0a00_0001], true, mark).is_none());
        // The cohort's address is a lease under the mark and not under its own address.
        assert!(Sources::new(plan, vec![plan.cohort()], true, mark).is_some());
        assert!(Sources::new(plan, vec![plan.cohort()], true, own).is_none());
        let mut s = Sources::new(plan, vec![NET + 7], true, mark).unwrap();
        assert!(!s.add(NET + 7) && s.add(NET + 8) && s.len() == 2);
    }

    #[test]
    fn a_frame_without_a_source_has_no_origin() {
        let s = sources(true, CohortSpelling::NodeWithMark);
        assert_eq!(s.origin(None, false, 0), Origin::NoSource);
    }

    #[test]
    fn the_mark_tells_the_cohort_from_the_node_on_ipv4_only() {
        let s = sources(true, CohortSpelling::NodeWithMark);
        assert_eq!(s.origin(Some(NODE), true, 0), Origin::Node);
        assert_eq!(s.origin(Some(NODE), true, BOX_COHORT_DSCP), Origin::Cohort);
        assert_eq!(s.origin(Some(NODE), false, BOX_COHORT_DSCP), Origin::Node);
        assert_eq!(
            s.origin(Some(NET + 7), true, BOX_COHORT_DSCP),
            Origin::Row(0)
        );
    }

    #[test]
    fn before_the_baseline_is_in_force_the_node_is_a_row() {
        let s = sources(false, CohortSpelling::NodeWithMark);
        assert_eq!(s.origin(Some(NODE), true, BOX_COHORT_DSCP), Origin::Row(1));
    }

    #[test]
    fn a_registered_lease_is_its_row() {
        let s = sources(true, CohortSpelling::NodeWithMark);
        assert_eq!(s.origin(Some(NET + 7), true, 0), Origin::Row(0));
        assert_eq!(s.origin(Some(NET + 9), true, 0), Origin::Row(2));
    }

    #[test]
    fn an_unheld_lease_is_unregistered_and_anything_else_is_unknown() {
        let s = sources(true, CohortSpelling::NodeWithMark);
        assert_eq!(s.origin(Some(NET + 8), true, 0), Origin::Unregistered);
        assert_eq!(s.origin(Some(NET + 250), true, 0), Origin::Unregistered);
        assert_eq!(s.origin(Some(NET + 1), true, 0), Origin::Unknown);
        assert_eq!(s.origin(Some(NET + 252), true, 0), Origin::Unknown);
        assert_eq!(s.origin(Some(NET + 254), true, 0), Origin::Unknown);
        assert_eq!(s.origin(Some(NET), true, 0), Origin::Unknown);
        assert_eq!(s.origin(Some(0x0a00_0001), true, 0), Origin::Unknown);
    }

    #[test]
    fn the_cohort_address_is_a_lease_under_the_mark_and_the_cohort_under_its_own_address() {
        let marked = sources(true, CohortSpelling::NodeWithMark);
        assert_eq!(marked.origin(Some(COHORT), true, 0), Origin::Unregistered);
        let own = sources(true, CohortSpelling::OwnAddress);
        assert_eq!(own.origin(Some(COHORT), true, 0), Origin::Cohort);
        assert_eq!(own.origin(Some(NODE), true, BOX_COHORT_DSCP), Origin::Node);
        let early = sources(false, CohortSpelling::OwnAddress);
        assert_eq!(early.origin(Some(COHORT), true, 0), Origin::Unknown);
    }
}
