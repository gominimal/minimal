//! The ledger of published forwards: which loopback listener is bound for
//! which box, and which port of the box it dials.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A box's port is published by binding a listener on the host and
//! forwarding it to the box. The ledger is the host's own record of the
//! forwards it has applied. Two decisions read it: a frame toward a box
//! opens a reply record only at a port some forward dials, and a publish for
//! a listener somebody else holds is not applied.
//!
//! THEOREM L1, for every sequence of operations on a [`Ledger`]:
//!   (a) a listener has at most one holder;
//!   (b) a publish for a held listener changes nothing: its holder's forward
//!       stands, whoever asks, and the answer says whether the asker is the
//!       holder;
//!   (c) the ledger never holds more than `row_cap` forwards applied by rows
//!       or more than `interim_cap` applied by the interim; a row's publish
//!       past the bound is refused and evicts nothing; an interim publish
//!       past the bound evicts the oldest interim forward and no other;
//!   (d) `dials(addr, port)` is true exactly when some held forward dials
//!       that address at that port, and `dials_in` the same with the
//!       protocol;
//!   (e) a retraction removes its listener's forward and no other, and
//!       hands it back; a retraction of a listener nobody holds changes
//!       nothing.
//!
//! Entries are kept in the order they were applied, so "oldest" is "first".
//!
//! Not here: a declared forward waiting on a listener another box holds,
//! the hand-over when the holder unbinds, and the range probe. The listener
//! address is taken as given; checking it against the address the host
//! allocated for the box is a separate rule.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// What applied a forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Applier {
    /// A registered row.
    Row,
    /// The interim: a publish for an address no row holds yet.
    Interim,
}

/// One applied forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Forward {
    /// The loopback listener: address and port.
    pub listener_addr: u32,
    pub listener_port: u16,
    /// The box address the forward dials.
    pub addr: u32,
    /// The port of the box it dials.
    pub inside: u16,
    pub proto: u8,
    pub by: Applier,
}

/// What a publish did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Published {
    /// Nobody held the listener: the forward is noted.
    Noted,
    /// As `Noted`, and the interim forward at this position, the oldest, was
    /// evicted to make room.
    NotedEvicting(usize),
    /// The asker's address already holds the listener. Nothing changed.
    Held,
    /// Another address holds the listener. Nothing changed.
    HeldElsewhere,
    /// The ledger holds its bound of forwards applied this way, and nothing
    /// may be evicted for this one. Nothing changed.
    Full,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Ledger {
    entries: Vec<Forward>,
    row_cap: usize,
    interim_cap: usize,
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn at_listener(f: Forward, la: u32, lp: u16) -> bool {
    f.listener_addr == la && f.listener_port == lp
}

/// Some forward holds the listener.
pub open spec fn held(s: Seq<Forward>, la: u32, lp: u16) -> bool {
    exists|j: int| 0 <= j < s.len() && at_listener(#[trigger] s[j], la, lp)
}

/// No listener is held twice.
pub open spec fn one_holder(s: Seq<Forward>) -> bool {
    forall|i: int, j: int|
        0 <= i < j < s.len() ==> !at_listener(s[i], s[j].listener_addr, s[j].listener_port)
}

/// How many forwards of `s` were applied by `by`.
pub open spec fn applied_by(s: Seq<Forward>, by: Applier) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        applied_by(s.drop_last(), by) + if s.last().by == by { 1nat } else { 0nat }
    }
}

/// Some forward dials `addr` at `port`.
pub open spec fn dials(s: Seq<Forward>, addr: u32, port: u16) -> bool {
    exists|j: int| 0 <= j < s.len() && (#[trigger] s[j]).addr == addr && s[j].inside == port
}

/// Some forward dials `addr` at `port` in `proto`.
pub open spec fn dials_in(s: Seq<Forward>, addr: u32, port: u16, proto: u8) -> bool {
    exists|j: int| 0 <= j < s.len() && (#[trigger] s[j]).addr == addr && s[j].inside == port && s[j].proto == proto
}

/// `e` is a forward of `s`.
pub open spec fn has_forward(s: Seq<Forward>, e: Forward) -> bool {
    exists|k: int| 0 <= k < s.len() && s[k] == e
}

/// Every forward of `before` at another listener is still in `now`.
pub open spec fn keeps_other_listeners(now: Seq<Forward>, before: Seq<Forward>, la: u32, lp: u16) -> bool {
    forall|k: int| 0 <= k < before.len() && !at_listener(before[k], la, lp) ==> has_forward(now, #[trigger] before[k])
}

/// Every forward of `now` was a forward of `before`.
pub open spec fn nothing_new(now: Seq<Forward>, before: Seq<Forward>) -> bool {
    forall|j: int| 0 <= j < now.len() ==> has_forward(before, #[trigger] now[j])
}

/// No forward before position `j` was applied by the interim.
pub open spec fn no_interim_before(s: Seq<Forward>, j: int) -> bool {
    forall|k: int| 0 <= k < j ==> (#[trigger] s[k]).by == Applier::Row
}

pub closed spec fn lview(l: Ledger) -> Seq<Forward> { l.entries@ }
pub closed spec fn row_cap_of(l: Ledger) -> int { l.row_cap as int }
pub closed spec fn interim_cap_of(l: Ledger) -> int { l.interim_cap as int }

/// L1 (a) and (c) as a predicate.
pub open spec fn within_bounds(s: Seq<Forward>, row_cap: int, interim_cap: int) -> bool {
    &&& one_holder(s)
    &&& applied_by(s, Applier::Row) <= row_cap
    &&& applied_by(s, Applier::Interim) <= interim_cap
}

pub open spec fn linv(l: Ledger) -> bool {
    within_bounds(lview(l), row_cap_of(l), interim_cap_of(l))
}

pub open spec fn same_caps(now: Ledger, before: Ledger) -> bool {
    row_cap_of(now) == row_cap_of(before) && interim_cap_of(now) == interim_cap_of(before)
}

pub proof fn lemma_applied_push(s: Seq<Forward>, e: Forward, by: Applier)
    ensures
        applied_by(s.push(e), by) == applied_by(s, by) + if e.by == by { 1nat } else { 0nat },
{
    assert(s.push(e).drop_last() =~= s);
    assert(s.push(e).last() == e);
}

pub proof fn lemma_applied_remove(s: Seq<Forward>, i: int, by: Applier)
    requires
        0 <= i < s.len(),
    ensures
        applied_by(s.remove(i), by) + (if s[i].by == by { 1nat } else { 0nat }) == applied_by(s, by),
    decreases s.len(),
{
    if i == s.len() - 1 {
        assert(s.remove(i) =~= s.drop_last());
    } else {
        lemma_applied_remove(s.drop_last(), i, by);
        assert(s.remove(i).drop_last() =~= s.drop_last().remove(i));
        assert(s.remove(i).last() == s.last());
    }
}

pub proof fn lemma_applied_take(s: Seq<Forward>, i: int, by: Applier)
    requires
        0 <= i < s.len(),
    ensures
        applied_by(s.take(i + 1), by) == applied_by(s.take(i), by) + if s[i].by == by { 1nat } else { 0nat },
{
    assert(s.take(i + 1).drop_last() =~= s.take(i));
    assert(s.take(i + 1).last() == s[i]);
}

/// A table with no interim forward has an interim count of zero.
pub proof fn lemma_no_interim_count(s: Seq<Forward>)
    requires
        no_interim_before(s, s.len() as int),
    ensures
        applied_by(s, Applier::Interim) == 0,
    decreases s.len(),
{
    if s.len() > 0 {
        assert(s.last() == s[s.len() - 1]);
        assert forall|k: int| 0 <= k < s.drop_last().len() implies (#[trigger] s.drop_last()[k]).by == Applier::Row by {
            assert(s.drop_last()[k] == s[k]);
        }
        lemma_no_interim_count(s.drop_last());
    }
}

/// Removing a forward keeps every listener at one holder.
pub proof fn lemma_remove_one_holder(s: Seq<Forward>, i: int)
    requires
        0 <= i < s.len(),
        one_holder(s),
    ensures
        one_holder(s.remove(i)),
{
    let after = s.remove(i);
    assert forall|a: int, b: int| 0 <= a < b < after.len() implies !at_listener(
        after[a],
        after[b].listener_addr,
        after[b].listener_port,
    ) by {
        let a0 = if a < i { a } else { a + 1 };
        let b0 = if b < i { b } else { b + 1 };
        assert(after[a] == s[a0] && after[b] == s[b0]);
        assert(!at_listener(s[a0], s[b0].listener_addr, s[b0].listener_port));
    }
}

/// Pushing a forward at a listener nobody holds keeps every listener at one holder.
pub proof fn lemma_push_one_holder(s: Seq<Forward>, e: Forward)
    requires
        one_holder(s),
        !held(s, e.listener_addr, e.listener_port),
    ensures
        one_holder(s.push(e)),
{
    let after = s.push(e);
    assert forall|a: int, b: int| 0 <= a < b < after.len() implies !at_listener(
        after[a],
        after[b].listener_addr,
        after[b].listener_port,
    ) by {
        if b == s.len() {
            assert(!at_listener(s[a], e.listener_addr, e.listener_port));
        } else {
            assert(!at_listener(s[a], s[b].listener_addr, s[b].listener_port));
        }
    }
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == (a == b),
))]
fn same_applier(a: Applier, b: Applier) -> bool {
    match a {
        Applier::Row => match b {
            Applier::Row => true,
            Applier::Interim => false,
        },
        Applier::Interim => match b {
            Applier::Row => false,
            Applier::Interim => true,
        },
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Ledger {
    /// An empty ledger with these bounds.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            linv(r),
            lview(r).len() == 0,
            row_cap_of(r) == row_cap,
            interim_cap_of(r) == interim_cap,
    ))]
    pub fn new(row_cap: usize, interim_cap: usize) -> Ledger {
        Ledger {
            entries: Vec::new(),
            row_cap,
            interim_cap,
        }
    }

    /// Where the forward holding the listener is, if one does.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(i) => i < lview(*self).len() && at_listener(lview(*self)[i as int], la, lp),
                None => !held(lview(*self), la, lp),
            },
    ))]
    fn find(&self, la: u32, lp: u16) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> !at_listener(#[trigger] self.entries@[j], la, lp),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].listener_addr == la && self.entries[i].listener_port == lp {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// The forward holding the listener, if one does.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(e) => at_listener(e, la, lp) && has_forward(lview(*self), e),
                None => !held(lview(*self), la, lp),
            },
    ))]
    pub fn holder(&self, la: u32, lp: u16) -> Option<Forward> {
        match self.find(la, lp) {
            Some(i) => {
                let e = self.entries[i];
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(self.entries@[i as int] == e);
                }
                Some(e)
            }
            None => None,
        }
    }

    /// How many forwards `by` applied.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r as nat == applied_by(lview(*self), by),
    ))]
    fn count(&self, by: Applier) -> usize {
        let mut n: usize = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                n <= i,
                n as nat == applied_by(self.entries@.take(i as int), by),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_applied_take(self.entries@, i as int, by);
            }
            if same_applier(self.entries[i].by, by) {
                n += 1;
            }
            i += 1;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(self.entries@.take(self.entries.len() as int) =~= self.entries@);
        }
        n
    }

    /// Where the oldest interim forward is, if there is one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(j) => j < lview(*self).len() && lview(*self)[j as int].by == Applier::Interim
                    && no_interim_before(lview(*self), j as int),
                None => no_interim_before(lview(*self), lview(*self).len() as int),
            },
    ))]
    fn oldest_interim(&self) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                no_interim_before(self.entries@, i as int),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if same_applier(self.entries[i].by, Applier::Interim) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Applies a publish. L1 (a), (b), (c).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            linv(*old(self)),
        ensures
            linv(*final(self)),
            publish_post(*old(self), *final(self), f, r),
    ))]
    pub fn publish(&mut self, f: Forward) -> Published {
        if let Some(i) = self.find(f.listener_addr, f.listener_port) {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_publish_held(*old(self), *self, f, i as int);
            }
            if self.entries[i].addr == f.addr {
                return Published::Held;
            }
            return Published::HeldElsewhere;
        }
        match f.by {
            Applier::Row => {
                if self.count(Applier::Row) >= self.row_cap {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_publish_full(*old(self), *self, f);
                    }
                    return Published::Full;
                }
                self.entries.push(f);
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_publish_noted(*old(self), *self, f);
                }
                Published::Noted
            }
            Applier::Interim => {
                if self.interim_cap == 0 {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_publish_full(*old(self), *self, f);
                    }
                    return Published::Full;
                }
                if self.count(Applier::Interim) < self.interim_cap {
                    self.entries.push(f);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_publish_noted(*old(self), *self, f);
                    }
                    return Published::Noted;
                }
                match self.oldest_interim() {
                    Some(j) => {
                        self.entries.remove(j);
                        self.entries.push(f);
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            lemma_publish_evicting(*old(self), *self, f, j);
                        }
                        Published::NotedEvicting(j)
                    }
                    None => {
                        // Unreachable: the interim count is at a bound above zero.
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            lemma_no_interim_count(self.entries@);
                        }
                        Published::Full
                    }
                }
            }
        }
    }

    /// Retracts the listener's forward and hands it back. L1 (e).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            linv(*old(self)),
        ensures
            linv(*final(self)),
            retract_post(*old(self), *final(self), la, lp, r),
    ))]
    pub fn retract(&mut self, la: u32, lp: u16) -> Option<Forward> {
        match self.find(la, lp) {
            Some(i) => {
                let e = self.entries[i];
                #[cfg(verus_keep_ghost)]
                proof! {
                    let before = self.entries@;
                    let after = before.remove(i as int);
                    assert(before[i as int] == e);
                    lemma_applied_remove(before, i as int, Applier::Row);
                    lemma_applied_remove(before, i as int, Applier::Interim);
                    lemma_remove_one_holder(before, i as int);
                    assert forall|j: int| 0 <= j < after.len() implies !at_listener(#[trigger] after[j], la, lp) by {
                        let j0 = if j < i { j } else { j + 1 };
                        assert(after[j] == before[j0]);
                        if j0 < i {
                            assert(!at_listener(before[j0], before[i as int].listener_addr, before[i as int].listener_port));
                        } else {
                            assert(!at_listener(before[i as int], before[j0].listener_addr, before[j0].listener_port));
                        }
                    }
                    assert forall|j: int| 0 <= j < after.len() implies has_forward(before, #[trigger] after[j]) by {
                        let j0 = if j < i { j } else { j + 1 };
                        assert(before[j0] == after[j]);
                    }
                    assert forall|k: int| 0 <= k < before.len() && !at_listener(before[k], la, lp) implies has_forward(after, #[trigger] before[k]) by {
                        let k0 = if k < i { k } else { k - 1 };
                        assert(after[k0] == before[k]);
                    }
                }
                self.entries.remove(i);
                #[cfg(verus_keep_ghost)]
                proof! {
                    // The position found is the witness that the order is kept.
                    assert(removed_at(lview(*self), lview(*old(self)), e, i as int));
                }
                Some(e)
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let s = self.entries@;
                    assert forall|j: int| 0 <= j < s.len() implies has_forward(s, #[trigger] s[j]) by {
                        assert(s[j] == s[j]);
                    }
                }
                None
            }
        }
    }

    /// Whether some forward dials `addr` at `port`. L1 (d).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == dials(lview(*self), addr, port),
    ))]
    pub fn dials(&self, addr: u32, port: u16) -> bool {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> !((#[trigger] self.entries@[j]).addr == addr && self.entries@[j].inside == port),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].addr == addr && self.entries[i].inside == port {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Whether some forward dials `addr` at `port` in `proto`. L1 (d).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == dials_in(lview(*self), addr, port, proto),
    ))]
    pub fn dials_in(&self, addr: u32, port: u16, proto: u8) -> bool {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> !((#[trigger] self.entries@[j]).addr == addr && self.entries@[j].inside == port && self.entries@[j].proto == proto),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].addr == addr
                && self.entries[i].inside == port
                && self.entries[i].proto == proto
            {
                return true;
            }
            i += 1;
        }
        false
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == lview(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(verus_keep_ghost)]
verus! {

/// What `publish` promises of its result and of the ledger before and after.
pub open spec fn publish_post(before: Ledger, after: Ledger, f: Forward, r: Published) -> bool {
    &&& same_caps(after, before)
    &&& match r {
        Published::Noted => {
            &&& !held(lview(before), f.listener_addr, f.listener_port)
            &&& lview(after) == lview(before).push(f)
        },
        Published::NotedEvicting(j) => {
            &&& !held(lview(before), f.listener_addr, f.listener_port)
            &&& f.by == Applier::Interim
            &&& j < lview(before).len()
            &&& lview(before)[j as int].by == Applier::Interim
            &&& no_interim_before(lview(before), j as int)
            &&& applied_by(lview(before), Applier::Interim) >= interim_cap_of(before)
            &&& lview(after) == lview(before).remove(j as int).push(f)
        },
        Published::Held => {
            &&& lview(after) == lview(before)
            &&& held(lview(before), f.listener_addr, f.listener_port)
            &&& holder_of(lview(before), f).addr == f.addr
        },
        Published::HeldElsewhere => {
            &&& lview(after) == lview(before)
            &&& held(lview(before), f.listener_addr, f.listener_port)
            &&& holder_of(lview(before), f).addr != f.addr
        },
        Published::Full => {
            &&& lview(after) == lview(before)
            &&& !held(lview(before), f.listener_addr, f.listener_port)
            &&& match f.by {
                Applier::Row => applied_by(lview(before), Applier::Row) >= row_cap_of(before),
                Applier::Interim => interim_cap_of(before) == 0,
            }
        },
    }
}

/// The forward `e` sat at position `i`, and `now` is `before` without it, in
/// the same order.
pub open spec fn removed_at(now: Seq<Forward>, before: Seq<Forward>, e: Forward, i: int) -> bool {
    0 <= i < before.len() && before[i] == e && now == before.remove(i)
}

/// What `retract` promises of its result and of the ledger before and after.
pub open spec fn retract_post(before: Ledger, after: Ledger, la: u32, lp: u16, r: Option<Forward>) -> bool {
    &&& same_caps(after, before)
    &&& !held(lview(after), la, lp)
    &&& nothing_new(lview(after), lview(before))
    &&& keeps_other_listeners(lview(after), lview(before), la, lp)
    &&& match r {
        Some(e) => {
            &&& at_listener(e, la, lp)
            &&& has_forward(lview(before), e)
            &&& lview(after).len() + 1 == lview(before).len()
            &&& exists|i: int| removed_at(lview(after), lview(before), e, i)
        },
        None => {
            &&& !held(lview(before), la, lp)
            &&& lview(after) == lview(before)
        },
    }
}

/// The forward that holds `f`'s listener: the one a publish of `f` finds.
pub open spec fn holder_of(s: Seq<Forward>, f: Forward) -> Forward {
    s[choose|j: int| 0 <= j < s.len() && at_listener(#[trigger] s[j], f.listener_addr, f.listener_port)]
}

/// With one holder per listener, the forward found at `i` is the holder.
pub proof fn lemma_holder_is(s: Seq<Forward>, f: Forward, i: int)
    requires
        one_holder(s),
        0 <= i < s.len(),
        at_listener(s[i], f.listener_addr, f.listener_port),
    ensures
        holder_of(s, f) == s[i],
        held(s, f.listener_addr, f.listener_port),
{
    let j = choose|j: int| 0 <= j < s.len() && at_listener(#[trigger] s[j], f.listener_addr, f.listener_port);
    if j < i {
        assert(!at_listener(s[j], s[i].listener_addr, s[i].listener_port));
    } else if i < j {
        assert(!at_listener(s[i], s[j].listener_addr, s[j].listener_port));
    }
}

/// A publish at a listener somebody holds changes nothing, and its answer
/// says whether the asker is the holder.
pub proof fn lemma_publish_held(before: Ledger, after: Ledger, f: Forward, i: int)
    requires
        linv(before),
        after == before,
        0 <= i < lview(before).len(),
        at_listener(lview(before)[i], f.listener_addr, f.listener_port),
    ensures
        linv(after),
        publish_post(before, after, f, if lview(before)[i].addr == f.addr { Published::Held } else { Published::HeldElsewhere }),
{
    lemma_holder_is(lview(before), f, i);
}

/// A refused publish changes nothing.
pub proof fn lemma_publish_full(before: Ledger, after: Ledger, f: Forward)
    requires
        linv(before),
        after == before,
        !held(lview(before), f.listener_addr, f.listener_port),
        match f.by {
            Applier::Row => applied_by(lview(before), Applier::Row) >= row_cap_of(before),
            Applier::Interim => interim_cap_of(before) == 0,
        },
    ensures
        linv(after),
        publish_post(before, after, f, Published::Full),
{
}

/// Appending `f` at a free listener within its bound keeps L1 and is `Noted`.
pub proof fn lemma_publish_noted(before: Ledger, after: Ledger, f: Forward)
    requires
        linv(before),
        same_caps(after, before),
        !held(lview(before), f.listener_addr, f.listener_port),
        lview(after) == lview(before).push(f),
        f.by == Applier::Row ==> applied_by(lview(before), Applier::Row) < row_cap_of(before),
        f.by == Applier::Interim ==> applied_by(lview(before), Applier::Interim) < interim_cap_of(before),
    ensures
        linv(after),
        publish_post(before, after, f, Published::Noted),
{
    lemma_applied_push(lview(before), f, Applier::Row);
    lemma_applied_push(lview(before), f, Applier::Interim);
    lemma_push_one_holder(lview(before), f);
}

/// Evicting the oldest interim forward for an interim `f` at a free listener
/// keeps L1 and is `NotedEvicting`.
pub proof fn lemma_publish_evicting(before: Ledger, after: Ledger, f: Forward, j: usize)
    requires
        linv(before),
        same_caps(after, before),
        !held(lview(before), f.listener_addr, f.listener_port),
        f.by == Applier::Interim,
        j < lview(before).len(),
        lview(before)[j as int].by == Applier::Interim,
        no_interim_before(lview(before), j as int),
        applied_by(lview(before), Applier::Interim) >= interim_cap_of(before),
        lview(after) == lview(before).remove(j as int).push(f),
    ensures
        linv(after),
        publish_post(before, after, f, Published::NotedEvicting(j)),
{
    let s = lview(before);
    let mid = s.remove(j as int);
    lemma_applied_remove(s, j as int, Applier::Row);
    lemma_applied_remove(s, j as int, Applier::Interim);
    lemma_remove_one_holder(s, j as int);
    // Nothing in the shorter table holds the listener either.
    assert(!held(mid, f.listener_addr, f.listener_port)) by {
        if held(mid, f.listener_addr, f.listener_port) {
            let x = choose|x: int| 0 <= x < mid.len() && at_listener(#[trigger] mid[x], f.listener_addr, f.listener_port);
            let x0 = if x < j { x } else { x + 1 };
            assert(at_listener(s[x0], f.listener_addr, f.listener_port));
        }
    }
    lemma_applied_push(mid, f, Applier::Row);
    lemma_applied_push(mid, f, Applier::Interim);
    lemma_push_one_holder(mid, f);
}

} // verus!

#[cfg(kani)]
mod proofs {
    //! One operation from any ledger of up to `MAX` forwards that satisfies
    //! L1 (a) and (c), checked against plain scans of a copy taken before.

    use super::*;

    const MAX: usize = 3;

    fn any_forward() -> Forward {
        Forward {
            listener_addr: kani::any(),
            listener_port: kani::any(),
            addr: kani::any(),
            inside: kani::any(),
            proto: kani::any(),
            by: if kani::any() {
                Applier::Row
            } else {
                Applier::Interim
            },
        }
    }

    /// Where `s` holds the listener, by a plain scan.
    fn holder_at(s: &[Forward], la: u32, lp: u16) -> Option<usize> {
        let mut i = 0;
        while i < s.len() {
            if s[i].listener_addr == la && s[i].listener_port == lp {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// How many forwards of `s` the interim applied (`interim`) or rows did.
    fn applied(s: &[Forward], interim: bool) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < s.len() {
            let is_interim = match s[i].by {
                Applier::Row => false,
                Applier::Interim => true,
            };
            if is_interim == interim {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// L1 (a) and (c), written a second time.
    fn holds_l1(s: &[Forward], row_cap: usize, interim_cap: usize) -> bool {
        let mut j = 0;
        while j < s.len() {
            let mut i = 0;
            while i < j {
                if s[i].listener_addr == s[j].listener_addr
                    && s[i].listener_port == s[j].listener_port
                {
                    return false;
                }
                i += 1;
            }
            j += 1;
        }
        applied(s, false) <= row_cap && applied(s, true) <= interim_cap
    }

    /// `a` is `b` with the forward at `gone` removed, if any, and then
    /// `added` appended, if any.
    fn is_edit(a: &[Forward], b: &[Forward], gone: Option<usize>, added: Option<Forward>) -> bool {
        let kept = match gone {
            Some(_) => b.len() - 1,
            None => b.len(),
        };
        let total = match added {
            Some(_) => kept + 1,
            None => kept,
        };
        if a.len() != total {
            return false;
        }
        let mut i = 0;
        while i < kept {
            let from = match gone {
                Some(g) => {
                    if i < g {
                        i
                    } else {
                        i + 1
                    }
                }
                None => i,
            };
            if a[i] != b[from] {
                return false;
            }
            i += 1;
        }
        match added {
            Some(f) => a[kept] == f,
            None => true,
        }
    }

    /// Any ledger of up to `MAX` forwards that satisfies L1 (a) and (c), with
    /// room for one more, so no operation reallocates.
    fn any_ledger() -> Ledger {
        let row_cap: usize = kani::any();
        let interim_cap: usize = kani::any();
        kani::assume(row_cap <= MAX && interim_cap <= MAX);
        let n: usize = kani::any();
        kani::assume(n <= MAX);
        let mut entries = Vec::with_capacity(MAX + 1);
        let mut i = 0;
        while i < n {
            entries.push(any_forward());
            i += 1;
        }
        kani::assume(holds_l1(&entries, row_cap, interim_cap));
        Ledger {
            entries,
            row_cap,
            interim_cap,
        }
    }

    /// A new ledger is empty and satisfies L1.
    #[kani::proof]
    #[kani::unwind(2)]
    fn kani_ledger_new() {
        let row_cap: usize = kani::any();
        let interim_cap: usize = kani::any();
        let l = Ledger::new(row_cap, interim_cap);
        assert!(l.entries.len() == 0 && l.row_cap == row_cap && l.interim_cap == interim_cap);
        assert!(holds_l1(&l.entries, row_cap, interim_cap));
    }

    /// One `publish` to any ledger. L1 (a), (b), (c).
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_ledger_publish_step() {
        let mut l = any_ledger();
        let before = l.entries.clone();
        let (row_cap, interim_cap) = (l.row_cap, l.interim_cap);
        let f = any_forward();
        let holder = holder_at(&before, f.listener_addr, f.listener_port);
        let interim = match f.by {
            Applier::Row => false,
            Applier::Interim => true,
        };
        let r = l.publish(f);

        assert!(l.row_cap == row_cap && l.interim_cap == interim_cap);
        assert!(holds_l1(&l.entries, row_cap, interim_cap));
        match r {
            Published::Noted => {
                assert!(holder.is_none());
                assert!(is_edit(&l.entries, &before, None, Some(f)));
                let cap = if interim { interim_cap } else { row_cap };
                assert!(applied(&before, interim) < cap);
            }
            Published::NotedEvicting(j) => {
                assert!(holder.is_none());
                assert!(interim && interim_cap > 0);
                assert!(applied(&before, true) == interim_cap);
                assert!(j < before.len());
                // The evicted forward is the first the interim applied.
                assert!(applied(&before[..j], true) == 0);
                assert!(applied(&before[..j + 1], true) == 1);
                assert!(is_edit(&l.entries, &before, Some(j), Some(f)));
            }
            Published::Held => {
                assert!(is_edit(&l.entries, &before, None, None));
                match holder {
                    Some(i) => {
                        assert!(before[i].addr == f.addr);
                    }
                    None => {
                        assert!(false);
                    }
                }
            }
            Published::HeldElsewhere => {
                assert!(is_edit(&l.entries, &before, None, None));
                match holder {
                    Some(i) => {
                        assert!(before[i].addr != f.addr);
                    }
                    None => {
                        assert!(false);
                    }
                }
            }
            Published::Full => {
                assert!(holder.is_none());
                assert!(is_edit(&l.entries, &before, None, None));
                if interim {
                    assert!(interim_cap == 0);
                } else {
                    assert!(applied(&before, false) >= row_cap);
                }
            }
        }
        kani::cover!(r == Published::Noted && interim);
        kani::cover!(r == Published::Noted && !interim);
        kani::cover!(matches!(r, Published::NotedEvicting(_)));
        kani::cover!(matches!(r, Published::NotedEvicting(j) if j > 0));
        kani::cover!(r == Published::Held);
        kani::cover!(r == Published::HeldElsewhere);
        kani::cover!(r == Published::Full && interim);
        kani::cover!(r == Published::Full && !interim);
    }

    /// One `retract` from any ledger. L1 (e).
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_ledger_retract_step() {
        let mut l = any_ledger();
        let before = l.entries.clone();
        let (row_cap, interim_cap) = (l.row_cap, l.interim_cap);
        let la: u32 = kani::any();
        let lp: u16 = kani::any();
        let holder = holder_at(&before, la, lp);
        let r = l.retract(la, lp);

        assert!(l.row_cap == row_cap && l.interim_cap == interim_cap);
        assert!(holds_l1(&l.entries, row_cap, interim_cap));
        assert!(holder_at(&l.entries, la, lp).is_none());
        match (r, holder) {
            (Some(e), Some(i)) => {
                assert!(e == before[i]);
                assert!(is_edit(&l.entries, &before, Some(i), None));
            }
            (None, None) => {
                assert!(is_edit(&l.entries, &before, None, None));
            }
            (Some(_), None) => {
                assert!(false);
            }
            (None, Some(_)) => {
                assert!(false);
            }
        }
        kani::cover!(r.is_some() && before.len() == MAX);
        kani::cover!(r.is_none() && before.len() > 0);
    }

    /// The readers agree with a plain scan. L1 (d).
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_ledger_readers() {
        let l = any_ledger();
        let addr: u32 = kani::any();
        let port: u16 = kani::any();
        let proto: u8 = kani::any();

        let any_proto = l.dials(addr, port);
        let this_proto = l.dials_in(addr, port, proto);
        let mut found = false;
        let mut found_in = false;
        let mut k = 0;
        while k < l.entries.len() {
            if l.entries[k].addr == addr && l.entries[k].inside == port {
                found = true;
                if l.entries[k].proto == proto {
                    found_in = true;
                }
            }
            k += 1;
        }
        assert!(any_proto == found && this_proto == found_in);

        let la: u32 = kani::any();
        let lp: u16 = kani::any();
        let held = l.holder(la, lp);
        match (held, holder_at(&l.entries, la, lp)) {
            (Some(e), Some(j)) => {
                assert!(e == l.entries[j]);
            }
            (None, None) => {}
            (Some(_), None) => {
                assert!(false);
            }
            (None, Some(_)) => {
                assert!(false);
            }
        }
        assert!(l.len() == l.entries.len());
        kani::cover!(any_proto && !this_proto);
        kani::cover!(this_proto);
        kani::cover!(held.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(listener_port: u16, addr: u32, inside: u16, by: Applier) -> Forward {
        Forward {
            listener_addr: 0x7f00_4005,
            listener_port,
            addr,
            inside,
            proto: 6,
            by,
        }
    }

    #[test]
    fn a_listener_has_one_holder_and_a_second_publish_changes_nothing() {
        let mut l = Ledger::new(4, 4);
        assert_eq!(l.publish(fwd(8080, 7, 80, Applier::Row)), Published::Noted);
        assert_eq!(l.publish(fwd(8080, 7, 80, Applier::Row)), Published::Held);
        assert_eq!(
            l.publish(fwd(8080, 9, 80, Applier::Row)),
            Published::HeldElsewhere
        );
        assert_eq!(l.holder(0x7f00_4005, 8080).unwrap().addr, 7);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn a_frame_opens_a_record_only_at_a_port_a_forward_dials() {
        let mut l = Ledger::new(4, 4);
        assert_eq!(l.publish(fwd(8080, 7, 80, Applier::Row)), Published::Noted);
        assert!(l.dials(7, 80));
        assert!(!l.dials(7, 8080));
        assert!(!l.dials(9, 80));
        assert!(l.dials_in(7, 80, 6));
        assert!(!l.dials_in(7, 80, 17));
    }

    #[test]
    fn a_retraction_removes_its_forward_and_no_other() {
        let mut l = Ledger::new(4, 4);
        assert_eq!(l.publish(fwd(8080, 7, 80, Applier::Row)), Published::Noted);
        assert_eq!(l.publish(fwd(8081, 7, 81, Applier::Row)), Published::Noted);
        assert_eq!(l.retract(0x7f00_4005, 8080).unwrap().inside, 80);
        assert!(l.retract(0x7f00_4005, 8080).is_none());
        assert!(!l.dials(7, 80));
        assert!(l.dials(7, 81));
    }

    #[test]
    fn a_rows_publish_past_the_bound_is_refused_and_evicts_nothing() {
        let mut l = Ledger::new(2, 2);
        assert_eq!(l.publish(fwd(1, 7, 1, Applier::Row)), Published::Noted);
        assert_eq!(l.publish(fwd(2, 7, 2, Applier::Row)), Published::Noted);
        assert_eq!(l.publish(fwd(3, 7, 3, Applier::Row)), Published::Full);
        assert!(l.dials(7, 1) && l.dials(7, 2) && !l.dials(7, 3));
    }

    #[test]
    fn an_interim_publish_past_the_bound_evicts_the_oldest_interim_and_no_row() {
        let mut l = Ledger::new(2, 2);
        assert_eq!(l.publish(fwd(1, 7, 1, Applier::Row)), Published::Noted);
        assert_eq!(l.publish(fwd(2, 8, 2, Applier::Interim)), Published::Noted);
        assert_eq!(l.publish(fwd(3, 8, 3, Applier::Interim)), Published::Noted);
        assert_eq!(
            l.publish(fwd(4, 8, 4, Applier::Interim)),
            Published::NotedEvicting(1)
        );
        assert!(l.dials(7, 1) && !l.dials(8, 2) && l.dials(8, 3) && l.dials(8, 4));
        let mut none = Ledger::new(2, 0);
        assert_eq!(
            none.publish(fwd(1, 8, 1, Applier::Interim)),
            Published::Full
        );
    }
}
