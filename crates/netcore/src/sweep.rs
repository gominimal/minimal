//! What removing expired entries from a table means.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! THEOREM SW1, for every table with distinct keys:
//!   (a) a touch removes the entry for one row and key when it has expired,
//!       in place, and changes nothing otherwise: an entry is in the table
//!       afterwards exactly when it was before and is not that expired entry;
//!   (b) an expiry pass that removes nothing changes nothing, and one that
//!       removes something found an expired entry;
//!   (c) a sweep is due when none has run, when the interval is zero, or when
//!       at least the interval has passed since the last; with time behind
//!       the last sweep and a positive interval it is not due;
//!   (d) an insert that sweeps leaves exactly the entries that had not
//!       expired, and the new one.
//!
//! (d) says nothing about the order of the entries a sweep keeps: no reader
//! of a swept table depends on position.
//!
//! This file holds specification and proof only. The operations are in
//! [`crate::slab`] and [`crate::pool`].

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::pool::{
    Entry, Throttle, added, distinct_keys, has, holds, keeps_live, none_expired, only_adds,
    subset_of, theorem_added_members,
};

#[cfg(verus_keep_ghost)]
verus! {

/// Position `i` of `s` holds the entry for `(row, key)`, and it has expired at `now_ms`.
pub open spec fn expired_at(s: Seq<Entry>, row: u32, key: u64, now_ms: u64, i: int) -> bool {
    0 <= i < s.len() && s[i].row == row && s[i].key == key && s[i].deadline_ms <= now_ms
}

/// `s` holds an entry for `(row, key)` that has expired at `now_ms`.
pub open spec fn expired_held(s: Seq<Entry>, row: u32, key: u64, now_ms: u64) -> bool {
    exists|i: int| expired_at(s, row, key, now_ms, i)
}

/// `after` is `before` with the expired entry for `(row, key)` removed in
/// place, or `before` itself when there is none.
#[verifier::opaque]
pub open spec fn dropped_if_expired(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, now_ms: u64) -> bool {
    if expired_held(before, row, key, now_ms) {
        exists|i: int| expired_at(before, row, key, now_ms, i) && after == before.remove(i)
    } else {
        after == before
    }
}

/// Whether a sweep may run at `now_ms`.
pub open spec fn due(th: Throttle, now_ms: u64) -> bool {
    match th.last_ms {
        None => true,
        Some(t) => if now_ms >= t { now_ms - t >= th.interval_ms } else { th.interval_ms == 0 },
    }
}

/// `after` is `before` with every expired entry gone and `e` added.
#[verifier::opaque]
pub open spec fn swept_and_added(after: Seq<Entry>, before: Seq<Entry>, e: Entry, now_ms: u64) -> bool {
    &&& has(after, e)
    &&& only_adds(after, before, e)
    &&& keeps_live(after, before, now_ms)
    &&& forall|j: int| 0 <= j < after.len() ==> (#[trigger] after[j]) == e || after[j].deadline_ms > now_ms
}

/// What a subset of a table holds, the table held.
pub proof fn lemma_subset_not_held(first: Seq<Entry>, mid: Seq<Entry>, row: u32, key: u64)
    requires
        subset_of(mid, first),
        !holds(first, row, key),
    ensures
        !holds(mid, row, key),
{
    assert forall|j: int| 0 <= j < mid.len() implies !(mid[j].row == row && mid[j].key == key) by {
        assert(has(first, mid[j]));
    }
}

/// Sweeping `first` to `mid` and then adding `e`, wherever it is put, is a
/// sweep-and-add.
pub proof fn lemma_swept_added(first: Seq<Entry>, mid: Seq<Entry>, after: Seq<Entry>, e: Entry, now_ms: u64)
    requires
        subset_of(mid, first),
        keeps_live(mid, first, now_ms),
        none_expired(mid, now_ms),
        added(after, mid, e),
    ensures
        swept_and_added(after, first, e, now_ms),
{
    reveal(swept_and_added);
    theorem_added_members(after, mid, e, e, 0);
    assert forall|j: int| 0 <= j < after.len() implies (has(first, #[trigger] after[j]) || after[j] == e)
        && (after[j] == e || after[j].deadline_ms > now_ms) by {
        theorem_added_members(after, mid, e, after[j], 0);
        assert(has(after, after[j]));
        if after[j] != e {
            let m = choose|m: int| 0 <= m < mid.len() && mid[m] == after[j];
            assert(has(first, mid[m]));
        }
    }
    assert forall|k: int| 0 <= k < first.len() && first[k].deadline_ms > now_ms implies has(after, #[trigger] first[k]) by {
        assert(has(mid, first[k]));
        theorem_added_members(after, mid, e, first[k], 0);
    }
}

/// SW1(c).
pub proof fn theorem_due_rule(th: Throttle, now_ms: u64)
    ensures
        th.last_ms.is_none() ==> due(th, now_ms),
        th.interval_ms == 0 ==> due(th, now_ms),
        th.last_ms.is_some() && now_ms < th.last_ms.unwrap() && th.interval_ms > 0 ==> !due(th, now_ms),
        th.last_ms.is_some() && now_ms >= th.last_ms.unwrap() ==> (due(th, now_ms) == (now_ms - th.last_ms.unwrap()
            >= th.interval_ms)),
{
}

/// SW1(d).
pub proof fn theorem_sweep_exact(after: Seq<Entry>, before: Seq<Entry>, e: Entry, now_ms: u64, x: Entry)
    requires
        !holds(before, e.row, e.key),
        swept_and_added(after, before, e, now_ms),
    ensures
        has(after, e),
        has(before, x) ==> (has(after, x) == (x.deadline_ms > now_ms)),
        has(after, x) ==> x == e || has(before, x),
{
    reveal(swept_and_added);
    if has(before, x) {
        let k = choose|k: int| 0 <= k < before.len() && before[k] == x;
        // `before` does not hold the new entry's row and key, so `x` is not the new entry.
        assert(!(before[k].row == e.row && before[k].key == e.key));
        if has(after, x) {
            let j = choose|j: int| 0 <= j < after.len() && after[j] == x;
            assert(after[j] != e);
        }
    }
    if has(after, x) {
        let j = choose|j: int| 0 <= j < after.len() && after[j] == x;
        assert(has(before, after[j]) || after[j] == e);
    }
}

/// A table that does not hold `(row, key)` is left as it is by a touch.
pub proof fn lemma_not_held_untouched(s: Seq<Entry>, row: u32, key: u64, now_ms: u64)
    requires
        !holds(s, row, key),
    ensures
        dropped_if_expired(s, s, row, key, now_ms),
{
    reveal(dropped_if_expired);
}

/// A touch adds nothing: every entry after it was an entry before, and the
/// table is no longer.
pub proof fn lemma_dropped_subset(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, now_ms: u64)
    requires
        dropped_if_expired(after, before, row, key, now_ms),
    ensures
        subset_of(after, before),
        after.len() <= before.len(),
{
    reveal(dropped_if_expired);
    if expired_held(before, row, key, now_ms) {
        let i = choose|i: int| expired_at(before, row, key, now_ms, i) && after == before.remove(i);
        assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) by {
            let j0 = if j < i { j } else { j + 1 };
            assert(after[j] == before[j0]);
        }
    } else {
        assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) by {
            assert(after[j] == before[j]);
        }
    }
}

/// SW1(a).
pub proof fn theorem_drop_exact(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, now_ms: u64, x: Entry)
    requires
        distinct_keys(before),
        dropped_if_expired(after, before, row, key, now_ms),
        has(before, x),
    ensures
        has(after, x) == !(x.row == row && x.key == key && x.deadline_ms <= now_ms),
{
    reveal(crate::pool::distinct_keys);
    reveal(dropped_if_expired);
    let k = choose|k: int| 0 <= k < before.len() && before[k] == x;
    if expired_held(before, row, key, now_ms) {
        let i = choose|i: int| expired_at(before, row, key, now_ms, i) && after == before.remove(i);
        if k == i {
            // Keys are distinct, so no other position holds this row and key.
            assert forall|j: int| 0 <= j < after.len() implies after[j] != x by {
                let j0 = if j < i { j } else { j + 1 };
                assert(after[j] == before[j0]);
                if j0 < i {
                    assert(!(before[j0].row == before[i].row && before[j0].key == before[i].key));
                } else {
                    assert(!(before[i].row == before[j0].row && before[i].key == before[j0].key));
                }
            }
        } else {
            let k0 = if k < i { k } else { k - 1 };
            assert(after[k0] == x);
            if k < i {
                assert(!(before[k].row == before[i].row && before[k].key == before[i].key));
            } else {
                assert(!(before[i].row == before[k].row && before[i].key == before[k].key));
            }
        }
    } else {
        assert(!expired_at(before, row, key, now_ms, k));
    }
}

} // verus!
