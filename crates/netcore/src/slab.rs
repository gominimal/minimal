//! A table with a hard capacity and a quota per row, looked up by binary
//! search.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The same table as [`crate::pool::Pool`], kept another way: the entries
//! sit in a slab and do not move between two rewrites of it; a second array
//! holds their positions in the slab, in order of row and then key. The table's
//! contents, as every guarantee here speaks of them, are the entries in that
//! order. A lookup is a binary search of the positions; an insert writes the
//! entry at the slab's end and puts its position in place.
//!
//! THEOREM G7, as for `Pool`: never more than `cap` entries, never more than
//! `quota` for one row, never one row and key twice; an insert that would
//! break a bound changes nothing and says which.
//!
//! THEOREM SB1: [`Slab::lower`] reads at most `log2(n) + 1` entries of a
//! table of `n` and at least `log2(n + 1)`, and [`Slab::place`] at most one
//! more. The count is a result of each only the verifier sees, raised by
//! hand beside each read, and it is part of their guarantee as far as that
//! goes: nothing ties the count to the reads the code makes. For the largest table the
//! constructor allows that is at most 15 reads by `lower`, and for one of
//! 4,096 entries at most 13. The public functions do not carry the count;
//! each says in its comment how many searches it makes.
//!
//! Removing an entry leaves its slot in the slab unused. An insert that adds
//! an entry rewrites the slab, to hold only the held entries, exactly when
//! the slab has reached twice the capacity ([`Slab::push_new`] says so).

#[cfg(verus_keep_ghost)]
use vstd::arithmetic::logarithm::log;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::pool::{Entry, Inserted, Swept, Throttle};
#[cfg(verus_keep_ghost)]
use crate::pool::{
    added, changed_only_to, count, distinct_keys, has, held_key, holds, keeps_live,
    keeps_other_rows, keeps_others, keeps_unmatched, keeps_unvalued, key_ends, lemma_count_le_len,
    lemma_count_remove, lemma_count_update, lemma_rank_eq, lemma_reclaim_not_held,
    lemma_reclaim_tables, lemma_remove_keeps_live, lemma_remove_keeps_other_rows,
    lemma_remove_keeps_unmatched, lemma_remove_keeps_unvalued, lemma_remove_subset,
    lemma_remove_within_caps, lemma_sorted_distinct, lemma_subset_member, live_key, live_number,
    none_ending, none_expired, none_valued, only_adds, rank, rank_of, refreshed_from, row_live,
    sorted, subset_of, within_caps,
};
#[cfg(verus_keep_ghost)]
use crate::sweep::{
    dropped_if_expired, due, expired_at, expired_held, lemma_subset_not_held, lemma_swept_added,
    swept_and_added,
};
use crate::time::Instant;

/// The most entries a table may be made for: positions in the slab are 16
/// bits, and the slab may come to hold twice the capacity.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_CAP: usize = 32767;

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Slab {
    slab: Vec<Entry>,
    order: Vec<u16>,
    cap: usize,
    quota: usize,
    /// No held entry's deadline is below this. While the clock is below it,
    /// nothing has expired and nothing need be read to know so.
    floor_ms: u64,
}

#[cfg(verus_keep_ghost)]
verus! {

/// The entries the positions `order` name in `slab`, in that order.
pub open spec fn mapped(slab: Seq<Entry>, order: Seq<u16>) -> Seq<Entry> {
    Seq::new(order.len(), |i: int| slab[order[i] as int])
}

pub closed spec fn sview(t: Slab) -> Seq<Entry> { mapped(t.slab@, t.order@) }
pub closed spec fn scap(t: Slab) -> int { t.cap as int }
pub closed spec fn squota(t: Slab) -> int { t.quota as int }
/// How many slots of the slab have been written since it was last rewritten.
pub closed spec fn sslots(t: Slab) -> int { t.slab@.len() as int }

/// What the representation keeps, beyond G7: every position is in the slab;
/// the entries are in strictly increasing order of rank; the capacity is one
/// a 16-bit position can serve; and the slab, which also holds the slots of
/// entries since removed, is at most twice the capacity. And no held entry's
/// deadline is below the stored floor.
pub closed spec fn rep(t: Slab) -> bool {
    &&& t.cap <= MAX_CAP
    &&& t.slab@.len() <= 2 * t.cap
    &&& forall|i: int| 0 <= i < t.order@.len() ==> (#[trigger] t.order@[i]) < t.slab@.len()
    &&& sorted(mapped(t.slab@, t.order@))
    &&& floored(mapped(t.slab@, t.order@), t.floor_ms)
}

/// The stored floor: no held entry's deadline is below it.
pub closed spec fn sfloor(t: Slab) -> u64 { t.floor_ms }

/// No entry of `s` has a deadline below `floor`.
#[verifier::opaque]
pub open spec fn floored(s: Seq<Entry>, floor: u64) -> bool {
    forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).deadline_ms >= floor
}

/// A floor holds of any part of what it holds of.
pub proof fn lemma_floored_subset(now: Seq<Entry>, before: Seq<Entry>, floor: u64)
    requires
        subset_of(now, before),
        floored(before, floor),
    ensures
        floored(now, floor),
{
    reveal(floored);
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).deadline_ms >= floor by {
        assert(has(before, now[j]));
        let k = choose|k: int| 0 <= k < before.len() && before[k] == now[j];
        assert(before[k].deadline_ms >= floor);
    }
}

/// A floor at or below an entry's deadline holds with the entry put in,
/// with it put in place of another, and with any entry left out; and a
/// lower floor holds wherever a higher one did.
pub proof fn lemma_floored_steps(s: Seq<Entry>, i: int, e: Entry, floor: u64, lower: u64)
    requires
        floored(s, floor),
        lower <= floor,
    ensures
        floored(s, lower),
        0 <= i <= s.len() && e.deadline_ms >= floor ==> floored(s.insert(i, e), floor),
        0 <= i < s.len() && e.deadline_ms >= floor ==> floored(s.update(i, e), floor),
        0 <= i < s.len() ==> floored(s.remove(i), floor),
{
    reveal(floored);
    if 0 <= i <= s.len() && e.deadline_ms >= floor {
        let t = s.insert(i, e);
        assert forall|j: int| 0 <= j < t.len() implies (#[trigger] t[j]).deadline_ms >= floor by {
            if j < i {
                assert(t[j] == s[j]);
            } else if j > i {
                assert(t[j] == s[j - 1]);
            }
        }
    }
    if 0 <= i < s.len() {
        let t = s.remove(i);
        assert forall|j: int| 0 <= j < t.len() implies (#[trigger] t[j]).deadline_ms >= floor by {
            let j0 = if j < i { j } else { j + 1 };
            assert(t[j] == s[j0]);
        }
    }
}

/// Under a floor above the clock nothing has expired.
pub proof fn lemma_floored_none_expired(s: Seq<Entry>, floor: u64, now_ms: u64)
    requires
        floored(s, floor),
        now_ms < floor,
    ensures
        none_expired(s, now_ms),
        forall|row: u32| row_live(s, row, now_ms),
{
    reveal(floored);
}

/// The invariant every operation keeps.
pub open spec fn sinv(t: Slab) -> bool {
    within_caps(sview(t), scap(t), squota(t)) && rep(t)
}

/// Reading the view: position `i` of the contents is the slab's entry at
/// `order[i]`.
pub proof fn lemma_mapped_at(slab: Seq<Entry>, order: Seq<u16>, i: int)
    requires
        0 <= i < order.len(),
    ensures
        mapped(slab, order).len() == order.len(),
        mapped(slab, order)[i] == slab[order[i] as int],
{
}

/// [`lemma_count_insert`] at the end: putting an entry in after the last is
/// pushing it.
proof fn lemma_count_insert_at_end(s: Seq<Entry>, e: Entry, row: u32)
    ensures
        count(s.insert(s.len() as int, e), row)
            == count(s, row) + if e.row == row { 1nat } else { 0nat },
{
    let i = s.len() as int;
    assert(s.insert(i, e) =~= s.push(e));
    assert(s.push(e).drop_last() =~= s);
    assert(s.push(e).last() == e);
}

/// [`lemma_count_insert`] before the end: the last entry stays last, and
/// what comes before it is the shorter sequence with the entry put in.
proof fn lemma_count_insert_inner(s: Seq<Entry>, i: int, e: Entry)
    requires
        0 <= i < s.len(),
    ensures
        s.insert(i, e).drop_last() == s.drop_last().insert(i, e),
        s.insert(i, e).last() == s.last(),
{
    assert(s.insert(i, e).drop_last() =~= s.drop_last().insert(i, e));
    assert(s.insert(i, e).last() == s.last());
}

/// How a row's count changes when an entry is put in at any place.
pub proof fn lemma_count_insert(s: Seq<Entry>, i: int, e: Entry, row: u32)
    requires
        0 <= i <= s.len(),
    ensures
        count(s.insert(i, e), row) == count(s, row) + if e.row == row { 1nat } else { 0nat },
    decreases s.len(),
{
    if i == s.len() {
        lemma_count_insert_at_end(s, e, row);
    } else {
        lemma_count_insert(s.drop_last(), i, e, row);
        lemma_count_insert_inner(s, i, e);
    }
}

/// Putting an entry in at any place is one way of adding.
pub proof fn lemma_added_insert(before: Seq<Entry>, i: int, e: Entry)
    requires
        0 <= i <= before.len(),
        !holds(before, e.row, e.key),
        sorted(before.insert(i, e)),
    ensures
        added(before.insert(i, e), before, e),
{
    reveal(added);
    let after = before.insert(i, e);
    assert(after[i] == e);
    assert forall|k: int| 0 <= k < before.len() implies has(after, #[trigger] before[k]) by {
        let k1 = if k < i { k } else { k + 1 };
        assert(after[k1] == before[k]);
    }
    assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) || after[j] == e by {
        if j < i {
            assert(before[j] == after[j]);
        } else if j > i {
            assert(before[j - 1] == after[j]);
        }
    }
    assert forall|r: u32| #[trigger] count(after, r) == count(before, r) + if r == e.row { 1nat } else { 0nat } by {
        lemma_count_insert(before, i, e, r);
    }
    lemma_sorted_distinct(after);
}

/// An entry put between everything that ranks below it and everything that
/// ranks above keeps the order.
pub proof fn lemma_sorted_insert(s: Seq<Entry>, i: int, e: Entry)
    requires
        sorted(s),
        0 <= i <= s.len(),
        forall|k: int| 0 <= k < i ==> rank(#[trigger] s[k]) < rank(e),
        forall|k: int| i <= k < s.len() ==> rank(#[trigger] s[k]) > rank(e),
    ensures
        sorted(s.insert(i, e)),
{
    let t = s.insert(i, e);
    assert forall|a: int, b: int| 0 <= a < b < t.len() implies rank(t[a]) < rank(t[b]) by {
        let a0 = if a < i { a } else { a - 1 };
        let b0 = if b < i { b } else { b - 1 };
        if a == i {
            assert(t[b] == s[b0]);
        } else if b == i {
            assert(t[a] == s[a0]);
        } else {
            assert(t[a] == s[a0] && t[b] == s[b0]);
            assert(rank(s[a0]) < rank(s[b0]));
        }
    }
}

/// The order survives leaving one entry out.
pub proof fn lemma_sorted_remove(s: Seq<Entry>, i: int)
    requires
        sorted(s),
        0 <= i < s.len(),
    ensures
        sorted(s.remove(i)),
{
    let t = s.remove(i);
    assert forall|a: int, b: int| 0 <= a < b < t.len() implies rank(t[a]) < rank(t[b]) by {
        let a0 = if a < i { a } else { a + 1 };
        let b0 = if b < i { b } else { b + 1 };
        assert(t[a] == s[a0] && t[b] == s[b0]);
        assert(rank(s[a0]) < rank(s[b0]));
    }
}

/// Leaving a position out of the order leaves its entry out of the contents.
pub proof fn lemma_mapped_remove(slab: Seq<Entry>, order: Seq<u16>, i: int)
    requires
        0 <= i < order.len(),
    ensures
        mapped(slab, order.remove(i)) == mapped(slab, order).remove(i),
{
    assert(mapped(slab, order.remove(i)) =~= mapped(slab, order).remove(i));
}

/// In a table with distinct keys, a position holds the only entry with its
/// row and key.
pub proof fn lemma_only_position(s: Seq<Entry>, i: int)
    requires
        sorted(s),
        0 <= i < s.len(),
    ensures
        forall|j: int| 0 <= j < s.len() && s[j].row == s[i].row && s[j].key == s[i].key ==> j == i,
{
    assert forall|j: int| 0 <= j < s.len() && s[j].row == s[i].row && s[j].key == s[i].key implies j == i by {
        lemma_rank_eq(s[j].row, s[j].key, s[i].row, s[i].key);
        if j < i {
            assert(rank(s[j]) < rank(s[i]));
        } else if j > i {
            assert(rank(s[i]) < rank(s[j]));
        }
    }
}

/// What `remove` promises when the entry at `i`, the one for `(row, key)`,
/// is left out.
pub proof fn lemma_removed(before: Seq<Entry>, after: Seq<Entry>, i: int, row: u32, key: u64)
    requires
        sorted(before),
        0 <= i < before.len(),
        before[i].row == row,
        before[i].key == key,
        after == before.remove(i),
    ensures
        holds(before, row, key),
        !holds(after, row, key),
        subset_of(after, before),
        after.len() + 1 == before.len(),
        keeps_others(after, before, row, key),
{
    lemma_only_position(before, i);
    assert forall|j: int| 0 <= j < after.len() implies !(after[j].row == row && after[j].key == key) by {
        let j0 = if j < i { j } else { j + 1 };
        assert(after[j] == before[j0]);
    }
    assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) by {
        let j0 = if j < i { j } else { j + 1 };
        assert(before[j0] == after[j]);
    }
    assert forall|k: int| 0 <= k < before.len() && !(before[k].row == row && before[k].key == key) implies has(
        after,
        #[trigger] before[k],
    ) by {
        let k0 = if k < i { k } else { k - 1 };
        assert(after[k0] == before[k]);
    }
}

/// A table is a subset of itself and keeps all of itself.
pub proof fn lemma_unchanged(s: Seq<Entry>, row: u32, key: u64)
    ensures
        subset_of(s, s),
        keeps_others(s, s, row, key),
{
    assert forall|j: int| 0 <= j < s.len() implies has(s, #[trigger] s[j]) by {
        assert(s[j] == s[j]);
    }
    assert forall|k: int| 0 <= k < s.len() && !(s[k].row == row && s[k].key == key) implies has(
        s,
        #[trigger] s[k],
    ) by {
        assert(s[k] == s[k]);
    }
}

/// An entry replaced by one of the same row and key keeps the order.
pub proof fn lemma_sorted_update(s: Seq<Entry>, i: int, e: Entry)
    requires
        sorted(s),
        0 <= i < s.len(),
        s[i].row == e.row,
        s[i].key == e.key,
    ensures
        sorted(s.update(i, e)),
{
    let t = s.update(i, e);
    assert forall|a: int, b: int| 0 <= a < b < t.len() implies rank(t[a]) < rank(t[b]) by {
        assert(rank(s[a]) < rank(s[b]));
    }
}

/// An entry ranks below the first rank of `row` exactly when its own row is
/// lower.
pub proof fn lemma_rank_row(e: Entry, row: u32)
    ensures
        rank(e) < rank_of(row, 0) <==> e.row < row,
{
}

/// Entries in order of rank are in order of row.
pub proof fn lemma_rank_rows_ordered(x: Entry, y: Entry)
    ensures
        rank(x) <= rank(y) ==> x.row <= y.row,
{
}

/// The two searches of `row_count` split the contents at the row's first
/// rank and at the next row's: the row's count is the width between.
proof fn lemma_row_split(s: Seq<Entry>, row: u32, a: int, b: int)
    requires
        0 <= a <= s.len(),
        0 <= b <= s.len(),
        forall|i: int| 0 <= i < a ==> rank(#[trigger] s[i]) < rank_of(row, 0),
        forall|i: int| a <= i < s.len() ==> rank(#[trigger] s[i]) >= rank_of(row, 0),
        row < u32::MAX ==> forall|i: int|
            0 <= i < b ==> rank(#[trigger] s[i]) < rank_of((row + 1) as u32, 0),
        row < u32::MAX ==> forall|i: int|
            b <= i < s.len() ==> rank(#[trigger] s[i]) >= rank_of((row + 1) as u32, 0),
        row == u32::MAX ==> b == s.len(),
        sorted(s),
    ensures
        a <= b,
        count(s, row) == b - a,
{
    // The first search splits the contents at the row's first rank,
    // the second at the next row's.
    assert forall|k: int| 0 <= k < s.len() implies (k < a ==> (#[trigger] s[k]).row < row)
        && (k >= a ==> s[k].row >= row) by {
        lemma_rank_row(s[k], row);
    }
    if row < u32::MAX {
        assert forall|k: int| 0 <= k < s.len() implies (k < b ==> (#[trigger] s[k]).row <= row)
            && (k >= b ==> s[k].row > row) by {
            lemma_rank_row(s[k], (row + 1) as u32);
        }
        if b < a {
            assert(s[b as int].row < row && s[b as int].row > row);
        }
    }
    lemma_count_between(s, row, a, b);
}

/// A row's count is the width of its run: everything before `a` is of a
/// lower row, everything from `b` on of a higher, and everything between is
/// the row's.
pub proof fn lemma_count_between(s: Seq<Entry>, row: u32, a: int, b: int)
    requires
        0 <= a <= b <= s.len(),
        forall|k: int| 0 <= k < a ==> (#[trigger] s[k]).row < row,
        forall|k: int| a <= k < b ==> (#[trigger] s[k]).row == row,
        forall|k: int| b <= k < s.len() ==> (#[trigger] s[k]).row > row,
    ensures
        count(s, row) == b - a,
    decreases s.len(),
{
    if s.len() > 0 {
        let t = s.drop_last();
        assert(s.last() == s[s.len() - 1]);
        if b < s.len() {
            lemma_count_between(t, row, a, b);
        } else if a < b {
            lemma_count_between(t, row, a, b - 1);
        } else {
            lemma_count_between(t, row, a - 1, b - 1);
        }
    }
}

/// A sweep in progress. `order` has been read up to `i`; the positions kept
/// so far are its first `w`; and `g`, the contents as they would be had each
/// entry removed gone when it was met, is what those `w` positions name,
/// followed by what the positions from `i` on name.
#[verifier::opaque]
pub open spec fn sweeping(slab: Seq<Entry>, order: Seq<u16>, g: Seq<Entry>, w: int, i: int) -> bool {
    &&& 0 <= w <= i <= order.len()
    &&& g.len() == w + (order.len() - i)
    &&& forall|j: int| 0 <= j < w ==> (#[trigger] order[j]) < slab.len() && g[j] == slab[order[j] as int]
    &&& forall|j: int| i <= j < order.len() ==> (#[trigger] order[j]) < slab.len() && g[w + (j - i)] == slab[
        order[j] as int
    ]
}

/// A sweep that has kept everything before `i` starts from the contents.
pub proof fn lemma_sweep_start(slab: Seq<Entry>, order: Seq<u16>, i: int)
    requires
        0 <= i <= order.len(),
        forall|j: int| 0 <= j < order.len() ==> (#[trigger] order[j]) < slab.len(),
    ensures
        sweeping(slab, order, mapped(slab, order), i, i),
{
    reveal(sweeping);
}

/// The entry a sweep reads next is the one at `w` of `g`.
pub proof fn lemma_sweep_read(slab: Seq<Entry>, order: Seq<u16>, g: Seq<Entry>, w: int, i: int)
    requires
        sweeping(slab, order, g, w, i),
        i < order.len(),
    ensures
        0 <= w <= i,
        w < g.len(),
        order[i] < slab.len(),
        g[w] == slab[order[i] as int],
{
    reveal(sweeping);
}

/// Keeping the entry read: its position is written at `w`, and `g` stays.
pub proof fn lemma_sweep_keep(
    slab: Seq<Entry>,
    order: Seq<u16>,
    after: Seq<u16>,
    g: Seq<Entry>,
    w: int,
    i: int,
    w2: int,
    i2: int,
)
    requires
        sweeping(slab, order, g, w, i),
        i < order.len(),
        after == order.update(w, order[i]),
        w2 == w + 1,
        i2 == i + 1,
    ensures
        sweeping(slab, after, g, w2, i2),
{
    reveal(sweeping);
    assert forall|j: int| i2 <= j < after.len() implies (#[trigger] after[j]) < slab.len() && g[w2 + (j - i2)]
        == slab[after[j] as int] by {
        assert(after[j] == order[j]);
        assert(w2 + (j - i2) == w + (j - i));
    }
}

/// Removing the entry read: `g` loses its entry at `w`. The position
/// written at `w` is not among the kept and will be written over or cut off.
pub proof fn lemma_sweep_drop(
    slab: Seq<Entry>,
    order: Seq<u16>,
    after: Seq<u16>,
    g: Seq<Entry>,
    w: int,
    i: int,
    i2: int,
)
    requires
        sweeping(slab, order, g, w, i),
        i < order.len(),
        after == order.update(w, order[i]),
        i2 == i + 1,
    ensures
        sweeping(slab, after, g.remove(w), w, i2),
{
    reveal(sweeping);
    let h = g.remove(w);
    assert forall|j: int| i2 <= j < after.len() implies (#[trigger] after[j]) < slab.len() && h[w + (j - i2)]
        == slab[after[j] as int] by {
        assert(after[j] == order[j]);
        assert(h[w + (j - i2)] == g[w + (j - i)]);
    }
}

/// A sweep that has read every position leaves `g` as what the first `w`
/// positions name.
pub proof fn lemma_sweep_end(slab: Seq<Entry>, order: Seq<u16>, g: Seq<Entry>, w: int)
    requires
        sweeping(slab, order, g, w, order.len() as int),
    ensures
        0 <= w <= order.len(),
        g.len() == w,
        mapped(slab, order.take(w)) == g,
        forall|j: int| 0 <= j < w ==> (#[trigger] order.take(w)[j]) < slab.len(),
{
    reveal(sweeping);
    assert forall|j: int| 0 <= j < w implies (#[trigger] order.take(w)[j]) < slab.len() && mapped(
        slab,
        order.take(w),
    )[j] == g[j] by {
        assert(order.take(w)[j] == order[j]);
    }
    assert(mapped(slab, order.take(w)) =~= g);
}

/// A table keeps all of itself, by each of the ways a sweep is said to keep.
pub proof fn lemma_self_kept(s: Seq<Entry>, now_ms: u64, row: u32, hi: u64, lo: u64)
    ensures
        subset_of(s, s),
        keeps_live(s, s, now_ms),
        keeps_other_rows(s, s, row),
        keeps_unmatched(s, s, hi, lo),
{
    assert forall|k: int| 0 <= k < s.len() implies has(s, #[trigger] s[k]) by {
        assert(s[k] == s[k]);
    }
}

/// SB1, the bound in numbers: a table the constructor allows is searched in
/// at most 15 reads, and one of 4,096 entries in at most 13.
pub proof fn theorem_sb1_probes_in_numbers(n: int)
    requires
        0 <= n <= MAX_CAP,
    ensures
        log(2, n) + 1 <= 15,
        n <= 4096 ==> log(2, n) + 1 <= 13,
{
    // 2^15 = 32768 > MAX_CAP, and 2^12 = 4096.
    reveal(log);
    vstd::arithmetic::logarithm::lemma_log_is_ordered(2, n, 32767);
    assert(log(2, 32767) == 14) by (compute);
    if n <= 4096 {
        vstd::arithmetic::logarithm::lemma_log_is_ordered(2, n, 4096);
        assert(log(2, 4096) == 12) by (compute);
    }
}

/// One halving step of a search, from above: an interval of `k >= 1` that
/// is at most half of `m` has a logarithm at least one smaller.
proof fn lemma_log_halve_down(m: int, k: int)
    requires
        1 <= k,
        2 * k <= m,
    ensures
        log(2, k) + 1 <= log(2, m),
{
    reveal(log);
    vstd::arithmetic::logarithm::lemma_log_is_ordered(2, k, m / 2);
}

/// One halving step of a search, from below: `k` at least half of `m >= 2`
/// (rounded down) has a logarithm at most one smaller.
proof fn lemma_log_halve_up(m: int, k: int)
    requires
        2 <= m,
        m / 2 <= k,
    ensures
        log(2, k) + 1 >= log(2, m),
{
    reveal(log);
    vstd::arithmetic::logarithm::lemma_log_is_ordered(2, m / 2, k);
}

/// Putting a new entry's slot at the slab's end and its position at place
/// `i` of the order keeps the representation, and the contents become the
/// old ones with the entry put in at `i`.
/// `push_new_at`'s last step, read against the table as it was on entry:
/// `t` is the table after the floor and the compaction, `u` after the push
/// and the insert into the order.
proof fn lemma_pushed_new_at(old: Slab, t: Slab, u: Slab, i: int, e: Entry)
    requires
        sinv(old),
        !holds(sview(old), e.row, e.key),
        count(sview(old), e.row) < squota(old),
        sview(old).len() < scap(old),
        0 <= i <= sview(old).len(),
        forall|k: int| 0 <= k < i ==> rank(#[trigger] sview(old)[k]) < rank(e),
        forall|k: int| i <= k < sview(old).len() ==> rank(#[trigger] sview(old)[k]) > rank(e),
        sinv(t),
        sview(t) == sview(old),
        scap(t) == scap(old),
        squota(t) == squota(old),
        t.slab@.len() < 2 * t.cap,
        e.deadline_ms >= t.floor_ms,
        sslots(old) < 2 * scap(old) ==> sslots(t) == sslots(old),
        sslots(old) >= 2 * scap(old) ==> sslots(t) == sview(t).len(),
        u.cap == t.cap,
        u.quota == t.quota,
        u.floor_ms == t.floor_ms,
        u.slab@ == t.slab@.push(e),
        u.order@ == t.order@.insert(i, t.slab@.len() as u16),
    ensures
        sinv(u),
        scap(u) == scap(old),
        squota(u) == squota(old),
        added(sview(u), sview(old), e),
        sslots(old) < 2 * scap(old) ==> sslots(u) == sslots(old) + 1,
        sslots(old) >= 2 * scap(old) ==> sslots(u) == sview(u).len(),
{
    lemma_slab_insert(t, u, i, e);
}

/// One more entry read by `live_count`: the count of the first `i + 1`
/// entries is that of the first `i` and one more if the entry at `i` has not
/// expired.
proof fn lemma_live_step(s: Seq<Entry>, i: int, now_ms: u64)
    requires
        0 <= i < s.len(),
    ensures
        live_number(s.take(i + 1), now_ms) == live_number(s.take(i), now_ms)
            + if s[i].deadline_ms > now_ms { 1nat } else { 0nat },
{
    assert(s.take(i + 1).drop_last() =~= s.take(i));
    assert(s.take(i + 1).last() == s[i]);
}

proof fn lemma_slab_insert(t: Slab, u: Slab, i: int, e: Entry)
    requires
        sinv(t),
        t.slab@.len() < 2 * t.cap,
        u.cap == t.cap,
        u.quota == t.quota,
        u.floor_ms == t.floor_ms,
        e.deadline_ms >= t.floor_ms,
        u.slab@ == t.slab@.push(e),
        u.order@ == t.order@.insert(i, t.slab@.len() as u16),
        0 <= i <= sview(t).len(),
        sview(t).len() < scap(t),
        count(sview(t), e.row) < squota(t),
        !holds(sview(t), e.row, e.key),
        forall|k: int| 0 <= k < i ==> rank(#[trigger] sview(t)[k]) < rank(e),
        forall|k: int| i <= k < sview(t).len() ==> rank(#[trigger] sview(t)[k]) > rank(e),
    ensures
        sinv(u),
        sview(u) == sview(t).insert(i, e),
        added(sview(u), sview(t), e),
{
    let before = sview(t);
    let p = t.slab@.len();
    assert(p < 2 * MAX_CAP);
    lemma_sorted_insert(before, i, e);
    lemma_added_insert(before, i, e);
    // Every older position names what it named, one place later from `i` on;
    // the new one names the new slot.
    assert forall|j: int| 0 <= j < u.order@.len() implies (#[trigger] u.order@[j]) < u.slab@.len()
        && u.slab@[u.order@[j] as int] == before.insert(i, e)[j] by {
        if j < i {
            assert(u.order@[j] == t.order@[j]);
        } else if j > i {
            assert(u.order@[j] == t.order@[j - 1]);
        } else {
            assert(u.order@[j] == p as u16);
        }
    }
    assert(sview(u) =~= before.insert(i, e));
    assert forall|r: u32| count(sview(u), r) <= u.quota by {
        lemma_count_insert(before, i, e, r);
    }
    lemma_sorted_distinct(sview(u));
    lemma_floored_steps(before, i, e, t.floor_ms, t.floor_ms);
}

/// `lower`'s step when the middle entry ranks below the target, stated in
/// the loop invariant's own terms for the range after the step (`lo2`, `hi2`,
/// `p2`): everything up to and including it ranks below, and the probe
/// bounds hold with one more read. Only the order is needed.
proof fn lemma_lower_go_up(s: Seq<Entry>, n: int, lo: int, hi: int, mid: int, target: int, probes: int, lo2: int, hi2: int, p2: int)
    requires
        sorted(s),
        s.len() == n,
        0 <= lo <= mid < hi <= n,
        mid == lo + (hi - lo) / 2,
        forall|i: int| 0 <= i < lo ==> rank(#[trigger] s[i]) < target,
        forall|i: int| hi <= i < n ==> rank(#[trigger] s[i]) >= target,
        rank(s[mid]) < target,
        0 <= probes <= log(2, n) + 1,
        probes + log(2, hi - lo) <= log(2, n),
        probes + log(2, hi - lo + 1) >= log(2, n + 1),
        lo2 == mid + 1,
        hi2 == hi,
        p2 == probes + 1,
    ensures
        lo2 <= hi2 <= n,
        forall|i: int| 0 <= i < lo2 ==> rank(#[trigger] s[i]) < target,
        forall|i: int| hi2 <= i < n ==> rank(#[trigger] s[i]) >= target,
        0 <= p2 <= log(2, n) + 1,
        lo2 < hi2 ==> p2 + log(2, hi2 - lo2) <= log(2, n),
        p2 + log(2, hi2 - lo2 + 1) >= log(2, n + 1),
{
    assert forall|i: int| 0 <= i < lo2 implies rank(#[trigger] s[i]) < target by {
        if i < mid {
            assert(rank(s[i]) < rank(s[mid]));
        }
    }
    let m = hi - lo;
    let k = hi - mid - 1;
    vstd::arithmetic::logarithm::lemma_log_nonnegative(2, m);
    if k >= 1 {
        lemma_log_halve_down(m, k);
    }
    lemma_log_halve_up(m + 1, k + 1);
}

/// `lower`'s step when the middle entry ranks at or above the target, in
/// the loop invariant's own terms for the range after the step.
proof fn lemma_lower_go_down(s: Seq<Entry>, n: int, lo: int, hi: int, mid: int, target: int, probes: int, lo2: int, hi2: int, p2: int)
    requires
        sorted(s),
        s.len() == n,
        0 <= lo <= mid < hi <= n,
        mid == lo + (hi - lo) / 2,
        forall|i: int| 0 <= i < lo ==> rank(#[trigger] s[i]) < target,
        forall|i: int| hi <= i < n ==> rank(#[trigger] s[i]) >= target,
        rank(s[mid]) >= target,
        0 <= probes <= log(2, n) + 1,
        probes + log(2, hi - lo) <= log(2, n),
        probes + log(2, hi - lo + 1) >= log(2, n + 1),
        lo2 == lo,
        hi2 == mid,
        p2 == probes + 1,
    ensures
        lo2 <= hi2 <= n,
        forall|i: int| 0 <= i < lo2 ==> rank(#[trigger] s[i]) < target,
        forall|i: int| hi2 <= i < n ==> rank(#[trigger] s[i]) >= target,
        0 <= p2 <= log(2, n) + 1,
        lo2 < hi2 ==> p2 + log(2, hi2 - lo2) <= log(2, n),
        p2 + log(2, hi2 - lo2 + 1) >= log(2, n + 1),
{
    assert forall|i: int| hi2 <= i < n implies rank(#[trigger] s[i]) >= target by {
        if mid < i {
            assert(rank(s[mid]) < rank(s[i]));
        }
    }
    let m = hi - lo;
    let k = mid - lo;
    vstd::arithmetic::logarithm::lemma_log_nonnegative(2, m);
    if k >= 1 {
        lemma_log_halve_down(m, k);
    }
    lemma_log_halve_up(m + 1, k + 1);
}

/// The keep step's arithmetic: the `|` of two values each 0 or 1 is 0 or 1,
/// and 1 exactly when either is.
proof fn lemma_or_01(a: usize, b: usize)
    requires
        a <= 1,
        b <= 1,
    ensures
        a | b <= 1,
        (a | b == 1) == (a == 1 || b == 1),
{
    assert(a | b <= 1 && ((a | b == 1) == (a == 1 || b == 1))) by (bit_vector)
        requires
            a <= 1,
            b <= 1;
}

/// `insert_reclaiming`'s new entry, in the contract's own terms: `first`
/// the contents at entry, `mid` after the removal at `gone` (or none at -1),
/// `last` after the insert, `quota` and `cap` the table's. The length does
/// not fall; with room, nothing was removed and the step is an `added`; at
/// the row's quota the entry removed was of `row`, so every entry of another
/// row is kept.
proof fn lemma_reclaim_more(first: Seq<Entry>, mid: Seq<Entry>, last: Seq<Entry>, gone: int, e: Entry, row: u32, quota: int, cap: int)
    requires
        gone == -1 ==> mid == first,
        gone != -1 ==> 0 <= gone < first.len() && mid == first.remove(gone),
        added(last, mid, e),
        count(first, row) < quota && first.len() < cap ==> gone == -1,
        count(first, row) >= quota ==> gone != -1 && first[gone].row == row,
    ensures
        last.len() >= first.len(),
        (count(first, row) < quota && first.len() < cap) ==> added(last, first, e),
        count(first, row) >= quota ==> keeps_other_rows(last, first, row),
{
    crate::pool::theorem_added_members(last, mid, e, e, 0);
    if gone != -1 && first[gone].row == row {
        assert forall|k: int| 0 <= k < first.len() && first[k].row != row implies has(last, #[trigger] first[k]) by {
            assert(has(first, first[k]));
            crate::pool::lemma_remove_keeps(first, gone, first[k]);
            crate::pool::theorem_added_members(last, mid, e, first[k], 0);
        }
    }
}

/// `insert_reclaiming` at a key the table holds, found at `i`: the entry is
/// refreshed where it is, and the answer is `Refreshed`.
proof fn lemma_reclaim_refreshed(before: Slab, after: Slab, e: Entry, i: int)
    requires
        0 <= i < sview(before).len(),
        sview(before)[i].row == e.row,
        sview(before)[i].key == e.key,
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        refreshed_from(sview(after), sview(before), e.row, e.key),
        changed_only_to(sview(after), sview(before), e),
        has(sview(after), e),
    ensures
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        holds(sview(before), e.row, e.key),
        refreshed_from(sview(after), sview(before), e.row, e.key),
        changed_only_to(sview(after), sview(before), e),
        has(sview(after), e),
{
}

/// `insert_reclaiming` of a key the table does not hold, with room in the
/// row and the table: nothing is given up, and the answer is `New`.
proof fn lemma_reclaim_new_with_room(before: Slab, after: Slab, e: Entry, now_ms: u64)
    requires
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        count(sview(before), e.row) < squota(before),
        sview(before).len() < scap(before),
        added(sview(after), sview(before), e),
    ensures
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        has(sview(after), e),
        only_adds(sview(after), sview(before), e),
        keeps_live(sview(after), sview(before), now_ms),
        sview(after).len() <= sview(before).len() + 1,
        sview(after).len() >= sview(before).len(),
        (count(sview(before), e.row) < squota(before) && sview(before).len() < scap(before))
            ==> added(sview(after), sview(before), e),
        count(sview(before), e.row) >= squota(before) ==> keeps_other_rows(sview(after), sview(before), e.row),
{
    let first = sview(before);
    lemma_reclaim_tables(first, first, sview(after), -1, e, now_ms);
    lemma_reclaim_more(first, first, sview(after), -1, e, e.row, squota(before), scap(before));
}

/// `insert_reclaiming`'s removal at `j` makes room for `e`: a key the table
/// did not hold is still not held, and the row and the table are below their
/// bounds. At the row's quota the entry removed is of `e`'s row.
proof fn lemma_reclaim_room(before: Slab, mid: Slab, e: Entry, j: int)
    requires
        sinv(before),
        !holds(sview(before), e.row, e.key),
        0 <= j < sview(before).len(),
        count(sview(before), e.row) >= squota(before) ==> sview(before)[j].row == e.row,
        sview(mid) == sview(before).remove(j),
        scap(mid) == scap(before),
        squota(mid) == squota(before),
    ensures
        !holds(sview(mid), e.row, e.key),
        count(sview(mid), e.row) < squota(mid),
        sview(mid).len() < scap(mid),
{
    let first = sview(before);
    lemma_count_remove(first, j, e.row);
    lemma_reclaim_not_held(first, first.remove(j), j, e.row, e.key);
}

/// `insert_reclaiming` of a key the table does not hold, at the row's quota,
/// after the expired entry of the row at `j` was removed: the answer is `New`.
proof fn lemma_reclaim_new_at_quota(before: Slab, after: Slab, e: Entry, now_ms: u64, j: int)
    requires
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        count(sview(before), e.row) >= squota(before),
        0 <= j < sview(before).len(),
        sview(before)[j].row == e.row,
        sview(before)[j].deadline_ms <= now_ms,
        added(sview(after), sview(before).remove(j), e),
    ensures
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        has(sview(after), e),
        only_adds(sview(after), sview(before), e),
        keeps_live(sview(after), sview(before), now_ms),
        sview(after).len() <= sview(before).len() + 1,
        sview(after).len() >= sview(before).len(),
        (count(sview(before), e.row) < squota(before) && sview(before).len() < scap(before))
            ==> added(sview(after), sview(before), e),
        count(sview(before), e.row) >= squota(before) ==> keeps_other_rows(sview(after), sview(before), e.row),
{
    let first = sview(before);
    let mid = first.remove(j);
    lemma_reclaim_tables(first, mid, sview(after), j, e, now_ms);
    lemma_reclaim_more(first, mid, sview(after), j, e, e.row, squota(before), scap(before));
}

/// `insert_reclaiming` of a key the table does not hold, below the row's
/// quota in a full table, after the expired entry at `j` was removed: the
/// answer is `New`.
proof fn lemma_reclaim_new_full(before: Slab, after: Slab, e: Entry, now_ms: u64, j: int)
    requires
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        count(sview(before), e.row) < squota(before),
        sview(before).len() >= scap(before),
        0 <= j < sview(before).len(),
        sview(before)[j].deadline_ms <= now_ms,
        added(sview(after), sview(before).remove(j), e),
    ensures
        sinv(after),
        scap(after) == scap(before),
        squota(after) == squota(before),
        !holds(sview(before), e.row, e.key),
        has(sview(after), e),
        only_adds(sview(after), sview(before), e),
        keeps_live(sview(after), sview(before), now_ms),
        sview(after).len() <= sview(before).len() + 1,
        sview(after).len() >= sview(before).len(),
        (count(sview(before), e.row) < squota(before) && sview(before).len() < scap(before))
            ==> added(sview(after), sview(before), e),
        count(sview(before), e.row) >= squota(before) ==> keeps_other_rows(sview(after), sview(before), e.row),
{
    let first = sview(before);
    let mid = first.remove(j);
    lemma_reclaim_tables(first, mid, sview(after), j, e, now_ms);
    lemma_reclaim_more(first, mid, sview(after), j, e, e.row, squota(before), scap(before));
}

/// The logarithm of one is zero.
proof fn lemma_log_one()
    ensures
        log(2, 1) == 0,
{
    reveal(log);
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r as int == rank_of(row, key),
))]
fn rank_exec(row: u32, key: u64) -> u128 {
    (row as u128) * 18446744073709551616 + (key as u128)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Slab {
    /// An empty table. `None` when the quota exceeds the capacity or the
    /// capacity is more than [`MAX_CAP`].
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(t) => sinv(t) && sview(t).len() == 0 && scap(t) == cap && squota(t) == quota,
                None => quota > cap || cap > MAX_CAP,
            },
    ))]
    pub fn new(cap: usize, quota: usize) -> Option<Slab> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(floored);
        }
        if quota > cap || cap > MAX_CAP {
            return None;
        }
        // Room for every slot the slab can come to hold. An insert allocates
        // only when it rewrites the slab, once no slot is left.
        let t = Slab {
            slab: Vec::with_capacity(2 * cap),
            order: Vec::with_capacity(cap),
            cap,
            quota,
            floor_ms: u64::MAX,
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(mapped(t.slab@, t.order@) =~= Seq::<Entry>::empty());
        }
        Some(t)
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == sview(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// The most entries the table holds.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == scap(*self),
    ))]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The entry the contents hold at position `i`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
            i < sview(*self).len(),
        ensures
            r == sview(*self)[i as int],
    ))]
    fn at(&self, i: usize) -> Entry {
        self.slab[self.order[i] as usize]
    }

    /// The entry the contents hold at position `i`, for a caller that reads
    /// every entry. The order is by row, then key.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
            i < sview(*self).len(),
        ensures
            r == sview(*self)[i as int],
    ))]
    pub fn nth(&self, i: usize) -> Entry {
        self.at(i)
    }

    /// The first position whose entry ranks at or above `target`: every
    /// entry before it ranks below, every entry from it on at or above.
    /// SB1: it reads at most `log2(n) + 1` entries and at least
    /// `log2(n + 1)`: `probes`, which only the verifier sees, is how many.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        with
            -> probes: Ghost<int>
        requires
            sinv(*self),
        ensures
            r <= sview(*self).len(),
            forall|i: int| 0 <= i < r ==> rank(#[trigger] sview(*self)[i]) < target,
            forall|i: int| r <= i < sview(*self).len() ==> rank(#[trigger] sview(*self)[i]) >= target,
            log(2, sview(*self).len() as int + 1) <= probes@ <= log(2, sview(*self).len() as int) + 1,
    ))]
    fn lower(&self, target: u128) -> usize {
        let mut lo: usize = 0;
        let mut hi: usize = self.order.len();
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost n: int = self.order@.len() as int;
            let ghost mut count: int = 0;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            vstd::arithmetic::logarithm::lemma_log_nonnegative(2, n);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                n == self.order@.len(),
                lo <= hi <= n,
                forall|i: int| 0 <= i < lo ==> rank(#[trigger] sview(*self)[i]) < target,
                forall|i: int| hi <= i < n ==> rank(#[trigger] sview(*self)[i]) >= target,
                0 <= count <= log(2, n) + 1,
                lo < hi ==> count + log(2, (hi - lo) as int) <= log(2, n),
                count + log(2, (hi - lo + 1) as int) >= log(2, n + 1),
            decreases hi - lo,
        ))]
        while lo < hi {
            // The range and the count as the step found them.
            #[cfg(verus_keep_ghost)]
            proof_decl! {
                let ghost lo0: int = lo as int;
                let ghost hi0: int = hi as int;
                let ghost p0: int = count;
            }
            let mid = lo + (hi - lo) / 2;
            let e = self.at(mid);
            #[cfg(verus_keep_ghost)]
            proof! {
                // One read of one entry.
                count = count + 1;
            }
            if rank_exec(e.row, e.key) < target {
                lo = mid + 1;
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_lower_go_up(sview(*self), n, lo0, hi0, mid as int, target as int, p0, lo as int, hi as int, count);
                }
            } else {
                hi = mid;
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_lower_go_down(sview(*self), n, lo0, hi0, mid as int, target as int, p0, lo as int, hi as int, count);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_log_one();
        }
        #[cfg(verus_keep_ghost)]
        proof_with! {|= Ghost(count)}
        lo
    }

    /// Where the entry for `(row, key)` is in the contents, and whether the
    /// table holds one: its place when it does, and otherwise the place a
    /// new one would take, with everything before ranking below it and
    /// everything from there on above. One search and at most one read
    /// more: `reads`, which only the verifier sees, is how many entries.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        with
            -> reads: Ghost<int>
        requires
            sinv(*self),
        ensures
            log(2, sview(*self).len() as int + 1) <= reads@ <= log(2, sview(*self).len() as int) + 2,
            r.0 < sview(*self).len() ==> reads@ >= log(2, sview(*self).len() as int + 1) + 1,
            r.0 <= sview(*self).len(),
            r.1 ==> r.0 < sview(*self).len() && sview(*self)[r.0 as int].row == row
                && sview(*self)[r.0 as int].key == key,
            !r.1 ==> !holds(sview(*self), row, key),
            forall|k: int| 0 <= k < r.0 ==> rank(#[trigger] sview(*self)[k]) < rank_of(row, key),
            !r.1 ==> forall|k: int| r.0 <= k < sview(*self).len() ==> rank(#[trigger] sview(*self)[k]) > rank_of(
                row,
                key,
            ),
    ))]
    fn place(&self, row: u32, key: u64) -> (usize, bool) {
        let target = rank_exec(row, key);
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(searched)}
        let i = self.lower(target);
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut count: int = searched;
        }
        let mut held = false;
        if i < self.order.len() {
            let e = self.at(i);
            #[cfg(verus_keep_ghost)]
            proof! {
                // One read of one entry.
                count = count + 1;
            }
            // Both fields are compared, with no branch between them.
            held = (e.row == row) & (e.key == key);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            if !held {
                let s = sview(*self);
                // Everything before `i` ranks below the target and everything
                // from it on at or above; an entry with this row and key would
                // rank exactly the target, so it could only be at `i`, and the
                // entry at `i` is not it.
                assert forall|j: int| 0 <= j < s.len() implies !(s[j].row == row && s[j].key == key) by {
                    lemma_rank_eq(s[j].row, s[j].key, row, key);
                    if j > i {
                        assert(rank(s[i as int]) < rank(s[j]));
                    }
                }
                assert forall|k: int| i <= k < s.len() implies rank(#[trigger] s[k]) > rank_of(row, key) by {
                    lemma_rank_eq(s[k].row, s[k].key, row, key);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof_with! {|= Ghost(count)}
        (i, held)
    }

    /// Where the entry for `(row, key)` is in the contents, if the table
    /// holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            match r {
                Some(i) => i < sview(*self).len() && sview(*self)[i as int].row == row
                    && sview(*self)[i as int].key == key,
                None => !holds(sview(*self), row, key),
            },
    ))]
    fn find(&self, row: u32, key: u64) -> Option<usize> {
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let (i, held) = self.place(row, key);
        if held { Some(i) } else { None }
    }

    /// The entry for `(row, key)`, if the table holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            match r {
                Some(e) => e.row == row && e.key == key && has(sview(*self), e),
                None => !holds(sview(*self), row, key),
            },
    ))]
    pub fn entry(&self, row: u32, key: u64) -> Option<Entry> {
        match self.find(row, key) {
            Some(i) => Some(self.at(i)),
            None => None,
        }
    }

    /// How many entries `row` holds.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            r == count(sview(*self), row),
    ))]
    pub fn row_count(&self, row: u32) -> usize {
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let a = self.lower(rank_exec(row, 0));
        let b = if row < u32::MAX {
            #[cfg(verus_keep_ghost)]
            proof_with! {=> Ghost(_reads)}
            self.lower(rank_exec(row + 1, 0))
        } else {
            self.order.len()
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_row_split(sview(*self), row, a as int, b as int);
        }
        b - a
    }

    /// Replaces the entry at position `i` of the contents by one of the same
    /// row and key. Nothing else changes, and nothing moves.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
            i < sview(*old(self)).len(),
            sview(*old(self))[i as int].row == entry.row,
            sview(*old(self))[i as int].key == entry.key,
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sslots(*final(self)) == sslots(*old(self)),
            sview(*final(self)) == sview(*old(self)).update(i as int, entry),
            refreshed_from(sview(*final(self)), sview(*old(self)), entry.row, entry.key),
            changed_only_to(sview(*final(self)), sview(*old(self)), entry),
            has(sview(*final(self)), entry),
    ))]
    fn set_at(&mut self, i: usize, entry: Entry) {
        if entry.deadline_ms < self.floor_ms {
            self.floor_ms = entry.deadline_ms;
        }
        let p = self.order[i] as usize;
        self.slab[p] = entry;
        #[cfg(verus_keep_ghost)]
        proof! {
            let before = sview(*old(self));
            let after = sview(*self);
            lemma_floored_steps(before, i as int, entry, old(self).floor_ms, self.floor_ms);
            lemma_floored_steps(before, i as int, entry, self.floor_ms, self.floor_ms);
            // Positions are distinct (the order is strict), so only
            // position `i` of the contents reads the slot written.
            assert(after =~= before.update(i as int, entry));
            lemma_sorted_update(before, i as int, entry);
            assert forall|r: u32| count(after, r) <= self.quota by {
                lemma_count_update(before, i as int, entry, r);
            }
            lemma_sorted_distinct(after);
            assert(after[i as int] == entry);
        }
    }

    /// Replaces the deadline and value of `(row, key)`, where it is. Returns
    /// whether the table held it; `false` changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            r == holds(sview(*old(self)), row, key),
            r ==> refreshed_from(sview(*final(self)), sview(*old(self)), row, key)
                && changed_only_to(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                && has(sview(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value }),
            !r ==> sview(*final(self)) == sview(*old(self)),
    ))]
    pub fn set(&mut self, row: u32, key: u64, deadline: Instant, value: u32) -> bool {
        let entry = Entry {
            row,
            key,
            deadline_ms: deadline.ms,
            value,
        };
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let (i, held) = self.place(row, key);
        if held {
            self.set_at(i, entry);
        }
        held
    }

    /// Rewrites the slab to hold exactly the held entries, in the order of
    /// the contents, so every slot past them is free again. The contents do
    /// not change.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)) == sview(*old(self)),
            sfloor(*final(self)) == sfloor(*old(self)),
            final(self).slab@.len() == final(self).order@.len(),
    ))]
    fn compact(&mut self) {
        let n = self.order.len();
        let mut fresh: Vec<Entry> = Vec::with_capacity(2 * self.cap);
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*old(self)),
                self.slab@ == old(self).slab@,
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                self.floor_ms == old(self).floor_ms,
                self.order@.len() == n,
                n == old(self).order@.len(),
                n <= MAX_CAP,
                i <= n,
                fresh@.len() == i,
                forall|k: int| 0 <= k < i ==> (#[trigger] fresh@[k]) == old(self).slab@[old(self).order@[k] as int],
                forall|k: int| 0 <= k < i ==> (#[trigger] self.order@[k]) == k,
                forall|k: int| i <= k < n ==> (#[trigger] self.order@[k]) == old(self).order@[k],
            decreases n - i,
        ))]
        while i < n {
            let p = self.order[i] as usize;
            fresh.push(self.slab[p]);
            self.order[i] = i as u16;
            i += 1;
        }
        self.slab = fresh;
        #[cfg(verus_keep_ghost)]
        proof! {
            // Position `k` now names slot `k`, which holds what position `k`
            // named before.
            assert(sview(*self) =~= sview(*old(self)));
        }
    }

    /// Adds an entry the table does not hold, at its place `i` in the
    /// contents, where there is room for it, rewriting the slab first when
    /// it has no slot left. The one place the table grows.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
            !holds(sview(*old(self)), entry.row, entry.key),
            count(sview(*old(self)), entry.row) < squota(*old(self)),
            sview(*old(self)).len() < scap(*old(self)),
            i <= sview(*old(self)).len(),
            forall|k: int| 0 <= k < i ==> rank(#[trigger] sview(*old(self))[k]) < rank(entry),
            forall|k: int| i <= k < sview(*old(self)).len() ==> rank(#[trigger] sview(*old(self))[k]) > rank(entry),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            added(sview(*final(self)), sview(*old(self)), entry),
            // The slab is rewritten only when it has no slot left.
            sslots(*old(self)) < 2 * scap(*old(self)) ==> sslots(*final(self)) == sslots(*old(self)) + 1,
            sslots(*old(self)) >= 2 * scap(*old(self)) ==> sslots(*final(self)) == sview(*final(self)).len(),
    ))]
    fn push_new_at(&mut self, entry: Entry, i: usize) {
        if entry.deadline_ms < self.floor_ms {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_floored_steps(sview(*self), 0, entry, self.floor_ms, entry.deadline_ms);
            }
            self.floor_ms = entry.deadline_ms;
        }
        if self.slab.len() >= 2 * self.cap {
            // The contents, and so the place, are what they were.
            self.compact();
        }
        let p = self.slab.len();
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost t0: Slab = *self;
        }
        self.slab.push(entry);
        self.order.insert(i, p as u16);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_pushed_new_at(*old(self), t0, *self, i as int, entry);
        }
    }

    /// Adds an entry the table does not hold, where there is room for it:
    /// finds its place, then [`Slab::push_new_at`].
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
            !holds(sview(*old(self)), entry.row, entry.key),
            count(sview(*old(self)), entry.row) < squota(*old(self)),
            sview(*old(self)).len() < scap(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            added(sview(*final(self)), sview(*old(self)), entry),
            sslots(*old(self)) < 2 * scap(*old(self)) ==> sslots(*final(self)) == sslots(*old(self)) + 1,
            sslots(*old(self)) >= 2 * scap(*old(self)) ==> sslots(*final(self)) == sview(*final(self)).len(),
    ))]
    fn push_new(&mut self, entry: Entry) {
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let (i, _) = self.place(entry.row, entry.key);
        self.push_new_at(entry, i);
    }

    /// Adds `(row, key)` or replaces its deadline and value. Refuses,
    /// changing nothing, when the row is at its quota or the table is full.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            match r {
                Inserted::New => {
                    &&& !holds(sview(*old(self)), row, key)
                    &&& added(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::Refreshed => {
                    &&& holds(sview(*old(self)), row, key)
                    &&& refreshed_from(sview(*final(self)), sview(*old(self)), row, key)
                    &&& changed_only_to(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& has(sview(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::RowAtQuota => {
                    &&& sview(*final(self)) == sview(*old(self))
                    &&& !holds(sview(*final(self)), row, key)
                    &&& count(sview(*final(self)), row) >= squota(*final(self))
                },
                Inserted::PoolFull => {
                    &&& sview(*final(self)) == sview(*old(self))
                    &&& !holds(sview(*final(self)), row, key)
                    &&& sview(*final(self)).len() >= scap(*final(self))
                },
            },
    ))]
    pub fn insert(&mut self, row: u32, key: u64, deadline: Instant, value: u32) -> Inserted {
        let entry = Entry {
            row,
            key,
            deadline_ms: deadline.ms,
            value,
        };
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let (i, held) = self.place(row, key);
        if held {
            self.set_at(i, entry);
            return Inserted::Refreshed;
        }
        if self.order.len() >= self.cap {
            // Both refusals may apply; the row's quota is the one reported.
            if self.row_count(row) >= self.quota {
                return Inserted::RowAtQuota;
            }
            return Inserted::PoolFull;
        }
        // Below the capacity a row can be at its quota only when the quota
        // is below the capacity, so only then is the row counted.
        if self.quota < self.cap && self.row_count(row) >= self.quota {
            return Inserted::RowAtQuota;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_count_le_len(sview(*self), row);
        }
        self.push_new_at(entry, i);
        Inserted::New
    }

    /// Removes the entry at position `i` of the contents. Its slot in the
    /// slab is no longer named and is not reused until the slab is compacted.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
            i < sview(*old(self)).len(),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)) == sview(*old(self)).remove(i as int),
    ))]
    fn remove_at(&mut self, i: usize) {
        #[cfg(verus_keep_ghost)]
        proof! {
            let before = sview(*self);
            lemma_mapped_remove(self.slab@, self.order@, i as int);
            lemma_sorted_remove(before, i as int);
            lemma_floored_steps(before, i as int, before[i as int], self.floor_ms, self.floor_ms);
            crate::pool::lemma_remove_within_caps(before, i as int, self.cap as int, self.quota as int);
            // Every position left was a position before.
            assert forall|j: int| 0 <= j < self.order@.remove(i as int).len() implies (#[trigger] self.order@.remove(
                i as int,
            )[j]) < self.slab@.len() by {
                let j0 = if j < i { j } else { j + 1 };
                assert(self.order@.remove(i as int)[j] == self.order@[j0]);
            }
        }
        let _ = self.order.remove(i);
    }

    /// Removes `(row, key)`. Returns whether the table held it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            r == holds(sview(*old(self)), row, key),
            !holds(sview(*final(self)), row, key),
            subset_of(sview(*final(self)), sview(*old(self))),
            sview(*final(self)).len() + (if r { 1int } else { 0int }) == sview(*old(self)).len(),
            keeps_others(sview(*final(self)), sview(*old(self)), row, key),
            !r ==> sview(*final(self)) == sview(*old(self)),
    ))]
    pub fn remove(&mut self, row: u32, key: u64) -> bool {
        match self.find(row, key) {
            Some(i) => {
                self.remove_at(i);
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_removed(sview(*old(self)), sview(*self), i as int, row, key);
                }
                true
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_unchanged(sview(*self), row, key);
                }
                false
            }
        }
    }

    /// Removes the entry for `(row, key)` if it has expired at `now_ms`, in
    /// place, and says whether it did.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            r == expired_held(sview(*old(self)), row, key, now.ms),
            dropped_if_expired(sview(*final(self)), sview(*old(self)), row, key, now.ms),
    ))]
    pub fn drop_expired(&mut self, row: u32, key: u64, now: Instant) -> bool {
        match self.find(row, key) {
            Some(i) => {
                if self.at(i).deadline_ms <= now.ms {
                    self.remove_at(i);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        reveal(dropped_if_expired);
                        assert(expired_at(sview(*old(self)), row, key, now.ms, i as int));
                    }
                    true
                } else {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        reveal(dropped_if_expired);
                        lemma_only_position(sview(*self), i as int);
                        assert forall|j: int| !expired_at(sview(*self), row, key, now.ms, j) by {
                        }
                    }
                    false
                }
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    reveal(dropped_if_expired);
                }
                false
            }
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Slab {
    /// The deadline of `(row, key)`, if the table holds it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            r.is_some() == holds(sview(*self), row, key),
            match r {
                Some(d) => exists|v: u32| #[trigger] has(sview(*self), Entry { row, key, deadline_ms: d, value: v }),
                None => true,
            },
    ))]
    pub fn get(&self, row: u32, key: u64) -> Option<u64> {
        match self.find(row, key) {
            Some(i) => {
                let e = self.at(i);
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(sview(*self)[i as int] == Entry { row, key, deadline_ms: e.deadline_ms, value: e.value });
                    assert(has(sview(*self), Entry { row, key, deadline_ms: e.deadline_ms, value: e.value }));
                    // The witness for the value, stated on the result as the contract states it.
                    let r: Option<u64> = Some(e.deadline_ms);
                    assert(match r {
                        Some(d) => exists|v: u32| #[trigger] has(sview(*self), Entry { row, key, deadline_ms: d, value: v }),
                        None => true,
                    });
                }
                Some(e.deadline_ms)
            }
            None => None,
        }
    }

    /// Whether the table holds `(row, key)` in an entry that has not
    /// expired. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            r == crate::flow::live(sview(*self), row, key, now.ms),
    ))]
    pub fn live(&self, row: u32, key: u64, now: Instant) -> bool {
        match self.find(row, key) {
            Some(i) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_only_position(sview(*self), i as int);
                }
                self.at(i).deadline_ms > now.ms
            }
            None => false,
        }
    }

    /// How many entries have not expired at `now_ms`. Changes nothing: for
    /// comparing a table with another, not for deciding.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            r == live_number(sview(*self), now.ms),
            r <= sview(*self).len(),
    ))]
    pub fn live_count(&self, now: Instant) -> usize {
        let mut n: usize = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                i <= self.order@.len(),
                n == live_number(sview(*self).take(i as int), now.ms),
                n <= i,
            decreases self.order@.len() - i,
        ))]
        while i < self.order.len() {
            let e = self.at(i);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_live_step(sview(*self), i as int, now.ms);
            }
            if e.deadline_ms > now.ms {
                n += 1;
            }
            i += 1;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(sview(*self).take(self.order@.len() as int) =~= sview(*self));
        }
        n
    }

    /// Whether any row holds `key` in an entry that has not expired. Reads
    /// every entry: the order is by row first.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            r == live_key(sview(*self), key, now.ms),
    ))]
    pub fn any_live(&self, key: u64, now: Instant) -> bool {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                i <= self.order@.len(),
                forall|j: int| 0 <= j < i ==> !((#[trigger] sview(*self)[j]).key == key && sview(*self)[j].deadline_ms > now.ms),
            decreases self.order@.len() - i,
        ))]
        while i < self.order.len() {
            let e = self.at(i);
            if e.key == key && e.deadline_ms > now.ms {
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(sview(*self)[i as int].key == key && sview(*self)[i as int].deadline_ms > now.ms);
                }
                return true;
            }
            i += 1;
        }
        false
    }

    /// An entry that holds `key`, under whichever row, if any does. Reads
    /// every entry until it finds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            match r {
                Some(e) => has(sview(*self), e) && e.key == key,
                None => !held_key(sview(*self), key),
            },
    ))]
    pub fn holder(&self, key: u64) -> Option<Entry> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                i <= self.order@.len(),
                forall|j: int| 0 <= j < i ==> (#[trigger] sview(*self)[j]).key != key,
            decreases self.order@.len() - i,
        ))]
        while i < self.order.len() {
            let e = self.at(i);
            if e.key == key {
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(sview(*self)[i as int] == e);
                }
                return Some(e);
            }
            i += 1;
        }
        None
    }

    /// Removes every entry. The room reserved is kept.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)).len() == 0,
    ))]
    pub fn clear(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(floored);
        }
        self.slab.clear();
        self.order.clear();
        self.floor_ms = u64::MAX;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(mapped(self.slab@, self.order@) =~= Seq::<Entry>::empty());
        }
    }

    /// Where an expired entry is, if the table holds one. While the clock is
    /// below the stored floor it reads nothing. A search of the whole table
    /// that finds nothing leaves the floor at the least deadline it saw, so
    /// the next one reads nothing until the clock reaches a deadline. The
    /// contents never change.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sslots(*final(self)) == sslots(*old(self)),
            sview(*final(self)) == sview(*old(self)),
            match r {
                Some(j) => j < sview(*old(self)).len() && sview(*old(self))[j as int].deadline_ms <= now_ms,
                None => none_expired(sview(*old(self)), now_ms)
                    && (sview(*old(self)).len() > 0 ==> sfloor(*final(self)) > now_ms),
            },
    ))]
    fn find_expired(&mut self, now_ms: u64) -> Option<usize> {
        if now_ms < self.floor_ms {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_floored_none_expired(sview(*self), self.floor_ms, now_ms);
            }
            return None;
        }
        let n = self.order.len();
        let mut low: u64 = u64::MAX;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                *self == *old(self),
                n == self.order@.len(),
                i <= n,
                forall|j: int| 0 <= j < i ==> (#[trigger] sview(*self)[j]).deadline_ms > now_ms,
                forall|j: int| 0 <= j < i ==> (#[trigger] sview(*self)[j]).deadline_ms >= low,
                i == 0 ==> low == u64::MAX,
                i > 0 ==> low > now_ms,
            decreases n - i,
        ))]
        while i < n {
            let d = self.at(i).deadline_ms;
            if d <= now_ms {
                return Some(i);
            }
            if d < low {
                low = d;
            }
            i += 1;
        }
        // Every deadline is at least the least one seen.
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(floored);
        }
        self.floor_ms = low;
        None
    }

    /// Where an expired entry of `row` is, if the table holds one. Reads the
    /// row's own entries and at most one more, after one search.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*self),
        ensures
            match r {
                Some(j) => j < sview(*self).len() && sview(*self)[j as int].row == row
                    && sview(*self)[j as int].deadline_ms <= now_ms,
                None => row_live(sview(*self), row, now_ms),
            },
    ))]
    fn find_expired_in_row(&self, row: u32, now_ms: u64) -> Option<usize> {
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let mut i = self.lower(rank_exec(row, 0));
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost a: int = i as int;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let s = sview(*self);
            assert forall|j: int| 0 <= j < s.len() implies (j < a ==> (#[trigger] s[j]).row < row) && (j >= a
                ==> s[j].row >= row) by {
                lemma_rank_row(s[j], row);
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                a <= i <= self.order@.len(),
                forall|j: int| 0 <= j < a ==> (#[trigger] sview(*self)[j]).row < row,
                forall|j: int| a <= j < self.order@.len() ==> (#[trigger] sview(*self)[j]).row >= row,
                forall|j: int| a <= j < i ==> (#[trigger] sview(*self)[j]).deadline_ms > now_ms,
            decreases self.order@.len() - i,
        ))]
        while i < self.order.len() {
            let e = self.at(i);
            if e.row != row {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let s = sview(*self);
                    // This entry is of a later row, and so is every one after it.
                    assert forall|j: int| i <= j < s.len() implies (#[trigger] s[j]).row > row by {
                        if j > i {
                            assert(rank(s[i as int]) < rank(s[j]));
                        }
                        lemma_rank_rows_ordered(s[i as int], s[j]);
                    }
                }
                return None;
            }
            if e.deadline_ms <= now_ms {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Looks the key up once and counts the row once. As [`Slab::insert`], except
    /// that where `insert` would refuse, one expired entry is removed first
    /// to make room: one of the same row when the row is at its quota, any
    /// one when the table is full. A refusal therefore means the row, or the
    /// table, is full of entries that have not expired, and it changes
    /// nothing. An entry that has not expired is never removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            match r {
                Inserted::New => {
                    &&& !holds(sview(*old(self)), row, key)
                    &&& has(sview(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& only_adds(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& keeps_live(sview(*final(self)), sview(*old(self)), now.ms)
                    &&& sview(*final(self)).len() <= sview(*old(self)).len() + 1
                    // At most one entry is given up, and only where `insert`
                    // would have refused; at the row's quota, one of the row.
                    &&& sview(*final(self)).len() >= sview(*old(self)).len()
                    &&& (count(sview(*old(self)), row) < squota(*old(self)) && sview(*old(self)).len() < scap(*old(self)))
                        ==> added(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& count(sview(*old(self)), row) >= squota(*old(self))
                        ==> keeps_other_rows(sview(*final(self)), sview(*old(self)), row)
                },
                Inserted::Refreshed => {
                    &&& holds(sview(*old(self)), row, key)
                    &&& refreshed_from(sview(*final(self)), sview(*old(self)), row, key)
                    &&& changed_only_to(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& has(sview(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::RowAtQuota => {
                    &&& sview(*final(self)) == sview(*old(self))
                    &&& !holds(sview(*final(self)), row, key)
                    &&& count(sview(*final(self)), row) >= squota(*final(self))
                    &&& row_live(sview(*final(self)), row, now.ms)
                },
                Inserted::PoolFull => {
                    &&& sview(*final(self)) == sview(*old(self))
                    &&& !holds(sview(*final(self)), row, key)
                    &&& sview(*final(self)).len() >= scap(*final(self))
                    &&& none_expired(sview(*final(self)), now.ms)
                },
            },
    ))]
    pub fn insert_reclaiming(
        &mut self,
        row: u32,
        key: u64,
        deadline: Instant,
        value: u32,
        now: Instant,
    ) -> Inserted {
        let entry = Entry {
            row,
            key,
            deadline_ms: deadline.ms,
            value,
        };
        #[cfg(verus_keep_ghost)]
        proof_with! {=> Ghost(_reads)}
        let (i, held) = self.place(row, key);
        if held {
            self.set_at(i, entry);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_reclaim_refreshed(*old(self), *self, entry, i as int);
            }
            return Inserted::Refreshed;
        }
        // The contents at entry, and where the removed entry was in them, or
        // -1 when nothing is removed.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
            let ghost mut gone: int = -1;
        }
        let at_quota = self.row_count(row) >= self.quota;
        if !at_quota && self.order.len() < self.cap {
            // There is room: nothing is given up, and the place is known.
            self.push_new_at(entry, i);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_reclaim_new_with_room(*old(self), *self, entry, now.ms);
            }
            return Inserted::New;
        }
        if at_quota {
            match self.find_expired_in_row(row, now.ms) {
                Some(j) => {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        gone = j as int;
                    }
                    self.remove_at(j);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_reclaim_room(*old(self), *self, entry, j as int);
                    }
                }
                None => return Inserted::RowAtQuota,
            }
        } else {
            match self.find_expired(now.ms) {
                Some(j) => {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        gone = j as int;
                    }
                    self.remove_at(j);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_reclaim_room(*old(self), *self, entry, j as int);
                    }
                }
                None => return Inserted::PoolFull,
            }
        }
        // The contents between the removal, if there was one, and the insert.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mid: Seq<Entry> = sview(*self);
        }
        self.push_new(entry);
        #[cfg(verus_keep_ghost)]
        proof! {
            if at_quota {
                lemma_reclaim_new_at_quota(*old(self), *self, entry, now.ms, gone);
            } else {
                lemma_reclaim_new_full(*old(self), *self, entry, now.ms, gone);
            }
        }
        Inserted::New
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Slab {
    /// Removes entries whose deadline is at or before `now_ms`, at most
    /// `budget` of them, and returns how many it removed. Entries that have
    /// not expired are never removed. When the budget is less than the
    /// number expired, which of them go is not promised; this body takes the
    /// first in order of row and key. One pass, and this body writes nothing
    /// when it finds nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            r <= budget,
            sview(*final(self)).len() + r == sview(*old(self)).len(),
            subset_of(sview(*final(self)), sview(*old(self))),
            keeps_live(sview(*final(self)), sview(*old(self)), now.ms),
            r < budget ==> none_expired(sview(*final(self)), now.ms),
            r == 0 ==> sview(*final(self)) == sview(*old(self)),
            r > 0 ==> !none_expired(sview(*old(self)), now.ms),
    ))]
    pub fn expire(&mut self, now: Instant, budget: usize) -> usize {
        let n = self.order.len();
        if budget == 0 {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_self_kept(sview(*self), now.ms, 0, 0, 0);
            }
            return 0;
        }
        if now.ms < self.floor_ms {
            // Nothing has expired, and nothing is read to know it.
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_self_kept(sview(*self), now.ms, 0, 0, 0);
                lemma_floored_none_expired(sview(*self), self.floor_ms, now.ms);
            }
            return 0;
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_self_kept(first, now.ms, 0, 0, 0);
        }
        // Up to the first entry to remove, read and write nothing.
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                n == self.order@.len(),
                i <= n,
                forall|j: int| 0 <= j < i ==> (#[trigger] sview(*self)[j]).deadline_ms > now.ms,
            ensures
                i < n ==> sview(*self)[i as int].deadline_ms <= now.ms,
            decreases n - i,
        ))]
        while i < n {
            let e = self.at(i);
            if e.deadline_ms <= now.ms {
                break;
            }
            i += 1;
        }
        if i == n {
            return 0;
        }
        // From there, one pass: every position is written at the next kept
        // place, and that place moves on only when its entry stays. `g` is
        // the contents had each entry removed gone when it was met.
        let mut w: usize = i;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = first;
            let ghost i0: int = i as int;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_start(self.slab@, self.order@, i as int);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.slab@ == old(self).slab@,
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                self.floor_ms == old(self).floor_ms,
                self.cap <= MAX_CAP,
                self.slab@.len() <= 2 * self.cap,
                n == self.order@.len(),
                w <= i <= n,
                i0 < n,
                sweeping(self.slab@, self.order@, g, w as int, i as int),
                sorted(g),
                within_caps(g, self.cap as int, self.quota as int),
                subset_of(g, first),
                keeps_live(g, first, now.ms),
                budget > 0,
                i - w <= budget,
                i0 <= i,
                i == i0 || w < i,
                i == i0 ==> w == i && g[w as int].deadline_ms <= now.ms,
                i - w < budget ==> forall|j: int| 0 <= j < w ==> (#[trigger] g[j]).deadline_ms > now.ms,
                w < i ==> !none_expired(first, now.ms),
            decreases n - i,
        ))]
        while i < n {
            #[cfg(verus_keep_ghost)]
            proof_decl! {
                let ghost o0: Seq<u16> = self.order@;
                let ghost w0: int = w as int;
                let ghost i1: int = i as int;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_sweep_read(self.slab@, o0, g, w0, i1);
            }
            let p = self.order[i];
            let e = self.slab[p as usize];
            self.order[w] = p;
            // The kept place moves on by the test's value, with no branch:
            // each term is 0 or 1, and so is their `|`.
            let live = (e.deadline_ms > now.ms) as usize;
            let spent = (i - w >= budget) as usize;
            let k = live | spent;
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_or_01(live, spent);
            }
            w += k;
            i += 1;
            #[cfg(verus_keep_ghost)]
            proof! {
                let keep = k == 1;
                if keep {
                    lemma_sweep_keep(self.slab@, o0, self.order@, g, w0, i1, w as int, i as int);
                } else {
                    lemma_remove_within_caps(g, w0, self.cap as int, self.quota as int);
                    lemma_sorted_remove(g, w0);
                    lemma_remove_subset(g, first, w0);
                    lemma_remove_keeps_live(g, first, w0, now.ms);
                    // The entry removed was an entry at entry, and it has expired.
                    lemma_subset_member(g, first, w0);
                    lemma_sweep_drop(self.slab@, o0, self.order@, g, w0, i1, i as int);
                    g = g.remove(w0);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_end(self.slab@, self.order@, g, w as int);
        }
        self.order.truncate(w);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(sview(*self) == g);
            lemma_sorted_distinct(g);
            lemma_floored_subset(g, first, self.floor_ms);
        }
        n - w
    }

    /// Removes every entry of `row` whose deadline is at or before `now_ms`
    /// and returns how many. No entry of another row is removed, and none
    /// that has not expired.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)).len() + r == sview(*old(self)).len(),
            subset_of(sview(*final(self)), sview(*old(self))),
            keeps_live(sview(*final(self)), sview(*old(self)), now.ms),
            keeps_other_rows(sview(*final(self)), sview(*old(self)), row),
            row_live(sview(*final(self)), row, now.ms),
    ))]
    pub fn release_expired(&mut self, row: u32, now: Instant) -> usize {
        let n = self.order.len();
        if now.ms < self.floor_ms {
            // Nothing has expired, and nothing is read to know it.
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_self_kept(sview(*self), now.ms, row, 0, 0);
                lemma_floored_none_expired(sview(*self), self.floor_ms, now.ms);
            }
            return 0;
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_self_kept(first, now.ms, row, 0, 0);
        }
        // Up to the first entry to remove, read and write nothing.
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                n == self.order@.len(),
                i <= n,
                forall|j: int| 0 <= j < i && (#[trigger] sview(*self)[j]).row == row ==> sview(*self)[j].deadline_ms > now.ms,
            decreases n - i,
        ))]
        while i < n {
            let e = self.at(i);
            if e.row == row && e.deadline_ms <= now.ms {
                break;
            }
            i += 1;
        }
        if i == n {
            return 0;
        }
        // From there, one pass: every position is written at the next kept
        // place, and that place moves on only when its entry stays. `g` is
        // the contents had each entry removed gone when it was met.
        let mut w: usize = i;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = first;
            let ghost i0: int = i as int;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_start(self.slab@, self.order@, i as int);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.slab@ == old(self).slab@,
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                self.floor_ms == old(self).floor_ms,
                self.cap <= MAX_CAP,
                self.slab@.len() <= 2 * self.cap,
                n == self.order@.len(),
                w <= i <= n,
                i0 < n,
                sweeping(self.slab@, self.order@, g, w as int, i as int),
                sorted(g),
                within_caps(g, self.cap as int, self.quota as int),
                subset_of(g, first),
                keeps_live(g, first, now.ms),
                keeps_other_rows(g, first, row),
                forall|j: int| 0 <= j < w && (#[trigger] g[j]).row == row ==> g[j].deadline_ms > now.ms,
            decreases n - i,
        ))]
        while i < n {
            #[cfg(verus_keep_ghost)]
            proof_decl! {
                let ghost o0: Seq<u16> = self.order@;
                let ghost w0: int = w as int;
                let ghost i1: int = i as int;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_sweep_read(self.slab@, o0, g, w0, i1);
            }
            let p = self.order[i];
            let e = self.slab[p as usize];
            self.order[w] = p;
            // The kept place moves on by the test's value, with no branch:
            // each term is 0 or 1, and so is their `|`.
            let other = (e.row != row) as usize;
            let live = (e.deadline_ms > now.ms) as usize;
            let k = other | live;
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_or_01(other, live);
            }
            w += k;
            i += 1;
            #[cfg(verus_keep_ghost)]
            proof! {
                let keep = k == 1;
                if keep {
                    lemma_sweep_keep(self.slab@, o0, self.order@, g, w0, i1, w as int, i as int);
                } else {
                    lemma_remove_within_caps(g, w0, self.cap as int, self.quota as int);
                    lemma_sorted_remove(g, w0);
                    lemma_remove_subset(g, first, w0);
                    lemma_remove_keeps_live(g, first, w0, now.ms);
                    lemma_remove_keeps_other_rows(g, first, w0, row);
                    lemma_sweep_drop(self.slab@, o0, self.order@, g, w0, i1, i as int);
                    g = g.remove(w0);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_end(self.slab@, self.order@, g, w as int);
        }
        self.order.truncate(w);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(sview(*self) == g);
            lemma_sorted_distinct(g);
            lemma_floored_subset(g, first, self.floor_ms);
        }
        n - w
    }

    /// Removes every entry, of any row and expired or not, whose key has
    /// `hi` above bit 32 and `lo` in its low 16 bits, and returns how many.
    /// No other entry is removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)).len() + r == sview(*old(self)).len(),
            subset_of(sview(*final(self)), sview(*old(self))),
            keeps_unmatched(sview(*final(self)), sview(*old(self)), hi, lo),
            none_ending(sview(*final(self)), hi, lo),
    ))]
    pub fn remove_ends(&mut self, hi: u64, lo: u64) -> usize {
        let n = self.order.len();
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_self_kept(first, 0, 0, hi, lo);
        }
        // Up to the first entry to remove, read and write nothing.
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                n == self.order@.len(),
                i <= n,
                forall|j: int| 0 <= j < i ==> !key_ends((#[trigger] sview(*self)[j]).key, hi, lo),
            decreases n - i,
        ))]
        while i < n {
            let e = self.at(i);
            if e.key / 4294967296 == hi && e.key % 65536 == lo {
                break;
            }
            i += 1;
        }
        if i == n {
            return 0;
        }
        // From there, one pass: every position is written at the next kept
        // place, and that place moves on only when its entry stays. `g` is
        // the contents had each entry removed gone when it was met.
        let mut w: usize = i;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = first;
            let ghost i0: int = i as int;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_start(self.slab@, self.order@, i as int);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.slab@ == old(self).slab@,
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                self.floor_ms == old(self).floor_ms,
                self.cap <= MAX_CAP,
                self.slab@.len() <= 2 * self.cap,
                n == self.order@.len(),
                w <= i <= n,
                i0 < n,
                sweeping(self.slab@, self.order@, g, w as int, i as int),
                sorted(g),
                within_caps(g, self.cap as int, self.quota as int),
                subset_of(g, first),
                keeps_unmatched(g, first, hi, lo),
                forall|j: int| 0 <= j < w ==> !key_ends((#[trigger] g[j]).key, hi, lo),
            decreases n - i,
        ))]
        while i < n {
            #[cfg(verus_keep_ghost)]
            proof_decl! {
                let ghost o0: Seq<u16> = self.order@;
                let ghost w0: int = w as int;
                let ghost i1: int = i as int;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_sweep_read(self.slab@, o0, g, w0, i1);
            }
            let p = self.order[i];
            let e = self.slab[p as usize];
            self.order[w] = p;
            // The kept place moves on by the test's value, with no branch:
            // each term is 0 or 1, and so is their `|`.
            let high = (e.key / 4294967296 != hi) as usize;
            let low = (e.key % 65536 != lo) as usize;
            let k = high | low;
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_or_01(high, low);
            }
            w += k;
            i += 1;
            #[cfg(verus_keep_ghost)]
            proof! {
                let keep = k == 1;
                if keep {
                    lemma_sweep_keep(self.slab@, o0, self.order@, g, w0, i1, w as int, i as int);
                } else {
                    lemma_remove_within_caps(g, w0, self.cap as int, self.quota as int);
                    lemma_sorted_remove(g, w0);
                    lemma_remove_subset(g, first, w0);
                    lemma_remove_keeps_unmatched(g, first, w0, hi, lo);
                    lemma_sweep_drop(self.slab@, o0, self.order@, g, w0, i1, i as int);
                    g = g.remove(w0);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_end(self.slab@, self.order@, g, w as int);
        }
        self.order.truncate(w);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(sview(*self) == g);
            lemma_sorted_distinct(g);
            lemma_floored_subset(g, first, self.floor_ms);
        }
        n - w
    }

    /// Removes every entry, of any row and expired or not, whose value is
    /// `value`, and returns how many. No other entry is removed, and a
    /// table that holds none is left as it was. Reads every entry once.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            sview(*final(self)).len() + r == sview(*old(self)).len(),
            subset_of(sview(*final(self)), sview(*old(self))),
            keeps_unvalued(sview(*final(self)), sview(*old(self)), value),
            none_valued(sview(*final(self)), value),
            r == 0 ==> sview(*final(self)) == sview(*old(self)),
            r > 0 ==> !none_valued(sview(*old(self)), value),
    ))]
    pub fn remove_valued(&mut self, value: u32) -> usize {
        let n = self.order.len();
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_self_kept(first, 0, 0, 0, 0);
            assert(keeps_unvalued(first, first, value));
        }
        // Up to the first entry to remove, read and write nothing.
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(*self),
                n == self.order@.len(),
                i <= n,
                forall|j: int| 0 <= j < i ==> (#[trigger] sview(*self)[j]).value != value,
                // The table is not written in this loop.
                sview(*self) == first,
            ensures
                // Where the loop stopped early, the entry there has the value.
                i < n ==> first[i as int].value == value,
                i <= n,
                forall|j: int| 0 <= j < i ==> (#[trigger] first[j]).value != value,
            decreases n - i,
        ))]
        while i < n {
            let e = self.at(i);
            if e.value == value {
                break;
            }
            i += 1;
        }
        if i == n {
            return 0;
        }
        // From there, one pass: every position is written at the next kept
        // place, and that place moves on only when its entry stays. `g` is
        // the contents had each entry removed gone when it was met.
        let mut w: usize = i;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = first;
            let ghost i0: int = i as int;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_start(self.slab@, self.order@, i as int);
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.slab@ == old(self).slab@,
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                self.floor_ms == old(self).floor_ms,
                self.cap <= MAX_CAP,
                self.slab@.len() <= 2 * self.cap,
                n == self.order@.len(),
                w <= i <= n,
                i0 < n,
                i0 <= i,
                i == i0 ==> w == i0 && g == first && first[i0].value == value,
                i > i0 ==> w < i,
                // The entry where the pass began has the value.
                first[i0].value == value,
                sweeping(self.slab@, self.order@, g, w as int, i as int),
                sorted(g),
                within_caps(g, self.cap as int, self.quota as int),
                subset_of(g, first),
                keeps_unvalued(g, first, value),
                forall|j: int| 0 <= j < w ==> (#[trigger] g[j]).value != value,
            decreases n - i,
        ))]
        while i < n {
            #[cfg(verus_keep_ghost)]
            proof_decl! {
                let ghost o0: Seq<u16> = self.order@;
                let ghost w0: int = w as int;
                let ghost i1: int = i as int;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_sweep_read(self.slab@, o0, g, w0, i1);
            }
            let p = self.order[i];
            let e = self.slab[p as usize];
            self.order[w] = p;
            // The kept place moves on by the test's value, with no branch.
            let k = (e.value != value) as usize;
            w += k;
            i += 1;
            #[cfg(verus_keep_ghost)]
            proof! {
                let keep = k == 1;
                if keep {
                    lemma_sweep_keep(self.slab@, o0, self.order@, g, w0, i1, w as int, i as int);
                } else {
                    lemma_remove_within_caps(g, w0, self.cap as int, self.quota as int);
                    lemma_sorted_remove(g, w0);
                    lemma_remove_subset(g, first, w0);
                    lemma_remove_keeps_unvalued(g, first, w0, value);
                    lemma_sweep_drop(self.slab@, o0, self.order@, g, w0, i1, i as int);
                    g = g.remove(w0);
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_sweep_end(self.slab@, self.order@, g, w as int);
        }
        self.order.truncate(w);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(sview(*self) == g);
            lemma_sorted_distinct(g);
            lemma_floored_subset(g, first, self.floor_ms);
        }
        n - w
    }

    /// Adds an entry for a key the table does not hold, in a table with no
    /// quota below its capacity. At the capacity it first removes every
    /// expired entry, unless a sweep ran less than the interval ago. Returns
    /// what it did and the throttle to keep.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sinv(*old(self)),
            squota(*old(self)) == scap(*old(self)),
            !holds(sview(*old(self)), row, key),
        ensures
            sinv(*final(self)),
            scap(*final(self)) == scap(*old(self)),
            squota(*final(self)) == squota(*old(self)),
            r.1.interval_ms == th.interval_ms,
            (r.0 == Swept::New) == (sview(*old(self)).len() < scap(*old(self))),
            (r.0 == Swept::Throttled) == (sview(*old(self)).len() >= scap(*old(self)) && !due(th, now.ms)),
            (r.0 == Swept::Full) == (sview(*old(self)).len() >= scap(*old(self)) && due(th, now.ms)
                && none_expired(sview(*old(self)), now.ms)),
            r.1.last_ms == (if r.0 == Swept::SweptNew || r.0 == Swept::Full { Some(now.ms) } else { th.last_ms }),
            r.0 == Swept::New ==> added(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value }),
            r.0 == Swept::SweptNew ==> swept_and_added(sview(*final(self)), sview(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value }, now.ms),
            r.0 == Swept::Full || r.0 == Swept::Throttled ==> sview(*final(self)) == sview(*old(self)),
    ))]
    pub fn insert_sweeping(
        &mut self,
        th: Throttle,
        row: u32,
        key: u64,
        deadline: Instant,
        value: u32,
        now: Instant,
    ) -> (Swept, Throttle) {
        let entry = Entry {
            row,
            key,
            deadline_ms: deadline.ms,
            value,
        };
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost first: Seq<Entry> = sview(*self);
        }
        if self.order.len() < self.cap {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_count_le_len(first, row);
            }
            self.push_new(entry);
            return (Swept::New, th);
        }
        if !th.due(now) {
            return (Swept::Throttled, th);
        }
        let stamped = Throttle {
            interval_ms: th.interval_ms,
            last_ms: Some(now.ms),
        };
        let n = self.order.len();
        let removed = self.expire(now, n);
        if removed == 0 {
            return (Swept::Full, stamped);
        }
        // The contents between the sweep and the insert.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mid: Seq<Entry> = sview(*self);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            // Either the budget was not reached, or every entry went.
            assert(none_expired(mid, now.ms));
            lemma_subset_not_held(first, mid, row, key);
            lemma_count_le_len(mid, row);
        }
        self.push_new(entry);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_swept_added(first, mid, sview(*self), entry, now.ms);
        }
        (Swept::SweptNew, stamped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(row: u32, key: u64, deadline_ms: u64, value: u32) -> Entry {
        Entry {
            row,
            key,
            deadline_ms,
            value,
        }
    }

    fn contents(t: &Slab) -> Vec<Entry> {
        (0..t.len()).map(|i| t.at(i)).collect()
    }

    #[test]
    fn entries_are_held_in_order_of_row_then_key_whatever_order_they_arrive_in() {
        let mut t = Slab::new(8, 8).unwrap();
        assert_eq!(t.insert(3, 1, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 9, Instant { ms: 20 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 5, Instant { ms: 30 }, 0), Inserted::New);
        assert_eq!(t.insert(2, u64::MAX, Instant { ms: 40 }, 0), Inserted::New);
        assert_eq!(
            contents(&t),
            vec![
                e(1, 5, 30, 0),
                e(1, 9, 20, 0),
                e(2, u64::MAX, 40, 0),
                e(3, 1, 10, 0)
            ]
        );
        assert_eq!(t.entry(1, 9), Some(e(1, 9, 20, 0)));
        assert_eq!(t.entry(1, 6), None);
        assert_eq!(t.entry(0, 0), None);
        assert_eq!(t.entry(4, 0), None);
    }

    #[test]
    fn a_held_key_is_replaced_where_it_is_and_nothing_else_moves() {
        let mut t = Slab::new(4, 4).unwrap();
        assert_eq!(t.insert(1, 5, Instant { ms: 30 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 9, Instant { ms: 20 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 5, Instant { ms: 99 }, 7), Inserted::Refreshed);
        assert!(t.set(1, 9, Instant { ms: 50 }, 3));
        assert!(!t.set(1, 8, Instant { ms: 50 }, 3));
        assert_eq!(contents(&t), vec![e(1, 5, 99, 7), e(1, 9, 50, 3)]);
    }

    #[test]
    fn a_row_stops_at_its_quota_and_the_table_at_its_capacity() {
        let mut t = Slab::new(3, 2).unwrap();
        assert_eq!(t.insert(1, 1, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 2, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 3, Instant { ms: 0 }, 0), Inserted::RowAtQuota);
        assert_eq!(t.insert(2, 1, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(t.insert(3, 1, Instant { ms: 0 }, 0), Inserted::PoolFull);
        assert_eq!(t.insert(1, 2, Instant { ms: 5 }, 0), Inserted::Refreshed);
        assert_eq!(t.len(), 3);
        assert_eq!(t.row_count(1), 2);
        assert_eq!(t.row_count(9), 0);
    }

    #[test]
    fn removing_leaves_the_rest_in_order_and_the_slot_unused() {
        let mut t = Slab::new(4, 4).unwrap();
        assert_eq!(t.insert(1, 9, Instant { ms: 20 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 5, Instant { ms: 30 }, 0), Inserted::New);
        assert_eq!(t.insert(2, 1, Instant { ms: 40 }, 0), Inserted::New);
        assert!(t.remove(1, 9));
        assert!(!t.remove(1, 9));
        assert!(!t.remove(3, 1));
        assert_eq!(contents(&t), vec![e(1, 5, 30, 0), e(2, 1, 40, 0)]);
        assert_eq!(t.len(), 2);
        // The slab still has the removed entry's slot.
        assert_eq!(t.slab.len(), 3);
        // The key can come back, and is found again.
        assert_eq!(t.insert(1, 9, Instant { ms: 50 }, 7), Inserted::New);
        assert_eq!(t.entry(1, 9), Some(e(1, 9, 50, 7)));
        assert_eq!(
            contents(&t),
            vec![e(1, 5, 30, 0), e(1, 9, 50, 7), e(2, 1, 40, 0)]
        );
    }

    #[test]
    fn dropping_takes_an_expired_entry_and_leaves_a_live_one() {
        let mut t = Slab::new(4, 4).unwrap();
        assert_eq!(t.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 8, Instant { ms: 100 }, 0), Inserted::New);
        assert!(!t.drop_expired(1, 7, Instant { ms: 99 }));
        assert!(!t.drop_expired(1, 9, Instant { ms: 500 }));
        assert!(t.drop_expired(1, 7, Instant { ms: 100 }));
        assert_eq!(contents(&t), vec![e(1, 8, 100, 0)]);
    }

    #[test]
    fn a_capacity_no_position_can_serve_is_refused() {
        assert!(Slab::new(MAX_CAP, MAX_CAP).is_some());
        assert!(Slab::new(MAX_CAP + 1, 1).is_none());
        assert!(Slab::new(4, 5).is_none());
    }

    #[test]
    fn the_search_finds_the_first_entry_at_or_above_a_rank() {
        let mut t = Slab::new(8, 8).unwrap();
        for (row, key) in [(1u32, 5u64), (1, 9), (3, 0), (3, u64::MAX)] {
            assert_eq!(t.insert(row, key, Instant { ms: 0 }, 0), Inserted::New);
        }
        assert_eq!(t.lower(rank_exec(0, 0)), 0);
        assert_eq!(t.lower(rank_exec(1, 5)), 0);
        assert_eq!(t.lower(rank_exec(1, 6)), 1);
        assert_eq!(t.lower(rank_exec(2, 0)), 2);
        assert_eq!(t.lower(rank_exec(3, u64::MAX)), 3);
        assert_eq!(t.lower(rank_exec(4, 0)), 4);
    }

    #[test]
    fn a_slab_full_of_unused_slots_is_rewritten_by_the_next_insert_that_adds() {
        let mut t = Slab::new(3, 3).unwrap();
        assert_eq!(t.insert(3, 1, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 5, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(t.insert(2, 2, Instant { ms: 10 }, 0), Inserted::New);
        assert!(t.remove(1, 5));
        for key in 6..9u64 {
            assert_eq!(t.insert(1, key, Instant { ms: 10 }, 0), Inserted::New);
            assert!(t.remove(1, key));
        }
        assert_eq!(t.slab.len(), 6);
        assert_eq!(t.insert(0, 0, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(t.slab.len(), 3);
        assert_eq!(
            contents(&t),
            vec![e(0, 0, 10, 0), e(2, 2, 10, 0), e(3, 1, 10, 0)]
        );
    }

    #[test]
    fn the_slab_never_passes_twice_the_capacity_however_long_the_churn() {
        let mut t = Slab::new(4, 4).unwrap();
        for round in 0..50u64 {
            for key in 0..4u64 {
                assert_eq!(
                    t.insert(1, round * 4 + key, Instant { ms: round }, 0),
                    Inserted::New
                );
                assert!(t.slab.len() <= 8);
            }
            assert_eq!(
                t.insert(1, 1_000_000, Instant { ms: round }, 0),
                Inserted::RowAtQuota
            );
            for key in 0..4u64 {
                assert!(t.remove(1, round * 4 + key));
            }
        }
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn a_row_is_counted_between_its_neighbours_and_the_last_row_too() {
        let mut t = Slab::new(8, 8).unwrap();
        for (row, key) in [
            (0, 0),
            (0, u64::MAX),
            (5, 0),
            (5, 7),
            (5, u64::MAX),
            (u32::MAX, 0),
            (u32::MAX, u64::MAX),
        ] {
            assert_eq!(t.insert(row, key, Instant { ms: 10 }, 0), Inserted::New);
        }
        assert_eq!(t.row_count(0), 2);
        assert_eq!(t.row_count(4), 0);
        assert_eq!(t.row_count(5), 3);
        assert_eq!(t.row_count(6), 0);
        assert_eq!(t.row_count(u32::MAX), 2);
    }

    #[test]
    fn a_full_row_takes_a_new_entry_in_place_of_an_expired_one_of_that_row() {
        let mut t = Slab::new(8, 2).unwrap();
        assert_eq!(t.insert(1, 1, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 2, Instant { ms: 50 }, 0), Inserted::New);
        assert_eq!(t.insert(2, 1, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(
            t.insert_reclaiming(1, 3, Instant { ms: 90 }, 0, Instant { ms: 9 }),
            Inserted::RowAtQuota
        );
        assert_eq!(
            t.insert_reclaiming(1, 3, Instant { ms: 90 }, 0, Instant { ms: 10 }),
            Inserted::New
        );
        assert_eq!(
            contents(&t),
            vec![e(1, 2, 50, 0), e(1, 3, 90, 0), e(2, 1, 5, 0)]
        );
    }

    #[test]
    fn a_full_table_takes_a_new_entry_in_place_of_an_expired_one_of_any_row() {
        let mut t = Slab::new(2, 2).unwrap();
        assert_eq!(t.insert(1, 1, Instant { ms: 50 }, 0), Inserted::New);
        assert_eq!(t.insert(2, 1, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(
            t.insert_reclaiming(3, 1, Instant { ms: 90 }, 0, Instant { ms: 9 }),
            Inserted::PoolFull
        );
        assert_eq!(
            t.insert_reclaiming(3, 1, Instant { ms: 90 }, 0, Instant { ms: 10 }),
            Inserted::New
        );
        assert_eq!(contents(&t), vec![e(1, 1, 50, 0), e(3, 1, 90, 0)]);
        assert_eq!(
            t.insert_reclaiming(1, 1, Instant { ms: 60 }, 4, Instant { ms: 10 }),
            Inserted::Refreshed
        );
        assert_eq!(t.get(1, 1), Some(60));
    }

    #[test]
    fn the_readers_see_the_contents_and_nothing_else() {
        let mut t = Slab::new(8, 8).unwrap();
        assert_eq!(t.insert(2, 7, Instant { ms: 10 }, 1), Inserted::New);
        assert_eq!(t.insert(1, 9, Instant { ms: 20 }, 2), Inserted::New);
        assert_eq!(t.insert(3, 7, Instant { ms: 30 }, 3), Inserted::New);
        assert!(t.remove(2, 7));
        assert_eq!(t.get(2, 7), None);
        assert_eq!(t.get(1, 9), Some(20));
        assert!(t.live(1, 9, Instant { ms: 19 }));
        assert!(!t.live(1, 9, Instant { ms: 20 }));
        assert!(!t.live(2, 7, Instant { ms: 0 }));
        assert_eq!(t.live_count(Instant { ms: 19 }), 2);
        assert_eq!(t.live_count(Instant { ms: 20 }), 1);
        assert_eq!(t.live_count(Instant { ms: 30 }), 0);
        assert!(t.any_live(7, Instant { ms: 29 }));
        assert!(!t.any_live(7, Instant { ms: 30 }));
        assert_eq!(t.holder(7), Some(e(3, 7, 30, 3)));
        assert_eq!(t.holder(8), None);
        t.clear();
        assert_eq!(t.len(), 0);
        assert_eq!(t.insert(2, 7, Instant { ms: 10 }, 1), Inserted::New);
        assert_eq!(contents(&t), vec![e(2, 7, 10, 1)]);
    }

    #[test]
    fn expiry_removes_only_expired_entries_keeps_the_order_and_stops_at_its_budget() {
        let mut t = Slab::new(8, 8).unwrap();
        for (row, key, deadline) in [
            (3, 1, 5),
            (1, 9, 50),
            (2, 2, 5),
            (1, 4, 5),
            (2, 8, 60),
            (4, 0, 5),
        ] {
            assert_eq!(
                t.insert(row, key, Instant { ms: deadline }, 0),
                Inserted::New
            );
        }
        assert_eq!(t.expire(Instant { ms: 4 }, 8), 0);
        assert_eq!(t.len(), 6);
        assert_eq!(t.expire(Instant { ms: 5 }, 0), 0);
        // The first two expired in order of row and key go; the rest stay.
        assert_eq!(t.expire(Instant { ms: 5 }, 2), 2);
        assert_eq!(
            contents(&t),
            vec![e(1, 9, 50, 0), e(2, 8, 60, 0), e(3, 1, 5, 0), e(4, 0, 5, 0)]
        );
        assert_eq!(t.expire(Instant { ms: 5 }, 8), 2);
        assert_eq!(contents(&t), vec![e(1, 9, 50, 0), e(2, 8, 60, 0)]);
        assert_eq!(t.entry(2, 8), Some(e(2, 8, 60, 0)));
        assert_eq!(t.expire(Instant { ms: 60 }, 8), 2);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn releasing_takes_one_rows_expired_entries_and_removing_by_ends_takes_every_row() {
        let mut t = Slab::new(8, 8).unwrap();
        let key = |hi: u64, mid: u64, lo: u64| hi * 4294967296 + mid * 65536 + lo;
        assert_eq!(
            t.insert(1, key(7, 1, 80), Instant { ms: 5 }, 0),
            Inserted::New
        );
        assert_eq!(
            t.insert(1, key(7, 2, 81), Instant { ms: 50 }, 0),
            Inserted::New
        );
        assert_eq!(
            t.insert(2, key(7, 3, 80), Instant { ms: 5 }, 0),
            Inserted::New
        );
        assert_eq!(
            t.insert(2, key(8, 4, 80), Instant { ms: 50 }, 0),
            Inserted::New
        );
        assert_eq!(t.release_expired(3, Instant { ms: 10 }), 0);
        assert_eq!(t.release_expired(1, Instant { ms: 10 }), 1);
        assert_eq!(t.len(), 3);
        assert_eq!(t.get(2, key(7, 3, 80)), Some(5));
        assert_eq!(t.remove_ends(7, 82), 0);
        assert_eq!(t.remove_ends(7, 80), 1);
        assert_eq!(
            contents(&t),
            vec![e(1, key(7, 2, 81), 50, 0), e(2, key(8, 4, 80), 50, 0)]
        );
    }

    #[test]
    fn removing_by_value_takes_every_entry_with_it_of_every_row_and_no_other() {
        let mut t = Slab::new(8, 8).unwrap();
        assert_eq!(t.insert(1, 10, Instant { ms: 5 }, 6), Inserted::New);
        assert_eq!(t.insert(1, 11, Instant { ms: 50 }, 2), Inserted::New);
        assert_eq!(t.insert(2, 10, Instant { ms: 50 }, 6), Inserted::New);
        assert_eq!(t.insert(3, 12, Instant { ms: 50 }, 0), Inserted::New);
        assert_eq!(t.insert(4, 13, Instant { ms: 50 }, 6), Inserted::New);
        assert_eq!(t.remove_valued(7), 0);
        assert_eq!(t.len(), 5);
        assert_eq!(t.remove_valued(6), 3);
        assert_eq!(contents(&t), vec![e(1, 11, 50, 2), e(3, 12, 50, 0)]);
        assert_eq!(t.remove_valued(6), 0);
        assert_eq!(t.insert(2, 10, Instant { ms: 60 }, 0), Inserted::New);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn at_the_capacity_a_due_sweep_makes_room_and_a_throttled_one_changes_nothing() {
        let mut t = Slab::new(3, 3).unwrap();
        let th = Throttle {
            interval_ms: 100,
            last_ms: None,
        };
        let (did, th) = t.insert_sweeping(th, 1, 1, Instant { ms: 10 }, 0, Instant { ms: 0 });
        assert_eq!((did, th.last_ms), (Swept::New, None));
        assert_eq!(t.insert(1, 2, Instant { ms: 500 }, 0), Inserted::New);
        assert_eq!(t.insert(2, 1, Instant { ms: 10 }, 0), Inserted::New);
        let (did, th) = t.insert_sweeping(th, 3, 1, Instant { ms: 900 }, 0, Instant { ms: 9 });
        assert_eq!((did, th.last_ms), (Swept::Full, Some(9)));
        let (did, th) = t.insert_sweeping(th, 3, 1, Instant { ms: 900 }, 0, Instant { ms: 20 });
        assert_eq!((did, th.last_ms), (Swept::Throttled, Some(9)));
        assert_eq!(t.len(), 3);
        let (did, th) = t.insert_sweeping(th, 3, 1, Instant { ms: 900 }, 0, Instant { ms: 109 });
        assert_eq!((did, th.last_ms), (Swept::SweptNew, Some(109)));
        assert_eq!(contents(&t), vec![e(1, 2, 500, 0), e(3, 1, 900, 0)]);
    }

    #[test]
    fn the_floor_follows_the_least_deadline_down_and_a_fruitless_search_raises_it() {
        let mut t = Slab::new(3, 3).unwrap();
        assert_eq!(t.floor_ms, u64::MAX);
        assert_eq!(t.insert(1, 1, Instant { ms: 50 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 2, Instant { ms: 30 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 3, Instant { ms: 40 }, 0), Inserted::New);
        assert_eq!(t.floor_ms, 30);
        // Removing the earliest leaves the floor where it was: still a bound.
        assert!(t.remove(1, 2));
        assert_eq!(t.floor_ms, 30);
        assert_eq!(t.insert(1, 4, Instant { ms: 90 }, 0), Inserted::New);
        // Full, the clock past the floor, nothing expired: the search reads
        // the table once and leaves the floor at the least deadline held.
        assert_eq!(
            t.insert_reclaiming(2, 1, Instant { ms: 99 }, 0, Instant { ms: 35 }),
            Inserted::PoolFull
        );
        assert_eq!(t.floor_ms, 40);
        // Below the floor nothing is read and nothing changes.
        assert_eq!(
            t.insert_reclaiming(2, 1, Instant { ms: 99 }, 0, Instant { ms: 39 }),
            Inserted::PoolFull
        );
        assert_eq!(t.expire(Instant { ms: 39 }, 8), 0);
        assert_eq!(t.release_expired(1, Instant { ms: 39 }), 0);
        assert_eq!(t.len(), 3);
        // At the floor the earliest has expired and makes room.
        assert_eq!(
            t.insert_reclaiming(2, 1, Instant { ms: 99 }, 0, Instant { ms: 40 }),
            Inserted::New
        );
        assert_eq!(
            contents(&t),
            vec![e(1, 1, 50, 0), e(1, 4, 90, 0), e(2, 1, 99, 0)]
        );
        t.clear();
        assert_eq!(t.floor_ms, u64::MAX);
    }
    // The largest table the constructor allows, driven until its slab holds
    // twice the capacity, so positions reach 65,533, two below the top of
    // the index's type; then once more, so it compacts. No bounded check
    // reaches these positions.
    #[test]
    fn the_largest_table_uses_the_top_positions_and_compacts() {
        let cap = MAX_CAP;
        let Some(mut t) = Slab::new(cap, cap) else {
            panic!("the largest capacity is refused");
        };
        assert!(Slab::new(cap + 1, cap + 1).is_none());
        let mut k = 0;
        while k < cap {
            assert_eq!(
                t.insert(1, k as u64, Instant { ms: 10 + k as u64 }, 7),
                Inserted::New
            );
            k += 1;
        }
        assert_eq!(
            t.insert(1, cap as u64, Instant { ms: 10 }, 7),
            Inserted::RowAtQuota
        );
        assert_eq!(t.insert(9, 0, Instant { ms: 10 }, 7), Inserted::PoolFull);
        // Each turn frees a place and takes the next unused slot.
        let mut k = 0;
        while k < cap {
            assert!(t.remove(1, k as u64));
            assert_eq!(
                t.insert(2, k as u64, Instant { ms: 20 + k as u64 }, 9),
                Inserted::New
            );
            k += 1;
        }
        assert_eq!(t.slab.len(), 2 * cap);
        assert_eq!(t.order.iter().copied().max(), Some((2 * cap - 1) as u16));
        assert_eq!(t.len(), cap);
        assert_eq!(t.get(1, 0), None);
        assert_eq!(t.get(2, 0), Some(20));
        assert_eq!(t.get(2, (cap - 1) as u64), Some(20 + (cap - 1) as u64));
        assert_eq!(t.row_count(2), cap);
        // No slot is left: the next new entry rewrites the slab.
        assert!(t.remove(2, 0));
        assert_eq!(t.insert(3, 5, Instant { ms: 30 }, 1), Inserted::New);
        assert_eq!(t.slab.len(), cap);
        assert_eq!(t.len(), cap);
        assert_eq!(t.get(3, 5), Some(30));
        assert_eq!(t.get(2, 1), Some(21));
        assert_eq!(t.get(2, (cap - 1) as u64), Some(20 + (cap - 1) as u64));
        assert_eq!(t.row_count(2), cap - 1);
    }

    // Which expired entry goes first is by row and then key, wherever it
    // arrived: for the one given up to make room, and for a sweep of one.
    #[test]
    fn expired_entries_go_in_order_of_row_and_key() {
        let Some(mut t) = Slab::new(3, 3) else {
            panic!("refused");
        };
        assert_eq!(t.insert(2, 1, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 9, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(t.insert(1, 3, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(
            t.insert_reclaiming(7, 7, Instant { ms: 99 }, 0, Instant { ms: 10 }),
            Inserted::New
        );
        assert_eq!(t.get(1, 3), None);
        assert_eq!(t.get(1, 9), Some(5));
        assert_eq!(t.get(2, 1), Some(5));
        assert_eq!(t.expire(Instant { ms: 10 }, 1), 1);
        assert_eq!(t.get(1, 9), None);
        assert_eq!(t.get(2, 1), Some(5));
        assert_eq!(t.get(7, 7), Some(99));
    }
}

#[cfg(kani)]
impl Slab {
    /// The contents, in order.
    pub(crate) fn kani_contents(&self) -> Vec<Entry> {
        // Room by the capacity, a number the checker knows for a table of a
        // given shape, and not by the number of entries, which it may not.
        let mut out = Vec::with_capacity(self.cap);
        let mut i = 0;
        while i < self.order.len() {
            out.push(self.slab[self.order[i] as usize]);
            i += 1;
        }
        out
    }

    /// The entry at place `i` of the contents, read through the index.
    pub(crate) fn kani_at(&self, i: usize) -> Entry {
        self.slab[self.order[i] as usize]
    }

    /// The invariant read from the fields with plain loops and no
    /// allocation: the limits; every position inside the slab; the contents
    /// strictly increasing by row and then key; no row over the quota; no
    /// deadline below the floor. In contents in order of row, a row holds
    /// more than the quota exactly when some entry has the row of the entry
    /// `quota` places after it.
    pub(crate) fn kani_holds(&self) -> bool {
        let n = self.order.len();
        if self.quota > self.cap
            || self.cap > MAX_CAP
            || n > self.cap
            || self.slab.len() > 2 * self.cap
        {
            return false;
        }
        let mut i = 0;
        while i < n {
            if self.order[i] as usize >= self.slab.len() {
                return false;
            }
            i += 1;
        }
        let mut i = 0;
        while i < n {
            let a = self.kani_at(i);
            if a.deadline_ms < self.floor_ms {
                return false;
            }
            if i + 1 < n {
                let b = self.kani_at(i + 1);
                if !(a.row < b.row || (a.row == b.row && a.key < b.key)) {
                    return false;
                }
            }
            if i + self.quota < n && self.kani_at(i + self.quota).row == a.row {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The limits `kani_holds` requires.
    pub(crate) fn kani_limits_hold(&self) -> bool {
        self.quota <= self.cap
            && self.cap <= MAX_CAP
            && self.order.len() <= self.cap
            && self.slab.len() <= 2 * self.cap
    }

    /// Place `i` of the index names a slot of the slab. `i` is below the
    /// number of entries.
    pub(crate) fn kani_in_range_at(&self, i: usize) -> bool {
        (self.order[i] as usize) < self.slab.len()
    }

    /// The entry at place `i` comes before the next, if there is one, by row
    /// and then key. `i` is below the number of entries.
    pub(crate) fn kani_sorted_at(&self, i: usize) -> bool {
        if i + 1 < self.order.len() {
            let (a, b) = (self.kani_at(i), self.kani_at(i + 1));
            a.row < b.row || (a.row == b.row && a.key < b.key)
        } else {
            true
        }
    }

    /// The entry `quota` places after place `i`, if there is one, is of
    /// another row. `i` is below the number of entries.
    pub(crate) fn kani_quota_at(&self, i: usize) -> bool {
        let n = self.order.len();
        !(self.quota <= n
            && i < n - self.quota
            && self.kani_at(i + self.quota).row == self.kani_at(i).row)
    }

    /// The entry at place `i` is not below the floor. `i` is below the
    /// number of entries.
    pub(crate) fn kani_floor_at(&self, i: usize) -> bool {
        self.kani_at(i).deadline_ms >= self.floor_ms
    }

    /// The capacity and the quota.
    pub(crate) fn kani_limits(&self) -> (usize, usize) {
        (self.cap, self.quota)
    }

    /// Costly, and kept only until the harnesses of `notes`, `flow` and
    /// `pins` draw their tables by shape: the lengths here are numbers the
    /// checker does not know.
    /// Any table of up to `max` entries that satisfies the invariant: any
    /// capacity and quota up to `max`, a slab of any length up to twice the
    /// capacity with any entries in any order, used or not, and any index
    /// into it. Built with room, so no operation reallocates.
    pub(crate) fn kani_any(max: usize) -> Slab {
        let cap: usize = kani::any();
        let quota: usize = kani::any();
        kani::assume(cap <= max && quota <= cap);
        let m: usize = kani::any();
        kani::assume(m <= 2 * cap);
        let mut slab = Vec::with_capacity(2 * max + 1);
        let mut i = 0;
        while i < m {
            slab.push(Entry {
                row: kani::any(),
                key: kani::any(),
                deadline_ms: kani::any(),
                value: kani::any(),
            });
            i += 1;
        }
        let n: usize = kani::any();
        kani::assume(n <= cap && n <= m);
        let mut order: Vec<u16> = Vec::with_capacity(max + 1);
        let mut i = 0;
        while i < n {
            order.push(kani::any());
            i += 1;
        }
        let t = Slab {
            slab,
            order,
            cap,
            quota,
            floor_ms: kani::any(),
        };
        kani::assume(t.kani_holds());
        t
    }

    /// Any table of capacity `cap` with `m` slab slots and `n` entries that
    /// satisfies the invariant: any quota, any entries in any order of the
    /// slab, used or not, any floor. The three lengths are plain numbers, so
    /// every allocation and loop of the operation under check starts from a
    /// length the checker knows. Built with the room `new` reserves.
    pub(crate) fn kani_shaped(cap: usize, m: usize, n: usize) -> Slab {
        assert!(m <= 2 * cap && n <= cap && n <= m);
        let quota: usize = kani::any();
        kani::assume(quota <= cap);
        let mut slab = Vec::with_capacity(2 * cap);
        let mut i = 0;
        while i < m {
            slab.push(Entry {
                row: kani::any(),
                key: kani::any(),
                deadline_ms: kani::any(),
                value: kani::any(),
            });
            i += 1;
        }
        let mut order: Vec<u16> = Vec::with_capacity(cap);
        let mut i = 0;
        while i < n {
            order.push(kani::any());
            i += 1;
        }
        let t = Slab {
            slab,
            order,
            cap,
            quota,
            floor_ms: kani::any(),
        };
        kani::assume(t.kani_holds());
        t
    }
}

#[cfg(kani)]
mod proofs {
    //! Bounded checks of the compiled code against a second reading of what
    //! each operation does, written with plain scans of the contents.
    //!
    //! As for `Pool`: one operation, from an arbitrary table that satisfies
    //! the invariant, with arbitrary arguments. An arbitrary table here has
    //! unused slots and positions in any order of the slab. What the table
    //! holds afterwards is read by row and key through arbitrary indices,
    //! never by building the expected table.
    //!
    //! Every table of up to `MAX` entries is covered, one shape to a
    //! harness: a shape is a capacity, a slab length and a number of
    //! entries, as plain numbers, and there are forty of them. Each check
    //! is a function of a table and has a module of its own with one
    //! harness for each shape, named `c<capacity>_<slots>_<entries>`, and a
    //! harness `reached` that says which cases the largest shapes reach.
    //! The contents before and after are kept in arrays.
    //! The two inserts that give entries up have their check whole at some
    //! shapes and in eight parts, a harness each, at the others.

    use super::*;
    use crate::pool::{kani_count_row, kani_lookup};

    const NONE: Entry = Entry {
        row: 0,
        key: 0,
        deadline_ms: 0,
        value: 0,
    };

    /// The contents in an array, and how many there are.
    fn snapshot(t: &Slab) -> ([Entry; MAX], usize) {
        let mut out = [NONE; MAX];
        let mut i = 0;
        while i < t.order.len() {
            out[i] = t.kani_at(i);
            i += 1;
        }
        (out, t.order.len())
    }

    /// One harness of `$check` for each shape of a table of up to `MAX`
    /// entries.
    macro_rules! every_shape {
        ($check:path) => {
            shape!($check, c0_0_0, 0, 0, 0);
            shape!($check, c1_0_0, 1, 0, 0);
            shape!($check, c1_1_0, 1, 1, 0);
            shape!($check, c1_1_1, 1, 1, 1);
            shape!($check, c1_2_0, 1, 2, 0);
            shape!($check, c1_2_1, 1, 2, 1);
            shape!($check, c2_0_0, 2, 0, 0);
            shape!($check, c2_1_0, 2, 1, 0);
            shape!($check, c2_1_1, 2, 1, 1);
            shape!($check, c2_2_0, 2, 2, 0);
            shape!($check, c2_2_1, 2, 2, 1);
            shape!($check, c2_2_2, 2, 2, 2);
            shape!($check, c2_3_0, 2, 3, 0);
            shape!($check, c2_3_1, 2, 3, 1);
            shape!($check, c2_3_2, 2, 3, 2);
            shape!($check, c2_4_0, 2, 4, 0);
            shape!($check, c2_4_1, 2, 4, 1);
            shape!($check, c2_4_2, 2, 4, 2);
            shape!($check, c3_0_0, 3, 0, 0);
            shape!($check, c3_1_0, 3, 1, 0);
            shape!($check, c3_1_1, 3, 1, 1);
            shape!($check, c3_2_0, 3, 2, 0);
            shape!($check, c3_2_1, 3, 2, 1);
            shape!($check, c3_2_2, 3, 2, 2);
            shape!($check, c3_3_0, 3, 3, 0);
            shape!($check, c3_3_1, 3, 3, 1);
            shape!($check, c3_3_2, 3, 3, 2);
            shape!($check, c3_3_3, 3, 3, 3);
            shape!($check, c3_4_0, 3, 4, 0);
            shape!($check, c3_4_1, 3, 4, 1);
            shape!($check, c3_4_2, 3, 4, 2);
            shape!($check, c3_4_3, 3, 4, 3);
            shape!($check, c3_5_0, 3, 5, 0);
            shape!($check, c3_5_1, 3, 5, 1);
            shape!($check, c3_5_2, 3, 5, 2);
            shape!($check, c3_5_3, 3, 5, 3);
            shape!($check, c3_6_0, 3, 6, 0);
            shape!($check, c3_6_1, 3, 6, 1);
            shape!($check, c3_6_2, 3, 6, 2);
            shape!($check, c3_6_3, 3, 6, 3);
        };
    }

    macro_rules! shape {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(Slab::kani_shaped($cap, $m, $n));
            }
        };
    }

    const MAX: usize = 3;

    fn entry(row: u32, key: u64, deadline_ms: u64, value: u32) -> Entry {
        Entry {
            row,
            key,
            deadline_ms,
            value,
        }
    }

    /// An arbitrary entry of `before`, other than the one for `(row, key)`,
    /// is still held as it was.
    fn another_is_kept(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let w: usize = kani::any();
        if w < before.len() && !(before[w].row == row && before[w].key == key) {
            assert!(kani_lookup(now, before[w].row, before[w].key) == Some(before[w]));
        }
    }

    /// The contents are what they were: the same length, and the same entry
    /// at one arbitrary place. Two tables are not compared whole.
    fn unchanged(before: &[Entry], now: &[Entry]) {
        assert!(now.len() == before.len());
        let u: usize = kani::any();
        if u < before.len() {
            assert!(now[u] == before[u]);
        }
    }

    /// An arbitrary entry of `now`, other than the one for `(row, key)`, was
    /// held before as it is.
    fn nothing_else_is_new(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let v: usize = kani::any();
        if v < now.len() && !(now[v].row == row && now[v].key == key) {
            assert!(kani_lookup(before, now[v].row, now[v].key) == Some(now[v]));
        }
    }

    /// The search against a scan: the place returned has below it exactly
    /// the entries that come before `(row, key)`. Returns the place and the
    /// number of entries.
    fn lower_from(t: Slab) -> (usize, usize) {
        let (s, len) = snapshot(&t);
        let s = &s[..len];
        let (row, key): (u32, u64) = (kani::any(), kani::any());
        let r = t.lower(rank_exec(row, key));
        assert!(r <= s.len());
        let w: usize = kani::any();
        if w < s.len() {
            let below = s[w].row < row || (s[w].row == row && s[w].key < key);
            assert!(below == (w < r));
        }
        (r, s.len())
    }

    /// The readers against scans. Returns whether the row and key were held,
    /// whether the key was held under any row, whether it was live under
    /// any, the row's count and the number of entries.
    fn readers_from(t: Slab) -> (bool, bool, bool, usize, usize) {
        let (s, len) = snapshot(&t);
        let s = &s[..len];
        let (row, key, now): (u32, u64, u64) = (kani::any(), kani::any(), kani::any());
        let held = kani_lookup(s, row, key);
        assert!(t.len() == s.len());
        assert!(t.entry(row, key) == held);
        assert!(t.get(row, key) == held.map(|e| e.deadline_ms));
        assert!(
            t.live(row, key, Instant { ms: now }) == matches!(held, Some(e) if e.deadline_ms > now)
        );
        let in_row = kani_count_row(s, row);
        assert!(t.row_count(row) == in_row);
        let (mut by_key, mut live_by_key, mut live) = (false, false, 0usize);
        let mut i = 0;
        while i < s.len() {
            if s[i].key == key {
                by_key = true;
                if s[i].deadline_ms > now {
                    live_by_key = true;
                }
            }
            if s[i].deadline_ms > now {
                live += 1;
            }
            i += 1;
        }
        assert!(t.any_live(key, Instant { ms: now }) == live_by_key);
        assert!(t.live_count(Instant { ms: now }) == live);
        match t.holder(key) {
            Some(e) => assert!(e.key == key && kani_lookup(s, e.row, e.key) == Some(e)),
            None => assert!(!by_key),
        }
        (held.is_some(), by_key, live_by_key, in_row, s.len())
    }

    /// One `insert` from a table, the insert that compacts among them.
    /// Returns the result, whether the slab had no unused slot, the number
    /// of entries before, and the capacity.
    fn insert_from(mut t: Slab) -> (Inserted, bool, usize, usize) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let (row, key, deadline, value): (u32, u64, u64, u32) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let was = kani_lookup(before, row, key);
        let count = kani_count_row(before, row);
        let slab_was_full = t.slab.len() == 2 * t.cap;
        let r = t.insert(row, key, Instant { ms: deadline }, value);
        assert!(t.kani_holds());
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        match r {
            Inserted::Refreshed => {
                assert!(was.is_some());
                assert!(after.len() == before.len());
                assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
            }
            Inserted::New => {
                assert!(was.is_none() && count < t.quota && before.len() < t.cap);
                assert!(after.len() == before.len() + 1);
                assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
            }
            Inserted::RowAtQuota => {
                assert!(was.is_none() && count >= t.quota);
                unchanged(before, after);
            }
            Inserted::PoolFull => {
                assert!(was.is_none() && count < t.quota && before.len() >= t.cap);
                unchanged(before, after);
            }
        }
        another_is_kept(before, after, row, key);
        nothing_else_is_new(before, after, row, key);
        (r, slab_was_full, before.len(), t.cap)
    }

    /// One `remove` from a table. Returns whether an entry went and the
    /// number of entries before.
    fn remove_from(mut t: Slab) -> (bool, usize) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let (row, key): (u32, u64) = (kani::any(), kani::any());
        let was = kani_lookup(before, row, key);
        let r = t.remove(row, key);
        assert!(t.kani_holds());
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        assert!(r == was.is_some());
        assert!(kani_lookup(after, row, key).is_none());
        assert!(after.len() + (r as usize) == before.len());
        another_is_kept(before, after, row, key);
        (r, before.len())
    }

    /// One `expire` from a table, with any instant and budget: the first
    /// expired entries in order go, up to the budget, and nothing else.
    /// Returns how many went, how many had expired, the number of entries
    /// before, whether the budget was above zero, and whether the first
    /// entry had not expired.
    fn expire_from(mut t: Slab) -> (usize, usize, usize, bool, bool) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let (now, budget): (u64, usize) = (kani::any(), kani::any());
        let mut expired: usize = 0;
        let mut c = 0;
        while c < before.len() {
            if before[c].deadline_ms <= now {
                expired += 1;
            }
            c += 1;
        }
        let gone = t.expire(Instant { ms: now }, budget);
        assert!(t.kani_holds());
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        assert!(gone == if expired < budget { expired } else { budget });
        assert!(after.len() + gone == before.len());
        let w: usize = kani::any();
        if w < before.len() {
            let kept = kani_lookup(after, before[w].row, before[w].key);
            if before[w].deadline_ms > now {
                assert!(kept == Some(before[w]));
            } else {
                // An expired entry goes exactly when fewer than the budget
                // of expired entries come before it.
                let mut ahead: usize = 0;
                let mut j = 0;
                while j < w {
                    if before[j].deadline_ms <= now {
                        ahead += 1;
                    }
                    j += 1;
                }
                assert!(kept.is_none() == (ahead < budget));
            }
        }
        let v: usize = kani::any();
        if v < after.len() {
            assert!(kani_lookup(before, after[v].row, after[v].key) == Some(after[v]));
        }
        let first_live = before.len() > 0 && before[0].deadline_ms > now;
        (gone, expired, before.len(), budget > 0, first_live)
    }

    /// One `release_expired` or one `remove_ends` from a table. Returns
    /// which it was, how many went and the number of entries before.
    fn release_or_ends_from(mut t: Slab) -> (bool, usize, usize) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let by_row: bool = kani::any();
        let (row, now, hi, lo): (u32, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let mut matched: usize = 0;
        let mut c = 0;
        while c < before.len() {
            let goes = if by_row {
                before[c].row == row && before[c].deadline_ms <= now
            } else {
                (before[c].key >> 32) == hi && (before[c].key & 0xffff) == lo
            };
            if goes {
                matched += 1;
            }
            c += 1;
        }
        let gone = if by_row {
            t.release_expired(row, Instant { ms: now })
        } else {
            t.remove_ends(hi, lo)
        };
        assert!(t.kani_holds());
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        assert!(gone == matched);
        assert!(after.len() + gone == before.len());
        let w: usize = kani::any();
        if w < before.len() {
            let kept = kani_lookup(after, before[w].row, before[w].key);
            let goes = if by_row {
                before[w].row == row && before[w].deadline_ms <= now
            } else {
                (before[w].key >> 32) == hi && (before[w].key & 0xffff) == lo
            };
            if goes {
                assert!(kept.is_none());
            } else {
                assert!(kept == Some(before[w]));
            }
        }
        let v: usize = kani::any();
        if v < after.len() {
            assert!(kani_lookup(before, after[v].row, after[v].key) == Some(after[v]));
        }
        (by_row, gone, before.len())
    }

    /// One `remove_valued` from a table. Returns how many went and the
    /// number of entries before.
    fn valued_from(mut t: Slab) -> (usize, usize) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let value: u32 = kani::any();
        let mut matched: usize = 0;
        let mut c = 0;
        while c < before.len() {
            if before[c].value == value {
                matched += 1;
            }
            c += 1;
        }
        let gone = t.remove_valued(value);
        assert!(t.kani_holds());
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        assert!(gone == matched);
        assert!(after.len() + gone == before.len());
        let w: usize = kani::any();
        if w < before.len() {
            let kept = kani_lookup(after, before[w].row, before[w].key);
            if before[w].value == value {
                assert!(kept.is_none());
            } else {
                assert!(kept == Some(before[w]));
            }
        }
        let v: usize = kani::any();
        if v < after.len() {
            assert!(kani_lookup(before, after[v].row, after[v].key) == Some(after[v]));
        }
        (gone, before.len())
    }

    // The checks of the two inserts that give entries up are divided where
    // the operation can remove and then add in a way a single harness does
    // not finish reading back: where the table is full, and for the
    // reclaiming insert also where the slab is at twice the capacity and
    // holds an entry (a row at its quota gives one up whatever room the
    // table has). Each part reads little; together they assert what the
    // whole check asserts.
    const WHOLE: u8 = 0;
    const RESULT: u8 = 1;
    const KEPT: u8 = 2;
    const NOTHING_NEW: u8 = 3;
    const LIMITS: u8 = 4;
    const IN_RANGE: u8 = 5;
    const SORTED: u8 = 6;
    const QUOTA: u8 = 7;
    const FLOOR: u8 = 8;

    /// One conjunct of the invariant, at one arbitrary place: what
    /// `kani_holds` says of every place.
    fn holds_at(t: &Slab, part: u8) {
        let n = t.order.len();
        let i: usize = kani::any();
        kani::assume(i < n || n == 0);
        if part == LIMITS {
            assert!(
                t.quota <= t.cap && t.cap <= MAX_CAP && n <= t.cap && t.slab.len() <= 2 * t.cap
            );
        } else if part == IN_RANGE {
            if i < n {
                assert!((t.order[i] as usize) < t.slab.len());
            }
        } else if part == SORTED {
            if i < n && i + 1 < n {
                let (a, b) = (t.kani_at(i), t.kani_at(i + 1));
                assert!(a.row < b.row || (a.row == b.row && a.key < b.key));
            }
        } else if part == QUOTA {
            if i < n && t.quota <= n && i < n - t.quota {
                assert!(t.kani_at(i + t.quota).row != t.kani_at(i).row);
            }
        } else if i < n {
            assert!(t.kani_at(i).deadline_ms >= t.floor_ms);
        }
    }

    /// One `insert_reclaiming` from a table, asserting `part` of its check.
    /// Returns the result, whether the row was at its quota, whether any
    /// entry had expired, the number of entries before, and the capacity.
    fn insert_reclaiming_from(mut t: Slab, part: u8) -> (Inserted, bool, bool, usize, usize) {
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let (row, key, deadline, value, now): (u32, u64, u64, u32, u64) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        let was = kani_lookup(before, row, key);
        let count = kani_count_row(before, row);
        let (mut any_expired, mut row_expired) = (false, false);
        let mut c = 0;
        while c < before.len() {
            if before[c].deadline_ms <= now {
                any_expired = true;
                if before[c].row == row {
                    row_expired = true;
                }
            }
            c += 1;
        }
        let r = t.insert_reclaiming(
            row,
            key,
            Instant { ms: deadline },
            value,
            Instant { ms: now },
        );
        let facts = (r, count >= t.quota, any_expired, before.len(), t.cap);
        if part >= LIMITS {
            holds_at(&t, part);
            return facts;
        }
        if part == WHOLE {
            assert!(t.kani_holds());
        }
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        if part == WHOLE || part == RESULT {
            match r {
                Inserted::Refreshed => {
                    assert!(was.is_some());
                    assert!(after.len() == before.len());
                    assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
                }
                Inserted::New => {
                    assert!(was.is_none());
                    assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
                    if count >= t.quota {
                        // One expired entry of the row made room.
                        assert!(row_expired && after.len() == before.len());
                    } else if before.len() >= t.cap {
                        // One expired entry of any row made room.
                        assert!(any_expired && after.len() == before.len());
                    } else {
                        assert!(after.len() == before.len() + 1);
                    }
                }
                Inserted::RowAtQuota => {
                    assert!(was.is_none() && count >= t.quota && !row_expired);
                }
                Inserted::PoolFull => {
                    assert!(
                        was.is_none() && count < t.quota && before.len() >= t.cap && !any_expired
                    );
                }
            }
        }
        if part == WHOLE || part == KEPT {
            match r {
                Inserted::Refreshed => another_is_kept(before, after, row, key),
                Inserted::New => {
                    // An entry that has not expired is never given up.
                    let w: usize = kani::any();
                    if w < before.len() && before[w].deadline_ms > now {
                        assert!(
                            kani_lookup(after, before[w].row, before[w].key) == Some(before[w])
                        );
                    }
                }
                Inserted::RowAtQuota | Inserted::PoolFull => {}
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            match r {
                Inserted::RowAtQuota | Inserted::PoolFull => unchanged(before, after),
                Inserted::Refreshed | Inserted::New => {}
            }
            nothing_else_is_new(before, after, row, key);
        }
        facts
    }

    /// One `insert_sweeping` from a table with no quota below its capacity,
    /// asserting `part` of its check. Returns the result, whether any entry
    /// had expired, and the numbers of entries before and after.
    fn insert_sweeping_from(mut t: Slab, part: u8) -> (Swept, bool, usize, usize) {
        kani::assume(t.quota == t.cap);
        let (before, len) = snapshot(&t);
        let before = &before[..len];
        let (row, key, deadline, value, now): (u32, u64, u64, u32, u64) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        kani::assume(kani_lookup(before, row, key).is_none());
        let th = Throttle {
            interval_ms: kani::any(),
            last_ms: kani::any(),
        };
        let may_sweep = match th.last_ms {
            None => true,
            Some(last) => {
                if now < last {
                    th.interval_ms == 0
                } else {
                    (now as u128) >= (last as u128) + (th.interval_ms as u128)
                }
            }
        };
        let mut live_before: usize = 0;
        let mut c = 0;
        while c < before.len() {
            if before[c].deadline_ms > now {
                live_before += 1;
            }
            c += 1;
        }
        let any_expired = live_before < before.len();
        let (r, after_th) = t.insert_sweeping(
            th,
            row,
            key,
            Instant { ms: deadline },
            value,
            Instant { ms: now },
        );
        let facts = (r, any_expired, before.len(), t.order.len());
        if part >= LIMITS {
            holds_at(&t, part);
            return facts;
        }
        if part == WHOLE {
            assert!(t.kani_holds());
        }
        let (after, len) = snapshot(&t);
        let after = &after[..len];
        if part == WHOLE || part == RESULT {
            assert!(after_th.interval_ms == th.interval_ms);
            if before.len() < t.cap {
                assert!(r == Swept::New && after_th == th);
                assert!(after.len() == before.len() + 1);
                assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
            } else if !may_sweep {
                assert!(r == Swept::Throttled && after_th == th);
            } else if !any_expired {
                assert!(r == Swept::Full && after_th.last_ms == Some(now));
            } else {
                assert!(r == Swept::SweptNew && after_th.last_ms == Some(now));
                // Exactly the entries that had not expired, and the new one.
                assert!(after.len() == live_before + 1);
                assert!(kani_lookup(after, row, key) == Some(entry(row, key, deadline, value)));
            }
        }
        if part == WHOLE || part == KEPT {
            if before.len() < t.cap {
                another_is_kept(before, after, row, key);
            } else if may_sweep && any_expired {
                let w: usize = kani::any();
                if w < before.len() {
                    let kept = kani_lookup(after, before[w].row, before[w].key);
                    if before[w].deadline_ms > now {
                        assert!(kept == Some(before[w]));
                    } else {
                        assert!(kept.is_none());
                    }
                }
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            if before.len() >= t.cap && (!may_sweep || !any_expired) {
                unchanged(before, after);
            }
            nothing_else_is_new(before, after, row, key);
        }
        facts
    }

    /// Positions need not follow the slab's order.
    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_slab_positions_out_of_order() {
        let t = Slab::kani_shaped(MAX, 2 * MAX, MAX);
        kani::cover!(t.order[0] > t.order[1]);
        kani::cover!(t.order[0] < t.order[1]);
    }

    mod lower {
        use super::*;

        every_shape!(lower_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, n) = lower_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(r == 0 && n == MAX);
            kani::cover!(r == MAX);
            kani::cover!(r == 1 && n == MAX);
        }
    }

    mod readers {
        use super::*;

        every_shape!(readers_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (held, by_key, live_by_key, in_row, n) =
                readers_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(held && n == MAX);
            kani::cover!(by_key && !live_by_key);
            kani::cover!(in_row == MAX);
        }
    }

    #[cfg(feature = "kani-full")]
    mod insert_step {
        use super::*;

        every_shape!(insert_from);

        // One shape to a harness: three in one was four times the size.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, slab_was_full, n, cap) = insert_from(Slab::kani_shaped(MAX, 2 * MAX, MAX - 1));
            kani::cover!(r == Inserted::New && slab_was_full && n == MAX - 1);
            kani::cover!(r == Inserted::Refreshed);
            kani::cover!(r == Inserted::RowAtQuota && n < cap);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_with_a_slot_left() {
            let (r, slab_was_full, _, _) =
                insert_from(Slab::kani_shaped(MAX, 2 * MAX - 1, MAX - 1));
            kani::cover!(r == Inserted::New && !slab_was_full);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, _, _, cap) = insert_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(r == Inserted::PoolFull && cap == MAX);
        }
    }

    #[cfg(feature = "kani-full")]
    mod remove_step {
        use super::*;

        every_shape!(remove_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, n) = remove_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(r && n == MAX);
            kani::cover!(!r && n == MAX);
        }
    }

    #[cfg(feature = "kani-full")]
    mod expire_step {
        use super::*;

        every_shape!(expire_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (gone, expired, n, budgeted, first_live) =
                expire_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(gone == 0 && n == MAX && budgeted);
            kani::cover!(gone == MAX);
            kani::cover!(gone == 1 && expired == MAX);
            kani::cover!(gone == 1 && n == MAX && first_live);
        }
    }

    #[cfg(feature = "kani-full")]
    mod release_and_ends_step {
        use super::*;

        every_shape!(release_or_ends_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (by_row, gone, n) = release_or_ends_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(by_row && gone == MAX);
            kani::cover!(by_row && gone == 1 && n == MAX);
            kani::cover!(!by_row && gone == MAX);
            kani::cover!(!by_row && gone == 0 && n == MAX);
        }
    }

    #[cfg(feature = "kani-full")]
    mod valued_step {
        use super::*;

        every_shape!(valued_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (gone, n) = valued_from(Slab::kani_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(gone == MAX);
            kani::cover!(gone == 1 && n == MAX);
            kani::cover!(gone == 0 && n == MAX);
        }
    }

    macro_rules! shape_part {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(Slab::kani_shaped($cap, $m, $n), $part);
            }
        };
    }

    #[cfg(feature = "kani-full")]
    mod insert_reclaiming_step {
        use super::*;

        // The whole check, where the operation cannot both give an entry up
        // and rewrite the slab.
        shape_part!(insert_reclaiming_from, c1_0_0, 1, 0, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c1_1_0, 1, 1, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c1_2_0, 1, 2, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c2_0_0, 2, 0, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c2_1_0, 2, 1, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c2_1_1, 2, 1, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c2_2_0, 2, 2, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c2_2_1, 2, 2, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c2_3_0, 2, 3, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c2_3_1, 2, 3, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c2_4_0, 2, 4, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_0_0, 3, 0, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_1_0, 3, 1, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_1_1, 3, 1, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c3_2_0, 3, 2, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_2_1, 3, 2, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c3_2_2, 3, 2, 2, WHOLE);
        shape_part!(insert_reclaiming_from, c3_3_0, 3, 3, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_3_1, 3, 3, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c3_3_2, 3, 3, 2, WHOLE);
        shape_part!(insert_reclaiming_from, c3_4_0, 3, 4, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_4_1, 3, 4, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c3_4_2, 3, 4, 2, WHOLE);
        shape_part!(insert_reclaiming_from, c3_5_0, 3, 5, 0, WHOLE);
        shape_part!(insert_reclaiming_from, c3_5_1, 3, 5, 1, WHOLE);
        shape_part!(insert_reclaiming_from, c3_5_2, 3, 5, 2, WHOLE);
        shape_part!(insert_reclaiming_from, c3_6_0, 3, 6, 0, WHOLE);

        // One part to a harness.
        shape_part!(insert_reclaiming_from, c0_0_0_result, 0, 0, 0, RESULT);
        shape_part!(insert_reclaiming_from, c0_0_0_kept, 0, 0, 0, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c0_0_0_nothing_new,
            0,
            0,
            0,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c0_0_0_limits, 0, 0, 0, LIMITS);
        shape_part!(insert_reclaiming_from, c0_0_0_in_range, 0, 0, 0, IN_RANGE);
        shape_part!(insert_reclaiming_from, c0_0_0_sorted, 0, 0, 0, SORTED);
        shape_part!(insert_reclaiming_from, c0_0_0_quota, 0, 0, 0, QUOTA);
        shape_part!(insert_reclaiming_from, c0_0_0_floor, 0, 0, 0, FLOOR);
        shape_part!(insert_reclaiming_from, c1_1_1_result, 1, 1, 1, RESULT);
        shape_part!(insert_reclaiming_from, c1_1_1_kept, 1, 1, 1, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c1_1_1_nothing_new,
            1,
            1,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c1_1_1_limits, 1, 1, 1, LIMITS);
        shape_part!(insert_reclaiming_from, c1_1_1_in_range, 1, 1, 1, IN_RANGE);
        shape_part!(insert_reclaiming_from, c1_1_1_sorted, 1, 1, 1, SORTED);
        shape_part!(insert_reclaiming_from, c1_1_1_quota, 1, 1, 1, QUOTA);
        shape_part!(insert_reclaiming_from, c1_1_1_floor, 1, 1, 1, FLOOR);
        shape_part!(insert_reclaiming_from, c1_2_1_result, 1, 2, 1, RESULT);
        shape_part!(insert_reclaiming_from, c1_2_1_kept, 1, 2, 1, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c1_2_1_nothing_new,
            1,
            2,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c1_2_1_limits, 1, 2, 1, LIMITS);
        shape_part!(insert_reclaiming_from, c1_2_1_in_range, 1, 2, 1, IN_RANGE);
        shape_part!(insert_reclaiming_from, c1_2_1_sorted, 1, 2, 1, SORTED);
        shape_part!(insert_reclaiming_from, c1_2_1_quota, 1, 2, 1, QUOTA);
        shape_part!(insert_reclaiming_from, c1_2_1_floor, 1, 2, 1, FLOOR);
        shape_part!(insert_reclaiming_from, c2_2_2_result, 2, 2, 2, RESULT);
        shape_part!(insert_reclaiming_from, c2_2_2_kept, 2, 2, 2, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c2_2_2_nothing_new,
            2,
            2,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c2_2_2_limits, 2, 2, 2, LIMITS);
        shape_part!(insert_reclaiming_from, c2_2_2_in_range, 2, 2, 2, IN_RANGE);
        shape_part!(insert_reclaiming_from, c2_2_2_sorted, 2, 2, 2, SORTED);
        shape_part!(insert_reclaiming_from, c2_2_2_quota, 2, 2, 2, QUOTA);
        shape_part!(insert_reclaiming_from, c2_2_2_floor, 2, 2, 2, FLOOR);
        shape_part!(insert_reclaiming_from, c2_3_2_result, 2, 3, 2, RESULT);
        shape_part!(insert_reclaiming_from, c2_3_2_kept, 2, 3, 2, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c2_3_2_nothing_new,
            2,
            3,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c2_3_2_limits, 2, 3, 2, LIMITS);
        shape_part!(insert_reclaiming_from, c2_3_2_in_range, 2, 3, 2, IN_RANGE);
        shape_part!(insert_reclaiming_from, c2_3_2_sorted, 2, 3, 2, SORTED);
        shape_part!(insert_reclaiming_from, c2_3_2_quota, 2, 3, 2, QUOTA);
        shape_part!(insert_reclaiming_from, c2_3_2_floor, 2, 3, 2, FLOOR);
        shape_part!(insert_reclaiming_from, c2_4_1_result, 2, 4, 1, RESULT);
        shape_part!(insert_reclaiming_from, c2_4_1_kept, 2, 4, 1, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c2_4_1_nothing_new,
            2,
            4,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c2_4_1_limits, 2, 4, 1, LIMITS);
        shape_part!(insert_reclaiming_from, c2_4_1_in_range, 2, 4, 1, IN_RANGE);
        shape_part!(insert_reclaiming_from, c2_4_1_sorted, 2, 4, 1, SORTED);
        shape_part!(insert_reclaiming_from, c2_4_1_quota, 2, 4, 1, QUOTA);
        shape_part!(insert_reclaiming_from, c2_4_1_floor, 2, 4, 1, FLOOR);
        shape_part!(insert_reclaiming_from, c2_4_2_result, 2, 4, 2, RESULT);
        shape_part!(insert_reclaiming_from, c2_4_2_kept, 2, 4, 2, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c2_4_2_nothing_new,
            2,
            4,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c2_4_2_limits, 2, 4, 2, LIMITS);
        shape_part!(insert_reclaiming_from, c2_4_2_in_range, 2, 4, 2, IN_RANGE);
        shape_part!(insert_reclaiming_from, c2_4_2_sorted, 2, 4, 2, SORTED);
        shape_part!(insert_reclaiming_from, c2_4_2_quota, 2, 4, 2, QUOTA);
        shape_part!(insert_reclaiming_from, c2_4_2_floor, 2, 4, 2, FLOOR);
        shape_part!(insert_reclaiming_from, c3_3_3_result, 3, 3, 3, RESULT);
        shape_part!(insert_reclaiming_from, c3_3_3_kept, 3, 3, 3, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_3_3_nothing_new,
            3,
            3,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_3_3_limits, 3, 3, 3, LIMITS);
        shape_part!(insert_reclaiming_from, c3_3_3_in_range, 3, 3, 3, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_3_3_sorted, 3, 3, 3, SORTED);
        shape_part!(insert_reclaiming_from, c3_3_3_quota, 3, 3, 3, QUOTA);
        shape_part!(insert_reclaiming_from, c3_3_3_floor, 3, 3, 3, FLOOR);
        shape_part!(insert_reclaiming_from, c3_4_3_result, 3, 4, 3, RESULT);
        shape_part!(insert_reclaiming_from, c3_4_3_kept, 3, 4, 3, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_4_3_nothing_new,
            3,
            4,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_4_3_limits, 3, 4, 3, LIMITS);
        shape_part!(insert_reclaiming_from, c3_4_3_in_range, 3, 4, 3, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_4_3_sorted, 3, 4, 3, SORTED);
        shape_part!(insert_reclaiming_from, c3_4_3_quota, 3, 4, 3, QUOTA);
        shape_part!(insert_reclaiming_from, c3_4_3_floor, 3, 4, 3, FLOOR);
        shape_part!(insert_reclaiming_from, c3_5_3_result, 3, 5, 3, RESULT);
        shape_part!(insert_reclaiming_from, c3_5_3_kept, 3, 5, 3, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_5_3_nothing_new,
            3,
            5,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_5_3_limits, 3, 5, 3, LIMITS);
        shape_part!(insert_reclaiming_from, c3_5_3_in_range, 3, 5, 3, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_5_3_sorted, 3, 5, 3, SORTED);
        shape_part!(insert_reclaiming_from, c3_5_3_quota, 3, 5, 3, QUOTA);
        shape_part!(insert_reclaiming_from, c3_5_3_floor, 3, 5, 3, FLOOR);
        shape_part!(insert_reclaiming_from, c3_6_1_result, 3, 6, 1, RESULT);
        shape_part!(insert_reclaiming_from, c3_6_1_kept, 3, 6, 1, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_6_1_nothing_new,
            3,
            6,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_6_1_limits, 3, 6, 1, LIMITS);
        shape_part!(insert_reclaiming_from, c3_6_1_in_range, 3, 6, 1, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_6_1_sorted, 3, 6, 1, SORTED);
        shape_part!(insert_reclaiming_from, c3_6_1_quota, 3, 6, 1, QUOTA);
        shape_part!(insert_reclaiming_from, c3_6_1_floor, 3, 6, 1, FLOOR);
        shape_part!(insert_reclaiming_from, c3_6_2_result, 3, 6, 2, RESULT);
        shape_part!(insert_reclaiming_from, c3_6_2_kept, 3, 6, 2, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_6_2_nothing_new,
            3,
            6,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_6_2_limits, 3, 6, 2, LIMITS);
        shape_part!(insert_reclaiming_from, c3_6_2_in_range, 3, 6, 2, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_6_2_sorted, 3, 6, 2, SORTED);
        shape_part!(insert_reclaiming_from, c3_6_2_quota, 3, 6, 2, QUOTA);
        shape_part!(insert_reclaiming_from, c3_6_2_floor, 3, 6, 2, FLOOR);
        shape_part!(insert_reclaiming_from, c3_6_3_result, 3, 6, 3, RESULT);
        shape_part!(insert_reclaiming_from, c3_6_3_kept, 3, 6, 3, KEPT);
        shape_part!(
            insert_reclaiming_from,
            c3_6_3_nothing_new,
            3,
            6,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_reclaiming_from, c3_6_3_limits, 3, 6, 3, LIMITS);
        shape_part!(insert_reclaiming_from, c3_6_3_in_range, 3, 6, 3, IN_RANGE);
        shape_part!(insert_reclaiming_from, c3_6_3_sorted, 3, 6, 3, SORTED);
        shape_part!(insert_reclaiming_from, c3_6_3_quota, 3, 6, 3, QUOTA);
        shape_part!(insert_reclaiming_from, c3_6_3_floor, 3, 6, 3, FLOOR);

        // The cases reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, at_quota, any_expired, n, cap) =
                insert_reclaiming_from(Slab::kani_shaped(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Inserted::New && at_quota && n == MAX);
            kani::cover!(r == Inserted::New && !at_quota && n == MAX);
            kani::cover!(r == Inserted::RowAtQuota && any_expired);
            kani::cover!(r == Inserted::PoolFull && cap == MAX);
            kani::cover!(r == Inserted::Refreshed);
        }
    }

    #[cfg(feature = "kani-full")]
    mod insert_sweeping_step {
        use super::*;

        // The whole check, where the operation cannot both give an entry up
        // and rewrite the slab.
        shape_part!(insert_sweeping_from, c1_0_0, 1, 0, 0, WHOLE);
        shape_part!(insert_sweeping_from, c1_1_0, 1, 1, 0, WHOLE);
        shape_part!(insert_sweeping_from, c1_2_0, 1, 2, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_0_0, 2, 0, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_1_0, 2, 1, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_1_1, 2, 1, 1, WHOLE);
        shape_part!(insert_sweeping_from, c2_2_0, 2, 2, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_2_1, 2, 2, 1, WHOLE);
        shape_part!(insert_sweeping_from, c2_3_0, 2, 3, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_3_1, 2, 3, 1, WHOLE);
        shape_part!(insert_sweeping_from, c2_4_0, 2, 4, 0, WHOLE);
        shape_part!(insert_sweeping_from, c2_4_1, 2, 4, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_0_0, 3, 0, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_1_0, 3, 1, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_1_1, 3, 1, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_2_0, 3, 2, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_2_1, 3, 2, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_2_2, 3, 2, 2, WHOLE);
        shape_part!(insert_sweeping_from, c3_3_0, 3, 3, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_3_1, 3, 3, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_3_2, 3, 3, 2, WHOLE);
        shape_part!(insert_sweeping_from, c3_4_0, 3, 4, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_4_1, 3, 4, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_4_2, 3, 4, 2, WHOLE);
        shape_part!(insert_sweeping_from, c3_5_0, 3, 5, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_5_1, 3, 5, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_5_2, 3, 5, 2, WHOLE);
        shape_part!(insert_sweeping_from, c3_6_0, 3, 6, 0, WHOLE);
        shape_part!(insert_sweeping_from, c3_6_1, 3, 6, 1, WHOLE);
        shape_part!(insert_sweeping_from, c3_6_2, 3, 6, 2, WHOLE);

        // One part to a harness.
        shape_part!(insert_sweeping_from, c0_0_0_result, 0, 0, 0, RESULT);
        shape_part!(insert_sweeping_from, c0_0_0_kept, 0, 0, 0, KEPT);
        shape_part!(
            insert_sweeping_from,
            c0_0_0_nothing_new,
            0,
            0,
            0,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c0_0_0_limits, 0, 0, 0, LIMITS);
        shape_part!(insert_sweeping_from, c0_0_0_in_range, 0, 0, 0, IN_RANGE);
        shape_part!(insert_sweeping_from, c0_0_0_sorted, 0, 0, 0, SORTED);
        shape_part!(insert_sweeping_from, c0_0_0_quota, 0, 0, 0, QUOTA);
        shape_part!(insert_sweeping_from, c0_0_0_floor, 0, 0, 0, FLOOR);
        shape_part!(insert_sweeping_from, c1_1_1_result, 1, 1, 1, RESULT);
        shape_part!(insert_sweeping_from, c1_1_1_kept, 1, 1, 1, KEPT);
        shape_part!(
            insert_sweeping_from,
            c1_1_1_nothing_new,
            1,
            1,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c1_1_1_limits, 1, 1, 1, LIMITS);
        shape_part!(insert_sweeping_from, c1_1_1_in_range, 1, 1, 1, IN_RANGE);
        shape_part!(insert_sweeping_from, c1_1_1_sorted, 1, 1, 1, SORTED);
        shape_part!(insert_sweeping_from, c1_1_1_quota, 1, 1, 1, QUOTA);
        shape_part!(insert_sweeping_from, c1_1_1_floor, 1, 1, 1, FLOOR);
        shape_part!(insert_sweeping_from, c1_2_1_result, 1, 2, 1, RESULT);
        shape_part!(insert_sweeping_from, c1_2_1_kept, 1, 2, 1, KEPT);
        shape_part!(
            insert_sweeping_from,
            c1_2_1_nothing_new,
            1,
            2,
            1,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c1_2_1_limits, 1, 2, 1, LIMITS);
        shape_part!(insert_sweeping_from, c1_2_1_in_range, 1, 2, 1, IN_RANGE);
        shape_part!(insert_sweeping_from, c1_2_1_sorted, 1, 2, 1, SORTED);
        shape_part!(insert_sweeping_from, c1_2_1_quota, 1, 2, 1, QUOTA);
        shape_part!(insert_sweeping_from, c1_2_1_floor, 1, 2, 1, FLOOR);
        shape_part!(insert_sweeping_from, c2_2_2_result, 2, 2, 2, RESULT);
        shape_part!(insert_sweeping_from, c2_2_2_kept, 2, 2, 2, KEPT);
        shape_part!(
            insert_sweeping_from,
            c2_2_2_nothing_new,
            2,
            2,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c2_2_2_limits, 2, 2, 2, LIMITS);
        shape_part!(insert_sweeping_from, c2_2_2_in_range, 2, 2, 2, IN_RANGE);
        shape_part!(insert_sweeping_from, c2_2_2_sorted, 2, 2, 2, SORTED);
        shape_part!(insert_sweeping_from, c2_2_2_quota, 2, 2, 2, QUOTA);
        shape_part!(insert_sweeping_from, c2_2_2_floor, 2, 2, 2, FLOOR);
        shape_part!(insert_sweeping_from, c2_3_2_result, 2, 3, 2, RESULT);
        shape_part!(insert_sweeping_from, c2_3_2_kept, 2, 3, 2, KEPT);
        shape_part!(
            insert_sweeping_from,
            c2_3_2_nothing_new,
            2,
            3,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c2_3_2_limits, 2, 3, 2, LIMITS);
        shape_part!(insert_sweeping_from, c2_3_2_in_range, 2, 3, 2, IN_RANGE);
        shape_part!(insert_sweeping_from, c2_3_2_sorted, 2, 3, 2, SORTED);
        shape_part!(insert_sweeping_from, c2_3_2_quota, 2, 3, 2, QUOTA);
        shape_part!(insert_sweeping_from, c2_3_2_floor, 2, 3, 2, FLOOR);
        shape_part!(insert_sweeping_from, c2_4_2_result, 2, 4, 2, RESULT);
        shape_part!(insert_sweeping_from, c2_4_2_kept, 2, 4, 2, KEPT);
        shape_part!(
            insert_sweeping_from,
            c2_4_2_nothing_new,
            2,
            4,
            2,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c2_4_2_limits, 2, 4, 2, LIMITS);
        shape_part!(insert_sweeping_from, c2_4_2_in_range, 2, 4, 2, IN_RANGE);
        shape_part!(insert_sweeping_from, c2_4_2_sorted, 2, 4, 2, SORTED);
        shape_part!(insert_sweeping_from, c2_4_2_quota, 2, 4, 2, QUOTA);
        shape_part!(insert_sweeping_from, c2_4_2_floor, 2, 4, 2, FLOOR);
        shape_part!(insert_sweeping_from, c3_3_3_result, 3, 3, 3, RESULT);
        shape_part!(insert_sweeping_from, c3_3_3_kept, 3, 3, 3, KEPT);
        shape_part!(
            insert_sweeping_from,
            c3_3_3_nothing_new,
            3,
            3,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c3_3_3_limits, 3, 3, 3, LIMITS);
        shape_part!(insert_sweeping_from, c3_3_3_in_range, 3, 3, 3, IN_RANGE);
        shape_part!(insert_sweeping_from, c3_3_3_sorted, 3, 3, 3, SORTED);
        shape_part!(insert_sweeping_from, c3_3_3_quota, 3, 3, 3, QUOTA);
        shape_part!(insert_sweeping_from, c3_3_3_floor, 3, 3, 3, FLOOR);
        shape_part!(insert_sweeping_from, c3_4_3_result, 3, 4, 3, RESULT);
        shape_part!(insert_sweeping_from, c3_4_3_kept, 3, 4, 3, KEPT);
        shape_part!(
            insert_sweeping_from,
            c3_4_3_nothing_new,
            3,
            4,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c3_4_3_limits, 3, 4, 3, LIMITS);
        shape_part!(insert_sweeping_from, c3_4_3_in_range, 3, 4, 3, IN_RANGE);
        shape_part!(insert_sweeping_from, c3_4_3_sorted, 3, 4, 3, SORTED);
        shape_part!(insert_sweeping_from, c3_4_3_quota, 3, 4, 3, QUOTA);
        shape_part!(insert_sweeping_from, c3_4_3_floor, 3, 4, 3, FLOOR);
        shape_part!(insert_sweeping_from, c3_5_3_result, 3, 5, 3, RESULT);
        shape_part!(insert_sweeping_from, c3_5_3_kept, 3, 5, 3, KEPT);
        shape_part!(
            insert_sweeping_from,
            c3_5_3_nothing_new,
            3,
            5,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c3_5_3_limits, 3, 5, 3, LIMITS);
        shape_part!(insert_sweeping_from, c3_5_3_in_range, 3, 5, 3, IN_RANGE);
        shape_part!(insert_sweeping_from, c3_5_3_sorted, 3, 5, 3, SORTED);
        shape_part!(insert_sweeping_from, c3_5_3_quota, 3, 5, 3, QUOTA);
        shape_part!(insert_sweeping_from, c3_5_3_floor, 3, 5, 3, FLOOR);
        shape_part!(insert_sweeping_from, c3_6_3_result, 3, 6, 3, RESULT);
        shape_part!(insert_sweeping_from, c3_6_3_kept, 3, 6, 3, KEPT);
        shape_part!(
            insert_sweeping_from,
            c3_6_3_nothing_new,
            3,
            6,
            3,
            NOTHING_NEW
        );
        shape_part!(insert_sweeping_from, c3_6_3_limits, 3, 6, 3, LIMITS);
        shape_part!(insert_sweeping_from, c3_6_3_in_range, 3, 6, 3, IN_RANGE);
        shape_part!(insert_sweeping_from, c3_6_3_sorted, 3, 6, 3, SORTED);
        shape_part!(insert_sweeping_from, c3_6_3_quota, 3, 6, 3, QUOTA);
        shape_part!(insert_sweeping_from, c3_6_3_floor, 3, 6, 3, FLOOR);

        // The cases reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, _, _, _) =
                insert_sweeping_from(Slab::kani_shaped(MAX, 2 * MAX, MAX - 1), LIMITS);
            kani::cover!(r == Swept::New);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, any_expired, n, m) =
                insert_sweeping_from(Slab::kani_shaped(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Swept::Throttled && any_expired && n == MAX);
            kani::cover!(r == Swept::Full && n == MAX);
            kani::cover!(r == Swept::SweptNew && m == 1 && n == MAX);
            kani::cover!(r == Swept::SweptNew && m == MAX);
        }
    }
}
