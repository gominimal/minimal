//! A table with a hard capacity and a quota per row.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! THEOREM G7, for every sequence of operations on a [`Pool`]:
//!   (a) it never holds more than `cap` entries;
//!   (b) it never holds more than `quota` entries for one row;
//!   (c) it never holds two entries with the same row and key;
//!   (d) an insert that would break (a) or (b) changes nothing and says which;
//!   (e) its quota never exceeds its capacity;
//!   (f) what it holds after an entry is added does not depend on where the
//!       entry is put.
//!
//! The check comes before the insert. `insert` sweeps nothing to make room;
//! `insert_reclaiming` gives up at most one expired entry, and only when a
//! bound would otherwise refuse. Sweeping is `expire`; `drop_expired` removes
//! one expired entry a frame touched. Removal and expiry can only lower the
//! counts.
//!
//! The entries are a `Vec` scanned in order: the simplest structure the
//! theorem can be proved of, and linear in the table's size per lookup.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::sweep::{
    dropped_if_expired, due, expired_at, expired_held, lemma_subset_not_held, lemma_swept_added,
    swept_and_added,
};
use crate::time::Instant;

/// One entry: which row holds it, the row's own key, when it expires, and a
/// value its table keeps with it. The value is not part of the entry's
/// identity: a row holds a key once, whatever its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Entry {
    pub row: u32,
    pub key: u64,
    pub deadline_ms: u64,
    pub value: u32,
}

/// What an insert did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Inserted {
    /// A new entry was added.
    New,
    /// The row already held this key; its deadline and value were replaced.
    Refreshed,
    /// The row holds `quota` entries already. Nothing changed.
    RowAtQuota,
    /// The table holds `cap` entries already. Nothing changed.
    PoolFull,
}

/// When a table last swept its expired entries at its capacity, and the
/// least time between two such sweeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Throttle {
    pub interval_ms: u64,
    pub last_ms: Option<u64>,
}

/// What an insert that may sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Swept {
    /// There was room. A new entry was added and nothing was swept.
    New,
    /// The table was at its capacity and a sweep was due. Every expired entry
    /// was removed and the new one added.
    SweptNew,
    /// The table was at its capacity, a sweep was due and nothing had
    /// expired. Nothing changed but the instant of the last sweep.
    Full,
    /// The table was at its capacity and a sweep was not due. Nothing changed.
    Throttled,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Throttle {
    /// Whether a sweep may run at `now_ms`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r == due(*self, now.ms),
    ))]
    pub fn due(&self, now: Instant) -> bool {
        match self.last_ms {
            None => true,
            Some(t) => {
                if now.ms >= t {
                    now.ms - t >= self.interval_ms
                } else {
                    self.interval_ms == 0
                }
            }
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Pool {
    entries: Vec<Entry>,
    cap: usize,
    quota: usize,
}

#[cfg(verus_keep_ghost)]
verus! {

/// How many entries of `s` belong to `row`.
pub open spec fn count(s: Seq<Entry>, row: u32) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        count(s.drop_last(), row) + if s.last().row == row { 1nat } else { 0nat }
    }
}

pub open spec fn holds(s: Seq<Entry>, row: u32, key: u64) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].row == row && s[j].key == key
}

#[verifier::opaque]
pub open spec fn distinct_keys(s: Seq<Entry>) -> bool {
    forall|i: int, j: int|
        0 <= i < j < s.len() ==> !(s[i].row == s[j].row && s[i].key == s[j].key)
}

/// G7 (a), (b), (c) and (e) as a predicate on the table's contents and limits.
pub open spec fn within_caps(s: Seq<Entry>, cap: int, quota: int) -> bool {
    &&& quota <= cap
    &&& s.len() <= cap
    &&& forall|row: u32| count(s, row) <= quota
    &&& distinct_keys(s)
}

pub closed spec fn view(p: Pool) -> Seq<Entry> { p.entries@ }
pub closed spec fn spec_cap(p: Pool) -> int { p.cap as int }
pub closed spec fn spec_quota(p: Pool) -> int { p.quota as int }

/// The invariant every operation keeps.
pub open spec fn inv(p: Pool) -> bool {
    within_caps(view(p), spec_cap(p), spec_quota(p))
}

pub proof fn lemma_count_push(s: Seq<Entry>, e: Entry, row: u32)
    ensures
        count(s.push(e), row) == count(s, row) + if e.row == row { 1nat } else { 0nat },
{
    assert(s.push(e).drop_last() =~= s);
    assert(s.push(e).last() == e);
}

/// Replacing an entry by one of the same row changes no row's count.
pub proof fn lemma_count_update(s: Seq<Entry>, i: int, e: Entry, row: u32)
    requires
        0 <= i < s.len(),
        e.row == s[i].row,
    ensures
        count(s.update(i, e), row) == count(s, row),
    decreases s.len(),
{
    if i == s.len() - 1 {
        assert(s.update(i, e).drop_last() =~= s.drop_last());
        assert(s.update(i, e).last() == e);
    } else {
        lemma_count_update(s.drop_last(), i, e, row);
        assert(s.update(i, e).drop_last() =~= s.drop_last().update(i, e));
        assert(s.update(i, e).last() == s.last());
    }
}

/// One more element of a prefix adds that element's contribution.
pub proof fn lemma_count_take(s: Seq<Entry>, i: int, row: u32)
    requires
        0 <= i < s.len(),
    ensures
        count(s.take(i + 1), row) == count(s.take(i), row) + if s[i].row == row {
            1nat
        } else {
            0nat
        },
{
    assert(s.take(i + 1).drop_last() =~= s.take(i));
    assert(s.take(i + 1).last() == s[i]);
}

/// A count never exceeds the length.
pub proof fn lemma_count_le_len(s: Seq<Entry>, row: u32)
    ensures
        count(s, row) <= s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_count_le_len(s.drop_last(), row);
    }
}

/// The facts `insert_reclaiming` needs about its three tables: `first` at entry, `mid` after at most one expired
/// entry was removed (at `gone`, or -1 for none), and `mid` with `added` pushed.
pub proof fn lemma_reclaim_not_held(first: Seq<Entry>, mid: Seq<Entry>, gone: int, row: u32, key: u64)
    requires
        gone == -1 ==> mid == first,
        gone != -1 ==> 0 <= gone < first.len() && mid == first.remove(gone),
    ensures
        holds(mid, row, key) ==> holds(first, row, key),
{
    if holds(mid, row, key) {
        let x = choose|x: int| 0 <= x < mid.len() && mid[x].row == row && mid[x].key == key;
        let x0 = if gone == -1 || x < gone { x } else { x + 1 };
        assert(first[x0].row == row && first[x0].key == key);
    }
}

/// `first` with at most one expired entry given up is `mid`; `last` is `mid`
/// with `e` added, wherever it is put.
pub proof fn lemma_reclaim_tables(first: Seq<Entry>, mid: Seq<Entry>, last: Seq<Entry>, gone: int, e: Entry, now_ms: u64)
    requires
        gone == -1 ==> mid == first,
        gone != -1 ==> 0 <= gone < first.len() && first[gone].deadline_ms <= now_ms && mid == first.remove(gone),
        added(last, mid, e),
    ensures
        has(last, e),
        only_adds(last, first, e),
        keeps_live(last, first, now_ms),
        last.len() <= first.len() + 1,
{
    theorem_added_members(last, mid, e, e, 0);
    assert forall|x: int| 0 <= x < last.len() implies has(first, #[trigger] last[x]) || last[x] == e by {
        theorem_added_members(last, mid, e, last[x], 0);
        assert(has(last, last[x]));
        if last[x] != e {
            let m = choose|m: int| 0 <= m < mid.len() && mid[m] == last[x];
            let m0 = if gone == -1 || m < gone { m } else { m + 1 };
            assert(first[m0] == last[x]);
        }
    }
    assert forall|k: int| 0 <= k < first.len() && first[k].deadline_ms > now_ms implies has(last, #[trigger] first[k]) by {
        let k0 = if gone == -1 || k < gone { k } else { k - 1 };
        assert(mid[k0] == first[k]);
        theorem_added_members(last, mid, e, first[k], 0);
    }
}

/// `insert_reclaiming` found `(row, key)` at `i` and rewrote that entry: `Refreshed`.
pub proof fn lemma_reclaiming_refreshed(before: Pool, after: Pool, row: u32, key: u64, deadline_ms: u64, value: u32, i: int)
    requires
        inv(after),
        spec_cap(after) == spec_cap(before),
        spec_quota(after) == spec_quota(before),
        0 <= i < view(before).len(),
        view(before)[i].row == row,
        view(before)[i].key == key,
        view(after) == view(before).update(i, Entry { row, key, deadline_ms, value }),
    ensures
        inv(after),
        spec_cap(after) == spec_cap(before),
        spec_quota(after) == spec_quota(before),
        holds(view(before), row, key),
        refreshed_from(view(after), view(before), row, key),
        changed_only_to(view(after), view(before), Entry { row, key, deadline_ms, value }),
        has(view(after), Entry { row, key, deadline_ms, value }),
{
    assert(view(after)[i] == Entry { row, key, deadline_ms, value });
}

/// Removing an entry `j` leaves room for `(row, key)`: any entry when the row is below its quota, an entry of the row
/// when the row is at it.
pub proof fn lemma_reclaiming_room(before: Pool, mid: Pool, row: u32, key: u64, j: int)
    requires
        inv(before),
        spec_cap(mid) == spec_cap(before),
        spec_quota(mid) == spec_quota(before),
        !holds(view(before), row, key),
        0 <= j < view(before).len(),
        count(view(before), row) >= spec_quota(before) ==> view(before)[j].row == row,
        view(mid) == view(before).remove(j),
    ensures
        !holds(view(mid), row, key),
        count(view(mid), row) < spec_quota(mid),
        view(mid).len() < spec_cap(mid),
{
    lemma_count_remove(view(before), j, row);
    lemma_reclaim_not_held(view(before), view(mid), j, row, key);
}

/// `insert_reclaiming` added `(row, key)` to `mid`, the table with at most one expired entry given up (at `gone`, or
/// -1 for none): `New`.
/// What `insert_reclaiming` gives up for a new entry. `mid` is the table
/// between the removal, if there was one (`gone` is where, or -1), and the
/// insert. The table does not shrink; with nothing removed the entry is
/// added outright; with one removed, every entry of another row than the
/// removed one's is kept.
proof fn lemma_reclaiming_given_up(before: Seq<Entry>, mid: Seq<Entry>, after: Seq<Entry>, gone: int, e: Entry)
    requires
        gone == -1 ==> mid == before,
        gone != -1 ==> 0 <= gone < before.len() && mid == before.remove(gone),
        added(after, mid, e),
    ensures
        after.len() >= before.len(),
        gone == -1 ==> added(after, before, e),
        gone != -1 ==> keeps_other_rows(after, before, before[gone].row),
{
    reveal(added);
    if gone != -1 {
        assert forall|k: int| 0 <= k < before.len() && before[k].row != before[gone].row implies has(after, #[trigger] before[k]) by {
            let k2 = if k < gone { k } else { k - 1 };
            assert(mid[k2] == before[k]);
            assert(has(after, mid[k2]));
        }
    }
}

pub proof fn lemma_reclaiming_new(
    before: Pool,
    after: Pool,
    row: u32,
    key: u64,
    deadline_ms: u64,
    value: u32,
    now_ms: u64,
    mid: Seq<Entry>,
    gone: int,
)
    requires
        inv(after),
        spec_cap(after) == spec_cap(before),
        spec_quota(after) == spec_quota(before),
        !holds(view(before), row, key),
        gone == -1 ==> mid == view(before),
        gone != -1 ==> 0 <= gone < view(before).len() && view(before)[gone].deadline_ms <= now_ms
            && mid == view(before).remove(gone),
        added(view(after), mid, Entry { row, key, deadline_ms, value }),
    ensures
        inv(after),
        spec_cap(after) == spec_cap(before),
        spec_quota(after) == spec_quota(before),
        !holds(view(before), row, key),
        has(view(after), Entry { row, key, deadline_ms, value }),
        only_adds(view(after), view(before), Entry { row, key, deadline_ms, value }),
        keeps_live(view(after), view(before), now_ms),
        view(after).len() <= view(before).len() + 1,
{
    lemma_reclaim_tables(view(before), mid, view(after), gone, Entry { row, key, deadline_ms, value }, now_ms);
}

/// Removing an entry lowers its row's count by one and no other.
pub proof fn lemma_count_remove(s: Seq<Entry>, i: int, row: u32)
    requires
        0 <= i < s.len(),
    ensures
        count(s.remove(i), row) + (if s[i].row == row { 1nat } else { 0nat }) == count(s, row),
    decreases s.len(),
{
    if i == s.len() - 1 {
        assert(s.remove(i) =~= s.drop_last());
    } else {
        lemma_count_remove(s.drop_last(), i, row);
        assert(s.remove(i).drop_last() =~= s.drop_last().remove(i));
        assert(s.remove(i).last() == s.last());
    }
}

/// An entry other than the one removed is still there.
pub proof fn lemma_remove_keeps(s: Seq<Entry>, i: int, e: Entry)
    requires
        0 <= i < s.len(),
        s[i] != e,
        has(s, e),
    ensures
        has(s.remove(i), e),
{
    let j = choose|j: int| 0 <= j < s.len() && s[j] == e;
    if j < i {
        assert(s.remove(i)[j] == e);
    } else {
        assert(s.remove(i)[j - 1] == e);
    }
}

/// Removing an entry keeps a table within its bounds and its keys distinct.
pub proof fn lemma_remove_within_caps(s: Seq<Entry>, i: int, cap: int, quota: int)
    requires
        within_caps(s, cap, quota),
        0 <= i < s.len(),
    ensures
        within_caps(s.remove(i), cap, quota),
{
    reveal(crate::pool::distinct_keys);
    let after = s.remove(i);
    assert forall|r: u32| count(after, r) <= quota by {
        lemma_count_remove(s, i, r);
    }
    assert forall|a: int, b: int| 0 <= a < b < after.len() implies !(after[a].row == after[b].row
        && after[a].key == after[b].key) by {
        let a0 = if a < i { a } else { a + 1 };
        let b0 = if b < i { b } else { b + 1 };
        assert(after[a] == s[a0] && after[b] == s[b0]);
        assert(!(s[a0].row == s[b0].row && s[a0].key == s[b0].key));
    }
}

/// Removing a place keeps a table a subset of `first`.
pub proof fn lemma_remove_subset(g: Seq<Entry>, first: Seq<Entry>, w: int)
    requires
        subset_of(g, first),
        0 <= w < g.len(),
    ensures
        subset_of(g.remove(w), first),
{
    let next = g.remove(w);
    assert forall|j: int| 0 <= j < next.len() implies has(first, #[trigger] next[j]) by {
        let j0 = if j < w { j } else { j + 1 };
        assert(next[j] == g[j0]);
        assert(has(first, g[j0]));
    }
}

/// Removing an expired entry keeps every live entry of `first`.
pub proof fn lemma_remove_keeps_live(g: Seq<Entry>, first: Seq<Entry>, w: int, now_ms: u64)
    requires
        keeps_live(g, first, now_ms),
        0 <= w < g.len(),
        g[w].deadline_ms <= now_ms,
    ensures
        keeps_live(g.remove(w), first, now_ms),
{
    assert forall|k: int| 0 <= k < first.len() && first[k].deadline_ms > now_ms implies has(g.remove(w), #[trigger] first[k]) by {
        assert(has(g, first[k]));
        assert(g[w] != first[k]);
        lemma_remove_keeps(g, w, first[k]);
    }
}

/// Removing an entry of `row` keeps every entry of `first` of another row.
pub proof fn lemma_remove_keeps_other_rows(g: Seq<Entry>, first: Seq<Entry>, w: int, row: u32)
    requires
        keeps_other_rows(g, first, row),
        0 <= w < g.len(),
        g[w].row == row,
    ensures
        keeps_other_rows(g.remove(w), first, row),
{
    assert forall|k: int| 0 <= k < first.len() && first[k].row != row implies has(g.remove(w), #[trigger] first[k]) by {
        assert(has(g, first[k]));
        assert(g[w] != first[k]);
        lemma_remove_keeps(g, w, first[k]);
    }
}

/// Removing an entry with that value keeps every entry of `first` with
/// another.
pub proof fn lemma_remove_keeps_unvalued(g: Seq<Entry>, first: Seq<Entry>, w: int, value: u32)
    requires
        keeps_unvalued(g, first, value),
        0 <= w < g.len(),
        g[w].value == value,
    ensures
        keeps_unvalued(g.remove(w), first, value),
{
    assert forall|k: int| 0 <= k < first.len() && first[k].value != value implies has(g.remove(w), #[trigger] first[k]) by {
        assert(has(g, first[k]));
        assert(g[w] != first[k]);
        lemma_remove_keeps(g, w, first[k]);
    }
}

/// Removing an entry whose key has those ends keeps every entry of `first`
/// whose key has not.
pub proof fn lemma_remove_keeps_unmatched(g: Seq<Entry>, first: Seq<Entry>, w: int, hi: u64, lo: u64)
    requires
        keeps_unmatched(g, first, hi, lo),
        0 <= w < g.len(),
        key_ends(g[w].key, hi, lo),
    ensures
        keeps_unmatched(g.remove(w), first, hi, lo),
{
    assert forall|k: int| 0 <= k < first.len() && !key_ends(first[k].key, hi, lo) implies has(g.remove(w), #[trigger] first[k]) by {
        assert(has(g, first[k]));
        assert(g[w] != first[k]);
        lemma_remove_keeps(g, w, first[k]);
    }
}

/// The entry at a place of a subset of `first` is an entry of `first`.
pub proof fn lemma_subset_member(g: Seq<Entry>, first: Seq<Entry>, w: int)
    requires
        subset_of(g, first),
        0 <= w < g.len(),
    ensures
        has(first, g[w]),
{
}

/// `e` is an entry of `s`.
pub open spec fn has(s: Seq<Entry>, e: Entry) -> bool {
    exists|k: int| 0 <= k < s.len() && s[k] == e
}

/// Every entry of `now` was an entry of `before`.
pub open spec fn subset_of(now: Seq<Entry>, before: Seq<Entry>) -> bool {
    forall|j: int| 0 <= j < now.len() ==> has(before, #[trigger] now[j])
}

/// Every entry of `before` that has not expired at `now_ms` is still in `now`.
pub open spec fn keeps_live(now: Seq<Entry>, before: Seq<Entry>, now_ms: u64) -> bool {
    forall|k: int| 0 <= k < before.len() && before[k].deadline_ms > now_ms ==> has(now, #[trigger] before[k])
}

/// `now` is `before` except where an entry became `e`.
pub open spec fn changed_only_to(now: Seq<Entry>, before: Seq<Entry>, e: Entry) -> bool {
    &&& now.len() == before.len()
    &&& forall|j: int| 0 <= j < now.len() ==> (#[trigger] now[j]) == before[j] || now[j] == e
}

/// No entry of `now` expires earlier than the entry at its position in `before`.
pub open spec fn not_shortened(now: Seq<Entry>, before: Seq<Entry>) -> bool {
    &&& now.len() == before.len()
    &&& forall|j: int| 0 <= j < now.len() ==> (#[trigger] now[j]).deadline_ms >= before[j].deadline_ms
}

/// Keys are distinct, so a position with an entry's row and key holds that entry.
pub proof fn lemma_only_entry(s: Seq<Entry>, e: Entry, j: int)
    requires
        distinct_keys(s),
        has(s, e),
        0 <= j < s.len(),
        s[j].row == e.row,
        s[j].key == e.key,
    ensures
        s[j] == e,
{
    reveal(crate::pool::distinct_keys);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    if j < k {
        assert(!(s[j].row == s[k].row && s[j].key == s[k].key));
    } else if k < j {
        assert(!(s[k].row == s[j].row && s[k].key == s[j].key));
    }
}

/// Replacing one entry's deadline by a later one shortens nothing.
pub proof fn lemma_refresh_not_shortened(now: Seq<Entry>, before: Seq<Entry>, was: Entry, is: Entry)
    requires
        distinct_keys(before),
        has(before, was),
        refreshed_from(now, before, was.row, was.key),
        changed_only_to(now, before, is),
        is.deadline_ms >= was.deadline_ms,
    ensures
        not_shortened(now, before),
{
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).deadline_ms >= before[j].deadline_ms by {
        if now[j] != before[j] {
            lemma_only_entry(before, was, j);
        }
    }
}

/// Where an entry sorts: by row, then by key. A plain integer, so comparing
/// two entries is comparing two numbers.
pub open spec fn rank_of(row: u32, key: u64) -> int {
    row as int * 18446744073709551616 + key as int
}

pub open spec fn rank(e: Entry) -> int {
    rank_of(e.row, e.key)
}

/// The entries are in strictly increasing order of rank.
pub open spec fn sorted(s: Seq<Entry>) -> bool {
    forall|i: int, j: int| 0 <= i < j < s.len() ==> rank(s[i]) < rank(s[j])
}

/// Two ranks are equal exactly when the rows and the keys are.
pub proof fn lemma_rank_eq(r1: u32, k1: u64, r2: u32, k2: u64)
    ensures
        (rank_of(r1, k1) == rank_of(r2, k2)) == (r1 == r2 && k1 == k2),
        r1 < r2 ==> rank_of(r1, k1) < rank_of(r2, k2),
{
}

/// A sorted table holds no row and key twice.
pub proof fn lemma_sorted_distinct(s: Seq<Entry>)
    requires
        sorted(s),
    ensures
        distinct_keys(s),
{
    reveal(crate::pool::distinct_keys);
    assert forall|i: int, j: int| 0 <= i < j < s.len() implies !(s[i].row == s[j].row && s[i].key == s[j].key) by {
        assert(rank(s[i]) < rank(s[j]));
        lemma_rank_eq(s[i].row, s[i].key, s[j].row, s[j].key);
    }
}

/// Every entry of `before` other than the one for `(row, key)` is still in `now`.
pub open spec fn keeps_others(now: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64) -> bool {
    forall|k: int| 0 <= k < before.len() && !(before[k].row == row && before[k].key == key) ==> has(now, #[trigger] before[k])
}

/// The key's high field (above bit 32) is `hi` and its low 16 bits are `lo`.
pub open spec fn key_ends(key: u64, hi: u64, lo: u64) -> bool {
    key / 4294967296 == hi && key % 65536 == lo
}

/// Every entry of `before` whose key does not have those ends is still in `now`.
pub open spec fn keeps_unmatched(now: Seq<Entry>, before: Seq<Entry>, hi: u64, lo: u64) -> bool {
    forall|k: int| 0 <= k < before.len() && !key_ends(before[k].key, hi, lo) ==> has(now, #[trigger] before[k])
}

/// No entry of `s` has a key with those ends.
pub open spec fn none_ending(s: Seq<Entry>, hi: u64, lo: u64) -> bool {
    forall|j: int| 0 <= j < s.len() ==> !key_ends((#[trigger] s[j]).key, hi, lo)
}

/// Every entry of `before` whose value is not `value` is still in `now`.
pub open spec fn keeps_unvalued(now: Seq<Entry>, before: Seq<Entry>, value: u32) -> bool {
    forall|k: int| 0 <= k < before.len() && before[k].value != value ==> has(now, #[trigger] before[k])
}

/// No entry of `s` has the value `value`.
pub open spec fn none_valued(s: Seq<Entry>, value: u32) -> bool {
    forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).value != value
}

/// How many entries of `s` have not expired at `now_ms`.
pub open spec fn live_number(s: Seq<Entry>, now_ms: u64) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        live_number(s.drop_last(), now_ms) + if s.last().deadline_ms > now_ms { 1nat } else { 0nat }
    }
}

/// No entry of `s` has expired at `now_ms`.
pub open spec fn none_expired(s: Seq<Entry>, now_ms: u64) -> bool {
    forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).deadline_ms > now_ms
}

/// Proof text only: what the loop of [`Pool::expire`] carries about the
/// table as it would be had each expired entry been removed when it was
/// met. Opaque, so that a turn of the loop that removes nothing does not
/// unfold it.
#[verifier::opaque]
spec fn expire_carries(g: Seq<Entry>, first: Seq<Entry>, cap: int, quota: int, now_ms: u64) -> bool {
    within_caps(g, cap, quota) && subset_of(g, first) && keeps_live(g, first, now_ms)
}

/// Proof text only: the same for the loop of [`Pool::release_expired`].
#[verifier::opaque]
spec fn release_carries(g: Seq<Entry>, first: Seq<Entry>, cap: int, quota: int, now_ms: u64, row: u32) -> bool {
    within_caps(g, cap, quota) && subset_of(g, first) && keeps_live(g, first, now_ms) && keeps_other_rows(g, first, row)
}

/// Proof text only: the same for the loop of [`Pool::remove_ends`].
#[verifier::opaque]
spec fn ends_carries(g: Seq<Entry>, first: Seq<Entry>, cap: int, quota: int, hi: u64, lo: u64) -> bool {
    within_caps(g, cap, quota) && subset_of(g, first) && keeps_unmatched(g, first, hi, lo)
}

/// No entry of `row` in `s` has expired at `now_ms`.
pub open spec fn row_live(s: Seq<Entry>, row: u32, now_ms: u64) -> bool {
    forall|j: int| 0 <= j < s.len() && (#[trigger] s[j]).row == row ==> s[j].deadline_ms > now_ms
}

/// Every entry of `now` was an entry of `before` or is `e`.
pub open spec fn only_adds(now: Seq<Entry>, before: Seq<Entry>, e: Entry) -> bool {
    forall|j: int| 0 <= j < now.len() ==> has(before, #[trigger] now[j]) || now[j] == e
}

/// `after` is `before` with `e` added, in whatever place: `before` did not
/// hold `e`'s row and key; `after` holds `e`, every entry of `before` and
/// nothing else; it is one longer, and each row's count is what it was, plus
/// one for `e`'s row. A row and key held once is still held once.
#[verifier::opaque]
pub open spec fn added(after: Seq<Entry>, before: Seq<Entry>, e: Entry) -> bool {
    &&& !holds(before, e.row, e.key)
    &&& has(after, e)
    &&& after.len() == before.len() + 1
    &&& forall|k: int| 0 <= k < before.len() ==> has(after, #[trigger] before[k])
    &&& only_adds(after, before, e)
    &&& forall|r: u32| #[trigger] count(after, r) == count(before, r) + if r == e.row { 1nat } else { 0nat }
    &&& distinct_keys(before) ==> distinct_keys(after)
}

/// Appending is one way of adding.
pub proof fn lemma_added_push(before: Seq<Entry>, e: Entry)
    requires
        !holds(before, e.row, e.key),
    ensures
        added(before.push(e), before, e),
{
    reveal(crate::pool::distinct_keys);
    reveal(added);
    let after = before.push(e);
    assert(after[before.len() as int] == e);
    assert forall|k: int| 0 <= k < before.len() implies has(after, #[trigger] before[k]) by {
        assert(after[k] == before[k]);
    }
    assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) || after[j] == e by {
        if j < before.len() {
            assert(before[j] == after[j]);
        }
    }
    assert forall|r: u32| #[trigger] count(after, r) == count(before, r) + if r == e.row { 1nat } else { 0nat } by {
        lemma_count_push(before, e, r);
    }
    if distinct_keys(before) {
        assert forall|a: int, b: int| 0 <= a < b < after.len() implies !(after[a].row == after[b].row
            && after[a].key == after[b].key) by {
            if b == before.len() {
                assert(!(before[a].row == e.row && before[a].key == e.key));
            } else {
                assert(!(before[a].row == before[b].row && before[a].key == before[b].key));
            }
        }
    }
}

/// G7 (f): adding an entry keeps keys distinct, by row and key and, where no
/// row held the new key, by key alone. The second follows from the first and
/// from what the table holds.
pub proof fn theorem_added_keeps_keys(after: Seq<Entry>, before: Seq<Entry>, e: Entry)
    requires
        added(after, before, e),
    ensures
        distinct_keys(before) ==> distinct_keys(after),
        unique_keys(before) && !held_key(before, e.key) ==> unique_keys(after),
{
    reveal(crate::pool::distinct_keys);
    reveal(added);
}

/// G7 (f): what a table holds after an entry is added is fixed, whatever
/// order it is kept in: the new entry, what it held before and nothing else,
/// with one more entry in all and one more for that entry's row.
pub proof fn theorem_added_members(after: Seq<Entry>, before: Seq<Entry>, e: Entry, x: Entry, r: u32)
    requires
        added(after, before, e),
    ensures
        !holds(before, e.row, e.key),
        has(after, x) == (x == e || has(before, x)),
        after.len() == before.len() + 1,
        count(after, r) == count(before, r) + if r == e.row { 1nat } else { 0nat },
{
    reveal(added);
    if has(before, x) {
        let k = choose|k: int| 0 <= k < before.len() && before[k] == x;
        assert(has(after, before[k]));
    }
    if has(after, x) {
        let j = choose|j: int| 0 <= j < after.len() && after[j] == x;
        assert(has(before, after[j]) || after[j] == e);
    }
}

/// No entry of `now` expires later than both `limit` and the entry at its
/// position in `before`.
pub open spec fn bounded_by(now: Seq<Entry>, before: Seq<Entry>, limit: u64) -> bool {
    &&& now.len() == before.len()
    &&& forall|j: int| 0 <= j < now.len() ==> (#[trigger] now[j]).deadline_ms <= before[j].deadline_ms
        || now[j].deadline_ms <= limit
}

/// Replacing one entry's deadline by its old one or by one within `limit`
/// lengthens nothing past `limit`.
pub proof fn lemma_refresh_bounded(now: Seq<Entry>, before: Seq<Entry>, was: Entry, is: Entry, limit: u64)
    requires
        distinct_keys(before),
        has(before, was),
        refreshed_from(now, before, was.row, was.key),
        changed_only_to(now, before, is),
        is.deadline_ms <= was.deadline_ms || is.deadline_ms <= limit,
    ensures
        bounded_by(now, before, limit),
{
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).deadline_ms <= before[j].deadline_ms
        || now[j].deadline_ms <= limit by {
        if now[j] != before[j] {
            lemma_only_entry(before, was, j);
        }
    }
}

/// Some row of `s` holds `key`.
pub open spec fn held_key(s: Seq<Entry>, key: u64) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].key == key
}

/// No key is held under two rows.
pub open spec fn unique_keys(s: Seq<Entry>) -> bool {
    forall|i: int, j: int| 0 <= i < j < s.len() ==> s[i].key != s[j].key
}

/// Every entry of `before` in another row than `row` is still in `now`.
pub open spec fn keeps_other_rows(now: Seq<Entry>, before: Seq<Entry>, row: u32) -> bool {
    forall|k: int| 0 <= k < before.len() && before[k].row != row ==> has(now, #[trigger] before[k])
}

/// `e`'s row and key are held in `now`, with a deadline not earlier.
pub open spec fn kept_by_key(now: Seq<Entry>, e: Entry) -> bool {
    exists|j: int| 0 <= j < now.len() && now[j].row == e.row && now[j].key == e.key
        && now[j].deadline_ms >= e.deadline_ms
}

/// Some row of `s` holds `key` with a deadline of at least `limit`.
pub open spec fn held_until(s: Seq<Entry>, key: u64, limit: u64) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].key == key && s[j].deadline_ms >= limit
}

/// No entry of `now` ends later than both `limit` and the entry of `before`
/// with its row and key.
pub open spec fn bounded_by_key(now: Seq<Entry>, before: Seq<Entry>, limit: u64) -> bool {
    forall|j: int, k: int| 0 <= j < now.len() && 0 <= k < before.len()
        && (#[trigger] now[j]).row == (#[trigger] before[k]).row && now[j].key == before[k].key
        ==> now[j].deadline_ms <= before[k].deadline_ms || now[j].deadline_ms <= limit
}

/// Removing entries keeps keys unique.
pub proof fn lemma_unique_subset(now: Seq<Entry>, before: Seq<Entry>)
    requires
        unique_keys(before),
        distinct_keys(now),
        subset_of(now, before),
    ensures
        unique_keys(now),
{
    reveal(crate::pool::distinct_keys);
    assert forall|i: int, j: int| 0 <= i < j < now.len() implies now[i].key != now[j].key by {
        assert(has(before, now[i]));
        assert(has(before, now[j]));
        let a = choose|a: int| 0 <= a < before.len() && before[a] == now[i];
        let b = choose|b: int| 0 <= b < before.len() && before[b] == now[j];
        if now[i].key == now[j].key {
            if a < b {
                assert(before[a].key != before[b].key);
            } else if b < a {
                assert(before[b].key != before[a].key);
            } else {
                assert(!(now[i].row == now[j].row && now[i].key == now[j].key));
            }
        }
    }
}

/// Replacing one entry in place keeps keys unique.
pub proof fn lemma_unique_refreshed(now: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64)
    requires
        unique_keys(before),
        refreshed_from(now, before, row, key),
    ensures
        unique_keys(now),
{
    assert forall|i: int, j: int| 0 <= i < j < now.len() implies now[i].key != now[j].key by {
        assert(now[i].key == before[i].key);
        assert(now[j].key == before[j].key);
        assert(before[i].key != before[j].key);
    }
}

/// Adding an entry whose key no row holds keeps keys unique.
pub proof fn lemma_unique_push(s: Seq<Entry>, e: Entry)
    requires
        unique_keys(s),
        !held_key(s, e.key),
    ensures
        unique_keys(s.push(e)),
{
    let t = s.push(e);
    assert forall|i: int, j: int| 0 <= i < j < t.len() implies t[i].key != t[j].key by {
        if j < s.len() {
            assert(t[i] == s[i] && t[j] == s[j]);
        } else {
            assert(t[i] == s[i] && t[j] == e);
            assert(s[i].key == s[i].key);
        }
    }
}

/// Some row of `s` holds `key` in an entry that has not expired at `now_ms`.
pub open spec fn live_key(s: Seq<Entry>, key: u64, now_ms: u64) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].key == key && s[j].deadline_ms > now_ms
}

/// `now` is `before` with the entry for `(row, key)` replaced: the same
/// length, and at each position either the same entry or the entry for
/// `(row, key)` on both sides.
pub open spec fn refreshed_from(now: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64) -> bool {
    &&& now.len() == before.len()
    &&& forall|j: int| 0 <= j < now.len() ==> (#[trigger] now[j]) == before[j] || (now[j].row == row
        && now[j].key == key && before[j].row == row && before[j].key == key)
}

/// The entry for `row` and `key` now ends at the later of its old deadline
/// and `fresh`, and has value `v`, or its old value when `v` is `None`: a
/// refresh that does nothing is not a refresh.
/// Opaque: a caller that only passes this on does not unfold it. The four
/// functions that establish it reveal it.
#[verifier::opaque]
pub open spec fn extended(now: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, fresh: u64, v: Option<u32>) -> bool {
    exists|e: Entry| #[trigger] has(before, e) && e.row == row && e.key == key
        && has(now, Entry {
            row,
            key,
            deadline_ms: if e.deadline_ms >= fresh { e.deadline_ms } else { fresh },
            value: match v {
                Some(x) => x,
                None => e.value,
            },
        })
}

} // verus!

/// [`rank_of`] as a number the code can compare.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used once the table is kept sorted")
)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r as int == rank_of(row, key),
))]
fn rank_exec(row: u32, key: u64) -> u128 {
    (row as u128) * 18446744073709551616 + (key as u128)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Pool {
    /// An empty table. `None` when the quota exceeds the capacity.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(p) => inv(p) && view(p).len() == 0 && spec_cap(p) == cap && spec_quota(p) == quota,
                None => quota > cap,
            },
    ))]
    pub fn new(cap: usize, quota: usize) -> Option<Pool> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        if quota > cap {
            return None;
        }
        Some(Pool {
            entries: Vec::new(),
            cap,
            quota,
        })
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == view(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// How many entries have not expired at `now_ms`. Changes nothing: for
    /// comparing a table with another, not for deciding.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r == live_number(view(*self), now.ms),
            r <= view(*self).len(),
    ))]
    pub fn live_count(&self, now: Instant) -> usize {
        let mut n: usize = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                n == live_number(self.entries@.take(i as int), now.ms),
                n <= i,
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            #[cfg(verus_keep_ghost)]
            proof! {
                let s = self.entries@;
                assert(s.take(i as int + 1).drop_last() =~= s.take(i as int));
                assert(s.take(i as int + 1).last() == s[i as int]);
            }
            if self.entries[i].deadline_ms > now.ms {
                n += 1;
            }
            i += 1;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(self.entries@.take(self.entries@.len() as int) =~= self.entries@);
        }
        n
    }

    /// How many entries `row` holds.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r as nat == count(view(*self), row),
    ))]
    pub fn row_count(&self, row: u32) -> usize {
        let mut n: usize = 0;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                n <= i,
                n as nat == count(self.entries@.take(i as int), row),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_count_take(self.entries@, i as int, row);
            }
            if self.entries[i].row == row {
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

    /// Where the entry for `(row, key)` is, if the table holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(i) => i < view(*self).len() && view(*self)[i as int].row == row
                    && view(*self)[i as int].key == key,
                None => !holds(view(*self), row, key),
            },
    ))]
    fn find(&self, row: u32, key: u64) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> !(self.entries@[j].row == row && self.entries@[j].key == key),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].row == row && self.entries[i].key == key {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// The deadline of `(row, key)`, if the table holds it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r.is_some() == holds(view(*self), row, key),
            match r {
                Some(d) => exists|v: u32| #[trigger] has(view(*self), Entry { row, key, deadline_ms: d, value: v }),
                None => true,
            },
    ))]
    pub fn get(&self, row: u32, key: u64) -> Option<u64> {
        match self.find(row, key) {
            Some(i) => {
                let d = self.entries[i].deadline_ms;
                #[cfg(verus_keep_ghost)]
                proof! {
                    let v = self.entries@[i as int].value;
                    assert(self.entries@[i as int] == Entry { row, key, deadline_ms: d, value: v });
                    assert(has(view(*self), Entry { row, key, deadline_ms: d, value: v }));
                    let r: Option<u64> = Some(d);
                    assert(match r {
                        Some(d) => exists|v: u32| #[trigger] has(view(*self), Entry { row, key, deadline_ms: d, value: v }),
                        None => true,
                    });
                }
                Some(d)
            }
            None => None,
        }
    }

    /// The first position whose entry ranks at or above `target`, in a sorted
    /// table: every entry before it ranks below, every entry from it on ranks
    /// at or above. Not yet called: the table is not kept sorted yet.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used once the table is kept sorted")
    )]
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            sorted(view(*self)),
        ensures
            r <= view(*self).len(),
            forall|i: int| 0 <= i < r ==> rank(#[trigger] view(*self)[i]) < target,
            forall|i: int| r <= i < view(*self).len() ==> rank(#[trigger] view(*self)[i]) >= target,
    ))]
    fn lower_bound(&self, target: u128) -> usize {
        let mut lo: usize = 0;
        let mut hi: usize = self.entries.len();
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                lo <= hi <= self.entries.len(),
                sorted(self.entries@),
                forall|i: int| 0 <= i < lo ==> rank(#[trigger] self.entries@[i]) < target,
                forall|i: int| hi <= i < self.entries.len() ==> rank(#[trigger] self.entries@[i]) >= target,
            decreases hi - lo,
        ))]
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let e = self.entries[mid];
            if rank_exec(e.row, e.key) < target {
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert forall|i: int| 0 <= i < mid + 1 implies rank(#[trigger] self.entries@[i]) < target by {
                        if i < mid {
                            assert(rank(self.entries@[i]) < rank(self.entries@[mid as int]));
                        }
                    }
                }
                lo = mid + 1;
            } else {
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert forall|i: int| mid <= i < self.entries.len() implies rank(#[trigger] self.entries@[i]) >= target by {
                        if mid < i {
                            assert(rank(self.entries@[mid as int]) < rank(self.entries@[i]));
                        }
                    }
                }
                hi = mid;
            }
        }
        lo
    }

    /// Replaces the entry at `i` by one with the same row and key. The one
    /// place a held entry is rewritten.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            inv(*old(self)),
            i < view(*old(self)).len(),
            view(*old(self))[i as int].row == entry.row,
            view(*old(self))[i as int].key == entry.key,
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            view(*final(self)) == view(*old(self)).update(i as int, entry),
    ))]
    fn set_at(&mut self, i: usize, entry: Entry) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        self.entries[i] = entry;
        #[cfg(verus_keep_ghost)]
        proof! {
            let before = old(self).entries@;
            let after = before.update(i as int, entry);
            assert(self.entries@ =~= after);
            assert(after[i as int] == entry);
            // The replaced entry has the row and key of the one it replaces, so no
            // pair of positions gains a shared row and key.
            assert forall|a: int, b: int| 0 <= a < b < after.len() implies !(after[a].row
                == after[b].row && after[a].key == after[b].key) by {
                assert(!(before[a].row == before[b].row && before[a].key == before[b].key));
            }
            assert(distinct_keys(after));
            // No row's count changed, so each is still within the quota.
            assert forall|r: u32| count(self.entries@, r) <= self.quota by {
                lemma_count_update(before, i as int, entry, r);
                assert(count(before, r) <= old(self).quota);
            }
        }
    }

    /// Adds an entry the table does not hold, where there is room for it. The
    /// one place the table grows.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            inv(*old(self)),
            !holds(view(*old(self)), entry.row, entry.key),
            count(view(*old(self)), entry.row) < spec_quota(*old(self)),
            view(*old(self)).len() < spec_cap(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            added(view(*final(self)), view(*old(self)), entry),
    ))]
    fn push_new(&mut self, entry: Entry) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let before = self.entries@;
            lemma_added_push(before, entry);
            assert forall|r: u32| count(before.push(entry), r) <= self.quota by {
                lemma_count_push(before, entry, r);
            }
            // The table does not hold this row and key, so the pushed entry is
            // distinct from every one before it.
            let after = before.push(entry);
            assert forall|a: int, b: int| 0 <= a < b < after.len() implies !(after[a].row
                == after[b].row && after[a].key == after[b].key) by {
                if b == before.len() {
                    assert(!holds(before, entry.row, entry.key));
                    assert(!(before[a].row == entry.row && before[a].key == entry.key));
                } else {
                    assert(!(before[a].row == before[b].row && before[a].key == before[b].key));
                }
            }
            assert(distinct_keys(after));
        }
        self.entries.push(entry);
    }

    /// The entry for `(row, key)`, if the table holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(e) => e.row == row && e.key == key && has(view(*self), e),
                None => !holds(view(*self), row, key),
            },
    ))]
    pub fn entry(&self, row: u32, key: u64) -> Option<Entry> {
        match self.find(row, key) {
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

    /// Whether the table holds `(row, key)` in an entry that has not
    /// expired. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*self),
        ensures
            r == crate::flow::live(view(*self), row, key, now.ms),
    ))]
    pub fn live(&self, row: u32, key: u64, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        match self.find(row, key) {
            Some(i) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let s = self.entries@;
                    // Keys are distinct, so position `i` is the only one with this row and key.
                    assert forall|j: int| 0 <= j < s.len() && s[j].row == row && s[j].key == key implies j == i by {
                        if j < i {
                            assert(!(s[j].row == s[i as int].row && s[j].key == s[i as int].key));
                        } else if j > i {
                            assert(!(s[i as int].row == s[j].row && s[i as int].key == s[j].key));
                        }
                    }
                }
                self.entries[i].deadline_ms > now.ms
            }
            None => false,
        }
    }

    /// Whether any row holds `key` in an entry that has not expired.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r == live_key(view(*self), key, now.ms),
    ))]
    pub fn any_live(&self, key: u64, now: Instant) -> bool {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> !(self.entries@[j].key == key && self.entries@[j].deadline_ms > now.ms),
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].key == key && self.entries[i].deadline_ms > now.ms {
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(self.entries@[i as int].key == key && self.entries@[i as int].deadline_ms > now.ms);
                }
                return true;
            }
            i += 1;
        }
        false
    }

    /// An entry that holds `key`, under whichever row, if any does.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(e) => has(view(*self), e) && e.key == key,
                None => !held_key(view(*self), key),
            },
    ))]
    pub fn holder(&self, key: u64) -> Option<Entry> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> self.entries@[j].key != key,
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].key == key {
                let e = self.entries[i];
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(self.entries@[i as int] == e);
                }
                return Some(e);
            }
            i += 1;
        }
        None
    }

    /// Replaces the deadline and the value of `(row, key)` and nothing else.
    /// Returns whether the table held it; when it did not, nothing changes.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            r == holds(view(*old(self)), row, key),
            r ==> refreshed_from(view(*final(self)), view(*old(self)), row, key),
            r ==> has(view(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value }),
            r ==> changed_only_to(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value }),
            !r ==> view(*final(self)) == view(*old(self)),
    ))]
    pub fn set(&mut self, row: u32, key: u64, deadline: Instant, value: u32) -> bool {
        let entry = Entry {
            row,
            key,
            deadline_ms: deadline.ms,
            value,
        };
        match self.find(row, key) {
            Some(i) => {
                self.set_at(i, entry);
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(self.entries@[i as int] == entry);
                }
                true
            }
            None => false,
        }
    }

    /// Removes every entry.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            view(*final(self)).len() == 0,
    ))]
    pub fn clear(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        self.entries = Vec::new();
    }

    /// Adds `(row, key)` or replaces its deadline and value. Refuses, changing
    /// nothing, when the row is at its quota or the table is full.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            match r {
                Inserted::New => {
                    &&& !holds(view(*old(self)), row, key)
                    &&& added(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::Refreshed => {
                    &&& holds(view(*old(self)), row, key)
                    &&& view(*final(self)).len() == view(*old(self)).len()
                    &&& refreshed_from(view(*final(self)), view(*old(self)), row, key)
                    &&& changed_only_to(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& has(view(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::RowAtQuota => {
                    &&& view(*final(self)) == view(*old(self))
                    &&& !holds(view(*final(self)), row, key)
                    &&& count(view(*final(self)), row) >= spec_quota(*final(self))
                },
                Inserted::PoolFull => {
                    &&& view(*final(self)) == view(*old(self))
                    &&& !holds(view(*final(self)), row, key)
                    &&& view(*final(self)).len() >= spec_cap(*final(self))
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
        match self.find(row, key) {
            Some(i) => {
                self.set_at(i, entry);
                #[cfg(verus_keep_ghost)]
                proof! {
                    assert(self.entries@[i as int] == entry);
                }
                Inserted::Refreshed
            }
            None => {
                if self.row_count(row) >= self.quota {
                    return Inserted::RowAtQuota;
                }
                if self.entries.len() >= self.cap {
                    return Inserted::PoolFull;
                }
                self.push_new(entry);
                Inserted::New
            }
        }
    }

    /// Where an expired entry is, if the table holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(j) => j < view(*self).len() && view(*self)[j as int].deadline_ms <= now_ms,
                None => none_expired(view(*self), now_ms),
            },
    ))]
    fn find_expired(&self, now_ms: u64) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i ==> (#[trigger] self.entries@[j]).deadline_ms > now_ms,
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].deadline_ms <= now_ms {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Where an expired entry of `row` is, if the table holds one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(j) => j < view(*self).len() && view(*self)[j as int].row == row
                    && view(*self)[j as int].deadline_ms <= now_ms,
                None => row_live(view(*self), row, now_ms),
            },
    ))]
    fn find_expired_in_row(&self, row: u32, now_ms: u64) -> Option<usize> {
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                i <= self.entries.len(),
                forall|j: int| 0 <= j < i && (#[trigger] self.entries@[j]).row == row ==> self.entries@[j].deadline_ms > now_ms,
            decreases self.entries.len() - i,
        ))]
        while i < self.entries.len() {
            if self.entries[i].row == row && self.entries[i].deadline_ms <= now_ms {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Looks the key up and counts the row once. As [`Pool::insert`], except
    /// that where `insert` would refuse, one
    /// expired entry is removed first to make room: one of the same row when
    /// the row is at its quota, any one when the table is full. A refusal
    /// therefore means the row, or the table, is full of entries that have
    /// not expired, and it changes nothing. An entry that has not expired is
    /// never removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            match r {
                Inserted::New => {
                    &&& !holds(view(*old(self)), row, key)
                    &&& has(view(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& only_adds(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& keeps_live(view(*final(self)), view(*old(self)), now.ms)
                    &&& view(*final(self)).len() <= view(*old(self)).len() + 1
                    // At most one entry is given up, and only where `insert`
                    // would have refused; at the row's quota, one of the row.
                    &&& view(*final(self)).len() >= view(*old(self)).len()
                    &&& (count(view(*old(self)), row) < spec_quota(*old(self)) && view(*old(self)).len() < spec_cap(*old(self)))
                        ==> added(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& count(view(*old(self)), row) >= spec_quota(*old(self))
                        ==> keeps_other_rows(view(*final(self)), view(*old(self)), row)
                },
                Inserted::Refreshed => {
                    &&& holds(view(*old(self)), row, key)
                    &&& refreshed_from(view(*final(self)), view(*old(self)), row, key)
                    &&& changed_only_to(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                    &&& has(view(*final(self)), Entry { row, key, deadline_ms: deadline.ms, value })
                },
                Inserted::RowAtQuota => {
                    &&& view(*final(self)) == view(*old(self))
                    &&& !holds(view(*final(self)), row, key)
                    &&& count(view(*final(self)), row) >= spec_quota(*final(self))
                    &&& row_live(view(*final(self)), row, now.ms)
                },
                Inserted::PoolFull => {
                    &&& view(*final(self)) == view(*old(self))
                    &&& !holds(view(*final(self)), row, key)
                    &&& view(*final(self)).len() >= spec_cap(*final(self))
                    &&& none_expired(view(*final(self)), now.ms)
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
        if let Some(i) = self.find(row, key) {
            self.set_at(i, entry);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_reclaiming_refreshed(*old(self), *self, row, key, deadline.ms, value, i as int);
            }
            return Inserted::Refreshed;
        }
        // Where the removed entry was, or -1 when nothing is removed.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut gone: int = -1;
        }
        if self.row_count(row) >= self.quota {
            match self.find_expired_in_row(row, now.ms) {
                Some(j) => {
                    self.remove_at(j);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        // One entry of this row went, so the row is below its quota and the table below its capacity.
                        gone = j as int;
                        lemma_reclaiming_room(*old(self), *self, row, key, gone);
                    }
                }
                None => return Inserted::RowAtQuota,
            }
        } else if self.entries.len() >= self.cap {
            match self.find_expired(now.ms) {
                Some(j) => {
                    self.remove_at(j);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        gone = j as int;
                        lemma_reclaiming_room(*old(self), *self, row, key, gone);
                    }
                }
                None => return Inserted::PoolFull,
            }
        }
        // The table between the removal, if there was one, and the insert.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mid: Seq<Entry> = self.entries@;
        }
        self.push_new(entry);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_reclaiming_new(*old(self), *self, row, key, deadline.ms, value, now.ms, mid, gone);
            lemma_reclaiming_given_up(view(*old(self)), mid, view(*self), gone, Entry { row, key, deadline_ms: deadline.ms, value });
        }
        Inserted::New
    }

    /// Removes the entry at `i`.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            inv(*old(self)),
            i < view(*old(self)).len(),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            view(*final(self)) == view(*old(self)).remove(i as int),
    ))]
    fn remove_at(&mut self, i: usize) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let before = self.entries@;
            let after = before.remove(i as int);
            assert forall|r: u32| count(after, r) <= self.quota by {
                lemma_count_remove(before, i as int, r);
            }
            assert forall|a: int, b: int| 0 <= a < b < after.len() implies !(after[a].row
                == after[b].row && after[a].key == after[b].key) by {
                let a0 = if a < i { a } else { a + 1 };
                let b0 = if b < i { b } else { b + 1 };
                assert(after[a] == before[a0] && after[b] == before[b0]);
                assert(!(before[a0].row == before[b0].row && before[a0].key == before[b0].key));
            }
            assert(distinct_keys(after));
        }
        self.entries.remove(i);
    }

    /// Removes `(row, key)`. Returns whether the table held it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            r == holds(view(*old(self)), row, key),
            !holds(view(*final(self)), row, key),
            subset_of(view(*final(self)), view(*old(self))),
            view(*final(self)).len() + (if r { 1int } else { 0int }) == view(*old(self)).len(),
            keeps_others(view(*final(self)), view(*old(self)), row, key),
            !r ==> view(*final(self)) == view(*old(self)),
    ))]
    pub fn remove(&mut self, row: u32, key: u64) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        match self.find(row, key) {
            Some(i) => {
                self.remove_at(i);
                #[cfg(verus_keep_ghost)]
                proof! {
                    let before = old(self).entries@;
                    let after = self.entries@;
                    assert(after =~= before.remove(i as int));
                    // Keys were distinct, so the one removed was the only entry with this row and key.
                    assert forall|j: int| 0 <= j < after.len() implies !(after[j].row == row
                        && after[j].key == key) by {
                        let j0 = if j < i { j } else { j + 1 };
                        assert(after[j] == before[j0]);
                        if j0 < i {
                            assert(!(before[j0].row == before[i as int].row && before[j0].key == before[i as int].key));
                        } else {
                            assert(!(before[i as int].row == before[j0].row && before[i as int].key == before[j0].key));
                        }
                    }
                    assert forall|j: int| 0 <= j < after.len() implies has(before, #[trigger] after[j]) by {
                        let j0 = if j < i { j } else { j + 1 };
                        assert(before[j0] == after[j]);
                    }
                    assert forall|k: int| 0 <= k < before.len() && !(before[k].row == row && before[k].key
                        == key) implies has(after, #[trigger] before[k]) by {
                        assert(k != i);
                        let k0 = if k < i { k } else { k - 1 };
                        assert(after[k0] == before[k]);
                    }
                }
                true
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let s = self.entries@;
                    assert forall|j: int| 0 <= j < s.len() implies has(s, #[trigger] s[j]) by {
                        assert(s[j] == s[j]);
                    }
                    assert forall|k: int| 0 <= k < s.len() && !(s[k].row == row && s[k].key == key) implies has(s, #[trigger] s[k]) by {
                        assert(s[k] == s[k]);
                    }
                }
                false
            }
        }
    }

    /// Removes entries whose deadline is at or before `now_ms`, at most
    /// `budget` of them, and returns how many it removed. Entries that have
    /// not expired are never removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            r <= budget,
            view(*final(self)).len() + r == view(*old(self)).len(),
            subset_of(view(*final(self)), view(*old(self))),
            keeps_live(view(*final(self)), view(*old(self)), now.ms),
            r < budget ==> none_expired(view(*final(self)), now.ms),
            r == 0 ==> view(*final(self)) == view(*old(self)),
            r > 0 ==> !none_expired(view(*old(self)), now.ms),
    ))]
    pub fn expire(&mut self, now: Instant, budget: usize) -> usize {
        // One pass: each entry that stays is written down to the next free
        // place, then the tail is dropped. `g` is the table as it would be
        // had each expired entry been removed when it was met.
        let n = self.entries.len();
        let mut removed: usize = 0;
        let mut i: usize = 0;
        let mut w: usize = 0;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = self.entries@;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let s = self.entries@;
            assert forall|j: int| 0 <= j < s.len() implies has(s, #[trigger] s[j]) by {
                assert(s[j] == s[j]);
            }
            assert forall|k: int| 0 <= k < s.len() && s[k].deadline_ms > now.ms implies has(s, #[trigger] s[k]) by {
                assert(s[k] == s[k]);
            }
            assert(expire_carries(s, s, self.cap as int, self.quota as int, now.ms)) by {
                reveal(expire_carries);
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                n == self.entries@.len(),
                n == old(self).entries@.len(),
                w <= i,
                i <= n,
                w + removed == i,
                removed <= budget,
                g.len() == w + (n - i),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
                forall|j: int| w <= j < g.len() ==> #[trigger] g[j] == self.entries@[j + removed],
                expire_carries(g, old(self).entries@, self.cap as int, self.quota as int, now.ms),
                removed < budget ==> forall|j: int| 0 <= j < w ==> (#[trigger] g[j]).deadline_ms > now.ms,
                removed == 0 ==> self.entries@ == old(self).entries@,
                removed > 0 ==> !none_expired(old(self).entries@, now.ms),
            decreases n - i,
        ))]
        while i < n {
            let e = self.entries[i];
            if removed < budget && e.deadline_ms <= now.ms {
                #[cfg(verus_keep_ghost)]
                proof! {
                    reveal(expire_carries);
                    let first = old(self).entries@;
                    let next = g.remove(w as int);
                    assert(g[w as int] == e);
                    lemma_remove_within_caps(g, w as int, self.cap as int, self.quota as int);
                    lemma_remove_subset(g, first, w as int);
                    lemma_remove_keeps_live(g, first, w as int, now.ms);
                    // The entry removed was an entry at loop entry, and it has expired.
                    lemma_subset_member(g, first, w as int);
                    g = next;
                }
                removed += 1;
                i += 1;
            } else {
                if w != i {
                    self.entries[w] = e;
                }
                w += 1;
                i += 1;
            }
        }
        // Drop the places past the last entry kept.
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                g.len() == w,
                w <= self.entries@.len(),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
            decreases self.entries@.len() - w,
        ))]
        while self.entries.len() > w {
            let _ = self.entries.pop();
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(expire_carries);
            assert(self.entries@ =~= g);
        }
        removed
    }

    /// Removes the entry for `(row, key)` if it has expired at `now_ms`, in
    /// place, and says whether it did. A live entry, and every other entry,
    /// stays where it is.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            r == expired_held(view(*old(self)), row, key, now.ms),
            dropped_if_expired(view(*final(self)), view(*old(self)), row, key, now.ms),
    ))]
    pub fn drop_expired(&mut self, row: u32, key: u64, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        match self.find(row, key) {
            Some(i) => {
                if self.entries[i].deadline_ms <= now.ms {
                    self.remove_at(i);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        reveal(dropped_if_expired);
                        assert(expired_at(old(self).entries@, row, key, now.ms, i as int));
                    }
                    true
                } else {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        reveal(dropped_if_expired);
                        let s = self.entries@;
                        // Keys are distinct, so position `i` is the only one with this row and key.
                        assert forall|j: int| !expired_at(s, row, key, now.ms, j) by {
                            if 0 <= j < s.len() && s[j].row == row && s[j].key == key {
                                if j < i {
                                    assert(!(s[j].row == s[i as int].row && s[j].key == s[i as int].key));
                                } else if j > i {
                                    assert(!(s[i as int].row == s[j].row && s[i as int].key == s[j].key));
                                }
                            }
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

    /// Adds an entry for a key the table does not hold, in a table with no
    /// quota below its capacity. At the capacity it first removes every
    /// expired entry, unless a sweep ran less than the interval ago. Returns
    /// what it did and the throttle to keep.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
            spec_quota(*old(self)) == spec_cap(*old(self)),
            !holds(view(*old(self)), row, key),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            r.1.interval_ms == th.interval_ms,
            (r.0 == Swept::New) == (view(*old(self)).len() < spec_cap(*old(self))),
            (r.0 == Swept::Throttled) == (view(*old(self)).len() >= spec_cap(*old(self)) && !due(th, now.ms)),
            (r.0 == Swept::Full) == (view(*old(self)).len() >= spec_cap(*old(self)) && due(th, now.ms)
                && none_expired(view(*old(self)), now.ms)),
            r.1.last_ms == (if r.0 == Swept::SweptNew || r.0 == Swept::Full { Some(now.ms) } else { th.last_ms }),
            r.0 == Swept::New ==> added(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value }),
            r.0 == Swept::SweptNew ==> swept_and_added(view(*final(self)), view(*old(self)), Entry { row, key, deadline_ms: deadline.ms, value }, now.ms),
            r.0 == Swept::Full || r.0 == Swept::Throttled ==> view(*final(self)) == view(*old(self)),
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
        if self.entries.len() < self.cap {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_count_le_len(self.entries@, row);
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
        let n = self.entries.len();
        let removed = self.expire(now, n);
        if removed == 0 {
            return (Swept::Full, stamped);
        }
        // The table between the sweep and the insert.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mid: Seq<Entry> = self.entries@;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            // Either the budget was not reached, or every entry went.
            assert(none_expired(mid, now.ms));
            lemma_subset_not_held(old(self).entries@, mid, row, key);
            lemma_count_le_len(mid, row);
        }
        self.push_new(entry);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_swept_added(old(self).entries@, mid, self.entries@, entry, now.ms);
        }
        (Swept::SweptNew, stamped)
    }

    /// Removes every entry, of any row and expired or not, whose key has
    /// `hi` above bit 32 and `lo` in its low 16 bits, and returns how many.
    /// No other entry is removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            view(*final(self)).len() + r == view(*old(self)).len(),
            subset_of(view(*final(self)), view(*old(self))),
            keeps_unmatched(view(*final(self)), view(*old(self)), hi, lo),
            none_ending(view(*final(self)), hi, lo),
    ))]
    pub fn remove_ends(&mut self, hi: u64, lo: u64) -> usize {
        // One pass, as `expire`: `g` is the table had each matching entry
        // been removed when it was met.
        let n = self.entries.len();
        let mut removed: usize = 0;
        let mut i: usize = 0;
        let mut w: usize = 0;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = self.entries@;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let s = self.entries@;
            assert forall|j: int| 0 <= j < s.len() implies has(s, #[trigger] s[j]) by {
                assert(s[j] == s[j]);
            }
            assert forall|k: int| 0 <= k < s.len() && !key_ends(s[k].key, hi, lo) implies has(s, #[trigger] s[k]) by {
                assert(s[k] == s[k]);
            }
            assert(ends_carries(s, s, self.cap as int, self.quota as int, hi, lo)) by {
                reveal(ends_carries);
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                n == self.entries@.len(),
                n == old(self).entries@.len(),
                w <= i,
                i <= n,
                w + removed == i,
                g.len() == w + (n - i),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
                forall|j: int| w <= j < g.len() ==> #[trigger] g[j] == self.entries@[j + removed],
                ends_carries(g, old(self).entries@, self.cap as int, self.quota as int, hi, lo),
                forall|j: int| 0 <= j < w ==> !key_ends((#[trigger] g[j]).key, hi, lo),
            decreases n - i,
        ))]
        while i < n {
            let e = self.entries[i];
            if e.key / 4294967296 == hi && e.key % 65536 == lo {
                #[cfg(verus_keep_ghost)]
                proof! {
                    reveal(ends_carries);
                    let first = old(self).entries@;
                    let next = g.remove(w as int);
                    assert(g[w as int] == e);
                    lemma_remove_within_caps(g, w as int, self.cap as int, self.quota as int);
                    lemma_remove_subset(g, first, w as int);
                    lemma_remove_keeps_unmatched(g, first, w as int, hi, lo);
                    g = next;
                }
                removed += 1;
                i += 1;
            } else {
                if w != i {
                    self.entries[w] = e;
                }
                w += 1;
                i += 1;
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                g.len() == w,
                w <= self.entries@.len(),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
            decreases self.entries@.len() - w,
        ))]
        while self.entries.len() > w {
            let _ = self.entries.pop();
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ends_carries);
            assert(self.entries@ =~= g);
        }
        removed
    }

    /// Removes every entry of `row` whose deadline is at or before `now_ms`
    /// and returns how many. No entry of another row is removed, and none
    /// that has not expired.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            inv(*old(self)),
        ensures
            inv(*final(self)),
            spec_cap(*final(self)) == spec_cap(*old(self)),
            spec_quota(*final(self)) == spec_quota(*old(self)),
            view(*final(self)).len() + r == view(*old(self)).len(),
            subset_of(view(*final(self)), view(*old(self))),
            keeps_live(view(*final(self)), view(*old(self)), now.ms),
            keeps_other_rows(view(*final(self)), view(*old(self)), row),
            row_live(view(*final(self)), row, now.ms),
    ))]
    pub fn release_expired(&mut self, row: u32, now: Instant) -> usize {
        // One pass, as `expire`: `g` is the table had each entry released
        // been removed when it was met.
        let n = self.entries.len();
        let mut removed: usize = 0;
        let mut i: usize = 0;
        let mut w: usize = 0;
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost mut g: Seq<Entry> = self.entries@;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            let s = self.entries@;
            assert forall|j: int| 0 <= j < s.len() implies has(s, #[trigger] s[j]) by {
                assert(s[j] == s[j]);
            }
            assert forall|k: int| 0 <= k < s.len() && s[k].deadline_ms > now.ms implies has(s, #[trigger] s[k]) by {
                assert(s[k] == s[k]);
            }
            assert forall|k: int| 0 <= k < s.len() && s[k].row != row implies has(s, #[trigger] s[k]) by {
                assert(s[k] == s[k]);
            }
            assert(release_carries(s, s, self.cap as int, self.quota as int, now.ms, row)) by {
                reveal(release_carries);
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                n == self.entries@.len(),
                n == old(self).entries@.len(),
                w <= i,
                i <= n,
                w + removed == i,
                g.len() == w + (n - i),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
                forall|j: int| w <= j < g.len() ==> #[trigger] g[j] == self.entries@[j + removed],
                release_carries(g, old(self).entries@, self.cap as int, self.quota as int, now.ms, row),
                forall|j: int| 0 <= j < w && (#[trigger] g[j]).row == row ==> g[j].deadline_ms > now.ms,
            decreases n - i,
        ))]
        while i < n {
            let e = self.entries[i];
            if e.row == row && e.deadline_ms <= now.ms {
                #[cfg(verus_keep_ghost)]
                proof! {
                    reveal(release_carries);
                    let first = old(self).entries@;
                    let next = g.remove(w as int);
                    assert(g[w as int] == e);
                    lemma_remove_within_caps(g, w as int, self.cap as int, self.quota as int);
                    lemma_remove_subset(g, first, w as int);
                    lemma_remove_keeps_live(g, first, w as int, now.ms);
                    lemma_remove_keeps_other_rows(g, first, w as int, row);
                    g = next;
                }
                removed += 1;
                i += 1;
            } else {
                if w != i {
                    self.entries[w] = e;
                }
                w += 1;
                i += 1;
            }
        }
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                self.cap == old(self).cap,
                self.quota == old(self).quota,
                g.len() == w,
                w <= self.entries@.len(),
                forall|j: int| 0 <= j < w ==> #[trigger] g[j] == self.entries@[j],
            decreases self.entries@.len() - w,
        ))]
        while self.entries.len() > w {
            let _ = self.entries.pop();
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(release_carries);
            assert(self.entries@ =~= g);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_finds_a_key_under_any_row() {
        let mut p = Pool::new(8, 2).unwrap();
        assert!(p.holder(10).is_none());
        assert_eq!(p.insert(1, 10, Instant { ms: 5 }, 7), Inserted::New);
        let held = Entry {
            row: 1,
            key: 10,
            deadline_ms: 5,
            value: 7,
        };
        assert!(p.holder(10) == Some(held));
        assert!(p.holder(11).is_none());
    }

    #[test]
    fn release_expired_removes_one_rows_expired_entries_only() {
        let mut p = Pool::new(8, 3).unwrap();
        assert_eq!(p.insert(1, 10, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 11, Instant { ms: 9 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 12, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 13, Instant { ms: 5 }, 0), Inserted::New);
        assert_eq!(p.release_expired(1, Instant { ms: 5 }), 2);
        assert_eq!(p.len(), 2);
        assert_eq!(p.row_count(1), 1);
        assert_eq!(p.row_count(2), 1);
        assert_eq!(p.release_expired(1, Instant { ms: 5 }), 0);
    }

    #[test]
    fn a_row_stops_at_its_quota_and_others_are_unaffected() {
        let mut p = Pool::new(8, 2).unwrap();
        assert_eq!(p.insert(1, 10, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 11, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 12, Instant { ms: 0 }, 0), Inserted::RowAtQuota);
        assert_eq!(p.insert(2, 12, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.row_count(1), 2);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn the_table_stops_at_its_capacity() {
        let mut p = Pool::new(2, 2).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 1, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(3, 1, Instant { ms: 0 }, 0), Inserted::PoolFull);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn a_held_key_is_refreshed_even_when_the_row_is_at_quota() {
        let mut p = Pool::new(4, 1).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 7, Instant { ms: 200 }, 0), Inserted::Refreshed);
        assert_eq!(p.get(1, 7), Some(200));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn a_full_row_takes_a_new_entry_in_place_of_an_expired_one() {
        let mut p = Pool::new(4, 2).unwrap();
        assert_eq!(p.insert(1, 10, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 11, Instant { ms: 500 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 10, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(
            p.insert_reclaiming(1, 12, Instant { ms: 900 }, 0, Instant { ms: 50 }),
            Inserted::RowAtQuota
        );
        assert_eq!(p.len(), 3);
        assert_eq!(
            p.insert_reclaiming(1, 12, Instant { ms: 900 }, 0, Instant { ms: 100 }),
            Inserted::New
        );
        assert_eq!(p.get(1, 10), None);
        assert_eq!(p.get(1, 11), Some(500));
        assert_eq!(p.get(2, 10), Some(100));
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn a_full_table_takes_a_new_entry_in_place_of_an_expired_one_of_any_row() {
        let mut p = Pool::new(2, 2).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 1, Instant { ms: 500 }, 0), Inserted::New);
        assert_eq!(
            p.insert_reclaiming(3, 1, Instant { ms: 900 }, 0, Instant { ms: 50 }),
            Inserted::PoolFull
        );
        assert_eq!(
            p.insert_reclaiming(3, 1, Instant { ms: 900 }, 0, Instant { ms: 200 }),
            Inserted::New
        );
        assert_eq!(p.get(1, 1), None);
        assert_eq!(p.get(2, 1), Some(500));
    }

    #[test]
    fn lower_bound_finds_the_first_entry_at_or_above_a_rank() {
        let mut p = Pool::new(8, 8).unwrap();
        // Inserted in increasing order of (row, key), so the table is sorted.
        assert_eq!(p.insert(1, 5, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 9, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(3, 0, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(3, u64::MAX, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.lower_bound(rank_exec(0, 0)), 0);
        assert_eq!(p.lower_bound(rank_exec(1, 5)), 0);
        assert_eq!(p.lower_bound(rank_exec(1, 6)), 1);
        assert_eq!(p.lower_bound(rank_exec(1, 9)), 1);
        assert_eq!(p.lower_bound(rank_exec(2, 0)), 2);
        assert_eq!(p.lower_bound(rank_exec(3, u64::MAX)), 3);
        assert_eq!(p.lower_bound(rank_exec(4, 0)), 4);
        assert_eq!(p.lower_bound(rank_exec(u32::MAX, u64::MAX)), 4);
    }

    #[test]
    fn a_quota_above_the_capacity_is_refused() {
        assert!(Pool::new(2, 3).is_none());
    }
    #[test]
    fn removing_an_entry_frees_its_row_quota() {
        let mut p = Pool::new(4, 1).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 0 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 8, Instant { ms: 0 }, 0), Inserted::RowAtQuota);
        assert!(p.remove(1, 7));
        assert!(!p.remove(1, 7));
        assert_eq!(p.insert(1, 8, Instant { ms: 0 }, 0), Inserted::New);
    }

    #[test]
    fn dropping_an_expired_entry_removes_it_in_place_and_nothing_else() {
        let mut p = Pool::new(8, 8).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 8, Instant { ms: 50 }, 3), Inserted::New);
        assert_eq!(p.insert(2, 8, Instant { ms: 50 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 9, Instant { ms: 100 }, 0), Inserted::New);
        assert!(p.drop_expired(1, 8, Instant { ms: 50 }));
        assert_eq!(
            p.entries,
            vec![
                Entry {
                    row: 1,
                    key: 7,
                    deadline_ms: 100,
                    value: 0
                },
                Entry {
                    row: 2,
                    key: 8,
                    deadline_ms: 50,
                    value: 0
                },
                Entry {
                    row: 1,
                    key: 9,
                    deadline_ms: 100,
                    value: 0
                },
            ]
        );
        assert!(!p.drop_expired(1, 8, Instant { ms: 50 }));
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn dropping_leaves_a_live_entry_and_a_missing_key_alone() {
        let mut p = Pool::new(8, 8).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 8, Instant { ms: 100 }, 0), Inserted::New);
        let before = p.entries.clone();
        // One millisecond before the deadline the entry is live.
        assert!(!p.drop_expired(1, 7, Instant { ms: 99 }));
        assert!(!p.drop_expired(3, 7, Instant { ms: 500 }));
        assert!(!p.drop_expired(1, 9, Instant { ms: 500 }));
        assert_eq!(p.entries, before);
        // At the deadline it has expired.
        assert!(p.drop_expired(1, 7, Instant { ms: 100 }));
        assert_eq!(p.get(1, 7), None);
        assert_eq!(p.get(1, 8), Some(100));
    }

    fn throttle(interval_ms: u64, last_ms: Option<u64>) -> Throttle {
        Throttle {
            interval_ms,
            last_ms,
        }
    }

    #[test]
    fn a_sweep_is_due_by_the_interval_and_never_with_time_behind_it() {
        assert!(throttle(1000, None).due(Instant { ms: 0 }));
        assert!(!throttle(1000, Some(5000)).due(Instant { ms: 5999 }));
        assert!(throttle(1000, Some(5000)).due(Instant { ms: 6000 }));
        // Time behind the last sweep: not due, unless the interval is zero.
        assert!(!throttle(1000, Some(5000)).due(Instant { ms: 4000 }));
        assert!(throttle(0, Some(5000)).due(Instant { ms: 4000 }));
        assert!(throttle(0, Some(5000)).due(Instant { ms: 5000 }));
    }

    #[test]
    fn below_the_capacity_an_insert_sweeps_nothing_and_leaves_the_throttle() {
        let mut p = Pool::new(3, 3).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 10 }, 0), Inserted::New);
        let th = throttle(1000, None);
        assert_eq!(
            p.insert_sweeping(th, 1, 2, Instant { ms: 900 }, 5, Instant { ms: 500 }),
            (Swept::New, th)
        );
        // The expired entry is still there: there was room without it.
        assert_eq!(p.get(1, 1), Some(10));
        assert_eq!(
            p.entry(1, 2),
            Some(Entry {
                row: 1,
                key: 2,
                deadline_ms: 900,
                value: 5
            })
        );
    }

    #[test]
    fn at_the_capacity_a_due_sweep_removes_every_expired_entry_and_adds() {
        let mut p = Pool::new(3, 3).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 10 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 1, Instant { ms: 900 }, 0), Inserted::New);
        assert_eq!(p.insert(3, 1, Instant { ms: 20 }, 0), Inserted::New);
        let (r, th) = p.insert_sweeping(
            throttle(1000, None),
            4,
            1,
            Instant { ms: 900 },
            0,
            Instant { ms: 500 },
        );
        assert_eq!(r, Swept::SweptNew);
        assert_eq!(th, throttle(1000, Some(500)));
        assert_eq!(
            p.entries,
            vec![
                Entry {
                    row: 2,
                    key: 1,
                    deadline_ms: 900,
                    value: 0
                },
                Entry {
                    row: 4,
                    key: 1,
                    deadline_ms: 900,
                    value: 0
                },
            ]
        );
    }

    #[test]
    fn at_the_capacity_with_nothing_expired_the_sweep_is_stamped_and_the_insert_refused() {
        let mut p = Pool::new(2, 2).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 900 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 1, Instant { ms: 900 }, 0), Inserted::New);
        let before = p.entries.clone();
        let (r, th) = p.insert_sweeping(
            throttle(1000, None),
            3,
            1,
            Instant { ms: 900 },
            0,
            Instant { ms: 500 },
        );
        assert_eq!(r, Swept::Full);
        assert_eq!(th, throttle(1000, Some(500)));
        assert_eq!(p.entries, before);
    }

    #[test]
    fn between_sweeps_an_insert_at_the_capacity_changes_nothing_even_with_expired_entries() {
        let mut p = Pool::new(2, 2).unwrap();
        assert_eq!(p.insert(1, 1, Instant { ms: 900 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 1, Instant { ms: 900 }, 0), Inserted::New);
        let before = p.entries.clone();
        // Both have expired at 1400, and the last sweep was 900 ms ago.
        let th = throttle(1000, Some(500));
        assert_eq!(
            p.insert_sweeping(th, 3, 1, Instant { ms: 2000 }, 0, Instant { ms: 1400 }),
            (Swept::Throttled, th)
        );
        assert_eq!(p.entries, before);
        // One interval after the last sweep it runs.
        let (r, th) = p.insert_sweeping(th, 3, 1, Instant { ms: 2000 }, 0, Instant { ms: 1500 });
        assert_eq!(r, Swept::SweptNew);
        assert_eq!(th, throttle(1000, Some(1500)));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn removing_by_key_ends_takes_every_row_and_expired_or_not_and_nothing_else() {
        let k = |hi: u64, mid: u64, lo: u64| hi * 4294967296 + mid * 65536 + lo;
        let mut p = Pool::new(8, 8).unwrap();
        assert_eq!(
            p.insert(1, k(6, 1000, 80), Instant { ms: 900 }, 0),
            Inserted::New
        );
        assert_eq!(
            p.insert(2, k(6, 2000, 80), Instant { ms: 10 }, 0),
            Inserted::New
        );
        assert_eq!(
            p.insert(1, k(6, 1000, 81), Instant { ms: 900 }, 0),
            Inserted::New
        );
        assert_eq!(
            p.insert(1, k(17, 1000, 80), Instant { ms: 900 }, 0),
            Inserted::New
        );
        assert_eq!(p.remove_ends(6, 80), 2);
        assert_eq!(
            p.entries,
            vec![
                Entry {
                    row: 1,
                    key: k(6, 1000, 81),
                    deadline_ms: 900,
                    value: 0
                },
                Entry {
                    row: 1,
                    key: k(17, 1000, 80),
                    deadline_ms: 900,
                    value: 0
                },
            ]
        );
        assert_eq!(p.remove_ends(6, 80), 0);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn the_live_count_leaves_out_what_has_expired() {
        let mut p = Pool::new(4, 4).unwrap();
        assert_eq!(p.live_count(Instant { ms: 0 }), 0);
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(2, 7, Instant { ms: 200 }, 0), Inserted::New);
        assert_eq!(p.live_count(Instant { ms: 99 }), 2);
        assert_eq!(p.live_count(Instant { ms: 100 }), 1);
        assert_eq!(p.live_count(Instant { ms: 200 }), 0);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn live_is_true_until_the_deadline_and_only_for_a_held_key() {
        let mut p = Pool::new(4, 4).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert!(p.live(1, 7, Instant { ms: 99 }));
        assert!(!p.live(1, 7, Instant { ms: 100 }));
        assert!(!p.live(2, 7, Instant { ms: 0 }));
        assert!(!p.live(1, 8, Instant { ms: 0 }));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn an_expiry_that_removes_nothing_leaves_the_table_as_it_was() {
        let mut p = Pool::new(8, 8).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 1), Inserted::New);
        assert_eq!(p.insert(2, 7, Instant { ms: 200 }, 2), Inserted::New);
        let before = p.entries.clone();
        assert_eq!(p.expire(Instant { ms: 99 }, 8), 0);
        assert_eq!(p.entries, before);
        // A budget of nothing removes nothing, whatever has expired.
        assert_eq!(p.expire(Instant { ms: 500 }, 0), 0);
        assert_eq!(p.entries, before);
    }

    #[test]
    fn expiry_keeps_what_stays_in_order_and_stops_at_its_budget() {
        let mut p = Pool::new(8, 8).unwrap();
        for (key, deadline) in [(0u64, 10u64), (1, 900), (2, 10), (3, 900), (4, 10)] {
            assert_eq!(
                p.insert(1, key, Instant { ms: deadline }, key as u32),
                Inserted::New
            );
        }
        // Two of the three expired entries go: the first two met.
        assert_eq!(p.expire(Instant { ms: 100 }, 2), 2);
        assert_eq!(
            p.entries,
            vec![
                Entry {
                    row: 1,
                    key: 1,
                    deadline_ms: 900,
                    value: 1
                },
                Entry {
                    row: 1,
                    key: 3,
                    deadline_ms: 900,
                    value: 3
                },
                Entry {
                    row: 1,
                    key: 4,
                    deadline_ms: 10,
                    value: 4
                },
            ]
        );
        assert_eq!(p.expire(Instant { ms: 100 }, 8), 1);
        assert_eq!(p.len(), 2);
        // Everything expired: the table is emptied.
        assert_eq!(p.expire(Instant { ms: 1000 }, 8), 2);
        assert_eq!(p.len(), 0);
        assert_eq!(p.expire(Instant { ms: 1000 }, 8), 0);
    }

    #[test]
    fn expiry_removes_only_expired_entries_and_stops_at_its_budget() {
        let mut p = Pool::new(8, 8).unwrap();
        for key in 0..4 {
            assert_eq!(p.insert(1, key, Instant { ms: 100 }, 0), Inserted::New);
        }
        assert_eq!(p.insert(1, 9, Instant { ms: 500 }, 0), Inserted::New);
        assert_eq!(p.expire(Instant { ms: 100 }, 3), 3);
        assert_eq!(p.len(), 2);
        assert_eq!(p.get(1, 9), Some(500));
        assert_eq!(p.expire(Instant { ms: 100 }, 3), 1);
        assert_eq!(p.expire(Instant { ms: 100 }, 3), 0);
        assert_eq!(p.get(1, 9), Some(500));
    }

    #[test]
    fn set_on_a_held_key_sets_its_deadline_and_value_and_nothing_else() {
        let mut p = Pool::new(4, 2).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 0), Inserted::New);
        assert_eq!(p.insert(1, 8, Instant { ms: 200 }, 3), Inserted::New);
        assert_eq!(p.insert(2, 7, Instant { ms: 300 }, 4), Inserted::New);
        assert!(p.set(1, 7, Instant { ms: 50 }, 9));
        assert_eq!(
            p.entry(1, 7),
            Some(Entry {
                row: 1,
                key: 7,
                deadline_ms: 50,
                value: 9,
            })
        );
        assert_eq!(
            p.entry(1, 8),
            Some(Entry {
                row: 1,
                key: 8,
                deadline_ms: 200,
                value: 3,
            })
        );
        assert_eq!(
            p.entry(2, 7),
            Some(Entry {
                row: 2,
                key: 7,
                deadline_ms: 300,
                value: 4,
            })
        );
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn set_on_a_missing_key_returns_false_and_changes_nothing() {
        let mut p = Pool::new(4, 2).unwrap();
        assert_eq!(p.insert(1, 7, Instant { ms: 100 }, 5), Inserted::New);
        let before = p.entries.clone();
        assert!(!p.set(1, 8, Instant { ms: 200 }, 9));
        assert!(!p.set(2, 7, Instant { ms: 200 }, 9));
        assert_eq!(p.entries, before);
        assert_eq!(p.entry(1, 8), None);
        assert_eq!(p.entry(2, 7), None);
    }
}

/// Bounded check of G7 against a count written separately from `row_count`:
/// any five inserts into a table of capacity 4, any quota up to 4.
/// Helpers for the bounded checks, shared with the modules built on `Pool`.
/// They read and build a table directly, with plain loops that share no code
/// with the specification.
#[cfg(kani)]
impl Pool {
    /// G7 read from the fields: the quota within the capacity, the length
    /// within the capacity, no row and key twice, no row over the quota.
    pub(crate) fn kani_holds_g7(&self) -> bool {
        if self.quota > self.cap || self.entries.len() > self.cap {
            return false;
        }
        let mut i = 0;
        while i < self.entries.len() {
            let mut same_row = 0;
            let mut j = 0;
            while j < self.entries.len() {
                if self.entries[j].row == self.entries[i].row {
                    same_row += 1;
                    if j != i && self.entries[j].key == self.entries[i].key {
                        return false;
                    }
                }
                j += 1;
            }
            if same_row > self.quota {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Any table of up to `max` entries that satisfies G7: any capacity and
    /// quota up to `max`, any rows, keys, deadlines and values. Built with
    /// room for one more entry than the bound, so no operation reallocates.
    pub(crate) fn kani_any(max: usize) -> Pool {
        let cap: usize = kani::any();
        let quota: usize = kani::any();
        kani::assume(cap <= max && quota <= cap);
        let n: usize = kani::any();
        kani::assume(n <= cap);
        let mut entries = Vec::with_capacity(max + 1);
        let mut i = 0;
        while i < n {
            entries.push(Entry {
                row: kani::any(),
                key: kani::any(),
                deadline_ms: kani::any(),
                value: kani::any(),
            });
            i += 1;
        }
        let p = Pool {
            entries,
            cap,
            quota,
        };
        kani::assume(p.kani_holds_g7());
        p
    }

    /// A copy of the entries, in order.
    pub(crate) fn kani_entries(&self) -> Vec<Entry> {
        self.entries.clone()
    }

    /// The capacity and the quota.
    pub(crate) fn kani_limits(&self) -> (usize, usize) {
        (self.cap, self.quota)
    }
}

/// The entry `s` holds for `(row, key)`, by a plain scan.
#[cfg(kani)]
pub(crate) fn kani_lookup(s: &[Entry], row: u32, key: u64) -> Option<Entry> {
    let mut i = 0;
    while i < s.len() {
        if s[i].row == row && s[i].key == key {
            return Some(s[i]);
        }
        i += 1;
    }
    None
}

/// How many entries of `s` belong to `row`, by a plain scan.
#[cfg(kani)]
pub(crate) fn kani_count_row(s: &[Entry], row: u32) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        if s[i].row == row {
            n += 1;
        }
        i += 1;
    }
    n
}

#[cfg(kani)]
mod proofs {
    //! Bounded checks of the compiled code against a second, independently
    //! written reading of G7.
    //!
    //! Verus proves each operation keeps the invariant from any state that
    //! has it, for every size. These harnesses check the same thing the same
    //! way: one operation, from an arbitrary table that satisfies
    //! [`holds_g7`], with every row, key and deadline unconstrained. An
    //! arbitrary table of up to [`MAX`] entries includes every table of that
    //! size any sequence of operations can reach, so no harness needs more
    //! than one step. What they add to Verus: the real `Vec`, the real
    //! integers, and an oracle that shares no code with the specification.
    //!
    //! Each harness ends in `kani::cover!` lines. A cover that is not
    //! satisfiable means the harness never exercised that outcome, and is a
    //! failure of the harness.
    use super::*;

    /// The most entries a table in these harnesses holds. Three is the least
    /// that has, at once, the entry an operation touches, another of its row
    /// and one of another row; four adds a second bystander, and was affordable
    /// (at three the slowest harness took about four minutes).
    const MAX: usize = 4;

    /// G7 read from the fields with plain loops: the quota within the
    /// capacity, the length within the capacity, no row and key twice, and no
    /// row holding more than the quota.
    fn holds_g7(p: &Pool) -> bool {
        p.kani_holds_g7()
    }

    /// The entry `s` holds for `(row, key)`, by a plain scan.
    fn lookup(s: &[Entry], row: u32, key: u64) -> Option<Entry> {
        kani_lookup(s, row, key)
    }

    fn count_row(s: &[Entry], row: u32) -> usize {
        kani_count_row(s, row)
    }

    /// Any table of up to `MAX` entries that satisfies G7: any capacity and
    /// quota up to `MAX`, any rows, keys, deadlines and values.
    fn any_pool() -> Pool {
        Pool::kani_any(MAX)
    }

    /// One arbitrary entry of `before`, other than the one for `(row, key)`,
    /// is still held with its deadline and value. The index is
    /// unconstrained, so this is a claim about every such entry.
    fn another_is_kept(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let w: usize = kani::any();
        if w < before.len() && !(before[w].row == row && before[w].key == key) {
            assert!(lookup(now, before[w].row, before[w].key) == Some(before[w]));
        }
    }

    /// One arbitrary entry of `now` was held before with the same deadline
    /// and value, unless it is the entry for `(row, key)`.
    fn nothing_else_is_new(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let v: usize = kani::any();
        if v < now.len() && !(now[v].row == row && now[v].key == key) {
            assert!(lookup(before, now[v].row, now[v].key) == Some(now[v]));
        }
    }

    /// The base case: a new table satisfies G7 and is empty, and is refused
    /// exactly when the quota exceeds the capacity. Every `usize`.
    #[kani::proof]
    #[kani::unwind(2)]
    fn kani_pool_new() {
        let cap: usize = kani::any();
        let quota: usize = kani::any();
        match Pool::new(cap, quota) {
            Some(p) => {
                assert!(quota <= cap);
                assert!(p.len() == 0 && holds_g7(&p));
            }
            None => {
                assert!(quota > cap);
            }
        }
        kani::cover!(quota > cap);
        kani::cover!(quota == cap && cap > 0);
    }

    /// `any_pool` is not vacuous: it yields an empty table, a full one, and
    /// one with a row at its quota.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_any_pool_reaches_the_corners() {
        let p = any_pool();
        kani::cover!(p.entries.len() == 0);
        kani::cover!(p.entries.len() == MAX);
        kani::cover!(p.entries.len() == MAX && p.quota == 1);
        kani::cover!(p.entries.len() == 2 && p.entries[0].row == p.entries[1].row);
    }

    /// One `insert` from any table.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_insert_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (row, key, deadline, value): (u32, u64, u64, u32) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let want = Entry {
            row,
            key,
            deadline_ms: deadline,
            value,
        };
        let was = lookup(&before, row, key);
        let outcome = p.insert(row, key, Instant { ms: deadline }, value);
        assert!(holds_g7(&p));
        another_is_kept(&before, &p.entries, row, key);
        nothing_else_is_new(&before, &p.entries, row, key);
        match outcome {
            Inserted::New => {
                assert!(was.is_none());
                assert!(lookup(&p.entries, row, key) == Some(want));
                assert!(p.entries.len() == before.len() + 1);
            }
            Inserted::Refreshed => {
                assert!(was.is_some());
                assert!(lookup(&p.entries, row, key) == Some(want));
                assert!(p.entries.len() == before.len());
            }
            Inserted::RowAtQuota => {
                assert!(was.is_none());
                assert!(p.entries == before);
                assert!(count_row(&before, row) >= p.quota);
            }
            Inserted::PoolFull => {
                assert!(was.is_none());
                assert!(p.entries == before);
                assert!(before.len() >= p.cap);
            }
        }
        kani::cover!(outcome == Inserted::New);
        kani::cover!(outcome == Inserted::Refreshed);
        kani::cover!(outcome == Inserted::RowAtQuota);
        kani::cover!(outcome == Inserted::PoolFull);
    }

    /// One `insert_reclaiming` from any table.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_insert_reclaiming_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (row, key, deadline, value, now): (u32, u64, u64, u32, u64) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        let want = Entry {
            row,
            key,
            deadline_ms: deadline,
            value,
        };
        let was = lookup(&before, row, key);
        let outcome = p.insert_reclaiming(
            row,
            key,
            Instant { ms: deadline },
            value,
            Instant { ms: now },
        );
        assert!(holds_g7(&p));
        nothing_else_is_new(&before, &p.entries, row, key);
        // An entry that has not expired is never the one given up.
        let w: usize = kani::any();
        if w < before.len()
            && before[w].deadline_ms > now
            && !(before[w].row == row && before[w].key == key)
        {
            assert!(lookup(&p.entries, before[w].row, before[w].key) == Some(before[w]));
        }
        match outcome {
            Inserted::New => {
                assert!(was.is_none());
                assert!(lookup(&p.entries, row, key) == Some(want));
                assert!(p.entries.len() <= before.len() + 1);
                assert!(p.entries.len() >= before.len());
            }
            Inserted::Refreshed => {
                assert!(was.is_some());
                assert!(lookup(&p.entries, row, key) == Some(want));
                assert!(p.entries.len() == before.len());
                another_is_kept(&before, &p.entries, row, key);
            }
            Inserted::RowAtQuota => {
                assert!(was.is_none());
                assert!(p.entries == before);
                assert!(count_row(&before, row) >= p.quota);
                // The row holds nothing that has expired.
                let j: usize = kani::any();
                if j < before.len() && before[j].row == row {
                    assert!(before[j].deadline_ms > now);
                }
            }
            Inserted::PoolFull => {
                assert!(was.is_none());
                assert!(p.entries == before);
                assert!(before.len() >= p.cap);
                // The table holds nothing that has expired.
                let j: usize = kani::any();
                if j < before.len() {
                    assert!(before[j].deadline_ms > now);
                }
            }
        }
        kani::cover!(outcome == Inserted::New && p.entries.len() == before.len() + 1);
        // Room was made by giving up an expired entry.
        kani::cover!(outcome == Inserted::New && p.entries.len() == before.len());
        kani::cover!(outcome == Inserted::Refreshed);
        kani::cover!(outcome == Inserted::RowAtQuota);
        kani::cover!(outcome == Inserted::PoolFull);
    }

    /// One `set` from any table.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_set_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (row, key, deadline, value): (u32, u64, u64, u32) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let was = lookup(&before, row, key);
        let held = p.set(row, key, Instant { ms: deadline }, value);
        assert!(holds_g7(&p));
        assert!(held == was.is_some());
        assert!(p.entries.len() == before.len());
        another_is_kept(&before, &p.entries, row, key);
        nothing_else_is_new(&before, &p.entries, row, key);
        if held {
            assert!(
                lookup(&p.entries, row, key)
                    == Some(Entry {
                        row,
                        key,
                        deadline_ms: deadline,
                        value,
                    })
            );
        } else {
            assert!(p.entries == before);
        }
        kani::cover!(held);
        kani::cover!(!held && before.len() == MAX);
    }

    /// One `remove` from any table.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_remove_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (row, key): (u32, u64) = (kani::any(), kani::any());
        let was = lookup(&before, row, key);
        let removed = p.remove(row, key);
        assert!(holds_g7(&p));
        assert!(removed == was.is_some());
        assert!(lookup(&p.entries, row, key).is_none());
        assert!(p.entries.len() + usize::from(removed) == before.len());
        another_is_kept(&before, &p.entries, row, key);
        nothing_else_is_new(&before, &p.entries, row, key);
        if !removed {
            assert!(p.entries == before);
        }
        kani::cover!(removed && before.len() == MAX);
        kani::cover!(!removed && before.len() == MAX);
    }

    /// One `insert_sweeping` from any table whose quota is its capacity, with
    /// any throttle, against a plain reading: room, or not due, or nothing
    /// expired, or the entries that had not expired, in order, and the new one.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_insert_sweeping_step() {
        let mut p = any_pool();
        kani::assume(p.quota == p.cap);
        let before = p.entries.clone();
        let (row, key, deadline, value, now): (u32, u64, u64, u32, u64) = (
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        );
        kani::assume(lookup(&before, row, key).is_none());
        let th = Throttle {
            interval_ms: kani::any(),
            last_ms: kani::any(),
        };
        let may_sweep = match th.last_ms {
            None => true,
            Some(t) => {
                if now < t {
                    th.interval_ms == 0
                } else {
                    (now as u128) >= (t as u128) + (th.interval_ms as u128)
                }
            }
        };
        // How many entries had not expired, and whether any had: by one
        // arbitrary index each, and a plain count.
        let mut live_before: usize = 0;
        let mut c: usize = 0;
        while c < before.len() {
            if before[c].deadline_ms > now {
                live_before += 1;
            }
            c += 1;
        }
        let any_expired = live_before < before.len();
        let new = Entry {
            row,
            key,
            deadline_ms: deadline,
            value,
        };
        let (r, after_th) = p.insert_sweeping(
            th,
            row,
            key,
            Instant { ms: deadline },
            value,
            Instant { ms: now },
        );
        assert!(holds_g7(&p));
        assert!(after_th.interval_ms == th.interval_ms);
        // What the table holds afterwards, read by row and key and not by
        // position: the guarantees say what is held, not where.
        let v: usize = kani::any();
        let w: usize = kani::any();
        if before.len() < p.cap {
            assert!(r == Swept::New && after_th == th);
            assert!(p.entries.len() == before.len() + 1);
            assert!(lookup(&p.entries, row, key) == Some(new));
            if w < before.len() {
                assert!(lookup(&p.entries, before[w].row, before[w].key) == Some(before[w]));
            }
        } else if !may_sweep {
            assert!(r == Swept::Throttled && after_th == th);
            assert!(p.entries == before);
        } else if !any_expired {
            assert!(r == Swept::Full && after_th.last_ms == Some(now));
            assert!(p.entries == before);
        } else {
            assert!(r == Swept::SweptNew && after_th.last_ms == Some(now));
            // Exactly the entries that had not expired, and the new one.
            assert!(p.entries.len() == live_before + 1);
            assert!(lookup(&p.entries, row, key) == Some(new));
            if w < before.len() {
                let kept = lookup(&p.entries, before[w].row, before[w].key);
                if before[w].deadline_ms > now {
                    assert!(kept == Some(before[w]));
                } else {
                    assert!(kept.is_none());
                }
            }
            if v < p.entries.len() && !(p.entries[v].row == row && p.entries[v].key == key) {
                assert!(lookup(&before, p.entries[v].row, p.entries[v].key) == Some(p.entries[v]));
            }
        }
        kani::cover!(r == Swept::New);
        kani::cover!(r == Swept::Throttled && any_expired && before.len() == MAX);
        kani::cover!(r == Swept::Full && before.len() == MAX);
        kani::cover!(r == Swept::SweptNew && p.entries.len() == 1 && before.len() == MAX);
        kani::cover!(r == Swept::SweptNew && p.entries.len() == MAX);
        kani::cover!(r == Swept::Full && p.cap == 0);
    }

    /// One `remove_ends` from any table: exactly the entries whose key has
    /// those ends go, by shifts and masks where the code divides.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_remove_ends_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (hi, lo): (u64, u64) = (kani::any(), kani::any());
        // How many entries have those ends: a plain count.
        let mut matched: usize = 0;
        let mut c: usize = 0;
        while c < before.len() {
            if (before[c].key >> 32) == hi && (before[c].key & 0xffff) == lo {
                matched += 1;
            }
            c += 1;
        }
        let gone = p.remove_ends(hi, lo);
        assert!(holds_g7(&p));
        assert!(gone == matched);
        assert!(p.entries.len() + gone == before.len());
        // What the table holds afterwards, read by row and key through one
        // arbitrary index each way, and not by building the expected table.
        let w: usize = kani::any();
        if w < before.len() {
            let kept = lookup(&p.entries, before[w].row, before[w].key);
            if (before[w].key >> 32) == hi && (before[w].key & 0xffff) == lo {
                assert!(kept.is_none());
            } else {
                assert!(kept == Some(before[w]));
            }
        }
        let v: usize = kani::any();
        if v < p.entries.len() {
            assert!(lookup(&before, p.entries[v].row, p.entries[v].key) == Some(p.entries[v]));
        }
        kani::cover!(gone == 0 && before.len() == MAX);
        kani::cover!(gone == MAX);
        kani::cover!(gone == 1 && before.len() == MAX);
    }

    /// One `drop_expired` from any table, with any row, key and instant.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_drop_expired_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (row, key, now): (u32, u64, u64) = (kani::any(), kani::any(), kani::any());
        let was = lookup(&before, row, key);
        let expired = match was {
            Some(e) => e.deadline_ms <= now,
            None => false,
        };
        let dropped = p.drop_expired(row, key, Instant { ms: now });
        assert!(holds_g7(&p));
        assert!(dropped == expired);
        if dropped {
            // The others keep their order: position by position, skipping the one removed.
            assert!(p.entries.len() + 1 == before.len());
            let at = before.iter().position(|e| e.row == row && e.key == key);
            let v: usize = kani::any();
            if let Some(at) = at {
                if v < p.entries.len() {
                    assert!(p.entries[v] == before[if v < at { v } else { v + 1 }]);
                }
            }
        } else {
            assert!(p.entries == before);
        }
        kani::cover!(dropped && before.len() == MAX);
        kani::cover!(!dropped && was.is_some() && before.len() == MAX);
        kani::cover!(!dropped && was.is_none() && before.len() == MAX);
    }

    /// One `expire` from any table, with any instant and any budget.
    #[cfg(feature = "kani-full")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_expire_step() {
        let mut p = any_pool();
        let before = p.entries.clone();
        let (now, budget): (u64, usize) = (kani::any(), kani::any());
        let gone = p.expire(Instant { ms: now }, budget);
        assert!(holds_g7(&p));
        assert!(gone <= budget);
        assert!(p.entries.len() + gone == before.len());
        // Nothing appears, and nothing that has not expired goes.
        let v: usize = kani::any();
        if v < p.entries.len() {
            assert!(lookup(&before, p.entries[v].row, p.entries[v].key) == Some(p.entries[v]));
        }
        let w: usize = kani::any();
        if w < before.len() && before[w].deadline_ms > now {
            assert!(lookup(&p.entries, before[w].row, before[w].key) == Some(before[w]));
        }
        // With budget to spare, nothing expired is left.
        if gone < budget {
            let j: usize = kani::any();
            if j < p.entries.len() {
                assert!(p.entries[j].deadline_ms > now);
            }
        }
        // Removing nothing leaves the table as it was; removing something means
        // something had expired.
        if gone == 0 {
            assert!(p.entries == before);
        } else {
            assert!(before.iter().any(|e| e.deadline_ms <= now));
        }
        kani::cover!(gone == 0 && before.len() == MAX);
        kani::cover!(gone == MAX);
        // The budget stopped it with expired entries still held.
        kani::cover!(gone == budget && gone == 1 && before.len() == MAX);
    }

    /// The readers agree with the plain scans, on any table.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_readers() {
        let p = any_pool();
        let (row, key, now): (u32, u64, u64) = (kani::any(), kani::any(), kani::any());
        let held = lookup(&p.entries, row, key);
        let held_deadline = match held {
            Some(e) => Some(e.deadline_ms),
            None => None,
        };
        assert!(p.get(row, key) == held_deadline);
        match p.entry(row, key) {
            Some(e) => {
                assert!(e.row == row && e.key == key && held == Some(e));
            }
            None => {
                assert!(held.is_none());
            }
        }
        assert!(p.row_count(row) == count_row(&p.entries, row));
        assert!(p.len() == p.entries.len());
        // `any_live`, against one arbitrary entry in each direction.
        let live = p.any_live(key, Instant { ms: now });
        let j: usize = kani::any();
        if j < p.entries.len() && p.entries[j].key == key && p.entries[j].deadline_ms > now {
            assert!(live);
        }
        if live {
            let mut found = false;
            let mut i = 0;
            while i < p.entries.len() {
                if p.entries[i].key == key && p.entries[i].deadline_ms > now {
                    found = true;
                }
                i += 1;
            }
            assert!(found);
        }
        kani::cover!(held.is_some());
        kani::cover!(live && held.is_none());
    }

    /// `clear` empties any table and keeps its limits.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_clear_step() {
        let mut p = any_pool();
        let (cap, quota) = (p.cap, p.quota);
        kani::cover!(p.entries.len() == MAX);
        p.clear();
        assert!(p.entries.is_empty() && p.cap == cap && p.quota == quota);
        assert!(holds_g7(&p));
    }

    /// `lower_bound` on any sorted table of up to four entries: everything
    /// before the result ranks below the target, everything from it on ranks
    /// at or above.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_pool_lower_bound() {
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let mut entries = Vec::with_capacity(4);
        let mut i = 0;
        while i < n {
            entries.push(Entry {
                row: kani::any(),
                key: kani::any(),
                deadline_ms: 0,
                value: 0,
            });
            i += 1;
        }
        let mut k = 1;
        while k < entries.len() {
            kani::assume(
                rank_exec(entries[k - 1].row, entries[k - 1].key)
                    < rank_exec(entries[k].row, entries[k].key),
            );
            k += 1;
        }
        let p = Pool {
            entries,
            cap: 4,
            quota: 4,
        };
        let (row, key): (u32, u64) = (kani::any(), kani::any());
        let target = rank_exec(row, key);
        let at = p.lower_bound(target);
        assert!(at <= p.entries.len());
        let j: usize = kani::any();
        if j < p.entries.len() {
            let r = rank_exec(p.entries[j].row, p.entries[j].key);
            assert!((j < at) == (r < target));
        }
        kani::cover!(at == 0 && n == 4);
        kani::cover!(at == 4);
        kani::cover!(at == 2 && n == 4);
    }

    /// `rank_exec` orders by row, then by key, for every row and key.
    #[kani::proof]
    fn kani_pool_rank_orders_by_row_then_key() {
        let (r1, k1, r2, k2): (u32, u64, u32, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let (a, b) = (rank_exec(r1, k1), rank_exec(r2, k2));
        assert!((a == b) == (r1 == r2 && k1 == k2));
        assert!((a < b) == (r1 < r2 || (r1 == r2 && k1 < k2)));
        kani::cover!(a == b);
        kani::cover!(r1 > r2 && k1 < k2);
    }
}
