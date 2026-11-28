//! One box's DNS admissions: the questions it asked, the addresses its
//! answers admitted, and the flows it opened to them.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A box that declares names may reach the addresses its own lookups returned
//! for those names, for a window. This module is the three tables behind
//! that and the one decision that reads them. Reading a DNS message is
//! `dnsa`'s and `dnsq`'s, and refusing an answer's address is `rebind`'s;
//! matching a question to a declared name is the caller's: by the time this
//! module is called, a name is its index in the box's declaration and an
//! address has passed those checks.
//!
//! THEOREM G5, for every sequence of operations on a [`Pins`]:
//!   (a) `answer` succeeds exactly when the box has an unexpired outstanding
//!       question with the same name, transaction id and port, and it
//!       consumes that question: the same reply does not succeed twice;
//!   (b) an address enters the admitted table only through `admit`, which
//!       takes the token only `answer` returns, under that token's name, and
//!       with a window that starts when the answer was matched, however late
//!       the token is used; a token from tables with another owner address, or from before
//!       the last `clear` (which raises the epoch until it is the largest a
//!       `u64` holds), admits nothing. An address some name already
//!       holds is not entered again: its one entry is extended, under the
//!       name that first admitted it, whoever asks and expired or not, and
//!       counts against no other name's quota;
//!   (c) `egress` returns `Refused` exactly when the frame has no live flow
//!       record and its destination has no live admission; `ByFlow` exactly
//!       when it has a live flow record for the same destination, protocol
//!       and ports; otherwise the destination's window admits it;
//!   (d) `egress` opens a flow record only for a frame its destination's live
//!       window admits, and never for a closing segment;
//!   (e) a closing TCP segment on a live flow is admitted and ends the record;
//!   (f) `egress` reads each table once and changes only the flow table; a
//!       refused frame changes nothing; a refresh never shortens a record;
//!   (g) each table keeps G7: a hard capacity, and a quota per name (questions
//!       and addresses) or per destination (flows).
//!
//!   (h) a question or a flow is refused for want of room only when its
//!       row, or its table, is full of entries that have not expired; making
//!       room removes one expired entry, of its own row when the row is at
//!       its quota, and never one that has not expired; with room, nothing
//!       is removed.
//!       An address is refused only when no name holds it and its name is at
//!       its quota or the table at its capacity; `release_expired` removes
//!       every expired address of one name, and after it a name at its quota
//!       holds only addresses that have not expired;
//!   (i) the admitted table never holds one address under two names.
//!
//! `expire` is scheduled by the shell.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::flow::{FIN, RST, TCP, key};
#[cfg(verus_keep_ghost)]
use crate::flow::{
    add_ms_spec, key_of, lemma_expired_not_live, lemma_has_live, lemma_not_held_not_live,
    lemma_refreshed_no_new_keys, lemma_same_no_new_keys, lemma_subset_no_new_keys, live,
    no_new_keys,
};
use crate::pool::{Entry, Inserted};
#[cfg(verus_keep_ghost)]
use crate::pool::{
    added, bounded_by, bounded_by_key, changed_only_to, count, has, held_key, held_until, holds,
    keeps_live, keeps_other_rows, keeps_others, kept_by_key, lemma_refresh_bounded,
    lemma_refresh_not_shortened, lemma_unique_push, lemma_unique_refreshed, lemma_unique_subset,
    live_key, none_expired, not_shortened, only_adds, refreshed_from, row_live, subset_of,
    unique_keys,
};
use crate::slab::Slab;
#[cfg(verus_keep_ghost)]
use crate::slab::{scap, sinv, squota, sview};
use crate::time::Instant;

/// The sizes and windows of one box's tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Limits {
    pub asked_cap: usize,
    pub asked_per_name: usize,
    pub admitted_cap: usize,
    pub admitted_per_name: usize,
    pub flows_cap: usize,
    pub flows_per_destination: usize,
    /// How long a question waits for its answer.
    pub query_ms: u64,
    /// How long an answer admits its addresses.
    pub window_ms: u64,
    /// How long an idle flow record is kept.
    pub idle_ms: u64,
}

/// The transport facts of a frame the box sent, when it has any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Transport {
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
}

/// What recording a question did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Asked {
    Recorded,
    /// The same question again: its wait starts over.
    Refreshed,
    /// This name has its quota of questions outstanding. Nothing changed, and
    /// the reply to this one will admit nothing.
    NameAtQuota,
    /// The table is full. Nothing changed.
    Full,
}

/// Proof that a reply matched one of the box's outstanding questions. Only
/// [`Pins::answer`] makes one.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Answered {
    name: u32,
    at_ms: u64,
    owner: u32,
    epoch: u64,
}

/// What admitting one address did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Admitted {
    New,
    /// A name already held this address: that entry's window runs at least
    /// as long, under `holder`, the name that first admitted it.
    Refreshed {
        holder: u32,
    },
    /// No name holds the address and this one holds its quota. Nothing changed.
    NameAtQuota,
    /// The table is full. Nothing changed.
    Full,
    /// The token was issued by tables with another owner address or epoch, or before these were
    /// last cleared. Nothing changed.
    Stale,
}

/// What one matched answer did with its addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Admits {
    /// Addresses now admitted: entered under the answer's name, or extended
    /// under the name that already held them.
    pub admitted: u16,
    /// Addresses no name holds afterwards: refused for want of room.
    pub refused: u16,
}

/// The decision for one frame to a destination the box's rules do not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Egress {
    /// A live flow record carries the frame.
    ByFlow,
    /// The destination's window admits the frame and its flow is now recorded.
    Retained,
    /// The destination's window admits the frame. No flow is recorded: the
    /// frame has no ports, is a closing segment, or the flow table refused it.
    Window,
    /// Neither. Nothing changed.
    Refused,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Pins {
    asked: Slab,
    admitted: Slab,
    flows: Slab,
    query_ms: u64,
    window_ms: u64,
    idle_ms: u64,
    /// The box these tables belong to.
    owner: u32,
    /// Raised by every `clear`. A token from an earlier epoch admits nothing.
    epoch: u64,
}

#[cfg(verus_keep_ghost)]
verus! {

pub closed spec fn asked_pool(p: Pins) -> Slab { p.asked }
pub closed spec fn admitted_pool(p: Pins) -> Slab { p.admitted }
pub closed spec fn flows_pool(p: Pins) -> Slab { p.flows }
pub closed spec fn query_ms_of(p: Pins) -> u64 { p.query_ms }
pub closed spec fn window_ms_of(p: Pins) -> u64 { p.window_ms }
pub closed spec fn idle_ms_of(p: Pins) -> u64 { p.idle_ms }
pub closed spec fn answered_name(a: Answered) -> u32 { a.name }
pub closed spec fn answered_at(a: Answered) -> u64 { a.at_ms }
pub closed spec fn answered_owner(a: Answered) -> u32 { a.owner }
pub closed spec fn answered_epoch(a: Answered) -> u64 { a.epoch }
pub closed spec fn owner_of(p: Pins) -> u32 { p.owner }
pub closed spec fn epoch_of(p: Pins) -> u64 { p.epoch }

/// The token was issued by these tables since they were last cleared.
pub open spec fn token_current(a: Answered, p: Pins) -> bool {
    answered_owner(a) == owner_of(p) && answered_epoch(a) == epoch_of(p)
}

pub open spec fn asked(p: Pins) -> Seq<Entry> { sview(asked_pool(p)) }
pub open spec fn admitted(p: Pins) -> Seq<Entry> { sview(admitted_pool(p)) }
pub open spec fn flows(p: Pins) -> Seq<Entry> { sview(flows_pool(p)) }

/// The invariant every operation keeps: G7 on each table, and no zero window.
#[verifier::opaque]
pub open spec fn pinv(p: Pins) -> bool {
    &&& sinv(asked_pool(p))
    &&& sinv(admitted_pool(p))
    &&& sinv(flows_pool(p))
    &&& unique_keys(admitted(p))
    &&& query_ms_of(p) > 0
    &&& window_ms_of(p) > 0
    &&& idle_ms_of(p) > 0
}

/// Nothing but the tables' contents changed.
pub open spec fn same_limits(now: Pins, before: Pins) -> bool {
    same_sizes(now, before) && epoch_of(now) == epoch_of(before)
}

/// The sizes, windows and owner are unchanged.
pub open spec fn same_sizes(now: Pins, before: Pins) -> bool {
    &&& owner_of(now) == owner_of(before)
    &&& query_ms_of(now) == query_ms_of(before)
    &&& window_ms_of(now) == window_ms_of(before)
    &&& idle_ms_of(now) == idle_ms_of(before)
    &&& scap(asked_pool(now)) == scap(asked_pool(before))
    &&& squota(asked_pool(now)) == squota(asked_pool(before))
    &&& scap(admitted_pool(now)) == scap(admitted_pool(before))
    &&& squota(admitted_pool(now)) == squota(admitted_pool(before))
    &&& scap(flows_pool(now)) == scap(flows_pool(before))
    &&& squota(flows_pool(now)) == squota(flows_pool(before))
}

/// The key of a question inside its name's row: transaction id and port.
pub open spec fn question_key(txid: u16, port: u16) -> u64 {
    key_of(0, txid, port)
}

/// The key of a flow inside its destination's row.
pub open spec fn transport_key(t: Transport) -> u64 {
    key_of(t.proto, t.sport, t.dport)
}

pub open spec fn transport_closes(t: Transport) -> bool {
    t.proto == TCP && t.flags & (FIN | RST) != 0
}

/// The frame has ports and the table holds an unexpired record for them.
pub open spec fn flow_live(s: Seq<Entry>, dst: u32, t: Option<Transport>, now_ms: u64) -> bool {
    match t {
        Some(x) => live(s, dst, transport_key(x), now_ms),
        None => false,
    }
}

/// The frame has ports and the table holds a record for them, expired or not.
pub open spec fn flow_held(s: Seq<Entry>, dst: u32, t: Option<Transport>) -> bool {
    match t {
        Some(x) => holds(s, dst, transport_key(x)),
        None => false,
    }
}

/// The flow key of a frame with ports; unused for a frame without.
pub open spec fn opt_key(t: Option<Transport>) -> u64 {
    match t {
        Some(x) => transport_key(x),
        None => 0,
    }
}

pub open spec fn closes(t: Option<Transport>) -> bool {
    match t {
        Some(x) => transport_closes(x),
        None => false,
    }
}

/// What `ask` promises of its result and of the tables before and after.
pub open spec fn ask_post(before: Pins, after: Pins, name: u32, txid: u16, port: u16, now_ms: u64, r: Asked) -> bool {
    &&& same_limits(after, before)
    &&& admitted(after) == admitted(before)
    &&& flows(after) == flows(before)
    &&& match r {
        Asked::Recorded => {
            &&& !holds(asked(before), name, question_key(txid, port))
            &&& has(asked(after), Entry {
                row: name,
                key: question_key(txid, port),
                deadline_ms: add_ms_spec(now_ms, query_ms_of(before)),
                value: 0,
            })
            &&& only_adds(asked(after), asked(before), Entry {
                row: name,
                key: question_key(txid, port),
                deadline_ms: add_ms_spec(now_ms, query_ms_of(before)),
                value: 0,
            })
            &&& keeps_live(asked(after), asked(before), now_ms)
            &&& asked(after).len() <= asked(before).len() + 1
            &&& asked(after).len() >= asked(before).len()
            &&& (count(asked(before), name) < squota(asked_pool(before))
                && asked(before).len() < scap(asked_pool(before)))
                ==> added(asked(after), asked(before), Entry {
                    row: name,
                    key: question_key(txid, port),
                    deadline_ms: add_ms_spec(now_ms, query_ms_of(before)),
                    value: 0,
                })
            &&& count(asked(before), name) >= squota(asked_pool(before))
                ==> keeps_other_rows(asked(after), asked(before), name)
        },
        Asked::Refreshed => {
            &&& holds(asked(before), name, question_key(txid, port))
            &&& refreshed_from(asked(after), asked(before), name, question_key(txid, port))
            &&& has(asked(after), Entry {
                row: name,
                key: question_key(txid, port),
                deadline_ms: add_ms_spec(now_ms, query_ms_of(before)),
                value: 0,
            })
        },
        Asked::NameAtQuota => {
            &&& asked(after) == asked(before)
            &&& !holds(asked(before), name, question_key(txid, port))
            &&& count(asked(before), name) >= squota(asked_pool(before))
            &&& row_live(asked(before), name, now_ms)
        },
        Asked::Full => {
            &&& asked(after) == asked(before)
            &&& !holds(asked(before), name, question_key(txid, port))
            &&& asked(before).len() >= scap(asked_pool(before))
            &&& none_expired(asked(before), now_ms)
        },
    }
}

/// What `answer` promises of its result and of the tables before and after.
pub open spec fn answer_post(before: Pins, after: Pins, name: u32, txid: u16, port: u16, now_ms: u64, r: Option<Answered>) -> bool {
    &&& same_limits(after, before)
    &&& admitted(after) == admitted(before)
    &&& flows(after) == flows(before)
    &&& r.is_some() == live(asked(before), name, question_key(txid, port), now_ms)
    &&& no_new_keys(asked(after), asked(before))
    &&& match r {
        Some(a) => {
            &&& answered_name(a) == name
            &&& answered_at(a) == now_ms
            &&& token_current(a, before)
            &&& !holds(asked(after), name, question_key(txid, port))
            &&& keeps_others(asked(after), asked(before), name, question_key(txid, port))
        },
        None => asked(after) == asked(before),
    }
}

/// What `admit` promises of its result and of the tables before and after.
pub open spec fn admit_post(before: Pins, after: Pins, a: Answered, addr: u32, r: Admitted) -> bool {
    &&& same_limits(after, before)
    &&& asked(after) == asked(before)
    &&& flows(after) == flows(before)
    &&& match r {
        Admitted::Stale => {
            &&& !token_current(a, before)
            &&& admitted(after) == admitted(before)
        },
        Admitted::New => {
            &&& token_current(a, before)
            &&& !held_key(admitted(before), addr as u64)
            &&& added(admitted(after), admitted(before), Entry {
                row: answered_name(a),
                key: addr as u64,
                deadline_ms: add_ms_spec(answered_at(a), window_ms_of(before)),
                value: 0,
            })
        },
        Admitted::Refreshed { holder } => {
            &&& token_current(a, before)
            &&& holds(admitted(before), holder, addr as u64)
            &&& refreshed_from(admitted(after), admitted(before), holder, addr as u64)
            &&& not_shortened(admitted(after), admitted(before))
            &&& bounded_by(admitted(after), admitted(before),
                add_ms_spec(answered_at(a), window_ms_of(before)))
            &&& crate::pool::extended(admitted(after), admitted(before), holder, addr as u64,
                add_ms_spec(answered_at(a), window_ms_of(before)), None)
        },
        Admitted::NameAtQuota => {
            &&& token_current(a, before)
            &&& admitted(after) == admitted(before)
            &&& !held_key(admitted(before), addr as u64)
            &&& count(admitted(before), answered_name(a)) >= squota(admitted_pool(before))
        },
        Admitted::Full => {
            &&& token_current(a, before)
            &&& admitted(after) == admitted(before)
            &&& !held_key(admitted(before), addr as u64)
            &&& admitted(before).len() >= scap(admitted_pool(before))
        },
    }
}

/// What `release_expired` promises of its result and of the tables before
/// and after.
pub open spec fn release_post(before: Pins, after: Pins, name: u32, now_ms: u64, r: usize) -> bool {
    &&& same_limits(after, before)
    &&& asked(after) == asked(before)
    &&& flows(after) == flows(before)
    &&& admitted(after).len() + r == admitted(before).len()
    &&& subset_of(admitted(after), admitted(before))
    &&& keeps_live(admitted(after), admitted(before), now_ms)
    &&& keeps_other_rows(admitted(after), admitted(before), name)
    &&& row_live(admitted(after), name, now_ms)
}

/// `key` is one of `addrs`.
pub open spec fn listed(addrs: Seq<u32>, key: u64) -> bool {
    exists|i: int| 0 <= i < addrs.len() && addrs[i] as u64 == key
}

/// `release_expired(name, now)` keeps `e`: another name's, or unexpired.
pub open spec fn release_keeps(e: Entry, name: u32, now_ms: u64) -> bool {
    e.row != name || e.deadline_ms > now_ms
}

/// Some entry of `s` that the release keeps holds `key`.
pub open spec fn kept_holder(s: Seq<Entry>, key: u64, name: u32, now_ms: u64) -> bool {
    exists|k: int| 0 <= k < s.len() && s[k].key == key && release_keeps(s[k], name, now_ms)
}

/// Some entry of `s` that the release keeps is at `(row, key)`.
pub open spec fn kept_at(s: Seq<Entry>, row: u32, key: u64, name: u32, now_ms: u64) -> bool {
    exists|k: int| 0 <= k < s.len() && s[k].row == row && s[k].key == key && release_keeps(s[k], name, now_ms)
}

/// How many positions of `addrs` name an address no row of `s` holds.
pub open spec fn refused_in(s: Seq<Entry>, addrs: Seq<u32>) -> nat
    decreases addrs.len(),
{
    if addrs.len() == 0 {
        0
    } else {
        refused_in(s, addrs.drop_last()) + if held_key(s, addrs.last() as u64) { 0nat } else { 1nat }
    }
}

/// What a matched answer carrying `addrs` does to the admitted table.
/// Opaque: a caller that only passes it on does not unfold it. The lemmas
/// and theorems that read it reveal it.
#[verifier::opaque]
pub open spec fn resolved_tables(before: Pins, after: Pins, name: u32, addrs: Seq<u32>, now_ms: u64) -> bool {
    let b = admitted(before);
    let a = admitted(after);
    let limit = add_ms_spec(now_ms, window_ms_of(before));
    // Nothing but these addresses is new, and a new one is the name's.
    &&& forall|j: int| 0 <= j < a.len() ==> kept_at(b, (#[trigger] a[j]).row, a[j].key, name, now_ms)
        || (a[j].row == name && listed(addrs, a[j].key) && a[j].deadline_ms == limit && a[j].value == 0)
    // Nothing is lost but the name's own expired addresses.
    &&& forall|k: int| 0 <= k < b.len() && release_keeps(#[trigger] b[k], name, now_ms) ==> kept_by_key(a, b[k])
    // Nothing is extended but these addresses.
    &&& forall|j: int| 0 <= j < a.len() && !listed(addrs, (#[trigger] a[j]).key) ==> has(b, a[j])
    &&& bounded_by_key(a, b, limit)
    // Each address is entered or extended, or refused for want of room.
    &&& forall|i: int| 0 <= i < addrs.len() ==> held_until(a, (#[trigger] addrs[i]) as u64, limit)
        || (!held_key(a, addrs[i] as u64)
            && (count(a, name) >= squota(admitted_pool(before)) || a.len() >= scap(admitted_pool(before))))
    // Addresses are taken in order: after one is refused, none is entered.
    &&& forall|i: int, j: int| 0 <= i < j < addrs.len() && !held_key(a, (#[trigger] addrs[i]) as u64)
        && held_key(a, (#[trigger] addrs[j]) as u64)
        ==> kept_holder(b, addrs[j] as u64, name, now_ms)
            || exists|k: int| 0 <= k < i && addrs[k] == addrs[j]
}

/// What `resolve` promises of its result and of the tables before and after.
pub open spec fn resolve_post(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>) -> bool {
    &&& same_limits(after, before)
    &&& flows(after) == flows(before)
    &&& r.is_some() == live(asked(before), name, question_key(txid, port), now_ms)
    &&& no_new_keys(asked(after), asked(before))
    &&& match r {
        Some(c) => {
            &&& !holds(asked(after), name, question_key(txid, port))
            &&& keeps_others(asked(after), asked(before), name, question_key(txid, port))
            &&& c.admitted + c.refused == addrs.len()
            &&& c.refused == refused_in(admitted(after), addrs)
            &&& addrs.len() > 0 ==> resolved_tables(before, after, name, addrs, now_ms)
            // An answer that carries no address leaves the admitted table alone.
            &&& addrs.len() == 0 ==> admitted(after) == admitted(before)
            // Otherwise the name's expired addresses were released first.
            &&& addrs.len() > 0 && now_ms < u64::MAX ==> row_live(admitted(after), name, now_ms)
        },
        None => asked(after) == asked(before) && admitted(after) == admitted(before),
    }
}

/// What `expire_questions` promises: the question table loses expired
/// entries and the other two tables are as they were.
pub open spec fn expire_questions_post(before: Pins, after: Pins, now_ms: u64, budget: usize, r: usize) -> bool {
    &&& same_limits(after, before)
    &&& admitted(after) == admitted(before)
    &&& flows(after) == flows(before)
    &&& r <= budget
    &&& asked(after).len() + r == asked(before).len()
    &&& subset_of(asked(after), asked(before))
    &&& keeps_live(asked(after), asked(before), now_ms)
    &&& r < budget ==> none_expired(asked(after), now_ms)
}

/// What `expire` promises of its result and of the tables before and after.
pub open spec fn expire_post(before: Pins, after: Pins, now_ms: u64, budget: usize, r: usize) -> bool {
    &&& same_limits(after, before)
    &&& r <= budget
    &&& asked(after).len() + admitted(after).len() + flows(after).len() + r
        == asked(before).len() + admitted(before).len() + flows(before).len()
    &&& subset_of(asked(after), asked(before))
    &&& subset_of(admitted(after), admitted(before))
    &&& subset_of(flows(after), flows(before))
    &&& keeps_live(asked(after), asked(before), now_ms)
    &&& keeps_live(admitted(after), admitted(before), now_ms)
    &&& keeps_live(flows(after), flows(before), now_ms)
    &&& r < budget ==> none_expired(asked(after), now_ms)
        && none_expired(admitted(after), now_ms)
        && none_expired(flows(after), now_ms)
}

/// What `egress` promises of its result and of the tables before and after.
pub open spec fn egress_post(before: Pins, after: Pins, dst: u32, t: Option<Transport>, now_ms: u64, r: Egress) -> bool {
    &&& same_limits(after, before)
    &&& asked(after) == asked(before)
    &&& admitted(after) == admitted(before)
    &&& match r {
        Egress::Refused => {
            &&& !flow_live(flows(before), dst, t, now_ms)
            &&& !live_key(admitted(before), dst as u64, now_ms)
            &&& flows(after) == flows(before)
        },
        Egress::ByFlow => {
            &&& flow_live(flows(before), dst, t, now_ms)
            &&& no_new_keys(flows(after), flows(before))
            &&& closes(t) ==> !flow_held(flows(after), dst, t)
            &&& closes(t) ==> keeps_others(flows(after), flows(before), dst, opt_key(t))
            &&& !closes(t) ==> not_shortened(flows(after), flows(before))
            &&& !closes(t) ==> refreshed_from(flows(after), flows(before), dst, opt_key(t))
            &&& !closes(t) ==> bounded_by(flows(after), flows(before),
                add_ms_spec(now_ms, idle_ms_of(before)))
            &&& !closes(t) ==> crate::pool::extended(flows(after), flows(before), dst, opt_key(t),
                add_ms_spec(now_ms, idle_ms_of(before)), None)
        },
        Egress::Window => {
            &&& !flow_live(flows(before), dst, t, now_ms)
            &&& live_key(admitted(before), dst as u64, now_ms)
            &&& flows(after) == flows(before)
            &&& t.is_some() && !closes(t) ==> (count(flows(before), dst) >= squota(flows_pool(before))
                && row_live(flows(before), dst, now_ms))
                || (flows(before).len() >= scap(flows_pool(before))
                && none_expired(flows(before), now_ms))
        },
        Egress::Retained => {
            &&& !flow_live(flows(before), dst, t, now_ms)
            &&& live_key(admitted(before), dst as u64, now_ms)
            &&& t.is_some()
            &&& !closes(t)
            &&& flow_held(flows(after), dst, t)
            &&& now_ms < u64::MAX ==> flow_live(flows(after), dst, t, now_ms)
            &&& if flow_held(flows(before), dst, t) {
                refreshed_from(flows(after), flows(before), dst, opt_key(t))
                    && changed_only_to(flows(after), flows(before), Entry {
                        row: dst,
                        key: opt_key(t),
                        deadline_ms: add_ms_spec(now_ms, idle_ms_of(before)),
                        value: 0,
                    })
            } else {
                &&& only_adds(flows(after), flows(before), Entry {
                    row: dst,
                    key: opt_key(t),
                    deadline_ms: add_ms_spec(now_ms, idle_ms_of(before)),
                    value: 0,
                })
                &&& keeps_live(flows(after), flows(before), now_ms)
                &&& flows(after).len() <= flows(before).len() + 1
                &&& flows(after).len() >= flows(before).len()
                &&& (count(flows(before), dst) < squota(flows_pool(before))
                    && flows(before).len() < scap(flows_pool(before)))
                    ==> added(flows(after), flows(before), Entry {
                        row: dst,
                        key: opt_key(t),
                        deadline_ms: add_ms_spec(now_ms, idle_ms_of(before)),
                        value: 0,
                    })
                &&& count(flows(before), dst) >= squota(flows_pool(before))
                    ==> keeps_other_rows(flows(after), flows(before), dst)
            }
        },
    }
}

/// G5 (g): from `ask`'s guarantee alone, a question is refused only for
/// want of room: one the table already holds is refreshed, and one whose
/// name and table both have room is recorded.
pub proof fn theorem_g5_ask_refuses_only_for_room(before: Pins, after: Pins, name: u32, txid: u16, port: u16, now_ms: u64, r: Asked)
    requires
        ask_post(before, after, name, txid, port, now_ms, r),
    ensures
        holds(asked(before), name, question_key(txid, port)) ==> r == Asked::Refreshed,
        count(asked(before), name) < squota(asked_pool(before))
            && asked(before).len() < scap(asked_pool(before))
            ==> r == Asked::Recorded || r == Asked::Refreshed,
{
}

/// G5 (h): from `admit`'s guarantee alone, an address offered with a current
/// token is refused only for want of room: one some name holds is refreshed,
/// and one no name holds, whose name and table both have room, is entered.
pub proof fn theorem_g5_admit_refuses_only_for_room(before: Pins, after: Pins, a: Answered, addr: u32, r: Admitted)
    requires
        admit_post(before, after, a, addr, r),
        token_current(a, before),
    ensures
        held_key(admitted(before), addr as u64) ==> match r {
            Admitted::Refreshed { holder } => true,
            _ => false,
        },
        !held_key(admitted(before), addr as u64)
            && count(admitted(before), answered_name(a)) < squota(admitted_pool(before))
            && admitted(before).len() < scap(admitted_pool(before))
            ==> r == Admitted::New,
{
    match r {
        Admitted::Refreshed { holder } => {
            let s = admitted(before);
            let j = choose|j: int| 0 <= j < s.len() && s[j].row == holder && s[j].key == addr as u64;
            assert(s[j].key == addr as u64);
        },
        _ => {},
    }
}

/// G5 (b): from `admit`'s guarantee alone, an address entered new is entered
/// under the token's name, for the token's instant plus the window, and the
/// table then holds that entry, what it held before and nothing else.
pub proof fn theorem_g5_new_is_the_names(before: Pins, after: Pins, a: Answered, addr: u32, x: Entry)
    requires
        admit_post(before, after, a, addr, Admitted::New),
    ensures
        has(admitted(after), x) == (has(admitted(before), x) || x == Entry {
            row: answered_name(a),
            key: addr as u64,
            deadline_ms: add_ms_spec(answered_at(a), window_ms_of(before)),
            value: 0,
        }),
        admitted(after).len() == admitted(before).len() + 1,
{
    crate::pool::theorem_added_members(
        admitted(after),
        admitted(before),
        Entry {
            row: answered_name(a),
            key: addr as u64,
            deadline_ms: add_ms_spec(answered_at(a), window_ms_of(before)),
            value: 0,
        },
        x,
        0,
    );
}

/// G5 (b): from `admit`'s guarantee alone, an address a name holds is
/// refreshed under that name and no other, whichever name the token carries.
pub proof fn theorem_g5_first_owner(before: Pins, after: Pins, a: Answered, addr: u32, r: Admitted, e: Entry)
    requires
        pinv(before),
        admit_post(before, after, a, addr, r),
        token_current(a, before),
        has(admitted(before), e),
        e.key == addr as u64,
    ensures
        r == (Admitted::Refreshed { holder: e.row }),
{
    reveal(pinv);
    let s = admitted(before);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].key == addr as u64);
    match r {
        Admitted::Refreshed { holder } => {
            let j = choose|j: int| 0 <= j < s.len() && s[j].row == holder && s[j].key == addr as u64;
            if j < k {
                assert(s[j].key != s[k].key);
            } else if k < j {
                assert(s[k].key != s[j].key);
            }
        },
        _ => {},
    }
}

/// G5 (h): after `release_expired` for a name, an address of that name
/// refused at the quota is refused by addresses that have not expired.
pub proof fn theorem_g5_released_quota_is_live(before: Pins, mid: Pins, after: Pins, name: u32, now_ms: u64, n: usize, a: Answered, addr: u32)
    requires
        release_post(before, mid, name, now_ms, n),
        admit_post(mid, after, a, addr, Admitted::NameAtQuota),
        answered_name(a) == name,
    ensures
        row_live(admitted(mid), name, now_ms),
        count(admitted(mid), name) >= squota(admitted_pool(mid)),
        admitted(after) == admitted(mid),
{
}

/// The six theorems named `theorem_gd_a` to `theorem_gd_f` state G5 for one
/// answer from `resolve`'s guarantee alone; `Gate::dns_answer` (GD1, GD2)
/// rests on them. Their letters are their own and are not the gate's GD0 to
/// GD2.
///
/// G5 (b), of one answer (a): from `resolve`'s guarantee alone, an entry the admitted
/// table did not hold before is there because this table held a live
/// question for this name, is under this name, and is one of the answer's
/// addresses.
pub proof fn theorem_gd_a_admitted_only_by_its_question(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, r: Option<Admits>, j: int)
    requires
        resolve_post(before, after, name, txid, port, addrs, now_ms, r),
        0 <= j < admitted(after).len(),
        !holds(admitted(before), admitted(after)[j].row, admitted(after)[j].key),
    ensures
        live(asked(before), name, question_key(txid, port), now_ms),
        admitted(after)[j].row == name,
        listed(addrs, admitted(after)[j].key),
        admitted(after)[j].deadline_ms == add_ms_spec(now_ms, window_ms_of(before)),
{
    reveal(resolved_tables);
    let a = admitted(after);
    if r.is_none() {
        assert(a[j].row == a[j].row && a[j].key == a[j].key);
    }
}

/// Of one answer (b), first owner: an address of the answer that another name held, or
/// that this name held unexpired, is still held under that name and no
/// other, until at least this answer's window.
pub proof fn theorem_gd_b_first_owner_keeps(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, c: Admits, e: Entry, j: int)
    requires
        pinv(after),
        resolve_post(before, after, name, txid, port, addrs, now_ms, Some(c)),
        has(admitted(before), e),
        listed(addrs, e.key),
        release_keeps(e, name, now_ms),
        0 <= j < admitted(after).len(),
        admitted(after)[j].key == e.key,
    ensures
        admitted(after)[j].row == e.row,
        admitted(after)[j].deadline_ms >= add_ms_spec(now_ms, window_ms_of(before)),
{
    reveal(pinv);
    reveal(resolved_tables);
    let a = admitted(after);
    let b = admitted(before);
    let limit = add_ms_spec(now_ms, window_ms_of(before));
    let k = choose|k: int| 0 <= k < b.len() && b[k] == e;
    assert(kept_by_key(a, b[k]));
    let m = choose|m: int| 0 <= m < a.len() && a[m].row == e.row && a[m].key == e.key && a[m].deadline_ms >= e.deadline_ms;
    if m < j {
        assert(a[m].key != a[j].key);
    } else if j < m {
        assert(a[j].key != a[m].key);
    }
    let i = choose|i: int| 0 <= i < addrs.len() && addrs[i] as u64 == e.key;
    assert(held_key(a, addrs[i] as u64)) by {
        assert(a[j].key == addrs[i] as u64);
    }
    let n = choose|n: int| 0 <= n < a.len() && a[n].key == addrs[i] as u64 && a[n].deadline_ms >= limit;
    if n < j {
        assert(a[n].key != a[j].key);
    } else if j < n {
        assert(a[j].key != a[n].key);
    }
}

/// Of one answer (c), room: if the name and the table both have room afterwards, every
/// address of the answer is held.
pub proof fn theorem_gd_c_room_admits_all(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, c: Admits, i: int)
    requires
        resolve_post(before, after, name, txid, port, addrs, now_ms, Some(c)),
        count(admitted(after), name) < squota(admitted_pool(before)),
        admitted(after).len() < scap(admitted_pool(before)),
        0 <= i < addrs.len(),
    ensures
        held_key(admitted(after), addrs[i] as u64),
{
    reveal(resolved_tables);
    let a = admitted(after);
    let limit = add_ms_spec(now_ms, window_ms_of(before));
    assert(held_until(a, addrs[i] as u64, limit));
    let n = choose|n: int| 0 <= n < a.len() && a[n].key == addrs[i] as u64 && a[n].deadline_ms >= limit;
    assert(a[n].key == addrs[i] as u64);
}

/// Of one answer (d), order: an address entered by this answer (held after, by no entry
/// the release kept) comes before every address the answer was refused,
/// unless it repeats an earlier one.
pub proof fn theorem_gd_d_entered_in_order(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, c: Admits, i: int, j: int)
    requires
        resolve_post(before, after, name, txid, port, addrs, now_ms, Some(c)),
        0 <= i < j < addrs.len(),
        !held_key(admitted(after), addrs[i] as u64),
        !kept_holder(admitted(before), addrs[j] as u64, name, now_ms),
        forall|k: int| 0 <= k < i ==> addrs[k] != addrs[j],
    ensures
        !held_key(admitted(after), addrs[j] as u64),
{
    reveal(resolved_tables);
}

/// Of one answer (f): an address the name held expired, and holds after an answer that
/// carries an address, was released and entered again: its entry is a fresh
/// admission by this answer, never the old one extended.
pub proof fn theorem_gd_f_expired_comes_back_fresh(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, c: Admits, e: Entry, j: int)
    requires
        pinv(before),
        resolve_post(before, after, name, txid, port, addrs, now_ms, Some(c)),
        addrs.len() > 0,
        has(admitted(before), e),
        e.row == name,
        e.deadline_ms <= now_ms,
        0 <= j < admitted(after).len(),
        admitted(after)[j].row == name,
        admitted(after)[j].key == e.key,
    ensures
        listed(addrs, e.key),
        admitted(after)[j].deadline_ms == add_ms_spec(now_ms, window_ms_of(before)),
        admitted(after)[j].value == 0,
{
    reveal(pinv);
    reveal(resolved_tables);
    let b = admitted(before);
    if kept_at(b, name, e.key, name, now_ms) {
        let k = choose|k: int| 0 <= k < b.len() && b[k].row == name && b[k].key == e.key && release_keeps(b[k], name, now_ms);
        crate::pool::lemma_only_entry(b, e, k);
    }
}

/// G5 (h), of one answer (e): an answer that carries an address leaves its name with no expired address: the release came first.
pub proof fn theorem_gd_e_released_first(before: Pins, after: Pins, name: u32, txid: u16, port: u16, addrs: Seq<u32>, now_ms: u64, c: Admits, j: int)
    requires
        resolve_post(before, after, name, txid, port, addrs, now_ms, Some(c)),
        addrs.len() > 0,
        now_ms < u64::MAX,
        0 <= j < admitted(after).len(),
        admitted(after)[j].row == name,
    ensures
        admitted(after)[j].deadline_ms > now_ms,
{
}

/// Two tables of the same rows, position by position, count each row alike.
proof fn lemma_count_same_rows(s: Seq<Entry>, t: Seq<Entry>, row: u32)
    requires
        s.len() == t.len(),
        forall|j: int| 0 <= j < s.len() ==> (#[trigger] s[j]).row == t[j].row,
    ensures
        count(s, row) == count(t, row),
    decreases s.len(),
{
    if s.len() > 0 {
        let ds = s.drop_last();
        let dt = t.drop_last();
        assert forall|j: int| 0 <= j < ds.len() implies (#[trigger] ds[j]).row == dt[j].row by {
            assert(ds[j] == s[j]);
            assert(dt[j] == t[j]);
        }
        lemma_count_same_rows(ds, dt, row);
        assert(s.last() == s[s.len() - 1]);
        assert(t.last() == t[t.len() - 1]);
    }
}

/// `refused_in` reads only which listed addresses some row holds.
proof fn lemma_refused_in_agree(s: Seq<Entry>, t: Seq<Entry>, addrs: Seq<u32>)
    requires
        forall|k: int| 0 <= k < addrs.len() ==> held_key(s, (#[trigger] addrs[k]) as u64) == held_key(t, addrs[k] as u64),
    ensures
        refused_in(s, addrs) == refused_in(t, addrs),
    decreases addrs.len(),
{
    if addrs.len() > 0 {
        let d = addrs.drop_last();
        assert forall|k: int| 0 <= k < d.len() implies held_key(s, (#[trigger] d[k]) as u64) == held_key(t, d[k] as u64) by {
            assert(d[k] == addrs[k]);
        }
        lemma_refused_in_agree(s, t, d);
        assert(addrs.last() == addrs[addrs.len() - 1]);
    }
}

/// One more address of the prefix adds its own refusal, if any.
#[verifier::spinoff_prover]
proof fn lemma_refused_in_take(s: Seq<Entry>, addrs: Seq<u32>, i: int)
    requires
        0 <= i < addrs.len(),
    ensures
        refused_in(s, addrs.take(i + 1)) == refused_in(s, addrs.take(i))
            + if held_key(s, addrs[i] as u64) { 0nat } else { 1nat },
{
    assert(addrs.take(i + 1).drop_last() =~= addrs.take(i));
    assert(addrs.take(i + 1).last() == addrs[i]);
}

/// A key is listed in the prefix one longer exactly when it is listed in the
/// prefix or is the next address.
proof fn lemma_listed_take(addrs: Seq<u32>, i: int, key: u64)
    requires
        0 <= i < addrs.len(),
    ensures
        listed(addrs.take(i + 1), key) == (listed(addrs.take(i), key) || key == addrs[i] as u64),
{
    let p = addrs.take(i);
    let q = addrs.take(i + 1);
    if listed(q, key) {
        let k = choose|k: int| 0 <= k < q.len() && q[k] as u64 == key;
        if k < i {
            assert(p[k] == q[k]);
        }
    }
    if listed(p, key) {
        let k = choose|k: int| 0 <= k < p.len() && p[k] as u64 == key;
        assert(q[k] == p[k]);
    }
    if key == addrs[i] as u64 {
        assert(q[i] == addrs[i]);
    }
}

/// Before the first address: the release alone gives `resolved_tables` of the
/// empty prefix, no refusal, and every entry kept by the release.
proof fn lemma_resolve_base(b: Pins, r: Pins, name: u32, addrs: Seq<u32>, now_ms: u64)
    requires
        pinv(b),
        subset_of(admitted(r), admitted(b)),
        keeps_live(admitted(r), admitted(b), now_ms),
        keeps_other_rows(admitted(r), admitted(b), name),
        row_live(admitted(r), name, now_ms),
    ensures
        resolved_tables(b, r, name, addrs.take(0), now_ms),
        refused_in(admitted(r), addrs.take(0)) == 0,
{
    reveal(pinv);
    reveal(resolved_tables);
    let bs = admitted(b);
    let rs = admitted(r);
    let p = addrs.take(0);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    assert(p.len() == 0);
    assert forall|j: int| 0 <= j < rs.len() implies kept_at(bs, (#[trigger] rs[j]).row, rs[j].key, name, now_ms)
        && has(bs, rs[j]) by {
        assert(has(bs, rs[j]));
        let k = choose|k: int| 0 <= k < bs.len() && bs[k] == rs[j];
        assert(bs[k].row == rs[j].row && bs[k].key == rs[j].key);
        assert(release_keeps(bs[k], name, now_ms));
    }
    assert forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) implies kept_by_key(rs, bs[k]) by {
        assert(has(rs, bs[k]));
        let j = choose|j: int| 0 <= j < rs.len() && rs[j] == bs[k];
        assert(rs[j].row == bs[k].row && rs[j].key == bs[k].key && rs[j].deadline_ms >= bs[k].deadline_ms);
    }
    assert forall|j: int, k: int| 0 <= j < rs.len() && 0 <= k < bs.len()
        && (#[trigger] rs[j]).row == (#[trigger] bs[k]).row && rs[j].key == bs[k].key
        implies rs[j].deadline_ms <= bs[k].deadline_ms || rs[j].deadline_ms <= limit by {
        assert(has(bs, rs[j]));
        let k0 = choose|k0: int| 0 <= k0 < bs.len() && bs[k0] == rs[j];
        if k0 < k {
            assert(!(bs[k0].row == bs[k].row && bs[k0].key == bs[k].key));
        } else if k < k0 {
            assert(!(bs[k].row == bs[k0].row && bs[k].key == bs[k0].key));
        }
    }
    assert(bounded_by_key(rs, bs, limit));
}

/// `bounded_by_key` carries over a step that keeps each old position's row
/// and key and lengthens it at most to `limit`, and appends only entries
/// within `limit`.
proof fn lemma_resolve_bounded_step(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, limit: u64)
    requires
        bounded_by_key(ms, bs, limit),
        ms.len() <= as_.len(),
        forall|j: int| 0 <= j < as_.len() ==> if j < ms.len() {
            (#[trigger] as_[j]).row == ms[j].row && as_[j].key == ms[j].key
                && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit)
        } else {
            as_[j].deadline_ms <= limit
        },
    ensures
        bounded_by_key(as_, bs, limit),
{
    assert forall|j: int, k: int| 0 <= j < as_.len() && 0 <= k < bs.len()
        && (#[trigger] as_[j]).row == (#[trigger] bs[k]).row && as_[j].key == bs[k].key
        implies as_[j].deadline_ms <= bs[k].deadline_ms || as_[j].deadline_ms <= limit by {
        if j < ms.len() {
            assert(ms[j].row == bs[k].row && ms[j].key == bs[k].key);
            assert(ms[j].deadline_ms <= bs[k].deadline_ms || ms[j].deadline_ms <= limit);
        }
    }
}

/// Clause 2 of `resolved_tables` (nothing lost) carries over a step that
/// keeps each old position's row and key and shortens nothing. Kept apart
/// from the other clauses: its trigger is on the table before, theirs on
/// the table after, and together they instantiate each other without end.
proof fn lemma_resolve_kept_step(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, name: u32, now_ms: u64)
    requires
        forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) ==> kept_by_key(ms, bs[k]),
        ms.len() <= as_.len(),
        forall|j: int| 0 <= j < ms.len() ==> (#[trigger] ms[j]).row == as_[j].row && ms[j].key == as_[j].key
            && as_[j].deadline_ms >= ms[j].deadline_ms,
    ensures
        forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) ==> kept_by_key(as_, bs[k]),
{
    assert forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) implies kept_by_key(as_, bs[k]) by {
        assert(kept_by_key(ms, bs[k]));
    }
}

/// A refused address (at the quota or at capacity) leaves the table alone.
/// The clauses of `resolved_tables` other than `bounded_by_key`, over `ms`
/// and the prefix `p`, carry to the prefix one longer.
proof fn lemma_resolve_step_refused(bs: Seq<Entry>, ms: Seq<Entry>, name: u32, addrs: Seq<u32>, p: Seq<u32>, q: Seq<u32>, i: int, now_ms: u64, limit: u64, quota: int, cap: int)
    requires
        0 <= i < addrs.len(),
        p == addrs.take(i),
        q == addrs.take(i + 1),
        !held_key(ms, addrs[i] as u64),
        count(ms, name) >= quota || ms.len() >= cap,
        forall|j: int| 0 <= j < ms.len() ==> kept_at(bs, (#[trigger] ms[j]).row, ms[j].key, name, now_ms)
            || (ms[j].row == name && listed(p, ms[j].key) && ms[j].deadline_ms == limit && ms[j].value == 0),
        forall|j: int| 0 <= j < ms.len() && !listed(p, (#[trigger] ms[j]).key) ==> has(bs, ms[j]),
        forall|k: int| 0 <= k < p.len() ==> held_until(ms, (#[trigger] p[k]) as u64, limit)
            || (!held_key(ms, p[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < p.len() && !held_key(ms, (#[trigger] p[i2]) as u64)
            && held_key(ms, (#[trigger] p[j2]) as u64)
            ==> kept_holder(bs, p[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && p[k] == p[j2],
    ensures
        forall|j: int| 0 <= j < ms.len() ==> kept_at(bs, (#[trigger] ms[j]).row, ms[j].key, name, now_ms)
            || (ms[j].row == name && listed(q, ms[j].key) && ms[j].deadline_ms == limit && ms[j].value == 0),
        forall|j: int| 0 <= j < ms.len() && !listed(q, (#[trigger] ms[j]).key) ==> has(bs, ms[j]),
        forall|k: int| 0 <= k < q.len() ==> held_until(ms, (#[trigger] q[k]) as u64, limit)
            || (!held_key(ms, q[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(ms, (#[trigger] q[i2]) as u64)
            && held_key(ms, (#[trigger] q[j2]) as u64)
            ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && q[k] == q[j2],
        refused_in(ms, q) == refused_in(ms, p) + 1,
{
    let x = addrs[i];
    assert forall|key: u64| #[trigger] listed(q, key) == (listed(p, key) || key == x as u64) by {
        lemma_listed_take(addrs, i, key);
    }
    assert forall|k: int| 0 <= k < q.len() implies held_until(ms, (#[trigger] q[k]) as u64, limit)
        || (!held_key(ms, q[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)) by {
        if k < i {
            assert(q[k] == p[k]);
        } else {
            assert(q[k] == x);
        }
    }
    assert forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(ms, (#[trigger] q[i2]) as u64)
        && held_key(ms, (#[trigger] q[j2]) as u64)
        implies kept_holder(bs, q[j2] as u64, name, now_ms)
            || exists|k: int| 0 <= k < i2 && q[k] == q[j2] by {
        if j2 == i {
            assert(q[j2] == x);
        }
        assert(j2 < i);
        assert(q[i2] == p[i2]);
        assert(q[j2] == p[j2]);
        if !kept_holder(bs, p[j2] as u64, name, now_ms) {
            let k = choose|k: int| 0 <= k < i2 && p[k] == p[j2];
            assert(q[k] == p[k]);
        }
    }
    lemma_refused_in_take(ms, addrs, i);
}

/// What adding `e` does to which keys are held, through `theorem_added_members`
/// only: a key is held after exactly when it was held before or is `e`'s, and
/// a key held until `limit` before still is.
proof fn lemma_added_key(as_: Seq<Entry>, ms: Seq<Entry>, e: Entry, key: u64, limit: u64)
    requires
        added(as_, ms, e),
    ensures
        held_key(as_, key) == (held_key(ms, key) || key == e.key),
        held_until(ms, key, limit) ==> held_until(as_, key, limit),
        key == e.key && e.deadline_ms >= limit ==> held_until(as_, key, limit),
{
    crate::pool::theorem_added_members(as_, ms, e, e, 0);
    if held_key(as_, key) {
        let j = choose|j: int| 0 <= j < as_.len() && as_[j].key == key;
        crate::pool::theorem_added_members(as_, ms, e, as_[j], 0);
        assert(has(as_, as_[j]));
        if as_[j] != e {
            let m = choose|m: int| 0 <= m < ms.len() && ms[m] == as_[j];
            assert(ms[m].key == key);
        }
    }
    if held_key(ms, key) {
        let m = choose|m: int| 0 <= m < ms.len() && ms[m].key == key;
        crate::pool::theorem_added_members(as_, ms, e, ms[m], 0);
        assert(has(ms, ms[m]));
        let j = choose|j: int| 0 <= j < as_.len() && as_[j] == ms[m];
        assert(as_[j].key == key);
    }
    if held_until(ms, key, limit) {
        let m = choose|m: int| 0 <= m < ms.len() && ms[m].key == key && ms[m].deadline_ms >= limit;
        crate::pool::theorem_added_members(as_, ms, e, ms[m], 0);
        assert(has(ms, ms[m]));
        let j = choose|j: int| 0 <= j < as_.len() && as_[j] == ms[m];
        assert(as_[j].key == key && as_[j].deadline_ms >= limit);
    }
    if key == e.key {
        let j = choose|j: int| 0 <= j < as_.len() && as_[j] == e;
        assert(as_[j].key == key);
    }
}

/// Each entry after adding `e` is `e` or was there before.
proof fn lemma_added_entry(as_: Seq<Entry>, ms: Seq<Entry>, e: Entry, j: int)
    requires
        added(as_, ms, e),
        0 <= j < as_.len(),
    ensures
        as_[j] == e || has(ms, as_[j]),
{
    crate::pool::theorem_added_members(as_, ms, e, as_[j], 0);
    assert(has(as_, as_[j]));
}

/// Clause 2 of `resolved_tables` (nothing lost) carries over adding `e`.
proof fn lemma_resolve_kept_added(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, e: Entry, name: u32, now_ms: u64)
    requires
        forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) ==> kept_by_key(ms, bs[k]),
        added(as_, ms, e),
    ensures
        forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) ==> kept_by_key(as_, bs[k]),
{
    assert forall|k: int| 0 <= k < bs.len() && release_keeps(#[trigger] bs[k], name, now_ms) implies kept_by_key(as_, bs[k]) by {
        assert(kept_by_key(ms, bs[k]));
        let m = choose|m: int| 0 <= m < ms.len() && ms[m].row == bs[k].row && ms[m].key == bs[k].key
            && ms[m].deadline_ms >= bs[k].deadline_ms;
        crate::pool::theorem_added_members(as_, ms, e, ms[m], 0);
        assert(has(ms, ms[m]));
        let j = choose|j: int| 0 <= j < as_.len() && as_[j] == ms[m];
        assert(as_[j].row == bs[k].row && as_[j].key == bs[k].key && as_[j].deadline_ms >= bs[k].deadline_ms);
    }
}

/// `bounded_by_key` carries over adding an entry that ends by `limit`.
proof fn lemma_resolve_bounded_added(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, e: Entry, limit: u64)
    requires
        bounded_by_key(ms, bs, limit),
        added(as_, ms, e),
        e.deadline_ms <= limit,
    ensures
        bounded_by_key(as_, bs, limit),
{
    assert forall|j: int, k: int| 0 <= j < as_.len() && 0 <= k < bs.len()
        && (#[trigger] as_[j]).row == (#[trigger] bs[k]).row && as_[j].key == bs[k].key
        implies as_[j].deadline_ms <= bs[k].deadline_ms || as_[j].deadline_ms <= limit by {
        lemma_added_entry(as_, ms, e, j);
        if as_[j] != e {
            let m = choose|m: int| 0 <= m < ms.len() && ms[m] == as_[j];
            assert(ms[m].row == bs[k].row && ms[m].key == bs[k].key);
        }
    }
}

/// `resolved_tables` of the longer prefix after an address was added, from
/// the clauses the step lemma shows of the table after and `added` itself:
/// clause 2 and `bounded_by_key` follow by membership, not by position.
proof fn lemma_resolve_pack_added(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64, e: Entry)
    requires
        0 <= i < addrs.len(),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
        added(admitted(a), admitted(m), e),
        e.deadline_ms == add_ms_spec(now_ms, window_ms_of(b)),
        ({
            let bs = admitted(b);
            let as_ = admitted(a);
            let q = addrs.take(i + 1);
            let limit = add_ms_spec(now_ms, window_ms_of(b));
            let quota = squota(admitted_pool(b));
            let cap = scap(admitted_pool(b));
            &&& forall|j: int| 0 <= j < as_.len() ==> kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
                || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0)
            &&& forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) ==> has(bs, as_[j])
            &&& forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
                || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap))
            &&& forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
                && held_key(as_, (#[trigger] q[j2]) as u64)
                ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                    || exists|k: int| 0 <= k < i2 && q[k] == q[j2]
        }),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
{
    reveal(resolved_tables);
    let bs = admitted(b);
    let ms = admitted(m);
    let as_ = admitted(a);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    lemma_resolve_kept_added(bs, ms, as_, e, name, now_ms);
    lemma_resolve_bounded_added(bs, ms, as_, e, limit);
}

/// A new address is entered under the name: the name and the table had room,
/// so every earlier address is held. Stated by key: `added` fixes what the
/// table holds, not where.
proof fn lemma_resolve_step_new(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, name: u32, addrs: Seq<u32>, p: Seq<u32>, q: Seq<u32>, i: int, now_ms: u64, limit: u64, quota: int, cap: int)
    requires
        0 <= i < addrs.len(),
        p == addrs.take(i),
        q == addrs.take(i + 1),
        count(as_, name) <= quota,
        as_.len() <= cap,
        !held_key(ms, addrs[i] as u64),
        added(as_, ms, Entry { row: name, key: addrs[i] as u64, deadline_ms: limit, value: 0 }),
        forall|j: int| 0 <= j < ms.len() ==> kept_at(bs, (#[trigger] ms[j]).row, ms[j].key, name, now_ms)
            || (ms[j].row == name && listed(p, ms[j].key) && ms[j].deadline_ms == limit && ms[j].value == 0),
        forall|j: int| 0 <= j < ms.len() && !listed(p, (#[trigger] ms[j]).key) ==> has(bs, ms[j]),
        forall|k: int| 0 <= k < p.len() ==> held_until(ms, (#[trigger] p[k]) as u64, limit)
            || (!held_key(ms, p[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)),
    ensures
        forall|j: int| 0 <= j < as_.len() ==> kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
            || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0),
        forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) ==> has(bs, as_[j]),
        forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
            || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
            && held_key(as_, (#[trigger] q[j2]) as u64)
            ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && q[k] == q[j2],
        refused_in(as_, q) == refused_in(ms, p),
{
    let x = addrs[i];
    let e = Entry { row: name, key: x as u64, deadline_ms: limit, value: 0 };
    assert forall|k: int| 0 <= k < i implies #[trigger] p[k] == q[k] by {
    }
    assert(q[i] == x);
    assert forall|key: u64| #[trigger] listed(q, key) == (listed(p, key) || key == x as u64) by {
        lemma_listed_take(addrs, i, key);
    }
    // The name and the table had room before the address was added.
    crate::pool::theorem_added_members(as_, ms, e, e, name);
    assert(count(ms, name) < quota);
    assert(ms.len() < cap);
    // So every earlier address is held until the limit, in `ms` and in `as_`.
    assert forall|k: int| 0 <= k < i implies held_until(as_, (#[trigger] p[k]) as u64, limit)
        && held_key(ms, p[k] as u64) && held_key(as_, p[k] as u64) by {
        assert(held_until(ms, p[k] as u64, limit));
        lemma_added_key(as_, ms, e, p[k] as u64, limit);
    }
    lemma_added_key(as_, ms, e, x as u64, limit);
    assert forall|j: int| 0 <= j < as_.len() implies kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
        || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0) by {
        lemma_added_entry(as_, ms, e, j);
    }
    assert forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) implies has(bs, as_[j]) by {
        lemma_added_entry(as_, ms, e, j);
    }
    assert forall|k: int| 0 <= k < q.len() implies held_until(as_, (#[trigger] q[k]) as u64, limit)
        || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap)) by {
        if k < i {
            assert(q[k] == p[k]);
        } else {
            assert(q[k] == x);
        }
    }
    // Every address of the longer prefix is held, so no pair has a refused first.
    assert forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
        && held_key(as_, (#[trigger] q[j2]) as u64)
        implies kept_holder(bs, q[j2] as u64, name, now_ms)
            || exists|k: int| 0 <= k < i2 && q[k] == q[j2] by {
        assert(q[i2] == p[i2]);
    }
    // The count.
    assert forall|k: int| 0 <= k < p.len() implies held_key(as_, (#[trigger] p[k]) as u64) == held_key(ms, p[k] as u64) by {
    }
    lemma_refused_in_agree(as_, ms, p);
    lemma_refused_in_take(as_, addrs, i);
}

/// What `admit`'s `Refreshed` guarantee makes of the admitted table: one
/// position `j0`, holding `x`, changed, to the later of its deadline and
/// `limit`, and every other position is unchanged. Apart from the step
/// lemma, so that the pairwise `unique_keys` quantifiers stay here.
proof fn lemma_refreshed_shape(ms: Seq<Entry>, as_: Seq<Entry>, holder: u32, x: u64, limit: u64) -> (j0: int)
    requires
        unique_keys(ms),
        unique_keys(as_),
        refreshed_from(as_, ms, holder, x),
        crate::pool::extended(as_, ms, holder, x, limit, None),
    ensures
        0 <= j0 < ms.len(),
        as_.len() == ms.len(),
        ms[j0].key == x,
        as_[j0] == (Entry {
            row: ms[j0].row,
            key: x,
            deadline_ms: if ms[j0].deadline_ms >= limit { ms[j0].deadline_ms } else { limit },
            value: ms[j0].value,
        }),
        forall|j: int| 0 <= j < as_.len() && j != j0 ==> #[trigger] as_[j] == ms[j],
{
    reveal(crate::pool::extended);
    let w = choose|w: Entry| #[trigger] has(ms, w) && w.row == holder && w.key == x
        && has(as_, Entry {
            row: holder,
            key: x,
            deadline_ms: if w.deadline_ms >= limit { w.deadline_ms } else { limit },
            value: w.value,
        });
    let fe = Entry {
        row: holder,
        key: x,
        deadline_ms: if w.deadline_ms >= limit { w.deadline_ms } else { limit },
        value: w.value,
    };
    let p0 = choose|p0: int| 0 <= p0 < as_.len() && as_[p0] == fe;
    let w0 = choose|w0: int| 0 <= w0 < ms.len() && ms[w0] == w;
    assert(ms[p0].key == x);
    if p0 < w0 {
        assert(ms[p0].key != ms[w0].key);
    } else if w0 < p0 {
        assert(ms[w0].key != ms[p0].key);
    }
    assert forall|j: int| 0 <= j < as_.len() && j != p0 implies #[trigger] as_[j] == ms[j] by {
        if as_[j] != ms[j] {
            if j < p0 {
                assert(as_[j].key != as_[p0].key);
            } else {
                assert(as_[p0].key != as_[j].key);
            }
        }
    }
    p0
}

/// An address some row held is extended in place, the table clauses: what
/// is new or extended, and what the release kept.
proof fn lemma_resolve_step_refreshed(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, name: u32, addrs: Seq<u32>, p: Seq<u32>, q: Seq<u32>, i: int, now_ms: u64, limit: u64, quota: int, cap: int, j0: int)
    requires
        0 <= i < addrs.len(),
        p == addrs.take(i),
        q == addrs.take(i + 1),
        0 <= j0 < ms.len(),
        as_.len() == ms.len(),
        ms[j0].key == addrs[i] as u64,
        as_[j0] == (Entry {
            row: ms[j0].row,
            key: addrs[i] as u64,
            deadline_ms: if ms[j0].deadline_ms >= limit { ms[j0].deadline_ms } else { limit },
            value: ms[j0].value,
        }),
        forall|j: int| 0 <= j < as_.len() && j != j0 ==> #[trigger] as_[j] == ms[j],
        forall|j: int| 0 <= j < ms.len() ==> kept_at(bs, (#[trigger] ms[j]).row, ms[j].key, name, now_ms)
            || (ms[j].row == name && listed(p, ms[j].key) && ms[j].deadline_ms == limit && ms[j].value == 0),
        forall|j: int| 0 <= j < ms.len() && !listed(p, (#[trigger] ms[j]).key) ==> has(bs, ms[j]),
        forall|k: int| 0 <= k < p.len() ==> held_until(ms, (#[trigger] p[k]) as u64, limit)
            || (!held_key(ms, p[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < p.len() && !held_key(ms, (#[trigger] p[i2]) as u64)
            && held_key(ms, (#[trigger] p[j2]) as u64)
            ==> kept_holder(bs, p[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && p[k] == p[j2],
    ensures
        forall|j: int| 0 <= j < as_.len() ==> kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
            || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0),
        forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) ==> has(bs, as_[j]),
        forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
            || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
            && held_key(as_, (#[trigger] q[j2]) as u64)
            ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && q[k] == q[j2],
        forall|j: int| 0 <= j < as_.len() ==> if j < ms.len() {
            (#[trigger] as_[j]).row == ms[j].row && as_[j].key == ms[j].key
                && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit)
        } else {
            as_[j].deadline_ms <= limit
        },
        ms.len() <= as_.len(),
        forall|j: int| 0 <= j < ms.len() ==> (#[trigger] ms[j]).row == as_[j].row && ms[j].key == as_[j].key
            && as_[j].deadline_ms >= ms[j].deadline_ms,
        refused_in(as_, q) == refused_in(ms, p),
{
    let x = addrs[i];
    let w = ms[j0];
    assert forall|key: u64| #[trigger] listed(q, key) == (listed(p, key) || key == x as u64) by {
        lemma_listed_take(addrs, i, key);
    }
    assert forall|j: int| #![trigger as_[j]] #![trigger ms[j]] 0 <= j < as_.len() implies as_[j].row == ms[j].row
        && as_[j].key == ms[j].key && as_[j].deadline_ms >= ms[j].deadline_ms
        && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit) by {
        if j != j0 {
            assert(as_[j] == ms[j]);
        }
    }
    assert forall|j: int| 0 <= j < as_.len() implies kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
        || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0) by {
        if j != j0 {
            assert(as_[j] == ms[j]);
        } else {
            assert(kept_at(bs, w.row, w.key, name, now_ms)
                || (w.row == name && listed(p, w.key) && w.deadline_ms == limit && w.value == 0));
        }
    }
    assert forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) implies has(bs, as_[j]) by {
        assert(j != j0);
        assert(as_[j] == ms[j]);
        assert(!listed(p, ms[j].key));
    }
    assert forall|j: int| 0 <= j < as_.len() implies if j < ms.len() {
        (#[trigger] as_[j]).row == ms[j].row && as_[j].key == ms[j].key
            && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit)
    } else {
        as_[j].deadline_ms <= limit
    } by {
    }
    // Where `x` sits in the shorter prefix decides clause 6; with it settled,
    // the address clauses go to their own lemma.
    let xl = listed(p, x as u64);
    if !xl {
        assert(!listed(p, ms[j0].key));
        assert(kept_at(bs, ms[j0].row, ms[j0].key, name, now_ms));
        assert(kept_holder(bs, x as u64, name, now_ms));
    }
    lemma_resolve_step_refreshed_addrs(bs, ms, as_, name, addrs, p, q, i, now_ms, limit, quota, cap, j0);
}

/// An address some row held is extended in place, the address clauses:
/// which listed addresses are held, in order, and the count.
proof fn lemma_resolve_step_refreshed_addrs(bs: Seq<Entry>, ms: Seq<Entry>, as_: Seq<Entry>, name: u32, addrs: Seq<u32>, p: Seq<u32>, q: Seq<u32>, i: int, now_ms: u64, limit: u64, quota: int, cap: int, j0: int)
    requires
        0 <= i < addrs.len(),
        p == addrs.take(i),
        q == addrs.take(i + 1),
        0 <= j0 < ms.len(),
        as_.len() == ms.len(),
        ms[j0].key == addrs[i] as u64,
        as_[j0] == (Entry {
            row: ms[j0].row,
            key: addrs[i] as u64,
            deadline_ms: if ms[j0].deadline_ms >= limit { ms[j0].deadline_ms } else { limit },
            value: ms[j0].value,
        }),
        forall|j: int| 0 <= j < as_.len() && j != j0 ==> #[trigger] as_[j] == ms[j],
        forall|k: int| 0 <= k < p.len() ==> held_until(ms, (#[trigger] p[k]) as u64, limit)
            || (!held_key(ms, p[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < p.len() && !held_key(ms, (#[trigger] p[i2]) as u64)
            && held_key(ms, (#[trigger] p[j2]) as u64)
            ==> kept_holder(bs, p[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && p[k] == p[j2],
        !listed(p, addrs[i] as u64) ==> kept_holder(bs, addrs[i] as u64, name, now_ms),
    ensures
        forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
            || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap)),
        forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
            && held_key(as_, (#[trigger] q[j2]) as u64)
            ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                || exists|k: int| 0 <= k < i2 && q[k] == q[j2],
        refused_in(as_, q) == refused_in(ms, p),
{
    let x = addrs[i];
    assert forall|k: int| 0 <= k < i implies #[trigger] p[k] == q[k] by {
    }
    assert(q[i] == x);
    assert forall|j: int| #![trigger as_[j]] #![trigger ms[j]] 0 <= j < as_.len() implies as_[j].key == ms[j].key
        && as_[j].deadline_ms >= ms[j].deadline_ms by {
        if j != j0 {
            assert(as_[j] == ms[j]);
        }
    }
    assert(as_[j0].deadline_ms >= limit);
    assert(held_until(as_, x as u64, limit));
    assert(held_key(ms, x as u64));
    // Which keys are held, and each row's count, are unchanged.
    assert forall|key: u64| #![trigger held_key(as_, key)] #![trigger held_key(ms, key)]
        held_key(as_, key) == held_key(ms, key) by {
    }
    assert forall|j: int| 0 <= j < as_.len() implies (#[trigger] as_[j]).row == ms[j].row by {
        if j != j0 {
            assert(as_[j] == ms[j]);
        }
    }
    lemma_count_same_rows(as_, ms, name);
    assert forall|k: int| 0 <= k < q.len() implies held_until(as_, (#[trigger] q[k]) as u64, limit)
        || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap)) by {
        if k < i {
            assert(q[k] == p[k]);
            if !held_until(ms, p[k] as u64, limit) {
                assert(!held_key(ms, p[k] as u64));
            }
        } else {
            assert(q[k] == x);
        }
    }
    // Where `x` sits in the shorter prefix, if it does.
    let xl = listed(p, x as u64);
    let kx = if xl { choose|k: int| 0 <= k < p.len() && p[k] as u64 == x as u64 } else { 0 };
    if xl {
        assert(p[kx] == x);
        assert(held_key(ms, p[kx] as u64));
    }
    assert forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
        && held_key(as_, (#[trigger] q[j2]) as u64)
        implies kept_holder(bs, q[j2] as u64, name, now_ms)
            || exists|k: int| 0 <= k < i2 && q[k] == q[j2] by {
        assert(q[i2] == p[i2]);
        assert(!held_key(ms, p[i2] as u64));
        if j2 < i {
            assert(q[j2] == p[j2]);
            assert(held_key(ms, p[j2] as u64));
        } else {
            assert(q[j2] == x);
            if xl {
                if kx < i2 {
                    assert(q[kx] == p[kx]);
                } else if kx > i2 {
                    // The pair (i2, kx) of the shorter prefix.
                    assert(p[kx] == x);
                }
            }
        }
    }
    // The count.
    assert forall|k: int| 0 <= k < p.len() implies held_key(as_, (#[trigger] p[k]) as u64) == held_key(ms, p[k] as u64) by {
    }
    lemma_refused_in_agree(as_, ms, p);
    lemma_refused_in_take(as_, addrs, i);
}

/// The clauses of `resolved_tables` that the step lemmas read, other than
/// clause 2 and `bounded_by_key`.
proof fn lemma_resolve_unpack(b: Pins, m: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64)
    requires
        0 <= i <= addrs.len(),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        ({
            let bs = admitted(b);
            let ms = admitted(m);
            let p = addrs.take(i);
            let limit = add_ms_spec(now_ms, window_ms_of(b));
            let quota = squota(admitted_pool(b));
            let cap = scap(admitted_pool(b));
            &&& forall|j: int| 0 <= j < ms.len() ==> kept_at(bs, (#[trigger] ms[j]).row, ms[j].key, name, now_ms)
                || (ms[j].row == name && listed(p, ms[j].key) && ms[j].deadline_ms == limit && ms[j].value == 0)
            &&& forall|j: int| 0 <= j < ms.len() && !listed(p, (#[trigger] ms[j]).key) ==> has(bs, ms[j])
            &&& forall|k: int| 0 <= k < p.len() ==> held_until(ms, (#[trigger] p[k]) as u64, limit)
                || (!held_key(ms, p[k] as u64) && (count(ms, name) >= quota || ms.len() >= cap))
            &&& forall|i2: int, j2: int| 0 <= i2 < j2 < p.len() && !held_key(ms, (#[trigger] p[i2]) as u64)
                && held_key(ms, (#[trigger] p[j2]) as u64)
                ==> kept_holder(bs, p[j2] as u64, name, now_ms)
                    || exists|k: int| 0 <= k < i2 && p[k] == p[j2]
        }),
{
    reveal(resolved_tables);
}

/// `resolved_tables` of the longer prefix, from its clauses for the table
/// after a step, with clause 2 and `bounded_by_key` carried from the table
/// before the step.
proof fn lemma_resolve_pack(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64)
    requires
        0 <= i < addrs.len(),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
        ({
            let bs = admitted(b);
            let ms = admitted(m);
            let as_ = admitted(a);
            let q = addrs.take(i + 1);
            let limit = add_ms_spec(now_ms, window_ms_of(b));
            let quota = squota(admitted_pool(b));
            let cap = scap(admitted_pool(b));
            &&& ms.len() <= as_.len()
            &&& forall|j: int| 0 <= j < ms.len() ==> (#[trigger] ms[j]).row == as_[j].row && ms[j].key == as_[j].key
                && as_[j].deadline_ms >= ms[j].deadline_ms
            &&& forall|j: int| 0 <= j < as_.len() ==> if j < ms.len() {
                (#[trigger] as_[j]).row == ms[j].row && as_[j].key == ms[j].key
                    && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit)
            } else {
                as_[j].deadline_ms <= limit
            }
            &&& forall|j: int| 0 <= j < as_.len() ==> kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
                || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0)
            &&& forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) ==> has(bs, as_[j])
            &&& forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
                || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap))
            &&& forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
                && held_key(as_, (#[trigger] q[j2]) as u64)
                ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                    || exists|k: int| 0 <= k < i2 && q[k] == q[j2]
        }),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
{
    reveal(resolved_tables);
    let bs = admitted(b);
    let ms = admitted(m);
    let as_ = admitted(a);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    lemma_resolve_kept_step(bs, ms, as_, name, now_ms);
    lemma_resolve_bounded_step(bs, ms, as_, limit);
}

/// The step for an address refused at the quota or at capacity, over the
/// tables. Kept apart from the other outcomes so that each proof sees only
/// its own facts.
proof fn lemma_resolve_step_pins_refused(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64)
    requires
        0 <= i < addrs.len(),
        admitted(a) == admitted(m),
        !held_key(admitted(m), addrs[i] as u64),
        count(admitted(m), name) >= squota(admitted_pool(b)) || admitted(m).len() >= scap(admitted_pool(b)),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
        refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)) + 1,
{
    let bs = admitted(b);
    let ms = admitted(m);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    let quota = squota(admitted_pool(b));
    let cap = scap(admitted_pool(b));
    lemma_resolve_unpack(b, m, name, addrs, i, now_ms);
    lemma_resolve_step_refused(bs, ms, name, addrs, addrs.take(i), addrs.take(i + 1), i, now_ms, limit, quota, cap);
    assert forall|j: int| 0 <= j < ms.len() implies (#[trigger] ms[j]).row == ms[j].row && ms[j].key == ms[j].key
        && ms[j].deadline_ms >= ms[j].deadline_ms by {
    }
    lemma_resolve_pack(b, m, a, name, addrs, i, now_ms);
}

/// The step for an address entered new, over the tables.
proof fn lemma_resolve_step_pins_new(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64)
    requires
        0 <= i < addrs.len(),
        count(admitted(a), name) <= squota(admitted_pool(b)),
        admitted(a).len() <= scap(admitted_pool(b)),
        !held_key(admitted(m), addrs[i] as u64),
        added(admitted(a), admitted(m), Entry {
            row: name,
            key: addrs[i] as u64,
            deadline_ms: add_ms_spec(now_ms, window_ms_of(b)),
            value: 0,
        }),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
        refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)),
{
    let bs = admitted(b);
    let ms = admitted(m);
    let as_ = admitted(a);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    let quota = squota(admitted_pool(b));
    let cap = scap(admitted_pool(b));
    lemma_resolve_unpack(b, m, name, addrs, i, now_ms);
    lemma_resolve_step_new(bs, ms, as_, name, addrs, addrs.take(i), addrs.take(i + 1), i, now_ms, limit, quota, cap);
    lemma_resolve_pack_added(b, m, a, name, addrs, i, now_ms,
        Entry { row: name, key: addrs[i] as u64, deadline_ms: limit, value: 0 });
}

/// The step for an address some row held, extended in place: from the
/// clauses of the shorter prefix to the facts `lemma_resolve_pack` reads.
/// Apart from the pack, so the two prefixes' clauses are never in one query.
proof fn lemma_resolve_step_pins_refreshed_clauses(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64, j0: int)
    requires
        0 <= i < addrs.len(),
        0 <= j0 < admitted(m).len(),
        admitted(a).len() == admitted(m).len(),
        admitted(m)[j0].key == addrs[i] as u64,
        admitted(a)[j0] == (Entry {
            row: admitted(m)[j0].row,
            key: addrs[i] as u64,
            deadline_ms: if admitted(m)[j0].deadline_ms >= add_ms_spec(now_ms, window_ms_of(b)) {
                admitted(m)[j0].deadline_ms
            } else {
                add_ms_spec(now_ms, window_ms_of(b))
            },
            value: admitted(m)[j0].value,
        }),
        forall|j: int| 0 <= j < admitted(a).len() && j != j0 ==> #[trigger] admitted(a)[j] == admitted(m)[j],
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        ({
            let bs = admitted(b);
            let ms = admitted(m);
            let as_ = admitted(a);
            let q = addrs.take(i + 1);
            let limit = add_ms_spec(now_ms, window_ms_of(b));
            let quota = squota(admitted_pool(b));
            let cap = scap(admitted_pool(b));
            &&& ms.len() <= as_.len()
            &&& forall|j: int| 0 <= j < ms.len() ==> (#[trigger] ms[j]).row == as_[j].row && ms[j].key == as_[j].key
                && as_[j].deadline_ms >= ms[j].deadline_ms
            &&& forall|j: int| 0 <= j < as_.len() ==> if j < ms.len() {
                (#[trigger] as_[j]).row == ms[j].row && as_[j].key == ms[j].key
                    && (as_[j].deadline_ms <= ms[j].deadline_ms || as_[j].deadline_ms <= limit)
            } else {
                as_[j].deadline_ms <= limit
            }
            &&& forall|j: int| 0 <= j < as_.len() ==> kept_at(bs, (#[trigger] as_[j]).row, as_[j].key, name, now_ms)
                || (as_[j].row == name && listed(q, as_[j].key) && as_[j].deadline_ms == limit && as_[j].value == 0)
            &&& forall|j: int| 0 <= j < as_.len() && !listed(q, (#[trigger] as_[j]).key) ==> has(bs, as_[j])
            &&& forall|k: int| 0 <= k < q.len() ==> held_until(as_, (#[trigger] q[k]) as u64, limit)
                || (!held_key(as_, q[k] as u64) && (count(as_, name) >= quota || as_.len() >= cap))
            &&& forall|i2: int, j2: int| 0 <= i2 < j2 < q.len() && !held_key(as_, (#[trigger] q[i2]) as u64)
                && held_key(as_, (#[trigger] q[j2]) as u64)
                ==> kept_holder(bs, q[j2] as u64, name, now_ms)
                    || exists|k: int| 0 <= k < i2 && q[k] == q[j2]
        }),
        refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)),
{
    let bs = admitted(b);
    let ms = admitted(m);
    let as_ = admitted(a);
    let limit = add_ms_spec(now_ms, window_ms_of(b));
    let quota = squota(admitted_pool(b));
    let cap = scap(admitted_pool(b));
    lemma_resolve_unpack(b, m, name, addrs, i, now_ms);
    lemma_resolve_step_refreshed(bs, ms, as_, name, addrs, addrs.take(i), addrs.take(i + 1), i, now_ms, limit, quota, cap, j0);
}

/// The step for an address some row held, extended in place, over the tables.
proof fn lemma_resolve_step_pins_refreshed(b: Pins, m: Pins, a: Pins, name: u32, addrs: Seq<u32>, i: int, now_ms: u64, j0: int)
    requires
        0 <= i < addrs.len(),
        0 <= j0 < admitted(m).len(),
        admitted(a).len() == admitted(m).len(),
        admitted(m)[j0].key == addrs[i] as u64,
        admitted(a)[j0] == (Entry {
            row: admitted(m)[j0].row,
            key: addrs[i] as u64,
            deadline_ms: if admitted(m)[j0].deadline_ms >= add_ms_spec(now_ms, window_ms_of(b)) {
                admitted(m)[j0].deadline_ms
            } else {
                add_ms_spec(now_ms, window_ms_of(b))
            },
            value: admitted(m)[j0].value,
        }),
        forall|j: int| 0 <= j < admitted(a).len() && j != j0 ==> #[trigger] admitted(a)[j] == admitted(m)[j],
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
        refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)),
{
    lemma_resolve_step_pins_refreshed_clauses(b, m, a, name, addrs, i, now_ms, j0);
    lemma_resolve_pack(b, m, a, name, addrs, i, now_ms);
}

/// The name's entries stay live when an entry is added that is another
/// name's or itself live.
proof fn lemma_added_row_live(as_: Seq<Entry>, ms: Seq<Entry>, e: Entry, name: u32, now_ms: u64)
    requires
        added(as_, ms, e),
        row_live(ms, name, now_ms),
        e.row != name || e.deadline_ms > now_ms,
    ensures
        row_live(as_, name, now_ms),
{
    assert forall|j: int| 0 <= j < as_.len() && (#[trigger] as_[j]).row == name implies as_[j].deadline_ms > now_ms by {
        lemma_added_entry(as_, ms, e, j);
        if as_[j] != e {
            let m = choose|m: int| 0 <= m < ms.len() && ms[m] == as_[j];
            assert(ms[m].row == name);
        }
    }
}

/// One step of `resolve`'s loop, whatever `admit` returned.
proof fn lemma_resolve_step(b: Pins, m: Pins, a: Pins, name: u32, token: Answered, addrs: Seq<u32>, i: int, now_ms: u64, r: Admitted)
    requires
        0 <= i < addrs.len(),
        pinv(m),
        pinv(a),
        same_limits(m, b),
        token_current(token, m),
        answered_name(token) == name,
        answered_at(token) == now_ms,
        admit_post(m, a, token, addrs[i], r),
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        resolved_tables(b, a, name, addrs.take(i + 1), now_ms),
        refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)) + match r {
            Admitted::New => 0nat,
            Admitted::Refreshed { .. } => 0nat,
            _ => 1nat,
        },
        now_ms < u64::MAX && row_live(admitted(m), name, now_ms) ==> row_live(admitted(a), name, now_ms),
{
    reveal(pinv);
    match r {
        Admitted::New => {
            assert(count(admitted(a), name) <= squota(admitted_pool(a)));
            lemma_resolve_step_pins_new(b, m, a, name, addrs, i, now_ms);
            if now_ms < u64::MAX && row_live(admitted(m), name, now_ms) {
                lemma_added_row_live(admitted(a), admitted(m), Entry {
                    row: name,
                    key: addrs[i] as u64,
                    deadline_ms: add_ms_spec(now_ms, window_ms_of(b)),
                    value: 0,
                }, name, now_ms);
            }
        },
        Admitted::Refreshed { holder } => {
            let j0 = lemma_refreshed_shape(admitted(m), admitted(a), holder, addrs[i] as u64,
                add_ms_spec(now_ms, window_ms_of(b)));
            lemma_resolve_step_pins_refreshed(b, m, a, name, addrs, i, now_ms, j0);
            assert forall|j: int| 0 <= j < admitted(a).len() && (#[trigger] admitted(a)[j]).row == name
                && now_ms < u64::MAX && row_live(admitted(m), name, now_ms)
                implies admitted(a)[j].deadline_ms > now_ms by {
                if j != j0 {
                    assert(admitted(a)[j] == admitted(m)[j]);
                }
            }
        },
        Admitted::NameAtQuota => {
            lemma_resolve_step_pins_refused(b, m, a, name, addrs, i, now_ms);
        },
        Admitted::Full => {
            lemma_resolve_step_pins_refused(b, m, a, name, addrs, i, now_ms);
        },
        Admitted::Stale => {},
    }
}

/// `lemma_resolve_step` for every result `admit` may return from `m`, stated
/// before the call, so the loop body needs no name for the result.
proof fn lemma_resolve_steps(b: Pins, m: Pins, name: u32, token: Answered, addrs: Seq<u32>, i: int, now_ms: u64)
    requires
        0 <= i < addrs.len(),
        pinv(m),
        same_limits(m, b),
        token_current(token, m),
        answered_name(token) == name,
        answered_at(token) == now_ms,
        resolved_tables(b, m, name, addrs.take(i), now_ms),
    ensures
        forall|a: Pins, r: Admitted| #[trigger] admit_post(m, a, token, addrs[i], r) && pinv(a) ==> {
            &&& resolved_tables(b, a, name, addrs.take(i + 1), now_ms)
            &&& refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)) + match r {
                Admitted::New => 0nat,
                Admitted::Refreshed { .. } => 0nat,
                _ => 1nat,
            }
            &&& now_ms < u64::MAX && row_live(admitted(m), name, now_ms) ==> row_live(admitted(a), name, now_ms)
        },
{
    assert forall|a: Pins, r: Admitted| #[trigger] admit_post(m, a, token, addrs[i], r) && pinv(a) implies {
        &&& resolved_tables(b, a, name, addrs.take(i + 1), now_ms)
        &&& refused_in(admitted(a), addrs.take(i + 1)) == refused_in(admitted(m), addrs.take(i)) + match r {
            Admitted::New => 0nat,
            Admitted::Refreshed { .. } => 0nat,
            _ => 1nat,
        }
        &&& now_ms < u64::MAX && row_live(admitted(m), name, now_ms) ==> row_live(admitted(a), name, now_ms)
    } by {
        lemma_resolve_step(b, m, a, name, token, addrs, i, now_ms, r);
    }
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == add_ms_spec(a, b),
))]
fn add_ms(a: u64, b: u64) -> u64 {
    if a > u64::MAX - b { u64::MAX } else { a + b }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r >= a, r >= b, r == a || r == b,
))]
fn later(a: u64, b: u64) -> u64 {
    if a >= b { a } else { b }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Pins {
    /// Empty tables. `None` when a quota exceeds its capacity, a capacity
    /// exceeds what a table's index can number, or a window is zero.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(p) => {
                    &&& pinv(p)
                    &&& owner_of(p) == owner
                    &&& asked(p).len() == 0 && admitted(p).len() == 0 && flows(p).len() == 0
                    &&& query_ms_of(p) == l.query_ms && window_ms_of(p) == l.window_ms
                        && idle_ms_of(p) == l.idle_ms
                    &&& scap(asked_pool(p)) == l.asked_cap
                    &&& squota(asked_pool(p)) == l.asked_per_name
                    &&& scap(admitted_pool(p)) == l.admitted_cap
                    &&& squota(admitted_pool(p)) == l.admitted_per_name
                    &&& scap(flows_pool(p)) == l.flows_cap
                    &&& squota(flows_pool(p)) == l.flows_per_destination
                },
                None => l.asked_per_name > l.asked_cap || l.admitted_per_name > l.admitted_cap
                    || l.flows_per_destination > l.flows_cap || l.asked_cap > crate::slab::MAX_CAP
                    || l.admitted_cap > crate::slab::MAX_CAP || l.flows_cap > crate::slab::MAX_CAP
                    || l.query_ms == 0 || l.window_ms == 0 || l.idle_ms == 0,
            },
    ))]
    pub fn new(owner: u32, l: Limits) -> Option<Pins> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        if l.query_ms == 0 || l.window_ms == 0 || l.idle_ms == 0 {
            return None;
        }
        let asked = Slab::new(l.asked_cap, l.asked_per_name)?;
        let admitted = Slab::new(l.admitted_cap, l.admitted_per_name)?;
        let flows = Slab::new(l.flows_cap, l.flows_per_destination)?;
        Some(Pins {
            asked,
            admitted,
            flows,
            query_ms: l.query_ms,
            window_ms: l.window_ms,
            idle_ms: l.idle_ms,
            owner,
            epoch: 0,
        })
    }

    /// The box these tables belong to.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == owner_of(*self),
    ))]
    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// Whether the table holds an unexpired question for this name,
    /// transaction id and port. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*self),
        ensures
            r == crate::flow::live(asked(*self), name, question_key(txid, port), now.ms),
    ))]
    pub fn asked_live(&self, name: u32, txid: u16, port: u16, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.asked.live(name, key(0, txid, port), now)
    }

    /// How many questions and how many admissions have not expired at
    /// `now_ms`. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*self),
        ensures
            r.0 == crate::pool::live_number(asked(*self), now.ms),
            r.1 == crate::pool::live_number(admitted(*self), now.ms),
    ))]
    pub fn live_counts(&self, now: Instant) -> (usize, usize) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        (self.asked.live_count(now), self.admitted.live_count(now))
    }

    /// Whether some name holds this address in an unexpired admission.
    /// Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*self),
        ensures
            r == live_key(admitted(*self), addr as u64, now.ms),
    ))]
    pub fn admitted_live(&self, addr: u32, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.admitted.any_live(addr as u64, now)
    }

    /// The admission that holds this address, under whichever name, expired
    /// or not, if any does. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*self),
        ensures
            match r {
                Some(e) => has(admitted(*self), e) && e.key == addr as u64,
                None => !held_key(admitted(*self), addr as u64),
            },
    ))]
    pub fn admission(&self, addr: u32) -> Option<Entry> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.admitted.holder(addr as u64)
    }

    /// Records a question the box sent to its resolver for the declared name
    /// at index `name`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            ask_post(*old(self), *final(self), name, txid, port, now.ms, r),
    ))]
    pub fn ask(&mut self, name: u32, txid: u16, port: u16, now: Instant) -> Asked {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        let k = key(0, txid, port);
        let deadline = add_ms(now.ms, self.query_ms);
        match self
            .asked
            .insert_reclaiming(name, k, Instant { ms: deadline }, 0, now)
        {
            Inserted::New => Asked::Recorded,
            Inserted::Refreshed => Asked::Refreshed,
            Inserted::RowAtQuota => Asked::NameAtQuota,
            Inserted::PoolFull => Asked::Full,
        }
    }

    /// Matches a reply from the box's resolver to an outstanding question and
    /// consumes it. G5 (a).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            answer_post(*old(self), *final(self), name, txid, port, now_ms, r),
    ))]
    pub(crate) fn answer(
        &mut self,
        name: u32,
        txid: u16,
        port: u16,
        now_ms: u64,
    ) -> Option<Answered> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_same_no_new_keys(sview(self.asked));
        }
        let k = key(0, txid, port);
        let e = match self.asked.entry(name, k) {
            Some(e) => e,
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_not_held_not_live(sview(self.asked), name, k, now_ms);
                }
                return None;
            }
        };
        if e.deadline_ms <= now_ms {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_expired_not_live(sview(self.asked), e, now_ms);
            }
            return None;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_has_live(sview(self.asked), e, now_ms);
        }
        let _ = self.asked.remove(name, k);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_subset_no_new_keys(sview(self.asked), sview(old(self).asked));
        }
        Some(Answered {
            name,
            at_ms: now_ms,
            owner: self.owner,
            epoch: self.epoch,
        })
    }

    /// Admits one address from a matched answer for the window that started
    /// when the answer was matched: under the answer's name if no name holds
    /// the address, otherwise by extending the entry that does. The caller
    /// has already refused addresses the box's rules and the infrastructure
    /// ranges exclude. G5 (b), (h), (i).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            admit_post(*old(self), *final(self), *a, addr, r),
    ))]
    pub(crate) fn admit(&mut self, a: &Answered, addr: u32) -> Admitted {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::extended);
        }
        if a.owner != self.owner || a.epoch != self.epoch {
            return Admitted::Stale;
        }
        let k = addr as u64;
        let deadline = add_ms(a.at_ms, self.window_ms);
        match self.admitted.holder(k) {
            Some(e) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let s = sview(self.admitted);
                    let i = choose|i: int| 0 <= i < s.len() && s[i] == e;
                    assert(s[i].row == e.row && s[i].key == k);
                }
                let kept = later(e.deadline_ms, deadline);
                let _ = self.admitted.set(e.row, k, Instant { ms: kept }, e.value);
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_refresh_not_shortened(sview(self.admitted), sview(old(self).admitted), e, Entry { row: e.row, key: k, deadline_ms: kept, value: e.value });
                    lemma_refresh_bounded(sview(self.admitted), sview(old(self).admitted), e, Entry { row: e.row, key: k, deadline_ms: kept, value: e.value }, deadline);
                    lemma_unique_refreshed(sview(self.admitted), sview(old(self).admitted), e.row, k);
                }
                Admitted::Refreshed { holder: e.row }
            }
            None => match self.admitted.insert(a.name, k, Instant { ms: deadline }, 0) {
                Inserted::New | Inserted::Refreshed => {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        let s = sview(old(self).admitted);
                        // No row held the key, so the insert did not find it.
                        assert(!holds(s, a.name, k)) by {
                            if holds(s, a.name, k) {
                                let j = choose|j: int| 0 <= j < s.len() && s[j].row == a.name && s[j].key == k;
                                assert(s[j].key == k);
                            }
                        }
                        crate::pool::theorem_added_keeps_keys(
                            sview(self.admitted),
                            s,
                            Entry { row: a.name, key: k, deadline_ms: deadline, value: 0 },
                        );
                    }
                    Admitted::New
                }
                Inserted::RowAtQuota => Admitted::NameAtQuota,
                Inserted::PoolFull => Admitted::Full,
            },
        }
    }

    /// Removes every expired address of `name`. The shell calls it once for a
    /// matched answer that carries addresses, before admitting them, so the
    /// name's quota counts only addresses that have not expired. G5 (h).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            release_post(*old(self), *final(self), name, now_ms, r),
    ))]
    pub(crate) fn release_expired(&mut self, name: u32, now_ms: u64) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        let n = self.admitted.release_expired(name, Instant { ms: now_ms });
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_unique_subset(sview(self.admitted), sview(old(self).admitted));
        }
        n
    }

    /// A resolver's reply that answers the question `(name, txid, port)` with
    /// `addrs`, which the caller has already filtered. If the box holds that
    /// question unexpired, it is consumed; then, when the answer carries any
    /// address, the name's expired addresses are released and each address
    /// is admitted in order. `None` when no such question is held, and then
    /// nothing changes. The token `answer` makes is used here and nowhere
    /// else. G5 (a), (b), (h), (i).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
            addrs@.len() <= u16::MAX,
        ensures
            pinv(*final(self)),
            resolve_post(*old(self), *final(self), name, txid, port, addrs@, now.ms, r),
    ))]
    pub fn resolve(
        &mut self,
        name: u32,
        txid: u16,
        port: u16,
        addrs: &[u32],
        now: Instant,
    ) -> Option<Admits> {
        let token = self.answer(name, txid, port, now.ms)?;
        // The tables as `answer` left them. The question table is not touched
        // again, so `answer`'s facts about it, stated of this snapshot, hold
        // after the loop without being loop invariants.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost answered: Pins = *self;
        }
        let mut c = Admits {
            admitted: 0,
            refused: 0,
        };
        if addrs.is_empty() {
            return Some(c);
        }
        let _ = self.release_expired(name, now.ms);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_resolve_base(*old(self), *self, name, addrs@, now.ms);
        }
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                pinv(*self),
                same_limits(*self, *old(self)),
                flows(*self) == flows(*old(self)),
                token_current(token, *self),
                answered_name(token) == name,
                answered_at(token) == now.ms,
                i <= addrs.len(),
                addrs@.len() <= u16::MAX,
                c.admitted + c.refused == i,
                c.refused == refused_in(admitted(*self), addrs@.take(i as int)),
                resolved_tables(*old(self), *self, name, addrs@.take(i as int), now.ms),
                now.ms < u64::MAX ==> row_live(admitted(*self), name, now.ms),
                addrs@.len() > 0,
                asked(*self) == asked(answered),
            decreases addrs.len() - i,
        ))]
        while i < addrs.len() {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_resolve_steps(*old(self), *self, name, token, addrs@, i as int, now.ms);
            }
            match self.admit(&token, addrs[i]) {
                Admitted::New | Admitted::Refreshed { .. } => c.admitted += 1,
                Admitted::NameAtQuota | Admitted::Full | Admitted::Stale => c.refused += 1,
            }
            i += 1;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(addrs@.take(addrs@.len() as int) =~= addrs@);
        }
        Some(c)
    }

    /// Removes expired questions, at most `budget`, and returns how many.
    /// Admissions and flows are not touched: an expired admission stays
    /// until its own name answers again.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            expire_questions_post(*old(self), *final(self), now.ms, budget, r),
    ))]
    pub fn expire_questions(&mut self, now: Instant, budget: usize) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.asked.expire(now, budget)
    }

    /// Decides one frame the box sent to `dst`, a destination its rules do not
    /// name. G5 (c), (d), (e), (f).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            egress_post(*old(self), *final(self), dst, t, now.ms, r),
    ))]
    pub fn egress(&mut self, dst: u32, t: Option<Transport>, now: Instant) -> Egress {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::extended);
        }
        let x = match t {
            Some(x) => x,
            None => {
                return if self.admitted.any_live(dst as u64, now) {
                    Egress::Window
                } else {
                    Egress::Refused
                };
            }
        };
        let k = key(x.proto, x.sport, x.dport);
        let ends = x.proto == TCP && x.flags & (FIN | RST) != 0;
        let fresh = add_ms(now.ms, self.idle_ms);
        let held = match self.flows.entry(dst, k) {
            Some(e) => {
                if e.deadline_ms > now.ms {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_has_live(sview(self.flows), e, now.ms);
                    }
                    if ends {
                        let _ = self.flows.remove(dst, k);
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            lemma_subset_no_new_keys(sview(self.flows), sview(old(self).flows));
                        }
                    } else {
                        let kept = later(e.deadline_ms, fresh);
                        let _ = self.flows.set(dst, k, Instant { ms: kept }, e.value);
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            lemma_refresh_not_shortened(sview(self.flows), sview(old(self).flows), e, Entry { row: dst, key: k, deadline_ms: kept, value: e.value });
                            lemma_refresh_bounded(sview(self.flows), sview(old(self).flows), e, Entry { row: dst, key: k, deadline_ms: kept, value: e.value }, fresh);
                            lemma_refreshed_no_new_keys(sview(self.flows), sview(old(self).flows), dst, k);
                        }
                    }
                    return Egress::ByFlow;
                }
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_expired_not_live(sview(self.flows), e, now.ms);
                }
                true
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_not_held_not_live(sview(self.flows), dst, k, now.ms);
                }
                false
            }
        };
        // The window is asked only now: a frame on a live flow never needs it.
        if !self.admitted.any_live(dst as u64, now) {
            return Egress::Refused;
        }
        if ends {
            return Egress::Window;
        }
        if held {
            // An expired record for the same flow is reopened in place, as a
            // new record.
            let _ = self.flows.set(dst, k, Instant { ms: fresh }, 0);
            #[cfg(verus_keep_ghost)]
            proof! {
                let added = Entry { row: dst, key: k, deadline_ms: fresh, value: 0 };
                let after = sview(self.flows);
                let i = choose|i: int| 0 <= i < after.len() && after[i] == added;
                assert(after[i].row == dst && after[i].key == k);
                if now.ms < u64::MAX {
                    lemma_has_live(after, added, now.ms);
                }
            }
            return Egress::Retained;
        }
        match self
            .flows
            .insert_reclaiming(dst, k, Instant { ms: fresh }, 0, now)
        {
            Inserted::New | Inserted::Refreshed => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    let added = Entry { row: dst, key: k, deadline_ms: fresh, value: 0 };
                    let after = sview(self.flows);
                    let i = choose|i: int| 0 <= i < after.len() && after[i] == added;
                    assert(after[i].row == dst && after[i].key == k);
                    if now.ms < u64::MAX {
                        lemma_has_live(after, added, now.ms);
                    }
                }
                Egress::Retained
            }
            Inserted::RowAtQuota | Inserted::PoolFull => Egress::Window,
        }
    }

    /// How many flow records the table holds, expired or not. Changes
    /// nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r == flows(*self).len(),
    ))]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Removes the flow record toward `dst` for this transport, expired or
    /// not, and says whether the table held one. Nothing else changes.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            same_limits(*final(self), *old(self)),
            asked(*final(self)) == asked(*old(self)),
            admitted(*final(self)) == admitted(*old(self)),
            r == holds(flows(*old(self)), dst, transport_key(t)),
            !holds(flows(*final(self)), dst, transport_key(t)),
            keeps_others(flows(*final(self)), flows(*old(self)), dst, transport_key(t)),
            flows(*final(self)).len() + (if r { 1int } else { 0int }) == flows(*old(self)).len(),
            !r ==> flows(*final(self)) == flows(*old(self)),
    ))]
    pub fn forget_flow(&mut self, dst: u32, t: Transport) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.flows.remove(dst, key(t.proto, t.sport, t.dport))
    }

    /// Removes expired admissions, at most `budget`, and returns how many.
    /// An admission that has not expired is never removed, and the other two
    /// tables are as they were.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            same_limits(*final(self), *old(self)),
            asked(*final(self)) == asked(*old(self)),
            flows(*final(self)) == flows(*old(self)),
            r <= budget,
            admitted(*final(self)).len() + r == admitted(*old(self)).len(),
            subset_of(admitted(*final(self)), admitted(*old(self))),
            keeps_live(admitted(*final(self)), admitted(*old(self)), now.ms),
            r < budget ==> none_expired(admitted(*final(self)), now.ms),
    ))]
    pub fn expire_admissions(&mut self, now: Instant, budget: usize) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        let n = self.admitted.expire(now, budget);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_unique_subset(sview(self.admitted), sview(old(self).admitted));
        }
        n
    }

    /// Removes expired entries from the three tables, at most `budget` in all,
    /// and returns how many. An entry that has not expired is never removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            expire_post(*old(self), *final(self), now.ms, budget, r),
    ))]
    pub fn expire(&mut self, now: Instant, budget: usize) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        let a = self.asked.expire(now, budget);
        let b = self.admitted.expire(now, budget - a);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_unique_subset(sview(self.admitted), sview(old(self).admitted));
        }
        let c = self.flows.expire(now, budget - a - b);
        a + b + c
    }

    /// Ends everything: the box stopped, or its row was replaced.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            pinv(*old(self)),
        ensures
            pinv(*final(self)),
            same_sizes(*final(self), *old(self)),
            epoch_of(*old(self)) < u64::MAX ==> epoch_of(*final(self)) > epoch_of(*old(self)),
            asked(*final(self)).len() == 0,
            admitted(*final(self)).len() == 0,
            flows(*final(self)).len() == 0,
    ))]
    pub fn clear(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(pinv);
        }
        self.epoch = self.epoch.saturating_add(1);
        self.asked.clear();
        self.admitted.clear();
        self.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Limits = Limits {
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
    const A: u32 = 0xcb00_7107;
    const OWNER: u32 = 0x0a00_0005;

    fn tcp(sport: u16, flags: u8) -> Option<Transport> {
        Some(Transport {
            proto: TCP,
            sport,
            dport: 443,
            flags,
        })
    }

    fn pinned(at: u64) -> Pins {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: at }), Asked::Recorded);
        let a = p.answer(0, 7, 5000, at).unwrap();
        assert_eq!(p.admit(&a, A), Admitted::New);
        p
    }

    #[test]
    fn an_answer_needs_its_question_and_consumes_it() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert!(p.answer(0, 7, 5000, 0).is_none());
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert!(p.answer(1, 7, 5000, 1).is_none());
        assert!(p.answer(0, 8, 5000, 1).is_none());
        assert!(p.answer(0, 7, 5001, 1).is_none());
        assert!(p.answer(0, 7, 5000, 1).is_some());
        assert!(p.answer(0, 7, 5000, 2).is_none());
    }

    #[test]
    fn a_late_answer_matches_nothing() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert!(p.answer(0, 7, 5000, 30_000).is_none());
    }

    #[test]
    fn an_unadmitted_destination_is_refused_and_nothing_changes() {
        let mut p = pinned(0);
        assert_eq!(
            p.egress(A + 1, tcp(40000, 0x02), Instant { ms: 1 }),
            Egress::Refused
        );
        assert_eq!(p.egress(A + 1, None, Instant { ms: 1 }), Egress::Refused);
    }

    #[test]
    fn the_window_opens_a_flow_and_the_flow_outlives_the_window() {
        let mut p = pinned(0);
        assert_eq!(
            p.egress(A, tcp(40000, 0x02), Instant { ms: 1 }),
            Egress::Retained
        );
        assert_eq!(
            p.egress(A, tcp(40000, 0x10), Instant { ms: 300_000 }),
            Egress::ByFlow
        );
        assert_eq!(
            p.egress(A, tcp(40001, 0x02), Instant { ms: 300_000 }),
            Egress::Refused
        );
    }

    #[test]
    fn a_closing_segment_ends_the_flow() {
        let mut p = pinned(0);
        assert_eq!(
            p.egress(A, tcp(40000, 0x02), Instant { ms: 1 }),
            Egress::Retained
        );
        assert_eq!(
            p.egress(A, tcp(40000, 0x11), Instant { ms: 2 }),
            Egress::ByFlow
        );
        assert_eq!(
            p.egress(A, tcp(40000, 0x10), Instant { ms: 300_000 }),
            Egress::Refused
        );
    }

    #[test]
    fn a_frame_without_ports_rides_the_window_only() {
        let mut p = pinned(0);
        assert_eq!(p.egress(A, None, Instant { ms: 1 }), Egress::Window);
        assert_eq!(p.egress(A, None, Instant { ms: 300_000 }), Egress::Refused);
    }

    #[test]
    fn a_destination_stops_at_its_flow_quota_and_still_rides_the_window() {
        let mut p = pinned(0);
        assert_eq!(
            p.egress(A, tcp(1, 0x02), Instant { ms: 1 }),
            Egress::Retained
        );
        assert_eq!(
            p.egress(A, tcp(2, 0x02), Instant { ms: 1 }),
            Egress::Retained
        );
        assert_eq!(p.egress(A, tcp(3, 0x02), Instant { ms: 1 }), Egress::Window);
        assert_eq!(
            p.egress(A, tcp(3, 0x10), Instant { ms: 300_000 }),
            Egress::Refused
        );
    }

    #[test]
    fn a_name_stops_at_its_address_quota() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let a = p.answer(0, 7, 5000, 0).unwrap();
        assert_eq!(p.admit(&a, 1), Admitted::New);
        assert_eq!(p.admit(&a, 2), Admitted::New);
        assert_eq!(p.admit(&a, 3), Admitted::NameAtQuota);
        assert_eq!(p.admit(&a, 2), Admitted::Refreshed { holder: 0 });
        assert_eq!(p.egress(3, None, Instant { ms: 1 }), Egress::Refused);
    }

    #[test]
    fn a_token_used_late_grants_no_later_window() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let a = p.answer(0, 7, 5000, 0).unwrap();
        let _ = p.expire(Instant { ms: 1_000_000 }, 16);
        assert_eq!(p.admit(&a, A), Admitted::New);
        assert_eq!(
            p.egress(A, None, Instant { ms: 1_000_000 }),
            Egress::Refused
        );
    }

    #[test]
    fn a_name_stops_at_its_question_quota() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert_eq!(p.ask(0, 2, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert_eq!(p.ask(0, 3, 5000, Instant { ms: 0 }), Asked::NameAtQuota);
        assert_eq!(p.ask(0, 2, 5000, Instant { ms: 1 }), Asked::Refreshed);
        assert_eq!(p.ask(1, 3, 5000, Instant { ms: 0 }), Asked::Recorded);
    }

    #[test]
    fn a_token_from_before_a_clear_or_from_another_box_admits_nothing() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let a = p.answer(0, 7, 5000, 0).unwrap();
        let mut other = Pins::new(OWNER + 1, L).unwrap();
        assert_eq!(other.admit(&a, A), Admitted::Stale);
        p.clear();
        assert_eq!(p.admit(&a, A), Admitted::Stale);
        assert_eq!(p.egress(A, None, Instant { ms: 1 }), Egress::Refused);
    }

    #[test]
    fn a_name_at_its_quota_takes_a_new_address_once_an_old_one_expires() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let a = p.answer(0, 7, 5000, 0).unwrap();
        assert_eq!(p.admit(&a, 1), Admitted::New);
        assert_eq!(p.admit(&a, 2), Admitted::New);
        assert_eq!(p.ask(0, 8, 5000, Instant { ms: 300_000 }), Asked::Recorded);
        let b = p.answer(0, 8, 5000, 300_000).unwrap();
        assert_eq!(p.admit(&b, 3), Admitted::NameAtQuota);
        assert_eq!(p.release_expired(0, 300_000), 2);
        assert_eq!(p.admit(&b, 3), Admitted::New);
        assert_eq!(p.egress(3, None, Instant { ms: 300_001 }), Egress::Window);
        assert_eq!(p.egress(1, None, Instant { ms: 300_001 }), Egress::Refused);
    }

    // Names: 0 is N1, 1 is N2. The window is 300 s and the quota 2.

    // A second name's answer extends the first owner's entry and is
    // charged nothing.
    #[test]
    fn a_second_name_extends_the_first_owners_entry() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        let n1 = p.answer(0, 1, 5000, 0).unwrap();
        assert_eq!(p.admit(&n1, 10), Admitted::New);
        assert_eq!(p.ask(1, 2, 5000, Instant { ms: 10_000 }), Asked::Recorded);
        let n2 = p.answer(1, 2, 5000, 10_000).unwrap();
        assert_eq!(p.admit(&n2, 10), Admitted::Refreshed { holder: 0 });
        assert_eq!(p.egress(10, None, Instant { ms: 309_999 }), Egress::Window);
        assert_eq!(p.egress(10, None, Instant { ms: 310_000 }), Egress::Refused);
        // N2 still has its whole quota; N1 has one place left.
        assert_eq!(p.admit(&n2, 20), Admitted::New);
        assert_eq!(p.admit(&n2, 21), Admitted::New);
        assert_eq!(p.admit(&n1, 30), Admitted::New);
        assert_eq!(p.admit(&n1, 31), Admitted::NameAtQuota);
    }

    // An expired entry is revived under its first owner by another
    // name's answer.
    #[test]
    fn an_expired_entry_is_revived_under_its_first_owner() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        let n1 = p.answer(0, 1, 5000, 0).unwrap();
        assert_eq!(p.admit(&n1, 10), Admitted::New);
        assert_eq!(p.egress(10, None, Instant { ms: 301_000 }), Egress::Refused);
        assert_eq!(p.ask(1, 2, 5000, Instant { ms: 301_000 }), Asked::Recorded);
        let n2 = p.answer(1, 2, 5000, 301_000).unwrap();
        assert_eq!(p.release_expired(1, 301_000), 0);
        assert_eq!(p.admit(&n2, 10), Admitted::Refreshed { holder: 0 });
        assert_eq!(p.egress(10, None, Instant { ms: 600_999 }), Egress::Window);
        assert_eq!(p.admit(&n2, 20), Admitted::New);
        assert_eq!(p.admit(&n2, 21), Admitted::New);
    }

    // The first owner's own later answer releases its expired entry;
    // another name at its quota is then refused the address.
    #[test]
    fn a_released_address_is_refused_to_a_name_at_its_quota() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        let n1 = p.answer(0, 1, 5000, 0).unwrap();
        assert_eq!(p.admit(&n1, 10), Admitted::New);
        assert_eq!(p.ask(1, 2, 5000, Instant { ms: 5_000 }), Asked::Recorded);
        let n2 = p.answer(1, 2, 5000, 5_000).unwrap();
        assert_eq!(p.admit(&n2, 20), Admitted::New);
        assert_eq!(p.admit(&n2, 21), Admitted::New);
        assert_eq!(p.ask(0, 3, 5000, Instant { ms: 301_000 }), Asked::Recorded);
        let n1 = p.answer(0, 3, 5000, 301_000).unwrap();
        assert_eq!(p.release_expired(0, 301_000), 1);
        assert_eq!(p.admit(&n1, 11), Admitted::New);
        assert_eq!(p.ask(1, 4, 5000, Instant { ms: 302_000 }), Asked::Recorded);
        let n2 = p.answer(1, 4, 5000, 302_000).unwrap();
        assert_eq!(p.release_expired(1, 302_000), 0);
        assert_eq!(p.admit(&n2, 10), Admitted::NameAtQuota);
        assert_eq!(p.egress(10, None, Instant { ms: 302_000 }), Egress::Refused);
    }

    #[test]
    fn an_answer_with_no_question_changes_nothing() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.resolve(0, 7, 5000, &[A], Instant { ms: 0 }), None);
        assert_eq!(p.egress(A, None, Instant { ms: 1 }), Egress::Refused);
    }

    #[test]
    fn an_answer_admits_in_order_until_the_quota() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 7, 5000, Instant { ms: 0 }), Asked::Recorded);
        let c = p
            .resolve(0, 7, 5000, &[1, 2, 3, 1], Instant { ms: 0 })
            .unwrap();
        assert_eq!((c.admitted, c.refused), (3, 1));
        assert_eq!(p.egress(1, None, Instant { ms: 1 }), Egress::Window);
        assert_eq!(p.egress(2, None, Instant { ms: 1 }), Egress::Window);
        assert_eq!(p.egress(3, None, Instant { ms: 1 }), Egress::Refused);
        // The question was consumed: the same answer again does nothing.
        assert_eq!(p.resolve(0, 7, 5000, &[3], Instant { ms: 1 }), None);
    }

    // Through `resolve`: the release is part of the answer.
    #[test]
    fn an_answer_releases_its_names_expired_addresses_first() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert!(p.resolve(0, 1, 5000, &[10], Instant { ms: 0 }).is_some());
        assert_eq!(p.ask(1, 2, 5000, Instant { ms: 5_000 }), Asked::Recorded);
        assert!(
            p.resolve(1, 2, 5000, &[20, 21], Instant { ms: 5_000 })
                .is_some()
        );
        assert_eq!(p.ask(0, 3, 5000, Instant { ms: 301_000 }), Asked::Recorded);
        let c = p
            .resolve(0, 3, 5000, &[11], Instant { ms: 301_000 })
            .unwrap();
        assert_eq!((c.admitted, c.refused), (1, 0));
        assert_eq!(p.ask(1, 4, 5000, Instant { ms: 302_000 }), Asked::Recorded);
        let c = p
            .resolve(1, 4, 5000, &[10], Instant { ms: 302_000 })
            .unwrap();
        assert_eq!((c.admitted, c.refused), (0, 1));
        assert_eq!(p.egress(10, None, Instant { ms: 302_000 }), Egress::Refused);
    }

    // An answer with no address consumes its question and releases nothing.
    #[test]
    fn an_empty_answer_releases_nothing() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert!(p.resolve(0, 1, 5000, &[10], Instant { ms: 0 }).is_some());
        assert_eq!(p.ask(0, 2, 5000, Instant { ms: 301_000 }), Asked::Recorded);
        let c = p.resolve(0, 2, 5000, &[], Instant { ms: 301_000 }).unwrap();
        assert_eq!((c.admitted, c.refused), (0, 0));
        // The expired entry is still there for another name to revive.
        assert_eq!(p.ask(1, 3, 5000, Instant { ms: 301_000 }), Asked::Recorded);
        let c = p
            .resolve(1, 3, 5000, &[10], Instant { ms: 301_000 })
            .unwrap();
        assert_eq!((c.admitted, c.refused), (1, 0));
        assert_eq!(p.resolve(1, 3, 5000, &[20], Instant { ms: 301_000 }), None);
    }

    #[test]
    fn expiring_questions_leaves_admissions() {
        let mut p = Pins::new(OWNER, L).unwrap();
        assert_eq!(p.ask(0, 1, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert!(p.resolve(0, 1, 5000, &[10], Instant { ms: 0 }).is_some());
        assert_eq!(p.ask(0, 2, 5000, Instant { ms: 0 }), Asked::Recorded);
        assert_eq!(p.expire_questions(Instant { ms: 1_000_000 }, 8), 1);
        // The admission is long expired and still held: another name revives it.
        assert_eq!(
            p.ask(1, 3, 5000, Instant { ms: 1_000_000 }),
            Asked::Recorded
        );
        let c = p
            .resolve(1, 3, 5000, &[10], Instant { ms: 1_000_000 })
            .unwrap();
        assert_eq!((c.admitted, c.refused), (1, 0));
        assert_eq!(
            p.egress(10, None, Instant { ms: 1_000_001 }),
            Egress::Window
        );
    }

    #[test]
    fn clear_ends_admissions_and_flows() {
        let mut p = pinned(0);
        assert_eq!(
            p.egress(A, tcp(40000, 0x02), Instant { ms: 1 }),
            Egress::Retained
        );
        p.clear();
        assert_eq!(
            p.egress(A, tcp(40000, 0x10), Instant { ms: 2 }),
            Egress::Refused
        );
    }
}

#[cfg(kani)]
mod proofs {
    //! Bounded checks in the pool's shape: one operation from arbitrary
    //! tables, every argument and every instant unconstrained. Each of the
    //! three tables holds up to `MAX` entries.
    //!
    //! The table the operation reads and writes most takes every shape, one
    //! shape to a harness: a capacity, a slab length and a number of
    //! entries, as plain numbers, forty of them. The other two take one
    //! fixed shape each. Each check is a function of the tables and has a
    //! module of its own with one harness for each shape, named
    //! `c<capacity>_<slots>_<entries>`, and harnesses `reached*` that say
    //! which cases one shape reaches. What a table holds is read through its
    //! index into arrays, and two tables are compared by their lengths and
    //! one arbitrary place, never whole.
    //!
    //! `ask`, `resolve` and `egress` can give an entry up and then add one.
    //! Their checks are whole at some shapes and in ten parts, a harness
    //! each, at the others: where the table is full, and where the slab is
    //! at twice the capacity and holds an entry. Each part reads little;
    //! together they assert what the whole check asserts.

    use super::*;
    use crate::pool::{Entry, kani_count_row, kani_lookup};

    const MAX: usize = 3;

    /// The pairs of places of a table of `MAX` entries.
    const PAIRS: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];
    const _: () = assert!(PAIRS.len() == MAX * (MAX - 1) / 2);

    const NONE: Entry = Entry {
        row: 0,
        key: 0,
        deadline_ms: 0,
        value: 0,
    };

    // The parts of a divided check.
    const WHOLE: u8 = 0;
    const RESULT: u8 = 1;
    const KEPT: u8 = 2;
    const NOTHING_NEW: u8 = 3;
    const OTHERS: u8 = 4;
    const UNIQUE: u8 = 5;
    // From here on, one conjunct each of the written table's invariant,
    // `Slab::kani_holds`.
    const LIMITS: u8 = 6;
    const IN_RANGE: u8 = 7;
    const SORTED: u8 = 8;
    const QUOTA: u8 = 9;
    const FLOOR: u8 = 10;

    /// One harness of `$check` for each shape of a table of up to `MAX`
    /// entries, built by `$make`.
    macro_rules! every_shape {
        ($check:path, $make:path) => {
            shape!($check, $make, c0_0_0, 0, 0, 0);
            shape!($check, $make, c1_0_0, 1, 0, 0);
            shape!($check, $make, c1_1_0, 1, 1, 0);
            shape!($check, $make, c1_1_1, 1, 1, 1);
            shape!($check, $make, c1_2_0, 1, 2, 0);
            shape!($check, $make, c1_2_1, 1, 2, 1);
            shape!($check, $make, c2_0_0, 2, 0, 0);
            shape!($check, $make, c2_1_0, 2, 1, 0);
            shape!($check, $make, c2_1_1, 2, 1, 1);
            shape!($check, $make, c2_2_0, 2, 2, 0);
            shape!($check, $make, c2_2_1, 2, 2, 1);
            shape!($check, $make, c2_2_2, 2, 2, 2);
            shape!($check, $make, c2_3_0, 2, 3, 0);
            shape!($check, $make, c2_3_1, 2, 3, 1);
            shape!($check, $make, c2_3_2, 2, 3, 2);
            shape!($check, $make, c2_4_0, 2, 4, 0);
            shape!($check, $make, c2_4_1, 2, 4, 1);
            shape!($check, $make, c2_4_2, 2, 4, 2);
            shape!($check, $make, c3_0_0, 3, 0, 0);
            shape!($check, $make, c3_1_0, 3, 1, 0);
            shape!($check, $make, c3_1_1, 3, 1, 1);
            shape!($check, $make, c3_2_0, 3, 2, 0);
            shape!($check, $make, c3_2_1, 3, 2, 1);
            shape!($check, $make, c3_2_2, 3, 2, 2);
            shape!($check, $make, c3_3_0, 3, 3, 0);
            shape!($check, $make, c3_3_1, 3, 3, 1);
            shape!($check, $make, c3_3_2, 3, 3, 2);
            shape!($check, $make, c3_3_3, 3, 3, 3);
            shape!($check, $make, c3_4_0, 3, 4, 0);
            shape!($check, $make, c3_4_1, 3, 4, 1);
            shape!($check, $make, c3_4_2, 3, 4, 2);
            shape!($check, $make, c3_4_3, 3, 4, 3);
            shape!($check, $make, c3_5_0, 3, 5, 0);
            shape!($check, $make, c3_5_1, 3, 5, 1);
            shape!($check, $make, c3_5_2, 3, 5, 2);
            shape!($check, $make, c3_5_3, 3, 5, 3);
            shape!($check, $make, c3_6_0, 3, 6, 0);
            shape!($check, $make, c3_6_1, 3, 6, 1);
            shape!($check, $make, c3_6_2, 3, 6, 2);
            shape!($check, $make, c3_6_3, 3, 6, 3);
        };
    }

    macro_rules! shape {
        ($check:path, $make:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check($make($cap, $m, $n));
            }
        };
    }

    macro_rules! shape_part {
        ($check:path, $make:path, $name:ident, $cap:expr, $m:expr, $n:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check($make($cap, $m, $n), $part);
            }
        };
    }

    /// A module `$name` with one harness for each part of `$check` at one
    /// shape.
    macro_rules! in_parts {
        ($check:path, $make:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            mod $name {
                use super::*;

                shape_part!($check, $make, result, $cap, $m, $n, RESULT);
                shape_part!($check, $make, kept, $cap, $m, $n, KEPT);
                shape_part!($check, $make, nothing_new, $cap, $m, $n, NOTHING_NEW);
                shape_part!($check, $make, others, $cap, $m, $n, OTHERS);
                shape_part!($check, $make, unique, $cap, $m, $n, UNIQUE);
                shape_part!($check, $make, limits, $cap, $m, $n, LIMITS);
                shape_part!($check, $make, in_range, $cap, $m, $n, IN_RANGE);
                shape_part!($check, $make, sorted, $cap, $m, $n, SORTED);
                shape_part!($check, $make, quota, $cap, $m, $n, QUOTA);
                shape_part!($check, $make, floor, $cap, $m, $n, FLOOR);
            }
        };
    }

    /// Every shape of a table of up to `MAX` entries: the whole check where
    /// the operation cannot both give an entry up and rewrite the slab or
    /// fill the table, and one part to a harness at the others.
    macro_rules! divided {
        ($check:path, $make:path) => {
            shape_part!($check, $make, c1_0_0, 1, 0, 0, WHOLE);
            shape_part!($check, $make, c1_1_0, 1, 1, 0, WHOLE);
            shape_part!($check, $make, c1_2_0, 1, 2, 0, WHOLE);
            shape_part!($check, $make, c2_0_0, 2, 0, 0, WHOLE);
            shape_part!($check, $make, c2_1_0, 2, 1, 0, WHOLE);
            shape_part!($check, $make, c2_1_1, 2, 1, 1, WHOLE);
            shape_part!($check, $make, c2_2_0, 2, 2, 0, WHOLE);
            shape_part!($check, $make, c2_2_1, 2, 2, 1, WHOLE);
            shape_part!($check, $make, c2_3_0, 2, 3, 0, WHOLE);
            shape_part!($check, $make, c2_3_1, 2, 3, 1, WHOLE);
            shape_part!($check, $make, c2_4_0, 2, 4, 0, WHOLE);
            shape_part!($check, $make, c3_0_0, 3, 0, 0, WHOLE);
            shape_part!($check, $make, c3_1_0, 3, 1, 0, WHOLE);
            shape_part!($check, $make, c3_1_1, 3, 1, 1, WHOLE);
            shape_part!($check, $make, c3_2_0, 3, 2, 0, WHOLE);
            shape_part!($check, $make, c3_2_1, 3, 2, 1, WHOLE);
            shape_part!($check, $make, c3_2_2, 3, 2, 2, WHOLE);
            shape_part!($check, $make, c3_3_0, 3, 3, 0, WHOLE);
            shape_part!($check, $make, c3_3_1, 3, 3, 1, WHOLE);
            shape_part!($check, $make, c3_3_2, 3, 3, 2, WHOLE);
            shape_part!($check, $make, c3_4_0, 3, 4, 0, WHOLE);
            shape_part!($check, $make, c3_4_1, 3, 4, 1, WHOLE);
            shape_part!($check, $make, c3_4_2, 3, 4, 2, WHOLE);
            shape_part!($check, $make, c3_5_0, 3, 5, 0, WHOLE);
            shape_part!($check, $make, c3_5_1, 3, 5, 1, WHOLE);
            shape_part!($check, $make, c3_5_2, 3, 5, 2, WHOLE);
            shape_part!($check, $make, c3_6_0, 3, 6, 0, WHOLE);
            in_parts!($check, $make, c0_0_0, 0, 0, 0);
            in_parts!($check, $make, c1_1_1, 1, 1, 1);
            in_parts!($check, $make, c1_2_1, 1, 2, 1);
            in_parts!($check, $make, c2_2_2, 2, 2, 2);
            in_parts!($check, $make, c2_3_2, 2, 3, 2);
            in_parts!($check, $make, c2_4_1, 2, 4, 1);
            in_parts!($check, $make, c2_4_2, 2, 4, 2);
            in_parts!($check, $make, c3_3_3, 3, 3, 3);
            in_parts!($check, $make, c3_4_3, 3, 4, 3);
            in_parts!($check, $make, c3_5_3, 3, 5, 3);
            in_parts!($check, $make, c3_6_1, 3, 6, 1);
            in_parts!($check, $make, c3_6_2, 3, 6, 2);
            in_parts!($check, $make, c3_6_3, 3, 6, 3);
        };
    }

    /// A table's contents in an array, and how many there are.
    fn snapshot(t: &Slab) -> ([Entry; MAX], usize) {
        let mut out = [NONE; MAX];
        let mut i = 0;
        while i < t.len() {
            out[i] = t.kani_at(i);
            i += 1;
        }
        (out, t.len())
    }

    /// The fixed shape of a table the operation does not write: one entry.
    fn fixed() -> Slab {
        Slab::kani_shaped(1, 1, 1)
    }

    /// The fixed shape of the admitted table where the operation does not
    /// write it: two entries, so that the clause that no address is under
    /// two names reads a pair.
    fn fixed_admitted() -> Slab {
        Slab::kani_shaped(2, 2, 2)
    }

    /// Pins over these tables, with any windows above zero, any owner and
    /// any epoch.
    fn pins_of(asked: Slab, admitted: Slab, flows: Slab) -> Pins {
        let (query_ms, window_ms, idle_ms): (u64, u64, u64) =
            (kani::any(), kani::any(), kani::any());
        kani::assume(query_ms > 0 && window_ms > 0 && idle_ms > 0);
        // The invariant's clause: no address under two names.
        let (s, n) = snapshot(&admitted);
        kani::assume(keys_are_unique(&s[..n]));
        Pins {
            asked,
            admitted,
            flows,
            query_ms,
            window_ms,
            idle_ms,
            owner: kani::any(),
            epoch: kani::any(),
        }
    }

    fn asked_shaped(cap: usize, m: usize, n: usize) -> Pins {
        pins_of(Slab::kani_shaped(cap, m, n), fixed_admitted(), fixed())
    }

    fn admitted_shaped(cap: usize, m: usize, n: usize) -> Pins {
        pins_of(fixed(), Slab::kani_shaped(cap, m, n), fixed())
    }

    fn flows_shaped(cap: usize, m: usize, n: usize) -> Pins {
        pins_of(fixed(), fixed_admitted(), Slab::kani_shaped(cap, m, n))
    }

    /// The windows, owner and epoch, and each table's capacity and quota.
    fn limits(p: &Pins) -> (u64, u64, u64, u32, u64, [(usize, usize); 3]) {
        (
            p.query_ms,
            p.window_ms,
            p.idle_ms,
            p.owner,
            p.epoch,
            [
                p.asked.kani_limits(),
                p.admitted.kani_limits(),
                p.flows.kani_limits(),
            ],
        )
    }

    fn sound(p: &Pins) -> bool {
        if !(p.asked.kani_holds() && p.admitted.kani_holds() && p.flows.kani_holds()) {
            return false;
        }
        let (s, n) = snapshot(&p.admitted);
        keys_are_unique(&s[..n])
    }

    /// One conjunct of a table's invariant, at one arbitrary place: what
    /// `kani_holds` says of every place.
    fn holds_at(t: &Slab, part: u8) {
        let n = t.len();
        let i: usize = kani::any();
        kani::assume(i < n || n == 0);
        if part == LIMITS {
            assert!(t.kani_limits_hold());
        } else if part == IN_RANGE {
            if i < n {
                assert!(t.kani_in_range_at(i));
            }
        } else if part == SORTED {
            if i < n {
                assert!(t.kani_sorted_at(i));
            }
        } else if part == QUOTA {
            if i < n {
                assert!(t.kani_quota_at(i));
            }
        } else if i < n {
            assert!(t.kani_floor_at(i));
        }
    }

    /// No key appears under two rows, read at every pair of places of a
    /// table of up to `MAX` entries.
    fn keys_are_unique(s: &[Entry]) -> bool {
        let mut p = 0;
        while p < PAIRS.len() {
            let (i, j) = PAIRS[p];
            if j < s.len() && s[i].key == s[j].key {
                return false;
            }
            p += 1;
        }
        true
    }

    /// No key appears under two rows, at one arbitrary pair of places.
    fn unique_at(s: &[Entry]) {
        let (i, j): (usize, usize) = (kani::any(), kani::any());
        if i < j && j < s.len() {
            assert!(s[i].key != s[j].key);
        }
    }

    /// The entry that holds `key` under any row, by a plain scan.
    fn holder_of(s: &[Entry], key: u64) -> Option<Entry> {
        let mut i = 0;
        while i < s.len() {
            if s[i].key == key {
                return Some(s[i]);
            }
            i += 1;
        }
        None
    }

    fn another_is_kept(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let w: usize = kani::any();
        if w < before.len() && !(before[w].row == row && before[w].key == key) {
            assert!(kani_lookup(now, before[w].row, before[w].key) == Some(before[w]));
        }
    }

    fn nothing_else_is_new(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let v: usize = kani::any();
        if v < now.len() && !(now[v].row == row && now[v].key == key) {
            assert!(kani_lookup(before, now[v].row, now[v].key) == Some(now[v]));
        }
    }

    /// One arbitrary entry of `before` that has not expired, other than the
    /// one for `(row, key)`, is still held.
    fn unexpired_are_kept(before: &[Entry], now: &[Entry], row: u32, key: u64, now_ms: u64) {
        let x: usize = kani::any();
        if x < before.len()
            && before[x].deadline_ms > now_ms
            && !(before[x].row == row && before[x].key == key)
        {
            assert!(kani_lookup(now, before[x].row, before[x].key) == Some(before[x]));
        }
    }

    /// The row holds nothing that has expired.
    fn row_is_live(s: &[Entry], row: u32, now_ms: u64) {
        let j: usize = kani::any();
        if j < s.len() && s[j].row == row {
            assert!(s[j].deadline_ms > now_ms);
        }
    }

    /// The table holds nothing that has expired.
    fn all_are_live(s: &[Entry], now_ms: u64) {
        let j: usize = kani::any();
        if j < s.len() {
            assert!(s[j].deadline_ms > now_ms);
        }
    }

    /// The contents are what they were: the same length, and the same entry
    /// at one arbitrary place.
    fn unchanged(before: &[Entry], now: &[Entry]) {
        assert!(now.len() == before.len());
        let u: usize = kani::any();
        if u < before.len() {
            assert!(now[u] == before[u]);
        }
    }

    /// The table holds what `before` held, compared as `unchanged` does.
    fn unchanged_table(t: &Slab, before: &[Entry]) {
        let (now, n) = snapshot(t);
        unchanged(before, &now[..n]);
    }

    /// One `ask`, asserting `part` of its check. Returns the result, whether
    /// the name was at its quota, the number of questions before, and the
    /// capacity.
    fn ask_from(mut p: Pins, part: u8) -> (Asked, bool, usize, usize) {
        let (asked, n) = snapshot(&p.asked);
        let asked = &asked[..n];
        let (admitted, n) = snapshot(&p.admitted);
        let admitted = &admitted[..n];
        let (flows, n) = snapshot(&p.flows);
        let flows = &flows[..n];
        let was = limits(&p);
        let (cap, quota) = p.asked.kani_limits();
        let query_ms = p.query_ms;
        let (name, txid, port, now): (u32, u16, u16, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let k = ((txid as u64) << 16) | (port as u64);
        let held = kani_lookup(asked, name, k);
        let fresh = now.saturating_add(query_ms);
        let outcome = p.ask(name, txid, port, Instant { ms: now });
        let facts = (
            outcome,
            kani_count_row(asked, name) >= quota,
            asked.len(),
            cap,
        );
        if part >= LIMITS {
            holds_at(&p.asked, part);
            return facts;
        }
        if part == WHOLE {
            assert!(sound(&p));
        }
        if part == WHOLE || part == OTHERS {
            assert!(limits(&p) == was);
            unchanged_table(&p.admitted, admitted);
            unchanged_table(&p.flows, flows);
            assert!(p.admitted.kani_holds() && p.flows.kani_holds());
        }
        if part == UNIQUE {
            let (s, n) = snapshot(&p.admitted);
            unique_at(&s[..n]);
        }
        let (asked2, n) = snapshot(&p.asked);
        let asked2 = &asked2[..n];
        if part == WHOLE || part == RESULT {
            match outcome {
                Asked::Recorded => {
                    assert!(held.is_none());
                    assert!(
                        kani_lookup(asked2, name, k)
                            == Some(Entry {
                                row: name,
                                key: k,
                                deadline_ms: fresh,
                                value: 0,
                            })
                    );
                    assert!(asked2.len() <= asked.len() + 1);
                }
                Asked::Refreshed => {
                    assert!(held.is_some());
                    assert!(
                        kani_lookup(asked2, name, k)
                            == Some(Entry {
                                row: name,
                                key: k,
                                deadline_ms: fresh,
                                value: 0,
                            })
                    );
                    assert!(asked2.len() == asked.len());
                }
                Asked::NameAtQuota => {
                    assert!(held.is_none());
                    assert!(kani_count_row(asked, name) >= quota);
                    row_is_live(asked, name, now);
                }
                Asked::Full => {
                    assert!(held.is_none());
                    assert!(asked.len() >= cap);
                    all_are_live(asked, now);
                }
            }
        }
        if part == WHOLE || part == KEPT {
            match outcome {
                Asked::Recorded => unexpired_are_kept(asked, asked2, name, k, now),
                Asked::Refreshed => another_is_kept(asked, asked2, name, k),
                Asked::NameAtQuota | Asked::Full => {}
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            match outcome {
                Asked::NameAtQuota | Asked::Full => unchanged(asked, asked2),
                Asked::Recorded | Asked::Refreshed => {}
            }
            nothing_else_is_new(asked, asked2, name, k);
        }
        facts
    }

    /// One `answer`. G5 (a). Returns whether a token came back, whether the
    /// question was held, live or not, and the number of questions before.
    fn answer_from(mut p: Pins) -> (bool, bool, usize) {
        let (asked, n) = snapshot(&p.asked);
        let asked = &asked[..n];
        let (admitted, n) = snapshot(&p.admitted);
        let admitted = &admitted[..n];
        let (flows, n) = snapshot(&p.flows);
        let flows = &flows[..n];
        let was = limits(&p);
        let (owner, epoch) = (p.owner, p.epoch);
        let (name, txid, port, now): (u32, u16, u16, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let k = ((txid as u64) << 16) | (port as u64);
        let live = match kani_lookup(asked, name, k) {
            Some(e) => e.deadline_ms > now,
            None => false,
        };
        let token = p.answer(name, txid, port, now);
        let (asked2, n) = snapshot(&p.asked);
        let asked2 = &asked2[..n];
        assert!(sound(&p));
        assert!(limits(&p) == was);
        unchanged_table(&p.admitted, admitted);
        unchanged_table(&p.flows, flows);
        assert!(token.is_some() == live);
        nothing_else_is_new(asked, asked2, name, k);
        another_is_kept(asked, asked2, name, k);
        let answered = match token {
            Some(a) => {
                assert!(a.name == name && a.at_ms == now && a.owner == owner && a.epoch == epoch);
                assert!(kani_lookup(asked2, name, k).is_none());
                assert!(asked2.len() + 1 == asked.len());
                true
            }
            None => {
                unchanged(asked, asked2);
                false
            }
        };
        (answered, kani_lookup(asked, name, k).is_some(), asked.len())
    }

    /// One `admit`, with any token. G5 (b), (h), (i). Returns the result,
    /// the token's name, the number of admissions before, and the capacity.
    fn admit_from(mut p: Pins) -> (Admitted, u32, usize, usize) {
        let (asked, n) = snapshot(&p.asked);
        let asked = &asked[..n];
        let (admitted, n) = snapshot(&p.admitted);
        let admitted = &admitted[..n];
        let (flows, n) = snapshot(&p.flows);
        let flows = &flows[..n];
        let was = limits(&p);
        let (cap, quota) = p.admitted.kani_limits();
        let (owner, epoch, window_ms) = (p.owner, p.epoch, p.window_ms);
        let a = Answered {
            name: kani::any(),
            at_ms: kani::any(),
            owner: kani::any(),
            epoch: kani::any(),
        };
        let addr: u32 = kani::any();
        let k = addr as u64;
        let held = holder_of(admitted, k);
        let until = a.at_ms.saturating_add(window_ms);
        let outcome = p.admit(&a, addr);
        let (admitted2, n) = snapshot(&p.admitted);
        let admitted2 = &admitted2[..n];
        assert!(sound(&p));
        assert!(limits(&p) == was);
        unchanged_table(&p.asked, asked);
        unchanged_table(&p.flows, flows);
        let current = a.owner == owner && a.epoch == epoch;
        match outcome {
            Admitted::Stale => {
                assert!(!current);
                unchanged(admitted, admitted2);
            }
            Admitted::New => {
                assert!(current && held.is_none());
                assert!(
                    holder_of(admitted2, k)
                        == Some(Entry {
                            row: a.name,
                            key: k,
                            deadline_ms: until,
                            value: 0,
                        })
                );
                assert!(admitted2.len() == admitted.len() + 1);
                another_is_kept(admitted, admitted2, a.name, k);
                nothing_else_is_new(admitted, admitted2, a.name, k);
            }
            Admitted::Refreshed { holder } => {
                assert!(current);
                let (row, was, kept) = match held {
                    Some(e) => (e.row, e.deadline_ms, e.value),
                    None => (0, 0, 0),
                };
                assert!(held.is_some() && holder == row);
                let want = if was >= until { was } else { until };
                assert!(
                    holder_of(admitted2, k)
                        == Some(Entry {
                            row,
                            key: k,
                            deadline_ms: want,
                            value: kept,
                        })
                );
                assert!(admitted2.len() == admitted.len());
                another_is_kept(admitted, admitted2, row, k);
                nothing_else_is_new(admitted, admitted2, row, k);
            }
            Admitted::NameAtQuota => {
                assert!(current && held.is_none());
                unchanged(admitted, admitted2);
                assert!(kani_count_row(admitted, a.name) >= quota);
            }
            Admitted::Full => {
                assert!(current && held.is_none());
                unchanged(admitted, admitted2);
                assert!(admitted.len() >= cap);
            }
        }
        (outcome, a.name, admitted.len(), cap)
    }

    /// One `release_expired`. G5 (h). Returns how many went and the number
    /// of admissions before.
    fn release_from(mut p: Pins) -> (usize, usize) {
        let (asked, n) = snapshot(&p.asked);
        let asked = &asked[..n];
        let (admitted, n) = snapshot(&p.admitted);
        let admitted = &admitted[..n];
        let (flows, n) = snapshot(&p.flows);
        let flows = &flows[..n];
        let was = limits(&p);
        let (name, now): (u32, u64) = (kani::any(), kani::any());
        let removed = p.release_expired(name, now);
        let (admitted2, n) = snapshot(&p.admitted);
        let admitted2 = &admitted2[..n];
        assert!(sound(&p));
        assert!(limits(&p) == was);
        unchanged_table(&p.asked, asked);
        unchanged_table(&p.flows, flows);
        assert!(admitted2.len() + removed == admitted.len());
        row_is_live(admitted2, name, now);
        // An entry of another name, or one that has not expired, is kept; and
        // nothing is new.
        let x: usize = kani::any();
        if x < admitted.len() && (admitted[x].row != name || admitted[x].deadline_ms > now) {
            assert!(kani_lookup(admitted2, admitted[x].row, admitted[x].key) == Some(admitted[x]));
        }
        let v: usize = kani::any();
        if v < admitted2.len() {
            assert!(
                kani_lookup(admitted, admitted2[v].row, admitted2[v].key) == Some(admitted2[v])
            );
        }
        (removed, admitted.len())
    }

    /// What one `resolve` found, for the covers.
    #[derive(Clone, Copy)]
    struct Resolved {
        answered: bool,
        admitted: u16,
        refused: u16,
        holder: Option<Entry>,
        name: u32,
        now: u64,
        left: usize,
        left_of_name: usize,
        cap: usize,
        quota: usize,
        before: usize,
        after: usize,
    }

    /// One `resolve` of one address, from the admitted table `admitted_pool`
    /// with the question held and live and no flows, asserting `part` of its
    /// check. Read by key, not by position, and without building the
    /// expected table: the expired entries of the name are gone; the address
    /// is refreshed under whoever still holds it, or entered under the name
    /// if the name and the table have room, or refused; nothing else
    /// changed. G5 (a), (b), (h), (i); the one-answer theorems (a), (b), (e), (f) at this bound.
    /// `None` only where a table of one slot cannot be made.
    fn resolve_one_from(admitted_pool: Slab, part: u8) -> Option<Resolved> {
        let (query_ms, window_ms, idle_ms): (u64, u64, u64) =
            (kani::any(), kani::any(), kani::any());
        kani::assume(query_ms > 0 && window_ms > 0 && idle_ms > 0);
        let (name, txid, port, now): (u32, u16, u16, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(now < u64::MAX);
        let k = ((txid as u64) << 16) | (port as u64);
        let (before, n) = snapshot(&admitted_pool);
        let before = &before[..n];
        kani::assume(keys_are_unique(before));
        let (cap, quota) = admitted_pool.kani_limits();
        let mut asked_pool = match Slab::new(1, 1) {
            Some(x) => x,
            None => return None,
        };
        // The question, live at `now`.
        let _ = asked_pool.insert(name, k, Instant { ms: now + 1 }, 0);
        let flows_pool = match Slab::new(1, 1) {
            Some(x) => x,
            None => return None,
        };
        let mut p = Pins {
            asked: asked_pool,
            admitted: admitted_pool,
            flows: flows_pool,
            query_ms,
            window_ms,
            idle_ms,
            owner: kani::any(),
            epoch: kani::any(),
        };
        let was = limits(&p);
        let addr: u32 = kani::any();
        let a = addr as u64;
        let limit = if now > u64::MAX - window_ms {
            u64::MAX
        } else {
            now + window_ms
        };
        // What the release leaves: everything but the name's expired entries.
        let released = |e: &Entry| e.row == name && e.deadline_ms <= now;
        let mut left: usize = 0;
        let mut left_of_name: usize = 0;
        let mut holder: Option<Entry> = None;
        let mut c: usize = 0;
        while c < before.len() {
            if !released(&before[c]) {
                left += 1;
                if before[c].row == name {
                    left_of_name += 1;
                }
                if before[c].key == a {
                    holder = Some(before[c]);
                }
            }
            c += 1;
        }
        let outcome = p.resolve(name, txid, port, &[addr], Instant { ms: now });
        let (answered, admitted_n, refused_n) = match outcome {
            Some(c) => (true, c.admitted, c.refused),
            None => (false, 0, 0),
        };
        let facts = Some(Resolved {
            answered,
            admitted: admitted_n,
            refused: refused_n,
            holder,
            name,
            now,
            left,
            left_of_name,
            cap,
            quota,
            before: before.len(),
            after: p.admitted.len(),
        });
        if part >= LIMITS {
            holds_at(&p.admitted, part);
            return facts;
        }
        if part == WHOLE {
            assert!(sound(&p));
        }
        if part == WHOLE || part == OTHERS {
            assert!(limits(&p) == was);
            assert!(p.asked.len() == 0);
            assert!(p.flows.len() == 0);
            assert!(p.asked.kani_holds() && p.flows.kani_holds());
        }
        let (after, n) = snapshot(&p.admitted);
        let after = &after[..n];
        if part == UNIQUE {
            unique_at(after);
        }
        if part == WHOLE || part == RESULT {
            let c = match outcome {
                Some(c) => c,
                None => {
                    assert!(false);
                    return facts;
                }
            };
            match holder {
                Some(h) => {
                    // Refreshed under its holder, whoever asked; never shortened.
                    assert!(c.admitted == 1 && c.refused == 0);
                    assert!(after.len() == left);
                    let want = Entry {
                        deadline_ms: if h.deadline_ms >= limit {
                            h.deadline_ms
                        } else {
                            limit
                        },
                        ..h
                    };
                    assert!(kani_lookup(after, h.row, a) == Some(want));
                }
                None => {
                    if left_of_name < quota && left < cap {
                        assert!(c.admitted == 1 && c.refused == 0);
                        assert!(after.len() == left + 1);
                        let want = Entry {
                            row: name,
                            key: a,
                            deadline_ms: limit,
                            value: 0,
                        };
                        assert!(kani_lookup(after, name, a) == Some(want));
                    } else {
                        assert!(c.admitted == 0 && c.refused == 1);
                        assert!(after.len() == left);
                    }
                }
            }
        }
        // Every other entry the release left is as it was; the released ones are gone.
        if part == WHOLE || part == KEPT {
            let w: usize = kani::any();
            if w < before.len() && before[w].key != a {
                let now_held = kani_lookup(after, before[w].row, before[w].key);
                if released(&before[w]) {
                    assert!(now_held.is_none());
                } else {
                    assert!(now_held == Some(before[w]));
                }
            }
        }
        // Nothing else is new.
        if part == WHOLE || part == NOTHING_NEW {
            let v: usize = kani::any();
            if v < after.len() && after[v].key != a {
                assert!(kani_lookup(before, after[v].row, after[v].key) == Some(after[v]));
            }
        }
        facts
    }

    /// One `egress`, asserting `part` of its check. G5 (c), (d), (e), (f).
    /// Returns the result, whether the frame closes, whether it has ports,
    /// whether a record for it was held, and the numbers of flows before
    /// and after.
    fn egress_from(mut p: Pins, part: u8) -> (Egress, bool, bool, bool, usize, usize) {
        let (asked, n) = snapshot(&p.asked);
        let asked = &asked[..n];
        let (admitted, n) = snapshot(&p.admitted);
        let admitted = &admitted[..n];
        let (flows, n) = snapshot(&p.flows);
        let flows = &flows[..n];
        let was = limits(&p);
        let idle_ms = p.idle_ms;
        let (dst, now): (u32, u64) = (kani::any(), kani::any());
        let has_ports: bool = kani::any();
        let x = Transport {
            proto: kani::any(),
            sport: kani::any(),
            dport: kani::any(),
            flags: kani::any(),
        };
        let t = if has_ports { Some(x) } else { None };
        // Some name's admission of this address has not expired.
        let mut window = false;
        let mut i = 0;
        while i < admitted.len() {
            if admitted[i].key == dst as u64 && admitted[i].deadline_ms > now {
                window = true;
            }
            i += 1;
        }
        let k = ((x.proto as u64) << 32) | ((x.sport as u64) << 16) | (x.dport as u64);
        let held = if has_ports {
            kani_lookup(flows, dst, k)
        } else {
            None
        };
        let live = match held {
            Some(e) => e.deadline_ms > now,
            None => false,
        };
        let ends = has_ports && x.proto == TCP && x.flags & (FIN | RST) != 0;
        let fresh = now.saturating_add(idle_ms);
        let outcome = p.egress(dst, t, Instant { ms: now });
        let facts = (
            outcome,
            ends,
            has_ports,
            held.is_some(),
            flows.len(),
            p.flows.len(),
        );
        if part >= LIMITS {
            holds_at(&p.flows, part);
            return facts;
        }
        if part == WHOLE {
            assert!(sound(&p));
        }
        if part == WHOLE || part == OTHERS {
            assert!(limits(&p) == was);
            unchanged_table(&p.asked, asked);
            unchanged_table(&p.admitted, admitted);
            assert!(p.asked.kani_holds() && p.admitted.kani_holds());
        }
        if part == UNIQUE {
            let (s, n) = snapshot(&p.admitted);
            unique_at(&s[..n]);
        }
        let (flows2, n) = snapshot(&p.flows);
        let flows2 = &flows2[..n];
        if part == WHOLE || part == RESULT {
            match outcome {
                Egress::Refused => {
                    assert!(!live && !window);
                }
                Egress::ByFlow => {
                    assert!(live);
                    if ends {
                        assert!(kani_lookup(flows2, dst, k).is_none());
                        assert!(flows2.len() + 1 == flows.len());
                    } else {
                        let (was, kept) = match held {
                            Some(e) => (e.deadline_ms, e.value),
                            None => (0, 0),
                        };
                        let want = if was >= fresh { was } else { fresh };
                        assert!(
                            kani_lookup(flows2, dst, k)
                                == Some(Entry {
                                    row: dst,
                                    key: k,
                                    deadline_ms: want,
                                    value: kept,
                                })
                        );
                        assert!(flows2.len() == flows.len());
                    }
                }
                Egress::Window => {
                    assert!(!live && window);
                }
                Egress::Retained => {
                    assert!(!live && window && has_ports && !ends);
                    assert!(
                        kani_lookup(flows2, dst, k)
                            == Some(Entry {
                                row: dst,
                                key: k,
                                deadline_ms: fresh,
                                value: 0,
                            })
                    );
                    assert!(flows2.len() <= flows.len() + 1);
                }
            }
        }
        if part == WHOLE || part == KEPT {
            match outcome {
                Egress::ByFlow => another_is_kept(flows, flows2, dst, k),
                Egress::Retained => unexpired_are_kept(flows, flows2, dst, k, now),
                Egress::Refused | Egress::Window => {}
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            match outcome {
                Egress::Refused | Egress::Window => unchanged(flows, flows2),
                Egress::ByFlow | Egress::Retained => nothing_else_is_new(flows, flows2, dst, k),
            }
        }
        facts
    }

    /// Every shape of the question table; the admitted table holds two
    /// entries and the flow table one.
    #[cfg(feature = "kani-full")]
    mod ask_step {
        use super::*;

        divided!(ask_from, asked_shaped);

        // The cases reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, at_quota, n, _) = ask_from(asked_shaped(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Asked::Recorded && at_quota && n == MAX);
            kani::cover!(r == Asked::Recorded && !at_quota && n == MAX);
            kani::cover!(r == Asked::Refreshed);
            kani::cover!(r == Asked::NameAtQuota);
            kani::cover!(r == Asked::Full);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_with_room() {
            let (r, _, n, cap) = ask_from(asked_shaped(MAX, 2 * MAX - 1, MAX - 1), LIMITS);
            kani::cover!(r == Asked::Recorded && n < cap);
        }
    }

    /// Every shape of the question table; the admitted table holds two
    /// entries and the flow table one.
    #[cfg(feature = "kani-full")]
    mod answer_step {
        use super::*;

        every_shape!(answer_from, asked_shaped);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (answered, held, n) = answer_from(asked_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(answered && n == MAX);
            kani::cover!(!answered && held);
            kani::cover!(!held && n == MAX);
        }
    }

    /// Every shape of the admitted table; the other two hold one entry each.
    #[cfg(feature = "kani-full")]
    mod admit_step {
        use super::*;

        every_shape!(admit_from, admitted_shaped);

        // A table with a place left, in a slab with no slot left.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, name, _, _) = admit_from(admitted_shaped(MAX, 2 * MAX, MAX - 1));
            kani::cover!(r == Admitted::Stale);
            kani::cover!(r == Admitted::New);
            kani::cover!(matches!(r, Admitted::Refreshed { holder } if holder == name));
            kani::cover!(matches!(r, Admitted::Refreshed { holder } if holder != name));
            kani::cover!(r == Admitted::NameAtQuota);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_with_a_slot_left() {
            let (r, _, _, _) = admit_from(admitted_shaped(MAX, 2 * MAX - 1, MAX - 1));
            kani::cover!(r == Admitted::New);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, _, n, cap) = admit_from(admitted_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(r == Admitted::Full && n == cap);
        }
    }

    /// Every shape of the admitted table; the other two hold one entry each.
    #[cfg(feature = "kani-full")]
    mod release_step {
        use super::*;

        every_shape!(release_from, admitted_shaped);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (removed, n) = release_from(admitted_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(removed == 0 && n == MAX);
            kani::cover!(removed == MAX);
        }
    }

    /// Every shape of the admitted table; the question table holds the one
    /// question and the flow table nothing.
    #[cfg(feature = "kani-full")]
    mod resolve_one_step {
        use super::*;

        divided!(resolve_one_from, Slab::kani_shaped);

        // The cases reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            if let Some(c) = resolve_one_from(Slab::kani_shaped(MAX, 2 * MAX, MAX), LIMITS) {
                kani::cover!(c.answered);
                kani::cover!(c.admitted == 1 && c.holder.is_some());
                kani::cover!(c.admitted == 1 && c.holder.is_none());
                kani::cover!(c.refused == 1 && c.left_of_name >= c.quota);
                kani::cover!(c.refused == 1 && c.left >= c.cap && c.left_of_name < c.quota);
                kani::cover!(c.admitted == 1 && c.holder.is_none() && c.after < c.before + 1);
                kani::cover!(
                    matches!(c.holder, Some(h) if h.row != c.name && h.deadline_ms <= c.now)
                );
            }
        }
    }

    /// Every shape of the flow table; the question table holds one entry and
    /// the admitted table two.
    #[cfg(feature = "kani-full")]
    mod egress_step {
        use super::*;

        divided!(egress_from, flows_shaped);

        // The cases reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, ends, has_ports, _, n, after) =
                egress_from(flows_shaped(MAX, 2 * MAX, MAX - 1), LIMITS);
            kani::cover!(r == Egress::Refused);
            kani::cover!(r == Egress::ByFlow && ends);
            kani::cover!(r == Egress::ByFlow && !ends);
            kani::cover!(r == Egress::Window && has_ports && !ends);
            kani::cover!(r == Egress::Window && !has_ports);
            kani::cover!(r == Egress::Retained && after == n + 1);
            kani::cover!(r == Egress::Retained && after == n);
        }

        // A full table: a record opens only in place of an expired one.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, _, _, held, n, after) = egress_from(flows_shaped(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Egress::Retained && !held && n == MAX && after == MAX);
            kani::cover!(r == Egress::Window && n == MAX);
        }
    }
}
