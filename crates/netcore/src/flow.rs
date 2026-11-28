//! One box's table of inbound conversations, and the replies it admits.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A box that publishes a port may answer the clients that connect to it even
//! when its egress rules would refuse the client's address. The table is the
//! one thing that admits a frame the rules do not, so what it admits is narrow.
//!
//! THEOREM G6, for every sequence of operations on a [`Flows`] (a clause
//! keeps its letter for good, so the letters have gaps and are not in order):
//!   (a) `reply` admits a frame exactly when the frame names this box, is TCP
//!       or UDP, and the table holds a record for the same client, protocol
//!       and ports that has not expired;
//!   (b) `reply` never opens a record, and a refused reply changes nothing
//!       but removing the frame's own record, in place, when it has
//!       expired; it never moves the instant of the last sweep;
//!   (c) a TCP reply carrying FIN is admitted and marks the record as
//!       closed by the box, and a FIN from the client marks it as closed by
//!       the client; an RST from either side marks it as closed by both. The
//!       first FIN sets the record's life to `tcp_closing`, which may
//!       shorten it; while one side has closed, every later frame leaves it
//!       at least `tcp_closing` to live; the second FIN sets it to
//!       `tcp_closed`, as an RST does, and no frame extends it after. An
//!       opening packet from the client that is not an RST, on a record in a
//!       closing state, makes it an open record again. No frame of its
//!       conversation removes a live record;
//!   (d) `inbound` opens a record only for an opening packet addressed to this
//!       box: any UDP datagram, or a TCP SYN without ACK; and a record it
//!       opens admits the reply at the same instant (at every instant but
//!       the last a `u64` can name); a frame that opens nothing and finds no
//!       live record of its own changes nothing but removing that record,
//!       in place, when it has expired, and never moves the instant of the
//!       last sweep;
//!   (e) an inbound frame the table refuses changes nothing but the instant
//!       of the last sweep, and is refused only when the table is at its
//!       capacity, holds no record closed by both sides (q), and either no
//!       sweep was due, or one was and found nothing expired and no record
//!       it may give up (n); a sweep removes every expired record, and a
//!       record that has not expired goes only as (n) and (q) say;
//!   (f) a frame without FIN or RST on a record no side has closed never shortens
//!       its life, never sets it past the
//!       instant of the frame plus that frame's window, and changes no other
//!       record. The
//!       window is chosen by the frame's protocol and, for a UDP datagram
//!       toward the box, by whether the box has replied on that record;
//!   (g) the table keeps G7: a hard capacity, with no bound per client below
//!       it;
//!   (h) a UDP record is marked replied by the box's reply and by nothing
//!       else; every record `inbound` opens or reopens starts unmarked, and
//!       a TCP record is never reported as replied: while no side has
//!       closed its value says whether the box has sent a segment on it,
//!       set by the box's segment and by nothing else and kept until a
//!       side closes; after that its value is which sides
//!       have closed, set by a FIN of that side or, for both, by an RST of
//!       either, and by nothing else, and cleared by an opening packet from
//!       the client and by nothing else;
//!   (j) ending a port removes every record of that protocol and box port,
//!       of every client and expired or not, and no other record: afterwards
//!       the table holds none, so no reply on that port is admitted by one;
//!   (k) the table reads itself whole only for a frame that would open a
//!       record it does not hold, at its capacity: as the sweep, at most
//!       once in its interval (SW1 (c)), and as the pass of (q), only as (r)
//!       says; the instant of the last sweep moves with the sweep and at no
//!       other time, and `clear` forgets it.
//!   (n) with `evict_after` set, a sweep that was due at the capacity and
//!       found nothing expired gives up one record that has not expired,
//!       and the opening frame takes its room. The record is the first, by
//!       class, then by deadline, then by its place in the table's order
//!       (client, then key), of those in a class: 1, closed by both sides;
//!       2, closed by one; 3, never answered by the box; 4, answered, with
//!       no side closed, and its last frame at least `evict_after` ago, read
//!       from its deadline. Every other record is unchanged. A record in no
//!       class is never given up: one the box has answered, that no side
//!       has closed, within `evict_after` of its last frame. With
//!       `evict_after` unset no record that has not expired is ever given
//!       up but one closed by both sides (q);
//!   (m) after a segment from the box, FIN and RST included, on
//!       a record both sides had not already closed, the record is live for
//!       at least `tcp_closed` more, so the box's next frames of that
//!       conversation are admitted (a) unless the table, at its capacity,
//!       gives the record up to an opening ((n), (q));
//!   (q) at the capacity, when no sweep was due or one was and found nothing
//!       expired, an opening takes its room from the records closed by both
//!       sides: every one of them goes, expired or not and whether or not
//!       `evict_after` is set, and every other record is unchanged. A
//!       conversation both sides have finished never costs a new one its
//!       place, and one that a side has not finished is not touched;
//!   (r) the pass of (q) runs only while the table's mark is set. A segment
//!       that leaves its record closed by both sides sets the mark and
//!       nothing else does; the pass and `clear` clear it and nothing else
//!       does; with the mark clear the table holds no such record. So
//!       between two passes a conversation was closed by both sides, and an
//!       opening that finds the mark clear reads no more than (k)'s sweep.
//!
//! THEOREM K1: `key` is injective. Two conversations of one client with the
//! same key have the same protocol and ports.
//!
//! An expired record admits nothing. It stays until a frame of its own
//! conversation touches it (a reply, or an inbound frame that does not open,
//! removes it; an opening frame reopens it in place), a sweep at the
//! capacity, `end_port`, `clear` or `expire`.
//!
//! Not here: whether a live record still names the peer that opened it after
//! an address is reused. When a port's records end is the gate's to say
//! ([`crate::gate::Gate::retract`]).

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::pool::{Entry, Inserted, Swept, Throttle};
#[cfg(verus_keep_ghost)]
use crate::pool::{
    bounded_by, changed_only_to, distinct_keys, has, holds, keeps_live, keeps_others,
    keeps_unmatched, keeps_unvalued, key_ends, lemma_refresh_bounded, lemma_refresh_not_shortened,
    none_ending, none_expired, none_valued, not_shortened, only_adds, refreshed_from, subset_of,
};
use crate::slab::Slab;
#[cfg(verus_keep_ghost)]
use crate::slab::{scap, sinv, squota, sview};
#[cfg(verus_keep_ghost)]
use crate::sweep::{
    dropped_if_expired, due, lemma_dropped_subset, lemma_not_held_untouched, swept_and_added,
};
use crate::time::{Instant, Span};

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const TCP: u8 = 6;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const UDP: u8 = 17;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const FIN: u8 = 0x01;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const SYN: u8 = 0x02;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const RST: u8 = 0x04;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ACK: u8 = 0x10;

/// A TCP record's value: no side has closed, and the box has sent a segment.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ANSWERED: u32 = 1;
/// A TCP record's value: the box has closed (it sent FIN).
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BOX_FIN: u32 = 2;
/// A TCP record's value: the client has closed (it sent FIN).
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const CLIENT_FIN: u32 = 4;
/// A TCP record's value: both have, or either sent RST.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const BOTH_FIN: u32 = 6;

/// One conversation, named by its ends and not by a direction. An inbound
/// frame's source is the client; a frame the box sends has the client as its
/// destination. The shell builds this once per frame from parsed facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Conversation {
    pub proto: u8,
    pub client: u32,
    pub client_port: u16,
    pub box_addr: u32,
    pub box_port: u16,
}

/// How long a record lives after each kind of event, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Windows {
    /// After any TCP segment in either direction, while neither side has
    /// sent FIN.
    pub tcp_idle_ms: u64,
    /// After the first FIN, and after every later segment while one side
    /// has sent FIN and the other has not.
    pub tcp_closing_ms: u64,
    /// After the second FIN, or an RST.
    pub tcp_closed_ms: u64,
    /// After a UDP datagram from the client.
    pub udp_unreplied_ms: u64,
    /// After a UDP datagram from the box.
    pub udp_replied_ms: u64,
    /// How long after its last frame an answered record no side has closed
    /// is safe from being given up at the capacity. `None`: no record that
    /// has not expired is ever given up, and a full table refuses.
    pub evict_after_ms: Option<u64>,
}

/// What one inbound frame did. The shell delivers the frame unless the result
/// is `NotThisBox` or `TableFull`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Inbound {
    /// The frame opened a record.
    Opened,
    /// The frame belongs to a live record, which stays live: it runs at
    /// least as long, unless the frame is a FIN, which sets the closing life.
    /// `replied`: the box had replied on it, which chose the longer UDP window.
    Refreshed { replied: bool },
    /// A TCP RST from the client closed a live record: it is held as closed
    /// by both sides, and nothing extends it.
    Ended,
    /// The frame opens nothing: not TCP or UDP, or a TCP segment that is not
    /// a SYN without ACK and has no live record. An expired record of its
    /// conversation is removed; nothing else changed.
    Untracked,
    /// The frame is not addressed to this box. Nothing changed.
    NotThisBox,
    /// The table is full. Nothing changed.
    TableFull,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Flows {
    pool: Slab,
    box_addr: u32,
    windows: Windows,
    /// When the table last swept at its capacity, and how long it waits
    /// before the next.
    throttle: Throttle,
    /// The mark of G6 (r). Clear: no record is closed by both sides.
    may_hold_closed: bool,
}

#[cfg(verus_keep_ghost)]
verus! {

/// The key of a conversation inside its client's row: protocol, client port,
/// box port, in fixed positions.
pub open spec fn key_of(proto: u8, client_port: u16, box_port: u16) -> u64 {
    (proto as u64 * 4294967296 + client_port as u64 * 65536 + box_port as u64) as u64
}

pub open spec fn conv_key(c: Conversation) -> u64 {
    key_of(c.proto, c.client_port, c.box_port)
}

pub open spec fn is_flow_proto(proto: u8) -> bool {
    proto == TCP || proto == UDP
}

/// An opening packet: any UDP datagram, or a TCP SYN without ACK.
pub open spec fn opening(proto: u8, flags: u8) -> bool {
    proto == UDP || (proto == TCP && flags & SYN != 0 && flags & ACK == 0)
}

/// The key belongs to a TCP conversation.
pub open spec fn tcp_key(key: u64) -> bool {
    key_of(TCP, 0, 0) <= key <= key_of(TCP, 0xffff, 0xffff)
}

/// A TCP record's value while no side has closed: 0, or `ANSWERED`.
pub open spec fn open_value(v: u32) -> bool {
    v == 0 || v == ANSWERED
}

/// A TCP record's value once the box has sent FIN.
pub open spec fn with_box_fin(v: u32) -> u32 {
    if open_value(v) { BOX_FIN } else if v == CLIENT_FIN { BOTH_FIN } else { v }
}

/// A TCP record's value once the client has sent FIN.
pub open spec fn with_client_fin(v: u32) -> u32 {
    if open_value(v) { CLIENT_FIN } else if v == BOX_FIN { BOTH_FIN } else { v }
}

/// A TCP record's value after a segment with `flags` from the box
/// (`from_box`) or from the client.
pub open spec fn tcp_value(v: u32, flags: u8, from_box: bool) -> u32 {
    if flags & RST != 0 {
        // A reset from either side: closed by both.
        BOTH_FIN
    } else if !from_box && flags & SYN != 0 && flags & ACK == 0 {
        // An opening packet from the client: an open record again, and an
        // open one as it was.
        if open_value(v) { v } else { 0 }
    } else if flags & FIN == 0 {
        // The box's segment marks an open record as answered.
        if from_box && v == 0 { ANSWERED } else { v }
    } else if from_box {
        with_box_fin(v)
    } else {
        with_client_fin(v)
    }
}

/// The later of two instants.
pub open spec fn later_spec(a: u64, b: u64) -> u64 {
    if a >= b { a } else { b }
}

/// When a live TCP record that ended at `was` with value `before` ends
/// after a segment at `now_ms` that leaves its value `after`: G6 (c).
pub open spec fn tcp_deadline(w: Windows, was: u64, before: u32, after: u32, now_ms: u64) -> u64 {
    if open_value(after) {
        later_spec(was, add_ms_spec(now_ms, w.tcp_idle_ms))
    } else if after == BOTH_FIN {
        if before == BOTH_FIN { was } else { add_ms_spec(now_ms, w.tcp_closed_ms) }
    } else if before == after {
        later_spec(was, add_ms_spec(now_ms, w.tcp_closing_ms))
    } else {
        add_ms_spec(now_ms, w.tcp_closing_ms)
    }
}

/// The record a TCP segment leaves in place of `e`.
pub open spec fn tcp_after(w: Windows, e: Entry, flags: u8, from_box: bool, now_ms: u64) -> Entry {
    Entry {
        row: e.row,
        key: e.key,
        deadline_ms: tcp_deadline(w, e.deadline_ms, e.value, tcp_value(e.value, flags, from_box), now_ms),
        value: tcp_value(e.value, flags, from_box),
    }
}

/// Every entry of `before` for `(row, key)` is in `after` as what the
/// segment makes of it. Opaque: a reader of the two step contracts that does
/// not ask what a TCP record became does not unfold it.
#[verifier::opaque]
pub open spec fn tcp_stepped(after: Seq<Entry>, before: Seq<Entry>, w: Windows, row: u32, key: u64, flags: u8, from_box: bool, now_ms: u64) -> bool {
    forall|j: int| 0 <= j < before.len() && (#[trigger] before[j]).row == row && before[j].key == key
        ==> has(after, tcp_after(w, before[j], flags, from_box, now_ms))
}

/// G6 (f) for a record no side has closed: no record's life is shortened,
/// none ends later than `limit` unless it already did, and the frame's own
/// ends at the later of its old end and `limit`, with value `v` or, for
/// `None`, the value it had. Opaque, as `tcp_stepped` is.
#[verifier::opaque]
pub open spec fn open_refresh(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, limit: u64, v: Option<u32>) -> bool {
    &&& not_shortened(after, before)
    &&& bounded_by(after, before, limit)
    &&& crate::pool::extended(after, before, row, key, limit, v)
}

/// The frame finds its record open on both sides and leaves it so: UDP, or
/// TCP without FIN or RST on a record no side has closed.
pub open spec fn stays_open(s: Seq<Entry>, row: u32, key: u64, proto: u8, flags: u8, now_ms: u64) -> bool {
    proto != TCP || (flags & FIN == 0 && flags & RST == 0
        && (live_with(s, row, key, now_ms, 0) || live_with(s, row, key, now_ms, ANSWERED)))
}

/// `s` holds a record for `(row, key)` that has not expired at `now_ms`.
pub open spec fn live(s: Seq<Entry>, row: u32, key: u64, now_ms: u64) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].row == row && s[j].key == key && s[j].deadline_ms > now_ms
}

/// Every row and key in `now` was in `before`.
pub open spec fn no_new_keys(now: Seq<Entry>, before: Seq<Entry>) -> bool {
    forall|j: int| 0 <= j < now.len() ==> holds(before, (#[trigger] now[j]).row, now[j].key)
}

/// `a + b`, stopping at the largest value.
pub open spec fn add_ms_spec(a: u64, b: u64) -> u64 {
    if a as int + b as int > u64::MAX as int { u64::MAX } else { (a + b) as u64 }
}

/// The window an inbound frame of `proto` grants on a record the box has or
/// has not replied on.
pub open spec fn inbound_window(w: Windows, proto: u8, replied: bool) -> u64 {
    if proto == TCP {
        w.tcp_idle_ms
    } else if replied {
        w.udp_replied_ms
    } else {
        w.udp_unreplied_ms
    }
}

/// A record's value: 1 once the box has replied on it, 0 before.
pub open spec fn flag_of(replied: bool) -> u32 {
    if replied { 1u32 } else { 0u32 }
}

/// The key belongs to a UDP conversation.
pub open spec fn udp_key(key: u64) -> bool {
    key_of(UDP, 0, 0) <= key <= key_of(UDP, 0xffff, 0xffff)
}

/// An entry's value is 0; or 1, a UDP record the box has replied on or a TCP
/// record no side has closed that it has answered; or, on a TCP record,
/// which sides have closed.
pub open spec fn flag_ok(e: Entry) -> bool {
    e.value == 0 || e.value == 1
        || ((e.value == BOX_FIN || e.value == CLIENT_FIN || e.value == BOTH_FIN) && tcp_key(e.key))
}

pub open spec fn flags_ok(s: Seq<Entry>) -> bool {
    forall|j: int| 0 <= j < s.len() ==> flag_ok(#[trigger] s[j])
}

/// `s` holds a record for `(row, key)` that has not expired at `now_ms` and
/// whose value is `v`.
pub open spec fn live_with(s: Seq<Entry>, row: u32, key: u64, now_ms: u64, v: u32) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].row == row && s[j].key == key
        && s[j].deadline_ms > now_ms && s[j].value == v
}

/// The window a frame the box sends of `proto` grants.
pub open spec fn reply_window(w: Windows, proto: u8) -> u64 {
    if proto == TCP { w.tcp_idle_ms } else { w.udp_replied_ms }
}

/// No window is zero, and a reply never buys a shorter one.
pub open spec fn windows_ok(w: Windows) -> bool {
    w.tcp_idle_ms > 0 && w.udp_unreplied_ms > 0 && w.udp_replied_ms >= w.udp_unreplied_ms
        && w.tcp_closed_ms > 0 && w.tcp_closed_ms <= w.tcp_closing_ms && w.tcp_closing_ms <= w.tcp_idle_ms
        && (w.evict_after_ms is Some ==> 0 < w.evict_after_ms->0 <= w.tcp_idle_ms)
}

/// The window an open record was last given: by its protocol and, for UDP,
/// by whether the box has replied.
pub open spec fn open_window(w: Windows, e: Entry) -> u64 {
    if tcp_key(e.key) {
        w.tcp_idle_ms
    } else if e.value == 1 {
        w.udp_replied_ms
    } else {
        w.udp_unreplied_ms
    }
}

/// G6 (n): the class a record that has not expired may be given up in, 1
/// first; 5 is never.
pub open spec fn class_of(w: Windows, e: Entry, now_ms: u64) -> int {
    if tcp_key(e.key) && e.value == BOTH_FIN {
        1
    } else if tcp_key(e.key) && (e.value == BOX_FIN || e.value == CLIENT_FIN) {
        2
    } else if e.value == 0 {
        3
    } else if w.evict_after_ms is Some
        && e.deadline_ms as int + w.evict_after_ms->0 as int <= open_window(w, e) as int + now_ms as int {
        4
    } else {
        5
    }
}

/// `s[i]` is in a class, and is first among the first `k` entries by class,
/// then deadline, then position.
pub open spec fn best_in(s: Seq<Entry>, w: Windows, now_ms: u64, i: int, k: int) -> bool {
    &&& 0 <= i < k <= s.len()
    &&& class_of(w, s[i], now_ms) < 5
    &&& forall|j: int| 0 <= j < k ==> {
        ||| class_of(w, s[i], now_ms) < class_of(w, #[trigger] s[j], now_ms)
        ||| class_of(w, s[i], now_ms) == class_of(w, s[j], now_ms) && s[i].deadline_ms < s[j].deadline_ms
        ||| class_of(w, s[i], now_ms) == class_of(w, s[j], now_ms) && s[i].deadline_ms == s[j].deadline_ms && i <= j
    }
}

/// G6 (n): `s[i]` is the record a sweep gives up.
pub open spec fn victim_at(s: Seq<Entry>, w: Windows, now_ms: u64, i: int) -> bool {
    best_in(s, w, now_ms, i, s.len() as int)
}

/// None of the first `k` entries is in a class.
pub open spec fn none_evictable_in(s: Seq<Entry>, w: Windows, now_ms: u64, k: int) -> bool {
    forall|j: int| 0 <= j < k && j < s.len() ==> class_of(w, #[trigger] s[j], now_ms) == 5
}

/// No record is in a class.
pub open spec fn none_evictable(s: Seq<Entry>, w: Windows, now_ms: u64) -> bool {
    none_evictable_in(s, w, now_ms, s.len() as int)
}

/// `after` is `before` without the entry at position `i`, and with `e`:
/// every other entry is held as it was, nothing else is new, and the table
/// is as long as it was.
#[verifier::opaque]
pub open spec fn gave_up_and_added(after: Seq<Entry>, before: Seq<Entry>, i: int, e: Entry) -> bool {
    &&& 0 <= i < before.len()
    &&& has(after, e)
    &&& after.len() == before.len()
    &&& forall|j: int| 0 <= j < before.len() && j != i ==> has(after, #[trigger] before[j])
    &&& only_adds(after, before, e)
    &&& !holds(after, before[i].row, before[i].key)
}

/// G6 (q): `after` is `before` without its records closed by both sides, of
/// which it held one at least, and with `e`: every other entry is held as it
/// was and nothing else is new.
#[verifier::opaque]
pub open spec fn closed_gave_room(after: Seq<Entry>, before: Seq<Entry>, e: Entry) -> bool {
    &&& !none_valued(before, BOTH_FIN)
    &&& has(after, e)
    &&& after.len() <= before.len()
    &&& keeps_unvalued(after, before, BOTH_FIN)
    &&& only_adds(after, before, e)
    &&& none_valued(after, BOTH_FIN)
}

/// How an opening frame found room at the capacity: G6 (e), (n), (q). A
/// sweep was due and removed what had expired; or the records closed by both
/// sides went; or a sweep was due, nothing had expired, no record was closed
/// by both sides, and it gave up the one record (n) names.
pub open spec fn made_room(after: Seq<Entry>, before: Seq<Entry>, w: Windows, e: Entry, now_ms: u64, due: bool) -> bool {
    if due && !none_expired(before, now_ms) {
        swept_and_added(after, before, e, now_ms)
    } else if !none_valued(before, BOTH_FIN) {
        closed_gave_room(after, before, e)
    } else {
        due && w.evict_after_ms is Some
            && exists|i: int| victim_at(before, w, now_ms, i) && gave_up_and_added(after, before, i, e)
    }
}

/// Every entry of `before` that has not expired at `now_ms` and is not
/// closed by both sides is still in `now`.
pub open spec fn keeps_unclosed_live(now: Seq<Entry>, before: Seq<Entry>, now_ms: u64) -> bool {
    forall|k: int| 0 <= k < before.len() && before[k].deadline_ms > now_ms && before[k].value != BOTH_FIN
        ==> has(now, #[trigger] before[k])
}

pub closed spec fn pool_of(f: Flows) -> Slab { f.pool }
pub closed spec fn throttle_of(f: Flows) -> Throttle { f.throttle }
pub closed spec fn box_of(f: Flows) -> u32 { f.box_addr }
pub closed spec fn windows_of(f: Flows) -> Windows { f.windows }
pub closed spec fn mark_of(f: Flows) -> bool { f.may_hold_closed }

pub open spec fn table(f: Flows) -> Seq<Entry> { sview(pool_of(f)) }

/// The invariant every operation keeps: G7 on the table with no bound per
/// client below its capacity (one client may hold every record), windows in
/// order, every value a flag, and no record closed by both sides while the
/// mark is clear: G6 (r).
#[verifier::opaque]
pub open spec fn finv(f: Flows) -> bool {
    sinv(pool_of(f)) && squota(pool_of(f)) == scap(pool_of(f)) && windows_ok(windows_of(f))
        && flags_ok(table(f)) && (!mark_of(f) ==> none_valued(table(f), BOTH_FIN))
}

/// Nothing but the table's contents and the instant of its last sweep
/// changed.
pub open spec fn same_frame(now: Flows, before: Flows) -> bool {
    &&& box_of(now) == box_of(before)
    &&& windows_of(now) == windows_of(before)
    &&& scap(pool_of(now)) == scap(pool_of(before))
    &&& squota(pool_of(now)) == squota(pool_of(before))
    &&& throttle_of(now).interval_ms == throttle_of(before).interval_ms
}

/// The table has not swept since `before`.
pub open spec fn stamp_same(now: Flows, before: Flows) -> bool {
    throttle_of(now).last_ms == throttle_of(before).last_ms
}

/// The frame makes the table sweep: it would open a record the table does
/// not hold, the table is at its capacity, and a sweep is due.
pub open spec fn inbound_sweeps(before: Flows, c: Conversation, flags: u8, now_ms: u64) -> bool {
    &&& c.box_addr == box_of(before)
    &&& is_flow_proto(c.proto)
    &&& opening(c.proto, flags)
    &&& !holds(table(before), c.client, conv_key(c))
    &&& table(before).len() >= scap(pool_of(before))
    &&& due(throttle_of(before), now_ms)
}

/// G6 (k): the instant of the last sweep moves to `now_ms` exactly when the
/// frame makes the table sweep, whether or not the sweep found anything.
pub open spec fn inbound_stamp(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64) -> bool {
    throttle_of(after).last_ms == if inbound_sweeps(before, c, flags, now_ms) {
        Some(now_ms)
    } else {
        throttle_of(before).last_ms
    }
}

/// The frame makes the pass of G6 (q) run: it would open a record the table
/// does not hold, the table is at its capacity, no sweep that was due found
/// an expired record, and the mark is set.
pub open spec fn inbound_passes(before: Flows, c: Conversation, flags: u8, now_ms: u64) -> bool {
    &&& c.box_addr == box_of(before)
    &&& is_flow_proto(c.proto)
    &&& opening(c.proto, flags)
    &&& !holds(table(before), c.client, conv_key(c))
    &&& table(before).len() >= scap(pool_of(before))
    &&& !(due(throttle_of(before), now_ms) && !none_expired(table(before), now_ms))
    &&& mark_of(before)
}

/// G6 (r) for an inbound frame: the pass clears the mark and nothing else
/// here does; the mark is set only when the frame leaves its own record
/// live and closed by both sides.
pub open spec fn inbound_mark(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64) -> bool {
    &&& inbound_passes(before, c, flags, now_ms) ==> !mark_of(after)
    &&& !inbound_passes(before, c, flags, now_ms) && mark_of(before) ==> mark_of(after)
    &&& !mark_of(before) && mark_of(after)
        ==> c.proto == TCP && live_with(table(after), c.client, conv_key(c), now_ms, BOTH_FIN)
}

/// G6 (r) for a frame the box sends: it never clears the mark, and sets it
/// only when it leaves its own record live and closed by both sides.
pub open spec fn reply_mark(before: Flows, after: Flows, c: Conversation, now_ms: u64) -> bool {
    &&& mark_of(before) ==> mark_of(after)
    &&& !mark_of(before) && mark_of(after)
        ==> c.proto == TCP && live_with(table(after), c.client, conv_key(c), now_ms, BOTH_FIN)
}

/// The key is of a conversation of `proto` at the box's `port`.
pub open spec fn at_port(key: u64, proto: u8, port: u16) -> bool {
    key_ends(key, proto as u64, port as u64)
}

/// `now` is `before` without the records of `proto` at the box's `port`.
pub open spec fn port_ended(now: Seq<Entry>, before: Seq<Entry>, proto: u8, port: u16) -> bool {
    &&& subset_of(now, before)
    &&& keeps_unmatched(now, before, proto as u64, port as u64)
    &&& none_ending(now, proto as u64, port as u64)
}

/// A conversation's key is at a port exactly when its protocol and box port
/// are that protocol and port, whatever its client port.
pub proof fn lemma_at_port_key(p: u8, cp: u16, bp: u16, proto: u8, port: u16)
    ensures
        at_port(key_of(p, cp, bp), proto, port) == (p == proto && bp == port),
{
}

/// G6 (j): after a port is ended the table holds no record of it, for any
/// client and client port.
pub proof fn theorem_g6j_ended_port_holds_no_record(now: Seq<Entry>, before: Seq<Entry>, proto: u8, port: u16, client: u32, cp: u16)
    requires
        port_ended(now, before, proto, port),
    ensures
        !holds(now, client, key_of(proto, cp, port)),
{
    lemma_at_port_key(proto, cp, port, proto, port);
    assert forall|j: int| 0 <= j < now.len() implies !(now[j].row == client && now[j].key == key_of(proto, cp, port)) by {
        assert(!key_ends(now[j].key, proto as u64, port as u64));
    }
}

/// G6 (j): a record of another protocol or another box port stays.
pub proof fn theorem_g6j_other_records_stay(now: Seq<Entry>, before: Seq<Entry>, proto: u8, port: u16, x: Entry, p: u8, cp: u16, bp: u16)
    requires
        port_ended(now, before, proto, port),
        has(before, x),
        x.key == key_of(p, cp, bp),
        !(p == proto && bp == port),
    ensures
        has(now, x),
{
    lemma_at_port_key(p, cp, bp, proto, port);
    let k = choose|k: int| 0 <= k < before.len() && before[k] == x;
    assert(!key_ends(before[k].key, proto as u64, port as u64));
}

/// K1.
pub proof fn lemma_key_injective(p1: u8, c1: u16, b1: u16, p2: u8, c2: u16, b2: u16)
    requires
        key_of(p1, c1, b1) == key_of(p2, c2, b2),
    ensures
        p1 == p2 && c1 == c2 && b1 == b2,
{
}

pub proof fn lemma_same_no_new_keys(s: Seq<Entry>)
    ensures
        no_new_keys(s, s),
{
    assert forall|j: int| 0 <= j < s.len() implies holds(s, (#[trigger] s[j]).row, s[j].key) by {
        assert(s[j].row == s[j].row && s[j].key == s[j].key);
    }
}

pub proof fn lemma_subset_no_new_keys(now: Seq<Entry>, before: Seq<Entry>)
    requires
        subset_of(now, before),
    ensures
        no_new_keys(now, before),
{
    assert forall|j: int| 0 <= j < now.len() implies holds(before, (#[trigger] now[j]).row, now[j].key) by {
        assert(has(before, now[j]));
        let k = choose|k: int| 0 <= k < before.len() && before[k] == now[j];
        assert(before[k].row == now[j].row && before[k].key == now[j].key);
    }
}

pub proof fn lemma_refreshed_no_new_keys(now: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64)
    requires
        refreshed_from(now, before, row, key),
    ensures
        no_new_keys(now, before),
{
    assert forall|j: int| 0 <= j < now.len() implies holds(before, (#[trigger] now[j]).row, now[j].key) by {
        assert(before[j].row == now[j].row && before[j].key == now[j].key);
    }
}

/// An entry of the table that has not expired makes its row and key live.
pub proof fn lemma_has_live(s: Seq<Entry>, e: Entry, now_ms: u64)
    requires
        has(s, e),
        e.deadline_ms > now_ms,
    ensures
        live(s, e.row, e.key, now_ms),
        holds(s, e.row, e.key),
{
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].row == e.row && s[k].key == e.key && s[k].deadline_ms > now_ms);
}

/// Keys are distinct, so an expired entry is the only one for its row and key.
pub proof fn lemma_expired_not_live(s: Seq<Entry>, e: Entry, now_ms: u64)
    requires
        distinct_keys(s),
        has(s, e),
        e.deadline_ms <= now_ms,
    ensures
        !live(s, e.row, e.key, now_ms),
        holds(s, e.row, e.key),
{
    reveal(crate::pool::distinct_keys);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].row == e.row && s[k].key == e.key);
    if live(s, e.row, e.key, now_ms) {
        let j = choose|j: int|
            0 <= j < s.len() && s[j].row == e.row && s[j].key == e.key && s[j].deadline_ms > now_ms;
        if j < k {
            assert(!(s[j].row == s[k].row && s[j].key == s[k].key));
        } else if k < j {
            assert(!(s[k].row == s[j].row && s[k].key == s[j].key));
        }
    }
}

/// A row and key the table does not hold is not live.
pub proof fn lemma_not_held_not_live(s: Seq<Entry>, row: u32, key: u64, now_ms: u64)
    requires
        !holds(s, row, key),
    ensures
        !live(s, row, key, now_ms),
{
    if live(s, row, key, now_ms) {
        let j = choose|j: int|
            0 <= j < s.len() && s[j].row == row && s[j].key == key && s[j].deadline_ms > now_ms;
        assert(s[j].row == row && s[j].key == key);
    }
}

/// An unexpired entry is live with its own value.
pub proof fn lemma_has_live_with(s: Seq<Entry>, e: Entry, now_ms: u64)
    requires
        has(s, e),
        e.deadline_ms > now_ms,
    ensures
        live_with(s, e.row, e.key, now_ms, e.value),
{
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].row == e.row && s[k].key == e.key && s[k].deadline_ms > now_ms && s[k].value == e.value);
}

/// An entry of a table whose values are flags carries a flag.
pub proof fn lemma_flag_of_entry(s: Seq<Entry>, e: Entry)
    requires
        flags_ok(s),
        has(s, e),
    ensures
        flag_ok(e),
{
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(flag_ok(s[k]));
}

pub proof fn lemma_flags_subset(now: Seq<Entry>, before: Seq<Entry>)
    requires
        flags_ok(before),
        subset_of(now, before),
    ensures
        flags_ok(now),
{
    assert forall|j: int| 0 <= j < now.len() implies flag_ok(#[trigger] now[j]) by {
        assert(has(before, now[j]));
        lemma_flag_of_entry(before, now[j]);
    }
}

pub proof fn lemma_flags_changed(now: Seq<Entry>, before: Seq<Entry>, e: Entry)
    requires
        flags_ok(before),
        changed_only_to(now, before, e),
        flag_ok(e),
    ensures
        flags_ok(now),
{
    assert forall|j: int| 0 <= j < now.len() implies flag_ok(#[trigger] now[j]) by {
        if now[j] != e {
            assert(now[j] == before[j]);
            assert(flag_ok(before[j]));
        }
    }
}

pub proof fn lemma_flags_adds(now: Seq<Entry>, before: Seq<Entry>, e: Entry)
    requires
        flags_ok(before),
        only_adds(now, before, e),
        flag_ok(e),
    ensures
        flags_ok(now),
{
    assert forall|j: int| 0 <= j < now.len() implies flag_ok(#[trigger] now[j]) by {
        if now[j] != e {
            assert(has(before, now[j]));
            lemma_flag_of_entry(before, now[j]);
        }
    }
}

/// A TCP conversation's key is a TCP key and not a UDP one.
/// A table that holds no entry with `v` holds none after losing entries.
pub proof fn lemma_valued_subset(now: Seq<Entry>, before: Seq<Entry>, v: u32)
    requires
        none_valued(before, v),
        subset_of(now, before),
    ensures
        none_valued(now, v),
{
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).value != v by {
        assert(has(before, now[j]));
    }
}

/// Nor after one entry became `e`, whose value is another.
pub proof fn lemma_valued_changed(now: Seq<Entry>, before: Seq<Entry>, e: Entry, v: u32)
    requires
        none_valued(before, v),
        changed_only_to(now, before, e),
        e.value != v,
    ensures
        none_valued(now, v),
{
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).value != v by {
        if now[j] != e {
            assert(now[j] == before[j]);
        }
    }
}

/// Nor after gaining `e`, whose value is another.
pub proof fn lemma_valued_adds(now: Seq<Entry>, before: Seq<Entry>, e: Entry, v: u32)
    requires
        none_valued(before, v),
        only_adds(now, before, e),
        e.value != v,
    ensures
        none_valued(now, v),
{
    assert forall|j: int| 0 <= j < now.len() implies (#[trigger] now[j]).value != v by {
        if now[j] != e {
            assert(has(before, now[j]));
        }
    }
}

proof fn lemma_tcp_conv_key(c: Conversation)
    requires
        c.proto == TCP,
    ensures
        tcp_key(conv_key(c)),
        !udp_key(conv_key(c)),
{
}

/// A live record is the only one for its row and key, so the table is live
/// with a value exactly when the record carries it.
proof fn lemma_live_with_only(s: Seq<Entry>, e: Entry, now_ms: u64, v: u32)
    requires
        distinct_keys(s),
        has(s, e),
        e.deadline_ms > now_ms,
    ensures
        live_with(s, e.row, e.key, now_ms, v) == (e.value == v),
{
    if live_with(s, e.row, e.key, now_ms, v) {
        let j = choose|j: int| 0 <= j < s.len() && s[j].row == e.row && s[j].key == e.key
            && s[j].deadline_ms > now_ms && s[j].value == v;
        crate::pool::lemma_only_entry(s, e, j);
    }
    if e.value == v {
        lemma_has_live_with(s, e, now_ms);
    }
}

/// What a TCP segment makes of a live record of a TCP key: a flag, still
/// live, and, without FIN on a record no side has closed, the idle refresh.
proof fn lemma_tcp_after(w: Windows, e: Entry, flags: u8, from_box: bool, now_ms: u64)
    requires
        windows_ok(w),
        flag_ok(e),
        tcp_key(e.key),
        !udp_key(e.key),
        e.deadline_ms > now_ms,
    ensures
        flag_ok(tcp_after(w, e, flags, from_box, now_ms)),
        tcp_after(w, e, flags, from_box, now_ms).deadline_ms > now_ms,
        flags & FIN == 0 && flags & RST == 0 && open_value(e.value) ==> tcp_after(w, e, flags, from_box, now_ms) == (Entry {
            row: e.row,
            key: e.key,
            deadline_ms: later_spec(e.deadline_ms, add_ms_spec(now_ms, w.tcp_idle_ms)),
            value: if from_box { ANSWERED } else { e.value },
        }),
{
}

/// The segment's record became what the segment makes of it, and keys are
/// distinct, so every entry for its row and key did.
proof fn lemma_tcp_stepped(
    now: Seq<Entry>,
    before: Seq<Entry>,
    w: Windows,
    e: Entry,
    flags: u8,
    from_box: bool,
    now_ms: u64,
)
    requires
        distinct_keys(before),
        has(before, e),
        has(now, tcp_after(w, e, flags, from_box, now_ms)),
    ensures
        tcp_stepped(now, before, w, e.row, e.key, flags, from_box, now_ms),
{
    reveal(tcp_stepped);
    assert forall|j: int| 0 <= j < before.len() && (#[trigger] before[j]).row == e.row
        && before[j].key == e.key
        implies has(now, tcp_after(w, before[j], flags, from_box, now_ms)) by {
        crate::pool::lemma_only_entry(before, e, j);
    }
}

/// `inbound` on a live record: a UDP record extended to the later of its
/// deadline and the window its flag buys, a TCP record stepped by the
/// segment.
proof fn lemma_inbound_refreshed(
    b: Flows,
    a: Flows,
    c: Conversation,
    flags: u8,
    now_ms: u64,
    e: Entry,
    window: u64,
    fresh: u64,
    deadline: u64,
    value: u32,
)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a).interval_ms == throttle_of(b).interval_ms,
        c.box_addr == box_of(b),
        is_flow_proto(c.proto),
        !(c.proto == TCP && flags & RST != 0),
        has(table(b), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.deadline_ms > now_ms,
        window == (if c.proto == TCP { windows_of(b).tcp_idle_ms } else { windows_of(b).udp_unreplied_ms }),
        fresh == (if c.proto == UDP && e.value == 1 { add_ms_spec(now_ms, windows_of(b).udp_replied_ms) } else { add_ms_spec(now_ms, window) }),
        c.proto == UDP ==> value == e.value && deadline == later_spec(e.deadline_ms, fresh),
        c.proto == TCP ==> value == tcp_value(e.value, flags, false)
            && deadline == tcp_deadline(windows_of(b), e.deadline_ms, e.value, value, now_ms),
        refreshed_from(table(a), table(b), c.client, conv_key(c)),
        changed_only_to(table(a), table(b),
            Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        mark_of(a) == (mark_of(b) || value == BOTH_FIN),
    ensures
        finv(a),
        same_frame(a, b),
        inbound_post(b, a, c, flags, now_ms, Inbound::Refreshed { replied: c.proto == UDP && e.value == 1 }),
        inbound_mark(b, a, c, flags, now_ms),
{
    reveal(finv);
    if value == BOTH_FIN {
        let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
        lemma_has_live_with(table(a), is, now_ms);
    }
    if !mark_of(a) {
        lemma_valued_changed(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }, BOTH_FIN);
    }
    reveal(crate::pool::extended);
    let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
    lemma_has_live(table(b), e, now_ms);
    lemma_live_with_only(table(b), e, now_ms, 1);
    lemma_live_with_only(table(b), e, now_ms, 0);
    lemma_flag_of_entry(table(b), e);
    if c.proto == TCP {
        lemma_tcp_conv_key(c);
        lemma_tcp_after(windows_of(b), e, flags, false, now_ms);
        assert(is == tcp_after(windows_of(b), e, flags, false, now_ms));
        lemma_tcp_stepped(table(a), table(b), windows_of(b), e, flags, false, now_ms);
    }
    lemma_flags_changed(table(a), table(b), is);
    lemma_has_live(table(a), is, now_ms);
    if stays_open(table(b), c.client, conv_key(c), c.proto, flags, now_ms) {
        reveal(open_refresh);
        lemma_refresh_not_shortened(table(a), table(b), e, is);
        lemma_refresh_bounded(table(a), table(b), e, is, fresh);
    }
}

/// `inbound` on a live record of a TCP conversation, by a reset: the record
/// is stepped to closed by both, and nothing else changes.
proof fn lemma_inbound_reset(
    b: Flows,
    a: Flows,
    c: Conversation,
    flags: u8,
    now_ms: u64,
    e: Entry,
    deadline: u64,
    value: u32,
)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a).interval_ms == throttle_of(b).interval_ms,
        c.box_addr == box_of(b),
        c.proto == TCP,
        flags & RST != 0,
        has(table(b), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.deadline_ms > now_ms,
        value == tcp_value(e.value, flags, false),
        deadline == tcp_deadline(windows_of(b), e.deadline_ms, e.value, value, now_ms),
        refreshed_from(table(a), table(b), c.client, conv_key(c)),
        changed_only_to(table(a), table(b),
            Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        mark_of(a) == (mark_of(b) || value == BOTH_FIN),
    ensures
        finv(a),
        same_frame(a, b),
        inbound_post(b, a, c, flags, now_ms, Inbound::Ended),
        inbound_mark(b, a, c, flags, now_ms),
{
    reveal(finv);
    if value == BOTH_FIN {
        let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
        lemma_has_live_with(table(a), is, now_ms);
    }
    if !mark_of(a) {
        lemma_valued_changed(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }, BOTH_FIN);
    }
    let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
    lemma_has_live(table(b), e, now_ms);
    lemma_flag_of_entry(table(b), e);
    lemma_tcp_conv_key(c);
    lemma_tcp_after(windows_of(b), e, flags, false, now_ms);
    assert(is == tcp_after(windows_of(b), e, flags, false, now_ms));
    lemma_tcp_stepped(table(a), table(b), windows_of(b), e, flags, false, now_ms);
    lemma_flags_changed(table(a), table(b), is);
    lemma_has_live(table(a), is, now_ms);
}

/// `reply` refusing: the frame's own record was not live, and the table is
/// as `missed` says.
proof fn lemma_reply_refused(b: Flows, a: Flows, c: Conversation, flags: u8, now_ms: u64)
    requires
        same_frame(a, b),
        stamp_same(a, b),
        !(c.box_addr == box_of(b) && is_flow_proto(c.proto)
            && live(table(b), c.client, conv_key(c), now_ms)),
        no_new_keys(table(a), table(b)),
        missed(a, b, c, now_ms),
    ensures
        reply_post(b, a, c, flags, now_ms, false),
{
    reveal(reply_post);
}

/// `reply` on a live UDP record: it is marked and extended by the replied
/// window.
proof fn lemma_reply_refreshed_udp(
    b: Flows,
    a: Flows,
    c: Conversation,
    flags: u8,
    now_ms: u64,
    e: Entry,
    deadline: u64,
    value: u32,
)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a) == throttle_of(b),
        c.box_addr == box_of(b),
        c.proto == UDP,
        has(table(b), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.deadline_ms > now_ms,
        value == 1,
        deadline == later_spec(e.deadline_ms, add_ms_spec(now_ms, windows_of(b).udp_replied_ms)),
        refreshed_from(table(a), table(b), c.client, conv_key(c)),
        changed_only_to(table(a), table(b),
            Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        mark_of(a) == (mark_of(b) || value == BOTH_FIN),
    ensures
        finv(a),
        reply_post(b, a, c, flags, now_ms, true),
        reply_mark(b, a, c, now_ms),
{
    reveal(reply_post);
    reveal(finv);
    if !mark_of(a) {
        lemma_valued_changed(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }, BOTH_FIN);
    }
    reveal(open_refresh);
    reveal(crate::pool::extended);
    let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
    let limit = add_ms_spec(now_ms, windows_of(b).udp_replied_ms);
    lemma_has_live(table(b), e, now_ms);
    lemma_flags_changed(table(a), table(b), is);
    lemma_refreshed_no_new_keys(table(a), table(b), c.client, conv_key(c));
    lemma_has_live(table(a), is, now_ms);
    lemma_refresh_not_shortened(table(a), table(b), e, is);
    lemma_refresh_bounded(table(a), table(b), e, is, limit);
    // The record this reply leaves is live: G6 (r).
    if value == BOTH_FIN {
        let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
        lemma_has_live_with(table(a), is, now_ms);
    }
}

/// `reply` on a live TCP record: the record is stepped by the segment, and
/// refreshed by the idle window when no side has closed.
proof fn lemma_reply_refreshed_tcp(
    b: Flows,
    a: Flows,
    c: Conversation,
    flags: u8,
    now_ms: u64,
    e: Entry,
    deadline: u64,
    value: u32,
)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a) == throttle_of(b),
        c.box_addr == box_of(b),
        c.proto == TCP,
        has(table(b), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.deadline_ms > now_ms,
        value == tcp_value(e.value, flags, true),
        deadline == tcp_deadline(windows_of(b), e.deadline_ms, e.value, value, now_ms),
        refreshed_from(table(a), table(b), c.client, conv_key(c)),
        changed_only_to(table(a), table(b),
            Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }),
        mark_of(a) == (mark_of(b) || value == BOTH_FIN),
    ensures
        finv(a),
        reply_post(b, a, c, flags, now_ms, true),
        reply_mark(b, a, c, now_ms),
{
    reveal(reply_post);
    reveal(finv);
    if !mark_of(a) {
        lemma_valued_changed(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value }, BOTH_FIN);
    }
    let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
    lemma_has_live(table(b), e, now_ms);
    lemma_flag_of_entry(table(b), e);
    lemma_tcp_conv_key(c);
    lemma_tcp_after(windows_of(b), e, flags, true, now_ms);
    assert(is == tcp_after(windows_of(b), e, flags, true, now_ms));
    lemma_tcp_stepped(table(a), table(b), windows_of(b), e, flags, true, now_ms);
    lemma_flags_changed(table(a), table(b), is);
    lemma_refreshed_no_new_keys(table(a), table(b), c.client, conv_key(c));
    lemma_has_live(table(a), is, now_ms);
    if stays_open(table(b), c.client, conv_key(c), c.proto, flags, now_ms) {
        reveal(open_refresh);
        reveal(crate::pool::extended);
        let limit = add_ms_spec(now_ms, windows_of(b).tcp_idle_ms);
        // The open record is `e`, unanswered or answered; either way the box's
        // segment leaves it answered.
        lemma_live_with_only(table(b), e, now_ms, 0);
        lemma_live_with_only(table(b), e, now_ms, ANSWERED);
        lemma_refresh_not_shortened(table(a), table(b), e, is);
        lemma_refresh_bounded(table(a), table(b), e, is, limit);
    }
    // The record this reply leaves is live: G6 (r).
    if value == BOTH_FIN {
        let is = Entry { row: c.client, key: conv_key(c), deadline_ms: deadline, value };
        lemma_has_live_with(table(a), is, now_ms);
    }
}

/// `inbound` opening on an expired record of the same conversation: it is
/// reopened in place as a new record.
proof fn lemma_inbound_reopened(b: Flows, a: Flows, c: Conversation, flags: u8, now_ms: u64, e: Entry, window: u64, fresh: u64)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a).interval_ms == throttle_of(b).interval_ms,
        c.box_addr == box_of(b),
        is_flow_proto(c.proto),
        opening(c.proto, flags),
        has(table(b), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.deadline_ms <= now_ms,
        window == (if c.proto == TCP { windows_of(b).tcp_idle_ms } else { windows_of(b).udp_unreplied_ms }),
        fresh == add_ms_spec(now_ms, window),
        refreshed_from(table(a), table(b), c.client, conv_key(c)),
        changed_only_to(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        mark_of(a) == mark_of(b),
    ensures
        finv(a),
        same_frame(a, b),
        inbound_post(b, a, c, flags, now_ms, Inbound::Opened),
{
    reveal(finv);
    let is = Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 };
    if !mark_of(a) {
        lemma_valued_changed(table(a), table(b), is, BOTH_FIN);
    }
    lemma_expired_not_live(table(b), e, now_ms);
    lemma_flags_changed(table(a), table(b), is);
    lemma_refresh_not_shortened(table(a), table(b), e, is);
    if now_ms < u64::MAX {
        lemma_has_live(table(a), is, now_ms);
    }
}

/// After a record is given up at the capacity, the table has room for one
/// more, the opening's key is not held, and its row is under its quota (the
/// quota is the capacity).
proof fn lemma_room_after_give_up(before: Seq<Entry>, mid: Seq<Entry>, cap: int, quota: int, row: u32, key: u64)
    requires
        before.len() <= cap,
        quota == cap,
        mid.len() + 1 == before.len(),
        subset_of(mid, before),
        !holds(before, row, key),
    ensures
        mid.len() < cap,
        !holds(mid, row, key),
        crate::pool::count(mid, row) < quota,
{
    crate::sweep::lemma_subset_not_held(before, mid, row, key);
    crate::pool::lemma_count_le_len(mid, row);
}

/// `inbound` opening a conversation no record holds: a new record is added.
proof fn lemma_inbound_inserted(b: Flows, a: Flows, c: Conversation, flags: u8, now_ms: u64, window: u64, fresh: u64)
    requires
        finv(b),
        sinv(pool_of(a)),
        box_of(a) == box_of(b),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        throttle_of(a).interval_ms == throttle_of(b).interval_ms,
        c.box_addr == box_of(b),
        is_flow_proto(c.proto),
        opening(c.proto, flags),
        !holds(table(b), c.client, conv_key(c)),
        window == (if c.proto == TCP { windows_of(b).tcp_idle_ms } else { windows_of(b).udp_unreplied_ms }),
        fresh == add_ms_spec(now_ms, window),
        has(table(a), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        only_adds(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        keeps_live(table(a), table(b), now_ms),
        table(a).len() <= table(b).len() + 1,
        table(b).len() < scap(pool_of(b)) ==> crate::pool::added(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        table(b).len() >= scap(pool_of(b)) ==> due(throttle_of(b), now_ms) && !none_expired(table(b), now_ms)
            && swept_and_added(table(a), table(b), Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }, now_ms),
        mark_of(a) == mark_of(b),
    ensures
        finv(a),
        same_frame(a, b),
        inbound_post(b, a, c, flags, now_ms, Inbound::Opened),
{
    reveal(finv);
    let added = Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 };
    if !mark_of(a) {
        lemma_valued_adds(table(a), table(b), added, BOTH_FIN);
    }
    lemma_not_held_not_live(table(b), c.client, conv_key(c), now_ms);
    lemma_flags_adds(table(a), table(b), added);
    if now_ms < u64::MAX {
        lemma_has_live(table(a), added, now_ms);
    }
}

/// `give_up_and_open`'s step: the record at `i`, which `victim` named, was
/// removed (`mid`) and the new one added in its room.
proof fn lemma_gave_up(
    b: Flows,
    mid: Seq<Entry>,
    a: Flows,
    c: Conversation,
    now_ms: u64,
    fresh: u64,
    i: int,
)
    requires
        finv(b),
        sinv(pool_of(a)),
        windows_of(a) == windows_of(b),
        scap(pool_of(a)) == scap(pool_of(b)),
        squota(pool_of(a)) == squota(pool_of(b)),
        !holds(table(b), c.client, conv_key(c)),
        victim_at(table(b), windows_of(b), now_ms, i),
        // What the removal left.
        !holds(mid, table(b)[i].row, table(b)[i].key),
        subset_of(mid, table(b)),
        mid.len() + 1 == table(b).len(),
        keeps_others(mid, table(b), table(b)[i].row, table(b)[i].key),
        // What the insert made of it.
        crate::pool::added(table(a), mid, Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
        mark_of(a) == mark_of(b),
    ensures
        finv(a),
        gave_up_and_added(table(a), table(b), i,
            Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }),
{
    reveal(finv);
    reveal(gave_up_and_added);
    reveal(crate::pool::added);
    let s = table(b);
    let t = table(a);
    let e = Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 };
    let gone = s[i];
    // Every entry the table now holds is `e` or one it held before.
    assert forall|j: int| 0 <= j < t.len() implies has(s, #[trigger] t[j]) || t[j] == e by {
        if t[j] != e {
            assert(has(mid, t[j]));
            let k = choose|k: int| 0 <= k < mid.len() && mid[k] == t[j];
            assert(has(s, mid[k]));
        }
    }
    if !mark_of(a) {
        lemma_valued_adds(t, s, e, BOTH_FIN);
    }
    // Every entry but the one given up is still held: keys are distinct.
    assert forall|j: int| 0 <= j < s.len() && j != i implies has(t, #[trigger] s[j]) by {
        reveal(crate::pool::distinct_keys);
        if j < i {
            assert(!(s[j].row == s[i].row && s[j].key == s[i].key));
        } else {
            assert(!(s[i].row == s[j].row && s[i].key == s[j].key));
        }
        assert(has(mid, s[j]));
        let k = choose|k: int| 0 <= k < mid.len() && mid[k] == s[j];
        assert(has(t, mid[k]));
    }
    // The record given up is not held: `e` is another conversation's, and
    // what the removal left did not hold it.
    if holds(t, gone.row, gone.key) {
        let j = choose|j: int| 0 <= j < t.len() && t[j].row == gone.row && t[j].key == gone.key;
        if t[j] == e {
            assert(s[i].row == c.client && s[i].key == conv_key(c));
        } else {
            assert(has(mid, t[j]));
            let k = choose|k: int| 0 <= k < mid.len() && mid[k] == t[j];
            assert(mid[k].row == gone.row && mid[k].key == gone.key);
        }
    }
    assert(gave_up_and_added(t, s, i, e));
    // Every value is a flag: `e`'s is 0, and the rest were held before.
    assert forall|j: int| 0 <= j < t.len() implies flag_ok(#[trigger] t[j]) by {
        if t[j] != e {
            assert(has(s, t[j]));
            lemma_flag_of_entry(s, t[j]);
        }
    }
}

/// The pass removed the records closed by both sides from `table(b)`,
/// leaving `mid`, and the insert added `e` to that: the room came from the
/// closed records, and the invariant holds with the mark clear.
proof fn lemma_room_from_closed(b: Flows, mid: Seq<Entry>, a: Flows, e: Entry)
    requires
        finv(b),
        sinv(pool_of(a)),
        squota(pool_of(a)) == scap(pool_of(a)),
        windows_of(a) == windows_of(b),
        !mark_of(a),
        e.value == 0,
        !none_valued(table(b), BOTH_FIN),
        mid.len() < table(b).len(),
        subset_of(mid, table(b)),
        keeps_unvalued(mid, table(b), BOTH_FIN),
        none_valued(mid, BOTH_FIN),
        crate::pool::added(table(a), mid, e),
    ensures
        finv(a),
        closed_gave_room(table(a), table(b), e),
{
    reveal(finv);
    reveal(closed_gave_room);
    reveal(crate::pool::added);
    let s = table(b);
    let t = table(a);
    assert forall|j: int| 0 <= j < t.len() implies has(s, #[trigger] t[j]) || t[j] == e by {
        if t[j] != e {
            assert(has(mid, t[j]));
            let k = choose|k: int| 0 <= k < mid.len() && mid[k] == t[j];
            assert(has(s, mid[k]));
        }
    }
    assert forall|k: int| 0 <= k < s.len() && s[k].value != BOTH_FIN
        implies has(t, #[trigger] s[k]) by {
        assert(has(mid, s[k]));
        let j = choose|j: int| 0 <= j < mid.len() && mid[j] == s[k];
        assert(has(t, mid[j]));
    }
    lemma_valued_adds(t, mid, e, BOTH_FIN);
    assert(closed_gave_room(t, s, e));
    assert forall|j: int| 0 <= j < t.len() implies flag_ok(#[trigger] t[j]) by {
        if t[j] != e {
            assert(has(s, t[j]));
            lemma_flag_of_entry(s, t[j]);
        }
    }
}

/// What `open_at_capacity` did, read against the table as `open_new` found
/// it: the record G6 (e), (n), (q) say an opening frame at the capacity gets,
/// the instant of the last sweep, and the mark.
proof fn lemma_inbound_at_capacity(
    b: Flows,
    a: Flows,
    c: Conversation,
    flags: u8,
    now_ms: u64,
    fresh: u64,
    throttled: bool,
    r: Inbound,
)
    requires
        finv(b),
        finv(a),
        same_frame(a, b),
        c.box_addr == box_of(b),
        is_flow_proto(c.proto),
        opening(c.proto, flags),
        !holds(table(b), c.client, conv_key(c)),
        table(b).len() >= scap(pool_of(b)),
        fresh == add_ms_spec(now_ms, inbound_window(windows_of(b), c.proto, false)),
        throttled == !due(throttle_of(b), now_ms),
        !throttled ==> none_expired(table(b), now_ms),
        throttle_of(a).last_ms == (if throttled { throttle_of(b).last_ms } else { Some(now_ms) }),
        !mark_of(a),
        r == Inbound::Opened || r == Inbound::TableFull,
        r == Inbound::Opened ==> (mark_of(b) && closed_gave_room(table(a), table(b),
            Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 }))
            || (none_valued(table(b), BOTH_FIN) && !throttled
                && windows_of(b).evict_after_ms is Some
                && exists|i: int| victim_at(table(b), windows_of(b), now_ms, i)
                    && gave_up_and_added(table(a), table(b), i,
                        Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 })),
        r == Inbound::TableFull ==> table(a) == table(b) && none_valued(table(b), BOTH_FIN)
            && (!throttled && windows_of(b).evict_after_ms is Some
                ==> none_evictable(table(b), windows_of(b), now_ms)),
    ensures
        inbound_post(b, a, c, flags, now_ms, r),
        inbound_stamp(b, a, c, flags, now_ms),
        inbound_mark(b, a, c, flags, now_ms),
{
    reveal(finv);
    lemma_not_held_not_live(table(b), c.client, conv_key(c), now_ms);
    if r == Inbound::Opened {
        let e = Entry { row: c.client, key: conv_key(c), deadline_ms: fresh, value: 0 };
        if mark_of(b) && closed_gave_room(table(a), table(b), e) {
            reveal(closed_gave_room);
        } else {
            reveal(gave_up_and_added);
        }
        if now_ms < u64::MAX {
            lemma_has_live(table(a), e, now_ms);
        }
    }
}

/// `has_live`'s answer: the pool's `live` for the conversation's row and key
/// is the table's.
proof fn lemma_has_live_reads(f: Flows, c: Conversation, now_ms: u64)
    ensures
        live(sview(pool_of(f)), c.client, key_of(c.proto, c.client_port, c.box_port), now_ms)
            == live(table(f), c.client, conv_key(c), now_ms),
{
}

/// G6 (h): from `inbound`'s guarantee alone, a TCP record is never reported
/// as replied.
pub proof fn theorem_g6h_tcp_is_never_replied(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, replied: bool)
    requires
        inbound_post(before, after, c, flags, now_ms, Inbound::Refreshed { replied }),
        c.proto == TCP,
    ensures
        !replied,
{
}

/// G6 (f): from `inbound`'s guarantee alone, a datagram on a record the box
/// has not replied on never buys the replied window. `e` is the record.
pub proof fn theorem_g6f_unreplied_window(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, replied: bool, e: Entry)
    requires
        finv(before),
        inbound_post(before, after, c, flags, now_ms, Inbound::Refreshed { replied }),
        has(table(before), e),
        e.row == c.client,
        e.key == conv_key(c),
    ensures
        replied == (c.proto == UDP && e.value == 1),
        c.proto == UDP && e.value == 0 ==> bounded_by(table(after), table(before),
            add_ms_spec(now_ms, windows_of(before).udp_unreplied_ms)),
        c.proto == UDP && e.value == 1 ==> crate::pool::extended(table(after), table(before), c.client, conv_key(c),
            add_ms_spec(now_ms, windows_of(before).udp_replied_ms), None),
{
    reveal(finv);
    let s = table(before);
    let j = choose|j: int| 0 <= j < s.len() && s[j].row == c.client && s[j].key == conv_key(c)
        && s[j].deadline_ms > now_ms;
    crate::pool::lemma_only_entry(s, e, j);
    lemma_live_with_only(s, e, now_ms, 1);
    reveal(open_refresh);
}

/// G6 (c): a FIN marks its side's close, and both once the other side has
/// closed too.
pub proof fn theorem_g6c_fin_marks(v: u32, flags: u8)
    requires
        v == 0 || v == ANSWERED || v == BOX_FIN || v == CLIENT_FIN || v == BOTH_FIN,
        flags & FIN != 0,
        flags & RST == 0,
    ensures
        tcp_value(v, flags, true) == BOX_FIN || tcp_value(v, flags, true) == BOTH_FIN,
        (tcp_value(v, flags, true) == BOTH_FIN) == (v == CLIENT_FIN || v == BOTH_FIN),
        // The client's FIN, unless the segment is an opening packet.
        !(flags & SYN != 0 && flags & ACK == 0) ==> {
            &&& tcp_value(v, flags, false) == CLIENT_FIN || tcp_value(v, flags, false) == BOTH_FIN
            &&& (tcp_value(v, flags, false) == BOTH_FIN) == (v == BOX_FIN || v == BOTH_FIN)
        },
{
}

/// G6 (c), (h): an opening packet from the client leaves an open record: as
/// it was if it was open, and unanswered if a side had closed; a segment
/// from the box without FIN marks an unanswered open record answered and
/// changes no other value; and a segment from the client that neither opens
/// nor carries FIN leaves the value as it was. All of a segment that is not
/// a reset.
pub proof fn theorem_g6c_reopens(v: u32, flags: u8)
    requires
        flags & RST == 0,
    ensures
        flags & SYN != 0 && flags & ACK == 0 ==> tcp_value(v, flags, false) == (if open_value(v) { v } else { 0 }),
        flags & FIN == 0 ==> tcp_value(v, flags, true) == (if v == 0 { ANSWERED } else { v }),
        flags & FIN == 0 && !(flags & SYN != 0 && flags & ACK == 0) ==> tcp_value(v, flags, false) == v,
{
}

/// G6 (h): no segment from the client marks a record answered.
pub proof fn theorem_g6h_only_the_box_answers(v: u32, flags: u8)
    requires
        v != ANSWERED,
    ensures
        tcp_value(v, flags, false) != ANSWERED,
{
}

/// G6 (n), the floor: a record the box has answered, that no side has
/// closed, whose deadline is more than its window less `evict_after` ahead
/// of `now_ms`, is in no class; and with `evict_after` unset no answered
/// open record is.
pub proof fn theorem_g6n_floor(w: Windows, e: Entry, now_ms: u64)
    requires
        e.value == 1,
    ensures
        w.evict_after_ms is None ==> class_of(w, e, now_ms) == 5,
        w.evict_after_ms is Some
            && e.deadline_ms as int + w.evict_after_ms->0 as int > open_window(w, e) as int + now_ms as int
            ==> class_of(w, e, now_ms) == 5,
{
}

/// G6 (n), the floor in the frame's own terms: a segment from the box
/// without FIN or RST on an open TCP record leaves it in no class at every
/// instant less than `evict_after` later.
pub proof fn theorem_g6n_answered_is_kept(w: Windows, e: Entry, flags: u8, now_ms: u64, t: u64)
    requires
        windows_ok(w),
        w.evict_after_ms is Some,
        tcp_key(e.key),
        open_value(e.value),
        e.deadline_ms > now_ms,
        flags & FIN == 0,
        flags & RST == 0,
        now_ms <= t,
        (t as int - now_ms as int) < w.evict_after_ms->0 as int,
        now_ms as int + w.tcp_idle_ms as int <= u64::MAX as int,
    ensures
        class_of(w, tcp_after(w, e, flags, true, now_ms), t) == 5,
{
}

/// G6 (n), exactly one: from `inbound`'s guarantee alone, an opening that
/// gave up a record left every other record as it was.
pub proof fn theorem_g6n_one(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, x: Entry)
    requires
        finv(before),
        inbound_post(before, after, c, flags, now_ms, Inbound::Opened),
        !holds(table(before), c.client, conv_key(c)),
        table(before).len() >= scap(pool_of(before)),
        none_expired(table(before), now_ms),
        none_valued(table(before), BOTH_FIN),
        has(table(before), x),
    ensures
        table(after).len() == table(before).len(),
        has(table(after), x) || exists|i: int| victim_at(table(before), windows_of(before), now_ms, i)
            && table(before)[i] == x,
{
    reveal(gave_up_and_added);
    let s = table(before);
    let e = Entry {
        row: c.client,
        key: conv_key(c),
        deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
        value: 0,
    };
    assert(made_room(table(after), s, windows_of(before), e, now_ms, due(throttle_of(before), now_ms)));
    // The record given up, and where `x` was.
    let i = choose|i: int| victim_at(s, windows_of(before), now_ms, i)
        && gave_up_and_added(table(after), s, i, e);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == x;
    if k != i {
        assert(has(table(after), s[k]));
    }
}

/// G6 (n), off: with `evict_after` unset, an opening never gives up a
/// record that has not expired, but one closed by both sides (q).
pub proof fn theorem_g6n_off(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, r: Inbound)
    requires
        inbound_post(before, after, c, flags, now_ms, r),
        windows_of(before).evict_after_ms is None,
        r == Inbound::Opened && !holds(table(before), c.client, conv_key(c)),
    ensures
        keeps_unclosed_live(table(after), table(before), now_ms),
        none_valued(table(before), BOTH_FIN) ==> keeps_live(table(after), table(before), now_ms),
        table(before).len() >= scap(pool_of(before))
            ==> !none_expired(table(before), now_ms) || !none_valued(table(before), BOTH_FIN),
{
    reveal(closed_gave_room);
}

/// G6 (q): from `inbound`'s guarantee alone, an opening at the capacity
/// that no due sweep served, at a table holding a record closed by both
/// sides, removed every such record and no other.
pub proof fn theorem_g6q_the_closed_yield(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, x: Entry)
    requires
        inbound_post(before, after, c, flags, now_ms, Inbound::Opened),
        !holds(table(before), c.client, conv_key(c)),
        table(before).len() >= scap(pool_of(before)),
        !(due(throttle_of(before), now_ms) && !none_expired(table(before), now_ms)),
        !none_valued(table(before), BOTH_FIN),
        has(table(before), x),
    ensures
        x.value != BOTH_FIN ==> has(table(after), x),
        none_valued(table(after), BOTH_FIN),
        table(after).len() <= table(before).len(),
{
    reveal(closed_gave_room);
}

/// G6 (e), (q): an opening is never refused for room while the table holds
/// a record closed by both sides.
pub proof fn theorem_g6q_no_refusal_over_a_closed_record(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64)
    requires
        inbound_post(before, after, c, flags, now_ms, Inbound::TableFull),
    ensures
        none_valued(table(before), BOTH_FIN),
{
}

/// G6 (q): a record a side has not finished is in no pass: closed by one
/// side or by none, its value is not the one the pass removes.
pub proof fn theorem_g6q_only_the_closed(v: u32, flags: u8, from_box: bool)
    ensures
        open_value(v) ==> v != BOTH_FIN,
        BOX_FIN != BOTH_FIN && CLIENT_FIN != BOTH_FIN,
        tcp_value(v, flags, from_box) == BOTH_FIN ==> flags & RST != 0 || v == BOTH_FIN
            || (flags & FIN != 0 && (v == BOX_FIN || v == CLIENT_FIN)),
{
}

/// G6 (r): with the mark clear the table holds no record closed by both
/// sides.
pub proof fn theorem_g6r_a_clear_mark_holds_none(f: Flows)
    requires
        finv(f),
        !mark_of(f),
    ensures
        none_valued(table(f), BOTH_FIN),
{
    reveal(finv);
}

/// G6 (r): the mark, once cleared, is set again only by a frame that closed
/// a conversation for both sides: from the two guarantees alone, the frame's
/// record is closed by both sides after it and was not before.
pub proof fn theorem_g6r_a_set_mark_is_a_closed_conversation(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, inbound: bool)
    requires
        finv(before),
        !mark_of(before),
        mark_of(after),
        inbound ==> inbound_mark(before, after, c, flags, now_ms),
        !inbound ==> reply_mark(before, after, c, now_ms),
    ensures
        live_with(table(after), c.client, conv_key(c), now_ms, BOTH_FIN),
        !live_with(table(before), c.client, conv_key(c), now_ms, BOTH_FIN),
{
    reveal(finv);
}

/// G6 (e), (n): at the capacity with something expired, the opening is by
/// the sweep and by nothing else: every expired record goes, none that has
/// not expired does, and no record is given up in its place.
pub proof fn theorem_g6n_sweep_first(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64)
    requires
        inbound_post(before, after, c, flags, now_ms, Inbound::Opened),
        !holds(table(before), c.client, conv_key(c)),
        table(before).len() >= scap(pool_of(before)),
        due(throttle_of(before), now_ms),
        !none_expired(table(before), now_ms),
    ensures
        swept_and_added(table(after), table(before), Entry {
            row: c.client,
            key: conv_key(c),
            deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
            value: 0,
        }, now_ms),
{
}

/// A record a refresh of another conversation does not touch is held after
/// it as it was.
proof fn lemma_refreshed_keeps(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, e: Entry)
    requires
        refreshed_from(after, before, row, key),
        has(before, e),
        !(e.row == row && e.key == key),
    ensures
        has(after, e),
{
    let k = choose|k: int| 0 <= k < before.len() && before[k] == e;
    assert(after[k] == before[k]);
}

/// A record that has not expired is held after a touch removes the expired
/// record of another conversation.
proof fn lemma_dropped_keeps(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64, now_ms: u64, e: Entry)
    requires
        dropped_if_expired(after, before, row, key, now_ms),
        has(before, e),
        e.deadline_ms > now_ms,
    ensures
        has(after, e),
{
    reveal(dropped_if_expired);
    let k = choose|k: int| 0 <= k < before.len() && before[k] == e;
    if crate::sweep::expired_held(before, row, key, now_ms) {
        let i = choose|i: int| crate::sweep::expired_at(before, row, key, now_ms, i)
            && after == before.remove(i);
        if k < i {
            assert(after[k] == before[k]);
        } else {
            assert(after[k - 1] == before[k]);
        }
    }
}

/// G6 (n) across operations: a reply on another conversation leaves every
/// record that has not expired as it was.
pub proof fn theorem_g6n_reply_keeps_others(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, r: bool, e: Entry)
    requires
        finv(before),
        reply_post(before, after, c, flags, now_ms, r),
        has(table(before), e),
        e.deadline_ms > now_ms,
        !(e.row == c.client && e.key == conv_key(c)),
    ensures
        has(table(after), e),
{
    reveal(reply_post);
    reveal(missed);
    if r {
        lemma_refreshed_keeps(table(after), table(before), c.client, conv_key(c), e);
    } else if c.box_addr == box_of(before) && is_flow_proto(c.proto) {
        lemma_dropped_keeps(table(after), table(before), c.client, conv_key(c), now_ms, e);
    }
}

/// G6 (n) across operations: an inbound frame of another conversation,
/// whatever it does, leaves a record that has not expired and is in no class
/// as it was. An opening at the capacity gives up a record in a class or
/// none.
pub proof fn theorem_g6n_inbound_keeps_the_floor(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, r: Inbound, e: Entry)
    requires
        finv(before),
        inbound_post(before, after, c, flags, now_ms, r),
        has(table(before), e),
        e.deadline_ms > now_ms,
        class_of(windows_of(before), e, now_ms) == 5,
        !(e.row == c.client && e.key == conv_key(c)),
    ensures
        has(table(after), e),
{
    let s = table(before);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    match r {
        Inbound::Opened => {
            if holds(s, c.client, conv_key(c)) {
                lemma_refreshed_keeps(table(after), s, c.client, conv_key(c), e);
            } else if s.len() >= scap(pool_of(before))
                && !(due(throttle_of(before), now_ms) && !none_expired(s, now_ms))
                && !none_valued(s, BOTH_FIN) {
                // The records closed by both sides went: each is in class 1,
                // so not `e`.
                reveal(closed_gave_room);
                reveal(finv);
                lemma_flag_of_entry(s, e);
                assert(e.value != BOTH_FIN);
                assert(has(table(after), s[k]));
            } else if s.len() >= scap(pool_of(before)) && none_expired(s, now_ms) {
                // A record was given up: one in a class, so not `e`.
                reveal(gave_up_and_added);
                let ne = Entry {
                    row: c.client,
                    key: conv_key(c),
                    deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                    value: 0,
                };
                assert(made_room(table(after), s, windows_of(before), ne, now_ms, due(throttle_of(before), now_ms)));
                let i = choose|i: int| victim_at(s, windows_of(before), now_ms, i)
                    && gave_up_and_added(table(after), s, i, ne);
                assert(k != i);
                assert(has(table(after), s[k]));
            } else {
                assert(has(table(after), s[k]));
            }
        },
        Inbound::Refreshed { replied } => {
            lemma_refreshed_keeps(table(after), s, c.client, conv_key(c), e);
        },
        Inbound::Ended => {
            lemma_refreshed_keeps(table(after), s, c.client, conv_key(c), e);
        },
        Inbound::Untracked => {
            if is_flow_proto(c.proto) {
                lemma_dropped_keeps(table(after), s, c.client, conv_key(c), now_ms, e);
            }
        },
        _ => {},
    }
}

/// G6 (n): a record in no class stays in none when its life is extended and
/// its value kept: a later deadline never puts a record into class 4.
pub proof fn theorem_g6n_longer_life_keeps_the_floor(w: Windows, e: Entry, later: u64, now_ms: u64)
    requires
        class_of(w, e, now_ms) == 5,
        later >= e.deadline_ms,
    ensures
        class_of(w, Entry { row: e.row, key: e.key, deadline_ms: later, value: e.value }, now_ms) == 5,
{
}

/// G6 (c): a reset from either side leaves the record closed by both,
/// whatever it was and whatever else the segment carries.
pub proof fn theorem_g6c_reset_closes(v: u32, flags: u8, from_box: bool)
    requires
        flags & RST != 0,
    ensures
        tcp_value(v, flags, from_box) == BOTH_FIN,
{
}

/// G6 (c): a reset never removes a live record and never extends one: from
/// `inbound`'s guarantee alone, the record is held afterwards, live at the
/// frame's instant, and ends no later than it did or the closed window
/// after the frame.
pub proof fn theorem_g6c_reset_lingers(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, e: Entry)
    requires
        finv(before),
        inbound_post(before, after, c, flags, now_ms, Inbound::Ended),
        has(table(before), e),
        e.row == c.client,
        e.key == conv_key(c),
    ensures
        live(table(after), c.client, conv_key(c), now_ms),
        has(table(after), Entry {
            row: e.row,
            key: e.key,
            deadline_ms: if e.value == BOTH_FIN { e.deadline_ms } else {
                add_ms_spec(now_ms, windows_of(before).tcp_closed_ms)
            },
            value: BOTH_FIN,
        }),
{
    reveal(finv);
    reveal(tcp_stepped);
    let s = table(before);
    // The live record is `e`, and the segment made it into its step.
    let j = choose|j: int| 0 <= j < s.len() && s[j].row == c.client && s[j].key == conv_key(c)
        && s[j].deadline_ms > now_ms;
    crate::pool::lemma_only_entry(s, e, j);
    assert(s[j].row == c.client && s[j].key == conv_key(c));
    assert(has(table(after), tcp_after(windows_of(before), e, flags, false, now_ms)));
}

/// G6 (c): a live record stays live; a finished close is never extended;
/// anything else lives at least the closed window after the frame, a record
/// one side has closed at least the closing window, and an open one at least
/// the idle window; the
/// first FIN of a side cuts the life to at most the closing window; and no
/// frame sets a life past the old end or the idle window.
pub proof fn theorem_g6c_life(w: Windows, was: u64, before: u32, after: u32, now_ms: u64)
    requires
        windows_ok(w),
        was > now_ms,
    ensures
        tcp_deadline(w, was, before, after, now_ms) > now_ms,
        after == BOTH_FIN && before == BOTH_FIN ==> tcp_deadline(w, was, before, after, now_ms) == was,
        !(after == BOTH_FIN && before == BOTH_FIN) ==> tcp_deadline(w, was, before, after, now_ms)
            >= add_ms_spec(now_ms, w.tcp_closed_ms),
        after == BOX_FIN || after == CLIENT_FIN ==> tcp_deadline(w, was, before, after, now_ms)
            >= add_ms_spec(now_ms, w.tcp_closing_ms),
        open_value(after) ==> tcp_deadline(w, was, before, after, now_ms)
            >= add_ms_spec(now_ms, w.tcp_idle_ms),
        !open_value(after) && before != after ==> tcp_deadline(w, was, before, after, now_ms)
            <= add_ms_spec(now_ms, w.tcp_closing_ms),
        tcp_deadline(w, was, before, after, now_ms)
            <= later_spec(was, add_ms_spec(now_ms, w.tcp_idle_ms)),
{
}

/// G6 (m): after any segment from the box, FIN and RST included, on a
/// record both sides had not already closed, the record is live for at
/// least the closed window.
pub proof fn theorem_g6m_the_box_is_heard_after_its_fin(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, e: Entry, t: u64)
    requires
        finv(before),
        reply_post(before, after, c, flags, now_ms, true),
        c.proto == TCP,
        has(table(before), e),
        e.row == c.client,
        e.key == conv_key(c),
        e.value != BOTH_FIN,
        t < add_ms_spec(now_ms, windows_of(before).tcp_closed_ms),
    ensures
        live(table(after), c.client, conv_key(c), t),
{
    reveal(reply_post);
    reveal(finv);
    reveal(tcp_stepped);
    let s = table(before);
    let w = windows_of(before);
    // The live record is `e`.
    let j = choose|j: int| 0 <= j < s.len() && s[j].row == c.client && s[j].key == conv_key(c)
        && s[j].deadline_ms > now_ms;
    crate::pool::lemma_only_entry(s, e, j);
    // The segment made `e` into `x`, which the table now holds.
    assert(s[j].row == c.client && s[j].key == conv_key(c));
    let x = tcp_after(w, e, flags, true, now_ms);
    assert(has(table(after), x));
    theorem_g6c_life(w, e.deadline_ms, e.value, tcp_value(e.value, flags, true), now_ms);
    lemma_has_live(table(after), x, t);
}

/// What `inbound` promises of its result and of the table before and after.
pub open spec fn inbound_post(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, r: Inbound) -> bool {
    match r {
        Inbound::Opened => {
            &&& c.box_addr == box_of(before)
            &&& opening(c.proto, flags)
            &&& !live(table(before), c.client, conv_key(c), now_ms)
            &&& now_ms < u64::MAX ==> live(table(after), c.client, conv_key(c), now_ms)
            &&& has(table(after), Entry {
                row: c.client,
                key: conv_key(c),
                deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                value: 0,
            })
            &&& if holds(table(before), c.client, conv_key(c)) {
                refreshed_from(table(after), table(before), c.client, conv_key(c))
                    && not_shortened(table(after), table(before))
                    && changed_only_to(table(after), table(before), Entry {
                        row: c.client,
                        key: conv_key(c),
                        deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                        value: 0,
                    })
            } else {
                &&& only_adds(table(after), table(before), Entry {
                    row: c.client,
                    key: conv_key(c),
                    deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                    value: 0,
                })
                &&& table(after).len() <= table(before).len() + 1
                // A record that has not expired goes only at the capacity,
                // when no sweep that was due found an expired one: G6 (n),
                // (q).
                &&& (table(before).len() < scap(pool_of(before))
                    || (due(throttle_of(before), now_ms) && !none_expired(table(before), now_ms)))
                    ==> keeps_live(table(after), table(before), now_ms)
                // Below the capacity nothing is removed. At it, room was
                // made as `made_room` says.
                &&& table(before).len() < scap(pool_of(before)) ==> crate::pool::added(table(after), table(before), Entry {
                    row: c.client,
                    key: conv_key(c),
                    deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                    value: 0,
                })
                &&& table(before).len() >= scap(pool_of(before))
                    ==> made_room(table(after), table(before), windows_of(before), Entry {
                    row: c.client,
                    key: conv_key(c),
                    deadline_ms: add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, false)),
                    value: 0,
                }, now_ms, due(throttle_of(before), now_ms))
            }
        },
        Inbound::Refreshed { replied } => {
            &&& c.box_addr == box_of(before)
            &&& live(table(before), c.client, conv_key(c), now_ms)
            &&& replied == (c.proto == UDP && live_with(table(before), c.client, conv_key(c), now_ms, 1))
            &&& live(table(after), c.client, conv_key(c), now_ms)
            &&& refreshed_from(table(after), table(before), c.client, conv_key(c))
            // A TCP record becomes what the segment makes of it, FIN included.
            &&& c.proto == TCP ==> tcp_stepped(table(after), table(before),
                windows_of(before), c.client, conv_key(c), flags, false, now_ms)
            // A record no side has closed is refreshed as before.
            &&& stays_open(table(before), c.client, conv_key(c), c.proto, flags, now_ms)
                ==> open_refresh(table(after), table(before), c.client, conv_key(c),
                    add_ms_spec(now_ms, inbound_window(windows_of(before), c.proto, replied)), None)
            &&& !(c.proto == TCP && flags & RST != 0)
        },
        // A reset closes the record for both sides: G6 (c).
        Inbound::Ended => {
            &&& c.box_addr == box_of(before)
            &&& c.proto == TCP && flags & RST != 0
            &&& live(table(before), c.client, conv_key(c), now_ms)
            &&& live(table(after), c.client, conv_key(c), now_ms)
            &&& refreshed_from(table(after), table(before), c.client, conv_key(c))
            &&& tcp_stepped(table(after), table(before),
                windows_of(before), c.client, conv_key(c), flags, false, now_ms)
        },
        // A frame of its own conversation touches an expired record: it is
        // removed in place.
        Inbound::Untracked => {
            &&& c.box_addr == box_of(before)
            &&& !is_flow_proto(c.proto) ==> table(after) == table(before)
            &&& is_flow_proto(c.proto) ==> !opening(c.proto, flags)
                && !live(table(before), c.client, conv_key(c), now_ms)
                && dropped_if_expired(table(after), table(before), c.client, conv_key(c), now_ms)
        },
        Inbound::NotThisBox => {
            &&& c.box_addr != box_of(before)
            &&& table(after) == table(before)
        },
        // The table is full and holds no record closed by both sides. When
        // a sweep was due it ran and found nothing expired and nothing it
        // may give up; when none was due, expired records may be holding
        // the room.
        Inbound::TableFull => {
            &&& c.box_addr == box_of(before)
            &&& table(after) == table(before)
            &&& opening(c.proto, flags)
            &&& !holds(table(before), c.client, conv_key(c))
            &&& table(before).len() >= scap(pool_of(before))
            &&& none_valued(table(before), BOTH_FIN)
            &&& due(throttle_of(before), now_ms) ==> none_expired(table(before), now_ms)
                && (windows_of(before).evict_after_ms is Some
                    ==> none_evictable(table(before), windows_of(before), now_ms))
        },
    }
}

/// G6 (b): what a reply the table refuses does to it. For a TCP or UDP frame
/// of this box, the frame's own record is removed in place if it has
/// expired; otherwise nothing changes.
#[verifier::opaque]
pub open spec fn missed(after: Flows, before: Flows, c: Conversation, now_ms: u64) -> bool {
    if c.box_addr == box_of(before) && is_flow_proto(c.proto) {
        dropped_if_expired(table(after), table(before), c.client, conv_key(c), now_ms)
    } else {
        table(after) == table(before)
    }
}

/// What `reply` promises of its result and of the table before and after.
/// Opaque: a judge that reads only whether the reply was admitted does not
/// unfold what became of the table.
#[verifier::opaque]
pub open spec fn reply_post(before: Flows, after: Flows, c: Conversation, flags: u8, now_ms: u64, r: bool) -> bool {
    &&& same_frame(after, before)
    &&& stamp_same(after, before)
    &&& r == (c.box_addr == box_of(before) && is_flow_proto(c.proto)
        && live(table(before), c.client, conv_key(c), now_ms))
    &&& no_new_keys(table(after), table(before))
    &&& !r ==> missed(after, before, c, now_ms)
    &&& r ==> refreshed_from(table(after), table(before), c.client, conv_key(c))
    &&& r ==> live(table(after), c.client, conv_key(c), now_ms)
    // A TCP record becomes what the segment makes of it, FIN and RST
    // included.
    &&& r && c.proto == TCP ==> tcp_stepped(table(after), table(before),
        windows_of(before), c.client, conv_key(c), flags, true, now_ms)
    // A record no side has closed is refreshed as before.
    &&& r && stays_open(table(before), c.client, conv_key(c), c.proto, flags, now_ms)
        ==> open_refresh(table(after), table(before), c.client, conv_key(c),
            add_ms_spec(now_ms, reply_window(windows_of(before), c.proto)),
            Some(1u32))
}

} // verus!

/// The key of a conversation inside its client's row.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == key_of(proto, client_port, box_port),
))]
pub fn key(proto: u8, client_port: u16, box_port: u16) -> u64 {
    (proto as u64) * 4294967296 + (client_port as u64) * 65536 + (box_port as u64)
}

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

/// A TCP record's value after a segment with `flags` from the box
/// (`from_box`) or from the client.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == tcp_value(v, flags, from_box),
))]
fn tcp_value_of(v: u32, flags: u8, from_box: bool) -> u32 {
    if flags & RST != 0 {
        BOTH_FIN
    } else if !from_box && flags & SYN != 0 && flags & ACK == 0 {
        if v == 0 || v == ANSWERED { v } else { 0 }
    } else if flags & FIN == 0 {
        if from_box && v == 0 { ANSWERED } else { v }
    } else if from_box {
        if v == 0 || v == ANSWERED {
            BOX_FIN
        } else if v == CLIENT_FIN {
            BOTH_FIN
        } else {
            v
        }
    } else if v == 0 || v == ANSWERED {
        CLIENT_FIN
    } else if v == BOX_FIN {
        BOTH_FIN
    } else {
        v
    }
}

/// When a live TCP record ends after a segment: G6 (c).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == tcp_deadline(w, was, before, after, now_ms),
))]
fn tcp_deadline_of(w: Windows, was: u64, before: u32, after: u32, now_ms: u64) -> u64 {
    if after == 0 || after == ANSWERED {
        later(was, add_ms(now_ms, w.tcp_idle_ms))
    } else if after == BOTH_FIN {
        if before == BOTH_FIN {
            was
        } else {
            add_ms(now_ms, w.tcp_closed_ms)
        }
    } else if before == after {
        later(was, add_ms(now_ms, w.tcp_closing_ms))
    } else {
        add_ms(now_ms, w.tcp_closing_ms)
    }
}

/// The class a record may be given up in: G6 (n).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r as int == class_of(w, e, now_ms),
))]
fn class_of_entry(w: Windows, e: Entry, now_ms: u64) -> u8 {
    let tcp = key(TCP, 0, 0) <= e.key && e.key <= key(TCP, 0xffff, 0xffff);
    if tcp && e.value == BOTH_FIN {
        1
    } else if tcp && (e.value == BOX_FIN || e.value == CLIENT_FIN) {
        2
    } else if e.value == 0 {
        3
    } else {
        match w.evict_after_ms {
            Some(floor) => {
                let window = if tcp {
                    w.tcp_idle_ms
                } else if e.value == 1 {
                    w.udp_replied_ms
                } else {
                    w.udp_unreplied_ms
                };
                if e.deadline_ms as u128 + floor as u128 <= window as u128 + now_ms as u128 {
                    4
                } else {
                    5
                }
            }
            None => 5,
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Flows {
    /// The position of the record a sweep gives up, if any record is in a
    /// class: G6 (n). Reads every record once.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*self),
        ensures
            match r {
                Some(i) => victim_at(table(*self), windows_of(*self), now_ms, i as int),
                None => none_evictable(table(*self), windows_of(*self), now_ms),
            },
    ))]
    fn victim(&self, now_ms: u64) -> Option<usize> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        let n = self.pool.len();
        let mut best: Option<(usize, u8, u64)> = None;
        let mut i: usize = 0;
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                sinv(self.pool),
                n == sview(self.pool).len(),
                i <= n,
                match best {
                    Some((at, class, deadline)) => best_in(sview(self.pool), self.windows, now_ms, at as int, i as int)
                        && class as int == class_of(self.windows, sview(self.pool)[at as int], now_ms)
                        && deadline == sview(self.pool)[at as int].deadline_ms,
                    None => none_evictable_in(sview(self.pool), self.windows, now_ms, i as int),
                },
            decreases n - i,
        ))]
        while i < n {
            let e = self.pool.nth(i);
            let class = class_of_entry(self.windows, e, now_ms);
            if class < 5 {
                let better = match best {
                    None => true,
                    Some((_, held, deadline)) => {
                        class < held || (class == held && e.deadline_ms < deadline)
                    }
                };
                if better {
                    best = Some((i, class, e.deadline_ms));
                }
            }
            i += 1;
        }
        match best {
            Some((at, _, _)) => Some(at),
            None => None,
        }
    }

    /// An empty table for the box at `box_addr`, with no bound per client
    /// below its capacity, that has not swept and sweeps at its capacity at
    /// most once in `sweep_ms`. `None` when the capacity exceeds what the
    /// table's index can number, a window is zero, or the replied UDP window
    /// is shorter than the unreplied one.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(f) => finv(f) && table(f).len() == 0 && box_of(f) == box_addr
                    && windows_of(f) == windows && scap(pool_of(f)) == cap
                    && throttle_of(f) == Throttle { interval_ms: sweep.ms, last_ms: None }
                    && !mark_of(f),
                None => cap > crate::slab::MAX_CAP || !windows_ok(windows),
            },
    ))]
    pub fn new(box_addr: u32, cap: usize, windows: Windows, sweep: Span) -> Option<Flows> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        if windows.tcp_idle_ms == 0
            || windows.udp_unreplied_ms == 0
            || windows.udp_replied_ms < windows.udp_unreplied_ms
            || windows.tcp_closed_ms == 0
            || windows.tcp_closed_ms > windows.tcp_closing_ms
            || windows.tcp_closing_ms > windows.tcp_idle_ms
        {
            return None;
        }
        let floor_fits = match windows.evict_after_ms {
            Some(floor) => floor > 0 && floor <= windows.tcp_idle_ms,
            None => true,
        };
        if !floor_fits {
            return None;
        }
        match Slab::new(cap, cap) {
            Some(pool) => Some(Flows {
                pool,
                box_addr,
                windows,
                throttle: Throttle {
                    interval_ms: sweep.ms,
                    last_ms: None,
                },
                may_hold_closed: false,
            }),
            None => None,
        }
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == table(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// The most records the table holds. No operation changes it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == scap(pool_of(*self)),
    ))]
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// Whether the table is at its capacity: the next frame that would open
    /// a record it does not hold takes room only from a sweep.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == (table(*self).len() >= scap(pool_of(*self))),
    ))]
    pub fn is_full(&self) -> bool {
        self.pool.len() >= self.pool.capacity()
    }

    /// The mark of G6 (r): whether the table may hold a record closed by
    /// both sides. For counting and for tests, not for deciding.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == mark_of(*self),
    ))]
    pub fn may_hold_closed(&self) -> bool {
        self.may_hold_closed
    }

    /// The box this table belongs to.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == box_of(*self),
    ))]
    pub fn box_addr(&self) -> u32 {
        self.box_addr
    }

    /// How many records have not expired at `now_ms`. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*self),
        ensures
            r == crate::pool::live_number(table(*self), now.ms),
    ))]
    pub fn live_count(&self, now: Instant) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        self.pool.live_count(now)
    }

    /// Whether the table holds an unexpired record for this conversation.
    /// Changes nothing: for comparing a table with another, not for deciding.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*self),
        ensures
            r == live(table(*self), c.client, conv_key(c), now.ms),
    ))]
    pub fn has_live(&self, c: Conversation, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_has_live_reads(*self, c, now.ms);
        }
        self.pool
            .live(c.client, key(c.proto, c.client_port, c.box_port), now)
    }

    /// Whether a frame the box sent is a reply the table admits. G6 (a), (b),
    /// (c), (f).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
        ensures
            finv(*final(self)),
            reply_post(*old(self), *final(self), c, flags, now.ms, r),
            reply_mark(*old(self), *final(self), c, now.ms),
    ))]
    pub fn reply(&mut self, c: Conversation, flags: u8, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::extended);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(missed);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_same_no_new_keys(sview(self.pool));
        }
        if c.box_addr != self.box_addr {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_reply_refused(*old(self), *self, c, flags, now.ms);
            }
            return false;
        }
        if c.proto != TCP && c.proto != UDP {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_reply_refused(*old(self), *self, c, flags, now.ms);
            }
            return false;
        }
        let k = key(c.proto, c.client_port, c.box_port);
        let e = match self.pool.entry(c.client, k) {
            Some(e) => e,
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_not_held_untouched(sview(self.pool), c.client, k, now.ms);
                    lemma_not_held_not_live(sview(self.pool), c.client, k, now.ms);
                    lemma_reply_refused(*old(self), *self, c, flags, now.ms);
                }
                return false;
            }
        };
        if e.deadline_ms <= now.ms {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_expired_not_live(sview(self.pool), e, now.ms);
            }
            // The frame's own record has expired: the touch removes it.
            let _ = self.pool.drop_expired(c.client, k, now);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_dropped_subset(sview(self.pool), sview(old(self).pool), c.client, k, now.ms);
                lemma_subset_no_new_keys(sview(self.pool), sview(old(self).pool));
                lemma_flags_subset(sview(self.pool), sview(old(self).pool));
                if !self.may_hold_closed {
                    lemma_valued_subset(sview(self.pool), sview(old(self).pool), BOTH_FIN);
                }
                lemma_reply_refused(*old(self), *self, c, flags, now.ms);
            }
            return false;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_has_live(sview(self.pool), e, now.ms);
        }
        // The box's reply marks a UDP record. A TCP record's value says
        // which sides have closed, and its life follows from that.
        let value = if c.proto == UDP {
            1
        } else {
            tcp_value_of(e.value, flags, true)
        };
        let deadline = if c.proto == UDP {
            later(e.deadline_ms, add_ms(now.ms, self.windows.udp_replied_ms))
        } else {
            tcp_deadline_of(self.windows, e.deadline_ms, e.value, value, now.ms)
        };
        // A record this segment leaves closed by both sides: G6 (r).
        self.may_hold_closed = self.may_hold_closed || value == BOTH_FIN;
        let _ = self.pool.set(c.client, k, Instant { ms: deadline }, value);
        #[cfg(verus_keep_ghost)]
        proof! {
            if c.proto == UDP {
                lemma_reply_refreshed_udp(*old(self), *self, c, flags, now.ms, e, deadline, value);
            } else {
                lemma_reply_refreshed_tcp(*old(self), *self, c, flags, now.ms, e, deadline, value);
            }
        }
        true
    }

    /// Records what one inbound frame does to the table. The caller has
    /// already decided the frame is addressed to a port this box publishes.
    /// G6 (d), (e), (f).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            inbound_post(*old(self), *final(self), c, flags, now.ms, r),
            inbound_stamp(*old(self), *final(self), c, flags, now.ms),
            inbound_mark(*old(self), *final(self), c, flags, now.ms),
    ))]
    pub fn inbound(&mut self, c: Conversation, flags: u8, now: Instant) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        if c.box_addr != self.box_addr {
            return Inbound::NotThisBox;
        }
        if c.proto != TCP && c.proto != UDP {
            return Inbound::Untracked;
        }
        let k = key(c.proto, c.client_port, c.box_port);
        let window = if c.proto == TCP {
            self.windows.tcp_idle_ms
        } else {
            self.windows.udp_unreplied_ms
        };
        let fresh = add_ms(now.ms, window);
        match self.pool.entry(c.client, k) {
            Some(e) => {
                if e.deadline_ms > now.ms {
                    self.step_live(c, k, e, flags, now.ms, fresh)
                } else {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        lemma_expired_not_live(sview(self.pool), e, now.ms);
                    }
                    self.touch_expired(c, k, flags, now, fresh)
                }
            }
            None => self.open_new(c, k, flags, now.ms, fresh),
        }
    }

    /// A frame of a conversation whose record has not expired: the record is
    /// refreshed, or ended by a reset. G6 (d), (f), (r).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            c.box_addr == box_of(*old(self)),
            is_flow_proto(c.proto),
            k == conv_key(c),
            has(table(*old(self)), e),
            e.row == c.client,
            e.key == k,
            e.deadline_ms > now_ms,
            fresh == add_ms_spec(now_ms, inbound_window(windows_of(*old(self)), c.proto, false)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            r == Inbound::Ended || r is Refreshed,
            inbound_post(*old(self), *final(self), c, flags, now_ms, r),
            inbound_stamp(*old(self), *final(self), c, flags, now_ms),
            inbound_mark(*old(self), *final(self), c, flags, now_ms),
    ))]
    fn step_live(
        &mut self,
        c: Conversation,
        k: u64,
        e: Entry,
        flags: u8,
        now_ms: u64,
        fresh: u64,
    ) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost window: u64 = if c.proto == TCP {
                self.windows.tcp_idle_ms
            } else {
                self.windows.udp_unreplied_ms
            };
        }
        // A datagram on a record the box has replied on keeps the
        // replied window.
        let replied = c.proto == UDP && e.value == 1;
        let fresh = if replied {
            add_ms(now_ms, self.windows.udp_replied_ms)
        } else {
            fresh
        };
        let value = if c.proto == TCP {
            tcp_value_of(e.value, flags, false)
        } else {
            e.value
        };
        let deadline = if c.proto == TCP {
            tcp_deadline_of(self.windows, e.deadline_ms, e.value, value, now_ms)
        } else {
            later(e.deadline_ms, fresh)
        };
        // A record this segment leaves closed by both sides:
        // G6 (r).
        self.may_hold_closed = self.may_hold_closed || value == BOTH_FIN;
        let _ = self.pool.set(c.client, k, Instant { ms: deadline }, value);
        if c.proto == TCP && flags & RST != 0 {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_inbound_reset(*old(self), *self, c, flags, now_ms, e, deadline, value);
            }
            return Inbound::Ended;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_inbound_refreshed(
                *old(self), *self, c, flags, now_ms, e, window, fresh, deadline, value,
            );
        }
        Inbound::Refreshed { replied }
    }

    /// A frame of a conversation whose record has expired: a frame that does
    /// not open removes it; an opening one reopens it in place. G6 (c), (e).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            c.box_addr == box_of(*old(self)),
            is_flow_proto(c.proto),
            k == conv_key(c),
            holds(table(*old(self)), c.client, k),
            !live(table(*old(self)), c.client, k, now.ms),
            fresh == add_ms_spec(now.ms, inbound_window(windows_of(*old(self)), c.proto, false)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            r == Inbound::Untracked || r == Inbound::Opened,
            inbound_post(*old(self), *final(self), c, flags, now.ms, r),
            inbound_stamp(*old(self), *final(self), c, flags, now.ms),
            inbound_mark(*old(self), *final(self), c, flags, now.ms),
    ))]
    fn touch_expired(
        &mut self,
        c: Conversation,
        k: u64,
        flags: u8,
        now: Instant,
        fresh: u64,
    ) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost window: u64 = if c.proto == TCP {
                self.windows.tcp_idle_ms
            } else {
                self.windows.udp_unreplied_ms
            };
        }
        let opens = c.proto == UDP || (flags & SYN != 0 && flags & ACK == 0);
        // The record the table holds for the conversation, which has expired.
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost j: int = choose|j: int| 0 <= j < table(*self).len()
                && table(*self)[j].row == c.client && table(*self)[j].key == k;
            let ghost e: Entry = table(*self)[j];
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(has(table(*self), e));
            assert(e.deadline_ms <= now.ms);
            lemma_expired_not_live(sview(self.pool), e, now.ms);
        }
        if !opens {
            // The frame's own record has expired: the touch removes it.
            let _ = self.pool.drop_expired(c.client, k, now);
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_dropped_subset(sview(self.pool), sview(old(self).pool), c.client, k, now.ms);
                lemma_flags_subset(sview(self.pool), sview(old(self).pool));
                if !self.may_hold_closed {
                    lemma_valued_subset(sview(self.pool), sview(old(self).pool), BOTH_FIN);
                }
            }
            return Inbound::Untracked;
        }
        // An expired record for the same conversation is reopened in
        // place, as a new record.
        let _ = self.pool.set(c.client, k, Instant { ms: fresh }, 0);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_inbound_reopened(*old(self), *self, c, flags, now.ms, e, window, fresh);
        }
        Inbound::Opened
    }

    /// A frame of a conversation the table does not hold. An opening packet
    /// adds its record. At the capacity it sweeps when a sweep is due; with
    /// no room from that, the records closed by both sides go, G6 (q); with
    /// none of those and a sweep that was due, a record is given up as G6
    /// (n) says; or the frame is refused. Any other frame opens nothing and
    /// changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            c.box_addr == box_of(*old(self)),
            is_flow_proto(c.proto),
            k == conv_key(c),
            !holds(table(*old(self)), c.client, k),
            fresh == add_ms_spec(now_ms, inbound_window(windows_of(*old(self)), c.proto, false)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            r == Inbound::Opened || r == Inbound::TableFull || r == Inbound::Untracked,
            (r == Inbound::Untracked) == !opening(c.proto, flags),
            inbound_post(*old(self), *final(self), c, flags, now_ms, r),
            inbound_stamp(*old(self), *final(self), c, flags, now_ms),
            inbound_mark(*old(self), *final(self), c, flags, now_ms),
    ))]
    fn open_new(&mut self, c: Conversation, k: u64, flags: u8, now_ms: u64, fresh: u64) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! {
            let ghost window: u64 = if c.proto == TCP {
                self.windows.tcp_idle_ms
            } else {
                self.windows.udp_unreplied_ms
            };
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_not_held_untouched(sview(self.pool), c.client, k, now_ms);
            lemma_not_held_not_live(sview(self.pool), c.client, k, now_ms);
        }
        if !(c.proto == UDP || (flags & SYN != 0 && flags & ACK == 0)) {
            return Inbound::Untracked;
        }
        // At the capacity every expired record goes, unless the table
        // swept less than its interval ago.
        let (did, th) = self.pool.insert_sweeping(
            self.throttle,
            c.client,
            k,
            Instant { ms: fresh },
            0,
            Instant { ms: now_ms },
        );
        self.throttle = th;
        let throttled = match did {
            Swept::New | Swept::SweptNew => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    reveal(crate::pool::added);
                    reveal(swept_and_added);
                    lemma_inbound_inserted(*old(self), *self, c, flags, now_ms, window, fresh);
                }
                return Inbound::Opened;
            }
            Swept::Throttled => true,
            Swept::Full => false,
        };
        let r = self.open_at_capacity(c, k, now_ms, fresh, throttled);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_inbound_at_capacity(*old(self), *self, c, flags, now_ms, fresh, throttled, r);
        }
        r
    }

    /// At the capacity with no room from a sweep: the records closed by both
    /// sides go when the mark is set, and the new record takes their room,
    /// G6 (q); otherwise the frame is refused when the sweep was throttled,
    /// or a record is given up as G6 (n) says. The instant of the last sweep
    /// does not move, and the mark is clear after.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            c.box_addr == box_of(*old(self)),
            is_flow_proto(c.proto),
            k == conv_key(c),
            !holds(table(*old(self)), c.client, k),
            table(*old(self)).len() >= scap(pool_of(*old(self))),
            !throttled ==> none_expired(table(*old(self)), now_ms),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            throttle_of(*final(self)) == throttle_of(*old(self)),
            !mark_of(*final(self)),
            r == Inbound::Opened || r == Inbound::TableFull,
            r == Inbound::Opened ==> (mark_of(*old(self)) && closed_gave_room(table(*final(self)),
                table(*old(self)), Entry { row: c.client, key: k, deadline_ms: fresh, value: 0 }))
                || (none_valued(table(*old(self)), BOTH_FIN) && !throttled
                    && windows_of(*old(self)).evict_after_ms is Some
                    && exists|i: int|
                        victim_at(table(*old(self)), windows_of(*old(self)), now_ms, i)
                        && gave_up_and_added(table(*final(self)), table(*old(self)), i,
                            Entry { row: c.client, key: k, deadline_ms: fresh, value: 0 })),
            r == Inbound::TableFull ==> table(*final(self)) == table(*old(self))
                && none_valued(table(*old(self)), BOTH_FIN)
                && (!throttled && windows_of(*old(self)).evict_after_ms is Some
                    ==> none_evictable(table(*old(self)), windows_of(*old(self)), now_ms)),
    ))]
    fn open_at_capacity(
        &mut self,
        c: Conversation,
        k: u64,
        now_ms: u64,
        fresh: u64,
        throttled: bool,
    ) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        // No room from a sweep. The records closed by both sides go first:
        // G6 (q).
        if self.may_hold_closed {
            if self.drop_closed() > 0 {
                #[cfg(verus_keep_ghost)]
                proof_decl! {
                    let ghost mid: Seq<Entry> = sview(self.pool);
                }
                return match self.pool.insert(c.client, k, Instant { ms: fresh }, 0) {
                    Inserted::New => {
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            let e = Entry { row: c.client, key: k, deadline_ms: fresh, value: 0 };
                            lemma_room_from_closed(*old(self), mid, *self, e);
                        }
                        Inbound::Opened
                    }
                    // Not reached: the pass left room, and the key is not
                    // held.
                    Inserted::Refreshed | Inserted::RowAtQuota | Inserted::PoolFull => {
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            // The pass left `mid` a part of the table, shorter than the
                            // capacity, without the key.
                            lemma_subset_no_new_keys(mid, table(*old(self)));
                            crate::pool::lemma_count_le_len(mid, c.client);
                            assert(!holds(mid, c.client, k));
                            assert(false);
                        }
                        Inbound::TableFull
                    }
                };
            }
        }
        if throttled {
            return Inbound::TableFull;
        }
        // A sweep was due and nothing had expired: G6 (n).
        self.give_up_and_open(c, k, now_ms, fresh)
    }

    /// The pass of G6 (q): removes every record closed by both sides and
    /// returns how many. Called only with the mark set, and clears it: G6
    /// (r). Reads every record once; the instant of the last sweep does not
    /// move.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            mark_of(*old(self)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            stamp_same(*final(self), *old(self)),
            !mark_of(*final(self)),
            table(*final(self)).len() + r == table(*old(self)).len(),
            subset_of(table(*final(self)), table(*old(self))),
            keeps_unvalued(table(*final(self)), table(*old(self)), BOTH_FIN),
            none_valued(table(*final(self)), BOTH_FIN),
            r == 0 ==> table(*final(self)) == table(*old(self)),
            r > 0 ==> !none_valued(table(*old(self)), BOTH_FIN),
    ))]
    fn drop_closed(&mut self) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        let n = self.pool.remove_valued(BOTH_FIN);
        self.may_hold_closed = false;
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_flags_subset(sview(self.pool), sview(old(self).pool));
        }
        n
    }

    /// At the capacity with nothing expired: gives up the record G6 (n) names
    /// and opens `c`'s in its room, or refuses and changes nothing when no
    /// record is in a class or `evict_after` is unset.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
            c.box_addr == box_of(*old(self)), is_flow_proto(c.proto),
            k == conv_key(c),
            !holds(table(*old(self)), c.client, k),
            table(*old(self)).len() >= scap(pool_of(*old(self))),
            none_expired(table(*old(self)), now_ms),
        ensures
            finv(*final(self)), same_frame(*final(self), *old(self)),
            throttle_of(*final(self)) == throttle_of(*old(self)),
            mark_of(*final(self)) == mark_of(*old(self)),
            r == Inbound::Opened || r == Inbound::TableFull,
            r == Inbound::Opened ==> windows_of(*old(self)).evict_after_ms is Some
                && exists|i: int| victim_at(table(*old(self)), windows_of(*old(self)), now_ms, i)
                    && gave_up_and_added(table(*final(self)), table(*old(self)), i,
                        Entry { row: c.client, key: k, deadline_ms: fresh, value: 0 }),
            r == Inbound::TableFull ==> table(*final(self)) == table(*old(self))
                && (windows_of(*old(self)).evict_after_ms is Some
                    ==> none_evictable(table(*old(self)), windows_of(*old(self)), now_ms)),
    ))]
    fn give_up_and_open(&mut self, c: Conversation, k: u64, now_ms: u64, fresh: u64) -> Inbound {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        // Nothing had expired. With `evict_after` set, one
        // record in a class is given up: G6 (n).
        if self.windows.evict_after_ms.is_none() {
            return Inbound::TableFull;
        }
        match self.victim(now_ms) {
            None => Inbound::TableFull,
            Some(at) => {
                let gone = self.pool.nth(at);
                #[cfg(verus_keep_ghost)]
                proof! {
                    // The record given up is held, so the removal takes one.
                    let s = sview(self.pool);
                    assert(s[at as int].row == gone.row && s[at as int].key == gone.key);
                    assert(holds(s, gone.row, gone.key));
                }
                let _ = self.pool.remove(gone.row, gone.key);
                #[cfg(verus_keep_ghost)]
                proof_decl! {
                    let ghost mid: Seq<Entry> = sview(self.pool);
                }
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_room_after_give_up(
                        sview(old(self).pool), mid, scap(self.pool), squota(self.pool), c.client, k,
                    );
                }
                match self.pool.insert(c.client, k, Instant { ms: fresh }, 0) {
                    Inserted::New => {
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            lemma_gave_up(*old(self), mid, *self, c, now_ms, fresh, at as int);
                        }
                        Inbound::Opened
                    }
                    // Not reached: the removal left room, and the
                    // key is not held.
                    Inserted::Refreshed | Inserted::RowAtQuota | Inserted::PoolFull => {
                        #[cfg(verus_keep_ghost)]
                        proof! {
                            assert(false);
                        }
                        Inbound::TableFull
                    }
                }
            }
        }
    }

    /// Removes expired records, at most `budget`, and returns how many. A
    /// record that has not expired is never removed.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            stamp_same(*final(self), *old(self)),
            mark_of(*final(self)) == mark_of(*old(self)),
            r <= budget,
            table(*final(self)).len() + r == table(*old(self)).len(),
            subset_of(table(*final(self)), table(*old(self))),
            keeps_live(table(*final(self)), table(*old(self)), now.ms),
            r < budget ==> none_expired(table(*final(self)), now.ms),
    ))]
    pub fn expire(&mut self, now: Instant, budget: usize) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        let n = self.pool.expire(now, budget);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_flags_subset(sview(self.pool), sview(old(self).pool));
            if !self.may_hold_closed {
                lemma_valued_subset(sview(self.pool), sview(old(self).pool), BOTH_FIN);
            }
        }
        n
    }

    /// Ends the records of one protocol and box port, of every client and
    /// expired or not, and returns how many. G6 (j).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            finv(*old(self)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            stamp_same(*final(self), *old(self)),
            mark_of(*final(self)) == mark_of(*old(self)),
            table(*final(self)).len() + r == table(*old(self)).len(),
            port_ended(table(*final(self)), table(*old(self)), proto, port),
    ))]
    pub fn end_port(&mut self, proto: u8, port: u16) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        let n = self.pool.remove_ends(proto as u64, port as u64);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_flags_subset(sview(self.pool), sview(old(self).pool));
            if !self.may_hold_closed {
                lemma_valued_subset(sview(self.pool), sview(old(self).pool), BOTH_FIN);
            }
        }
        n
    }

    /// Ends every record: the box stopped, or its ingress was revoked. The
    /// table is as one that has not swept, with its mark clear.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            finv(*old(self)),
        ensures
            finv(*final(self)),
            same_frame(*final(self), *old(self)),
            table(*final(self)).len() == 0,
            throttle_of(*final(self)).last_ms.is_none(),
            !mark_of(*final(self)),
    ))]
    pub fn clear(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(finv);
        }
        self.pool.clear();
        self.throttle = Throttle {
            interval_ms: self.throttle.interval_ms,
            last_ms: None,
        };
        self.may_hold_closed = false;
    }

    /// When the table last swept at its capacity, if it has.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == throttle_of(*self).last_ms,
    ))]
    pub fn last_sweep(&self) -> Option<u64> {
        self.throttle.last_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Windows = Windows {
        tcp_idle_ms: 300_000,
        tcp_closing_ms: 120_000,
        tcp_closed_ms: 5_000,
        udp_unreplied_ms: 30_000,
        udp_replied_ms: 300_000,
        evict_after_ms: None,
    };
    const BOX: u32 = 0x0a00_0005;

    /// A table of four records that gives up records at its capacity, with
    /// a floor of ten seconds.
    fn evicting() -> Flows {
        let mut w = W;
        w.evict_after_ms = Some(10_000);
        Flows::new(BOX, 4, w, Span { ms: 1_000 }).unwrap()
    }

    #[test]
    fn at_the_capacity_a_closed_record_goes_before_a_closing_one_and_that_before_an_unanswered_one()
    {
        let mut f = evicting();
        let closed = conv(TCP, 1, 1, 80);
        let closing = conv(TCP, 1, 2, 80);
        let unanswered = conv(TCP, 1, 3, 80);
        let answered = conv(TCP, 1, 4, 80);
        for c in [closed, closing, unanswered, answered] {
            assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        }
        assert!(f.reply(closed, SYN | ACK, Instant { ms: 1 }));
        assert_eq!(f.inbound(closed, RST, Instant { ms: 2 }), Inbound::Ended);
        assert!(f.reply(closing, FIN | ACK, Instant { ms: 2 }));
        assert!(f.reply(answered, SYN | ACK, Instant { ms: 2 }));
        // Nothing has expired. Each opening takes the room of the next class.
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 3 }),
            Inbound::Opened
        );
        assert!(!f.has_live(closed, Instant { ms: 3 }));
        assert!(
            f.has_live(closing, Instant { ms: 3 })
                && f.has_live(unanswered, Instant { ms: 3 })
                && f.has_live(answered, Instant { ms: 3 })
        );
        assert_eq!(
            f.inbound(conv(TCP, 2, 2, 80), SYN, Instant { ms: 1_003 }),
            Inbound::Opened
        );
        assert!(!f.has_live(closing, Instant { ms: 1_003 }));
        assert_eq!(
            f.inbound(conv(TCP, 2, 3, 80), SYN, Instant { ms: 2_003 }),
            Inbound::Opened
        );
        assert!(!f.has_live(unanswered, Instant { ms: 2_003 }));
        assert!(f.has_live(answered, Instant { ms: 2_003 }));
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn an_answered_record_is_given_up_only_after_its_floor() {
        let mut f = evicting();
        let all = [
            conv(TCP, 1, 1, 80),
            conv(TCP, 1, 2, 80),
            conv(TCP, 1, 3, 80),
            conv(TCP, 1, 4, 80),
        ];
        for c in all {
            assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
            assert!(f.reply(c, SYN | ACK, Instant { ms: 0 }));
        }
        // Every record is answered and within the floor: the table refuses.
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 9_999 }),
            Inbound::TableFull
        );
        // The second stays busy; at the floor the first of the idle ones goes.
        assert!(f.reply(all[1], ACK, Instant { ms: 9_999 }));
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 11_000 }),
            Inbound::Opened
        );
        assert!(!f.has_live(all[0], Instant { ms: 11_000 }));
        assert!(f.has_live(all[1], Instant { ms: 11_000 }));
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn with_no_floor_set_a_full_table_of_records_that_have_not_expired_refuses() {
        let mut f = flows();
        assert_eq!(f.capacity(), 4);
        for p in 1..=4 {
            assert!(!f.is_full());
            assert_eq!(
                f.inbound(conv(TCP, 1, p, 80), SYN, Instant { ms: 0 }),
                Inbound::Opened
            );
        }
        assert!(f.is_full());
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 2_000 }),
            Inbound::TableFull
        );
        assert_eq!(f.len(), 4);
        assert_eq!(f.capacity(), 4);
    }

    /// Four conversations of one client, opened and answered at 0, and a
    /// fifth refused at 10, whose sweep is the one for that second.
    fn full_and_swept(f: &mut Flows) -> [Conversation; 4] {
        let old = [
            conv(TCP, 1, 1, 80),
            conv(TCP, 1, 2, 80),
            conv(TCP, 1, 3, 80),
            conv(TCP, 1, 4, 80),
        ];
        for c in old {
            assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
            assert!(f.reply(c, SYN | ACK, Instant { ms: 0 }));
        }
        assert_eq!(
            f.inbound(conv(TCP, 2, 9, 80), SYN, Instant { ms: 10 }),
            Inbound::TableFull
        );
        assert_eq!(f.last_sweep(), Some(10));
        assert!(!f.may_hold_closed());
        old
    }

    #[test]
    fn at_the_capacity_finished_conversations_give_their_room_at_once_with_no_floor_set() {
        let mut f = flows();
        let old = full_and_swept(&mut f);
        // Every conversation finishes from both sides.
        for c in old {
            assert!(f.reply(c, FIN | ACK, Instant { ms: 20 }));
            assert_eq!(
                f.inbound(c, FIN | ACK, Instant { ms: 20 }),
                Inbound::Refreshed { replied: false }
            );
        }
        assert!(f.may_hold_closed());
        assert_eq!(f.len(), 4);
        // As many again in the same instant, with no sweep due: all admitted.
        for p in 1..=4 {
            assert_eq!(
                f.inbound(conv(TCP, 2, p, 80), SYN, Instant { ms: 30 }),
                Inbound::Opened
            );
        }
        assert!(!f.may_hold_closed());
        assert_eq!(f.len(), 4);
        assert_eq!(f.last_sweep(), Some(10));
        for c in old {
            assert!(!f.has_live(c, Instant { ms: 30 }));
        }
        // The table is full of open conversations again, and refuses.
        assert_eq!(
            f.inbound(conv(TCP, 2, 5, 80), SYN, Instant { ms: 30 }),
            Inbound::TableFull
        );
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn a_conversation_one_side_has_not_finished_keeps_its_room() {
        let mut f = flows();
        let old = full_and_swept(&mut f);
        // Two finish from both sides, by a second FIN and by a reset; two
        // from the box only.
        assert!(f.reply(old[0], FIN | ACK, Instant { ms: 20 }));
        assert_eq!(
            f.inbound(old[0], FIN | ACK, Instant { ms: 20 }),
            Inbound::Refreshed { replied: false }
        );
        assert_eq!(f.inbound(old[1], RST, Instant { ms: 20 }), Inbound::Ended);
        assert!(f.reply(old[2], FIN | ACK, Instant { ms: 20 }));
        assert!(f.reply(old[3], FIN | ACK, Instant { ms: 20 }));
        for p in 1..=2 {
            assert_eq!(
                f.inbound(conv(TCP, 2, p, 80), SYN, Instant { ms: 30 }),
                Inbound::Opened
            );
        }
        assert_eq!(
            f.inbound(conv(TCP, 2, 3, 80), SYN, Instant { ms: 30 }),
            Inbound::TableFull
        );
        assert!(!f.has_live(old[0], Instant { ms: 30 }) && !f.has_live(old[1], Instant { ms: 30 }));
        assert!(f.has_live(old[2], Instant { ms: 30 }) && f.has_live(old[3], Instant { ms: 30 }));
        assert_eq!(f.len(), 4);
        assert!(!f.may_hold_closed());
    }

    #[test]
    fn a_mark_left_by_a_record_that_was_reopened_costs_one_pass_and_is_cleared() {
        let mut f = flows();
        let old = full_and_swept(&mut f);
        assert_eq!(f.inbound(old[0], RST, Instant { ms: 20 }), Inbound::Ended);
        assert!(f.may_hold_closed());
        // The client connects again: the record is open, and the mark stays.
        assert_eq!(
            f.inbound(old[0], SYN, Instant { ms: 21 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(f.may_hold_closed());
        // The next opening finds nothing to free, is refused, and clears it.
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 30 }),
            Inbound::TableFull
        );
        assert!(!f.may_hold_closed());
        assert_eq!(f.len(), 4);
        for c in old {
            assert!(f.has_live(c, Instant { ms: 30 }));
        }
    }

    #[test]
    fn an_expired_record_goes_before_a_finished_one_when_a_sweep_is_due() {
        let mut f = flows();
        let old = full_and_swept(&mut f);
        assert_eq!(f.inbound(old[0], RST, Instant { ms: 20 }), Inbound::Ended);
        // The reset's record has expired by the next due sweep; the others
        // have not. The sweep takes it and the pass does not run.
        let later = 20 + W.tcp_closed_ms;
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: later }),
            Inbound::Opened
        );
        assert_eq!(f.last_sweep(), Some(later));
        assert!(f.may_hold_closed());
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn a_floor_of_zero_or_past_the_idle_window_is_refused() {
        let mut w = W;
        w.evict_after_ms = Some(0);
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
        w.evict_after_ms = Some(W.tcp_idle_ms + 1);
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
        w.evict_after_ms = Some(W.tcp_idle_ms);
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_some());
    }

    fn conv(proto: u8, client: u32, client_port: u16, box_port: u16) -> Conversation {
        Conversation {
            proto,
            client,
            client_port,
            box_addr: BOX,
            box_port,
        }
    }

    fn flows() -> Flows {
        Flows::new(BOX, 4, W, Span { ms: 1_000 }).unwrap()
    }

    #[test]
    fn a_reply_is_admitted_only_after_the_opening() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert!(!f.reply(c, ACK, Instant { ms: 0 }));
        assert_eq!(f.len(), 0);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, SYN | ACK, Instant { ms: 1 }));
    }

    #[test]
    fn a_mid_stream_segment_opens_nothing() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, ACK, Instant { ms: 0 }), Inbound::Untracked);
        assert_eq!(
            f.inbound(c, SYN | ACK, Instant { ms: 0 }),
            Inbound::Untracked
        );
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn a_reply_must_match_client_protocol_and_both_ports() {
        let mut f = flows();
        assert_eq!(
            f.inbound(conv(TCP, 1, 40000, 8080), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert!(!f.reply(conv(TCP, 2, 40000, 8080), ACK, Instant { ms: 1 }));
        assert!(!f.reply(conv(TCP, 1, 40001, 8080), ACK, Instant { ms: 1 }));
        assert!(!f.reply(conv(TCP, 1, 40000, 8081), ACK, Instant { ms: 1 }));
        assert!(!f.reply(conv(UDP, 1, 40000, 8080), 0, Instant { ms: 1 }));
        let mut other_box = conv(TCP, 1, 40000, 8080);
        other_box.box_addr = BOX + 1;
        assert!(!f.reply(other_box, ACK, Instant { ms: 1 }));
    }

    #[test]
    fn an_expired_record_admits_nothing_and_the_reply_that_touches_it_removes_it() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert!(!f.reply(c, 0, Instant { ms: 30_000 }));
        assert_eq!(f.len(), 0);
        assert_eq!(f.expire(Instant { ms: 30_000 }, 8), 0);
        assert_eq!(f.last_sweep(), None);
    }

    #[test]
    fn a_reply_for_another_record_leaves_an_expired_one() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert!(!f.reply(conv(UDP, 1, 5001, 53), 0, Instant { ms: 30_000 }));
        let mut other_box = c;
        other_box.box_addr = BOX + 1;
        assert!(!f.reply(other_box, 0, Instant { ms: 30_000 }));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn a_segment_that_opens_nothing_removes_its_expired_record() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(c, ACK, Instant { ms: 300_000 }),
            Inbound::Untracked
        );
        assert_eq!(f.len(), 0);
        assert_eq!(f.last_sweep(), None);
    }

    // A touch frees room, and the next opening is
    // inserted below the capacity without a sweep.
    #[test]
    fn a_reply_on_an_expired_record_makes_room_between_sweeps() {
        let mut f = flows();
        let u = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(u, 0, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(conv(TCP, 2, 1, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 2, 2, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 2, 3, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        // At the capacity a sweep runs and finds nothing expired.
        assert_eq!(
            f.inbound(conv(TCP, 2, 4, 80), SYN, Instant { ms: 29_999 }),
            Inbound::TableFull
        );
        assert_eq!(f.last_sweep(), Some(29_999));
        // `u` has expired and no sweep is due.
        assert_eq!(
            f.inbound(conv(TCP, 2, 4, 80), SYN, Instant { ms: 30_000 }),
            Inbound::TableFull
        );
        assert!(!f.reply(u, 0, Instant { ms: 30_000 }));
        assert_eq!(f.len(), 3);
        assert_eq!(
            f.inbound(conv(TCP, 2, 4, 80), SYN, Instant { ms: 30_000 }),
            Inbound::Opened
        );
        assert_eq!(f.len(), 4);
        assert_eq!(f.last_sweep(), Some(29_999));
    }

    #[test]
    fn ending_a_port_ends_its_records_of_every_client_and_no_other() {
        let mut f = flows();
        let a = conv(TCP, 1, 40000, 8080);
        let b = conv(TCP, 2, 40001, 8080);
        let other_port = conv(TCP, 1, 40000, 8081);
        let udp = conv(UDP, 2, 40001, 8080);
        assert_eq!(f.inbound(a, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(f.inbound(b, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(other_port, SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(f.inbound(udp, 0, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(f.end_port(TCP, 8080), 2);
        assert_eq!(f.len(), 2);
        assert!(!f.reply(a, ACK, Instant { ms: 1 }));
        assert!(!f.reply(b, ACK, Instant { ms: 1 }));
        assert!(f.reply(other_port, ACK, Instant { ms: 1 }));
        assert!(f.reply(udp, 0, Instant { ms: 1 }));
        assert_eq!(f.end_port(TCP, 8080), 0);
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn ending_a_port_takes_an_expired_record_too() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(f.end_port(UDP, 53), 1);
        assert_eq!(f.len(), 0);
        let mut f = flows();
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        // Past its window, and touched by no frame, the record is still held;
        // ending the port removes it.
        assert!(!f.has_live(c, Instant { ms: 30_000 }));
        assert_eq!(f.len(), 1);
        assert_eq!(f.end_port(UDP, 53), 1);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn a_box_reset_closes_the_record_and_removes_nothing() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, FIN | ACK, Instant { ms: 1 }));
        // The box still acknowledges what arrives after its FIN.
        assert!(f.reply(c, ACK, Instant { ms: 2 }));
        assert!(f.reply(c, RST, Instant { ms: 3 }));
        assert_eq!(f.len(), 1);
        // The reset sent again passes inside the closed window, and extends
        // nothing.
        assert!(f.reply(c, RST, Instant { ms: 4 }));
        assert!(f.reply(
            c,
            ACK,
            Instant {
                ms: 3 + W.tcp_closed_ms - 1
            }
        ));
        assert!(!f.reply(
            c,
            ACK,
            Instant {
                ms: 3 + W.tcp_closed_ms
            }
        ));
    }

    #[test]
    fn a_connect_after_a_reset_reopens_the_record() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(f.inbound(c, RST, Instant { ms: 1 }), Inbound::Ended);
        assert_eq!(
            f.inbound(c, SYN, Instant { ms: 2 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(f.reply(
            c,
            SYN | ACK,
            Instant {
                ms: 2 + W.tcp_closed_ms
            }
        ));
    }

    #[test]
    fn a_half_closed_connection_lives_while_it_carries_data() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, FIN | ACK, Instant { ms: 1_000 }));
        // One side has closed: each frame renews the closing window.
        let mut at = 1_000;
        while at < 600_000 {
            at += 100_000;
            assert_eq!(
                f.inbound(c, ACK, Instant { ms: at }),
                Inbound::Refreshed { replied: false }
            );
            assert!(f.reply(c, ACK, Instant { ms: at + 1 }));
        }
        // And without one it ends when that window has run, not the idle one.
        assert!(f.reply(c, ACK, Instant { ms: at + 120_000 }));
        assert!(!f.reply(
            c,
            ACK,
            Instant {
                ms: at + 120_000 + 120_001
            }
        ));
    }

    #[test]
    fn the_first_fin_shortens_the_life_to_the_closing_window() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, FIN | ACK, Instant { ms: 1_000 }));
        // Alive just inside the closing window, gone at its end, well before
        // the idle window's.
        assert!(f.has_live(c, Instant { ms: 120_999 }));
        assert!(!f.has_live(c, Instant { ms: 121_000 }));
    }

    #[test]
    fn a_finished_close_lingers_for_the_closed_window_and_is_not_renewed() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, FIN | ACK, Instant { ms: 1_000 }));
        assert_eq!(
            f.inbound(c, FIN | ACK, Instant { ms: 2_000 }),
            Inbound::Refreshed { replied: false }
        );
        // The box's last acknowledgement, and one sent again, still pass.
        assert!(f.reply(c, ACK, Instant { ms: 2_001 }));
        assert!(f.reply(c, ACK, Instant { ms: 6_999 }));
        // Nothing renews it: it ends five seconds after the second FIN.
        assert!(!f.reply(c, ACK, Instant { ms: 7_000 }));
    }

    #[test]
    fn the_client_closing_first_reaches_the_same_end() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(c, FIN | ACK, Instant { ms: 1_000 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(f.reply(c, FIN | ACK, Instant { ms: 2_000 }));
        assert_eq!(
            f.inbound(c, ACK, Instant { ms: 2_001 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(!f.has_live(c, Instant { ms: 7_000 }));
    }

    #[test]
    fn an_opening_packet_on_a_closing_record_makes_it_open_again() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, FIN | ACK, Instant { ms: 1_000 }));
        assert_eq!(
            f.inbound(c, FIN | ACK, Instant { ms: 2_000 }),
            Inbound::Refreshed { replied: false }
        );
        // The same client and ports again, inside the closed window.
        assert_eq!(
            f.inbound(c, SYN, Instant { ms: 3_000 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(f.reply(c, SYN | ACK, Instant { ms: 3_001 }));
        // An open record: alive long after the closed window would have run.
        assert!(f.reply(c, ACK, Instant { ms: 200_000 }));
        // The box's own SYN-ACK or a late SYN from the box reopens nothing.
        assert!(f.reply(c, FIN | ACK, Instant { ms: 200_001 }));
        assert!(f.reply(c, SYN, Instant { ms: 200_002 }));
        assert!(!f.has_live(c, Instant { ms: 320_002 }));
    }

    #[test]
    fn the_closing_windows_are_ordered_and_above_zero() {
        let mut w = W;
        w.tcp_closed_ms = 0;
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
        let mut w = W;
        w.tcp_closed_ms = w.tcp_closing_ms + 1;
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
        let mut w = W;
        w.tcp_closing_ms = w.tcp_idle_ms + 1;
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
    }

    #[test]
    fn a_client_reset_closes_the_record_and_the_box_is_still_heard() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(c, FIN | ACK, Instant { ms: 1 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(f.reply(c, ACK, Instant { ms: 2 }));
        assert_eq!(f.inbound(c, RST, Instant { ms: 3 }), Inbound::Ended);
        assert_eq!(f.len(), 1);
        // The box's answer to the reset passes; nothing passes once the
        // closed window has run.
        assert!(f.reply(c, ACK, Instant { ms: 4 }));
        assert!(!f.reply(
            c,
            ACK,
            Instant {
                ms: 3 + W.tcp_closed_ms
            }
        ));
    }

    #[test]
    fn a_udp_answer_extends_the_record_and_a_later_datagram_does_not_shorten_it() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, 0, Instant { ms: 1_000 }));
        assert_eq!(
            f.inbound(c, 0, Instant { ms: 2_000 }),
            Inbound::Refreshed { replied: true }
        );
        assert!(f.reply(c, 0, Instant { ms: 300_000 }));
    }

    // A record reopened after the replied window starts unreplied.
    #[test]
    fn a_reopened_udp_record_starts_unreplied() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, 0, Instant { ms: 1_000 }));
        assert_eq!(f.inbound(c, 0, Instant { ms: 302_000 }), Inbound::Opened);
        assert_eq!(
            f.inbound(c, 0, Instant { ms: 312_000 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(!f.reply(c, 0, Instant { ms: 342_001 }));
    }

    // A datagram on a replied record keeps the replied window.
    #[test]
    fn a_datagram_on_a_replied_record_keeps_the_replied_window() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert!(f.reply(c, 0, Instant { ms: 1_000 }));
        assert_eq!(
            f.inbound(c, 0, Instant { ms: 40_000 }),
            Inbound::Refreshed { replied: true }
        );
        assert!(f.reply(c, 0, Instant { ms: 70_001 }));
    }

    // After the refresh the record ends at t2 + R, past the first reply's
    // t1 + R.
    #[test]
    fn a_refresh_on_a_replied_record_ends_at_the_replied_window() {
        for (at, admitted) in [(339_999, true), (340_000, false)] {
            let mut f = flows();
            let c = conv(UDP, 1, 5000, 53);
            assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
            assert!(f.reply(c, 0, Instant { ms: 1_000 }));
            assert_eq!(
                f.inbound(c, 0, Instant { ms: 40_000 }),
                Inbound::Refreshed { replied: true }
            );
            assert_eq!(f.reply(c, 0, Instant { ms: at }), admitted);
        }
    }

    #[test]
    fn a_datagram_before_any_reply_buys_the_unreplied_window_only() {
        let mut f = flows();
        let c = conv(UDP, 1, 5000, 53);
        assert_eq!(f.inbound(c, 0, Instant { ms: 0 }), Inbound::Opened);
        assert_eq!(
            f.inbound(c, 0, Instant { ms: 10_000 }),
            Inbound::Refreshed { replied: false }
        );
        assert!(!f.reply(c, 0, Instant { ms: 40_000 }));
    }

    #[test]
    fn a_replied_window_shorter_than_the_unreplied_one_is_refused() {
        let mut w = W;
        w.udp_replied_ms = w.udp_unreplied_ms - 1;
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
    }

    #[test]
    fn one_client_may_fill_the_table_and_then_everyone_finds_it_full() {
        let mut f = flows();
        assert_eq!(
            f.inbound(conv(TCP, 1, 1, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 1, 2, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 1, 3, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 1, 4, 80), SYN, Instant { ms: 0 }),
            Inbound::Opened
        );
        assert_eq!(
            f.inbound(conv(TCP, 1, 5, 80), SYN, Instant { ms: 0 }),
            Inbound::TableFull
        );
        assert_eq!(
            f.inbound(conv(TCP, 2, 5, 80), SYN, Instant { ms: 0 }),
            Inbound::TableFull
        );
        assert_eq!(f.len(), 4);
    }

    #[test]
    fn a_frame_for_another_box_changes_nothing() {
        let mut f = flows();
        let mut c = conv(TCP, 1, 40000, 8080);
        c.box_addr = BOX + 1;
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::NotThisBox);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn clear_ends_every_record() {
        let mut f = flows();
        let c = conv(TCP, 1, 40000, 8080);
        assert_eq!(f.inbound(c, SYN, Instant { ms: 0 }), Inbound::Opened);
        f.clear();
        assert!(!f.reply(c, ACK, Instant { ms: 1 }));
    }

    #[test]
    fn a_zero_window_is_refused() {
        let mut w = W;
        w.udp_unreplied_ms = 0;
        assert!(Flows::new(BOX, 4, w, Span { ms: 1_000 }).is_none());
    }
}

#[cfg(kani)]
mod proofs {
    //! Bounded checks in the same shape as the table's: one operation from
    //! an arbitrary table that satisfies G7, every field of the frame and
    //! every instant unconstrained, checked against plain scans and a key
    //! spelled a second way.
    //!
    //! Every table of up to `MAX` records is covered, one shape to a
    //! harness: a shape is a capacity, a slab length and a number of
    //! records, as plain numbers, and there are forty of them, named
    //! `c<capacity>_<slots>_<records>`. The contents before and after are
    //! kept in arrays and read by row and key at arbitrary places, never
    //! compared whole. Where `inbound` can give records up and then add
    //! one, its check is in nine parts, a harness each, in a module named
    //! for the shape; together they assert what the whole check asserts.
    //! The harnesses `reached*` say which outcomes the largest shapes reach.

    use super::*;
    use crate::pool::{Entry, kani_lookup};

    const MAX: usize = 3;

    const NONE: Entry = Entry {
        row: 0,
        key: 0,
        deadline_ms: 0,
        value: 0,
    };

    // The parts of a divided check. `WHOLE` is all of them.
    const WHOLE: u8 = 0;
    const RESULT: u8 = 1;
    const KEPT: u8 = 2;
    const NOTHING_NEW: u8 = 3;
    const LIMITS: u8 = 4;
    const IN_RANGE: u8 = 5;
    const SORTED: u8 = 6;
    const QUOTA: u8 = 7;
    const FLOOR: u8 = 8;
    const FLAGS: u8 = 9;

    /// K1 over every input.
    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_key_injective() {
        let (p1, c1, b1): (u8, u16, u16) = (kani::any(), kani::any(), kani::any());
        let (p2, c2, b2): (u8, u16, u16) = (kani::any(), kani::any(), kani::any());
        if key(p1, c1, b1) == key(p2, c2, b2) {
            assert!(p1 == p2 && c1 == c2 && b1 == b2);
        }
    }

    /// The key, spelled with shifts where the code multiplies.
    fn key2(c: Conversation) -> u64 {
        ((c.proto as u64) << 32) | ((c.client_port as u64) << 16) | (c.box_port as u64)
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_flow_key_is_the_three_fields_side_by_side() {
        let c: Conversation = any_conversation();
        assert!(key(c.proto, c.client_port, c.box_port) == key2(c));
    }

    fn any_conversation() -> Conversation {
        Conversation {
            proto: kani::any(),
            client: kani::any(),
            client_port: kani::any(),
            box_addr: kani::any(),
            box_port: kani::any(),
        }
    }

    /// Any flow table of capacity `cap` with `m` slab slots and `n` records,
    /// for any box, with any windows above zero, and any mark.
    fn flows_shaped(cap: usize, m: usize, n: usize) -> Flows {
        flows_marked(cap, m, n, kani::any())
    }

    /// The same with the mark clear, as a plain value: no record is closed
    /// by both sides, and a step from it has no pass to consider. For the
    /// `inbound` steps of a full table, where the sweep and the pass in one
    /// formula are more than the checker decides; the pass at a full table
    /// has its own family, `capacity_step`.
    fn flows_unmarked(cap: usize, m: usize, n: usize) -> Flows {
        flows_marked(cap, m, n, false)
    }

    fn flows_marked(cap: usize, m: usize, n: usize, mark: bool) -> Flows {
        let windows = Windows {
            tcp_idle_ms: kani::any(),
            tcp_closing_ms: kani::any(),
            tcp_closed_ms: kani::any(),
            udp_unreplied_ms: kani::any(),
            udp_replied_ms: kani::any(),
            // The step harnesses read a table that gives up nothing.
            evict_after_ms: None,
        };
        kani::assume(
            windows.tcp_idle_ms > 0
                && windows.udp_unreplied_ms > 0
                && windows.udp_replied_ms >= windows.udp_unreplied_ms
                && windows.tcp_closed_ms > 0
                && windows.tcp_closed_ms <= windows.tcp_closing_ms
                && windows.tcp_closing_ms <= windows.tcp_idle_ms,
        );
        let pool = Slab::kani_shaped(cap, m, n);
        // No bound per client below the capacity.
        let (limit, per_client) = pool.kani_limits();
        kani::assume(per_client == limit);
        // The invariant's value clause: a flag, set only on a UDP record.
        // And its mark clause: clear only over a table that holds no record
        // closed by both sides.
        let mut i = 0;
        while i < pool.len() {
            kani::assume(flag_holds(pool.kani_at(i)));
            kani::assume(mark || pool.kani_at(i).value != 6);
            i += 1;
        }
        Flows {
            pool,
            box_addr: kani::any(),
            windows,
            throttle: Throttle {
                interval_ms: kani::any(),
                last_ms: kani::any(),
            },
            may_hold_closed: mark,
        }
    }

    /// The invariant's mark clause, at one arbitrary place.
    fn the_mark_holds(f: &Flows) {
        let i: usize = kani::any();
        if i < f.pool.len() {
            assert!(f.may_hold_closed || f.pool.kani_at(i).value != 6);
        }
    }

    fn flag_holds(e: Entry) -> bool {
        e.value == 0
            || (e.value == 1 && ((e.key >> 32) == UDP as u64 || (e.key >> 32) == TCP as u64))
            || ((e.value == 2 || e.value == 4 || e.value == 6) && (e.key >> 32) == TCP as u64)
    }

    /// A TCP record's value after a segment, spelled with bits where the
    /// code compares: 2 is the box's FIN, 4 the client's.
    fn value2(v: u32, flags: u8, from_box: bool) -> u32 {
        let opening = flags & (SYN | ACK) == SYN;
        if flags & RST != 0 {
            6
        } else if opening && !from_box {
            if v <= 1 { v } else { 0 }
        } else if flags & FIN == 0 {
            if from_box && v == 0 { 1 } else { v }
        } else if from_box {
            if v <= 1 { 2 } else { v | 2 }
        } else if v <= 1 {
            4
        } else {
            v | 4
        }
    }

    /// When a TCP record ends after a segment, spelled as a table.
    fn deadline2(w: Windows, was: u64, before: u32, after: u32, now: u64) -> u64 {
        let same = before == after;
        match (after, same) {
            (0, _) | (1, _) => was.max(now.saturating_add(w.tcp_idle_ms)),
            (6, true) => was,
            (6, false) => now.saturating_add(w.tcp_closed_ms),
            (_, true) => was.max(now.saturating_add(w.tcp_closing_ms)),
            (_, false) => now.saturating_add(w.tcp_closing_ms),
        }
    }

    /// The contents in an array, and how many there are.
    fn snapshot(t: &Slab) -> ([Entry; MAX], usize) {
        let mut out = [NONE; MAX];
        let mut i = 0;
        while i < t.len() {
            out[i] = t.kani_at(i);
            i += 1;
        }
        (out, t.len())
    }

    /// One conjunct of the table's invariant, at one arbitrary place: what
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

    /// One arbitrary entry of the table carries a flag.
    fn every_value_is_a_flag(t: &Slab) {
        let j: usize = kani::any();
        if j < t.len() {
            assert!(flag_holds(t.kani_at(j)));
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

    /// An arbitrary entry of `now`, other than the one for `(row, key)`, was
    /// held before as it is.
    fn nothing_else_is_new(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let v: usize = kani::any();
        if v < now.len() && !(now[v].row == row && now[v].key == key) {
            assert!(kani_lookup(before, now[v].row, now[v].key) == Some(now[v]));
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

    /// `now` is `before` without its entry for `(row, key)`, every other
    /// entry in its place: one arbitrary position is compared.
    fn removed_in_place(before: &[Entry], now: &[Entry], row: u32, key: u64) {
        let mut i = 0;
        while i < before.len() && !(before[i].row == row && before[i].key == key) {
            i += 1;
        }
        assert!(i < before.len());
        assert!(now.len() + 1 == before.len());
        let j: usize = kani::any();
        if j < now.len() {
            let j0 = if j < i { j } else { j + 1 };
            assert!(now[j] == before[j0]);
        }
    }

    /// One `reply` from a table. G6 (a), (b), (c), (f). Returns whether it
    /// was admitted, the protocol, whether the flags close, the value of the
    /// record held for the conversation, whether the frame names the box,
    /// whether the record was live, and whether the table is one record
    /// shorter.
    fn reply_from(mut f: Flows) -> (bool, u8, bool, Option<u32>, bool, bool, bool) {
        let (before, len) = snapshot(&f.pool);
        let before = &before[..len];
        let (box_addr, w) = (f.box_addr, f.windows);
        let (limits, th, mark) = (f.pool.kani_limits(), f.throttle, f.may_hold_closed);
        let c = any_conversation();
        let (flags, now): (u8, u64) = (kani::any(), kani::any());
        let k = key2(c);
        let held = kani_lookup(before, c.client, k);
        let live = match held {
            Some(e) => e.deadline_ms > now,
            None => false,
        };
        let expected = c.box_addr == box_addr && (c.proto == TCP || c.proto == UDP) && live;
        // The frame touches its own record: this box, TCP or UDP, held.
        let touches =
            c.box_addr == box_addr && (c.proto == TCP || c.proto == UDP) && held.is_some();
        let admitted = f.reply(c, flags, Instant { ms: now });
        assert!(admitted == expected);
        assert!(f.pool.kani_holds());
        assert!(f.box_addr == box_addr);
        assert!(f.windows == w && f.throttle == th && f.pool.kani_limits() == limits);
        let (after, len) = snapshot(&f.pool);
        let after = &after[..len];
        nothing_else_is_new(before, after, c.client, k);
        another_is_kept(before, after, c.client, k);
        if !admitted && touches {
            // Held and not live: expired, and removed in place.
            removed_in_place(before, after, c.client, k);
            assert!(f.may_hold_closed == mark);
        } else if !admitted {
            unchanged(before, after);
            assert!(f.may_hold_closed == mark);
        } else {
            let (was, kept) = match held {
                Some(e) => (e.deadline_ms, e.value),
                None => (0, 0),
            };
            let value = if c.proto == UDP {
                1
            } else {
                value2(kept, flags, true)
            };
            let want = if c.proto == UDP {
                was.max(now.saturating_add(w.udp_replied_ms))
            } else {
                deadline2(w, was, kept, value, now)
            };
            assert!(
                kani_lookup(after, c.client, k)
                    == Some(Entry {
                        row: c.client,
                        key: k,
                        deadline_ms: want,
                        value,
                    })
            );
            assert!(after.len() == before.len());
            // The mark is set by a segment that leaves the record closed by
            // both sides, and by nothing else.
            assert!(f.may_hold_closed == (mark || value == 6));
        }
        every_value_is_a_flag(&f.pool);
        the_mark_holds(&f);
        (
            admitted,
            c.proto,
            flags & (FIN | RST) != 0,
            held.map(|e| e.value),
            c.box_addr == box_addr,
            live,
            after.len() + 1 == before.len(),
        )
    }

    /// One `inbound` from a table, asserting `part` of its check. G6 (d),
    /// (e), (f), (k). Returns the outcome, whether a sweep was due, the
    /// numbers of records before and after, whether the first record had
    /// expired, whether the frame was TCP, and whether it was TCP or UDP.
    fn inbound_from(mut f: Flows, part: u8) -> (Inbound, bool, usize, usize, bool, bool, bool) {
        let (before, len) = snapshot(&f.pool);
        let before = &before[..len];
        let (cap, _) = f.pool.kani_limits();
        let (box_addr, w, th, mark) = (f.box_addr, f.windows, f.throttle, f.may_hold_closed);
        let c = any_conversation();
        let (flags, now): (u8, u64) = (kani::any(), kani::any());
        let k = key2(c);
        let held = kani_lookup(before, c.client, k);
        let live = match held {
            Some(e) => e.deadline_ms > now,
            None => false,
        };
        let flow_proto = c.proto == TCP || c.proto == UDP;
        let opening = c.proto == UDP || (c.proto == TCP && flags & SYN != 0 && flags & ACK == 0);
        // A sweep is due: none has run, or the interval has passed; with time
        // behind the last sweep, only at an interval of zero.
        let due = match th.last_ms {
            None => true,
            Some(last) => {
                if now < last {
                    th.interval_ms == 0
                } else {
                    (now as u128) >= (last as u128) + (th.interval_ms as u128)
                }
            }
        };
        let sweeps = c.box_addr == box_addr
            && flow_proto
            && opening
            && held.is_none()
            && before.len() >= cap
            && due;
        // The pass of G6 (q) runs: the frame would open a record at the
        // capacity, no sweep that was due found an expired record, and the
        // mark is set.
        let mut some_expired = false;
        let mut some_closed = false;
        let mut n = 0;
        while n < before.len() {
            if before[n].deadline_ms <= now {
                some_expired = true;
            }
            if before[n].value == 6 {
                some_closed = true;
            }
            n += 1;
        }
        let passes = c.box_addr == box_addr
            && flow_proto
            && opening
            && held.is_none()
            && before.len() >= cap
            && !(due && some_expired)
            && mark;
        let window = if c.proto == TCP {
            w.tcp_idle_ms
        } else {
            w.udp_unreplied_ms
        };
        let fresh = now.saturating_add(window);
        let outcome = f.inbound(c, flags, Instant { ms: now });
        let first_expired = before.len() > 0 && before[0].deadline_ms <= now;
        let facts = (
            outcome,
            due,
            before.len(),
            f.pool.len(),
            first_expired,
            c.proto == TCP,
            flow_proto,
        );
        if part == FLAGS {
            every_value_is_a_flag(&f.pool);
            the_mark_holds(&f);
            return facts;
        }
        if part >= LIMITS {
            holds_at(&f.pool, part);
            return facts;
        }
        if part == WHOLE {
            assert!(f.pool.kani_holds());
            every_value_is_a_flag(&f.pool);
            the_mark_holds(&f);
        }
        let (after, len) = snapshot(&f.pool);
        let after = &after[..len];
        if part == WHOLE || part == RESULT {
            assert!(f.box_addr == box_addr);
            assert!(f.windows == w && f.pool.kani_limits() == (cap, cap));
            assert!(f.throttle.interval_ms == th.interval_ms);
            assert!(f.throttle.last_ms == if sweeps { Some(now) } else { th.last_ms });
            match outcome {
                Inbound::NotThisBox => {
                    assert!(c.box_addr != box_addr);
                    assert!(f.may_hold_closed == mark);
                }
                Inbound::Untracked => {
                    assert!(c.box_addr == box_addr);
                    assert!(!flow_proto || (!opening && !live));
                    assert!(f.may_hold_closed == mark);
                }
                Inbound::Opened => {
                    assert!(c.box_addr == box_addr && opening && !live);
                    assert!(
                        kani_lookup(after, c.client, k)
                            == Some(Entry {
                                row: c.client,
                                key: k,
                                deadline_ms: fresh,
                                value: 0,
                            })
                    );
                    assert!(after.len() <= before.len() + 1);
                    // The pass clears the mark; no other opening moves it.
                    assert!(f.may_hold_closed == (mark && !passes));
                    // Room at the capacity with no sweep due is the pass's,
                    // and the pass ran over a record closed by both sides.
                    if held.is_none() && before.len() >= cap && !due {
                        assert!(passes && some_closed);
                    }
                }
                Inbound::Refreshed { replied } => {
                    assert!(c.box_addr == box_addr && live);
                    assert!(!(c.proto == TCP && flags & RST != 0));
                    let (was, kept) = match held {
                        Some(e) => (e.deadline_ms, e.value),
                        None => (0, 0),
                    };
                    assert!(replied == (c.proto == UDP && kept == 1));
                    assert!(!replied || c.proto == UDP);
                    let limit = if replied {
                        now.saturating_add(w.udp_replied_ms)
                    } else {
                        fresh
                    };
                    let value = if c.proto == TCP {
                        value2(kept, flags, false)
                    } else {
                        kept
                    };
                    let want = if c.proto == TCP {
                        deadline2(w, was, kept, value, now)
                    } else if was >= limit {
                        was
                    } else {
                        limit
                    };
                    assert!(
                        kani_lookup(after, c.client, k)
                            == Some(Entry {
                                row: c.client,
                                key: k,
                                deadline_ms: want,
                                value,
                            })
                    );
                    assert!(after.len() == before.len());
                    assert!(f.may_hold_closed == (mark || value == 6));
                }
                Inbound::Ended => {
                    assert!(c.box_addr == box_addr && live && c.proto == TCP && flags & RST != 0);
                    let (was, kept) = match held {
                        Some(e) => (e.deadline_ms, e.value),
                        None => (0, 0),
                    };
                    assert!(
                        kani_lookup(after, c.client, k)
                            == Some(Entry {
                                row: c.client,
                                key: k,
                                deadline_ms: deadline2(w, was, kept, 6, now),
                                value: 6,
                            })
                    );
                    assert!(after.len() == before.len());
                    assert!(f.may_hold_closed);
                }
                Inbound::TableFull => {
                    assert!(c.box_addr == box_addr && opening && held.is_none());
                    assert!(before.len() >= cap);
                    // A sweep that was due ran, and found nothing expired.
                    let j: usize = kani::any();
                    if due && j < before.len() {
                        assert!(before[j].deadline_ms > now);
                    }
                    // Never refused over a record closed by both sides.
                    assert!(!some_closed);
                    assert!(f.may_hold_closed == (mark && !passes));
                }
            }
        }
        if part == WHOLE || part == KEPT {
            match outcome {
                Inbound::Opened => {
                    // An entry that has not expired is never given up for
                    // it, but one closed by both sides when the pass runs:
                    // those go, expired or not.
                    let x: usize = kani::any();
                    if x < before.len() && !(before[x].row == c.client && before[x].key == k) {
                        let now_held = kani_lookup(after, before[x].row, before[x].key);
                        if passes && before[x].value == 6 {
                            assert!(now_held.is_none());
                        } else if before[x].deadline_ms > now {
                            assert!(now_held == Some(before[x]));
                        }
                    }
                }
                Inbound::Refreshed { .. } | Inbound::Ended => {
                    another_is_kept(before, after, c.client, k)
                }
                Inbound::NotThisBox | Inbound::Untracked | Inbound::TableFull => {}
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            match outcome {
                Inbound::NotThisBox | Inbound::TableFull => unchanged(before, after),
                Inbound::Untracked => {
                    if flow_proto && held.is_some() {
                        // Held and not live: expired, and removed in place.
                        removed_in_place(before, after, c.client, k);
                    } else {
                        unchanged(before, after);
                    }
                }
                Inbound::Opened | Inbound::Refreshed { .. } | Inbound::Ended => {}
            }
            nothing_else_is_new(before, after, c.client, k);
        }
        facts
    }

    /// One `open_at_capacity` on a full table, asserting `part` of its
    /// check. G6 (q), (r), and the refusal of (e). `throttled` is a plain
    /// value: each harness reads one of the two ways into the function.
    /// Returns the outcome, how many records were closed by both sides
    /// before, how many records there are after, and the mark before.
    fn at_capacity_from(mut f: Flows, throttled: bool, part: u8) -> (Inbound, usize, usize, bool) {
        let (before, len) = snapshot(&f.pool);
        let before = &before[..len];
        let (cap, _) = f.pool.kani_limits();
        let (box_addr, w, th, mark) = (f.box_addr, f.windows, f.throttle, f.may_hold_closed);
        let mut c = any_conversation();
        c.box_addr = box_addr;
        kani::assume(c.proto == TCP || c.proto == UDP);
        let now: u64 = kani::any();
        let k = key2(c);
        // What the function requires: the key is not held, the table is at
        // its capacity, and where a sweep was due nothing had expired.
        kani::assume(kani_lookup(before, c.client, k).is_none());
        kani::assume(before.len() >= cap);
        let mut closed: usize = 0;
        let mut i = 0;
        while i < before.len() {
            if !throttled {
                kani::assume(before[i].deadline_ms > now);
            }
            if before[i].value == 6 {
                closed += 1;
            }
            i += 1;
        }
        let window = if c.proto == TCP {
            w.tcp_idle_ms
        } else {
            w.udp_unreplied_ms
        };
        let fresh = now.saturating_add(window);
        let outcome = f.open_at_capacity(c, k, now, fresh, throttled);
        let facts = (outcome, closed, f.pool.len(), mark);
        if part == FLAGS {
            every_value_is_a_flag(&f.pool);
            the_mark_holds(&f);
            return facts;
        }
        if part >= LIMITS {
            holds_at(&f.pool, part);
            return facts;
        }
        let (after, len) = snapshot(&f.pool);
        let after = &after[..len];
        if part == RESULT {
            assert!(f.box_addr == box_addr);
            assert!(f.windows == w && f.throttle == th && f.pool.kani_limits() == (cap, cap));
            // The pass clears the mark, and with it clear nothing sets it.
            assert!(!f.may_hold_closed);
            // With no floor set the table gives up nothing else: the frame
            // is opened exactly when the mark is set over a record closed
            // by both sides.
            let opens = mark && closed > 0;
            assert!(outcome == Inbound::Opened || outcome == Inbound::TableFull);
            assert!((outcome == Inbound::Opened) == opens);
            if opens {
                assert!(
                    kani_lookup(after, c.client, k)
                        == Some(Entry {
                            row: c.client,
                            key: k,
                            deadline_ms: fresh,
                            value: 0,
                        })
                );
                assert!(after.len() + closed == before.len() + 1);
            }
        }
        if part == KEPT {
            // Every record closed by both sides goes with the pass, expired
            // or not, and no other record does.
            let x: usize = kani::any();
            if x < before.len() {
                let now_held = kani_lookup(after, before[x].row, before[x].key);
                if outcome == Inbound::Opened && before[x].value == 6 {
                    assert!(now_held.is_none());
                } else {
                    assert!(now_held == Some(before[x]));
                }
            }
        }
        if part == NOTHING_NEW {
            if outcome == Inbound::TableFull {
                unchanged(before, after);
            }
            nothing_else_is_new(before, after, c.client, k);
        }
        facts
    }

    /// The class a record may be given up in, spelled apart from the code.
    fn class2(w: Windows, floor: u64, e: Entry, now: u64) -> u8 {
        let tcp = (e.key >> 32) == TCP as u64;
        if tcp && e.value == 6 {
            1
        } else if tcp && (e.value == 2 || e.value == 4) {
            2
        } else if e.value == 0 {
            3
        } else {
            let window = if tcp { w.tcp_idle_ms } else { w.udp_replied_ms };
            if (e.deadline_ms as u128) + (floor as u128) <= (window as u128) + (now as u128) {
                4
            } else {
                5
            }
        }
    }

    /// The choice of the record a full table gives up, against the second
    /// reading of the classes: G6 (n). `Flows::victim` alone, at fixed
    /// windows and a bounded clock. The whole step that uses the choice
    /// (find nothing expired, choose, remove, insert) is not run here as one
    /// harness: no shape of it was decided within the limits; Verus has it
    /// for every table and every window, and the table operations it is
    /// made of have their own harnesses.
    fn victim_of(mut f: Flows) -> (Option<usize>, u8) {
        let floor: u64 = 300;
        f.windows = Windows {
            tcp_idle_ms: 7_440,
            tcp_closing_ms: 120,
            tcp_closed_ms: 10,
            udp_unreplied_ms: 30,
            udp_replied_ms: 300,
            evict_after_ms: Some(floor),
        };
        let w = f.windows;
        let (before, len) = snapshot(&f.pool);
        let before = &before[..len];
        let now: u64 = kani::any();
        kani::assume(now <= 1 << 16);
        let mut i = 0;
        while i < before.len() {
            kani::assume(before[i].deadline_ms <= 1 << 17);
            i += 1;
        }
        let got = f.victim(now);
        let x: usize = kani::any();
        kani::assume(x < before.len());
        let cx = class2(w, floor, before[x], now);
        match got {
            // No record is in a class.
            None => {
                assert!(cx == 5);
                (got, 0)
            }
            Some(at) => {
                assert!(at < before.len());
                let ca = class2(w, floor, before[at], now);
                // The record is in a class; none is in a lower one; none of
                // its class has an earlier deadline; and of those with its
                // deadline it is the first in the table's order.
                assert!(ca < 5);
                assert!(cx >= ca);
                if cx == ca {
                    assert!(before[x].deadline_ms >= before[at].deadline_ms);
                    if before[x].deadline_ms == before[at].deadline_ms {
                        assert!(x >= at);
                    }
                }
                (got, ca)
            }
        }
    }

    #[cfg(feature = "kani-full")]
    mod victim_choice {
        use super::*;

        macro_rules! chosen {
            ($name:ident, $cap:expr, $m:expr) => {
                #[kani::proof]
                #[kani::unwind(8)]
                fn $name() {
                    let _ = victim_of(flows_shaped($cap, $m, $cap));
                }
            };
        }
        chosen!(c1_1, 1, 1);
        chosen!(c1_2, 1, 2);
        chosen!(c2_2, 2, 2);
        chosen!(c2_4, 2, 4);
        chosen!(c3_3, 3, 3);
        chosen!(c3_6, 3, 6);

        // Every class is chosen for some table, and so is "none".
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (got, class) = victim_of(flows_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(got.is_some() && class == 1);
            kani::cover!(got.is_some() && class == 2);
            kani::cover!(got.is_some() && class == 3);
            kani::cover!(got.is_some() && class == 4);
            kani::cover!(got.is_none());
        }
    }

    /// One harness of `$check` for a table of one shape.
    macro_rules! shape {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(flows_shaped($cap, $m, $n));
            }
        };
    }

    /// One harness of `$check` for a table of one shape, asserting `$part`.
    macro_rules! shape_part {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(flows_shaped($cap, $m, $n), $part);
            }
        };
    }

    /// A module `$name` of nine harnesses of `$check` for a table of one
    /// shape, one part of the check to a harness.
    macro_rules! every_part {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            mod $name {
                use super::*;

                shape_part!($check, result, $cap, $m, $n, RESULT);
                shape_part!($check, kept, $cap, $m, $n, KEPT);
                shape_part!($check, nothing_new, $cap, $m, $n, NOTHING_NEW);
                shape_part!($check, limits, $cap, $m, $n, LIMITS);
                shape_part!($check, in_range, $cap, $m, $n, IN_RANGE);
                shape_part!($check, sorted, $cap, $m, $n, SORTED);
                shape_part!($check, quota, $cap, $m, $n, QUOTA);
                shape_part!($check, floor, $cap, $m, $n, FLOOR);
                shape_part!($check, flags, $cap, $m, $n, FLAGS);
            }
        };
    }

    /// The nine parts of `inbound`'s check for a full table of one shape,
    /// with the mark clear.
    macro_rules! every_full_part {
        ($name:ident, $cap:expr, $m:expr, $n:expr) => {
            mod $name {
                use super::*;
                full_part!(result, $cap, $m, $n, RESULT);
                full_part!(kept, $cap, $m, $n, KEPT);
                full_part!(nothing_new, $cap, $m, $n, NOTHING_NEW);
                full_part!(limits, $cap, $m, $n, LIMITS);
                full_part!(in_range, $cap, $m, $n, IN_RANGE);
                full_part!(sorted, $cap, $m, $n, SORTED);
                full_part!(quota, $cap, $m, $n, QUOTA);
                full_part!(floor, $cap, $m, $n, FLOOR);
                full_part!(flags, $cap, $m, $n, FLAGS);
            }
        };
    }

    macro_rules! full_part {
        ($name:ident, $cap:expr, $m:expr, $n:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = inbound_from(flows_unmarked($cap, $m, $n), $part);
            }
        };
    }

    /// The nine parts of the check of `open_at_capacity` for a full table of
    /// one shape, with any mark, by one of the two ways in.
    macro_rules! every_capacity_part {
        ($name:ident, $cap:expr, $m:expr, $throttled:expr) => {
            mod $name {
                use super::*;
                capacity_part!(result, $cap, $m, $throttled, RESULT);
                capacity_part!(kept, $cap, $m, $throttled, KEPT);
                capacity_part!(nothing_new, $cap, $m, $throttled, NOTHING_NEW);
                capacity_part!(limits, $cap, $m, $throttled, LIMITS);
                capacity_part!(in_range, $cap, $m, $throttled, IN_RANGE);
                capacity_part!(sorted, $cap, $m, $throttled, SORTED);
                capacity_part!(quota, $cap, $m, $throttled, QUOTA);
                capacity_part!(floor, $cap, $m, $throttled, FLOOR);
                capacity_part!(flags, $cap, $m, $throttled, FLAGS);
            }
        };
    }

    macro_rules! capacity_part {
        ($name:ident, $cap:expr, $m:expr, $throttled:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = at_capacity_from(flows_shaped($cap, $m, $cap), $throttled, $part);
            }
        };
    }

    /// One harness of `$check` for each shape of a table of up to `MAX`
    /// records.
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

    #[cfg(feature = "kani-full")]
    mod reply_step {
        use super::*;

        every_shape!(reply_from);

        // The outcomes reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (admitted, proto, closing, held, to_box, live, shorter) =
                reply_from(flows_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(admitted && proto == UDP && held == Some(0));
            kani::cover!(admitted && proto == TCP && closing);
            kani::cover!(admitted && proto == TCP && !closing);
            kani::cover!(admitted && proto == UDP);
            kani::cover!(!admitted && held.is_some() && to_box && proto == TCP);
            // An expired UDP record removed by the reply that touches it.
            kani::cover!(!admitted && proto == UDP && shorter);
            kani::cover!(!admitted && !to_box && live);
        }
    }

    #[cfg(feature = "kani-full")]
    mod inbound_step {
        use super::*;

        // The whole check, where the step cannot both give a record up and
        // add one: every table below its capacity, and capacity zero, where
        // nothing is added.
        shape_part!(inbound_from, c0_0_0, 0, 0, 0, WHOLE);
        shape_part!(inbound_from, c1_0_0, 1, 0, 0, WHOLE);
        shape_part!(inbound_from, c1_1_0, 1, 1, 0, WHOLE);
        shape_part!(inbound_from, c1_2_0, 1, 2, 0, WHOLE);
        shape_part!(inbound_from, c2_0_0, 2, 0, 0, WHOLE);
        shape_part!(inbound_from, c2_1_0, 2, 1, 0, WHOLE);
        shape_part!(inbound_from, c2_1_1, 2, 1, 1, WHOLE);
        shape_part!(inbound_from, c2_2_0, 2, 2, 0, WHOLE);
        shape_part!(inbound_from, c2_2_1, 2, 2, 1, WHOLE);
        shape_part!(inbound_from, c2_3_0, 2, 3, 0, WHOLE);
        shape_part!(inbound_from, c2_3_1, 2, 3, 1, WHOLE);
        shape_part!(inbound_from, c2_4_0, 2, 4, 0, WHOLE);
        shape_part!(inbound_from, c2_4_1, 2, 4, 1, WHOLE);
        shape_part!(inbound_from, c3_0_0, 3, 0, 0, WHOLE);
        shape_part!(inbound_from, c3_1_0, 3, 1, 0, WHOLE);
        shape_part!(inbound_from, c3_1_1, 3, 1, 1, WHOLE);
        shape_part!(inbound_from, c3_2_0, 3, 2, 0, WHOLE);
        shape_part!(inbound_from, c3_2_1, 3, 2, 1, WHOLE);
        shape_part!(inbound_from, c3_2_2, 3, 2, 2, WHOLE);
        shape_part!(inbound_from, c3_3_0, 3, 3, 0, WHOLE);
        shape_part!(inbound_from, c3_3_1, 3, 3, 1, WHOLE);
        shape_part!(inbound_from, c3_3_2, 3, 3, 2, WHOLE);
        shape_part!(inbound_from, c3_4_0, 3, 4, 0, WHOLE);
        shape_part!(inbound_from, c3_4_1, 3, 4, 1, WHOLE);
        shape_part!(inbound_from, c3_4_2, 3, 4, 2, WHOLE);
        shape_part!(inbound_from, c3_5_0, 3, 5, 0, WHOLE);
        shape_part!(inbound_from, c3_5_1, 3, 5, 1, WHOLE);
        shape_part!(inbound_from, c3_5_2, 3, 5, 2, WHOLE);
        shape_part!(inbound_from, c3_6_0, 3, 6, 0, WHOLE);
        shape_part!(inbound_from, c3_6_1, 3, 6, 1, WHOLE);
        shape_part!(inbound_from, c3_6_2, 3, 6, 2, WHOLE);

        // One part to a harness: the table full, where a sweep can give
        // records up before the new one is added.
        every_full_part!(c1_1_1, 1, 1, 1);
        every_full_part!(c1_2_1, 1, 2, 1);
        every_full_part!(c2_2_2, 2, 2, 2);
        every_full_part!(c2_3_2, 2, 3, 2);
        every_full_part!(c2_4_2, 2, 4, 2);
        every_full_part!(c3_3_3, 3, 3, 3);
        every_full_part!(c3_4_3, 3, 4, 3);
        every_full_part!(c3_5_3, 3, 5, 3);
        every_full_part!(c3_6_3, 3, 6, 3);

        // The outcomes reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, _, before, after, _, tcp, flow_proto) =
                inbound_from(flows_shaped(MAX, 2 * MAX, MAX - 1), LIMITS);
            kani::cover!(r == Inbound::Opened && after == before + 1);
            // Reopened in place.
            kani::cover!(r == Inbound::Opened && after == before);
            kani::cover!(r == Inbound::Refreshed { replied: false });
            kani::cover!(r == Inbound::Refreshed { replied: true });
            kani::cover!(r == Inbound::Ended);
            kani::cover!(r == Inbound::Untracked && tcp);
            kani::cover!(r == Inbound::Untracked && !flow_proto);
            // An expired record removed by a frame that opens nothing.
            kani::cover!(r == Inbound::Untracked && after + 1 == before);
            kani::cover!(r == Inbound::NotThisBox);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, due, before, after, first_expired, _, _) =
                inbound_from(flows_unmarked(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Inbound::TableFull && due);
            // Refused with an expired record in the table: no sweep was due.
            kani::cover!(r == Inbound::TableFull && !due && before > 0 && first_expired);
            // Room made by giving up an expired record, or reopened in place.
            kani::cover!(r == Inbound::Opened && after == before);
            // Opened by a sweep that removed more than one record.
            kani::cover!(r == Inbound::Opened && after + 1 < before);
        }
    }

    #[cfg(feature = "kani-full")]
    mod capacity_step {
        use super::*;

        // `open_at_capacity` alone, on every shape of a full table, by each
        // of its two ways in: no sweep was due, or one was and found
        // nothing expired. `inbound` reaches it only after the sweep's
        // insert returned without room, so nothing of the sweep is in these
        // formulas.
        every_capacity_part!(c1_1_throttled, 1, 1, true);
        every_capacity_part!(c1_1_due, 1, 1, false);
        every_capacity_part!(c1_2_throttled, 1, 2, true);
        every_capacity_part!(c1_2_due, 1, 2, false);
        every_capacity_part!(c2_2_throttled, 2, 2, true);
        every_capacity_part!(c2_2_due, 2, 2, false);
        every_capacity_part!(c2_3_throttled, 2, 3, true);
        every_capacity_part!(c2_3_due, 2, 3, false);
        every_capacity_part!(c2_4_throttled, 2, 4, true);
        every_capacity_part!(c2_4_due, 2, 4, false);
        every_capacity_part!(c3_3_throttled, 3, 3, true);
        every_capacity_part!(c3_3_due, 3, 3, false);
        every_capacity_part!(c3_4_throttled, 3, 4, true);
        every_capacity_part!(c3_4_due, 3, 4, false);
        every_capacity_part!(c3_5_throttled, 3, 5, true);
        every_capacity_part!(c3_5_due, 3, 5, false);
        every_capacity_part!(c3_6_throttled, 3, 6, true);
        every_capacity_part!(c3_6_due, 3, 6, false);

        // The outcomes reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, closed, after, mark) =
                at_capacity_from(flows_shaped(MAX, 2 * MAX, MAX), true, LIMITS);
            // One finished conversation gives its place; all of them do.
            kani::cover!(r == Inbound::Opened && closed == 1 && after == MAX);
            kani::cover!(r == Inbound::Opened && closed == MAX && after == 1);
            // Refused with the mark set over a table that holds none, and
            // with it clear.
            kani::cover!(r == Inbound::TableFull && mark);
            kani::cover!(r == Inbound::TableFull && !mark);
        }
    }
}
