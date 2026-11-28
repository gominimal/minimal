//! One box's refusal notes: the connects it may answer with a reset.
//!
//! Layer 1 of the crate, a bounded table. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A client's SYN delivered to a port nothing publishes is answered by a
//! reset from the box's side. That reset is a frame the box sends to an
//! address its rules may refuse, so the gate notes the SYN when it delivers
//! it, and admits exactly the reset that answers it, once.
//!
//! THEOREM N1, for every sequence of operations on a [`Notes`]:
//!   (a) `refusal` admits a segment exactly when it names this box, is
//!       RST|ACK with sequence number 0 and no payload, and the table holds
//!       an unexpired note for the same client and both ports whose number
//!       is the segment's acknowledgement number;
//!   (b) an admitted refusal consumes its note and no other, so one delivered
//!       SYN buys at most one reset; a refused one changes nothing;
//!   (c) `note_connect` notes only a segment addressed to this box whose SYN
//!       flag is set and whose ACK and RST flags are clear, and what it notes
//!       admits the answering reset at the same instant; a connect on ports
//!       already noted replaces the note's number with its own, so the note
//!       answers the latest connect on those ports and no earlier one: no
//!       other operation puts a number at those ports
//!       (`theorem_n1_connect_elsewhere_adds_nothing`,
//!       `theorem_n1_refusal_adds_nothing`; an expiry and `clear` only
//!       remove);
//!   (d) a connect is not noted for want of room only when its client's row,
//!       or the table, is full of notes that have not expired;
//!   (e) the table keeps G7: a hard capacity, and a quota per client address,
//!       and holds at most one note per client and pair of ports.
//!
//! A note's key is the two ports; the acknowledgement number is its value.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::flow::{ACK, FIN, RST, SYN};
#[cfg(verus_keep_ghost)]
use crate::flow::{add_ms_spec, lemma_same_no_new_keys, lemma_subset_no_new_keys, no_new_keys};
use crate::pool::Inserted;
#[cfg(verus_keep_ghost)]
use crate::pool::{
    Entry, bounded_by, count, distinct_keys, extended, has, holds, keeps_live, keeps_others,
    none_expired, not_shortened, only_adds, refreshed_from, row_live, subset_of,
};
use crate::slab::Slab;
#[cfg(verus_keep_ghost)]
use crate::slab::{scap, sinv, squota, sview};
use crate::time::{Instant, Span};

/// A TCP segment between a client and a box, named by its ends. For
/// `note_connect` it is a segment the client sent; for `refusal`, one the box
/// sent. `seq`, `ack` and `payload_len` are the segment's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Segment {
    pub client: u32,
    pub client_port: u16,
    pub box_addr: u32,
    pub box_port: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: u16,
}

/// What noting a delivered segment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Noted {
    /// The connect is noted.
    Noted,
    /// A connect on ports already noted: the note now carries this connect's
    /// number and runs at least as long.
    Renoted,
    /// Not a connect: the SYN flag is clear, or ACK or RST is set. Nothing changed.
    NotAConnect,
    /// Not addressed to this box. Nothing changed.
    NotThisBox,
    /// This client holds its quota of notes, none expired. Nothing changed:
    /// the connect will time out, never be admitted.
    ClientAtQuota,
    /// The table is full of notes that have not expired. Nothing changed.
    Full,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Notes {
    pool: Slab,
    box_addr: u32,
    window_ms: u64,
}

#[cfg(verus_keep_ghost)]
verus! {

/// The acknowledgement number a reply to a SYN at `seq` carrying
/// `payload_len` bytes gives: the payload, one for the SYN, and one more if
/// FIN is set. Sequence numbers live on a circle.
pub open spec fn answering_ack(seq: u32, payload_len: u16, flags: u8) -> u32 {
    ((seq as int + payload_len as int + 1 + if flags & FIN != 0 { 1int } else { 0int }) % 0x1_0000_0000) as u32
}

/// The key of a note inside its client's row: both ports, in fixed positions.
pub open spec fn note_key(client_port: u16, box_port: u16) -> u64 {
    (client_port as u64 * 0x1_0000 + box_port as u64) as u64
}

/// A segment whose SYN flag is set and whose ACK and RST flags are clear.
pub open spec fn is_connect(flags: u8) -> bool {
    flags & (SYN | ACK | RST) == SYN
}

/// The one shape of reset a note admits: RST|ACK, sequence 0, no payload.
pub open spec fn is_refusal_shape(s: Segment) -> bool {
    s.flags == RST | ACK && s.seq == 0 && s.payload_len == 0
}

pub closed spec fn pool_of(n: Notes) -> Slab { n.pool }
pub closed spec fn box_of(n: Notes) -> u32 { n.box_addr }
pub closed spec fn window_of(n: Notes) -> u64 { n.window_ms }

pub open spec fn table(n: Notes) -> Seq<Entry> { sview(pool_of(n)) }

#[verifier::opaque]
pub open spec fn ninv(n: Notes) -> bool {
    sinv(pool_of(n)) && window_of(n) > 0
}

pub open spec fn same_frame(now: Notes, before: Notes) -> bool {
    &&& box_of(now) == box_of(before)
    &&& window_of(now) == window_of(before)
    &&& scap(pool_of(now)) == scap(pool_of(before))
    &&& squota(pool_of(now)) == squota(pool_of(before))
}

/// The key a connect `s` is noted under.
pub open spec fn connect_key(s: Segment) -> u64 {
    note_key(s.client_port, s.box_port)
}

/// The number a connect `s` leaves in its note: the acknowledgement number
/// its refusal must carry.
pub open spec fn connect_ack(s: Segment) -> u32 {
    answering_ack(s.seq, s.payload_len, s.flags)
}

/// The key a refusal `s` looks for.
pub open spec fn refusal_key(s: Segment) -> u64 {
    note_key(s.client_port, s.box_port)
}

/// The table holds an unexpired note at `(row, key)` whose number is `ack`.
pub open spec fn noted_live(s: Seq<Entry>, row: u32, key: u64, now_ms: u64, ack: u32) -> bool {
    exists|j: int| 0 <= j < s.len() && s[j].row == row && s[j].key == key
        && s[j].deadline_ms > now_ms && s[j].value == ack
}

/// Two notes of one client with the same key have the same ports.
pub proof fn lemma_note_key_injective(c1: u16, b1: u16, c2: u16, b2: u16)
    requires
        note_key(c1, b1) == note_key(c2, b2),
    ensures
        c1 == c2 && b1 == b2,
{
}

/// An unexpired entry is a live note with its own number.
pub proof fn lemma_has_noted(s: Seq<Entry>, e: Entry, now_ms: u64)
    requires
        has(s, e),
        e.deadline_ms > now_ms,
    ensures
        noted_live(s, e.row, e.key, now_ms, e.value),
        holds(s, e.row, e.key),
{
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].row == e.row && s[k].key == e.key && s[k].deadline_ms > now_ms && s[k].value == e.value);
}

/// Keys are distinct, so an entry that has expired or carries another number
/// is the only one for its row and key, and no note there is live with `ack`.
pub proof fn lemma_not_noted(s: Seq<Entry>, e: Entry, now_ms: u64, ack: u32)
    requires
        distinct_keys(s),
        has(s, e),
        e.deadline_ms <= now_ms || e.value != ack,
    ensures
        !noted_live(s, e.row, e.key, now_ms, ack),
{
    reveal(crate::pool::distinct_keys);
    let k = choose|k: int| 0 <= k < s.len() && s[k] == e;
    assert(s[k].row == e.row && s[k].key == e.key);
    if noted_live(s, e.row, e.key, now_ms, ack) {
        let j = choose|j: int|
            0 <= j < s.len() && s[j].row == e.row && s[j].key == e.key
                && s[j].deadline_ms > now_ms && s[j].value == ack;
        if j < k {
            assert(!(s[j].row == s[k].row && s[j].key == s[k].key));
        } else if k < j {
            assert(!(s[k].row == s[j].row && s[k].key == s[j].key));
        }
    }
}

/// A row and key the table does not hold has no live note.
pub proof fn lemma_not_held_not_noted(s: Seq<Entry>, row: u32, key: u64, now_ms: u64, ack: u32)
    requires
        !holds(s, row, key),
    ensures
        !noted_live(s, row, key, now_ms, ack),
{
    if noted_live(s, row, key, now_ms, ack) {
        let j = choose|j: int|
            0 <= j < s.len() && s[j].row == row && s[j].key == key
                && s[j].deadline_ms > now_ms && s[j].value == ack;
        assert(s[j].row == row && s[j].key == key);
    }
}

/// What `note_connect` promises of its result and of the table before and after.
pub open spec fn noted_post(before: Notes, after: Notes, s: Segment, now_ms: u64, r: Noted) -> bool {
    match r {
        Noted::Noted => {
            &&& s.box_addr == box_of(before)
            &&& is_connect(s.flags)
            &&& !holds(table(before), s.client, connect_key(s))
            &&& has(table(after), Entry {
                row: s.client,
                key: connect_key(s),
                deadline_ms: add_ms_spec(now_ms, window_of(before)),
                value: connect_ack(s),
            })
            &&& only_adds(table(after), table(before), Entry {
                row: s.client,
                key: connect_key(s),
                deadline_ms: add_ms_spec(now_ms, window_of(before)),
                value: connect_ack(s),
            })
            &&& keeps_live(table(after), table(before), now_ms)
            &&& table(after).len() <= table(before).len() + 1
            &&& now_ms < u64::MAX ==> noted_live(table(after), s.client, connect_key(s), now_ms, connect_ack(s))
        },
        Noted::Renoted => {
            &&& s.box_addr == box_of(before)
            &&& is_connect(s.flags)
            &&& holds(table(before), s.client, connect_key(s))
            &&& refreshed_from(table(after), table(before), s.client, connect_key(s))
            &&& not_shortened(table(after), table(before))
            &&& bounded_by(table(after), table(before), add_ms_spec(now_ms, window_of(before)))
            &&& extended(table(after), table(before), s.client, connect_key(s), add_ms_spec(now_ms, window_of(before)), Some(connect_ack(s)))
            &&& now_ms < u64::MAX ==> noted_live(table(after), s.client, connect_key(s), now_ms, connect_ack(s))
        },
        Noted::NotAConnect => {
            &&& s.box_addr == box_of(before)
            &&& !is_connect(s.flags)
            &&& table(after) == table(before)
        },
        Noted::NotThisBox => {
            &&& s.box_addr != box_of(before)
            &&& table(after) == table(before)
        },
        Noted::ClientAtQuota => {
            &&& s.box_addr == box_of(before)
            &&& table(after) == table(before)
            &&& is_connect(s.flags)
            &&& !holds(table(before), s.client, connect_key(s))
            &&& count(table(before), s.client) >= squota(pool_of(before))
            &&& row_live(table(before), s.client, now_ms)
        },
        Noted::Full => {
            &&& s.box_addr == box_of(before)
            &&& table(after) == table(before)
            &&& is_connect(s.flags)
            &&& !holds(table(before), s.client, connect_key(s))
            &&& table(before).len() >= scap(pool_of(before))
            &&& none_expired(table(before), now_ms)
        },
    }
}

/// What `refusal` promises of its result and of the table before and after.
pub open spec fn refusal_post(before: Notes, after: Notes, s: Segment, now_ms: u64, r: bool) -> bool {
    &&& same_frame(after, before)
    &&& r == (s.box_addr == box_of(before) && is_refusal_shape(s)
        && noted_live(table(before), s.client, refusal_key(s), now_ms, s.ack))
    &&& no_new_keys(table(after), table(before))
    &&& !r ==> table(after) == table(before)
    &&& r ==> !holds(table(after), s.client, refusal_key(s))
    &&& r ==> keeps_others(table(after), table(before), s.client, refusal_key(s))
    &&& r ==> table(after).len() + 1 == table(before).len()
    &&& r ==> subset_of(table(after), table(before))
}

/// N1 (d): a connect to this box that is already noted is renoted, never
/// refused for room and never noted twice.
pub proof fn theorem_n1_held_is_renoted(before: Notes, after: Notes, s: Segment, now_ms: u64, r: Noted)
    requires
        noted_post(before, after, s, now_ms, r),
        s.box_addr == box_of(before),
        is_connect(s.flags),
        holds(table(before), s.client, connect_key(s)),
    ensures
        r == Noted::Renoted,
{
}

/// N1 (a): a reset on noted ports that carries another number than the
/// note's is refused, whatever else the table holds.
pub proof fn theorem_n1_another_number_is_refused(before: Notes, after: Notes, s: Segment, now_ms: u64, r: bool, e: Entry)
    requires
        ninv(before),
        refusal_post(before, after, s, now_ms, r),
        has(table(before), e),
        e.row == s.client,
        e.key == refusal_key(s),
        e.value != s.ack,
    ensures
        !r,
{
    reveal(ninv);
    lemma_not_noted(table(before), e, now_ms, s.ack);
}

/// N1 (c): once a connect is noted or renoted, the note on its ports answers
/// that connect and no earlier one: a reset there with any other number is
/// refused.
pub proof fn theorem_n1_latest_connect_only(
    before: Notes,
    mid: Notes,
    after: Notes,
    c: Segment,
    now_ms: u64,
    n: Noted,
    s: Segment,
    at_ms: u64,
    r: bool,
)
    requires
        ninv(mid),
        noted_post(before, mid, c, now_ms, n),
        n == Noted::Noted || n == Noted::Renoted,
        refusal_post(mid, after, s, at_ms, r),
        s.client == c.client,
        s.client_port == c.client_port,
        s.box_port == c.box_port,
        s.ack != connect_ack(c),
    ensures
        !r,
{
    reveal(extended);
    let fresh = add_ms_spec(now_ms, window_of(before));
    if n == Noted::Noted {
        let e = Entry { row: c.client, key: connect_key(c), deadline_ms: fresh, value: connect_ack(c) };
        theorem_n1_another_number_is_refused(mid, after, s, at_ms, r, e);
    } else {
        let old = choose|old: Entry| #[trigger] has(table(before), old) && old.row == c.client && old.key == connect_key(c)
            && has(table(mid), Entry {
                row: c.client,
                key: connect_key(c),
                deadline_ms: if old.deadline_ms >= fresh { old.deadline_ms } else { fresh },
                value: connect_ack(c),
            });
        let e = Entry {
            row: c.client,
            key: connect_key(c),
            deadline_ms: if old.deadline_ms >= fresh { old.deadline_ms } else { fresh },
            value: connect_ack(c),
        };
        theorem_n1_another_number_is_refused(mid, after, s, at_ms, r, e);
    }
}

/// Every entry `after` holds at `(row, key)` is one `before` held: nothing at
/// those ports is new, and no number there changed.
pub open spec fn nothing_new_at(after: Seq<Entry>, before: Seq<Entry>, row: u32, key: u64) -> bool {
    forall|j: int| 0 <= j < after.len() && after[j].row == row && after[j].key == key
        ==> has(before, #[trigger] after[j])
}

/// N1 (c) across operations: only a connect on a note's own client and
/// ports puts a number there.
pub proof fn theorem_n1_connect_elsewhere_adds_nothing(
    before: Notes,
    after: Notes,
    c: Segment,
    now_ms: u64,
    n: Noted,
    row: u32,
    key: u64,
)
    requires
        noted_post(before, after, c, now_ms, n),
        !((n == Noted::Noted || n == Noted::Renoted) && c.client == row && connect_key(c) == key),
    ensures
        nothing_new_at(table(after), table(before), row, key),
{
}

/// N1 (c) across operations: a refusal puts no number anywhere.
pub proof fn theorem_n1_refusal_adds_nothing(before: Notes, after: Notes, s: Segment, now_ms: u64, r: bool)
    requires
        refusal_post(before, after, s, now_ms, r),
    ensures
        subset_of(table(after), table(before)),
{
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == note_key(client_port, box_port),
))]
fn key(client_port: u16, box_port: u16) -> u64 {
    (client_port as u64) * 0x1_0000 + (box_port as u64)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == answering_ack(seq, payload_len, flags),
))]
fn answer_to(seq: u32, payload_len: u16, flags: u8) -> u32 {
    let fin: u64 = if flags & FIN != 0 { 1 } else { 0 };
    ((seq as u64 + payload_len as u64 + 1 + fin) % 0x1_0000_0000) as u32
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

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Notes {
    /// An empty table for the box at `box_addr`. `None` when the quota
    /// exceeds the capacity, the capacity exceeds what the table's index
    /// can number, or the window is zero.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Some(n) => ninv(n) && table(n).len() == 0 && box_of(n) == box_addr
                    && window_of(n) == window.ms && scap(pool_of(n)) == cap
                    && squota(pool_of(n)) == quota,
                None => quota > cap || cap > crate::slab::MAX_CAP || window.ms == 0,
            },
    ))]
    pub fn new(box_addr: u32, cap: usize, quota: usize, window: Span) -> Option<Notes> {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        if window.ms == 0 {
            return None;
        }
        match Slab::new(cap, quota) {
            Some(pool) => Some(Notes {
                pool,
                box_addr,
                window_ms: window.ms,
            }),
            None => None,
        }
    }

    /// The box these notes belong to.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == box_of(*self),
    ))]
    pub fn box_addr(&self) -> u32 {
        self.box_addr
    }

    /// How many notes have not expired at `now_ms`. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*self),
        ensures
            r == crate::pool::live_number(table(*self), now.ms),
    ))]
    pub fn live_count(&self, now: Instant) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        self.pool.live_count(now)
    }

    /// Whether the table holds an unexpired note for this client and port
    /// pair, whatever number it acknowledges. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*self),
        ensures
            r == crate::flow::live(table(*self), client, note_key(client_port, box_port), now.ms),
    ))]
    pub fn has_live(&self, client: u32, client_port: u16, box_port: u16, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        self.pool.live(client, key(client_port, box_port), now)
    }

    /// Notes a segment the gate delivered toward this box, if it is a
    /// connect. The caller has already decided the segment is not from the
    /// proxy's address. N1 (c), (d).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*old(self)),
        ensures
            ninv(*final(self)),
            same_frame(*final(self), *old(self)),
            noted_post(*old(self), *final(self), s, now.ms, r),
    ))]
    pub fn note_connect(&mut self, s: Segment, now: Instant) -> Noted {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(crate::pool::distinct_keys);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(extended);
        }
        if s.box_addr != self.box_addr {
            return Noted::NotThisBox;
        }
        if s.flags & (SYN | ACK | RST) != SYN {
            return Noted::NotAConnect;
        }
        let k = key(s.client_port, s.box_port);
        let ack = answer_to(s.seq, s.payload_len, s.flags);
        let fresh = add_ms(now.ms, self.window_ms);
        match self.pool.entry(s.client, k) {
            Some(e) => {
                let kept = later(e.deadline_ms, fresh);
                #[cfg(verus_keep_ghost)]
                proof! {
                    let t = sview(self.pool);
                    let i = choose|i: int| 0 <= i < t.len() && t[i] == e;
                    assert(t[i].row == s.client && t[i].key == k);
                }
                let _ = self.pool.set(s.client, k, Instant { ms: kept }, ack);
                #[cfg(verus_keep_ghost)]
                proof! {
                    if now.ms < u64::MAX {
                        lemma_has_noted(sview(self.pool), Entry { row: s.client, key: k, deadline_ms: kept, value: ack }, now.ms);
                    }
                }
                Noted::Renoted
            }
            None => match self
                .pool
                .insert_reclaiming(s.client, k, Instant { ms: fresh }, ack, now)
            {
                Inserted::New | Inserted::Refreshed => {
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        if now.ms < u64::MAX {
                            lemma_has_noted(sview(self.pool), Entry { row: s.client, key: k, deadline_ms: fresh, value: ack }, now.ms);
                        }
                    }
                    Noted::Noted
                }
                Inserted::RowAtQuota => Noted::ClientAtQuota,
                Inserted::PoolFull => Noted::Full,
            },
        }
    }

    /// Whether a segment the box sent is the refusal of a noted connect. An
    /// admitted refusal consumes its note. N1 (a), (b).
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*old(self)),
        ensures
            ninv(*final(self)),
            refusal_post(*old(self), *final(self), s, now.ms, r),
    ))]
    pub fn refusal(&mut self, s: Segment, now: Instant) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_same_no_new_keys(sview(self.pool));
        }
        if s.box_addr != self.box_addr {
            return false;
        }
        if s.flags != RST | ACK || s.seq != 0 || s.payload_len != 0 {
            return false;
        }
        let k = key(s.client_port, s.box_port);
        let e = match self.pool.entry(s.client, k) {
            Some(e) => e,
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_not_held_not_noted(sview(self.pool), s.client, k, now.ms, s.ack);
                }
                return false;
            }
        };
        if e.deadline_ms <= now.ms || e.value != s.ack {
            #[cfg(verus_keep_ghost)]
            proof! {
                lemma_not_noted(sview(self.pool), e, now.ms, s.ack);
            }
            return false;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_has_noted(sview(self.pool), e, now.ms);
        }
        let _ = self.pool.remove(s.client, k);
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_subset_no_new_keys(sview(self.pool), sview(old(self).pool));
        }
        true
    }

    /// How many notes the table holds, expired or not. Changes nothing.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            r == table(*self).len(),
    ))]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Removes the note for this client and pair of ports if it has expired
    /// at `now_ms`, in place, and says whether it did. No other note changes.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*old(self)),
        ensures
            ninv(*final(self)),
            same_frame(*final(self), *old(self)),
            r == crate::sweep::expired_held(table(*old(self)), client, note_key(client_port, box_port), now.ms),
            crate::sweep::dropped_if_expired(
                table(*final(self)),
                table(*old(self)),
                client,
                note_key(client_port, box_port),
                now.ms,
            ),
    ))]
    pub fn drop_expired(
        &mut self,
        client: u32,
        client_port: u16,
        box_port: u16,
        now: Instant,
    ) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        self.pool
            .drop_expired(client, key(client_port, box_port), now)
    }

    /// Removes expired notes, at most `budget`, and returns how many.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            ninv(*old(self)),
        ensures
            ninv(*final(self)),
            same_frame(*final(self), *old(self)),
            r <= budget,
            table(*final(self)).len() + r == table(*old(self)).len(),
            subset_of(table(*final(self)), table(*old(self))),
            keeps_live(table(*final(self)), table(*old(self)), now.ms),
            r < budget ==> none_expired(table(*final(self)), now.ms),
    ))]
    pub fn expire(&mut self, now: Instant, budget: usize) -> usize {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        self.pool.expire(now, budget)
    }

    /// Ends every note: the box stopped, or its row was replaced.
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires
            ninv(*old(self)),
        ensures
            ninv(*final(self)),
            same_frame(*final(self), *old(self)),
            table(*final(self)).len() == 0,
    ))]
    pub fn clear(&mut self) {
        #[cfg(verus_keep_ghost)]
        proof! {
            reveal(ninv);
        }
        self.pool.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOX: u32 = 0x6440_0007;
    const CLIENT: u32 = 0x6440_0001;

    fn notes() -> Notes {
        Notes::new(BOX, 4, 2, Span { ms: 5_000 }).unwrap()
    }

    fn syn(client_port: u16, seq: u32) -> Segment {
        Segment {
            client: CLIENT,
            client_port,
            box_addr: BOX,
            box_port: 8080,
            flags: SYN,
            seq,
            ack: 0,
            payload_len: 0,
        }
    }

    fn reset(client_port: u16, ack: u32) -> Segment {
        Segment {
            client: CLIENT,
            client_port,
            box_addr: BOX,
            box_port: 8080,
            flags: RST | ACK,
            seq: 0,
            ack,
            payload_len: 0,
        }
    }

    #[test]
    fn a_noted_connect_admits_its_reset_once() {
        let mut n = notes();
        assert!(!n.refusal(reset(40000, 101), Instant { ms: 0 }));
        assert_eq!(
            n.note_connect(syn(40000, 100), Instant { ms: 0 }),
            Noted::Noted
        );
        assert!(n.refusal(reset(40000, 101), Instant { ms: 1 }));
        assert!(!n.refusal(reset(40000, 101), Instant { ms: 2 }));
    }

    #[test]
    fn the_reset_must_match_ports_and_acknowledgement_and_have_the_refusal_shape() {
        let mut n = notes();
        assert_eq!(
            n.note_connect(syn(40000, 100), Instant { ms: 0 }),
            Noted::Noted
        );
        assert!(!n.refusal(reset(40001, 101), Instant { ms: 1 }));
        assert!(!n.refusal(reset(40000, 100), Instant { ms: 1 }));
        let mut wrong = reset(40000, 101);
        wrong.flags = RST;
        assert!(!n.refusal(wrong, Instant { ms: 1 }));
        wrong = reset(40000, 101);
        wrong.flags = SYN | ACK;
        assert!(!n.refusal(wrong, Instant { ms: 1 }));
        wrong = reset(40000, 101);
        wrong.seq = 1;
        assert!(!n.refusal(wrong, Instant { ms: 1 }));
        wrong = reset(40000, 101);
        wrong.payload_len = 1;
        assert!(!n.refusal(wrong, Instant { ms: 1 }));
        wrong = reset(40000, 101);
        wrong.box_addr = BOX + 1;
        assert!(!n.refusal(wrong, Instant { ms: 1 }));
        assert!(n.refusal(reset(40000, 101), Instant { ms: 1 }));
    }

    #[test]
    fn the_acknowledgement_wraps_and_counts_payload_and_fin() {
        let mut n = notes();
        assert_eq!(
            n.note_connect(syn(1, u32::MAX), Instant { ms: 0 }),
            Noted::Noted
        );
        assert!(n.refusal(reset(1, 0), Instant { ms: 1 }));
        let mut s = syn(2, 10);
        s.payload_len = 5;
        s.flags = SYN | FIN;
        assert_eq!(n.note_connect(s, Instant { ms: 0 }), Noted::Noted);
        assert!(n.refusal(reset(2, 17), Instant { ms: 1 }));
    }

    #[test]
    fn only_a_bare_syn_is_noted() {
        let mut n = notes();
        let mut s = syn(1, 0);
        s.flags = SYN | ACK;
        assert_eq!(n.note_connect(s, Instant { ms: 0 }), Noted::NotAConnect);
        s.flags = SYN | RST;
        assert_eq!(n.note_connect(s, Instant { ms: 0 }), Noted::NotAConnect);
        s.flags = ACK;
        assert_eq!(n.note_connect(s, Instant { ms: 0 }), Noted::NotAConnect);
        s = syn(1, 0);
        s.box_addr = BOX + 1;
        assert_eq!(n.note_connect(s, Instant { ms: 0 }), Noted::NotThisBox);
    }

    #[test]
    fn a_note_expires_and_an_expired_one_makes_room() {
        let mut n = notes();
        assert_eq!(n.note_connect(syn(1, 0), Instant { ms: 0 }), Noted::Noted);
        assert!(!n.refusal(reset(1, 1), Instant { ms: 5_000 }));
        assert_eq!(n.note_connect(syn(2, 0), Instant { ms: 0 }), Noted::Noted);
        assert_eq!(
            n.note_connect(syn(3, 0), Instant { ms: 1 }),
            Noted::ClientAtQuota
        );
        assert_eq!(
            n.note_connect(syn(3, 0), Instant { ms: 5_000 }),
            Noted::Noted
        );
        assert!(n.refusal(reset(3, 1), Instant { ms: 5_001 }));
    }

    #[test]
    fn a_retransmitted_syn_is_the_same_note() {
        let mut n = notes();
        assert_eq!(n.note_connect(syn(1, 7), Instant { ms: 0 }), Noted::Noted);
        assert_eq!(
            n.note_connect(syn(1, 7), Instant { ms: 1_000 }),
            Noted::Renoted
        );
        assert!(n.refusal(reset(1, 8), Instant { ms: 5_500 }));
    }

    #[test]
    fn a_second_syn_on_the_same_ports_replaces_the_number() {
        let mut n = notes();
        assert_eq!(
            n.note_connect(syn(40000, 1000), Instant { ms: 0 }),
            Noted::Noted
        );
        assert_eq!(
            n.note_connect(syn(40000, 5000), Instant { ms: 1_000 }),
            Noted::Renoted
        );
        assert!(!n.refusal(reset(40000, 1001), Instant { ms: 1_100 }));
        assert!(n.refusal(reset(40000, 5001), Instant { ms: 1_100 }));
        assert!(!n.refusal(reset(40000, 5001), Instant { ms: 1_100 }));
    }

    // The second SYN restarts the window; the note is refused
    // at its deadline, not after it.
    #[test]
    fn a_second_syn_restarts_the_window() {
        for (at, admitted) in [(5_000, true), (5_001, true), (5_999, true), (6_000, false)] {
            let mut n = notes();
            assert_eq!(
                n.note_connect(syn(40000, 1000), Instant { ms: 0 }),
                Noted::Noted
            );
            assert_eq!(
                n.note_connect(syn(40000, 5000), Instant { ms: 1_000 }),
                Noted::Renoted
            );
            assert_eq!(n.refusal(reset(40000, 5001), Instant { ms: at }), admitted);
        }
    }

    #[test]
    fn a_reset_with_another_number_leaves_the_note() {
        let mut n = notes();
        assert_eq!(n.note_connect(syn(1, 7), Instant { ms: 0 }), Noted::Noted);
        assert!(!n.refusal(reset(1, 9), Instant { ms: 1 }));
        assert!(n.refusal(reset(1, 8), Instant { ms: 1 }));
    }

    #[test]
    fn a_second_syn_revives_an_expired_note() {
        let mut n = notes();
        assert_eq!(n.note_connect(syn(1, 7), Instant { ms: 0 }), Noted::Noted);
        assert_eq!(
            n.note_connect(syn(1, 20), Instant { ms: 6_000 }),
            Noted::Renoted
        );
        assert!(n.refusal(reset(1, 21), Instant { ms: 10_999 }));
    }

    #[test]
    fn a_zero_window_is_refused() {
        assert!(Notes::new(BOX, 4, 2, Span { ms: 0 }).is_none());
    }
}

#[cfg(kani)]
mod proofs {
    //! Bounded checks of the compiled code against a second reading of N1:
    //! one operation from an arbitrary table that satisfies the invariant,
    //! every field of the segment and every instant unconstrained.
    //!
    //! Every table of up to `MAX` entries is covered, one shape to a
    //! harness: a shape is a capacity, a slab length and a number of
    //! entries, as plain numbers, and there are forty of them, named
    //! `c<capacity>_<slots>_<entries>`. The contents before and after are
    //! kept in arrays and read by row and key at arbitrary places, never
    //! compared whole. Where `note_connect` can give a note up and then add
    //! one at a full table or a full slab, its check is in eight parts, a
    //! harness each, in a module named for the shape; together they assert
    //! what the whole check asserts.
    //! The harnesses `reached*` say which outcomes the largest shapes reach.

    use super::*;
    use crate::pool::{Entry, kani_count_row, kani_lookup};

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

    /// The contents are what they were: the same length, and the same entry
    /// at one arbitrary place. Two tables are not compared whole.
    fn unchanged(before: &[Entry], now: &[Entry]) {
        assert!(now.len() == before.len());
        let u: usize = kani::any();
        if u < before.len() {
            assert!(now[u] == before[u]);
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

    fn any_segment() -> Segment {
        Segment {
            client: kani::any(),
            client_port: kani::any(),
            box_addr: kani::any(),
            box_port: kani::any(),
            flags: kani::any(),
            seq: kani::any(),
            ack: kani::any(),
            payload_len: kani::any(),
        }
    }

    /// Notes over any table of capacity `cap` with `m` slab slots and `n`
    /// entries, for any box and any window above zero.
    fn notes_shaped(cap: usize, m: usize, n: usize) -> Notes {
        let window_ms: u64 = kani::any();
        kani::assume(window_ms > 0);
        Notes {
            pool: Slab::kani_shaped(cap, m, n),
            box_addr: kani::any(),
            window_ms,
        }
    }

    /// The key, spelled with a shift where the code multiplies.
    fn key2(client_port: u16, box_port: u16) -> u64 {
        ((client_port as u64) << 16) | (box_port as u64)
    }

    /// The acknowledgement a SYN calls for, spelled with wrapping additions
    /// where the code takes a remainder.
    fn ack2(s: Segment) -> u32 {
        let fin = if s.flags & FIN != 0 { 1 } else { 0 };
        s.seq
            .wrapping_add(s.payload_len as u32)
            .wrapping_add(1)
            .wrapping_add(fin)
    }

    /// One `refusal` from a table. N1 (a), (b). Returns whether it was
    /// admitted, whether the segment was for this box, whether it had the
    /// refusal's shape, whether the note on its ports was live with its
    /// number, live with another, or expired, and the number of entries
    /// before.
    fn refusal_from(mut n: Notes) -> (bool, bool, bool, bool, bool, bool, usize) {
        let (before, len) = snapshot(&n.pool);
        let before = &before[..len];
        let limits = n.pool.kani_limits();
        let (box_addr, window) = (n.box_addr, n.window_ms);
        let s = any_segment();
        let now: u64 = kani::any();
        let k = key2(s.client_port, s.box_port);
        let held = kani_lookup(before, s.client, k);
        let live = match held {
            Some(e) => e.deadline_ms > now && e.value == s.ack,
            None => false,
        };
        let shape = s.flags == RST | ACK && s.seq == 0 && s.payload_len == 0;
        let admitted = n.refusal(s, Instant { ms: now });
        assert!(n.box_addr == box_addr && n.window_ms == window);
        assert!(n.pool.kani_limits() == limits);
        assert!(admitted == (s.box_addr == box_addr && shape && live));
        assert!(n.pool.kani_holds());
        let (after, len) = snapshot(&n.pool);
        let after = &after[..len];
        nothing_else_is_new(before, after, s.client, k);
        another_is_kept(before, after, s.client, k);
        if admitted {
            assert!(kani_lookup(after, s.client, k).is_none());
            assert!(after.len() + 1 == before.len());
        } else {
            unchanged(before, after);
        }
        let other = matches!(held, Some(e) if e.deadline_ms > now && e.value != s.ack);
        let expired = matches!(held, Some(e) if e.deadline_ms <= now);
        (
            admitted,
            s.box_addr == box_addr,
            shape,
            live,
            other,
            expired,
            before.len(),
        )
    }

    /// One `note_connect` from a table, asserting `part` of its check. N1
    /// (c), (d). Returns the outcome, the numbers of entries before and
    /// after, whether the client's row was at its quota, and the capacity.
    fn note_connect_from(mut n: Notes, part: u8) -> (Noted, usize, usize, bool, usize) {
        let (before, len) = snapshot(&n.pool);
        let before = &before[..len];
        let (cap, quota) = n.pool.kani_limits();
        let (box_addr, window) = (n.box_addr, n.window_ms);
        let s = any_segment();
        let now: u64 = kani::any();
        let k = key2(s.client_port, s.box_port);
        let number = ack2(s);
        let held = kani_lookup(before, s.client, k);
        let count = kani_count_row(before, s.client);
        let connect = s.flags & (SYN | ACK | RST) == SYN;
        let fresh = now.saturating_add(window);
        let outcome = n.note_connect(s, Instant { ms: now });
        let facts = (outcome, before.len(), n.pool.len(), count >= quota, cap);
        if part >= LIMITS {
            holds_at(&n.pool, part);
            return facts;
        }
        if part == WHOLE {
            assert!(n.pool.kani_holds());
        }
        let (after, len) = snapshot(&n.pool);
        let after = &after[..len];
        if part == WHOLE || part == RESULT {
            assert!(n.box_addr == box_addr && n.window_ms == window);
            assert!(n.pool.kani_limits() == (cap, quota));
            match outcome {
                Noted::NotThisBox => {
                    assert!(s.box_addr != box_addr);
                }
                Noted::NotAConnect => {
                    assert!(s.box_addr == box_addr && !connect);
                }
                Noted::Noted => {
                    assert!(s.box_addr == box_addr && connect && held.is_none());
                    assert!(
                        kani_lookup(after, s.client, k)
                            == Some(Entry {
                                row: s.client,
                                key: k,
                                deadline_ms: fresh,
                                value: number,
                            })
                    );
                    assert!(after.len() <= before.len() + 1);
                }
                Noted::Renoted => {
                    assert!(s.box_addr == box_addr && connect);
                    let was = match held {
                        Some(e) => e.deadline_ms,
                        None => 0,
                    };
                    assert!(held.is_some());
                    let want = if was >= fresh { was } else { fresh };
                    assert!(
                        kani_lookup(after, s.client, k)
                            == Some(Entry {
                                row: s.client,
                                key: k,
                                deadline_ms: want,
                                value: number,
                            })
                    );
                    assert!(after.len() == before.len());
                }
                Noted::ClientAtQuota => {
                    assert!(s.box_addr == box_addr);
                    assert!(connect && held.is_none());
                    assert!(count >= quota);
                    row_is_live(before, s.client, now);
                }
                Noted::Full => {
                    assert!(s.box_addr == box_addr);
                    assert!(connect && held.is_none());
                    assert!(before.len() >= cap);
                    all_are_live(before, now);
                }
            }
        }
        if part == WHOLE || part == KEPT {
            match outcome {
                Noted::Noted => unexpired_are_kept(before, after, s.client, k, now),
                Noted::Renoted => another_is_kept(before, after, s.client, k),
                Noted::NotThisBox | Noted::NotAConnect | Noted::ClientAtQuota | Noted::Full => {}
            }
        }
        if part == WHOLE || part == NOTHING_NEW {
            match outcome {
                Noted::Noted | Noted::Renoted => {}
                Noted::NotThisBox | Noted::NotAConnect | Noted::ClientAtQuota | Noted::Full => {
                    unchanged(before, after)
                }
            }
            nothing_else_is_new(before, after, s.client, k);
        }
        facts
    }

    /// One harness of `$check` for a table of one shape.
    macro_rules! shape {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(notes_shaped($cap, $m, $n));
            }
        };
    }

    /// One harness of `$check` for a table of one shape, asserting `$part`.
    macro_rules! shape_part {
        ($check:path, $name:ident, $cap:expr, $m:expr, $n:expr, $part:expr) => {
            #[kani::proof]
            #[kani::unwind(8)]
            fn $name() {
                let _ = $check(notes_shaped($cap, $m, $n), $part);
            }
        };
    }

    /// A module `$name` of eight harnesses of `$check` for a table of one
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
            }
        };
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

    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_notes_key_and_acknowledgement_agree_with_a_second_spelling() {
        let s = any_segment();
        assert!(key(s.client_port, s.box_port) == key2(s.client_port, s.box_port));
        assert!(answer_to(s.seq, s.payload_len, s.flags) == ack2(s));
    }

    #[cfg(feature = "kani-full")]
    mod refusal_step {
        use super::*;

        every_shape!(refusal_from);

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (admitted, to_box, shape, live, other, expired, len) =
                refusal_from(notes_shaped(MAX, 2 * MAX, MAX));
            kani::cover!(admitted);
            kani::cover!(!admitted && live && to_box);
            kani::cover!(!admitted && shape && to_box && other);
            kani::cover!(!admitted && shape && to_box && len == MAX);
            kani::cover!(!admitted && shape && to_box && expired);
            kani::cover!(!admitted && shape && !to_box && live);
        }
    }

    #[cfg(feature = "kani-full")]
    mod note_connect_step {
        use super::*;

        // The whole check, where the step cannot both give a note up and
        // add one at a full table or a full slab: capacity zero, where
        // nothing is added, and every table below its capacity whose slab
        // has a slot left or holds no entry.
        shape_part!(note_connect_from, c0_0_0, 0, 0, 0, WHOLE);
        shape_part!(note_connect_from, c1_0_0, 1, 0, 0, WHOLE);
        shape_part!(note_connect_from, c1_1_0, 1, 1, 0, WHOLE);
        shape_part!(note_connect_from, c1_2_0, 1, 2, 0, WHOLE);
        shape_part!(note_connect_from, c2_0_0, 2, 0, 0, WHOLE);
        shape_part!(note_connect_from, c2_1_0, 2, 1, 0, WHOLE);
        shape_part!(note_connect_from, c2_1_1, 2, 1, 1, WHOLE);
        shape_part!(note_connect_from, c2_2_0, 2, 2, 0, WHOLE);
        shape_part!(note_connect_from, c2_2_1, 2, 2, 1, WHOLE);
        shape_part!(note_connect_from, c2_3_0, 2, 3, 0, WHOLE);
        shape_part!(note_connect_from, c2_3_1, 2, 3, 1, WHOLE);
        shape_part!(note_connect_from, c2_4_0, 2, 4, 0, WHOLE);
        shape_part!(note_connect_from, c3_0_0, 3, 0, 0, WHOLE);
        shape_part!(note_connect_from, c3_1_0, 3, 1, 0, WHOLE);
        shape_part!(note_connect_from, c3_1_1, 3, 1, 1, WHOLE);
        shape_part!(note_connect_from, c3_2_0, 3, 2, 0, WHOLE);
        shape_part!(note_connect_from, c3_2_1, 3, 2, 1, WHOLE);
        shape_part!(note_connect_from, c3_2_2, 3, 2, 2, WHOLE);
        shape_part!(note_connect_from, c3_3_0, 3, 3, 0, WHOLE);
        shape_part!(note_connect_from, c3_3_1, 3, 3, 1, WHOLE);
        shape_part!(note_connect_from, c3_3_2, 3, 3, 2, WHOLE);
        shape_part!(note_connect_from, c3_4_0, 3, 4, 0, WHOLE);
        shape_part!(note_connect_from, c3_4_1, 3, 4, 1, WHOLE);
        shape_part!(note_connect_from, c3_4_2, 3, 4, 2, WHOLE);
        shape_part!(note_connect_from, c3_5_0, 3, 5, 0, WHOLE);
        shape_part!(note_connect_from, c3_5_1, 3, 5, 1, WHOLE);
        shape_part!(note_connect_from, c3_5_2, 3, 5, 2, WHOLE);
        shape_part!(note_connect_from, c3_6_0, 3, 6, 0, WHOLE);

        // One part to a harness: the table full, or the slab at twice the
        // capacity with an entry in it.
        every_part!(note_connect_from, c1_1_1, 1, 1, 1);
        every_part!(note_connect_from, c1_2_1, 1, 2, 1);
        every_part!(note_connect_from, c2_2_2, 2, 2, 2);
        every_part!(note_connect_from, c2_3_2, 2, 3, 2);
        every_part!(note_connect_from, c2_4_1, 2, 4, 1);
        every_part!(note_connect_from, c2_4_2, 2, 4, 2);
        every_part!(note_connect_from, c3_3_3, 3, 3, 3);
        every_part!(note_connect_from, c3_4_3, 3, 4, 3);
        every_part!(note_connect_from, c3_5_3, 3, 5, 3);
        every_part!(note_connect_from, c3_6_1, 3, 6, 1);
        every_part!(note_connect_from, c3_6_2, 3, 6, 2);
        every_part!(note_connect_from, c3_6_3, 3, 6, 3);

        // The outcomes reached, read from the result alone.
        #[kani::proof]
        #[kani::unwind(8)]
        fn reached() {
            let (r, before, after, _, _) =
                note_connect_from(notes_shaped(MAX, 2 * MAX, MAX - 1), LIMITS);
            kani::cover!(r == Noted::Noted && after == before + 1);
            kani::cover!(r == Noted::Noted && after == before);
            kani::cover!(r == Noted::Renoted);
            kani::cover!(r == Noted::NotAConnect);
            kani::cover!(r == Noted::NotThisBox);
            kani::cover!(r == Noted::ClientAtQuota);
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn reached_full() {
            let (r, before, after, at_quota, cap) =
                note_connect_from(notes_shaped(MAX, 2 * MAX, MAX), LIMITS);
            kani::cover!(r == Noted::Noted && !at_quota && after == before);
            kani::cover!(r == Noted::Noted && at_quota && after == before);
            kani::cover!(r == Noted::Full && cap == MAX);
        }
    }
}
