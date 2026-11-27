//! Which addresses a DNS answer gives for the name that was asked.
//!
//! Layer 2 of the crate, a reader of bytes a guest chose. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A box that declares a DNS host may reach the addresses that host
//! resolves to. The addresses come from the answer the resolver sent the
//! box, so what is read as "an address of that name" decides what the box
//! may reach. This module is that reading: the payload of one UDP datagram
//! in, the asked name and its addresses out.
//!
//! It reads the header, the one question and the answer section, and
//! nothing after it. A name is plain labels with compression pointers, and
//! a pointer is followed only to a place strictly before the start of the
//! run of labels it is read in, so a name has one decoding and the walk
//! ends. Names are compared as their bytes on the wire with ASCII letters
//! lowered; nothing is converted for display.
//!
//! The answer section is walked once, in order, with a set of names that
//! starts as the asked name: an address record owned by a name in the set
//! gives its address; an alias record owned by a name in the set adds its
//! target. A record owned by any other name, of any other type or of any
//! class but IN is read past.
//!
//! THEOREM DA1: `answer_addresses` returns for every byte string, reads no
//! byte outside it, and takes a number of steps bounded by its length.
//!
//! THEOREM DA2: `answer_addresses` returns [`spec_answer`] of the payload.
//!
//! THEOREM DA3 (what the reading is for): in a payload that is read, every
//! address returned is the four data bytes of a record of the answer
//! section whose type is A, whose class is IN, whose data is four bytes
//! long and whose owner is the asked name or a name reached from it; and
//! every name reached is the target of a record of the answer section
//! whose type is CNAME, whose class is IN and whose owner is the asked name
//! or a name reached from it (`theorem_da3_addresses_come_from_the_chain`).
//!
//! THEOREM DA4: at most [`MAX_ADDRS`] addresses are returned and at most
//! [`MAX_CHAIN`] names are reached; `more` and `chain_cut` say when the
//! answer held more of either, and nothing is returned in their place.
//!
//! Read as "nothing to admit" ([`Unread`]), each for its reason: fewer than
//! twelve bytes; not a response; an operation other than a standard query;
//! a response code other than "no error"; a question count other than one;
//! a question or a counted record that does not decode; a question of a
//! class other than IN; an address record whose data is not four bytes; an
//! alias record whose data is not exactly one name.
//!
//! Not read: the authority and additional sections, the time-to-live, and
//! the truncation flag's meaning (it is reported; what was carried is
//! read). Not here: that the datagram is whole (the caller reads the
//! frame's facts), that it came from the resolver, and that the asked name
//! is one the box declared. Those are the caller's, with registry rows.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The type of an address record.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const TYPE_A: u16 = 1;
/// The type of an alias record.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const TYPE_CNAME: u16 = 5;
/// The Internet class.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const CLASS_IN: u16 = 1;
/// The longest name, its root byte included.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_NAME: usize = 255;
/// The header's length, and where the question starts.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const HEADER: usize = 12;
/// The most addresses one answer gives.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_ADDRS: usize = 32;
/// The most names an answer's aliases reach beside the asked one.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_CHAIN: usize = 8;

/// Why an answer gives nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Unread {
    /// Fewer than twelve bytes.
    Short,
    /// The response flag is clear.
    NotAResponse,
    /// An operation other than a standard query.
    Operation,
    /// A response code other than "no error".
    Failed,
    /// A question count other than one.
    Questions,
    /// The question does not decode, or its class is not IN.
    Question,
    /// A counted record of the answer section does not decode, or an address
    /// or alias record of class IN has data of the wrong shape.
    Record,
}

/// What an answer gives.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Given {
    /// The message id.
    pub id: u16,
    /// The asked name: its labels on the wire, each behind its length,
    /// letters lowered, ending in the root.
    pub asked: Vec<u8>,
    /// The asked type.
    pub qtype: u16,
    /// The truncation flag.
    pub truncated: bool,
    /// The addresses, in the answer's order.
    pub addrs: Vec<u32>,
    /// The answer held an address past [`MAX_ADDRS`].
    pub more: bool,
    /// The answer's aliases reached a name past [`MAX_CHAIN`].
    pub chain_cut: bool,
}

/// How an answer was read.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Answer {
    Read(Given),
    Unread(Unread),
}

#[cfg(verus_keep_ghost)]
verus! {

/// The 16-bit number at `i`, most significant byte first.
pub open spec fn spec_be16(d: Seq<u8>, i: int) -> int {
    d[i] as int * 256 + d[i + 1] as int
}

/// The 32-bit number at `i`, most significant byte first.
pub open spec fn spec_be32(d: Seq<u8>, i: int) -> int {
    spec_be16(d, i) * 65536 + spec_be16(d, i + 2)
}

/// An ASCII capital letter lowered; any other byte as it is.
pub open spec fn lower(b: u8) -> u8 {
    if 65 <= b <= 90 {
        (b + 32) as u8
    } else {
        b
    }
}

/// The bytes of `s` with ASCII capitals lowered.
pub open spec fn lowered(s: Seq<u8>) -> Seq<u8> {
    Seq::new(s.len(), |i: int| lower(s[i]))
}

/// The name that starts at `p`, and the index after it where it stands. The
/// name is given as its labels each behind its length, letters lowered,
/// ending in the root byte. A pointer is followed only to a place strictly
/// before `bound`, the start of the run of labels being read; the run it
/// leads to starts a new bound. `None` for a length byte from 64 to 191, a
/// label or pointer outside `d`, or a pointer not before `bound`.
pub open spec fn name_at(d: Seq<u8>, p: int, bound: int) -> Option<(Seq<u8>, int)>
    decreases bound, d.len() - p,
{
    if p < 0 || p >= d.len() || bound < 0 {
        None
    } else if d[p] == 0 {
        Some((Seq::<u8>::empty().push(0u8), p + 1))
    } else if d[p] <= 63 {
        if p + 1 + d[p] as int > d.len() {
            None
        } else {
            match name_at(d, p + 1 + d[p] as int, bound) {
                Some((rest, end)) => Some((
                    Seq::<u8>::empty().push(d[p]) + lowered(d.subrange(p + 1, p + 1 + d[p] as int)) + rest,
                    end,
                )),
                None => None,
            }
        }
    } else if d[p] >= 192 {
        if p + 1 >= d.len() {
            None
        } else {
            let target = (d[p] as int - 192) * 256 + d[p + 1] as int;
            if target >= bound {
                None
            } else {
                match name_at(d, target, target) {
                    Some((rest, end)) => Some((rest, p + 2)),
                    None => None,
                }
            }
        }
    } else {
        None
    }
}

/// The name at `p` when it is at most [`MAX_NAME`] bytes, and the index
/// after it.
pub open spec fn name_of(d: Seq<u8>, p: int) -> Option<(Seq<u8>, int)> {
    match name_at(d, p, p) {
        Some((n, end)) => if n.len() <= MAX_NAME {
            Some((n, end))
        } else {
            None
        },
        None => None,
    }
}

/// The record that starts at `p`: a name, ten bytes of type, class,
/// time-to-live and data length, and that many bytes of data inside `d`.
/// Given as its owner, its type, its class, where its data stands, how long
/// the data is, and where the next record starts.
pub open spec fn record_at(d: Seq<u8>, p: int) -> Option<(Seq<u8>, int, int, int, int, int)> {
    match name_of(d, p) {
        Some((owner, e)) => if e + 10 <= d.len() && e + 10 + spec_be16(d, e + 8) <= d.len() {
            Some((
                owner,
                spec_be16(d, e),
                spec_be16(d, e + 2),
                e + 10,
                spec_be16(d, e + 8),
                e + 10 + spec_be16(d, e + 8),
            ))
        } else {
            None
        },
        None => None,
    }
}

pub open spec fn owner_of(r: (Seq<u8>, int, int, int, int, int)) -> Seq<u8> {
    r.0
}

pub open spec fn data_at(r: (Seq<u8>, int, int, int, int, int)) -> int {
    r.3
}

pub open spec fn data_len(r: (Seq<u8>, int, int, int, int, int)) -> int {
    r.4
}

pub open spec fn next_of(r: (Seq<u8>, int, int, int, int, int)) -> int {
    r.5
}

/// `n` is one of the names reached.
pub open spec fn reached(chain: Seq<Seq<u8>>, n: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < chain.len() && #[trigger] chain[i] == n
}

/// The record is an address record of class IN.
pub open spec fn is_a(r: (Seq<u8>, int, int, int, int, int)) -> bool {
    r.1 == TYPE_A && r.2 == CLASS_IN
}

/// The record is an alias record of class IN.
pub open spec fn is_cname(r: (Seq<u8>, int, int, int, int, int)) -> bool {
    r.1 == TYPE_CNAME && r.2 == CLASS_IN
}

/// The target of an alias record: the one name its data is, exactly.
pub open spec fn target_of(d: Seq<u8>, r: (Seq<u8>, int, int, int, int, int)) -> Option<Seq<u8>> {
    match name_of(d, data_at(r)) {
        Some((t, e)) => if e == data_at(r) + data_len(r) {
            Some(t)
        } else {
            None
        },
        None => None,
    }
}

/// The walk after one record, or `None` when the record makes the answer
/// unread. A walk is the names reached (the asked one first), the addresses
/// so far, and whether the addresses and the names ran past their bounds.
pub open spec fn step(d: Seq<u8>, w: (Seq<Seq<u8>>, Seq<u32>, bool, bool), r: (Seq<u8>, int, int, int, int, int)) -> Option<(Seq<Seq<u8>>, Seq<u32>, bool, bool)> {
    if is_a(r) {
        if data_len(r) != 4 {
            None
        } else if !reached(w.0, owner_of(r)) {
            Some(w)
        } else if w.1.len() < MAX_ADDRS {
            Some((w.0, w.1.push(spec_be32(d, data_at(r)) as u32), w.2, w.3))
        } else {
            Some((w.0, w.1, true, w.3))
        }
    } else if is_cname(r) {
        match target_of(d, r) {
            None => None,
            Some(t) => if !reached(w.0, owner_of(r)) || reached(w.0, t) {
                Some(w)
            } else if w.0.len() <= MAX_CHAIN {
                Some((w.0.push(t), w.1, w.2, w.3))
            } else {
                Some((w.0, w.1, w.2, true))
            },
        }
    } else {
        Some(w)
    }
}

/// The walk over `n` records from `p`, or `None` when one of them does not
/// decode or makes the answer unread.
pub open spec fn walk(d: Seq<u8>, p: int, n: nat, w: (Seq<Seq<u8>>, Seq<u32>, bool, bool)) -> Option<(Seq<Seq<u8>>, Seq<u32>, bool, bool)>
    decreases n,
{
    if n == 0 {
        Some(w)
    } else {
        match record_at(d, p) {
            None => None,
            Some(r) => match step(d, w, r) {
                None => None,
                Some(w2) => walk(d, next_of(r), (n - 1) as nat, w2),
            },
        }
    }
}

/// Where the `k`-th counted record starts, the first being number 0, when
/// every record before it decodes.
pub open spec fn record_start(d: Seq<u8>, p: int, k: nat) -> Option<int>
    decreases k,
{
    if k == 0 {
        Some(p)
    } else {
        match record_at(d, p) {
            Some(r) => record_start(d, next_of(r), (k - 1) as nat),
            None => None,
        }
    }
}

/// What the header and the question give: the asked name, the asked type
/// and where the answer section starts; or why the answer is unread.
pub open spec fn opening(d: Seq<u8>) -> Result<(Seq<u8>, int, int), Unread> {
    if d.len() < HEADER {
        Err(Unread::Short)
    } else if d[2] & 0x80 == 0 {
        Err(Unread::NotAResponse)
    } else if d[2] & 0x78 != 0 {
        Err(Unread::Operation)
    } else if d[3] & 0x0f != 0 {
        Err(Unread::Failed)
    } else if spec_be16(d, 4) != 1 {
        Err(Unread::Questions)
    } else {
        match name_of(d, HEADER as int) {
            Some((q, e)) => if e + 4 <= d.len() && spec_be16(d, e + 2) == CLASS_IN {
                Ok((q, spec_be16(d, e), e + 4))
            } else {
                Err(Unread::Question)
            },
            None => Err(Unread::Question),
        }
    }
}

/// The walk an answer starts with: the asked name reached, nothing else.
pub open spec fn start(q: Seq<u8>) -> (Seq<Seq<u8>>, Seq<u32>, bool, bool) {
    (Seq::<Seq<u8>>::empty().push(q), Seq::<u32>::empty(), false, false)
}

/// DA2: what the payload gives.
pub open spec fn spec_answer(d: Seq<u8>) -> Result<(Seq<u8>, int, (Seq<Seq<u8>>, Seq<u32>, bool, bool)), Unread> {
    match opening(d) {
        Err(why) => Err(why),
        Ok((q, qtype, at)) => match walk(d, at, spec_be16(d, 6) as nat, start(q)) {
            None => Err(Unread::Record),
            Some(w) => Ok((q, qtype, w)),
        },
    }
}

/// The result is what the specification gives.
pub open spec fn answers(d: Seq<u8>, r: Answer) -> bool {
    match (spec_answer(d), r) {
        (Err(why), Answer::Unread(got)) => got == why,
        (Ok((q, qtype, w)), Answer::Read(g)) => {
            &&& g.id as int == spec_be16(d, 0)
            &&& g.asked@ == q
            &&& g.qtype as int == qtype
            &&& g.truncated == (d[2] & 0x02 != 0)
            &&& g.addrs@ == w.1
            &&& g.more == w.2
            &&& g.chain_cut == w.3
        },
        _ => false,
    }
}

/// DA3, DA4.
pub proof fn theorem_da3_addresses_come_from_the_chain(d: Seq<u8>)
    requires
        spec_answer(d) is Ok,
    ensures
        ({
            let q = spec_answer(d)->Ok_0.0;
            let w = spec_answer(d)->Ok_0.2;
            let at = opening(d)->Ok_0.2;
            let n = spec_be16(d, 6) as nat;
            &&& w.0.len() >= 1 && w.0[0] == q
            &&& w.0.len() <= MAX_CHAIN + 1
            &&& w.1.len() <= MAX_ADDRS
            &&& forall|j: int| #![trigger w.1[j]] 0 <= j < w.1.len() ==> exists|k: nat| #![trigger record_start(d, at, k)] k < n && ({
                let s = record_start(d, at, k);
                &&& s is Some
                &&& record_at(d, s->0) is Some
                &&& is_a(record_at(d, s->0)->0)
                &&& data_len(record_at(d, s->0)->0) == 4
                &&& reached(w.0, owner_of(record_at(d, s->0)->0))
                &&& w.1[j] as int == spec_be32(d, data_at(record_at(d, s->0)->0))
            })
            &&& forall|m: int| #![trigger w.0[m]] 1 <= m < w.0.len() ==> exists|k: nat| #![trigger record_start(d, at, k)] k < n && ({
                let s = record_start(d, at, k);
                &&& s is Some
                &&& record_at(d, s->0) is Some
                &&& is_cname(record_at(d, s->0)->0)
                &&& reached(w.0, owner_of(record_at(d, s->0)->0))
                &&& target_of(d, record_at(d, s->0)->0) == Some(w.0[m])
            })
        }),
{
    // By induction over the walk, with the record number of each address and each name kept.
    let o = opening(d)->Ok_0;
    let q = o.0;
    let at = o.2;
    let n = spec_be16(d, 6) as nat;
    let w0 = start(q);
    assert(chain_ok(d, at, 0, q, w0, Seq::<nat>::empty(), Seq::<nat>::empty().push(0)));
    let (ka, km) = lemma_chain_walk(d, at, 0, n, q, w0, Seq::<nat>::empty(), Seq::<nat>::empty().push(0), at);
    let w = spec_answer(d)->Ok_0.2;
    assert(w == walk(d, at, n, w0)->0);
    assert(chain_ok(d, at, n, q, w, ka, km));
    let at = opening(d)->Ok_0.2;
    assert forall|j: int| #![trigger w.1[j]] 0 <= j < w.1.len() implies exists|k: nat| #![trigger record_start(d, at, k)] k < n && ({
        let s = record_start(d, at, k);
        &&& s is Some
        &&& record_at(d, s->0) is Some
        &&& is_a(record_at(d, s->0)->0)
        &&& data_len(record_at(d, s->0)->0) == 4
        &&& reached(w.0, owner_of(record_at(d, s->0)->0))
        &&& w.1[j] as int == spec_be32(d, data_at(record_at(d, s->0)->0))
    }) by {
        assert(addr_from(d, at, w.0, w.1[j], ka[j]));
        assert(record_start(d, at, ka[j]) is Some);
    }
    assert forall|m: int| #![trigger w.0[m]] 1 <= m < w.0.len() implies exists|k: nat| #![trigger record_start(d, at, k)] k < n && ({
        let s = record_start(d, at, k);
        &&& s is Some
        &&& record_at(d, s->0) is Some
        &&& is_cname(record_at(d, s->0)->0)
        &&& reached(w.0, owner_of(record_at(d, s->0)->0))
        &&& target_of(d, record_at(d, s->0)->0) == Some(w.0[m])
    }) by {
        assert(alias_from(d, at, w.0, w.0[m], km[m]));
        assert(record_start(d, at, km[m]) is Some);
    }
    // Ground terms for the ensures' `exists`: the record of the first address and of the first alias, at
    // which every conjunct but the last holds, so that the last one, which names `w.1[j]` or `w.0[m]`,
    // is the one the solver must look at.
    if w.1.len() > 0 {
        assert(addr_from(d, at, w.0, w.1[0], ka[0]));
        assert(record_start(d, at, ka[0]) is Some);
    }
    if w.0.len() > 1 {
        assert(alias_from(d, at, w.0, w.0[1], km[1]));
        assert(record_start(d, at, km[1]) is Some);
    }
}

// Helper specifications and lemmas for the proofs below.

/// The `k`-th record from `at` is an address record whose data is `x` and whose owner is in `chain`.
spec fn addr_from(d: Seq<u8>, at: int, chain: Seq<Seq<u8>>, x: u32, k: nat) -> bool {
    let s = record_start(d, at, k);
    &&& s is Some
    &&& record_at(d, s->0) is Some
    &&& is_a(record_at(d, s->0)->0)
    &&& data_len(record_at(d, s->0)->0) == 4
    &&& reached(chain, owner_of(record_at(d, s->0)->0))
    &&& x as int == spec_be32(d, data_at(record_at(d, s->0)->0))
}

/// The `k`-th record from `at` is an alias record whose target is `t` and whose owner is in `chain`.
spec fn alias_from(d: Seq<u8>, at: int, chain: Seq<Seq<u8>>, t: Seq<u8>, k: nat) -> bool {
    let s = record_start(d, at, k);
    &&& s is Some
    &&& record_at(d, s->0) is Some
    &&& is_cname(record_at(d, s->0)->0)
    &&& reached(chain, owner_of(record_at(d, s->0)->0))
    &&& target_of(d, record_at(d, s->0)->0) == Some(t)
}

/// DA3 and DA4 for a walk over the first `i` records from `at`, started from the name `q`, with
/// `ka[j]` the record that gave address `j` and `km[m]` the record that reached name `m` (`km[0]` unused).
spec fn chain_ok(d: Seq<u8>, at: int, i: nat, q: Seq<u8>, w: (Seq<Seq<u8>>, Seq<u32>, bool, bool), ka: Seq<nat>, km: Seq<nat>) -> bool {
    &&& w.0.len() >= 1
    &&& w.0[0] == q
    &&& w.0.len() <= MAX_CHAIN + 1
    &&& w.1.len() <= MAX_ADDRS
    &&& ka.len() == w.1.len()
    &&& km.len() == w.0.len()
    &&& forall|j: int| #![trigger w.1[j]] #![trigger ka[j]] 0 <= j < w.1.len() ==> ka[j] < i && addr_from(d, at, w.0, w.1[j], ka[j])
    &&& forall|m: int| #![trigger w.0[m]] #![trigger km[m]] 1 <= m < w.0.len() ==> km[m] < i && alias_from(d, at, w.0, w.0[m], km[m])
}

/// A decoded name has at least its root byte and ends after its start, inside `d`.
proof fn lemma_name_at_shape(d: Seq<u8>, p: int, bound: int)
    requires
        name_at(d, p, bound) is Some,
    ensures
        (name_at(d, p, bound)->0).0.len() >= 1,
        p < (name_at(d, p, bound)->0).1 <= d.len(),
    decreases bound, d.len() - p,
{
    if d[p] == 0 {
    } else if d[p] <= 63 {
        lemma_name_at_shape(d, p + 1 + d[p] as int, bound);
    } else {
        let target = (d[p] as int - 192) * 256 + d[p + 1] as int;
        lemma_name_at_shape(d, target, target);
    }
}

/// The start of record `i + 1` is the end of record `i`.
proof fn lemma_record_start_next(d: Seq<u8>, at: int, i: nat)
    ensures
        record_start(d, at, i + 1) == match record_start(d, at, i) {
            Some(s) => match record_at(d, s) {
                Some(r) => Some(next_of(r)),
                None => None,
            },
            None => None,
        },
    decreases i,
{
    reveal_with_fuel(record_start, 2);
    if i > 0 {
        match record_at(d, at) {
            Some(r) => lemma_record_start_next(d, next_of(r), (i - 1) as nat),
            None => {},
        }
    }
}

/// A name reached stays reached when the chain grows.
proof fn lemma_reached_push(c: Seq<Seq<u8>>, t: Seq<u8>, x: Seq<u8>)
    requires
        reached(c, x),
    ensures
        reached(c.push(t), x),
{
    let i = choose|i: int| 0 <= i < c.len() && c[i] == x;
    assert(c.push(t)[i] == x);
}

/// One step keeps DA3 and DA4, with one more record counted; returns the record numbers after it.
proof fn lemma_chain_step(d: Seq<u8>, at: int, i: nat, q: Seq<u8>, w: (Seq<Seq<u8>>, Seq<u32>, bool, bool), ka: Seq<nat>, km: Seq<nat>, p: int) -> (r: (Seq<nat>, Seq<nat>))
    requires
        record_start(d, at, i) == Some(p),
        record_at(d, p) is Some,
        step(d, w, record_at(d, p)->0) is Some,
        chain_ok(d, at, i, q, w, ka, km),
    ensures
        record_start(d, at, i + 1) == Some(next_of(record_at(d, p)->0)),
        chain_ok(d, at, i + 1, q, step(d, w, record_at(d, p)->0)->0, r.0, r.1),
{
    lemma_record_start_next(d, at, i);
    let rec = record_at(d, p)->0;
    let w2 = step(d, w, rec)->0;
    let grew = is_cname(rec) && reached(w.0, owner_of(rec)) && !reached(w.0, target_of(d, rec)->0) && w.0.len() <= MAX_CHAIN;
    let t = target_of(d, rec)->0;
    let added = is_a(rec) && reached(w.0, owner_of(rec)) && w.1.len() < MAX_ADDRS;
    let ka2 = if added { ka.push(i) } else { ka };
    let km2 = if grew { km.push(i) } else { km };
    if grew {
        assert(w2.0 == w.0.push(t));
    } else {
        assert(w2.0 == w.0);
    }
    if added {
        assert(w2.1 == w.1.push(spec_be32(d, data_at(rec)) as u32));
    } else {
        assert(w2.1 == w.1);
    }
    assert forall|x: Seq<u8>| reached(w.0, x) implies reached(w2.0, x) by {
        if grew {
            lemma_reached_push(w.0, t, x);
        }
    }
    assert forall|j: int| #![trigger w2.1[j]] #![trigger ka2[j]] 0 <= j < w2.1.len() implies ka2[j] < i + 1 && addr_from(d, at, w2.0, w2.1[j], ka2[j]) by {
        if j < w.1.len() {
            assert(w2.1[j] == w.1[j]);
            assert(ka2[j] == ka[j]);
            assert(addr_from(d, at, w.0, w.1[j], ka[j]));
            let rk = record_at(d, record_start(d, at, ka[j])->0)->0;
            assert(reached(w2.0, owner_of(rk)));
        } else {
            assert(ka2[j] == i);
        }
    }
    assert forall|m: int| #![trigger w2.0[m]] #![trigger km2[m]] 1 <= m < w2.0.len() implies km2[m] < i + 1 && alias_from(d, at, w2.0, w2.0[m], km2[m]) by {
        if m < w.0.len() {
            assert(w2.0[m] == w.0[m]);
            assert(km2[m] == km[m]);
            assert(alias_from(d, at, w.0, w.0[m], km[m]));
            let rk = record_at(d, record_start(d, at, km[m])->0)->0;
            assert(reached(w2.0, owner_of(rk)));
        } else {
            assert(km2[m] == i);
            assert(reached(w2.0, owner_of(rec)));
        }
    }
    (ka2, km2)
}

/// A walk over `n` records from record `i` keeps DA3 and DA4; returns the record numbers after it.
proof fn lemma_chain_walk(d: Seq<u8>, at: int, i: nat, n: nat, q: Seq<u8>, w: (Seq<Seq<u8>>, Seq<u32>, bool, bool), ka: Seq<nat>, km: Seq<nat>, p: int) -> (r: (Seq<nat>, Seq<nat>))
    requires
        record_start(d, at, i) == Some(p),
        chain_ok(d, at, i, q, w, ka, km),
        walk(d, p, n, w) is Some,
    ensures
        chain_ok(d, at, i + n, q, walk(d, p, n, w)->0, r.0, r.1),
    decreases n,
{
    if n == 0 {
        (ka, km)
    } else {
        let rec = record_at(d, p)->0;
        let w2 = step(d, w, rec)->0;
        let (ka2, km2) = lemma_chain_step(d, at, i, q, w, ka, km, p);
        let r = lemma_chain_walk(d, at, i + 1, (n - 1) as nat, q, w2, ka2, km2, next_of(rec));
        assert(i + 1 + (n - 1) as nat == i + n);
        r
    }
}

/// A byte pushed, then a sequence appended, is the byte and the sequence appended.
proof fn lemma_push_concat(a: Seq<u8>, b: u8, l: Seq<u8>)
    ensures
        a.push(b) + l == a + (Seq::<u8>::empty().push(b) + l),
{
    assert(a.push(b) + l =~= a + (Seq::<u8>::empty().push(b) + l));
}

/// Appending, then pushing, is appending the pushed sequence.
proof fn lemma_concat_push(a: Seq<u8>, l: Seq<u8>, c: u8)
    ensures
        (a + l).push(c) == a + l.push(c),
{
    assert((a + l).push(c) =~= a + l.push(c));
}

/// Nothing of a label lowered yet.
proof fn lemma_lowered_none(base: Seq<u8>, d: Seq<u8>, a: int)
    requires
        0 <= a <= d.len(),
    ensures
        base + lowered(d.subrange(a, a)) == base,
{
    assert(base + lowered(d.subrange(a, a)) =~= base);
}

/// One more byte of a label, lowered.
proof fn lemma_lowered_step(d: Seq<u8>, a: int, i: int)
    requires
        0 <= a,
        0 <= i,
        a + i < d.len(),
    ensures
        lowered(d.subrange(a, a + i + 1)) == lowered(d.subrange(a, a + i)).push(lower(d[a + i])),
{
    assert(lowered(d.subrange(a, a + i + 1)) =~= lowered(d.subrange(a, a + i)).push(lower(d[a + i])));
}

/// A name read ends inside the payload.
proof fn lemma_name_end(d: Seq<u8>, p: int)
    requires
        name_of(d, p) is Some,
    ensures
        p < (name_of(d, p)->0).1 <= d.len(),
{
    lemma_name_at_shape(d, p, p);
}

/// The names of a chain with one more pushed.
proof fn lemma_chain_view_push(c: Seq<Vec<u8>>, t: Vec<u8>)
    ensures
        chain_view(c.push(t)) == chain_view(c).push(t@),
{
    assert(chain_view(c.push(t)) =~= chain_view(c).push(t@));
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        i + 1 < d.len(),
    ensures
        r as int == spec_be16(d@, i as int),
))]
fn be16(d: &[u8], i: usize) -> u16 {
    (d[i] as u16) * 256 + (d[i + 1] as u16)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        i + 3 < d.len(),
    ensures
        r as int == spec_be32(d@, i as int),
))]
fn be32(d: &[u8], i: usize) -> u32 {
    (be16(d, i) as u32) * 65536 + (be16(d, i + 2) as u32)
}

/// What stands at one place of a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
enum Piece {
    /// The root byte: the name ends here.
    Root,
    /// A label of this many bytes, inside the payload.
    Label(usize),
    /// A pointer to this place, which is before the bound.
    Pointer(usize),
    /// Anything else, or outside the payload: no name.
    Bad,
}

#[cfg(verus_keep_ghost)]
verus! {

/// What stands at `p`, for a run of labels whose bound is `bound`: the four
/// cases of [`name_at`].
spec fn piece_at(d: Seq<u8>, p: int, bound: int) -> Piece {
    if p < 0 || p >= d.len() || bound < 0 {
        Piece::Bad
    } else if d[p] == 0 {
        Piece::Root
    } else if d[p] <= 63 {
        if p + 1 + d[p] as int > d.len() {
            Piece::Bad
        } else {
            Piece::Label(d[p] as usize)
        }
    } else if d[p] >= 192 {
        if p + 1 >= d.len() || (d[p] as int - 192) * 256 + d[p + 1] as int >= bound {
            Piece::Bad
        } else {
            Piece::Pointer(((d[p] as int - 192) * 256 + d[p + 1] as int) as usize)
        }
    } else {
        Piece::Bad
    }
}

/// `read_name`'s loop invariant, opaque so that the loop's query does not
/// unfold `name_at`.
#[verifier::opaque]
spec fn rn_inv(d: Seq<u8>, start: int, p: int, bound: int, out: Seq<u8>, end: Option<usize>) -> bool {
    // What is still to be read decides the whole: the name at `start`
    // is what was written followed by the name at `p`, and it ends
    // where the first pointer was, or where the rest ends.
    match name_at(d, p, bound) {
        Some((rest, e)) => name_at(d, start, start) == Some((
            out + rest,
            match end {
                Some(x) => x as int,
                None => e,
            },
        )),
        None => name_at(d, start, start) is None,
    }
}

/// The invariant at the start of `read_name`.
proof fn lemma_rn_start(d: Seq<u8>, start: int)
    ensures
        rn_inv(d, start, start, start, Seq::<u8>::empty(), None),
{
    reveal(rn_inv);
    if name_at(d, start, start) is Some {
        let rest = (name_at(d, start, start)->0).0;
        assert(Seq::<u8>::empty() + rest =~= rest);
    }
}

/// A bad piece: the name does not decode.
proof fn lemma_rn_bad(d: Seq<u8>, start: int, p: int, bound: int, out: Seq<u8>, end: Option<usize>)
    requires
        rn_inv(d, start, p, bound, out, end),
        p >= 0,
        bound >= 0,
        piece_at(d, p, bound) is Bad,
    ensures
        name_of(d, start) is None,
{
    reveal(rn_inv);
    lemma_piece(d, p, bound);
}

/// The root: the name is what was written and the root.
proof fn lemma_rn_root(d: Seq<u8>, start: int, p: int, bound: int, out: Seq<u8>, end: Option<usize>)
    requires
        rn_inv(d, start, p, bound, out, end),
        p >= 0,
        bound >= 0,
        piece_at(d, p, bound) is Root,
        out.len() < MAX_NAME,
    ensures
        p < d.len(),
        name_of(d, start) == Some((out.push(0u8), match end {
            Some(x) => x as int,
            None => p + 1,
        })),
{
    reveal(rn_inv);
    lemma_piece(d, p, bound);
    assert(out + Seq::<u8>::empty().push(0u8) =~= out.push(0u8));
}

/// A label: too long a name does not decode; otherwise the invariant holds after it.
proof fn lemma_rn_label(d: Seq<u8>, start: int, p: int, bound: int, out: Seq<u8>, end: Option<usize>, l: int)
    requires
        rn_inv(d, start, p, bound, out, end),
        p >= 0,
        bound >= 0,
        piece_at(d, p, bound) == Piece::Label(l as usize),
        0 <= l <= usize::MAX,
    ensures
        1 <= l <= 63,
        l == d[p],
        p + 1 + l <= d.len(),
        out.len() + 1 + l >= MAX_NAME ==> name_of(d, start) is None,
        rn_inv(d, start, p + 1 + l, bound, out.push(d[p]) + lowered(d.subrange(p + 1, p + 1 + l)), end),
{
    reveal(rn_inv);
    lemma_piece(d, p, bound);
    let lab = Seq::<u8>::empty().push(d[p]) + lowered(d.subrange(p + 1, p + 1 + l));
    assert(lab.len() == 1 + l);
    lemma_push_concat(out, d[p], lowered(d.subrange(p + 1, p + 1 + l)));
    if name_at(d, p + 1 + l, bound) is Some {
        let rest = (name_at(d, p + 1 + l, bound)->0).0;
        lemma_name_at_shape(d, p + 1 + l, bound);
        assert(out + (lab + rest) =~= (out + lab) + rest);
    }
}

/// A pointer: the invariant holds at its target, with the first pointer's end kept.
proof fn lemma_rn_pointer(d: Seq<u8>, start: int, p: int, bound: int, out: Seq<u8>, end: Option<usize>, t: int, end2: Option<usize>)
    requires
        rn_inv(d, start, p, bound, out, end),
        p >= 0,
        bound >= 0,
        piece_at(d, p, bound) == Piece::Pointer(t as usize),
        0 <= t <= usize::MAX,
        p + 2 <= usize::MAX,
        end2 == match end {
            Some(x) => Some(x),
            None => Some((p + 2) as usize),
        },
    ensures
        p + 1 < d.len(),
        0 <= t < bound,
        rn_inv(d, start, t, t, out, end2),
{
    reveal(rn_inv);
    lemma_piece(d, p, bound);
}

/// What each piece says of the name at `p` (one step of `name_at`).
proof fn lemma_piece(d: Seq<u8>, p: int, bound: int)
    requires
        p >= 0,
        bound >= 0,
    ensures
        piece_at(d, p, bound) is Bad ==> name_at(d, p, bound) is None,
        piece_at(d, p, bound) is Root ==> p < d.len() && name_at(d, p, bound) == Some((Seq::<u8>::empty().push(0u8), p + 1)),
        piece_at(d, p, bound) matches Piece::Label(l) ==> {
            &&& 1 <= l <= 63
            &&& l == d[p]
            &&& p + 1 + l <= d.len()
            &&& name_at(d, p, bound) == match name_at(d, p + 1 + l, bound) {
                Some((rest, end)) => Some((Seq::<u8>::empty().push(d[p]) + lowered(d.subrange(p + 1, p + 1 + l)) + rest, end)),
                None => None,
            }
        },
        piece_at(d, p, bound) matches Piece::Pointer(t) ==> {
            &&& p + 1 < d.len()
            &&& t < bound
            &&& name_at(d, p, bound) == match name_at(d, t as int, t as int) {
                Some((rest, end)) => Some((rest, p + 2)),
                None => None,
            }
        },
{
}

} // verus!

/// What stands at `p`.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == piece_at(d@, p as int, bound as int),
))]
fn piece(d: &[u8], p: usize, bound: usize) -> Piece {
    if p >= d.len() {
        return Piece::Bad;
    }
    let b = d[p];
    if b == 0 {
        Piece::Root
    } else if b <= 63 {
        if d.len() - p - 1 < b as usize {
            Piece::Bad
        } else {
            Piece::Label(b as usize)
        }
    } else if b >= 192 {
        if d.len() - p < 2 {
            return Piece::Bad;
        }
        let target = ((b - 192) as usize) * 256 + d[p + 1] as usize;
        if target >= bound {
            Piece::Bad
        } else {
            Piece::Pointer(target)
        }
    } else {
        Piece::Bad
    }
}

/// An ASCII capital letter lowered; any other byte as it is.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == lower(c),
))]
fn lower_byte(c: u8) -> u8 {
    if c >= 65 {
        if c <= 90 {
            return c + 32;
        }
    }
    c
}

/// Writes one label to `out`: its length byte, then its bytes with letters
/// lowered.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires
        1 <= len <= 63,
        p + 1 + len <= d@.len(),
        d@[p as int] == len,
    ensures
        final(out)@ == old(out)@.push(d@[p as int]) + lowered(d@.subrange(p as int + 1, p as int + 1 + len as int)),
))]
fn copy_label(d: &[u8], p: usize, len: usize, out: &mut Vec<u8>) {
    out.push(d[p]);
    let mut i: usize = 0;
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_lowered_none(old(out)@.push(d@[p as int]), d@, p as int + 1);
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= len,
            p + 1 + len <= d@.len(),
            out@ == old(out)@.push(d@[p as int]) + lowered(d@.subrange(p as int + 1, p as int + 1 + i as int)),
            p + 1 + len <= d.len(),
        decreases len - i,
    ))]
    while i < len {
        let c = d[p + 1 + i];
        out.push(lower_byte(c));
        #[cfg(verus_keep_ghost)]
        proof! {
            lemma_lowered_step(d@, p as int + 1, i as int);
            lemma_concat_push(old(out)@.push(d@[p as int]), lowered(d@.subrange(p as int + 1, p as int + 1 + i as int)), lower(c));
        }
        i += 1;
    }
}

/// The name that starts at `start` and the index after it, when it decodes
/// to at most [`MAX_NAME`] bytes.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Some((n, e)) => name_of(d@, start as int) == Some((n@, e as int)),
            None => name_of(d@, start as int) is None,
        },
))]
fn read_name(d: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut out: Vec<u8> = Vec::new();
    let mut p = start;
    let mut bound = start;
    let mut end: Option<usize> = None;
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_rn_start(d@, start as int);
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            out@.len() < MAX_NAME,
            bound <= start,
            rn_inv(d@, start as int, p as int, bound as int, out@, end),
        decreases bound, d@.len() - p,
    ))]
    loop {
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(d@.len() == d.len());
        }
        match piece(d, p, bound) {
            Piece::Bad => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rn_bad(d@, start as int, p as int, bound as int, out@, end);
                }
                return None;
            }
            Piece::Root => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rn_root(d@, start as int, p as int, bound as int, out@, end);
                }
                out.push(0);
                let e = match end {
                    Some(x) => x,
                    None => p + 1,
                };
                return Some((out, e));
            }
            Piece::Label(len) => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rn_label(d@, start as int, p as int, bound as int, out@, end, len as int);
                }
                if out.len() + 1 + len >= MAX_NAME {
                    return None;
                }
                copy_label(d, p, len, &mut out);
                p = p + 1 + len;
            }
            Piece::Pointer(target) => {
                #[cfg(verus_keep_ghost)]
                proof_decl! {
                    let ghost end0: Option<usize> = end;
                }
                match end {
                    Some(_) => {}
                    None => {
                        end = Some(p + 2);
                    }
                }
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_rn_pointer(d@, start as int, p as int, bound as int, out@, end0, target as int, end);
                }
                p = target;
                bound = target;
            }
        }
    }
}

/// Whether two names are the same bytes.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == (a@ == b@),
))]
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= a@.len(),
            a@.len() == b@.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a@.len() - i,
    ))]
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(a@ =~= b@);
    }
    true
}

/// Whether `n` is one of the names reached.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == reached(chain_view(chain@), n@),
))]
fn in_chain(chain: &Vec<Vec<u8>>, n: &[u8]) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= chain@.len(),
            forall|j: int| 0 <= j < i ==> chain@[j]@ != n@,
        decreases chain@.len() - i,
    ))]
    while i < chain.len() {
        if same(chain[i].as_slice(), n) {
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(chain_view(chain@)[i as int] == n@);
            }
            return true;
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert forall|j: int| 0 <= j < chain_view(chain@).len() implies #[trigger] chain_view(chain@)[j] != n@ by {
            assert(chain_view(chain@)[j] == chain@[j]@);
        }
    }
    false
}

#[cfg(verus_keep_ghost)]
verus! {

/// The names a chain holds, as sequences.
pub open spec fn chain_view(c: Seq<Vec<u8>>) -> Seq<Seq<u8>> {
    Seq::new(c.len(), |i: int| c[i]@)
}

} // verus!

/// What the walk holds: the names reached, the asked one first; the
/// addresses so far; and whether either ran past its bound.
#[cfg_attr(verus_keep_ghost, verus_verify)]
struct Held {
    chain: Vec<Vec<u8>>,
    addrs: Vec<u32>,
    more: bool,
    cut: bool,
}

#[cfg(verus_keep_ghost)]
verus! {

/// What is held, as a walk of the specification.
spec fn held_view(h: Held) -> (Seq<Seq<u8>>, Seq<u32>, bool, bool) {
    (chain_view(h.chain@), h.addrs@, h.more, h.cut)
}

/// What is held is within the bounds.
spec fn held_ok(h: Held) -> bool {
    h.chain@.len() >= 1 && h.chain@.len() <= MAX_CHAIN + 1 && h.addrs@.len() <= MAX_ADDRS
}

} // verus!

/// The record that starts at `p`: its owner, type, class, where its data
/// stands and how long it is.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Some((owner, typ, class, at, len)) => {
                &&& record_at(d@, p as int) == Some((owner@, typ as int, class as int, at as int, len as int, at as int + len as int))
                &&& at + len <= d@.len()
            },
            None => record_at(d@, p as int) is None,
        },
))]
fn read_record(d: &[u8], p: usize) -> Option<(Vec<u8>, u16, u16, usize, usize)> {
    let (owner, o) = match read_name(d, p) {
        Some(x) => x,
        None => {
            return None;
        }
    };
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_name_end(d@, p as int);
    }
    if d.len() - o < 10 {
        return None;
    }
    let len = be16(d, o + 8) as usize;
    let at = o + 10;
    if d.len() - at < len {
        return None;
    }
    Some((owner, be16(d, o), be16(d, o + 2), at, len))
}

/// One step of the walk: what is held after the record with this owner,
/// type, class and data, or `None` when the record makes the answer unread.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        held_ok(h),
        at + len <= d@.len(),
    ensures
        match r {
            Some(h2) => {
                &&& held_ok(h2)
                &&& step(d@, held_view(h), (owner@, typ as int, class as int, at as int, len as int, at as int + len as int))
                    == Some(held_view(h2))
            },
            None => step(d@, held_view(h), (owner@, typ as int, class as int, at as int, len as int, at as int + len as int))
                is None,
        },
))]
fn take(
    d: &[u8],
    h: Held,
    owner: &[u8],
    typ: u16,
    class: u16,
    at: usize,
    len: usize,
) -> Option<Held> {
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(d@.len() == d.len());
    }
    let mut h = h;
    if class == CLASS_IN && typ == TYPE_A {
        if len != 4 {
            return None;
        }
        if in_chain(&h.chain, owner) {
            if h.addrs.len() < MAX_ADDRS {
                h.addrs.push(be32(d, at));
            } else {
                h.more = true;
            }
        }
        Some(h)
    } else if class == CLASS_IN && typ == TYPE_CNAME {
        let target = match read_name(d, at) {
            Some((t, te)) => {
                if te != at + len {
                    return None;
                }
                t
            }
            None => {
                return None;
            }
        };
        if in_chain(&h.chain, owner) && !in_chain(&h.chain, target.as_slice()) {
            if h.chain.len() <= MAX_CHAIN {
                #[cfg(verus_keep_ghost)]
                proof! {
                    lemma_chain_view_push(h.chain@, target);
                }
                h.chain.push(target);
            } else {
                h.cut = true;
            }
        }
        Some(h)
    } else {
        Some(h)
    }
}

/// The header and the question: the asked name, the asked type and where
/// the answer section starts, or why the answer is unread.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Ok((q, qtype, at)) => opening(d@) == Ok::<(Seq<u8>, int, int), Unread>((q@, qtype as int, at as int)) && at <= d@.len(),
            Err(why) => opening(d@) == Err::<(Seq<u8>, int, int), Unread>(why),
        },
))]
fn read_opening(d: &[u8]) -> Result<(Vec<u8>, u16, usize), Unread> {
    if d.len() < HEADER {
        return Err(Unread::Short);
    }
    if d[2] & 0x80 == 0 {
        return Err(Unread::NotAResponse);
    }
    if d[2] & 0x78 != 0 {
        return Err(Unread::Operation);
    }
    if d[3] & 0x0f != 0 {
        return Err(Unread::Failed);
    }
    if be16(d, 4) != 1 {
        return Err(Unread::Questions);
    }
    let (q, e) = match read_name(d, HEADER) {
        Some(x) => x,
        None => {
            return Err(Unread::Question);
        }
    };
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_name_end(d@, HEADER as int);
    }
    if d.len() - e < 4 {
        return Err(Unread::Question);
    }
    if be16(d, e + 2) != CLASS_IN {
        return Err(Unread::Question);
    }
    Ok((q, be16(d, e), e + 4))
}

/// Reads one answer: the asked name and the addresses its answer section
/// gives for it, or why it gives none. DA1, DA2.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        answers(d@, r),
))]
pub fn answer_addresses(d: &[u8]) -> Answer {
    let (first, qtype, at) = match read_opening(d) {
        Ok(x) => x,
        Err(why) => {
            return Answer::Unread(why);
        }
    };
    let count = be16(d, 6);
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost q: Seq<u8> = first@;
    }
    let mut h = Held {
        chain: Vec::new(),
        addrs: Vec::new(),
        more: false,
        cut: false,
    };
    h.chain.push(first);
    let mut p = at;
    let mut left = count;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(chain_view(h.chain@) =~= Seq::<Seq<u8>>::empty().push(q));
        assert(h.addrs@ =~= Seq::<u32>::empty());
        assert(held_view(h) == start(q));
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            p <= d@.len(),
            held_ok(h),
            // What is left of the walk decides the whole.
            walk(d@, p as int, left as nat, held_view(h))
                == walk(d@, at as int, count as nat, start((opening(d@)->Ok_0).0)),
            // What the opening found, for a return inside the loop.
            opening(d@) == Ok::<(Seq<u8>, int, int), Unread>((q, qtype as int, at as int)),
            count as int == spec_be16(d@, 6),
        decreases left,
    ))]
    while left > 0 {
        let (owner, typ, class, data, len) = match read_record(d, p) {
            Some(x) => x,
            None => {
                return Answer::Unread(Unread::Record);
            }
        };
        h = match take(d, h, owner.as_slice(), typ, class, data, len) {
            Some(h2) => h2,
            None => {
                return Answer::Unread(Unread::Record);
            }
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(d@.len() == d.len());
        }
        p = data + len;
        left -= 1;
    }
    // The asked name once more, for the result: the walk holds the first reading.
    let asked = match read_opening(d) {
        Ok((q, _, _)) => q,
        Err(why) => {
            return Answer::Unread(why);
        }
    };
    Answer::Read(Given {
        id: be16(d, 0),
        asked,
        qtype,
        truncated: d[2] & 0x02 != 0,
        addrs: h.addrs,
        more: h.more,
        chain_cut: h.cut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response with one question for `name` and these records in its
    /// answer section, each an owner on the wire, a type, a class and data.
    fn reply(flags: [u8; 2], name: &[u8], records: &[(&[u8], u16, u16, &[u8])]) -> Vec<u8> {
        let mut d = vec![0xbe, 0xef, flags[0], flags[1], 0, 1];
        d.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        d.extend_from_slice(&[0; 4]);
        d.extend_from_slice(name);
        d.extend_from_slice(&[0, 1, 0, 1]);
        for (owner, typ, class, data) in records {
            d.extend_from_slice(owner);
            d.extend_from_slice(&typ.to_be_bytes());
            d.extend_from_slice(&class.to_be_bytes());
            d.extend_from_slice(&[0, 0, 0, 60]);
            d.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            d.extend_from_slice(data);
        }
        d
    }

    const OK: [u8; 2] = [0x81, 0x80];
    const WEB: &[u8] = b"\x03web\x07example\x00";
    /// A pointer to the question's name at byte 12.
    const ASKED: &[u8] = &[0xc0, 12];

    fn given(d: &[u8]) -> Given {
        match answer_addresses(d) {
            Answer::Read(g) => g,
            Answer::Unread(why) => panic!("unread: {why:?}"),
        }
    }

    fn unread(d: &[u8]) -> Unread {
        match answer_addresses(d) {
            Answer::Read(_) => panic!("read"),
            Answer::Unread(why) => why,
        }
    }

    #[test]
    fn addresses_of_the_asked_name_are_given_in_order() {
        let d = reply(
            OK,
            b"\x03WEB\x07Example\x00",
            &[(ASKED, 1, 1, &[10, 0, 0, 1]), (WEB, 1, 1, &[10, 0, 0, 2])],
        );
        let g = given(&d);
        assert_eq!(g.asked, WEB);
        assert_eq!(g.id, 0xbeef);
        assert_eq!(g.qtype, 1);
        assert_eq!(g.addrs, vec![0x0a00_0001, 0x0a00_0002]);
        assert!(!g.more && !g.chain_cut && !g.truncated);
    }

    #[test]
    fn an_alias_is_followed_only_forward_and_only_from_a_name_reached() {
        let cdn: &[u8] = b"\x03cdn\x07example\x00";
        let other: &[u8] = b"\x05other\x07example\x00";
        // The target's address before the alias that reaches it is not given.
        let early = reply(OK, WEB, &[(cdn, 1, 1, &[10, 0, 0, 9]), (ASKED, 5, 1, cdn)]);
        assert!(given(&early).addrs.is_empty());
        let late = reply(OK, WEB, &[(ASKED, 5, 1, cdn), (cdn, 1, 1, &[10, 0, 0, 9])]);
        assert_eq!(given(&late).addrs, vec![0x0a00_0009]);
        // An alias owned by a name that was not reached reaches nothing.
        let off = reply(OK, WEB, &[(other, 5, 1, cdn), (cdn, 1, 1, &[10, 0, 0, 9])]);
        assert!(given(&off).addrs.is_empty());
    }

    #[test]
    fn another_owner_type_or_class_is_read_past() {
        let other: &[u8] = b"\x05other\x07example\x00";
        let d = reply(
            OK,
            WEB,
            &[
                (other, 1, 1, &[10, 0, 0, 3]),
                (ASKED, 28, 1, &[0; 16]),
                (ASKED, 1, 3, &[10, 0, 0, 4]),
                (ASKED, 1, 1, &[10, 0, 0, 5]),
            ],
        );
        assert_eq!(given(&d).addrs, vec![0x0a00_0005]);
    }

    #[test]
    fn what_is_not_a_plain_answer_gives_nothing() {
        let a: &[(&[u8], u16, u16, &[u8])] = &[(ASKED, 1, 1, &[10, 0, 0, 1])];
        assert_eq!(unread(&[0; 11]), Unread::Short);
        assert_eq!(unread(&reply([0x01, 0x00], WEB, a)), Unread::NotAResponse);
        assert_eq!(unread(&reply([0xa9, 0x80], WEB, a)), Unread::Operation);
        assert_eq!(unread(&reply([0x81, 0x83], WEB, a)), Unread::Failed);
        let mut two = reply(OK, WEB, a);
        two[5] = 2;
        assert_eq!(unread(&two), Unread::Questions);
        let short = reply(OK, WEB, &[(ASKED, 1, 1, &[10, 0, 0])]);
        assert_eq!(unread(&short), Unread::Record);
        let whole = reply(OK, WEB, a);
        assert_eq!(unread(&whole[..whole.len() - 1]), Unread::Record);
    }

    #[test]
    fn a_pointer_forward_or_at_itself_is_not_followed() {
        let at_itself = reply(OK, WEB, &[(&[0xc0, 29], 1, 1, &[10, 0, 0, 1])]);
        assert_eq!(unread(&at_itself), Unread::Record);
        let forward = reply(OK, WEB, &[(&[0xc0, 200], 1, 1, &[10, 0, 0, 1])]);
        assert_eq!(unread(&forward), Unread::Record);
    }

    #[test]
    fn what_follows_the_answer_section_is_not_read() {
        let mut d = reply(OK, WEB, &[(ASKED, 1, 1, &[10, 0, 0, 1])]);
        d.extend_from_slice(&[0xff; 9]);
        assert_eq!(given(&d).addrs, vec![0x0a00_0001]);
    }

    #[test]
    fn the_bounds_are_said_and_nothing_is_given_past_them() {
        let mut records: Vec<(&[u8], u16, u16, &[u8])> = Vec::new();
        let data: Vec<[u8; 4]> = (0..40u8).map(|i| [10, 0, 0, i]).collect();
        for a in &data {
            records.push((ASKED, 1, 1, a));
        }
        let g = given(&reply(OK, WEB, &records));
        assert_eq!(g.addrs.len(), MAX_ADDRS);
        assert!(g.more);
    }

    /// The domain pre-check of the Kani harnesses in `mod proofs`: each
    /// harness's inputs drawn under its own assumptions, in its own order,
    /// and the turns of every loop it reaches counted. Kani's
    /// `#[kani::unwind(N)]` passes a loop that goes round at most N - 1
    /// times in one call: above that a check FAILS, and at N - 2 or above it
    /// prints a WARN. The loops are counted in COPIES kept here, each checked
    /// against the code on every draw (the lines marked `counted` are the
    /// only additions to a copy); that each copy is still of the text it was
    /// copied from is checked outside the crate. A failure here is a finding
    /// about a harness, never a reason to change the code.
    mod domain_check {
        use super::super::*;

        /// Random draws per harness, beside the exhaustive ones and the
        /// inputs from the prediction table.
        const DRAWS: usize = 100_000;

        // The generator.

        /// SplitMix64 with a fixed seed: every run draws the same inputs.
        /// The crate has no dependencies.
        struct Gen(u64);

        impl Gen {
            fn word(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }

            /// A byte: half the time any byte, half the time one of the bytes
            /// where the reader's decisions change.
            fn byte(&mut self) -> u8 {
                const EDGES: [u8; 28] = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 63, 64, 127, 128,
                    135, 191, 192, 193, 255, 0x41, 0x5a,
                ];
                let r = self.word();
                if r & 1 == 0 {
                    (r >> 8) as u8
                } else {
                    EDGES[((r >> 8) % EDGES.len() as u64) as usize]
                }
            }

            /// A number from 0 to `k`: what `kani::any()` followed by
            /// `kani::assume(x <= k)` leaves.
            fn upto(&mut self, k: usize) -> usize {
                (self.word() % (k as u64 + 1)) as usize
            }
        }

        /// The generator for a harness, seeded by FNV-1a of its name.
        fn seed(name: &str) -> Gen {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in name.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            Gen(h)
        }

        fn fill(g: &mut Gen, d: &mut [u8]) {
            for x in d.iter_mut() {
                *x = g.byte();
            }
        }

        /// Lays a name along its own walk from `start`: at each place the
        /// walk reaches, a root, a label or a pointer back, chosen at random,
        /// written over what is there. Random bytes almost never make a
        /// name of many pieces; this only changes how often each input is
        /// drawn, and the harness's assumptions still decide which count.
        fn lay(g: &mut Gen, d: &mut [u8], start: usize) {
            let mut p = start;
            let mut bound = start;
            let mut k = 0;
            while k < 12 && p + 1 < d.len() {
                k += 1;
                let pick = g.word() % 8;
                if pick == 0 {
                    d[p] = 0;
                    return;
                } else if pick < 5 || bound == 0 {
                    let room = (d.len() - p - 1).min(63);
                    let len = if g.word().is_multiple_of(2) {
                        1 + g.upto(room.min(3) - 1)
                    } else {
                        1 + g.upto(room - 1)
                    };
                    d[p] = len as u8;
                    p += 1 + len;
                } else {
                    let t = g.upto(bound - 1);
                    d[p] = 0xc0 | (t >> 8) as u8;
                    d[p + 1] = (t & 0xff) as u8;
                    p = t;
                    bound = t;
                }
            }
        }

        /// For five bytes the reader tells no two bytes of one class apart
        /// (dnsa.rs:917-943): 0 the root; 1 to 4 labels that can fit; 5 for
        /// 5..=63, labels that cannot; 64 for 64..=191; 192 a pointer whose
        /// target is the next byte; 193 for 193..=255, pointers past every
        /// bound. A pointer's second byte is itself one of these.
        const CLASSES: [u8; 9] = [0, 1, 2, 3, 4, 5, 64, 192, 193];

        /// Every five bytes over [`CLASSES`].
        fn every_five(mut f: impl FnMut([u8; N])) {
            for i in 0..59_049usize {
                let mut k = i;
                let mut d = [0u8; N];
                for x in d.iter_mut() {
                    *x = CLASSES[k % 9];
                    k /= 9;
                }
                f(d);
            }
        }

        // The counts.

        /// The most turns that went round in one call, for each loop a
        /// harness reaches; `own` is the harness's own loop.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Most {
            own: u32,
            walk2: u32,
            read_name: u32,
            copy_label: u32,
            answer: u32,
            in_chain: u32,
            same: u32,
        }

        const ZERO: Most = Most {
            own: 0,
            walk2: 0,
            read_name: 0,
            copy_label: 0,
            answer: 0,
            in_chain: 0,
            same: 0,
        };

        impl Most {
            fn loops(&self) -> [(&'static str, u32); 7] {
                [
                    ("own", self.own),
                    ("walk2", self.walk2),
                    ("read_name", self.read_name),
                    ("copy_label", self.copy_label),
                    ("answer", self.answer),
                    ("in_chain", self.in_chain),
                    ("same", self.same),
                ]
            }
        }

        fn up(most: &mut u32, back: u32) {
            if back > *most {
                *most = back;
            }
        }

        /// The loops that went round more than `unwind - 1` times in one
        /// call: Kani's unwinding check fails on each.
        fn over(unwind: u32, most: &Most) -> Vec<(&'static str, u32)> {
            let mut bad = Vec::new();
            for (name, back) in most.loops() {
                if back > unwind - 1 {
                    bad.push((name, back));
                }
            }
            bad
        }

        /// FAIL above `unwind - 1`, WARN at `unwind - 2` or above, and the
        /// maxima of the prediction table reached.
        fn judge(harness: &str, unwind: u32, most: &Most, predicted: &Most) {
            for (name, back) in most.loops() {
                if back + 2 >= unwind && back < unwind {
                    println!(
                        "WARN {harness}: {name} went round {back} times under unwind({unwind})"
                    );
                }
            }
            let bad = over(unwind, most);
            assert!(
                bad.is_empty(),
                "FAIL {harness}: above unwind({unwind}) - 1: {bad:?}"
            );
            assert_eq!(
                most, predicted,
                "{harness}: the maxima are not the predicted ones"
            );
        }

        // Copies of the code's loops, and of the functions between a
        // harness and them.

        /// COPY of `copy_label` (dnsa.rs:971-996), proof blocks left out.
        fn copy_label_c(d: &[u8], p: usize, len: usize, out: &mut Vec<u8>, most: &mut Most) {
            out.push(d[p]);
            let mut i: usize = 0;
            let mut back = 0; // counted
            while i < len {
                let c = d[p + 1 + i];
                out.push(lower_byte(c));
                i += 1;
                back += 1; // counted
                up(&mut most.copy_label, back); // counted
            }
        }

        /// COPY of `read_name` (dnsa.rs:1008-1080), proof blocks left out.
        fn read_name_c(d: &[u8], start: usize, most: &mut Most) -> Option<(Vec<u8>, usize)> {
            let mut out: Vec<u8> = Vec::new();
            let mut p = start;
            let mut bound = start;
            let mut end: Option<usize> = None;
            let mut back = 0; // counted
            loop {
                match piece(d, p, bound) {
                    Piece::Bad => {
                        return None;
                    }
                    Piece::Root => {
                        out.push(0);
                        let e = match end {
                            Some(x) => x,
                            None => p + 1,
                        };
                        return Some((out, e));
                    }
                    Piece::Label(len) => {
                        if out.len() + 1 + len >= MAX_NAME {
                            return None;
                        }
                        copy_label_c(d, p, len, &mut out, most);
                        p = p + 1 + len;
                    }
                    Piece::Pointer(target) => {
                        match end {
                            Some(_) => {}
                            None => {
                                end = Some(p + 2);
                            }
                        }
                        p = target;
                        bound = target;
                    }
                }
                back += 1; // counted
                up(&mut most.read_name, back); // counted
            }
        }

        /// COPY of `same` (dnsa.rs:1088-1111), proof blocks left out.
        fn same_c(a: &[u8], b: &[u8], most: &mut Most) -> bool {
            if a.len() != b.len() {
                return false;
            }
            let mut i: usize = 0;
            let mut back = 0; // counted
            while i < a.len() {
                if a[i] != b[i] {
                    return false;
                }
                i += 1;
                back += 1; // counted
                up(&mut most.same, back); // counted
            }
            true
        }

        /// COPY of `in_chain` (dnsa.rs:1119-1144), proof blocks left out.
        fn in_chain_c(chain: &Vec<Vec<u8>>, n: &[u8], most: &mut Most) -> bool {
            let mut i: usize = 0;
            let mut back = 0; // counted
            while i < chain.len() {
                if same_c(chain[i].as_slice(), n, most) {
                    return true;
                }
                i += 1;
                back += 1; // counted
                up(&mut most.in_chain, back); // counted
            }
            false
        }

        /// COPY of `read_record` (dnsa.rs:1194-1214), proof blocks left out.
        fn read_record_c(
            d: &[u8],
            p: usize,
            most: &mut Most,
        ) -> Option<(Vec<u8>, u16, u16, usize, usize)> {
            let (owner, o) = match read_name_c(d, p, most) {
                Some(x) => x,
                None => {
                    return None;
                }
            };
            if d.len() - o < 10 {
                return None;
            }
            let len = be16(d, o + 8) as usize;
            let at = o + 10;
            if d.len() - at < len {
                return None;
            }
            Some((owner, be16(d, o), be16(d, o + 2), at, len))
        }

        /// COPY of `take` (dnsa.rs:1234-1287), proof blocks left out; the
        /// type and class come as one pair, to keep to seven arguments.
        fn take_c(
            d: &[u8],
            h: Held,
            owner: &[u8],
            (typ, class): (u16, u16),
            at: usize,
            len: usize,
            most: &mut Most,
        ) -> Option<Held> {
            let mut h = h;
            if class == CLASS_IN && typ == TYPE_A {
                if len != 4 {
                    return None;
                }
                if in_chain_c(&h.chain, owner, most) {
                    if h.addrs.len() < MAX_ADDRS {
                        h.addrs.push(be32(d, at));
                    } else {
                        h.more = true;
                    }
                }
                Some(h)
            } else if class == CLASS_IN && typ == TYPE_CNAME {
                let target = match read_name_c(d, at, most) {
                    Some((t, te)) => {
                        if te != at + len {
                            return None;
                        }
                        t
                    }
                    None => {
                        return None;
                    }
                };
                if in_chain_c(&h.chain, owner, most)
                    && !in_chain_c(&h.chain, target.as_slice(), most)
                {
                    if h.chain.len() <= MAX_CHAIN {
                        h.chain.push(target);
                    } else {
                        h.cut = true;
                    }
                }
                Some(h)
            } else {
                Some(h)
            }
        }

        /// COPY of `read_opening` (dnsa.rs:1299-1332), proof blocks left out.
        fn read_opening_c(d: &[u8], most: &mut Most) -> Result<(Vec<u8>, u16, usize), Unread> {
            if d.len() < HEADER {
                return Err(Unread::Short);
            }
            if d[2] & 0x80 == 0 {
                return Err(Unread::NotAResponse);
            }
            if d[2] & 0x78 != 0 {
                return Err(Unread::Operation);
            }
            if d[3] & 0x0f != 0 {
                return Err(Unread::Failed);
            }
            if be16(d, 4) != 1 {
                return Err(Unread::Questions);
            }
            let (q, e) = match read_name_c(d, HEADER, most) {
                Some(x) => x,
                None => {
                    return Err(Unread::Question);
                }
            };
            if d.len() - e < 4 {
                return Err(Unread::Question);
            }
            if be16(d, e + 2) != CLASS_IN {
                return Err(Unread::Question);
            }
            Ok((q, be16(d, e), e + 4))
        }

        /// COPY of `answer_addresses` (dnsa.rs:1341-1416), proof blocks
        /// left out.
        fn answer_addresses_c(d: &[u8], most: &mut Most) -> Answer {
            let (first, qtype, at) = match read_opening_c(d, most) {
                Ok(x) => x,
                Err(why) => {
                    return Answer::Unread(why);
                }
            };
            let count = be16(d, 6);
            let mut h = Held {
                chain: Vec::new(),
                addrs: Vec::new(),
                more: false,
                cut: false,
            };
            h.chain.push(first);
            let mut p = at;
            let mut left = count;
            let mut back = 0; // counted
            while left > 0 {
                let (owner, typ, class, data, len) = match read_record_c(d, p, most) {
                    Some(x) => x,
                    None => {
                        return Answer::Unread(Unread::Record);
                    }
                };
                h = match take_c(d, h, owner.as_slice(), (typ, class), data, len, most) {
                    Some(h2) => h2,
                    None => {
                        return Answer::Unread(Unread::Record);
                    }
                };
                p = data + len;
                left -= 1;
                back += 1; // counted
                up(&mut most.answer, back); // counted
            }
            let asked = match read_opening_c(d, most) {
                Ok((q, _, _)) => q,
                Err(why) => {
                    return Answer::Unread(why);
                }
            };
            Answer::Read(Given {
                id: be16(d, 0),
                asked,
                qtype,
                truncated: d[2] & 0x02 != 0,
                addrs: h.addrs,
                more: h.more,
                chain_cut: h.cut,
            })
        }

        /// Two answers are the same, field by field (`Answer` derives no
        /// comparison).
        fn agree(a: &Answer, b: &Answer) -> bool {
            match (a, b) {
                (Answer::Read(x), Answer::Read(y)) => {
                    x.id == y.id
                        && x.asked == y.asked
                        && x.qtype == y.qtype
                        && x.truncated == y.truncated
                        && x.addrs == y.addrs
                        && x.more == y.more
                        && x.chain_cut == y.chain_cut
                }
                (Answer::Unread(x), Answer::Unread(y)) => x == y,
                _ => false,
            }
        }

        // Copies of the harnesses' helpers in `mod proofs`, which is built
        // only under Kani.

        /// COPY of `N` (dnsa.rs:1562).
        const N: usize = 5;
        /// COPY of `TURNS` (dnsa.rs:1564).
        const TURNS: usize = 7;

        /// COPY of `piece2` (dnsa.rs:1568-1596).
        fn piece2_c(d: &[u8], p: usize, bound: usize) -> Piece {
            if p >= d.len() {
                return Piece::Bad;
            }
            let b = d[p];
            match b >> 6 {
                0 => {
                    if b == 0 {
                        Piece::Root
                    } else if p + b as usize >= d.len() {
                        Piece::Bad
                    } else {
                        Piece::Label(b as usize)
                    }
                }
                3 => {
                    if p + 1 >= d.len() {
                        return Piece::Bad;
                    }
                    let t = u16::from_be_bytes([b & 0x3f, d[p + 1]]) as usize;
                    if t < bound {
                        Piece::Pointer(t)
                    } else {
                        Piece::Bad
                    }
                }
                _ => Piece::Bad,
            }
        }

        /// COPY of `Walk` (dnsa.rs:1599-1612).
        enum WalkC {
            NoName,
            Past,
            Name {
                byte: Option<u8>,
                len: usize,
                end: usize,
            },
        }

        /// COPY of `walk2` (dnsa.rs:1615-1678).
        fn walk2_c(d: &[u8], start: usize, want: usize, most: &mut Most) -> WalkC {
            let mut p = start;
            let mut bound = start;
            let mut n: usize = 0;
            let mut end: Option<usize> = None;
            let mut byte: Option<u8> = None;
            let mut turns = 0;
            let mut back = 0; // counted
            while turns < TURNS {
                turns += 1;
                if p >= d.len() {
                    return WalkC::NoName;
                }
                let b = d[p];
                if b == 0 {
                    if n == want {
                        byte = Some(0);
                    }
                    return WalkC::Name {
                        byte,
                        len: n + 1,
                        end: match end {
                            Some(e) => e,
                            None => p + 1,
                        },
                    };
                }
                match b >> 6 {
                    0 => {
                        let l = b as usize;
                        if p + l >= d.len() {
                            return WalkC::NoName;
                        }
                        if want >= n && want - n <= l {
                            let c = d[p + (want - n)];
                            byte = Some(if want == n {
                                c
                            } else if c.is_ascii_uppercase() {
                                c | 0x20
                            } else {
                                c
                            });
                        }
                        n += 1 + l;
                        p += 1 + l;
                    }
                    3 => {
                        if p + 1 >= d.len() {
                            return WalkC::NoName;
                        }
                        let t = ((b as usize & 0x3f) << 8) | d[p + 1] as usize;
                        if t >= bound {
                            return WalkC::NoName;
                        }
                        if end.is_none() {
                            end = Some(p + 2);
                        }
                        p = t;
                        bound = t;
                    }
                    _ => return WalkC::NoName,
                }
                back += 1; // counted
                up(&mut most.walk2, back); // counted
            }
            WalkC::Past
        }

        /// COPY of `quiet` (dnsa.rs:1681-1683).
        fn quiet_c(b: u8) -> bool {
            b <= 3 || b >= 0x40
        }

        /// COPY of `word2` (dnsa.rs:1685-1687).
        fn word2_c(d: &[u8], i: usize) -> u16 {
            u16::from_be_bytes([d[i], d[i + 1]])
        }

        /// COPY of `written` (dnsa.rs:1942-1947).
        fn written_c(x: u8, records: u8, class: [u8; 2], data: [u8; 4]) -> [u8; 35] {
            [
                0xbe, 0xef, 0x81, 0x80, 0, 1, 0, records, 0, 0, 0, 0, 1, x, 0, 0, 1, 0, 1, 0xc0,
                12, 0, 1, class[0], class[1], 0, 0, 0, 60, 0, 4, data[0], data[1], data[2],
                data[3],
            ]
        }

        // Copies of the harness bodies, in their statement order: the free
        // inputs come as arguments, an assumption is a return where it
        // stands (so what ran before it is counted), each call to the code
        // goes to a counted copy whose result is checked against the code,
        // and `kani::cover!` is left out.

        /// COPY of the body of `kani_same_is_equality` (dnsa.rs:1725-1743).
        fn same_is_equality_c(a: [u8; 4], b: [u8; 4], n: usize, m: usize, most: &mut Most) {
            // kani::assume(n <= 4 && m <= 4): the draw gives no other.
            let mut equal = n == m;
            let mut i = 0;
            let mut back = 0; // counted
            while i < 4 {
                if i < n && i < m && a[i] != b[i] {
                    equal = false;
                }
                i += 1;
                back += 1; // counted
                up(&mut most.own, back); // counted
            }
            let got = same_c(&a[..n], &b[..m], most);
            assert_eq!(got, same(&a[..n], &b[..m]));
            assert!(got == equal);
        }

        /// COPY of `a_name_agrees_from` (dnsa.rs:1750-1779), the body of
        /// `kani_a_name_agrees_from_0` to `_5` (dnsa.rs:1782-1833).
        fn a_name_agrees_from_c(start: usize, d: [u8; N], want: usize, most: &mut Most) {
            // kani::assume(want <= 2 * N): the draw gives no other.
            let got = read_name_c(&d, start, most);
            assert_eq!(got, read_name(&d, start));
            match walk2_c(&d, start, want, most) {
                WalkC::Past => {
                    // kani::assume(false)
                }
                WalkC::NoName => {
                    assert!(got.is_none());
                }
                WalkC::Name { byte, len, end } => match got {
                    None => {
                        panic!("the second reading finds a name the code does not");
                    }
                    Some((name, e)) => {
                        assert!(name.len() == len);
                        assert!(e == end);
                        if want < len {
                            assert!(byte == Some(name[want]));
                        }
                    }
                },
            }
        }

        /// COPY of the body of `kani_a_record_agrees` (dnsa.rs:1841-1871).
        fn a_record_agrees_c(d: [u8; N + 10], p: usize, most: &mut Most) {
            // kani::assume(p <= 2): the draw gives no other.
            let owner = walk2_c(&d[..N], p, 0, most);
            if !matches!(owner, WalkC::Name { .. }) {
                return; // kani::assume(matches!(owner, Walk::Name { .. }))
            }
            let got = read_record_c(&d, p, most);
            assert_eq!(got, read_record(&d, p));
            match owner {
                WalkC::Past => panic!("assumed away"),
                WalkC::NoName => panic!("assumed away"),
                WalkC::Name { byte: _, len, end } => {
                    assert!(end <= N);
                    let fits =
                        end + 10 <= d.len() && end + 10 + word2_c(&d, end + 8) as usize <= d.len();
                    match got {
                        None => assert!(!fits),
                        Some((owner, typ, class, at, data)) => {
                            assert!(fits);
                            assert!(owner.len() == len);
                            assert!(typ == word2_c(&d, end));
                            assert!(class == word2_c(&d, end + 2));
                            assert!(at == end + 10);
                            assert!(data == word2_c(&d, end + 8) as usize);
                        }
                    }
                }
            }
        }

        /// The record harness as the brief describes it before its fix,
        /// RECONSTRUCTED, not copied: the owner is settled after the call,
        /// so the assumption that follows cuts nothing already counted.
        fn old_record_c(d: [u8; N + 10], p: usize, most: &mut Most) {
            let got = read_record_c(&d, p, most);
            assert_eq!(got, read_record(&d, p));
            let _owner = walk2_c(&d[..N], p, 0, most);
        }

        /// COPY of the body of `kani_too_short_is_unread` (dnsa.rs:1874-1883).
        fn too_short_is_unread_c(d: [u8; 11], most: &mut Most) {
            let mut n = 0;
            let mut back = 0; // counted
            while n <= 11 {
                let got = read_opening_c(&d[..n], most);
                assert_eq!(got, read_opening(&d[..n]));
                assert!(matches!(got, Err(Unread::Short)));
                n += 1;
                back += 1; // counted
                up(&mut most.own, back); // counted
            }
        }

        /// COPY of the body of `kani_the_opening_decides_in_order`
        /// (dnsa.rs:1891-1937). With `quiet_header` false it is the harness
        /// before its fix as the brief describes it (RECONSTRUCTED): the
        /// header's free bytes not kept quiet.
        #[expect(
            clippy::manual_unwrap_or_default,
            reason = "a copy of the harness kani_the_opening_decides_in_order, kept as its text is"
        )]
        fn opening_c(d: [u8; HEADER + N], quiet_header: bool, most: &mut Most) {
            if quiet_header {
                if !(quiet_c(d[0]) && quiet_c(d[1])) {
                    return;
                }
                if !(quiet_c(d[6]) && quiet_c(d[7]) && quiet_c(d[8])) {
                    return;
                }
                if !(quiet_c(d[9]) && quiet_c(d[10]) && quiet_c(d[11])) {
                    return;
                }
            }
            let name = walk2_c(&d, HEADER, 0, most);
            if matches!(name, WalkC::Past) {
                return; // kani::assume(!matches!(name, Walk::Past))
            }
            let got = read_opening_c(&d, most);
            assert_eq!(got, read_opening(&d));
            if d[2] & 0x80 == 0 {
                assert!(matches!(got, Err(Unread::NotAResponse)));
            } else if d[2] & 0x78 != 0 {
                assert!(matches!(got, Err(Unread::Operation)));
            } else if d[3] & 0x0f != 0 {
                assert!(matches!(got, Err(Unread::Failed)));
            } else if d[4] != 0 || d[5] != 1 {
                assert!(matches!(got, Err(Unread::Questions)));
            } else {
                let end = match name {
                    WalkC::Name {
                        byte: _,
                        len: _,
                        end,
                    } => Some(end),
                    _ => None,
                };
                let good = match end {
                    Some(e) => e + 4 <= d.len() && d[e + 2] == 0 && d[e + 3] == 1,
                    None => false,
                };
                match got {
                    Ok((_, qtype, at)) => {
                        assert!(good);
                        let e = match end {
                            Some(e) => e,
                            None => 0,
                        };
                        assert!(qtype == word2_c(&d, e));
                        assert!(at == e + 4);
                    }
                    Err(why) => assert!(!good && matches!(why, Unread::Question)),
                }
            }
        }

        /// COPY of the body of `kani_a_written_answer_gives_its_address`
        /// (dnsa.rs:1952-1973).
        fn written_answer_c(x: u8, class: [u8; 2], data: [u8; 4], most: &mut Most) {
            let d = written_c(x, 1, class, data);
            let got = answer_addresses_c(&d, most);
            assert!(agree(&got, &answer_addresses(&d)));
            match got {
                Answer::Unread(_) => panic!("a written answer is read"),
                Answer::Read(g) => {
                    assert!(g.id == 0xbeef && g.qtype == 1 && !g.truncated);
                    assert!(g.asked.len() == 3 && g.asked[0] == 1 && g.asked[2] == 0);
                    assert!(g.asked[1] == if x.is_ascii_uppercase() { x | 0x20 } else { x });
                    assert!(!g.more && !g.chain_cut);
                    if class[0] == 0 && class[1] == 1 {
                        assert!(g.addrs.len() == 1 && g.addrs[0] == u32::from_be_bytes(data));
                    } else {
                        assert!(g.addrs.is_empty());
                    }
                }
            }
        }

        /// COPY of the body of `kani_no_counted_record_reads_nothing_more`
        /// (dnsa.rs:1977-1991).
        fn no_counted_record_c(rest: [u8; 16], most: &mut Most) {
            let mut d = written_c(b'x', 0, [0, 1], [0; 4]);
            let mut i = 0;
            let mut back = 0; // counted
            while i < 16 {
                d[19 + i] = rest[i];
                i += 1;
                back += 1; // counted
                up(&mut most.own, back); // counted
            }
            let got = answer_addresses_c(&d, most);
            assert!(agree(&got, &answer_addresses(&d)));
            match got {
                Answer::Unread(_) => panic!("a written answer is read"),
                Answer::Read(g) => assert!(g.addrs.is_empty() && !g.more && !g.chain_cut),
            }
        }

        // The draws.

        /// The record harness's free inputs: fifteen bytes, half the time a
        /// name laid from `p` in the first `width`; and `p` up to 2.
        fn record_draw(g: &mut Gen, width: usize) -> ([u8; N + 10], usize) {
            let mut d = [0u8; N + 10];
            fill(g, &mut d);
            let p = g.upto(2);
            if g.word().is_multiple_of(2) {
                lay(g, &mut d[..width], p);
            }
            (d, p)
        }

        /// The opening harness's seventeen free bytes: half the time a
        /// header that lets the question be read, half the time a name laid
        /// from the question. Neither is an assumption: the harness's own
        /// still decide which draws count.
        fn opening_draw(g: &mut Gen) -> [u8; HEADER + N] {
            let mut d = [0u8; HEADER + N];
            fill(g, &mut d);
            if g.word().is_multiple_of(2) {
                d[2] = 0x80 | g.upto(7) as u8;
                d[3] = (g.upto(15) as u8) << 4;
                d[4] = 0;
                d[5] = 1;
            }
            if g.word().is_multiple_of(2) {
                lay(g, &mut d, HEADER);
            }
            d
        }

        /// The written harness's free inputs: half the time class IN.
        fn written_draw(g: &mut Gen) -> (u8, [u8; 2], [u8; 4]) {
            let x = g.byte();
            let class = if g.word().is_multiple_of(2) {
                [0, 1]
            } else {
                [g.byte(), g.byte()]
            };
            let data = [g.byte(), g.byte(), g.byte(), g.byte()];
            (x, class, data)
        }

        /// Inputs from the prediction table for the opening harness: the
        /// most turns of `walk2` (7, rejected after it ran), of `read_name`
        /// (6) and of `copy_label` (4).
        const OPENING_AT_MOST: [[u8; HEADER + N]; 3] = [
            [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 192, 0, 0],
            [0, 3, 128, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 97, 192, 1, 0],
            [0, 0, 128, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0],
        ];

        // The twelve counted checks.

        #[test]
        fn kani_same_is_equality() {
            let mut g = seed("kani_same_is_equality");
            let mut most = ZERO;
            for _ in 0..DRAWS {
                let a = [g.byte(), g.byte(), g.byte(), g.byte()];
                // Equal bytes, one byte changed, or any bytes: equal bytes
                // are what take `same` round most.
                let mut b = a;
                match g.word() % 3 {
                    0 => {}
                    1 => b[g.upto(3)] = g.byte(),
                    _ => b = [g.byte(), g.byte(), g.byte(), g.byte()],
                }
                let n = g.upto(4);
                let m = g.upto(4);
                same_is_equality_c(a, b, n, m, &mut most);
            }
            let predicted = Most {
                own: 4,
                same: 4,
                ..ZERO
            };
            judge("kani_same_is_equality", 6, &most, &predicted);
        }

        /// Every five bytes over the classes, then random draws, half of
        /// them with a name laid from `start`.
        fn name_from(start: usize, predicted: Most) {
            let harness = format!("kani_a_name_agrees_from_{start}");
            let mut most = ZERO;
            every_five(|d| {
                for want in 0..=2 * N {
                    a_name_agrees_from_c(start, d, want, &mut most);
                }
            });
            let mut g = seed(&harness);
            for _ in 0..DRAWS {
                let mut d = [0u8; N];
                fill(&mut g, &mut d);
                if g.word().is_multiple_of(2) {
                    lay(&mut g, &mut d, start);
                }
                let want = g.upto(2 * N);
                a_name_agrees_from_c(start, d, want, &mut most);
            }
            judge(&harness, 8, &most, &predicted);
        }

        #[test]
        fn kani_a_name_agrees_from_0() {
            name_from(
                0,
                Most {
                    walk2: 2,
                    read_name: 2,
                    copy_label: 4,
                    ..ZERO
                },
            );
        }

        #[test]
        fn kani_a_name_agrees_from_1() {
            name_from(
                1,
                Most {
                    walk2: 4,
                    read_name: 4,
                    copy_label: 4,
                    ..ZERO
                },
            );
        }

        #[test]
        fn kani_a_name_agrees_from_2() {
            name_from(
                2,
                Most {
                    walk2: 3,
                    read_name: 3,
                    copy_label: 4,
                    ..ZERO
                },
            );
        }

        #[test]
        fn kani_a_name_agrees_from_3() {
            name_from(
                3,
                Most {
                    walk2: 3,
                    read_name: 3,
                    copy_label: 4,
                    ..ZERO
                },
            );
        }

        #[test]
        fn kani_a_name_agrees_from_4() {
            name_from(4, ZERO);
        }

        #[test]
        fn kani_a_name_agrees_from_5() {
            name_from(5, ZERO);
        }

        #[test]
        fn kani_a_record_agrees() {
            let mut g = seed("kani_a_record_agrees");
            let mut most = ZERO;
            // Every first five bytes over the classes: only they decide a
            // loop, once the owner is a name in them.
            for p in 0..3 {
                every_five(|head| {
                    let mut d = [0u8; N + 10];
                    d[..N].copy_from_slice(&head);
                    fill(&mut g, &mut d[N..]);
                    a_record_agrees_c(d, p, &mut most);
                });
            }
            for _ in 0..DRAWS {
                let (d, p) = record_draw(&mut g, N);
                a_record_agrees_c(d, p, &mut most);
            }
            let predicted = Most {
                walk2: 4,
                read_name: 4,
                copy_label: 3,
                ..ZERO
            };
            judge("kani_a_record_agrees", 8, &most, &predicted);
        }

        #[test]
        fn kani_too_short_is_unread() {
            let mut g = seed("kani_too_short_is_unread");
            let mut most = ZERO;
            for _ in 0..DRAWS / 100 {
                let mut d = [0u8; 11];
                fill(&mut g, &mut d);
                too_short_is_unread_c(d, &mut most);
            }
            judge(
                "kani_too_short_is_unread",
                14,
                &most,
                &Most { own: 12, ..ZERO },
            );
        }

        #[test]
        fn kani_the_opening_decides_in_order() {
            let mut g = seed("kani_the_opening_decides_in_order");
            let mut most = ZERO;
            for d in OPENING_AT_MOST {
                opening_c(d, true, &mut most);
            }
            for _ in 0..DRAWS {
                let d = opening_draw(&mut g);
                opening_c(d, true, &mut most);
            }
            let predicted = Most {
                walk2: 7,
                read_name: 6,
                copy_label: 4,
                ..ZERO
            };
            judge("kani_the_opening_decides_in_order", 8, &most, &predicted);
        }

        #[test]
        fn kani_a_written_answer_gives_its_address() {
            let mut g = seed("kani_a_written_answer_gives_its_address");
            let mut most = ZERO;
            for _ in 0..DRAWS / 10 {
                let (x, class, data) = written_draw(&mut g);
                written_answer_c(x, class, data, &mut most);
            }
            let predicted = Most {
                read_name: 2,
                copy_label: 1,
                answer: 1,
                same: 3,
                ..ZERO
            };
            judge(
                "kani_a_written_answer_gives_its_address",
                8,
                &most,
                &predicted,
            );
        }

        #[test]
        fn kani_no_counted_record_reads_nothing_more() {
            let mut g = seed("kani_no_counted_record_reads_nothing_more");
            let mut most = ZERO;
            for _ in 0..DRAWS / 100 {
                let mut rest = [0u8; 16];
                fill(&mut g, &mut rest);
                no_counted_record_c(rest, &mut most);
            }
            let predicted = Most {
                own: 16,
                read_name: 1,
                copy_label: 1,
                ..ZERO
            };
            judge(
                "kani_no_counted_record_reads_nothing_more",
                18,
                &most,
                &predicted,
            );
        }

        // The three past faults: each check must flag its harness.

        /// `kani_no_counted_record_reads_nothing_more` under its old
        /// unwind(8): its own loop goes round 16 times.
        #[test]
        fn old_no_counted_record_under_unwind_8_is_flagged() {
            let mut g = seed("old_no_counted_record");
            let mut most = ZERO;
            for _ in 0..DRAWS / 100 {
                let mut rest = [0u8; 16];
                fill(&mut g, &mut rest);
                no_counted_record_c(rest, &mut most);
            }
            assert_eq!(over(8, &most), vec![("own", 16)]);
        }

        /// `kani_a_record_agrees` with the owner settled after the call:
        /// `copy_label` runs over a label of up to fourteen bytes.
        #[test]
        fn old_record_with_the_owner_settled_after_the_call_is_flagged() {
            let mut g = seed("old_record");
            let mut most = ZERO;
            for _ in 0..DRAWS {
                let (d, p) = record_draw(&mut g, N + 10);
                old_record_c(d, p, &mut most);
            }
            let bad = over(8, &most);
            println!("old record harness under unwind(8): {bad:?}");
            assert!(
                bad.iter().any(|(l, _)| *l == "copy_label"),
                "not flagged: {bad:?}"
            );
        }

        /// `kani_the_opening_decides_in_order` with the header's free bytes
        /// not kept quiet: a pointer in the question reaches a long label in
        /// the header.
        #[test]
        fn old_opening_with_a_free_header_is_flagged() {
            let mut g = seed("old_opening");
            let mut most = ZERO;
            for _ in 0..DRAWS {
                let d = opening_draw(&mut g);
                opening_c(d, false, &mut most);
            }
            let bad = over(8, &most);
            println!("old opening harness under unwind(8): {bad:?}");
            assert!(
                bad.iter().any(|(l, _)| *l == "copy_label"),
                "not flagged: {bad:?}"
            );
        }

        // What the draws reach.

        /// The directed draws reach what the checks above need, and
        /// `kani_a_piece_agrees`'s statement (dnsa.rs:1691-1704) holds on
        /// drawn bytes, which keeps the copy of `piece2` in use.
        #[test]
        fn the_draws_reach_what_the_checks_need() {
            let mut g = seed("the_draws_reach_what_the_checks_need");
            let mut scratch = ZERO;
            let mut header = 0;
            let mut question = 0;
            let mut class_in = 0;
            let mut owner = 0;
            for _ in 0..DRAWS {
                let d = opening_draw(&mut g);
                if d[2] & 0xf8 == 0x80 && d[3] & 0x0f == 0 && d[4] == 0 && d[5] == 1 {
                    header += 1;
                    if matches!(walk2_c(&d, HEADER, 0, &mut scratch), WalkC::Name { .. }) {
                        question += 1;
                    }
                }
                let (_, class, _) = written_draw(&mut g);
                if class == [0, 1] {
                    class_in += 1;
                }
                let (r, p) = record_draw(&mut g, N);
                if matches!(walk2_c(&r[..N], p, 0, &mut scratch), WalkC::Name { .. }) {
                    owner += 1;
                }
                let mut b = [0u8; 5];
                fill(&mut g, &mut b);
                let n = g.upto(5);
                let at = g.upto(6);
                let bound = g.upto(6);
                assert_eq!(piece(&b[..n], at, bound), piece2_c(&b[..n], at, bound));
            }
            assert!(header >= DRAWS / 4, "a readable header in {header} draws");
            assert!(
                question >= DRAWS / 100,
                "a question name in {question} draws"
            );
            assert!(class_in >= DRAWS / 4, "class IN in {class_in} draws");
            assert!(owner >= DRAWS / 100, "an owner name in {owner} draws");
        }

        // The comparisons themselves, as plain tests: what the harnesses
        // state, over every byte string of a length or over byte classes,
        // with each harness's assumptions where they stand. The real code
        // is called; nothing is counted.

        /// What a comparison saw. `pairs`: inputs run (a string and a start,
        /// or one record or opening input); `checks`: the places `want`
        /// read; `given`: a name, a record or an opening; `none`: no name,
        /// no record, or an opening refused at its question; `other`: an
        /// opening refused by its header; `rejected`: cut by an assumption.
        #[derive(Default)]
        struct Seen {
            pairs: u64,
            checks: u64,
            given: u64,
            none: u64,
            other: u64,
            rejected: u64,
        }

        /// Prints what a comparison saw, and asserts that it saw a name or
        /// a record at all.
        fn report(test: &str, seen: &Seen) {
            print_seen(test, seen);
            assert!(
                seen.given > 0,
                "{test}: nothing was given, so no assertion on a name ran"
            );
        }

        /// Prints what a comparison saw.
        fn print_seen(test: &str, seen: &Seen) {
            println!(
                "{test}: {} inputs, {} checks: {} given, {} none, {} refused by the header, {} cut by an assumption",
                seen.pairs, seen.checks, seen.given, seen.none, seen.other, seen.rejected
            );
        }

        /// Calls `f` on every string of `len` bytes over `alphabet`, the
        /// first byte's index in `first.0..first.1`.
        fn every_string(
            len: usize,
            alphabet: &[u8],
            first: (usize, usize),
            mut f: impl FnMut(&[u8]),
        ) {
            if len == 0 || first.0 >= first.1 {
                return;
            }
            let mut ix = vec![0usize; len];
            ix[0] = first.0;
            let mut d: Vec<u8> = ix.iter().map(|&i| alphabet[i]).collect();
            loop {
                f(&d);
                let mut k = len;
                loop {
                    if k == 0 {
                        return;
                    }
                    k -= 1;
                    let top = if k == 0 { first.1 } else { alphabet.len() };
                    ix[k] += 1;
                    if ix[k] < top {
                        d[k] = alphabet[ix[k]];
                        break;
                    }
                    ix[k] = if k == 0 { first.0 } else { 0 };
                    d[k] = alphabet[ix[k]];
                }
            }
        }

        /// The statements of `a_name_agrees_from` (dnsa.rs:1750-1779) on
        /// one string from one start, at every `want` up to `wants`: the
        /// real `read_name` against the copied `walk2`. `want` decides only
        /// the byte `walk2` gives (dnsa.rs:1629-1631, 1647-1656), not which
        /// arm it returns, so a string with no name (or past the second
        /// reading) is checked at `want` 0 alone.
        fn name_case(d: &[u8], start: usize, wants: usize, seen: &mut Seen) {
            let mut scratch = ZERO;
            seen.pairs += 1;
            let got = read_name(d, start);
            let mut want = 0;
            while want <= wants {
                seen.checks += 1;
                match walk2_c(d, start, want, &mut scratch) {
                    WalkC::Past => {
                        // kani::assume(false)
                        seen.rejected += 1;
                        return;
                    }
                    WalkC::NoName => {
                        assert!(got.is_none(), "{d:?} from {start}: the code gives a name");
                        seen.none += 1;
                        return;
                    }
                    WalkC::Name { byte, len, end } => match &got {
                        None => {
                            panic!(
                                "{d:?} from {start}: the second reading gives a name, the code none"
                            );
                        }
                        Some((name, e)) => {
                            assert!(name.len() == len, "{d:?} from {start}: length");
                            assert!(*e == end, "{d:?} from {start}: end");
                            if want < len {
                                assert!(
                                    byte == Some(name[want]),
                                    "{d:?} from {start}: byte {want}"
                                );
                            }
                            if want == 0 {
                                seen.given += 1;
                            }
                        }
                    },
                }
                want += 1;
            }
        }

        /// Every byte.
        fn all_bytes() -> Vec<u8> {
            (0..=255u8).collect()
        }

        /// The byte classes of [`CLASSES`] and the edges of a label's
        /// length (63, 64), of a pointer (191, 192, 193, 255), of a byte
        /// (127, 128) and of the letters that are lowered (`@` is 64, `A`,
        /// `Z`, `[`, `a`).
        const EDGE_CLASSES: [u8; 18] = [
            0, 1, 2, 3, 4, 5, 63, 64, 65, 90, 91, 97, 127, 128, 191, 192, 193, 255,
        ];

        /// Every name over `alphabet` at `len` bytes, from every start, at
        /// every `want` up to twice the length (the harness's `want <= 2 * N`).
        fn names_over(len: usize, alphabet: &[u8], first: (usize, usize)) -> Seen {
            let mut seen = Seen::default();
            every_string(len, alphabet, first, |d| {
                for start in 0..=len {
                    name_case(d, start, 2 * len, &mut seen);
                }
            });
            seen
        }

        /// The name harness's statements on every string of three bytes
        /// (16,777,216), from every start 0 to 3, every `want` 0 to 6.
        #[test]
        fn every_name_of_three_bytes_agrees() {
            let seen = names_over(3, &all_bytes(), (0, 256));
            report("every_name_of_three_bytes_agrees", &seen);
        }

        /// The name harness's statements on every string of four bytes
        /// whose first byte is in `lo..hi`, from every start 0 to 4, every
        /// `want` 0 to 8. The eight tests below share the 4,294,967,296
        /// strings out by first byte, 32 first bytes (536,870,912 strings)
        /// each, so a job can run them side by side.
        fn names_of_four_bytes(lo: usize, hi: usize) {
            let seen = names_over(4, &all_bytes(), (lo, hi));
            report(
                &format!(
                    "every_name_of_four_bytes_agrees, first bytes {lo} to {}",
                    hi - 1
                ),
                &seen,
            );
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_000_031() {
            names_of_four_bytes(0, 32);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_032_063() {
            names_of_four_bytes(32, 64);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_064_095() {
            names_of_four_bytes(64, 96);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_096_127() {
            names_of_four_bytes(96, 128);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_128_159() {
            names_of_four_bytes(128, 160);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_160_191() {
            names_of_four_bytes(160, 192);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_192_223() {
            names_of_four_bytes(192, 224);
        }

        #[test]
        #[ignore = "536,870,912 strings: run as its own job in a release build"]
        fn every_name_of_four_bytes_agrees_first_224_255() {
            names_of_four_bytes(224, 256);
        }

        /// The name harness's statements on every string of five bytes over
        /// [`EDGE_CLASSES`] (1,889,568), from every start 0 to 5, every
        /// `want` 0 to 10.
        #[test]
        fn every_name_of_five_edge_bytes_agrees() {
            let seen = names_over(5, &EDGE_CLASSES, (0, EDGE_CLASSES.len()));
            report("every_name_of_five_edge_bytes_agrees", &seen);
        }

        /// The same at six bytes (34,012,224 strings, starts 0 to 6, `want`
        /// 0 to 12).
        #[test]
        #[ignore = "34,012,224 strings at seven starts: run as its own job in a release build"]
        fn every_name_of_six_edge_bytes_agrees() {
            let seen = names_over(6, &EDGE_CLASSES, (0, EDGE_CLASSES.len()));
            report("every_name_of_six_edge_bytes_agrees", &seen);
        }

        /// The statements of `kani_a_record_agrees` (dnsa.rs:1841-1871) on
        /// one input, the real `read_record` against the copied `walk2`.
        fn record_case(d: &[u8; N + 10], p: usize, seen: &mut Seen) {
            let mut scratch = ZERO;
            seen.pairs += 1;
            // kani::assume(p <= 2): the caller gives no other.
            let owner = walk2_c(&d[..N], p, 0, &mut scratch);
            if !matches!(owner, WalkC::Name { .. }) {
                // kani::assume(matches!(owner, Walk::Name { .. }))
                seen.rejected += 1;
                return;
            }
            let got = read_record(d, p);
            seen.checks += 1;
            match owner {
                WalkC::Past => panic!("assumed away"),
                WalkC::NoName => panic!("assumed away"),
                WalkC::Name { byte: _, len, end } => {
                    assert!(end <= N);
                    let fits =
                        end + 10 <= d.len() && end + 10 + word2_c(d, end + 8) as usize <= d.len();
                    match got {
                        None => {
                            assert!(!fits, "{d:?} at {p}: fits, no record");
                            seen.none += 1;
                        }
                        Some((owner, typ, class, at, data)) => {
                            assert!(fits, "{d:?} at {p}: a record that does not fit");
                            assert!(owner.len() == len);
                            assert!(typ == word2_c(d, end));
                            assert!(class == word2_c(d, end + 2));
                            assert!(at == end + 10);
                            assert!(data == word2_c(d, end + 8) as usize);
                            seen.given += 1;
                        }
                    }
                }
            }
        }

        /// The record harness's statements with its first five bytes over
        /// [`EDGE_CLASSES`] and `p` 0 to 2. When the owner is a name, the
        /// rest is laid four ways: data lengths 0, exactly the room left,
        /// one past it, and 0xffff (the bytes around them `A`). The input
        /// is still whole before the harness's statements run on it.
        #[test]
        fn every_record_over_edge_bytes_agrees() {
            let mut seen = Seen::default();
            let mut scratch = ZERO;
            every_string(N, &EDGE_CLASSES, (0, EDGE_CLASSES.len()), |head| {
                for p in 0..3 {
                    let mut d = [b'A'; N + 10];
                    d[..N].copy_from_slice(head);
                    let end = match walk2_c(&d[..N], p, 0, &mut scratch) {
                        WalkC::Name {
                            byte: _,
                            len: _,
                            end,
                        } => end,
                        _ => {
                            record_case(&d, p, &mut seen);
                            continue;
                        }
                    };
                    let room = d.len() - (end + 10);
                    for data in [0, room, room + 1, 0xffff] {
                        d[end + 8..end + 10].copy_from_slice(&(data as u16).to_be_bytes());
                        record_case(&d, p, &mut seen);
                    }
                }
            });
            report("every_record_over_edge_bytes_agrees", &seen);
            assert!(seen.none > 0, "no record was refused");
        }

        /// The statements of `kani_the_opening_decides_in_order`
        /// (dnsa.rs:1891-1937) on one input, the real `read_opening`
        /// against the copied `walk2` and `quiet`.
        fn opening_case(d: &[u8; HEADER + N], seen: &mut Seen) {
            let mut scratch = ZERO;
            seen.pairs += 1;
            if !(quiet_c(d[0]) && quiet_c(d[1])) {
                seen.rejected += 1;
                return;
            }
            if !(quiet_c(d[6]) && quiet_c(d[7]) && quiet_c(d[8])) {
                seen.rejected += 1;
                return;
            }
            if !(quiet_c(d[9]) && quiet_c(d[10]) && quiet_c(d[11])) {
                seen.rejected += 1;
                return;
            }
            let name = walk2_c(d, HEADER, 0, &mut scratch);
            if matches!(name, WalkC::Past) {
                seen.rejected += 1;
                return;
            }
            let got = read_opening(d);
            seen.checks += 1;
            if d[2] & 0x80 == 0 {
                assert!(matches!(got, Err(Unread::NotAResponse)));
                seen.other += 1;
            } else if d[2] & 0x78 != 0 {
                assert!(matches!(got, Err(Unread::Operation)));
                seen.other += 1;
            } else if d[3] & 0x0f != 0 {
                assert!(matches!(got, Err(Unread::Failed)));
                seen.other += 1;
            } else if d[4] != 0 || d[5] != 1 {
                assert!(matches!(got, Err(Unread::Questions)));
                seen.other += 1;
            } else {
                let end = match name {
                    WalkC::Name {
                        byte: _,
                        len: _,
                        end,
                    } => Some(end),
                    _ => None,
                };
                let good = match end {
                    Some(e) => e + 4 <= d.len() && d[e + 2] == 0 && d[e + 3] == 1,
                    None => false,
                };
                match got {
                    Ok((_, qtype, at)) => {
                        assert!(good, "{d:?}: read, not good");
                        let e = end.unwrap_or_default();
                        assert!(qtype == word2_c(d, e));
                        assert!(at == e + 4);
                        seen.given += 1;
                    }
                    Err(why) => {
                        assert!(!good && matches!(why, Unread::Question), "{d:?}: {why:?}");
                        seen.none += 1;
                    }
                }
            }
        }

        /// Headers for the opening harness: one for each refusal in its
        /// order, and two that pass.
        const OPENING_HEADERS: [[u8; 4]; 7] = [
            [0x00, 0x00, 0, 1],
            [0x88, 0x00, 0, 1],
            [0x80, 0x01, 0, 1],
            [0x80, 0x00, 0, 2],
            [0x80, 0x00, 1, 1],
            [0x80, 0x00, 0, 1],
            [0x87, 0xf0, 0, 1],
        ];

        /// Fillings of the header's bytes 0, 1, 6, 7, 8, 9, 10 and 11, the
        /// ones the harness keeps quiet: four mixed, then for each of bytes
        /// 6 to 11 in turn that byte 3 (a label of three bytes there) and
        /// the rest 0. Every filling is quiet, so the harness's quiet
        /// assumptions cut none of them; they are still evaluated.
        const OPENING_QUIET: [[u8; 8]; 10] = [
            [0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 1, 0, 1, 0, 1, 0],
            [3, b'A', 2, b'Z', 0xc0, 0, 1, 0],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0, 0, 3, 0, 0, 0, 0, 0],
            [0, 0, 0, 3, 0, 0, 0, 0],
            [0, 0, 0, 0, 3, 0, 0, 0],
            [0, 0, 0, 0, 0, 3, 0, 0],
            [0, 0, 0, 0, 0, 0, 3, 0],
            [0, 0, 0, 0, 0, 0, 0, 3],
        ];

        /// [`EDGE_CLASSES`] and 6 to 11, so that a pointer's low half can
        /// name every header byte.
        const OPENING_CLASSES: [u8; 24] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 63, 64, 65, 90, 91, 97, 127, 128, 191, 192, 193,
            255,
        ];

        /// The opening harness's statements on one question under every
        /// header and filling.
        fn openings_of(question: &[u8], seen: &mut Seen) {
            for header in OPENING_HEADERS {
                for quiet in OPENING_QUIET {
                    let mut d = [0u8; HEADER + N];
                    d[0] = quiet[0];
                    d[1] = quiet[1];
                    d[2..6].copy_from_slice(&header);
                    d[6..12].copy_from_slice(&quiet[2..]);
                    d[HEADER..].copy_from_slice(question);
                    opening_case(&d, seen);
                }
            }
        }

        /// The opening harness's statements with the question's five bytes
        /// over [`EDGE_CLASSES`] (1,889,568), under the seven headers and
        /// ten fillings: 132,269,760 inputs. A pointer here reaches header
        /// bytes 0 to 5 only; the next two tests reach the rest.
        #[test]
        fn every_opening_over_edge_bytes_agrees() {
            let mut seen = Seen::default();
            every_string(N, &EDGE_CLASSES, (0, EDGE_CLASSES.len()), |question| {
                openings_of(question, &mut seen);
            });
            report("every_opening_over_edge_bytes_agrees", &seen);
            assert!(seen.none > 0, "no question was refused");
            assert!(seen.other > 0, "no header was refused");
        }

        /// A pointer in the question to EVERY header byte: a pointer at
        /// each place 12 to 15 whose low half is each of 0 to 11, the
        /// question's other three bytes over [`OPENING_CLASSES`] (13,824),
        /// under the seven headers and ten fillings: 46,448,640 inputs. No
        /// such question can be read whole (a pointer ends the name at 14
        /// or later, and the type and class need four bytes more), so what
        /// is asserted to be reached is a name read through the pointer.
        #[test]
        fn every_opening_with_a_pointer_to_each_header_byte_agrees() {
            let mut seen = Seen::default();
            let mut scratch = ZERO;
            let mut named: u64 = 0;
            every_string(3, &OPENING_CLASSES, (0, OPENING_CLASSES.len()), |rest| {
                for at in 0..N - 1 {
                    for t in 0..HEADER as u8 {
                        let mut question = [0u8; N];
                        let mut k = 0;
                        for (place, byte) in question.iter_mut().enumerate() {
                            if place == at {
                                *byte = 0xc0;
                            } else if place == at + 1 {
                                *byte = t;
                            } else {
                                *byte = rest[k];
                                k += 1;
                            }
                        }
                        openings_of(&question, &mut seen);
                        let mut d = [0u8; HEADER + N];
                        d[HEADER..].copy_from_slice(&question);
                        for quiet in OPENING_QUIET {
                            d[0] = quiet[0];
                            d[1] = quiet[1];
                            d[6..12].copy_from_slice(&quiet[2..]);
                            if matches!(walk2_c(&d, HEADER, 0, &mut scratch), WalkC::Name { .. }) {
                                named += 1;
                            }
                        }
                    }
                }
            });
            print_seen(
                "every_opening_with_a_pointer_to_each_header_byte_agrees",
                &seen,
            );
            println!(
                "every_opening_with_a_pointer_to_each_header_byte_agrees: {named} names read through a pointer"
            );
            assert!(seen.pairs == 46_448_640);
            assert!(named > 0, "no name was read through a pointer");
            assert!(seen.none > 0, "no question was refused");
        }

        /// The opening harness's statements with the question's five bytes
        /// over [`OPENING_CLASSES`] (7,962,624), under the seven headers and
        /// ten fillings: 557,383,680 inputs.
        #[test]
        #[ignore = "557,383,680 inputs: run as its own job in a release build"]
        fn every_opening_over_edge_bytes_and_header_places_agrees() {
            let mut seen = Seen::default();
            every_string(
                N,
                &OPENING_CLASSES,
                (0, OPENING_CLASSES.len()),
                |question| {
                    openings_of(question, &mut seen);
                },
            );
            report(
                "every_opening_over_edge_bytes_and_header_places_agrees",
                &seen,
            );
            assert!(seen.none > 0, "no question was refused");
            assert!(seen.other > 0, "no header was refused");
        }

        /// `kani_a_name_agrees_from_5`'s own assertion (dnsa.rs:1829-1833):
        /// from the end of five bytes, `a_name_agrees_from` gives nothing,
        /// which is its `Walk::Name` arm not being taken. Over every five
        /// bytes of [`EDGE_CLASSES`] (1,889,568) and every `want` 0 to 10;
        /// no byte is read from the end (dnsa.rs:918, 1624), so the class
        /// set stands for every string.
        #[test]
        fn kani_a_name_agrees_from_5_gives_nothing() {
            let mut scratch = ZERO;
            let mut cases: u64 = 0;
            every_string(N, &EDGE_CLASSES, (0, EDGE_CLASSES.len()), |s| {
                let mut d = [0u8; N];
                d.copy_from_slice(s);
                for want in 0..=2 * N {
                    a_name_agrees_from_c(N, d, want, &mut scratch);
                    assert!(!matches!(
                        walk2_c(&d, N, want, &mut scratch),
                        WalkC::Name { .. }
                    ));
                    assert!(read_name(&d, N).is_none());
                    cases += 1;
                }
            });
            println!("kani_a_name_agrees_from_5_gives_nothing: {cases} inputs");
            assert!(cases == 1_889_568 * 11);
        }

        /// `kani_only_capitals_are_lowered`'s statement (dnsa.rs:1707-1712)
        /// for every byte: all 256, exact.
        #[test]
        fn kani_only_capitals_are_lowered_for_every_byte() {
            let mut cases = 0;
            for c in 0..=255u8 {
                let want = if c.is_ascii_uppercase() { c | 0x20 } else { c };
                assert!(lower_byte(c) == want, "{c}");
                cases += 1;
            }
            println!("kani_only_capitals_are_lowered_for_every_byte: {cases} inputs");
            assert!(cases == 256);
        }

        /// `kani_words_are_big_endian`'s statements (dnsa.rs:1715-1722),
        /// `i` 0 to 2 as assumed. `be16`: every value of the two bytes it
        /// reads (65,536 at each `i`). `be32`: the four bytes it reads
        /// cannot all be walked here, so each byte POSITION walks all 256
        /// values with the other three at 0x00, at 0xff, and at 16 random
        /// draws (18 fillings: 55,296 inputs in all).
        #[test]
        fn kani_words_are_big_endian_over_the_bytes_read() {
            let mut g = seed("kani_words_are_big_endian");
            let mut cases16 = 0;
            for i in 0..=2usize {
                for w in 0..=u16::MAX {
                    let mut d = [0u8; 6];
                    fill(&mut g, &mut d);
                    d[i..i + 2].copy_from_slice(&w.to_be_bytes());
                    assert!(be16(&d, i) == u16::from_be_bytes([d[i], d[i + 1]]));
                    cases16 += 1;
                }
            }
            let mut cases32 = 0;
            for i in 0..=2usize {
                for at in 0..4 {
                    for filling in 0..18 {
                        let mut d = [0u8; 6];
                        match filling {
                            0 => {}
                            1 => d = [0xff; 6],
                            _ => fill(&mut g, &mut d),
                        }
                        for v in 0..=255u8 {
                            d[i + at] = v;
                            assert!(
                                be32(&d, i)
                                    == u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
                            );
                            cases32 += 1;
                        }
                    }
                }
            }
            println!(
                "kani_words_are_big_endian_over_the_bytes_read: be16 {cases16} inputs, be32 {cases32} inputs"
            );
            assert!(cases16 == 3 * 65_536 && cases32 == 3 * 4 * 18 * 256);
        }

        /// `kani_a_piece_agrees`'s statement (dnsa.rs:1691-1704): `piece`
        /// reads at most the byte at `p` and the one after it
        /// (dnsa.rs:921, 934). So: every value of those two bytes (65,536;
        /// 256 when `p` is 4, the last byte), every `n` 0 to 5, every `p`
        /// and `bound` 0 to 6 and usize::MAX - 1 and usize::MAX; the other
        /// three bytes drawn at random (one draw when `p` is past the five
        /// bytes, where nothing is read).
        #[test]
        fn kani_a_piece_agrees_over_the_bytes_read() {
            const PLACES: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, usize::MAX - 1, usize::MAX];
            let mut g = seed("kani_a_piece_agrees");
            let mut cases: u64 = 0;
            for n in 0..=5usize {
                for p in PLACES {
                    for bound in PLACES {
                        let values: u32 = match p {
                            0..=3 => 65_536,
                            4 => 256,
                            _ => 1,
                        };
                        for v in 0..values {
                            let mut d = [0u8; 5];
                            fill(&mut g, &mut d);
                            match p {
                                0..=3 => d[p..p + 2].copy_from_slice(&(v as u16).to_be_bytes()),
                                4 => d[4] = v as u8,
                                _ => {}
                            }
                            // kani::assume(n <= 5): the loop gives no other.
                            let got = piece(&d[..n], p, bound);
                            assert!(got == piece2_c(&d[..n], p, bound), "{d:?} {n} {p} {bound}");
                            cases += 1;
                        }
                    }
                }
            }
            println!("kani_a_piece_agrees_over_the_bytes_read: {cases} inputs");
            assert!(cases == 6 * 9 * (4 * 65_536 + 256 + 4));
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // The reader's parts at the bit level, each against a second reading
    // written apart from the code, and the whole reader on payloads whose
    // shape is written out. The whole reader on a free payload holds vectors
    // of vectors on every path, which the checker does not get through: DA1
    // to DA3 for every payload are Verus's.

    /// What stands at one place, read apart from the code, by the top two
    /// bits.
    fn piece2(d: &[u8], p: usize, bound: usize) -> Piece {
        if p >= d.len() {
            return Piece::Bad;
        }
        let b = d[p];
        match b >> 6 {
            0 => {
                if b == 0 {
                    Piece::Root
                } else if p + b as usize >= d.len() {
                    Piece::Bad
                } else {
                    Piece::Label(b as usize)
                }
            }
            3 => {
                if p + 1 >= d.len() {
                    return Piece::Bad;
                }
                let t = u16::from_be_bytes([b & 0x3f, d[p + 1]]) as usize;
                if t < bound {
                    Piece::Pointer(t)
                } else {
                    Piece::Bad
                }
            }
            _ => Piece::Bad,
        }
    }

    /// One place of a name is one of four things, for every byte, place and
    /// bound.
    #[kani::proof]
    fn kani_a_piece_agrees() {
        let d: [u8; 5] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 5);
        let p: usize = kani::any();
        let bound: usize = kani::any();
        let got = piece(&d[..n], p, bound);
        assert!(got == piece2(&d[..n], p, bound));
        kani::cover!(matches!(got, Piece::Root));
        kani::cover!(matches!(got, Piece::Label(_)));
        kani::cover!(matches!(got, Piece::Pointer(_)));
        kani::cover!(matches!(got, Piece::Bad) && p < n);
    }

    /// A capital letter is lowered and no other byte changes.
    #[kani::proof]
    fn kani_only_capitals_are_lowered() {
        let c: u8 = kani::any();
        let want = if c.is_ascii_uppercase() { c | 0x20 } else { c };
        assert!(lower_byte(c) == want);
    }

    /// Two and four bytes are read most significant first.
    #[kani::proof]
    fn kani_words_are_big_endian() {
        let d: [u8; 6] = kani::any();
        let i: usize = kani::any();
        kani::assume(i <= 2);
        assert!(be16(&d, i) == u16::from_be_bytes([d[i], d[i + 1]]));
        assert!(be32(&d, i) == u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]));
    }

    /// Two names are the same exactly when they are the same bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_same_is_equality() {
        let a: [u8; 4] = kani::any();
        let b: [u8; 4] = kani::any();
        let n: usize = kani::any();
        let m: usize = kani::any();
        kani::assume(n <= 4 && m <= 4);
        let mut equal = n == m;
        let mut i = 0;
        while i < 4 {
            if i < n && i < m && a[i] != b[i] {
                equal = false;
            }
            i += 1;
        }
        assert!(same(&a[..n], &b[..m]) == equal);
        kani::cover!(equal && n == 4);
    }

    /// Nothing shorter than a header is read, at each length.
    #[kani::proof]
    #[kani::unwind(14)]
    fn kani_too_short_is_unread() {
        let d: [u8; 11] = kani::any();
        let mut n = 0;
        while n <= 11 {
            assert!(matches!(read_opening(&d[..n]), Err(Unread::Short)));
            n += 1;
        }
    }

    /// A header that passes with `records` records, the question
    /// `\x01x\x00` of type A and class IN, and one record: the owner a
    /// pointer to the question's name, type A, four bytes of data.
    fn written(x: u8, records: u8, class: [u8; 2], data: [u8; 4]) -> [u8; 35] {
        [
            0xbe, 0xef, 0x81, 0x80, 0, 1, 0, records, 0, 0, 0, 0, 1, x, 0, 0, 1, 0, 1, 0xc0, 12, 0,
            1, class[0], class[1], 0, 0, 0, 60, 0, 4, data[0], data[1], data[2], data[3],
        ]
    }

    /// The whole reader on a written answer: the record's address is given,
    /// byte for byte, exactly when its class is IN, and the asked name comes
    /// back lowered.
    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_a_written_answer_gives_its_address() {
        let x: u8 = kani::any();
        let class: [u8; 2] = kani::any();
        let data: [u8; 4] = kani::any();
        let d = written(x, 1, class, data);
        match answer_addresses(&d) {
            Answer::Unread(_) => assert!(false),
            Answer::Read(g) => {
                assert!(g.id == 0xbeef && g.qtype == 1 && !g.truncated);
                assert!(g.asked.len() == 3 && g.asked[0] == 1 && g.asked[2] == 0);
                assert!(g.asked[1] == if x.is_ascii_uppercase() { x | 0x20 } else { x });
                assert!(!g.more && !g.chain_cut);
                if class[0] == 0 && class[1] == 1 {
                    assert!(g.addrs.len() == 1 && g.addrs[0] == u32::from_be_bytes(data));
                } else {
                    assert!(g.addrs.is_empty());
                }
            }
        }
    }

    /// The record count decides how far the reader goes: with a count of
    /// zero the record's bytes are not read, whatever they are.
    #[kani::proof]
    #[kani::unwind(18)]
    fn kani_no_counted_record_reads_nothing_more() {
        let rest: [u8; 16] = kani::any();
        let mut d = written(b'x', 0, [0, 1], [0; 4]);
        let mut i = 0;
        while i < 16 {
            d[19 + i] = rest[i];
            i += 1;
        }
        match answer_addresses(&d) {
            Answer::Unread(_) => assert!(false),
            Answer::Read(g) => assert!(g.addrs.is_empty() && !g.more && !g.chain_cut),
        }
    }

    /// The harnesses for a name, a record and the opening, against the
    /// second reading. The name harnesses as written are beyond the checker:
    /// a name read through the reader's vector, from five free bytes, is a
    /// formula of about 1.8 million steps that does not fit in 32 GiB; the
    /// record and opening harnesses read a name the same way and have not
    /// completed on this text. The same comparison is made exhaustively by
    /// the unit checks in `tests`: every payload of three and four bytes and
    /// the edge classes at five and six.
    #[cfg(feature = "kani-full")]
    mod beyond_reach {
        use super::*;

        /// The longest run of bytes a name is read from here. Five holds a
        /// root, a label of up to three bytes with its root, and a pointer
        /// behind a one-label name.
        const N: usize = 5;

        /// How many pieces the second reading follows.
        const TURNS: usize = 7;

        /// A name read apart from the code, without holding it.
        enum Walk {
            /// No name stands there.
            NoName,
            /// More pieces than this reading follows: the harness leaves those
            /// payloads out.
            Past,
            /// A name: its byte at the place asked for, if it is that long; how
            /// many bytes it has; and the index after it where it stands.
            Name {
                byte: Option<u8>,
                len: usize,
                end: usize,
            },
        }

        /// The name that starts at `start`, and its byte at `want`.
        fn walk2(d: &[u8], start: usize, want: usize) -> Walk {
            let mut p = start;
            let mut bound = start;
            let mut n: usize = 0;
            let mut end: Option<usize> = None;
            let mut byte: Option<u8> = None;
            let mut turns = 0;
            while turns < TURNS {
                turns += 1;
                if p >= d.len() {
                    return Walk::NoName;
                }
                let b = d[p];
                if b == 0 {
                    if n == want {
                        byte = Some(0);
                    }
                    return Walk::Name {
                        byte,
                        len: n + 1,
                        end: match end {
                            Some(e) => e,
                            None => p + 1,
                        },
                    };
                }
                match b >> 6 {
                    0 => {
                        let l = b as usize;
                        if p + l >= d.len() {
                            return Walk::NoName;
                        }
                        if want >= n && want - n <= l {
                            let c = d[p + (want - n)];
                            byte = Some(if want == n {
                                c
                            } else if c.is_ascii_uppercase() {
                                c | 0x20
                            } else {
                                c
                            });
                        }
                        n += 1 + l;
                        p += 1 + l;
                    }
                    3 => {
                        if p + 1 >= d.len() {
                            return Walk::NoName;
                        }
                        let t = ((b as usize & 0x3f) << 8) | d[p + 1] as usize;
                        if t >= bound {
                            return Walk::NoName;
                        }
                        if end.is_none() {
                            end = Some(p + 2);
                        }
                        p = t;
                        bound = t;
                    }
                    _ => return Walk::NoName,
                }
            }
            Walk::Past
        }

        /// A byte that does not stand as a label of more than three bytes.
        fn quiet(b: u8) -> bool {
            b <= 3 || b >= 0x40
        }

        fn word2(d: &[u8], i: usize) -> u16 {
            u16::from_be_bytes([d[i], d[i + 1]])
        }

        /// A name in five free bytes, from `start`: the code gives a name
        /// exactly when the second reading does, of the same length, ending at
        /// the same index, with the same byte at every place. Gives the bytes,
        /// the place asked for, the name's length and the index after it, when
        /// there is a name.
        fn a_name_agrees_from(start: usize) -> Option<([u8; N], usize, usize, usize)> {
            let d: [u8; N] = kani::any();
            let want: usize = kani::any();
            kani::assume(want <= 2 * N);
            let got = read_name(&d, start);
            match walk2(&d, start, want) {
                Walk::Past => {
                    kani::assume(false);
                    None
                }
                Walk::NoName => {
                    assert!(got.is_none());
                    None
                }
                Walk::Name { byte, len, end } => match got {
                    None => {
                        assert!(false);
                        None
                    }
                    Some((name, e)) => {
                        assert!(name.len() == len);
                        assert!(e == end);
                        if want < len {
                            assert!(byte == Some(name[want]));
                        }
                        Some((d, want, len, end))
                    }
                },
            }
        }

        /// From the first byte, where no pointer has a target: plain labels.
        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_0() {
            if let Some((d, want, len, _)) = a_name_agrees_from(0) {
                kani::cover!(len == 1);
                kani::cover!(len == 3);
                kani::cover!(want > 0 && want < len && d[0] == 2 && d[1] == b'A');
            }
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_1() {
            if let Some((_, _, len, end)) = a_name_agrees_from(1) {
                kani::cover!(len == 1);
                kani::cover!(len > N && end == N);
            }
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_2() {
            if let Some((_, _, len, end)) = a_name_agrees_from(2) {
                kani::cover!(len == 1 && end == 3);
                kani::cover!(len == 1 && end == 4);
            }
        }

        /// From the fourth byte, where a pointer reaches a one-label name.
        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_3() {
            if let Some((_, _, len, end)) = a_name_agrees_from(3) {
                kani::cover!(len == 3 && end == N);
                kani::cover!(len == 1 && end == N);
            }
        }

        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_4() {
            if let Some((_, _, len, end)) = a_name_agrees_from(4) {
                kani::cover!(len == 1 && end == N);
            }
        }

        /// From the end: no name.
        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_name_agrees_from_5() {
            assert!(a_name_agrees_from(N).is_none());
        }

        /// A record whose owner is a name in the first five bytes, in fifteen
        /// free bytes: its type, class and data are where the second reading
        /// finds them, and it is no record when its data does not fit. The owner
        /// is settled from the first five bytes before the code is called, so
        /// the code reads no name that runs past them. That no name gives no
        /// record is DA1's.
        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_a_record_agrees() {
            let d: [u8; N + 10] = kani::any();
            let p: usize = kani::any();
            kani::assume(p <= 2);
            let owner = walk2(&d[..N], p, 0);
            kani::assume(matches!(owner, Walk::Name { .. }));
            let got = read_record(&d, p);
            match owner {
                Walk::Past => assert!(false),
                Walk::NoName => assert!(false),
                Walk::Name { byte: _, len, end } => {
                    assert!(end <= N);
                    let fits =
                        end + 10 <= d.len() && end + 10 + word2(&d, end + 8) as usize <= d.len();
                    match got {
                        None => assert!(!fits),
                        Some((owner, typ, class, at, data)) => {
                            assert!(fits);
                            assert!(owner.len() == len);
                            assert!(typ == word2(&d, end));
                            assert!(class == word2(&d, end + 2));
                            assert!(at == end + 10);
                            assert!(data == word2(&d, end + 8) as usize);
                            kani::cover!(data == 4);
                        }
                    }
                    kani::cover!(!fits);
                }
            }
        }

        /// The header decides in its order: a response, a standard query, no
        /// error, one question; then the question, free in five bytes, and its
        /// class. A pointer in the question reaches back into the header, so
        /// the header's bytes that the opening does not read (the id and the
        /// three later counts) are kept from standing as a label of more than
        /// three bytes.
        #[kani::proof]
        #[kani::unwind(8)]
        fn kani_the_opening_decides_in_order() {
            let d: [u8; HEADER + N] = kani::any();
            kani::assume(quiet(d[0]) && quiet(d[1]));
            kani::assume(quiet(d[6]) && quiet(d[7]) && quiet(d[8]));
            kani::assume(quiet(d[9]) && quiet(d[10]) && quiet(d[11]));
            let name = walk2(&d, HEADER, 0);
            kani::assume(!matches!(name, Walk::Past));
            let got = read_opening(&d);
            if d[2] & 0x80 == 0 {
                assert!(matches!(got, Err(Unread::NotAResponse)));
            } else if d[2] & 0x78 != 0 {
                assert!(matches!(got, Err(Unread::Operation)));
            } else if d[3] & 0x0f != 0 {
                assert!(matches!(got, Err(Unread::Failed)));
            } else if d[4] != 0 || d[5] != 1 {
                assert!(matches!(got, Err(Unread::Questions)));
            } else {
                let end = match name {
                    Walk::Name {
                        byte: _,
                        len: _,
                        end,
                    } => Some(end),
                    _ => None,
                };
                let good = match end {
                    Some(e) => e + 4 <= d.len() && d[e + 2] == 0 && d[e + 3] == 1,
                    None => false,
                };
                match got {
                    Ok((_, qtype, at)) => {
                        assert!(good);
                        let e = match end {
                            Some(e) => e,
                            None => 0,
                        };
                        assert!(qtype == word2(&d, e));
                        assert!(at == e + 4);
                    }
                    Err(why) => assert!(!good && matches!(why, Unread::Question)),
                }
                kani::cover!(good);
                kani::cover!(!good);
            }
        }
    }
}
