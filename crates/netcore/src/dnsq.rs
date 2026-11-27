//! Whether a DNS query asks only about names in one zone.
//!
//! Layer 2 of the crate, a reader of bytes a guest chose. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A box that may reach nothing may still ask the resolver about a name in
//! the box zone, which the resolver answers by itself whatever the type
//! asked. A question for any other name is handed on to resolvers outside,
//! and a question carries data in its name. So for such a box a datagram to
//! the resolver is forwarded only when every question in it is for a name
//! in the zone, and this module is the reading of the datagram that says so.
//!
//! It reads the header and the questions and nothing after them, and it reads
//! them one way: a name is a run of plain labels ending in the root, with no
//! compression pointer, so two readers of an admitted payload cannot find
//! two different names in it.
//!
//! THEOREM DQ1: `zone_query` returns for every byte string and every apex,
//! reads no byte outside either, and takes at most a number of steps bounded
//! by the payload's length.
//!
//! THEOREM DQ2: `zone_query` is true exactly when the payload satisfies
//! [`spec_zone_query`]: at least a header; a query (QR clear) with opcode 0;
//! at least one question; and every one of the counted questions, read in
//! order from byte 12, is a name of plain labels (each 1 to 63 bytes) ending
//! in the root inside the payload, at most 255 bytes long, followed by a
//! type and class IN, whose last labels are the apex's bytes exactly,
//! starting on a label boundary, with at least one label before them. The
//! type is not read.
//!
//! THEOREM DQ4 (what the rule is for): in an admitted payload every counted
//! question's name ends in the apex, byte for byte, below at least one
//! label, and its class is IN
//! (`theorem_dq4_every_question_is_for_a_zone_name`).
//!
//! THEOREM DQ5: one question that fails refuses the payload, whatever stands
//! before or after it (`theorem_dq5_one_bad_question_refuses`).
//!
//! Not read: the answer, authority and additional sections. An ordinary
//! query carries an EDNS record there.
//!
//! Not here: that the resolver reads a question the way the wire format
//! says, and that it answers every question for a name in the zone by
//! itself, of any type. Both are assumptions with a probe (registry).

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The Internet class.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const CLASS_IN: u16 = 1;
/// The longest name on the wire, its root byte included.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_NAME: usize = 255;
/// The longest label.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_LABEL: u8 = 63;
/// The header's length, and where the first question starts.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const HEADER: usize = 12;

#[cfg(verus_keep_ghost)]
verus! {

/// The 16-bit number at `i`, most significant byte first.
pub open spec fn spec_be16(d: Seq<u8>, i: int) -> int {
    d[i] as int * 256 + d[i + 1] as int
}

/// Where the name of plain labels that starts at `p` ends: the index after
/// its root byte. `None` when a length byte is above 63, or a label or the
/// root lies outside `d`: the byte after every label must be inside.
pub open spec fn name_end(d: Seq<u8>, p: int) -> Option<int>
    decreases d.len() - p,
{
    if p < 0 || p >= d.len() {
        None
    } else if d[p] == 0 {
        Some(p + 1)
    } else if d[p] > MAX_LABEL || p + 1 + d[p] as int >= d.len() {
        None
    } else {
        name_end(d, p + 1 + d[p] as int)
    }
}

/// `q` is where a label, or the root, of the name that starts at `s` starts.
pub open spec fn boundary(d: Seq<u8>, s: int, q: int) -> bool
    decreases d.len() - s,
{
    if s < 0 || s >= d.len() || q < s {
        false
    } else if q == s {
        true
    } else if d[s] == 0 || d[s] > MAX_LABEL || s + 1 + d[s] as int >= d.len() {
        false
    } else {
        boundary(d, s + 1 + d[s] as int, q)
    }
}

/// An apex is a name of plain labels with at least one label, whole.
pub open spec fn apex_ok(apex: Seq<u8>) -> bool {
    apex.len() >= 2 && apex.len() < MAX_NAME && name_end(apex, 0) == Some(apex.len() as int)
}

/// The question that starts at `s` is for a name below the apex, in class
/// IN: the index after it, or `None`.
pub open spec fn spec_question(d: Seq<u8>, s: int, apex: Seq<u8>) -> Option<int> {
    match name_end(d, s) {
        Some(e) => {
            if e - s <= MAX_NAME
                && e + 4 <= d.len()
                && spec_be16(d, e + 2) == CLASS_IN
                && e - s > apex.len()
                && boundary(d, s, e - apex.len())
                && d.subrange(e - apex.len(), e) == apex
            {
                Some(e + 4)
            } else {
                None
            }
        },
        None => None,
    }
}

/// The `n` questions from `p` on are all questions below the apex.
pub open spec fn spec_questions(d: Seq<u8>, p: int, n: nat, apex: Seq<u8>) -> bool
    decreases n,
{
    if n == 0 {
        true
    } else {
        match spec_question(d, p, apex) {
            Some(q) => spec_questions(d, q, (n - 1) as nat, apex),
            None => false,
        }
    }
}

/// Where the `k`-th counted question starts, the first being number 0.
pub open spec fn question_start(d: Seq<u8>, p: int, k: nat, apex: Seq<u8>) -> Option<int>
    decreases k,
{
    if k == 0 {
        Some(p)
    } else {
        match spec_question(d, p, apex) {
            Some(q) => question_start(d, q, (k - 1) as nat, apex),
            None => None,
        }
    }
}

/// The header says: a query, of the standard kind.
pub open spec fn standard_query(d: Seq<u8>) -> bool {
    d.len() >= HEADER && d[2] & 0x80 == 0 && d[2] & 0x78 == 0
}

/// DQ2: the payload is a standard query whose every question is for a name
/// below the apex, in class IN.
pub open spec fn spec_zone_query(d: Seq<u8>, apex: Seq<u8>) -> bool {
    &&& apex_ok(apex)
    &&& standard_query(d)
    &&& spec_be16(d, 4) >= 1
    &&& spec_questions(d, HEADER as int, spec_be16(d, 4) as nat, apex)
}

/// DQ4.
pub proof fn theorem_dq4_every_question_is_for_a_zone_name(d: Seq<u8>, apex: Seq<u8>, k: nat)
    requires
        spec_zone_query(d, apex),
        k < spec_be16(d, 4),
    ensures
        question_start(d, HEADER as int, k, apex) is Some,
        ({
            let s = question_start(d, HEADER as int, k, apex)->0;
            &&& name_end(d, s) is Some
            &&& ({
                let e = name_end(d, s)->0;
                &&& spec_be16(d, e + 2) == CLASS_IN
                &&& e - s > apex.len()
                &&& boundary(d, s, e - apex.len())
                &&& d.subrange(e - apex.len(), e) == apex
            })
        }),
{
    lemma_questions_start(d, HEADER as int, spec_be16(d, 4) as nat, apex, k);
    let s = question_start(d, HEADER as int, k, apex)->0;
    assert(name_end(d, s) is Some);
    lemma_name_end_bounds(d, s);
}

/// DQ5.
pub proof fn theorem_dq5_one_bad_question_refuses(d: Seq<u8>, apex: Seq<u8>, k: nat)
    requires
        k < spec_be16(d, 4),
        match question_start(d, HEADER as int, k, apex) {
            Some(s) => spec_question(d, s, apex) is None,
            None => true,
        },
    ensures
        !spec_zone_query(d, apex),
{
    if spec_zone_query(d, apex) {
        lemma_questions_start(d, HEADER as int, spec_be16(d, 4) as nat, apex, k);
    }
}

/// The `k`-th of `n` questions that are all questions below the apex
/// starts somewhere, and is one.
proof fn lemma_questions_start(d: Seq<u8>, p: int, n: nat, apex: Seq<u8>, k: nat)
    requires
        spec_questions(d, p, n, apex),
        k < n,
    ensures
        question_start(d, p, k, apex) is Some,
        spec_question(d, question_start(d, p, k, apex)->0, apex) is Some,
    decreases k,
{
    if k > 0 {
        let q = spec_question(d, p, apex)->0;
        lemma_questions_start(d, q, (n - 1) as nat, apex, (k - 1) as nat);
    }
}

/// A name's end is past its start and inside the payload.
pub proof fn lemma_name_end_bounds(d: Seq<u8>, p: int)
    requires
        name_end(d, p) is Some,
    ensures
        p < name_end(d, p)->0 <= d.len(),
    decreases d.len() - p,
{
    if d[p] != 0 {
        lemma_name_end_bounds(d, p + 1 + d[p] as int);
    }
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

/// Where the name of plain labels that starts at `s` ends, if it ends inside
/// `d` within `MAX_NAME` bytes.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Some(e) => name_end(d@, s as int) == Some(e as int) && e - s <= MAX_NAME,
            None => match name_end(d@, s as int) {
                Some(e) => e - s > MAX_NAME,
                None => true,
            },
        },
))]
fn end_of_name(d: &[u8], s: usize) -> Option<usize> {
    let mut p = s;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            s <= p,
            p - s < MAX_NAME,
            name_end(d@, p as int) == name_end(d@, s as int),
        decreases d.len() - p,
    ))]
    while p < d.len() {
        let len = d[p];
        if len == 0 {
            return Some(p + 1);
        }
        if len > MAX_LABEL {
            return None;
        }
        // The label and the root after it must fit in what is left of the
        // name's 255 bytes.
        if (len as usize) + 1 >= MAX_NAME - (p - s) {
            #[cfg(verus_keep_ghost)]
            proof! {
                if name_end(d@, s as int) is Some {
                    lemma_name_end_bounds(d@, p as int + 1 + len as int);
                }
            }
            return None;
        }
        if (len as usize) + 1 > d.len() - p {
            return None;
        }
        p += 1 + len as usize;
    }
    None
}

/// Whether `q` is where a label of the name starting at `s` starts.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        name_end(d@, s as int) is Some,
        s <= q,
        q < d.len(),
    ensures
        r == boundary(d@, s as int, q as int),
))]
fn on_boundary(d: &[u8], s: usize, q: usize) -> bool {
    let mut p = s;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            s <= p <= q,
            q < d.len(),
            name_end(d@, p as int) is Some,
            boundary(d@, p as int, q as int) == boundary(d@, s as int, q as int),
        decreases q - p,
    ))]
    while p < q {
        let len = d[p];
        if len == 0 {
            return false;
        }
        if (len as usize) + 1 > q - p {
            #[cfg(verus_keep_ghost)]
            proof! {
                // The next label would start past `q`: two steps of `boundary`.
                reveal_with_fuel(boundary, 2);
            }
            return false;
        }
        p += 1 + len as usize;
    }
    true
}

/// The index after the question that starts at `s`, when it is a question
/// for a name below the apex, in class IN.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        apex_ok(apex@),
    ensures
        match r {
            Some(q) => spec_question(d@, s as int, apex@) == Some(q as int),
            None => spec_question(d@, s as int, apex@) is None,
        },
))]
fn question(d: &[u8], s: usize, apex: &[u8]) -> Option<usize> {
    let e = end_of_name(d, s)?;
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_name_end_bounds(d@, s as int);
    }
    if d.len() - e < 4 {
        return None;
    }
    if be16(d, e + 2) != CLASS_IN {
        return None;
    }
    let a = apex.len();
    if e - s <= a {
        return None;
    }
    let from = e - a;
    if !on_boundary(d, s, from) {
        return None;
    }
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= a,
            a == apex.len(),
            from + a == e,
            e <= d.len(),
            forall|j: int| 0 <= j < i ==> d@[from as int + j] == apex@[j],
            // What the checks before the comparison found, for a return inside it.
            name_end(d@, s as int) == Some(e as int),
            e - s <= MAX_NAME,
            e + 4 <= d.len(),
            spec_be16(d@, e as int + 2) == CLASS_IN,
            e - s > a,
            boundary(d@, s as int, from as int),
        decreases a - i,
    ))]
    while i < a {
        if d[from + i] != apex[i] {
            #[cfg(verus_keep_ghost)]
            proof! {
                // One byte differs, so the subrange is not the apex.
                assert(d@.subrange(from as int, e as int)[i as int] == d@[from as int + i as int]);
            }
            return None;
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(d@.subrange(from as int, e as int) =~= apex@);
    }
    Some(e + 4)
}

/// Whether `apex` is a whole name of plain labels with at least one label.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == apex_ok(apex@),
))]
pub fn apex_is_a_name(apex: &[u8]) -> bool {
    if apex.len() < 2 || apex.len() >= MAX_NAME {
        return false;
    }
    match end_of_name(apex, 0) {
        Some(e) => e == apex.len(),
        None => false,
    }
}

/// DQ1, DQ2: whether the UDP payload `d` is a standard DNS query whose every
/// question is for a name below `apex`, in class IN. `apex` is the
/// zone's name on the wire: its labels, each behind its length, and the
/// root.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == spec_zone_query(d@, apex@),
))]
pub fn zone_query(d: &[u8], apex: &[u8]) -> bool {
    if !apex_is_a_name(apex) {
        return false;
    }
    if d.len() < HEADER {
        return false;
    }
    if d[2] & 0x80 != 0 || d[2] & 0x78 != 0 {
        return false;
    }
    let count = be16(d, 4);
    if count == 0 {
        return false;
    }
    let mut p: usize = HEADER;
    let mut left: u16 = count;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            apex_ok(apex@),
            p <= d.len(),
            spec_questions(d@, p as int, left as nat, apex@)
                == spec_questions(d@, HEADER as int, count as nat, apex@),
            // What the header checks found, for a return inside the loop.
            standard_query(d@),
            spec_be16(d@, 4) == count as int,
        decreases left,
    ))]
    while left > 0 {
        match question(d, p, apex) {
            Some(q) => {
                p = q;
            }
            None => {
                #[cfg(verus_keep_ghost)]
                proof! {
                    // A question fails, so do the questions from `p` on.
                    assert(!spec_questions(d@, p as int, left as nat, apex@));
                }
                return false;
            }
        }
        left -= 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const APEX: &[u8] = b"\x03min\x08internal\x00";

    /// A query with these questions, each a name on the wire, a type and a
    /// class.
    fn query(flags: u8, questions: &[(&[u8], u16, u16)]) -> Vec<u8> {
        let mut d = vec![0x12, 0x34, flags, 0x00];
        d.extend_from_slice(&u16::try_from(questions.len()).unwrap().to_be_bytes());
        d.extend_from_slice(&[0; 6]);
        for (name, kind, class) in questions {
            d.extend_from_slice(name);
            d.extend_from_slice(&kind.to_be_bytes());
            d.extend_from_slice(&class.to_be_bytes());
        }
        d
    }

    const BOX: &[u8] = b"\x03web\x03min\x08internal\x00";

    #[test]
    fn a_question_for_a_name_below_the_apex_passes() {
        assert!(zone_query(&query(0x01, &[(BOX, 1, 1)]), APEX));
        assert!(zone_query(
            &query(0x01, &[(b"\x01a\x03WEB\x03min\x08internal\x00", 1, 1)]),
            APEX
        ));
        assert!(zone_query(&query(0x01, &[(BOX, 1, 1), (BOX, 1, 1)]), APEX));
    }

    #[test]
    fn what_follows_the_questions_is_not_read() {
        let mut d = query(0x01, &[(BOX, 1, 1)]);
        d.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert!(zone_query(&d, APEX));
    }

    #[test]
    fn the_apex_itself_another_case_and_another_zone_are_refused() {
        assert!(!zone_query(&query(0x01, &[(APEX, 1, 1)]), APEX));
        assert!(!zone_query(
            &query(0x01, &[(b"\x03web\x03MIN\x08internal\x00", 1, 1)]),
            APEX
        ));
        assert!(!zone_query(
            &query(0x01, &[(b"\x07example\x03com\x00", 1, 1)]),
            APEX
        ));
        // The apex's bytes inside one longer label are not the apex.
        assert!(!zone_query(
            &query(0x01, &[(b"\x10xxx\x03min\x08internal\x00", 1, 1)]),
            APEX
        ));
    }

    #[test]
    fn every_type_passes_for_a_name_below_the_apex() {
        for kind in [1, 28, 16, 64, 65, 255, 0, u16::MAX] {
            assert!(zone_query(&query(0x01, &[(BOX, kind, 1)]), APEX));
        }
        assert!(zone_query(&query(0x01, &[(BOX, 1, 1), (BOX, 28, 1)]), APEX));
    }

    #[test]
    fn another_class_or_another_zone_is_refused_wherever_it_stands() {
        assert!(!zone_query(&query(0x01, &[(BOX, 1, 3)]), APEX));
        assert!(!zone_query(&query(0x01, &[(BOX, 28, 255)]), APEX));
        assert!(!zone_query(
            &query(0x01, &[(BOX, 1, 1), (BOX, 16, 3)]),
            APEX
        ));
        assert!(!zone_query(
            &query(0x01, &[(b"\x07example\x03com\x00", 28, 1), (BOX, 1, 1)]),
            APEX
        ));
        assert!(!zone_query(
            &query(0x01, &[(BOX, 1, 1), (b"\x07example\x03com\x00", 28, 1)]),
            APEX
        ));
    }

    #[test]
    fn a_reply_another_opcode_no_question_and_a_short_payload_are_refused() {
        assert!(!zone_query(&query(0x81, &[(BOX, 1, 1)]), APEX));
        assert!(!zone_query(&query(0x09, &[(BOX, 1, 1)]), APEX));
        assert!(!zone_query(&query(0x01, &[]), APEX));
        assert!(!zone_query(&[0x12, 0x34, 0x01], APEX));
        let whole = query(0x01, &[(BOX, 1, 1)]);
        assert!(!zone_query(&whole[..whole.len() - 1], APEX));
    }

    #[test]
    fn a_pointer_a_long_label_and_a_question_count_past_the_payload_are_refused() {
        assert!(!zone_query(
            &query(0x01, &[(b"\x03web\xc0\x0c", 1, 1)]),
            APEX
        ));
        assert!(!zone_query(&query(0x01, &[(b"\x40", 1, 1)]), APEX));
        let mut d = query(0x01, &[(BOX, 1, 1)]);
        d[5] = 2;
        assert!(!zone_query(&d, APEX));
    }

    #[test]
    fn an_apex_that_is_not_a_whole_name_refuses_everything() {
        assert!(!zone_query(
            &query(0x01, &[(BOX, 1, 1)]),
            b"\x03min\x08internal"
        ));
        assert!(!zone_query(&query(0x01, &[(BOX, 1, 1)]), b"\x00"));
        assert!(!zone_query(&query(0x01, &[(BOX, 1, 1)]), b""));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The longest payload a harness reads: a header, and room for two of
    /// the shortest questions that pass (a one-byte label, the apex, a type
    /// and a class: nine bytes each).
    const LEN: usize = 12 + 18;

    /// A short apex, `\x01z\x00`: one label of one byte and the root.
    const APEX: [u8; 3] = [1, b'z', 0];

    /// The name that starts at `s`, read apart from the code: `Some(end)`
    /// when it is plain labels ending in the root inside `d`.
    fn name2(d: &[u8], s: usize) -> Option<usize> {
        let mut p = s;
        let mut steps = 0;
        while steps <= LEN {
            if p >= d.len() {
                return None;
            }
            let len = d[p] as usize;
            if len == 0 {
                return Some(p + 1);
            }
            if len > 63 || p + 1 + len >= d.len() {
                return None;
            }
            p += 1 + len;
            steps += 1;
        }
        None
    }

    /// One question at `s`, read apart from the code: the index after it when
    /// it is a question in class IN for a name of at least one label below
    /// `APEX`. The type's two bytes are not read.
    fn question2(d: &[u8], s: usize) -> Option<usize> {
        let e = name2(d, s)?;
        if e + 4 > d.len() {
            return None;
        }
        if d[e + 2] != 0 || d[e + 3] != 1 {
            return None;
        }
        // The name's last three bytes are the apex, and the label before
        // them ends exactly where the apex starts: walk to that place.
        if e - s <= APEX.len() {
            return None;
        }
        let from = e - APEX.len();
        let mut p = s;
        while p < from {
            p += 1 + d[p] as usize;
        }
        if p != from || d[from] != APEX[0] || d[from + 1] != APEX[1] || d[from + 2] != APEX[2] {
            return None;
        }
        Some(e + 4)
    }

    /// A header and one shortest question: twelve bytes and nine.
    const ONE: usize = 12 + 9;

    /// Whether the first twelve bytes are the header of a standard query.
    fn header2(d: &[u8]) -> bool {
        d.len() >= 12 && d[2] & 0x80 == 0 && d[2] & 0x78 == 0
    }

    // DQ1 and DQ2 at the bit level, in parts: one harness for each shape of
    // payload, so that no single run carries every shape at once.

    /// The three slowest harnesses of this module, minutes and about 8 GiB
    /// each: behind `kani-full`, and run in CI one to a job, by name.
    #[cfg(feature = "kani-full")]
    mod heavy {
        use super::*;

        /// The question count the header carries.
        fn count2(d: &[u8]) -> usize {
            (d[4] as usize) * 256 + d[5] as usize
        }

        /// Nothing shorter than a header and one shortest question passes.
        #[kani::proof]
        #[kani::unwind(24)]
        fn kani_too_short_refuses() {
            let d: [u8; ONE] = kani::any();
            let n: usize = kani::any();
            kani::assume(n < ONE);
            assert!(!zone_query(&d[..n], &APEX));
        }

        /// A payload that is not a standard query, or that counts no question,
        /// is refused whatever follows the header.
        #[kani::proof]
        #[kani::unwind(24)]
        fn kani_a_bad_header_refuses() {
            let d: [u8; ONE] = kani::any();
            kani::assume(!header2(&d) || count2(&d) == 0);
            assert!(!zone_query(&d, &APEX));
            kani::cover!(count2(&d) == 0 && header2(&d));
            kani::cover!(!header2(&d) && count2(&d) == 1);
        }

        /// One question in the shortest payload that can hold one: admitted
        /// exactly when the second reading admits it.
        #[kani::proof]
        #[kani::unwind(24)]
        fn kani_one_shortest_question_agrees() {
            let d: [u8; ONE] = kani::any();
            kani::assume(header2(&d) && count2(&d) == 1);
            let got = zone_query(&d, &APEX);
            assert!(got == question2(&d, 12).is_some());
            kani::cover!(got);
            kani::cover!(!got);
        }
    }

    // From here on a harness writes the question count, and a question it
    // takes as good, as bytes: the reader's outer loop then runs a known
    // number of times, and the run carries only the bytes under test.

    /// One question in a payload of 22 bytes: admitted exactly when the second
    /// reading admits it.
    #[kani::proof]
    #[kani::unwind(28)]
    fn kani_one_question_in_22_bytes_agrees() {
        let mut d: [u8; 22] = kani::any();
        d[4] = 0;
        d[5] = 1;
        kani::assume(header2(&d));
        let got = zone_query(&d, &APEX);
        assert!(got == question2(&d, 12).is_some());
        kani::cover!(got);
        kani::cover!(!got);
    }

    /// One question in a payload of 23 bytes: admitted exactly when the second
    /// reading admits it.
    #[kani::proof]
    #[kani::unwind(28)]
    fn kani_one_question_in_23_bytes_agrees() {
        let mut d: [u8; 23] = kani::any();
        d[4] = 0;
        d[5] = 1;
        kani::assume(header2(&d));
        let got = zone_query(&d, &APEX);
        assert!(got == question2(&d, 12).is_some());
        kani::cover!(got);
        kani::cover!(!got);
    }

    /// One question in a payload of 24 bytes: admitted exactly when the second
    /// reading admits it.
    #[kani::proof]
    #[kani::unwind(28)]
    fn kani_one_question_in_24_bytes_agrees() {
        let mut d: [u8; 24] = kani::any();
        d[4] = 0;
        d[5] = 1;
        kani::assume(header2(&d));
        let got = zone_query(&d, &APEX);
        assert!(got == question2(&d, 12).is_some());
        kani::cover!(got);
        kani::cover!(!got);
    }

    /// One question in a payload of 25 bytes: admitted exactly when the second
    /// reading admits it.
    #[kani::proof]
    #[kani::unwind(28)]
    fn kani_one_question_in_25_bytes_agrees() {
        let mut d: [u8; 25] = kani::any();
        d[4] = 0;
        d[5] = 1;
        kani::assume(header2(&d));
        let got = zone_query(&d, &APEX);
        assert!(got == question2(&d, 12).is_some());
        kani::cover!(got);
        kani::cover!(!got);
    }

    /// The shortest good question at `s`, with any byte as its label.
    fn put_good(d: &mut [u8; LEN], s: usize) {
        d[s] = 1;
        d[s + 2] = APEX[0];
        d[s + 3] = APEX[1];
        d[s + 4] = APEX[2];
        d[s + 5] = 0;
        d[s + 6] = 1;
        d[s + 7] = 0;
        d[s + 8] = 1;
    }

    /// Two questions, the first of them the shortest good one: the payload
    /// is admitted exactly when the second question is good too.
    #[kani::proof]
    #[kani::unwind(36)]
    fn kani_the_second_question_decides() {
        let mut d: [u8; LEN] = kani::any();
        d[4] = 0;
        d[5] = 2;
        put_good(&mut d, 12);
        kani::assume(header2(&d));
        assert!(question2(&d, 12) == Some(ONE));
        let got = zone_query(&d, &APEX);
        assert!(got == question2(&d, ONE).is_some());
        kani::cover!(got);
        kani::cover!(!got);
    }

    /// DQ5 at the bit level: two questions counted and the first bad by the
    /// second reading: refused, though the bytes where a shortest first
    /// question would end are a good question.
    #[kani::proof]
    #[kani::unwind(36)]
    fn kani_a_bad_first_question_refuses() {
        let mut d: [u8; LEN] = kani::any();
        d[4] = 0;
        d[5] = 2;
        put_good(&mut d, ONE);
        kani::assume(header2(&d));
        kani::assume(question2(&d, 12).is_none());
        assert!(!zone_query(&d, &APEX));
        // Bad in more than one way: no name at all, and a name of the right
        // length that is not a question below the apex.
        kani::cover!(name2(&d, 12).is_none());
        kani::cover!(name2(&d, 12) == Some(ONE - 4));
    }

    /// Three questions counted where two good ones fill the payload: refused,
    /// the third having no byte to stand in.
    /// Only the header's other bytes and the two label bytes vary.
    #[kani::proof]
    #[kani::unwind(36)]
    fn kani_a_third_question_with_no_room_refuses() {
        let mut d: [u8; LEN] = kani::any();
        d[4] = 0;
        d[5] = 3;
        put_good(&mut d, 12);
        put_good(&mut d, ONE);
        kani::assume(header2(&d));
        assert!(question2(&d, 12) == Some(ONE));
        assert!(question2(&d, ONE) == Some(LEN));
        assert!(!zone_query(&d, &APEX));
    }

    /// A payload of a header and one counted question passes only under an
    /// apex that is a whole name, whatever the apex's three bytes are.
    #[kani::proof]
    #[kani::unwind(24)]
    fn kani_a_broken_apex_refuses() {
        let mut d: [u8; ONE] = kani::any();
        d[4] = 0;
        d[5] = 1;
        let apex: [u8; 3] = kani::any();
        assert!(!zone_query(&d, &apex[..]) || apex_is_a_name(&apex[..]));
        kani::cover!(zone_query(&d, &apex[..]));
    }
}
