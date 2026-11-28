//! A DNS answer, from the addresses the reply carried to what the box's
//! tables hold.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! [`crate::pins::Pins::resolve`] admits the addresses it is given. Which
//! addresses an answer may admit is [`crate::rebind::rebind`]'s to say. This
//! module is the one place the two meet: the caller hands over every address
//! the answer carried for the name, in order, and learns what became of
//! each.
//!
//! THEOREM TA1: with no live question `(name, txid, port)` in the box's
//! tables the result is `NoQuestion` and nothing changed.
//!
//! THEOREM TA2: otherwise the tables changed as `Pins::resolve` promises of
//! the addresses that pass the check, in their order, and of no others; the
//! reply table and the refusal notes are as they were.
//!
//! THEOREM TA3: an address has the fate `Refused(x)` exactly when the check
//! says `x` of it and `x` is not `Admitted`.
//!
//! THEOREM TA4: an address that passed has the fate `Held` exactly when the
//! admitted table holds it afterwards, with the name that holds it and its
//! deadline; and `NoRoom` exactly when no name holds it afterwards, which
//! happens only with the answer's name at its quota or the table at its
//! capacity (`theorem_ta4_no_room_is_quota_or_capacity`).
//!
//! THEOREM TA5 (what it is for): an admission the table holds afterwards and
//! did not hold before is the answer's name's, and its address is one of
//! the answer's that passed the check
//! (`theorem_ta5_a_new_admission_passed_the_check`).
//!
//! Not here: that the addresses are those of the answer to that question,
//! that the rules are this box's, that `own` are the switch's addresses, and
//! that `box_zone` is true exactly for a name inside the box zone. Those are
//! the caller's (registry).

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::judge::BoxTables;
#[cfg(verus_keep_ghost)]
use crate::judge::tinv;
use crate::pins::Admits;
#[cfg(verus_keep_ghost)]
use crate::pins::{admitted, admitted_pool, kept_at, pinv, resolve_post};
use crate::policy::Rules;
#[cfg(verus_keep_ghost)]
use crate::policy::rules_of;
#[cfg(verus_keep_ghost)]
use crate::pool::{Entry, count, has, held_key};
#[cfg(verus_keep_ghost)]
use crate::rebind::rebind_spec;
use crate::rebind::{Rebind, rebind};
use crate::row::RowRules;
#[cfg(verus_keep_ghost)]
use crate::slab::{scap, squota};
use crate::time::Instant;

/// What became of one address of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Fate {
    /// The check refused it, for this reason. It reached no table.
    Refused(Rebind),
    /// The admitted table holds it afterwards, under `holder`, until
    /// `until_ms`. `holder` is the answer's name, or the name that already
    /// held the address.
    Held { holder: u32, until_ms: u64 },
    /// No name holds it afterwards: there was no room.
    NoRoom,
}

/// What an answer did.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Answer {
    /// The box holds no live question for it. Nothing changed.
    NoQuestion,
    /// More addresses than a DNS message can carry. Nothing changed.
    TooMany,
    /// The question was consumed. One fate for each address, in order, and
    /// the counts `Pins::resolve` returned for those that passed the check.
    Fates(Vec<Fate>, Admits),
}

#[cfg(verus_keep_ghost)]
verus! {

/// The check admits `a` for this name and these rules.
pub open spec fn passes(a: u32, box_zone: bool, rules: RowRules, own: Seq<u32>) -> bool {
    rebind_spec(a, box_zone, rules.deny@, rules.allow_subnets, own) == Rebind::Admitted
}

/// The addresses of `addrs` that pass the check, in their order.
pub open spec fn passing(addrs: Seq<u32>, box_zone: bool, rules: RowRules, own: Seq<u32>) -> Seq<u32>
    decreases addrs.len(),
{
    if addrs.len() == 0 {
        Seq::<u32>::empty()
    } else if passes(addrs.last(), box_zone, rules, own) {
        passing(addrs.drop_last(), box_zone, rules, own).push(addrs.last())
    } else {
        passing(addrs.drop_last(), box_zone, rules, own)
    }
}

/// TA3, TA4: what a fate says of its address and of the admitted table
/// afterwards.
pub open spec fn fate_ok(after: Seq<Entry>, a: u32, box_zone: bool, rules: RowRules, own: Seq<u32>, f: Fate) -> bool {
    match f {
        Fate::Refused(x) => x != Rebind::Admitted && rebind_spec(a, box_zone, rules.deny@, rules.allow_subnets, own) == x,
        Fate::Held { holder, until_ms } => {
            &&& passes(a, box_zone, rules, own)
            &&& exists|j: int| 0 <= j < after.len() && (#[trigger] after[j]).key == a as u64 && after[j].row == holder
                && after[j].deadline_ms == until_ms
        },
        Fate::NoRoom => passes(a, box_zone, rules, own) && !held_key(after, a as u64),
    }
}

/// What `answer` promises of its result and of the tables before and after.
pub open spec fn answer_post(
    before: BoxTables,
    after: BoxTables,
    rules: RowRules,
    own: Seq<u32>,
    name: u32,
    box_zone: bool,
    txid: u16,
    port: u16,
    addrs: Seq<u32>,
    now_ms: u64,
    r: Answer,
) -> bool {
    &&& after.flows == before.flows
    &&& after.notes == before.notes
    &&& match r {
        Answer::TooMany => addrs.len() > u16::MAX && after.pins == before.pins,
        Answer::NoQuestion => {
            &&& addrs.len() <= u16::MAX
            &&& resolve_post(before.pins, after.pins, name, txid, port, passing(addrs, box_zone, rules, own), now_ms, None)
        },
        Answer::Fates(f, c) => {
            &&& addrs.len() <= u16::MAX
            &&& resolve_post(before.pins, after.pins, name, txid, port, passing(addrs, box_zone, rules, own), now_ms, Some(c))
            &&& f@.len() == addrs.len()
            &&& forall|i: int| 0 <= i < addrs.len() ==> fate_ok(admitted(after.pins), addrs[i], box_zone, rules, own, #[trigger] f@[i])
        },
    }
}

/// A passing address of `addrs` is one of `passing(addrs, ..)`.
pub proof fn lemma_passing_has(addrs: Seq<u32>, box_zone: bool, rules: RowRules, own: Seq<u32>, i: int)
    requires
        0 <= i < addrs.len(),
        passes(addrs[i], box_zone, rules, own),
    ensures
        exists|k: int| 0 <= k < passing(addrs, box_zone, rules, own).len()
            && #[trigger] passing(addrs, box_zone, rules, own)[k] == addrs[i],
    decreases addrs.len(),
{
    let p = passing(addrs, box_zone, rules, own);
    let d = addrs.drop_last();
    let q = passing(d, box_zone, rules, own);
    if i == addrs.len() - 1 {
        assert(p == q.push(addrs.last()));
        assert(p[q.len() as int] == addrs[i]);
    } else {
        lemma_passing_has(d, box_zone, rules, own, i);
        let k = choose|k: int| 0 <= k < q.len() && #[trigger] q[k] == d[i];
        assert(p[k] == q[k]);
        assert(p[k] == addrs[i]);
    }
}

/// Each of `passing(addrs, ..)` is an address of `addrs` that passes.
pub proof fn lemma_passing_from(addrs: Seq<u32>, box_zone: bool, rules: RowRules, own: Seq<u32>, k: int)
    requires
        0 <= k < passing(addrs, box_zone, rules, own).len(),
    ensures
        exists|i: int| 0 <= i < addrs.len() && #[trigger] addrs[i] == passing(addrs, box_zone, rules, own)[k]
            && passes(addrs[i], box_zone, rules, own),
    decreases addrs.len(),
{
    let p = passing(addrs, box_zone, rules, own);
    if addrs.len() > 0 {
        let d = addrs.drop_last();
        let q = passing(d, box_zone, rules, own);
        if passes(addrs.last(), box_zone, rules, own) && k == q.len() {
            assert(p == q.push(addrs.last()));
            assert(addrs[addrs.len() - 1] == p[k]);
        } else {
            assert(p[k] == q[k]);
            lemma_passing_from(d, box_zone, rules, own, k);
            let i = choose|i: int| 0 <= i < d.len() && #[trigger] d[i] == q[k] && passes(d[i], box_zone, rules, own);
            assert(addrs[i] == d[i]);
        }
    }
}

/// TA4: an address with no room was refused at the name's quota or at the
/// table's capacity.
pub proof fn theorem_ta4_no_room_is_quota_or_capacity(
    before: BoxTables,
    after: BoxTables,
    rules: RowRules,
    own: Seq<u32>,
    name: u32,
    box_zone: bool,
    txid: u16,
    port: u16,
    addrs: Seq<u32>,
    now_ms: u64,
    f: Vec<Fate>,
    c: Admits,
    i: int,
)
    requires
        answer_post(before, after, rules, own, name, box_zone, txid, port, addrs, now_ms, Answer::Fates(f, c)),
        0 <= i < addrs.len(),
        f@[i] == Fate::NoRoom,
    ensures
        count(admitted(after.pins), name) >= squota(admitted_pool(before.pins))
            || admitted(after.pins).len() >= scap(admitted_pool(before.pins)),
{
    let p = passing(addrs, box_zone, rules, own);
    let a = admitted(after.pins);
    assert(fate_ok(a, addrs[i], box_zone, rules, own, f@[i]));
    lemma_passing_has(addrs, box_zone, rules, own, i);
    let k = choose|k: int| 0 <= k < p.len() && #[trigger] p[k] == addrs[i];
    assert(p.len() > 0);
    assert(crate::pins::resolved_tables(before.pins, after.pins, name, p, now_ms));
    reveal(crate::pins::resolved_tables);
    let key = p[k] as u64;
    assert(!held_key(a, key));
}

/// TA5: an admission held afterwards was held before, or is the answer's
/// name's for an address of the answer that passed the check.
pub proof fn theorem_ta5_a_new_admission_passed_the_check(
    before: BoxTables,
    after: BoxTables,
    rules: RowRules,
    own: Seq<u32>,
    name: u32,
    box_zone: bool,
    txid: u16,
    port: u16,
    addrs: Seq<u32>,
    now_ms: u64,
    r: Answer,
    e: Entry,
)
    requires
        answer_post(before, after, rules, own, name, box_zone, txid, port, addrs, now_ms, r),
        has(admitted(after.pins), e),
    ensures
        has(admitted(before.pins), e) || kept_at(admitted(before.pins), e.row, e.key, name, now_ms) || (e.row == name
            && exists|i: int| 0 <= i < addrs.len() && (#[trigger] addrs[i]) as u64 == e.key && passes(addrs[i], box_zone, rules, own)),
{
    let p = passing(addrs, box_zone, rules, own);
    let b = admitted(before.pins);
    let a = admitted(after.pins);
    match r {
        Answer::TooMany => {},
        Answer::NoQuestion => {},
        Answer::Fates(f, c) => {
            if p.len() > 0 {
                assert(crate::pins::resolved_tables(before.pins, after.pins, name, p, now_ms));
                reveal(crate::pins::resolved_tables);
                let j = choose|j: int| 0 <= j < a.len() && a[j] == e;
                assert(kept_at(b, a[j].row, a[j].key, name, now_ms) || (a[j].row == name && crate::pins::listed(p, a[j].key)));
                if !kept_at(b, e.row, e.key, name, now_ms) {
                    let k = choose|k: int| 0 <= k < p.len() && p[k] as u64 == e.key;
                    lemma_passing_from(addrs, box_zone, rules, own, k);
                    let i = choose|i: int| 0 <= i < addrs.len() && #[trigger] addrs[i] == p[k] && passes(addrs[i], box_zone, rules, own);
                    assert(addrs[i] as u64 == e.key);
                }
            }
        },
    }
}

} // verus!

/// The addresses of `addrs` the check admits, in their order.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r@ == passing(addrs@, box_zone, *rules, own@),
        r@.len() <= addrs@.len(),
))]
fn passing_of(addrs: &[u32], box_zone: bool, rules: &RowRules, own: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= addrs.len(),
            out@ == passing(addrs@.take(i as int), box_zone, *rules, own@),
            out@.len() <= i,
        decreases addrs.len() - i,
    ))]
    while i < addrs.len() {
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(addrs@.take(i as int + 1).drop_last() =~= addrs@.take(i as int));
            assert(addrs@.take(i as int + 1).last() == addrs@[i as int]);
        }
        match rebind(addrs[i], box_zone, &rules.deny, &rules.allow_subnets, own) {
            Rebind::Admitted => out.push(addrs[i]),
            Rebind::DeniedSubnet => {}
            Rebind::Infrastructure => {}
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(addrs@.take(addrs@.len() as int) =~= addrs@);
    }
    out
}

/// A resolver's reply that answers the question `(name, txid, port)` of the
/// box these tables belong to. `addrs` are all the addresses the answer
/// carries for the name, as the reply carried them; `rules` are the box's;
/// `own` are the switch's own addresses; `box_zone` says the name is inside
/// the box zone. TA1 to TA4.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        answer_post(*old(t), *final(t), rules_of(*rules), own@, name, box_zone, txid, port, addrs@, now.ms, r),
))]
pub fn answer(
    t: &mut BoxTables,
    rules: &Rules,
    own: &[u32],
    name: u32,
    box_zone: bool,
    txid: u16,
    port: u16,
    addrs: &[u32],
    now: Instant,
) -> Answer {
    let rules = rules.get();
    if addrs.len() > u16::MAX as usize {
        return Answer::TooMany;
    }
    let pass = passing_of(addrs, box_zone, rules, own);
    let c = match t.pins.resolve(name, txid, port, pass.as_slice(), now) {
        Some(c) => c,
        None => return Answer::NoQuestion,
    };
    let mut fates: Vec<Fate> = Vec::new();
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            pinv(t.pins),
            i <= addrs.len(),
            fates@.len() == i,
            forall|j: int| 0 <= j < i ==> fate_ok(admitted(t.pins), addrs@[j], box_zone, *rules, own@, #[trigger] fates@[j]),
        decreases addrs.len() - i,
    ))]
    while i < addrs.len() {
        let a = addrs[i];
        let fate = match rebind(a, box_zone, &rules.deny, &rules.allow_subnets, own) {
            Rebind::Admitted => match t.pins.admission(a) {
                Some(e) => Fate::Held {
                    holder: e.row,
                    until_ms: e.deadline_ms,
                },
                None => Fate::NoRoom,
            },
            Rebind::DeniedSubnet => Fate::Refused(Rebind::DeniedSubnet),
            Rebind::Infrastructure => Fate::Refused(Rebind::Infrastructure),
        };
        fates.push(fate);
        i += 1;
    }
    Answer::Fates(fates, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Flows, Windows};
    use crate::notes::Notes;
    use crate::pins::{Asked, Limits, Pins};
    use crate::policy::{Abilities, Declared, Enforced, Net, Section, effective};
    use crate::row::Cidr;
    use crate::time::Span;

    const NET: u32 = 0x6440_0000;
    const BOX: u32 = NET + 7;
    const PUBLIC: u32 = 0xcb00_7107;
    const DENIED: u32 = 0xc633_6401;

    fn tables() -> BoxTables {
        let windows = Windows {
            tcp_idle_ms: 300_000,
            tcp_closing_ms: 120_000,
            tcp_closed_ms: 5_000,
            udp_unreplied_ms: 30_000,
            udp_replied_ms: 300_000,
            evict_after_ms: None,
        };
        let limits = Limits {
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
        BoxTables {
            flows: Flows::new(BOX, 4, windows, Span { ms: 1_000 }).unwrap(),
            notes: Notes::new(BOX, 4, 2, Span { ms: 5_000 }).unwrap(),
            pins: Pins::new(BOX, limits).unwrap(),
        }
    }

    fn rules() -> Rules {
        made(RowRules {
            allow_protocols: None,
            deny: vec![Cidr {
                addr: 0xc633_6400,
                prefix: 24,
            }],
            allow_subnets: Some(Vec::new()),
            laned: false,
        })
    }

    /// Rules through the one road: a declaration, enforced whole.
    fn made(r: RowRules) -> Rules {
        let net = |c: &Cidr| Net::V4(*c);
        let d = Declared {
            allow_subnets: match &r.allow_subnets {
                None => Section::Listed(vec![Net::V4(Cidr { addr: 0, prefix: 0 })]),
                Some(v) => Section::Listed(v.iter().map(net).collect()),
            },
            deny_subnets: Section::Listed(r.deny.iter().map(net).collect()),
            allow_protocols: match &r.allow_protocols {
                None => Section::Absent,
                Some(v) => Section::Listed(v.clone()),
            },
            laned: r.laned,
            host_address: false,
        };
        let host = Abilities {
            per_box_host_address: true,
        };
        match effective(&d, &host).enforced() {
            Enforced::Whole(e) => e.rules(),
            Enforced::Part(_) => panic!("every block is kept"),
        }
    }

    #[test]
    fn an_answer_with_no_question_changes_nothing() {
        let mut t = tables();
        let r = answer(
            &mut t,
            &rules(),
            &[],
            0,
            false,
            7,
            4000,
            &[PUBLIC],
            Instant { ms: 10 },
        );
        assert!(matches!(r, Answer::NoQuestion));
        assert!(!t.pins.admitted_live(PUBLIC, Instant { ms: 10 }));
    }

    #[test]
    fn each_address_has_its_fate_in_order() {
        let mut t = tables();
        assert_eq!(t.pins.ask(0, 7, 4000, Instant { ms: 0 }), Asked::Recorded);
        let addrs = [DENIED, PUBLIC, 0x7f00_0001, PUBLIC + 1, PUBLIC + 2, NET + 9];
        let Answer::Fates(f, c) = answer(
            &mut t,
            &rules(),
            &[],
            0,
            false,
            7,
            4000,
            &addrs,
            Instant { ms: 10 },
        ) else {
            panic!("the question was live");
        };
        assert_eq!(f.len(), 6);
        assert_eq!(f[0], Fate::Refused(Rebind::DeniedSubnet));
        assert_eq!(
            f[1],
            Fate::Held {
                holder: 0,
                until_ms: 300_010
            }
        );
        assert_eq!(f[2], Fate::Refused(Rebind::Infrastructure));
        assert_eq!(
            f[3],
            Fate::Held {
                holder: 0,
                until_ms: 300_010
            }
        );
        // The name's quota is two.
        assert_eq!(f[4], Fate::NoRoom);
        assert_eq!(f[5], Fate::Refused(Rebind::Infrastructure));
        assert_eq!((c.admitted, c.refused), (2, 1));
        assert!(!t.pins.admitted_live(DENIED, Instant { ms: 10 }));
        assert!(!t.pins.admitted_live(NET + 9, Instant { ms: 10 }));
        assert!(t.pins.admitted_live(PUBLIC, Instant { ms: 10 }));
    }

    #[test]
    fn an_address_another_name_holds_is_held_under_that_name() {
        let mut t = tables();
        assert_eq!(t.pins.ask(0, 7, 4000, Instant { ms: 0 }), Asked::Recorded);
        assert!(matches!(
            answer(
                &mut t,
                &rules(),
                &[],
                0,
                false,
                7,
                4000,
                &[PUBLIC],
                Instant { ms: 10 }
            ),
            Answer::Fates(..)
        ));
        assert_eq!(t.pins.ask(1, 8, 4001, Instant { ms: 20 }), Asked::Recorded);
        let Answer::Fates(f, _) = answer(
            &mut t,
            &rules(),
            &[],
            1,
            false,
            8,
            4001,
            &[PUBLIC],
            Instant { ms: 30 },
        ) else {
            panic!("the question was live");
        };
        assert_eq!(
            f[0],
            Fate::Held {
                holder: 0,
                until_ms: 300_030
            }
        );
    }

    #[test]
    fn more_addresses_than_a_message_carries_change_nothing() {
        let mut t = tables();
        assert_eq!(t.pins.ask(0, 7, 4000, Instant { ms: 0 }), Asked::Recorded);
        let many = vec![PUBLIC; 65_536];
        assert!(matches!(
            answer(
                &mut t,
                &rules(),
                &[],
                0,
                false,
                7,
                4000,
                &many,
                Instant { ms: 10 }
            ),
            Answer::TooMany
        ));
        assert!(t.pins.asked_live(0, 7, 4000, Instant { ms: 10 }));
    }
}
