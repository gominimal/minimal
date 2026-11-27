//! From what a box declared to what is enforced.
//!
//! Layer 3 of the crate, from policy to rules. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! Every theorem about a decision starts from "given these rules". This
//! module is where the rules come from: [`Declared`] is what was written,
//! with no meaning attached; [`Effective`] is what will be enforced, has
//! private fields and one constructor, [`effective`]; and the rules the
//! decision tables read are made from an `Effective` and from nothing else
//! ([`Effective::rules`]).
//!
//! What a declaration means, in one place:
//!   * a destination is reached when an allowed IPv4 block contains it and no
//!     denied IPv4 block does. No allow section, or an empty one, reaches
//!     nothing; a section of denied blocks alone reaches nothing;
//!   * a protocol passes when no protocol section was written, or the
//!     section lists it. An empty section passes none;
//!   * an IPv6 block is never enforced: there is no IPv6 path. Nor is an
//!     IPv4 block with a prefix above 32, or an entry that could not be
//!     read as a block. None is dropped silently: the outcome names every
//!     one by its place;
//!   * a box at the host's address on a host that cannot decide for each
//!     such box is not refused here, and is not silently accepted: the
//!     outcome says it is unenforced.
//!
//! THEOREM TP1 (the default): with no allow section the policy reaches no
//! destination.
//!
//! THEOREM TP2 (deny grants nothing): a declaration with denied blocks and
//! no allowed block reaches no destination, and a declaration reaches
//! exactly what [`declared_reach`] says (`theorem_tp2_reach_is_declared`).
//!
//! THEOREM TP3 (direction): adding a denied block never widens what is
//! reached, and adding an allowed block never narrows it.
//!
//! THEOREM TP4 (nothing accepted and ignored): every IPv4 block declared
//! with a prefix of at most 32 is in the policy, and every other entry
//! declared is named in the outcome, by section and position; nothing else
//! is named.
//!
//! THEOREM TP5 (never silently unenforced): the outcome is marked
//! unenforced exactly when the box is at the host's address and the host
//! cannot decide for each such box; and the policy leaves an outcome only
//! through [`Outcome::enforced`], which returns it exactly when every
//! entry declared is kept and the box is not so marked, and otherwise returns
//! what is not enforced, from which the policy is taken only by
//! [`Unenforced::accept`].
//!
//! THEOREM TP7 (one form): every block of an enforced policy has a prefix
//! of at most 32 (`theorem_tp7_every_block_is_readable`). Host bits below
//! the prefix are as declared: containment masks them.
//!
//! THEOREM TP6 (one road to the tables): the rules [`Effective::rules`]
//! returns allow a destination and a protocol exactly when the policy does,
//! so V2 to V9 read of those rules are statements about what was declared.
//!
//! A scope has three cases and none is spelled with an empty list:
//! `Only` is never empty (`einv`).
//!
//! Not here: names. A declared name carries no port and is admitted through
//! the DNS tables; this module passes the lane flag through and says nothing
//! of names.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::row::{Cidr, RowRules};
#[cfg(verus_keep_ghost)]
use crate::row::{allow_covers, cidr_contains, covers, has_proto, proto_allowed};

/// A destination block as declared. An IPv4 block with a prefix of at most
/// 32 is enforced. Everything else is kept only to be named, never enforced:
/// an IPv4 block with a longer prefix, an IPv6 block, and an entry the
/// caller could not read as a block at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Net {
    V4(Cidr),
    V6,
    Unreadable,
}

/// One section of a declaration: not written, or written with these
/// entries, which may be none.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Section<T> {
    Absent,
    Listed(Vec<T>),
}

/// What a box declared about where it may send. It can say anything a
/// configuration can say, including what will not be enforced.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Declared {
    pub allow_subnets: Section<Net>,
    pub deny_subnets: Section<Net>,
    pub allow_protocols: Section<u8>,
    /// The box declares a credentialed upstream.
    pub laned: bool,
    /// The box runs at the host's address.
    pub host_address: bool,
}

/// What this host can enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Abilities {
    /// It can decide for each box at the host's address.
    pub per_box_host_address: bool,
}

/// How much is allowed: all of it, none of it, or these and no others.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Scope<T> {
    Every,
    Nothing,
    Only(Vec<T>),
}

/// What will be enforced. Built by [`effective`] and by nothing else.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Effective {
    protocols: Scope<u8>,
    subnets: Scope<Cidr>,
    deny: Vec<Cidr>,
    laned: bool,
}

/// A policy, and what of the declaration it does not enforce. The policy
/// is reached only through [`Outcome::enforced`], which hands it over when
/// all of the declaration is enforced and otherwise says what is not.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Outcome {
    policy: Effective,
    /// The positions of the entries of the allow section that are not
    /// enforced.
    pub skipped_allowed: Vec<usize>,
    /// The positions of the entries of the deny section that are not
    /// enforced.
    pub skipped_denied: Vec<usize>,
    /// The box is at the host's address and this host cannot decide for
    /// each such box: nothing here is enforced for it.
    pub host_address_unenforced: bool,
}

/// A policy of which part of the declaration is not enforced: the entries
/// named, or everything, for a box the host cannot decide for. The policy is
/// reached only by saying so: [`Unenforced::accept`].
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Unenforced {
    policy: Effective,
    /// The positions of the entries of the allow section that are not
    /// enforced.
    pub skipped_allowed: Vec<usize>,
    /// The positions of the entries of the deny section that are not
    /// enforced.
    pub skipped_denied: Vec<usize>,
    /// The box is at the host's address and this host cannot decide for
    /// each such box: nothing of the policy is enforced for it.
    pub host_address: bool,
}

/// The rules a decision reads, made from an enforced policy and from nothing
/// else: [`Effective::rules`] is the only way to make one. A row registered
/// with the gate, a row of the per-box configuration, a cohort member, the
/// judge and the DNS answer entry take this type, so a rule set that reaches
/// a decision came from a declaration, through [`effective`].
///
/// Rules of the plain type can be written anywhere:
///
/// ```
/// use netcore::row::RowRules;
/// let plain = RowRules {
///     allow_protocols: None,
///     deny: Vec::new(),
///     allow_subnets: None,
///     laned: false,
/// };
/// assert!(plain.deny.is_empty());
/// ```
///
/// and this type cannot be made from them outside this module:
///
/// ```compile_fail,E0451
/// use netcore::policy::Rules;
/// use netcore::row::RowRules;
/// let plain = RowRules {
///     allow_protocols: None,
///     deny: Vec::new(),
///     allow_subnets: None,
///     laned: false,
/// };
/// let _made = Rules { inner: plain };
/// ```
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Rules {
    inner: RowRules,
}

/// What [`Outcome::enforced`] returns: the policy, or what is not enforced.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Enforced {
    Whole(Effective),
    Part(Unenforced),
}

#[cfg(verus_keep_ghost)]
verus! {

pub closed spec fn rules_of(r: Rules) -> RowRules { r.inner }
pub closed spec fn policy_of(o: Outcome) -> Effective { o.policy }
pub closed spec fn skipped_allowed_of(o: Outcome) -> Seq<usize> { o.skipped_allowed@ }
pub closed spec fn skipped_denied_of(o: Outcome) -> Seq<usize> { o.skipped_denied@ }
pub closed spec fn unenforced_of(o: Outcome) -> bool { o.host_address_unenforced }
pub closed spec fn unenforced_policy(u: Unenforced) -> Effective { u.policy }
pub closed spec fn named_skipped_allowed(u: Unenforced) -> Seq<usize> { u.skipped_allowed@ }
pub closed spec fn named_skipped_denied(u: Unenforced) -> Seq<usize> { u.skipped_denied@ }
pub closed spec fn named_host_address(u: Unenforced) -> bool { u.host_address }

/// All of the declaration is enforced: every entry of both sections is a
/// block that is kept, and the box is not one the host cannot decide for.
pub open spec fn whole(o: Outcome) -> bool {
    skipped_allowed_of(o).len() == 0 && skipped_denied_of(o).len() == 0 && !unenforced_of(o)
}

/// An entry that is enforced: an IPv4 block with a prefix of at most 32.
pub open spec fn kept(n: Net) -> bool {
    match n {
        Net::V4(c) => c.prefix <= 32,
        Net::V6 => false,
        Net::Unreadable => false,
    }
}

/// The blocks of a list that are kept, in order.
pub open spec fn v4s(s: Seq<Net>) -> Seq<Cidr>
    decreases s.len(),
{
    if s.len() == 0 {
        Seq::empty()
    } else {
        match s.last() {
            Net::V4(c) => if kept(s.last()) {
                v4s(s.drop_last()).push(c)
            } else {
                v4s(s.drop_last())
            },
            Net::V6 => v4s(s.drop_last()),
            Net::Unreadable => v4s(s.drop_last()),
        }
    }
}

/// The entries of a section; none when it was not written.
pub open spec fn listed<T>(s: Section<T>) -> Seq<T> {
    match s {
        Section::Absent => Seq::empty(),
        Section::Listed(v) => v@,
    }
}

/// TP2's right-hand side: what a declaration reaches, said of the
/// declaration alone.
pub open spec fn declared_reach(d: Declared, a: u32) -> bool {
    covers(v4s(listed(d.allow_subnets)), a) && !covers(v4s(listed(d.deny_subnets)), a)
}

/// The protocols a declaration passes.
pub open spec fn declared_proto(d: Declared, p: u8) -> bool {
    match d.allow_protocols {
        Section::Absent => true,
        Section::Listed(v) => has_proto(v@, p),
    }
}

pub closed spec fn protocols_of(e: Effective) -> Scope<u8> { e.protocols }
pub closed spec fn subnets_of(e: Effective) -> Scope<Cidr> { e.subnets }
pub closed spec fn deny_of(e: Effective) -> Seq<Cidr> { e.deny@ }
pub closed spec fn laned_of(e: Effective) -> bool { e.laned }

/// A scope allows a destination.
pub open spec fn scope_covers(s: Scope<Cidr>, a: u32) -> bool {
    match s {
        Scope::Every => true,
        Scope::Nothing => false,
        Scope::Only(v) => covers(v@, a),
    }
}

/// A scope passes a protocol.
pub open spec fn scope_has(s: Scope<u8>, p: u8) -> bool {
    match s {
        Scope::Every => true,
        Scope::Nothing => false,
        Scope::Only(v) => has_proto(v@, p),
    }
}

/// What a policy reaches.
pub open spec fn reach(e: Effective, a: u32) -> bool {
    scope_covers(subnets_of(e), a) && !covers(deny_of(e), a)
}

/// What a policy passes.
pub open spec fn passes(e: Effective, p: u8) -> bool {
    scope_has(protocols_of(e), p)
}

/// No scope is spelled with an empty list.
pub open spec fn einv(e: Effective) -> bool {
    &&& subnets_of(e) matches Scope::Only(v) ==> v@.len() > 0
    &&& protocols_of(e) matches Scope::Only(v) ==> v@.len() > 0
}

/// `at` holds exactly the positions of the entries of `s` that are not kept.
pub open spec fn names_skipped(at: Seq<usize>, s: Seq<Net>) -> bool {
    &&& forall|i: int| 0 <= i < s.len() && !kept(#[trigger] s[i]) ==> at.contains(i as usize)
    &&& forall|j: int| 0 <= j < at.len() ==> (#[trigger] at[j]) < s.len() && !kept(s[at[j] as int])
}

/// The scope of a list of allowed blocks, with no case left to choice:
/// `Every` exactly when a block is the whole address space, `Nothing`
/// exactly when there is no block, and otherwise the blocks themselves.
pub open spec fn scope_is(s: Scope<Cidr>, blocks: Seq<Cidr>) -> bool {
    let whole = exists|i: int| 0 <= i < blocks.len() && (#[trigger] blocks[i]).prefix == 0;
    match s {
        Scope::Every => whole,
        Scope::Nothing => blocks.len() == 0,
        Scope::Only(v) => !whole && blocks.len() > 0 && v@ == blocks,
    }
}

/// What `effective` promises.
pub open spec fn effective_post(d: Declared, host: Abilities, o: Outcome) -> bool {
    &&& einv(policy_of(o))
    &&& forall|a: u32| reach(policy_of(o), a) == #[trigger] declared_reach(d, a)
    &&& forall|p: u8| passes(policy_of(o), p) == #[trigger] declared_proto(d, p)
    &&& laned_of(policy_of(o)) == d.laned
    // TP4.
    &&& deny_of(policy_of(o)) == v4s(listed(d.deny_subnets))
    &&& scope_is(subnets_of(policy_of(o)), v4s(listed(d.allow_subnets)))
    &&& names_skipped(skipped_allowed_of(o), listed(d.allow_subnets))
    &&& names_skipped(skipped_denied_of(o), listed(d.deny_subnets))
    // TP5.
    &&& unenforced_of(o) == (d.host_address && !host.per_box_host_address)
}

/// TP1.
pub proof fn theorem_tp1_no_allow_section_reaches_nothing(d: Declared, a: u32)
    requires
        d.allow_subnets is Absent,
    ensures
        !declared_reach(d, a),
{
}

/// TP2: denied blocks alone, or an empty allow section, reach nothing.
pub proof fn theorem_tp2_deny_grants_nothing(d: Declared, a: u32)
    requires
        v4s(listed(d.allow_subnets)).len() == 0,
    ensures
        !declared_reach(d, a),
{
}

/// TP2: a policy reaches exactly what its declaration says.
pub proof fn theorem_tp2_reach_is_declared(d: Declared, host: Abilities, o: Outcome, a: u32, p: u8)
    requires
        effective_post(d, host, o),
    ensures
        reach(policy_of(o), a) == declared_reach(d, a),
        passes(policy_of(o), p) == declared_proto(d, p),
{
}

/// TP3: one more denied block never widens.
pub proof fn theorem_tp3_a_denied_block_never_widens(d: Declared, more: Declared, c: Net, a: u32)
    requires
        more.allow_subnets == d.allow_subnets,
        listed(more.deny_subnets) == listed(d.deny_subnets).push(c),
    ensures
        declared_reach(more, a) ==> declared_reach(d, a),
{
    if covers(v4s(listed(d.deny_subnets)), a) {
        lemma_v4s_push_covers(listed(d.deny_subnets), c, a);
    }
}

/// TP3: one more allowed block never narrows.
pub proof fn theorem_tp3_an_allowed_block_never_narrows(d: Declared, more: Declared, c: Net, a: u32)
    requires
        more.deny_subnets == d.deny_subnets,
        listed(more.allow_subnets) == listed(d.allow_subnets).push(c),
    ensures
        declared_reach(d, a) ==> declared_reach(more, a),
{
    if covers(v4s(listed(d.allow_subnets)), a) {
        lemma_v4s_push_covers(listed(d.allow_subnets), c, a);
    }
}

/// TP4: an IPv4 block declared as allowed is one the policy allows by, or
/// the policy allows everything; one declared as denied is one it denies by.
pub proof fn theorem_tp4_every_v4_block_is_enforced(d: Declared, host: Abilities, o: Outcome, i: int)
    requires
        effective_post(d, host, o),
    ensures
        0 <= i < v4s(listed(d.deny_subnets)).len() ==> deny_of(policy_of(o))[i] == v4s(listed(d.deny_subnets))[i],
        0 <= i < v4s(listed(d.allow_subnets)).len() ==> forall|a: u32|
            #[trigger] cidr_contains(v4s(listed(d.allow_subnets))[i], a) ==> scope_covers(subnets_of(policy_of(o)), a),
{
}

/// TP7: every block of an enforced policy has a prefix of at most 32.
pub proof fn theorem_tp7_every_block_is_readable(d: Declared, host: Abilities, o: Outcome, j: int)
    requires
        effective_post(d, host, o),
    ensures
        0 <= j < deny_of(policy_of(o)).len() ==> deny_of(policy_of(o))[j].prefix <= 32,
        subnets_of(policy_of(o)) matches Scope::Only(v) ==> (0 <= j < v@.len() ==> v@[j].prefix <= 32),
{
    if 0 <= j < deny_of(policy_of(o)).len() {
        lemma_v4s_readable(listed(d.deny_subnets), j);
    }
    if let Scope::Only(v) = subnets_of(policy_of(o)) {
        if 0 <= j < v@.len() {
            lemma_v4s_readable(listed(d.allow_subnets), j);
        }
    }
}

/// Every kept block of a list has a prefix of at most 32.
proof fn lemma_v4s_readable(s: Seq<Net>, j: int)
    requires
        0 <= j < v4s(s).len(),
    ensures
        v4s(s)[j].prefix <= 32,
    decreases s.len(),
{
    if s.len() > 0 {
        match s.last() {
            Net::V4(c) => {
                if c.prefix <= 32 {
                    if j < v4s(s.drop_last()).len() {
                        lemma_v4s_readable(s.drop_last(), j);
                    }
                } else {
                    lemma_v4s_readable(s.drop_last(), j);
                }
            },
            Net::V6 => lemma_v4s_readable(s.drop_last(), j),
            Net::Unreadable => lemma_v4s_readable(s.drop_last(), j),
        }
    }
}

/// One more entry at the end of a list: its kept blocks gain it when it is
/// kept, and are as they were when it is not.
proof fn lemma_v4s_push(s: Seq<Net>, n: Net)
    ensures
        v4s(s.push(n)) == (match n {
            Net::V4(c) => if kept(n) { v4s(s).push(c) } else { v4s(s) },
            Net::V6 => v4s(s),
            Net::Unreadable => v4s(s),
        }),
{
    assert(s.push(n).drop_last() =~= s);
}

/// A block that covers an address in a list still covers it with one more
/// block at the end.
proof fn lemma_covers_push(s: Seq<Cidr>, c: Cidr, a: u32)
    requires
        covers(s, a),
    ensures
        covers(s.push(c), a),
{
    let i = choose|i: int| 0 <= i < s.len() && cidr_contains(s[i], a);
    assert(s.push(c)[i] == s[i]);
}

/// The IPv4 blocks of a list grow by at most one block at the end, so what
/// they cover only grows.
proof fn lemma_v4s_push_covers(s: Seq<Net>, n: Net, a: u32)
    requires
        covers(v4s(s), a),
    ensures
        covers(v4s(s.push(n)), a),
{
    lemma_v4s_push(s, n);
    match n {
        Net::V4(c) => {
            if c.prefix <= 32 {
                lemma_covers_push(v4s(s), c, a);
            }
        },
        Net::V6 => {},
        Net::Unreadable => {},
    }
}

/// A block of prefix 0 contains every address.
proof fn lemma_whole_block(c: Cidr, a: u32)
    requires
        c.prefix == 0,
    ensures
        cidr_contains(c, a),
{
    assert(a & 0u32 == c.addr & 0u32) by (bit_vector);
}

/// `names_skipped` over one more entry of the list, at position `s.len()`.
proof fn lemma_names_skipped_push(at: Seq<usize>, s: Seq<Net>, n: Net)
    requires
        names_skipped(at, s),
        s.len() < usize::MAX,
    ensures
        !kept(n) ==> names_skipped(at.push(s.len() as usize), s.push(n)),
        kept(n) ==> names_skipped(at, s.push(n)),
{
    let t = s.push(n);
    if !kept(n) {
        let b = at.push(s.len() as usize);
        assert forall|i: int| 0 <= i < t.len() && !kept(#[trigger] t[i])
            implies b.contains(i as usize) by {
            if i < s.len() {
                assert(s[i] == t[i]);
                let j = choose|j: int| 0 <= j < at.len() && at[j] == i as usize;
                assert(b[j] == at[j]);
            } else {
                assert(b[at.len() as int] == s.len() as usize);
            }
        }
        assert forall|j: int| 0 <= j < b.len()
            implies (#[trigger] b[j]) < t.len() && !kept(t[b[j] as int]) by {
            if j < at.len() {
                assert(b[j] == at[j]);
                assert(t[at[j] as int] == s[at[j] as int]);
            }
        }
    } else {
        assert forall|i: int| 0 <= i < t.len() && !kept(#[trigger] t[i])
            implies at.contains(i as usize) by {
            assert(i < s.len());
            assert(s[i] == t[i]);
        }
        assert forall|j: int| 0 <= j < at.len()
            implies (#[trigger] at[j]) < t.len() && !kept(t[at[j] as int]) by {
            assert(t[at[j] as int] == s[at[j] as int]);
        }
    }
}

/// TP6's right-hand side for one policy and its rules.
pub open spec fn rules_are(e: Effective, r: RowRules) -> bool {
    &&& forall|a: u32| (#[trigger] allow_covers(r.allow_subnets, a) && !covers(r.deny@, a)) == reach(e, a)
    &&& forall|p: u8| #[trigger] proto_allowed(r.allow_protocols, p) == passes(e, p)
    &&& r.laned == laned_of(e)
    &&& r.deny@ == deny_of(e)
}

} // verus!

/// The kept blocks of `list` in order, the positions of its entries that
/// are not kept, and whether some kept block is the whole address space.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r.0@ == v4s(list@),
        names_skipped(r.1@, list@),
        r.2 == (exists|i: int| 0 <= i < r.0@.len() && (#[trigger] r.0@[i]).prefix == 0),
))]
fn split(list: &[Net]) -> (Vec<Cidr>, Vec<usize>, bool) {
    let mut v4: Vec<Cidr> = Vec::new();
    let mut skipped: Vec<usize> = Vec::new();
    let mut whole = false;
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= list.len(),
            v4@ == v4s(list@.take(i as int)),
            names_skipped(skipped@, list@.take(i as int)),
            whole == (exists|j: int| 0 <= j < v4@.len() && (#[trigger] v4@[j]).prefix == 0),
        decreases list.len() - i,
    ))]
    while i < list.len() {
        #[cfg(verus_keep_ghost)]
        proof! {
            // The list read so far gains one entry.
            assert(list@.take(i as int + 1) =~= list@.take(i as int).push(list@[i as int]));
            lemma_v4s_push(list@.take(i as int), list@[i as int]);
            lemma_names_skipped_push(skipped@, list@.take(i as int), list@[i as int]);
        }
        match list[i] {
            Net::V4(c) => {
                if c.prefix <= 32 {
                    if c.prefix == 0 {
                        whole = true;
                    }
                    #[cfg(verus_keep_ghost)]
                    proof_decl! {
                        let ghost before: Seq<Cidr> = v4@;
                    }
                    v4.push(c);
                    #[cfg(verus_keep_ghost)]
                    proof! {
                        // The blocks so far are kept in place, and `c` is the last.
                        assert(v4@[before.len() as int] == c);
                        assert forall|j: int| 0 <= j < before.len() implies v4@[j] == before[j] by {
                        }
                    }
                } else {
                    skipped.push(i);
                }
            }
            Net::V6 => {
                skipped.push(i);
            }
            Net::Unreadable => {
                skipped.push(i);
            }
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(list@.take(list.len() as int) =~= list@);
        assert(whole == (exists|j: int| 0 <= j < v4@.len() && (#[trigger] v4@[j]).prefix == 0));
    }
    (v4, skipped, whole)
}

/// What is enforced for a declaration on this host, and what is not.
/// TP1 to TP5.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        effective_post(*d, *host, r),
))]
pub fn effective(d: &Declared, host: &Abilities) -> Outcome {
    let (allowed, skipped_allowed, whole) = match &d.allow_subnets {
        Section::Absent => (Vec::new(), Vec::new(), false),
        Section::Listed(list) => split(list),
    };
    let (deny, skipped_denied, _) = match &d.deny_subnets {
        Section::Absent => (Vec::new(), Vec::new(), false),
        Section::Listed(list) => split(list),
    };
    let subnets = if whole {
        Scope::Every
    } else if allowed.is_empty() {
        Scope::Nothing
    } else {
        Scope::Only(allowed)
    };
    let protocols = match &d.allow_protocols {
        Section::Absent => Scope::Every,
        Section::Listed(list) => {
            if list.is_empty() {
                Scope::Nothing
            } else {
                Scope::Only(list.clone())
            }
        }
    };
    #[cfg(verus_keep_ghost)]
    proof! {
        // A block of prefix 0 contains every address; no block, no address.
        assert forall|a: u32| scope_covers(subnets, a) == #[trigger] covers(allowed@, a) by {
            if whole {
                let i = choose|i: int|
                    0 <= i < allowed@.len() && (#[trigger] allowed@[i]).prefix == 0;
                lemma_whole_block(allowed@[i], a);
            }
        }
    }
    Outcome {
        policy: Effective {
            protocols,
            subnets,
            deny,
            laned: d.laned,
        },
        skipped_allowed,
        skipped_denied,
        host_address_unenforced: d.host_address && !host.per_box_host_address,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Outcome {
    /// The policy, when all of the declaration is enforced; otherwise what
    /// is not, with the policy inside it. TP5.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Enforced::Whole(e) => whole(self) && e == policy_of(self),
                Enforced::Part(u) => !whole(self) && unenforced_policy(u) == policy_of(self)
                    && named_skipped_allowed(u) == skipped_allowed_of(self)
                    && named_skipped_denied(u) == skipped_denied_of(self)
                    && named_host_address(u) == unenforced_of(self),
            },
    ))]
    pub fn enforced(self) -> Enforced {
        if self.skipped_allowed.is_empty()
            && self.skipped_denied.is_empty()
            && !self.host_address_unenforced
        {
            Enforced::Whole(self.policy)
        } else {
            Enforced::Part(Unenforced {
                policy: self.policy,
                skipped_allowed: self.skipped_allowed,
                skipped_denied: self.skipped_denied,
                host_address: self.host_address_unenforced,
            })
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Unenforced {
    /// The policy, taken knowing that part of the declaration is not
    /// enforced. The caller says so to whoever declared it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures r == unenforced_policy(self),
    ))]
    pub fn accept(self) -> Effective {
        self.policy
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Effective {
    /// The rules the decision tables read. TP6.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires
            einv(*self),
        ensures
            rules_are(*self, rules_of(r)),
    ))]
    pub fn rules(&self) -> Rules {
        let inner = RowRules {
            allow_protocols: match &self.protocols {
                Scope::Every => None,
                Scope::Nothing => Some(Vec::new()),
                Scope::Only(list) => Some(list.clone()),
            },
            deny: self.deny.clone(),
            allow_subnets: match &self.subnets {
                Scope::Every => None,
                Scope::Nothing => Some(Vec::new()),
                Scope::Only(list) => Some(list.clone()),
            },
            laned: self.laned,
        };
        Rules { inner }
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Rules {
    /// The rules, to read.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures *r == rules_of(*self),
    ))]
    pub fn get(&self) -> &RowRules {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Plan;
    use crate::row::{Dest, RowArm, decide_row};

    const HOST: Abilities = Abilities {
        per_box_host_address: true,
    };

    fn block(a: u8, b: u8, prefix: u8) -> Net {
        Net::V4(Cidr {
            addr: u32::from_be_bytes([a, b, 0, 0]),
            prefix,
        })
    }

    fn declared(allow: Section<Net>, deny: Section<Net>) -> Declared {
        Declared {
            allow_subnets: allow,
            deny_subnets: deny,
            allow_protocols: Section::Absent,
            laned: false,
            host_address: false,
        }
    }

    #[test]
    fn the_policy_leaves_an_outcome_only_whole_or_by_accepting_what_is_not_enforced() {
        let whole = effective(
            &declared(Section::Listed(vec![block(93, 184, 16)]), Section::Absent),
            &HOST,
        );
        assert!(matches!(whole.enforced(), Enforced::Whole(_)));
        let v6 = effective(
            &declared(
                Section::Listed(vec![Net::V6, block(93, 184, 16)]),
                Section::Absent,
            ),
            &HOST,
        );
        let Enforced::Part(not) = v6.enforced() else {
            panic!("an IPv6 block was declared");
        };
        assert_eq!(not.skipped_allowed, vec![0]);
        assert!(!not.host_address);
        let _policy: Effective = not.accept();
        // A prefix above 32 and an entry that could not be read are named
        // by their places, in either section, and the rest is enforced.
        let long = Net::V4(Cidr {
            addr: 0x0a00_0000,
            prefix: 33,
        });
        let odd = effective(
            &declared(
                Section::Listed(vec![block(93, 184, 16), long, Net::Unreadable]),
                Section::Listed(vec![Net::Unreadable, block(10, 0, 8), long]),
            ),
            &HOST,
        );
        let Enforced::Part(not) = odd.enforced() else {
            panic!("two entries of each section are not kept");
        };
        assert_eq!(not.skipped_allowed, vec![1, 2]);
        assert_eq!(not.skipped_denied, vec![0, 2]);
        let mut d = declared(Section::Listed(vec![block(93, 184, 16)]), Section::Absent);
        d.host_address = true;
        let weak = Abilities {
            per_box_host_address: false,
        };
        assert!(matches!(effective(&d, &weak).enforced(), Enforced::Part(u) if u.host_address));
    }

    fn arm(o: &Outcome, dst: [u8; 4]) -> RowArm {
        let plan = Plan::new(0x6440_0000, 16).unwrap();
        decide_row(
            &plan,
            o.policy.rules().get(),
            false,
            Dest::V4 {
                dst: u32::from_be_bytes(dst),
                proto: 6,
                port: 443,
            },
        )
    }

    #[test]
    fn nothing_written_reaches_nothing() {
        let o = effective(&declared(Section::Absent, Section::Absent), &HOST);
        assert_eq!(arm(&o, [93, 184, 215, 14]), RowArm::UndeclaredSubnet);
        let o = effective(
            &declared(Section::Listed(Vec::new()), Section::Absent),
            &HOST,
        );
        assert_eq!(arm(&o, [93, 184, 215, 14]), RowArm::UndeclaredSubnet);
    }

    #[test]
    fn denied_blocks_alone_reach_nothing() {
        let o = effective(
            &declared(Section::Absent, Section::Listed(vec![block(10, 0, 8)])),
            &HOST,
        );
        assert_eq!(arm(&o, [93, 184, 215, 14]), RowArm::UndeclaredSubnet);
    }

    #[test]
    fn the_whole_space_is_every_and_a_denied_block_still_refuses() {
        let o = effective(
            &declared(
                Section::Listed(vec![block(0, 0, 0)]),
                Section::Listed(vec![block(93, 184, 16)]),
            ),
            &HOST,
        );
        assert_eq!(arm(&o, [8, 8, 8, 8]), RowArm::Rules);
        assert_eq!(arm(&o, [93, 184, 215, 14]), RowArm::DeniedSubnet);
    }

    #[test]
    fn an_ipv6_block_is_named_and_grants_nothing() {
        let o = effective(
            &declared(
                Section::Listed(vec![Net::V6, block(93, 184, 16), Net::V6]),
                Section::Listed(vec![Net::V6]),
            ),
            &HOST,
        );
        assert_eq!(o.skipped_allowed, vec![0, 2]);
        assert_eq!(o.skipped_denied, vec![0]);
        assert_eq!(arm(&o, [93, 184, 215, 14]), RowArm::Rules);
        assert_eq!(arm(&o, [8, 8, 8, 8]), RowArm::UndeclaredSubnet);
        // The written-out allow-all in IPv6 alone reaches nothing.
        let o = effective(
            &declared(Section::Listed(vec![Net::V6]), Section::Absent),
            &HOST,
        );
        assert_eq!(arm(&o, [8, 8, 8, 8]), RowArm::UndeclaredSubnet);
    }

    #[test]
    fn a_host_address_box_on_a_host_that_cannot_decide_for_it_is_marked() {
        let mut d = declared(Section::Listed(vec![block(93, 184, 16)]), Section::Absent);
        d.host_address = true;
        let weak = Abilities {
            per_box_host_address: false,
        };
        assert!(effective(&d, &weak).host_address_unenforced);
        assert!(!effective(&d, &HOST).host_address_unenforced);
        d.host_address = false;
        assert!(!effective(&d, &weak).host_address_unenforced);
    }

    #[test]
    fn an_empty_protocol_section_passes_none_and_an_absent_one_all() {
        let mut d = declared(Section::Listed(vec![block(93, 184, 16)]), Section::Absent);
        assert_eq!(
            arm(&effective(&d, &HOST), [93, 184, 215, 14]),
            RowArm::Rules
        );
        d.allow_protocols = Section::Listed(Vec::new());
        assert_eq!(
            arm(&effective(&d, &HOST), [93, 184, 215, 14]),
            RowArm::UndeclaredProtocol
        );
        d.allow_protocols = Section::Listed(vec![17]);
        assert_eq!(
            arm(&effective(&d, &HOST), [93, 184, 215, 14]),
            RowArm::UndeclaredProtocol
        );
    }
}
