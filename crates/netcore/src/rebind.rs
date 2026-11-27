//! Which addresses a DNS answer may admit.
//!
//! Layer 3 of the crate, from policy to rules. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! A name a box declares makes an address reachable. This is the check that
//! stops a name from being a way around the rules: the address an answer
//! carries is admitted only if the rules could have named it.
//!
//! The decision is a table, [`rebind_spec`], in the order the arms are tried:
//! the box's own denied subnets; the ranges no name may name; the plane
//! (100.64.0.0/10), which a box-zone name and every other name answer from
//! opposite sides; private space the box's allowed subnets do not cover.
//!
//! THEOREM RB1, for every address, rule list and list of the switch's own
//! addresses:
//!   (a) [`rebind`] returns `rebind_spec`;
//!   (b) an address in a denied subnet is never admitted;
//!   (c) an address in 169.254.0.0/16, 127.0.0.0/8, 0.0.0.0/8, 224.0.0.0/4 or
//!       240.0.0.0/4, or one of the switch's own listed addresses, is never
//!       admitted;
//!   (d) for a name outside the box zone, an address in 100.64.0.0/10 is
//!       never admitted: for a plan inside that range, no address of the
//!       plan's block, so no box's lease, nor the gateway, the node, the
//!       proxy, the cohort's address or the host alias;
//!   (e) for a box-zone name, only an address in 100.64.0.0/10 is admitted;
//!   (f) a private address (10/8, 172.16/12, 192.168/16) is admitted only
//!       when the allowed subnets cover it.
//!
//! THEOREM FL1 (the floor): [`floor_ok`] refuses the ranges no name may
//! name, the whole of 100.64.0.0/10, and every address of the plan's own
//! block, and reads no rule list. Whatever the check above admits for a name
//! outside the box zone, on a plan inside 100.64.0.0/10, passes the floor;
//! [`floor`] keeps exactly the addresses of a list that pass, in order, and
//! leaves a list that already passes as it is.
//!
//! What it does not say:
//! that the address came from the answer to the question asked, which is the
//! caller's to establish, and which box a box-zone address belongs to.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::plan::Plan;
#[cfg(verus_keep_ghost)]
use crate::plan::{spec_contains, spec_shared, wf};
use crate::row::{Cidr, any_covers};
#[cfg(verus_keep_ghost)]
use crate::row::{allow_covers, covers, in_plane, in_private};

/// What the check says of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Rebind {
    /// The address may be admitted.
    Admitted,
    /// Refused: a subnet the box denied.
    DeniedSubnet,
    /// Refused: a range no name may name, the wrong side of the plane, or
    /// private space the box did not allow.
    Infrastructure,
}

#[cfg(verus_keep_ghost)]
verus! {

/// 169.254.0.0/16, 127.0.0.0/8, 0.0.0.0/8, 224.0.0.0/4 or 240.0.0.0/4.
pub open spec fn never_named(a: u32) -> bool {
    a >> 16 == 0xa9feu32 || a >> 24 == 127u32 || a >> 24 == 0u32 || a >> 28 == 0xeu32 || a >> 28 == 0xfu32
}

/// `a` is one of `own`.
pub open spec fn own_address(own: Seq<u32>, a: u32) -> bool {
    exists|i: int| 0 <= i < own.len() && own[i] == a
}

/// The table.
pub open spec fn rebind_spec(a: u32, box_zone: bool, deny: Seq<Cidr>, allow: Option<Vec<Cidr>>, own: Seq<u32>) -> Rebind {
    if covers(deny, a) {
        Rebind::DeniedSubnet
    } else if never_named(a) || own_address(own, a) {
        Rebind::Infrastructure
    } else if box_zone != in_plane(a) {
        Rebind::Infrastructure
    } else if in_private(a) && !allow_covers(allow, a) {
        Rebind::Infrastructure
    } else {
        Rebind::Admitted
    }
}

/// RB1 (c), as addresses: the ranges no name may name are 0.0.0.0 to
/// 0.255.255.255, 127.0.0.0 to 127.255.255.255, 169.254.0.0 to
/// 169.254.255.255, and 224.0.0.0 upward. Stated by bounds, where the
/// definition shifts, so that neither can lose a range unnoticed.
pub proof fn theorem_rb1_the_ranges_no_name_may_name(a: u32)
    ensures
        never_named(a) == (a <= 0x00ff_ffffu32
            || (0x7f00_0000u32 <= a && a <= 0x7fff_ffffu32)
            || (0xa9fe_0000u32 <= a && a <= 0xa9fe_ffffu32)
            || a >= 0xe000_0000u32),
{
    assert((a >> 16 == 0xa9feu32 || a >> 24 == 127u32 || a >> 24 == 0u32 || a >> 28 == 0xeu32 || a >> 28 == 0xfu32)
        == (a <= 0x00ff_ffffu32
            || (0x7f00_0000u32 <= a && a <= 0x7fff_ffffu32)
            || (0xa9fe_0000u32 <= a && a <= 0xa9fe_ffffu32)
            || a >= 0xe000_0000u32)) by (bit_vector);
}

/// RB1 (b), (c), (f).
pub proof fn theorem_rb1_refused_ranges(a: u32, box_zone: bool, deny: Seq<Cidr>, allow: Option<Vec<Cidr>>, own: Seq<u32>)
    ensures
        covers(deny, a) ==> rebind_spec(a, box_zone, deny, allow, own) != Rebind::Admitted,
        never_named(a) ==> rebind_spec(a, box_zone, deny, allow, own) != Rebind::Admitted,
        own_address(own, a) ==> rebind_spec(a, box_zone, deny, allow, own) != Rebind::Admitted,
        in_private(a) && !allow_covers(allow, a) ==> rebind_spec(a, box_zone, deny, allow, own) != Rebind::Admitted,
{
}

/// RB1 (d): no ordinary name reaches the plan's block.
pub proof fn theorem_rb1_ordinary_name_reaches_no_box(plan: Plan, a: u32, deny: Seq<Cidr>, allow: Option<Vec<Cidr>>, own: Seq<u32>)
    requires
        wf(plan),
        spec_shared(plan),
        rebind_spec(a, false, deny, allow, own) == Rebind::Admitted,
    ensures
        !in_plane(a),
        !spec_contains(plan, a as int),
{
    // The block lies inside 100.64.0.0/10, and the address is outside it.
    assert((a >> 22 == 0x191u32) == (0x6440_0000u32 <= a && a <= 0x647f_ffffu32)) by (bit_vector);
}

/// RB1 (e): a box-zone name reaches the plane only.
pub proof fn theorem_rb1_zone_name_stays_in_the_plane(a: u32, deny: Seq<Cidr>, allow: Option<Vec<Cidr>>, own: Seq<u32>)
    requires
        rebind_spec(a, true, deny, allow, own) == Rebind::Admitted,
    ensures
        in_plane(a),
        !own_address(own, a),
{
}

/// The floor: an address a DNS answer may never admit into any table of the
/// host gate, whatever the rules say. Not one of the ranges no name may
/// name, not in 100.64.0.0/10, not in the plan's own block.
pub open spec fn floor_ok(plan: Plan, a: u32) -> bool {
    &&& !never_named(a)
    &&& !in_plane(a)
    &&& !spec_contains(plan, a as int)
}

/// `s` without the addresses that fail the floor, in order.
pub open spec fn floored(plan: Plan, s: Seq<u32>) -> Seq<u32>
    decreases s.len(),
{
    if s.len() == 0 {
        Seq::<u32>::empty()
    } else if floor_ok(plan, s.last()) {
        floored(plan, s.drop_last()).push(s.last())
    } else {
        floored(plan, s.drop_last())
    }
}

/// FL1: every address the floor keeps passes it and was in the list.
pub proof fn theorem_floored_members(plan: Plan, s: Seq<u32>, j: int)
    requires
        0 <= j < floored(plan, s).len(),
    ensures
        floor_ok(plan, floored(plan, s)[j]),
        exists|k: int| 0 <= k < s.len() && s[k] == floored(plan, s)[j],
        floored(plan, s).len() <= s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        let rest = floored(plan, s.drop_last());
        lemma_floored_len(plan, s.drop_last());
        if floor_ok(plan, s.last()) && j == rest.len() {
            assert(floored(plan, s)[j] == s[s.len() - 1]);
        } else {
            theorem_floored_members(plan, s.drop_last(), j);
            let k = choose|k: int| 0 <= k < s.drop_last().len() && s.drop_last()[k] == rest[j];
            assert(s[k] == floored(plan, s)[j]);
        }
    }
}

pub proof fn lemma_floored_len(plan: Plan, s: Seq<u32>)
    ensures
        floored(plan, s).len() <= s.len(),
    decreases s.len(),
{
    if s.len() > 0 {
        lemma_floored_len(plan, s.drop_last());
    }
}

/// FL1: a list that already passes is left as it is.
pub proof fn theorem_floored_identity(plan: Plan, s: Seq<u32>)
    requires
        forall|k: int| 0 <= k < s.len() ==> floor_ok(plan, #[trigger] s[k]),
    ensures
        floored(plan, s) == s,
    decreases s.len(),
{
    if s.len() > 0 {
        assert forall|k: int| 0 <= k < s.drop_last().len() implies floor_ok(plan, #[trigger] s.drop_last()[k]) by {
            assert(s.drop_last()[k] == s[k]);
        }
        theorem_floored_identity(plan, s.drop_last());
        assert(floor_ok(plan, s[s.len() - 1]));
        assert(s.drop_last().push(s.last()) =~= s);
    }
}

/// FL1: on a plan inside 100.64.0.0/10, whatever the check admits for a name
/// outside the box zone passes the floor. A caller that filtered as the
/// product does is therefore not changed by it.
pub proof fn theorem_floor_is_below_the_check(plan: Plan, a: u32, deny: Seq<Cidr>, allow: Option<Vec<Cidr>>, own: Seq<u32>)
    requires
        wf(plan),
        spec_shared(plan),
        rebind_spec(a, false, deny, allow, own) == Rebind::Admitted,
    ensures
        floor_ok(plan, a),
{
    theorem_rb1_ordinary_name_reaches_no_box(plan, a, deny, allow, own);
}

} // verus!

/// Whether `a` passes the floor.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires wf(*plan),
    ensures r == floor_ok(*plan, a),
))]
pub fn passes_floor(plan: &Plan, a: u32) -> bool {
    if a >> 16 == 0xa9fe || a >> 24 == 127 || a >> 24 == 0 || a >> 28 == 0xe || a >> 28 == 0xf {
        return false;
    }
    if a >> 22 == 0x191 {
        return false;
    }
    !plan.contains(a)
}

/// `addrs` without the addresses that fail the floor, in order.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires wf(*plan),
    ensures
        r@ == floored(*plan, addrs@),
        r@.len() <= addrs@.len(),
))]
pub fn floor(plan: &Plan, addrs: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            wf(*plan),
            i <= addrs.len(),
            out@ == floored(*plan, addrs@.take(i as int)),
            out@.len() <= i,
        decreases addrs.len() - i,
    ))]
    while i < addrs.len() {
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(addrs@.take(i as int + 1).drop_last() =~= addrs@.take(i as int));
            assert(addrs@.take(i as int + 1).last() == addrs@[i as int]);
        }
        if passes_floor(plan, addrs[i]) {
            out.push(addrs[i]);
        }
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(addrs@.take(addrs@.len() as int) =~= addrs@);
    }
    out
}

/// Whether `a` is one of `own`.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == own_address(own@, a),
))]
fn is_own(own: &[u32], a: u32) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= own.len(),
            forall|j: int| 0 <= j < i ==> own@[j] != a,
        decreases own.len() - i,
    ))]
    while i < own.len() {
        if own[i] == a {
            return true;
        }
        i += 1;
    }
    false
}

/// What the check says of address `a`, an answer for a name inside the box
/// zone (`box_zone`) or outside it, for a box with these denied and allowed
/// subnets, on a switch whose own addresses are `own`. RB1 (a).
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        r == rebind_spec(a, box_zone, deny@, *allow, own@),
))]
pub fn rebind(
    a: u32,
    box_zone: bool,
    deny: &[Cidr],
    allow: &Option<Vec<Cidr>>,
    own: &[u32],
) -> Rebind {
    if any_covers(deny, a) {
        return Rebind::DeniedSubnet;
    }
    if a >> 16 == 0xa9fe || a >> 24 == 127 || a >> 24 == 0 || a >> 28 == 0xe || a >> 28 == 0xf {
        return Rebind::Infrastructure;
    }
    if is_own(own, a) {
        return Rebind::Infrastructure;
    }
    let plane = a >> 22 == 0x191;
    if box_zone != plane {
        return Rebind::Infrastructure;
    }
    let private = a >> 24 == 10 || a >> 20 == 0xac1 || a >> 16 == 0xc0a8;
    if private {
        let covered = match allow {
            None => true,
            Some(list) => any_covers(list.as_slice(), a),
        };
        if !covered {
            return Rebind::Infrastructure;
        }
    }
    Rebind::Admitted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    fn block(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Cidr {
        Cidr {
            addr: ip(a, b, c, d),
            prefix,
        }
    }

    #[test]
    fn an_ordinary_name_reaches_a_public_address_and_nothing_of_the_switch() {
        let own = [ip(100, 64, 3, 1), ip(100, 64, 3, 254)];
        assert_eq!(
            rebind(ip(93, 184, 216, 34), false, &[], &None, &own),
            Rebind::Admitted
        );
        // A sibling's lease, the gateway and the alias: all inside the plane.
        assert_eq!(
            rebind(ip(100, 64, 3, 9), false, &[], &None, &own),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(100, 64, 3, 1), false, &[], &None, &own),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(100, 127, 255, 255), false, &[], &None, &own),
            Rebind::Infrastructure
        );
        // The addresses on either side of the plane are outside it.
        assert_eq!(
            rebind(ip(100, 63, 255, 255), false, &[], &None, &own),
            Rebind::Admitted
        );
        assert_eq!(
            rebind(ip(100, 128, 0, 0), false, &[], &None, &own),
            Rebind::Admitted
        );
    }

    #[test]
    fn the_ranges_no_name_may_name_are_refused_for_every_name() {
        for zone in [false, true] {
            for a in [
                ip(169, 254, 169, 254),
                ip(127, 0, 0, 1),
                ip(0, 0, 0, 0),
                ip(0, 255, 255, 255),
                ip(224, 0, 0, 1),
                ip(239, 255, 255, 255),
                ip(240, 0, 0, 1),
                ip(255, 255, 255, 255),
            ] {
                assert_eq!(rebind(a, zone, &[], &None, &[]), Rebind::Infrastructure);
            }
        }
    }

    #[test]
    fn a_zone_name_reaches_the_plane_only_and_never_the_switchs_own_addresses() {
        let own = [ip(100, 64, 3, 1), ip(100, 64, 3, 254)];
        assert_eq!(
            rebind(ip(100, 64, 3, 9), true, &[], &None, &own),
            Rebind::Admitted
        );
        assert_eq!(
            rebind(ip(100, 64, 3, 1), true, &[], &None, &own),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(100, 64, 3, 254), true, &[], &None, &own),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(93, 184, 216, 34), true, &[], &None, &own),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(10, 0, 0, 5), true, &[], &None, &own),
            Rebind::Infrastructure
        );
    }

    #[test]
    fn private_space_needs_the_allowed_subnets_to_cover_it() {
        let lan = Some(vec![block(192, 168, 1, 0, 24)]);
        assert_eq!(
            rebind(ip(192, 168, 1, 7), false, &[], &lan, &[]),
            Rebind::Admitted
        );
        assert_eq!(
            rebind(ip(192, 168, 2, 7), false, &[], &lan, &[]),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(10, 1, 2, 3), false, &[], &lan, &[]),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(172, 16, 0, 1), false, &[], &lan, &[]),
            Rebind::Infrastructure
        );
        assert_eq!(
            rebind(ip(172, 32, 0, 1), false, &[], &lan, &[]),
            Rebind::Admitted
        );
        // No allowed-subnets list at all covers everything.
        assert_eq!(
            rebind(ip(10, 1, 2, 3), false, &[], &None, &[]),
            Rebind::Admitted
        );
        // A public address needs no cover.
        assert_eq!(
            rebind(ip(93, 184, 216, 34), false, &[], &lan, &[]),
            Rebind::Admitted
        );
    }

    #[test]
    fn the_floor_keeps_what_passes_in_order_and_reads_no_rule() {
        let plan = Plan::new(ip(100, 64, 3, 0), 24).unwrap();
        let public = ip(93, 184, 216, 34);
        let lan = ip(192, 168, 1, 7);
        let kept = floor(
            &plan,
            &[
                public,
                ip(100, 64, 3, 9), // a lease in the block
                ip(100, 64, 3, 1), // the gateway
                ip(100, 99, 0, 1), // the plane, outside the block
                lan,               // private space: the rules' business, not the floor's
                ip(169, 254, 169, 254),
                ip(127, 0, 0, 1),
                ip(0, 0, 0, 0),
                ip(224, 0, 0, 1),
                ip(255, 255, 255, 255),
                public + 1,
            ],
        );
        assert_eq!(kept, vec![public, lan, public + 1]);
        assert_eq!(floor(&plan, &[]), Vec::<u32>::new());
        assert_eq!(floor(&plan, &[public, lan]), vec![public, lan]);
    }

    #[test]
    fn the_floor_refuses_a_plans_block_even_outside_the_plane() {
        let plan = Plan::new(ip(10, 9, 8, 0), 24).unwrap();
        assert!(!passes_floor(&plan, ip(10, 9, 8, 77)));
        assert!(passes_floor(&plan, ip(10, 9, 9, 77)));
        assert!(!passes_floor(&plan, ip(100, 64, 0, 5)));
    }

    #[test]
    fn a_denied_subnet_outranks_every_allowance() {
        let deny = [block(93, 184, 0, 0, 16), block(192, 168, 1, 0, 24)];
        let lan = Some(vec![block(192, 168, 0, 0, 16)]);
        assert_eq!(
            rebind(ip(93, 184, 216, 34), false, &deny, &None, &[]),
            Rebind::DeniedSubnet
        );
        assert_eq!(
            rebind(ip(192, 168, 1, 7), false, &deny, &lan, &[]),
            Rebind::DeniedSubnet
        );
        assert_eq!(
            rebind(ip(192, 168, 2, 7), false, &deny, &lan, &[]),
            Rebind::Admitted
        );
        // The deny is reported even where infrastructure would also refuse.
        let deny = [block(127, 0, 0, 0, 8)];
        assert_eq!(
            rebind(ip(127, 0, 0, 1), false, &deny, &None, &[]),
            Rebind::DeniedSubnet
        );
    }
}

#[cfg(kani)]
mod proofs {
    //! The check against a second reading written with address ranges, where
    //! the code shifts.
    use super::*;

    fn in_range(a: u32, lo: [u8; 4], hi: [u8; 4]) -> bool {
        u32::from_be_bytes(lo) <= a && a <= u32::from_be_bytes(hi)
    }

    fn block_holds(c: Cidr, a: u32) -> bool {
        let span: u64 = if c.prefix >= 32 {
            1
        } else {
            1u64 << (32 - c.prefix as u32)
        };
        let base = (c.addr as u64 / span) * span;
        base <= a as u64 && (a as u64) < base + span
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_rebind_agrees_with_the_ranges() {
        let a: u32 = kani::any();
        let box_zone: bool = kani::any();
        let deny = [
            Cidr {
                addr: kani::any(),
                prefix: kani::any(),
            },
            Cidr {
                addr: kani::any(),
                prefix: kani::any(),
            },
        ];
        let allow_list = vec![Cidr {
            addr: kani::any(),
            prefix: kani::any(),
        }];
        let allow_declared: bool = kani::any();
        let allow = if allow_declared {
            Some(allow_list.clone())
        } else {
            None
        };
        let own: [u32; 2] = [kani::any(), kani::any()];

        let denied = block_holds(deny[0], a) || block_holds(deny[1], a);
        let never = in_range(a, [169, 254, 0, 0], [169, 254, 255, 255])
            || in_range(a, [127, 0, 0, 0], [127, 255, 255, 255])
            || in_range(a, [0, 0, 0, 0], [0, 255, 255, 255])
            || in_range(a, [224, 0, 0, 0], [255, 255, 255, 255]);
        let plane = in_range(a, [100, 64, 0, 0], [100, 127, 255, 255]);
        let private = in_range(a, [10, 0, 0, 0], [10, 255, 255, 255])
            || in_range(a, [172, 16, 0, 0], [172, 31, 255, 255])
            || in_range(a, [192, 168, 0, 0], [192, 168, 255, 255]);
        let covered = !allow_declared || block_holds(allow_list[0], a);
        let want = if denied {
            Rebind::DeniedSubnet
        } else if never || own[0] == a || own[1] == a || box_zone != plane || (private && !covered)
        {
            Rebind::Infrastructure
        } else {
            Rebind::Admitted
        };
        assert!(rebind(a, box_zone, &deny, &allow, &own) == want);
        kani::cover!(want == Rebind::Admitted && box_zone);
        kani::cover!(want == Rebind::Admitted && !box_zone && private);
        kani::cover!(want == Rebind::DeniedSubnet && never);
        kani::cover!(want == Rebind::Infrastructure && own[1] == a && !never);
    }
}
