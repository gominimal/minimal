//! The rebinding intersection: which of an allowed name's answers a box may
//! reach (NET-066, NET-067).
//!
//! A name rule (`egress.allow_dns_hosts`) admits addresses, never names: when
//! the resolver Minimal owns answers a name the rule matches, the answer's
//! addresses are admitted for the box for a bounded window, and only those. An
//! answer that lands in a denied range is refused, so a name an attacker
//! controls cannot be rebound into the box's own switch, the host's loopback, a
//! metadata service or a private network the box never declared.
//!
//! One pure function, [`intersect`], decides every answer from owned
//! addresses and owned [`Cidr`] sets, with no resolver I/O: that is what lets
//! the Kani harness below exhaust it. The relay in `minimald` observes the
//! answer, applies the intersection, and pins what it admits; it never reasons
//! about the ranges itself.
//!
//! The denied ranges are the box's own `egress.deny_subnets` plus the
//! infrastructure deny set (design §5.3): link-local and metadata space,
//! loopback, the `100.64.0.0/10` plane the switch lives on, the gateway's own
//! addresses, and RFC 1918 unless the box's `egress.allow_subnets` covers the
//! answer.

use std::fmt;
use std::net::Ipv4Addr;

use super::net_verdict::Cidr;

/// The ranges the infrastructure deny set refuses unconditionally: link-local
/// (which holds the cloud metadata address), loopback, and the carrier-grade
/// NAT plane the switch is numbered from.
pub const INFRASTRUCTURE_DENY: [(Ipv4Addr, u8); 3] = [
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

/// The RFC 1918 ranges, refused unless the box's `allow_subnets` covers the
/// answer.
pub const PRIVATE_RANGES: [(Ipv4Addr, u8); 3] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
];

fn cidrs(ranges: &[(Ipv4Addr, u8)]) -> Vec<Cidr> {
    ranges
        .iter()
        .map(|(addr, prefix)| Cidr::new(*addr, *prefix).expect("a prefix of at most 32 bits"))
        .collect()
}

/// The ranges one box's answers are intersected against, owned and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindRules {
    /// The box's declared subnets; an answer in a private range is admitted
    /// only when one covers it. `None` declares every subnet.
    pub allow_subnets: Option<Vec<Cidr>>,
    /// The box's own `egress.deny_subnets`.
    pub deny_subnets: Vec<Cidr>,
    /// The unconditional infrastructure deny set: [`INFRASTRUCTURE_DENY`] plus
    /// the gateway's own addresses.
    pub infrastructure: Vec<Cidr>,
    /// Ranges refused unless `allow_subnets` covers the answer
    /// ([`PRIVATE_RANGES`]).
    pub private: Vec<Cidr>,
}

impl RebindRules {
    /// The rules for a box declaring `allow_subnets` and `deny_subnets`, on a
    /// switch whose gateway answers at `gateway_addresses` (the un-enrolled
    /// gateway, the helper's and the answerer's addresses).
    #[must_use]
    pub fn for_box(
        allow_subnets: Option<Vec<Cidr>>,
        deny_subnets: Vec<Cidr>,
        gateway_addresses: &[Ipv4Addr],
    ) -> Self {
        let mut infrastructure = cidrs(&INFRASTRUCTURE_DENY);
        // A /32 is always a valid prefix, so `filter_map` drops nothing.
        infrastructure.extend(
            gateway_addresses
                .iter()
                .filter_map(|addr| Cidr::new(*addr, 32)),
        );
        Self {
            allow_subnets,
            deny_subnets,
            infrastructure,
            private: cidrs(&PRIVATE_RANGES),
        }
    }
}

/// Why an answer's address was refused admission: the range it fell into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The box's own `egress.deny_subnets`.
    DeniedSubnet,
    /// The infrastructure deny set.
    Infrastructure,
    /// An RFC 1918 range the box's `allow_subnets` does not cover.
    PrivateRange,
}

impl Refusal {
    /// The range's name as a log line carries it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeniedSubnet => "deny_subnets",
            Self::Infrastructure => "infrastructure",
            Self::PrivateRange => "private-range",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verdict on one answered address: the range that refuses it, or `None`
/// when it may be admitted. The box's own denies are named first, then the
/// infrastructure set, then a private range no declared subnet covers.
#[must_use]
pub fn refusal(addr: Ipv4Addr, rules: &RebindRules) -> Option<Refusal> {
    if rules.deny_subnets.iter().any(|c| c.contains(addr)) {
        return Some(Refusal::DeniedSubnet);
    }
    if rules.infrastructure.iter().any(|c| c.contains(addr)) {
        return Some(Refusal::Infrastructure);
    }
    let covered = rules
        .allow_subnets
        .as_ref()
        .is_none_or(|allowed| allowed.iter().any(|c| c.contains(addr)));
    if !covered && rules.private.iter().any(|c| c.contains(addr)) {
        return Some(Refusal::PrivateRange);
    }
    None
}

/// An answer split by the intersection: what the box may reach, and what was
/// refused with the range that refused it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Intersection {
    /// The answered addresses admitted for the box.
    pub admitted: Vec<Ipv4Addr>,
    /// The answered addresses refused, each with its reason.
    pub refused: Vec<(Ipv4Addr, Refusal)>,
}

/// Intersects `answers` with `rules`. Pure: the same inputs always give the
/// same split, every answer lands in exactly one side, and the admitted side
/// holds no address any denied range contains.
#[must_use]
pub fn intersect(answers: &[Ipv4Addr], rules: &RebindRules) -> Intersection {
    let mut split = Intersection::default();
    for &addr in answers {
        match refusal(addr, rules) {
            Some(why) => split.refused.push((addr, why)),
            None => split.admitted.push(addr),
        }
    }
    split
}

/// Bounded verification of [`intersect`] (NET-067): exhaustive over at most two
/// IPv4 answers and two symbolic prefixes per set, every prefix length in
/// `0..=32`. The harness restates the denied ranges independently of the
/// function and checks both sides: an admitted address lies in no denied range,
/// and a refused one lies in the range named.
///
/// The bounds are what they are because this harness carries FOUR symbolic
/// prefix sets at once and matches every answer against each, and CBMC's cost
/// here is linear in both. Measured on one machine, each run reporting
/// `VERIFICATION:- SUCCESSFUL` except the first: at four answers and symbolic
/// set lengths the solve did not finish and grew until a CI runner was taken
/// down; at two answers with symbolic set lengths, 46 s and 10.0 GB of CBMC
/// peak; with the set lengths concrete (see [`any_cidrs`]), 31 s and 2.8 GB;
/// and with `kissat` in place of the default solver, 70 s and 1.2 GB, which is
/// the shape checked in — it was runner memory that killed this proof, not the
/// clock. Two levers were measured and rejected because they bought nothing:
/// drawing the prefix lengths from a concrete menu instead of `0..=32`, and
/// sizing the two output `Vec`s in [`intersect`] up front (that one doubled the
/// memory, a symbolic-length allocation costing more than the reallocation it
/// removes).
///
/// Run: `cargo kani -p sessions` (or `just kani`). The count of harnesses in
/// this crate is asserted by `scripts/kani.sh`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// At most this many answers, and exactly this many prefixes per set. The
    /// unwind bound below is one more, for each loop's exit check. Two answers
    /// still put one address on each side of the split at once, against every
    /// set, which is the shape the property is about.
    const BOUND: usize = 2;

    /// A set of exactly [`BOUND`] symbolic prefixes — which is every set size
    /// the property can tell apart. Nothing here asks a set anything but
    /// `iter().any(|c| c.contains(addr))`, for the answers drawn below, so a set
    /// whose entries contain none of those answers behaves as an empty set does
    /// and one whose entries coincide behaves as a one-entry set does; the
    /// symbolic networks cover both. Drawing a symbolic LENGTH instead, as this
    /// harness first did, makes CBMC carry a symbolic bound and a symbolic slice
    /// length through all four sets, which cost 7 of the 10 GB above.
    ///
    /// `with_capacity` is the exact bound on purpose: a `Vec` that grows makes
    /// CBMC model a reallocation and a copy per push.
    fn any_cidrs() -> Vec<Cidr> {
        let raw: [(u32, u8); BOUND] = kani::any();
        let mut cidrs = Vec::with_capacity(BOUND);
        for (addr, prefix) in &raw {
            kani::assume(*prefix <= 32);
            cidrs.push(Cidr::new(Ipv4Addr::from(*addr), *prefix).unwrap());
        }
        cidrs
    }

    #[kani::proof]
    #[kani::unwind(3)]
    // kissat rather than the default solver: the same proof, at 1.2 GB of CBMC
    // peak instead of 2.8 GB for twice the wall time. `cadical` was measured
    // too and matched the default on both counts. The binary ships in the Kani
    // bundle the lane already installs and caches.
    #[kani::solver(kissat)]
    fn kani_rebinding_intersection_admits_no_denied_address() {
        let n: usize = kani::any();
        kani::assume(n <= BOUND);
        let raw: [u32; BOUND] = kani::any();
        let mut answers: Vec<Ipv4Addr> = Vec::with_capacity(BOUND);
        for addr in raw.iter().take(n) {
            answers.push(Ipv4Addr::from(*addr));
        }
        let rules = RebindRules {
            allow_subnets: if kani::any() { Some(any_cidrs()) } else { None },
            deny_subnets: any_cidrs(),
            infrastructure: any_cidrs(),
            private: any_cidrs(),
        };

        let split = intersect(&answers, &rules);
        assert!(split.admitted.len() + split.refused.len() == answers.len());

        // The denied ranges, restated here rather than read back from the
        // function under proof.
        let in_any = |set: &[Cidr], addr: Ipv4Addr| set.iter().any(|c| c.contains(addr));
        for addr in &split.admitted {
            assert!(!in_any(&rules.deny_subnets, *addr));
            assert!(!in_any(&rules.infrastructure, *addr));
            let covered = rules
                .allow_subnets
                .as_ref()
                .is_none_or(|a| in_any(a, *addr));
            assert!(covered || !in_any(&rules.private, *addr));
        }
        for (addr, why) in &split.refused {
            match why {
                Refusal::DeniedSubnet => assert!(in_any(&rules.deny_subnets, *addr)),
                Refusal::Infrastructure => assert!(in_any(&rules.infrastructure, *addr)),
                Refusal::PrivateRange => {
                    assert!(in_any(&rules.private, *addr));
                    assert!(
                        rules
                            .allow_subnets
                            .as_ref()
                            .is_some_and(|a| !in_any(a, *addr))
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const GITHUB: Ipv4Addr = Ipv4Addr::new(140, 82, 112, 3);

    fn rules(allow: Option<&[&str]>, deny: &[&str]) -> RebindRules {
        let parse = |s: &&str| Cidr::parse(s).unwrap();
        RebindRules::for_box(
            allow.map(|a| a.iter().map(parse).collect()),
            deny.iter().map(parse).collect(),
            &[GATEWAY],
        )
    }

    #[test]
    fn public_answer_is_admitted_and_denied_ranges_are_named() {
        let rules = rules(Some(&[]), &["140.82.0.0/16"]);
        let split = intersect(
            &[
                GITHUB,
                Ipv4Addr::new(185, 199, 108, 153),
                Ipv4Addr::new(169, 254, 169, 254),
                Ipv4Addr::LOCALHOST,
                GATEWAY,
                Ipv4Addr::new(10, 0, 0, 5),
            ],
            &rules,
        );
        assert_eq!(split.admitted, vec![Ipv4Addr::new(185, 199, 108, 153)]);
        assert_eq!(
            split.refused,
            vec![
                (GITHUB, Refusal::DeniedSubnet),
                (Ipv4Addr::new(169, 254, 169, 254), Refusal::Infrastructure),
                (Ipv4Addr::LOCALHOST, Refusal::Infrastructure),
                (GATEWAY, Refusal::Infrastructure),
                (Ipv4Addr::new(10, 0, 0, 5), Refusal::PrivateRange),
            ]
        );
    }

    #[test]
    fn private_answer_is_admitted_only_when_allow_subnets_covers_it() {
        let lan = Ipv4Addr::new(192, 168, 1, 20);
        assert_eq!(
            refusal(lan, &rules(Some(&[]), &[])),
            Some(Refusal::PrivateRange)
        );
        assert_eq!(refusal(lan, &rules(Some(&["192.168.0.0/16"]), &[])), None);
        // A box declaring every subnet covers it too.
        assert_eq!(refusal(lan, &rules(None, &[])), None);
        // Covering a private range never lifts the infrastructure set.
        assert_eq!(
            refusal(GATEWAY, &rules(Some(&["0.0.0.0/0"]), &[])),
            Some(Refusal::Infrastructure)
        );
    }

    #[test]
    fn box_deny_is_named_before_the_infrastructure_set() {
        let rules = rules(None, &["127.0.0.0/8"]);
        assert_eq!(
            refusal(Ipv4Addr::LOCALHOST, &rules),
            Some(Refusal::DeniedSubnet)
        );
    }

    mod property {
        use super::*;
        use proptest::prelude::*;

        fn arb_cidrs() -> impl Strategy<Value = Vec<Cidr>> {
            proptest::collection::vec((any::<u32>(), 0u8..=32), 0..=4).prop_map(|raw| {
                raw.into_iter()
                    .map(|(a, p)| Cidr::new(Ipv4Addr::from(a), p).unwrap())
                    .collect()
            })
        }

        proptest! {
            /// The proptest twin of
            /// `kani_rebinding_intersection_admits_no_denied_address`, under
            /// the ordinary test run: every answer lands on one side, an
            /// admitted address lies in no denied range, and a refused one
            /// lies in the range named.
            #[test]
            fn rebinding_intersection_admits_no_denied_address(
                answers in proptest::collection::vec(any::<u32>(), 0..=4),
                allow in proptest::option::of(arb_cidrs()),
                deny in arb_cidrs(),
                infrastructure in arb_cidrs(),
                private in arb_cidrs(),
            ) {
                let answers: Vec<Ipv4Addr> = answers.into_iter().map(Ipv4Addr::from).collect();
                let rules = RebindRules { allow_subnets: allow, deny_subnets: deny, infrastructure, private };
                let split = intersect(&answers, &rules);
                prop_assert_eq!(split.admitted.len() + split.refused.len(), answers.len());

                let in_any = |set: &[Cidr], addr: Ipv4Addr| set.iter().any(|c| c.contains(addr));
                for addr in &split.admitted {
                    prop_assert!(!in_any(&rules.deny_subnets, *addr));
                    prop_assert!(!in_any(&rules.infrastructure, *addr));
                    let covered = rules.allow_subnets.as_ref().is_none_or(|a| in_any(a, *addr));
                    prop_assert!(covered || !in_any(&rules.private, *addr));
                }
                for (addr, why) in &split.refused {
                    match why {
                        Refusal::DeniedSubnet => prop_assert!(in_any(&rules.deny_subnets, *addr)),
                        Refusal::Infrastructure => prop_assert!(in_any(&rules.infrastructure, *addr)),
                        Refusal::PrivateRange => {
                            prop_assert!(in_any(&rules.private, *addr));
                            prop_assert!(rules.allow_subnets.as_ref().is_some_and(|a| !in_any(a, *addr)));
                        }
                    }
                }
            }
        }
    }
}
