//! The redemption decision (BEP-019 to BEP-021, BEP-024, BEP-031, BEP-058).
//!
//! The proxy decides whether to redeem a sealed value in one pure function,
//! [`decide`], over owned values. The TLS and socket shell does the I/O. It
//! opens the value with [`crate::seal::open`], resolves the connection's
//! source address to a box, and looks up the box the value names. It then
//! gives the facts to [`decide`] as a [`Redemption`]. [`decide`] reads no
//! clock, no socket and no key, so a property test and a Kani harness can
//! cover every input.
//!
//! The box ids and the authority hosts are type parameters. The shell uses
//! the box id strings and interns each host name. A Kani harness uses `u8`
//! ids, so it can exhaust them.
//!
//! The checks run in a fixed order, and a refusal names the first check that
//! failed, as a [`Check`]. [`Check::marker`] is the word the audit record
//! carries for it:
//!
//! 1. The value decrypts under this host's proxy key (BEP-019).
//! 2. The member carries a `mode` and a recognised `breadth` (BEP-058).
//! 3. The connection's source is the box the value names (BEP-020). A source
//!    in the `host_ip` cohort passes only when the named box is a live
//!    `host_ip` box of this host. The admission then says
//!    [`Attributed::Cohort`], and the audit records it `cohort_attributed`.
//!    A value that [`crate::seal::open`] refuses as bound to another box id
//!    is [`Unsealed::OtherBox`], and this check refuses it too.
//! 4. The clock is before the value's expiry (BEP-024). A value that
//!    [`crate::seal::open`] refuses as past its expiry is
//!    [`Unsealed::Expired`], and this check refuses it too.
//! 5. No revocation in force covers the value's box id (BEP-024, BEP-071).
//! 6. The connection's port is a declared port of the module's current host
//!    set for that hostname (BEP-031). A hostname outside the current set is
//!    not credentialed, so check 8 refuses it.
//! 7. The connection authority is in the value's bound host set (BEP-021).
//! 8. The connection authority is in the module's current host set
//!    (BEP-021).
//!
//! The other redemption checks (egress and request authority) are not in
//! this module yet.

use std::fmt;

use crate::seal::{BoundField, Breadth, Mode, OpenError, Opened};

/// What the shell found when it opened the sealed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsealed<B> {
    /// The value does not decrypt under this host's proxy key. This includes
    /// a value sealed to another host's key.
    Undecryptable,
    /// The value decrypted, but its member carries no `breadth` or one this
    /// proxy does not recognise. [`crate::seal::open`] reports this without
    /// the value's context, so no box id comes with it.
    Unbounded,
    /// The value decrypted, but it names a box other than the one the shell
    /// bound the open to. [`crate::seal::open`] reports this as
    /// [`OpenError::ContextMismatch`] with [`BoundField::BoxId`], before it
    /// reads the member, so no bounds come with it. [`decide`] refuses it
    /// at the attribution check (BEP-020).
    OtherBox,
    /// The value decrypted for the box the shell bound the open to, but it
    /// is past its expiry, or its member is past the member's own expiry.
    /// [`crate::seal::open`] reports this as [`OpenError::Expired`] before
    /// it reads the member, so no bounds come with it. [`decide`] refuses
    /// it at the expiry check (BEP-024), after the attribution check.
    Expired,
    /// The value decrypted.
    Opened {
        /// The box the value names.
        box_id: B,
        /// The member's bounds.
        bounds: Bounds,
        /// The earliest expiry of the value and its member, in seconds
        /// since the Unix epoch.
        expiry: u64,
    },
}

impl Unsealed<String> {
    /// Maps the result of [`crate::seal::open`] to the decryption fact.
    ///
    /// A value that opens gives [`Unsealed::Opened`]. A value sealed to
    /// another key, or one that does not decrypt, gives
    /// [`Unsealed::Undecryptable`]. Only [`OpenError::NotOpenable`] says
    /// that. [`OpenError::Unsupported`] says the header's type, algorithm or
    /// key is not one this proxy reads, so it comes back unchanged. A member with a missing or unknown
    /// breadth gives [`Unsealed::Unbounded`], so [`decide`] refuses it as
    /// [`Check::UnboundedMember`]. A value bound to another box id gives
    /// [`Unsealed::OtherBox`], so [`decide`] refuses it as
    /// [`Check::CrossBox`], or as [`Check::NoLiveBox`] when the source
    /// resolves to no live box. A value past its expiry gives
    /// [`Unsealed::Expired`], so [`decide`] refuses it as [`Check::Expired`]
    /// once the attribution passes.
    ///
    /// The shell binds the open to the box id that the source resolves to.
    /// For an [`Attribution::OwnIp`] source, that is the sending box, so a
    /// value from another `own_ip` box comes back as
    /// [`Unsealed::OtherBox`].
    ///
    /// An [`Attribution::HostIpCohort`] source resolves to no single box.
    /// [`crate::seal`] has no call that reads the value's box id before the
    /// open. So the shell binds the open to each live box of the cohort in
    /// turn, and keeps the first result that is not [`Unsealed::OtherBox`].
    /// That box is in the cohort, so the shell sets
    /// [`Redemption::named_box_in_cohort`]. When every live box of the
    /// cohort gives [`Unsealed::OtherBox`], the shell gives that, and
    /// [`decide`] refuses it as [`Check::CrossBox`].
    ///
    /// # Errors
    ///
    /// Every other [`OpenError`] comes back unchanged. Those refusals belong
    /// to checks this module does not make, and the shell refuses on them.
    /// A header with no `mode` does not parse, so it is
    /// [`OpenError::Malformed`] before any decryption.
    pub fn from_open(result: Result<Opened, OpenError>) -> Result<Self, OpenError> {
        match result {
            Ok(opened) => Ok(Self::Opened {
                expiry: opened
                    .member
                    .exp
                    .map_or(opened.context.expiry, |exp| exp.min(opened.context.expiry)),
                box_id: opened.context.box_id,
                bounds: Bounds {
                    mode: Some(opened.context.mode),
                    breadth: Some(opened.member.breadth),
                },
            }),
            Err(OpenError::NotOpenable) => Ok(Self::Undecryptable),
            Err(OpenError::Expired) => Ok(Self::Expired),
            Err(OpenError::UnknownBreadth) => Ok(Self::Unbounded),
            Err(OpenError::ContextMismatch(BoundField::BoxId)) => Ok(Self::OtherBox),
            Err(other) => Err(other),
        }
    }
}

/// The bounds a sealed member carries (BEP-058).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bounds {
    /// The mode, or `None` when the value carries none.
    pub mode: Option<Mode>,
    /// The breadth, or `None` when the member carries none or one this
    /// proxy does not recognise.
    pub breadth: Option<Breadth>,
}

/// The box the connection's source address resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution<B> {
    /// The source resolves to no live box.
    NoLiveBox,
    /// The source is the own address of this live `own_ip` box.
    OwnIp(B),
    /// The source is the shared address of this host's live `host_ip`
    /// boxes. It does not say which one. On an un-enrolled node, until
    /// NET-132 and NET-133 are built, every VM-hosted box and the host shell
    /// send from this address (see [`Redemption::named_box_in_cohort`]).
    HostIpCohort,
}

/// One authority: a hostname, interned as an `H`, and a port.
///
/// A host-set entry written with no port is port 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Authority<H> {
    /// The hostname.
    pub host: H,
    /// The port.
    pub port: u16,
}

/// One redemption, as the shell sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption<B, H> {
    /// The decryption fact, with the named box and the member's bounds.
    pub unsealed: Unsealed<B>,
    /// The box the connection's source resolves to.
    pub attribution: Attribution<B>,
    /// Whether the box the value names is a live box of this host behind
    /// the cohort's shared address.
    ///
    /// On an enrolled node, the shell sets this field only when the named
    /// box is a live `host_ip` box of this host. Cross-box redemption
    /// between `own_ip` boxes is then always refused.
    ///
    /// An un-enrolled node has an interim, until the per-box attachment
    /// facts (NET-132, NET-133) are built. Every VM-hosted box, `own_ip`
    /// included, and the host shell send from one shared attachment. The
    /// shell gives such a source as [`Attribution::HostIpCohort`]. It sets
    /// this field when the named box is any live VM-hosted box of this
    /// host. The admission is then audited `cohort_attributed`. The
    /// cross-box and host-shell refusals do not hold in that interim. The
    /// spec records this as a residual risk (T28, Gatehouse §6.10).
    pub named_box_in_cohort: bool,
    /// The clock reading for this request, in seconds since the Unix epoch.
    pub now: u64,
    /// The box ids that the revocations in force name. The shell selects
    /// the revocations in force before it calls [`decide`] (BEP-071).
    pub revoked: Vec<B>,
    /// The authority the connection arrived on.
    pub authority: Authority<H>,
    /// The module's host set at the version the value carries.
    pub bound_set: Vec<Authority<H>>,
    /// The module's current host set.
    pub current_set: Vec<Authority<H>>,
}

/// How an admitted request was attributed to the box the value names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attributed {
    /// The source is the named box's own address.
    OwnBox,
    /// The source is the `host_ip` cohort, and the named box is in it. The
    /// audit records this `cohort_attributed`.
    Cohort,
}

/// The check that refused a redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// The value does not decrypt under this host's proxy key (BEP-019).
    Undecryptable,
    /// The member carries no `mode` or no recognised `breadth` (BEP-058).
    UnboundedMember,
    /// The source address resolves to no live box (BEP-020).
    NoLiveBox,
    /// The source is a box other than the one the value names, or the
    /// `host_ip` cohort when the named box is not in it (BEP-020).
    CrossBox,
    /// The clock is at or after the value's expiry (BEP-024).
    Expired,
    /// A revocation in force names the value's box (BEP-024).
    Revoked,
    /// The hostname is in the module's current host set, but not on the
    /// connection's port (BEP-031).
    OffPort,
    /// The authority is not in the value's bound host set (BEP-021).
    OutsideBoundSet,
    /// The authority is not in the module's current host set (BEP-021).
    OutsideCurrentSet,
}

impl Check {
    /// The audit record's marker for this check.
    #[must_use]
    pub fn marker(self) -> &'static str {
        match self {
            Self::Undecryptable => "undecryptable",
            Self::UnboundedMember => "unbounded_member",
            Self::NoLiveBox => "no_live_box",
            Self::CrossBox => "cross_box",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::OffPort => "off_port",
            Self::OutsideBoundSet => "outside_bound_set",
            Self::OutsideCurrentSet => "outside_current_set",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.marker())
    }
}

/// The redemption decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Every check passed.
    Admit {
        /// How the source was attributed to the named box.
        attributed: Attributed,
        /// The member's mode, for the audit.
        mode: Mode,
        /// The member's breadth.
        breadth: Breadth,
    },
    /// The first check that failed.
    Refuse(Check),
}

/// Decides one redemption. Pure: the result depends only on `redemption`.
#[must_use]
pub fn decide<B: PartialEq, H: PartialEq>(redemption: &Redemption<B, H>) -> Decision {
    // BEP-019: only a value this host's key opens is redeemed.
    let (box_id, bounds, expiry) = match &redemption.unsealed {
        Unsealed::Undecryptable => return Decision::Refuse(Check::Undecryptable),
        Unsealed::Unbounded => return Decision::Refuse(Check::UnboundedMember),
        // BEP-020: open refused the value as bound to another box id. The
        // bounds are unknown, so the attribution check is the first that
        // can fail.
        Unsealed::OtherBox => {
            return Decision::Refuse(match redemption.attribution {
                Attribution::NoLiveBox => Check::NoLiveBox,
                Attribution::OwnIp(_) | Attribution::HostIpCohort => Check::CrossBox,
            });
        }
        // BEP-024: open refused the value as past its expiry. The open was
        // bound to the box the source resolves to, so only the source can
        // fail first.
        Unsealed::Expired => {
            return Decision::Refuse(match redemption.attribution {
                Attribution::NoLiveBox => Check::NoLiveBox,
                Attribution::HostIpCohort if !redemption.named_box_in_cohort => Check::CrossBox,
                Attribution::OwnIp(_) | Attribution::HostIpCohort => Check::Expired,
            });
        }
        Unsealed::Opened {
            box_id,
            bounds,
            expiry,
        } => (box_id, bounds, *expiry),
    };
    // BEP-058: a member with no mode or no recognised breadth is refused.
    let (Some(mode), Some(breadth)) = (bounds.mode, bounds.breadth) else {
        return Decision::Refuse(Check::UnboundedMember);
    };
    // BEP-020: the source must be the named box, or the cohort it is in.
    let attributed = match &redemption.attribution {
        Attribution::NoLiveBox => return Decision::Refuse(Check::NoLiveBox),
        Attribution::OwnIp(sender) if sender == box_id => Attributed::OwnBox,
        Attribution::HostIpCohort if redemption.named_box_in_cohort => Attributed::Cohort,
        Attribution::OwnIp(_) | Attribution::HostIpCohort => {
            return Decision::Refuse(Check::CrossBox);
        }
    };
    // BEP-024: only a value before its expiry, and not revoked, is redeemed.
    if redemption.now >= expiry {
        return Decision::Refuse(Check::Expired);
    }
    if redemption.revoked.contains(box_id) {
        return Decision::Refuse(Check::Revoked);
    }
    // BEP-031: a credentialed hostname is reached only on a declared port.
    let authority = &redemption.authority;
    let current = &redemption.current_set;
    if current.iter().any(|a| a.host == authority.host) && !current.contains(authority) {
        return Decision::Refuse(Check::OffPort);
    }
    // BEP-021: the authority is in the bound set and in the current set.
    if !redemption.bound_set.contains(authority) {
        return Decision::Refuse(Check::OutsideBoundSet);
    }
    if !current.contains(authority) {
        return Decision::Refuse(Check::OutsideCurrentSet);
    }
    Decision::Admit {
        attributed,
        mode,
        breadth,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use zeroize::Zeroizing;

    use super::*;
    use crate::seal::{Binding, Context, Member, MemberKind, MemberList, ProxyKey, open, seal};

    const BOUNDED: Bounds = Bounds {
        mode: Some(Mode::User),
        breadth: Some(Breadth::Full),
    };

    /// The authority every test connects to unless it says otherwise.
    const API: Authority<u8> = Authority { host: 1, port: 443 };

    /// The facts after attribution, set so that every later check passes.
    fn rest<B>() -> Redemption<B, u8> {
        Redemption {
            unsealed: Unsealed::Undecryptable,
            attribution: Attribution::NoLiveBox,
            named_box_in_cohort: false,
            now: 1_500,
            revoked: Vec::new(),
            authority: API,
            bound_set: vec![API],
            current_set: vec![API],
        }
    }

    /// An opened value for `named`, sent from `named`, that passes the
    /// source and bounds checks.
    fn own(named: u8) -> Redemption<u8, u8> {
        Redemption {
            unsealed: Unsealed::Opened {
                box_id: named,
                bounds: BOUNDED,
                expiry: 2_000,
            },
            attribution: Attribution::OwnIp(named),
            ..rest()
        }
    }

    const ADMITTED: Decision = Decision::Admit {
        attributed: Attributed::OwnBox,
        mode: Mode::User,
        breadth: Breadth::Full,
    };

    fn any_authority() -> impl Strategy<Value = Authority<u8>> {
        (0u8..4, prop::sample::select(vec![443u16, 8443, 80]))
            .prop_map(|(host, port)| Authority { host, port })
    }

    fn key(bytes: [u8; 32]) -> Option<ProxyKey> {
        ProxyKey::from_bytes(&bytes)
    }

    fn sealed_to(key: &ProxyKey, box_id: &str, host: &str, mode: Mode) -> String {
        let context = Context {
            box_id: box_id.into(),
            host: host.into(),
            module: "github".into(),
            host_set_version: 1,
            mode,
            iat: 1_000,
            expiry: 2_000,
            kid: key.public().kid(),
        };
        let members = MemberList {
            members: vec![Member {
                kind: MemberKind::SignIn,
                breadth: Breadth::Full,
                jws: Zeroizing::new("h.p.s".into()),
                exp: None,
            }],
            default_owner: None,
        };
        seal(&key.public(), &context, &members).expect("seal")
    }

    fn mode_of(user: bool) -> Mode {
        if user { Mode::User } else { Mode::Installation }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// BEP-019: a value redeems only under the key it was sealed to. A
        /// value sealed to any other host's key is refused as undecryptable.
        #[test]
        fn prop_off_host_sealed_value_is_refused(
            sealer in any::<[u8; 32]>(),
            host_key in any::<[u8; 32]>(),
            box_id in "[a-z0-9]{1,12}",
            user in any::<bool>(),
        ) {
            let (Some(sealer), Some(host_key)) = (key(sealer), key(host_key)) else {
                return Ok(());
            };
            let sealed = sealed_to(&sealer, &box_id, "host-a", mode_of(user));
            let binding = Binding {
                box_id: box_id.clone(),
                host: "host-a".into(),
                module: "github".into(),
                now: 1_500,
            };
            let same_key = sealer.public().kid() == host_key.public().kid();
            let unsealed = Unsealed::from_open(open(&host_key, &sealed, &binding))
                .expect("a decryption fact");
            let decision = decide(&Redemption {
                unsealed,
                attribution: Attribution::OwnIp(box_id.clone()),
                named_box_in_cohort: false,
                ..rest()
            });
            if same_key {
                prop_assert!(matches!(decision, Decision::Admit { .. }), "admitted");
            } else {
                prop_assert_eq!(decision, Decision::Refuse(Check::Undecryptable));
            }

            // The key it was sealed to always admits it.
            let own = Unsealed::from_open(open(&sealer, &sealed, &binding))
                .expect("a decryption fact");
            prop_assert_eq!(
                decide(&Redemption {
                    unsealed: own,
                    attribution: Attribution::OwnIp(box_id),
                    named_box_in_cohort: false,
                    ..rest()
                }),
                Decision::Admit {
                    attributed: Attributed::OwnBox,
                    mode: mode_of(user),
                    breadth: Breadth::Full,
                }
            );
        }

        /// BEP-020: a value redeems only from the box it names, or from the
        /// `host_ip` cohort when the named box is in it.
        #[test]
        fn prop_cross_box_sealed_value_is_refused(
            named in any::<u8>(),
            sender in any::<u8>(),
            source in 0u8..3,
            in_cohort in any::<bool>(),
        ) {
            let attribution = match source {
                0 => Attribution::NoLiveBox,
                1 => Attribution::OwnIp(sender),
                _ => Attribution::HostIpCohort,
            };
            let decision = decide(&Redemption {
                unsealed: Unsealed::Opened { box_id: named, bounds: BOUNDED, expiry: 2_000 },
                attribution: attribution.clone(),
                named_box_in_cohort: in_cohort,
                ..rest()
            });
            let expected = match attribution {
                Attribution::NoLiveBox => Err(Check::NoLiveBox),
                Attribution::OwnIp(s) if s == named => Ok(Attributed::OwnBox),
                Attribution::HostIpCohort if in_cohort => Ok(Attributed::Cohort),
                _ => Err(Check::CrossBox),
            };
            match expected {
                Ok(attributed) => prop_assert_eq!(decision, Decision::Admit {
                    attributed,
                    mode: Mode::User,
                    breadth: Breadth::Full,
                }),
                Err(check) => prop_assert_eq!(decision, Decision::Refuse(check)),
            }
        }

        /// BEP-058: a member redeems only with a mode and a recognised
        /// breadth, whatever its attribution.
        #[test]
        fn prop_member_without_bounds_is_refused(
            mode in prop::option::of(any::<bool>().prop_map(mode_of)),
            breadth in any::<bool>(),
            named in any::<u8>(),
        ) {
            let bounds = Bounds { mode, breadth: breadth.then_some(Breadth::Full) };
            let decision = decide(&Redemption {
                unsealed: Unsealed::Opened { box_id: named, bounds, expiry: 2_000 },
                attribution: Attribution::OwnIp(named),
                named_box_in_cohort: false,
                ..rest()
            });
            match (bounds.mode, bounds.breadth) {
                (Some(mode), Some(breadth)) => prop_assert_eq!(decision, Decision::Admit {
                    attributed: Attributed::OwnBox,
                    mode,
                    breadth,
                }),
                _ => prop_assert_eq!(decision, Decision::Refuse(Check::UnboundedMember)),
            }
        }

        /// BEP-021: a value redeems only when the connection authority is in
        /// the value's bound host set and in the module's current host set.
        #[test]
        fn prop_authority_outside_bound_or_current_set_is_refused(
            bound in prop::collection::vec(any_authority(), 0..=4),
            current in prop::collection::vec(any_authority(), 0..=4),
            authority in any_authority(),
            named in any::<u8>(),
        ) {
            let decision = decide(&Redemption {
                authority,
                bound_set: bound.clone(),
                current_set: current.clone(),
                ..own(named)
            });
            let in_bound = bound.contains(&authority);
            let in_current = current.contains(&authority);
            let credentialed = current.iter().any(|a| a.host == authority.host);
            let expected = if credentialed && !in_current {
                Decision::Refuse(Check::OffPort)
            } else if !in_bound {
                Decision::Refuse(Check::OutsideBoundSet)
            } else if !in_current {
                Decision::Refuse(Check::OutsideCurrentSet)
            } else {
                ADMITTED
            };
            prop_assert_eq!(decision, expected);
            prop_assert_eq!(matches!(decision, Decision::Admit { .. }), in_bound && in_current);
        }

        /// BEP-024: a value redeems only before its expiry, and only when no
        /// revocation in force names its box.
        #[test]
        fn prop_expired_or_revoked_value_is_refused(
            now in 0u64..4_000,
            expiry in 0u64..4_000,
            revoked in prop::collection::vec(0u8..4, 0..=3),
            named in 0u8..4,
        ) {
            let decision = decide(&Redemption {
                unsealed: Unsealed::Opened { box_id: named, bounds: BOUNDED, expiry },
                now,
                revoked: revoked.clone(),
                ..own(named)
            });
            let expected = if now >= expiry {
                Decision::Refuse(Check::Expired)
            } else if revoked.contains(&named) {
                Decision::Refuse(Check::Revoked)
            } else {
                ADMITTED
            };
            prop_assert_eq!(decision, expected);

            // A value that open refuses as expired is refused as expired
            // from its own box, whatever the revocations.
            prop_assert_eq!(
                decide(&Redemption {
                    unsealed: Unsealed::Expired,
                    revoked,
                    ..own(named)
                }),
                Decision::Refuse(Check::Expired)
            );
        }

        /// BEP-031: a connection to a credentialed hostname is admitted only
        /// on a port that the module's current host set declares for it.
        #[test]
        fn prop_off_port_connection_is_refused(
            current in prop::collection::vec(any_authority(), 1..=4),
            pick in any::<prop::sample::Index>(),
            port in any::<u16>(),
            named in any::<u8>(),
        ) {
            let host = pick.get(&current).host;
            let authority = Authority { host, port };
            let decision = decide(&Redemption {
                authority,
                bound_set: current.clone(),
                current_set: current.clone(),
                ..own(named)
            });
            if current.contains(&authority) {
                prop_assert_eq!(decision, ADMITTED);
            } else {
                prop_assert_eq!(decision, Decision::Refuse(Check::OffPort));
            }
        }
    }

    /// BEP-024: `seal::open` refuses a value past its expiry as `Expired`.
    /// The shell maps that to `Expired`, and the refusal names `expired`.
    /// An open value carries the earlier of its own and its member's expiry.
    #[test]
    fn from_open_expired_is_refused_as_expired() {
        let Some(key) = key([5; 32]) else {
            panic!("a valid key");
        };
        let sealed = sealed_to(&key, "box-a", "host-a", Mode::User);
        let at = |now| Binding {
            box_id: "box-a".into(),
            host: "host-a".into(),
            module: "github".into(),
            now,
        };
        let late = Unsealed::from_open(open(&key, &sealed, &at(2_000))).expect("a decryption fact");
        assert_eq!(late, Unsealed::Expired);
        let decision = decide(&Redemption {
            unsealed: late,
            attribution: Attribution::OwnIp("box-a".to_owned()),
            ..rest()
        });
        assert_eq!(decision, Decision::Refuse(Check::Expired));
        assert_eq!(Check::Expired.marker(), "expired");

        let early =
            Unsealed::from_open(open(&key, &sealed, &at(1_500))).expect("a decryption fact");
        let Unsealed::Opened { expiry, .. } = early else {
            panic!("an opened value");
        };
        assert_eq!(expiry, 2_000);
    }

    /// BEP-058: `seal::open` refuses a member with a missing or unknown
    /// breadth as `UnknownBreadth`, after it decrypts. The shell maps that to
    /// `Unbounded`, and the refusal names `unbounded_member`, from every
    /// source.
    #[test]
    fn from_open_unknown_breadth_is_refused_as_unbounded_member() {
        let unsealed =
            Unsealed::from_open(Err(OpenError::UnknownBreadth)).expect("a decryption fact");
        assert_eq!(unsealed, Unsealed::Unbounded);
        for attribution in [
            Attribution::NoLiveBox,
            Attribution::OwnIp("a".to_owned()),
            Attribution::HostIpCohort,
        ] {
            let decision = decide(&Redemption {
                unsealed: unsealed.clone(),
                attribution,
                named_box_in_cohort: true,
                ..rest()
            });
            assert_eq!(decision, Decision::Refuse(Check::UnboundedMember));
            let Decision::Refuse(check) = decision else {
                unreachable!()
            };
            assert_eq!(check.marker(), "unbounded_member");
        }
    }

    /// BEP-020: `seal::open` refuses a value from another `own_ip` box as
    /// `ContextMismatch(BoxId)`, after it decrypts. The shell maps that to
    /// `OtherBox`, and the refusal names `cross_box`.
    #[test]
    fn from_open_other_box_is_refused_as_cross_box() {
        let Some(key) = key([7; 32]) else {
            panic!("a valid key");
        };
        let sealed = sealed_to(&key, "box-a", "host-a", Mode::User);
        let binding = Binding {
            box_id: "box-b".into(),
            host: "host-a".into(),
            module: "github".into(),
            now: 1_500,
        };
        let unsealed =
            Unsealed::from_open(open(&key, &sealed, &binding)).expect("a decryption fact");
        assert_eq!(unsealed, Unsealed::OtherBox);
        for (attribution, check) in [
            (Attribution::NoLiveBox, Check::NoLiveBox),
            (Attribution::OwnIp("box-b".to_owned()), Check::CrossBox),
            (Attribution::HostIpCohort, Check::CrossBox),
        ] {
            let decision = decide(&Redemption {
                unsealed: unsealed.clone(),
                attribution,
                named_box_in_cohort: true,
                ..rest()
            });
            assert_eq!(decision, Decision::Refuse(check));
        }
        assert_eq!(Check::CrossBox.marker(), "cross_box");
    }

    /// BEP-020, BEP-028: a cohort source names no single box, so the shell
    /// binds the open to each live cohort box in turn. The value opens for
    /// the box it names, and the decision admits it as `Cohort`. Bound to
    /// another cohort box, it is `OtherBox`, refused as `cross_box`.
    #[test]
    fn cohort_open_bound_to_named_box_is_admitted_as_cohort() {
        let Some(key) = key([9; 32]) else {
            panic!("a valid key");
        };
        let sealed = sealed_to(&key, "box-a", "host-a", Mode::User);
        let bind = |box_id: &str| Binding {
            box_id: box_id.into(),
            host: "host-a".into(),
            module: "github".into(),
            now: 1_500,
        };
        let mut admitted = None;
        for live in ["box-b", "box-a"] {
            let unsealed =
                Unsealed::from_open(open(&key, &sealed, &bind(live))).expect("a decryption fact");
            if unsealed == Unsealed::OtherBox {
                let decision = decide(&Redemption {
                    unsealed,
                    attribution: Attribution::HostIpCohort,
                    named_box_in_cohort: true,
                    ..rest()
                });
                assert_eq!(decision, Decision::Refuse(Check::CrossBox));
                continue;
            }
            admitted = Some(decide(&Redemption {
                unsealed,
                attribution: Attribution::HostIpCohort,
                named_box_in_cohort: true,
                ..rest()
            }));
            break;
        }
        assert_eq!(
            admitted,
            Some(Decision::Admit {
                attributed: Attributed::Cohort,
                mode: Mode::User,
                breadth: Breadth::Full,
            })
        );
    }

    /// An unsupported header is not a value sealed to another key, so the
    /// shell gets the error back and the marker never says `undecryptable`.
    #[test]
    fn from_open_unsupported_comes_back_unchanged() {
        assert_eq!(
            Unsealed::<String>::from_open(Err(OpenError::Unsupported)),
            Err(OpenError::Unsupported)
        );
        assert_eq!(
            Unsealed::<String>::from_open(Err(OpenError::NotOpenable)),
            Ok(Unsealed::Undecryptable)
        );
    }

    #[test]
    fn markers_name_each_check() {
        let markers = [
            Check::Undecryptable,
            Check::UnboundedMember,
            Check::NoLiveBox,
            Check::CrossBox,
            Check::Expired,
            Check::Revoked,
            Check::OffPort,
            Check::OutsideBoundSet,
            Check::OutsideCurrentSet,
        ]
        .map(Check::marker);
        assert_eq!(
            markers,
            [
                "undecryptable",
                "unbounded_member",
                "no_live_box",
                "cross_box",
                "expired",
                "revoked",
                "off_port",
                "outside_bound_set",
                "outside_current_set",
            ]
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Attribution, Authority, Bounds, Check, Decision, Redemption, Unsealed, decide};
    use crate::seal::{Breadth, Mode};

    fn any_mode() -> Option<Mode> {
        match kani::any::<u8>() % 3 {
            0 => None,
            1 => Some(Mode::User),
            _ => Some(Mode::Installation),
        }
    }

    fn any_bounds() -> Bounds {
        Bounds {
            mode: any_mode(),
            breadth: if kani::any() {
                Some(Breadth::Full)
            } else {
                None
            },
        }
    }

    fn any_unsealed() -> Unsealed<u8> {
        match kani::any::<u8>() % 5 {
            0 => Unsealed::Undecryptable,
            1 => Unsealed::Unbounded,
            2 => Unsealed::OtherBox,
            3 => Unsealed::Expired,
            _ => Unsealed::Opened {
                box_id: kani::any(),
                bounds: any_bounds(),
                expiry: kani::any(),
            },
        }
    }

    /// An authority, with the host interned as a `u8` id.
    fn any_authority() -> Authority<u8> {
        Authority {
            host: kani::any(),
            port: kani::any(),
        }
    }

    /// A host set of at most four authorities.
    fn any_set() -> Vec<Authority<u8>> {
        let len = kani::any::<u8>() % 5;
        let mut set = Vec::with_capacity(4);
        for _ in 0..len {
            set.push(any_authority());
        }
        set
    }

    /// The box ids of at most two revocations in force.
    fn any_revoked() -> Vec<u8> {
        let len = kani::any::<u8>() % 3;
        let mut revoked = Vec::with_capacity(2);
        for _ in 0..len {
            revoked.push(kani::any());
        }
        revoked
    }

    fn any_attribution() -> Attribution<u8> {
        match kani::any::<u8>() % 3 {
            0 => Attribution::NoLiveBox,
            1 => Attribution::OwnIp(kani::any()),
            _ => Attribution::HostIpCohort,
        }
    }

    fn any_redemption() -> Redemption<u8, u8> {
        Redemption {
            unsealed: any_unsealed(),
            attribution: any_attribution(),
            named_box_in_cohort: kani::any(),
            now: kani::any(),
            revoked: any_revoked(),
            authority: any_authority(),
            bound_set: any_set(),
            current_set: any_set(),
        }
    }

    /// BEP-019: a value that does not decrypt is never admitted.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_refuses_undecryptable() {
        let r = any_redemption();
        let decision = decide(&r);
        if matches!(r.unsealed, Unsealed::Undecryptable) {
            assert_eq!(decision, Decision::Refuse(Check::Undecryptable));
        }
        if matches!(decision, Decision::Admit { .. }) {
            assert!(matches!(r.unsealed, Unsealed::Opened { .. }));
        }
    }

    /// BEP-020: an admission comes only from the named `own_ip` box, or
    /// from the `host_ip` cohort when the named box is in it.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_refuses_misattributed() {
        let r = any_redemption();
        let decision = decide(&r);
        if matches!(r.unsealed, Unsealed::OtherBox) {
            let check = if matches!(r.attribution, Attribution::NoLiveBox) {
                Check::NoLiveBox
            } else {
                Check::CrossBox
            };
            assert_eq!(decision, Decision::Refuse(check));
        }
        if let Decision::Admit { .. } = decision {
            let Unsealed::Opened { box_id, .. } = r.unsealed else {
                panic!("admitted an undecryptable value");
            };
            match r.attribution {
                Attribution::NoLiveBox => panic!("admitted from no live box"),
                Attribution::OwnIp(sender) => assert_eq!(sender, box_id),
                Attribution::HostIpCohort => assert!(r.named_box_in_cohort),
            }
        }
    }

    /// BEP-058: an admission always has a mode and a recognised breadth.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_refuses_unbounded_member() {
        let r = any_redemption();
        let decision = decide(&r);
        match r.unsealed {
            Unsealed::Unbounded => {
                assert_eq!(decision, Decision::Refuse(Check::UnboundedMember));
            }
            Unsealed::Opened { bounds, .. }
                if bounds.mode.is_none() || bounds.breadth.is_none() =>
            {
                assert_eq!(decision, Decision::Refuse(Check::UnboundedMember));
            }
            _ => {}
        }
    }

    /// BEP-021: an admission has the connection authority in the bound set
    /// and in the current set.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_requires_authority_in_both_sets() {
        let r = any_redemption();
        let decision = decide(&r);
        if matches!(decision, Decision::Admit { .. }) {
            assert!(r.bound_set.contains(&r.authority));
            assert!(r.current_set.contains(&r.authority));
        }
        if decision == Decision::Refuse(Check::OutsideBoundSet) {
            assert!(!r.bound_set.contains(&r.authority));
        }
        if decision == Decision::Refuse(Check::OutsideCurrentSet) {
            assert!(!r.current_set.contains(&r.authority));
        }
    }

    /// BEP-024: an admission has the clock before the value's expiry, and
    /// no revocation in force names the value's box.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_refuses_expired_or_revoked() {
        let r = any_redemption();
        let decision = decide(&r);
        if matches!(decision, Decision::Admit { .. }) {
            let Unsealed::Opened { box_id, expiry, .. } = r.unsealed else {
                panic!("admitted a value that did not open");
            };
            assert!(r.now < expiry);
            assert!(!r.revoked.contains(&box_id));
        }
        if decision == Decision::Refuse(Check::Expired) {
            match r.unsealed {
                Unsealed::Expired => {}
                Unsealed::Opened { expiry, .. } => assert!(r.now >= expiry),
                _ => panic!("refused as expired with no expiry"),
            }
        }
        if decision == Decision::Refuse(Check::Revoked) {
            let Unsealed::Opened { box_id, .. } = r.unsealed else {
                panic!("refused as revoked with no box id");
            };
            assert!(r.revoked.contains(&box_id));
        }
    }

    /// BEP-031: an admission has the connection's `host:port` declared in
    /// the current set, and a credentialed hostname on another port is
    /// never admitted.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_enforces_port_discipline() {
        let r = any_redemption();
        let decision = decide(&r);
        let credentialed = r.current_set.iter().any(|a| a.host == r.authority.host);
        let declared = r.current_set.contains(&r.authority);
        if matches!(decision, Decision::Admit { .. }) {
            assert!(declared);
        }
        if decision == Decision::Refuse(Check::OffPort) {
            assert!(credentialed && !declared);
        }
    }
}
