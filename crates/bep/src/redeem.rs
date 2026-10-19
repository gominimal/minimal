//! The redemption decision (BEP-019, BEP-020, BEP-058).
//!
//! The proxy decides whether to redeem a sealed value in one pure function,
//! [`decide`], over owned values. The TLS and socket shell does the I/O. It
//! opens the value with [`crate::seal::open`], resolves the connection's
//! source address to a box, and looks up the box the value names. It then
//! gives the facts to [`decide`] as a [`Redemption`]. [`decide`] reads no
//! clock, no socket and no key, so a property test and a Kani harness can
//! cover every input.
//!
//! The box ids are a type parameter. The shell uses the box id strings. A
//! Kani harness uses `u8` ids, so it can exhaust them.
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
//!
//! The other redemption checks (host sets, egress, request authority,
//! expiry and revocation) are not in this module yet.

use std::fmt;

use crate::seal::{Breadth, Mode, OpenError, Opened};

/// What the shell found when it opened the sealed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsealed<B> {
    /// The value does not decrypt under this host's proxy key. This includes
    /// a value sealed to another host's key.
    Undecryptable,
    /// The value decrypted.
    Opened {
        /// The box the value names.
        box_id: B,
        /// The member's bounds.
        bounds: Bounds,
    },
}

impl Unsealed<String> {
    /// Maps the result of [`crate::seal::open`] to the decryption fact.
    ///
    /// A value that opens gives [`Unsealed::Opened`]. A value sealed to
    /// another key, or one that does not decrypt, gives
    /// [`Unsealed::Undecryptable`].
    ///
    /// # Errors
    ///
    /// Every other [`OpenError`] comes back unchanged. Those refusals belong
    /// to checks this module does not make, and the shell refuses on them.
    pub fn from_open(result: Result<Opened, OpenError>) -> Result<Self, OpenError> {
        match result {
            Ok(opened) => Ok(Self::Opened {
                box_id: opened.context.box_id,
                bounds: Bounds {
                    mode: Some(opened.context.mode),
                    breadth: Some(opened.member.breadth),
                },
            }),
            Err(OpenError::NotOpenable | OpenError::Unsupported) => Ok(Self::Undecryptable),
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
    /// boxes. It does not say which one.
    HostIpCohort,
}

/// One redemption, as the shell sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption<B> {
    /// The decryption fact, with the named box and the member's bounds.
    pub unsealed: Unsealed<B>,
    /// The box the connection's source resolves to.
    pub attribution: Attribution<B>,
    /// Whether the box the value names is a live `host_ip` box of this host.
    pub named_box_in_cohort: bool,
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
pub fn decide<B: PartialEq>(redemption: &Redemption<B>) -> Decision {
    // BEP-019: only a value this host's key opens is redeemed.
    let Unsealed::Opened { box_id, bounds } = &redemption.unsealed else {
        return Decision::Refuse(Check::Undecryptable);
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
                unsealed: Unsealed::Opened { box_id: named, bounds: BOUNDED },
                attribution: attribution.clone(),
                named_box_in_cohort: in_cohort,
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
                unsealed: Unsealed::Opened { box_id: named, bounds },
                attribution: Attribution::OwnIp(named),
                named_box_in_cohort: false,
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
    }

    #[test]
    fn markers_name_each_check() {
        let markers = [
            Check::Undecryptable,
            Check::UnboundedMember,
            Check::NoLiveBox,
            Check::CrossBox,
        ]
        .map(Check::marker);
        assert_eq!(
            markers,
            [
                "undecryptable",
                "unbounded_member",
                "no_live_box",
                "cross_box"
            ]
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{Attribution, Bounds, Check, Decision, Redemption, Unsealed, decide};
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
        if kani::any() {
            Unsealed::Undecryptable
        } else {
            Unsealed::Opened {
                box_id: kani::any(),
                bounds: any_bounds(),
            }
        }
    }

    fn any_attribution() -> Attribution<u8> {
        match kani::any::<u8>() % 3 {
            0 => Attribution::NoLiveBox,
            1 => Attribution::OwnIp(kani::any()),
            _ => Attribution::HostIpCohort,
        }
    }

    fn any_redemption() -> Redemption<u8> {
        Redemption {
            unsealed: any_unsealed(),
            attribution: any_attribution(),
            named_box_in_cohort: kani::any(),
        }
    }

    /// BEP-019: a value that does not decrypt is never admitted.
    #[kani::proof]
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
    fn kani_redeem_refuses_misattributed() {
        let r = any_redemption();
        if let Decision::Admit { .. } = decide(&r) {
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
    fn kani_redeem_refuses_unbounded_member() {
        let r = any_redemption();
        let decision = decide(&r);
        if let Unsealed::Opened { bounds, .. } = r.unsealed {
            if bounds.mode.is_none() || bounds.breadth.is_none() {
                assert_eq!(decision, Decision::Refuse(Check::UnboundedMember));
            }
        }
    }
}
