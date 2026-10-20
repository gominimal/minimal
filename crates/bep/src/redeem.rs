//! The redemption decision (BEP-019 to BEP-025, BEP-031, BEP-058).
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
//! 4. The sending box's declared egress admits the connection authority
//!    (BEP-022).
//! 5. The clock is before the value's expiry (BEP-024). A value that
//!    [`crate::seal::open`] refuses as past its expiry is
//!    [`Unsealed::Expired`], and this check refuses it too.
//! 6. No revocation in force covers the value's box id (BEP-024, BEP-071).
//! 7. The connection's port is a declared port of the module's current host
//!    set for that hostname (BEP-031). A hostname outside the current set is
//!    not credentialed, so check 9 refuses it.
//! 8. The connection authority is in the value's bound host set (BEP-021).
//! 9. The connection authority is in the module's current host set
//!    (BEP-021).
//! 10. The request's `Host` header, and the authority of an absolute-form
//!     request target, equal the connection authority (BEP-023).
//!
//! [`decide`] admits only when every check passes (BEP-025). The shell then
//! substitutes the member's credential and forwards the request to the
//! connection authority. A request that carries no sealed value goes to
//! [`decide_plain`], which makes checks 4 and 10 alone. So the egress and
//! request-authority checks hold whether or not a request carries a value.

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
    /// once the attribution and the declared egress pass.
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
    /// The request's `Host` header and request target.
    pub request: RequestAuthority<H>,
    /// The authorities the sending box's declared egress admits (BEP-022).
    pub egress: Vec<Authority<H>>,
}

/// The authorities a request names, beside the one it arrived on (BEP-023).
///
/// An authority written with no port is port 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestAuthority<H> {
    /// The `Host` header, or the HTTP/2 `:authority`. `None` when the
    /// request carries neither, which never equals the connection authority.
    pub host: Option<Authority<H>>,
    /// The authority of an absolute-form request target. `None` for an
    /// origin-form target, which names the connection authority itself.
    pub target: Option<Authority<H>>,
}

impl<H: PartialEq> RequestAuthority<H> {
    /// Whether the request names only `connection`.
    fn pins(&self, connection: &Authority<H>) -> bool {
        self.host.as_ref() == Some(connection)
            && self.target.as_ref().is_none_or(|t| t == connection)
    }
}

/// One request that carries no sealed value, as the shell sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plain<H> {
    /// The authority the connection arrived on.
    pub authority: Authority<H>,
    /// The request's `Host` header and request target.
    pub request: RequestAuthority<H>,
    /// The authorities the sending box's declared egress admits (BEP-022).
    pub egress: Vec<Authority<H>>,
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
    /// The sending box's declared egress does not admit the authority
    /// (BEP-022).
    OutsideDeclaredEgress,
    /// The `Host` header or the request target names an authority other
    /// than the connection authority (BEP-023).
    HostMismatch,
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
            Self::OutsideDeclaredEgress => "outside_declared_egress",
            Self::HostMismatch => "host_mismatch",
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
        // bound to the box the source resolves to, so only the source or the
        // declared egress (BEP-022) can fail first.
        Unsealed::Expired => {
            return Decision::Refuse(match redemption.attribution {
                Attribution::NoLiveBox => Check::NoLiveBox,
                Attribution::HostIpCohort if !redemption.named_box_in_cohort => Check::CrossBox,
                Attribution::OwnIp(_) | Attribution::HostIpCohort
                    if !redemption.egress.contains(&redemption.authority) =>
                {
                    Check::OutsideDeclaredEgress
                }
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
    // BEP-022: the box reaches only what its declared egress admits.
    let authority = &redemption.authority;
    if !redemption.egress.contains(authority) {
        return Decision::Refuse(Check::OutsideDeclaredEgress);
    }
    // BEP-024: only a value before its expiry, and not revoked, is redeemed.
    if redemption.now >= expiry {
        return Decision::Refuse(Check::Expired);
    }
    if redemption.revoked.contains(box_id) {
        return Decision::Refuse(Check::Revoked);
    }
    // BEP-031: a credentialed hostname is reached only on a declared port.
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
    // BEP-023: the request names only the authority it arrived on.
    if !redemption.request.pins(authority) {
        return Decision::Refuse(Check::HostMismatch);
    }
    // BEP-025: every check passed.
    Decision::Admit {
        attributed,
        mode,
        breadth,
    }
}

/// Decides one request that carries no sealed value. Pure: the result
/// depends only on `plain`. The shell forwards the request with no
/// substitution on `Ok`.
///
/// # Errors
///
/// The first check that failed: [`Check::OutsideDeclaredEgress`] or
/// [`Check::HostMismatch`].
pub fn decide_plain<H: PartialEq>(plain: &Plain<H>) -> Result<(), Check> {
    request_check(&plain.authority, &plain.request, &plain.egress).map_or(Ok(()), Err)
}

/// The checks a request passes with or without a sealed value, in order.
fn request_check<H: PartialEq>(
    authority: &Authority<H>,
    request: &RequestAuthority<H>,
    egress: &[Authority<H>],
) -> Option<Check> {
    // BEP-022: the box reaches only what its declared egress admits.
    if !egress.contains(authority) {
        return Some(Check::OutsideDeclaredEgress);
    }
    // BEP-023: the request names only the authority it arrived on.
    if !request.pins(authority) {
        return Some(Check::HostMismatch);
    }
    None
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
            request: PINNED,
            egress: vec![API],
        }
    }

    /// An origin-form request whose `Host` header is the connection's.
    const PINNED: RequestAuthority<u8> = RequestAuthority {
        host: Some(API),
        target: None,
    };

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

    /// An origin-form request to `authority`.
    fn pinned(authority: Authority<u8>) -> RequestAuthority<u8> {
        RequestAuthority {
            host: Some(authority),
            target: None,
        }
    }

    /// `redemption`, sent to `authority` with a pinned request, from a box
    /// whose declared egress admits `authority`.
    fn reached(authority: Authority<u8>, redemption: Redemption<u8, u8>) -> Redemption<u8, u8> {
        Redemption {
            authority,
            request: pinned(authority),
            egress: vec![authority],
            ..redemption
        }
    }

    fn any_request() -> impl Strategy<Value = RequestAuthority<u8>> {
        (
            prop::option::of(any_authority()),
            prop::option::of(any_authority()),
        )
            .prop_map(|(host, target)| RequestAuthority { host, target })
    }

    fn any_unsealed() -> impl Strategy<Value = Unsealed<u8>> {
        prop_oneof![
            Just(Unsealed::Undecryptable),
            Just(Unsealed::Unbounded),
            Just(Unsealed::OtherBox),
            Just(Unsealed::Expired),
            (
                0u8..3,
                prop::option::of(any::<bool>().prop_map(mode_of)),
                any::<bool>(),
                0u64..4_000,
            )
                .prop_map(|(box_id, mode, breadth, expiry)| Unsealed::Opened {
                    box_id,
                    bounds: Bounds {
                        mode,
                        breadth: breadth.then_some(Breadth::Full),
                    },
                    expiry,
                }),
        ]
    }

    fn any_redemption() -> impl Strategy<Value = Redemption<u8, u8>> {
        (
            any_unsealed(),
            (0u8..3, 0u8..3).prop_map(|(source, sender)| match source {
                0 => Attribution::NoLiveBox,
                1 => Attribution::OwnIp(sender),
                _ => Attribution::HostIpCohort,
            }),
            any::<bool>(),
            0u64..4_000,
            prop::collection::vec(0u8..3, 0..=2),
            any_authority(),
            (
                prop::collection::vec(any_authority(), 0..=4),
                prop::collection::vec(any_authority(), 0..=4),
                prop::collection::vec(any_authority(), 0..=4),
            ),
            any_request(),
        )
            .prop_map(
                |(
                    unsealed,
                    attribution,
                    named_box_in_cohort,
                    now,
                    revoked,
                    authority,
                    (bound_set, current_set, egress),
                    request,
                )| Redemption {
                    unsealed,
                    attribution,
                    named_box_in_cohort,
                    now,
                    revoked,
                    authority,
                    bound_set,
                    current_set,
                    request,
                    egress,
                },
            )
    }

    /// The checks of BEP-019 to BEP-024, BEP-031 and BEP-058, written out
    /// one by one in their order, apart from [`decide`]. Each entry is a
    /// check and whether it fails.
    fn failures(r: &Redemption<u8, u8>) -> Vec<(Check, bool)> {
        let a = r.authority;
        let (opened, box_id, bounded, expiry) = match &r.unsealed {
            Unsealed::Opened {
                box_id,
                bounds,
                expiry,
            } => (
                true,
                Some(*box_id),
                bounds.mode.is_some() && bounds.breadth.is_some(),
                Some(*expiry),
            ),
            Unsealed::Undecryptable | Unsealed::Unbounded => (false, None, false, None),
            Unsealed::OtherBox | Unsealed::Expired => (false, None, true, None),
        };
        let attributed = match &r.attribution {
            Attribution::NoLiveBox => false,
            Attribution::OwnIp(sender) => {
                opened && Some(*sender) == box_id || matches!(r.unsealed, Unsealed::Expired)
            }
            Attribution::HostIpCohort => {
                r.named_box_in_cohort && !matches!(r.unsealed, Unsealed::OtherBox)
            }
        };
        let credentialed = r.current_set.iter().any(|c| c.host == a.host);
        let host_pinned = r.request.host == Some(a);
        let target_pinned = r.request.target.is_none() || r.request.target == Some(a);
        vec![
            (
                Check::Undecryptable,
                matches!(r.unsealed, Unsealed::Undecryptable),
            ),
            (Check::UnboundedMember, !bounded),
            (
                Check::NoLiveBox,
                matches!(r.attribution, Attribution::NoLiveBox),
            ),
            (Check::CrossBox, !attributed),
            (Check::OutsideDeclaredEgress, !r.egress.contains(&a)),
            (
                Check::Expired,
                matches!(r.unsealed, Unsealed::Expired) || expiry.is_some_and(|e| r.now >= e),
            ),
            (
                Check::Revoked,
                box_id.is_some_and(|b| r.revoked.contains(&b)),
            ),
            (Check::OffPort, credentialed && !r.current_set.contains(&a)),
            (Check::OutsideBoundSet, !r.bound_set.contains(&a)),
            (Check::OutsideCurrentSet, !r.current_set.contains(&a)),
            (Check::HostMismatch, !(host_pinned && target_pinned)),
        ]
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
                ..reached(authority, own(named))
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
                ..reached(authority, own(named))
            });
            if current.contains(&authority) {
                prop_assert_eq!(decision, ADMITTED);
            } else {
                prop_assert_eq!(decision, Decision::Refuse(Check::OffPort));
            }
        }

        /// BEP-022: a request is admitted only when the sending box's
        /// declared egress admits its authority, whether or not it carries
        /// a sealed value.
        #[test]
        fn prop_undeclared_egress_authority_is_refused(
            egress in prop::collection::vec(any_authority(), 0..=4),
            authority in any_authority(),
            named in any::<u8>(),
            other in any_redemption(),
        ) {
            let declared = egress.contains(&authority);

            // With a sealed value that passes every other check.
            let decision = decide(&Redemption {
                bound_set: vec![authority],
                current_set: vec![authority],
                egress: egress.clone(),
                ..reached(authority, own(named))
            });
            if declared {
                prop_assert_eq!(decision, ADMITTED);
            } else {
                prop_assert_eq!(decision, Decision::Refuse(Check::OutsideDeclaredEgress));
            }

            // With no sealed value.
            let plain = decide_plain(&Plain {
                authority,
                request: pinned(authority),
                egress: egress.clone(),
            });
            if declared {
                prop_assert_eq!(plain, Ok(()));
            } else {
                prop_assert_eq!(plain, Err(Check::OutsideDeclaredEgress));
            }

            // With any other facts, an admission has a declared authority.
            let reach = other.authority;
            let any = decide(&Redemption { egress: egress.clone(), ..other });
            if matches!(any, Decision::Admit { .. }) {
                prop_assert!(egress.contains(&reach));
            }
        }

        /// BEP-023: a request is admitted, and its value substituted, only
        /// when its `Host` header and its request target name the
        /// connection authority. An origin-form target names it.
        #[test]
        fn prop_host_header_mismatch_is_refused(
            authority in any_authority(),
            request in any_request(),
            named in any::<u8>(),
        ) {
            let pinned_request = request.host == Some(authority)
                && request.target.is_none_or(|t| t == authority);

            let decision = decide(&Redemption {
                request,
                ..reached(authority, Redemption {
                    bound_set: vec![authority],
                    current_set: vec![authority],
                    ..own(named)
                })
            });
            if pinned_request {
                prop_assert_eq!(decision, ADMITTED);
            } else {
                prop_assert_eq!(decision, Decision::Refuse(Check::HostMismatch));
            }

            let plain = decide_plain(&Plain {
                authority,
                request,
                egress: vec![authority],
            });
            if pinned_request {
                prop_assert_eq!(plain, Ok(()));
            } else {
                prop_assert_eq!(plain, Err(Check::HostMismatch));
            }
        }

        /// BEP-025: the decision admits exactly when every check passes,
        /// and otherwise refuses naming the first check that fails.
        #[test]
        fn prop_admit_iff_every_check_passes(r in any_redemption()) {
            admits_iff_every_check_passes(&r)?;

            // The same facts, with every authority check passing, so the
            // earlier checks decide alone.
            let a = r.authority;
            let mut reaching = reached(a, r);
            reaching.bound_set.push(a);
            reaching.current_set.push(a);
            admits_iff_every_check_passes(&reaching)?;

            // And sent from the box the value names, so an opened value
            // reaches the expiry, revocation and bounds checks.
            if let Unsealed::Opened { box_id, .. } = reaching.unsealed {
                reaching.attribution = Attribution::OwnIp(box_id);
                admits_iff_every_check_passes(&reaching)?;
            }
        }
    }

    /// The decision is `Admit` when no check in [`failures`] fails, and
    /// otherwise `Refuse` naming the first check that fails.
    fn admits_iff_every_check_passes(r: &Redemption<u8, u8>) -> Result<(), TestCaseError> {
        let first = failures(r).into_iter().find(|(_, failed)| *failed);
        let decision = decide(r);
        match first {
            Some((check, _)) => prop_assert_eq!(decision, Decision::Refuse(check)),
            None => {
                let Unsealed::Opened { bounds, .. } = r.unsealed else {
                    panic!("every check passed for a value that did not open");
                };
                let attributed = if matches!(r.attribution, Attribution::OwnIp(_)) {
                    Attributed::OwnBox
                } else {
                    Attributed::Cohort
                };
                prop_assert_eq!(
                    decision,
                    Decision::Admit {
                        attributed,
                        mode: bounds.mode.expect("a mode"),
                        breadth: bounds.breadth.expect("a breadth"),
                    }
                );
            }
        }
        Ok(())
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
            Check::OutsideDeclaredEgress,
            Check::HostMismatch,
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
                "outside_declared_egress",
                "host_mismatch",
            ]
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{
        Attribution, Authority, Bounds, Check, Decision, Plain, Redemption, RequestAuthority,
        Unsealed, decide, decide_plain,
    };
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

    fn any_option_authority() -> Option<Authority<u8>> {
        if kani::any() {
            Some(any_authority())
        } else {
            None
        }
    }

    fn any_request() -> RequestAuthority<u8> {
        RequestAuthority {
            host: any_option_authority(),
            target: any_option_authority(),
        }
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
            request: any_request(),
            egress: any_set(),
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

    /// BEP-022: an admission, with or without a sealed value, has the
    /// connection authority in the box's declared egress.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_requires_egress_admission() {
        let r = any_redemption();
        let decision = decide(&r);
        if matches!(decision, Decision::Admit { .. }) {
            assert!(r.egress.contains(&r.authority));
        }
        if decision == Decision::Refuse(Check::OutsideDeclaredEgress) {
            assert!(!r.egress.contains(&r.authority));
        }
        let plain = Plain {
            authority: r.authority,
            request: r.request,
            egress: r.egress,
        };
        match decide_plain(&plain) {
            Ok(()) => assert!(plain.egress.contains(&plain.authority)),
            Err(Check::OutsideDeclaredEgress) => {
                assert!(!plain.egress.contains(&plain.authority));
            }
            Err(check) => assert_eq!(check, Check::HostMismatch),
        }
    }

    /// BEP-023: an admission, with or without a sealed value, has the
    /// `Host` header and any absolute-form target equal to the connection
    /// authority.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_pins_request_authority() {
        let r = any_redemption();
        let pinned = r.request.host == Some(r.authority)
            && (r.request.target.is_none() || r.request.target == Some(r.authority));
        if matches!(decide(&r), Decision::Admit { .. }) {
            assert!(pinned);
        }
        let plain = Plain {
            authority: r.authority,
            request: r.request,
            egress: r.egress,
        };
        if decide_plain(&plain).is_ok() {
            assert!(pinned);
        }
    }

    /// BEP-025: the decision admits exactly when every check passes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_redeem_admits_iff_all_checks_pass() {
        let r = any_redemption();
        let decision = decide(&r);
        let a = r.authority;
        let all_pass = match r.unsealed {
            Unsealed::Opened {
                box_id,
                bounds,
                expiry,
            } => {
                let attributed = match r.attribution {
                    Attribution::NoLiveBox => false,
                    Attribution::OwnIp(sender) => sender == box_id,
                    Attribution::HostIpCohort => r.named_box_in_cohort,
                };
                bounds.mode.is_some()
                    && bounds.breadth.is_some()
                    && attributed
                    && r.now < expiry
                    && !r.revoked.contains(&box_id)
                    && r.bound_set.contains(&a)
                    && r.current_set.contains(&a)
                    && r.egress.contains(&a)
                    && r.request.host == Some(a)
                    && (r.request.target.is_none() || r.request.target == Some(a))
            }
            _ => false,
        };
        assert_eq!(matches!(decision, Decision::Admit { .. }), all_pass);
    }
}
