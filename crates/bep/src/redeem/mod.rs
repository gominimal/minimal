//! The redemption decision: one pure function over owned values that admits a
//! request carrying a sealed value exactly when every check passes, and names
//! the first failing check otherwise (BEP-025).
//!
//! The shell around it (the listener, the key store, the attribution of a
//! source address to a box, the revocation set) establishes the facts and
//! interns every authority, box and module as a small id; the decision reads
//! the facts alone and touches no clock, socket or key. That separation is
//! what lets the property tests drive it over arbitrary inputs and the Kani
//! harnesses exhaust it over host sets of at most four authorities.
//!
//! - [`request`] holds the checks over the connection and the request, which
//!   hold whether or not a sealed value is carried and so run first: that the
//!   connection arrived on a `host:port` the module declares, that the sending
//!   box's declared egress admits the connection authority, and that the
//!   request's `Host` header and target name that authority itself.
//! - [`member`] holds the checks over the sealed member itself: that the
//!   value decrypted under this host's key, that the connection is attributed
//!   to a box the value may be redeemed from, that the connection authority is
//!   in the value's bound host set and in the module's current one, that the
//!   value is neither expired nor revoked, and that the member carries a mode
//!   and a recognised breadth.
//! - [`store`] holds the checks over a store handle carried as the member
//!   (BEP-064), which stand where the module member's host-set, mode and
//!   breadth checks stand: that the signature verified under a registered
//!   client key, that the handle's own expiry has not passed, that its
//!   `upstream` is within the rule currently registered for its store and
//!   identifier, and that its injection form is that rule's.

use std::fmt;

pub mod member;
pub mod request;
pub mod store;

pub use member::{Attribution, Breadth, Mode, Revocation, SealedMember};
pub use request::{Egress, Endpoint, HostId, Request};
pub use store::{BasicField, InjectId, StoreHandle, StoreRule};

/// An authority (`host:port`), interned by the shell as a small id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct AuthorityId(pub u8);

/// A box, interned by the shell as a small id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct BoxId(pub u8);

/// A module (`github`), interned by the shell as a small id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ModuleId(pub u8);

/// A module's host set: the authorities it declares, interned.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostSet(pub Vec<AuthorityId>);

impl HostSet {
    /// Whether `authority` is in the set.
    #[must_use]
    pub fn contains(&self, authority: AuthorityId) -> bool {
        self.0.contains(&authority)
    }

    /// Whether every authority in the set is in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|authority| other.contains(*authority))
    }
}

/// One redemption check, named as the audit record names it when it is the
/// first to fail. The variants are in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Check {
    /// The connection arrived on a `host:port` the module declares (BEP-031).
    OnDeclaredPort,
    /// The sending box's declared egress admits the connection authority
    /// (BEP-022).
    EgressAdmitted,
    /// The request's `Host` header and target name the connection authority
    /// itself (BEP-023).
    AuthorityPinned,
    /// The value decrypts under this host's proxy key (BEP-019).
    Decrypts,
    /// The connection source address resolves to a live box the value may be
    /// redeemed from (BEP-020).
    Attributed,
    /// The store handle's signature verifies under a registered client key
    /// (BEP-064).
    HandleVerified,
    /// The store handle's own expiry has not passed (BEP-064).
    HandleUnexpired,
    /// The store handle's `upstream` is within the rule currently registered
    /// for its store and identifier (BEP-064).
    HandleWithinRule,
    /// The store handle's injection form is that rule's (BEP-064).
    HandleInjectRegistered,
    /// The connection authority is in the value's bound host set (BEP-021).
    InBoundSet,
    /// The connection authority is in the module's current host set
    /// (BEP-021).
    InCurrentSet,
    /// The value's expiry has not passed (BEP-024).
    Unexpired,
    /// The value has not been revoked (BEP-024).
    Unrevoked,
    /// The member carries a mode (BEP-058).
    HasMode,
    /// The member carries a recognised breadth (BEP-058).
    HasBreadth,
}

/// The marker the audit record carries for a store handle refused on any of
/// its four checks (BEP-064).
pub const STORE_HANDLE_INVALID: &str = "store_handle_invalid";

impl Check {
    /// The name the audit record carries. The four store-handle checks share
    /// one marker, [`STORE_HANDLE_INVALID`], as BEP-064 names it; which of
    /// them failed is what the decision's own log line says.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OnDeclaredPort => "on_declared_port",
            Self::EgressAdmitted => "egress_admitted",
            Self::AuthorityPinned => "authority_pinned",
            Self::Decrypts => "decrypts",
            Self::Attributed => "attributed",
            Self::HandleVerified
            | Self::HandleUnexpired
            | Self::HandleWithinRule
            | Self::HandleInjectRegistered => STORE_HANDLE_INVALID,
            Self::InBoundSet => "in_bound_set",
            Self::InCurrentSet => "in_current_set",
            Self::Unexpired => "unexpired",
            Self::Unrevoked => "unrevoked",
            Self::HasMode => "has_mode",
            Self::HasBreadth => "has_breadth",
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The outcome of one redemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Every check passed: the shell replaces the sealed value with the
    /// member's credential and forwards the request to the connection
    /// authority (BEP-025).
    Admit,
    /// The first check that failed, in the order the checks run.
    Refuse(Check),
}

/// Everything the decision reads: the facts the shell established for one
/// request carrying a sealed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    /// The connection the request arrived on and what the request said about
    /// where it was going (BEP-022, BEP-023, BEP-031).
    pub request: Request,
    /// The member the value unsealed to under this host's key, or `None`
    /// when it did not decrypt (BEP-019).
    pub member: Option<SealedMember>,
    /// The store handle the member is, when it is one: its `upstream` is the
    /// member's bound set, and its checks stand where the module member's
    /// host-set, mode and breadth checks stand (BEP-064).
    pub store: Option<StoreHandle>,
    /// What the connection's source address resolved to.
    pub attribution: Attribution,
    /// The connection authority the request arrived on.
    pub authority: AuthorityId,
    /// The module's current host set.
    pub current_set: HostSet,
    /// The clock, as seconds since the Unix epoch.
    pub now: u64,
    /// The revocations in force.
    pub revocations: Vec<Revocation>,
}

/// Decides one redemption: [`Decision::Admit`] exactly when every check
/// passes, [`Decision::Refuse`] naming the first failing check otherwise.
///
/// The connection and request checks run before the member checks, so a
/// request refused for its port, its egress or its unpinned authority is
/// refused as such whether or not it carries a sealed value. A member that is
/// a store handle takes the handle's checks in place of the module member's
/// (BEP-064); one decision covers both kinds (BEP-025).
#[must_use]
pub fn decide(redemption: &Redemption) -> Decision {
    let member_failure = || match &redemption.store {
        Some(handle) => store::first_failure(redemption, handle),
        None => member::first_failure(redemption),
    };
    match request::first_failure(redemption).or_else(member_failure) {
        Some(check) => Decision::Refuse(check),
        None => Decision::Admit,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;

    use super::*;
    use crate::control::{ClientKey, ClientKeys};
    use crate::keychain::{MemoryKey, MemoryStore, PrivateKey as _};
    use crate::keys::Keys;
    use crate::mint::{self, ParsedHandle};
    use crate::seal::{self, Member, SealedContext};

    /// Ids are drawn from this many, so sets overlap and boxes coincide often
    /// enough that every property sees both of its arms.
    const IDS: u8 = 4;

    /// Ports are drawn from these, so a connection and a declared authority
    /// coincide on the port often enough that the port check sees both arms.
    const PORTS: [u16; 4] = [443, 80, 8443, 22];

    fn arb_authority() -> impl Strategy<Value = AuthorityId> {
        (0..IDS).prop_map(AuthorityId)
    }

    fn arb_endpoint() -> impl Strategy<Value = Endpoint> {
        ((0..IDS).prop_map(HostId), 0..PORTS.len()).prop_map(|(host, port)| Endpoint {
            host,
            port: PORTS[port],
        })
    }

    fn arb_egress() -> impl Strategy<Value = Egress> {
        prop::collection::vec(arb_authority(), 0..=4).prop_map(Egress)
    }

    /// The connection and request facts, drawn freely: the endpoint the
    /// connection arrived on need not be declared, the egress need not admit
    /// the connection authority, and the `Host` header and the target need not
    /// name it.
    fn arb_request() -> impl Strategy<Value = Request> {
        (
            arb_endpoint(),
            prop::collection::vec(arb_endpoint(), 0..=4),
            arb_egress(),
            prop::option::weighted(0.8, arb_authority()),
            prop::option::weighted(0.8, arb_authority()),
        )
            .prop_map(
                |(endpoint, declared, egress, host_header, target)| Request {
                    endpoint,
                    declared,
                    egress,
                    host_header,
                    target,
                },
            )
    }

    /// A request that passes every connection and request check against
    /// `authority`: it arrived on a declared endpoint, the box's egress admits
    /// the authority, and both the `Host` header and the target name it. The
    /// member properties draw this, so the refusal each of them reads is its
    /// own member check's.
    fn admitting_request(authority: AuthorityId, endpoint: Endpoint) -> Request {
        Request {
            endpoint,
            declared: vec![endpoint],
            egress: Egress(vec![authority]),
            host_header: Some(authority),
            target: Some(authority),
        }
    }

    fn arb_host_set() -> impl Strategy<Value = HostSet> {
        prop::collection::vec(arb_authority(), 1..=4).prop_map(HostSet)
    }

    fn arb_member() -> impl Strategy<Value = SealedMember> {
        (
            (0..IDS).prop_map(BoxId),
            (0..IDS).prop_map(ModuleId),
            arb_host_set(),
            prop::option::weighted(0.8, prop_oneof![Just(Mode::User), Just(Mode::Installation)]),
            prop::option::weighted(0.8, Just(Breadth::Full)),
            4..8u64,
        )
            .prop_map(|(box_id, module, bound_set, mode, breadth, expires_at)| {
                SealedMember {
                    box_id,
                    module,
                    bound_set,
                    mode,
                    breadth,
                    expires_at,
                }
            })
    }

    fn arb_inject() -> impl Strategy<Value = InjectId> {
        (0..2u8).prop_map(InjectId)
    }

    fn arb_store_rule() -> impl Strategy<Value = StoreRule> {
        (arb_host_set(), arb_inject()).prop_map(|(upstream, inject)| StoreRule { upstream, inject })
    }

    /// A store handle's facts, drawn freely: the shell's verification
    /// verdict, the handle's own expiry, its injection form, and the rule
    /// currently registered for it, when one is.
    fn arb_store_handle() -> impl Strategy<Value = StoreHandle> {
        (
            any::<bool>(),
            0..8u64,
            arb_inject(),
            prop::option::weighted(0.8, arb_store_rule()),
        )
            .prop_map(|(verified, expires_at, inject, rule)| StoreHandle {
                verified,
                expires_at,
                inject,
                rule,
            })
    }

    fn arb_attribution() -> impl Strategy<Value = Attribution> {
        prop_oneof![
            2 => Just(Attribution::NoBox),
            5 => (0..IDS).prop_map(|id| Attribution::OwnIp(BoxId(id))),
            3 => (0..IDS).prop_map(|id| Attribution::HostIp(BoxId(id))),
        ]
    }

    fn arb_revocation() -> impl Strategy<Value = Revocation> {
        prop_oneof![
            (0..IDS).prop_map(|id| Revocation::Box(BoxId(id))),
            (0..IDS).prop_map(|id| Revocation::Module(ModuleId(id))),
        ]
    }

    fn arb_redemption() -> impl Strategy<Value = Redemption> {
        (
            prop::option::weighted(0.9, arb_member()),
            arb_attribution(),
            arb_authority(),
            arb_host_set(),
            0..8u64,
            prop::collection::vec(arb_revocation(), 0..=2),
            arb_endpoint(),
        )
            .prop_map(
                |(member, attribution, authority, current_set, now, revocations, endpoint)| {
                    Redemption {
                        request: admitting_request(authority, endpoint),
                        member,
                        store: None,
                        attribution,
                        authority,
                        current_set,
                        now,
                        revocations,
                    }
                },
            )
    }

    /// `redemption` with every check repaired, so the decision admits it. The
    /// request properties break exactly one dimension of it, and so read the
    /// refusal their requirement names rather than an earlier check's.
    fn admitting(redemption: &Redemption) -> Redemption {
        let authority = redemption.authority;
        let member = redemption.member.clone().unwrap_or_else(|| SealedMember {
            box_id: BoxId(0),
            module: ModuleId(0),
            bound_set: HostSet(vec![authority]),
            mode: None,
            breadth: None,
            expires_at: 0,
        });
        let member = SealedMember {
            bound_set: HostSet(vec![authority]),
            mode: Some(Mode::User),
            breadth: Some(Breadth::Full),
            expires_at: redemption.now + 1,
            ..member
        };
        Redemption {
            request: admitting_request(authority, redemption.request.endpoint),
            attribution: Attribution::OwnIp(member.box_id),
            member: Some(member),
            store: None,
            authority,
            current_set: HostSet(vec![authority]),
            now: redemption.now,
            revocations: Vec::new(),
        }
    }

    /// This host's keys and another host's.
    static HOSTS: LazyLock<[Keys<MemoryStore>; 2]> = LazyLock::new(|| {
        [
            Keys::open(MemoryStore::new()).unwrap(),
            Keys::open(MemoryStore::new()).unwrap(),
        ]
    });

    fn context() -> SealedContext {
        SealedContext {
            box_id: "box-a1".into(),
            host: "mac-1".into(),
            module: "github".into(),
            host_set_version: 3,
            mode: "user".into(),
            breadth: "full".into(),
            expires_at: 4_102_444_800,
        }
    }

    fn attributed(member: &SealedMember, redemption: &Redemption) -> bool {
        match redemption.attribution {
            Attribution::NoBox => false,
            Attribution::OwnIp(box_id) => box_id == member.box_id,
            Attribution::HostIp(_) => true,
        }
    }

    fn revoked(member: &SealedMember, redemption: &Redemption) -> bool {
        redemption
            .revocations
            .iter()
            .any(|revocation| match *revocation {
                Revocation::Box(box_id) => box_id == member.box_id,
                Revocation::Module(module) => module == member.module,
            })
    }

    /// The decision BEP-025 states for a store handle, restated from the raw
    /// facts: the envelope's checks with the handle's four in place of the
    /// module member's host-set, mode and breadth checks (BEP-064).
    fn expected_for_store(
        member: &SealedMember,
        handle: &StoreHandle,
        redemption: &Redemption,
    ) -> Decision {
        let checks = [
            (Check::Attributed, attributed(member, redemption)),
            (Check::HandleVerified, handle.verified),
            (Check::HandleUnexpired, redemption.now < handle.expires_at),
            (
                Check::HandleWithinRule,
                handle
                    .rule
                    .as_ref()
                    .is_some_and(|rule| member.bound_set.is_subset_of(&rule.upstream)),
            ),
            (
                Check::HandleInjectRegistered,
                handle
                    .rule
                    .as_ref()
                    .is_some_and(|rule| rule.inject == handle.inject),
            ),
            (
                Check::InBoundSet,
                member.bound_set.0.contains(&redemption.authority),
            ),
            (Check::Unexpired, redemption.now < member.expires_at),
            (Check::Unrevoked, !revoked(member, redemption)),
        ];
        checks
            .iter()
            .find(|(_, passes)| !passes)
            .map_or(Decision::Admit, |(check, _)| Decision::Refuse(*check))
    }

    /// One client's handle-signing key with a handle signed under it, read
    /// back as the shell reads it, and the same handle with one bit of its
    /// signature flipped.
    struct Signer {
        key: MemoryKey,
        honest: ParsedHandle,
        tampered: ParsedHandle,
    }

    /// Two clients, each with a signed handle: the keys a proxy may hold any
    /// subset of.
    static SIGNERS: LazyLock<[Signer; 2]> = LazyLock::new(|| {
        std::array::from_fn(|_| {
            let key = mint::client_key(&MemoryStore::new()).unwrap();
            let minted = mint::mint_store_handle(
                &HOSTS[0].public_identity(),
                &key,
                &mint::StoreMintRequest {
                    box_id: "box-a1",
                    host: "mac-1",
                    store: "keychain",
                    id: "anthropic-api-key",
                    upstream: &["api.anthropic.com:443".to_owned()],
                    inject: &mint::Inject::header("x-api-key", ""),
                    now: 0,
                },
            )
            .unwrap();
            let text = minted.handle.as_str();
            let (body, signature) = text.rsplit_once('.').unwrap();
            let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0x01;
            let tampered = format!("{body}.{}", URL_SAFE_NO_PAD.encode(&bytes));
            Signer {
                key,
                honest: mint::parse_store_handle(text).unwrap(),
                tampered: mint::parse_store_handle(&tampered).unwrap(),
            }
        })
    });

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        /// BEP-019: a value sealed to another host's key does not unseal
        /// here, and a value that did not decrypt is refused as such
        /// whatever else the request carries.
        #[test]
        fn prop_off_host_sealed_value_is_refused(
            redemption in arb_redemption(),
            other_host in any::<bool>(),
        ) {
            let sealed = seal::seal(&HOSTS[0], &context(), &Member::new("gho_credential")).unwrap();
            let unsealed = seal::unseal(&HOSTS[usize::from(other_host)], sealed.as_str());
            prop_assert_eq!(unsealed.is_ok(), !other_host);

            let member = redemption.member.clone().filter(|_| unsealed.is_ok());
            let redemption = Redemption { member, ..redemption };
            match decide(&redemption) {
                Decision::Admit => prop_assert!(!other_host && redemption.member.is_some()),
                Decision::Refuse(check) => {
                    prop_assert_eq!(check == Check::Decrypts, redemption.member.is_none());
                }
            }
        }

        /// BEP-020: admitted only when the source address resolves to the
        /// box the value names, or to a `host_ip` box of this host.
        #[test]
        fn prop_cross_box_sealed_value_is_refused(redemption in arb_redemption()) {
            let Some(member) = &redemption.member else { return Ok(()) };
            let attributed = attributed(member, &redemption);
            match decide(&redemption) {
                Decision::Admit => prop_assert!(attributed),
                Decision::Refuse(check) => prop_assert_eq!(check == Check::Attributed, !attributed),
            }
        }

        /// BEP-021: admitted only when the connection authority is in both
        /// the value's bound host set and the module's current one.
        #[test]
        fn prop_authority_outside_bound_or_current_set_is_refused(
            redemption in arb_redemption(),
        ) {
            let Some(member) = &redemption.member else { return Ok(()) };
            let in_bound = member.bound_set.0.contains(&redemption.authority);
            let in_current = redemption.current_set.0.contains(&redemption.authority);
            match decide(&redemption) {
                Decision::Admit => prop_assert!(in_bound && in_current),
                Decision::Refuse(Check::InBoundSet) => prop_assert!(!in_bound),
                Decision::Refuse(Check::InCurrentSet) => prop_assert!(in_bound && !in_current),
                Decision::Refuse(_) => {}
            }
        }

        /// BEP-024: admitted only when the clock is before the expiry and no
        /// revocation in force covers the value.
        #[test]
        fn prop_expired_or_revoked_value_is_refused(redemption in arb_redemption()) {
            let Some(member) = &redemption.member else { return Ok(()) };
            let unexpired = redemption.now < member.expires_at;
            let revoked = revoked(member, &redemption);
            match decide(&redemption) {
                Decision::Admit => prop_assert!(unexpired && !revoked),
                Decision::Refuse(Check::Unexpired) => prop_assert!(!unexpired),
                Decision::Refuse(Check::Unrevoked) => prop_assert!(unexpired && revoked),
                Decision::Refuse(_) => {}
            }
        }

        /// BEP-058: a member whose context names no mode, or no breadth the
        /// proxy recognises, is refused; only `user` and `installation` are
        /// modes and only `full` is a breadth.
        #[test]
        fn prop_member_without_bounds_is_refused(
            redemption in arb_redemption(),
            mode in prop_oneof![
                Just(String::from("user")),
                Just(String::from("installation")),
                Just(String::from("full")),
                Just(String::new()),
                "[a-z]{0,12}",
            ],
            breadth in prop_oneof![
                Just(String::from("full")),
                Just(String::from("user")),
                Just(String::new()),
                "[a-z]{0,12}",
            ],
        ) {
            let Some(member) = redemption.member.clone() else { return Ok(()) };
            let has_mode = mode == "user" || mode == "installation";
            let has_breadth = breadth == "full";
            let member = SealedMember {
                mode: Mode::recognise(&mode),
                breadth: Breadth::recognise(&breadth),
                ..member
            };
            prop_assert_eq!(member.mode.is_some(), has_mode);
            prop_assert_eq!(member.breadth.is_some(), has_breadth);

            let redemption = Redemption { member: Some(member), ..redemption };
            match decide(&redemption) {
                Decision::Admit => prop_assert!(has_mode && has_breadth),
                Decision::Refuse(Check::HasMode) => prop_assert!(!has_mode),
                Decision::Refuse(Check::HasBreadth) => prop_assert!(has_mode && !has_breadth),
                Decision::Refuse(_) => {}
            }
        }

        /// BEP-022: admitted only when the sending box's declared egress
        /// admits the connection authority, whether or not the request carries
        /// a sealed value: the check runs before the value is read, so the
        /// refusal names the egress either way.
        #[test]
        fn prop_undeclared_egress_authority_is_refused(
            redemption in arb_redemption(),
            egress in arb_egress(),
            sealed in any::<bool>(),
        ) {
            let base = admitting(&redemption);
            prop_assert_eq!(decide(&base), Decision::Admit);

            let admits = egress.admits(base.authority);
            let request = Request { egress, ..base.request.clone() };
            let member = base.member.clone().filter(|_| sealed);
            let varied = Redemption { request, member, ..base };
            let expected = if !admits {
                Decision::Refuse(Check::EgressAdmitted)
            } else if sealed {
                Decision::Admit
            } else {
                Decision::Refuse(Check::Decrypts)
            };
            prop_assert_eq!(decide(&varied), expected);
        }

        /// BEP-023: substitution happens only when the `Host` header, the
        /// request target and the connection authority are one and the same
        /// authority; an origin-form target names the connection authority,
        /// which the shell fills in.
        #[test]
        fn prop_host_header_mismatch_is_refused(
            redemption in arb_redemption(),
            host_header in prop::option::weighted(0.8, arb_authority()),
            target in prop::option::weighted(0.8, arb_authority()),
        ) {
            let base = admitting(&redemption);
            prop_assert_eq!(decide(&base), Decision::Admit);

            let pinned = host_header == Some(base.authority)
                && target == Some(base.authority);
            let request = Request { host_header, target, ..base.request.clone() };
            let varied = Redemption { request, ..base };
            let expected = if pinned {
                Decision::Admit
            } else {
                Decision::Refuse(Check::AuthorityPinned)
            };
            prop_assert_eq!(decide(&varied), expected);
        }

        /// BEP-031: a connection for a credentialed hostname is admitted only
        /// when its `host:port` is one of the module's declared authorities,
        /// so the same hostname on any other port is refused.
        #[test]
        fn prop_off_port_connection_is_refused(
            redemption in arb_redemption(),
            endpoint in arb_endpoint(),
            declared in prop::collection::vec(arb_endpoint(), 0..=4),
        ) {
            let base = admitting(&redemption);
            prop_assert_eq!(decide(&base), Decision::Admit);

            let on_port = declared.contains(&endpoint);
            let request = Request { endpoint, declared, ..base.request.clone() };
            let varied = Redemption { request, ..base };
            let expected = if on_port {
                Decision::Admit
            } else {
                Decision::Refuse(Check::OnDeclaredPort)
            };
            prop_assert_eq!(decide(&varied), expected);
        }

        /// BEP-064: a store handle is admitted only when its signature
        /// verifies under a registered client key, the clock is before its
        /// expiry, its `upstream` is a subset of the rule currently
        /// registered for its store and identifier, and its injection form is
        /// that rule's — and the refusal names the first of those to fail,
        /// never a module member's mode, breadth or current-set check. The
        /// verification is the shell's, run here for real: each case draws
        /// which of two clients signed the handle, which client keys the
        /// proxy holds, and whether the signature was tampered with.
        #[test]
        fn prop_store_handle_verified_against_current_rule(
            redemption in arb_redemption(),
            signer in 0..2usize,
            held in prop::collection::vec(0..2usize, 0..=2),
            tampered in any::<bool>(),
            handle in arb_store_handle(),
        ) {
            let Some(member) = redemption.member.clone() else { return Ok(()) };

            let mut keys = ClientKeys::new();
            for index in &held {
                keys.register(&ClientKey::of(&SIGNERS[*index].key.public_key().unwrap())).unwrap();
            }
            let parsed = if tampered {
                &SIGNERS[signer].tampered
            } else {
                &SIGNERS[signer].honest
            };
            let verified = keys
                .holding(&parsed.claims.key)
                .is_some_and(|public| parsed.verifies_under(public));
            prop_assert_eq!(verified, held.contains(&signer) && !tampered);

            let handle = StoreHandle { verified, ..handle };
            let unexpired = redemption.now < handle.expires_at;
            let within = handle
                .rule
                .as_ref()
                .is_some_and(|rule| member.bound_set.is_subset_of(&rule.upstream));
            let registered_form = handle
                .rule
                .as_ref()
                .is_some_and(|rule| rule.inject == handle.inject);
            let redemption = Redemption {
                member: Some(member.clone()),
                store: Some(handle.clone()),
                ..redemption
            };
            let decision = decide(&redemption);
            prop_assert_eq!(decision, expected_for_store(&member, &handle, &redemption));
            match decision {
                Decision::Admit => {
                    prop_assert!(verified && unexpired && within && registered_form);
                }
                Decision::Refuse(Check::HandleVerified) => prop_assert!(!verified),
                Decision::Refuse(Check::HandleUnexpired) => {
                    prop_assert!(verified && !unexpired);
                }
                Decision::Refuse(Check::HandleWithinRule) => {
                    prop_assert!(verified && unexpired && !within);
                }
                Decision::Refuse(Check::HandleInjectRegistered) => {
                    prop_assert!(verified && unexpired && within && !registered_form);
                }
                Decision::Refuse(
                    check @ (Check::HasMode | Check::HasBreadth | Check::InCurrentSet),
                ) => {
                    return Err(TestCaseError::fail(format!(
                        "a module member's check read a store handle: {check}"
                    )));
                }
                Decision::Refuse(_) => {}
            }
            // Every one of the four is a `store_handle_invalid` to the audit
            // record, whichever failed first.
            for check in [
                Check::HandleVerified,
                Check::HandleUnexpired,
                Check::HandleWithinRule,
                Check::HandleInjectRegistered,
            ] {
                prop_assert_eq!(check.name(), STORE_HANDLE_INVALID);
            }
        }

        /// BEP-025: the decision is `Admit` exactly when every check passes,
        /// and `Refuse` naming the first failing check, in order, otherwise.
        /// The checks are restated here from the raw facts, for a module
        /// member and for a store handle alike. Half the cases keep the
        /// admitting request the member properties draw, so every member
        /// check is still reached; the other half draw the connection and
        /// request facts freely too.
        #[test]
        fn prop_admit_iff_every_check_passes(
            redemption in arb_redemption(),
            request in prop::option::weighted(0.5, arb_request()),
            store in prop::option::weighted(0.3, arb_store_handle()),
        ) {
            let redemption = match request {
                Some(request) => Redemption { request, store, ..redemption },
                None => Redemption { store, ..redemption },
            };
            let request_checks = [
                (
                    Check::OnDeclaredPort,
                    redemption.request.declared.contains(&redemption.request.endpoint),
                ),
                (
                    Check::EgressAdmitted,
                    redemption.request.egress.0.contains(&redemption.authority),
                ),
                (
                    Check::AuthorityPinned,
                    redemption.request.host_header == Some(redemption.authority)
                        && redemption.request.target == Some(redemption.authority),
                ),
            ];
            if let Some((check, _)) = request_checks.iter().find(|(_, passes)| !passes) {
                prop_assert_eq!(decide(&redemption), Decision::Refuse(*check));
                return Ok(());
            }
            let expected = match (&redemption.member, &redemption.store) {
                (None, _) => Decision::Refuse(Check::Decrypts),
                (Some(member), Some(handle)) => expected_for_store(member, handle, &redemption),
                (Some(member), None) => {
                    let checks = [
                        (Check::Attributed, attributed(member, &redemption)),
                        (Check::InBoundSet, member.bound_set.0.contains(&redemption.authority)),
                        (Check::InCurrentSet, redemption.current_set.0.contains(&redemption.authority)),
                        (Check::Unexpired, redemption.now < member.expires_at),
                        (Check::Unrevoked, !revoked(member, &redemption)),
                        (Check::HasMode, member.mode.is_some()),
                        (Check::HasBreadth, member.breadth.is_some()),
                    ];
                    checks
                        .iter()
                        .find(|(_, passes)| !passes)
                        .map_or(Decision::Admit, |(check, _)| Decision::Refuse(*check))
                }
            };
            prop_assert_eq!(decide(&redemption), expected);
        }
    }
}

/// Bounded proofs of the member checks (BEP-019 to BEP-021, BEP-024,
/// BEP-025, BEP-058, BEP-064), exhaustive over host sets of at most four
/// authorities and revocation sets of at most two entries, with every id,
/// clock reading and expiry left symbolic.
///
/// Run: `cargo kani -p bep` (or `just kani`). Kani pinned at 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The host-set bound: the spec's "at most 4 authorities".
    const AUTHORITIES: usize = 4;
    /// The revocation-set bound: the spec's "2 members".
    const REVOCATIONS: usize = 2;

    fn any_host_set() -> HostSet {
        HostSet(kani::vec::any_vec::<AuthorityId, AUTHORITIES>())
    }

    fn any_member() -> SealedMember {
        SealedMember {
            box_id: kani::any(),
            module: kani::any(),
            bound_set: any_host_set(),
            mode: kani::any(),
            breadth: kani::any(),
            expires_at: kani::any(),
        }
    }

    /// A request that passes every connection and request check against
    /// `authority`, with the endpoint it arrived on left symbolic. The member
    /// proofs hold this, so the refusal each of them reads is its own member
    /// check's.
    fn admitting_request(authority: AuthorityId) -> Request {
        let endpoint: Endpoint = kani::any();
        Request {
            endpoint,
            declared: vec![endpoint],
            egress: Egress(vec![authority]),
            host_header: Some(authority),
            target: Some(authority),
        }
    }

    /// The connection and request facts left symbolic: the declared endpoints
    /// and the egress bounded as the host sets are.
    fn any_request() -> Request {
        Request {
            endpoint: kani::any(),
            declared: kani::vec::any_vec::<Endpoint, AUTHORITIES>(),
            egress: Egress(kani::vec::any_vec::<AuthorityId, AUTHORITIES>()),
            host_header: kani::any(),
            target: kani::any(),
        }
    }

    fn any_redemption() -> Redemption {
        let authority: AuthorityId = kani::any();
        Redemption {
            request: admitting_request(authority),
            member: if kani::any() {
                Some(any_member())
            } else {
                None
            },
            store: None,
            attribution: kani::any(),
            authority,
            current_set: any_host_set(),
            now: kani::any(),
            revocations: kani::vec::any_vec::<Revocation, REVOCATIONS>(),
        }
    }

    /// A store handle's facts left symbolic, its rule's host set bounded as
    /// the others are.
    fn any_store_handle() -> StoreHandle {
        StoreHandle {
            verified: kani::any(),
            expires_at: kani::any(),
            inject: kani::any(),
            rule: if kani::any() {
                Some(StoreRule {
                    upstream: any_host_set(),
                    inject: kani::any(),
                })
            } else {
                None
            },
        }
    }

    fn attributed(member: &SealedMember, redemption: &Redemption) -> bool {
        match redemption.attribution {
            Attribution::NoBox => false,
            Attribution::OwnIp(box_id) => box_id == member.box_id,
            Attribution::HostIp(_) => true,
        }
    }

    fn revoked(member: &SealedMember, redemption: &Redemption) -> bool {
        redemption
            .revocations
            .iter()
            .any(|revocation| match *revocation {
                Revocation::Box(box_id) => box_id == member.box_id,
                Revocation::Module(module) => module == member.module,
            })
    }

    /// BEP-025 for a store handle, restated from the raw facts (BEP-064).
    fn expected_for_store(
        member: &SealedMember,
        handle: &StoreHandle,
        redemption: &Redemption,
    ) -> Decision {
        let checks = [
            (Check::Attributed, attributed(member, redemption)),
            (Check::HandleVerified, handle.verified),
            (Check::HandleUnexpired, redemption.now < handle.expires_at),
            (
                Check::HandleWithinRule,
                handle
                    .rule
                    .as_ref()
                    .is_some_and(|rule| member.bound_set.is_subset_of(&rule.upstream)),
            ),
            (
                Check::HandleInjectRegistered,
                handle
                    .rule
                    .as_ref()
                    .is_some_and(|rule| rule.inject == handle.inject),
            ),
            (
                Check::InBoundSet,
                member.bound_set.0.contains(&redemption.authority),
            ),
            (Check::Unexpired, redemption.now < member.expires_at),
            (Check::Unrevoked, !revoked(member, redemption)),
        ];
        checks
            .iter()
            .find(|(_, passes)| !passes)
            .map_or(Decision::Admit, |(check, _)| Decision::Refuse(*check))
    }

    /// BEP-019: a value that did not decrypt under this host's key is
    /// refused as such, and nothing else is.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_refuses_undecryptable() {
        let redemption = any_redemption();
        match decide(&redemption) {
            Decision::Admit => assert!(redemption.member.is_some()),
            Decision::Refuse(check) => {
                assert_eq!(check == Check::Decrypts, redemption.member.is_none());
            }
        }
    }

    /// BEP-020: admitted only when the source address resolves to the box
    /// the value names, or to a `host_ip` box of this host.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_refuses_misattributed() {
        let redemption = any_redemption();
        let Some(member) = &redemption.member else {
            return;
        };
        let attributed = attributed(member, &redemption);
        match decide(&redemption) {
            Decision::Admit => assert!(attributed),
            Decision::Refuse(check) => assert_eq!(check == Check::Attributed, !attributed),
        }
    }

    /// BEP-021: admitted only when the connection authority is in both the
    /// bound set and the current set.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_requires_authority_in_both_sets() {
        let redemption = any_redemption();
        let Some(member) = &redemption.member else {
            return;
        };
        let in_bound = member.bound_set.0.contains(&redemption.authority);
        let in_current = redemption.current_set.0.contains(&redemption.authority);
        match decide(&redemption) {
            Decision::Admit => assert!(in_bound && in_current),
            Decision::Refuse(Check::InBoundSet) => assert!(!in_bound),
            Decision::Refuse(Check::InCurrentSet) => assert!(in_bound && !in_current),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-024: admitted only when the clock is before the expiry and no
    /// revocation covers the value.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_refuses_expired_or_revoked() {
        let redemption = any_redemption();
        let Some(member) = &redemption.member else {
            return;
        };
        let unexpired = redemption.now < member.expires_at;
        let revoked = revoked(member, &redemption);
        match decide(&redemption) {
            Decision::Admit => assert!(unexpired && !revoked),
            Decision::Refuse(Check::Unexpired) => assert!(!unexpired),
            Decision::Refuse(Check::Unrevoked) => assert!(unexpired && revoked),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-058: admitted only when the member carries a mode and a
    /// recognised breadth.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_refuses_unbounded_member() {
        let redemption = any_redemption();
        let Some(member) = &redemption.member else {
            return;
        };
        let has_mode = member.mode.is_some();
        let has_breadth = member.breadth.is_some();
        match decide(&redemption) {
            Decision::Admit => assert!(has_mode && has_breadth),
            Decision::Refuse(Check::HasMode) => assert!(!has_mode),
            Decision::Refuse(Check::HasBreadth) => assert!(has_mode && !has_breadth),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-022: admitted only when the sending box's declared egress admits
    /// the connection authority, sealed value or not.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_requires_egress_admission() {
        let redemption = Redemption {
            request: any_request(),
            ..any_redemption()
        };
        let admits = redemption.request.egress.admits(redemption.authority);
        match decide(&redemption) {
            Decision::Admit => assert!(admits),
            Decision::Refuse(Check::EgressAdmitted) => assert!(!admits),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-023: admitted only when the `Host` header, the request target and
    /// the connection authority are one and the same authority.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_pins_request_authority() {
        let redemption = Redemption {
            request: any_request(),
            ..any_redemption()
        };
        let pinned = redemption.request.host_header == Some(redemption.authority)
            && redemption.request.target == Some(redemption.authority);
        match decide(&redemption) {
            Decision::Admit => assert!(pinned),
            Decision::Refuse(Check::AuthorityPinned) => assert!(!pinned),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-031: admitted only when the connection's `host:port` is one of the
    /// module's declared authorities.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_enforces_port_discipline() {
        let redemption = Redemption {
            request: any_request(),
            ..any_redemption()
        };
        let on_port = redemption
            .request
            .declared
            .contains(&redemption.request.endpoint);
        match decide(&redemption) {
            Decision::Admit => assert!(on_port),
            Decision::Refuse(Check::OnDeclaredPort) => assert!(!on_port),
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-064: a store handle is admitted only when its signature verified
    /// under a registered client key, the clock is before its own expiry,
    /// its `upstream` is within the rule currently registered for it and its
    /// injection form is that rule's; a refusal names the first of those to
    /// fail, and never a module member's mode, breadth or current-set check.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_refuses_invalid_store_handle() {
        let redemption = Redemption {
            store: Some(any_store_handle()),
            ..any_redemption()
        };
        let (Some(member), Some(handle)) = (&redemption.member, &redemption.store) else {
            return;
        };
        let unexpired = redemption.now < handle.expires_at;
        let within = handle
            .rule
            .as_ref()
            .is_some_and(|rule| member.bound_set.is_subset_of(&rule.upstream));
        let registered_form = handle
            .rule
            .as_ref()
            .is_some_and(|rule| rule.inject == handle.inject);
        match decide(&redemption) {
            Decision::Admit => {
                assert!(handle.verified && unexpired && within && registered_form);
            }
            Decision::Refuse(Check::HandleVerified) => assert!(!handle.verified),
            Decision::Refuse(Check::HandleUnexpired) => {
                assert!(handle.verified && !unexpired);
            }
            Decision::Refuse(Check::HandleWithinRule) => {
                assert!(handle.verified && unexpired && !within);
            }
            Decision::Refuse(Check::HandleInjectRegistered) => {
                assert!(handle.verified && unexpired && within && !registered_form);
            }
            Decision::Refuse(Check::HasMode | Check::HasBreadth | Check::InCurrentSet) => {
                unreachable!("a module member's check read a store handle");
            }
            Decision::Refuse(_) => {}
        }
    }

    /// BEP-025: `Admit` exactly when every check passes, `Refuse` naming the
    /// first failing check, in order, otherwise — for a module member and for
    /// a store handle alike.
    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_redeem_admits_iff_all_checks_pass() {
        let redemption = Redemption {
            request: any_request(),
            store: if kani::any() {
                Some(any_store_handle())
            } else {
                None
            },
            ..any_redemption()
        };
        let request_checks = [
            (
                Check::OnDeclaredPort,
                redemption
                    .request
                    .declared
                    .contains(&redemption.request.endpoint),
            ),
            (
                Check::EgressAdmitted,
                redemption.request.egress.0.contains(&redemption.authority),
            ),
            (
                Check::AuthorityPinned,
                redemption.request.host_header == Some(redemption.authority)
                    && redemption.request.target == Some(redemption.authority),
            ),
        ];
        if let Some((check, _)) = request_checks.iter().find(|(_, passes)| !passes) {
            assert_eq!(decide(&redemption), Decision::Refuse(*check));
            return;
        }
        let expected = match (&redemption.member, &redemption.store) {
            (None, _) => Decision::Refuse(Check::Decrypts),
            (Some(member), Some(handle)) => expected_for_store(member, handle, &redemption),
            (Some(member), None) => {
                let checks = [
                    (Check::Attributed, attributed(member, &redemption)),
                    (
                        Check::InBoundSet,
                        member.bound_set.0.contains(&redemption.authority),
                    ),
                    (
                        Check::InCurrentSet,
                        redemption.current_set.0.contains(&redemption.authority),
                    ),
                    (Check::Unexpired, redemption.now < member.expires_at),
                    (Check::Unrevoked, !revoked(member, &redemption)),
                    (Check::HasMode, member.mode.is_some()),
                    (Check::HasBreadth, member.breadth.is_some()),
                ];
                checks
                    .iter()
                    .find(|(_, passes)| !passes)
                    .map_or(Decision::Admit, |(check, _)| Decision::Refuse(*check))
            }
        };
        assert_eq!(decide(&redemption), expected);
    }
}
