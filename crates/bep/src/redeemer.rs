//! The redeemer `bep serve` installs: the I/O shell around
//! [`redeem::decide`] (BEP-019, BEP-020, BEP-022, BEP-025).
//!
//! For each request that carries a sealed value, [`BoxRedeemer`]:
//!
//! 1. reads the sending box's attribution and declared egress from the box
//!    registry ([`crate::boxes`]),
//! 2. opens the value under this host's proxy key, bound to the box that
//!    the attribution names, or to the `host_ip` cohort box that the value
//!    names, in one open ([`Unsealed::from_open`]),
//! 3. reads the member's handle and verifies it under the registered client
//!    keys ([`handle::read_opened`]),
//! 4. gives the facts and the revocations it holds to [`redeem::decide`],
//! 5. and on an admit only, resolves the sign-in reference to the member's
//!    credential from the sign-in item in the host keychain.
//!
//! A revoked value is refused at step 4, so no reference is resolved for it
//! (BEP-071). The redeemer never logs or returns the credential except in
//! [`Verdict::Admit`], which the forwarder substitutes and zeroes.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::audit::Mapping;
use crate::boxes::BoxRegistry;
use crate::control::Registry;
use crate::forward::{Redeemer, Verdict};
use crate::handle::{self, Handle, StoreRule};
use crate::keys::HeldKey;
use crate::module::Module;
use crate::redeem::{
    self, Attribution, Authority, Decision, Redemption, RequestAuthority, Unsealed,
};
use crate::seal::{self, Binding, OpenError, Opened};
use crate::signin::{Keychain, Standing};

/// The audit marker of an admitted redemption whose sign-in reference
/// resolves to no live sign-in: the item is gone, names another sign-in, or
/// its token expired.
pub const SIGN_IN_REQUIRED: &str = "github_sign_in_required";

/// The box ids that the revocations in force name.
pub type Revocations = Arc<RwLock<Vec<String>>>;

/// The clock, in seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// The redemption decision over this host's proxy key, the registered
/// client keys, the box registry and the sign-in item.
pub struct BoxRedeemer<K, C> {
    key: K,
    node: String,
    module: Module,
    clients: Registry,
    boxes: BoxRegistry,
    keychain: C,
    revocations: Revocations,
    clock: Clock,
}

impl<K, C> std::fmt::Debug for BoxRedeemer<K, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxRedeemer")
            .field("node", &self.node)
            .field("module", &self.module.id)
            .finish_non_exhaustive()
    }
}

/// What the shell found for one sealed value, before the decision.
struct Facts {
    redemption: Redemption<String, String>,
    identifier: Option<String>,
}

impl<K: HeldKey, C: Keychain> BoxRedeemer<K, C> {
    /// A redeemer that opens values under `key` for Box Host `node` and
    /// `module`. It verifies handles under `clients`, reads each box from
    /// `boxes`, and resolves sign-in references from `keychain`. The clock
    /// is the system clock.
    ///
    /// Interim: the redeemer starts with no revocation in force, and in
    /// `bep serve` nothing writes one. T20
    /// (<https://github.com/gominimal/minimal/issues/2277>) records
    /// revocations over the control socket. T33
    /// (<https://github.com/gominimal/minimal/issues/2290>) restores them
    /// from every retained audit segment at start, the BEP-068
    /// restore-on-start sub-requirement. Those two are the flip.
    #[must_use]
    pub fn new(
        key: K,
        node: impl Into<String>,
        module: Module,
        clients: Registry,
        boxes: BoxRegistry,
        keychain: C,
    ) -> Self {
        Self {
            key,
            node: node.into(),
            module,
            clients,
            boxes,
            keychain,
            revocations: Revocations::default(),
            clock: system_clock(),
        }
    }

    /// This redeemer, with `revocations` as the revocations in force.
    #[must_use]
    pub fn with_revocations(mut self, revocations: Revocations) -> Self {
        self.revocations = revocations;
        self
    }

    /// This redeemer, with `clock` as its clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn open(&self, box_id: &str, sealed: &str, now: u64) -> Result<Opened, OpenError> {
        seal::open_held(
            &self.key,
            sealed,
            &Binding {
                box_id: box_id.to_owned(),
                host: self.node.clone(),
                module: self.module.id.to_owned(),
                now,
            },
        )
    }

    /// The cohort box to bind the one open of `sealed` to.
    ///
    /// The value's protected header names its box in `sub`. The header is
    /// not yet authenticated here, but the open authenticates it: an open
    /// bound to a box that the value does not carry fails as
    /// [`Unsealed::OtherBox`]. When `sub` names no cohort box, or the header
    /// does not parse, the target is the first cohort box. That open
    /// classifies the value as every cohort open does: other box, or the
    /// error that precedes the box check. `None` means the cohort is empty.
    fn cohort_target(cohort: &[String], sealed: &str) -> Option<String> {
        let carried = Self::carried_box(sealed);
        carried
            .filter(|id| cohort.contains(id))
            .or_else(|| cohort.first().cloned())
    }

    /// The `sub` member of the protected header of `sealed`, read with no
    /// key and no check. Only [`Self::cohort_target`] reads it.
    fn carried_box(sealed: &str) -> Option<String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        #[derive(serde::Deserialize)]
        struct Sub {
            sub: String,
        }
        if sealed.len() > seal::MAX_SEALED_LEN {
            return None;
        }
        let header = URL_SAFE_NO_PAD.decode(sealed.split('.').next()?).ok()?;
        serde_json::from_slice::<Sub>(&header).ok().map(|h| h.sub)
    }

    /// The decryption fact for one open. An open error that no check of
    /// [`redeem::decide`] names is refused as undecryptable: the proxy
    /// cannot read the value.
    fn unsealed(result: Result<Opened, OpenError>) -> (Unsealed<String>, Option<Opened>) {
        let opened = result.as_ref().ok().cloned();
        match Unsealed::from_open(result) {
            Ok(unsealed) => (unsealed, opened),
            Err(error) => {
                tracing::debug!(%error, "the sealed value did not open");
                (Unsealed::Undecryptable, None)
            }
        }
    }

    /// Gathers the facts [`redeem::decide`] reads for one request.
    ///
    /// The revoked set is what [`Self::with_revocations`] gave, which is
    /// empty in `bep serve` until T20 (#2277) and T33 (#2290) land. The
    /// store rules are empty until T25
    /// (<https://github.com/gominimal/minimal/issues/2280>) reads
    /// `[secret-store-rules]`, so this redeemer never admits a
    /// store-handle member yet.
    fn facts(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
        now: u64,
    ) -> Facts {
        let attribution = self.boxes.attribution(box_id);
        let egress = self.boxes.egress(box_id);
        let (unsealed, opened, named_box_in_cohort) = match &attribution {
            Attribution::OwnIp(sender) => {
                let (unsealed, opened) = Self::unsealed(self.open(sender, sealed, now));
                (unsealed, opened, false)
            }
            // The cohort's shared address names no single box. The open is
            // bound once, to the cohort box the value's header names, so a
            // request costs one key agreement whatever the cohort's size.
            Attribution::HostIpCohort => match Self::cohort_target(&self.boxes.cohort(), sealed) {
                None => (Unsealed::OtherBox, None, false),
                Some(member) => {
                    let (unsealed, opened) = Self::unsealed(self.open(&member, sealed, now));
                    let named = unsealed != Unsealed::OtherBox;
                    (unsealed, opened, named)
                }
            },
            Attribution::NoLiveBox => {
                let (unsealed, opened) = Self::unsealed(self.open(box_id, sealed, now));
                (unsealed, opened, false)
            }
        };
        let current_set: Vec<Authority<String>> = self
            .module
            .hosts
            .iter()
            .map(|a| Authority {
                host: a.host.to_owned(),
                port: a.port,
            })
            .collect();
        let (bound_set, handle, identifier) = match &opened {
            Some(opened) => {
                // Only the module's current host-set version is known, so a
                // value sealed under another version has an empty bound set.
                let bound_set = if opened.context.host_set_version == self.module.host_set_version {
                    current_set.clone()
                } else {
                    Vec::new()
                };
                // Interim: no store rules until T25 (#2280) reads
                // `[secret-store-rules]`, so a store-handle member is not
                // admitted here.
                let rules: &[StoreRule] = &[];
                let read = {
                    let clients = self.clients.read().unwrap_or_else(PoisonError::into_inner);
                    handle::read_opened(opened, &clients, rules, &self.module, now)
                };
                (bound_set, read.handle, read.identifier)
            }
            None => (
                Vec::new(),
                Handle {
                    verified: false,
                    bound: false,
                    exp: 0,
                    upstream: Vec::new(),
                    inject: None,
                    rule: None,
                },
                None,
            ),
        };
        let revoked = self
            .revocations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Facts {
            redemption: Redemption {
                unsealed,
                attribution,
                named_box_in_cohort,
                now,
                revoked,
                authority: authority.clone(),
                bound_set,
                current_set,
                request: request.clone(),
                egress,
                handle,
            },
            identifier,
        }
    }

    /// The credential the sign-in reference `identifier` names, when the
    /// held sign-in is that one and its token is live.
    fn credential(&self, identifier: &str, now: u64) -> Option<Zeroizing<String>> {
        let instance = identifier
            .strip_prefix(self.module.id)
            .and_then(|rest| rest.strip_prefix(':'))?;
        let metadata = match self.keychain.metadata() {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "the sign-in item was not read");
                return None;
            }
        };
        // Interim: a token that is `Standing::RenewsAtProxy` is refused here,
        // and the request is refused `github_sign_in_required`. BEP-069
        // renews the token at the proxy before it is substituted. T24
        // (https://github.com/gominimal/minimal/issues/2279) wires that
        // renewal, and is the flip. Until then the refusal stands, while
        // `min auth status` tells the user that the token renews at the proxy.
        if metadata.instance != instance || metadata.standing(now) != Standing::Live {
            return None;
        }
        match self.keychain.material() {
            Ok(Some(material)) if material.instance == instance => {
                Some(Zeroizing::new(material.access_token.clone()))
            }
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "the sign-in item was not read");
                None
            }
        }
    }
}

impl<K, C> Redeemer for BoxRedeemer<K, C>
where
    K: HeldKey + Send + Sync,
    C: Keychain + Send + Sync,
{
    fn egress(&self, box_id: &str) -> Vec<Authority<String>> {
        self.boxes.egress(box_id)
    }

    fn redeem(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
    ) -> Verdict {
        let now = (self.clock)();
        let facts = self.facts(box_id, authority, request, sealed, now);
        let verdict = match redeem::decide(&facts.redemption) {
            Decision::Refuse(check) => Verdict::Refuse(check.marker()),
            Decision::Admit { .. } => {
                let identifier = facts.identifier.unwrap_or_default();
                match self.credential(&identifier, now) {
                    Some(credential) => Verdict::Admit {
                        credential,
                        identifier,
                        mapping: Mapping::ModuleUnmapped,
                    },
                    None => Verdict::Refuse(SIGN_IN_REQUIRED),
                }
            }
        };
        tracing::debug!(box_id, ?verdict, "sealed value decided");
        verdict
    }
}

/// The refusal marker of a decision, or `None` for an admit. For the tests.
#[cfg(test)]
fn marker(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::Admit { .. } => None,
        Decision::Refuse(check) => Some(check.marker()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use p256::ecdsa::SigningKey;
    use proptest::prelude::*;

    use super::*;
    use crate::audit::{Decision as Record, Outcome};
    use crate::boxes::{Boxes, Stance};
    use crate::forward::{Flow, HalfEnd, Validated, forward_requests};
    use crate::handle::{Claims, ClientKeys, Inject};
    use crate::keys::memory::{MemoryKey, MemoryStore};
    use crate::keys::{KeyStore, Role};
    use crate::module::GITHUB;
    use crate::proxy::AuditWriter;
    use crate::redeem::Check;
    use crate::seal::{Breadth, Context, Member, MemberKind, MemberList, Mode};
    use crate::signin::{Flow as SignInFlow, Material, MemoryKeychain, Metadata};

    const NOW: u64 = 1_800_000_000;
    const NODE: &str = "node-1";
    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "ghu_the_real_token";

    struct World<K = MemoryKey> {
        redeemer: Arc<BoxRedeemer<K, MemoryKeychain>>,
        boxes: BoxRegistry,
        revocations: Revocations,
        sealing: seal::ProxyPublicKey,
        client: SigningKey,
    }

    fn github() -> Vec<Authority<String>> {
        GITHUB
            .hosts
            .iter()
            .map(|a| Authority {
                host: a.host.to_owned(),
                port: a.port,
            })
            .collect()
    }

    fn api() -> Authority<String> {
        Authority {
            host: "api.github.com".into(),
            port: 443,
        }
    }

    fn new_world() -> World {
        new_world_with(|key| key)
    }

    /// A world whose sealing key is `wrap` of a fresh memory key.
    fn new_world_with<K: HeldKey>(wrap: impl FnOnce(MemoryKey) -> K) -> World<K> {
        let store = MemoryStore::default();
        let key = wrap(store.generate(Role::Sealing).unwrap());
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
            .unwrap();
        let keychain = MemoryKeychain::default();
        keychain
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: SignInFlow::Device,
                    token_expires_at: NOW + 3600,
                    refresh_expires_at: NOW + 7200,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: TOKEN.into(),
                    refresh_token: "ghr_refresh".into(),
                },
            )
            .unwrap();
        let boxes: BoxRegistry = Arc::new(Boxes::new());
        let revocations = Revocations::default();
        let redeemer = BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::new(RwLock::new(keys)),
            Arc::clone(&boxes),
            keychain,
        )
        .with_revocations(Arc::clone(&revocations))
        .with_clock(Arc::new(|| NOW));
        World {
            redeemer: Arc::new(redeemer),
            boxes,
            revocations,
            sealing,
            client,
        }
    }

    /// A value sealed for `box_id` on this node, with a sign-in member.
    fn sealed_for<K>(world: &World<K>, box_id: &str, expiry: u64, version: u32) -> String {
        let jws = handle::sign(
            &world.client,
            &Claims {
                sub: box_id.into(),
                node_id: NODE.into(),
                store: GITHUB.id.into(),
                id: INSTANCE.into(),
                upstream: GITHUB.hosts.iter().map(|a| a.host.to_owned()).collect(),
                inject: None::<Inject>,
                iat: NOW - 10,
                exp: NOW + 3600,
                jti: "jti-1".into(),
            },
        );
        seal::seal(
            &world.sealing,
            &Context {
                box_id: box_id.into(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry,
                kid: world.sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::SignIn,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap()
    }

    /// Sends one request from `box_id` to `authority`, with `host` as its
    /// `Host` header and `sealed` as its bearer token. Gives what reached the
    /// upstream, how the half ended, and the audit records.
    fn send(
        world: &World,
        box_id: &str,
        authority: &Authority<String>,
        host: &str,
        sealed: &str,
    ) -> (String, HalfEnd, Vec<Record>) {
        let records = Arc::new(std::sync::Mutex::new(Vec::<Record>::new()));
        let audit: Arc<dyn AuditWriter> = records.clone();
        let redeemer: Arc<dyn Redeemer> = world.redeemer.clone();
        let flow = Flow::new(
            box_id,
            authority.clone(),
            audit,
            redeemer,
            Validated::unchecked(()).proof(),
        );
        let request =
            format!("GET /user HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {sealed}\r\n\r\n");
        let mut client = Cursor::new(request.into_bytes());
        let mut upstream = Vec::new();
        let end = forward_requests(&flow, &mut client, &mut upstream);
        let records = records.lock().unwrap().clone();
        (String::from_utf8(upstream).unwrap(), end, records)
    }

    fn refused(end: &HalfEnd) -> Option<&'static str> {
        match end {
            HalfEnd::Refused(refusal) => Some(refusal.marker),
            HalfEnd::Closed(_) => None,
        }
    }

    // BEP-025: a sealed member from a registered box, to an authority its
    // declared egress admits, reaches the upstream with the credential in
    // place of the sealed value.
    #[test]
    fn sealed_member_is_redeemed_within_declared_egress() {
        let world = new_world();
        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(
            upstream.contains(&format!("Bearer {TOKEN}")),
            "the credential reaches the upstream: {upstream}"
        );
        assert!(!upstream.contains(&sealed), "the sealed value is replaced");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(
            records[0].identifier.as_deref(),
            Some(format!("github:{INSTANCE}").as_str())
        );
        assert!(!format!("{records:?}").contains(TOKEN));

        // BEP-022: the same value to a host the box did not declare is
        // refused, and nothing goes upstream.
        let github = Authority {
            host: "github.com".to_owned(),
            port: 443,
        };
        let (upstream, end, records) = send(&world, "b1", &github, "github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::OutsideDeclaredEgress.marker()));
        assert!(upstream.is_empty());
        assert_eq!(
            records[0].marker.as_deref(),
            Some(Check::OutsideDeclaredEgress.marker())
        );

        // A box that is not registered has no declared egress.
        let (upstream, end, _) = send(&world, "b9", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::OutsideDeclaredEgress.marker()));
        assert!(upstream.is_empty());

        // A revoked box's value is refused before the sign-in is read.
        world.revocations.write().unwrap().push("b1".into());
        let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::Revoked.marker()));
        assert!(upstream.is_empty());
        world.revocations.write().unwrap().clear();

        // With the sign-in gone, the admitted value resolves to nothing.
        world.redeemer.keychain.clear();
        let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty());
    }

    // BEP-020: a value sealed for one `own_ip` box, sent from another, is
    // refused before anything goes upstream. A forgotten box is no live box.
    #[test]
    fn cross_box_value_is_refused_cross_box() {
        let world = new_world();
        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        world.boxes.register("b2", vec![api()], Stance::OwnIp);
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b2", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::CrossBox.marker()));
        assert!(upstream.is_empty());
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(records[0].marker.as_deref(), Some("cross_box"));

        // A value sealed to another host's key does not open here.
        let other = new_world();
        other.boxes.register("b1", vec![api()], Stance::OwnIp);
        let (upstream, end, _) = send(&other, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::Undecryptable.marker()));
        assert!(upstream.is_empty());

        // The Host header must name the connection authority.
        let (upstream, end, _) = send(&world, "b1", &api(), "github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::HostMismatch.marker()));
        assert!(upstream.is_empty());

        // The redeemer refuses a box that is not registered as no live box.
        world.boxes.forget("b1");
        let request = RequestAuthority {
            host: Some(api()),
            target: None,
        };
        assert!(matches!(
            world.redeemer.redeem("b1", &api(), &request, &sealed),
            Verdict::Refuse("no_live_box")
        ));
    }

    /// A sealing key that counts its key agreements.
    struct Counting {
        inner: MemoryKey,
        agreements: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl HeldKey for Counting {
        fn role(&self) -> Role {
            self.inner.role()
        }
        fn public(&self) -> seal::ProxyPublicKey {
            self.inner.public()
        }
        fn exportable(&self) -> bool {
            self.inner.exportable()
        }
        fn agree(
            &self,
            peer: &seal::ProxyPublicKey,
        ) -> Result<Zeroizing<Vec<u8>>, crate::keys::KeyError> {
            self.agreements
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.agree(peer)
        }
        fn probe(&self) -> Result<(), crate::keys::KeyError> {
            self.inner.probe()
        }
    }

    #[test]
    fn host_ip_cohort_value_is_opened_once() {
        let agreements = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&agreements);
        let world = new_world_with(move |inner| Counting {
            inner,
            agreements: counter,
        });
        for id in ["c0", "c1", "c2", "c3", "c4"] {
            world.boxes.register(id, github(), Stance::HostIp);
        }
        let request = RequestAuthority {
            host: Some(api()),
            target: None,
        };
        let count = || agreements.swap(0, std::sync::atomic::Ordering::SeqCst);

        // The last cohort box in order: the old loop paid five agreements.
        let sealed = sealed_for(&world, "c4", NOW + 600, GITHUB.host_set_version);
        let verdict = world.redeemer.redeem("c0", &api(), &request, &sealed);
        assert!(matches!(verdict, Verdict::Admit { .. }));
        assert_eq!(count(), 1);

        // A value for a box outside the cohort pays one agreement too.
        let sealed = sealed_for(&world, "other", NOW + 600, GITHUB.host_set_version);
        let verdict = world.redeemer.redeem("c0", &api(), &request, &sealed);
        assert!(matches!(verdict, Verdict::Refuse(m) if m == Check::CrossBox.marker()));
        assert_eq!(count(), 1);
    }

    /// One scenario for the property test.
    #[derive(Debug, Clone)]
    struct Scenario {
        sender: usize,
        named: usize,
        stances: [Option<Stance>; 3],
        egress_api: [bool; 3],
        authority: usize,
        host_matches: bool,
        expired: bool,
        revoked: bool,
        old_version: bool,
        foreign_key: bool,
    }

    fn scenario() -> impl Strategy<Value = Scenario> {
        let stance = prop_oneof![
            Just(None),
            Just(Some(Stance::OwnIp)),
            Just(Some(Stance::HostIp))
        ];
        (
            (0usize..3, 0usize..3),
            [stance.clone(), stance.clone(), stance],
            any::<[bool; 3]>(),
            0usize..3,
            // Each failure is drawn rarely, so admits are common too.
            (
                prop::bool::weighted(0.85),
                prop::bool::weighted(0.15),
                prop::bool::weighted(0.15),
                prop::bool::weighted(0.15),
                prop::bool::weighted(0.15),
            ),
        )
            .prop_map(
                |(
                    (sender, named),
                    stances,
                    egress_api,
                    authority,
                    (host_matches, expired, revoked, old_version, foreign_key),
                )| Scenario {
                    sender,
                    named,
                    stances,
                    egress_api,
                    authority,
                    host_matches,
                    expired,
                    revoked,
                    old_version,
                    foreign_key,
                },
            )
    }

    const IDS: [&str; 3] = ["b0", "b1", "b2"];

    fn authority_of(i: usize) -> Authority<String> {
        match i {
            0 => api(),
            1 => Authority {
                host: "github.com".into(),
                port: 443,
            },
            _ => Authority {
                host: "example.com".into(),
                port: 443,
            },
        }
    }

    /// The decision for `s`, built from the scenario's own facts, with no
    /// call into the redeemer.
    fn expected(s: &Scenario) -> Option<&'static str> {
        let authority = authority_of(s.authority);
        let egress_of = |i: usize| -> Vec<Authority<String>> {
            match s.stances[i] {
                None => Vec::new(),
                Some(_) if s.egress_api[i] => vec![api(), authority_of(1)],
                Some(_) => vec![authority_of(1)],
            }
        };
        let request = RequestAuthority {
            host: Some(if s.host_matches {
                authority.clone()
            } else {
                authority_of((s.authority + 1) % 3)
            }),
            target: None,
        };
        // BEP-022 and BEP-023 hold before any redemption.
        let egress = egress_of(s.sender);
        if let Err(check) = redeem::decide_plain(&redeem::Plain {
            authority: authority.clone(),
            request: request.clone(),
            egress: egress.clone(),
        }) {
            return Some(check.marker());
        }
        let attribution = match s.stances[s.sender] {
            None => Attribution::NoLiveBox,
            Some(Stance::OwnIp) => Attribution::OwnIp(IDS[s.sender].to_owned()),
            Some(Stance::HostIp) => Attribution::HostIpCohort,
        };
        let in_cohort = s.stances[s.named] == Some(Stance::HostIp);
        let opens_for_sender = match s.stances[s.sender] {
            None | Some(Stance::OwnIp) => s.named == s.sender,
            Some(Stance::HostIp) => in_cohort,
        };
        let unsealed = if s.foreign_key {
            Unsealed::Undecryptable
        } else if !opens_for_sender {
            Unsealed::OtherBox
        } else if s.expired {
            Unsealed::Expired
        } else {
            Unsealed::Opened {
                box_id: IDS[s.named].to_owned(),
                bounds: redeem::Bounds {
                    mode: Some(Mode::User),
                    breadth: Some(Breadth::Full),
                },
                expiry: NOW + 600,
            }
        };
        let current = github();
        let decision = redeem::decide(&Redemption {
            unsealed,
            attribution: attribution.clone(),
            named_box_in_cohort: matches!(attribution, Attribution::HostIpCohort)
                && in_cohort
                && opens_for_sender,
            now: NOW,
            revoked: if s.revoked {
                vec![IDS[s.named].to_owned()]
            } else {
                Vec::new()
            },
            authority,
            bound_set: if s.old_version {
                Vec::new()
            } else {
                current.clone()
            },
            current_set: current.clone(),
            request,
            egress,
            handle: Handle {
                verified: true,
                bound: true,
                exp: NOW + 3600,
                upstream: current.clone(),
                inject: None::<Inject>,
                rule: Some(handle::Rule {
                    upstream: current,
                    inject: None,
                }),
            },
        });
        marker(decision)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        // BEP-025: through the serving shell, a request reaches the upstream
        // with the credential exactly when the pure decision admits it, and
        // a refusal names the check the decision names.
        #[test]
        fn prop_serve_redeems_iff_decide_admits(s in scenario()) {
            let world = new_world();
            for (i, stance) in s.stances.iter().enumerate() {
                if let Some(stance) = stance {
                    let egress = if s.egress_api[i] {
                        vec![api(), authority_of(1)]
                    } else {
                        vec![authority_of(1)]
                    };
                    world.boxes.register(IDS[i], egress, *stance);
                }
            }
            if s.revoked {
                world.revocations.write().unwrap().push(IDS[s.named].into());
            }
            let sealer = if s.foreign_key { new_world() } else { world_ref(&world) };
            let expiry = if s.expired { NOW } else { NOW + 600 };
            let version = if s.old_version { GITHUB.host_set_version + 1 } else { GITHUB.host_set_version };
            let sealed = sealed_for(&sealer, IDS[s.named], expiry, version);
            let authority = authority_of(s.authority);
            let host = if s.host_matches {
                authority.host.clone()
            } else {
                authority_of((s.authority + 1) % 3).host
            };
            let (upstream, end, _) = send(&world, IDS[s.sender], &authority, &host, &sealed);
            let want = expected(&s);
            prop_assert_eq!(refused(&end), want, "{:?}", s);
            prop_assert_eq!(upstream.contains(TOKEN), want.is_none());
            prop_assert_eq!(upstream.is_empty(), want.is_some());
        }
    }

    /// A world that seals with `world`'s keys.
    fn world_ref(world: &World) -> World {
        World {
            redeemer: Arc::clone(&world.redeemer),
            boxes: Arc::clone(&world.boxes),
            revocations: Arc::clone(&world.revocations),
            sealing: world.sealing,
            client: world.client.clone(),
        }
    }
}
