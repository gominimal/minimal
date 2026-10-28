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
//!    credential from the sign-in item in the host keychain. A token that
//!    has expired, or expires within 5 minutes, is renewed first, one
//!    renewal in flight per item (BEP-069). An admitted store member is
//!    given to the forwarder as [`Redeemed::Store`], and the forwarder reads
//!    its value from the host store (BEP-032).
//!
//! A revoked value is refused at step 4, so no reference is resolved for it
//! (BEP-071). The redeemer never logs or returns the credential except in
//! [`Verdict::Admit`], which the forwarder substitutes and zeroes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::audit::Mapping;
use crate::boxes::BoxRegistry;
use crate::control::Registry;
use crate::forward::{
    Ran, Redeemed, Redeemer, SEALED_HEADER_MISPLACED, SingleFlight, StoreAdmit, Verdict,
};
use crate::handle::{self, Handle, Rules, StoreRule};
use crate::keys::HeldKey;
use crate::module::Module;
use crate::redeem::{
    self, Attribution, Authority, Decision, Redemption, RequestAuthority, Unsealed,
};
use crate::seal::{self, Binding, MemberKind, OpenError, Opened};
use crate::signin::{self, Keychain, NoTokenEndpoint, RenewError, Resolved, TokenEndpoint};

/// The audit marker of an admitted redemption whose sign-in reference
/// resolves to no live sign-in: the item is gone, names another sign-in, or
/// its token expired and was not renewed.
pub const SIGN_IN_REQUIRED: &str = "github_sign_in_required";

/// The box ids that the revocations in force name.
pub type Revocations = Arc<RwLock<Vec<String>>>;

/// The source of the current `[secret-store-rules]`, asked at each request.
pub type StoreRules = Arc<dyn Rules + Send + Sync>;

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
    rules: StoreRules,
    clock: Clock,
    endpoint: Arc<dyn TokenEndpoint>,
    renewals: SingleFlight<Result<Resolved, RenewError>>,
    /// When the last renewal of each item failed, by instance. Within
    /// [`RENEW_RETRY_AFTER_SECS`] of it, no request calls GitHub again.
    failed_renewals: Mutex<HashMap<String, u64>>,
}

/// How long the proxy waits after a failed renewal of an item before it asks
/// GitHub again. A refused refresh token stays refused, and each attempt
/// can take up to 30 seconds, so a request in this window does not retry.
pub const RENEW_RETRY_AFTER_SECS: u64 = 60;

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
    /// The opened member's kind, or `None` when the value did not open.
    kind: Option<MemberKind>,
    /// The handle's `jti` for the audit record, or empty when the value did
    /// not open or the handle does not parse.
    jti: String,
}

impl<K: HeldKey, C: Keychain> BoxRedeemer<K, C> {
    /// A redeemer that opens values under `key` for Box Host `node` and
    /// `module`. It verifies handles under `clients`, reads each box from
    /// `boxes`, and resolves sign-in references from `keychain`. The clock
    /// is the system clock.
    ///
    /// A `revoke_box` request on the control socket puts a revocation in
    /// force ([`crate::revoke::record`]). `bep serve` passes the
    /// revocations restored from every retained audit segment through
    /// [`with_revocations`](Self::with_revocations) (BEP-068).
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
            rules: Arc::new(Vec::<StoreRule>::new()),
            clock: system_clock(),
            endpoint: Arc::new(NoTokenEndpoint),
            renewals: SingleFlight::default(),
            failed_renewals: Mutex::new(HashMap::new()),
        }
    }

    /// This redeemer, with `endpoint` as GitHub's token endpoint, which
    /// renews an expiring sign-in (BEP-069). With none, an expired token is
    /// refused.
    #[must_use]
    pub fn with_token_endpoint(mut self, endpoint: Arc<dyn TokenEndpoint>) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// This redeemer, with `revocations` as the revocations in force.
    #[must_use]
    pub fn with_revocations(mut self, revocations: Revocations) -> Self {
        self.revocations = revocations;
        self
    }

    /// This redeemer, with `rules` as the current `[secret-store-rules]`.
    /// With none, no store member is admitted.
    #[must_use]
    pub fn with_rules(mut self, rules: StoreRules) -> Self {
        self.rules = rules;
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
    /// The revoked set is the revocations in force that cover the box id
    /// the value names ([`crate::revoke::in_force_for`]). A `revoke_box` request on the
    /// control socket puts one in force. `bep serve` passes the
    /// revocations restored from every retained audit segment through
    /// [`with_revocations`](Self::with_revocations) (BEP-068).
    ///
    /// For a store member, the bound set is the handle's `upstream` and the
    /// current set is the current rule's authorities, so the checks that
    /// read a module's host sets read those (BEP-032, BEP-064). The rules
    /// are the ones [`Self::with_rules`] gives. `bep serve` gives the
    /// `[secret-store-rules]` of the user-level client `config.toml` merged
    /// over the organization's, less each rule the deny set refuses
    /// (BEP-034), read again when either file changes.
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
        let kind = opened.as_ref().map(|opened| opened.member.kind);
        let (bound_set, current_set, handle, identifier, jti) = match &opened {
            Some(opened) => {
                let read = {
                    let clients = self.clients.read().unwrap_or_else(PoisonError::into_inner);
                    handle::read_opened(opened, &clients, &*self.rules, &self.module, now)
                };
                let (bound_set, current_set) = match opened.member.kind {
                    MemberKind::Store => (
                        read.handle.upstream.clone(),
                        read.handle
                            .rule
                            .as_ref()
                            .map(|rule| rule.upstream.clone())
                            .unwrap_or_default(),
                    ),
                    // Only the module's current host-set version is known,
                    // so a value sealed under another version has an empty
                    // bound set.
                    MemberKind::SignIn => {
                        let bound_set =
                            if opened.context.host_set_version == self.module.host_set_version {
                                current_set.clone()
                            } else {
                                Vec::new()
                            };
                        (bound_set, current_set)
                    }
                };
                // Gatehouse §6.10: the audit record carries the handle's
                // `jti` as its correlation id. The `jti` is the claim even
                // when the signature does not verify, so a refusal of a
                // forged handle still correlates. `decide` admits only a
                // verified handle, so an admitted record's `jti` is verified.
                (
                    bound_set,
                    current_set,
                    read.handle,
                    read.identifier,
                    read.jti.unwrap_or_default(),
                )
            }
            None => (
                Vec::new(),
                current_set,
                Handle {
                    verified: false,
                    bound: false,
                    exp: 0,
                    upstream: Vec::new(),
                    inject: None,
                    rule: None,
                },
                None,
                String::new(),
            ),
        };
        let revoked = {
            let set = self
                .revocations
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            // The value's own box id, which differs from the source's for a
            // cohort member. A value that did not open names no box, and
            // `decide` refuses it before it reads this set.
            match &unsealed {
                Unsealed::Opened { box_id: named, .. } => crate::revoke::in_force_for(&set, named)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<String>>(),
                _ => Vec::new(),
            }
        };
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
            kind,
            jti,
        }
    }

    /// The verdict on a sign-in member, from its `facts` at clock reading
    /// `now`.
    fn sign_in_verdict(&self, box_id: &str, facts: Facts, now: u64) -> Verdict {
        let verdict = match redeem::decide(&facts.redemption) {
            Decision::Refuse(check) => Verdict::Refuse(check.marker()),
            decision @ Decision::Admit { .. } => {
                let identifier = facts.identifier.unwrap_or_default();
                match self.credential(&identifier, now) {
                    // The admission's marker reaches the audit record, so a
                    // cohort admission is recorded `cohort_attributed`
                    // (BEP-028).
                    Some((credential, renewed)) => Verdict::Admit {
                        credential,
                        identifier,
                        mapping: Mapping::ModuleUnmapped,
                        renewed,
                        marker: decision.marker(),
                        cohort_attributed: decision.cohort_attributed(),
                    },
                    None => Verdict::Refuse(SIGN_IN_REQUIRED),
                }
            }
        };
        tracing::debug!(box_id, ?verdict, jti = ?facts.jti, "sealed value decided");
        verdict
    }

    /// The decision on a store member, from its `facts` (BEP-032). An
    /// admitted member names the store, the identifier and the injection
    /// form for the forwarder, which reads the value. Nothing is read here.
    fn store_decision(box_id: &str, facts: Facts) -> Redeemed {
        let decided = match redeem::decide(&facts.redemption) {
            Decision::Refuse(check) => Redeemed::Verdict(Verdict::Refuse(check.marker())),
            decision @ Decision::Admit { .. } => {
                let reference = facts
                    .identifier
                    .as_deref()
                    .and_then(|identifier| identifier.split_once(':'));
                match (reference, facts.redemption.handle.inject) {
                    (Some((store, id)), Some(inject)) => Redeemed::Store(StoreAdmit {
                        store: store.to_owned(),
                        id: id.to_owned(),
                        inject,
                        mapping: Mapping::ModuleUnmapped,
                        marker: decision.marker(),
                        cohort_attributed: decision.cohort_attributed(),
                    }),
                    // A checked store handle names both, so this is not
                    // reached. It refuses rather than inject nothing.
                    _ => Redeemed::Verdict(Verdict::Refuse(
                        redeem::Check::StoreHandleInvalid.marker(),
                    )),
                }
            }
        };
        match &decided {
            Redeemed::Store(admit) => tracing::debug!(
                box_id,
                store = %admit.store,
                id = %admit.id,
                "store reference admitted"
            ),
            Redeemed::Verdict(verdict) => {
                tracing::debug!(box_id, ?verdict, "store reference decided")
            }
        }
        decided
    }

    /// The credential the sign-in reference `identifier` names, when the
    /// held sign-in is that one, and whether this request renewed it.
    ///
    /// A token that has expired or expires within 5 minutes goes to the
    /// renewal, one in flight per item (BEP-069). A request that finds a
    /// renewal in flight waits for its outcome and does not renew again.
    fn credential(&self, identifier: &str, now: u64) -> Option<(Zeroizing<String>, bool)> {
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
        if metadata.instance != instance {
            return None;
        }
        if metadata.needs_renewal(now) && !self.renewal_backed_off(instance, now) {
            let ran = self.renewals.run(instance, || {
                let outcome = signin::renew(&self.keychain, self.endpoint.as_ref(), instance, now);
                self.record_renewal(instance, &outcome, now);
                outcome
            });
            return match ran {
                Ran::Led(Ok(resolved)) => Some((resolved.token, resolved.renewed)),
                Ran::Waited(Ok(resolved)) => Some((resolved.token, false)),
                Ran::Led(Err(error)) | Ran::Waited(Err(error)) => {
                    tracing::debug!(%error, "the sign-in reference resolved to no token");
                    None
                }
                Ran::Abandoned => None,
                Ran::TimedOut => {
                    tracing::warn!(
                        "the sign-in renewal in flight did not end in time; the request is refused"
                    );
                    None
                }
            };
        }
        if now >= metadata.token_expires_at {
            // A renewal failed within the back-off, and the token expired.
            tracing::debug!("the sign-in reference resolved to an expired token");
            return None;
        }
        match self.keychain.material() {
            Ok(Some(material)) if material.instance == instance => {
                Some((Zeroizing::new(material.access_token.clone()), false))
            }
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "the sign-in item was not read");
                None
            }
        }
    }
}

impl<K, C> BoxRedeemer<K, C> {
    /// True when the last renewal of `instance` failed less than
    /// [`RENEW_RETRY_AFTER_SECS`] before `now`.
    fn renewal_backed_off(&self, instance: &str, now: u64) -> bool {
        self.failed_renewals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(instance)
            .is_some_and(|&failed| now < failed.saturating_add(RENEW_RETRY_AFTER_SECS))
    }

    /// Record the outcome of a renewal of `instance`. A renewal that gave no
    /// new token starts the back-off. A renewed token ends it.
    fn record_renewal(&self, instance: &str, outcome: &Result<Resolved, RenewError>, now: u64) {
        let mut failed = self
            .failed_renewals
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match outcome {
            // A renewed token, or a token that another renewal already wrote
            // with time to live. Nothing failed.
            Ok(resolved) if !resolved.failed => {
                failed.remove(instance);
            }
            _ => {
                failed.insert(instance.to_owned(), now);
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
        self.redeem_with_jti(box_id, authority, request, sealed).0
    }

    fn redeem_with_jti(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
    ) -> (Verdict, String) {
        let now = (self.clock)();
        let facts = self.facts(box_id, authority, request, sealed, now);
        let jti = facts.jti.clone();
        (self.sign_in_verdict(box_id, facts, now), jti)
    }

    /// Decides one request that carries `sealed` in the header named
    /// `header`. An admitted store member is [`Redeemed::Store`], and the
    /// forwarder checks that `header` is where the rule's injection form
    /// puts the value (BEP-032).
    ///
    /// Any other value in a header other than `Authorization` is refused as
    /// [`SEALED_HEADER_MISPLACED`] before it is decided, so no sign-in is
    /// read or renewed for it.
    fn redeem_reference(
        &self,
        box_id: &str,
        authority: &Authority<String>,
        request: &RequestAuthority<String>,
        sealed: &str,
        header: &str,
    ) -> (Redeemed, String) {
        let now = (self.clock)();
        let facts = self.facts(box_id, authority, request, sealed, now);
        let jti = facts.jti.clone();
        if facts.kind == Some(MemberKind::Store) {
            return (Self::store_decision(box_id, facts), jti);
        }
        if !header.eq_ignore_ascii_case("authorization") {
            return (
                Redeemed::Verdict(Verdict::Refuse(SEALED_HEADER_MISPLACED)),
                String::new(),
            );
        }
        (
            Redeemed::Verdict(self.sign_in_verdict(box_id, facts, now)),
            jti,
        )
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
    const REFRESH: &str = "ghr_refresh";

    struct World<K = MemoryKey, C = MemoryKeychain> {
        redeemer: Arc<BoxRedeemer<K, C>>,
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
        let keychain = MemoryKeychain::default();
        seed(&keychain, NOW + 3600, NOW + 7200);
        world_over(key, keychain, |redeemer| redeemer)
    }

    /// Hold the sign-in `INSTANCE` in `keychain`, with token `TOKEN`.
    fn seed(keychain: &dyn Keychain, token_expires_at: u64, refresh_expires_at: u64) {
        keychain
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: SignInFlow::Device,
                    token_expires_at,
                    refresh_expires_at,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: TOKEN.into(),
                    refresh_token: REFRESH.into(),
                },
            )
            .unwrap();
    }

    /// A world over sealing key `key` and `keychain`, with the redeemer
    /// that `configure` gives.
    fn world_over<K: HeldKey, C: Keychain>(
        key: K,
        keychain: C,
        configure: impl FnOnce(BoxRedeemer<K, C>) -> BoxRedeemer<K, C>,
    ) -> World<K, C> {
        let sealing = key.public();
        let client = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let mut keys = ClientKeys::new();
        keys.register(&client.verifying_key().to_sec1_bytes())
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
            redeemer: Arc::new(configure(redeemer)),
            boxes,
            revocations,
            sealing,
            client,
        }
    }

    /// A value sealed for `box_id` on this node, with a sign-in member.
    fn sealed_for<K, C>(world: &World<K, C>, box_id: &str, expiry: u64, version: u32) -> String {
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
    fn send<C: Keychain + Send + Sync + 'static>(
        world: &World<MemoryKey, C>,
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

    /// A value sealed for `box_id` on this node, with one store-handle
    /// member whose `jti` is `jti`.
    fn sealed_store_for<K, C>(world: &World<K, C>, box_id: &str, jti: &str) -> String {
        let jws = handle::sign(
            &world.client,
            &Claims {
                sub: box_id.into(),
                node_id: NODE.into(),
                store: "keychain".into(),
                id: "anthropic".into(),
                upstream: vec!["api.github.com".into()],
                inject: Some(Inject::Header {
                    name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                }),
                iat: NOW - 10,
                exp: NOW + 3600,
                jti: jti.into(),
            },
        );
        seal::seal(
            &world.sealing,
            &Context {
                box_id: box_id.into(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry: NOW + 600,
                kid: world.sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::Store,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap()
    }

    // BEP-067 (Gatehouse §6.10): a redeemed member and a refused store
    // member both write an audit record that carries the handle's `jti`.
    // A value that does not open has no handle, so its `jti` is empty.
    #[test]
    fn a_store_handle_audit_record_carries_its_jti() {
        let world = new_world();
        world.boxes.register("b1", vec![api()], Stance::OwnIp);

        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (_, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(records[0].jti, "jti-1");
        let line = crate::audit::Record::from_decision(&records[0], crate::audit::ZERO_HASH);
        assert_eq!(line.jti, "jti-1");

        let sealed = sealed_store_for(&world, "b1", "jti-store-7");
        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::StoreHandleInvalid.marker()));
        assert!(upstream.is_empty());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(records[0].marker.as_deref(), Some("store_handle_invalid"));
        assert_eq!(records[0].jti, "jti-store-7");
        let line = crate::audit::Record::from_decision(&records[0], crate::audit::ZERO_HASH);
        assert_eq!(line.jti, "jti-store-7");

        // A value sealed to another host's key does not open here.
        let other = new_world();
        other.boxes.register("b1", vec![api()], Stance::OwnIp);
        let (_, end, records) = send(&other, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(Check::Undecryptable.marker()));
        assert_eq!(records[0].jti, "");
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

    // BEP-028: a `host_ip` sender that presents a value naming another live
    // `host_ip` box is admitted, and its audit record is marked
    // `cohort_attributed`. An admission from the named box itself carries
    // no marker.
    #[test]
    fn host_ip_redemption_is_cohort_attributed_in_the_audit_record() {
        let world = new_world();
        world.boxes.register("c1", github(), Stance::HostIp);
        world.boxes.register("c2", github(), Stance::HostIp);
        let sealed = sealed_for(&world, "c2", NOW + 600, GITHUB.host_set_version);
        let (upstream, end, records) = send(&world, "c1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(upstream.contains(&format!("Bearer {TOKEN}")));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(records[0].marker.as_deref(), Some("cohort_attributed"));

        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (_, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(records[0].marker, None);
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

    const RENEWED: &str = "ghu_the_renewed_token";
    const RENEWED_REFRESH: &str = "ghr_renewed";

    /// A stand-in for GitHub's token endpoint. It counts the refreshes,
    /// records the refresh tokens it got, and runs `during` before it
    /// answers.
    #[derive(Default)]
    struct FakeEndpoint {
        calls: std::sync::atomic::AtomicUsize,
        got: std::sync::Mutex<Vec<String>>,
        refuse: bool,
        during: Option<Box<dyn Fn() + Send + Sync>>,
    }

    impl FakeEndpoint {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl TokenEndpoint for FakeEndpoint {
        fn refresh(
            &self,
            flow: SignInFlow,
            refresh_token: &str,
        ) -> Result<signin::Refreshed, signin::RefreshError> {
            assert_eq!(flow, SignInFlow::Device);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.got.lock().unwrap().push(refresh_token.to_owned());
            if let Some(during) = &self.during {
                during();
            }
            if self.refuse {
                return Err(signin::RefreshError::Refused("bad_refresh_token".into()));
            }
            Ok(signin::Refreshed {
                access_token: RENEWED.into(),
                refresh_token: RENEWED_REFRESH.into(),
                expires_in: 28_800,
                refresh_token_expires_in: 15_897_600,
            })
        }
    }

    /// A world whose held token expires at `token_expires_at`, renewed
    /// through `endpoint`.
    fn renewal_world<C: Keychain>(
        keychain: C,
        token_expires_at: u64,
        refresh_expires_at: u64,
        endpoint: Arc<FakeEndpoint>,
    ) -> World<MemoryKey, C> {
        seed(&keychain, token_expires_at, refresh_expires_at);
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let world = world_over(key, keychain, |redeemer| {
            redeemer.with_token_endpoint(endpoint)
        });
        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        world
    }

    fn renewal_records(records: &[Record]) -> usize {
        records
            .iter()
            .filter(|r| r.marker.as_deref() == Some(crate::forward::SIGN_IN_RENEWED))
            .count()
    }

    // BEP-069: an expired token, and one that expires within 5 minutes, is
    // renewed from the refresh material, written to the same item, and the
    // renewed token is substituted. The renewal is its own audit record.
    #[test]
    fn an_expiring_sign_in_is_renewed_at_the_proxy() {
        for token_expires_at in [NOW - 1, NOW + signin::RENEW_WITHIN_SECS] {
            let endpoint = Arc::new(FakeEndpoint::default());
            let world = renewal_world(
                MemoryKeychain::default(),
                token_expires_at,
                NOW + 86_400,
                Arc::clone(&endpoint),
            );
            let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

            let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
            assert_eq!(refused(&end), None, "{end:?}");
            assert!(
                upstream.contains(&format!("Bearer {RENEWED}")),
                "{upstream}"
            );
            assert!(!upstream.contains(TOKEN));
            assert_eq!(endpoint.calls(), 1);
            assert_eq!(*endpoint.got.lock().unwrap(), vec![REFRESH.to_owned()]);

            // The same item holds the renewed material, under the same
            // instance.
            let keychain = &world.redeemer.keychain;
            let metadata = keychain.metadata().unwrap().unwrap();
            assert_eq!(metadata.instance, INSTANCE);
            assert_eq!(metadata.token_expires_at, NOW + 28_800);
            assert_eq!(metadata.refresh_expires_at, NOW + 15_897_600);
            let material = keychain.material().unwrap().unwrap();
            assert_eq!(material.access_token, RENEWED);
            assert_eq!(material.refresh_token, RENEWED_REFRESH);

            // One renewal record, then the decision.
            assert_eq!(records.len(), 2, "{records:?}");
            assert_eq!(
                records[0].marker.as_deref(),
                Some(crate::forward::SIGN_IN_RENEWED)
            );
            assert_eq!(
                records[0].identifier.as_deref(),
                Some(format!("github:{INSTANCE}").as_str())
            );
            assert_eq!(records[1].outcome, Outcome::Admit);
            assert_eq!(records[1].marker, None);
            assert!(!format!("{records:?}").contains(RENEWED));

            // The next request uses the renewed token and renews nothing.
            let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
            assert_eq!(refused(&end), None, "{end:?}");
            assert!(upstream.contains(&format!("Bearer {RENEWED}")));
            assert_eq!(endpoint.calls(), 1);
            assert_eq!(renewal_records(&records), 0);
        }
    }

    // BEP-069: while one renewal is in flight, the other requests for the
    // item wait for its outcome and do not renew again.
    #[test]
    fn concurrent_redemptions_share_one_renewal() {
        let endpoint = Arc::new(FakeEndpoint {
            during: Some(Box::new(|| {
                std::thread::sleep(std::time::Duration::from_millis(300));
            })),
            ..FakeEndpoint::default()
        });
        let world = renewal_world(
            MemoryKeychain::default(),
            NOW - 1,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let requests = 8;
        let barrier = std::sync::Barrier::new(requests);
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..requests)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        send(&world, "b1", &api(), "api.github.com", &sealed)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(endpoint.calls(), 1, "one renewal for every request");
        let mut renewals = 0;
        for (upstream, end, records) in &results {
            assert_eq!(refused(end), None, "{end:?}");
            assert!(
                upstream.contains(&format!("Bearer {RENEWED}")),
                "{upstream}"
            );
            renewals += renewal_records(records);
        }
        assert_eq!(renewals, 1, "the one renewal is audited once");
    }

    /// A keychain that reads from a memory keychain and refuses every write.
    struct RefusingWrites(MemoryKeychain);

    impl Keychain for RefusingWrites {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.0.metadata()
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.0.material()
        }
        fn write(
            &self,
            metadata: &Metadata,
            material: &Material,
        ) -> Result<(), signin::SignInError> {
            // The seed goes in. Every later write is refused.
            if self.0.metadata()?.is_none() {
                return self.0.write(metadata, material);
            }
            Err(signin::SignInError::Keychain {
                action: "write the sign-in",
                detail: "locked".into(),
            })
        }
    }

    // BEP-069: a renewal that is not written to the item refuses the
    // request and substitutes nothing.
    #[test]
    fn renewal_not_persisted_is_refused() {
        let endpoint = Arc::new(FakeEndpoint::default());
        let world = renewal_world(
            RefusingWrites(MemoryKeychain::default()),
            NOW - 1,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(endpoint.calls(), 1);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty(), "{upstream}");
        assert_eq!(renewal_records(&records), 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Refuse);
        let material = world.redeemer.keychain.material().unwrap().unwrap();
        assert_eq!(material.access_token, TOKEN, "the item is unchanged");
    }

    /// A keychain over a memory keychain that refuses every write while
    /// `refuse` is set.
    struct SwitchedWrites {
        inner: MemoryKeychain,
        refuse: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Keychain for SwitchedWrites {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.inner.metadata()
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.inner.material()
        }
        fn write(
            &self,
            metadata: &Metadata,
            material: &Material,
        ) -> Result<(), signin::SignInError> {
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(signin::SignInError::Keychain {
                    action: "write the sign-in",
                    detail: "locked".into(),
                });
            }
            self.inner.write(metadata, material)
        }
    }

    // BEP-069: a renewal that the item did not take is discarded, and the
    // request is refused. After the back-off, the next renewal asks GitHub
    // again with the refresh token in the item, not with a held one.
    #[test]
    fn an_unsaved_renewal_is_discarded_and_renewed_from_the_item() {
        let endpoint = Arc::new(FakeEndpoint::default());
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
        let now = Arc::clone(&clock);
        let refuse = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let keychain = SwitchedWrites {
            inner: MemoryKeychain::default(),
            refuse: Arc::clone(&refuse),
        };
        seed(&keychain, NOW - 1, NOW + 86_400);
        refuse.store(true, std::sync::atomic::Ordering::SeqCst);
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let world = world_over(key, keychain, |redeemer| {
            redeemer
                .with_token_endpoint(Arc::clone(&endpoint) as Arc<dyn TokenEndpoint>)
                .with_clock(Arc::new(move || {
                    now.load(std::sync::atomic::Ordering::SeqCst)
                }))
        });
        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty(), "{upstream}");
        assert_eq!(renewal_records(&records), 0);
        assert_eq!(endpoint.calls(), 1);

        clock.store(
            NOW + RENEW_RETRY_AFTER_SECS,
            std::sync::atomic::Ordering::SeqCst,
        );
        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty(), "{upstream}");
        assert_eq!(renewal_records(&records), 0);
        assert_eq!(endpoint.calls(), 2, "GitHub is asked again");
        assert_eq!(
            *endpoint.got.lock().unwrap(),
            vec![REFRESH.to_owned(), REFRESH.to_owned()],
            "each renewal presents the item's refresh token"
        );
        let material = world.redeemer.keychain.material().unwrap().unwrap();
        assert_eq!(material.access_token, TOKEN, "the item is unchanged");
        assert_eq!(material.refresh_token, REFRESH, "the item is unchanged");
    }

    // BEP-069: an item deleted while its renewal runs stays deleted. The
    // renewed material is discarded and the request is refused.
    #[test]
    fn renewal_finding_item_deleted_refuses_and_creates_nothing() {
        let keychain = Arc::new(MemoryKeychain::default());
        let logout = Arc::clone(&keychain);
        let endpoint = Arc::new(FakeEndpoint {
            during: Some(Box::new(move || logout.clear())),
            ..FakeEndpoint::default()
        });
        let world = renewal_world(
            Arc::clone(&keychain),
            NOW - 1,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(endpoint.calls(), 1);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty(), "{upstream}");
        assert_eq!(renewal_records(&records), 0);
        assert_eq!(keychain.item(signin::SERVICE), None, "no item is created");
        assert_eq!(
            keychain.item(signin::META_SERVICE),
            None,
            "no item is created"
        );
    }

    // BEP-069: a token that expires more than 5 minutes after the request is
    // substituted without a renewal.
    #[test]
    fn a_sign_in_with_time_to_live_is_not_renewed() {
        let endpoint = Arc::new(FakeEndpoint::default());
        let world = renewal_world(
            MemoryKeychain::default(),
            NOW + signin::RENEW_WITHIN_SECS + 1,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(upstream.contains(&format!("Bearer {TOKEN}")), "{upstream}");
        assert_eq!(endpoint.calls(), 0);
        assert_eq!(records.len(), 1);
        assert_eq!(renewal_records(&records), 0);
    }

    // BEP-069: an expired token that GitHub refuses to renew, or whose
    // refresh material expired too, is refused `github_sign_in_required`.
    #[test]
    fn unrenewable_sign_in_refuses_with_sign_in_required() {
        // GitHub refuses the renewal of an expired token.
        let endpoint = Arc::new(FakeEndpoint {
            refuse: true,
            ..FakeEndpoint::default()
        });
        let world = renewal_world(
            MemoryKeychain::default(),
            NOW - 1,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(endpoint.calls(), 1);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(records[0].marker.as_deref(), Some(SIGN_IN_REQUIRED));
        let material = world.redeemer.keychain.material().unwrap().unwrap();
        assert_eq!(material.access_token, TOKEN, "the item is unchanged");

        // The refresh material expired too: GitHub is not asked.
        let endpoint = Arc::new(FakeEndpoint::default());
        let world = renewal_world(
            MemoryKeychain::default(),
            NOW - 7200,
            NOW - 1,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (upstream, end, records) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(endpoint.calls(), 0);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty());
        assert_eq!(records[0].marker.as_deref(), Some(SIGN_IN_REQUIRED));

        // A token that has not expired yet is still substituted when GitHub
        // refuses its early renewal.
        let endpoint = Arc::new(FakeEndpoint {
            refuse: true,
            ..FakeEndpoint::default()
        });
        let world = renewal_world(
            MemoryKeychain::default(),
            NOW + 60,
            NOW + 86_400,
            Arc::clone(&endpoint),
        );
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(endpoint.calls(), 1);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(upstream.contains(&format!("Bearer {TOKEN}")));
    }

    // BEP-069: a failed renewal is not retried on every request. Within the
    // back-off the held token is used while it lives, and GitHub is not
    // asked again. After the back-off, the next request asks once more.
    #[test]
    fn a_failed_renewal_is_not_retried_within_the_back_off() {
        let endpoint = Arc::new(FakeEndpoint {
            refuse: true,
            ..FakeEndpoint::default()
        });
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
        let now = Arc::clone(&clock);
        let keychain = MemoryKeychain::default();
        seed(&keychain, NOW + 100, NOW + 86_400);
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let world = world_over(key, keychain, |redeemer| {
            redeemer
                .with_token_endpoint(Arc::clone(&endpoint) as Arc<dyn TokenEndpoint>)
                .with_clock(Arc::new(move || {
                    now.load(std::sync::atomic::Ordering::SeqCst)
                }))
        });
        world.boxes.register("b1", vec![api()], Stance::OwnIp);
        let sealed = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);

        for _ in 0..3 {
            let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
            assert_eq!(refused(&end), None, "{end:?}");
            assert!(upstream.contains(&format!("Bearer {TOKEN}")));
        }
        assert_eq!(endpoint.calls(), 1, "one call to GitHub in the back-off");

        clock.store(
            NOW + RENEW_RETRY_AFTER_SECS,
            std::sync::atomic::Ordering::SeqCst,
        );
        let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(upstream.contains(&format!("Bearer {TOKEN}")));
        assert_eq!(endpoint.calls(), 2, "the back-off ended");

        // The token expires inside the next back-off: the request is refused
        // `github_sign_in_required`, and GitHub is not asked.
        clock.store(NOW + 101, std::sync::atomic::Ordering::SeqCst);
        let (upstream, end, _) = send(&world, "b1", &api(), "api.github.com", &sealed);
        assert_eq!(refused(&end), Some(SIGN_IN_REQUIRED));
        assert!(upstream.is_empty());
        assert_eq!(endpoint.calls(), 2);
    }

    const STORE_ID: &str = "openai";
    const STORED_KEY: &str = "sk-stored-key";

    fn openai() -> Authority<String> {
        Authority {
            host: "api.openai.com".into(),
            port: 443,
        }
    }

    fn bearer() -> Inject {
        Inject::Header {
            name: "Authorization".into(),
            prefix: Some("Bearer ".into()),
        }
    }

    /// The `[secret-store-rules]` rule for [`STORE_ID`] in the keychain:
    /// `api.openai.com`, as a bearer token.
    fn openai_rule() -> StoreRule {
        StoreRule {
            store: crate::store::NATIVE_STORE.into(),
            id: STORE_ID.into(),
            upstream: vec!["api.openai.com".into()],
            inject: bearer(),
        }
    }

    /// A value sealed for `box_id` on this node, with a store member for
    /// [`STORE_ID`] in the keychain, to `api.openai.com` as a bearer token.
    fn store_sealed_for<K, C>(world: &World<K, C>, box_id: &str) -> String {
        let jws = handle::sign(
            &world.client,
            &Claims {
                sub: box_id.into(),
                node_id: NODE.into(),
                store: crate::store::NATIVE_STORE.into(),
                id: STORE_ID.into(),
                upstream: vec!["api.openai.com".into()],
                inject: Some(bearer()),
                iat: NOW - 10,
                exp: NOW + 3600,
                jti: "jti-store".into(),
            },
        );
        seal::seal(
            &world.sealing,
            &Context {
                box_id: box_id.into(),
                host: NODE.into(),
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: NOW - 10,
                expiry: NOW + 600,
                kid: world.sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::Store,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap()
    }

    /// Sends one request from `box_id` to `api.openai.com` with
    /// `sealed_header` on a flow that reads store values from `store`, as
    /// `bep serve` builds it. Gives what reached the upstream, how the half
    /// ended, and the audit records.
    fn send_to_store(
        world: &World,
        box_id: &str,
        store: Arc<dyn crate::store::ValueReader>,
        sealed_header: &str,
    ) -> (String, HalfEnd, Vec<Record>) {
        let records = Arc::new(std::sync::Mutex::new(Vec::<Record>::new()));
        let audit: Arc<dyn AuditWriter> = records.clone();
        let redeemer: Arc<dyn Redeemer> = world.redeemer.clone();
        let flow = Flow::new(
            box_id,
            openai(),
            audit,
            redeemer,
            Validated::unchecked(()).proof(),
        )
        .with_store(store);
        let request =
            format!("GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n{sealed_header}\r\n\r\n");
        let mut client = Cursor::new(request.into_bytes());
        let mut upstream = Vec::new();
        let end = forward_requests(&flow, &mut client, &mut upstream);
        let records = records.lock().unwrap().clone();
        (String::from_utf8(upstream).unwrap(), end, records)
    }

    // BEP-032: a store member that passes every check reaches the rule's
    // registered upstream with the stored key in the registered form. The
    // box holds only the sealed value, and the audit names the store and
    // the identifier, never the key.
    #[test]
    fn serve_injects_a_stored_key_for_an_admitted_store_member() {
        use crate::store::{MemoryReader, MemorySecretStore, SecretStore as _};

        let keychain = MemoryKeychain::default();
        seed(&keychain, NOW + 3600, NOW + 7200);
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let world = world_over(key, keychain, |redeemer| {
            redeemer.with_rules(Arc::new(vec![openai_rule()]))
        });
        world.boxes.register("b1", vec![openai()], Stance::OwnIp);
        let program = std::path::PathBuf::from("/opt/minimal/bin/bep");
        let store = Arc::new(MemorySecretStore::default());
        store
            .set(STORE_ID, STORED_KEY.as_bytes(), &program)
            .unwrap();
        let reader: Arc<dyn crate::store::ValueReader> = Arc::new(MemoryReader {
            store: Arc::clone(&store),
            app: program,
        });
        let sealed = store_sealed_for(&world, "b1");
        assert!(!sealed.contains(STORED_KEY), "the box never holds the key");

        let bearer_header = format!("Authorization: Bearer {sealed}");
        let (upstream, end, records) =
            send_to_store(&world, "b1", Arc::clone(&reader), &bearer_header);
        assert_eq!(refused(&end), None, "{end:?}");
        assert!(
            upstream.contains(&format!("\r\nauthorization: Bearer {STORED_KEY}\r\n")),
            "{upstream}"
        );
        assert!(!upstream.contains(&sealed), "the sealed value is replaced");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, Outcome::Admit);
        assert_eq!(records[0].identifier.as_deref(), Some("keychain:openai"));
        assert!(!format!("{records:?}").contains(STORED_KEY));

        // The same value from another box is refused, and nothing goes
        // upstream (BEP-020).
        world.boxes.register("b2", vec![openai()], Stance::OwnIp);
        let (upstream, end, _) = send_to_store(&world, "b2", Arc::clone(&reader), &bearer_header);
        assert_eq!(refused(&end), Some(Check::CrossBox.marker()));
        assert!(upstream.is_empty());

        // In a header that the rule does not name, it is refused before the
        // store is read.
        let (upstream, end, _) = send_to_store(
            &world,
            "b1",
            Arc::clone(&reader),
            &format!("x-api-key: {sealed}"),
        );
        assert_eq!(refused(&end), Some(SEALED_HEADER_MISPLACED));
        assert!(upstream.is_empty());

        // A sign-in member outside `Authorization` is still refused before
        // it is decided.
        let sign_in = sealed_for(&world, "b1", NOW + 600, GITHUB.host_set_version);
        let (upstream, end, _) = send_to_store(
            &world,
            "b1",
            Arc::clone(&reader),
            &format!("x-api-key: {sign_in}"),
        );
        assert_eq!(refused(&end), Some(SEALED_HEADER_MISPLACED));
        assert!(upstream.is_empty());

        // With no rule for the item, the handle is invalid (BEP-064).
        let keychain = MemoryKeychain::default();
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let bare = world_over(key, keychain, |redeemer| redeemer);
        bare.boxes.register("b1", vec![openai()], Stance::OwnIp);
        let sealed = store_sealed_for(&bare, "b1");
        let (upstream, end, _) = send_to_store(
            &bare,
            "b1",
            Arc::clone(&reader),
            &format!("Authorization: Bearer {sealed}"),
        );
        assert_eq!(refused(&end), Some(Check::StoreHandleInvalid.marker()));
        assert!(upstream.is_empty());
    }

    // The store `bep serve` opens off macOS reads nothing, so an admitted
    // store member is refused `store_item_unreadable`, never forwarded
    // without the key.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn serve_refuses_an_unreadable_store_member() {
        let keychain = MemoryKeychain::default();
        let key = MemoryStore::default().generate(Role::Sealing).unwrap();
        let world = world_over(key, keychain, |redeemer| {
            redeemer.with_rules(Arc::new(vec![openai_rule()]))
        });
        world.boxes.register("b1", vec![openai()], Stance::OwnIp);
        let sealed = store_sealed_for(&world, "b1");
        let (upstream, end, records) = send_to_store(
            &world,
            "b1",
            Arc::new(crate::store::HostStore),
            &format!("Authorization: Bearer {sealed}"),
        );
        assert_eq!(refused(&end), Some(crate::forward::STORE_ITEM_UNREADABLE));
        assert!(upstream.is_empty());
        assert_eq!(records[0].outcome, Outcome::Refuse);
        assert_eq!(
            records[0].marker.as_deref(),
            Some(crate::forward::STORE_ITEM_UNREADABLE)
        );
    }
}
