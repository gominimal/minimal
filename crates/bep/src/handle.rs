//! Store handles: the wire format, the client-key registry, and the check
//! against the current rule (BEP-063, BEP-064).
//!
//! A store handle is the signed reference a sealed member carries in its
//! `jws`. The client signs it under its local key, and registers that key
//! with the proxy. A sign-in reference (BEP-005) has the same wire format.
//!
//! The wire format is a compact JWS, `header.payload.signature`, each part in
//! unpadded base64url:
//!
//! - The header is `{"alg":"ES256","typ":"gatehouse-store-handle+jws",
//!   "kid":<kid>}`. `kid` is the RFC 7638 thumbprint of the signing key (see
//!   [`crate::seal::ProxyPublicKey::kid`]).
//! - The payload is a [`Claims`]: `sub`, `node_id`, `store`, `id`,
//!   `upstream`, `inject`, `iat`, `exp` and `jti`.
//! - The signature is ES256 over `header.payload`, as the 64-byte `r || s`.
//!
//! The handle's kind is not in the payload. The sealed member carries it,
//! as `{kind, jws}`.
//!
//! The proxy reads a handle with [`read_opened`] at each request, from the
//! member that [`crate::seal::open`] opened. It looks up the signing key in
//! the [`ClientKeys`] registry. It compares `sub` and `node_id` with the box
//! id and the Box Host of the opened value. It reads the current rule for
//! the handle's store and identifier from a [`Rules`] source. It keeps no
//! copy of a rule, so an edited rule decides the next request. A sign-in
//! reference has the module as its rule: the module's current authorities
//! and no injection form.
//!
//! [`read_opened`] gives the facts as a [`Handle`]. [`Handle::check`] is the
//! BEP-064 decision. It is pure, and [`crate::redeem::decide`] makes it.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::module::{HTTPS_PORT, Module};
use crate::redeem::Authority;
use crate::seal::{MemberKind, Opened, ProxyPublicKey};

/// The JWS `alg` of every handle.
pub const ALG: &str = "ES256";

/// The JWS `typ` of every handle.
pub const TYP: &str = "gatehouse-store-handle+jws";

/// What a handle refers to. The sealed member carries the kind, not the
/// handle's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleKind {
    /// An item in a host store, under a `[secret-store-rules]` rule.
    Store,
    /// The host's GitHub sign-in item (BEP-005). The GitHub module is its
    /// rule.
    SignIn,
}

/// How the proxy injects a store value into a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum Inject {
    /// A header, with an optional prefix before the value.
    Header {
        /// The header name.
        name: String,
        /// The text before the value, such as `Bearer `.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
    },
    /// HTTP basic authentication, with the value in one field.
    BasicAuth {
        /// The field that carries the value: `user` or `password`.
        field: String,
    },
}

/// The payload of a handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The id of the box the handle was minted for.
    pub sub: String,
    /// The Box Host whose proxy redeems the handle.
    pub node_id: String,
    /// The store. A sign-in reference carries the module identifier.
    pub store: String,
    /// The item's identifier in the store. A sign-in reference carries the
    /// sign-in's instance identifier.
    pub id: String,
    /// The upstream authorities, each `host` or `host:port`. A `host` with
    /// no port is port 443.
    pub upstream: Vec<String>,
    /// The injection form. A sign-in reference carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<Inject>,
    /// The time of the mint, in seconds since the Unix epoch.
    pub iat: u64,
    /// The expiry, in seconds since the Unix epoch.
    pub exp: u64,
    /// The handle's unique id. The audit uses it to correlate records.
    pub jti: String,
}

impl Claims {
    /// The identifier an audit record carries for this handle:
    /// `<store>:<id>`.
    #[must_use]
    pub fn identifier(&self) -> String {
        format!("{}:{}", self.store, self.id)
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// Why a handle did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyError {
    /// The handle is not a compact JWS with this header and payload.
    Malformed,
    /// No registered client key has the handle's `kid`.
    UnknownKey,
    /// The signature does not verify under the registered key.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
        })
    }
}

impl std::error::Error for VerifyError {}

/// The thumbprint of a client key, as a handle's `kid` carries it.
#[must_use]
pub fn kid(key: &VerifyingKey) -> String {
    ProxyPublicKey::from_sec1_bytes(&key.to_sec1_bytes())
        .map(|public| public.kid())
        .unwrap_or_default()
}

/// The client keys registered with the proxy. A handle verifies only under
/// one of them.
#[derive(Debug, Clone, Default)]
pub struct ClientKeys {
    keys: Vec<(String, VerifyingKey)>,
}

impl ClientKeys {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a client key from its SEC1 encoding, and returns its `kid`.
    /// A key already registered is not added again.
    ///
    /// # Errors
    ///
    /// [`VerifyError::Malformed`] when the bytes are not a P-256 point.
    pub fn register(&mut self, sec1: &[u8]) -> Result<String, VerifyError> {
        let key = VerifyingKey::from_sec1_bytes(sec1).map_err(|_| VerifyError::Malformed)?;
        let kid = kid(&key);
        if !self.keys.iter().any(|(k, _)| *k == kid) {
            self.keys.push((kid.clone(), key));
        }
        Ok(kid)
    }

    /// Whether a key with this `kid` is registered.
    #[must_use]
    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|(k, _)| k == kid)
    }

    fn get(&self, kid: &str) -> Option<&VerifyingKey> {
        self.keys.iter().find(|(k, _)| k == kid).map(|(_, key)| key)
    }
}

/// Signs `claims` under `key` in the handle wire format.
///
/// # Panics
///
/// Never: the header and the claims always serialise.
#[must_use]
pub fn sign(key: &SigningKey, claims: &Claims) -> String {
    let header = Header {
        alg: ALG.into(),
        typ: TYP.into(),
        kid: kid(key.verifying_key()),
    };
    let header = serde_json::to_vec(&header).expect("a handle header serialises");
    let payload = serde_json::to_vec(claims).expect("handle claims serialise");
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Reads the claims of a handle without verifying it, so that a refusal
/// can name the store and identifier.
fn unverified_claims(jws: &str) -> Result<(Header, Claims), VerifyError> {
    let mut parts = jws.split('.');
    let (Some(header), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| VerifyError::Malformed)
    };
    let header: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| VerifyError::Malformed)?;
    if header.alg != ALG || header.typ != TYP {
        return Err(VerifyError::Malformed);
    }
    let claims: Claims =
        serde_json::from_slice(&decode(payload)?).map_err(|_| VerifyError::Malformed)?;
    Ok((header, claims))
}

/// Verifies a handle under the registered client keys, and returns its
/// claims.
///
/// # Errors
///
/// The [`VerifyError`] that says why the handle did not verify.
pub fn verify(jws: &str, keys: &ClientKeys) -> Result<Claims, VerifyError> {
    let (header, claims) = unverified_claims(jws)?;
    let key = keys.get(&header.kid).ok_or(VerifyError::UnknownKey)?;
    let (input, signature) = jws.rsplit_once('.').ok_or(VerifyError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(VerifyError::BadSignature)?;
    key.verify(input.as_bytes(), &signature)
        .map_err(|_| VerifyError::BadSignature)?;
    Ok(claims)
}

/// One `[secret-store-rules]` rule, as the proxy reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRule {
    /// The store the rule is for.
    pub store: String,
    /// The item's identifier in the store.
    pub id: String,
    /// The upstream authorities the rule registers, each `host` or
    /// `host:port`.
    pub upstream: Vec<String>,
    /// The injection form the rule registers.
    pub inject: Inject,
}

/// The source of the current `[secret-store-rules]`. [`read`] asks it once
/// for each request, so an edited rule decides the next request.
pub trait Rules {
    /// The current rule for `id` in `store`, or `None` when no rule names it.
    fn rule(&self, store: &str, id: &str) -> Option<StoreRule>;
}

impl Rules for [StoreRule] {
    fn rule(&self, store: &str, id: &str) -> Option<StoreRule> {
        self.iter()
            .find(|r| r.store == store && r.id == id)
            .cloned()
    }
}

impl Rules for Vec<StoreRule> {
    fn rule(&self, store: &str, id: &str) -> Option<StoreRule> {
        self.as_slice().rule(store, id)
    }
}

impl<F: Fn(&str, &str) -> Option<StoreRule>> Rules for F {
    fn rule(&self, store: &str, id: &str) -> Option<StoreRule> {
        self(store, id)
    }
}

/// The rule a handle is judged against: the authorities and the injection
/// form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule<H, I> {
    /// The authorities the rule registers.
    pub upstream: Vec<Authority<H>>,
    /// The rule's injection form. `None` for a module, which injects in its
    /// own way.
    pub inject: Option<I>,
}

/// The facts of one handle, as [`Handle::check`] judges them.
///
/// The hosts are type parameter `H` and the injection forms `I`, so a Kani
/// harness can use small ids. [`read`] gives them as strings and [`Inject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle<H, I> {
    /// Whether the signature verifies under a registered client key.
    pub verified: bool,
    /// Whether the handle's `sub` and `node_id` equal the box id and the
    /// Box Host of the opened value.
    pub bound: bool,
    /// The handle's expiry, in seconds since the Unix epoch.
    pub exp: u64,
    /// The handle's upstream authorities.
    pub upstream: Vec<Authority<H>>,
    /// The handle's injection form.
    pub inject: Option<I>,
    /// The current rule for the handle's store and identifier, or `None`
    /// when no rule names them.
    pub rule: Option<Rule<H, I>>,
}

/// Why a handle is invalid (BEP-064). The audit marks each one
/// `store_handle_invalid`. The debug log names which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Invalid {
    /// The signature does not verify under a registered client key.
    Signature,
    /// The handle's `sub` or `node_id` differs from the box id or the Box
    /// Host of the opened value.
    ContextMismatch,
    /// The clock is at or after the handle's expiry.
    Expired,
    /// No current rule names the handle's store and identifier.
    NoRule,
    /// An authority of the handle is not in the current rule.
    OutsideRule,
    /// The handle's injection form differs from the current rule's.
    InjectMismatch,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Signature => "signature",
            Self::ContextMismatch => "context_mismatch",
            Self::Expired => "expired",
            Self::NoRule => "no_rule",
            Self::OutsideRule => "outside_rule",
            Self::InjectMismatch => "inject_mismatch",
        })
    }
}

impl<H: PartialEq, I: PartialEq> Handle<H, I> {
    /// The BEP-064 check at clock reading `now`. Pure.
    ///
    /// # Errors
    ///
    /// The first [`Invalid`] reason, in the order of the variants.
    pub fn check(&self, now: u64) -> Result<(), Invalid> {
        if !self.verified {
            return Err(Invalid::Signature);
        }
        if !self.bound {
            return Err(Invalid::ContextMismatch);
        }
        if now >= self.exp {
            return Err(Invalid::Expired);
        }
        let Some(rule) = &self.rule else {
            return Err(Invalid::NoRule);
        };
        if !self.upstream.iter().all(|a| rule.upstream.contains(a)) {
            return Err(Invalid::OutsideRule);
        }
        if self.inject != rule.inject {
            return Err(Invalid::InjectMismatch);
        }
        Ok(())
    }
}

/// Parses an authority, `host` or `host:port`. A `host` with no port is
/// port 443. The host is lowercased.
#[must_use]
pub fn parse_authority(text: &str) -> Option<Authority<String>> {
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (text, HTTPS_PORT),
    };
    if host.is_empty() {
        return None;
    }
    Some(Authority {
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// Parses a list of authorities. `None` when one of them does not parse.
fn parse_authorities(list: &[String]) -> Option<Vec<Authority<String>>> {
    list.iter().map(|a| parse_authority(a)).collect()
}

/// What [`read_opened`] found for one handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The audit identifier, `<store>:<id>`, or `None` when the handle does
    /// not parse.
    pub identifier: Option<String>,
    /// The handle's `jti`, the audit correlation id, or `None` when the
    /// handle does not parse.
    pub jti: Option<String>,
    /// The handle's facts.
    pub handle: Handle<String, Inject>,
}

/// Where a handle came from: the opened value and its member.
struct Origin<'a> {
    /// The member's kind.
    kind: HandleKind,
    /// The box id of the opened value.
    box_id: &'a str,
    /// The Box Host of the opened value.
    host: &'a str,
    /// The module the value was opened for.
    module: &'a str,
}

/// Reads one handle from `origin` for the request at clock reading `now`.
///
/// It verifies the signature under `keys`, and compares `sub` and
/// `node_id` with the origin. It reads the current rule from `rules` for a
/// store handle, or takes `module`'s authorities and no injection form for
/// a sign-in reference. It logs one debug line with the store, the
/// identifier and the outcome, and never the signature.
///
/// Private: only [`read_opened`] calls it, so the origin is always the
/// sealed member's own.
fn read<R: Rules + ?Sized>(
    jws: &str,
    origin: &Origin<'_>,
    keys: &ClientKeys,
    rules: &R,
    module: &Module,
    now: u64,
) -> Read {
    let (claims, verified) = match verify(jws, keys) {
        Ok(claims) => (Some(claims), Ok(())),
        Err(error) => (unverified_claims(jws).ok().map(|(_, c)| c), Err(error)),
    };
    let Some(claims) = claims else {
        tracing::debug!(
            store = "",
            id = "",
            outcome = "malformed",
            "store handle checked"
        );
        return Read {
            identifier: None,
            jti: None,
            handle: Handle {
                verified: false,
                bound: false,
                exp: 0,
                upstream: Vec::new(),
                inject: None,
                rule: None,
            },
        };
    };
    let rule = match origin.kind {
        // A value opened for another module has no rule here.
        _ if origin.module != module.id => None,
        // A sign-in reference for another module has no rule here.
        HandleKind::SignIn if claims.store != module.id => None,
        HandleKind::SignIn => Some(Rule {
            upstream: module
                .hosts
                .iter()
                .map(|a| Authority {
                    host: a.host.to_owned(),
                    port: a.port,
                })
                .collect(),
            inject: None,
        }),
        HandleKind::Store => rules.rule(&claims.store, &claims.id).and_then(|rule| {
            Some(Rule {
                upstream: parse_authorities(&rule.upstream)?,
                inject: Some(rule.inject),
            })
        }),
    };
    // An authority that does not parse is in no rule.
    let upstream = parse_authorities(&claims.upstream);
    let upstream_parsed = upstream.is_some();
    let handle = Handle {
        verified: verified.is_ok() && upstream_parsed,
        bound: claims.sub == origin.box_id && claims.node_id == origin.host,
        exp: claims.exp,
        upstream: upstream.unwrap_or_default(),
        inject: claims.inject.clone(),
        rule,
    };
    let outcome = outcome(verified, upstream_parsed, handle.check(now));
    // The store and identifier can come from a handle that did not verify,
    // so they are logged escaped.
    tracing::debug!(
        store = ?claims.store,
        id = ?claims.id,
        outcome = %outcome,
        "store handle checked"
    );
    Read {
        identifier: Some(claims.identifier()),
        jti: Some(claims.jti),
        handle,
    }
}

/// The outcome that the debug line names for one handle.
///
/// A handle whose signature verifies but whose `upstream` does not parse is
/// refused through `verified`, so [`Handle::check`] gives
/// [`Invalid::Signature`]. The log names `unparsed_upstream` for it, so the
/// line gives the real cause.
fn outcome(
    verified: Result<(), VerifyError>,
    upstream_parsed: bool,
    check: Result<(), Invalid>,
) -> String {
    match (verified, check) {
        (Err(error), _) => error.to_string(),
        (Ok(()), _) if !upstream_parsed => "unparsed_upstream".to_owned(),
        (Ok(()), Err(invalid)) => invalid.to_string(),
        (Ok(()), Ok(())) => "valid".to_owned(),
    }
}

/// Reads the handle of the member that [`crate::seal::open`] opened, for
/// the request at clock reading `now`.
///
/// The shell builds [`crate::redeem::Redemption::handle`] with this, from
/// the same [`Opened`] that gave [`crate::redeem::Unsealed::Opened`]. So the
/// handle that [`crate::redeem::decide`] judges is the sealed member's own
/// `jws`, and never a handle from somewhere else. The member gives the
/// kind. The opened value gives the box id and the Box Host that `sub` and
/// `node_id` must equal. A value opened for a module other than `module`,
/// or a sign-in reference for another module, has no rule, so it is
/// refused as `store_handle_invalid`.
///
/// A member of [`crate::seal::MemberKind`] has no store kind yet, so this
/// reads sign-in references only. The store path of the check is the same
/// code, and a store member kind reaches it through the `match` below.
pub fn read_opened<R: Rules + ?Sized>(
    opened: &Opened,
    keys: &ClientKeys,
    rules: &R,
    module: &Module,
    now: u64,
) -> Read {
    let kind = match opened.member.kind {
        MemberKind::SignIn => HandleKind::SignIn,
    };
    let origin = Origin {
        kind,
        box_id: &opened.context.box_id,
        host: &opened.context.host,
        module: &opened.context.module,
    };
    read(
        opened.member.jws.as_str(),
        &origin,
        keys,
        rules,
        module,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unparsed_upstream_is_logged_apart_from_the_signature() {
        assert_eq!(
            outcome(Ok(()), false, Err(Invalid::Signature)),
            "unparsed_upstream"
        );
        assert_eq!(outcome(Ok(()), true, Err(Invalid::Expired)), "expired");
        assert_eq!(outcome(Ok(()), true, Ok(())), "valid");
    }
    use crate::module::GITHUB;
    use crate::redeem::{
        Attribution, Bounds, Check, Decision, Redemption, RequestAuthority, Unsealed, decide,
    };
    use crate::seal::{Breadth, Mode};

    fn client_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("a valid scalar")
    }

    fn registered(key: &SigningKey) -> ClientKeys {
        let mut keys = ClientKeys::new();
        keys.register(&key.verifying_key().to_sec1_bytes())
            .expect("register");
        keys
    }

    fn bearer() -> Inject {
        Inject::Header {
            name: "Authorization".into(),
            prefix: Some("Bearer ".into()),
        }
    }

    fn store_claims() -> Claims {
        Claims {
            sub: "b1".into(),
            node_id: "host".into(),
            store: "keychain".into(),
            id: "anthropic".into(),
            upstream: vec!["api.anthropic.com".into()],
            inject: Some(bearer()),
            iat: 0,
            exp: 2_000,
            jti: "jti-store".into(),
        }
    }

    /// A store member of box `b1` on Box Host `host`, opened for GitHub.
    const STORE: Origin<'static> = Origin {
        kind: HandleKind::Store,
        box_id: "b1",
        host: "host",
        module: "github",
    };

    /// A sign-in member of box `b1` on Box Host `host`, opened for GitHub.
    const SIGN_IN: Origin<'static> = Origin {
        kind: HandleKind::SignIn,
        ..STORE
    };

    fn store_rule() -> StoreRule {
        StoreRule {
            store: "keychain".into(),
            id: "anthropic".into(),
            upstream: vec!["api.anthropic.com:443".into()],
            inject: bearer(),
        }
    }

    #[test]
    fn a_signed_handle_verifies_and_round_trips() {
        let key = client_key(7);
        let jws = sign(&key, &store_claims());
        assert_eq!(verify(&jws, &registered(&key)), Ok(store_claims()));
        assert_eq!(
            verify(&jws, &ClientKeys::new()),
            Err(VerifyError::UnknownKey)
        );
        assert_eq!(
            verify("a.b", &registered(&key)),
            Err(VerifyError::Malformed)
        );
    }

    #[test]
    fn a_tampered_or_foreign_signature_does_not_verify() {
        let key = client_key(7);
        let jws = sign(&key, &store_claims());
        let (input, _) = jws.rsplit_once('.').expect("three parts");
        let other = sign(&client_key(9), &store_claims());
        let (_, foreign) = other.rsplit_once('.').expect("three parts");
        assert_eq!(
            verify(&format!("{input}.{foreign}"), &registered(&key)),
            Err(VerifyError::BadSignature)
        );
        // A widened payload under the original signature.
        let mut wide = store_claims();
        wide.upstream.push("evil.example".into());
        let wide = sign(&key, &wide);
        let (_, sig) = jws.rsplit_once('.').expect("three parts");
        let (wide_input, _) = wide.rsplit_once('.').expect("three parts");
        assert_eq!(
            verify(&format!("{wide_input}.{sig}"), &registered(&key)),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn read_judges_a_store_handle_against_its_rule() {
        let key = client_key(7);
        let keys = registered(&key);
        let rules = vec![store_rule()];
        let jws = sign(&key, &store_claims());
        let read = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert_eq!(read.identifier.as_deref(), Some("keychain:anthropic"));
        assert_eq!(read.handle.check(1_000), Ok(()));
        assert_eq!(read.handle.check(2_000), Err(Invalid::Expired));
        let none: Vec<StoreRule> = Vec::new();
        let read = super::read(&jws, &STORE, &keys, &none, &GITHUB, 1_000);
        assert_eq!(read.handle.check(1_000), Err(Invalid::NoRule));
    }

    /// A redemption from box `b1` to `authority`, which passes every check
    /// but the handle's. For a store handle the bound set is the handle's
    /// `upstream` and the current set is the rule's (BEP-032).
    fn redemption(
        authority: Authority<String>,
        read: Read,
        module_sets: bool,
    ) -> Redemption<String, String> {
        let current = if module_sets {
            read.handle
                .rule
                .as_ref()
                .map(|r| r.upstream.clone())
                .unwrap_or_default()
        } else {
            vec![authority.clone()]
        };
        let bound = if module_sets {
            read.handle.upstream.clone()
        } else {
            vec![authority.clone()]
        };
        Redemption {
            unsealed: Unsealed::Opened {
                box_id: "b1".into(),
                bounds: Bounds {
                    mode: Some(Mode::User),
                    breadth: Some(Breadth::Full),
                },
                expiry: 5_000,
            },
            attribution: Attribution::OwnIp("b1".into()),
            named_box_in_cohort: false,
            now: 1_000,
            revoked: Vec::new(),
            authority: authority.clone(),
            bound_set: bound,
            current_set: current,
            request: RequestAuthority {
                host: Some(authority.clone()),
                target: None,
            },
            egress: vec![authority],
            handle: read.handle,
        }
    }

    fn admitted(decision: Decision) -> bool {
        matches!(decision, Decision::Admit { .. })
    }

    /// BEP-064: an edited `[secret-store-rules]` rule decides the next
    /// request, with no restart and no new handle.
    #[test]
    fn edited_store_rule_applies_to_next_request() {
        let key = client_key(7);
        let keys = registered(&key);
        let jws = sign(&key, &store_claims());
        let api = parse_authority("api.anthropic.com").expect("authority");
        // The rules as the operator's configuration holds them; `read`
        // asks for the rule at each request.
        let current = std::cell::RefCell::new(vec![store_rule()]);
        let rules = |store: &str, id: &str| current.borrow().rule(store, id);

        let first = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert!(admitted(decide(&redemption(api.clone(), first, true))));

        // The operator narrows the rule to another authority.
        current.borrow_mut()[0].upstream = vec!["other.example.com".into()];
        let narrowed = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert_eq!(narrowed.handle.check(1_000), Err(Invalid::OutsideRule));
        assert_eq!(
            decide(&redemption(api.clone(), narrowed, true)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );
        assert_eq!(Check::StoreHandleInvalid.marker(), "store_handle_invalid");

        // The operator changes the injection form.
        current.borrow_mut()[0] = StoreRule {
            inject: Inject::Header {
                name: "x-api-key".into(),
                prefix: None,
            },
            ..store_rule()
        };
        let reformed = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert_eq!(reformed.handle.check(1_000), Err(Invalid::InjectMismatch));
        assert_eq!(
            decide(&redemption(api.clone(), reformed, true)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );

        // The operator removes the rule.
        current.borrow_mut().clear();
        let removed = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert_eq!(removed.handle.check(1_000), Err(Invalid::NoRule));

        // The operator restores the rule: the same handle is admitted again.
        current.borrow_mut().push(store_rule());
        let restored = read(&jws, &STORE, &keys, &rules, &GITHUB, 1_000);
        assert!(admitted(decide(&redemption(api.clone(), restored, true))));

        // A handle past its expiry, or under no registered key, is refused.
        let late = read(&jws, &STORE, &keys, &rules, &GITHUB, 2_000);
        assert_eq!(late.handle.check(2_000), Err(Invalid::Expired));
        let unknown = read(&jws, &STORE, &ClientKeys::new(), &rules, &GITHUB, 1_000);
        assert_eq!(unknown.identifier.as_deref(), Some("keychain:anthropic"));
        assert_eq!(
            decide(&redemption(api, unknown, true)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );
    }

    fn sign_in_claims() -> Claims {
        Claims {
            sub: "b1".into(),
            node_id: "host".into(),
            store: GITHUB.id.into(),
            id: "instance-1".into(),
            upstream: GITHUB.hosts.iter().map(ToString::to_string).collect(),
            inject: None,
            iat: 0,
            exp: 2_000,
            jti: "jti-signin".into(),
        }
    }

    /// BEP-064: a sign-in reference has the GitHub module as its rule. Its
    /// `upstream` is within the module's current authorities and it carries
    /// no `inject`. A reference that disagrees refuses, as a stale
    /// registration does. No `[secret-store-rules]` rule decides it.
    #[test]
    fn sign_in_reference_is_judged_against_the_module() {
        let key = client_key(3);
        let keys = registered(&key);
        let api = parse_authority("api.github.com").expect("authority");
        let no_rules: Vec<StoreRule> = Vec::new();

        let reference = sign(&key, &sign_in_claims());
        let read_ok = read(&reference, &SIGN_IN, &keys, &no_rules, &GITHUB, 1_000);
        assert_eq!(read_ok.identifier.as_deref(), Some("github:instance-1"));
        assert_eq!(read_ok.handle.check(1_000), Ok(()));
        assert!(admitted(decide(&redemption(api.clone(), read_ok, false))));

        // A store rule that names the sign-in does not stand in for the
        // module.
        let rules = vec![StoreRule {
            store: GITHUB.id.into(),
            id: "instance-1".into(),
            upstream: vec!["evil.example".into()],
            inject: Inject::BasicAuth {
                field: "password".into(),
            },
        }];
        let wide = sign(
            &key,
            &Claims {
                upstream: vec!["evil.example".into()],
                ..sign_in_claims()
            },
        );
        let read_wide = read(&wide, &SIGN_IN, &keys, &rules, &GITHUB, 1_000);
        assert_eq!(read_wide.handle.check(1_000), Err(Invalid::OutsideRule));
        assert_eq!(
            decide(&redemption(api.clone(), read_wide, false)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );

        // An off-port authority is outside the module.
        let off_port = sign(
            &key,
            &Claims {
                upstream: vec!["api.github.com:8443".into()],
                ..sign_in_claims()
            },
        );
        let read_off = read(&off_port, &SIGN_IN, &keys, &no_rules, &GITHUB, 1_000);
        assert_eq!(read_off.handle.check(1_000), Err(Invalid::OutsideRule));

        // A reference with an injection form disagrees with the module.
        let injecting = sign(
            &key,
            &Claims {
                inject: Some(bearer()),
                ..sign_in_claims()
            },
        );
        let read_inject = read(&injecting, &SIGN_IN, &keys, &no_rules, &GITHUB, 1_000);
        assert_eq!(
            read_inject.handle.check(1_000),
            Err(Invalid::InjectMismatch)
        );
        assert_eq!(
            decide(&redemption(api.clone(), read_inject, false)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );

        // A reference signed for another module is not judged against this
        // one, even when its upstream is within this module's hosts.
        let other = sign(
            &key,
            &Claims {
                store: "other-module".into(),
                ..sign_in_claims()
            },
        );
        let read_other = read(&other, &SIGN_IN, &keys, &no_rules, &GITHUB, 1_000);
        assert_eq!(read_other.handle.check(1_000), Err(Invalid::NoRule));
        assert_eq!(
            decide(&redemption(api, read_other, false)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );
    }

    /// A value opened for `module`, whose one member carries `jws`.
    fn opened(jws: &str, module: &str) -> Opened {
        use crate::seal::{Context, Member};
        Opened {
            context: Context {
                box_id: "b1".into(),
                host: "host".into(),
                module: module.into(),
                host_set_version: 1,
                mode: Mode::User,
                iat: 0,
                expiry: 5_000,
                kid: "kid".into(),
            },
            member: Member {
                kind: MemberKind::SignIn,
                breadth: Breadth::Full,
                jws: zeroize::Zeroizing::new(jws.into()),
                exp: None,
            },
            default_owner: None,
        }
    }

    /// BEP-064: the handle the decision judges is the opened member's own
    /// `jws`. The member gives the kind, and the opened value gives the box
    /// id and the Box Host. A handle for another box or Box Host, a handle
    /// that does not fit the member's kind, or a value opened for another
    /// module is refused.
    #[test]
    fn handle_is_read_from_the_opened_member() {
        let key = client_key(3);
        let keys = registered(&key);
        let no_rules: Vec<StoreRule> = Vec::new();
        let api = parse_authority("api.github.com").expect("authority");

        let reference = sign(&key, &sign_in_claims());
        let own = read_opened(
            &opened(&reference, GITHUB.id),
            &keys,
            &no_rules,
            &GITHUB,
            1_000,
        );
        assert_eq!(own.identifier.as_deref(), Some("github:instance-1"));
        assert_eq!(own.jti.as_deref(), Some("jti-signin"));
        assert!(admitted(decide(&redemption(api.clone(), own, false))));

        let other_module = read_opened(
            &opened(&reference, "other"),
            &keys,
            &no_rules,
            &GITHUB,
            1_000,
        );
        assert_eq!(other_module.handle.check(1_000), Err(Invalid::NoRule));

        // A handle minted for another box, or for another Box Host, does not
        // belong to the value that carries it.
        for claims in [
            Claims {
                sub: "b2".into(),
                ..sign_in_claims()
            },
            Claims {
                node_id: "other-host".into(),
                ..sign_in_claims()
            },
        ] {
            let moved = read_opened(
                &opened(&sign(&key, &claims), GITHUB.id),
                &keys,
                &no_rules,
                &GITHUB,
                1_000,
            );
            assert_eq!(moved.handle.check(1_000), Err(Invalid::ContextMismatch));
            assert_eq!(
                decide(&redemption(api.clone(), moved, false)),
                Decision::Refuse(Check::StoreHandleInvalid)
            );
        }

        // A store handle inside a sign-in member, with a rule that admits it,
        // is judged against the module as the member's kind says.
        let rules = vec![store_rule()];
        let store = sign(&key, &store_claims());
        let foreign = read_opened(&opened(&store, GITHUB.id), &keys, &rules, &GITHUB, 1_000);
        assert_eq!(foreign.handle.check(1_000), Err(Invalid::NoRule));
        assert_eq!(
            decide(&redemption(api, foreign, true)),
            Decision::Refuse(Check::StoreHandleInvalid)
        );
    }

    #[test]
    fn parse_authority_defaults_to_443() {
        assert_eq!(
            parse_authority("API.example.com"),
            Some(Authority {
                host: "api.example.com".into(),
                port: 443
            })
        );
        assert_eq!(
            parse_authority("h:8443"),
            Some(Authority {
                host: "h".into(),
                port: 8443
            })
        );
        assert_eq!(parse_authority("h:x"), None);
        assert_eq!(parse_authority(""), None);
    }
}
