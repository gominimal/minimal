//! Minting a GitHub member from the held sign-in on an un-enrolled host
//! (BEP-005), and the identity events the client records for a mint and for
//! `min auth logout` (BEP-067).
//!
//! A locally minted member is the signed-in account's user token, `mode =
//! "user"` and `full` breadth, sealed to this host's key with the box, the
//! host, the module, the host-set version and the expiry bound in the
//! authenticated context (BEP-006). The expiry is the earlier of eight hours
//! from the mint and the token's own expiry: the member is a creation-time
//! snapshot, and a box that outlives it is re-created to re-mint.
//!
//! The mint, the logout and a box's removal each make one [`Event`] for the
//! proxy's log; the client submits it over the control socket
//! ([`crate::control`]) and never opens the log itself. A mint is recorded
//! before its value is sealed, because the value carries the position the log
//! gave its record: a revocation covers what was minted before it and nothing
//! after (BEP-043, BEP-044).
//!
//! The store-reference mint is here too ([`mint_store_handle`]): a box that
//! refers to a Keychain value by identifier receives no value and no member
//! of a module, but a short-lived [`StoreHandle`] signed under the client's
//! own key ([`client_key`]), carrying the store, the identifier, the
//! registered upstream authorities, the injection form and the expiry
//! (BEP-063). The handle is the member inside the same envelope as a module's
//! member, so the box binding and the expiry of BEP-019 and BEP-020 hold for
//! it unchanged; the proxy verifies the signature under the client key the
//! client registers over the control socket at first use
//! ([`crate::control::ClientKey`]).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::PublicKey;
use p256::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};

use crate::audit::{Decision, Event, Kind, Mapping};
use crate::github::SignIn;
use crate::keychain::{KeyStore, PrivateKey, StoreError};
use crate::keys::{Fingerprint, PublicIdentity};
use crate::seal::{Member, SealError, SealedContext, SealedValue, seal_to};

/// The longest a locally minted member lives: eight hours from its mint.
pub const MAX_LIFETIME_SECS: u64 = 8 * 60 * 60;
/// The module identifier the member is sealed under.
pub const MODULE: &str = "github";
/// The mode of a member minted from the held sign-in.
pub const MODE: &str = "user";
/// The breadth of a locally minted member: the account's whole reach.
pub const BREADTH: &str = "full";
/// The member identifier the audit records name.
pub const CREDENTIAL: &str = "github:user-token";
/// The authority a GitHub identity event names.
pub const AUTHORITY: &str = "api.github.com";
/// The subject of a revocation that covers every box on the host.
pub const EVERY_BOX: &str = "*";

/// What a mint is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintRequest<'a> {
    /// The box the member is minted for.
    pub box_id: &'a str,
    /// The host the member is sealed on.
    pub host: &'a str,
    /// The version of the module's host set the member is minted under.
    pub host_set_version: u32,
    /// The clock, as seconds since the Unix epoch.
    pub now: u64,
}

/// A minted member: the sealed value for the box, and the context it was
/// sealed with.
#[derive(Debug)]
pub struct Minted {
    /// The sealed value, as delivered into the box.
    pub value: SealedValue,
    /// The authenticated context the value was sealed with.
    pub context: SealedContext,
}

/// Why a member could not be minted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The held sign-in's token has already expired; sign in again.
    #[error("the GitHub sign-in as {account} expired at {expired_at}; run `min auth login`")]
    Expired { account: String, expired_at: u64 },
    /// The envelope could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
}

/// The expiry a member minted at `now` from a token expiring at
/// `token_expires_at` carries: the earlier of eight hours on and the token's
/// own expiry.
#[must_use]
pub fn member_expiry(now: u64, token_expires_at: Option<u64>) -> u64 {
    let ceiling = now.saturating_add(MAX_LIFETIME_SECS);
    token_expires_at.map_or(ceiling, |expiry| expiry.min(ceiling))
}

/// Whether `sign_in` may mint for `request`: refused once its token has
/// expired. The client asks before it records a mint, so the log never holds
/// the record of one that could not be made.
///
/// # Errors
///
/// [`MintError::Expired`] when the sign-in's token has expired at
/// `request.now`.
pub fn unexpired(sign_in: &SignIn, request: &MintRequest<'_>) -> Result<(), MintError> {
    if let Some(expired_at) = sign_in.expires_at.filter(|expiry| *expiry <= request.now) {
        tracing::warn!(
            account = %sign_in.account,
            box_id = request.box_id,
            expired_at,
            "refusing to mint from an expired GitHub sign-in"
        );
        return Err(MintError::Expired {
            account: sign_in.account.clone(),
            expired_at,
        });
    }
    Ok(())
}

/// Mints a `user`, `full` member for `request.box_id` from `sign_in`, sealed
/// to `keys`, carrying `mint_position`: where the log recorded the mint's
/// [`mint_event`].
///
/// # Errors
///
/// [`MintError::Expired`] when the sign-in's token has expired at
/// `request.now`; [`MintError::Seal`] when the envelope cannot be sealed.
pub fn mint(
    identity: &PublicIdentity,
    sign_in: &SignIn,
    request: &MintRequest<'_>,
    mint_position: u64,
) -> Result<Minted, MintError> {
    unexpired(sign_in, request)?;
    let context = SealedContext {
        box_id: request.box_id.to_owned(),
        host: request.host.to_owned(),
        module: MODULE.to_owned(),
        host_set_version: request.host_set_version,
        mode: MODE.to_owned(),
        breadth: BREADTH.to_owned(),
        expires_at: member_expiry(request.now, sign_in.expires_at),
        mint_position,
    };
    let value = seal_to(identity, &context, &Member::new(sign_in.token.expose()))?;
    tracing::info!(
        account = %sign_in.account,
        box_id = request.box_id,
        expires_at = context.expires_at,
        "minted a GitHub member from the held sign-in"
    );
    Ok(Minted { value, context })
}

/// The `mint` event a member minted for `box_id` records.
#[must_use]
pub fn mint_event(box_id: &str) -> Event {
    identity_event(Kind::Mint, box_id)
}

/// The `revocation` event `min auth logout` records: every GitHub member on
/// this host is refused from now on (BEP-044).
#[must_use]
pub fn revocation_event() -> Event {
    identity_event(Kind::Revocation, EVERY_BOX)
}

/// The `revocation` event a box's removal records: every sealed value naming
/// `box_id` is refused from now on, whatever its own expiry says (BEP-043).
#[must_use]
pub fn box_revocation_event(box_id: &str) -> Event {
    identity_event(Kind::Revocation, box_id)
}

fn identity_event(kind: Kind, box_id: &str) -> Event {
    Event {
        kind,
        box_id: box_id.to_owned(),
        authority: AUTHORITY.to_owned(),
        credential: Some(CREDENTIAL.to_owned()),
        mapping: Mapping::Unmapped,
        decision: Decision::Admit,
        marker: None,
    }
}

// ---------------------------------------------------------------------------
// Store references: the handle a box receives for a value it never holds
// (BEP-063).
// ---------------------------------------------------------------------------

/// The prefix every store handle carries; the `1` is the handle version.
pub const HANDLE_PREFIX: &str = "minstore1.";

/// The longest a store handle lives: eight hours from its mint, the same
/// ceiling as a GitHub member ([`MAX_LIFETIME_SECS`]).
///
/// A host that is not enrolled has no in-box re-mint path (Gatehouse §8.3), so
/// a handle is a creation-time snapshot like the member beside it, and a box
/// that outlives it is recreated. A handle shorter than that ended the box's
/// use of the value minutes into its life. A handle copied out of its box
/// buys nothing a shorter lifetime would take away: the sealed context binds
/// it to this box and this host, and the proxy refuses it anywhere else.
pub const HANDLE_LIFETIME_SECS: u64 = MAX_LIFETIME_SECS;

/// The name the client's handle-signing key lives under in the host key
/// store.
///
/// The client's own key, not one of the proxy's roles
/// ([`crate::keys::KeyRole`]): the client signs handles with it, and the proxy
/// only ever holds its public half, registered over the control socket.
pub const CLIENT_KEY_NAME: &str = "dev.minimal.bep.client";

/// The mode a store handle's envelope carries: minted from a store reference
/// rather than from the held sign-in.
pub const STORE_MODE: &str = "store";

/// The breadth a store handle's envelope carries: one referenced identifier,
/// and nothing else the store holds.
pub const STORE_BREADTH: &str = "reference";

/// The host-set version a store handle's envelope carries: none, because a
/// store handle binds no module host set. Its bound set is the handle's own
/// `upstream`, which the rule registers and BEP-064 checks.
pub const STORE_HOST_SET_VERSION: u32 = 0;

/// The domain separator the signature covers, so a signature over a handle is
/// a signature over nothing else this key signs.
const HANDLE_CONTEXT: &[u8] = b"minimal bep store handle v1";

/// How a store value is put on the wire, as the handle carries the rule's
/// registered form.
///
/// The field names are the `[secret-store-rules]` rule's own, so BEP-064's
/// check that a handle's `inject` is still the rule's is an equality of the
/// two forms. Which combinations are a form at all is the rule's grammar and
/// the client's to check before it mints: a handle carrying a combination no
/// rule can spell equals no rule, and is refused for that.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inject {
    /// The header the value is written to, for the header form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// What precedes the value in that header; absent when the rule declares
    /// no prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The basic-authentication field the value fills, for that form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<String>,
}

impl Inject {
    /// The header form: `prefix` then the value, as the whole value of
    /// `name`. An empty prefix is carried as none, as the rule writes it.
    #[must_use]
    pub fn header(name: impl Into<String>, prefix: &str) -> Self {
        Self {
            header: Some(name.into()),
            prefix: (!prefix.is_empty()).then(|| prefix.to_owned()),
            basic_auth: None,
        }
    }

    /// The basic-authentication form: the value as the `field` field.
    #[must_use]
    pub fn basic_auth(field: impl Into<String>) -> Self {
        Self {
            header: None,
            prefix: None,
            basic_auth: Some(field.into()),
        }
    }
}

/// What a store handle claims: the reference it was minted for, what the
/// value may reach, how it is injected, when the handle expires, and the
/// client key it is signed under (BEP-063).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreClaims {
    /// The store the value is read from (`keychain`).
    pub store: String,
    /// The identifier the value is stored under.
    pub id: String,
    /// The authorities the value may be injected into, each `host` or
    /// `host:port`, as the rule registers them.
    pub upstream: Vec<String>,
    /// How the value is put on the wire, as the rule registers it.
    pub inject: Inject,
    /// The expiry, as seconds since the Unix epoch.
    pub exp: u64,
    /// The fingerprint of the client key the handle is signed under: which
    /// registered key the proxy verifies it with.
    pub key: String,
}

/// A store handle: [`HANDLE_PREFIX`], then the claims and the signature over
/// them, each unpadded base64url, separated by a dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHandle(String);

impl StoreHandle {
    /// The handle's text: what the box carries and sends on.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A store handle as read back: its claims, the bytes they were signed as,
/// and the signature over them.
#[derive(Debug, Clone)]
pub struct ParsedHandle {
    /// What the handle claims.
    pub claims: StoreClaims,
    /// The exact bytes the signature covers.
    signed: Vec<u8>,
    /// The DER signature.
    signature: Vec<u8>,
}

impl ParsedHandle {
    /// Whether the signature verifies under `public`: the first of BEP-064's
    /// checks, and what the client key registration is for.
    #[must_use]
    pub fn verifies_under(&self, public: &PublicKey) -> bool {
        p256::ecdsa::Signature::from_der(&self.signature).is_ok_and(|signature| {
            p256::ecdsa::VerifyingKey::from(public)
                .verify(&self.signed, &signature)
                .is_ok()
        })
    }
}

/// Why a store handle could not be minted or read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HandleError {
    /// The claims did not encode, or did not decode as claims.
    #[error("the store handle's claims: {0}")]
    Claims(#[from] serde_json_lenient::Error),
    /// The key store refused to sign the handle, or to describe the key.
    #[error("the client's handle-signing key: {0}")]
    Key(#[from] StoreError),
    /// The text is no store handle.
    #[error("not a store handle: {0}")]
    Malformed(&'static str),
    /// The envelope the handle is delivered in could not be sealed.
    #[error(transparent)]
    Seal(#[from] SealError),
}

/// What a store handle is minted for: the reference, the rule in force for
/// it, and the box the envelope is bound to.
#[derive(Debug, Clone, Copy)]
pub struct StoreMintRequest<'a> {
    /// The box the handle is minted for.
    pub box_id: &'a str,
    /// The host the envelope is sealed on.
    pub host: &'a str,
    /// The store the value is read from.
    pub store: &'a str,
    /// The identifier the value is stored under.
    pub id: &'a str,
    /// The upstream authorities the rule registers for it.
    pub upstream: &'a [String],
    /// The injection form the rule registers for it.
    pub inject: &'a Inject,
    /// The clock, as seconds since the Unix epoch.
    pub now: u64,
}

/// A minted store handle: the handle, the envelope the box receives it in,
/// and the claims it carries.
#[derive(Debug)]
pub struct MintedHandle {
    /// The handle, signed under the client's key.
    pub handle: StoreHandle,
    /// The sealed value delivered into the box: the handle as the member,
    /// bound to this host's keys and to the box.
    pub value: SealedValue,
    /// The claims the handle carries.
    pub claims: StoreClaims,
}

/// The client's handle-signing key in `store`, generated there on first use.
///
/// One key per host store, found again on every run: the proxy holds its
/// public half from the first registration on, so handles minted later verify
/// without registering again. A key the store refuses this program is
/// replaced: macOS admits only the program that generated a key, so a rebuilt
/// client is refused its predecessor's. Unlike the proxy's keys, which
/// BEP-060 replaces only on the operator's word, this one signs nothing but
/// handles, and every mint registers the key it signs under first.
///
/// # Errors
///
/// When the store cannot be searched, or cannot replace or generate the key.
pub fn client_key<S: KeyStore>(store: &S) -> Result<S::Key, StoreError> {
    if let Some(key) = store.find(CLIENT_KEY_NAME)? {
        match key.public_key() {
            Err(StoreError::Unusable) => {
                tracing::warn!(
                    name = CLIENT_KEY_NAME,
                    store = S::NAME,
                    "the store refuses this program the client's handle-signing key; replacing it"
                );
                store.delete(CLIENT_KEY_NAME)?;
            }
            _ => return Ok(key),
        }
    }
    let key = store.generate(CLIENT_KEY_NAME)?;
    tracing::info!(
        name = CLIENT_KEY_NAME,
        store = S::NAME,
        "generated the client's handle-signing key"
    );
    Ok(key)
}

/// The `mint` event a store handle minted for `request` records: the box, the
/// first authority the rule registers, and the store and identifier as the
/// proxy's own records name a handle.
#[must_use]
pub fn store_mint_event(request: &StoreMintRequest<'_>) -> Event {
    Event {
        kind: Kind::Mint,
        box_id: request.box_id.to_owned(),
        authority: request
            .upstream
            .first()
            .map_or_else(|| crate::audit::NONE.to_owned(), Clone::clone),
        credential: Some(format!("{}:{}", request.store, request.id)),
        mapping: Mapping::Unmapped,
        decision: Decision::Admit,
        marker: None,
    }
}

/// Mints a handle for one store reference, signed under `client`, and seals
/// it to `keys` for `request.box_id` (BEP-063), carrying `mint_position`:
/// where the log recorded the handle's [`store_mint_event`].
///
/// The handle expires [`HANDLE_LIFETIME_SECS`] after `request.now`, and the
/// envelope it is delivered in carries the same expiry, so BEP-020's check
/// and BEP-064's agree about when it is spent.
///
/// # Errors
///
/// A [`HandleError`]: the claims do not encode, the key store refuses to sign
/// or to describe the client key, or the envelope cannot be sealed.
pub fn mint_store_handle<K: PrivateKey>(
    identity: &PublicIdentity,
    client: &K,
    request: &StoreMintRequest<'_>,
    mint_position: u64,
) -> Result<MintedHandle, HandleError> {
    let fingerprint = Fingerprint::of(&client.public_key()?);
    let claims = StoreClaims {
        store: request.store.to_owned(),
        id: request.id.to_owned(),
        upstream: request.upstream.to_vec(),
        inject: request.inject.clone(),
        exp: request.now.saturating_add(HANDLE_LIFETIME_SECS),
        key: fingerprint.to_string(),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json_lenient::to_vec(&claims)?);
    let signature = client.sign(&signed_bytes(&encoded))?;
    let handle = StoreHandle(format!(
        "{HANDLE_PREFIX}{encoded}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    ));
    let context = SealedContext {
        box_id: request.box_id.to_owned(),
        host: request.host.to_owned(),
        // The store is the module a handle belongs to, so a revocation
        // covering it reads as one covering a module's members does.
        module: request.store.to_owned(),
        host_set_version: STORE_HOST_SET_VERSION,
        mode: STORE_MODE.to_owned(),
        breadth: STORE_BREADTH.to_owned(),
        expires_at: claims.exp,
        mint_position,
    };
    let value = seal_to(identity, &context, &Member::new(handle.as_str()))?;
    tracing::info!(
        store = request.store,
        id = request.id,
        box_id = request.box_id,
        exp = claims.exp,
        key = %fingerprint,
        "minted a store handle for a store reference"
    );
    Ok(MintedHandle {
        handle,
        value,
        claims,
    })
}

/// Reads `handle`: its claims, and the signature to verify under the client
/// key those claims name.
///
/// # Errors
///
/// A [`HandleError`]: the text is no store handle, or its claims do not
/// decode.
pub fn parse_store_handle(handle: &str) -> Result<ParsedHandle, HandleError> {
    let body = handle
        .strip_prefix(HANDLE_PREFIX)
        .ok_or(HandleError::Malformed("it carries no store-handle prefix"))?;
    let (encoded, signature) = body
        .split_once('.')
        .ok_or(HandleError::Malformed("it carries no signature"))?;
    let claims = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| HandleError::Malformed("the claims are not base64url"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| HandleError::Malformed("the signature is not base64url"))?;
    Ok(ParsedHandle {
        claims: serde_json_lenient::from_slice(&claims)?,
        signed: signed_bytes(encoded),
        signature,
    })
}

/// The bytes a handle's signature covers: the domain separator, the handle
/// version and the encoded claims exactly as the handle carries them, so
/// verification never depends on re-encoding what was signed.
fn signed_bytes(encoded: &str) -> Vec<u8> {
    let mut signed = Vec::with_capacity(HANDLE_CONTEXT.len() + HANDLE_PREFIX.len() + encoded.len());
    signed.extend_from_slice(HANDLE_CONTEXT);
    signed.extend_from_slice(HANDLE_PREFIX.as_bytes());
    signed.extend_from_slice(encoded.as_bytes());
    signed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Secret;
    use crate::keychain::MemoryStore;
    use crate::keys::Keys;
    use crate::seal::unseal;

    const NOW: u64 = 1_800_000_000;

    fn sign_in(expires_at: Option<u64>) -> SignIn {
        SignIn {
            account: "octocat".into(),
            token: Secret::new("ghu_16C7e42F292c6912E7710c838347Ae178B4a"),
            expires_at,
            refresh_token: Some(Secret::new("ghr_refresh")),
            refresh_expires_at: Some(NOW + 15_811_200),
        }
    }

    fn request() -> MintRequest<'static> {
        MintRequest {
            box_id: "box-a1",
            host: "mac-1",
            host_set_version: 3,
            now: NOW,
        }
    }

    /// BEP-005: a member minted from the held sign-in is `user` mode, `full`
    /// breadth, and expires no later than eight hours after its mint —
    /// earlier when the token itself does.
    #[test]
    fn local_mint_expiry_is_at_most_8h() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        let ceiling = NOW + MAX_LIFETIME_SECS;

        // GitHub's own eight-hour user token, a token that never expires,
        // and one with an hour left: none of the three outlives the ceiling.
        for (token_expiry, expected) in [
            (Some(NOW + 28_800), ceiling),
            (None, ceiling),
            (Some(NOW + 3_600), NOW + 3_600),
            (Some(NOW + 100_000), ceiling),
        ] {
            let minted = mint(
                &keys.public_identity(),
                &sign_in(token_expiry),
                &request(),
                5,
            )
            .unwrap();
            assert!(minted.context.expires_at <= ceiling, "{token_expiry:?}");
            assert_eq!(minted.context.expires_at, expected, "{token_expiry:?}");

            let unsealed = unseal(&keys, minted.value.as_str()).unwrap();
            assert_eq!(unsealed.context, minted.context);
            assert_eq!(unsealed.context.mode, "user");
            assert_eq!(unsealed.context.breadth, "full");
            assert_eq!(unsealed.context.module, "github");
            assert_eq!(unsealed.context.box_id, "box-a1");
            assert_eq!(unsealed.context.host, "mac-1");
            assert_eq!(unsealed.context.host_set_version, 3);
            assert_eq!(unsealed.context.mint_position, 5);
            assert_eq!(unsealed.member.expose(), sign_in(None).token.expose());
        }

        // The mint's record names the box and the member, never the token.
        let event = mint_event("box-a1");
        assert_eq!(event.kind, Kind::Mint);
        assert_eq!(event.box_id, "box-a1");
        assert_eq!(event.credential.as_deref(), Some(CREDENTIAL));
        let line = serde_json_lenient::to_string(&event).unwrap();
        assert!(!line.contains("ghu_"), "{line}");

        // An expired sign-in mints nothing, and says so before any record.
        assert!(matches!(
            unexpired(&sign_in(Some(NOW)), &request()),
            Err(MintError::Expired { expired_at, .. }) if expired_at == NOW
        ));
        assert!(matches!(
            mint(&keys.public_identity(), &sign_in(Some(NOW)), &request(), 5),
            Err(MintError::Expired { expired_at, .. }) if expired_at == NOW
        ));

        // Logout's revocation covers every box on the host.
        let revocation = revocation_event();
        assert_eq!(revocation.kind, Kind::Revocation);
        assert_eq!(revocation.box_id, EVERY_BOX);
    }

    /// A key the store refuses this program, as macOS refuses a rebuilt
    /// binary the key its predecessor generated.
    #[derive(Clone)]
    enum Held {
        Refused,
        Usable(crate::keychain::MemoryKey),
    }

    impl PrivateKey for Held {
        fn public_key(&self) -> Result<PublicKey, StoreError> {
            match self {
                Self::Refused => Err(StoreError::Unusable),
                Self::Usable(key) => key.public_key(),
            }
        }

        fn agree(&self, peer: &PublicKey) -> Result<crate::keychain::SharedSecret, StoreError> {
            match self {
                Self::Refused => Err(StoreError::Unusable),
                Self::Usable(key) => key.agree(peer),
            }
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StoreError> {
            match self {
                Self::Refused => Err(StoreError::Unusable),
                Self::Usable(key) => key.sign(message),
            }
        }

        fn created_at(&self) -> Option<std::time::SystemTime> {
            None
        }
    }

    /// A store holding a client key its previous program generated.
    #[derive(Default)]
    struct Rebuilt {
        replaced: std::sync::Mutex<bool>,
        keys: MemoryStore,
    }

    impl KeyStore for Rebuilt {
        type Key = Held;

        const NAME: &'static str = "rebuilt";

        fn find(&self, name: &str) -> Result<Option<Held>, StoreError> {
            if !*self.replaced.lock().unwrap() {
                return Ok(Some(Held::Refused));
            }
            Ok(self.keys.find(name)?.map(Held::Usable))
        }

        fn generate(&self, name: &str) -> Result<Held, StoreError> {
            self.keys.generate(name).map(Held::Usable)
        }

        fn delete(&self, _name: &str) -> Result<(), StoreError> {
            *self.replaced.lock().unwrap() = true;
            Ok(())
        }
    }

    /// A rebuilt client is refused the key its predecessor generated. That
    /// key signs nothing but handles, and every mint registers the key it
    /// signs under first, so it is replaced with one this program can use,
    /// found again from then on, rather than failing every mint.
    #[test]
    fn a_client_key_this_program_is_refused_is_replaced() {
        let store = Rebuilt::default();
        let replaced = client_key(&store).unwrap().public_key().unwrap();
        assert_eq!(client_key(&store).unwrap().public_key().unwrap(), replaced);
    }
}
