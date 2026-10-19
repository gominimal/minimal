//! The sealed envelope (BEP-006, BEP-027).
//!
//! A sealed value is a compact JWE (RFC 7516) with `typ`
//! `gatehouse-sealed-secret+jwe`, after Gatehouse §6.10 (Sealed secret). The
//! key agreement is ECDH-ES on P-256 with the host's proxy key (RFC 7518
//! §4.6), in direct mode, so the encrypted-key segment is empty. The content
//! encryption is A256GCM.
//!
//! The bound context is in the JWE protected header, with the member names of
//! Gatehouse §6.10: `sub` (the box id), `node_id` (the host), `upstream`
//! (`{"module", "host_set_version"}`), `mode`, `iat`, `exp` and `kid`, the
//! proxy key's fingerprint. A256GCM authenticates the protected header as its
//! associated data, so a change to any byte of the context makes the value
//! fail to open. The plaintext is the member list, as JSON:
//! `{"members": [{"kind": "signin", "breadth": "full", "jws": ..., "exp"?: ...}],
//! "default_owner"?: ...}`. A v1 value carries exactly one member, and
//! [`open`] refuses a member of unknown `kind`.
//!
//! [`open`] refuses a value sealed to another key, a value that does not
//! decrypt, a value bound to another box, host or module, and a value past
//! its expiry at the clock time the caller gives. It returns the carried
//! context with the member. It does not compare the mode or the host-set
//! version. The mode is for the audit record. The caller admits an authority
//! only when it is in both the carried host-set version's set and the
//! current set.
//!
//! The envelope gives confidentiality and binding, not origin. [`seal`]
//! needs only the public key, so any holder of that key, a box included, can
//! seal a value that [`open`] accepts. So an opened member carries no
//! authority of its own. In v1 its credential is a sign-in reference, a
//! handle signed under the client's local key (BEP-005). The caller must
//! verify that signature, the handle's expiry and its upstream set before it
//! uses the credential (BEP-064). A forged envelope then carries nothing
//! that the caller admits.
//!
//! The printed form has five dot-separated segments, and the second is
//! empty. No GitHub token form matches it: not the `ghp_`, `gho_`, `ghu_`,
//! `ghs_`, `ghr_` or `github_pat_` prefixes, not 40 hex digits, and not a
//! three-segment JWT. So `api.github.com` rejects it when a box presents it
//! directly (BEP-027).

use std::fmt;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

/// The JWE `typ` of every sealed value.
pub const TYP: &str = "gatehouse-sealed-secret+jwe";

/// The JWE key-management algorithm: direct ECDH-ES key agreement.
const ALG: &str = "ECDH-ES";

/// The JWE content-encryption algorithm.
const ENC: &str = "A256GCM";

/// The length of a P-256 scalar or coordinate, and of an A256GCM key.
const FIELD_LEN: usize = 32;

/// The length of an A256GCM nonce.
const IV_LEN: usize = 12;

/// The length of an A256GCM tag.
const TAG_LEN: usize = 16;

/// The longest sealed value [`open`] reads. A box sends the value, so
/// [`open`] refuses a longer one before it decodes anything. One member with
/// a signed handle is far below this.
pub const MAX_SEALED_LEN: usize = 16 * 1024;

/// The mode a member acts in. The proxy records it for the audit and does
/// not refuse on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The member acts as the signed-in user.
    User,
    /// The member acts as a GitHub App installation.
    Installation,
}

/// What a member is. Its wire name is the member's `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberKind {
    /// A reference to the host's GitHub sign-in (BEP-005).
    SignIn,
}

/// How much of the module's authority a member carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Breadth {
    /// Everything the module's registration permits.
    Full,
}

/// The context a sealed value carries in its protected header.
///
/// Every field is authenticated: a change to one makes the value fail to
/// open. [`open`] compares `box_id`, `host` and `module` with the request,
/// and refuses the value when [`Context::is_expired`] at the request's
/// clock time. The caller records `mode` for the audit, and admits an
/// authority only when it is in both the `host_set_version` set and the
/// current set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Context {
    /// The id of the box the value was minted for.
    pub box_id: String,
    /// The Box Host whose proxy can open the value.
    pub host: String,
    /// The module identifier, as in [`crate::module::Module::id`].
    pub module: String,
    /// The module's host-set version at the mint.
    pub host_set_version: u32,
    /// The mode the members act in.
    pub mode: Mode,
    /// The issue time, in seconds since the Unix epoch.
    pub iat: u64,
    /// The expiry, in seconds since the Unix epoch.
    pub expiry: u64,
    /// The fingerprint of the proxy key the value is sealed to, as
    /// [`ProxyPublicKey::kid`] gives it.
    pub kid: String,
}

impl Context {
    /// Whether the value is expired at `now`, in seconds since the Unix
    /// epoch.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expiry
    }
}

/// The request [`open`] checks a sealed value against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Binding {
    /// The id of the box that presents the value.
    pub box_id: String,
    /// This Box Host.
    pub host: String,
    /// The module of the upstream the request goes to.
    pub module: String,
    /// The proxy's clock at the request, in seconds since the Unix epoch.
    pub now: u64,
}

/// A field of [`Context`] that [`open`] compares with the expected
/// [`Binding`]. Its `Display` names the field and never carries a value, so
/// a log line can say which field differed.
///
/// Only the box id, host and module are compared (Gatehouse §6.10). The
/// expiry is a clock check, reported as [`OpenError::Expired`]. The mode,
/// host-set version, issue time and key id are carried in the authenticated
/// header: a change to one of them breaks the tag, and [`open`] reports it
/// as [`OpenError::NotOpenable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundField {
    /// [`Context::box_id`].
    BoxId,
    /// [`Context::host`].
    Host,
    /// [`Context::module`].
    Module,
}

impl fmt::Display for BoundField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BoxId => "box id",
            Self::Host => "host",
            Self::Module => "module",
        })
    }
}

/// One entry of the member list: its kind, its breadth, its signed handle
/// and its expiry, if it has one.
#[derive(Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's kind.
    pub kind: MemberKind,
    /// The member's breadth.
    pub breadth: Breadth,
    /// The signed handle, a compact JWS. Zeroed on drop.
    pub jws: Zeroizing<String>,
    /// The member's own expiry, in seconds since the Unix epoch. [`open`]
    /// checks it only when it is present.
    pub exp: Option<u64>,
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("kind", &self.kind)
            .field("breadth", &self.breadth)
            .field("jws", &"<redacted>")
            .field("exp", &self.exp)
            .finish()
    }
}

/// The sealed plaintext: the member list. A v1 value carries exactly one
/// member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberList {
    /// The members.
    pub members: Vec<Member>,
    /// The member that acts when a request names no owner, if any.
    pub default_owner: Option<String>,
}

/// What [`open`] returns: the carried context and the member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The context from the protected header.
    pub context: Context,
    /// The one member of the decrypted list.
    pub member: Member,
    /// The list's default owner, if any.
    pub default_owner: Option<String>,
}

/// This host's proxy key: the static P-256 secret that opens sealed values.
pub struct ProxyKey(SecretKey);

impl ProxyKey {
    /// Draws a new key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`SealError::Random`] when the random source fails.
    pub fn generate() -> Result<Self, SealError> {
        random_secret().map(Self)
    }

    /// Restores a key from its 32 secret bytes. Returns `None` when the
    /// bytes are not a valid P-256 scalar.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; FIELD_LEN]) -> Option<Self> {
        SecretKey::from_slice(bytes).ok().map(Self)
    }

    /// The public half, which a mint seals to.
    #[must_use]
    pub fn public(&self) -> ProxyPublicKey {
        ProxyPublicKey(self.0.public_key())
    }
}

impl fmt::Debug for ProxyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProxyKey").field(&"<redacted>").finish()
    }
}

/// The public half of a [`ProxyKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyPublicKey(PublicKey);

impl ProxyPublicKey {
    /// Restores a public key from its SEC1 encoding. Returns `None` when the
    /// bytes are not a P-256 point.
    #[must_use]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Option<Self> {
        PublicKey::from_sec1_bytes(bytes).ok().map(Self)
    }

    /// The uncompressed SEC1 encoding.
    #[must_use]
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.0.to_sec1_bytes()
    }

    /// The key's fingerprint: its RFC 7638 JWK thumbprint under SHA-256, in
    /// unpadded base64url. A sealed value carries it as `kid`.
    #[must_use]
    pub fn kid(&self) -> String {
        let jwk = Jwk::of(&self.0);
        // RFC 7638 §3.2: the required members, in lexicographic order, with
        // no whitespace.
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk.crv, jwk.kty, jwk.x, jwk.y
        );
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
    }
}

/// Why a value was not sealed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    /// The context's `kid` is not the fingerprint of the recipient key.
    #[error("the key id in the context is not the recipient key's fingerprint")]
    KidMismatch,
    /// The member list does not hold exactly one member.
    #[error("the member list does not hold exactly one member")]
    MemberCount,
    /// The operating system's random source failed.
    #[error("the random source failed")]
    Random,
    /// The cipher refused the plaintext.
    #[error("the member list could not be encrypted")]
    Encrypt,
}

/// Why a sealed value did not open. No variant carries a value from the
/// envelope or the expected binding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    /// The value is not a compact JWE, is longer than [`MAX_SEALED_LEN`], or
    /// a segment or the header does not decode.
    #[error("the value is not a sealed value")]
    Malformed,
    /// The header's `typ`, `alg`, `enc` or key is not one this proxy reads.
    #[error("the sealed value uses an unsupported type or algorithm")]
    Unsupported,
    /// The `kid` is not this proxy key's fingerprint, or the value does not
    /// decrypt under this proxy key because a byte of the header or the
    /// ciphertext changed.
    #[error("the sealed value does not open under this host's proxy key")]
    NotOpenable,
    /// A bound field differs from the expected binding.
    #[error("the sealed value is bound to a different {0}")]
    ContextMismatch(BoundField),
    /// The value's expiry ([`Context::expiry`]), or the member's `exp`
    /// when it has one, is at or before the request's clock time.
    #[error("the sealed value is past its expiry")]
    Expired,
    /// The plaintext is not a member list of exactly one member.
    #[error("the sealed value carries no member list this proxy reads")]
    BadMembers,
    /// The member's breadth is missing or not one this proxy knows.
    #[error("the sealed member has a missing or unknown breadth")]
    UnknownBreadth,
    /// The member's kind is missing or not one this proxy knows.
    #[error("the sealed member has a missing or unknown kind")]
    UnknownKind,
}

/// Seals `members` to `recipient`, bound to `context`. Returns the compact
/// JWE.
///
/// # Errors
///
/// [`SealError`] when `context.kid` is not the recipient's fingerprint, the
/// list does not hold exactly one member, the random source fails or the
/// cipher refuses.
pub fn seal(
    recipient: &ProxyPublicKey,
    context: &Context,
    members: &MemberList,
) -> Result<String, SealError> {
    if context.kid != recipient.kid() {
        return Err(SealError::KidMismatch);
    }
    if members.members.len() != 1 {
        return Err(SealError::MemberCount);
    }
    seal_plaintext(recipient, context, &members.to_json()?)
}

/// Seals `plaintext` to `recipient` with `context` in the protected header.
fn seal_plaintext(
    recipient: &ProxyPublicKey,
    context: &Context,
    plaintext: &[u8],
) -> Result<String, SealError> {
    let ephemeral = random_secret()?;
    let header = Header::new(context, Jwk::of(&ephemeral.public_key()));
    let header_json = serde_json::to_vec(&header).map_err(|_| SealError::Encrypt)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);

    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.0.as_affine());
    let cipher = content_cipher(shared.raw_secret_bytes());

    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).map_err(|_| SealError::Random)?;

    let mut sealed = cipher
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: plaintext,
                aad: header_b64.as_bytes(),
            },
        )
        .map_err(|_| SealError::Encrypt)?;
    let tag = sealed.split_off(sealed.len() - TAG_LEN);

    Ok(format!(
        "{header_b64}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(sealed),
        URL_SAFE_NO_PAD.encode(tag),
    ))
}

/// Opens `sealed` under `key`, for a request from the box, host and module
/// that `expected` names.
///
/// # Errors
///
/// [`OpenError::ContextMismatch`] names the first of box id, host and module
/// that differs. [`OpenError::Expired`] says the value's expiry, or the
/// member's `exp` when it has one, is at or before `expected.now`. The other variants say the
/// value is malformed or longer than [`MAX_SEALED_LEN`], uses an unsupported algorithm, is sealed to another
/// key or does not decrypt, or carries no list of exactly one member with a
/// known kind and breadth.
///
/// A value that opens is not proof of who sealed it. The caller must verify
/// the member's signed handle, its `jws`, before it uses it. See the module docs.
pub fn open(key: &ProxyKey, sealed: &str, expected: &Binding) -> Result<Opened, OpenError> {
    if sealed.len() > MAX_SEALED_LEN {
        return Err(OpenError::Malformed);
    }
    let mut parts = sealed.split('.');
    let (Some(header_b64), Some(encrypted_key), Some(iv), Some(ciphertext), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(OpenError::Malformed);
    };
    if !encrypted_key.is_empty() {
        return Err(OpenError::Unsupported);
    }

    let header_json = decode(header_b64)?;
    let header: Header = serde_json::from_slice(&header_json).map_err(|_| OpenError::Malformed)?;
    if header.typ != TYP || header.alg != ALG || header.enc != ENC {
        return Err(OpenError::Unsupported);
    }
    // A value sealed to another key is refused before any decryption.
    if header.kid != key.public().kid() {
        return Err(OpenError::NotOpenable);
    }
    let ephemeral = header.epk.to_public_key().ok_or(OpenError::Unsupported)?;

    let iv: [u8; IV_LEN] = decode(iv)?.try_into().map_err(|_| OpenError::Malformed)?;
    let mut message = decode(ciphertext)?;
    let tag = decode(tag)?;
    if tag.len() != TAG_LEN {
        return Err(OpenError::Malformed);
    }
    message.extend_from_slice(&tag);

    let shared = p256::ecdh::diffie_hellman(key.0.to_nonzero_scalar(), ephemeral.as_affine());
    let cipher = content_cipher(shared.raw_secret_bytes());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::from(iv),
                Payload {
                    msg: &message,
                    aad: header_b64.as_bytes(),
                },
            )
            .map_err(|_| OpenError::NotOpenable)?,
    );

    // Gatehouse §6.10: the box, host and module bind, and the expiry is a
    // check against the clock. The mode is for the audit, and the host-set
    // version selects the bound set.
    let context = header.into_context();
    for (field, carried, wanted) in [
        (BoundField::BoxId, &context.box_id, &expected.box_id),
        (BoundField::Host, &context.host, &expected.host),
        (BoundField::Module, &context.module, &expected.module),
    ] {
        if carried != wanted {
            return Err(OpenError::ContextMismatch(field));
        }
    }
    if context.is_expired(expected.now) {
        return Err(OpenError::Expired);
    }

    let MemberList {
        mut members,
        default_owner,
    } = MemberList::from_json(&plaintext)?;
    let member = members.pop().ok_or(OpenError::BadMembers)?;
    // A member can carry its own expiry. A member past it is refused here,
    // so a caller never has to check `member.exp` itself.
    if member.exp.is_some_and(|exp| expected.now >= exp) {
        return Err(OpenError::Expired);
    }
    Ok(Opened {
        context,
        member,
        default_owner,
    })
}

fn decode(segment: &str) -> Result<Vec<u8>, OpenError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| OpenError::Malformed)
}

fn random_secret() -> Result<SecretKey, SealError> {
    let mut bytes = Zeroizing::new([0u8; FIELD_LEN]);
    // A random 32-byte string is a valid scalar unless it is zero or at
    // least the group order: a chance near 2^-32 per draw.
    for _ in 0..16 {
        getrandom::fill(bytes.as_mut()).map_err(|_| SealError::Random)?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
    Err(SealError::Random)
}

/// The A256GCM cipher under the Concat KDF output for direct ECDH-ES
/// (RFC 7518 §4.6.2), with empty `apu` and `apv`.
fn content_cipher(shared: &[u8]) -> Aes256Gcm {
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(shared);
    put_len_prefixed(&mut hash, ENC.as_bytes());
    put_len_prefixed(&mut hash, b"");
    put_len_prefixed(&mut hash, b"");
    hash.update(256u32.to_be_bytes());
    let key = Zeroizing::new(<[u8; FIELD_LEN]>::from(hash.finalize()));
    // The key is 32 bytes, the A256GCM key length.
    #[allow(clippy::expect_used)]
    Aes256Gcm::new_from_slice(key.as_ref()).expect("a SHA-256 digest is an A256GCM key")
}

fn put_len_prefixed(hash: &mut Sha256, bytes: &[u8]) {
    // Every input here is a fixed short constant.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hash.update(len.to_be_bytes());
    hash.update(bytes);
}

/// A P-256 public key as a JWK (RFC 7518 §6.2).
#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

impl Jwk {
    fn of(key: &PublicKey) -> Self {
        let sec1 = key.to_sec1_bytes();
        // P-256 encodes uncompressed: 0x04, then x, then y.
        let x = sec1.get(1..=FIELD_LEN).unwrap_or_default();
        let y = sec1.get(1 + FIELD_LEN..).unwrap_or_default();
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }

    fn to_public_key(&self) -> Option<PublicKey> {
        if self.kty != "EC" || self.crv != "P-256" {
            return None;
        }
        let x = URL_SAFE_NO_PAD.decode(&self.x).ok()?;
        let y = URL_SAFE_NO_PAD.decode(&self.y).ok()?;
        if x.len() != FIELD_LEN || y.len() != FIELD_LEN {
            return None;
        }
        let mut sec1 = Vec::with_capacity(1 + 2 * FIELD_LEN);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        PublicKey::from_sec1_bytes(&sec1).ok()
    }
}

/// The JWE protected header, with the member names of Gatehouse §6.10.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    typ: String,
    alg: String,
    enc: String,
    kid: String,
    epk: Jwk,
    #[serde(rename = "sub")]
    box_id: String,
    #[serde(rename = "node_id")]
    host: String,
    upstream: Upstream,
    mode: Mode,
    iat: u64,
    exp: u64,
}

/// The header's `upstream` member: the module id and its host-set version.
#[derive(Debug, Serialize, Deserialize)]
struct Upstream {
    module: String,
    host_set_version: u32,
}

impl Header {
    fn new(context: &Context, epk: Jwk) -> Self {
        Self {
            typ: TYP.into(),
            alg: ALG.into(),
            enc: ENC.into(),
            kid: context.kid.clone(),
            epk,
            box_id: context.box_id.clone(),
            host: context.host.clone(),
            upstream: Upstream {
                module: context.module.clone(),
                host_set_version: context.host_set_version,
            },
            mode: context.mode,
            iat: context.iat,
            exp: context.expiry,
        }
    }

    fn into_context(self) -> Context {
        Context {
            box_id: self.box_id,
            host: self.host,
            module: self.upstream.module,
            host_set_version: self.upstream.host_set_version,
            mode: self.mode,
            iat: self.iat,
            expiry: self.exp,
            kid: self.kid,
        }
    }
}

/// The member list as JSON.
#[derive(Serialize, Deserialize)]
struct WireList {
    members: Vec<WireMember>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    default_owner: Option<String>,
}

/// One member as JSON. `kind` and `breadth` read as optional strings, so a
/// missing or unknown value is told apart from a malformed list.
#[derive(Serialize, Deserialize)]
struct WireMember {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    breadth: Option<String>,
    jws: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    exp: Option<u64>,
}

impl Drop for WireMember {
    fn drop(&mut self) {
        self.jws.zeroize();
    }
}

impl MemberKind {
    fn as_wire(self) -> &'static str {
        match self {
            Self::SignIn => "signin",
        }
    }

    fn from_wire(wire: Option<&str>) -> Option<Self> {
        match wire? {
            "signin" => Some(Self::SignIn),
            _ => None,
        }
    }
}

impl Breadth {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Full => "full",
        }
    }

    fn from_wire(wire: Option<&str>) -> Option<Self> {
        match wire? {
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

impl MemberList {
    fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let wire = WireList {
            members: self
                .members
                .iter()
                .map(|member| WireMember {
                    kind: Some(member.kind.as_wire().into()),
                    breadth: Some(member.breadth.as_wire().into()),
                    jws: member.jws.as_str().into(),
                    exp: member.exp,
                })
                .collect(),
            default_owner: self.default_owner.clone(),
        };
        serde_json::to_vec(&wire)
            .map(Zeroizing::new)
            .map_err(|_| SealError::Encrypt)
    }

    fn from_json(json: &[u8]) -> Result<Self, OpenError> {
        let wire: WireList = serde_json::from_slice(json).map_err(|_| OpenError::BadMembers)?;
        if wire.members.len() != 1 {
            return Err(OpenError::BadMembers);
        }
        let members = wire
            .members
            .iter()
            .map(|member| {
                let kind =
                    MemberKind::from_wire(member.kind.as_deref()).ok_or(OpenError::UnknownKind)?;
                let breadth = Breadth::from_wire(member.breadth.as_deref())
                    .ok_or(OpenError::UnknownBreadth)?;
                Ok(Member {
                    kind,
                    breadth,
                    jws: Zeroizing::new(member.jws.clone()),
                    exp: member.exp,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            members,
            default_owner: wire.default_owner.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn member(jws: &str) -> Member {
        Member {
            kind: MemberKind::SignIn,
            breadth: Breadth::Full,
            jws: Zeroizing::new(jws.into()),
            exp: Some(1_900_000_000),
        }
    }

    fn members(jws: &str) -> MemberList {
        MemberList {
            members: vec![member(jws)],
            default_owner: None,
        }
    }

    fn binding(context: &Context) -> Binding {
        Binding {
            box_id: context.box_id.clone(),
            host: context.host.clone(),
            module: context.module.clone(),
            now: 0,
        }
    }

    fn context_strategy(kid: String) -> impl Strategy<Value = Context> {
        (
            "[a-z0-9-]{1,40}",
            "[a-z0-9.-]{1,40}",
            "[a-z]{1,12}",
            any::<u32>(),
            prop_oneof![Just(Mode::User), Just(Mode::Installation)],
            any::<u64>(),
            1..=u64::MAX,
        )
            .prop_map(
                move |(box_id, host, module, host_set_version, mode, iat, expiry)| Context {
                    box_id,
                    host,
                    module,
                    host_set_version,
                    mode,
                    iat,
                    expiry,
                    kid: kid.clone(),
                },
            )
    }

    /// A member of the protected header that the authenticated context
    /// carries.
    #[derive(Debug, Clone, Copy)]
    enum HeaderField {
        BoxId,
        Host,
        Module,
        HostSetVersion,
        Mode,
        Iat,
        Expiry,
    }

    /// Rewrites one field of the sealed value's protected header and keeps
    /// every other byte.
    fn rewrite_header(sealed: &str, field: HeaderField) -> String {
        let (header_b64, rest) = sealed.split_once('.').unwrap();
        let mut header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let value = match field {
            HeaderField::BoxId => &mut header["sub"],
            HeaderField::Host => &mut header["node_id"],
            HeaderField::Module => &mut header["upstream"]["module"],
            HeaderField::HostSetVersion => &mut header["upstream"]["host_set_version"],
            HeaderField::Mode => &mut header["mode"],
            HeaderField::Iat => &mut header["iat"],
            HeaderField::Expiry => &mut header["exp"],
        };
        *value = match value.take() {
            serde_json::Value::String(s) if s == "user" => "installation".into(),
            serde_json::Value::String(s) if s == "installation" => "user".into(),
            serde_json::Value::String(s) => format!("{s}x").into(),
            serde_json::Value::Number(n) => (n.as_u64().unwrap() ^ 1).into(),
            other => panic!("unexpected header value {other}"),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        format!("{header_b64}.{rest}")
    }

    const COMPARED: [BoundField; 3] = [BoundField::BoxId, BoundField::Host, BoundField::Module];

    const CARRIED: [HeaderField; 7] = [
        HeaderField::BoxId,
        HeaderField::Host,
        HeaderField::Module,
        HeaderField::HostSetVersion,
        HeaderField::Mode,
        HeaderField::Iat,
        HeaderField::Expiry,
    ];

    // BEP-006: the box id, host, module, host-set version, mode and expiry
    // are bound in the authenticated context, and the breadth rides the
    // authenticated plaintext.
    proptest! {
        #[test]
        fn sealed_context_binds_box_host_module_version_expiry(
            (key_bytes, context) in any::<[u8; 32]>()
                .prop_filter_map("not a P-256 scalar", |b| ProxyKey::from_bytes(&b).map(|_| b))
                .prop_flat_map(|b| {
                    let kid = ProxyKey::from_bytes(&b).unwrap().public().kid();
                    (Just(b), context_strategy(kid))
                }),
            jws in "[A-Za-z0-9_-]{0,40}\\.[A-Za-z0-9_-]{0,40}\\.[A-Za-z0-9_-]{0,40}",
            compared in 0..COMPARED.len(),
            carried in 0..CARRIED.len(),
        ) {
            let key = ProxyKey::from_bytes(&key_bytes).unwrap();
            let sealed = seal(&key.public(), &context, &members(&jws)).unwrap();

            // It opens for its own box, host and module before its expiry,
            // whatever the carried mode and host-set version, and returns the
            // carried context and the member with its breadth.
            let opened = open(&key, &sealed, &binding(&context)).unwrap();
            prop_assert_eq!(&opened.context, &context);
            prop_assert_eq!(&opened.member, &member(&jws));
            prop_assert_eq!(opened.default_owner, None);

            // At or after its expiry it is refused, and the error names the
            // expiry and carries no value.
            let late = Binding { now: context.expiry, ..binding(&context) };
            let err = open(&key, &sealed, &late).unwrap_err();
            prop_assert_eq!(&err, &OpenError::Expired);
            prop_assert_eq!(err.to_string(), "the sealed value is past its expiry");

            // A request from another box, host or module is refused, and the
            // error names the field and carries no value.
            let field = COMPARED[compared];
            let mut other = binding(&context);
            match field {
                BoundField::BoxId => other.box_id.push('x'),
                BoundField::Host => other.host.push('x'),
                BoundField::Module => other.module.push('x'),
            }
            let err = open(&key, &sealed, &other).unwrap_err();
            prop_assert_eq!(&err, &OpenError::ContextMismatch(field));
            prop_assert_eq!(
                err.to_string(),
                format!("the sealed value is bound to a different {field}")
            );

            // A rewrite of any carried field breaks the tag, and is never
            // reported as a mismatch of a named field.
            let forged = rewrite_header(&sealed, CARRIED[carried]);
            prop_assert_eq!(
                open(&key, &forged, &binding(&context)).unwrap_err(),
                OpenError::NotOpenable
            );

            // Another host's proxy key does not open it.
            let other_key = ProxyKey::generate().unwrap();
            prop_assert_eq!(
                open(&other_key, &sealed, &binding(&context)).unwrap_err(),
                OpenError::NotOpenable
            );
        }
    }

    fn fixed_context(key: &ProxyKey) -> Context {
        Context {
            box_id: "0199f0c2-7a3e-7cc1-9d1e-000000000000".into(),
            host: "bep-test-host".into(),
            module: crate::module::GITHUB.id.into(),
            host_set_version: crate::module::GITHUB.host_set_version,
            mode: Mode::User,
            iat: 1_800_000_000,
            expiry: 1_900_000_000,
            kid: key.public().kid(),
        }
    }

    #[test]
    fn sealed_value_is_a_direct_compact_jwe_with_the_gatehouse_typ() {
        let key = ProxyKey::generate().unwrap();
        let sealed = seal(&key.public(), &fixed_context(&key), &members("h.p.s")).unwrap();
        let parts: Vec<&str> = sealed.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[1].is_empty());
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], TYP);
        assert_eq!(header["alg"], "ECDH-ES");
        assert_eq!(header["enc"], "A256GCM");
        assert_eq!(header["epk"]["crv"], "P-256");
        assert_eq!(header["iat"], 1_800_000_000_u64);
    }

    #[test]
    fn a_forged_kid_and_a_wrong_context_kid_are_refused() {
        let key = ProxyKey::generate().unwrap();
        let other = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        assert_eq!(
            seal(&other.public(), &context, &members("h.p.s")).unwrap_err(),
            SealError::KidMismatch
        );
        // Sealed to `other`, relabelled with this key's kid: the agreement
        // and the tag both fail.
        let to_other = Context {
            kid: other.public().kid(),
            ..context.clone()
        };
        let sealed = seal(&other.public(), &to_other, &members("h.p.s")).unwrap();
        let (header_b64, rest) = sealed.split_once('.').unwrap();
        let mut header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        header["kid"] = key.public().kid().into();
        let forged = format!(
            "{}.{rest}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
        );
        assert_eq!(
            open(&key, &forged, &binding(&context)).unwrap_err(),
            OpenError::NotOpenable
        );
        assert_eq!(
            open(&key, "ghp_notours", &binding(&context)).unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn expiry_is_a_clock_check() {
        let key = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        assert!(!context.is_expired(context.expiry - 1));
        assert!(context.is_expired(context.expiry));
        assert!(context.is_expired(context.expiry + 1));
        let sealed = seal(&key.public(), &context, &members("h.p.s")).unwrap();
        let before = Binding {
            now: context.expiry - 1,
            ..binding(&context)
        };
        assert!(open(&key, &sealed, &before).is_ok());
        let after = Binding {
            now: context.expiry + 1,
            ..binding(&context)
        };
        assert_eq!(open(&key, &sealed, &after).unwrap_err(), OpenError::Expired);
    }

    #[test]
    fn a_member_past_its_own_exp_is_refused() {
        let key = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        let early = MemberList {
            members: vec![Member {
                exp: Some(context.expiry - 100),
                ..member("h.p.s")
            }],
            default_owner: None,
        };
        let sealed = seal(&key.public(), &context, &early).unwrap();
        let before = Binding {
            now: context.expiry - 101,
            ..binding(&context)
        };
        assert!(open(&key, &sealed, &before).is_ok());
        let after = Binding {
            now: context.expiry - 100,
            ..binding(&context)
        };
        assert_eq!(open(&key, &sealed, &after).unwrap_err(), OpenError::Expired);
    }

    #[test]
    fn a_value_longer_than_the_cap_is_refused_before_decoding() {
        let key = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        let long = "a".repeat(MAX_SEALED_LEN + 1);
        assert_eq!(
            open(&key, &long, &binding(&context)).unwrap_err(),
            OpenError::Malformed
        );
    }

    // Gatehouse §6.10: the un-enrolled member is `{kind, breadth, jws}`, and
    // its `exp` is optional. A member with no `exp` opens until the value's
    // expiry.
    #[test]
    fn a_member_with_no_exp_opens_until_the_value_expiry() {
        let key = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        let plaintext = br#"{"members":[{"kind":"signin","breadth":"full","jws":"h.p.s"}]}"#;
        let sealed = seal_plaintext(&key.public(), &context, plaintext).unwrap();
        let late = Binding {
            now: context.expiry - 1,
            ..binding(&context)
        };
        let opened = open(&key, &sealed, &late).unwrap();
        assert_eq!(
            opened.member,
            Member {
                exp: None,
                ..member("h.p.s")
            }
        );
    }

    #[test]
    fn the_header_uses_the_gatehouse_member_names() {
        let key = ProxyKey::generate().unwrap();
        let context = Context {
            mode: Mode::Installation,
            ..fixed_context(&key)
        };
        let sealed = seal(&key.public(), &context, &members("h.p.s")).unwrap();
        let (header_b64, _) = sealed.split_once('.').unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["sub"], context.box_id.as_str());
        assert_eq!(header["node_id"], context.host.as_str());
        assert_eq!(header["upstream"]["module"], context.module.as_str());
        assert_eq!(
            header["upstream"]["host_set_version"],
            context.host_set_version
        );
        assert_eq!(header["mode"], "installation");
        for gone in ["box_id", "host", "module", "host_set_version"] {
            assert!(header.get(gone).is_none(), "{gone} is in the header");
        }
    }

    #[test]
    fn a_list_of_other_than_one_member_or_an_unknown_breadth_is_refused() {
        let key = ProxyKey::generate().unwrap();
        let context = fixed_context(&key);
        let two = MemberList {
            members: vec![member("a.b.c"), member("d.e.f")],
            default_owner: None,
        };
        assert_eq!(
            seal(&key.public(), &context, &two).unwrap_err(),
            SealError::MemberCount
        );
        let cases: [(&[u8], OpenError); 6] = [
            (br#"{"members":[]}"#, OpenError::BadMembers),
            (
                br#"{"members":[{"kind":"signin","breadth":"full","jws":"a.b.c"},{"kind":"signin","breadth":"full","jws":"d.e.f"}]}"#,
                OpenError::BadMembers,
            ),
            (
                br#"{"members":[{"breadth":"full","jws":"a.b.c"}]}"#,
                OpenError::UnknownKind,
            ),
            (
                br#"{"members":[{"kind":"token","breadth":"full","jws":"a.b.c"}]}"#,
                OpenError::UnknownKind,
            ),
            (
                br#"{"members":[{"kind":"signin","jws":"a.b.c"}]}"#,
                OpenError::UnknownBreadth,
            ),
            (
                br#"{"members":[{"kind":"signin","breadth":"repo","jws":"a.b.c"}]}"#,
                OpenError::UnknownBreadth,
            ),
        ];
        for (plaintext, want) in cases {
            let sealed = seal_plaintext(&key.public(), &context, plaintext).unwrap();
            assert_eq!(open(&key, &sealed, &binding(&context)).unwrap_err(), want);
        }
    }

    #[test]
    fn debug_output_carries_no_secret() {
        let shown = format!("{:?}", members("s3cr3t-value"));
        assert!(!shown.contains("s3cr3t"));
    }

    // BEP-027: GitHub rejects a sealed value presented as a credential. Needs
    // the network, so it runs under `--run-ignored`.
    #[test]
    #[ignore = "calls api.github.com over the network"]
    fn sealed_value_rejected_by_github() {
        let key = ProxyKey::generate().unwrap();
        let sealed = seal(
            &key.public(),
            &fixed_context(&key),
            &members("signin.reference.jws"),
        )
        .unwrap();

        let client = reqwest::blocking::Client::builder()
            .user_agent("minimal-bep-test")
            .build()
            .unwrap();
        let attempts = [
            client
                .get("https://api.github.com/user")
                .header("Authorization", format!("Bearer {sealed}")),
            client
                .get("https://api.github.com/user")
                .header("Authorization", format!("token {sealed}")),
            client
                .get("https://api.github.com/user")
                .basic_auth("x-access-token", Some(&sealed)),
        ];
        for request in attempts {
            let response = request.send().unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "api.github.com did not reject the sealed value as a credential"
            );
        }
    }
}
