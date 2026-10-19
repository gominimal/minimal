//! The sealed envelope (BEP-006, BEP-027).
//!
//! A member is sealed to this host's proxy key. The seal is an ephemeral
//! X25519 agreement with the proxy's static key, HKDF-SHA256 over the shared
//! secret, and ChaCha20-Poly1305 under the derived key. Each seal draws a
//! fresh ephemeral key, so each derived key encrypts one message and the
//! nonce can be fixed.
//!
//! The bound context (box id, host, module identifier, host-set version,
//! mode and expiry) is the AEAD's associated data. It also travels in the
//! clear inside the envelope. A failed open can then name the field that
//! differed, and the tag still covers every byte of it. The member's
//! breadth and its secret are the authenticated plaintext.
//!
//! The printed form is `minseal1_` followed by unpadded base64url. No GitHub
//! token form matches it: not the `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` or
//! `github_pat_` prefixes, not 40 hex digits, and not a dotted JWT. So
//! `api.github.com` rejects it when a box presents it directly (BEP-027).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The prefix of every sealed value.
pub const PREFIX: &str = "minseal1_";

/// The envelope format version, the first byte after the prefix decodes.
const FORMAT_VERSION: u8 = 1;

/// The HKDF info string. It separates this key use from any other.
const KDF_INFO: &[u8] = b"minimal bep seal v1";

/// The length of an X25519 public key.
const KEY_LEN: usize = 32;

/// The mode a member acts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The member acts as the signed-in user.
    User,
    /// The member acts as a GitHub App installation.
    App,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::App => "app",
        }
    }
}

/// How much of the module's authority a member carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Breadth {
    /// Everything the module's registration permits.
    Full,
}

impl Breadth {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
        }
    }

    fn parse(raw: &[u8]) -> Option<Self> {
        match raw {
            b"full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// The fields a sealed member is bound to. A member opens only against a
/// context equal to the one it was sealed with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Context {
    /// The id of the box the member was minted for.
    pub box_id: String,
    /// The Box Host whose proxy can open the member.
    pub host: String,
    /// The module identifier, as in [`crate::module::Module::id`].
    pub module: String,
    /// The module's host-set version at the mint.
    pub host_set_version: u32,
    /// The mode the member acts in.
    pub mode: Mode,
    /// The expiry, in seconds since the Unix epoch.
    pub expiry: u64,
}

/// A bound field of [`Context`]. Its `Display` names the field and never
/// carries a value, so a log line can say which field differed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundField {
    /// [`Context::box_id`].
    BoxId,
    /// [`Context::host`].
    Host,
    /// [`Context::module`].
    Module,
    /// [`Context::host_set_version`].
    HostSetVersion,
    /// [`Context::mode`].
    Mode,
    /// [`Context::expiry`].
    Expiry,
}

impl fmt::Display for BoundField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BoxId => "box id",
            Self::Host => "host",
            Self::Module => "module",
            Self::HostSetVersion => "host-set version",
            Self::Mode => "mode",
            Self::Expiry => "expiry",
        })
    }
}

/// The sealed plaintext: the member's breadth and its secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's breadth.
    pub breadth: Breadth,
    /// The member's secret bytes. Zeroed on drop.
    pub secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("breadth", &self.breadth)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// This host's proxy key: the static X25519 secret that opens sealed
/// members.
pub struct ProxyKey(StaticSecret);

impl ProxyKey {
    /// Draws a new key from the operating system's random source.
    #[must_use]
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    /// Restores a key from its 32 secret bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The public half, which a mint seals to.
    #[must_use]
    pub fn public(&self) -> ProxyPublicKey {
        ProxyPublicKey(PublicKey::from(&self.0))
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
    /// Restores a public key from its 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// The 32 public bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }
}

/// Why a member was not sealed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    /// The proxy public key is a low-order point, so the agreement carries
    /// no secret.
    #[error("the proxy public key is not a usable X25519 key")]
    WeakProxyKey,
    /// A context field is longer than the envelope can carry.
    #[error("the {0} is too long to seal")]
    FieldTooLong(BoundField),
    /// The cipher refused the plaintext.
    #[error("the member could not be encrypted")]
    Encrypt,
}

/// Why a sealed value did not open. No variant carries a value from the
/// envelope or the expected context.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    /// The value is not a sealed value: a wrong prefix, bad base64url, or a
    /// truncated envelope.
    #[error("the value is not a sealed value")]
    Malformed,
    /// The envelope is in a format version this proxy does not read.
    #[error("the sealed value is in an unsupported format version")]
    UnsupportedVersion,
    /// A bound field of the envelope differs from the expected context.
    #[error("the sealed value is bound to a different {0}")]
    ContextMismatch(BoundField),
    /// The envelope does not decrypt under this proxy key: it was sealed to
    /// another key, or a byte of it changed.
    #[error("the sealed value does not open under this host's proxy key")]
    NotOpenable,
    /// The member's breadth is missing or not one this proxy knows.
    #[error("the sealed member carries no breadth this proxy recognises")]
    UnknownBreadth,
}

/// Seals `member` to `recipient`, bound to `context`. Returns the printed
/// sealed value.
///
/// # Errors
///
/// [`SealError`] when the recipient key is weak, a context field is too
/// long, or the cipher refuses the plaintext.
pub fn seal(
    recipient: &ProxyPublicKey,
    context: &Context,
    member: &Member,
) -> Result<String, SealError> {
    let aad = encode_context(context)?;

    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient.0);
    if !shared.was_contributory() {
        return Err(SealError::WeakProxyKey);
    }
    let cipher = derive_cipher(shared.as_bytes(), &ephemeral_public, &recipient.0);

    let mut plaintext = Zeroizing::new(Vec::with_capacity(member.secret.len() + 16));
    put_bytes(&mut plaintext, member.breadth.as_str().as_bytes())
        .map_err(|()| SealError::Encrypt)?;
    plaintext.extend_from_slice(&member.secret);

    let ciphertext = cipher
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SealError::Encrypt)?;

    let mut envelope = Vec::with_capacity(1 + KEY_LEN + aad.len() + ciphertext.len());
    envelope.push(FORMAT_VERSION);
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&aad);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope)))
}

/// Opens `sealed` under `key`, expecting it bound to `expected`.
///
/// # Errors
///
/// [`OpenError::ContextMismatch`] names the first bound field that differs.
/// The other variants say the value is malformed, in an unknown format,
/// sealed to another key or changed, or carries an unknown breadth.
pub fn open(key: &ProxyKey, sealed: &str, expected: &Context) -> Result<Member, OpenError> {
    let body = sealed.strip_prefix(PREFIX).ok_or(OpenError::Malformed)?;
    let envelope = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| OpenError::Malformed)?;

    let (&version, rest) = envelope.split_first().ok_or(OpenError::Malformed)?;
    if version != FORMAT_VERSION {
        return Err(OpenError::UnsupportedVersion);
    }
    let (ephemeral_bytes, rest) = rest.split_at_checked(KEY_LEN).ok_or(OpenError::Malformed)?;
    let ephemeral_public = PublicKey::from(
        <[u8; KEY_LEN]>::try_from(ephemeral_bytes).map_err(|_| OpenError::Malformed)?,
    );

    let before = rest.len();
    let mut cursor = rest;
    let carried = decode_context(&mut cursor)?;
    let aad = rest
        .get(..before - cursor.len())
        .ok_or(OpenError::Malformed)?;
    let ciphertext = cursor;

    let expected_fields = context_fields(expected);
    for ((field, carried), (_, expected)) in carried.iter().zip(expected_fields.iter()) {
        if carried != expected {
            return Err(OpenError::ContextMismatch(*field));
        }
    }

    let shared = key.0.diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err(OpenError::NotOpenable);
    }
    let cipher = derive_cipher(shared.as_bytes(), &ephemeral_public, &key.public().0);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| OpenError::NotOpenable)?,
    );

    let mut cursor: &[u8] = &plaintext;
    let breadth = take_bytes(&mut cursor)
        .ok()
        .and_then(Breadth::parse)
        .ok_or(OpenError::UnknownBreadth)?;
    Ok(Member {
        breadth,
        secret: Zeroizing::new(cursor.to_vec()),
    })
}

fn derive_cipher(
    shared: &[u8; KEY_LEN],
    ephemeral: &PublicKey,
    recipient: &PublicKey,
) -> ChaCha20Poly1305 {
    let mut salt = [0u8; 2 * KEY_LEN];
    let (left, right) = salt.split_at_mut(KEY_LEN);
    left.copy_from_slice(ephemeral.as_bytes());
    right.copy_from_slice(recipient.as_bytes());
    let kdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    // 32 bytes is far below HKDF-SHA256's 8160-byte output limit.
    #[allow(clippy::expect_used)]
    kdf.expand(KDF_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    ChaCha20Poly1305::new(Key::from_slice(okm.as_ref()))
}

/// The context's fields in envelope order, each as its encoded bytes.
fn context_fields(context: &Context) -> [(BoundField, Vec<u8>); 6] {
    [
        (BoundField::BoxId, context.box_id.as_bytes().to_vec()),
        (BoundField::Host, context.host.as_bytes().to_vec()),
        (BoundField::Module, context.module.as_bytes().to_vec()),
        (
            BoundField::HostSetVersion,
            context.host_set_version.to_be_bytes().to_vec(),
        ),
        (BoundField::Mode, context.mode.as_str().as_bytes().to_vec()),
        (BoundField::Expiry, context.expiry.to_be_bytes().to_vec()),
    ]
}

/// Encodes the context as a sequence of length-prefixed fields, in the
/// order of [`context_fields`].
fn encode_context(context: &Context) -> Result<Vec<u8>, SealError> {
    let mut out = Vec::new();
    for (field, bytes) in context_fields(context) {
        put_bytes(&mut out, &bytes).map_err(|()| SealError::FieldTooLong(field))?;
    }
    Ok(out)
}

fn decode_context(cursor: &mut &[u8]) -> Result<[(BoundField, Vec<u8>); 6], OpenError> {
    let mut take = |field| {
        take_bytes(cursor)
            .map(|bytes| (field, bytes.to_vec()))
            .map_err(|()| OpenError::Malformed)
    };
    Ok([
        take(BoundField::BoxId)?,
        take(BoundField::Host)?,
        take(BoundField::Module)?,
        take(BoundField::HostSetVersion)?,
        take(BoundField::Mode)?,
        take(BoundField::Expiry)?,
    ])
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ()> {
    let len = u32::try_from(bytes.len()).map_err(|_| ())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_bytes<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], ()> {
    let (len, rest) = cursor.split_first_chunk::<4>().ok_or(())?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| ())?;
    let (bytes, rest) = rest.split_at_checked(len).ok_or(())?;
    *cursor = rest;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn member(secret: &[u8]) -> Member {
        Member {
            breadth: Breadth::Full,
            secret: Zeroizing::new(secret.to_vec()),
        }
    }

    fn context_strategy() -> impl Strategy<Value = Context> {
        (
            "[a-z0-9-]{1,40}",
            "[a-z0-9.-]{1,40}",
            "[a-z]{1,12}",
            any::<u32>(),
            prop_oneof![Just(Mode::User), Just(Mode::App)],
            any::<u64>(),
        )
            .prop_map(
                |(box_id, host, module, host_set_version, mode, expiry)| Context {
                    box_id,
                    host,
                    module,
                    host_set_version,
                    mode,
                    expiry,
                },
            )
    }

    /// Changes exactly one bound field of `context`.
    fn alter(context: &Context, field: BoundField) -> Context {
        let mut out = context.clone();
        match field {
            BoundField::BoxId => out.box_id.push('x'),
            BoundField::Host => out.host.push('x'),
            BoundField::Module => out.module.push('x'),
            BoundField::HostSetVersion => {
                out.host_set_version = out.host_set_version.wrapping_add(1);
            }
            BoundField::Mode => {
                out.mode = match out.mode {
                    Mode::User => Mode::App,
                    Mode::App => Mode::User,
                };
            }
            BoundField::Expiry => out.expiry = out.expiry.wrapping_add(1),
        }
        out
    }

    const FIELDS: [BoundField; 6] = [
        BoundField::BoxId,
        BoundField::Host,
        BoundField::Module,
        BoundField::HostSetVersion,
        BoundField::Mode,
        BoundField::Expiry,
    ];

    // BEP-006: the box id, host, module, host-set version, mode and expiry are
    // bound, and the breadth rides the authenticated plaintext.
    proptest! {
        #[test]
        fn sealed_context_binds_box_host_module_version_expiry(
            context in context_strategy(),
            secret in proptest::collection::vec(any::<u8>(), 0..64),
            field_index in 0..FIELDS.len(),
        ) {
            let key = ProxyKey::generate();
            let sealed = seal(&key.public(), &context, &member(&secret)).unwrap();

            let opened = open(&key, &sealed, &context).unwrap();
            prop_assert_eq!(opened.breadth, Breadth::Full);
            prop_assert_eq!(opened.secret.as_slice(), secret.as_slice());

            let field = FIELDS[field_index];
            let other = alter(&context, field);
            let err = open(&key, &sealed, &other).unwrap_err();
            prop_assert_eq!(&err, &OpenError::ContextMismatch(field));

            // The error a proxy logs names the field and carries no value.
            prop_assert_eq!(
                err.to_string(),
                format!("the sealed value is bound to a different {field}")
            );

            // Another host's key does not open it.
            let other_key = ProxyKey::generate();
            prop_assert_eq!(
                open(&other_key, &sealed, &context).unwrap_err(),
                OpenError::NotOpenable
            );
        }
    }

    #[test]
    fn a_rewritten_carried_context_does_not_open() {
        let key = ProxyKey::generate();
        let context = Context {
            box_id: "box-a".into(),
            host: "host-1".into(),
            module: "github".into(),
            host_set_version: 1,
            mode: Mode::User,
            expiry: 1_900_000_000,
        };
        let sealed = seal(&key.public(), &context, &member(b"ref")).unwrap();
        // Rewrite the carried box id to another of the same length, so the
        // field compare passes and only the tag can catch it.
        let mut envelope = URL_SAFE_NO_PAD
            .decode(sealed.strip_prefix(PREFIX).unwrap())
            .unwrap();
        let at = 1 + KEY_LEN + 4 + 4;
        envelope[at] = b'b';
        let forged = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(envelope));
        let other = Context {
            box_id: "box-b".into(),
            ..context.clone()
        };
        assert_eq!(
            open(&key, &forged, &other).unwrap_err(),
            OpenError::NotOpenable
        );
        assert_eq!(
            open(&key, "ghp_notours", &context).unwrap_err(),
            OpenError::Malformed
        );
    }

    #[test]
    fn debug_output_carries_no_secret() {
        let shown = format!("{:?}", member(b"s3cr3t-value"));
        assert!(!shown.contains("s3cr3t"));
    }

    // BEP-027: GitHub rejects a sealed value presented as a credential. Needs
    // the network, so it runs under `--run-ignored`.
    #[test]
    #[ignore = "calls api.github.com over the network"]
    fn sealed_value_rejected_by_github() {
        let key = ProxyKey::generate();
        let context = Context {
            box_id: "0199f0c2-7a3e-7cc1-9d1e-000000000000".into(),
            host: "bep-test-host".into(),
            module: crate::module::GITHUB.id.into(),
            host_set_version: crate::module::GITHUB.host_set_version,
            mode: Mode::User,
            expiry: 1_900_000_000,
        };
        let sealed = seal(&key.public(), &context, &member(b"signin-reference")).unwrap();

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
