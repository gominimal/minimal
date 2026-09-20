//! The sealed envelope: a member bound to this host's sealing key and to its
//! authenticated context.
//!
//! A sealed value is `minsealed1.` followed by the unpadded base64url of
//!
//! ```text
//! header length (u16, big-endian) || header || ephemeral point (65) || nonce (12) || ciphertext
//! ```
//!
//! The header is JSON naming the sealing and root key fingerprints the value
//! is bound to and the context of BEP-006: the box, the host, the module, the
//! host-set version, the mode, the breadth and the expiry. The header bytes
//! are the AEAD's associated data, so a change to any of them, or to the
//! ciphertext, fails authentication. The content key is HKDF-SHA256 over an
//! ephemeral P-256 agreement with the host's sealing key, which only that key
//! can repeat, so the value decrypts on this host alone. The value is no
//! GitHub token in shape or in substance, so GitHub refuses it when it is
//! presented directly (BEP-027).

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::keychain::{KeyStore, PrivateKey, StoreError};
use crate::keys::{Fingerprint, KeyRole, Keys};

/// The prefix every sealed value carries; the `1` is the envelope version.
pub const PREFIX: &str = "minsealed1.";

const KDF_INFO: &[u8] = b"minimal bep sealed member v1";
const POINT_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The authenticated context a member is sealed with (BEP-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedContext {
    /// The box the member is minted for.
    #[serde(rename = "box")]
    pub box_id: String,
    /// The host the member is sealed on.
    pub host: String,
    /// The module identifier (`github`).
    pub module: String,
    /// The version of the module's host set the member was minted under.
    pub host_set_version: u32,
    /// The member's mode.
    pub mode: String,
    /// The member's breadth.
    pub breadth: String,
    /// The expiry, as seconds since the Unix epoch.
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Header {
    sealing_key: String,
    root_key: String,
    context: SealedContext,
}

/// A member's credential: the plaintext a value seals. Zeroed on drop and
/// redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Member(Zeroizing<String>);

impl Member {
    /// Wraps a credential.
    #[must_use]
    pub fn new(credential: impl Into<String>) -> Self {
        Self(Zeroizing::new(credential.into()))
    }

    /// The credential itself.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Member(<redacted>)")
    }
}

/// A sealed value, as delivered into a box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedValue(String);

impl SealedValue {
    /// The value's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What an unsealed value held.
#[derive(Debug)]
pub struct Unsealed {
    /// The authenticated context.
    pub context: SealedContext,
    /// The member's credential.
    pub member: Member,
}

/// Why a member could not be sealed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SealError {
    /// The context did not encode.
    #[error("encoding the sealed context: {0}")]
    Encode(#[from] serde_json_lenient::Error),
    /// The cipher refused the message.
    #[error("sealing the member: {0}")]
    Cipher(aes_gcm::Error),
}

/// Why a sealed value is refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The value is not a sealed value at all.
    #[error("not a sealed value: {0}")]
    Malformed(&'static str),
    /// The value is bound to a key this host does not hold: a previous key
    /// of this host, or another host's.
    #[error(
        "sealed to key {sealed_to}, not this host's {role} key {current}; \
         a running box holding it is re-created to re-mint"
    )]
    KeyMismatch {
        role: KeyRole,
        sealed_to: String,
        current: Fingerprint,
    },
    /// The context or the ciphertext was altered after sealing.
    #[error("the sealed value fails authentication under this host's key")]
    Unauthenticated,
    /// The key store refused the agreement.
    #[error("the key store refused the sealed value: {0}")]
    Store(#[from] StoreError),
}

/// Seals `member` under `context` to the sealing key and root of `keys`.
///
/// # Errors
///
/// When the context does not encode or the cipher refuses the message.
pub fn seal<S: KeyStore>(
    keys: &Keys<S>,
    context: &SealedContext,
    member: &Member,
) -> Result<SealedValue, SealError> {
    let sealing = keys.fingerprint(KeyRole::Sealing);
    let header = serde_json_lenient::to_vec(&Header {
        sealing_key: sealing.to_string(),
        root_key: keys.fingerprint(KeyRole::Root).to_string(),
        context: context.clone(),
    })?;

    let ephemeral = EphemeralSecret::generate_from_rng(&mut rand::rng());
    let point = ephemeral.public_key().to_sec1_point(false);
    let shared = ephemeral.diffie_hellman(keys.public_key(KeyRole::Sealing));
    let content_key = derive_content_key(&sealing, shared.raw_secret_bytes(), point.as_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = Aes256Gcm::new(&content_key)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: member.expose().as_bytes(),
                aad: &header,
            },
        )
        .map_err(SealError::Cipher)?;

    Ok(SealedValue(encode(
        &header,
        point.as_bytes(),
        &nonce,
        &ciphertext,
    )))
}

/// Unseals `value` under the sealing key of `keys`, returning the
/// authenticated context and the member.
///
/// # Errors
///
/// A [`Refusal`]: the value is malformed, bound to a key this host does not
/// hold, altered after sealing, or the store refuses the agreement.
pub fn unseal<S: KeyStore>(keys: &Keys<S>, value: &str) -> Result<Unsealed, Refusal> {
    let parts = decode(value)?;
    let header: Header = serde_json_lenient::from_slice(&parts.header)
        .map_err(|_| Refusal::Malformed("the header is not a sealed context"))?;

    for (role, sealed_to) in [
        (KeyRole::Sealing, header.sealing_key),
        (KeyRole::Root, header.root_key),
    ] {
        let current = keys.fingerprint(role);
        if sealed_to != current.to_string() {
            tracing::warn!(
                role = %role,
                key = %sealed_to,
                current = %current,
                reason = "sealed_to_previous_key",
                "refusing a member sealed to a key this host does not hold; \
                 a running box holding it is re-created to re-mint"
            );
            return Err(Refusal::KeyMismatch {
                role,
                sealed_to,
                current,
            });
        }
    }

    let peer = PublicKey::from_sec1_bytes(&parts.point)
        .map_err(|_| Refusal::Malformed("the ephemeral point is not on P-256"))?;
    let shared = keys.key(KeyRole::Sealing).agree(&peer)?;
    let content_key =
        derive_content_key(&keys.fingerprint(KeyRole::Sealing), &*shared, &parts.point);

    let plaintext = Aes256Gcm::new(&content_key)
        .decrypt(
            &parts.nonce.into(),
            Payload {
                msg: &parts.ciphertext,
                aad: &parts.header,
            },
        )
        .map_err(|_| Refusal::Unauthenticated)?;
    let credential =
        String::from_utf8(plaintext).map_err(|_| Refusal::Malformed("the member is not text"))?;

    Ok(Unsealed {
        context: header.context,
        member: Member::new(credential),
    })
}

fn derive_content_key(
    sealing: &Fingerprint,
    shared: &[u8],
    point: &[u8],
) -> Zeroizing<Key<Aes256Gcm>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(sealing.as_bytes()), shared)
        .expand_multi_info(&[KDF_INFO, point], &mut okm[..])
        .expect("32 bytes is within HKDF-SHA256's output bound");
    Zeroizing::new(Key::<Aes256Gcm>::from(*okm))
}

struct Parts {
    header: Vec<u8>,
    point: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn encode(header: &[u8], point: &[u8], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> String {
    let len = u16::try_from(header.len()).expect("a sealed context is far shorter than 64 KiB");
    let body: Vec<u8> = len
        .to_be_bytes()
        .iter()
        .chain(header)
        .chain(point)
        .chain(nonce)
        .chain(ciphertext)
        .copied()
        .collect();
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(body))
}

fn decode(value: &str) -> Result<Parts, Refusal> {
    let encoded = value
        .strip_prefix(PREFIX)
        .ok_or(Refusal::Malformed("missing the sealed-value prefix"))?;
    let body = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Refusal::Malformed("the body is not base64url"))?;
    let (len, rest) = body
        .split_first_chunk::<2>()
        .ok_or(Refusal::Malformed("the body is truncated"))?;
    let len = usize::from(u16::from_be_bytes(*len));
    if rest.len() < len + POINT_LEN + NONCE_LEN + TAG_LEN {
        return Err(Refusal::Malformed("the body is truncated"));
    }
    let (header, rest) = rest.split_at(len);
    let (point, rest) = rest.split_at(POINT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    Ok(Parts {
        header: header.to_vec(),
        point: point.to_vec(),
        nonce: nonce.try_into().expect("split at NONCE_LEN"),
        ciphertext: ciphertext.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryStore;

    /// An in-place edit of one context field.
    type Edit = fn(&mut SealedContext);

    fn context() -> SealedContext {
        SealedContext {
            box_id: "box-a1".into(),
            host: "mac-1".into(),
            module: "github".into(),
            host_set_version: 3,
            mode: "sealed".into(),
            breadth: "account".into(),
            expires_at: 4_102_444_800,
        }
    }

    /// Re-encodes `value` with its header swapped for `header`, keeping the
    /// ephemeral point, nonce and ciphertext: what an attacker who edits the
    /// context in place produces.
    fn with_header(value: &SealedValue, header: &Header) -> String {
        let parts = decode(value.as_str()).unwrap();
        let header = serde_json_lenient::to_vec(header).unwrap();
        encode(&header, &parts.point, &parts.nonce, &parts.ciphertext)
    }

    fn header_of(value: &SealedValue) -> Header {
        serde_json_lenient::from_slice(&decode(value.as_str()).unwrap().header).unwrap()
    }

    #[test]
    fn sealed_context_binds_box_host_module_version_expiry() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        let member = Member::new("gho_16C7e42F292c6912E7710c838347Ae178B4a");
        let sealed = seal(&keys, &context(), &member).unwrap();
        assert!(sealed.as_str().starts_with(PREFIX));

        let unsealed = unseal(&keys, sealed.as_str()).unwrap();
        assert_eq!(unsealed.context, context());
        assert_eq!(unsealed.member, member);

        // Every context field is authenticated: editing any one of them in
        // the envelope fails the unseal, even though the ciphertext is intact.
        let edits: [(&str, Edit); 7] = [
            ("box", |c| c.box_id = "box-b2".into()),
            ("host", |c| c.host = "mac-2".into()),
            ("module", |c| c.module = "gitlab".into()),
            ("host_set_version", |c| c.host_set_version += 1),
            ("mode", |c| c.mode = "passthrough".into()),
            ("breadth", |c| c.breadth = "org".into()),
            ("expires_at", |c| c.expires_at += 3600),
        ];
        for (field, edit) in edits {
            let mut header = header_of(&sealed);
            edit(&mut header.context);
            let forged = with_header(&sealed, &header);
            assert!(
                matches!(unseal(&keys, &forged), Err(Refusal::Unauthenticated)),
                "editing {field} must fail authentication"
            );
        }

        // A flipped ciphertext byte fails the same way.
        let mut parts = decode(sealed.as_str()).unwrap();
        parts.ciphertext[0] ^= 0x01;
        let forged = encode(&parts.header, &parts.point, &parts.nonce, &parts.ciphertext);
        assert!(matches!(
            unseal(&keys, &forged),
            Err(Refusal::Unauthenticated)
        ));

        // And the value decrypts under this host's key only: another host's
        // keys refuse it as bound to a key they do not hold.
        let other_host = Keys::open(MemoryStore::new()).unwrap();
        assert!(matches!(
            unseal(&other_host, sealed.as_str()),
            Err(Refusal::KeyMismatch {
                role: KeyRole::Sealing,
                ..
            })
        ));
        // Even one that claims this host's fingerprints in its header.
        let mut header = header_of(&sealed);
        header.sealing_key = other_host.fingerprint(KeyRole::Sealing).to_string();
        header.root_key = other_host.fingerprint(KeyRole::Root).to_string();
        let relabelled = with_header(&sealed, &header);
        assert!(matches!(
            unseal(&other_host, &relabelled),
            Err(Refusal::Unauthenticated)
        ));

        // Each seal is fresh: the same member seals to a different value.
        assert_ne!(seal(&keys, &context(), &member).unwrap(), sealed);
    }

    #[test]
    fn malformed_values_are_refused_as_such() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        for value in [
            "",
            "gho_abc",
            "minsealed1.",
            "minsealed1.!!!",
            "minsealed1.AAAA",
        ] {
            assert!(
                matches!(unseal(&keys, value), Err(Refusal::Malformed(_))),
                "{value:?}"
            );
        }
    }

    /// BEP-027: GitHub rejects the sealed value as a credential when it is
    /// presented directly. Needs the network; `--run-ignored ignored-only`.
    #[tokio::test]
    #[ignore = "reaches api.github.com"]
    async fn sealed_value_rejected_by_github() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        let sealed = seal(
            &keys,
            &context(),
            &Member::new("gho_16C7e42F292c6912E7710c838347Ae178B4a"),
        )
        .unwrap();
        let client = reqwest::Client::builder()
            .user_agent("minimal-bep-test")
            .build()
            .unwrap();
        for scheme in ["Bearer", "token"] {
            let response = client
                .get("https://api.github.com/user")
                .header("Authorization", format!("{scheme} {sealed}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "GitHub must refuse the sealed value under `{scheme}`"
            );
        }
    }
}
