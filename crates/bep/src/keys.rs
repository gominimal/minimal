//! The proxy's key set: the sealing key, the root CA key and the signing CA
//! key.
//!
//! Each is generated once, non-exportable, in the host key store (BEP-014,
//! BEP-059), found again on every open, and replaced only by an explicit
//! operator command, never on restart (BEP-060). A key is identified by its
//! fingerprint, the SHA-256 of its SEC1 public point, which is all this
//! crate ever reports about a key.

use std::fmt;
use std::time::SystemTime;

use p256::PublicKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha256};

use crate::keychain::{KeyStore, PrivateKey, StoreError};

/// Which of the proxy's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRole {
    /// The key members are sealed to.
    Sealing,
    /// The root CA key: the trust anchor injected into boxes.
    Root,
    /// The signing CA key: issues per-hostname leaves under the root.
    Signing,
}

impl KeyRole {
    /// Every role, in the order diagnostics list them.
    pub const ALL: [Self; 3] = [Self::Sealing, Self::Root, Self::Signing];

    /// The name the key lives under in the store (a keychain item's label).
    #[must_use]
    pub fn store_name(self) -> &'static str {
        match self {
            Self::Sealing => "dev.minimal.bep.sealing",
            Self::Root => "dev.minimal.bep.root",
            Self::Signing => "dev.minimal.bep.signing",
        }
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sealing => "sealing",
            Self::Root => "root",
            Self::Signing => "signing",
        })
    }
}

/// A key's identity: the SHA-256 of its uncompressed SEC1 public point.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of `public`.
    #[must_use]
    pub fn of(public: &PublicKey) -> Self {
        Self(Sha256::digest(public.to_sec1_point(false).as_bytes()).into())
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Why the key set could not be opened or changed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeysError {
    /// The store failed on the named key.
    #[error("the {role} key: {source}")]
    Store {
        role: KeyRole,
        #[source]
        source: StoreError,
    },
}

/// What diagnostics report about one of the proxy's keys: its identity and
/// age, never the key.
#[derive(Debug, Clone)]
pub struct KeyStatus {
    pub role: KeyRole,
    /// The store the key is looked for in.
    pub store: &'static str,
    /// The key's fingerprint, or `None` when the store holds no such key.
    pub fingerprint: Option<Fingerprint>,
    /// When the key was generated, when the store records it.
    pub generated_at: Option<SystemTime>,
}

impl KeyStatus {
    /// Whether the store holds the key.
    #[must_use]
    pub fn present(&self) -> bool {
        self.fingerprint.is_some()
    }
}

/// A key as held open: the store handle with its public half derived once.
struct Held<K> {
    key: K,
    public: PublicKey,
    fingerprint: Fingerprint,
}

impl<K: PrivateKey> Held<K> {
    fn new(role: KeyRole, key: K) -> Result<Self, KeysError> {
        let public = key.public_key().map_err(store_error(role))?;
        let fingerprint = Fingerprint::of(&public);
        Ok(Self {
            key,
            public,
            fingerprint,
        })
    }
}

fn store_error(role: KeyRole) -> impl FnOnce(StoreError) -> KeysError {
    move |source| KeysError::Store { role, source }
}

fn generate<S: KeyStore>(store: &S, role: KeyRole) -> Result<Held<S::Key>, KeysError> {
    let key = store
        .generate(role.store_name())
        .map_err(store_error(role))?;
    let held = Held::new(role, key)?;
    tracing::info!(role = %role, key = %held.fingerprint, store = S::NAME, "generated key");
    Ok(held)
}

fn find_or_generate<S: KeyStore>(store: &S, role: KeyRole) -> Result<Held<S::Key>, KeysError> {
    match store.find(role.store_name()).map_err(store_error(role))? {
        Some(key) => Held::new(role, key),
        None => generate(store, role),
    }
}

/// The proxy's keys, open in their store.
pub struct Keys<S: KeyStore> {
    store: S,
    sealing: Held<S::Key>,
    root: Held<S::Key>,
    signing: Held<S::Key>,
}

impl<S: KeyStore> Keys<S> {
    /// Opens the proxy's keys in `store`, generating any it does not hold. A
    /// key the store holds is used as it is: opening never regenerates.
    ///
    /// # Errors
    ///
    /// When the store cannot find, generate or describe a key.
    pub fn open(store: S) -> Result<Self, KeysError> {
        let sealing = find_or_generate(&store, KeyRole::Sealing)?;
        let root = find_or_generate(&store, KeyRole::Root)?;
        let signing = find_or_generate(&store, KeyRole::Signing)?;
        Ok(Self {
            store,
            sealing,
            root,
            signing,
        })
    }

    fn held(&self, role: KeyRole) -> &Held<S::Key> {
        match role {
            KeyRole::Sealing => &self.sealing,
            KeyRole::Root => &self.root,
            KeyRole::Signing => &self.signing,
        }
    }

    /// The store handle for `role`'s key.
    #[must_use]
    pub fn key(&self, role: KeyRole) -> &S::Key {
        &self.held(role).key
    }

    /// The public half of `role`'s key.
    #[must_use]
    pub fn public_key(&self, role: KeyRole) -> &PublicKey {
        &self.held(role).public
    }

    /// The fingerprint of `role`'s key.
    #[must_use]
    pub fn fingerprint(&self, role: KeyRole) -> Fingerprint {
        self.held(role).fingerprint
    }

    /// Replaces `role`'s key with a newly generated one, on an explicit
    /// operator command. Every member sealed to the previous sealing key or
    /// under the previous root is refused from now on; a running box holding
    /// one is re-created to re-mint. Returns the new key's fingerprint.
    ///
    /// # Errors
    ///
    /// When the store cannot delete the old key or generate the new one.
    pub fn replace(&mut self, role: KeyRole) -> Result<Fingerprint, KeysError> {
        let previous = self.fingerprint(role);
        self.store
            .delete(role.store_name())
            .map_err(store_error(role))?;
        let held = generate(&self.store, role)?;
        let fingerprint = held.fingerprint;
        match role {
            KeyRole::Sealing => self.sealing = held,
            KeyRole::Root => self.root = held,
            KeyRole::Signing => self.signing = held,
        }
        tracing::info!(
            role = %role,
            previous = %previous,
            key = %fingerprint,
            "replaced key on operator command; members sealed to the previous key are refused \
             and a running box holding one is re-created to re-mint"
        );
        Ok(fingerprint)
    }
}

/// Describes each of the proxy's keys as `store` holds them, without
/// generating any. What the support bundle lists.
///
/// # Errors
///
/// When the store cannot be searched or a held key cannot be described.
pub fn inspect<S: KeyStore>(store: &S) -> Result<Vec<KeyStatus>, KeysError> {
    KeyRole::ALL
        .into_iter()
        .map(|role| {
            let key = store.find(role.store_name()).map_err(store_error(role))?;
            let (fingerprint, generated_at) = match key {
                Some(key) => (
                    Some(Fingerprint::of(
                        &key.public_key().map_err(store_error(role))?,
                    )),
                    key.created_at(),
                ),
                None => (None, None),
            };
            Ok(KeyStatus {
                role,
                store: S::NAME,
                fingerprint,
                generated_at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;

    use super::*;
    use crate::keychain::MemoryStore;
    use crate::seal::{Member, Refusal, SealedContext, seal, unseal};

    fn context() -> SealedContext {
        SealedContext {
            box_id: "box-1".into(),
            host: "host-1".into(),
            module: "github".into(),
            host_set_version: 1,
            mode: "sealed".into(),
            breadth: "account".into(),
            expires_at: 4_102_444_800,
        }
    }

    fn fingerprints<S: KeyStore>(keys: &Keys<S>) -> [Fingerprint; 3] {
        KeyRole::ALL.map(|role| keys.fingerprint(role))
    }

    /// Generating the key set touches no file: the store takes no path, and
    /// a directory the process works in stays empty across generation.
    fn assert_no_file_written(before: impl FnOnce() -> Keys<MemoryStore>) -> Keys<MemoryStore> {
        let dir = tempfile::tempdir().unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let keys = before();
        let written: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        std::env::set_current_dir(cwd).unwrap();
        assert!(written.is_empty(), "key generation wrote {written:?}");
        keys
    }

    #[test]
    fn signing_key_is_non_exportable_and_has_no_file() {
        let store = MemoryStore::new();
        let keys = assert_no_file_written(|| Keys::open(store.clone()).unwrap());

        // The signing key is usable without ever leaving the store: the seam
        // offers `sign`, `agree` and `public_key`, and nothing returning
        // private bytes.
        let message = b"leaf certificate to be";
        let der = keys.key(KeyRole::Signing).sign(message).unwrap();
        let verifier = p256::ecdsa::VerifyingKey::from(keys.public_key(KeyRole::Signing));
        let signature = p256::ecdsa::Signature::from_der(&der).unwrap();
        verifier.verify(message, &signature).unwrap();

        let status = inspect(&store).unwrap();
        let signing = status.iter().find(|s| s.role == KeyRole::Signing).unwrap();
        assert!(signing.present());
        assert_eq!(
            signing.fingerprint,
            Some(keys.fingerprint(KeyRole::Signing))
        );
        assert!(signing.generated_at.is_some());
        assert_eq!(signing.store, "memory");
    }

    #[test]
    fn sealing_and_root_keys_persist_non_exportable() {
        let store = MemoryStore::new();
        let empty = inspect(&store).unwrap();
        assert!(empty.iter().all(|s| !s.present()));

        let first = assert_no_file_written(|| Keys::open(store.clone()).unwrap());
        let sealed = seal(&first, &context(), &Member::new("ghp_before_restart")).unwrap();
        let before = fingerprints(&first);
        let generated_at: Vec<_> = inspect(&store)
            .unwrap()
            .into_iter()
            .map(|s| s.generated_at)
            .collect();
        drop(first);

        // A proxy restart: a fresh open against the same store.
        let second = Keys::open(store.clone()).unwrap();
        assert_eq!(fingerprints(&second), before);
        assert_eq!(second.fingerprint(KeyRole::Sealing), before[0]);
        assert_eq!(second.fingerprint(KeyRole::Root), before[1]);
        let after: Vec<_> = inspect(&store)
            .unwrap()
            .into_iter()
            .map(|s| s.generated_at)
            .collect();
        assert_eq!(after, generated_at);

        // The keys still work, and are still only reachable through the seam.
        let unsealed = unseal(&second, sealed.as_str()).unwrap();
        assert_eq!(unsealed.member.expose(), "ghp_before_restart");
        let der = second.key(KeyRole::Root).sign(b"signing ca to be").unwrap();
        let verifier = p256::ecdsa::VerifyingKey::from(second.public_key(KeyRole::Root));
        verifier
            .verify(
                b"signing ca to be",
                &p256::ecdsa::Signature::from_der(&der).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn keys_never_regenerated_on_restart() {
        let store = MemoryStore::new();
        let original = fingerprints(&Keys::open(store.clone()).unwrap());

        for _ in 0..5 {
            assert_eq!(fingerprints(&Keys::open(store.clone()).unwrap()), original);
        }

        // Only the operator command changes a key, and only that key.
        let mut keys = Keys::open(store.clone()).unwrap();
        let replaced = keys.replace(KeyRole::Signing).unwrap();
        assert_ne!(replaced, original[2]);
        assert_eq!(keys.fingerprint(KeyRole::Signing), replaced);
        assert_eq!(keys.fingerprint(KeyRole::Sealing), original[0]);
        assert_eq!(keys.fingerprint(KeyRole::Root), original[1]);

        // And the replacement itself persists across the next restart.
        let reopened = fingerprints(&Keys::open(store).unwrap());
        assert_eq!(reopened, [original[0], original[1], replaced]);
    }

    #[test]
    fn key_replacement_kills_outstanding_members() {
        let store = MemoryStore::new();
        let mut keys = Keys::open(store.clone()).unwrap();
        let ctx = context();
        let under_first_sealing = seal(&keys, &ctx, &Member::new("ghp_one")).unwrap();
        assert!(unseal(&keys, under_first_sealing.as_str()).is_ok());

        let previous_sealing = keys.fingerprint(KeyRole::Sealing);
        let new_sealing = keys.replace(KeyRole::Sealing).unwrap();
        let refusal = unseal(&keys, under_first_sealing.as_str()).unwrap_err();
        match &refusal {
            Refusal::KeyMismatch {
                role,
                sealed_to,
                current,
            } => {
                assert_eq!(*role, KeyRole::Sealing);
                assert_eq!(sealed_to, &previous_sealing.to_string());
                assert_eq!(*current, new_sealing);
            }
            other => panic!("expected a key mismatch, got {other:?}"),
        }
        assert!(
            refusal.to_string().contains("re-created to re-mint"),
            "the refusal reports the recreate-to-re-mint rule: {refusal}"
        );

        // Members minted after the replacement are fine; replacing the root
        // then kills those too, since the envelope binds the root as well.
        let under_second_sealing = seal(&keys, &ctx, &Member::new("ghp_two")).unwrap();
        assert!(unseal(&keys, under_second_sealing.as_str()).is_ok());
        keys.replace(KeyRole::Root).unwrap();
        assert!(matches!(
            unseal(&keys, under_second_sealing.as_str()),
            Err(Refusal::KeyMismatch {
                role: KeyRole::Root,
                ..
            })
        ));
        // Still refused after a restart: the old keys are gone from the store.
        let reopened = Keys::open(store).unwrap();
        assert!(matches!(
            unseal(&reopened, under_first_sealing.as_str()),
            Err(Refusal::KeyMismatch { .. })
        ));
    }
}
