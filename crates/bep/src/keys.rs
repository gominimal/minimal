//! The proxy's keys and the store that holds them (BEP-014, BEP-059,
//! BEP-060).
//!
//! The proxy holds three P-256 keys, one for each [`Role`]: the sealing key,
//! which opens sealed values, the root CA key and the signing CA key. A
//! [`KeyStore`] generates each key non-exportable and holds it. The proxy
//! never sees a private key's bytes, so it can write none of them to a file.
//! It uses a key only through [`HeldKey`]: its public half, a key agreement
//! and a probe.
//!
//! [`load`] runs at each start. It finds each key, and generates a key only
//! for a role that the store does not hold. It never replaces a key that the
//! store holds, also when the store refuses it. A refused key stops the start
//! (see [`StartError`]). [`replace`] is the operator's command, and the only
//! path that replaces a key.
//!
//! On macOS the store is the login keychain ([`Keychain`]). The keychain
//! admits a non-exportable key only to the program that generated it, so a
//! rebuilt proxy is refused its keys and recovers through [`replace`].

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::seal::ProxyPublicKey;

/// What a proxy key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// The key that opens sealed values. Its public half is the one a mint
    /// seals to.
    Sealing,
    /// The root CA key, under which the box trust anchor is issued.
    Root,
    /// The signing CA key, which issues the per-hostname leaves.
    Signing,
}

impl Role {
    /// Every role, in the order the proxy loads them.
    pub const ALL: [Self; 3] = [Self::Sealing, Self::Root, Self::Signing];

    /// The name that `bep --replace-key` takes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sealing => "sealing",
            Self::Root => "root",
            Self::Signing => "signing",
        }
    }

    /// The label of the store item that holds the key.
    #[must_use]
    pub fn label(self) -> String {
        format!("dev.gominimal.bep.{}", self.as_str())
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A role name that is not `sealing`, `root` or `signing`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("`{0}` is not a key role. Use sealing, root or signing.")]
pub struct UnknownRole(pub String);

impl FromStr for Role {
    type Err = UnknownRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == s)
            .ok_or_else(|| UnknownRole(s.to_owned()))
    }
}

/// Why the store did not give a key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The store holds the key and refused this program its use.
    #[error("the key store refused the {role} key: {detail}")]
    Refused {
        /// The role of the refused key.
        role: Role,
        /// What the store said.
        detail: String,
    },
    /// The store did not generate or remove the key.
    #[error("the key store failed for the {role} key: {detail}")]
    Store {
        /// The role of the key.
        role: Role,
        /// What the store said.
        detail: String,
    },
}

/// A key that a [`KeyStore`] holds. No method returns the private half.
pub trait HeldKey {
    /// The role the key is held under.
    fn role(&self) -> Role;

    /// The public half.
    fn public(&self) -> ProxyPublicKey;

    /// Whether the store lets the private half out. A key the proxy holds is
    /// never exportable.
    fn exportable(&self) -> bool;

    /// The raw ECDH shared secret (the x-coordinate) with `peer`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store refuses the key's use.
    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError>;

    /// Uses the key once, so that a store which refuses the key refuses it
    /// at start, and not at the first request.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store refuses the key's use.
    fn probe(&self) -> Result<(), KeyError>;
}

/// A store that generates keys non-exportable and holds them across
/// restarts.
pub trait KeyStore {
    /// The store's key handle.
    type Key: HeldKey;

    /// The key the store holds for `role`, or `None` when it holds none.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store holds a key and refuses it.
    fn find(&self, role: Role) -> Result<Option<Self::Key>, KeyError>;

    /// Generates a new non-exportable key for `role` and holds it.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not generate the key.
    fn generate(&self, role: Role) -> Result<Self::Key, KeyError>;

    /// Removes every key the store holds for `role`. Removing a role with no
    /// key is not an error.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not remove the key.
    fn remove(&self, role: Role) -> Result<(), KeyError>;
}

/// The proxy's three keys.
#[derive(Debug)]
pub struct ProxyKeys<K> {
    /// The key that opens sealed values.
    pub sealing: K,
    /// The root CA key.
    pub root: K,
    /// The signing CA key.
    pub signing: K,
}

impl<K: HeldKey> ProxyKeys<K> {
    /// The key held for `role`.
    pub fn get(&self, role: Role) -> &K {
        match role {
            Role::Sealing => &self.sealing,
            Role::Root => &self.root,
            Role::Signing => &self.signing,
        }
    }
}

/// Why the proxy did not start.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StartError {
    /// The store holds these keys and refused them.
    Refused(Vec<Role>),
    /// The store did not generate a missing key.
    Store(KeyError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // BEP-060: the wording is fixed by the task's diagnostics line.
            Self::Refused(roles) => {
                for (i, role) in roles.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    write!(
                        f,
                        "The keychain refused the proxy its {role} key. Run `bep --replace-key {role}` to make a new one; boxes created before then must be re-created."
                    )?;
                }
                Ok(())
            }
            Self::Store(err) => write!(f, "The proxy did not start: {err}."),
        }
    }
}

/// Loads the proxy's keys at start (BEP-059, BEP-060).
///
/// A key the store holds is used as it is. A key the store does not hold is
/// generated, which happens on the first start. A key the store holds and
/// refuses is never replaced here.
///
/// # Errors
///
/// [`StartError::Refused`] with the role of each refused key, or
/// [`StartError::Store`] when a missing key was not generated.
pub fn load<S: KeyStore>(store: &S) -> Result<ProxyKeys<S::Key>, StartError> {
    let mut refused = Vec::new();
    let mut found = Vec::new();
    for role in Role::ALL {
        match store.find(role) {
            Ok(Some(key)) => match key.probe() {
                Ok(()) => found.push(key),
                Err(err) => {
                    tracing::error!(role = %role, error = %err, "the key store refused a proxy key");
                    refused.push(role);
                }
            },
            Ok(None) => {
                let key = store.generate(role).map_err(StartError::Store)?;
                tracing::info!(role = %role, fingerprint = %key.public().kid(), "generated a proxy key");
                found.push(key);
            }
            Err(err @ KeyError::Refused { .. }) => {
                tracing::error!(role = %role, error = %err, "the key store refused a proxy key");
                refused.push(role);
            }
            Err(err @ KeyError::Store { .. }) => return Err(StartError::Store(err)),
        }
    }
    if !refused.is_empty() {
        return Err(StartError::Refused(refused));
    }
    let mut keys = found.into_iter();
    let (Some(sealing), Some(root), Some(signing), None) =
        (keys.next(), keys.next(), keys.next(), keys.next())
    else {
        unreachable!("one key is found or generated for each of the three roles");
    };
    tracing::info!(
        sealing = %sealing.public().kid(),
        root = %root.public().kid(),
        signing = %signing.public().kid(),
        "proxy keys ready"
    );
    Ok(ProxyKeys {
        sealing,
        root,
        signing,
    })
}

/// Why [`replace`] did not replace a key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplaceError {
    /// The old key was not removed, so the store still holds it.
    #[error("{0}")]
    Remove(KeyError),
    /// The old key was removed, and no new key was generated.
    #[error("{0}")]
    Generate(KeyError),
}

/// Replaces the key held for `role`: the operator's command (BEP-060).
///
/// The old key is removed before the new key is generated, so no value
/// sealed to an old sealing key opens after this returns. The store holds
/// one key under a role's label, so the new key cannot be generated first.
///
/// # Errors
///
/// [`ReplaceError::Remove`] when the store keeps the old key, and
/// [`ReplaceError::Generate`] when the old key is gone and no new key was
/// generated.
pub fn replace<S: KeyStore>(store: &S, role: Role) -> Result<S::Key, ReplaceError> {
    store.remove(role).map_err(ReplaceError::Remove)?;
    let key = match store.generate(role) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(role = %role, error = %err, "removed a proxy key and generated no new key");
            return Err(ReplaceError::Generate(err));
        }
    };
    tracing::warn!(role = %role, fingerprint = %key.public().kid(), "replaced a proxy key");
    Ok(key)
}

/// What `bep --replace-key <role>` prints after a replacement.
#[must_use]
pub fn replacement_report(role: Role) -> &'static str {
    match role {
        Role::Sealing => {
            "Replaced the proxy's sealing key. The proxy now refuses every value sealed to the old key. Re-create each box created before now to give it new values."
        }
        Role::Root => {
            "Replaced the proxy's root key. Boxes created before now do not trust the new root. Re-create each box created before now."
        }
        Role::Signing => "Replaced the proxy's signing key. Running boxes need no change.",
    }
}

#[cfg(target_os = "macos")]
pub use keychain::Keychain;

/// The macOS login keychain as a [`KeyStore`].
#[cfg(target_os = "macos")]
mod keychain {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::error::CFErrorRef;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, SecKey};
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits,
        kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecPrivateKeyAttrs,
        kSecPublicKeyAttrs,
    };
    use zeroize::Zeroizing;

    use super::{HeldKey, KeyError, KeyStore, Role};
    use crate::seal::ProxyPublicKey;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        // `security-framework-sys` does not declare this attribute.
        static kSecAttrIsExtractable: CFStringRef;
    }

    /// The search codes that mean the keychain denies this program the key:
    /// `errSecAuthFailed`, `errSecNoAccessForItem` and `errSecUserCanceled`.
    const DENIED: [i32; 3] = [-25293, -25243, -128];

    /// The login keychain.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Keychain;

    /// A private key the keychain holds.
    pub struct KeychainKey {
        role: Role,
        key: SecKey,
        public: ProxyPublicKey,
    }

    impl std::fmt::Debug for KeychainKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("KeychainKey")
                .field("role", &self.role)
                .field("kid", &self.public.kid())
                .finish_non_exhaustive()
        }
    }

    fn attr(name: CFStringRef) -> CFString {
        // SAFETY: `name` is a constant the Security framework exports, which
        // lives for the life of the process.
        unsafe { CFString::wrap_under_get_rule(name) }
    }

    fn refused(role: Role, detail: impl ToString) -> KeyError {
        KeyError::Refused {
            role,
            detail: detail.to_string(),
        }
    }

    impl KeychainKey {
        fn new(role: Role, key: SecKey) -> Result<Self, KeyError> {
            let public = key
                .public_key()
                .and_then(|public| public.external_representation())
                .and_then(|bytes| ProxyPublicKey::from_sec1_bytes(&bytes.to_vec()))
                .ok_or_else(|| refused(role, "the key has no P-256 public half"))?;
            Ok(Self { role, key, public })
        }
    }

    impl HeldKey for KeychainKey {
        fn role(&self) -> Role {
            self.role
        }

        fn public(&self) -> ProxyPublicKey {
            self.public
        }

        fn exportable(&self) -> bool {
            self.key.external_representation().is_some()
        }

        fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            let peer = public_sec_key(peer).map_err(|detail| refused(self.role, detail))?;
            self.key
                .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
                .map(Zeroizing::new)
                .map_err(|err| refused(self.role, err))
        }

        fn probe(&self) -> Result<(), KeyError> {
            match self.role {
                Role::Sealing => self.agree(&self.public).map(drop),
                Role::Root | Role::Signing => self
                    .key
                    .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, b"bep key probe")
                    .map(drop)
                    .map_err(|err| refused(self.role, err)),
            }
        }
    }

    fn public_sec_key(public: &ProxyPublicKey) -> Result<SecKey, String> {
        let attrs = CFDictionary::from_CFType_pairs(&[
            (
                attr(unsafe { kSecAttrKeyType }),
                attr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
            ),
            (
                attr(unsafe { kSecAttrKeyClass }),
                attr(unsafe { kSecAttrKeyClassPublic }).into_CFType(),
            ),
        ]);
        let data = CFData::from_buffer(&public.to_sec1_bytes());
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: both arguments are live Core Foundation objects, and the
        // result follows the create rule.
        let key = unsafe {
            security_framework_sys::key::SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attrs.as_concrete_TypeRef(),
                &mut error,
            )
        };
        if key.is_null() {
            if !error.is_null() {
                // SAFETY: a non-null error follows the create rule.
                let error =
                    unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
                return Err(error.to_string());
            }
            return Err("the peer key was not accepted".to_owned());
        }
        // SAFETY: a non-null key follows the create rule.
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    }

    impl KeyStore for Keychain {
        type Key = KeychainKey;

        fn find(&self, role: Role) -> Result<Option<KeychainKey>, KeyError> {
            let found = ItemSearchOptions::new()
                .class(ItemClass::key())
                .key_class(KeyClass::private())
                .label(&role.label())
                .load_refs(true)
                .limit(1i64)
                .search();
            match found {
                Err(err) if err.code() == errSecItemNotFound => Ok(None),
                // Only a real access denial is a refused key. A locked
                // keychain or a session with no UI is not, and the
                // replacement advice would delete a healthy key.
                Err(err) if DENIED.contains(&err.code()) => Err(refused(role, err)),
                Err(err) => Err(KeyError::Store {
                    role,
                    detail: err.to_string(),
                }),
                Ok(results) => match results.into_iter().next() {
                    None => Ok(None),
                    Some(SearchResult::Ref(Reference::Key(key))) => {
                        KeychainKey::new(role, key).map(Some)
                    }
                    // An item holds the label, so never generate a second
                    // key beside it.
                    Some(_) => Err(KeyError::Store {
                        role,
                        detail: "the keychain item under the key's label is not a key".to_owned(),
                    }),
                },
            }
        }

        fn generate(&self, role: Role) -> Result<KeychainKey, KeyError> {
            let label = CFString::new(&role.label());
            let private = CFDictionary::from_CFType_pairs(&[
                (
                    attr(unsafe { kSecAttrIsPermanent }),
                    CFBoolean::true_value().into_CFType(),
                ),
                // BEP-014, BEP-059: the private half never leaves the
                // keychain.
                (
                    attr(unsafe { kSecAttrIsExtractable }),
                    CFBoolean::false_value().into_CFType(),
                ),
                (attr(unsafe { kSecAttrLabel }), label.clone().into_CFType()),
            ]);
            let public = CFDictionary::from_CFType_pairs(&[(
                attr(unsafe { kSecAttrIsPermanent }),
                CFBoolean::false_value().into_CFType(),
            )]);
            let attrs = CFDictionary::from_CFType_pairs(&[
                (
                    attr(unsafe { kSecAttrKeyType }),
                    attr(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
                ),
                (
                    attr(unsafe { kSecAttrKeySizeInBits }),
                    CFNumber::from(256i32).into_CFType(),
                ),
                (attr(unsafe { kSecAttrLabel }), label.into_CFType()),
                (attr(unsafe { kSecPrivateKeyAttrs }), private.into_CFType()),
                (attr(unsafe { kSecPublicKeyAttrs }), public.into_CFType()),
            ]);
            #[allow(deprecated)]
            let key = SecKey::generate(attrs.to_untyped()).map_err(|err| KeyError::Store {
                role,
                detail: err.to_string(),
            })?;
            let key = KeychainKey::new(role, key)?;
            if key.exportable() {
                // Never keep a key the keychain lets out.
                drop(self.remove(role));
                return Err(KeyError::Store {
                    role,
                    detail: "the keychain made the key exportable".to_owned(),
                });
            }
            Ok(key)
        }

        fn remove(&self, role: Role) -> Result<(), KeyError> {
            match ItemSearchOptions::new()
                .class(ItemClass::key())
                .label(&role.label())
                .delete()
            {
                Err(err) if err.code() != errSecItemNotFound => Err(KeyError::Store {
                    role,
                    detail: err.to_string(),
                }),
                _ => Ok(()),
            }
        }
    }
}

/// A store in process memory, for tests. It models the keychain: it
/// outlives a proxy that loads from it, and it can refuse a key it holds.
#[cfg(test)]
pub(crate) mod memory {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use p256::{PublicKey, SecretKey};
    use zeroize::Zeroizing;

    use super::{HeldKey, KeyError, KeyStore, Role};
    use crate::seal::{self, Binding, OpenError, Opened, ProxyKey, ProxyPublicKey};

    #[derive(Default)]
    struct Inner {
        keys: HashMap<Role, SecretKey>,
        refused: HashSet<Role>,
        generated: usize,
        broken: bool,
    }

    #[derive(Default)]
    pub(crate) struct MemoryStore(Mutex<Inner>);

    pub(crate) struct MemoryKey {
        role: Role,
        secret: SecretKey,
        refused: bool,
    }

    impl MemoryStore {
        pub(crate) fn refuse(&self, role: Role) {
            self.0.lock().unwrap().refused.insert(role);
        }

        /// Makes the store fail every search and generation, as a locked
        /// keychain does.
        pub(crate) fn break_store(&self) {
            self.0.lock().unwrap().broken = true;
        }

        pub(crate) fn generated(&self) -> usize {
            self.0.lock().unwrap().generated
        }

        /// The secret bytes, so a test can look for them in files.
        pub(crate) fn secret_bytes(&self, role: Role) -> Vec<u8> {
            self.0.lock().unwrap().keys[&role].to_bytes().to_vec()
        }
    }

    impl std::fmt::Debug for MemoryKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemoryKey")
                .field("role", &self.role)
                .finish_non_exhaustive()
        }
    }

    impl MemoryKey {
        /// Opens a sealed value under this key.
        pub(crate) fn open(&self, sealed: &str, expected: &Binding) -> Result<Opened, OpenError> {
            let bytes: [u8; 32] = self.secret.to_bytes().into();
            let key = ProxyKey::from_bytes(&bytes).ok_or(OpenError::NotOpenable)?;
            seal::open(&key, sealed, expected)
        }
    }

    impl HeldKey for MemoryKey {
        fn role(&self) -> Role {
            self.role
        }

        fn public(&self) -> ProxyPublicKey {
            ProxyPublicKey::from_sec1_bytes(&self.secret.public_key().to_sec1_bytes())
                .expect("a P-256 public key")
        }

        fn exportable(&self) -> bool {
            false
        }

        fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            if self.refused {
                return Err(KeyError::Refused {
                    role: self.role,
                    detail: "refused".into(),
                });
            }
            let peer = PublicKey::from_sec1_bytes(&peer.to_sec1_bytes()).expect("a P-256 point");
            let shared =
                p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }

        fn probe(&self) -> Result<(), KeyError> {
            self.agree(&self.public()).map(drop)
        }
    }

    fn broken(role: Role) -> KeyError {
        KeyError::Store {
            role,
            detail: "the keychain is locked".into(),
        }
    }

    impl KeyStore for MemoryStore {
        type Key = MemoryKey;

        fn find(&self, role: Role) -> Result<Option<MemoryKey>, KeyError> {
            let inner = self.0.lock().unwrap();
            if inner.broken {
                return Err(broken(role));
            }
            Ok(inner.keys.get(&role).map(|secret| MemoryKey {
                role,
                secret: secret.clone(),
                refused: inner.refused.contains(&role),
            }))
        }

        fn generate(&self, role: Role) -> Result<MemoryKey, KeyError> {
            if self.0.lock().unwrap().broken {
                return Err(broken(role));
            }
            let secret = loop {
                let mut bytes = Zeroizing::new([0u8; 32]);
                getrandom::fill(bytes.as_mut()).expect("random source");
                if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
                    break secret;
                }
            };
            let mut inner = self.0.lock().unwrap();
            inner.generated += 1;
            inner.refused.remove(&role);
            inner.keys.insert(role, secret.clone());
            Ok(MemoryKey {
                role,
                secret,
                refused: false,
            })
        }

        fn remove(&self, role: Role) -> Result<(), KeyError> {
            self.0.lock().unwrap().keys.remove(&role);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryStore;
    use super::*;

    // BEP-059, BEP-060
    #[test]
    fn keys_never_regenerated_on_restart() {
        let store = MemoryStore::default();
        let first = load(&store).unwrap();
        assert_eq!(store.generated(), 3);
        let kids: Vec<String> = Role::ALL
            .iter()
            .map(|role| first.get(*role).public().kid())
            .collect();
        drop(first);

        for _ in 0..3 {
            let again = load(&store).unwrap();
            let again_kids: Vec<String> = Role::ALL
                .iter()
                .map(|role| again.get(*role).public().kid())
                .collect();
            assert_eq!(again_kids, kids);
        }
        assert_eq!(store.generated(), 3, "a restart generated a key");

        // A refused key is not replaced on restart either.
        store.refuse(Role::Sealing);
        assert!(load(&store).is_err());
        assert_eq!(store.generated(), 3, "a refused key was regenerated");
    }

    // BEP-060
    #[test]
    fn refused_key_names_the_replacement_command() {
        let store = MemoryStore::default();
        drop(load(&store).unwrap());
        store.refuse(Role::Sealing);
        store.refuse(Role::Signing);

        let err = load(&store).unwrap_err();
        assert_eq!(err, StartError::Refused(vec![Role::Sealing, Role::Signing]));
        assert_eq!(
            err.to_string(),
            "The keychain refused the proxy its sealing key. Run `bep --replace-key sealing` to make a new one; boxes created before then must be re-created.\n\
             The keychain refused the proxy its signing key. Run `bep --replace-key signing` to make a new one; boxes created before then must be re-created."
        );

        // The named command is the way out.
        replace(&store, "sealing".parse().unwrap()).unwrap();
        replace(&store, "signing".parse().unwrap()).unwrap();
        assert!(load(&store).is_ok());
    }

    #[test]
    fn a_store_failure_is_not_a_refused_key() {
        let store = MemoryStore::default();
        drop(load(&store).unwrap());
        store.break_store();

        let err = load(&store).unwrap_err();
        assert!(matches!(err, StartError::Store(_)), "{err}");
        assert!(!err.to_string().contains("--replace-key"), "{err}");
        assert_eq!(store.generated(), 3);
    }

    #[test]
    fn a_failed_generation_reports_the_old_key_removed() {
        let store = MemoryStore::default();
        drop(load(&store).unwrap());
        store.break_store();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Generate(_)), "{err}");
    }

    #[test]
    fn role_names_round_trip() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
        }
        assert_eq!("ca".parse::<Role>(), Err(UnknownRole("ca".to_owned())));
    }
}
