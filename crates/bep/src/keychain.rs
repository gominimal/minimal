//! The host key store seam: where the proxy's private keys live.
//!
//! The proxy's keys are generated non-exportable on the host and written to
//! no file (BEP-014, BEP-059). The seam exposes what a key can do — derive
//! its public half, agree a shared secret, sign — and nothing that returns
//! private material, so no backend can hand a key out through this API.
//!
//! v1 binds the macOS Keychain (`MacosKeychain`). A Linux host waits on a
//! store that holds keys non-exportable (a TPM or Secret Service backend fills
//! this seam later) and is unverified for the keychain rule meanwhile.
//! [`MemoryStore`] is the seam's in-process reference backend: keys live in
//! process memory, never reach a file, and persist for as long as the store
//! value does, which is how tests on any host model a proxy restart.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use p256::PublicKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::Generate;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
pub use macos::{KeychainKey, MacosKeychain};

/// A raw ECDH shared secret: the x-coordinate of the agreed P-256 point,
/// zeroed on drop.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// Why the key store could not do what was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The platform store failed the operation; the message is the
    /// platform's own.
    #[error("the key store could not {op}: {message}")]
    Backend { op: &'static str, message: String },
    /// Generation asked for a name the store already holds.
    #[error("the key store already holds a key named {name}")]
    Exists { name: String },
    /// Deletion or use named a key the store does not hold.
    #[error("the key store holds no key named {name}")]
    Missing { name: String },
    /// The key's public half did not decode as a P-256 point.
    #[error("the key's public half is not a valid P-256 point")]
    InvalidPublicKey,
}

/// A private key held by a store. Every operation runs inside the store; the
/// private bytes never cross this trait.
pub trait PrivateKey {
    /// The key's public half.
    ///
    /// # Errors
    ///
    /// When the store cannot produce the public half.
    fn public_key(&self) -> Result<PublicKey, StoreError>;

    /// Agrees a shared secret with `peer` (P-256 ECDH, raw x-coordinate).
    ///
    /// # Errors
    ///
    /// When the store refuses the agreement.
    fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, StoreError>;

    /// Signs `message` (ECDSA P-256 over SHA-256), returning the DER
    /// signature.
    ///
    /// # Errors
    ///
    /// When the store refuses to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StoreError>;

    /// When the key was generated, if the store records it.
    fn created_at(&self) -> Option<SystemTime>;
}

/// A store that holds private keys by name.
pub trait KeyStore {
    /// The store's key handle.
    type Key: PrivateKey;

    /// The store's name, as diagnostics report it.
    const NAME: &'static str;

    /// Finds the key named `name`, if the store holds one.
    ///
    /// # Errors
    ///
    /// When the store cannot be searched.
    fn find(&self, name: &str) -> Result<Option<Self::Key>, StoreError>;

    /// Generates a new non-exportable P-256 key under `name`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Exists`] when the name is taken, or when the store
    /// refuses to generate.
    fn generate(&self, name: &str) -> Result<Self::Key, StoreError>;

    /// Deletes the key named `name`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Missing`] when there is none, or when the store refuses
    /// to delete.
    fn delete(&self, name: &str) -> Result<(), StoreError>;
}

/// An in-process key store: keys live in memory for the life of the store
/// value and every clone shares them. Nothing is written anywhere.
#[derive(Clone, Default)]
pub struct MemoryStore {
    keys: Arc<Mutex<BTreeMap<String, MemoryKey>>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, MemoryKey>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A key held by a [`MemoryStore`].
#[derive(Clone)]
pub struct MemoryKey {
    inner: Arc<MemoryKeyInner>,
}

struct MemoryKeyInner {
    secret: p256::SecretKey,
    created_at: SystemTime,
}

impl KeyStore for MemoryStore {
    type Key = MemoryKey;

    const NAME: &'static str = "memory";

    fn find(&self, name: &str) -> Result<Option<Self::Key>, StoreError> {
        Ok(self.keys().get(name).cloned())
    }

    fn generate(&self, name: &str) -> Result<Self::Key, StoreError> {
        let mut keys = self.keys();
        if keys.contains_key(name) {
            return Err(StoreError::Exists {
                name: name.to_owned(),
            });
        }
        let key = MemoryKey {
            inner: Arc::new(MemoryKeyInner {
                secret: p256::SecretKey::generate_from_rng(&mut rand::rng()),
                created_at: SystemTime::now(),
            }),
        };
        keys.insert(name.to_owned(), key.clone());
        Ok(key)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.keys()
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| StoreError::Missing {
                name: name.to_owned(),
            })
    }
}

impl PrivateKey for MemoryKey {
    fn public_key(&self) -> Result<PublicKey, StoreError> {
        Ok(self.inner.secret.public_key())
    }

    fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, StoreError> {
        let shared =
            p256::ecdh::diffie_hellman(self.inner.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StoreError> {
        let signer = p256::ecdsa::SigningKey::from(&self.inner.secret);
        let signature: p256::ecdsa::Signature = signer.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn created_at(&self) -> Option<SystemTime> {
        Some(self.inner.created_at)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! The macOS Keychain backend. Keys are P-256 pairs generated by
    //! `SecKeyCreateRandomKey` into the login keychain as permanent,
    //! sensitive and non-extractable items, so the keychain refuses to
    //! export the private half (`SecKeyCopyExternalRepresentation` and
    //! `security export` both fail on it); every private-key operation is a
    //! `SecKey` call and the bytes stay in the keychain. A key is identified
    //! by its item label.

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use core_foundation::base::{CFGetTypeID, TCFType, ToVoid};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::date::CFDate;
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use core_foundation::error::{CFError, CFErrorRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToSec1Point;
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
    use security_framework_sys::key::SecKeyCreateWithData;
    use zeroize::Zeroizing;

    use super::{KeyStore, PrivateKey, SharedSecret, StoreError};

    // SAFETY: these are the Security.framework attribute-key constants
    // `kSecAttrIsExtractable` and `kSecAttrIsSensitive` (SecItem.h, macOS
    // 10.6+), immutable `CFStringRef` statics that `security-framework-sys`
    // does not declare. They are read-only and valid for the process lifetime.
    // The names are Apple's; `security-framework-sys` allows the same lint.
    #[allow(non_upper_case_globals)]
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrIsExtractable: CFStringRef;
        static kSecAttrIsSensitive: CFStringRef;
    }

    /// The item attribute holding a keychain item's creation date
    /// (`kSecAttrCreationDate`).
    const CREATION_DATE_ATTR: &str = "cdat";

    /// Seconds from the Unix epoch to CoreFoundation's reference date
    /// (2001-01-01T00:00:00Z).
    const CF_EPOCH_UNIX_SECS: f64 = 978_307_200.0;

    /// The P-256 key size the backend generates.
    const KEY_BITS: i32 = 256;

    /// The macOS Keychain, as the operator's login keychain.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct MacosKeychain;

    /// A key held by the macOS Keychain.
    pub struct KeychainKey {
        key: SecKey,
        created_at: Option<SystemTime>,
    }

    fn backend(op: &'static str, error: &impl std::fmt::Display) -> StoreError {
        StoreError::Backend {
            op,
            message: error.to_string(),
        }
    }

    fn cf_error(op: &'static str) -> impl FnOnce(CFError) -> StoreError {
        move |error| backend(op, &error)
    }

    /// The attribute dictionary for a permanent, non-extractable P-256 pair
    /// labelled `name`.
    fn generation_attributes(name: &str) -> CFDictionary {
        let label = CFString::new(name);
        let size = CFNumber::from(KEY_BITS);
        // SAFETY: the `kSec*` statics are immutable framework constants.
        let private = unsafe {
            CFMutableDictionary::from_CFType_pairs(&[
                (
                    kSecAttrIsPermanent.to_void(),
                    CFBoolean::true_value().to_void(),
                ),
                (
                    kSecAttrIsExtractable.to_void(),
                    CFBoolean::false_value().to_void(),
                ),
                (
                    kSecAttrIsSensitive.to_void(),
                    CFBoolean::true_value().to_void(),
                ),
            ])
        };
        // SAFETY: as above.
        let public = unsafe {
            CFMutableDictionary::from_CFType_pairs(&[(
                kSecAttrIsPermanent.to_void(),
                CFBoolean::true_value().to_void(),
            )])
        };
        // SAFETY: as above.
        unsafe {
            CFMutableDictionary::from_CFType_pairs(&[
                (
                    kSecAttrKeyType.to_void(),
                    kSecAttrKeyTypeECSECPrimeRandom.to_void(),
                ),
                (kSecAttrKeySizeInBits.to_void(), size.to_void()),
                (kSecAttrLabel.to_void(), label.to_void()),
                (kSecPrivateKeyAttrs.to_void(), private.to_void()),
                (kSecPublicKeyAttrs.to_void(), public.to_void()),
            ])
        }
        .to_immutable()
    }

    fn private_key_query(name: &str) -> ItemSearchOptions {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(name)
            .limit(1);
        options
    }

    /// Runs a keychain search, reading "nothing matched" as `None`.
    fn search(
        op: &'static str,
        options: &ItemSearchOptions,
    ) -> Result<Option<SearchResult>, StoreError> {
        match options.search() {
            Ok(items) => Ok(items.into_iter().next()),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(error) => Err(backend(op, &error)),
        }
    }

    fn find_key(name: &str) -> Result<Option<SecKey>, StoreError> {
        let mut options = private_key_query(name);
        options.load_refs(true);
        Ok(
            search("find the key", &options)?.and_then(|item| match item {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            }),
        )
    }

    fn creation_date(name: &str) -> Result<Option<SystemTime>, StoreError> {
        let mut options = private_key_query(name);
        options.load_attributes(true);
        let Some(SearchResult::Dict(attributes)) = search("read the key's attributes", &options)?
        else {
            return Ok(None);
        };
        let attr = CFString::from_static_string(CREATION_DATE_ATTR);
        let Some(value) = attributes.find(attr.to_void()) else {
            return Ok(None);
        };
        // SAFETY: `value` is a live entry of `attributes`, which outlives this
        // scope; the type id is checked before it is read as a `CFDate`.
        let date = unsafe {
            if CFGetTypeID(*value) != CFDate::type_id() {
                return Ok(None);
            }
            CFDate::wrap_under_get_rule((*value).cast())
        };
        let unix_secs = date.abs_time() + CF_EPOCH_UNIX_SECS;
        Ok((unix_secs >= 0.0).then(|| UNIX_EPOCH + Duration::from_secs_f64(unix_secs)))
    }

    /// Builds a transient public `SecKey` from a P-256 point for a key
    /// agreement.
    fn peer_key(peer: &PublicKey) -> Result<SecKey, StoreError> {
        let point = peer.to_sec1_point(false);
        let data = CFData::from_buffer(point.as_bytes());
        let size = CFNumber::from(KEY_BITS);
        // SAFETY: the `kSec*` statics are immutable framework constants.
        let attributes = unsafe {
            CFMutableDictionary::from_CFType_pairs(&[
                (
                    kSecAttrKeyType.to_void(),
                    kSecAttrKeyTypeECSECPrimeRandom.to_void(),
                ),
                (kSecAttrKeyClass.to_void(), kSecAttrKeyClassPublic.to_void()),
                (kSecAttrKeySizeInBits.to_void(), size.to_void()),
            ])
        }
        .to_immutable();
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: `data` and `attributes` are live CF objects for the call;
        // the returned reference follows the create rule and `error` is set
        // only when the result is null.
        unsafe {
            let key = SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &raw mut error,
            );
            if key.is_null() {
                let error = CFError::wrap_under_create_rule(error);
                return Err(backend("import the peer key", &error));
            }
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }

    impl KeyStore for MacosKeychain {
        type Key = KeychainKey;

        const NAME: &'static str = "macos-keychain";

        fn find(&self, name: &str) -> Result<Option<Self::Key>, StoreError> {
            let Some(key) = find_key(name)? else {
                return Ok(None);
            };
            Ok(Some(KeychainKey {
                key,
                created_at: creation_date(name)?,
            }))
        }

        fn generate(&self, name: &str) -> Result<Self::Key, StoreError> {
            if find_key(name)?.is_some() {
                return Err(StoreError::Exists {
                    name: name.to_owned(),
                });
            }
            // `SecKey::new` takes `GenerateKeyOptions`, which cannot express
            // the non-extractable attribute; the deprecated entry point takes
            // the attribute dictionary directly.
            #[allow(deprecated)]
            let key = SecKey::generate(generation_attributes(name))
                .map_err(cf_error("generate the key"))?;
            Ok(KeychainKey {
                key,
                created_at: creation_date(name)?,
            })
        }

        fn delete(&self, name: &str) -> Result<(), StoreError> {
            let key = find_key(name)?.ok_or_else(|| StoreError::Missing {
                name: name.to_owned(),
            })?;
            key.delete()
                .map_err(|error| backend("delete the key", &error))
        }
    }

    impl PrivateKey for KeychainKey {
        fn public_key(&self) -> Result<PublicKey, StoreError> {
            let public = self.key.public_key().ok_or(StoreError::InvalidPublicKey)?;
            let point = public
                .external_representation()
                .ok_or(StoreError::InvalidPublicKey)?;
            PublicKey::from_sec1_bytes(point.bytes()).map_err(|_| StoreError::InvalidPublicKey)
        }

        fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, StoreError> {
            let peer = peer_key(peer)?;
            let shared = Zeroizing::new(
                self.key
                    .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
                    .map_err(cf_error("agree the shared secret"))?,
            );
            let mut out = Zeroizing::new([0u8; 32]);
            let bytes: &[u8] = &shared;
            if bytes.len() != out.len() {
                return Err(backend(
                    "agree the shared secret",
                    &format!("expected 32 bytes, got {}", bytes.len()),
                ));
            }
            out.copy_from_slice(bytes);
            Ok(out)
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, StoreError> {
            self.key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
                .map_err(cf_error("sign"))
        }

        fn created_at(&self) -> Option<SystemTime> {
            self.created_at
        }
    }
}
