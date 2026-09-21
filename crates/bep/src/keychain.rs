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
//!
//! The same store holds the values `min secret` puts there by identifier
//! ([`SecretItems`], [`MemorySecrets`], `KeychainSecrets`). Each item carries
//! an access control ([`ItemAcl`]) with one entry created for the proxy's
//! process identity, so the proxy reads the value without a prompt and every
//! other application prompts (BEP-051). The proxy reads a referenced value
//! through [`value_for_request`] — once per request that injects it, nothing
//! held between two — so a replacement is injected from the next request on
//! and a deletion refuses it (BEP-033, BEP-045, BEP-054).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use p256::PublicKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::Generate;
use zeroize::Zeroizing;

use crate::github::Secret;

#[cfg(target_os = "macos")]
pub use macos::{KeychainKey, KeychainSecrets, MacosKeychain};

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
    /// The store holds the key but will not hand it to this process.
    ///
    /// macOS admits the program that generated a key and no other, and it
    /// recognises a program by its signature, so a rebuilt or replaced binary
    /// is a different program and is locked out of what the previous one
    /// made. The keys are the proxy's alone by design (BEP-059); the way back
    /// is to replace them, which refuses every member sealed to the old ones
    /// (BEP-060).
    #[error(
        "the key store holds the key but will not let this program use it, which is what it \
         does for a key another program generated; `bep --replace-key <sealing|root|signing>` \
         is the way back, and every member sealed to the old key is refused from then on"
    )]
    Unusable,
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

// ---------------------------------------------------------------------------
// Stored secrets: the values `min secret` holds by identifier, and the access
// control that admits the proxy alone (BEP-050 to BEP-053). The same store
// holds them as holds the proxy's keys — the macOS Keychain here — and the
// seam is separate because a value is written by the operator and read by the
// proxy, where a key is never read by anyone.
// ---------------------------------------------------------------------------

/// What an access entry created for the proxy is described as. The descriptor
/// is what the store shows when it prompts, and what a listing recognises the
/// entry by when it reads an item's access control back (BEP-052).
const PROXY_ACL_DESCRIPTOR: &str = "Minimal box egress proxy";

/// The access control `min secret set` puts on a stored item: the
/// applications admitted to read it without a prompt, and the descriptor the
/// store shows for anything else (BEP-051).
///
/// One entry, created for the proxy's process identity: the proxy reads the
/// value for each request it injects it into, and every other application —
/// `min` itself included — prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemAcl {
    trusted: Vec<PathBuf>,
    descriptor: String,
}

impl ItemAcl {
    /// The access control admitting `proxy` — the proxy binary's path, which
    /// is its process identity to the store — and nothing else.
    #[must_use]
    pub fn for_proxy(proxy: &Path) -> Self {
        Self {
            trusted: vec![proxy.to_path_buf()],
            descriptor: format!("{PROXY_ACL_DESCRIPTOR} ({})", proxy.display()),
        }
    }

    /// The applications this access control admits without a prompt.
    #[must_use]
    pub fn trusted(&self) -> &[PathBuf] {
        &self.trusted
    }

    /// The descriptor the store shows when it prompts for this item.
    #[must_use]
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    /// Whether `application` reads the item without a prompt.
    #[must_use]
    pub fn admits(&self, application: &Path) -> bool {
        self.trusted.iter().any(|trusted| trusted == application)
    }

    /// Whether `application` is prompted for before it reads the item.
    #[must_use]
    pub fn prompts(&self, application: &Path) -> bool {
        !self.admits(application)
    }

    /// Whether `descriptor` describes an entry created for a proxy identity:
    /// how a listing recognises the entry in an item's access control, since
    /// the store hands back the descriptor it was given and not the path.
    #[must_use]
    pub fn is_proxy_descriptor(descriptor: &str) -> bool {
        descriptor.starts_with(PROXY_ACL_DESCRIPTOR)
    }
}

/// One item a secret store holds, as a listing reads it: the identifier and
/// the state of its access control, never the value (BEP-052).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretItem {
    /// The identifier the value is stored under.
    pub id: String,
    /// Whether the item's access control carries the entry created for the
    /// proxy's process identity.
    pub proxy_access: bool,
}

/// A store that holds secret values by identifier: what `min secret set`
/// writes, `min secret list` reads the metadata of, and the proxy reads a
/// referenced value from for each request it injects it into.
pub trait SecretItems {
    /// Stores `value` under `id` with `acl` on the item, replacing any item
    /// held under `id` before.
    ///
    /// # Errors
    ///
    /// When the store refuses the write or the access control.
    fn set(&self, id: &str, value: &Secret, acl: &ItemAcl) -> Result<(), StoreError>;

    /// The value held under `id`, if the store holds one.
    ///
    /// # Errors
    ///
    /// When the store refuses the read.
    fn read(&self, id: &str) -> Result<Option<Secret>, StoreError>;

    /// Every item the store holds, by identifier, and no value.
    ///
    /// # Errors
    ///
    /// When the store cannot be searched.
    fn items(&self) -> Result<Vec<SecretItem>, StoreError>;

    /// Removes the item held under `id`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Missing`] when the store holds none, or when the store
    /// refuses the deletion.
    fn delete(&self, id: &str) -> Result<(), StoreError>;
}

/// The value one request injects, read from `store` now (BEP-033): the store
/// is asked on every request that redeems a reference, nothing is held
/// between two, and the value lives only as long as the request that carries
/// it — so an item replaced since the last request hands over the new value
/// with no restart of the proxy (BEP-054).
///
/// `None` is every reason the value cannot be injected: the store holds no
/// item under `id`, or holds one it will not hand over — a deleted item and
/// one whose access control no longer admits the proxy alike — and the caller
/// refuses the request for either (BEP-045).
///
/// Every read is logged with the identifier and whether a value was found.
/// The value itself is written nowhere: it is returned, injected into the one
/// request, and dropped with it.
#[must_use]
pub fn value_for_request<S>(store: &S, id: &str) -> Option<Secret>
where
    S: SecretItems + ?Sized,
{
    match store.read(id) {
        Ok(value) => {
            tracing::info!(id, found = value.is_some(), "read a stored value");
            value
        }
        Err(error) => {
            tracing::warn!(id, %error, "the store would not hand over a stored value");
            None
        }
    }
}

/// An in-process secret store: items live in memory for the life of the store
/// value and every clone shares them. Nothing is written anywhere, which is
/// how a host with no bound store and a test on any host model one.
#[derive(Clone, Default)]
pub struct MemorySecrets {
    items: Arc<Mutex<BTreeMap<String, (Secret, ItemAcl)>>>,
}

impl MemorySecrets {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The access control held on `id`'s item: what `min secret set` put
    /// there, for a caller checking the entry rather than the value.
    #[must_use]
    pub fn acl(&self, id: &str) -> Option<ItemAcl> {
        self.held().get(id).map(|(_, acl)| acl.clone())
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, (Secret, ItemAcl)>> {
        self.items.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SecretItems for MemorySecrets {
    fn set(&self, id: &str, value: &Secret, acl: &ItemAcl) -> Result<(), StoreError> {
        self.held()
            .insert(id.to_owned(), (value.clone(), acl.clone()));
        Ok(())
    }

    fn read(&self, id: &str) -> Result<Option<Secret>, StoreError> {
        Ok(self.held().get(id).map(|(value, _)| value.clone()))
    }

    fn items(&self) -> Result<Vec<SecretItem>, StoreError> {
        Ok(self
            .held()
            .iter()
            .map(|(id, (_, acl))| SecretItem {
                id: id.clone(),
                proxy_access: ItemAcl::is_proxy_descriptor(acl.descriptor()),
            })
            .collect())
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.held()
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::Missing {
                name: id.to_owned(),
            })
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
    //!
    //! A stored secret is a generic-password item instead, identified by its
    //! account under one service, and carries the access control that admits
    //! the proxy alone.

    use std::ffi::{CString, c_char};
    use std::os::unix::ffi::OsStrExt as _;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use core_foundation::array::{CFArray, CFArrayRef};
    use core_foundation::base::{CFGetTypeID, CFType, CFTypeRef, OSStatus, TCFType, ToVoid};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::date::CFDate;
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use core_foundation::error::{CFError, CFErrorRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use p256::PublicKey;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use security_framework::base::Error;
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Limit, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, SecKey};
    use security_framework::os::macos::access::SecAccess;
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::{delete_generic_password, get_generic_password};
    use security_framework_sys::base::{
        SecAccessRef, SecKeychainItemRef, errSecItemNotFound, errSecSuccess,
    };
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel,
        kSecAttrService, kSecClass, kSecClassGenericPassword, kSecPrivateKeyAttrs,
        kSecPublicKeyAttrs, kSecValueData,
    };
    use security_framework_sys::key::SecKeyCreateWithData;
    use security_framework_sys::keychain_item::SecItemAdd;
    use zeroize::Zeroizing;

    use super::{
        ItemAcl, KeyStore, PrivateKey, Secret, SecretItem, SecretItems, SharedSecret, StoreError,
    };

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
            // The keychain refusing to copy the public half is not a claim
            // about the key: it is what it does for a key this program is not
            // the one admitted to. Only the decode below judges the key.
            let public = self.key.public_key().ok_or(StoreError::Unusable)?;
            let point = public
                .external_representation()
                .ok_or(StoreError::Unusable)?;
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
    // -----------------------------------------------------------------------
    // Stored secrets: one generic-password item per identifier, all under one
    // service, each carrying an access control that admits the proxy alone.
    // -----------------------------------------------------------------------

    /// The keychain service every stored value lives under, so a listing is a
    /// search for this service and nothing else on the host appears in it.
    const SECRET_SERVICE: &str = "dev.minimal.bep.secret";

    /// The item attribute holding a generic-password item's account, which is
    /// the stored identifier here (`kSecAttrAccount`).
    const ACCOUNT_ATTR: &str = "acct";

    // SAFETY: the legacy keychain access API — `SecAccess.h`, `SecACL.h`,
    // `SecTrustedApplication.h`, and `kSecAttrAccess` of `SecItem.h` — which
    // `security-framework-sys` does not declare. It is the only API that says
    // "this program reads the item without a prompt and everything else
    // prompts", which is what BEP-051 asks for; the headers have deprecated it
    // since 10.10 and the login keychain still implements it.
    // `SecTrustedApplicationRef` and `SecACLRef` are opaque CoreFoundation
    // types, passed and returned as `CFTypeRef`. The names are Apple's.
    #[allow(non_snake_case, non_upper_case_globals)]
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccess: CFStringRef;

        fn SecTrustedApplicationCreateFromPath(
            path: *const c_char,
            app: *mut CFTypeRef,
        ) -> OSStatus;

        fn SecAccessCreate(
            descriptor: CFStringRef,
            trustedlist: CFArrayRef,
            accessRef: *mut SecAccessRef,
        ) -> OSStatus;

        fn SecKeychainItemCopyAccess(
            itemRef: SecKeychainItemRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;

        fn SecAccessCopyACLList(accessRef: SecAccessRef, aclList: *mut CFArrayRef) -> OSStatus;

        fn SecACLCopyContents(
            acl: CFTypeRef,
            applicationList: *mut CFArrayRef,
            description: *mut CFStringRef,
            promptSelector: *mut u16,
        ) -> OSStatus;
    }

    /// The macOS Keychain as a store of secret values: one generic-password
    /// item per identifier in the login keychain, the value the item's data.
    ///
    /// Reading a value prompts for every program outside the item's access
    /// control, the proxy excepted, which is the point of the control; `min`
    /// itself only ever writes, lists and removes.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KeychainSecrets;

    /// The `SecAccess` for `acl`: an access control trusting the named paths,
    /// carrying the descriptor the keychain shows when it prompts for anything
    /// else.
    fn sec_access(acl: &ItemAcl) -> Result<SecAccess, StoreError> {
        let mut applications = Vec::with_capacity(acl.trusted().len());
        for path in acl.trusted() {
            let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                backend(
                    "set the item's access control",
                    &format!("the path {} contains a NUL byte", path.display()),
                )
            })?;
            let mut app: CFTypeRef = std::ptr::null();
            // SAFETY: `c_path` is a live NUL-terminated string for the call,
            // and the returned reference follows the create rule.
            let status =
                unsafe { SecTrustedApplicationCreateFromPath(c_path.as_ptr(), &raw mut app) };
            if status != errSecSuccess || app.is_null() {
                return Err(backend(
                    "set the item's access control",
                    &Error::from_code(status),
                ));
            }
            // SAFETY: created by the call above, and owned from here.
            applications.push(unsafe { CFType::wrap_under_create_rule(app) });
        }
        let descriptor = CFString::new(acl.descriptor());
        let trusted = CFArray::from_CFTypes(&applications);
        let mut access: SecAccessRef = std::ptr::null_mut();
        // SAFETY: `descriptor` and `trusted` are live CF objects for the call,
        // and the returned access follows the create rule.
        let status = unsafe {
            SecAccessCreate(
                descriptor.as_concrete_TypeRef(),
                trusted.as_concrete_TypeRef(),
                &raw mut access,
            )
        };
        if status != errSecSuccess || access.is_null() {
            return Err(backend(
                "set the item's access control",
                &Error::from_code(status),
            ));
        }
        // SAFETY: created by the call above, and owned from here.
        Ok(unsafe { SecAccess::wrap_under_create_rule(access) })
    }

    /// The keychain item holding `id`'s value, if the store holds one: the
    /// reference form, which is what an access control is read back through.
    fn find_item(id: &str) -> Result<Option<SecKeychainItem>, StoreError> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .service(SECRET_SERVICE)
            .account(id)
            .load_refs(true)
            .limit(1);
        Ok(
            search("find the stored value", &options)?.and_then(|item| match item {
                SearchResult::Ref(Reference::KeychainItem(item)) => Some(item),
                _ => None,
            }),
        )
    }

    /// Whether `item`'s access control carries an entry created for the
    /// proxy's process identity (BEP-052).
    ///
    /// The keychain hands an entry's descriptor back, never the paths it
    /// trusts, so the descriptor is what the entry is recognised by. An access
    /// control this build cannot read reads as no entry rather than as one:
    /// the listing understates what is set rather than claiming it.
    fn proxy_access_set(item: &SecKeychainItem) -> bool {
        let mut raw_access: SecAccessRef = std::ptr::null_mut();
        // SAFETY: `item` is a live keychain item, and the returned access
        // follows the create rule.
        let access = unsafe {
            if SecKeychainItemCopyAccess(item.as_concrete_TypeRef(), &raw mut raw_access)
                != errSecSuccess
                || raw_access.is_null()
            {
                return false;
            }
            SecAccess::wrap_under_create_rule(raw_access)
        };
        let mut raw_list: CFArrayRef = std::ptr::null();
        // SAFETY: `access` is live for the call, and the returned array
        // follows the create rule.
        let entries = unsafe {
            if SecAccessCopyACLList(access.as_concrete_TypeRef(), &raw mut raw_list)
                != errSecSuccess
                || raw_list.is_null()
            {
                return false;
            }
            CFArray::<CFTypeRef>::wrap_under_create_rule(raw_list)
        };
        entries.iter().any(|entry| {
            entry_descriptor(*entry)
                .is_some_and(|descriptor| ItemAcl::is_proxy_descriptor(&descriptor))
        })
    }

    /// The descriptor of one access-control entry, or `None` when the entry
    /// carries none.
    fn entry_descriptor(entry: CFTypeRef) -> Option<String> {
        let mut applications: CFArrayRef = std::ptr::null();
        let mut description: CFStringRef = std::ptr::null();
        let mut prompt: u16 = 0;
        // SAFETY: `entry` is a live element of the list the caller holds; both
        // returned references follow the create rule and are released here.
        unsafe {
            if SecACLCopyContents(
                entry,
                &raw mut applications,
                &raw mut description,
                &raw mut prompt,
            ) != errSecSuccess
            {
                return None;
            }
            if !applications.is_null() {
                drop(CFArray::<CFTypeRef>::wrap_under_create_rule(applications));
            }
            (!description.is_null())
                .then(|| CFString::wrap_under_create_rule(description).to_string())
        }
    }

    impl SecretItems for KeychainSecrets {
        fn set(&self, id: &str, value: &Secret, acl: &ItemAcl) -> Result<(), StoreError> {
            let access = sec_access(acl)?;
            // An item's access control cannot be replaced in place, so a
            // replacement is a fresh item: whatever is held goes first, and
            // the new value arrives under the new control (BEP-054). The
            // removal is not undone when the add below fails, so a failed
            // replacement says the value held before it is gone.
            let replaced = match delete_generic_password(SECRET_SERVICE, id) {
                Ok(()) => true,
                Err(error) if error.code() == errSecItemNotFound => false,
                Err(error) => return Err(backend("write the value", &error)),
            };
            let service = CFString::new(SECRET_SERVICE);
            let account = CFString::new(id);
            let data = CFData::from_buffer(value.expose().as_bytes());
            // SAFETY: the `kSec*` statics are immutable framework constants,
            // and every value is a live CF object for the call.
            let attributes = unsafe {
                CFMutableDictionary::from_CFType_pairs(&[
                    (kSecClass.to_void(), kSecClassGenericPassword.to_void()),
                    (kSecAttrService.to_void(), service.to_void()),
                    (kSecAttrAccount.to_void(), account.to_void()),
                    (kSecValueData.to_void(), data.to_void()),
                    (kSecAttrAccess.to_void(), access.to_void()),
                ])
            }
            .to_immutable();
            // SAFETY: `attributes` is live for the call, and no result is
            // asked for.
            let status =
                unsafe { SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut()) };
            if status != errSecSuccess {
                let op = if replaced {
                    "write the value, and the value held under it before is gone"
                } else {
                    "write the value"
                };
                return Err(backend(op, &Error::from_code(status)));
            }
            Ok(())
        }

        fn read(&self, id: &str) -> Result<Option<Secret>, StoreError> {
            let bytes = match get_generic_password(SECRET_SERVICE, id) {
                Ok(bytes) => bytes,
                Err(error) if error.code() == errSecItemNotFound => return Ok(None),
                Err(error) => return Err(backend("read the value", &error)),
            };
            String::from_utf8(bytes)
                .map(|value| Some(Secret::new(value)))
                .map_err(|error| backend("read the value", &error))
        }

        fn items(&self) -> Result<Vec<SecretItem>, StoreError> {
            let mut options = ItemSearchOptions::new();
            options
                .class(ItemClass::generic_password())
                .service(SECRET_SERVICE)
                .load_attributes(true)
                .limit(Limit::All);
            let found = match options.search() {
                Ok(found) => found,
                Err(error) if error.code() == errSecItemNotFound => Vec::new(),
                Err(error) => return Err(backend("list the stored values", &error)),
            };
            let mut items = Vec::new();
            for result in found {
                let Some(id) = result
                    .simplify_dict()
                    .and_then(|attributes| attributes.get(ACCOUNT_ATTR).cloned())
                else {
                    continue;
                };
                let proxy_access = find_item(&id)?.is_some_and(|item| proxy_access_set(&item));
                items.push(SecretItem { id, proxy_access });
            }
            Ok(items)
        }

        fn delete(&self, id: &str) -> Result<(), StoreError> {
            match delete_generic_password(SECRET_SERVICE, id) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == errSecItemNotFound => Err(StoreError::Missing {
                    name: id.to_owned(),
                }),
                Err(error) => Err(backend("delete the stored value", &error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{ItemAcl, MemorySecrets, SecretItem, SecretItems, StoreError, value_for_request};
    use crate::github::Secret;
    use crate::redeem::store::header_value;

    /// The identifier a store reference names, throughout these tests.
    const ID: &str = "anthropic-api-key";

    /// The prefix the reference's rule registers for the header form.
    const PREFIX: &str = "Bearer ";

    /// The access control `min secret set` puts on the item.
    fn acl() -> ItemAcl {
        ItemAcl::for_proxy(Path::new("/usr/lib/minimal/bin/bep"))
    }

    /// One request that redeems a reference to `id`, as the proxy runs it:
    /// the store is read for this request and the value goes out in the
    /// registered form, or there is nothing to inject and the request is
    /// refused. The listener's own tests prove these two run in this order on
    /// a real request; here they are the request.
    fn injected<S>(store: &S, id: &str) -> Option<String>
    where
        S: SecretItems + ?Sized,
    {
        let value = value_for_request(store, id)?;
        header_value(PREFIX, value.expose())
    }

    /// A store the test watches: it holds items exactly as [`MemorySecrets`]
    /// does and records every call made through the seam, so a test can say
    /// what the requests did to the store — and what they did not do. Every
    /// clone shares both the items and the record, as the proxy's handle on
    /// the store shares them with `min secret`'s.
    #[derive(Clone, Default)]
    struct WatchedSecrets {
        held: MemorySecrets,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl WatchedSecrets {
        /// Every call made through the seam so far, in order.
        fn calls(&self) -> Vec<String> {
            self.locked().clone()
        }

        fn record(&self, call: String) {
            self.locked().push(call);
        }

        fn locked(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
            self.calls.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    impl SecretItems for WatchedSecrets {
        fn set(&self, id: &str, value: &Secret, acl: &ItemAcl) -> Result<(), StoreError> {
            self.record(format!("set {id}"));
            self.held.set(id, value, acl)
        }

        fn read(&self, id: &str) -> Result<Option<Secret>, StoreError> {
            self.record(format!("read {id}"));
            self.held.read(id)
        }

        fn items(&self) -> Result<Vec<SecretItem>, StoreError> {
            self.record("items".to_owned());
            self.held.items()
        }

        fn delete(&self, id: &str) -> Result<(), StoreError> {
            self.record(format!("delete {id}"));
            self.held.delete(id)
        }
    }

    /// A store that holds the item and will not hand the value over: what a
    /// read does when the item's access control no longer admits the proxy —
    /// an item disabled rather than deleted (BEP-045).
    struct RefusingSecrets;

    impl SecretItems for RefusingSecrets {
        fn set(&self, _: &str, _: &Secret, _: &ItemAcl) -> Result<(), StoreError> {
            unreachable!("a request never writes to the store")
        }

        fn read(&self, id: &str) -> Result<Option<Secret>, StoreError> {
            Err(StoreError::Backend {
                op: "read the value",
                message: format!("the access control on {id} does not admit this process"),
            })
        }

        fn items(&self) -> Result<Vec<SecretItem>, StoreError> {
            unreachable!("a request never lists the store")
        }

        fn delete(&self, _: &str) -> Result<(), StoreError> {
            unreachable!("a request never deletes from the store")
        }
    }

    /// BEP-033: the value is read from the store for the request that injects
    /// it. Three successive requests make three reads, so nothing is held
    /// between two of them and no request can carry a value the store no
    /// longer holds; and a request makes no call on the store but that read,
    /// so it writes the value back nowhere. Nor does the value reach a file
    /// around the injection: the only form it renders in is redacted, so a
    /// log line or an audit record written from it names the identifier and
    /// never the value.
    #[test]
    fn store_value_read_per_request_never_written() {
        let held = "sk-ant-api03-held";
        let store = WatchedSecrets::default();
        store
            .set(ID, &Secret::new(held), &acl())
            .expect("the store holds the value");

        // The first request, spelled out: the read hands back the value, and
        // what the value renders as is redacted.
        let value = value_for_request(&store, ID).expect("the store holds the value");
        assert_eq!(
            format!("{value:?}"),
            "Secret(<redacted>)",
            "the value renders redacted, so nothing written out carries it"
        );
        assert_eq!(
            header_value(PREFIX, value.expose()).as_deref(),
            Some("Bearer sk-ant-api03-held")
        );

        // Two more requests, each reading the store again.
        for request in 2..=3 {
            assert_eq!(
                injected(&store, ID).as_deref(),
                Some("Bearer sk-ant-api03-held"),
                "request {request} carries the stored value"
            );
        }

        assert_eq!(
            store.calls(),
            [
                format!("set {ID}"),
                format!("read {ID}"),
                format!("read {ID}"),
                format!("read {ID}"),
            ],
            "one read per request, and no request writes anything"
        );
    }

    /// BEP-045: an item the store no longer holds refuses the next request
    /// that would inject it, and an item the store holds but will not hand
    /// over refuses one just the same. Nothing stands between the removal and
    /// the refusal: the handle the proxy has held since it started is the one
    /// that now finds nothing, so no restart is needed for the deletion to
    /// bite, and every refused request reads the store again rather than
    /// answering from something kept.
    #[test]
    fn deleted_keychain_item_refuses_next_injection() {
        let store = WatchedSecrets::default();
        // The handle the proxy took at startup and never renews.
        let proxy = store.clone();
        store
            .set(ID, &Secret::new("sk-ant-api03-live"), &acl())
            .expect("the store holds the value");
        assert_eq!(
            injected(&proxy, ID).as_deref(),
            Some("Bearer sk-ant-api03-live"),
            "the request before the removal carries the value"
        );

        // What `min secret remove` does to the item.
        store.delete(ID).expect("the store held the item");

        assert_eq!(
            injected(&proxy, ID),
            None,
            "the next request has nothing to inject and is refused"
        );
        assert_eq!(injected(&proxy, ID), None, "and so is the request after it");
        assert_eq!(
            store.calls(),
            [
                format!("set {ID}"),
                format!("read {ID}"),
                format!("delete {ID}"),
                format!("read {ID}"),
                format!("read {ID}"),
            ],
            "each refused request asked the store itself"
        );

        // An item still held, whose access control no longer admits the
        // proxy: the read fails rather than coming back empty, and the
        // request is refused for that too.
        assert_eq!(
            injected(&RefusingSecrets, ID),
            None,
            "a value the store will not hand over is injected into nothing"
        );
    }

    /// BEP-054: a value written over an existing item is injected by the next
    /// request that redeems a reference to it, through the handle the proxy
    /// has held since it started — no restart of the proxy between the write
    /// and the request — and the value held before it goes out on no later
    /// request.
    #[test]
    fn replaced_secret_is_injected_on_next_request() {
        let old = "sk-ant-api03-old";
        let new = "sk-ant-api03-new";
        let store = WatchedSecrets::default();
        // The handle the proxy took at startup and never renews.
        let proxy = store.clone();
        store
            .set(ID, &Secret::new(old), &acl())
            .expect("the store holds the value");
        assert_eq!(
            injected(&proxy, ID).as_deref(),
            Some("Bearer sk-ant-api03-old")
        );

        // What `min secret set <id>` does over an existing item.
        store
            .set(ID, &Secret::new(new), &acl())
            .expect("the store replaces the value");

        for request in 1..=2 {
            let carried = injected(&proxy, ID).expect("the request injects the new value");
            assert_eq!(
                carried, "Bearer sk-ant-api03-new",
                "request {request} after the replacement"
            );
            assert!(
                !carried.contains(old),
                "the replaced value went out: {carried}"
            );
        }
        assert_eq!(
            store.calls(),
            [
                format!("set {ID}"),
                format!("read {ID}"),
                format!("set {ID}"),
                format!("read {ID}"),
                format!("read {ID}"),
            ],
            "the requests after the replacement read the store again"
        );
    }

    /// The access control `min secret set` puts on an item names the proxy's
    /// process identity — the proxy binary's path — as the one application
    /// admitted without a prompt, says so in the descriptor the keychain shows
    /// when it prompts, and prompts for everything else (BEP-051).
    #[test]
    fn keychain_item_acl_names_proxy_identity() {
        let proxy = Path::new("/usr/lib/minimal/bin/bep");
        let acl = ItemAcl::for_proxy(proxy);

        assert_eq!(acl.trusted(), [proxy.to_path_buf()]);
        assert!(
            acl.admits(proxy),
            "the proxy reads the item without a prompt"
        );
        assert!(
            acl.prompts(Path::new("/Applications/Editor.app")),
            "every other application prompts"
        );
        assert!(
            acl.prompts(Path::new("/usr/lib/minimal/bin/min")),
            "`min` itself prompts: it writes the item and never reads it"
        );
        assert!(
            acl.descriptor().contains("/usr/lib/minimal/bin/bep"),
            "the descriptor names the identity the entry was created for: {}",
            acl.descriptor()
        );
        assert!(
            ItemAcl::is_proxy_descriptor(acl.descriptor()),
            "a listing recognises the entry by its descriptor"
        );
        assert!(!ItemAcl::is_proxy_descriptor("iTerm"));

        // What a store holds under the item is the entry the set put there.
        let store = MemorySecrets::new();
        store
            .set("anthropic-api-key", &Secret::new("sk-value"), &acl)
            .expect("the store holds the value");
        assert_eq!(store.acl("anthropic-api-key").as_ref(), Some(&acl));
        let items = store.items().expect("the store lists its items");
        let [item] = items.as_slice() else {
            panic!("one item was stored, got {items:?}")
        };
        assert_eq!(item.id, "anthropic-api-key");
        assert!(item.proxy_access, "the entry created for the proxy is set");
    }
}
