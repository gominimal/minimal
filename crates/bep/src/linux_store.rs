//! The proxy's key store on Linux (BEP-088, BEP-089): the TPM and Secret
//! Service together.
//!
//! The store looks up each role in every store, because a role can be in
//! either one. It generates a missing key in the TPM where the TPM creates
//! and loads it, and otherwise in Secret Service. The store is chosen at
//! generation only. A later start loads each key from the store that holds
//! it, and never generates a key that another store holds. A store that
//! does not answer is reported through [`KeyStore::reach`], so a start that
//! misses a key does not name a replacement for a key that can still be
//! there.

use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::ca::CaKey;
use crate::keys::{HeldKey, KeyError, KeyStore, Role, Slot, StoreReach, UnreadStore, missing_in};
use crate::seal::ProxyPublicKey;
use crate::secret_service::{SecretService, SecretServiceKey};
use crate::tpm::{TpmKey, TpmStore};

/// The log name of the TPM store.
const TPM: &str = "tpm";
/// The log name of the Secret Service store.
const SECRET_SERVICE: &str = "secret-service";

/// A key that the TPM or Secret Service holds.
#[derive(Debug)]
pub enum LinuxKey<T = TpmKey, S = SecretServiceKey> {
    /// A key in the TPM.
    Tpm(T),
    /// A software key in Secret Service.
    SecretService(S),
}

impl<T, S> LinuxKey<T, S> {
    /// The log name of the store that holds the key.
    pub fn store(&self) -> &'static str {
        match self {
            Self::Tpm(_) => TPM,
            Self::SecretService(_) => SECRET_SERVICE,
        }
    }
}

impl<T: HeldKey, S: HeldKey> HeldKey for LinuxKey<T, S> {
    fn role(&self) -> Role {
        match self {
            Self::Tpm(key) => key.role(),
            Self::SecretService(key) => key.role(),
        }
    }

    fn public(&self) -> ProxyPublicKey {
        match self {
            Self::Tpm(key) => key.public(),
            Self::SecretService(key) => key.public(),
        }
    }

    fn exportable(&self) -> bool {
        match self {
            Self::Tpm(key) => key.exportable(),
            Self::SecretService(key) => key.exportable(),
        }
    }

    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        match self {
            Self::Tpm(key) => key.agree(peer),
            Self::SecretService(key) => key.agree(peer),
        }
    }

    fn probe(&self) -> Result<(), KeyError> {
        match self {
            Self::Tpm(key) => key.probe(),
            Self::SecretService(key) => key.probe(),
        }
    }
}

impl<T: CaKey, S: CaKey> CaKey for LinuxKey<T, S> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Tpm(key) => key.sign(msg),
            Self::SecretService(key) => key.sign(msg),
        }
    }
}

/// The key store over the TPM store and the Secret Service store.
#[derive(Debug)]
pub struct LinuxStore<T = TpmStore, S = SecretService> {
    tpm: T,
    secret_service: S,
    /// The first store that did not answer a lookup.
    unread: Mutex<Option<UnreadStore>>,
}

impl LinuxStore {
    /// The store over the TPM key files in `~/.minimal/bep/tpm` and the
    /// user's Secret Service, or `None` when there is no home directory.
    #[must_use]
    pub fn at_home() -> Option<Self> {
        TpmStore::at_home().map(|tpm| Self::new(tpm, SecretService::new()))
    }
}

impl<T: KeyStore, S: KeyStore> LinuxStore<T, S> {
    /// The store over `tpm` and `secret_service`.
    pub fn new(tpm: T, secret_service: S) -> Self {
        Self {
            tpm,
            secret_service,
            unread: Mutex::new(None),
        }
    }

    fn mark_unread(&self, store: UnreadStore) {
        let mut unread = self
            .unread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unread.get_or_insert(store);
    }

    /// The answer of a Secret Service lookup, or `None` when Secret
    /// Service did not answer. That store is then marked unread.
    fn secret_service_answer<V>(&self, role: Role, answer: Result<V, KeyError>) -> Option<V> {
        match answer {
            Ok(value) => Some(value),
            Err(err) => {
                let unread = match err {
                    KeyError::Locked { .. } => UnreadStore::SecretServiceLocked,
                    _ => UnreadStore::SecretServiceUnreachable,
                };
                tracing::warn!(role = %role, store = SECRET_SERVICE, error = %err, "Secret Service did not answer a proxy key lookup");
                self.mark_unread(unread);
                None
            }
        }
    }

    /// Whether either store holds a key for `role` in `slot`. A Secret
    /// Service that does not answer holds none here, and is marked unread.
    /// A start reads that mark through [`KeyStore::reach`].
    fn held_anywhere(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        if self.tpm.holds_in(role, slot)? {
            return Ok(true);
        }
        Ok(self
            .secret_service_answer(role, self.secret_service.holds_in(role, slot))
            .unwrap_or(false))
    }

    /// Whether Secret Service holds a key for `role` in `slot`, for a
    /// change to the stores. A locked keyring can hold the key, so its
    /// error stops the change. A Secret Service that this session cannot
    /// reach holds none here, as on a headless host (BEP-088).
    fn secret_service_holds(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        match self.secret_service.holds_in(role, slot) {
            Err(err @ KeyError::Locked { .. }) => {
                tracing::warn!(role = %role, store = SECRET_SERVICE, error = %err, "Secret Service did not answer a proxy key lookup");
                self.mark_unread(UnreadStore::SecretServiceLocked);
                Err(err)
            }
            answer => Ok(self.secret_service_answer(role, answer).unwrap_or(false)),
        }
    }
}

impl<T: KeyStore, S: KeyStore> KeyStore for LinuxStore<T, S> {
    type Key = LinuxKey<T::Key, S::Key>;

    fn find(&self, role: Role) -> Result<Option<Self::Key>, KeyError> {
        // A key file in the TPM store is the role's key, so its errors
        // stop the start. A TPM store that does not answer at all can hide
        // the key, so the lookup goes on in Secret Service.
        match self.tpm.find(role) {
            Ok(Some(key)) => {
                tracing::info!(role = %role, store = TPM, "found the proxy key");
                return Ok(Some(LinuxKey::Tpm(key)));
            }
            Ok(None) => {}
            Err(err @ KeyError::Store { .. }) => {
                tracing::warn!(role = %role, store = TPM, error = %err, "the TPM store did not answer a proxy key lookup");
                self.mark_unread(UnreadStore::TpmUnreachable);
            }
            Err(err) => return Err(err),
        }
        let found = self.secret_service_answer(role, self.secret_service.find(role));
        match found.flatten() {
            Some(key) => {
                tracing::info!(role = %role, store = SECRET_SERVICE, "found the proxy key");
                Ok(Some(LinuxKey::SecretService(key)))
            }
            None => {
                tracing::info!(role = %role, store = "none", "found the proxy key");
                Ok(None)
            }
        }
    }

    fn generate_in(&self, role: Role, slot: Slot) -> Result<Self::Key, KeyError> {
        // BEP-089: a key another store holds is never made again elsewhere.
        if self.tpm.holds_in(role, slot)? || self.secret_service_holds(role, slot)? {
            return Err(KeyError::Store {
                role,
                detail: "a key store already holds this key".into(),
            });
        }
        // BEP-088: the TPM is usable when it creates the key and loads it.
        // The TPM store loads each key it makes before it returns it.
        let tpm = match self.tpm.generate_in(role, slot) {
            Ok(key) => {
                tracing::info!(role = %role, store = TPM, "chose the key store for a new proxy key");
                return Ok(LinuxKey::Tpm(key));
            }
            Err(err) => err,
        };
        match self.secret_service.generate_in(role, slot) {
            Ok(key) => {
                tracing::info!(
                    role = %role,
                    store = SECRET_SERVICE,
                    tpm = %tpm,
                    "chose the key store for a new proxy key, because the TPM did not make it"
                );
                Ok(LinuxKey::SecretService(key))
            }
            Err(secret_service) => Err(KeyError::NoStore {
                role,
                tpm: tpm.to_string(),
                secret_service: secret_service.to_string(),
            }),
        }
    }

    fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        self.tpm.remove_in(role, slot)?;
        if self.secret_service_holds(role, slot)? {
            self.secret_service.remove_in(role, slot)?;
        }
        Ok(())
    }

    fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        self.held_anywhere(role, slot)
    }

    fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
        if let Some(kid) = self.tpm.kid_in(role, slot)? {
            return Ok(Some(kid));
        }
        Ok(self
            .secret_service_answer(role, self.secret_service.kid_in(role, slot))
            .flatten())
    }

    fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
        // A key moves inside the store that holds it, never to another.
        if self.tpm.holds_in(role, from)? {
            return self.tpm.relabel(role, from, to);
        }
        if self.secret_service_holds(role, from)? {
            return self.secret_service.relabel(role, from, to);
        }
        if from == Slot::Held {
            Ok(())
        } else {
            Err(missing_in(role, from))
        }
    }

    fn reach(&self) -> StoreReach {
        let unread = self
            .unread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *unread {
            Some(store) => StoreReach::Unread(store),
            None => StoreReach::Every,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::*;
    use crate::keys::memory::MemoryStore;
    use crate::keys::{PublishedKid, StartError, load, load_with};

    const ANSWERS: u8 = 0;
    const LOCKED: u8 = 1;
    const UNREACHABLE: u8 = 2;

    /// A memory store that can stop answering, as a locked or unreachable
    /// Secret Service does.
    #[derive(Default)]
    struct Gated {
        inner: MemoryStore,
        state: AtomicU8,
    }

    impl Gated {
        fn set(&self, state: u8) {
            self.state.store(state, Ordering::SeqCst);
        }

        fn gate(&self, role: Role) -> Result<(), KeyError> {
            let detail = "test".to_string();
            match self.state.load(Ordering::SeqCst) {
                LOCKED => Err(KeyError::Locked { role, detail }),
                UNREACHABLE => Err(KeyError::Unreachable { role, detail }),
                _ => Ok(()),
            }
        }
    }

    impl KeyStore for Gated {
        type Key = <MemoryStore as KeyStore>::Key;

        fn find(&self, role: Role) -> Result<Option<Self::Key>, KeyError> {
            self.gate(role)?;
            self.inner.find(role)
        }

        fn generate_in(&self, role: Role, slot: Slot) -> Result<Self::Key, KeyError> {
            self.gate(role)?;
            self.inner.generate_in(role, slot)
        }

        fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
            self.gate(role)?;
            self.inner.remove_in(role, slot)
        }

        fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
            self.gate(role)?;
            self.inner.holds_in(role, slot)
        }

        fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
            self.gate(role)?;
            self.inner.kid_in(role, slot)
        }

        fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
            self.gate(role)?;
            self.inner.relabel(role, from, to)
        }
    }

    fn store() -> LinuxStore<MemoryStore, Gated> {
        LinuxStore::new(MemoryStore::default(), Gated::default())
    }

    /// The same keys under a new store value, as at the next start.
    fn restart(old: LinuxStore<MemoryStore, Gated>) -> LinuxStore<MemoryStore, Gated> {
        LinuxStore::new(old.tpm, old.secret_service)
    }

    fn published(roles: &'static [Role]) -> impl Fn(Role) -> PublishedKid {
        move |role| {
            if roles.contains(&role) {
                PublishedKid::Unread
            } else {
                PublishedKid::Absent
            }
        }
    }

    fn stores(
        keys: &crate::keys::ProxyKeys<<LinuxStore<MemoryStore, Gated> as KeyStore>::Key>,
    ) -> Vec<&'static str> {
        Role::ALL.map(|role| keys.get(role).store()).to_vec()
    }

    // BEP-088
    #[test]
    fn linux_key_store_is_the_tpm_where_usable_else_secret_service() {
        let usable = store();
        let keys = load(&usable, &[]).expect("a first start");
        assert_eq!(stores(&keys), [TPM; 3]);
        assert_eq!(usable.tpm.generated(), 3);
        assert_eq!(usable.secret_service.inner.generated(), 0);

        let no_tpm = store();
        no_tpm.tpm.fail_generation();
        let keys = load(&no_tpm, &[]).expect("a first start");
        assert_eq!(stores(&keys), [SECRET_SERVICE; 3]);
        assert_eq!(no_tpm.secret_service.inner.generated(), 3);

        // The store is chosen for each key it generates.
        let partial = store();
        partial.tpm.fail_generation_of(Role::Root);
        let keys = load(&partial, &[]).expect("a first start");
        assert_eq!(stores(&keys), [TPM, SECRET_SERVICE, TPM]);

        // A host with no Secret Service in this session still starts on
        // its TPM.
        let headless = store();
        headless.secret_service.set(UNREACHABLE);
        let keys = load(&headless, &[]).expect("a first start");
        assert_eq!(stores(&keys), [TPM; 3]);
    }

    // BEP-088
    #[test]
    fn no_tpm_and_no_secret_service_refuses_start() {
        let store = store();
        store.tpm.fail_generation();
        store.secret_service.set(UNREACHABLE);
        let err = load(&store, &[]).expect_err("nowhere to keep a key");
        assert_eq!(err, StartError::NoStore(Role::Sealing));
        assert_eq!(
            err.to_string(),
            "The proxy did not start: this host has no usable TPM and no unlocked Secret Service keyring, so the proxy has nowhere to keep its keys."
        );
        assert!(!err.to_string().contains("only on macOS"));
        assert_eq!(store.tpm.generated(), 0);

        // A locked keyring can hold the keys, so the start makes none and
        // says which store it cannot read.
        let locked = self::store();
        locked.tpm.fail_generation();
        locked.secret_service.set(LOCKED);
        let err = load(&locked, &[]).expect_err("a locked keyring");
        assert_eq!(
            err,
            StartError::Kept {
                missing: Role::ALL.to_vec(),
                store: UnreadStore::SecretServiceLocked,
            }
        );
        assert!(!err.to_string().contains("--replace-key"));
        assert_eq!(locked.tpm.generated(), 0);
    }

    // BEP-089
    #[test]
    fn a_held_key_is_never_moved_to_another_store() {
        let all: &'static [Role] = &Role::ALL;
        // Keys made in Secret Service while the TPM was not usable.
        let mut store = store();
        store.tpm.fail_generation();
        let first = load(&store, &[]).expect("a first start");
        let kids = Role::ALL.map(|role| first.get(role).public().kid());
        drop(first);

        // A TPM that works now does not take over the keys.
        store.tpm.clear_generation_failure();
        store = restart(store);
        let again = load_with(&store, published(all)).expect("a later start");
        assert_eq!(stores(&again), [SECRET_SERVICE; 3]);
        assert_eq!(Role::ALL.map(|role| again.get(role).public().kid()), kids);
        assert_eq!(store.tpm.generated(), 0);
        drop(again);

        // A Secret Service that stops answering is no reason to use the
        // TPM in its place.
        for state in [LOCKED, UNREACHABLE] {
            store.secret_service.set(state);
            let next = restart(store);
            let err = load_with(&next, published(all)).expect_err("keys it cannot read");
            assert!(matches!(err, StartError::Kept { .. }), "{err:?}");
            assert_eq!(next.tpm.generated(), 0);
            next.secret_service.set(ANSWERS);
            store = next;
        }

        // With no identity file, a locked keyring that holds every key
        // looks like a first start. The TPM makes no key to hide them.
        store.secret_service.set(LOCKED);
        let next = restart(store);
        let err = load(&next, &[]).expect_err("keys it cannot read");
        assert!(matches!(err, StartError::Kept { .. }), "{err:?}");
        assert!(!err.to_string().contains("--replace-key"));
        assert_eq!(next.tpm.generated(), 0);
        // A change to the stores does not read a locked keyring as empty.
        let err = next
            .generate_in(Role::Sealing, Slot::New)
            .expect_err("locked");
        assert!(matches!(err, KeyError::Locked { .. }), "{err:?}");
        assert!(next.remove_in(Role::Sealing, Slot::Held).is_err());
        assert!(next.relabel(Role::Sealing, Slot::Held, Slot::Old).is_err());
        assert_eq!(next.tpm.generated(), 0);
        next.secret_service.set(ANSWERS);
        assert!(
            next.secret_service
                .inner
                .holds_in(Role::Sealing, Slot::Held)
                .unwrap()
        );

        // Keys made in the TPM stay there when the TPM stops making keys.
        let tpm = self::store();
        let first = load(&tpm, &[]).expect("a first start");
        let kids = Role::ALL.map(|role| first.get(role).public().kid());
        drop(first);
        tpm.tpm.fail_generation();
        let tpm = restart(tpm);
        let again = load_with(&tpm, published(all)).expect("a later start");
        assert_eq!(stores(&again), [TPM; 3]);
        assert_eq!(Role::ALL.map(|role| again.get(role).public().kid()), kids);
        assert_eq!(tpm.secret_service.inner.generated(), 0);

        // The store never generates a role that a store holds.
        let err = tpm
            .generate_in(Role::Sealing, Slot::Held)
            .expect_err("held");
        assert!(matches!(err, KeyError::Store { .. }), "{err:?}");
        assert_eq!(tpm.secret_service.inner.generated(), 0);
    }

    // BEP-089
    #[test]
    fn a_missing_role_key_refuses_start_and_names_replacement() {
        let store = store();
        load(&store, &[]).expect("a first start");
        store.tpm.remove(Role::Root).expect("remove");
        let store = restart(store);
        let err = load(&store, &[]).expect_err("a lost key");
        assert_eq!(err, StartError::Lost(vec![Role::Root]));
        assert_eq!(
            err.to_string(),
            "No key store on this host holds the proxy's root key. Run `bep --replace-key root` to make a new one. Boxes created before then must be re-created."
        );
        // The start made no key in either store.
        assert_eq!(store.tpm.generated(), 3);
        assert_eq!(store.secret_service.inner.generated(), 0);
    }

    // BEP-089
    #[test]
    fn a_missing_role_with_an_unreadable_store_refuses_start_and_keeps_the_key() {
        let cases = [
            (LOCKED, "Secret Service is locked"),
            (UNREACHABLE, "Secret Service cannot be reached"),
        ];
        for (state, why) in cases {
            // The sealing key is in the TPM, and the root key in Secret
            // Service.
            let store = store();
            store.tpm.fail_generation_of(Role::Root);
            load(&store, &[]).expect("a first start");
            store.tpm.clear_generation_failure();
            store.secret_service.set(state);
            let store = restart(store);
            let err = load(&store, &[]).expect_err("a key it cannot read");
            assert_eq!(
                err.to_string(),
                format!(
                    "The proxy did not start: no key store it can read holds the proxy's root key, and {why}. The key may be there, so it is kept."
                )
            );
            assert!(!err.to_string().contains("--replace-key"));
            // The root key is still in Secret Service, and the TPM made
            // no second one.
            store.secret_service.set(ANSWERS);
            assert!(
                store
                    .secret_service
                    .inner
                    .holds_in(Role::Root, Slot::Held)
                    .unwrap()
            );
            assert_eq!(store.tpm.generated(), 2);
        }
        assert_eq!(
            UnreadStore::TpmUnreachable.to_string(),
            "the TPM cannot be reached"
        );
    }
}
