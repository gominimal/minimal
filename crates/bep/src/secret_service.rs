//! The Secret Service key store, for a Linux host with no usable TPM
//! (BEP-088, BEP-089).
//!
//! [`SecretService`] generates each proxy key as a software P-256 key and
//! holds its private half in Secret Service through
//! [`secret_items`](crate::secret_items), as [`signin`](crate::signin) holds
//! the sign-in. Each item has one attribute, `service`, whose value is the
//! role's label in its slot (see [`Role::slot_label`]). Secret Service holds no key non-exportable and
//! has no control per program, so a program running as the proxy's user can
//! read these keys.
//!
//! A locked keyring and a Secret Service that this session cannot reach are
//! [`KeyError::Locked`] and [`KeyError::Unreachable`]. Neither removes or
//! replaces a key: the keys still exist, and the start refuses until the
//! operator unlocks the keyring or starts the proxy from the desktop
//! session. No call shows an unlock prompt. A Secret Service that does not
//! answer in time is [`KeyError::Store`]: a provider is there and can hold
//! the keys, so the start stops and makes no key in another store.

use base64::Engine as _;
use p256::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::keys::{HeldKey, KeyError, KeyStore, Role, Slot, missing_in};
use crate::seal::ProxyPublicKey;
use crate::secret_items::{Cause, Items, SessionItems};

/// The one attribute of each item. Its value is the role's slot label.
const ATTRIBUTE: &str = "service";

/// The store name in the log lines.
const STORE: &str = "secret-service";

/// The proxy's keys in Secret Service.
#[derive(Debug, Clone, Default)]
pub struct SecretService<I = SessionItems> {
    items: I,
}

impl SecretService {
    /// The store in the user's Secret Service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I: Items> SecretService<I> {
    /// The store that keeps its items in `items`. A test gives it items
    /// held in memory.
    #[must_use]
    pub fn with_items(items: I) -> Self {
        Self { items }
    }

    /// The private half held for `role` in `slot`, or `None`.
    fn lookup(&self, role: Role, slot: Slot) -> Result<Option<SecretKey>, KeyError> {
        let label = role.slot_label(slot);
        let Some(held) = self
            .items
            .lookup(&[(ATTRIBUTE, &label)])
            .map_err(|cause| failure(role, &cause))?
        else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&held).map_err(|_| unreadable(role))?;
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| unreadable(role))?,
        );
        SecretKey::from_slice(&bytes)
            .map(Some)
            .map_err(|_| unreadable(role))
    }

    /// Holds `secret` for `role` in `slot`, in place of any key there. With
    /// no answer from Secret Service, a request it already has can still
    /// put the key there, and the error says so. The next generation in
    /// the slot replaces that key.
    fn store(&self, role: Role, slot: Slot, secret: &SecretKey) -> Result<(), KeyError> {
        let label = role.slot_label(slot);
        let bytes = Zeroizing::new(secret.to_bytes().to_vec());
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes.as_slice()));
        self.items
            .store(&label, &[(ATTRIBUTE, &label)], encoded.as_bytes())
            .map_err(|cause| match cause {
                Cause::NoAnswer(_) => KeyError::Store {
                    role,
                    detail: format!("{cause}, and it can still store the key"),
                },
                cause => failure(role, &cause),
            })
    }

    /// Removes the item for `role` in `slot`. An empty slot is not an error.
    fn clear(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        let label = role.slot_label(slot);
        self.items
            .clear(&[(ATTRIBUTE, &label)])
            .map(|_| ())
            .map_err(|cause| failure(role, &cause))
    }
}

/// The key error for a Secret Service call that failed with `cause`.
fn failure(role: Role, cause: &Cause) -> KeyError {
    let detail = cause.to_string();
    match cause {
        Cause::Locked(_) => KeyError::Locked { role, detail },
        Cause::Unreachable(_) | Cause::NoProvider(_) => KeyError::Unreachable { role, detail },
        // A provider that does not answer in time can hold the key, so it
        // is not the headless host that has no Secret Service.
        _ => KeyError::Store { role, detail },
    }
}

fn unreadable(role: Role) -> KeyError {
    KeyError::Store {
        role,
        detail: "Secret Service holds an item for this key that is not a P-256 private key".into(),
    }
}

fn random_secret() -> Result<SecretKey, getrandom::Error> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

/// A software key that Secret Service holds. The private half is in this
/// process's memory while the proxy runs, and zeroed on drop.
pub struct SecretServiceKey {
    role: Role,
    secret: SecretKey,
}

impl std::fmt::Debug for SecretServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretServiceKey")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl HeldKey for SecretServiceKey {
    fn role(&self) -> Role {
        self.role
    }

    fn store(&self) -> Option<&'static str> {
        Some("secret-service")
    }

    fn public(&self) -> ProxyPublicKey {
        ProxyPublicKey::from_sec1_bytes(&self.secret.public_key().to_sec1_bytes())
            .expect("a P-256 public key")
    }

    /// `false`: the custody rule of [`custody`](crate::keys::custody) is
    /// the keychain's export flag. A Secret Service key is a software key
    /// by design (BEP-088), and the proxy reports it as such (BEP-090).
    fn exportable(&self) -> bool {
        false
    }

    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let peer =
            PublicKey::from_sec1_bytes(&peer.to_sec1_bytes()).map_err(|_| KeyError::Store {
                role: self.role,
                detail: "the peer key is not a P-256 point".into(),
            })?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }

    /// The key was read from Secret Service when the store found it, so a
    /// locked or unreachable keyring refused the start there.
    fn probe(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

impl crate::ca::CaKey for SecretServiceKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature =
            p256::ecdsa::SigningKey::from(&self.secret).sign(msg);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl<I: Items> KeyStore for SecretService<I> {
    type Key = SecretServiceKey;

    fn find(&self, role: Role) -> Result<Option<SecretServiceKey>, KeyError> {
        let Some(secret) = self.lookup(role, Slot::Held)? else {
            return Ok(None);
        };
        let key = SecretServiceKey { role, secret };
        tracing::info!(role = %role, fingerprint = %key.public().kid(), store = STORE, "loaded a proxy key");
        Ok(Some(key))
    }

    fn generate_in(&self, role: Role, slot: Slot) -> Result<SecretServiceKey, KeyError> {
        let secret = random_secret().map_err(|err| KeyError::Store {
            role,
            detail: format!("the random source failed: {err}"),
        })?;
        self.store(role, slot, &secret)?;
        let key = SecretServiceKey { role, secret };
        tracing::info!(role = %role, fingerprint = %key.public().kid(), store = STORE, "generated a proxy key");
        Ok(key)
    }

    fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
        self.clear(role, slot)
    }

    fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
        self.lookup(role, slot).map(|secret| secret.is_some())
    }

    fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
        Ok(self.lookup(role, slot)?.map(|secret| {
            ProxyPublicKey::from_sec1_bytes(&secret.public_key().to_sec1_bytes())
                .expect("a P-256 public key")
                .kid()
        }))
    }

    fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
        let Some(secret) = self.lookup(role, from)? else {
            return if from == Slot::Held {
                Ok(())
            } else {
                Err(missing_in(role, from))
            };
        };
        // Write the key in `to` first, so a failure leaves it in `from`.
        self.store(role, to, &secret)?;
        self.clear(role, from)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::keys::{StartError, load};
    use crate::secret_items::MemoryItems;

    fn fake() -> (MemoryItems, SecretService<MemoryItems>) {
        let items = MemoryItems::default();
        (items.clone(), SecretService::with_items(items))
    }

    fn labels(items: &MemoryItems) -> Vec<String> {
        items.attribute_values(&[], ATTRIBUTE).unwrap()
    }

    fn kids(store: &SecretService<MemoryItems>) -> Vec<String> {
        let keys = load(store, &[]).unwrap();
        Role::ALL
            .into_iter()
            .map(|role| keys.get(role).public().kid())
            .collect()
    }

    // BEP-088, BEP-089
    #[test]
    fn keys_are_generated_and_held_in_secret_service() {
        let (items, store) = fake();
        let first = kids(&store);
        assert_eq!(
            labels(&items),
            vec![
                "dev.gominimal.bep.root",
                "dev.gominimal.bep.sealing",
                "dev.gominimal.bep.signing"
            ]
        );
        assert_eq!(kids(&store), first, "a restart loads the held keys");
    }

    // An item is the key's 32 bytes in base64, as text, under the one
    // attribute `service`. A host that wrote its keys before reads them
    // after, with or without a line end.
    #[test]
    fn a_key_is_held_as_base64_text_under_its_label() {
        let (items, store) = fake();
        let key = store.generate_in(Role::Root, Slot::Held).unwrap();
        let held = items
            .lookup(&[(ATTRIBUTE, "dev.gominimal.bep.root")])
            .unwrap()
            .unwrap();
        let text = std::str::from_utf8(&held).unwrap().to_owned();
        assert_eq!(text.len(), 44);
        items
            .store(
                "dev.gominimal.bep.root",
                &[(ATTRIBUTE, "dev.gominimal.bep.root")],
                format!("{text}\n").as_bytes(),
            )
            .unwrap();
        let found = store.find(Role::Root).unwrap().unwrap();
        assert_eq!(found.public().kid(), key.public().kid());
    }

    // BEP-090
    #[test]
    fn each_held_key_names_its_store() {
        let (_, store) = fake();
        let keys = load(&store, &[]).unwrap();
        for role in Role::ALL {
            assert_eq!(keys.get(role).store(), Some("secret-service"));
        }
    }

    // BEP-060, BEP-089
    #[test]
    fn a_replacement_moves_the_new_key_into_the_role() {
        let (items, store) = fake();
        let first = kids(&store);
        crate::keys::replace(&store, Role::Signing).unwrap();
        let second = kids(&store);
        assert_eq!(first[..2], second[..2]);
        assert_ne!(first[2], second[2]);
        assert_eq!(items.len(), 3);
    }

    fn refuses_start_and_keeps_the_keys(
        fail: impl Fn(&MemoryItems, bool),
        expected: &StartError,
        text: &str,
    ) {
        let (items, store) = fake();
        let first = kids(&store);
        fail(&items, true);
        let err = load(&store, &[]).unwrap_err();
        assert_eq!(&err, expected);
        assert_eq!(err.to_string(), text);
        assert!(!text.contains("--replace-key"));
        fail(&items, false);
        assert_eq!(kids(&store), first, "the refused start kept every key");
    }

    // BEP-089
    #[test]
    fn a_locked_secret_service_refuses_start() {
        refuses_start_and_keeps_the_keys(
            MemoryItems::set_locked,
            &StartError::Locked(Role::Sealing),
            "The proxy did not start: the login keyring is locked, and it holds the proxy's sealing key. Unlock the login keyring, then start the proxy again.",
        );
    }

    // BEP-089
    #[test]
    fn an_unreachable_secret_service_refuses_start() {
        refuses_start_and_keeps_the_keys(
            |items, on| items.set_failure(on.then(|| Cause::Unreachable("no session bus".into()))),
            &StartError::Unreachable(Role::Sealing),
            "The proxy did not start: Secret Service cannot be reached from this session, and it holds the proxy's sealing key. Start the proxy from the desktop session that holds the login keyring.",
        );
    }

    // BEP-089: a Secret Service that does not answer in time is there and
    // can hold the keys. The start stops with what happened, and reads
    // neither as a locked keyring nor as a host with no Secret Service.
    #[test]
    fn a_secret_service_that_does_not_answer_refuses_start() {
        let stuck = KeyError::Store {
            role: Role::Sealing,
            detail: "Secret Service did not answer in 60 s".into(),
        };
        refuses_start_and_keeps_the_keys(
            |items, on| {
                items.set_failure(on.then(|| Cause::NoAnswer(Duration::from_secs(60))));
            },
            &StartError::Store(stuck),
            "The proxy did not start: the key store failed for the sealing key: Secret Service did not answer in 60 s.",
        );
    }

    #[test]
    fn a_generation_with_no_answer_says_the_key_can_still_be_stored() {
        let (items, store) = fake();
        items.set_failure(Some(Cause::NoAnswer(Duration::from_secs(60))));
        let err = store.generate(Role::Root).map(|_| ()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the key store failed for the root key: Secret Service did not answer in 60 s, and it can still store the key"
        );
    }

    #[test]
    fn secret_service_failures_are_sorted_by_cause() {
        assert!(matches!(
            failure(Role::Root, &Cause::Locked("locked".into())),
            KeyError::Locked {
                role: Role::Root,
                ..
            }
        ));
        assert!(matches!(
            failure(Role::Root, &Cause::NoProvider("no Secret Service".into())),
            KeyError::Unreachable { .. }
        ));
        assert!(matches!(
            failure(Role::Root, &Cause::Unreachable("no bus".into())),
            KeyError::Unreachable {
                role: Role::Root,
                ..
            }
        ));
        for other in [
            Cause::NoAnswer(Duration::from_secs(1)),
            Cause::Other("something else".into()),
        ] {
            assert!(
                matches!(
                    failure(Role::Root, &other),
                    KeyError::Store {
                        role: Role::Root,
                        ..
                    }
                ),
                "{other:?}"
            );
        }
    }

    // BEP-089: a locked keyring writes and removes nothing.
    #[test]
    fn a_locked_keyring_takes_no_change() {
        let (items, store) = fake();
        store.generate_in(Role::Root, Slot::Held).unwrap();
        items.set_locked(true);
        assert!(matches!(
            store.generate_in(Role::Signing, Slot::Held),
            Err(KeyError::Locked { .. })
        ));
        assert!(matches!(
            store.remove_in(Role::Root, Slot::Held),
            Err(KeyError::Locked { .. })
        ));
        // A slot that holds no item is empty, locked or not.
        assert!(!store.holds_in(Role::Signing, Slot::Held).unwrap());
        assert_eq!(items.len(), 1);
    }

    // BEP-089
    #[test]
    fn an_item_that_is_not_a_key_is_not_an_empty_slot() {
        let (items, store) = fake();
        for held in [b"".as_slice(), b"not base64", b"\xff\x00", b"c2hvcnQ="] {
            items
                .store("x", &[(ATTRIBUTE, "dev.gominimal.bep.root")], held)
                .unwrap();
            assert!(
                matches!(
                    store.lookup(Role::Root, Slot::Held),
                    Err(KeyError::Store {
                        role: Role::Root,
                        ..
                    })
                ),
                "{held:?}"
            );
        }
    }

    // BEP-088, BEP-089: Secret Service is the one store of software keys
    // that a release build holds. BEP-014 and BEP-059 exempt it, so the
    // custody rule never refuses its key and a release build can start.
    #[test]
    fn a_release_build_holds_a_secret_service_key() {
        use crate::keys::{Build, Custody, custody};
        let (_, store) = fake();
        for role in Role::ALL {
            let key = store.generate_in(role, Slot::Held).unwrap();
            assert!(!key.exportable());
            assert_eq!(custody(&key, Build::Release), Custody::Held);
            assert_eq!(custody(&key, Build::Debug), Custody::Held);
        }
    }
}
