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
//! On macOS the store is [`Keychain`]. A release build generates each key
//! in the Secure Enclave and holds it in the data-protection keychain, under
//! the access group that the signed `bep.app` bundle's provisioning profile
//! grants. A debug build cannot hold that entitlement, so it keeps its keys
//! in the login keychain, which admits a key only to the program that
//! generated it: a rebuilt proxy is refused its keys and recovers through
//! [`replace`].

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
        self.slot_label(Slot::Held)
    }

    /// The label of the store item that holds the key in `slot`.
    #[must_use]
    pub fn slot_label(self, slot: Slot) -> String {
        match slot {
            Slot::Held => format!("dev.gominimal.bep.{}", self.as_str()),
            Slot::New => format!("dev.gominimal.bep.{}.new", self.as_str()),
            Slot::Old => format!("dev.gominimal.bep.{}.old", self.as_str()),
        }
    }
}

/// Where a store holds a key for a role. The proxy uses only the key under
/// [`Slot::Held`]. [`replace`] uses the other two slots, so that the store
/// keeps the old key until the new key holds the role's label (BEP-060).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    /// The role's label: the key the proxy uses.
    Held,
    /// The new key that [`replace`] generated, before it takes the role's
    /// label.
    New,
    /// The old key, while [`replace`] moves the new key to the role's label.
    Old,
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
    /// The store made a key, the keychain made it exportable, and the
    /// build refused it. `removed` says whether the store then removed it.
    #[error(
        "the keychain made the new {role} key exportable. This build does not use an exportable key"
    )]
    Exportable {
        /// The role of the key.
        role: Role,
        /// Whether the store removed the refused key. A store that never
        /// kept the key answers `true`.
        removed: bool,
    },
}

/// A key that a [`KeyStore`] holds. No method returns the private half.
pub trait HeldKey {
    /// The role the key is held under.
    fn role(&self) -> Role;

    /// The public half.
    fn public(&self) -> ProxyPublicKey;

    /// Whether the store lets the private half out. A release build of the
    /// proxy holds no exportable key (see [`custody`]).
    fn exportable(&self) -> bool;

    /// The build whose custody rule the proxy holds this key under. A store
    /// answers the build it runs in. A test key can answer
    /// [`Build::Release`] in a debug build, so a test on every host pins the
    /// rule of both builds. A key cannot answer its way out of the release
    /// rule: [`custody_build`] ignores [`Build::Debug`] in a release build.
    fn build(&self) -> Build {
        Build::CURRENT
    }

    /// The raw ECDH shared secret (the x-coordinate) with `peer`.
    /// [`seal::open_held`](crate::seal::open_held) opens a sealed value
    /// through it, so the private half stays in the store.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store refuses the key's use, and
    /// [`KeyError::Store`] when the store fails for another reason.
    fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError>;

    /// Uses the key once, so that a store which refuses the key refuses it
    /// at start, and not at the first request.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store refuses the key's use, and
    /// [`KeyError::Store`] when the store fails for another reason, as a
    /// locked keychain does.
    fn probe(&self) -> Result<(), KeyError>;
}

/// The kind of build the proxy runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    /// A build with debug assertions, as a developer runs it.
    Debug,
    /// A release build, as the proxy ships.
    Release,
}

impl Build {
    /// The build this binary is.
    pub const CURRENT: Self = if cfg!(debug_assertions) {
        Self::Debug
    } else {
        Self::Release
    };
}

/// The build whose custody rule holds `key`. A key can make the rule
/// stricter than the binary's own build, never weaker: a release build
/// applies the release rule to every key, whatever [`HeldKey::build`]
/// answers.
#[must_use]
pub fn custody_build<K: HeldKey + ?Sized>(key: &K) -> Build {
    match (Build::CURRENT, key.build()) {
        (Build::Debug, Build::Debug) => Build::Debug,
        _ => Build::Release,
    }
}

/// What the custody rule does with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The key is non-exportable, and the proxy holds it.
    Held,
    /// The key is exportable, and a debug build keeps it.
    KeptExportable,
    /// The key is exportable, and a release build refuses it.
    Refused,
}

/// The custody rule for `key` in `build` (BEP-014, BEP-059). The keychain's
/// generation, [`load`] for a stored sealing key, and the CA's key check all
/// take this one decision.
///
/// A release build refuses an exportable key. A debug build keeps it: the
/// macOS login keychain lets the program that made a key export it although
/// the key was asked for non-exportable, and the keychain that enforces it
/// needs an entitlement that only a Developer ID signature carries.
#[must_use]
pub fn custody<K: HeldKey + ?Sized>(key: &K, build: Build) -> Custody {
    match (key.exportable(), build) {
        (false, _) => Custody::Held,
        (true, Build::Debug) => Custody::KeptExportable,
        (true, Build::Release) => Custody::Refused,
    }
}

/// The refusal of a key that [`custody`] refuses where the keychain
/// generates a key.
///
/// # Errors
///
/// [`KeyError::Exportable`] when the build refuses `key` because the
/// keychain made it exportable.
pub fn keep_generated<K: HeldKey + ?Sized>(key: &K) -> Result<(), KeyError> {
    match custody(key, custody_build(key)) {
        Custody::Refused => Err(KeyError::Exportable {
            role: key.role(),
            removed: true,
        }),
        Custody::Held | Custody::KeptExportable => Ok(()),
    }
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

    /// Generates a new non-exportable key for `role` and holds it under the
    /// role's label.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not generate the key.
    fn generate(&self, role: Role) -> Result<Self::Key, KeyError> {
        self.generate_in(role, Slot::Held)
    }

    /// Generates a new non-exportable key for `role` and holds it in
    /// `slot`. A failed generation leaves no key in `slot`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not generate the key.
    fn generate_in(&self, role: Role, slot: Slot) -> Result<Self::Key, KeyError>;

    /// Removes every key the store holds for `role` under the role's label.
    /// Removing a role with no key is not an error.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not remove the key.
    fn remove(&self, role: Role) -> Result<(), KeyError> {
        self.remove_in(role, Slot::Held)
    }

    /// Removes every key the store holds for `role` in `slot`. Removing from
    /// an empty slot is not an error.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not remove the key.
    fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError>;

    /// Whether the store holds a key for `role` in `slot`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not answer.
    fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError>;

    /// The `kid` of the key the store holds for `role` in `slot`, or `None`
    /// when the slot is empty.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not answer, and
    /// [`KeyError::Refused`] when it holds the key and refuses it.
    fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError>;

    /// Moves the key for `role` from slot `from` to slot `to`. The store
    /// holds no key in `to` when this runs. A move out of an empty
    /// role's label moves nothing, and is not an error: a role can have no
    /// key yet. Every other move expects a key, so an empty [`Slot::New`]
    /// or [`Slot::Old`] is a failure.
    ///
    /// # Errors
    ///
    /// [`KeyError::Store`] when the store does not move the key, or when
    /// `from` is not the role's label and the store holds no key there. A key that
    /// did not move stays in `from`.
    fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError>;
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
    /// The store refused these keys, or no longer holds keys that the proxy
    /// published before.
    Unusable {
        /// The keys the store holds and refused.
        refused: Vec<Role>,
        /// The keys the published identity names and the store does not
        /// hold.
        missing: Vec<Role>,
    },
    /// The store holds a key that a release build refuses because the
    /// keychain made it exportable (BEP-014, BEP-059).
    Exportable(Role),
    /// The store did not generate a missing key.
    Store(KeyError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unusable { refused, missing } => {
                let mut lines = Vec::new();
                // BEP-060: the wording is fixed by the task's diagnostics line.
                for role in refused {
                    lines.push(format!(
                        "The keychain refused the proxy its {role} key. Run `bep --replace-key {role}` to make a new one; boxes created before then must be re-created."
                    ));
                }
                for role in missing {
                    lines.push(format!(
                        "The keychain no longer holds the proxy's {role} key. Run `bep --replace-key {role}` to make a new one. Boxes created before then must be re-created."
                    ));
                }
                f.write_str(&lines.join("\n"))
            }
            Self::Exportable(role) => write!(
                f,
                "The proxy did not start: the keychain holds the proxy's {role} key as exportable, and a release build does not use an exportable key. Run `bep --replace-key {role}` to make a new one. Boxes created before then must be re-created."
            ),
            Self::Store(err) => write!(f, "The proxy did not start: {err}."),
        }
    }
}

/// Loads the proxy's keys at start (BEP-059, BEP-060).
///
/// `published` holds the roles that the proxy's published identity names.
/// The proxy made a key for each of them before. A key the store holds is
/// used as it is. A key the store does not hold is generated only on a first
/// start: `published` does not name its role, and the store holds no key for
/// any role. A key the store holds and refuses, or a key the store lost, is
/// never replaced here. `load` does not know the `kid` of each published
/// key, so it never puts back an old key that a replacement left aside
/// alone. [`load_with`] does.
///
/// # Errors
///
/// [`StartError::Unusable`] with the role of each refused or lost key,
/// [`StartError::Exportable`] when a release build finds an exportable
/// sealing key, or [`StartError::Store`] when a missing key was not
/// generated.
pub fn load<S: KeyStore>(store: &S, published: &[Role]) -> Result<ProxyKeys<S::Key>, StartError> {
    load_with(store, |role| {
        if published.contains(&role) {
            PublishedKid::Unread
        } else {
            PublishedKid::Absent
        }
    })
}

/// Loads the proxy's keys at start, as [`load`] does. `published` gives,
/// for each role, the `kid` that the proxy's published identity names.
///
/// # Errors
///
/// As [`load`].
pub fn load_with<S: KeyStore>(
    store: &S,
    published: impl Fn(Role) -> PublishedKid,
) -> Result<ProxyKeys<S::Key>, StartError> {
    let mut refused = Vec::new();
    let mut missing = Vec::new();
    let mut found = Vec::new();
    let published_roles: Vec<Role> = Role::ALL
        .into_iter()
        .filter(|role| published(*role) != PublishedKid::Absent)
        .collect();
    for role in Role::ALL {
        // BEP-060: a replacement that stopped after the old key moved aside
        // leaves the label empty. The old key is still the one in use.
        let held = match store.find(role) {
            Ok(None) => match recover_interrupted(store, role, &published(role)) {
                Ok(true) => store.find(role),
                // A start removes no key, so an old key whose `kid` was not
                // compared stays aside, and the role is a lost key.
                Ok(false) | Err(Interrupted::Unread) => Ok(None),
                Err(Interrupted::Check(err) | Interrupted::Move(err)) => {
                    return Err(StartError::Store(err));
                }
            },
            held => held,
        };
        match held {
            Ok(Some(key)) => match key.probe() {
                // BEP-059: the CA refuses an exportable root or signing key.
                // The sealing key has no such site, so a release build
                // refuses it here when a debug build left it exportable.
                Ok(()) if role == Role::Sealing => {
                    if custody(&key, custody_build(&key)) == Custody::Refused {
                        return Err(StartError::Exportable(role));
                    }
                    found.push((role, Some(key)));
                }
                Ok(()) => found.push((role, Some(key))),
                Err(err @ KeyError::Refused { .. }) => {
                    tracing::error!(role = %role, error = %err, "the key store refused a proxy key");
                    refused.push(role);
                }
                // A locked store is not a refused key, and the replacement
                // advice would delete a healthy key.
                Err(err @ (KeyError::Store { .. } | KeyError::Exportable { .. })) => {
                    return Err(StartError::Store(err));
                }
            },
            Ok(None) if published_roles.contains(&role) => {
                tracing::error!(role = %role, "the key store lost a published proxy key");
                missing.push(role);
            }
            Ok(None) => found.push((role, None)),
            Err(err @ KeyError::Refused { .. }) => {
                tracing::error!(role = %role, error = %err, "the key store refused a proxy key");
                refused.push(role);
            }
            Err(err @ (KeyError::Store { .. } | KeyError::Exportable { .. })) => {
                return Err(StartError::Store(err));
            }
        }
    }
    // BEP-060: a first start finds no key at all. When the store holds a key
    // for another role, a key it does not hold was made before and lost,
    // whatever the published identity says. The identity file can be
    // absent, at another path, or written again without the role.
    let holds_any = !refused.is_empty() || found.iter().any(|(_, key)| key.is_some());
    if holds_any {
        for (role, key) in &found {
            if key.is_none() && !published_roles.contains(role) {
                tracing::error!(role = %role, "the key store lost a proxy key that it made before");
                missing.push(*role);
            }
        }
        missing.sort();
    }
    if !refused.is_empty() || !missing.is_empty() {
        return Err(StartError::Unusable { refused, missing });
    }
    // Generate only after every role is known to be usable, so a start that
    // refuses leaves the store as it was.
    let mut keys = Vec::with_capacity(found.len());
    let mut generated = Vec::new();
    for (role, key) in found {
        let key = match key {
            Some(key) => key,
            None => match store.generate(role) {
                Ok(key) => {
                    tracing::info!(role = %role, fingerprint = %key.public().kid(), "generated a proxy key");
                    generated.push(role);
                    key
                }
                Err(err) => {
                    roll_back(store, &generated);
                    return Err(StartError::Store(err));
                }
            },
        };
        keys.push(key);
    }
    for key in &keys {
        // BEP-014, BEP-059: once for each role at each start of a debug
        // build. A release build refuses an exportable key where the keychain
        // generates it, at load for a stored sealing key, and at the CA for
        // the root and signing keys.
        if custody(key, custody_build(key)) == Custody::KeptExportable {
            let role = key.role();
            tracing::warn!(
                role = %role,
                "kept the proxy's {role} key although the keychain made it exportable: this is a debug build, and a release build refuses it"
            );
        }
    }
    let mut keys = keys.into_iter();
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
    /// The store did not move the old key out of the role's label, so the
    /// old key is still in use.
    #[error("{0}")]
    Remove(KeyError),
    /// No new key was generated, so the old key is still in use.
    #[error("no new key was made, so the old key is still in use: {0}")]
    Generate(KeyError),
    /// A new key was made, and the build refused it because the keychain
    /// made it exportable. `held` says whether the role's label held a key
    /// on entry. That key is then still in use.
    #[error("{refused}. {}", held_text(*.held))]
    Exportable {
        /// The refusal.
        refused: KeyError,
        /// Whether the role's label held a key on entry.
        held: bool,
    },
    /// The new key did not take the role's label. It was removed, and the
    /// old key is still in use.
    #[error("the new key did not take the old key's place, so the old key is still in use: {0}")]
    Move(KeyError),
    /// The new key did not take the role's label, and the old key did not
    /// return to it. The store holds no key under the role's label.
    #[error(
        "the new key did not take the old key's place: {moved}. The old key was not put back: {restored}. The store holds no key for this role now."
    )]
    Restore {
        /// Why the new key did not move.
        moved: KeyError,
        /// Why the old key did not move back.
        restored: KeyError,
    },
    /// An earlier replacement stopped after the old key moved aside, and
    /// the old key did not move back to the role's label. The store holds
    /// no key under the role's label.
    #[error(
        "the old key that an earlier replacement moved aside was not put back: {0}. The store holds no key for this role now."
    )]
    Recover(KeyError),
    /// The role's label held no key, and the store did not say whether an
    /// earlier replacement left keys aside. Nothing was changed. The store
    /// holds no key under the role's label.
    #[error(
        "the store did not say whether an earlier replacement left keys aside: {0}. The store holds no key for this role now."
    )]
    Check(KeyError),
    /// The role's label held no key, and no new key was generated. The
    /// store holds no key under the role's label.
    #[error("no new key was made, and the store holds no key for this role: {0}")]
    NoKey(KeyError),
    /// The role's label held no key, and the new key did not take it. The
    /// new key was removed. The store holds no key under the role's label.
    #[error(
        "the new key did not take the role's label: {0}. The store holds no key for this role now."
    )]
    MoveNoKey(KeyError),
    /// The role's label held no key, an earlier replacement left a key
    /// aside, and the published identity did not give the `kid` to compare
    /// it with. Nothing was changed. The store holds no key under the
    /// role's label.
    #[error(
        "an earlier replacement left a key aside, and the published identity did not say whether it is the key in use. The store holds no key for this role now."
    )]
    Unread,
    /// The role's label held no key, and the store did not remove a key
    /// that an earlier replacement left aside, or did not move the label's
    /// empty slot aside. The store holds no key under the role's label.
    #[error("{0}. The store holds no key for this role now.")]
    RemoveNoKey(KeyError),
}

/// What a [`ReplaceError`] says of the key under the role's label.
fn held_text(held: bool) -> &'static str {
    if held {
        "The old key is still in use"
    } else {
        "The store holds no key for this role"
    }
}

/// What the proxy's published identity file names for a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedKid {
    /// No identity file names a key for the role.
    Absent,
    /// The identity file names the key with this `kid`.
    Kid(String),
    /// The identity file was not read, or names a key for the role that
    /// was not read.
    Unread,
}

/// Removes the keys that a failed first start generated. The next start
/// then finds no key, and is a first start again. Without this, it finds
/// some roles and not others, and refuses them as lost keys.
fn roll_back<S: KeyStore>(store: &S, generated: &[Role]) {
    for role in generated {
        match store.remove(*role) {
            Ok(()) => {
                tracing::warn!(role = %role, "removed a proxy key that a failed first start generated")
            }
            Err(err) => {
                tracing::error!(role = %role, error = %err, "did not remove a proxy key that a failed first start generated")
            }
        }
    }
}

/// A key that [`replace_outcome`] made and moved to the role's label.
#[derive(Debug)]
pub struct Replaced<K> {
    /// The new key, which the proxy now uses.
    pub key: K,
    /// Why the store did not remove the old key, when it did not. The old
    /// key then stays under the [`Slot::Old`] label. The proxy never loads
    /// it, and the next replacement removes it.
    pub old_kept: Option<KeyError>,
}

/// Replaces the key held for `role`, as [`replace_outcome`] does with no
/// identity file that names a key for `role`, and returns only the new key.
///
/// # Errors
///
/// As [`replace_outcome`].
pub fn replace<S: KeyStore>(store: &S, role: Role) -> Result<S::Key, ReplaceError> {
    replace_outcome(store, role, &PublishedKid::Absent).map(|replaced| replaced.key)
}

/// Replaces the key held for `role`: the operator's command (BEP-060).
///
/// The store holds one key under a role's label. So the new key is
/// generated in [`Slot::New`], beside the old key. The old key then moves
/// to [`Slot::Old`], the new key moves to the role's label, and the old key
/// is removed. After `Ok`, the proxy loads only the new key, so it opens no
/// value sealed to an old sealing key. If the store does not remove the old
/// key, [`Replaced::old_kept`] says why. The old key then stays under the
/// [`Slot::Old`] label, where the proxy never loads it, and the next
/// replacement removes it.
///
/// Until the new key holds the role's label, every failure leaves the old
/// key under it, still in use: a failed generation, and a failed move,
/// which also removes the new key. A replacement that stopped after the
/// old key moved aside leaves it in [`Slot::Old`] with the role's label
/// empty. The next replacement first moves it back, so a failed generation
/// then keeps it in use. A failed move whose old key also does not move
/// back leaves that same state, so the new key stays in [`Slot::New`].
/// A failed move whose new key is also lost leaves the old key alone in
/// [`Slot::Old`]. `published` gives the `kid` that the identity file names,
/// so the next replacement puts that key back too. A key alone in
/// [`Slot::Old`] whose `kid` differs from the one the identity file names
/// is a replaced key, and the replacement removes it. When no identity
/// file names a key for the role, a start keeps that key aside and
/// refuses, and an explicit replacement removes it and makes a new key.
///
/// # Errors
///
/// [`ReplaceError::Generate`] when no new key was generated and the old key
/// is under the role's label, [`ReplaceError::NoKey`] when no new key was
/// generated and the role's label holds no key,
/// [`ReplaceError::Exportable`] when the build refused the new key,
/// [`ReplaceError::Remove`] when the old key did not move aside, and
/// [`ReplaceError::Move`] when the new key did not take its place. The old
/// key is still in use after each of these. [`ReplaceError::Restore`] when
/// the old key also did not move back, and [`ReplaceError::Recover`] when
/// the old key that an earlier replacement moved aside did not move back.
/// [`ReplaceError::Check`] when the role's label holds no key and the store
/// did not say whether an earlier replacement left keys aside, and
/// [`ReplaceError::Unread`] when a key alone in [`Slot::Old`] was not
/// compared with `published`. [`ReplaceError::NoKey`],
/// [`ReplaceError::RemoveNoKey`] and [`ReplaceError::MoveNoKey`] when the
/// role's label held no key and the generation, the cleanup or the move
/// failed.
pub fn replace_outcome<S: KeyStore>(
    store: &S,
    role: Role,
    published: &PublishedKid,
) -> Result<Replaced<S::Key>, ReplaceError> {
    // A replacement that stopped after the old key moved aside leaves the
    // role's label empty, the old key in `Slot::Old` and the new key in
    // `Slot::New`. Move the old key back before the cleanup below removes
    // it. A refused or unreadable key is still under the label, so only an
    // empty label takes the old key back. A key in `Slot::Old` with no key
    // in `Slot::New` is a replaced key that a finished replacement did not
    // remove. Values sealed to it are dead, so it never comes back.
    // A key in `Slot::Old` alone whose `kid` the identity file names is the
    // key in use: a failed move lost the new key, and the old key did not
    // move back. It comes back too.
    // A store that does not say whether `Slot::New` holds a key stops the
    // replacement, so the cleanup never removes an old key it can recover.
    let mut held = true;
    if matches!(store.find(role), Ok(None)) {
        held = match recover_interrupted(store, role, published) {
            Ok(recovered) => recovered,
            Err(Interrupted::Check(err)) => {
                tracing::error!(role = %role, error = %err, "did not check for the proxy keys that an earlier replacement left aside");
                return Err(ReplaceError::Check(err));
            }
            Err(Interrupted::Unread) => {
                tracing::error!(role = %role, "did not compare the proxy key that an earlier replacement left aside with the published identity, and kept it");
                return Err(ReplaceError::Unread);
            }
            Err(Interrupted::Move(err)) => {
                tracing::error!(role = %role, error = %err, "did not move back the proxy key that an earlier replacement moved aside");
                return Err(ReplaceError::Recover(err));
            }
        };
    }
    // A replacement that stopped part way can leave keys in the other slots.
    let removal = |err| {
        if held {
            ReplaceError::Remove(err)
        } else {
            ReplaceError::RemoveNoKey(err)
        }
    };
    for slot in [Slot::New, Slot::Old] {
        store.remove_in(role, slot).map_err(removal)?;
    }
    let key = match store.generate_in(role, Slot::New) {
        Ok(key) => key,
        Err(err @ KeyError::Exportable { .. }) => {
            if held {
                tracing::warn!(role = %role, error = %err, "refused the new proxy key and kept the old key");
            } else {
                tracing::warn!(role = %role, error = %err, "refused the new proxy key, and the store holds no key for the role");
            }
            return Err(ReplaceError::Exportable { refused: err, held });
        }
        Err(err) if !held => {
            tracing::warn!(role = %role, error = %err, "generated no new proxy key, and the store holds no key for the role");
            return Err(ReplaceError::NoKey(err));
        }
        Err(err) => {
            tracing::warn!(role = %role, error = %err, "generated no new proxy key and kept the old key");
            return Err(ReplaceError::Generate(err));
        }
    };
    if let Err(err) = store.relabel(role, Slot::Held, Slot::Old) {
        discard_new(store, role);
        if held {
            tracing::warn!(role = %role, error = %err, "did not move the old proxy key aside and kept the old key");
        } else {
            tracing::warn!(role = %role, error = %err, "did not move the role's empty label aside, and the store holds no key for the role");
        }
        return Err(removal(err));
    }
    if let Err(moved) = store.relabel(role, Slot::New, Slot::Held) {
        if !held {
            // No old key moved aside, so none moves back.
            discard_new(store, role);
            tracing::warn!(role = %role, error = %moved, "did not move the new proxy key in, and the store holds no key for the role");
            return Err(ReplaceError::MoveNoKey(moved));
        }
        // The new key goes only after the old key is back under the label.
        // With both side slots full, the next start or replacement moves
        // the old key back.
        if let Err(restored) = store.relabel(role, Slot::Old, Slot::Held) {
            tracing::error!(role = %role, error = %moved, restore_error = %restored, "did not move the new proxy key in or the old proxy key back");
            return Err(ReplaceError::Restore { moved, restored });
        }
        discard_new(store, role);
        tracing::warn!(role = %role, error = %moved, "did not move the new proxy key in and kept the old key");
        return Err(ReplaceError::Move(moved));
    }
    let old_kept = store.remove_in(role, Slot::Old).err();
    if let Some(err) = &old_kept {
        // The new key is in use. The next replacement removes the old one.
        tracing::warn!(role = %role, error = %err, "did not remove the old proxy key after its replacement");
    }
    tracing::warn!(role = %role, fingerprint = %key.public().kid(), "replaced a proxy key");
    Ok(Replaced { key, old_kept })
}

/// Moves back the old key of a replacement that stopped after the old key
/// moved aside, and removes that replacement's new key. Call it only when
/// the role's label holds no key. It moves the key in [`Slot::Old`] back
/// when [`Slot::New`] also holds a key. It also moves it back when it is
/// alone and its `kid` is the one `published` names: a failed move lost
/// the new key. A key in [`Slot::Old`] alone whose `kid` differs from the
/// one `published` names is a replaced key, and values sealed to it are
/// dead. When `published` names no key, it moves no key back.
///
/// Returns whether it moved a key back.
fn recover_interrupted<S: KeyStore>(
    store: &S,
    role: Role,
    published: &PublishedKid,
) -> Result<bool, Interrupted> {
    if !store
        .holds_in(role, Slot::Old)
        .map_err(Interrupted::Check)?
    {
        return Ok(false);
    }
    let new = store
        .holds_in(role, Slot::New)
        .map_err(Interrupted::Check)?;
    if !new {
        let named = match published {
            // A start keeps the key aside, and an explicit replacement
            // removes it: the operator asked for a new key.
            PublishedKid::Absent => return Ok(false),
            PublishedKid::Kid(kid) => kid,
            PublishedKid::Unread => return Err(Interrupted::Unread),
        };
        let old = store.kid_in(role, Slot::Old).map_err(Interrupted::Check)?;
        if old.as_deref() != Some(named.as_str()) {
            return Ok(false);
        }
    }
    store
        .relabel(role, Slot::Old, Slot::Held)
        .map_err(Interrupted::Move)?;
    tracing::warn!(role = %role, "moved back the old proxy key of a replacement that stopped part way");
    if new {
        discard_new(store, role);
    }
    Ok(true)
}

/// Why [`recover_interrupted`] stopped.
enum Interrupted {
    /// The store did not say whether a side slot holds a key, or did not
    /// give the `kid` of the key in [`Slot::Old`].
    Check(KeyError),
    /// [`Slot::Old`] alone holds a key, and the published `kid` to compare
    /// it with was not read.
    Unread,
    /// The old key did not move back.
    Move(KeyError),
}

/// The error for a move out of an empty slot. Only the move of the old key
/// aside finds an empty slot and succeeds: a role can have no key yet.
#[cfg(any(test, target_os = "macos"))]
fn missing_in(role: Role, slot: Slot) -> KeyError {
    let detail = match slot {
        Slot::New => "the store holds no new key to move in",
        Slot::Old => "the store holds no old key to move back",
        Slot::Held => "the store holds no key to move aside",
    };
    KeyError::Store {
        role,
        detail: detail.to_owned(),
    }
}

/// Removes the new key that a failed [`replace`] generated.
fn discard_new<S: KeyStore>(store: &S, role: Role) {
    if let Err(err) = store.remove_in(role, Slot::New) {
        tracing::error!(role = %role, error = %err, "did not remove the new proxy key of a failed replacement");
    }
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

/// The macOS keychain as a [`KeyStore`]: the Secure Enclave in a release
/// build, the login keychain in a debug build.
#[cfg(target_os = "macos")]
mod keychain {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::error::CFErrorRef;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, SecKey};
    use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccessGroup, kSecAttrIsPermanent, kSecAttrKeyClass,
        kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs, kSecPublicKeyAttrs,
        kSecUseDataProtectionKeychain,
    };
    use zeroize::Zeroizing;

    use super::{HeldKey, KeyError, KeyStore, Role, Slot, missing_in};
    use crate::seal::ProxyPublicKey;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        // `security-framework-sys` does not declare this attribute.
        static kSecAttrIsExtractable: CFStringRef;
        static kSecClass: CFStringRef;
        static kSecClassKey: CFStringRef;
        fn SecItemUpdate(
            query: core_foundation::dictionary::CFDictionaryRef,
            attributes_to_update: core_foundation::dictionary::CFDictionaryRef,
        ) -> i32;
    }

    /// The search codes that mean the keychain denies this program the key:
    /// `errSecAuthFailed`, `errSecNoAccessForItem` and `errSecUserCanceled`.
    const DENIED: [i32; 3] = [-25293, -25243, -128];

    /// `errSecMissingEntitlement`: this program is not signed with the
    /// keychain access group that [`ACCESS_GROUP`] names.
    const MISSING_ENTITLEMENT: i32 = -34018;

    /// Whether this build holds its keys in the Secure Enclave (#2812). A
    /// release build does. A debug build keeps the login keychain, because
    /// only the signed `bep.app` bundle holds the entitlement the
    /// data-protection keychain asks for, and a debug build keeps an
    /// exportable key with a warning (T111, #2785).
    const SECURE_ENCLAVE: bool = !cfg!(debug_assertions);

    /// The keychain access group a release build's keys live in. The
    /// `keychain-access-groups` entitlement of `bep.app`
    /// (`packaging/macos/bep/bep.entitlements`) names it, and the bundle's
    /// provisioning profile authorises it for team `3G47C5HY64`.
    pub const ACCESS_GROUP: &str = "3G47C5HY64.dev.minimal.bep";

    /// The keychain that holds the proxy's keys: the Secure Enclave and the
    /// data-protection keychain in a release build, the login keychain in a
    /// debug build.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Keychain;

    /// A search for the proxy's private keys in this build's keychain.
    fn private_keys(label: &str) -> ItemSearchOptions {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label);
        if SECURE_ENCLAVE {
            search.ignore_legacy_keychains().access_group(ACCESS_GROUP);
        }
        search
    }

    /// A store error, with plain advice when the keychain refused this
    /// program the entitlement a release build needs.
    fn store_error(role: Role, err: &security_framework::base::Error) -> KeyError {
        let detail = if err.code() == MISSING_ENTITLEMENT {
            format!(
                "this bep is not signed with the keychain entitlement a release build needs ({err}). Run the bep that a Minimal release installs"
            )
        } else {
            err.to_string()
        };
        KeyError::Store { role, detail }
    }

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

    /// Classifies an error from a use of a key. Only a code in [`DENIED`] is
    /// a refused key. Any other code is a store failure, so a locked keychain
    /// never gets the advice to replace a healthy key.
    fn use_error(role: Role, err: &core_foundation::error::CFError) -> KeyError {
        let denied = i32::try_from(err.code()).is_ok_and(|code| DENIED.contains(&code));
        if denied {
            refused(role, err)
        } else {
            KeyError::Store {
                role,
                detail: err.to_string(),
            }
        }
    }

    impl KeychainKey {
        fn new(role: Role, key: SecKey) -> Result<Self, KeyError> {
            let public = key
                .public_key()
                .and_then(|public| public.external_representation())
                .and_then(|bytes| ProxyPublicKey::from_sec1_bytes(&bytes))
                .ok_or_else(|| refused(role, "the key has no P-256 public half"))?;
            Ok(Self { role, key, public })
        }
    }

    // #2440: the root and signing CA keys sign certificates in the keychain,
    // so the private half never leaves it.
    impl crate::ca::CaKey for KeychainKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
                .map_err(|err| use_error(self.role, &err))
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
            let peer = public_sec_key(peer).map_err(|detail| KeyError::Store {
                role: self.role,
                detail,
            })?;
            self.key
                .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
                .map(Zeroizing::new)
                .map_err(|err| use_error(self.role, &err))
        }

        fn probe(&self) -> Result<(), KeyError> {
            match self.role {
                Role::Sealing => self.agree(&self.public).map(drop),
                Role::Root | Role::Signing => self
                    .key
                    .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, b"bep key probe")
                    .map(drop)
                    .map_err(|err| use_error(self.role, &err)),
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
            let found = private_keys(&role.label())
                .load_refs(true)
                .limit(1i64)
                .search();
            match found {
                Err(err) if err.code() == errSecItemNotFound => Ok(None),
                // Only a real access denial is a refused key. A locked
                // keychain or a session with no UI is not, and the
                // replacement advice would delete a healthy key.
                Err(err) if DENIED.contains(&err.code()) => Err(refused(role, err)),
                Err(err) => Err(store_error(role, &err)),
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

        fn generate_in(&self, role: Role, slot: Slot) -> Result<KeychainKey, KeyError> {
            let label = CFString::new(&role.slot_label(slot));
            // SAFETY: the Security framework exports these constants for the
            // life of the process.
            let (permanent, label_attr) =
                unsafe { (attr(kSecAttrIsPermanent), attr(kSecAttrLabel)) };
            let mut private = vec![
                (permanent, CFBoolean::true_value().into_CFType()),
                (label_attr, label.clone().into_CFType()),
            ];
            let mut placement = Vec::new();
            if SECURE_ENCLAVE {
                // BEP-014, BEP-059: the Secure Enclave never lets the private
                // half out. The key is usable once the Mac has been unlocked
                // after a restart, so boxes keep working while the screen is
                // locked, and it never moves to another Mac.
                let access = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                    kSecAccessControlPrivateKeyUsage,
                )
                .map_err(|err| store_error(role, &err))?;
                // SAFETY: the Security framework exports these constants for
                // the life of the process.
                let (access_control, group, token, enclave, data_protection) = unsafe {
                    (
                        attr(kSecAttrAccessControl),
                        attr(kSecAttrAccessGroup),
                        attr(kSecAttrTokenID),
                        attr(kSecAttrTokenIDSecureEnclave),
                        attr(kSecUseDataProtectionKeychain),
                    )
                };
                private.push((access_control, access.into_CFType()));
                private.push((group, CFString::new(ACCESS_GROUP).into_CFType()));
                placement.push((token, enclave.into_CFType()));
                placement.push((data_protection, CFBoolean::true_value().into_CFType()));
            } else {
                // BEP-014, BEP-059: the private half never leaves the
                // keychain.
                private.push((
                    attr(unsafe { kSecAttrIsExtractable }),
                    CFBoolean::false_value().into_CFType(),
                ));
            }
            let private = CFDictionary::from_CFType_pairs(&private);
            let public = CFDictionary::from_CFType_pairs(&[(
                attr(unsafe { kSecAttrIsPermanent }),
                CFBoolean::false_value().into_CFType(),
            )]);
            let mut attrs = vec![
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
            ];
            attrs.extend(placement);
            let attrs = CFDictionary::from_CFType_pairs(&attrs);
            #[allow(deprecated)]
            let key = SecKey::generate(attrs.to_untyped()).map_err(|err| {
                // Only the missing entitlement gets the plain advice. Every
                // other failure keeps the text the Security framework gave.
                match i32::try_from(err.code()) {
                    Ok(MISSING_ENTITLEMENT) => store_error(
                        role,
                        &security_framework::base::Error::from_code(MISSING_ENTITLEMENT),
                    ),
                    _ => KeyError::Store {
                        role,
                        detail: err.to_string(),
                    },
                }
            })?;
            let key = match KeychainKey::new(role, key) {
                Ok(key) => key,
                Err(err) => {
                    // The keychain stored the key. Remove it, so that a
                    // failed first start leaves no key behind.
                    drop(self.remove_in(role, slot));
                    return Err(err);
                }
            };
            if let Err(err) = super::keep_generated(&key) {
                // A release build never keeps a key the keychain lets out.
                if let Err(remove_err) = self.remove_in(role, slot) {
                    tracing::error!(role = %role, error = %remove_err, "did not remove a proxy key that the keychain made exportable");
                    return Err(KeyError::Exportable {
                        role,
                        removed: false,
                    });
                }
                return Err(err);
            }
            Ok(key)
        }

        fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
            // The private key is the only item the store keeps: the
            // public half is never made permanent.
            match private_keys(&role.slot_label(slot)).delete() {
                Err(err) if err.code() != errSecItemNotFound => Err(store_error(role, &err)),
                _ => Ok(()),
            }
        }

        fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
            let found = private_keys(&role.slot_label(slot))
                .load_refs(true)
                .limit(1i64)
                .search();
            match found {
                Err(err) if err.code() == errSecItemNotFound => Ok(false),
                // A key the keychain refuses is still a key in the slot.
                Err(err) if DENIED.contains(&err.code()) => Ok(true),
                Err(err) => Err(store_error(role, &err)),
                Ok(results) => Ok(!results.is_empty()),
            }
        }

        fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
            let found = private_keys(&role.slot_label(slot))
                .load_refs(true)
                .limit(1i64)
                .search();
            match found {
                Err(err) if err.code() == errSecItemNotFound => Ok(None),
                Err(err) if DENIED.contains(&err.code()) => Err(refused(role, err)),
                Err(err) => Err(store_error(role, &err)),
                Ok(results) => match results.into_iter().next() {
                    None => Ok(None),
                    Some(SearchResult::Ref(Reference::Key(key))) => {
                        KeychainKey::new(role, key).map(|key| Some(key.public().kid()))
                    }
                    Some(_) => Err(KeyError::Store {
                        role,
                        detail: "the keychain item under the key's label is not a key".to_owned(),
                    }),
                },
            }
        }

        fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
            // SAFETY: the Security framework exports these constants for the
            // life of the process.
            let class = unsafe { (attr(kSecClass), attr(kSecClassKey)) };
            let mut query = vec![
                (class.0.into_CFType(), class.1.into_CFType()),
                (
                    attr(unsafe { kSecAttrLabel }).into_CFType(),
                    CFString::new(&role.slot_label(from)).into_CFType(),
                ),
            ];
            if SECURE_ENCLAVE {
                // SAFETY: the Security framework exports these constants for
                // the life of the process.
                let (data_protection, group) = unsafe {
                    (
                        attr(kSecUseDataProtectionKeychain),
                        attr(kSecAttrAccessGroup),
                    )
                };
                query.push((
                    data_protection.into_CFType(),
                    CFBoolean::true_value().into_CFType(),
                ));
                query.push((
                    group.into_CFType(),
                    CFString::new(ACCESS_GROUP).into_CFType(),
                ));
            }
            let query = CFDictionary::from_CFType_pairs(&query);
            let update = CFDictionary::from_CFType_pairs(&[(
                attr(unsafe { kSecAttrLabel }),
                CFString::new(&role.slot_label(to)),
            )]);
            // SAFETY: both dictionaries are valid for the call, which keeps
            // no reference to either.
            let status =
                unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
            match status {
                0 => Ok(()),
                // A role can have no key to move aside. Every other move
                // expects a key, so its absence is a failure (see
                // `KeyStore::relabel`).
                status if status == errSecItemNotFound && from == Slot::Held => Ok(()),
                status if status == errSecItemNotFound => Err(missing_in(role, from)),
                status => Err(store_error(
                    role,
                    &security_framework::base::Error::from_code(status),
                )),
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

    use super::{HeldKey, KeyError, KeyStore, Role, Slot};
    use crate::seal::{self, Binding, OpenError, Opened, ProxyPublicKey};

    #[derive(Default)]
    struct Inner {
        keys: HashMap<(Role, Slot), SecretKey>,
        refused: HashSet<(Role, Slot)>,
        generated: usize,
        broken: bool,
        no_generation: bool,
        no_generation_of: Option<Role>,
        no_move_in: bool,
        lose_new: bool,
        no_old_removal: bool,
        no_move_back: bool,
        no_check: bool,
        locked_use: bool,
    }

    #[derive(Default)]
    pub(crate) struct MemoryStore(Mutex<Inner>);

    pub(crate) struct MemoryKey {
        role: Role,
        secret: SecretKey,
        refused: bool,
        locked: bool,
    }

    impl MemoryStore {
        pub(crate) fn refuse(&self, role: Role) {
            self.0.lock().unwrap().refused.insert((role, Slot::Held));
        }

        /// Makes the store fail every search and generation, as a locked
        /// keychain does.
        pub(crate) fn break_store(&self) {
            self.0.lock().unwrap().broken = true;
        }

        /// Makes every later generation fail, while searches still work.
        pub(crate) fn fail_generation(&self) {
            self.0.lock().unwrap().no_generation = true;
        }

        /// Makes every later generation for `role` fail, while the other
        /// roles still generate.
        pub(crate) fn fail_generation_of(&self, role: Role) {
            self.0.lock().unwrap().no_generation_of = Some(role);
        }

        /// Makes every later move of a new key to a role's label fail,
        /// while every other move still works.
        pub(crate) fn fail_move_in(&self) {
            self.0.lock().unwrap().no_move_in = true;
        }

        /// Makes every later generation return a key that the store does
        /// not keep, as a keychain item that went missing does.
        pub(crate) fn lose_new_keys(&self) {
            self.0.lock().unwrap().lose_new = true;
        }

        /// Makes the store keep the keys that later generations make.
        pub(crate) fn keep_new_keys(&self) {
            self.0.lock().unwrap().lose_new = false;
        }

        /// Makes every later removal of a key in [`Slot::Old`] fail. The
        /// removal of an empty [`Slot::Old`] still works.
        pub(crate) fn fail_old_removal(&self) {
            self.0.lock().unwrap().no_old_removal = true;
        }

        /// Makes every later move of a key from [`Slot::Old`] to a role's
        /// label fail, while every other move still works.
        pub(crate) fn fail_move_back(&self) {
            self.0.lock().unwrap().no_move_back = true;
        }

        /// Makes later moves from [`Slot::Old`] work again.
        pub(crate) fn clear_move_back_failure(&self) {
            self.0.lock().unwrap().no_move_back = false;
        }

        /// Makes every later check of a slot fail, while every other call
        /// still works.
        pub(crate) fn fail_checks(&self) {
            self.0.lock().unwrap().no_check = true;
        }

        /// Makes later checks of a slot work again.
        pub(crate) fn clear_check_failure(&self) {
            self.0.lock().unwrap().no_check = false;
        }

        /// The secret bytes of the key in `slot`, or `None` when the slot
        /// is empty.
        pub(crate) fn held_in(&self, role: Role, slot: Slot) -> Option<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .keys
                .get(&(role, slot))
                .map(|secret| secret.to_bytes().to_vec())
        }

        /// Lets every role generate again.
        pub(crate) fn clear_generation_failure(&self) {
            self.0.lock().unwrap().no_generation_of = None;
        }

        /// Makes every later use of a found key fail as a locked keychain
        /// does, while searches still work.
        pub(crate) fn lock_use(&self) {
            self.0.lock().unwrap().locked_use = true;
        }

        /// Stops refusing every key.
        pub(crate) fn clear_refusals(&self) {
            self.0.lock().unwrap().refused.clear();
        }

        pub(crate) fn generated(&self) -> usize {
            self.0.lock().unwrap().generated
        }

        /// The secret bytes, so a test can look for them in files.
        pub(crate) fn secret_bytes(&self, role: Role) -> Vec<u8> {
            self.0.lock().unwrap().keys[&(role, Slot::Held)]
                .to_bytes()
                .to_vec()
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
            seal::open_held(self, sealed, expected)
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
            if self.locked {
                return Err(broken(self.role));
            }
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

    impl crate::ca::CaKey for MemoryKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            use p256::ecdsa::signature::Signer as _;
            if self.locked {
                return Err(broken(self.role));
            }
            if self.refused {
                return Err(KeyError::Refused {
                    role: self.role,
                    detail: "refused".into(),
                });
            }
            let signature: p256::ecdsa::Signature =
                p256::ecdsa::SigningKey::from(&self.secret).sign(msg);
            Ok(signature.to_der().as_bytes().to_vec())
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
            Ok(inner.keys.get(&(role, Slot::Held)).map(|secret| MemoryKey {
                role,
                secret: secret.clone(),
                refused: inner.refused.contains(&(role, Slot::Held)),
                locked: inner.locked_use,
            }))
        }

        fn generate_in(&self, role: Role, slot: Slot) -> Result<MemoryKey, KeyError> {
            let inner = self.0.lock().unwrap();
            if inner.broken || inner.no_generation || inner.no_generation_of == Some(role) {
                return Err(broken(role));
            }
            drop(inner);
            let secret = loop {
                let mut bytes = Zeroizing::new([0u8; 32]);
                getrandom::fill(bytes.as_mut()).expect("random source");
                if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
                    break secret;
                }
            };
            let mut inner = self.0.lock().unwrap();
            inner.generated += 1;
            inner.refused.remove(&(role, slot));
            if !inner.lose_new {
                inner.keys.insert((role, slot), secret.clone());
            }
            Ok(MemoryKey {
                role,
                secret,
                refused: false,
                locked: false,
            })
        }

        fn remove_in(&self, role: Role, slot: Slot) -> Result<(), KeyError> {
            let mut inner = self.0.lock().unwrap();
            if inner.no_old_removal && slot == Slot::Old && inner.keys.contains_key(&(role, slot)) {
                return Err(broken(role));
            }
            inner.keys.remove(&(role, slot));
            inner.refused.remove(&(role, slot));
            Ok(())
        }

        fn holds_in(&self, role: Role, slot: Slot) -> Result<bool, KeyError> {
            let inner = self.0.lock().unwrap();
            if inner.broken || inner.no_check {
                return Err(broken(role));
            }
            Ok(inner.keys.contains_key(&(role, slot)))
        }

        fn kid_in(&self, role: Role, slot: Slot) -> Result<Option<String>, KeyError> {
            let inner = self.0.lock().unwrap();
            if inner.broken || inner.no_check {
                return Err(broken(role));
            }
            Ok(inner.keys.get(&(role, slot)).map(|secret| {
                ProxyPublicKey::from_sec1_bytes(&secret.public_key().to_sec1_bytes())
                    .expect("a P-256 public key")
                    .kid()
            }))
        }

        fn relabel(&self, role: Role, from: Slot, to: Slot) -> Result<(), KeyError> {
            let mut inner = self.0.lock().unwrap();
            if inner.broken
                || (inner.no_move_in && from == Slot::New && to == Slot::Held)
                || (inner.no_move_back && from == Slot::Old && to == Slot::Held)
            {
                return Err(broken(role));
            }
            match inner.keys.remove(&(role, from)) {
                Some(secret) => {
                    inner.keys.insert((role, to), secret);
                }
                None if from == Slot::Held => {}
                None => return Err(super::missing_in(role, from)),
            }
            if inner.refused.remove(&(role, from)) {
                inner.refused.insert((role, to));
            }
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
        let first = load(&store, &[]).unwrap();
        assert_eq!(store.generated(), 3);
        let kids: Vec<String> = Role::ALL
            .iter()
            .map(|role| first.get(*role).public().kid())
            .collect();
        drop(first);

        for _ in 0..3 {
            let again = load(&store, &Role::ALL).unwrap();
            let again_kids: Vec<String> = Role::ALL
                .iter()
                .map(|role| again.get(*role).public().kid())
                .collect();
            assert_eq!(again_kids, kids);
        }
        assert_eq!(store.generated(), 3, "a restart generated a key");

        // A refused key is not replaced on restart either.
        store.refuse(Role::Sealing);
        assert!(load(&store, &Role::ALL).is_err());
        assert_eq!(store.generated(), 3, "a refused key was regenerated");
    }

    // BEP-060
    #[test]
    fn refused_key_names_the_replacement_command() {
        let store = MemoryStore::default();
        drop(load(&store, &[]).unwrap());
        store.refuse(Role::Sealing);
        store.refuse(Role::Signing);

        let err = load(&store, &Role::ALL).unwrap_err();
        assert_eq!(
            err,
            StartError::Unusable {
                refused: vec![Role::Sealing, Role::Signing],
                missing: vec![],
            }
        );
        assert_eq!(
            err.to_string(),
            "The keychain refused the proxy its sealing key. Run `bep --replace-key sealing` to make a new one; boxes created before then must be re-created.\n\
             The keychain refused the proxy its signing key. Run `bep --replace-key signing` to make a new one; boxes created before then must be re-created."
        );

        // A replacement that makes no new key keeps the refused key, so the
        // start still names the command.
        store.fail_generation_of(Role::Sealing);
        assert!(matches!(
            replace(&store, Role::Sealing),
            Err(ReplaceError::Generate(_))
        ));
        assert_eq!(load(&store, &Role::ALL).unwrap_err(), err);
        store.clear_generation_failure();

        // The named command is the way out.
        replace(&store, "sealing".parse().unwrap()).unwrap();
        replace(&store, "signing".parse().unwrap()).unwrap();
        assert!(load(&store, &Role::ALL).is_ok());
    }

    // BEP-060: a later start never makes a published key again.
    #[test]
    fn a_published_key_the_store_lost_refuses_the_start() {
        let store = MemoryStore::default();
        drop(load(&store, &[]).unwrap());
        store.remove(Role::Root).unwrap();
        store.refuse(Role::Signing);

        let err = load(&store, &Role::ALL).unwrap_err();
        assert_eq!(
            err,
            StartError::Unusable {
                refused: vec![Role::Signing],
                missing: vec![Role::Root],
            }
        );
        assert!(
            err.to_string()
                .contains("no longer holds the proxy's root key. Run `bep --replace-key root`"),
            "{err}"
        );
        assert_eq!(store.generated(), 3, "a lost key was made again");

        // The store holds the other keys, so a root key that the identity
        // does not name was lost too. It is never made again silently.
        store.clear_refusals();
        let err = load(&store, &[Role::Sealing]).unwrap_err();
        assert_eq!(
            err,
            StartError::Unusable {
                refused: vec![],
                missing: vec![Role::Root],
            }
        );
        assert_eq!(store.generated(), 3, "a lost key was made again");

        // With no identity file at all, the start refuses the same way.
        assert_eq!(load(&store, &[]).unwrap_err(), err);
        assert_eq!(store.generated(), 3, "a lost key was made again");
    }

    // BEP-060: a failed replacement and a deleted identity file do not make
    // the lost key again.
    #[test]
    fn a_lost_key_with_no_identity_file_refuses_the_start() {
        let store = MemoryStore::default();
        drop(load(&store, &[]).unwrap());
        store.remove(Role::Sealing).unwrap();
        store.fail_generation();
        assert!(matches!(
            replace(&store, Role::Sealing),
            Err(ReplaceError::NoKey(_))
        ));

        let err = load(&store, &[]).unwrap_err();
        assert_eq!(
            err,
            StartError::Unusable {
                refused: vec![],
                missing: vec![Role::Sealing],
            }
        );
        assert_eq!(store.generated(), 3);
    }

    // BEP-060: a new key that is gone before it takes the role's label is
    // a failed move, not a replacement, and the old key stays in use.
    #[test]
    fn a_missing_new_key_keeps_the_old_key() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.lose_new_keys();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Move(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old));
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: a new key that does not take the role's label is removed,
    // and the old key stays in use.
    #[test]
    fn a_failed_move_keeps_the_old_key() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.fail_move_in();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Move(_)), "{err}");
        assert!(
            err.to_string().contains("the old key is still in use"),
            "{err}"
        );
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old));
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: a replacement that stopped after the old key moved aside
    // leaves the label empty. The next replacement takes the old key back,
    // so a failed generation keeps it in use.
    #[test]
    fn an_interrupted_replacement_keeps_the_old_key() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.generate_in(Role::Sealing, Slot::New).unwrap();
        store.relabel(Role::Sealing, Slot::Held, Slot::Old).unwrap();
        store.fail_generation();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Generate(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old));
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: a start after a replacement that stopped between its two
    // moves uses the old key, and does not refuse the role as lost. A later
    // replacement keeps the old key in use until its own move.
    #[test]
    fn a_start_after_an_interrupted_replacement_uses_the_old_key() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.generate_in(Role::Sealing, Slot::New).unwrap();
        store.relabel(Role::Sealing, Slot::Held, Slot::Old).unwrap();
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);

        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old.clone()));
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);

        store.fail_generation();
        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Generate(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old));
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: only the move of the old key aside accepts an empty slot. A
    // move back out of an empty `Slot::Old` is a failure.
    #[test]
    fn a_move_back_of_no_key_fails() {
        let store = MemoryStore::default();
        store
            .relabel(Role::Sealing, Slot::Held, Slot::Old)
            .expect("a role can have no key to move aside");
        assert!(store.relabel(Role::Sealing, Slot::Old, Slot::Held).is_err());
        assert!(store.relabel(Role::Sealing, Slot::New, Slot::Held).is_err());
    }

    // BEP-060, Gatehouse §6.10: a replaced key that a finished replacement
    // did not remove stays in `Slot::Old` with no new key beside it. Values
    // sealed to it are dead, so a later replacement whose identity file
    // names another key removes it and never puts it back under the label.
    #[test]
    fn a_replaced_key_left_aside_is_not_put_back() {
        let store = MemoryStore::default();
        load(&store, &[]).unwrap();
        store.relabel(Role::Sealing, Slot::Held, Slot::Old).unwrap();
        store.fail_generation();

        let other = PublishedKid::Kid("another".into());
        let err = replace_outcome(&store, Role::Sealing, &other).unwrap_err();
        assert!(matches!(err, ReplaceError::NoKey(_)), "{err}");
        assert!(!err.to_string().contains("still in use"), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
    }

    // BEP-060: a new key that does not take the label, beside an old key
    // that does not move back, stays in `Slot::New`. The next replacement
    // then puts the old key back, so no key of the role is lost.
    #[test]
    fn a_failed_move_back_keeps_both_keys_for_the_next_replacement() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.fail_move_in();
        store.fail_move_back();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Restore { .. }), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), Some(old.clone()));
        assert!(store.held_in(Role::Sealing, Slot::New).is_some());

        store.clear_move_back_failure();
        let err = replace_outcome(&store, Role::Sealing, &PublishedKid::Absent).unwrap_err();
        assert!(matches!(err, ReplaceError::Move(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), Some(old));
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: a store that does not say whether an earlier replacement
    // left keys aside is reported as that, and nothing is removed.
    #[test]
    fn an_unanswered_check_for_keys_left_aside_is_reported() {
        let store = MemoryStore::default();
        load(&store, &[]).unwrap();
        let old = store.secret_bytes(Role::Sealing);
        store.generate_in(Role::Sealing, Slot::New).unwrap();
        store.relabel(Role::Sealing, Slot::Held, Slot::Old).unwrap();
        store.fail_checks();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Check(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), Some(old));
        assert!(store.held_in(Role::Sealing, Slot::New).is_some());
    }

    // BEP-060: an old key that an earlier replacement moved aside and that
    // does not move back is reported as no key in use, not as a kept key.
    #[test]
    fn an_interrupted_replacement_not_put_back_is_reported() {
        let store = MemoryStore::default();
        load(&store, &[]).unwrap();
        let old = store.secret_bytes(Role::Sealing);
        store.generate_in(Role::Sealing, Slot::New).unwrap();
        let new = store.held_in(Role::Sealing, Slot::New);
        assert!(new.is_some());
        store.relabel(Role::Sealing, Slot::Held, Slot::Old).unwrap();
        store.fail_move_back();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Recover(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), Some(old));
        assert_eq!(store.held_in(Role::Sealing, Slot::New), new);
    }

    /// A store whose replacement lost its new key and did not move the old
    /// key back: the label is empty, and the old key is alone in
    /// [`Slot::Old`]. Gives the store and the old key's `kid`.
    fn old_key_left_alone() -> (MemoryStore, String) {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        store.lose_new_keys();
        store.fail_move_back();
        let err =
            replace_outcome(&store, Role::Sealing, &PublishedKid::Kid(kid.clone())).unwrap_err();
        assert!(matches!(err, ReplaceError::Restore { .. }), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
        assert!(store.held_in(Role::Sealing, Slot::Old).is_some());
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        store.clear_move_back_failure();
        (store, kid)
    }

    // BEP-060: an old key left alone aside whose `kid` the identity file
    // names is the key in use. The next replacement puts it back before
    // its cleanup, so a failed move keeps it in use.
    #[test]
    fn an_old_key_the_identity_names_comes_back_at_the_next_replacement() {
        let (store, kid) = old_key_left_alone();
        let published = |role| {
            if role == Role::Sealing {
                PublishedKid::Kid(kid.clone())
            } else {
                PublishedKid::Absent
            }
        };

        let err = replace_outcome(&store, Role::Sealing, &published(Role::Sealing)).unwrap_err();
        assert!(matches!(err, ReplaceError::Move(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        let keys = load_with(&store, published).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // BEP-060: a start finds the old key left alone aside under the label
    // when the identity file names its `kid`.
    #[test]
    fn an_old_key_the_identity_names_comes_back_at_the_next_start() {
        let (store, kid) = old_key_left_alone();
        let keys = load_with(&store, |_| PublishedKid::Kid(kid.clone())).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
    }

    // BEP-060: an old key left alone aside is compared with the identity
    // file. A key it does not name is a replaced key, and is removed. A key
    // that is not compared stays, and nothing is removed.
    #[test]
    fn an_old_key_left_alone_is_removed_only_when_the_identity_names_another() {
        let (store, _kid) = old_key_left_alone();
        let old = store.held_in(Role::Sealing, Slot::Old);
        let err = replace_outcome(&store, Role::Sealing, &PublishedKid::Unread).unwrap_err();
        assert_eq!(err, ReplaceError::Unread);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), old);

        store.fail_checks();
        let other = PublishedKid::Kid("another".into());
        let err = replace_outcome(&store, Role::Sealing, &other).unwrap_err();
        assert!(matches!(err, ReplaceError::Check(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), old);
        store.clear_check_failure();

        store.fail_generation();
        let err = replace_outcome(&store, Role::Sealing, &other).unwrap_err();
        assert!(matches!(err, ReplaceError::NoKey(_)), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
    }

    // BEP-060: an old key left alone aside, with no identity file that names
    // a key for the role, stays aside at a start, and the start refuses. An
    // explicit replacement removes it and makes a new key.
    #[test]
    fn an_old_key_left_alone_with_no_identity_is_kept_until_a_replacement() {
        let (store, _kid) = old_key_left_alone();
        let old = store.held_in(Role::Sealing, Slot::Old);
        assert!(old.is_some());

        let Err(StartError::Unusable { missing, .. }) = load_with(&store, |_| PublishedKid::Absent)
        else {
            panic!("the start did not refuse the lost sealing key");
        };
        assert_eq!(missing, vec![Role::Sealing]);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), old);
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);

        store.keep_new_keys();
        let replaced = replace_outcome(&store, Role::Sealing, &PublishedKid::Absent).unwrap();
        assert!(replaced.old_kept.is_none());
        let held = store.held_in(Role::Sealing, Slot::Held);
        assert!(held.is_some());
        assert_ne!(held, old);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
    }

    // BEP-060: a failed cleanup for a role whose label held no key says that
    // the store holds no key, not that an old key is in use.
    #[test]
    fn a_failed_cleanup_with_no_key_held_reports_no_key() {
        let (store, _kid) = old_key_left_alone();
        store.fail_old_removal();
        let other = PublishedKid::Kid("another".into());
        let err = replace_outcome(&store, Role::Sealing, &other).unwrap_err();
        assert!(matches!(err, ReplaceError::RemoveNoKey(_)), "{err}");
        assert!(!err.to_string().contains("still in use"), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
    }

    // BEP-060: a failed move for a role whose label held no key moves no
    // old key back, removes the new key, and says the store holds no key.
    #[test]
    fn a_failed_move_with_no_key_held_reports_no_key() {
        let store = MemoryStore::default();
        store.fail_move_in();
        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::MoveNoKey(_)), "{err}");
        assert!(!err.to_string().contains("put back"), "{err}");
        assert_eq!(store.held_in(Role::Sealing, Slot::Held), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        assert_eq!(store.held_in(Role::Sealing, Slot::Old), None);
    }

    // BEP-060: an old key that the store does not remove is reported, not
    // hidden behind a plain success.
    #[test]
    fn an_old_key_not_removed_is_reported() {
        let store = MemoryStore::default();
        let old = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        store.fail_old_removal();

        let replaced = replace_outcome(&store, Role::Sealing, &PublishedKid::Absent).unwrap();
        assert!(replaced.old_kept.is_some());
        assert!(store.held_in(Role::Sealing, Slot::Old).is_some());
        let keys = load(&store, &Role::ALL).unwrap();
        let new = keys.get(Role::Sealing).public().kid();
        assert_eq!(new, replaced.key.public().kid());
        assert_ne!(new, old);
    }

    // BEP-060: a replacement holds one key under the role's label, and a new
    // one.
    #[test]
    fn a_replacement_leaves_only_the_new_key() {
        let store = MemoryStore::default();
        let old = load(&store, &[]).unwrap().get(Role::Root).public().kid();
        let new = replace(&store, Role::Root).unwrap().public().kid();
        assert_ne!(new, old);
        assert!(store.held_in(Role::Root, Slot::New).is_none());
        assert!(store.held_in(Role::Root, Slot::Old).is_none());
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Root).public().kid(), new);
    }

    #[test]
    fn a_store_failure_is_not_a_refused_key() {
        let store = MemoryStore::default();
        drop(load(&store, &[]).unwrap());
        store.break_store();

        let err = load(&store, &Role::ALL).unwrap_err();
        assert!(matches!(err, StartError::Store(_)), "{err}");
        assert!(!err.to_string().contains("--replace-key"), "{err}");
        assert_eq!(store.generated(), 3);
    }

    // BEP-060: a key that fails its probe because the store is locked is
    // not a refused key, so the start gives no replacement advice.
    #[test]
    fn a_locked_store_at_probe_is_not_a_refused_key() {
        let store = MemoryStore::default();
        drop(load(&store, &[]).unwrap());
        store.lock_use();

        let err = load(&store, &Role::ALL).unwrap_err();
        assert!(matches!(err, StartError::Store(_)), "{err}");
        assert!(!err.to_string().contains("--replace-key"), "{err}");
        assert_eq!(store.generated(), 3);
    }

    // BEP-060: a first start that generates one key and fails on the next
    // leaves no key, so the next start is a first start and not a lost key.
    #[test]
    fn keys_never_regenerated_on_restart_after_a_failed_first_start() {
        let store = MemoryStore::default();
        store.fail_generation_of(Role::Root);
        let err = load(&store, &[]).unwrap_err();
        assert!(matches!(err, StartError::Store(_)), "{err}");
        for role in Role::ALL {
            assert!(store.find(role).unwrap().is_none(), "{role}");
        }

        store.clear_generation_failure();
        let keys = load(&store, &[]).unwrap();
        for role in Role::ALL {
            assert_eq!(keys.get(role).role(), role);
        }
    }

    // BEP-060: a replacement that makes no new key keeps the old key in
    // use, and says so.
    #[test]
    fn a_failed_generation_keeps_the_old_key() {
        let store = MemoryStore::default();
        let kid = load(&store, &[]).unwrap().get(Role::Sealing).public().kid();
        let old = store.secret_bytes(Role::Sealing);
        store.fail_generation();

        let err = replace(&store, Role::Sealing).unwrap_err();
        assert!(matches!(err, ReplaceError::Generate(_)), "{err}");
        assert_eq!(
            err.to_string(),
            "no new key was made, so the old key is still in use: the key store failed for the sealing key: the keychain is locked"
        );
        assert_eq!(store.secret_bytes(Role::Sealing), old);
        assert_eq!(store.held_in(Role::Sealing, Slot::New), None);
        assert_eq!(store.generated(), 3);
        let keys = load(&store, &Role::ALL).unwrap();
        assert_eq!(keys.get(Role::Sealing).public().kid(), kid);
    }

    // #2440, BEP-013: the store-held root key signs the root certificate,
    // and the signing CA key signs below it. A refused root key issues none.
    #[test]
    fn keychain_root_key_signs_the_root_certificate() {
        use std::time::{Duration, SystemTime};

        use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
        use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

        use crate::ca::{Ca, CaError, Union, issue_root};
        use crate::module::GITHUB;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        let union = Union::new(&[GITHUB], [""; 0]);
        let root = issue_root(&keys.root, union.clone(), now).unwrap();
        let ca = Ca::with_root(&keys.root, &keys.signing, root.clone(), now).unwrap();
        let leaf = ca.issue_leaf("api.github.com", now).unwrap();

        let anchor = CertificateDer::from(root.der().to_vec());
        let anchors = [anchor_from_trusted_cert(&anchor).unwrap()];
        let ee = EndEntityCert::try_from(&leaf.chain[0]).unwrap();
        let time = UnixTime::since_unix_epoch(now.duration_since(SystemTime::UNIX_EPOCH).unwrap());
        ee.verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &anchors,
            &leaf.chain[1..],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .expect("the chain validates against the root the root key signed");
        ee.verify_is_valid_for_subject_name(&ServerName::try_from("api.github.com").unwrap())
            .unwrap();

        // A root key the store refuses issues no root, and says so by role.
        store.refuse(Role::Root);
        let refused = store.find(Role::Root).unwrap().unwrap();
        let err = issue_root(&refused, union, now).unwrap_err();
        assert!(
            matches!(
                err,
                CaError::Key(KeyError::Refused {
                    role: Role::Root,
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn role_names_round_trip() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
        }
        assert_eq!("ca".parse::<Role>(), Err(UnknownRole("ca".to_owned())));
    }
}
