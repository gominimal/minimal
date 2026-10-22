//! The proxy's published identity (BEP-072).
//!
//! BEP-072 also asks for the root certificate. This file publishes the root
//! CA's public key and fingerprint only. The proxy issues no certificate
//! yet. The self-signed, name-constrained root certificate is deferred to
//! <https://github.com/gominimal/minimal/issues/2437>, which adds it to this
//! file.
//!
//! At each start the proxy writes the public half and the fingerprint of
//! each of its keys to a file the operator's processes read. A mint seals
//! from that file alone: sealing is public-key work, so a mint never opens
//! the proxy's key store. The fingerprint is the `kid` a sealed context
//! binds.
//!
//! The file is JSON, one object per role:
//! `{"sealing": {"public": ..., "kid": ...}, "root": {...}, "signing": {...}}`.
//! `public` is the uncompressed SEC1 point in unpadded base64url. A role is
//! read only when it is used, and [`Identity::key`] refuses a role whose
//! entry is missing, does not parse as a P-256 key, or carries a `kid` that is
//! not the key's fingerprint.

use std::io;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::keys::{HeldKey, KeyStore, ProxyKeys, Role};
use crate::seal::{self, Context, MemberList, ProxyPublicKey, SealError};

/// One published key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKey {
    /// The uncompressed SEC1 point, in unpadded base64url.
    pub public: String,
    /// The key's fingerprint, as [`ProxyPublicKey::kid`] computes it.
    pub kid: String,
}

impl PublishedKey {
    fn of(key: &ProxyPublicKey) -> Self {
        Self {
            public: URL_SAFE_NO_PAD.encode(key.to_sec1_bytes()),
            kid: key.kid(),
        }
    }
}

/// The published identity: one entry per key role.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identity {
    /// The sealing key, which a mint seals to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<PublishedKey>,
    /// The root CA's public key. It is not the root certificate, which
    /// BEP-072 asks for. The issuance of that certificate is deferred to
    /// <https://github.com/gominimal/minimal/issues/2437>, which publishes
    /// it here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PublishedKey>,
    /// The signing CA key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<PublishedKey>,
}

/// Why a published identity was not used.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The entry for the role is missing or is not a key of that role.
    #[error(
        "The proxy's published identity has no usable {0} key. Start `bep` to publish it again."
    )]
    NotAKey(Role),
    /// Another user owns the file or can change it, so it can name a key
    /// that is not the proxy's.
    #[error(
        "The proxy's published identity at {0} can be changed by another user, so it is not used. Delete it, then start `bep` to publish it again."
    )]
    Writable(PathBuf),
    /// Other users can change the directory that holds the file, so they can
    /// put another file in its place.
    #[error(
        "Other users can change the directory {0}, so the proxy's published identity in it is not used. Give a file in a directory that only you can change, with `bep --identity <PATH>`."
    )]
    OpenDirectory(PathBuf),
    /// The file is not a published identity.
    #[error(
        "The proxy's published identity at {0} is not valid JSON. Delete it, then start `bep` to publish it again."
    )]
    Malformed(PathBuf),
    /// The file was not read or written.
    #[error("The proxy's published identity at {path} was not accessed: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// The value was not sealed.
    #[error("The value was not sealed: {0}")]
    Seal(#[from] SealError),
}

impl Identity {
    /// The identity of the proxy's loaded keys.
    pub fn of<K: HeldKey>(keys: &ProxyKeys<K>) -> Self {
        Self {
            sealing: Some(PublishedKey::of(&keys.sealing.public())),
            root: Some(PublishedKey::of(&keys.root.public())),
            signing: Some(PublishedKey::of(&keys.signing.public())),
        }
    }

    /// The identity to publish after `role` was replaced by `key`.
    ///
    /// The other roles come from the store when it gives their public half,
    /// and from `previous` when it does not. A role with neither source is
    /// left out, with a warning. The caller passes `None` only when no
    /// identity file exists, so the roles left out were never published. A replacement never needs the
    /// whole store to be usable, so a second refused key does not keep the
    /// old public key published (BEP-060).
    pub fn after_replacement<S: KeyStore>(
        store: &S,
        role: Role,
        key: &S::Key,
        previous: Option<&Self>,
    ) -> Self {
        let entry = |other: Role| {
            if other == role {
                return Some(PublishedKey::of(&key.public()));
            }
            let entry = match store.find(other) {
                Ok(Some(held)) => Some(PublishedKey::of(&held.public())),
                _ => previous.and_then(|previous| previous.entry(other).cloned()),
            };
            if entry.is_none() {
                // The next start treats this role as a first start.
                tracing::warn!(role = %other, "no public key is known for a proxy key role, so the identity does not name it");
            }
            entry
        };
        Self {
            sealing: entry(Role::Sealing),
            root: entry(Role::Root),
            signing: entry(Role::Signing),
        }
    }

    /// The roles this identity has an entry for. The proxy made a key for
    /// each of them before.
    #[must_use]
    pub fn roles(&self) -> Vec<Role> {
        Role::ALL
            .into_iter()
            .filter(|role| self.entry(*role).is_some())
            .collect()
    }

    fn entry(&self, role: Role) -> Option<&PublishedKey> {
        match role {
            Role::Sealing => self.sealing.as_ref(),
            Role::Root => self.root.as_ref(),
            Role::Signing => self.signing.as_ref(),
        }
    }

    /// The published public key for `role`.
    ///
    /// # Errors
    ///
    /// [`PublishError::NotAKey`] naming `role` when the entry is missing, is
    /// not a P-256 public key, or carries a `kid` that is not its
    /// fingerprint.
    pub fn key(&self, role: Role) -> Result<ProxyPublicKey, PublishError> {
        let entry = self.entry(role).ok_or(PublishError::NotAKey(role))?;
        let key = URL_SAFE_NO_PAD
            .decode(&entry.public)
            .ok()
            .and_then(|bytes| ProxyPublicKey::from_sec1_bytes(&bytes))
            .ok_or(PublishError::NotAKey(role))?;
        if key.kid() != entry.kid {
            return Err(PublishError::NotAKey(role));
        }
        Ok(key)
    }

    /// Writes the identity to `path`, replacing the file whole.
    ///
    /// The file decides which key a mint seals to, so only its owner can
    /// change it. A new directory is created mode 0700 and the file is mode
    /// 0600. The staged file is created new, so it never follows a link.
    ///
    /// # Errors
    ///
    /// [`PublishError::Io`] when the file is not written.
    pub fn publish(&self, path: &Path) -> Result<(), PublishError> {
        let io = |source| PublishError::Io {
            path: path.to_owned(),
            source,
        };
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder.create(dir).map_err(io)?;
            check_dir(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|err| io(err.into()))?;
        let staged = path.with_extension("json.new");
        // A staged file left by a stopped write, or a link put in its place.
        match std::fs::remove_file(&staged) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(io(err)),
            _ => {}
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&staged).map_err(io)?;
        io::Write::write_all(&mut file, &json).map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        std::fs::rename(&staged, path).map_err(io)
    }

    /// Reads a published identity from `path`.
    ///
    /// # Errors
    ///
    /// [`PublishError::Io`] when the file is not read,
    /// [`PublishError::Writable`] when another user owns it or can change
    /// it, [`PublishError::OpenDirectory`] when other users can change its
    /// directory, and [`PublishError::Malformed`] when it is not a published
    /// identity.
    pub fn read(path: &Path) -> Result<Self, PublishError> {
        let io = |source| PublishError::Io {
            path: path.to_owned(),
            source,
        };
        let mut file = std::fs::File::open(path).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let meta = file.metadata().map_err(io)?;
            if meta.mode() & 0o022 != 0 || meta.uid() != euid() {
                return Err(PublishError::Writable(path.to_owned()));
            }
        }
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            check_dir(dir)?;
        }
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut file, &mut bytes).map_err(io)?;
        serde_json::from_slice(&bytes).map_err(|_| PublishError::Malformed(path.to_owned()))
    }

    /// Seals `members` to the published sealing key, bound to `context`.
    ///
    /// # Errors
    ///
    /// [`PublishError::NotAKey`] naming the sealing role when the identity
    /// carries no usable sealing key, and [`PublishError::Seal`] when
    /// [`seal::seal`] refuses.
    pub fn seal(&self, context: &Context, members: &MemberList) -> Result<String, PublishError> {
        let key = self.key(Role::Sealing)?;
        Ok(seal::seal(&key, context, members)?)
    }
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: `geteuid` takes no argument and cannot fail.
    unsafe { libc::geteuid() }
}

/// Refuses a directory that other users can change, unless its sticky bit
/// keeps them from replacing a file they do not own.
fn check_dir(dir: &Path) -> Result<(), PublishError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(dir).map_err(|source| PublishError::Io {
            path: dir.to_owned(),
            source,
        })?;
        let sticky = meta.mode() & 0o1000 != 0;
        let others_write = meta.mode() & 0o022 != 0;
        if (others_write && !sticky) || (meta.uid() != euid() && meta.uid() != 0) {
            return Err(PublishError::OpenDirectory(dir.to_owned()));
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::keys::memory::MemoryStore;
    use crate::keys::{load, replace, replacement_report};
    use crate::seal::{Binding, Breadth, Member, MemberKind, Mode, OpenError};

    fn context(identity: &Identity) -> Context {
        Context {
            box_id: "box-1".into(),
            host: "laptop".into(),
            module: "github".into(),
            host_set_version: 1,
            mode: Mode::User,
            iat: 1_700_000_000,
            expiry: 1_900_000_000,
            kid: identity.key(Role::Sealing).unwrap().kid(),
        }
    }

    fn members() -> MemberList {
        MemberList {
            members: vec![Member {
                kind: MemberKind::SignIn,
                breadth: Breadth::Full,
                jws: Zeroizing::new("signed.handle.jws".into()),
                exp: None,
            }],
            default_owner: None,
        }
    }

    fn binding() -> Binding {
        Binding {
            box_id: "box-1".into(),
            host: "laptop".into(),
            module: "github".into(),
            now: 1_800_000_000,
        }
    }

    /// Every byte of every file under `dir`.
    fn files(dir: &Path) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(files(&path));
            } else {
                out.push(std::fs::read(path).unwrap());
            }
        }
        out
    }

    /// Asserts that no file under `dir` holds the secret, raw, in base64url
    /// or in hex.
    fn assert_in_no_file(dir: &Path, secret: &[u8]) {
        let b64 = URL_SAFE_NO_PAD.encode(secret);
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        for file in files(dir) {
            assert!(!file.windows(secret.len()).any(|w| w == secret));
            let text = String::from_utf8_lossy(&file).to_lowercase();
            assert!(!text.contains(&b64.to_lowercase()));
            assert!(!text.contains(&hex));
        }
    }

    // BEP-014
    #[test]
    fn signing_key_is_non_exportable_and_has_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/identity.json");
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        Identity::of(&keys).publish(&path).unwrap();

        assert!(!keys.signing.exportable());
        assert_in_no_file(dir.path(), &store.secret_bytes(Role::Signing));
        // The published entry is the public half alone.
        let published = Identity::read(&path).unwrap();
        assert_eq!(published.key(Role::Signing).unwrap(), keys.signing.public());
    }

    // BEP-059
    #[test]
    fn sealing_and_root_keys_persist_non_exportable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();

        let first = load(&store, &[]).unwrap();
        Identity::of(&first).publish(&path).unwrap();
        let before = Identity::read(&path).unwrap();
        drop(first);

        // A restart loads the same keys, and publishes the same identity.
        let second = load(&store, &Role::ALL).unwrap();
        Identity::of(&second).publish(&path).unwrap();
        let after = Identity::read(&path).unwrap();
        for role in [Role::Sealing, Role::Root] {
            assert_eq!(after.key(role).unwrap(), before.key(role).unwrap());
            assert!(!second.get(role).exportable());
            assert_in_no_file(dir.path(), &store.secret_bytes(role));
        }
    }

    // BEP-072
    #[test]
    fn a_value_sealed_to_the_published_identity_unseals_under_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        Identity::of(&keys).publish(&path).unwrap();

        // The mint reads the file only.
        let published = Identity::read(&path).unwrap();
        let sealed = published.seal(&context(&published), &members()).unwrap();

        let opened = keys.sealing.open(&sealed, &binding()).unwrap();
        assert_eq!(opened.member.jws.as_str(), "signed.handle.jws");
        assert_eq!(opened.context.kid, keys.sealing.public().kid());
    }

    #[cfg(unix)]
    #[test]
    fn the_identity_file_is_the_owners_alone() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/identity.json");
        let keys = load(&MemoryStore::default(), &[]).unwrap();
        let identity = Identity::of(&keys);
        // A link in place of the staged file is not followed.
        std::fs::create_dir(dir.path().join("bep")).unwrap();
        let target = dir.path().join("elsewhere");
        symlink(&target, path.with_extension("json.new")).unwrap();
        identity.publish(&path).unwrap();
        assert!(!target.exists());

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(Identity::read(&path).unwrap(), identity);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            Identity::read(&path),
            Err(PublishError::Writable(_))
        ));
        // Publishing again repairs it.
        identity.publish(&path).unwrap();
        assert_eq!(mode(&path), 0o600);

        let fresh = dir.path().join("new/dir/identity.json");
        identity.publish(&fresh).unwrap();
        assert_eq!(mode(fresh.parent().unwrap()), 0o700);

        // A directory that other users can change is refused, for reads and
        // for writes. Its sticky bit makes it safe again.
        let bep_dir = dir.path().join("bep");
        std::fs::set_permissions(&bep_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            Identity::read(&path),
            Err(PublishError::OpenDirectory(_))
        ));
        assert!(matches!(
            identity.publish(&path),
            Err(PublishError::OpenDirectory(_))
        ));
        std::fs::set_permissions(&bep_dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(Identity::read(&path).unwrap(), identity);
    }

    // BEP-060: a second refused key does not keep the old key published.
    #[test]
    fn a_replacement_publishes_the_new_key_beside_a_refused_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        let before = Identity::of(&keys);
        before.publish(&path).unwrap();
        drop(keys);

        store.refuse(Role::Signing);
        store.remove(Role::Root).unwrap();
        let new = replace(&store, Role::Sealing).unwrap();
        let previous = Identity::read(&path).ok();
        let after = Identity::after_replacement(&store, Role::Sealing, &new, previous.as_ref());
        after.publish(&path).unwrap();

        let published = Identity::read(&path).unwrap();
        assert_eq!(published.key(Role::Sealing).unwrap(), new.public());
        assert_eq!(published.signing, before.signing);
        // A role the store lost stays published, so the next start refuses
        // and does not make it again silently.
        assert_eq!(published.root, before.root);
        assert_eq!(published.roles(), Role::ALL.to_vec());

        // With no previous file, the store alone gives the other roles.
        let alone = Identity::after_replacement(&store, Role::Sealing, &new, None);
        assert_eq!(alone.roles(), vec![Role::Sealing, Role::Signing]);
    }

    // BEP-072
    #[test]
    fn a_published_identity_carrying_no_key_is_refused_by_role() {
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        let good = Identity::of(&keys);
        let ctx = context(&good);

        let missing = Identity {
            sealing: None,
            ..good.clone()
        };
        let not_a_point = Identity {
            sealing: Some(PublishedKey {
                public: URL_SAFE_NO_PAD.encode([4u8; 65]),
                kid: good.sealing.clone().unwrap().kid,
            }),
            ..good.clone()
        };
        let other_roles_key = Identity {
            sealing: good.root.clone(),
            ..good.clone()
        };
        let wrong_kid = Identity {
            sealing: Some(PublishedKey {
                kid: good.root.clone().unwrap().kid,
                ..good.sealing.clone().unwrap()
            }),
            ..good.clone()
        };
        for identity in [missing, not_a_point, wrong_kid] {
            let err = identity.seal(&ctx, &members()).unwrap_err();
            assert!(matches!(err, PublishError::NotAKey(Role::Sealing)), "{err}");
            assert!(err.to_string().contains("sealing key"), "{err}");
        }
        // A key published under another role's entry is a key, but the
        // context names the sealing fingerprint, so the seal refuses.
        assert!(other_roles_key.seal(&ctx, &members()).is_err());

        let no_root: Identity = serde_json::from_str(r#"{"sealing": null}"#).unwrap();
        let err = no_root.key(Role::Root).unwrap_err();
        assert!(matches!(err, PublishError::NotAKey(Role::Root)));
        assert!(err.to_string().contains("root key"), "{err}");
    }

    // BEP-060
    #[test]
    fn key_replacement_kills_outstanding_members() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        Identity::of(&keys).publish(&path).unwrap();
        let published = Identity::read(&path).unwrap();
        let sealed = published.seal(&context(&published), &members()).unwrap();
        assert!(keys.sealing.open(&sealed, &binding()).is_ok());
        drop(keys);

        let new = replace(&store, Role::Sealing).unwrap();
        assert_ne!(new.public().kid(), published.sealing.unwrap().kid);
        assert!(replacement_report(Role::Sealing).contains("Re-create"));

        let restarted = load(&store, &Role::ALL).unwrap();
        assert_eq!(
            restarted.sealing.open(&sealed, &binding()).unwrap_err(),
            OpenError::NotOpenable
        );
        // The republished identity seals to the new key.
        let republished = Identity::of(&restarted);
        let fresh = republished
            .seal(&context(&republished), &members())
            .unwrap();
        assert!(restarted.sealing.open(&fresh, &binding()).is_ok());
    }
}
