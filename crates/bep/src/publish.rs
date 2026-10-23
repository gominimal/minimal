//! The proxy's published identity (BEP-072).
//!
//! The file also carries the root certificate, PEM, that the proxy issued
//! from its root CA key at its start or at a root key replacement. A box
//! with a GitHub grant gets that certificate at its creation.
//!
//! At each start the proxy writes the public half and the fingerprint of
//! each of its keys to a file the operator's processes read. A mint seals
//! from that file alone: sealing is public-key work, so a mint never opens
//! the proxy's key store. The fingerprint is the `kid` a sealed context
//! binds.
//!
//! The file is JSON, one object per role:
//! `{"sealing": {"public": ..., "kid": ...}, "root": {...}, "signing": {...}}`,
//! beside `root_not_after` and `root_certificate`.
//! `public` is the uncompressed SEC1 point in unpadded base64url. A role is
//! read only when it is used, and [`Identity::key`] refuses a role whose
//! entry is missing, does not parse as a P-256 key, or carries a `kid` that is
//! not the key's fingerprint.

use std::io;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ca::{self, CaError, CaKey, RootCertificate, Union};
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

/// How long the root CA is valid, counted from the root key's creation.
///
/// OQ3: the root's validity is an open question
/// (<https://github.com/gominimal/arch/issues/85>). Until it is answered the
/// root is valid for ten years. The interception CA issues its root
/// certificate with this validity (`ROOT_VALIDITY` in [`crate::ca`] is
/// defined from it). Its end is the expiry of every sign-in reference a mint
/// makes (BEP-005).
pub const ROOT_VALIDITY_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// The published identity: one entry per key role.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identity {
    /// The sealing key, which a mint seals to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<PublishedKey>,
    /// The root CA's public key. The root certificate is
    /// [`Self::root_certificate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PublishedKey>,
    /// The signing CA key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<PublishedKey>,
    /// When the root CA's validity ends, in seconds since the Unix epoch:
    /// the root key's creation time plus [`ROOT_VALIDITY_SECS`]. A mint
    /// reads it as the expiry of each member (BEP-005).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_not_after: Option<u64>,
    /// The current root certificate, PEM: self-signed under the root key,
    /// with the registered names as its constraints (BEP-013, BEP-072).
    /// `None` in a file that an older `bep` published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate: Option<String>,
}

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// The certificate `der` in PEM, with 64 characters to a line.
#[must_use]
pub fn certificate_pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = String::with_capacity(body.len() + body.len() / 64 + 64);
    pem.push_str(PEM_BEGIN);
    pem.push('\n');
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    pem
}

/// The SHA-256 fingerprint of the certificate `der`, as uppercase hex
/// pairs joined by colons, the form `openssl x509 -fingerprint -sha256`
/// prints.
#[must_use]
pub fn certificate_fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
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
    /// The identity does not say when the root CA's validity ends. An
    /// identity that an older `bep` published has no such entry, and a
    /// restart keeps it unset while the root key stays the same.
    #[error(
        "The proxy's published identity does not say when its root certificate expires. Run `bep --replace-key root` to make a new root key with a known expiry, then start `bep serve` again."
    )]
    NoRootValidity,
    /// The identity carries no root certificate, or one that is not PEM.
    /// An identity that an older `bep` published has none.
    #[error(
        "The proxy's published identity carries no usable root certificate. Start `bep` to publish it again."
    )]
    NoRootCertificate,
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
            root_not_after: None,
            root_certificate: None,
        }
    }

    /// This identity with `der` as its root certificate. The caller issued
    /// it under the root key this identity names.
    #[must_use]
    pub fn with_root_certificate(mut self, der: &[u8]) -> Self {
        self.root_certificate = Some(certificate_pem(der));
        self
    }

    /// Issues the root certificate under `root_key`, constrained to
    /// `union`, and gives this identity with it beside the certificate. The
    /// certificate ends no later than [`Self::root_not_after`], so call
    /// [`Self::with_root_validity`] first. A
    /// start and a root key replacement publish the identity it gives.
    ///
    /// # Errors
    ///
    /// The CA's refusal, as [`ca::issue_root`] gives it.
    pub fn issuing_root<K: CaKey>(
        self,
        root_key: &K,
        union: Union,
        now: std::time::SystemTime,
    ) -> Result<(Self, RootCertificate), CaError> {
        // BEP-005: the certificate ends no later than the root key's
        // validity, which counts from the key's creation, not from now.
        let ends = self
            .root_not_after
            .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs));
        let root = ca::issue_root_until(root_key, union, now, ends)?;
        Ok((self.with_root_certificate(root.der()), root))
    }

    /// The published root certificate, DER.
    ///
    /// # Errors
    ///
    /// [`PublishError::NoRootCertificate`] when the identity carries no
    /// root certificate, or one that is not a PEM certificate.
    pub fn root_certificate_der(&self) -> Result<Vec<u8>, PublishError> {
        let pem = self
            .root_certificate
            .as_deref()
            .ok_or(PublishError::NoRootCertificate)?;
        let body = pem
            .trim()
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_END))
            .ok_or(PublishError::NoRootCertificate)?;
        let body: String = body.split_whitespace().collect();
        STANDARD
            .decode(body)
            .ok()
            .filter(|der| !der.is_empty())
            .ok_or(PublishError::NoRootCertificate)
    }

    /// The SHA-256 fingerprint of the published root certificate, as
    /// [`certificate_fingerprint`] gives it.
    ///
    /// # Errors
    ///
    /// [`PublishError::NoRootCertificate`] as [`Self::root_certificate_der`]
    /// gives it.
    pub fn root_certificate_fingerprint(&self) -> Result<String, PublishError> {
        self.root_certificate_der()
            .map(|der| certificate_fingerprint(&der))
    }

    /// This identity with the end of the root CA's validity.
    ///
    /// The key store keeps no creation time, so the end is taken only from
    /// a known one. `root_made_at` is the root key's creation time, in
    /// seconds since the Unix epoch, when the caller made the root key
    /// itself. The validity then ends [`ROOT_VALIDITY_SECS`] later.
    /// Otherwise, when `previous` names the same root key, its end is kept.
    /// In every other case the end stays unset. An identity with no root
    /// entry gets no end.
    ///
    /// A root key of unknown age, such as one loaded from the store with no
    /// identity file or one that an older `bep` published with no end, can
    /// be older than now. An end counted from now can then be later than
    /// the root's real end. So a mint refuses the identity until the root
    /// key is replaced.
    #[must_use]
    pub fn with_root_validity(
        mut self,
        previous: Option<&Self>,
        root_made_at: Option<u64>,
    ) -> Self {
        let kid = self.root.as_ref().map(|root| root.kid.as_str());
        let same_root = previous.filter(|previous| {
            kid.is_some() && previous.root.as_ref().map(|r| r.kid.as_str()) == kid
        });
        self.root_not_after = match (kid, root_made_at, same_root) {
            (None, _, _) => None,
            (Some(_), Some(made_at), _) => Some(made_at.saturating_add(ROOT_VALIDITY_SECS)),
            (Some(_), None, Some(previous)) => previous.root_not_after,
            (Some(_), None, None) => None,
        };
        self
    }

    /// When the root CA's validity ends, in seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`PublishError::NotAKey`] naming the root role when the identity has
    /// no usable root key, and [`PublishError::NoRootValidity`] when it does
    /// not carry the end.
    pub fn root_not_after(&self) -> Result<u64, PublishError> {
        self.key(Role::Root)?;
        self.root_not_after.ok_or(PublishError::NoRootValidity)
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
        let root = entry(Role::Root);
        // A root certificate stays valid while its root key stays. A new
        // root key needs a new certificate, which the caller adds with
        // `with_root_certificate`.
        let root_certificate = previous
            .filter(|previous| {
                role != Role::Root && previous.root.is_some() && previous.root == root
            })
            .and_then(|previous| previous.root_certificate.clone());
        Self {
            sealing: entry(Role::Sealing),
            root,
            signing: entry(Role::Signing),
            // The caller adds the end with `with_root_validity`, from the
            // root key's creation time when it is known.
            root_not_after: None,
            root_certificate,
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

    fn github_union() -> Union {
        Union::new(&[crate::module::GITHUB], [""; 0])
    }

    /// The SubjectPublicKeyInfo's last 65 bytes are the uncompressed point.
    fn certificate_carries_key(der: &[u8], key: &ProxyPublicKey) -> bool {
        let point = key.to_sec1_bytes();
        der.windows(point.len()).any(|w| w == &point[..])
    }

    // BEP-072, BEP-013: the published identity carries the root certificate
    // that the start issued from the held root key, beside that key.
    #[test]
    fn published_identity_carries_the_root_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let keys = load(&store, &[]).unwrap();
        let (identity, root) = Identity::of(&keys)
            .issuing_root(&keys.root, github_union(), std::time::SystemTime::now())
            .unwrap();
        identity.publish(&path).unwrap();

        let published = Identity::read(&path).unwrap();
        let pem = published.root_certificate.as_deref().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{pem}");
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"), "{pem}");
        assert!(pem.lines().all(|line| line.len() <= 64), "{pem}");
        let der = published.root_certificate_der().unwrap();
        assert_eq!(der, root.der().to_vec());
        assert!(certificate_carries_key(&der, &keys.root.public()));
        assert_eq!(published.key(Role::Root).unwrap(), keys.root.public());
        let fingerprint = published.root_certificate_fingerprint().unwrap();
        assert_eq!(fingerprint, certificate_fingerprint(root.der()));
        assert_eq!(fingerprint.len(), 32 * 3 - 1);
        // The certificate is public material: no key's private half is in
        // the file.
        for role in Role::ALL {
            assert_in_no_file(dir.path(), &store.secret_bytes(role));
        }

        // An identity that an older `bep` published has no certificate.
        let older = Identity::of(&keys);
        assert!(matches!(
            older.root_certificate_der(),
            Err(PublishError::NoRootCertificate)
        ));
        let broken = Identity {
            root_certificate: Some("not a certificate".into()),
            ..older
        };
        assert!(matches!(
            broken.root_certificate_fingerprint(),
            Err(PublishError::NoRootCertificate)
        ));
    }

    // BEP-072, BEP-060: a root key replacement publishes a certificate under
    // the new key. A replacement of another key keeps the certificate.
    #[test]
    fn root_replacement_publishes_a_new_root_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let now = std::time::SystemTime::now();
        let keys = load(&store, &[]).unwrap();
        let (first, _) = Identity::of(&keys)
            .issuing_root(&keys.root, github_union(), now)
            .unwrap();
        first.publish(&path).unwrap();
        let old_root = keys.root.public();
        drop(keys);

        // A sealing key replacement keeps the root key, so it keeps the
        // published certificate.
        let sealing = replace(&store, Role::Sealing).unwrap();
        let previous = Identity::read(&path).unwrap();
        let kept = Identity::after_replacement(&store, Role::Sealing, &sealing, Some(&previous));
        assert_eq!(kept.root_certificate, first.root_certificate);
        kept.publish(&path).unwrap();

        // A root key replacement drops the old certificate and publishes one
        // under the new key.
        let root = replace(&store, Role::Root).unwrap();
        let previous = Identity::read(&path).unwrap();
        let replaced = Identity::after_replacement(&store, Role::Root, &root, Some(&previous));
        assert_eq!(replaced.root_certificate, None);
        let (replaced, issued) = replaced.issuing_root(&root, github_union(), now).unwrap();
        replaced.publish(&path).unwrap();

        let published = Identity::read(&path).unwrap();
        let der = published.root_certificate_der().unwrap();
        assert_eq!(der, issued.der().to_vec());
        assert_ne!(published.root_certificate, first.root_certificate);
        assert!(certificate_carries_key(&der, &root.public()));
        assert!(!certificate_carries_key(&der, &old_root));
        assert_eq!(published.key(Role::Root).unwrap(), root.public());
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

    // BEP-005, OQ3: the identity carries the end of the root's validity, the
    // root key's creation plus the fixed default, from one start to the next.
    #[test]
    fn published_identity_carries_the_root_validity_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        let store = MemoryStore::default();
        let created = 1_700_000_000;

        // The first start makes the root key, so its validity starts then.
        let keys = load(&store, &[]).unwrap();
        Identity::of(&keys)
            .with_root_validity(None, Some(created))
            .publish(&path)
            .unwrap();
        let first = Identity::read(&path).unwrap();
        assert_eq!(first.root_not_after, Some(created + ROOT_VALIDITY_SECS));
        assert_eq!(
            first.root_not_after().unwrap(),
            created + ROOT_VALIDITY_SECS
        );
        drop(keys);

        // A later start with the same root key keeps the end.
        let restarted = load(&store, &Role::ALL).unwrap();
        let later = Identity::of(&restarted).with_root_validity(Some(&first), None);
        assert_eq!(later.root_not_after, first.root_not_after);
        drop(restarted);

        // A replaced root key starts a new validity.
        let replaced_at = created + 2 * 86_400;
        let new = replace(&store, Role::Root).unwrap();
        let after = Identity::after_replacement(&store, Role::Root, &new, Some(&first))
            .with_root_validity(Some(&first), Some(replaced_at));
        assert_eq!(after.root_not_after, Some(replaced_at + ROOT_VALIDITY_SECS));

        // A replaced sealing key leaves the root's end as it was.
        let sealing = replace(&store, Role::Sealing).unwrap();
        let resealed = Identity::after_replacement(&store, Role::Sealing, &sealing, Some(&after))
            .with_root_validity(Some(&after), None);
        assert_eq!(resealed.root_not_after, after.root_not_after);

        // An identity from an older `bep` has no end, and a mint refuses it.
        let old: Identity = serde_json::from_str(
            &serde_json::to_string(&Identity {
                root_not_after: None,
                ..first
            })
            .unwrap(),
        )
        .unwrap();
        let err = old.root_not_after().unwrap_err();
        assert!(matches!(err, PublishError::NoRootValidity), "{err}");

        // A restart with the same root key does not give such an identity
        // an end, because the root key's creation time is unknown.
        let upgraded = Identity {
            root_not_after: None,
            ..resealed
        };
        let restarted = load(&store, &Role::ALL).unwrap();
        let republished = Identity::of(&restarted).with_root_validity(Some(&upgraded), None);
        assert_eq!(republished.root_not_after, None);
        assert!(matches!(
            republished.root_not_after(),
            Err(PublishError::NoRootValidity)
        ));
        drop(restarted);

        // Its next root replacement starts a known validity.
        let replaced_again = replaced_at + 3 * 86_400;
        let root = replace(&store, Role::Root).unwrap();
        let renewed = Identity::after_replacement(&store, Role::Root, &root, Some(&upgraded))
            .with_root_validity(Some(&upgraded), Some(replaced_again));
        assert_eq!(
            renewed.root_not_after,
            Some(replaced_again + ROOT_VALIDITY_SECS)
        );

        // With no identity file, a start that loads the root key from the
        // store does not know its age, so the identity gets no end.
        std::fs::remove_file(&path).unwrap();
        let loaded = load(&store, &[]).unwrap();
        Identity::of(&loaded)
            .with_root_validity(None, None)
            .publish(&path)
            .unwrap();
        let unknown = Identity::read(&path).unwrap();
        assert_eq!(unknown.root_not_after, None);
        assert!(matches!(
            unknown.root_not_after(),
            Err(PublishError::NoRootValidity)
        ));
    }
}
