//! The proxy's interception CA (BEP-013): three layers of certificates.
//!
//! - The root is a self-signed CA certificate under the root CA key. It is
//!   the anchor that a box's trust store holds. Its permitted-names
//!   constraint is the registered [`Union`]: the hosts of the configured
//!   modules and the hosts that the operator's store rules register, less
//!   the fixed [`DENY_SET`]. The deny set is also its excluded-names
//!   constraint.
//! - The signing CA is one CA certificate per host, under the signing CA
//!   key, which the root issues. It carries no constraint of its own.
//! - A leaf is a certificate for one hostname, which the signing CA issues.
//!   The proxy issues a leaf for a name in the union only. A permitted
//!   subtree also admits the subdomains of a name (RFC 5280 §4.2.1.10), so
//!   the exact admission is the issuance check, not the constraint.
//!
//! The root and signing CA keys stay in the key store. The CA uses them only
//! through [`CaKey::sign`]. When the union changes, [`Ca::reissue_root`]
//! issues the root again under the same key and subject with the changed
//! constraints. The certificates below the root carry an authority key
//! identifier with the key identifier only, so they chain to each issue of
//! the root. A box keeps the root it got at its creation.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PublicKeyData, SanType, SerialNumber, SignatureAlgorithm, SigningKey,
};
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::keys::{HeldKey, KeyError, Role};
use crate::module::Module;

/// The infrastructure deny set: the names that the root never permits, also
/// when a module or a store rule registers them. A name in this set, or a
/// subdomain of one, is outside the union. The root also carries the set as
/// its excluded-names constraint.
///
/// This is the one definition of the set. The store-rule check of BEP-034
/// reads it too: the client passes it as the `infrastructure` part of
/// `boxes::core::bep::StoreDenySet`.
///
/// The task text gives the categories of the set: `min.internal`,
/// `minimal.dev`, the tenant issuer, the BEP, EGW and relay endpoints, the
/// registry and build cache, and the node-plane baseline set. It also keeps
/// `localhost`, `.local`, `home.arpa` and `.internal` allowed. The mapping
/// of each category to a domain, and the `minimal.farm` entry, are this
/// change's reading of those categories. That reading waits for a
/// confirmation on <https://github.com/gominimal/minimal/issues/2441>, the
/// tracking issue. Each entry covers the endpoints in its comment.
///
/// The built-in baseline of an un-enrolled host
/// (`NodePlaneBaseline::built_in` in `crates/minvmd/src/net/baseline.rs`)
/// is addresses, not names. The root excludes every IP address, so no
/// entry here is needed for those addresses. This set does not cover a
/// configured cache (`MINIMAL_REMOTE_CACHE_URL`), registry or baseline
/// endpoint outside its domains, a gap that waits on
/// <https://github.com/gominimal/minimal/issues/2441>.
///
/// The `minimal.dev` entry covers the hosted tenant issuers only. A
/// self-hosted Gatehouse issuer (Gatehouse §2.1 F14) is under no entry.
/// That gap is residual on <https://github.com/gominimal/minimal/issues/2441>.
///
/// Only `min.internal` under `.internal` is denied. The module host sets
/// stay in the union: the store-rule check refuses a rule that names them,
/// but the root permits them.
///
/// Keep one quoted name on each line: the `boxes` tests read this list from
/// the source text.
pub const DENY_SET: &[&str] = &[
    // The box-internal names: `host.min.internal`, `minimald.min.internal`,
    // the services under them, and the proxy's in-box address.
    "min.internal",
    // Minimal's own infrastructure: the hosted tenant issuers, the
    // registry, the build cache (`cache.minimal.dev`) and the installer.
    // A self-hosted issuer is not under this entry (#2441).
    "minimal.dev",
    // The build cache by the name the design gives it (architecture.md
    // line 844). Gatehouse §6.10 refuses an upstream that names it. Only
    // this host is denied, not the rest of `gominimal.dev`.
    "cache.gominimal.dev",
    // Minimal's hosted endpoints: the BEP, EGW and relay endpoints, the
    // hosted build cache (`cache.minimal.farm`) and the agent runtime.
    // This entry is this change's reading. No design line names this
    // domain, so the entry waits for the confirmation on #2441.
    "minimal.farm",
];

/// The subject common name of the root.
pub const ROOT_COMMON_NAME: &str = "Minimal Box Egress Proxy Root CA";

/// The subject common name of the signing CA.
pub const SIGNING_COMMON_NAME: &str = "Minimal Box Egress Proxy Signing CA";

const ORGANIZATION: &str = "Minimal";

/// How far before `now` each certificate starts, for clock skew.
const BACKDATE: Duration = Duration::from_secs(60 * 60);
const DAY: u64 = 24 * 60 * 60;
// BEP-005, OQ3: one constant gives the root's validity and each member's
// expiry.
const ROOT_VALIDITY: Duration = Duration::from_secs(crate::publish::ROOT_VALIDITY_SECS);
const SIGNING_VALIDITY: Duration = Duration::from_secs(365 * DAY);
const LEAF_VALIDITY: Duration = Duration::from_secs(7 * DAY);

/// A held key that can sign a certificate. The keychain key and the
/// in-memory test key of [`crate::keys`] implement it, so the root and
/// signing CA keys sign in the store that holds them.
pub trait CaKey: HeldKey {
    /// An ECDSA P-256 SHA-256 signature over `msg`, DER-encoded as X9.62
    /// specifies. The private half stays in the store.
    ///
    /// # Errors
    ///
    /// [`KeyError::Refused`] when the store refuses the key's use, and
    /// [`KeyError::Store`] when the store fails for another reason.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// The hostnames the root permits: the union of the module host sets and the
/// registered authorities, less the [`DENY_SET`]. Each name is lowercase,
/// with no port and no trailing dot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Union(BTreeSet<String>);

impl Union {
    /// The union of the host sets of `modules` and the hosts of `registered`,
    /// less the deny set. A registered authority can carry a port, which the
    /// union drops: a name constraint has no port.
    #[must_use]
    pub fn new<I, S>(modules: &[Module], registered: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let module_hosts = modules.iter().flat_map(|module| {
            module
                .hosts
                .iter()
                .map(|authority| authority.host.to_owned())
        });
        let registered_hosts = registered
            .into_iter()
            .map(|authority| host_of(authority.as_ref()));
        Self(
            module_hosts
                .chain(registered_hosts)
                .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty() && !denied(host) && dns_host(host))
                .collect(),
        )
    }

    /// Whether the union holds `hostname` exactly. A subdomain of a name in
    /// the union is not in the union.
    #[must_use]
    pub fn contains(&self, hostname: &str) -> bool {
        self.0
            .contains(&hostname.trim_end_matches('.').to_ascii_lowercase())
    }

    /// The names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Whether the union holds no name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Union {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.names().collect();
        write!(f, "[{}]", names.join(", "))
    }
}

/// The host of an authority: the text before a `:port` suffix.
fn host_of(authority: &str) -> String {
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            host.to_owned()
        }
        _ => authority.to_owned(),
    }
}

/// Whether `host` is a DNS name that the root can permit. A DNS name
/// constraint cannot carry an IP address, so the union skips one. It also
/// skips a name that a permitted subtree must not carry: a wildcard, a
/// name with an empty label, a non-ASCII name, and a single-label name
/// such as a top-level domain, which permits every name under it.
fn dns_host(host: &str) -> bool {
    if host.contains([':', '[', ']']) || host.parse::<std::net::IpAddr>().is_ok() {
        tracing::warn!(
            host,
            "skipped a registered host that is an IP address, not a DNS name"
        );
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    // RFC 1035 caps a whole name at 253 bytes in its text form.
    let valid = host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        tracing::warn!(
            host,
            "skipped a registered host that is not a DNS name of two or more labels"
        );
    }
    valid
}

/// Whether `host` is a name in the deny set or a subdomain of one.
fn denied(host: &str) -> bool {
    DENY_SET.iter().any(|deny| {
        host == *deny
            || host
                .strip_suffix(deny)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Why the CA did not issue a certificate.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// The key store refused or failed a key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The union holds no name. A root with no permitted names has no
    /// constraint at all, so the CA refuses to issue it.
    #[error("no module or store rule registers a host, so the proxy has no root CA to issue")]
    EmptyUnion,
    /// The hostname is not in the union.
    #[error("{hostname} is not a host that a module or a store rule registers")]
    OutsideUnion {
        /// The hostname of the refused leaf.
        hostname: String,
        /// The union, as text.
        union: String,
    },
    /// A name is not a DNS name that a certificate can carry.
    #[error("{0} is not a DNS name")]
    InvalidName(String),
    /// The signing CA expired, so a leaf it signs would not validate.
    #[error("the proxy signing CA expired at {0}, so the proxy issues no leaf certificate")]
    SigningExpired(OffsetDateTime),
    /// The root expired, so a signing CA it issues would not validate.
    #[error("the proxy root CA expired at {0}, so the proxy issues no signing CA")]
    RootExpired(OffsetDateTime),
    /// A key passed for one CA role holds another role.
    #[error("the proxy {expected} CA needs the {expected} key, not the {got} key")]
    WrongRole {
        /// The role the CA needs.
        expected: Role,
        /// The role of the key it got.
        got: Role,
    },
    /// A key passed for a CA role is exportable. The proxy holds only
    /// non-exportable keys.
    #[error("the proxy {0} key is exportable, so the proxy does not use it for a CA")]
    Exportable(Role),
    /// The certificate encoding failed.
    #[error("the certificate was not issued: {0}")]
    Certificate(rcgen::Error),
}

/// A leaf certificate and its private key, for the proxy's TLS server side.
pub struct Leaf {
    /// The hostname the leaf is for.
    pub hostname: String,
    /// The leaf certificate, then the signing CA certificate. The root is not
    /// in the chain: the box holds it.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key, PKCS#8 DER. It lives in process memory only.
    pub key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leaf")
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

/// A held key as an `rcgen` signer. It keeps the store's error, which
/// `rcgen` cannot carry.
struct Signer<'k, K> {
    key: &'k K,
    public: Box<[u8]>,
    failure: RefCell<Option<KeyError>>,
}

impl<'k, K: CaKey> Signer<'k, K> {
    fn new(key: &'k K) -> Self {
        Self {
            key,
            public: key.public().to_sec1_bytes(),
            failure: RefCell::new(None),
        }
    }

    /// The error of a signing, as the store gave it when the store failed.
    fn error(&self, err: rcgen::Error) -> CaError {
        self.failure
            .borrow_mut()
            .take()
            .map_or(CaError::Certificate(err), CaError::Key)
    }
}

impl<K: CaKey> PublicKeyData for Signer<'_, K> {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl<K: CaKey> SigningKey for Signer<'_, K> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key.sign(msg).map_err(|err| {
            *self.failure.borrow_mut() = Some(err);
            rcgen::Error::RemoteKeyError
        })
    }
}

/// A root certificate that [`issue_root`] issued, with the union it
/// permits. [`Ca::with_root`] keeps it as the CA's anchor.
#[derive(Debug, Clone)]
pub struct RootCertificate {
    der: CertificateDer<'static>,
    not_after: OffsetDateTime,
    union: Union,
}

impl RootCertificate {
    /// The certificate, DER.
    #[must_use]
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// The union the certificate permits.
    #[must_use]
    pub fn union(&self) -> &Union {
        &self.union
    }
}

/// Issues the self-signed root certificate under the held `root_key`,
/// constrained to `union` (BEP-013). The proxy issues it at each start, so
/// a changed union gets a root under the same key and subject.
///
/// # Errors
///
/// [`CaError::WrongRole`] when `root_key` is not the root key,
/// [`CaError::Exportable`] when it is exportable, [`CaError::EmptyUnion`]
/// when the union holds no name, and [`CaError::Key`] when the store refuses
/// the key or cannot sign with it.
pub fn issue_root<K: CaKey>(
    root_key: &K,
    union: Union,
    now: SystemTime,
) -> Result<RootCertificate, CaError> {
    issue_root_until(root_key, union, now, None)
}

/// Issues the root certificate as [`issue_root`] does, and ends it no later
/// than `ends` when that is known. A start passes the root key's published
/// validity end, so each issue under one root key keeps the end counted
/// from the key's creation (BEP-005).
///
/// # Errors
///
/// As [`issue_root`], and [`CaError::RootExpired`] when `now` is at or past
/// `ends`.
pub fn issue_root_until<K: CaKey>(
    root_key: &K,
    union: Union,
    now: SystemTime,
    ends: Option<SystemTime>,
) -> Result<RootCertificate, CaError> {
    check_key(root_key, Role::Root)?;
    let signer = Signer::new(root_key);
    let mut params = root_params(&union, now)?;
    if let Some(ends) = ends.map(OffsetDateTime::from) {
        if OffsetDateTime::from(now) >= ends {
            return Err(CaError::RootExpired(ends));
        }
        params.not_after = params.not_after.min(ends);
    }
    let der = params
        .self_signed(&signer)
        .map_err(|err| signer.error(err))?
        .der()
        .clone();
    Ok(RootCertificate {
        der,
        not_after: params.not_after,
        union,
    })
}

/// The host's interception CA: the root, the signing CA, and the leaves.
pub struct Ca<'k, K> {
    root_key: Signer<'k, K>,
    signing_key: Signer<'k, K>,
    signing_params: CertificateParams,
    root_expiry: OffsetDateTime,
    union: Union,
    root: CertificateDer<'static>,
    signing: CertificateDer<'static>,
}

impl<K> fmt::Debug for Ca<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca")
            .field("union", &self.union)
            .finish_non_exhaustive()
    }
}

impl<'k, K: CaKey> Ca<'k, K> {
    /// Issues the root under `root_key`, constrained to `union`, and the
    /// signing CA under `signing_key`, issued by the root.
    ///
    /// # Errors
    ///
    /// [`CaError::WrongRole`] when `root_key` is not the root key or
    /// `signing_key` is not the signing key, [`CaError::Exportable`] when a
    /// key is exportable, [`CaError::EmptyUnion`] when the union holds no
    /// name, and [`CaError::Key`] when the store refuses a key.
    pub fn new(
        root_key: &'k K,
        signing_key: &'k K,
        union: Union,
        now: SystemTime,
    ) -> Result<Self, CaError> {
        let root = issue_root(root_key, union, now)?;
        Self::with_root(root_key, signing_key, root, now)
    }

    /// The CA anchored on `root`, which [`issue_root`] issued under
    /// `root_key`, with a signing CA under `signing_key` issued by it.
    ///
    /// # Errors
    ///
    /// [`CaError::WrongRole`] when `root_key` is not the root key or
    /// `signing_key` is not the signing key, [`CaError::Exportable`] when a
    /// key is exportable, [`CaError::RootExpired`] when `root` expired, and
    /// [`CaError::Key`] when the store refuses a key.
    pub fn with_root(
        root_key: &'k K,
        signing_key: &'k K,
        root: RootCertificate,
        now: SystemTime,
    ) -> Result<Self, CaError> {
        // A key that is not the role's own, or that can leave the store,
        // lets the signing CA key sign a root that the constraints do not
        // bind.
        check_key(root_key, Role::Root)?;
        check_key(signing_key, Role::Signing)?;
        if OffsetDateTime::from(now) >= root.not_after {
            return Err(CaError::RootExpired(root.not_after));
        }
        let root_key = Signer::new(root_key);
        let signing_key = Signer::new(signing_key);
        // The issuer is named by subject and key identifier, which are the
        // same in each issue of the root under the same key.
        let root_params = root_params(&root.union, now)?;
        let (signing_params, signing) =
            issue_signing(&root_params, &root_key, &signing_key, now, root.not_after)?;

        Ok(Self {
            root_key,
            signing_key,
            signing_params,
            root_expiry: root.not_after,
            union: root.union,
            root: root.der,
            signing,
        })
    }

    /// The root certificate, DER. A box's trust store holds it.
    #[must_use]
    pub fn root(&self) -> &CertificateDer<'static> {
        &self.root
    }

    /// The signing CA certificate, DER.
    #[must_use]
    pub fn signing(&self) -> &CertificateDer<'static> {
        &self.signing
    }

    /// The union the current root permits.
    #[must_use]
    pub fn union(&self) -> &Union {
        &self.union
    }

    /// Issues a leaf for `hostname` under the signing CA.
    ///
    /// # Errors
    ///
    /// [`CaError::OutsideUnion`] when `hostname` is not in the union,
    /// [`CaError::SigningExpired`] when `now` is at or past the signing CA
    /// expiry, and [`CaError::Key`] when the store refuses the signing CA
    /// key.
    pub fn issue_leaf(&self, hostname: &str, now: SystemTime) -> Result<Leaf, CaError> {
        if !self.union.contains(hostname) {
            tracing::warn!(
                hostname,
                union = %self.union,
                "refused a leaf certificate for a name outside the registered union"
            );
            return Err(CaError::OutsideUnion {
                hostname: hostname.to_owned(),
                union: self.union.to_string(),
            });
        }
        let leaf = self.sign_leaf(&hostname.trim_end_matches('.').to_ascii_lowercase(), now)?;
        tracing::debug!(hostname = %leaf.hostname, "issued a leaf certificate");
        Ok(leaf)
    }

    /// Signs a leaf for `hostname` with no union check.
    fn sign_leaf(&self, hostname: &str, now: SystemTime) -> Result<Leaf, CaError> {
        let expiry = self.signing_params.not_after;
        if OffsetDateTime::from(now) >= expiry {
            tracing::warn!(hostname, %expiry, "refused a leaf certificate: the signing CA expired");
            return Err(CaError::SigningExpired(expiry));
        }
        let name = rcgen::string::Ia5String::try_from(hostname)
            .map_err(|_| CaError::InvalidName(hostname.to_owned()))?;
        let key =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(CaError::Certificate)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        // The subject CN is capped at 64 bytes (RFC 5280 ub-common-name).
        // The SAN carries the name, so a longer name gets no CN.
        if hostname.len() <= 64 {
            params.distinguished_name.push(DnType::CommonName, hostname);
        }
        params.subject_alt_names = vec![SanType::DnsName(name)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(serial()?);
        validity(&mut params, now, LEAF_VALIDITY);
        // A leaf never outlives the signing CA that issued it.
        params.not_after = params.not_after.min(self.signing_params.not_after);
        let cert = params
            .signed_by(
                &key,
                &Issuer::from_params(&self.signing_params, &self.signing_key),
            )
            .map_err(|err| self.signing_key.error(err))?;
        Ok(Leaf {
            hostname: hostname.to_owned(),
            chain: vec![cert.der().clone(), self.signing.clone()],
            key: Zeroizing::new(key.serialize_der()),
        })
    }

    /// The time at which the signing CA expires. After it, [`Ca::issue_leaf`]
    /// refuses every leaf until [`Ca::renew_signing`] runs.
    #[must_use]
    pub fn signing_expiry(&self) -> SystemTime {
        self.signing_params.not_after.into()
    }

    /// Issues the signing CA again under the same key, from `now`, issued by
    /// the current root. The root certificate does not change, and the new
    /// signing CA names the root by the same key identifier, so a box that
    /// trusts the root trusts the leaves of either signing CA. A long-running caller runs it before
    /// [`Ca::signing_expiry`]. Leaves that the earlier signing CA issued stay
    /// valid until their own expiry, because the key and subject are the same.
    /// The new signing CA never outlives the current root.
    ///
    /// # Errors
    ///
    /// [`CaError::RootExpired`] when `now` is at or past the root expiry,
    /// and [`CaError::Key`] when the store refuses a key. The current signing
    /// CA stays in place on an error.
    pub fn renew_signing(&mut self, now: SystemTime) -> Result<(), CaError> {
        if OffsetDateTime::from(now) >= self.root_expiry {
            tracing::warn!(expiry = %self.root_expiry, "refused to renew the signing CA: the root CA expired");
            return Err(CaError::RootExpired(self.root_expiry));
        }
        let root_params = root_params(&self.union, now)?;
        let (params, signing) = issue_signing(
            &root_params,
            &self.root_key,
            &self.signing_key,
            now,
            self.root_expiry,
        )?;
        // BEP-061: one line per rotation, naming the certificate it replaced
        // and the one now in use.
        tracing::info!(
            old_fingerprint = %crate::publish::certificate_fingerprint(&self.signing),
            new_fingerprint = %crate::publish::certificate_fingerprint(&signing),
            expiry = %params.not_after,
            "rotated the signing CA under the unchanged root and key identifier"
        );
        self.signing_params = params;
        self.signing = signing;
        Ok(())
    }

    /// Issues the root again under the same key and subject, constrained to
    /// `union`. It returns `false` and issues nothing when the union did not
    /// change. The signing CA and the leaves stay valid under each issue of
    /// the root.
    ///
    /// # Errors
    ///
    /// [`CaError::EmptyUnion`] when the union holds no name, and
    /// [`CaError::Key`] when the store refuses the root key. The current
    /// root stays in place on an error.
    pub fn reissue_root(&mut self, union: Union, now: SystemTime) -> Result<bool, CaError> {
        if union == self.union {
            return Ok(false);
        }
        let mut params = root_params(&union, now)?;
        // The same root key keeps the same validity end.
        params.not_after = params.not_after.min(self.root_expiry);
        let root = params
            .self_signed(&self.root_key)
            .map_err(|err| self.root_key.error(err))?
            .der()
            .clone();
        let added: Vec<&str> = union
            .0
            .difference(&self.union.0)
            .map(String::as_str)
            .collect();
        let removed: Vec<&str> = self
            .union
            .0
            .difference(&union.0)
            .map(String::as_str)
            .collect();
        tracing::info!(
            added = ?added,
            removed = ?removed,
            "re-issued the root CA under the same key with changed name constraints"
        );
        self.root = root;
        self.root_expiry = params.not_after;
        self.union = union;
        Ok(true)
    }
}

/// Issues the signing CA under `signing_key`, signed by the root that
/// `root_params` and `root_key` describe. The signing CA expires no later
/// than `root_expiry`, the expiry of the root certificate in use.
fn issue_signing<K: CaKey>(
    root_params: &CertificateParams,
    root_key: &Signer<'_, K>,
    signing_key: &Signer<'_, K>,
    now: SystemTime,
    root_expiry: OffsetDateTime,
) -> Result<(CertificateParams, CertificateDer<'static>), CaError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject(SIGNING_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(serial()?);
    validity(&mut params, now, SIGNING_VALIDITY);
    // A signing CA never outlives the root that issued it.
    params.not_after = params.not_after.min(root_expiry);
    let signing = params
        .signed_by(signing_key, &Issuer::from_params(root_params, root_key))
        .map_err(|err| root_key.error(err))?
        .der()
        .clone();
    Ok((params, signing))
}

fn subject(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, ORGANIZATION);
    name.push(DnType::CommonName, common_name);
    name
}

/// Refuses a CA key that does not hold `expected` or that is exportable.
fn check_key<K: HeldKey>(key: &K, expected: Role) -> Result<(), CaError> {
    let got = key.role();
    if got != expected {
        return Err(CaError::WrongRole { expected, got });
    }
    if key.exportable() {
        return Err(CaError::Exportable(got));
    }
    Ok(())
}

fn root_params(union: &Union, now: SystemTime) -> Result<CertificateParams, CaError> {
    if union.is_empty() {
        return Err(CaError::EmptyUnion);
    }
    let dns = |name: &str| {
        rcgen::string::Ia5String::try_from(name)
            .map(|_| GeneralSubtree::DnsName(name.to_owned()))
            .map_err(|_| CaError::InvalidName(name.to_owned()))
    };
    let mut params = CertificateParams::default();
    params.distinguished_name = subject(ROOT_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: union.names().map(dns).collect::<Result<_, _>>()?,
        // The union holds DNS names only. A name type with no subtree is
        // unconstrained (RFC 5280 §4.2.1.10), so the root excludes every IP
        // address.
        excluded_subtrees: DENY_SET
            .iter()
            .map(|name| GeneralSubtree::DnsName((*name).to_owned()))
            .chain([
                GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
                GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
            ])
            .collect(),
    });
    params.serial_number = Some(serial()?);
    validity(&mut params, now, ROOT_VALIDITY);
    Ok(params)
}

fn validity(params: &mut CertificateParams, now: SystemTime, lifetime: Duration) {
    params.not_before = OffsetDateTime::from(now - BACKDATE);
    params.not_after = OffsetDateTime::from(now + lifetime);
}

/// A random positive 16-byte serial number.
fn serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CaError::Certificate(rcgen::Error::RingUnspecified))?;
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    Ok(SerialNumber::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;
    use rustls_pki_types::{ServerName, UnixTime};
    use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};
    use zeroize::Zeroizing;

    use super::*;
    use crate::module::{Authority, GITHUB, HTTPS_PORT};
    use crate::seal::ProxyPublicKey;

    /// A software key in place of a keychain key.
    struct TestKey {
        role: Role,
        pair: KeyPair,
        exportable: bool,
    }

    impl TestKey {
        fn new(role: Role) -> Self {
            Self {
                role,
                pair: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
                exportable: false,
            }
        }
    }

    impl HeldKey for TestKey {
        fn role(&self) -> Role {
            self.role
        }
        fn public(&self) -> ProxyPublicKey {
            ProxyPublicKey::from_sec1_bytes(self.pair.public_key_raw()).unwrap()
        }
        fn exportable(&self) -> bool {
            self.exportable
        }
        fn agree(&self, _peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            Err(KeyError::Store {
                role: self.role,
                detail: "a CA test key does no key agreement".into(),
            })
        }
        fn probe(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    impl CaKey for TestKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            SigningKey::sign(&self.pair, msg).map_err(|err| KeyError::Store {
                role: self.role,
                detail: err.to_string(),
            })
        }
    }

    fn keys() -> (TestKey, TestKey) {
        (TestKey::new(Role::Root), TestKey::new(Role::Signing))
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    /// Whether `leaf` validates for `hostname` against `root` alone.
    fn validates(root: &CertificateDer<'_>, leaf: &Leaf, hostname: &str) -> bool {
        let anchors = [anchor_from_trusted_cert(root).unwrap()];
        let ee = EndEntityCert::try_from(&leaf.chain[0]).unwrap();
        let time =
            UnixTime::since_unix_epoch(now().duration_since(SystemTime::UNIX_EPOCH).unwrap());
        let path = ee.verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &anchors,
            &leaf.chain[1..],
            time,
            KeyUsage::server_auth(),
            None,
            None,
        );
        let name = ServerName::try_from(hostname.to_owned()).unwrap();
        path.is_ok() && ee.verify_is_valid_for_subject_name(&name).is_ok()
    }

    /// One DER TLV: the tag, the content and the rest of `der`.
    fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
        let tag = der[0];
        let (len, start) = if der[1] < 0x80 {
            (usize::from(der[1]), 2)
        } else {
            let n = usize::from(der[1] & 0x7f);
            let len = der[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            (len, 2 + n)
        };
        (tag, &der[start..start + len], &der[start + len..])
    }

    /// The dNSName entries of a certificate's name constraints, as the
    /// permitted and the excluded sets.
    fn name_constraints(cert: &[u8]) -> (BTreeSet<String>, BTreeSet<String>) {
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x1e];
        let at = cert
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("a name constraints extension");
        let mut rest = &cert[at + OID.len()..];
        if rest[0] == 0x01 {
            rest = tlv(rest).2;
        }
        let (_, octets, _) = tlv(rest);
        let (_, seq, _) = tlv(octets);
        let mut sets = (BTreeSet::new(), BTreeSet::new());
        let mut subtrees = seq;
        while !subtrees.is_empty() {
            let (tag, mut list, next) = tlv(subtrees);
            while !list.is_empty() {
                let (_, subtree, more) = tlv(list);
                let (name_tag, name, _) = tlv(subtree);
                list = more;
                if name_tag == 0x87 {
                    // An iPAddress subtree: the IP sets hold these.
                    continue;
                }
                assert_eq!(name_tag, 0x82, "a dNSName subtree");
                let name = String::from_utf8(name.to_vec()).unwrap();
                match tag {
                    0xa0 => sets.0.insert(name),
                    0xa1 => sets.1.insert(name),
                    other => panic!("unexpected subtree tag {other:#x}"),
                };
            }
            subtrees = next;
        }
        sets
    }

    /// The subject Name and the SubjectPublicKeyInfo of a certificate.
    fn subject_and_key(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (_, cert, _) = tlv(cert);
        let (_, tbs, _) = tlv(cert);
        let mut fields = Vec::new();
        let mut rest = tbs;
        while !rest.is_empty() {
            let (tag, content, next) = tlv(rest);
            let whole = &rest[..rest.len() - next.len()];
            fields.push((tag, content, whole.to_vec()));
            rest = next;
        }
        // version, serial, signature, issuer, validity, subject, spki
        assert_eq!(fields[0].0, 0xa0);
        (fields[5].2.clone(), fields[6].2.clone())
    }

    fn leak_module(hosts: &[String]) -> Module {
        let hosts: Vec<Authority> = hosts
            .iter()
            .map(|host| Authority {
                host: Box::leak(host.clone().into_boxed_str()),
                port: HTTPS_PORT,
            })
            .collect();
        Module {
            id: "test",
            host_set_version: 1,
            hosts: Box::leak(hosts.into_boxed_slice()),
        }
    }

    fn host() -> impl Strategy<Value = String> {
        (
            prop::collection::vec("[a-z][a-z0-9]{0,6}", 1..3),
            prop::sample::select(vec!["com", "org", "io", "dev", "internal"]),
        )
            .prop_map(|(labels, tld)| format!("{}.{tld}", labels.join(".")))
    }

    fn denied_host() -> impl Strategy<Value = String> {
        (
            prop::option::of("[a-z]{1,6}"),
            prop::sample::select(DENY_SET.to_vec()),
        )
            .prop_map(|(label, deny)| match label {
                Some(label) => format!("{label}.{deny}"),
                None => deny.to_owned(),
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        // BEP-013
        #[test]
        fn prop_root_constraints_equal_registered_union(
            module_sets in prop::collection::vec(prop::collection::vec(host(), 0..4), 0..3),
            registered in prop::collection::vec(host(), 0..4),
            registered_ports in prop::collection::vec(prop::option::of(1u16..), 4),
            denied in prop::collection::vec(denied_host(), 0..3),
            outside in "[a-z]{1,8}",
        ) {
            let mut modules = vec![GITHUB];
            modules.extend(module_sets.iter().map(|hosts| leak_module(hosts)));
            let mut authorities: Vec<String> = registered
                .iter()
                .zip(registered_ports.iter().chain(std::iter::repeat(&None)))
                .map(|(host, port)| port.map_or_else(|| host.clone(), |p| format!("{host}:{p}")))
                .collect();
            authorities.extend(denied.iter().cloned());
            let union = Union::new(&modules, &authorities);

            let expected: BTreeSet<String> = GITHUB
                .hosts
                .iter()
                .map(|a| a.host.to_owned())
                .chain(module_sets.iter().flatten().cloned())
                .chain(registered.iter().cloned())
                .filter(|host| !denied_host_check(host))
                .collect();

            let (root_key, signing_key) = keys();
            let ca = Ca::new(&root_key, &signing_key, union, now()).unwrap();

            let (permitted, excluded) = name_constraints(ca.root());
            prop_assert_eq!(&permitted, &expected);
            prop_assert_eq!(
                excluded,
                DENY_SET.iter().map(|d| (*d).to_owned()).collect::<BTreeSet<_>>()
            );

            // A leaf for each name in the union validates against the root alone.
            for name in &expected {
                let leaf = ca.issue_leaf(name, now()).unwrap();
                prop_assert!(validates(ca.root(), &leaf, name), "{} did not validate", name);
            }

            // A leaf for a name outside the permitted subtrees fails, even
            // when the signing CA signs it.
            let outside = format!("{outside}.outside.test");
            prop_assert!(ca.issue_leaf(&outside, now()).is_err());
            let forged = ca.sign_leaf(&outside, now()).unwrap();
            prop_assert!(!validates(ca.root(), &forged, &outside));

            // A denied name is outside the union and outside the root.
            for name in &denied {
                prop_assert!(
                    matches!(ca.issue_leaf(name, now()), Err(CaError::OutsideUnion { .. })),
                    "{} was issued", name
                );
                let forged = ca.sign_leaf(name, now()).unwrap();
                prop_assert!(!validates(ca.root(), &forged, name));
            }

            // The proxy issues no leaf for a subdomain of a name in the union,
            // though the constraint admits one.
            for name in &expected {
                let sub = format!("sub.{name}");
                if !expected.contains(&sub) {
                    prop_assert!(ca.issue_leaf(&sub, now()).is_err());
                }
            }
        }
    }

    fn denied_host_check(host: &str) -> bool {
        DENY_SET
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    // BEP-013 (#2441): the root excludes every name of the decided deny set,
    // also when a store rule registers it or a name under it, and the names
    // the ruling leaves allowed stay registrable.
    #[test]
    fn root_excludes_every_deny_set_name() {
        assert_eq!(
            DENY_SET,
            [
                "min.internal",
                "minimal.dev",
                "cache.gominimal.dev",
                "minimal.farm"
            ]
        );
        let (root_key, signing_key) = keys();
        let allowed = ["printer.local", "nas.home.arpa", "svc.corp.internal"];
        let registered: Vec<String> = DENY_SET
            .iter()
            .flat_map(|name| [format!("{name}:443"), format!("api.{name}")])
            .chain(allowed.iter().map(|name| (*name).to_owned()))
            .collect();
        let ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], &registered),
            now(),
        )
        .unwrap();
        let (permitted, excluded) = name_constraints(ca.root());
        for name in DENY_SET {
            assert!(excluded.contains(*name), "{name} is not excluded");
            for host in [(*name).to_owned(), format!("api.{name}")] {
                assert!(!permitted.contains(&host), "{host} is permitted");
                assert!(!ca.union().contains(&host), "{host} is in the union");
                assert!(ca.issue_leaf(&host, now()).is_err(), "{host} got a leaf");
                let forged = ca.sign_leaf(&host, now()).unwrap();
                assert!(!validates(ca.root(), &forged, &host), "{host} validates");
            }
        }
        for name in allowed {
            assert!(permitted.contains(name), "{name} is not permitted");
            let leaf = ca.issue_leaf(name, now()).unwrap();
            assert!(
                validates(ca.root(), &leaf, name),
                "{name} does not validate"
            );
        }
        for name in [
            "localhost",
            "local",
            "home.arpa",
            "internal",
            "corp.internal",
        ] {
            assert!(!denied(name), "{name} is denied");
        }
    }

    #[test]
    fn github_leaves_validate_and_other_names_do_not() {
        let (root_key, signing_key) = keys();
        let ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        for authority in GITHUB.hosts {
            let leaf = ca.issue_leaf(authority.host, now()).unwrap();
            assert!(validates(ca.root(), &leaf, authority.host));
        }
        let err = ca.issue_leaf("example.com", now()).unwrap_err();
        assert!(
            matches!(err, CaError::OutsideUnion { ref hostname, .. } if hostname == "example.com")
        );
        let forged = ca.sign_leaf("example.com", now()).unwrap();
        assert!(!validates(ca.root(), &forged, "example.com"));
    }

    // BEP-013, BEP-072: the root comes from the held root key, carries the
    // union as its constraints, and anchors the CA that `bep serve` runs.
    #[test]
    fn root_certificate_is_issued_from_the_held_root_key() {
        let (root_key, signing_key) = keys();
        let union = Union::new(&[GITHUB], [""; 0]);
        let root = issue_root(&root_key, union.clone(), now()).unwrap();

        // Self-signed under the root key, with the root's subject.
        let (_, spki) = subject_and_key(root.der());
        assert!(spki.ends_with(&root_key.public().to_sec1_bytes()));
        let (permitted, excluded) = name_constraints(root.der());
        assert_eq!(permitted, union.names().map(str::to_owned).collect());
        assert_eq!(
            excluded,
            DENY_SET.iter().map(|name| (*name).to_owned()).collect()
        );

        // The CA keeps that root as its anchor, and its leaves validate
        // against it alone.
        let ca = Ca::with_root(&root_key, &signing_key, root.clone(), now()).unwrap();
        assert_eq!(ca.root(), root.der());
        assert_eq!(ca.union(), &union);
        let leaf = ca.issue_leaf("api.github.com", now()).unwrap();
        assert!(validates(root.der(), &leaf, "api.github.com"));

        // A changed union gets a root under the same key and subject.
        let changed = Union::new(&[GITHUB], ["api.anthropic.com:443"]);
        let again = issue_root(&root_key, changed.clone(), now()).unwrap();
        assert_eq!(subject_and_key(again.der()), subject_and_key(root.der()));
        assert_eq!(
            name_constraints(again.der()).0,
            changed.names().map(str::to_owned).collect()
        );
        assert!(validates(again.der(), &leaf, "api.github.com"));

        // Only the root key issues the root.
        assert!(matches!(
            issue_root(&signing_key, union.clone(), now()),
            Err(CaError::WrongRole {
                expected: Role::Root,
                got: Role::Signing
            })
        ));
        assert!(matches!(
            issue_root(&root_key, Union::default(), now()),
            Err(CaError::EmptyUnion)
        ));
        // A root past its expiry anchors no CA.
        let late = now() + ROOT_VALIDITY + Duration::from_secs(1);
        assert!(matches!(
            Ca::with_root(&root_key, &signing_key, root, late),
            Err(CaError::RootExpired(_))
        ));
    }

    #[test]
    fn ca_refuses_a_wrong_role_or_exportable_key() {
        let union = || Union::new(&[GITHUB], [""; 0]);
        let (root_key, signing_key) = keys();
        let sealing_key = TestKey::new(Role::Sealing);

        // One key for both roles, the roles swapped, and the sealing key.
        for (root, signing, expected, got) in [
            (&root_key, &root_key, Role::Signing, Role::Root),
            (&signing_key, &root_key, Role::Root, Role::Signing),
            (&root_key, &sealing_key, Role::Signing, Role::Sealing),
        ] {
            let err = Ca::new(root, signing, union(), now()).unwrap_err();
            assert!(
                matches!(err, CaError::WrongRole { expected: e, got: g } if e == expected && g == got),
                "{err:?}"
            );
        }

        let exportable = TestKey {
            exportable: true,
            ..TestKey::new(Role::Signing)
        };
        let err = Ca::new(&root_key, &exportable, union(), now()).unwrap_err();
        assert!(matches!(err, CaError::Exportable(Role::Signing)), "{err:?}");
    }

    #[test]
    fn empty_union_issues_no_root() {
        let (root_key, signing_key) = keys();
        let union = Union::new(&[], ["minimal.dev", "cache.minimal.dev:443"]);
        assert!(union.is_empty());
        assert!(matches!(
            Ca::new(&root_key, &signing_key, union, now()),
            Err(CaError::EmptyUnion)
        ));
    }

    /// The raw notAfter time of a certificate.
    fn not_after(cert: &[u8]) -> Vec<u8> {
        let (_, cert, _) = tlv(cert);
        let (_, tbs, _) = tlv(cert);
        let mut rest = tbs;
        // version, serial, signature, issuer, then validity
        for _ in 0..4 {
            rest = tlv(rest).2;
        }
        let (_, validity, _) = tlv(rest);
        let (_, _, after) = tlv(validity);
        tlv(after).1.to_vec()
    }

    // BEP-005: a start issues the root under the key's validity end, which
    // counts from the key's creation. A later start keeps the same end.
    #[test]
    fn root_certificate_ends_at_the_root_key_validity_end() {
        let (root_key, signing_key) = keys();
        let union = Union::new(&[GITHUB], [""; 0]);
        let ends = now() + Duration::from_secs(86_400);
        let first = issue_root_until(&root_key, union.clone(), now(), Some(ends)).unwrap();
        let later = now() + Duration::from_secs(3_600);
        let again = issue_root_until(&root_key, union.clone(), later, Some(ends)).unwrap();
        assert_eq!(not_after(first.der()), not_after(again.der()));
        let rolling = issue_root(&root_key, union.clone(), later).unwrap();
        assert_ne!(not_after(first.der()), not_after(rolling.der()));

        // The signing CA and a re-issued root keep the end.
        let mut ca = Ca::with_root(&root_key, &signing_key, first.clone(), now()).unwrap();
        assert_eq!(not_after(ca.signing()), not_after(first.der()));
        let changed = Union::new(&[GITHUB], ["api.anthropic.com:443"]);
        assert!(ca.reissue_root(changed, later).unwrap());
        assert_eq!(not_after(ca.root()), not_after(first.der()));

        // A root key past its end issues no certificate.
        assert!(matches!(
            issue_root_until(&root_key, union, ends, Some(ends)),
            Err(CaError::RootExpired(_))
        ));
    }

    #[test]
    fn leaf_never_outlives_signing_ca() {
        let (root_key, signing_key) = keys();
        let ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let host = GITHUB.hosts[0].host;
        let early = ca.issue_leaf(host, now()).unwrap();
        assert_ne!(not_after(&early.chain[0]), not_after(ca.signing()));
        let late = ca
            .issue_leaf(host, now() + SIGNING_VALIDITY - Duration::from_secs(DAY))
            .unwrap();
        assert_eq!(not_after(&late.chain[0]), not_after(ca.signing()));
        let expired = ca.issue_leaf(host, now() + SIGNING_VALIDITY);
        assert!(matches!(expired, Err(CaError::SigningExpired(_))));
    }

    #[test]
    fn signing_ca_renews_under_same_key_and_subject() {
        let (root_key, signing_key) = keys();
        let mut ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let host = GITHUB.hosts[0].host;
        let before = ca.signing().clone();
        let later = now() + SIGNING_VALIDITY;
        assert!(ca.issue_leaf(host, later).is_err());
        ca.renew_signing(later).unwrap();
        assert!(ca.signing_expiry() > later);
        assert_eq!(subject_and_key(&before), subject_and_key(ca.signing()));
        let leaf = ca.issue_leaf(host, later).unwrap();
        assert_eq!(leaf.chain[1], *ca.signing());
    }

    #[test]
    fn renewed_signing_ca_never_outlives_the_root() {
        let (root_key, signing_key) = keys();
        let mut ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let root_expiry = now() + ROOT_VALIDITY;
        let late = root_expiry - Duration::from_secs(30 * DAY);
        ca.renew_signing(late).unwrap();
        assert_eq!(not_after(ca.signing()), not_after(ca.root()));
        assert!(ca.issue_leaf(GITHUB.hosts[0].host, late).is_ok());
        let expired = ca.renew_signing(root_expiry);
        assert!(matches!(expired, Err(CaError::RootExpired(_))));
    }

    #[test]
    fn long_names_stay_within_dns_and_common_name_limits() {
        let label = "a".repeat(63);
        // 65 bytes: a valid DNS name, too long for a common name.
        let medium = format!("{}.com", "b".repeat(61));
        // 255 bytes: over the 253-byte limit of a DNS name.
        let long = format!("{label}.{label}.{label}.{label}");
        assert_eq!(medium.len(), 65);
        assert_eq!(long.len(), 255);
        let union = Union::new(&[], [medium.as_str(), long.as_str()]);
        assert_eq!(union.names().collect::<Vec<_>>(), [medium.as_str()]);

        let (root_key, signing_key) = keys();
        let ca = Ca::new(&root_key, &signing_key, union, now()).unwrap();
        let leaf = ca.issue_leaf(&medium, now()).unwrap();
        assert!(validates(ca.root(), &leaf, &medium));
        // The name occurs once in the leaf: in the SAN, not in a common name.
        let der = &leaf.chain[0];
        let count = der
            .windows(medium.len())
            .filter(|w| *w == medium.as_bytes())
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn ip_literal_authorities_are_not_in_the_union() {
        let union = Union::new(
            &[],
            [
                "[::1]:443",
                "::1",
                "127.0.0.1",
                "10.0.0.1:8080",
                "cache.example.com:443",
            ],
        );
        assert_eq!(union.names().collect::<Vec<_>>(), ["cache.example.com"]);
    }

    #[test]
    fn names_a_subtree_must_not_carry_are_not_in_the_union() {
        let union = Union::new(
            &[],
            [
                "com",
                "localhost:443",
                "*.github.com",
                ".example.com",
                "a..example.com",
                "bücher.example",
                "-bad.example.com",
                "ok.example.com",
            ],
        );
        assert_eq!(union.names().collect::<Vec<_>>(), ["ok.example.com"]);
    }

    /// The elements of a certificate's authority key identifier, as their
    /// tags.
    fn akid_tags(cert: &[u8]) -> Vec<u8> {
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x23];
        let at = cert
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("an authority key identifier extension");
        let mut rest = &cert[at + OID.len()..];
        if rest[0] == 0x01 {
            rest = tlv(rest).2;
        }
        let (_, octets, _) = tlv(rest);
        let (_, mut seq, _) = tlv(octets);
        let mut tags = Vec::new();
        while !seq.is_empty() {
            let (tag, _, next) = tlv(seq);
            tags.push(tag);
            seq = next;
        }
        tags
    }

    /// The authority key identifier extension value of `cert`.
    fn akid(cert: &[u8]) -> Vec<u8> {
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x23];
        let at = cert
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("an authority key identifier extension");
        let mut rest = &cert[at + OID.len()..];
        if rest[0] == 0x01 {
            rest = tlv(rest).2;
        }
        tlv(rest).1.to_vec()
    }

    // BEP-061: a box holds the root alone. The rotation leaves the root as
    // it was, so leaves from the old and the new signing CA both validate
    // against the trust store the box got at creation.
    #[test]
    fn signing_ca_rotation_invisible_to_boxes() {
        let (root_key, signing_key) = keys();
        let mut ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let host = GITHUB.hosts[0].host;
        let box_trust = ca.root().clone();
        let before = ca.signing().clone();
        let old_leaf = ca.issue_leaf(host, now()).unwrap();

        ca.renew_signing(now()).unwrap();

        assert_eq!(*ca.root(), box_trust, "the root changed");
        assert_ne!(*ca.signing(), before, "no new signing CA was issued");
        assert_eq!(akid(ca.signing()), akid(&before));
        assert_eq!(subject_and_key(ca.signing()), subject_and_key(&before));
        let new_leaf = ca.issue_leaf(host, now()).unwrap();
        assert_eq!(new_leaf.chain[1], *ca.signing());
        assert!(validates(&box_trust, &new_leaf, host));
        assert!(validates(&box_trust, &old_leaf, host));
    }

    #[test]
    fn signing_ca_and_leaf_carry_a_keyid_only_akid() {
        let (root_key, signing_key) = keys();
        let ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let leaf = ca.issue_leaf("github.com", now()).unwrap();
        // [0] keyIdentifier alone: no authorityCertIssuer, no serial number.
        assert_eq!(akid_tags(ca.signing()), [0x80]);
        assert_eq!(akid_tags(&leaf.chain[0]), [0x80]);
    }

    #[test]
    fn ip_address_leaf_fails_against_the_root() {
        let (root_key, signing_key) = keys();
        let ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        for ip in ["10.0.0.1", "::1"] {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut params = CertificateParams::default();
            params.subject_alt_names = vec![SanType::IpAddress(ip.parse().unwrap())];
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.use_authority_key_identifier_extension = true;
            validity(&mut params, now(), LEAF_VALIDITY);
            let cert = params
                .signed_by(
                    &key,
                    &Issuer::from_params(&ca.signing_params, &ca.signing_key),
                )
                .unwrap();
            let forged = Leaf {
                hostname: ip.to_owned(),
                chain: vec![cert.der().clone(), ca.signing().clone()],
                key: Zeroizing::new(key.serialize_der()),
            };
            assert!(!validates(ca.root(), &forged, ip), "{ip} validated");
        }
    }

    // BEP-013
    #[test]
    fn root_recertified_under_same_key_and_subject() {
        let (root_key, signing_key) = keys();
        let mut ca = Ca::new(
            &root_key,
            &signing_key,
            Union::new(&[GITHUB], [""; 0]),
            now(),
        )
        .unwrap();
        let first = ca.root().clone();
        let before = ca.issue_leaf("api.github.com", now()).unwrap();

        let union = Union::new(&[GITHUB], ["api.anthropic.com:443"]);
        assert!(
            !ca.reissue_root(Union::new(&[GITHUB], [""; 0]), now())
                .unwrap()
        );
        assert_eq!(ca.root(), &first, "an unchanged union issues no root");
        assert!(ca.reissue_root(union.clone(), now()).unwrap());
        let second = ca.root().clone();

        assert_ne!(first, second);
        assert_eq!(subject_and_key(&first), subject_and_key(&second));
        let (old_permitted, _) = name_constraints(&first);
        let (new_permitted, _) = name_constraints(&second);
        assert!(!old_permitted.contains("api.anthropic.com"));
        assert_eq!(new_permitted, union.names().map(str::to_owned).collect());

        // The added authority validates against the new root, and not against
        // the root a running box still holds.
        let added = ca.issue_leaf("api.anthropic.com", now()).unwrap();
        assert!(validates(&second, &added, "api.anthropic.com"));
        assert!(!validates(&first, &added, "api.anthropic.com"));

        // A box with the first root keeps validating the names it permitted,
        // for leaves issued before and after the re-issue.
        let after = ca.issue_leaf("api.github.com", now()).unwrap();
        assert!(validates(&first, &before, "api.github.com"));
        assert!(validates(&first, &after, "api.github.com"));
        assert!(validates(&second, &before, "api.github.com"));
    }

    #[test]
    fn refused_signing_key_is_a_key_error() {
        struct Refusing(TestKey);
        impl HeldKey for Refusing {
            fn role(&self) -> Role {
                self.0.role()
            }
            fn public(&self) -> ProxyPublicKey {
                self.0.public()
            }
            fn exportable(&self) -> bool {
                false
            }
            fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
                self.0.agree(peer)
            }
            fn probe(&self) -> Result<(), KeyError> {
                Ok(())
            }
        }
        impl CaKey for Refusing {
            fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, KeyError> {
                Err(KeyError::Refused {
                    role: self.0.role,
                    detail: "refused".into(),
                })
            }
        }
        let root = Refusing(TestKey::new(Role::Root));
        let signing = Refusing(TestKey::new(Role::Signing));
        let err = Ca::new(&root, &signing, Union::new(&[GITHUB], [""; 0]), now()).unwrap_err();
        assert!(matches!(
            err,
            CaError::Key(KeyError::Refused {
                role: Role::Root,
                ..
            })
        ));
    }
}
