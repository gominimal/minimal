//! The host's interception certificates: the root a box is given to trust, the
//! one name-constrained signing certificate under it, and the per-hostname
//! leaves the proxy presents on a flow it terminated.
//!
//! One signing certificate per host, not one per box (BEP-014, BEP-059 to
//! BEP-061). It is constrained to the union of the credentialed upstream sets
//! every box on the host declares, so nothing the host's boxes did not ask for
//! can ever be impersonated under the injected root (BEP-013). X.509 permitted
//! subtrees admit a name's subdomains (RFC 5280 §4.2.1.10), so the constraint
//! is a ceiling and never the admission rule: exact admission happens at leaf
//! issuance, which refuses every name outside the union. A box's own reach
//! inside the union is narrower still, bounded by its egress declaration and by
//! its sealed values' host sets.
//!
//! Both CA private keys stay in the host key store: rcgen encodes the
//! certificate and hands the bytes to be signed back through
//! [`PrivateKey`](crate::keychain::PrivateKey), so nothing but a signature
//! crosses the seam. Each leaf carries a freshly generated key pair of its own,
//! since the proxy terminates TLS with it.

use std::fmt;

use p256::PublicKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PublicKeyData,
    SignatureAlgorithm, SigningKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keychain::{KeyStore, PrivateKey};
use crate::keys::{KeyRole, Keys};

/// The union of the credentialed upstream sets the boxes on this host declare:
/// the permitted names the host's signing certificate carries.
///
/// A name is lowercased and stripped of a trailing dot, so one hostname
/// declared in two spellings is one name. A name that normalises to nothing is
/// dropped: an empty permitted subtree admits every name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclaredUnion {
    names: Vec<String>,
}

impl DeclaredUnion {
    /// The union of `declarations`, one declaration per box on the host.
    #[must_use]
    pub fn of<D, S, N>(declarations: D) -> Self
    where
        D: IntoIterator<Item = S>,
        S: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        let mut names: Vec<String> = declarations
            .into_iter()
            .flatten()
            .filter_map(|name| {
                let name = normalize(name.as_ref());
                (!name.is_empty()).then_some(name)
            })
            .collect();
        names.sort();
        names.dedup();
        Self { names }
    }

    /// The declared names, sorted and deduplicated: the permitted-names
    /// constraint of the signing certificate derived from them.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether `host` is one of the declared names. Exact: a subdomain of a
    /// declared name is not itself declared, though the X.509 constraint
    /// permits it.
    #[must_use]
    pub fn admits(&self, host: &str) -> bool {
        self.names.binary_search(&normalize(host)).is_ok()
    }

    /// Whether no box on the host declares a credentialed upstream.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The constraint version: a digest over the declared names, carried by
    /// every certificate log line and by the support bundle, so a signing
    /// certificate can be matched to the declarations it was derived from.
    #[must_use]
    pub fn version(&self) -> String {
        let mut digest = Sha256::new();
        for name in &self.names {
            digest.update(name.as_bytes());
            digest.update([0]);
        }
        format!("sha256:{}", hex::encode(digest.finalize()))
    }
}

/// Why a certificate could not be issued.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// No box on the host declares a credentialed upstream, so there is no
    /// union to constrain a signing certificate to. An unconstrained signing
    /// certificate is never issued.
    #[error("no box on this host declares a credentialed upstream")]
    NothingDeclared,
    /// A leaf was asked for a name no box on the host declares.
    #[error("{host} is not one of the {declared} names the host's boxes declare")]
    Undeclared { host: String, declared: usize },
    /// A certificate could not be built or signed.
    #[error("the {subject} certificate could not be issued: {source}")]
    Issue {
        subject: String,
        #[source]
        source: rcgen::Error,
    },
}

/// Normalises a declared or requested hostname to the one spelling the
/// constraint and the admission check compare.
fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn issue(subject: impl Into<String>) -> impl FnOnce(rcgen::Error) -> CaError {
    let subject = subject.into();
    move |source| CaError::Issue { subject, source }
}

/// A store-held key as rcgen's signing seam: rcgen encodes the certificate, the
/// store signs it, and the private half never crosses the seam.
struct StoreKey<'k, K> {
    key: &'k K,
    /// The uncompressed SEC1 point, the form X.509 carries a P-256 public key
    /// in.
    point: Vec<u8>,
}

impl<'k, K> StoreKey<'k, K> {
    fn new(key: &'k K, public: &PublicKey) -> Self {
        Self {
            key,
            point: public.to_sec1_point(false).as_bytes().to_vec(),
        }
    }
}

impl<K> PublicKeyData for StoreKey<'_, K> {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl<K: PrivateKey> SigningKey for StoreKey<'_, K> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key.sign(message).map_err(|error| {
            // rcgen's seam carries no cause, so the store's own message is
            // reported here rather than lost.
            tracing::error!(%error, "the key store refused to sign a certificate");
            rcgen::Error::RemoteKeyError
        })
    }
}

/// A leaf certificate and its key, as the proxy presents them on one
/// intercepted flow.
pub struct Leaf {
    host: String,
    cert_der: Vec<u8>,
    signing_der: Vec<u8>,
    key_der: Zeroizing<Vec<u8>>,
}

impl Leaf {
    /// The hostname the leaf was issued for.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The leaf certificate, DER.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The chain the proxy presents, in the order a TLS server sends it: the
    /// leaf, then the signing certificate that chains it to the injected root.
    #[must_use]
    pub fn chain_der(&self) -> [&[u8]; 2] {
        [&self.cert_der, &self.signing_der]
    }

    /// The leaf's private key, `PKCS#8` DER. Generated for this leaf alone; the
    /// CA keys never leave the store.
    #[must_use]
    pub fn private_key_der(&self) -> &[u8] {
        &self.key_der
    }
}

impl fmt::Debug for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leaf")
            .field("host", &self.host)
            .field("key_der", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The host's interception certificates, open over the host's keys.
pub struct Authority<'k, K: PrivateKey> {
    union: DeclaredUnion,
    version: String,
    root_der: Vec<u8>,
    signing_der: Vec<u8>,
    signing: Issuer<'static, StoreKey<'k, K>>,
}

impl<'k, K: PrivateKey> Authority<'k, K> {
    /// Issues the host's root certificate and the one signing certificate under
    /// it, with the signing certificate's permitted names constrained to
    /// `union`.
    ///
    /// # Errors
    ///
    /// [`CaError::NothingDeclared`] when no box on the host declares a
    /// credentialed upstream, or [`CaError::Issue`] when the store refuses to
    /// sign or a declared name is no valid DNS name.
    pub fn open<S>(keys: &'k Keys<S>, union: DeclaredUnion) -> Result<Self, CaError>
    where
        S: KeyStore<Key = K>,
    {
        if union.is_empty() {
            return Err(CaError::NothingDeclared);
        }
        let root_key = StoreKey::new(keys.key(KeyRole::Root), keys.public_key(KeyRole::Root));
        let signing_key = StoreKey::new(
            keys.key(KeyRole::Signing),
            keys.public_key(KeyRole::Signing),
        );

        // One intermediate under the root, no CA under the signing
        // certificate: the only thing it may issue is a leaf.
        let root_params = ca_params("Minimal box egress proxy root", 1, None);
        let root_cert = root_params.self_signed(&root_key).map_err(issue("root"))?;
        let root_issuer = Issuer::new(root_params, root_key);

        let signing_params = ca_params(
            "Minimal box egress proxy signing",
            0,
            Some(permitted_subtrees(&union)),
        );
        let signing_cert = signing_params
            .signed_by(&signing_key, &root_issuer)
            .map_err(issue("signing"))?;

        let version = union.version();
        tracing::info!(
            root = %keys.fingerprint(KeyRole::Root),
            signing = %keys.fingerprint(KeyRole::Signing),
            names = union.names().len(),
            constraint = %version,
            "issued the host signing certificate"
        );

        Ok(Self {
            root_der: root_cert.der().to_vec(),
            signing_der: signing_cert.der().to_vec(),
            signing: Issuer::new(signing_params, signing_key),
            union,
            version,
        })
    }

    /// The root certificate, DER: the trust anchor injected into a box.
    #[must_use]
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The signing certificate, DER: the host's one name-constrained issuer of
    /// leaves.
    #[must_use]
    pub fn signing_der(&self) -> &[u8] {
        &self.signing_der
    }

    /// The union the signing certificate's permitted names were derived from.
    #[must_use]
    pub fn union(&self) -> &DeclaredUnion {
        &self.union
    }

    /// The constraint version the certificate log lines and the support bundle
    /// carry.
    #[must_use]
    pub fn constraint_version(&self) -> &str {
        &self.version
    }

    /// Issues a leaf for `host`. A declared name alone gets one: the X.509
    /// constraint admits a declared name's subdomains, this does not.
    ///
    /// # Errors
    ///
    /// [`CaError::Undeclared`] when no box on the host declares `host`, or
    /// [`CaError::Issue`] when the key pair or the certificate cannot be made.
    pub fn issue_leaf(&self, host: &str) -> Result<Leaf, CaError> {
        let host = normalize(host);
        if !self.union.admits(&host) {
            return Err(CaError::Undeclared {
                host,
                declared: self.union.names().len(),
            });
        }
        self.sign_leaf(&host)
    }

    /// Signs a leaf for `host` under the signing certificate, admission
    /// already decided: [`Self::issue_leaf`] is the way in.
    fn sign_leaf(&self, host: &str) -> Result<Leaf, CaError> {
        let key = KeyPair::generate().map_err(issue(host))?;
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(issue(host))?;
        params.distinguished_name = distinguished_name(host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.signing).map_err(issue(host))?;
        tracing::info!(host, constraint = %self.version, "issued a leaf certificate");
        Ok(Leaf {
            host: host.to_owned(),
            cert_der: cert.der().to_vec(),
            signing_der: self.signing_der.clone(),
            key_der: Zeroizing::new(key.serialize_der()),
        })
    }
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

fn ca_params(
    common_name: &str,
    path_len: u8,
    name_constraints: Option<NameConstraints>,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params.name_constraints = name_constraints;
    params
}

/// The permitted `dNSName` subtrees for `union`. Excluded subtrees stay empty:
/// the permitted set is the whole statement of what the host's boxes declared.
fn permitted_subtrees(union: &DeclaredUnion) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: union
            .names()
            .iter()
            .map(|name| GeneralSubtree::DnsName(name.clone()))
            .collect(),
        excluded_subtrees: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::prelude::*;
    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;
    use crate::keychain::MemoryStore;

    /// The names a box may declare: a GitHub credentialed upstream set, with
    /// two spellings that normalise onto one name.
    const DECLARABLE: [&str; 6] = [
        "github.com",
        "API.github.com",
        "api.github.com.",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "ghcr.io",
    ];

    /// Names no box declares, and that no subtree of any declarable name
    /// permits — the last two are the suffix-confusion shapes.
    const OUTSIDE: [&str; 4] = [
        "evil.test",
        "notgithub.com",
        "github.com.evil.test",
        "api.github.com.evil.test",
    ];

    /// Reads one DER tag-length-value, returning the tag, the value and what
    /// follows it.
    fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
        let (tag, rest) = der.split_first().expect("a tag");
        let (first, rest) = rest.split_first().expect("a length");
        let (len, rest) = match *first {
            0x81 => {
                let (len, rest) = rest.split_first().expect("a one-byte length");
                (usize::from(*len), rest)
            }
            0x82 => {
                let (len, rest) = rest.split_at(2);
                (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
            }
            len => {
                assert!(len < 0x80, "unsupported DER length form {len:#x}");
                (usize::from(len), rest)
            }
        };
        let (value, rest) = rest.split_at(len);
        (*tag, value, rest)
    }

    /// The permitted `dNSName` subtrees the signing certificate carries, read
    /// back out of its DER by the same code path a box's TLS client uses,
    /// never from the value that wrote them.
    fn permitted_dns_names(signing_der: &[u8]) -> Vec<String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(signing_der.to_vec()))
            .expect("the signing certificate parses");
        let constraints = roots
            .roots
            .first()
            .expect("one anchor")
            .name_constraints
            .as_ref()
            .expect("the signing certificate carries a name-constraints extension")
            .as_ref()
            .to_vec();
        // The contents of the NameConstraints SEQUENCE: a `[0]` permitted
        // subtrees, each a SEQUENCE whose base is a `[2]` dNSName.
        let (tag, permitted, _) = tlv(&constraints);
        assert_eq!(tag, 0xa0, "permitted subtrees come first");
        let mut names = Vec::new();
        let mut rest = permitted;
        while !rest.is_empty() {
            let (tag, subtree, next) = tlv(rest);
            assert_eq!(tag, 0x30, "a general subtree is a SEQUENCE");
            let (tag, name, _) = tlv(subtree);
            assert_eq!(tag, 0x82, "the base is a dNSName");
            names.push(String::from_utf8(name.to_vec()).expect("an IA5 string"));
            rest = next;
        }
        names
    }

    /// A verifier over the root as a box's trust store holds it.
    fn verifier(root_der: &[u8]) -> Arc<WebPkiServerVerifier> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_der.to_vec()))
            .expect("the root parses");
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("a verifier over the injected root")
    }

    /// Whether `leaf`'s chain validates for `host` against the injected root,
    /// name constraints included.
    fn validates(verifier: &WebPkiServerVerifier, leaf: &Leaf, host: &str) -> bool {
        let [end_entity, signing] = leaf.chain_der();
        verifier
            .verify_server_cert(
                &CertificateDer::from(end_entity.to_vec()),
                &[CertificateDer::from(signing.to_vec())],
                &ServerName::try_from(host.to_owned()).expect("a DNS name"),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    /// Any family of declared credentialed upstream sets on a host: one set per
    /// box, a box that declares none included.
    fn arb_declarations() -> impl Strategy<Value = Vec<Vec<String>>> {
        prop::collection::vec(
            prop::collection::vec(
                prop::sample::select(DECLARABLE.to_vec()).prop_map(str::to_owned),
                0..DECLARABLE.len(),
            ),
            0..4,
        )
    }

    proptest! {
        // Each case builds a root, a signing certificate and a leaf per name,
        // so the case count stays well under proptest's default.
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// BEP-013: the signing certificate's permitted names are exactly the
        /// union the host's boxes declare; a leaf for a declared name
        /// validates against the injected root through it; a leaf for a name
        /// outside the permitted subtrees does not, even signed by this
        /// signing certificate; and only a declared name is issued one.
        #[test]
        fn prop_signing_ca_constraints_equal_declared_union(declared in arb_declarations()) {
            let keys = Keys::open(MemoryStore::new()).expect("the key set opens");
            let union = DeclaredUnion::of(declared);
            let authority = match Authority::open(&keys, union.clone()) {
                Ok(authority) => authority,
                Err(error) => {
                    prop_assert!(union.is_empty(), "a declared union was refused: {}", error);
                    return Ok(());
                }
            };

            prop_assert_eq!(
                permitted_dns_names(authority.signing_der()),
                union.names().to_vec()
            );
            prop_assert_eq!(authority.constraint_version(), union.version());

            let verifier = verifier(authority.root_der());

            for name in union.names() {
                let leaf = authority
                    .issue_leaf(name)
                    .expect("a declared name gets a leaf");
                prop_assert_eq!(leaf.host(), name.as_str());
                prop_assert!(
                    validates(&verifier, &leaf, name),
                    "a leaf for the declared {} does not validate",
                    name
                );
            }

            for outside in OUTSIDE {
                prop_assert!(
                    union.names().iter().all(|name| {
                        outside != name.as_str() && !outside.ends_with(&format!(".{name}"))
                    }),
                    "{} is inside a permitted subtree",
                    outside
                );
                // Signed under this very signing certificate, bypassing
                // issuance: the constraint alone must refuse it.
                let leaf = authority
                    .sign_leaf(outside)
                    .expect("the signing certificate signs it");
                prop_assert!(
                    !validates(&verifier, &leaf, outside),
                    "a leaf for the undeclared {} validated",
                    outside
                );
            }

            for candidate in DECLARABLE.iter().chain(OUTSIDE.iter()) {
                prop_assert_eq!(
                    authority.issue_leaf(candidate).is_ok(),
                    union.admits(candidate),
                    "issuance and the declared union disagree over {}",
                    candidate
                );
            }
        }
    }

    /// A host whose boxes declare nothing, or nothing that is a name, gets no
    /// signing certificate: an empty permitted-subtrees constraint would admit
    /// every name on the internet.
    #[test]
    fn no_signing_certificate_without_a_declared_name() {
        let keys = Keys::open(MemoryStore::new()).unwrap();
        for declared in [
            vec![],
            vec![vec![]],
            vec![vec![String::new(), " . ".into()]],
        ] {
            let union = DeclaredUnion::of(declared);
            assert!(union.is_empty(), "{union:?} should have no names");
            assert!(matches!(
                Authority::open(&keys, union),
                Err(CaError::NothingDeclared)
            ));
        }
    }
}
