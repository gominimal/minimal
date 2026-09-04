//! Certificates in both directions, transport-agnostic.
//!
//! - The client presents a Gatehouse-shaped user certificate and signs the
//!   SSH auth request with a key it may not hold itself (a WebCrypto key in a
//!   tab, an agent, a keychain): [`RawSigner`] is that seam, [`SshSigner`]
//!   does the SSH encoding russh expects.
//! - The client verifies the host's certificate against Host CA anchors and
//!   an expected principal ([`HostPolicy`]) instead of accepting any key.
//! - A daemon verifies a user certificate the same way ([`verify_user_cert`]).
//!
//! The decision functions name their refusals with the codes from
//! gominimal/arch `specs/authn-authz/vectors/ssh-certs/invalid/manifest.json`,
//! and are tested against those vectors at the manifest's fixed clock.

use std::future::Future;

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{self, Fingerprint, HashAlg};
use russh::keys::{Algorithm, Certificate, PublicKey};

/// Why a certificate was refused. `code()` is the manifest's `expected_error`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    #[error("certificate signature does not verify")]
    BadSignature,
    #[error("certificate is not signed by a trusted CA")]
    UnknownCa,
    #[error("certificate has the wrong type")]
    WrongCertType,
    #[error("certificate is not yet valid")]
    NotYetValid,
    #[error("certificate has expired")]
    Expired,
    #[error("certificate carries an unknown critical option: {0}")]
    UnknownCriticalOption(String),
    #[error("certificate serial is revoked")]
    Revoked,
    #[error("certificate principals do not include {0}")]
    PrincipalMismatch(String),
    #[error("malformed: {0}")]
    Malformed(String),
}

impl CertError {
    pub fn code(&self) -> &'static str {
        match self {
            CertError::BadSignature => "bad_signature",
            CertError::UnknownCa => "unknown_ca",
            CertError::WrongCertType => "wrong_cert_type",
            CertError::NotYetValid => "cert_not_yet_valid",
            CertError::Expired => "cert_expired",
            CertError::UnknownCriticalOption(_) => "unknown_critical_option",
            CertError::Revoked => "cert_revoked",
            CertError::PrincipalMismatch(_) => "principal_mismatch",
            CertError::Malformed(_) => "malformed",
        }
    }
}

/// Critical options a Gatehouse cert may carry (spec §5.3: "nothing custom";
/// unknown ones make the certificate invalid, as OpenSSH does).
const KNOWN_CRITICAL_OPTIONS: &[&str] = &["source-address", "force-command", "verify-required"];

/// CA public keys a certificate may chain to, by SHA-256 fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    fingerprints: Vec<Fingerprint>,
}

impl Anchors {
    /// From OpenSSH public key lines (`ssh-ed25519 AAAA... comment`).
    pub fn from_openssh_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Result<Self, CertError> {
        let mut fingerprints = Vec::new();
        for line in lines {
            let key = PublicKey::from_openssh(line.trim())
                .map_err(|e| CertError::Malformed(format!("CA public key: {e}")))?;
            fingerprints.push(key.fingerprint(HashAlg::Sha256));
        }
        Ok(Self { fingerprints })
    }

    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.fingerprints.iter().any(|f| f == fp)
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

/// The checks every certificate gets, in an order where each vector's single
/// defect is reported by its own code: self-signature, CA, type, validity
/// window, critical options, revocation.
pub fn verify_certificate(
    cert: &Certificate,
    anchors: &Anchors,
    expected: CertType,
    now: u64,
    revoked: impl Fn(u64) -> bool,
) -> Result<(), CertError> {
    if cert.verify_signature().is_err() {
        return Err(CertError::BadSignature);
    }
    if !anchors.contains(&cert.signature_key().fingerprint(HashAlg::Sha256)) {
        return Err(CertError::UnknownCa);
    }
    if cert.cert_type() != expected {
        return Err(CertError::WrongCertType);
    }
    if now < cert.valid_after() {
        return Err(CertError::NotYetValid);
    }
    if now >= cert.valid_before() {
        return Err(CertError::Expired);
    }
    for name in cert.critical_options().0.keys() {
        if !KNOWN_CRITICAL_OPTIONS.contains(&name.as_str()) {
            return Err(CertError::UnknownCriticalOption(name.clone()));
        }
    }
    if revoked(cert.serial()) {
        return Err(CertError::Revoked);
    }
    Ok(())
}

/// A daemon's decision on a user certificate presented for `username`.
pub fn verify_user_cert(
    cert: &Certificate,
    anchors: &Anchors,
    username: &str,
    now: u64,
    revoked: impl Fn(u64) -> bool,
) -> Result<(), CertError> {
    verify_certificate(cert, anchors, CertType::User, now, revoked)?;
    if !cert.valid_principals().iter().any(|p| p == username) {
        return Err(CertError::PrincipalMismatch(username.to_string()));
    }
    Ok(())
}

/// A client's decision on a host certificate: chains to a Host CA anchor and
/// names `expected` (exactly, or through a per-node wildcard `*.<suffix>`).
pub fn verify_host_cert(
    cert: &Certificate,
    anchors: &Anchors,
    expected: &str,
    now: u64,
) -> Result<(), CertError> {
    verify_certificate(cert, anchors, CertType::Host, now, |_| false)?;
    let matches = cert.valid_principals().iter().any(|p| {
        p == expected
            || p
                .strip_prefix("*.")
                .is_some_and(|suffix| expected.ends_with(&format!(".{suffix}")))
    });
    if !matches {
        return Err(CertError::PrincipalMismatch(expected.to_string()));
    }
    Ok(())
}

/// What the client demands of the host: a certificate from one of these CAs
/// naming this principal. A bare host key is refused.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    pub anchors: Anchors,
    pub expected_principal: String,
}

impl HostPolicy {
    pub fn check(&self, presented: &russh::keys::PublicKeyOrCertificate, now: u64) -> Result<(), CertError> {
        match presented {
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
                verify_host_cert(cert, &self.anchors, &self.expected_principal, now)
            }
            russh::keys::PublicKeyOrCertificate::PublicKey { .. } => {
                Err(CertError::Malformed("host presented a bare key, a certificate is required".into()))
            }
        }
    }
}

/// Signs raw bytes with a key the core does not hold: a WebCrypto key behind
/// a JS callback, an agent, a keychain, or (in tests) an in-memory key.
/// Returns the raw signature blob (64 bytes for Ed25519).
pub trait RawSigner: Send {
    fn sign_raw(&mut self, data: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("signing: {0}")]
pub struct SignError(pub String);

impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        SignError("ssh session went away during authentication".into())
    }
}

/// russh's `Signer` over a [`RawSigner`]: russh hands over its whole to-sign
/// buffer (session id ‖ USERAUTH_REQUEST) and expects it back extended with
/// the SSH-encoded signature, `string( string algorithm ‖ string blob )`.
pub struct SshSigner<S> {
    inner: S,
    algorithm: Algorithm,
}

impl<S: RawSigner> SshSigner<S> {
    pub fn new(inner: S, algorithm: Algorithm) -> Self {
        Self { inner, algorithm }
    }
}

impl<S: RawSigner> russh::Signer for SshSigner<S> {
    type Error = SignError;

    fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            let raw = self.inner.sign_raw(&to_sign).await.map_err(SignError)?;
            let signature = ssh_key::Signature::new(self.algorithm.clone(), raw)
                .map_err(|e| SignError(format!("signature blob: {e}")))?;
            let mut out = to_sign;
            use russh::keys::ssh_encoding::Encode as _;
            let mut encoded = Vec::new();
            signature
                .encode(&mut encoded)
                .map_err(|e| SignError(format!("encode signature: {e}")))?;
            encoded
                .encode(&mut out)
                .map_err(|e| SignError(format!("encode signature: {e}")))?;
            Ok(out)
        }
    }
}

/// The client's presented identity.
pub struct Credential<S> {
    pub username: String,
    pub certificate: Certificate,
    pub signer: S,
}

impl<S> Credential<S> {
    /// The signature algorithm the certificate's key demands.
    pub fn algorithm(&self) -> Algorithm {
        self.certificate.public_key().algorithm()
    }
}

/// An in-memory Ed25519 key as a [`RawSigner`] (native tests and the CLI's
/// keychain-less path).
#[cfg(not(target_arch = "wasm32"))]
pub struct KeySigner(pub russh::keys::PrivateKey);

#[cfg(not(target_arch = "wasm32"))]
impl RawSigner for KeySigner {
    fn sign_raw(&mut self, data: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        use russh::keys::signature::Signer as _;
        let result = self
            .0
            .try_sign(data)
            .map(|sig| sig.as_bytes().to_vec())
            .map_err(|e| e.to_string());
        async move { result }
    }
}

/// `ssh-ed25519 AAAA...` for a raw 32-byte Ed25519 public key — what a page
/// gets from `crypto.subtle.exportKey("raw", publicKey)`.
pub fn ssh_public_key_from_ed25519_raw(raw: &[u8]) -> Result<String, CertError> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| CertError::Malformed("ed25519 public key must be 32 bytes".into()))?;
    let key = PublicKey::from(ssh_key::public::Ed25519PublicKey(bytes));
    key.to_openssh().map_err(|e| CertError::Malformed(e.to_string()))
}
