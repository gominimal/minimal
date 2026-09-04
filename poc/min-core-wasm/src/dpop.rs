//! The public-client login pieces the tab shares with the CLI: PKCE (RFC
//! 7636), the DPoP key thumbprint (RFC 7638 over the OKP JWK), and DPoP
//! proofs (RFC 9449) signed through the same [`RawSigner`] the SSH auth uses.
//! HTTP itself is the host's job; these produce and consume bytes and JSON.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Serialize;

use crate::credential::RawSigner;

pub fn b64url(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    digest.as_ref().try_into().expect("sha256 is 32 bytes")
}

/// `code_challenge` (S256) for a `code_verifier`.
pub fn pkce_challenge(verifier: &str) -> String {
    b64url(&sha256(verifier.as_bytes()))
}

/// A fresh 43-character `code_verifier`.
pub fn pkce_verifier() -> Result<String, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    Ok(b64url(&seed))
}

/// The DPoP key as a public JWK (OKP / Ed25519), members in thumbprint order.
#[derive(Serialize)]
pub struct Ed25519Jwk {
    pub crv: &'static str,
    pub kty: &'static str,
    pub x: String,
}

impl Ed25519Jwk {
    pub fn new(raw_public: &[u8]) -> Self {
        Self {
            crv: "Ed25519",
            kty: "OKP",
            x: b64url(raw_public),
        }
    }

    /// RFC 7638 thumbprint: SHA-256 over the canonical `{"crv","kty","x"}`.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#, self.crv, self.kty, self.x);
        b64url(&sha256(canonical.as_bytes()))
    }
}

/// `dpop_jkt` for a raw Ed25519 public key.
pub fn dpop_jkt_ed25519(raw_public: &[u8]) -> String {
    Ed25519Jwk::new(raw_public).thumbprint()
}

#[derive(Serialize)]
struct Header<'a> {
    typ: &'static str,
    alg: &'static str,
    jwk: &'a Ed25519Jwk,
}

#[derive(Serialize)]
struct Claims<'a> {
    jti: String,
    htm: &'a str,
    htu: &'a str,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

/// A DPoP proof JWS (`typ: dpop+jwt`, `alg: EdDSA`) for one request.
/// `access_token`, when bound, becomes the `ath` claim (its SHA-256).
pub async fn dpop_proof<S: RawSigner>(
    raw_public: &[u8],
    htm: &str,
    htu: &str,
    iat: u64,
    nonce: Option<&str>,
    access_token: Option<&str>,
    signer: &mut S,
) -> Result<String, String> {
    let jwk = Ed25519Jwk::new(raw_public);
    let header = serde_json::to_vec(&Header {
        typ: "dpop+jwt",
        alg: "EdDSA",
        jwk: &jwk,
    })
    .map_err(|e| e.to_string())?;
    let mut jti = [0u8; 16];
    getrandom::getrandom(&mut jti).map_err(|e| e.to_string())?;
    let claims = serde_json::to_vec(&Claims {
        jti: b64url(&jti),
        htm,
        htu,
        iat,
        nonce,
        ath: access_token.map(|t| b64url(&sha256(t.as_bytes()))),
    })
    .map_err(|e| e.to_string())?;
    let signing_input = format!("{}.{}", b64url(&header), b64url(&claims));
    let signature = signer.sign_raw(signing_input.as_bytes()).await?;
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}
