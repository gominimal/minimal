//! The GitHub module's sign-in on an un-enrolled host: the two OAuth flows
//! under the Minimal-published GitHub App, the material a completed sign-in
//! leaves behind, and the host store that holds it.
//!
//! Both flows need a `client_id`, so the client presents [`MINIMAL_APP`] and
//! the App's registration is the member's ceiling (BEP-001). The device flow
//! is the reference profile: a code the operator enters at GitHub, polled
//! until GitHub grants the token. The browser flow is the authorization-code
//! flow with PKCE on a loopback redirect; GitHub's token exchange for it also
//! takes the App's client secret, which is why the secret is embedded — a
//! recorded decision whose rationale is Gatehouse §6.10.
//!
//! A completed sign-in is a [`SignIn`]: the account, the user token with its
//! expiry, and GitHub's refresh material. It lives in a [`SignInStore`] — the
//! macOS Keychain ([`KeychainSignIns`]) on a Mac, an in-process store
//! ([`MemorySignIns`]) for tests — and in no file under the project or the
//! box (BEP-002). Nothing here logs or prints a token: the log lines carry
//! the account and the expiry.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng as _;
pub use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keychain::StoreError;

#[cfg(target_os = "macos")]
pub use macos::KeychainSignIns;

/// The GitHub App a sign-in runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct App {
    /// The App's OAuth client id.
    pub client_id: &'static str,
    /// The App's client secret, embedded as a public value: GitHub's token
    /// exchange for the browser flow requires it, and a PKCE-only exchange is
    /// not offered (Gatehouse §6.10).
    pub client_secret: &'static str,
}

/// The Minimal-published GitHub App. Its registration is the member's
/// ceiling: a user token is the App's permissions intersected with the
/// user's and with the installations the user holds.
pub const MINIMAL_APP: App = App {
    client_id: "Iv23liv6KetAFJp4Eb5K",
    client_secret: "",
};

/// The environment variable naming a GitHub App to present instead of
/// [`MINIMAL_APP`]: the App's client id.
pub const APP_CLIENT_ID_VAR: &str = "MINIMAL_GITHUB_APP_CLIENT_ID";

/// The environment variable holding that App's client secret. The device flow
/// needs none; GitHub's web application flow requires one at the code
/// exchange, so a host running the browser flow sets this.
pub const APP_CLIENT_SECRET_VAR: &str = "MINIMAL_GITHUB_APP_CLIENT_SECRET";

/// The App the client presents: [`MINIMAL_APP`], or the one the environment
/// names.
///
/// The override exists so a host can sign in under its own App — a fork, a
/// test registration — without a rebuild. A client id is public by
/// construction: both flows put it on the wire, so it is not a secret and is
/// spelled above rather than configured. The secret is not spelled above
/// because the device flow needs none and this repository is public.
///
/// The returned `App` borrows for the process: an overridden value is leaked
/// once, at the first sign-in, which is the lifetime the flows want anyway.
#[must_use]
pub fn published_app() -> App {
    fn from_env(var: &str, fallback: &'static str) -> &'static str {
        match std::env::var(var) {
            Ok(value) if !value.is_empty() => Box::leak(value.into_boxed_str()),
            _ => fallback,
        }
    }
    App {
        client_id: from_env(APP_CLIENT_ID_VAR, MINIMAL_APP.client_id),
        client_secret: from_env(APP_CLIENT_SECRET_VAR, MINIMAL_APP.client_secret),
    }
}

/// A token or other secret: zeroed on drop, redacted from `Debug`, and
/// serialised as its bare text only into the store that holds it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a secret.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The secret itself.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// A completed GitHub sign-in: what the host store holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    /// The signed-in account's login.
    pub account: String,
    /// The user token.
    pub token: Secret,
    /// When the token expires, as seconds since the Unix epoch, or `None`
    /// for an App registered without token expiry.
    pub expires_at: Option<u64>,
    /// GitHub's refresh token, when the grant carried one.
    pub refresh_token: Option<Secret>,
    /// When the refresh token expires, when the grant said.
    pub refresh_expires_at: Option<u64>,
}

/// Where the host holds the sign-in. The store is the only place the token
/// and refresh material are written (BEP-002).
pub trait SignInStore {
    /// The store's name, as diagnostics report it.
    const NAME: &'static str;

    /// The held sign-in, if any.
    ///
    /// # Errors
    ///
    /// When the store cannot be read, or holds something that is not a
    /// sign-in.
    fn load(&self) -> Result<Option<SignIn>, StoreError>;

    /// Holds `sign_in`, replacing any held before.
    ///
    /// # Errors
    ///
    /// When the store refuses the write.
    fn store(&self, sign_in: &SignIn) -> Result<(), StoreError>;

    /// Forgets the held sign-in; `true` when one was held.
    ///
    /// # Errors
    ///
    /// When the store refuses the deletion.
    fn clear(&self) -> Result<bool, StoreError>;
}

/// An in-process sign-in store: the sign-in lives in memory for the life of
/// the store value and every clone shares it. Nothing is written anywhere.
#[derive(Clone, Default)]
pub struct MemorySignIns {
    held: Arc<Mutex<Option<SignIn>>>,
}

impl MemorySignIns {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Option<SignIn>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SignInStore for MemorySignIns {
    const NAME: &'static str = "memory";

    fn load(&self) -> Result<Option<SignIn>, StoreError> {
        Ok(self.held().clone())
    }

    fn store(&self, sign_in: &SignIn) -> Result<(), StoreError> {
        *self.held() = Some(sign_in.clone());
        Ok(())
    }

    fn clear(&self) -> Result<bool, StoreError> {
        Ok(self.held().take().is_some())
    }
}

/// Why a sign-in step failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GitHubError {
    /// The HTTP client could not be built.
    #[error("building the GitHub client: {0}")]
    Client(#[source] reqwest::Error),
    /// The request did not complete.
    #[error("{endpoint}: {source}")]
    Transport {
        endpoint: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// GitHub answered with a status the flow does not expect.
    #[error("{endpoint} answered {status}: {body}")]
    Status {
        endpoint: &'static str,
        status: u16,
        body: String,
    },
    /// GitHub's answer was not the JSON the flow expects.
    #[error("{endpoint} answered something other than the expected JSON: {message}")]
    Malformed {
        endpoint: &'static str,
        message: String,
    },
    /// GitHub refused the sign-in: the operator denied it, the code
    /// expired, or the App's registration was rejected.
    #[error("GitHub refused the sign-in: {error}{}", .description.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Refused {
        error: String,
        description: Option<String>,
    },
    /// The browser flow's redirect came back with a state the flow did not
    /// send.
    #[error("the browser flow's redirect carried a state this sign-in did not send")]
    StateMismatch,
}

/// Where GitHub's endpoints live: `github.com` for OAuth and
/// `api.github.com` for the API, or a test double for both.
#[derive(Debug, Clone)]
pub struct Endpoints {
    oauth: Url,
    api: Url,
}

impl Endpoints {
    /// GitHub itself.
    ///
    /// # Panics
    ///
    /// Never: the two literals parse.
    #[must_use]
    pub fn github() -> Self {
        Self {
            oauth: Url::parse("https://github.com/").expect("a literal URL"),
            api: Url::parse("https://api.github.com/").expect("a literal URL"),
        }
    }

    /// Endpoints at the given bases, for a test double.
    #[must_use]
    pub fn at(oauth: Url, api: Url) -> Self {
        Self { oauth, api }
    }

    fn oauth(&self, path: &str) -> Url {
        self.oauth.join(path).expect("a literal path joins")
    }

    fn api(&self, path: &str) -> Url {
        self.api.join(path).expect("a literal path joins")
    }
}

/// The device flow's code, as GitHub issues it.
#[derive(Debug, Deserialize)]
pub struct DeviceCode {
    #[serde(rename = "device_code")]
    code: Secret,
    /// The code the operator enters at [`Self::verification_uri`].
    pub user_code: String,
    /// Where the operator enters the code.
    pub verification_uri: String,
    /// How long the code is valid, in seconds.
    pub expires_in: u64,
    /// The polling interval GitHub asks for, in seconds.
    pub interval: u64,
}

/// What GitHub's token endpoint grants.
#[derive(Debug, Deserialize)]
pub struct Grant {
    /// The user token.
    pub access_token: Secret,
    /// The token's lifetime in seconds, when the App registers expiring
    /// tokens.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// The refresh token, when the App registers expiring tokens.
    #[serde(default)]
    pub refresh_token: Option<Secret>,
    /// The refresh token's lifetime in seconds.
    #[serde(default)]
    pub refresh_token_expires_in: Option<u64>,
}

impl Grant {
    /// The sign-in this grant leaves for `account`, dated from `now`
    /// (seconds since the Unix epoch).
    #[must_use]
    pub fn into_sign_in(self, account: String, now: u64) -> SignIn {
        SignIn {
            account,
            token: self.access_token,
            expires_at: self.expires_in.map(|secs| now + secs),
            refresh_token: self.refresh_token,
            refresh_expires_at: self.refresh_token_expires_in.map(|secs| now + secs),
        }
    }
}

/// GitHub's token endpoint answers a pending or refused device poll with an
/// `error` body and a 200, so both shapes are read from one reply.
#[derive(Deserialize)]
#[serde(untagged)]
enum TokenReply {
    Grant(Grant),
    Error {
        error: String,
        #[serde(default)]
        error_description: Option<String>,
    },
}

/// A PKCE verifier and its S256 challenge (RFC 7636).
#[derive(Debug)]
pub struct Pkce {
    verifier: Secret,
    challenge: String,
}

impl Pkce {
    /// A fresh verifier of 32 random bytes, base64url-encoded.
    #[must_use]
    pub fn generate() -> Self {
        let verifier = random_token();
        let challenge = Self::challenge_of(&verifier);
        Self {
            verifier: Secret::new(verifier),
            challenge,
        }
    }

    /// The S256 challenge of `verifier`: the base64url of its SHA-256, as
    /// the token endpoint recomputes it.
    #[must_use]
    pub fn challenge_of(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    /// The challenge the authorization request carries.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

/// 32 random bytes, base64url-encoded: a PKCE verifier or a `state`.
#[must_use]
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// What the browser flow's authorization request names.
#[derive(Debug)]
pub struct AuthorizeRequest<'a> {
    /// The loopback redirect the browser is sent back to.
    pub redirect_uri: &'a str,
    /// The `state` the redirect must carry back.
    pub state: &'a str,
    /// The PKCE pair for this request.
    pub pkce: &'a Pkce,
}

#[derive(Serialize)]
struct DeviceCodeRequest<'a> {
    client_id: &'a str,
}

#[derive(Serialize)]
struct DevicePoll<'a> {
    client_id: &'a str,
    device_code: &'a str,
    grant_type: &'a str,
}

#[derive(Serialize)]
struct CodeExchange<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    code_verifier: &'a str,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const SLOW_DOWN: Duration = Duration::from_secs(5);

/// GitHub, as the sign-in talks to it.
#[derive(Debug, Clone)]
pub struct GitHub {
    client: reqwest::Client,
    endpoints: Endpoints,
    app: App,
}

impl GitHub {
    /// A client for `app` at `endpoints`.
    ///
    /// # Errors
    ///
    /// When the HTTP client cannot be built.
    pub fn new(app: App, endpoints: Endpoints) -> Result<Self, GitHubError> {
        let client = reqwest::Client::builder()
            .user_agent("minimal")
            .build()
            .map_err(GitHubError::Client)?;
        Ok(Self {
            client,
            endpoints,
            app,
        })
    }

    /// Asks GitHub for a device code (the device flow's first step).
    ///
    /// # Errors
    ///
    /// A [`GitHubError`] when the request fails or the answer is not a device
    /// code.
    pub async fn device_code(&self) -> Result<DeviceCode, GitHubError> {
        let code: DeviceCode = self
            .post_json(
                "requesting a device code",
                self.endpoints.oauth("login/device/code"),
                &DeviceCodeRequest {
                    client_id: self.app.client_id,
                },
            )
            .await?;
        tracing::info!(
            verification_uri = %code.verification_uri,
            expires_in = code.expires_in,
            interval = code.interval,
            "requested a GitHub device code"
        );
        Ok(code)
    }

    /// Polls GitHub at the interval it asked for until the operator has
    /// entered `code` and GitHub grants the token, or refuses.
    ///
    /// # Errors
    ///
    /// [`GitHubError::Refused`] when the operator denies the sign-in or the
    /// code expires; another [`GitHubError`] when a poll fails.
    pub async fn wait_for_device_grant(&self, code: &DeviceCode) -> Result<Grant, GitHubError> {
        let mut interval = Duration::from_secs(code.interval);
        loop {
            tokio::time::sleep(interval).await;
            let reply: TokenReply = self
                .post_json(
                    "polling for the device grant",
                    self.endpoints.oauth("login/oauth/access_token"),
                    &DevicePoll {
                        client_id: self.app.client_id,
                        device_code: code.code.expose(),
                        grant_type: DEVICE_GRANT,
                    },
                )
                .await?;
            match reply {
                TokenReply::Grant(grant) => {
                    tracing::info!("GitHub granted the device sign-in");
                    return Ok(grant);
                }
                TokenReply::Error { error, .. } if error == "authorization_pending" => {}
                TokenReply::Error { error, .. } if error == "slow_down" => interval += SLOW_DOWN,
                TokenReply::Error {
                    error,
                    error_description,
                } => {
                    tracing::warn!(error = %error, "GitHub refused the device sign-in");
                    return Err(GitHubError::Refused {
                        error,
                        description: error_description,
                    });
                }
            }
        }
    }

    /// The URL the browser flow sends the operator to.
    #[must_use]
    pub fn authorize_url(&self, request: &AuthorizeRequest<'_>) -> Url {
        let mut url = self.endpoints.oauth("login/oauth/authorize");
        url.query_pairs_mut()
            .append_pair("client_id", self.app.client_id)
            .append_pair("redirect_uri", request.redirect_uri)
            .append_pair("state", request.state)
            .append_pair("code_challenge", request.pkce.challenge())
            .append_pair("code_challenge_method", "S256");
        url
    }

    /// Exchanges the browser flow's authorization `code` for the token,
    /// proving the PKCE verifier.
    ///
    /// # Errors
    ///
    /// [`GitHubError::Refused`] when GitHub rejects the code or the verifier;
    /// another [`GitHubError`] when the exchange fails.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce: &Pkce,
    ) -> Result<Grant, GitHubError> {
        let reply: TokenReply = self
            .post_json(
                "exchanging the authorization code",
                self.endpoints.oauth("login/oauth/access_token"),
                &CodeExchange {
                    client_id: self.app.client_id,
                    client_secret: self.app.client_secret,
                    code,
                    redirect_uri,
                    code_verifier: pkce.verifier.expose(),
                },
            )
            .await?;
        match reply {
            TokenReply::Grant(grant) => {
                tracing::info!("GitHub granted the browser sign-in");
                Ok(grant)
            }
            TokenReply::Error {
                error,
                error_description,
            } => {
                tracing::warn!(error = %error, "GitHub refused the browser sign-in");
                Err(GitHubError::Refused {
                    error,
                    description: error_description,
                })
            }
        }
    }

    /// The login of the account `token` belongs to.
    ///
    /// # Errors
    ///
    /// A [`GitHubError`] when GitHub does not answer with the account.
    pub async fn account(&self, token: &Secret) -> Result<String, GitHubError> {
        const ENDPOINT: &str = "reading the signed-in account";
        let response = self
            .client
            .get(self.endpoints.api("user"))
            .header("Accept", "application/vnd.github+json")
            .bearer_auth(token.expose())
            .send()
            .await
            .map_err(transport(ENDPOINT))?;
        let user: User = read_json(ENDPOINT, response).await?;
        Ok(user.login)
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &'static str,
        url: Url,
        body: &impl Serialize,
    ) -> Result<T, GitHubError> {
        let body = serde_json_lenient::to_vec(body).map_err(|source| GitHubError::Malformed {
            endpoint,
            message: source.to_string(),
        })?;
        let response = self
            .client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(transport(endpoint))?;
        read_json(endpoint, response).await
    }
}

fn transport(endpoint: &'static str) -> impl FnOnce(reqwest::Error) -> GitHubError {
    move |source| GitHubError::Transport { endpoint, source }
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    endpoint: &'static str,
    response: reqwest::Response,
) -> Result<T, GitHubError> {
    let status = response.status();
    let bytes = response.bytes().await.map_err(transport(endpoint))?;
    if !status.is_success() {
        return Err(GitHubError::Status {
            endpoint,
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    serde_json_lenient::from_slice(&bytes).map_err(|source| GitHubError::Malformed {
        endpoint,
        message: source.to_string(),
    })
}

#[cfg(target_os = "macos")]
mod macos {
    //! The macOS Keychain backend: the sign-in is one generic-password item
    //! in the login keychain, its JSON the item's data. The item is
    //! per-user and never a file the project or a box can read.

    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use security_framework_sys::base::errSecItemNotFound;

    use super::{SignIn, SignInStore, StoreError};

    /// The keychain service the item lives under.
    const SERVICE: &str = "dev.minimal.bep.github";
    /// The item's account: there is one sign-in per host.
    const ACCOUNT: &str = "sign-in";

    /// The macOS Keychain, as the operator's login keychain.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct KeychainSignIns;

    fn backend(op: &'static str, error: &impl std::fmt::Display) -> StoreError {
        StoreError::Backend {
            op,
            message: error.to_string(),
        }
    }

    impl SignInStore for KeychainSignIns {
        const NAME: &'static str = "macos-keychain";

        fn load(&self) -> Result<Option<SignIn>, StoreError> {
            let bytes = match get_generic_password(SERVICE, ACCOUNT) {
                Ok(bytes) => bytes,
                Err(error) if error.code() == errSecItemNotFound => return Ok(None),
                Err(error) => return Err(backend("read the sign-in", &error)),
            };
            serde_json_lenient::from_slice(&bytes)
                .map(Some)
                .map_err(|error| backend("read the sign-in", &error))
        }

        fn store(&self, sign_in: &SignIn) -> Result<(), StoreError> {
            let bytes = serde_json_lenient::to_vec(sign_in)
                .map_err(|error| backend("write the sign-in", &error))?;
            set_generic_password(SERVICE, ACCOUNT, &bytes)
                .map_err(|error| backend("write the sign-in", &error))
        }

        fn clear(&self) -> Result<bool, StoreError> {
            match delete_generic_password(SERVICE, ACCOUNT) {
                Ok(()) => Ok(true),
                Err(error) if error.code() == errSecItemNotFound => Ok(false),
                Err(error) => Err(backend("delete the sign-in", &error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PKCE challenge is the S256 of the verifier, and every pair is
    /// fresh.
    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        let pkce = Pkce::generate();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.expose().as_bytes()));
        assert_eq!(pkce.challenge(), expected);
        assert_eq!(Pkce::challenge_of(pkce.verifier.expose()), expected);
        assert_eq!(pkce.verifier.expose().len(), 43);
        assert_ne!(Pkce::generate().challenge(), pkce.challenge());
    }

    /// A sign-in round-trips through the store's JSON, and its secrets stay
    /// out of `Debug`.
    #[test]
    fn sign_in_round_trips_and_redacts() {
        let sign_in = SignIn {
            account: "octocat".into(),
            token: Secret::new("ghu_token"),
            expires_at: Some(1_700_000_000),
            refresh_token: Some(Secret::new("ghr_refresh")),
            refresh_expires_at: Some(1_710_000_000),
        };
        let json = serde_json_lenient::to_string(&sign_in).unwrap();
        assert_eq!(
            serde_json_lenient::from_str::<SignIn>(&json).unwrap(),
            sign_in
        );
        let debug = format!("{sign_in:?}");
        assert!(
            !debug.contains("ghu_token") && !debug.contains("ghr_refresh"),
            "{debug}"
        );

        let store = MemorySignIns::new();
        assert_eq!(store.load().unwrap(), None);
        store.store(&sign_in).unwrap();
        assert_eq!(store.load().unwrap(), Some(sign_in));
        assert!(store.clear().unwrap());
        assert!(!store.clear().unwrap());
    }
}
