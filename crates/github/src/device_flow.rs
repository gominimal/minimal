//! GitHub OAuth device-flow client (spec R1.1) — the `client` feature.
//!
//! [`DeviceFlowClient`] runs the three HTTP calls that make up a device-flow
//! login: `POST {oauth_base}/login/device/code`
//! ([`DeviceFlowClient::start_device_flow`]), the token-exchange poll `POST
//! {oauth_base}/login/oauth/access_token` ([`DeviceFlowClient::poll`]), and
//! `GET {api_base}/user` to learn the authenticated identity
//! ([`DeviceFlowClient::fetch_user`]). [`assemble_grant`] then builds a
//! complete [`Grant`] ready for [`crate::GrantStore::save`].
//! [`DeviceFlowClient::login`] wires the four together for the common case.
//!
//! This module is intentionally independent of `rest.rs` (the GitHub REST
//! client, also behind `client`): both are grounded in the same crate-wide
//! [`Error`] taxonomy but do not depend on each other's types, so they stay
//! separately testable and composable by the daemon-side unit that wires
//! them together.
//!
//! # Error mapping (spec R8.1)
//!
//! Every failure mode maps into the crate-wide [`Error`] used everywhere else
//! in this crate — no bespoke error type for this module:
//!
//! * A transport failure (DNS, TCP, TLS, timeout) becomes [`Error::Request`];
//!   a response that doesn't decode becomes [`Error::Decode`]. Both messages
//!   come from the underlying error's `Display`, which never includes header
//!   values, so no token material can reach them.
//! * A `client_id` GitHub does not recognize is the device-code endpoint's
//!   one realistic pre-auth failure mode; it becomes [`Error::NotConfigured`]
//!   — the same guidance as "no GitHub App configured yet", since the fix is
//!   identical either way (spec R1.1).
//! * An expired or declined device code becomes [`Error::NeedsReauth`] (spec
//!   R1.2): the caller must restart `min github login`.
//! * Any other OAuth-shaped error GitHub returns from the token endpoint
//!   becomes [`Error::UnexpectedStatus`], carrying GitHub's own error code and
//!   description.
//!
//! # Security
//!
//! [`DeviceAuthorization`] carries the device code as a [`SecretString`]: it
//! is never shown to the user (only `user_code`/`verification_uri` are, per
//! spec R1.4), and possessing it plus reachability to GitHub's token endpoint
//! is enough to complete the login, so it gets the same redacting-Debug and
//! zeroize-on-drop treatment as an access or refresh token. No public type in
//! this module renders token material through `Debug` or `Display` — see the
//! `no_token_material_in_debug_of_public_types` test.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use reqwest::header::ACCEPT;
use serde::Deserialize;
use url::Url;

use crate::error::Error;
use crate::scopes::ScopeSet;
use crate::secret::SecretString;
use crate::store::{Grant, GrantState};
use crate::types::GrantId;

/// `User-Agent` sent on every request; GitHub requires one on all API calls.
const USER_AGENT: &str = concat!("minimal-github-device-flow/", env!("CARGO_PKG_VERSION"));

/// RFC 8628's default backoff bump, used when a `slow_down` response doesn't
/// advise a specific new interval.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// A device-flow client bound to one GitHub instance: `oauth_base` (normally
/// [`crate::GithubConfig::oauth_base`]) and `api_base` (normally
/// [`crate::GithubConfig::api_base`]), or both pointed at a
/// [`crate::testing::MockGithub`] in tests.
#[derive(Debug, Clone)]
pub struct DeviceFlowClient {
    http: reqwest::Client,
    oauth_base: Url,
    api_base: Url,
}

/// The device-code + user-code pair returned by `POST /login/device/code`
/// (spec R1.1, R1.4).
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    /// The URL to open in a browser (e.g. `https://github.com/login/device`).
    pub verification_uri: Url,
    /// The short code the user enters at `verification_uri`. Not secret — it
    /// is meant to be read aloud or typed by the user (spec R1.4).
    pub user_code: String,
    /// The device code used to poll for the access token. Not a GitHub token,
    /// but possessing it (plus reachability to the token endpoint) is enough
    /// to complete the login, so it gets [`SecretString`]'s redacting-Debug
    /// and zeroize-on-drop treatment; only [`DeviceFlowClient::poll`] reads
    /// it.
    device_code: SecretString,
    /// Minimum time between polls (server-advised; may grow via `slow_down`).
    pub interval: Duration,
    /// When the device code expires. [`DeviceFlowClient::poll`] stops with
    /// [`Error::NeedsReauth`] once this passes rather than polling forever,
    /// even if the server never sends `expired_token`.
    expires_at: Instant,
}

/// A freshly minted user + refresh token pair (spec R1.1) — not yet a full
/// [`Grant`] (no `grant_id`/`scopes` assigned; see [`assemble_grant`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AccessTokenPair {
    /// The user-to-server access token (~8h lifetime). Never logged.
    pub access_token: SecretString,
    /// Expiry of `access_token`.
    pub access_token_expires_at: DateTime<Utc>,
    /// The rotating refresh token (~6mo lifetime). Never logged.
    pub refresh_token: SecretString,
    /// Expiry of `refresh_token`.
    pub refresh_token_expires_at: DateTime<Utc>,
}

/// The authenticated identity from `GET /user` (spec R1.3, G4).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GithubUser {
    /// The user's login (handle).
    pub login: String,
    /// The user's numeric GitHub id.
    pub id: u64,
}

impl DeviceFlowClient {
    /// Builds a client against `oauth_base` (device flow) and `api_base`
    /// (`GET /user`).
    #[must_use]
    pub fn new(oauth_base: Url, api_base: Url) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client construction is infallible with the enabled backends"),
            oauth_base,
            api_base,
        }
    }

    /// `POST {oauth_base}/login/device/code` (spec R1.1, R1.4): starts a
    /// device-flow login and returns the verification URL, user code, and
    /// device code to poll with.
    ///
    /// # Errors
    ///
    /// [`Error::Request`]/[`Error::Decode`] on transport or shape failures;
    /// [`Error::NotConfigured`] if GitHub rejects `client_id` (the endpoint's
    /// only realistic pre-auth failure mode).
    pub async fn start_device_flow(&self, client_id: &str) -> Result<DeviceAuthorization, Error> {
        let url = self.oauth_base.join("login/device/code").map_err(url_err)?;
        let resp = self
            .http
            .post(url)
            .header(ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .form(&[("client_id", client_id)])
            .send()
            .await
            .map_err(request_err)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(request_err)?;
        if !status.is_success() {
            // The device-code endpoint has exactly one realistic failure mode
            // pre-auth: a `client_id` GitHub does not recognize. From the
            // user's perspective the fix is the same as "no App configured":
            // set a valid GitHub App client id.
            return Err(Error::NotConfigured);
        }
        let wire: DeviceCodeWire = serde_json::from_slice(&bytes).map_err(decode_err)?;
        let verification_uri = Url::parse(&wire.verification_uri).map_err(|e| Error::Decode {
            reason: format!("invalid verification_uri from GitHub: {e}"),
        })?;
        Ok(DeviceAuthorization {
            verification_uri,
            user_code: wire.user_code,
            device_code: SecretString::new(wire.device_code),
            // A server-advised interval of 0 would otherwise turn the poll
            // loop into a hot spin against GitHub; floor it at 1 second.
            interval: Duration::from_secs(wire.interval.max(1)),
            expires_at: Instant::now() + Duration::from_secs(wire.expires_in),
        })
    }

    /// Polls `POST {oauth_base}/login/oauth/access_token` until the user
    /// approves, honoring `authorization_pending` (keep waiting) and
    /// `slow_down` (back off) per RFC 8628, until success, an expired device
    /// code, or any other terminal GitHub error (spec R1.1).
    ///
    /// # Errors
    ///
    /// [`Error::NeedsReauth`] if the device code expires (server-signalled
    /// `expired_token`, or this client's own real-time deadline); transport/
    /// decode errors as in [`DeviceFlowClient::start_device_flow`];
    /// [`Error::UnexpectedStatus`] for any other OAuth error GitHub reports.
    pub async fn poll(
        &self,
        client_id: &str,
        authorization: &DeviceAuthorization,
    ) -> Result<AccessTokenPair, Error> {
        let mut interval = authorization.interval;
        loop {
            if Instant::now() >= authorization.expires_at {
                return Err(Error::NeedsReauth);
            }
            tokio::time::sleep(interval).await;
            let wire = self
                .token_exchange(client_id, authorization.device_code.expose_secret())
                .await?;
            match wire.error.as_deref() {
                Some("authorization_pending") => continue,
                Some("slow_down") => {
                    interval = wire
                        .interval
                        .map(Duration::from_secs)
                        .unwrap_or(interval + SLOW_DOWN_STEP);
                    continue;
                }
                Some("expired_token") => return Err(Error::NeedsReauth),
                Some(other) => {
                    return Err(Error::UnexpectedStatus {
                        status: 200,
                        message: format!(
                            "{other}: {}",
                            wire.error_description
                                .as_deref()
                                .unwrap_or("no further detail")
                        ),
                    });
                }
                None => return token_pair_from_wire(wire),
            }
        }
    }

    /// `GET {api_base}/user`: the authenticated identity for a freshly minted
    /// access token (spec R1.3).
    ///
    /// # Errors
    ///
    /// [`Error::NeedsReauth`] on `401`; transport/decode errors otherwise, as
    /// in [`DeviceFlowClient::start_device_flow`].
    pub async fn fetch_user(&self, access_token: &SecretString) -> Result<GithubUser, Error> {
        let url = self.api_base.join("user").map_err(url_err)?;
        let resp = self
            .http
            .get(url)
            .header(ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .bearer_auth(access_token.expose_secret())
            .send()
            .await
            .map_err(request_err)?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::NeedsReauth);
        }
        let bytes = resp.bytes().await.map_err(request_err)?;
        if !status.is_success() {
            return Err(Error::UnexpectedStatus {
                status: status.as_u16(),
                message: error_message(&bytes),
            });
        }
        let wire: UserWire = serde_json::from_slice(&bytes).map_err(decode_err)?;
        Ok(GithubUser {
            login: wire.login,
            id: wire.id,
        })
    }

    /// Runs a full device-flow login end-to-end — start, poll to completion,
    /// `GET /user`, and assemble a complete [`Grant`] ready for
    /// [`crate::GrantStore::save`] (spec R1.1). `on_authorization` is called
    /// exactly once, as soon as the verification URL and user code are known,
    /// so the caller (`min github login`) can display them (spec R1.4)
    /// before this blocks on the user's approval.
    ///
    /// `grant_id` and `scopes` are the caller's concern (a freshly minted id
    /// for "mint" or a chosen existing id for "reuse" — spec R6.4; the
    /// resolved scope set — spec R5): this module only knows how to talk to
    /// GitHub, not grant-id or scope policy.
    ///
    /// # Errors
    ///
    /// Whatever [`DeviceFlowClient::start_device_flow`],
    /// [`DeviceFlowClient::poll`], or [`DeviceFlowClient::fetch_user`] return.
    pub async fn login(
        &self,
        client_id: &str,
        grant_id: GrantId,
        scopes: ScopeSet,
        on_authorization: impl FnOnce(&DeviceAuthorization),
    ) -> Result<Grant, Error> {
        let authorization = self.start_device_flow(client_id).await?;
        on_authorization(&authorization);
        let tokens = self.poll(client_id, &authorization).await?;
        let user = self.fetch_user(&tokens.access_token).await?;
        Ok(assemble_grant(grant_id, user, scopes, tokens))
    }

    /// One `POST {oauth_base}/login/oauth/access_token` attempt, returning
    /// the raw decoded response for [`DeviceFlowClient::poll`] to interpret.
    async fn token_exchange(&self, client_id: &str, device_code: &str) -> Result<TokenWire, Error> {
        let url = self
            .oauth_base
            .join("login/oauth/access_token")
            .map_err(url_err)?;
        let resp = self
            .http
            .post(url)
            .header(ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .map_err(request_err)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(request_err)?;
        let wire: TokenWire = serde_json::from_slice(&bytes).map_err(decode_err)?;
        if !status.is_success() && wire.error.is_none() {
            return Err(Error::UnexpectedStatus {
                status: status.as_u16(),
                message: error_message(&bytes),
            });
        }
        Ok(wire)
    }
}

/// Assembles a complete [`Grant`] ready for [`crate::GrantStore::save`] from
/// a freshly authenticated device-flow session (spec R1.1).
#[must_use]
pub fn assemble_grant(
    grant_id: GrantId,
    user: GithubUser,
    scopes: ScopeSet,
    tokens: AccessTokenPair,
) -> Grant {
    let now = Utc::now();
    Grant {
        grant_id,
        github_login: user.login,
        github_user_id: user.id,
        scopes,
        access_token: tokens.access_token,
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token: tokens.refresh_token,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        created_at: now,
        last_refreshed_at: now,
        state: GrantState::Valid,
    }
}

/// Builds an [`AccessTokenPair`] from a successful token-exchange response
/// (no `error` field present).
fn token_pair_from_wire(wire: TokenWire) -> Result<AccessTokenPair, Error> {
    let missing = |field: &str| Error::Decode {
        reason: format!("GitHub's token response is missing `{field}`"),
    };
    let access_token = wire.access_token.ok_or_else(|| missing("access_token"))?;
    let refresh_token = wire.refresh_token.ok_or_else(|| missing("refresh_token"))?;
    let expires_in = wire.expires_in.ok_or_else(|| missing("expires_in"))?;
    let refresh_expires_in = wire
        .refresh_token_expires_in
        .ok_or_else(|| missing("refresh_token_expires_in"))?;
    let now = Utc::now();
    Ok(AccessTokenPair {
        access_token: SecretString::new(access_token),
        access_token_expires_at: now + chrono::Duration::seconds(saturating_i64(expires_in)),
        refresh_token: SecretString::new(refresh_token),
        refresh_token_expires_at: now
            + chrono::Duration::seconds(saturating_i64(refresh_expires_in)),
    })
}

/// Converts a token lifetime in seconds to `i64`, saturating rather than
/// panicking on the practically-impossible case of a value over ~292 billion
/// years' worth of seconds.
fn saturating_i64(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

fn request_err(e: reqwest::Error) -> Error {
    Error::Request {
        reason: e.to_string(),
    }
}

fn decode_err(e: serde_json::Error) -> Error {
    Error::Decode {
        reason: e.to_string(),
    }
}

fn url_err(e: url::ParseError) -> Error {
    Error::Request {
        reason: format!("invalid GitHub base URL: {e}"),
    }
}

/// Extracts GitHub's `message` field from an error body, falling back to a
/// bounded excerpt of the raw body so a malformed error response still yields
/// something actionable without risking an unbounded or binary blob in a log
/// (mirrors `rest.rs`'s identical convention for the same reason).
fn error_message(bytes: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
        && let Some(message) = value.get("message").and_then(|m| m.as_str())
    {
        return message.to_string();
    }
    String::from_utf8_lossy(bytes).chars().take(200).collect()
}

/// Wire shape of `POST /login/device/code`'s success response.
#[derive(Deserialize)]
struct DeviceCodeWire {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

/// Wire shape of `POST /login/oauth/access_token`'s response — success and
/// every scripted RFC 8628 error share one envelope, distinguished by
/// whether `error` is present.
#[derive(Deserialize, Default)]
struct TokenWire {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Wire shape of `GET /user` (only the fields this client needs).
#[derive(Deserialize)]
struct UserWire {
    login: String,
    id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal one-shot HTTP responder used only for the one scenario the
    /// full `test-support` mock doesn't script (it never validates
    /// `client_id`). Self-contained so this test compiles and runs even when
    /// only the `client` feature (not `test-support`) is enabled.
    async fn one_shot_response(status_line: &str, body: &str) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let status_line = status_line.to_string();
        let body = body.to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await; // drain the request, unread
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Url::parse(&format!("http://{addr}/")).expect("valid loopback url")
    }

    #[tokio::test]
    async fn bad_client_id_maps_to_not_configured() {
        let url = one_shot_response("404 Not Found", r#"{"message":"Not Found"}"#).await;
        let client = DeviceFlowClient::new(url.clone(), url);
        let err = client
            .start_device_flow("client-id-github-does-not-know")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotConfigured), "got {err:?}");
    }

    #[cfg(feature = "test-support")]
    mod mock_backed {
        use super::*;
        use crate::testing::{MockGithub, TokenStep};

        fn client(mock: &MockGithub) -> DeviceFlowClient {
            DeviceFlowClient::new(mock.base_url().clone(), mock.base_url().clone())
        }

        #[tokio::test]
        async fn happy_path_end_to_end() {
            let mock = MockGithub::start().await.expect("mock starts");
            // A short interval keeps this test's single poll fast without
            // needing tokio's paused-clock machinery (which doesn't mix well
            // with reqwest's own timeout timer racing real loopback I/O).
            mock.configure(|fx| fx.set_device_interval(1));
            let c = client(&mock);

            let auth = c
                .start_device_flow("test-client")
                .await
                .expect("start_device_flow ok");
            assert_eq!(auth.user_code, "WDJB-MJHT");
            assert_eq!(
                auth.verification_uri.as_str(),
                "https://github.com/login/device"
            );

            let tokens = c.poll("test-client", &auth).await.expect("poll ok");
            assert_eq!(tokens.access_token.expose_secret(), "ghu_mock_access_1");
            assert_eq!(tokens.refresh_token.expose_secret(), "ghr_mock_refresh_1");

            let user = c
                .fetch_user(&tokens.access_token)
                .await
                .expect("fetch_user ok");
            assert_eq!(user.login, "octocat");
            assert_eq!(user.id, 583_231);

            let grant_id = GrantId::new("grant-1").expect("valid grant id");
            let grant = assemble_grant(grant_id.clone(), user, ScopeSet::defaults(), tokens);
            assert_eq!(grant.grant_id, grant_id);
            assert_eq!(grant.github_login, "octocat");
            assert_eq!(grant.github_user_id, 583_231);
            assert_eq!(grant.scopes, ScopeSet::defaults());
            assert_eq!(grant.state, GrantState::Valid);
        }

        #[tokio::test]
        async fn slow_down_then_approve_backs_off_and_succeeds() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| {
                fx.set_device_interval(1);
                fx.script_device_exchange([TokenStep::SlowDown, TokenStep::Approve]);
            });
            let c = client(&mock);

            let auth = c
                .start_device_flow("test-client")
                .await
                .expect("start_device_flow ok");
            let tokens = c
                .poll("test-client", &auth)
                .await
                .expect("poll succeeds after slow_down backoff");
            assert!(!tokens.access_token.expose_secret().is_empty());

            let polls = mock
                .captured()
                .into_iter()
                .filter(|r| r.path == "/login/oauth/access_token")
                .count();
            assert_eq!(polls, 2, "one slow_down response, then one approval");
        }

        #[tokio::test]
        async fn pending_loop_eventually_succeeds() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| {
                fx.set_device_interval(1);
                fx.script_device_exchange([
                    TokenStep::Pending,
                    TokenStep::Pending,
                    TokenStep::Approve,
                ]);
            });
            let c = client(&mock);

            let auth = c
                .start_device_flow("test-client")
                .await
                .expect("start_device_flow ok");
            c.poll("test-client", &auth)
                .await
                .expect("poll succeeds after the pending loop");

            let polls = mock
                .captured()
                .into_iter()
                .filter(|r| r.path == "/login/oauth/access_token")
                .count();
            assert_eq!(polls, 3, "two pending polls, then one approval");
        }

        #[tokio::test]
        async fn expired_device_code_maps_to_needs_reauth() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| {
                fx.set_device_interval(1);
                fx.script_device_exchange([TokenStep::Expired]);
            });
            let c = client(&mock);

            let auth = c
                .start_device_flow("test-client")
                .await
                .expect("start_device_flow ok");
            let err = c.poll("test-client", &auth).await.unwrap_err();
            assert!(matches!(err, Error::NeedsReauth), "got {err:?}");
        }

        #[tokio::test]
        async fn no_token_material_in_debug_of_public_types() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_device_interval(1));
            let c = client(&mock);

            let auth = c
                .start_device_flow("test-client")
                .await
                .expect("start_device_flow ok");
            let tokens = c.poll("test-client", &auth).await.expect("poll ok");
            let user = c
                .fetch_user(&tokens.access_token)
                .await
                .expect("fetch_user ok");

            let secrets = [
                tokens.access_token.expose_secret().to_string(),
                tokens.refresh_token.expose_secret().to_string(),
            ];
            assert!(
                secrets.iter().all(|s| !s.is_empty()),
                "sanity: the mock did mint tokens"
            );

            let auth_debug = format!("{auth:?}");
            let tokens_debug = format!("{tokens:?}");
            let grant = assemble_grant(
                GrantId::new("grant-1").expect("valid grant id"),
                user,
                ScopeSet::defaults(),
                tokens,
            );
            let grant_debug = format!("{grant:?}");

            for secret in &secrets {
                assert!(
                    !auth_debug.contains(secret.as_str()),
                    "DeviceAuthorization Debug leaked a token"
                );
                assert!(
                    !tokens_debug.contains(secret.as_str()),
                    "AccessTokenPair Debug leaked a token"
                );
                assert!(
                    !grant_debug.contains(secret.as_str()),
                    "Grant Debug leaked a token"
                );
            }
            // Belt-and-suspenders: the redaction marker is present instead.
            assert!(tokens_debug.contains(crate::secret::REDACTED));
            assert!(grant_debug.contains(crate::secret::REDACTED));
        }
    }
}
