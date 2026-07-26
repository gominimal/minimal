//! Token-refresh state machine for stored GitHub grants (spec R1.2, R6.2) —
//! the auth hard core of the `client` feature.
//!
//! [`GrantManager`] owns the lifecycle of every stored [`Grant`]'s access
//! token. Per grant, the observable phases are
//! `Valid -> NearExpiry (<5 min) -> Refreshing -> Valid | NeedsReauth`
//! (see [`GrantPhase`]); the persisted states remain the two in
//! [`GrantState`], because `NearExpiry` is a pure function of the clock and
//! `Refreshing` is a pure function of the in-flight lock.
//!
//! [`GrantManager::token_for`] is **the only sanctioned token accessor in the
//! entire system**: every daemon-side consumer (REST, git ops, facade) must
//! obtain access tokens through it — directly, or via the
//! [`TokenProvider`]-implementing [`GrantTokenProvider`] handle — so that
//! refresh, rotation persistence, and the needs-reauth transition can never be
//! bypassed. Reading `Grant::access_token` off a [`GrantStore`] anywhere else
//! is a review-rejectable pattern.
//!
//! # Why the design is shaped this way
//!
//! * **Per-grant single-flight.** GitHub **rotates the refresh token on every
//!   refresh**: the exchange consumes the presented refresh token and answers
//!   with a new one. If two callers raced the exchange, the loser would hold a
//!   consumed refresh token and the winner's rotation could be lost on disk —
//!   either way the grant is bricked until re-auth. So each grant has one
//!   `tokio::sync::Mutex`; concurrent [`GrantManager::token_for`] callers
//!   queue on it, the first performs the refresh, and the rest re-read the
//!   store under the lock and observe the already-rotated pair (N callers ⇒
//!   exactly one HTTP refresh).
//! * **Persist-before-use (write-ahead rotation).** The rotated
//!   refresh+access pair is written — atomically and `fsync`'d, via
//!   [`GrantStore::save`] — **before** the new access token is handed to any
//!   caller. No token that is not durable on disk ever escapes this module,
//!   so a crash at any point loses at most an access token (refreshable), and
//!   the on-disk refresh chain is never behind a token that callers are
//!   already using. If the persist fails, the new pair is discarded and the
//!   caller gets an error instead of a token (fail closed).
//! * **Failure taxonomy** ([`RefreshFailure`]): transport errors and 5xx are
//!   *transient* — retried a bounded number of times, and the grant stays
//!   `Valid` (the refresh token was not consumed, so a later call simply
//!   retries). `invalid_grant`/`bad_refresh_token` is *terminal*: the state
//!   is persisted as `needs_reauth` and every subsequent call returns the
//!   sticky, actionable [`RefreshError::AuthExpired`] — re-auth, never silent
//!   failure (spec R1.2). Anything else OAuth-shaped is *fatal* for this
//!   attempt but leaves the grant `Valid`.
//! * **Retry-once-on-401 for REST callers** ([`with_reauth_retry`]): a `401`
//!   from GitHub despite a seemingly valid token (early revocation, clock
//!   skew) surfaces from [`crate::RestClient`] as [`Error::NeedsReauth`]; the
//!   helper forces one refresh ([`GrantManager::refresh_now`]) and retries the
//!   call once. A second `401` is terminal. `refresh_now` carries a short
//!   just-refreshed grace so a stampede of concurrent `401` retries collapses
//!   into one rotation.
//!
//! # Security
//!
//! Tokens only ever travel as [`SecretString`]; no [`RefreshError`] variant,
//! `Debug` output, or log-worthy message in this module can carry token
//! material (errors carry logins, grant ids, statuses, and I/O causes only).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::ACCEPT;
use serde::Deserialize;
use url::Url;

use crate::device_flow::AccessTokenPair;
use crate::error::Error;
use crate::rest::TokenProvider;
use crate::secret::SecretString;
use crate::store::{Grant, GrantState, GrantStore};
use crate::types::GrantId;

/// `User-Agent` sent on refresh requests; GitHub requires one on all calls.
const USER_AGENT: &str = concat!("minimal-github-refresh/", env!("CARGO_PKG_VERSION"));

/// How close to expiry an access token may get before [`GrantManager::token_for`]
/// refreshes it instead of returning it (the `NearExpiry` threshold, 5 minutes).
const NEAR_EXPIRY_SECS: i64 = 5 * 60;

/// How recently a grant must have been refreshed for
/// [`GrantManager::refresh_now`] to skip the rotation and return the current
/// token. Collapses concurrent 401-retry stampedes into one rotation, and
/// terminates the retry-once loop: if a token refreshed seconds ago still
/// answers `401`, re-auth is genuinely required.
const FORCED_REFRESH_GRACE_SECS: i64 = 10;

/// Bounded retry budget for [`RefreshFailure::Transient`] failures: total
/// attempts are `1 + TRANSIENT_RETRIES`.
const TRANSIENT_RETRIES: u32 = 2;

/// Base backoff between transient-failure retries (multiplied by the attempt
/// number). Deliberately short: refresh normally runs minutes ahead of expiry,
/// so there is no need to be patient, only to not hammer.
const RETRY_BACKOFF_BASE: Duration = Duration::from_millis(100);

fn near_expiry_window() -> chrono::Duration {
    chrono::Duration::seconds(NEAR_EXPIRY_SECS)
}

fn forced_refresh_grace() -> chrono::Duration {
    chrono::Duration::seconds(FORCED_REFRESH_GRACE_SECS)
}

/// The observable lifecycle phase of a grant (spec R1.2), for status surfaces
/// like `min github status`. Only [`GrantState`]'s two states persist; the
/// other two are derived (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GrantPhase {
    /// The access token is valid and not near expiry.
    Valid,
    /// The access token expires within the refresh threshold (5 minutes); the
    /// next [`GrantManager::token_for`] will refresh before returning.
    NearExpiry,
    /// A refresh for this grant is in flight right now.
    Refreshing,
    /// The grant cannot be refreshed (persisted `needs_reauth`, or the
    /// refresh token itself has expired); only `min github login` helps.
    NeedsReauth,
}

/// The phase of `grant` at time `now`, ignoring in-flight refreshes (which
/// only [`GrantManager::phase`] can observe).
#[must_use]
pub fn phase_of(grant: &Grant, now: DateTime<Utc>) -> GrantPhase {
    if grant.state == GrantState::NeedsReauth || grant.refresh_token_expires_at <= now {
        // An expired refresh token cannot be exchanged; only re-auth helps.
        GrantPhase::NeedsReauth
    } else if grant.access_token_expires_at <= now + near_expiry_window() {
        GrantPhase::NearExpiry
    } else {
        GrantPhase::Valid
    }
}

/// How one refresh-exchange attempt failed, as classified by a
/// [`RefreshBackend`]. The classification drives the state machine: only
/// `InvalidGrant` moves a grant to `needs_reauth`; only `Transient` is
/// retried.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefreshFailure {
    /// GitHub reported `invalid_grant`/`bad_refresh_token`: the refresh token
    /// is expired, revoked, or already rotated away. Terminal — the grant
    /// must go to `needs_reauth` (spec R1.2).
    InvalidGrant,
    /// A failure that did not consume the refresh token and may succeed on
    /// retry: transport errors (DNS, TCP, TLS, timeout) and `5xx` responses.
    /// The grant stays `Valid`.
    Transient(Error),
    /// A failure that will not improve on retry (malformed response, an OAuth
    /// error other than `invalid_grant`, a non-5xx HTTP error). The grant
    /// stays `Valid`; the attempt is simply reported.
    Fatal(Error),
}

/// Performs one refresh-token exchange. [`GrantManager`] is generic over this
/// so the state machine is testable with scripted backends while production
/// uses [`HttpRefreshBackend`] against GitHub's OAuth endpoint.
///
/// Implementations must classify failures per [`RefreshFailure`]'s contract —
/// in particular, they must **never** report a transport-level failure as
/// [`RefreshFailure::InvalidGrant`], since that classification is what
/// invalidates a grant.
pub trait RefreshBackend: Send + Sync {
    /// Exchanges `refresh_token` for a freshly rotated access + refresh pair.
    fn refresh(
        &self,
        refresh_token: &SecretString,
    ) -> impl Future<Output = Result<AccessTokenPair, RefreshFailure>> + Send;
}

/// A shared backend refreshes exactly like the backend it wraps.
impl<B: RefreshBackend> RefreshBackend for Arc<B> {
    fn refresh(
        &self,
        refresh_token: &SecretString,
    ) -> impl Future<Output = Result<AccessTokenPair, RefreshFailure>> + Send {
        (**self).refresh(refresh_token)
    }
}

/// The production [`RefreshBackend`]: `POST
/// {oauth_base}/login/oauth/access_token` with `grant_type=refresh_token`,
/// per GitHub's "Refreshing user access tokens" flow. `oauth_base` is
/// normally [`crate::GithubConfig::oauth_base`] (or a
/// `crate::testing::MockGithub` in tests); `client_id` is the GitHub App's
/// public client id (not a secret).
#[derive(Debug, Clone)]
pub struct HttpRefreshBackend {
    http: reqwest::Client,
    oauth_base: Url,
    client_id: String,
}

impl HttpRefreshBackend {
    /// Builds a backend against `oauth_base` for the App named by `client_id`.
    #[must_use]
    pub fn new(oauth_base: Url, client_id: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client construction is infallible with the enabled backends"),
            oauth_base,
            client_id: client_id.into(),
        }
    }
}

impl RefreshBackend for HttpRefreshBackend {
    async fn refresh(
        &self,
        refresh_token: &SecretString,
    ) -> Result<AccessTokenPair, RefreshFailure> {
        let transient = |reason: String| RefreshFailure::Transient(Error::Request { reason });
        let url = self
            .oauth_base
            .join("login/oauth/access_token")
            .map_err(|e| {
                RefreshFailure::Fatal(Error::Request {
                    reason: format!("invalid GitHub base URL: {e}"),
                })
            })?;
        let resp = self
            .http
            .post(url)
            .header(ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.expose_secret()),
            ])
            .send()
            .await
            .map_err(|e| transient(e.to_string()))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| transient(e.to_string()))?;
        if status.is_server_error() {
            return Err(RefreshFailure::Transient(Error::UnexpectedStatus {
                status: status.as_u16(),
                message: error_message(&bytes),
            }));
        }
        let wire: RefreshWire = serde_json::from_slice(&bytes).map_err(|e| {
            if status.is_success() {
                RefreshFailure::Fatal(Error::Decode {
                    reason: e.to_string(),
                })
            } else {
                RefreshFailure::Fatal(Error::UnexpectedStatus {
                    status: status.as_u16(),
                    message: error_message(&bytes),
                })
            }
        })?;
        match wire.error.as_deref() {
            // GitHub uses `bad_refresh_token` in places its docs say
            // `invalid_grant`; both mean the same dead refresh token.
            Some("invalid_grant" | "bad_refresh_token") => Err(RefreshFailure::InvalidGrant),
            Some(other) => Err(RefreshFailure::Fatal(Error::UnexpectedStatus {
                status: status.as_u16(),
                message: format!(
                    "{other}: {}",
                    wire.error_description
                        .as_deref()
                        .unwrap_or("no further detail")
                ),
            })),
            None if !status.is_success() => Err(RefreshFailure::Fatal(Error::UnexpectedStatus {
                status: status.as_u16(),
                message: error_message(&bytes),
            })),
            None => pair_from_wire(wire),
        }
    }
}

/// Errors from [`GrantManager`]. Distinct from the crate-wide [`Error`] so the
/// sticky auth-expired condition can carry the login it names (making the
/// message actionable, spec R8.1); converts into [`Error`] (see the `From`
/// impl) for [`TokenProvider`] call sites.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// The grant's refresh token is expired or revoked; the state is persisted
    /// as `needs_reauth` and this error repeats — stickily, without further
    /// GitHub traffic — until the user re-authenticates (spec R1.2).
    #[error("github auth expired for {login}; run 'min github login'")]
    AuthExpired {
        /// The GitHub login the dead grant belonged to.
        login: String,
    },

    /// No grant with this id is stored.
    #[error("no stored GitHub auth grant `{grant_id}`; run 'min github login'")]
    UnknownGrant {
        /// The grant id that was requested.
        grant_id: String,
    },

    /// Reading the grant from the on-disk store failed.
    #[error("reading GitHub auth grant `{grant_id}` from the grant store failed")]
    Load {
        /// The grant id whose file could not be read.
        grant_id: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// Persisting the rotated tokens failed. The freshly minted pair was
    /// discarded rather than handed out (persist-before-use, fail closed).
    #[error(
        "persisting refreshed GitHub credentials for grant `{grant_id}` failed; \
         the refreshed tokens were discarded"
    )]
    Persist {
        /// The grant id whose file could not be written.
        grant_id: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The refresh exchange failed without invalidating the grant (transport,
    /// 5xx after retries, malformed response, unexpected OAuth error). The
    /// grant stays `Valid`; a later call retries.
    #[error(transparent)]
    Github(#[from] Error),
}

impl From<RefreshError> for Error {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::Github(e) => e,
            // Both mean "no usable stored auth": per `TokenProvider`'s
            // contract, that must surface as `NeedsReauth` so REST callers
            // handle exactly one auth-expiry variant. (The login-bearing
            // message stays available to `token_for` callers.)
            RefreshError::AuthExpired { .. } | RefreshError::UnknownGrant { .. } => {
                Error::NeedsReauth
            }
            // `Error` has no storage variant; from a REST caller's viewpoint
            // the request as a whole failed, so `Request` with the full I/O
            // cause chain is the closest honest mapping (never any token
            // material — these variants carry ids and I/O errors only).
            other @ (RefreshError::Load { .. } | RefreshError::Persist { .. }) => Error::Request {
                reason: chained_display(&other),
            },
        }
    }
}

/// Renders an error with its full `source()` chain, `: `-separated, so a
/// mapped error keeps its root cause visible.
fn chained_display(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// Which freshness policy a token request runs under.
#[derive(Clone, Copy)]
enum RefreshPolicy {
    /// Refresh only when the access token is within the near-expiry window.
    IfNearExpiry,
    /// Refresh unless the grant was refreshed within the forced-refresh
    /// grace (the 401-retry path).
    Forced,
}

/// Shared state behind [`GrantManager`]'s cheap clones.
struct ManagerInner<B> {
    store: GrantStore,
    backend: B,
    /// One single-flight mutex per grant id. Entries are never removed: the
    /// set of grant ids a daemon touches is small and bounded (spec NG2 — one
    /// local user), so the map cannot grow meaningfully.
    locks: SyncMutex<HashMap<GrantId, Arc<tokio::sync::Mutex<()>>>>,
}

/// The token-refresh state machine over a [`GrantStore`] (see the module docs
/// for the full contract). Cheap to clone; clones share state, so a process
/// must hold exactly one lineage of clones per store directory for the
/// single-flight guarantee to hold.
pub struct GrantManager<B> {
    inner: Arc<ManagerInner<B>>,
}

impl<B> Clone for GrantManager<B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B> fmt::Debug for GrantManager<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The backend is deliberately omitted: it needs no Debug bound, and
        // nothing about it belongs in logs.
        f.debug_struct("GrantManager")
            .field("store", &self.inner.store)
            .finish_non_exhaustive()
    }
}

impl<B> GrantManager<B> {
    /// Builds a manager over `store`, refreshing through `backend`.
    #[must_use]
    pub fn new(store: GrantStore, backend: B) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                store,
                backend,
                locks: SyncMutex::new(HashMap::new()),
            }),
        }
    }

    /// The underlying grant store.
    #[must_use]
    pub fn store(&self) -> &GrantStore {
        &self.inner.store
    }

    /// A cloneable [`TokenProvider`] handle bound to one grant, for wiring a
    /// [`crate::RestClient`] (or any other consumer of the trait) to this
    /// manager.
    #[must_use]
    pub fn token_provider(&self, grant_id: GrantId) -> GrantTokenProvider<B> {
        GrantTokenProvider {
            manager: self.clone(),
            grant_id,
        }
    }

    /// The per-grant single-flight lock, created on first use.
    fn lock_for(&self, grant_id: &GrantId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.inner.locks.lock().expect("grant-lock map poisoned");
        Arc::clone(locks.entry(grant_id.clone()).or_default())
    }
}

impl<B: RefreshBackend> GrantManager<B> {
    /// Returns an access token for `grant_id` that is valid right now,
    /// transparently refreshing (and rotating) first when the stored token is
    /// within 5 minutes of expiry. **The only sanctioned token accessor** —
    /// see the module docs.
    ///
    /// # Errors
    ///
    /// [`RefreshError::AuthExpired`] (sticky) once the grant needs re-auth;
    /// [`RefreshError::UnknownGrant`]/[`RefreshError::Load`] when the grant
    /// can't be read; [`RefreshError::Persist`] when the rotated pair can't
    /// be made durable (no token is returned then — fail closed);
    /// [`RefreshError::Github`] for refresh attempts that failed without
    /// invalidating the grant.
    pub async fn token_for(&self, grant_id: &GrantId) -> Result<SecretString, RefreshError> {
        self.token_inner(grant_id, RefreshPolicy::IfNearExpiry)
            .await
    }

    /// Forces a refresh regardless of expiry — the 401-retry hook (see
    /// [`with_reauth_retry`]) — unless the grant was already refreshed within
    /// the last few seconds, in which case the current token is returned
    /// unrotated (see [`FORCED_REFRESH_GRACE_SECS`] for why).
    ///
    /// # Errors
    ///
    /// As [`GrantManager::token_for`].
    pub async fn refresh_now(&self, grant_id: &GrantId) -> Result<SecretString, RefreshError> {
        self.token_inner(grant_id, RefreshPolicy::Forced).await
    }

    /// The grant's current [`GrantPhase`]. Advisory: the phase can change the
    /// moment this returns (a refresh may start or finish concurrently).
    ///
    /// # Errors
    ///
    /// [`RefreshError::UnknownGrant`]/[`RefreshError::Load`] when the grant
    /// can't be read.
    pub async fn phase(&self, grant_id: &GrantId) -> Result<GrantPhase, RefreshError> {
        let lock = self.lock_for(grant_id);
        // Held => a `token_inner` call is in flight for this grant right now.
        if lock.try_lock().is_err() {
            return Ok(GrantPhase::Refreshing);
        }
        let grant = self.load(grant_id).await?;
        Ok(phase_of(&grant, Utc::now()))
    }

    async fn token_inner(
        &self,
        grant_id: &GrantId,
        policy: RefreshPolicy,
    ) -> Result<SecretString, RefreshError> {
        let lock = self.lock_for(grant_id);
        let _flight = lock.lock().await;

        // (Re-)read under the lock. A caller that queued behind a concurrent
        // refresh observes the already-rotated, already-persisted pair here
        // and returns without its own HTTP call — this line is the
        // single-flight collapse.
        let mut grant = self.load(grant_id).await?;

        if grant.state == GrantState::NeedsReauth {
            // Sticky: no GitHub traffic once a grant needs re-auth.
            return Err(RefreshError::AuthExpired {
                login: grant.github_login,
            });
        }

        let now = Utc::now();
        let fresh_enough = match policy {
            RefreshPolicy::IfNearExpiry => {
                grant.access_token_expires_at > now + near_expiry_window()
            }
            RefreshPolicy::Forced => now < grant.last_refreshed_at + forced_refresh_grace(),
        };
        if fresh_enough {
            return Ok(grant.access_token);
        }

        // An expired refresh token cannot be exchanged; transition without a
        // doomed round-trip to GitHub (spec R1.2).
        if grant.refresh_token_expires_at <= now {
            return Err(self.transition_to_needs_reauth(grant).await);
        }

        let pair = match self.refresh_with_retry(&grant.refresh_token).await {
            Ok(pair) => pair,
            Err(RefreshFailure::InvalidGrant) => {
                return Err(self.transition_to_needs_reauth(grant).await);
            }
            Err(RefreshFailure::Transient(e) | RefreshFailure::Fatal(e)) => {
                // The refresh token was not consumed; the grant stays `Valid`
                // on disk and a later call retries from scratch.
                return Err(RefreshError::Github(e));
            }
        };

        // Persist-before-use: make the rotated pair durable BEFORE any caller
        // sees the new access token. On persist failure the pair is dropped
        // and an error returned instead of a token (fail closed) — handing
        // out a token whose rotation is not on disk would let a crash orphan
        // the refresh chain callers are relying on.
        grant.access_token = pair.access_token;
        grant.access_token_expires_at = pair.access_token_expires_at;
        grant.refresh_token = pair.refresh_token;
        grant.refresh_token_expires_at = pair.refresh_token_expires_at;
        grant.last_refreshed_at = Utc::now();
        grant.state = GrantState::Valid;
        self.persist(&grant).await?;

        Ok(grant.access_token)
    }

    /// Persists `needs_reauth` and builds the sticky error. Must be called
    /// with the grant's single-flight lock held.
    async fn transition_to_needs_reauth(&self, mut grant: Grant) -> RefreshError {
        grant.state = GrantState::NeedsReauth;
        let login = grant.github_login.clone();
        if let Err(_persist) = self.persist(&grant).await {
            // Deliberately not propagated: the auth-expired condition came
            // from the exchange itself and is re-derivable (the dead refresh
            // token fails identically next time), so surfacing a disk error
            // here would mask the actionable guidance. An unpersisted sticky
            // state costs at most one redundant doomed refresh attempt after
            // a daemon restart.
        }
        RefreshError::AuthExpired { login }
    }

    /// One refresh exchange with bounded retry on transient failures.
    async fn refresh_with_retry(
        &self,
        refresh_token: &SecretString,
    ) -> Result<AccessTokenPair, RefreshFailure> {
        let mut attempt: u32 = 0;
        loop {
            match self.inner.backend.refresh(refresh_token).await {
                // The retried attempt's error is superseded, not swallowed:
                // if the budget runs out, the final attempt's error returns.
                Err(RefreshFailure::Transient(_)) if attempt < TRANSIENT_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(RETRY_BACKOFF_BASE * attempt).await;
                }
                other => return other,
            }
        }
    }

    /// Reads a grant off the store without blocking the async runtime.
    async fn load(&self, grant_id: &GrantId) -> Result<Grant, RefreshError> {
        let store = self.inner.store.clone();
        let id = grant_id.clone();
        tokio::task::spawn_blocking(move || store.get(&id))
            .await
            .expect("grant-store read task panicked")
            .map_err(|source| RefreshError::Load {
                grant_id: grant_id.to_string(),
                source,
            })?
            .ok_or_else(|| RefreshError::UnknownGrant {
                grant_id: grant_id.to_string(),
            })
    }

    /// Writes a grant to the store (atomic + `fsync`, per [`GrantStore::save`])
    /// without blocking the async runtime.
    async fn persist(&self, grant: &Grant) -> Result<(), RefreshError> {
        let store = self.inner.store.clone();
        let owned = grant.clone();
        tokio::task::spawn_blocking(move || store.save(&owned))
            .await
            .expect("grant-store write task panicked")
            .map_err(|source| RefreshError::Persist {
                grant_id: grant.grant_id.to_string(),
                source,
            })
    }
}

/// A [`TokenProvider`] bound to one grant of a [`GrantManager`] — the bridge
/// that lets [`crate::RestClient`] (and any other consumer of the trait) pull
/// refresh-aware tokens without knowing about grants.
pub struct GrantTokenProvider<B> {
    manager: GrantManager<B>,
    grant_id: GrantId,
}

impl<B> Clone for GrantTokenProvider<B> {
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            grant_id: self.grant_id.clone(),
        }
    }
}

impl<B> fmt::Debug for GrantTokenProvider<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantTokenProvider")
            .field("grant_id", &self.grant_id)
            .finish_non_exhaustive()
    }
}

impl<B: RefreshBackend> TokenProvider for GrantTokenProvider<B> {
    async fn token(&self) -> Result<SecretString, Error> {
        self.manager
            .token_for(&self.grant_id)
            .await
            .map_err(Error::from)
    }
}

/// Runs `op` with retry-once-on-401 semantics for REST callers: when `op`
/// fails with [`Error::NeedsReauth`] (how a `401` surfaces from
/// [`crate::RestClient`]), forces one refresh via
/// [`GrantManager::refresh_now`] and runs `op` once more. Any second failure
/// — including a repeat `401`, or the refresh itself finding the grant dead —
/// is returned as-is.
///
/// # Errors
///
/// Whatever `op` returns; or the forced refresh's failure mapped through
/// `From<RefreshError>` (a dead grant surfaces as [`Error::NeedsReauth`]).
pub async fn with_reauth_retry<B, T, F, Fut>(
    manager: &GrantManager<B>,
    grant_id: &GrantId,
    op: F,
) -> Result<T, Error>
where
    B: RefreshBackend,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    match op().await {
        Err(Error::NeedsReauth) => {
            manager.refresh_now(grant_id).await.map_err(Error::from)?;
            op().await
        }
        other => other,
    }
}

/// Builds an [`AccessTokenPair`] from a successful refresh response.
fn pair_from_wire(wire: RefreshWire) -> Result<AccessTokenPair, RefreshFailure> {
    let missing = |field: &str| {
        RefreshFailure::Fatal(Error::Decode {
            reason: format!("GitHub's refresh response is missing `{field}`"),
        })
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
/// panicking on absurd values (mirrors `device_flow`'s identical convention).
fn saturating_i64(seconds: u64) -> i64 {
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

/// Extracts GitHub's `message` field from an error body, falling back to a
/// bounded excerpt of the raw body (mirrors `rest.rs`/`device_flow.rs`'s
/// identical convention, for the same no-unbounded-blob-in-logs reason).
fn error_message(bytes: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
        && let Some(message) = value.get("message").and_then(|m| m.as_str())
    {
        return message.to_string();
    }
    String::from_utf8_lossy(bytes).chars().take(200).collect()
}

/// Wire shape of a `grant_type=refresh_token` exchange — success and OAuth
/// errors share one envelope, distinguished by whether `error` is present.
/// (`device_flow` has a private equivalent; duplicated deliberately so the
/// two modules stay independently compilable and testable.)
#[derive(Deserialize, Default)]
struct RefreshWire {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use crate::scopes::ScopeSet;

    /// A scripted step for [`MockBackend`].
    #[derive(Clone, Copy)]
    enum Step {
        /// Succeed, minting `mock_access_N` / `mock_refresh_N`.
        Rotate,
        /// Fail with [`RefreshFailure::InvalidGrant`].
        InvalidGrant,
        /// Fail with [`RefreshFailure::Transient`].
        Transient,
        /// Fail with [`RefreshFailure::Fatal`].
        Fatal,
    }

    /// A scripted [`RefreshBackend`]: consumes one [`Step`] per call (an
    /// exhausted script keeps rotating) and counts calls.
    struct MockBackend {
        calls: AtomicUsize,
        seq: AtomicUsize,
        delay: Duration,
        script: SyncMutex<VecDeque<Step>>,
    }

    impl MockBackend {
        fn scripted(steps: impl IntoIterator<Item = Step>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                seq: AtomicUsize::new(0),
                delay: Duration::ZERO,
                script: SyncMutex::new(steps.into_iter().collect()),
            })
        }

        fn rotating() -> Arc<Self> {
            Self::scripted([])
        }

        fn with_delay(self: Arc<Self>, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                seq: AtomicUsize::new(0),
                delay,
                script: SyncMutex::new(self.script.lock().unwrap().clone()),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl RefreshBackend for MockBackend {
        async fn refresh(
            &self,
            _refresh_token: &SecretString,
        ) -> Result<AccessTokenPair, RefreshFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.delay > Duration::ZERO {
                tokio::time::sleep(self.delay).await;
            }
            let step = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Step::Rotate);
            match step {
                Step::Rotate => {
                    let n = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
                    let now = Utc::now();
                    Ok(AccessTokenPair {
                        access_token: SecretString::new(format!("mock_access_{n}")),
                        access_token_expires_at: now + chrono::Duration::hours(8),
                        refresh_token: SecretString::new(format!("mock_refresh_{n}")),
                        refresh_token_expires_at: now + chrono::Duration::days(180),
                    })
                }
                Step::InvalidGrant => Err(RefreshFailure::InvalidGrant),
                Step::Transient => Err(RefreshFailure::Transient(Error::Request {
                    reason: "scripted transient failure".to_string(),
                })),
                Step::Fatal => Err(RefreshFailure::Fatal(Error::UnexpectedStatus {
                    status: 400,
                    message: "scripted fatal failure".to_string(),
                })),
            }
        }
    }

    fn grant_id() -> GrantId {
        GrantId::new("grant-1").unwrap()
    }

    /// A stored grant whose access/refresh tokens expire the given durations
    /// from now. `last_refreshed_at` is set an hour back so the forced-refresh
    /// grace never triggers by accident.
    fn grant_expiring_in(access: chrono::Duration, refresh: chrono::Duration) -> Grant {
        let now = Utc::now();
        Grant {
            grant_id: grant_id(),
            github_login: "octocat".to_string(),
            github_user_id: 42,
            scopes: ScopeSet::defaults(),
            access_token: SecretString::new("ghu_seed_access"),
            access_token_expires_at: now + access,
            refresh_token: SecretString::new("ghr_seed_refresh"),
            refresh_token_expires_at: now + refresh,
            created_at: now - chrono::Duration::hours(1),
            last_refreshed_at: now - chrono::Duration::hours(1),
            state: GrantState::Valid,
        }
    }

    fn setup(
        grant: &Grant,
        backend: Arc<MockBackend>,
    ) -> (TempDir, GrantStore, GrantManager<Arc<MockBackend>>) {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(tmp.path().join("grants")).unwrap();
        store.save(grant).unwrap();
        let manager = GrantManager::new(store.clone(), backend);
        (tmp, store, manager)
    }

    // --- phase / threshold ---------------------------------------------------

    #[test]
    fn phase_of_encodes_the_near_expiry_threshold() {
        let now = Utc::now();
        let fresh = grant_expiring_in(chrono::Duration::minutes(6), chrono::Duration::days(30));
        assert_eq!(phase_of(&fresh, now), GrantPhase::Valid);

        let near = grant_expiring_in(chrono::Duration::minutes(4), chrono::Duration::days(30));
        assert_eq!(phase_of(&near, now), GrantPhase::NearExpiry);

        let mut reauth = fresh.clone();
        reauth.state = GrantState::NeedsReauth;
        assert_eq!(phase_of(&reauth, now), GrantPhase::NeedsReauth);

        // An expired refresh token is needs-reauth regardless of the access
        // token's freshness: nothing can be refreshed any more.
        let dead_refresh =
            grant_expiring_in(chrono::Duration::hours(8), chrono::Duration::seconds(-1));
        assert_eq!(phase_of(&dead_refresh, now), GrantPhase::NeedsReauth);
    }

    #[tokio::test]
    async fn fresh_token_is_returned_without_any_refresh() {
        let backend = MockBackend::rotating();
        let grant = grant_expiring_in(chrono::Duration::minutes(6), chrono::Duration::days(30));
        let (_tmp, _store, manager) = setup(&grant, Arc::clone(&backend));

        let token = manager.token_for(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "ghu_seed_access");
        assert_eq!(
            backend.calls(),
            0,
            "a fresh token must not trigger a refresh"
        );
    }

    #[tokio::test]
    async fn near_expiry_token_is_refreshed_before_being_returned() {
        let backend = MockBackend::rotating();
        let grant = grant_expiring_in(chrono::Duration::minutes(4), chrono::Duration::days(30));
        let (_tmp, _store, manager) = setup(&grant, Arc::clone(&backend));

        let token = manager.token_for(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "mock_access_1");
        assert_eq!(backend.calls(), 1);
    }

    // --- write-ahead rotation ------------------------------------------------

    #[tokio::test]
    async fn rotation_is_on_disk_by_the_time_the_token_is_returned() {
        let backend = MockBackend::rotating();
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, backend);

        let token = manager.token_for(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "mock_access_1");

        // The instant a caller holds the new access token, the rotated pair —
        // crucially including the NEW refresh token — must already be durable.
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.access_token.expose_secret(), "mock_access_1");
        assert_eq!(on_disk.refresh_token.expose_secret(), "mock_refresh_1");
        assert_eq!(on_disk.state, GrantState::Valid);
        assert!(on_disk.last_refreshed_at > grant.last_refreshed_at);
    }

    #[tokio::test]
    async fn failed_persist_fails_closed_and_leaves_the_old_grant_intact() {
        let backend = MockBackend::rotating();
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        // Crash-inject the persist: a directory squatting on the store's temp
        // path makes `GrantStore::save` fail before touching the final file.
        fs::create_dir(store.dir().join("grant-1.json.tmp")).unwrap();

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(matches!(err, RefreshError::Persist { .. }), "got {err:?}");
        assert_eq!(backend.calls(), 1);

        // Fail closed: the freshly minted pair was discarded, never returned,
        // and never leaks through the error's rendering...
        let rendered = format!("{err} / {err:?} / {}", chained_display(&err));
        assert!(!rendered.contains("mock_access_1"));
        assert!(!rendered.contains("mock_refresh_1"));

        // ...and the on-disk grant is exactly as before the attempt.
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.access_token.expose_secret(), "ghu_seed_access");
        assert_eq!(on_disk.refresh_token.expose_secret(), "ghr_seed_refresh");
        assert_eq!(on_disk.state, GrantState::Valid);
    }

    // --- single-flight -------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_collapse_to_exactly_one_refresh() {
        let backend = MockBackend::rotating().with_delay(Duration::from_millis(100));
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, _store, manager) = setup(&grant, Arc::clone(&backend));

        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let manager = manager.clone();
                tokio::spawn(async move { manager.token_for(&grant_id()).await.unwrap() })
            })
            .collect();
        for task in tasks {
            let token = task.await.unwrap();
            assert_eq!(
                token.expose_secret(),
                "mock_access_1",
                "every caller must observe the single rotated token"
            );
        }
        assert_eq!(
            backend.calls(),
            1,
            "N concurrent token_for calls must perform exactly one refresh"
        );
    }

    // --- needs-reauth --------------------------------------------------------

    #[tokio::test]
    async fn invalid_grant_persists_needs_reauth_and_the_error_is_sticky() {
        let backend = MockBackend::scripted([Step::InvalidGrant]);
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "github auth expired for octocat; run 'min github login'"
        );
        assert_eq!(backend.calls(), 1);
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.state, GrantState::NeedsReauth);

        // Sticky: the second call repeats the actionable error without any
        // further backend traffic (spec R1.2 — re-auth, never silent retry).
        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(matches!(err, RefreshError::AuthExpired { .. }));
        assert_eq!(backend.calls(), 1, "needs_reauth must not refresh again");
        assert_eq!(
            manager.phase(&grant_id()).await.unwrap(),
            GrantPhase::NeedsReauth
        );
    }

    #[tokio::test]
    async fn expired_refresh_token_goes_needs_reauth_without_calling_github() {
        let backend = MockBackend::rotating();
        // Access token near expiry AND the refresh token itself already dead.
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::seconds(-1));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(
            matches!(err, RefreshError::AuthExpired { .. }),
            "got {err:?}"
        );
        assert_eq!(backend.calls(), 0, "a dead refresh token must not be sent");
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.state, GrantState::NeedsReauth);
    }

    // --- transient failures --------------------------------------------------

    #[tokio::test]
    async fn transient_failure_is_retried_and_then_succeeds() {
        let backend = MockBackend::scripted([Step::Transient, Step::Rotate]);
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        let token = manager.token_for(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "mock_access_1");
        assert_eq!(backend.calls(), 2, "one failed attempt, one retry");
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.refresh_token.expose_secret(), "mock_refresh_1");
    }

    #[tokio::test]
    async fn exhausted_transient_retries_leave_the_grant_valid_and_retryable() {
        // Enough scripted failures to cover two full retry cycles (the mock
        // falls back to `Rotate` once its script runs out).
        let per_call = 1 + TRANSIENT_RETRIES as usize;
        let backend = MockBackend::scripted(vec![Step::Transient; per_call * 2]);
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(matches!(err, RefreshError::Github(_)), "got {err:?}");
        assert_eq!(
            backend.calls(),
            per_call,
            "initial attempt + bounded retries"
        );

        // Never sticky: the grant stays Valid on disk with its refresh token
        // untouched, and the next call attempts a fresh refresh cycle.
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.state, GrantState::Valid);
        assert_eq!(on_disk.refresh_token.expose_secret(), "ghr_seed_refresh");

        manager.token_for(&grant_id()).await.unwrap_err();
        assert_eq!(backend.calls(), per_call * 2);
    }

    #[tokio::test]
    async fn fatal_failure_is_not_retried_and_leaves_the_grant_valid() {
        let backend = MockBackend::scripted([Step::Fatal, Step::Rotate]);
        let grant = grant_expiring_in(chrono::Duration::minutes(1), chrono::Duration::days(30));
        let (_tmp, store, manager) = setup(&grant, Arc::clone(&backend));

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(matches!(err, RefreshError::Github(_)), "got {err:?}");
        assert_eq!(backend.calls(), 1, "fatal failures must not burn retries");
        let on_disk = store.get(&grant_id()).unwrap().unwrap();
        assert_eq!(on_disk.state, GrantState::Valid);
    }

    // --- forced refresh (401 retry hook) ------------------------------------

    #[tokio::test]
    async fn refresh_now_rotates_a_fresh_token_but_the_grace_collapses_repeats() {
        let backend = MockBackend::rotating();
        let grant = grant_expiring_in(chrono::Duration::hours(8), chrono::Duration::days(30));
        let (_tmp, _store, manager) = setup(&grant, Arc::clone(&backend));

        // Forced: rotates even though the token is nowhere near expiry.
        let token = manager.refresh_now(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "mock_access_1");
        assert_eq!(backend.calls(), 1);

        // A second forced refresh within the grace returns the same token
        // without another rotation — this is what stops a 401-retry stampede
        // from rotating N times, and what terminates the retry-once loop.
        let token = manager.refresh_now(&grant_id()).await.unwrap();
        assert_eq!(token.expose_secret(), "mock_access_1");
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn unknown_grant_is_an_actionable_error() {
        let backend = MockBackend::rotating();
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(tmp.path().join("grants")).unwrap();
        let manager = GrantManager::new(store, backend);

        let err = manager.token_for(&grant_id()).await.unwrap_err();
        assert!(
            matches!(err, RefreshError::UnknownGrant { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("min github login"));
        // The TokenProvider-facing mapping folds this into NeedsReauth.
        assert!(matches!(Error::from(err), Error::NeedsReauth));
    }

    // --- HTTP backend + REST integration, against the mock GitHub -----------

    #[cfg(feature = "test-support")]
    mod http_backed {
        use super::*;

        use crate::device_flow::DeviceFlowClient;
        use crate::device_flow::assemble_grant;
        use crate::rest::RestClient;
        use crate::testing::{MockGithub, RefreshStep};

        fn install_url() -> Url {
            Url::parse("https://github.com/apps/minimal/installations/new").unwrap()
        }

        fn http_backend(mock: &MockGithub) -> HttpRefreshBackend {
            HttpRefreshBackend::new(mock.base_url().clone(), "test-client")
        }

        /// Counts refresh exchanges the mock has served.
        fn refresh_calls(mock: &MockGithub) -> usize {
            mock.captured()
                .iter()
                .filter(|r| {
                    r.path == "/login/oauth/access_token"
                        && r.body_string().contains("grant_type=refresh_token")
                })
                .count()
        }

        #[tokio::test]
        async fn http_backend_speaks_the_refresh_wire_shape() {
            let mock = MockGithub::start().await.expect("mock starts");
            let pair = http_backend(&mock)
                .refresh(&SecretString::new("ghr_current"))
                .await
                .expect("refresh ok");
            assert_eq!(pair.access_token.expose_secret(), "ghu_mock_access_1");
            assert_eq!(pair.refresh_token.expose_secret(), "ghr_mock_refresh_1");

            let captured = mock.captured();
            let req = captured
                .iter()
                .find(|r| r.path == "/login/oauth/access_token")
                .expect("refresh request captured");
            let body = req.body_string();
            assert!(body.contains("grant_type=refresh_token"));
            assert!(body.contains("client_id=test-client"));
            assert!(body.contains("refresh_token=ghr_current"));
        }

        #[tokio::test]
        async fn http_backend_maps_invalid_grant() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.script_refresh([RefreshStep::InvalidGrant]));
            let err = http_backend(&mock)
                .refresh(&SecretString::new("ghr_revoked"))
                .await
                .unwrap_err();
            assert!(matches!(err, RefreshFailure::InvalidGrant), "got {err:?}");
        }

        /// The full write-ahead loop against a rotation-*enforcing* mock: each
        /// refresh must present exactly the refresh token minted by the
        /// previous one, which only works if every rotation was persisted and
        /// re-read — a lost rotation would surface as `invalid_grant` here.
        #[tokio::test]
        async fn manager_survives_strict_rotation_across_sequential_refreshes() {
            let mock = MockGithub::start().await.expect("mock starts");
            // A 60s access TTL keeps every minted token inside the 5-minute
            // near-expiry window, so each token_for performs a refresh.
            mock.configure(|fx| {
                fx.set_device_interval(1);
                fx.set_token_ttls(60, 15_897_600);
            });

            // Seed the grant through a real device-flow login so the mock
            // knows the current refresh token, then turn on strict rotation.
            let dfc = DeviceFlowClient::new(mock.base_url().clone(), mock.base_url().clone());
            let auth = dfc.start_device_flow("test-client").await.unwrap();
            let tokens = dfc.poll("test-client", &auth).await.unwrap();
            let user = dfc.fetch_user(&tokens.access_token).await.unwrap();
            let grant = assemble_grant(grant_id(), user, ScopeSet::defaults(), tokens);
            mock.configure(|fx| fx.set_strict_refresh(true));

            let tmp = TempDir::new().unwrap();
            let store = GrantStore::open(tmp.path().join("grants")).unwrap();
            store.save(&grant).unwrap();
            let manager = GrantManager::new(store.clone(), http_backend(&mock));

            let token = manager.token_for(&grant_id()).await.unwrap();
            assert_eq!(token.expose_secret(), "ghu_mock_access_2");
            let token = manager.token_for(&grant_id()).await.unwrap();
            assert_eq!(token.expose_secret(), "ghu_mock_access_3");

            // Each exchange presented the previous rotation's refresh token.
            let presented: Vec<String> = mock
                .captured()
                .iter()
                .filter(|r| {
                    r.path == "/login/oauth/access_token"
                        && r.body_string().contains("grant_type=refresh_token")
                })
                .map(|r| r.body_string())
                .collect();
            assert_eq!(presented.len(), 2);
            assert!(presented[0].contains("refresh_token=ghr_mock_refresh_1"));
            assert!(presented[1].contains("refresh_token=ghr_mock_refresh_2"));

            // And a rotated-away refresh token is dead — the brick a lost
            // rotation would cause, demonstrated directly.
            let err = http_backend(&mock)
                .refresh(&SecretString::new("ghr_mock_refresh_1"))
                .await
                .unwrap_err();
            assert!(matches!(err, RefreshFailure::InvalidGrant), "got {err:?}");
        }

        #[tokio::test]
        async fn with_reauth_retry_refreshes_once_and_retries_the_call() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_force_unauthorized(true));

            let grant = grant_expiring_in(chrono::Duration::hours(8), chrono::Duration::days(30));
            let tmp = TempDir::new().unwrap();
            let store = GrantStore::open(tmp.path().join("grants")).unwrap();
            store.save(&grant).unwrap();
            let manager = GrantManager::new(store, http_backend(&mock));
            let client = RestClient::new(
                mock.base_url().clone(),
                install_url(),
                manager.token_provider(grant_id()),
            );

            // First /user answers 401; before the retry, "GitHub" recovers
            // (as if the old token had been revoked but the account is fine).
            let attempts = AtomicUsize::new(0);
            let user = with_reauth_retry(&manager, &grant_id(), || {
                if attempts.fetch_add(1, Ordering::SeqCst) == 1 {
                    mock.configure(|fx| fx.set_force_unauthorized(false));
                }
                client.get_user()
            })
            .await
            .expect("retried call succeeds");
            assert_eq!(user.login, "octocat");
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            assert_eq!(refresh_calls(&mock), 1, "exactly one forced refresh");
        }

        #[tokio::test]
        async fn with_reauth_retry_gives_up_after_a_second_401() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_force_unauthorized(true));

            let grant = grant_expiring_in(chrono::Duration::hours(8), chrono::Duration::days(30));
            let tmp = TempDir::new().unwrap();
            let store = GrantStore::open(tmp.path().join("grants")).unwrap();
            store.save(&grant).unwrap();
            let manager = GrantManager::new(store, http_backend(&mock));
            let client = RestClient::new(
                mock.base_url().clone(),
                install_url(),
                manager.token_provider(grant_id()),
            );

            let err = with_reauth_retry(&manager, &grant_id(), || client.get_user())
                .await
                .unwrap_err();
            assert!(matches!(err, Error::NeedsReauth), "got {err:?}");
            assert_eq!(refresh_calls(&mock), 1, "retry-once, not retry-forever");
            let user_calls = mock.captured().iter().filter(|r| r.path == "/user").count();
            assert_eq!(user_calls, 2);
        }
    }
}
