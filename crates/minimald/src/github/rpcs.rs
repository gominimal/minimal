//! GitHub auth RPC handlers (spec R1.1–R1.4): `GithubBeginLogin`,
//! `GithubPollLogin`, `GithubStatus`, `GithubListAuths`, `GithubLogout`.
//!
//! Owned by the `daemon-auth-rpcs` task. Handlers here delegate to
//! `super::state::GithubService`'s device-flow client and `GrantManager`
//! (device-flow login/poll, status, logout), plus refresh status reporting;
//! every span opened here is `github.auth` or `github.refresh` (see the
//! span-name conventions documented in `super::state`). No handler may
//! return a response type carrying token material — every RPC response type
//! is defined in `minimald-rpc` as plain, token-free data.
//!
//! # Channel framing lives in `rpc.rs`
//!
//! These functions are the *decision logic* for each RPC: they take an
//! already-deserialized request (plus whatever daemon state they need) and
//! return the `Errorable<Response>` (or, for [`status`], the
//! `Result<Errorable<Response>, ConnectionError>` a manager lookup can also
//! fail with). The SSH-channel read/write plumbing
//! (`ServeOneshot::handle_channel`) is a `rpc.rs`-private extension trait, so
//! the thin `serve_github_*` wrappers that call into this module live there,
//! matching every other RPC in this daemon.
//!
//! # Device-flow polling: parked, not blocked (R1.1)
//!
//! [`begin_login`] performs exactly one HTTP call itself (`start_device_flow`,
//! fast) so the client gets the verification URL/code immediately, then
//! *parks* the rest of the flow: it spawns a background task that owns the
//! one [`github::DeviceAuthorization`] this login minted and drives
//! `DeviceFlowClient::poll` (which blocks internally, per RFC 8628, until the
//! user approves, the code expires, or GitHub reports a terminal error) plus
//! `fetch_user` and persisting the resulting grant. [`poll_login`] never
//! talks to GitHub itself — it only reads the outcome slot the background
//! task writes to exactly once, keyed by the `login_id` [`begin_login`]
//! returned. This is what lets `GithubPollLogin` answer `Pending` promptly on
//! every call instead of blocking an RPC channel for the lifetime of a login.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use github::{
    DeviceAuthorization, Error as GithubError, GrantId, GrantState, RepoSpec, RestClient, ScopeSet,
    TokenProvider,
};
use minimald_rpc::{
    Errorable, GithubBeginLoginRequest, GithubBeginLoginResponse, GithubIdentity,
    GithubListAuthsRequest, GithubListAuthsResponse, GithubLogoutRequest, GithubLogoutResponse,
    GithubPollLoginRequest, GithubPollLoginResponse, GithubStatusRequest, GithubStatusResponse,
    GrantMetadata, RepoInstallationStatus, SessionRepoStatus,
};

use super::GithubService;
use crate::connection::ConnectionError;
use crate::server::ServerStateHandle;
use crate::sessions::SessionKeyPredicate;

/// GitHub's typical device-code TTL (RFC 8628's own worked example, and what
/// GitHub's device-flow docs use), for [`GithubBeginLoginResponse::expires_in_secs`].
///
/// [`github::DeviceAuthorization`] deliberately keeps its real expiry private
/// (only [`github::DeviceFlowClient::poll`] needs it, to stop polling once
/// the code is truly dead — see that module's docs), so there is no accessor
/// this handler can read the *actual* server-advised value from. Reporting
/// this well-known default costs only display-countdown accuracy: the
/// enforcement of the real expiry happens inside `poll` regardless of what is
/// reported here, and shows up to the client as [`GithubPollLoginResponse::Expired`].
const DEVICE_CODE_TYPICAL_EXPIRY_SECS: u64 = 900;

/// The observed outcome of one in-flight device-flow login, as tracked by
/// [`PENDING_LOGINS`]. Distinct from the wire-facing
/// [`GithubPollLoginResponse`] so this module's internal bookkeeping doesn't
/// have to carry `minimald_rpc`'s `#[non_exhaustive]`/`#[serde(default)]`
/// shape.
#[derive(Debug, Clone)]
enum LoginOutcome {
    Pending,
    Complete { login: String, grant_id: String },
    Failed { message: String },
    Expired,
}

/// Process-lifetime registry of in-flight/completed device-flow logins,
/// keyed by the opaque `login_id` [`begin_login`] mints. Not persisted: a
/// daemon restart mid-login simply means the user re-runs `min github
/// login`. Exactly one background task (spawned by `begin_login`) writes
/// each entry, exactly once, on completion; every [`poll_login`] call only
/// reads. Entries are never evicted — mirrors `github::refresh`'s per-grant
/// lock map: the set of logins one daemon process drives in its lifetime is
/// small and bounded (one anonymous local user, per spec NG2), so this can't
/// grow meaningfully.
static PENDING_LOGINS: LazyLock<StdMutex<HashMap<String, LoginOutcome>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Monotonic counter backing [`next_login_id`]/[`mint_grant_id`]: unique
/// enough within one daemon process (all that either id needs — see their
/// docs), without pulling in a UUID dependency this crate doesn't otherwise
/// need.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mints an opaque, process-unique handle for a new in-flight login. Not a
/// secret (it names a login attempt, not a credential) — safe in logs, safe
/// to hand back to the client so it can poll.
fn next_login_id() -> String {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("login-{}-{n}", now.as_nanos())
}

/// Mints a fresh [`GrantId`] for a just-completed login (spec R6.4 "mint").
/// Every `GithubBeginLogin` mints a new grant; reusing an existing one is a
/// client-side decision made by never calling `login`/`begin_login` again
/// and instead referencing an id from [`GithubListAuths`](minimald_rpc::GithubListAuths)
/// at session-activation time — this handler doesn't implement reuse itself.
///
/// Includes the GitHub login for a human-legible id, sanitized to the
/// filename-safe character set [`github::store`]'s [`github::GrantStore`]
/// requires (ASCII alphanumerics, `-`, `_`); GitHub logins are already in
/// that set, so this is defense in depth, not a load-bearing filter.
fn mint_grant_id(login: &str) -> GrantId {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let safe_login: String = login
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    GrantId::new(format!("{safe_login}-{}-{n}", now.as_nanos()))
        .expect("non-empty by construction: at minimum the timestamp/counter suffix is present")
}

/// Reads the current outcome for `login_id`, if any login with that id was
/// ever begun on this daemon process.
fn peek_login_outcome(login_id: &str) -> Option<LoginOutcome> {
    PENDING_LOGINS
        .lock()
        .expect("pending-logins lock poisoned")
        .get(login_id)
        .cloned()
}

/// Records the terminal (or initial `Pending`) outcome for `login_id`.
fn set_login_outcome(login_id: &str, outcome: LoginOutcome) {
    PENDING_LOGINS
        .lock()
        .expect("pending-logins lock poisoned")
        .insert(login_id.to_string(), outcome);
}

/// Resolves the scopes a login should request (spec R5.1/R5.2): the caller's
/// explicit `scope:permission` labels if any were given, else the
/// least-privilege defaults.
fn resolve_requested_scopes(scopes: &[String]) -> Result<ScopeSet, GithubError> {
    if scopes.is_empty() {
        return Ok(ScopeSet::defaults());
    }
    ScopeSet::from_attr_value(&scopes.join(","))
}

/// Renders a [`ScopeSet`] as the plain `scope:level` labels the wire types
/// use (e.g. `contents:rw`), in the set's canonical consent order.
fn render_scope_labels(scopes: &ScopeSet) -> Vec<String> {
    scopes.iter().map(|(s, p)| format!("{s}:{p}")).collect()
}

/// `GithubBeginLogin` (spec R1.1, R1.4): starts a device-flow login and
/// parks the rest of it in the background (see the module docs).
///
/// # Errors
///
/// Never returns `Err` at the transport level; failures ahead of a usable
/// response (no GitHub App configured, malformed requested scopes, or the
/// device-code request itself failing) come back as `Errorable::Err` with an
/// actionable, non-secret message (spec R8.1).
#[tracing::instrument(name = "github.auth", skip_all)]
pub(crate) async fn begin_login(
    service: GithubService,
    req: GithubBeginLoginRequest,
) -> Errorable<GithubBeginLoginResponse> {
    let client_id = match service.config().client_id() {
        Ok(id) => id.to_string(),
        Err(e) => {
            return Errorable::Err {
                error: e.to_string(),
            };
        }
    };
    let scopes = match resolve_requested_scopes(&req.scopes) {
        Ok(s) => s,
        Err(e) => {
            return Errorable::Err {
                error: e.to_string(),
            };
        }
    };

    let authorization = match service.device_flow().start_device_flow(&client_id).await {
        Ok(a) => a,
        Err(e) => {
            return Errorable::Err {
                error: e.to_string(),
            };
        }
    };

    let login_id = next_login_id();
    let response = GithubBeginLoginResponse::new(
        authorization.verification_uri.to_string(),
        authorization.user_code.clone(),
        login_id.clone(),
        authorization.interval.as_secs(),
        DEVICE_CODE_TYPICAL_EXPIRY_SECS,
    );

    set_login_outcome(&login_id, LoginOutcome::Pending);
    tokio::spawn(run_device_flow_poll(
        service,
        client_id,
        authorization,
        scopes,
        login_id,
    ));

    Errorable::Ok(response)
}

/// The background half of a device-flow login (see the module docs): drives
/// `poll` to completion, fetches the identity, mints and persists a
/// [`github::Grant`], and records the terminal [`LoginOutcome`] for
/// [`poll_login`] to observe. Never panics on a GitHub-side failure — every
/// arm resolves to a recorded outcome instead.
#[tracing::instrument(name = "github.auth", skip_all, fields(grant_id = tracing::field::Empty))]
async fn run_device_flow_poll(
    service: GithubService,
    client_id: String,
    authorization: DeviceAuthorization,
    scopes: ScopeSet,
    login_id: String,
) {
    let outcome = poll_and_persist(&service, &client_id, &authorization, scopes).await;
    tracing::info!("github device-flow login resolved");
    set_login_outcome(&login_id, outcome);
}

/// The fallible core of [`run_device_flow_poll`], split out only so its
/// early-return arms read as a flat sequence of `match`es rather than nested
/// closures. Runs under the caller's `#[instrument]`ed span (records
/// `grant_id` on it once the login mints one).
async fn poll_and_persist(
    service: &GithubService,
    client_id: &str,
    authorization: &DeviceAuthorization,
    scopes: ScopeSet,
) -> LoginOutcome {
    let tokens = match service.device_flow().poll(client_id, authorization).await {
        Ok(t) => t,
        Err(GithubError::NeedsReauth) => return LoginOutcome::Expired,
        Err(e) => {
            return LoginOutcome::Failed {
                message: e.to_string(),
            };
        }
    };
    let user = match service.device_flow().fetch_user(&tokens.access_token).await {
        Ok(u) => u,
        Err(e) => {
            return LoginOutcome::Failed {
                message: e.to_string(),
            };
        }
    };

    let grant_id = mint_grant_id(&user.login);
    tracing::Span::current().record("grant_id", tracing::field::display(&grant_id));
    let login = user.login.clone();
    let grant = github::assemble_grant(grant_id.clone(), user, scopes, tokens);

    let store = service.grants().store().clone();
    match tokio::task::spawn_blocking(move || store.save(&grant)).await {
        Ok(Ok(())) => LoginOutcome::Complete {
            login,
            grant_id: grant_id.to_string(),
        },
        Ok(Err(e)) => LoginOutcome::Failed {
            message: format!("failed to persist GitHub authentication: {e}"),
        },
        Err(_join_err) => LoginOutcome::Failed {
            message: "internal error persisting GitHub authentication".to_string(),
        },
    }
}

/// `GithubPollLogin` (spec R1.1): reads the current outcome of an in-flight
/// login without ever touching the network itself (see the module docs).
///
/// # Errors
///
/// Never returns `Err`: an unknown `login_id` (never begun, or from a
/// previous daemon process) is reported as
/// [`GithubPollLoginResponse::Failed`], not a transport error.
#[tracing::instrument(name = "github.auth", skip_all)]
pub(crate) async fn poll_login(req: GithubPollLoginRequest) -> Errorable<GithubPollLoginResponse> {
    if req.login_id.trim().is_empty() {
        return Errorable::Err {
            error: "missing login_id".to_string(),
        };
    }

    Errorable::Ok(match peek_login_outcome(&req.login_id) {
        None => GithubPollLoginResponse::Failed {
            message: format!(
                "no in-flight GitHub login with id `{}` (it may have completed on a since-restarted daemon)",
                req.login_id
            ),
        },
        Some(LoginOutcome::Pending) => GithubPollLoginResponse::Pending,
        Some(LoginOutcome::Complete { login, grant_id }) => {
            GithubPollLoginResponse::Complete { login, grant_id }
        }
        Some(LoginOutcome::Failed { message }) => GithubPollLoginResponse::Failed { message },
        Some(LoginOutcome::Expired) => GithubPollLoginResponse::Expired,
    })
}

/// `GithubStatus` (spec R1.4/R8.2): identity + token validity/expiry (a live
/// `token_for` refresh check plus a real `GET /user`, not just an
/// on-disk-expiry guess), per-repo App-installation state with guidance URLs
/// (spec R1.5), and the requested session's repo/branch/scope table decoded
/// straight from its `Record` attrs.
///
/// # Errors
///
/// [`ConnectionError::Internal`] only for a genuine daemon-internal failure
/// (the sessions manager itself being unreachable); an unknown or dead
/// session, a session with no GitHub involvement, or GitHub being
/// unreachable all resolve to a normal `Errorable::Ok` response with the
/// corresponding fields empty/`false`/`None` rather than an error — `min
/// github status` must always have *something* to show (R8.2).
#[tracing::instrument(name = "github.auth", skip_all, fields(grant_id = tracing::field::Empty))]
pub(crate) async fn status(
    s: ServerStateHandle,
    req: GithubStatusRequest,
) -> Result<Errorable<GithubStatusResponse>, ConnectionError> {
    let service = s.github().await;

    let mut session_repos = Vec::new();
    let mut session_grant_id: Option<GrantId> = None;
    let mut repo_set: Vec<RepoSpec> = Vec::new();

    if let Some(session_id) = req.session_id {
        let mngr = s.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .map_err(|e| ConnectionError::Internal(e.to_string()))?;
        // An unknown/dead session just means an empty session table below —
        // `min github status` still answers with whatever else it can show.
        if let Some(handle) = handle
            && let Ok(record) = handle.record().await
            && let Ok(attrs) = super::authz::read_github_attrs(&record)
        {
            session_grant_id = attrs.grant_id;
            let scope_labels = attrs
                .scopes
                .as_ref()
                .map(render_scope_labels)
                .unwrap_or_default();
            for repo in &attrs.repos {
                session_repos.push(SessionRepoStatus::new(
                    format!("{}/{}", repo.owner(), repo.repo()),
                    repo.branch().unwrap_or_default().to_string(),
                    repo.base().map(str::to_string),
                    scope_labels.clone(),
                ));
            }
            repo_set = attrs.repos;
        }
    }

    for extra in &req.repos {
        if let Ok(spec) = extra.parse::<RepoSpec>()
            && !repo_set
                .iter()
                .any(|r| r.owner() == spec.owner() && r.repo() == spec.repo())
        {
            repo_set.push(spec);
        }
    }

    let active_grant = match session_grant_id {
        Some(id) => Some(id),
        None => sole_stored_grant(&service).await,
    };
    if let Some(grant_id) = &active_grant {
        tracing::Span::current().record("grant_id", tracing::field::display(grant_id));
    }

    let (identity, token_valid, token_expires_at) = match &active_grant {
        Some(grant_id) => check_identity(&service, grant_id).await,
        None => (None, false, None),
    };

    let installations = match &active_grant {
        Some(grant_id) if token_valid => {
            let rest = service.rest_client(grant_id.clone());
            let mut out = Vec::with_capacity(repo_set.len());
            for repo in &repo_set {
                out.push(repo_installation_status(&rest, repo.owner(), repo.repo()).await);
            }
            out
        }
        _ => repo_set
            .iter()
            .map(|r| {
                RepoInstallationStatus::new(format!("{}/{}", r.owner(), r.repo()), false, None)
            })
            .collect(),
    };

    Ok(Errorable::Ok(GithubStatusResponse::new(
        identity,
        token_valid,
        token_expires_at,
        installations,
        session_repos,
    )))
}

/// The grant to report on when a status request names no session: for the
/// single-anonymous-user daemon (spec NG2), that is the sole stored grant if
/// there is exactly one. With zero or several stored grants and no session
/// to disambiguate, there is no principled "active" one to guess, so this
/// reports `None` rather than picking arbitrarily.
async fn sole_stored_grant(service: &GithubService) -> Option<GrantId> {
    let store = service.grants().store().clone();
    let summaries = tokio::task::spawn_blocking(move || store.list())
        .await
        .ok()?
        .ok()?;
    match &summaries[..] {
        [only] => Some(only.grant_id.clone()),
        _ => None,
    }
}

/// Identity + live token validity for `grant_id` (spec R1.4/R8.2): the
/// stored login (for display even if the token turns out dead) plus a
/// refresh-aware `token_for` and an actual `GET /user`, since GitHub can
/// revoke a token out from under a locally-fresh-looking expiry.
async fn check_identity(
    service: &GithubService,
    grant_id: &GrantId,
) -> (Option<GithubIdentity>, bool, Option<DateTime<Utc>>) {
    let identity = load_grant(service, grant_id)
        .await
        .map(|g| GithubIdentity::new(g.github_login, grant_id.to_string()));

    let token_valid = match service.grants().token_for(grant_id).await {
        Ok(_token) => service
            .rest_client(grant_id.clone())
            .get_user()
            .await
            .is_ok(),
        Err(_) => false,
    };

    let token_expires_at = if token_valid {
        load_grant(service, grant_id)
            .await
            .map(|g| g.access_token_expires_at)
    } else {
        None
    };

    (identity, token_valid, token_expires_at)
}

/// Reads a single stored [`github::Grant`] off the disk store, off the async
/// runtime. `None` on any failure (unknown grant, I/O error, or a panicked
/// blocking task) — every caller here treats an unreadable grant the same as
/// an absent one rather than surfacing a transport error from a status read.
async fn load_grant(service: &GithubService, grant_id: &GrantId) -> Option<github::Grant> {
    let store = service.grants().store().clone();
    let id = grant_id.clone();
    tokio::task::spawn_blocking(move || store.get(&id))
        .await
        .ok()?
        .ok()?
}

/// One [`RepoInstallationStatus`] row (spec R1.5): installed, or not with the
/// guidance URL to install the App.
async fn repo_installation_status<T: TokenProvider>(
    rest: &RestClient<T>,
    owner: &str,
    repo: &str,
) -> RepoInstallationStatus {
    match rest.repo_installation(owner, repo).await {
        Ok(_) => RepoInstallationStatus::new(format!("{owner}/{repo}"), true, None),
        Err(GithubError::AppNotInstalled { install_url }) => {
            RepoInstallationStatus::new(format!("{owner}/{repo}"), false, Some(install_url))
        }
        Err(_) => RepoInstallationStatus::new(format!("{owner}/{repo}"), false, None),
    }
}

/// `GithubListAuths` (spec R1.3/R6.4): every stored grant as metadata only —
/// `github::GrantStore::list` returns [`github::GrantSummary`], which is
/// structurally incapable of carrying a token (see that type's docs), so
/// there is no token to accidentally serialize here regardless.
///
/// `token_valid` is the cheap, offline signal (persisted [`GrantState`]),
/// deliberately not a live `GET /user` per grant — listing every stored
/// grant must not fan out a GitHub call per entry just to answer "which
/// ones do I have" (unlike [`status`], which checks the one active grant
/// live).
///
/// # Errors
///
/// [`Errorable::Err`] if the on-disk grant store can't be read; never a
/// transport error.
#[tracing::instrument(name = "github.auth", skip_all)]
pub(crate) async fn list_auths(
    service: GithubService,
    _req: GithubListAuthsRequest,
) -> Errorable<GithubListAuthsResponse> {
    let store = service.grants().store().clone();
    let summaries = match tokio::task::spawn_blocking(move || store.list()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Errorable::Err {
                error: format!("reading stored GitHub auth grants failed: {e}"),
            };
        }
        Err(_join_err) => {
            return Errorable::Err {
                error: "internal error reading stored GitHub auth grants".to_string(),
            };
        }
    };

    let grants = summaries
        .into_iter()
        .map(|g| {
            GrantMetadata::new(
                g.grant_id.to_string(),
                g.github_login,
                Some(g.created_at),
                render_scope_labels(&g.scopes),
                // A grant isn't itself tied to a fixed repo list on disk —
                // repos are declared per-session (see `github.repos` attrs);
                // a grant's *actual* GitHub-side repo access is whatever the
                // App installation covers, which `min github status` reports
                // per repo instead of duplicating here.
                Vec::new(),
                g.state == GrantState::Valid,
                Some(g.access_token_expires_at),
            )
        })
        .collect();

    Errorable::Ok(GithubListAuthsResponse::new(grants))
}

/// `GithubLogout` (spec R6.4): deletes the stored grant, and — best-effort —
/// would revoke it against GitHub too, but `github::rest::RestClient`
/// exposes no revocation endpoint yet (only user/installation/PR
/// operations), so there is nothing to call there today. Deleting the local
/// file is the security-relevant half regardless: it is what stops
/// `minimald` itself from ever presenting this token again (spec R6.1/R6.3).
///
/// Rejects an empty `grant_id` rather than guessing which grant to remove
/// (fail-closed).
///
/// # Errors
///
/// [`Errorable::Err`] for an empty `grant_id` or an on-disk failure; never a
/// transport error.
#[tracing::instrument(name = "github.auth", skip_all, fields(grant_id = %req.grant_id))]
pub(crate) async fn logout(
    service: GithubService,
    req: GithubLogoutRequest,
) -> Errorable<GithubLogoutResponse> {
    let Ok(grant_id) = GrantId::new(req.grant_id.trim()) else {
        return Errorable::Err {
            error: "grant_id must not be empty".to_string(),
        };
    };

    let store = service.grants().store().clone();
    let existed = {
        let id = grant_id.clone();
        match tokio::task::spawn_blocking(move || store.get(&id)).await {
            Ok(Ok(g)) => g.is_some(),
            Ok(Err(e)) => {
                return Errorable::Err {
                    error: format!("reading GitHub auth grant `{grant_id}` failed: {e}"),
                };
            }
            Err(_join_err) => {
                return Errorable::Err {
                    error: "internal error reading GitHub auth grant".to_string(),
                };
            }
        }
    };

    let store = service.grants().store().clone();
    let id = grant_id.clone();
    match tokio::task::spawn_blocking(move || store.delete(&id)).await {
        Ok(Ok(())) => Errorable::Ok(GithubLogoutResponse::new(existed)),
        Ok(Err(e)) => Errorable::Err {
            error: format!("deleting GitHub auth grant `{grant_id}` failed: {e}"),
        },
        Err(_join_err) => Errorable::Err {
            error: "internal error deleting GitHub auth grant".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet as StdHashSet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use minimald_rpc::{
        GithubBeginLogin, GithubListAuths, GithubLogout, GithubPollLogin, GithubStatus,
    };

    use crate::test_harness::TestServer;

    // -- a tiny hand-rolled mock GitHub -------------------------------------
    //
    // `github::testing::MockGithub` lives behind the `github` crate's
    // `test-support` feature, which `minimald`'s `Cargo.toml` does not
    // currently enable (that file is out of this task's ownership) — this
    // mock is self-contained here instead, on top of `tokio`'s TCP stack
    // (already a `minimald` dependency via `github`'s own `client` feature),
    // mirroring the one-shot HTTP responder `github::device_flow`'s own
    // tests use, extended to serve the handful of requests one full
    // login→poll→status round trip makes.

    /// Serves exactly the endpoints [`begin_login`]/[`run_device_flow_poll`]/
    /// [`status`] call: the OAuth device flow, `GET /user`, and `GET
    /// /repos/{owner}/{repo}/installation`. Always approves the device code
    /// on the first poll attempt — these tests exercise the RPC plumbing,
    /// not GitHub's own pending/slow_down backoff (that is `github::device_flow`'s
    /// own test suite's job).
    struct MockGithub {
        addr: SocketAddr,
        installed: Arc<StdMutex<StdHashSet<String>>>,
    }

    impl MockGithub {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            let installed: Arc<StdMutex<StdHashSet<String>>> =
                Arc::new(StdMutex::new(StdHashSet::new()));
            let installed_bg = Arc::clone(&installed);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let installed = Arc::clone(&installed_bg);
                    tokio::spawn(async move {
                        let _ = Self::handle_one(stream, installed).await;
                    });
                }
            });
            Self { addr, installed }
        }

        fn base_url(&self) -> String {
            format!("http://{}/", self.addr)
        }

        async fn handle_one(
            mut stream: TcpStream,
            installed: Arc<StdMutex<StdHashSet<String>>>,
        ) -> std::io::Result<()> {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (header_len, want_body) = loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(end) = find_header_end(&buf) {
                    let headers = String::from_utf8_lossy(&buf[..end]).into_owned();
                    break (end, content_length(&headers));
                }
            };
            while buf.len() < header_len + 4 + want_body {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let headers_text = String::from_utf8_lossy(&buf[..header_len]).into_owned();
            let request_line = headers_text.lines().next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();

            let (status, body) = Self::route(&method, &path, &installed);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            Ok(())
        }

        fn route(
            method: &str,
            path: &str,
            installed: &StdMutex<StdHashSet<String>>,
        ) -> (&'static str, String) {
            match (method, path) {
                ("POST", "/login/device/code") => (
                    "200 OK",
                    serde_json::json!({
                        "device_code": "mock-device-code",
                        "user_code": "MOCK-1234",
                        "verification_uri": "https://github.com/login/device",
                        "expires_in": 900,
                        "interval": 1,
                    })
                    .to_string(),
                ),
                ("POST", "/login/oauth/access_token") => (
                    "200 OK",
                    serde_json::json!({
                        "access_token": "ghu_mock_access_token",
                        "token_type": "bearer",
                        "expires_in": 28800,
                        "refresh_token": "ghr_mock_refresh_token",
                        "refresh_token_expires_in": 15_897_600,
                    })
                    .to_string(),
                ),
                ("GET", "/user") => (
                    "200 OK",
                    serde_json::json!({"login": "octocat", "id": 583_231}).to_string(),
                ),
                (method, path)
                    if method == "GET"
                        && path.starts_with("/repos/")
                        && path.ends_with("/installation") =>
                {
                    let repo = path
                        .trim_start_matches("/repos/")
                        .trim_end_matches("/installation")
                        .trim_end_matches('/');
                    if installed.lock().expect("mock lock poisoned").contains(repo) {
                        let owner = repo.split('/').next().unwrap_or("");
                        (
                            "200 OK",
                            serde_json::json!({
                                "id": 1,
                                "app_slug": "minimal",
                                "target_type": "User",
                                "account": {"login": owner},
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            "404 Not Found",
                            serde_json::json!({"message": "Not Found"}).to_string(),
                        )
                    }
                }
                _ => (
                    "404 Not Found",
                    serde_json::json!({"message": "Not Found"}).to_string(),
                ),
            }
        }
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    /// Builds a [`TestServer`] whose `GithubService` targets `mock`, by
    /// scoping the `MINIMALD_GITHUB_*` env-var overrides
    /// (`github::GithubConfig::from_env`'s only input) to the narrow window
    /// around `TestServer::new()`'s single read of them — the daemon
    /// resolves and captures its config once at construction, so the
    /// override does not need to (and, to minimize cross-test interference
    /// under a non-isolated `cargo test` run, should not) outlive that call.
    async fn server_against(mock: &MockGithub) -> TestServer {
        let base = mock.base_url();
        // SAFETY: no other thread in this process is expected to read these
        // three daemon-config env vars mid-mutation; the window is scoped to
        // one synchronous-from-this-task's-perspective `TestServer::new()`
        // call, mirroring the same accepted-risk pattern already used by
        // e.g. `paths::tests` and `minvmd`'s image tests for env-var-driven
        // construction.
        unsafe {
            std::env::set_var(github::config::ENV_CLIENT_ID, "test-client");
            std::env::set_var(github::config::ENV_OAUTH_BASE, &base);
            std::env::set_var(github::config::ENV_API_BASE, &base);
        }
        let server = TestServer::new().await;
        unsafe {
            std::env::remove_var(github::config::ENV_CLIENT_ID);
            std::env::remove_var(github::config::ENV_OAUTH_BASE);
            std::env::remove_var(github::config::ENV_API_BASE);
        }
        server
    }

    #[tokio::test]
    async fn login_poll_status_round_trip_against_the_mock() {
        let mock = MockGithub::start().await;
        let server = server_against(&mock).await;
        let mut client = server.connect().await;

        // -- login: begin --
        let begin = client
            .call::<GithubBeginLogin>(&GithubBeginLoginRequest::new(vec![]))
            .await;
        let begin = match begin {
            Errorable::Ok(r) => r,
            Errorable::Err { error } => panic!("begin_login failed: {error}"),
        };
        assert_eq!(begin.verification_uri, "https://github.com/login/device");
        assert_eq!(begin.user_code, "MOCK-1234");
        assert!(!begin.login_id.is_empty());

        // -- login: poll to completion --
        let mut grant_id = String::new();
        let mut login = String::new();
        let mut completed = false;
        for _ in 0..50 {
            match client
                .call::<GithubPollLogin>(&GithubPollLoginRequest::new(begin.login_id.clone()))
                .await
            {
                Errorable::Ok(GithubPollLoginResponse::Pending) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Errorable::Ok(GithubPollLoginResponse::Complete {
                    login: l,
                    grant_id: g,
                }) => {
                    login = l;
                    grant_id = g;
                    completed = true;
                    break;
                }
                other => panic!("unexpected poll outcome: {other:?}"),
            }
        }
        assert!(completed, "login did not complete in time");
        assert_eq!(login, "octocat");
        assert!(!grant_id.is_empty());

        // -- status: identity/token valid, and a not-installed repo carries
        // an install URL (spec R1.5) --
        let status_resp = client
            .call::<GithubStatus>(&GithubStatusRequest::new(
                None,
                vec!["octocat/hello".to_string()],
            ))
            .await;
        let status_resp = match status_resp {
            Errorable::Ok(r) => r,
            Errorable::Err { error } => panic!("status failed: {error}"),
        };
        assert!(
            status_resp.token_valid,
            "freshly minted token must be valid"
        );
        let identity = status_resp
            .identity
            .expect("an identity must be reported once a grant is stored");
        assert_eq!(identity.login, "octocat");
        assert_eq!(identity.grant_id, grant_id);
        assert_eq!(status_resp.installations.len(), 1);
        let install = &status_resp.installations[0];
        assert_eq!(install.repo, "octocat/hello");
        assert!(!install.installed);
        assert_eq!(
            install.install_url.as_deref(),
            Some("https://github.com/apps/minimal/installations/new")
        );

        // Now mark it installed and confirm the flip.
        mock.installed
            .lock()
            .unwrap()
            .insert("octocat/hello".to_string());
        let status_resp = client
            .call::<GithubStatus>(&GithubStatusRequest::new(
                None,
                vec!["octocat/hello".to_string()],
            ))
            .await
            .unwrap();
        assert!(status_resp.installations[0].installed);
        assert!(status_resp.installations[0].install_url.is_none());

        // -- serialized responses are grep-clean of the mock's token bytes --
        for secret in ["ghu_mock_access_token", "ghr_mock_refresh_token"] {
            assert!(!serde_json::to_string(&begin).unwrap().contains(secret));
            assert!(
                !serde_json::to_string(&status_resp)
                    .unwrap()
                    .contains(secret)
            );
        }

        // -- list-auths: metadata only, still no token bytes --
        let listed = client
            .call::<GithubListAuths>(&GithubListAuthsRequest::new())
            .await;
        let listed = match listed {
            Errorable::Ok(r) => r,
            Errorable::Err { error } => panic!("list_auths failed: {error}"),
        };
        assert_eq!(listed.grants.len(), 1);
        assert_eq!(listed.grants[0].grant_id, grant_id);
        assert_eq!(listed.grants[0].login, "octocat");
        assert!(listed.grants[0].token_valid);
        let listed_json = serde_json::to_string(&listed).unwrap();
        for secret in ["ghu_mock_access_token", "ghr_mock_refresh_token"] {
            assert!(!listed_json.contains(secret));
        }

        // -- logout: removes the grant --
        let logout_resp = client
            .call::<GithubLogout>(&GithubLogoutRequest::new(grant_id.clone()))
            .await;
        match logout_resp {
            Errorable::Ok(r) => assert!(r.removed),
            Errorable::Err { error } => panic!("logout failed: {error}"),
        }
        let listed_after = client
            .call::<GithubListAuths>(&GithubListAuthsRequest::new())
            .await
            .unwrap();
        assert!(listed_after.grants.is_empty());
    }

    #[tokio::test]
    async fn begin_login_without_a_configured_app_fails_closed() {
        // No env overrides at all: the ambient test environment has no
        // `MINIMALD_GITHUB_CLIENT_ID` set (see `super::state`'s own tests,
        // which assume exactly this), so `GithubConfig::from_env` resolves
        // unconfigured and `begin_login` must refuse before any network I/O.
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GithubBeginLogin>(&GithubBeginLoginRequest::new(vec![]))
            .await;
        match resp {
            Errorable::Err { error } => {
                assert!(error.contains("MINIMALD_GITHUB_CLIENT_ID"));
            }
            Errorable::Ok(_) => panic!("expected NotConfigured to fail begin_login"),
        }
    }

    #[tokio::test]
    async fn poll_login_of_unknown_id_is_a_clean_failed_not_a_transport_error() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GithubPollLogin>(&GithubPollLoginRequest::new("no-such-login".to_string()))
            .await;
        match resp {
            Errorable::Ok(GithubPollLoginResponse::Failed { message }) => {
                assert!(message.contains("no-such-login"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn logout_of_empty_grant_id_is_rejected() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GithubLogout>(&GithubLogoutRequest::new(String::new()))
            .await;
        assert!(matches!(resp, Errorable::Err { .. }));
    }

    #[tokio::test]
    async fn logout_of_unknown_grant_is_not_an_error_and_reports_not_removed() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GithubLogout>(&GithubLogoutRequest::new("never-existed".to_string()))
            .await;
        match resp {
            Errorable::Ok(r) => assert!(!r.removed),
            Errorable::Err { error } => panic!("logout of unknown grant should not error: {error}"),
        }
    }

    #[tokio::test]
    async fn status_with_no_session_and_no_stored_grants_reports_no_identity() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GithubStatus>(&GithubStatusRequest::new(None, vec![]))
            .await
            .unwrap();
        assert!(resp.identity.is_none());
        assert!(!resp.token_valid);
        assert!(resp.installations.is_empty());
        assert!(resp.session_repos.is_empty());
    }
}
