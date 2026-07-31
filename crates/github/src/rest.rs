//! Typed GitHub REST client: authenticated user, App-installation check,
//! repository default branch, and pull-request list/create/get (spec R1.4,
//! R1.5, R2.6, R4.5).
//!
//! [`RestClient`] is generic over [`TokenProvider`] so the daemon can plug in
//! its real, refresh-aware token source while tests use [`StaticToken`]. Every
//! call is built from an `api_base` [`url::Url`] — normally
//! [`crate::GithubConfig::api_base`] — so the client is retargetable at the
//! in-process mock GitHub (`crate::testing`, `test-support` feature) in tests
//! and points at real `https://api.github.com` in production.
//!
//! # Error mapping (spec R8.1)
//!
//! * `401` from any endpoint becomes [`Error::NeedsReauth`] — the caller
//!   should prompt `min github login` rather than retry.
//! * `404` on [`RestClient::repo_installation`] becomes
//!   [`Error::AppNotInstalled`], carrying the caller-supplied installation URL
//!   (spec R1.5).
//! * `404` elsewhere becomes an endpoint-specific, actionable variant
//!   ([`Error::RepoNotFound`], [`Error::PullNotFound`]).
//! * Any other non-2xx status becomes [`Error::UnexpectedStatus`], carrying
//!   only the status code and GitHub's own `message` (or a bounded excerpt of
//!   the body) — never the full response, which could otherwise grow
//!   unbounded or echo request data back into a log.
//! * Transport failures (DNS, TCP, TLS, timeout) and response bodies that
//!   don't decode become [`Error::Request`] / [`Error::Decode`], built from
//!   the underlying error's `Display`, which never includes header values —
//!   so no token material can reach these error paths.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Error;
use crate::secret::SecretString;

/// Supplies a valid GitHub access token for an authenticated REST call.
///
/// Implementations own refresh: a call to [`TokenProvider::token`] must
/// return a token that is valid *right now*, refreshing a stored grant first
/// if needed. Any failure to produce one (including a revoked or expired
/// refresh token) must surface as [`Error::NeedsReauth`] per spec R1.2, so
/// [`RestClient`] callers only ever need to handle that one variant for
/// auth-expiry, whether it originated from the provider or from a `401`
/// GitHub returned despite a seemingly-valid token.
pub trait TokenProvider: Send + Sync {
    /// Returns a currently-valid access token.
    fn token(&self) -> impl Future<Output = Result<SecretString, Error>> + Send;
}

/// A [`TokenProvider`] that always returns the same fixed token.
///
/// Real callers (the daemon) implement a refresh-aware provider over the
/// on-disk [`crate::GrantStore`]; this one exists so [`RestClient`] is
/// unit-testable without wiring a live grant store.
#[derive(Debug, Clone)]
pub struct StaticToken(SecretString);

impl StaticToken {
    /// Wraps a fixed token that every call returns unchanged.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self(SecretString::new(token))
    }
}

impl TokenProvider for StaticToken {
    async fn token(&self) -> Result<SecretString, Error> {
        Ok(self.0.clone())
    }
}

/// The authenticated user (`GET /user`, spec R1.3).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct User {
    /// The user's login (handle).
    pub login: String,
    /// The user's numeric GitHub id.
    pub id: u64,
}

/// A GitHub App installation on a repository's owner
/// (`GET /repos/{owner}/{repo}/installation`).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Installation {
    /// The installation id.
    pub id: u64,
    /// The installed App's slug (e.g. `minimal`).
    pub app_slug: String,
    /// Whether the installation targets a `User` or an `Organization`.
    pub target_type: String,
    /// The account (user or org) the installation is scoped to.
    pub account: InstallationAccount,
}

/// The account an [`Installation`] is scoped to.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct InstallationAccount {
    /// The account's login.
    pub login: String,
}

/// A repository (`GET /repos/{owner}/{repo}`); only the fields this client
/// needs.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Repository {
    /// `owner/repo`.
    pub full_name: String,
    /// The repository's default branch.
    pub default_branch: String,
}

/// A pull request, as returned by list, create, and get.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct PullRequest {
    /// The pull-request number.
    pub number: u64,
    /// The pull-request title.
    pub title: String,
    /// The pull-request description. Absent in some list responses, so this
    /// defaults to empty rather than failing to decode.
    #[serde(default)]
    pub body: String,
    /// `"open"`, `"closed"`, etc.
    pub state: String,
    /// The web URL for the pull request.
    pub html_url: String,
    /// The head (source) branch.
    pub head: PullRef,
    /// The base (target) branch.
    pub base: PullRef,
}

/// One end (`head` or `base`) of a [`PullRequest`]: just the ref name this
/// client needs.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct PullRef {
    /// The branch name.
    #[serde(rename = "ref")]
    pub ref_name: String,
}

/// Request body for [`RestClient::create_pull`].
#[derive(Debug, Clone, Serialize)]
struct CreatePullBody<'a> {
    title: &'a str,
    head: &'a str,
    base: &'a str,
    body: &'a str,
    draft: bool,
}

/// A typed GitHub REST client (spec R1.4, R1.5, R2.6, R4.5).
///
/// See the module docs for the error-mapping contract.
#[derive(Debug, Clone)]
pub struct RestClient<T> {
    http: reqwest::Client,
    api_base: Url,
    install_url: Url,
    token: T,
}

impl<T: TokenProvider> RestClient<T> {
    /// Builds a client against `api_base` (normally
    /// [`crate::GithubConfig::api_base`]).
    ///
    /// `install_url` is the GitHub App installation page to surface when
    /// [`RestClient::repo_installation`] finds the App not installed (spec
    /// R1.5) — e.g. `https://github.com/apps/gominimal/installations/new`. It
    /// is caller-supplied rather than derived here: building it correctly
    /// needs the App's public slug, which a 404 response carries no way to
    /// learn.
    #[must_use]
    pub fn new(api_base: Url, install_url: Url, token: T) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client construction is infallible with the enabled backends"),
            api_base,
            install_url,
            token,
        }
    }

    /// The authenticated user (spec R1.3).
    pub async fn get_user(&self) -> Result<User, Error> {
        let url = self.url("user")?;
        let resp = self.send(self.http.get(url)).await?;
        decode(resp, |status, message| Error::UnexpectedStatus {
            status,
            message,
        })
        .await
    }

    /// Whether — and as whom — the GitHub App is installed on `owner/repo`.
    ///
    /// A `404` here is GitHub's signal that the App is not installed on this
    /// target; that case becomes [`Error::AppNotInstalled`] rather than an
    /// opaque failure (spec R1.5).
    pub async fn repo_installation(&self, owner: &str, repo: &str) -> Result<Installation, Error> {
        let url = self.url(&format!("repos/{owner}/{repo}/installation"))?;
        let resp = self.send(self.http.get(url)).await?;
        let install_url = self.install_url.to_string();
        decode(resp, move |status, message| {
            if status == 404 {
                Error::AppNotInstalled {
                    install_url: install_url.clone(),
                }
            } else {
                Error::UnexpectedStatus { status, message }
            }
        })
        .await
    }

    /// The repository's default branch.
    pub async fn repo_default_branch(&self, owner: &str, repo: &str) -> Result<String, Error> {
        Ok(self.get_repo(owner, repo).await?.default_branch)
    }

    async fn get_repo(&self, owner: &str, repo: &str) -> Result<Repository, Error> {
        let url = self.url(&format!("repos/{owner}/{repo}"))?;
        let resp = self.send(self.http.get(url)).await?;
        decode(resp, repo_not_found(owner, repo)).await
    }

    /// Lists open pull requests on `owner/repo` whose head matches
    /// `head_owner:head_branch`, for existing-PR-before-create detection
    /// (spec R4.5).
    pub async fn list_pulls(
        &self,
        owner: &str,
        repo: &str,
        head_owner: &str,
        head_branch: &str,
    ) -> Result<Vec<PullRequest>, Error> {
        let mut url = self.url(&format!("repos/{owner}/{repo}/pulls"))?;
        url.query_pairs_mut()
            .append_pair("head", &format!("{head_owner}:{head_branch}"))
            .append_pair("state", "open");
        let resp = self.send(self.http.get(url)).await?;
        decode(resp, repo_not_found(owner, repo)).await
    }

    /// Opens a pull request on `owner/repo`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_pull(
        &self,
        owner: &str,
        repo: &str,
        title: &str,
        head: &str,
        base: &str,
        body: &str,
        draft: bool,
    ) -> Result<PullRequest, Error> {
        let url = self.url(&format!("repos/{owner}/{repo}/pulls"))?;
        let payload = CreatePullBody {
            title,
            head,
            base,
            body,
            draft,
        };
        let json = serde_json::to_vec(&payload).map_err(|e| Error::Request {
            reason: format!("encoding create-pull payload: {e}"),
        })?;
        let builder = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json);
        let resp = self.send(builder).await?;
        decode(resp, repo_not_found(owner, repo)).await
    }

    /// Fetches a single pull request by number.
    pub async fn get_pull(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<PullRequest, Error> {
        let url = self.url(&format!("repos/{owner}/{repo}/pulls/{number}"))?;
        let resp = self.send(self.http.get(url)).await?;
        let (owner, repo) = (owner.to_string(), repo.to_string());
        decode(resp, move |status, message| {
            if status == 404 {
                Error::PullNotFound {
                    owner: owner.clone(),
                    repo: repo.clone(),
                    number,
                }
            } else {
                Error::UnexpectedStatus { status, message }
            }
        })
        .await
    }

    /// Resolves `path` (relative, no leading `/`) against `api_base`.
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.api_base.join(path).map_err(|e| Error::Request {
            reason: format!("building request URL for `{path}`: {e}"),
        })
    }

    /// Attaches auth/standard headers and sends the request.
    async fn send(&self, builder: reqwest::RequestBuilder) -> Result<reqwest::Response, Error> {
        let token = self.token.token().await?;
        builder
            .bearer_auth(token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::USER_AGENT, "minimal-github-client")
            .send()
            .await
            .map_err(|e| Error::Request {
                reason: e.to_string(),
            })
    }
}

/// Builds an `on_error` closure for [`decode`] that maps a `404` to
/// [`Error::RepoNotFound`] and anything else to [`Error::UnexpectedStatus`].
fn repo_not_found(owner: &str, repo: &str) -> impl FnOnce(u16, String) -> Error + 'static {
    let (owner, repo) = (owner.to_string(), repo.to_string());
    move |status, message| {
        if status == 404 {
            Error::RepoNotFound { owner, repo }
        } else {
            Error::UnexpectedStatus { status, message }
        }
    }
}

/// Decodes a GitHub REST response, applying the shared `401 -> NeedsReauth`
/// mapping universally and deferring any other non-2xx status to `on_error`.
async fn decode<R, F>(resp: reqwest::Response, on_error: F) -> Result<R, Error>
where
    R: for<'de> Deserialize<'de>,
    F: FnOnce(u16, String) -> Error,
{
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Error::NeedsReauth);
    }
    let bytes = resp.bytes().await.map_err(|e| Error::Request {
        reason: e.to_string(),
    })?;
    if !status.is_success() {
        return Err(on_error(status.as_u16(), error_message(&bytes)));
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::Decode {
        reason: e.to_string(),
    })
}

/// Extracts GitHub's `message` field from an error body, falling back to a
/// bounded excerpt of the raw body so a malformed error response still yields
/// something actionable without risking an unbounded or binary blob in a log.
fn error_message(bytes: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes)
        && let Some(message) = value.get("message").and_then(|m| m.as_str())
    {
        return message.to_string();
    }
    String::from_utf8_lossy(bytes).chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-support")]
    mod mock_tests {
        use super::*;
        use crate::testing::MockGithub;

        async fn client(mock: &MockGithub) -> RestClient<StaticToken> {
            let install_url = Url::parse("https://github.com/apps/minimal/installations/new")
                .expect("valid install URL");
            RestClient::new(
                mock.base_url().clone(),
                install_url,
                StaticToken::new("ghu_mock_token"),
            )
        }

        #[tokio::test]
        async fn get_user_returns_the_mock_identity() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_user("octocat", 583_231));
            let user = client(&mock).await.get_user().await.expect("get_user ok");
            assert_eq!(user.login, "octocat");
            assert_eq!(user.id, 583_231);
        }

        #[tokio::test]
        async fn get_user_401_maps_to_needs_reauth() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_force_unauthorized(true));
            let err = client(&mock).await.get_user().await.unwrap_err();
            assert!(matches!(err, Error::NeedsReauth), "got {err:?}");
        }

        #[tokio::test]
        async fn installation_present_reports_the_installation() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_installed("octocat", "hello", true));
            let install = client(&mock)
                .await
                .repo_installation("octocat", "hello")
                .await
                .expect("installation present");
            assert_eq!(install.app_slug, "minimal");
            assert_eq!(install.account.login, "octocat");
        }

        #[tokio::test]
        async fn installation_absent_maps_to_app_not_installed_with_url() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_installed("octocat", "hello", false));
            let err = client(&mock)
                .await
                .repo_installation("octocat", "hello")
                .await
                .unwrap_err();
            match err {
                Error::AppNotInstalled { install_url } => {
                    assert_eq!(
                        install_url,
                        "https://github.com/apps/minimal/installations/new"
                    );
                }
                other => panic!("expected AppNotInstalled, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn repo_default_branch_reads_the_configured_branch() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| fx.set_default_branch("octocat", "hello", "develop"));
            let branch = client(&mock)
                .await
                .repo_default_branch("octocat", "hello")
                .await
                .expect("default branch ok");
            assert_eq!(branch, "develop");
        }

        #[tokio::test]
        async fn list_pulls_detects_existing_pr_by_head() {
            let mock = MockGithub::start().await.expect("mock starts");
            mock.configure(|fx| {
                fx.add_pull("octocat", "hello", "feat/x", "main");
            });
            let pulls = client(&mock)
                .await
                .list_pulls("octocat", "hello", "octocat", "feat/x")
                .await
                .expect("list_pulls ok");
            assert_eq!(pulls.len(), 1);
            assert_eq!(pulls[0].head.ref_name, "feat/x");
            assert_eq!(pulls[0].base.ref_name, "main");
            assert_eq!(pulls[0].state, "open");

            // A different head branch does not match the existing PR.
            let none = client(&mock)
                .await
                .list_pulls("octocat", "hello", "octocat", "feat/other")
                .await
                .expect("list_pulls ok");
            assert!(none.is_empty());
        }

        #[tokio::test]
        async fn create_pull_sends_the_expected_payload_shape() {
            let mock = MockGithub::start().await.expect("mock starts");
            let pr = client(&mock)
                .await
                .create_pull(
                    "octocat",
                    "hello",
                    "Add feature x",
                    "feat/x",
                    "main",
                    "does the thing",
                    true,
                )
                .await
                .expect("create_pull ok");
            assert_eq!(pr.title, "Add feature x");
            assert_eq!(pr.head.ref_name, "feat/x");
            assert_eq!(pr.base.ref_name, "main");
            assert!(pr.html_url.contains("/octocat/hello/pull/"));

            let requests = mock.captured();
            let create_req = requests
                .iter()
                .find(|r| r.method == "POST" && r.path == "/repos/octocat/hello/pulls")
                .expect("create-pull request captured");
            let body: serde_json::Value =
                serde_json::from_str(&create_req.body_string()).expect("valid JSON body");
            assert_eq!(body["title"], "Add feature x");
            assert_eq!(body["head"], "feat/x");
            assert_eq!(body["base"], "main");
            assert_eq!(body["body"], "does the thing");
            assert_eq!(body["draft"], true);
            assert_eq!(create_req.bearer_token(), Some("ghu_mock_token"));
        }

        #[tokio::test]
        async fn create_pull_422_maps_to_unexpected_status() {
            let mock = MockGithub::start().await.expect("mock starts");
            // Omitting `head` triggers the mock's 422 "head is required" path.
            let err = client(&mock)
                .await
                .create_pull("octocat", "hello", "t", "", "main", "", false)
                .await
                .unwrap_err();
            match err {
                Error::UnexpectedStatus { status, message } => {
                    assert_eq!(status, 422);
                    assert_eq!(message, "head is required");
                }
                other => panic!("expected UnexpectedStatus, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn get_pull_404_maps_to_pull_not_found() {
            let mock = MockGithub::start().await.expect("mock starts");
            // The mock does not route single-PR-by-number GETs, so it always
            // 404s; the client must still map that to `PullNotFound`, not a
            // generic `UnexpectedStatus`.
            let err = client(&mock)
                .await
                .get_pull("octocat", "hello", 999)
                .await
                .unwrap_err();
            match err {
                Error::PullNotFound {
                    owner,
                    repo,
                    number,
                } => {
                    assert_eq!(owner, "octocat");
                    assert_eq!(repo, "hello");
                    assert_eq!(number, 999);
                }
                other => panic!("expected PullNotFound, got {other:?}"),
            }
        }
    }

    #[test]
    fn repo_not_found_mapper_maps_404_and_defers_other_statuses() {
        let mapper = repo_not_found("octocat", "hello");
        match mapper(404, "Not Found".to_string()) {
            Error::RepoNotFound { owner, repo } => {
                assert_eq!(owner, "octocat");
                assert_eq!(repo, "hello");
            }
            other => panic!("expected RepoNotFound, got {other:?}"),
        }

        let mapper = repo_not_found("octocat", "hello");
        match mapper(500, "boom".to_string()) {
            Error::UnexpectedStatus { status, message } => {
                assert_eq!(status, 500);
                assert_eq!(message, "boom");
            }
            other => panic!("expected UnexpectedStatus, got {other:?}"),
        }
    }

    #[test]
    fn error_message_prefers_githubs_message_field_and_falls_back_to_excerpt() {
        let with_message = serde_json::json!({ "message": "Not Found" }).to_string();
        assert_eq!(error_message(with_message.as_bytes()), "Not Found");

        let long_body = "x".repeat(500);
        let excerpt = error_message(long_body.as_bytes());
        assert_eq!(excerpt.chars().count(), 200);
    }

    #[test]
    fn static_token_provider_returns_its_fixed_token() {
        use std::task::{Context, Poll, Waker};

        // `StaticToken::token` never actually awaits anything, so a single
        // synchronous poll with a no-op waker resolves it without needing a
        // tokio runtime.
        let provider = StaticToken::new("ghu_fixed");
        let mut fut = std::pin::pin!(provider.token());
        let mut cx = Context::from_waker(Waker::noop());
        let token = match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("StaticToken::token unexpectedly pending"),
        };
        assert_eq!(token.unwrap().expose_secret(), "ghu_fixed");
    }
}
