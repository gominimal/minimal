//! A programmable, in-process mock GitHub for tests and e2e (`test-support`).
//!
//! [`MockGithub`] binds a loopback TCP port and serves three surfaces off it,
//! all speaking real GitHub wire shapes so the production device-flow, REST, and
//! git clients can be pointed at it through the `MINIMALD_GITHUB_*_BASE_URL`
//! overrides:
//!
//! * the **OAuth device flow** (`/login/device/code`, `/login/oauth/access_token`)
//!   with scriptable pending/slow-down/expired steps and refresh-token
//!   **rotation** ([`fixtures`]);
//! * the **REST API** (`/user`, repo default branch, App-installation lookup,
//!   pull-request list/create with existing-PR-by-head detection);
//! * an **auth-enforcing git smart-HTTP** endpoint backed by `git http-backend`
//!   ([`smart_http`]) that rejects unauthenticated fetches — the surface that
//!   later proves a credential helper actually fired.
//!
//! Every request is captured (see [`MockGithub::captured`]) so tests can assert
//! on what a client sent. The mock adds no new external runtime dependency: it
//! is hand-rolled on the workspace `tokio` TCP stack ([`http`]).

pub mod fixtures;
pub mod http;
pub mod smart_http;

pub use fixtures::{Fixtures, RefreshStep, TokenStep};
pub use smart_http::GitAuth;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

use http::{Handler, Request, Response};

/// `127.0.0.1:0` — loopback with an OS-chosen port.
fn loopback_any() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// Shared state behind the accept loop: the programmable fixtures, the captured
/// request log, the git fixture root, and the git-auth policy.
struct MockState {
    fixtures: Mutex<Fixtures>,
    captured: Mutex<Vec<CapturedRequest>>,
    git_root: PathBuf,
    git_auth: Mutex<GitAuth>,
}

impl Handler for MockState {
    async fn handle(&self, req: Request) -> Response {
        self.record(&req);
        if req.path.starts_with("/login/") {
            // OAuth / device flow — synchronous, guard not held across an await.
            let mut fx = self.fixtures.lock().expect("fixtures lock poisoned");
            fx.handle_oauth(&req)
        } else if smart_http::is_git_path(&req.path) {
            // Snapshot the auth policy, then release the lock before awaiting the
            // git http-backend subprocess.
            let auth = self
                .git_auth
                .lock()
                .expect("git-auth lock poisoned")
                .clone();
            smart_http::serve(&self.git_root, &auth, &req).await
        } else {
            let mut fx = self.fixtures.lock().expect("fixtures lock poisoned");
            fx.handle_rest(&req)
        }
    }
}

impl MockState {
    fn record(&self, req: &Request) {
        self.captured
            .lock()
            .expect("captured lock poisoned")
            .push(CapturedRequest::from_request(req));
    }
}

/// A running mock GitHub server. Dropping it stops the accept loop and (when the
/// git root is a temp dir) cleans up the fixture repositories.
pub struct MockGithub {
    addr: SocketAddr,
    base_url: Url,
    state: Arc<MockState>,
    accept: JoinHandle<()>,
    /// Kept alive so the fixture-repo temp dir outlives the server; `None` when
    /// the caller supplied its own git root.
    _git_root_guard: Option<tempfile::TempDir>,
}

impl MockGithub {
    /// Starts a mock on `127.0.0.1:0` with default fixtures and a fresh temp
    /// directory for git fixtures.
    pub async fn start() -> io::Result<Self> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().to_path_buf();
        Self::bind(loopback_any(), root, Some(dir)).await
    }

    /// Starts a mock whose git fixtures live under `git_root` (created if
    /// missing), bound to `127.0.0.1:0`. Used by the `github-mock` binary so a
    /// real `git` can be pointed at persistent fixture repos.
    pub async fn start_with_git_root(git_root: impl Into<PathBuf>) -> io::Result<Self> {
        Self::start_with_git_root_at(git_root, loopback_any()).await
    }

    /// Like [`MockGithub::start_with_git_root`] but bound to an explicit address
    /// (pass a port of `0` to let the OS pick one). Used by the `github-mock`
    /// binary so an e2e script can pin the listen address when it needs to.
    pub async fn start_with_git_root_at(
        git_root: impl Into<PathBuf>,
        addr: SocketAddr,
    ) -> io::Result<Self> {
        let root = git_root.into();
        std::fs::create_dir_all(&root)?;
        Self::bind(addr, root, None).await
    }

    async fn bind(
        addr: SocketAddr,
        git_root: PathBuf,
        guard: Option<tempfile::TempDir>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let base_url = Url::parse(&format!("http://{addr}/")).expect("loopback URL is valid");

        let mut fixtures = Fixtures::default();
        // Trim the trailing slash so `html_url`s read like `…/owner/repo/pull/1`.
        fixtures.set_public_base(base_url.as_str().trim_end_matches('/').to_string());

        let state = Arc::new(MockState {
            fixtures: Mutex::new(fixtures),
            captured: Mutex::new(Vec::new()),
            git_root,
            git_auth: Mutex::new(GitAuth::default()),
        });

        let accept = tokio::spawn(http::serve(listener, Arc::clone(&state)));
        Ok(Self {
            addr,
            base_url,
            state,
            accept,
            _git_root_guard: guard,
        })
    }

    /// The base URL to feed every `MINIMALD_GITHUB_*_BASE_URL` override; a single
    /// origin serves OAuth, REST, and git.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The bound loopback address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The directory holding the bare git fixture repositories.
    #[must_use]
    pub fn git_root(&self) -> &Path {
        &self.state.git_root
    }

    /// Mutates the programmable fixtures under the lock.
    pub fn configure(&self, f: impl FnOnce(&mut Fixtures)) {
        let mut fx = self.state.fixtures.lock().expect("fixtures lock poisoned");
        f(&mut fx);
    }

    /// Sets the credential policy enforced by the git smart-HTTP endpoint.
    pub fn set_git_auth(&self, auth: GitAuth) {
        *self.state.git_auth.lock().expect("git-auth lock poisoned") = auth;
    }

    /// Creates a bare git fixture repository served at
    /// `{base_url}/{owner}/{repo}.git`, with one commit on `default_branch`, and
    /// aligns the REST fixtures (default branch + App installed) to match.
    pub fn create_bare_repo(
        &self,
        owner: &str,
        repo: &str,
        default_branch: &str,
    ) -> io::Result<PathBuf> {
        let path = smart_http::create_bare_repo(&self.state.git_root, owner, repo, default_branch)?;
        self.configure(|fx| {
            fx.set_default_branch(owner, repo, default_branch);
            fx.set_installed(owner, repo, true);
        });
        Ok(path)
    }

    /// A snapshot of every request the mock has served so far, in order.
    #[must_use]
    pub fn captured(&self) -> Vec<CapturedRequest> {
        self.state
            .captured
            .lock()
            .expect("captured lock poisoned")
            .clone()
    }

    /// Clears the captured-request log.
    pub fn clear_captured(&self) {
        self.state
            .captured
            .lock()
            .expect("captured lock poisoned")
            .clear();
    }
}

impl Drop for MockGithub {
    fn drop(&mut self) {
        // Stop accepting so the port frees and the temp git root can be removed.
        self.accept.abort();
    }
}

/// A recorded request, for test assertions on what a client sent.
///
/// The `Authorization` header is captured but kept out of the public header list
/// and redacted in `Debug`, so a token presented to the mock cannot leak through
/// a debug print of the capture log. Read it deliberately via
/// [`CapturedRequest::bearer_token`] / [`CapturedRequest::basic_auth`].
#[derive(Clone)]
pub struct CapturedRequest {
    /// Request method (`GET`, `POST`, …).
    pub method: String,
    /// Request path (query stripped).
    pub path: String,
    /// Raw query string (without `?`).
    pub query: String,
    /// Request body bytes.
    pub body: Vec<u8>,
    headers: Vec<(String, String)>,
    authorization: Option<String>,
}

impl CapturedRequest {
    fn from_request(req: &Request) -> Self {
        let mut authorization = None;
        let mut headers = Vec::new();
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.clone());
            } else {
                headers.push((name.clone(), value.clone()));
            }
        }
        Self {
            method: req.method.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            body: req.body.clone(),
            headers,
            authorization,
        }
    }

    /// The first non-`Authorization` header matching `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body decoded as UTF-8, lossily.
    #[must_use]
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Whether an `Authorization` header was present.
    #[must_use]
    pub fn had_authorization(&self) -> bool {
        self.authorization.is_some()
    }

    /// The bearer token from an `Authorization: Bearer …`/`token …` header, if
    /// present. Deliberately explicit so read sites are greppable.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        let value = self.authorization.as_deref()?;
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .or_else(|| value.strip_prefix("token "))
            .map(str::trim)
    }

    /// The `(username, password)` from an `Authorization: Basic …` header, if
    /// present.
    #[must_use]
    pub fn basic_auth(&self) -> Option<(String, String)> {
        smart_http::decode_basic_for_test(self.authorization.as_deref()?)
    }
}

impl std::fmt::Debug for CapturedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("headers", &self.headers)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[REDACTED]"),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests;
