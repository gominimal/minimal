//! Programmable state and OAuth/REST route logic for the mock GitHub server.
//!
//! [`Fixtures`] is the mutable heart of the mock: it holds the scripted device
//! flow, the token/refresh behaviour (including refresh-token **rotation**), the
//! authenticated user, per-repo installation and default-branch state, and the
//! in-memory pull-request table. The HTTP transport ([`super::http`]) hands each
//! parsed request to [`Fixtures::handle_oauth`] or [`Fixtures::handle_rest`],
//! which read/mutate this state and build a [`Response`] — synchronously, so the
//! caller never holds the guard across an `.await`.
//!
//! Everything here speaks the real GitHub wire shapes (form-encoded token
//! exchange, the `error`/`error_description` device-flow envelope, the REST JSON
//! objects) so the production device-flow and REST clients can be pointed at the
//! mock unchanged via the `MINIMALD_GITHUB_*_BASE_URL` overrides.

use std::collections::BTreeMap;

use serde_json::json;

use super::http::{Request, Response};

/// One scripted step of the device-code token-exchange poll
/// (`grant_type=urn:ietf:params:oauth:grant-type:device_code`).
///
/// A test scripts a sequence with [`Fixtures::script_device_exchange`]; each
/// poll consumes the next step, and the **last** step is sticky (repeated once
/// the queue is exhausted) so an `Approve` at the end stays approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenStep {
    /// `authorization_pending` — the user has not yet approved.
    Pending,
    /// `slow_down` — the client is polling too fast; interval is bumped.
    SlowDown,
    /// `expired_token` — the device code expired before approval.
    Expired,
    /// `access_denied` — the user rejected the request.
    AccessDenied,
    /// The user approved: mint a fresh access + refresh token pair.
    Approve,
}

/// One scripted step of a refresh-token exchange (`grant_type=refresh_token`).
///
/// The default behaviour with no script is [`RefreshStep::Rotate`] on every
/// call. Scripted sequences are sticky-on-last like [`TokenStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefreshStep {
    /// Succeed and rotate: mint a fresh access token **and a fresh refresh
    /// token** (GitHub rotates refresh tokens on every refresh).
    Rotate,
    /// `invalid_grant` — the refresh token is expired/revoked; the caller must
    /// re-authenticate.
    InvalidGrant,
}

/// Per-repository mock state.
#[derive(Debug, Clone)]
struct RepoFixture {
    default_branch: String,
    installed: bool,
    pulls: Vec<Pull>,
}

impl Default for RepoFixture {
    fn default() -> Self {
        Self {
            // Happy-path default so a repo works without explicit setup; tests
            // flip these to exercise the not-installed / other-branch paths.
            default_branch: "main".to_string(),
            installed: true,
            pulls: Vec::new(),
        }
    }
}

/// An in-memory pull request.
#[derive(Debug, Clone)]
struct Pull {
    number: u64,
    title: String,
    head: String,
    base: String,
    body: String,
    html_url: String,
}

/// The authenticated GitHub user the mock reports from `GET /user`.
#[derive(Debug, Clone)]
struct UserFixture {
    login: String,
    id: u64,
}

/// Programmable state backing the mock GitHub server.
///
/// Construct via [`Fixtures::default`] (which yields sensible happy-path
/// defaults) and mutate through the setter methods before — or between —
/// requests.
#[derive(Debug)]
pub struct Fixtures {
    // Device flow.
    device_code: String,
    user_code: String,
    verification_uri: String,
    device_interval: u64,
    device_expires_in: u64,
    token_script: Vec<TokenStep>,
    token_cursor: usize,

    // Token/refresh minting.
    refresh_script: Vec<RefreshStep>,
    refresh_cursor: usize,
    token_seq: u64,
    access_ttl: u64,
    refresh_ttl: u64,
    last_refresh_token: Option<String>,
    strict_refresh: bool,

    // REST.
    user: UserFixture,
    force_unauthorized: bool,
    repos: BTreeMap<(String, String), RepoFixture>,
    next_pull_number: u64,

    /// Public base URL of the mock, used to build `html_url`s. Set by the server
    /// once it has bound a port.
    public_base: String,
}

impl Default for Fixtures {
    fn default() -> Self {
        Self {
            device_code: "mock_device_code".to_string(),
            user_code: "WDJB-MJHT".to_string(),
            verification_uri: "https://github.com/login/device".to_string(),
            device_interval: 5,
            device_expires_in: 900,
            // Empty script => approve immediately, so the common case (drive a
            // full login) needs no setup.
            token_script: Vec::new(),
            token_cursor: 0,
            refresh_script: Vec::new(),
            refresh_cursor: 0,
            token_seq: 0,
            access_ttl: 28_800,      // ~8h, like a real user token
            refresh_ttl: 15_897_600, // ~6mo
            last_refresh_token: None,
            strict_refresh: false,
            user: UserFixture {
                login: "octocat".to_string(),
                id: 583_231,
            },
            force_unauthorized: false,
            repos: BTreeMap::new(),
            next_pull_number: 1000,
            public_base: "https://github.example".to_string(),
        }
    }
}

impl Fixtures {
    // --- device-flow / token scripting --------------------------------------

    /// Sets the device/user codes and verification URI returned by
    /// `POST /login/device/code`.
    pub fn set_device_codes(
        &mut self,
        device_code: impl Into<String>,
        user_code: impl Into<String>,
        verification_uri: impl Into<String>,
    ) {
        self.device_code = device_code.into();
        self.user_code = user_code.into();
        self.verification_uri = verification_uri.into();
    }

    /// Sets the poll `interval` (seconds) advertised in the device-code and
    /// `slow_down` responses.
    pub fn set_device_interval(&mut self, seconds: u64) {
        self.device_interval = seconds;
    }

    /// Scripts the device-code token-exchange poll. The sequence is consumed one
    /// step per poll; the last step is sticky. An empty script approves
    /// immediately.
    pub fn script_device_exchange(&mut self, steps: impl IntoIterator<Item = TokenStep>) {
        self.token_script = steps.into_iter().collect();
        self.token_cursor = 0;
    }

    /// Scripts refresh-token exchanges. Empty (the default) rotates on every
    /// call; otherwise the sequence is consumed one step per refresh, last
    /// sticky.
    pub fn script_refresh(&mut self, steps: impl IntoIterator<Item = RefreshStep>) {
        self.refresh_script = steps.into_iter().collect();
        self.refresh_cursor = 0;
    }

    /// When enabled, a refresh presenting anything other than the most recently
    /// issued refresh token is rejected with `invalid_grant` — modelling
    /// GitHub's refresh-token rotation, so a lost rotation bricks the grant.
    pub fn set_strict_refresh(&mut self, strict: bool) {
        self.strict_refresh = strict;
    }

    /// Sets the access-token and refresh-token lifetimes (seconds) reported in
    /// token responses.
    pub fn set_token_ttls(&mut self, access_ttl: u64, refresh_ttl: u64) {
        self.access_ttl = access_ttl;
        self.refresh_ttl = refresh_ttl;
    }

    // --- REST state ---------------------------------------------------------

    /// Sets the login and numeric id reported by `GET /user`.
    pub fn set_user(&mut self, login: impl Into<String>, id: u64) {
        self.user = UserFixture {
            login: login.into(),
            id,
        };
    }

    /// When enabled, authenticated REST endpoints answer `401 Bad credentials`,
    /// exercising the "401 → needs re-auth" client path.
    pub fn set_force_unauthorized(&mut self, unauthorized: bool) {
        self.force_unauthorized = unauthorized;
    }

    /// Sets whether the App is installed on `owner/repo` (spec R1.5). Not
    /// installed makes `GET /repos/{o}/{r}/installation` answer `404`.
    pub fn set_installed(&mut self, owner: &str, repo: &str, installed: bool) {
        self.repo_entry(owner, repo).installed = installed;
    }

    /// Sets the default branch reported for `owner/repo`.
    pub fn set_default_branch(&mut self, owner: &str, repo: &str, branch: impl Into<String>) {
        self.repo_entry(owner, repo).default_branch = branch.into();
    }

    /// Seeds an existing open pull request for `owner/repo` so
    /// existing-PR-by-head detection (spec R4.5) fires. Returns the PR number.
    pub fn add_pull(
        &mut self,
        owner: &str,
        repo: &str,
        head: impl Into<String>,
        base: impl Into<String>,
    ) -> u64 {
        let number = self.next_pull_number;
        self.next_pull_number += 1;
        let head = head.into();
        let base = base.into();
        let html_url = format!("{}/{owner}/{repo}/pull/{number}", self.public_base);
        self.repo_entry(owner, repo).pulls.push(Pull {
            number,
            title: format!("PR for {head}"),
            head,
            base,
            body: String::new(),
            html_url,
        });
        number
    }

    /// Sets the base URL used to construct `html_url`s. Called by the server
    /// once bound.
    pub(super) fn set_public_base(&mut self, base: impl Into<String>) {
        self.public_base = base.into();
    }

    // --- routing ------------------------------------------------------------

    /// Handles an OAuth / device-flow request (`/login/...`). Synchronous: no
    /// `.await`, so the caller can hold the state lock across it.
    pub(super) fn handle_oauth(&mut self, req: &Request) -> Response {
        match req.path.as_str() {
            "/login/device/code" => self.device_code_response(),
            "/login/oauth/access_token" => self.token_response(req),
            _ => not_found("unknown OAuth endpoint"),
        }
    }

    /// Handles a REST request. Synchronous, as [`Fixtures::handle_oauth`].
    pub(super) fn handle_rest(&mut self, req: &Request) -> Response {
        let segments = req.segments();
        match (req.method.as_str(), segments.as_slice()) {
            ("GET", ["user"]) => self.user_response(),
            ("GET", ["repos", owner, repo]) => self.repo_response(owner, repo),
            ("GET", ["repos", owner, repo, "installation"]) => {
                self.installation_response(owner, repo)
            }
            ("GET", ["repos", owner, repo, "pulls"]) => self.list_pulls_response(owner, repo, req),
            ("POST", ["repos", owner, repo, "pulls"]) => {
                self.create_pull_response(owner, repo, req)
            }
            _ => not_found("unknown REST endpoint"),
        }
    }

    // --- device flow --------------------------------------------------------

    fn device_code_response(&self) -> Response {
        Response::json(
            200,
            &json!({
                "device_code": self.device_code,
                "user_code": self.user_code,
                "verification_uri": self.verification_uri,
                "expires_in": self.device_expires_in,
                "interval": self.device_interval,
            }),
        )
    }

    fn token_response(&mut self, req: &Request) -> Response {
        let form = parse_form(&req.body);
        let grant_type = form_get(&form, "grant_type").unwrap_or_default();
        if grant_type == "refresh_token" {
            let presented = form_get(&form, "refresh_token").unwrap_or_default();
            self.refresh_response(&presented)
        } else {
            self.device_poll_response()
        }
    }

    fn device_poll_response(&mut self) -> Response {
        match self.next_token_step() {
            TokenStep::Pending => oauth_error(200, "authorization_pending", "waiting for the user"),
            TokenStep::SlowDown => Response::json(
                200,
                &json!({
                    "error": "slow_down",
                    "error_description": "polling too fast",
                    "interval": self.device_interval + 5,
                }),
            ),
            TokenStep::Expired => oauth_error(200, "expired_token", "the device code has expired"),
            TokenStep::AccessDenied => {
                oauth_error(200, "access_denied", "the user cancelled the request")
            }
            TokenStep::Approve => self.mint_token_response(),
        }
    }

    fn refresh_response(&mut self, presented: &str) -> Response {
        if self.strict_refresh {
            match &self.last_refresh_token {
                Some(expected) if expected == presented => {}
                _ => {
                    return oauth_error(
                        200,
                        "invalid_grant",
                        "the refresh token is expired or was already rotated",
                    );
                }
            }
        }
        match self.next_refresh_step() {
            RefreshStep::Rotate => self.mint_token_response(),
            RefreshStep::InvalidGrant => oauth_error(
                200,
                "invalid_grant",
                "the refresh token is expired or revoked",
            ),
        }
    }

    /// Mints a fresh access + refresh token pair (always a new refresh token, so
    /// callers observe rotation) and returns the OAuth success envelope.
    fn mint_token_response(&mut self) -> Response {
        self.token_seq += 1;
        let seq = self.token_seq;
        let access = format!("ghu_mock_access_{seq}");
        let refresh = format!("ghr_mock_refresh_{seq}");
        self.last_refresh_token = Some(refresh.clone());
        Response::json(
            200,
            &json!({
                "access_token": access,
                "expires_in": self.access_ttl,
                "refresh_token": refresh,
                "refresh_token_expires_in": self.refresh_ttl,
                "token_type": "bearer",
                "scope": "",
            }),
        )
    }

    fn next_token_step(&mut self) -> TokenStep {
        step_at(&self.token_script, &mut self.token_cursor).unwrap_or(TokenStep::Approve)
    }

    fn next_refresh_step(&mut self) -> RefreshStep {
        step_at(&self.refresh_script, &mut self.refresh_cursor).unwrap_or(RefreshStep::Rotate)
    }

    // --- REST ---------------------------------------------------------------

    fn user_response(&self) -> Response {
        if self.force_unauthorized {
            return bad_credentials();
        }
        Response::json(
            200,
            &json!({ "login": self.user.login, "id": self.user.id }),
        )
    }

    fn repo_response(&mut self, owner: &str, repo: &str) -> Response {
        if self.force_unauthorized {
            return bad_credentials();
        }
        let entry = self.repo_entry(owner, repo);
        Response::json(
            200,
            &json!({
                "name": repo,
                "full_name": format!("{owner}/{repo}"),
                "owner": { "login": owner },
                "default_branch": entry.default_branch,
            }),
        )
    }

    fn installation_response(&mut self, owner: &str, repo: &str) -> Response {
        if self.force_unauthorized {
            return bad_credentials();
        }
        if self.repo_entry(owner, repo).installed {
            Response::json(
                200,
                &json!({
                    "id": 42,
                    "app_slug": "minimal",
                    "target_type": "User",
                    "account": { "login": owner },
                }),
            )
        } else {
            // GitHub answers 404 when the App is not installed on the repo.
            Response::json(
                404,
                &json!({
                    "message": "Not Found",
                    "documentation_url":
                        "https://docs.github.com/rest/apps/apps#get-a-repository-installation-for-the-authenticated-app",
                }),
            )
        }
    }

    fn list_pulls_response(&mut self, owner: &str, repo: &str, req: &Request) -> Response {
        if self.force_unauthorized {
            return bad_credentials();
        }
        let query = parse_form(req.query.as_bytes());
        let head_filter = form_get(&query, "head").map(|h| branch_of_head(&h));
        let entry = self.repo_entry(owner, repo);
        let matches: Vec<_> = entry
            .pulls
            .iter()
            .filter(|p| head_filter.as_deref().is_none_or(|b| p.head == b))
            .map(|p| pull_json(owner, repo, p))
            .collect();
        Response::json(200, &json!(matches))
    }

    fn create_pull_response(&mut self, owner: &str, repo: &str, req: &Request) -> Response {
        if self.force_unauthorized {
            return bad_credentials();
        }
        let payload: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => {
                return Response::json(
                    422,
                    &json!({ "message": "Invalid request body: expected JSON" }),
                );
            }
        };
        let head = branch_of_head(payload["head"].as_str().unwrap_or_default());
        let base = payload["base"].as_str().unwrap_or("main").to_string();
        let title = payload["title"].as_str().unwrap_or_default().to_string();
        let body = payload["body"].as_str().unwrap_or_default().to_string();
        if head.is_empty() {
            return Response::json(422, &json!({ "message": "head is required" }));
        }

        let number = self.next_pull_number;
        self.next_pull_number += 1;
        let html_url = format!("{}/{owner}/{repo}/pull/{number}", self.public_base);
        let pull = Pull {
            number,
            title,
            head,
            base,
            body,
            html_url,
        };
        let response = Response::json(201, &pull_json(owner, repo, &pull));
        self.repo_entry(owner, repo).pulls.push(pull);
        response
    }

    fn repo_entry(&mut self, owner: &str, repo: &str) -> &mut RepoFixture {
        self.repos
            .entry((owner.to_string(), repo.to_string()))
            .or_default()
    }
}

/// Reads the step at `*cursor`, advances the cursor (clamping to the last
/// element so the final step is sticky), and returns it — or `None` if the
/// script is empty.
fn step_at<T: Copy>(script: &[T], cursor: &mut usize) -> Option<T> {
    if script.is_empty() {
        return None;
    }
    let idx = (*cursor).min(script.len() - 1);
    if *cursor < script.len() - 1 {
        *cursor += 1;
    }
    Some(script[idx])
}

fn pull_json(owner: &str, repo: &str, p: &Pull) -> serde_json::Value {
    json!({
        "number": p.number,
        "title": p.title,
        "body": p.body,
        "state": "open",
        "html_url": p.html_url,
        "head": { "ref": p.head, "label": format!("{owner}:{}", p.head) },
        "base": { "ref": p.base },
        "base_repo": format!("{owner}/{repo}"),
    })
}

/// GitHub's `head` filter/field is `owner:branch` for cross-repo and `branch`
/// for same-repo; the mock keys detection on the branch ref.
fn branch_of_head(head: &str) -> String {
    head.rsplit(':').next().unwrap_or(head).to_string()
}

fn parse_form(bytes: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(bytes)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn form_get(form: &[(String, String)], key: &str) -> Option<String> {
    form.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn oauth_error(status: u16, error: &str, description: &str) -> Response {
    Response::json(
        status,
        &json!({ "error": error, "error_description": description }),
    )
}

fn bad_credentials() -> Response {
    Response::json(
        401,
        &json!({
            "message": "Bad credentials",
            "documentation_url": "https://docs.github.com/rest",
        }),
    )
}

fn not_found(message: &str) -> Response {
    Response::json(404, &json!({ "message": message }))
}
