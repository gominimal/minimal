//! Self-tests for the mock GitHub server.
//!
//! These drive the mock the way the production clients will: OAuth/REST over a
//! tiny raw HTTP/1.1 client (so the tests carry no client-crate dependency), and
//! the git smart-HTTP surface with a real `git` process — which is the only
//! honest way to prove the auth gate actually blocks an unauthenticated fetch.

use std::net::SocketAddr;
use std::process::Stdio;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

use super::{Fixtures, GitAuth, MockGithub, RefreshStep, TokenStep};

// --- a minimal raw HTTP/1.1 client -----------------------------------------

/// A parsed HTTP response from the mock.
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is valid JSON")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Sends one request and reads the full response (the mock always closes the
/// connection, so read-to-EOF yields the whole message).
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    content_type: Option<&str>,
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).await.expect("connect to mock");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    stream.write_all(body).await.expect("write request body");
    stream.flush().await.expect("flush request");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .expect("read response to EOF");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header/body separator");
    let head = std::str::from_utf8(&raw[..split]).expect("response head is UTF-8");
    let body = raw[split + 4..].to_vec();

    let mut lines = head.lines();
    let status_line = lines.next().expect("status line present");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("numeric status code");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    HttpResponse {
        status,
        headers,
        body,
    }
}

async fn get(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> HttpResponse {
    request(addr, "GET", path, headers, None, &[]).await
}

async fn post_form(addr: SocketAddr, path: &str, form: &str) -> HttpResponse {
    request(
        addr,
        "POST",
        path,
        &[],
        Some("application/x-www-form-urlencoded"),
        form.as_bytes(),
    )
    .await
}

async fn post_json(addr: SocketAddr, path: &str, body: &Value) -> HttpResponse {
    request(
        addr,
        "POST",
        path,
        &[],
        Some("application/json"),
        serde_json::to_vec(body)
            .expect("serialize JSON body")
            .as_slice(),
    )
    .await
}

/// Polls the device-code token endpoint once.
async fn poll_device_token(addr: SocketAddr, device_code: &str) -> HttpResponse {
    let form = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}",
    );
    post_form(addr, "/login/oauth/access_token", &form).await
}

/// Exchanges a refresh token once.
async fn refresh(addr: SocketAddr, refresh_token: &str) -> HttpResponse {
    let form = format!("grant_type=refresh_token&refresh_token={refresh_token}");
    post_form(addr, "/login/oauth/access_token", &form).await
}

// --- device flow ------------------------------------------------------------

#[tokio::test]
async fn scripted_device_flow_pending_then_slowdown_then_approve() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx: &mut Fixtures| {
        fx.set_device_codes("dev-abc", "WXYZ-1234", "https://github.test/login/device");
        fx.set_device_interval(5);
        fx.script_device_exchange([TokenStep::Pending, TokenStep::SlowDown, TokenStep::Approve]);
    });
    let addr = mock.addr();

    // Step 1: request a device code.
    let start = post_form(addr, "/login/device/code", "client_id=Iv1.mock").await;
    assert_eq!(start.status, 200);
    let start = start.json();
    assert_eq!(start["device_code"], "dev-abc");
    assert_eq!(start["user_code"], "WXYZ-1234");
    assert_eq!(
        start["verification_uri"],
        "https://github.test/login/device"
    );
    assert_eq!(start["interval"], 5);

    // Step 2: first poll is pending.
    let pending = poll_device_token(addr, "dev-abc").await;
    assert_eq!(pending.status, 200);
    assert_eq!(pending.json()["error"], "authorization_pending");

    // Step 3: second poll asks us to slow down (bumped interval).
    let slow = poll_device_token(addr, "dev-abc").await.json();
    assert_eq!(slow["error"], "slow_down");
    assert_eq!(slow["interval"], 10);

    // Step 4: third poll is approved with an access + refresh token pair.
    let ok = poll_device_token(addr, "dev-abc").await.json();
    assert!(ok["access_token"].as_str().unwrap().starts_with("ghu_"));
    assert!(ok["refresh_token"].as_str().unwrap().starts_with("ghr_"));
    assert_eq!(ok["token_type"], "bearer");

    // Sticky-on-last: a further poll stays approved.
    let again = poll_device_token(addr, "dev-abc").await.json();
    assert!(again["access_token"].as_str().unwrap().starts_with("ghu_"));
}

#[tokio::test]
async fn scripted_device_flow_expired_and_denied() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.script_device_exchange([TokenStep::Expired]));
    let expired = poll_device_token(mock.addr(), "mock_device_code")
        .await
        .json();
    assert_eq!(expired["error"], "expired_token");

    mock.configure(|fx| fx.script_device_exchange([TokenStep::AccessDenied]));
    let denied = poll_device_token(mock.addr(), "mock_device_code")
        .await
        .json();
    assert_eq!(denied["error"], "access_denied");
}

// --- refresh with rotation --------------------------------------------------

#[tokio::test]
async fn refresh_rotates_the_refresh_token_every_call() {
    let mock = MockGithub::start().await.expect("start mock");
    let addr = mock.addr();

    let first = refresh(addr, "ghr_seed").await.json();
    let second = refresh(
        addr,
        first["refresh_token"].as_str().expect("refresh token"),
    )
    .await
    .json();

    // Rotation: both the access token and the refresh token change each call.
    assert_ne!(first["access_token"], second["access_token"]);
    assert_ne!(first["refresh_token"], second["refresh_token"]);
    assert!(first["refresh_token_expires_in"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn scripted_refresh_invalid_grant_triggers_reauth() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.script_refresh([RefreshStep::InvalidGrant]));
    let resp = refresh(mock.addr(), "ghr_anything").await.json();
    assert_eq!(resp["error"], "invalid_grant");
}

#[tokio::test]
async fn strict_refresh_rejects_a_stale_rotated_token() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.set_strict_refresh(true));
    let addr = mock.addr();

    // Approve via the device flow to seed the first (tracked) refresh token.
    let granted = poll_device_token(addr, "mock_device_code").await.json();
    let r1 = granted["refresh_token"].as_str().expect("r1").to_string();

    // Rotating with r1 succeeds and yields r2; r1 is now stale.
    let rotated = refresh(addr, &r1).await.json();
    let r2 = rotated["refresh_token"].as_str().expect("r2").to_string();
    assert_ne!(r1, r2);

    // Presenting the stale r1 again is rejected — the grant is bricked.
    let stale = refresh(addr, &r1).await.json();
    assert_eq!(stale["error"], "invalid_grant");

    // The freshest token still works.
    let ok = refresh(addr, &r2).await.json();
    assert!(ok["access_token"].as_str().unwrap().starts_with("ghu_"));
}

// --- REST -------------------------------------------------------------------

#[tokio::test]
async fn get_user_reports_the_configured_login() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.set_user("norrie", 4242));
    let resp = get(mock.addr(), "/user", &[]).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("Content-Type"),
        Some("application/json; charset=utf-8")
    );
    let user = resp.json();
    assert_eq!(user["login"], "norrie");
    assert_eq!(user["id"], 4242);
}

#[tokio::test]
async fn forced_unauthorized_answers_401_bad_credentials() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.set_force_unauthorized(true));
    let resp = get(mock.addr(), "/user", &[]).await;
    assert_eq!(resp.status, 401);
    assert_eq!(resp.json()["message"], "Bad credentials");
}

#[tokio::test]
async fn installation_lookup_reports_installed_and_not_installed() {
    let mock = MockGithub::start().await.expect("start mock");
    let addr = mock.addr();

    // Default is installed (200).
    let installed = get(addr, "/repos/octocat/hello/installation", &[]).await;
    assert_eq!(installed.status, 200);
    assert_eq!(installed.json()["app_slug"], "minimal");

    // Flip to not-installed → 404 (spec R1.5), so the client can guide to install.
    mock.configure(|fx| fx.set_installed("octocat", "hello", false));
    let missing = get(addr, "/repos/octocat/hello/installation", &[]).await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.json()["message"], "Not Found");
}

#[tokio::test]
async fn repo_reports_its_default_branch() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| fx.set_default_branch("octocat", "hello", "trunk"));
    let resp = get(mock.addr(), "/repos/octocat/hello", &[]).await;
    assert_eq!(resp.status, 200);
    let repo = resp.json();
    assert_eq!(repo["default_branch"], "trunk");
    assert_eq!(repo["full_name"], "octocat/hello");
}

#[tokio::test]
async fn pull_create_then_list_by_head_detects_the_existing_pr() {
    let mock = MockGithub::start().await.expect("start mock");
    let addr = mock.addr();

    // No PRs yet for this head.
    let empty = get(addr, "/repos/octocat/hello/pulls?head=octocat:feat/x", &[]).await;
    assert_eq!(empty.status, 200);
    assert_eq!(empty.json().as_array().unwrap().len(), 0);

    // Create a PR from feat/x → main.
    let created = post_json(
        addr,
        "/repos/octocat/hello/pulls",
        &serde_json::json!({
            "title": "Add x",
            "head": "feat/x",
            "base": "main",
            "body": "the body",
        }),
    )
    .await;
    assert_eq!(created.status, 201);
    let created = created.json();
    let number = created["number"].as_u64().expect("pr number");
    assert!(created["html_url"].as_str().unwrap().contains("/pull/"));

    // List-by-head now finds exactly that PR (existing-PR detection, R4.5).
    let found = get(addr, "/repos/octocat/hello/pulls?head=octocat:feat/x", &[]).await;
    let arr = found.json();
    let arr = arr.as_array().expect("array of pulls");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["number"], number);
    assert_eq!(arr[0]["head"]["ref"], "feat/x");

    // A different head sees none.
    let other = get(
        addr,
        "/repos/octocat/hello/pulls?head=octocat:feat/other",
        &[],
    )
    .await;
    assert_eq!(other.json().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn seeded_pull_is_detectable_by_head() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.configure(|fx| {
        fx.add_pull("octocat", "hello", "feat/seed", "main");
    });
    let found = get(
        mock.addr(),
        "/repos/octocat/hello/pulls?head=octocat:feat/seed",
        &[],
    )
    .await;
    assert_eq!(found.json().as_array().unwrap().len(), 1);
}

// --- request capture --------------------------------------------------------

#[tokio::test]
async fn requests_are_captured_and_the_token_is_redacted() {
    let mock = MockGithub::start().await.expect("start mock");
    let addr = mock.addr();

    get(
        addr,
        "/user",
        &[
            ("Authorization", "Bearer ghu_supersecret"),
            ("Accept", "application/vnd.github+json"),
        ],
    )
    .await;

    let captured = mock.captured();
    assert_eq!(captured.len(), 1);
    let req = &captured[0];
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/user");
    assert!(req.had_authorization());
    assert_eq!(req.bearer_token(), Some("ghu_supersecret"));
    // The non-secret header is retrievable...
    assert_eq!(req.header("Accept"), Some("application/vnd.github+json"));
    // ...but Authorization is not exposed through the header list...
    assert_eq!(req.header("Authorization"), None);
    // ...and never appears in Debug output.
    let debug = format!("{req:?}");
    assert!(
        !debug.contains("ghu_supersecret"),
        "token leaked in Debug: {debug}"
    );
    assert!(debug.contains("[REDACTED]"));

    // The capture log clears on demand.
    mock.clear_captured();
    assert!(mock.captured().is_empty());
}

#[tokio::test]
async fn captured_body_and_query_are_recorded() {
    let mock = MockGithub::start().await.expect("start mock");
    post_form(
        mock.addr(),
        "/login/oauth/access_token",
        "grant_type=refresh_token&refresh_token=r",
    )
    .await;
    let captured = mock.captured();
    let last = captured.last().expect("a captured request");
    assert_eq!(last.method, "POST");
    assert!(last.body_string().contains("grant_type=refresh_token"));
}

// --- git smart-HTTP (the credential-helper proof) ---------------------------

/// Runs `git` with terminal prompts disabled (so a missing credential fails
/// instead of hanging) and returns `(success, combined_output)`.
async fn run_git(args: &[&str]) -> (bool, String) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", "/nonexistent-mock-home")
        .stdin(Stdio::null())
        .output()
        .await
        .expect("spawn git");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), combined)
}

fn repo_url(mock: &MockGithub, userinfo: Option<&str>, owner: &str, repo: &str) -> String {
    let host = mock.addr();
    match userinfo {
        Some(creds) => format!("http://{creds}@{host}/{owner}/{repo}.git"),
        None => format!("http://{host}/{owner}/{repo}.git"),
    }
}

#[tokio::test]
async fn smart_http_rejects_unauthenticated_and_accepts_basic_auth() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.create_bare_repo("octocat", "hello", "main")
        .expect("create bare fixture repo");

    // Unauthenticated fetch is rejected at the gate.
    let (ok, out) = run_git(&["ls-remote", &repo_url(&mock, None, "octocat", "hello")]).await;
    assert!(!ok, "unauthenticated ls-remote should fail; got:\n{out}");

    // With Basic credentials (any username/password under the default policy) the
    // ref advertisement succeeds and the seeded branch is visible.
    let (ok, out) = run_git(&[
        "ls-remote",
        &repo_url(&mock, Some("x-access-token:ghu_token"), "octocat", "hello"),
    ])
    .await;
    assert!(ok, "authenticated ls-remote should succeed; got:\n{out}");
    assert!(
        out.contains("refs/heads/main"),
        "missing default branch ref:\n{out}"
    );
}

#[tokio::test]
async fn smart_http_exact_auth_policy_checks_credentials() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.create_bare_repo("octocat", "hello", "main")
        .expect("create bare fixture repo");
    mock.set_git_auth(GitAuth::Exact {
        username: "x-access-token".to_string(),
        password: "correct-horse".to_string(),
    });

    let (bad, _) = run_git(&[
        "ls-remote",
        &repo_url(&mock, Some("x-access-token:wrong"), "octocat", "hello"),
    ])
    .await;
    assert!(!bad, "wrong password must be rejected");

    let (good, out) = run_git(&[
        "ls-remote",
        &repo_url(
            &mock,
            Some("x-access-token:correct-horse"),
            "octocat",
            "hello",
        ),
    ])
    .await;
    assert!(good, "correct credentials must be accepted; got:\n{out}");
}

#[tokio::test]
async fn smart_http_clone_transfers_the_repository() {
    let mock = MockGithub::start().await.expect("start mock");
    mock.create_bare_repo("octocat", "hello", "main")
        .expect("create bare fixture repo");
    let dest = tempfile::tempdir().expect("clone dest");
    let dest_path = dest.path().join("hello");

    let (ok, out) = run_git(&[
        "clone",
        "-q",
        &repo_url(&mock, Some("x-access-token:ghu_token"), "octocat", "hello"),
        dest_path.to_str().expect("utf-8 dest"),
    ])
    .await;
    assert!(ok, "authenticated clone should succeed; got:\n{out}");
    assert!(
        dest_path.join("README.md").is_file(),
        "clone did not fetch the tree"
    );
}
