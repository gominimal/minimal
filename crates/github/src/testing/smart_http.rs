//! An auth-enforcing git smart-HTTP endpoint backed by `git http-backend`.
//!
//! This is the part of the mock that later *proves the credential helper
//! actually fires*: it serves local **bare** fixture repositories over the git
//! smart-HTTP protocol, but only after the request presents HTTP Basic
//! credentials. An unauthenticated fetch is answered `401` with a
//! `WWW-Authenticate` challenge (exactly as github.com does), so any code path
//! that reaches these repos without injecting credentials fails loudly.
//!
//! Requests that clear the auth gate are handed to `git http-backend` run as a
//! CGI program: the request path/method/query become CGI environment variables,
//! the request body is piped to the child's stdin, and the child's CGI response
//! (status + headers + body) is translated back into an HTTP [`Response`].

use std::path::{Path, PathBuf};
use std::process::Stdio;

use base64::Engine as _;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::http::{Request, Response};

/// The credential policy the smart-HTTP endpoint enforces.
#[derive(Debug, Clone, Default)]
pub enum GitAuth {
    /// Require *some* non-empty Basic credentials, accepting any username and
    /// password. This still proves a credential helper fired.
    #[default]
    AnyBasic,
    /// Require these exact Basic credentials; anything else is rejected `401`.
    Exact {
        /// Expected Basic-auth username.
        username: String,
        /// Expected Basic-auth password (the injected token, in practice).
        password: String,
    },
}

/// Serves one git smart-HTTP request out of the bare repositories under
/// `project_root`, enforcing `auth`.
pub(super) async fn serve(project_root: &Path, auth: &GitAuth, req: &Request) -> Response {
    match check_auth(auth, req) {
        AuthOutcome::Ok(remote_user) => run_http_backend(project_root, req, &remote_user).await,
        AuthOutcome::Unauthorized => unauthorized(),
    }
}

enum AuthOutcome {
    Ok(String),
    Unauthorized,
}

fn check_auth(auth: &GitAuth, req: &Request) -> AuthOutcome {
    let Some((user, pass)) = req.header("authorization").and_then(parse_basic) else {
        return AuthOutcome::Unauthorized;
    };
    match auth {
        GitAuth::AnyBasic => {
            if user.is_empty() && pass.is_empty() {
                AuthOutcome::Unauthorized
            } else {
                AuthOutcome::Ok(user)
            }
        }
        GitAuth::Exact { username, password } => {
            // Constant-work-ish comparison is not required for a test mock, but
            // fail-closed on any mismatch.
            if &user == username && &pass == password {
                AuthOutcome::Ok(user)
            } else {
                AuthOutcome::Unauthorized
            }
        }
    }
}

/// Decodes a captured `Authorization: Basic …` header value into its
/// `(username, password)` parts, for test-side inspection of what a client sent
/// (see [`super::CapturedRequest::basic_auth`]).
pub(super) fn decode_basic_for_test(header: &str) -> Option<(String, String)> {
    parse_basic(header)
}

/// Decodes a `Basic base64(user:pass)` header value into its parts.
fn parse_basic(header: &str) -> Option<(String, String)> {
    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let decoded = String::from_utf8(raw).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

async fn run_http_backend(project_root: &Path, req: &Request, remote_user: &str) -> Response {
    let mut cmd = Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("GIT_PROJECT_ROOT", project_root)
        .env("PATH_INFO", &req.path)
        .env("REQUEST_METHOD", &req.method)
        .env("QUERY_STRING", &req.query)
        .env("REMOTE_USER", remote_user)
        .env("REMOTE_ADDR", "127.0.0.1")
        // Keep a PATH so `git` can locate its subprograms after `env_clear`.
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    if let Some(ct) = req.header("content-type") {
        cmd.env("CONTENT_TYPE", ct);
    }
    if !req.body.is_empty() {
        cmd.env("CONTENT_LENGTH", req.body.len().to_string());
    }
    // Forward the protocol-version negotiation so smart-HTTP v2 works.
    if let Some(proto) = req.header("git-protocol") {
        cmd.env("GIT_PROTOCOL", proto);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Response::text(500, format!("failed to spawn git http-backend: {e}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        // Errors here (child exited early) surface via the output below.
        let _ = stdin.write_all(&req.body).await;
        let _ = stdin.shutdown().await;
    }

    match child.wait_with_output().await {
        Ok(output) => cgi_to_response(&output.stdout),
        Err(e) => Response::text(500, format!("git http-backend failed: {e}")),
    }
}

/// Translates a CGI response (headers, blank line, body) into an HTTP response.
/// A `Status:` header sets the code; otherwise CGI defaults to `200`.
fn cgi_to_response(raw: &[u8]) -> Response {
    let Some(split) = find_header_end(raw) else {
        // No header/body separator: treat the whole thing as a 500 body.
        return Response::text(500, "malformed CGI response from git http-backend");
    };
    let (head, body) = raw.split_at(split.0);
    let body = &body[split.1..];

    let mut status = 200u16;
    let mut headers = Vec::new();
    for line in String::from_utf8_lossy(head).lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("status") {
            status = value
                .split_whitespace()
                .next()
                .and_then(|c| c.parse().ok())
                .unwrap_or(200);
        } else {
            headers.push((name.to_string(), value.to_string()));
        }
    }

    Response {
        status,
        headers,
        body: body.to_vec(),
    }
}

/// Finds the end of the CGI header block, returning `(offset_of_blank_line,
/// separator_len)` for both `\r\n\r\n` and `\n\n` framings.
fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return Some((pos, 4));
    }
    find_subslice(raw, b"\n\n").map(|pos| (pos, 2))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn unauthorized() -> Response {
    Response::new(401)
        .with_header("WWW-Authenticate", "Basic realm=\"GitHub\"")
        .with_body(
            "text/plain; charset=utf-8",
            b"authentication required".to_vec(),
        )
}

/// Whether `path` is a git smart-HTTP request the endpoint should handle.
pub(super) fn is_git_path(path: &str) -> bool {
    path.contains("/info/refs")
        || path.ends_with("/git-upload-pack")
        || path.ends_with("/git-receive-pack")
        || path.contains("/objects/")
        || path.ends_with("/HEAD")
}

/// Creates a bare fixture repository at `<project_root>/<owner>/<repo>.git` with
/// a single initial commit on `default_branch`, and enables push
/// (`http.receivepack`). Returns the path to the bare repo.
///
/// Runs `git` synchronously; intended for test/e2e setup, not the hot path.
pub(super) fn create_bare_repo(
    project_root: &Path,
    owner: &str,
    repo: &str,
    default_branch: &str,
) -> std::io::Result<PathBuf> {
    use std::process::Command as SyncCommand;

    let bare = project_root.join(owner).join(format!("{repo}.git"));
    std::fs::create_dir_all(bare.parent().expect("bare path has a parent"))?;

    // Build the history in a throwaway working tree, then clone it bare. This is
    // the simplest way to get a bare repo that already advertises a branch.
    let seed = tempfile::tempdir()?;
    let work = seed.path();
    let git = |args: &[&str], cwd: &Path| -> std::io::Result<()> {
        let status = SyncCommand::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "mock")
            .env("GIT_AUTHOR_EMAIL", "mock@example.com")
            .env("GIT_COMMITTER_NAME", "mock")
            .env("GIT_COMMITTER_EMAIL", "mock@example.com")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!("git {args:?} failed")))
        }
    };

    git(&["init", "-q", "-b", default_branch], work)?;
    std::fs::write(work.join("README.md"), b"mock fixture repo\n")?;
    git(&["add", "README.md"], work)?;
    git(&["commit", "-q", "-m", "initial commit"], work)?;
    git(
        &[
            "clone",
            "-q",
            "--bare",
            work.to_str().expect("temp path is utf-8"),
            bare.to_str().expect("bare path is utf-8"),
        ],
        work,
    )?;
    // Allow authenticated pushes to the bare repo over http.
    git(&["config", "http.receivepack", "true"], &bare)?;

    Ok(bare)
}
