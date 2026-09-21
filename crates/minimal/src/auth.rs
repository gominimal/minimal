//! `min auth`: the GitHub sign-in on an un-enrolled host.
//!
//! `login` completes one of the two flows under the Minimal-published GitHub
//! App — the browser flow (authorization code with PKCE on a loopback
//! redirect) by default, the device flow under `--device` — and stores the
//! sign-in in the host keychain and nowhere else (BEP-001, BEP-002). `status`
//! reports whether a sign-in is held, as whom and until when, and never a
//! token (BEP-004). `logout` forgets the sign-in and records a `revocation`
//! with the proxy (BEP-044, BEP-067).
//!
//! The mint a box creation performs from the held sign-in lives here too
//! ([`mint_member`]): it seals the member (BEP-005) and records the `mint`
//! with the proxy. Both records go over the proxy's control socket
//! ([`submit_audit`]), one JSON line each way, because the proxy is the
//! audit log's sole writer.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use bep::github::{AuthorizeRequest, Pkce, Secret, Url, random_token};
use bep::{GitHub, MintRequest, Record, SealedValue, SignIn, SignInStore, Submission};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, UnixStream};

use crate::{AuthCommand, GlobalArgs};

/// The proxy's control socket, under the minimal state dir.
pub const CONTROL_SOCKET: &str = "bep/control.sock";

/// Where the proxy's control socket lives: `<minimal_dir>/bep/control.sock`,
/// with `--minimal-dir` honoured.
#[must_use]
pub fn control_socket_path(minimal_dir: Option<&Path>) -> PathBuf {
    let base = match minimal_dir {
        Some(dir) => dir.to_path_buf(),
        None => paths::minimal_state_dir()
            .as_utf8_path()
            .as_std_path()
            .to_path_buf(),
    };
    base.join(CONTROL_SOCKET)
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub async fn cmd_auth(global: &GlobalArgs, command: AuthCommand) -> Result<(), anyhow::Error> {
    let store = host_store()?;
    let mut out = std::io::stdout();
    match command {
        AuthCommand::Login(args) => {
            let github = GitHub::new(
                bep::github::published_app(),
                bep::github::Endpoints::github(),
            )?;
            if args.device {
                login_device(&github, &store, &mut out).await?;
            } else {
                login_browser(&github, &store, &mut out, open_browser).await?;
            }
            Ok(())
        }
        AuthCommand::Logout => {
            logout(
                &store,
                &control_socket_path(global.minimal_dir.as_deref()),
                &mut out,
            )
            .await
        }
        AuthCommand::Status => status(&store, &mut out, unix_now()),
    }
}

/// The host's sign-in store: the macOS Keychain. A Linux host waits on a
/// store that holds the material outside any file, per the spec's keychain
/// rule.
#[cfg(target_os = "macos")]
pub(crate) fn host_store() -> Result<bep::github::KeychainSignIns, anyhow::Error> {
    Ok(bep::github::KeychainSignIns)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn host_store() -> Result<bep::MemorySignIns, anyhow::Error> {
    bail!(
        "min auth holds the GitHub sign-in in the host keychain, and this host has no \
         keychain backend yet (macOS only)"
    )
}

/// The host store the one key that is the client's rather than the proxy's
/// lives in: the handle-signing key a store reference is minted under
/// (BEP-063).
///
/// The proxy's own keys are deliberately not opened here. The host grants
/// them to the proxy's process identity alone (BEP-059), so a client that
/// opened that store would find keys it cannot use — and on a host where it
/// ran first would generate keys the proxy then could not use. What a client
/// needs to seal is public, and it reads it from where the proxy published
/// it.
#[cfg(target_os = "macos")]
pub(crate) fn host_key_store() -> Result<bep::keychain::MacosKeychain, anyhow::Error> {
    Ok(bep::keychain::MacosKeychain)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn host_key_store() -> Result<bep::MemoryStore, anyhow::Error> {
    bail!(
        "the handle a box receives for a stored secret is signed under a key in the host \
         keychain, and this host has no keychain backend yet (macOS only)"
    )
}

/// Whether a GitHub sign-in is held on this host: what a box declaring a
/// GitHub grant is checked against at creation (BEP-003). A host with no
/// keychain backend, or a store that cannot be read, holds none.
#[must_use]
pub fn sign_in_held() -> bool {
    host_store().is_ok_and(|store| matches!(store.load(), Ok(Some(_))))
}

/// Opens `url` in the operator's browser.
fn open_browser(url: &Url) -> Result<(), anyhow::Error> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let status = std::process::Command::new(opener)
        .arg(url.as_str())
        .status()
        .with_context(|| format!("running {opener}"))?;
    if !status.success() {
        bail!("{opener} exited with {status}");
    }
    Ok(())
}

/// Signs in by the device flow: prints the code to enter at GitHub, waits
/// for the grant, and stores the sign-in.
///
/// # Errors
///
/// When GitHub refuses or a step fails, or the store refuses the sign-in.
pub async fn login_device<S: SignInStore>(
    github: &GitHub,
    store: &S,
    out: &mut impl Write,
) -> Result<SignIn, anyhow::Error> {
    let code = github.device_code().await?;
    writeln!(
        out,
        "Open {} and enter the code {}",
        code.verification_uri, code.user_code
    )?;
    let grant = github.wait_for_device_grant(&code).await?;
    complete(github, store, out, grant).await
}

/// Signs in by the browser flow: sends the browser to GitHub through `open`
/// with a PKCE challenge, takes the code back on a loopback redirect,
/// exchanges it, and stores the sign-in.
///
/// # Errors
///
/// When the browser cannot be opened, the redirect carries the wrong state,
/// GitHub refuses, or the store refuses the sign-in.
pub async fn login_browser<S: SignInStore>(
    github: &GitHub,
    store: &S,
    out: &mut impl Write,
    open: impl FnOnce(&Url) -> Result<(), anyhow::Error>,
) -> Result<SignIn, anyhow::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding the loopback redirect")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let pkce = Pkce::generate();
    let state = random_token();
    let url = github.authorize_url(&AuthorizeRequest {
        redirect_uri: &redirect_uri,
        state: &state,
        pkce: &pkce,
    });
    writeln!(
        out,
        "Opening your browser to sign in to GitHub; if it does not appear, open\n  {url}"
    )?;
    open(&url)?;
    tracing::info!("opened the browser for the GitHub sign-in; waiting on the redirect");

    let redirect = await_redirect(&listener).await?;
    if redirect.state != state {
        bail!(bep::GitHubError::StateMismatch);
    }
    let grant = github
        .exchange_code(&redirect.code, &redirect_uri, &pkce)
        .await?;
    complete(github, store, out, grant).await
}

/// What the browser brought back.
struct Redirect {
    code: String,
    state: String,
}

/// Serves the loopback redirect until a `/callback` with a code arrives,
/// answering anything else (a favicon fetch, say) with a 404.
async fn await_redirect(listener: &TcpListener) -> Result<Redirect, anyhow::Error> {
    loop {
        let (mut stream, _) = listener.accept().await.context("accepting the redirect")?;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
            if stream.read(&mut byte).await? == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let request = String::from_utf8_lossy(&head);
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        let url = Url::parse(&format!("http://127.0.0.1{target}"))?;
        if url.path() != "/callback" {
            respond(&mut stream, "404 Not Found", "Not found.").await?;
            continue;
        }
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        if let Some(error) = param("error") {
            respond(
                &mut stream,
                "200 OK",
                "GitHub refused the sign-in; you can close this tab.",
            )
            .await?;
            bail!(bep::GitHubError::Refused {
                error,
                description: param("error_description"),
            });
        }
        let (Some(code), Some(state)) = (param("code"), param("state")) else {
            respond(
                &mut stream,
                "400 Bad Request",
                "The redirect carried no code.",
            )
            .await?;
            continue;
        };
        respond(
            &mut stream,
            "200 OK",
            "Signed in to GitHub; you can close this tab.",
        )
        .await?;
        return Ok(Redirect { code, state });
    }
}

async fn respond(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> Result<(), anyhow::Error> {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// The half both flows share once GitHub has granted: read the account,
/// store the sign-in, report it.
async fn complete<S: SignInStore>(
    github: &GitHub,
    store: &S,
    out: &mut impl Write,
    grant: bep::github::Grant,
) -> Result<SignIn, anyhow::Error> {
    let account = github.account(&grant.access_token).await?;
    let sign_in = grant.into_sign_in(account, unix_now());
    store
        .store(&sign_in)
        .with_context(|| format!("storing the sign-in in the {} store", S::NAME))?;
    tracing::info!(
        account = %sign_in.account,
        expires_at = sign_in.expires_at,
        store = S::NAME,
        "stored the GitHub sign-in"
    );
    writeln!(
        out,
        "Signed in to GitHub as {}; {}",
        sign_in.account,
        expiry_text(sign_in.expires_at, unix_now())
    )?;
    Ok(sign_in)
}

/// Reports whether a sign-in is held, as whom, and until when — never the
/// token.
///
/// # Errors
///
/// When the store cannot be read.
pub fn status<S: SignInStore>(
    store: &S,
    out: &mut impl Write,
    now: u64,
) -> Result<(), anyhow::Error> {
    match store.load().context("reading the held sign-in")? {
        None => writeln!(out, "GitHub: not signed in (run `min auth login`)")?,
        Some(sign_in) => {
            writeln!(
                out,
                "GitHub: signed in as {}; {}",
                sign_in.account,
                expiry_text(sign_in.expires_at, now)
            )?;
            if let Some(refresh_expires_at) = sign_in.refresh_expires_at {
                writeln!(
                    out,
                    "  refresh material {}",
                    expiry_text(Some(refresh_expires_at), now)
                )?;
            }
            if sign_in.expires_at.is_some_and(|at| at <= now) && renewable(&sign_in, now).is_some()
            {
                writeln!(
                    out,
                    "  renews when the next box with a GitHub grant is created"
                )?;
            }
        }
    }
    Ok(())
}

/// Forgets the held sign-in and records the revocation with the proxy.
///
/// # Errors
///
/// When the store refuses to forget the sign-in.
pub async fn logout<S: SignInStore>(
    store: &S,
    control: &Path,
    out: &mut impl Write,
) -> Result<(), anyhow::Error> {
    let held = store.clear().context("forgetting the held sign-in")?;
    tracing::info!(held, store = S::NAME, "forgot the GitHub sign-in");
    // The revocation is what makes every member minted from the sign-in
    // refused (BEP-044); a proxy that is not running redeems nothing
    // meanwhile, so its absence is a warning, not a failed logout.
    match submit_audit(control, &Submission::Audit(bep::revocation_event())).await {
        Ok(record) => tracing::info!(
            previous_hash = %record.previous_hash,
            "the proxy recorded the revocation"
        ),
        Err(error) => eprintln!("warning: the proxy did not record the revocation: {error:#}"),
    }
    if held {
        writeln!(out, "Signed out of GitHub")?;
    } else {
        writeln!(out, "GitHub: no sign-in was held")?;
    }
    Ok(())
}

/// How close to its expiry a held token is renewed rather than used. GitHub
/// revokes a token the moment it renews it, which cuts off every member
/// already minted from it; renewing this early costs those members at most
/// these last minutes, and spares a box created in them a member that dies
/// almost at once.
const RENEW_WITHIN_SECS: u64 = 5 * 60;

/// The refresh token `sign_in` can still be renewed with at `now`, if any.
fn renewable(sign_in: &SignIn, now: u64) -> Option<&Secret> {
    sign_in
        .refresh_token
        .as_ref()
        .filter(|_| sign_in.refresh_expires_at.is_none_or(|at| at > now))
}

/// Renews the held sign-in from GitHub's refresh token when its token has
/// expired or is about to, and holds the renewed one in its place (BEP-002).
/// A sign-in with longer to live, or one whose token never expires, is left
/// as it is, and so is a store holding none.
///
/// # Errors
///
/// When the store cannot be read or written, when the token has expired and
/// the refresh material has too, or when GitHub refuses the renewal; each
/// means signing in again.
pub async fn renew_if_expiring<S: SignInStore>(
    store: &S,
    github: &GitHub,
    now: u64,
) -> Result<(), anyhow::Error> {
    let Some(sign_in) = store.load().context("reading the held sign-in")? else {
        return Ok(());
    };
    let Some(expires_at) = sign_in.expires_at else {
        return Ok(());
    };
    if expires_at > now + RENEW_WITHIN_SECS {
        return Ok(());
    }
    let Some(refresh_token) = renewable(&sign_in, now) else {
        if expires_at <= now {
            bail!(
                "the GitHub sign-in as {} {}, and its refresh material has expired too; run \
                 `min auth login`",
                sign_in.account,
                expiry_text(Some(expires_at), now)
            );
        }
        return Ok(());
    };
    let grant = github.refresh(refresh_token).await.with_context(|| {
        format!(
            "renewing the GitHub sign-in as {}; run `min auth login` if GitHub keeps refusing",
            sign_in.account
        )
    })?;
    let renewed = grant.into_sign_in(sign_in.account, now);
    store
        .store(&renewed)
        .with_context(|| format!("storing the renewed sign-in in the {} store", S::NAME))?;
    tracing::info!(
        account = %renewed.account,
        expires_at = renewed.expires_at,
        store = S::NAME,
        "renewed the GitHub sign-in"
    );
    Ok(())
}

/// Mints a member for a box from the held sign-in, sealed to `keys`, and
/// records the mint with the proxy; the value is what the box receives.
///
/// # Errors
///
/// When no sign-in is held or it has expired, the envelope cannot be sealed,
/// or the proxy does not record the mint.
pub async fn mint_member<S: SignInStore>(
    store: &S,
    identity: &bep::PublicIdentity,
    control: &Path,
    request: &MintRequest<'_>,
) -> Result<SealedValue, anyhow::Error> {
    let sign_in = store
        .load()
        .context("reading the held sign-in")?
        .ok_or_else(|| anyhow::anyhow!("no GitHub sign-in is held; run `min auth login`"))?;
    let minted = bep::mint(identity, &sign_in, request)?;
    submit_audit(control, &Submission::Audit(minted.event))
        .await
        .context("recording the mint with the proxy")?;
    Ok(minted.value)
}

/// The proxy's answer to a submission: the record it appended, or why it
/// refused.
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply {
    Record(Box<Record>),
    Refused { error: String },
}

/// Submits an identity event to the proxy over its control socket: one JSON
/// line out, one back.
///
/// # Errors
///
/// When the socket cannot be reached, the exchange fails, or the proxy
/// refuses the submission.
pub async fn submit_audit(socket: &Path, submission: &Submission) -> Result<Record, anyhow::Error> {
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "connecting to the proxy's control socket {}",
            socket.display()
        )
    })?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json_lenient::to_string(submission)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    let mut reply = String::new();
    BufReader::new(reader).read_line(&mut reply).await?;
    let reply: Reply =
        serde_json_lenient::from_str(reply.trim()).context("reading the proxy's reply")?;
    match reply {
        Reply::Record(record) => Ok(*record),
        Reply::Refused { error } => bail!("the proxy refused the submission: {error}"),
    }
}

/// "expires 2026-09-20T13:19:16Z (in 7h 59m)", "expired 2026-09-20T05:19:16Z",
/// or "does not expire".
fn expiry_text(expires_at: Option<u64>, now: u64) -> String {
    let Some(expires_at) = expires_at else {
        return "does not expire".to_owned();
    };
    let stamp = chrono::DateTime::from_timestamp(i64::try_from(expires_at).unwrap_or(i64::MAX), 0)
        .map_or_else(
            || expires_at.to_string(),
            |t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
    if expires_at <= now {
        return format!("expired {stamp}");
    }
    let left = expires_at - now;
    format!(
        "expires {stamp} (in {}h {}m)",
        left / 3600,
        (left % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bep::github::{Endpoints, MemorySignIns, Secret};
    use bep::{Keys, Kind, Log, MemoryStore, Revocations};
    use tokio::net::{TcpStream, UnixListener};

    use super::*;

    const TOKEN: &str = "ghu_TESTTOKENfa2c1b0d8e7f6a5b4c3d2e1f0a9b8c7d";
    const REFRESH: &str = "ghr_TESTREFRESH0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d";
    const RENEWED: &str = "ghu_TESTRENEWED9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";
    const RENEWED_REFRESH: &str = "ghr_TESTRENEWED0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c";
    const DEVICE_CODE: &str = "device-code-3f2a";
    const AUTH_CODE: &str = "auth-code-9b1c";
    const APP: bep::github::App = bep::github::App {
        client_id: "Iv23liTestApp",
        client_secret: "test-client-secret",
    };

    /// What the fake GitHub has seen.
    #[derive(Default)]
    struct Seen {
        device_polls: u32,
        challenge: Option<String>,
        refreshes: u32,
    }

    /// A GitHub on loopback: the device-code, token and user endpoints, as
    /// far as the two flows exercise them.
    struct FakeGitHub {
        base: Url,
        seen: Arc<Mutex<Seen>>,
    }

    impl FakeGitHub {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let served = seen.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let seen = served.clone();
                    tokio::spawn(serve(stream, seen));
                }
            });
            Self { base, seen }
        }

        fn client(&self) -> GitHub {
            GitHub::new(APP, Endpoints::at(self.base.clone(), self.base.clone())).unwrap()
        }
    }

    /// One request as the fake reads it.
    struct Request {
        method: String,
        target: String,
        authorization: String,
        body: Vec<u8>,
    }

    async fn read_request(stream: &mut TcpStream) -> Request {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_ne!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "request cut short"
            );
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let mut lines = head.lines();
        let mut request_line = lines.next().unwrap().split_whitespace();
        let method = request_line.next().unwrap().to_owned();
        let target = request_line.next().unwrap().to_owned();
        let mut length = 0;
        let mut authorization = String::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse().unwrap(),
                    "authorization" => authorization = value.trim().to_owned(),
                    _ => {}
                }
            }
        }
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        Request {
            method,
            target,
            authorization,
            body,
        }
    }

    async fn reply(stream: &mut TcpStream, status: &str, body: &str) {
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    fn grant() -> String {
        format!(
            r#"{{"access_token":"{TOKEN}","token_type":"bearer","scope":"","expires_in":28800,"refresh_token":"{REFRESH}","refresh_token_expires_in":15811200}}"#
        )
    }

    async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Seen>>) {
        let Request {
            method,
            target,
            authorization,
            body,
        } = read_request(&mut stream).await;
        match (method.as_str(), target.as_str()) {
            ("POST", "/login/device/code") => {
                let request: serde_json_lenient::Value =
                    serde_json_lenient::from_slice(&body).unwrap();
                assert_eq!(request["client_id"], APP.client_id);
                let body = format!(
                    r#"{{"device_code":"{DEVICE_CODE}","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":0}}"#
                );
                reply(&mut stream, "200 OK", &body).await;
            }
            ("POST", "/login/oauth/access_token") => {
                let request: serde_json_lenient::Value =
                    serde_json_lenient::from_slice(&body).unwrap();
                assert_eq!(request["client_id"], APP.client_id);
                if request["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code" {
                    assert_eq!(request["device_code"], DEVICE_CODE);
                    let polls = {
                        let mut seen = seen.lock().unwrap();
                        seen.device_polls += 1;
                        seen.device_polls
                    };
                    // The first poll finds the operator still at the prompt;
                    // the second finds the grant.
                    if polls == 1 {
                        reply(&mut stream, "200 OK", r#"{"error":"authorization_pending","error_description":"The authorization request is still pending."}"#).await;
                    } else {
                        reply(&mut stream, "200 OK", &grant()).await;
                    }
                } else if request["grant_type"] == "refresh_token" {
                    assert_eq!(request["refresh_token"], REFRESH);
                    assert_eq!(request["client_secret"], APP.client_secret);
                    seen.lock().unwrap().refreshes += 1;
                    let body = format!(
                        r#"{{"access_token":"{RENEWED}","token_type":"bearer","scope":"","expires_in":28800,"refresh_token":"{RENEWED_REFRESH}","refresh_token_expires_in":15897600}}"#
                    );
                    reply(&mut stream, "200 OK", &body).await;
                } else {
                    // The browser flow's exchange: the code, the embedded
                    // secret, the redirect it was issued for, and a verifier
                    // hashing to the challenge the authorization carried.
                    assert_eq!(request["code"], AUTH_CODE);
                    assert_eq!(request["client_secret"], APP.client_secret);
                    assert!(
                        request["redirect_uri"]
                            .as_str()
                            .unwrap()
                            .starts_with("http://127.0.0.1:")
                    );
                    let verifier = request["code_verifier"].as_str().unwrap();
                    let expected = seen
                        .lock()
                        .unwrap()
                        .challenge
                        .clone()
                        .expect("an authorization was opened");
                    if Pkce::challenge_of(verifier) == expected {
                        reply(&mut stream, "200 OK", &grant()).await;
                    } else {
                        reply(
                            &mut stream,
                            "200 OK",
                            r#"{"error":"incorrect_client_credentials"}"#,
                        )
                        .await;
                    }
                }
            }
            ("GET", "/user") => {
                if authorization == format!("Bearer {TOKEN}") {
                    reply(&mut stream, "200 OK", r#"{"login":"octocat","id":583231}"#).await;
                } else {
                    reply(
                        &mut stream,
                        "401 Unauthorized",
                        r#"{"message":"Bad credentials"}"#,
                    )
                    .await;
                }
            }
            other => panic!("unexpected request {other:?}"),
        }
    }

    fn held(store: &MemorySignIns) -> SignIn {
        store.load().unwrap().expect("a sign-in is held")
    }

    /// A sign-in as `octocat` whose token expires at `expires_at` and whose
    /// refresh material expires at `refresh_expires_at`.
    fn signed_in(expires_at: u64, refresh_expires_at: u64) -> MemorySignIns {
        let store = MemorySignIns::new();
        store
            .store(&SignIn {
                account: "octocat".into(),
                token: Secret::new(TOKEN),
                expires_at: Some(expires_at),
                refresh_token: Some(Secret::new(REFRESH)),
                refresh_expires_at: Some(refresh_expires_at),
            })
            .unwrap();
        store
    }

    /// BEP-002: a token that has expired, or is about to, renews from the
    /// refresh material. The renewed token and refresh token replace the old
    /// ones in the store, and the account stays the one that signed in.
    #[tokio::test]
    async fn an_expiring_sign_in_is_renewed_from_its_refresh_token() {
        let github = FakeGitHub::start().await;
        let now = unix_now();
        for expires_at in [now - 60, now + 60] {
            let store = signed_in(expires_at, now + 86_400);
            renew_if_expiring(&store, &github.client(), now)
                .await
                .unwrap();

            let renewed = held(&store);
            assert_eq!(renewed.account, "octocat");
            assert_eq!(renewed.token.expose(), RENEWED);
            assert_eq!(renewed.expires_at, Some(now + 28_800));
            assert_eq!(renewed.refresh_token.unwrap().expose(), RENEWED_REFRESH);
        }
        assert_eq!(github.seen.lock().unwrap().refreshes, 2);
    }

    /// GitHub revokes the token it renews, and every member minted from a
    /// token dies with it, so a token with longer to live is never renewed:
    /// the store is untouched and GitHub is not asked.
    #[tokio::test]
    async fn a_sign_in_with_time_to_live_is_not_renewed() {
        let github = FakeGitHub::start().await;
        let now = unix_now();
        let store = signed_in(now + 3_600, now + 86_400);
        renew_if_expiring(&store, &github.client(), now)
            .await
            .unwrap();

        assert_eq!(held(&store).token.expose(), TOKEN);
        assert_eq!(github.seen.lock().unwrap().refreshes, 0);
    }

    /// A token and refresh material that have both expired cannot be renewed:
    /// the error says to sign in again, and GitHub is not asked.
    #[tokio::test]
    async fn an_expired_sign_in_past_its_refresh_material_asks_for_login() {
        let github = FakeGitHub::start().await;
        let now = unix_now();
        let store = signed_in(now - 60, now - 1);
        let error = renew_if_expiring(&store, &github.client(), now)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("min auth login"), "{error}");
        assert_eq!(github.seen.lock().unwrap().refreshes, 0);
    }

    /// BEP-001: `min auth login --device` completes the device flow under
    /// the App — code shown, grant polled for, account read — and reports
    /// the signed-in account.
    #[tokio::test]
    async fn auth_login_completes_device_flow_and_reports_account() {
        let github = FakeGitHub::start().await;
        let store = MemorySignIns::new();
        let mut out = Vec::new();

        let before = unix_now();
        let sign_in = login_device(&github.client(), &store, &mut out)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();

        assert!(out.contains("enter the code ABCD-1234"), "{out}");
        assert!(out.contains("login/device"), "{out}");
        assert!(out.contains("Signed in to GitHub as octocat"), "{out}");
        assert!(!out.contains(TOKEN) && !out.contains(REFRESH), "{out}");
        assert_eq!(github.seen.lock().unwrap().device_polls, 2);
        assert_eq!(sign_in.account, "octocat");
        assert_eq!(sign_in.token.expose(), TOKEN);
        assert!(sign_in.expires_at.unwrap() >= before + 28_800);
        assert_eq!(held(&store), sign_in);
    }

    /// BEP-001 (browser flow): the bare `min auth login` opens the
    /// authorization URL with a PKCE challenge, takes the code back on the
    /// loopback redirect, and exchanges it with the verifier.
    #[tokio::test]
    async fn auth_login_completes_browser_pkce_flow() {
        let github = FakeGitHub::start().await;
        let store = MemorySignIns::new();
        let mut out = Vec::new();
        let seen = github.seen.clone();
        let (status_tx, status_rx) = tokio::sync::oneshot::channel();

        // The "browser": checks the authorization request, remembers its
        // challenge for the token endpoint, and follows the redirect back
        // with a code and the state.
        let expected_authorize = github.base.join("login/oauth/authorize").unwrap();
        let browser = move |url: &Url| {
            let mut opened = url.clone();
            opened.set_query(None);
            assert_eq!(opened, expected_authorize);
            let param = |name: &str| {
                url.query_pairs()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_else(|| panic!("{name} missing from {url}"))
            };
            assert_eq!(param("client_id"), APP.client_id);
            assert_eq!(param("code_challenge_method"), "S256");
            seen.lock().unwrap().challenge = Some(param("code_challenge"));
            let redirect = Url::parse(&param("redirect_uri")).unwrap();
            let state = param("state");
            tokio::spawn(async move {
                let host = format!(
                    "{}:{}",
                    redirect.host_str().unwrap(),
                    redirect.port().unwrap()
                );
                let mut stream = TcpStream::connect(&host).await.unwrap();
                let request = format!(
                    "GET {}?code={AUTH_CODE}&state={state} HTTP/1.1\r\nHost: {host}\r\n\r\n",
                    redirect.path()
                );
                stream.write_all(request.as_bytes()).await.unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).await.unwrap();
                status_tx.send(response).unwrap();
            });
            Ok(())
        };

        let sign_in = login_browser(&github.client(), &store, &mut out, browser)
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        let response = status_rx.await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("Signed in to GitHub"), "{response}");
        assert!(out.contains("Signed in to GitHub as octocat"), "{out}");
        assert!(!out.contains(TOKEN) && !out.contains(REFRESH), "{out}");
        assert_eq!(github.seen.lock().unwrap().device_polls, 0);
        assert_eq!(sign_in.account, "octocat");
        assert_eq!(sign_in.token.expose(), TOKEN);
        assert_eq!(sign_in.refresh_token.as_ref().unwrap().expose(), REFRESH);
        assert_eq!(held(&store), sign_in);
    }

    /// BEP-002: a completed sign-in leaves its token and refresh material in
    /// the store and in no file under the project or the box.
    #[tokio::test]
    async fn auth_login_stores_material_in_keychain_only() {
        let github = FakeGitHub::start().await;
        let store = MemorySignIns::new();
        let tree = tempfile::tempdir().unwrap();
        let project = tree.path().join("project");
        let state = tree.path().join("state");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::create_dir_all(state.join("bep")).unwrap();
        std::fs::write(project.join("minimal.toml"), "[project]\n").unwrap();

        let mut out = Vec::new();
        login_device(&github.client(), &store, &mut out)
            .await
            .unwrap();

        // The store holds both the token and the refresh material.
        let sign_in = held(&store);
        assert_eq!(sign_in.token.expose(), TOKEN);
        assert_eq!(sign_in.refresh_token.as_ref().unwrap().expose(), REFRESH);
        assert!(sign_in.refresh_expires_at.is_some());

        // No file under the project or the state tree carries either — and
        // the sign-in was given no path at all to write one to.
        let mut files = Vec::new();
        let mut pending = vec![tree.path().to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        assert_eq!(files.len(), 1, "{files:?}");
        for file in files {
            let contents = std::fs::read(&file).unwrap();
            let contents = String::from_utf8_lossy(&contents);
            assert!(
                !contents.contains(TOKEN) && !contents.contains(REFRESH),
                "{}",
                file.display()
            );
        }
        assert!(!String::from_utf8(out).unwrap().contains(TOKEN));
    }

    /// BEP-004: `min auth status` reports whether a sign-in is held and its
    /// expiry, and never the token.
    #[test]
    fn auth_status_reports_expiry_without_token() {
        let store = MemorySignIns::new();
        let now = 1_800_000_000;

        let mut out = Vec::new();
        status(&store, &mut out, now).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("not signed in"), "{out}");

        store
            .store(&SignIn {
                account: "octocat".into(),
                token: Secret::new(TOKEN),
                expires_at: Some(now + 28_800),
                refresh_token: Some(Secret::new(REFRESH)),
                refresh_expires_at: Some(now + 15_811_200),
            })
            .unwrap();
        let mut out = Vec::new();
        status(&store, &mut out, now + 60).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("signed in as octocat"), "{out}");
        assert!(
            out.contains("expires 2027-01-15T16:00:00Z (in 7h 59m)"),
            "{out}"
        );
        assert!(out.contains("refresh material expires"), "{out}");
        assert!(!out.contains(TOKEN) && !out.contains(REFRESH), "{out}");
        assert!(!out.contains("ghu_") && !out.contains("ghr_"), "{out}");

        // An expired sign-in is reported as such, still without the token.
        let mut out = Vec::new();
        status(&store, &mut out, now + 30_000).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("expired 2027-01-15T16:00:00Z"), "{out}");
        assert!(!out.contains(TOKEN), "{out}");
    }

    /// A proxy's control socket on loopback: reads one submission per
    /// connection, appends it to the log it alone writes and puts a revocation
    /// it carries in force, as the proxy's own intake does.
    ///
    /// The returned set is what a test reads to see what the proxy would
    /// refuse from then on.
    async fn fake_proxy(socket: &Path, log: &Path) -> Arc<Mutex<Revocations>> {
        let listener = UnixListener::bind(socket).unwrap();
        let mut log = Log::open(log).unwrap();
        let revocations = Arc::new(Mutex::new(Revocations::default()));
        let in_force = Arc::clone(&revocations);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut line = String::new();
                BufReader::new(reader).read_line(&mut line).await.unwrap();
                let submission: Submission = serde_json_lenient::from_str(&line).unwrap();
                let reply = {
                    let mut in_force = in_force.lock().unwrap();
                    match bep::submit(&mut log, &mut in_force, &submission) {
                        Ok(record) => serde_json_lenient::to_string(&record).unwrap(),
                        Err(error) => format!(r#"{{"error":"{error}"}}"#),
                    }
                };
                writer
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        revocations
    }

    /// BEP-067: a mint and a logout each append their record to the proxy's
    /// log over the control socket, chained onto whatever the proxy wrote
    /// before.
    #[tokio::test]
    async fn mint_and_logout_append_audit_records() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let audit = dir.path().join("audit.jsonl");
        let _revocations = fake_proxy(&socket, &audit).await;

        let store = MemorySignIns::new();
        let now = unix_now();
        store
            .store(&SignIn {
                account: "octocat".into(),
                token: Secret::new(TOKEN),
                expires_at: Some(now + 28_800),
                refresh_token: Some(Secret::new(REFRESH)),
                refresh_expires_at: Some(now + 15_811_200),
            })
            .unwrap();
        let keys = Keys::open(MemoryStore::new()).unwrap();

        let value = mint_member(
            &store,
            &keys.public_identity(),
            &socket,
            &MintRequest {
                box_id: "box-a1",
                host: "mac-1",
                host_set_version: 1,
                now,
            },
        )
        .await
        .unwrap();
        let unsealed = bep::unseal(&keys, value.as_str()).unwrap();
        assert_eq!(unsealed.member.expose(), TOKEN);
        assert_eq!(unsealed.context.mode, "user");
        assert_eq!(unsealed.context.breadth, "full");
        assert!(unsealed.context.expires_at <= now + 8 * 3600);

        let mut out = Vec::new();
        logout(&store, &socket, &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Signed out of GitHub")
        );
        assert_eq!(store.load().unwrap(), None);

        let lines: Vec<Record> = std::fs::read_to_string(&audit)
            .unwrap()
            .lines()
            .map(|line| {
                assert!(!line.contains(TOKEN), "{line}");
                serde_json_lenient::from_str(line).unwrap()
            })
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0].kind, Kind::Mint);
        assert_eq!(lines[0].sub, "box-a1");
        assert_eq!(lines[0].credential, "github:user-token");
        assert_eq!(lines[0].previous_hash, bep::Hash::ZERO);
        assert_eq!(lines[1].kind, Kind::Revocation);
        assert_eq!(lines[1].sub, "*");
        assert_eq!(lines[1].previous_hash, lines[0].line_hash());

        // Without a sign-in there is nothing to mint, and the log is untouched.
        let refused = mint_member(
            &store,
            &keys.public_identity(),
            &socket,
            &MintRequest {
                box_id: "box-b2",
                host: "mac-1",
                host_set_version: 1,
                now,
            },
        )
        .await
        .unwrap_err();
        assert!(
            refused.to_string().contains("no GitHub sign-in is held"),
            "{refused:#}"
        );
        assert_eq!(std::fs::read_to_string(&audit).unwrap().lines().count(), 2);
    }

    /// BEP-044: `min auth logout` sends the proxy the one revocation that puts
    /// every GitHub member minted on this host beyond redemption, whichever box
    /// it was minted for — and a proxy that is not there does not turn a logout
    /// into a failure.
    #[tokio::test]
    async fn logout_sends_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let audit = dir.path().join("audit.jsonl");
        let revocations = fake_proxy(&socket, &audit).await;

        let store = MemorySignIns::new();
        let now = unix_now();
        let sign_in = SignIn {
            account: "octocat".into(),
            token: Secret::new(TOKEN),
            expires_at: Some(now + 28_800),
            refresh_token: Some(Secret::new(REFRESH)),
            refresh_expires_at: Some(now + 15_811_200),
        };
        store.store(&sign_in).unwrap();
        let keys = Keys::open(MemoryStore::new()).unwrap();

        // A member minted for a box: what the logout has to cover. Minting
        // revokes nothing of its own.
        mint_member(
            &store,
            &keys.public_identity(),
            &socket,
            &MintRequest {
                box_id: "box-a1",
                host: "mac-1",
                host_set_version: 1,
                now,
            },
        )
        .await
        .unwrap();
        assert!(revocations.lock().unwrap().is_empty());

        let mut out = Vec::new();
        logout(&store, &socket, &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Signed out of GitHub")
        );
        assert_eq!(store.load().unwrap(), None);

        // What the proxy now refuses: every member of the module on this host,
        // which is broader than any one box's values.
        let (module, one_box) = {
            let in_force = revocations.lock().unwrap();
            (
                in_force.covers_module("github"),
                in_force.covers_box("box-a1"),
            )
        };
        assert!(module);
        assert!(!one_box, "a logout revokes the module, not one box");

        // The submission's own record: a revocation naming every box, and no
        // token anywhere in the log.
        let log = std::fs::read_to_string(&audit).unwrap();
        let last: Record = serde_json_lenient::from_str(log.lines().last().unwrap()).unwrap();
        assert_eq!(last.kind, Kind::Revocation);
        assert_eq!(last.sub, "*");
        assert!(!log.contains(TOKEN), "{log}");

        // A logout with no proxy listening still forgets the sign-in and
        // succeeds: an absent proxy redeems nothing meanwhile.
        store.store(&sign_in).unwrap();
        let mut out = Vec::new();
        logout(&store, &dir.path().join("absent.sock"), &mut out)
            .await
            .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Signed out of GitHub")
        );
        assert_eq!(store.load().unwrap(), None);
        // Nothing was appended for the submission that went nowhere.
        let after = std::fs::read_to_string(&audit).unwrap();
        assert_eq!(after.lines().count(), 2, "{after}");
    }
}
