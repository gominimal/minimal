//! `min auth`: sign in to GitHub under the Minimal-published GitHub App, and
//! report the held sign-in.
//!
//! The sign-in lives in one host keychain item (`bep::signin`), never in a
//! file. `min auth status` reads the item's metadata and never the token.
//! Renewal is the proxy's work: this client never presents or refreshes the
//! token (BEP-069).

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use bep::signin::{self, Completed, Flow, HostKeychain, Keychain, Material, Standing, Stored};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroize as _;

use crate::{AuthLoginArgs, GlobalArgs};

/// The client id of the Minimal-published GitHub App.
pub(crate) const CLIENT_ID: &str = "Iv23liv6KetAFJp4Eb5K";

/// The App's public client secret, embedded at build time. A build without
/// it ships no browser flow, so its bare `min auth login` takes the device
/// flow (BEP-001).
const BUILT_IN_SECRET: Option<&str> = option_env!("MINIMAL_GITHUB_APP_CLIENT_SECRET");

/// The callback path the App registers, on `http://127.0.0.1`, any port.
const CALLBACK_PATH: &str = "/callback";

/// How long the browser flow waits for the browser to come back.
const BROWSER_TIMEOUT: Duration = Duration::from_secs(300);

/// How long one connection to the callback listener has to send its request
/// line and headers.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// What a new sign-in prints on stderr about the App's installations.
pub(crate) const INSTALL_NOTE: &str = "The token reaches only the repositories of the accounts and organizations where the Minimal GitHub App is installed.";

/// Where the sign-in talks to GitHub. Tests point it at a local server.
#[derive(Debug, Clone)]
pub(crate) struct Endpoints {
    /// `https://github.com`: the device-code, authorize and token endpoints.
    pub oauth: String,
    /// `https://api.github.com`: the signed-in user.
    pub api: String,
}

impl Endpoints {
    fn github() -> Self {
        Endpoints {
            oauth: "https://github.com".into(),
            api: "https://api.github.com".into(),
        }
    }
}

/// Opens a URL in the person's browser.
pub(crate) type Opener = dyn Fn(&str) -> std::io::Result<()> + Sync;

/// One `min auth login`, with everything that reaches outside the process
/// passed in.
pub(crate) struct Login<'a> {
    pub keychain: &'a dyn Keychain,
    pub endpoints: &'a Endpoints,
    /// The App's client secret. With none, the bare verb takes the device
    /// flow.
    pub client_secret: Option<&'a str>,
    /// `--device`.
    pub device: bool,
    pub open_browser: &'a Opener,
}

/// The flow a `min auth login` takes: the browser flow wherever it is
/// shipped, the device flow under `--device` or in a build with no secret.
pub(crate) fn choose_flow(device: bool, client_secret: Option<&str>) -> Flow {
    match (device, client_secret) {
        (false, Some(s)) if !s.is_empty() => Flow::Browser,
        _ => Flow::Device,
    }
}

/// `min auth login [--device]`.
pub async fn cmd_auth_login(_global: &GlobalArgs, args: AuthLoginArgs) -> anyhow::Result<()> {
    let login = Login {
        keychain: &HostKeychain,
        endpoints: &Endpoints::github(),
        client_secret: BUILT_IN_SECRET,
        device: args.device,
        open_browser: &open_in_browser,
    };
    run_login(&login, &mut std::io::stdout(), &mut std::io::stderr()).await?;
    Ok(())
}

/// `min auth status`.
pub fn cmd_auth_status(_global: &GlobalArgs) -> anyhow::Result<()> {
    write_status(&HostKeychain, now(), &mut std::io::stdout())
}

/// Sign in, store the sign-in in the keychain item, and print the account.
pub(crate) async fn run_login(
    login: &Login<'_>,
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
) -> anyhow::Result<Stored> {
    let http = reqwest::Client::builder()
        .user_agent(concat!("min/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .context("building the HTTP client")?;
    let flow = choose_flow(login.device, login.client_secret);
    let token = match flow {
        Flow::Device => device_flow(&http, login.endpoints, err).await?,
        Flow::Browser => {
            let secret = login.client_secret.unwrap_or_default();
            browser_flow(&http, login.endpoints, secret, login.open_browser, err).await?
        }
    };
    let account = signed_in_account(&http, login.endpoints, &token.access_token).await?;
    let issued = now();
    let completed = Completed {
        account,
        flow,
        material: Material {
            // The write stores the metadata's instance, which
            // `store_sign_in` picks.
            instance: String::new(),
            access_token: token.access_token,
            refresh_token: token.refresh_token,
        },
        token_expires_at: issued.saturating_add(token.expires_in),
        refresh_expires_at: issued.saturating_add(token.refresh_expires_in),
    };
    let stored = signin::store_sign_in(login.keychain, &completed)
        .context("GitHub accepted the sign-in, but it was not saved")?;
    tracing::info!(
        account = %stored.metadata.account,
        flow = %flow,
        new_instance = stored.new_instance,
        "GitHub sign-in stored in the host keychain"
    );
    writeln!(out, "Signed in to GitHub as {}.", stored.metadata.account)?;
    if stored.new_instance {
        // The App's installations bound what the token reaches. A first
        // sign-in says so.
        writeln!(err, "{INSTALL_NOTE}")?;
    }
    Ok(stored)
}

/// Print the held sign-in's standing. Reads the item's metadata, never its
/// token (BEP-004).
pub(crate) fn write_status(
    keychain: &dyn Keychain,
    now: u64,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let Some(meta) = keychain.metadata()? else {
        writeln!(
            out,
            "Not signed in to GitHub. Run `min auth login` to sign in."
        )?;
        return Ok(());
    };
    let account = &meta.account;
    match meta.standing(now) {
        Standing::Live => writeln!(
            out,
            "Signed in to GitHub as {account}. The token expires at {}.",
            format_time(meta.token_expires_at)
        )?,
        Standing::RenewsAtProxy => writeln!(
            out,
            "Signed in to GitHub as {account}. The token renews at the proxy on the next request that uses it."
        )?,
        Standing::Lapsed => writeln!(
            out,
            "The GitHub sign-in for {account} expired at {}. Run `min auth login` to sign in again.",
            format_time(meta.refresh_expires_at)
        )?,
    }
    Ok(())
}

fn format_time(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|s| chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0))
        .map_or_else(
            || unix.to_string(),
            |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A token GitHub issued, with its two lifetimes in seconds.
struct Token {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    refresh_expires_in: u64,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token_expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
    interval: Option<u64>,
}

impl TokenReply {
    fn into_token(self) -> anyhow::Result<Token> {
        let (Some(access_token), Some(refresh_token), Some(expires_in), Some(refresh_expires_in)) = (
            self.access_token,
            self.refresh_token,
            self.expires_in,
            self.refresh_token_expires_in,
        ) else {
            bail!(
                "GitHub returned a token that cannot renew, so the sign-in was not saved. The Minimal GitHub App must issue expiring tokens."
            );
        };
        Ok(Token {
            access_token,
            refresh_token,
            expires_in,
            refresh_expires_in,
        })
    }
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct User {
    login: String,
}

/// Send one form POST and read the whole reply. An error here is a network
/// error or a timeout: the request or its reply did not get through.
async fn send_form(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> reqwest::Result<(reqwest::StatusCode, String)> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let reply = http
        .post(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    let status = reply.status();
    Ok((status, reply.text().await?))
}

/// Parse a reply, then zeroize its text: a token endpoint's reply holds the
/// raw token pair.
fn parse_reply<T: serde::de::DeserializeOwned>(mut text: String) -> serde_json_lenient::Result<T> {
    let parsed = serde_json_lenient::from_str(&text);
    text.zeroize();
    parsed
}

async fn post_form<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> anyhow::Result<T> {
    let (status, mut text) = send_form(http, url, form)
        .await
        .with_context(|| format!("could not reach {url}"))?;
    if !status.is_success() {
        text.zeroize();
        bail!("GitHub refused the sign-in request to {url} ({status})");
    }
    parse_reply(text).with_context(|| format!("GitHub answered {url} with an unexpected reply"))
}

/// One poll of the device flow's token endpoint. `None` is a transient
/// failure: a network error, a timeout or a 5xx. The poll loop retries it
/// while the code is live.
async fn poll_device_token(
    http: &reqwest::Client,
    url: &str,
    form: &[(&str, &str)],
) -> anyhow::Result<Option<TokenReply>> {
    let (status, mut text) = match send_form(http, url, form).await {
        Ok(reply) => reply,
        Err(e) => {
            tracing::warn!(error = %e, "a device-flow poll did not reach GitHub; retrying");
            return Ok(None);
        }
    };
    if status.is_server_error() {
        text.zeroize();
        tracing::warn!(%status, "GitHub failed a device-flow poll; retrying");
        return Ok(None);
    }
    // A 4xx that carries an OAuth `error` goes to the caller's handling of
    // that error, as a 200 with one does.
    match parse_reply::<TokenReply>(text) {
        Ok(reply) if status.is_success() || reply.error.is_some() => Ok(Some(reply)),
        Ok(_) | Err(_) if !status.is_success() => {
            bail!("GitHub refused the sign-in request to {url} ({status})")
        }
        Ok(_) | Err(_) => bail!("GitHub answered {url} with an unexpected reply"),
    }
}

/// The OAuth device flow (BEP-001).
async fn device_flow(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    err: &mut (dyn Write + Send),
) -> anyhow::Result<Token> {
    let code: DeviceCode = post_form(
        http,
        &format!("{}/login/device/code", endpoints.oauth),
        &[("client_id", CLIENT_ID)],
    )
    .await?;
    writeln!(
        err,
        "To sign in to GitHub, open {} and enter the code {}.",
        code.verification_uri, code.user_code
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = Duration::from_secs(code.interval.unwrap_or(5));
    let token_url = format!("{}/login/oauth/access_token", endpoints.oauth);
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "The code expired before it was entered. Run `min auth login --device` to start again."
            );
        }
        tokio::time::sleep(interval).await;
        let Some(reply) = poll_device_token(
            http,
            &token_url,
            &[
                ("client_id", CLIENT_ID),
                ("device_code", &code.device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ],
        )
        .await?
        else {
            continue;
        };
        match reply.error.as_deref() {
            None => return reply.into_token(),
            Some("authorization_pending") => {}
            Some("slow_down") => {
                interval = Duration::from_secs(reply.interval.unwrap_or(interval.as_secs() + 5));
            }
            Some("expired_token") => bail!(
                "The code expired before it was entered. Run `min auth login --device` to start again."
            ),
            Some("access_denied") => {
                bail!("The sign-in was cancelled on GitHub. Nothing was saved.")
            }
            Some(other) => bail!(
                "GitHub refused the sign-in ({other}): {}",
                reply.error_description.unwrap_or_default()
            ),
        }
    }
}

/// The authorization-code flow with PKCE, back through a one-shot listener
/// on `127.0.0.1` (BEP-001).
async fn browser_flow(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    client_secret: &str,
    open_browser: &Opener,
    err: &mut (dyn Write + Send),
) -> anyhow::Result<Token> {
    let verifier = format!(
        "{}{}",
        signin::new_instance_id()?,
        signin::new_instance_id()?
    );
    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
    let state = signin::new_instance_id()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("could not open a local port for the browser to return to")?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
    let mut authorize = url::Url::parse(&format!("{}/login/oauth/authorize", endpoints.oauth))
        .context("the GitHub address is not a URL")?;
    authorize
        .query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    writeln!(
        err,
        "Opening GitHub in your browser to sign in. If it does not open, go to:\n  {authorize}"
    )?;
    if let Err(e) = open_browser(authorize.as_str()) {
        tracing::warn!(error = %e, "could not open the browser");
    }
    let code = tokio::time::timeout(BROWSER_TIMEOUT, await_callback(&listener, &state))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "The browser did not return within 5 minutes. Run `min auth login` to start again, or `min auth login --device` to sign in with a code."
            )
        })??;
    let reply: TokenReply = post_form(
        http,
        &format!("{}/login/oauth/access_token", endpoints.oauth),
        &[
            ("client_id", CLIENT_ID),
            ("client_secret", client_secret),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", &verifier),
        ],
    )
    .await?;
    if let Some(e) = reply.error.as_deref() {
        bail!(
            "GitHub refused the sign-in ({e}): {}",
            reply.error_description.as_deref().unwrap_or_default()
        );
    }
    reply.into_token()
}

/// Serve the callback listener until a request to the callback path carries
/// a code with the expected state.
///
/// Each connection is read in its own task under [`REQUEST_READ_TIMEOUT`],
/// so a connection that sends nothing, such as a browser's speculative
/// connection, never holds up the callback.
async fn await_callback(listener: &tokio::net::TcpListener, state: &str) -> anyhow::Result<String> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    loop {
        let (mut conn, target) = tokio::select! {
            accepted = listener.accept() => {
                let (mut conn, _) = accepted?;
                let tx = tx.clone();
                tokio::spawn(async move {
                    let read = tokio::time::timeout(
                        REQUEST_READ_TIMEOUT,
                        read_request_target(&mut conn),
                    );
                    if let Ok(Some(target)) = read.await {
                        let _ = tx.send((conn, target)).await;
                    }
                });
                continue;
            }
            Some(request) = rx.recv() => request,
        };
        let Some(query) = target
            .strip_prefix(CALLBACK_PATH)
            .and_then(|r| r.strip_prefix('?'))
        else {
            respond(&mut conn, "404 Not Found", "Not found.").await;
            continue;
        };
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        if get("state").as_deref() != Some(state) {
            respond(&mut conn, "400 Bad Request", "This sign-in link is stale.").await;
            continue;
        }
        if let Some(code) = get("code") {
            respond(
                &mut conn,
                "200 OK",
                "Return to the terminal to finish signing in.",
            )
            .await;
            return Ok(code);
        }
        respond(&mut conn, "200 OK", "The sign-in did not complete.").await;
        bail!(
            "The sign-in was cancelled on GitHub ({}). Nothing was saved.",
            get("error").unwrap_or_default()
        );
    }
}

async fn read_request_target(conn: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > 16 * 1024 {
            return None;
        }
        let n = conn.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next()?.split_whitespace();
    (parts.next()? == "GET").then_some(())?;
    parts.next().map(str::to_owned)
}

async fn respond(conn: &mut tokio::net::TcpStream, status: &str, text: &str) {
    let body = format!("<!doctype html><title>min</title><p>{text}</p>\n");
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.write_all(reply.as_bytes()).await;
    let _ = conn.shutdown().await;
}

async fn signed_in_account(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    token: &str,
) -> anyhow::Result<String> {
    let url = format!("{}/user", endpoints.api);
    let reply = http
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = reply.status();
    let text = reply.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("GitHub did not name the signed-in account ({status}). Nothing was saved.");
    }
    let user: User = serde_json_lenient::from_str(&text)
        .context("GitHub named the signed-in account in an unexpected reply")?;
    Ok(user.login)
}

fn open_in_browser(url: &str) -> std::io::Result<()> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(drop)
}

/// Unpadded base64url, for the PKCE challenge.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bep::signin::{META_SERVICE, MemoryKeychain, Metadata, SERVICE, valid_account};
    use std::sync::{Arc, Mutex};

    const ACCESS: &str = "ghu_testaccesstoken0123456789";
    const REFRESH: &str = "ghr_testrefreshtoken0123456789";

    /// What the fake GitHub saw: one `<method> <path> <body>` per request.
    type Seen = Arc<Mutex<Vec<String>>>;

    struct FakeGitHub {
        endpoints: Endpoints,
        seen: Seen,
        /// The PKCE challenge the authorize URL carried.
        challenge: Arc<Mutex<Option<String>>>,
    }

    /// How the fake GitHub answers the device flow's polls.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Script {
        /// `authorization_pending` once, then the token.
        Pending,
        /// A connection reset, then a 502, then the token.
        Flaky,
        /// `authorization_pending` once, then a token in an unexpected form.
        OddToken,
    }

    /// A local stand-in for github.com and api.github.com. The device flow
    /// answers `authorization_pending` once, then a token.
    async fn fake_github(account: &'static str) -> FakeGitHub {
        fake_github_scripted(account, Script::Pending).await
    }

    async fn fake_github_scripted(account: &'static str, script: Script) -> FakeGitHub {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let seen: Seen = Arc::default();
        let challenge: Arc<Mutex<Option<String>>> = Arc::default();
        let (seen2, challenge2) = (seen.clone(), challenge.clone());
        tokio::spawn(async move {
            let mut polls = 0;
            loop {
                let (mut conn, _) = listener.accept().await.expect("accept");
                let (method, path, headers, body) = read_request(&mut conn).await;
                seen2
                    .lock()
                    .unwrap()
                    .push(format!("{method} {path} {body}"));
                let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect();
                let field = |k: &str| {
                    form.iter()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                let access = if script == Script::OddToken {
                    "ghu_odd token"
                } else {
                    ACCESS
                };
                let mut status = "200 OK";
                let token = format!(
                    r#"{{"access_token":"{access}","expires_in":28800,"refresh_token":"{REFRESH}","refresh_token_expires_in":15897600,"token_type":"bearer","scope":""}}"#
                );
                let reply = match path.as_str() {
                    "/login/device/code" => {
                        assert_eq!(field("client_id"), CLIENT_ID);
                        r#"{"device_code":"dc-1","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":0}"#.to_owned()
                    }
                    "/login/oauth/access_token" if field("grant_type").ends_with("device_code") => {
                        assert_eq!(field("device_code"), "dc-1");
                        polls += 1;
                        match (script, polls) {
                            (Script::Flaky, 1) => {
                                // Reset the connection: a zero linger
                                // makes the close send an RST.
                                #[allow(deprecated)]
                                conn.set_linger(Some(Duration::ZERO)).expect("linger");
                                drop(conn);
                                continue;
                            }
                            (Script::Flaky, 2) => {
                                status = "502 Bad Gateway";
                                "<html>bad gateway</html>".to_owned()
                            }
                            (Script::Pending | Script::OddToken, 1) => {
                                r#"{"error":"authorization_pending"}"#.to_owned()
                            }
                            _ => token,
                        }
                    }
                    "/login/oauth/access_token" => {
                        assert_eq!(field("client_secret"), "test-secret");
                        assert_eq!(field("code"), "the-code");
                        let want = challenge2.lock().unwrap().clone().expect("authorize first");
                        let got = base64url(&Sha256::digest(field("code_verifier").as_bytes()));
                        if got == want {
                            token
                        } else {
                            r#"{"error":"bad_verification_code"}"#.to_owned()
                        }
                    }
                    "/user" => {
                        assert!(headers.contains(&format!("bearer {}", access.to_lowercase())));
                        format!(r#"{{"login":"{account}","id":1}}"#)
                    }
                    other => panic!("unexpected request to {other}"),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                conn.write_all(head.as_bytes()).await.expect("write");
                conn.write_all(reply.as_bytes()).await.expect("write");
                let _ = conn.shutdown().await;
            }
        });
        FakeGitHub {
            endpoints: Endpoints {
                oauth: base.clone(),
                api: base,
            },
            seen,
            challenge,
        }
    }

    /// Read one request: method, path, lowercased head, body.
    async fn read_request(conn: &mut tokio::net::TcpStream) -> (String, String, String, String) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = conn.read(&mut chunk).await.expect("read");
            assert!(n > 0, "connection closed mid-head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
        let len = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse::<usize>().expect("length"));
        while buf.len() < head_end + len {
            let n = conn.read(&mut chunk).await.expect("read");
            buf.extend_from_slice(&chunk[..n]);
        }
        let first = String::from_utf8_lossy(&buf[..head_end])
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned();
        (method, path, head, body)
    }

    fn no_browser(_: &str) -> std::io::Result<()> {
        panic!("the device flow opened a browser")
    }

    async fn login_with(
        keychain: &MemoryKeychain,
        gh: &FakeGitHub,
        secret: Option<&str>,
        device: bool,
        opener: &Opener,
    ) -> (Stored, String, String) {
        let login = Login {
            keychain,
            endpoints: &gh.endpoints,
            client_secret: secret,
            device,
            open_browser: opener,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let stored = run_login(&login, &mut out, &mut err).await.expect("login");
        (
            stored,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    fn device_requests(gh: &FakeGitHub) -> usize {
        gh.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST /login/device/code"))
            .count()
    }

    // BEP-001
    #[tokio::test]
    async fn auth_login_completes_device_flow_and_reports_account() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let (stored, out, err) =
            login_with(&keychain, &gh, Some("test-secret"), true, &no_browser).await;
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert!(err.contains("https://github.com/login/device"), "{err}");
        assert!(err.contains("WDJB-MJHT"), "{err}");
        assert_eq!(stored.metadata.account, "octocat");
        assert_eq!(stored.metadata.flow, Flow::Device);
        assert_eq!(device_requests(&gh), 1);
        // The pending answer was polled through to the token.
        let polls = gh
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains("device_code=dc-1"))
            .count();
        assert_eq!(polls, 2);
        assert!(!out.contains(ACCESS) && !err.contains(ACCESS));

        // An Enterprise Managed User login carries an underscore.
        assert!(valid_account("octo_emu"));
        assert!(valid_account(&"a_".repeat(32)));
        assert!(!valid_account(&"a".repeat(65)));
        assert!(!valid_account("octo cat") && !valid_account("octo=cat"));
        let emu = fake_github("octo_emu").await;
        let keychain = MemoryKeychain::default();
        let (stored, out, _) = login_with(&keychain, &emu, None, true, &no_browser).await;
        assert_eq!(out, "Signed in to GitHub as octo_emu.\n");
        assert_eq!(stored.metadata.account, "octo_emu");
        let read = keychain.metadata().expect("read").expect("held");
        assert_eq!(read, stored.metadata);
    }

    fn device_polls(gh: &FakeGitHub) -> usize {
        gh.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains("device_code=dc-1"))
            .count()
    }

    // BEP-001: a reset connection and a 5xx during the poll do not end the
    // sign-in while the code is live.
    #[tokio::test]
    async fn auth_login_device_poll_retries_transient_failures() {
        let gh = fake_github_scripted("octocat", Script::Flaky).await;
        let keychain = MemoryKeychain::default();
        let (stored, out, _) = login_with(&keychain, &gh, None, true, &no_browser).await;
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert_eq!(stored.metadata.account, "octocat");
        assert_eq!(device_polls(&gh), 3);
        assert!(keychain.raw().is_some());
    }

    // BEP-002: a token the item cannot store saves nothing, and the held
    // sign-in stays as it was.
    #[tokio::test]
    async fn auth_login_with_an_odd_token_keeps_the_held_item() {
        let keychain = MemoryKeychain::default();
        let gh = fake_github("octocat").await;
        login_with(&keychain, &gh, None, true, &no_browser).await;
        let before = keychain.raw();
        let odd = fake_github_scripted("octocat", Script::OddToken).await;
        let login = Login {
            keychain: &keychain,
            endpoints: &odd.endpoints,
            client_secret: None,
            device: true,
            open_browser: &no_browser,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let e = run_login(&login, &mut out, &mut err)
            .await
            .expect_err("an odd token is refused");
        let text = format!("{e:#}");
        assert!(text.contains("unexpected form"), "{text}");
        assert!(text.contains("nothing was saved"), "{text}");
        assert!(!text.contains("damaged"), "{text}");
        assert!(out.is_empty());
        assert_eq!(keychain.raw(), before);
    }

    // BEP-001, the browser flow
    #[tokio::test]
    async fn auth_login_completes_browser_pkce_flow() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let challenge = gh.challenge.clone();
        let opener = move |authorize: &str| -> std::io::Result<()> {
            let url = url::Url::parse(authorize).expect("authorize url");
            assert!(url.path().ends_with("/login/oauth/authorize"));
            let q: std::collections::HashMap<String, String> =
                url.query_pairs().into_owned().collect();
            assert_eq!(q["client_id"], CLIENT_ID);
            assert_eq!(q["code_challenge_method"], "S256");
            let redirect = url::Url::parse(&q["redirect_uri"]).expect("redirect");
            assert_eq!(redirect.host_str(), Some("127.0.0.1"));
            assert_eq!(redirect.path(), "/callback");
            *challenge.lock().unwrap() = Some(q["code_challenge"].clone());
            let back = format!("{}?code=the-code&state={}", q["redirect_uri"], q["state"]);
            let port = redirect.port().expect("port");
            tokio::spawn(async move {
                // A connection that sends nothing, as a browser's speculative
                // connection does, must not hold up the callback.
                let _silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .expect("silent connection");
                let page = reqwest::get(back).await.expect("callback");
                assert!(page.status().is_success());
            });
            Ok(())
        };
        let (stored, out, _) =
            login_with(&keychain, &gh, Some("test-secret"), false, &opener).await;
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert_eq!(stored.metadata.flow, Flow::Browser);
        assert_eq!(device_requests(&gh), 0);
        assert!(
            gh.seen
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.contains("code_verifier="))
        );
    }

    // BEP-001: no browser flow is shipped without the secret
    #[tokio::test]
    async fn auth_login_without_built_in_secret_takes_device_flow() {
        assert_eq!(choose_flow(false, None), Flow::Device);
        assert_eq!(choose_flow(false, Some("")), Flow::Device);
        assert_eq!(choose_flow(true, Some("s")), Flow::Device);
        assert_eq!(choose_flow(false, Some("s")), Flow::Browser);
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let (stored, out, _) = login_with(&keychain, &gh, None, false, &no_browser).await;
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert_eq!(stored.metadata.flow, Flow::Device);
        assert_eq!(device_requests(&gh), 1);
    }

    // BEP-002
    #[tokio::test]
    async fn auth_login_stores_material_in_keychain_only() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        login_with(&keychain, &gh, None, true, &no_browser).await;
        // The token item holds the secret. The metadata item, which
        // `min auth status` reads, holds no token.
        let secret = keychain.item(SERVICE).expect("token item");
        let meta = keychain.item(META_SERVICE).expect("metadata item");
        assert!(secret.contains(ACCESS) && secret.contains(REFRESH));
        assert!(!meta.contains(ACCESS) && !meta.contains(REFRESH), "{meta}");
        assert_eq!(keychain.raw(), Some((meta.clone(), secret)));
        let read = keychain.metadata().expect("read").expect("held");
        assert_eq!(read.encode(), meta);
        let material = keychain.material().expect("read").expect("held");
        assert_eq!(material.access_token, ACCESS);
        assert_eq!(material.refresh_token, REFRESH);
    }

    // BEP-002: a first sign-in, and a sign-in after a logout
    #[tokio::test]
    async fn a_sign_in_with_no_held_item_is_a_new_instance() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let (first, _, err) = login_with(&keychain, &gh, None, true, &no_browser).await;
        assert!(first.new_instance);
        assert!(err.contains(INSTALL_NOTE), "{err}");
        keychain.clear();
        let (after_logout, _, _) = login_with(&keychain, &gh, None, true, &no_browser).await;
        assert!(after_logout.new_instance);
        assert_ne!(first.metadata.instance, after_logout.metadata.instance);
        // A different account is a new instance too.
        let other = fake_github("hubot").await;
        let (switched, _, _) = login_with(&keychain, &other, None, true, &no_browser).await;
        assert!(switched.new_instance);
        assert_ne!(switched.metadata.instance, after_logout.metadata.instance);
        // The token item names its own instance: the new one, never the
        // instance of the item it replaced.
        let material = keychain.material().expect("read").expect("held");
        assert_eq!(material.instance, switched.metadata.instance);
        let secret = keychain.item(SERVICE).expect("token item");
        assert!(secret.contains(&switched.metadata.instance), "token item");
        assert!(!secret.contains(&after_logout.metadata.instance));
        let meta = keychain.metadata().expect("read").expect("held");
        assert_eq!(material.instance, meta.instance);
    }

    // BEP-002: the same account replaces the material in place
    #[tokio::test]
    async fn re_login_to_the_same_account_keeps_the_instance() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let held = Metadata {
            account: "octocat".into(),
            instance: "0123456789abcdef0123456789abcdef".into(),
            flow: Flow::Device,
            token_expires_at: 1,
            refresh_expires_at: 2,
        };
        let old = Material {
            instance: String::new(),
            access_token: "ghu_old".into(),
            refresh_token: "ghr_old".into(),
        };
        keychain.write(&held, &old).expect("seed");
        let (stored, _, err) = login_with(&keychain, &gh, None, true, &no_browser).await;
        assert!(!stored.new_instance);
        assert!(!err.contains(INSTALL_NOTE), "{err}");
        assert_eq!(stored.metadata.instance, held.instance);
        let material = keychain.material().expect("read").expect("held");
        assert_eq!(material.access_token, ACCESS);
        assert_eq!(material.refresh_token, REFRESH);
        assert!(stored.metadata.token_expires_at > 1);
    }

    /// A keychain that refuses every read and records whether a write came.
    #[derive(Default)]
    struct RefusingKeychain {
        wrote: std::sync::atomic::AtomicBool,
    }

    impl Keychain for RefusingKeychain {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            Err(signin::SignInError::Keychain {
                action: "read the sign-in",
                detail: "locked".into(),
            })
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.metadata().map(|_| None)
        }
        fn write(&self, _: &Metadata, _: &Material) -> Result<(), signin::SignInError> {
            self.wrote.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    // BEP-002: a refused read is not "no item held", so it mints no instance
    #[tokio::test]
    async fn re_login_with_a_refused_keychain_read_writes_nothing() {
        let gh = fake_github("octocat").await;
        let keychain = RefusingKeychain::default();
        let login = Login {
            keychain: &keychain,
            endpoints: &gh.endpoints,
            client_secret: None,
            device: true,
            open_browser: &no_browser,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let e = run_login(&login, &mut out, &mut err)
            .await
            .expect_err("refused read");
        assert!(format!("{e:#}").contains("locked"), "{e:#}");
        assert!(!keychain.wrote.load(std::sync::atomic::Ordering::SeqCst));
    }

    fn held(token_expires_at: u64, refresh_expires_at: u64) -> MemoryKeychain {
        let keychain = MemoryKeychain::default();
        let meta = Metadata {
            account: "octocat".into(),
            instance: "0123456789abcdef0123456789abcdef".into(),
            flow: Flow::Device,
            token_expires_at,
            refresh_expires_at,
        };
        let material = Material {
            instance: String::new(),
            access_token: ACCESS.into(),
            refresh_token: REFRESH.into(),
        };
        keychain.write(&meta, &material).expect("seed");
        keychain
    }

    fn status(keychain: &MemoryKeychain, now: u64) -> String {
        let mut out = Vec::new();
        write_status(keychain, now, &mut out).expect("status");
        String::from_utf8(out).expect("utf8")
    }

    // BEP-004
    #[test]
    fn auth_status_reports_expiry_without_token() {
        // 2026-10-19 12:00:00 UTC, token 8 h later.
        let now = 1_792_411_200;
        let keychain = held(now + 8 * 3600, now + 180 * 86_400);
        let out = status(&keychain, now);
        assert_eq!(
            out,
            "Signed in to GitHub as octocat. The token expires at 2026-10-19 20:00 UTC.\n"
        );
        assert!(!out.contains(ACCESS) && !out.contains(REFRESH));
        assert_eq!(
            status(&MemoryKeychain::default(), now),
            "Not signed in to GitHub. Run `min auth login` to sign in.\n"
        );
        let lapsed = status(&keychain, now + 200 * 86_400);
        assert!(
            lapsed.contains("Run `min auth login` to sign in again."),
            "{lapsed}"
        );
        assert!(!lapsed.contains(ACCESS) && !lapsed.contains(REFRESH));
    }

    // BEP-004: an expired token with live refresh material
    #[test]
    fn auth_status_reports_renewal_of_expired_sign_in() {
        let now = 1_792_411_200;
        let keychain = held(now - 60, now + 86_400);
        let out = status(&keychain, now);
        assert_eq!(
            out,
            "Signed in to GitHub as octocat. The token renews at the proxy on the next request that uses it.\n"
        );
        assert!(!out.contains(ACCESS) && !out.contains(REFRESH));
    }

    #[test]
    fn base64url_matches_rfc_7636_example() {
        // RFC 7636 appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            base64url(&Sha256::digest(verifier.as_bytes())),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
