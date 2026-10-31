//! `min auth`: sign in to GitHub under the Minimal-published GitHub App,
//! report the held sign-in, and sign out.
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

/// How long the browser flow holds the browser's response while it
/// exchanges the code and reads the account and the App's installations.
const FINISH_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the browser flow re-reads the App's installations while it
/// waits for an installation.
const INSTALL_POLL: Duration = Duration::from_secs(5);

/// Where a person installs the App and chooses its repositories.
pub(crate) const INSTALL_URL: &str = "https://github.com/apps/gominimal/installations/new";

/// Where a person changes an installation's repositories.
const SETTINGS_URL: &str = "https://github.com/settings/installations";

// The sentences the terminal and the browser page share. The page renders a
// backticked span as a command chip.

/// The next step of every failure.
pub(crate) const TRY_AGAIN: &str = "Run `min auth login` to try again.";
const NOTHING_SAVED: &str = "Nothing was saved.";
const CANCELLED: &str = "The sign-in was cancelled on GitHub.";
pub(crate) const NOT_FINISHED: &str = "GitHub approved the sign-in, but `min` could not finish it.";
const NOT_APPROVED: &str = "GitHub did not approve the sign-in.";
const TERMINAL_SAYS: &str = "Your terminal says why.";
const STALE: &str = "It belongs to an earlier `min auth login`. Run `min auth login` again.";
/// Completed by the install URL in the terminal, and by a link on the page.
pub(crate) const NEXT_STEP: &str = "One more step: choose which repositories your boxes can reach";
pub(crate) const NO_REACH: &str = "Your boxes can't reach private repositories until you do.";
const UNREAD: &str = "`min` could not read where the Minimal GitHub App is installed.";
const CLOSE_TAB: &str = "You can close this tab.";
const WAITING: &str =
    "Waiting for the installation to finish in your browser. Press Ctrl-C to stop waiting.";
const STOPPED_WAITING: &str =
    "Stopped waiting. `min` did not see an installation of the Minimal GitHub App.";

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

/// `min auth logout`.
pub async fn cmd_auth_logout(_global: &GlobalArgs) -> anyhow::Result<()> {
    let logout = Logout {
        keychain: &HostKeychain,
        endpoints: &Endpoints::github(),
        client_secret: BUILT_IN_SECRET,
    };
    run_logout(&logout, &mut std::io::stdout(), &mut std::io::stderr()).await?;
    Ok(())
}

/// What `min auth logout` prints on stdout once the item is deleted.
pub(crate) const SIGNED_OUT: &str =
    "Signed out of GitHub. Boxes created before now lose GitHub access at their next request.";

/// What `min auth logout` prints on stderr when GitHub did not confirm the
/// revocation. The local deletion is the enforcement (BEP-044).
pub(crate) const NOT_CONFIRMED: &str = "GitHub did not confirm the sign-out. \
The sign-in is removed from this machine. \
To be sure GitHub revoked it, revoke the app at https://github.com/settings/apps/authorizations.";

/// Why the logout failed when the token is still in the host keychain.
pub(crate) const NOT_REMOVED: &str =
    "The GitHub sign-in was not removed, so you are still signed in";

/// Why the logout failed when the host keychain could not be read after a
/// failed delete.
pub(crate) const NOT_KNOWN: &str = "The GitHub sign-in may still be in the host keychain, \
because the keychain could not be read after the delete. \
Run `min auth status` to check";

/// Why the logout failed when the token is gone but the rest of the item
/// is still held.
pub(crate) const PARTLY_REMOVED: &str = "Part of the GitHub sign-in is still in the host keychain. \
Run `min auth logout` again to remove it";

/// The sign-in item, as `min auth logout` deletes it.
pub(crate) trait SignInItem: Keychain + Sync {
    /// Delete both parts of the item. Deleting an item that is not held is
    /// not an error.
    fn delete(&self) -> anyhow::Result<()>;
}

impl SignInItem for signin::MemoryKeychain {
    fn delete(&self) -> anyhow::Result<()> {
        self.clear();
        Ok(())
    }
}

impl SignInItem for HostKeychain {
    fn delete(&self) -> anyhow::Result<()> {
        // BEP-069: the delete holds the item lock, so a renewal at the proxy
        // cannot check the item before the delete and write it back after.
        // A lock that is not taken does not stop the delete: the delete is
        // the enforcement (BEP-044).
        let _lock = signin::lock_item()
            .inspect_err(|error| {
                tracing::warn!(%error, "the sign-in was deleted without the item lock");
            })
            .ok();
        host_delete()?;
        confirm_deleted(self)
    }
}

/// Read the item back after a delete: a keychain command can exit 0 and
/// delete nothing. A read that fails is an error, not "deleted", because the
/// local deletion is the enforcement (BEP-044).
fn confirm_deleted(item: &dyn Keychain) -> anyhow::Result<()> {
    let meta = item.metadata()?;
    let material = item.material()?;
    if meta.is_some() || material.is_some() {
        bail!("the host keychain still holds the GitHub sign-in after the delete");
    }
    Ok(())
}

/// Delete the metadata item under [`signin::META_SERVICE`], then the item
/// under [`signin::SERVICE`], which holds the token. The token goes last: a
/// delete that stops part way keeps the token, so "still signed in" stays
/// true.
#[cfg(target_os = "macos")]
fn host_delete() -> anyhow::Result<()> {
    // `security` exits 44 when no item matches.
    const NOT_FOUND: i32 = 44;
    let out = keychain_tool(
        "/usr/bin/security",
        &[
            "delete-generic-password",
            "-s",
            signin::SERVICE,
            "-a",
            signin::ITEM_ACCOUNT,
        ],
    )?;
    if !out.status.success() && out.status.code() != Some(NOT_FOUND) {
        bail!(
            "the host keychain refused to delete the GitHub sign-in: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn host_delete() -> anyhow::Result<()> {
    for service in [signin::META_SERVICE, signin::SERVICE] {
        let out = keychain_tool("secret-tool", &["clear", "service", service])?;
        // `secret-tool` fails with no message when nothing matches.
        if !out.status.success() && !out.stderr.is_empty() {
            bail!(
                "the host keychain refused to delete the GitHub sign-in: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(())
}

fn keychain_tool(tool: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    std::process::Command::new(tool)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("could not run the host keychain tool `{tool}`"))
}

/// One `min auth logout`, with everything that reaches outside the process
/// passed in.
pub(crate) struct Logout<'a> {
    pub keychain: &'a dyn SignInItem,
    pub endpoints: &'a Endpoints,
    /// The App's client secret. GitHub revokes a sign-in only under it.
    pub client_secret: Option<&'a str>,
}

/// What a logout did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoggedOut {
    /// No sign-in was held, and nothing changed.
    NotSignedIn,
    /// The item is deleted. `confirmed` is whether GitHub confirmed the
    /// revocation.
    Deleted { confirmed: bool },
}

/// Delete the sign-in item, then ask GitHub to revoke the sign-in, best
/// effort (BEP-044). A refused or unreachable revocation is reported, and
/// the logout still succeeds. Deleting the item refuses every reference to
/// it at its next request: the proxy reads the item for each request, and a
/// later sign-in is a new instance that no earlier reference names.
pub(crate) async fn run_logout(
    logout: &Logout<'_>,
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
) -> anyhow::Result<LoggedOut> {
    // A read that fails does not stop the delete: the delete is the
    // enforcement, and a damaged item is deleted like any other.
    let meta = logout.keychain.metadata();
    let material = logout.keychain.material();
    if matches!(meta, Ok(None)) && matches!(material, Ok(None)) {
        writeln!(out, "Not signed in to GitHub.")?;
        return Ok(LoggedOut::NotSignedIn);
    }
    let account = meta
        .ok()
        .flatten()
        .map_or_else(|| "unknown".to_owned(), |m| m.account);
    let token = material
        .ok()
        .flatten()
        .map(|m| zeroize::Zeroizing::new(m.access_token.clone()));
    // The token is read above, before any delete, so a delete that stops
    // after the token item is gone can still ask GitHub to revoke it.
    let mut partly = None;
    if let Err(e) = logout.keychain.delete() {
        match logout.keychain.material() {
            Ok(Some(_)) => return Err(e.context(NOT_REMOVED)),
            Err(read) => {
                return Err(e.context(format!("{read}")).context(NOT_KNOWN));
            }
            // The token is gone, so every reference is refused. The rest of
            // the item is reported after the revocation.
            Ok(None) => partly = Some(e),
        }
    }
    let revoked = match (token, logout.client_secret.filter(|s| !s.is_empty())) {
        (Some(token), Some(secret)) => revoke(logout.endpoints, secret, &token).await,
        (None, _) => Err("no token was read from the sign-in".to_owned()),
        (_, None) => Err("this build carries no client secret to revoke under".to_owned()),
    };
    let confirmed = revoked.is_ok();
    tracing::info!(
        account = %account,
        github_confirmed = confirmed,
        partly_deleted = partly.is_some(),
        detail = revoked.err().as_deref().unwrap_or(""),
        "GitHub sign-in deleted from the host keychain"
    );
    writeln!(out, "{SIGNED_OUT}")?;
    if !confirmed {
        writeln!(err, "{NOT_CONFIRMED}")?;
    }
    if let Some(e) = partly {
        return Err(e.context(PARTLY_REMOVED));
    }
    Ok(LoggedOut::Deleted { confirmed })
}

/// Ask GitHub to revoke this host's token, which also voids its refresh
/// token. The App's grant for the account stays, so the account's other
/// hosts stay signed in. `Err` says why GitHub did not confirm, for the
/// log. It never holds the token.
async fn revoke(endpoints: &Endpoints, secret: &str, token: &str) -> Result<(), String> {
    let url = format!("{}/applications/{CLIENT_ID}/token", endpoints.api);
    let http = reqwest::Client::builder()
        .user_agent(concat!("min/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("building the HTTP client: {e}"))?;
    let mut body = serde_json_lenient::json!({ "access_token": token }).to_string();
    let sent = http
        .delete(&url)
        .basic_auth(CLIENT_ID, Some(secret))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send()
        .await;
    body.zeroize();
    match sent {
        Ok(reply) if reply.status() == reqwest::StatusCode::NO_CONTENT => Ok(()),
        Ok(reply) => Err(format!("GitHub answered {url} with {}", reply.status())),
        Err(e) => Err(format!("could not reach {url}: {e}")),
    }
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
    match flow {
        Flow::Device => {
            let token = device_flow(&http, login.endpoints, err).await?;
            let signed = read_sign_in(&http, login.endpoints, token).await?;
            let (stored, _) = save(login, flow, signed.token, &signed.account)?;
            report(out, err, &stored.metadata.account, &signed.installs)?;
            Ok(stored)
        }
        Flow::Browser => {
            let mut browser = Browser::open(login.endpoints, login.open_browser, err).await?;
            let (stored, installs, access) = browser.sign_in(&http, login).await?;
            report(out, err, &stored.metadata.account, &installs)?;
            // Only an empty list shows that no installation exists. After a
            // failed read the App may already be installed.
            if installs.none() {
                // The install wait gets its own BROWSER_TIMEOUT, so a slow
                // sign-in does not shorten the time to install the App.
                browser.deadline = tokio::time::Instant::now() + BROWSER_TIMEOUT;
                writeln!(err, "{WAITING}")?;
                browser
                    .await_install(
                        &http,
                        login.endpoints,
                        &access,
                        &stored.metadata.account,
                        err,
                    )
                    .await?;
            }
            Ok(stored)
        }
    }
}

/// A token, the account it signs in, and the App's installations it
/// reaches.
struct Signed {
    token: Token,
    account: String,
    installs: Installs,
}

/// Read the account a new token signs in, and the App's installations it
/// reaches. A failed read of the installations does not fail the sign-in.
async fn read_sign_in(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    token: Token,
) -> anyhow::Result<Signed> {
    let account = signed_in_account(http, endpoints, &token.access_token).await?;
    let installs = match list_installations(http, endpoints, &token.access_token).await {
        Ok(list) => Installs::Listed(list),
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not read the App's installations");
            Installs::Unread
        }
    };
    Ok(Signed {
        token,
        account,
        installs,
    })
}

/// Store a sign-in in the keychain item. Returns the stored item and a copy
/// of the access token, for the browser flow's later reads of the App's
/// installations.
fn save(
    login: &Login<'_>,
    flow: Flow,
    token: Token,
    account: &str,
) -> anyhow::Result<(Stored, zeroize::Zeroizing<String>)> {
    let access = zeroize::Zeroizing::new(token.access_token.clone());
    let issued = now();
    let completed = Completed {
        account: account.to_owned(),
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
    Ok((stored, access))
}

/// Print the account, then where the App's installations let boxes reach,
/// or the install URL as the one next step. The browser page says the same.
fn report(
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
    account: &str,
    installs: &Installs,
) -> anyhow::Result<()> {
    writeln!(out, "Signed in to GitHub as {account}.")?;
    match installs {
        Installs::Listed(list) if !list.is_empty() => {
            let accounts: Vec<String> = list.iter().map(|i| i.account.login.clone()).collect();
            writeln!(err, "{}", reach_sentence(&join(&accounts)))?;
        }
        Installs::Listed(_) => {
            writeln!(err, "{NEXT_STEP} at {INSTALL_URL}.")?;
            writeln!(err, "{NO_REACH}")?;
        }
        Installs::Unread => {
            writeln!(err, "{UNREAD}")?;
            writeln!(err, "{NEXT_STEP} at {INSTALL_URL}.")?;
        }
    }
    Ok(())
}

/// The sentence that names where boxes reach repositories. `accounts` is
/// already joined, as plain text or as HTML.
fn reach_sentence(accounts: &str) -> String {
    format!("Your boxes can reach repositories on {accounts} through the Minimal GitHub App.")
}

/// The sentence that says what one installation reaches. `selection` is
/// what [`selection`] returns.
fn reach_there(selection: &str) -> String {
    format!("Your boxes can reach {selection} there.")
}

/// "a", "a and b", "a, b and c".
fn join(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
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

/// One installation of the App that the signed-in user can reach.
#[derive(Deserialize, Clone)]
struct Installation {
    id: u64,
    account: InstallAccount,
    /// `all` or `selected`.
    repository_selection: String,
}

#[derive(Deserialize, Clone)]
struct InstallAccount {
    /// A user's or an organization's login, or an enterprise's slug.
    #[serde(alias = "slug")]
    login: String,
}

#[derive(Deserialize)]
struct InstallationList {
    installations: Vec<Installation>,
}

#[derive(Deserialize)]
struct RepositoryCount {
    total_count: u64,
}

/// The App's installations a sign-in reaches, as far as `min` could read
/// them.
enum Installs {
    Listed(Vec<Installation>),
    /// The read failed.
    Unread,
}

impl Installs {
    /// Whether `min` read the installations and there were none.
    fn none(&self) -> bool {
        matches!(self, Installs::Listed(list) if list.is_empty())
    }
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

/// The authorization-code flow with PKCE, back through a listener on
/// `127.0.0.1` (BEP-001). The listener answers each request with a page
/// that states the real outcome.
struct Browser {
    callback: Callback,
    state: String,
    verifier: String,
    redirect_uri: String,
    /// When the browser flow gives up: [`BROWSER_TIMEOUT`] after the
    /// browser was opened, and again after the install wait starts.
    deadline: tokio::time::Instant,
}

impl Browser {
    /// Open the listener, print the authorize URL, and open it in the
    /// browser.
    async fn open(
        endpoints: &Endpoints,
        open_browser: &Opener,
        err: &mut (dyn Write + Send),
    ) -> anyhow::Result<Self> {
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
        let callback = Callback::new(listener);
        let deadline = tokio::time::Instant::now() + BROWSER_TIMEOUT;
        if let Err(e) = open_browser(authorize.as_str()) {
            tracing::warn!(error = %e, "could not open the browser");
        }
        Ok(Browser {
            callback,
            state,
            verifier,
            redirect_uri,
            deadline,
        })
    }

    /// Serve the callback until a request carries a code with the expected
    /// state. Hold that request's response until the code is exchanged, the
    /// account and the App's installations are read and the sign-in is
    /// stored, then answer it with the page for the outcome.
    async fn sign_in(
        &mut self,
        http: &reqwest::Client,
        login: &Login<'_>,
    ) -> anyhow::Result<(Stored, Installs, zeroize::Zeroizing<String>)> {
        loop {
            let (mut conn, query) = tokio::time::timeout_at(self.deadline, self.callback.next())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "The browser did not return within 5 minutes. Run `min auth login` to start again, or `min auth login --device` to sign in with a code."
                    )
                })??;
            if query.get("state") != Some(self.state.as_str()) {
                respond(&mut conn, &Page::stale()).await;
                continue;
            }
            if let Some(code) = query.get("code") {
                return match self.finish(http, login, code).await {
                    Ok((stored, installs, access)) => {
                        let page = Page::signed_in(&stored.metadata.account, &installs);
                        respond(&mut conn, &page).await;
                        Ok((stored, installs, access))
                    }
                    Err(e) => {
                        respond(&mut conn, &Page::not_finished()).await;
                        Err(anyhow::anyhow!("{NOT_FINISHED}\n{e:#}\n{TRY_AGAIN}"))
                    }
                };
            }
            match query.get("error") {
                Some("access_denied") => {
                    respond(&mut conn, &Page::cancelled()).await;
                    bail!("{CANCELLED} {NOTHING_SAVED} {TRY_AGAIN}");
                }
                other => {
                    respond(&mut conn, &Page::not_approved()).await;
                    bail!(
                        "{NOT_APPROVED} GitHub sent back `{}`.\n{TRY_AGAIN}",
                        other.unwrap_or("no code")
                    );
                }
            }
        }
    }

    /// Exchange the code, read the account and the App's installations
    /// under [`FINISH_TIMEOUT`], then store the sign-in.
    async fn finish(
        &self,
        http: &reqwest::Client,
        login: &Login<'_>,
        code: &str,
    ) -> anyhow::Result<(Stored, Installs, zeroize::Zeroizing<String>)> {
        let secret = login.client_secret.unwrap_or_default();
        let read = async {
            let reply: TokenReply = post_form(
                http,
                &format!("{}/login/oauth/access_token", login.endpoints.oauth),
                &[
                    ("client_id", CLIENT_ID),
                    ("client_secret", secret),
                    ("code", code),
                    ("redirect_uri", &self.redirect_uri),
                    ("code_verifier", &self.verifier),
                ],
            )
            .await?;
            if let Some(e) = reply.error.as_deref() {
                bail!(
                    "GitHub refused the sign-in ({e}): {}",
                    reply.error_description.as_deref().unwrap_or_default()
                );
            }
            read_sign_in(http, login.endpoints, reply.into_token()?).await
        };
        let signed = tokio::time::timeout(FINISH_TIMEOUT, read)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "GitHub did not answer within {} seconds.",
                    FINISH_TIMEOUT.as_secs()
                )
            })??;
        let (stored, access) = save(login, Flow::Browser, signed.token, &signed.account)?;
        Ok((stored, signed.installs, access))
    }

    /// Wait, until the browser flow's deadline, for the App to be
    /// installed. A request to the callback re-reads the App's installations
    /// with the held token, and so does a timer, because GitHub may send the
    /// browser back from the install to a port nothing listens on.
    ///
    /// No code that reaches the callback here is exchanged: the sign-in is
    /// already held, and an install's code is issued without the PKCE
    /// challenge. The callback need not carry the state, because GitHub may
    /// not pass it through the install. A request that carries another
    /// state gets the expired-link page. At the deadline, or when the
    /// listener fails, the terminal says the wait stopped and gives the
    /// install URL again.
    async fn await_install(
        &mut self,
        http: &reqwest::Client,
        endpoints: &Endpoints,
        token: &str,
        account: &str,
        err: &mut (dyn Write + Send),
    ) -> anyhow::Result<()> {
        let mut poll =
            tokio::time::interval_at(tokio::time::Instant::now() + INSTALL_POLL, INSTALL_POLL);
        loop {
            let (mut conn, query) = tokio::select! {
                () = tokio::time::sleep_until(self.deadline) => {
                    writeln!(err, "{STOPPED_WAITING}")?;
                    writeln!(err, "{NEXT_STEP} at {INSTALL_URL}.")?;
                    return Ok(());
                }
                _ = poll.tick() => {
                    // Bound the re-read by the deadline too: a slow read must
                    // not hold the wait past it. A read cut short loops back
                    // to the deadline arm.
                    let read = tokio::time::timeout_at(
                        self.deadline,
                        installed(http, endpoints, token, None),
                    );
                    if let Ok(Some((on, selection))) = read.await {
                        writeln!(err, "Installed on {on}. {}", reach_there(&selection))?;
                        return Ok(());
                    }
                    continue;
                }
                request = self.callback.next() => match request {
                    Ok(request) => request,
                    // The sign-in is already saved. A listener that cannot
                    // accept ends the wait, not the command.
                    Err(error) => {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "the callback listener failed while waiting for the install"
                        );
                        writeln!(err, "{STOPPED_WAITING}")?;
                        writeln!(err, "{NEXT_STEP} at {INSTALL_URL}.")?;
                        return Ok(());
                    }
                },
            };
            if query.get("state").is_some_and(|s| s != self.state) {
                respond(&mut conn, &Page::stale()).await;
                continue;
            }
            let id = query.get("installation_id").and_then(|v| v.parse().ok());
            // The same bound as the poll arm: a slow read answers the held
            // page and loops back to the deadline arm.
            let read =
                tokio::time::timeout_at(self.deadline, installed(http, endpoints, token, id));
            if let Ok(Some((on, selection))) = read.await {
                respond(&mut conn, &Page::installed(&on, &selection)).await;
                writeln!(err, "Installed on {on}. {}", reach_there(&selection))?;
                return Ok(());
            }
            let page = Page::signed_in(account, &Installs::Listed(Vec::new()));
            respond(&mut conn, &page).await;
        }
    }
}

/// Re-read the App's installations. With one or more, name the account of
/// the installation `id`, or of the first one, and what it reaches.
async fn installed(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    token: &str,
    id: Option<u64>,
) -> Option<(String, String)> {
    let read = tokio::time::timeout(FINISH_TIMEOUT, list_installations(http, endpoints, token));
    let list = match read.await {
        Ok(Ok(list)) => list,
        Ok(Err(error)) => {
            tracing::warn!(error = %format!("{error:#}"), "could not read the App's installations");
            return None;
        }
        Err(_) => return None,
    };
    let chosen = id
        .and_then(|id| list.iter().find(|i| i.id == id))
        .or_else(|| list.first())?;
    let selection = selection(http, endpoints, token, chosen).await;
    Some((chosen.account.login.clone(), selection))
}

/// What one installation lets boxes reach: "all repositories", or how many
/// were selected.
async fn selection(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    token: &str,
    installation: &Installation,
) -> String {
    if installation.repository_selection == "all" {
        return "all repositories".to_owned();
    }
    let url = format!(
        "{}/user/installations/{}/repositories?per_page=1",
        endpoints.api, installation.id
    );
    let count = tokio::time::timeout(
        FINISH_TIMEOUT,
        get_json::<RepositoryCount>(http, &url, token),
    )
    .await;
    match count {
        Ok(Ok(RepositoryCount { total_count: 1 })) => "1 selected repository".to_owned(),
        Ok(Ok(RepositoryCount { total_count })) => format!("{total_count} selected repositories"),
        _ => "the selected repositories".to_owned(),
    }
}

/// The App's installations the token reaches.
async fn list_installations(
    http: &reqwest::Client,
    endpoints: &Endpoints,
    token: &str,
) -> anyhow::Result<Vec<Installation>> {
    let url = format!("{}/user/installations?per_page=100", endpoints.api);
    let list: InstallationList = get_json(http, &url, token).await?;
    Ok(list.installations)
}

async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    token: &str,
) -> anyhow::Result<T> {
    let reply = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    let status = reply.status();
    let text = reply.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("GitHub answered {url} with {status}");
    }
    serde_json_lenient::from_str(&text)
        .with_context(|| format!("GitHub answered {url} with an unexpected reply"))
}

/// One parsed request to the callback path.
struct Query(Vec<(String, String)>);

impl Query {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// A request the callback listener has read: the connection, and the
/// request target.
type Request = (tokio::net::TcpStream, String);

/// The callback listener.
///
/// Each connection is read in its own task under [`REQUEST_READ_TIMEOUT`],
/// so a connection that sends nothing, such as a browser's speculative
/// connection, never holds up the callback.
struct Callback {
    listener: tokio::net::TcpListener,
    tx: tokio::sync::mpsc::Sender<Request>,
    rx: tokio::sync::mpsc::Receiver<Request>,
}

impl Callback {
    fn new(listener: tokio::net::TcpListener) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        Callback { listener, tx, rx }
    }

    /// The next request to the callback path. A request to any other path
    /// gets the not-found page.
    async fn next(&mut self) -> anyhow::Result<(tokio::net::TcpStream, Query)> {
        loop {
            let (mut conn, target) = tokio::select! {
                accepted = self.listener.accept() => {
                    let (mut conn, _) = accepted?;
                    let host = format!("127.0.0.1:{}", self.listener.local_addr()?.port());
                    let tx = self.tx.clone();
                    tokio::spawn(async move {
                        let read = tokio::time::timeout(
                            REQUEST_READ_TIMEOUT,
                            read_request_target(&mut conn, &host),
                        );
                        if let Ok(Some(target)) = read.await {
                            let _ = tx.send((conn, target)).await;
                        }
                    });
                    continue;
                }
                Some(request) = self.rx.recv() => request,
            };
            let Some(query) = target
                .strip_prefix(CALLBACK_PATH)
                .and_then(|r| r.strip_prefix('?'))
            else {
                respond(&mut conn, &Page::not_found()).await;
                continue;
            };
            let pairs = url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();
            return Ok((conn, Query(pairs)));
        }
    }
}

/// The target of a `GET` whose `Host` header is `host`, the callback's own
/// `127.0.0.1:<port>`. A request with another `Host`, such as a page that
/// reaches the listener through DNS rebinding, gets no reply.
async fn read_request_target(conn: &mut tokio::net::TcpStream, host: &str) -> Option<String> {
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
    let mut lines = head.lines();
    let mut parts = lines.next()?.split_whitespace();
    (parts.next()? == "GET").then_some(())?;
    let target = parts.next()?.to_owned();
    lines
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| name.eq_ignore_ascii_case("host") && value.trim() == host)
        .then_some(target)
}

async fn respond(conn: &mut tokio::net::TcpStream, page: &Page) {
    let _ = conn.write_all(page.response().as_bytes()).await;
    let _ = conn.shutdown().await;
}

/// The status glyph a page shows.
#[derive(Clone, Copy)]
enum Glyph {
    Done,
    Stopped,
    Failed,
}

/// One page the callback listener answers with. `heading` and `body` are
/// HTML: every value from GitHub in them is escaped.
struct Page {
    status: &'static str,
    title: &'static str,
    glyph: Glyph,
    heading: String,
    body: String,
}

impl Page {
    fn signed_in(account: &str, installs: &Installs) -> Page {
        let heading = format!(
            "Signed in to GitHub as <strong>{}</strong>",
            escape(account)
        );
        let body = match installs {
            Installs::Listed(list) if !list.is_empty() => {
                let accounts: Vec<String> = list
                    .iter()
                    .map(|i| format!("<strong>{}</strong>", escape(&i.account.login)))
                    .collect();
                format!(
                    "<p>{} {}</p>\n<p class=\"muted\"><a href=\"{SETTINGS_URL}\">Change which repositories</a></p>",
                    reach_sentence(&join(&accounts)),
                    prose(CLOSE_TAB)
                )
            }
            Installs::Listed(_) => format!(
                "<p>{}.</p>\n{}\n<p class=\"muted\">{}</p>",
                prose(NEXT_STEP),
                choose_button(),
                prose(NO_REACH)
            ),
            Installs::Unread => format!(
                "<p>{}</p>\n<p>{}.</p>\n{}",
                prose(UNREAD),
                prose(NEXT_STEP),
                choose_button()
            ),
        };
        Page {
            status: "200 OK",
            title: "Signed in",
            glyph: Glyph::Done,
            heading,
            body,
        }
    }

    fn installed(account: &str, selection: &str) -> Page {
        Page {
            status: "200 OK",
            title: "Installed",
            glyph: Glyph::Done,
            heading: format!("Installed on <strong>{}</strong>", escape(account)),
            body: format!(
                "<p>{} {}</p>",
                escape(&reach_there(selection)),
                prose(CLOSE_TAB)
            ),
        }
    }

    fn not_finished() -> Page {
        Page {
            status: "502 Bad Gateway",
            title: "Sign-in not finished",
            glyph: Glyph::Failed,
            heading: "Sign-in not finished".to_owned(),
            body: format!(
                "<p>{} {} {}</p>",
                prose(NOT_FINISHED),
                prose(TERMINAL_SAYS),
                prose(TRY_AGAIN)
            ),
        }
    }

    fn not_approved() -> Page {
        Page {
            body: format!(
                "<p>{} {} {}</p>",
                prose(NOT_APPROVED),
                prose(TERMINAL_SAYS),
                prose(TRY_AGAIN)
            ),
            ..Page::not_finished()
        }
    }

    fn cancelled() -> Page {
        Page {
            status: "200 OK",
            title: "Sign-in cancelled",
            glyph: Glyph::Stopped,
            heading: "Sign-in cancelled".to_owned(),
            body: format!("<p>{} {}</p>", prose(NOTHING_SAVED), prose(TRY_AGAIN)),
        }
    }

    fn stale() -> Page {
        Page {
            status: "400 Bad Request",
            title: "Sign-in link expired",
            glyph: Glyph::Failed,
            heading: "This sign-in link has expired".to_owned(),
            body: format!("<p>{}</p>", prose(STALE)),
        }
    }

    fn not_found() -> Page {
        Page {
            status: "404 Not Found",
            title: "Not found",
            glyph: Glyph::Failed,
            heading: "Not found".to_owned(),
            body: String::new(),
        }
    }

    /// The whole HTTP response: one self-contained document, with no script
    /// and no external request.
    fn response(&self) -> String {
        let (class, symbol) = match self.glyph {
            Glyph::Done => ("done", "&#10003;"),
            Glyph::Stopped => ("stopped", "!"),
            Glyph::Failed => ("failed", "&#215;"),
        };
        let document = format!(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n<title>{title} · Minimal</title>\n\
<style>{PAGE_STYLE}</style>\n</head>\n<body>\n<main class=\"card\">\n{MARK}\n\
<div class=\"glyph {class}\" aria-hidden=\"true\">{symbol}</div>\n<h1>{heading}</h1>\n{body}\n\
</main>\n</body>\n</html>\n",
            title = self.title,
            heading = self.heading,
            body = self.body,
        );
        format!(
            "HTTP/1.1 {}\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Security-Policy: {PAGE_CSP}\r\n\
Referrer-Policy: no-referrer\r\n\
Cache-Control: no-store\r\n\
X-Content-Type-Options: nosniff\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n{document}",
            self.status,
            document.len()
        )
    }
}

/// The page's Content-Security-Policy: no script, no external request.
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

fn choose_button() -> String {
    format!("<p><a class=\"button\" href=\"{INSTALL_URL}\">Choose repositories</a></p>")
}

/// Escape text for HTML, then render each backticked span as a command
/// chip.
fn prose(text: &str) -> String {
    escape(text)
        .split('`')
        .enumerate()
        .map(|(i, part)| {
            if i % 2 == 1 {
                format!("<code>{part}</code>")
            } else {
                part.to_owned()
            }
        })
        .collect()
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The `minimal` mark (`docs/public/minimal-mark-{light,dark}.svg`), filled
/// with the page's text colour so one copy serves light and dark.
const MARK: &str = r#"<svg class="mark" width="48" height="24" viewBox="0 0 48 24" fill="currentColor" role="img" aria-label="Minimal" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M10.2734 0.000213623H18.1767L29.2412 16V23.9999H21.338L10.2734 8.00011V0.000213623Z"/><path fill-rule="evenodd" clip-rule="evenodd" d="M3.16132 23.9999L0 19.4285V11.4286H7.90326L11.0645 16V23.9999H3.16132Z"/><path fill-rule="evenodd" clip-rule="evenodd" d="M28.4531 0.000213623H36.3564L47.4208 16V23.9999H39.5176L28.4531 8.00011V0.000213623Z"/></svg>"#;

const PAGE_STYLE: &str = ":root{color-scheme:light dark;--bg:#f5f5f4;--card:#fff;--fg:#141414;--muted:#5c5c5c;--line:#e5e5e5;--chip:#f0f0ef;--done:#1a7f37;--stopped:#9a6700;--failed:#cf222e;--button:#141414;--button-fg:#fff}\
@media (prefers-color-scheme:dark){:root{--bg:#0d0d0d;--card:#171717;--fg:#e5e5e5;--muted:#a3a3a3;--line:#2a2a2a;--chip:#232323;--done:#2ea043;--stopped:#bb8009;--failed:#da3633;--button:#e5e5e5;--button-fg:#141414}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--fg);font:16px/1.5 -apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif}\
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:32px 24px;text-align:center}\
.mark{display:block;margin:0 auto 24px;color:var(--fg)}\
.glyph{width:40px;height:40px;margin:0 auto 12px;border-radius:50%;display:grid;place-items:center;font-size:20px;font-weight:700;color:#fff}\
.done{background:var(--done)}.stopped{background:var(--stopped)}.failed{background:var(--failed)}\
h1{margin:0 0 12px;font-size:20px;font-weight:600;overflow-wrap:anywhere}\
p{margin:0 0 12px;overflow-wrap:anywhere}\
.muted{color:var(--muted);font-size:14px}\
a{color:inherit}\
code{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:1px 6px;white-space:nowrap;-webkit-user-select:all;user-select:all}\
.button{display:inline-block;margin:4px 0;padding:10px 18px;border-radius:8px;background:var(--button);color:var(--button-fg);font-weight:600;text-decoration:none}";

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
    use base64::Engine as _;
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
        /// The reply to `GET /user/installations`. It starts with one
        /// installation, on the signed-in account, with all repositories.
        installs: Arc<Mutex<String>>,
    }

    /// A `GET /user/installations` reply with one installation per
    /// `(id, account, repository_selection)`.
    fn installs_json(installs: &[(u64, &str, &str)]) -> String {
        let list: Vec<String> = installs
            .iter()
            .map(|(id, account, selection)| {
                format!(
                    r#"{{"id":{id},"app_slug":"gominimal","account":{{"login":{}}},"repository_selection":"{selection}"}}"#,
                    serde_json_lenient::to_string(account).expect("json")
                )
            })
            .collect();
        format!(
            r#"{{"total_count":{},"installations":[{}]}}"#,
            installs.len(),
            list.join(",")
        )
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
        /// As `Pending`, but the revocation of the token is refused.
        RevokeRefused,
        /// The browser flow's token exchange fails with a 502.
        ExchangeFails,
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
        let installs = Arc::new(Mutex::new(installs_json(&[(1, account, "all")])));
        let (seen2, challenge2, installs2) = (seen.clone(), challenge.clone(), installs.clone());
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
                            (Script::Pending | Script::OddToken | Script::RevokeRefused, 1) => {
                                r#"{"error":"authorization_pending"}"#.to_owned()
                            }
                            _ => token,
                        }
                    }
                    "/login/oauth/access_token" if script == Script::ExchangeFails => {
                        status = "502 Bad Gateway";
                        "<html>bad gateway</html>".to_owned()
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
                    p if p.starts_with("/user/installations/") => {
                        assert!(headers.contains(&format!("bearer {}", access.to_lowercase())));
                        assert!(p.ends_with("/repositories?per_page=1"), "{p}");
                        r#"{"total_count":3,"repositories":[]}"#.to_owned()
                    }
                    "/user/installations?per_page=100" => {
                        assert!(headers.contains(&format!("bearer {}", access.to_lowercase())));
                        installs2.lock().unwrap().clone()
                    }
                    p if p == format!("/applications/{CLIENT_ID}/token") => {
                        assert_eq!(method, "DELETE");
                        // Basic auth: the client id and the test secret.
                        let basic = base64::engine::general_purpose::STANDARD
                            .encode(format!("{CLIENT_ID}:test-secret"));
                        assert!(headers.contains(&format!("basic {}", basic.to_lowercase())));
                        if script == Script::RevokeRefused {
                            status = "422 Unprocessable Entity";
                            r#"{"message":"Validation Failed"}"#.to_owned()
                        } else {
                            status = "204 No Content";
                            String::new()
                        }
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
            installs,
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

    /// One step of a scripted browser.
    #[derive(Clone)]
    enum Visit {
        /// Go to the URL built from the redirect URI and the state.
        To(fn(&str, &str) -> String),
        /// Install the App: GitHub's installations reply becomes this.
        Install(String),
    }

    /// What the browser got back for one visit.
    struct Got {
        status: u16,
        headers: reqwest::header::HeaderMap,
        body: String,
    }

    /// Sign in through the browser flow, with a browser that makes `visits`
    /// in order once the authorize URL is opened.
    async fn browser_login(
        keychain: &MemoryKeychain,
        gh: &FakeGitHub,
        visits: Vec<Visit>,
    ) -> (anyhow::Result<Stored>, String, String, Vec<Got>) {
        let got: Arc<Mutex<Vec<Got>>> = Arc::default();
        let task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::default();
        let (challenge, installs) = (gh.challenge.clone(), gh.installs.clone());
        let (got2, task2) = (got.clone(), task.clone());
        let opener = move |authorize: &str| -> std::io::Result<()> {
            let url = url::Url::parse(authorize).expect("authorize url");
            let q: std::collections::HashMap<String, String> =
                url.query_pairs().into_owned().collect();
            *challenge.lock().unwrap() = Some(q["code_challenge"].clone());
            let (redirect, state) = (q["redirect_uri"].clone(), q["state"].clone());
            let (visits, got, installs) = (visits.clone(), got2.clone(), installs.clone());
            *task2.lock().unwrap() = Some(tokio::spawn(async move {
                for visit in visits {
                    match visit {
                        Visit::Install(json) => *installs.lock().unwrap() = json,
                        Visit::To(to) => {
                            let reply =
                                reqwest::get(to(&redirect, &state)).await.expect("callback");
                            let status = reply.status().as_u16();
                            let headers = reply.headers().clone();
                            let body = reply.text().await.expect("body");
                            got.lock().unwrap().push(Got {
                                status,
                                headers,
                                body,
                            });
                        }
                    }
                }
            }));
            Ok(())
        };
        let login = Login {
            keychain,
            endpoints: &gh.endpoints,
            client_secret: Some("test-secret"),
            device: false,
            open_browser: &opener,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let done = run_login(&login, &mut out, &mut err).await;
        let browser = task.lock().unwrap().take().expect("the browser was opened");
        browser.await.expect("browser");
        let got = std::mem::take(&mut *got.lock().unwrap());
        (
            done,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
            got,
        )
    }

    /// The command chip every failure page names as its next step.
    const CHIP: &str = "<code>min auth login</code>";

    fn to_callback(redirect: &str, state: &str) -> String {
        format!("{redirect}?code=the-code&state={state}")
    }

    /// Check what every page carries: the status, the headers, the heading,
    /// the inline mark, and no script, external request, code or token.
    fn assert_page(got: &Got, status: u16, heading: &str) {
        let body = &got.body;
        assert_eq!(got.status, status, "{body}");
        assert_eq!(
            got.headers["content-security-policy"],
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
        );
        assert_eq!(got.headers["referrer-policy"], "no-referrer");
        assert_eq!(got.headers["cache-control"], "no-store");
        assert_eq!(got.headers["x-content-type-options"], "nosniff");
        assert_eq!(got.headers["content-type"], "text/html; charset=utf-8");
        assert!(body.starts_with("<!doctype html>"), "{body}");
        assert!(body.contains(&format!("<h1>{heading}</h1>")), "{body}");
        assert!(body.contains("<svg class=\"mark\""), "{body}");
        assert!(
            body.contains("@media (prefers-color-scheme:dark)"),
            "{body}"
        );
        assert!(body.contains("user-select:all"), "{body}");
        for absent in [
            "<script", "<img", "<link", "url(", "the-code", "state=", ACCESS,
        ] {
            assert!(!body.contains(absent), "{absent} in {body}");
        }
    }

    // The browser page: signed in, and the App is installed.
    #[tokio::test]
    async fn browser_page_names_the_installed_accounts() {
        let gh = fake_github("octocat").await;
        *gh.installs.lock().unwrap() =
            installs_json(&[(1, "octocat", "all"), (2, "acme", "selected")]);
        let keychain = MemoryKeychain::default();
        let (done, out, err, got) =
            browser_login(&keychain, &gh, vec![Visit::To(to_callback)]).await;
        assert_eq!(done.expect("login").metadata.flow, Flow::Browser);
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert!(
            err.ends_with(
                "Your boxes can reach repositories on octocat and acme through the Minimal GitHub App.\n"
            ),
            "{err}"
        );
        assert_eq!(got.len(), 1);
        assert_page(
            &got[0],
            200,
            "Signed in to GitHub as <strong>octocat</strong>",
        );
        assert!(
            got[0].body.contains(
                "<p>Your boxes can reach repositories on <strong>octocat</strong> and <strong>acme</strong> through the Minimal GitHub App. You can close this tab.</p>\n<p class=\"muted\"><a href=\"https://github.com/settings/installations\">Change which repositories</a></p>"
            ),
            "{}",
            got[0].body
        );
    }

    // The browser page: signed in with no installation offers the install,
    // and GitHub's return from the install renders the installed page from
    // a fresh read of the installations, without exchanging the install's
    // code.
    #[tokio::test]
    async fn browser_page_offers_choose_repositories_then_confirms_the_install() {
        let gh = fake_github("octocat").await;
        *gh.installs.lock().unwrap() = installs_json(&[]);
        let keychain = MemoryKeychain::default();
        let visits = vec![
            Visit::To(to_callback),
            Visit::Install(installs_json(&[(7, "acme", "selected")])),
            // No state, and a code issued without the PKCE challenge.
            Visit::To(|redirect, _| {
                format!("{redirect}?code=install-code&installation_id=7&setup_action=install")
            }),
        ];
        let (done, out, err, got) = browser_login(&keychain, &gh, visits).await;
        done.expect("login");
        assert!(keychain.raw().is_some());
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert_eq!(
            err.lines().skip(2).collect::<Vec<_>>(),
            [
                "One more step: choose which repositories your boxes can reach at https://github.com/apps/gominimal/installations/new.",
                "Your boxes can't reach private repositories until you do.",
                "Waiting for the installation to finish in your browser. Press Ctrl-C to stop waiting.",
                "Installed on acme. Your boxes can reach 3 selected repositories there.",
            ],
            "{err}"
        );
        assert_eq!(got.len(), 2);
        assert_page(
            &got[0],
            200,
            "Signed in to GitHub as <strong>octocat</strong>",
        );
        assert!(
            got[0].body.contains(
                "<p>One more step: choose which repositories your boxes can reach.</p>\n<p><a class=\"button\" href=\"https://github.com/apps/gominimal/installations/new\">Choose repositories</a></p>\n<p class=\"muted\">Your boxes can&#39;t reach private repositories until you do.</p>"
            ),
            "{}",
            got[0].body
        );
        assert_page(&got[1], 200, "Installed on <strong>acme</strong>");
        assert!(
            got[1].body.contains(
                "<p>Your boxes can reach 3 selected repositories there. You can close this tab.</p>"
            ),
            "{}",
            got[1].body
        );
        assert!(!got[1].body.contains("install-code"));
        let seen = gh.seen.lock().unwrap();
        let exchanges: Vec<&String> = seen
            .iter()
            .filter(|r| r.starts_with("POST /login/oauth/access_token"))
            .collect();
        assert_eq!(exchanges.len(), 1, "{seen:?}");
        assert!(exchanges[0].contains("code=the-code"), "{seen:?}");
        assert!(
            seen.iter()
                .any(|r| r.starts_with("GET /user/installations/7/repositories")),
            "{seen:?}"
        );
    }

    // GitHub may send the browser back from the install to a port nothing
    // listens on. The re-read of the installations still ends the wait.
    #[tokio::test]
    async fn an_install_the_browser_does_not_return_from_ends_the_wait() {
        let gh = fake_github("octocat").await;
        *gh.installs.lock().unwrap() = installs_json(&[]);
        let keychain = MemoryKeychain::default();
        let visits = vec![
            Visit::To(to_callback),
            Visit::Install(installs_json(&[(9, "octocat", "all")])),
        ];
        let (done, _, err, got) = browser_login(&keychain, &gh, visits).await;
        done.expect("login");
        assert!(
            err.ends_with("Installed on octocat. Your boxes can reach all repositories there.\n"),
            "{err}"
        );
        assert_eq!(got.len(), 1);
    }

    // A failed read of the installations does not prove that none exists,
    // so the sign-in does not wait for an install.
    #[tokio::test]
    async fn unread_installations_do_not_start_the_wait() {
        let gh = fake_github("octocat").await;
        *gh.installs.lock().unwrap() = "not json".to_owned();
        let keychain = MemoryKeychain::default();
        let visits = vec![Visit::To(to_callback)];
        let (done, _, err, got) = tokio::time::timeout(
            Duration::from_secs(60),
            browser_login(&keychain, &gh, visits),
        )
        .await
        .expect("the sign-in does not wait");
        done.expect("login");
        assert!(
            err.ends_with(
                "`min` could not read where the Minimal GitHub App is installed.\n\
                 One more step: choose which repositories your boxes can reach at \
                 https://github.com/apps/gominimal/installations/new.\n"
            ),
            "{err}"
        );
        assert!(!err.contains("Waiting for the installation"), "{err}");
        assert_eq!(got.len(), 1);
    }

    // At the deadline the wait says it stopped and gives the install URL.
    #[tokio::test]
    async fn the_install_wait_gives_the_install_url_at_the_deadline() {
        let gh = fake_github("octocat").await;
        let opener = |_: &str| -> std::io::Result<()> { Ok(()) };
        let mut browser = Browser::open(&gh.endpoints, &opener, &mut Vec::new())
            .await
            .expect("open");
        browser.deadline = tokio::time::Instant::now();
        let mut err = Vec::new();
        browser
            .await_install(
                &reqwest::Client::new(),
                &gh.endpoints,
                ACCESS,
                "octocat",
                &mut err,
            )
            .await
            .expect("wait");
        assert_eq!(
            String::from_utf8(err).expect("utf8"),
            "Stopped waiting. `min` did not see an installation of the Minimal GitHub App.\n\
             One more step: choose which repositories your boxes can reach at \
             https://github.com/apps/gominimal/installations/new.\n"
        );
    }

    // A re-read that GitHub never answers does not hold the wait past its
    // deadline: the wait stops at the deadline, not at FINISH_TIMEOUT.
    #[tokio::test]
    async fn a_stalled_install_read_does_not_outlive_the_deadline() {
        let gh = fake_github("octocat").await;
        let opener = |_: &str| -> std::io::Result<()> { Ok(()) };
        let mut browser = Browser::open(&gh.endpoints, &opener, &mut Vec::new())
            .await
            .expect("open");
        // An API that accepts connections and never answers them.
        let stall = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let api = format!("http://{}", stall.local_addr().expect("addr"));
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((conn, _)) = stall.accept().await {
                held.push(conn);
            }
        });
        let endpoints = Endpoints {
            oauth: gh.endpoints.oauth.clone(),
            api,
        };
        let started = tokio::time::Instant::now();
        browser.deadline = started + INSTALL_POLL + Duration::from_secs(1);
        let mut err = Vec::new();
        browser
            .await_install(
                &reqwest::Client::new(),
                &endpoints,
                ACCESS,
                "octocat",
                &mut err,
            )
            .await
            .expect("wait");
        assert!(
            started.elapsed() < INSTALL_POLL + Duration::from_secs(4),
            "the wait ran {:?}",
            started.elapsed()
        );
        assert!(
            String::from_utf8(err)
                .expect("utf8")
                .starts_with("Stopped waiting."),
        );
    }

    // A request whose Host is not the callback's own 127.0.0.1:<port>, as a
    // page that reaches the listener through DNS rebinding sends, gets no
    // reply, so it cannot read the account a callback page names.
    #[tokio::test]
    async fn a_callback_with_another_host_gets_no_reply() {
        let gh = fake_github("octocat").await;
        let opener = |_: &str| -> std::io::Result<()> { Ok(()) };
        let mut browser = Browser::open(&gh.endpoints, &opener, &mut Vec::new())
            .await
            .expect("open");
        let url = url::Url::parse(&browser.redirect_uri).expect("redirect");
        let port = url.port().expect("port");
        let send = |host: String| async move {
            let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            let request =
                format!("GET {CALLBACK_PATH}?installation_id=1 HTTP/1.1\r\nHost: {host}\r\n\r\n");
            conn.write_all(request.as_bytes()).await.expect("write");
            let mut reply = Vec::new();
            let _ = tokio::time::timeout(
                REQUEST_READ_TIMEOUT + Duration::from_secs(1),
                conn.read_to_end(&mut reply),
            )
            .await;
            reply
        };
        let rebound = tokio::spawn(send(format!("attacker.example:{port}")));
        let next = tokio::time::timeout(Duration::from_secs(2), browser.callback.next()).await;
        assert!(
            next.is_err(),
            "a request with another Host reached the flow"
        );
        assert!(rebound.await.expect("join").is_empty());

        let own = tokio::spawn(send(format!("127.0.0.1:{port}")));
        let (mut conn, query) =
            tokio::time::timeout(Duration::from_secs(2), browser.callback.next())
                .await
                .expect("the callback's own Host reaches the flow")
                .expect("next");
        assert_eq!(query.get("installation_id"), Some("1"));
        respond(&mut conn, &Page::not_found()).await;
        drop(conn);
        assert!(!own.await.expect("join").is_empty());
    }

    // The install callback's re-read is bounded by the deadline too: a
    // callback near the deadline does not hold the wait past it.
    #[tokio::test]
    async fn a_stalled_install_read_on_the_callback_does_not_outlive_the_deadline() {
        let gh = fake_github("octocat").await;
        let opener = |_: &str| -> std::io::Result<()> { Ok(()) };
        let mut browser = Browser::open(&gh.endpoints, &opener, &mut Vec::new())
            .await
            .expect("open");
        // An API that accepts connections and never answers them.
        let stall = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let api = format!("http://{}", stall.local_addr().expect("addr"));
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((conn, _)) = stall.accept().await {
                held.push(conn);
            }
        });
        let endpoints = Endpoints {
            oauth: gh.endpoints.oauth.clone(),
            api,
        };
        let callback = format!("{}?installation_id=1", browser.redirect_uri);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = reqwest::get(callback).await;
        });
        let started = tokio::time::Instant::now();
        browser.deadline = started + Duration::from_secs(2);
        let mut err = Vec::new();
        browser
            .await_install(
                &reqwest::Client::new(),
                &endpoints,
                ACCESS,
                "octocat",
                &mut err,
            )
            .await
            .expect("wait");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait ran {:?}",
            started.elapsed()
        );
        assert!(
            String::from_utf8(err)
                .expect("utf8")
                .starts_with("Stopped waiting."),
        );
    }

    // A failed exchange renders the not-finished page, never a success.
    #[tokio::test]
    async fn browser_page_says_not_finished_when_the_exchange_fails() {
        let gh = fake_github_scripted("octocat", Script::ExchangeFails).await;
        let keychain = MemoryKeychain::default();
        let (done, out, _, got) = browser_login(&keychain, &gh, vec![Visit::To(to_callback)]).await;
        let text = format!("{:#}", done.expect_err("a failed exchange fails"));
        assert!(
            text.starts_with("GitHub approved the sign-in, but `min` could not finish it.\n"),
            "{text}"
        );
        assert!(text.contains("502 Bad Gateway"), "{text}");
        assert!(
            text.ends_with("\nRun `min auth login` to try again."),
            "{text}"
        );
        assert_eq!(out, "");
        assert!(keychain.raw().is_none());
        assert_eq!(got.len(), 1);
        assert_page(&got[0], 502, "Sign-in not finished");
        assert!(
            got[0].body.contains(&format!(
                "<p>GitHub approved the sign-in, but <code>min</code> could not finish it. Your terminal says why. Run {CHIP} to try again.</p>"
            )),
            "{}",
            got[0].body
        );
    }

    // The browser page: cancelled on GitHub, and refused by GitHub.
    #[tokio::test]
    async fn browser_page_says_cancelled_and_not_approved() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let cancel = Visit::To(|redirect, state| {
            format!("{redirect}?error=access_denied&error_description=denied&state={state}")
        });
        let (done, out, _, got) = browser_login(&keychain, &gh, vec![cancel]).await;
        assert_eq!(
            format!("{:#}", done.expect_err("cancelled")),
            "The sign-in was cancelled on GitHub. Nothing was saved. Run `min auth login` to try again."
        );
        assert_eq!(out, "");
        assert!(keychain.raw().is_none());
        assert_page(&got[0], 200, "Sign-in cancelled");
        assert!(
            got[0].body.contains(&format!(
                "<p>Nothing was saved. Run {CHIP} to try again.</p>"
            )),
            "{}",
            got[0].body
        );

        let refuse = Visit::To(|redirect, state| {
            format!("{redirect}?error=redirect_uri_mismatch&state={state}")
        });
        let (done, _, _, got) = browser_login(&keychain, &gh, vec![refuse]).await;
        assert_eq!(
            format!("{:#}", done.expect_err("refused")),
            "GitHub did not approve the sign-in. GitHub sent back `redirect_uri_mismatch`.\nRun `min auth login` to try again."
        );
        assert_page(&got[0], 502, "Sign-in not finished");
        assert!(
            got[0].body.contains(&format!(
                "<p>GitHub did not approve the sign-in. Your terminal says why. Run {CHIP} to try again.</p>"
            )),
            "{}",
            got[0].body
        );
    }

    // The browser page: an expired link and an unknown path answer, and the
    // listener keeps serving the real callback.
    #[tokio::test]
    async fn browser_pages_for_expired_link_and_unknown_path_keep_the_listener() {
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        let visits = vec![
            Visit::To(|redirect, _| format!("{redirect}?code=the-code&state=earlier")),
            Visit::To(|redirect, _| redirect.replace("/callback", "/favicon.ico")),
            Visit::To(to_callback),
        ];
        let (done, out, _, got) = browser_login(&keychain, &gh, visits).await;
        done.expect("login");
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert_eq!(got.len(), 3);
        assert_page(&got[0], 400, "This sign-in link has expired");
        assert!(
            got[0].body.contains(&format!(
                "<p>It belongs to an earlier {CHIP}. Run {CHIP} again.</p>"
            )),
            "{}",
            got[0].body
        );
        assert_page(&got[1], 404, "Not found");
        assert!(!got[1].body.contains("min auth login"), "{}", got[1].body);
        assert_page(
            &got[2],
            200,
            "Signed in to GitHub as <strong>octocat</strong>",
        );
    }

    // Names from GitHub are escaped on the page.
    #[tokio::test]
    async fn browser_page_escapes_names_from_github() {
        let gh = fake_github("octocat").await;
        let hostile = r#"<img src=x onerror=alert(1)>&"'"#;
        *gh.installs.lock().unwrap() = installs_json(&[(1, hostile, "all")]);
        let keychain = MemoryKeychain::default();
        let (done, _, _, got) = browser_login(&keychain, &gh, vec![Visit::To(to_callback)]).await;
        done.expect("login");
        assert_page(
            &got[0],
            200,
            "Signed in to GitHub as <strong>octocat</strong>",
        );
        assert!(
            got[0]
                .body
                .contains("<strong>&lt;img src=x onerror=alert(1)&gt;&amp;&quot;&#39;</strong>"),
            "{}",
            got[0].body
        );
        let installed = Page::installed(hostile, "all repositories").response();
        assert!(
            installed.contains(
                "<h1>Installed on <strong>&lt;img src=x onerror=alert(1)&gt;&amp;&quot;&#39;</strong></h1>"
            ),
            "{installed}"
        );
        assert!(!installed.contains("<img"), "{installed}");
    }

    // The device flow prints the same install line as the browser flow.
    #[tokio::test]
    async fn device_sign_in_without_installation_prints_the_install_url() {
        let gh = fake_github("octocat").await;
        *gh.installs.lock().unwrap() = installs_json(&[]);
        let keychain = MemoryKeychain::default();
        let (_, out, err) = login_with(&keychain, &gh, None, true, &no_browser).await;
        assert_eq!(out, "Signed in to GitHub as octocat.\n");
        assert!(
            err.ends_with(
                "One more step: choose which repositories your boxes can reach at https://github.com/apps/gominimal/installations/new.\nYour boxes can't reach private repositories until you do.\n"
            ),
            "{err}"
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
        assert_eq!(
            err.lines().last(),
            Some("Your boxes can reach repositories on octocat through the Minimal GitHub App."),
            "{err}"
        );
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
        // Every sign-in says where the App's installations let boxes reach.
        assert!(
            err.ends_with(
                "Your boxes can reach repositories on octocat through the Minimal GitHub App.\n"
            ),
            "{err}"
        );
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

    /// A memory keychain that counts the reads of the material and the
    /// writes.
    #[derive(Default)]
    struct CountingKeychain {
        inner: MemoryKeychain,
        material_reads: std::sync::atomic::AtomicUsize,
        writes: std::sync::atomic::AtomicUsize,
    }

    impl Keychain for CountingKeychain {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.inner.metadata()
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.material_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.material()
        }
        fn write(
            &self,
            metadata: &Metadata,
            material: &Material,
        ) -> Result<(), signin::SignInError> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.write(metadata, material)
        }
    }

    // BEP-069: the proxy alone presents and renews the token. After sign-in
    // the client reads only the item's metadata, whatever the token's
    // standing, and never sends a refresh grant.
    #[tokio::test]
    async fn client_never_presents_or_refreshes_the_token() {
        let gh = fake_github("octocat").await;
        let keychain = CountingKeychain::default();
        let login = Login {
            keychain: &keychain,
            endpoints: &gh.endpoints,
            client_secret: None,
            device: true,
            open_browser: &no_browser,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let stored = run_login(&login, &mut out, &mut err).await.expect("login");
        let seen_at_sign_in = gh.seen.lock().unwrap().len();
        assert_eq!(keychain.writes.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Live, within the proxy's renewal window, expired with live
        // refresh material, and lapsed.
        let expires = stored.metadata.token_expires_at;
        for now in [
            expires - 3600,
            expires - 60,
            expires + 60,
            stored.metadata.refresh_expires_at + 60,
        ] {
            let mut out = Vec::new();
            write_status(&keychain, now, &mut out).expect("status");
            let out = String::from_utf8(out).expect("utf8");
            assert!(!out.contains(ACCESS) && !out.contains(REFRESH), "{out}");
        }

        assert_eq!(
            keychain
                .material_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the client never reads the token"
        );
        assert_eq!(
            keychain.writes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the client never writes a renewed token"
        );
        let seen = gh.seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            seen_at_sign_in,
            "nothing reaches GitHub after sign-in"
        );
        assert!(
            !seen.iter().any(|r| r.contains("grant_type=refresh_token")),
            "{seen:?}"
        );
        // The requests that carry the token are the sign-in's account
        // lookup and its one read of the App's installations.
        assert_eq!(
            seen.iter().filter(|r| r.starts_with("GET /user ")).count(),
            1
        );
        assert_eq!(
            seen.iter()
                .filter(|r| r.starts_with("GET /user/installations"))
                .count(),
            1
        );
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

    /// A keychain the test and a proxy's redeemer share.
    #[derive(Clone, Default)]
    struct Shared(Arc<MemoryKeychain>);

    impl Keychain for Shared {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.0.metadata()
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.0.material()
        }
        fn write(&self, meta: &Metadata, material: &Material) -> Result<(), signin::SignInError> {
            self.0.write(meta, material)
        }
    }

    impl SignInItem for Shared {
        fn delete(&self) -> anyhow::Result<()> {
            self.0.delete()
        }
    }

    /// A keychain that refuses to delete the item.
    #[derive(Default)]
    struct Undeletable(MemoryKeychain);

    impl Keychain for Undeletable {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.0.metadata()
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            self.0.material()
        }
        fn write(&self, meta: &Metadata, material: &Material) -> Result<(), signin::SignInError> {
            self.0.write(meta, material)
        }
    }

    impl SignInItem for Undeletable {
        fn delete(&self) -> anyhow::Result<()> {
            bail!("the host keychain refused to delete the GitHub sign-in: locked")
        }
    }

    /// What a [`Broken`] keychain does after its delete fails.
    #[derive(Clone, Copy)]
    enum After {
        /// The token item is gone, and the metadata item is still held.
        TokenGone,
        /// Every read fails.
        ReadsRefused,
    }

    /// A keychain whose delete fails part way.
    struct Broken {
        inner: MemoryKeychain,
        after: After,
        tried: std::sync::atomic::AtomicBool,
    }

    impl Broken {
        fn new(after: After) -> Self {
            Self {
                inner: MemoryKeychain::default(),
                after,
                tried: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn refused(&self) -> Option<signin::SignInError> {
            (self.tried.load(std::sync::atomic::Ordering::SeqCst)
                && matches!(self.after, After::ReadsRefused))
            .then(|| signin::SignInError::Keychain {
                action: "read the sign-in",
                detail: "unreadable".into(),
            })
        }
    }

    impl Keychain for Broken {
        fn metadata(&self) -> Result<Option<Metadata>, signin::SignInError> {
            self.refused().map_or_else(|| self.inner.metadata(), Err)
        }
        fn material(&self) -> Result<Option<Material>, signin::SignInError> {
            if let Some(e) = self.refused() {
                return Err(e);
            }
            if self.tried.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.material()
        }
        fn write(&self, meta: &Metadata, material: &Material) -> Result<(), signin::SignInError> {
            self.inner.write(meta, material)
        }
    }

    impl SignInItem for Broken {
        fn delete(&self) -> anyhow::Result<()> {
            self.tried.store(true, std::sync::atomic::Ordering::SeqCst);
            bail!("the host keychain refused to delete the GitHub sign-in: locked")
        }
    }

    async fn logout_with(
        keychain: &dyn SignInItem,
        endpoints: &Endpoints,
        secret: Option<&str>,
    ) -> (anyhow::Result<LoggedOut>, String, String) {
        let logout = Logout {
            keychain,
            endpoints,
            client_secret: secret,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let done = run_logout(&logout, &mut out, &mut err).await;
        (
            done,
            String::from_utf8(out).expect("utf8"),
            String::from_utf8(err).expect("utf8"),
        )
    }

    fn revocations(gh: &FakeGitHub) -> Vec<String> {
        gh.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with(&format!("DELETE /applications/{CLIENT_ID}/token")))
            .cloned()
            .collect()
    }

    // BEP-044: logout deletes the item, asks GitHub to revoke the sign-in,
    // and reports a refused or unreachable revocation without failing.
    #[tokio::test]
    async fn logout_revokes_at_github_best_effort() {
        let deleted =
            |k: &MemoryKeychain| k.item(SERVICE).is_none() && k.item(META_SERVICE).is_none();

        // GitHub confirms the revocation.
        let gh = fake_github("octocat").await;
        let keychain = MemoryKeychain::default();
        login_with(&keychain, &gh, None, true, &no_browser).await;
        let (done, out, err) = logout_with(&keychain, &gh.endpoints, Some("test-secret")).await;
        assert_eq!(
            done.expect("logout"),
            LoggedOut::Deleted { confirmed: true }
        );
        assert_eq!(out, format!("{SIGNED_OUT}\n"));
        assert_eq!(err, "");
        assert!(deleted(&keychain));
        let asked = revocations(&gh);
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert!(asked[0].contains(ACCESS), "the revocation names the token");

        // GitHub refuses the revocation: the logout still succeeds.
        let refusing = fake_github_scripted("octocat", Script::RevokeRefused).await;
        login_with(&keychain, &refusing, None, true, &no_browser).await;
        let (done, out, err) =
            logout_with(&keychain, &refusing.endpoints, Some("test-secret")).await;
        assert_eq!(
            done.expect("logout"),
            LoggedOut::Deleted { confirmed: false }
        );
        assert_eq!(out, format!("{SIGNED_OUT}\n"));
        assert_eq!(err, format!("{NOT_CONFIRMED}\n"));
        assert!(deleted(&keychain));
        assert_eq!(revocations(&refusing).len(), 1);

        // GitHub cannot be reached: nothing listens on the port.
        let dead = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            format!("http://{}", l.local_addr().expect("addr"))
        };
        let unreachable = Endpoints {
            oauth: dead.clone(),
            api: dead,
        };
        login_with(&keychain, &gh, None, true, &no_browser).await;
        let (done, out, err) = logout_with(&keychain, &unreachable, Some("test-secret")).await;
        assert_eq!(
            done.expect("logout"),
            LoggedOut::Deleted { confirmed: false }
        );
        assert_eq!(out, format!("{SIGNED_OUT}\n"));
        assert_eq!(err, format!("{NOT_CONFIRMED}\n"));
        assert!(deleted(&keychain));

        // A build with no client secret cannot ask GitHub, and says so.
        login_with(&keychain, &gh, None, true, &no_browser).await;
        let (done, _, err) = logout_with(&keychain, &gh.endpoints, None).await;
        assert_eq!(
            done.expect("logout"),
            LoggedOut::Deleted { confirmed: false }
        );
        assert_eq!(err, format!("{NOT_CONFIRMED}\n"));
        assert!(deleted(&keychain));
        assert_eq!(revocations(&gh).len(), 1, "GitHub was not asked again");

        // Nothing held: nothing to delete and nothing to revoke.
        let (done, out, err) = logout_with(&keychain, &gh.endpoints, Some("test-secret")).await;
        assert_eq!(done.expect("logout"), LoggedOut::NotSignedIn);
        assert_eq!(out, "Not signed in to GitHub.\n");
        assert_eq!(err, "");
        assert_eq!(revocations(&gh).len(), 1);

        // A keychain that refuses the delete fails the logout, keeps the
        // item and asks GitHub nothing.
        let stuck = Undeletable::default();
        login_with(&stuck.0, &gh, None, true, &no_browser).await;
        let (done, out, _) = logout_with(&stuck, &gh.endpoints, Some("test-secret")).await;
        let text = format!("{:#}", done.expect_err("a refused delete fails"));
        assert!(text.contains("still signed in"), "{text}");
        assert!(text.contains("locked"), "{text}");
        assert_eq!(out, "");
        assert!(stuck.0.raw().is_some());
        assert_eq!(revocations(&gh).len(), 1);

        // A delete that stops after the token item is gone: every reference
        // is refused, so GitHub is still asked, and the command says what
        // is left and how to remove it.
        let half = Broken::new(After::TokenGone);
        login_with(&half.inner, &gh, None, true, &no_browser).await;
        let (done, out, err) = logout_with(&half, &gh.endpoints, Some("test-secret")).await;
        let text = format!("{:#}", done.expect_err("a part-way delete fails"));
        assert!(text.starts_with(PARTLY_REMOVED), "{text}");
        assert!(!text.contains("still signed in"), "{text}");
        assert_eq!(out, format!("{SIGNED_OUT}\n"));
        assert_eq!(err, "");
        assert_eq!(revocations(&gh).len(), 2, "GitHub was asked to revoke");

        // A failed delete whose read-back also fails cannot say whether the
        // sign-in is held: the logout fails, says so, and asks GitHub nothing.
        let unread = Broken::new(After::ReadsRefused);
        login_with(&unread.inner, &gh, None, true, &no_browser).await;
        let (done, out, err) = logout_with(&unread, &gh.endpoints, Some("test-secret")).await;
        let text = format!("{:#}", done.expect_err("an unreadable keychain fails"));
        assert!(text.starts_with(NOT_KNOWN), "{text}");
        assert!(text.contains("unreadable"), "{text}");
        assert_eq!(out, "");
        assert_eq!(err, "");
        assert_eq!(revocations(&gh).len(), 2);

        // The host keychain's read-back after a delete: a read that fails is
        // an error, never "deleted".
        let e = confirm_deleted(&RefusingKeychain::default()).expect_err("refused read-back");
        assert!(format!("{e:#}").contains("locked"), "{e:#}");
        let held = MemoryKeychain::default();
        login_with(&held, &gh, None, true, &no_browser).await;
        assert!(
            confirm_deleted(&held).is_err(),
            "a held item is not deleted"
        );
        held.clear();
        confirm_deleted(&held).expect("an empty keychain is deleted");

        // The stderr line gives each fact its own sentence.
        assert!(!NOT_CONFIRMED.contains(';'), "{NOT_CONFIRMED}");
    }

    /// A proxy sealing key held in memory, for the redeemer.
    struct TestKey(p256::ecdsa::SigningKey);

    impl bep::keys::HeldKey for TestKey {
        fn role(&self) -> bep::keys::Role {
            bep::keys::Role::Sealing
        }
        fn public(&self) -> bep::seal::ProxyPublicKey {
            bep::seal::ProxyPublicKey::from_sec1_bytes(&self.0.verifying_key().to_sec1_bytes())
                .expect("a P-256 key")
        }
        fn exportable(&self) -> bool {
            false
        }
        fn agree(
            &self,
            peer: &bep::seal::ProxyPublicKey,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, bep::keys::KeyError> {
            let peer = p256::PublicKey::from_sec1_bytes(&peer.to_sec1_bytes()).expect("peer");
            let shared = p256::ecdh::diffie_hellman(self.0.as_nonzero_scalar(), peer.as_affine());
            Ok(zeroize::Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }
        fn probe(&self) -> Result<(), bep::keys::KeyError> {
            Ok(())
        }
    }

    // BEP-044: a sign-in after a logout is redeemed through the references
    // minted from it, and every reference minted before the logout stays
    // refused.
    #[tokio::test]
    async fn sign_in_after_logout_revives_no_earlier_reference() {
        use bep::boxes::{Boxes, Stance};
        use bep::forward::{Redeemer as _, Verdict};
        use bep::handle::{Claims, ClientKeys};
        use bep::module::GITHUB;
        use bep::redeem::{Authority, RequestAuthority};
        use bep::seal::{Breadth, Context, Member, MemberKind, MemberList, Mode};
        use p256::ecdsa::SigningKey;

        const NODE: &str = "node-1";
        let now = now();
        let keychain = Shared::default();
        let key = TestKey(SigningKey::from_bytes(&[7u8; 32].into()).expect("key"));
        let sealing = bep::keys::HeldKey::public(&key);
        let client = SigningKey::from_bytes(&[9u8; 32].into()).expect("key");
        let mut clients = ClientKeys::new();
        clients
            .register(&client.verifying_key().to_sec1_bytes())
            .expect("register");
        let hosts: Vec<Authority<String>> = GITHUB
            .hosts
            .iter()
            .map(|a| Authority {
                host: a.host.to_owned(),
                port: a.port,
            })
            .collect();
        let boxes = Arc::new(Boxes::new());
        for b in ["b1", "b2", "b3"] {
            boxes.register(b, hosts.clone(), Stance::OwnIp);
        }
        let redeemer = bep::redeemer::BoxRedeemer::new(
            key,
            NODE,
            GITHUB,
            Arc::new(std::sync::RwLock::new(clients)),
            Arc::clone(&boxes),
            keychain.clone(),
        );

        // A reference to the held sign-in, minted for `box_id`: a handle
        // naming the item's instance, sealed for this proxy.
        let mint = |box_id: &str| {
            let instance = keychain.metadata().expect("read").expect("held").instance;
            let jws = bep::handle::sign(
                &client,
                &Claims {
                    sub: box_id.into(),
                    node_id: NODE.into(),
                    store: GITHUB.id.into(),
                    id: instance,
                    upstream: GITHUB.hosts.iter().map(|a| a.host.to_owned()).collect(),
                    inject: None,
                    iat: now - 10,
                    exp: now + 3600,
                    jti: format!("jti-{box_id}"),
                },
            );
            bep::seal::seal(
                &sealing,
                &Context {
                    box_id: box_id.into(),
                    host: NODE.into(),
                    module: GITHUB.id.into(),
                    host_set_version: GITHUB.host_set_version,
                    mode: Mode::User,
                    iat: now - 10,
                    expiry: now + 3600,
                    kid: sealing.kid(),
                },
                &MemberList {
                    members: vec![Member {
                        kind: MemberKind::SignIn,
                        breadth: Breadth::Full,
                        jws: zeroize::Zeroizing::new(jws),
                        exp: None,
                    }],
                    default_owner: None,
                },
            )
            .expect("seal")
        };
        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        let request = RequestAuthority {
            host: Some(api.clone()),
            target: None,
        };
        let admitted =
            |box_id: &str, sealed: &str| match redeemer.redeem(box_id, &api, &request, sealed) {
                Verdict::Admit { credential, .. } => {
                    assert_eq!(credential.as_str(), ACCESS);
                    true
                }
                Verdict::Refuse(_) => false,
            };

        let gh = fake_github("octocat").await;
        let (first, _, _) = login_with(&keychain.0, &gh, None, true, &no_browser).await;
        let before_1 = mint("b1");
        let before_2 = mint("b2");
        assert!(admitted("b1", &before_1), "a reference to the held sign-in");
        assert!(admitted("b2", &before_2), "a reference to the held sign-in");

        let (done, _, _) = logout_with(&keychain, &gh.endpoints, Some("test-secret")).await;
        assert_eq!(
            done.expect("logout"),
            LoggedOut::Deleted { confirmed: true }
        );
        // Every reference is refused at its next request.
        assert!(!admitted("b1", &before_1), "refused after logout");
        assert!(!admitted("b2", &before_2), "refused after logout");

        // The same account signs in again: a new instance.
        let (second, _, _) = login_with(&keychain.0, &gh, None, true, &no_browser).await;
        assert!(second.new_instance);
        assert_ne!(second.metadata.instance, first.metadata.instance);
        let after = mint("b3");
        assert!(
            admitted("b3", &after),
            "a reference minted after the sign-in"
        );
        assert!(!admitted("b1", &before_1), "minted before the logout");
        assert!(!admitted("b2", &before_2), "minted before the logout");
    }
}
