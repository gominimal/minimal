//! Handing a bundle to the diag portal.
//!
//! The portal takes a `min bug` bundle, runs an agent over it in a sandbox,
//! and publishes a report at an unguessable URL. A browser gets past its
//! Turnstile challenge by having a human solve one; there is no human here,
//! so this presents a GitHub token instead. That answers the question the
//! portal actually needs answered — whose daily allowance this diagnosis
//! spends — and it is a token the developer already has, because a
//! diagnostic upload is not worth a credential of its own.
//!
//! Upload is two requests. That is the portal's contract, not a choice made
//! here: a create that declares the bundle's name, length and hash, then the
//! bytes. It is the better shape for this end too, because every refusal that
//! matters — an unknown token, a spent allowance, an oversized bundle — lands
//! on the first request, so being turned away costs a round trip instead of
//! the whole upload.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde_json_lenient::{Value, json};
use sha2::{Digest as _, Sha256};
use url::{Host, Url};

/// Where the portal lives.
///
/// `agents.minimal.farm` is the agent runtime's Worker, which the portal is
/// mounted on rather than deployed beside: the custom domain belongs to a
/// Pulumi stack, and a second Worker would need a route declared there.
pub const DEFAULT_ENDPOINT: &str = "https://agents.minimal.farm";

/// A bundle the portal took.
#[derive(Debug)]
pub struct Uploaded {
    /// The page a person opens to read the report once it is written.
    pub report_url: String,
    /// The same diagnosis as JSON, for a caller that would rather poll than
    /// look. An agent uploads and then waits; handing it this spares it
    /// having to know how the portal spells its own API.
    pub status_url: String,
}

/// What the portal will not accept, checked here before anything is read.
///
/// `min bug --upload` sends an archive it just wrote, about a megabyte of it.
/// `min diag upload` takes whatever path it is given, so without this the
/// refusal would arrive from the portal after the whole file had been pulled
/// into memory to be hashed.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// How long to wait for the portal to answer at all.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait between reads once it has.
///
/// This bounds a portal that accepts the connection and then says nothing. It
/// does not bound a stalled write, so the two requests below carry an overall
/// deadline as well.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Overall deadline for the create request, which carries no bundle.
const CREATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall deadline for the request that carries the bundle.
///
/// Generous, because it has to cover [`MAX_BUNDLE_BYTES`] over a slow link
/// and cutting off an upload that is merely slow would be the worse failure.
/// It is here so that a peer which accepts the connection and then stops
/// reading is bounded at all: neither the connect nor the read deadline
/// covers a write that never drains.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Sends a bundle and returns where its diagnosis will appear.
///
/// The bundle is read whole, which is sound because [`MAX_BUNDLE_BYTES`] is
/// checked against the file's length first. A stream would buy nothing after
/// that: the create request declares the exact byte count and sha256 up front,
/// and computing those means reading every byte regardless.
pub async fn upload(
    path: &Path,
    endpoint: &str,
    token: &str,
    note: &str,
) -> Result<Uploaded, anyhow::Error> {
    let (base, local_only) = checked_base(endpoint)?;
    let base = &base;
    let size = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if size == 0 {
        bail!("{} is empty; there is nothing to diagnose", path.display());
    }
    if size > MAX_BUNDLE_BYTES {
        bail!(
            "{} is {size} bytes; the portal takes at most {MAX_BUNDLE_BYTES}. Collect with a smaller \
             --log-tail-bytes, or send it to the dev team directly",
            path.display()
        );
    }
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no file name to tell the portal", path.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    // Redirects are not followed. Keeping the bundle on the host the operator
    // named is the point of joining the portal's path to `base` rather than
    // following whatever URL it returns, and a 3xx would walk straight around
    // that: reqwest follows up to ten by default, to any host. A portal that
    // wants the bytes elsewhere can say so in the path it hands back.
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);
    // The loopback exception is only sound if the request actually stays on
    // the machine. reqwest honours HTTP_PROXY by default, so without this a
    // proxy in the environment would carry the token off the host through the
    // very case that was allowed for being local.
    if local_only {
        builder = builder.no_proxy();
    }
    let client = builder.build().context("building the HTTP client")?;

    let created = client
        .post(format!("{base}/diag/api/diagnoses"))
        .timeout(CREATE_TIMEOUT)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            json!({ "name": name, "bytes": bytes.len(), "sha256": sha256, "context": note })
                .to_string(),
        )
        .send()
        .await
        .with_context(|| format!("asking {base} to take a bundle"))?;
    let status = created.status();
    let body = created.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "{base} would not take the bundle ({status}): {}",
            refusal(&body)
        );
    }
    let created: Value = serde_json_lenient::from_str(&body).with_context(|| {
        format!(
            "{base} answered with something that is not JSON: {}",
            refusal(&body)
        )
    })?;
    let id = created["id"]
        .as_str()
        .context("the portal took the bundle but did not say what it called the diagnosis")?
        .to_owned();
    // The path the portal names, joined to the base this command was given.
    // Joining rather than following keeps the bytes on the host the caller
    // chose: a portal that answered with an absolute URL could otherwise
    // redirect a machine's diagnostics somewhere the operator never named.
    let put_path = created["upload"]
        .as_str()
        .filter(|p| p.starts_with('/'))
        .context("the portal did not say where to put the bundle")?;

    let sent = client
        .put(format!("{base}{put_path}"))
        .timeout(UPLOAD_TIMEOUT)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/zstd")
        .header(reqwest::header::CONTENT_LENGTH, bytes.len())
        .body(bytes)
        .send()
        .await
        .with_context(|| format!("sending the bundle to {base}"))?;
    let status = sent.status();
    if !status.is_success() {
        let body = sent.text().await.unwrap_or_default();
        bail!(
            "{base} did not keep the bundle ({status}): {}",
            refusal(&body)
        );
    }

    Ok(Uploaded {
        report_url: format!("{base}/diag/{id}"),
        status_url: format!("{base}/diag/api/diagnoses/{id}"),
    })
}

/// The endpoint to upload to, and whether the client must refuse proxies.
///
/// The upload presents a GitHub token, so the scheme is the caller's to get
/// wrong and this function's to refuse. Plain HTTP is allowed only to a
/// loopback host, which is how the portal is served while it is being worked
/// on; anything else must be HTTPS, because a bearer credential does not go
/// on the wire in clear. Checked before the bundle is read, for the same
/// reason the length is: a refusal should not cost a file read.
///
/// The trailing slash is trimmed here too, so the URLs built below cannot
/// differ by one. The flag returned alongside it is true for the loopback
/// case, which the caller turns into a client that ignores HTTP_PROXY: the
/// exception is granted for the request staying on the machine, so it has to.
fn checked_base(endpoint: &str) -> Result<(String, bool), anyhow::Error> {
    let base = endpoint.trim_end_matches('/');
    let url = Url::parse(base).with_context(|| format!("{base} is not a URL"))?;
    let loopback = match url.host() {
        Some(Host::Domain(host)) => host == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    let local_only = match url.scheme() {
        "https" => false,
        "http" if loopback => true,
        "http" => {
            bail!("{base} is plain http, and the upload carries a token; name an https portal")
        }
        scheme => bail!("{base} speaks {scheme}; the portal is reached over https"),
    };
    Ok((base.to_owned(), local_only))
}

/// The portal's own words for a refusal.
///
/// Every route answers `{"error": "..."}`, and that sentence is written to be
/// read by whoever hit it — "at most 5 diagnoses a day from one account" is
/// the whole diagnosis of the failure. A body that is not that shape is shown
/// verbatim and cut short, because an unparseable refusal is usually an
/// intermediary's error page and its first line says which.
fn refusal(body: &str) -> String {
    serde_json_lenient::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| body.chars().take(200).collect())
}

/// The GitHub user token to upload with, from the first place that has one.
///
/// The rungs are where a developer or an agent already keeps one, ordered so
/// that a deliberate choice outranks an ambient one: the flag, then the two
/// variables GitHub's own tooling reads, then `gh` itself — which is where a
/// laptop that has only ever signed in through the CLI keeps it, and the
/// reason this does not stop at the environment.
///
/// `gh` failing is not an error here. It is frequently not installed, and the
/// message this ends on names every rung rather than whichever one was tried
/// last.
pub async fn resolve_token(explicit: Option<&str>) -> Result<String, anyhow::Error> {
    if let Some(token) = explicit.map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(token.to_owned());
    }
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Some(token) = std::env::var(var)
            .ok()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
        {
            return Ok(token);
        }
    }
    if let Ok(out) = tokio::process::Command::new("gh")
        .args(["auth", "token"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        && out.status.success()
    {
        let token = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !token.is_empty() {
            return Ok(token);
        }
    }
    bail!(
        "no GitHub token to upload with: pass --token, set $GITHUB_TOKEN, or run `gh auth login`. \
         It must be a user token; a GitHub Actions job's own GITHUB_TOKEN is an app installation \
         token and the portal refuses it"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_reported_in_the_portals_own_words() {
        assert_eq!(
            refusal(r#"{"error":"at most 5 diagnoses a day from one account"}"#),
            "at most 5 diagnoses a day from one account"
        );
    }

    /// An intermediary's HTML error page is not the portal's JSON, and the
    /// operator still has to be told something they can act on.
    #[test]
    fn a_body_that_is_not_the_portals_shape_is_shown_verbatim_and_cut_short() {
        assert_eq!(
            refusal("<html>502 Bad Gateway</html>"),
            "<html>502 Bad Gateway</html>"
        );
        assert_eq!(refusal(&"x".repeat(500)).len(), 200);
        // Valid JSON, but not a refusal: there is no sentence to lift, so the
        // body itself is the most informative thing left.
        assert_eq!(refusal(r#"{"state":"queued"}"#), r#"{"state":"queued"}"#);
    }

    /// The bundle is uploaded with a bearer token, so an endpoint that would
    /// put that token on the wire in clear is refused rather than used.
    #[test]
    fn a_portal_that_would_leak_the_token_is_refused() {
        // Loopback is how the portal is served while it is being worked on,
        // and nothing leaves the machine, so plain http is allowed there.
        // The flag is what makes the loopback exception safe: the caller
        // turns it into a client that ignores HTTP_PROXY, so an http upload
        // cannot be carried off the machine by a proxy in the environment.
        for (ok, local_only) in [
            ("https://agents.minimal.farm", false),
            ("http://127.0.0.1:8787", true),
            ("http://localhost:8787", true),
            ("http://[::1]:8787", true),
        ] {
            assert_eq!(checked_base(ok).unwrap().1, local_only, "{ok}");
        }

        let err = checked_base("http://agents.minimal.farm")
            .unwrap_err()
            .to_string();
        assert!(err.contains("plain http"), "{err}");

        // Not a transport that can carry the request at all, and `file://`
        // would read the local disk rather than reach a portal.
        let err = checked_base("file:///etc/passwd").unwrap_err().to_string();
        assert!(err.contains("speaks file"), "{err}");

        assert!(checked_base("agents.minimal.farm").is_err());
    }

    /// The trailing slash is trimmed once, so the two URLs the upload builds
    /// cannot differ by one.
    #[test]
    fn a_trailing_slash_is_trimmed() {
        assert_eq!(
            checked_base("https://agents.minimal.farm/").unwrap().0,
            "https://agents.minimal.farm"
        );
    }

    /// Both refusals happen on the file's length, before a byte is read and
    /// before the network is touched: the endpoint below is unroutable, so a
    /// test that reached it would hang rather than pass.
    #[tokio::test]
    async fn a_bundle_the_portal_cannot_take_is_refused_before_it_is_read() {
        let dir = tempfile::TempDir::new().unwrap();

        let empty = dir.path().join("empty.tar.zst");
        tokio::fs::File::create(&empty).await.unwrap();
        let err = upload(&empty, "http://127.0.0.1:1", "t", "")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "{err}");

        // Sparse: `set_len` past the cap costs no disk and no memory, which is
        // exactly the cost this check exists to avoid paying.
        let huge = dir.path().join("huge.tar.zst");
        tokio::fs::File::create(&huge)
            .await
            .unwrap()
            .set_len(MAX_BUNDLE_BYTES + 1)
            .await
            .unwrap();
        let err = upload(&huge, "http://127.0.0.1:1", "t", "")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&MAX_BUNDLE_BYTES.to_string()),
            "the refusal must name the ceiling: {err}"
        );
    }

    #[tokio::test]
    async fn the_flag_outranks_the_environment() {
        // SAFETY: single-threaded test, and the value is restored below.
        unsafe { std::env::set_var("GITHUB_TOKEN", "from-the-environment") };
        assert_eq!(
            resolve_token(Some("from-the-flag")).await.unwrap(),
            "from-the-flag"
        );
        // An empty flag is not a choice; it falls through to the next rung.
        assert_eq!(
            resolve_token(Some("  ")).await.unwrap(),
            "from-the-environment"
        );
        unsafe { std::env::remove_var("GITHUB_TOKEN") };
    }
}
