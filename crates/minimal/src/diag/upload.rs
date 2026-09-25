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

use anyhow::{Context as _, bail};
use serde_json_lenient::{Value, json};
use sha2::{Digest as _, Sha256};

/// Where the portal lives.
///
/// `agents.minimal.farm` is the agent runtime's Worker, which the portal is
/// mounted on rather than deployed beside: the custom domain belongs to a
/// Pulumi stack, and a second Worker would need a route declared there.
pub const DEFAULT_ENDPOINT: &str = "https://agents.minimal.farm";

/// A bundle the portal took.
pub struct Uploaded {
    /// The page a person opens to read the report once it is written.
    pub report_url: String,
    /// The same diagnosis as JSON, for a caller that would rather poll than
    /// look. An agent uploads and then waits; handing it this spares it
    /// having to know how the portal spells its own API.
    pub status_url: String,
}

/// Sends a bundle and returns where its diagnosis will appear.
///
/// The bundle is read whole. `min bug` writes about a megabyte and the portal
/// refuses anything past sixty-four, so the memory is bounded and known, and
/// a stream would buy nothing but a length this has to compute anyway: the
/// portal is told the exact byte count up front and holds the upload to it.
pub async fn upload(
    path: &Path,
    endpoint: &str,
    token: &str,
    note: &str,
) -> Result<Uploaded, anyhow::Error> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.is_empty() {
        bail!("{} is empty; there is nothing to diagnose", path.display());
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no file name to tell the portal", path.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    // Trimmed once, here, so the two URLs below cannot differ by a slash.
    let base = endpoint.trim_end_matches('/');
    let client = reqwest::Client::new();

    let created = client
        .post(format!("{base}/diag/api/diagnoses"))
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

/// The GitHub token to upload with, from the first place that has one.
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
    bail!("no GitHub token to upload with: pass --token, set $GITHUB_TOKEN, or run `gh auth login`")
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
