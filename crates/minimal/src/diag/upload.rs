//! Handing a bundle to the diag portal.
//!
//! The portal takes a `min bug` bundle and keeps it for the minimal team. It
//! does not diagnose it on arrival: someone signs in on the report page and
//! starts the diagnosis there, and that sign-in is what names the account
//! the diagnosis is charged to. So the upload carries no credential at all.
//! A developer's GitHub token usually reaches far beyond what reporting a bug
//! needs, and it is not this command's to hand over.
//!
//! Upload is two requests. That is the portal's contract, not a choice made
//! here: a create that declares the bundle's name, length and hash, then the
//! bytes. It is the better shape for this end too, because the refusals that
//! matter — a spent allowance, an oversized bundle — land on the first
//! request, so being turned away costs a round trip instead of the whole
//! upload.
//!
//! The create hands back a delete token beside the diagnosis id. That token
//! is how the uploader takes the bundle back before it expires: see
//! [`delete`].

use std::path::Path;
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

/// How long the portal keeps a bundle, as the sentence printed after an
/// upload states it. The portal's `expires_at` is the authority on the date.
const RETENTION_DAYS: u32 = 7;

/// A bundle the portal took.
#[derive(Debug)]
pub struct Uploaded {
    /// What the portal calls the diagnosis.
    pub id: String,
    /// The page a person opens to start the diagnosis and read its report.
    pub report_url: String,
    /// The capability to delete the bundle before it expires. Printed once,
    /// in the delete command, and never put in the report URL: that URL is
    /// the thing people share.
    pub delete_token: String,
    /// When the portal deletes the bundle on its own, as the portal said it.
    pub expires_at: Option<String>,
}

impl Uploaded {
    /// The lines printed after an upload, in order.
    ///
    /// Plain about where the bundle went and what happens to it next, because
    /// the upload no longer asks for anything that would make that obvious.
    pub fn receipt(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Report:  {}", self.report_url),
            format!(
                "The bundle is stored for the minimal team for {RETENTION_DAYS} days. It is not \
                 diagnosed until someone signs in at the report URL and starts the diagnosis."
            ),
        ];
        if let Some(expires_at) = &self.expires_at {
            lines.push(format!("Expires: {}", expiry(expires_at)));
        }
        lines.push(format!(
            "Delete:  min diag delete {} {}",
            self.id, self.delete_token
        ));
        lines
    }
}

/// The portal's expiry, as a date a person reads.
///
/// RFC 3339 is shown in UTC to the minute; anything else is shown as the
/// portal sent it rather than guessed at.
fn expiry(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw).map_or_else(
        |_| raw.to_owned(),
        |t| {
            t.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d %H:%M UTC")
                .to_string()
        },
    )
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
/// does not bound a stalled write, so every request below carries an overall
/// deadline as well.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Overall deadline for the create and delete requests, which carry no
/// bundle.
const CREATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall deadline for the request that carries the bundle.
///
/// Generous, because it has to cover [`MAX_BUNDLE_BYTES`] over a slow link
/// and cutting off an upload that is merely slow would be the worse failure.
/// It is here so that a peer which accepts the connection and then stops
/// reading is bounded at all: neither the connect nor the read deadline
/// covers a write that never drains.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Sends a bundle and returns where its diagnosis can be started.
///
/// The bundle is read whole, which is sound because [`MAX_BUNDLE_BYTES`] is
/// checked against the file's length first. A stream would buy nothing after
/// that: the create request declares the exact byte count and sha256 up front,
/// and computing those means reading every byte regardless.
pub async fn upload(path: &Path, endpoint: &str, note: &str) -> Result<Uploaded, anyhow::Error> {
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

    let client = client(local_only)?;

    let created = client
        .post(format!("{base}/diag/api/diagnoses"))
        .timeout(CREATE_TIMEOUT)
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
    let delete_token = created["delete_token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .context("the portal took the bundle but did not say how to delete it")?
        .to_owned();
    let expires_at = match &created["expires_at"] {
        Value::String(t) => Some(t.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    };

    let sent = client
        .put(format!("{base}{put_path}"))
        .timeout(UPLOAD_TIMEOUT)
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
        id,
        delete_token,
        expires_at,
    })
}

/// Deletes a bundle before it expires, with the token its upload printed.
///
/// The portal deletes the bundle and anything derived from it. Its three
/// answers are told apart here because they mean different things to the
/// person who asked: gone, not there (any more), or not theirs to delete.
pub async fn delete(endpoint: &str, id: &str, delete_token: &str) -> Result<(), anyhow::Error> {
    let (base, local_only) = checked_base(endpoint)?;
    // The id becomes a path segment; anything that would change the path is
    // not an id the portal handed out.
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("`{id}` is not a diagnosis id");
    }
    let answered = client(local_only)?
        .delete(format!("{base}/diag/api/diagnoses/{id}"))
        .timeout(CREATE_TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "delete_token": delete_token }).to_string())
        .send()
        .await
        .with_context(|| format!("asking {base} to delete {id}"))?;
    let status = answered.status();
    match status {
        reqwest::StatusCode::NO_CONTENT => Ok(()),
        reqwest::StatusCode::NOT_FOUND => bail!(
            "{base} has no bundle {id}: it was never uploaded, has expired, or was already deleted"
        ),
        reqwest::StatusCode::FORBIDDEN => {
            bail!("{base} refused to delete {id}: that is not its delete token")
        }
        _ => {
            let body = answered.text().await.unwrap_or_default();
            bail!("{base} did not delete {id} ({status}): {}", refusal(&body))
        }
    }
}

/// The client every request to the portal goes through.
///
/// Redirects are not followed. Keeping the bundle on the host the operator
/// named is the point of joining the portal's path to the base rather than
/// following whatever URL it returns, and a 3xx would walk straight around
/// that: reqwest follows up to ten by default, to any host. A portal that
/// wants the bytes elsewhere can say so in the path it hands back.
fn client(local_only: bool) -> Result<reqwest::Client, anyhow::Error> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);
    // The loopback exception is only sound if the request actually stays on
    // the machine. reqwest honours HTTP_PROXY by default, so without this a
    // proxy in the environment would carry the bundle off the host through
    // the very case that was allowed for being local.
    if local_only {
        builder = builder.no_proxy();
    }
    builder.build().context("building the HTTP client")
}

/// The endpoint to talk to, and whether the client must refuse proxies.
///
/// The upload carries a machine's diagnostics and the delete carries the
/// token that removes them, so the scheme is the caller's to get wrong and
/// this function's to refuse. Plain HTTP is allowed only to a loopback host,
/// which is how the portal is served while it is being worked on; anything
/// else must be HTTPS, because neither goes on the wire in clear. Checked
/// before the bundle is read, for the same reason the length is: a refusal
/// should not cost a file read.
///
/// The trailing slash is trimmed here too, so the URLs built from it cannot
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
            bail!(
                "{base} is plain http, and a bundle or delete token does not go on the wire in \
                 clear; name an https portal"
            )
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    /// One request as the stand-in portal received it.
    #[derive(Debug)]
    struct Seen {
        method: String,
        path: String,
        /// Header names lowercased.
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// A loopback portal that answers each connection with the next canned
    /// `(status, body)` and records what it was sent.
    ///
    /// Every answer closes its connection, so one request is one connection
    /// and the order of `answers` is the order of requests.
    async fn portal(
        answers: Vec<(u16, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<Seen>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let mut seen = Vec::new();
            for (status, body) in answers {
                let (mut conn, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    let n = conn.read(&mut buf).await.unwrap();
                    assert!(n > 0, "the client hung up mid-request");
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
                let mut lines = head.split("\r\n");
                let mut start = lines.next().unwrap().split(' ');
                let method = start.next().unwrap().to_owned();
                let path = start.next().unwrap().to_owned();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
                    .collect();
                let length: usize = headers
                    .iter()
                    .find(|(n, _)| n == "content-length")
                    .map_or(0, |(_, v)| v.parse().unwrap());
                while raw.len() < head_end + length {
                    let n = conn.read(&mut buf).await.unwrap();
                    assert!(n > 0, "the client hung up mid-body");
                    raw.extend_from_slice(&buf[..n]);
                }
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                conn.write_all(response.as_bytes()).await.unwrap();
                conn.shutdown().await.ok();
                seen.push(Seen {
                    method,
                    path,
                    headers,
                    body: raw[head_end..head_end + length].to_vec(),
                });
            }
            seen
        });
        (base, served)
    }

    /// The whole upload exchange against a stand-in portal: no credential on
    /// either request, the bundle declared and then sent as declared, and the
    /// receipt naming the report URL and the delete command the portal's
    /// answer implies.
    #[tokio::test]
    async fn an_upload_sends_no_credential_and_prints_the_url_and_delete_command() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("minimal-diag-x.tar.zst");
        let bundle = b"\x28\xb5\x2f\xfdnot really zstd".to_vec();
        tokio::fs::write(&path, &bundle).await.unwrap();

        let (base, served) = portal(vec![
            (
                201,
                r#"{"id":"d-123","upload":"/diag/api/diagnoses/d-123/bundle","delete_token":"tok-xyz","expires_at":"2026-10-16T12:00:00Z"}"#,
            ),
            (202, r#"{"id":"d-123","state":"stored"}"#),
        ])
        .await;

        let uploaded = upload(&path, &base, "min up hangs").await.unwrap();
        let seen = served.await.unwrap();
        let base = base.trim_end_matches('/');

        for request in &seen {
            assert_eq!(
                request.header("authorization"),
                None,
                "{} {} carried a credential",
                request.method,
                request.path
            );
        }

        let create = &seen[0];
        assert_eq!(
            (create.method.as_str(), create.path.as_str()),
            ("POST", "/diag/api/diagnoses")
        );
        let declared: Value = serde_json_lenient::from_slice(&create.body).unwrap();
        assert_eq!(declared["name"], "minimal-diag-x.tar.zst");
        assert_eq!(declared["bytes"], bundle.len());
        assert_eq!(declared["sha256"], hex::encode(Sha256::digest(&bundle)));
        assert_eq!(declared["context"], "min up hangs");

        let put = &seen[1];
        assert_eq!(
            (put.method.as_str(), put.path.as_str()),
            ("PUT", "/diag/api/diagnoses/d-123/bundle")
        );
        assert_eq!(put.body, bundle);

        let receipt = uploaded.receipt();
        assert_eq!(receipt[0], format!("Report:  {base}/diag/d-123"));
        assert!(
            receipt[1].contains("stored for the minimal team for 7 days")
                && receipt[1].contains("not diagnosed until someone signs in"),
            "{}",
            receipt[1]
        );
        assert_eq!(receipt[2], "Expires: 2026-10-16 12:00 UTC");
        assert_eq!(receipt[3], "Delete:  min diag delete d-123 tok-xyz");
        // The delete token is printed once, in the command, and kept out of
        // the URL that gets shared.
        assert!(!receipt[0].contains("tok-xyz"));
    }

    /// The delete sends the token in the body and nothing in a header, and
    /// each of the portal's three answers reads as what it means.
    #[tokio::test]
    async fn a_delete_reports_each_answer_plainly() {
        let (base, served) = portal(vec![
            (204, ""),
            (403, r#"{"error":"forbidden"}"#),
            (404, r#"{"error":"not found"}"#),
        ])
        .await;

        delete(&base, "d-123", "tok-xyz").await.unwrap();
        let wrong = delete(&base, "d-123", "nope")
            .await
            .unwrap_err()
            .to_string();
        assert!(wrong.contains("not its delete token"), "{wrong}");
        let gone = delete(&base, "d-404", "tok").await.unwrap_err().to_string();
        assert!(
            gone.contains("expired") && gone.contains("already deleted"),
            "{gone}"
        );

        let seen = served.await.unwrap();
        for (request, (id, token)) in
            seen.iter()
                .zip([("d-123", "tok-xyz"), ("d-123", "nope"), ("d-404", "tok")])
        {
            assert_eq!(request.method, "DELETE");
            assert_eq!(request.path, format!("/diag/api/diagnoses/{id}"));
            assert_eq!(request.header("authorization"), None);
            let body: Value = serde_json_lenient::from_slice(&request.body).unwrap();
            assert_eq!(body, json!({ "delete_token": token }));
        }
    }

    /// An id is a path segment the portal handed out; one that would walk
    /// the path elsewhere is refused before anything is sent.
    #[tokio::test]
    async fn a_delete_refuses_an_id_that_is_not_one() {
        for id in ["", "../admin", "a/b", "a?b"] {
            let err = delete("http://127.0.0.1:1", id, "t")
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("not a diagnosis id"), "{id}: {err}");
        }
    }

    #[test]
    fn an_expiry_that_is_not_rfc3339_is_shown_as_sent() {
        assert_eq!(expiry("2026-10-16T14:00:00+02:00"), "2026-10-16 12:00 UTC");
        assert_eq!(expiry("1791892800"), "1791892800");
    }

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

    /// An endpoint that would put a bundle or a delete token on the wire in
    /// clear is refused rather than used.
    #[test]
    fn a_portal_reached_in_clear_is_refused() {
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

    /// The trailing slash is trimmed once, so the URLs built from the base
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
        let err = upload(&empty, "http://127.0.0.1:1", "")
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
        let err = upload(&huge, "http://127.0.0.1:1", "")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&MAX_BUNDLE_BYTES.to_string()),
            "the refusal must name the ceiling: {err}"
        );
    }
}
