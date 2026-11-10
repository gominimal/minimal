use crate::fetchers::{FetchBackend, GcsUrl, ReqwestUrl};
use crate::file_cache;
use crate::file_cache::CachingDownloader;
use anyhow::Result;
use google_cloud_storage::client::Storage;
use ot::OpTracker;

use std::fs::File;
use std::path::{Path, PathBuf};

/// How long a download waits for one connection to open.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// [`Storage`], with a bound on the wait for the first answer to a read. The
/// client has no connect bound of its own. Rules that drop packets leave each
/// attempt waiting for the kernel's retry limit, and it retries for minutes.
/// The bound ends with the first answer, so it does not limit a long download.
#[derive(Debug)]
struct BoundedStorage<'a> {
    storage: &'a Storage,
    bound: std::time::Duration,
}

impl FetchBackend for BoundedStorage<'_> {
    type Url = GcsUrl;
    type Request = <Storage as FetchBackend>::Request;
    type Response = <Storage as FetchBackend>::Response;

    fn get(&self, url: GcsUrl) -> Result<Self::Request, google_cloud_storage::Error> {
        self.storage.get(url)
    }

    async fn execute(
        &self,
        req: Self::Request,
    ) -> Result<Self::Response, google_cloud_storage::Error> {
        tokio::time::timeout(self.bound, self.storage.execute(req))
            .await
            .unwrap_or_else(|elapsed| Err(google_cloud_storage::Error::timeout(elapsed)))
    }
}

#[derive(Debug, Clone)]
pub struct RemoteStorage {
    client: Storage,
    cache: file_cache::FileCache,
}

impl RemoteStorage {
    #[tracing::instrument]
    pub async fn new(cache_dir: PathBuf, with_gcloud_auth: bool) -> Result<Self> {
        Self::new_with_offline(cache_dir, with_gcloud_auth, false).await
    }

    /// Same as [Self::new], but with an `offline` flag. When `offline=true`, any cache
    /// miss surfaces as an error rather than a silent network fetch — see
    /// [`file_cache::FileCacheError::OfflineCacheMiss`]. Pair with `--no-fetch` so the
    /// flag means "I am offline; use only what's cached" end-to-end.
    #[tracing::instrument]
    pub async fn new_with_offline(
        cache_dir: PathBuf,
        with_gcloud_auth: bool,
        offline: bool,
    ) -> Result<Self> {
        let cache = file_cache::FileCache::new_with_offline(cache_dir, offline)?;

        let client = if with_gcloud_auth {
            Storage::builder().build().await?
        } else {
            Storage::builder()
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await?
        };
        Ok(Self { client, cache })
    }

    /// Returns the cached copy of `url`, or downloads it, after the sha256
    /// check.
    #[tracing::instrument]
    pub async fn download_web_with_verification_and_caching(
        &self,
        url: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        self.download_web_within(CONNECT_TIMEOUT, url, sha256, op)
            .await
    }

    /// [`download_web_with_verification_and_caching`](Self::download_web_with_verification_and_caching),
    /// failing when a connection does not open within `bound`.
    async fn download_web_within(
        &self,
        bound: std::time::Duration,
        url: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        // Rules that drop packets, not reject them, leave a connect waiting
        // for the kernel's retry limit, once per address the name answered.
        // This bound covers every address of one connection.
        //
        // reqwest applies the bound twice. It wraps the whole connect, name
        // lookup and TLS included, which is what holds the overall bound.
        // It also passes the bound to hyper-util's connector, which divides
        // it evenly by the number of addresses the name answered
        // (`ConnectingTcpRemote::new`, hyper-util 0.1.20). The connector
        // carries no unused time forward, so an address after one that
        // refused at once still gets only its even share.
        let client = reqwest::Client::builder().connect_timeout(bound).build()?;
        let backend = (&client, &self.cache);
        backend
            .download(ReqwestUrl::try_from(url)?, sha256, op)
            .await
            .map_err(|e| match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => connect_failure(e, bound),
            })
    }

    /// The cached copy of the source named `filename`, if the cache holds
    /// one with this hash. In offline mode a miss is an error, as it is for
    /// a download.
    pub fn cached(&self, filename: &str, sha256: &str) -> Result<Option<PathBuf>> {
        let cached = self.cache.read_cached(filename, sha256)?;
        if cached.is_none() && self.cache.is_offline() {
            return Err(file_cache::FileCacheError::OfflineCacheMiss {
                sha256: sha256.to_string(),
                filename: filename.to_string(),
            }
            .into());
        }
        Ok(cached)
    }

    /// Moves the file at `from` into the cache under `filename`, after the
    /// sha256 check. A build box fetched it (NET-155), so the check here is
    /// the one the daemon relies on.
    pub fn adopt(&self, filename: &str, sha256: &str, from: &Path) -> Result<PathBuf> {
        Ok(self.cache.adopt(filename, sha256, from)?)
    }

    #[tracing::instrument]
    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        self.download_gcs_within(CONNECT_TIMEOUT, bucket_id, file, sha256, op)
            .await
    }

    /// [`download_with_verification_and_caching`](Self::download_with_verification_and_caching),
    /// failing when no first answer comes within `bound`.
    async fn download_gcs_within(
        &self,
        bound: std::time::Duration,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        let storage = BoundedStorage {
            storage: &self.client,
            bound,
        };
        let backend = (&storage, &self.cache);
        backend
            .download(
                GcsUrl {
                    bucket: format!("projects/_/buckets/{bucket_id}"),
                    object: file.to_string(),
                },
                sha256,
                op,
            )
            .await
            .map_err(|e| match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => gcs_failure(e, bound),
            })
    }

    #[tracing::instrument(skip(file))]
    pub async fn upload(&self, bucket_id: &str, file_path: &str, file: File) -> Result<()> {
        let _response = self
            .client
            .write_object(
                format!("projects/_/buckets/{bucket_id}"),
                file_path,
                tokio::fs::File::from_std(file),
            )
            .send_buffered()
            .await?;

        Ok(())
    }
}

/// A `gs://` download's error. When [`BoundedStorage`] ended the wait at
/// `bound`, the error names the host and the bound the way a web download's
/// does. The storage client's own timeouts carry a different source and are
/// unchanged, as is any other error.
fn gcs_failure(e: google_cloud_storage::Error, bound: std::time::Duration) -> anyhow::Error {
    let unanswered = std::error::Error::source(&e)
        .is_some_and(|source| source.is::<tokio::time::error::Elapsed>());
    if unanswered {
        anyhow::Error::from(e).context(format!(
            "could not connect to {GCS_HOST}:443: no answer after {bound:?}"
        ))
    } else {
        anyhow::Error::from(e)
    }
}

/// A web download's error, naming the host it could not connect to
/// (NET-155). The URL on the error is the request's last, so a redirect
/// names the host it sent the download to. `bound` is the connect timeout
/// the client was built with. Any other error is unchanged.
fn connect_failure(e: reqwest::Error, bound: std::time::Duration) -> anyhow::Error {
    let target = e
        .url()
        .and_then(|url| Some((url.host_str()?.to_string(), url.port_or_known_default()?)));
    match target {
        Some((host, port)) if e.is_connect() => {
            let why = if e.is_timeout() {
                format!("no answer after {bound:?}")
            } else {
                let mut cause: &dyn std::error::Error = &e;
                while let Some(next) = cause.source() {
                    cause = next;
                }
                cause.to_string()
            };
            anyhow::Error::from(e).context(format!("could not connect to {host}:{port}: {why}"))
        }
        _ => anyhow::Error::from(e),
    }
}

/// The host every `gs://` source is read from: the Google Cloud Storage
/// client's endpoint. The source's URL names a bucket, not a host. A build
/// box fetches from it, and its egress rules name it (NET-155, NET-167).
pub const GCS_HOST: &str = "storage.googleapis.com";

/// What a build box's fetch says when the egress rules it runs under do not
/// allow a host. Nothing leaves for that host, not even a name query.
pub const RULES_REFUSE: &str = "the egress rules do not allow this host";

/// What a build box's fetch says when the box it runs for has no network.
pub const NO_NETWORK: &str = "the box has no network";

/// The `https` URL of an object in a Cloud Storage bucket, which a build box
/// fetches anonymously, as [`RemoteStorage`] reads a `gs://` source. The
/// object's file name stays the last path segment, so the download cache
/// keeps one entry for either kind of read.
pub fn gcs_object_url(bucket: &str, object: &str) -> Result<String> {
    let mut url = url::Url::parse(&format!("https://{GCS_HOST}/"))?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("{GCS_HOST} takes no path"))?
        .pop_if_empty()
        .push(bucket)
        .extend(object.trim_start_matches('/').split('/'));
    Ok(url.into())
}

/// How many redirects of one source [`source_hosts`] follows.
const MAX_REDIRECTS: usize = 10;

/// How long one redirect probe waits for a response's head.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long [`source_hosts`] follows redirects in all. A build waits on it to
/// open its grant, and gives up on the answer at 60 seconds.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The hosts a build box's fetch of `sources` reaches (NET-167): each declared
/// host, and each host those sources redirect to now. This is the one place
/// that decides what a redirect widens. It reads response heads only. A hop it
/// cannot reach adds nothing: the fetch then fails and names that host.
pub async fn source_hosts(sources: &[String]) -> std::collections::BTreeSet<String> {
    let probe = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build();
    let mut hosts = std::collections::BTreeSet::new();
    let started = std::time::Instant::now();
    for source in sources {
        let Ok(mut at) = reqwest::Url::parse(source) else {
            continue;
        };
        hosts.extend(at.host_str().map(str::to_ascii_lowercase));
        let Ok(probe) = &probe else { continue };
        for _ in 0..MAX_REDIRECTS {
            if started.elapsed() >= PROBE_BUDGET {
                break;
            }
            let Ok(response) = probe.get(at.clone()).send().await else {
                break;
            };
            let next = response
                .status()
                .is_redirection()
                .then(|| response.headers().get(reqwest::header::LOCATION).cloned())
                .flatten()
                .and_then(|location| at.join(location.to_str().ok()?).ok());
            // Dropping the response closes the connection, so no body is read.
            drop(response);
            let Some(next) = next else { break };
            hosts.extend(next.host_str().map(str::to_ascii_lowercase));
            at = next;
        }
    }
    hosts
}

/// How long a build box's fetch waits between two reads of a body.
const FETCH_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How many times a build box's fetch retries a transient failure, the first
/// attempt not counted. It is the remote cache's default
/// (`rcache::DEFAULT_FETCH_RETRIES`).
const FETCH_RETRIES: u32 = 3;

/// How long a build box's fetch waits before its first retry. The wait
/// doubles before each retry after it, as the remote cache's does.
const FETCH_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(500);

/// Downloads `url` to `out` and checks its sha256 (NET-155). This is the
/// body of the fetch process inside a build box, so it follows redirects and
/// resolves names in the namespace it runs in, and it holds no cache.
///
/// A failure after the connection opened, a server error or a 429 status,
/// or a body cut off is retried up to [`FETCH_RETRIES`] times, with a
/// doubling wait between tries. A connection that is refused or gets no
/// answer, a name that does not resolve, any other status, and a hash
/// mismatch fail at once: retrying them gives the same answer later.
///
/// # Errors
///
/// A connection or read failure, a non-success status, a hash mismatch, or a
/// failed write of `out`. After retries, the last attempt's error.
pub async fn fetch_to_file(url: &str, sha256: &str, out: &Path) -> Result<()> {
    let client = fetch_client(CONNECT_TIMEOUT)?;
    retrying_transient(FETCH_RETRIES, FETCH_BACKOFF_BASE, || {
        fetch_once(&client, CONNECT_TIMEOUT, url, sha256, out)
    })
    .await
}

/// The client of a build box's fetch, whose connections open within `bound`.
fn fetch_client(bound: std::time::Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(bound)
        .read_timeout(FETCH_READ_TIMEOUT)
        .build()?)
}

/// How one attempt of a build box's fetch failed.
#[derive(Debug)]
enum FetchAttempt {
    /// A failure another attempt may not meet.
    Transient(anyhow::Error),
    /// A failure every attempt would meet.
    Final(anyhow::Error),
}

/// Runs `once` until it succeeds, fails with [`FetchAttempt::Final`], or has
/// failed `retries` times more than its first attempt. The wait before a
/// retry is `backoff`, doubled for each retry before it.
async fn retrying_transient<Fut>(
    retries: u32,
    backoff: std::time::Duration,
    mut once: impl FnMut() -> Fut,
) -> Result<()>
where
    Fut: std::future::Future<Output = Result<(), FetchAttempt>>,
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match once().await {
            Ok(()) => return Ok(()),
            Err(FetchAttempt::Transient(_)) if attempt <= retries => {
                tokio::time::sleep(backoff * 2u32.pow(attempt - 1)).await;
            }
            Err(FetchAttempt::Transient(e) | FetchAttempt::Final(e)) => return Err(e),
        }
    }
}

/// One attempt of [`fetch_to_file`].
async fn fetch_once(
    client: &reqwest::Client,
    bound: std::time::Duration,
    url: &str,
    sha256: &str,
    out: &Path,
) -> Result<(), FetchAttempt> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let fail = |e: anyhow::Error| FetchAttempt::Final(e);
    let response = client.get(url).send().await.map_err(|e| {
        // A connect failure covers a refusal, no answer within `bound`, and
        // a name the namespace's resolver does not answer, the rules'
        // refusal included. A bad URL or a redirect loop stays bad.
        if e.is_connect() || e.is_builder() || e.is_redirect() {
            FetchAttempt::Final(connect_failure(e, bound))
        } else {
            FetchAttempt::Transient(e.into())
        }
    })?;
    let status = response.status();
    let mut response = response.error_for_status().map_err(|e| {
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            FetchAttempt::Transient(e.into())
        } else {
            FetchAttempt::Final(e.into())
        }
    })?;
    let mut file = File::create(out).map_err(|e| fail(e.into()))?;
    let mut hasher = Sha256::new();
    // A read that fails is a connection reset or a body cut off.
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| FetchAttempt::Transient(e.into()))?
    {
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|e| fail(e.into()))?;
    }
    file.sync_all().map_err(|e| fail(e.into()))?;
    let got = hex::encode(hasher.finalize());
    if got != sha256 {
        return Err(fail(anyhow::anyhow!(
            "the hash is {got}, and {sha256} was declared"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-155: a `gs://` source is the public object at
    /// `storage.googleapis.com`, under the cache name the client's read
    /// would give it.
    #[test]
    fn a_gs_object_becomes_a_url_on_the_cloud_storage_host() {
        use crate::fetchers::FetchUrl as _;
        let url = gcs_object_url("minimal-staging-archives", "a/b/zsh-5.9.2.tar.xz").unwrap();
        assert_eq!(
            url,
            "https://storage.googleapis.com/minimal-staging-archives/a/b/zsh-5.9.2.tar.xz"
        );
        assert_eq!(
            ReqwestUrl::try_from(url.as_str()).unwrap().filename(),
            GcsUrl {
                bucket: String::new(),
                object: "a/b/zsh-5.9.2.tar.xz".to_string(),
            }
            .filename()
        );
        assert_eq!(
            gcs_object_url("b", "/with space/100%.tar").unwrap(),
            "https://storage.googleapis.com/b/with%20space/100%25.tar"
        );
    }
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    const SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A download that could not connect names the host and the socket's
    /// reason, in the text the daemon reads the host from.
    #[tokio::test]
    async fn a_failed_connect_names_the_host() {
        let closed = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let tmp = tempfile::tempdir().unwrap();
        let storage = RemoteStorage::new(tmp.path().to_path_buf(), false)
            .await
            .unwrap();

        let e = storage
            .download_web_with_verification_and_caching(
                &format!("http://{addr}/pkg.tar.gz"),
                SHA,
                &OpTracker::new_root(),
            )
            .await
            .expect_err("the port is closed");
        let text = e.to_string();
        assert!(
            text.starts_with(&format!("could not connect to {addr}: ")),
            "{text}"
        );
    }

    /// NET-167: a source's hosts are its own and each host it redirects to.
    /// The source is at a literal address and redirects to a name, so the
    /// two hosts differ on one listener.
    #[tokio::test]
    async fn source_redirect_hosts_join_the_build_box_egress() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for location in [format!("http://localhost:{port}/two"), String::new()] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                let response = if location.is_empty() {
                    "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\
                         connection: close\r\n\r\n"
                    )
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let hosts = source_hosts(&[format!("http://127.0.0.1:{port}/one")]).await;
        assert_eq!(
            hosts.into_iter().collect::<Vec<_>>(),
            ["127.0.0.1", "localhost"]
        );
    }

    /// A build box's fetch that could not connect names the host the same way.
    #[tokio::test]
    async fn a_failed_build_box_fetch_names_the_host() {
        let closed = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let tmp = tempfile::tempdir().unwrap();

        let e = fetch_to_file(
            &format!("http://{addr}/pkg.tar.gz"),
            SHA,
            &tmp.path().join("fetched"),
        )
        .await
        .expect_err("the port is closed");
        let text = e.to_string();
        assert!(
            text.starts_with(&format!("could not connect to {addr}: ")),
            "{text}"
        );
    }

    /// A server that answers its `n`th connection with `replies[n]`, or the
    /// last reply once they run out, and closes it. Returns its address and
    /// the count of connections it took.
    async fn scripted_server(
        replies: Vec<Vec<u8>>,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let taken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = taken.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let reply = replies[n.min(replies.len() - 1)].clone();
                let mut request = [0u8; 2048];
                let served = async {
                    if stream.read(&mut request).await? == 0 {
                        return Ok(());
                    }
                    stream.write_all(&reply).await?;
                    stream.shutdown().await
                };
                // A client that hangs up first ends its connection early. The
                // tests check the count of connections taken, not this.
                if let Err(e) = served.await {
                    eprintln!("a scripted connection ended early: {e}");
                }
            }
        });
        (addr, taken)
    }

    /// An HTTP reply with `status`, whose head declares `length` bytes of
    /// body and whose body is `body`.
    fn reply(status: &str, length: usize, body: &[u8]) -> Vec<u8> {
        let mut reply =
            format!("HTTP/1.1 {status}\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n")
                .into_bytes();
        reply.extend_from_slice(body);
        reply
    }

    fn sha256_hex(body: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(body))
    }

    /// NET-155: a server error and a body cut off are transient, so the
    /// fetch tries again and succeeds on the third connection.
    #[tokio::test]
    async fn a_transient_fetch_failure_is_retried_until_it_succeeds() {
        let body = b"the source".to_vec();
        let (addr, taken) = scripted_server(vec![
            reply("503 Service Unavailable", 0, b""),
            reply("200 OK", body.len(), &body[..3]),
            reply("200 OK", body.len(), &body),
        ])
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("fetched");
        let client = fetch_client(CONNECT_TIMEOUT).unwrap();
        let url = format!("http://{addr}/pkg.tar.gz");
        let sha = sha256_hex(&body);

        retrying_transient(3, std::time::Duration::from_millis(10), || {
            fetch_once(&client, CONNECT_TIMEOUT, &url, &sha, &out)
        })
        .await
        .expect("the third attempt succeeds");

        assert_eq!(taken.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(std::fs::read(&out).unwrap(), body);
    }

    /// NET-155: a server error on every attempt gives up after the retries,
    /// with the last attempt's error.
    #[tokio::test]
    async fn a_persistent_server_error_gives_up_after_the_retries() {
        let (addr, taken) = scripted_server(vec![
            reply("500 Internal Server Error", 0, b""),
            reply("502 Bad Gateway", 0, b""),
            reply("429 Too Many Requests", 0, b""),
            reply("503 Service Unavailable", 0, b""),
        ])
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("fetched");
        let client = fetch_client(CONNECT_TIMEOUT).unwrap();
        let url = format!("http://{addr}/pkg.tar.gz");

        let e = retrying_transient(3, std::time::Duration::from_millis(10), || {
            fetch_once(&client, CONNECT_TIMEOUT, &url, SHA, &out)
        })
        .await
        .expect_err("every attempt fails");

        assert_eq!(taken.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert!(e.to_string().contains("503 Service Unavailable"), "{e}");
    }

    /// NET-155: a client error status and a hash mismatch fail the first
    /// attempt: another attempt would get the same answer.
    #[tokio::test]
    async fn a_client_error_or_a_hash_mismatch_is_not_retried() {
        let backoff = std::time::Duration::from_secs(30);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("fetched");
        let client = fetch_client(CONNECT_TIMEOUT).unwrap();
        for (status, body) in [("404 Not Found", &b""[..]), ("200 OK", &b"other bytes"[..])] {
            let (addr, taken) = scripted_server(vec![reply(status, body.len(), body)]).await;
            let url = format!("http://{addr}/pkg.tar.gz");
            let started = std::time::Instant::now();

            retrying_transient(3, backoff, || {
                fetch_once(&client, CONNECT_TIMEOUT, &url, SHA, &out)
            })
            .await
            .expect_err("the attempt fails");

            assert_eq!(
                taken.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{status}"
            );
            assert!(started.elapsed() < backoff, "{status}");
        }
    }

    /// NET-155: a refused connection fails at once, with no retry, so a
    /// source the box's rules refuse fails its build in seconds.
    #[tokio::test]
    async fn a_refused_connect_is_not_retried() {
        let closed = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("fetched");
        let client = fetch_client(CONNECT_TIMEOUT).unwrap();
        let url = format!("http://{addr}/pkg.tar.gz");
        let backoff = std::time::Duration::from_secs(30);
        let attempts = std::sync::atomic::AtomicU32::new(0);

        let started = std::time::Instant::now();
        let e = retrying_transient(3, backoff, || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fetch_once(&client, CONNECT_TIMEOUT, &url, SHA, &out)
        })
        .await
        .expect_err("the port is closed");

        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(started.elapsed() < backoff);
        assert!(
            e.to_string()
                .starts_with(&format!("could not connect to {addr}: ")),
            "{e}"
        );
    }

    /// NET-155: a connection that gets no answer fails at its bound, with no
    /// retry.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_unanswered_connect_is_not_retried() {
        let (addr, _held, _listener) = dropping_port().await;
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("fetched");
        let bound = std::time::Duration::from_millis(300);
        let client = fetch_client(bound).unwrap();
        let url = format!("http://{addr}/pkg.tar.gz");
        let backoff = std::time::Duration::from_secs(30);
        let attempts = std::sync::atomic::AtomicU32::new(0);

        let started = std::time::Instant::now();
        let e = retrying_transient(3, backoff, || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            fetch_once(&client, bound, &url, SHA, &out)
        })
        .await
        .expect_err("the address drops every packet");
        let took = started.elapsed();

        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(took < bound * 2, "took {took:?}");
        assert_eq!(
            e.to_string(),
            format!("could not connect to {addr}: no answer after 300ms")
        );
    }

    /// A `gs://` source whose host gives no answer fails at the bound, and
    /// names the host. The listener takes the connection and never answers.
    #[tokio::test]
    async fn a_gs_source_fails_when_no_answer_comes() {
        let silent = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = silent.local_addr().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let storage = RemoteStorage {
            client: Storage::builder()
                .with_endpoint(format!("http://{addr}"))
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await
                .unwrap(),
            cache: file_cache::FileCache::new_with_offline(tmp.path().to_path_buf(), false)
                .unwrap(),
        };

        let bound = std::time::Duration::from_millis(200);
        let e = storage
            .download_gcs_within(
                bound,
                "bucket".to_string(),
                "pkg.tar.gz",
                SHA,
                &OpTracker::new_root(),
            )
            .await
            .expect_err("no answer comes");
        assert_eq!(
            e.to_string(),
            "could not connect to storage.googleapis.com:443: no answer after 200ms"
        );
    }

    /// Only the bound's own timeout reads as no answer. A timeout the storage
    /// client reports keeps its own text.
    #[tokio::test]
    async fn only_the_bounds_timeout_reads_as_no_answer() {
        let bound = std::time::Duration::from_millis(200);
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("the future never completes");

        let ours = gcs_failure(google_cloud_storage::Error::timeout(elapsed), bound);
        assert_eq!(
            ours.to_string(),
            "could not connect to storage.googleapis.com:443: no answer after 200ms"
        );

        let clients = google_cloud_storage::Error::timeout("the client's own deadline");
        let text = clients.to_string();
        assert_eq!(gcs_failure(clients, bound).to_string(), text);
    }

    /// A loopback port whose accept queue is full, so the kernel drops
    /// every new SYN to it, as egress rules that drop packets do.
    #[cfg(target_os = "linux")]
    pub(super) async fn dropping_port() -> (
        std::net::SocketAddr,
        Vec<tokio::net::TcpStream>,
        tokio::net::TcpListener,
    ) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
            .unwrap();
        let listener = socket.listen(0).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut held = Vec::new();
        loop {
            let attempt = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                tokio::net::TcpStream::connect(addr),
            )
            .await;
            match attempt {
                Ok(Ok(stream)) => held.push(stream),
                _ => break,
            }
            assert!(held.len() < 64, "the accept queue never filled");
        }
        (addr, held, listener)
    }

    /// A download whose connect gets no answer fails at its bound, not at
    /// the kernel's retry limit, and names the address and the bound.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_unplaced_connect_to_a_dropping_address_times_out() {
        let (addr, _held, _listener) = dropping_port().await;
        let tmp = tempfile::tempdir().unwrap();
        let storage = RemoteStorage::new(tmp.path().to_path_buf(), false)
            .await
            .unwrap();
        let bound = std::time::Duration::from_millis(300);

        let started = std::time::Instant::now();
        let e = storage
            .download_web_within(
                bound,
                &format!("http://{addr}/pkg.tar.gz"),
                SHA,
                &OpTracker::new_root(),
            )
            .await
            .expect_err("the address drops every packet");
        let took = started.elapsed();

        assert_eq!(
            e.to_string(),
            format!("could not connect to {addr}: no answer after 300ms")
        );
        assert!(took < bound * 2, "took {took:?}");
    }
}
