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

/// Downloads `url` to `out` and checks its sha256 (NET-155). This is the
/// body of the fetch process inside a build box, so it follows redirects and
/// resolves names in the namespace it runs in, and it holds no cache.
///
/// # Errors
///
/// A connection or read failure, a non-success status, a hash mismatch, or a
/// failed write of `out`.
pub async fn fetch_to_file(url: &str, sha256: &str, out: &Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(FETCH_READ_TIMEOUT)
        .build()?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| connect_failure(e, CONNECT_TIMEOUT))?
        .error_for_status()?;
    let mut file = File::create(out)?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = response.chunk().await? {
        hasher.update(&chunk);
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    let got = hex::encode(hasher.finalize());
    anyhow::ensure!(
        got == sha256,
        "the hash is {got}, and {sha256} was declared"
    );
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
