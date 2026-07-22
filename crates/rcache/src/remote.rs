use crate::index_file::IndexFile;
use common::{SpecHash, archive};
use lcache::{Cache, LocalDir, PendingDir};
use ot::{OpTracker, Operation};
use sha2::Digest;
use std::io::{Seek, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::fetchers::*;
use google_cloud_storage::{Error as GcsError, client::Storage};
use reqwest::{Client, Error as ReqwestError};

// Writers live in `remote_writer.rs`. This module is read-only.
//
// Historical note: `upload`/`finish_uploads` used to live here on `RemoteCache<Storage>`,
// but did an unsynchronized read-modify-write on the index file, which lost entries when
// two writers raced. The bifurcation forces writers down a path that fetches the index
// generation up-front and writes with `if_generation_match` for compare-and-swap semantics.

/// An error from operations with the remote cache.
#[derive(Debug)]
pub enum Error<BE: std::fmt::Debug> {
    /// An error occurred with the fetcher backend.
    Backend(BE),
    /// An I/O error occurred.
    IO(std::io::Error),
    /// An error occurred interacting with the local cache.
    Cache(lcache::CacheErr),
    /// A remote object was not found.
    NotFound,
    /// An error occurred unpacking an archive.
    ArchiveError(archive::ArchiveError),
    /// The sha256 hash that was requested differed from what was written/downloaded.
    HashMismatch { want: String, got: String },
    /// The requested per-commit index snapshot does not exist.
    SnapshotMissing { object: String },
    /// The cache configuration could not be resolved or followed.
    Config(String),
}

impl<BE: std::fmt::Debug> std::fmt::Display for Error<BE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<BE: std::fmt::Debug> std::error::Error for Error<BE> {}

impl<BE: std::fmt::Debug> From<BE> for Error<BE> {
    fn from(backend_err: BE) -> Self {
        Self::Backend(backend_err)
    }
}

/// A source of compiled build artifacts accessible over the network. Artifacts
/// can be fetched by [SpecHash]. Read-only — for writes, see
/// [crate::RemoteCacheWriter].
#[derive(Debug, Clone)]
pub struct RemoteCache<B: FetchBackend> {
    backend: B,
    base: B::Url,
    index: IndexFile,

    #[allow(dead_code)]
    dir: Option<PathBuf>,

    ot: Option<OpTracker>,

    /// The GCS object generation of the index when it was fresh-fetched
    /// from the backend. `None` for non-GCS backends and for the
    /// local-cache load path (where we never asked GCS what generation
    /// we have). Used by [`Self::into_writer`] to skip a refetch when
    /// transitioning to a writer.
    gcs_generation: Option<i64>,
}

pub const INDEX_FILENAME: &str = "index.shisha";
const INDEX_EXPIRY_SECONDS: u64 = 5 * 60; // how long a fetch of the remote index is considered fresh for

/// Which index object a [`RemoteCache`] reader loads. The choice is made by
/// the caller (see `mfile::File::cache_config`); this layer only executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexSource {
    /// The global mutable root index (`index.shisha`). Absent (404) means an
    /// empty index: a fresh cache with nothing published yet.
    Root,
    /// An immutable per-commit snapshot object
    /// (`<host>/<owner>/<repo>/<commit>.shisha`). Absent is
    /// [`Error::SnapshotMissing`]; the caller decides whether to retry with
    /// [`IndexSource::Root`].
    Snapshot { object: String },
}

impl IndexSource {
    /// The object name to fetch, relative to the cache base URL.
    fn object(&self) -> &str {
        match self {
            IndexSource::Root => INDEX_FILENAME,
            IndexSource::Snapshot { object } => object,
        }
    }

    /// File name for the locally-cached copy of this index. Snapshots flatten
    /// the full object key so distinct snapshots never share a local file,
    /// even when different repos pin the same commit hash.
    fn local_filename(&self) -> String {
        match self {
            IndexSource::Root => INDEX_FILENAME.to_string(),
            IndexSource::Snapshot { object } => object.replace('/', "_"),
        }
    }
}

impl RemoteCache<Client> {
    /// Always reads the root index: this constructor serves writer-adjacent
    /// paths, for which the root object is authoritative.
    #[tracing::instrument(skip_all, err)]
    pub async fn new_over_https<URL: Into<ReqwestUrl>>(
        url: URL,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
    ) -> Result<Self, Error<ReqwestError>> {
        let backend = Client::builder()
            .user_agent("minimal/remote-cache")
            .build()?;
        let url = url.into();

        Self::new(backend, url, index_dir, ot, IndexSource::Root).await
    }
}

impl RemoteCache<Storage> {
    /// Instantiates a new remote cache using the given GCS client + bucket.
    /// Always reads the root index: this constructor serves writer-adjacent
    /// paths, for which the root object is authoritative.
    #[tracing::instrument(skip_all, fields(bucket_id = %bucket_id), err)]
    pub async fn new_with_gcs_bucket(
        storage: Storage,
        bucket_id: &str,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
    ) -> Result<Self, Error<GcsError>> {
        let url = GcsUrl {
            bucket: format!("projects/_/buckets/{bucket_id}"),
            object: "".to_string(),
        };

        Self::new(storage, url, index_dir, ot, IndexSource::Root).await
    }

    /// Convert this reader into a writer, reusing the already-fetched index
    /// and generation when possible. If the reader was loaded from the local
    /// cache fast path (and therefore has no recorded generation), the index
    /// is refetched from GCS so the writer's compare-and-swap commit has an
    /// authoritative generation to match against.
    #[tracing::instrument(skip_all, err)]
    pub async fn into_writer(
        self,
        ot: Option<OpTracker>,
    ) -> Result<crate::RemoteCacheWriter, Error<GcsError>> {
        let (index, generation) = match self.gcs_generation {
            Some(g) => (self.index, g),
            None => crate::remote_writer::fetch_gcs_index(&self.backend, &self.base).await?,
        };
        Ok(crate::RemoteCacheWriter::from_parts(
            self.backend,
            self.base,
            index,
            generation,
            ot,
        ))
    }
}

impl RemoteCache<AnyBackend> {
    /// Reader from an already-resolved [`AnyUrl`] — the "where to get artifacts"
    /// location. For a GCS url the caller supplies the (authed or anonymous)
    /// `Storage` client; for an HTTPS url a reqwest client is built internally
    /// and `gcs_storage` is ignored. Objects on the HTTPS path are fetched with
    /// unauthenticated GETs, so the mirror must serve them publicly.
    pub async fn new_any(
        url: AnyUrl,
        gcs_storage: Option<Storage>,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
        source: IndexSource,
    ) -> Result<Self, Error<AnyRespError>> {
        let backend = match &url {
            AnyUrl::Gcs(_) => AnyBackend::Gcs(Box::new(
                gcs_storage.expect("new_any: a GCS url requires a Storage client"),
            )),
            AnyUrl::Https(_) => {
                let client = Client::builder()
                    .user_agent("minimal/remote-cache")
                    .build()
                    .map_err(AnyRespError::Https)?;
                AnyBackend::Https(client)
            }
        };
        Self::new(backend, url, index_dir, ot, source).await
    }

    /// Convenience reader over a plain-HTTPS base-URL string (public GCS bucket
    /// URL, or an S3-compatible mirror such as a Cloudflare R2 custom domain).
    /// `url` MUST end in `/`, or [`url::Url::join`] drops its last path segment
    /// when resolving object names against it.
    #[tracing::instrument(skip_all, fields(url = %url), err)]
    pub async fn new_any_https(
        url: &str,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
        source: IndexSource,
    ) -> Result<Self, Error<AnyRespError>> {
        let parsed = reqwest::Url::parse(url).map_err(AnyRespError::InvalidUrl)?;
        Self::new_any(
            AnyUrl::Https(ReqwestUrl::from(parsed)),
            None,
            index_dir,
            ot,
            source,
        )
        .await
    }
}

impl<B: FetchBackend> RemoteCache<B> {
    /// Creates a new remote cache based on the given backend and URL, loading
    /// the index object selected by `source`.
    pub async fn new(
        backend: B,
        url: B::Url,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
        source: IndexSource,
    ) -> Result<Self, Error<<B::Response as FetchResponse>::Error>> {
        // Fast path: use the locally-cached index. The mutable root index is
        // trusted for INDEX_EXPIRY_SECONDS; snapshots are immutable, so any
        // cached copy is current.
        if let Some(id) = index_dir.as_ref() {
            let l_idx_path = id.join(source.local_filename());
            let age = std::fs::metadata(&l_idx_path)
                .and_then(|stat| stat.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok());
            let fresh = match (&source, age) {
                (IndexSource::Root, Some(elapsed)) => elapsed.as_secs() <= INDEX_EXPIRY_SECONDS,
                (IndexSource::Snapshot { .. }, Some(_)) => true,
                (_, None) => false,
            };
            if fresh {
                // A bad copy falls through to a refetch instead of wedging
                // every subsequent run on it. The wire parser reads records
                // till EOF and would silently accept a copy truncated
                // mid-record as a shorter index, so add the strictness a
                // whole file allows: its length must be a whole number of
                // records. (Truncation at an exact record boundary is
                // indistinguishable in-format; the atomic write below is the
                // guard against truncation ever landing.)
                let load = |path: &std::path::Path| -> std::io::Result<IndexFile> {
                    let mut f = std::fs::File::open(path)?;
                    if !f
                        .metadata()?
                        .len()
                        .is_multiple_of(crate::index_file::WIRE_RECORD_LEN)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "length is not a whole number of records",
                        ));
                    }
                    IndexFile::from_reader(&mut f)
                };
                match load(&l_idx_path) {
                    Ok(index) => {
                        tracing::debug!("Re-using local copy of {}", source.object());
                        return Ok(Self {
                            backend,
                            index,
                            dir: index_dir,
                            base: url,
                            ot,
                            // Loading from local cache means we never asked GCS
                            // for the current generation. into_writer must
                            // refetch.
                            gcs_generation: None,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            "local copy of {} unreadable: {e}; refetching",
                            source.object()
                        )
                    }
                }
            }
        }

        let fetch_start = Instant::now();
        let index_req = backend.get(url.join(source.object()).unwrap())?;

        let fetch_op = OpTracker::new_with_root(&ot).with_op(Operation::FetchIndex);

        // TODO: Gotta be a better way to stream it into [IndexFile].
        let mut index_resp = backend.execute(index_req).await?;
        // Capture the GCS generation, if the backend exposes one. Reads
        // need to do this before consuming chunks because the response
        // metadata may not survive the body read in some impls. Writers
        // compare-and-swap against the root index object, so a snapshot's
        // generation must never seed that path: None forces into_writer
        // to refetch the root.
        let gcs_generation = match &source {
            IndexSource::Root => index_resp.generation(),
            IndexSource::Snapshot { .. } => None,
        };
        let index = match (index_resp.status_code(), &source) {
            (404, IndexSource::Root) => IndexFile::default(),
            (404, IndexSource::Snapshot { object }) => {
                return Err(Error::SnapshotMissing {
                    object: object.clone(),
                });
            }
            // Any other error status must not fall through to body parsing:
            // an error page is not an index, and an empty error body would
            // "parse" as an empty index, masking the outage.
            (status, _) if !index_resp.is_success() => {
                return Err(match index_resp.error_for_status() {
                    Err(e) => Error::Backend(e),
                    Ok(_) => Error::IO(std::io::Error::other(format!(
                        "index fetch failed with HTTP {status}"
                    ))),
                });
            }
            _ => {
                // Progress total only; a plain-HTTPS backend may omit
                // Content-Length (chunked transfer), so don't panic on None.
                fetch_op.set_length(index_resp.content_length().unwrap_or(0));

                let mut buffer =
                    Vec::with_capacity(index_resp.content_length().unwrap_or(1024 * 1024) as usize);
                while let Some(chunk) = index_resp.chunk().await? {
                    fetch_op.increment(chunk.len() as u64);
                    buffer.extend(chunk);
                }
                fetch_op.set_done();

                let index =
                    IndexFile::from_reader(&mut std::io::Cursor::new(buffer)).map_err(Error::IO)?;

                // Best-effort local caching, via temp file + rename so a crash
                // or concurrent reader never observes a partial file.
                if let Some(index_dir) = index_dir.as_ref() {
                    let write_atomic = || -> std::io::Result<()> {
                        let mut tmp = tempfile::NamedTempFile::new_in(index_dir)?;
                        index.write_to(tmp.as_file_mut())?;
                        tmp.persist(index_dir.join(source.local_filename()))
                            .map_err(|e| e.error)?;
                        Ok(())
                    };
                    if let Err(e) = write_atomic() {
                        tracing::warn!("failed to cache {} locally: {e}", source.object());
                    }
                }
                index
            }
        };
        tracing::debug!(
            "Fetched remote-index in {}ms",
            fetch_start.elapsed().as_millis()
        );

        Ok(Self {
            backend,
            index,
            dir: index_dir,
            base: url,
            ot,
            gcs_generation,
        })
    }

    /// Returns true if the build for the given spec hash is present in the cache.
    pub fn exists(&self, spec_hash: &SpecHash) -> bool {
        self.index.exists(spec_hash)
    }

    /// Returns the sha256 of the cached artifact for the given spec hash, or
    /// `None` if it isn't in the index.
    pub fn sha256(&self, spec_hash: &SpecHash) -> Option<[u8; 32]> {
        self.index.sha256(spec_hash)
    }

    /// Download the given spec hash into the local cache.
    #[tracing::instrument(skip_all, fields(span_name = %span_name), err)]
    pub async fn materialize(
        &self,
        spec_hash: &SpecHash,
        cache: &Cache<LocalDir>,
        span_name: &str,
    ) -> Result<(Duration, PendingDir), Error<<B::Response as FetchResponse>::Error>> {
        let sha256: [u8; 32] = self.index.sha256(spec_hash).ok_or(Error::NotFound)?;

        let materialize_op = OpTracker::new_with_root(&self.ot).with_op(Operation::FetchPkg {
            name: span_name.to_string(),
        });

        let start = Instant::now();
        let req = self.backend.get(
            self.base
                .join(&format!("{}.zst", hex::encode(sha256)))
                .unwrap(),
        )?;

        // Fetch the remote archive into a temporary file and seek to the beginning for decoding.
        let mut resp = self.backend.execute(req).await?;
        // Progress total only; tolerate a missing Content-Length (see above).
        materialize_op.set_length(resp.content_length().unwrap_or(0));

        let mut w = common::Tee::new(
            tempfile::tempfile().map_err(Error::IO)?,
            common::HashWriter(sha2::Sha256::new()),
        );
        while let Some(chunk) = resp.chunk().await? {
            materialize_op.increment(chunk.len() as u64);
            w.write_all(&chunk).map_err(Error::IO)?;
        }
        let (mut tar_file, hasher) = w.into_inner();
        let got_sha256 = hasher.0.finalize();
        if got_sha256 != sha256 {
            return Err(Error::HashMismatch {
                want: hex::encode(sha256),
                got: hex::encode(got_sha256),
            });
        }

        tar_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(Error::IO)?;
        materialize_op.set_op(Operation::ExtractPkg {
            name: span_name.to_string(),
        });
        let cache_hnd = cache.write_dir(spec_hash).map_err(Error::Cache)?;
        // Decompression is synchronous and CPU-bound; run it on the blocking
        // pool so the async worker stays free. Besides honouring the
        // no-blocking-in-async rule, this yield point is what lets the progress
        // renderer task be scheduled between `set_op(ExtractPkg)` and
        // `set_done()`. Without it the extract runs to completion inline, the two
        // bracketing version bumps coalesce in the watch channel, and the
        // renderer never observes the ExtractPkg state — so the extract spinner
        // is never drawn.
        let dest = cache_hnd.path().to_path_buf();
        tokio::task::spawn_blocking(move || {
            archive::extract_compressed_tar(tar_file, archive::Compression::Zstd, &dest, None)
        })
        .await
        .expect("extract task is awaited immediately and never cancelled")
        .map_err(Error::ArchiveError)?;

        materialize_op.set_done();

        Ok((Instant::now().duration_since(start), cache_hnd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[derive(Debug, Clone)]
    struct MockUrl(String);

    impl FetchUrl for MockUrl {
        type JoinError = ();
        fn join(&self, input: &str) -> Result<Self, ()> {
            Ok(MockUrl(format!("{}/{}", self.0, input)))
        }
        fn filename(&self) -> String {
            self.0.rsplit('/').next().unwrap_or(&self.0).to_string()
        }
    }

    #[derive(Debug)]
    struct MockResponse {
        data: Vec<u8>,
        consumed: bool,
    }

    impl FetchResponse for MockResponse {
        type Error = std::io::Error;

        fn error_for_status(self) -> Result<Self, Self::Error> {
            Ok(self)
        }
        fn is_success(&self) -> bool {
            true
        }
        fn status_code(&self) -> usize {
            200
        }
        fn content_length(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
        async fn bytes(self) -> Result<Bytes, Self::Error> {
            Ok(Bytes::from(self.data))
        }
        async fn chunk(&mut self) -> Result<Option<Bytes>, Self::Error> {
            if self.consumed {
                return Ok(None);
            }
            self.consumed = true;
            Ok(Some(Bytes::from(self.data.clone())))
        }
    }

    #[derive(Debug)]
    struct MockBackend {
        responses: std::collections::HashMap<String, Vec<u8>>,
    }

    impl FetchBackend for MockBackend {
        type Url = MockUrl;
        type Request = MockUrl;
        type Response = MockResponse;

        fn get(&self, url: MockUrl) -> Result<MockUrl, std::io::Error> {
            Ok(url)
        }
        async fn execute(&self, req: MockUrl) -> Result<MockResponse, std::io::Error> {
            let data = self.responses.get(&req.0).cloned().unwrap_or_default();
            Ok(MockResponse {
                data,
                consumed: false,
            })
        }
    }

    #[tokio::test]
    async fn materialize_fails_if_hash_mismatch() {
        let spec_hash = SpecHash::from_bytes([0xAA; 32]);
        let claimed_sha256: [u8; 32] = [0xBB; 32];

        // Build an index that maps spec_hash -> claimed_sha256.
        let mut index = IndexFile::default();
        index.extend(std::iter::once((spec_hash.clone(), claimed_sha256)));
        let mut index_bytes = Vec::new();
        index.write_to(&mut index_bytes).unwrap();

        // The archive payload — its real sha256 won't match claimed_sha256.
        let wrong_content = b"definitely not the right content";

        let mut responses = std::collections::HashMap::new();
        responses.insert(format!("mock://cache/{}", INDEX_FILENAME), index_bytes);
        responses.insert(
            format!("mock://cache/{}.zst", hex::encode(claimed_sha256)),
            wrong_content.to_vec(),
        );

        let rc = RemoteCache::new(
            MockBackend { responses },
            MockUrl("mock://cache".to_string()),
            None,
            None,
            IndexSource::Root,
        )
        .await
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let cache = lcache::Cache::at_dir(tmp.path()).unwrap();

        let result = rc.materialize(&spec_hash, &cache, "test-pkg").await;
        assert!(
            matches!(result, Err(Error::HashMismatch { .. })),
            "expected HashMismatch, got: {result:?}",
        );
    }

    #[tokio::test]
    async fn sha256_returns_indexed_hash_or_none() {
        let spec_hash = SpecHash::from_bytes([0xAA; 32]);
        let sha256: [u8; 32] = [0xCD; 32];

        // Index maps spec_hash -> sha256.
        let mut index = IndexFile::default();
        index.extend(std::iter::once((spec_hash.clone(), sha256)));
        let mut index_bytes = Vec::new();
        index.write_to(&mut index_bytes).unwrap();

        let mut responses = std::collections::HashMap::new();
        responses.insert(format!("mock://cache/{}", INDEX_FILENAME), index_bytes);

        let rc = RemoteCache::new(
            MockBackend { responses },
            MockUrl("mock://cache".to_string()),
            None,
            None,
            IndexSource::Root,
        )
        .await
        .unwrap();

        // Present spec hash -> its indexed sha256; absent -> None.
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));
        assert_eq!(rc.sha256(&SpecHash::from_bytes([0x11; 32])), None);
    }

    /// A throwaway single-purpose HTTP/1.1 server that answers `GET /<path>`
    /// with the matching entry in `objects` (200) and 404s everything else.
    /// Returns the base URL (with the required trailing `/`). Used to exercise
    /// the real reqwest transport behind `AnyBackend::Https` end-to-end (not a
    /// mock backend).
    fn serve_objects(objects: Vec<(String, Vec<u8>)>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let req = String::from_utf8_lossy(&buf);
                let hit = objects
                    .iter()
                    .find(|(path, _)| req.starts_with(&format!("GET /{path} ")));
                let (status, body): (&str, &[u8]) = match hit {
                    Some((_, bytes)) => ("200 OK", bytes),
                    None => ("404 Not Found", b""),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/")
    }

    fn serve_index(index: Option<Vec<u8>>) -> String {
        serve_objects(match index {
            Some(bytes) => vec![(INDEX_FILENAME.to_string(), bytes)],
            None => vec![],
        })
    }

    fn index_bytes_for(spec_hash: &SpecHash, sha256: [u8; 32]) -> Vec<u8> {
        let mut index = IndexFile::default();
        index.extend(std::iter::once((spec_hash.clone(), sha256)));
        let mut bytes = Vec::new();
        index.write_to(&mut bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn new_any_https_fetches_and_parses_index_over_real_http() {
        let spec_hash = SpecHash::from_bytes([0x07; 32]);
        let sha256: [u8; 32] = [0x42; 32];
        let mut index = IndexFile::default();
        index.extend(std::iter::once((spec_hash.clone(), sha256)));
        let mut index_bytes = Vec::new();
        index.write_to(&mut index_bytes).unwrap();

        let base = serve_index(Some(index_bytes));

        // Reads the index over real HTTPS-shaped transport (AnyBackend::Https ->
        // reqwest get/execute/chunk/content_length), then parses it.
        let rc = RemoteCache::new_any_https(&base, None, None, IndexSource::Root)
            .await
            .unwrap();
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));
        assert_eq!(rc.sha256(&SpecHash::from_bytes([0x99; 32])), None);
    }

    #[tokio::test]
    async fn new_any_https_treats_404_index_as_empty() {
        // A 404 on the index must yield an empty (not errored) cache, matching
        // the GCS path — a fresh bucket/mirror has no index yet.
        let base = serve_index(None);
        let rc = RemoteCache::new_any_https(&base, None, None, IndexSource::Root)
            .await
            .unwrap();
        assert_eq!(rc.sha256(&SpecHash::from_bytes([0x07; 32])), None);
    }

    #[tokio::test]
    async fn snapshot_source_fetches_the_per_commit_object() {
        const OBJECT: &str = "github.com/gominimal/pkgs/0123abcd.shisha";
        let spec_hash = SpecHash::from_bytes([0x07; 32]);
        let sha256: [u8; 32] = [0x42; 32];
        // Only the snapshot object exists; the root index deliberately 404s,
        // proving the reader asked for the snapshot.
        let base = serve_objects(vec![(
            OBJECT.to_string(),
            index_bytes_for(&spec_hash, sha256),
        )]);

        let source = IndexSource::Snapshot {
            object: OBJECT.to_string(),
        };
        let rc = RemoteCache::new_any_https(&base, None, None, source)
            .await
            .unwrap();
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));
    }

    #[tokio::test]
    async fn snapshot_source_404_is_snapshot_missing_not_empty() {
        const OBJECT: &str = "github.com/gominimal/pkgs/0123abcd.shisha";
        // Root index exists but the snapshot doesn't: the reader must surface
        // SnapshotMissing (letting the caller decide on fallback), not
        // silently read root or treat 404 as an empty index.
        let base = serve_index(Some(index_bytes_for(
            &SpecHash::from_bytes([0x07; 32]),
            [0x42; 32],
        )));

        let source = IndexSource::Snapshot {
            object: OBJECT.to_string(),
        };
        let err = RemoteCache::new_any_https(&base, None, None, source)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::SnapshotMissing { object } if object == OBJECT),
            "expected SnapshotMissing for {OBJECT}, got {err:?}"
        );
    }

    #[tokio::test]
    async fn snapshot_local_cache_never_expires_but_root_does() {
        const OBJECT: &str = "github.com/gominimal/pkgs/0123abcd.shisha";
        let spec_hash = SpecHash::from_bytes([0x07; 32]);
        let sha256: [u8; 32] = [0x42; 32];

        // Seed the local index dir with copies older than the root expiry.
        let dir = tempfile::tempdir().unwrap();
        let stale = std::time::SystemTime::now()
            - std::time::Duration::from_secs(INDEX_EXPIRY_SECONDS + 60);
        for name in ["github.com_gominimal_pkgs_0123abcd.shisha", INDEX_FILENAME] {
            let path = dir.path().join(name);
            std::fs::write(&path, index_bytes_for(&spec_hash, sha256)).unwrap();
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.set_times(std::fs::FileTimes::new().set_modified(stale))
                .unwrap();
        }

        // Nothing is served remotely: a fetch attempt can only 404.
        let base = serve_objects(vec![]);

        // The snapshot copy is immutable, so its age doesn't matter.
        let source = IndexSource::Snapshot {
            object: OBJECT.to_string(),
        };
        let rc = RemoteCache::new_any_https(&base, Some(dir.path().to_path_buf()), None, source)
            .await
            .unwrap();
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));

        // The root copy is past expiry: the reader refetches, and the 404
        // yields an empty index rather than the stale local entries.
        let rc = RemoteCache::new_any_https(
            &base,
            Some(dir.path().to_path_buf()),
            None,
            IndexSource::Root,
        )
        .await
        .unwrap();
        assert_eq!(rc.sha256(&spec_hash), None);
    }

    #[tokio::test]
    async fn index_fetch_error_status_is_an_error_not_an_empty_index() {
        use std::io::{Read, Write};
        // A server that 500s with an empty body: the worst case, since an
        // empty body "parses" as an empty index.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.flush();
            }
        });
        let base = format!("http://{addr}/");

        let err = RemoteCache::new_any_https(&base, None, None, IndexSource::Root)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Backend(_)),
            "expected Backend error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn corrupt_local_snapshot_copy_is_refetched_not_fatal() {
        const OBJECT: &str = "github.com/gominimal/pkgs/0123abcd.shisha";
        let spec_hash = SpecHash::from_bytes([0x07; 32]);
        let sha256: [u8; 32] = [0x42; 32];
        let base = serve_objects(vec![(
            OBJECT.to_string(),
            index_bytes_for(&spec_hash, sha256),
        )]);

        // Seed a corrupt local copy (a write cut short by a crash — not a
        // whole number of records). Snapshot copies never expire, so recovery
        // must come from the load-time whole-record check, not an age check.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("github.com_gominimal_pkgs_0123abcd.shisha"),
            b"truncated",
        )
        .unwrap();

        let source = IndexSource::Snapshot {
            object: OBJECT.to_string(),
        };
        let rc = RemoteCache::new_any_https(&base, Some(dir.path().to_path_buf()), None, source)
            .await
            .unwrap();
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));
    }

    #[tokio::test]
    async fn new_any_https_rejects_malformed_url() {
        let err = RemoteCache::new_any_https("not a url", None, None, IndexSource::Root)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Backend(AnyRespError::InvalidUrl(_))),
            "expected InvalidUrl, got {err:?}"
        );
    }
}
