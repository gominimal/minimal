use crate::remote_index::RemoteIndex;
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
    index: RemoteIndex,

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

impl RemoteCache<Client> {
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

        Self::new(backend, url, index_dir, ot).await
    }
}

impl RemoteCache<Storage> {
    /// Instantiates a new remote cache using the given GCS client + bucket.
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

        Self::new(storage, url, index_dir, ot).await
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

impl<B: FetchBackend> RemoteCache<B> {
    /// Creates a new remote cache based on the given backend and URL.
    pub async fn new(
        backend: B,
        url: B::Url,
        index_dir: Option<PathBuf>,
        ot: Option<OpTracker>,
    ) -> Result<Self, Error<<B::Response as FetchResponse>::Error>> {
        // Fast path: Use locally-cached index if its recent
        if let Some(id) = index_dir.as_ref() {
            let l_idx_path = id.join(INDEX_FILENAME);
            if let Ok(stat) = std::fs::metadata(&l_idx_path)
                && let Ok(modified) = stat.modified()
                && let Ok(elapsed) = modified.elapsed()
                && elapsed.as_secs() <= INDEX_EXPIRY_SECONDS
            {
                tracing::debug!("Re-using remote index (fetched {}s ago)", elapsed.as_secs());
                return Ok(Self {
                    backend,
                    index: RemoteIndex::from_reader(
                        &mut std::fs::File::open(&l_idx_path).map_err(Error::IO)?,
                    )
                    .map_err(Error::IO)?,
                    dir: index_dir,
                    base: url,
                    ot,
                    // Loading from local cache means we never asked GCS for
                    // the current generation. into_writer must refetch.
                    gcs_generation: None,
                });
            }
        }

        let fetch_start = Instant::now();
        let index_req = backend.get(url.join(INDEX_FILENAME).unwrap())?;

        let fetch_op = OpTracker::new_with_root(&ot).with_op(Operation::FetchIndex);

        // TODO: Gotta be a better way to stream it into [RemoteIndex].
        let mut index_resp = backend.execute(index_req).await?;
        // Capture the GCS generation, if the backend exposes one. Reads
        // need to do this before consuming chunks because the response
        // metadata may not survive the body read in some impls.
        let gcs_generation = index_resp.generation();
        let index = match index_resp.status_code() {
            404 => RemoteIndex::default(),
            _ => {
                fetch_op.set_length(index_resp.content_length().unwrap());

                let mut buffer =
                    Vec::with_capacity(index_resp.content_length().unwrap_or(1024 * 1024) as usize);
                while let Some(chunk) = index_resp.chunk().await? {
                    fetch_op.increment(chunk.len() as u64);
                    buffer.extend(chunk);
                }
                fetch_op.set_done();

                let index = RemoteIndex::from_reader(&mut std::io::Cursor::new(buffer))
                    .map_err(Error::IO)?;

                if let Some(index_dir) = index_dir.as_ref() {
                    let l_idx_path = index_dir.join(INDEX_FILENAME);
                    index
                        .write_to(&mut std::fs::File::create(&l_idx_path).map_err(Error::IO)?)
                        .unwrap();
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
        materialize_op.set_length(resp.content_length().unwrap());

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
        archive::extract_compressed_tar(
            tar_file,
            archive::Compression::Zstd,
            cache_hnd.path(),
            None,
        )
        .map_err(Error::ArchiveError)?;

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
        let mut index = RemoteIndex::default();
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
        let mut index = RemoteIndex::default();
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
        )
        .await
        .unwrap();

        // Present spec hash -> its indexed sha256; absent -> None.
        assert_eq!(rc.sha256(&spec_hash), Some(sha256));
        assert_eq!(rc.sha256(&SpecHash::from_bytes([0x11; 32])), None);
    }
}
