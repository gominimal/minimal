use crate::remote_index::RemoteIndex;
use common::{SpecHash, archive};
use lcache::{Cache, LocalDir, PendingDir};
use ot::{OpTracker, Operation};
use std::io::{Seek, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::fetchers::*;
use google_cloud_storage::{Error as GcsError, client::Storage};
use reqwest::{Client, Error as ReqwestError};

/// An error from operations with the remote cache.
#[derive(Debug)]
pub enum Error<BE: std::fmt::Debug> {
    Backend(BE),
    IO(std::io::Error),
    Cache(lcache::CacheErr),
    NotFound,
    ArchiveError(archive::ArchiveError),
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
/// can be fetched by [SpecHash].
#[derive(Debug, Clone)]
pub struct RemoteCache<B: FetchBackend> {
    backend: B,
    base: B::Url,
    index: RemoteIndex,

    #[allow(dead_code)]
    dir: Option<PathBuf>,

    ot: Option<OpTracker>,

    uploaded: Vec<(SpecHash, [u8; 32])>,
}

pub const INDEX_FILENAME: &str = "index.shisha";
const INDEX_EXPIRY_SECONDS: u64 = 5 * 60; // how long a fetch of the remote index is considered fresh for

impl RemoteCache<Client> {
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

    /// Upserts the given artifact to the GCS bucket, staging it for inclusion
    /// in the index. Returns false if the given artifact is already in the index.
    ///
    /// Call [RemoteCache::finish_uploads] when all your uploads are done to finish the index.
    pub async fn upload(
        &mut self,
        spec_hash: &SpecHash,
        artifact: (std::fs::File, [u8; 32]),
    ) -> Result<bool, Error<GcsError>> {
        let (tar_file, sha256) = artifact;
        let indexed_sha = self.index.sha256(spec_hash);
        if indexed_sha == Some(sha256) {
            return Ok(false); // Cached one is up to date.
        }

        self.backend
            .write_object(
                self.base.bucket.clone(),
                self.base
                    .join(&format!("{}.zst", hex::encode(sha256)))
                    .unwrap()
                    .object,
                tokio::fs::File::from_std(tar_file),
            )
            .set_cache_control("public, max-age=7200")
            .send_buffered()
            .await?;

        self.uploaded.push((spec_hash.clone(), sha256));
        Ok(true)
    }

    /// Pushes a new index to the GCS bucket, complete with all the previous entries
    /// as well as any new entries which were added using [RemoteCache::upload].
    pub async fn finish_uploads(self) -> Result<(), Error<GcsError>> {
        let Self {
            mut index,
            backend,
            base,
            uploaded,
            dir: _,
            ot: _,
        } = self;

        index.extend(uploaded);

        let mut data = Vec::with_capacity(2048);
        index.write_to(&mut data).map_err(Error::IO)?;

        let bytes_data = bytes::Bytes::copy_from_slice(&data);
        backend
            .write_object(
                base.bucket.clone(),
                base.join(INDEX_FILENAME).unwrap().object,
                bytes_data,
            )
            .set_cache_control("public, max-age=300")
            .send_buffered()
            .await?;
        Ok(())
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
                    uploaded: vec![],
                    ot,
                });
            }
        }

        let fetch_start = Instant::now();
        let index_req = backend.get(url.join(INDEX_FILENAME).unwrap())?;

        let fetch_op = OpTracker::new_with_root(&ot).with_op(Operation::FetchIndex);

        // TODO: Gotta be a better way to stream it into [RemoteIndex].
        let mut index_resp = backend.execute(index_req).await?;
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
            uploaded: vec![],
            ot,
        })
    }

    /// Returns true if the build for the given spec hash is present in the cache.
    pub fn exists(&self, spec_hash: &SpecHash) -> bool {
        self.index.exists(spec_hash)
    }

    /// Download the given spec hash into the local cache.
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

        let mut tar_file = tempfile::tempfile().map_err(Error::IO)?;
        while let Some(chunk) = resp.chunk().await? {
            materialize_op.increment(chunk.len() as u64);
            tar_file.write_all(&chunk).map_err(Error::IO)?;
        }
        tar_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(Error::IO)?;

        materialize_op.set_op(Operation::Extract {
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
