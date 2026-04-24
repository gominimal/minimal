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

// Writers live in `remote_writer.rs`. This module is read-only.
//
// Historical note: `upload`/`finish_uploads` used to live here on `RemoteCache<Storage>`,
// but did an unsynchronized read-modify-write on the index file, which lost entries when
// two writers raced. The bifurcation forces writers down a path that fetches the index
// generation up-front and writes with `if_generation_match` for compare-and-swap semantics.

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

    /// Convert this reader into a writer, reusing the already-fetched index
    /// and generation when possible. If the reader was loaded from the local
    /// cache fast path (and therefore has no recorded generation), the index
    /// is refetched from GCS so the writer's compare-and-swap commit has an
    /// authoritative generation to match against.
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
