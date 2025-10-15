use crate::{Cache, EntryMeta, LocalDir, MetaInner, remote_index::RemoteIndex};
use common::{SpecHash, archive};
use std::io::{Seek, Write};

use common::fetchers::*;
use google_cloud_storage::{Error as GcsError, client::Storage};
use reqwest::{Client, Error as ReqwestError};

/// An error from operations with the remote cache.
#[derive(Debug)]
pub enum Error<BE: std::fmt::Debug> {
    Backend(BE),
    IO(std::io::Error),
    Cache(crate::CacheErr),
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
#[derive(Debug)]
pub struct RemoteCache<B: FetchBackend> {
    backend: B,
    base: B::Url,
    index: RemoteIndex,

    uploaded: Vec<(SpecHash, [u8; 32])>,
}

const INDEX_FILENAME: &str = "index.shisha";

impl RemoteCache<Client> {
    pub async fn new_over_https<URL: Into<ReqwestUrl>>(
        url: URL,
    ) -> Result<Self, Error<ReqwestError>> {
        let backend = Client::builder()
            .user_agent("minimal/remote-cache")
            .build()?;
        let url = url.into();

        Self::new(backend, url).await
    }
}

impl RemoteCache<Storage> {
    /// Instantiates a new remote cache using the given GCS client + bucket.
    pub async fn new_with_gcs_bucket(
        storage: Storage,
        bucket_id: &str,
    ) -> Result<Self, Error<GcsError>> {
        let url = GcsUrl {
            bucket: format!("projects/_/buckets/{bucket_id}"),
            object: "".to_string(),
        };

        Self::new(storage, url).await
    }

    /// Uploads the given artifact to the GCS bucket, staging it for inclusion
    /// in the index.
    ///
    /// Call [RemoteCache::finish_uploads] when all your uploads are done to finish the index.
    pub async fn upload(
        &mut self,
        spec_hash: &SpecHash,
        cache: &Cache<LocalDir>,
    ) -> Result<(), Error<GcsError>> {
        let cache_dir = cache.read_dir(spec_hash).map_err(Error::Cache)?;

        let (tar_file, sha256) = archive::compress_dir(cache_dir.path()).map_err(Error::IO)?;
        let indexed_sha = self.index.sha256(spec_hash);
        if indexed_sha == Some(sha256) {
            return Ok(()); // Cached one is up to date.
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
            .send_buffered()
            .await?;

        self.uploaded.push((spec_hash.clone(), sha256));
        Ok(())
    }

    /// Pushes a new index to the GCS bucket, complete with all the previous entries
    /// as well as any new entries which were added using [RemoteCache::upload].
    pub async fn finish_uploads(self) -> Result<(), Error<GcsError>> {
        let Self {
            mut index,
            backend,
            base,
            uploaded,
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
    ) -> Result<Self, Error<<B::Response as FetchResponse>::Error>> {
        let index_req = backend.get(url.join(INDEX_FILENAME).unwrap())?;

        // TODO: Gotta be a better way to stream it into [RemoteIndex].
        let index_resp = backend.execute(index_req).await?;

        let index = match index_resp.status_code() {
            404 => RemoteIndex::default(),
            _ => {
                let index_data = index_resp.error_for_status()?.bytes().await?;
                RemoteIndex::from_reader(&mut std::io::Cursor::new(index_data))
                    .map_err(Error::IO)?
            }
        };

        Ok(Self {
            backend,
            index,
            base: url,
            uploaded: vec![],
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
        inner: MetaInner,
        cache: &Cache<LocalDir>,
    ) -> Result<(), Error<<B::Response as FetchResponse>::Error>> {
        let sha256: [u8; 32] = self.index.sha256(spec_hash).ok_or(Error::NotFound)?;

        let req = self.backend.get(
            self.base
                .join(&format!("{}.zst", hex::encode(sha256)))
                .unwrap(),
        )?;

        // Fetch the remote archive into a temporary file and seek to the beginning for decoding.
        let mut resp = self.backend.execute(req).await?;
        let mut tar_file = tempfile::tempfile().map_err(Error::IO)?;
        while let Some(chunk) = resp.chunk().await? {
            tar_file.write_all(&chunk).map_err(Error::IO)?;
        }
        tar_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(Error::IO)?;

        let cache_hnd = cache.write_dir(spec_hash).map_err(Error::Cache)?;
        archive::extract_compressed_tar(
            tar_file,
            archive::Compression::Zstd,
            cache_hnd.path(),
            None,
        )
        .map_err(Error::ArchiveError)?;

        cache_hnd
            .finalize(EntryMeta {
                inner,
                fetched: true,
                ..Default::default()
            })
            .map_err(Error::Cache)?;

        Ok(())
    }
}
