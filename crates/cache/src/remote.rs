use crate::{remote_index::RemoteIndex, Cache, LocalDir};
use common::{SpecHash, Tee};
use sha2::{Digest, Sha256};
use std::io::{Seek, Write};

use common::fetchers::*;
use google_cloud_storage::{client::Storage, Error as GcsError};
use reqwest::{Client, Error as ReqwestError};

#[derive(Debug)]
pub enum Error<BE: std::fmt::Debug> {
    Backend(BE),
    IO(std::io::Error),
    Cache(crate::CacheErr),
    NotFound,
}

impl<BE: std::fmt::Debug> From<BE> for Error<BE> {
    fn from(backend_err: BE) -> Self {
        Self::Backend(backend_err)
    }
}

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

    pub async fn upload(
        &mut self,
        spec_hash: &SpecHash,
        cache: &Cache<LocalDir>,
    ) -> Result<(), Error<GcsError>> {
        let cache_dir = cache.read_dir(spec_hash).map_err(Error::Cache)?;

        // Compress to archive while computing hash
        let mut tar_file = tempfile::tempfile().map_err(Error::IO)?;
        let mut hasher = Sha256::new();
        {
            let mut w = Tee::new(&mut tar_file, &mut hasher);
            let encoder = zstd::stream::Encoder::new(&mut w, 3).map_err(Error::IO)?;
            let mut tar_builder = tar::Builder::new(encoder);
            tar_builder
                .append_dir_all(".", cache_dir.path())
                .map_err(Error::IO)?;
            tar_builder
                .into_inner()
                .map_err(Error::IO)?
                .finish()
                .map_err(Error::IO)?;
        }
        tar_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(Error::IO)?;

        let sha256 = hasher.finalize();

        let indexed_sha = self.index.sha256(spec_hash);
        if indexed_sha == Some(sha256.into()) {
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

        self.uploaded.push((spec_hash.clone(), sha256.into()));
        Ok(())
    }

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

impl<B: FetchBackend> RemoteCache<B>
where
    Error<<B as FetchBackend>::Error>:
        From<<<B as FetchBackend>::Response as FetchResponse>::Error>,
{
    pub async fn new(backend: B, url: B::Url) -> Result<Self, Error<B::Error>> {
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
        cache: &Cache<LocalDir>,
    ) -> Result<(), Error<B::Error>> {
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

        // Unzip archive into the cache
        let mut archive =
            tar::Archive::new(zstd::stream::Decoder::new(tar_file).map_err(Error::IO)?);
        let cache_hnd = cache.write_dir(spec_hash).map_err(Error::Cache)?;
        archive.unpack(cache_hnd.path()).map_err(Error::IO)?;
        cache_hnd.finalize().map_err(Error::Cache)?;

        Ok(())
    }
}
