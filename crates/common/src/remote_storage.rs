use crate::fetchers::{GcsUrl, ReqwestUrl};
use crate::file_cache;
use crate::file_cache::CachingDownloader;
use anyhow::Result;
use google_cloud_storage::client::Storage;
use ot::OpTracker;

use std::fs::File;
use std::path::PathBuf;

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

    #[tracing::instrument]
    pub async fn download_web_with_verification_and_caching(
        &self,
        url: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        let client = reqwest::Client::new();
        let backend = (&client, &self.cache);
        backend
            .download(ReqwestUrl::try_from(url)?, sha256, op)
            .await
            .map_err(|e| match e {
                either::Either::Left(e) => anyhow::Error::from(e),
                either::Either::Right(e) => anyhow::Error::from(e),
            })
    }

    #[tracing::instrument]
    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf> {
        let backend = (&self.client, &self.cache);
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
                either::Either::Right(e) => anyhow::Error::from(e),
            })
    }

    #[tracing::instrument(skip(file))]
    #[allow(dead_code)]
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
