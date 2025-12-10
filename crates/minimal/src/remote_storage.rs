use anyhow::Result;
use common::fetchers::{GcsUrl, ReqwestUrl};
use common::file_cache;
use common::file_cache::CachingDownloader;
use google_cloud_storage::client::Storage;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RemoteStorage {
    client: Storage,
    cache: file_cache::FileCache,
}

impl RemoteStorage {
    #[tracing::instrument]
    pub async fn new(cache_dir: PathBuf) -> Result<Self> {
        let cache = file_cache::FileCache::new(cache_dir)?;

        let client = Storage::builder()
            .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
            .build()
            .await?;
        Ok(Self { client, cache })
    }

    #[tracing::instrument]
    pub async fn download_https_with_verification_and_caching(
        &self,
        url: &str,
        sha256: &str,
    ) -> Result<PathBuf> {
        let client = reqwest::Client::new();
        let backend = (&client, &self.cache);
        backend
            .download(ReqwestUrl::try_from(url)?, sha256)
            .await
            .map_err(anyhow::Error::from)
    }

    #[tracing::instrument]
    pub async fn download_with_verification_and_caching(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
    ) -> Result<PathBuf> {
        let backend = (&self.client, &self.cache);
        backend
            .download(
                GcsUrl {
                    bucket: format!("projects/_/buckets/{bucket_id}"),
                    object: file.to_string(),
                },
                sha256,
            )
            .await
            .map_err(anyhow::Error::from)
    }

    #[tracing::instrument]
    pub async fn download<B: Write + std::fmt::Debug>(
        &self,
        bucket_id: String,
        file: &str,
        into: &mut B,
    ) -> Result<()> {
        let mut reader = self
            .client
            .read_object(format!("projects/_/buckets/{bucket_id}"), file)
            .send()
            .await?;
        while let Some(chunk) = reader.next().await.transpose()? {
            into.write_all(&chunk)?;
        }

        Ok(())
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

impl op::SourceFetcher for RemoteStorage {
    async fn download_https(&self, url: &str, sha256: &str) -> Result<PathBuf, anyhow::Error> {
        self.download_https_with_verification_and_caching(url, sha256)
            .await
    }

    async fn download_gcs(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
    ) -> Result<PathBuf, anyhow::Error> {
        self.download_with_verification_and_caching(bucket_id, file, sha256)
            .await
    }
}
