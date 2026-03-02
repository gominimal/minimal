use crate::{Error, Materialized, Options, Runnable};
use cache::PendingDir;
use graph::SourceInput;

use anyhow::{Context, Result, anyhow};
use std::future::Future;
use std::path::PathBuf;
use tracing::debug;
use url::Url;

pub trait SourceFetcher: Send + Sync + std::fmt::Debug {
    /// Returns a path to the specified URL, after sha256 verification.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    fn download_web(
        &self,
        url: &str,
        sha256: &str,
    ) -> impl Future<Output = Result<PathBuf, anyhow::Error>> + Send;

    /// Returns a path to the specified bucket + file, after sha256 verification.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    fn download_gcs(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
    ) -> impl Future<Output = Result<PathBuf, anyhow::Error>> + Send;
}

impl SourceFetcher for common::RemoteStorage {
    async fn download_web(&self, url: &str, sha256: &str) -> Result<PathBuf, anyhow::Error> {
        self.download_web_with_verification_and_caching(url, sha256)
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

/// Loads a source.
pub struct SourceLoad<'a, SF: SourceFetcher> {
    pub source: &'a SourceInput,
    pub remote_fetcher: &'a SF,
    pub into: Option<PendingDir>,
}

impl<'a, SF: SourceFetcher> Runnable for SourceLoad<'a, SF> {
    type Result = Materialized;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let span = tracing::info_span!(
            "source_fetch",
            "indicatif.pb_show" = tracing::field::Empty,
            "from" = format!("{:?}", self.source.from),
        );
        let _enter = span.enter();

        use graph::SourceFetch;
        let (cached_path, filename) = match &self.source.from {
            SourceFetch::Local {
                full_path,
                filename,
                file_hash: _,
            } => (full_path.clone(), filename.clone()),
            SourceFetch::Web {
                url,
                sha256,
                url_pos: _,
                sha256_pos: _,
            } => {
                let url =
                    Url::parse(url).with_context(|| format!("Failed to parse URL '{}'", url))?;
                let filename = url
                    .path_segments()
                    .map(|mut s| s.next_back().unwrap())
                    .unwrap()
                    .to_string();

                match url.scheme() {
                    "https" | "http" => {
                        let cached_path = self
                            .remote_fetcher
                            .download_web(url.as_str(), sha256)
                            .await?;

                        debug!("  Downloaded and verified source from {}", url);
                        (cached_path, filename)
                    }

                    "gs" => {
                        let bucket_id = url.host_str().with_context(|| {
                            format!(
                                "Invalid gs:// URL: missing bucket name in '{}'",
                                url.as_str()
                            )
                        })?;

                        let file_name = url.path().trim_start_matches('/');

                        let cached_path = self
                            .remote_fetcher
                            .download_gcs(bucket_id.to_string(), file_name, sha256)
                            .await?;

                        debug!(
                            "  Downloaded and verified source from gs://{}/{}",
                            bucket_id, file_name
                        );
                        (cached_path, filename)
                    }
                    _ => todo!(),
                }
            }
        };

        if self.source.extract {
            use common::archive;
            match (
                archive::Compression::from_extension(&filename),
                self.into.take(),
            ) {
                (Some(compression), None) => {
                    let tempdir = opts.cache.temp_dir()?;
                    let tempdir_path = tempdir.path();
                    let f = std::fs::File::open(cached_path)?;
                    archive::extract_compressed_tar(
                        f,
                        compression,
                        tempdir_path,
                        self.source.strip_prefix.as_ref(),
                    )
                    .map_err(anyhow::Error::from)?;
                    Ok(Materialized::TempDir(tempdir))
                }
                (Some(compression), Some(pending_dir)) => {
                    let f = std::fs::File::open(cached_path)?;
                    archive::extract_compressed_tar(
                        f,
                        compression,
                        pending_dir.path(),
                        self.source.strip_prefix.as_ref(),
                    )
                    .map_err(anyhow::Error::from)?;
                    Ok(Materialized::Given(pending_dir))
                }

                (None, _) => {
                    Err(anyhow!("cannot extract archive {}: unhandled extension", filename).into())
                }
            }
        } else {
            Ok(Materialized::File(cached_path))
        }
    }
}
