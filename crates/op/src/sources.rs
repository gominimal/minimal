use crate::{Error, Materialized, Options, Runnable};
use graph::SourceInput;
use lcache::PendingDir;

use anyhow::{Context, Result, anyhow};
use ot::OpTracker;
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
        op: &OpTracker,
    ) -> impl Future<Output = Result<PathBuf, anyhow::Error>> + Send;

    /// Returns a path to the specified bucket + file, after sha256 verification.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    fn download_gcs(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> impl Future<Output = Result<PathBuf, anyhow::Error>> + Send;
}

impl SourceFetcher for common::RemoteStorage {
    async fn download_web(
        &self,
        url: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf, anyhow::Error> {
        self.download_web_with_verification_and_caching(url, sha256, op)
            .await
    }

    async fn download_gcs(
        &self,
        bucket_id: String,
        file: &str,
        sha256: &str,
        op: &OpTracker,
    ) -> Result<PathBuf, anyhow::Error> {
        self.download_with_verification_and_caching(bucket_id, file, sha256, op)
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
        use graph::SourceFetch;
        let op = OpTracker::new_with_root(&opts.ot).with_op(ot::Operation::FetchSource {
            url: match &self.source.from {
                SourceFetch::Local { filename, .. } => filename.clone(),
                SourceFetch::Web { url, .. } => url.clone(),
            },
        });

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
                            .download_web(url.as_str(), sha256, &op)
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
                            .download_gcs(bucket_id.to_string(), file_name, sha256, &op)
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
