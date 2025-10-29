use crate::{Error, Materialized, Options, Runnable};
use graph::SourceInput;

use anyhow::{Context, Result, anyhow};
use std::future::Future;
use std::path::PathBuf;
use tracing::debug;
use url::Url;

pub trait SourceFetcher: Sync {
    /// Returns a path to the specified URL, after sha256 verification.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    fn download_https(
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

/// Loads a source.
pub struct SourceLoad<'a, SF: SourceFetcher> {
    pub source: &'a SourceInput,
    pub remote_fetcher: &'a SF,
}

impl<'a, SF: SourceFetcher> Runnable for SourceLoad<'a, SF> {
    type Result = Materialized;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        use graph::dep_graph::SourceFetch;
        match &self.source.from {
            SourceFetch::URL(url) => {
                let url =
                    Url::parse(url).with_context(|| format!("Failed to parse URL '{}'", url))?;

                let cached_path = match url.scheme() {
                    "https" => {
                        let cached_path = self
                            .remote_fetcher
                            .download_https(url.as_str(), &self.source.sha256)
                            .await?;

                        debug!("  Downloaded and verified source from {}", url);
                        cached_path
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
                            .download_gcs(bucket_id.to_string(), file_name, &self.source.sha256)
                            .await?;

                        debug!(
                            "  Downloaded and verified source from gs://{}/{}",
                            bucket_id, file_name
                        );
                        cached_path
                    }
                    _ => todo!(),
                };

                if self.source.extract {
                    let file_name = url
                        .path_segments()
                        .map(|mut s| s.next_back().unwrap())
                        .unwrap();
                    let tempdir = opts.cache.temp_dir()?;
                    let tempdir_path = tempdir.path();

                    use common::archive;
                    match archive::Compression::from_extension(file_name) {
                        Some(compression) => {
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
                        None => Err(anyhow!(
                            "cannot extract archive {}: unhandled extension",
                            file_name
                        )
                        .into()),
                    }
                } else {
                    Ok(Materialized::File(cached_path))
                }
            }
        }
    }
}
