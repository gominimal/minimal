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

        // Attribution capture keys on the archive's declared sha256, which is
        // what the sealed attribution manifest names per package. Local files
        // are project-side and never appear there.
        let source_sha256 = match &self.source.from {
            SourceFetch::Web { sha256, .. } => Some(sha256.clone()),
            SourceFetch::Local { .. } => None,
        };

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
                    record_notices(opts, source_sha256.as_deref(), tempdir_path);
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
                    record_notices(opts, source_sha256.as_deref(), pending_dir.path());
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

/// Best-effort: a build never fails because attribution could not be
/// recorded, but the miss is logged so it is not silent.
fn record_notices(opts: &Options<'_>, source_sha256: Option<&str>, root: &std::path::Path) {
    let Some(sha256) = source_sha256 else {
        return;
    };
    if let Err(error) = crate::notices::record(&opts.cache, sha256, root) {
        tracing::warn!(%sha256, %error, "could not record upstream notices");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Options;
    use flate2::{Compression, write::GzEncoder};
    use graph::{Graph, SourceFetch, SourceInput};
    use lcache::Cache;
    use std::path::Path;
    use tempfile::TempDir;

    const SHA: &str = "4474de87e084953eefc1120cf905a79f72bbbf85091e30cf37c9214eafcaa9c9";

    /// Serves one local archive for any URL, standing in for a verified fetch.
    #[derive(Debug)]
    struct FixtureFetcher(PathBuf);

    impl SourceFetcher for FixtureFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            Ok(self.0.clone())
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            unreachable!("only web sources are fetched here")
        }
    }

    fn tarball(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join("pkg-1.0.tar.gz");
        let enc = GzEncoder::new(std::fs::File::create(&path).unwrap(), Compression::fast());
        let mut tar = tar::Builder::new(enc);
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, *body).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
        path
    }

    #[tokio::test]
    async fn extracting_a_web_source_records_its_notices() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let archive = tarball(
            tmp.path(),
            &[
                ("pkg-1.0/NOTICE", b"upstream notice"),
                ("pkg-1.0/LICENSE", b"apache"),
                ("pkg-1.0/src/main.rs", b"fn main() {}"),
            ],
        );
        let fetcher = FixtureFetcher(archive);
        let graph = Graph::new();
        let opts = Options {
            cache: cache.clone(),
            graph: &graph,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let source = SourceInput {
            from: SourceFetch::Web {
                url: "https://example.invalid/pkg-1.0.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: Some("pkg-1.0".into()),
        };

        let materialized = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
        }
        .run(&opts)
        .await
        .unwrap();

        let Materialized::TempDir(root) = materialized else {
            panic!("an extracted source materializes into a temp dir");
        };
        assert!(root.path().join("NOTICE").exists());

        let record = crate::notices::read(&cache, SHA)
            .unwrap()
            .expect("recorded");
        assert_eq!(record.source_sha256, SHA);
        let names: Vec<&str> = record.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["NOTICE"]);
        assert_eq!(record.files[0].text.as_deref(), Some("upstream notice"));
    }
}
