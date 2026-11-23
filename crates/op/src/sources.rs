use crate::{Error, Materialized, Options, Runnable};
use graph::SourceInput;
use lcache::PendingDir;

use anyhow::{Context, Result, anyhow};
use ot::OpTracker;
use std::future::Future;
use std::path::{Path, PathBuf};
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

    /// The cached file of this name and hash, if there is one. A build box
    /// asks before it opens any network (NET-155).
    fn cached(&self, _filename: &str, _sha256: &str) -> Result<Option<PathBuf>, anyhow::Error> {
        Ok(None)
    }

    /// Takes the file a build box fetched into the cache, after the sha256
    /// check, and returns its path.
    fn adopt(&self, filename: &str, _sha256: &str, _from: &Path) -> Result<PathBuf, anyhow::Error> {
        Err(anyhow!("this fetcher takes no file for {filename}"))
    }
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

    fn cached(&self, filename: &str, sha256: &str) -> Result<Option<PathBuf>, anyhow::Error> {
        common::RemoteStorage::cached(self, filename, sha256)
    }

    fn adopt(&self, filename: &str, sha256: &str, from: &Path) -> Result<PathBuf, anyhow::Error> {
        common::RemoteStorage::adopt(self, filename, sha256, from)
    }
}

/// Loads a source.
pub struct SourceLoad<'a, SF: SourceFetcher> {
    pub source: &'a SourceInput,
    pub remote_fetcher: &'a SF,
    pub into: Option<PendingDir>,
    /// The build box the build runs in, if it runs for a box (NET-155). A
    /// source is fetched inside it, so its egress decides the fetch. `None`
    /// fetches the source as the caller's own traffic: `mip`'s.
    pub build_box: Option<&'a crate::BuildBox>,
    /// The package the source belongs to.
    pub package: &'a str,
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
                        let cached_path = match self.build_box {
                            Some(build_box) => {
                                build_box
                                    .fetch(
                                        self.package,
                                        self.remote_fetcher,
                                        url.as_str(),
                                        &filename,
                                        sha256,
                                        opts,
                                        &op,
                                    )
                                    .await?
                            }
                            None => {
                                self.remote_fetcher
                                    .download_web(url.as_str(), sha256, &op)
                                    .await?
                            }
                        };

                        debug!(
                            "  Downloaded and verified source from {}",
                            crate::specs::stripped_url(url.as_str()).unwrap_or_default()
                        );
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

                        let cached_path = match self.build_box {
                            // The public object, over `https`, from inside
                            // the build box (NET-155). The cache key is the
                            // object's last path segment either way.
                            Some(build_box) => {
                                build_box
                                    .fetch(
                                        self.package,
                                        self.remote_fetcher,
                                        &common::gcs_object_url(bucket_id, file_name)?,
                                        &filename,
                                        sha256,
                                        opts,
                                        &op,
                                    )
                                    .await?
                            }
                            None => {
                                self.remote_fetcher
                                    .download_gcs(bucket_id.to_string(), file_name, sha256, &op)
                                    .await?
                            }
                        };

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
    /// It counts the fetches that reached it, and `cached` serves it from the
    /// cache.
    #[derive(Debug)]
    struct FixtureFetcher {
        archive: PathBuf,
        cached: bool,
        fetches: std::sync::atomic::AtomicUsize,
    }

    impl FixtureFetcher {
        fn new(archive: PathBuf) -> Self {
            Self {
                archive,
                cached: false,
                fetches: Default::default(),
            }
        }
    }

    impl SourceFetcher for FixtureFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.archive.clone())
        }

        fn cached(&self, _filename: &str, _sha256: &str) -> anyhow::Result<Option<PathBuf>> {
            Ok(self.cached.then(|| self.archive.clone()))
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            anyhow::bail!("only web sources are fetched here")
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
        let fetcher = FixtureFetcher::new(archive);
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
            build_box: None,
            package: "pkg",
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

    /// An extracted source keeps each file's modification time from the
    /// tarball, so a build's tools see the age order upstream shipped: an
    /// autotools `configure` stays newer than its `configure.ac` and is not
    /// regenerated.
    #[tokio::test]
    async fn an_extracted_source_keeps_the_tarballs_modification_times() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let path = tmp.path().join("pkg-1.0.tar.gz");
        let enc = GzEncoder::new(std::fs::File::create(&path).unwrap(), Compression::fast());
        let mut tar = tar::Builder::new(enc);
        for (name, mtime) in [
            ("pkg-1.0/configure.ac", 1_000),
            ("pkg-1.0/configure", 2_000),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_mtime(mtime);
            header.set_cksum();
            tar.append(&header, std::io::empty()).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
        let fetcher = FixtureFetcher::new(path);
        let graph = Graph::new();
        let opts = Options {
            cache,
            graph: &graph,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let source = web_source();
        let materialized = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
            build_box: None,
            package: "pkg",
        }
        .run(&opts)
        .await
        .unwrap();
        let Materialized::TempDir(root) = materialized else {
            panic!("an extracted source materializes into a temp dir");
        };
        let mtime = |name: &str| {
            std::fs::metadata(root.path().join(name))
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        assert_eq!(mtime("configure.ac"), 1_000);
        assert_eq!(mtime("configure"), 2_000);
    }

    fn web_source() -> SourceInput {
        SourceInput {
            from: SourceFetch::Web {
                url: "https://downloads.example.org/pkg-1.0.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: Some("pkg-1.0".into()),
        }
    }

    fn closed_build_box() -> crate::BuildBox {
        crate::BuildBox::on_network("/nonexistent".into(), None)
    }

    /// What a source refused at `host_port` says: what a download that could
    /// not connect says, with the rules as the reason, so the daemon names
    /// the host and the next step.
    fn refused_at(host_port: &str) -> String {
        format!(
            "other: could not connect to {host_port}: {}",
            common::RULES_REFUSE
        )
    }

    /// NET-155: a source already in the download cache needs no network, so
    /// a build box with none still has it, and nothing is fetched.
    #[tokio::test]
    async fn a_cached_source_opens_no_network() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let archive = tarball(tmp.path(), &[("pkg-1.0/README", b"readme")]);
        let mut fetcher = FixtureFetcher::new(archive);
        fetcher.cached = true;
        let graph = Graph::new();
        let opts = Options {
            cache: cache.clone(),
            graph: &graph,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let source = web_source();
        let build_box = closed_build_box();
        let materialized = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
            build_box: Some(&build_box),
            package: "pkg",
        }
        .run(&opts)
        .await
        .unwrap();
        let Materialized::TempDir(root) = materialized else {
            panic!("an extracted source materializes into a temp dir");
        };
        assert!(root.path().join("README").exists());
        assert_eq!(fetcher.fetches.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// NET-155: in a build box a `gs://` source goes over `https` from inside
    /// the box, not through the daemon's bucket client, so a box with no
    /// network refuses it and the bucket client is never asked.
    #[tokio::test]
    async fn gs_source_fetches_over_https_in_the_build_box() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let archive = tarball(tmp.path(), &[("pkg-1.0/README", b"readme")]);
        let fetcher = FixtureFetcher::new(archive);
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
                url: "gs://minimal-staging-archives/pkg-1.0.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: Some("pkg-1.0".into()),
        };
        let build_box = closed_build_box();
        let refused = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
            build_box: Some(&build_box),
            package: "pkg",
        }
        .run(&opts)
        .await
        .expect_err("a build box with no network fetches nothing");
        assert_eq!(
            refused.to_string(),
            refused_at("storage.googleapis.com:443"),
            "the refusal names the host the box would fetch from"
        );
    }

    /// NET-155, NET-171: a source outside the cache, for a build box with no
    /// network, stops the build with the refusal. It reaches no fetcher, so
    /// the daemon does not fetch it either.
    #[tokio::test]
    async fn source_fetch_runs_in_the_build_box() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let archive = tarball(tmp.path(), &[("pkg-1.0/README", b"readme")]);
        let fetcher = FixtureFetcher::new(archive);
        let graph = Graph::new();
        let opts = Options {
            cache: cache.clone(),
            graph: &graph,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let source = web_source();
        let build_box = closed_build_box();
        let refused = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
            build_box: Some(&build_box),
            package: "pkg",
        }
        .run(&opts)
        .await
        .expect_err("a build box with no network fetches nothing");
        assert_eq!(refused.to_string(), refused_at("downloads.example.org:443"));
        assert_eq!(fetcher.fetches.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Outside any box, the caller fetches as its own traffic.
        let materialized = SourceLoad {
            source: &source,
            remote_fetcher: &fetcher,
            into: None,
            build_box: None,
            package: "pkg",
        }
        .run(&opts)
        .await
        .unwrap();
        assert!(matches!(materialized, Materialized::TempDir(_)));
        assert_eq!(fetcher.fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
