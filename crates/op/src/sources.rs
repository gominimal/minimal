use crate::{Error, Materialized, Options, Runnable};
use graph::SourceInput;
use lcache::PendingDir;

use anyhow::{Context, Result, anyhow};
use ot::OpTracker;
use sandbox::config::ClassifierLeaf;
use std::future::Future;
use std::path::PathBuf;
use tracing::{debug, info};
use url::Url;

pub trait SourceFetcher: Send + Sync + std::fmt::Debug {
    /// Returns a path to the specified URL, after sha256 verification, and
    /// whether the fetch opened a connection in `leaf`.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    ///
    /// `leaf` is the classifier leaf of the box the build runs for, if any
    /// (NET-155). A fetch with a leaf opens its connections in that leaf, so
    /// the box's egress verdict decides them. `None` keeps the fetch as the
    /// caller's own traffic. The `bool` is `true` only when the fetch had a
    /// leaf and opened a connection in it. It is `false` when the download
    /// cache served the source, or when the fetch had no leaf.
    fn download_web(
        &self,
        url: &str,
        sha256: &str,
        leaf: Option<&ClassifierLeaf>,
        op: &OpTracker,
    ) -> impl Future<Output = Result<(PathBuf, bool), anyhow::Error>> + Send;

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
        leaf: Option<&ClassifierLeaf>,
        op: &OpTracker,
    ) -> Result<(PathBuf, bool), anyhow::Error> {
        let Some(leaf) = leaf else {
            let path = self
                .download_web_with_verification_and_caching(url, sha256, None, false, op)
                .await?;
            return Ok((path, false));
        };
        // A leaf in the deny subtree admits no destination, so the download
        // resolves no name for it.
        self.download_web_placed(url, sha256, &leaf.procs(), leaf.is_deny(), op)
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
    /// The classifier leaf of the box the build runs for, if any (NET-155).
    /// A web source is fetched in that leaf, so the box's egress verdict
    /// decides the fetch. `None` fetches it as the caller's own traffic.
    pub classifier_leaf: Option<&'a ClassifierLeaf>,
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
                        let fetched = self
                            .remote_fetcher
                            .download_web(url.as_str(), sha256, self.classifier_leaf, &op)
                            .await;
                        if let Some(leaf) = self.classifier_leaf {
                            // The leaf's own name is the box's id in the tree.
                            let box_id = leaf
                                .dir()
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            let host = url.host_str().unwrap_or_default();
                            let leaf = leaf.dir().display();
                            match &fetched {
                                Ok((_, true)) => info!(
                                    %box_id, host, %leaf,
                                    "fetched a web source for a box in the box's classifier leaf",
                                ),
                                Ok((_, false)) => info!(
                                    %box_id, host, %leaf,
                                    "the download cache served a web source for a box, and no connection opened",
                                ),
                                // The error can quote the request URL, with
                                // its credentials and its signed query.
                                Err(e) => info!(
                                    %box_id, host, %leaf,
                                    error = %crate::specs::strip_urls(&format!("{e:#}")),
                                    "a web source for a box could not be fetched in the box's classifier leaf",
                                ),
                            }
                        }
                        let (cached_path, _) = fetched?;

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
    /// It records the classifier leaf each fetch was asked to run in.
    #[derive(Debug)]
    struct FixtureFetcher(PathBuf, std::sync::Mutex<Vec<Option<ClassifierLeaf>>>);

    impl FixtureFetcher {
        fn new(archive: PathBuf) -> Self {
            Self(archive, Default::default())
        }
    }

    impl SourceFetcher for FixtureFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            leaf: Option<&ClassifierLeaf>,
            _op: &OpTracker,
        ) -> anyhow::Result<(PathBuf, bool)> {
            self.1.lock().unwrap().push(leaf.cloned());
            Ok((self.0.clone(), leaf.is_some()))
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
            classifier_leaf: None,
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

    /// NET-155: a web source loaded for a build placed in a box's classifier
    /// leaf is fetched in that leaf, so the box's egress verdict decides the
    /// fetch. A load with no leaf fetches as the caller's own traffic. The
    /// fetched archive is extracted the same way in both cases.
    #[tokio::test]
    async fn web_source_fetch_runs_in_the_given_classifier_leaf() {
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
                url: "https://downloads.example.org/pkg-1.0.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: Some("pkg-1.0".into()),
        };
        let leaf = ClassifierLeaf::under(
            Path::new("/sys/fs/cgroup/minimald.slice"),
            "sealed",
            sandbox::config::Verdict::Deny,
        );

        for given in [Some(&leaf), None] {
            let materialized = SourceLoad {
                source: &source,
                remote_fetcher: &fetcher,
                into: None,
                classifier_leaf: given,
            }
            .run(&opts)
            .await
            .unwrap();
            let Materialized::TempDir(root) = materialized else {
                panic!("an extracted source materializes into a temp dir");
            };
            assert!(root.path().join("README").exists());
        }
        assert_eq!(
            *fetcher.1.lock().unwrap(),
            vec![Some(leaf.clone()), None],
            "each fetch runs in the leaf its load was given"
        );
        assert_eq!(
            leaf.procs(),
            Path::new("/sys/fs/cgroup/minimald.slice/boxes/deny/sealed/cgroup.procs"),
            "the download joins the leaf through its cgroup.procs"
        );
    }

    /// Fails every web fetch with an error that quotes a URL with
    /// credentials and a signed query, as a reqwest error does.
    #[derive(Debug)]
    struct LeakyFailFetcher;

    impl SourceFetcher for LeakyFailFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _leaf: Option<&ClassifierLeaf>,
            _op: &OpTracker,
        ) -> anyhow::Result<(PathBuf, bool)> {
            Err(anyhow!(
                "error sending request for url (https://user:secret@host/x?sig=abc)"
            ))
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

    /// Writes every event's fields into one shared string.
    #[derive(Clone, Default)]
    struct CaptureEvents(std::sync::Arc<std::sync::Mutex<String>>);

    impl tracing::field::Visit for CaptureEvents {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = writeln!(self.0.lock().unwrap(), "{}={value:?}", field.name());
        }
    }

    impl tracing::Subscriber for CaptureEvents {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            event.record(&mut self.clone());
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// NET-155: the daemon log line for a box's failed web-source fetch
    /// keeps the error, but strips the credentials and the query from any
    /// URL the error quotes.
    #[tokio::test]
    async fn web_source_fetch_failure_log_strips_url_credentials() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let graph = Graph::new();
        let opts = Options {
            cache,
            graph: &graph,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let source = SourceInput {
            from: SourceFetch::Web {
                url: "https://host/x.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: None,
        };
        let leaf = ClassifierLeaf::under(
            Path::new("/sys/fs/cgroup/minimald.slice"),
            "sealed",
            sandbox::config::Verdict::Deny,
        );
        let capture = CaptureEvents::default();
        let _guard = tracing::subscriber::set_default(capture.clone());

        let result = SourceLoad {
            source: &source,
            remote_fetcher: &LeakyFailFetcher,
            into: None,
            classifier_leaf: Some(&leaf),
        }
        .run(&opts)
        .await;

        assert!(result.is_err(), "the failed fetch fails the load");
        let logged = capture.0.lock().unwrap().clone();
        assert!(
            logged.contains("could not be fetched") && logged.contains("https://host/x"),
            "the failure is logged with the stripped URL: {logged}"
        );
        assert!(
            !logged.contains("secret"),
            "no password in the log: {logged}"
        );
        assert!(
            !logged.contains("sig=abc"),
            "no signed query in the log: {logged}"
        );
    }
}
