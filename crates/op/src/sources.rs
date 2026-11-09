use crate::{Error, Materialized, Options, Runnable};
use common::Placement;
use graph::SourceInput;
use lcache::PendingDir;

use anyhow::{Context, Result, anyhow};
use ot::OpTracker;
use sandbox2::config::ClassifierLeaf;
use std::future::Future;
use std::path::{Path, PathBuf};
use tracing::{debug, info};
use url::Url;

/// Where a source fetch for a box opens its connections (NET-155), so the
/// box's egress rules decide them.
#[derive(Debug, Clone, Copy)]
pub enum SourcePlace<'a> {
    /// In the box's classifier leaf.
    Leaf(&'a ClassifierLeaf),
    /// On the box's own network. `exec_base` holds the sandbox that keeps
    /// that network up for the fetch.
    Network {
        network: &'a crate::BuildNetwork,
        exec_base: &'a Path,
    },
}

pub trait SourceFetcher: Send + Sync + std::fmt::Debug {
    /// Returns a path to the specified URL, after sha256 verification, and
    /// whether the fetch opened a connection at `place`.
    ///
    /// The returned path may be cached - there's no expectation a fresh fetch is performed.
    ///
    /// `place` is where the box the build runs for opens the fetch's
    /// connections, if the build runs for a box (NET-155). `None` keeps the
    /// fetch as the caller's own traffic. The `bool` is `true` only when the
    /// fetch had a place and opened a connection there. It is `false` when
    /// the download cache served the source, or when the fetch had no place.
    fn download_web(
        &self,
        url: &str,
        sha256: &str,
        place: Option<SourcePlace<'_>>,
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
        place: Option<SourcePlace<'_>>,
        op: &OpTracker,
    ) -> Result<(PathBuf, bool), anyhow::Error> {
        let Some(place) = place else {
            let path = self
                .download_web_with_verification_and_caching(url, sha256, None, op)
                .await?;
            return Ok((path, false));
        };
        // Kept up until the download ends.
        let _held;
        let placement = match place {
            // A leaf in the deny subtree admits no destination, so the
            // download resolves no name for it.
            SourcePlace::Leaf(leaf) if leaf.is_deny() => Placement::Refused(common::RULES_REFUSE),
            SourcePlace::Leaf(leaf) => Placement::Cgroup(leaf.procs()),
            SourcePlace::Network { network, exec_base } => {
                if let Some(why) = network.refusal() {
                    return self
                        .download_web_placed(url, sha256, &Placement::Refused(why), op)
                        .await;
                }
                // A source the download cache holds needs no network.
                if let Some(path) = self.cached_web(url, sha256)? {
                    return Ok((path, false));
                }
                let (namespace, held) = network.hold(exec_base).await?;
                _held = held;
                Placement::Namespace(namespace)
            }
        };
        self.download_web_placed(url, sha256, &placement, op).await
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
    /// Where the box the build runs for fetches its sources, if it runs for
    /// a box (NET-155). A source is fetched there, so the box's egress
    /// verdict decides the fetch. `None` fetches it as the caller's own
    /// traffic.
    pub place: Option<SourcePlace<'a>>,
}

/// Fetches `url` at `place` and logs where it came from, for a box's build
/// (NET-155). The log names the URL's host and never quotes the URL.
async fn fetch_placed<SF: SourceFetcher>(
    fetcher: &SF,
    url: &Url,
    sha256: &str,
    place: Option<SourcePlace<'_>>,
    op: &OpTracker,
) -> Result<PathBuf, anyhow::Error> {
    let fetched = fetcher.download_web(url.as_str(), sha256, place, op).await;
    let host = url.host_str().unwrap_or_default();
    let leaf = match place {
        Some(SourcePlace::Leaf(leaf)) => Some(leaf),
        _ => None,
    };
    if let Some(leaf) = leaf {
        // The leaf's own name is the box's id in the tree.
        let box_id = leaf
            .dir()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
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
            // The error can quote the request URL, with its credentials and
            // its signed query.
            Err(e) => info!(
                %box_id, host, %leaf,
                error = %crate::specs::strip_urls(&format!("{e:#}")),
                "a web source for a box could not be fetched in the box's classifier leaf",
            ),
        }
    } else if place.is_some() {
        match &fetched {
            Ok((_, connected)) => info!(
                host,
                connected, "fetched a web source for a box on the box's own network",
            ),
            Err(e) => info!(
                host,
                error = %crate::specs::strip_urls(&format!("{e:#}")),
                "a web source for a box could not be fetched on the box's own network",
            ),
        }
    }
    fetched.map(|(path, _)| path)
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
                        let cached_path =
                            fetch_placed(self.remote_fetcher, &url, sha256, self.place, &op)
                                .await?;

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

                        // The Cloud Storage client opens its connections
                        // where it runs. A box's fetch must open them at its
                        // place, so it reads the object over `https` there.
                        let cached_path = if self.place.is_some() {
                            let object = Url::parse(&common::gcs_object_url(bucket_id, file_name)?)
                                .context("Failed to name a gs:// object as a URL")?;
                            fetch_placed(self.remote_fetcher, &object, sha256, self.place, &op)
                                .await?
                        } else {
                            self.remote_fetcher
                                .download_gcs(bucket_id.to_string(), file_name, sha256, &op)
                                .await?
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
    /// It records the classifier leaf each fetch was asked to run in, and
    /// each URL it was asked for.
    #[derive(Debug)]
    struct FixtureFetcher(
        PathBuf,
        std::sync::Mutex<Vec<Option<ClassifierLeaf>>>,
        std::sync::Mutex<Vec<String>>,
    );

    impl FixtureFetcher {
        fn new(archive: PathBuf) -> Self {
            Self(archive, Default::default(), Default::default())
        }
    }

    impl SourceFetcher for FixtureFetcher {
        async fn download_web(
            &self,
            url: &str,
            _sha256: &str,
            place: Option<SourcePlace<'_>>,
            _op: &OpTracker,
        ) -> anyhow::Result<(PathBuf, bool)> {
            let leaf = match place {
                Some(SourcePlace::Leaf(leaf)) => Some(leaf.clone()),
                _ => None,
            };
            self.1.lock().unwrap().push(leaf);
            self.2.lock().unwrap().push(url.to_string());
            Ok((self.0.clone(), place.is_some()))
        }

        async fn download_gcs(
            &self,
            bucket_id: String,
            file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            self.2
                .lock()
                .unwrap()
                .push(format!("client:{bucket_id}/{file}"));
            Ok(self.0.clone())
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
            place: None,
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
            sandbox2::config::Verdict::Deny,
        );

        for given in [Some(&leaf), None] {
            let materialized = SourceLoad {
                source: &source,
                remote_fetcher: &fetcher,
                into: None,
                place: given.map(SourcePlace::Leaf),
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

    /// NET-155: a `gs://` source loaded for a box is read over `https` at
    /// the box's place, on the box's own network or in its leaf, so the
    /// box's rules decide it. A load for no box stays on the Cloud Storage
    /// client, as its caller's own traffic.
    #[tokio::test]
    async fn a_gs_source_for_a_box_is_fetched_at_the_boxs_place() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let cache = Cache::at_dir(tmp.path().join("cache")).unwrap();
        let archive = tarball(tmp.path(), &[("pkg-1.0/README", b"readme")]);
        let fetcher = FixtureFetcher::new(archive);
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
                url: "gs://sources-bucket/dir/pkg-1.0.tar.gz".into(),
                sha256: SHA.into(),
                url_pos: None,
                sha256_pos: None,
            },
            extract: true,
            strip_prefix: Some("pkg-1.0".into()),
        };
        let leaf = ClassifierLeaf::under(
            Path::new("/sys/fs/cgroup/minimald.slice"),
            "box-1",
            sandbox2::config::Verdict::Allow,
        );
        let network = crate::BuildNetwork::none();

        for place in [
            Some(SourcePlace::Leaf(&leaf)),
            Some(SourcePlace::Network {
                network: &network,
                exec_base: tmp.path(),
            }),
            None,
        ] {
            SourceLoad {
                source: &source,
                remote_fetcher: &fetcher,
                into: None,
                place,
            }
            .run(&opts)
            .await
            .unwrap();
        }
        let web = "https://storage.googleapis.com/sources-bucket/dir/pkg-1.0.tar.gz";
        assert_eq!(
            *fetcher.2.lock().unwrap(),
            vec![web, web, "client:sources-bucket/dir/pkg-1.0.tar.gz"]
        );
    }

    /// NET-155: a box with no network has nowhere to open a connection. A
    /// source the download cache lacks fails before it leaves, and the error
    /// names the host and the reason. Rules that admit nothing fail the same
    /// way, with their own reason. Neither case looks for a network.
    #[tokio::test]
    async fn a_fetch_on_a_closed_network_sends_nothing() {
        let tmp = TempDir::new().unwrap();
        let storage = common::RemoteStorage::new(tmp.path().join("downloads"), false)
            .await
            .unwrap();
        let op = OpTracker::new_root();
        let denied =
            crate::BuildNetwork::new(|| panic!("no network is made")).with_denies_all(true);
        for (network, why) in [
            (crate::BuildNetwork::none(), common::NO_NETWORK),
            (denied, common::RULES_REFUSE),
        ] {
            let place = SourcePlace::Network {
                network: &network,
                exec_base: tmp.path(),
            };
            let refused = storage
                .download_web(
                    "https://sources.example.invalid/a.tar.gz",
                    SHA,
                    Some(place),
                    &op,
                )
                .await
                .expect_err("nothing leaves");
            assert_eq!(
                refused.to_string(),
                format!("could not connect to sources.example.invalid:443: {why}"),
                "{refused:#}"
            );
        }
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
            _place: Option<SourcePlace<'_>>,
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
            sandbox2::config::Verdict::Deny,
        );
        let capture = CaptureEvents::default();
        let _guard = tracing::subscriber::set_default(capture.clone());

        let result = SourceLoad {
            source: &source,
            remote_fetcher: &LeakyFailFetcher,
            into: None,
            place: Some(SourcePlace::Leaf(&leaf)),
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
