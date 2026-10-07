use std::collections::BTreeSet;

use anyhow::anyhow;
use graph::{BuildSpecRef, Transitives};
use lcache::{CacheErr, EntryMeta, MetaInner, PendingDir};
use rcache::RemoteCache;

use crate::{Error, Options, Runnable, SpecBuild};

/// The return value of a successful patched build.
pub struct PatchedBuildResult {
    pub outputs: PendingDir,
    pub build_ms: usize,
    pub meta: EntryMeta,
}

/// Builds a spec, resolving each dependency to its most recent cached build by
/// name, falling back to its exact spec-hash entry. Every dependency that has
/// neither is reported together in one error.
///
/// This breaks the normal caching model but is useful for development workflows
/// where you want to test a build against locally-modified dependencies.
pub struct PatchedBuild<'a, SF: crate::SourceFetcher> {
    /// The spec to be built.
    pub spec: &'a BuildSpecRef,
    /// A fetcher which can be used to fetch sources.
    pub remote_fetcher: &'a SF,

    /// Optional async writer that receives a copy of the sandbox's stdout stream.
    pub stdout_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,
    /// Optional async writer that receives a copy of the sandbox's stderr stream.
    pub stderr_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,

    /// The remote cache to consult before reporting a dependency missing.
    /// When `None`, dependency resolution stays purely local.
    pub remote_cache: Option<&'a RemoteCache<common::fetchers::AnyBackend>>,
}

impl<'a, SF: crate::SourceFetcher> Runnable for PatchedBuild<'a, SF> {
    type Result = PatchedBuildResult;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();

        // Select dependencies by name to be used in the build.
        let mut dependencies = BTreeSet::new();
        let transitives = Transitives::new(opts.graph, self.spec, true);
        let build_deps: Vec<_> = transitives
            .transitive_runtime_deps
            .keys()
            .to_owned()
            .collect();

        let mut missing = Vec::new();
        for bsr in build_deps.iter() {
            let dep_build = opts.graph.get(bsr).unwrap();
            let cache_dir = match opts.cache.unsafe_get_build_by_name(&dep_build.name) {
                Ok(entry) => entry,
                Err(by_name) => {
                    warn_unless_not_found(&dep_build.name, "by name", &by_name);
                    match opts.cache.read_dir(&opts.graph.spec_hash(bsr)) {
                        Ok(entry) => entry,
                        Err(by_hash) => {
                            warn_unless_not_found(&dep_build.name, "by spec hash", &by_hash);
                            // A patched build exists to pick up locally-modified
                            // dependencies, so a local build (by name, then by
                            // spec hash) always wins. Only a dependency absent
                            // in both local caches falls through to the remote
                            // cache; a dependency absent everywhere is reported.
                            match self.remote_cache {
                                Some(remote_cache) => {
                                    let spec_hash = opts.graph.spec_hash(bsr);
                                    let (fetch_time, pending_dir) = match remote_cache
                                        .materialize(&spec_hash, &opts.cache, &dep_build.name)
                                        .await
                                    {
                                        Ok(fetched) => fetched,
                                        Err(e) => {
                                            // A plain miss is already reported in
                                            // the final error; only warn on a real
                                            // failure (fetch, hash mismatch, IO).
                                            if !matches!(e, rcache::Error::NotFound) {
                                                tracing::warn!(
                                                    dep = %dep_build.name,
                                                    error = %e,
                                                    "patched-build remote-cache lookup failed"
                                                );
                                            }
                                            missing.push(dep_build.name.clone());
                                            continue;
                                        }
                                    };
                                    pending_dir
                                        .finalize(EntryMeta {
                                            inner: MetaInner::Spec(dep_build.name.clone()),
                                            fetched: true,
                                            fetch_ms: Some(fetch_time.as_millis() as usize),
                                            origin: Some(dep_build.from.as_ref().clone()),
                                            ..Default::default()
                                        })
                                        .map_err(Error::Cache)?;
                                    opts.cache.read_dir(&spec_hash).map_err(Error::Cache)?
                                }
                                None => {
                                    missing.push(dep_build.name.clone());
                                    continue;
                                }
                            }
                        }
                    }
                }
            };
            dependencies.insert(cache_dir.path().to_path_buf());
        }

        if !missing.is_empty() {
            return Err(Error::Other(anyhow!(
                "patched-build could not find builds of: {}, locally or in the remote cache",
                missing.join(", ")
            )));
        }

        let res = SpecBuild {
            spec: self.spec,
            override_deps: Some(dependencies),
            remote_fetcher: self.remote_fetcher,
            stdout_writer: self.stdout_writer.take(),
            stderr_writer: self.stderr_writer.take(),
            cancel: tokio_util::sync::CancellationToken::new(),
            cpu_weight: None,
        }
        .run(opts)
        .await?;

        Ok(PatchedBuildResult {
            meta: EntryMeta {
                inner: MetaInner::Spec(build.name.clone()),
                breaker_build: true,
                build_ms: Some(res.build_ms),
                origin: Some(build.from.as_ref().clone()),
                ..Default::default()
            },
            outputs: res.outputs,
            build_ms: res.build_ms,
        })
    }
}

/// Logs a dependency lookup failure that is not a plain cache miss, so an IO
/// error or a corrupt cache is not mistaken for an unbuilt dependency.
fn warn_unless_not_found(name: &str, lookup: &str, err: &CacheErr) {
    if !matches!(err, CacheErr::NotFound) {
        tracing::warn!(dep = name, lookup, error = ?err, "patched-build dependency lookup failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceFetcher;
    use common::{SpecHash, archive};
    use decode::Layer;
    use graph::Graph;
    use indoc::indoc;
    use lcache::{Cache, LocalDir};
    use rcache::{INDEX_FILENAME, IndexFile, IndexSource, RemoteCache};
    use tempfile::TempDir;

    /// A [`SourceFetcher`] that must never be called: the paths exercised here
    /// short-circuit before any source is fetched.
    #[derive(Debug)]
    struct UnusedFetcher;

    impl SourceFetcher for UnusedFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &ot::OpTracker,
        ) -> anyhow::Result<std::path::PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &ot::OpTracker,
        ) -> anyhow::Result<std::path::PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }
    }

    fn graph_from(ncl: &str) -> Graph {
        Graph::new()
            .ingest(Layer::new_for_test(ncl.to_string()).unwrap())
            .unwrap()
    }

    fn patched_build<'a>(
        spec: &'a BuildSpecRef,
        fetcher: &'a UnusedFetcher,
    ) -> PatchedBuild<'a, UnusedFetcher> {
        PatchedBuild {
            spec,
            remote_fetcher: fetcher,
            stdout_writer: None,
            stderr_writer: None,
            remote_cache: None,
        }
    }

    /// Fakes a completed build of `package` whose cache entry is recorded
    /// under `meta_name` rather than the package's own name, so a by-name
    /// lookup for `package` misses while its spec-hash entry still exists.
    fn fake_build(cache: &Cache<LocalDir>, graph: &Graph, package: &str, meta_name: &str) {
        let hash = graph.spec_hash(graph.by_name(package).expect("package in graph"));
        let pending = cache.write_dir(&hash).expect("write cache dir");
        std::fs::write(pending.path().join("marker"), b"x").expect("write build output");
        pending
            .finalize(EntryMeta {
                inner: MetaInner::Spec(meta_name.to_string()),
                ..Default::default()
            })
            .expect("finalize cache entry");
    }

    /// Serializes a one-file payload as a compressed artifact and returns the
    /// index wire bytes mapping every one of `spec_hashes ->` it, plus the
    /// artifact's sha256 and bytes.
    fn remote_artifact(spec_hashes: &[SpecHash]) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("remote.txt"), b"from remote cache").unwrap();
        let (mut f, sha256) = archive::compress_dir(dir.path(), None, &None).unwrap();
        let mut artifact = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut artifact).unwrap();

        let mut index = IndexFile::default();
        index.extend(spec_hashes.iter().map(|h| (h.clone(), sha256)));
        let mut index_bytes = Vec::new();
        index.write_to(&mut index_bytes).unwrap();

        (index_bytes, sha256, artifact)
    }

    /// A throwaway HTTP/1.1 server resolving `GET /<path>` against `objects`;
    /// every other path 404s. Returns a base URL ending in `/`, so
    /// [`RemoteCache::new_any_https`] joins object names against it correctly.
    fn serve_objects(objects: Vec<(String, Vec<u8>)>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let req = String::from_utf8_lossy(&buf);
                let hit = objects
                    .iter()
                    .find(|(path, _)| req.starts_with(&format!("GET /{path} ")));
                let (status, body): (&str, &[u8]) = match hit {
                    Some((_, bytes)) => ("200 OK", bytes),
                    None => ("404 Not Found", b""),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/")
    }

    /// Builds a [`RemoteCache`] over a local server that serves an artifact
    /// for each of `spec_hashes` and nothing else.
    async fn remote_cache_for(
        spec_hashes: &[SpecHash],
    ) -> RemoteCache<common::fetchers::AnyBackend> {
        let (index_bytes, sha256, artifact) = remote_artifact(spec_hashes);
        let objects = vec![
            (INDEX_FILENAME.to_string(), index_bytes),
            (format!("{}.zst", hex::encode(sha256)), artifact),
        ];
        let base = serve_objects(objects);
        RemoteCache::new_any_https(&base, None, None, IndexSource::Root)
            .await
            .expect("build remote cache over local server")
            .with_fetch_retries(0)
    }

    /// A dependency with no local build but a remote-cache entry is resolved
    /// from the remote cache and not reported missing.
    #[tokio::test]
    async fn resolves_dependency_from_remote_cache_on_local_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        // dep-a resolves by name; dep-b is absent locally but lives in the
        // remote cache; dep-c is absent everywhere.
        fake_build(&cache, &dg, "dep-a", "dep-a");

        let bsr = *dg.by_name("top").unwrap();
        let dep_b_bsr = dg.by_name("dep-b").unwrap();
        let dep_b_hash = dg.spec_hash(dep_b_bsr);
        let remote_cache = remote_cache_for(std::slice::from_ref(&dep_b_hash)).await;

        let fetcher = UnusedFetcher;
        let mut pb = PatchedBuild {
            spec: &bsr,
            remote_fetcher: &fetcher,
            stdout_writer: None,
            stderr_writer: None,
            remote_cache: Some(&remote_cache),
        };
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let err = pb.run(&opts).await.err().expect("dep-c is missing");
        let msg = format!("{err}");
        assert!(
            msg.contains("dep-c") && !msg.contains("dep-b"),
            "only dep-c should be reported missing, got: {msg}"
        );
        assert!(
            msg.contains("locally or in the remote cache"),
            "the error must say how to recover, got: {msg}"
        );

        // dep-b was materialized from the remote cache and finalized into the
        // local cache as a fetched entry.
        let entry = cache
            .read_dir(&dep_b_hash)
            .expect("dep-b is in the local cache");
        assert!(entry.path().join("remote.txt").exists());
        let meta = cache.read_meta(&dep_b_hash).expect("dep-b meta");
        assert!(meta.fetched, "dep-b must be recorded as fetched");
    }

    /// A local build, by name or by spec hash, wins over a remote-cache entry
    /// for the same dependency: the remote cache is never consulted.
    #[tokio::test]
    async fn local_build_wins_over_remote_cache() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        // dep-a and dep-c resolve by name; dep-b only by spec hash.
        fake_build(&cache, &dg, "dep-a", "dep-a");
        fake_build(&cache, &dg, "dep-b", "some-other-name");
        fake_build(&cache, &dg, "dep-c", "dep-c");

        let hashes: Vec<SpecHash> = ["dep-a", "dep-b", "dep-c"]
            .iter()
            .map(|n| dg.spec_hash(dg.by_name(n).unwrap()))
            .collect();
        // The remote cache serves all three dependencies too.
        let remote_cache = remote_cache_for(&hashes).await;

        let bsr = *dg.by_name("top").unwrap();
        let fetcher = UnusedFetcher;
        let mut pb = PatchedBuild {
            spec: &bsr,
            remote_fetcher: &fetcher,
            stdout_writer: None,
            stderr_writer: None,
            remote_cache: Some(&remote_cache),
        };
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        pb.run(&opts).await.expect("all dependencies are local");

        for hash in &hashes {
            let meta = cache.read_meta(hash).expect("local meta");
            assert!(
                !meta.fetched,
                "a local build must not be replaced by a fetch"
            );
            let entry = cache.read_dir(hash).expect("local entry");
            assert!(entry.path().join("marker").exists());
            assert!(!entry.path().join("remote.txt").exists());
        }
    }

    /// A remote cache with no entry for a locally-missing dependency still
    /// reports it missing.
    #[tokio::test]
    async fn reports_missing_when_remote_cache_lacks_dependency() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        fake_build(&cache, &dg, "dep-a", "dep-a");

        let bsr = *dg.by_name("top").unwrap();
        // Serve an index for an unrelated hash, so the remote cache has no
        // entry for dep-b or dep-c.
        let remote_cache = remote_cache_for(&[SpecHash::from_bytes([0xEE; 32])]).await;

        let fetcher = UnusedFetcher;
        let mut pb = PatchedBuild {
            spec: &bsr,
            remote_fetcher: &fetcher,
            stdout_writer: None,
            stderr_writer: None,
            remote_cache: Some(&remote_cache),
        };
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let err = pb
            .run(&opts)
            .await
            .err()
            .expect("dep-b and dep-c are missing");
        let msg = format!("{err}");
        for missing in ["dep-b", "dep-c"] {
            assert!(
                msg.contains(missing),
                "the error must name every missing dependency ({missing}), got: {msg}"
            );
        }
        assert!(
            !msg.contains("dep-a"),
            "dep-a is cached by name and must not be reported missing, got: {msg}"
        );
    }

    /// A top-level pure collection with three runtime dependencies, so
    /// dependency resolution runs without any sandbox build work.
    const THREE_DEPS: &str = indoc! {r#"
        let {BuildSpec, ..} = import "minimal.ncl" in
        let dep_a = { name = "dep-a", build_deps = [], cmd = "" } | BuildSpec in
        let dep_b = { name = "dep-b", build_deps = [], cmd = "" } | BuildSpec in
        let dep_c = { name = "dep-c", build_deps = [], cmd = "" } | BuildSpec in
        {
            name = "top",
            build_deps = [],
            runtime_deps = [dep_a, dep_b, dep_c],
            cmd = "",
        } | BuildSpec
    "#};

    /// A dependency with no by-name build but a spec-hash entry is still used,
    /// and every dependency that has no local build at all is reported in one
    /// error rather than one per attempt.
    #[test]
    fn reports_every_missing_dependency_and_uses_spec_hash_fallback() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        // dep-a resolves by name; dep-b only by spec hash; dep-c is absent.
        fake_build(&cache, &dg, "dep-a", "dep-a");
        fake_build(&cache, &dg, "dep-b", "some-other-name");

        let bsr = *dg.by_name("top").unwrap();
        let fetcher = UnusedFetcher;
        let mut pb = patched_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let err = futures::executor::block_on(pb.run(&opts))
            .err()
            .expect("PatchedBuild::run should fail when a dependency is missing");

        let msg = format!("{err}");
        assert!(
            msg.contains("dep-c"),
            "the error must name the missing dependency, got: {msg}"
        );
        assert!(
            !msg.contains("dep-a"),
            "dep-a is cached by name and must not be reported missing, got: {msg}"
        );
        assert!(
            !msg.contains("dep-b"),
            "dep-b is cached by spec hash and must not be reported missing, got: {msg}"
        );
    }

    /// Several missing dependencies are collected into one error rather than
    /// the first miss aborting the lookup.
    #[test]
    fn reports_several_missing_dependencies_in_one_error() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        // Only dep-a is built; dep-b and dep-c are both absent.
        fake_build(&cache, &dg, "dep-a", "dep-a");

        let bsr = *dg.by_name("top").unwrap();
        let fetcher = UnusedFetcher;
        let mut pb = patched_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let err = futures::executor::block_on(pb.run(&opts))
            .err()
            .expect("PatchedBuild::run should fail when dependencies are missing");

        let msg = format!("{err}");
        for missing in ["dep-b", "dep-c"] {
            assert!(
                msg.contains(missing),
                "the error must name every missing dependency ({missing}), got: {msg}"
            );
        }
        assert!(
            !msg.contains("dep-a"),
            "dep-a is cached by name and must not be reported missing, got: {msg}"
        );
        assert!(
            msg.contains("locally or in the remote cache"),
            "the error must say how to recover, got: {msg}"
        );
    }

    /// When every dependency resolves — some by name, some only by spec hash —
    /// the build proceeds.
    #[test]
    fn resolves_dependencies_by_name_or_spec_hash() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(THREE_DEPS);

        fake_build(&cache, &dg, "dep-a", "dep-a");
        fake_build(&cache, &dg, "dep-b", "some-other-name");
        fake_build(&cache, &dg, "dep-c", "dep-c");

        let bsr = *dg.by_name("top").unwrap();
        let fetcher = UnusedFetcher;
        let mut pb = patched_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let result =
            futures::executor::block_on(pb.run(&opts)).expect("all dependencies are resolvable");

        // `top` is a pure collection, so no build work is performed.
        assert_eq!(result.build_ms, 0);
    }
}
