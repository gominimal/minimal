use std::collections::BTreeSet;

use anyhow::anyhow;
use graph::{BuildSpecRef, Transitives};
use lcache::{EntryMeta, MetaInner, PendingDir};

use crate::{Error, Options, Runnable, SpecBuild};

/// The return value of a successful patched build.
pub struct PatchedBuildResult {
    pub outputs: PendingDir,
    pub build_ms: usize,
    pub meta: EntryMeta,
}

/// Builds a spec, resolving dependencies by name from the most recent cached
/// build of each dependency rather than by spec hash.
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
                Err(_) => match opts.cache.read_dir(&opts.graph.spec_hash(bsr)) {
                    Ok(entry) => entry,
                    Err(_) => {
                        missing.push(dep_build.name.clone());
                        continue;
                    }
                },
            };
            dependencies.insert(cache_dir.path().to_path_buf());
        }

        if !missing.is_empty() {
            return Err(Error::Other(anyhow!(
                "patched-build needs local builds of: {}; run 'min package build {}' first",
                missing.join(", "),
                missing.join(" ")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceFetcher;
    use decode::Layer;
    use graph::Graph;
    use indoc::indoc;
    use lcache::{Cache, LocalDir};
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
