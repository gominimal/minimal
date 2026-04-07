use std::collections::HashSet;

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
        let mut dependencies = HashSet::new();
        let transitives = Transitives::new(opts.graph, self.spec, true);
        let build_deps: Vec<_> = transitives
            .transitive_runtime_deps
            .keys()
            .to_owned()
            .collect();

        for bsr in build_deps.iter() {
            let dep_build = opts.graph.get(bsr).unwrap();
            let cache_dir = opts
                .cache
                .unsafe_get_build_by_name(&dep_build.name)
                .map_err(|e| {
                    Error::Other(anyhow!("resolving dep '{}' by name: {}", dep_build.name, e))
                })?;
            dependencies.insert(cache_dir.path().to_path_buf());
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
