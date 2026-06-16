use std::{collections::HashSet, path::PathBuf, time::Instant};

use crate::{Error, Materialized, Options, Runnable, SubsetBuild};
use anyhow::anyhow;
use common::Target;
use globset::GlobSet;
use graph::{BuildDep, BuildSpec, BuildSpecRef, SubsetInput, Transitives};
use lcache::{CacheErr, MetaInner, PendingDir};
use ot::{OpTracker, Operation};
use sandbox2::config::SandboxMapped;
use tracing::info;

/// The return value of a successful build of a build-spec.
pub struct SpecBuildResult {
    pub outputs: PendingDir,
    pub build_ms: usize,
}

/// Builds a spec, storing the resulting outputs in the cache.
pub struct SpecBuild<'a, SF: crate::SourceFetcher> {
    /// The spec to be built.
    pub spec: &'a BuildSpecRef,
    /// A fetcher which can be used to fetch sources.
    pub remote_fetcher: &'a SF,

    /// If set, overrides the set of dependencies injected into the build.
    /// If unset, the necessary dependencies are computed automatically.
    ///
    /// Does not override `Local` or `Source` variant build_deps - those will
    /// always be made present automatically.
    pub override_deps: Option<HashSet<PathBuf>>,

    /// Optional async writer that receives a copy of the sandbox's stdout stream.
    pub stdout_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,
    /// Optional async writer that receives a copy of the sandbox's stderr stream.
    pub stderr_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,

    /// Cancellation token to stop the build.
    pub cancel: tokio_util::sync::CancellationToken,

    /// CPU shares, for partitioning CPU when the system is contended. Maps roughly to
    /// cgroups v2 cpu.weights.
    pub cpu_weight: Option<u64>,
}

impl<'a, SF: crate::SourceFetcher> SpecBuild<'a, SF> {
    async fn build_deps_mapped(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
        op: &OpTracker,
    ) -> Result<Vec<SandboxMapped>, Error> {
        let mut build_deps = Vec::new();

        for input in build.build_deps.iter() {
            match input {
                BuildDep::Local { full_path, .. } => {
                    build_deps.push(SandboxMapped::FileCopy(full_path.to_path_buf()))
                }
                BuildDep::Source(source) => {
                    let resolved_src = crate::SourceLoad {
                        source,
                        remote_fetcher: self.remote_fetcher,
                        into: None,
                    }
                    .run(&Options {
                        ot: Some(op.to_owned()),
                        cache: opts.cache.clone(),
                        graph: opts.graph,
                        exec_base: opts.exec_base.clone(),
                    })
                    .await?;
                    match resolved_src {
                        Materialized::Given(_) => unreachable!(),
                        Materialized::File(path) => build_deps.push(SandboxMapped::File(path)),
                        Materialized::TempDir(td) => build_deps.push(SandboxMapped::TempDir(td)),
                    }
                }
                BuildDep::Build(_) => {} // Handled by Transitives
                _ => todo!("input: {:?}", input),
            }
        }
        Ok(build_deps)
    }

    async fn rootfs_mapped(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
    ) -> Result<(HashSet<SandboxMapped>, bool, bool), Error> {
        if let Some(deps) = &self.override_deps {
            return Ok((
                deps.iter().map(|p| SandboxMapped::Dir(p.clone())).collect(),
                true,
                true,
            ));
        }

        let mut dependencies = HashSet::new();
        let transitives = Transitives::new(opts.graph, self.spec, true);

        let (mut needs_dns, mut need_internet) = (false, false);
        let build_deps: Vec<_> = transitives.transitive_runtime_deps.into_iter().collect();
        for (bsr, dep_info) in build_deps.into_iter() {
            match dep_info.outputs {
                // Regular build
                None => {
                    let cache_dir = opts.cache.read_dir(&opts.graph.spec_hash(&bsr)).unwrap();
                    dependencies.insert(SandboxMapped::Dir(cache_dir.path().to_path_buf()));
                }
                // Subset
                Some(outputs) => {
                    let subset = SubsetInput {
                        from: bsr,
                        outputs: outputs.into_iter().collect(),
                    };
                    let subset_hash = opts.graph.subset_hash(&subset);

                    // If the subset exists use it, otherwise build it
                    dependencies.insert(SandboxMapped::Dir(
                        match opts.cache.read_dir(&subset_hash) {
                            Ok(cache_dir) => cache_dir,
                            Err(CacheErr::NotFound) => {
                                let mut sb = SubsetBuild {
                                    subset: &subset,
                                    from_dir: None,
                                };
                                let pending_dir = sb.run(opts).await?;
                                pending_dir.finalize(lcache::EntryMeta {
                                    inner: MetaInner::Subset(subset.as_spec(opts.graph)),
                                    fetched: false,
                                    origin: Some(build.from.as_ref().clone()),
                                    ..Default::default()
                                })?;

                                opts.cache.read_dir(&subset_hash)?
                            }
                            Err(e) => {
                                return Err(e.into());
                            }
                        }
                        .path()
                        .to_path_buf(),
                    ));
                }
            }

            needs_dns |= opts
                .graph
                .get(&bsr)
                .unwrap()
                .abstract_deps
                .get("dns")
                .is_some();
            need_internet |= opts
                .graph
                .get(&bsr)
                .unwrap()
                .abstract_deps
                .get("internet")
                .is_some();
        }

        // We should also consider if the spec being-built needs internet, rather than just its deps.
        needs_dns |= opts
            .graph
            .get(self.spec)
            .unwrap()
            .abstract_deps
            .get("dns")
            .is_some();
        need_internet |= opts
            .graph
            .get(self.spec)
            .unwrap()
            .abstract_deps
            .get("internet")
            .is_some();

        Ok((dependencies, needs_dns, need_internet))
    }

    fn invocations(&self, build: &BuildSpec) -> Result<Vec<(String, Vec<String>)>, Error> {
        if build.cmds.is_empty() || build.cmds[0].is_empty() {
            return Err(Error::Other(anyhow!(
                "cannot build spec: no build command specified"
            )));
        }

        Ok(build
            .cmds
            .iter()
            .filter_map(|e| e.split_at_checked(1))
            .map(|(exec, args)| (exec[0].clone(), args.to_vec()))
            .collect())
    }

    async fn materialize_prebuilt<'b>(
        &mut self,
        opts: &Options<'b>,
        build: &BuildSpec,
    ) -> Result<SpecBuildResult, Error> {
        if let BuildDep::Source(source) = &build.build_deps[0] {
            let start = Instant::now();
            let out_dir = opts
                .cache
                .write_dir(&opts.graph.spec_hash(self.spec))
                .unwrap();
            let resolved_src = crate::SourceLoad {
                source,
                remote_fetcher: self.remote_fetcher,
                into: Some(out_dir),
            }
            .run(opts)
            .await?;

            if let Materialized::Given(d) = resolved_src {
                let build_ms = Instant::now().duration_since(start).as_millis() as usize;
                Ok(SpecBuildResult {
                    outputs: d,
                    build_ms,
                })
            } else {
                panic!(
                    "prebuilt source materialized as non-tempdir: {:?}",
                    resolved_src
                );
            }
        } else {
            panic!("prebuilt input was not source: {:?}", &build.build_deps[0]);
        }
    }
}

impl<'a, SF: crate::SourceFetcher> Runnable for SpecBuild<'a, SF> {
    type Result = SpecBuildResult;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();

        let build_op = OpTracker::new_with_root(&opts.ot).with_op(Operation::PackageBuild {
            name: build.name.clone(),
        });

        // Special case: prebuilts
        if build.is_pure_prebuilt() {
            return self.materialize_prebuilt(opts, build).await;
        }
        if build.is_pure_collection() {
            // A collection is an empty package that only has runtime deps, so lets just commit an empty package
            return Ok(SpecBuildResult {
                outputs: opts.cache.write_dir(&opts.graph.spec_hash(self.spec))?,
                build_ms: 0,
            });
        }
        if build.target != Target::host() {
            return Err(Error::Other(anyhow!(
                "cannot build spec with target {} on {}",
                build.target.as_ref(),
                Target::host().as_ref()
            )));
        }

        let inputs = self.build_deps_mapped(build, opts, &build_op).await?;
        let (rootfs, needs_dns, needs_internet) = self.rootfs_mapped(build, opts).await?;

        let channel = ();

        let mut config = sandbox2::config::Config::new(&build.name)
            .with_isolated_wd(inputs.into_iter())
            .with_rootfs(rootfs.into_iter())
            .with_dns(needs_dns)
            .with_disable_networking(!needs_dns && !needs_internet);
        if let Some(a) = &build.build_args {
            config = config.with_build_args(a.iter());
        }
        if let Some(w) = self.cpu_weight {
            config = config.with_cpu_weight(w);
        }
        let mut sandbox = config.build(&opts.exec_base, channel).await?;
        sandbox.keep_dir(true);

        info!("Building package: {}", build.name);
        let start = Instant::now();
        sandbox
            .run_with_cancel(
                self.invocations(build)?
                    .into_iter()
                    .map(|(program, args)| sandbox2::config::Invocation {
                        executable: program,
                        args,
                        envs: Default::default(),
                    })
                    .collect(),
                self.stdout_writer.take(),
                self.stderr_writer.take(),
                self.cancel.clone(),
            )
            .await?;
        let build_ms = Instant::now().duration_since(start).as_millis() as usize;

        let out_dir = opts
            .cache
            .write_dir(&opts.graph.spec_hash(self.spec))
            .unwrap();

        build_op.set_op(Operation::CollectOutputs {
            name: build.name.clone(),
            outputs: build.outputs.iter().map(|(n, _)| n.clone()).collect(),
        });

        // Build individual globs for each output so we can verify each one matched
        let output_globs: Vec<(String, globset::Glob)> = build
            .outputs
            .iter()
            .map(|(name, o)| {
                globset::GlobBuilder::new(o.glob())
                    .literal_separator(true)
                    .empty_alternates(true)
                    .build()
                    .map(|g| (name.clone(), g))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Other(anyhow!(e)))?;

        {
            // Match the outputs into their final destination
            sandbox.match_outputs_into(
                GlobSet::new(output_globs.iter().map(|(_, g)| g.clone())).unwrap(),
                out_dir.path(),
            )?;

            // Verify each glob matched at least one file
            let mut unmatched: Vec<&str> =
                output_globs.iter().map(|(name, _)| name.as_str()).collect();
            for entry in walkdir::WalkDir::new(out_dir.path()) {
                let entry = entry
                    .map_err(|e| Error::Other(anyhow!("failed to walk output directory: {}", e)))?;
                if entry.file_type().is_dir() {
                    continue;
                }
                let rel_path = entry
                    .path()
                    .strip_prefix(out_dir.path())
                    .expect("path should be under out_dir");
                for (name, glob) in &output_globs {
                    if glob.compile_matcher().is_match(rel_path) {
                        unmatched.retain(|n| n != name);
                    }
                }
                if unmatched.is_empty() {
                    break;
                }
            }
            if !unmatched.is_empty() {
                return Err(Error::Other(anyhow!(
                    "output globs did not match any files: {}",
                    unmatched.join(", ")
                )));
            }
        }

        sandbox.keep_dir(false);
        build_op.set_done();
        Ok(SpecBuildResult {
            outputs: out_dir,
            build_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceFetcher;
    use decode::Layer;
    use graph::{BuildSpecRef, Graph};
    use indoc::indoc;
    use lcache::Cache;
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    /// A [`SourceFetcher`] that must never be called. The build paths exercised
    /// here short-circuit before any source is fetched, so reaching either
    /// method indicates the function (or the test) took an unexpected branch.
    #[derive(Debug)]
    struct UnusedFetcher;

    impl SourceFetcher for UnusedFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }
    }

    fn graph_from(ncl: &str) -> Graph {
        Graph::new()
            .ingest(Layer::new_for_test(ncl.to_string()).unwrap())
            .unwrap()
    }

    fn spec_build<'a>(
        spec: &'a BuildSpecRef,
        fetcher: &'a UnusedFetcher,
    ) -> SpecBuild<'a, UnusedFetcher> {
        SpecBuild {
            spec,
            remote_fetcher: fetcher,
            override_deps: None,
            stdout_writer: None,
            stderr_writer: None,
            cancel: CancellationToken::new(),
            cpu_weight: None,
        }
    }

    /// A spec with no build deps and an empty command is a "pure collection":
    /// running it does no build work and commits an empty output directory.
    #[test]
    fn run_pure_collection_commits_empty_outputs_with_zero_build_time() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(indoc! {r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            {
                name = "collection",
                build_deps = [],
                cmd = "",
            } | BuildSpec
        "#});
        let bsr = *dg.by_name("collection").unwrap();
        let fetcher = UnusedFetcher;
        let mut sb = spec_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
        };

        let result = futures::executor::block_on(sb.run(&opts)).unwrap();

        // No build is executed for a collection, so no time is spent building...
        assert_eq!(result.build_ms, 0);
        // ...and the caller is handed a real, usable output directory.
        assert!(
            result.outputs.path().is_dir(),
            "a committed collection must yield an existing output directory"
        );
    }

    /// A spec whose declared target is not the host cannot be built, and the
    /// error must name the offending target so the caller understands why.
    #[test]
    fn run_rejects_spec_targeting_a_non_host_system() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        // amd64/macos is never a supported host (macOS hosts are arm64 only),
        // so this spec is unbuildable on whatever host runs the test suite.
        let dg = graph_from(indoc! {r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            {
                name = "cross",
                build_deps = [],
                cmd = "echo hi",
                target = "amd64/macos",
            } | BuildSpec
        "#});
        let bsr = *dg.by_name("cross").unwrap();
        let fetcher = UnusedFetcher;
        let mut sb = spec_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
        };

        let err = futures::executor::block_on(sb.run(&opts))
            .err()
            .expect("SpecBuild::run should fail for an unbuildable target");

        let msg = format!("{err}");
        assert!(
            msg.contains("amd64/macos"),
            "error should name the unbuildable target, got: {msg}"
        );
    }
}
