use std::{collections::HashSet, path::PathBuf, time::Instant};

use crate::{Error, Materialized, Options, Runnable, SubsetBuild};
use anyhow::anyhow;
use cache::{CacheErr, MetaInner, PendingDir};
use common::Target;
use globset::GlobSet;
use graph::{BuildSpec, BuildSpecInput, BuildSpecRef, SubsetInput, Transitives};
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
    /// Does not override `Local` or `Source` variant inputs - those will
    /// always be made present automatically.
    pub override_deps: Option<HashSet<PathBuf>>,
}

impl<'a, SF: crate::SourceFetcher> SpecBuild<'a, SF> {
    async fn inputs_mapped(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
    ) -> Result<Vec<SandboxMapped>, Error> {
        let mut inputs = Vec::new();

        for input in build.inputs.iter() {
            match input {
                BuildSpecInput::Local { full_path, .. } => {
                    inputs.push(SandboxMapped::File(full_path.to_path_buf()))
                }
                BuildSpecInput::Source(source) => {
                    let resolved_src = crate::SourceLoad {
                        source,
                        remote_fetcher: self.remote_fetcher,
                        into: None,
                    }
                    .run(opts)
                    .await?;
                    match resolved_src {
                        Materialized::Given(_) => unreachable!(),
                        Materialized::File(path) => inputs.push(SandboxMapped::File(path)),
                        Materialized::TempDir(td) => inputs.push(SandboxMapped::TempDir(td)),
                    }
                }
                BuildSpecInput::Build(_) => {} // Handled by Transitives
                _ => todo!("input: {:?}", input),
            }
        }
        Ok(inputs)
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
                                pending_dir.finalize(cache::EntryMeta {
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
        if let BuildSpecInput::Source(source) = &build.inputs[0] {
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
            panic!("prebuilt input was not source: {:?}", &build.inputs[0]);
        }
    }
}

impl<'a, SF: crate::SourceFetcher> Runnable for SpecBuild<'a, SF> {
    type Result = SpecBuildResult;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();

        let span = tracing::info_span!(
            "build",
            "indicatif.pb_show" = tracing::field::Empty,
            "package" = build.name,
        );
        let _enter = span.enter();

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

        let inputs = self.inputs_mapped(build, opts).await?;
        let (mut rootfs, needs_dns, _need_internet) = self.rootfs_mapped(build, opts).await?;
        // TODO: Plumb need_internet

        let synth_files = opts.cache.temp_dir()?;
        if needs_dns {
            common::synth_dns_config(synth_files.path()).map_err(anyhow::Error::from)?;
        }
        rootfs.insert(SandboxMapped::TempDir(synth_files));

        let mut config = sandbox2::config::Config::new(&build.name)
            .with_isolated_wd(inputs.into_iter())
            .with_rootfs(rootfs.into_iter());
        if let Some(a) = &build.build_args {
            config = config.with_build_args(a.iter());
        }
        let mut sandbox = config.build(&opts.exec_base).await?;
        sandbox.keep_dir(true);

        info!("Building package: {}", build.name);
        let start = Instant::now();
        sandbox.run(
            self.invocations(build)?
                .into_iter()
                .map(|(program, args)| sandbox2::config::Invocation {
                    executable: program,
                    args,
                    envs: Default::default(),
                })
                .collect(),
        )?;
        let build_ms = Instant::now().duration_since(start).as_millis() as usize;

        let out_dir = opts
            .cache
            .write_dir(&opts.graph.spec_hash(self.spec))
            .unwrap();

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
            let span = tracing::info_span!(
                "collect_outputs",
                "indicatif.pb_show" = tracing::field::Empty,
                "outputs" = {
                    let s = output_globs
                        .iter()
                        .map(|g| g.0.clone())
                        .collect::<Vec<_>>()
                        .join(" ");
                    match s.char_indices().nth(30) {
                        Some((idx, _)) => format!("{}...", &s[..idx]),
                        None => s.to_string(),
                    }
                },
            );
            let _enter = span.enter();

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
        Ok(SpecBuildResult {
            outputs: out_dir,
            build_ms,
        })
    }
}
