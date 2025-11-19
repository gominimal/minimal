use std::{collections::HashSet, path::PathBuf};

use crate::{Error, Materialized, Options, Runnable, SubsetBuild};
use cache::{CacheErr, MetaInner, PendingDir};
use graph::{BuildSpec, BuildSpecInput, BuildSpecRef, SubsetInput, Transitives};
use tempfile::TempDir;
use tracing::info;

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
    async fn inputs(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
    ) -> Result<(Vec<build_sandbox::Input>, Vec<TempDir>), Error> {
        let mut inputs = Vec::new();
        let mut temp_dirs = Vec::new();

        for input in build.inputs.iter() {
            match input {
                BuildSpecInput::Local { full_path, .. } => {
                    inputs.push(build_sandbox::Input::File(full_path.to_path_buf()))
                }
                BuildSpecInput::Source(source) => {
                    let resolved_src = crate::SourceLoad {
                        source,
                        remote_fetcher: self.remote_fetcher,
                    }
                    .run(opts)
                    .await?;
                    match resolved_src {
                        Materialized::File(path) => inputs.push(build_sandbox::Input::File(path)),
                        Materialized::TempDir(td) => {
                            inputs.push(build_sandbox::Input::Dir(td.path().to_path_buf()));
                            temp_dirs.push(td);
                        }
                    }
                }
                BuildSpecInput::Build(_) => {} // Handled by Transitives
                _ => todo!("input: {:?}", input),
            }
        }
        Ok((inputs, temp_dirs))
    }

    async fn dependencies(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
    ) -> Result<(HashSet<PathBuf>, bool), Error> {
        if let Some(deps) = &self.override_deps {
            return Ok((deps.clone(), true));
        }

        let mut dependencies = HashSet::new();
        let transitives = Transitives::new(opts.graph, self.spec, true);

        let mut needs_dns = false;
        let build_deps: Vec<_> = transitives.transitive_runtime_deps.into_iter().collect();
        for (bsr, dep_info) in build_deps.into_iter() {
            match dep_info.outputs {
                // Regular build
                None => {
                    let cache_dir = opts.cache.read_dir(&opts.graph.spec_hash(&bsr)).unwrap();
                    dependencies.insert(cache_dir.path().to_path_buf());
                }
                // Subset
                Some(outputs) => {
                    let subset = SubsetInput {
                        from: bsr,
                        outputs: outputs.into_iter().collect(),
                    };
                    let subset_hash = opts.graph.subset_hash(&subset);

                    // If the subset exists use it, otherwise build it
                    dependencies.insert(
                        match opts.cache.read_dir(&subset_hash) {
                            Ok(cache_dir) => cache_dir,
                            Err(CacheErr::NotFound) => {
                                let mut sb = SubsetBuild { subset: &subset };
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
                    );
                }
            }

            needs_dns |= opts
                .graph
                .get(&bsr)
                .unwrap()
                .abstract_deps
                .get("dns")
                .is_some();
        }
        Ok((dependencies, needs_dns))
    }

    fn invocation(&self, build: &BuildSpec) -> Result<(String, Vec<String>), Error> {
        let cmd_parts: Vec<String> =
            shlex::split(&build.cmd).unwrap_or_else(|| vec![build.cmd.clone()]);
        let (executable, args) = if !cmd_parts.is_empty() {
            let exe = cmd_parts[0].clone();
            let args = cmd_parts[1..].to_vec();
            (exe, args)
        } else {
            (build.cmd.clone(), vec![])
        };

        Ok((executable, args))
    }
}

impl<'a, SF: crate::SourceFetcher> Runnable for SpecBuild<'a, SF> {
    type Result = PendingDir;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();
        let (inputs, mut temp_dirs) = self.inputs(build, opts).await?;
        let (mut dependencies, needs_dns) = self.dependencies(build, opts).await?;
        let (executable, args) = self.invocation(build)?;

        let synth_files = TempDir::new()?;
        if needs_dns {
            common::synth_dns_config(synth_files.path()).map_err(anyhow::Error::from)?;
        }
        dependencies.insert(synth_files.path().to_path_buf());
        temp_dirs.push(synth_files);

        let config = build_sandbox::BuildConfig {
            name: build.name.clone(),
            dependencies,
            inputs,
            build_script: build_sandbox::config::BuildScript {
                executable: executable.into(),
                args,
                build_args: build.build_args.clone(),
            },
            outputs: build
                .outputs
                .values()
                .map(|output| match output {
                    graph::BuildOutput::Library { glob } => glob.clone(),
                    graph::BuildOutput::Data { glob } => glob.clone(),
                    graph::BuildOutput::Binary { glob } => glob.clone(),
                })
                .collect(),
        };

        let out_dir = opts
            .cache
            .write_dir(&opts.graph.spec_hash(self.spec))
            .unwrap();
        info!("Building package: {}", build.name);
        let target_id = build.name.clone();
        build_sandbox::run_build(&config, out_dir.path(), opts.exec_base.clone(), &target_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to build {}: {}", build.name, e))?;

        for tempdir in temp_dirs.into_iter() {
            drop(tempdir);
        }
        Ok(out_dir)
    }
}
