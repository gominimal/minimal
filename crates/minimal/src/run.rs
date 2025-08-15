use build_sandbox::{BuildConfig, config::BuildScript, run_build};
use cache::{Cache, LocalDir};
use graph::{BuildOutput, BuildSpecRef, DepGraph, ExecPlan, SpecHash};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::debug;

/// A run executes builds.
pub struct Run {
    graph: DepGraph,
    cache: Cache<LocalDir>,
}

impl Run {
    pub fn new(graph: DepGraph, cache: Cache<LocalDir>) -> Self {
        Self { graph, cache }
    }

    pub fn execute(
        &mut self,
        debug: Option<BuildSpecRef>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Execute builds in dependency order - each build runs in isolation
        // and can only access outputs from previously completed builds
        for phase in ExecPlan::new(&self.graph) {
            for bsr in phase.iter() {
                let build = self.graph.get(bsr).unwrap();
                let bsh = build.spec_hash(&self.graph);
                println!("Executing build: {} [{}]", build.name, bsh.to_hex());

                let mut dependencies = HashMap::new();
                let mut inputs = Vec::new();

                debug!("Build {} has {} inputs", build.name, build.inputs.len());
                for (i, input) in build.inputs.iter().enumerate() {
                    use graph::BuildSpecInput::*;
                    match input {
                        Build(dep_ref) => {
                            let dep_build = self.graph.get(dep_ref).unwrap();
                            let dep_hash = dep_build.spec_hash(&self.graph);

                            debug!(
                                "  Input {}: Build({}) -- [{}]",
                                i,
                                dep_build.name,
                                dep_hash.to_hex()
                            );

                            let cache_path =
                                self.cache.read_dir(dep_hash).unwrap().path().to_path_buf();

                            dependencies.insert(cache_path, PathBuf::from("/"));
                        }
                        Path(path) => {
                            debug!("  Input {}: HostPath({})", i, path.display());
                            let host_path = PathBuf::from(path);
                            dependencies.insert(host_path.clone(), host_path);
                        }
                        Local((path, _hash)) => {
                            debug!("  Input {}: Local file from {}", i, path.display());
                            inputs.push(path.to_path_buf());
                        }
                        Source(_) => todo!(),
                    }
                }

                let toolchain_path = PathBuf::from("toolchains/x86_64-unknown-linux-gnu")
                    .canonicalize()
                    .unwrap();
                dependencies.insert(toolchain_path.clone(), toolchain_path);

                let scripts_path = PathBuf::from("scripts").canonicalize().unwrap();
                dependencies.insert(scripts_path.clone(), scripts_path);

                debug!(
                    "Dependencies for isolated build {}: {:?}",
                    build.name, dependencies
                );

                let config = BuildConfig {
                    dependencies,
                    inputs,
                    build_script: BuildScript {
                        executable: build.cmd.clone().into(),
                        args: vec![],
                    },
                    outputs: build
                        .outputs
                        .values()
                        .map(|output| match output {
                            BuildOutput::Library { glob } => glob.clone(),
                            BuildOutput::Binary { .. } => todo!(),
                        })
                        .collect(),
                    debug_shell: matches!(debug, Some(debug_bsr) if bsr == &debug_bsr),
                };

                run_build(&config, self.cache.write_dir(bsh).unwrap().path(), true)?;

                println!("Completed isolated build: {}", build.name);
            }
        }

        Ok(())
    }
}
