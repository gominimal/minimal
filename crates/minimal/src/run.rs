use build_sandbox::{BuildConfig, config::BuildScript, run_build};
use cache::{Cache, LocalDir};
use graph::{BuildOutput, BuildSpecRef, DepGraph, ExecPlan, SpecHash};
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

                // Dependencies are bind-mounted, inputs are copied to wd
                let mut dependencies = Vec::new();
                let mut inputs = Vec::new();

                // Add host paths from this build's own inputs
                debug!("Build {} has {} inputs", build.name, build.inputs.len());
                for (i, input) in build.inputs.iter().enumerate() {
                    use graph::BuildSpecInput::*;
                    match input {
                        Path(path) => {
                            debug!("  Input {}: HostPath({})", i, path.display());
                            dependencies.push(PathBuf::from(path));
                        }
                        Build(dep_ref) => {
                            let dep_build = self.graph.get(dep_ref).unwrap();
                            let dep_hash = dep_build.spec_hash(&self.graph);

                            debug!(
                                "  Input {}: Build({}) -- [{}]",
                                i,
                                dep_build.name,
                                dep_hash.to_hex()
                            );
                            dependencies
                                .push(self.cache.read_dir(dep_hash).unwrap().path().to_path_buf());
                        }
                        Local(path) => {
                            debug!("  Input {}: Local file from {}", i, path.display());
                            inputs.push(path.to_path_buf());
                        }
                        Source(_) => todo!(),
                    }
                }

                // Add toolchain and scripts (always needed)
                dependencies.push(
                    PathBuf::from("toolchains/x86_64-unknown-linux-gnu")
                        .canonicalize()
                        .unwrap(),
                );
                dependencies.push(PathBuf::from("scripts").canonicalize().unwrap());

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

                // Each build runs in complete isolation and outputs to the directory for itself
                run_build(&config, self.cache.write_dir(bsh).unwrap().path(), true)?;

                println!("Completed isolated build: {}", build.name);
            }
        }

        Ok(())
    }
}
