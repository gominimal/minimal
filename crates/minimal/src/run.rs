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
    is_source_build: bool,
    package_name: String,
}

impl Run {
    pub fn new(graph: DepGraph, cache: Cache<LocalDir>, is_source_build: bool, package_name: String) -> Self {
        Self { graph, cache, is_source_build, package_name }
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

                if self.cache.read_dir(bsh).is_ok() {
                    println!(
                        "Skipping already-cached build {} [{}]",
                        build.name,
                        bsh.to_hex()
                    );
                    continue;
                }

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
                        HostPath(path) => {
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

                let toolchain_path = PathBuf::from("/home/bweeks/x-tools/x86_64-minimal-linux-gnu")
                    .canonicalize()
                    .unwrap();
                dependencies.insert(toolchain_path.clone(), toolchain_path);

                let scripts_path = PathBuf::from("scripts").canonicalize().unwrap();
                dependencies.insert(scripts_path.clone(), scripts_path);

                debug!(
                    "Dependencies for isolated build {}: {:?}",
                    build.name, dependencies
                );

                let cmd_parts: Vec<String> =
                    shlex::split(&build.cmd).unwrap_or_else(|| vec![build.cmd.clone()]);
                let (executable, args) = if !cmd_parts.is_empty() {
                    let exe = cmd_parts[0].clone();
                    let args = cmd_parts[1..].to_vec();
                    (exe, args)
                } else {
                    (build.cmd.clone(), vec![])
                };

                let config = BuildConfig {
                    dependencies,
                    inputs,
                    build_script: BuildScript {
                        executable: executable.into(),
                        args,
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

                run_build(&config, self.cache.write_dir(bsh).unwrap().path(), true).map_err(
                    |e| {
                        self.cache.invalidate_dir(bsh).unwrap();
                        e
                    },
                )?;

                println!("Completed isolated build: {}", build.name);

                // If this is a source build of the requested package, copy outputs to prebuilt
                if self.is_source_build && build.name == self.package_name {
                    self.update_prebuilt_binaries(bsh)?;
                }
            }
        }

        Ok(())
    }

    fn update_prebuilt_binaries(&self, bsh: blake3::Hash) -> Result<(), Box<dyn std::error::Error>> {
        let cache_handle = self.cache.read_dir(bsh).unwrap();
        let cache_dir = cache_handle.path();
        let package_dir = PathBuf::from("packages").join(&self.package_name);
        let prebuilt_dir = package_dir.join("prebuilt");

        println!("Updating prebuilt binaries for package: {}", self.package_name);

        // Clear existing prebuilt directory
        if prebuilt_dir.exists() {
            std::fs::remove_dir_all(&prebuilt_dir)?;
        }
        std::fs::create_dir_all(&prebuilt_dir)?;

        // Copy built files to prebuilt
        // Special handling for make - bin/make goes to usr/bin/make
        if self.package_name == "make" {
            let make_bin_src = cache_dir.join("bin/make");
            if make_bin_src.exists() {
                let make_bin_dst = prebuilt_dir.join("usr/bin");
                std::fs::create_dir_all(&make_bin_dst)?;
                std::fs::copy(&make_bin_src, make_bin_dst.join("make"))?;
                println!("  Copied bin/make -> prebuilt/usr/bin/make");
            }
        }

        // Handle all outputs - copy entire directory structure
        for entry in std::fs::read_dir(&cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().unwrap().to_str().unwrap();
                // Skip bin directory for make package (already handled above)
                if self.package_name == "make" && dir_name == "bin" {
                    continue;
                }
                // Copy entire directory structure
                let dest = prebuilt_dir.join(dir_name);
                copy_dir_recursive(&path, &dest)?;
                println!("  Copied {} -> prebuilt/{}", dir_name, dir_name);
            }
        }

        println!("Successfully updated prebuilt binaries for {}", self.package_name);
        Ok(())
    }
}

fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
