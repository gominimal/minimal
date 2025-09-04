use build_sandbox::{BuildConfig, config::BuildScript, run_build};
use cache::{Cache, LocalDir};
use graph::dep_graph::SourceFetch;
use graph::{
    BuildManifest, BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, ExecPlan,
    SpecHash,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};
use url::Url;

use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage};

/// A run executes builds.
pub struct Run {
    graph: DepGraph,
    cache: Cache<LocalDir>,
    is_source_build: bool,
    package_name: String,
    remote_storage: RemoteStorage,
    lockfile: PrebuiltsLock,
}

impl Run {
    pub fn new(
        graph: DepGraph,
        cache: Cache<LocalDir>,
        is_source_build: bool,
        package_name: String,
        remote_storage: RemoteStorage,
        lockfile: PrebuiltsLock,
    ) -> Self {
        Self {
            graph,
            cache,
            is_source_build,
            package_name,
            remote_storage,
            lockfile,
        }
    }

    async fn sandbox_paths_from_buildspec(
        &self,
        build: &BuildSpec,
    ) -> Result<(HashMap<PathBuf, PathBuf>, Vec<PathBuf>), Box<dyn std::error::Error>> {
        let mut dependencies = HashMap::new();
        let mut inputs = Vec::new();

        debug!("Build {} has {} inputs", build.name, build.inputs.len());
        for (i, input) in build.inputs.iter().enumerate() {
            use BuildSpecInput::*;
            match input {
                Build(dep_ref) => {
                    let dep_hash = self.graph.spec_hash(dep_ref);
                    let dep_build = self.graph.get(dep_ref).unwrap();

                    debug!(
                        "  Input {}: Build({}) -- [{}]",
                        i,
                        dep_build.name,
                        dep_hash.0.to_hex()
                    );

                    let cache_path = self.cache.read_dir(&dep_hash).unwrap().path().to_path_buf();
                    dependencies.insert(cache_path, PathBuf::from("/"));

                    for (bsh, _attribution) in BuildManifest::make(&self.graph, dep_ref, &dep_hash)
                        .transitive_runtime_deps
                        .into_iter()
                    {
                        debug!("   - Transitive runtime dep -- [{}]", dep_hash.0.to_hex());

                        let cache_path = self.cache.read_dir(&bsh).unwrap().path().to_path_buf();
                        if dependencies
                            .insert(cache_path, PathBuf::from("/"))
                            .is_some()
                        {
                            warn!(
                                "Transitive dependency [{}] was already present - probably fine",
                                dep_hash.0.to_hex(),
                            );
                        }
                    }
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
                Source(source) => {
                    debug!("  Input {}: Source({:?})", i, source.from);

                    match &source.from {
                        SourceFetch::URL(url_str) => {
                            let url = Url::parse(url_str)
                                .map_err(|e| format!("Failed to parse URL '{}': {}", url_str, e))?;

                            match url.scheme() {
                                "gs" => {
                                    let bucket_id = url.host_str().ok_or_else(|| {
                                        format!(
                                            "Invalid gs:// URL: missing bucket name in '{}'",
                                            url_str
                                        )
                                    })?;

                                    let file_name = url.path().trim_start_matches('/');

                                    let temp_base = std::env::temp_dir().join(format!(
                                        "minpkgs-sources-{}",
                                        build.name.replace('/', "-")
                                    ));
                                    std::fs::create_dir_all(&temp_base)?;

                                    let local_filename =
                                        file_name.rsplit('/').next().unwrap_or(file_name);
                                    let temp_path = temp_base.join(local_filename);

                                    let content = self
                                        .remote_storage
                                        .download(bucket_id.to_string(), file_name)
                                        .await?;

                                    std::fs::write(&temp_path, content)?;

                                    // Verify SHA256 hash
                                    let mut hasher = Sha256::new();
                                    hasher.update(&std::fs::read(&temp_path)?);
                                    let computed_hash = hasher.finalize();
                                    let computed_hex = hex::encode(computed_hash);

                                    if computed_hex != source.sha256 {
                                        return Err(format!(
                                            "SHA256 mismatch for {}: expected {}, got {}",
                                            url_str, source.sha256, computed_hex
                                        )
                                        .into());
                                    }

                                    debug!(
                                        "  Downloaded and verified source from gs://{}/{}",
                                        bucket_id, file_name
                                    );
                                    inputs.push(temp_path);
                                }
                                _ => todo!(),
                            }
                        }
                    }
                }
                Prebuilt(package_name) => {
                    debug!("  Input {}: Prebuilt({})", i, package_name);

                    // First check if we have a locked hash for this package
                    let package_hash =
                        if let Some(locked_hash) = self.lockfile.get_hash(package_name) {
                            debug!("  Using locked hash for {}: {}", package_name, locked_hash);
                            SpecHash(blake3::Hash::from_hex(locked_hash).map_err(|e| {
                                format!("Invalid hex hash in lockfile for {}: {}", package_name, e)
                            })?)
                        } else {
                            debug!(
                                "  No locked hash found, computing from source spec for {}",
                                package_name
                            );
                            // Fall back to computing the hash (may fail with circular dependency)
                            self.compute_package_hash(package_name)?
                        };

                    let bucket_id = "minimal-staging-archives";
                    let file_path = format!(
                        "prebuilts/{}/{}.tar.zst",
                        package_name,
                        package_hash.0.to_hex()
                    );

                    let temp_base = std::env::temp_dir()
                        .join(format!("minpkgs-prebuilt-{}", build.name.replace('/', "-")));
                    std::fs::create_dir_all(&temp_base)?;

                    let temp_archive_path = temp_base.join(format!("{}.tar.zst", package_name));

                    // Download the prebuilt archive
                    let content = self
                        .remote_storage
                        .download(bucket_id.to_string(), &file_path)
                        .await
                        .map_err(|e| {
                            format!(
                                "Failed to download prebuilt archive for {}: {}",
                                package_name, e
                            )
                        })?;

                    std::fs::write(&temp_archive_path, content)?;

                    // Extract the archive
                    let extract_dir = temp_base.join("extracted");
                    std::fs::create_dir_all(&extract_dir)?;

                    self.extract_prebuilt_archive(&temp_archive_path, &extract_dir)?;

                    debug!(
                        "  Downloaded and extracted prebuilt archive for {} to {}",
                        package_name,
                        extract_dir.display()
                    );
                    inputs.push(extract_dir);
                }
            }
        }
        for (i, bsr) in build.runtime_deps.iter().enumerate() {
            let dep_hash = self.graph.spec_hash(bsr);
            let dep_build = self.graph.get(bsr).unwrap();

            debug!(
                "  Runtime dep {}: Build({}) -- [{}]",
                i,
                dep_build.name,
                dep_hash.0.to_hex()
            );

            let cache_path = self.cache.read_dir(&dep_hash).unwrap().path().to_path_buf();
            dependencies.insert(cache_path, PathBuf::from("/"));

            for (bsh, _attribution) in BuildManifest::make(&self.graph, bsr, &dep_hash)
                .transitive_runtime_deps
                .into_iter()
            {
                debug!("   - Transitive runtime dep -- [{}]", dep_hash.0.to_hex());

                let cache_path = self.cache.read_dir(&bsh).unwrap().path().to_path_buf();
                if dependencies
                    .insert(cache_path, PathBuf::from("/"))
                    .is_some()
                {
                    warn!(
                        "Transitive dependency [{}] was already present - probably fine",
                        dep_hash.0.to_hex(),
                    );
                }
            }
        }

        debug!(
            "Dependencies for isolated build {}: {:?}",
            build.name, dependencies
        );

        Ok((dependencies, inputs))
    }

    pub async fn execute(
        &mut self,
        debug: Option<BuildSpecRef>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Execute builds in dependency order - each build runs in isolation
        // and can only access outputs from previously completed builds
        let mut lockfile_updates = Vec::new(); // Track what needs lockfile updates

        for phase in ExecPlan::new(&self.graph) {
            for bsr in phase.iter() {
                let bsh = self.graph.spec_hash(bsr);
                let build = self.graph.get(bsr).unwrap();

                if self.cache.read_dir(&bsh).is_ok() {
                    println!(
                        "Skipping already-cached build {} [{}]",
                        build.name,
                        bsh.0.to_hex()
                    );
                    continue;
                }

                println!("Executing build: {} [{}]", build.name, bsh.0.to_hex());
                let (dependencies, inputs) = self.sandbox_paths_from_buildspec(build).await?;

                // Check if this is a pure prebuilt package (only has Prebuilt inputs + system dependencies)
                let has_prebuilt = build
                    .inputs
                    .iter()
                    .any(|input| matches!(input, BuildSpecInput::Prebuilt(_)));
                let has_local_or_source = build.inputs.iter().any(|input| {
                    matches!(input, BuildSpecInput::Local(_) | BuildSpecInput::Source(_))
                });

                if has_prebuilt && !has_local_or_source {
                    // Pure prebuilt package - just copy the prebuilt files directly
                    println!(
                        "Pure prebuilt package: {}, copying files directly",
                        build.name
                    );

                    let cache_handle = self.cache.write_dir(&bsh).unwrap();
                    let output_dir = cache_handle.path();

                    // Find the prebuilt input and copy its contents
                    for input in inputs.iter() {
                        // Copy all contents from the prebuilt extraction directory
                        for entry in std::fs::read_dir(input)? {
                            let entry = entry?;
                            let src = entry.path();
                            let filename = src.file_name().unwrap();
                            let dst = output_dir.join(filename);

                            if src.is_dir() {
                                copy_dir_recursive(&src, &dst)?;
                            } else {
                                std::fs::copy(&src, &dst)?;
                            }
                        }
                    }
                } else {
                    // Regular build with build script
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

                    run_build(&config, self.cache.write_dir(&bsh).unwrap().path(), true)
                        .inspect_err(|_| {
                            self.cache.invalidate_dir(&bsh).unwrap();
                        })?;
                }

                println!("Completed isolated build: {}", build.name);

                // If this is a source build of the requested package, handle upload
                if self.is_source_build && build.name == self.package_name {
                    // Store info for later upload (to avoid borrow checker issues)
                    lockfile_updates.push((build.name.clone(), bsh));
                }
            }
        }

        // Handle uploads and lockfile updates after the main build loop
        for (package_name, bsh) in lockfile_updates {
            println!("Processing upload for {}", package_name);
            self.upload_prebuilt_archive(&bsh).await?;
        }

        Ok(())
    }

    async fn upload_prebuilt_archive(
        &mut self,
        bsh: &SpecHash,
    ) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("Auto-uploading prebuilt archive for {}", self.package_name);

        let package_hash = self.compute_package_hash(&self.package_name)?;
        let cache_handle = self.cache.read_dir(bsh).unwrap();
        let cache_dir = cache_handle.path();
        let archive_name = format!("{}.tar.zst", package_hash.0.to_hex());
        let temp_archive_path = std::env::temp_dir().join(&archive_name);

        create_prebuilt_archive(&cache_dir.to_path_buf(), &temp_archive_path)?;

        let bucket_id = "minimal-staging-archives";
        let gcs_path = format!("prebuilts/{}/{}", self.package_name, archive_name);

        let archive_data = std::fs::read(&temp_archive_path)?;
        self.remote_storage
            .upload(bucket_id.to_string(), &gcs_path, &archive_data)
            .await?;

        std::fs::remove_file(&temp_archive_path)?;

        eprintln!(
            "Automatically uploaded prebuilt to gs://{}/{}",
            bucket_id, gcs_path
        );

        self.lockfile.update_hash(
            self.package_name.clone(),
            package_hash.0.to_hex().to_string(),
        );
        let lockfile_path = std::path::Path::new("prebuilts.lock");
        self.lockfile.save(lockfile_path)?;
        eprintln!(
            "Updated prebuilts.lock with new hash for {}",
            self.package_name
        );

        Ok(())
    }

    fn compute_package_hash(
        &self,
        package_name: &str,
    ) -> Result<SpecHash, Box<dyn std::error::Error>> {
        // For prebuilt packages, we need to compute the hash based on the SOURCE build spec,
        // not the current build spec (which would cause circular reference).

        // Load the source build spec for this package
        use graph::{SpecReader, SpecReaderOptions};
        use std::path::Path;

        let package_dir = Path::new("packages").join(package_name);
        let source_spec_path = package_dir.join("build.source.ncl");

        if !source_spec_path.exists() {
            return Err(format!(
                "Source build spec not found for package '{}': {}",
                package_name,
                source_spec_path.display()
            )
            .into());
        }

        let sr = SpecReader::new_with_path(
            &source_spec_path,
            &SpecReaderOptions {
                minimal_lib_path: "crates/graph/minimal-ncl".into(),
            },
        )
        .map_err(|e| format!("Failed to load source spec for {}: {:?}", package_name, e))?;

        let source_graph = graph::DepGraph::new(sr).map_err(|e| {
            format!(
                "Failed to build source dependency graph for {}: {:?}",
                package_name, e
            )
        })?;

        // The top-level build spec should be for this package
        let source_spec = source_graph
            .get(&source_graph.top_level)
            .ok_or_else(|| format!("Source spec not found for package '{}'", package_name))?;

        if source_spec.name != package_name {
            return Err(format!(
                "Source spec name mismatch: expected '{}', got '{}'",
                package_name, source_spec.name
            )
            .into());
        }

        Ok(source_graph.spec_hash(&source_graph.top_level))
    }

    fn extract_prebuilt_archive(
        &self,
        archive_path: &PathBuf,
        extract_dir: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::open(archive_path)?;
        let decoder = zstd::stream::Decoder::new(file)?;
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(extract_dir)?;
        Ok(())
    }
}

fn create_prebuilt_archive(prebuilt_dir: &PathBuf, archive_path: &PathBuf) -> std::io::Result<()> {
    let file = std::fs::File::create(archive_path)?;
    let encoder = zstd::stream::Encoder::new(file, 3)?; // Compression level 3
    let mut tar_builder = tar::Builder::new(encoder);

    // Add all files from the prebuilt directory to the archive
    tar_builder.append_dir_all(".", prebuilt_dir)?;

    let encoder = tar_builder.into_inner()?;
    encoder.finish()?;

    Ok(())
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
