use anyhow::{Context, Result, bail};
use build_sandbox::{BuildConfig, config::BuildScript, run_build};
use cache::{Cache, LocalDir};
use graph::dep_graph::SourceFetch;
use graph::{
    BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, ExecPlan, SourceInput, SpecHash,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::debug;
use url::Url;

use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage};

/// yields a directory that the files in an [InputSource] are available.
async fn materialize_source(
    build_name: &str,
    source: &SourceInput,
    remote_storage: &RemoteStorage,
) -> Result<PathBuf> {
    match &source.from {
        SourceFetch::URL(url) => {
            let url = Url::parse(&url).with_context(|| format!("Failed to parse URL '{}'", url))?;

            match url.scheme() {
                "gs" => {
                    let bucket_id = url.host_str().with_context(|| {
                        format!(
                            "Invalid gs:// URL: missing bucket name in '{}'",
                            url.as_str()
                        )
                    })?;

                    let file_name = url.path().trim_start_matches('/');

                    let temp_base = std::env::temp_dir()
                        .join(format!("minpkgs-sources-{}", build_name.replace('/', "-")));
                    std::fs::create_dir_all(&temp_base)?;

                    let local_filename = file_name.rsplit('/').next().unwrap_or(file_name);
                    let temp_path = temp_base.join(local_filename);

                    let content = remote_storage
                        .download(bucket_id.to_string(), file_name)
                        .await?;

                    std::fs::write(&temp_path, content)?;

                    // Verify SHA256 hash
                    let mut hasher = Sha256::new();
                    hasher.update(&std::fs::read(&temp_path)?);
                    let computed_hash = hasher.finalize();
                    let computed_hex = hex::encode(computed_hash);

                    if computed_hex != source.sha256 {
                        bail!(
                            "SHA256 mismatch for {}: expected {}, got {}",
                            url.as_str(),
                            source.sha256,
                            computed_hex
                        );
                    }

                    debug!(
                        "  Downloaded and verified source from gs://{}/{}",
                        bucket_id, file_name
                    );
                    Ok(temp_path)
                }
                _ => todo!(),
            }
        }
    }
}

/// yields 'dependencies' mappings for making the given input or runtime_dep available to a sandbox build.
///
/// If a build is missing but a cycle-breaker is present for itself or any of its dependencies, it will try to use that.
fn all_paths_for_spec(
    spec_ref: &BuildSpecRef,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
) -> Result<HashMap<PathBuf, PathBuf>> {
    let mut out_paths = HashMap::with_capacity(12);

    // Make the input build itself available in the sandbox.
    let (spec_bsr, self_paths) = path_for_self_spec(
        spec_ref,
        &graph.spec_hash(spec_ref),
        graph.get(spec_ref).unwrap(),
        graph,
        cache,
    )?;
    out_paths.insert(self_paths.0, self_paths.1);

    // Make all the transitive deps available in the sandbox.
    path_transitive_deps_of(&graph.get(&spec_bsr).unwrap(), graph, cache, &mut out_paths)?;

    Ok(out_paths)
}

fn path_for_self_spec(
    input_ref: &BuildSpecRef,
    input_hash: &SpecHash,
    input_build: &BuildSpec,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
) -> Result<(BuildSpecRef, (PathBuf, PathBuf))> {
    match cache.read_dir(&input_hash) {
        Ok(cache_entry) => {
            let cache_path = cache_entry.path().to_path_buf();
            Ok((input_ref.clone(), (cache_path, PathBuf::from("/"))))
        }
        Err(cache::CacheErr::NotFound) => match input_build.replace_on_cycle {
            None => panic!(
                "missing build in cache for {} [{}]",
                input_build.name,
                input_hash.0.to_hex()
            ),
            Some(cycle_breaker) => {
                let breaker_hash = graph.spec_hash(&cycle_breaker);
                let breaker_build = graph.get(&cycle_breaker).unwrap();

                debug!(
                    "  --- subbing in cycle breaker {} [{}] ---",
                    breaker_build.name,
                    breaker_hash.0.to_hex()
                );
                path_for_self_spec(&cycle_breaker, &breaker_hash, &breaker_build, graph, cache)
            }
        },
        Err(e) => {
            panic!(
                "unexpected cache error when resolving path for {} [{}]: {:?}",
                input_build.name,
                input_hash.0.to_hex(),
                e
            );
        }
    }
}

/// yields 'dependencies' mappings for the transitive dependencies of the given build spec.
fn path_transitive_deps_of(
    input_build: &BuildSpec,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    out_paths: &mut HashMap<PathBuf, PathBuf>,
) -> Result<()> {
    use BuildSpecInput::*;
    for dep_bsr in input_build
        .inputs
        .iter()
        .filter_map(|input| match input {
            Build(dep_bsr) => Some(dep_bsr),
            Source(_) | HostPath(_) | Local(_) | Prebuilt(_) => None,
        })
        .chain(input_build.runtime_deps.iter())
    {
        let (dep_bsr, dep_paths) = path_for_self_spec(
            dep_bsr,
            &graph.spec_hash(dep_bsr),
            &graph.get(dep_bsr).unwrap(),
            graph,
            cache,
        )?;
        if !out_paths.contains_key(&dep_paths.0) {
            let dep_build = graph.get(&dep_bsr).unwrap();
            debug!(
                "   - Transitive dep {} -- [{}]",
                dep_build.name,
                graph.spec_hash(&dep_bsr).0.to_hex()
            );

            out_paths.insert(dep_paths.0, dep_paths.1);
            path_transitive_deps_of(&dep_build, graph, cache, out_paths)?;
        }
    }

    Ok(())
}

fn is_pure_prebuilt(build: &BuildSpec) -> bool {
    let has_prebuilt = build
        .inputs
        .iter()
        .any(|input| matches!(input, BuildSpecInput::Prebuilt(_)));
    let has_local_or_source = build
        .inputs
        .iter()
        .any(|input| matches!(input, BuildSpecInput::Local(_) | BuildSpecInput::Source(_)));

    has_prebuilt && !has_local_or_source
}

async fn materialize_prebuilt(
    build: &BuildSpec,
    build_hash: &SpecHash,
    cache: &Cache<LocalDir>,
    lockfile: &PrebuiltsLock,
    remote_storage: &RemoteStorage,
) -> Result<()> {
    eprintln!(
        "Pure prebuilt package: {}, copying files directly",
        build.name
    );
    let cache_handle = cache.write_dir(build_hash).unwrap();
    let output_dir = cache_handle.path();

    // Find the prebuilt input and copy its contents
    for input in build.inputs.iter() {
        if let BuildSpecInput::Prebuilt(package_name) = input {
            // First check if we have a locked hash for this package
            let package_hash = if let Some(locked_hash) = lockfile.get_hash(package_name) {
                debug!("  Using locked hash for {}: {}", package_name, locked_hash);
                SpecHash(blake3::Hash::from_hex(locked_hash).with_context(|| {
                    format!("Invalid hex hash in lockfile for {}", package_name)
                })?)
            } else {
                debug!(
                    "  No locked hash found, computing from source spec for {}",
                    package_name
                );
                // Fall back to computing the hash (may fail with circular dependency)
                compute_source_package_hash(package_name)?
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
            let content = remote_storage
                .download(bucket_id.to_string(), &file_path)
                .await
                .with_context(|| {
                    format!("Failed to download prebuilt archive for {}", package_name)
                })?;

            std::fs::write(&temp_archive_path, content)?;

            // Extract the archive
            let extract_dir = temp_base.join("extracted");
            std::fs::create_dir_all(&extract_dir)?;

            extract_prebuilt_archive(&temp_archive_path, &extract_dir)?;

            debug!(
                "  Downloaded and extracted prebuilt archive for {} to {}",
                package_name,
                extract_dir.display()
            );

            // Copy all contents from the prebuilt extraction directory
            for entry in std::fs::read_dir(extract_dir)? {
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
    }
    cache_handle.finalize().unwrap();
    Ok(())
}

/// A run executes builds according to some plan.
pub struct Run<'a> {
    graph: &'a DepGraph,
    cache: Cache<LocalDir>,
    remote_storage: RemoteStorage,
    lockfile: PrebuiltsLock,
}

impl<'a> Run<'a> {
    pub fn new(
        graph: &'a DepGraph,
        cache: Cache<LocalDir>,
        remote_storage: RemoteStorage,
        lockfile: PrebuiltsLock,
    ) -> Self {
        Self {
            graph,
            cache,
            remote_storage,
            lockfile,
        }
    }

    async fn sandbox_paths_from_buildspec(
        &self,
        build: &BuildSpec,
    ) -> Result<(HashMap<PathBuf, PathBuf>, Vec<PathBuf>)> {
        let mut dependencies = HashMap::new();
        let mut inputs = Vec::new();

        debug!("Build {} has {} inputs", build.name, build.inputs.len());
        for (i, input) in build.inputs.iter().enumerate() {
            use BuildSpecInput::*;
            match input {
                Build(dep_ref) => {
                    debug!(
                        "  Input {}: Build({}) -- [{}]",
                        i,
                        self.graph.get(&dep_ref).unwrap().name,
                        self.graph.spec_hash(&dep_ref).0.to_hex()
                    );

                    let input_paths = all_paths_for_spec(dep_ref, &self.graph, &self.cache)?;
                    dependencies.extend(input_paths);
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
                    inputs.push(
                        materialize_source(build.name.as_str(), source, &self.remote_storage)
                            .await?,
                    );
                }
                Prebuilt(package_name) => {
                    debug!("  Input {}: Prebuilt({})", i, package_name);
                    bail!("prebuilt input cannot exist in a non-prebuilt build spec");
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

            let dep_paths = all_paths_for_spec(bsr, &self.graph, &self.cache)?;
            dependencies.extend(dep_paths);
        }

        debug!(
            "Dependencies for isolated build {}: {:?}",
            build.name, dependencies
        );

        Ok((dependencies, inputs))
    }

    pub async fn execute(&mut self, plan: ExecPlan<'a>, debug: Option<BuildSpecRef>) -> Result<()> {
        // Execute builds in dependency order - each build runs in isolation
        // and can only access outputs from previously completed builds
        // let mut lockfile_updates = Vec::new(); // Track what needs lockfile updates

        for phase in plan {
            for bsr in phase.iter() {
                let bsh = self.graph.spec_hash(bsr);
                let build = self.graph.get(bsr).unwrap();

                if self.cache.read_dir(&bsh).is_ok() {
                    eprintln!(
                        "Skipping already-cached build {} [{}]",
                        build.name,
                        bsh.0.to_hex()
                    );
                    continue;
                }
                if is_pure_prebuilt(build) {
                    materialize_prebuilt(
                        build,
                        &bsh,
                        &self.cache,
                        &self.lockfile,
                        &self.remote_storage,
                    )
                    .await?;
                    continue;
                }

                eprintln!("Executing build: {} [{}]", build.name, bsh.0.to_hex());
                let (dependencies, inputs) = self.sandbox_paths_from_buildspec(build).await?;

                if build.cmd.trim().is_empty() {
                    eprintln!(
                        "No-op package with empty cmd: {}, creating cache entry",
                        build.name
                    );
                    let cache_handle = self.cache.write_dir(&bsh).unwrap();
                    cache_handle.finalize().unwrap();
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
                                BuildOutput::Data { glob } => glob.clone(),
                                BuildOutput::Binary { path } => path.clone(),
                            })
                            .collect(),
                        debug_shell: matches!(debug, Some(debug_bsr) if bsr == &debug_bsr),
                    };

                    let out_dir = self.cache.write_dir(&bsh).unwrap();
                    run_build(&config, out_dir.path(), true)?;
                    out_dir.finalize().unwrap();
                }

                eprintln!("Completed isolated build: {}", build.name);
            }
        }

        Ok(())
    }

    pub(crate) async fn upload_prebuilt_archive(
        &mut self,
        build: &BuildSpec,
        bsh: &SpecHash,
    ) -> Result<()> {
        eprintln!("Auto-uploading prebuilt archive for {}", build.name);

        let package_hash = compute_source_package_hash(&build.name)?;
        let cache_handle = self.cache.read_dir(bsh).unwrap();
        let cache_dir = cache_handle.path();
        let archive_name = format!("{}.tar.zst", package_hash.0.to_hex());
        let temp_archive_path = std::env::temp_dir().join(&archive_name);

        create_prebuilt_archive(&cache_dir.to_path_buf(), &temp_archive_path)?;

        let bucket_id = "minimal-staging-archives";
        let gcs_path = format!("prebuilts/{}/{}", build.name, archive_name);

        let archive_data = std::fs::read(&temp_archive_path)?;
        self.remote_storage
            .upload(bucket_id.to_string(), &gcs_path, &archive_data)
            .await?;

        std::fs::remove_file(&temp_archive_path)?;

        eprintln!(
            "Automatically uploaded prebuilt to gs://{}/{}",
            bucket_id, gcs_path
        );

        self.lockfile
            .update_hash(build.name.clone(), package_hash.0.to_hex().to_string());
        let lockfile_path = std::path::Path::new("prebuilts.lock");
        self.lockfile.save(lockfile_path)?;
        eprintln!("Updated prebuilts.lock with new hash for {}", build.name);

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

fn extract_prebuilt_archive(archive_path: &PathBuf, extract_dir: &PathBuf) -> Result<()> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = zstd::stream::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(extract_dir)?;
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

fn compute_source_package_hash(package_name: &str) -> Result<SpecHash> {
    // For prebuilt packages, we need to compute the hash based on the SOURCE build spec,
    // not the current build spec (which would cause circular reference).

    // Load the source build spec for this package
    use graph::{SpecReader, SpecReaderOptions};
    use std::path::Path;

    let package_dir = Path::new("packages").join(package_name);
    let source_spec_path = package_dir.join("build.source.ncl");

    if !source_spec_path.exists() {
        bail!(
            "Source build spec not found for package '{}': {}",
            package_name,
            source_spec_path.display()
        );
    }

    let sr = SpecReader::new_with_path(
        &source_spec_path,
        &SpecReaderOptions {
            minimal_lib_path: "crates/graph/minimal-ncl".into(),
        },
    )
    .map_err(|e| anyhow::anyhow!("Failed to load source spec for {}: {:?}", package_name, e))?;

    let source_graph = graph::DepGraph::new(sr).map_err(|e| {
        anyhow::anyhow!(
            "Failed to build source dependency graph for {}: {:?}",
            package_name,
            e
        )
    })?;

    // The top-level build spec should be for this package
    let source_spec = source_graph
        .get(&source_graph.top_levels[0])
        .with_context(|| format!("Source spec not found for package '{}'", package_name))?;

    if source_spec.name != package_name {
        bail!(
            "Source spec name mismatch: expected '{}', got '{}'",
            package_name,
            source_spec.name
        );
    }

    Ok(source_graph.spec_hash(&source_graph.top_levels[0]))
}
