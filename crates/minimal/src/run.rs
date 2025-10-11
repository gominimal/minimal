use anyhow::{Context, Result, bail};
use build_sandbox::{BuildConfig, Input as SandboxInput, config::BuildScript, run_build};
use cache::{Cache, LocalDir, PendingDir, RemoteCache};
use common::SpecHash;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::dep_graph::SourceFetch;
use graph::{BinProvider, ExecPlan};
use graph::{BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, SourceInput};
use std::collections::HashSet;
use std::path::PathBuf;
use tempfile::{Builder, TempDir, tempfile};
use tracing::{debug, info};
use url::Url;

use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage};

/// A materialized source, either a file or directory tree.
#[derive(Debug)]
pub enum Materialized {
    File(PathBuf),
    TempDir(tempfile::TempDir),
}

/// yields a directory that the files in an [SourceInput] are available.
pub(crate) async fn materialize_source(
    build_name: &str,
    source: &SourceInput,
    remote_storage: &RemoteStorage,
    cache: &Cache<LocalDir>,
) -> Result<Materialized> {
    match &source.from {
        SourceFetch::URL(url) => {
            let url = Url::parse(url).with_context(|| format!("Failed to parse URL '{}'", url))?;

            let cached_path = match url.scheme() {
                "https" => {
                    let cached_path = {
                        let span = tracing::info_span!(
                            "https_download",
                            "indicatif.pb_show" = tracing::field::Empty,
                            "build" = build_name,
                            "url" = url.as_str()
                        );
                        let _enter = span.enter();

                        remote_storage
                            .download_https_with_verification_and_caching(
                                url.as_str(),
                                &source.sha256,
                            )
                            .await?
                    };

                    debug!("  Downloaded and verified source from {}", url);
                    cached_path
                }

                "gs" => {
                    let bucket_id = url.host_str().with_context(|| {
                        format!(
                            "Invalid gs:// URL: missing bucket name in '{}'",
                            url.as_str()
                        )
                    })?;

                    let file_name = url.path().trim_start_matches('/');

                    let cached_path = {
                        let span = tracing::info_span!(
                            "gcs_download",
                            "indicatif.pb_show" = tracing::field::Empty,
                            "build" = build_name,
                            "url" = url.as_str()
                        );
                        let _enter = span.enter();

                        remote_storage
                            .download_with_verification_and_caching(
                                bucket_id.to_string(),
                                file_name,
                                &source.sha256,
                            )
                            .await?
                    };

                    debug!(
                        "  Downloaded and verified source from gs://{}/{}",
                        bucket_id, file_name
                    );
                    cached_path
                }
                _ => todo!(),
            };

            if source.extract {
                let file_name = url
                    .path_segments()
                    .map(|mut s| s.next_back().unwrap())
                    .unwrap();
                let tempdir = cache.temp_dir()?;
                let tempdir_path = tempdir.path();
                let span = tracing::info_span!(
                    "extract",
                    "indicatif.pb_show" = tracing::field::Empty,
                    "build" = build_name,
                    "file" = file_name,
                );
                let _enter = span.enter();

                if url.path().ends_with(".tar.gz") {
                    let f = std::fs::File::open(cached_path)?;
                    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(f));

                    if let Some(strip_prefix) = &source.strip_prefix {
                        for entry in archive.entries()? {
                            let mut entry = entry?;
                            let path = entry.path()?.strip_prefix(strip_prefix)?.to_owned();
                            entry.unpack(tempdir_path.join(path))?;
                        }
                    } else {
                        archive.unpack(tempdir_path)?;
                    }

                    Ok(Materialized::TempDir(tempdir))
                } else if url.path().ends_with(".tar.xz") {
                    let mut decomp_buf = tempfile()?;
                    let f = std::fs::File::open(cached_path)?;
                    lzma_rs::xz_decompress(&mut std::io::BufReader::new(f), &mut decomp_buf)?;
                    std::io::Seek::rewind(&mut decomp_buf)?;
                    let mut archive = tar::Archive::new(decomp_buf);

                    if let Some(strip_prefix) = &source.strip_prefix {
                        for entry in archive.entries()? {
                            let mut entry = entry?;
                            let path = entry.path()?.strip_prefix(strip_prefix)?.to_owned();
                            entry.unpack(tempdir_path.join(path))?;
                        }
                    } else {
                        archive.unpack(tempdir_path)?;
                    }

                    Ok(Materialized::TempDir(tempdir))
                } else {
                    bail!("cannot extract archive {}: unhandled extension", file_name)
                }
            } else {
                Ok(Materialized::File(cached_path))
            }
        }
    }
}

/// yields 'dependencies' mappings for making the given input or runtime_dep available to a sandbox build.
///
/// If a build is missing but a cycle-breaker is present for itself or any of its dependencies, it will try to use that.
async fn all_paths_for_spec(
    spec_ref: &BuildSpecRef,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    remote_cache: Option<&RemoteCache<GcsStorage>>,
) -> Result<HashSet<PathBuf>> {
    let mut out_paths = HashSet::with_capacity(12);

    // Make the input build itself available in the sandbox.
    let (spec_bsr, self_paths) = path_for_self_spec(
        spec_ref,
        &graph.spec_hash(spec_ref),
        graph.get(spec_ref).unwrap(),
        graph,
        cache,
        remote_cache,
    )
    .await?;
    out_paths.insert(self_paths.0);

    // Make all the transitive deps available in the sandbox.
    path_transitive_deps_of(
        graph.get(&spec_bsr).unwrap(),
        graph,
        cache,
        &mut out_paths,
        remote_cache,
    )
    .await?;

    Ok(out_paths)
}

async fn path_for_self_spec(
    input_ref: &BuildSpecRef,
    input_hash: &SpecHash,
    input_build: &BuildSpec,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    remote_cache: Option<&RemoteCache<GcsStorage>>,
) -> Result<(BuildSpecRef, (PathBuf, PathBuf))> {
    match (
        cache.read_dir(input_hash),
        remote_cache.as_ref().map(|c| c.exists(input_hash)),
    ) {
        (Ok(cache_entry), _) => {
            let cache_path = cache_entry.path().to_path_buf();
            Ok((*input_ref, (cache_path, PathBuf::from("/"))))
        }
        // In the remote cache but not the local cache.
        (_, Some(true)) => {
            let span = tracing::info_span!(
                "download_cached",
                "indicatif.pb_show" = tracing::field::Empty,
                "build" = input_build.name,
            );
            let _enter = span.enter();

            remote_cache
                .as_ref()
                .unwrap()
                .materialize(input_hash, &input_build.name, cache)
                .await?;
            let cache_path = cache.read_dir(input_hash).unwrap().path().to_path_buf();
            Ok((*input_ref, (cache_path, PathBuf::from("/"))))
        }
        (Err(cache::CacheErr::NotFound), None | Some(false)) => {
            match input_build.replace_on_cycle {
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
                    Box::pin(path_for_self_spec(
                        &cycle_breaker,
                        &breaker_hash,
                        breaker_build,
                        graph,
                        cache,
                        remote_cache,
                    ))
                    .await
                }
            }
        }
        (Err(e), _) => {
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
async fn path_transitive_deps_of(
    input_build: &BuildSpec,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    out_paths: &mut HashSet<PathBuf>,
    remote_cache: Option<&RemoteCache<GcsStorage>>,
) -> Result<()> {
    for dep in input_build.runtime_deps.iter() {
        let (dep_bsr, dep_paths) = path_for_self_spec(
            dep.bsr(),
            &graph.spec_hash(dep.bsr()),
            graph.get(dep.bsr()).unwrap(),
            graph,
            cache,
            remote_cache,
        )
        .await?;
        if !out_paths.contains(&dep_paths.0) {
            let dep_build = graph.get(&dep_bsr).unwrap();
            debug!(
                "   - Transitive dep {} -- [{}]",
                dep_build.name,
                graph.spec_hash(&dep_bsr).0.to_hex()
            );

            out_paths.insert(dep_paths.0);
            Box::pin(path_transitive_deps_of(
                dep_build,
                graph,
                cache,
                out_paths,
                remote_cache,
            ))
            .await?;
        }
    }

    Ok(())
}

#[tracing::instrument(skip_all, fields(name = build.name, indicatif.pb_show))]
async fn materialize_prebuilt(
    build: &BuildSpec,
    build_hash: &SpecHash,
    cache: &Cache<LocalDir>,
    lockfile: &PrebuiltsLock,
    remote_storage: &RemoteStorage,
) -> Result<PendingDir> {
    let cache_handle = cache.write_dir(build_hash).unwrap();
    let output_dir = cache_handle.path();

    // Find the prebuilt input and copy its contents
    for input in build.inputs.iter() {
        if let BuildSpecInput::Prebuilt(package_name, sha256) = input {
            // First check if we have a locked hash for this package
            let package_hash = if let Some(locked_hash) = lockfile.get_hash(package_name) {
                debug!("  Using locked hash for {}: {}", package_name, locked_hash);
                SpecHash(blake3::Hash::from_hex(locked_hash).with_context(|| {
                    format!("Invalid hex hash in lockfile for {}", package_name)
                })?)
            } else {
                panic!("No locked hash found for {}", package_name);
            };

            let bucket_id = "minimal-staging-archives";
            let file_path = format!(
                "prebuilts/{}/{}.tar.zst",
                package_name,
                package_hash.0.to_hex()
            );

            // Download the prebuilt archive
            let archive_path = if let Some(sha256) = sha256 {
                remote_storage
                    .download_with_verification_and_caching(
                        bucket_id.to_string(),
                        &file_path,
                        sha256,
                    )
                    .await
                    .with_context(|| {
                        format!("Failed to download prebuilt archive for {}", package_name)
                    })?
            } else {
                let (mut f, archive_path) = Builder::new()
                    .prefix("minpkgs-prebuilt")
                    .suffix(".tar.zst")
                    .tempfile()?
                    .keep()?;

                remote_storage
                    .download(bucket_id.to_string(), &file_path, &mut f)
                    .await
                    .with_context(|| {
                        format!("Failed to download prebuilt archive for {}", package_name)
                    })?;

                f.sync_all()?;
                drop(f);
                archive_path
            };

            extract_prebuilt_archive(&archive_path, &output_dir.to_path_buf())?;

            debug!(
                "  Downloaded and extracted prebuilt archive for {} to {}",
                package_name,
                archive_path.display()
            );
        }
    }
    Ok(cache_handle)
}

/// A run executes builds according to some plan.
#[derive(Debug)]
pub struct Run<'a> {
    graph: &'a DepGraph,
    cache: Cache<LocalDir>,
    remote_storage: RemoteStorage,
    lockfile: PrebuiltsLock,
    output_base: PathBuf,
    latest_spongebob_url: Option<String>,
}

impl<'a> Run<'a> {
    pub fn new(
        graph: &'a DepGraph,
        cache: Cache<LocalDir>,
        remote_storage: RemoteStorage,
        lockfile: PrebuiltsLock,
        output_base: PathBuf,
    ) -> Self {
        Self {
            graph,
            cache,
            remote_storage,
            lockfile,
            output_base,
            latest_spongebob_url: None,
        }
    }

    async fn sandbox_paths_from_buildspec(
        &self,
        build: &BuildSpec,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
    ) -> Result<(HashSet<PathBuf>, Vec<SandboxInput>, Vec<TempDir>)> {
        let mut dependencies = HashSet::new();
        let mut inputs = Vec::new();
        let mut tempdirs = Vec::new();

        debug!("Build {} has {} inputs", build.name, build.inputs.len());
        for (i, input) in build.inputs.iter().enumerate() {
            use BuildSpecInput::*;
            match input {
                Build(dep_ref) => {
                    debug!(
                        "  Input {}: Build({}) -- [{}]",
                        i,
                        self.graph.get(dep_ref).unwrap().name,
                        self.graph.spec_hash(dep_ref).0.to_hex()
                    );

                    let input_paths =
                        all_paths_for_spec(dep_ref, self.graph, &self.cache, remote_cache).await?;
                    dependencies.extend(input_paths);
                }
                Subset(s) => todo!("subsets: {:?}", s),
                HostPath(_) => {
                    todo!();
                }
                Local((path, _hash)) => {
                    debug!("  Input {}: Local file from {}", i, path.display());
                    inputs.push(SandboxInput::File(path.to_path_buf()));
                }
                Source(source) => {
                    debug!("  Input {}: Source({:?})", i, source.from);
                    match materialize_source(
                        build.name.as_str(),
                        source,
                        &self.remote_storage,
                        &self.cache,
                    )
                    .await?
                    {
                        Materialized::File(path) => inputs.push(SandboxInput::File(path)),
                        Materialized::TempDir(td) => {
                            inputs.push(SandboxInput::Dir(td.path().to_path_buf()));
                            tempdirs.push(td);
                        }
                    };
                }
                Prebuilt(package_name, _sha256) => {
                    debug!("  Input {}: Prebuilt({})", i, package_name);
                    bail!("prebuilt input cannot exist in a non-prebuilt build spec");
                }
            }
        }
        for (i, dep) in build.runtime_deps.iter().enumerate() {
            let dep_hash = self.graph.spec_hash(dep.bsr());
            let dep_build = self.graph.get(dep.bsr()).unwrap();

            debug!(
                "  Runtime dep {}: Build({}) -- [{}]",
                i,
                dep_build.name,
                dep_hash.0.to_hex()
            );

            let dep_paths =
                all_paths_for_spec(dep.bsr(), self.graph, &self.cache, remote_cache).await?;
            dependencies.extend(dep_paths);
        }

        Ok((dependencies, inputs, tempdirs))
    }

    /// runs a single isolated build, does not take self so it can be spawned in a thread.
    ///
    /// Upon success, returns both the pending cache entry representing the build outputs,
    /// and the spongebob URL of the build.
    #[tracing::instrument(skip_all, fields(indicatif.pb_hide))]
    async fn do_build(
        &self,
        build: &BuildSpecRef,
        _full_build: bool,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
        spongebob_invocation: &mut Option<spongebob::SpongeBobInvocation>,
    ) -> Result<(Option<PendingDir>, Option<String>)> {
        let bsh = self.graph.spec_hash(build);
        let build = self.graph.get(build).unwrap();

        // Check if already in cache
        if let Ok(e) = self.cache.read_dir(&bsh) {
            info!(
                "Package {} already built and cached at: {}",
                build.name,
                e.path().display(),
            );
            // Return None to indicate this was a cache hit, not a new build
            return Ok((None, None));
        }
        if build.is_pure_prebuilt() {
            info!("Materializing prebuilt package: {}", build.name);
            let result = materialize_prebuilt(
                build,
                &bsh,
                &self.cache,
                &self.lockfile,
                &self.remote_storage,
            )
            .await?;
            info!("Successfully materialized prebuilt package: {}", build.name);
            return Ok((Some(result), None));
        }

        let (dependencies, inputs, temp_dirs) = self
            .sandbox_paths_from_buildspec(build, remote_cache)
            .await?;

        if build.cmd.trim().is_empty() {
            info!(
                "No-op package with empty cmd: {}, creating cache entry",
                build.name
            );
            let cache_handle = self.cache.write_dir(&bsh).unwrap();
            Ok((Some(cache_handle), None))
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
                name: build.name.clone(),
                dependencies,
                inputs,
                build_script: BuildScript {
                    executable: executable.into(),
                    args,
                    build_args: build.build_args.clone(),
                },
                outputs: build
                    .outputs
                    .values()
                    .map(|output| match output {
                        BuildOutput::Library { glob } => glob.clone(),
                        BuildOutput::Data { glob } => glob.clone(),
                        BuildOutput::Binary { glob } => glob.clone(),
                    })
                    .collect(),
            };

            let out_dir = self.cache.write_dir(&bsh).unwrap();

            info!("Building package: {}", build.name);
            let build_result = run_build(
                &config,
                out_dir.path(),
                spongebob_invocation,
                self.output_base.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to build {}: {}", build.name, e))?;

            // Extract SpongeBob URL from BuildResult
            let spongebob_url = build_result.spongebob_url;

            info!("Successfully built package: {}", build.name);
            for tempdir in temp_dirs.into_iter() {
                drop(tempdir);
            }
            Ok((Some(out_dir), spongebob_url))
        }
    }

    pub async fn execute<BP: BinProvider>(
        &mut self,
        plan: ExecPlan<'a, BP>,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
        spongebob_invocation: &mut Option<spongebob::SpongeBobInvocation>,
    ) -> Result<()> {
        // Execute builds in dependency order - each build runs in isolation
        // and can only access outputs from previously completed builds

        let tokio_runtime = tokio::runtime::Handle::current();

        for phase in plan {
            use std::sync::{Arc, Mutex};
            let self2 = Arc::new(&*self);
            let build_which_errored = Arc::new(Mutex::new(None));
            let cache_handles = Arc::new(Mutex::new(Vec::with_capacity(
                phase.as_ref().unwrap().builds.len(),
            )));
            let spongebob_urls = Arc::new(Mutex::new(Vec::<String>::new()));

            rayon::scope(|s| {
                for (bsr, full_build) in phase.unwrap().builds.iter() {
                    let tokio_runtime = tokio_runtime.clone();
                    let bsr = bsr.to_owned();
                    let full_build = full_build.to_owned();
                    let self2 = self2.clone();
                    let err_bsr = build_which_errored.clone();
                    let cache_handles = cache_handles.clone();
                    let spongebob_urls = spongebob_urls.clone();
                    let mut invocation_clone = spongebob_invocation.clone();

                    s.spawn(move |_| {
                        let _rt = tokio_runtime.enter();
                        let result = futures::executor::block_on(self2.do_build(
                            &bsr,
                            full_build,
                            remote_cache,
                            &mut invocation_clone,
                        ));

                        match result {
                            Err(e) => {
                                *err_bsr.lock().unwrap() = Some((bsr, e));
                            }
                            Ok((cache_handle, spongebob_url)) => {
                                if let Some(cache_handle) = cache_handle {
                                    cache_handles.lock().unwrap().push((
                                        cache_handle,
                                        self2.graph.get(&bsr).unwrap().name.clone(),
                                    ));
                                }
                                if let Some(url) = spongebob_url {
                                    spongebob_urls.lock().unwrap().push(url);
                                }
                            }
                        }
                    });
                }
            });

            let err = Arc::into_inner(build_which_errored)
                .unwrap()
                .into_inner()
                .unwrap();

            // Commit all the builds to the build cache
            Arc::into_inner(cache_handles)
                .unwrap()
                .into_inner()
                .unwrap()
                .into_iter()
                .for_each(|(cache_hnd, name)| {
                    cache_hnd
                        .finalize(cache::EntryMeta {
                            spec_name: name,
                            fetched: false,
                            ..Default::default()
                        })
                        .unwrap()
                });

            // Store the latest SpongeBob URL (if any) for display at the end
            let urls = Arc::into_inner(spongebob_urls)
                .unwrap()
                .into_inner()
                .unwrap();
            if let Some(latest_url) = urls.last() {
                self.latest_spongebob_url = Some(latest_url.clone());
            }

            err.map(|(_bsr, e)| Err(e)).unwrap_or(Ok(()))?;
        }

        Ok(())
    }

    /// Get the latest SpongeBob URL from the most recent build session
    #[allow(dead_code)]
    pub fn latest_spongebob_url(&self) -> Option<&String> {
        self.latest_spongebob_url.as_ref()
    }
}

fn extract_prebuilt_archive(archive_path: &PathBuf, extract_dir: &PathBuf) -> Result<()> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = zstd::stream::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(extract_dir)?;
    Ok(())
}
