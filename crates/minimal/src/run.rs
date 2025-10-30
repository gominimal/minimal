use anyhow::{Context, Result, bail};
use cache::{Cache, LocalDir, MetaInner, PendingDir, RemoteCache};
use common::SpecHash;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::{BinProvider, ExecPlan, RuntimeDep, SubsetInput};
use graph::{BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph};
use op::{Runnable, SpecBuild, SubsetBuild};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tempfile::Builder;
use tracing::{debug, info};

use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage};

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
            remote_cache
                .as_ref()
                .unwrap()
                .materialize(
                    input_hash,
                    MetaInner::Spec(input_build.name.clone()),
                    Some(input_build.from.as_ref().clone()),
                    cache,
                    input_build.name.as_str(),
                )
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

/// Yields the cached directory containing the subset of build artifacts described by the given [SubsetInput].
///
/// If the subset is not already materialized in the cache, it will be created.
pub async fn materialize_subset(
    subset: &SubsetInput,
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    remote_cache: Option<&RemoteCache<GcsStorage>>,
) -> Result<(BuildSpecRef, (PathBuf, PathBuf))> {
    let build = graph.get(&subset.from).unwrap();
    let subset_spec = subset.as_spec(graph);
    let subset_hash = graph.subset_hash(subset);

    match (
        cache.read_dir(&subset_hash),
        remote_cache.as_ref().map(|c| c.exists(&subset_hash)),
    ) {
        // We have the subset already in the local cache.
        (Ok(cache_entry), _) => {
            let cache_path = cache_entry.path().to_path_buf();
            Ok((subset.from, (cache_path, PathBuf::from("/"))))
        }
        // In the remote cache but not the local cache.
        (_, Some(true)) => {
            let name = format!("{} (subset)", build.name);

            remote_cache
                .as_ref()
                .unwrap()
                .materialize(
                    &subset_hash,
                    MetaInner::Subset(subset_spec),
                    Some(graph.get(&subset.from).unwrap().from.as_ref().clone()),
                    cache,
                    name.as_str(),
                )
                .await?;
            let cache_path = cache.read_dir(&subset_hash).unwrap().path().to_path_buf();
            Ok((subset.from, (cache_path, PathBuf::from("/"))))
        }
        (Err(cache::CacheErr::NotFound), None | Some(false)) => {
            // Subset is neither downloadable nor in the local cache.
            // Either:
            //  - We can build it: we have built the thing which this is a subset of
            //  - We can't (build we are a subset of isnt built) but theres a cycle-breaker.
            let dep_hash = graph.spec_hash(&subset.from);
            if let Ok(cache_dir) = cache.read_dir(&dep_hash) {
                drop(cache_dir);
                let pending_dir = SubsetBuild { subset }
                    .run(&op::Options {
                        cache: cache.clone(),
                        graph,
                        exec_base: "/invalid".into(),
                    })
                    .await
                    .unwrap();
                pending_dir.finalize(cache::EntryMeta {
                    inner: MetaInner::Subset(subset_spec),
                    fetched: false,
                    origin: Some(build.from.as_ref().clone()),
                    ..Default::default()
                })?;

                let cache_path = cache.read_dir(&subset_hash).unwrap().path().to_path_buf();
                return Ok((subset.from, (cache_path, PathBuf::from("/"))));
            };

            match build.replace_on_cycle {
                None => panic!(
                    "missing build in cache for subset of {} [{}]",
                    build.name,
                    subset_hash.0.to_hex(),
                ),
                Some(cycle_breaker) => {
                    let breaker_hash = graph.spec_hash(&cycle_breaker);
                    let breaker_build = graph.get(&cycle_breaker).unwrap();

                    debug!(
                        "  --- subbing in cycle breaker {} to resolve subset [{}] ---",
                        breaker_build.name,
                        breaker_hash.0.to_hex()
                    );
                    Box::pin(materialize_subset(
                        &subset.override_build(cycle_breaker),
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
                build.name,
                subset_hash.0.to_hex(),
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
        let (dep_bsr, dep_paths) = match dep {
            RuntimeDep::Build(bsr) => {
                path_for_self_spec(
                    bsr,
                    &graph.spec_hash(dep.bsr()),
                    graph.get(dep.bsr()).unwrap(),
                    graph,
                    cache,
                    remote_cache,
                )
                .await?
            }
            RuntimeDep::Subset(subset) => {
                materialize_subset(subset, graph, cache, remote_cache).await?
            }
        };

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

            extract_prebuilt_archive(&archive_path, output_dir)?;

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
        }
    }

    async fn sandbox_paths_from_buildspec(
        &self,
        build: &BuildSpec,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
    ) -> Result<HashSet<PathBuf>> {
        let mut dependencies = HashSet::new();

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
                Subset(s) => {
                    let (_based_on_bsr, paths) =
                        materialize_subset(s, self.graph, &self.cache, remote_cache).await?;
                    dependencies.insert(paths.0);
                }
                HostPath(_) => {
                    todo!();
                }
                Local { full_path, .. } => {
                    debug!("  Input {}: Local file from {}", i, full_path.display());
                    // Handled by [SpecBuild]
                }
                Source(source) => {
                    debug!("  Input {}: Source({:?})", i, source.from);
                    // Handled by [SpecBuild]
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

        Ok(dependencies)
    }

    /// runs a single isolated build, does not take self so it can be spawned in a thread.
    ///
    /// Upon success, returns the pending cache entry representing the build outputs.
    #[tracing::instrument(skip_all, fields(indicatif.pb_hide))]
    async fn do_build(
        &self,
        bsr: &BuildSpecRef,
        _full_build: bool,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
    ) -> Result<Option<PendingDir>> {
        let bsh = self.graph.spec_hash(bsr);
        let build = self.graph.get(bsr).unwrap();

        // Check if already in cache
        if let Ok(e) = self.cache.read_dir(&bsh) {
            info!(
                "Package {} already built and cached at: {}",
                build.name,
                e.path().display(),
            );
            // Return None to indicate this was a cache hit, not a new build
            return Ok(None);
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
            return Ok(Some(result));
        }

        let dependencies = self
            .sandbox_paths_from_buildspec(build, remote_cache)
            .await?;

        if build.cmd.trim().is_empty() {
            info!(
                "No-op package with empty cmd: {}, creating cache entry",
                build.name
            );
            let cache_handle = self.cache.write_dir(&bsh).unwrap();
            return Ok(Some(cache_handle));
        }

        let out_dir = SpecBuild {
            spec: bsr,
            override_deps: Some(dependencies),
            remote_fetcher: &self.remote_storage,
        }
        .run(&op::Options {
            cache: self.cache.clone(),
            graph: self.graph,
            exec_base: self.output_base.clone(),
        })
        .await
        .map_err(anyhow::Error::from)?;

        info!("Successfully built package: {}", build.name);
        Ok(Some(out_dir))
    }

    pub async fn execute<BP: BinProvider>(
        &mut self,
        plan: ExecPlan<'a, BP>,
        remote_cache: Option<&RemoteCache<GcsStorage>>,
    ) -> Result<()> {
        // Execute builds in dependency order - each build runs in isolation
        // and can only access outputs from previously completed builds

        let tokio_runtime = tokio::runtime::Handle::current();

        for phase in plan {
            use std::sync::{Arc, Mutex};
            let self2 = Arc::new(&*self);
            let build_which_errored = Arc::new(Mutex::new(None));
            let outputs = Arc::new(Mutex::new(Vec::with_capacity(
                phase.as_ref().unwrap().builds.len(),
            )));

            rayon::scope(|s| {
                for build in phase.unwrap().builds.iter() {
                    // TODO: Wire the build based on deps, rather than probing whats available

                    let tokio_runtime = tokio_runtime.clone();
                    let bsr = build.spec.to_owned();
                    let full_build = build.full_build();
                    let self2 = self2.clone();
                    let err_bsr = build_which_errored.clone();
                    let outputs = outputs.clone();

                    s.spawn(move |_| {
                        let _rt = tokio_runtime.enter();
                        let result = futures::executor::block_on(self2.do_build(
                            &bsr,
                            full_build,
                            remote_cache,
                        ));

                        match result {
                            Err(e) => {
                                *err_bsr.lock().unwrap() = Some((bsr, e));
                            }
                            Ok(cache_handle) => {
                                if let Some(cache_handle) = cache_handle {
                                    let build = self2.graph.get(&bsr).unwrap();
                                    outputs.lock().unwrap().push((
                                        cache_handle,
                                        cache::EntryMeta {
                                            inner: MetaInner::Spec(build.name.clone()),
                                            fetched: false,
                                            breaker_build: !full_build,
                                            origin: Some(build.from.as_ref().clone()),
                                            ..Default::default()
                                        },
                                    ));
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
            Arc::into_inner(outputs)
                .unwrap()
                .into_inner()
                .unwrap()
                .into_iter()
                .for_each(|(cache_hnd, meta)| cache_hnd.finalize(meta).unwrap());

            err.map(|(_bsr, e)| Err(e)).unwrap_or(Ok(()))?;
        }

        Ok(())
    }
}

fn extract_prebuilt_archive(archive_path: &PathBuf, extract_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(archive_path)?;
    use common::archive;
    archive::extract_compressed_tar(file, archive::Compression::Zstd, extract_dir, None)?;

    Ok(())
}
