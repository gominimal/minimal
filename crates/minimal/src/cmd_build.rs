use crate::{Error, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use crate::{GlobalArgs, PackagesArg};
use anyhow::Context;
use cache::{Cache, CacheBinProvider, LocalDir, RemoteBinProvider};
use graph::{DepGraph, ExecPlan, Transitives};
use std::path::Path;
use tracing::info;

#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_build(args: BuildArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    cmd_build_impl(&graph, globals, cache, globals.num_parallel_builds).await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    globals: &GlobalArgs,
    cache: Cache<LocalDir>,
    num_parallel_builds: usize,
) -> anyhow::Result<()> {
    // Create SpongeBob invocation for this build command
    let mut spongebob_client = spongebob::SpongeBob::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create SpongeBob client: {}", e))?;

    let command_info = format!(
        "build --packages {}",
        graph
            .top_levels
            .iter()
            .map(|bsr| graph.get(bsr).unwrap().name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );

    let mut spongebob_invocation = spongebob_client
        .create_invocation(&command_info)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create SpongeBob invocation: {}", e))?;
    let spongebob_url = spongebob_invocation.url().to_string();
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_parallel_builds)
        .build_global()
        .unwrap();

    let output_base = globals.path_config().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();

    let mut run = Run::new(
        graph,
        cache.clone(),
        RemoteStorage::new(globals.path_config().download_cache_dir().to_path_buf())
            .await
            .unwrap(),
        PrebuiltsLock::load(Path::new("prebuilts.lock")).unwrap(),
        output_base,
    );

    match (globals.no_cache, globals.no_fetch) {
        // No local or remote cache
        (true, true) => run.execute(ExecPlan::new(graph), None, &mut spongebob_invocation).await,
        // Both caches
        (false, false) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, (local_adapter, remote_adapter)),
                Some(&remote_cache),
                &mut spongebob_invocation,
            )
            .await
        }
        // Only remote cache
        (true, false) => {
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, remote_adapter),
                Some(&remote_cache),
                &mut spongebob_invocation,
            )
            .await
        }
        // Only local cache
        (false, true) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            run.execute(ExecPlan::new_with_bin_provider(graph, local_adapter), None, &mut spongebob_invocation)
                .await
        }
    }
    .context("Failed to execute build")?;

    // If we got this far, everything we need is either fetchable or built.
    //
    // There could still be stuff thats fetchable but not in the local cache. We
    // can materialize that locally now.
    if !globals.no_fetch {
        let needs_materialize: Vec<_> =
            Transitives::for_toplevels(graph, graph.top_levels.to_vec(), false)
                .into_iter()
                .filter_map(|bsr| {
                    // Filter runtime_deps that are in the local cache
                    cache
                        .read_dir(&graph.spec_hash(&bsr))
                        .map(|_| None)
                        .unwrap_or(Some(bsr))
                })
                .collect();

        if !needs_materialize.is_empty() {
            let remote_cache = globals.remote_cache().await.unwrap();
            let tokio_runtime = tokio::runtime::Handle::current();
            rayon::scope(|s| {
                let remote_cache = &remote_cache;
                let cache = &cache;
                for bsr in needs_materialize.into_iter() {
                    let tokio_runtime = tokio_runtime.clone();

                    s.spawn(move |_| {
                        let _rt = tokio_runtime.enter();
                        let span = tracing::info_span!(
                            "download_cached",
                            "indicatif.pb_show" = tracing::field::Empty,
                            "build" = graph.get(&bsr).unwrap().name,
                        );
                        let _enter = span.enter();

                        futures::executor::block_on(
                            remote_cache.materialize(&graph.spec_hash(&bsr), cache),
                        )
                        .unwrap();
                    });
                }
            });
        }
    }

    // Log build results to SpongeBob
    log_build_results_to_spongebob(&mut spongebob_invocation, graph, true).await?;

    // Display build summary
    display_build_summary(graph, &cache, globals, &run, &spongebob_url);

    Ok(())
}

/// Log build command results to SpongeBob
async fn log_build_results_to_spongebob(
    spongebob_invocation: &mut spongebob::SpongeBobInvocation,
    graph: &DepGraph,
    success: bool,
) -> anyhow::Result<()> {
    let packages_list = graph
        .top_levels
        .iter()
        .map(|bsr| graph.get(bsr).unwrap().name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let _build_summary = if success {
        format!(
            "Build completed successfully for packages: {}",
            packages_list
        )
    } else {
        format!("Build failed for packages: {}", packages_list)
    };

    let build_log = format!(
        "Build Command Summary\n\
         Packages: {}\n\
         Status: {}\n\
         Total packages: {}\n",
        packages_list,
        if success { "SUCCESS" } else { "FAILED" },
        graph.top_levels.len()
    );

    // Upload build summary
    info!("Uploading build summary to SpongeBob invocation");
    spongebob_invocation
        .upload_file("build-summary.txt", build_log.into_bytes())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to upload build summary to SpongeBob: {}", e))?;

    Ok(())
}

/// Display a summary of what was built and where outputs can be found
fn display_build_summary(
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    _globals: &GlobalArgs,
    _run: &Run,
    command_spongebob_url: &str,
) {
    info!("Build completed successfully!");

    // Show target packages and their cache locations
    if !graph.top_levels.is_empty() {
        info!("Target packages:");
        for bsr in &graph.top_levels {
            let build = graph.get(bsr).unwrap();
            let spec_hash = graph.spec_hash(bsr);

            // Check if the package exists in cache
            if let Ok(e) = cache.read_dir(&spec_hash) {
                info!("  {} -> {}", build.name, e.path().display());
            } else {
                info!("  {} -> (not in cache)", build.name);
            }
        }
    }
    info!("{}", command_spongebob_url);
}
