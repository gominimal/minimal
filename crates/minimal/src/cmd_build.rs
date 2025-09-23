use crate::{Error, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use crate::{GlobalArgs, PackagesArg};
use anyhow::Context;
use cache::{Cache, CacheBinProvider, LocalDir, RemoteBinProvider};
use graph::{DepGraph, ExecPlan, Transitives};
use std::path::Path;

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
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_parallel_builds)
        .build_global()
        .unwrap();

    let mut run = Run::new(
        graph,
        cache.clone(),
        RemoteStorage::new().await.unwrap(),
        PrebuiltsLock::load(Path::new("prebuilts.lock")).unwrap(),
    );

    match (globals.no_cache, globals.no_fetch) {
        // No local or remote cache
        (true, true) => run.execute(ExecPlan::new(graph), None).await,
        // Both caches
        (false, false) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, (local_adapter, remote_adapter)),
                Some(&remote_cache),
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
            )
            .await
        }
        // Only local cache
        (false, true) => {
            let local_adapter = CacheBinProvider::new(&graph, cache.clone());
            run.execute(ExecPlan::new_with_bin_provider(graph, local_adapter), None)
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
            Transitives::for_toplevels(&graph, graph.top_levels.iter().copied().collect(), false)
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

    Ok(())
}
