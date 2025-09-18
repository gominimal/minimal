use crate::{Error, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use crate::{GlobalArgs, PackagesArg};
use anyhow::Context;
use cache::{Cache, CacheBinProvider, LocalDir};
use graph::{DepGraph, ExecPlan};
use std::path::Path;

#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_build(args: BuildArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    cmd_build_impl(&graph, globals.no_cache, cache, globals.num_parallel_builds).await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    ignore_cache: bool,
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
    if ignore_cache {
        run.execute(ExecPlan::new(graph)).await
    } else {
        let adapter = CacheBinProvider::new(graph, cache.clone());
        run.execute(ExecPlan::new_with_bin_provider(graph, adapter))
            .await
    }
    .context("Failed to execute build")?;

    Ok(())
}
