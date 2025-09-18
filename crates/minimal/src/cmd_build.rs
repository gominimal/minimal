use crate::{Error, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use crate::{GlobalArgs, PackagesArg};
use anyhow::Context;
use cache::{Cache, CacheBinProvider, LocalDir};
use graph::{BuildSpecRef, DepGraph, ExecPlan};

#[derive(clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,
}

pub async fn cmd_build(args: BuildArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    let debug_bsr = if args.debug {
        Some(graph.top_levels[0])
    } else {
        None
    };

    cmd_build_impl(
        &graph,
        globals.no_cache,
        cache,
        debug_bsr,
        globals.num_parallel_builds,
    )
    .await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    ignore_cache: bool,
    cache: Cache<LocalDir>,
    debug_bsr: Option<BuildSpecRef>,
    num_parallel_builds: usize,
) -> anyhow::Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_parallel_builds)
        .build_global()
        .unwrap();

    let remote_storage = RemoteStorage::new().await.unwrap();

    // Load the lockfile
    let lockfile_path = std::path::Path::new("prebuilts.lock");
    let lockfile = PrebuiltsLock::load(lockfile_path).unwrap_or_else(|e| {
        eprintln!(
            "Warning: Failed to load lockfile {}: {}",
            lockfile_path.display(),
            e
        );
        eprintln!("Using empty lockfile...");
        PrebuiltsLock::default()
    });

    let mut run = Run::new(graph, cache.clone(), remote_storage, lockfile);
    if ignore_cache {
        run.execute(ExecPlan::new(graph), debug_bsr).await
    } else {
        let adapter = CacheBinProvider::new(graph, cache.clone());
        run.execute(ExecPlan::new_with_bin_provider(graph, adapter), debug_bsr)
            .await
    }
    .context("Failed to execute build")?;

    Ok(())
}
