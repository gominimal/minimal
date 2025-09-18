use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use anyhow::{Context, Result};
use cache::{Cache, CacheBinProvider, LocalDir};
use graph::{BuildSpecRef, DepGraph, ExecPlan};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct BuildArgs {
    /// Package names to build
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Option<Vec<String>>,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Whether to ignore the local cache
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Number of parallel builds
    #[arg(short, long, default_value_t = 4)]
    num_parallel_builds: usize,
}

pub async fn cmd_build(args: BuildArgs) -> Result<()> {
    let graph = match args.packages {
        Some(ref packages) => match packages.len() {
            0 => super::graph_from_all_packages(),
            1 => super::graph_from_package_name(&packages[0]),
            _ => super::graph_from_package_names(packages),
        },
        None => super::graph_from_all_packages(),
    };

    let debug_bsr = if args.debug {
        Some(graph.top_levels[0])
    } else {
        None
    };

    let cache = super::load_cache(args.cache_dir).unwrap();

    cmd_build_impl(
        &graph,
        args.no_cache,
        cache,
        debug_bsr,
        args.num_parallel_builds,
    )
    .await
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    ignore_cache: bool,
    cache: Cache<LocalDir>,
    debug_bsr: Option<BuildSpecRef>,
    num_parallel_builds: usize,
) -> Result<()> {
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
