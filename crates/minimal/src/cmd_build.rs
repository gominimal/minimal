use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use anyhow::{Context, Result};
use graph::planner2::ExecPlan;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct BuildArgs {
    /// Package name to build
    #[arg(short, long)]
    package: Option<String>,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,

    /// Build from source instead of using prebuilt binaries
    #[arg(short, long)]
    source: bool,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Number of parallel builds
    #[arg(short, long, default_value_t = 4)]
    num_parallel_builds: usize,
}

pub async fn cmd_build(args: BuildArgs) -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.num_parallel_builds)
        .build_global()
        .unwrap();

    let graph = match args.package {
        Some(ref package) => super::graph_from_package_name(package, args.source),
        None => super::graph_from_all_packages(),
    };

    let debug_bsr = if args.debug {
        Some(graph.top_levels[0])
    } else {
        None
    };

    let cache = super::load_cache(args.cache_dir).unwrap();
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

    let mut run = Run::new(&graph, cache, remote_storage, lockfile);
    run.execute(ExecPlan::new(&graph), debug_bsr)
        .await
        .context("Failed to execute build")?;

    if args.source {
        for bsr in &graph.top_levels {
            run.upload_prebuilt_archive(graph.get(bsr).unwrap(), &graph.spec_hash(bsr))
                .await?;
        }
    }

    Ok(())
}
