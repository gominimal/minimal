use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use build_sandbox::Result;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct BuildArgs {
    /// Package name to build
    #[arg(short, long)]
    package: String,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,

    /// Build from source instead of using prebuilt binaries
    #[arg(short, long)]
    source: bool,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub async fn cmd_build(args: BuildArgs) -> Result<()> {
    let dp = super::graph_from_package_name(&args.package, args.source);

    let debug_bsr = if args.debug { Some(dp.top_level) } else { None };

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

    let mut run = Run::new(
        dp,
        cache,
        args.source,
        args.package.clone(),
        remote_storage,
        lockfile,
    );
    run.execute(debug_bsr).await.unwrap();

    Ok(())
}
