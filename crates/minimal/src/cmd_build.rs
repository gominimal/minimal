use crate::run::Run;
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

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub fn cmd_build(args: BuildArgs) -> Result<()> {
    let dp = super::graph_from_package_name(&args.package);

    let debug_bsr = if args.debug { Some(dp.top_level) } else { None };

    let cache = super::load_cache(args.cache_dir).unwrap();
    let mut run = Run::new(dp, cache);
    run.execute(debug_bsr).unwrap();

    Ok(())
}
