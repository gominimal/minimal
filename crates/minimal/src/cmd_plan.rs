use anyhow::Result;
use graph::ExecPlan;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Package name to build
    #[arg(short, long)]
    package: Option<String>,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub fn cmd_plan(args: PlanArgs) -> Result<()> {
    let graph = match args.package {
        Some(ref package) => super::graph_from_package_name(package, false),
        None => super::graph_from_all_packages(),
    };
    let cache = super::load_cache(args.cache_dir).unwrap();

    println!("✓ = Already built, ⚙️ = To be built");
    for (i, phase) in ExecPlan::new(&graph).enumerate() {
        println!("Phase {}", i + 1);
        for bsr in phase.iter() {
            let build = graph.get(bsr).unwrap();
            let bsh = graph.spec_hash(bsr);
            let is_cached = cache.read_dir(&bsh).is_ok();
            let cached_emoji = if is_cached { "✓" } else { "⚙️" };

            println!(" - {} {} [{}]", cached_emoji, build.name, bsh.0.to_hex());
        }
    }

    Ok(())
}
