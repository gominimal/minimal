use build_sandbox::Result;
use graph::{ExecPlan, SpecHash};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Package name to build
    #[arg(short, long)]
    package: String,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub fn cmd_plan(args: PlanArgs) -> Result<()> {
    let graph = super::graph_from_package_name(&args.package, false);
    let cache = super::load_cache(args.cache_dir).unwrap();
    println!("✓ = Already built, ⚙️ = To be built");

    for (i, phase) in ExecPlan::new(&graph).enumerate() {
        println!("Phase {}", i + 1);
        for bsr in phase.iter() {
            let build = graph.get(bsr).unwrap();
            let bsh = build.spec_hash(&graph);
            let is_cached = cache.read_dir(bsh).is_ok();
            let cached_emoji = if is_cached { "✓" } else { "⚙️" };

            println!(" - {} {} [{}]", cached_emoji, build.name, bsh.to_hex());
        }
    }

    Ok(())
}
