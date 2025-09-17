use anyhow::Result;
use graph::planner2::ExecPlan;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Package names to build
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Option<Vec<String>>,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub fn cmd_plan(args: PlanArgs) -> Result<()> {
    let graph = match args.packages {
        Some(ref packages) => match packages.len() {
            0 => super::graph_from_all_packages(),
            1 => super::graph_from_package_name(&packages[0], false),
            _ => super::graph_from_package_names(packages),
        },
        None => super::graph_from_all_packages(),
    };

    let cache = super::load_cache(args.cache_dir).unwrap();

    println!("✓ = Already built, ⚙️ = To be built");
    for (i, phase) in ExecPlan::new(&graph).enumerate() {
        println!("Phase {}", i + 1);
        for (bsr, do_full_build) in phase.unwrap().builds.iter() {
            let build = graph.get(bsr).unwrap();
            let bsh = graph.spec_hash(bsr);
            let is_cached = cache.read_dir(&bsh).is_ok();
            let cached_emoji = if is_cached { "✓" } else { "⚙️" };

            println!(
                " - {} {} [{}] full_build={}",
                cached_emoji,
                build.name,
                bsh.0.to_hex(),
                do_full_build
            );
        }
    }

    Ok(())
}
