use anyhow::Result;
use cache::{Cache, CacheBinProvider, LocalDir};
use graph::{BinProvider, DepGraph, ExecPlan};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Package names to build
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Option<Vec<String>>,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Whether to ignore the local cache
    #[arg(long, default_value_t = false)]
    no_cache: bool,
}

pub fn cmd_plan(args: PlanArgs) -> Result<()> {
    let graph = match args.packages {
        Some(ref packages) => match packages.len() {
            0 => super::graph_from_all_packages(),
            1 => super::graph_from_package_name(&packages[0]),
            _ => super::graph_from_package_names(packages),
        },
        None => super::graph_from_all_packages(),
    };

    let cache = super::load_cache(args.cache_dir).unwrap();
    if args.no_cache {
        print_plan(&graph, &cache, ExecPlan::new(&graph));
    } else {
        let adapter = CacheBinProvider::new(&graph, cache.clone());
        print_plan(
            &graph,
            &cache,
            ExecPlan::new_with_bin_provider(&graph, adapter),
        );
    }

    Ok(())
}

fn print_plan<BP: BinProvider>(graph: &DepGraph, cache: &Cache<LocalDir>, plan: ExecPlan<BP>) {
    println!("✓ = Already built, ⚙️ = To be built");
    for (i, phase) in plan.enumerate() {
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
}
