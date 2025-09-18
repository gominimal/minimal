use crate::{Error, GlobalArgs, PackagesArg};
use cache::{Cache, CacheBinProvider, LocalDir};
use graph::{BinProvider, DepGraph, ExecPlan};

#[derive(clap::Args)]
pub struct PlanArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub fn cmd_plan(args: PlanArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    if globals.no_cache {
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
