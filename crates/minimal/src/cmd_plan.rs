use crate::{Error, GlobalArgs, PackagesArg};
use cache::{Cache, CacheBinProvider, LocalDir, RemoteBinProvider};
use graph::{BinProvider, DepGraph, ExecPlan};

#[derive(clap::Args)]
pub struct PlanArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_plan(args: PlanArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    match (globals.no_cache, globals.no_fetch) {
        // no local or remote cache
        (true, true) => print_plan(&graph, &cache, ExecPlan::new(&graph)),
        // both local and remote cache
        (false, false) => {
            let local_adapter = CacheBinProvider::new(&graph, cache.clone());
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(&graph, &remote_cache);
            print_plan(
                &graph,
                &cache,
                ExecPlan::new_with_bin_provider(&graph, (local_adapter, remote_adapter)),
            )
        }

        // Only remote cache
        (true, false) => {
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(&graph, &remote_cache);
            print_plan(
                &graph,
                &cache,
                ExecPlan::new_with_bin_provider(&graph, remote_adapter),
            )
        }
        // Only local cache
        (false, true) => {
            let local_adapter = CacheBinProvider::new(&graph, cache.clone());
            print_plan(
                &graph,
                &cache,
                ExecPlan::new_with_bin_provider(&graph, local_adapter),
            )
        }
    }
    .map_err(|e| Error::PlanErr(graph, e))
}

fn print_plan<BP: BinProvider>(
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    plan: ExecPlan<BP>,
) -> Result<(), graph::PlanErr> {
    eprintln!("✓ = Already built, ⚙️ = To be built");
    for (i, phase) in plan.enumerate() {
        eprintln!("Phase {}", i + 1);
        for build in phase?.builds.iter() {
            let b = graph.get(&build.spec).unwrap();
            let bsh = graph.spec_hash(&build.spec);
            let is_cached = cache.read_dir(&bsh).is_ok();
            let cached_emoji = if is_cached { "✓" } else { "⚙️" };
            let num_cycle_breakers = build
                .with_deps
                .iter()
                .filter_map(|d| d.cycle_breaker().to_owned())
                .count();

            eprintln!(
                " - {} {} [{}] full_build={} deps={} {}",
                cached_emoji,
                b.name,
                bsh.0.to_hex(),
                build.full_build(),
                build.with_deps.len(),
                if num_cycle_breakers > 0 {
                    format!("({} cycle-breakers)", num_cycle_breakers)
                } else {
                    "".to_string()
                }
            );
        }
    }

    Ok(())
}
