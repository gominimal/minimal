use cache::{CacheBinProvider, RemoteBinProvider};
use graph::{BinProvider, ExecPlan, Graph};
use mctx::{Cache, Context, Error};

#[derive(clap::Args)]
pub struct PlanArgs {
    /// Packages to plan
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args=0..)]
    packages: Vec<String>,
}

pub async fn cmd_plan(args: PlanArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = if !args.packages.is_empty() {
        ctx.graph_from_package_names(args.packages.clone())?
    } else {
        let mut g = ctx.graph_from_all_packages()?;
        g.top_levels = g.from_origin(&ctx.repo_origin()).collect();
        g
    };
    let cache = ctx.local_cache();

    match (!ctx.use_local_cache(), !ctx.use_remote_cache()) {
        // no local or remote cache
        (true, true) => print_plan(&graph, &cache, ExecPlan::new(&graph)),
        // both local and remote cache
        (false, false) => {
            let local_adapter = CacheBinProvider::new(&graph, cache.clone());
            let remote_cache = ctx.remote_cache(false, false).await.unwrap();
            let remote_adapter = RemoteBinProvider::new(&graph, &remote_cache);
            print_plan(
                &graph,
                &cache,
                ExecPlan::new_with_bin_provider(&graph, (local_adapter, remote_adapter)),
            )
        }

        // Only remote cache
        (true, false) => {
            let remote_cache = ctx.remote_cache(false, false).await.unwrap();
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
    .map_err(|e| Error::Plan(Box::new((graph, e))))
}

fn print_plan<BP: BinProvider>(
    graph: &Graph,
    cache: &Cache,
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
