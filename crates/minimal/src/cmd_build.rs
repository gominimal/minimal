use crate::PackagesArg;
use graph::DepGraph;
use mctx::{Cache, Context, Error};
use tracing::{info, trace};

#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_build(args: BuildArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_build");
    let graph = ctx.graph_from_package_names(args.packages.names())?;
    let cache = ctx.local_cache();

    cmd_build_impl(&graph, ctx, cache, false).await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    ctx: &mut Context,
    cache: Cache,
    quiet: bool,
) -> Result<(), Error> {
    trace!("build_impl");

    ctx.build_graph(graph).await?;

    // Display build summary
    if !quiet {
        display_build_summary(graph, &cache, ctx);
    }

    Ok(())
}

/// Display a summary of what was built and where outputs can be found
fn display_build_summary(graph: &DepGraph, cache: &Cache, _ctx: &mut Context) {
    info!("Build completed successfully!");

    // Show target packages and their cache locations
    if !graph.top_levels.is_empty() {
        info!("Target packages:");
        for bsr in &graph.top_levels {
            let build = graph.get(bsr).unwrap();
            let spec_hash = graph.spec_hash(bsr);

            // Check if the package exists in cache
            if let Ok(e) = cache.read_dir(&spec_hash) {
                let suffix = if let Ok(meta) = cache.read_meta(&spec_hash) {
                    if let Some(fetch_ms) = meta.fetch_ms
                        && meta.fetched
                    {
                        if fetch_ms > 1000 {
                            format!("(fetched in {:.1}s)", fetch_ms as f32 / 1000.0)
                        } else {
                            format!("(fetched in {}ms)", fetch_ms)
                        }
                    } else if let Some(build_ms) = meta.build_ms {
                        if build_ms > 1000 {
                            format!("(built in {:.1}s)", build_ms as f32 / 1000.0)
                        } else {
                            format!("(built in {}ms)", build_ms)
                        }
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };
                info!("  {} -> {} {}", build.name, e.path().display(), suffix);
            }
        }
    }
}
