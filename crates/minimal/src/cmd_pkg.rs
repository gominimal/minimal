use futures::channel::mpsc;
use graph::Graph;
use mctx::{Cache, Context, Error};
use orchestrator::BuildLogLine;
use tracing::{info, trace};

#[derive(Debug, clap::Args)]
pub struct PkgArgs {
    /// Whether to log stdout/stderr during the build
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Packages to build
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args=0..)]
    packages: Vec<String>,
}

pub async fn cmd_pkg(args: PkgArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_pkg");
    let graph = if !args.packages.is_empty() {
        ctx.graph_from_package_names(args.packages.clone())?
    } else {
        let mut g = ctx.graph_from_all_packages()?;
        g.top_levels = g.from_origin(&ctx.repo_origin()).collect();
        g
    };
    let cache = ctx.local_cache();

    let log_sink = if args.verbose {
        let (tx, mut rx) = mpsc::unbounded::<BuildLogLine>();
        tokio::spawn(async move {
            use futures::StreamExt;
            while let Some(log) = rx.next().await {
                if log.is_stderr {
                    tracing::warn!(target: "build", name = %log.name, "{}", log.line);
                } else {
                    tracing::info!(target: "build", name = %log.name, "{}", log.line);
                }
            }
        });
        Some(tx)
    } else {
        None
    };

    pkg_build_impl(&graph, ctx, cache, false, log_sink).await?;

    Ok(())
}

pub async fn pkg_build_impl(
    graph: &Graph,
    ctx: &mut Context,
    cache: Cache,
    quiet: bool,
    log_sink: Option<mpsc::UnboundedSender<BuildLogLine>>,
) -> Result<(), Error> {
    trace!("build_impl");

    ctx.build_graph(graph, log_sink).await?;

    // Display build summary
    if !quiet {
        display_build_summary(graph, &cache, ctx);
    }

    Ok(())
}

/// Display a summary of what was built and where outputs can be found
fn display_build_summary(graph: &Graph, cache: &Cache, _ctx: &mut Context) {
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
