//! Command to add packages as a dependency.

use mctx::{Context, Error};

#[derive(clap::Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub kind: AddKind,

    /// Packages to add, comma-separated
    #[arg(value_delimiter=',', num_args=0..)]
    pub packages: Vec<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = false, multiple = false)]
pub struct AddKind {
    /// Add as a runtime dependency - your program needs this package anywhere it runs
    #[arg(long)]
    runtime: bool,

    /// Add as a tool - made available in your development shell
    #[arg(long, alias = "shell")]
    tool: bool,
}

pub async fn cmd_add(args: AddArgs, ctx: &mut Context) -> Result<(), Error> {
    // Side-effect of making sure the named packages exist.
    let graph = ctx.graph_from_package_names(args.packages.clone())?;

    match args.kind {
        AddKind {
            runtime: true,
            tool: true,
        } => unreachable!(),
        // Build-time dependency
        AddKind {
            runtime: false,
            tool: false,
        } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::BuildPackages,
        )?,
        // Run-time dependency
        AddKind {
            runtime: true,
            tool: false,
        } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::RuntimePackages,
        )?,
        // Tool
        AddKind {
            runtime: false,
            tool: true,
        } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::ToolPackages,
        )?,
    }

    ctx.download_if_available(&graph, graph.top_levels.clone())
        .await?;
    Ok(())
}
