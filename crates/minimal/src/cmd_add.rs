//! Command to add packages as a dependency.

use mctx::{Context, Error};

#[derive(clap::Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub kind: AddKind,

    /// Packages to add, space-separated
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = false, num_args=0..)]
    pub packages: Vec<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
pub struct AddKind {
    /// Add as a runtime dependency - your program needs this package anywhere it runs
    #[arg(long)]
    runtime: bool,

    /// Add as a build dependency - your program needs this package to build
    #[arg(long)]
    build: bool,

    /// Add to a task's package list
    #[arg(long)]
    task: Option<String>,
}

pub async fn cmd_add(args: AddArgs, ctx: &mut Context) -> Result<(), Error> {
    // Side-effect of making sure the named packages exist.
    let graph = ctx.graph_from_package_names(args.packages.clone())?;

    match args.kind {
        // Build-time dependency
        AddKind { build: true, .. } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::BuildPackages,
        )?,
        // Run-time dependency
        AddKind { runtime: true, .. } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::RuntimePackages,
        )?,
        // Task
        AddKind {
            task: Some(task), ..
        } => ctx.add_deps(
            &graph,
            graph.top_levels.clone(),
            mctx::AddDepMode::TaskPackages { name: task },
        )?,
        _ => unreachable!(),
    }

    ctx.download_if_available(&graph, graph.top_levels.clone())
        .await?;
    Ok(())
}
