//! Command to materialize outputs defined in the minimal file.

use anyhow::anyhow;
use common::Target;
use common::target::{Arch, OS};
use std::path::PathBuf;

use mctx::{Context, Error};

#[derive(clap::Args)]
pub struct MaterializeArgs {
    /// The output file to write
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture for OCI images (e.g., "amd64", "arm64").
    /// Overrides the `arch` field in minimal.toml and the host default.
    #[arg(long)]
    arch: Option<String>,

    /// The name of the output in `minimal.toml` to materialize
    output_name: String,
}

pub async fn cmd_materialize(args: MaterializeArgs, ctx: &mut Context) -> Result<(), Error> {
    let mfile = ctx.minimal_file();
    let output = match mfile.outputs.get(&args.output_name) {
        Some(t) => t.clone(),
        None => {
            return Err(Error::Other(anyhow!(
                "no such output named '{}'",
                args.output_name
            )));
        }
    };

    // Resolve target architecture: CLI flag > minimal.toml > host default.
    // String-to-arch parsing is delegated to common::target::Arch so the
    // alias set stays consistent across every consumer.
    let arch: Arch = match args.arch.or(output.arch) {
        Some(s) => s
            .parse()
            .map_err(|e: common::target::ArchParseError| Error::Other(anyhow!("{e}")))?,
        None => Target::host().arch().clone(),
    };

    // OCI images are always Linux
    let target = Target::new(arch, OS::Linux);

    // Build the graph for the target architecture
    let graph = match output.packages.len() {
        0 => ctx.graph_from_package_names_with_target(["base"], target)?,
        _ => ctx.graph_from_package_names_with_target(output.packages.clone(), target)?,
    };
    let cache = ctx.local_cache();

    // Make sure the packages are built for the target
    crate::cmd_pkg::pkg_build_impl(&graph, ctx, cache.clone(), false, false, None).await?;

    // Create the OCI image — arch is queried from graph.target()
    let mut op = op::OciImageCreate {
        packages: output.packages,
        output_file: args.output,
        name: Some(args.output_name.clone()),
        entrypoint: output.entrypoint,
        cmd: output.cmd,
        vars: output.vars,
    };
    let opts = op::Options {
        cache,
        graph: &graph,
        exec_base: "/invalid".into(),
        ot: ctx.op_tracker(),
    };

    use op::Runnable;
    op.run(&opts).await.map_err(|e| Error::Other(anyhow!(e)))
}
