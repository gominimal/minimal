//! Command to materialize outputs defined in the minimal file.

use anyhow::anyhow;
use std::path::PathBuf;

use crate::{Context, Error};

#[derive(clap::Args)]
pub struct MaterializeArgs {
    /// The output file to write
    #[arg(short, long)]
    output: PathBuf,

    /// The name of the output in `minimal.toml` to materialize
    output_name: String,
}

pub async fn cmd_materialize(args: MaterializeArgs, ctx: &mut Context) -> Result<(), Error> {
    let mfile = ctx.minimal_file()?;
    let output = match mfile.outputs.get(&args.output_name) {
        Some(t) => t.clone(),
        None => {
            return Err(Error::Other(anyhow!(
                "no such output named '{}'",
                args.output_name
            )));
        }
    };

    let graph = match output.packages.len() {
        0 => ctx.graph_from_package_names(&["base".to_string()])?,
        _ => ctx.graph_from_package_names(&output.packages)?,
    };
    let cache = ctx.local_cache();

    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(&graph, ctx, cache.clone(), false).await?;

    // Create the OCI image using the op orchestration struct
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
    };
    use op::Runnable;
    op.run(&opts).await?;

    Ok(())
}
