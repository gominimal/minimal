//! Command to materialize outputs defined in the minimal file.

use anyhow::anyhow;
use common::Target;
use common::target::{Arch, OS};
use graph::Transitives;
use mfile::{OutputKind, StrOrList};
use std::collections::HashMap;
use std::path::PathBuf;

use mctx::{Context, Error};

#[derive(clap::Args)]
pub struct MaterializeArgs {
    /// The output file to write
    #[arg(short, long)]
    output: PathBuf,

    /// Override the architecture used when building the output
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
    let arch: Arch = match args.arch.clone().or(output.arch) {
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

    crate::cmd_pkg::pkg_build_impl(&graph, ctx, ctx.local_cache(), true, false, None).await?;

    match output.kind {
        OutputKind::OciImage {
            entrypoint,
            cmd,
            vars,
        } => materialize_oci_image(&args, ctx, graph, output.packages, entrypoint, cmd, vars).await,
        OutputKind::RawFile { path } => materialize_raw_file(&args, ctx, graph, path).await,
    }
}

async fn materialize_oci_image(
    args: &MaterializeArgs,
    ctx: &mut Context,
    graph: graph::Graph,
    packages: Vec<String>,
    entrypoint: Option<StrOrList>,
    cmd: Option<StrOrList>,
    vars: HashMap<String, String>,
) -> Result<(), Error> {
    let mut op = op::OciImageCreate {
        packages,
        output_file: args.output.clone(),
        name: Some(args.output_name.clone()),
        entrypoint,
        cmd,
        vars,
    };
    let opts = op::Options {
        cache: ctx.local_cache(),
        graph: &graph,
        exec_base: "/invalid".into(),
        ot: ctx.op_tracker(),
    };

    use op::Runnable;
    op.run(&opts).await.map_err(|e| Error::Other(anyhow!(e)))
}

async fn materialize_raw_file(
    args: &MaterializeArgs,
    ctx: &mut Context,
    graph: graph::Graph,
    path: String,
) -> Result<(), Error> {
    let rel_path = if let Some(stripped) = path.strip_prefix("/") {
        stripped.to_string()
    } else {
        path.clone()
    };

    let cache = ctx.local_cache();
    let transitives = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);

    for dir in transitives
        .keys()
        .map(|bsr| cache.read_dir(&graph.spec_hash(bsr)))
    {
        let dir = dir.map_err(|e| Error::Other(anyhow!(e)))?;
        let p = dir.path().join(&rel_path);
        if p.exists() {
            std::fs::copy(&p, &args.output).map_err(|e| Error::IO("copying output file", p, e))?;
            return Ok(());
        }
    }

    Err(Error::Other(anyhow!(
        "raw-file output {:?} was not found in the built package set",
        path
    )))
}
