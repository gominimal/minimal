//! Command to materialize outputs defined in the minimal file.

use anyhow::anyhow;
use futures::StreamExt;
use futures::channel::mpsc;
use std::path::PathBuf;
use tracing::info;

use mctx::{Context, Error};
use op::{Materialize, MaterializeEvent, Runnable, Sink};

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
    let output = ctx
        .minimal_file()
        .outputs
        .get(&args.output_name)
        .ok_or_else(|| Error::Other(anyhow!("no such output named '{}'", args.output_name)))?
        .clone();

    let target = output
        .target(args.arch.as_deref())
        .map_err(|e| Error::Other(anyhow!("{e}")))?;
    let graph = ctx.graph_from_package_names_with_target(output.top_levels(), target)?;
    crate::cmd_pkg::pkg_build_impl(&graph, ctx, ctx.local_cache(), true, false, None).await?;

    let (tx, rx) = mpsc::unbounded();
    let renderer = tokio::spawn(log_events(rx));

    let mut op = Materialize {
        name: args.output_name,
        spec: output.kind.try_into()?,
        sink: Sink::Path(args.output),
        events: Some(tx),
    };
    let result = op
        .run(&op::Options {
            cache: ctx.local_cache(),
            graph: &graph,
            exec_base: "/invalid".into(),
            ot: ctx.op_tracker(),
        })
        .await;

    // Closes the event stream, so the renderer's last lines land before the
    // outcome is reported.
    drop(op);
    let _ = renderer.await;

    result?;
    Ok(())
}

/// Logs progress events until the sender is dropped.
async fn log_events(mut rx: mpsc::UnboundedReceiver<MaterializeEvent>) {
    while let Some(event) = rx.next().await {
        info!("{}", event.render());
    }
}
