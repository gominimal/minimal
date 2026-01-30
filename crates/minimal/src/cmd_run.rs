use anyhow::anyhow;
use graph::DepGraph;
use mctx::{Context, Error};
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");
    let graph = ctx.graph_from_all_packages()?;
    let (task, graph) = match ctx.task(graph, &args.task_name)? {
        None => return Err(Error::Other(anyhow!("no such task: {}", args.task_name))),
        Some((t, g)) => (t, g),
    };

    run_task(&task, graph, ctx).await
}

pub async fn run_task(task: &mfile::Task, graph: DepGraph, ctx: &mut Context) -> Result<(), Error> {
    let runnable_env = ctx
        .make_env(
            graph,
            if task.inherit_cwd {
                Some(std::env::current_dir().unwrap())
            } else {
                None
            },
            task.state_key.as_ref(),
            Some(&task.patch),
            Some(&task.vars),
            task.packages.clone(),
        )
        .await?;

    let (command, args) = task.cmd_and_args();
    let mut cmd = runnable_env
        .command(&command, args)
        .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
    cmd.spawn()
        .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
        .wait()
        .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;

    Ok(())
}
