use anyhow::anyhow;
use graph::Graph;
use mctx::{Context, Error};
use tracing::trace;

#[derive(Debug, clap::Args)]
#[command(trailing_var_arg = true)]
pub struct RunArgs {
    pub task_name: String,
    /// Additional arguments to pass to the task, parsed according to the task's args schema.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub task_args: Vec<String>,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");
    let graph = ctx.graph_from_all_packages()?;
    let (task, graph) = match ctx.task(graph, &args.task_name)? {
        None => return Err(Error::Other(anyhow!("no such task: {}", args.task_name))),
        Some((t, g)) => (t, g),
    };

    let parsed_args = if !task.args.is_empty() {
        Some(
            task.args
                .parse_argv_named(&format!("minimal run {}", args.task_name), &args.task_args)
                .map_err(|e| {
                    e.print().unwrap();
                    Error::Other(anyhow!(
                        "task {} called with invalid arguments",
                        args.task_name
                    ))
                })?,
        )
    } else {
        None
    };

    run_task(&args.task_name, &task, parsed_args, graph, ctx).await
}

pub async fn run_task(
    task_name: &str,
    task: &mfile::Task,
    parsed_args: Option<toml::Value>,
    mut graph: Graph,
    ctx: &mut Context,
) -> Result<(), Error> {
    let mut env = ctx
        .make_env(
            task_name,
            &mut graph,
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

    // Resolve the invocations to run from the task definition.
    let (interactive, invocations) = env.task_invocations(task, parsed_args.as_ref()).await?;

    // Execute: use container/command for interactive (preserves inherited stdio),
    if interactive {
        let container = env
            .container()
            .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;
        for inv in invocations {
            let mut cmd = env
                .command(&container, &inv.executable, inv.args.iter())
                .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
            cmd.spawn()
                .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
                .wait()
                .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
        }
    } else {
        trace!("Task invocation: {:?}", invocations);
        env.run(
            invocations,
            Some(tokio::io::stdout()),
            Some(tokio::io::stderr()),
        )
        .await?;
    }

    Ok(())
}
