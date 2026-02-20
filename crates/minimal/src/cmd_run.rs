use std::{io::Write, path::PathBuf};

use anyhow::anyhow;
use graph::DepGraph;
use hakoniwa::Output;
use mctx::{Context, Error};
use mfile::TaskAction;
use shlex::Shlex;
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    pub task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");
    let graph = ctx.graph_from_all_packages()?;
    let (task, graph) = match ctx.task(graph, &args.task_name)? {
        None => return Err(Error::Other(anyhow!("no such task: {}", args.task_name))),
        Some((t, g)) => (t, g),
    };

    run_task(&args.task_name, &task, graph, ctx).await
}

pub async fn run_task(
    task_name: &str,
    task: &mfile::Task,
    graph: DepGraph,
    ctx: &mut Context,
) -> Result<(), Error> {
    let mut env = ctx
        .make_env(
            task_name,
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
    let container = env
        .container()
        .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;

    if let Some((command, args)) = task.exec_and_args() {
        let mut cmd = env
            .command(&container, &command, args)
            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
        cmd.spawn()
            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
            .wait()
            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
    } else {
        // exec_and_args() only valid for some action variants, handle the others here
        if let TaskAction::CmdCmd(argv) = &task.action {
            let mut meta_cmd = env
                .command(&container, &argv[0], &argv[1..])
                .map_err(|e| Error::Other(anyhow!("building meta-command failed: {}", e)))?;

            let Output {
                status,
                stderr,
                stdout,
            } = meta_cmd
                .output()
                .map_err(|e| Error::Other(anyhow!("meta-command failed: {}", e)))?;
            std::io::stderr().write_all(&stderr).unwrap();
            if !status.success() {
                return Err(Error::Other(anyhow!("meta-command failed: {:?}", status)));
            }

            use std::io::BufRead;
            for line_result in std::io::Cursor::new(stdout).lines() {
                match line_result {
                    Ok(line) => {
                        let mut args = Shlex::new(&line);
                        let prog = args.next().unwrap();
                        println!("+ {}", &line);

                        let mut cmd = env
                            .command(&container, &prog, args)
                            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
                        cmd.spawn()
                            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
                            .wait()
                            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
                    }
                    Err(e) => {
                        return Err(Error::IO("reading meta-commands", PathBuf::new(), e));
                    }
                }
            }
        } else {
            unreachable!();
        }
    }

    Ok(())
}
