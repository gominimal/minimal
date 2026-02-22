use std::{io::Write, path::PathBuf};

use anyhow::anyhow;
use graph::{DepGraph, Transitives};
use hakoniwa::Output;
use mctx::{Context, Error};
use mfile::TaskAction;
use shlex::Shlex;
use tracing::trace;

use crate::shim_listener;

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
    // Clone graph before make_env consumes it - needed for the shim listener
    let graph_for_shim = graph.clone();

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

    // Get paths from the environment for shim setup
    let rootfs_path = env.rootfs_path();
    let state_dir = env.state_dir().to_path_buf();

    // Locate min-client binary (next to current executable)
    let min_client_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("min-client")))
        .filter(|p| p.exists());

    // Inject the min binary and bashrc into the rootfs
    shim_listener::inject_shim_scripts(&rootfs_path, min_client_bin.as_deref())
        .map_err(|e| Error::Other(anyhow!("injecting shim scripts: {}", e)))?;

    // Create the /state/.min/ directory (visible inside sandbox)
    let min_dir = state_dir.join(".min");
    std::fs::create_dir_all(&min_dir)
        .map_err(|e| Error::Other(anyhow!("creating .min directory: {}", e)))?;

    // Compute the initial set of packages in the rootfs (for tracking)
    let initial_packages: std::collections::HashSet<_> =
        Transitives::for_toplevels(&graph_for_shim, graph_for_shim.top_levels.clone(), false)
            .keys()
            .copied()
            .collect();

    // Get mfile path for persistence
    let mfile_path = ctx.minimal_file().ok().and_then(|f| f.file_path().cloned());

    // Start the shim listener
    let listener_config = shim_listener::ShimListenerConfig {
        port_file_path: min_dir.join("port"),
        graph: graph_for_shim,
        cache: ctx.local_cache(),
        mctx_config: ctx.config(),
        rootfs_path,
        state_dir,
        mfile_path,
        task_name: task_name.to_string(),
        initial_packages,
    };
    let shim_handle = shim_listener::start(listener_config);

    // Create container and run the task command
    let container = env
        .container()
        .map_err(|e| Error::Other(anyhow!("building container failed: {}", e)))?;

    let result: Result<(), Error> = if let Some((command, args)) = task.exec_and_args() {
        let mut cmd = env
            .command(&container, &command, args)
            .map_err(|e| Error::Other(anyhow!("building command failed: {}", e)))?;
        cmd.spawn()
            .map_err(|e| Error::Other(anyhow!("command launch failed: {}", e)))?
            .wait()
            .map_err(|e| Error::Other(anyhow!("command failed: {}", e)))?;
        Ok(())
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

            Ok(())
        } else {
            unreachable!();
        }
    };

    // Shut down the shim listener
    shim_handle.shutdown();

    result
}
