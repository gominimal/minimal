use crate::{Context, Error};
use anyhow::anyhow;
use graph::Transitives;
use op::Runnable;
use tracing::trace;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    trace!("cmd_run");
    let mut graph = ctx.graph_from_all_packages()?;
    let mut temp_dirs = vec![];
    let env_base_dir = ctx.paths().env_base_dir().to_path_buf();

    let cache = ctx.local_cache();
    let mfile = ctx.minimal_file()?;
    let mut task = match mfile.tasks.get(&args.task_name) {
        Some(t) => t.clone(),
        None => {
            return Err(Error::Other(anyhow!(
                "no such task named '{}'",
                args.task_name
            )));
        }
    };

    graph.hydrate_task(&mut task)?; // Apply profile settings

    graph.top_levels = task
        .packages
        .iter()
        .flat_map(|p| graph.by_name(p))
        .cloned()
        .collect(); // TODO: Probably time to retire this top_levels concept

    let cwd = if task.inherit_cwd {
        std::env::current_dir().unwrap()
    } else {
        mfile.repo_path().unwrap().to_path_buf()
    };

    let state_base_dir = match &task.state_key {
        Some(name) => mfile.state_dir(name, env_base_dir).unwrap(),
        None => {
            let tmp = cache.temp_dir().map_err(|e| {
                Error::Other(anyhow::Error::from(e).context("creating temporary state directory"))
            })?;
            let tmp_path = tmp.path().to_path_buf();
            temp_dirs.push(tmp);
            tmp_path
        }
    };

    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(&graph, ctx, cache.clone()).await?;

    let transitive_deps = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);
    let base = tempfile::tempdir_in(ctx.paths().run_base_dir()).map_err(anyhow::Error::from)?;

    let mut op = op::EnvSetup {
        state_base_dir: &state_base_dir,
        top_levels: &graph.top_levels,
        transitives: &transitive_deps,

        cwd: &cwd,
        patches: Some(&task.patch),
        env_vars: Some(&task.vars),
        hostname: task.state_key.to_owned(),
    };
    let opts = op::Options {
        cache,
        graph: &graph,
        exec_base: base.path().to_path_buf(),
    };
    let runnable_env = op.run(&opts).await?;

    let (command, args) = task.cmd_and_args();
    let mut cmd = runnable_env.command(&command, args)?;
    cmd.spawn()
        .map_err(anyhow::Error::from)?
        .wait()
        .map_err(anyhow::Error::from)?;

    drop(temp_dirs);
    Ok(())
}
