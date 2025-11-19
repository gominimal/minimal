use crate::{Context, Error};
use anyhow::anyhow;
use graph::Transitives;
use op::Runnable;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
    let env_base_dir = ctx.paths().env_base_dir().to_path_buf();
    let mfile = ctx.minimal_file()?;
    let task = match mfile.tasks.get(&args.task_name) {
        Some(t) => t.clone(),
        None => {
            return Err(Error::Other(anyhow!(
                "no such task named '{}'",
                args.task_name
            )));
        }
    };
    let env = match mfile.envs.get(&task.env) {
        Some(e) => e.clone(),
        None => {
            return Err(Error::Other(anyhow!("no such env named '{}'", task.env)));
        }
    };
    let cwd = if task.inherit_cwd {
        std::env::current_dir().unwrap()
    } else {
        mfile.dir_path().unwrap().to_path_buf()
    };
    let state_base_dir = mfile.env_state_dir(&task.env, env_base_dir).unwrap();

    let graph = match env.packages.len() {
        0 => ctx.graph_from_package_name("base")?,
        1 => ctx.graph_from_package_name(&env.packages[0])?,
        _ => ctx.graph_from_package_names(&env.packages)?,
    };
    let cache = ctx.local_cache();
    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(&graph, ctx, cache.clone(), ctx.num_parallel_builds).await?;

    let transitive_deps = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);
    let base = tempfile::tempdir_in(ctx.paths().run_base_dir()).map_err(anyhow::Error::from)?;

    let mut op = op::EnvSetup {
        state_base_dir: &state_base_dir,
        top_levels: &graph.top_levels,
        transitives: &transitive_deps,

        cwd: &cwd,
        patches: Some(&env.patch),
        env_vars: Some(&env.vars),
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

    Ok(())
}
