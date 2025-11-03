use crate::Context;
use crate::Error;
use anyhow::anyhow;
use graph::Transitives;

use hakoniwa::Container;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Any additional directories to bind-mount read-write.
    #[arg(long, required = false)]
    rw_dir: Vec<String>,

    task_name: String,
}

pub async fn cmd_run(args: RunArgs, ctx: &mut Context) -> Result<(), Error> {
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

    let graph = match env.packages.len() {
        0 => ctx.graph_from_package_name("base")?,
        1 => ctx.graph_from_package_name(&env.packages[0])?,
        _ => ctx.graph_from_package_names(&env.packages)?,
    };
    let cache = ctx.local_cache();
    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(&graph, ctx, cache.clone(), ctx.num_parallel_builds).await?;

    // Start setting up the run container
    let base = tempfile::tempdir_in(ctx.paths().run_base_dir()).map_err(anyhow::Error::from)?;
    for dep in Transitives::for_toplevels(&graph, graph.top_levels.clone(), false).into_iter() {
        common::hardlink_dir_contents(
            cache.read_dir(&graph.spec_hash(&dep)).unwrap().path(),
            base.path(),
        )
        .map_err(anyhow::Error::from)?;
    }

    // Create the cwd in the rootfs, and bindmount the cwd to it
    std::fs::create_dir_all(base.path().join(cwd.clone())).map_err(anyhow::Error::from)?;

    let mut container = Container::new();
    container
        .rootfs(base.path())
        .map_err(anyhow::Error::from)?
        .devfsmount("/dev")
        .tmpfsmount("/tmp")
        .bindmount_rw(cwd.clone().to_str().unwrap(), cwd.clone().to_str().unwrap())
        .symlink("/usr/bin", "/bin")
        .symlink("/usr/lib", "/lib64");
    for rw_mount in args.rw_dir {
        std::fs::create_dir_all(base.path().join(rw_mount.clone())).map_err(anyhow::Error::from)?;
        container.bindmount_rw(&rw_mount, &rw_mount);
    }
    // TODO: Support bind-mounting files using the below setup
    // container.mount(
    //     "/home/xxx/.claude.json",
    //     "/home/xxx/.claude.json",
    //     "",
    //     hakoniwa::MountOptions::BIND,
    // );

    let (command, args) = task.cmd_and_args();
    let mut cmd = container.command(&command);
    cmd.args(args);

    cmd.current_dir(&cwd);
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env(
            "HOME",
            std::env::var("HOME").unwrap_or("/".to_string()).as_str(),
        )
        .env("LANG", "en_US.utf8")
        .env("LC_ALL", "en_US.utf8")
        .env("PWD", cwd.to_str().unwrap());
    if let Ok(term) = std::env::var("TERM") {
        cmd.env("TERM", term.as_str());
    }
    if let Ok(ct) = std::env::var("COLORTERM") {
        cmd.env("COLORTERM", ct.as_str());
    }
    if let Ok(lsc) = std::env::var("LS_COLORS") {
        cmd.env("LS_COLORS", lsc.as_str());
    }
    env.vars.iter().for_each(|(var, val)| {
        cmd.env(var, val);
    });

    cmd.spawn()
        .map_err(anyhow::Error::from)?
        .wait()
        .map_err(anyhow::Error::from)?;

    Ok(())
}
