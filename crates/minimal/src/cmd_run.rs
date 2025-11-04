use std::env::home_dir;
use std::path::PathBuf;

use crate::Context;
use crate::Error;
use anyhow::anyhow;
use common::mfile::PatchSetting;
use graph::Transitives;

use hakoniwa::Container;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
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
    for dep in Transitives::for_toplevels(&graph, graph.top_levels.clone(), false).into_keys() {
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

    for (dir, opts) in &env.patch.dir {
        let dir = if let Some(stripped) = dir.strip_prefix("~/") {
            home_dir().unwrap().join(stripped)
        } else {
            PathBuf::from(dir.clone())
        };

        // Create the dir if it doesnt exist
        if let Err(e) = std::fs::create_dir(&dir)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(anyhow::Error::from(e).into());
        }
        // Create the dir in the sandbox rootfs
        std::fs::create_dir_all(base.path().join(&dir)).map_err(anyhow::Error::from)?;

        match opts {
            PatchSetting::ReadWrite => {
                container.bindmount_rw(dir.to_str().unwrap(), dir.to_str().unwrap());
            }
            PatchSetting::ReadOnly => {
                container.bindmount_ro(dir.to_str().unwrap(), dir.to_str().unwrap());
            }
        }
    }
    for (file, opts) in &env.patch.file {
        let file = if let Some(stripped) = file.strip_prefix("~/") {
            home_dir().unwrap().join(stripped)
        } else {
            PathBuf::from(file.clone())
        };

        // Create the dir if it doesnt exist
        if !std::fs::exists(&file).map_err(anyhow::Error::from)? {
            std::fs::write(&file, []).map_err(anyhow::Error::from)?;
        }
        // Create the dir in the sandbox rootfs
        std::fs::create_dir_all(base.path().join(file.parent().unwrap()))
            .map_err(anyhow::Error::from)?;

        container.mount(
            file.to_str().unwrap(),
            file.to_str().unwrap(),
            "",
            match opts {
                PatchSetting::ReadOnly => {
                    hakoniwa::MountOptions::BIND | hakoniwa::MountOptions::RDONLY
                }
                PatchSetting::ReadWrite => hakoniwa::MountOptions::BIND,
            },
        );
    }

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
