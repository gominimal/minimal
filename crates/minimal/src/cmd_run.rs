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
    let mut env = match mfile.envs.get(&task.env) {
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
    // Make sure the directories for storing durable state exist.
    let state_base_dir = mfile.env_state_dir(&task.env, env_base_dir).unwrap();
    std::fs::create_dir_all(state_base_dir.join("home")).map_err(anyhow::Error::from)?; // XDG_CONFIG_HOME ala ~/.config
    std::fs::create_dir_all(state_base_dir.join("data")).map_err(anyhow::Error::from)?; // XDG_DATA_HOME ala ~/.local/share
    std::fs::create_dir_all(state_base_dir.join("cache")).map_err(anyhow::Error::from)?; // XDG_CACHE_HOME  ala ~/.cache
    std::fs::create_dir_all(state_base_dir.join("state")).map_err(anyhow::Error::from)?; // XDG_STATE_HOME  ala ~/.local/state

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

        // Check attributes on each dependency to see if theres any additional env wiring.
        let attrs = &graph.get(&dep).unwrap().attrs;
        if let Some(dirs) = attrs.get("env_dir_mappings") {
            for mapping in dirs.as_list().unwrap() {
                let mapping = mapping.as_map().unwrap();
                env.patch.dir.insert(
                    mapping.get("path").unwrap().as_string().unwrap().clone(),
                    if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                        PatchSetting::ReadOnly
                    } else {
                        PatchSetting::ReadWrite
                    },
                );
            }
        }
        if let Some(dirs) = attrs.get("env_file_mappings") {
            for mapping in dirs.as_list().unwrap() {
                let mapping = mapping.as_map().unwrap();
                env.patch.file.insert(
                    mapping.get("path").unwrap().as_string().unwrap().clone(),
                    if *mapping.get("read_only").unwrap().as_bool().unwrap() {
                        PatchSetting::ReadOnly
                    } else {
                        PatchSetting::ReadWrite
                    },
                );
            }
        }
    }

    // Create the cwd & env in the rootfs
    std::fs::create_dir_all(base.path().join(cwd.clone())).map_err(anyhow::Error::from)?;
    std::fs::create_dir_all(base.path().join("state")).map_err(anyhow::Error::from)?;

    let mut container = Container::new();
    container
        .rootfs(base.path())
        .map_err(anyhow::Error::from)?
        .devfsmount("/dev")
        .tmpfsmount("/tmp")
        .bindmount_rw(cwd.clone().to_str().unwrap(), cwd.clone().to_str().unwrap())
        .bindmount_rw(state_base_dir.to_str().unwrap(), "/state")
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
            std::fs::write(&file, if file.ends_with(".json") { "{}" } else { "" })
                .map_err(anyhow::Error::from)?;
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
        .env("XDG_CONFIG_HOME", "/state/home")
        .env("XDG_DATA_HOME", "/state/data")
        .env("XDG_CACHE_HOME", "/state/cache")
        .env("XDG_STATE_HOME", "/state/state")
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
