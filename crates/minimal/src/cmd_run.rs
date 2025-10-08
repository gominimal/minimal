use crate::Error;
use crate::{GlobalArgs, PackagesArg};
use graph::Transitives;

use hakoniwa::Container;

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    packages: PackagesArg,

    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

pub async fn cmd_run(args: RunArgs, globals: &GlobalArgs) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = if args.packages.packages.is_none() {
        globals.graph_from_package_name(&"base".to_string())?
    } else {
        args.packages.graph(globals)?
    };
    let cache = globals.cache().map_err(anyhow::Error::from)?;
    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(
        &graph,
        globals,
        cache.clone(),
        globals.num_parallel_builds,
        true,
    )
    .await?;

    // Start setting up the run container
    let base = tempfile::tempdir().map_err(anyhow::Error::from)?;
    for dep in Transitives::for_toplevels(&graph, graph.top_levels.clone(), false).into_iter() {
        common::hardlink_dir_contents(
            cache.read_dir(&graph.spec_hash(&dep)).unwrap().path(),
            base.path(),
        )
        .map_err(anyhow::Error::from)?;
    }

    // Create the cwd in the rootfs, and bindmount the cwd to it
    let cwd = std::env::current_dir().unwrap();
    std::fs::create_dir_all(base.path().join(cwd.clone())).map_err(anyhow::Error::from)?;

    let command = if args.args[0].starts_with("/") || args.args[0].starts_with("./") {
        args.args[0].clone()
    } else {
        format!("/bin/{}", args.args[0])
    };
    let mut cmd = Container::new()
        .rootfs(base.path())
        .map_err(anyhow::Error::from)?
        .devfsmount("/dev")
        .tmpfsmount("/tmp")
        .bindmount_rw(cwd.clone().to_str().unwrap(), cwd.clone().to_str().unwrap())
        .symlink("/usr/bin", "/bin")
        .symlink("/usr/lib", "/lib64")
        .command(&command);

    cmd.args(args.args.iter().skip(1));
    cmd.current_dir(&cwd);
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env(
            "HOME",
            std::env::var("HOME").unwrap_or("/".to_string()).as_str(),
        )
        .env("LANG", "en_US.utf8")
        .env("LC_ALL", "en_US.utf8");

    cmd.spawn()
        .map_err(anyhow::Error::from)?
        .wait()
        .map_err(anyhow::Error::from)?;

    Ok(())
}
