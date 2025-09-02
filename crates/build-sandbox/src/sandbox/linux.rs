use std::{
    fs::{create_dir_all, remove_dir, write},
    os::unix::process::CommandExt,
    process::Command,
};

use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use tracing::info;

use super::Sandbox;
use crate::config::BuildConfig;
use crate::error::Result;

pub struct LinuxSandbox {
    config: BuildConfig,
}

fn create_namespaces() -> std::io::Result<(u32, u32)> {
    let original_uid = unsafe { libc::getuid() };
    let original_gid = unsafe { libc::getgid() };

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
        .map_err(|e| std::io::Error::other(format!("unshare failed: {}", e)))?;

    Ok((original_uid, original_gid))
}

fn setup_uid_gid_mapping(original_uid: u32, original_gid: u32) -> std::io::Result<()> {
    write("/proc/self/setgroups", "deny")
        .map_err(|e| std::io::Error::other(format!("setgroups deny failed: {}", e)))?;

    let uid_mapping = format!("0 {} 1", original_uid);
    write("/proc/self/uid_map", &uid_mapping)
        .map_err(|e| std::io::Error::other(format!("UID mapping failed: {}", e)))?;

    let gid_mapping = format!("0 {} 1", original_gid);
    write("/proc/self/gid_map", &gid_mapping)
        .map_err(|e| std::io::Error::other(format!("GID mapping failed: {}", e)))?;

    Ok(())
}

fn create_isolated_root() -> std::io::Result<String> {
    let new_root = format!("/tmp/build_sandbox_root_{}", std::process::id());
    create_dir_all(&new_root).map_err(|e| std::io::Error::other(format!("mkdir failed: {}", e)))?;

    mount(
        Some("tmpfs"),
        new_root.as_str(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=100m"),
    )
    .map_err(|e| std::io::Error::other(format!("tmpfs mount failed: {}", e)))?;

    Ok(new_root)
}

fn is_cache_directory(path: &std::path::Path) -> bool {
    path.to_string_lossy().contains("/.cache/minimal-builds/")
}

fn setup_overlayfs(config: &BuildConfig, new_root: &str) -> std::io::Result<()> {
    let cache_dirs: Vec<String> = config
        .dependencies
        .iter()
        .filter(|(path, namespace_path)| {
            is_cache_directory(path) && namespace_path.as_os_str() == "/"
        })
        .map(|(path, _)| path.to_string_lossy().to_string())
        .collect();

    if !cache_dirs.is_empty() {
        info!(
            "Setting up OverlayFS with {} cache directories as read-only lower layers",
            cache_dirs.len()
        );

        let overlay_base = format!("{}/overlay", new_root);
        let upper_dir = format!("{}/upper", overlay_base);
        let work_dir = format!("{}/work", overlay_base);
        create_dir_all(&upper_dir)
            .map_err(|e| std::io::Error::other(format!("create upper dir failed: {}", e)))?;
        create_dir_all(&work_dir)
            .map_err(|e| std::io::Error::other(format!("create work dir failed: {}", e)))?;

        let mount_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            cache_dirs.join(":"),
            upper_dir,
            work_dir
        );

        mount(
            Some("overlay"),
            new_root,
            Some("overlay"),
            MsFlags::empty(),
            Some(mount_opts.as_str()),
        )
        .map_err(|e| std::io::Error::other(format!("OverlayFS mount failed: {}", e)))?;
    }

    Ok(())
}

fn bind_essential_directories(new_root: &str) -> std::io::Result<()> {
    let essential_dirs = [("/tmp", "tmp"), ("/proc", "proc"), ("/dev", "dev")];

    for (src, dest_rel) in essential_dirs {
        let dest_path = format!("{}/{}", new_root, dest_rel);
        create_dir_all(&dest_path)
            .map_err(|e| std::io::Error::other(format!("mkdir failed: {}", e)))?;
        mount(
            Some(src),
            dest_path.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| std::io::Error::other(format!("bind mount {} failed: {}", src, e)))?;
    }

    let etc_path = format!("{}/etc", new_root);
    create_dir_all(&etc_path)
        .map_err(|e| std::io::Error::other(format!("mkdir /etc failed: {}", e)))?;
    mount(
        Some("tmpfs"),
        etc_path.as_str(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=10m"),
    )
    .map_err(|e| std::io::Error::other(format!("tmpfs mount /etc failed: {}", e)))?;

    Ok(())
}

fn pivot_to_new_root(new_root: &str, working_dir: Option<&str>) -> std::io::Result<()> {
    let old_root = format!("{}/old_root", new_root);
    create_dir_all(&old_root)
        .map_err(|e| std::io::Error::other(format!("mkdir old_root failed: {}", e)))?;

    nix::unistd::pivot_root(new_root, &*old_root)
        .map_err(|e| std::io::Error::other(format!("pivot_root failed: {}", e)))?;

    if let Some(wd) = working_dir {
        std::env::set_current_dir(wd)
            .map_err(|e| std::io::Error::other(format!("chdir failed: {}", e)))?;
    }

    remove_dir("/old_root").unwrap();

    Ok(())
}

impl Sandbox for LinuxSandbox {
    fn create_instance(config: &BuildConfig) -> Result<Box<dyn Sandbox>> {
        info!("Creating Linux native mount namespace sandbox");

        Ok(Box::new(LinuxSandbox {
            config: config.clone(),
        }))
    }

    fn execute(&self, command: &mut Command) -> Result<()> {
        let config = self.config.clone();

        unsafe {
            command.pre_exec(move || {
                // Get the current working directory before pivot_root
                let working_dir = std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(|s| s.to_string()));

                let (original_uid, original_gid) = create_namespaces()?;
                setup_uid_gid_mapping(original_uid, original_gid)?;
                let new_root = create_isolated_root()?;
                setup_overlayfs(&config, &new_root)?;
                bind_essential_directories(&new_root)?;
                pivot_to_new_root(&new_root, working_dir.as_deref())?;

                Ok(())
            });
        }

        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}
