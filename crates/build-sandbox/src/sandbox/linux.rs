use std::{
    fs::{File, create_dir_all, read_dir, remove_dir, write},
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

fn create_namespaces() -> std::io::Result<()> {
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
        .map_err(|e| std::io::Error::other(format!("unshare failed: {}", e)))
}

fn setup_uid_gid_mapping() -> std::io::Result<()> {
    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };

    let parent_uid = 1000;
    let uid_mapping = format!("{} {} 1", current_uid, parent_uid);
    write("/proc/self/uid_map", &uid_mapping)
        .map_err(|e| std::io::Error::other(format!("UID mapping failed: {}", e)))?;

    // Try to deny setgroups, but don't fail if it doesn't work
    let _ = write("/proc/self/setgroups", "deny");

    let parent_gid = 1000;
    let gid_mapping = format!("{} {} 1", current_gid, parent_gid);
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

fn bind_buildroot_toolchain(dep_str: &str, new_root: &str) -> std::io::Result<()> {
    let dest_path = format!("{}/opt/toolchain", new_root);
    create_dir_all(&dest_path)?;

    mount(
        Some(dep_str),
        dest_path.as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| std::io::Error::other(format!("mount failed: {}", e)))?;

    Ok(())
}

fn recursively_mount_files(
    host_dir: &std::path::Path,
    namespace_dir: &std::path::Path,
    new_root: &str,
) -> std::io::Result<()> {
    for entry in read_dir(host_dir)? {
        let entry = entry?;
        let host_path = entry.path();
        let file_name = entry.file_name();
        let namespace_path = namespace_dir.join(&file_name);
        let dest_path = format!("{}{}", new_root, namespace_path.to_string_lossy());

        if host_path.is_dir() {
            create_dir_all(&dest_path)?;
            recursively_mount_files(&host_path, &namespace_path, new_root)?;
        } else {
            if let Some(parent) = std::path::Path::new(&dest_path).parent() {
                create_dir_all(parent)?;
            }
            File::create(&dest_path)?;
            mount(
                Some(host_path.to_str().unwrap()),
                dest_path.as_str(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| std::io::Error::other(format!("mount failed for {}: {}", dest_path, e)))?;
        }
    }
    Ok(())
}

fn bind_dependencies(config: &BuildConfig, new_root: &str) -> std::io::Result<()> {
    for (host_path, namespace_path) in &config.dependencies {
        let host_str = host_path.to_string_lossy();
        let namespace_str = namespace_path.to_string_lossy();

        if host_str.contains("/home/bweeks/x-tools/x86_64-minimal-linux-gnu") {
            bind_buildroot_toolchain(&host_str, new_root)?;
            continue;
        }

        if host_path.is_dir() {
            recursively_mount_files(host_path, namespace_path, new_root)?;
        } else {
            let dest_path = format!("{}{}", new_root, namespace_str);

            if let Some(parent) = std::path::Path::new(&dest_path).parent() {
                create_dir_all(parent)?;
            }

            File::create(&dest_path)?;

            mount(
                Some(host_str.as_ref()),
                dest_path.as_str(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| std::io::Error::other(format!("mount failed: {}", e)))?;
        }
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
        .unwrap();
    }

    Ok(())
}

fn pivot_to_new_root(new_root: &str, working_dir: Option<&str>) -> std::io::Result<()> {
    let old_root = format!("{}/old_root", new_root);
    create_dir_all(&old_root)
        .map_err(|e| std::io::Error::other(format!("mkdir old_root failed: {}", e)))?;

    nix::unistd::pivot_root(new_root, &*old_root)
        .map_err(|e| std::io::Error::other(format!("pivot_root failed: {}", e)))?;

    // Change to the working directory if specified
    if let Some(wd) = working_dir {
        std::env::set_current_dir(wd)
            .map_err(|e| std::io::Error::other(format!("chdir failed: {}", e)))?;
    }

    // Try to unmount and remove old root, but don't fail if it doesn't work
    if nix::mount::umount("/old_root").is_ok() {
        let _ = remove_dir("/old_root");
    }

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

                create_namespaces()?;
                setup_uid_gid_mapping()?;
                let new_root = create_isolated_root()?;
                bind_dependencies(&config, &new_root)?;
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
