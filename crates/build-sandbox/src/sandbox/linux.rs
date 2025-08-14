use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;
use tracing::info;

use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};

use super::Sandbox;
use crate::config::BuildConfig;
use crate::error::Result;

pub struct LinuxSandbox {
    config: BuildConfig,
}

fn debug_log() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/mount_namespace_debug.log")
}

fn create_namespaces() -> std::io::Result<()> {
    let _ = debug_log()
        .and_then(|mut f| f.write_all(b"Step 1: Creating user and mount namespaces...\n"));

    match unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(_) => {
            let _ = debug_log().and_then(|mut f| {
                f.write_all("[OK] User and mount namespaces created successfully\n".as_bytes())
            });
            Ok(())
        }
        Err(e) => {
            let msg = format!("[ERROR] Failed to create namespaces: {}\n", e);
            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            Err(std::io::Error::other(format!("unshare failed: {}", e)))
        }
    }
}

fn setup_uid_gid_mapping() -> std::io::Result<()> {
    let _ = debug_log().and_then(|mut f| f.write_all(b"Step 2: Setting up UID/GID mappings...\n"));

    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };

    let msg = format!("  Current UID: {}, GID: {}\n", current_uid, current_gid);
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    let parent_uid = 1000;
    let uid_mapping = format!("{} {} 1", current_uid, parent_uid);
    let msg = format!("  Writing uid_map: '{}'\n", uid_mapping);
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    std::fs::write("/proc/self/uid_map", &uid_mapping).map_err(|e| {
        let msg = format!("[ERROR] UID mapping failed: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("UID mapping failed: {}", e))
    })?;

    let _ = debug_log().and_then(|mut f| f.write_all("[OK] UID mapping successful\n".as_bytes()));

    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| {
            let msg = format!("[WARN] setgroups deny failed: {}\n", e);
            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            e
        })
        .ok();

    let _ =
        debug_log().and_then(|mut f| f.write_all("[OK] setgroups deny successful\n".as_bytes()));

    let parent_gid = 1000;
    let gid_mapping = format!("{} {} 1", current_gid, parent_gid);
    let msg = format!("  Writing gid_map: '{}'\n", gid_mapping);
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    std::fs::write("/proc/self/gid_map", &gid_mapping).map_err(|e| {
        let msg = format!("[ERROR] GID mapping failed: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("GID mapping failed: {}", e))
    })?;

    let _ = debug_log().and_then(|mut f| f.write_all("[OK] GID mapping successful\n".as_bytes()));

    Ok(())
}

fn create_isolated_root() -> std::io::Result<String> {
    let _ = debug_log()
        .and_then(|mut f| f.write_all(b"Step 3: Creating isolated root filesystem...\n"));

    let new_root = format!("/tmp/build_sandbox_root_{}", std::process::id());
    std::fs::create_dir_all(&new_root).map_err(|e| {
        let msg = format!("[ERROR] Failed to create new root dir: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("mkdir failed: {}", e))
    })?;

    mount(
        Some("tmpfs"),
        new_root.as_str(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=100m"),
    )
    .map_err(|e| {
        let msg = format!("[ERROR] Failed to mount tmpfs: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("tmpfs mount failed: {}", e))
    })?;

    let _ = debug_log().and_then(|mut f| f.write_all("[OK] Created tmpfs new root\n".as_bytes()));

    let _ =
        debug_log().and_then(|mut f| f.write_all(b"Step 4: Creating essential directories...\n"));
    let essential_dirs = ["tmp", "proc", "dev", "lib", "lib64", "opt"];
    for dir in essential_dirs {
        let new_dir = format!("{}/{}", new_root, dir);
        std::fs::create_dir_all(&new_dir).map_err(|e| {
            let msg = format!("[ERROR] Failed to create {}: {}\n", new_dir, e);
            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            std::io::Error::other(format!("mkdir failed: {}", e))
        })?;

        let msg = format!("[OK] Created directory {}\n", new_dir);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
    }

    // Create /bin as a symlink to /usr/bin
    let bin_link = format!("{}/bin", new_root);
    let usr_bin_target = "usr/bin";
    std::os::unix::fs::symlink(usr_bin_target, &bin_link).map_err(|e| {
        let msg = format!("[ERROR] Failed to create /bin symlink: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("symlink /bin -> /usr/bin failed: {}", e))
    })?;
    let msg = "[OK] Created symlink /bin -> /usr/bin\n".to_string();
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    Ok(new_root)
}

fn bind_buildroot_toolchain(dep_str: &str, new_root: &str) -> std::io::Result<()> {
    let msg = "  Special handling: mounting buildroot toolchain under /opt\n";
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    // Mount the entire toolchain under /opt/toolchain
    let dest_path = format!("{}/opt/toolchain", new_root);

    // Create the destination directory
    std::fs::create_dir_all(&dest_path).map_err(|e| {
        let msg = format!("  [ERROR] Failed to create {}: {}\n", dest_path, e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        e
    })?;

    // Bind mount the entire toolchain directory
    mount(
        Some(dep_str),
        dest_path.as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        let msg = format!(
            "  [ERROR] Failed to mount {} to {}: {}\n",
            dep_str, dest_path, e
        );
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("mount failed: {}", e))
    })?;

    let msg = format!("  [OK] Mounted toolchain {} to {}\n", dep_str, dest_path);
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    Ok(())
}

fn bind_minimal_out(dep: &std::path::Path, new_root: &str) -> std::io::Result<()> {
    let msg = "  Special handling: layering minimal-out packages on base system\n";
    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

    if let Ok(entries) = std::fs::read_dir(dep) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let entry_name = entry.file_name();
            let dest_path = format!("{}/{}", new_root, entry_name.to_string_lossy());

            if entry_path.is_dir() {
                std::fs::create_dir_all(&dest_path).map_err(|e| {
                    let msg = format!("  [ERROR] Failed to create {}: {}\n", dest_path, e);
                    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                    e
                })?;

                mount(
                    Some(entry_path.to_str().unwrap()),
                    dest_path.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    None::<&str>,
                )
                .map_err(|e| {
                    let msg = format!(
                        "  [ERROR] Failed to bind {} to {}: {}\n",
                        entry_path.display(),
                        dest_path,
                        e
                    );
                    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                    std::io::Error::other(format!("mount failed: {}", e))
                })?;

                let msg = format!("  [OK] Layered {} to {}\n", entry_path.display(), dest_path);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            }
        }
    }
    Ok(())
}

fn bind_dependencies(config: &BuildConfig, new_root: &str) -> std::io::Result<()> {
    let _ = debug_log()
        .and_then(|mut f| f.write_all(b"Step 5: Binding dependency paths into new root...\n"));

    for dep in &config.dependencies {
        let dep_str = dep.to_string_lossy();
        let msg = format!("  Binding dependency: {}\n", dep_str);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

        if dep_str.contains("toolchains/x86_64-buildroot-linux-gnu") {
            bind_buildroot_toolchain(&dep_str, new_root)?;
            continue;
        }

        if dep_str.ends_with("minimal-out") {
            bind_minimal_out(dep, new_root)?;
            continue;
        }

        let dest_path = format!("{}{}", new_root, dep_str);

        if let Some(parent) = std::path::Path::new(&dest_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                let msg = format!(
                    "  [ERROR] Failed to create parent dirs for {}: {}\n",
                    dest_path, e
                );
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                e
            })?;
        }

        if dep.is_file() {
            std::fs::File::create(&dest_path).map_err(|e| {
                let msg = format!(
                    "  [ERROR] Failed to create dest file {}: {}\n",
                    dest_path, e
                );
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                e
            })?;
        } else if dep.is_dir() {
            std::fs::create_dir_all(&dest_path).map_err(|e| {
                let msg = format!("  [ERROR] Failed to create dest dir {}: {}\n", dest_path, e);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                e
            })?;
        }

        mount(
            Some(dep_str.as_ref()),
            dest_path.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| {
            let msg = format!(
                "  [ERROR] Failed to bind {} to {}: {}\n",
                dep_str, dest_path, e
            );
            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            std::io::Error::other(format!("mount failed: {}", e))
        })?;

        let msg = format!("  [OK] Bound {} to {} (read-only)\n", dep_str, dest_path);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
    }

    Ok(())
}

fn bind_essential_directories(new_root: &str) -> std::io::Result<()> {
    let _ = debug_log()
        .and_then(|mut f| f.write_all(b"Step 6: Binding essential system directories...\n"));

    let essential_dirs = [
        ("/tmp", "tmp"),
        ("/proc", "proc"),
        ("/dev", "dev"),
        ("/lib", "lib"),
        ("/lib64", "lib64"),
    ];

    for (src, dest_rel) in essential_dirs {
        let dest_path = format!("{}/{}", new_root, dest_rel);
        match mount(
            Some(src),
            dest_path.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            Ok(_) => {
                let msg = format!("  [OK] Bound {} to {}\n", src, dest_path);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            }
            Err(e) => {
                let msg = format!("  [WARN] Failed to bind {} to {}: {}\n", src, dest_path, e);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            }
        }
    }

    Ok(())
}

fn pivot_to_new_root(new_root: &str) -> std::io::Result<()> {
    let _ = debug_log().and_then(|mut f| f.write_all(b"Step 7: Performing pivot_root...\n"));

    let old_root = format!("{}/old_root", new_root);
    std::fs::create_dir_all(&old_root).map_err(|e| {
        let msg = format!("[ERROR] Failed to create old_root dir: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("mkdir old_root failed: {}", e))
    })?;

    nix::unistd::pivot_root(new_root, &*old_root).map_err(|e| {
        let msg = format!("[ERROR] pivot_root failed: {}\n", e);
        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        std::io::Error::other(format!("pivot_root failed: {}", e))
    })?;

    let _ = debug_log().and_then(|mut f| f.write_all("[OK] pivot_root successful\n".as_bytes()));

    let _ = debug_log().and_then(|mut f| f.write_all(b"  Unmounting old root...\n"));
    match nix::mount::umount("/old_root") {
        Ok(_) => {
            let _ =
                debug_log().and_then(|mut f| f.write_all("  [OK] Old root unmounted\n".as_bytes()));

            if let Err(e) = std::fs::remove_dir("/old_root") {
                let msg = format!("  [WARN] Failed to remove old_root dir: {}\n", e);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
            } else {
                let _ = debug_log().and_then(|mut f| {
                    f.write_all("  [OK] Removed old_root directory\n".as_bytes())
                });
            }
        }
        Err(e) => {
            let msg = format!(
                "  [WARN] Failed to unmount old root: {} (continuing anyway)\n",
                e
            );
            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
        }
    }

    let _ = debug_log()
        .and_then(|mut f| f.write_all(b"=== Mount namespace setup completed successfully ===\n"));

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
                let _ = debug_log()
                    .and_then(|mut f| f.write_all(b"=== Mount namespace setup starting ===\n"));

                create_namespaces()?;
                setup_uid_gid_mapping()?;
                let new_root = create_isolated_root()?;
                bind_dependencies(&config, &new_root)?;
                bind_essential_directories(&new_root)?;
                pivot_to_new_root(&new_root)?;

                Ok(())
            });
        }

        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}
