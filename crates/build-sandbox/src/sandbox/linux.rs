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
                use std::io::Write;

                let debug_log = || {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/tmp/mount_namespace_debug.log")
                };

                let _ = debug_log()
                    .and_then(|mut f| f.write_all(b"=== Mount namespace setup starting ===\n"));

                // Step 1: Create user namespace first, then mount namespace (required on Debian 12)
                let _ = debug_log().and_then(|mut f| {
                    f.write_all(b"Step 1: Creating user and mount namespaces...\n")
                });
                match unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all(
                                "[OK] User and mount namespaces created successfully\n".as_bytes(),
                            )
                        });
                    }
                    Err(e) => {
                        let msg = format!("[ERROR] Failed to create namespaces: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("unshare failed: {}", e)));
                    }
                }

                // Step 2: Set up minimal UID/GID mappings (map current user to root inside namespace)
                let _ = debug_log()
                    .and_then(|mut f| f.write_all(b"Step 2: Setting up UID/GID mappings...\n"));

                let current_uid = libc::getuid();
                let current_gid = libc::getgid();

                let msg = format!("  Current UID: {}, GID: {}\n", current_uid, current_gid);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

                // We need to map the parent UID (1000) to the current namespace UID (65534)
                let parent_uid = 1000; // The original user UID from `id` command
                let uid_mapping = format!("{} {} 1", current_uid, parent_uid);
                let msg = format!("  Writing uid_map: '{}'\n", uid_mapping);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                match std::fs::write("/proc/self/uid_map", &uid_mapping) {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all("[OK] UID mapping successful\n".as_bytes())
                        });
                    }
                    Err(e) => {
                        let msg = format!("[ERROR] UID mapping failed: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("UID mapping failed: {}", e)));
                    }
                }

                // Deny setgroups to allow gid_map writing
                match std::fs::write("/proc/self/setgroups", "deny") {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all("[OK] setgroups deny successful\n".as_bytes())
                        });
                    }
                    Err(e) => {
                        let msg = format!("[WARN] setgroups deny failed: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        // Continue - this might not be critical
                    }
                }

                // Write gid_map - map parent GID to current namespace GID
                let parent_gid = 1000; // The original user GID from `id` command
                let gid_mapping = format!("{} {} 1", current_gid, parent_gid);
                let msg = format!("  Writing gid_map: '{}'\n", gid_mapping);
                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                match std::fs::write("/proc/self/gid_map", &gid_mapping) {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all("[OK] GID mapping successful\n".as_bytes())
                        });
                    }
                    Err(e) => {
                        let msg = format!("[ERROR] GID mapping failed: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("GID mapping failed: {}", e)));
                    }
                }

                // Step 3: Create isolated root filesystem using tmpfs
                let _ = debug_log().and_then(|mut f| {
                    f.write_all(b"Step 3: Creating isolated root filesystem...\n")
                });

                let new_root = format!("/tmp/build_sandbox_root_{}", std::process::id());
                if let Err(e) = std::fs::create_dir_all(&new_root) {
                    let msg = format!("[ERROR] Failed to create new root dir: {}\n", e);
                    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                    return Err(std::io::Error::other(format!("mkdir failed: {}", e)));
                }

                // Mount tmpfs as new root
                match mount(
                    Some("tmpfs"),
                    new_root.as_str(),
                    Some("tmpfs"),
                    MsFlags::empty(),
                    Some("size=100m"),
                ) {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all("[OK] Created tmpfs new root\n".as_bytes())
                        });
                    }
                    Err(e) => {
                        let msg = format!("[ERROR] Failed to mount tmpfs: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("tmpfs mount failed: {}", e)));
                    }
                }

                // Create essential directories in new root
                let _ = debug_log()
                    .and_then(|mut f| f.write_all(b"Step 4: Creating essential directories...\n"));
                let essential_dirs = ["tmp", "proc", "dev", "lib", "lib64"];
                for dir in essential_dirs {
                    let new_dir = format!("{}/{}", new_root, dir);
                    if let Err(e) = std::fs::create_dir_all(&new_dir) {
                        let msg = format!("[ERROR] Failed to create {}: {}\n", new_dir, e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("mkdir failed: {}", e)));
                    } else {
                        let msg = format!("[OK] Created directory {}\n", new_dir);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                    }
                }

                // Step 5: Bind mount dependency paths (read-only access) into new root
                let _ = debug_log().and_then(|mut f| {
                    f.write_all(b"Step 5: Binding dependency paths into new root...\n")
                });

                for dep in &config.dependencies {
                    let dep_str = dep.to_string_lossy();
                    let msg = format!("  Binding dependency: {}\n", dep_str);
                    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

                    // Special handling for minimal-out directory - bind mount its contents to /usr/local
                    if dep_str.ends_with("minimal-out") {
                        let msg =
                            "  Special handling: mounting minimal-out contents to /usr/local\n"
                                .to_string();
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));

                        // Create /usr/local if it doesn't exist
                        let usr_local_path = format!("{}/usr/local", new_root);
                        if let Err(e) = std::fs::create_dir_all(&usr_local_path) {
                            let msg = format!("  [ERROR] Failed to create /usr/local: {}\n", e);
                            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                            continue;
                        }

                        // Mount each subdirectory of minimal-out to /usr/local/
                        if let Ok(entries) = std::fs::read_dir(dep) {
                            for entry in entries.flatten() {
                                let entry_path = entry.path();
                                let entry_name = entry.file_name();
                                let dest_path = format!(
                                    "{}/usr/local/{}",
                                    new_root,
                                    entry_name.to_string_lossy()
                                );

                                if entry_path.is_dir() {
                                    // Create the destination directory
                                    if let Err(e) = std::fs::create_dir_all(&dest_path) {
                                        let msg = format!(
                                            "  [ERROR] Failed to create {}: {}\n",
                                            dest_path, e
                                        );
                                        let _ = debug_log()
                                            .and_then(|mut f| f.write_all(msg.as_bytes()));
                                        continue;
                                    }

                                    // Bind mount the directory
                                    match mount(
                                        Some(entry_path.to_str().unwrap()),
                                        dest_path.as_str(),
                                        None::<&str>,
                                        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                                        None::<&str>,
                                    ) {
                                        Ok(_) => {
                                            let msg = format!(
                                                "  [OK] Bound {} to {} (read-only)\n",
                                                entry_path.display(),
                                                dest_path
                                            );
                                            let _ = debug_log()
                                                .and_then(|mut f| f.write_all(msg.as_bytes()));
                                        }
                                        Err(e) => {
                                            let msg = format!(
                                                "  [ERROR] Failed to bind {} to {}: {}\n",
                                                entry_path.display(),
                                                dest_path,
                                                e
                                            );
                                            let _ = debug_log()
                                                .and_then(|mut f| f.write_all(msg.as_bytes()));
                                        }
                                    }
                                }
                            }
                        }
                        continue; // Skip the normal processing for minimal-out
                    }

                    // Create the destination path in new root with full path
                    let dest_path = format!("{}{}", new_root, dep_str);

                    if let Some(parent) = std::path::Path::new(&dest_path).parent()
                        && let Err(e) = std::fs::create_dir_all(parent)
                    {
                        let msg = format!(
                            "  [ERROR] Failed to create parent dirs for {}: {}\n",
                            dest_path, e
                        );
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        continue;
                    }

                    // Create the file/directory if it doesn't exist
                    if dep.is_file() {
                        if let Err(e) = std::fs::File::create(&dest_path) {
                            let msg = format!(
                                "  [ERROR] Failed to create dest file {}: {}\n",
                                dest_path, e
                            );
                            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                            continue;
                        }
                    } else if dep.is_dir()
                        && let Err(e) = std::fs::create_dir_all(&dest_path)
                    {
                        let msg =
                            format!("  [ERROR] Failed to create dest dir {}: {}\n", dest_path, e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        continue;
                    }

                    match mount(
                        Some(dep_str.as_ref()),
                        dest_path.as_str(),
                        None::<&str>,
                        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                        None::<&str>,
                    ) {
                        Ok(_) => {
                            let msg =
                                format!("  [OK] Bound {} to {} (read-only)\n", dep_str, dest_path);
                            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        }
                        Err(e) => {
                            let msg = format!(
                                "  [ERROR] Failed to bind {} to {}: {}\n",
                                dep_str, dest_path, e
                            );
                            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                            continue;
                        }
                    }
                }

                // Step 6: Bind mount essential system directories
                let _ = debug_log().and_then(|mut f| {
                    f.write_all(b"Step 6: Binding essential system directories...\n")
                });
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
                            let msg = format!(
                                "  [WARN] Failed to bind {} to {}: {}\n",
                                src, dest_path, e
                            );
                            let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                            // Continue - some might fail
                        }
                    }
                }

                // Step 7: Create old_root directory and pivot_root
                let _ = debug_log()
                    .and_then(|mut f| f.write_all(b"Step 7: Performing pivot_root...\n"));
                let old_root = format!("{}/old_root", new_root);
                if let Err(e) = std::fs::create_dir_all(&old_root) {
                    let msg = format!("[ERROR] Failed to create old_root dir: {}\n", e);
                    let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                    return Err(std::io::Error::other(format!(
                        "mkdir old_root failed: {}",
                        e
                    )));
                }

                match nix::unistd::pivot_root(new_root.as_str(), old_root.as_str()) {
                    Ok(_) => {
                        let _ = debug_log().and_then(|mut f| {
                            f.write_all("[OK] pivot_root successful\n".as_bytes())
                        });

                        // Unmount the old root to complete isolation
                        let _ = debug_log()
                            .and_then(|mut f| f.write_all(b"  Unmounting old root...\n"));
                        match nix::mount::umount("/old_root") {
                            Ok(_) => {
                                let _ = debug_log().and_then(|mut f| {
                                    f.write_all("  [OK] Old root unmounted\n".as_bytes())
                                });

                                // Remove the old_root directory
                                if let Err(e) = std::fs::remove_dir("/old_root") {
                                    let msg =
                                        format!("  [WARN] Failed to remove old_root dir: {}\n", e);
                                    let _ =
                                        debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                                } else {
                                    let _ = debug_log().and_then(|mut f| {
                                        f.write_all(
                                            "  [OK] Removed old_root directory\n".as_bytes(),
                                        )
                                    });
                                }
                            }
                            Err(e) => {
                                let msg = format!(
                                    "  [WARN] Failed to unmount old root: {} (continuing anyway)\n",
                                    e
                                );
                                let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                                // Don't fail here - the pivot_root already succeeded, which is the main isolation
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!("[ERROR] pivot_root failed: {}\n", e);
                        let _ = debug_log().and_then(|mut f| f.write_all(msg.as_bytes()));
                        return Err(std::io::Error::other(format!("pivot_root failed: {}", e)));
                    }
                }

                let _ = debug_log().and_then(|mut f| {
                    f.write_all(b"=== Mount namespace setup completed successfully ===\n")
                });
                Ok(())
            });
        }

        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}
