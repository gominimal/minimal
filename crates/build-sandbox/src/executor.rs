use build_events::events::{
    BuildEvent, FileCreated, TargetCompleted, TargetKind, TargetStarted, build_event,
};
use hakoniwa::Container;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

use crate::config::{BuildConfig, Input};
use crate::error::{ExecutionError, Result};

#[derive(Debug)]
pub struct BuildExecutor {
    build_workspace_dir: PathBuf,
}

static HAKONIWA_SPAWN_LOCK: Mutex<()> = Mutex::new(());

impl BuildExecutor {
    /// Create a new build executor with a unique sandbox workspace
    ///
    /// # Parameters
    /// * `sandbox_base_dir` - Base directory where temporary build sandboxes are created
    /// * `package_name` - Name of the package being built (used in directory naming for debugging)
    #[tracing::instrument]
    pub fn new(sandbox_base_dir: PathBuf, package_name: String) -> Result<Self> {
        // Make sure the parent directory exists
        fs::create_dir_all(&sandbox_base_dir).map_err(|e| ExecutionError::FileOperation {
            operation: "create sandbox base directory".to_string(),
            path: sandbox_base_dir.display().to_string(),
            source: e,
        })?;

        // Create a unique directory name using package name, timestamp, and process ID.
        // At this layer its plausible that there might be two packages of the same name
        // built at the same time, so we do an atomic directory creation dance /w an attempt
        // counter to make sure each build gets its own folder.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ExecutionError::FileOperation {
                operation: "get timestamp".to_string(),
                path: String::new(),
                source: std::io::Error::other(e),
            })?
            .as_secs();
        let pid = std::process::id();
        let build_workspace_dir = {
            let mut attempt = 0u32;
            loop {
                let dir_name = if attempt == 0 {
                    format!("{}-{}-{}", package_name, timestamp, pid)
                } else {
                    format!("{}-{}-{}-{}", package_name, timestamp, pid, attempt)
                };

                let candidate_dir = sandbox_base_dir.join(dir_name);
                match fs::create_dir(&candidate_dir) {
                    Ok(()) => break candidate_dir,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        attempt += 1;
                        if attempt > 20 {
                            return Err(ExecutionError::FileOperation {
                                operation: "create build directory".to_string(),
                                path: candidate_dir.display().to_string(),
                                source: std::io::Error::new(
                                    std::io::ErrorKind::AlreadyExists,
                                    "too many directory creation attempts",
                                ),
                            }
                            .into());
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(ExecutionError::FileOperation {
                            operation: "create build directory".to_string(),
                            path: candidate_dir.display().to_string(),
                            source: e,
                        }
                        .into());
                    }
                }
            }
        };

        let executor = BuildExecutor {
            build_workspace_dir,
        };

        fs::create_dir_all(executor.output_staging_dir())
            .map_err(|_| ExecutionError::TempDirCreation)?;
        Ok(executor)
    }

    #[tracing::instrument(skip(config), fields(indicatif.pb_hide, package = %config.name))]
    pub async fn execute(&self, config: &BuildConfig, target_id: &str) -> Result<i32> {
        debug!(
            "Linking {} inputs to build environment",
            config.inputs.len()
        );
        for input in &config.inputs {
            match input {
                Input::File(p) => {
                    debug!("  Linking input: {}", p.display());
                    self.hardlink_to_tmpdir(p)?;
                }
                Input::Dir(p) => {
                    debug!("  Linking input dir: {}", p.display());
                    for entry in fs::read_dir(p)? {
                        let entry = entry?;
                        self.hardlink_to_tmpdir(&entry.path())?;
                    }
                }
            }
        }

        // Emit TargetStarted event using global event bus
        build_events::event_bus().emit(BuildEvent {
            event: Some(build_event::Event::TargetStarted(TargetStarted {
                target_id: target_id.to_string(),
                label: config.name.clone(),
                target_kind: TargetKind::Binary as i32,
                timestamp_millis: current_millis(),
            })),
        });

        let execute_result = self.execute_in_container(config, target_id).await;

        // Emit TargetCompleted event using global event bus
        let (success, error_message) = match &execute_result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        build_events::event_bus().emit(BuildEvent {
            event: Some(build_event::Event::TargetCompleted(TargetCompleted {
                target_id: target_id.to_string(),
                label: config.name.clone(),
                success,
                timestamp_millis: current_millis(),
                error_message,
                outputs: vec![],  // Outputs are collected later
                cache_hit: false, // Cache hit detection happens earlier
            })),
        });

        // Emit FileCreated events for stdout and stderr
        if let Ok(stdout_contents) = fs::read(self.build_workspace_dir.join("stdout")) {
            build_events::event_bus().emit(BuildEvent {
                event: Some(build_event::Event::FileCreated(FileCreated {
                    target_id: target_id.to_string(),
                    name: "stdout".to_string(),
                    contents: stdout_contents.into(),
                    timestamp_millis: current_millis(),
                })),
            });
        }

        if let Ok(stderr_contents) = fs::read(self.build_workspace_dir.join("stderr")) {
            build_events::event_bus().emit(BuildEvent {
                event: Some(build_event::Event::FileCreated(FileCreated {
                    target_id: target_id.to_string(),
                    name: "stderr".to_string(),
                    contents: stderr_contents.into(),
                    timestamp_millis: current_millis(),
                })),
            });
        }

        // Return the original result
        execute_result?;

        Ok(0)
    }

    pub fn build_workspace_dir(&self) -> &Path {
        &self.build_workspace_dir
    }

    pub fn output_staging_dir(&self) -> PathBuf {
        self.build_workspace_dir.join("output").to_path_buf()
    }

    fn hardlink_to_tmpdir(&self, input: &Path) -> Result<()> {
        let dest_path = if let Some(file_name) = input.file_name() {
            self.build_workspace_dir.join(file_name)
        } else {
            return Ok(());
        };

        if input.is_file() {
            match fs::hard_link(input, &dest_path) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        warn!(
                            "Not linking {} => {}, already exists",
                            input.display(),
                            dest_path.display()
                        );
                        Ok(())
                    } else {
                        Err(e)
                    }
                }
            }
            .map_err(|e| ExecutionError::HardLinkFailed {
                source: input.display().to_string(),
                destination: dest_path.display().to_string(),
                error: e,
            })?;
        } else if input.is_dir() {
            match fs::create_dir(&dest_path) {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(e.into());
                    }
                }
            };
            hardlink_dir_contents(input, &dest_path)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(config), fields(indicatif.pb_show))]
    async fn execute_in_container(&self, config: &BuildConfig, target_id: &str) -> Result<()> {
        let rootfs = self.prepare_rootfs(config)?;
        let sandbox_mount_point = "/build";
        let mut container = Container::new();
        container
            .rootfs(&rootfs)
            .map_err(|e| ExecutionError::SandboxFailed {
                message: format!("Failed to set rootfs: {}", e),
            })?
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            .bindmount_rw(
                self.build_workspace_dir.to_str().unwrap(),
                sandbox_mount_point,
            )
            .bindmount_rw(
                self.output_staging_dir().to_str().unwrap(),
                format!("{}/output", sandbox_mount_point).as_str(),
            )
            .unshare(hakoniwa::Namespace::Cgroup);

        let needs_bin_symlink = config
            .dependencies
            .iter()
            .all(|p| !fs::exists(p.join("bin")).unwrap());
        if needs_bin_symlink {
            container.symlink("/usr/bin", "/bin");
        }
        let needs_lib64_symlink = config
            .dependencies
            .iter()
            .all(|p| !fs::exists(p.join("lib64")).unwrap());
        if needs_lib64_symlink {
            container.symlink("/usr/lib", "/lib64");
        }

        if config.disable_networking {
            container.unshare(hakoniwa::Namespace::Network);
        }

        let mut stdout_f =
            fs::File::create(self.build_workspace_dir.join("stdout")).map_err(|e| {
                ExecutionError::SandboxFailed {
                    message: format!("Failed to create ./stdout: {}", e),
                }
            })?;
        let mut stderr_f =
            fs::File::create(self.build_workspace_dir.join("stderr")).map_err(|e| {
                ExecutionError::SandboxFailed {
                    message: format!("Failed to create ./stderr: {}", e),
                }
            })?;
        for exec in config.invocations.iter() {
            let mut program = exec.executable.to_string_lossy();

            // Add /usr/bin/ for commands that are not absolute, and don't shadow anything in cwd
            if !program.starts_with("/")
                && !fs::exists(rootfs.join("build").join(program.as_ref()))?
                && fs::exists(rootfs.join("usr/bin").join(program.as_ref()))?
            {
                *program.to_mut() = format!("/usr/bin/{}", &program);
            }

            let mut cmd = container.command(&program);
            cmd.stderr(hakoniwa::Stdio::MakePipe);
            cmd.stdout(hakoniwa::Stdio::MakePipe);
            for arg in &exec.args {
                cmd.arg(arg);
            }

            cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("HOME", sandbox_mount_point)
                .env("OUTPUT_DIR", &format!("{}/output", sandbox_mount_point))
                .env("LANG", "en_US.utf8")
                .env("LC_ALL", "en_US.utf8");
            if let Some(build_args) = &config.build_args {
                cmd.envs(build_args.iter().map(|(k, v)| {
                    (
                        "MINIMAL_ARG_".to_owned()
                            + &k.as_str()
                                .trim()
                                .replace("=", "")
                                .replace(":", "")
                                .replace("/", "")
                                .replace("\"", "")
                                .replace("'", "")
                                .to_uppercase(),
                        v,
                    )
                }));
            }

            debug!(
                "Executing: {} {}",
                exec.executable.display(),
                exec.args.join(" ")
            );

            cmd.current_dir(sandbox_mount_point);

            // Exclusive section: only one hakoniwa command can be spawned
            // at a time. This prevents races with a file descriptor being held
            // by one forked process while being needed closed in another process.
            //
            // Waiting for spawn lets us wait till exec, at which point all such
            // file descriptors (which have O_CLOEXEC) will have been closed.
            let mut child = {
                // recover from poisoned lock - no need to permanently break
                // all container invocations forever.
                let _guard = HAKONIWA_SPAWN_LOCK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                cmd.spawn()
            }
            .map_err(|e| ExecutionError::SandboxFailed {
                message: format!("Container execution failed: {}", e),
            })?;

            let output = child
                .wait_with_output()
                .map_err(|e| ExecutionError::SandboxFailed {
                    message: format!("Container output collection failed: {}", e),
                })?;
            stdout_f
                .write_all(&output.stdout)
                .map_err(|e| ExecutionError::SandboxFailed {
                    message: format!("Failed to write stdout: {}", e),
                })?;
            stderr_f
                .write_all(&output.stderr)
                .map_err(|e| ExecutionError::SandboxFailed {
                    message: format!("Failed to write stderr: {}", e),
                })?;
            stdout_f.flush()?;
            stderr_f.flush()?;

            if !output.status.success() {
                let exit_code = output.status.code;

                // Read the last few lines of stderr for immediate context
                let stderr_snippet = fs::read_to_string(self.build_workspace_dir.join("stderr"))
                    .unwrap_or_default()
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n");

                error!(
                    exit_code = exit_code,
                    temp_dir = self.build_workspace_dir.to_str().unwrap(),
                    stderr_snippet = %stderr_snippet,
                    "Build command failed"
                );

                return Err(ExecutionError::BuildFailed {
                    code: exit_code,
                    temp_dir: self.build_workspace_dir.clone(),
                    spongebob_url: None, // URL is now tracked at invocation level
                }
                .into());
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(config), fields(indicatif.pb_show))]
    fn prepare_rootfs(&self, config: &BuildConfig) -> Result<PathBuf> {
        let rootfs = self.build_workspace_dir.join("rootfs");
        fs::create_dir_all(&rootfs)?;

        for cache_path in &config.dependencies {
            hardlink_dir_contents(cache_path, &rootfs)?;
        }

        Ok(rootfs)
    }
}

fn hardlink_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    use common::HardlinkError;
    common::hardlink_dir_contents(src, dst).map_err(|e| match e {
        HardlinkError::IO(op, path, e) => ExecutionError::FileOperation {
            operation: op.to_string(),
            path: path.display().to_string(),
            source: e,
        }
        .into(),
        HardlinkError::HardlinkFailed(src, dst, e) => ExecutionError::HardLinkFailed {
            source: src.display().to_string(),
            destination: dst.display().to_string(),
            error: e,
        }
        .into(),
    })
}

/// Helper function to get current timestamp in milliseconds
fn current_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before UNIX epoch")
        .as_millis() as i64
}
