use hakoniwa::Container;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

use crate::config::BuildConfig;
use crate::error::{ExecutionError, Result};

#[derive(Debug)]
pub struct BuildExecutor {
    build_workspace_dir: PathBuf,
}

impl BuildExecutor {
    /// Create a new build executor with a unique sandbox workspace
    ///
    /// # Parameters
    /// * `sandbox_base_dir` - Base directory where temporary build sandboxes are created
    /// * `package_name` - Name of the package being built (used in directory naming for debugging)
    #[tracing::instrument]
    pub fn new(sandbox_base_dir: PathBuf, package_name: String) -> Result<Self> {
        // Create a unique directory name using timestamp and process ID
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ExecutionError::FileOperation {
                operation: "get timestamp".to_string(),
                path: String::new(),
                source: std::io::Error::other(e),
            })?
            .as_secs();
        let pid = std::process::id();

        // Include package name if provided for better debugging
        let dir_name = format!("{}-{}-{}", package_name, timestamp, pid);

        let build_workspace_dir = sandbox_base_dir.join(dir_name);

        // Create the build directory
        fs::create_dir_all(&build_workspace_dir).map_err(|e| ExecutionError::FileOperation {
            operation: "create build directory".to_string(),
            path: build_workspace_dir.display().to_string(),
            source: e,
        })?;

        let executor = BuildExecutor {
            build_workspace_dir,
        };

        fs::create_dir_all(executor.output_staging_dir())
            .map_err(|_| ExecutionError::TempDirCreation)?;
        Ok(executor)
    }

    #[tracing::instrument(skip(config, spongebob_client), fields(indicatif.pb_hide, package = %config.name))]
    pub async fn execute(
        &self,
        config: &BuildConfig,
        spongebob_client: &mut spongebob::SpongeBob,
    ) -> Result<(i32, Option<String>)> {
        info!(
            "Linking {} inputs to build environment",
            config.inputs.len()
        );
        for input in &config.inputs {
            info!("  Linking input: {}", input.display());
            self.hardlink_to_tmpdir(input)?;
        }

        let spongebob_url = self.execute_in_container(config, spongebob_client).await?;

        Ok((0, spongebob_url))
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
            hardlink_dir_contents(input, &dest_path)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(config, spongebob_client), fields(indicatif.pb_show))]
    async fn execute_in_container(
        &self,
        config: &BuildConfig,
        spongebob_client: &mut spongebob::SpongeBob,
    ) -> Result<Option<String>> {
        let rootfs = self.prepare_rootfs(config)?;
        let sandbox_mount_point = "/build";
        let program = &config.build_script.executable.to_string_lossy();
        let mut cmd = Container::new()
            .rootfs(&rootfs)
            .map_err(|e| ExecutionError::SandboxFailed {
                message: format!("Failed to set rootfs: {}", e),
            })?
            .devfsmount("/dev")
            .bindmount_rw(
                self.build_workspace_dir.to_str().unwrap(),
                sandbox_mount_point,
            )
            .bindmount_rw(
                self.output_staging_dir().to_str().unwrap(),
                format!("{}/output", sandbox_mount_point).as_str(),
            )
            .symlink("/usr/bin", "/bin")
            .symlink("/usr/lib", "/lib64")
            .command(program);

        for arg in &config.build_script.args {
            cmd.arg(arg);
        }

        cmd.env("HOME", sandbox_mount_point)
            .env("PWD", sandbox_mount_point)
            .env("TMPDIR", sandbox_mount_point)
            .env("OUTPUT_DIR", &format!("{}/output", sandbox_mount_point))
            .env("LANG", "en_US.utf8")
            .env("LC_ALL", "en_US.utf8")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        if let Some(build_args) = &config.build_script.build_args {
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

        info!(
            "Executing: {} {}",
            config.build_script.executable.display(),
            config.build_script.args.join(" ")
        );

        cmd.current_dir(sandbox_mount_point);

        let output = cmd.output().map_err(|e| ExecutionError::SandboxFailed {
            message: format!("Container execution failed: {}", e),
        })?;

        fs::write(self.build_workspace_dir.join("stdout"), &output.stdout).map_err(|e| {
            ExecutionError::SandboxFailed {
                message: format!("Failed to write stdout: {}", e),
            }
        })?;
        fs::write(self.build_workspace_dir.join("stderr"), &output.stderr).map_err(|e| {
            ExecutionError::SandboxFailed {
                message: format!("Failed to write stderr: {}", e),
            }
        })?;

        let spongebob_url = self.upload_logs(config, &output.stdout, &output.stderr, spongebob_client)
            .await;

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
            }
            .into());
        }

        Ok(spongebob_url)
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

    async fn upload_logs(
        &self,
        config: &BuildConfig,
        stdout: &[u8],
        stderr: &[u8],
        client: &mut spongebob::SpongeBob,
    ) -> Option<String> {
        let result = client
            .upload_build_logs(&config.name, stdout.to_vec(), stderr.to_vec())
            .await;

        match result {
            Ok(spongebob_url) => {
                info!(
                    "Successfully uploaded build logs to SpongeBob for {}",
                    config.name
                );
                Some(spongebob_url)
            }
            Err(e) => {
                warn!(
                    "Failed to upload logs to SpongeBob for {}: {}",
                    config.name, e
                );
                None
            }
        }
    }
}

fn hardlink_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).map_err(|e| ExecutionError::FileOperation {
        operation: "read directory".to_string(),
        path: src.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| ExecutionError::FileOperation {
            operation: "read directory entry".to_string(),
            path: src.display().to_string(),
            source: e,
        })?;

        let path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        let metadata = entry
            .metadata()
            .map_err(|e| ExecutionError::FileOperation {
                operation: "get metadata".to_string(),
                path: path.display().to_string(),
                source: e,
            })?;

        if metadata.is_dir() {
            fs::create_dir_all(&dst_path).map_err(|e| ExecutionError::FileOperation {
                operation: "create directory".to_string(),
                path: dst_path.display().to_string(),
                source: e,
            })?;
            hardlink_dir_contents(&path, &dst_path)?;
        } else if metadata.is_file() {
            match fs::hard_link(&path, &dst_path) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        warn!(
                            "Not linking {} => {}, already exists",
                            path.display(),
                            dst_path.display()
                        );
                        Ok(())
                    } else {
                        Err(e)
                    }
                }
            }
            .map_err(|e| ExecutionError::HardLinkFailed {
                source: path.display().to_string(),
                destination: dst_path.display().to_string(),
                error: e,
            })?;
        } else if metadata.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| ExecutionError::FileOperation {
                operation: "read symlink".to_string(),
                path: path.display().to_string(),
                source: e,
            })?;
            symlink(&target, &dst_path).map_err(|e| ExecutionError::FileOperation {
                operation: "create symlink".to_string(),
                path: dst_path.display().to_string(),
                source: e,
            })?;
        }
    }

    Ok(())
}
