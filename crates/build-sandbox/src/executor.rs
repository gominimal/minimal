use hakoniwa::Container;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tracing::{error, info};

use crate::config::BuildConfig;
use crate::error::{ExecutionError, Result};

#[derive(Debug)]
pub struct BuildExecutor {
    path: PathBuf,
}

impl BuildExecutor {
    #[tracing::instrument]
    pub fn new() -> Result<Self> {
        let executor = BuildExecutor {
            path: tempdir()?.path().to_path_buf(),
        };
        fs::create_dir_all(executor.output_staging_dir())
            .map_err(|_| ExecutionError::TempDirCreation)?;
        Ok(executor)
    }

    #[tracing::instrument(skip(config))]
    pub fn execute(&self, config: &BuildConfig) -> Result<i32> {
        info!(
            "Linking {} inputs to build environment",
            config.inputs.len()
        );
        for input in &config.inputs {
            info!("  Linking input: {}", input.display());
            self.hardlink_to_tmpdir(input)?;
        }

        self.execute_in_container(config)?;

        Ok(0)
    }

    pub fn temp_output_dir(&self) -> &Path {
        &self.path
    }

    pub fn output_staging_dir(&self) -> PathBuf {
        self.path.join("output").to_path_buf()
    }

    fn hardlink_to_tmpdir(&self, input: &Path) -> Result<()> {
        let dest_path = if let Some(file_name) = input.file_name() {
            self.path.join(file_name)
        } else {
            return Ok(());
        };

        if input.is_file() {
            fs::hard_link(input, &dest_path).map_err(|e| ExecutionError::HardLinkFailed {
                source: input.display().to_string(),
                destination: dest_path.display().to_string(),
                error: e,
            })?;
        } else if input.is_dir() {
            hardlink_dir_contents(input, &dest_path)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(config))]
    fn execute_in_container(&self, config: &BuildConfig) -> Result<()> {
        let rootfs = self.prepare_rootfs(config)?;
        let program = &config.build_script.executable.to_string_lossy();
        let mut cmd = Container::new()
            .rootfs(&rootfs)
            .map_err(|e| ExecutionError::SandboxFailed {
                message: format!("Failed to set rootfs: {}", e),
            })?
            .devfsmount("/dev")
            .bindmount_rw(self.path.to_str().unwrap(), "/tmp")
            .bindmount_rw(self.output_staging_dir().to_str().unwrap(), "/tmp/output")
            .symlink("/usr/bin", "/bin")
            .symlink("/usr/lib", "/lib64")
            .command(program);

        for arg in &config.build_script.args {
            cmd.arg(arg);
        }

        cmd.env("HOME", "/tmp")
            .env("PWD", "/tmp")
            .env("TMPDIR", "/tmp")
            .env("OUTPUT_DIR", "/tmp/output")
            .env("LANG", "en_US.utf8")
            .env("LC_ALL", "en_US.utf8")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

        info!(
            "Executing: {} {}",
            config.build_script.executable.display(),
            config.build_script.args.join(" ")
        );

        cmd.current_dir("/tmp");

        let output = cmd.output().map_err(|e| ExecutionError::SandboxFailed {
            message: format!("Container execution failed: {}", e),
        })?;

        fs::write(self.path.join("stdout"), &output.stdout).map_err(|e| {
            ExecutionError::SandboxFailed {
                message: format!("Failed to write stdout: {}", e),
            }
        })?;
        fs::write(self.path.join("stderr"), &output.stderr).map_err(|e| {
            ExecutionError::SandboxFailed {
                message: format!("Failed to write stderr: {}", e),
            }
        })?;

        if !output.status.success() {
            let exit_code = output.status.code;

            // Read the last few lines of stderr for immediate context
            let stderr_snippet = fs::read_to_string(self.path.join("stderr"))
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
                temp_dir = self.path.to_str().unwrap(),
                stderr_snippet = %stderr_snippet,
                "Build command failed"
            );

            return Err(ExecutionError::BuildFailed {
                code: exit_code,
                temp_dir: self.path.clone(),
            }
            .into());
        }

        Ok(())
    }

    #[tracing::instrument(skip(config))]
    fn prepare_rootfs(&self, config: &BuildConfig) -> Result<PathBuf> {
        let rootfs = self.path.join("rootfs");
        fs::create_dir_all(&rootfs)?;

        for cache_path in &config.dependencies {
            hardlink_dir_contents(cache_path, &rootfs)?;
        }

        Ok(rootfs)
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
            fs::hard_link(&path, &dst_path).map_err(|e| ExecutionError::HardLinkFailed {
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
