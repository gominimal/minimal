use fs_extra::dir::{self as fs_dir};
use hakoniwa::Container;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

use crate::config::BuildConfig;
use crate::error::{ExecutionError, Result};

static BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct BuildExecutor {
    pub temp_dir_path: PathBuf,
    pub output_staging_path: PathBuf,
}

impl BuildExecutor {
    pub fn new() -> Result<Self> {
        let build_id = BUILD_COUNTER.fetch_add(1, Ordering::SeqCst);
        let unique_id = format!("{}-{}", std::process::id(), build_id);
        let temp_dir_path = std::env::temp_dir().join(format!("build-sandbox-{}", unique_id));
        fs::create_dir_all(&temp_dir_path).map_err(|_| ExecutionError::TempDirCreation)?;

        let output_staging_path = temp_dir_path.join("output");
        fs::create_dir_all(&output_staging_path).map_err(|_| ExecutionError::TempDirCreation)?;

        info!("Created build environment at {}", temp_dir_path.display());

        Ok(BuildExecutor {
            temp_dir_path,
            output_staging_path,
        })
    }

    pub fn execute(&self, config: &BuildConfig, _verbose: bool) -> Result<BuildResult> {
        info!(
            "Copying {} inputs to build environment",
            config.inputs.len()
        );
        for input in &config.inputs {
            info!("  Copying input: {}", input.display());
            self.copy_to_tmpdir(input)?;
        }

        if config.debug_shell {
            self.create_debug_helper()?;
        }

        self.execute_in_container(config)?;

        Ok(BuildResult { exit_code: 0 })
    }

    pub fn temp_output_dir(&self) -> &Path {
        &self.temp_dir_path
    }

    pub fn output_staging_dir(&self) -> &Path {
        &self.output_staging_path
    }

    fn copy_to_tmpdir(&self, input: &Path) -> Result<()> {
        let dest_path = if let Some(file_name) = input.file_name() {
            self.temp_dir_path.join(file_name)
        } else {
            return Ok(());
        };

        if input.is_file() {
            fs::copy(input, &dest_path).map_err(|e| ExecutionError::CopyFailed {
                source: input.display().to_string(),
                destination: dest_path.display().to_string(),
                error: e,
            })?;
        } else if input.is_dir() {
            let mut options = fs_dir::CopyOptions::new();
            options.overwrite = true;
            options.copy_inside = true;

            fs_dir::copy(input, &dest_path, &options).map_err(|e| {
                ExecutionError::FileOperation {
                    operation: "copy directory".to_string(),
                    path: input.display().to_string(),
                    source: std::io::Error::other(e.to_string()),
                }
            })?;
        }

        Ok(())
    }

    fn execute_in_container(&self, config: &BuildConfig) -> Result<()> {
        info!("Executing command in container...");

        let rootfs = self.prepare_rootfs(config)?;

        let program = if config.debug_shell {
            "/bin/bash"
        } else {
            &config.build_script.executable.to_string_lossy()
        };

        info!("Using program: {}", program);

        let temp_dir_str = self.temp_dir_path.to_string_lossy().into_owned();
        let output_dir_str = self.output_staging_path.to_string_lossy().into_owned();

        let mut cmd = Container::new()
            .rootfs(&rootfs)
            .map_err(|e| ExecutionError::SandboxFailed {
                message: format!("Failed to set rootfs: {}", e),
            })?
            .devfsmount("/dev")
            .bindmount_rw(&temp_dir_str, "/tmp")
            .bindmount_rw(&output_dir_str, "/tmp/output")
            .command(program);

        if !config.debug_shell {
            for arg in &config.build_script.args {
                cmd.arg(arg);
            }
        }

        cmd.env("HOME", "/tmp")
            .env("PWD", "/tmp")
            .env("TMPDIR", "/tmp")
            .env("OUTPUT_DIR", "/tmp/output")
            .env("LANG", "en_US.utf8")
            .env("LC_ALL", "en_US.utf8")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

        if config.debug_shell {
            cmd.env("SHELL", "/bin/bash").env("TERM", "xterm");
            if let Ok(user) = std::env::var("USER") {
                cmd.env("USER", &user);
            }
            info!("Starting interactive debug shell...");
        } else {
            info!(
                "Executing: {} {}",
                config.build_script.executable.display(),
                config.build_script.args.join(" ")
            );
        }

        cmd.current_dir("/tmp");

        let mut child = cmd.spawn().map_err(|e| ExecutionError::SandboxFailed {
            message: format!("Container execution failed: {}", e),
        })?;

        let status = child.wait().map_err(|e| ExecutionError::SandboxFailed {
            message: format!("Failed to wait for container process: {}", e),
        })?;

        if !status.success() {
            let exit_code = status.code;
            return Err(ExecutionError::BuildFailed { code: exit_code }.into());
        }

        Ok(())
    }

    fn prepare_rootfs(&self, config: &BuildConfig) -> Result<PathBuf> {
        let rootfs = self.temp_dir_path.join("rootfs");
        fs::create_dir_all(&rootfs)?;

        for (cache_path, mount_point) in &config.dependencies {
            if mount_point == Path::new("/") {
                self.copy_dir_contents(cache_path, &rootfs)?;
            } else {
                let dest = rootfs.join(mount_point.strip_prefix("/").unwrap_or(mount_point));
                fs::create_dir_all(&dest)?;
                self.copy_dir_contents(cache_path, &dest)?;
            }
        }

        Ok(rootfs)
    }

    fn copy_dir_contents(&self, src: &Path, dst: &Path) -> Result<()> {
        let mut options = fs_dir::CopyOptions::new();
        options.overwrite = true;
        options.copy_inside = true;
        options.content_only = true;

        fs_dir::copy(src, dst, &options).map_err(|e| ExecutionError::FileOperation {
            operation: "copy directory contents".to_string(),
            path: src.display().to_string(),
            source: std::io::Error::other(e.to_string()),
        })?;

        Ok(())
    }

    fn create_debug_helper(&self) -> Result<()> {
        let bashrc = r#"echo "=== Build Sandbox Debug Shell ==="
echo "TMPDIR=$TMPDIR"
echo "OUTPUT_DIR=$OUTPUT_DIR" 
echo "Type 'exit' to leave"
echo "=================================="
"#;
        let bashrc_path = self.temp_dir_path.join(".bashrc");
        fs::write(&bashrc_path, bashrc).map_err(|e| ExecutionError::FileOperation {
            operation: "write .bashrc".to_string(),
            path: bashrc_path.display().to_string(),
            source: e,
        })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct BuildResult {
    pub exit_code: i32,
}
