use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::info;

use crate::config::BuildConfig;
use crate::error::{ExecutionError, Result};
use crate::sandbox;

pub struct BuildExecutor {
    pub temp_dir_path: PathBuf,
    pub output_staging_path: PathBuf,
}

impl BuildExecutor {
    pub fn new() -> Result<Self> {
        let temp_dir_path =
            std::env::temp_dir().join(format!("build-sandbox-{}", std::process::id()));
        fs::create_dir_all(&temp_dir_path).map_err(|_| ExecutionError::TempDirCreation)?;

        let output_staging_path = temp_dir_path.join("output");
        fs::create_dir_all(&output_staging_path).map_err(|_| ExecutionError::TempDirCreation)?;

        info!("Created build environment at {}", temp_dir_path.display());

        Ok(BuildExecutor {
            temp_dir_path,
            output_staging_path,
        })
    }

    pub fn execute(&self, config: &BuildConfig, verbose: bool) -> Result<BuildResult> {
        info!(
            "Copying {} inputs to build environment",
            config.inputs.len()
        );
        for input in &config.inputs {
            info!("  Copying input: {}", input.display());
            self.copy_to_tmpdir(input)?;
        }

        let toolchain_script = Path::new("scripts/toolchain-setup.sh");
        if toolchain_script.exists() {
            info!(
                "  Copying toolchain setup script: {}",
                toolchain_script.display()
            );
            self.copy_to_tmpdir(toolchain_script)?;
        }

        if config.debug_shell {
            self.create_debug_helper()?;
        }

        let mut sandbox = sandbox::create_sandbox(config)?;

        let mut cmd = if config.debug_shell {
            info!("Launching debug shell in sandbox environment");
            info!("  TMPDIR: {}", self.temp_dir_path.display());
            info!("  OUTPUT_DIR: {}", self.output_staging_path.display());
            info!("  Type 'exit' to leave the debug shell");

            let mut c = Command::new("/usr/bin/bash");
            sandbox.execute(&mut c)?;
            c.arg("-i");
            c
        } else if cfg!(target_os = "linux") {
            let mut c = Command::new(&config.build_script.executable);
            sandbox.execute(&mut c)?;
            c
        } else {
            Command::new(&config.build_script.executable)
        };

        if !config.debug_shell {
            for arg in &config.build_script.args {
                cmd.arg(arg);
            }
        }

        cmd.current_dir(&self.temp_dir_path);
        cmd.env("TMPDIR", &self.temp_dir_path);
        cmd.env("OUTPUT_DIR", &self.output_staging_path);

        let path_components = [
            // Cross-compilation toolchain (gcc, etc.) - highest priority
            PathBuf::from("/opt/toolchain/bin"),
            // Build dependencies and host system utilities
            PathBuf::from("/usr/bin"),
        ];

        if !path_components.is_empty() {
            let path_string = path_components
                .iter()
                .map(|p| p.to_string_lossy())
                .collect::<Vec<_>>()
                .join(":");
            cmd.env("PATH", &path_string);
            info!("Set PATH to {}", path_string);
        }

        let output = if config.debug_shell {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            info!("Starting interactive debug shell...");

            let status = cmd.status().map_err(|e| ExecutionError::ProcessSpawn {
                context: format!("Failed to start debug shell: {}", e),
            })?;

            std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        } else {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

            info!(
                "Executing: {} {}",
                config.build_script.executable.display(),
                config.build_script.args.join(" ")
            );

            let status = cmd.status().map_err(|e| ExecutionError::ProcessSpawn {
                context: format!(
                    "Failed to execute build script '{}': {}",
                    config.build_script.executable.display(),
                    e
                ),
            })?;

            std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        };

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if verbose || cfg!(target_os = "linux") {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if !stdout.is_empty() {
                eprintln!("=== Build Output (stdout) ===\n{}", stdout);
            }
            if !stderr.is_empty() {
                eprintln!("=== Build Output (stderr) ===\n{}", stderr);
            }
        }

        let success = output.status.success();
        let exit_code = output.status.code().unwrap_or(-1);

        if !success {
            if stderr.contains("sandbox") || stderr.contains("namespace") {
                return Err(ExecutionError::SandboxFailed { message: stderr }.into());
            } else {
                return Err(ExecutionError::BuildFailed { code: exit_code }.into());
            }
        }

        sandbox.cleanup()?;

        Ok(BuildResult { exit_code })
    }

    pub fn temp_output_dir(&self) -> &Path {
        &self.temp_dir_path
    }

    pub fn output_staging_dir(&self) -> &Path {
        &self.output_staging_path
    }

    fn copy_to_tmpdir(&self, input: &Path) -> Result<()> {
        if input.is_file() {
            let file_name = input
                .file_name()
                .ok_or_else(|| ExecutionError::FileOperation {
                    operation: "get file name".to_string(),
                    path: input.display().to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Path has no file name",
                    ),
                })?;
            let dest = self.temp_dir_path.join(file_name);
            fs::copy(input, &dest).map_err(|e| ExecutionError::CopyFailed {
                source: input.display().to_string(),
                destination: dest.display().to_string(),
                error: e,
            })?;
        } else if input.is_dir() {
            Self::copy_dir_contents(input, &self.temp_dir_path)?;
        }

        Ok(())
    }

    fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
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
            let file_name = path
                .file_name()
                .ok_or_else(|| ExecutionError::FileOperation {
                    operation: "get file name".to_string(),
                    path: path.display().to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Path has no file name",
                    ),
                })?;
            let dest_path = dst.join(file_name);

            if path.is_dir() {
                fs::create_dir_all(&dest_path).map_err(|e| ExecutionError::FileOperation {
                    operation: "create directory".to_string(),
                    path: dest_path.display().to_string(),
                    source: e,
                })?;
                Self::copy_dir_contents(&path, &dest_path)?;
            } else {
                fs::copy(&path, &dest_path).map_err(|e| ExecutionError::CopyFailed {
                    source: path.display().to_string(),
                    destination: dest_path.display().to_string(),
                    error: e,
                })?;
            }
        }
        Ok(())
    }

    fn create_debug_helper(&self) -> Result<()> {
        let helper_script = r#"#!/usr/bin/bash
echo "==================================================================="
echo "Build Sandbox Debug Shell"
echo "==================================================================="
echo ""
echo "Environment Variables:"
echo "  TMPDIR=$TMPDIR"
echo "  OUTPUT_DIR=$OUTPUT_DIR"
echo ""
echo "Useful commands:"
echo "  ls -la          # List files in current directory"
echo "  find . -type f  # Find all files"
echo "  find . -name '*.h' # Find header files"
echo "  env | sort      # Show all environment variables"
echo "  mount           # Show mount points (if in sandbox)"
echo "  pwd             # Show current directory"
echo ""
echo "Directories of interest:"
echo "  /tmp            # Temporary directory"
echo "  include/        # Header files from dependencies"
echo "  lib/            # Libraries from dependencies"
echo ""
echo "Type 'exit' to leave the debug shell"
echo "==================================================================="
echo ""
"#;

        let helper_path = self.temp_dir_path.join("debug-helper.sh");
        fs::write(&helper_path, helper_script).map_err(|e| ExecutionError::FileOperation {
            operation: "write debug helper script".to_string(),
            path: helper_path.display().to_string(),
            source: e,
        })?;

        let bashrc = format!("source {}/debug-helper.sh\n", self.temp_dir_path.display());
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
