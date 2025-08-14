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

        // If debug shell mode, write a helper script
        if config.debug_shell {
            self.create_debug_helper()?;
        }

        let mut sandbox = sandbox::create_sandbox(config)?;

        let mut cmd = if config.debug_shell {
            // Debug mode: launch interactive bash shell
            info!("Launching debug shell in sandbox environment");
            info!("  TMPDIR: {}", self.temp_dir_path.display());
            info!("  OUTPUT_DIR: {}", self.output_staging_path.display());
            info!("  Type 'exit' to leave the debug shell");

            if cfg!(target_os = "linux") {
                let mut c = Command::new("/usr/bin/bash");
                sandbox.execute(&mut c)?;
                c.arg("-i"); // Interactive shell
                c
            } else {
                let mut c = Command::new("/usr/bin/bash");
                c.arg("-i");
                c
            }
        } else if cfg!(target_os = "macos") {
            let mut c = Command::new("sandbox-exec");
            sandbox.execute(&mut c)?;
            c.arg(format!(
                "-D_TMPDIR=/private{}",
                self.temp_dir_path.display()
            ))
            .arg(&config.build_script.executable);
            c
        } else if cfg!(target_os = "linux") {
            // For Linux, create the command and let the sandbox set up mount namespaces via pre_exec
            let mut c = Command::new(&config.build_script.executable);
            sandbox.execute(&mut c)?; // This sets up the pre_exec hook for mount namespace setup
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

        // Build PATH from dependencies, prioritizing toolchain and build outputs
        let mut path_components = Vec::new();

        for dep in &config.dependencies {
            let dep_str = dep.to_string_lossy();
            if dep_str.contains("toolchains/x86_64-buildroot-linux-gnu") {
                cmd.env("TOOLCHAIN_DIR", dep);
                info!("Set TOOLCHAIN_DIR to {}", dep.display());
                // Add toolchain bin directory to PATH (mounted at /opt/toolchain/bin in sandbox)
                path_components.push(std::path::PathBuf::from("/opt/toolchain/bin"));
            } else if dep_str.ends_with("/scripts") {
                cmd.env("SCRIPTS_DIR", dep);
                info!("Set SCRIPTS_DIR to {}", dep.display());
            }
        }

        // Add minimal output bin directory to PATH (mounted at /opt/minimal/bin in sandbox)
        for dep in &config.dependencies {
            let dep_str = dep.to_string_lossy();
            if dep_str.ends_with("minimal-out") {
                path_components.push(std::path::PathBuf::from("/opt/minimal/bin"));
                break;
            }
        }

        // Include system PATH as fallback
        if let Ok(system_path) = std::env::var("PATH") {
            for component in system_path.split(':') {
                if !component.is_empty() {
                    path_components.push(std::path::PathBuf::from(component));
                }
            }
        }

        // Set the combined PATH
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
            // For interactive shell, inherit stdio
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            info!("Starting interactive debug shell...");

            let status = cmd.status().map_err(|_| ExecutionError::ProcessSpawn)?;

            // Create a fake output for compatibility
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

            let status = cmd.status().map_err(|_| ExecutionError::ProcessSpawn)?;

            // Create a fake output for compatibility since we inherited stdio
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
            let file_name = input.file_name().ok_or(ExecutionError::ProcessSpawn)?;
            let dest = self.temp_dir_path.join(file_name);
            fs::copy(input, &dest).map_err(|_| ExecutionError::ProcessSpawn)?;
        } else if input.is_dir() {
            Self::copy_dir_contents(input, &self.temp_dir_path)?;
        }

        Ok(())
    }

    fn copy_dir_contents(src: &Path, dst: &Path) -> Result<()> {
        for entry in fs::read_dir(src).map_err(|_| ExecutionError::ProcessSpawn)? {
            let entry = entry.map_err(|_| ExecutionError::ProcessSpawn)?;
            let path = entry.path();
            let file_name = path.file_name().ok_or(ExecutionError::ProcessSpawn)?;
            let dest_path = dst.join(file_name);

            if path.is_dir() {
                fs::create_dir_all(&dest_path).map_err(|_| ExecutionError::ProcessSpawn)?;
                Self::copy_dir_contents(&path, &dest_path)?;
            } else {
                fs::copy(&path, &dest_path).map_err(|_| ExecutionError::ProcessSpawn)?;
            }
        }
        Ok(())
    }

    fn create_debug_helper(&self) -> Result<()> {
        let helper_script = r#"#!/bin/bash
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
        fs::write(&helper_path, helper_script).map_err(|_| ExecutionError::ProcessSpawn)?;

        // Also create a .bashrc to run the helper on shell start
        let bashrc = format!("source {}/debug-helper.sh\n", self.temp_dir_path.display());
        let bashrc_path = self.temp_dir_path.join(".bashrc");
        fs::write(&bashrc_path, bashrc).map_err(|_| ExecutionError::ProcessSpawn)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct BuildResult {
    pub exit_code: i32,
}
