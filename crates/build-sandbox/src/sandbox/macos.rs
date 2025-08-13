use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;
use tracing::{debug, trace};

use super::Sandbox;
use crate::config::BuildConfig;
use crate::error::{Result, SandboxError};

pub struct MacOSSandbox {
    policy_file: NamedTempFile,
}

impl Sandbox for MacOSSandbox {
    fn create_instance(config: &BuildConfig) -> Result<Box<dyn Sandbox>> {
        let mut policy_file = NamedTempFile::new().map_err(|_| SandboxError::PolicyCreation)?;

        let policy_content = generate_policy_content(config)?;

        trace!("Generated Seatbelt policy:\n{}", policy_content);

        policy_file
            .write_all(policy_content.as_bytes())
            .map_err(|_| SandboxError::PolicyCreation)?;

        Ok(Box::new(MacOSSandbox { policy_file }))
    }

    fn execute(&self, command: &mut Command) -> Result<()> {
        command.arg("-f").arg(self.policy_file.path());
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

fn generate_policy_content(config: &BuildConfig) -> Result<String> {
    let default_policy = include_str!("../../profiles/default.sb");
    let mut policy = String::from(default_policy);

    let mut build_additions = Vec::new();

    for dep_path in &config.dependencies {
        let path_type = determine_path_type(dep_path)?;

        match path_type {
            PathType::File => {
                build_additions.push(format!(
                    "(allow file-read* file-map-executable file-test-existence process-exec (path \"{}\"))",
                    dep_path.display()
                ));
            }
            PathType::Directory => {
                build_additions.push(format!(
                    "(allow file-read* file-map-executable file-test-existence process-exec (subpath \"{}\"))",
                    dep_path.display()
                ));
            }
        }
    }

    policy.push_str("\n; Build-specific additions\n");
    build_additions.sort();
    for addition in build_additions {
        policy.push_str(&addition);
        policy.push('\n');
    }

    Ok(policy)
}

#[derive(Debug)]
enum PathType {
    File,
    Directory,
}

fn determine_path_type(path: &Path) -> Result<PathType> {
    let metadata = fs::metadata(path).map_err(|_| SandboxError::PathTypeDetection {
        path: path.to_path_buf(),
    })?;

    if metadata.is_file() {
        Ok(PathType::File)
    } else if metadata.is_dir() {
        Ok(PathType::Directory)
    } else {
        Err(SandboxError::PathTypeDetection {
            path: path.to_path_buf(),
        }
        .into())
    }
}
