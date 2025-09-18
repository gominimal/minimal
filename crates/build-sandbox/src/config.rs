use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::error::{ConfigError, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildConfig {
    pub name: String,
    pub dependencies: HashSet<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub build_script: BuildScript,
    pub outputs: Vec<String>,
    #[serde(default)]
    pub debug_shell: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildScript {
    pub executable: PathBuf,
    pub args: Vec<String>,
}

impl BuildConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.build_script.executable.exists() {
            return Err(ConfigError::InvalidExecutable {
                path: self.build_script.executable.clone(),
            }
            .into());
        }

        for dep in &self.dependencies {
            if !dep.exists() {
                return Err(ConfigError::InvalidDependency { path: dep.clone() }.into());
            }
        }

        for input in &self.inputs {
            if !input.exists() {
                return Err(ConfigError::InvalidInput {
                    path: input.clone(),
                }
                .into());
            }
        }

        Ok(())
    }
}
