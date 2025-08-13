use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{ConfigError, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildConfig {
    pub dependencies: Vec<PathBuf>,
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
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound {
            path: path.to_path_buf(),
        })?;

        let config: BuildConfig = serde_json::from_str(&content).map_err(ConfigError::JsonParse)?;
        config.validate()?;
        Ok(config)
    }

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
