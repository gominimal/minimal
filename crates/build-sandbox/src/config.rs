use nickel_lang_core::term::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::error::{ConfigError, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Input {
    File(PathBuf),
    Dir(PathBuf),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildConfig {
    pub name: String,
    pub dependencies: HashSet<PathBuf>,
    pub inputs: Vec<Input>,
    pub build_script: BuildScript,
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildScript {
    pub executable: PathBuf,
    pub args: Vec<String>,

    pub build_args: Option<IndexMap<String, String>>,
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
            match input {
                Input::File(p) | Input::Dir(p) => {
                    if !p.exists() {
                        return Err(ConfigError::InvalidInput { path: p.clone() }.into());
                    }
                }
            }
        }

        Ok(())
    }
}
