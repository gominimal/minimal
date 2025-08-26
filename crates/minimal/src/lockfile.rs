use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PrebuiltsLock {
    pub prebuilts: HashMap<String, String>, // package_name -> hash
}

impl PrebuiltsLock {
    /// Load lockfile from disk, or create empty one if it doesn't exist
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&contents)?)
        } else {
            Ok(Self {
                prebuilts: HashMap::new(),
            })
        }
    }

    /// Save lockfile to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Get the locked hash for a package, if it exists
    pub fn get_hash(&self, package: &str) -> Option<&str> {
        self.prebuilts.get(package).map(|s| s.as_str())
    }

    /// Update the locked hash for a package
    pub fn update_hash(&mut self, package: String, hash: String) {
        self.prebuilts.insert(package, hash);
    }

    /// Check if a package has a locked hash
    #[allow(dead_code)]
    pub fn has_package(&self, package: &str) -> bool {
        self.prebuilts.contains_key(package)
    }
}
