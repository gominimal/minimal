//! `Config` — minvmd daemon configuration.
//!
//! Reads `~/.minimal/vm/minvmd.toml`; falls back to defaults when the file is
//! absent. Unknown keys are silently ignored (forward-compatible).

use std::path::Path;

use serde::Deserialize;

// TODO(unit-2): wire into lifecycle::up. `Config` is consumed by
// image::ensure_image in Sub-task 2.1 and lifecycle in Sub-task 3.1. Until
// those land, only tests construct it, so the bin target flags dead code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub cpus: u32,
    pub memory_mib: u64,
    pub state_size_gib: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mib: 2048,
            state_size_gib: 10,
        }
    }
}

#[allow(dead_code)]
impl Config {
    /// Load config from `path`. If the file does not exist, returns defaults.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(toml::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Load from the canonical path `$MINIMAL_HOME/vm/minvmd.toml`.
    /// `$MINIMAL_HOME` defaults to `~/.minimal` when unset.
    pub fn load_default() -> anyhow::Result<Self> {
        let home = std::env::var_os("MINIMAL_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".minimal")))
            .ok_or_else(|| anyhow::anyhow!("cannot determine MINIMAL_HOME"))?;
        Self::load(&home.join("vm").join("minvmd.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{serial_test::serial, with_isolated_home};

    #[test]
    #[serial]
    fn default_config_when_no_file() {
        with_isolated_home(|_home| {
            let cfg = Config::load_default().expect("load");
            assert_eq!(cfg.cpus, 2);
            assert_eq!(cfg.memory_mib, 2048);
            assert_eq!(cfg.state_size_gib, 10);
        });
    }

    #[test]
    #[serial]
    fn load_default_resolves_minimal_home_and_reads_file() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            std::fs::create_dir_all(&vm_dir).unwrap();
            std::fs::write(
                vm_dir.join("minvmd.toml"),
                "cpus = 8\nmemory_mib = 16384\nstate_size_gib = 40\n",
            )
            .unwrap();

            let cfg = Config::load_default().expect("load_default");
            assert_eq!(cfg.cpus, 8);
            assert_eq!(cfg.memory_mib, 16384);
            assert_eq!(cfg.state_size_gib, 40);
        });
    }

    #[test]
    #[serial]
    fn overrides_from_toml_file() {
        with_isolated_home(|home| {
            let vm_dir = home.join("vm");
            std::fs::create_dir_all(&vm_dir).unwrap();
            let toml_path = vm_dir.join("minvmd.toml");
            std::fs::write(
                &toml_path,
                "cpus = 4\nmemory_mib = 8192\nstate_size_gib = 20\n",
            )
            .unwrap();

            let cfg = Config::load(&toml_path).expect("load");
            assert_eq!(cfg.cpus, 4);
            assert_eq!(cfg.memory_mib, 8192);
            assert_eq!(cfg.state_size_gib, 20);
        });
    }
}
