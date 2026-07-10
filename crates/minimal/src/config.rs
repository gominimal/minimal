//! Client-side config-dir resolution and `config.toml` loading.
//!
//! Both the loadouts and dirs subsystems route through this module so
//! `--config-dir`, `paths::minimal_config_dir()`, and the on-disk
//! `config.toml` layout are all resolved in one place.

use std::path::PathBuf;

use crate::GlobalArgs;

/// Resolve `<config>/minimal` on the platform's user config dir,
/// or the `--config-dir` override if the caller passed one. The
/// base for both the loadouts subdir and the client config file.
pub fn resolve_minimal_config_dir(global: &GlobalArgs) -> PathBuf {
    if let Some(dir) = &global.config_dir {
        return dir.join("minimal");
    }
    paths::minimal_config_dir()
        .as_utf8_path()
        .as_std_path()
        .to_path_buf()
}

/// Read the client config once, so both loadout resolution and
/// compose-option handling see the same values without hitting the
/// disk twice.
pub fn read_client_config(
    global: &GlobalArgs,
) -> Result<sessions::client::config::Config, anyhow::Error> {
    let cfg_path = resolve_minimal_config_dir(global).join("config.toml");
    sessions::client::config::read_config_or_default(&cfg_path).map_err(|e| anyhow::anyhow!("{e}"))
}
