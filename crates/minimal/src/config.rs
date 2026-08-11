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
/// Delegates to the `minimal-client` resolution the attach path
/// uses, so the two can never drift.
pub fn resolve_minimal_config_dir(global: &GlobalArgs) -> PathBuf {
    minimal_client::attach::minimal_config_dir(global.config_dir.as_deref())
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

/// Read the user policy from `<config>/minimal/user_policy.toml`.
/// A missing file returns [`UserPolicy::empty`] — a fresh install
/// activates fine without needing the file to exist.
///
/// [`UserPolicy::empty`]: sessions::core::policy::UserPolicy::empty
pub fn read_user_policy(
    global: &GlobalArgs,
) -> Result<sessions::core::policy::UserPolicy, anyhow::Error> {
    sessions::core::policy::read_user_policy_or_default(&user_policy_path(global))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Absolute path to `user_policy.toml` under the resolved config
/// dir. Exposed separately so callers that need to save (not just
/// read) — e.g. after an interactive prompt appends a rule — can
/// reuse the same resolution.
pub fn user_policy_path(global: &GlobalArgs) -> PathBuf {
    resolve_minimal_config_dir(global).join("user_policy.toml")
}
