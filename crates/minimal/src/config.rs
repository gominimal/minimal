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
/// Delegates to `paths::minimal_config_dir_with_override`, which the
/// attach path also uses, so every reader sees the same layout.
pub fn resolve_minimal_config_dir(global: &GlobalArgs) -> PathBuf {
    paths::minimal_config_dir_with_override(global.config_dir.as_deref())
}

/// Read the client config once, so both loadout resolution and
/// compose-option handling see the same values without hitting the
/// disk twice.
pub fn read_client_config(
    global: &GlobalArgs,
) -> Result<boxes::client::config::Config, anyhow::Error> {
    let cfg_path = resolve_minimal_config_dir(global).join("config.toml");
    boxes::client::config::read_config_or_default(&cfg_path).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Read the user policy from `<config>/minimal/user_policy.toml`.
/// A missing file returns [`UserPolicy::empty`] — a fresh install
/// activates fine without needing the file to exist.
///
/// [`UserPolicy::empty`]: boxes::core::policy::UserPolicy::empty
pub fn read_user_policy(
    global: &GlobalArgs,
) -> Result<boxes::core::policy::UserPolicy, anyhow::Error> {
    boxes::core::policy::read_user_policy_or_default(&user_policy_path(global))
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Absolute path to `user_policy.toml` under the resolved config
/// dir. Exposed separately so callers that need to save (not just
/// read) — e.g. after an interactive prompt appends a rule — can
/// reuse the same resolution.
pub fn user_policy_path(global: &GlobalArgs) -> PathBuf {
    resolve_minimal_config_dir(global).join("user_policy.toml")
}

/// The organization-level client configuration. An administrator writes it,
/// and it applies to every user of this machine.
pub const ORGANIZATION_CONFIG_PATH: &str = "/etc/minimal/config.toml";

/// Whether the user or the organization client configuration sets
/// `[secrets] acknowledge_full_breadth_unenrolled = true` (BEP-057).
/// A missing file sets nothing. A project file is never read here.
///
/// # Errors
///
/// A file that exists but is not read or does not parse, naming its path.
pub fn full_breadth_acknowledged(global: &GlobalArgs) -> Result<bool, anyhow::Error> {
    let user = resolve_minimal_config_dir(global).join("config.toml");
    acknowledged_in(&[user, PathBuf::from(ORGANIZATION_CONFIG_PATH)])
}

/// Whether any of `paths` sets the acknowledgement. The first file that
/// sets it decides.
///
/// # Errors
///
/// A file that exists but is not read or does not parse, naming its path.
pub fn acknowledged_in(paths: &[PathBuf]) -> Result<bool, anyhow::Error> {
    for path in paths {
        let config = boxes::client::config::read_config_or_default(path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if config.secrets.acknowledge_full_breadth_unenrolled {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BEP-057: the `[secrets]` table the refusal text names parses through
    /// the client configuration reader, so `min session` still starts, and
    /// the acknowledgement reads as set.
    #[test]
    fn secrets_table_reads_through_client_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path().join("minimal");
        std::fs::create_dir_all(&config_dir).expect("mkdir");
        std::fs::write(
            config_dir.join("config.toml"),
            "[secrets]\nacknowledge_full_breadth_unenrolled = true\n",
        )
        .expect("write config.toml");
        let global = GlobalArgs {
            config_dir: Some(dir.path().to_path_buf()),
            ..GlobalArgs::default()
        };
        let config = read_client_config(&global).expect("config.toml parses");
        assert!(config.secrets.acknowledge_full_breadth_unenrolled);
        assert!(full_breadth_acknowledged(&global).expect("reads"));
    }
}
