//! The switches that turn the check off: the environment and the config
//! files (the user's and the organization's), read in a fixed order
//! ([`off_switch`]).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use boxes::client::config::ORGANIZATION_CONFIG_PATH;
use mlog::otel::Flag;

/// What turned the check off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDisabledReason {
    /// `[telemetry] enabled = false` in this file: the user config or the
    /// organization's (`/etc/minimal/config.toml`). Either turns it off.
    Config(PathBuf),
    /// This config file exists but could not be read or parsed, or (`None`)
    /// no config directory resolves at all. The check fails closed until it
    /// is fixed, and says so rather than claiming a setting the file may not
    /// hold.
    ConfigUnreadable(Option<PathBuf>),
    /// An environment variable, named.
    Env(&'static str),
    /// `--minimal-dir`: an alternate state directory has its own state file
    /// and no install record, so the same install would be counted twice,
    /// once as a `source` build.
    MinimalDir,
}

impl UpdateDisabledReason {
    /// What the person can do to run the check again, as one sentence.
    pub fn remedy(&self) -> String {
        match self {
            Self::Config(path) if path == Path::new(ORGANIZATION_CONFIG_PATH) => {
                "Your organization turned it off; only an administrator can turn it back on."
                    .to_string()
            }
            Self::Config(path) => format!(
                "Remove that line, or set enabled = true, in {} to run it.",
                path.display()
            ),
            Self::ConfigUnreadable(Some(path)) => format!("Fix {} to run it.", path.display()),
            Self::ConfigUnreadable(None) => {
                "Set HOME, or pass --config-dir, to run it.".to_string()
            }
            Self::Env(name) => format!("Unset {name} to run it."),
            Self::MinimalDir => "Run it without --minimal-dir.".to_string(),
        }
    }
}

impl std::fmt::Display for UpdateDisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(path) => {
                write!(f, "[telemetry] enabled = false in {}", path.display())
            }
            Self::ConfigUnreadable(Some(path)) => {
                write!(f, "{}, which could not be read or parsed", path.display())
            }
            Self::ConfigUnreadable(None) => f.write_str(
                "the missing config directory (neither XDG_CONFIG_HOME nor HOME is an absolute \
                 UTF-8 path)",
            ),
            Self::Env(name) => write!(f, "{name} in the environment"),
            Self::MinimalDir => {
                f.write_str("--minimal-dir (an alternate state directory is not counted)")
            }
        }
    }
}

/// The switch that turns the check off, if any. `DO_NOT_TRACK` (the
/// cross-tool convention) and `CI` win on presence; `OTEL_SDK_DISABLED`
/// when it is `true` (any case, as mlog reads it: the architecture's D9 has
/// it turn off everything, the check included); `MINIMAL_TELEMETRY` turns
/// it off when falsy (`0`, `false`, `no`, `off`; a truthy value is the
/// OpenTelemetry opt-in and says nothing here); then the config.
pub fn off_switch(
    config: ConfigState,
    var: impl Fn(&str) -> Option<OsString>,
) -> Option<UpdateDisabledReason> {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    if set("DO_NOT_TRACK") {
        return Some(UpdateDisabledReason::Env("DO_NOT_TRACK"));
    }
    if set("CI") {
        return Some(UpdateDisabledReason::Env("CI"));
    }
    if var("OTEL_SDK_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Some(UpdateDisabledReason::Env("OTEL_SDK_DISABLED"));
    }
    // the same reading of a boolean-ish variable as the telemetry switches
    // (`0`, `false`, `no`, `off`, any case): one parser for every switch
    let telemetry = var("MINIMAL_TELEMETRY").and_then(|v| v.into_string().ok());
    if Flag::parse(telemetry.as_deref().map(str::trim)) == Flag::False {
        return Some(UpdateDisabledReason::Env("MINIMAL_TELEMETRY"));
    }
    match config {
        ConfigState::Enabled => None,
        ConfigState::Disabled(path) => Some(UpdateDisabledReason::Config(path)),
        ConfigState::Unreadable(path) => Some(UpdateDisabledReason::ConfigUnreadable(path)),
    }
}

/// What the config files say about the check: the user's and the
/// organization's, read together, the stricter winning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigState {
    /// Both missing, or present with the check on (the default).
    Enabled,
    /// `[telemetry] enabled = false` in this file.
    Disabled(PathBuf),
    /// This file is present but not readable or not parsable, or (`None`)
    /// the user's config directory does not resolve.
    Unreadable(Option<PathBuf>),
}

/// [`ConfigState`] from the user's config directory (`None` when it does
/// not resolve) and the organization's file. An unreadable file wins over
/// one that turns the check off, and the user's file is named first.
pub fn config_state_at(user_dir: Option<&Path>, organization: &Path) -> ConfigState {
    use boxes::client::config::read_config_or_default;
    let Some(user_dir) = user_dir else {
        return ConfigState::Unreadable(None);
    };
    let mut state = ConfigState::Enabled;
    for path in [user_dir.join("config.toml"), organization.to_path_buf()] {
        match read_config_or_default(&path) {
            Ok(config) if config.telemetry.enabled => {}
            Ok(_) => {
                if state == ConfigState::Enabled {
                    state = ConfigState::Disabled(path);
                }
            }
            Err(_) => return ConfigState::Unreadable(Some(path)),
        }
    }
    state
}
