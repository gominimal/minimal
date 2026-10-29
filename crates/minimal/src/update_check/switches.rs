//! The switches that turn the check off: the environment and the user
//! config, read in a fixed order ([`off_switch`]).

use std::ffi::OsString;

use mlog::otel::Flag;

/// What turned the check off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDisabledReason {
    /// `[telemetry] enabled = false` in the user config.
    Config,
    /// The user config exists but could not be read or parsed: the check
    /// fails closed until it is fixed, and says so rather than claiming a
    /// setting the file may not hold.
    ConfigUnreadable,
    /// An environment variable, named.
    Env(&'static str),
    /// `--minimal-dir`: an alternate state directory has its own state file
    /// and no install record, so the same install would be counted twice,
    /// once as a `source` build.
    MinimalDir,
}

impl std::fmt::Display for UpdateDisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateDisabledReason::Config => f.write_str("[telemetry] enabled = false in config.toml"),
            UpdateDisabledReason::ConfigUnreadable => {
                f.write_str("a config.toml that could not be read or parsed (the check stays off until it is fixed)")
            }
            UpdateDisabledReason::Env(name) => write!(f, "{name} in the environment"),
            UpdateDisabledReason::MinimalDir => f.write_str("--minimal-dir (an alternate state directory is not counted)"),
        }
    }
}

/// The switch that turns the check off, if any. `DO_NOT_TRACK` (the
/// cross-tool convention) and `CI` win on presence; `MINIMAL_TELEMETRY`
/// turns it off when falsy (`0`, `false`, `no`, `off`; a truthy value is the
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
    // the same reading of a boolean-ish variable as the telemetry switches
    // (`0`, `false`, `no`, `off`, any case): one parser for every switch
    let telemetry = var("MINIMAL_TELEMETRY").and_then(|v| v.into_string().ok());
    if Flag::parse(telemetry.as_deref().map(str::trim)) == Flag::False {
        return Some(UpdateDisabledReason::Env("MINIMAL_TELEMETRY"));
    }
    match config {
        ConfigState::Enabled => None,
        ConfigState::Disabled => Some(UpdateDisabledReason::Config),
        ConfigState::Unreadable => Some(UpdateDisabledReason::ConfigUnreadable),
    }
}

/// What the user config says about the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigState {
    /// Missing, or present with the check on (the default).
    Enabled,
    /// `[telemetry] enabled = false`.
    Disabled,
    /// Present but not readable or not parsable.
    Unreadable,
}
