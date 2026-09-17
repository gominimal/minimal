//! User-level configuration for the minimal client, read from
//! `<config>/minimal/config.toml`.
//!
//! Small on purpose: today it carries the default loadouts the
//! client applies when the user activates a session without naming
//! any explicit ones, and the configurable session leader/subcommand
//! keys (`[session-keys]`). Additional keys can be added as sections
//! grow, but every new field should start with a
//! `#[serde(default)]` so an old config keeps parsing after an
//! upgrade.

use std::path::{Path, PathBuf};

use crate::keys;

/// Root of the minimal client config.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    /// `[loadouts]` section: preferences that apply across the
    /// loadout subsystem.
    #[serde(default)]
    pub loadouts: LoadoutsConfig,
    /// `[session-keys]` section: the configurable session leader chord
    /// and its command-mode subcommand keys. Negotiated with the
    /// daemon per attach channel; see [`keys`] and
    /// [`SessionKeysConfig::to_session_keys`]. Renamed to the kebab
    /// table form (`[session-keys]`) the on-disk config uses; fields
    /// within stay `snake_case` to match the rest of the config.
    #[serde(default, rename = "session-keys")]
    pub session_keys: SessionKeysConfig,
}

/// The `[loadouts]` section.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct LoadoutsConfig {
    /// Loadouts (by filename stem) automatically applied to each
    /// new session unless the client overrides them.
    #[serde(default)]
    pub default_loadouts: Vec<String>,
    /// When true, the patch walker follows symlinks while
    /// enumerating loadout patch sources. Off by default — most
    /// walks want the on-disk file, not a symlink target. Turn on
    /// when your dotfile tree is a symlink farm (stow / chezmoi /
    /// hand-linked) and you actually want the walk to descend
    /// through the links.
    #[serde(default)]
    pub follow_symlinks: bool,
}

/// The `[session-keys]` section: the configurable session leader
/// chord, its command-mode subcommand keys, and the bell flag. Every
/// field defaults (omitted means the shipped default), so an old
/// config keeps parsing; [`SessionKeysConfig::to_session_keys`]
/// resolves the defaults and validates the leader loudly at load.
///
/// See the [`keys`] module for why the leader must not be
/// termios-special, and how the daemon re-runs the same check as a
/// silent backstop.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SessionKeysConfig {
    /// The chord that enters command mode, as a logical key name
    /// (e.g. `"ctrl-]"`). Omitted means the default `ctrl-]`.
    /// Validated loudly at load against the termios-special and
    /// wrapping-ambiguous reject sets.
    #[serde(default)]
    pub leader: Option<keys::Key>,
    /// The command-mode subcommand keys (`[session-keys.subcommands]`).
    #[serde(default)]
    pub subcommands: SubcommandsConfig,
    /// Whether entering command mode rings the terminal bell
    /// (BEL `0x07`). Off by default.
    #[serde(default)]
    pub bell_on_leader: bool,
}

/// The `[session-keys.subcommands]` table: the keys bound in command
/// mode. Named fields (not a free-form map) so a typo fails loudly via
/// `deny_unknown_fields`, and so each key is typed as a [`keys::Key`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SubcommandsConfig {
    /// The command-mode key that detaches the channel. Omitted means `d`.
    #[serde(default)]
    pub detach: Option<keys::Key>,
    /// The command-mode key that verbatim-forwards a leader byte down
    /// the PTY (for nested sessions). Omitted means the resolved
    /// leader, so a double-press forwards.
    #[serde(default)]
    pub forward: Option<keys::Key>,
}

/// Failure loading the config file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file couldn't be read.
    #[error("read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file wasn't valid TOML or didn't match the [`Config`]
    /// schema.
    #[error("parse `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    /// The file parsed but a section failed validation — e.g. an
    /// unsafe session-key leader (termios-special or
    /// wrapping-ambiguous). Surfaced loudly at load rather than
    /// acting on the chord later.
    #[error("invalid config `{path}`: {source}")]
    Validation {
        path: PathBuf,
        #[source]
        source: keys::KeyError,
    },
}

/// Parse and validate the config at `path`.
///
/// # Errors
///
/// See [`ConfigError`]. A missing file returns [`ConfigError::Io`] —
/// use [`read_config_or_default`] if you want the default config in
/// that case. A file that parses but fails section validation (e.g.
/// an unsafe session-key leader) returns [`ConfigError::Validation`].
pub fn read_config_file(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let cfg: Config = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    cfg.validate().map_err(|source| ConfigError::Validation {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(cfg)
}

/// Parse the config at `path`, or return [`Config::default`] when
/// the file doesn't exist. Any other read or parse failure
/// propagates as [`ConfigError`].
///
/// # Errors
///
/// See [`ConfigError`]. `NotFound` is folded into `Ok(default)`;
/// permission or parse failures still surface.
pub fn read_config_or_default(path: &Path) -> Result<Config, ConfigError> {
    match read_config_file(path) {
        Ok(cfg) => Ok(cfg),
        Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(Config::default())
        }
        Err(e) => Err(e),
    }
}

impl Config {
    /// Validate every section, failing loudly. Currently validates
    /// the session-key leader against the termios-special and
    /// wrapping-ambiguous reject sets (the UX gate; the daemon re-runs
    /// the same check as a silent backstop).
    ///
    /// # Errors
    ///
    /// Returns [`keys::KeyError`] when a section is invalid.
    pub fn validate(&self) -> Result<(), keys::KeyError> {
        self.session_keys.to_session_keys().map(|_| ())
    }
}

impl SessionKeysConfig {
    /// Resolve this config into the negotiated [`keys::SessionKeys`],
    /// filling omitted fields with the shipped defaults (`forward`
    /// falls back to the resolved leader, so a double-press
    /// forwards), rejecting an unsafe leader or a detach key that
    /// shadows another binding loudly.
    ///
    /// # Errors
    ///
    /// Returns [`keys::KeyError`] when the resolved leader is
    /// termios-special or wrapping-ambiguous, or the detach key
    /// aliases the leader or forward key (shadowing a binding).
    pub fn to_session_keys(&self) -> Result<keys::SessionKeys, keys::KeyError> {
        let default = keys::SessionKeys::default();
        let leader = self.leader.unwrap_or(default.leader);
        keys::validate_leader(&leader)?;
        let detach_key = self.subcommands.detach.unwrap_or(default.detach_key);
        let forward_key = self.subcommands.forward.unwrap_or(leader);
        let keys = keys::SessionKeys {
            leader,
            detach_key,
            forward_key,
            bell_on_leader: self.bell_on_leader,
        };
        keys::validate_detach_unaliased(&keys)?;
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    /// A well-formed config with a populated `default_loadouts`
    /// list round-trips through the parser.
    #[test]
    fn read_config_file_ok() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [loadouts]
                default_loadouts = ["helix", "fish"]
            "#},
        );
        let cfg = read_config_file(&path).unwrap();
        assert_eq!(cfg.loadouts.default_loadouts, vec!["helix", "fish"]);
        // `follow_symlinks` defaults to false when omitted.
        assert!(!cfg.loadouts.follow_symlinks);
    }

    /// `follow_symlinks` round-trips when explicitly set.
    #[test]
    fn read_config_file_follow_symlinks_opt_in() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r"
                [loadouts]
                follow_symlinks = true
            "},
        );
        let cfg = read_config_file(&path).unwrap();
        assert!(cfg.loadouts.follow_symlinks);
    }

    /// An empty config file parses to `Config::default()`.
    #[test]
    fn read_config_file_empty_is_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "");
        let cfg = read_config_file(&path).unwrap();
        assert_eq!(cfg, Config::default());
    }

    /// A missing `[loadouts]` section deserializes to the default
    /// `LoadoutsConfig` (empty default list) — every subsection is
    /// optional.
    #[test]
    fn read_config_file_missing_section_uses_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "# empty");
        let cfg = read_config_file(&path).unwrap();
        assert!(cfg.loadouts.default_loadouts.is_empty());
    }

    /// Unknown top-level keys are rejected so a typo (`loadout`
    /// vs `loadouts`) fails loudly instead of silently doing
    /// nothing.
    #[test]
    fn read_config_file_unknown_key_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "[loadout]\n");
        let err = read_config_file(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    /// A missing config file folds into `Config::default()` via
    /// `read_config_or_default`.
    #[test]
    fn read_config_or_default_missing_returns_default() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        let cfg = read_config_or_default(&missing).unwrap();
        assert_eq!(cfg, Config::default());
    }

    /// A malformed config file still errors under
    /// `read_config_or_default` — only `NotFound` is silenced.
    #[test]
    fn read_config_or_default_malformed_still_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "= not = toml =");
        let err = read_config_or_default(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    // --- [session-keys] ------------------------------------------------

    /// A populated `[session-keys]` section round-trips through the
    /// parser and resolves to the configured keys.
    #[test]
    fn session_keys_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-]"
                bell_on_leader = true

                [session-keys.subcommands]
                detach = "d"
                forward = "ctrl-]"
            "#},
        );
        let cfg = read_config_file(&path).unwrap();
        let keys = cfg.session_keys.to_session_keys().unwrap();
        assert_eq!(keys.leader, keys::Key::parse("ctrl-]").unwrap());
        assert_eq!(keys.detach_key, keys::Key::parse("d").unwrap());
        assert_eq!(keys.forward_key, keys::Key::parse("ctrl-]").unwrap());
        assert!(keys.bell_on_leader);
    }

    /// An omitted `[session-keys]` section resolves to the shipped
    /// defaults.
    #[test]
    fn session_keys_omitted_resolves_to_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "# empty");
        let cfg = read_config_file(&path).unwrap();
        assert_eq!(
            cfg.session_keys.to_session_keys().unwrap(),
            keys::SessionKeys::default()
        );
    }

    /// `forward` omitted falls back to the *resolved* leader, not a
    /// hardcoded key: a custom leader with no forward gets forward =
    /// leader.
    #[test]
    fn session_keys_forward_defaults_to_leader() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-^"
            "#},
        );
        let cfg = read_config_file(&path).unwrap();
        let keys = cfg.session_keys.to_session_keys().unwrap();
        assert_eq!(keys.leader, keys::Key::parse("ctrl-^").unwrap());
        assert_eq!(keys.forward_key, keys.leader);
        // detach still defaults to `d`.
        assert_eq!(keys.detach_key, keys::Key::parse("d").unwrap());
    }

    /// A termios-special leader is rejected loudly at load.
    #[test]
    fn session_keys_rejects_termios_special_leader() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-c"
            "#},
        );
        let err = read_config_file(&path).unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation { .. }),
            "expected Validation, got {err:?}"
        );
    }

    /// A wrapping-ambiguous leader is rejected loudly at load.
    #[test]
    fn session_keys_rejects_ambiguous_leader() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-i"
            "#},
        );
        assert!(matches!(
            read_config_file(&path).unwrap_err(),
            ConfigError::Validation { .. }
        ));
    }

    /// The old default `ctrl-w` (`VWERASE`) is now rejected — the
    /// hard-cut retires it as a latent termios footgun.
    #[test]
    fn session_keys_rejects_old_ctrl_w_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-w"
            "#},
        );
        assert!(matches!(
            read_config_file(&path).unwrap_err(),
            ConfigError::Validation { .. }
        ));
    }

    /// A safe custom leader parses and validates.
    #[test]
    fn session_keys_accepts_safe_custom_leader() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-^"
            "#},
        );
        let cfg = read_config_file(&path).unwrap();
        assert!(cfg.validate().is_ok());
    }

    /// An unknown key in `[session-keys]` is a parse error
    /// (`deny_unknown_fields`), not a silent no-op.
    #[test]
    fn session_keys_unknown_field_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                laeder = "ctrl-]"
            "#},
        );
        assert!(matches!(
            read_config_file(&path).unwrap_err(),
            ConfigError::Parse { .. }
        ));
    }

    /// An unknown subcommand name is a parse error, not silently
    /// ignored.
    #[test]
    fn session_keys_unknown_subcommand_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys.subcommands]
                detach = "d"
                detatch = "x"
            "#},
        );
        assert!(matches!(
            read_config_file(&path).unwrap_err(),
            ConfigError::Parse { .. }
        ));
    }

    /// Validation also surfaces through `read_config_or_default` (the
    /// path `min` uses): only `NotFound` is silenced, not a bad leader.
    #[test]
    fn read_config_or_default_surfaces_validation_error() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [session-keys]
                leader = "ctrl-z"
            "#},
        );
        assert!(matches!(
            read_config_or_default(&path).unwrap_err(),
            ConfigError::Validation { .. }
        ));
    }
}
