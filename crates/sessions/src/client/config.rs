//! User-level configuration for the minimal client, read from
//! `<config>/minimal/config.toml`.
//!
//! Small on purpose: today it carries only the default loadouts the
//! client applies when the user activates a session without naming
//! any explicit ones. Additional keys can be added as sections
//! grow, but every new field should start with a
//! `#[serde(default)]` so an old config keeps parsing after an
//! upgrade.

use std::path::{Path, PathBuf};

/// Root of the minimal client config.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    /// `[loadouts]` section: preferences that apply across the
    /// loadout subsystem.
    #[serde(default)]
    pub loadouts: LoadoutsConfig,
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
}

/// Parse the config at `path`.
///
/// # Errors
///
/// See [`ConfigError`]. A missing file returns
/// [`ConfigError::Io`] — use [`read_config_or_default`] if you
/// want the default config in that case.
pub fn read_config_file(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
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
}
