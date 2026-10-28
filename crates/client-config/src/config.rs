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
use crate::store_rules::{
    StoreAction, StoreDenySet, StoreRuleConfig, StoreRuleRefused, StoreRules, check_store_rules,
};

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
    /// `[secrets]` section: the operator's choices about broker
    /// secrets.
    #[serde(default)]
    pub secrets: SecretsConfig,
    /// `[secret-store-rules]` section: the operator's store rules, by item
    /// identifier. A reader that does not use them still parses the file.
    /// The client checks them against the deny set (BEP-034) before use.
    #[serde(
        default,
        rename = "secret-store-rules",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub secret_store_rules: StoreRules,
}

/// The `[secrets]` section.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SecretsConfig {
    /// When true, a GitHub grant that declares scopes narrower than
    /// `full` is accepted on an un-enrolled host, which mints it
    /// `full` (BEP-057). Read from the user and organization
    /// configuration only, never from a project.
    #[serde(default)]
    pub acknowledge_full_breadth_unenrolled: bool,
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

/// The organization-level client configuration. An administrator writes it,
/// and it applies to every user of this machine.
pub const ORGANIZATION_CONFIG_PATH: &str = "/etc/minimal/config.toml";

/// Read the client config at `path` and take its `[secret-store-rules]`
/// out of it. A missing file is the default config with no rules.
///
/// # Errors
///
/// See [`ConfigError`]: a file that exists but is not read, does not parse
/// or is not valid.
pub fn read_config_parts(path: &Path) -> Result<(Config, StoreRules), ConfigError> {
    let mut config = read_config_or_default(path)?;
    let rules = std::mem::take(&mut config.secret_store_rules);
    Ok((config, rules))
}

/// What [`read_client_store_rules`] read.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ClientStoreRules {
    /// The user configuration, with its `[secret-store-rules]` taken out.
    pub config: Config,
    /// The merged store rules that the client mints under and the proxy
    /// redeems under.
    pub rules: StoreRules,
    /// Each rule the deny set refused, organization file first. Each names
    /// its file.
    pub refused: Vec<StoreRuleRefused>,
    /// Why the organization file was not used, when it exists and is not
    /// read, does not parse or is not valid. Its rules are then left out of
    /// [`Self::rules`], so a caller that enforces store rules refuses on it.
    pub organization_error: Option<ConfigError>,
}

/// Read the `[secret-store-rules]` of the `user` and the `organization`
/// client configuration, and merge them into the one set that `min` mints
/// under and `bep` redeems under.
///
/// Each file's rules are checked against `deny` (BEP-034). A user rule
/// replaces the fields of an organization rule for the same item, but keeps
/// the stricter of the two actions, as [`merge_store_rules`] says. A rule
/// that the deny set refuses still sets that floor. An item that has only
/// refused rules gets a `deny` rule with no upstream, so a store reference
/// to it is denied.
///
/// # Errors
///
/// A user file that exists and is not read, does not parse or is not valid.
/// The same failure in the organization file is
/// [`ClientStoreRules::organization_error`].
pub fn read_client_store_rules(
    user: &Path,
    organization: &Path,
    deny: StoreDenySet<'_>,
) -> Result<ClientStoreRules, ConfigError> {
    let (config, user_read) = read_config_parts(user)?;
    let (org_read, organization_error) = match read_config_parts(organization) {
        Ok((_, rules)) => (rules, None),
        Err(e) => (StoreRules::new(), Some(e)),
    };
    let (org_rules, mut refused) =
        check_store_rules(org_read.clone(), &organization.display().to_string(), deny);
    let (user_rules, user_refused) =
        check_store_rules(user_read.clone(), &user.display().to_string(), deny);
    refused.extend(user_refused);
    let merged = merge_store_rules(org_rules, user_rules);
    let merged = keep_read_actions(&org_read, merged);
    let merged = keep_read_actions(&user_read, merged);
    let rules = deny_refused_items(&[&org_read, &user_read], merged);
    Ok(ClientStoreRules {
        config,
        rules,
        refused,
        organization_error,
    })
}

/// How strict a rule's consent is: no action and `allow` ask for nothing,
/// `ask` asks the person, and `deny` never redeems.
fn action_rank(action: Option<StoreAction>) -> u8 {
    match action {
        None | Some(StoreAction::Allow) => 0,
        Some(StoreAction::Ask) => 1,
        Some(StoreAction::Deny) => 2,
    }
}

/// Merge the user's rules over the organization's. A user rule replaces
/// the fields of an organization rule for the same item. It keeps the
/// organization rule's action when that action is stricter, so a user
/// file can never loosen an organization `deny` or `ask`.
#[must_use]
pub fn merge_store_rules(org: StoreRules, user: StoreRules) -> StoreRules {
    let mut rules = org;
    for (item, mut rule) in user {
        if let Some(org_rule) = rules.get(&item)
            && action_rank(org_rule.action) > action_rank(rule.action)
        {
            rule.action = org_rule.action;
        }
        rules.insert(item, rule);
    }
    rules
}

/// Raise the action of each rule in `merged` to the action of the rule for
/// the same item in `read`, when that action is stricter. `read` holds the
/// rules of one file as read, before the deny set refuses any of them. So a
/// rule that is refused still keeps the rule that applies to its item from
/// loosening its `deny` or `ask`.
fn keep_read_actions(read: &StoreRules, mut merged: StoreRules) -> StoreRules {
    for (item, rule) in &mut merged {
        if let Some(read_rule) = read.get(item)
            && action_rank(read_rule.action) > action_rank(rule.action)
        {
            rule.action = read_rule.action;
        }
    }
    merged
}

/// Add a `deny` rule to `merged` for each item that a file in `reads` has a
/// rule for and `merged` has none. Such an item has only refused rules. Its
/// `deny` rule registers no upstream and no header, so a store reference to
/// the item is denied, and is never redeemed with no rule to check.
fn deny_refused_items(reads: &[&StoreRules], mut merged: StoreRules) -> StoreRules {
    for read in reads {
        for (item, rule) in *read {
            merged
                .entry(item.clone())
                .or_insert_with(|| StoreRuleConfig {
                    store: rule.store.clone(),
                    upstream: Vec::new(),
                    header: None,
                    prefix: None,
                    basic_auth: None,
                    action: Some(StoreAction::Deny),
                });
        }
    }
    merged
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
        assert!(
            cfg.loadouts.default_loadouts.is_empty(),
            "expected empty, got {:?}",
            cfg.loadouts.default_loadouts
        );
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

    /// A file with both `[loadouts]` and `[secrets]` parses, and the
    /// full-breadth acknowledgement round-trips (BEP-057).
    #[test]
    fn read_config_file_loadouts_and_secrets() {
        let dir = TempDir::new().unwrap();
        let path = write_file(
            dir.path(),
            "config.toml",
            indoc::indoc! {r#"
                [loadouts]
                default_loadouts = ["helix"]

                [secrets]
                acknowledge_full_breadth_unenrolled = true
            "#},
        );
        let cfg = read_config_file(&path).unwrap();
        assert_eq!(cfg.loadouts.default_loadouts, vec!["helix"]);
        assert!(cfg.secrets.acknowledge_full_breadth_unenrolled);
        // Omitted, the acknowledgement is off.
        assert!(
            !Config::default()
                .secrets
                .acknowledge_full_breadth_unenrolled
        );
    }

    /// An unknown key in `[secrets]` is a parse error.
    #[test]
    fn secrets_unknown_field_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "config.toml", "[secrets]\nacknowledge = true\n");
        assert!(matches!(
            read_config_file(&path).unwrap_err(),
            ConfigError::Parse { .. }
        ));
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

    fn rule(action: Option<StoreAction>) -> StoreRuleConfig {
        StoreRuleConfig {
            store: None,
            upstream: vec!["api.example.com".to_owned()],
            header: Some("Authorization".to_owned()),
            prefix: None,
            basic_auth: None,
            action,
        }
    }

    /// A deny set that refuses a rule on `api.github.com`.
    fn deny() -> StoreDenySet<'static> {
        StoreDenySet {
            module_hosts: &["api.github.com"],
            infrastructure: &[],
            sign_in_items: &[],
        }
    }

    /// The rules of `rules` that [`deny`] accepts.
    fn accepted(rules: StoreRules) -> StoreRules {
        check_store_rules(rules, "config.toml", deny()).0
    }

    /// A user rule replaces an organization rule's fields, but never
    /// loosens the organization's `deny` or `ask`.
    #[test]
    fn user_store_rule_keeps_stricter_org_action() {
        let org: StoreRules = [
            ("denied".to_owned(), rule(Some(StoreAction::Deny))),
            ("asked".to_owned(), rule(Some(StoreAction::Ask))),
            ("loose".to_owned(), rule(None)),
            ("org-only".to_owned(), rule(Some(StoreAction::Ask))),
        ]
        .into();
        let mut user_denied = rule(None);
        user_denied.upstream = vec!["other.example.com".to_owned()];
        let user: StoreRules = [
            ("denied".to_owned(), user_denied),
            ("asked".to_owned(), rule(Some(StoreAction::Allow))),
            ("loose".to_owned(), rule(Some(StoreAction::Deny))),
            ("user-only".to_owned(), rule(None)),
        ]
        .into();
        let merged = merge_store_rules(org, user);
        assert_eq!(merged["denied"].action, Some(StoreAction::Deny));
        assert_eq!(merged["denied"].upstream, ["other.example.com"]);
        assert_eq!(merged["asked"].action, Some(StoreAction::Ask));
        assert_eq!(merged["loose"].action, Some(StoreAction::Deny));
        assert_eq!(merged["org-only"].action, Some(StoreAction::Ask));
        assert_eq!(merged["user-only"].action, None);
    }

    /// An organization `deny` rule that the deny set refuses still keeps a
    /// user rule for the same item from loosening it.
    #[test]
    fn refused_org_rule_keeps_its_action_over_user_rule() {
        let mut refused = rule(Some(StoreAction::Deny));
        refused.upstream = vec!["api.github.com".to_owned()];
        let org_read: StoreRules = [("item".to_owned(), refused)].into();
        let org = accepted(org_read.clone());
        assert_eq!(org, StoreRules::new());
        let user: StoreRules = [("item".to_owned(), rule(Some(StoreAction::Allow)))].into();
        let merged = keep_read_actions(&org_read, merge_store_rules(org, user));
        assert_eq!(merged["item"].action, Some(StoreAction::Deny));
        assert_eq!(merged["item"].upstream, ["api.example.com"]);
    }

    /// An item whose only rules the deny set refuses gets a `deny` rule with
    /// no upstream, so a store reference to it is denied. A refused user
    /// `deny` rule also keeps its action over an organization rule.
    #[test]
    fn refused_only_item_is_denied() {
        let mut refused = rule(None);
        refused.upstream = vec!["api.github.com".to_owned()];
        let mut refused_deny = refused.clone();
        refused_deny.action = Some(StoreAction::Deny);
        let org_read: StoreRules = [
            ("org-refused".to_owned(), refused.clone()),
            ("shared".to_owned(), rule(Some(StoreAction::Allow))),
        ]
        .into();
        let user_read: StoreRules = [
            ("user-refused".to_owned(), refused_deny.clone()),
            ("shared".to_owned(), refused_deny),
        ]
        .into();
        let org = accepted(org_read.clone());
        let user = accepted(user_read.clone());
        let merged = merge_store_rules(org, user);
        let merged = keep_read_actions(&org_read, merged);
        let merged = keep_read_actions(&user_read, merged);
        let merged = deny_refused_items(&[&org_read, &user_read], merged);
        for item in ["org-refused", "user-refused"] {
            assert_eq!(merged[item].action, Some(StoreAction::Deny), "{item}");
            assert_eq!(merged[item].upstream, Vec::<String>::new(), "{item}");
            assert_eq!(merged[item].header, None, "{item}");
        }
        assert_eq!(merged["shared"].action, Some(StoreAction::Deny));
        assert_eq!(merged["shared"].upstream, ["api.example.com"]);
        let rule = &merged["org-refused"];
        assert_eq!(
            crate::store_rules::store_consent(rule, true),
            crate::store_rules::StoreConsent::Deny
        );
    }

    /// The one reader merges both files: an organization `deny` holds
    /// against a user `allow`, refusals name their file, and an
    /// organization file that does not parse is reported, with its rules
    /// left out.
    #[test]
    fn read_client_store_rules_keeps_the_organization_deny() {
        let dir = TempDir::new().unwrap();
        let org = write_file(
            dir.path(),
            "org.toml",
            "[secret-store-rules.item]\nupstream = [\"api.example.com\"]\n\
             header = \"x-key\"\naction = \"deny\"\n",
        );
        let user = write_file(
            dir.path(),
            "user.toml",
            "[secret-store-rules.item]\nupstream = [\"api.example.com\"]\n\
             header = \"x-key\"\naction = \"allow\"\n\
             [secret-store-rules.leak]\nupstream = [\"api.github.com\"]\n\
             header = \"x-key\"\n",
        );
        let read = read_client_store_rules(&user, &org, deny()).unwrap();
        assert!(read.organization_error.is_none());
        assert_eq!(read.rules["item"].action, Some(StoreAction::Deny));
        assert_eq!(read.rules["leak"].action, Some(StoreAction::Deny));
        assert_eq!(read.rules["leak"].upstream, Vec::<String>::new());
        assert_eq!(read.refused.len(), 1);
        assert_eq!(read.refused[0].file, user.display().to_string());

        let broken = write_file(dir.path(), "broken.toml", "not toml [");
        let read = read_client_store_rules(&user, &broken, deny()).unwrap();
        assert!(matches!(
            read.organization_error,
            Some(ConfigError::Parse { .. })
        ));
        assert_eq!(read.rules["item"].action, Some(StoreAction::Allow));
        assert!(read_client_store_rules(&broken, &org, deny()).is_err());
    }
}
