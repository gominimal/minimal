//! Client-side config-dir resolution and `config.toml` loading.
//!
//! Both the loadouts and dirs subsystems route through this module so
//! `--config-dir`, `paths::minimal_config_dir()`, and the on-disk
//! `config.toml` layout are all resolved in one place.

use std::io::Write;
use std::path::{Path, PathBuf};

use boxes::core::bep::{StoreAction, StoreDenySet, StoreRules, check_store_rules};

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
///
/// It also reads `[secret-store-rules]` and prints each refused rule on
/// stderr, as [`read_client_config_and_store_rules`] does, once per file
/// in a process. These callers use no store rules, so an organization
/// file that is not read or does not parse does not fail them: its error
/// prints once on stderr and its rules are left out. Box creation reads
/// the rules for a box that declares a store reference through
/// [`read_client_config_and_store_rules`], so this reader never decides
/// a store reference.
pub fn read_client_config(
    global: &GlobalArgs,
) -> Result<boxes::client::config::Config, anyhow::Error> {
    Ok(read_client_and_org_config(global, false)?.0)
}

/// Read the client config and the `[secret-store-rules]` of the user and
/// the organization client configuration. Each rule the deny set refuses
/// (BEP-034) is printed on stderr, naming its file, and left out of the
/// returned rules. A user rule replaces the fields of an organization rule
/// for the same item, but keeps the stricter of the two actions, as
/// [`merge_store_rules`] says. A rule that the deny set refuses still sets
/// that floor. An item that has only refused rules gets a `deny` rule with
/// no upstream, so a store reference to it is denied. The refusals of a file print on its first
/// read in a process only, so a command that reads the config more than
/// once prints each one once.
///
/// Use this reader, and not [`read_client_config`], on a path that
/// enforces store consent or store references. It fails closed on an
/// organization file that is not read or does not parse.
///
/// # Errors
///
/// A file that exists but is not read or does not parse, naming its path.
pub fn read_client_config_and_store_rules(
    global: &GlobalArgs,
) -> Result<(boxes::client::config::Config, StoreRules), anyhow::Error> {
    read_client_and_org_config(global, true)
}

/// [`read_client_config_and_store_rules`], with an organization file that
/// is not read or does not parse fatal only when `org_required` is set.
fn read_client_and_org_config(
    global: &GlobalArgs,
    org_required: bool,
) -> Result<(boxes::client::config::Config, StoreRules), anyhow::Error> {
    let user = resolve_minimal_config_dir(global).join("config.toml");
    let (config, user_rules) = read_config_parts(&user)?;
    let org_path = Path::new(ORGANIZATION_CONFIG_PATH);
    let org_rules = match read_config_parts(org_path) {
        Ok((_, rules)) => rules,
        Err(e) if !org_required => {
            report_org_read_error_once(&e);
            StoreRules::new()
        }
        Err(e) => return Err(e),
    };
    let org_read = org_rules.clone();
    let user_read = user_rules.clone();
    let org_rules = refuse_store_rules_once(org_rules, org_path);
    let user_rules = refuse_store_rules_once(user_rules, &user);
    let merged = merge_store_rules(org_rules, user_rules);
    let merged = keep_read_actions(&org_read, merged);
    let merged = keep_read_actions(&user_read, merged);
    Ok((config, deny_refused_items(&[&org_read, &user_read], merged)))
}

/// Print, on its first call in this process, that the organization file
/// was not read and that its secret-store rules do not apply.
fn report_org_read_error_once(error: &anyhow::Error) {
    static PRINTED: std::sync::Once = std::sync::Once::new();
    tracing::debug!(file = ORGANIZATION_CONFIG_PATH, %error, "organization config not read");
    PRINTED.call_once(|| {
        eprintln!(
            "Minimal did not use {ORGANIZATION_CONFIG_PATH}: {error}\n\
             The secret-store rules in that file do not apply to this command.\n\
             Correct or remove {ORGANIZATION_CONFIG_PATH}, and then run the command again."
        );
    });
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
                .or_insert_with(|| boxes::core::bep::StoreRuleConfig {
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

/// [`refuse_store_rules`] to stderr on the first read of `path` in this
/// process, and to nowhere after it.
fn refuse_store_rules_once(rules: StoreRules, path: &Path) -> StoreRules {
    static PRINTED: std::sync::Mutex<std::collections::BTreeSet<PathBuf>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let first = PRINTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.to_path_buf());
    if first {
        refuse_store_rules(rules, path, &mut std::io::stderr())
    } else {
        refuse_store_rules(rules, path, &mut std::io::sink())
    }
}

/// Read the client config at `path` and take its `[secret-store-rules]`
/// out of it. A missing file is the default config with no rules.
///
/// # Errors
///
/// A file that exists but is not read, does not parse or is not valid,
/// naming its path.
pub fn read_config_parts(
    path: &Path,
) -> Result<(boxes::client::config::Config, StoreRules), anyhow::Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => anyhow::bail!("read `{}`: {e}", path.display()),
    };
    let mut config: boxes::client::config::Config =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse `{}`: {e}", path.display()))?;
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid config `{}`: {e}", path.display()))?;
    let rules = std::mem::take(&mut config.secret_store_rules);
    Ok((config, rules))
}

/// Check `rules`, read from `path`, against the deny set (BEP-034). Writes
/// each refusal to `out` for the person, logs one debug line naming each
/// refused rule and why, and returns the rules that pass.
pub fn refuse_store_rules(rules: StoreRules, path: &Path, out: &mut impl Write) -> StoreRules {
    let module_hosts = store_module_hosts();
    let deny = store_deny_set(&module_hosts);
    let file = path.display().to_string();
    let (accepted, refused) = check_store_rules(rules, &file, deny);
    tracing::debug!(
        file,
        refused = ?refused
            .iter()
            .map(|r| format!("{}: {} {:?}", r.rule, r.requirement(), r.reason))
            .collect::<Vec<_>>(),
        "read [secret-store-rules]"
    );
    for refusal in &refused {
        // A failed write to stderr leaves nothing else to tell.
        let _ = writeln!(out, "{refusal}");
    }
    accepted
}

/// The user-level client configuration file: `config.toml` in the resolved
/// config dir. `min secret set` writes store rules here and nowhere else
/// (BEP-079).
#[must_use]
pub fn user_config_path(global: &GlobalArgs) -> PathBuf {
    resolve_minimal_config_dir(global).join("config.toml")
}

/// What [`write_store_rule`] changed: the file it wrote, after any
/// symlink, with its bytes before and after the write.
/// [`restore_config`] puts the old bytes back.
#[derive(Debug)]
pub struct ConfigSnapshot {
    /// The file that was written. A symlinked `config.toml` names its target.
    file: PathBuf,
    /// The bytes before the write, or `None` when there was no file.
    before: Option<Vec<u8>>,
    /// The bytes the write left in the file.
    written: Vec<u8>,
}

/// The file a write to `path` changes: the target when `path` is a
/// symlink, so the rename keeps the link. A dangling link stays `path`.
fn write_target(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Write `rule` as the `[secret-store-rules.<id>]` rule of the client
/// configuration at `path`, replacing any rule for `id` there. Every other
/// line of the file stays as it is. The file is replaced in one rename, so a
/// failed write leaves the old file. A symlinked file is written at its
/// target. Returns the file as it was before.
///
/// # Errors
///
/// A file that is not read or does not parse, a `[secret-store-rules]` that
/// is not a table, or a write that fails, naming the path.
pub fn write_store_rule(
    path: &Path,
    id: &str,
    rule: &boxes::core::bep::StoreRuleConfig,
) -> Result<ConfigSnapshot, anyhow::Error> {
    let file = write_target(path);
    let before = match std::fs::read(&file) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => anyhow::bail!("read `{}`: {e}", path.display()),
    };
    let text = match &before {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("parse `{}`: {e}", path.display()))?,
        None => "",
    };
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| anyhow::anyhow!("parse `{}`: {e}", path.display()))?;
    let table = doc
        .entry(boxes::core::bep::STORE_RULES_TABLE)
        .or_insert_with(|| {
            let mut table = toml_edit::Table::new();
            table.set_implicit(true);
            toml_edit::Item::Table(table)
        })
        .as_table_mut()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "`{path}` sets {table} as an inline table. Write each rule as its own \
                 [{table}.<name>] section, and run the command again",
                path = path.display(),
                table = boxes::core::bep::STORE_RULES_TABLE
            )
        })?;
    table.insert(id, toml_edit::Item::Table(store_rule_table(rule)));
    let written = doc.to_string().into_bytes();
    write_config_bytes(&file, &written)?;
    Ok(ConfigSnapshot {
        file,
        before,
        written,
    })
}

/// `rule` as a TOML table, with the fields in the order the docs show.
fn store_rule_table(rule: &boxes::core::bep::StoreRuleConfig) -> toml_edit::Table {
    let mut table = toml_edit::Table::new();
    if let Some(store) = &rule.store {
        table.insert("store", toml_edit::value(store.as_str()));
    }
    let upstream: toml_edit::Array = rule.upstream.iter().map(String::as_str).collect();
    table.insert("upstream", toml_edit::value(upstream));
    for (key, field) in [
        ("header", &rule.header),
        ("prefix", &rule.prefix),
        ("basic_auth", &rule.basic_auth),
    ] {
        if let Some(text) = field {
            table.insert(key, toml_edit::value(text.as_str()));
        }
    }
    if let Some(action) = rule.action {
        let action = match action {
            StoreAction::Allow => "allow",
            StoreAction::Ask => "ask",
            StoreAction::Deny => "deny",
        };
        table.insert("action", toml_edit::value(action));
    }
    table
}

/// Put the file that `snapshot` names back as it was before the write: its
/// old bytes, or no file when there was none. A file that changed after the
/// write stays as it is, so no other edit is lost.
///
/// # Errors
///
/// A file that changed after the write, or a read, write or remove that
/// fails, naming the path.
pub fn restore_config(snapshot: &ConfigSnapshot) -> Result<(), anyhow::Error> {
    let path = &snapshot.file;
    let now = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => anyhow::bail!("read `{}`: {e}", path.display()),
    };
    if now.as_deref() != Some(snapshot.written.as_slice()) {
        anyhow::bail!(
            "`{}` changed after min secret set wrote the rule, so it was left as it is",
            path.display()
        );
    }
    match &snapshot.before {
        Some(bytes) => write_config_bytes(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => anyhow::bail!("remove `{}`: {e}", path.display()),
        },
    }
}

/// Replace the file at `path` with `bytes` in one rename, creating its
/// directory when it is missing.
fn write_config_bytes(path: &Path, bytes: &[u8]) -> Result<(), anyhow::Error> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("create `{}`: {e}", dir.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| anyhow::anyhow!("write `{}`: {e}", path.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        // Keep the old file's mode. A failure leaves the default mode.
        let _ = tmp.as_file().set_permissions(meta.permissions());
    }
    tmp.write_all(bytes)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| anyhow::anyhow!("write `{}`: {e}", path.display()))?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("write `{}`: {}", path.display(), e.error))?;
    Ok(())
}

/// The hosts of every deep module, for [`store_deny_set`].
#[must_use]
pub fn store_module_hosts() -> Vec<&'static str> {
    bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| authority.host)
        .collect()
}

/// What a store rule or a store reference can never name (BEP-034), over
/// the module hosts [`store_module_hosts`] gives. Reading the
/// configuration and creating a box judge against this one set.
#[must_use]
pub fn store_deny_set<'a>(module_hosts: &'a [&'a str]) -> StoreDenySet<'a> {
    StoreDenySet {
        module_hosts,
        infrastructure: bep::ca::DENY_SET,
        sign_in_items: &[bep::signin::SERVICE, bep::signin::META_SERVICE],
    }
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
        let (config, _) = read_config_parts(path)?;
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

    /// BEP-034: a `[secret-store-rules]` table reads through the client
    /// configuration, and a rule aimed at a GitHub host or the Host header
    /// is refused by name on stderr and left out.
    #[test]
    fn store_rules_read_through_client_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[secrets]\nacknowledge_full_breadth_unenrolled = true\n\n\
             [secret-store-rules.claude]\nupstream = [\"api.anthropic.com\"]\n\
             header = \"Authorization\"\nprefix = \"Bearer \"\n\n\
             [secret-store-rules.gh]\nupstream = [\"api.github.com\"]\nheader = \"Authorization\"\n\n\
             [secret-store-rules.host]\nupstream = [\"example.com\"]\nheader = \"Host\"\n\n\
             [secret-store-rules.internal]\nupstream = [\"host.min.internal\"]\nheader = \"X-Key\"\n",
        )
        .expect("write config.toml");
        let (config, rules) = read_config_parts(&path).expect("config.toml parses");
        assert!(config.secrets.acknowledge_full_breadth_unenrolled);
        assert!(acknowledged_in(std::slice::from_ref(&path)).expect("reads"));
        let mut out = Vec::new();
        let accepted = refuse_store_rules(rules, &path, &mut out);
        assert_eq!(accepted.keys().collect::<Vec<_>>(), ["claude"]);
        let out = String::from_utf8(out).expect("utf-8");
        let file = path.display();
        assert_eq!(
            out,
            format!(
                "The secret-store rule gh in {file} names api.github.com, which a secret can \
                 never be sent to. Remove or change the rule.\n\
                 The secret-store rule host in {file} names the header Host, which a secret can \
                 never be sent to. Remove or change the rule.\n\
                 The secret-store rule internal in {file} names host.min.internal, which is \
                 under min.internal. A secret can never be sent to min.internal or a name \
                 under it. Remove or change the rule.\n"
            )
        );
    }

    /// A config.toml that holds `[secret-store-rules]` still parses through
    /// the reader the attach path uses, which keeps the rules in `Config`.
    #[test]
    fn store_rules_parse_through_attach_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[secret-store-rules.claude]\nupstream = [\"api.anthropic.com\"]\n\
             header = \"Authorization\"\n",
        )
        .expect("write config.toml");
        let config = boxes::client::config::read_config_or_default(&path).expect("parses");
        assert_eq!(
            config.secret_store_rules.keys().collect::<Vec<_>>(),
            ["claude"]
        );
        let (config, rules) = read_config_parts(&path).expect("parses");
        assert!(config.secret_store_rules.is_empty());
        assert_eq!(rules.keys().collect::<Vec<_>>(), ["claude"]);
    }

    fn rule(action: Option<StoreAction>) -> boxes::core::bep::StoreRuleConfig {
        boxes::core::bep::StoreRuleConfig {
            store: None,
            upstream: vec!["api.example.com".to_owned()],
            header: Some("Authorization".to_owned()),
            prefix: None,
            basic_auth: None,
            action,
        }
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
        let dir = tempfile::tempdir().expect("tempdir");
        let org_path = dir.path().join("org.toml");
        let mut refused = rule(Some(StoreAction::Deny));
        refused.upstream = vec!["api.github.com".to_owned()];
        let org_read: StoreRules = [("item".to_owned(), refused)].into();
        let org = refuse_store_rules(org_read.clone(), &org_path, &mut std::io::sink());
        assert!(org.is_empty());
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
        let path = std::path::Path::new("config.toml");
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
        let org = refuse_store_rules(org_read.clone(), path, &mut std::io::sink());
        let user = refuse_store_rules(user_read.clone(), path, &mut std::io::sink());
        let merged = merge_store_rules(org, user);
        let merged = keep_read_actions(&org_read, merged);
        let merged = keep_read_actions(&user_read, merged);
        let merged = deny_refused_items(&[&org_read, &user_read], merged);
        for item in ["org-refused", "user-refused"] {
            assert_eq!(merged[item].action, Some(StoreAction::Deny), "{item}");
            assert!(merged[item].upstream.is_empty(), "{item}");
            assert_eq!(merged[item].header, None, "{item}");
        }
        assert_eq!(merged["shared"].action, Some(StoreAction::Deny));
        assert_eq!(merged["shared"].upstream, ["api.example.com"]);
        let rule = &merged["org-refused"];
        assert_eq!(
            boxes::core::bep::store_consent(rule, true),
            boxes::core::bep::StoreConsent::Deny
        );
    }

    fn sample_rule() -> boxes::core::bep::StoreRuleConfig {
        boxes::core::bep::StoreRuleConfig {
            store: None,
            upstream: vec!["api.example.com".to_owned()],
            header: Some("x-api-key".to_owned()),
            prefix: None,
            basic_auth: None,
            action: None,
        }
    }

    /// BEP-079: the write and the restore go through a symlinked
    /// `config.toml` to its target, and the link stays a link.
    #[cfg(unix)]
    #[test]
    fn secret_set_partial_failure_restores_both_through_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("config.toml");
        std::fs::write(&real, "# mine\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let snapshot = write_store_rule(&link, "claude", &sample_rule()).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains("[secret-store-rules.claude]")
        );
        restore_config(&snapshot).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "# mine\n");
    }

    /// BEP-079: an edit made after the rule write is not lost by the
    /// restore. The restore refuses and names the file.
    #[test]
    fn secret_set_partial_failure_restores_both_keeps_later_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "# mine\n").unwrap();
        let snapshot = write_store_rule(&path, "claude", &sample_rule()).unwrap();
        std::fs::write(&path, "# edited\n").unwrap();
        let err = restore_config(&snapshot).expect_err("the file changed");
        assert!(format!("{err:#}").contains("changed after min secret set wrote the rule"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# edited\n");
    }
}
