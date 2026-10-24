//! Client-side config-dir resolution and `config.toml` loading.
//!
//! Both the loadouts and dirs subsystems route through this module so
//! `--config-dir`, `paths::minimal_config_dir()`, and the on-disk
//! `config.toml` layout are all resolved in one place.

use std::io::Write;
use std::path::{Path, PathBuf};

use boxes::core::bep::{STORE_RULES_TABLE, StoreDenySet, StoreRules, check_store_rules};

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
/// stderr, as [`read_client_config_and_store_rules`] does, once per process.
pub fn read_client_config(
    global: &GlobalArgs,
) -> Result<boxes::client::config::Config, anyhow::Error> {
    Ok(read_client_config_and_store_rules(global)?.0)
}

/// Read the client config and its `[secret-store-rules]` once. Each rule the
/// deny set refuses (BEP-034) is printed on stderr and left out of the
/// returned rules. The refusals print on the first read in a process only,
/// so a command that reads the config more than once prints each one once.
///
/// # Errors
///
/// A file that exists but is not read or does not parse, naming its path.
pub fn read_client_config_and_store_rules(
    global: &GlobalArgs,
) -> Result<(boxes::client::config::Config, StoreRules), anyhow::Error> {
    let cfg_path = resolve_minimal_config_dir(global).join("config.toml");
    let (config, rules) = read_config_parts(&cfg_path)?;
    static PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let rules = if PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        refuse_store_rules(rules, &cfg_path, &mut std::io::sink())
    } else {
        refuse_store_rules(rules, &cfg_path, &mut std::io::stderr())
    };
    Ok((config, rules))
}

/// Read the client config at `path` and take its `[secret-store-rules]`
/// table out before the rest is parsed. A missing file is the default
/// config with no rules.
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
    let mut table: toml::Table =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse `{}`: {e}", path.display()))?;
    let rules: StoreRules = match table.remove(STORE_RULES_TABLE) {
        None => StoreRules::new(),
        Some(value) => value.try_into().map_err(|e| {
            anyhow::anyhow!("parse `{}`: [{STORE_RULES_TABLE}]: {e}", path.display())
        })?,
    };
    let config: boxes::client::config::Config = toml::Value::Table(table)
        .try_into()
        .map_err(|e| anyhow::anyhow!("parse `{}`: {e}", path.display()))?;
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid config `{}`: {e}", path.display()))?;
    Ok((config, rules))
}

/// Check `rules`, read from `path`, against the deny set (BEP-034). Writes
/// each refusal to `out` for the person, logs one debug line naming each
/// refused rule and why, and returns the rules that pass.
pub fn refuse_store_rules(rules: StoreRules, path: &Path, out: &mut impl Write) -> StoreRules {
    let module_hosts: Vec<&str> = bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| authority.host)
        .collect();
    let deny = StoreDenySet {
        module_hosts: &module_hosts,
        infrastructure: bep::ca::DENY_SET,
        sign_in_items: &[bep::signin::SERVICE, bep::signin::META_SERVICE],
    };
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
                 The secret-store rule internal in {file} names host.min.internal, which a \
                 secret can never be sent to. Remove or change the rule.\n"
            )
        );
    }
}
