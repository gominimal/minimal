//! Loadout selection, composition, and the `minimal loadout list`
//! command. Backed by the on-disk primitives in
//! [`sessions::client::disk`] and driven from the client `config.toml`
//! (see [`crate::config`]).

use anyhow::{Context as _, bail};
use std::path::PathBuf;

use crate::config::{read_client_config, resolve_minimal_config_dir};
use crate::{GlobalArgs, LoadoutListArgs};

/// The user's choice of which loadouts to apply for a session
/// activation, resolved from CLI flags before disk I/O begins.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoadoutSelection {
    /// `--no-loadouts` set — apply nothing regardless of config.
    None,
    /// `--loadout` set (one or more) — apply exactly these names,
    /// config defaults ignored.
    Cli(Vec<String>),
    /// Neither flag set — apply `[loadouts].default_loadouts` from
    /// the client config (which may itself be empty).
    Defaults,
}

impl LoadoutSelection {
    /// Fold `--loadout` and `--no-loadouts` into a single value.
    /// Clap enforces the mutual exclusion via `conflicts_with`, so
    /// the two flags together never reach here.
    pub(crate) fn from_flags(cli_loadouts: &[String], no_loadouts: bool) -> Self {
        if no_loadouts {
            Self::None
        } else if cli_loadouts.is_empty() {
            Self::Defaults
        } else {
            Self::Cli(cli_loadouts.to_vec())
        }
    }
}

/// Resolve the loadout names to apply for a session activation
/// and load each from disk.
///
/// Errors out on any missing or malformed loadout so the user
/// doesn't get a silently-empty session when their config is
/// broken.
pub(crate) fn resolve_active_loadouts(
    selection: LoadoutSelection,
    cfg: &sessions::client::config::Config,
    global: &GlobalArgs,
) -> Result<Vec<sessions::core::loadout::Loadout>, anyhow::Error> {
    let (names, source): (Vec<String>, &str) = match selection {
        LoadoutSelection::None => return Ok(Vec::new()),
        LoadoutSelection::Cli(names) => (names, "--loadout"),
        LoadoutSelection::Defaults => (cfg.loadouts.default_loadouts.clone(), "default_loadouts"),
    };
    let loadouts_dir = resolve_minimal_config_dir(global).join("loadouts");
    names
        .iter()
        .map(|name| {
            let path = loadouts_dir.join(format!("{name}.toml"));
            sessions::client::disk::read_loadout_file(&path)
                .with_context(|| format!("{source} `{name}`"))
        })
        .collect()
}

/// Build the [`ComposeOptions`] the client passes to
/// `UserComposer::compose`, translating relevant config fields.
///
/// [`ComposeOptions`]: sessions::core::compose::ComposeOptions
pub(crate) fn compose_options_from_config(
    cfg: &sessions::client::config::Config,
) -> sessions::core::compose::ComposeOptions {
    sessions::core::compose::ComposeOptions::default()
        .with_follow_symlinks(cfg.loadouts.follow_symlinks)
}

/// Compose the given loadouts into a [`sessions::wire::request::WireContribution`]
/// under the user's [`UserPolicy`] loaded from `user_policy.toml`.
/// User-origin items auto-pass the allow step but the policy's
/// `deny` / `ignore` rules still apply, so a loadout patch matching
/// a deny rule fails the composition here rather than at the daemon.
///
/// [`UserPolicy`]: sessions::core::policy::UserPolicy
pub(crate) fn compose_user_contribution(
    loadouts: Vec<sessions::core::loadout::Loadout>,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
) -> Result<sessions::wire::request::WireContribution, anyhow::Error> {
    let mut composer = sessions::client::composer::UserComposer::new();
    composer
        .add_all(loadouts)
        .map_err(|e| anyhow::anyhow!("composing loadouts: {e}"))?;
    composer
        .compose(policy, options)
        .map_err(|e| anyhow::anyhow!("composing loadouts: {e}"))
}

// =========================================================================
// `minimal loadout list` — enumerate discovered loadouts.
// =========================================================================

/// Resolve the loadouts directory. Order of precedence:
/// `--dir` on the subcommand, then `--config-dir` via
/// [`resolve_minimal_config_dir`], then the platform default.
fn resolve_loadouts_dir(args: &LoadoutListArgs, global: &GlobalArgs) -> PathBuf {
    if let Some(dir) = &args.dir {
        return dir.clone();
    }
    resolve_minimal_config_dir(global).join("loadouts")
}

/// List loadouts discovered in the loadouts directory. One row per
/// `.toml` file; malformed entries are shown with their parse error
/// so an operator can fix them in place. Loadouts named in
/// `[loadouts].default_loadouts` in the client config are marked
/// with a leading `*`.
pub fn cmd_loadout_list(args: LoadoutListArgs, global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let dir = resolve_loadouts_dir(&args, global);
    let entries = match sessions::client::disk::list_loadouts(&dir) {
        Ok(entries) => entries,
        Err(sessions::client::disk::ListError::NotFound { path }) => {
            eprintln!("No loadouts directory at {}.", path.display());
            eprintln!("Create it and drop `<name>.toml` files there to get started.");
            return Ok(());
        }
        Err(e) => bail!("{e}"),
    };

    // Load `<config>/minimal/config.toml` to discover which
    // loadouts should be marked as defaults. Missing file → no
    // defaults; malformed file → error out so the user can see it.
    // Routes through `read_client_config` so this and `cmd_activate`
    // share one config-loading path.
    let defaults: std::collections::HashSet<String> = read_client_config(global)?
        .loadouts
        .default_loadouts
        .into_iter()
        .collect();

    if entries.is_empty() {
        println!("No loadouts in {}.", dir.display());
        return Ok(());
    }

    // Warn about defaults that don't have a matching file — a
    // silent typo in `default_loadouts` would otherwise be
    // invisible until the user wondered why their loadout wasn't
    // active.
    let present: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.file_stem.as_str()).collect();
    defaults
        .iter()
        .filter(|missing| !present.contains(missing.as_str()))
        .for_each(|missing| {
            eprintln!(
                "Warning: `{missing}` listed in default_loadouts but no `{missing}.toml` in {}",
                dir.display(),
            );
        });

    let rows: Vec<LoadoutRow> = entries
        .iter()
        .map(|entry| LoadoutRow::from_entry(entry, &defaults))
        .collect();

    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let desc_w = rows
        .iter()
        .map(|r| r.desc.len())
        .max()
        .unwrap_or(11)
        .max(11);
    println!(
        "  {:<name_w$}  {:<desc_w$}  CONTRIBUTES",
        "NAME", "DESCRIPTION"
    );
    rows.into_iter().for_each(
        |LoadoutRow {
             marker,
             name,
             desc,
             counts,
         }| { println!("{marker} {name:<name_w$}  {desc:<desc_w$}  {counts}") },
    );
    if !defaults.is_empty() {
        println!();
        println!("* default (from `[loadouts].default_loadouts`)");
    }
    Ok(())
}

/// One row of `loadout list` output. Kept as a struct rather than a
/// tuple so the marker / name / description / counts columns can be
/// widened independently at print time — mirrors the `DirRow` shape
/// used by `crate::dirs`.
struct LoadoutRow {
    marker: &'static str,
    name: String,
    desc: String,
    counts: String,
}

impl LoadoutRow {
    /// Build a row from a discovered [`LoadoutEntry`]. Failures
    /// collapse into a single "(error: …)" cell in the counts
    /// column so the layout stays uniform across the whole listing.
    fn from_entry(
        entry: &sessions::client::disk::LoadoutEntry,
        defaults: &std::collections::HashSet<String>,
    ) -> Self {
        let marker = if defaults.contains(&entry.file_stem) {
            "*"
        } else {
            " "
        };
        match &entry.loadout {
            Ok(l) => Self {
                marker,
                name: entry.file_stem.clone(),
                desc: l.description().unwrap_or("").to_string(),
                counts: format!(
                    "{} pkg / {} var / {} patch / {} hook",
                    l.packages().len(),
                    l.vars().len() + l.vars_lenient().len(),
                    l.patches().iter().count(),
                    l.lifecycle_hooks().len(),
                ),
            },
            Err(e) => Self {
                marker,
                name: entry.file_stem.clone(),
                desc: String::new(),
                // Uses `entry.path` for a full-path prefix so a user
                // running with a `--dir` override (or with symlinks
                // in the tree) can trace which physical file is
                // broken even if two entries share a `file_stem`.
                counts: format!("(error at {}: {e})", entry.path.display()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LoadoutSelection::from_flags` — full truth table.
    #[test]
    fn loadout_selection_from_flags_truth_table() {
        assert!(matches!(
            LoadoutSelection::from_flags(&[], true),
            LoadoutSelection::None
        ));
        assert!(matches!(
            LoadoutSelection::from_flags(&[], false),
            LoadoutSelection::Defaults
        ));
        let cli = ["helix".to_string(), "fish".to_string()];
        match LoadoutSelection::from_flags(&cli, false) {
            LoadoutSelection::Cli(names) => assert_eq!(names, cli),
            other => panic!("expected Cli, got {other:?}"),
        }
    }

    /// `resolve_active_loadouts` on `LoadoutSelection::None` returns
    /// an empty vec without touching the filesystem. Uses a bogus
    /// config-dir override so a stray disk read would surface as a
    /// panic-shaped failure.
    #[test]
    fn resolve_active_loadouts_none_short_circuits() {
        let cfg = sessions::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(PathBuf::from("/definitely/does/not/exist")),
            minvmd: false,
        };
        let out = resolve_active_loadouts(LoadoutSelection::None, &cfg, &global)
            .expect("None → Ok(empty), no I/O");
        assert!(out.is_empty());
    }

    /// `resolve_active_loadouts` errors when a `--loadout NAME`
    /// selection names a file that isn't on disk. The concrete
    /// error goes to stderr via the closure; here we only assert
    /// the Result is Err.
    #[test]
    fn resolve_active_loadouts_cli_missing_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("minimal/loadouts")).unwrap();
        let cfg = sessions::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            minvmd: false,
        };
        let selection = LoadoutSelection::Cli(vec!["missing".to_string()]);
        assert!(resolve_active_loadouts(selection, &cfg, &global).is_err());
    }
}
