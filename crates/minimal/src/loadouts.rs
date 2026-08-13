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

/// Filename stem and `name` of the built-in `default` loadout.
const BUILTIN_DEFAULT_NAME: &str = "default";

/// The built-in `default` loadout, as inline TOML: a once-only
/// orientation banner and a shaped prompt, and nothing else — no
/// packages. It backs a zero-config box so a fresh install comes up
/// with the minimal mark and a pointer to `min add`, instead of a
/// bare prompt.
///
/// The banner ships through the attach shell's environment via the
/// documented MOTD recipe (see `docs/reference/loadouts.md`, "Vars in
/// the attach shell"): `PROMPT_COMMAND` evaluates the `MINIMAL_MOTD`
/// payload once and then unsets both vars, so it prints exactly once
/// and never for non-interactive commands; the `[ -t 1 ]` guard keeps
/// redirected output clean and the plain text renders under `NO_COLOR`.
///
/// The MOTD is a STATIC template: after the mark it prints the same
/// orientation lines the launcher-baseline banner prints — the session
/// name, the active loadout list, the detach chord, and a `min init`
/// pointer when the session workspace has no blueprint — by
/// interpolating `$MINIMAL_SESSION_NAME` (seeded by the daemon's
/// launcher baseline) and `$MINIMAL_LOADOUTS` (contributed by the
/// client alongside this loadout) in-shell at print time; both carry a
/// `${VAR:-fallback}` so a missing var still renders sanely. The
/// blueprint clause is a SESSION-filesystem fact, so it is tested
/// in-shell against the workspace root when the banner prints — both
/// mfile layouts, `minimal.toml` and `.minimal/minimal.toml` — which
/// stays correct across skipped uploads, an in-session `min init`, and
/// attaches from unrelated host directories. `/workbench` mirrors
/// `sandbox2::SESSION_DEFAULT_WD`, the attach shell's initial cwd (a
/// literal here because this client crate doesn't depend on the sandbox
/// crate; the daemon-side template derives it from the constant).
const BUILTIN_DEFAULT_TOML: &str = r#"
name = "default"
description = "orientation banner and shaped prompt"

[vars]
PROMPT_COMMAND = 'eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD'
PS1 = 'minimal:\w\$ '
MINIMAL_MOTD = '''
[ -t 1 ] && { printf '\n     ████  ████▄\n  ▄▄▄ ▀███▄ ▀███▄\n  ▀███  ▀███  ▀███\n\n'; printf '  minimal · session %s · loadout %s\n  detach: ctrl-w' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-default (built-in)}"; [ -f /workbench/minimal.toml ] || [ -f /workbench/.minimal/minimal.toml ] || printf ' · no minimal.toml here — min init to add one'; printf '\n\n  Add tools to this box:   min add --session <pkg>\n  Search the registry:     min search <query>\n\n'; }
'''
"#;

/// Parse [`BUILTIN_DEFAULT_TOML`] into a [`Loadout`]. The TOML is a
/// compile-time constant exercised by a unit test, so a parse failure
/// is a bug in this file rather than a runtime condition.
///
/// [`Loadout`]: sessions::core::loadout::Loadout
fn builtin_default_loadout() -> sessions::core::loadout::Loadout {
    toml::from_str(BUILTIN_DEFAULT_TOML).expect("built-in default loadout TOML must parse")
}

/// The loadouts resolved for a session activation, plus how the
/// zero-config fallback resolved — the display list interpolated into
/// the orientation banner tags the built-in `default` distinctly.
#[derive(Debug)]
pub(crate) struct ActiveLoadouts {
    /// The loadouts to compose, in application order.
    pub(crate) loadouts: Vec<sessions::core::loadout::Loadout>,
    /// True when the zero-config fallback used the built-in `default`
    /// loadout (as opposed to user files, including a shadowing user
    /// `default.toml`).
    pub(crate) builtin_default: bool,
}

/// Resolve the loadout names to apply for a session activation
/// and load each from disk.
///
/// Errors out on any missing or malformed loadout so the user
/// doesn't get a silently-empty session when their config is
/// broken.
///
/// With no flags and an empty `default_loadouts`, falls back to the
/// built-in [`builtin_default_loadout`] so a zero-config box is
/// oriented rather than bare; a user `default.toml` on disk shadows
/// the built-in.
pub(crate) fn resolve_active_loadouts(
    selection: LoadoutSelection,
    cfg: &sessions::client::config::Config,
    global: &GlobalArgs,
) -> Result<ActiveLoadouts, anyhow::Error> {
    let loadouts_dir = resolve_minimal_config_dir(global).join("loadouts");
    let (names, source): (Vec<String>, &str) = match selection {
        LoadoutSelection::None => {
            return Ok(ActiveLoadouts {
                loadouts: Vec::new(),
                builtin_default: false,
            });
        }
        LoadoutSelection::Cli(names) => (names, "--loadout"),
        LoadoutSelection::Defaults => {
            let configured = cfg.loadouts.default_loadouts.clone();
            if configured.is_empty() {
                // Zero-config: no flags and no configured defaults.
                // Fall back to the built-in `default` loadout unless
                // the user shadows it with their own `default.toml`,
                // in which case that file is loaded instead.
                if !loadouts_dir.join("default.toml").exists() {
                    return Ok(ActiveLoadouts {
                        loadouts: vec![builtin_default_loadout()],
                        builtin_default: true,
                    });
                }
                (vec![BUILTIN_DEFAULT_NAME.to_string()], "default_loadouts")
            } else {
                (configured, "default_loadouts")
            }
        }
    };
    let loadouts = names
        .iter()
        .map(|name| {
            let path = loadouts_dir.join(format!("{name}.toml"));
            // `LoadError`'s Display already embeds its I/O source, so flatten
            // it to a leaf before adding context; otherwise anyhow re-renders
            // the underlying error a second time from the chain.
            sessions::client::disk::read_loadout_file(&path)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("{source} `{name}`"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ActiveLoadouts {
        loadouts,
        builtin_default: false,
    })
}

/// Human-readable list of the active loadouts, as interpolated into the
/// orientation banner via `$MINIMAL_LOADOUTS`: comma-joined names,
/// `default (built-in)` for the zero-config fallback, `none` when no
/// loadout applies.
pub(crate) fn loadout_display_list(active: &ActiveLoadouts) -> String {
    if active.builtin_default {
        return format!("{BUILTIN_DEFAULT_NAME} (built-in)");
    }
    if active.loadouts.is_empty() {
        return "none".to_string();
    }
    active
        .loadouts
        .iter()
        .map(|l| l.name().as_ref())
        .collect::<Vec<_>>()
        .join(", ")
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

/// Resolve and validate every external hook script the active loadouts
/// declare, ready to upload.
///
/// Run before the daemon connection is opened so a mistyped script path
/// fails on this machine, naming the file, instead of surfacing after a
/// session already exists on the daemon.
///
/// Only *loadout* scripts are staged here. A project's external scripts
/// live in the project tree, which the daemon already has from the
/// workspace upload, so it resolves those itself —
/// [`check_project_hooks`] validates them without staging them.
///
/// Returns an empty list when hooks are disabled — `--no-hooks` means
/// nothing is staged, uploaded, or run.
pub(crate) fn stage_loadout_hook_scripts(
    active: &ActiveLoadouts,
    global: &GlobalArgs,
    project_root: &camino::Utf8Path,
    hooks_enabled: bool,
) -> Result<Vec<sessions::client::hookscripts::StagedScript>, anyhow::Error> {
    use sessions::client::hookscripts::{ScriptAnchors, stage_external_scripts};
    use sessions::core::source::{ProvenancedHook, Source};

    if !hooks_enabled {
        return Ok(Vec::new());
    }
    let loadouts_dir =
        camino::Utf8PathBuf::from_path_buf(resolve_minimal_config_dir(global).join("loadouts"))
            .map_err(|p| {
                anyhow::anyhow!("loadouts directory is not valid UTF-8: {}", p.display())
            })?;

    let hooks: Vec<ProvenancedHook> = active
        .loadouts
        .iter()
        .flat_map(|l| {
            let source = Source::UserLoadout {
                name: l.name().as_ref().to_owned(),
            };
            l.lifecycle_hooks()
                .iter()
                .map(move |h| ProvenancedHook::new(h.clone(), source.clone()))
        })
        .collect();

    let anchors = ScriptAnchors {
        loadouts_dir,
        project_root: project_root.to_owned(),
    };
    stage_external_scripts(&hooks, &anchors).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Validate the hooks a project declares, before a session exists.
///
/// The daemon composes these from the uploaded mfile, so nothing here is
/// staged or sent — but every reason a hook would fail later is knowable
/// now, on the machine that owns the file:
///
/// - an **external** script that is missing, is not a regular file, or
///   traverses a symlink. The daemon would surface this only when the
///   hook ran, which for `on_destroy` is at teardown, long after the
///   mistake.
/// - an **inline** script that is empty, which can only ever be a typo:
///   it declares a transition and then does nothing at it.
///
/// A project with no mfile, or one that does not parse, is not this
/// function's problem — the activation has its own handling for both, and
/// duplicating it here would report the same fault twice.
pub(crate) fn check_project_hooks(project_root: &camino::Utf8Path) -> Result<(), anyhow::Error> {
    use sessions::client::hookscripts::{ScriptAnchors, stage_external_scripts};
    use sessions::core::lifecyclehook::{HookScript, HookScriptBody};
    use sessions::core::source::{ProvenancedHook, Source};

    let Ok(mfile) = mfile::File::from_dir(project_root.as_std_path()) else {
        return Ok(());
    };
    let Some(session) = mfile.session.as_ref() else {
        return Ok(());
    };
    let hooks = &session.lifecycle_hooks;
    if hooks.is_empty() {
        return Ok(());
    }

    for hook in hooks {
        let scripts = [
            ("on_activate", hook.on_activate()),
            ("on_destroy", hook.on_destroy()),
            ("on_attach", hook.on_attach()),
            ("on_detach", hook.on_detach()),
        ];
        for (event, script) in scripts {
            let Some(HookScriptBody::Inline(body)) = script.map(HookScript::body) else {
                continue;
            };
            if body.trim().is_empty() {
                anyhow::bail!(
                    "the project's `{event}` lifecycle hook has an empty inline script \
                     (in {}/minimal.toml)",
                    project_root,
                );
            }
        }
    }

    // Resolved against the project root, the same anchor the daemon uses.
    // The loadouts dir is irrelevant here and is never consulted, since
    // every hook is tagged `Project`.
    let provenanced: Vec<ProvenancedHook> = hooks
        .iter()
        .map(|h| {
            ProvenancedHook::new(
                h.clone(),
                Source::Project {
                    path: paths::HostPath::try_new(project_root.as_str())
                        .expect("an activation's project path is a valid host path"),
                },
            )
        })
        .collect();
    let anchors = ScriptAnchors {
        loadouts_dir: project_root.to_owned(),
        project_root: project_root.to_owned(),
    };
    stage_external_scripts(&provenanced, &anchors).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Compose the resolved [`ActiveLoadouts`] into a
/// [`sessions::wire::request::WireContribution`] under the user's
/// [`UserPolicy`] loaded from `user_policy.toml`. User-origin items
/// auto-pass the allow step but the policy's `deny` / `ignore` rules
/// still apply, so a loadout patch matching a deny rule fails the
/// composition here rather than at the daemon.
///
/// The contribution also carries the first-prompt orientation as a
/// first-class field (never a var): the loadout display list computed
/// via [`loadout_display_list`], which the daemon seeds into the banner
/// env (`MINIMAL_LOADOUTS`) in the launcher baseline.
///
/// Returns the possibly-mutated policy alongside the wire
/// contribution — a hook (interactive prompt) may have appended
/// allow/ignore/deny rules and the caller wants to persist them.
///
/// [`UserPolicy`]: sessions::core::policy::UserPolicy
pub(crate) fn compose_user_contribution(
    active: ActiveLoadouts,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
    hooks_enabled: bool,
) -> Result<
    (
        sessions::wire::request::WireContribution,
        sessions::core::policy::UserPolicy,
    ),
    anyhow::Error,
> {
    let loadouts_display = loadout_display_list(&active);
    // `--no-hooks` strips the loadouts' transition scripts here, before
    // they reach the composer, rather than filtering them out after
    // composition: a hook the user opted out of then never participates
    // in composition, never rides the wire, and has no script staged for
    // it. The daemon applies the same flag to the project's hooks, and
    // the session record carries it for the later transitions.
    let loadouts: Vec<_> = if hooks_enabled {
        active.loadouts
    } else {
        active
            .loadouts
            .into_iter()
            .map(sessions::core::loadout::Loadout::without_lifecycle_hooks)
            .collect()
    };

    let mut composer = sessions::client::composer::UserComposer::new()
        .with_orientation(sessions::core::compose::Orientation { loadouts_display });
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
/// parseable `.toml` file; files that fail to parse are reported on
/// stderr and make the command exit non-zero, leaving the table of
/// valid loadouts intact. Loadouts named in
/// `[loadouts].default_loadouts` in the client config are marked
/// with a leading `*`.
pub fn cmd_loadout_list(args: LoadoutListArgs, global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let dir = resolve_loadouts_dir(&args, global);
    let entries = match sessions::client::disk::list_loadouts(&dir) {
        Ok(entries) => entries,
        // A missing directory is the fresh-install case: there are no
        // user loadouts yet, but the built-in `default` row below still
        // orients the user. Note where to add their own and continue.
        Err(sessions::client::disk::ListError::NotFound { path }) => {
            eprintln!(
                "No loadouts directory at {} yet — drop `<name>.toml` files there to add your own.",
                path.display()
            );
            Vec::new()
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

    // The built-in `default` loadout is always available, so it gets a
    // row unless the user has shadowed it with their own `default.toml`.
    let show_builtin = !present.contains(BUILTIN_DEFAULT_NAME);

    // Partition discovered entries: parsed loadouts become table rows,
    // while parse failures go to stderr and force a non-zero exit so a
    // script running `loadout list` can detect a broken file. Keeping
    // failures out of the table also preserves the layout their
    // multi-line parse errors would otherwise corrupt.
    let mut rows: Vec<LoadoutRow> = Vec::with_capacity(entries.len());
    let mut failures = 0usize;
    for entry in &entries {
        match &entry.loadout {
            Ok(loadout) => rows.push(LoadoutRow::from_entry(entry, loadout, &defaults)),
            Err(e) => {
                // `LoadError`'s Display already names the file, so the
                // path is not repeated here.
                eprintln!("{e}");
                failures += 1;
            }
        }
    }
    if show_builtin {
        rows.push(LoadoutRow::builtin_default());
    }

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
    if show_builtin {
        println!();
        println!("  default (built-in) applied when no loadouts are configured");
    }
    if !defaults.is_empty() {
        println!();
        println!("* default (from `[loadouts].default_loadouts`)");
    }
    if failures > 0 {
        bail!(
            "{failures} loadout file{} failed to parse",
            if failures == 1 { "" } else { "s" }
        );
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
    /// Build a row from a successfully parsed loadout. Parse failures
    /// never reach here — the caller reports them on stderr and keeps
    /// them out of the table (see [`cmd_loadout_list`]).
    fn from_entry(
        entry: &sessions::client::disk::LoadoutEntry,
        loadout: &sessions::core::loadout::Loadout,
        defaults: &std::collections::HashSet<String>,
    ) -> Self {
        let marker = if defaults.contains(&entry.file_stem) {
            "*"
        } else {
            " "
        };
        Self {
            marker,
            name: entry.file_stem.clone(),
            desc: loadout.description().unwrap_or("").to_string(),
            counts: format!(
                "{} pkg / {} var / {} patch",
                loadout.packages().len(),
                loadout.vars().len() + loadout.vars_lenient().len(),
                loadout.patches().iter().count(),
            ),
        }
    }

    /// Row for the built-in `default` loadout. Its name column carries
    /// the `(built-in)` tag so the listing distinguishes it from a
    /// user file of the same stem.
    fn builtin_default() -> Self {
        let l = builtin_default_loadout();
        Self {
            marker: " ",
            name: format!("{BUILTIN_DEFAULT_NAME} (built-in)"),
            desc: l.description().unwrap_or("").to_string(),
            counts: format!(
                "{} pkg / {} var / {} patch",
                l.packages().len(),
                l.vars().len() + l.vars_lenient().len(),
                l.patches().iter().count(),
            ),
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
            provider: None,
            no_input: false,
        };
        let out = resolve_active_loadouts(LoadoutSelection::None, &cfg, &global)
            .expect("None → Ok(empty), no I/O");
        assert!(out.loadouts.is_empty());
        assert!(!out.builtin_default);
        assert_eq!(loadout_display_list(&out), "none");
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
            provider: None,
            no_input: false,
        };
        let selection = LoadoutSelection::Cli(vec!["missing".to_string()]);
        assert!(resolve_active_loadouts(selection, &cfg, &global).is_err());
    }

    /// The `--loadout NAME` missing-file error names the underlying OS failure
    /// exactly once. `LoadError`'s Display already embeds its source, so the
    /// context chain must not re-render it (see the flatten in
    /// [`resolve_active_loadouts`]).
    #[test]
    fn resolve_active_loadouts_cli_missing_file_error_not_doubled() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        let cfg = sessions::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
        };
        let selection = LoadoutSelection::Cli(vec!["missing".to_string()]);
        let err = resolve_active_loadouts(selection, &cfg, &global)
            .expect_err("a missing --loadout file must error");
        let rendered = format!("{err:#}");
        // The concrete OS-error text is platform-dependent, so derive it from
        // the same failing read and assert it appears once, not twice.
        let needle = std::fs::read_to_string(loadouts.join("missing.toml"))
            .expect_err("the loadout file must be absent")
            .to_string();
        assert_eq!(
            rendered.matches(&needle).count(),
            1,
            "OS error should appear once in `{rendered}`",
        );
    }

    /// A loadout that declares a session transition script contributes
    /// it, alongside its other items.
    ///
    /// This inverts what the test asserted while hooks were gated off:
    /// the hook used to be stripped unconditionally before composition,
    /// and now rides the contribution unless `--no-hooks` is given (see
    /// [`no_hooks_strips_loadout_hooks_from_the_contribution`] for the
    /// opt-out direction).
    #[test]
    fn loadout_lifecycle_hook_composes_alongside_other_items() {
        let loadout: sessions::core::loadout::Loadout = toml::from_str(
            r#"
name = "dev"
packages = ["helix"]

[vars]
EDITOR = "hx"

[[lifecycle_hooks]]
on_activate = { type = "inline", value = "echo activated" }
"#,
        )
        .expect("loadout parses");
        // Sanity: the hook really is present on the loadout we feed in.
        assert_eq!(loadout.lifecycle_hooks().len(), 1);

        let (wire, _policy) = compose_user_contribution(
            ActiveLoadouts {
                loadouts: vec![loadout],
                builtin_default: false,
            },
            sessions::core::policy::UserPolicy::empty(),
            sessions::core::compose::ComposeOptions::default(),
            true,
        )
        .expect("composition succeeds with the declared hook");

        // The declared hook rides the contribution...
        assert_eq!(
            wire.lifecycle_hooks.len(),
            1,
            "declared lifecycle hook must reach the contribution"
        );
        // ...while the loadout's other items compose normally.
        assert_eq!(wire.requested_packages.len(), 1);
        assert_eq!(wire.vars.len(), 1);
        // The orientation rides as a first-class field, never a var.
        assert_eq!(wire.orientation.loadouts_display, "dev");
    }

    /// The built-in `default` loadout parses (guarding the `expect` in
    /// [`builtin_default_loadout`]) and has the shape the banner
    /// feature promises: no packages, no lifecycle hooks, and the three
    /// MOTD/prompt vars — no task or run-target lines.
    #[test]
    fn builtin_default_loadout_has_banner_shape() {
        let l = builtin_default_loadout();
        assert_eq!(l.name().as_ref(), BUILTIN_DEFAULT_NAME);
        assert!(
            l.packages().is_empty(),
            "built-in default contributes no packages"
        );
        assert!(l.lifecycle_hooks().is_empty());
        assert!(l.patches().is_empty());

        let vars: Vec<String> = l.all_vars().map(|(n, _)| n.as_str().to_owned()).collect();
        assert_eq!(vars.len(), 3);
        assert!(vars.iter().any(|n| n == "PROMPT_COMMAND"));
        assert!(vars.iter().any(|n| n == "MINIMAL_MOTD"));
        assert!(vars.iter().any(|n| n == "PS1"));

        // The MOTD carries the orientation lines as a static template:
        // the dynamic parts are `${MINIMAL_*:-fallback}` interpolations
        // the shell resolves at print time (the mark and the `min add`
        // pointers stay verbatim).
        let motd = l
            .all_vars()
            .find(|(n, _)| n.as_str() == "MINIMAL_MOTD")
            .map(|(_, v)| match v {
                sessions::core::primitives::VarValue::Specified { value } => value.clone(),
                other => panic!("MINIMAL_MOTD must be a literal value, got {other:?}"),
            })
            .expect("MINIMAL_MOTD present");
        assert!(motd.contains("████"), "the mark stays");
        assert!(motd.contains("min add --session"), "the pointers stay");
        assert!(motd.contains("${MINIMAL_SESSION_NAME:-"));
        assert!(motd.contains("${MINIMAL_LOADOUTS:-"));
        // The blueprint clause tests the session workspace itself at
        // print time — both mfile layouts — never a client-probed var.
        assert!(motd.contains("[ -f /workbench/minimal.toml ]"));
        assert!(motd.contains("[ -f /workbench/.minimal/minimal.toml ]"));
        assert!(
            !motd.contains("MINIMAL_BLUEPRINT"),
            "blueprint is a session-filesystem fact, not an env var"
        );
        assert!(motd.contains("detach: ctrl-w"));
        assert!(motd.contains("min init"));
    }

    /// The display list interpolated into the banner: comma-joined names
    /// for user loadouts, `none` for an empty set (the built-in and
    /// shadow cases are asserted in the resolution tests above).
    #[test]
    fn loadout_display_list_joins_names() {
        let mk = |name: &str| -> sessions::core::loadout::Loadout {
            toml::from_str(&format!("name = \"{name}\"\n")).expect("loadout parses")
        };
        let active = ActiveLoadouts {
            loadouts: vec![mk("helix"), mk("fish")],
            builtin_default: false,
        };
        assert_eq!(loadout_display_list(&active), "helix, fish");
    }

    /// The composed contribution carries the loadout display list as a
    /// first-class orientation field — never a var, so user vars and
    /// user policy cannot collide with it. (No blueprint field either:
    /// that is a session-filesystem fact the banner templates test
    /// in-shell at print time.)
    #[test]
    fn compose_carries_orientation_as_field_not_var() {
        let (wire, _policy) = compose_user_contribution(
            ActiveLoadouts {
                loadouts: Vec::new(),
                builtin_default: true,
            },
            sessions::core::policy::UserPolicy::empty(),
            sessions::core::compose::ComposeOptions::default(),
            true,
        )
        .expect("empty composition succeeds");
        assert_eq!(wire.orientation.loadouts_display, "default (built-in)");
        assert!(
            wire.vars.iter().all(|v| v.var.name != "MINIMAL_LOADOUTS"),
            "orientation must not ride the var lane"
        );
    }

    /// Zero-config resolution — no flags, empty `default_loadouts`, no
    /// user `default.toml` — falls back to the built-in `default`
    /// loadout instead of returning an empty vec.
    #[test]
    fn resolve_active_loadouts_defaults_falls_back_to_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("minimal/loadouts")).unwrap();
        let cfg = sessions::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
        };
        let out = resolve_active_loadouts(LoadoutSelection::Defaults, &cfg, &global)
            .expect("built-in fallback resolves");
        assert_eq!(out.loadouts.len(), 1);
        assert_eq!(out.loadouts[0].name().as_ref(), BUILTIN_DEFAULT_NAME);
        assert!(out.loadouts[0].packages().is_empty());
        assert!(out.builtin_default);
        assert_eq!(loadout_display_list(&out), "default (built-in)");
    }

    /// A user `default.toml` on disk shadows the built-in: zero-config
    /// resolution loads the user's file instead of the built-in.
    #[test]
    fn resolve_active_loadouts_user_default_shadows_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        std::fs::write(
            loadouts.join("default.toml"),
            "name = \"default\"\ndescription = \"user override\"\n",
        )
        .unwrap();
        let cfg = sessions::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
        };
        let out = resolve_active_loadouts(LoadoutSelection::Defaults, &cfg, &global)
            .expect("user default resolves");
        assert_eq!(out.loadouts.len(), 1);
        assert_eq!(out.loadouts[0].description(), Some("user override"));
        // A user shadow is NOT the built-in — the banner's loadout list
        // must not tag it `(built-in)`.
        assert!(!out.builtin_default);
        assert_eq!(loadout_display_list(&out), "default");
    }

    /// The built-in listing row carries the `(built-in)` tag and a
    /// zero-package contributes cell.
    #[test]
    fn builtin_default_row_is_tagged_and_packageless() {
        let row = LoadoutRow::builtin_default();
        assert_eq!(row.name, format!("{BUILTIN_DEFAULT_NAME} (built-in)"));
        assert_eq!(row.marker, " ");
        assert!(row.counts.starts_with("0 pkg"), "got: {}", row.counts);
    }

    /// A malformed loadout file makes `cmd_loadout_list` exit non-zero
    /// instead of silently returning `Ok`, so a script can detect the
    /// broken file. The parse error is surfaced on stderr, not folded
    /// into the table.
    #[test]
    fn cmd_loadout_list_errors_on_malformed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        // Valid TOML but missing the required `name` field → parse failure.
        std::fs::write(loadouts.join("broken.toml"), "x = 1\n").unwrap();
        let args = LoadoutListArgs {
            dir: Some(loadouts),
        };
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
        };
        assert!(cmd_loadout_list(args, &global).is_err());
    }

    /// A loadout carrying a hook contributes it when hooks are on and
    /// contributes nothing when `--no-hooks` turns them off.
    ///
    /// The off case is the one that matters: the hook must be absent
    /// from the *wire contribution*, not merely skipped at run time, so
    /// that a hook the user opted out of is never shipped to the daemon
    /// and never has a script staged for it.
    #[test]
    fn no_hooks_strips_loadout_hooks_from_the_contribution() {
        use sessions::core::lifecyclehook::{HookScript, LifecycleHook};
        use sessions::core::loadout::{Loadout, LoadoutName};

        let build = |hooks_enabled: bool| {
            let loadout = Loadout::new(LoadoutName::try_new("dev").unwrap()).with_lifecycle_hook(
                LifecycleHook::builder()
                    .with_on_activate(HookScript::inline("echo hi"))
                    .build()
                    .unwrap(),
            );
            let active = ActiveLoadouts {
                loadouts: vec![loadout],
                builtin_default: false,
            };
            let (contribution, _) = compose_user_contribution(
                active,
                sessions::core::policy::UserPolicy::empty(),
                sessions::core::compose::ComposeOptions::default(),
                hooks_enabled,
            )
            .expect("composing a hook-only loadout");
            contribution.lifecycle_hooks.len()
        };

        assert_eq!(build(true), 1, "hooks on: the loadout's hook composes in");
        assert_eq!(build(false), 0, "--no-hooks: nothing reaches the wire");
    }
}
