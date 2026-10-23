//! Loadout selection, composition, and the `minimal loadout list`
//! command. Backed by the on-disk primitives in
//! [`boxes::client::disk`] and driven from the client `config.toml`
//! (see [`crate::config`]).

use anyhow::{Context as _, bail};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::resolve_minimal_config_dir;
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

/// The trusted loadouts directory's name under `<config>/minimal/`.
/// Loadouts here are the user's own: their items auto-pass the user
/// policy's `allow` step.
pub(crate) const LOADOUTS_DIR_NAME: &str = "loadouts";

/// The untrusted loadouts directory's name under `<config>/minimal/`,
/// beside [`LOADOUTS_DIR_NAME`]. Loadouts here work the same way in
/// every respect but one: the user policy gates them like a project, so
/// their vars, patches, and lifecycle hooks must be allow-listed or
/// approved at a prompt.
pub(crate) const UNTRUSTED_LOADOUTS_DIR_NAME: &str = "loadouts-untrusted";

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
/// `sandbox::SESSION_DEFAULT_WD`, the attach shell's initial cwd (a
/// literal here because this client crate doesn't depend on the sandbox
/// crate; the daemon-side template derives it from the constant).
const BUILTIN_DEFAULT_TOML: &str = r#"
name = "default"
description = "orientation banner and shaped prompt"

[vars]
PROMPT_COMMAND = 'eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD'
PS1 = 'minimal:\w\$ '
MINIMAL_MOTD = '''
[ -t 1 ] && { printf '\n     ████  ████▄\n  ▄▄▄ ▀███▄ ▀███▄\n  ▀███  ▀███  ▀███\n\n'; printf '  minimal · session %s · loadout %s\n  detach: %s' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-default (built-in)}" "${MINIMAL_DETACH_HINT:-ctrl-] then d}"; [ -f /workbench/minimal.toml ] || [ -f /workbench/.minimal/minimal.toml ] || printf ' · no minimal.toml here — min init to add one'; printf '\n\n  Add tools to this box:   min add --session <pkg>\n  Search the registry:     min search <query>\n\n'; }
'''
"#;

/// Parse [`BUILTIN_DEFAULT_TOML`] into a [`Loadout`]. The TOML is a
/// compile-time constant exercised by a unit test, so a parse failure
/// is a bug in this file rather than a runtime condition.
///
/// [`Loadout`]: boxes::core::loadout::Loadout
fn builtin_default_loadout() -> boxes::core::loadout::Loadout {
    toml::from_str(BUILTIN_DEFAULT_TOML).expect("built-in default loadout TOML must parse")
}

/// The loadouts resolved for a session activation, plus how the
/// zero-config fallback resolved — the display list interpolated into
/// the orientation banner tags the built-in `default` distinctly.
#[derive(Debug)]
pub(crate) struct ActiveLoadouts {
    /// The loadouts to compose, in application order.
    pub(crate) loadouts: Vec<boxes::core::loadout::Loadout>,
    /// The directory these loadouts were read from — whatever
    /// `--config-dir` / `$XDG_CONFIG_HOME` resolved to for this run.
    ///
    /// Travels with the loadouts rather than being recomputed by each
    /// consumer, so everything anchored at a loadout's own directory
    /// (`<dir>/<name>/`) — its external hook scripts, and
    /// `$LOADOUT_ROOT` in its patch sources — resolves against the
    /// directory the files actually came from.
    ///
    /// The trusted directory. An untrusted loadout carries its own
    /// directory (see [`Loadout::untrusted`]), so this one anchors only
    /// trusted loadouts.
    ///
    /// [`Loadout::untrusted`]: boxes::core::loadout::Loadout::untrusted
    pub(crate) loadouts_dir: paths::HostAbsPath,
    /// True when the zero-config fallback used the built-in `default`
    /// loadout (as opposed to user files, including a shadowing user
    /// `default` loadout of their own).
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
/// oriented rather than bare; a user `default` loadout on disk — in
/// either layout, in either directory — shadows the built-in.
///
/// Every name is looked up in both the trusted and the untrusted
/// loadouts directory (see [`load_named_loadout`]); one found in the
/// untrusted directory comes back marked
/// [untrusted](boxes::core::loadout::Loadout::untrusted).
pub(crate) fn resolve_active_loadouts(
    selection: LoadoutSelection,
    cfg: &boxes::client::config::Config,
    global: &GlobalArgs,
) -> Result<ActiveLoadouts, anyhow::Error> {
    let loadouts_dir = resolve_loadouts_dir_for_activation(global, LOADOUTS_DIR_NAME)?;
    let untrusted_loadouts_dir =
        resolve_loadouts_dir_for_activation(global, UNTRUSTED_LOADOUTS_DIR_NAME)?;
    let (names, source): (Vec<String>, &str) = match selection {
        LoadoutSelection::None => {
            return Ok(ActiveLoadouts {
                loadouts: Vec::new(),
                loadouts_dir,
                builtin_default: false,
            });
        }
        LoadoutSelection::Cli(names) => (names, "--loadout"),
        LoadoutSelection::Defaults => {
            let configured = cfg.loadouts.default_loadouts.clone();
            if configured.is_empty() {
                // Zero-config: no flags and no configured defaults.
                // Fall back to the built-in `default` loadout unless
                // the user shadows it with their own — in either
                // layout, `default.toml` or `default/loadout.toml`, and
                // in either directory — in which case that file is
                // loaded instead.
                //
                // Probed through the resolver rather than a bare
                // `exists()` so both layouts are found by one rule,
                // and so a `default` that exists but is broken
                // (malformed TOML, both layouts at once) is reported
                // as the error it is instead of being read as absence.
                if !user_default_exists(&loadouts_dir, &untrusted_loadouts_dir)? {
                    return Ok(ActiveLoadouts {
                        loadouts: vec![builtin_default_loadout()],
                        loadouts_dir,
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
            // Validate before the name reaches a path join. Without
            // this, `--loadout ../../evil` would be interpolated
            // straight into a filename and read an arbitrary `.toml`
            // off disk — the post-read stem check does not catch it,
            // since `file_stem("../../evil.toml")` is just `evil`.
            //
            // `LoadoutName`'s own error is the nutype-generated
            // "failed the predicate test", which tells the user
            // nothing about what a loadout name may contain — so the
            // rule is spelled out here instead.
            let name = boxes::core::loadout::LoadoutName::try_new(name)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "`{name}` is not a loadout name: names are the file or directory \
                         a loadout is filed under, so they cannot be empty, be `.` or \
                         `..`, or contain `/`, `\\`, or NUL"
                    )
                })
                .with_context(|| format!("{source} `{name}`"))?;
            load_named_loadout(&loadouts_dir, &untrusted_loadouts_dir, &name)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no loadout `{name}` in `{loadouts_dir}` or `{untrusted_loadouts_dir}` \
                         (looked for `{name}.toml` and `{name}/{}` in each)",
                        boxes::client::disk::LOADOUT_FILE_NAME,
                    )
                })
                .with_context(|| format!("{source} `{name}`"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ActiveLoadouts {
        loadouts,
        loadouts_dir,
        builtin_default: false,
    })
}

/// Load loadout `name` from whichever of the trusted and untrusted
/// loadouts directories defines it, marking it
/// [untrusted](boxes::core::loadout::Loadout::untrusted) when it came
/// from the untrusted one. `Ok(None)` when neither does.
///
/// A name defined in both is an error rather than resolved by
/// precedence, for the reason a name defined in both layouts is (see
/// [`boxes::client::disk`]): whichever copy lost would go on looking
/// live while having no effect — and here, which copy wins also decides
/// whether the user policy gates it.
///
/// # Errors
///
/// A loadout that exists but cannot load, or a name in both directories.
fn load_named_loadout(
    loadouts_dir: &paths::HostAbsPath,
    untrusted_loadouts_dir: &paths::HostAbsPath,
    name: &boxes::core::loadout::LoadoutName,
) -> Result<Option<boxes::core::loadout::Loadout>, anyhow::Error> {
    use boxes::client::disk::{LoadError, load_loadout};
    // `LoadError`'s Display already embeds its I/O source, so flatten
    // it to a leaf before the caller adds context; otherwise anyhow
    // re-renders the underlying error a second time from the chain.
    let probe =
        |dir: &paths::HostAbsPath| match load_loadout(dir.as_utf8_path().as_std_path(), name) {
            Ok((loadout, layout)) => Ok(Some((loadout, layout))),
            Err(LoadError::NotFound { .. }) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        };
    match (probe(loadouts_dir)?, probe(untrusted_loadouts_dir)?) {
        (None, None) => Ok(None),
        (Some((loadout, _)), None) => Ok(Some(loadout)),
        (None, Some((loadout, _))) => {
            // `name` is a single path component that stays put
            // (`LoadoutName`), so the join stays under the directory.
            let dir = untrusted_loadouts_dir.sub_path_unchecked(name.as_ref());
            Ok(Some(loadout.untrusted(dir)))
        }
        (Some((_, trusted)), Some((_, untrusted))) => bail!(
            "loadout `{name}` is defined in both loadouts directories:\n  {}\n  {}\n\
             remove one.",
            trusted
                .path_for(loadouts_dir.as_utf8_path().as_std_path(), name)
                .display(),
            untrusted
                .path_for(untrusted_loadouts_dir.as_utf8_path().as_std_path(), name)
                .display(),
        ),
    }
}

/// Whether the user has a `default` loadout of their own on disk, in
/// either layout and either directory — the probe behind the
/// zero-config fallback in [`resolve_active_loadouts`].
///
/// Absence is the normal answer here, so not finding one maps to
/// `Ok(false)`. Every error means the file is *there* and unusable (or
/// there twice), which the user wants told rather than silently
/// replaced by the built-in.
fn user_default_exists(
    loadouts_dir: &paths::HostAbsPath,
    untrusted_loadouts_dir: &paths::HostAbsPath,
) -> Result<bool, anyhow::Error> {
    let name = boxes::core::loadout::LoadoutName::try_new(BUILTIN_DEFAULT_NAME)
        .expect("the built-in default's name is a valid loadout name");
    load_named_loadout(loadouts_dir, untrusted_loadouts_dir, &name)
        .map(|found| found.is_some())
        .context("default_loadouts `default`")
}

/// A loadouts directory an activation reads from:
/// `<config>/minimal/<subdir>` — [`LOADOUTS_DIR_NAME`] or
/// [`UNTRUSTED_LOADOUTS_DIR_NAME`] — under whatever
/// [`resolve_minimal_config_dir`] resolved for this run.
///
/// UTF-8 is required rather than best-effort: the directory is joined
/// with a loadout's name to anchor that loadout's own files (hook
/// scripts, `$LOADOUT_ROOT` patch sources), and those anchors travel
/// through UTF-8 path types all the way to the daemon.
///
/// A **relative** `--config-dir` is anchored at the process working
/// directory rather than refused. Every other consumer of the flag
/// reads it straight off the CWD, so refusing one here would break
/// `--config-dir some/rel/dir` for every activation — including ones
/// that apply no loadouts at all — over an anchor those runs never use.
/// The join is lexical (no `canonicalize`): the directory need not
/// exist yet, and resolving symlinks here would quietly change which
/// path a loadout's hook scripts are checked against. One consequence:
/// a relative dir containing `..` stays unnormalized, so a loadout
/// under it that uses `$LOADOUT_ROOT` fails expansion, which rejects
/// `..` in any pattern.
fn resolve_loadouts_dir_for_activation(
    global: &GlobalArgs,
    subdir: &str,
) -> Result<paths::HostAbsPath, anyhow::Error> {
    let dir = resolve_minimal_config_dir(global).join(subdir);
    let utf8 = camino::Utf8PathBuf::from_path_buf(dir)
        .map_err(|p| anyhow::anyhow!("loadouts directory is not valid UTF-8: {}", p.display()))?;
    match paths::HostAbsPath::try_new(utf8) {
        Ok(abs) => Ok(abs),
        Err(paths::Error::NotAbsolute(rel)) => {
            let cwd = paths::HostAbsPath::from_cwd()
                .context("resolving a relative --config-dir against the working directory")?;
            paths::HostAbsPath::try_new(cwd.as_utf8_path().join(rel))
                .map_err(|e| anyhow::anyhow!("loadouts directory: {e}"))
        }
        Err(e) => Err(anyhow::anyhow!("loadouts directory: {e}")),
    }
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
/// [`ComposeOptions`]: boxes::core::compose::ComposeOptions
pub(crate) fn compose_options_from_config(
    cfg: &boxes::client::config::Config,
) -> boxes::core::compose::ComposeOptions {
    boxes::core::compose::ComposeOptions::default()
        .with_follow_symlinks(cfg.loadouts.follow_symlinks)
}

/// Resolve and validate every external hook script in the composed
/// loadout contribution, ready to upload.
///
/// Takes the *composed* hooks, not the active loadouts, so only hooks
/// that survived composition are staged: one `--no-hooks` stripped, or
/// one from an untrusted loadout the user policy ignored or the user
/// refused at the prompt, is never read from disk or uploaded, and a
/// missing script it names cannot fail the activation.
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
/// `loadouts_dir` is the trusted loadouts directory; an untrusted
/// loadout's hooks carry their own directory in their source.
pub(crate) fn stage_loadout_hook_scripts(
    composed: &[boxes::wire::primitives::WireProvenancedHook],
    loadouts_dir: &paths::HostAbsPath,
    project_root: &paths::HostAbsPath,
) -> Result<Vec<boxes::client::hookscripts::StagedScript>, anyhow::Error> {
    use boxes::client::hookscripts::{ScriptAnchors, stage_external_scripts};
    use boxes::core::source::ProvenancedHook;

    let hooks: Vec<ProvenancedHook> = composed
        .iter()
        .cloned()
        .map(ProvenancedHook::try_from)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("staging loadout hook scripts: {e}"))?;

    let anchors = ScriptAnchors {
        loadouts_dir: loadouts_dir.clone(),
        project_root: project_root.clone(),
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
pub(crate) fn check_project_hooks(project_root: &paths::HostAbsPath) -> Result<(), anyhow::Error> {
    use boxes::client::hookscripts::{ScriptAnchors, stage_external_scripts};
    use boxes::core::lifecyclehook::{HookScript, HookScriptBody};
    use boxes::core::source::{ProvenancedHook, Source};

    let Ok(mfile) = mfile::File::from_dir(project_root.as_utf8_path().as_std_path()) else {
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
                        .expect("an absolute host path is a valid host path"),
                },
            )
        })
        .collect();
    let anchors = ScriptAnchors {
        loadouts_dir: project_root.clone(),
        project_root: project_root.clone(),
    };
    stage_external_scripts(&provenanced, &anchors).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// The wall-clock the daemon may spend running `on_activate` hooks inside a
/// single `FinalizeSession`: the summed declared timeouts of every
/// activation hook the client can see — the composed loadout hooks' plus
/// the project's. Taken from the composition, so a loadout hook the user
/// policy dropped adds nothing. Setup hooks run sequentially and without
/// an aggregate budget on the daemon, so this sum bounds the round-trip,
/// and it is known before the call — which is what lets the
/// `FinalizeSession` deadline be sized to it so a hook declaring more than
/// the base oneshot timeout can still finish.
///
/// Zero when hooks are disabled or nothing declares an `on_activate`. The
/// project's `minimal.toml` is read the same way [`check_project_hooks`]
/// reads it; an unreadable or session-less file contributes nothing.
pub(crate) fn activate_hook_budget(
    composed: &[boxes::wire::primitives::WireProvenancedHook],
    project_root: &camino::Utf8Path,
    hooks_enabled: bool,
) -> Duration {
    if !hooks_enabled {
        return Duration::ZERO;
    }
    let loadout: Duration = composed
        .iter()
        .filter_map(|h| h.hook.on_activate.clone())
        .map(|s| boxes::core::lifecyclehook::HookScript::from(s).timeout())
        .sum();
    let project: Duration = mfile::File::from_dir(project_root.as_std_path())
        .ok()
        .and_then(|f| f.session)
        .map(|s| {
            s.lifecycle_hooks
                .iter()
                .filter_map(|h| h.on_activate())
                .map(|hs| hs.timeout())
                .sum::<Duration>()
        })
        .unwrap_or(Duration::ZERO);
    loadout + project
}

/// How [`compose_user_contribution_gated`] may ask the user about
/// untrusted loadout items the policy can't decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PromptLane {
    /// Prompt on the terminal; permanent choices are saved to
    /// `user_policy.toml`.
    Interactive,
    /// Never prompt: any undecided item fails the composition with a
    /// ready-to-paste `user_policy.toml` snippet.
    NoPrompt,
    /// `min dash`: refuse as [`Self::NoPrompt`] does, even on a terminal.
    /// The dashboard composes its loadouts once, at startup, and reuses
    /// the result for every session it creates, so an "allow once"
    /// answered here would silently cover all of them.
    Dashboard,
}

impl PromptLane {
    /// The lane for a run, given whether it was told not to prompt
    /// (`--no-prompt`, `--no-input`). A terminal that cannot be prompted
    /// on takes the no-prompt lane too.
    pub(crate) fn for_run(no_prompt: bool) -> Self {
        if no_prompt || !crate::can_prompt_interactively() {
            Self::NoPrompt
        } else {
            Self::Interactive
        }
    }
}

/// [`compose_user_contribution`], gating the items of any untrusted
/// loadout against the user policy the way a project's items are gated:
/// on the [`PromptLane::Interactive`] lane by prompting (and saving any
/// permanent choice to `policy_path`, even when the activation then
/// aborts), on the [`PromptLane::NoPrompt`] lane by failing with the
/// `user_policy.toml` snippet that would let it through.
///
/// With no untrusted loadout active nothing can need approval, so this
/// is exactly [`compose_user_contribution`].
///
/// Runs before the daemon is contacted, so a refusal here leaves nothing
/// behind on it.
///
/// # Errors
///
/// Any composition failure, an abort at the prompt, or — on the
/// no-prompt lane — any item that would have needed approval.
pub(crate) fn compose_user_contribution_gated(
    active: ActiveLoadouts,
    policy: boxes::core::policy::UserPolicy,
    options: boxes::core::compose::ComposeOptions,
    hooks_enabled: bool,
    lane: PromptLane,
    policy_path: &std::path::Path,
) -> Result<
    (
        boxes::wire::request::WireContribution,
        boxes::core::policy::UserPolicy,
    ),
    anyhow::Error,
> {
    if !active.loadouts.iter().any(|l| l.is_untrusted()) {
        return compose_user_contribution(active, policy, options, hooks_enabled, None);
    }
    match lane {
        PromptLane::NoPrompt | PromptLane::Dashboard => {
            // `NoPromptHook` fake-approves so every gate runs and the
            // snippet lists every edit at once. The contribution it
            // produces is discarded unless nothing was recorded, so a
            // fake approval never reaches the daemon.
            let hooks = crate::prompt::NoPromptHook::new();
            let composed =
                compose_user_contribution(active, policy, options, hooks_enabled, Some(&hooks));
            let summary = hooks.into_summary();
            if summary.count() > 0 {
                let count = summary.count();
                let (s, need) = if count == 1 {
                    ("", "needs")
                } else {
                    ("s", "need")
                };
                let why = match lane {
                    PromptLane::Dashboard => {
                        "min dash does not ask about them: it would apply one answer to every \
                         session it creates"
                    }
                    _ => {
                        "this run cannot ask (--no-prompt or --no-input was set, or \
                         stdin/stderr is not a terminal)"
                    }
                };
                let rerun = match lane {
                    PromptLane::Dashboard => {
                        "Then run `min dash` again, or run `min session activate` to be asked \
                         about each item."
                    }
                    _ => "Then re-run this command.",
                };
                bail!(
                    "{count} item{s} from untrusted loadouts {need} your approval, but {why}.\n\n\
                     Add the following to {}:\n\n{}\n{rerun}",
                    policy_path.display(),
                    summary.as_toml_snippet(),
                );
            }
            composed
        }
        PromptLane::Interactive => {
            let hooks = crate::prompt::InteractivePrompt::new(policy_path, policy.clone());
            compose_interactively(active, policy, options, hooks_enabled, hooks, policy_path)
        }
    }
}

/// The [`PromptLane::Interactive`] half of
/// [`compose_user_contribution_gated`], taking the prompt ready-built so
/// a test can script its answers. `hooks` must start from `policy`.
fn compose_interactively(
    active: ActiveLoadouts,
    policy: boxes::core::policy::UserPolicy,
    options: boxes::core::compose::ComposeOptions,
    hooks_enabled: bool,
    hooks: crate::prompt::InteractivePrompt,
    policy_path: &std::path::Path,
) -> Result<
    (
        boxes::wire::request::WireContribution,
        boxes::core::policy::UserPolicy,
    ),
    anyhow::Error,
> {
    let composed =
        compose_user_contribution(active, policy.clone(), options, hooks_enabled, Some(&hooks));
    // Saved before the result propagates: a `DenyPermanent` aborts the
    // composition and still wants its rule kept, and a save failure must
    // not mask the composition's own error.
    let final_policy = hooks.into_final_policy();
    if final_policy != policy {
        match crate::prompt::save_user_policy(policy_path, &final_policy) {
            Ok(()) => eprintln!("Updated {}", policy_path.display()),
            Err(e) => eprintln!("warning: failed to update {}: {e}", policy_path.display()),
        }
    }
    composed
}

/// Compose the resolved [`ActiveLoadouts`] into a
/// [`boxes::wire::request::WireContribution`] under the user's
/// [`UserPolicy`] loaded from `user_policy.toml`. Items from trusted
/// loadouts auto-pass the allow step but the policy's `deny` /
/// `ignore` rules still apply, so a loadout patch matching a deny rule
/// fails the composition here rather than at the daemon. Items from
/// untrusted loadouts must also match `allow`, or be decided by
/// `prompt` — without one, an undecided item fails the composition.
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
/// [`UserPolicy`]: boxes::core::policy::UserPolicy
pub(crate) fn compose_user_contribution(
    active: ActiveLoadouts,
    policy: boxes::core::policy::UserPolicy,
    options: boxes::core::compose::ComposeOptions,
    hooks_enabled: bool,
    prompt: Option<&dyn boxes::core::hooks::PolicyHooks>,
) -> Result<
    (
        boxes::wire::request::WireContribution,
        boxes::core::policy::UserPolicy,
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
            .map(boxes::core::loadout::Loadout::without_lifecycle_hooks)
            .collect()
    };

    let mut composer = boxes::client::composer::UserComposer::new()
        .with_orientation(boxes::core::compose::Orientation { loadouts_display })
        // Anchors `$LOADOUT_ROOT` in the loadouts' patch sources at the
        // directory they were read from, so a loadout can patch in files
        // shipped beside it without naming an absolute config path.
        .with_loadouts_dir(active.loadouts_dir);
    composer
        .add_all(loadouts)
        .map_err(|e| anyhow::anyhow!("composing loadouts: {e}"))?;
    match prompt {
        Some(hooks) => composer.compose_with_hooks(policy, options, hooks),
        None => composer.compose(policy, options),
    }
    .map_err(|e| anyhow::anyhow!("composing loadouts: {e}"))
}

// =========================================================================
// `minimal loadout list` — enumerate discovered loadouts.
// =========================================================================

/// Resolve the minimal config directory to list loadouts from: `--dir`
/// on the subcommand, else [`resolve_minimal_config_dir`]
/// (`--config-dir`, then the platform default). Its
/// [`LOADOUTS_DIR_NAME`] and [`UNTRUSTED_LOADOUTS_DIR_NAME`]
/// subdirectories give each loadout its trust, as they do at activation,
/// and its `config.toml` names the defaults.
fn resolve_list_config_dir(args: &LoadoutListArgs, global: &GlobalArgs) -> PathBuf {
    args.dir
        .clone()
        .unwrap_or_else(|| resolve_minimal_config_dir(global))
}

/// List loadouts discovered in the minimal config directory's two
/// loadouts directories — trusted and untrusted — in both layouts
/// (`<name>.toml` and `<name>/loadout.toml`). One row per parseable loadout, with an
/// untrusted one tagged `(untrusted)`; ones that fail to load — a parse
/// error, a name defined in both layouts at once, or a name defined in
/// both directories — are reported on stderr and make the command exit
/// non-zero, leaving the table of valid loadouts intact. Loadouts named
/// in `[loadouts].default_loadouts` in that directory's `config.toml`
/// are marked with a leading `*`.
pub fn cmd_loadout_list(args: LoadoutListArgs, global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let config_dir = resolve_list_config_dir(&args, global);
    let dirs = [
        (config_dir.join(LOADOUTS_DIR_NAME), false),
        (config_dir.join(UNTRUSTED_LOADOUTS_DIR_NAME), true),
    ];
    // Each entry paired with whether it came from the untrusted directory.
    let mut entries: Vec<(boxes::client::disk::LoadoutEntry, bool)> = Vec::new();
    for (dir, untrusted) in &dirs {
        match boxes::client::disk::list_loadouts(dir) {
            Ok(found) => entries.extend(found.into_iter().map(|e| (e, *untrusted))),
            // The untrusted directory is opt-in: most users never create
            // it, so its absence is not worth a line.
            Err(boxes::client::disk::ListError::NotFound { .. }) if *untrusted => {}
            // A missing trusted directory is the fresh-install case: there
            // are no user loadouts yet, but the built-in `default` row
            // below still orients the user. Note where to add their own
            // and continue.
            Err(boxes::client::disk::ListError::NotFound { path }) => {
                eprintln!(
                    "No loadouts directory at {} yet — add your own as `<name>.toml` \
                     there, or as `<name>/loadout.toml` to keep one under version control.",
                    path.display()
                );
            }
            Err(e) => bail!("{e}"),
        }
    }
    // A name in both directories cannot be applied (activation refuses
    // it), so neither copy gets a row: both are reported as one failure.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (entry, _) in &entries {
        *seen.entry(entry.name.clone()).or_default() += 1;
    }
    let mut both: Vec<String> = seen
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name)
        .collect();
    both.sort();
    for name in &both {
        let paths: Vec<String> = entries
            .iter()
            .filter(|(e, _)| e.name == *name)
            .map(|(e, _)| format!("  {}", e.path.display()))
            .collect();
        eprintln!(
            "loadout `{name}` is defined in both loadouts directories:\n{}\nremove one.",
            paths.join("\n")
        );
    }
    let dir_list = dirs
        .iter()
        .map(|(d, _)| d.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ");

    // Load the listed directory's `config.toml` to discover which
    // loadouts should be marked as defaults. Missing file → no
    // defaults; malformed file → error out so the user can see it.
    // Read the way `read_client_config` reads it, but from `--dir`
    // when given, so the defaults belong to the directory listed.
    let defaults: std::collections::HashSet<String> =
        boxes::client::config::read_config_or_default(&config_dir.join("config.toml"))
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .loadouts
            .default_loadouts
            .into_iter()
            .collect();

    // Warn about defaults that don't have a matching file — a
    // silent typo in `default_loadouts` would otherwise be
    // invisible until the user wondered why their loadout wasn't
    // active.
    let present: std::collections::HashSet<&str> =
        entries.iter().map(|(e, _)| e.name.as_str()).collect();
    defaults
        .iter()
        .filter(|missing| !present.contains(missing.as_str()))
        .for_each(|missing| {
            eprintln!(
                "Warning: `{missing}` listed in default_loadouts but no `{missing}.toml` \
                 or `{missing}/loadout.toml` in {dir_list}",
            );
        });

    // The built-in `default` loadout is always available, so it gets a
    // row unless the user has shadowed it with a `default` of their own.
    let show_builtin = !present.contains(BUILTIN_DEFAULT_NAME);

    // Partition discovered entries: parsed loadouts become table rows,
    // while parse failures go to stderr and force a non-zero exit so a
    // script running `loadout list` can detect a broken file. Keeping
    // failures out of the table also preserves the layout their
    // multi-line parse errors would otherwise corrupt.
    let mut rows: Vec<LoadoutRow> = Vec::with_capacity(entries.len());
    let mut failures = both.len();
    // Sorted by name across both directories, as each directory's own
    // listing already is.
    entries.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
    for (entry, untrusted) in &entries {
        match &entry.loadout {
            // A name in both directories gets no row (reported above), but
            // a copy that also fails to load on its own is reported too,
            // below, rather than hidden behind the directory clash.
            Ok(_) if both.contains(&entry.name) => {}
            Ok(loadout) => rows.push(LoadoutRow::from_entry(
                entry, loadout, *untrusted, &defaults,
            )),
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
        // "failed to load", not "failed to parse": a conflicting pair
        // of layouts is counted here too, and it parses fine.
        bail!(
            "{failures} loadout{} failed to load",
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
    /// An `untrusted` loadout's name column carries an `(untrusted)` tag,
    /// as the built-in's carries `(built-in)`.
    fn from_entry(
        entry: &boxes::client::disk::LoadoutEntry,
        loadout: &boxes::core::loadout::Loadout,
        untrusted: bool,
        defaults: &std::collections::HashSet<String>,
    ) -> Self {
        let marker = if defaults.contains(&entry.name) {
            "*"
        } else {
            " "
        };
        Self {
            marker,
            name: if untrusted {
                format!("{} (untrusted)", entry.name)
            } else {
                entry.name.clone()
            },
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

    /// The directory these tests pretend their hand-built loadouts were
    /// read from. Nothing here declares a `$LOADOUT_ROOT` patch source
    /// or an external hook script, so the path only has to be
    /// well-formed — it is never touched on disk.
    fn stub_loadouts_dir() -> paths::HostAbsPath {
        paths::HostAbsPath::try_new("/nonexistent/minimal/loadouts").unwrap()
    }

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
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(PathBuf::from("/definitely/does/not/exist")),
            provider: None,
            no_input: false,
            vm: None,
        };
        let out = resolve_active_loadouts(LoadoutSelection::None, &cfg, &global)
            .expect("None → Ok(empty), no I/O");
        assert!(out.loadouts.is_empty());
        assert!(!out.builtin_default);
        assert_eq!(loadout_display_list(&out), "none");
    }

    /// `resolve_active_loadouts` errors when a `--loadout NAME`
    /// selection names a loadout that is on disk in neither layout,
    /// and the message names both places it looked — a user who
    /// mistyped needs to know where the file was expected.
    #[test]
    fn resolve_active_loadouts_cli_missing_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("minimal/loadouts")).unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        let selection = LoadoutSelection::Cli(vec!["missing".to_string()]);
        let err = resolve_active_loadouts(selection, &cfg, &global)
            .expect_err("a missing --loadout must error");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("missing.toml"), "got: {rendered}");
        assert!(rendered.contains("missing/loadout.toml"), "got: {rendered}");
    }

    /// The `--loadout NAME` error names the underlying failure exactly
    /// once. `LoadError`'s Display already embeds its source, so the
    /// context chain must not re-render it (see the flatten in
    /// [`resolve_active_loadouts`]).
    ///
    /// Exercised through a malformed file rather than a missing one:
    /// absence is now [`LoadError::NotFound`], which has no source to
    /// double, so it could not catch a regression here.
    ///
    /// [`LoadError::NotFound`]: boxes::client::disk::LoadError::NotFound
    #[test]
    fn resolve_active_loadouts_cli_error_not_doubled() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        let malformed = "= not = toml =";
        std::fs::write(loadouts.join("broken.toml"), malformed).unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        let selection = LoadoutSelection::Cli(vec!["broken".to_string()]);
        let err = resolve_active_loadouts(selection, &cfg, &global)
            .expect_err("a malformed --loadout file must error");
        let rendered = format!("{err:#}");
        // The parse-error text belongs to `toml`, so derive it from the
        // same failing parse and assert it appears once, not twice.
        let needle = toml::from_str::<boxes::core::loadout::LoadoutFile>(malformed)
            .expect_err("the fixture must not parse")
            .to_string();
        assert_eq!(
            rendered.matches(&needle).count(),
            1,
            "parse error should appear once in `{rendered}`",
        );
    }

    /// A `--loadout` value is validated as a name before it is joined
    /// into a path. Without that, `../../evil` would be interpolated
    /// straight into a filename and read an arbitrary `.toml` off
    /// disk — the stem check downstream does not catch it, because
    /// `file_stem("../../evil.toml")` is just `evil`.
    #[test]
    fn resolve_active_loadouts_rejects_a_traversing_name() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("minimal/loadouts")).unwrap();
        // Plant the file the traversal would have reached, so the test
        // fails loudly if the name ever gets through.
        std::fs::write(
            tmp.path().join("evil.toml"),
            "description = \"should never load\"\n",
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        // The dot forms carry no separator, so they need their own
        // refusal: under the directory layout `..` would resolve
        // `<loadouts>/../loadout.toml`, one level above the loadouts
        // directory, and `.` would resolve `<loadouts>/./loadout.toml`
        // — aliasing the flat loadout named `loadout` under a name
        // taken from the parent directory.
        for name in ["../evil", "../../evil", "sub/evil", ".", "..", "  ..  "] {
            let selection = LoadoutSelection::Cli(vec![name.to_string()]);
            assert!(
                resolve_active_loadouts(selection, &cfg, &global).is_err(),
                "`{name}` must be refused as a loadout name",
            );
        }
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
        let loadout: boxes::core::loadout::Loadout = toml::from_str(
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
                loadouts_dir: stub_loadouts_dir(),
                builtin_default: false,
            },
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            None,
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

    /// A loadout `on_activate` declaring more than the base oneshot RPC
    /// timeout yields a finalize budget equal to its declared timeout, so
    /// the `FinalizeSession` deadline (base + budget) clears the point at
    /// which such a hook was previously cut off. `--no-hooks` zeroes it.
    #[test]
    fn activate_hook_budget_reflects_declared_on_activate_timeout() {
        let loadout: boxes::core::loadout::Loadout = toml::from_str(
            r#"
name = "slow"

[[lifecycle_hooks]]
on_activate = { type = "inline", value = "sleep 90", timeout = 90 }
"#,
        )
        .expect("loadout parses");
        let active = ActiveLoadouts {
            loadouts: vec![loadout],
            loadouts_dir: stub_loadouts_dir(),
            builtin_default: false,
        };
        let (contribution, _) = compose_user_contribution(
            active,
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            None,
        )
        .expect("composing a hook-only loadout");
        // A tempdir with no minimal.toml: the project side contributes
        // nothing, isolating the loadout hook's declared timeout.
        let tmp = tempfile::tempdir().unwrap();
        let root = camino::Utf8Path::from_path(tmp.path()).unwrap();

        assert_eq!(
            activate_hook_budget(&contribution.lifecycle_hooks, root, true),
            Duration::from_secs(90),
        );
        assert_eq!(
            activate_hook_budget(&contribution.lifecycle_hooks, root, false),
            Duration::ZERO,
            "--no-hooks contributes no budget",
        );
    }

    /// An untrusted loadout's hook that the user policy ignores is dropped
    /// by the gate, so its script is never staged — a missing script
    /// cannot fail the activation — and it adds nothing to the budget.
    #[test]
    fn a_hook_the_policy_drops_is_not_staged() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = camino::Utf8Path::from_path(tmp.path())
            .unwrap()
            .join("loadouts-untrusted/ci");
        let loadout: boxes::core::loadout::Loadout = toml::from_str(
            r#"
name = "ci"

[[lifecycle_hooks]]
on_activate = { type = "external", value = "./missing.sh", timeout = 90 }
"#,
        )
        .expect("loadout parses");
        let active = ActiveLoadouts {
            loadouts: vec![loadout.untrusted(paths::HostAbsPath::try_new(dir.clone()).unwrap())],
            loadouts_dir: stub_loadouts_dir(),
            builtin_default: false,
        };
        let policy = boxes::core::policy::UserPolicy::empty()
            .with_hooks(boxes::core::policy::HooksPolicy::empty().with_ignore([dir.as_str()]));
        let (contribution, _) = compose_user_contribution(
            active,
            policy,
            boxes::core::compose::ComposeOptions::default(),
            true,
            None,
        )
        .expect("an ignored hook composes without asking");
        assert!(contribution.lifecycle_hooks.is_empty());

        let root = paths::HostAbsPath::try_new(
            camino::Utf8Path::from_path(tmp.path()).unwrap().to_owned(),
        )
        .unwrap();
        let staged =
            stage_loadout_hook_scripts(&contribution.lifecycle_hooks, &stub_loadouts_dir(), &root)
                .expect("nothing to stage, so nothing to fail");
        assert!(staged.is_empty());
        assert_eq!(
            activate_hook_budget(&contribution.lifecycle_hooks, root.as_utf8_path(), true),
            Duration::ZERO,
        );
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
                boxes::core::primitives::VarValue::Specified { value } => value.clone(),
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
        assert!(motd.contains("detach: %s"));
        assert!(motd.contains("${MINIMAL_DETACH_HINT:-ctrl-] then d}"));
        assert!(motd.contains("min init"));
    }

    /// The display list interpolated into the banner: comma-joined names
    /// for user loadouts, `none` for an empty set (the built-in and
    /// shadow cases are asserted in the resolution tests above).
    #[test]
    fn loadout_display_list_joins_names() {
        let mk = |name: &str| -> boxes::core::loadout::Loadout {
            toml::from_str(&format!("name = \"{name}\"\n")).expect("loadout parses")
        };
        let active = ActiveLoadouts {
            loadouts: vec![mk("helix"), mk("fish")],
            loadouts_dir: stub_loadouts_dir(),
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
                loadouts_dir: stub_loadouts_dir(),
                builtin_default: true,
            },
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            None,
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
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
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
            "description = \"user override\"\n",
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
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

    /// A `--loadout NAME` resolves the directory layout,
    /// `<loadouts>/<name>/loadout.toml`, exactly as it resolves the
    /// flat file — same name, same contents, and the same
    /// `loadouts_dir` anchor, which is what makes `$LOADOUT_ROOT` and
    /// the loadout's hook scripts land in `<loadouts>/<name>/` either
    /// way.
    #[test]
    fn resolve_active_loadouts_reads_the_directory_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(loadouts.join("dev")).unwrap();
        std::fs::write(
            loadouts.join("dev").join("loadout.toml"),
            "description = \"version controlled\"\npackages = [\"helix\"]\n",
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        let out = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["dev".to_string()]),
            &cfg,
            &global,
        )
        .expect("a directory-layout loadout resolves");
        assert_eq!(out.loadouts.len(), 1);
        assert_eq!(out.loadouts[0].name().as_ref(), "dev");
        assert_eq!(out.loadouts[0].description(), Some("version controlled"));
        assert_eq!(out.loadouts[0].packages(), &["helix"]);
        // The anchor is the loadouts dir, not the loadout's own
        // directory — `Source::loadout_dir` appends the name.
        assert_eq!(out.loadouts_dir.as_str(), loadouts.to_str().unwrap());
    }

    /// One name in both layouts is refused rather than resolved by
    /// precedence, and the error names both files.
    #[test]
    fn resolve_active_loadouts_refuses_a_name_in_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(loadouts.join("dev")).unwrap();
        std::fs::write(loadouts.join("dev.toml"), "description = \"flat\"\n").unwrap();
        std::fs::write(
            loadouts.join("dev").join("loadout.toml"),
            "description = \"dir\"\n",
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        let err = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["dev".to_string()]),
            &cfg,
            &global,
        )
        .expect_err("an ambiguous loadout must error");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("dev.toml"), "got: {rendered}");
        assert!(rendered.contains("loadout.toml"), "got: {rendered}");
    }

    /// A user `default/loadout.toml` shadows the built-in just as
    /// `default.toml` does — the zero-config probe looks in both
    /// layouts.
    #[test]
    fn resolve_active_loadouts_directory_default_shadows_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(loadouts.join("default")).unwrap();
        std::fs::write(
            loadouts.join("default").join("loadout.toml"),
            "description = \"user override\"\n",
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        let out = resolve_active_loadouts(LoadoutSelection::Defaults, &cfg, &global)
            .expect("user default resolves");
        assert_eq!(out.loadouts.len(), 1);
        assert_eq!(out.loadouts[0].description(), Some("user override"));
        assert!(!out.builtin_default);
        assert_eq!(loadout_display_list(&out), "default");
    }

    /// The zero-config probe reports a `default` that is present but
    /// unusable, instead of reading the failure as absence and
    /// silently substituting the built-in — which would leave the user
    /// wondering why their file had no effect.
    #[test]
    fn resolve_active_loadouts_reports_a_broken_user_default() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        std::fs::write(loadouts.join("default.toml"), "= not = toml =").unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        assert!(
            resolve_active_loadouts(LoadoutSelection::Defaults, &cfg, &global).is_err(),
            "a malformed user `default` must be reported, not fall back",
        );
    }

    /// Every resolution carries the loadouts directory it read from,
    /// and that directory follows `--config-dir` — this is what makes
    /// `$LOADOUT_ROOT` (and a loadout's hook scripts) resolve against
    /// the files that are actually in play, not a platform default.
    ///
    /// Asserted across all three exits: the `--no-loadouts`
    /// short-circuit, the zero-config built-in fallback, and a real
    /// file read from disk.
    #[test]
    fn resolve_active_loadouts_carries_the_effective_loadouts_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        let expected = paths::HostAbsPath::try_new(
            camino::Utf8PathBuf::from_path_buf(loadouts.clone()).unwrap(),
        )
        .unwrap();
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };

        let none = resolve_active_loadouts(LoadoutSelection::None, &cfg, &global).unwrap();
        assert_eq!(none.loadouts_dir, expected, "--no-loadouts");

        let builtin = resolve_active_loadouts(LoadoutSelection::Defaults, &cfg, &global).unwrap();
        assert!(builtin.builtin_default);
        assert_eq!(builtin.loadouts_dir, expected, "built-in fallback");

        std::fs::write(loadouts.join("dev.toml"), "description = \"d\"\n").unwrap();
        let named = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["dev".to_string()]),
            &cfg,
            &global,
        )
        .unwrap();
        assert_eq!(named.loadouts_dir, expected, "--loadout dev");
        assert_eq!(named.loadouts[0].name().as_ref(), "dev");
    }

    /// A relative `--config-dir` still resolves: it is anchored at the
    /// working directory, the way every other consumer of the flag
    /// reads it.
    ///
    /// Regression guard. `$LOADOUT_ROOT` needs an absolute anchor, but
    /// that requirement must not leak back onto the flag — a run with
    /// no loadouts at all (or none using the reference) has no business
    /// failing because the config dir was spelled relatively.
    #[test]
    fn resolve_active_loadouts_anchors_a_relative_config_dir_at_the_cwd() {
        let cfg = boxes::client::config::Config::default();
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(PathBuf::from("rel-cfg")),
            provider: None,
            no_input: false,
            vm: None,
        };
        let out = resolve_active_loadouts(LoadoutSelection::None, &cfg, &global)
            .expect("a relative --config-dir must still resolve");
        let cwd = camino::Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(
            out.loadouts_dir.as_utf8_path(),
            cwd.join("rel-cfg/minimal/loadouts"),
        );
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
        // Valid TOML, wrong schema: `packages` is a list → parse failure.
        std::fs::write(loadouts.join("broken.toml"), "packages = 1\n").unwrap();
        let args = LoadoutListArgs {
            dir: Some(tmp.path().to_path_buf()),
        };
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        assert!(cmd_loadout_list(args, &global).is_err());
    }

    /// A name defined in both layouts is a listing failure, exactly as
    /// a malformed file is: reported on stderr and a non-zero exit,
    /// with the valid loadouts beside it still listed.
    #[test]
    fn cmd_loadout_list_errors_on_a_name_in_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("loadouts");
        std::fs::create_dir_all(loadouts.join("dev")).unwrap();
        std::fs::write(loadouts.join("dev.toml"), "description = \"flat\"\n").unwrap();
        std::fs::write(
            loadouts.join("dev").join("loadout.toml"),
            "description = \"dir\"\n",
        )
        .unwrap();
        std::fs::write(loadouts.join("fine.toml"), "description = \"ok\"\n").unwrap();
        let args = LoadoutListArgs {
            dir: Some(tmp.path().to_path_buf()),
        };
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        assert!(cmd_loadout_list(args, &global).is_err());
    }

    /// The listing shows both layouts, and a `<name>/` directory that
    /// holds no `loadout.toml` is not one of them — it is the asset
    /// directory beside a flat `<name>.toml`, and listing it would
    /// invent a loadout that does not exist.
    #[test]
    fn cmd_loadout_list_lists_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("loadouts");
        std::fs::create_dir_all(loadouts.join("vc")).unwrap();
        std::fs::write(loadouts.join("flat.toml"), "description = \"flat\"\n").unwrap();
        std::fs::write(
            loadouts.join("vc").join("loadout.toml"),
            "description = \"dir\"\n",
        )
        .unwrap();
        // Assets beside `flat.toml`: a directory, but not a loadout.
        std::fs::create_dir_all(loadouts.join("flat")).unwrap();
        std::fs::write(loadouts.join("flat").join("config.toml"), "x = 1\n").unwrap();

        let entries = boxes::client::disk::list_loadouts(&loadouts).expect("lists");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["flat", "vc"]);
        assert!(entries.iter().all(|e| e.loadout.is_ok()));

        let args = LoadoutListArgs {
            dir: Some(tmp.path().to_path_buf()),
        };
        let global = GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(tmp.path().to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        };
        assert!(cmd_loadout_list(args, &global).is_ok());
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
        use boxes::core::lifecyclehook::{HookScript, LifecycleHook};
        use boxes::core::loadout::{Loadout, LoadoutName};

        let build = |hooks_enabled: bool| {
            let loadout = Loadout::new(LoadoutName::try_new("dev").unwrap()).with_lifecycle_hook(
                LifecycleHook::builder()
                    .with_on_activate(HookScript::inline("echo hi"))
                    .build()
                    .unwrap(),
            );
            let active = ActiveLoadouts {
                loadouts: vec![loadout],
                loadouts_dir: stub_loadouts_dir(),
                builtin_default: false,
            };
            let (contribution, _) = compose_user_contribution(
                active,
                boxes::core::policy::UserPolicy::empty(),
                boxes::core::compose::ComposeOptions::default(),
                hooks_enabled,
                None,
            )
            .expect("composing a hook-only loadout");
            contribution.lifecycle_hooks.len()
        };

        assert_eq!(build(true), 1, "hooks on: the loadout's hook composes in");
        assert_eq!(build(false), 0, "--no-hooks: nothing reaches the wire");
    }

    /// A `GlobalArgs` reading its config from `dir`.
    fn global_at(dir: &std::path::Path) -> GlobalArgs {
        GlobalArgs {
            repo_dir: None,
            minimal_dir: None,
            config_dir: Some(dir.to_path_buf()),
            provider: None,
            no_input: false,
            vm: None,
        }
    }

    /// A loadout in `loadouts-untrusted/` resolves by name like any
    /// other, in either layout, and comes back marked untrusted with its
    /// own directory — the one the hooks policy matches it by.
    #[test]
    fn resolve_active_loadouts_reads_the_untrusted_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let untrusted = tmp.path().join("minimal/loadouts-untrusted");
        std::fs::create_dir_all(untrusted.join("vc")).unwrap();
        std::fs::write(untrusted.join("ci.toml"), "packages = [\"helix\"]\n").unwrap();
        std::fs::write(untrusted.join("vc/loadout.toml"), "").unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        std::fs::create_dir_all(&loadouts).unwrap();
        std::fs::write(loadouts.join("dev.toml"), "").unwrap();

        let out = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["dev".into(), "ci".into(), "vc".into()]),
            &boxes::client::config::Config::default(),
            &global_at(tmp.path()),
        )
        .expect("loadouts in both directories resolve");
        let trust: Vec<(&str, bool)> = out
            .loadouts
            .iter()
            .map(|l| (l.name().as_ref(), l.is_untrusted()))
            .collect();
        assert_eq!(trust, vec![("dev", false), ("ci", true), ("vc", true)]);
        assert_eq!(out.loadouts[1].packages(), &["helix"]);
        match out.loadouts[1].source() {
            boxes::core::source::Source::UntrustedLoadout { dir, .. } => {
                assert_eq!(dir.as_str(), untrusted.join("ci").to_str().unwrap());
            }
            other => panic!("expected an untrusted source, got {other:?}"),
        }
    }

    /// One name in both directories is refused, naming both files —
    /// which copy won would also decide whether the policy gates it.
    #[test]
    fn resolve_active_loadouts_refuses_a_name_in_both_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        for dir in ["minimal/loadouts", "minimal/loadouts-untrusted"] {
            std::fs::create_dir_all(tmp.path().join(dir)).unwrap();
            std::fs::write(tmp.path().join(dir).join("dev.toml"), "").unwrap();
        }
        let err = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["dev".into()]),
            &boxes::client::config::Config::default(),
            &global_at(tmp.path()),
        )
        .expect_err("an ambiguous loadout must error");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("loadouts/dev.toml"), "got: {rendered}");
        assert!(
            rendered.contains("loadouts-untrusted/dev.toml"),
            "got: {rendered}"
        );
    }

    /// A missing `--loadout` names both directories it looked in.
    #[test]
    fn resolve_active_loadouts_missing_names_both_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_active_loadouts(
            LoadoutSelection::Cli(vec!["missing".into()]),
            &boxes::client::config::Config::default(),
            &global_at(tmp.path()),
        )
        .expect_err("a missing --loadout must error");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("minimal/loadouts`"), "got: {rendered}");
        assert!(
            rendered.contains("minimal/loadouts-untrusted`"),
            "got: {rendered}"
        );
    }

    /// An untrusted `default` shadows the built-in, as a trusted one does.
    #[test]
    fn resolve_active_loadouts_untrusted_default_shadows_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let untrusted = tmp.path().join("minimal/loadouts-untrusted");
        std::fs::create_dir_all(&untrusted).unwrap();
        std::fs::write(untrusted.join("default.toml"), "").unwrap();
        let out = resolve_active_loadouts(
            LoadoutSelection::Defaults,
            &boxes::client::config::Config::default(),
            &global_at(tmp.path()),
        )
        .expect("an untrusted default resolves");
        assert!(!out.builtin_default);
        assert_eq!(out.loadouts.len(), 1);
        assert!(out.loadouts[0].is_untrusted());
    }

    /// An untrusted loadout's hook, on the no-prompt lane, fails the
    /// composition with the snippet that would allow it — keyed by the
    /// loadout's own directory — before anything reaches the daemon.
    #[test]
    fn gated_compose_no_prompt_refuses_with_a_snippet() {
        use boxes::core::lifecyclehook::{HookScript, LifecycleHook};
        use boxes::core::loadout::{Loadout, LoadoutName};

        let tmp = tempfile::tempdir().unwrap();
        let dir = paths::HostAbsPath::try_new("/cfg/minimal/loadouts-untrusted/ci").unwrap();
        let loadout = Loadout::new(LoadoutName::try_new("ci").unwrap())
            .with_lifecycle_hook(
                LifecycleHook::builder()
                    .with_on_activate(HookScript::inline("echo hi"))
                    .build()
                    .unwrap(),
            )
            .untrusted(dir);
        let active = ActiveLoadouts {
            loadouts: vec![loadout],
            loadouts_dir: stub_loadouts_dir(),
            builtin_default: false,
        };
        let policy_path = tmp.path().join("user_policy.toml");
        let err = compose_user_contribution_gated(
            active,
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            PromptLane::NoPrompt,
            &policy_path,
        )
        .expect_err("an unapproved untrusted hook must refuse");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("[hooks]"), "got: {rendered}");
        assert!(
            rendered.contains("/cfg/minimal/loadouts-untrusted/ci"),
            "got: {rendered}"
        );
        assert!(!policy_path.exists(), "the no-prompt lane writes nothing");
    }

    /// An untrusted loadout carrying one inline `on_activate` hook, read
    /// from `/cfg/minimal/loadouts-untrusted/ci`.
    fn untrusted_hook_loadouts() -> ActiveLoadouts {
        use boxes::core::lifecyclehook::{HookScript, LifecycleHook};
        use boxes::core::loadout::{Loadout, LoadoutName};
        let loadout = Loadout::new(LoadoutName::try_new("ci").unwrap())
            .with_lifecycle_hook(
                LifecycleHook::builder()
                    .with_on_activate(HookScript::inline("echo hi"))
                    .build()
                    .unwrap(),
            )
            .untrusted(paths::HostAbsPath::try_new("/cfg/minimal/loadouts-untrusted/ci").unwrap());
        ActiveLoadouts {
            loadouts: vec![loadout],
            loadouts_dir: stub_loadouts_dir(),
            builtin_default: false,
        }
    }

    /// The interactive lane with `answers` scripted in.
    fn compose_answering(
        answers: Vec<crate::prompt::UserChoice>,
        policy_path: &std::path::Path,
    ) -> Result<
        (
            boxes::wire::request::WireContribution,
            boxes::core::policy::UserPolicy,
        ),
        anyhow::Error,
    > {
        let hooks = crate::prompt::InteractivePrompt::with_prompter(
            Box::new(crate::prompt::ScriptedPrompter::new(answers)),
            true,
        );
        compose_interactively(
            untrusted_hook_loadouts(),
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            hooks,
            policy_path,
        )
    }

    /// `min dash` refuses an undecided untrusted item even where it could
    /// prompt, naming itself rather than `--no-prompt`, and writes nothing.
    #[test]
    fn dashboard_lane_refuses_undecided_items() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("user_policy.toml");
        let err = compose_user_contribution_gated(
            untrusted_hook_loadouts(),
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            PromptLane::Dashboard,
            &policy_path,
        )
        .expect_err("an undecided untrusted hook must refuse in the dashboard");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("min dash does not ask"),
            "got: {rendered}"
        );
        assert!(rendered.contains("[hooks]"), "got: {rendered}");
        assert!(!rendered.contains("--no-prompt"), "got: {rendered}");
        assert!(!policy_path.exists());
    }

    /// "Allow permanently" on an untrusted loadout's hook keeps the hook,
    /// and records the loadout's own directory as a `[hooks]` allow rule —
    /// in the returned policy and in `user_policy.toml`.
    #[test]
    fn interactive_allow_permanent_records_the_loadout_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("user_policy.toml");
        let (contribution, policy) = compose_answering(
            vec![crate::prompt::UserChoice::AllowPermanent],
            &policy_path,
        )
        .expect("an allowed hook composes");
        assert_eq!(contribution.lifecycle_hooks.len(), 1);
        assert_eq!(
            policy.hooks().allow(),
            ["/cfg/minimal/loadouts-untrusted/ci"]
        );
        let saved = std::fs::read_to_string(&policy_path).expect("the rule was saved");
        assert!(
            saved.contains("/cfg/minimal/loadouts-untrusted/ci"),
            "got: {saved}"
        );
    }

    /// "Deny permanently" aborts the composition, and its rule is still
    /// saved: the user chose to record it whether or not this run fails.
    #[test]
    fn interactive_deny_permanent_aborts_and_still_saves() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("user_policy.toml");
        compose_answering(vec![crate::prompt::UserChoice::DenyPermanent], &policy_path)
            .expect_err("a denied hook aborts the activation");
        let saved = std::fs::read_to_string(&policy_path).expect("the rule was saved");
        assert!(saved.contains("deny"), "got: {saved}");
        assert!(
            saved.contains("/cfg/minimal/loadouts-untrusted/ci"),
            "got: {saved}"
        );
    }

    /// A once-only answer writes nothing: there is no rule to keep.
    #[test]
    fn interactive_allow_once_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("user_policy.toml");
        let (contribution, _) =
            compose_answering(vec![crate::prompt::UserChoice::AllowOnce], &policy_path)
                .expect("an allowed hook composes");
        assert_eq!(contribution.lifecycle_hooks.len(), 1);
        assert!(!policy_path.exists());
    }

    /// The same hook from a trusted loadout composes on the no-prompt
    /// lane: nothing about it needs approval.
    #[test]
    fn gated_compose_no_prompt_passes_trusted_loadouts() {
        use boxes::core::lifecyclehook::{HookScript, LifecycleHook};
        use boxes::core::loadout::{Loadout, LoadoutName};

        let tmp = tempfile::tempdir().unwrap();
        let loadout = Loadout::new(LoadoutName::try_new("dev").unwrap()).with_lifecycle_hook(
            LifecycleHook::builder()
                .with_on_activate(HookScript::inline("echo hi"))
                .build()
                .unwrap(),
        );
        let active = ActiveLoadouts {
            loadouts: vec![loadout],
            loadouts_dir: stub_loadouts_dir(),
            builtin_default: false,
        };
        let (contribution, _) = compose_user_contribution_gated(
            active,
            boxes::core::policy::UserPolicy::empty(),
            boxes::core::compose::ComposeOptions::default(),
            true,
            PromptLane::NoPrompt,
            &tmp.path().join("user_policy.toml"),
        )
        .expect("a trusted hook needs no approval");
        assert_eq!(contribution.lifecycle_hooks.len(), 1);
    }

    /// Without `--dir`, the listing covers both directories; a name in
    /// both is a failure, while the rest still list.
    #[test]
    fn cmd_loadout_list_covers_both_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("minimal/loadouts");
        let untrusted = tmp.path().join("minimal/loadouts-untrusted");
        std::fs::create_dir_all(&loadouts).unwrap();
        std::fs::create_dir_all(&untrusted).unwrap();
        std::fs::write(loadouts.join("dev.toml"), "").unwrap();
        std::fs::write(untrusted.join("ci.toml"), "").unwrap();
        let global = global_at(tmp.path());

        assert!(cmd_loadout_list(LoadoutListArgs { dir: None }, &global).is_ok());

        std::fs::write(untrusted.join("dev.toml"), "").unwrap();
        let err = cmd_loadout_list(LoadoutListArgs { dir: None }, &global)
            .expect_err("a name in both directories fails the listing");
        assert!(err.to_string().contains("1 loadout failed"), "got: {err}");
    }

    /// `--dir` names a minimal config directory, not a loadouts one: both
    /// of its loadouts subdirectories are listed, whatever `--config-dir`
    /// says, and a clash between them is caught there too.
    #[test]
    fn cmd_loadout_list_dir_names_the_minimal_config_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let minimal = tmp.path().join("elsewhere");
        std::fs::create_dir_all(minimal.join("loadouts")).unwrap();
        std::fs::create_dir_all(minimal.join("loadouts-untrusted")).unwrap();
        std::fs::write(minimal.join("loadouts/dev.toml"), "").unwrap();
        std::fs::write(minimal.join("loadouts-untrusted/dev.toml"), "").unwrap();
        // `--config-dir` points somewhere with nothing in it, so only
        // `--dir` can have produced the clash.
        let global = global_at(&tmp.path().join("unused"));

        let err = cmd_loadout_list(LoadoutListArgs { dir: Some(minimal) }, &global)
            .expect_err("the clash under --dir fails the listing");
        assert!(err.to_string().contains("1 loadout failed"), "got: {err}");
    }

    /// A row from the untrusted directory is tagged `(untrusted)`; one
    /// from the trusted directory is not.
    #[test]
    fn loadout_row_tags_untrusted_entries() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ci.toml"), "").unwrap();
        let entries = boxes::client::disk::list_loadouts(tmp.path()).unwrap();
        let entry = &entries[0];
        let loadout = entry.loadout.as_ref().unwrap();
        let defaults = std::collections::HashSet::new();
        assert_eq!(
            LoadoutRow::from_entry(entry, loadout, true, &defaults).name,
            "ci (untrusted)"
        );
        assert_eq!(
            LoadoutRow::from_entry(entry, loadout, false, &defaults).name,
            "ci"
        );
    }

    /// A name in both directories whose trusted copy is itself broken
    /// (both layouts at once) reports both faults: the directory clash
    /// does not hide the layout clash.
    #[test]
    fn cmd_loadout_list_reports_a_broken_copy_of_a_name_in_both_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let loadouts = tmp.path().join("loadouts");
        std::fs::create_dir_all(loadouts.join("dev")).unwrap();
        std::fs::write(loadouts.join("dev.toml"), "").unwrap();
        std::fs::write(loadouts.join("dev/loadout.toml"), "").unwrap();
        let untrusted = tmp.path().join("loadouts-untrusted");
        std::fs::create_dir_all(&untrusted).unwrap();
        std::fs::write(untrusted.join("dev.toml"), "").unwrap();

        let err = cmd_loadout_list(
            LoadoutListArgs {
                dir: Some(tmp.path().to_path_buf()),
            },
            &global_at(&tmp.path().join("unused")),
        )
        .expect_err("both faults fail the listing");
        assert!(err.to_string().contains("2 loadouts failed"), "got: {err}");
    }
}
