//! Resolving and validating external lifecycle-hook scripts on the
//! client, before they are uploaded to the daemon.
//!
//! An external script is declared as a relative path. What it is
//! relative *to* depends on who declared it, and that can't be settled
//! when the file is parsed — the same [`LifecycleHook`] type is
//! deserialized from a loadout and from a project's `minimal.toml`. So
//! the anchor is resolved here, from the hook's recorded
//! [`Source`], at the point the script is staged:
//!
//! | Source | Anchor |
//! |---|---|
//! | [`Source::UserLoadout`] | `<config>/minimal/loadouts/<name>/` |
//! | [`Source::Project`] | the project root |
//!
//! Validation runs on the client so a mistyped path fails locally and
//! immediately, naming the file, rather than surfacing partway through
//! an activation that has already created a session on the daemon.
//!
//! [`LifecycleHook`]: crate::core::lifecyclehook::LifecycleHook
//! [`Source::UserLoadout`]: crate::core::source::Source::UserLoadout
//! [`Source::Project`]: crate::core::source::Source::Project

use camino::{Utf8Path, Utf8PathBuf};

use crate::core::lifecyclehook::{HookScript, HookScriptBody, staged_script_path};
use crate::core::source::{Provenanced, ProvenancedHook, Source};

/// Why an external hook script couldn't be staged.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StageError {
    /// The declaring source has no anchor on this machine — a loadout
    /// whose script directory is missing, or a project path that isn't
    /// present.
    #[error("hook script `{script}` from {declared_by}: no such directory `{anchor}`")]
    MissingAnchor {
        script: Utf8PathBuf,
        declared_by: String,
        anchor: Utf8PathBuf,
    },

    /// A component of the path is a symlink. Rejected rather than
    /// followed: a symlink is the one way a path that passes every
    /// other check can still resolve outside its anchor.
    #[error(
        "hook script `{script}` from {declared_by}: `{component}` is a symlink, which is not allowed"
    )]
    SymlinkComponent {
        script: Utf8PathBuf,
        declared_by: String,
        component: Utf8PathBuf,
    },

    /// The path doesn't exist under its anchor.
    #[error("hook script `{script}` from {declared_by}: no such file `{resolved}`")]
    NotFound {
        script: Utf8PathBuf,
        declared_by: String,
        resolved: Utf8PathBuf,
    },

    /// The path exists but isn't a regular file.
    #[error("hook script `{script}` from {declared_by}: `{resolved}` is not a regular file")]
    NotAFile {
        script: Utf8PathBuf,
        declared_by: String,
        resolved: Utf8PathBuf,
    },

    /// Stat failed for a reason other than absence.
    #[error("hook script `{script}` from {declared_by}: reading `{resolved}`: {source_err}")]
    Io {
        script: Utf8PathBuf,
        declared_by: String,
        resolved: Utf8PathBuf,
        #[source]
        source_err: std::io::Error,
    },
}

/// Where each kind of contributor's external scripts are anchored.
#[derive(Debug, Clone)]
pub struct ScriptAnchors {
    /// The user's loadouts directory. A loadout named `dev` anchors its
    /// scripts at `<loadouts_dir>/dev/`.
    pub loadouts_dir: Utf8PathBuf,
    /// The project root, for hooks declared in `minimal.toml`.
    pub project_root: Utf8PathBuf,
}

impl ScriptAnchors {
    /// The directory `source`'s scripts resolve against, or `None` for
    /// a source that cannot declare scripts.
    #[must_use]
    pub fn for_source(&self, source: &Source) -> Option<Utf8PathBuf> {
        match source {
            // Same guard as `staged_script_path`, for the same reason:
            // the name is joined into a path that is then read from, so
            // it has to be a component that stays put. A name this
            // rejects has no anchor, so its scripts never stage — and
            // the daemon would refuse to read them anyway.
            Source::UserLoadout { name } => crate::core::lifecyclehook::safe_path_component(name)
                .then(|| self.loadouts_dir.join(name)),
            Source::Project { .. } => Some(self.project_root.clone()),
            Source::Package { .. } => None,
        }
    }
}

/// One external script resolved on the host and ready to upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedScript {
    /// Absolute host path to read the script from.
    pub host_path: Utf8PathBuf,
    /// Path within the session's staged-hooks directory, from
    /// [`staged_script_path`]. The daemon reconstructs this same value
    /// from the hook's source, so the two sides agree without a
    /// manifest.
    pub staged: Utf8PathBuf,
}

/// Resolve and validate every external script the given hooks declare.
///
/// Inline scripts are skipped — their bodies travel inside the
/// composition and need no file. Duplicates are collapsed: two hooks
/// naming the same script from the same source upload once.
///
/// # Errors
///
/// Returns the first [`StageError`]. Failing on the first is
/// deliberate: a broken script path is a typo to fix, and reporting
/// them one at a time keeps the message pointed at a single file.
pub fn stage_external_scripts(
    hooks: &[ProvenancedHook],
    anchors: &ScriptAnchors,
) -> Result<Vec<StagedScript>, StageError> {
    let mut out: Vec<StagedScript> = Vec::new();
    for ph in hooks {
        let source = ph.source();
        let Some(anchor) = anchors.for_source(source) else {
            // A package can't declare hooks and the gate denies any
            // that appear, so there is nothing to resolve.
            continue;
        };
        let hook = ph.hook();
        for script in [
            hook.on_activate(),
            hook.on_destroy(),
            hook.on_attach(),
            hook.on_detach(),
        ]
        .into_iter()
        .flatten()
        {
            let Some(staged) = external_staged_path(source, script) else {
                continue;
            };
            let HookScriptBody::External(rel) = script.body() else {
                continue;
            };
            let host_path = resolve_under_anchor(&anchor, rel.as_utf8_path(), source)?;
            let candidate = StagedScript { host_path, staged };
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    Ok(out)
}

/// The staged path for `script`, or `None` when it is inline (or from a
/// source that can't stage).
fn external_staged_path(source: &Source, script: &HookScript) -> Option<Utf8PathBuf> {
    match script.body() {
        HookScriptBody::Inline(_) => None,
        HookScriptBody::External(rel) => staged_script_path(source, rel),
    }
}

/// Resolve `rel` under `anchor`, rejecting a symlink at any component.
///
/// Each component is stat'd with `symlink_metadata` as the path is
/// walked. Canonicalizing instead would *follow* symlinks — it can tell
/// you where a path ends up, but not that it took a link to get there,
/// which is exactly the thing being refused. `..` and absolute paths
/// are already impossible here: `rel` comes from a
/// [`ConfigRelPath`](paths::ConfigRelPath), which rejects both at
/// construction.
fn resolve_under_anchor(
    anchor: &Utf8Path,
    rel: &Utf8Path,
    source: &Source,
) -> Result<Utf8PathBuf, StageError> {
    let label = source.to_string();
    let script = rel.to_owned();

    // Absence and unreadability are different problems, told apart here the
    // same way the per-component walk below tells them apart: "no such
    // directory" sends you to create it, an I/O error sends you to look at
    // permissions or the filesystem.
    match std::fs::symlink_metadata(anchor.as_std_path()) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            return Err(StageError::MissingAnchor {
                script,
                declared_by: label,
                anchor: anchor.to_owned(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StageError::MissingAnchor {
                script,
                declared_by: label,
                anchor: anchor.to_owned(),
            });
        }
        Err(e) => {
            return Err(StageError::Io {
                script,
                declared_by: label,
                resolved: anchor.to_owned(),
                source_err: e,
            });
        }
    }

    let mut current = anchor.to_owned();
    let mut components = rel.components().peekable();
    while let Some(component) = components.next() {
        current = current.join(component.as_str());
        let is_last = components.peek().is_none();
        let meta = match std::fs::symlink_metadata(current.as_std_path()) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StageError::NotFound {
                    script,
                    declared_by: label,
                    resolved: current,
                });
            }
            Err(e) => {
                return Err(StageError::Io {
                    script,
                    declared_by: label,
                    resolved: current,
                    source_err: e,
                });
            }
        };
        // Checked on every component, including the last: a symlinked
        // leaf is just as capable of pointing outside the anchor as a
        // symlinked directory partway down.
        if meta.file_type().is_symlink() {
            return Err(StageError::SymlinkComponent {
                script,
                declared_by: label,
                component: current,
            });
        }
        if is_last && !meta.is_file() {
            return Err(StageError::NotAFile {
                script,
                declared_by: label,
                resolved: current,
            });
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lifecyclehook::LifecycleHook;

    fn anchors(root: &Utf8Path) -> ScriptAnchors {
        ScriptAnchors {
            loadouts_dir: root.join("loadouts"),
            project_root: root.join("proj"),
        }
    }

    fn loadout_source() -> Source {
        Source::UserLoadout { name: "dev".into() }
    }

    fn project_source(root: &Utf8Path) -> Source {
        Source::Project {
            path: paths::HostPath::try_new(root.join("proj")).unwrap(),
        }
    }

    fn hook_with_activate(script: HookScript, source: Source) -> ProvenancedHook {
        let h = LifecycleHook::builder()
            .with_on_activate(script)
            .build()
            .unwrap();
        ProvenancedHook::new(h, source)
    }

    /// Create `<root>/loadouts/dev/` and return it.
    fn make_loadout_dir(root: &Utf8Path) -> Utf8PathBuf {
        let d = root.join("loadouts").join("dev");
        std::fs::create_dir_all(d.as_std_path()).unwrap();
        d
    }

    #[test]
    fn inline_scripts_need_no_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        make_loadout_dir(root);
        let hooks = vec![hook_with_activate(
            HookScript::inline("echo hi"),
            loadout_source(),
        )];
        assert!(
            stage_external_scripts(&hooks, &anchors(root))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn loadout_script_resolves_under_its_own_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        std::fs::write(dir.join("activate.sh").as_std_path(), "echo hi\n").unwrap();

        let hooks = vec![hook_with_activate(
            HookScript::try_external("activate.sh").unwrap(),
            loadout_source(),
        )];
        let staged = stage_external_scripts(&hooks, &anchors(root)).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].host_path, dir.join("activate.sh"));
        assert_eq!(
            staged[0].staged,
            Utf8PathBuf::from("loadout/dev/activate.sh")
        );
    }

    #[test]
    fn project_script_resolves_under_the_project_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let proj = root.join("proj").join("scripts");
        std::fs::create_dir_all(proj.as_std_path()).unwrap();
        std::fs::write(proj.join("setup.sh").as_std_path(), "echo hi\n").unwrap();

        let hooks = vec![hook_with_activate(
            HookScript::try_external("scripts/setup.sh").unwrap(),
            project_source(root),
        )];
        let staged = stage_external_scripts(&hooks, &anchors(root)).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(
            staged[0].staged,
            Utf8PathBuf::from("project/scripts/setup.sh")
        );
    }

    /// A symlinked leaf is refused even though it resolves to a real
    /// file inside the anchor — following it is what's disallowed, not
    /// where it happens to land.
    #[test]
    fn symlinked_script_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        std::fs::write(dir.join("real.sh").as_std_path(), "echo hi\n").unwrap();
        std::os::unix::fs::symlink(
            dir.join("real.sh").as_std_path(),
            dir.join("link.sh").as_std_path(),
        )
        .unwrap();

        let hooks = vec![hook_with_activate(
            HookScript::try_external("link.sh").unwrap(),
            loadout_source(),
        )];
        let err = stage_external_scripts(&hooks, &anchors(root)).unwrap_err();
        assert!(
            matches!(err, StageError::SymlinkComponent { .. }),
            "got: {err:?}",
        );
    }

    /// A symlinked *directory* partway down is refused too — this is
    /// the escape a leaf-only check would miss.
    #[test]
    fn symlinked_intermediate_directory_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        let outside = root.join("outside");
        std::fs::create_dir_all(outside.as_std_path()).unwrap();
        std::fs::write(outside.join("evil.sh").as_std_path(), "echo pwned\n").unwrap();
        std::os::unix::fs::symlink(outside.as_std_path(), dir.join("sub").as_std_path()).unwrap();

        let hooks = vec![hook_with_activate(
            HookScript::try_external("sub/evil.sh").unwrap(),
            loadout_source(),
        )];
        let err = stage_external_scripts(&hooks, &anchors(root)).unwrap_err();
        assert!(
            matches!(err, StageError::SymlinkComponent { .. }),
            "got: {err:?}",
        );
    }

    #[test]
    fn missing_script_is_reported_with_its_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        make_loadout_dir(root);
        let hooks = vec![hook_with_activate(
            HookScript::try_external("nope.sh").unwrap(),
            loadout_source(),
        )];
        let err = stage_external_scripts(&hooks, &anchors(root)).unwrap_err();
        assert!(matches!(err, StageError::NotFound { .. }), "got: {err:?}");
        assert!(err.to_string().contains("nope.sh"), "got: {err}");
    }

    #[test]
    fn directory_in_place_of_a_script_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        std::fs::create_dir_all(dir.join("adir").as_std_path()).unwrap();
        let hooks = vec![hook_with_activate(
            HookScript::try_external("adir").unwrap(),
            loadout_source(),
        )];
        let err = stage_external_scripts(&hooks, &anchors(root)).unwrap_err();
        assert!(matches!(err, StageError::NotAFile { .. }), "got: {err:?}");
    }

    /// A loadout that declares an external script but has no script
    /// directory gets a message naming the directory it should create,
    /// not a bare "file not found".
    #[test]
    fn missing_loadout_script_directory_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let hooks = vec![hook_with_activate(
            HookScript::try_external("activate.sh").unwrap(),
            loadout_source(),
        )];
        let err = stage_external_scripts(&hooks, &anchors(root)).unwrap_err();
        assert!(
            matches!(err, StageError::MissingAnchor { .. }),
            "got: {err:?}",
        );
        assert!(err.to_string().contains("loadouts/dev"), "got: {err}");
    }

    /// Two hooks naming the same script upload it once.
    #[test]
    fn duplicate_scripts_collapse() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        std::fs::write(dir.join("a.sh").as_std_path(), "echo hi\n").unwrap();

        let hooks = vec![
            hook_with_activate(HookScript::try_external("a.sh").unwrap(), loadout_source()),
            hook_with_activate(HookScript::try_external("a.sh").unwrap(), loadout_source()),
        ];
        assert_eq!(
            stage_external_scripts(&hooks, &anchors(root))
                .unwrap()
                .len(),
            1
        );
    }

    /// Every transition's script is staged, not just `on_activate`.
    #[test]
    fn all_four_transitions_are_staged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let dir = make_loadout_dir(root);
        for f in ["a.sh", "d.sh", "at.sh", "dt.sh"] {
            std::fs::write(dir.join(f).as_std_path(), "echo hi\n").unwrap();
        }
        let hook = LifecycleHook::builder()
            .with_on_activate(HookScript::try_external("a.sh").unwrap())
            .with_on_destroy(HookScript::try_external("d.sh").unwrap())
            .with_on_attach(HookScript::try_external("at.sh").unwrap())
            .with_on_detach(HookScript::try_external("dt.sh").unwrap())
            .build()
            .unwrap();
        let hooks = vec![ProvenancedHook::new(hook, loadout_source())];
        assert_eq!(
            stage_external_scripts(&hooks, &anchors(root))
                .unwrap()
                .len(),
            4
        );
    }

    /// A package-sourced hook stages nothing rather than erroring —
    /// the policy gate already denies it, so this path just has nothing
    /// to do.
    #[test]
    fn package_sourced_hooks_stage_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Utf8Path::from_path(tmp.path()).unwrap();
        let hooks = vec![hook_with_activate(
            HookScript::try_external("a.sh").unwrap(),
            Source::Package {
                name: "helix".into(),
            },
        )];
        assert!(
            stage_external_scripts(&hooks, &anchors(root))
                .unwrap()
                .is_empty()
        );
    }
}
