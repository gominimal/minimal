//! Walk patch sources and enumerate matched files.

use camino::{Utf8Path, Utf8PathBuf};

use paths::{HostAbsPath, SandboxRelPath};

use crate::core::compose::ComposeError;
use crate::core::primitives::{FileSet, PatchDest, PatchError};
use crate::core::source::{Provenanced, Source};

/// Per-file entry derived from a [`Patch`] after its source
/// [`FileSet`] is walked. `link_path` is `Some` only when symlink
/// resolution produced a distinct path (i.e. `follow_symlinks: true`
/// and the walker traversed a symlink). Policy matching runs
/// against both when present; deny on either wins.
///
/// [`Patch`]: crate::core::primitives::Patch
/// [`FileSet`]: crate::core::primitives::FileSet
pub(crate) struct PatchFile {
    /// `Some` when the file was reached via a symlink that resolved
    /// to a distinct canonical target; `None` when no link is in play
    /// (the common case).
    pub(crate) link_path: Option<HostAbsPath>,
    /// Canonical absolute path the link resolves to. Always the path
    /// used for actual host I/O.
    pub(crate) target_path: HostAbsPath,
    /// Destination for this file, relative to the sandbox user's home
    /// directory. Derived from the user-facing path (link when present,
    /// target otherwise) relative to the patch's walk root, joined
    /// under the patch's `dest`.
    pub(crate) dest: SandboxRelPath,
    /// The original patch's provenance.
    pub(crate) provenance: Source,
}

impl PatchFile {
    /// The path the user "asked for" — the link form when distinct
    /// from the target, otherwise the target itself. Used for
    /// user-facing display (error messages, prompt context) and dest
    /// computation.
    pub(crate) fn user_facing(&self) -> &HostAbsPath {
        self.link_path.as_ref().unwrap_or(&self.target_path)
    }
}

impl Provenanced for PatchFile {
    fn source(&self) -> &Source {
        &self.provenance
    }
}

/// A patch whose source string has been expanded into a concrete
/// [`FileSet`] against the session's resolved vars. Internal handoff
/// type between `expand_patch_sources` and [`enumerate_patch_files`].
pub(crate) struct ExpandedProvenancedPatch {
    pub(crate) source: FileSet,
    pub(crate) dest: PatchDest,
    pub(crate) provenance: Source,
    /// Whether the walker should follow symlinks for this patch.
    /// Resolved by [`expand_patch_sources`] from the compose default
    /// and any per-patch override carried on [`ProvenancedPatch`], so
    /// `enumerate_patch_files` reads it per-item and doesn't need to
    /// consult any sidecar map.
    ///
    /// [`expand_patch_sources`]: crate::core::compose::expand_patch_sources
    /// [`ProvenancedPatch`]: crate::core::source::ProvenancedPatch
    pub(crate) follow_symlinks: bool,
}

/// Walk each pre-expanded patch's `FileSet` and produce one
/// [`PatchFile`] per matched host file.
///
/// **Per-item follow behavior.** Each [`ExpandedProvenancedPatch`]
/// carries its own resolved `follow_symlinks` bool — the walker
/// reads it per iteration, so two patches in the same call can
/// drive different follow behavior.
///
/// **Path safety:** every yielded file is canonicalized via
/// [`std::fs::canonicalize`] when the item's `follow_symlinks` is
/// true, so the symlink target is known and dual-path policy checks
/// become possible downstream. The walk itself starts from the
/// un-canonical `walk_root` so the yielded link paths preserve the
/// user's structural intent (matching against the original glob
/// pattern and driving dest computation).
///
/// `..` and `.` components are rejected at expansion time, so they
/// can't appear in the walk root or yielded paths. A non-existent
/// walk root surfaces as a walkdir error on first iteration.
///
/// A patch whose walk root doesn't exist is *not* a hard error —
/// a `tracing::warn!` names the missing path and the patch is
/// dropped, so a loadout that opportunistically patches something
/// like `~/dotfiles/helix/` doesn't fail activation on a host that
/// doesn't have that dotfile tree. Other walk failures (permission
/// denied, non-UTF-8 paths, etc.) still accumulate and surface as
/// [`ComposeError::PatchWalk`].
pub(crate) fn enumerate_patch_files(
    items: Vec<ExpandedProvenancedPatch>,
) -> Result<Vec<PatchFile>, ComposeError> {
    let mut out = Vec::new();
    let mut accumulated_errors = Vec::new();
    for pp in items {
        let follow_symlinks = pp.follow_symlinks;
        let Some(walk_root) = pp.source.walk_root() else {
            accumulated_errors.push(PatchError::NoWalkRoot {
                pattern: pp.source.pattern().to_owned(),
            });
            continue;
        };
        let walk_root_path = walk_root.as_utf8_path().to_path_buf();
        let dest_root = pp.dest.as_sandbox_path().as_utf8_path();
        for entry_result in
            walkdir::WalkDir::new(walk_root_path.as_std_path()).follow_links(follow_symlinks)
        {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(source) => {
                    // `NotFound` is treated as "user doesn't have
                    // this on their host" — warn and move on.
                    // `walkdir::Error::path()` reports the specific
                    // item that failed, which is either the walk
                    // root itself (the common case) or a subitem
                    // that vanished mid-walk (the race). Log both
                    // the pattern's declared root and the failing
                    // path so operators can distinguish. `.io_error()`
                    // returns `None` for the loop-detection variant;
                    // those still fail hard.
                    if source
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    {
                        tracing::warn!(
                            source_pattern = %pp.source.pattern(),
                            walk_root = %walk_root_path,
                            missing_path = ?source.path(),
                            "patch source not found on host filesystem; dropping"
                        );
                        continue;
                    }
                    accumulated_errors.push(PatchError::WalkFailure {
                        root: walk_root_path.clone(),
                        source,
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let link_path = match Utf8PathBuf::from_path_buf(entry.into_path()) {
                Ok(p) => p,
                Err(p) => {
                    accumulated_errors.push(PatchError::NonUtf8Path {
                        path_lossy: p.to_string_lossy().into_owned(),
                    });
                    continue;
                }
            };
            if !pp.source.is_match(&link_path) {
                continue;
            }
            // Walker-yielded paths are descended from `walk_root_path`,
            // which is an absolute path because expansion already
            // rejected anything else. `new_unchecked` is sound.
            let walker_path = HostAbsPath::new_unchecked(link_path.clone());
            // When `follow_symlinks` is true, canonicalize each match
            // to obtain the symlink target. Default mode skips this:
            // walkdir filters symlinks-to-files at the `is_file()`
            // check above, so the walker-yielded path *is* the
            // canonical form (or near enough), and canonicalizing
            // would swap in OS-level prefix-symlink forms (e.g.
            // macOS's `/tmp` → `/private/tmp`) that policy patterns
            // don't anticipate.
            let (link_path, target_path) = if follow_symlinks {
                let canonical = match canonicalize_utf8(&link_path) {
                    Ok(p) => p,
                    Err(e) => {
                        accumulated_errors.push(e);
                        continue;
                    }
                };
                let target = HostAbsPath::new_unchecked(canonical);
                // `Some(link)` only if the canonical target actually
                // differs from the walker path. For non-symlink
                // files, target == walker_path and we record None.
                let link = if target.as_utf8_path() == walker_path.as_utf8_path() {
                    None
                } else {
                    Some(walker_path)
                };
                (link, target)
            } else {
                (None, walker_path)
            };
            let user_facing = link_path.as_ref().unwrap_or(&target_path);
            let dest = compute_dest(user_facing.as_utf8_path(), &walk_root_path, dest_root);
            out.push(PatchFile {
                link_path,
                target_path,
                dest,
                provenance: pp.provenance.clone(),
            });
        }
    }
    if accumulated_errors.is_empty() {
        return Ok(out);
    }
    Err(ComposeError::PatchWalk {
        sources: accumulated_errors,
    })
}

/// [`std::fs::canonicalize`] with UTF-8 enforcement.
///
/// Returns [`PatchError::CanonicalizeFailure`] for any IO
/// error — the path doesn't exist, the process can't traverse the
/// prefix, or (most subtly) the path is a symlink loop. Returns
/// [`PatchError::NonUtf8CanonicalPath`] if the canonical
/// form contains non-UTF-8 bytes (e.g. a parent directory with a
/// non-UTF-8 name).
pub(crate) fn canonicalize_utf8(path: &Utf8Path) -> Result<Utf8PathBuf, PatchError> {
    match std::fs::canonicalize(path.as_std_path()) {
        Ok(p) => Utf8PathBuf::from_path_buf(p).map_err(|p| PatchError::NonUtf8CanonicalPath {
            path_lossy: p.to_string_lossy().into_owned(),
        }),
        Err(source) => Err(PatchError::CanonicalizeFailure {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Compute the destination for a single source file under a patch's
/// `dest`. The result is relative to the sandbox user's home directory,
/// inherited from the patch's [`PatchDest`].
///
/// - **Single-file patches** (`walk_root == source_path`): `dest` is
///   used verbatim.
/// - **Multi-file patches**: the source path's components beneath
///   `walk_root` are appended to `dest`. The strip is path-component
///   aware (camino's `strip_prefix`), so `/etc/xdg` will not match
///   `/etc/xdgfoo/`.
///
/// # Invariants (panic conditions)
///
/// Both panics describe internal contracts that
/// `enumerate_patch_files` is responsible for upholding. They should
/// be unreachable in normal operation; if one fires, it indicates a
/// bug in this crate.
///
/// 1. `walk_root` must be a path-component prefix of `source_path`.
///    `enumerate_patch_files` walks `walk_root`, so every file it
///    yields is a descendant.
/// 2. `dest_root` is relative (it came from a [`SandboxRelPath`]) and
///    `suffix` is relative (it's the stripped tail), so the join
///    cannot produce an absolute path.
pub(crate) fn compute_dest(
    source_path: &Utf8Path,
    walk_root: &Utf8Path,
    dest_root: &Utf8Path,
) -> SandboxRelPath {
    let root_path = walk_root;
    let joined: Utf8PathBuf = if source_path == root_path {
        dest_root.to_path_buf()
    } else {
        let suffix = source_path.strip_prefix(root_path).unwrap_or_else(|_| {
            panic!("compose invariant: source path {source_path} is outside walk root {root_path}")
        });
        if dest_root.as_str().is_empty() {
            suffix.to_path_buf()
        } else {
            dest_root.join(suffix)
        }
    };
    SandboxRelPath::try_new(joined)
        .expect("compose invariant: dest_root and suffix are both relative")
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // compute_dest invariants
    // =================================================================

    #[test]
    fn multi_file_appends_relative_path() {
        let source = Utf8Path::new("/etc/xdg/sub/file.conf");
        let walk_root = Utf8Path::new("/etc/xdg");
        let dest = compute_dest(source, walk_root, Utf8Path::new("config"));
        assert_eq!(dest.as_str(), "config/sub/file.conf");
    }

    #[test]
    fn single_file_uses_dest_verbatim() {
        let source = Utf8Path::new("/home/u/file.conf");
        let walk_root = Utf8Path::new("/home/u/file.conf");
        let dest = compute_dest(source, walk_root, Utf8Path::new("etc/foo.conf"));
        assert_eq!(dest.as_str(), "etc/foo.conf");
    }

    /// Regression for component-boundary strip — `/etc/xdg` must
    /// not match `/etc/xdgfoo/bar`. Compose invariant; we panic
    /// rather than produce a garbage dest.
    #[test]
    #[should_panic(expected = "outside walk root")]
    fn panics_on_source_outside_walk_root() {
        let source = Utf8Path::new("/etc/xdgfoo/bar");
        let walk_root = Utf8Path::new("/etc/xdg");
        let _ = compute_dest(source, walk_root, Utf8Path::new("dst"));
    }

    // =================================================================
    // FileSet::resolve direct (unit, not via the gate)
    // =================================================================

    #[test]
    fn fileset_resolve_errors_when_pattern_has_no_walk_root() {
        let fs = crate::core::primitives::FileSet::try_new("**/*.pem").unwrap();
        let (paths, errors) = fs.resolve(false);
        assert!(paths.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(
            matches!(
                &errors[0],
                crate::core::primitives::PatchError::NoWalkRoot { .. }
            ),
            "got: {:?}",
            errors[0],
        );
    }

    // =================================================================
    // Per-patch `follow_symlinks` — each item drives its own walker
    // =================================================================

    /// Two patches in a single `enumerate_patch_files` call: one
    /// follows a symlink, the other doesn't. Verifies the walker
    /// reads the bool per-item rather than from a call-level arg.
    #[test]
    fn per_patch_follow_symlinks_drives_each_walker_independently() {
        use crate::core::primitives::{FileSet, PatchDest};
        use crate::core::source::Source;

        let tmp = tempfile::tempdir().unwrap();
        // Canonicalize upfront to sidestep macOS's `/tmp -> /private/tmp`
        // prefix symlink. Without this, `canonicalize_utf8` inside
        // `enumerate_patch_files` returns the `/private/tmp/...`
        // form for every file — including the plain files — so
        // `target != walker_path` fires spuriously and the assertion
        // "at least one entry has link_path = None" fails. Two
        // sibling symlink tests in compose.rs do the same thing for
        // the same reason.
        let root = Utf8PathBuf::from_path_buf(std::fs::canonicalize(tmp.path()).unwrap()).unwrap();
        // Two sibling dirs, each with one real file. Each dir also
        // contains a symlink named `link` pointing at a third dir's
        // real file. When follow_symlinks is on, we get 2 files
        // (target + link); when off, we get 1 (just the real file).
        let target_dir = root.join("target");
        std::fs::create_dir(target_dir.as_std_path()).unwrap();
        std::fs::write(target_dir.join("real.conf").as_std_path(), "t").unwrap();

        let follow_dir = root.join("follow");
        std::fs::create_dir(follow_dir.as_std_path()).unwrap();
        std::fs::write(follow_dir.join("real.conf").as_std_path(), "f").unwrap();
        std::os::unix::fs::symlink(
            target_dir.join("real.conf").as_std_path(),
            follow_dir.join("link.conf").as_std_path(),
        )
        .unwrap();

        let nofollow_dir = root.join("nofollow");
        std::fs::create_dir(nofollow_dir.as_std_path()).unwrap();
        std::fs::write(nofollow_dir.join("real.conf").as_std_path(), "n").unwrap();
        std::os::unix::fs::symlink(
            target_dir.join("real.conf").as_std_path(),
            nofollow_dir.join("link.conf").as_std_path(),
        )
        .unwrap();

        let items = vec![
            ExpandedProvenancedPatch {
                source: FileSet::try_new(format!("{}/*.conf", follow_dir.as_str())).unwrap(),
                dest: PatchDest::try_new("dest_follow").unwrap(),
                provenance: Source::UserLoadout {
                    name: "follow".to_string(),
                },
                follow_symlinks: true,
            },
            ExpandedProvenancedPatch {
                source: FileSet::try_new(format!("{}/*.conf", nofollow_dir.as_str())).unwrap(),
                dest: PatchDest::try_new("dest_nofollow").unwrap(),
                provenance: Source::UserLoadout {
                    name: "nofollow".to_string(),
                },
                follow_symlinks: false,
            },
        ];

        let files = enumerate_patch_files(items).unwrap();

        // Bucket by dest to identify which patch produced which.
        let follow_files: Vec<_> = files
            .iter()
            .filter(|f| f.dest.as_str().starts_with("dest_follow"))
            .collect();
        let nofollow_files: Vec<_> = files
            .iter()
            .filter(|f| f.dest.as_str().starts_with("dest_nofollow"))
            .collect();

        // Follow: two files (real.conf + link.conf as symlink to target).
        assert_eq!(
            follow_files.len(),
            2,
            "follow patch should yield real + link entries",
        );
        // A followed symlink populates `link_path`; the plain file
        // has `link_path = None`.
        assert!(follow_files.iter().any(|f| f.link_path.is_some()));
        assert!(follow_files.iter().any(|f| f.link_path.is_none()));

        // No-follow: just the single real file (walkdir skips the
        // symlink because `is_file()` on a symlink entry is false
        // when follow_links is off).
        assert_eq!(
            nofollow_files.len(),
            1,
            "no-follow patch should yield the real file only",
        );
        assert!(nofollow_files[0].link_path.is_none());
    }
}
