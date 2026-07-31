//! Workspace-change detection for the shell-exit prompt.
//!
//! A [`DeltaSource`] pairs a baseline snapshot of the session's workspace,
//! taken before the session process launches, with the workspace root, so the
//! shell-exit prompt can lead with the files that changed during the session.
//! Detection is best-effort throughout: both walks are bounded by
//! [`WALK_TIMEOUT`], and a workspace that cannot be walked in time yields no
//! [`DeltaSource`] (at activation) or no delta (at exit), so the prompt falls
//! back to its plain form rather than blocking or failing teardown.
//!
//! File comparison is exact for regular files up to [`DIGEST_CAP_BYTES`]:
//! their signatures carry a content digest, so a same-length edit that
//! preserves the modification time is still reported. Above the cap the
//! comparison falls back to (length, mtime).
//!
//! The workspace root's `.git` directory is excluded from both walks: the
//! delta reports working-tree files, and git-internal churn (index, refs,
//! objects) no longer appears in it — without the exclusion, any in-session
//! git operation floods the capped row list with `.git` noise. Only the
//! root-level `.git` is skipped; a nested one (a vendored subrepo) is
//! ordinary workspace content.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use walkdir::WalkDir;

/// Upper bound on either workspace walk (the baseline at activation, the
/// re-walk at exit). On expiry the walk's result is discarded: arming yields
/// no [`DeltaSource`], and the exit prompt renders its plain form — neither
/// activation nor teardown ever blocks on a wedged or oversized workspace.
/// The abandoned walk keeps running on the blocking pool until it finishes;
/// nothing awaits it.
const WALK_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest file that gets a content digest in its signature. Above the cap
/// the digest is `None` and comparison falls back to (length, mtime):
/// hashing scales with workspace bytes rather than entries, and an unbounded
/// hash pass would blow [`WALK_TIMEOUT`] on large workspaces, while a
/// same-length, mtime-preserved edit to a multi-megabyte file is outside
/// this guard's realistic threat model.
const DIGEST_CAP_BYTES: u64 = 4 * 1024 * 1024;

/// Per-file signature used to detect changes: byte length, mtime, and — for
/// regular files up to [`DIGEST_CAP_BYTES`] — a blake3 content digest, so a
/// same-length mtime-preserved edit cannot masquerade as "no files changed".
/// Symlinks are signed by their own (link) metadata and carry no digest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sig {
    len: u64,
    mtime: Option<SystemTime>,
    digest: Option<blake3::Hash>,
}

/// Relative path -> signature for every regular file and symlink under the
/// root. Directories are traversal structure, not entries: an empty added
/// directory does not count as a change, matching what "files changed" means
/// to the person reading the prompt.
type Snapshot = BTreeMap<PathBuf, Sig>;

/// A workspace root plus the baseline snapshot taken before the session
/// process launched. Shared with each attached binding so the shell-exit
/// prompt can compute the delta at exit time.
pub(crate) struct DeltaSource {
    root: PathBuf,
    baseline: Snapshot,
}

impl DeltaSource {
    /// Takes the baseline snapshot of `root` on the blocking pool, bounded by
    /// [`WALK_TIMEOUT`]. Returns `None` when the workspace cannot be walked
    /// in time — change detection is then disabled for the session's lifetime
    /// rather than misreporting or stalling activation.
    pub(crate) async fn arm(root: PathBuf) -> Option<Arc<Self>> {
        let walk_root = root.clone();
        let walk = tokio::task::spawn_blocking(move || snapshot(&walk_root));
        let baseline = tokio::time::timeout(WALK_TIMEOUT, walk)
            .await
            .ok()?
            .ok()?
            .ok()?;
        Some(Arc::new(Self { root, baseline }))
    }

    /// Re-walks the workspace and renders one row per changed file, sorted by
    /// path: `A <path>` added, `M <path>` modified, `D <path>` deleted. An
    /// empty vec means nothing changed; `None` means the delta could not be
    /// computed — including a re-walk that overruns [`WALK_TIMEOUT`] — and
    /// the caller should not claim anything about the workspace.
    pub(crate) async fn changed_files(self: &Arc<Self>) -> Option<Vec<String>> {
        let src = Arc::clone(self);
        let walk = tokio::task::spawn_blocking(move || {
            let now = snapshot(&src.root).ok()?;
            Some(diff(&src.baseline, &now))
        });
        tokio::time::timeout(WALK_TIMEOUT, walk)
            .await
            .ok()?
            .ok()
            .flatten()
    }
}

/// Walks `root` without following symlinks (walkdir's default), recording
/// every non-directory entry keyed by its root-relative path. A symlink is
/// recorded via its own metadata — never traversed, even when it points at a
/// directory — so links out of the root or link cycles cannot widen or wedge
/// the walk. The root-level `.git` directory is skipped entirely (see the
/// module docs for the tradeoff). Unreadable entries fail the whole
/// snapshot: a partial baseline would misreport their contents as added
/// later.
fn snapshot(root: &Path) -> std::io::Result<Snapshot> {
    let mut out = Snapshot::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !(e.depth() == 1 && e.file_name() == ".git"))
    {
        let entry = entry?;
        if entry.file_type().is_dir() {
            continue;
        }
        // With symlink-following off, this is the entry's own (symlink)
        // metadata, matching what the walk saw rather than the link target.
        let meta = entry.metadata()?;
        let digest = if entry.file_type().is_file() && meta.len() <= DIGEST_CAP_BYTES {
            Some(hash_file(entry.path())?)
        } else {
            None
        };
        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walk stays under root")
            .to_path_buf();
        out.insert(
            rel,
            Sig {
                len: meta.len(),
                mtime: meta.modified().ok(),
                digest,
            },
        );
    }
    Ok(out)
}

fn hash_file(path: &Path) -> std::io::Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(path)?)?;
    Ok(hasher.finalize())
}

fn diff(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let mut rows = Vec::new();
    for (path, sig) in after {
        match before.get(path) {
            None => rows.push(format!("A {}", path.display())),
            Some(old) if old != sig => rows.push(format!("M {}", path.display())),
            Some(_) => {}
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            rows.push(format!("D {}", path.display()));
        }
    }
    rows.sort_by(|a, b| a[2..].cmp(&b[2..]));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn diff_reports_adds_modifies_and_deletes_sorted_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "kept.txt", "same");
        write(root, "sub/edited.txt", "v1");
        write(root, "removed.txt", "bye");

        let before = snapshot(root).unwrap();
        write(root, "sub/edited.txt", "v2 longer");
        write(root, "added.txt", "new");
        std::fs::remove_file(root.join("removed.txt")).unwrap();
        let after = snapshot(root).unwrap();

        assert_eq!(
            diff(&before, &after),
            vec![
                "A added.txt".to_string(),
                "D removed.txt".to_string(),
                "M sub/edited.txt".to_string(),
            ],
        );
    }

    #[test]
    fn unchanged_workspace_diffs_empty() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/b.txt", "x");
        let snap = snapshot(dir.path()).unwrap();
        assert!(diff(&snap, &snapshot(dir.path()).unwrap()).is_empty());
        assert_eq!(snap.len(), 1);
    }

    #[test]
    fn empty_added_directory_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let before = snapshot(dir.path()).unwrap();
        std::fs::create_dir(dir.path().join("newdir")).unwrap();
        assert!(diff(&before, &snapshot(dir.path()).unwrap()).is_empty());
    }

    /// The CodeRabbit regression: an edit that keeps the byte length AND
    /// restores the mtime must still be reported, via the content digest.
    #[test]
    fn same_length_mtime_preserved_edit_is_reported_as_modified() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "sneaky.txt", "aaaa");
        let orig_mtime = std::fs::metadata(root.join("sneaky.txt"))
            .unwrap()
            .modified()
            .unwrap();
        let before = snapshot(root).unwrap();

        write(root, "sneaky.txt", "bbbb");
        let file = std::fs::File::options()
            .write(true)
            .open(root.join("sneaky.txt"))
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(orig_mtime))
            .unwrap();
        drop(file);
        // The metadata guard must be genuinely defeated for this test to
        // prove anything: same length, same mtime as the baseline.
        let meta = std::fs::metadata(root.join("sneaky.txt")).unwrap();
        assert_eq!(meta.len(), 4);
        assert_eq!(meta.modified().unwrap(), orig_mtime);

        assert_eq!(
            diff(&before, &snapshot(root).unwrap()),
            vec!["M sneaky.txt".to_string()],
        );
    }

    /// The root `.git` directory is invisible to the walk: git-internal churn
    /// must not appear in the delta, while a working-tree change — and a
    /// nested (vendored) `.git` — still must.
    #[test]
    fn root_git_dir_is_excluded_from_the_delta() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, ".git/index", "v1");
        write(root, "tracked.txt", "v1");
        let before = snapshot(root).unwrap();
        assert!(
            !before.keys().any(|p| p.starts_with(".git")),
            "the baseline must not contain root .git entries",
        );

        write(root, ".git/index", "v2 grown");
        write(root, ".git/objects/aa/blob", "obj");
        write(root, "tracked.txt", "v2 longer");
        write(root, "vendor/dep/.git/config", "vendored");
        let after = snapshot(root).unwrap();

        assert_eq!(
            diff(&before, &after),
            vec![
                "M tracked.txt".to_string(),
                "A vendor/dep/.git/config".to_string(),
            ],
        );
    }

    /// Symlinks are entries, never traversal: a link out of the root must not
    /// pull outside files into the snapshot, and a link cycle must not wedge
    /// the walk.
    #[test]
    fn symlinks_are_recorded_but_never_traversed() {
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "secret.txt", "outside");

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "real.txt", "inside");
        std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
        std::os::unix::fs::symlink(root, root.join("cycle")).unwrap();

        let snap = snapshot(root).unwrap();
        let paths: Vec<_> = snap.keys().cloned().collect();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("cycle"),
                PathBuf::from("escape"),
                PathBuf::from("real.txt"),
            ],
        );
        // Nothing behind the links was walked.
        assert!(!snap.keys().any(|p| p.to_string_lossy().contains("secret")));
    }
}
