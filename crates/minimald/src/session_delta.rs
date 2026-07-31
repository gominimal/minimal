//! Workspace-change detection for the shell-exit prompt.
//!
//! A [`DeltaSource`] pairs a baseline snapshot of the session's workspace,
//! taken before the session process launches, with the workspace root, so the
//! shell-exit prompt can lead with the files that changed during the session.
//! Detection is best-effort throughout: a workspace that cannot be walked
//! yields no [`DeltaSource`] at all, and the prompt falls back to its plain
//! form rather than blocking or failing teardown.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// Per-file signature used to detect changes: byte length plus mtime. Content
/// hashing would be exact but scales with workspace bytes, not entries; a
/// (len, mtime) pair is metadata-only and catches every edit a filesystem
/// timestamps.
type Sig = (u64, Option<SystemTime>);

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
    /// Takes the baseline snapshot of `root` on the blocking pool. Returns
    /// `None` when the workspace cannot be walked — change detection is then
    /// disabled for the session's lifetime rather than misreporting.
    pub(crate) async fn arm(root: PathBuf) -> Option<Arc<Self>> {
        let walk_root = root.clone();
        let baseline = tokio::task::spawn_blocking(move || snapshot(&walk_root))
            .await
            .ok()?
            .ok()?;
        Some(Arc::new(Self { root, baseline }))
    }

    /// Re-walks the workspace and renders one row per changed file, sorted by
    /// path: `A <path>` added, `M <path>` modified, `D <path>` deleted. An
    /// empty vec means nothing changed; `None` means the delta could not be
    /// computed and the caller should not claim anything about the workspace.
    pub(crate) async fn changed_files(self: &Arc<Self>) -> Option<Vec<String>> {
        let src = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let now = snapshot(&src.root).ok()?;
            Some(diff(&src.baseline, &now))
        })
        .await
        .ok()
        .flatten()
    }
}

/// Walks `root` without following symlinks, recording every non-directory
/// entry keyed by its root-relative path. Unreadable subdirectories fail the
/// whole snapshot: a partial baseline would misreport their contents as
/// added later.
fn snapshot(root: &Path) -> std::io::Result<Snapshot> {
    let mut out = Snapshot::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let path = entry.path();
            if meta.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .expect("walk stays under root")
                    .to_path_buf();
                out.insert(rel, (meta.len(), meta.modified().ok()));
            }
        }
    }
    Ok(out)
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
}
