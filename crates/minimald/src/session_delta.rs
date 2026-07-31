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

/// Assesses what a destroy of the workspace at `root` would permanently
/// lose, for the `SessionDelta` RPC.
///
/// Precision ladder: when the workspace has a root `.git` and git answers,
/// the report is VCS-exact — uncommitted files and unpushed commits, so a
/// fully committed-and-pushed tree is proven clean even though it differs
/// from the activation baseline. Otherwise it falls back to the
/// activation-delta walk (which may include committed work), and when that
/// too is unavailable it says so. Best-effort throughout: every arm is
/// bounded by [`WALK_TIMEOUT`] and failures degrade down the ladder, never
/// error.
pub(crate) async fn assess(
    root: PathBuf,
    delta: Option<Arc<DeltaSource>>,
) -> minimald_rpc::SessionDeltaResponse {
    if let Some(vcs) = vcs_at_risk(&root).await {
        return vcs;
    }
    match delta {
        Some(delta) => match delta.changed_files().await {
            Some(rows) => minimald_rpc::SessionDeltaResponse::ChangedSinceActivation { rows },
            None => minimald_rpc::SessionDeltaResponse::Unavailable,
        },
        None => minimald_rpc::SessionDeltaResponse::Unavailable,
    }
}

/// VCS-mode assessment: `Some` only when `root` has a `.git` entry and both
/// git commands succeed in time; any failure (no git binary, a `.git` that
/// isn't a real repository, a timeout) yields `None` and the caller falls
/// back to the activation delta.
async fn vcs_at_risk(root: &Path) -> Option<minimald_rpc::SessionDeltaResponse> {
    if !root.join(".git").exists() {
        return None;
    }
    let status = run_git(root, &["status", "--porcelain=v1", "-unormal"]).await?;
    let count = run_git(
        root,
        &["rev-list", "--branches", "--not", "--remotes", "--count"],
    )
    .await?;
    Some(minimald_rpc::SessionDeltaResponse::Vcs {
        uncommitted: parse_porcelain(&status),
        unpushed_commits: count.trim().parse::<u64>().ok()?,
    })
}

/// Runs one git command against `root`'s tree, mirroring the `checkouts`
/// crate's shell-out precedent, on the blocking pool with the walk timeout.
/// `None` on spawn failure (no git binary), non-zero exit, non-UTF-8
/// output, or timeout — the abandoned process keeps running detached until
/// it finishes; nothing awaits it.
async fn run_git(root: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-C").arg(root).args(args);
    let task = tokio::task::spawn_blocking(move || cmd.output());
    let out = tokio::time::timeout(WALK_TIMEOUT, task)
        .await
        .ok()?
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Renders `git status --porcelain=v1` output as the delta's `A/M/D <path>`
/// rows, sorted by path: untracked (`??`) and added entries render as `A`,
/// deletions in either column as `D`, everything else as `M`. Rename/copy
/// entries render their new path.
fn parse_porcelain(status: &str) -> Vec<String> {
    let mut rows = Vec::new();
    for line in status.lines() {
        if line.len() < 4 {
            continue;
        }
        // Format: `XY <path>` — X the index column, Y the worktree column,
        // both ASCII, so the byte split is a char split.
        let (code, path) = line.split_at(3);
        let path = match path.split_once(" -> ") {
            Some((_, new)) => new,
            None => path,
        };
        let marker = if code.starts_with("??") {
            'A'
        } else if code[..2].contains('D') {
            'D'
        } else if code[..2].contains('A') {
            'A'
        } else {
            'M'
        };
        rows.push(format!("{marker} {path}"));
    }
    rows.sort_by(|a, b| a[2..].cmp(&b[2..]));
    rows
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

    /// Porcelain-v1 status codes map onto the delta's `A/M/D` marker style,
    /// sorted by path: untracked and added are `A`, deletions in either
    /// column are `D`, edits (staged or not) are `M`, and renames render
    /// their new path.
    #[test]
    fn parse_porcelain_maps_status_codes_to_delta_markers() {
        let status = "?? new.txt\n M edited.txt\nM  staged.txt\nD  gone.txt\n\
                      A  staged-add.txt\nR  old.txt -> renamed.txt\n";
        assert_eq!(
            parse_porcelain(status),
            vec![
                "M edited.txt".to_string(),
                "D gone.txt".to_string(),
                "A new.txt".to_string(),
                "M renamed.txt".to_string(),
                "A staged-add.txt".to_string(),
                "M staged.txt".to_string(),
            ],
        );
        assert!(parse_porcelain("").is_empty());
    }

    /// The VCS assessment ladder against a real repository: committed but
    /// unpushed work is at risk via the commit count, pushing makes the
    /// tree proven-clean, new work lists as uncommitted — and a `.git`
    /// that is not a repository (the e2e seed's marker dir) declines VCS
    /// mode so the caller falls back to the activation delta.
    #[tokio::test]
    async fn vcs_at_risk_distinguishes_clean_uncommitted_and_unpushed() {
        use minimald_rpc::SessionDeltaResponse as R;

        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: no git binary in this environment");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "tracked.txt", "v1");
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-b", "main"]);
        git(&["add", "-A"]);
        git(&["commit", "-m", "initial"]);

        // Committed but nowhere pushed: the commit itself is at risk.
        assert_eq!(
            vcs_at_risk(root).await,
            Some(R::Vcs {
                uncommitted: vec![],
                unpushed_commits: 1
            }),
        );

        // Push to a bare remote: proven clean.
        let bare = tempfile::tempdir().unwrap();
        let init = std::process::Command::new("git")
            .args(["init", "--bare", "-b", "main"])
            .arg(bare.path())
            .output()
            .unwrap();
        assert!(init.status.success(), "git init --bare failed");
        git(&["remote", "add", "origin", bare.path().to_str().unwrap()]);
        git(&["push", "origin", "main"]);
        assert_eq!(
            vcs_at_risk(root).await,
            Some(R::Vcs {
                uncommitted: vec![],
                unpushed_commits: 0
            }),
        );

        // New work since: an edit and an untracked file list as at risk.
        write(root, "tracked.txt", "v2");
        write(root, "wip.txt", "unsaved");
        assert_eq!(
            vcs_at_risk(root).await,
            Some(R::Vcs {
                uncommitted: vec!["M tracked.txt".to_string(), "A wip.txt".to_string()],
                unpushed_commits: 0
            }),
        );

        // An empty `.git` marker dir is not a repository: VCS mode declines.
        let fake = tempfile::tempdir().unwrap();
        std::fs::create_dir(fake.path().join(".git")).unwrap();
        assert_eq!(vcs_at_risk(fake.path()).await, None);
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
