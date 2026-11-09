//! Reclaiming local disk: cache entries nothing has read in a while, plus the
//! execution directories left behind by processes that have since exited.
//!
//! [`CleanCache`] deliberately knows nothing about where its inputs come from.
//! The caller decides which entries are worth keeping (for `mip cache clean`,
//! everything the current project's tasks and stack need) and which directories
//! to sweep, so cleaning needs no project context and can run anywhere the
//! local cache does.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::anyhow;
use common::SpecHash;
use futures::channel::mpsc::UnboundedSender;
use lcache::{Cache, LocalDir};

use crate::Error;

/// A kind of execution directory [`CleanCache`] sweeps, named for how it reads
/// in a rendered event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleKind {
    /// A build sandbox.
    Sandbox,
    /// A task execution directory.
    Task,
    /// A temporary directory used while an artifact was being built.
    TempDir,
}

impl StaleKind {
    /// The word naming this kind in a rendered event.
    fn label(self) -> &'static str {
        match self {
            StaleKind::Sandbox => "sandbox",
            StaleKind::Task => "task",
            StaleKind::TempDir => "tempdir",
        }
    }
}

/// Progress emitted while cleaning. [`CleanCache`] never prints; every consumer
/// renders these itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanEvent {
    /// A cache entry was deleted. `name` is the entry's recorded identity,
    /// absent when its metadata could not be read.
    Deleted {
        hash: SpecHash,
        name: Option<String>,
    },
    /// A leftover execution directory whose owning process is gone was removed.
    Swept { kind: StaleKind, name: String },
}

impl CleanEvent {
    /// This event as one human-readable log line. Shared so every transport
    /// reports a clean identically.
    pub fn render(&self) -> String {
        match self {
            CleanEvent::Deleted { hash, name } => match name {
                Some(name) => format!("Deleting {} [{}]", name, hash.0),
                None => format!("Deleting Object [{}]", hash.0),
            },
            CleanEvent::Swept { kind, name } => {
                format!("Cleaning up stale {} {}", kind.label(), name)
            }
        }
    }
}

/// What a run of [`CleanCache`] removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanReport {
    /// Cache entries deleted.
    pub entries: usize,
    /// Leftover execution directories removed.
    pub dirs: usize,
}

/// Deletes cache entries whose last recorded read is older than `older_than` —
/// or that have no recorded read at all — then removes the leftover execution
/// directories under `sweep` whose owner is gone.
///
/// Entries in `keep` are never deleted, whatever their age, and directories
/// stamped with `daemon_id` are never swept.
pub struct CleanCache {
    /// Only delete entries last read at least this long ago.
    pub older_than: Duration,
    /// Entries to keep regardless of age.
    pub keep: HashSet<SpecHash>,
    /// Directories whose per-owner subdirectories to sweep, each labelled with
    /// what it holds.
    pub sweep: Vec<(StaleKind, PathBuf)>,
    /// The caller's own `daemon_id`, when it runs under one. Directories
    /// stamped with it are this daemon's live work and are left alone — see
    /// [`owner_is_gone`].
    pub daemon_id: Option<String>,
    /// Best-effort progress reporting; a hung-up receiver must never fail the
    /// clean.
    pub events: Option<UnboundedSender<CleanEvent>>,
}

impl CleanCache {
    /// Runs the clean. Every step is blocking filesystem work, so an async
    /// caller should `spawn_blocking` this.
    #[tracing::instrument(skip_all, fields(older_than = ?self.older_than), err)]
    pub fn run(&self, cache: &Cache<LocalDir>) -> Result<CleanReport, Error> {
        let cutoff = SystemTime::now()
            .checked_sub(self.older_than)
            .ok_or_else(|| {
                anyhow!(
                    "`older_than` of {:?} reaches back past the unix epoch",
                    self.older_than
                )
            })?;

        let atimes = cache
            .atimes()
            .map_err(|e| anyhow!("reading the cache's access log: {e}"))?;

        // Collected up front: deleting an entry removes the very directory
        // `iter_entries` is walking to find the next one.
        let stale: Vec<SpecHash> = cache
            .iter_entries()
            .filter(|hash| !self.keep.contains(hash))
            .filter(|hash| atimes.last_read(hash).is_none_or(|last| last < cutoff))
            .collect();

        let mut report = CleanReport::default();
        for hash in stale {
            let name = cache
                .read_meta(&hash)
                .ok()
                .map(|meta| meta.inner.to_string());
            self.emit(CleanEvent::Deleted {
                hash: hash.clone(),
                name,
            });
            cache.invalidate_dir(&hash)?;
            report.entries += 1;
        }

        // Liveness is `/proc/<pid>`, so without procfs every directory looks
        // orphaned. Skip the sweep there rather than delete live state.
        if !self.sweep.is_empty() && !Path::new("/proc/self").exists() {
            tracing::warn!("no procfs mounted; skipping the stale-directory sweep");
            return Ok(report);
        }

        for (kind, dir) in &self.sweep {
            report.dirs += self.sweep_dir(*kind, dir)?;
        }

        Ok(report)
    }

    /// Removes every subdirectory of `dir` whose trailing `-<owner>` names an
    /// owner that is gone, returning how many went.
    fn sweep_dir(&self, kind: StaleKind, dir: &Path) -> Result<usize, Error> {
        let now = SystemTime::now();
        let mut removed = 0;
        for entry in
            std::fs::read_dir(dir).map_err(|e| anyhow!("reading {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| anyhow!("reading an entry of {}: {e}", dir.display()))?;
            let name = entry.file_name();
            // A name that isn't utf-8 can't carry the `-<owner>` suffix either.
            let Some(name) = name.to_str() else { continue };
            // Only a build sandbox is judged by age: its build ends within
            // hours. A task directory holds a box's env, which can sit
            // untouched for days while still in use, so its age says nothing.
            // A sandbox's age is the newest time anywhere in it, not its own
            // directory's: a long build writes deep inside and leaves the top
            // level's time alone. The walk runs only for a name that could
            // otherwise go, and stops at the first recent entry.
            let path = entry.path();
            let last_touched = || match kind {
                StaleKind::Sandbox => newest_modified(&path, now.checked_sub(FOREIGN_OWNER_IDLE)?),
                StaleKind::Task | StaleKind::TempDir => None,
            };
            if !owner_is_gone(name, self.daemon_id.as_deref(), last_touched, now) {
                continue;
            }

            self.emit(CleanEvent::Swept {
                kind,
                name: name.to_string(),
            });
            common::remove_dir_all(entry.path())
                .map_err(|e| anyhow!("removing {}: {e}", entry.path().display()))?;
            removed += 1;
        }

        Ok(removed)
    }

    fn emit(&self, event: CleanEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.unbounded_send(event);
        }
    }
}

/// How long a directory stamped with another daemon's id must sit untouched
/// before a daemon reclaims it. Another live daemon's build finishes within
/// hours; a dead daemon's stamp never changes again, so a few days apart tells
/// the two cases apart without any way to ask the other daemon.
const FOREIGN_OWNER_IDLE: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// The newest modification time of `root` or anything under it, or `None`
/// when that can't be told: `root` itself or an entry under it can't be read
/// (one that vanished mid-walk is a sign of life). A directory the caller
/// may not list is skipped, its own time still counted. The walk stops at the
/// first time at or after `stop_at` and returns it; it never follows a
/// symlink or crosses onto another filesystem.
fn newest_modified(root: &Path, stop_at: SystemTime) -> Option<SystemTime> {
    use std::os::unix::fs::MetadataExt as _;

    let meta = std::fs::symlink_metadata(root).ok()?;
    let dev = meta.dev();
    let mut newest = meta.modified().ok()?;
    let mut dirs = if meta.is_dir() {
        vec![root.to_path_buf()]
    } else {
        Vec::new()
    };
    while let Some(dir) = dirs.pop() {
        if newest >= stop_at {
            break;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
            Err(_) => return None,
        };
        for entry in entries {
            let entry = entry.ok()?;
            // `DirEntry::metadata` does not follow a symlink.
            let meta = entry.metadata().ok()?;
            newest = newest.max(meta.modified().ok()?);
            if meta.is_dir() && meta.dev() == dev {
                dirs.push(entry.path());
            }
        }
    }
    Some(newest)
}

/// Whether `name`'s trailing `-<owner>` marks work nobody is doing any more.
///
/// The stamp is a pid, or — when the work ran under a daemon — that daemon's
/// `daemon_id` in the pid's place (`sandbox::Config::daemon_id`). So:
///
/// - our own `daemon_id`: never. That is this daemon's live work, and the id is
///   a random alphanumeric that can come out all-digits and read as a perfectly
///   plausible dead pid — without this check a daemon eventually reclaims a
///   sandbox out from under itself.
/// - a pid with no `/proc` entry: gone, reclaim it.
/// - another daemon's id, judged by a daemon (`daemon_id` is set), on a
///   directory `sandbox` named (`<name>-<timestamp>-<attempt>-<id>`) whose
///   `last_touched` time is [`FOREIGN_OWNER_IDLE`] or more before `now`: gone.
///   Every daemon gets a fresh id, so a restart leaves the old one's finished
///   sandboxes stamped with an id nobody will clear; left alone, they piled
///   up without bound (gominimal/minimal#1373). No file says whether another
///   daemon id is still running, so the newest time anywhere in the sandbox
///   stands in: a live build writes inside it. `last_touched` is asked only
///   here, as it may walk the whole sandbox; it answers `None` for a
///   directory that must not be judged by age, or whose age can't be told.
/// - anything else — a live pid, a recent foreign id, a name nobody stamped:
///   left alone. Not ours to judge.
fn owner_is_gone(
    name: &str,
    daemon_id: Option<&str>,
    last_touched: impl FnOnce() -> Option<SystemTime>,
    now: SystemTime,
) -> bool {
    let Some((_, owner)) = name.rsplit_once('-') else {
        return false;
    };
    if Some(owner) == daemon_id {
        return false;
    }
    if owner.parse::<u32>().is_err() {
        let mut stamp = name.rsplitn(4, '-').skip(1);
        let sandbox_named = stamp.next().is_some_and(|a| a.parse::<u32>().is_ok())
            && stamp.next().is_some_and(|t| t.parse::<u64>().is_ok());
        return daemon_id.is_some()
            && sandbox_named
            && last_touched()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|idle| idle >= FOREIGN_OWNER_IDLE);
    }

    matches!(std::fs::exists(format!("/proc/{owner}")), Ok(false))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lcache::{EntryMeta, FileSystem, MetaInner};
    use tempfile::TempDir;

    use super::*;

    /// A distinct spec hash per `n`.
    fn hash(n: u8) -> SpecHash {
        SpecHash::from_bytes([n; 32])
    }

    /// Writes an entry into `cache`, so it shows up in `iter_entries`.
    fn write_entry(cache: &Cache<LocalDir>, hash: &SpecHash, name: &str) {
        let w = cache.write_dir(hash).unwrap();
        w.open_write("f").unwrap().write_all(b"x").unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec(name.to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();
    }

    /// Records a read of each `(hash, epoch_secs)` in the cache's access log,
    /// in the append-only record format `ReadSnapshot` loads: 32 bytes of hash
    /// followed by 8 big-endian bytes of epoch seconds.
    fn record_reads(dir: &Path, reads: &[(SpecHash, u64)]) {
        // A tracker file name no `Cache` will hold open (those are pid % 32,
        // climbing on contention).
        let mut f = std::fs::File::create(dir.join("alog").join("900.v1")).unwrap();
        for (hash, epoch_secs) in reads {
            f.write_all(hash.as_bytes()).unwrap();
            f.write_all(&epoch_secs.to_be_bytes()).unwrap();
        }
    }

    fn secs_ago(d: Duration) -> u64 {
        SystemTime::now()
            .checked_sub(d)
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn deletes_only_unused_unkept_entries() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();

        let (recent, old, never_read, kept) = (hash(1), hash(2), hash(3), hash(4));
        for (h, name) in [
            (&recent, "recent"),
            (&old, "old"),
            (&never_read, "never-read"),
            (&kept, "kept"),
        ] {
            write_entry(&cache, h, name);
        }
        record_reads(
            tmp.path(),
            &[
                (recent.clone(), secs_ago(Duration::from_secs(60 * 60))),
                (
                    old.clone(),
                    secs_ago(Duration::from_secs(30 * 24 * 60 * 60)),
                ),
                // `kept` is old enough to delete, and survives on `keep` alone.
                (
                    kept.clone(),
                    secs_ago(Duration::from_secs(30 * 24 * 60 * 60)),
                ),
            ],
        );

        let report = CleanCache {
            older_than: Duration::from_secs(14 * 24 * 60 * 60),
            keep: HashSet::from([kept.clone()]),
            sweep: vec![],
            daemon_id: None,
            events: None,
        }
        .run(&cache)
        .unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 2,
                dirs: 0
            }
        );
        let mut left: Vec<SpecHash> = cache.iter_entries().collect();
        left.sort();
        let mut want = vec![recent, kept];
        want.sort();
        assert_eq!(left, want);
    }

    #[test]
    fn reports_deletions_as_events() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let gone = hash(7);
        write_entry(&cache, &gone, "curl");

        let (tx, mut rx) = futures::channel::mpsc::unbounded();
        CleanCache {
            older_than: Duration::from_secs(1),
            keep: HashSet::new(),
            sweep: vec![],
            daemon_id: None,
            events: Some(tx),
        }
        .run(&cache)
        .unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(
            event,
            CleanEvent::Deleted {
                hash: gone.clone(),
                name: Some("package curl".to_string()),
            }
        );
        assert_eq!(
            event.render(),
            format!("Deleting package curl [{}]", gone.0)
        );
    }

    /// The sweep reads `/proc`, so it only proves anything on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn sweeps_only_directories_whose_owner_exited() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let sandboxes = tmp.path().join("sandboxes");

        // A pid no process can hold: pid 0 is the scheduler, never a /proc entry.
        let dead = sandboxes.join("build-0");
        let live = sandboxes.join(format!("build-{}", std::process::id()));
        let unowned = sandboxes.join("build-scratch");
        for dir in [&dead, &live, &unowned] {
            std::fs::create_dir_all(dir).unwrap();
        }

        let (tx, mut rx) = futures::channel::mpsc::unbounded();
        let report = CleanCache {
            older_than: Duration::from_secs(1),
            keep: HashSet::new(),
            sweep: vec![(StaleKind::Sandbox, sandboxes.clone())],
            daemon_id: None,
            events: Some(tx),
        }
        .run(&cache)
        .unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 0,
                dirs: 1
            }
        );
        assert!(!dead.exists());
        assert!(live.exists());
        assert!(unowned.exists());

        let event = rx.try_recv().unwrap();
        assert_eq!(
            event,
            CleanEvent::Swept {
                kind: StaleKind::Sandbox,
                name: "build-0".to_string(),
            }
        );
        assert_eq!(event.render(), "Cleaning up stale sandbox build-0");
    }

    /// A sandbox stamped with another daemon's id goes once it has sat
    /// untouched past `FOREIGN_OWNER_IDLE`: a dead daemon's stamp never
    /// changes again (gominimal/minimal#1373). The same sandbox fresh stays,
    /// and so does our own, however old.
    #[cfg(target_os = "linux")]
    #[test]
    fn sweeps_another_daemons_sandboxes_once_idle() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let sandboxes = tmp.path().join("sandboxes");
        let daemon_id = "zyxwv";

        let foreign_old = sandboxes.join("build-1700000000-0-abcde");
        let foreign_fresh = sandboxes.join("build-1700000001-0-abcde");
        let ours_old = sandboxes.join(format!("build-1700000000-0-{daemon_id}"));
        let four_days_ago = SystemTime::now() - Duration::from_secs(4 * 24 * 60 * 60);
        for dir in [&foreign_old, &foreign_fresh, &ours_old] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("f"), b"x").unwrap();
        }
        // After the writes above, which would bump the directory's mtime.
        // The file inside too: a sandbox's age is its newest entry's.
        for dir in [&foreign_old, &ours_old] {
            for path in [dir.join("f"), dir.to_path_buf()] {
                std::fs::File::open(path)
                    .unwrap()
                    .set_modified(four_days_ago)
                    .unwrap();
            }
        }

        let report = CleanCache {
            older_than: Duration::from_secs(1),
            keep: HashSet::new(),
            sweep: vec![(StaleKind::Sandbox, sandboxes.clone())],
            daemon_id: Some(daemon_id.to_string()),
            events: None,
        }
        .run(&cache)
        .unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 0,
                dirs: 1
            }
        );
        assert!(!foreign_old.exists(), "a dead daemon's idle sandbox goes");
        assert!(foreign_fresh.exists(), "a fresh foreign sandbox stays");
        assert!(ours_old.exists(), "our own sandbox stays, however old");
    }

    /// A foreign sandbox whose own directory is days old but which holds a
    /// recent write deep inside stays: another daemon's long build writes
    /// there without touching the top level's time.
    #[cfg(target_os = "linux")]
    #[test]
    fn keeps_a_foreign_sandbox_written_deep_inside() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let sandboxes = tmp.path().join("sandboxes");

        let live = sandboxes.join("build-1700000000-0-abcde");
        let deep = live.join("work").join("target").join("debug");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("out.o"), b"x").unwrap();
        let four_days_ago = SystemTime::now() - Duration::from_secs(4 * 24 * 60 * 60);
        // Every directory is old; only the file the build just wrote is new.
        for dir in [
            deep.clone(),
            live.join("work").join("target"),
            live.join("work"),
            live.clone(),
        ] {
            std::fs::File::open(dir)
                .unwrap()
                .set_modified(four_days_ago)
                .unwrap();
        }

        let report = CleanCache {
            older_than: Duration::from_secs(1),
            keep: HashSet::new(),
            sweep: vec![(StaleKind::Sandbox, sandboxes.clone())],
            daemon_id: Some("zyxwv".to_string()),
            events: None,
        }
        .run(&cache)
        .unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 0,
                dirs: 0
            }
        );
        assert!(live.exists(), "a sandbox written inside recently stays");
    }

    /// `newest_modified` finds the newest time anywhere under a directory, and
    /// stops at the first one at or past where it was told to.
    #[cfg(target_os = "linux")]
    #[test]
    fn newest_modified_looks_inside() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("sb");
        let deep = root.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f"), b"x").unwrap();
        let old = SystemTime::now() - Duration::from_secs(10 * 24 * 60 * 60);
        // Whole seconds, so a filesystem with coarse times stores it exactly.
        let day_ago = SystemTime::now() - Duration::from_secs(24 * 60 * 60);
        let newer = SystemTime::UNIX_EPOCH
            + Duration::from_secs(
                day_ago
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        for path in [deep.join("f"), deep.clone(), root.join("a"), root.clone()] {
            std::fs::File::open(path)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        std::fs::File::open(deep.join("f"))
            .unwrap()
            .set_modified(newer)
            .unwrap();

        let far_future = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(newest_modified(&root, far_future), Some(newer));
        assert_eq!(
            newest_modified(&tmp.path().join("missing"), far_future),
            None
        );
    }

    /// A daemon never sweeps its own work, even though `sandbox` stamps its
    /// `daemon_id` where a pid would go — and even when that id is all digits
    /// and so reads as a perfectly plausible dead pid.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_daemon_does_not_sweep_its_own_directories() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let sandboxes = tmp.path().join("sandboxes");

        // `common::random_alphanumeric` can produce an all-digit id; picking one
        // here is what makes this a test rather than a coincidence.
        let daemon_id = "31337";
        assert!(
            !std::fs::exists(format!("/proc/{daemon_id}")).unwrap(),
            "the id must not collide with a live pid for this to prove anything",
        );

        let ours = sandboxes.join(format!("build-1700000000-0-{daemon_id}"));
        let other_daemon = sandboxes.join("build-1700000000-0-a1b2c");
        let dead_pid = sandboxes.join("build-1700000000-0-0");
        for dir in [&ours, &other_daemon, &dead_pid] {
            std::fs::create_dir_all(dir).unwrap();
        }

        let report = CleanCache {
            older_than: Duration::from_secs(1),
            keep: HashSet::new(),
            sweep: vec![(StaleKind::Sandbox, sandboxes.clone())],
            daemon_id: Some(daemon_id.to_string()),
            events: None,
        }
        .run(&cache)
        .unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 0,
                dirs: 1
            }
        );
        assert!(ours.exists(), "our own live sandbox must survive");
        assert!(
            other_daemon.exists(),
            "another daemon's fresh sandbox is not ours to judge",
        );
        assert!(!dead_pid.exists(), "a dead pid's sandbox still goes");
    }
}
