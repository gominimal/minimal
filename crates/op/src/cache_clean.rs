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
        let mut removed = 0;
        for entry in
            std::fs::read_dir(dir).map_err(|e| anyhow!("reading {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| anyhow!("reading an entry of {}: {e}", dir.display()))?;
            let name = entry.file_name();
            // A name that isn't utf-8 can't carry the `-<owner>` suffix either.
            let Some(name) = name.to_str() else { continue };
            if !owner_is_gone(name, self.daemon_id.as_deref()) {
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

/// Whether `name`'s trailing `-<owner>` marks work nobody is doing any more.
///
/// The stamp is a pid, or — when the work ran under a daemon — that daemon's
/// `daemon_id` in the pid's place (`sandbox2::Config::daemon_id`). So:
///
/// - our own `daemon_id`: never. That is this daemon's live work, and the id is
///   a random alphanumeric that can come out all-digits and read as a perfectly
///   plausible dead pid — without this check a daemon eventually reclaims a
///   sandbox out from under itself.
/// - a pid with no `/proc` entry: gone, reclaim it.
/// - anything else — a live pid, another daemon's id, a name nobody stamped:
///   left alone. Not ours to judge.
fn owner_is_gone(name: &str, daemon_id: Option<&str>) -> bool {
    let Some((_, owner)) = name.rsplit_once('-') else {
        return false;
    };
    if Some(owner) == daemon_id || owner.parse::<u32>().is_err() {
        return false;
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

    /// A daemon never sweeps its own work, even though `sandbox2` stamps its
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
            "another daemon's id is not ours to judge",
        );
        assert!(!dead_pid.exists(), "a dead pid's sandbox still goes");
    }
}
