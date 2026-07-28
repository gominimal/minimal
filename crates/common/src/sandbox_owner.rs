//! Which process owns a sandbox directory.
//!
//! A sandbox directory is reclaimable once the process it belongs to is gone.
//! Answering "which process" reliably is the whole point of this module, and it
//! is less obvious than it looks.
//!
//! The directory name carries a trailing `-<pid>`, but that is the pid of
//! whatever *created* the sandbox, recorded for uniqueness. Creator and owner
//! coincide only when the creating process is also the one whose lifetime the
//! sandbox tracks:
//!
//! * Under the CLI they do. `mip` creates the sandbox, runs it, and exits, so
//!   its pid dying is a faithful signal that the directory is finished with.
//! * Under a daemon they do not. `minimald` creates sandboxes and outlives them
//!   all, and inside the microVM it is **pid 1** — alive by definition, and
//!   still pid 1 after a restart. Every directory it creates looks permanently
//!   owned, so nothing can ever be reclaimed and nothing can tell a running
//!   build from an abandoned one.
//!
//! So ownership is recorded explicitly instead, in a [`LEADER_PID_FILE`] beside
//! the sandbox contents. It names the creating process while the sandbox is
//! being set up — a sandbox mid-construction must not look abandoned — and is
//! rewritten with the sandbox **leader**'s pid as soon as one is spawned.
//!
//! The contract lives here, rather than in `sandbox2` where the writing
//! happens, so that readers which do not (and should not) depend on the sandbox
//! implementation can still answer the question.

use std::path::Path;

/// Name of the file, inside a sandbox directory, recording the pid whose death
/// makes that directory reclaimable.
pub const LEADER_PID_FILE: &str = "leader.pid";

/// Record `pid` as the owner of the sandbox directory at `dir`.
///
/// Best-effort: a sandbox that cannot write its own marker still runs, it just
/// cannot be attributed later. Failing a build over a housekeeping file would
/// be the wrong trade. Returns whether the marker was written.
pub fn set_owning_pid(dir: &Path, pid: u32) -> bool {
    std::fs::write(dir.join(LEADER_PID_FILE), pid.to_string()).is_ok()
}

/// The pid owning the sandbox directory at `dir`, if it recorded one.
///
/// `None` means *unknown owner*, not *no owner* — a directory created before
/// this marker existed has none, and so does one abandoned before its leader
/// spawned. Callers reclaiming directories must treat the two the same way they
/// treat a live owner: leave it alone.
#[must_use]
pub fn owning_pid(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(LEADER_PID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether the sandbox directory at `dir` is reclaimable: it names an owner,
/// and that owner is gone.
///
/// A `/proc` lookup, so this is only meaningful on the host whose pids the
/// marker refers to. An unreadable `/proc/<pid>` reads as "still alive", which
/// keeps a reaper off directories whose owner it cannot rule out.
#[must_use]
pub fn owner_is_gone(dir: &Path) -> bool {
    match owning_pid(dir) {
        Some(pid) => !std::fs::exists(format!("/proc/{pid}")).unwrap_or(true),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_pid_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(set_owning_pid(tmp.path(), 4242));
        assert_eq!(owning_pid(tmp.path()), Some(4242));
    }

    /// Rewriting is the handover from creating process to sandbox leader, so
    /// the later write has to win outright rather than append.
    #[test]
    fn rewriting_the_marker_replaces_the_owner() {
        let tmp = tempfile::tempdir().unwrap();
        set_owning_pid(tmp.path(), 1);
        set_owning_pid(tmp.path(), 99999);
        assert_eq!(owning_pid(tmp.path()), Some(99999));
    }

    /// An unmarked directory is *unknown*, and unknown must never read as
    /// reclaimable — that is what keeps a reaper off a sandbox still being
    /// built, and off every directory created before this marker existed.
    #[test]
    fn an_unmarked_directory_is_never_reclaimable() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(owning_pid(tmp.path()), None);
        assert!(!owner_is_gone(tmp.path()));
    }

    #[test]
    fn a_malformed_marker_is_unknown_not_reclaimable() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(LEADER_PID_FILE), "not-a-pid").unwrap();
        assert_eq!(owning_pid(tmp.path()), None);
        assert!(!owner_is_gone(tmp.path()));
    }

    /// pid 0 is never a live process, so `/proc/0` never exists — the one pid
    /// that lets this assert the reclaimable arm without racing a real process.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_owner_makes_the_directory_reclaimable() {
        let tmp = tempfile::tempdir().unwrap();
        set_owning_pid(tmp.path(), 0);
        assert!(owner_is_gone(tmp.path()));
    }

    /// This process is alive by construction, so its own directory must not be
    /// reclaimable — the case the daemon got wrong by recording its own pid.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_owner_holds_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        set_owning_pid(tmp.path(), std::process::id());
        assert!(!owner_is_gone(tmp.path()));
    }
}
