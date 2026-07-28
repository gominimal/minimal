//! Steady-state guest maintenance: a cache sweep followed by an `fstrim`.
//!
//! Nothing else reclaims guest state. `cache/built` grows monotonically, while
//! the state volume is mounted without `discard`, so the host's backing raw
//! image is a high-water mark of every block ever written to it. The two halves
//! here are ordered and both required: the sweep frees blocks inside ext4, and
//! [`crate::guest::trim_state_volume`] returns those blocks to the host image.
//! Neither alone changes what the user sees on disk.
//!
//! **The schedule lives here, in the guest.** `minvmd` configures it — a
//! wall-clock time of day and a retention, handed over on the kernel command
//! line at boot — but the daemon owns the timer and fires its own cycles.
//!
//! That is only sound because the guest clock is now trustworthy. It sets from
//! the RTC at boot and then advances only while the VM is scheduled, so a host
//! that sleeps used to leave it hours behind; `minvmd`'s timekeep bridge fixes
//! that by pushing the host's wall clock in every minute and immediately after
//! a suspend. Without it, a "run at 03:00" schedule would fire at whatever the
//! guest believed 03:00 to be, which on a laptop is anyone's guess.
//!
//! The waiting is done in short slices against the wall clock rather than one
//! long sleep, because a single `sleep_until` is measured monotonically and
//! would not advance across a host suspend — the schedule would slip by exactly
//! the time the machine spent asleep, which is the failure the timekeep bridge
//! exists to prevent.
//!
//! **The sweep is fail-closed.** `mip cache clean` protects the packages of
//! *the current project*; a daemon has no such thing and must instead protect
//! the union over every session. If that union cannot be computed, the cache is
//! left entirely alone rather than risk evicting an entry out from under a
//! running build. The trim still runs — discarding blocks that are already free
//! cannot evict anything — and the skip is reported rather than raised, so one
//! session whose packages will not resolve costs a cycle its sweep instead of
//! disabling maintenance for the life of the VM.
//!
//! That protected set — not the recorded last-use times — is what makes the
//! sweep safe. `ReadSnapshot` reads the tracker files off disk, where the
//! owning process's records lag its in-memory state by up to a flush interval,
//! so an entry a live session just used can still look untouched here. Ageing
//! decides only *which of the unneeded entries* to drop.
//!
//! **Scope.** Leaked build sandboxes are deliberately not swept here. A build
//! sets `keep_dir(true)` until it succeeds, so a failed or interrupted one
//! leaves its directory behind, and reclaiming those needs a reliable "is the
//! owning process still alive" signal. The `-<pid>` suffix `sandbox2` stamps
//! into the directory name is the *creating* process's pid, which in the guest
//! is this daemon — pid 1, and so alive by definition, including across
//! restarts. Making the sandbox's leader process own its namespace is the fix;
//! until then no sound signal exists and this module does not guess.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use common::SpecHash;

use crate::server::ServerStateHandle;
use crate::sessions::MaintenanceInputs;

/// Environment variable naming the daily maintenance time as `HH:MM`, UTC.
/// Set by `minvmd` on the kernel command line; absent means no schedule.
pub(crate) const MAINTENANCE_AT_ENV: &str = "MINIMAL_MAINTENANCE_AT";

/// Environment variable carrying the sweep retention in seconds. Absent falls
/// back to [`DEFAULT_OLDER_THAN_SECS`].
pub(crate) const MAINTENANCE_OLDER_THAN_ENV: &str = "MINIMAL_MAINTENANCE_OLDER_THAN_SECS";

/// Retention applied when the host did not name one: 14 days, matching
/// `mip cache clean --older-than`'s default so the manual and scheduled sweeps
/// age entries out on the same terms.
pub(crate) const DEFAULT_OLDER_THAN_SECS: u64 = 14 * 24 * 60 * 60;

/// How long to wait between wall-clock checks. Bounds how late a cycle can be
/// after the host wakes from suspend, and is short enough that a clock step
/// lands the run near its scheduled minute rather than a tick later.
const TICK: Duration = Duration::from_secs(30);

/// What one maintenance cycle reclaimed.
///
/// Both halves are recorded because either can be a silent no-op: a sweep that
/// deleted nothing and a trim that returned nothing look identical in a log
/// that only says "maintenance ran".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MaintenanceReport {
    /// Cache entries deleted by the sweep.
    pub cache_entries_deleted: u64,
    /// Bytes those entries occupied, as measured before deletion.
    pub cache_bytes_deleted: u64,
    /// Cache entries held back because a session references them.
    pub cache_entries_protected: u64,
    /// Why the sweep was skipped, if it was. The trim still runs regardless.
    pub cache_sweep_skipped: Option<String>,
    /// Bytes `FITRIM` reported discarding. `None` when the trim did not run.
    pub bytes_trimmed: Option<u64>,
    /// Wall-clock duration of the cycle.
    pub duration_ms: u64,
}

/// Start the daily maintenance scheduler, if one is configured.
///
/// Reads its schedule from the environment the kernel command line supplied at
/// boot. No [`MAINTENANCE_AT_ENV`] means no schedule and no task — that is how
/// maintenance is switched off, and how a daemon that is not running under
/// `minvmd` behaves by default.
///
/// The task runs for the life of the daemon; the returned handle is safe to
/// drop.
pub(crate) fn spawn_scheduler(state: ServerStateHandle) -> Option<tokio::task::JoinHandle<()>> {
    let raw = std::env::var(MAINTENANCE_AT_ENV).ok()?;
    let Some(at) = TimeOfDay::parse(&raw) else {
        tracing::warn!(
            env = MAINTENANCE_AT_ENV,
            value = raw,
            "ignoring an unparseable maintenance time; expected HH:MM",
        );
        return None;
    };
    let older_than_secs = std::env::var(MAINTENANCE_OLDER_THAN_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(DEFAULT_OLDER_THAN_SECS);

    tracing::info!(
        at = %raw,
        older_than_secs,
        "guest maintenance scheduled daily (UTC)"
    );
    Some(tokio::spawn(async move {
        run_scheduler(&state, at, older_than_secs).await;
    }))
}

/// Fire one cycle each time the wall clock passes `at`.
///
/// Never returns. Every failure is logged and swallowed: maintenance is
/// best-effort housekeeping and must not be able to take the daemon down.
async fn run_scheduler(state: &ServerStateHandle, at: TimeOfDay, older_than_secs: u64) {
    // Anchored to the wall clock rather than a monotonic deadline, and
    // re-evaluated every tick, so a host suspend or a timekeep correction moves
    // the target instead of silently slipping the schedule by the sleep's
    // duration.
    let mut next = at.next_after(SystemTime::now());
    loop {
        tokio::time::sleep(TICK).await;
        let now = SystemTime::now();
        if now < next {
            continue;
        }
        // Recomputed from `now`, not by adding a day to `next`: if the clock
        // jumped forward past several occurrences (a laptop closed for a
        // weekend), this runs once and resumes the daily cadence rather than
        // firing a burst to "catch up" on housekeeping nobody missed.
        next = at.next_after(now);
        match run_cycle(state, older_than_secs).await {
            Ok(report) => tracing::info!(
                cache_entries_deleted = report.cache_entries_deleted,
                cache_bytes_deleted = report.cache_bytes_deleted,
                cache_entries_protected = report.cache_entries_protected,
                cache_sweep_skipped = report.cache_sweep_skipped,
                bytes_trimmed = report.bytes_trimmed,
                duration_ms = report.duration_ms,
                "guest maintenance reclaimed state"
            ),
            Err(error) => tracing::warn!(%error, "maintenance cycle could not run"),
        }
    }
}

/// A time of day, UTC, as `minvmd` configures it.
///
/// UTC rather than local time because the guest has no timezone configuration
/// to read — a microVM rootfs carries no `/etc/localtime` — so "03:00" means
/// the same instant regardless of where the host happens to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeOfDay {
    hour: u32,
    minute: u32,
}

impl TimeOfDay {
    /// Seconds in a day.
    const DAY: u64 = 24 * 60 * 60;

    /// Parse `HH:MM`. `None` for anything else, including out-of-range values —
    /// an unparseable schedule must switch maintenance off loudly rather than
    /// silently pick a time nobody asked for.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let (h, m) = s.trim().split_once(':')?;
        let hour: u32 = h.parse().ok()?;
        let minute: u32 = m.parse().ok()?;
        (hour < 24 && minute < 60).then_some(Self { hour, minute })
    }

    /// Seconds past midnight UTC.
    const fn seconds_into_day(self) -> u64 {
        (self.hour as u64) * 3600 + (self.minute as u64) * 60
    }

    /// The next instant strictly after `now` at which this time of day falls.
    ///
    /// Strictly after, so a cycle that finishes within the same minute it
    /// started cannot immediately re-trigger.
    pub(crate) fn next_after(self, now: SystemTime) -> SystemTime {
        let since_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let midnight = since_epoch - (since_epoch % Self::DAY);
        let today = midnight + self.seconds_into_day();
        let next = if today > since_epoch {
            today
        } else {
            today + Self::DAY
        };
        SystemTime::UNIX_EPOCH + Duration::from_secs(next)
    }
}

/// Run one maintenance cycle against `s`.
///
/// `Err` is reserved for a cycle that could not start at all; a cycle that
/// merely could not establish the protected set completes with
/// `cache_sweep_skipped` set and the cache untouched.
///
/// The cycle does not defer to in-flight builds. `FITRIM` is the online-discard
/// ioctl and is safe on a live filesystem, and the sweep only deletes entries
/// no session references, so contention here costs latency rather than
/// correctness — whereas a deferral built on an unreliable "is a build running"
/// signal costs the reclaim entirely. See the module note on scope.
pub(crate) async fn run_cycle(
    s: &ServerStateHandle,
    older_than_secs: u64,
) -> Result<MaintenanceReport, String> {
    let started = Instant::now();
    let inputs = s
        .sessions_manager()
        .await
        .maintenance_inputs()
        .await
        .map_err(|e| format!("reading maintenance inputs: {e}"))?;

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(older_than_secs))
        .ok_or_else(|| {
            format!("retention of {older_than_secs}s predates the epoch on this clock")
        })?;
    let protected = match protected_spec_hashes(&inputs).await {
        Ok(protected) => Some(protected),
        Err(error) => {
            tracing::warn!(%error, "protected set unknown; leaving the cache untouched");
            None
        }
    };

    // The sweep is synchronous filesystem work over potentially tens of
    // thousands of entries; keep it off the runtime's async workers.
    let daemon_ctx = Arc::clone(&inputs.daemon_ctx);
    let protected_count = protected.as_ref().map_or(0, HashSet::len) as u64;
    let mut report = tokio::task::spawn_blocking(move || sweep(&daemon_ctx, protected, cutoff))
        .await
        .map_err(|e| format!("sweep task panicked: {e}"))?;
    report.cache_entries_protected = protected_count;

    report.bytes_trimmed = trim(s).await;
    report.duration_ms = started.elapsed().as_millis() as u64;

    tracing::info!(
        cache_entries_deleted = report.cache_entries_deleted,
        cache_bytes_deleted = report.cache_bytes_deleted,
        cache_entries_protected = report.cache_entries_protected,
        cache_sweep_skipped = report.cache_sweep_skipped,
        bytes_trimmed = report.bytes_trimmed,
        duration_ms = report.duration_ms,
        "maintenance cycle complete"
    );
    Ok(report)
}

/// The union of spec hashes every known session depends on — the set the sweep
/// must not touch.
///
/// Each session's scaffolding is resolved from *its own* workspace, since that
/// is where the `minimal.toml` naming its tasks and stack lives. Resolution is
/// a Nickel evaluation, so it runs on the blocking pool.
///
/// `Err` means the union is unknown, which the caller turns into "leave the
/// cache alone": a session whose packages could not be enumerated is a session
/// whose cache entries cannot safely be aged out. It is deliberately
/// all-or-nothing — a partial union would look like a complete one to the
/// sweep, and the missing half is exactly what would be deleted.
///
/// A workspace with no `minimal.toml` is the one thing that is not a failure.
/// That is a session whose files were never uploaded — it references no
/// packages and has built nothing, so it has nothing to protect. Treating it as
/// unreadable would let one half-created session suppress the cache sweep for
/// the life of the VM.
async fn protected_spec_hashes(inputs: &MaintenanceInputs) -> Result<HashSet<SpecHash>, String> {
    let mut protected = HashSet::new();
    for (id, workspace) in &inputs.workspaces {
        if !workspace.as_utf8_path().join(mfile::MFILE_NAME).exists() {
            tracing::debug!(session_id = %id, "session workspace has no minimal.toml; nothing to protect");
            continue;
        }
        let config = mctx::ConfigBuilder::new()
            .with_repo_dir(workspace.as_utf8_path())
            .with_cache_dir(inputs.minimal_cache_dir.as_utf8_path())
            .with_state_dir(inputs.minimal_state_dir.as_utf8_path())
            .build()
            .map_err(|e| format!("config for session {id}: {}", mctx::Error::from(e)))?;

        // `mctx::Error` carries Nickel `Rc`s and is not `Send`, so the context,
        // the graph, and every error stay inside the closure — none of them
        // crosses the await.
        let hashes = tokio::task::spawn_blocking(move || {
            let mut ctx = mctx::Context::new(config).map_err(|e| e.to_string())?;
            let graph = ctx.graph_from_all_packages().map_err(|e| e.to_string())?;
            let packages = ctx.scaffolding_packages().map_err(|e| e.to_string())?;
            Ok::<Vec<SpecHash>, String>(packages.iter().map(|bsr| graph.spec_hash(bsr)).collect())
        })
        .await
        .map_err(|e| format!("resolving packages for session {id}: {e}"))?
        .map_err(|e| format!("resolving packages for session {id}: {e}"))?;

        protected.extend(hashes);
    }
    Ok(protected)
}

/// Delete aged-out cache entries.
///
/// `protected` is `None` when the set of entries live sessions depend on could
/// not be established; the cache is then left entirely alone. Blocking; call
/// from [`tokio::task::spawn_blocking`].
fn sweep(
    daemon_ctx: &mctx::DaemonContext,
    protected: Option<HashSet<SpecHash>>,
    cutoff: SystemTime,
) -> MaintenanceReport {
    let mut report = MaintenanceReport::default();
    let cache = daemon_ctx.local_cache();

    let Some(protected) = protected else {
        report.cache_sweep_skipped = Some(
            "the set of packages live sessions depend on could not be established".to_string(),
        );
        return report;
    };

    // An unreadable read tracker means "no entry has a recorded use", under
    // which every unprotected entry would look stale and the sweep would empty
    // the cache. Skip it instead — a wrongly-emptied cache is a rebuild of
    // everything, and the caller still gets its trim.
    match cache.atimes() {
        Ok(atimes) => {
            // Collected before deleting: `iter_entries` walks the same bucket
            // dirs the deletes mutate, and removing entries underneath a live
            // directory walk is how a sweep silently skips half the cache.
            let candidates: Vec<SpecHash> = cache
                .iter_entries()
                .filter(|hash| is_sweepable(hash, &protected, atimes.last_read(hash), cutoff))
                .collect();

            for hash in candidates {
                let bytes = dir_size(&cache.entry_path(&hash));
                let ident = cache.read_meta(&hash).map_or_else(
                    |_| format!("[{}]", hash.0),
                    |m| format!("{} [{}]", m.inner, hash.0),
                );
                match cache.invalidate_dir(&hash) {
                    Ok(()) => {
                        tracing::debug!(entry = %ident, bytes, "swept cache entry");
                        report.cache_entries_deleted += 1;
                        report.cache_bytes_deleted += bytes;
                    }
                    Err(e) => {
                        tracing::warn!(entry = %ident, error = %e, "could not sweep cache entry");
                    }
                }
            }
        }
        Err(e) => {
            report.cache_sweep_skipped = Some(format!("cache read tracker unavailable: {e}"));
            tracing::warn!(error = %e, "cache read tracker unavailable; skipping the cache sweep");
        }
    }

    report
}

/// Whether a cache entry may be deleted: no session depends on it, and it has
/// either never been recorded as used or was last used before `cutoff`.
///
/// Protection is checked first and is absolute. The never-used arm is why:
/// an entry built moments ago has no recorded read yet, so ageing alone would
/// class the freshest artifact in the cache as the stalest thing in it. Only
/// membership of the protected set separates "nobody has needed this in a
/// fortnight" from "this was built for a live session one second ago".
fn is_sweepable(
    hash: &SpecHash,
    protected: &HashSet<SpecHash>,
    last_read: Option<SystemTime>,
    cutoff: SystemTime,
) -> bool {
    !protected.contains(hash) && last_read.is_none_or(|last| last < cutoff)
}

/// Total bytes occupied by `path`, following no symlinks.
///
/// Reports *allocated* blocks rather than apparent size: the figure exists to
/// be compared against the host image's own `st_blocks`, and a sparse or
/// hardlinked tree's apparent size would overstate what a trim can return.
/// An unreadable subtree contributes what could be read — the number is
/// reporting, and a partial tally beats failing a delete that should proceed.
fn dir_size(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.blocks() * 512;
    }
    let mut total = meta.blocks() * 512;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            total += dir_size(&entry.path());
        }
    }
    total
}

/// Trim the state volume, returning the bytes discarded.
///
/// `None` when there is nothing this daemon may trim: a native daemon's state
/// dir is a host directory it does not own, and a microVM booted without a data
/// volume has no block device behind the mountpoint. Both are ordinary
/// configurations, not failures.
#[cfg(target_os = "linux")]
async fn trim(s: &ServerStateHandle) -> Option<u64> {
    if !s.state_volume_mounted().await {
        tracing::debug!("no data volume mounted at the state dir; skipping trim");
        return None;
    }
    let mountpoint = s.minimal_state_dir().await;
    let trimmed = tokio::task::spawn_blocking(move || {
        crate::guest::trim_state_volume(mountpoint.as_utf8_path().as_str())
    })
    .await;
    match trimmed {
        Ok(Ok(bytes)) => Some(bytes),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "fstrim failed; freed blocks stay in the host image");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "fstrim task panicked");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn trim(_s: &ServerStateHandle) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Epoch seconds → `SystemTime`, for readable schedule assertions.
    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn a_time_of_day_parses_from_hh_mm() {
        assert_eq!(
            TimeOfDay::parse("03:00"),
            Some(TimeOfDay { hour: 3, minute: 0 })
        );
        assert_eq!(
            TimeOfDay::parse("23:59"),
            Some(TimeOfDay {
                hour: 23,
                minute: 59
            })
        );
    }

    /// An unparseable schedule switches maintenance off rather than defaulting
    /// to a time nobody asked for — including the out-of-range values that
    /// would otherwise silently wrap.
    #[test]
    fn an_invalid_time_of_day_is_rejected() {
        for bad in [
            "", "3", "03", "03:60", "24:00", "-1:00", "aa:bb", "03:00:00",
        ] {
            assert_eq!(TimeOfDay::parse(bad), None, "should reject {bad:?}");
        }
    }

    /// Later the same day, the run is today; once the time has passed, it rolls
    /// to tomorrow.
    #[test]
    fn the_next_run_rolls_to_tomorrow_once_today_has_passed() {
        let three_am = TimeOfDay::parse("03:00").unwrap();
        // 1970-01-01T00:00:00Z — 03:00 is still ahead.
        assert_eq!(three_am.next_after(at(0)), at(3 * 3600));
        // 1970-01-01T04:00:00Z — 03:00 has gone, so tomorrow.
        assert_eq!(three_am.next_after(at(4 * 3600)), at(24 * 3600 + 3 * 3600));
    }

    /// Exactly on the scheduled second counts as passed, so a cycle finishing
    /// within its own minute cannot immediately re-trigger.
    #[test]
    fn the_next_run_is_strictly_after_now() {
        let three_am = TimeOfDay::parse("03:00").unwrap();
        let today = 3 * 3600;
        assert_eq!(three_am.next_after(at(today)), at(today + 24 * 3600));
    }

    /// A clock that jumps forward over several occurrences resumes the daily
    /// cadence rather than queueing a run for each one missed — housekeeping
    /// skipped while the host slept is not owed retrospectively.
    #[test]
    fn a_forward_clock_jump_does_not_queue_missed_runs() {
        let three_am = TimeOfDay::parse("03:00").unwrap();
        let after_a_long_weekend = at(3 * 24 * 3600 + 10 * 3600);
        assert_eq!(
            three_am.next_after(after_a_long_weekend),
            at(4 * 24 * 3600 + 3 * 3600),
            "the next run is the following 03:00, not a backlog"
        );
    }

    /// Midnight is a legitimate schedule and must not degenerate into "now".
    #[test]
    fn midnight_schedules_the_following_day_when_it_is_already_midnight() {
        let midnight = TimeOfDay::parse("00:00").unwrap();
        assert_eq!(midnight.next_after(at(0)), at(24 * 3600));
        assert_eq!(midnight.next_after(at(1)), at(24 * 3600));
    }

    /// A distinct spec hash per `nibble`. Only distinctness matters here — the
    /// predicate under test never looks at the bytes.
    fn spec_hash(nibble: char) -> SpecHash {
        SpecHash::from_hex(std::iter::repeat_n(nibble, 64).collect::<String>())
            .expect("64 hex chars is a valid hash")
    }

    /// The case the protected set exists for: a just-built entry has no
    /// recorded read, so ageing alone would delete the freshest artifact in
    /// the cache. Protection has to win over the never-used rule, not merely
    /// over the age comparison.
    #[test]
    fn a_protected_entry_is_never_swept_even_with_no_recorded_use() {
        let hash = spec_hash('a');
        let protected = HashSet::from([hash.clone()]);
        let now = SystemTime::now();
        assert!(!is_sweepable(&hash, &protected, None, now));
        assert!(!is_sweepable(
            &hash,
            &protected,
            Some(now - Duration::from_secs(999_999)),
            now
        ));
    }

    #[test]
    fn an_unprotected_entry_is_swept_when_stale_or_never_used() {
        let hash = spec_hash('b');
        let none = HashSet::new();
        let now = SystemTime::now();
        assert!(
            is_sweepable(&hash, &none, None, now),
            "no recorded use at all is sweepable"
        );
        assert!(
            is_sweepable(&hash, &none, Some(now - Duration::from_secs(60)), now),
            "last used before the cutoff is sweepable"
        );
    }

    /// An entry used since the cutoff stays, protected set or not — that is
    /// the retention knob doing its job.
    #[test]
    fn an_entry_used_since_the_cutoff_survives() {
        let hash = spec_hash('c');
        let now = SystemTime::now();
        assert!(!is_sweepable(
            &hash,
            &HashSet::new(),
            Some(now + Duration::from_secs(60)),
            now
        ));
    }

    #[test]
    fn dir_size_tallies_a_tree_and_is_zero_for_a_missing_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("tree");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/a"), vec![0u8; 8192]).unwrap();

        assert!(
            dir_size(&root) >= 8192,
            "an 8 KiB file must be accounted for"
        );
        assert_eq!(dir_size(&tmp.path().join("absent")), 0);
    }
}
