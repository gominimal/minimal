//! Steady-state guest maintenance: a cache sweep followed by an `fstrim`.
//!
//! Nothing else reclaims guest state. `cache/built` grows monotonically, while
//! the state volume is mounted without `discard`, so the host's backing raw
//! image is a high-water mark of every block ever written to it. The two halves
//! here are ordered and both required: the sweep frees blocks inside ext4, and
//! [`crate::guest::trim_state_volume`] returns those blocks to the host image.
//! Neither alone changes what the user sees on disk.
//!
//! **Policy lives on the caller.** The host `minvmd` decides *when* a cycle
//! runs and how long an entry may go unused; this module only executes and
//! reports. That mirrors the `Shutdown` RPC, and it keeps the schedule on the
//! side of the system with a trustworthy clock and a view of the power state.
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
use minimald_rpc::{MaintenanceReport, MaintenanceRequest};

use crate::server::ServerStateHandle;
use crate::sessions::MaintenanceInputs;

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
    req: MaintenanceRequest,
) -> Result<MaintenanceReport, String> {
    let started = Instant::now();
    let inputs = s
        .sessions_manager()
        .await
        .maintenance_inputs()
        .await
        .map_err(|e| format!("reading maintenance inputs: {e}"))?;

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(req.older_than_secs))
        .ok_or_else(|| {
            format!(
                "retention of {}s predates the epoch on this clock",
                req.older_than_secs
            )
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

    if req.trim {
        report.bytes_trimmed = trim(s).await;
    }
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
