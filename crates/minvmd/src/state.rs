//! State persistence for `minvmd` (R4.1, R4.6).
//!
//! All runtime files live in the shared provider-instance directory
//! (`<minimal_state_dir>/providers/local-0/`, see
//! [`paths::provider_instance_dir`]):
//!
//! - `minvmd.toml` — serialised [`State`] (lifecycle, pid, timestamp).
//! - `lifecycle.lock` — advisory lock guarding concurrent transitions (R4.6).
//! - `minvmd.lock` — the *alive* lock, held exclusively by the supervisor for
//!   its entire life. The kernel releases it on process death, so a free lock
//!   proves no daemon is alive regardless of what `minvmd.toml` claims.
//!
//! Writes to `minvmd.toml` are atomic: content is written to a `.tmp` sibling,
//! `fsync`'d, then renamed over the target (R4.1).
//!
//! [`StartingGuard`] is an RAII guard that resets the persisted state to
//! `Stopped` on drop unless explicitly committed, so a panicking or
//! short-circuiting transition cannot leave the daemon stuck in `Starting`
//! (R4.6).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use fd_lock::RwLock;
use paths::DaemonAbsPath;
use serde::{Deserialize, Serialize};

use crate::lifecycle::Lifecycle;

// ── State dir resolution ─────────────────────────────────────────────────────

static STATE_DIR_OVERRIDE: OnceLock<DaemonAbsPath> = OnceLock::new();

/// Set the `--minimal-state-dir` override. First call wins; must be called
/// before any path resolution.
pub fn set_state_dir_override(dir: DaemonAbsPath) {
    let _ = STATE_DIR_OVERRIDE.set(dir);
}

/// The active `--minimal-state-dir` override, if any. Used to forward the
/// flag when re-execing (`run --detach`, `__krun-vmm`).
pub fn state_dir_override() -> Option<&'static DaemonAbsPath> {
    STATE_DIR_OVERRIDE.get()
}

/// The provider-instance dir holding all minvmd runtime files:
/// `<minimal_state_dir>/providers/local-0`.
pub fn provider_dir() -> PathBuf {
    let base = STATE_DIR_OVERRIDE
        .get()
        .cloned()
        .unwrap_or_else(paths::minimal_state_dir);
    paths::provider_instance_dir(&base, 0)
        .as_utf8_path()
        .as_std_path()
        .to_path_buf()
}

// ── State ────────────────────────────────────────────────────────────────────

/// Serialisable daemon state written to `minvmd.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// Current lifecycle phase.
    pub lifecycle: Lifecycle,
    /// PID of the vmm child process, if one is running.
    pub vmm_pid: Option<u32>,
    /// Unix timestamp (seconds) when the daemon last entered `Running`.
    pub started_at: Option<u64>,
}

impl State {
    /// A freshly-provisioned, not-yet-started state.
    pub fn stopped() -> Self {
        Self {
            lifecycle: Lifecycle::Stopped,
            vmm_pid: None,
            started_at: None,
        }
    }
}

// ── StateDir ─────────────────────────────────────────────────────────────────

/// Root of the minvmd state directory (the provider-instance dir).
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// Open (and create if absent) the state directory at `dir`.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Default path: [`provider_dir`].
    pub fn default_path() -> PathBuf {
        provider_dir()
    }

    /// The directory this `StateDir` operates on.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path to `minvmd.toml`.
    pub fn state_path(&self) -> PathBuf {
        self.dir.join("minvmd.toml")
    }

    /// Path to `lifecycle.lock`.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("lifecycle.lock")
    }

    /// Path to `minvmd.lock` (the alive lock).
    pub fn alive_lock_path(&self) -> PathBuf {
        self.dir.join(paths::MINVMD_LOCK_FILE)
    }

    /// Read the current state from `minvmd.toml`.
    ///
    /// Returns `State { lifecycle: NotProvisioned, .. }` when the file does
    /// not yet exist.
    pub fn read_state(&self) -> io::Result<State> {
        match fs::read_to_string(self.state_path()) {
            Ok(s) => toml::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State {
                lifecycle: Lifecycle::NotProvisioned,
                vmm_pid: None,
                started_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    /// Write `state` to `minvmd.toml` atomically (tmp → fsync → rename) (R4.1).
    pub fn write_state(&self, state: &State) -> io::Result<()> {
        let target = self.state_path();
        let tmp = target.with_extension("toml.tmp");
        let serialised =
            toml::to_string(state).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        {
            let mut f = File::create(&tmp)?;
            f.write_all(serialised.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &target)
    }

    /// Read the state, treating a dead daemon's leftovers as `Stopped`.
    ///
    /// If the state file claims an active lifecycle but no live daemon holds
    /// the alive lock, the on-disk state is stale (the daemon died without
    /// cleanup); it is repaired to `Stopped` and that is returned.
    pub fn effective_state(&self) -> io::Result<State> {
        let state = self.read_state()?;
        if !state.lifecycle.is_active() || self.daemon_alive()? {
            return Ok(state);
        }
        // Stale. Repair under the lifecycle lock; re-check, a daemon may have
        // started in the meantime.
        let mut lock = self.lifecycle_lock()?;
        let _guard = lock.write()?;
        let state = self.read_state()?;
        if !state.lifecycle.is_active() || self.daemon_alive()? {
            return Ok(state);
        }
        tracing::warn!(stale = ?state.lifecycle, "daemon is gone; repairing state to Stopped");
        let repaired = State::stopped();
        self.write_state(&repaired)?;
        Ok(repaired)
    }

    /// Whether a live daemon currently holds the alive lock.
    pub fn daemon_alive(&self) -> io::Result<bool> {
        lock_held(&self.alive_lock_path())
    }

    /// Whether a live *native minimald* serves this instance (it holds its
    /// own lifetime lock in the same dir). Both backends bind the same
    /// `ssh.sock`, so minvmd must not start over a live native daemon.
    pub fn minimald_alive(&self) -> io::Result<bool> {
        lock_held(&self.dir.join(paths::MINIMALD_LOCK_FILE))
    }

    /// The alive lock. The supervisor `try_write()`s this once at startup and
    /// holds the guard until exit; everyone else probes it via
    /// [`Self::daemon_alive`].
    pub fn alive_lock(&self) -> io::Result<RwLock<File>> {
        Ok(RwLock::new(open_lock_file(&self.alive_lock_path())?))
    }

    /// Open the `lifecycle.lock` file suitable for wrapping in an
    /// [`fd_lock::RwLock`].
    pub fn open_lock_file(&self) -> io::Result<File> {
        open_lock_file(&self.lock_path())
    }

    /// An [`fd_lock::RwLock`] over `lifecycle.lock`. Callers take `.write()`
    /// for the duration of a lifecycle transition (R4.6).
    pub fn lifecycle_lock(&self) -> io::Result<RwLock<File>> {
        Ok(RwLock::new(self.open_lock_file()?))
    }
}

/// Whether some process holds an exclusive advisory lock on `path`.
/// Read-only probe: a missing file means no holder.
fn lock_held(path: &Path) -> io::Result<bool> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match RwLock::new(file).try_read() {
        Ok(_guard) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e),
    }
}

/// Open (creating if absent) a lock file; contents are irrelevant, only the
/// fd is used for advisory locking.
fn open_lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
}

// ── StartingGuard ─────────────────────────────────────────────────────────────

/// RAII guard that resets persisted state to `Stopped` on drop unless
/// [`commit`](StartingGuard::commit) is called (R4.6).
///
/// Use this when transitioning into `Starting`: if the caller panics or
/// returns early the guard's `Drop` impl writes `Stopped` so the daemon
/// cannot be left indefinitely stuck in a `Starting` state.
pub struct StartingGuard {
    dir: PathBuf,
    committed: bool,
}

impl StartingGuard {
    /// Create a guard scoped to `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            committed: false,
        }
    }

    /// Mark this transition as successfully completed; the `Drop` impl will
    /// do nothing.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for StartingGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let state_dir = StateDir {
            dir: self.dir.clone(),
        };
        // Intentional discard: we are in Drop, there is nowhere to propagate.
        let _ = state_dir.write_state(&State::stopped());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn make_state_dir(tmp: &tempfile::TempDir) -> StateDir {
        StateDir::new(tmp.path().to_path_buf()).expect("StateDir::new")
    }

    // ── Atomic write round-trip ──────────────────────────────────────────────

    #[test]
    fn state_round_trips_through_toml() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        let original = State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1_700_000_000),
        };
        sd.write_state(&original).expect("write");

        let read_back = sd.read_state().expect("read");
        assert_eq!(read_back.lifecycle, Lifecycle::Running);
        assert_eq!(read_back.vmm_pid, Some(12345));
        assert_eq!(read_back.started_at, Some(1_700_000_000));
    }

    #[test]
    fn missing_state_file_returns_not_provisioned() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        // No write; file does not exist.
        let s = sd.read_state().expect("read");
        assert_eq!(s.lifecycle, Lifecycle::NotProvisioned);
        assert!(s.vmm_pid.is_none());
        assert!(s.started_at.is_none());
    }

    #[test]
    fn atomic_write_uses_tmp_then_renames() {
        // After a successful write the .toml.tmp sibling must not exist.
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).expect("write");

        let tmp_path = sd.state_path().with_extension("toml.tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file should not exist after atomic rename"
        );
        assert!(sd.state_path().exists(), "minvmd.toml should exist");
    }

    // ── fd-lock concurrency guard ────────────────────────────────────────────

    #[test]
    fn lifecycle_lock_acquired_and_released() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        let mut lock = sd.lifecycle_lock().expect("lifecycle_lock");
        {
            let _guard = lock.write().expect("write lock acquired");
            // Lock is held here.
            assert!(sd.lock_path().exists(), "lock file must exist");
        }
        // Guard dropped — lock released. A second acquisition must succeed.
        let _guard2 = lock.write().expect("re-acquire after release");
    }

    #[test]
    fn lifecycle_lock_prevents_concurrent_access() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        let mut lock1 = sd.lifecycle_lock().expect("lock1");
        // Open a second fd to the same lock file.
        let mut lock2 = RwLock::new(sd.open_lock_file().expect("lock2 file"));

        let _guard1 = lock1.write().expect("first write lock");
        // A non-blocking attempt on the second fd must fail with WouldBlock.
        let result = lock2.try_write();
        assert!(
            result.is_err(),
            "second concurrent lock attempt must fail while first is held"
        );
    }

    // ── Alive lock + effective_state ─────────────────────────────────────────

    #[test]
    fn daemon_alive_reflects_alive_lock() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        assert!(!sd.daemon_alive().unwrap(), "no holder → not alive");

        let mut alive = sd.alive_lock().unwrap();
        let guard = alive.try_write().expect("acquire alive lock");
        assert!(sd.daemon_alive().unwrap(), "held lock → alive");
        drop(guard);
        assert!(!sd.daemon_alive().unwrap(), "released → not alive");
    }

    #[test]
    fn minimald_alive_reflects_native_instance_lock() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        assert!(!sd.minimald_alive().unwrap());

        let mut lock =
            RwLock::new(open_lock_file(&tmp.path().join(paths::MINIMALD_LOCK_FILE)).expect("open"));
        let _guard = lock.try_write().expect("acquire");
        assert!(sd.minimald_alive().unwrap());
    }

    #[test]
    fn effective_state_repairs_stale_active_state() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(12345),
            started_at: Some(1),
        })
        .unwrap();

        // No alive-lock holder: Running is a lie left by a dead daemon.
        let s = sd.effective_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
        assert!(s.vmm_pid.is_none());
        // Repair is persisted.
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn effective_state_trusts_active_state_when_daemon_alive() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(42),
            started_at: Some(1),
        })
        .unwrap();

        let mut alive = sd.alive_lock().unwrap();
        let _guard = alive.try_write().expect("acquire alive lock");
        let s = sd.effective_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Running);
        assert_eq!(s.vmm_pid, Some(42));
    }

    #[test]
    fn effective_state_passes_through_inactive_state() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);
        // Missing file → NotProvisioned, untouched.
        let s = sd.effective_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::NotProvisioned);
        assert!(!sd.state_path().exists(), "no repair write for inactive");
    }

    // ── StartingGuard RAII ───────────────────────────────────────────────────

    #[test]
    fn starting_guard_resets_to_stopped_on_drop() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        // Write Starting state.
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: Some(999),
            started_at: Some(42),
        })
        .expect("write starting");

        {
            let guard = StartingGuard::new(tmp.path().to_path_buf());
            // Drop without commit.
            drop(guard);
        }

        let s = sd.read_state().expect("read after guard drop");
        assert_eq!(
            s.lifecycle,
            Lifecycle::Stopped,
            "guard must reset to Stopped on uncommitted drop"
        );
        assert!(s.vmm_pid.is_none(), "vmm_pid cleared on reset");
        assert!(s.started_at.is_none(), "started_at cleared on reset");
    }

    #[test]
    fn starting_guard_does_not_reset_when_committed() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(777),
            started_at: Some(99),
        })
        .expect("write running");

        let guard = StartingGuard::new(tmp.path().to_path_buf());
        guard.commit(); // committed — drop must not reset

        let s = sd.read_state().expect("read after commit");
        assert_eq!(
            s.lifecycle,
            Lifecycle::Running,
            "committed guard must not overwrite state"
        );
        assert_eq!(s.vmm_pid, Some(777));
    }
}
