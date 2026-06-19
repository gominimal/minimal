//! State persistence for `minvmd` (R4.1, R4.6).
//!
//! Manages the state directory (`$XDG_STATE_HOME/minimal/minvmd/`) which
//! holds:
//!
//! - `state.toml` — serialised [`State`] (lifecycle, pid, timestamp).
//! - `lifecycle.lock` — advisory file lock via `fd-lock` guarding concurrent
//!   transitions (R4.6).
//! - `vmm.pid` — PID of the live vmm child process.
//!
//! Writes to `state.toml` are atomic: content is written to a `.tmp` sibling,
//! `fsync`'d, then renamed over the target (R4.1).
//!
//! [`StartingGuard`] is an RAII guard that resets the persisted state to
//! `Stopped` on drop unless explicitly committed, so a panicking or
//! short-circuiting transition cannot leave the daemon stuck in `Starting`
//! (R4.6).

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
};

use fd_lock::RwLock;
use serde::{Deserialize, Serialize};

use crate::lifecycle::Lifecycle;

// ── State ────────────────────────────────────────────────────────────────────

/// Serialisable daemon state written to `state.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// Current lifecycle phase.
    pub lifecycle: Lifecycle,
    /// PID of the vmm child process, if one is running.
    pub vmm_pid: Option<u32>,
    /// PID of the gvproxy child process, if one is running (R1.4).
    pub gvproxy_pid: Option<u32>,
    /// Unix timestamp (seconds) when the daemon last entered `Running`.
    pub started_at: Option<u64>,
}

impl State {
    /// A freshly-provisioned, not-yet-started state.
    pub fn stopped() -> Self {
        Self {
            lifecycle: Lifecycle::Stopped,
            vmm_pid: None,
            gvproxy_pid: None,
            started_at: None,
        }
    }
}

// ── StateDir ─────────────────────────────────────────────────────────────────

/// Root of the `minvmd` state directory.
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// Open (and create if absent) the state directory at `dir`.
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Default path: `$XDG_STATE_HOME/minimal/minvmd/` (fallback
    /// `~/.local/state/minimal/minvmd/`).
    pub fn default_path() -> PathBuf {
        dirs::state_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join(".local/state")
            })
            .join("minimal/minvmd")
    }

    /// Path to `state.toml`.
    pub fn state_path(&self) -> PathBuf {
        self.dir.join("state.toml")
    }

    /// Path to `lifecycle.lock`.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("lifecycle.lock")
    }

    /// Path to `vmm.pid`.
    pub fn vmm_pid_path(&self) -> PathBuf {
        self.dir.join("vmm.pid")
    }

    /// Read the current state from `state.toml`.
    ///
    /// Returns `State { lifecycle: NotProvisioned, .. }` when the file does
    /// not yet exist.
    pub fn read_state(&self) -> io::Result<State> {
        match fs::read_to_string(self.state_path()) {
            Ok(s) => toml::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(State {
                lifecycle: Lifecycle::NotProvisioned,
                vmm_pid: None,
                gvproxy_pid: None,
                started_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    /// Write `state` to `state.toml` atomically (tmp → fsync → rename) (R4.1).
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

    /// Open the `lifecycle.lock` file suitable for wrapping in an
    /// [`fd_lock::RwLock`].
    ///
    /// Create the file if it does not exist; the file's contents are
    /// irrelevant — only its file descriptor is used for advisory locking.
    pub fn open_lock_file(&self) -> io::Result<File> {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(self.lock_path())
    }

    /// Convenience: return an [`fd_lock::RwLock`] wrapping the lock file.
    ///
    /// Callers call `.write()` on the returned lock to acquire an exclusive
    /// advisory lock for the duration of a lifecycle transition (R4.6).
    pub fn lifecycle_lock(&self) -> io::Result<RwLock<File>> {
        Ok(RwLock::new(self.open_lock_file()?))
    }
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
        // Best-effort reset: read current state, overwrite lifecycle to
        // Stopped, clear vmm_pid and started_at.  Errors are swallowed
        // because Drop cannot propagate them; the best we can do is try.
        let state_dir = StateDir {
            dir: self.dir.clone(),
        };
        let result = state_dir.read_state().and_then(|mut s| {
            s.lifecycle = Lifecycle::Stopped;
            s.vmm_pid = None;
            s.gvproxy_pid = None;
            s.started_at = None;
            state_dir.write_state(&s)
        });
        // Intentional discard: we are in Drop, there is nowhere to propagate.
        let _ = result;
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
            gvproxy_pid: Some(12346),
            started_at: Some(1_700_000_000),
        };
        sd.write_state(&original).expect("write");

        let read_back = sd.read_state().expect("read");
        assert_eq!(read_back.lifecycle, Lifecycle::Running);
        assert_eq!(read_back.vmm_pid, Some(12345));
        assert_eq!(read_back.gvproxy_pid, Some(12346));
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
        assert!(s.gvproxy_pid.is_none());
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
        assert!(sd.state_path().exists(), "state.toml should exist");
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

    // ── StartingGuard RAII ───────────────────────────────────────────────────

    #[test]
    fn starting_guard_resets_to_stopped_on_drop() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        // Write Starting state.
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: Some(999),
            gvproxy_pid: Some(1000),
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
        assert!(s.gvproxy_pid.is_none(), "gvproxy_pid cleared on reset");
        assert!(s.started_at.is_none(), "started_at cleared on reset");
    }

    #[test]
    fn starting_guard_does_not_reset_when_committed() {
        let tmp = temp_dir();
        let sd = make_state_dir(&tmp);

        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(777),
            gvproxy_pid: Some(778),
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
        assert_eq!(s.gvproxy_pid, Some(778));
    }
}
