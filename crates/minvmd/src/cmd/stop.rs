//! `minvmd stop` subcommand (R4.4, R2.3).
//!
//! Reads `vmm_pid` from `minvmd.toml`, asks the in-VM minimald to shut down
//! (drain sessions + quiesce the data volume) over the bridge UDS, then sends
//! `SIGTERM` to the VMM child, waits up to 5 s, escalates to `SIGKILL` on
//! timeout, then resets `minvmd.toml` to `Stopped`.
//!
//! The command is idempotent: if the daemon is already stopped (or has never
//! been provisioned), it returns successfully with no action. Stale active
//! state from a dead daemon is repaired to `Stopped`.

use anyhow::{Context as _, Result};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Run the `stop` subcommand.
pub fn run() -> Result<()> {
    run_with_state_dir(StateDir::default_path(), true).map(|_| ())
}

/// What a host-side stop did to the VM, so a caller can say how the guest was
/// left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStop {
    /// No VMM was signalled: the VM was not running, a dead daemon's stale
    /// state was repaired, or a stop was already in progress.
    NothingSignalled,
    /// The guest acknowledged the Shutdown RPC, so its sessions were drained
    /// and its volume quiesced before the VMM was signalled.
    GuestAcknowledged,
    /// The VMM was signalled with no acknowledgement from the guest: it was
    /// not asked, or did not answer. Sessions were killed without their stop
    /// path, and data the guest had not flushed can be lost.
    GuestUnacknowledged,
}

/// Stop the VM whose provider dir is `provider_dir`, exactly as `minvmd stop`
/// would: best-effort guest Shutdown over the bridge socket in that dir, then
/// SIGTERM (SIGKILL after 5 s) to the VMM, then `Stopped`. The returned
/// [`HostStop`] says whether the guest acknowledged that Shutdown.
///
/// `quiesce_guest` false skips the guest Shutdown, for a caller whose own
/// Shutdown RPC to that guest has just failed.
///
/// For the minvmd binary `provider_dir` is the process-global default
/// ([`StateDir::default_path`]); the `minimal` CLI passes the provider dir it
/// resolved for *its* VM, so `min stop --force` can stop a wedged VM from the
/// host when the in-guest daemon cannot answer.
pub fn stop_at(provider_dir: std::path::PathBuf, quiesce_guest: bool) -> Result<HostStop> {
    run_with_state_dir(provider_dir, quiesce_guest)
}

/// `quiesce_guest` gates the Shutdown RPC (R2.3): production passes `true`;
/// unit tests pass `false` so they never reach a live daemon's bridge socket.
fn run_with_state_dir(dir: std::path::PathBuf, quiesce_guest: bool) -> Result<HostStop> {
    let state_dir = StateDir::new(dir).context("opening state dir")?;

    // ── Phase 1: read current state under lock ───────────────────────────────
    let vmm_pid = {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        if !state.lifecycle.is_active() {
            tracing::info!("minvmd is not running");
            return Ok(HostStop::NothingSignalled); // idempotent: already stopped
        }
        if !state_dir.daemon_alive().context("probing alive lock")? {
            // Dead daemon left active state behind; nothing to signal.
            state_dir
                .write_state(&State::stopped())
                .context("repairing stale state")?;
            tracing::info!("minvmd was not running; cleared stale state");
            return Ok(HostStop::NothingSignalled);
        }
        if state.lifecycle == Lifecycle::Stopping {
            tracing::info!("minvmd is already stopping");
            return Ok(HostStop::NothingSignalled); // idempotent: stop already in progress
        }

        state.vmm_pid // may be None during Starting before pid is written
    };

    // ── Phase 2: quiesce the guest, then signal the VMM child (lock NOT held) ─
    // Releasing the lock during the wait allows concurrent `status` reads.
    let acknowledged = match vmm_pid {
        Some(pid) => {
            let acknowledged = quiesce_guest && shutdown_guest_best_effort(&state_dir);
            signal_and_wait(pid)?;
            acknowledged
        }
        None => {
            tracing::warn!("daemon is active but vmm_pid is absent; cleaning up state");
            false
        }
    };

    // ── Phase 3: reset state to Stopped (under lock) ─────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state")?;
    }

    tracing::info!("minvmd stopped");
    Ok(if acknowledged {
        HostStop::GuestAcknowledged
    } else {
        HostStop::GuestUnacknowledged
    })
}

/// R2.3: ask the in-VM minimald (over the vsock bridge UDS) to drain sessions
/// and quiesce the data volume before the VMM is signalled, so a clean stop
/// leaves a clean ext4 journal. Best-effort: on any failure — guest already
/// gone, bridge down, timeout — SIGTERM proceeds and the journal replay
/// backstop bounds the damage. Returns whether the guest acknowledged.
fn shutdown_guest_best_effort(state_dir: &StateDir) -> bool {
    // Two deadlines, because they bound different things. The connect
    // deadline is short: libkrun accepts the bridge UDS connect even when the
    // guest is wedged, so a completed SSH handshake is the only proof of a
    // live daemon — a broken VM must not stall the user's recovery command.
    // The RPC deadline is long: the handler force-drains every session
    // (sandbox teardown, process kills — unbounded real work) and then
    // quiesces (10 s guest-side ceiling) before it acknowledges; giving up
    // mid-drain would SIGTERM the VMM with a dirty journal, defeating the
    // point of the call.
    const GUEST_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const GUEST_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    // The bridge socket is resolved from THIS state dir, never minvmd's
    // process-global provider dir: in the CLI process that global is unset
    // (the CLI sets the client crate's globals instead), and a wrong-VM
    // resolution could shut a healthy sibling VM's guest down from under
    // this stop.
    let uds = state_dir.dir().join(paths::SSH_SOCK_FILE);
    match crate::rpc_client::shutdown_guest(&uds, GUEST_CONNECT_TIMEOUT, GUEST_SHUTDOWN_TIMEOUT) {
        Ok(resp) => {
            tracing::info!(?resp, "guest acknowledged Shutdown RPC");
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "guest Shutdown RPC failed; proceeding with SIGTERM");
            false
        }
    }
}

/// Send `SIGTERM` to `pid`; wait up to 5 s; escalate to `SIGKILL` on timeout.
fn signal_and_wait(pid: u32) -> Result<()> {
    use std::time::{Duration, Instant};

    let pid_t = libc::pid_t::try_from(pid)
        .map_err(|_| anyhow::anyhow!("invalid vmm_pid {pid} in state"))?;
    if pid_t <= 0 {
        return Err(anyhow::anyhow!("invalid vmm_pid {pid} in state"));
    }

    // SAFETY: kill(pid, SIGTERM) delivers SIGTERM to the named process. The pid
    // was stored in minvmd.toml by the `run` supervisor that created the VMM
    // child; it may have already exited (ESRCH), which is handled below.
    let r = unsafe { libc::kill(pid_t, libc::SIGTERM) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Process does not exist; nothing to signal.
            tracing::debug!(pid, "vmm process already gone (ESRCH)");
            return Ok(());
        }
        return Err(anyhow::anyhow!("SIGTERM to pid {pid}: {err}"));
    }

    tracing::debug!(pid, "SIGTERM sent; waiting up to 5s");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: kill(pid, 0) checks for process existence without delivering
        // a signal. Errors other than ESRCH are ignored as best-effort.
        let alive = unsafe { libc::kill(pid_t, 0) == 0 };
        if !alive {
            break;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                pid,
                "vmm process did not exit after SIGTERM; sending SIGKILL"
            );
            // SAFETY: SIGKILL is a forced termination with no side effects
            // beyond killing the named process. The pid originated from our
            // own supervised VMM child.
            unsafe { libc::kill(pid_t, libc::SIGKILL) };
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::Lifecycle;
    use crate::state::State;

    fn make_state_dir(tmp: &tempfile::TempDir) -> StateDir {
        StateDir::new(tmp.path().to_path_buf()).expect("StateDir::new")
    }

    #[test]
    fn stop_is_noop_when_not_provisioned() {
        let tmp = tempfile::tempdir().unwrap();
        // No state file — should be a no-op.
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
    }

    #[test]
    fn stop_is_noop_when_already_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State::stopped()).unwrap();
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        // State should still be Stopped.
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_is_noop_when_already_stopping() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Stopping,
            vmm_pid: Some(999_999_999),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        // Hold the alive lock so Stopping counts as a live daemon.
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        // The live daemon owns the transition; state is untouched.
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopping);
    }

    #[test]
    fn stop_repairs_stale_active_state_without_signalling() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Running per the state file, but no alive-lock holder: the daemon is
        // dead. `stop` must repair to Stopped without touching the pid (which
        // may have been recycled).
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(std::process::id()), // a live pid that must NOT be signalled
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_with_no_pid_in_state_still_resets_to_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: None,
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        run_with_state_dir(tmp.path().to_path_buf(), false).unwrap();
        let s = sd.read_state().unwrap();
        assert_eq!(s.lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn stop_rejects_pid_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(0),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        assert!(run_with_state_dir(tmp.path().to_path_buf(), false).is_err());
    }

    /// `stop_at` is the CLI's host-side recovery entry point: given a provider
    /// dir whose state says Running under a live alive-lock, with the VMM a
    /// spawned process and no bridge socket to answer the guest RPC, it must
    /// quiesce (missing socket fails fast), signal the process, and leave the
    /// state Stopped — all within the guest-RPC connect deadline plus the
    /// SIGTERM grace.
    #[test]
    fn stop_at_signals_vmm_and_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(child.id()),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");

        let started = std::time::Instant::now();
        let outcome = stop_at(tmp.path().to_path_buf(), true).expect("host-side stop succeeds");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "a wedged VM must stop within the connect deadline plus the grace"
        );
        assert_eq!(
            outcome,
            HostStop::GuestUnacknowledged,
            "no guest answered, so the stop must not claim a quiesced volume"
        );

        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
        // SIGTERM'd: reaped here so the test leaves no stray child.
        let status = child.wait().unwrap();
        assert!(
            status.code().is_none(),
            "expected a signalled child, got {status:?}"
        );
    }

    /// The guest Shutdown goes to the bridge socket in the provider dir
    /// `stop_at` was given, never to minvmd's process-global one: resolving
    /// through that global from the CLI process could shut a healthy sibling
    /// VM's guest down. A listener at `<passed dir>/ssh.sock` must therefore
    /// see the connection. It never speaks SSH — libkrun's bridge accepts for
    /// a wedged guest too — so the stop reports no acknowledgement.
    #[test]
    fn stop_at_asks_the_guest_on_the_passed_dirs_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        let listener =
            std::os::unix::net::UnixListener::bind(tmp.path().join(paths::SSH_SOCK_FILE)).unwrap();
        let (connected_tx, connected_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let stream = listener.accept();
            let _ = connected_tx.send(stream.is_ok());
            // Hold the accepted stream open until the test is done, so the
            // client meets a mute peer rather than a reset.
            let _ = done_rx.recv();
            drop(stream);
        });
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(child.id()),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");

        let outcome = stop_at(tmp.path().to_path_buf(), true).expect("host-side stop succeeds");

        assert_eq!(
            connected_rx.try_recv(),
            Ok(true),
            "the guest Shutdown must connect to the passed dir's bridge socket"
        );
        assert_eq!(outcome, HostStop::GuestUnacknowledged);
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
        drop(done_tx);
        child.wait().unwrap();
    }

    #[test]
    fn stop_rejects_pid_exceeding_pid_t_max() {
        // u32::MAX > i32::MAX; try_from must fail rather than silently wrapping.
        if libc::pid_t::try_from(u32::MAX).is_ok() {
            // On a platform where pid_t is wider than i32, skip this guard.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(u32::MAX),
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let _lock = sd.try_acquire_alive_lock().unwrap().expect("acquire");
        assert!(run_with_state_dir(tmp.path().to_path_buf(), false).is_err());
    }
}
