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

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::lifecycle::Lifecycle;
use crate::state::{State, StateDir};

/// Bound on the connect half of a guest-shutdown ask: libkrun accepts the
/// bridge UDS connect even when the guest is wedged, and a broken VM must
/// not stall the stop.
pub(crate) const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the whole signal-stop path, counted from the signal's arrival:
/// the pending-ask audit, the guest quiesce, the VMM signal, and the
/// supervisor's teardown. It stays under launchd's default `ExitTimeOut`
/// (20 s; systemd's default `TimeoutStopSec` is 90 s), so the supervisor
/// ends by the signal itself rather than by the service manager's SIGKILL.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) const SIGNAL_STOP_BOUND: Duration = Duration::from_secs(15);

/// How long a signalled VMM child gets to exit on SIGTERM before SIGKILL.
const VMM_SIGTERM_GRACE: Duration = Duration::from_secs(5);

/// The part of a signal stop's budget kept back from the guest quiesce:
/// the [`VMM_SIGTERM_GRACE`] plus the supervisor's `Stopped` write after it
/// reaps the VMM.
const SIGNAL_STOP_TEARDOWN_RESERVE: Duration = Duration::from_secs(6);

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
    /// The VM was stopped with no acknowledgement from the guest: it was not
    /// asked, or did not answer. Sessions ended without their stop path, and
    /// data the guest had not flushed can be lost.
    GuestUnacknowledged,
}

/// How long a stop waits for the guest to acknowledge Shutdown before the VMM
/// is signalled. Long, because the handler force-drains every session
/// (sandbox teardown, process kills — unbounded real work) and then quiesces
/// (10 s guest-side ceiling) before it acknowledges; giving up mid-drain
/// would SIGTERM the VMM with a dirty journal. Public so a caller that asks
/// the guest itself, then falls back to [`stop_at`], gives it no less.
pub const GUEST_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

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
            // The bridge socket is resolved from THIS state dir, never
            // minvmd's process-global provider dir: in the CLI process that
            // global is unset (the CLI sets the client crate's globals
            // instead), and a wrong-VM resolution could shut a healthy
            // sibling VM's guest down from under this stop.
            let quiesce = quiesce_guest.then(|| GuestQuiesce {
                uds_path: state_dir.dir().join(paths::SSH_SOCK_FILE),
                connect_timeout: GUEST_CONNECT_TIMEOUT,
                rpc_deadline: None,
            });
            quiesce_then_signal(quiesce, pid, VMM_SIGTERM_GRACE)?
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

/// R2.3: how to ask the in-VM minimald (over the vsock bridge UDS) to drain
/// sessions and quiesce the data volume before the VMM is signalled, so a
/// clean stop leaves a clean ext4 journal.
///
/// Two bounds, because they bound different things. The connect bound is
/// short: libkrun accepts the bridge UDS connect even when the guest is
/// wedged, so a completed SSH handshake is the only proof of a live daemon —
/// a broken VM must not stall the stop. The RPC bound is long
/// ([`GUEST_SHUTDOWN_TIMEOUT`]): the handler force-drains every session
/// (sandbox teardown, process kills — unbounded real work) and then quiesces
/// (10 s guest-side ceiling) before it acknowledges; giving up mid-drain
/// would SIGTERM the VMM with a dirty journal, defeating the point of the
/// call. `rpc_deadline` caps it further for a stop with an overall deadline:
/// the RPC then gets whatever time the connect left before it.
struct GuestQuiesce {
    uds_path: PathBuf,
    connect_timeout: Duration,
    rpc_deadline: Option<Instant>,
}

/// The stop sequence `stop`, [`stop_at`] and the signal stop share: quiesce
/// the guest (best-effort: on any failure — guest already gone, bridge down,
/// timeout — SIGTERM proceeds and the journal replay backstop bounds the
/// damage), then SIGTERM the VMM child, escalating to SIGKILL once `grace`
/// has passed. `None` skips the quiesce.
///
/// Returns whether the guest acknowledged the Shutdown RPC: `false` when it
/// was not asked or did not answer.
fn quiesce_then_signal(quiesce: Option<GuestQuiesce>, pid: u32, grace: Duration) -> Result<bool> {
    let acknowledged = quiesce.is_some_and(|q| {
        match crate::rpc_client::shutdown_guest(
            &q.uds_path,
            q.connect_timeout,
            GUEST_SHUTDOWN_TIMEOUT,
            q.rpc_deadline,
        ) {
            Ok(resp) => {
                tracing::info!(?resp, "guest acknowledged Shutdown RPC");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "guest Shutdown RPC failed; proceeding with SIGTERM");
                false
            }
        }
    });
    signal_and_wait(pid, grace)?;
    Ok(acknowledged)
}

/// Send `SIGTERM` to `pid`; wait up to `grace`; escalate to `SIGKILL` on
/// timeout.
fn signal_and_wait(pid: u32, grace: Duration) -> Result<()> {
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

    tracing::debug!(pid, ?grace, "SIGTERM sent; waiting for the exit");

    let deadline = Instant::now() + grace;
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

/// How a signal stop ended ([`graceful_stop_from_signal`]).
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignalStop {
    /// The VM was running: the supervisor's main thread reaped the VMM and
    /// wrote `Stopped`, and it ends the process once its teardown returns.
    TeardownFinished,
    /// The VM was still booting: the VMM is signalled and `Stopped` is
    /// written here, because the main thread is still inside its READY wait
    /// and will not return in time. The lifecycle write lock stays held for
    /// the rest of the process's life, so the boot cannot fork another VMM;
    /// the caller ends the process.
    BootAborted,
}

/// Graceful stop as the `run` supervisor's signal watcher runs it: quiesce
/// the guest over the bridge UDS, signal the recorded VMM child, then wait
/// for the supervisor's own teardown to write the `Stopped` state.
///
/// This is the signal-side twin of `run_with_state_dir`: the same quiesce
/// (so the data volume's ext4 journal stays clean, informed by #705) and
/// the same SIGTERM→SIGKILL escalation, but driven from the stop-signal
/// thread where the main thread cannot be joined — the lifecycle record
/// is the only shared witness that its teardown finished. On any error the
/// caller falls back to dying by the signal as before, so the process
/// still terminates.
///
/// A signal during `Starting` (a cold boot spends tens of seconds there)
/// aborts the boot instead: there is no guest daemon to ask yet, so the
/// recorded VMM child, if the boot has forked one, is signalled without a
/// quiesce and `Stopped` is written here. The main thread is inside its
/// READY wait then, where it neither reaps the child nor returns before the
/// deadline; without this the supervisor would die by the signal and orphan
/// the VMM, which holds the inherited alive lock.
///
/// Everything runs against `deadline` (the signal's arrival plus
/// [`SIGNAL_STOP_BOUND`] in production): the guest ask gets what is left
/// after [`SIGNAL_STOP_TEARDOWN_RESERVE`], so a wedged or slow guest cannot
/// hold the stop past the service manager's timeout, and the `Stopped`
/// wait ends at the deadline.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn graceful_stop_from_signal(
    state_dir_path: PathBuf,
    deadline: Instant,
) -> Result<SignalStop> {
    let state_dir = StateDir::new(state_dir_path.clone())
        .with_context(|| format!("opening state dir: {}", state_dir_path.display()))?;

    // Snapshot the lifecycle under the write lock, as `stop` does, so no
    // concurrent `stop` or transition interleaves with the decision; the
    // quiesce, the signal, and the Stopped wait all run without it, exactly
    // as `stop` releases the lock during its waits. A `Running` state with
    // a pid and a `Starting` state are all this path owns — every other
    // transition belongs to `stop` — and the pid guard keeps a recycled pid
    // from being signalled.
    let vmm_pid = {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        match (state.lifecycle, state.vmm_pid) {
            (Lifecycle::Running, Some(pid)) => pid,
            (Lifecycle::Starting, pid) => {
                drop(_guard);
                return abort_boot_from_signal(&state_dir, pid, deadline);
            }
            _ => bail!(
                "refusing signal stop: lifecycle is {:?}, vmm pid is {:?}",
                state.lifecycle,
                state.vmm_pid
            ),
        }
    };

    // Same best-effort quiesce as `stop`: a failure here logs and falls
    // through to the signal, so a wedged guest cannot stall termination.
    // The UDS is the same `<state dir>/ssh.sock` the CLI resolves for the
    // default provider dir (R3.2), computed from the passed state dir. The
    // RPC runs until the quiesce deadline, whatever the connect leaves of
    // the budget, so a guest still draining sessions gets all of it.
    let now = Instant::now();
    let quiesce_budget = deadline
        .saturating_duration_since(now)
        .saturating_sub(SIGNAL_STOP_TEARDOWN_RESERVE);
    let quiesce_deadline = now + quiesce_budget;
    let quiesce = if quiesce_budget.is_zero() {
        tracing::warn!("no time left to quiesce the guest; proceeding with SIGTERM");
        None
    } else {
        Some(GuestQuiesce {
            uds_path: state_dir.dir().join(paths::SSH_SOCK_FILE),
            connect_timeout: GUEST_CONNECT_TIMEOUT.min(quiesce_budget / 2),
            rpc_deadline: Some(quiesce_deadline),
        })
    };
    quiesce_then_signal(quiesce, vmm_pid, grace_until(deadline))
        .context("stopping VMM after signal")?;

    // The supervisor's main thread watches the same child and writes
    // `Stopped` once it has reaped it; poll for that record, bounded.
    loop {
        let state = state_dir.read_state().context("reading state")?;
        if matches!(state.lifecycle, Lifecycle::Stopped) {
            tracing::info!("supervisor teardown finished; signal stop complete");
            return Ok(SignalStop::TeardownFinished);
        }
        if Instant::now() >= deadline {
            bail!("supervisor did not write Stopped before the signal-stop deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The SIGTERM grace of a stop that must end by `deadline`: the usual
/// [`VMM_SIGTERM_GRACE`], cut to the time the deadline leaves, so no round of
/// signalling runs past it.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn grace_until(deadline: Instant) -> Duration {
    VMM_SIGTERM_GRACE.min(deadline.saturating_duration_since(Instant::now()))
}

/// The `Starting` half of [`graceful_stop_from_signal`]: signal the booting
/// VMM child, if one is recorded, then write `Stopped`.
///
/// A boot may respawn the VMM while the lifecycle stays `Starting` (the
/// publish-port redraw), and a signal may arrive before the first child is
/// recorded, so the recorded pid is read again under the write lock after
/// each signal, and a child recorded meanwhile is signalled too.
///
/// The boot forks its VMM child and records the pid under that same lock,
/// and checks for `Starting` before it forks. So once this holds the lock
/// with no unsignalled child recorded, none exists; and the lock is then
/// kept for the rest of the process's life, so the boot can never fork
/// another. The caller ends the process by the signal straight away, which
/// would otherwise orphan a child forked in between, holding the inherited
/// alive lock.
///
/// A boot that reached `Running` meanwhile has had its VMM signalled, so
/// the main thread's teardown writes `Stopped`; that record is waited for
/// until `deadline`.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
fn abort_boot_from_signal(
    state_dir: &StateDir,
    mut signalled: Option<u32>,
    deadline: Instant,
) -> Result<SignalStop> {
    loop {
        if let Some(pid) = signalled {
            tracing::info!(pid, "stop signal during boot; signalling the VMM child");
            quiesce_then_signal(None, pid, grace_until(deadline))
                .context("stopping the booting VMM after signal")?;
        }

        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        match (state.lifecycle, state.vmm_pid) {
            (Lifecycle::Starting, Some(recorded)) if Some(recorded) != signalled => {
                if Instant::now() >= deadline {
                    bail!("the boot kept respawning the VMM past the signal-stop deadline");
                }
                signalled = Some(recorded);
            }
            (lifecycle @ (Lifecycle::Starting | Lifecycle::Stopped), _) => {
                if lifecycle == Lifecycle::Starting {
                    state_dir
                        .write_state(&State::stopped())
                        .context("writing Stopped state after aborting the boot")?;
                    tracing::info!("boot aborted; signal stop complete");
                }
                // Never released: the lock goes with the process, so the
                // boot's next fork waits on it until the signal ends both.
                std::mem::forget(guard);
                std::mem::forget(lock);
                return Ok(SignalStop::BootAborted);
            }
            _ => break,
        }
    }
    loop {
        let state = state_dir.read_state().context("reading state")?;
        if matches!(state.lifecycle, Lifecycle::Stopped) {
            return Ok(SignalStop::TeardownFinished);
        }
        if Instant::now() >= deadline {
            bail!("supervisor did not write Stopped before the signal-stop deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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

    #[test]
    fn signal_and_wait_reaps_a_spawned_process() {
        // A real child that ignores nothing: SIGTERM must end it within the
        // 5s grace, so signal_and_wait returns Ok without escalating. The
        // reaper thread matters: an unreaped child stays a zombie, and
        // kill(pid, 0) succeeds on a zombie — the poll would wait out the
        // whole grace. Reaping is what makes the pid observably gone (the
        // supervisor's main thread plays this role in production).
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let reaper = std::thread::spawn(move || {
            let status = child.wait().expect("wait");
            assert!(!status.success(), "sleep must not exit successfully");
        });
        let started = std::time::Instant::now();
        signal_and_wait(pid, VMM_SIGTERM_GRACE).expect("signal_and_wait");
        reaper.join().expect("reaper thread");
        // The reaped pid must have been observed gone well inside the 5s
        // grace — the poll's fast path, not the SIGKILL escalation.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "signal_and_wait should observe the reaped pid quickly, took {:?}",
            started.elapsed()
        );
        // kill(pid, 0) must now report ESRCH.
        // SAFETY: kill(pid, 0) only probes for the process; no signal.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(r, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn signal_stop_refuses_when_not_running_with_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        // Stopped: nothing to stop.
        sd.write_state(&State::stopped()).unwrap();
        let err =
            graceful_stop_from_signal(tmp.path().to_path_buf(), Instant::now() + SIGNAL_STOP_BOUND)
                .expect_err("must refuse a Stopped state");
        assert!(err.to_string().contains("refusing signal stop"));

        // Running but no pid: the signal path owns no child to signal.
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: None,
            started_at: None,
            ..State::stopped()
        })
        .unwrap();
        let err =
            graceful_stop_from_signal(tmp.path().to_path_buf(), Instant::now() + SIGNAL_STOP_BOUND)
                .expect_err("must refuse a Running state with no pid");
        assert!(err.to_string().contains("refusing signal stop"));
    }

    /// Whether some open handle still holds `sd`'s lifecycle write lock.
    fn lifecycle_lock_is_held(sd: &StateDir) -> bool {
        let mut lock = sd.lifecycle_lock().expect("opening lifecycle lock");
        match lock.try_write() {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
            Err(e) => panic!("probing the lifecycle lock: {e}"),
        }
    }

    #[test]
    fn signal_stop_before_the_boot_forks_writes_stopped_and_keeps_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // Starting, and the boot has not forked its VMM child yet: there is
        // nothing to signal, but the boot must not fork one once the watcher
        // has decided to end the process.
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            ..State::stopped()
        })
        .unwrap();

        let outcome =
            graceful_stop_from_signal(tmp.path().to_path_buf(), Instant::now() + SIGNAL_STOP_BOUND)
                .expect("signal stop before the boot forks");
        assert_eq!(outcome, SignalStop::BootAborted);
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
        // The boot forks under the lifecycle write lock, so a lock the stop
        // never gives back is what keeps a late fork from being orphaned.
        assert!(
            lifecycle_lock_is_held(&sd),
            "an aborted boot must keep the lifecycle lock until the process ends"
        );
    }

    #[test]
    fn signal_stop_during_boot_signals_the_vmm_and_writes_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // The booting "VMM child". The supervisor's main thread is inside
        // its READY wait at this point: it writes no `Stopped` record, so
        // the signal stop has to. The reaper only keeps the signalled child
        // from lingering as a zombie through the whole SIGTERM grace.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: Some(child.id()),
            ..State::stopped()
        })
        .unwrap();
        let reaper = std::thread::spawn(move || child.wait().expect("wait for signalled child"));

        let outcome =
            graceful_stop_from_signal(tmp.path().to_path_buf(), Instant::now() + SIGNAL_STOP_BOUND)
                .expect("signal stop during boot");
        assert_eq!(outcome, SignalStop::BootAborted);

        let status = reaper.join().expect("reaper thread");
        {
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "the booting VMM must be ended by the stop's signal; got {status:?}"
            );
        }
        let state = sd.read_state().unwrap();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert_eq!(state.vmm_pid, None);
        assert!(
            lifecycle_lock_is_held(&sd),
            "an aborted boot must keep the lifecycle lock until the process ends"
        );
    }

    #[test]
    fn signal_stop_during_boot_cuts_the_grace_to_the_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // A booting "VMM child" that ignores SIGTERM, so the stop has to
        // wait out its grace and escalate. It reports once the signal is
        // ignored, so the stop cannot race the trap.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn a SIGTERM-ignoring child");
        let mut ready = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().expect("child stdout")),
            &mut ready,
        )
        .expect("read the child's ready line");
        assert_eq!(ready.trim(), "ready");
        sd.write_state(&State {
            lifecycle: Lifecycle::Starting,
            vmm_pid: Some(child.id()),
            ..State::stopped()
        })
        .unwrap();

        // One second is left of the stop's budget: the grace round must end
        // with it rather than run its whole 5 s past the deadline.
        let bound = Duration::from_secs(1);
        let started = Instant::now();
        let outcome = graceful_stop_from_signal(tmp.path().to_path_buf(), started + bound)
            .expect("signal stop during boot");
        let elapsed = started.elapsed();
        assert_eq!(outcome, SignalStop::BootAborted);
        assert!(
            elapsed >= bound,
            "the grace was cut short of the deadline: {elapsed:?}"
        );
        assert!(
            elapsed
                < VMM_SIGTERM_GRACE
                    .checked_sub(Duration::from_secs(2))
                    .unwrap(),
            "the grace round ran past the stop's deadline: {elapsed:?}"
        );

        let status = child.wait().expect("wait for the killed child");
        {
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "a child that ignored SIGTERM must be killed at the deadline; got {status:?}"
            );
        }
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
    }

    #[test]
    fn signal_stop_quiesces_signals_and_waits_for_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);

        // The "VMM child": a real process the helper will SIGTERM. Its
        // death is what the supervisor's main thread would observe.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(pid),
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();

        // The "supervisor main thread": observes the child's death, then
        // writes the Stopped state, exactly as run's teardown does after
        // reaping the VMM child. (The bridge UDS is absent here, so the
        // quiesce half fails fast and logs — proving the fall-through.)
        let sd_dir = sd.dir().to_path_buf();
        let watcher = std::thread::spawn(move || {
            let status = child.wait().expect("wait for signalled child");
            assert!(!status.success());
            let sd = StateDir::new(sd_dir).expect("StateDir::new");
            sd.write_state(&State::stopped()).expect("write Stopped");
        });

        // The bound must cover the quiesce attempt (fast: no socket), the
        // 5s signal grace, and the teardown write — 30s is generous.
        graceful_stop_from_signal(
            tmp.path().to_path_buf(),
            Instant::now() + Duration::from_secs(30),
        )
        .expect("graceful stop");

        let state = sd.read_state().unwrap();
        assert_eq!(state.lifecycle, Lifecycle::Stopped);
        assert_eq!(state.vmm_pid, None);
        watcher.join().expect("watcher thread");
    }

    #[test]
    fn signal_stop_holds_its_deadline_against_a_wedged_guest() {
        // A bridge socket that accepts but never speaks SSH: the guest ask
        // would wait out its own timeouts (5 s + 120 s), so only the
        // signal-stop deadline keeps the stop inside a service manager's
        // stop timeout.
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        let listener =
            std::os::unix::net::UnixListener::bind(tmp.path().join(paths::SSH_SOCK_FILE))
                .expect("bind wedged bridge socket");
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(child.id()),
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();
        let sd_dir = sd.dir().to_path_buf();
        let watcher = std::thread::spawn(move || {
            child.wait().expect("wait for signalled child");
            let sd = StateDir::new(sd_dir).expect("StateDir::new");
            sd.write_state(&State::stopped()).expect("write Stopped");
        });

        let bound = Duration::from_secs(8);
        let started = Instant::now();
        graceful_stop_from_signal(tmp.path().to_path_buf(), started + bound)
            .expect("graceful stop");
        assert!(
            started.elapsed() <= bound,
            "the signal stop overran its deadline: {:?}",
            started.elapsed()
        );
        assert_eq!(sd.read_state().unwrap().lifecycle, Lifecycle::Stopped);
        watcher.join().expect("watcher thread");
    }

    #[test]
    fn signal_stop_gives_a_draining_guest_the_whole_quiesce_budget() {
        // A guest that completes the handshake at once and is still
        // draining sessions: the Shutdown RPC must keep waiting until the
        // quiesce deadline (the bound less the teardown reserve), not stop
        // at the half of the budget the connect was capped to, so the VMM
        // is signalled only once that budget is spent.
        let tmp = tempfile::tempdir().unwrap();
        let sd = make_state_dir(&tmp);
        crate::rpc_client::test_support::spawn_stalling_guest(
            &tmp.path().join(paths::SSH_SOCK_FILE),
        );

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        sd.write_state(&State {
            lifecycle: Lifecycle::Running,
            vmm_pid: Some(child.id()),
            started_at: Some(0),
            ..State::stopped()
        })
        .unwrap();
        let sd_dir = sd.dir().to_path_buf();
        let watcher = std::thread::spawn(move || {
            child.wait().expect("wait for signalled child");
            let signalled_at = Instant::now();
            let sd = StateDir::new(sd_dir).expect("StateDir::new");
            sd.write_state(&State::stopped()).expect("write Stopped");
            signalled_at
        });

        // 10 s bound less the 6 s reserve: a 4 s quiesce budget, of which
        // the connect is capped to 2 s.
        let bound = Duration::from_secs(10);
        let quiesce_budget = bound.checked_sub(SIGNAL_STOP_TEARDOWN_RESERVE).unwrap();
        let started = Instant::now();
        graceful_stop_from_signal(tmp.path().to_path_buf(), started + bound)
            .expect("graceful stop");
        let signalled_at = watcher.join().expect("watcher thread");
        assert!(
            signalled_at.duration_since(started)
                >= quiesce_budget
                    .checked_sub(Duration::from_millis(250))
                    .unwrap(),
            "the VMM was signalled {:?} into a {quiesce_budget:?} quiesce budget",
            signalled_at.duration_since(started)
        );
        assert!(
            started.elapsed() <= bound,
            "the signal stop overran its deadline: {:?}",
            started.elapsed()
        );
    }
}
