//! Auto-spawn logic for minvmd (R4.5).
//!
//! Before connecting to the minvmd UDS, the CLI reads the minvmd state. If it is
//! not running it spawns `minvmd run --detach` and waits (with a timeout) for the
//! UDS to become available. This runs on both macOS (Hypervisor.framework) and
//! Linux (KVM); on any other target it is a no-op.

use std::io;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::thread;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use minvmd::lifecycle::Lifecycle;

/// Default timeout in seconds to wait for the UDS when spawning minvmd (R4.5).
///
/// A cold VM boot (kernel bring-up + the in-VM minimald init: mount,
/// pivot_root, networking) was observed at ~22–28s before the bridge socket
/// accepts, and is slower under host load, so the default carries margin above
/// minvmd's own READY wait. This is an upper bound — the spawn returns as soon
/// as the UDS is ready — so it only costs time on a genuinely slow/failed boot.
/// Override with [`SPAWN_TIMEOUT_ENV`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 75;

/// Environment variable overriding [`DEFAULT_SPAWN_TIMEOUT_SECS`].
#[cfg(any(target_os = "macos", target_os = "linux"))]
const SPAWN_TIMEOUT_ENV: &str = "MINIMAL_SPAWN_TIMEOUT_SECS";

/// The minvmd UDS-readiness wait, overridable via [`SPAWN_TIMEOUT_ENV`]. A
/// non-numeric, empty, or zero value falls back to [`DEFAULT_SPAWN_TIMEOUT_SECS`]
/// — a zero timeout would give the boot no readiness window.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn spawn_timeout_secs() -> u64 {
    std::env::var(SPAWN_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(DEFAULT_SPAWN_TIMEOUT_SECS)
}

/// Poll interval while waiting for a shutting-down minvmd to reach a terminal
/// state before deciding whether to spawn.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const STOPPING_POLL_MS: u64 = 100;

/// Max time to wait for an in-progress `minvmd stop` (SIGTERM → SIGKILL, ~5 s)
/// to finish before giving up with a clear error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const STOPPING_WAIT_SECS: u64 = 6;

/// Max time to wait, after the daemon acknowledges a `Shutdown`, for the VM to
/// finish going down. Covers the guest's connection drain (5 s grace), its
/// poweroff, and the supervisor's state write.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const STOPPED_WAIT_SECS: u64 = 20;

/// What to do given the lifecycle read from the minvmd state.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// minvmd is already up (or coming up); nothing to do.
    AlreadyRunning,
    /// minvmd is shutting down; wait for it to reach a terminal state first.
    WaitForStopping,
    /// minvmd is not running; spawn it.
    Spawn,
}

/// Pure mapping from a lifecycle state to the action the CLI should take. Kept
/// separate from the I/O so it can be exhaustively unit-tested. `Lifecycle` is
/// `#[non_exhaustive]`, so any future state is treated conservatively as "spawn".
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn classify(lifecycle: Lifecycle) -> Decision {
    match lifecycle {
        Lifecycle::Running | Lifecycle::Starting => Decision::AlreadyRunning,
        Lifecycle::Stopping => Decision::WaitForStopping,
        Lifecycle::Stopped | Lifecycle::NotProvisioned => Decision::Spawn,
        _ => Decision::Spawn,
    }
}

/// Check whether minvmd needs to be spawned, and spawn it if necessary (R4.5).
///
/// - Reads the minvmd state from `minvmd.toml`, via `effective_state` so a
///   dead daemon's leftovers read as `Stopped` rather than wedging the CLI.
/// - If already running/starting, returns immediately.
/// - If stopping, waits for the shutdown to finish, then spawns.
/// - Otherwise spawns `minvmd run --detach` with a timeout.
///
/// On targets with no minvmd backend this is a no-op (see below).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn ensure_minvmd_running(minimal_dir: Option<&Path>) -> io::Result<()> {
    let provider_dir = crate::client::resolve_provider_dir(minimal_dir)?;
    let state_dir = minvmd::state::StateDir::new(provider_dir)?;

    match classify(state_dir.effective_state()?.lifecycle) {
        Decision::AlreadyRunning => {
            tracing::debug!("minvmd already running or starting");
            return Ok(());
        }
        Decision::WaitForStopping => {
            // `minvmd stop` can take up to ~5 s (SIGTERM → SIGKILL escalation),
            // so a fixed short sleep usually leaves the daemon still Stopping.
            // Spawning then would make the new `minvmd run` bail on its own
            // Stopping guard, surfacing an opaque 8 s UDS timeout. Instead poll
            // until it reaches a terminal state, re-reading on each tick.
            tracing::info!("minvmd is stopping; waiting for it to finish");
            let deadline = Instant::now() + Duration::from_secs(STOPPING_WAIT_SECS);
            loop {
                thread::sleep(Duration::from_millis(STOPPING_POLL_MS));
                match classify(state_dir.effective_state()?.lifecycle) {
                    // Something else restarted it in the meantime.
                    Decision::AlreadyRunning => return Ok(()),
                    // Shutdown completed; fall through to spawn.
                    Decision::Spawn => break,
                    Decision::WaitForStopping if Instant::now() >= deadline => {
                        return Err(io::Error::other(
                            "minvmd is still stopping after waiting; try again shortly",
                        ));
                    }
                    // Still stopping; keep polling.
                    Decision::WaitForStopping => continue,
                }
            }
        }
        Decision::Spawn => {
            // Not running; will spawn below.
        }
    }

    // Not running; spawn minvmd run --detach with timeout (R4.5).
    let timeout_secs = spawn_timeout_secs();
    tracing::info!("spawning minvmd run --detach with timeout {timeout_secs}");
    let mut cmd = Command::new("minvmd");
    // Forward the state-dir override so the daemon binds the socket where
    // this client will look for it.
    if let Some(dir) = minimal_dir {
        cmd.arg("--minimal-state-dir").arg(dir);
    }
    let output = cmd
        .arg("run")
        .arg("--detach")
        .arg("--timeout")
        .arg(timeout_secs.to_string())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to spawn minvmd: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "minvmd run --detach failed: {}",
            stderr
        )));
    }

    tracing::info!("minvmd spawned successfully");
    Ok(())
}

/// On targets without a minvmd backend (e.g. Windows), auto-spawn is a no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn ensure_minvmd_running(_minimal_dir: Option<&Path>) -> io::Result<()> {
    tracing::debug!("ensure_minvmd_running is a no-op on this platform");
    Ok(())
}

/// Wait for a shutting-down minvmd to reach a terminal lifecycle state.
///
/// The `Shutdown` RPC is acknowledged when the guest *starts* going down: the
/// daemon still has to drain its connections and power the VM off, and the
/// supervisor has to reap the VMM child, before the state file reads `Stopped`.
/// Returning to the user before then hands the next command a `Running` state
/// whose VM is already gone — it would connect to a dead bridge socket instead
/// of spawning a fresh VM (#730).
///
/// Reads via `effective_state`, so a supervisor that died without writing
/// `Stopped` still resolves rather than pinning the wait to its deadline.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn wait_for_minvmd_stopped(minimal_dir: Option<&Path>) -> io::Result<()> {
    let provider_dir = crate::client::resolve_provider_dir(minimal_dir)?;
    let state_dir = minvmd::state::StateDir::new(provider_dir)?;

    let deadline = Instant::now() + Duration::from_secs(STOPPED_WAIT_SECS);
    loop {
        if !state_dir.effective_state()?.lifecycle.is_active() {
            tracing::debug!("minvmd has stopped");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "the VM is still shutting down after {STOPPED_WAIT_SECS}s; \
                 run `minvmd stop` to force it down"
            )));
        }
        thread::sleep(Duration::from_millis(STOPPING_POLL_MS));
    }
}

/// Wait for the daemon the CLI talks to to finish shutting down. Only the
/// minvmd backend has a VM to tear down (and lifecycle state to observe); a
/// native minimald just exits, so there is nothing to wait for.
#[cfg(target_os = "macos")]
pub fn wait_for_daemon_stopped(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    let _ = use_minvmd;
    wait_for_minvmd_stopped(minimal_dir)
}

#[cfg(target_os = "linux")]
pub fn wait_for_daemon_stopped(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    if use_minvmd {
        return wait_for_minvmd_stopped(minimal_dir);
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn wait_for_daemon_stopped(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    let _ = (use_minvmd, minimal_dir);
    Ok(())
}

/// Ensure the daemon the CLI will talk to is running, spawning it if needed.
///
/// Backend selection:
/// - macOS: always via minvmd (libkrun/Hypervisor.framework; there is no native
///   macOS minimald). `use_minvmd`/`minimal_dir` are ignored.
/// - Linux: native minimald on the host (DM2) by default; the minvmd microVM
///   (DM1) when `use_minvmd` is set.
#[cfg(target_os = "macos")]
pub fn ensure_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    let _ = use_minvmd;
    ensure_minvmd_running(minimal_dir)
}

#[cfg(target_os = "linux")]
pub fn ensure_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    if use_minvmd {
        return ensure_minvmd_running(minimal_dir);
    }
    let sock = crate::client::resolve_socket_path(minimal_dir)
        .map_err(|e| io::Error::other(format!("resolving native minimald socket path: {e}")))?;
    ensure_minimald_running(&sock, minimal_dir)
}

/// On targets without an auto-spawn backend, this is a no-op.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn ensure_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<()> {
    let _ = (use_minvmd, minimal_dir);
    Ok(())
}

/// Whether the daemon the CLI talks to is currently up — the question
/// [`ensure_daemon_running`] answers before deciding to spawn, exposed for
/// callers that must *not* spawn. `min stop` is the case: without this it can
/// only discover an already-down daemon by failing to connect to it, which is a
/// connect error (or, against a stale socket, a timeout) for what is really the
/// goal state.
///
/// Backend selection mirrors [`ensure_daemon_running`] exactly, and each backend
/// uses the same probe its `ensure_*` counterpart gates its spawn on, so the two
/// cannot disagree about what "running" means.
///
/// This is a point-in-time answer, not a lease: the daemon can go down between
/// the probe and the caller's connect. Callers must still handle a failed
/// connect — this only keeps the *expected* case off that path.
#[cfg(target_os = "macos")]
pub fn is_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<bool> {
    let _ = use_minvmd;
    is_minvmd_running(minimal_dir)
}

#[cfg(target_os = "linux")]
pub fn is_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<bool> {
    if use_minvmd {
        return is_minvmd_running(minimal_dir);
    }
    let sock = crate::client::resolve_socket_path(minimal_dir)
        .map_err(|e| io::Error::other(format!("resolving native minimald socket path: {e}")))?;
    Ok(minimald_socket_live(&sock))
}

/// With no backend to probe, report "running" so the caller falls through to its
/// connect and surfaces whatever that says — the behaviour before this probe
/// existed. Claiming "not running" here would silently turn every such call into
/// a no-op on a platform we cannot actually observe.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn is_daemon_running(use_minvmd: bool, minimal_dir: Option<&Path>) -> io::Result<bool> {
    let _ = (use_minvmd, minimal_dir);
    Ok(true)
}

/// Whether a minvmd-backed VM is up. Read through `effective_state`, like the
/// rest of this module: a supervisor that died without writing `Stopped` leaves
/// `Running` behind, and that is a stopped VM, not a reachable one.
///
/// `is_active` counts `Stopping` as running: a VM mid-shutdown still holds the
/// socket, and a `stop` against it should ride out that shutdown rather than
/// return as though the VM were already down.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_minvmd_running(minimal_dir: Option<&Path>) -> io::Result<bool> {
    let provider_dir = crate::client::resolve_provider_dir(minimal_dir)?;
    let state_dir = minvmd::state::StateDir::new(provider_dir)?;
    Ok(state_dir.effective_state()?.lifecycle.is_active())
}

/// Linux native (DM2): the daemon is up exactly when its socket accepts a
/// connection. There is no lifecycle file for this backend — minimald owns the
/// socket for its whole lifetime, so reachability *is* the liveness signal.
///
/// Only two failures *prove* nothing is listening: a missing socket file, and a
/// refused connection (the stale file a killed daemon leaves behind — nothing
/// unlinks it). Every other connect error — a path over `SUN_LEN`, a directory
/// we cannot traverse — means we could not tell, and is deliberately reported as
/// live: the caller then attempts its own connect and surfaces the real error,
/// instead of this probe converting a broken socket path into a confident (and
/// wrong) "the daemon is not running".
#[cfg(target_os = "linux")]
fn minimald_socket_live(socket_path: &Path) -> bool {
    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_) => true,
        Err(e) => !matches!(
            e.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
        ),
    }
}

/// Linux native (DM2): if the SSH socket is not already accepting connections,
/// spawn `minimald run --detach --instance-num 0`. minimald daemonizes itself
/// (setsid) and only returns once it is listening, so this fail-fasts on a
/// non-zero exit.
#[cfg(target_os = "linux")]
fn ensure_minimald_running(socket_path: &Path, minimal_dir: Option<&Path>) -> io::Result<()> {
    if minimald_socket_live(socket_path) {
        tracing::debug!("native minimald already running (socket connectable)");
        return Ok(());
    }

    tracing::info!("spawning native minimald run --detach");
    // Forward the state-dir override so the spawned daemon binds the same socket
    // `resolve_socket_path` resolved above; otherwise minimald would default to
    // `$XDG_STATE_HOME/minimal` and the CLI would later connect to the override
    // socket and fail. minimald's flag is `--minimal-state-dir`.
    let mut cmd = Command::new("minimald");
    if let Some(dir) = minimal_dir {
        cmd.arg("--minimal-state-dir").arg(dir);
    }
    let output = cmd
        .args(["run", "--detach", "--instance-num", "0"])
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to spawn minimald: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "minimald run --detach failed: {stderr}"
        )));
    }
    tracing::info!("native minimald spawned successfully");
    Ok(())
}

#[cfg(test)]
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests {
    use super::{Decision, classify, is_daemon_running, wait_for_minvmd_stopped};
    use minvmd::lifecycle::Lifecycle;
    use minvmd::state::{State, StateDir};

    /// A state whose lifecycle is `l`, as a live supervisor would have left it.
    fn state_at(l: Lifecycle) -> State {
        State {
            lifecycle: l,
            vmm_pid: Some(999_999_999),
            started_at: Some(0),
        }
    }

    #[test]
    fn running_or_starting_needs_no_spawn() {
        assert_eq!(classify(Lifecycle::Running), Decision::AlreadyRunning);
        assert_eq!(classify(Lifecycle::Starting), Decision::AlreadyRunning);
    }

    #[test]
    fn stopped_or_not_provisioned_spawns() {
        assert_eq!(classify(Lifecycle::Stopped), Decision::Spawn);
        assert_eq!(classify(Lifecycle::NotProvisioned), Decision::Spawn);
    }

    #[test]
    fn stopping_waits_for_terminal_state() {
        assert_eq!(classify(Lifecycle::Stopping), Decision::WaitForStopping);
    }

    /// The state dir a `--minimal-dir` override resolves to.
    fn state_dir_for(minimal_dir: &std::path::Path) -> StateDir {
        StateDir::new(crate::client::resolve_provider_dir(Some(minimal_dir)).unwrap()).unwrap()
    }

    #[test]
    fn wait_returns_at_once_when_already_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        state_dir_for(tmp.path())
            .write_state(&State::stopped())
            .unwrap();
        wait_for_minvmd_stopped(Some(tmp.path())).expect("a stopped VM needs no waiting");
    }

    /// A supervisor that died without writing `Stopped` leaves `Running` behind
    /// but drops the alive lock. That is a stopped VM, not one still going down:
    /// the wait must resolve it, not sit out its deadline.
    #[test]
    fn wait_resolves_stale_running_state_from_a_dead_supervisor() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = state_dir_for(tmp.path());
        state_dir
            .write_state(&State {
                lifecycle: Lifecycle::Running,
                vmm_pid: Some(999_999_999),
                started_at: Some(0),
            })
            .unwrap();
        wait_for_minvmd_stopped(Some(tmp.path())).expect("stale Running must resolve as stopped");
        assert_eq!(
            state_dir.read_state().unwrap().lifecycle,
            Lifecycle::Stopped
        );
    }

    #[test]
    fn minvmd_is_not_running_when_never_provisioned() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_daemon_running(true, Some(tmp.path())).unwrap());
    }

    #[test]
    fn minvmd_is_not_running_when_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        state_dir_for(tmp.path())
            .write_state(&State::stopped())
            .unwrap();
        assert!(!is_daemon_running(true, Some(tmp.path())).unwrap());
    }

    /// The case the probe exists for: a supervisor that died without writing
    /// `Stopped` leaves `Running` behind. Trusting that would send `stop` at a
    /// socket nobody serves — the connect error the probe is meant to avoid.
    #[test]
    fn minvmd_is_not_running_on_stale_running_state_from_a_dead_supervisor() {
        let tmp = tempfile::tempdir().unwrap();
        state_dir_for(tmp.path())
            .write_state(&state_at(Lifecycle::Running))
            .unwrap();
        assert!(!is_daemon_running(true, Some(tmp.path())).unwrap());
    }

    #[test]
    fn minvmd_is_running_while_a_live_daemon_holds_the_alive_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = state_dir_for(tmp.path());
        state_dir
            .write_state(&state_at(Lifecycle::Running))
            .unwrap();
        let _alive = state_dir
            .try_acquire_alive_lock()
            .unwrap()
            .expect("the alive lock is free in a fresh state dir");
        assert!(is_daemon_running(true, Some(tmp.path())).unwrap());
    }

    /// A VM mid-shutdown still holds the socket, so `stop` should ride out its
    /// shutdown rather than report it already down.
    #[test]
    fn minvmd_stopping_still_counts_as_running() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = state_dir_for(tmp.path());
        state_dir
            .write_state(&state_at(Lifecycle::Stopping))
            .unwrap();
        let _alive = state_dir
            .try_acquire_alive_lock()
            .unwrap()
            .expect("the alive lock is free in a fresh state dir");
        assert!(is_daemon_running(true, Some(tmp.path())).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_minimald_is_not_running_when_no_socket_exists() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_daemon_running(false, Some(tmp.path())).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_minimald_is_running_when_the_socket_accepts() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = crate::client::resolve_socket_path(Some(tmp.path())).unwrap();
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(is_daemon_running(false, Some(tmp.path())).unwrap());
    }

    /// A crashed minimald leaves its socket file behind — std's `UnixListener`
    /// does not unlink on drop, and neither does a SIGKILL. The file existing is
    /// therefore not liveness; only a connect that is answered is.
    #[cfg(target_os = "linux")]
    #[test]
    fn native_minimald_is_not_running_when_the_socket_file_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = crate::client::resolve_socket_path(Some(tmp.path())).unwrap();
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(
            sock.exists(),
            "the stale socket file must outlive its daemon"
        );
        assert!(!is_daemon_running(false, Some(tmp.path())).unwrap());
    }

    /// A connect error that is not "refused" or "missing" leaves liveness
    /// unknown, and unknown must not read as "not running": that would report a
    /// clean stop for a socket path no daemon could ever bind, hiding the real
    /// error the caller's own connect is about to give. A path past `SUN_LEN` is
    /// the reachable case (a long `--minimal-dir`).
    #[cfg(target_os = "linux")]
    #[test]
    fn native_minimald_unknown_liveness_defers_to_the_callers_connect() {
        let tmp = tempfile::tempdir().unwrap();
        let long = tmp.path().join("d".repeat(120));
        std::fs::create_dir_all(&long).unwrap();
        let sock = crate::client::resolve_socket_path(Some(&long)).unwrap();
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        assert!(
            std::os::unix::net::UnixStream::connect(&sock)
                .unwrap_err()
                .kind()
                != std::io::ErrorKind::NotFound,
            "this test is only meaningful while the path is rejected for its length"
        );
        assert!(is_daemon_running(false, Some(&long)).unwrap());
    }
}
