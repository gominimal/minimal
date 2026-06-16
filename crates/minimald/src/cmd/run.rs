//! `minimald run` subcommand.
//!
//! The foreground supervisor: manages lifecycle state transitions
//! (Stopped → Starting → Running → Stopped), binds the UDS listener,
//! and runs the SSH server loop.
//!
//! `--detach` mode: spawns the supervisor as a background process (new
//! session via `setsid`) and returns only once the UDS is accepting
//! connections or the configurable timeout expires.

use std::{
    path::Path,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};

use crate::{
    lifecycle::{Action, Lifecycle, next_state},
    server::{Config, Server},
    state::{StartingGuard, State, StateDir},
};

/// Default timeout in seconds for `run --detach` to wait for the UDS.
/// Shorter than `minvmd`'s 8s since there's no VM boot.
pub const DEFAULT_DETACH_TIMEOUT_SECS: u64 = 4;

/// Run the `run` subcommand.
///
/// - `detach`: if true, spawn the supervisor in the background and poll the
///   UDS until it accepts connections (up to `timeout_secs`).
/// - `timeout_secs`: only used when `detach` is true; default 4 s.
pub async fn run(
    detach: bool,
    timeout_secs: u64,
    listen_on: &Path,
    config: Config,
    instance_num: u32,
) -> Result<()> {
    if detach {
        return run_detach(timeout_secs, listen_on);
    }
    run_foreground(listen_on, config, instance_num).await
}

/// Spawn `minimald run` as a detached background supervisor, then poll the
/// UDS until it accepts connections (up to `timeout_secs`).
fn run_detach(timeout_secs: u64, listen_on: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // SAFETY: setsid() is async-signal-safe. In the child, it creates a new
    // session so the supervisor is detached from the caller's controlling
    // terminal and not affected by SIGHUP when the shell exits.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    cmd.spawn()
        .with_context(|| format!("spawning background run supervisor: {}", exe.display()))?;

    poll_uds_ready(listen_on, Duration::from_secs(timeout_secs)).with_context(|| {
        format!(
            "waiting for minimald to become ready on {}",
            listen_on.display()
        )
    })
}

/// Poll `path` until a `UnixStream::connect` succeeds or `timeout` elapses.
///
/// Returns `Ok(())` on the first successful connect; returns an error on
/// timeout.
pub fn poll_uds_ready(path: &Path, timeout: Duration) -> Result<()> {
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    loop {
        if UnixStream::connect(path).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting for UDS at {} to accept connections",
                timeout.as_secs(),
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Foreground supervisor: bind the UDS, manage lifecycle state, run the
/// server loop until exit.
async fn run_foreground(
    listen_on: &Path,
    config: Config,
    instance_num: u32,
) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::net::UnixListener;

    // Remove stale socket before binding.
    if let Err(e) = std::fs::remove_file(listen_on)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(anyhow::anyhow!("socket already in use: {e}"));
    }

    let state_dir = StateDir::new(StateDir::default_path()).context("opening state dir")?;

    // ── Phase 1: Stopped → Starting (under lock) ───────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        match state.lifecycle {
            Lifecycle::Running => {
                bail!("minimald is already running (daemon_pid={:?})", state.daemon_pid)
            }
            Lifecycle::Starting => bail!("minimald is already starting"),
            Lifecycle::Stopping => {
                bail!("minimald is stopping; wait for it to finish before restarting")
            }
            Lifecycle::NotProvisioned | Lifecycle::Stopped => {}
        }

        // A clean install starts NotProvisioned; provision it
        // (NotProvisioned → Stopped) before starting.
        let base = match state.lifecycle {
            Lifecycle::NotProvisioned => {
                next_state(Lifecycle::NotProvisioned, Action::Provision)
                    .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?
            }
            other => other,
        };
        let starting = next_state(base, Action::Start)
            .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?;
        state_dir
            .write_state(&State {
                lifecycle: starting,
                daemon_pid: None,
                started_at: None,
            })
            .context("writing Starting state")?;
    }

    // StartingGuard: resets lifecycle to Stopped on drop if we bail before
    // committing (R4.6).
    let guard = StartingGuard::new(StateDir::default_path());

    // Bind the UDS listener.
    let listener = UnixListener::bind(listen_on)
        .map_err(|e| anyhow::anyhow!("listening to socket: {e}"))?;

    tracing::info!("Started listening on {}", listen_on.display());

    // Write daemon.pid and update state with the known pid.
    let daemon_pid = std::process::id();
    let daemon_pid_path = state_dir.daemon_pid_path();
    std::fs::write(&daemon_pid_path, format!("{daemon_pid}\n"))
        .context("writing daemon.pid")?;

    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        // A concurrent stop might have already reset us to Stopped; bail.
        if !matches!(state.lifecycle, Lifecycle::Starting) {
            let _ = std::fs::remove_file(&daemon_pid_path);
            bail!(
                "lifecycle changed to {:?} during spawn; aborting",
                state.lifecycle
            );
        }
        state_dir
            .write_state(&State {
                lifecycle: Lifecycle::Starting,
                daemon_pid: Some(daemon_pid),
                started_at: None,
            })
            .context("writing Starting state with daemon_pid")?;
    }

    // ── Phase 2: Starting → Running (under lock) ──────────────────────────
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        let running = next_state(state.lifecycle, Action::MarkRunning)
            .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?;
        state_dir
            .write_state(&State {
                lifecycle: running,
                daemon_pid: Some(daemon_pid),
                started_at: Some(started_at),
            })
            .context("writing Running state")?;
    }
    guard.commit();
    tracing::info!(pid = daemon_pid, "minimald is running");

    // Print the SSH debugging command for the user (same as before).
    let host = format!("local-{}", instance_num);
    tracing::info!(
        "Run the following to debug the socket:\n\nssh \\\n\t-o \
         'ProxyCommand=socat - UNIX-CONNECT:{}' \\\n\t-o \
         'UserKnownHostsFile={}' \\\n\t{}",
        listen_on.display(),
        listen_on
            .parent()
            .unwrap_or(Path::new("."))
            .join("known_hosts")
            .display(),
        host,
    );

    // ── Phase 3: Run the server loop ──────────────────────────────────────
    let result = Server::run(config, listener).await;

    // ── Phase 4: Running → Stopped (under lock) ───────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let _ = std::fs::remove_file(&daemon_pid_path);
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state after server exit")?;
    }

    result.map_err(|e| anyhow::anyhow!("serving on UDS: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_uds_returns_ok_when_listener_is_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(
            poll_uds_ready(&path, Duration::from_secs(1)).is_ok(),
            "expected Ok when a listener is bound"
        );
    }

    #[test]
    fn poll_uds_times_out_when_no_listener() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("absent.sock");
        let err = poll_uds_ready(&path, Duration::from_millis(150)).unwrap_err();
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
    }
}