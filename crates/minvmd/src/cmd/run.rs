//! `minvmd run` subcommand (R4.2).
//!
//! The foreground supervisor: resolves kernel + rootfs, manages lifecycle state
//! transitions (Stopped → Starting → Running → Stopped), spawns and supervises
//! the hidden `minvmd __krun-vmm` child, and waits for the guest `READY` marker
//! before reporting boot success.
//!
//! `--detach` mode: re-execs the supervisor as a background process (new
//! session via `setsid`) and returns only once the host UDS is accepting
//! connections or the configurable timeout expires (R4.2).
//!
//! Without libkrun this subcommand bails immediately with a "no libkrun" error
//! so the stock Linux CI (which has no libkrun) stays green.

use std::time::Duration;

use anyhow::{Result, bail};
// `.context()` is only called from the libkrun-gated supervisor functions; on
// the stub build the trait is unused, so scope the import to match.
#[cfg(minvmd_libkrun)]
use anyhow::Context as _;

/// Default timeout in seconds for `run --detach` to wait for the host UDS.
pub const DEFAULT_DETACH_TIMEOUT_SECS: u64 = 8;

/// Run the `run` subcommand.
///
/// - `detach`: if true, spawn the supervisor in the background and poll the
///   host UDS until it accepts connections (up to `timeout_secs`).
/// - `timeout_secs`: only used when `detach` is true; default 8 s.
pub fn run(detach: bool, timeout_secs: u64) -> Result<()> {
    #[cfg(minvmd_libkrun)]
    return run_supervisor(detach, timeout_secs);

    #[cfg(not(minvmd_libkrun))]
    {
        let _ = (detach, timeout_secs);
        bail!("`minvmd run` requires libkrun (macOS, or Linux with libkrun installed)");
    }
}

/// Poll `path` until a `UnixStream::connect` succeeds or `timeout` elapses.
///
/// Exposed publicly for unit testing and reuse by `run --detach`.
/// Returns `Ok(())` on the first successful connect; returns an error on
/// timeout.
pub fn poll_uds_ready(path: &std::path::Path, timeout: Duration) -> Result<()> {
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

#[cfg(minvmd_libkrun)]
fn run_supervisor(detach: bool, timeout_secs: u64) -> Result<()> {
    // R2.4: fail fast with an actionable error if the hypervisor backend is
    // unavailable (Linux: /dev/kvm). No-op on macOS. Runs in the foreground
    // caller so the user sees the error directly, even under --detach.
    crate::cmd::ensure_hypervisor_accessible()?;

    if detach {
        return run_detach(timeout_secs);
    }
    run_foreground()
}

/// Spawn `minvmd run` as a detached background supervisor, then poll the host
/// UDS until it accepts connections (up to `timeout_secs`).
#[cfg(minvmd_libkrun)]
fn run_detach(timeout_secs: u64) -> Result<()> {
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

    let uds_path = crate::sock::resolve_uds_path().context("resolving host UDS path")?;
    poll_uds_ready(&uds_path, Duration::from_secs(timeout_secs)).with_context(|| {
        format!(
            "waiting for minvmd to become ready on {}",
            uds_path.display()
        )
    })
}

/// Foreground supervisor: boot the VM, manage lifecycle state, supervise until
/// the VMM child exits.
#[cfg(minvmd_libkrun)]
fn run_foreground() -> Result<()> {
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::{resolve_kernel_path, resolve_rootfs_path};
    use crate::lifecycle::{Action, Lifecycle, next_state};
    use crate::state::{StartingGuard, State, StateDir};

    // Fail-fast: resolve paths before touching lifecycle state.
    let _kernel = resolve_kernel_path().context("resolving kernel path")?;
    let _rootfs = resolve_rootfs_path().context("resolving rootfs path")?;

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
                bail!("minvmd is already running (vmm_pid={:?})", state.vmm_pid)
            }
            Lifecycle::Starting => bail!("minvmd is already starting"),
            Lifecycle::Stopping => {
                bail!("minvmd is stopping; wait for it to finish before restarting")
            }
            Lifecycle::NotProvisioned | Lifecycle::Stopped => {}
        }

        // A clean install starts NotProvisioned; provision it
        // (NotProvisioned → Stopped) before starting, since the state machine
        // only permits Start from Stopped.
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
                vmm_pid: None,
                started_at: None,
            })
            .context("writing Starting state")?;
    }

    // StartingGuard: resets lifecycle to Stopped on drop if we bail before
    // committing (R4.6). Holds no lock so concurrent readers observe the
    // transient Starting state without contention.
    let guard = StartingGuard::new(StateDir::default_path());

    // ── Boot sequence ────────────────────────────────────────────────────────
    let nonce: u32 = {
        let mut buf = [0u8; 4];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .context("reading /dev/urandom for marker socket nonce")?;
        u32::from_le_bytes(buf)
    };
    let marker_sock_path = PathBuf::from(format!(
        "/tmp/minvmd-marker-{}-{nonce:08x}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker_sock_path);

    let listener =
        UnixListener::bind(&marker_sock_path).context("binding READY-marker unix socket")?;
    listener
        .set_nonblocking(false)
        .context("setting listener to blocking")?;

    // Spawn + supervise the host gvproxy switch before the VMM child boots, so
    // its `-listen` switch socket exists when libkrun dials it for the guest
    // shuttle. The guest's root netns (the daemon) attaches a primary tap for
    // egress (issue #572 extended), and own-IP PTasks attach further taps; both
    // are L2 clients on this one switch. The handle lives for the VM's lifetime
    // and stops gvproxy on drop (after the VMM child exits below).
    //
    // Best-effort: when the gvproxy binary is absent (e.g. the boot/session e2e
    // lanes that exercise only the vsock bridge) we warn and boot without
    // egress rather than failing the VM — the daemon then has no network, the
    // pre-existing behaviour.
    let _gvproxy = match crate::image::resolve_gvproxy_path() {
        binary if binary.exists() => {
            let switch_sock =
                crate::net::resolve_switch_sock().context("resolving switch socket")?;
            crate::sock::prepare_socket_dir(&switch_sock)
                .context("preparing switch socket dir")?;
            crate::sock::remove_stale_socket(&switch_sock)
                .context("removing stale switch socket")?;
            let gvproxy = crate::net::HostGvproxy::spawn(binary, switch_sock)
                .context("spawning host gvproxy switch")?;
            tracing::info!(pid = gvproxy.pid(), "host gvproxy switch up");
            Some(gvproxy)
        }
        binary if crate::cmd::own_ip_requested() => {
            // An own-IP VM cannot work without the switch: fail loudly rather
            // than booting a session that silently has no network.
            bail!(
                "own-IP VM requested but the gvproxy binary was not found at {}; \
                 set MINVMD_GVPROXY_BIN to the gvproxy binary",
                binary.display()
            );
        }
        binary => {
            // Non-own-IP boots (e.g. the boot/session e2e lanes) tolerate a
            // missing gvproxy: warn and boot without guest egress.
            tracing::warn!(
                path = %binary.display(),
                "gvproxy binary not found; booting without guest egress \
                 (set MINVMD_GVPROXY_BIN to enable networking)"
            );
            None
        }
    };

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut child = std::process::Command::new(&exe)
        .arg("__krun-vmm")
        .env(MARKER_SOCK_ENV, &marker_sock_path)
        .spawn()
        .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

    let child_pid = child.id();
    tracing::info!(pid = child_pid, "VMM child spawned");

    // Write vmm.pid and update state with the known pid so that concurrent
    // `stop` invocations during Starting can signal the correct process.
    let vmm_pid_path = state_dir.vmm_pid_path();
    std::fs::write(&vmm_pid_path, format!("{child_pid}\n")).context("writing vmm.pid")?;

    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;
        // A concurrent stop might have already reset us to Stopped; bail early.
        if !matches!(state.lifecycle, Lifecycle::Starting) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&vmm_pid_path);
            bail!(
                "lifecycle changed to {:?} during spawn; aborting",
                state.lifecycle
            );
        }
        state_dir
            .write_state(&State {
                lifecycle: Lifecycle::Starting,
                vmm_pid: Some(child_pid),
                started_at: None,
            })
            .context("writing Starting state with vmm_pid")?;
    }

    // Wait up to 5 s for the guest to write `READY\n` on the marker socket.
    const READY_TIMEOUT: Duration = Duration::from_secs(5);
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let sock_clone = marker_sock_path.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let (stream, _) = listener
                .accept()
                .map_err(|e| format!("accept on READY-marker socket: {e}"))?;
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| format!("reading READY marker: {e}"))?;
            let trimmed = line.trim();
            if trimmed != "READY" {
                return Err(format!("expected READY on marker socket, got {trimmed:?}"));
            }
            Ok(())
        })();
        let _ = tx.send(result);
        let _ = std::fs::remove_file(&sock_clone);
    });

    let boot_result = match rx.recv_timeout(READY_TIMEOUT) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow::anyhow!("boot failed: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "boot timed out waiting for READY marker after 5 s"
        )),
    };

    if let Err(e) = boot_result {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&vmm_pid_path);
        let _ = std::fs::remove_file(&marker_sock_path);
        return Err(e);
        // guard drops here → StartingGuard resets state to Stopped (R4.6)
    }

    // ── Phase 2: Starting → Running (under lock) ────────────────────────────
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
                vmm_pid: Some(child_pid),
                started_at: Some(started_at),
            })
            .context("writing Running state")?;
    }
    guard.commit();
    tracing::info!(pid = child_pid, "VM is up; supervisor is running");

    // Verify the bridge socket permissions (R3.2).
    match crate::sock::resolve_uds_path() {
        Ok(uds_path) => {
            if let Err(e) = crate::sock::verify_socket_permissions(&uds_path) {
                tracing::warn!(
                    path = %uds_path.display(),
                    error = %e,
                    "minimald bridge socket permissions check failed",
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "minimald bridge socket path resolution failed");
        }
    }

    // ── Phase 3: Supervise until VMM child exits ─────────────────────────────
    let status = child.wait().context("waiting for VMM child")?;
    tracing::info!(success = status.success(), "VMM child exited");

    // ── Phase 4: Running → Stopped (under lock) ─────────────────────────────
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let _ = std::fs::remove_file(&vmm_pid_path);
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state after VMM child exit")?;
    }

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        bail!("VMM child exited with code {code}");
    }

    Ok(())
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

    #[cfg(not(minvmd_libkrun))]
    #[test]
    fn run_bails_without_libkrun() {
        let err = run(false, DEFAULT_DETACH_TIMEOUT_SECS).unwrap_err();
        assert!(
            err.to_string().contains("requires libkrun"),
            "expected libkrun-required message, got: {err}"
        );
    }
}
