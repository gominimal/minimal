//! `minvmd run` subcommand (R4.2).
//!
//! The foreground supervisor: resolves kernel + rootfs, manages lifecycle state
//! transitions (Stopped → Starting → Running → Stopped), spawns and supervises
//! the hidden `minvmd __krun-vmm` child, and waits for the guest `READY` marker
//! before reporting boot success.
//!
//! `--detach` mode: re-execs the supervisor as a background process (new
//! session via `setsid`) and returns only once the VM is serving (host UDS
//! connectable, alive lock held, lifecycle Running) or the configurable
//! timeout expires (R4.2).
//!
//! Without libkrun this subcommand bails immediately with a "no libkrun" error
//! so the stock Linux CI (which has no libkrun) stays green.

#[cfg(minvmd_libkrun)]
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
/// - `detach`: if true, spawn the supervisor in the background and poll until
///   the VM is serving (up to `timeout_secs`).
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

#[cfg(minvmd_libkrun)]
fn run_supervisor(detach: bool, timeout_secs: u64) -> Result<()> {
    // R2.4: fail fast with an actionable error if the hypervisor backend is
    // unavailable (Linux: /dev/kvm). No-op on macOS. Runs in the foreground
    // caller so the user sees the error directly, even under --detach.
    crate::cmd::ensure_hypervisor_accessible()?;
    // Likewise the sun_path limit: libkrun aborts on an over-long UDS path
    // deep in the VMM child; catch it here with a clear error instead.
    crate::sock::check_uds_path_len(&crate::sock::resolve_uds_path()?)?;
    crate::sock::check_uds_path_len(&crate::net::resolve_switch_sock()?)?;

    if detach {
        return run_detach(timeout_secs);
    }
    run_foreground()
}

/// Spawn `minvmd run` as a detached background supervisor, then poll until
/// the VM is serving (up to `timeout_secs`).
#[cfg(minvmd_libkrun)]
fn run_detach(timeout_secs: u64) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("run");
    if let Some(dir) = crate::state::state_dir_override() {
        cmd.args(["--minimal-state-dir", dir.as_str()]);
    }
    // The supervisor's stderr goes to a log file, not /dev/null: it carries
    // the boot-failure diagnosis (the guest's mount-failure reason, image
    // disposition, repair guidance), and the failure messages below point at
    // it. Truncated per attempt so it holds exactly this boot's story.
    let state_dir = crate::state::StateDir::new(crate::state::StateDir::default_path())
        .context("opening state dir")?;
    let log_path = state_dir.dir().join("run.log");
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("creating supervisor log at {}", log_path.display()))?;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(log));

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

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning background run supervisor: {}", exe.display()))?;

    // Ready = UDS connectable AND a minvmd holds the alive lock AND lifecycle
    // is Running. The socket alone is not proof: ssh.sock is shared with
    // native minimald (a live peer backend would satisfy a bare connect while
    // our child's mutual-exclusion bail goes to /dev/null), and libkrun binds
    // it at VMM start — long before the guest serves — dialling the guest
    // vsock lazily per connection, so an early connect succeeds and then
    // drops at ssh time. Running is written only after the guest's READY
    // marker, which follows its vsock bind. A child exit surfaces as an error
    // instead of a silent timeout.
    let uds_path = crate::sock::resolve_uds_path().context("resolving host UDS path")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait().context("polling supervisor child")? {
            bail!(
                "the detached supervisor exited during startup ({status}); \
                 see {} for its error output",
                log_path.display()
            );
        }
        if std::os::unix::net::UnixStream::connect(&uds_path).is_ok()
            && state_dir.daemon_alive().context("probing alive lock")?
            && state_dir.read_state().context("reading state")?.lifecycle
                == crate::lifecycle::Lifecycle::Running
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out after {timeout_secs}s waiting for minvmd to become ready on {} \
                 (supervisor log: {})",
                uds_path.display(),
                log_path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Foreground supervisor: boot the VM, manage lifecycle state, supervise until
/// the VMM child exits.
#[cfg(minvmd_libkrun)]
fn run_foreground() -> Result<()> {
    use std::io::{BufReader, Read as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::{resolve_kernel_path, resolve_rootfs_path};
    use crate::lifecycle::{Action, Lifecycle, next_state};
    use crate::state::{StartingGuard, State, StateDir};

    // Fail-fast: resolve paths before touching lifecycle state.
    // (UDS path lengths were already checked in `run_supervisor`.)
    let _kernel = resolve_kernel_path().context("resolving kernel path")?;
    let _rootfs = resolve_rootfs_path().context("resolving rootfs path")?;

    let state_dir = StateDir::new(StateDir::default_path()).context("opening state dir")?;

    // ── Phase 1: Stopped → Starting (under lock) ───────────────────────────
    // The alive lock outlives the block: held for the whole supervisor life
    // and inherited by the VMM child, so observers can tell a live daemon/VM
    // from stale state.
    let alive_lock;
    {
        let mut lock = state_dir
            .lifecycle_lock()
            .context("opening lifecycle lock")?;
        let _guard = lock.write().context("acquiring lifecycle write lock")?;
        let state = state_dir.read_state().context("reading state")?;

        alive_lock = match state_dir
            .try_acquire_alive_lock()
            .context("acquiring alive lock")?
        {
            Some(l) => l,
            None => match state.lifecycle {
                Lifecycle::Running => {
                    bail!("minvmd is already running (vmm_pid={:?})", state.vmm_pid)
                }
                Lifecycle::Starting => bail!("minvmd is already starting"),
                Lifecycle::Stopping => {
                    bail!("minvmd is stopping; wait for it to finish before restarting")
                }
                _ => bail!("another minvmd (a `boot` VM?) holds the alive lock"),
            },
        };

        // Both backends bind the same ssh.sock; don't steal a live native
        // daemon's socket.
        if state_dir
            .minimald_alive()
            .context("probing native minimald lock")?
        {
            bail!("a native minimald is serving this instance's socket; stop it first");
        }

        // The state machine only permits Start from Stopped: provision a
        // clean install, and reclaim (via Fail) active state left behind by a
        // dead daemon — we hold the alive lock, so nothing live wrote it.
        let base = match state.lifecycle {
            Lifecycle::NotProvisioned => {
                next_state(Lifecycle::NotProvisioned, Action::Provision)
                    .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?
            }
            stale if stale.is_active() => {
                tracing::warn!(?stale, "reclaiming state left by a dead daemon");
                next_state(stale, Action::Fail)
                    .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?
            }
            other => other,
        };
        let starting = next_state(base, Action::Start)
            .map_err(|e| anyhow::anyhow!("lifecycle transition error: {e}"))?;
        state_dir
            .write_state(&State {
                lifecycle: starting,
                ..State::stopped()
            })
            .context("writing Starting state")?;
    }

    // StartingGuard: resets lifecycle to Stopped on drop if we bail before
    // committing (R4.6). Holds no lock so concurrent readers observe the
    // transient Starting state without contention.
    let guard = StartingGuard::new(state_dir.dir().to_path_buf());

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
    // egress, and own-IP PTasks attach further taps; both
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
            crate::sock::prepare_socket_dir(&switch_sock).context("preparing switch socket dir")?;
            crate::sock::remove_stale_socket(&switch_sock)
                .context("removing stale switch socket")?;
            match crate::net::HostGvproxy::spawn(binary, switch_sock) {
                Ok(gvproxy) => {
                    tracing::info!(pid = gvproxy.pid(), "host gvproxy switch up");
                    Some(gvproxy)
                }
                // An own-IP VM cannot work without the switch: fail loudly. A
                // non-own-IP boot tolerates it (same as a missing binary below).
                Err(error) if crate::cmd::own_ip_requested() => {
                    return Err(error).context("spawning host gvproxy switch");
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "failed to spawn host gvproxy switch; booting without \
                         guest egress"
                    );
                    None
                }
            }
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

    // R2.5: record whether the data volume image pre-exists this boot, before
    // the VMM child provisions it — a later boot failure is fatal for a
    // pre-existing image (may hold session data) and recoverable for a blank
    // one freshly created by this boot.
    let volume_path = crate::volume::resolve_data_volume_path();
    let volume_preexisted = crate::cmd::volume_preexists(&volume_path);

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("__krun-vmm");
    if let Some(dir) = crate::state::state_dir_override() {
        cmd.args(["--minimal-state-dir", dir.as_str()]);
    }
    alive_lock.inherit_into(&mut cmd);
    let mut child = cmd
        .env(MARKER_SOCK_ENV, &marker_sock_path)
        .spawn()
        .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

    let child_pid = child.id();
    tracing::info!(pid = child_pid, "VMM child spawned");

    // Update state with the known pid so that concurrent `stop` invocations
    // during Starting can signal the correct process.
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
            bail!(
                "lifecycle changed to {:?} during spawn; aborting",
                state.lifecycle
            );
        }
        state_dir
            .write_state(&State {
                lifecycle: Lifecycle::Starting,
                vmm_pid: Some(child_pid),
                ..State::stopped()
            })
            .context("writing Starting state with vmm_pid")?;
    }

    // Wait for the guest to write `READY\n` on the marker socket. The wait is
    // env-configurable (`MINVMD_READY_TIMEOUT_SECS`): a cold multi-GiB VM can
    // take ~20s+ to reach userspace, so a fixed 5s was too short.
    let ready_timeout: Duration = crate::cmd::ready_timeout();
    let known_hosts_path = crate::cmd::default_vm_known_hosts_path();
    let (tx, rx) = std::sync::mpsc::channel::<Result<crate::cmd::BootBeacon, String>>();
    let sock_clone = marker_sock_path.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<crate::cmd::BootBeacon, String> {
            let (stream, _) = listener
                .accept()
                .map_err(|e| format!("accept on READY-marker socket: {e}"))?;
            let mut reader = BufReader::new(stream);
            crate::cmd::read_ready_beacon(&mut reader, &known_hosts_path)
        })();
        let _ = tx.send(result);
        let _ = std::fs::remove_file(&sock_clone);
    });

    let boot_result = match rx.recv_timeout(ready_timeout) {
        Ok(Ok(crate::cmd::BootBeacon::Ready)) => Ok(()),
        Ok(Ok(crate::cmd::BootBeacon::MountFailed { reason })) => Err(
            crate::cmd::mount_failed_error(&reason, &volume_path, volume_preexisted),
        ),
        Ok(Err(e)) => Err(anyhow::anyhow!("boot failed: {e}")),
        Err(_) => Err(anyhow::anyhow!(
            "boot timed out waiting for READY marker after {} s (raise {} to wait longer)",
            ready_timeout.as_secs(),
            crate::cmd::READY_TIMEOUT_ENV,
        )),
    };

    if let Err(e) = boot_result {
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_file(&marker_sock_path);
        crate::cmd::discard_fresh_volume_image(&volume_path, volume_preexisted);
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
        // Record the resources the running VM was booted with (R2.6), resolved
        // from a single config read so the (vcpus, ram_mib) pair cannot tear. The
        // VMM child resolves the same effective values from the inherited env +
        // shared config.toml; a `config set` landing inside the brief boot window
        // could still make this parent read diverge from the child's, but the
        // recorded pair itself is always self-consistent.
        let (booted_vcpus, booted_ram_mib) = crate::cmd::effective_resources();
        state_dir
            .write_state(&State {
                lifecycle: running,
                vmm_pid: Some(child_pid),
                started_at: Some(started_at),
                booted_vcpus: Some(booted_vcpus),
                booted_ram_mib: Some(booted_ram_mib),
            })
            .context("writing Running state")?;
    }
    guard.commit();
    tracing::info!(pid = child_pid, "VM is up; supervisor is running");

    // Tighten + verify the bridge socket permissions (R3.2): libkrun creates
    // it with default perms, and the shared provider dir is not 0700.
    match crate::sock::resolve_uds_path() {
        Ok(uds_path) => {
            if let Err(e) = crate::sock::enforce_socket_permissions(&uds_path)
                .and_then(|()| crate::sock::verify_socket_permissions(&uds_path))
            {
                tracing::warn!(
                    path = %uds_path.display(),
                    error = %e,
                    "could not secure minimald bridge socket to 0600",
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
        state_dir
            .write_state(&State::stopped())
            .context("writing Stopped state after VMM child exit")?;
    }

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        // R9.10: host-side analog of `minimal-entry`'s OOM post-mortem. Only a
        // real guest-workload exit code (libkrun `exit()`s the VMM child with it)
        // suggests resource exhaustion; a signal-kill (`code == None`) is a
        // deliberate `minvmd stop` terminating the child, not a crash — so the
        // resource hint would be misleading there and is suppressed.
        if status.code().is_some() {
            eprintln!(
                "minvmd: the VM exited abnormally (code {code}); if a build was killed for lack \
                 of resources, raise them with `minvmd config set --ram-mib <MiB>` / `--vcpus <n>`."
            );
        }
        bail!("VMM child exited with code {code}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(minvmd_libkrun))]
    use super::*;

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
