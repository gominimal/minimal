//! `minvmd boot` subcommand (R2.3, R2.4).
//!
//! The parent process:
//! 1. Resolves kernel and rootfs paths from env vars (fail-fast validation).
//! 2. Creates a UNIX socket at a unique temp path and begins listening (the
//!    READY-marker socket).
//! 3. Fork-execs `minvmd __krun-vmm` with `MINVMD_MARKER_SOCK` pointing to
//!    that socket so the VMM child can register it with libkrun.
//! 4. Waits up to 5 s for the guest to connect and write `READY\n` on the
//!    marker socket (R2.4). On success prints `vm-up` to stdout.
//! 5. With `--foreground`: stays alive until the VMM child exits, propagating
//!    its exit code.
//!
//! Without libkrun this subcommand bails immediately with a "no libkrun" error
//! so the stock Linux CI (which has no libkrun) stays green.

use anyhow::{Result, bail};

/// Run the `boot` subcommand.
///
/// `foreground`: if true, block until the VMM child process exits after the VM
/// is confirmed up.
pub fn run(foreground: bool) -> Result<()> {
    #[cfg(minvmd_libkrun)]
    return run_boot(foreground);

    #[cfg(not(minvmd_libkrun))]
    {
        let _ = foreground;
        bail!("`minvmd boot` requires libkrun (macOS, or Linux with libkrun installed)");
    }
}

#[cfg(minvmd_libkrun)]
fn run_boot(foreground: bool) -> Result<()> {
    use std::io::BufReader;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::Context as _;

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::{resolve_kernel_path, resolve_rootfs_path};
    use crate::state::StateDir;

    // R2.4: fail fast with an actionable error if the hypervisor backend is
    // unavailable (Linux: /dev/kvm). No-op on macOS.
    crate::cmd::ensure_hypervisor_accessible()?;

    // Fail-fast: resolve paths before spawning anything. The UDS length
    // checks catch sun_path overflows here, with a clear error, instead of as
    // a libkrun abort in the VMM child after the READY timeout.
    let _kernel = resolve_kernel_path().context("resolving kernel path")?;
    let _rootfs = resolve_rootfs_path().context("resolving rootfs path")?;
    crate::sock::check_uds_path_len(&crate::sock::resolve_uds_path()?)?;
    crate::sock::check_uds_path_len(&crate::net::resolve_switch_sock()?)?;

    // `boot` skips lifecycle state, but not mutual exclusion: it binds the
    // shared ssh.sock, so it must hold the alive lock (inherited by the VMM
    // child below — for a non-foreground boot the lock lives on in the child
    // after this parent exits) and must not steal a native daemon's socket.
    let state_dir = StateDir::new(StateDir::default_path()).context("opening state dir")?;
    let alive_lock = state_dir
        .try_acquire_alive_lock()
        .context("acquiring alive lock")?
        .ok_or_else(|| {
            anyhow::anyhow!("minvmd is already running (or another boot VM is up); stop it first")
        })?;
    if state_dir
        .minimald_alive()
        .context("probing native minimald lock")?
    {
        bail!("a native minimald is serving this instance's socket; stop it first");
    }

    // Create the marker socket under /tmp with a PID + random nonce to prevent
    // predictable-path TOCTOU attacks (local-only risk, but cheap to harden).
    let nonce: u32 = {
        use std::io::Read as _;
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

    // Remove any stale socket from a previous run.
    let _ = std::fs::remove_file(&marker_sock_path);

    let listener =
        UnixListener::bind(&marker_sock_path).context("binding READY-marker unix socket")?;
    listener
        .set_nonblocking(false)
        .context("setting listener to blocking")?;

    // R2.5: record whether the data volume image pre-exists this boot, before
    // the VMM child provisions it — a later MOUNT_FAILED is fatal for a
    // pre-existing image (may hold session data) and recoverable for a blank
    // one freshly created by this boot.
    let volume_path = crate::volume::resolve_data_volume_path();
    let volume_preexisted = volume_path.exists();

    // Spawn `minvmd __krun-vmm` — the VMM child that calls krun_start_enter.
    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("__krun-vmm");
    if let Some(dir) = crate::state::state_dir_override() {
        cmd.args(["--minimal-state-dir", dir.as_str()]);
    }
    alive_lock.inherit_into(&mut cmd);
    let mut child = cmd
        .env(MARKER_SOCK_ENV, &marker_sock_path)
        // Inherit MINVMD_KERNEL_PATH and MINVMD_ROOTFS_PATH from environment.
        .spawn()
        .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

    let child_pid = child.id();
    tracing::info!(pid = child_pid, "VMM child spawned");

    // Wait for the READY marker from the guest (R2.4). The wait is
    // env-configurable (`MINVMD_READY_TIMEOUT_SECS`): a cold multi-GiB VM can
    // take ~20s+ to reach userspace, so a fixed 5s was too short.
    let ready_timeout: Duration = crate::cmd::ready_timeout();

    let known_hosts_path = crate::cmd::default_vm_known_hosts_path();

    // Run the accept loop in a separate thread so we can apply a wall-clock
    // timeout without platform-specific socket options.
    let (tx, rx) = std::sync::mpsc::channel::<Result<crate::cmd::BootBeacon, String>>();
    let sock_path_clone = marker_sock_path.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<crate::cmd::BootBeacon, String> {
            let (stream, _) = listener
                .accept()
                .map_err(|e| format!("accept on READY-marker socket: {e}"))?;
            let mut reader = BufReader::new(stream);
            crate::cmd::read_ready_beacon(&mut reader, &known_hosts_path)
        })();
        let _ = tx.send(result);
        let _ = std::fs::remove_file(&sock_path_clone);
    });

    match rx.recv_timeout(ready_timeout) {
        Ok(Ok(crate::cmd::BootBeacon::Ready)) => {
            println!("vm-up");
            // R3.2: by the time READY arrives, libkrun has created and is
            // listening on the minimald bridge socket. libkrun creates it with
            // default permissions, so tighten it to owner-only (0600) from the
            // parent process.
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
                    tracing::warn!(
                        error = %e,
                        "minimald bridge socket path resolution failed; skipping permission check",
                    );
                }
            }
        }
        Ok(Ok(crate::cmd::BootBeacon::MountFailed { reason })) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&marker_sock_path);
            return Err(crate::cmd::mount_failed_error(
                &reason,
                &volume_path,
                volume_preexisted,
            ));
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&marker_sock_path);
            bail!("boot failed: {e}");
        }
        Err(_timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&marker_sock_path);
            bail!(
                "boot timed out waiting for READY marker after {} s (raise {} to wait longer)",
                ready_timeout.as_secs(),
                crate::cmd::READY_TIMEOUT_ENV,
            );
        }
    }

    if foreground {
        let status = child.wait().context("waiting for VMM child")?;
        if !status.success() {
            let code = status.code().unwrap_or(-1);
            bail!("VMM child exited with code {code}");
        }
    }

    Ok(())
}
