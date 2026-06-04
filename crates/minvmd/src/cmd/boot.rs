//! `minvmd boot` subcommand (R2.3, R2.4).
//!
//! The parent process:
//! 1. Resolves kernel and rootfs paths from env vars (fail-fast validation).
//! 2. Creates a UNIX socket at a unique temp path and begins listening (the
//!    READY-marker socket).
//! 3. Fork-execs `minvmd __krun-vmm` with `MINVMD_MARKER_SOCK` pointing to
//!    that socket so the VMM child can register it with libkrun.
//! 4. Writes the child PID to `vmm.pid` in the state directory.
//! 5. Waits up to 5 s for the guest to connect and write `READY\n` on the
//!    marker socket (R2.4). On success prints `vm-up` to stdout.
//! 6. With `--foreground`: stays alive until the VMM child exits, propagating
//!    its exit code.
//!
//! On Linux this subcommand bails immediately with a "macOS only" error so the
//! Linux-only CI stays green.

use anyhow::{Result, bail};

/// Run the `boot` subcommand.
///
/// `foreground`: if true, block until the VMM child process exits after the VM
/// is confirmed up.
pub fn run(foreground: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    return run_macos(foreground);

    #[cfg(not(target_os = "macos"))]
    {
        let _ = foreground;
        bail!("`minvmd boot` is macOS-only; this Linux build is a no-op stub");
    }
}

#[cfg(target_os = "macos")]
fn run_macos(foreground: bool) -> Result<()> {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::Context as _;

    use crate::cmd::MARKER_SOCK_ENV;
    use crate::image::{resolve_kernel_path, resolve_rootfs_path};
    use crate::state::StateDir;

    // Fail-fast: resolve paths before spawning anything.
    let _kernel = resolve_kernel_path().context("resolving kernel path")?;
    let _rootfs = resolve_rootfs_path().context("resolving rootfs path")?;

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

    // Spawn `minvmd __krun-vmm` — the VMM child that calls krun_start_enter.
    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut child = std::process::Command::new(&exe)
        .arg("__krun-vmm")
        .env(MARKER_SOCK_ENV, &marker_sock_path)
        // Inherit MINVMD_KERNEL_PATH and MINVMD_ROOTFS_PATH from environment.
        .spawn()
        .with_context(|| format!("spawning VMM child: {}", exe.display()))?;

    let child_pid = child.id();
    tracing::info!(pid = child_pid, "VMM child spawned");

    // Write vmm.pid to the state directory (R2.3).
    let state_dir = StateDir::new(StateDir::default_path()).context("opening state dir")?;
    let vmm_pid_path = state_dir.vmm_pid_path();
    std::fs::write(&vmm_pid_path, format!("{child_pid}\n")).context("writing vmm.pid")?;

    // Wait for the READY marker from the guest (R2.4): up to 5 s.
    const READY_TIMEOUT: Duration = Duration::from_secs(5);

    // Run the accept loop in a separate thread so we can apply a wall-clock
    // timeout without platform-specific socket options.
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let sock_path_clone = marker_sock_path.clone();
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
        let _ = std::fs::remove_file(&sock_path_clone);
    });

    match rx.recv_timeout(READY_TIMEOUT) {
        Ok(Ok(())) => {
            println!("vm-up");
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&vmm_pid_path);
            let _ = std::fs::remove_file(&marker_sock_path);
            bail!("boot failed: {e}");
        }
        Err(_timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&vmm_pid_path);
            let _ = std::fs::remove_file(&marker_sock_path);
            bail!("boot timed out waiting for READY marker after 5 s");
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
