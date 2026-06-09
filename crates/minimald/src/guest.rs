//! In-VM (pid-1) guest support for the minvmd microVM.
//!
//! When minimald runs as the kernel `init=` target inside the microVM it is
//! pid-1: there is no `/init.krun` and no service manager underneath it. This
//! module provides the extra responsibilities that role entails:
//!
//! * the boot contract — emit a one-shot `READY` marker so the host knows the
//!   guest is up (R2.4), then listen for the host→guest SSH bridge (R3.1);
//! * pid-1 hygiene — mount `/proc` and `/sys` (the kernel auto-mounts
//!   devtmpfs on `/dev` but not these), and reap orphaned children, since
//!   hakoniwa double-forks its namespace children and a pid-1 that ignores
//!   `SIGCHLD` would accumulate zombies.
//!
//! Per the spec we keep this minimal and "run as pid-1, revisit if zombie
//! reaping bites".

use std::ffi::CString;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

/// Vsock port the guest connects out to (on the host, CID 2) to announce it has
/// booted. The host listens here for the one-shot `READY` marker.
const BOOT_MARKER_PORT: u32 = 7350;

/// The boot marker payload written once at startup.
const BOOT_MARKER: &[u8] = b"READY\n";

/// Emits the one-shot boot marker to the host.
///
/// Connects out to the host (`VMADDR_CID_HOST`, [`BOOT_MARKER_PORT`]), writes
/// `READY\n`, and closes. The vsock device can lag immediately after boot, so
/// connection attempts are retried with a short backoff before giving up.
pub async fn emit_ready_marker() -> std::io::Result<()> {
    const MAX_ATTEMPTS: u32 = 50;
    const BACKOFF: Duration = Duration::from_millis(100);

    let addr = VsockAddr::new(VMADDR_CID_HOST, BOOT_MARKER_PORT);
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match VsockStream::connect(addr).await {
            Ok(mut stream) => {
                stream.write_all(BOOT_MARKER).await?;
                // `VsockStream` has an inherent `shutdown(Shutdown)` that
                // shadows the tokio trait method, so disambiguate to flush the
                // write half via the async trait.
                AsyncWriteExt::shutdown(&mut stream).await?;
                tracing::info!(attempt, "emitted boot READY marker");
                return Ok(());
            }
            Err(e) => {
                tracing::debug!(attempt, error = %e, "vsock not ready, retrying");
                last_err = Some(e);
                tokio::time::sleep(BACKOFF).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "vsock never became available")
    }))
}

/// Default device + mountpoint for the writable state disk.
///
/// The guest root image is read-only, but minimald's session store, SSH host
/// key, and build caches need a writable location. The host attaches a second
/// virtio-blk device (`/dev/vdb`) backed by a persistent ext4 image; we mount it
/// here and resolve the state + cache dirs underneath it.
pub const STATE_DISK_DEVICE: &str = "/dev/vdb";
pub const STATE_DISK_MOUNT: &str = "/var/lib/minimal";

/// Mounts the writable state disk (`device`, ext4) at `target`, formatting it
/// first if it is blank.
///
/// The host attaches a freshly-provisioned sparse image on first boot, so the
/// device is unformatted; the first `mount(2)` fails, we `mke2fs` it (the rootfs
/// ships e2fsprogs), and retry. On subsequent boots the disk is already ext4 and
/// the first mount succeeds. Required for guest mode — without it minimald has
/// nowhere to write its session store or host key.
pub fn mount_state_disk(device: &str, target: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(target)?;
    if raw_mount_ext4(device, target).is_ok() {
        tracing::info!(device, target, "mounted state disk");
        return Ok(());
    }
    // Likely blank on first boot — format ext4, then retry.
    tracing::info!(device, "state disk mount failed; formatting ext4");
    format_ext4(device)?;
    raw_mount_ext4(device, target)?;
    tracing::info!(device, target, "formatted + mounted state disk");
    Ok(())
}

/// Single `mount(2)` of `device` as ext4 (read-write) at `target`. `EBUSY`
/// (already mounted) is success.
fn raw_mount_ext4(device: &str, target: &str) -> std::io::Result<()> {
    raw_mount(device, target, "ext4", 0)
}

/// `mount(2)` with explicit flags. `EBUSY` (already mounted) is treated as
/// success.
fn raw_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> std::io::Result<()> {
    let to_io = |_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in mount argument");
    let c_source = CString::new(source).map_err(to_io)?;
    let c_target = CString::new(target).map_err(to_io)?;
    let c_fstype = CString::new(fstype).map_err(to_io)?;
    // SAFETY: `mount(2)` with valid, call-lifetime C strings for
    // source/target/fstype, the given flags, and a null data pointer.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBUSY) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// SPIKE M2: enter the upstream guest rootfs from the initramfs. Mounts the
/// rootfs block `device` (ext4, read-only) at `newroot`, brings up the
/// pseudo-filesystems + a writable tmpfs (for session state) inside it, then
/// chroots in. minimald (static, already running) keeps executing with the
/// rootfs as its filesystem view, so `/bin/sh`, `socat`, and their glibc libs
/// resolve. The `newroot/{dev,proc,sys,run}` mountpoints must exist in the
/// rootfs (the generic microvm-rootfs provides them).
pub fn enter_rootfs(device: &str, newroot: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(newroot)?;
    raw_mount(device, newroot, "ext4", libc::MS_RDONLY)?;
    raw_mount("devtmpfs", &format!("{newroot}/dev"), "devtmpfs", 0)?;
    raw_mount("proc", &format!("{newroot}/proc"), "proc", 0)?;
    raw_mount("sysfs", &format!("{newroot}/sys"), "sysfs", 0)?;
    raw_mount("tmpfs", &format!("{newroot}/run"), "tmpfs", 0)?;

    let to_io = |_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in chroot path");
    let c_newroot = CString::new(newroot).map_err(to_io)?;
    // SAFETY: `chroot(2)` with a valid C string for the new root.
    if unsafe { libc::chroot(c_newroot.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    std::env::set_current_dir("/")?;
    tracing::info!(device, "entered upstream rootfs (chroot)");
    Ok(())
}

/// Format `device` as ext4 via the rootfs's `mke2fs` (e2fsprogs). No journal:
/// the data disk is small and crash-consistency is not required for the bring-up
/// session store.
fn format_ext4(device: &str) -> std::io::Result<()> {
    let status = std::process::Command::new("/usr/sbin/mke2fs")
        .args(["-q", "-F", "-t", "ext4", "-O", "^has_journal", device])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "mke2fs on {device} failed: {status}"
        )));
    }
    Ok(())
}

/// Spawn a socat relay bridging the host-mediated vsock `port` to a local UDS.
///
/// A direct `tokio_vsock::VsockListener` (`Server::run_on_vsock`) *accepts* the
/// bridged connection fine, but the SSH session over it dies almost immediately
/// with `Protocol error: early eof` — libkrun's bridged vsock stream does not
/// sustain a full bidirectional SSH session (a single short request/response, as
/// in minvmd's bridge_e2e, works). socat terminates the vsock and hands russh a
/// stable UNIX-domain stream over which the session completes, so we relay
/// through socat (already in the rootfs) into minimald's native `run_on_uds`.
/// The returned child is not kill-on-drop; pid-1's reaper handles it.
pub fn spawn_vsock_relay(port: u32, uds_path: &str) -> std::io::Result<std::process::Child> {
    let child = std::process::Command::new("/usr/bin/socat")
        .arg(format!("VSOCK-LISTEN:{port},fork"))
        .arg(format!("UNIX-CONNECT:{uds_path}"))
        .spawn()?;
    tracing::info!(port, uds = uds_path, "started vsock->uds relay (socat)");
    Ok(child)
}

/// Mounts `/proc` and `/sys` if they are not already present.
///
/// The kernel auto-mounts devtmpfs on `/dev`, but not these pseudo
/// filesystems; hakoniwa and other tooling need them. Missing or
/// already-mounted points are handled gracefully (an `EBUSY` from a
/// double mount is ignored).
pub fn mount_pseudo_filesystems() {
    mount_if_absent("/proc", "proc", "proc");
    mount_if_absent("/sys", "sysfs", "sysfs");
}

/// Mounts devtmpfs on `/dev`. The kernel auto-mounts it for a block-device root,
/// but NOT for an initramfs root — so an initramfs pid-1 must do it to get
/// `/dev/vsock`, `/dev/vda`, etc. EBUSY (already mounted) is benign.
pub fn mount_dev() {
    mount_if_absent("/dev", "devtmpfs", "devtmpfs");
}

/// Mounts `fstype` at `target` unless `target/<sentinel-of-fstype>` already
/// exists, i.e. unless it already looks mounted. Failures are logged, not
/// fatal: a pid-1 that can't mount /proc should still try to serve.
fn mount_if_absent(target: &str, source: &str, fstype: &str) {
    // Cheap "already mounted?" probe: /proc/self and /sys/kernel exist only
    // when the respective fs is mounted.
    let sentinel = match target {
        "/proc" => "/proc/self",
        "/sys" => "/sys/kernel",
        "/dev" => "/dev/null",
        _ => target,
    };
    if std::path::Path::new(sentinel).exists() {
        tracing::debug!(target, "pseudo fs already mounted");
        return;
    }

    if let Err(e) = std::fs::create_dir_all(target) {
        tracing::warn!(target, error = %e, "could not create mount point");
    }

    let (c_source, c_target, c_fstype) = match (
        CString::new(source),
        CString::new(target),
        CString::new(fstype),
    ) {
        (Ok(s), Ok(t), Ok(f)) => (s, t, f),
        _ => {
            tracing::warn!(target, "invalid mount argument");
            return;
        }
    };

    // SAFETY: `mount(2)` takes C strings for source/target/fstype (kept alive
    // for the call), a flags bitmask, and an optional data pointer (null here).
    // All pointers are valid for the duration of the call and there are no
    // Rust-side aliasing concerns.
    let rc = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // EBUSY: already mounted — benign.
        if err.raw_os_error() != Some(libc::EBUSY) {
            tracing::warn!(target, error = %err, "mount failed");
        }
    } else {
        tracing::info!(target, fstype, "mounted pseudo filesystem");
    }
}

/// Installs a `SIGCHLD` handler that reaps any terminated children.
///
/// As pid-1, minimald inherits orphaned grandchildren (hakoniwa double-forks
/// its namespace children), and must reap them or they become zombies. The
/// handler loops `waitpid(-1, WNOHANG)` until no more children are ready.
pub fn install_child_reaper() {
    // SAFETY: registering a signal handler. `reap_handler` only calls
    // `waitpid`, which is async-signal-safe, so it is safe to run in signal
    // context. `sigaction` is given a fully-initialised `sigaction` struct.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = reap_handler as *const () as usize;
        action.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "failed to install SIGCHLD reaper",
            );
        }
    }
}

/// `SIGCHLD` handler: reaps every available child without blocking.
///
/// # Safety
/// Runs in async-signal context. It only calls `waitpid(2)`, which is
/// async-signal-safe, and touches no shared Rust state.
extern "C" fn reap_handler(_sig: libc::c_int) {
    // SAFETY: `waitpid` is async-signal-safe; WNOHANG makes it non-blocking.
    // We loop until it reports no more reapable children (0) or an error
    // (e.g. ECHILD, -1).
    unsafe { while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {} }
}
