//! In-VM (pid-1) guest support for the minvmd microVM.
//!
//! minimald ships as the initramfs `/init`, so the kernel runs it as pid-1:
//! there is no `/init.krun` and no service manager underneath it. This module
//! provides the extra responsibilities that role entails:
//!
//! * the boot contract — emit a one-shot `READY` marker so the host knows the
//!   guest is up (R2.4);
//! * pid-1 hygiene — mount `/dev` (devtmpfs; the kernel does NOT auto-mount it
//!   for an initramfs root), `/proc`, and `/sys`;
//! * entering the generic upstream rootfs — mount the ext4 root block device
//!   and `chroot` into it so the userland (`/bin/sh`, libs) resolves.
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

/// Enter the generic upstream guest rootfs from the initramfs. Mounts the rootfs
/// block `device` (ext4, read-only), brings up the pseudo-filesystems +
/// a writable tmpfs (for session state) inside it, then chroots in.
///
/// NOTE: The rootfs at the time this function is called is expected to be the initramfs.
/// If it is instead another filesystem, then its memory will not be reclaimed.
///
/// The `/{dev,proc,sys,run}` mountpoints must already exist on the provided rootfs
/// device.
pub fn enter_rootfs(device: &str) -> std::io::Result<()> {
    const NEWROOT: &str = "/newroot";
    std::fs::create_dir_all(NEWROOT)?;
    raw_mount(device, NEWROOT, "ext4", libc::MS_RDONLY)?;
    raw_mount("devtmpfs", &format!("{NEWROOT}/dev"), "devtmpfs", 0)?;
    raw_mount("proc", &format!("{NEWROOT}/proc"), "proc", 0)?;
    raw_mount("sysfs", &format!("{NEWROOT}/sys"), "sysfs", 0)?;
    raw_mount("tmpfs", &format!("{NEWROOT}/run"), "tmpfs", 0)?;

    let to_io = |_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in chroot path");
    let c_newroot = CString::new(NEWROOT).map_err(to_io)?;
    // SAFETY: `chroot(2)` with a valid C string for the new root.
    if unsafe { libc::chroot(c_newroot.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    std::env::set_current_dir("/")?;

    tracing::info!(device, "switched to upstream rootfs (pivot_root)");
    Ok(())
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
