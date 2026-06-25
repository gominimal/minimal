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
    // devtmpfs provides `/dev/ptmx` but not the `/dev/pts` slave directory, so
    // `openpty(3)` (interactive session PTY) fails ENOENT without a devpts
    // mount. Create the mountpoint on the freshly-mounted devtmpfs and mount it.
    let devpts = format!("{NEWROOT}/dev/pts");
    let _ = std::fs::create_dir_all(&devpts);
    raw_mount("devpts", &devpts, "devpts", 0)?;
    raw_mount("proc", &format!("{NEWROOT}/proc"), "proc", 0)?;
    raw_mount("sysfs", &format!("{NEWROOT}/sys"), "sysfs", 0)?;
    raw_mount("tmpfs", &format!("{NEWROOT}/run"), "tmpfs", 0)?;
    // The rootfs is mounted read-only, but hakoniwa stages its per-container
    // mount namespace under /tmp (e.g. /tmp/hakoniwa-XXXX); without a writable
    // /tmp the interactive session sandbox fails to spawn with EROFS.
    raw_mount("tmpfs", &format!("{NEWROOT}/tmp"), "tmpfs", 0)?;

    let to_io = |_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in chroot path");
    let c_newroot = CString::new(NEWROOT).map_err(to_io)?;
    // SAFETY: `chroot(2)` with a valid C string for the new root.
    if unsafe { libc::chroot(c_newroot.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    std::env::set_current_dir("/")?;

    // pid-1 inherits no PATH from the kernel. Set the conventional guest PATH so
    // minimald's own tool lookups against the rootfs userland resolve — notably
    // `git`, which the session-context init shells out to for the upstream
    // checkout (`checkouts::command_exists`); without it, interactive attach
    // fails with "git command was not found in path".
    // SAFETY: runs once on the guest boot path (pid-1, just after chroot) before
    // the SSH server accepts connections or spawns any session task, so no other
    // thread is reading the environment concurrently.
    unsafe {
        std::env::set_var(
            "PATH",
            "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
        );
    }

    tracing::info!(device, "switched to upstream rootfs (pivot_root)");
    Ok(())
}

/// Mount the seeded-cache block `device` (ext4, read-write) at the guest cache
/// dir so session sandboxes compose offline from the pre-built closure.
///
/// Must run **after** [`enter_rootfs`] (so the chroot and the `/run` tmpfs are
/// in place) and **before** the daemon serves. The mountpoint lives on the
/// `/run` tmpfs, so it is created here. Read-write: mctx creates cache
/// subdirs / lockfiles, and writes persist to the host image file.
pub fn mount_cache(device: &str) -> std::io::Result<()> {
    // Must match `minimal_cache_dir`/`minimal_state_dir` for the microvm init in
    // `main.rs` (state is co-located here so package hardlinks stay on one fs).
    const CACHE_DIR: &str = "/run/minimal/cache";
    std::fs::create_dir_all(CACHE_DIR)?;
    raw_mount(device, CACHE_DIR, "ext4", 0)?;

    // The cache disk is a reusable, writable seeded artifact that also backs the
    // daemon's state dir. Reset any runtime state left by a prior boot — keep
    // only the seeded cache dirs; the host key (providers/), sandboxes, tasks,
    // and other state are regenerated. Without this a stale/corrupt host key
    // persisted on the image fails startup (`host_key` only regenerates on a
    // *missing* key, not a corrupt one).
    const SEED_KEEP: &[&str] = &["built", "vcs", "lc", "stdlib", "lost+found"];
    if let Ok(entries) = std::fs::read_dir(CACHE_DIR) {
        for entry in entries.flatten() {
            if SEED_KEEP
                .iter()
                .any(|k| std::ffi::OsStr::new(k) == entry.file_name())
            {
                continue;
            }
            let path = entry.path();
            let r = if entry.file_type().is_ok_and(|t| t.is_dir()) {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if let Err(e) = r {
                tracing::warn!(error = %e, path = %path.display(), "resetting stale cache-disk state");
            }
        }
    }
    tracing::info!(device, dir = CACHE_DIR, "mounted seeded cache disk");
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
