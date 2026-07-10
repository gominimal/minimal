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

use russh::keys::ssh_key::PublicKey;
use tokio::io::AsyncWriteExt;
use tokio_vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

/// Vsock port the guest connects out to (on the host, CID 2) to announce it has
/// booted. The host listens here for the one-shot `READY` marker.
const BOOT_MARKER_PORT: u32 = 7350;

/// Writes the two-line beacon payload (`READY\n<openssh-pubkey>\n`) to the
/// given async writer.
///
/// Factored out of [`emit_ready_marker`] so tests can exercise the format
/// with an in-memory writer instead of a live vsock connection.
pub(crate) async fn write_ready_beacon<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    pubkey: &PublicKey,
) -> std::io::Result<()> {
    let openssh = pubkey
        .to_openssh()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let payload = format!("READY\n{openssh}\n");
    writer.write_all(payload.as_bytes()).await
}

/// Emits the one-shot boot marker to the host, including the SSH host public key.
///
/// Connects out to the host (`VMADDR_CID_HOST`, [`BOOT_MARKER_PORT`]), writes
/// `READY\n<openssh-pubkey>\n`, and closes. The vsock device can lag immediately
/// after boot, so connection attempts are retried with a short backoff before
/// giving up.
pub async fn emit_ready_marker(pubkey: &PublicKey) -> std::io::Result<()> {
    let mut payload = Vec::new();
    write_ready_beacon(&mut payload, pubkey).await?;
    emit_marker(&payload, "READY").await
}

/// Emits the one-shot boot marker to the host (simple form: no host key).
///
/// Used in the degraded fallback path where the rootfs could not be mounted
/// and no SSH server is running. The host-side beacon reader handles a missing
/// second line gracefully (R2.3).
pub async fn emit_simple_ready_marker() -> std::io::Result<()> {
    emit_marker(b"READY\n", "READY (simple)").await
}

/// Emits the loud mount-failure marker instead of READY (spec R2.5): the data
/// volume is attached but could not be mounted, so the guest must not appear
/// healthy. The host beacon reader surfaces the reason to the user and decides
/// fatality (fatal when a prior volume image exists).
pub async fn emit_mount_failed_marker(reason: &str) -> std::io::Result<()> {
    emit_marker(&mount_failed_beacon(reason), "MOUNT_FAILED").await
}

/// Maximum bytes of failure reason carried in the `MOUNT_FAILED` beacon. The
/// host reads the reason with a capped line reader, so longer text is cut here
/// rather than truncated mid-protocol on the host side.
const MOUNT_FAILED_REASON_MAX_BYTES: usize = 512;

/// Builds the two-line `MOUNT_FAILED\n<one-line reason>\n` beacon payload.
/// The reason is flattened to a single line and capped at
/// [`MOUNT_FAILED_REASON_MAX_BYTES`] (on a char boundary).
pub(crate) fn mount_failed_beacon(reason: &str) -> Vec<u8> {
    let mut reason: String = reason
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let mut cut = MOUNT_FAILED_REASON_MAX_BYTES.min(reason.len());
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    reason.truncate(cut);
    format!("MOUNT_FAILED\n{reason}\n").into_bytes()
}

async fn emit_marker(payload: &[u8], label: &str) -> std::io::Result<()> {
    const MAX_ATTEMPTS: u32 = 50;
    const BACKOFF: Duration = Duration::from_millis(100);

    let addr = VsockAddr::new(VMADDR_CID_HOST, BOOT_MARKER_PORT);
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match VsockStream::connect(addr).await {
            Ok(mut stream) => {
                stream.write_all(payload).await?;
                AsyncWriteExt::shutdown(&mut stream).await?;
                tracing::info!(attempt, marker = label, "emitted boot marker");
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

/// `mount(2)` with explicit flags, returning the raw error — including
/// `EBUSY`. Callers that mount idempotent pseudo-filesystems want
/// [`raw_mount`]'s EBUSY tolerance instead.
fn mount_syscall(
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `mount(2)` with explicit flags. `EBUSY` (already mounted) is treated as
/// success — right for the idempotent pseudo-fs mounts on the boot path,
/// wrong for the data volume (see [`mount_state_volume`]).
fn raw_mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> std::io::Result<()> {
    match mount_syscall(source, target, fstype, flags) {
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => Ok(()),
        other => other,
    }
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
    // The upstream rootfs is mounted read-only, but `/tmp` must be writable: the
    // remote-cache staging (`tempfile`, default `/tmp`) and much else assume it.
    // Without this a session build fails with EROFS fetching its packages.
    raw_mount("tmpfs", &format!("{NEWROOT}/tmp"), "tmpfs", 0)?;
    // devpts for PTYs. The session shell's server-side `Pty::open` does
    // `posix_openpt` (opens /dev/ptmx) then opens the matching /dev/pts/N slave.
    // The devtmpfs /dev/ptmx and a plain devpts mount can resolve to DIFFERENT
    // devpts instances, so the master and slave never connect and the pty errors
    // immediately (EIO) — bash then exits at once. This is the minvmd-only break
    // (native DM2 works because the host sets devpts up). Mount devpts with an
    // accessible ptmx and repoint /dev/ptmx at it so both ends share one
    // instance. Best-effort — a pty failure must not turn boot into READY-only.
    let _ = std::fs::create_dir_all(format!("{NEWROOT}/dev/pts"));
    let pts_target = CString::new(format!("{NEWROOT}/dev/pts")).expect("no NUL in /dev/pts path");
    // SAFETY: mount(2) with valid C strings; `data` carries devpts options and
    // is read for the duration of the call.
    let rc = unsafe {
        libc::mount(
            c"devpts".as_ptr(),
            pts_target.as_ptr(),
            c"devpts".as_ptr(),
            0,
            c"ptmxmode=0666".as_ptr().cast(),
        )
    };
    if rc != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "mounting devpts; interactive PTY sessions may fail");
    } else {
        // Repoint /dev/ptmx (a devtmpfs node) at this instance's ptmx so
        // `posix_openpt` and `/dev/pts/N` land in the same devpts instance.
        let ptmx = format!("{NEWROOT}/dev/ptmx");
        let _ = std::fs::remove_file(&ptmx);
        if let Err(e) = std::os::unix::fs::symlink("pts/ptmx", &ptmx) {
            tracing::warn!(error = %e, "linking /dev/ptmx -> pts/ptmx; interactive PTY sessions may fail");
        }
    }

    // Transition into the new root the `switch_root(8)` way — mount-move it over
    // `/` then `chroot(".")` — rather than a bare `chroot(NEWROOT)`.
    //
    // A bare chroot leaves pid-1's root directory pointing at `/newroot` while
    // the mount-namespace root stays the initramfs. The kernel then refuses
    // `unshare(CLONE_NEWUSER)` with EPERM for any process in such a "chroot
    // environment" (user_namespaces(7): the caller's root must match the mount
    // namespace root). Every sandbox build does exactly that unshare via
    // hakoniwa, so it died with code 125 ("Operation not permitted") in-guest
    // while working natively (DM2 minimald is not chrooted). `pivot_root(2)`
    // can't be used here because the source root is the initramfs rootfs, which
    // the kernel forbids moving; `MS_MOVE` of the new root onto `/` is the
    // canonical initramfs hand-off and makes the new root the namespace root, so
    // the chroot below no longer constitutes a "chroot environment".
    std::env::set_current_dir(NEWROOT)?;
    let c_newroot = CString::new(NEWROOT).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in newroot path")
    })?;
    let c_slash = c"/";
    // SAFETY: `mount(2)` MS_MOVE with valid C strings for source/target, no
    // fs-type or data; relocates the `/newroot` mount onto `/`.
    if unsafe {
        libc::mount(
            c_newroot.as_ptr(),
            c_slash.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `chroot(2)` onto ".", the just-moved new root (now mounted at `/`).
    if unsafe { libc::chroot(c".".as_ptr()) } != 0 {
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

/// ext4 superblock magic (`0xEF53`), stored little-endian at byte offset 1080
/// (superblock starts at 1024; `s_magic` is at offset 56 within it).
const EXT4_MAGIC_OFFSET: u64 = 1080;
const EXT4_MAGIC_LE: [u8; 2] = [0x53, 0xEF];

/// Whether `device` already carries an ext4 filesystem, probed by reading the
/// superblock magic. This is the idempotency gate for [`mount_state_volume`]:
/// `mkfs` runs only when the magic is absent, so a VM restart after a partial
/// format re-formats cleanly and a formatted volume is reused untouched.
fn has_ext4_superblock(device: &str) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(device)?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))?;
    let mut buf = [0u8; 2];
    match f.read_exact(&mut buf) {
        Ok(()) => Ok(buf == EXT4_MAGIC_LE),
        // A device smaller than the superblock offset cannot hold ext4.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// The device block size ext4 is formatted with (4 KiB).
const EXT4_BLOCK_BYTES: u64 = 4096;

/// Safety margin left below the device size when formatting (spec R1.5).
///
/// libkrun reserves a small trailer on the raw backing file and shaves it off
/// between boots (observed: 64 KiB), so the block device the guest sees can
/// shrink slightly after the first boot. Formatting to the *exact* device size
/// then fails on the next boot with `EXT4-fs: bad geometry: block count exceeds
/// device`. Sizing the filesystem 1 MiB below the device (16× the observed shave)
/// keeps the ext4 geometry valid across reboots; 1 MiB on a multi-GiB volume is
/// negligible.
const MKFS_MARGIN_BYTES: u64 = 1024 * 1024;

/// The size of `device` in bytes, read from `/sys/block/<name>/size` (which is
/// in 512-byte sectors).
fn device_size_bytes(device: &str) -> std::io::Result<u64> {
    let name = std::path::Path::new(device)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "device has no basename")
        })?;
    let sectors: u64 = std::fs::read_to_string(format!("/sys/block/{name}/size"))?
        .trim()
        .parse()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad block size: {e}"),
            )
        })?;
    Ok(sectors * 512)
}

/// Smallest device we will format. Below this, the usable size after
/// [`MKFS_MARGIN_BYTES`] leaves too little for a journalled ext4 (and a device
/// ≤ the margin yields a zero block count), so `run_mkfs_ext4` rejects it rather
/// than handing `mkfs.ext4` a nonsensical size. The real data volume is
/// GiB-scale, so this only guards a misconfigured `MINVMD_VOLUME_BYTES` or a
/// malformed device.
const MKFS_MIN_DEVICE_BYTES: u64 = 16 * 1024 * 1024;

/// Format `device` as ext4 via `mkfs.ext4 -F` (non-interactive). Resolves from
/// `PATH` (`/usr/sbin`, set post-chroot in [`enter_rootfs`]); requires
/// `e2fsprogs` in the rootfs closure (spec R1.7).
///
/// ext4's defaults are a decade of hard-won tuning and are left alone, including
/// the inode ratio: mke2fs already defaults to a ~65536 bytes/inode ratio at
/// these volume sizes (measured — identical inode count with or without an
/// explicit `-i`), so no `-i` override is passed. Two non-default choices remain:
///
/// 1. **Eager inode + journal init** (`-E lazy_itable_init=0,lazy_journal_init=0`):
///    zero the inode table + journal *now*, at mkfs, rather than in the
///    background `ext4lazyinit` kernel thread after mount, so no background init
///    competes with the guest bringing up its vsock bridge + SSH server on 2
///    vCPUs. It's cheap because the volume is sparse — the zero-writes land in
///    unallocated holes, so the init is ~instant regardless of size (measured
///    sub-ms at 32–256 GiB). It runs once — first boot only; later boots detect
///    the superblock and skip mkfs.
///
/// 2. **Survive libkrun's backing-file trailer shave** across reboots: pass an
///    explicit block count sized [`MKFS_MARGIN_BYTES`] below the device (found via
///    a 3-boot persistence test — without the margin the volume fails to re-mount
///    on the next boot). The count is in block-size units, so `-b`
///    [`EXT4_BLOCK_BYTES`] pins that unit to keep the arithmetic exact.
fn run_mkfs_ext4(device: &str) -> std::io::Result<()> {
    let device_bytes = device_size_bytes(device)?;
    if device_bytes < MKFS_MIN_DEVICE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "data volume {device} is too small to format: {device_bytes} bytes \
                 (minimum {MKFS_MIN_DEVICE_BYTES})"
            ),
        ));
    }
    let fs_blocks = device_bytes.saturating_sub(MKFS_MARGIN_BYTES) / EXT4_BLOCK_BYTES;
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .args(["-b", &EXT4_BLOCK_BYTES.to_string()])
        .args(["-E", "lazy_itable_init=0,lazy_journal_init=0"])
        .arg(device)
        .arg(fs_blocks.to_string())
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "mkfs.ext4 -F {device} ({fs_blocks} blocks) failed: {status}"
        )));
    }
    Ok(())
}

/// Mountpoint of the per-VM writable data volume inside the guest (spec R1.5).
/// The state and cache dirs relocate here once [`mount_state_volume`] succeeds.
pub const STATE_VOLUME_MOUNTPOINT: &str = "/var/lib/minimal";

/// Repair `device` with `e2fsck -p` (preen: fix what is safe without asking).
/// Exit codes 0–2 mean no errors / errors corrected; ≥ 4 means uncorrected
/// problems remain, which is an error here.
fn run_e2fsck(device: &str) -> std::io::Result<()> {
    let status = std::process::Command::new("e2fsck")
        .arg("-p")
        .arg(device)
        .status()?;
    match status.code() {
        Some(code) if code < 4 => Ok(()),
        _ => Err(std::io::Error::other(format!(
            "e2fsck -p {device} left uncorrected errors: {status}"
        ))),
    }
}

/// Mount the per-VM writable data volume (spec R1.5, fail-closed per R2.4/R2.5).
///
/// Runs **after** [`enter_rootfs`] has chrooted into the rootfs, so `mkfs.ext4`
/// resolves against the rootfs userland (the initramfs has no e2fsprogs) and the
/// mount joins the live root mount namespace. Formats `device` on first boot
/// (superblock-gated, idempotent) and mounts it read-write at `mountpoint` with
/// `MS_NOATIME`.
///
/// Any failure — including an absent `device`, since minvmd attaches the volume
/// on every boot (R1.4) — is an error; the caller emits `MOUNT_FAILED` instead
/// of READY (R2.5). When a formatted volume fails to mount, one `e2fsck -p`
/// repair + mount retry is attempted before failing closed; the volume is never
/// reformatted once a superblock exists.
pub fn mount_state_volume(device: &str, mountpoint: &str) -> std::io::Result<()> {
    // Every error here becomes the MOUNT_FAILED reason shown to the user on
    // the host, so each failing operation names itself — a bare
    // "Read-only file system (os error 30)" would send them to fsck a
    // healthy image when the real fault is e.g. a pre-R1.7 rootfs.
    let with_context =
        |op: String| move |e: std::io::Error| std::io::Error::new(e.kind(), format!("{op}: {e}"));
    // The data volume mount uses the strict `mount_syscall`, not the
    // EBUSY-tolerant `raw_mount`: an EBUSY here is a real failure (the device
    // is held elsewhere), and reporting it as success would relocate state
    // onto an unmounted read-only mountpoint.
    let mount = || {
        mount_syscall(device, mountpoint, "ext4", libc::MS_NOATIME)
            .map_err(with_context(format!("mounting {device} at {mountpoint}")))
    };

    // `try_exists` distinguishes "absent" from a stat error (Err) so the failure
    // reason carried in the MOUNT_FAILED beacon names the right cause.
    if !std::path::Path::new(device)
        .try_exists()
        .map_err(with_context(format!("probing device {device}")))?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("data volume device {device} is not attached"),
        ));
    }
    // Ensure the mountpoint exists before formatting: it must be present on the
    // read-only rootfs (spec R1.7), so on a rootfs that predates R1.7 this fails
    // with EROFS — better to surface that here than after a needless mkfs.
    std::fs::create_dir_all(mountpoint).map_err(with_context(format!(
        "creating mountpoint {mountpoint} (rootfs predating R1.7?)"
    )))?;
    if has_ext4_superblock(device)
        .map_err(with_context(format!("probing ext4 superblock on {device}")))?
    {
        // Existing filesystem: the ext4 journal replays any unclean-shutdown
        // state on mount. On failure, repair once and retry; then fail closed
        // rather than reformatting user data away.
        if let Err(e) = mount() {
            tracing::warn!(device, error = %e, "mounting data volume failed; attempting e2fsck -p repair");
            run_e2fsck(device)?;
            mount()?;
        }
    } else {
        tracing::info!(device, "no ext4 superblock; formatting data volume");
        run_mkfs_ext4(device)?;
        mount()?;
    }
    tracing::info!(device, mountpoint, "mounted writable state volume");
    Ok(())
}

/// Quiesce the state volume before VMM teardown (spec R2.1): `syncfs(2)` the
/// mount to flush all pending writes and the ext4 journal to the block device,
/// then best-effort lazy-detach the mount so a clean stop leaves the journal
/// closed. A syncfs error propagates; an unmount failure is logged and
/// swallowed — the data is already synced, so the worst case is a journal
/// replay on the next boot.
pub fn quiesce_state_volume(mountpoint: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let dir = std::fs::File::open(mountpoint)?;
    // SAFETY: `syncfs(2)` on a valid open fd; blocks until all dirty pages and
    // journal entries of the containing filesystem reach the block device.
    if unsafe { libc::syncfs(dir.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    drop(dir);

    let c_mountpoint = CString::new(mountpoint)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in mountpoint"))?;
    // Try a plain unmount first: a full unmount closes the ext4 journal and
    // marks the superblock clean. It fails EBUSY while anything holds an fd
    // under the mount (e.g. the gvproxy switch socket in the state dir), so
    // fall back to remounting read-only — ext4 marks recovery complete on
    // the ro transition (clearing `INCOMPAT_RECOVER`) despite read-open fds
    // and bound sockets. A *write*-open fd (e.g. a session-spawned process
    // that outlived the drain, reparented to pid-1) defeats the remount too;
    // then only the lazy detach runs and the journal stays dirty — logged
    // with the holders below, bounded by the replay backstop. Every failure
    // arm is logged and swallowed: the data is already synced, so the worst
    // case is a journal replay on the next boot.
    //
    // SAFETY: `umount2(2)`/`mount(2)` with valid, call-lifetime C strings;
    // MS_REMOUNT|MS_RDONLY takes no source/fstype/data; MNT_DETACH is lazy
    // (succeeds with busy fds; the fs finishes when they drop).
    if unsafe { libc::umount2(c_mountpoint.as_ptr(), 0) } == 0 {
        tracing::info!(mountpoint, "state volume quiesced and unmounted");
        return Ok(());
    }
    let remount_ro = unsafe {
        libc::mount(
            std::ptr::null(),
            c_mountpoint.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOATIME,
            std::ptr::null(),
        )
    };
    if remount_ro != 0 {
        tracing::warn!(
            mountpoint,
            error = %std::io::Error::last_os_error(),
            holders = %fd_holders_under(mountpoint),
            "remounting state volume read-only (best-effort; already synced)"
        );
    }
    if unsafe { libc::umount2(c_mountpoint.as_ptr(), libc::MNT_DETACH) } != 0 {
        tracing::warn!(
            mountpoint,
            error = %std::io::Error::last_os_error(),
            "detaching state volume (best-effort; already synced)"
        );
    } else {
        tracing::info!(
            mountpoint,
            remounted_ro = remount_ro == 0,
            "state volume quiesced and lazily detached"
        );
    }
    Ok(())
}

/// Take the microVM down, by resetting it. Does not return on success: the
/// guest resets, and libkrun's VMM exits with it. On failure it returns the
/// `reboot(2)` error.
///
/// ONLY call this as the microVM's pid-1 (guard with [`is_minimal_microvm`]):
/// on an ordinary host it reboots the machine.
///
/// This is how the guest ends. As pid-1 minimald has nothing to return to:
/// letting `main` exit kills init, which panics the kernel ("Attempted to kill
/// init!") — and with no `panic=` on the cmdline the kernel then spins in the
/// panic handler forever. The VMM stays alive on a dead guest, the host keeps
/// reporting the VM as `Running`, and every later CLI command blocks on a
/// bridge socket nothing is behind (#730). Taking the VM down instead lets the
/// supervisor reap the VMM child and mark it `Stopped`, so the next command
/// boots a fresh one.
///
/// Reset (`RB_AUTOBOOT`), not power-off: a guest-initiated reset is what makes
/// a firecracker-family VMM exit, and it is the only mechanism that works on
/// both arches. `RB_POWER_OFF` needs a `pm_power_off` handler, which the x86_64
/// guest kernel does not have — there the kernel logs "Power off not available:
/// System halted instead" and halts the vCPU with the VMM still alive, which is
/// #730 all over again. (aarch64 does have one, via PSCI `SYSTEM_OFF`, which is
/// what hid the gap until CI's x86_64 KVM lane.) Reset reaches
/// `KVM_EXIT_SHUTDOWN` on both: PSCI `SYSTEM_RESET` on aarch64, i8042 reset /
/// triple fault on x86_64. libkrun exits on it rather than restarting the
/// guest, so this ends the VM despite the name.
///
/// `sync(2)` first: `reboot(2)` does not flush filesystems, and this also runs
/// on the paths that never reached the shutdown quiesce (a failed
/// `Server::run`).
pub fn shut_down_vm() -> std::io::Error {
    // SAFETY: neither call takes pointers. `reboot(2)` needs CAP_SYS_BOOT,
    // which the microVM's pid-1 has, and does not return on success; on failure
    // it returns -1 with errno set, which the caller surfaces.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    std::io::Error::last_os_error()
}

/// Reset the boot-ephemeral `providers/` directory under the (now persistent)
/// state dir, returning the number of entries removed (R3.2).
///
/// Provider registrations — per-instance host keys, known_hosts, socket
/// paths — are ephemeral per boot; before the persistent volume they died
/// with the tmpfs. `sessions/` and `cache/` are the durable state and are
/// untouchable by construction here: only entries *inside* `providers/` are
/// removed, never a glob over the state root. A missing `providers/` is not
/// an error (first boot).
pub fn reset_providers_dir(state_dir: &std::path::Path) -> std::io::Result<usize> {
    let providers = state_dir.join("providers");
    let entries = match std::fs::read_dir(&providers) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        removed += 1;
    }
    tracing::info!(
        dir = %providers.display(),
        removed,
        "reset boot-ephemeral directory"
    );
    Ok(removed)
}

/// Enumerate open fds (and cwds) under `mountpoint` across all processes, for
/// the EBUSY diagnostics in [`quiesce_state_volume`] — an unmountable volume
/// is invisible without knowing who holds it. Best-effort `/proc` scan.
fn fd_holders_under(mountpoint: &str) -> String {
    let prefix = format!("{mountpoint}/");
    let mut holders = Vec::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return "<no /proc>".to_string();
    };
    for proc_entry in procs.flatten() {
        let Some(pid) = proc_entry
            .file_name()
            .to_str()
            .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
            .map(str::to_string)
        else {
            continue;
        };
        let base = proc_entry.path();
        if let Ok(cwd) = std::fs::read_link(base.join("cwd"))
            && (cwd.starts_with(mountpoint) || cwd.to_string_lossy().starts_with(&prefix))
        {
            holders.push(format!("pid {pid} cwd {}", cwd.display()));
        }
        let Ok(fds) = std::fs::read_dir(base.join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if t.starts_with(&prefix) || t == mountpoint {
                    holders.push(format!("pid {pid} fd {t}"));
                }
            }
        }
    }
    if holders.is_empty() {
        "<none found>".to_string()
    } else {
        holders.join(", ")
    }
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

/// Brings up egress for the guest **root** netns (where `minimald` itself runs)
/// by attaching a primary `eth0` tap to the host gvproxy over the vsock shuttle.
///
/// This is the daemon-side mirror of the per-PTask switch attachment: the same
/// host gvproxy, the same `krun_add_vsock_port2(.., listen=false)` shuttle port,
/// but the tap lives in the root namespace (no netns move) so `minimald` gets a
/// default route + DNS and can reach the network — e.g. to clone the upstream
/// `pkgs` repo when scaffolding a session's `minimal.toml`.
///
/// Returns the live [`SwitchRelay`]; the caller MUST keep it alive for as long
/// as egress is needed (dropping it tears the relay down). Best-effort: if the
/// host gvproxy is not up (the shuttle connect fails) this returns an error and
/// the caller continues without egress.
pub async fn bring_up_root_egress() -> std::io::Result<crate::net::switch::SwitchRelay> {
    use crate::net::{DEFAULT_SUBNET, VSOCK_GVPROXY_SHUTTLE_PORT, VSOCK_HOST_CID, switch};
    use std::net::Ipv4Addr;

    const TAP: &str = "eth0";
    let ip = DEFAULT_SUBNET.daemon_ip();
    let gateway = DEFAULT_SUBNET.gateway();
    let cidr = format!("{ip}/{}", DEFAULT_SUBNET.prefix());

    // Open the tap in the current (root) netns; the OwnedFd keeps it alive.
    let tap_fd = switch::open_tap(TAP).map_err(|e| {
        std::io::Error::new(e.kind(), format!("open_tap({TAP}) [/dev/net/tun]: {e}"))
    })?;

    // Configure the interface directly via ioctls — the generic guest rootfs
    // ships no `ip`/iproute2 binary, so shelling out is not an option.
    configure_interface_v4(TAP, ip, DEFAULT_SUBNET.prefix(), Some(gateway))?;
    // Bring loopback up too (no address/route needed).
    configure_interface_v4("lo", Ipv4Addr::LOCALHOST, 8, None)?;

    // Point the resolver at the switch's DNS server (gvproxy, at the gateway).
    // The rootfs is mounted read-only, so write to the writable /run tmpfs and
    // bind-mount it over /etc/resolv.conf (a bind only changes the mount tree, so
    // it works over a read-only fs as long as the target path exists).
    if let Err(e) = install_resolv_conf(DEFAULT_SUBNET.dns_server()) {
        tracing::warn!(error = %e, "installing /etc/resolv.conf for guest egress (DNS may fail)");
    }

    // Relay the tap to the host gvproxy over the vsock shuttle (CID 2).
    let relay =
        switch::attach_to_switch_vsock(tap_fd, VSOCK_HOST_CID, VSOCK_GVPROXY_SHUTTLE_PORT, None)
            .await?;
    tracing::info!(%cidr, %gateway, "guest root egress up via host gvproxy shuttle");
    Ok(relay)
}

/// Installs `/etc/resolv.conf` pointing at `nameserver` on a read-only rootfs by
/// writing the file to the `/run` tmpfs and bind-mounting it over the target.
fn install_resolv_conf(nameserver: std::net::Ipv4Addr) -> std::io::Result<()> {
    std::fs::write("/run/resolv.conf", format!("nameserver {nameserver}\n"))?;
    let src = c"/run/resolv.conf";
    let dst = c"/etc/resolv.conf";
    // SAFETY: bind-mount with valid C paths, MS_BIND, and no fs-type/data.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Assigns `ip`/`prefix` to `ifname`, brings it up, and (when `gateway` is set)
/// installs a default route via it — all through `AF_INET` ioctls, so it works
/// in the generic guest rootfs which carries no `ip`/iproute2 binary.
fn configure_interface_v4(
    ifname: &str,
    ip: std::net::Ipv4Addr,
    prefix: u8,
    gateway: Option<std::net::Ipv4Addr>,
) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // A `struct ifreq` carrying a `sockaddr_in` in the union, padded to the full
    // 40-byte `ifreq` size the kernel expects.
    #[repr(C)]
    struct IfReqAddr {
        name: [libc::c_char; libc::IFNAMSIZ],
        addr: libc::sockaddr_in,
        _pad: [u8; 8],
    }
    // The flags variant of `ifreq`.
    #[repr(C)]
    struct IfReqFlags {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    let name_buf = |name: &str| -> [libc::c_char; libc::IFNAMSIZ] {
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        for (dst, b) in buf.iter_mut().zip(name.bytes()) {
            *dst = b as libc::c_char;
        }
        buf
    };
    let sockaddr_in = |addr: std::net::Ipv4Addr| -> libc::sockaddr_in {
        // SAFETY: sockaddr_in is plain old data; zeroing then filling is valid.
        let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        s.sin_family = libc::AF_INET as libc::sa_family_t;
        s.sin_addr = libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        };
        s
    };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid, owned socket fd.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = sock.as_raw_fd();

    let ioctl_addr = |req: libc::c_ulong, addr: libc::sockaddr_in| -> std::io::Result<()> {
        let mut ifr = IfReqAddr {
            name: name_buf(ifname),
            addr,
            _pad: [0; 8],
        };
        // SAFETY: fd is open; &mut ifr is a correctly-sized ifreq for an
        // address-setting ioctl.
        let rc = unsafe {
            libc::ioctl(
                fd,
                req as _,
                std::ptr::from_mut(&mut ifr).cast::<libc::c_void>(),
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };

    // Address (skip for the all-loopback case where we only flip flags up; lo
    // already carries 127.0.0.1, and re-setting it is harmless but we keep it
    // for the eth0 path which always needs it).
    if ifname != "lo" {
        ioctl_addr(libc::SIOCSIFADDR, sockaddr_in(ip))?;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        ioctl_addr(
            libc::SIOCSIFNETMASK,
            sockaddr_in(std::net::Ipv4Addr::from(mask)),
        )?;
    }

    // Bring the interface up: read flags, OR in IFF_UP|IFF_RUNNING, write back.
    let mut flags = IfReqFlags {
        name: name_buf(ifname),
        flags: 0,
        _pad: [0; 22],
    };
    // SAFETY: fd open; ifreq sized for the flags ioctls.
    if unsafe {
        libc::ioctl(
            fd,
            libc::SIOCGIFFLAGS as _,
            std::ptr::from_mut(&mut flags).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    flags.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    if unsafe {
        libc::ioctl(
            fd,
            libc::SIOCSIFFLAGS as _,
            std::ptr::from_mut(&mut flags).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    // Default route via the gateway (0.0.0.0/0 -> gw), if requested.
    if let Some(gw) = gateway {
        let as_sockaddr = |a: std::net::Ipv4Addr| -> libc::sockaddr {
            // SAFETY: sockaddr and sockaddr_in share the leading family field;
            // rtentry's route addresses are read as sockaddr but populated from
            // sockaddr_in, the standard SIOCADDRT idiom.
            unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sockaddr_in(a)) }
        };
        // SAFETY: rtentry is POD; zero then fill the fields SIOCADDRT reads.
        let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
        rt.rt_dst = as_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
        rt.rt_genmask = as_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
        rt.rt_gateway = as_sockaddr(gw);
        rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
        // SAFETY: fd open; &mut rt is a valid rtentry for SIOCADDRT.
        if unsafe {
            libc::ioctl(
                fd,
                libc::SIOCADDRT as _,
                std::ptr::from_mut(&mut rt).cast::<libc::c_void>(),
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext4_superblock_probe_detects_magic() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("guest-sb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // A file with the ext4 magic at offset 1080 probes positive.
        let ext4 = dir.join("ext4.img");
        {
            let mut f = std::fs::File::create(&ext4).unwrap();
            f.set_len(2048).unwrap();
            f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET)).unwrap();
            f.write_all(&EXT4_MAGIC_LE).unwrap();
        }
        assert!(has_ext4_superblock(ext4.to_str().unwrap()).unwrap());

        // A zeroed image (freshly provisioned, unformatted) probes negative.
        let blank = dir.join("blank.img");
        std::fs::File::create(&blank)
            .unwrap()
            .set_len(2048)
            .unwrap();
        assert!(!has_ext4_superblock(blank.to_str().unwrap()).unwrap());

        // A device too small to hold a superblock probes negative, not error.
        let tiny = dir.join("tiny.img");
        std::fs::File::create(&tiny).unwrap().set_len(64).unwrap();
        assert!(!has_ext4_superblock(tiny.to_str().unwrap()).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_ready_beacon_formats_two_lines() {
        use russh::keys::{Algorithm, PrivateKey, key::safe_rng};

        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let pubkey = key.public_key();
        let expected_openssh = pubkey.to_openssh().unwrap();

        let (mut writer, mut reader) = tokio::io::duplex(4096);
        write_ready_beacon(&mut writer, pubkey).await.unwrap();
        drop(writer);

        let mut output = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut output)
            .await
            .unwrap();
        let output_str = String::from_utf8(output).unwrap();

        assert_eq!(
            output_str,
            format!("READY\n{expected_openssh}\n"),
            "beacon must be READY\\n<openssh-pubkey>\\n"
        );
    }

    #[test]
    fn reset_providers_dir_clears_providers_only() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        std::fs::create_dir_all(state.join("providers/local-0")).unwrap();
        std::fs::write(state.join("providers/local-0/key"), b"k").unwrap();
        std::fs::write(state.join("providers/stray-file"), b"s").unwrap();
        std::fs::create_dir_all(state.join("sessions/abcde")).unwrap();
        std::fs::write(state.join("sessions/abcde/record.json"), b"{}").unwrap();
        std::fs::create_dir_all(state.join("cache")).unwrap();
        std::fs::write(state.join("cache/x"), b"x").unwrap();

        let removed = reset_providers_dir(state).unwrap();

        assert_eq!(removed, 2, "one dir + one stray file");
        assert!(
            std::fs::read_dir(state.join("providers")).unwrap().count() == 0,
            "providers/ must be emptied"
        );
        assert!(
            state.join("sessions/abcde/record.json").exists(),
            "sessions/ must be preserved"
        );
        assert!(state.join("cache/x").exists(), "cache/ must be preserved");

        // Missing providers/ (first boot) is not an error.
        let fresh = tempfile::tempdir().unwrap();
        assert_eq!(reset_providers_dir(fresh.path()).unwrap(), 0);
    }

    #[test]
    fn mount_failed_beacon_is_two_lines_flattened_and_capped() {
        // Multi-line reasons are flattened to one line.
        let payload = mount_failed_beacon("mount failed:\r\nEIO on /dev/vdb");
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            "MOUNT_FAILED\nmount failed:  EIO on /dev/vdb\n"
        );

        // Oversized reasons are capped on a char boundary; the payload stays
        // two-line and well-formed.
        let long = "é".repeat(MOUNT_FAILED_REASON_MAX_BYTES); // 2 bytes per char
        let payload = String::from_utf8(mount_failed_beacon(&long)).unwrap();
        let reason = payload
            .strip_prefix("MOUNT_FAILED\n")
            .unwrap()
            .strip_suffix('\n')
            .unwrap();
        assert!(reason.len() <= MOUNT_FAILED_REASON_MAX_BYTES);
        assert!(reason.chars().all(|c| c == 'é'));
    }
}
