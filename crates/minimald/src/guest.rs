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
    emit_marker(Some(pubkey)).await
}

/// Emits the one-shot boot marker to the host (simple form: no host key).
///
/// Used in the degraded fallback path where the rootfs could not be mounted
/// and no SSH server is running. The host-side beacon reader handles a missing
/// second line gracefully (R2.3).
pub async fn emit_simple_ready_marker() -> std::io::Result<()> {
    emit_marker(None).await
}

async fn emit_marker(pubkey: Option<&PublicKey>) -> std::io::Result<()> {
    const MAX_ATTEMPTS: u32 = 50;
    const BACKOFF: Duration = Duration::from_millis(100);

    let addr = VsockAddr::new(VMADDR_CID_HOST, BOOT_MARKER_PORT);
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match VsockStream::connect(addr).await {
            Ok(mut stream) => {
                match pubkey {
                    Some(pk) => write_ready_beacon(&mut stream, pk).await?,
                    None => stream.write_all(b"READY\n").await?,
                }
                AsyncWriteExt::shutdown(&mut stream).await?;
                tracing::info!(
                    attempt,
                    simple = pubkey.is_none(),
                    "emitted boot READY marker"
                );
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

/// Format `device` as ext4 via `mkfs.ext4 -F` (non-interactive). Resolves from
/// `PATH` (`/usr/sbin`, set post-chroot in [`enter_rootfs`]); requires
/// `e2fsprogs` in the rootfs closure (spec R1.7).
///
/// The filesystem is sized [`MKFS_MARGIN_BYTES`] below the device so it survives
/// libkrun's backing-file trailer shave across reboots.
fn run_mkfs_ext4(device: &str) -> std::io::Result<()> {
    let fs_blocks = device_size_bytes(device)?.saturating_sub(MKFS_MARGIN_BYTES) / EXT4_BLOCK_BYTES;
    let status = std::process::Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .args(["-b", &EXT4_BLOCK_BYTES.to_string()])
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

/// Mount the per-VM writable data volume (spec R1.5).
///
/// Runs **after** [`enter_rootfs`] has chrooted into the rootfs, so `mkfs.ext4`
/// resolves against the rootfs userland (the initramfs has no e2fsprogs) and the
/// mount joins the live root mount namespace. Formats `device` on first boot
/// (superblock-gated, idempotent) and mounts it read-write at `mountpoint` with
/// `MS_NOATIME`.
///
/// Returns `Ok(true)` when the volume was mounted, `Ok(false)` when `device` is
/// absent — the transitional legacy case where no data volume is attached and
/// the caller keeps the tmpfs state dir. Unit 2 (R2.4/R2.5) makes an *attached*
/// volume that fails to mount fatal; this Unit-1 form only reports the outcome.
pub fn mount_state_volume(device: &str, mountpoint: &str) -> std::io::Result<bool> {
    if !std::path::Path::new(device).exists() {
        tracing::info!(device, "no data volume attached; keeping tmpfs state dir");
        return Ok(false);
    }
    if !has_ext4_superblock(device)? {
        tracing::info!(device, "no ext4 superblock; formatting data volume");
        run_mkfs_ext4(device)?;
    }
    // The mountpoint must exist on the read-only rootfs (spec R1.7); on a rootfs
    // that predates R1.7 this create fails with EROFS, surfacing the missing
    // mountpoint rather than mounting somewhere unexpected.
    std::fs::create_dir_all(mountpoint)?;
    raw_mount(device, mountpoint, "ext4", libc::MS_NOATIME)?;
    tracing::info!(device, mountpoint, "mounted writable state volume");
    Ok(true)
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

    let _ = &cidr; // (kept for log context below)

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
        switch::attach_to_switch_vsock(tap_fd, VSOCK_HOST_CID, VSOCK_GVPROXY_SHUTTLE_PORT).await?;
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
}
