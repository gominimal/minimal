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
    let tap_fd = switch::open_tap(TAP)
        .map_err(|e| std::io::Error::new(e.kind(), format!("open_tap({TAP}) [/dev/net/tun]: {e}")))?;

    // Configure the interface directly via ioctls — the generic guest rootfs
    // ships no `ip`/iproute2 binary, so shelling out is not an option.
    configure_interface_v4(TAP, ip, DEFAULT_SUBNET.prefix(), Some(gateway))?;
    // Bring loopback up too (no address/route needed).
    configure_interface_v4("lo", Ipv4Addr::LOCALHOST, 8, None)?;

    // Point the resolver at gvproxy's gateway, which serves DNS for the switch.
    // The rootfs is mounted read-only, so write to the writable /run tmpfs and
    // bind-mount it over /etc/resolv.conf (a bind only changes the mount tree, so
    // it works over a read-only fs as long as the target path exists).
    if let Err(e) = install_resolv_conf(gateway) {
        tracing::warn!(error = %e, "installing /etc/resolv.conf for guest egress (DNS may fail)");
    }

    // Relay the tap to the host gvproxy over the vsock shuttle (CID 2).
    let relay = switch::attach_to_switch_vsock(tap_fd, VSOCK_HOST_CID, VSOCK_GVPROXY_SHUTTLE_PORT)
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
        let rc =
            unsafe { libc::ioctl(fd, req as _, std::ptr::from_mut(&mut ifr).cast::<libc::c_void>()) };
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
