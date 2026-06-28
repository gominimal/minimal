//! Bridging an `OwnIp` PTask's tap device onto the gvproxy switch.
//!
//! The gvproxy v0.8.9 spike (`docs/spikes/2026-06-21-gvproxy-attachment.md`)
//! established that the switch attachment is **not** an SCM_RIGHTS fd-pass — the
//! task title's "SCM_RIGHTS" wording predates that finding. Instead minimald:
//!
//! 1. opens a tap device in the host namespace ([`open_tap`]),
//! 2. moves the tap interface into the PTask's network namespace and configures
//!    its MAC/IP/route there (done by the caller via `ip`, per the spike's
//!    static-lease recipe), and
//! 3. runs an async relay ([`attach_to_switch`]) that bridges the host-side tap
//!    fd to gvproxy's control socket: a bare `POST /connect` HTTP upgrade,
//!    after which raw Ethernet frames flow in both directions framed with a
//!    2-byte little-endian length prefix (the HyperKit protocol).
//!
//! Implements R1.5 (per-PTask switch attachment) and R1.7 (the DM2 native-Linux
//! attachment path).

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

use super::{DEFAULT_MTU, PtaskLease, SwitchSubnet};

/// `ioctl` request number for `TUNSETIFF` (set the tap/tun interface a fd backs).
///
/// Typed as [`libc::Ioctl`], the per-target alias for `ioctl`'s request
/// argument — `c_ulong` on glibc, `c_int` on musl — so the constant resolves
/// to the width `libc::ioctl` expects on each target. The value `0x4004_54ca`
/// fits in an `i32`, so the musl narrowing is lossless.
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
/// `IFF_TAP`: the device is an Ethernet (layer-2) tap, not a layer-3 tun.
const IFF_TAP: libc::c_short = 0x0002;
/// `IFF_NO_PI`: do not prepend the 4-byte packet-info header to frames.
const IFF_NO_PI: libc::c_short = 0x1000;
/// `IFNAMSIZ`: kernel interface-name buffer length.
const IFNAMSIZ: usize = 16;

/// The HTTP request that upgrades a control-socket connection into a raw frame
/// stream. gvproxy hijacks the connection and writes no response.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// Bound the host-shuttle vsock connect + `/connect` upgrade so an unresponsive
/// or absent host gvproxy fails the `OwnIp` attach fast instead of stalling
/// guest-egress / session bring-up indefinitely.
const VSOCK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// `struct ifreq` reduced to the two fields `TUNSETIFF` reads, padded to the
/// kernel's `sizeof(struct ifreq)` (40 bytes on every LP64 Linux target) so the
/// kernel's `copy_from_user` never reads past the allocation.
#[repr(C)]
struct TunSetIfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Largest Ethernet frame the relay must buffer: MTU + 14-byte header + 4-byte
/// 802.1Q VLAN tag.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + 14 + 4
}

/// Opens a tap device named `name` in the calling process's network namespace.
///
/// The returned fd owns the tap: the interface exists as long as the fd is
/// open. The caller is expected to move the interface into the PTask's netns
/// (`ip link set <name> netns <pid>`) and configure its MAC/IP/route there
/// before relaying, while keeping this fd on the host side for the relay.
///
/// # Errors
///
/// Returns the underlying I/O error if `/dev/net/tun` cannot be opened or the
/// `TUNSETIFF` ioctl fails (commonly `EPERM` without `CAP_NET_ADMIN`).
pub fn open_tap(name: &str) -> io::Result<OwnedFd> {
    if name.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tap name {name:?} is too long (max {} chars)", IFNAMSIZ - 1),
        ));
    }

    // SAFETY: open() with a valid NUL-terminated path and flags returns a new
    // fd or -1; we check for -1 below and take ownership of the fd otherwise.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // From here, `tap` owns the fd and closes it on drop / early return.
    // SAFETY: `fd` is a fresh, valid, owned fd just returned by open().
    let tap = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut req = TunSetIfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 22],
    };
    for (dst, src) in req.name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }

    // SAFETY: `fd` is open; `&mut req` points to a correctly-sized `ifreq`
    // (40 bytes) the kernel reads and writes for TUNSETIFF.
    let rc = unsafe {
        libc::ioctl(
            fd,
            TUNSETIFF,
            std::ptr::from_mut(&mut req).cast::<libc::c_void>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(tap)
}

/// The `ip`/`nsenter` command lines that move an opened tap into the network
/// namespace of `netns_pid` and configure it there as an `OwnIp` PTask's switch
/// interface (set the lease MAC, assign the lease address within `subnet`, bring
/// the interface and loopback up, install a default route via the switch
/// gateway).
///
/// Each command is returned as an argv vector rather than executed, so the two
/// callers can run them under the privileges they have: the daemon
/// ([`move_tap_into_netns`]) execs them directly with `CAP_NET_ADMIN`, while the
/// unprivileged `ci-netns.yml` proof wraps each in `sudo`. Single-sourcing the
/// command construction keeps the proof driving the same wiring the daemon does.
///
/// The namespace is identified by PID, addressing `/proc/<pid>/ns/net` — the
/// namespace `sandbox2` unshared for the PTask, surfaced to the launcher via the
/// `hakoniwa::Child`'s PID.
#[must_use]
pub fn tap_netns_commands(
    tap: &str,
    netns_pid: u32,
    lease: PtaskLease,
    subnet: SwitchSubnet,
) -> Vec<Vec<String>> {
    let pid = netns_pid.to_string();
    let mac = lease.mac.to_string();
    let cidr = format!("{}/{}", lease.ip, subnet.prefix());
    let gw = subnet.gateway().to_string();

    // Enter the PTask's net namespace (by PID) to run an `ip` subcommand there.
    let nsenter = |args: &[&str]| -> Vec<String> {
        ["nsenter", "-t", &pid, "-n"]
            .into_iter()
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect()
    };

    vec![
        // Move the interface into the PTask's namespace (run in the host ns).
        ["ip", "link", "set", tap, "netns", &pid]
            .into_iter()
            .map(str::to_string)
            .collect(),
        // Configure it inside that namespace, mirroring the gvproxy spike's
        // static-lease recipe.
        nsenter(&["ip", "link", "set", tap, "address", &mac]),
        nsenter(&["ip", "addr", "add", &cidr, "dev", tap]),
        nsenter(&["ip", "link", "set", tap, "up"]),
        nsenter(&["ip", "link", "set", "lo", "up"]),
        nsenter(&["ip", "route", "add", "default", "via", &gw]),
    ]
}

/// Moves the opened tap `tap` into the PTask network namespace held by
/// `netns_pid` and configures its switch address there, by execing the
/// [`tap_netns_commands`] directly. The host-side tap fd keeps working after the
/// interface moves namespaces, which is what [`attach_to_switch`] relays on.
///
/// Run on the `minimald` (daemon) side; requires `CAP_NET_ADMIN` in the host
/// namespace. `sandbox2` never calls this — it only unshares the namespace and
/// surfaces the PID (no dependency cycle).
///
/// # Errors
///
/// Returns an error if `ip`/`nsenter` cannot be spawned or any command exits
/// non-zero, naming the failing command line.
/// Trusted directories (and the `PATH` handed to the children) searched for the
/// privileged `ip`/`nsenter` binaries, ordered most- to least-specific. Using a
/// fixed list instead of the inherited `PATH` is what keeps a tampered `PATH`
/// from shadowing them when they exec with `CAP_NET_ADMIN`.
const TRUSTED_EXEC_PATH: &str = "/usr/sbin:/sbin:/usr/bin:/bin";

/// Resolves `program` to an absolute path under [`TRUSTED_EXEC_PATH`]. Falls
/// back to the bare name if it is in none of those directories (an unusual
/// layout still works, just without the hardening).
fn trusted_program(program: &str) -> String {
    for dir in TRUSTED_EXEC_PATH.split(':') {
        let candidate = std::path::Path::new(dir).join(program);
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    program.to_string()
}

pub async fn move_tap_into_netns(
    tap: &str,
    netns_pid: u32,
    lease: PtaskLease,
    subnet: SwitchSubnet,
) -> io::Result<()> {
    for (index, argv) in tap_netns_commands(tap, netns_pid, lease, subnet)
        .into_iter()
        .enumerate()
    {
        let (program, rest) = argv
            .split_first()
            .expect("tap_netns_commands never yields an empty argv");
        // These run with `CAP_NET_ADMIN` in the host namespace, so resolve the
        // binary against a fixed trusted directory list rather than an inherited
        // `PATH` (a malicious `ip`/`nsenter` shadow placed early in `PATH` would
        // otherwise execute at that capability). The pinned `PATH` covers the
        // inner `ip` that `nsenter -n` execs inside the PTask namespace, which
        // resolves against this child's environment.
        let status = tokio::process::Command::new(trusted_program(program))
            .args(rest)
            .env("PATH", TRUSTED_EXEC_PATH)
            .status()
            .await?;
        if !status.success() {
            // Command 0 moves the tap into the PTask namespace; the rest
            // configure it there, so name the phase the failing command is in.
            let phase = if index == 0 {
                "moving PTask tap into its namespace"
            } else {
                "configuring PTask tap"
            };
            return Err(io::Error::other(format!(
                "{phase} failed (`{}` exited with {status})",
                argv.join(" ")
            )));
        }
    }
    Ok(())
}

/// Opens and configures the PTask switch tap **inside** the PTask's network
/// namespace, entirely in-process — no privileged `ip`/`nsenter` child
/// processes.
///
/// [`move_tap_into_netns`] execs `ip`/`nsenter`; those children inherit the
/// daemon's *real* credentials, not a `setcap`'d effective-only capability. That
/// works when the daemon is root (a DM1/3/4 VM) but fails on an unprivileged
/// host-native DM2 daemon (the `ip` child has no `CAP_NET_ADMIN`). This path
/// instead [`setns(2)`](libc::setns)es a throwaway thread into the PTask's net
/// namespace and does the tap creation + configuration there with the same raw
/// ioctls `guest.rs` uses, so the daemon's *own* `CAP_NET_ADMIN` (tap/ioctls) and
/// `CAP_SYS_ADMIN` (`setns`) suffice — grant them on a host-native DM2 daemon via
/// `setcap cap_net_admin,cap_sys_admin+ep`; a VM daemon is already root.
///
/// The interface lives in the PTask netns; the returned fd (valid across
/// namespaces) is what the switch relay drives.
///
/// # Errors
///
/// Returns the underlying error if entering the namespace, opening/creating the
/// tap, or any configuration ioctl fails (`EPERM` without the capabilities).
pub async fn open_tap_in_netns(
    name: &str,
    ns_fd: OwnedFd,
    lease: PtaskLease,
    subnet: SwitchSubnet,
) -> io::Result<OwnedFd> {
    // `ns_fd` is a handle to the PTask net namespace, captured by the caller the
    // instant the namespace existed — an exited process's `/proc/<pid>/ns/net`
    // vanishes (the namespaces are released before reap), and the just-spawned
    // PTask can exit before the gvproxy-spawning switch attach completes, so the
    // namespace must be pinned by fd up front, not re-opened here by PID.
    let name = name.to_owned();
    // `setns` rebinds the *calling thread's* net namespace, so it must run on a
    // throwaway OS thread — never a tokio worker/blocking-pool thread, which is
    // reused for unrelated work and would silently keep the foreign netns. The
    // scoped thread does the `setns` and exits (reverting the change); the
    // `spawn_blocking` thread that hosts the scope never `setns`es, so the pool
    // stays clean. The join keeps the blocking work off the async executor.
    match tokio::task::spawn_blocking(move || -> io::Result<OwnedFd> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| open_tap_in_netns_blocking(&name, ns_fd, &lease, subnet))
                .join()
                .map_err(|_| io::Error::other("tap-setup thread panicked"))?
        })
    })
    .await
    {
        Ok(result) => result,
        Err(e) => Err(io::Error::other(format!("tap-setup task failed: {e}"))),
    }
}

/// Opens a handle to the net namespace at `/proc/<netns_pid>/ns/net`. Holding the
/// returned fd keeps the namespace alive even after its process exits, so the
/// caller should open it the instant the PTask is spawned (before any slow work)
/// to win the race against a short-lived PTask process.
pub fn open_netns_fd(netns_pid: u32) -> io::Result<OwnedFd> {
    let path = std::ffi::CString::new(format!("/proc/{netns_pid}/ns/net"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: open() with a valid NUL-terminated path returns a new fd or -1.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "opening PTask netns /proc/{netns_pid}/ns/net: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: fresh, valid, owned netns fd from open().
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Blocking body of [`open_tap_in_netns`], run on a dedicated thread that
/// `setns`'es into the PTask net namespace (via the pre-opened `ns_fd`) — every
/// operation here then happens in that namespace.
fn open_tap_in_netns_blocking(
    name: &str,
    ns_fd: OwnedFd,
    lease: &PtaskLease,
    subnet: SwitchSubnet,
) -> io::Result<OwnedFd> {
    // SAFETY: `ns_fd` is an open netns fd; `CLONE_NEWNET` joins that net
    // namespace for this thread. Requires `CAP_SYS_ADMIN`.
    if unsafe { libc::setns(ns_fd.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("setns into PTask netns: {}", io::Error::last_os_error()),
        ));
    }
    // `TUNSETIFF` creates the tap in the *current* netns — now the PTask's.
    let tap = open_tap(name)
        .map_err(|e| io::Error::new(e.kind(), format!("creating tap {name} in netns: {e}")))?;
    configure_switch_interface(name, lease, subnet)
        .map_err(|e| io::Error::new(e.kind(), format!("configuring tap {name} in netns: {e}")))?;
    set_nonblocking(tap.as_raw_fd())?;
    Ok(tap)
}

/// Configures the switch tap `ifname` in the current (PTask) net namespace: the
/// lease MAC, the lease address within `subnet`, the interface and loopback up,
/// and a default route via the switch gateway — the in-process equivalent of the
/// `ip`/`nsenter` recipe in [`tap_netns_commands`]. Mirrors `guest.rs`'s ioctl
/// interface setup. IPv4-only, matching the `100.64/10` switch subnet.
fn configure_switch_interface(
    ifname: &str,
    lease: &PtaskLease,
    subnet: SwitchSubnet,
) -> io::Result<()> {
    // `ARPHRD_ETHER`: the L2 type for the `SIOCSIFHWADDR` MAC set.
    const ARPHRD_ETHER: u16 = 1;

    // The three `ifreq` variants the ioctls below read/write, each padded to the
    // kernel's 40-byte `sizeof(struct ifreq)`.
    #[repr(C)]
    struct IfReqHwaddr {
        name: [libc::c_char; IFNAMSIZ],
        hwaddr: libc::sockaddr,
        _pad: [u8; 8],
    }
    #[repr(C)]
    struct IfReqAddr {
        name: [libc::c_char; IFNAMSIZ],
        addr: libc::sockaddr_in,
        _pad: [u8; 8],
    }
    #[repr(C)]
    struct IfReqFlags {
        name: [libc::c_char; IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    let name_buf = |name: &str| -> [libc::c_char; IFNAMSIZ] {
        let mut buf = [0 as libc::c_char; IFNAMSIZ];
        for (dst, b) in buf.iter_mut().zip(name.bytes()) {
            *dst = b as libc::c_char;
        }
        buf
    };
    let sockaddr_in = |addr: std::net::Ipv4Addr| -> libc::sockaddr_in {
        // SAFETY: `sockaddr_in` is plain old data; zero then fill the fields.
        let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        s.sin_family = libc::AF_INET as libc::sa_family_t;
        s.sin_addr = libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        };
        s
    };

    // SAFETY: socket() returns a new fd or -1.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh, valid, owned socket fd; closed on drop.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = sock.as_raw_fd();

    let ioctl = |req: libc::c_ulong, ptr: *mut libc::c_void| -> io::Result<()> {
        // SAFETY: `fd` is an open AF_INET socket; `ptr` is a correctly-sized
        // `ifreq`/`rtentry` the kernel reads for `req`.
        let rc = unsafe { libc::ioctl(fd, req as libc::Ioctl, ptr) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };

    // 1. MAC, while the interface is still down (SIOCSIFHWADDR).
    let mut hw = IfReqHwaddr {
        name: name_buf(ifname),
        // SAFETY: `sockaddr` is POD; zero then fill family + the 6 MAC bytes.
        hwaddr: unsafe { std::mem::zeroed() },
        _pad: [0; 8],
    };
    hw.hwaddr.sa_family = ARPHRD_ETHER as libc::sa_family_t;
    for (dst, &b) in hw.hwaddr.sa_data.iter_mut().zip(lease.mac.0.iter()) {
        *dst = b as libc::c_char;
    }
    ioctl(
        libc::SIOCSIFHWADDR,
        std::ptr::from_mut(&mut hw).cast::<libc::c_void>(),
    )?;

    // 2. Address + netmask (SIOCSIFADDR / SIOCSIFNETMASK).
    let mut addr = IfReqAddr {
        name: name_buf(ifname),
        addr: sockaddr_in(lease.ip),
        _pad: [0; 8],
    };
    ioctl(
        libc::SIOCSIFADDR,
        std::ptr::from_mut(&mut addr).cast::<libc::c_void>(),
    )?;
    let prefix = subnet.prefix();
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let mut nm = IfReqAddr {
        name: name_buf(ifname),
        addr: sockaddr_in(std::net::Ipv4Addr::from(mask)),
        _pad: [0; 8],
    };
    ioctl(
        libc::SIOCSIFNETMASK,
        std::ptr::from_mut(&mut nm).cast::<libc::c_void>(),
    )?;

    // 3. Bring the tap up, then loopback (read flags, OR in IFF_UP|IFF_RUNNING).
    let bring_up = |iface: &str| -> io::Result<()> {
        let mut fl = IfReqFlags {
            name: name_buf(iface),
            flags: 0,
            _pad: [0; 22],
        };
        ioctl(
            libc::SIOCGIFFLAGS,
            std::ptr::from_mut(&mut fl).cast::<libc::c_void>(),
        )?;
        fl.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ioctl(
            libc::SIOCSIFFLAGS,
            std::ptr::from_mut(&mut fl).cast::<libc::c_void>(),
        )
    };
    bring_up(ifname)?;
    bring_up("lo")?;

    // 4. Default route via the switch gateway (0.0.0.0/0 -> gw), SIOCADDRT.
    let as_sockaddr = |a: std::net::Ipv4Addr| -> libc::sockaddr {
        // SAFETY: `sockaddr` and `sockaddr_in` share the leading family field;
        // populating rtentry's `sockaddr` route addresses from `sockaddr_in` is
        // the standard SIOCADDRT idiom (mirrors `guest.rs`).
        unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sockaddr_in(a)) }
    };
    // SAFETY: `rtentry` is POD; zero then fill the fields SIOCADDRT reads.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = as_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = as_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = as_sockaddr(subnet.gateway());
    rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
    ioctl(
        libc::SIOCADDRT,
        std::ptr::from_mut(&mut rt).cast::<libc::c_void>(),
    )?;

    Ok(())
}

/// Sets `O_NONBLOCK` on `fd` so the tap device can be epoll-driven via
/// [`AsyncFd`]. `std::fs::File` has no `set_nonblocking`, so this goes through
/// `fcntl` directly.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL on a valid, open fd reads/writes its status
    // flags; neither has any effect beyond that and cannot break memory safety.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A running switch relay. Dropping it aborts both relay directions, which
/// closes the gvproxy connection and detaches the PTask from the switch.
#[derive(Debug)]
#[must_use = "dropping the relay immediately detaches the PTask from the switch"]
pub struct SwitchRelay {
    tap_to_switch: JoinHandle<io::Result<()>>,
    switch_to_tap: JoinHandle<io::Result<()>>,
}

impl Drop for SwitchRelay {
    fn drop(&mut self) {
        self.tap_to_switch.abort();
        self.switch_to_tap.abort();
    }
}

/// Attaches `tap_fd` to the gvproxy switch listening on `api_sock` (DM2, native
/// Linux) and starts relaying frames between them.
///
/// Spawns two background tasks — tap→switch and switch→tap — and returns a
/// [`SwitchRelay`] handle whose lifetime keeps the attachment alive.
///
/// # Errors
///
/// Returns an error if the control socket cannot be connected, the connect
/// request cannot be written, or the tap fd cannot be put into non-blocking
/// mode for epoll-driven I/O.
pub async fn attach_to_switch(tap_fd: OwnedFd, api_sock: &Path) -> io::Result<SwitchRelay> {
    let mut sock = UnixStream::connect(api_sock).await?;
    sock.write_all(CONNECT_REQUEST).await?;
    let (sock_rx, sock_tx) = sock.into_split();
    spawn_relay(tap_fd, sock_rx, sock_tx)
}

/// Attaches `tap_fd` to the **host** gvproxy switch over AF_VSOCK (DM1/3/4) and
/// starts relaying frames between them.
///
/// On a libkrun VM the gvproxy switch runs on the host; the guest reaches it by
/// connecting to `cid` (CID 2 = the host) on `port`, which libkrun bridges to
/// the host gvproxy `-listen` socket (`minvmd` registers this via
/// `krun_add_vsock_port2(.., listen = false)`). This is the same HyperKit-framed
/// raw-L2 relay as [`attach_to_switch`] — the shuttle is *not* a second TCP/IP
/// stack — so exactly one gVisor stack (the host gvproxy) sits in the path.
///
/// # Errors
///
/// Returns an error if the vsock connection cannot be established, the connect
/// request cannot be written, or the tap fd cannot be put into non-blocking
/// mode for epoll-driven I/O.
pub async fn attach_to_switch_vsock(
    tap_fd: OwnedFd,
    cid: u32,
    port: u32,
) -> io::Result<SwitchRelay> {
    // Bound the connect + `/connect` upgrade: a wedged or absent host gvproxy
    // must fail the attach fast, not stall OwnIp bring-up forever.
    let sock = tokio::time::timeout(VSOCK_CONNECT_TIMEOUT, async {
        let mut sock =
            tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(cid, port)).await?;
        // `VsockStream` has an inherent (blocking, std::io) `write_all` that
        // shadows the async trait method, so disambiguate to the tokio trait —
        // same hazard `guest.rs` notes for `shutdown`.
        AsyncWriteExt::write_all(&mut sock, CONNECT_REQUEST).await?;
        Ok::<_, io::Error>(sock)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "vsock connect/upgrade to host gvproxy (cid {cid} port {port}) \
                 timed out after {VSOCK_CONNECT_TIMEOUT:?}"
            ),
        )
    })??;
    let (sock_rx, sock_tx) = tokio::io::split(sock);
    spawn_relay(tap_fd, sock_rx, sock_tx)
}

/// Wires `tap_fd` into the bidirectional frame relay against an already-connected,
/// `/connect`-upgraded switch stream split into `sock_rx`/`sock_tx`.
///
/// Shared by the DM2 UDS path ([`attach_to_switch`]) and the DM1/3/4 vsock path
/// ([`attach_to_switch_vsock`]); the relay loops are transport-agnostic
/// (`AsyncRead`/`AsyncWrite`), so only the connect step differs.
fn spawn_relay<R, W>(tap_fd: OwnedFd, sock_rx: R, sock_tx: W) -> io::Result<SwitchRelay>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // A tap character device does not support pread/pwrite, so `tokio::fs::File`
    // (which routes through the blocking pool via positional I/O) cannot drive
    // it. Use plain read/write in non-blocking mode with `AsyncFd` for epoll
    // readiness instead.
    // SAFETY: `tap_fd.into_raw_fd()` yields a valid, open, owned fd; `File`
    // takes exclusive ownership and closes it on drop.
    let tap_file = unsafe { std::fs::File::from_raw_fd(tap_fd.into_raw_fd()) };
    set_nonblocking(tap_file.as_raw_fd())?;
    let tap = Arc::new(AsyncFd::new(tap_file)?);

    let tap_to_switch = tokio::spawn(relay_tap_to_switch(Arc::clone(&tap), sock_tx));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
    })
}

/// tap → switch: read a raw Ethernet frame, prepend its 2-byte LE length, write
/// the framed packet to the control socket.
async fn relay_tap_to_switch<W>(tap: Arc<AsyncFd<std::fs::File>>, mut sock: W) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    // One byte larger than max_frame() so a full-size 1518-byte VLAN-tagged
    // frame gives n < buf.len() and is not mistaken for a truncated one.
    let mut buf = vec![0u8; max_frame() + 1];
    loop {
        let n = loop {
            let mut guard = tap.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };
        if n == 0 {
            return Ok(());
        }
        // A tap read is frame-atomic, but a frame larger than the buffer is
        // silently truncated to `buf.len()` by the kernel. Forwarding it would
        // emit corrupt bytes under a correct-looking length prefix, so drop it
        // and make the truncation observable instead of silently corrupting.
        if n == buf.len() {
            tracing::warn!(
                n,
                "tap frame filled the buffer; dropping possibly-truncated jumbo frame"
            );
            continue;
        }
        // One combined write keeps the length prefix and frame atomic even if
        // the socket closes between writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&buf[..n]);
        sock.write_all(&framed).await?;
    }
}

/// switch → tap: read a 2-byte LE length, then that many bytes of Ethernet
/// frame, write the frame to the tap device.
async fn relay_switch_to_tap<R>(mut sock: R, tap: Arc<AsyncFd<std::fs::File>>) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; max_frame()];
    loop {
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            // A clean close of the switch side ends the relay without error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        if n == 0 {
            tracing::warn!("switch sent zero-length frame claim; skipping");
            continue;
        }
        // Trust nothing the control socket claims about length: a frame larger
        // than the MTU-derived maximum would overrun the tap and points at a
        // malformed or hostile peer, so reject it rather than size an
        // allocation to it.
        if n > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switch frame length {n} exceeds max {}", frame.len()),
            ));
        }
        sock.read_exact(&mut frame[..n]).await?;
        loop {
            let mut guard = tap.writable().await?;
            // One non-blocking write per try_io call: write_all could issue
            // several syscalls and, on a partial write then EAGAIN, restart the
            // whole frame from byte 0 — re-emitting the already-written prefix.
            // A tap write is frame-atomic, so a single write delivers the whole
            // frame; a short count would mean a malformed write we surface.
            match guard.try_io(|inner| inner.get_ref().write(&frame[..n])) {
                Ok(result) => {
                    let written = result?;
                    if written != n {
                        tracing::warn!(written, n, "short tap write; frame may be truncated");
                    }
                    break;
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_is_little_endian_length() {
        // The HyperKit framing the relay emits: a 2-byte LE length prefix.
        assert_eq!((1u16).to_le_bytes(), [0x01, 0x00]);
        assert_eq!((1514u16).to_le_bytes(), [0xea, 0x05]);
        assert_eq!(u16::from_le_bytes([0xea, 0x05]) as usize, 1514);
    }

    #[test]
    fn max_frame_covers_mtu_header_and_vlan_tag() {
        assert_eq!(max_frame(), 1500 + 14 + 4);
    }

    #[test]
    fn open_tap_rejects_an_overlong_name() {
        let err = open_tap("this-name-is-way-too-long").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn tap_netns_commands_move_then_configure_by_pid() {
        use std::net::Ipv4Addr;

        let lease = PtaskLease {
            ip: Ipv4Addr::new(100, 64, 0, 2),
            mac: super::super::MacAddr::for_switch_ip(Ipv4Addr::new(100, 64, 0, 2)),
        };
        let cmds = tap_netns_commands("mtap0_2", 4321, lease, SwitchSubnet::default());

        // First the interface is moved into the PTask's namespace by PID; every
        // later command enters that namespace via `nsenter -t <pid> -n`.
        assert_eq!(cmds[0], ["ip", "link", "set", "mtap0_2", "netns", "4321"]);
        assert!(
            cmds[1..]
                .iter()
                .all(|c| c[..4] == ["nsenter", "-t", "4321", "-n"])
        );

        // The lease's address is configured as CIDR with the subnet prefix, and
        // the default route points at the switch gateway.
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert!(
            joined
                .iter()
                .any(|c| c.ends_with("ip addr add 100.64.0.2/16 dev mtap0_2"))
        );
        assert!(
            joined
                .iter()
                .any(|c| c.ends_with("ip route add default via 100.64.0.1"))
        );
        assert!(
            joined
                .iter()
                .any(|c| c.contains(&format!("address {}", lease.mac)))
        );
    }
}
