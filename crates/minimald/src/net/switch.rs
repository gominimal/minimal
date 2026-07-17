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

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

use super::policy::{Direction, PolicyWarnLimiter};
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
/// unprivileged netns proof (tests/netns.rs, mothballed) wraps each in `sudo`.
/// Single-sourcing the
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
pub async fn attach_to_switch(
    tap_fd: OwnedFd,
    api_sock: &Path,
    gate: Option<IngressGate>,
) -> io::Result<SwitchRelay> {
    let mut sock = UnixStream::connect(api_sock).await?;
    sock.write_all(CONNECT_REQUEST).await?;
    let (sock_rx, sock_tx) = sock.into_split();
    spawn_relay(tap_fd, sock_rx, sock_tx, gate)
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
    gate: Option<IngressGate>,
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
    spawn_relay(tap_fd, sock_rx, sock_tx, gate)
}

/// Wires `tap_fd` into the bidirectional frame relay against an already-connected,
/// `/connect`-upgraded switch stream split into `sock_rx`/`sock_tx`.
///
/// Shared by the DM2 UDS path ([`attach_to_switch`]) and the DM1/3/4 vsock path
/// ([`attach_to_switch_vsock`]); the relay loops are transport-agnostic
/// (`AsyncRead`/`AsyncWrite`), so only the connect step differs.
fn spawn_relay<R, W>(
    tap_fd: OwnedFd,
    sock_rx: R,
    sock_tx: W,
    gate: Option<IngressGate>,
) -> io::Result<SwitchRelay>
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

    // Share the UDP flow tracker with the egress leg so a reply to the PTask's own
    // UDP egress is recognized as solicited by the inbound gate (finding #2, UDP).
    let egress_conntrack = gate.as_ref().map(|g| Arc::clone(&g.conntrack));
    let tap_to_switch = tokio::spawn(relay_tap_to_switch(
        Arc::clone(&tap),
        sock_tx,
        egress_conntrack,
    ));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap, gate));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
    })
}

/// tap → switch: read a raw Ethernet frame, record any outbound UDP flow (so its
/// reply is allowed back in — finding #2, UDP), prepend its 2-byte LE length, and
/// write the framed packet to the control socket. `conntrack` is `None` for the
/// daemon relay, which has no ingress gate.
async fn relay_tap_to_switch<W>(
    tap: Arc<AsyncFd<std::fs::File>>,
    mut sock: W,
    conntrack: Option<Arc<UdpConntrack>>,
) -> io::Result<()>
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
        // Track outbound UDP so the inbound gate recognizes its reply as solicited.
        if let Some(ct) = &conntrack
            && let Some(pkt) = parse_ipv4_l4(&buf[..n])
            && pkt.proto == IPPROTO_UDP
        {
            ct.record_egress(&pkt);
        }
        // One combined write keeps the length prefix and frame atomic even if
        // the socket closes between writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&buf[..n]);
        sock.write_all(&framed).await?;
    }
}

/// Ethernet II header length: destination MAC (6) + source MAC (6) + EtherType (2).
const ETH_HDR: usize = 14;
/// EtherType for IPv4. Frames carrying anything else (ARP `0x0806`, IPv6
/// `0x86DD`, VLAN-tagged `0x8100`) are outside the gate's scope and pass through.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// A per-PTask inbound ingress filter for the `switch → tap` relay leg.
///
/// Realizes UC6 / finding #2: session↔session (and daemon→session) traffic on the
/// shared gvproxy switch is subject to the *target* PTask's ingress policy, which
/// gvproxy itself cannot enforce (v0.8.9 has no per-client ACL API):
///
/// - **TCP** — a stateless SYN gate: a new inbound connection (a bare SYN) to a
///   port the target did not declare is dropped; established/return traffic and
///   declared ports pass (an ACK-set segment is never a new connection).
/// - **UDP** — a conntracked gate: UDP has no connection-establishment signal, so
///   the egress leg records each outbound datagram's flow and the ingress leg
///   allows a matching reply while dropping unsolicited datagrams to undeclared
///   ports (see [`UdpConntrack`]).
///
/// ICMP and non-IPv4 traffic pass (out of scope).
pub struct IngressGate {
    /// TCP destination ports the target accepts new inbound connections on — the
    /// *internal* ports of its TCP `port_mappings` (what the sandbox listens on,
    /// and what both a peer session and the host-publish forwarder dial). An empty
    /// set denies every inbound SYN (the own-IP default-block posture).
    allowed: HashSet<u16>,
    /// UDP destination ports the target accepts new inbound datagrams on (the
    /// internal ports of its UDP `port_mappings`). Inbound UDP to any other port
    /// passes only if it matches a live outbound flow in `conntrack`.
    udp_allowed: HashSet<u16>,
    /// Outbound-UDP flow tracker, shared with the egress relay leg so a reply to
    /// the PTask's own UDP egress (DNS, QUIC, …) is allowed back in.
    conntrack: Arc<UdpConntrack>,
    /// The target PTask's switch IP, carried as the R2.7 log's `session_id`.
    label: String,
    /// Rate-limited emitter for dropped-frame warnings (R2.7).
    limiter: PolicyWarnLimiter,
}

impl IngressGate {
    /// Builds a gate from a PTask's ingress policy: the declared internal ports
    /// per transport (TCP and UDP separately), plus a fresh UDP flow tracker. A
    /// session with no ingress denies every new inbound connection/datagram while
    /// still receiving replies to its own egress.
    #[must_use]
    pub fn for_session(label: String, ingress: Option<&sessions::IngressPolicy>) -> Self {
        let ports = |proto: sessions::IpProto| -> HashSet<u16> {
            ingress
                .map(|i| {
                    i.port_mappings
                        .iter()
                        .filter(|m| m.proto == proto)
                        .map(|m| m.internal_port)
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            allowed: ports(sessions::IpProto::Tcp),
            udp_allowed: ports(sessions::IpProto::Udp),
            conntrack: Arc::new(UdpConntrack::default()),
            label,
            limiter: PolicyWarnLimiter::new(),
        }
    }

    /// The inbound-gate decision for one Ethernet frame: `Some((proto, dst_port,
    /// src))` when it must be dropped — a new TCP connection or an unsolicited UDP
    /// datagram to a port the target did not declare — else `None` (pass).
    fn inbound_drop(&self, frame: &[u8]) -> Option<(sessions::IpProto, u16, SocketAddrV4)> {
        if let Some((dst_port, src)) = blocked_syn(frame, &self.allowed) {
            return Some((sessions::IpProto::Tcp, dst_port, src));
        }
        if let Some((dst_port, src)) = blocked_udp(frame, &self.udp_allowed, &self.conntrack) {
            return Some((sessions::IpProto::Udp, dst_port, src));
        }
        None
    }
}

/// The L4 addressing of a TCP/UDP-over-IPv4 frame, as extracted by
/// [`parse_ipv4_l4`]. `tcp_flags` is meaningful only when `proto == IPPROTO_TCP`.
struct L4Packet {
    /// Source `ip:port`.
    src: SocketAddrV4,
    /// Destination `ip:port`.
    dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    proto: u8,
    /// TCP flags byte; `0` for UDP.
    tcp_flags: u8,
}

/// Parses an Ethernet II + IPv4 + TCP/UDP frame into its L4 addressing, or `None`
/// for non-IPv4 (ARP/IPv6/VLAN), non-TCP/UDP, IP fragments, and short/malformed
/// frames. Length-checked at every step and allocation-free, so a truncated or
/// hostile frame yields `None` rather than an out-of-bounds read.
fn parse_ipv4_l4(frame: &[u8]) -> Option<L4Packet> {
    // Ethernet header + minimum (20-byte) IPv4 header.
    if frame.len() < ETH_HDR + 20 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETH_HDR..];
    // IHL (low nibble of byte 0) is the header length in 32-bit words.
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let proto = ip[9];
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return None;
    }
    // A non-zero fragment offset (low 13 bits of bytes 6–7) is a later fragment
    // with no L4 header at `ihl`; pass rather than misparse.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
        return None;
    }
    let l4 = &ip[ihl..];
    // TCP needs through the flags byte (offset 13); UDP only its 8-byte header.
    // Both carry src/dst ports in the first four bytes.
    let need = if proto == IPPROTO_TCP { 14 } else { 8 };
    if l4.len() < need {
        return None;
    }
    Some(L4Packet {
        src: SocketAddrV4::new(
            Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
            u16::from_be_bytes([l4[0], l4[1]]),
        ),
        dst: SocketAddrV4::new(
            Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
            u16::from_be_bytes([l4[2], l4[3]]),
        ),
        proto,
        tcp_flags: if proto == IPPROTO_TCP { l4[13] } else { 0 },
    })
}

/// Returns `Some((dst_port, src))` iff `frame` is a bare TCP SYN (SYN set, ACK
/// clear) to a port not in `allowed` — the one TCP case the ingress gate drops.
/// `None` (pass) for non-TCP, declared ports, and any ACK-set segment (SYN-ACK,
/// established, egress return).
fn blocked_syn(frame: &[u8], allowed: &HashSet<u16>) -> Option<(u16, SocketAddrV4)> {
    let pkt = parse_ipv4_l4(frame)?;
    if pkt.proto != IPPROTO_TCP {
        return None;
    }
    let (syn, ack) = (pkt.tcp_flags & 0x02 != 0, pkt.tcp_flags & 0x10 != 0);
    if !(syn && !ack) || allowed.contains(&pkt.dst.port()) {
        return None;
    }
    Some((pkt.dst.port(), pkt.src))
}

/// TTL for a tracked outbound UDP flow: an egress datagram opens a window in which
/// the matching reply is allowed back in. Long enough for real request/reply (DNS,
/// QUIC handshakes) without keeping stale state around.
const UDP_FLOW_TTL: Duration = Duration::from_secs(120);
/// Sweep expired flows once the table crosses this many entries, bounding memory
/// under a burst of distinct destinations without a background timer.
const UDP_FLOW_SWEEP_AT: usize = 4096;

/// Per-PTask UDP flow tracker shared between the egress and ingress relay legs.
///
/// UDP has no connection-establishment signal, so the TCP SYN test cannot tell a
/// reply from an unsolicited datagram. This records each *outbound* datagram's
/// reverse key `(remote_ip, remote_port, local_port)` so the matching *inbound*
/// reply is allowed, while genuinely-new inbound UDP to an undeclared port is
/// dropped (finding #2, UDP). The PTask's own address is fixed (its lease), so the
/// reverse tuple alone identifies a flow.
#[derive(Debug, Default)]
struct UdpConntrack {
    flows: Mutex<HashMap<(Ipv4Addr, u16, u16), Instant>>,
}

impl UdpConntrack {
    /// Records an outbound UDP datagram (`pkt.src` = local lease, `pkt.dst` =
    /// remote) so its reply may return.
    fn record_egress(&self, pkt: &L4Packet) {
        let key = (*pkt.dst.ip(), pkt.dst.port(), pkt.src.port());
        let now = Instant::now();
        let mut flows = self.flows.lock().expect("UdpConntrack mutex poisoned");
        flows.insert(key, now);
        if flows.len() > UDP_FLOW_SWEEP_AT {
            flows.retain(|_, seen| now.duration_since(*seen) < UDP_FLOW_TTL);
        }
    }

    /// Whether an inbound UDP datagram (`pkt.src` = remote, `pkt.dst` = local
    /// lease) matches a live outbound flow — i.e. is a reply the PTask solicited.
    fn allows_ingress(&self, pkt: &L4Packet) -> bool {
        let key = (*pkt.src.ip(), pkt.src.port(), pkt.dst.port());
        let flows = self.flows.lock().expect("UdpConntrack mutex poisoned");
        flows
            .get(&key)
            .is_some_and(|seen| Instant::now().duration_since(*seen) < UDP_FLOW_TTL)
    }
}

/// Returns `Some((dst_port, src))` iff `frame` is an inbound UDP datagram to a port
/// not in `udp_allowed` that also does not match a live outbound flow in
/// `conntrack` (so it is unsolicited, not a reply). `None` (pass) for non-UDP,
/// declared ports, and solicited replies.
fn blocked_udp(
    frame: &[u8],
    udp_allowed: &HashSet<u16>,
    conntrack: &UdpConntrack,
) -> Option<(u16, SocketAddrV4)> {
    let pkt = parse_ipv4_l4(frame)?;
    if pkt.proto != IPPROTO_UDP {
        return None;
    }
    let dst_port = pkt.dst.port();
    if udp_allowed.contains(&dst_port) || conntrack.allows_ingress(&pkt) {
        return None;
    }
    Some((dst_port, pkt.src))
}

/// switch → tap: read a 2-byte LE length, then that many bytes of Ethernet
/// frame, apply the inbound ingress gate (finding #2), and write the frame to the
/// tap device.
async fn relay_switch_to_tap<R>(
    mut sock: R,
    tap: Arc<AsyncFd<std::fs::File>>,
    gate: Option<IngressGate>,
) -> io::Result<()>
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
        // Inbound ingress gate (finding #2): drop a new TCP connection or an
        // unsolicited UDP datagram to a port the target PTask did not declare, so a
        // peer session or the daemon tap cannot reach undeclared listeners on the
        // shared switch. Replies to the PTask's own egress pass (TCP: ACK set; UDP:
        // matched by the conntrack).
        if let Some(gate) = &gate
            && let Some((proto, dst_port, src)) = gate.inbound_drop(&frame[..n])
        {
            gate.limiter.warn(
                &gate.label,
                Direction::Ingress,
                SocketAddr::V4(src),
                proto,
                &format!("no ingress mapping for {proto} dst port {dst_port}"),
            );
            continue;
        }
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

    /// Builds an Ethernet II + IPv4 + TCP frame for the ingress-gate tests.
    /// `flags` is the raw TCP flags byte (SYN = 0x02, ACK = 0x10).
    fn tcp_frame(ethertype: u16, proto: u8, flags: u8, src: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&ethertype.to_be_bytes());
        // IPv4 header, IHL = 5 (20 bytes), fragment offset 0.
        f.push(0x45);
        f.push(0x00);
        f.extend_from_slice(&40u16.to_be_bytes()); // total length (unread)
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(proto);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&Ipv4Addr::new(100, 64, 0, 9).octets()); // dst IP
        // TCP header, data offset 5.
        f.extend_from_slice(&40000u16.to_be_bytes()); // src port
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // seq
        f.extend_from_slice(&0u32.to_be_bytes()); // ack
        f.push(0x50); // data offset 5, reserved
        f.push(flags);
        f.extend_from_slice(&0u16.to_be_bytes()); // window
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        f
    }

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const SRC: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);

    #[test]
    fn gate_drops_syn_to_undeclared_port() {
        let allowed = HashSet::from([80]);
        let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999);
        let hit = blocked_syn(&frame, &allowed).expect("a SYN to :9999 must be blocked");
        assert_eq!(hit.0, 9999);
        assert_eq!(*hit.1.ip(), SRC);
        assert_eq!(hit.1.port(), 40000);
    }

    #[test]
    fn gate_passes_syn_to_declared_port() {
        let allowed = HashSet::from([80]);
        let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 80);
        assert!(blocked_syn(&frame, &allowed).is_none());
    }

    #[test]
    fn gate_passes_established_and_return_traffic() {
        let allowed = HashSet::new();
        // SYN-ACK and a pure ACK to an undeclared port are return/established
        // traffic (egress replies) and must never be dropped.
        for flags in [SYN | ACK, ACK] {
            let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, flags, SRC, 9999);
            assert!(
                blocked_syn(&frame, &allowed).is_none(),
                "flags {flags:#x} must pass"
            );
        }
    }

    #[test]
    fn gate_passes_non_tcp_and_non_ipv4() {
        let allowed = HashSet::new();
        // ARP and IPv6 EtherTypes.
        for et in [0x0806u16, 0x86DD] {
            assert!(blocked_syn(&tcp_frame(et, IPPROTO_TCP, SYN, SRC, 9999), &allowed).is_none());
        }
        // UDP (proto 17) and ICMP (proto 1) are not gated by the TCP-SYN check.
        for proto in [17u8, 1] {
            assert!(
                blocked_syn(&tcp_frame(ETHERTYPE_IPV4, proto, SYN, SRC, 9999), &allowed).is_none()
            );
        }
    }

    #[test]
    fn gate_passes_truncated_frames() {
        let allowed = HashSet::new();
        let full = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999);
        // A prefix shorter than eth(14) + ip(20) + tcp-through-flags(14) = 48
        // bytes cannot yield the TCP flags/port and must pass rather than misread.
        for cut in [0, 14, 20, 33, 40, 47] {
            assert!(blocked_syn(&full[..cut], &allowed).is_none(), "len {cut}");
        }
        // A one-byte-truncated frame (byte 53) still carries a full TCP header
        // through the flags/port, so it is correctly still classified.
        assert!(blocked_syn(&full[..full.len() - 1], &allowed).is_some());
    }

    #[test]
    fn for_session_collects_tcp_internal_ports_only() {
        let ingress = sessions::IngressPolicy {
            port_mappings: vec![
                sessions::PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                },
                sessions::PortMapping {
                    external_port: 19999,
                    internal_port: 53,
                    proto: sessions::IpProto::Udp,
                },
            ],
            dynamic_allowed_range: None,
        };
        let gate = IngressGate::for_session("100.64.0.9".into(), Some(&ingress));
        assert!(gate.allowed.contains(&80)); // TCP internal port
        assert!(!gate.allowed.contains(&53)); // the UDP mapping is not a TCP port
        assert!(!gate.allowed.contains(&18080)); // external port is not the listener
        assert!(gate.udp_allowed.contains(&53)); // UDP internal port
        assert!(!gate.udp_allowed.contains(&80)); // the TCP mapping is not a UDP port
        // A no-ingress own-IP session denies every new inbound connection/datagram.
        let empty = IngressGate::for_session("x".into(), None);
        assert!(empty.allowed.is_empty() && empty.udp_allowed.is_empty());
    }

    /// Builds an Ethernet II + IPv4 + UDP frame for the conntrack tests.
    fn udp_frame(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.push(0x45); // IPv4, IHL 5
        f.push(0x00);
        f.extend_from_slice(&28u16.to_be_bytes()); // total length
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(IPPROTO_UDP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum
        f.extend_from_slice(&src_ip.octets());
        f.extend_from_slice(&dst_ip.octets());
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&8u16.to_be_bytes()); // UDP length
        f.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum
        f
    }

    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);

    #[test]
    fn gate_drops_unsolicited_udp_to_undeclared_port() {
        let ct = UdpConntrack::default();
        // A peer datagram to an undeclared port with no matching outbound flow.
        let frame = udp_frame(PEER, 33333, LEASE, 9999);
        let hit = blocked_udp(&frame, &HashSet::new(), &ct).expect("unsolicited UDP must drop");
        assert_eq!(hit.0, 9999);
        assert_eq!(*hit.1.ip(), PEER);
    }

    #[test]
    fn gate_passes_udp_to_declared_port() {
        let ct = UdpConntrack::default();
        let frame = udp_frame(PEER, 33333, LEASE, 53);
        assert!(blocked_udp(&frame, &HashSet::from([53]), &ct).is_none());
    }

    #[test]
    fn conntrack_allows_only_the_matching_reply() {
        let ct = UdpConntrack::default();
        // The PTask sends a DNS query out: lease:40000 -> 1.1.1.1:53.
        let egress =
            parse_ipv4_l4(&udp_frame(LEASE, 40000, Ipv4Addr::new(1, 1, 1, 1), 53)).unwrap();
        ct.record_egress(&egress);
        // The reply (1.1.1.1:53 -> lease:40000) is solicited, so it passes even to
        // the undeclared ephemeral port.
        let reply = udp_frame(Ipv4Addr::new(1, 1, 1, 1), 53, LEASE, 40000);
        assert!(blocked_udp(&reply, &HashSet::new(), &ct).is_none());
        // A datagram from the same peer to a *different* local port is unsolicited.
        let other = udp_frame(Ipv4Addr::new(1, 1, 1, 1), 53, LEASE, 40001);
        assert!(blocked_udp(&other, &HashSet::new(), &ct).is_some());
        // As is one from a different source to the tracked local port.
        let spoof = udp_frame(PEER, 53, LEASE, 40000);
        assert!(blocked_udp(&spoof, &HashSet::new(), &ct).is_some());
    }

    #[test]
    fn inbound_drop_tags_the_transport() {
        let ingress = sessions::IngressPolicy {
            port_mappings: vec![sessions::PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: sessions::IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        };
        let gate = IngressGate::for_session(LEASE.to_string(), Some(&ingress));
        // New TCP connection to an undeclared port -> dropped, tagged Tcp.
        let tcp = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 9999);
        assert_eq!(
            gate.inbound_drop(&tcp).map(|d| d.0),
            Some(sessions::IpProto::Tcp)
        );
        // Unsolicited UDP to an undeclared port -> dropped, tagged Udp.
        let udp = udp_frame(PEER, 33333, LEASE, 9999);
        assert_eq!(
            gate.inbound_drop(&udp).map(|d| d.0),
            Some(sessions::IpProto::Udp)
        );
        // Declared TCP port passes.
        let ok = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 80);
        assert!(gate.inbound_drop(&ok).is_none());
    }

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
