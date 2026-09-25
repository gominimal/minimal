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
//! attachment path). A gated relay — every own-IP session's — also carries its
//! session's network policy at this bridge, because gvproxy itself enforces
//! nothing per client (v0.8.9 has no per-client ACL API): the egress leg
//! applies the pure frame verdict (`sessions::core::egress`, NET-062/NET-063/
//! NET-064) to every frame before it reaches the switch, and the ingress leg
//! keeps the default-block posture of finding #2.

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

use super::policy::{Direction, PolicyWarnLimiter, Proto};
use super::{DEFAULT_MTU, PtaskLease, SwitchSubnet};
use sessions::core::egress::{self, DropReason, FrameSummary, FrameVerdict};

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
/// netns proof (`tests/netns_root_integration.rs`) wraps each in `sudo` on an
/// unprivileged runner. Single-sourcing the command construction keeps the proof
/// driving the same wiring the daemon does.
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

/// Moves the opened tap `tap` into the PTask network namespace held by
/// `netns_pid` and configures its switch address there, by execing the
/// [`tap_netns_commands`] directly. The host-side tap fd keeps working after the
/// interface moves namespaces, which is what [`attach_to_switch`] relays on.
///
/// Run on the `minimald` (daemon) side; requires `CAP_NET_ADMIN` in the host
/// namespace, which is why it is the mechanism only where the daemon has that
/// privilege by deployment — inside a microVM, reached over vsock; see
/// `net::provider::tap_mechanism`. `sandbox2` never calls this — it only
/// unshares the namespace and surfaces the PID (no dependency cycle).
///
/// # Errors
///
/// Returns an error if `ip`/`nsenter` cannot be spawned or any command exits
/// non-zero, naming the failing command line.
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
        // `output()` rather than `status()`: `ip` and `nsenter` distinguish
        // their failures only on stderr — "Cannot open network namespace" and
        // "Cannot find device" are both exit 255 — and an exit code alone has
        // already cost one diagnosis here.
        let out = tokio::process::Command::new(trusted_program(program))
            .args(rest)
            .env("PATH", TRUSTED_EXEC_PATH)
            .output()
            .await?;
        if !out.status.success() {
            // Command 0 moves the tap into the PTask namespace; the rest
            // configure it there, so name the phase the failing command is in.
            let phase = if index == 0 {
                "moving PTask tap into its namespace"
            } else {
                "configuring PTask tap"
            };
            let said = String::from_utf8_lossy(&out.stderr);
            let said = said.trim();
            let said = if said.is_empty() {
                "no stderr".to_string()
            } else {
                format!("said {said:?}")
            };
            // Whether the namespace this addresses still exists separates "the
            // supervisor exited under us" from "the tap is not where we think".
            // Both reach here as 255, and only one of them is our bug.
            let ns = std::path::Path::new(&format!("/proc/{netns_pid}/ns/net")).exists();
            return Err(io::Error::other(format!(
                "{phase} failed (`{}` exited with {}, {said}; /proc/{netns_pid}/ns/net present: {ns})",
                argv.join(" "),
                out.status
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
/// `gate` is the session's compiled network policy (see [`SessionGate`]):
/// `None` attaches ungated, which is the daemon's own relay — not a box, not a
/// session — and the netns proof's harness PTasks opt into via their declared
/// policies. `subnet` is the switch's subnet — the subnet gvproxy was configured
/// with — from which a gated relay derives the resolver address its egress
/// carve-out is keyed to (NET-079) and the deprecated host-alias literal it
/// notices (NET-004); the daemon relay ignores it.
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
    gate: Option<SessionGate>,
    subnet: SwitchSubnet,
) -> io::Result<SwitchRelay> {
    let mut sock = UnixStream::connect(api_sock).await?;
    sock.write_all(CONNECT_REQUEST).await?;
    let (sock_rx, sock_tx) = sock.into_split();
    spawn_relay(tap_fd, sock_rx, sock_tx, gate, subnet)
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
    gate: Option<SessionGate>,
    subnet: SwitchSubnet,
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
    spawn_relay(tap_fd, sock_rx, sock_tx, gate, subnet)
}

/// Wires `tap_fd` into the bidirectional frame relay against an already-connected,
/// `/connect`-upgraded switch stream split into `sock_rx`/`sock_tx`.
///
/// `subnet` is the switch this relay is attached to — the subnet the switch was
/// configured with — and a gated relay derives NET-004's deprecated host-alias
/// literal from it, so the notice always watches the address this switch (and
/// no other) NATs to the host's loopback. Shared by the DM2 UDS path
/// ([`attach_to_switch`]) and the DM1/3/4 vsock path
/// ([`attach_to_switch_vsock`]); the relay loops are transport-agnostic
/// (`AsyncRead`/`AsyncWrite`), so only the connect step differs.
fn spawn_relay<R, W>(
    tap_fd: OwnedFd,
    sock_rx: R,
    sock_tx: W,
    gate: Option<SessionGate>,
    subnet: SwitchSubnet,
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

    // One gate serves both legs: the egress leg applies its verdict, the
    // ingress leg its default-block posture, both sharing the conntrack (a
    // reply to the PTask's own UDP egress is solicited, finding #2) and the one
    // rate limiter, whose keys keep every rule's line independent.
    let gate = gate.map(Arc::new);
    // NET-004: a session relay tells its box — rate-limited — that frames to the
    // literal host-alias address are deprecated. The daemon's own relay (`gate`
    // is `None`) is not a box and gets no notice.
    let legacy_notice = gate
        .as_deref()
        .map(|gate| LegacyHostNotice::for_gate(gate, subnet));
    let tap_to_switch = tokio::spawn(relay_tap_to_switch(
        Arc::clone(&tap),
        sock_tx,
        gate.clone(),
        legacy_notice,
    ));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap, gate));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
    })
}

/// tap → switch: read a raw Ethernet frame, apply the session's egress verdict
/// to it (NET-062 — dropped frames never reach the switch and are not answered),
/// record any admitted outbound UDP flow (so its reply is allowed back in —
/// finding #2, UDP; only a declared frame opens a window), notice frames to the
/// deprecated literal host address (NET-004), prepend its 2-byte LE length, and
/// write the framed packet to the control socket. `gate` is `None` for the daemon
/// relay, which is not a box and forwards unchecked.
async fn relay_tap_to_switch<W>(
    tap: Arc<AsyncFd<std::fs::File>>,
    mut sock: W,
    gate: Option<Arc<SessionGate>>,
    notice: Option<LegacyHostNotice>,
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
        // Egress enforcement (NET-062, NET-063, NET-064): every frame is
        // decided against the box's declared policy before it reaches the
        // shared switch. A dropped frame is simply not written on — nothing is
        // sent back toward the box either, a drop is not a reset — and the drop
        // says so once per box per rule per minute (R2.7).
        if let Some(gate) = &gate {
            let summary = egress::summarize(&buf[..n]);
            if let FrameVerdict::Drop(reason) = egress::verdict(&summary, &gate.egress) {
                gate.limiter.warn(
                    &gate.label,
                    Direction::Egress,
                    drop_remote(&summary),
                    drop_transport(&reason),
                    reason.rule(),
                );
                continue;
            }
        }
        // Track outbound UDP so the inbound gate recognizes its reply as
        // solicited. Only a frame the verdict admitted gets a window: an
        // undeclared datagram must not punch a hole in the inbound gate.
        if let Some(gate) = &gate
            && let Some(pkt) = parse_ipv4_l4(&buf[..n])
            && pkt.proto == IPPROTO_UDP
        {
            gate.conntrack.record_egress(&pkt);
        }
        // NET-004: the literal host address still routes — the switch's `nat`
        // table maps it to the host's loopback — but the relay says, once per
        // interval, that `host.min.internal` is the name to use instead.
        if let Some(notice) = &notice
            && is_legacy_host_literal(&buf[..n], notice.alias)
        {
            notice.emit();
        }
        // One combined write keeps the length prefix and frame atomic even if
        // the socket closes between writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&buf[..n]);
        sock.write_all(&framed).await?;
    }
}

/// The R2.7 `remote_addr` of a dropped egress frame: the destination the box
/// tried to reach, when the frame carries one to read, with its L4 destination
/// port when that was readable too (`0` otherwise — a later fragment or a
/// truncated L4 header). `None` — rendered `none` in the warning — for the
/// drops with no IPv4 destination to name, as for IPv6, an undeclared family,
/// or a truncated frame.
fn drop_remote(summary: &FrameSummary) -> Option<SocketAddr> {
    let dst = summary.destination()?;
    Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(dst),
        summary.destination_port(),
    )))
}

/// The R2.7 `proto` of a dropped egress frame, from why the verdict dropped it:
/// `ipv6` for the family drop, `none` for a frame with no L4 header to name,
/// and the frame's IPv4 protocol number otherwise — `tcp`/`udp`/`icmp` by
/// name, anything else by number.
fn drop_transport(reason: &DropReason) -> Proto {
    match reason {
        DropReason::Ipv6 => Proto::Ipv6,
        DropReason::UndeclaredFamily(_) | DropReason::Truncated => Proto::None,
        DropReason::UndeclaredProtocol { proto }
        | DropReason::DeniedSubnet { proto, .. }
        | DropReason::UndeclaredSubnet { proto, .. } => Proto::from_ipv4_number(*proto),
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

/// The zone record name a box can resolve the host by (NET-003) — the name the
/// deprecation notice tells a box to use instead of the literal.
const HOST_MIN_INTERNAL: &str = "host.min.internal";

/// The limiter key the deprecation notice logs under: its own rule, so a
/// policy warning on the same relay never consumes the notice's interval and
/// vice versa (NET-062 keys the rate limit by box and rule).
const LEGACY_HOST_RULE: &str = "legacy-host-literal";

/// True when an Ethernet II frame is an IPv4 packet addressed to `alias` —
/// NET-004's deprecated literal host address, the address the switch's `nat`
/// table maps to the host's loopback. Any protocol counts: the notice is about
/// the destination address, not the transport.
fn is_legacy_host_literal(frame: &[u8], alias: Ipv4Addr) -> bool {
    // EtherType at 12..14; the IPv4 destination address at 14+16..14+20.
    frame.len() >= ETH_HDR + 20
        && frame[12..14] == ETHERTYPE_IPV4.to_be_bytes()
        && frame[30..34] == alias.octets()
}

/// Emits NET-004's deprecation notice on the egress relay leg: when a session
/// box sends frames to the literal host-alias address, the relay says so —
/// rate-limited, naming the box and [`HOST_MIN_INTERNAL`] — instead of letting
/// the connection pass silently on an address the code should not keep using.
struct LegacyHostNotice {
    /// The box's switch IP — the relay gate's `session_id` label, the same
    /// identity the policy warnings name.
    label: String,
    /// The literal address the notice watches for.
    alias: Ipv4Addr,
    /// The session gate's limiter, shared so one relay keeps one clock: its
    /// keys keep the notice's line independent of any policy warning's (the
    /// notice logs under its own rule key).
    limiter: Arc<PolicyWarnLimiter>,
}

impl LegacyHostNotice {
    /// Builds the notice from the relay's session gate, which carries the
    /// box's session label, and the subnet of the switch the relay is attached
    /// to, whose host alias is the deprecated literal — never a hardcoded
    /// default, so a custom-subnet switch's literal is watched too. The gate's
    /// limiter is shared, not the whole gate: the notice is egress-side.
    fn for_gate(gate: &SessionGate, subnet: SwitchSubnet) -> Self {
        Self {
            label: gate.label.clone(),
            alias: subnet.host_alias(),
            limiter: Arc::clone(&gate.limiter),
        }
    }

    /// Logs the notice if the rate limiter allows. Returns whether it fired.
    fn emit(&self) -> bool {
        if !self
            .limiter
            .should_warn_at(&self.label, LEGACY_HOST_RULE, Instant::now())
        {
            return false;
        }
        tracing::info!(
            session = %self.label,
            deprecated = %self.alias,
            replacement = HOST_MIN_INTERNAL,
            "connection to the deprecated literal host address; \
             use host.min.internal instead"
        );
        true
    }
}

/// A PTask's compiled network policy, applied at the relay bridge — gvproxy
/// v0.8.9 enforces nothing per client, so both directions of the session's
/// traffic are decided here:
///
/// - **Egress** (`tap → switch`) — every frame is decided by the pure verdict
///   in `sessions::core::egress` against the box's compiled
///   [`EgressRules`]: what the box did not declare is dropped, without
///   answering, and says so once per rule per minute (NET-062, NET-063,
///   NET-064).
/// - **Ingress** (`switch → tap`, UC6 / finding #2) — session↔session (and
///   daemon→session) traffic is subject to the *target* PTask's ingress
///   policy:
///   - **TCP** — a stateless SYN gate: a new inbound connection (a bare SYN)
///     to a port the target did not declare is dropped; established/return
///     traffic and declared ports pass (an ACK-set segment is never a new
///     connection).
///   - **UDP** — a conntracked gate: UDP has no connection-establishment
///     signal, so the egress leg records each *admitted* outbound datagram's
///     flow and the ingress leg allows a matching reply while dropping
///     unsolicited datagrams to undeclared ports (see [`UdpConntrack`]).
///
/// ICMP passes inbound (out of scope for the ingress half); non-IPv4 traffic
/// passes inbound, since its only sources are the switch's own ARP and the
/// relays minimald runs.
pub struct SessionGate {
    /// TCP destination ports the target accepts new inbound connections on — the
    /// *internal* ports of its TCP `port_mappings` (what the sandbox listens on,
    /// and what both a peer session and the host-publish forwarder dial). An empty
    /// set denies every inbound SYN (the own-IP default-block posture).
    allowed: HashSet<u16>,
    /// UDP destination ports the target accepts new inbound datagrams on (the
    /// internal ports of its UDP `port_mappings`). Inbound UDP to any other port
    /// passes only if it matches a live outbound flow in `conntrack`.
    udp_allowed: HashSet<u16>,
    /// Outbound-UDP flow tracker, shared between the relay legs so a reply to
    /// the PTask's own UDP egress (DNS, QUIC, …) is allowed back in — and an
    /// undeclared datagram cannot open a window.
    conntrack: Arc<UdpConntrack>,
    /// The target PTask's switch IP, carried as the R2.7 log's `session_id`.
    label: String,
    /// Rate-limited emitter for dropped-frame warnings (R2.7), keyed by box and
    /// rule, shared by both legs and the NET-004 notice.
    limiter: Arc<PolicyWarnLimiter>,
    /// The box's compiled egress rules, decided by `sessions::core::egress`.
    egress: egress::EgressRules,
}

impl SessionGate {
    /// Builds a gate from a session's whole policy: the declared internal ports
    /// per transport (TCP and UDP separately) drive the inbound half, the
    /// compiled egress rules the outbound half, and `subnet` names the switch
    /// the relay is attached to — whose gateway is the resolver the egress
    /// carve-out is keyed to (NET-079). A session with no declared ingress
    /// denies every new inbound connection/datagram while still receiving
    /// replies to its own egress; one with no declared egress allows all (the
    /// shipped default, until NET-074's deny-all default is in force).
    #[must_use]
    pub fn for_session(
        label: String,
        policy: &sessions::SessionPolicy,
        subnet: SwitchSubnet,
    ) -> Self {
        let ports = |proto: sessions::IpProto| -> HashSet<u16> {
            policy
                .ingress
                .as_ref()
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
            limiter: Arc::new(PolicyWarnLimiter::new()),
            egress: egress::EgressRules::from_policy(
                policy.egress.as_ref(),
                subnet.dns_server().octets(),
            ),
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
    if !syn || ack || allowed.contains(&pkt.dst.port()) {
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
    gate: Option<Arc<SessionGate>>,
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
                Some(SocketAddr::V4(src)),
                Proto::from_ipproto(proto),
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
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
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
            }),
            egress: None,
        };
        let gate = SessionGate::for_session("100.64.0.9".into(), &policy, SwitchSubnet::default());
        assert!(gate.allowed.contains(&80)); // TCP internal port
        assert!(!gate.allowed.contains(&53)); // the UDP mapping is not a TCP port
        assert!(!gate.allowed.contains(&18080)); // external port is not the listener
        assert!(gate.udp_allowed.contains(&53)); // UDP internal port
        assert!(!gate.udp_allowed.contains(&80)); // the TCP mapping is not a UDP port
        // A no-ingress own-IP session denies every new inbound connection/datagram.
        let empty = SessionGate::for_session(
            "x".into(),
            &sessions::SessionPolicy::default(),
            SwitchSubnet::default(),
        );
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
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
            }),
            egress: None,
        };
        let gate = SessionGate::for_session(LEASE.to_string(), &policy, SwitchSubnet::default());
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

    /// The egress-relay harness: drives a real [`spawn_relay`] end-to-end
    /// without a tap device or a gvproxy. A `SOCK_DGRAM` unix socketpair
    /// stands in for the tap (reads stay frame-atomic the way a tap's are,
    /// so the test writes whole frames as the box would), and a tokio
    /// duplex stands in for gvproxy's upgraded control socket — reading
    /// there observes exactly what the relay put on the wire, framed the
    /// way it frames.
    struct RelayHarness {
        /// The "box" end of the socketpair: frames written here are the
        /// box's egress; frames the relay writes back would be its answers.
        box_end: std::fs::File,
        /// The gvproxy side of the duplex: the relay's framed output.
        switch: tokio::io::DuplexStream,
        /// Keeps the relay's legs alive for the harness's lifetime.
        _relay: SwitchRelay,
    }

    /// Spawns a gated relay for a box at [`LEASE`] on the default switch
    /// subnet (whose gateway is the resolver the carve-out is keyed to),
    /// under `policy`.
    fn spawn_test_relay(policy: &sessions::SessionPolicy) -> RelayHarness {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `socketpair` with a valid domain/type either returns -1
        // (checked) or fills `fds` with two fresh descriptors.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: each fd in `fds` is a fresh, valid, owned descriptor just
        // returned by socketpair.
        let tap_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let box_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let (switch, relay_side) = tokio::io::duplex(64 * 1024);
        let (sock_rx, sock_tx) = tokio::io::split(relay_side);
        let gate = SessionGate::for_session(LEASE.to_string(), policy, SwitchSubnet::default());
        let relay = spawn_relay(
            tap_fd,
            sock_rx,
            sock_tx,
            Some(gate),
            SwitchSubnet::default(),
        )
        .expect("the harness relay spawns");
        RelayHarness {
            box_end,
            switch,
            _relay: relay,
        }
    }

    /// Reads one 2-byte-LE-framed frame off the relay's switch side.
    async fn read_framed(switch: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        switch.read_exact(&mut len_buf).await?;
        let n = u16::from_le_bytes(len_buf) as usize;
        let mut frame = vec![0u8; n];
        switch.read_exact(&mut frame).await?;
        Ok(frame)
    }

    /// An ARP frame: address resolution, a declared path for every box — the
    /// sentinel that says "everything before me has been decided".
    fn arp_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst MAC: broadcast
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        f.extend_from_slice(&[0u8; 28]); // payload is outside the verdict's scope
        f
    }

    /// An IPv6 frame: dropped as a family (NET-082), payload unread.
    fn ipv6_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&0x86DDu16.to_be_bytes()); // EtherType: IPv6
        f.extend_from_slice(&[0u8; 40]); // payload is outside the verdict's scope
        f
    }

    /// An Ethernet II + IPv4 + TCP frame the box sends to `dst`:`dst_port` —
    /// the egress direction of [`tcp_frame`], whose destination is the box
    /// itself. The segment is a new connection (SYN).
    fn egress_tcp_frame(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.push(0x45); // IPv4, IHL 5 (20 bytes), fragment offset 0
        f.push(0x00);
        f.extend_from_slice(&40u16.to_be_bytes()); // total length (unread)
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(IPPROTO_TCP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&40000u16.to_be_bytes()); // src port
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // seq
        f.extend_from_slice(&0u32.to_be_bytes()); // ack
        f.push(0x50); // data offset 5, reserved
        f.push(SYN);
        f.extend_from_slice(&0u16.to_be_bytes()); // window
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        f
    }

    /// An egress declaration that allows no destination: `allow_subnets`
    /// declared empty, every other dimension open. The address is the only
    /// thing undeclared, which is the drop the egress proofs probe — the
    /// strictest all-dimension deny-all would fire the protocol rule first.
    fn undeclared_destination_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: None,
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        }
    }

    /// NET-062: a frame to an undeclared destination is dropped at the relay —
    /// it never reaches the switch — and nothing is written back toward the
    /// box either: a drop is not a reset. The relay keeps forwarding after.
    #[tokio::test]
    async fn disallowed_egress_dropped_not_reset() {
        let mut harness = spawn_test_relay(&undeclared_destination_egress());

        // The box sends to an address it did not declare, then ARP (a declared
        // path for every box) as the sentinel: whatever has been put on the
        // wire by the time the sentinel arrives is everything the relay
        // forwarded — frames are decided in order, on one leg.
        let denied = egress_tcp_frame(LEASE, Ipv4Addr::new(203, 0, 113, 7), 443);
        let sentinel = arp_frame();
        harness.box_end.write_all(&denied).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();

        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(
            first, sentinel,
            "the undeclared frame never reached the switch"
        );

        // A reset would be a frame written back toward the box; a drop writes
        // nothing. Give the misbehavior a moment, then assert the box's end is
        // still silent.
        tokio::time::sleep(Duration::from_millis(100)).await;
        set_nonblocking(harness.box_end.as_raw_fd()).unwrap();
        let mut probe = [0u8; 1];
        let read = harness.box_end.read(&mut probe);
        assert!(
            matches!(read, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock),
            "a drop must not be answered: got {read:?}"
        );

        // And the relay still forwards afterwards — the drop broke nothing.
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay survives a dropped frame")
            .expect("the switch side stays open");
        assert_eq!(next, sentinel);
    }

    /// NET-062's warning: every drop is logged once per box per rule per
    /// minute — a flood of identical drops says one line, a different rule is
    /// still heard — and the line carries the box, the direction, the
    /// destination and the protocol (R2.7).
    #[tokio::test]
    async fn egress_drop_logged_rate_limited() {
        let capture = crate::test_harness::captured_log();
        let mut harness = spawn_test_relay(&undeclared_destination_egress());

        // Three identical drops, then the sentinel.
        let denied = egress_tcp_frame(LEASE, Ipv4Addr::new(203, 0, 113, 7), 443);
        let sentinel = arp_frame();
        for _ in 0..3 {
            harness.box_end.write_all(&denied).unwrap();
        }
        harness.box_end.write_all(&sentinel).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(first, sentinel);

        // `session_id`/`rule_matched` are string fields (rendered quoted);
        // the rest render through `Display`.
        let logged = capture.contents();
        assert_eq!(
            logged
                .matches("rule_matched=\"egress-undeclared-subnet\"")
                .count(),
            1,
            "three identical drops say one line: {logged}"
        );
        for expected in [
            "network policy violation",
            "session_id=\"100.64.0.9\"",
            "direction=egress",
            "remote_addr=203.0.113.7:443",
            "proto=tcp",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }

        // A drop under a different rule is not silenced by the first rule's
        // line: IPv6 says its own — no destination to name, no L4 protocol.
        harness.box_end.write_all(&ipv6_frame()).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(next, sentinel);

        let logged = capture.contents();
        assert_eq!(
            logged.matches("network policy violation").count(),
            2,
            "per-rule keys keep a second rule audible: {logged}"
        );
        for expected in [
            "rule_matched=\"egress-ipv6\"",
            "remote_addr=none",
            "proto=ipv6",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }
    }

    /// NET-063: a connection the policy declares completes — the frame
    /// reaches the switch exactly as the box sent it, and nothing is logged
    /// against it.
    #[tokio::test]
    async fn allowed_egress_succeeds() {
        let capture = crate::test_harness::captured_log();
        let policy = sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        };
        let mut harness = spawn_test_relay(&policy);

        let allowed = egress_tcp_frame(LEASE, Ipv4Addr::new(10, 1, 2, 3), 80);
        harness.box_end.write_all(&allowed).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the declared frame is forwarded")
            .expect("the switch side stays open");
        assert_eq!(first, allowed, "an allowed frame is forwarded verbatim");
        assert!(
            !capture.contents().contains("network policy violation"),
            "an allowed connection is not a violation"
        );
    }

    /// NET-064: with only TCP allowed, a UDP datagram is dropped — even to a
    /// declared subnet — and being dropped it opens no conntrack window, so
    /// its would-be reply is refused inbound too. TCP to the same declared
    /// subnet still completes.
    #[tokio::test]
    async fn udp_dropped_when_only_tcp_allowed() {
        let policy = sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        };
        let mut harness = spawn_test_relay(&policy);
        let peer = Ipv4Addr::new(10, 1, 2, 3);

        // UDP to the *declared* subnet: still dropped, because only TCP is
        // allowed. (UDP DNS to the gateway would still flow — the carve-out
        // is `sessions::core::egress`'s own proof.)
        let udp = udp_frame(LEASE, 40000, peer, 53);
        let sentinel = arp_frame();
        harness.box_end.write_all(&udp).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(first, sentinel, "the UDP datagram never reached the switch");

        // The dropped datagram opened no UDP conntrack window: its "reply"
        // from the peer is unsolicited inbound UDP to an undeclared port, and
        // must not reach the box either.
        let reply = udp_frame(peer, 53, LEASE, 40000);
        let mut framed = Vec::with_capacity(2 + reply.len());
        framed.extend_from_slice(&(reply.len() as u16).to_le_bytes());
        framed.extend_from_slice(&reply);
        harness.switch.write_all(&framed).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        set_nonblocking(harness.box_end.as_raw_fd()).unwrap();
        let mut probe = [0u8; 1];
        let read = harness.box_end.read(&mut probe);
        assert!(
            matches!(read, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock),
            "a dropped datagram must not open a reply window: got {read:?}"
        );

        // TCP to the same declared subnet still completes.
        let allowed = egress_tcp_frame(LEASE, peer, 80);
        harness.box_end.write_all(&allowed).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the declared TCP frame")
            .expect("the switch side stays open");
        assert_eq!(next, allowed, "TCP to the declared subnet completes");
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

    /// NET-004: a frame a session box sends to the old literal host address is
    /// noticed — one rate-limited line naming the box and the name to use
    /// instead — while frames to any other destination, or to the literal from
    /// a relay without a gate, notice nothing.
    #[test]
    fn legacy_host_literal_routes_with_deprecation() {
        // The literal is the attached switch's host alias — the address its
        // nat table routes to the host's loopback. Routing is the existing nat
        // table's job; what is new is the notice.
        let alias = SwitchSubnet::default().host_alias();
        assert_eq!(alias, Ipv4Addr::new(100, 64, 255, 254));

        let gate = SessionGate::for_session(
            "100.64.0.9".into(),
            &sessions::SessionPolicy::default(),
            SwitchSubnet::default(),
        );
        let notice = LegacyHostNotice::for_gate(&gate, SwitchSubnet::default());
        assert_eq!(notice.alias, alias, "the notice watches the switch's alias");

        // The alias comes from the switch the relay is attached to, never a
        // hardcoded default: a custom-subnet switch's literal is the one
        // noticed, and the default alias is not.
        let custom = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        let custom_notice = LegacyHostNotice::for_gate(
            &SessionGate::for_session(
                "10.0.0.9".into(),
                &sessions::SessionPolicy::default(),
                custom,
            ),
            custom,
        );
        assert_eq!(custom_notice.alias, custom.host_alias());
        assert_ne!(custom_notice.alias, alias);
        assert!(is_legacy_host_literal(
            &udp_frame(SRC, 40000, custom.host_alias(), 53),
            custom_notice.alias
        ));
        assert!(!is_legacy_host_literal(
            &udp_frame(SRC, 40000, alias, 53),
            custom_notice.alias
        ));

        // A frame to the literal is noticed; one to the gateway is not; a
        // truncated frame and a non-IPv4 ethertype are not.
        assert!(is_legacy_host_literal(
            &udp_frame(SRC, 40000, alias, 53),
            alias
        ));
        assert!(!is_legacy_host_literal(
            &udp_frame(SRC, 40000, Ipv4Addr::new(100, 64, 0, 1), 53),
            alias
        ));
        assert!(!is_legacy_host_literal(
            &udp_frame(SRC, 40000, alias, 53)[..14],
            alias
        ));
        assert!(!is_legacy_host_literal(
            &tcp_frame(0x0806, IPPROTO_TCP, SYN, SRC, 53),
            alias
        ));

        // Rate-limited through the limiter: the first connection to the literal
        // notices, a second one inside the interval does not.
        assert!(
            notice.emit(),
            "the first frames to the literal emit a notice"
        );
        assert!(
            !notice.emit(),
            "the notice is rate-limited within the interval"
        );

        // The notice shares the gate's limiter but logs under its own rule key,
        // so a policy warning on the same relay does not consume the
        // deprecation notice's interval.
        let gate = SessionGate::for_session(
            "100.64.0.10".into(),
            &sessions::SessionPolicy::default(),
            SwitchSubnet::default(),
        );
        assert!(gate.limiter.should_warn_at(
            "100.64.0.10",
            "egress-undeclared-subnet",
            Instant::now()
        ));
        let notice = LegacyHostNotice::for_gate(&gate, SwitchSubnet::default());
        assert!(
            notice.emit(),
            "a policy warning must not suppress the deprecation notice"
        );
    }
}
