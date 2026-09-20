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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sessions::core::net_verdict::{self, DropRule, EgressRules, Verdict};
use sessions::core::rebind::{self, RebindRules};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

use super::policy::{
    BoxZone, BoxZoneTarget, Direction, KeyedWarnLimiter, PinTable, PinnedAddress,
    PolicyWarnLimiter, admission_window,
};
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
    // UDP egress is recognized as solicited by the inbound gate (finding #2, UDP),
    // hand that leg the box's egress gate, and give it the box's identity so it
    // can notice a connection to the legacy literal host address (NET-004).
    let egress = gate.as_ref().map(EgressWatch::for_gate);
    let tap_to_switch = tokio::spawn(relay_tap_to_switch(Arc::clone(&tap), sock_tx, egress));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap, gate));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
    })
}

/// tap → switch: read a raw Ethernet frame, apply the box's egress verdict
/// (NET-062 to NET-064, NET-084), let the egress watch read an admitted frame
/// (an outbound UDP flow to remember so its reply is allowed back in — finding
/// #2, UDP; a connection to the legacy host address to notice), prepend its
/// 2-byte LE length, and write the framed packet to the control socket.
/// `egress` is `None` for the daemon relay, which carries no box's traffic and
/// has no gate.
async fn relay_tap_to_switch<W>(
    tap: Arc<AsyncFd<std::fs::File>>,
    mut sock: W,
    egress: Option<EgressWatch>,
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
        // The egress verdict. A dropped frame is neither forwarded nor answered:
        // nothing reaches the switch and nothing goes back down the tap, so the
        // box's connection attempt times out rather than seeing a reset.
        if let Some(egress) = &egress
            && !egress.admit(&buf[..n])
        {
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

/// Ethernet II header length: destination MAC (6) + source MAC (6) + EtherType (2).
const ETH_HDR: usize = 14;
/// EtherType for IPv4. On the inbound gate, frames carrying anything else (ARP
/// `0x0806`, IPv6 `0x86DD`, VLAN-tagged `0x8100`) are outside its scope and
/// pass through; the egress gate admits only IPv4 and ARP.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for ARP: how the box resolves the switch gateway's MAC, so it is
/// the one non-IP frame the egress gate admits (with the sender address
/// checked against the lease, as for IPv4).
const ETHERTYPE_ARP: u16 = 0x0806;
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
    /// The switch's host-gateway address: the literal a box was told to dial
    /// before `host.min.internal` answered it, which the egress leg notices as
    /// deprecated (NET-004). Carried here because this is the per-box relay
    /// context both legs are built from.
    legacy_host: Ipv4Addr,
    /// Rate-limited emitter for dropped-frame warnings (R2.7).
    limiter: PolicyWarnLimiter,
    /// The box's egress gate, applied on the `tap → switch` leg. Carried here
    /// so both legs of the relay are configured through one handle; `None`
    /// only for a relay with no box behind it.
    egress: Option<Arc<EgressGate>>,
}

/// What the egress (tap → switch) leg holds on a box's own relay: the box's
/// egress gate, which decides each outbound frame (NET-062 to NET-064,
/// NET-084), plus what it reads from an admitted one — the UDP flows whose
/// replies the ingress gate must admit, and the box's use of the literal host
/// address the name superseded (NET-004).
#[derive(Clone)]
struct EgressWatch {
    /// The box's egress gate, as [`IngressGate::egress`] carries it; `None`
    /// for a relay with no box behind it, which admits everything.
    egress: Option<Arc<EgressGate>>,
    /// Shared with the ingress leg's gate, so a reply to the box's own UDP egress
    /// is recognized as solicited (finding #2, UDP).
    conntrack: Arc<UdpConntrack>,
    /// The box, as its gate labels it — the R2.7 `session_id`.
    session_id: String,
    /// The literal host address, as [`IngressGate::legacy_host`] holds it.
    legacy_host: Ipv4Addr,
}

impl EgressWatch {
    /// The egress-side view of a box's ingress gate.
    fn for_gate(gate: &IngressGate) -> Self {
        Self {
            egress: gate.egress.clone(),
            conntrack: Arc::clone(&gate.conntrack),
            session_id: gate.label.clone(),
            legacy_host: gate.legacy_host,
        }
    }

    /// Decides one outbound frame: `false` when the egress gate drops it, in
    /// which case nothing else reads it; else `true`, after
    /// [`Self::observe`] has read it.
    fn admit(&self, frame: &[u8]) -> bool {
        if let Some(gate) = &self.egress
            && !gate.admit(frame)
        {
            return false;
        }
        self.observe(frame);
        true
    }

    /// Reads one outbound frame: records an outbound UDP flow, and notices a new
    /// connection to the literal host address.
    ///
    /// Observation only. The literal is the very address `host.min.internal`
    /// answers a box on the switch ([`policy::host_reach_address`]), so the
    /// connection routes as the name with nothing rewritten and keeps working;
    /// what it gains is one notice naming the box and the name to use instead
    /// (NET-004).
    ///
    /// [`policy::host_reach_address`]: super::policy::host_reach_address
    fn observe(&self, frame: &[u8]) {
        let Some(pkt) = parse_ipv4_l4(frame) else {
            return;
        };
        if pkt.proto == IPPROTO_UDP {
            self.conntrack.record_egress(&pkt);
        }
        if opens_connection(&pkt) && *pkt.dst.ip() == self.legacy_host {
            tracing::info!(
                session_id = self.session_id.as_str(),
                literal = %self.legacy_host,
                port = pkt.dst.port(),
                name = super::policy::HOST_HOSTNAME,
                "box connected to the deprecated literal host address; resolve the name instead"
            );
        }
    }
}

impl IngressGate {
    /// Builds a gate from a PTask's ingress policy: the declared internal ports
    /// per transport (TCP and UDP separately), plus a fresh UDP flow tracker. A
    /// session with no ingress denies every new inbound connection/datagram while
    /// still receiving replies to its own egress. `subnet` is the switch this
    /// PTask attaches to, whose host-gateway address the egress leg watches for
    /// (NET-004).
    #[must_use]
    pub fn for_session(
        label: String,
        ingress: Option<&sessions::IngressPolicy>,
        subnet: SwitchSubnet,
    ) -> Self {
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
            legacy_host: subnet.host_alias(),
            limiter: PolicyWarnLimiter::new(),
            egress: None,
        }
    }

    /// Adds the box's egress gate, so the relay this gate configures decides
    /// outbound frames as well as inbound ones. Shared, so the caller keeps a
    /// handle to read its drop counters.
    #[must_use]
    pub fn with_egress(mut self, egress: Arc<EgressGate>) -> Self {
        self.egress = Some(egress);
        self
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

/// A per-box egress filter for the `tap → switch` relay leg (NET-062, NET-063,
/// NET-064, NET-084).
///
/// The decision is [`net_verdict::frame_verdict`], a pure function in
/// `sessions` over an owned frame summary and the box's owned rules; this
/// type only summarizes the Ethernet frame, applies the verdict, counts what
/// was dropped and warns about it rate-limited per rule (R2.2/R2.7). A
/// dropped frame is discarded silently on the wire: nothing is forwarded and
/// nothing is answered, so the box sees a timeout, never a reset.
///
/// At the link layer only IPv4 and ARP are admitted. ARP is how the box
/// finds the gateway's MAC, and its sender address is held to the lease like
/// an IPv4 source; anything else (IPv6, VLAN-tagged) is undeclared by
/// construction and dropped.
///
/// A box declaring `egress.allow_dns_hosts` also reaches the addresses those
/// names resolved to (NET-066): the `switch → tap` leg hands every resolver
/// answer to [`Self::observe_answer`], which intersects it with the denied
/// ranges ([`rebind::intersect`], NET-067) and pins what survives for the
/// answer's window. A frame the verdict finds undeclared is then admitted when
/// its destination is pinned; a denied destination never is, because the
/// verdict names the box's denies before it looks for a declaration and the
/// intersection admits nothing in the infrastructure set.
///
/// A destination that is a sibling box's lease is decided by those same rules —
/// a box-zone name resolves with no allow entry (NET-072) and the address it
/// resolved to is then an address like any other (NET-073). What the
/// [`BoxZone`] adds here is the account of it: one debug line per box-to-box
/// connection naming both boxes and the verdict each side's rules give it, and
/// a refusal counted as a box-to-box one rather than lost among external drops.
pub struct EgressGate {
    rules: EgressRules,
    /// The session, carried as the warning's `session_id`.
    label: String,
    /// One R2.2 window per rule, so a flood dropped by one rule cannot silence
    /// the first drop by another.
    limiter: KeyedWarnLimiter<&'static str>,
    stats: Mutex<EgressDropStats>,
    /// The box's name rules, when it declares `egress.allow_dns_hosts`.
    names: Option<NameRules>,
    /// The addresses its allowed names resolved to, each for its window.
    pins: Mutex<PinTable>,
    /// The in-guest box zone, shared with every other box's relay: the table
    /// that names the sibling behind a destination address and carries its
    /// declared ingress. `None` for a relay built without one, whose box-to-box
    /// frames are then accounted for like any others.
    zone: Option<Arc<BoxZone>>,
}

/// A box's `egress.allow_dns_hosts` and the ranges an answer for one of those
/// names is intersected against.
struct NameRules {
    hosts: Vec<String>,
    rebind: RebindRules,
}

/// What a box's egress gate has dropped so far, for the diagnostics bundle:
/// a count per rule and the last dropped destination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressDropStats {
    /// Drops per rule name, as the warning's `rule_matched` spells it.
    pub by_rule: BTreeMap<&'static str, u64>,
    /// The box-to-box refusals among them, per rule (NET-073): the drops whose
    /// destination was a sibling box's lease. Counted separately so a bundle
    /// tells a refused sibling from a refused external address, and included in
    /// `by_rule` as well — the rule refused the frame either way.
    pub box_zone_by_rule: BTreeMap<&'static str, u64>,
    /// The destination of the most recent drop that carried one.
    pub last_destination: Option<SocketAddrV4>,
}

impl EgressDropStats {
    /// Every drop, across rules.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.by_rule.values().sum()
    }
}

/// The egress gate's decision on one Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressDecision {
    Admit,
    Drop {
        rule: &'static str,
        destination: Option<SocketAddrV4>,
        proto: Option<sessions::IpProto>,
    },
}

impl EgressDecision {
    /// The decision as the box-zone connection line spells it: `admit`, or the
    /// rule that refused the frame.
    fn verdict(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Drop { rule, .. } => rule,
        }
    }
}

/// A box-to-box frame as the egress leg sees it (NET-073): the sibling holding
/// the destination address with its ingress verdict, where it was dialled, and
/// whether this frame opens the connection.
struct BoxZoneFrame {
    /// The target box and what its own ingress rules say about the port.
    target: BoxZoneTarget,
    /// The `ip:port` dialled — the sibling's switch lease.
    destination: SocketAddrV4,
    /// The frame's transport.
    proto: sessions::IpProto,
    /// Whether the frame opens the connection (a bare TCP SYN), which is what
    /// the connection line is emitted for.
    opens: bool,
}

/// The sender protocol address of an Ethernet/IPv4 ARP frame, or `None` for
/// any other ARP shape (or a frame cut short of it).
fn arp_sender_ip(frame: &[u8]) -> Option<Ipv4Addr> {
    // ARP after the Ethernet header: htype(2) ptype(2) hlen(1) plen(1) oper(2)
    // sha(6) spa(4) ...; only Ethernet/IPv4 ARP has this layout.
    let arp = frame.get(ETH_HDR..ETH_HDR + 18)?;
    (arp[..6] == [0x00, 0x01, 0x08, 0x00, 6, 4])
        .then(|| Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]))
}

impl EgressGate {
    /// A gate for the box labelled `label`, deciding on `rules`.
    #[must_use]
    pub fn for_box(label: String, rules: EgressRules) -> Self {
        Self {
            rules,
            label,
            limiter: KeyedWarnLimiter::new(),
            stats: Mutex::new(EgressDropStats::default()),
            names: None,
            pins: Mutex::new(PinTable::default()),
            zone: None,
        }
    }

    /// Adds the in-guest box zone, so this leg can name the sibling a frame is
    /// addressed to and the verdict that box's own ingress rules give the port
    /// (NET-073). Shared with every other box's relay; it changes no verdict of
    /// this gate's own.
    #[must_use]
    pub fn with_box_zone(mut self, zone: Arc<BoxZone>) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Adds the box's `egress.allow_dns_hosts`: an answer for one of `hosts`
    /// admits its addresses for the answer's window, less the box's own
    /// denies and the infrastructure deny set, which holds `gateway_addresses`
    /// (the switch gateway and the other addresses the node answers on).
    #[must_use]
    pub fn with_dns_pinning(mut self, hosts: Vec<String>, gateway_addresses: &[Ipv4Addr]) -> Self {
        let rebind = RebindRules::for_box(
            self.rules.allow_subnets.clone(),
            self.rules.deny_subnets.clone(),
            gateway_addresses,
        );
        self.names = Some(NameRules { hosts, rebind });
        self
    }

    /// Reads one inbound frame for a resolver answer (NET-066, NET-067): a UDP
    /// datagram from the resolver carve-out to the lease that answers a name
    /// the box's `allow_dns_hosts` matches. The answer's addresses are
    /// intersected with the denied ranges; what survives is admitted for the
    /// answer's window, and each refused address is logged with the name and
    /// the answer. Anything else is not read.
    pub fn observe_answer(&self, frame: &[u8]) {
        self.observe_answer_at(frame, Instant::now());
    }

    fn observe_answer_at(&self, frame: &[u8], now: Instant) {
        let Some(names) = &self.names else {
            return;
        };
        let Some(pkt) = parse_ipv4_l4(frame) else {
            return;
        };
        let from_resolver = self.rules.resolver.is_some_and(|r| {
            pkt.proto == IPPROTO_UDP && pkt.src == SocketAddrV4::new(r.ip, r.port)
        });
        if !from_resolver || *pkt.dst.ip() != self.rules.lease {
            return;
        }
        let Some(answer) = super::dns::parse_resolved_name(pkt.payload) else {
            return;
        };
        if !super::dns::name_allowed(&names.hosts, &answer.name) {
            return;
        }
        let split = rebind::intersect(&answer.addresses, &names.rebind);
        for (address, why) in &split.refused {
            tracing::warn!(
                session_id = %self.label,
                name = answer.name.as_str(),
                answer = %address,
                rule_matched = why.as_str(),
                "refused a resolved address in a denied range"
            );
        }
        if split.admitted.is_empty() {
            return;
        }
        let window = admission_window(answer.ttl);
        tracing::debug!(
            session_id = %self.label,
            name = answer.name.as_str(),
            addresses = ?split.admitted,
            window_secs = window.as_secs(),
            "admitted a resolved name's addresses"
        );
        self.pins
            .lock()
            .expect("EgressGate pins mutex poisoned")
            .admit(
                &answer.name,
                &split.admitted,
                &answer.addresses,
                window,
                now,
            );
    }

    /// The box's admitted-address table as it stands now, for the diagnostics
    /// bundle: each entry's name, source answer and expiry.
    #[must_use]
    pub fn pinned(&self) -> Vec<PinnedAddress> {
        self.pins
            .lock()
            .expect("EgressGate pins mutex poisoned")
            .live(Instant::now())
    }

    /// The decision on `frame` at `now`, with no side effects.
    fn decide(&self, frame: &[u8], now: Instant) -> EgressDecision {
        let malformed = EgressDecision::Drop {
            rule: "malformed",
            destination: None,
            proto: None,
        };
        let Some(ethertype) = frame.get(12..14) else {
            return malformed;
        };
        match u16::from_be_bytes([ethertype[0], ethertype[1]]) {
            ETHERTYPE_ARP => match arp_sender_ip(frame) {
                Some(sender) if sender == self.rules.lease => EgressDecision::Admit,
                Some(_) => EgressDecision::Drop {
                    rule: net_verdict::DropRule::Source.as_str(),
                    destination: None,
                    proto: None,
                },
                None => malformed,
            },
            ETHERTYPE_IPV4 => {
                let Some(summary) = net_verdict::summarize_ipv4(&frame[ETH_HDR..]) else {
                    return malformed;
                };
                match net_verdict::frame_verdict(&summary, &self.rules) {
                    Verdict::Admit => EgressDecision::Admit,
                    // Undeclared by address, but resolved from an allowed name
                    // inside its window (NET-066). The verdict has already
                    // refused the box's denies, and the intersection never
                    // pinned the infrastructure set.
                    Verdict::Drop(DropRule::Undeclared)
                        if self
                            .pins
                            .lock()
                            .expect("EgressGate pins mutex poisoned")
                            .admits(summary.dst, now) =>
                    {
                        EgressDecision::Admit
                    }
                    Verdict::Drop(rule) => EgressDecision::Drop {
                        rule: rule.as_str(),
                        destination: Some(SocketAddrV4::new(
                            summary.dst,
                            summary.dst_port.unwrap_or(0),
                        )),
                        proto: net_verdict::ip_proto(summary.proto),
                    },
                }
            }
            _ => EgressDecision::Drop {
                rule: "ethertype",
                destination: None,
                proto: None,
            },
        }
    }

    /// Whether `frame` may leave the box. On a drop, counts it and emits the
    /// R2.7 warning if this rule's window has elapsed.
    fn admit(&self, frame: &[u8]) -> bool {
        self.admit_at(frame, Instant::now())
    }

    /// The sibling `frame` is addressed to, or `None` when the relay holds no
    /// box zone, the frame is not TCP/UDP over IPv4, or no live box holds the
    /// destination address.
    ///
    /// `decision` is what the rules made of the frame: an admitted frame that
    /// opens no connection is neither a connection to record nor a refusal to
    /// count, so the zone is not consulted for it and an established flow pays
    /// nothing for the account.
    fn box_zone_frame(&self, frame: &[u8], decision: EgressDecision) -> Option<BoxZoneFrame> {
        let zone = self.zone.as_ref()?;
        let pkt = parse_ipv4_l4(frame)?;
        let opens = opens_connection(&pkt);
        if !opens && matches!(decision, EgressDecision::Admit) {
            return None;
        }
        let proto = net_verdict::ip_proto(pkt.proto)?;
        let target = zone.target_at(*pkt.dst.ip(), proto, pkt.dst.port())?;
        Some(BoxZoneFrame {
            target,
            destination: pkt.dst,
            proto,
            opens,
        })
    }

    fn admit_at(&self, frame: &[u8], now: Instant) -> bool {
        let decision = self.decide(frame, now);
        let sibling = self.box_zone_frame(frame, decision);
        // One line per box-to-box connection (NET-073), naming both boxes and
        // the verdict each side's rules give it: this gate's own, which decides
        // the frame here, and the target's ingress, which decides it on the
        // target's relay leg. A connection is a bare SYN, as it is for both
        // gates, so the line lands once rather than once per frame it carries.
        if let Some(sibling) = &sibling
            && sibling.opens
        {
            tracing::debug!(
                session_id = %self.label,
                source = %self.label,
                target = %sibling.target.session,
                remote_addr = %sibling.destination,
                proto = %sibling.proto,
                egress = decision.verdict(),
                ingress = sibling.target.ingress.as_str(),
                "box-zone connection"
            );
        }
        match decision {
            EgressDecision::Admit => true,
            EgressDecision::Drop {
                rule,
                destination,
                proto,
            } => {
                {
                    let mut stats = self.stats.lock().expect("EgressGate stats mutex poisoned");
                    *stats.by_rule.entry(rule).or_insert(0) += 1;
                    if sibling.is_some() {
                        *stats.box_zone_by_rule.entry(rule).or_insert(0) += 1;
                    }
                    if destination.is_some() {
                        stats.last_destination = destination;
                    }
                }
                if self.limiter.should_warn_at(rule, now) {
                    tracing::warn!(
                        session_id = %self.label,
                        direction = %Direction::Egress,
                        remote_addr = destination.map(tracing::field::display),
                        proto = proto.map(tracing::field::display),
                        rule_matched = rule,
                        "network policy violation"
                    );
                }
                false
            }
        }
    }

    /// A snapshot of what this gate has dropped.
    #[must_use]
    pub fn drop_stats(&self) -> EgressDropStats {
        self.stats
            .lock()
            .expect("EgressGate stats mutex poisoned")
            .clone()
    }
}

/// The L4 addressing of a TCP/UDP-over-IPv4 frame, as extracted by
/// [`parse_ipv4_l4`]. `tcp_flags` is meaningful only when `proto == IPPROTO_TCP`.
struct L4Packet<'a> {
    /// Source `ip:port`.
    src: SocketAddrV4,
    /// Destination `ip:port`.
    dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    proto: u8,
    /// TCP flags byte; `0` for UDP.
    tcp_flags: u8,
    /// The bytes after the transport header: a UDP datagram's body (a DNS
    /// message, when the datagram is a resolver answer). Empty for TCP, whose
    /// options are not walked.
    payload: &'a [u8],
}

/// Parses an Ethernet II + IPv4 + TCP/UDP frame into its L4 addressing, or `None`
/// for non-IPv4 (ARP/IPv6/VLAN), non-TCP/UDP, IP fragments, and short/malformed
/// frames. Length-checked at every step and allocation-free, so a truncated or
/// hostile frame yields `None` rather than an out-of-bounds read.
fn parse_ipv4_l4(frame: &[u8]) -> Option<L4Packet<'_>> {
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
        payload: if proto == IPPROTO_UDP { &l4[8..] } else { &[] },
    })
}

/// Whether `pkt` opens a new connection: a bare TCP SYN (SYN set, ACK clear).
/// One definition for both legs — the inbound gate drops a new connection to an
/// undeclared port, the egress leg notices one to the legacy host address — so
/// "a connection" means the same thing in each, once per connection rather than
/// once per frame it carries.
fn opens_connection(pkt: &L4Packet<'_>) -> bool {
    pkt.proto == IPPROTO_TCP && pkt.tcp_flags & 0x02 != 0 && pkt.tcp_flags & 0x10 == 0
}

/// Returns `Some((dst_port, src))` iff `frame` is a bare TCP SYN (SYN set, ACK
/// clear) to a port not in `allowed` — the one TCP case the ingress gate drops.
/// `None` (pass) for non-TCP, declared ports, and any ACK-set segment (SYN-ACK,
/// established, egress return).
fn blocked_syn(frame: &[u8], allowed: &HashSet<u16>) -> Option<(u16, SocketAddrV4)> {
    let pkt = parse_ipv4_l4(frame)?;
    if !opens_connection(&pkt) || allowed.contains(&pkt.dst.port()) {
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
    fn record_egress(&self, pkt: &L4Packet<'_>) {
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
    fn allows_ingress(&self, pkt: &L4Packet<'_>) -> bool {
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
        // A resolver answer for one of the box's allowed names admits its
        // addresses for the answer's window (NET-066, NET-067). Read after the
        // inbound gate, so only an answer to the box's own lookup counts.
        if let Some(gate) = &gate
            && let Some(egress) = &gate.egress
        {
            egress.observe_answer(&frame[..n]);
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
        let gate =
            IngressGate::for_session("100.64.0.9".into(), Some(&ingress), SwitchSubnet::default());
        assert!(gate.allowed.contains(&80)); // TCP internal port
        assert!(!gate.allowed.contains(&53)); // the UDP mapping is not a TCP port
        assert!(!gate.allowed.contains(&18080)); // external port is not the listener
        assert!(gate.udp_allowed.contains(&53)); // UDP internal port
        assert!(!gate.udp_allowed.contains(&80)); // the TCP mapping is not a UDP port
        // A no-ingress own-IP session denies every new inbound connection/datagram.
        let empty = IngressGate::for_session("x".into(), None, SwitchSubnet::default());
        assert!(empty.allowed.is_empty() && empty.udp_allowed.is_empty());
    }

    /// A `MakeWriter` accumulating everything written into a shared buffer, so a
    /// test can assert on the structured fields a `tracing` event emitted.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A frame the box sends *out*: [`tcp_frame`]'s shape with the destination
    /// address rewritten, which is what the egress leg reads.
    fn egress_tcp_frame(dst: Ipv4Addr, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut f = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, flags, SRC, dst_port);
        f[ETH_HDR + 16..ETH_HDR + 20].copy_from_slice(&dst.octets());
        f
    }

    /// One frame as the relay writes it to the switch: a 2-byte LE length prefix
    /// followed by the frame, unaltered.
    fn framed(frame: &[u8]) -> Vec<u8> {
        let mut out = (frame.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(frame);
        out
    }

    /// NET-004. A box's connection to the literal host address still reaches the
    /// switch byte-for-byte — the literal *is* the address `host.min.internal`
    /// answers a box on the switch, so it routes as the name with nothing
    /// rewritten — and it is announced once per connection, naming the box and the
    /// name to use instead. Frames to anywhere else are silent, and the egress
    /// leg's UDP bookkeeping is untouched.
    #[tokio::test]
    async fn legacy_host_literal_routes_with_deprecation() {
        let subnet = SwitchSubnet::default();
        // The literal NET-004 names, and what the name answers on the switch.
        assert_eq!(subnet.host_alias(), Ipv4Addr::new(100, 64, 255, 254));
        assert_eq!(
            subnet.host_alias(),
            crate::net::policy::host_reach_address(crate::net::policy::HostReach::Switch, subnet)
        );

        let gate = IngressGate::for_session(SRC.to_string(), None, subnet);
        let watch = EgressWatch::for_gate(&gate);

        // What the box sends: a connection to the literal, a segment of that same
        // connection, a connection elsewhere, and a UDP datagram.
        let resolver = Ipv4Addr::new(1, 1, 1, 1);
        let outbound = [
            egress_tcp_frame(subnet.host_alias(), 8080, SYN),
            egress_tcp_frame(subnet.host_alias(), 8080, ACK),
            egress_tcp_frame(Ipv4Addr::new(93, 184, 216, 34), 443, SYN),
            udp_frame(SRC, 40000, resolver, 53),
        ];

        // A datagram socketpair stands in for the tap: frame-atomic reads, as a
        // tap device gives. Everything is queued before the relay runs, and
        // closing the box side ends it once the queue is drained.
        let (box_side, tap_side) = std::os::unix::net::UnixDatagram::pair().unwrap();
        tap_side.set_nonblocking(true).unwrap();
        // SAFETY: `into_raw_fd` yields a live, owned fd; `File` takes it
        // exclusively and closes it on drop.
        let tap_file = unsafe { std::fs::File::from_raw_fd(tap_side.into_raw_fd()) };
        let tap = Arc::new(AsyncFd::new(tap_file).unwrap());
        for frame in &outbound {
            box_side.send(frame).unwrap();
        }

        let (switch_side, mut switch_rx) = tokio::io::duplex(64 * 1024);
        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let expected: Vec<u8> = outbound.iter().flat_map(|f| framed(f)).collect();
        let mut relayed = vec![0u8; expected.len()];
        {
            // Both futures run in this task, so the relay sees the thread-local
            // subscriber. The relay only ever ends on a tap EOF, which a datagram
            // socketpair does not deliver, so the read is what finishes here: it
            // completes the moment every frame is through.
            let _guard = tracing::subscriber::set_default(subscriber);
            tokio::select! {
                ended = relay_tap_to_switch(tap, switch_side, Some(watch.clone())) =>
                    panic!("the relay ended before the frames were through: {ended:?}"),
                read = switch_rx.read_exact(&mut relayed) => read.unwrap(),
            };
        }

        // Every frame reached the switch, in order and unaltered: the literal
        // still works.
        assert_eq!(relayed, expected);

        // One notice, for the connection and not for its second segment, naming
        // the box and the name it should have resolved.
        let logged = capture.contents();
        let notices = logged.matches("deprecated literal host address").count();
        assert_eq!(notices, 1, "one notice per connection, got: {logged}");
        assert!(
            logged.contains(r#"name="host.min.internal""#),
            "the notice must name the name to use, got: {logged}"
        );
        assert!(
            logged.contains(&format!(r#"session_id="{SRC}""#)),
            "the notice must name the box, got: {logged}"
        );
        assert!(
            logged.contains("literal=")
                && logged.contains(&subnet.host_alias().to_string())
                && logged.contains("port=8080"),
            "the notice must name what was dialled, got: {logged}"
        );

        // The egress leg still records outbound UDP, so the reply is admitted.
        let reply = udp_frame(resolver, 53, SRC, 40000);
        assert!(
            watch
                .conntrack
                .allows_ingress(&parse_ipv4_l4(&reply).unwrap())
        );
    }

    /// Builds an Ethernet II + IPv4 + UDP frame for the conntrack tests.
    fn udp_frame(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        udp_datagram(src_ip, src_port, dst_ip, dst_port, &[])
    }

    /// [`udp_frame`] carrying `payload` as the datagram's body.
    fn udp_datagram(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len() as u16;
        let mut f = Vec::new();
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.push(0x45); // IPv4, IHL 5
        f.push(0x00);
        f.extend_from_slice(&(20 + udp_len).to_be_bytes()); // total length
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(IPPROTO_UDP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum
        f.extend_from_slice(&src_ip.octets());
        f.extend_from_slice(&dst_ip.octets());
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes()); // UDP length
        f.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum
        f.extend_from_slice(payload);
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
        let query = udp_frame(LEASE, 40000, Ipv4Addr::new(1, 1, 1, 1), 53);
        let egress = parse_ipv4_l4(&query).unwrap();
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
        let gate =
            IngressGate::for_session(LEASE.to_string(), Some(&ingress), SwitchSubnet::default());
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

    // ---- egress gate (NET-062, NET-063, NET-064, NET-084) ----

    use sessions::core::net_verdict::Endpoint;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const OUTSIDE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// An Ethernet II + IPv4 + TCP SYN from `src` to `dst:dst_port`: a box
    /// opening a connection.
    fn egress_syn(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let mut f = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, src, dst_port);
        f[ETH_HDR + 16..ETH_HDR + 20].copy_from_slice(&dst.octets());
        f
    }

    /// An Ethernet/IPv4 ARP request from `sender` for `target`.
    fn arp_request(sender: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // broadcast dst MAC
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // eth/ipv4 request
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // sender MAC
        f.extend_from_slice(&sender.octets());
        f.extend_from_slice(&[0u8; 6]); // target MAC (unknown)
        f.extend_from_slice(&target.octets());
        f
    }

    fn allow_only(
        subnets: &[&str],
        protocols: Option<Vec<sessions::IpProto>>,
    ) -> sessions::EgressPolicy {
        sessions::EgressPolicy {
            allow_subnets: Some(subnets.iter().map(ToString::to_string).collect()),
            allow_dns_hosts: None,
            allow_protocols: protocols,
            deny_subnets: None,
        }
    }

    /// The gate for a box named `web` leased [`LEASE`], resolving at the
    /// gateway, under `policy` (`None` = no egress section = allow-all).
    fn egress_gate(policy: Option<sessions::EgressPolicy>) -> Arc<EgressGate> {
        let resolver = Endpoint {
            ip: GATEWAY,
            port: 53,
        };
        Arc::new(EgressGate::for_box(
            "web".into(),
            EgressRules::for_box(LEASE, policy.as_ref(), Some(resolver)),
        ))
    }

    /// Runs the real relay with an OS pipe standing in for the tap: a frame
    /// written to the returned writer is read by the `tap → switch` leg, and
    /// whatever that leg forwards arrives length-framed on the returned stream.
    /// A pipe is a byte stream, not frame-atomic like a tap, so callers feed
    /// one frame at a time and settle it before the next.
    fn relay_over_pipe(
        gate: Arc<EgressGate>,
    ) -> (SwitchRelay, std::io::PipeWriter, tokio::io::DuplexStream) {
        let (reader, writer) = std::io::pipe().unwrap();
        let (ours, theirs) = tokio::io::duplex(4096);
        let (rx, tx) = tokio::io::split(theirs);
        let ingress = IngressGate::for_session(LEASE.to_string(), None, SwitchSubnet::default())
            .with_egress(gate);
        let relay = spawn_relay(OwnedFd::from(reader), rx, tx, Some(ingress)).unwrap();
        (relay, writer, ours)
    }

    /// Reads one length-framed frame from the switch side.
    async fn next_frame(switch: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut len = [0u8; 2];
        switch.read_exact(&mut len).await.unwrap();
        let mut frame = vec![0u8; u16::from_le_bytes(len) as usize];
        switch.read_exact(&mut frame).await.unwrap();
        frame
    }

    /// Asserts the switch side sees nothing for a while.
    async fn assert_switch_quiet(switch: &mut tokio::io::DuplexStream) {
        let mut buf = [0u8; 64];
        let quiet = tokio::time::timeout(Duration::from_millis(300), switch.read(&mut buf)).await;
        assert!(
            quiet.is_err(),
            "the switch must see nothing for a dropped frame"
        );
    }

    /// NET-062: a connection to an undeclared destination is dropped, not
    /// reset. Nothing reaches the switch for it — not the SYN and nothing in
    /// its place — and the relay goes on serving allowed frames afterwards.
    /// The `tap → switch` leg holds no handle that writes to the tap, so no
    /// reset can be sent back down it either.
    #[tokio::test]
    async fn disallowed_egress_dropped_not_reset() {
        let gate = egress_gate(Some(allow_only(&["10.0.0.0/8"], None)));
        let (_relay, mut feed, mut switch) = relay_over_pipe(Arc::clone(&gate));

        feed.write_all(&egress_syn(LEASE, OUTSIDE, 443)).unwrap();
        assert_switch_quiet(&mut switch).await;

        let allowed = egress_syn(LEASE, Ipv4Addr::new(10, 1, 2, 3), 443);
        feed.write_all(&allowed).unwrap();
        assert_eq!(next_frame(&mut switch).await, allowed);

        let stats = gate.drop_stats();
        assert_eq!(stats.total(), 1);
        assert_eq!(stats.by_rule.get("allow_subnets"), Some(&1));
        assert_eq!(
            stats.last_destination,
            Some(SocketAddrV4::new(OUTSIDE, 443))
        );
    }

    /// NET-063: a connection the rules allow completes — the frame reaches the
    /// switch intact — and so does a lookup to the resolver carve-out.
    #[tokio::test]
    async fn allowed_egress_succeeds() {
        let gate = egress_gate(Some(allow_only(&["93.184.216.0/24"], None)));
        let (_relay, mut feed, mut switch) = relay_over_pipe(Arc::clone(&gate));

        let syn = egress_syn(LEASE, OUTSIDE, 443);
        feed.write_all(&syn).unwrap();
        assert_eq!(next_frame(&mut switch).await, syn);

        let dns = udp_frame(LEASE, 40000, GATEWAY, 53);
        feed.write_all(&dns).unwrap();
        assert_eq!(next_frame(&mut switch).await, dns);

        assert_eq!(gate.drop_stats().total(), 0);
    }

    /// NET-064: with only TCP allowed, every UDP datagram is dropped — a DNS
    /// query included — while TCP still passes.
    #[test]
    fn udp_dropped_when_only_tcp_allowed() {
        let gate = egress_gate(Some(allow_only(
            &["0.0.0.0/0"],
            Some(vec![sessions::IpProto::Tcp]),
        )));
        assert!(!gate.admit(&udp_frame(LEASE, 40000, OUTSIDE, 5000)));
        assert!(!gate.admit(&udp_frame(LEASE, 40000, GATEWAY, 53)));
        assert!(gate.admit(&egress_syn(LEASE, OUTSIDE, 443)));

        let stats = gate.drop_stats();
        assert_eq!(stats.by_rule.get("allow_protocols"), Some(&2));
        assert_eq!(stats.last_destination, Some(SocketAddrV4::new(GATEWAY, 53)));
    }

    /// NET-084: a frame whose source is not the box's lease never leaves the
    /// relay, whatever the rules allow — IPv4 and ARP alike — while the same
    /// frames from the lease do.
    #[tokio::test]
    async fn relay_rejects_non_lease_source() {
        let gate = egress_gate(None);
        let (_relay, mut feed, mut switch) = relay_over_pipe(Arc::clone(&gate));

        feed.write_all(&egress_syn(PEER, OUTSIDE, 443)).unwrap();
        assert_switch_quiet(&mut switch).await;
        feed.write_all(&arp_request(PEER, GATEWAY)).unwrap();
        assert_switch_quiet(&mut switch).await;

        let own = egress_syn(LEASE, OUTSIDE, 443);
        feed.write_all(&own).unwrap();
        assert_eq!(next_frame(&mut switch).await, own);
        let arp = arp_request(LEASE, GATEWAY);
        feed.write_all(&arp).unwrap();
        assert_eq!(next_frame(&mut switch).await, arp);

        assert_eq!(gate.drop_stats().by_rule.get("source-not-lease"), Some(&2));
    }

    /// The link layer admits only IPv4 and ARP: anything else is undeclared
    /// by construction, and a frame too short to classify is dropped too.
    #[test]
    fn egress_gate_admits_only_ipv4_and_arp_at_the_link_layer() {
        let gate = egress_gate(None);
        assert!(!gate.admit(&tcp_frame(0x86DD, IPPROTO_TCP, SYN, LEASE, 443)));
        assert!(!gate.admit(&[0u8; 10]));
        assert!(gate.admit(&arp_request(LEASE, GATEWAY)));

        let stats = gate.drop_stats();
        assert_eq!(stats.by_rule.get("ethertype"), Some(&1));
        assert_eq!(stats.by_rule.get("malformed"), Some(&1));
        assert_eq!(stats.last_destination, None);
    }

    /// NET-062's warning: a dropped connection appears once in the log — its
    /// retransmitted SYNs are counted but not re-logged inside the window —
    /// as one structured line carrying the session, the direction, the
    /// destination, the protocol and the rule. The window is per rule, so a
    /// drop by another rule in the same window is still logged.
    #[test]
    fn egress_drop_logged_rate_limited() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let gate = egress_gate(Some(allow_only(&["10.0.0.0/8"], None)));
        for _ in 0..3 {
            assert!(!gate.admit(&egress_syn(LEASE, OUTSIDE, 443)));
        }
        assert!(!gate.admit(&egress_syn(PEER, OUTSIDE, 443)));
        drop(guard);

        let log = buf.contents();
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("network policy violation"))
            .collect();
        assert_eq!(lines.len(), 2, "got:\n{log}");
        for field in [
            "WARN",
            "session_id=web",
            "direction=egress",
            "remote_addr=93.184.216.34:443",
            "proto=tcp",
            "rule_matched=\"allow_subnets\"",
        ] {
            assert!(lines[0].contains(field), "missing {field} in: {}", lines[0]);
        }
        assert!(lines[1].contains("rule_matched=\"source-not-lease\""));
        assert_eq!(gate.drop_stats().total(), 4);
    }

    // ---- DNS-pinned admission (NET-066, NET-067) ----

    const GITHUB: Ipv4Addr = Ipv4Addr::new(140, 82, 112, 3);
    const GITHUB_ALT: Ipv4Addr = Ipv4Addr::new(140, 82, 112, 4);
    const PAGES: Ipv4Addr = Ipv4Addr::new(185, 199, 108, 153);
    const METADATA: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
    const LAN: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    /// The port the box's lookup went out from.
    const QUERY_PORT: u16 = 40000;

    /// A resolver answer as it arrives on the `switch → tap` leg: from the
    /// gateway's port 53 to the port the box's lookup went out from.
    fn dns_answer_frame(question: &str, records: &[(u32, Ipv4Addr)]) -> Vec<u8> {
        udp_datagram(
            GATEWAY,
            53,
            LEASE,
            QUERY_PORT,
            &crate::net::dns::tests::dns_response(question, records),
        )
    }

    /// A box that allows `github.com` and nothing else by address, denying
    /// `deny` on top.
    fn github_only(deny: &[&str]) -> sessions::EgressPolicy {
        sessions::EgressPolicy {
            allow_subnets: Some(vec![]),
            allow_dns_hosts: Some(vec!["github.com".into()]),
            allow_protocols: None,
            deny_subnets: Some(deny.iter().map(ToString::to_string).collect()),
        }
    }

    /// [`egress_gate`] with the policy's name rules attached, on the default
    /// switch.
    fn pinning_gate(policy: sessions::EgressPolicy) -> Arc<EgressGate> {
        let subnet = SwitchSubnet::default();
        let resolver = Endpoint {
            ip: GATEWAY,
            port: 53,
        };
        Arc::new(
            EgressGate::for_box(
                "web".into(),
                EgressRules::for_box(LEASE, Some(&policy), Some(resolver)),
            )
            .with_dns_pinning(
                policy.allow_dns_hosts.clone().unwrap_or_default(),
                &[subnet.gateway(), subnet.host_alias(), subnet.daemon_ip()],
            ),
        )
    }

    /// NET-066. A box allowing `github.com` reaches the addresses the resolver
    /// answered for it, once the answer has come back through the real
    /// `switch → tap` leg, and nothing else; the pin lasts the answer's window
    /// and no longer. One debug line records the admission with the name, the
    /// addresses and the window.
    #[tokio::test]
    async fn dns_pinned_admission_window() {
        let gate = pinning_gate(github_only(&[]));
        let ingress = IngressGate::for_session(LEASE.to_string(), None, SwitchSubnet::default())
            .with_egress(Arc::clone(&gate));
        let watch = EgressWatch::for_gate(&ingress);

        // Before any lookup the name admits nothing: address rules alone decide.
        assert!(!gate.admit(&egress_syn(LEASE, GITHUB, 443)));
        // The box's lookup leaves through the resolver carve-out.
        assert!(watch.admit(&udp_frame(LEASE, QUERY_PORT, GATEWAY, 53)));

        // The answer comes back down the real relay leg, reaches the box
        // unaltered, and is read on the way.
        let (box_side, tap_side) = std::os::unix::net::UnixDatagram::pair().unwrap();
        box_side.set_nonblocking(true).unwrap();
        tap_side.set_nonblocking(true).unwrap();
        let box_side = tokio::net::UnixDatagram::from_std(box_side).unwrap();
        // SAFETY: `into_raw_fd` yields a live, owned fd; `File` takes it
        // exclusively and closes it on drop.
        let tap_file = unsafe { std::fs::File::from_raw_fd(tap_side.into_raw_fd()) };
        let tap = Arc::new(AsyncFd::new(tap_file).unwrap());
        let (mut switch_tx, switch_rx) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(relay_switch_to_tap(switch_rx, tap, Some(ingress)));

        let answer = dns_answer_frame("github.com", &[(60, GITHUB), (60, GITHUB_ALT)]);
        switch_tx.write_all(&framed(&answer)).await.unwrap();
        let mut delivered = vec![0u8; max_frame()];
        let n = tokio::time::timeout(Duration::from_secs(5), box_side.recv(&mut delivered))
            .await
            .expect("the answer reaches the box")
            .unwrap();
        assert_eq!(&delivered[..n], &answer[..]);
        drop(switch_tx);
        relay.await.unwrap().unwrap();

        // The answered addresses, and only those.
        assert!(gate.admit(&egress_syn(LEASE, GITHUB, 443)));
        assert!(gate.admit(&egress_syn(LEASE, GITHUB_ALT, 22)));
        assert!(!gate.admit(&egress_syn(LEASE, PAGES, 443)));
        let pinned = gate.pinned();
        assert_eq!(
            pinned.iter().map(|p| p.address).collect::<Vec<_>>(),
            vec![GITHUB, GITHUB_ALT]
        );
        assert!(pinned.iter().all(|p| p.name == "github.com"));
        assert!(pinned.iter().all(|p| p.answer == vec![GITHUB, GITHUB_ALT]));

        // The window: the answer's TTL, held between the bounds, from the
        // moment the answer was read.
        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let t0 = Instant::now();
        let gate = pinning_gate(github_only(&[]));
        gate.observe_answer_at(&dns_answer_frame("github.com", &[(60, GITHUB)]), t0);
        let syn = egress_syn(LEASE, GITHUB, 443);
        assert!(gate.admit_at(&syn, t0));
        assert!(gate.admit_at(&syn, t0 + Duration::from_secs(59)));
        assert!(!gate.admit_at(&syn, t0 + Duration::from_secs(60)));
        // A zero TTL still admits for the floor; a day's TTL only the ceiling.
        gate.observe_answer_at(&dns_answer_frame("github.com", &[(0, GITHUB_ALT)]), t0);
        let alt = egress_syn(LEASE, GITHUB_ALT, 443);
        assert!(gate.admit_at(
            &alt,
            t0 + crate::net::policy::ADMISSION_WINDOW_MIN - Duration::from_secs(1)
        ));
        assert!(!gate.admit_at(&alt, t0 + crate::net::policy::ADMISSION_WINDOW_MIN));
        gate.observe_answer_at(&dns_answer_frame("github.com", &[(86400, PAGES)]), t0);
        let pages = egress_syn(LEASE, PAGES, 443);
        assert!(gate.admit_at(
            &pages,
            t0 + crate::net::policy::ADMISSION_WINDOW_MAX - Duration::from_secs(1)
        ));
        assert!(!gate.admit_at(&pages, t0 + crate::net::policy::ADMISSION_WINDOW_MAX));
        // An answer for a name the box did not allow admits nothing.
        gate.observe_answer_at(&dns_answer_frame("evil.example", &[(60, OUTSIDE)]), t0);
        assert!(!gate.admit_at(&egress_syn(LEASE, OUTSIDE, 443), t0));
        drop(guard);

        let log = capture.contents();
        let admissions: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("admitted a resolved name's addresses"))
            .collect();
        assert_eq!(admissions.len(), 3, "got:\n{log}");
        for field in [
            "DEBUG",
            "session_id=web",
            "name=\"github.com\"",
            "addresses=[140.82.112.3]",
            "window_secs=60",
        ] {
            assert!(
                admissions[0].contains(field),
                "missing {field} in: {}",
                admissions[0]
            );
        }
        assert!(admissions[1].contains("window_secs=30"));
        assert!(admissions[2].contains("window_secs=300"));
    }

    /// A resolver answer for `github.com` whose addresses land in every
    /// denied range: the box's own deny, the metadata address, loopback, the
    /// gateway, a private network, plus one public address.
    fn mixed_answer() -> Vec<u8> {
        dns_answer_frame(
            "github.com",
            &[
                (60, GITHUB),
                (60, METADATA),
                (60, Ipv4Addr::LOCALHOST),
                (60, GATEWAY),
                (60, LAN),
                (60, PAGES),
            ],
        )
    }

    /// NET-067. An allowed name that resolves into the box's `deny_subnets`
    /// or the infrastructure deny set is refused: no connection to such an
    /// answer opens, while the same answer's public address is reached.
    #[test]
    fn denied_range_resolution_refused() {
        let gate = pinning_gate(github_only(&["140.82.112.0/24"]));
        gate.observe_answer(&mixed_answer());

        for refused in [GITHUB, METADATA, Ipv4Addr::LOCALHOST, GATEWAY, LAN] {
            assert!(
                !gate.admit(&egress_syn(LEASE, refused, 443)),
                "{refused} must be refused"
            );
        }
        assert!(gate.admit(&egress_syn(LEASE, PAGES, 443)));

        // Only the public address was ever pinned; the box's own deny is what
        // refused its address, the others were never declared.
        assert_eq!(
            gate.pinned().iter().map(|p| p.address).collect::<Vec<_>>(),
            vec![PAGES]
        );
        let stats = gate.drop_stats();
        assert_eq!(stats.by_rule.get("deny_subnets"), Some(&1));
        assert_eq!(stats.by_rule.get("allow_subnets"), Some(&4));

        // A private answer is admitted once the box declares that network.
        let lan_box = pinning_gate(sessions::EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into()]),
            ..github_only(&[])
        });
        lan_box.observe_answer(&dns_answer_frame(
            "github.com",
            &[(60, LAN), (60, METADATA)],
        ));
        assert_eq!(
            lan_box
                .pinned()
                .iter()
                .map(|p| p.address)
                .collect::<Vec<_>>(),
            vec![LAN]
        );
    }

    // ---- the box zone: sibling resolution and reach (NET-072, NET-073) ----

    /// The port the sibling box `api` declares, and one it does not.
    const API_PORT: u16 = 8080;
    const API_UNDECLARED_PORT: u16 = 9090;

    /// The sibling's ingress: one TCP mapping, so [`API_PORT`] is the only port
    /// it accepts a new connection on.
    fn api_ingress() -> sessions::IngressPolicy {
        sessions::IngressPolicy {
            port_mappings: vec![sessions::PortMapping {
                external_port: 18080,
                internal_port: API_PORT,
                proto: sessions::IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        }
    }

    /// The switch's box zone with both boxes on it: `web` (the source, leased
    /// [`LEASE`], declaring no ingress) and `api` (the target, leased [`PEER`]).
    fn box_zone() -> Arc<BoxZone> {
        let zone = Arc::new(BoxZone::default());
        zone.register("web", LEASE, None);
        zone.register("api", PEER, Some(&api_ingress()));
        zone
    }

    /// The `web` box's gate on a switch carrying `zone`, wired as
    /// `net::provider` wires it: the rules, the resolver carve-out, the box
    /// zone, and name pinning when the policy declares names.
    fn zoned_gate(policy: Option<sessions::EgressPolicy>, zone: &Arc<BoxZone>) -> Arc<EgressGate> {
        let subnet = SwitchSubnet::default();
        let resolver = Endpoint {
            ip: GATEWAY,
            port: 53,
        };
        let mut gate = EgressGate::for_box(
            "web".into(),
            EgressRules::for_box(LEASE, policy.as_ref(), Some(resolver)),
        )
        .with_box_zone(Arc::clone(zone));
        if let Some(hosts) = policy.as_ref().and_then(|p| p.allow_dns_hosts.clone()) {
            gate = gate.with_dns_pinning(
                hosts,
                &[subnet.gateway(), subnet.host_alias(), subnet.daemon_ip()],
            );
        }
        Arc::new(gate)
    }

    /// NET-072. A box resolves a sibling's box-zone name with no
    /// `egress.allow_dns_hosts` entry for it. The box here allows one name,
    /// `github.com`, and no address at all: the sibling's name is in neither its
    /// allow list nor its address rules, and it resolves regardless — the lookup
    /// leaves through the resolver Minimal owns for the box, the answer comes
    /// back down the ingress leg, and the zone is what answered it.
    ///
    /// Resolving is not reaching: an answer for a name the box did not allow
    /// pins nothing, so the sibling's address stands or falls on the two boxes'
    /// own rules (NET-073). A box with no name allow list at all — the deny-all
    /// default — resolves the sibling the same way.
    #[test]
    fn box_zone_resolution_needs_no_allow_entry() {
        let zone = box_zone();
        let sibling = "api.min.internal";
        let policy = github_only(&[]);
        assert!(!crate::net::dns::name_allowed(
            policy
                .allow_dns_hosts
                .as_deref()
                .expect("a name allow list"),
            sibling
        ));
        // The zone answers the name from the zone alone, with the sibling's
        // switch lease, however the asking box spells it.
        assert_eq!(zone.resolve(sibling), Some(PEER));
        assert_eq!(zone.resolve("API.min.internal."), Some(PEER));

        let gate = zoned_gate(Some(policy), &zone);
        let ingress = IngressGate::for_session(LEASE.to_string(), None, SwitchSubnet::default())
            .with_egress(Arc::clone(&gate));
        let watch = EgressWatch::for_gate(&ingress);

        // The lookup leaves through the carve-out, though the box declares no
        // destination, and its answer comes back: solicited, so the ingress gate
        // passes it to a box that declared no port.
        assert!(watch.admit(&udp_frame(LEASE, QUERY_PORT, GATEWAY, 53)));
        let answer = dns_answer_frame(sibling, &[(15, PEER)]);
        assert!(ingress.inbound_drop(&answer).is_none());

        // Resolution is all the name bought: nothing is pinned, and the
        // sibling's address is refused by this box's rules like any other.
        gate.observe_answer(&answer);
        assert!(gate.pinned().is_empty());
        assert!(!gate.admit(&egress_syn(LEASE, PEER, API_PORT)));

        // The deny-all default: no `allow_dns_hosts` at all, and the lookup
        // still leaves.
        let deny_all = zoned_gate(Some(allow_only(&[], None)), &zone);
        assert!(deny_all.admit(&udp_frame(LEASE, QUERY_PORT, GATEWAY, 53)));
        assert!(!deny_all.admit(&egress_syn(LEASE, PEER, API_PORT)));
    }

    /// NET-073. A connection to a sibling's box-zone address opens only when
    /// both sides' rules allow it: the source's egress gate decides it on the
    /// source's relay leg and the target's ingress gate on the target's, and
    /// either refusal is enough. Over the real relay, a declared address to a
    /// declared port reaches the target; the same address to a port the target
    /// did not declare reaches the switch and is refused there; and a box whose
    /// own rules refuse the address sends nothing the target could refuse.
    ///
    /// Each attempt is recorded as one debug line naming both boxes and the
    /// verdict from each side's rules, and a refused sibling is counted as a
    /// box-to-box refusal under the rule that refused it — an external
    /// destination refused by the same rule is not.
    #[tokio::test]
    async fn box_zone_connection_enforced_at_connect() {
        let zone = box_zone();
        let target = IngressGate::for_session(
            PEER.to_string(),
            Some(&api_ingress()),
            SwitchSubnet::default(),
        );
        let syn = egress_syn(LEASE, PEER, API_PORT);
        let undeclared = egress_syn(LEASE, PEER, API_UNDECLARED_PORT);

        // Both sides allow it: the SYN leaves the source's relay intact and the
        // target's ingress admits it.
        let allowed = zoned_gate(Some(allow_only(&["100.64.0.0/24"], None)), &zone);
        let (_relay, mut feed, mut switch) = relay_over_pipe(Arc::clone(&allowed));
        feed.write_all(&syn).unwrap();
        let delivered = next_frame(&mut switch).await;
        assert_eq!(delivered, syn);
        assert!(target.inbound_drop(&delivered).is_none());

        // The target's half alone refuses: the source declared the address, so
        // its gate admits the frame, and the target's ingress drops it.
        feed.write_all(&undeclared).unwrap();
        let delivered = next_frame(&mut switch).await;
        assert_eq!(delivered, undeclared);
        assert_eq!(
            target
                .inbound_drop(&delivered)
                .map(|(proto, port, _)| (proto, port)),
            Some((sessions::IpProto::Tcp, API_UNDECLARED_PORT))
        );
        assert_eq!(allowed.drop_stats().total(), 0);

        // The source's half alone refuses: a deny-all box's SYN to the very port
        // the sibling declared never reaches the switch, so the target never
        // sees the connection at all.
        let denied = zoned_gate(Some(allow_only(&[], None)), &zone);
        let (_denied_relay, mut denied_feed, mut denied_switch) =
            relay_over_pipe(Arc::clone(&denied));
        denied_feed.write_all(&syn).unwrap();
        assert_switch_quiet(&mut denied_switch).await;

        // The account of it. Fresh gates, so the counters start clean, and the
        // lines are emitted on this thread, where the capture is installed.
        let capture = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let allowed = zoned_gate(Some(allow_only(&["100.64.0.0/24"], None)), &zone);
        assert!(allowed.admit(&syn));
        assert!(allowed.admit(&undeclared));
        let denied = zoned_gate(Some(allow_only(&[], None)), &zone);
        assert!(!denied.admit(&syn));
        assert!(!denied.admit(&egress_syn(LEASE, OUTSIDE, 443)));
        drop(guard);

        // Both refusals were the same rule; only the one to a sibling is a
        // box-to-box refusal.
        let stats = denied.drop_stats();
        assert_eq!(stats.by_rule.get("allow_subnets"), Some(&2));
        assert_eq!(stats.box_zone_by_rule.get("allow_subnets"), Some(&1));

        let log = capture.contents();
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("box-zone connection"))
            .collect();
        assert_eq!(lines.len(), 3, "got:\n{log}");
        for field in [
            "DEBUG",
            "session_id=web",
            "source=web",
            "target=api",
            "remote_addr=100.64.0.5:8080",
            "proto=tcp",
            "egress=\"admit\"",
            "ingress=\"declared\"",
        ] {
            assert!(lines[0].contains(field), "missing {field} in: {}", lines[0]);
        }
        assert!(lines[1].contains("remote_addr=100.64.0.5:9090"));
        assert!(lines[1].contains("egress=\"admit\""));
        assert!(lines[1].contains("ingress=\"undeclared\""));
        assert!(lines[2].contains("egress=\"allow_subnets\""));
        assert!(lines[2].contains("ingress=\"declared\""));
    }

    /// NET-067's log: each answer refused as a denied range appears as one
    /// warning naming the box, the name, the answer and the range that
    /// refused it; admitted addresses are not warned about.
    #[test]
    fn denied_range_resolution_logged() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let gate = pinning_gate(github_only(&["140.82.112.0/24"]));
        gate.observe_answer(&mixed_answer());
        drop(guard);

        let log = buf.contents();
        let refusals: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("refused a resolved address in a denied range"))
            .collect();
        assert_eq!(refusals.len(), 5, "got:\n{log}");
        for (line, answer, rule) in [
            (refusals[0], GITHUB, "deny_subnets"),
            (refusals[1], METADATA, "infrastructure"),
            (refusals[2], Ipv4Addr::LOCALHOST, "infrastructure"),
            (refusals[3], GATEWAY, "infrastructure"),
            (refusals[4], LAN, "private-range"),
        ] {
            for field in [
                "WARN".to_string(),
                "session_id=web".to_string(),
                "name=\"github.com\"".to_string(),
                format!("answer={answer}"),
                format!("rule_matched=\"{rule}\""),
            ] {
                assert!(line.contains(&field), "missing {field} in: {line}");
            }
        }
        assert!(!log.contains(&format!("answer={PAGES}")), "got:\n{log}");
    }
}
