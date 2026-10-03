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
//! keeps the default-block posture of finding #2. Every relay — gated or not,
//! the daemon's own included — also carries the lease it was attached with,
//! and rejects any frame whose source is not it (NET-084).
//!
//! The ingress leg's *refusals* — an unpublished port's (NET-014) and a revoked
//! port's (NET-121) — are answered, not dropped: a bare TCP SYN to a port the
//! box does not publish is answered with a reset so the connecting peer fails
//! at once instead of timing out. That refusal covers **TCP** only (design
//! §7.1 line 248, v1): a UDP datagram has no connection to refuse, so it stays
//! a drop, and the UDP analogue of the reset is not asked for by anything this
//! module implements.
//!
//! The refusal carries both bounds a source-fed channel needs: the resets ride
//! a **bounded** channel ([`RESET_CHANNEL_CAPACITY`]) that this module's legs
//! feed and the switch-side writer drains, so no box's flood grows the
//! daemon's memory — the excess is dropped, never queued — and each source
//! draws from a per-window refusal budget ([`ResetBudget`]), so the flooder
//! degrades to the timeout the reset replaced while nobody else does, with one
//! audited line per source per window. The resets themselves are built only
//! from state the gate holds ([`SessionGate::refuse_tcp_segment`]): a bare SYN
//! is answered the way a kernel refuses a connection, and a connection the
//! gate ended is reset from the sequence pair it tracked — never from the
//! numbers an arriving segment claims, and always addressed to that segment's
//! source.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::dns_gate::DnsGate;
use super::policy::{Direction, PolicyWarnLimiter, Proto};
use super::{DEFAULT_MTU, PtaskLease, SwitchSubnet};
use sessions::core::egress::{
    self, DropReason, FrameSummary, FrameVerdict, IngressRules, ListenVerdict,
};

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
/// `fcntl` directly. `pub(crate)`: the DNS gate's tests also put their
/// box-end stand-in in polling mode.
pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
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

/// A running switch relay. Dropping it aborts both relay directions and both
/// reset writers, which closes the gvproxy connection and detaches the PTask
/// from the switch.
#[derive(Debug)]
#[must_use = "dropping the relay immediately detaches the PTask from the switch"]
pub struct SwitchRelay {
    tap_to_switch: JoinHandle<io::Result<()>>,
    switch_to_tap: JoinHandle<io::Result<()>>,
    reset_writer: Option<JoinHandle<io::Result<()>>>,
    box_reset_writer: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for SwitchRelay {
    fn drop(&mut self) {
        self.tap_to_switch.abort();
        self.switch_to_tap.abort();
        if let Some(reset_writer) = &self.reset_writer {
            reset_writer.abort();
        }
        if let Some(box_reset_writer) = &self.box_reset_writer {
            box_reset_writer.abort();
        }
    }
}

/// Attaches `tap_fd` to the gvproxy switch listening on `api_sock` (DM2, native
/// Linux) and starts relaying frames between them.
///
/// `gate` is the session's compiled network policy (see [`SessionGate`]):
/// `None` attaches ungated, which is the daemon's own relay — not a box, not a
/// session — and the netns proof's harness PTasks opt into via their declared
/// policies. `lease` is the relay's lease on the switch — the one source
/// address frames it forwards may carry (NET-084): a frame whose IPv4 source,
/// or ARP sender address, is anything else is rejected before it reaches the
/// switch, whatever the gate says. A session relay passes the box's lease; the
/// daemon's own relay passes its own address. `subnet` is the switch's subnet —
/// the subnet gvproxy was configured with — from which a gated relay derives
/// the resolver address its egress carve-out is keyed to (NET-079) and the
/// deprecated host-alias literal it notices (NET-004); the daemon relay ignores
/// it.
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
    gate: Option<Arc<SessionGate>>,
    lease: Ipv4Addr,
    subnet: SwitchSubnet,
) -> io::Result<SwitchRelay> {
    let mut sock = UnixStream::connect(api_sock).await?;
    sock.write_all(CONNECT_REQUEST).await?;
    let (sock_rx, sock_tx) = sock.into_split();
    spawn_relay(tap_fd, sock_rx, sock_tx, gate, lease, subnet)
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
    gate: Option<Arc<SessionGate>>,
    lease: Ipv4Addr,
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
    spawn_relay(tap_fd, sock_rx, sock_tx, gate, lease, subnet)
}

/// Wires `tap_fd` into the bidirectional frame relay against an already-connected,
/// `/connect`-upgraded switch stream split into `sock_rx`/`sock_tx`.
///
/// `subnet` is the switch this relay is attached to — the subnet the switch was
/// configured with — and a gated relay derives NET-004's deprecated host-alias
/// literal from it, so the notice always watches the address this switch (and
/// no other) NATs to the host's loopback. `lease` is the relay's lease on that
/// switch, the one source its frames may carry (NET-084), checked on the egress
/// leg whatever the gate. Shared by the DM2 UDS path ([`attach_to_switch`]) and
/// the DM1/3/4 vsock path ([`attach_to_switch_vsock`]); the relay loops are
/// transport-agnostic (`AsyncRead`/`AsyncWrite`), so only the connect step
/// differs.
fn spawn_relay<R, W>(
    tap_fd: OwnedFd,
    sock_rx: R,
    sock_tx: W,
    gate: Option<Arc<SessionGate>>,
    lease: Ipv4Addr,
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
    // rate limiter, whose keys keep every rule's line independent. Its reset
    // channels' receiving halves leave the gate here — once, whoever else
    // already holds a clone: one toward the switch, one toward the box.
    let resets_rx = gate.as_ref().and_then(|gate| gate.take_resets());
    let box_resets_rx = gate.as_ref().and_then(|gate| gate.take_box_resets());
    // NET-073: a session relay publishes its gate under its lease, so a
    // sibling's relay can consult the box's own egress rules at connect time.
    // The daemon's own relay (`gate` is `None`) is not a box and publishes
    // nothing.
    if let Some(gate) = &gate {
        register_live_gate(lease, gate);
    }
    // NET-004: a session relay tells its box — rate-limited — that frames to the
    // literal host-alias address are deprecated. The daemon's own relay (`gate`
    // is `None`) is not a box and gets no notice.
    let legacy_notice = gate
        .as_deref()
        .map(|gate| LegacyHostNotice::for_gate(gate, subnet));
    // NET-084: every relay rejects a frame whose source is not its lease — a
    // session relay's lease is the box's, the daemon relay's its own address —
    // and says so through the notice below.
    let reject = ForeignSourceReject::for_relay(gate.as_deref(), lease);
    // The switch's write half is shared with the reset writer below: the
    // egress leg's forwarded frames and the gate's synthesized resets both
    // leave by it, one brief lock per write.
    let sock_tx = Arc::new(tokio::sync::Mutex::new(sock_tx));
    let tap_to_switch = tokio::spawn(relay_tap_to_switch(
        Arc::clone(&tap),
        Arc::clone(&sock_tx),
        gate.clone(),
        legacy_notice,
        reject,
    ));
    // The gate's resets — a refused SYN's (NET-014), a revoked port's and a
    // revocation's terminations (NET-121) — are written to the switch as they
    // arrive. The task ends when the gate's last holder drops, and the relay
    // aborts it on the way out.
    let reset_writer =
        resets_rx.map(|resets_rx| tokio::spawn(write_resets(resets_rx, Arc::clone(&sock_tx))));
    // The gate's box-directed resets — a revocation ending the box's own half
    // of a held connection (NET-121) — are written into the tap instead, raw
    // the way the ingress leg delivers frames to the box (only the switch side
    // is framed). The tap is written through the same `AsyncFd` readiness
    // guard; a frame-sized `write` is what both legs already issue, so this
    // writer needs no lock of its own against them.
    let box_reset_writer = box_resets_rx
        .map(|box_resets_rx| tokio::spawn(write_box_resets(box_resets_rx, Arc::clone(&tap))));
    let switch_to_tap = tokio::spawn(relay_switch_to_tap(sock_rx, tap, gate));
    Ok(SwitchRelay {
        tap_to_switch,
        switch_to_tap,
        reset_writer,
        box_reset_writer,
    })
}

/// Writes the gate's synthesized resets to the switch, framed the way every
/// frame leaves a relay: 2-byte little-endian length, then the frame. Ends
/// when the gate's last holder drops its reset sender. The channel is bounded
/// ([`RESET_CHANNEL_CAPACITY`]): the writer drains it at the switch's own
/// pace, and the gate — never this task — decides what a full bound costs (a
/// dropped reset, never a queued one).
async fn write_resets<W>(
    mut resets: tokio::sync::mpsc::Receiver<Vec<u8>>,
    sock: Arc<tokio::sync::Mutex<W>>,
) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    while let Some(frame) = resets.recv().await {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(&frame);
        sock.lock().await.write_all(&framed).await?;
    }
    Ok(())
}

/// Writes the gate's box-directed resets into the tap, raw — the box reads
/// Ethernet frames off its tap, and only the switch side of the relay is
/// length-framed. Ends when the gate's last holder drops its sender, with the
/// switch-side writer's own bounds.
async fn write_box_resets(
    mut resets: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tap: Arc<AsyncFd<std::fs::File>>,
) -> io::Result<()> {
    while let Some(frame) = resets.recv().await {
        write_tap_frame(&tap, &frame).await?;
    }
    Ok(())
}

/// tap → switch: read a raw Ethernet frame, reject it if its source is not the
/// lease the relay was attached with (NET-084 — the daemon's own relay
/// included), apply the session's egress verdict to what remains (NET-062 —
/// dropped frames never reach the switch and are not answered, save the one
/// drop a DNS pin lifts, NET-066), answer the box's own AAAA/HTTPS/SVCB
/// lookups (NET-136), record the outbound UDP flow of every datagram this leg
/// actually forwards (so its reply is allowed back in — finding #2, UDP; only
/// a declared, forwarded datagram opens a window), notice frames to the
/// deprecated literal host address (NET-004), prepend its 2-byte LE length,
/// and write the framed packet to the control socket. `gate` is `None` for the
/// daemon relay, which is not a box and forwards its own frames unchecked.
#[expect(
    clippy::indexing_slicing,
    reason = "every `buf[..n]` is bounded by `n`, the count this loop's own read of `buf` returned"
)]
async fn relay_tap_to_switch<W>(
    tap: Arc<AsyncFd<std::fs::File>>,
    sock: Arc<AsyncMutex<W>>,
    gate: Option<Arc<SessionGate>>,
    notice: Option<LegacyHostNotice>,
    reject: ForeignSourceReject,
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
        // NET-084: a frame whose source is not the lease this relay was
        // attached with never reaches the shared switch — a box's relay or
        // the daemon's own, whose lease is its own address. The source an
        // IPv4 frame carries is its IPv4 source address; an ARP frame's is
        // its sender protocol address, read whatever protocol type the
        // frame claims for it, so a foreign address cannot be announced by
        // address resolution either. A rejected frame is simply
        // not written on — a drop is not a reset — and opens no conntrack
        // window (the record below only sees frames past this check); the
        // rejection says so once per lease per minute, naming the session,
        // the lease and the source the frame carried.
        let summary = egress::summarize(&buf[..n]);
        if let Some(reason) = egress::foreign_source(&summary, reject.lease.octets()) {
            reject.emit(&reason);
            continue;
        }
        // Egress enforcement (NET-062, NET-063, NET-064): every frame is
        // decided against the box's declared policy before it reaches the
        // shared switch. A dropped frame is simply not written on — nothing is
        // sent back toward the box either, a drop is not a reset — and the drop
        // says so once per box per rule per minute (R2.7).
        if let Some(gate) = &gate
            && let FrameVerdict::Drop(reason) = egress::verdict(&summary, &gate.egress)
        {
            // NET-066, with design §5.3's conntrack-aware retention: an
            // address the box resolved from a name its policy allowed is
            // admitted for the DNS gate's window, and a flow that pin
            // established keeps its destination past the window until the
            // flow ends — together those are the one drop a pin lifts.
            // The resolution-time intersection (NET-067, on the ingress
            // leg) already subtracted the box's denies and the
            // infrastructure deny set from those addresses, so a pin
            // cannot smuggle a refused range past this drop. Denied
            // ranges and the protocol rules keep governing pinned
            // addresses too.
            let pinned = matches!(reason, DropReason::UndeclaredSubnet { .. })
                && reason.destination().is_some_and(|dst| {
                    // The flow's identity is the frame's own ports, so
                    // this parse is spent on the pin's path alone: a
                    // frame with no L4 header to read has no flow to
                    // retain and only the window can admit it.
                    let pkt = parse_ipv4_l4(&buf[..n]);
                    gate.dns.admits_flow(dst, pkt.as_ref(), Instant::now())
                });
            if !pinned {
                gate.limiter.warn(
                    &gate.label,
                    Direction::Egress,
                    drop_remote(&summary),
                    drop_transport(&reason),
                    None,
                    reason.rule(),
                );
                continue;
            }
        }
        // The frame's UDP addressing, parsed once for both of this leg's UDP
        // consumers below: the DNS gate's NODATA interception and the conntrack
        // window. A frame that is not IPv4+UDP — most of a box's traffic —
        // reaches neither, and costs no second parse here.
        if let Some(gate) = &gate {
            let udp = parse_ipv4_l4(&buf[..n]).filter(|pkt| pkt.proto == IPPROTO_UDP);
            // NET-136: the box's AAAA, HTTPS and SVCB lookups toward this
            // switch's resolver are answered NODATA by the relay itself and
            // never reach the switch. The box gets its empty answer — its own
            // query id, so its resolver stack matches the reply — and nothing
            // upstream can answer an empty-records lookup differently.
            if let Some(pkt) = &udp
                && let Some(payload) = udp_payload(&buf[..n], pkt)
                && let Some(reply) = gate.dns.intercept_query(&pkt.dst, payload)
            {
                let frame = udp_reply_frame(&buf[..n], pkt, &reply);
                write_tap_frame(&tap, &frame).await?;
                continue;
            }
            // Track outbound UDP so the inbound gate recognizes its reply as
            // solicited — after the interception, so a datagram this leg
            // answered itself opens no window: it never reached the resolver,
            // so nothing replies to it, and a window keyed to it would be dead
            // state whose only effect is to let an unsolicited inbound
            // datagram pass as solicited for the TTL. A frame the verdict did
            // not admit never gets here either: an undeclared datagram must
            // not punch a hole in the inbound gate.
            if let Some(pkt) = &udp {
                gate.conntrack.record_egress(pkt);
            }
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
        sock.lock().await.write_all(&framed).await?;
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
        // Unreachable on this relay, whose NET-084 check runs before the
        // verdict and rejects a foreign source first; a foreign-source drop
        // is not about a transport to name.
        DropReason::ForeignSource { .. } => Proto::None,
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
/// IPv4 protocol number for TCP. `pub(crate)`: the DNS gate's tests build
/// their own flow identities with it.
pub(crate) const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP. `pub(crate)`: the DNS gate's tests build
/// their own UDP frames with it.
pub(crate) const IPPROTO_UDP: u8 = 17;

/// The zone record name a box can resolve the host by (NET-003) — the name the
/// deprecation notice tells a box to use instead of the literal. `pub(crate)`:
/// the DNS gate answers for the same row, whose reply carries the switch's
/// NAT'd host alias, and reads the name here rather than a second spelling
/// of it.
pub(crate) const HOST_MIN_INTERNAL: &str = "host.min.internal";

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

/// NET-084's rejection notice on the egress relay leg: when a relay's tap
/// emits a frame whose source is not the lease the relay was attached with,
/// the relay rejects it — the frame never reaches the switch — and says so,
/// once per lease per minute, naming the session, the lease, and the source
/// the rejected frame carried.
struct ForeignSourceReject {
    /// The lease the relay was attached with: the one source address its
    /// frames may carry, and what the rejection line names as the lease.
    lease: Ipv4Addr,
    /// The relay's identity in the log — the gate's label (the box's lease,
    /// for a session relay) or the lease itself for the daemon's own relay,
    /// which is not a session.
    label: String,
    /// The limiter shared with the relay's other warns: the gate's when there
    /// is one, so every rule's line on one relay keeps its own interval; a
    /// fresh one for the daemon's own relay, which has no gate to share.
    limiter: Arc<PolicyWarnLimiter>,
}

impl ForeignSourceReject {
    /// Builds the notice for a relay attached with `lease`, taking its log
    /// identity and limiter from the gate when it carries one.
    fn for_relay(gate: Option<&SessionGate>, lease: Ipv4Addr) -> Self {
        Self {
            label: gate.map_or_else(|| lease.to_string(), |gate| gate.label.clone()),
            lease,
            limiter: gate.map_or_else(
                || Arc::new(PolicyWarnLimiter::new()),
                |gate| Arc::clone(&gate.limiter),
            ),
        }
    }

    /// Logs the rejection if the rate limiter allows. Returns whether it
    /// fired. The reason carries the source the rejected frame carried —
    /// `foreign_source` yields only [`DropReason::ForeignSource`], and that
    /// reason always names it.
    fn emit(&self, reason: &egress::DropReason) -> bool {
        let DropReason::ForeignSource { src, .. } = reason else {
            return false;
        };
        let source = Ipv4Addr::from(*src);
        if !self
            .limiter
            .should_warn_at(&self.label, reason.rule(), Instant::now())
        {
            return false;
        }
        tracing::warn!(
            // A `&str` field renders quoted, the way `PolicyWarnLimiter`'s
            // `session_id` does; `Display` would drop the quotes.
            session_id = self.label.as_str(),
            lease = %self.lease,
            source = %source,
            rule_matched = reason.rule(),
            "rejected egress frame whose source is not the lease"
        );
        true
    }
}

/// The live gate of every box this daemon relays, keyed by its lease (NET-073).
///
/// The connect-time half of the box-zone conjunction asks, for a bare SYN
/// arriving at a box's relay, who the *source* is and what the source's own
/// egress rules say — which only the source's own relay knows. Each session
/// relay publishes its gate here at spawn ([`register_live_gate`]); a target's
/// relay looks the source up through [`live_gate`]. Membership is the
/// sibling-box classification itself: only session relays register, so the
/// switch's own traffic, the daemon's relay (whose gate is `None`), and a
/// resolver are never found, and a source that is not a box on this daemon's
/// switch keeps today's target-ingress-only behavior.
///
/// Values are [`Weak`]: a gate lives exactly as long as its relay, so a dead
/// relay's entry answers nothing and needs no deregistration — leases are never
/// reused. The table still sweeps its dead entries past a threshold, the
/// [`UdpConntrack`] pattern, so it never grows without bound. Per-process:
/// boxes behind a *different* daemon are not seen from here, and their
/// connections decide on the target's ingress alone.
static LIVE_GATES: LazyLock<Mutex<HashMap<Ipv4Addr, Weak<SessionGate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Sweep dead entries once the table crosses this many leases — the
/// [`UdpConntrack`] bound, sized for the same burst-of-attach picture.
const LIVE_GATES_SWEEP_AT: usize = 4096;

/// Publishes a session relay's gate under its lease in [`LIVE_GATES`], sweeping
/// dead entries first when the table is at its threshold.
fn register_live_gate(lease: Ipv4Addr, gate: &Arc<SessionGate>) {
    let mut gates = LIVE_GATES.lock().expect("live gate table poisoned");
    if gates.len() >= LIVE_GATES_SWEEP_AT {
        gates.retain(|_, weak| weak.strong_count() > 0);
    }
    gates.insert(lease, Arc::downgrade(gate));
}

/// The live gate of the box `addr` belongs to, while its relay lives — `None`
/// for every other source, whatever the table once held. Read by the
/// listener watcher's launch path, which hands the gate its box's
/// publications through (NET-016).
pub(crate) fn live_gate(addr: Ipv4Addr) -> Option<Arc<SessionGate>> {
    LIVE_GATES
        .lock()
        .expect("live gate table poisoned")
        .get(&addr)
        .and_then(Weak::upgrade)
}

/// A PTask's compiled network policy, applied at the relay bridge — gvproxy
/// v0.8.9 enforces nothing per client, so both directions of the session's
/// traffic are decided here:
///
/// - **Egress** (`tap → switch`) — every frame is decided by the pure verdict
///   in `sessions::core::egress` against the box's compiled
///   [`EgressRules`]: what the box did not declare is dropped, without
///   answering, and says so once per rule per minute (NET-062, NET-063,
///   NET-064) — and every frame whose source is not the box's lease is
///   rejected before the rules are consulted at all (NET-084). One drop has
///   one exception: an address the box resolved from a name its
///   `allow_dns_hosts` declared, held in the DNS gate's admission table for
///   its window (NET-066) — and the box's AAAA, HTTPS and SVCB lookups
///   toward the switch's resolver are answered NODATA here, never written
///   on (NET-136).
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
/// relays minimald runs. A DNS reply from this switch's own resolver is also
/// observed on the ingress leg — the one traffic class that can grow what
/// the box may reach (NET-066/NET-067, [`DnsGate`]).
pub struct SessionGate {
    /// TCP destination ports the target accepts new inbound connections on — the
    /// *internal* ports of its TCP `port_mappings` (what the sandbox listens on,
    /// and what both a peer session and the host-publish forwarder dial). An empty
    /// set denies every inbound SYN (the own-IP default-block posture).
    allowed: HashSet<u16>,
    /// TCP ports the box's *processes* published by listening on them
    /// (NET-016): admitted beside the declared ones for as long as a
    /// listener holds the port, withdrawn — connections and all — when it
    /// closes (NET-017). Tracked apart from `allowed` because the two
    /// halves have different owners: a declared port's admission is the
    /// declaration's (held until the box stops, NET-121), and a withdrawal
    /// never touches it (NET-081's sub-requirement), while this set is
    /// the listener watcher's alone. Interior-mutable because the watcher
    /// publishes while the gate is shared between both relay legs.
    listen_published: Mutex<HashSet<u16>>,
    /// UDP destination ports the target accepts new inbound datagrams on (the
    /// internal ports of its UDP `port_mappings`). Inbound UDP to any other port
    /// passes only if it matches a live outbound flow in `conntrack`.
    udp_allowed: HashSet<u16>,
    /// TCP internal ports whose ingress has been revoked after publish
    /// (NET-121): the gate admits them no longer — every packet still touching
    /// one is refused ([`Self::refuse_tcp_segment`]) and never forwarded, so
    /// the connections the revoked forwarder held end at the gate instead of
    /// riding on past it. Interior-mutable because revocation arrives after
    /// the gate is shared.
    revoked: Mutex<HashSet<u16>>,
    /// The last client→box TCP packet of every admitted inbound flow, keyed by
    /// `(source ip, source port, destination port)` — the record a revocation
    /// resets the flow from: the packet's own ack/seq pair is an in-window
    /// sequence for the connection it belongs to, so the reset the revocation
    /// sends is read by a quiet peer at once. Swept like [`UdpConntrack`].
    inbound_flows: Mutex<HashMap<InboundFlowKey, (Instant, InboundFlowTail)>>,
    /// The flows a revocation has already terminated, each with the tail it was
    /// reset from, kept for [`TERMINATED_FLOW_TTL`] so a segment the ended
    /// connection still sends is answered from the state the gate **tracked** —
    /// the self-healing second reset — and never from numbers the arriving
    /// segment carries, which a spoofing peer chooses (see
    /// [`SessionGate::refuse_tcp_segment`]). Swept like [`UdpConntrack`].
    terminated_flows: Mutex<HashMap<InboundFlowKey, (Instant, InboundFlowTail)>>,
    /// The per-source budget the refusals are drawn against: a reset is
    /// synthesized for a source only while it has window budget left, so a
    /// box flooding SYNs at this box's ports cannot spend the daemon's memory
    /// or the reset channel on its own refusals ([`ResetBudget`]).
    reset_budget: ResetBudget,
    /// The resets this gate's legs synthesize — a refused SYN's (NET-014), a
    /// revoked port's, a revocation's terminations — handed to the egress leg
    /// and written to the switch, the only leg that holds the switch's write
    /// half. **Bounded** ([`RESET_CHANNEL_CAPACITY`]): the channel is fed by
    /// frames other boxes originate, so an unbounded one would let a single
    /// box grow the daemon's memory at will; the per-source budget
    /// ([`ResetBudget`]) is what keeps a well-behaved source's refusals inside
    /// it, and a send past the bound is dropped — the flooder degrades to a
    /// timeout, nobody else does.
    resets: mpsc::Sender<Vec<u8>>,
    /// The receiving half of [`Self::resets`], taken by the relay's spawn —
    /// once, and never again: a clone that spawns a second relay on this gate
    /// finds the slot empty and spawns none.
    resets_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// The resets a revocation sends the other way — into the box, at the
    /// peer's address, from the peer's next sequence — so the box's own half
    /// of a revoked connection ends at once too (NET-121), instead of
    /// holding a live socket into a forwarder that no longer exists. Bounded
    /// like [`Self::resets`], for the same reason.
    box_resets: mpsc::Sender<Vec<u8>>,
    /// The receiving half of [`Self::box_resets`], taken by the relay's spawn
    /// with the switch-side one.
    box_resets_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Outbound-UDP flow tracker, shared between the relay legs so a reply to
    /// the PTask's own UDP egress (DNS, QUIC, …) is allowed back in — and an
    /// undeclared datagram, or one the relay answered itself (NET-136), cannot
    /// open a window.
    conntrack: Arc<UdpConntrack>,
    /// The target PTask's switch IP, carried as the R2.7 log's `session_id`.
    label: String,
    /// Rate-limited emitter for dropped-frame warnings (R2.7), keyed by box and
    /// rule, shared by both legs and the NET-004 notice.
    limiter: Arc<PolicyWarnLimiter>,
    /// The box's compiled egress rules — its declared dimensions, the
    /// resolver the carve-out is keyed to, and its lease (NET-084) — decided
    /// by `sessions::core::egress`.
    egress: egress::EgressRules,
    /// The box's compiled ingress rules — its declared internal ports, the
    /// permit range and the dynamic stance — the shared decision a
    /// listen-published port is published by ([`Self::listen_verdict`],
    /// NET-016), kept here beside the egress compilation so both halves of
    /// the box's policy decide on one form of each.
    ingress: IngressRules,
    /// The DNS gate (NET-066, NET-067, NET-136): the per-box table of the
    /// addresses its allowed names resolved to, each holding for its
    /// admission window — the one thing that can lift an
    /// undeclared-destination drop on the egress leg — plus the
    /// AAAA/HTTPS/SVCB interception the egress leg answers NODATA with.
    /// Built at attach and shared by both legs through this gate.
    dns: DnsGate,
}

impl SessionGate {
    /// Builds a gate from a session's whole policy: the declared internal ports
    /// per transport (TCP and UDP separately) drive the inbound half, the
    /// compiled egress rules the outbound half, and `subnet` names the switch
    /// the relay is attached to — whose gateway is the resolver the egress
    /// carve-out is keyed to (NET-079). `lease` is the box's address on that
    /// switch, compiled into its egress rules as the one source its frames may
    /// carry (NET-084). A session with no declared ingress denies every new
    /// inbound connection/datagram while still receiving replies to its own
    /// egress; one with no declared egress allows all (the shipped default,
    /// until NET-074's deny-all default is in force).
    #[must_use]
    pub fn for_session(
        label: String,
        lease: Ipv4Addr,
        policy: &sessions::SessionPolicy,
        subnet: SwitchSubnet,
    ) -> Self {
        // The one egress compilation this box's frames are decided by, shared
        // with the DNS gate below — so a name's admission and a frame's
        // verdict can never disagree about what the box declared.
        let rules = compiled_egress(Some(policy), subnet, lease);
        let infrastructure = egress::InfrastructureDenySet::new(
            subnet.dns_server().octets(),
            subnet.host_alias().octets(),
        );
        let limiter = Arc::new(PolicyWarnLimiter::new());
        // One DNS gate per box, sharing the limiter, the resolver address
        // the egress rules already resolved from `subnet` (NET-079's
        // carve-out, the address this gate watches replies from), and the
        // subnet's host alias — the answer the zone's host row carries
        // (NET-003), which the gate passes through without a refusal.
        let dns = DnsGate::new(
            &label,
            policy.egress.as_ref(),
            rules.clone(),
            infrastructure,
            subnet.host_alias().octets(),
            Arc::clone(&limiter),
        );
        // The reset channel the legs synthesize refusals through: created with
        // the gate, its receiving half leaves it when the relay's spawn takes
        // it, and a gate that never spawns a relay — a policy-level caller —
        // just accumulates nothing, because nothing sends into a channel whose
        // gate was never attached. Bounded, and a send past the bound is
        // dropped (see the field doc): the per-source budget is what keeps a
        // legitimate source inside it.
        let (resets, resets_rx) = mpsc::channel(RESET_CHANNEL_CAPACITY);
        let (box_resets, box_resets_rx) = mpsc::channel(RESET_CHANNEL_CAPACITY);
        Self {
            allowed: declared_ingress_ports(Some(policy), sessions::IpProto::Tcp),
            // The runtime-published half starts empty: nothing a box's
            // processes listen on is published until the watcher sees it
            // (NET-016), and an own-IP box that starts no watcher — one whose
            // launch attached no switch — publishes nothing at all.
            listen_published: Mutex::new(HashSet::new()),
            udp_allowed: declared_ingress_ports(Some(policy), sessions::IpProto::Udp),
            revoked: Mutex::new(HashSet::new()),
            inbound_flows: Mutex::new(HashMap::new()),
            terminated_flows: Mutex::new(HashMap::new()),
            reset_budget: ResetBudget::default(),
            resets,
            resets_rx: Mutex::new(Some(resets_rx)),
            box_resets,
            box_resets_rx: Mutex::new(Some(box_resets_rx)),
            conntrack: Arc::new(UdpConntrack::default()),
            label,
            limiter,
            egress: rules,
            // The ingress half of the same compilation discipline: the
            // listener watcher asks this gate, so both it and the inbound
            // leg read the one decision the shared module holds (NET-016).
            ingress: IngressRules::from_policy(policy.ingress.as_ref()),
            dns,
        }
    }

    /// Shrinks the DNS gate's admission window — a test hook for the
    /// relay-level proof that an established flow outlives the window,
    /// which cannot be written against a five-minute one.
    #[cfg(test)]
    pub(crate) fn shrink_admission_window(&mut self, window: Duration) {
        self.dns.shrink_window(window);
    }

    /// Shrinks the DNS gate's flow idle cap — the window hook's twin, for
    /// the relay-level proofs that an established flow is *released* by
    /// idleness, which cannot be written against a day-long one.
    #[cfg(test)]
    pub(crate) fn shrink_flow_idle_cap(&mut self, cap: Duration) {
        self.dns.shrink_flow_idle_cap(cap);
    }

    /// Takes the receiving half of the gate's reset channel — once, at the
    /// relay's spawn, so the leg that writes to the switch owns it alone.
    fn take_resets(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.resets_rx
            .lock()
            .expect("gate reset-receiver lock poisoned")
            .take()
    }

    /// Takes the receiving half of the gate's box-directed reset channel —
    /// once, at the relay's spawn, with the switch-side one, so the leg that
    /// writes to the tap owns it alone.
    fn take_box_resets(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.box_resets_rx
            .lock()
            .expect("gate box-reset-receiver lock poisoned")
            .take()
    }

    /// Whether `port`'s ingress has been revoked (NET-121).
    fn port_revoked(&self, port: u16) -> bool {
        self.revoked
            .lock()
            .expect("gate revoked-port lock poisoned")
            .contains(&port)
    }

    /// Records the tail of an admitted inbound TCP flow: the packet's own
    /// addressing, sequence and acknowledgement pair, Ethernet addresses and
    /// length — the state a later withdrawal of its port builds the flow's
    /// terminating reset from. Only packets to admitted ports are recorded
    /// — a declared port's (NET-121) or a listen-published one's (NET-016),
    /// both of which a forward dials through this relay: a return segment of
    /// the box's own egress is no ingress flow. Swept past
    /// [`INBOUND_FLOW_SWEEP_AT`] entries, the conntrack's bound.
    fn record_inbound(&self, pkt: &L4Packet, frame: &[u8]) {
        if !self.admits_tcp(pkt.dst.port()) {
            return;
        }
        let tail = InboundFlowTail {
            src_mac: frame
                .get(6..12)
                .and_then(|mac| mac.try_into().ok())
                .unwrap_or([0; 6]),
            dst_mac: frame
                .get(0..6)
                .and_then(|mac| mac.try_into().ok())
                .unwrap_or([0; 6]),
            src: pkt.src,
            dst: pkt.dst,
            seq: pkt.seq,
            ack: pkt.ack,
            flags: pkt.tcp_flags,
            payload_len: tcp_payload_len(frame),
        };
        let key: InboundFlowKey = (*pkt.src.ip(), pkt.src.port(), pkt.dst.port());
        let now = Instant::now();
        let mut flows = self
            .inbound_flows
            .lock()
            .expect("gate inbound-flow lock poisoned");
        flows.insert(key, (now, tail));
        if flows.len() > INBOUND_FLOW_SWEEP_AT {
            flows.retain(|_, (seen, _)| now.duration_since(*seen) < INBOUND_FLOW_TTL);
        }
    }

    /// Revokes `port`'s ingress (NET-121): the gate admits it no longer, and
    /// every connection it held is terminated at **both ends** — each recorded
    /// flow is answered with a reset built from the last packet the gate saw
    /// of it, and the box's half of the same flow is ended by a reset written
    /// into the tap toward it, from the peer's address at the peer's next
    /// sequence — and every packet that still arrives for the port is
    /// refused — answered where the gate holds state to answer from, silent
    /// where it holds none — instead of being forwarded. Returns the number
    /// of held connections terminated, for the revocation's log line.
    pub(crate) fn revoke_port(&self, port: u16) -> usize {
        if !self
            .revoked
            .lock()
            .expect("gate revoked-port lock poisoned")
            .insert(port)
        {
            // Already revoked: the connections are gone, and a second
            // revocation terminates nothing.
            return 0;
        }
        self.terminate_port(port)
    }

    /// Ends every connection the gate holds on `port`, at **both ends** — the
    /// machinery a forward's disappearance runs whether the forward was a
    /// declaration's, revoked through [`Self::revoke_port`] (NET-121), or a
    /// listen-published one whose listener closed ([`Self::withdraw_published`],
    /// NET-017): each recorded flow is answered with a reset built from the
    /// last packet the gate saw of it, the box's half of the same flow is
    /// ended by a reset written into the tap toward it, and every flow's tail
    /// is kept for [`TERMINATED_FLOW_TTL`] so a segment the ended connection
    /// still sends is answered from the state the gate **tracked**. Returns
    /// the number of held connections terminated, for the caller's log line.
    fn terminate_port(&self, port: u16) -> usize {
        let now = Instant::now();
        let drained: Vec<(InboundFlowKey, InboundFlowTail)> = {
            let mut flows = self
                .inbound_flows
                .lock()
                .expect("gate inbound-flow lock poisoned");
            let drained = flows
                .extract_if(|key, _| key.2 == port)
                .map(|(key, (_, tail))| (key, tail))
                .collect();
            flows.retain(|_, (seen, _)| now.duration_since(*seen) < INBOUND_FLOW_TTL);
            drained
        };
        let terminated = drained.len();
        // The revocation's own resets are the gate's own doing, not a source's:
        // they draw no per-source budget, and a full channel drops them like
        // any other — a well-behaved revocation is one reset per held flow.
        // Each ended flow keeps its tail in the terminated table, so a segment
        // the connection still sends after its reset is answered from the
        // state the gate tracked rather than left to time out (see
        // [`Self::refuse_tcp_segment`]).
        {
            let mut ended = self
                .terminated_flows
                .lock()
                .expect("gate terminated-flow lock poisoned");
            for (key, tail) in &drained {
                ended.insert(*key, (now, *tail));
            }
            if ended.len() > TERMINATED_FLOW_SWEEP_AT {
                ended.retain(|_, (seen, _)| now.duration_since(*seen) < TERMINATED_FLOW_TTL);
            }
        }
        for (_, tail) in &drained {
            self.send_reset(rst_from_flow(tail));
            self.send_box_reset(rst_toward_box_from_flow(tail));
        }
        terminated
    }

    /// Answers one inbound TCP segment the gate refuses — a SYN to a port the
    /// box's declaration does not publish (NET-014) or any segment to a port
    /// whose ingress was revoked (NET-121) — with a reset on the switch side,
    /// subject to the two bounds a source-fed channel needs:
    ///
    /// - the **per-source budget** ([`ResetBudget`]): a source that has spent
    ///   its window's refusals gets no more until the window rolls, so one
    ///   box's flood cannot spend the gate's resets on itself. The flooder
    ///   degrades to a timeout; nobody else does.
    /// - the **channel's bound** ([`RESET_CHANNEL_CAPACITY`]): a send past it is
    ///   dropped rather than queued, so no burst of refusals grows the
    ///   daemon's memory.
    ///
    /// The reset's shape follows RFC 793, and is built from state the gate
    /// holds, never from numbers the arriving segment carries:
    ///
    /// - a bare SYN is answered with RST|ACK from sequence zero, acknowledging
    ///   the SYN — `SYN.seq + 1` — the kernel's own connection-refused shape,
    ///   which a connecting peer's half-open socket reads as the refusal it is.
    /// - a segment of an established connection is answered only when the gate
    ///   holds that connection's tail — the revocation's terminated table — and
    ///   then from the sequence pair it tracked, which is in the peer's window
    ///   by construction. A segment of a flow the gate holds **nothing** for is
    ///   answered with no reset at all: the arriving segment's own sequence
    ///   numbers are its sender's claim, and a spoofed one would let any box
    ///   make this box emit a reset carrying an attacker-chosen sequence to a
    ///   spoofed victim. The reset is always addressed to the frame's source
    ///   (`rst_frame` swaps the observed packet's own addresses), so a refusal
    ///   can never be steered at a third party.
    /// - a segment that is itself a reset is answered with nothing, before any
    ///   budget is spent: answering a reset with a reset is the one exchange
    ///   RFC 793 forbids outright, and the ended connection's stragglers are
    ///   exactly that — resets, ACKs and FINs a peer's already-closed socket
    ///   sends into a flow the gate has ended. Charging them against the
    ///   source's window would let one ended connection spend the peer's
    ///   refusals on replies that cannot exist.
    ///
    /// Returns whether a reset was queued.
    fn refuse_tcp_segment(&self, frame: &[u8], pkt: &L4Packet) -> bool {
        // Never answer a reset with a reset — and never let one spend the
        // source's refusal budget either.
        if pkt.tcp_flags & 0x04 != 0 {
            return false;
        }
        if !self.reset_budget.admit(*pkt.src.ip(), &self.label) {
            return false;
        }
        let syn = pkt.tcp_flags & 0x02 != 0;
        let ack = pkt.tcp_flags & 0x10 != 0;
        let reset = if syn && !ack {
            rst_reply_frame(frame, pkt)
        } else {
            // The flow the segment belongs to: the gate's own record of a
            // connection it admitted and then ended. `None` — a flow nothing
            // holds, or one whose tail has expired — is answered with nothing.
            let key: InboundFlowKey = (*pkt.src.ip(), pkt.src.port(), pkt.dst.port());
            self.terminated_flows
                .lock()
                .expect("gate terminated-flow lock poisoned")
                .get(&key)
                .filter(|(seen, _)| Instant::now().duration_since(*seen) < TERMINATED_FLOW_TTL)
                .map(|(_, tail)| rst_from_flow(tail))
        };
        match reset {
            Some(reset) => {
                self.send_reset(reset);
                true
            }
            None => false,
        }
    }

    /// Hands a synthesized reset to the leg that writes to the switch. The
    /// channel is bounded and its receiver is only ever dropped when the gate
    /// itself is — so a send fails only on the bound, and the excess reset is
    /// dropped there: never queued, never retried, never held.
    fn send_reset(&self, frame: Vec<u8>) {
        let _ = self.resets.try_send(frame);
    }

    /// Hands a revocation's box-directed reset to the leg that writes to the
    /// tap, with the switch-side one's own bounds: dropped at the channel's
    /// edge, never queued.
    fn send_box_reset(&self, frame: Vec<u8>) {
        let _ = self.box_resets.try_send(frame);
    }

    /// The inbound-gate decision for one Ethernet frame: `Some((proto, dst_port,
    /// src))` when it must be dropped — a new TCP connection or an unsolicited UDP
    /// datagram to a port the target did not declare — else `None` (pass).
    fn inbound_drop(&self, frame: &[u8]) -> Option<(sessions::IpProto, u16, SocketAddrV4)> {
        {
            // NET-016: the declared ports and the listen-published ones are
            // one admission set for a new inbound connection. The
            // runtime-published half is read under one lock per frame — the
            // same interior-mutable shape the revoked check holds below it —
            // rather than snapshotted, so a frame never decides on a set the
            // watcher has already moved on from.
            let listen_published = self
                .listen_published
                .lock()
                .expect("gate listen-published lock poisoned");
            if let Some((dst_port, src)) = blocked_syn(frame, &self.allowed, &listen_published) {
                return Some((sessions::IpProto::Tcp, dst_port, src));
            }
        }
        if let Some((dst_port, src)) = blocked_udp(frame, &self.udp_allowed, &self.conntrack) {
            return Some((sessions::IpProto::Udp, dst_port, src));
        }
        None
    }

    /// NET-073's connect-time half: whether a new inbound TCP connection to
    /// this box must be dropped because the *source* box's own egress rules
    /// refuse it. Only the source's relay holds those rules, so this relay
    /// asks the source's live gate (the [`LIVE_GATES`] table) and applies the
    /// one decision function the proxy's caller check uses
    /// ([`direct_connection_verdict`]) — the parity rule that a
    /// hostname-routing surface buys no reach a direct connection would not
    /// have.
    ///
    /// The source's half is the source's rules as declared —
    /// `allow_subnets` and `deny_subnets` — and nothing else: no pin lifts
    /// it, so a sibling is reached by a CIDR entry and never by a
    /// name-scoped grant. The DNS gate's pin (NET-066) is the source's *own*
    /// relay's lift of its own undeclared-destination drop, and a box-zone
    /// answer creates no pin at all — NET-072's carve-out is the
    /// resolution's alone ([`DnsGate`]) — so deciding this half by the
    /// declared subnets alone is what keeps it the one decision the source's
    /// own egress leg and the hostname proxy's caller check (NET-070) both
    /// make of the same connection.
    ///
    /// Returns `true` to drop. `false` leaves the decision where it was:
    /// [`inbound_drop`] still governs the connection with the target's own
    /// ingress rules — this check narrows it, never widens it. A connection
    /// event is a bare SYN; a source that is not a live box on this daemon's
    /// switch (the resolver, the daemon's own relay, a box behind another
    /// daemon) finds no gate and keeps today's target-ingress-only behavior.
    /// The box behind another daemon is ingress-only because no such source
    /// can arrive on this switch, not because its egress goes unchecked:
    /// each daemon's gvproxy is its own L2 segment, so no frame from that
    /// box's switch lease ever rides this one, and its host-address reach
    /// travels the host's loopback, where the host-side classifier owns the
    /// per-box verdict (NET-078, NET-079) — this switch sees nothing of it
    /// to check.
    ///
    /// One debug line per connection names both boxes and each side's verdict;
    /// a source refusal is also said once per source box and rule per minute
    /// (R2.7), under the source's label, through the source's *own* limiter —
    /// the same one its egress leg rate-limits by — so one refusal is one
    /// line, whichever leg said it. On traffic the source's relay carried,
    /// that leg has already dropped the frame its rules refuse (a box-zone
    /// answer pins nothing, so no pin lifts the identical verdict it makes),
    /// which makes this half the conjunction's backstop: it holds the
    /// source's rules true at the target even for a frame that reached the
    /// switch without the source relay's verdict on it.
    fn refuse_zone_connect(&self, frame: &[u8]) -> bool {
        let Some(pkt) = parse_ipv4_l4(frame) else {
            return false;
        };
        if pkt.proto != IPPROTO_TCP {
            return false;
        }
        let (syn, ack) = (pkt.tcp_flags & 0x02 != 0, pkt.tcp_flags & 0x10 != 0);
        if !syn || ack {
            return false;
        }
        let Some(peer) = live_gate(*pkt.src.ip()) else {
            return false;
        };
        let (dst, dst_port) = (pkt.dst.ip(), pkt.dst.port());
        // The source's half of the conjunction: the verdict the source's
        // declared rules give this connection, and nothing beside them — no
        // pin lifts a refusal here, so a sibling is reached by a CIDR entry
        // and never by a name-scoped grant (see the method doc).
        let (refusal, source_pass) = match direct_connection_verdict(&peer.egress, *dst, dst_port) {
            FrameVerdict::Admit => (None, true),
            FrameVerdict::Drop(reason) => (Some(reason), false),
        };
        // The target's half, as `inbound_drop` will decide the same frame a
        // breath later if the source's half passes — the declared and
        // listen-published ports together, the one admission set a new
        // inbound connection is decided on (NET-016).
        let target_pass = self.admits_tcp(dst_port);
        tracing::debug!(
            source = %peer.label,
            target = %self.label,
            source_pass,
            target_pass,
            port = dst_port,
            "box-zone connection decided at connect"
        );
        if source_pass {
            return false;
        }
        let reason = refusal.expect("refusal known when the source half fails");
        // The source's own limiter, not this relay's: the refusal stands for
        // the line the source's own egress leg would have said, and sharing
        // its limiter is what makes that true — one refusal is one line per
        // source box and rule per minute (R2.7), whichever leg said it, so
        // the two legs' says of one violation can never be two lines.
        peer.limiter.warn(
            &peer.label,
            Direction::Egress,
            Some(SocketAddr::V4(pkt.dst)),
            Proto::Tcp,
            Some(dst_port),
            reason.rule(),
        );
        true
    }

    /// Whether the target's own gate admits a direct inbound TCP connection to
    /// `port` — the port on the box the connection terminates on, which is the
    /// mapping's *internal* port for a proxied request translated through its
    /// declaration. The relay's half of the verdict
    /// [`proxied_request_verdict`] composes (its port predicate, the one
    /// `blocked_syn` applies to a new connection), exposed so the hostname
    /// proxy's refusals can be held to it: the proxy may forward a request
    /// only to a port this admits, and refuses every request whose port the
    /// same declaration does not publish (NET-069, NET-071).
    #[must_use]
    pub fn admits_direct_tcp(&self, port: u16) -> bool {
        self.allowed.contains(&port)
    }

    /// The shared verdict for one port a process in the box is listening on,
    /// on the transport it listens with (NET-016): the pure decision
    /// `sessions::core::egress` holds for the whole surface, asked of the
    /// rules this gate was compiled with at attach, so the listener watcher
    /// and the relay can never grow two derivations of the box's
    /// declaration that disagree. The transport is half of what the
    /// declaration must name for a port to be published already — a
    /// mapping's forward answers the one protocol it was exposed with
    /// (NET-121) — so the watcher asks with the transport it publishes on.
    /// The watcher calls this before it publishes anything.
    #[must_use]
    pub fn listen_verdict(&self, proto: sessions::IpProto, port: u16) -> ListenVerdict {
        self.ingress.listen_verdict(proto, port)
    }

    /// Admits one listen-published port (NET-016): the runtime-published
    /// half of the inbound gate's TCP set, so the connections its forwarder
    /// dials through the relay reach the box. The watcher calls this only
    /// *after* [`super::policy::expose_mapping`] bound the forward — the
    /// order the declaration's own apply holds (NET-121) — so a port is
    /// never admitted while nothing answers for it.
    pub(crate) fn admit_published(&self, port: u16) {
        self.listen_published
            .lock()
            .expect("gate listen-published lock poisoned")
            .insert(port);
    }

    /// Whether this gate admits a new inbound TCP connection to `port` —
    /// the declared ports (NET-121) and the listen-published ones
    /// (NET-016) together: the one predicate the inbound leg, the
    /// connect-time debug line, and the watcher's own tests read.
    pub(crate) fn admits_tcp(&self, port: u16) -> bool {
        self.allowed.contains(&port)
            || self
                .listen_published
                .lock()
                .expect("gate listen-published lock poisoned")
                .contains(&port)
    }

    /// Withdraws one listen-published port (NET-017): its admission goes,
    /// and the connections it held are terminated at both ends — a forward
    /// whose listener is gone must not leave connections hanging at it, the
    /// same end a revoked declared forwarder's connections come to. The
    /// declared set is never touched: a declaration's port is published
    /// already and held until the box stops (NET-121), and a withdrawal
    /// applies only to the runtime-published set (NET-081's
    /// sub-requirement). Returns the number of held connections terminated,
    /// for the withdrawal's log line.
    pub(crate) fn withdraw_published(&self, port: u16) -> usize {
        if !self
            .listen_published
            .lock()
            .expect("gate listen-published lock poisoned")
            .remove(&port)
        {
            // Never published through this gate: there is no admission to
            // withdraw and no connection of this publication to end.
            return 0;
        }
        self.terminate_port(port)
    }
}

/// The rule name an ingress refusal carries on both surfaces that decide
/// ingress (NET-069, NET-071): the relay logs this name when it drops a
/// direct connection to a port the target did not declare, and the hostname
/// proxy logs the *same* name when it refuses a proxied request to that port
/// before dialing — so the daemon log's tail (the diagnostics bundle's)
/// shows one rule for one violation, whichever route it took. R2.7's
/// `rule_matched` field.
pub const NO_INGRESS_MAPPING_RULE: &str = "no ingress mapping";

/// The rule name a refusal of a *revoked* ingress port carries (NET-121):
/// the relay logs it — rate-limited, with the port — for every segment the
/// gate answers with a reset once the port's forwarder has been unbound.
/// R2.7's `rule_matched` field.
pub const REVOKED_INGRESS_PORT_RULE: &str = "revoked ingress port";

/// The internal ports a target's ingress declaration admits on `proto` — the
/// one derivation both ingress surfaces read: the relay's inbound gate
/// ([`SessionGate::allowed`]/[`SessionGate::udp_allowed`]) and, through the
/// registry's routes, the hostname proxy's own port gate. Compiled by the
/// shared rules (`sessions::core::egress::IngressRules`), so the declared
/// half and the listen-published half of a box's ingress answer the same
/// form of the same declaration. An absent ingress policy admits nothing
/// (the own-IP default-block posture).
#[must_use]
pub fn declared_ingress_ports(
    policy: Option<&sessions::SessionPolicy>,
    proto: sessions::IpProto,
) -> HashSet<u16> {
    IngressRules::from_policy(policy.and_then(|policy| policy.ingress.as_ref()))
        .declared(proto)
        .collect()
}

/// The external ports a request to an **own-address** target may name
/// (NET-069): the ports its ingress declaration *publishes* — the port a URL
/// carries and the proxy sees, which [`Route::upstream`](crate::net::dns::Route::upstream)
/// then translates to the internal port behind it. An own-address box that
/// declares no ingress publishes nothing: absent ingress is the deny-all
/// posture `sessions::validate_policy` accepts on `own_ip`, the same posture
/// [`declared_ingress_ports`] gives a direct connection to it, so the set is
/// empty and never `None`. `None` on a route means a *host-address* box
/// (launch validation rejects an ingress declaration on every mode but
/// `own_ip`), a different verdict whose direct connections no surface gates —
/// collapsing the two is what would let a proxied request dial an undeclared
/// port on a native host's published-loopback route while a VM host refuses
/// it (NET-071).
#[must_use]
pub fn declared_request_ports(policy: Option<&sessions::SessionPolicy>) -> BTreeSet<u16> {
    policy
        .and_then(|policy| policy.ingress.as_ref())
        .map(|ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|m| m.external_port)
                .collect()
        })
        .unwrap_or_default()
}

/// The compiled egress rules a session's own outbound frames are decided by
/// on the relay ([`SessionGate::egress`]), keyed to `subnet`'s resolver — the
/// same compilation for the hostname proxy's caller check (NET-070), so a
/// session's egress declaration cannot mean one thing on the switch and
/// another through the proxy (NET-071). `lease` is the box's address on that
/// switch, compiled into the rules as the one source its frames may carry
/// (NET-084).
#[must_use]
pub fn compiled_egress(
    policy: Option<&sessions::SessionPolicy>,
    subnet: SwitchSubnet,
    lease: Ipv4Addr,
) -> egress::EgressRules {
    egress::EgressRules::from_policy(
        policy.and_then(|policy| policy.egress.as_ref()),
        subnet.dns_server().octets(),
        lease.octets(),
    )
}

/// The egress verdict a direct TCP connection from a box whose own frames are
/// decided by `rules` to `dst:port` would carry — the same pure
/// `sessions::core::egress` verdict the relay applies to every frame the box
/// sends, asked about a synthesized TCP frame, so the hostname proxy decides
/// a request with the relay's own function and never grows a second
/// implementation of the rules that could drift (NET-070, NET-071).
///
/// The frame is synthesized because the verdict's input *is* a frame: the
/// decision stays a pure function of an owned frame summary, exactly as the
/// NET-062..064 tier requires, and reusing it verbatim is what keeps exactly
/// one admit-or-drop function in the tree. The rules are address- and
/// protocol-shaped — never port-shaped, the resolver carve-out aside, which a
/// TCP frame cannot match — so the port names the connection without
/// changing the verdict.
///
/// The synthesized frame carries the rules' own lease as its source (NET-084):
/// it stands for a frame the box itself put on the wire, so the verdict's
/// lease check reads it as the box's own and the declared dimensions decide —
/// the same frame-source relationship the relay's frames have to the same
/// rules. Synthesizing it with any other source would have the lease check
/// refuse every request, and never consult the caller's declaration at all.
#[must_use]
pub fn direct_connection_verdict(
    rules: &egress::EgressRules,
    dst: Ipv4Addr,
    dst_port: u16,
) -> FrameVerdict {
    egress::verdict(
        &tcp_frame_summary(Ipv4Addr::from(rules.lease()), dst, dst_port),
        rules,
    )
}

/// Sizes of the Ethernet header and the minimum IPv4 header `summarize`
/// extracts; the synthesized frame is exactly the bytes [`egress::summarize`]
/// reads and nothing else.
const SYNTH_ETH_HDR: usize = 14;
const SYNTH_IPV4_HDR: usize = 20;
const SYNTH_L4_HDR: usize = 4;

/// The frame summary the egress verdict reads for a TCP connection from
/// `src` to `dst:port` — an Ethernet header carrying the minimum IPv4 header
/// and a 4-byte L4 header, with EtherType, IHL, protocol, source address,
/// destination address and destination port set at the offsets `summarize`
/// extracts them from. `src` is the box's lease the rules carry (NET-084).
///
/// [`egress::summarize`] reads a frame, so a frame is what stands for the
/// connection — but only the fields it extracts are written, and every index
/// below is a constant offset inside a fixed-size array sized for exactly
/// those fields, so none of them can be out of bounds.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    reason = "constant offsets into a fixed-size array sized for exactly these fields"
)]
fn tcp_frame_summary(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> FrameSummary {
    let mut frame = [0u8; SYNTH_ETH_HDR + SYNTH_IPV4_HDR + SYNTH_L4_HDR];
    frame[12..14].copy_from_slice(&[0x08, 0x00]); // EtherType: IPv4.
    let ip = &mut frame[SYNTH_ETH_HDR..];
    ip[0] = 0x45; // IPv4, IHL 5 (the 20-byte header below).
    ip[9] = IPPROTO_TCP;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    // The L4 destination port, at the offset `summarize` reads it from
    // (`ip[ihl + 2..ihl + 4]`) — the two bytes *after* the 20-byte IPv4
    // header, not the source-port slot inside it.
    ip[SYNTH_IPV4_HDR + 2..SYNTH_IPV4_HDR + 4].copy_from_slice(&dst_port.to_be_bytes());
    egress::summarize(&frame)
}

/// The decision for one proxied request, put to the same verdict a direct
/// connection between the same two boxes would meet (NET-069, NET-070,
/// NET-071): the caller's compiled egress rules for the target first, then
/// the target's declared ingress ports for the request's port. Decided by one
/// function ([`proxied_request_verdict`]) through the relay's own helpers —
/// [`direct_connection_verdict`], [`Route::upstream`](crate::net::dns::Route::upstream)
/// and [`NO_INGRESS_MAPPING_RULE`] — so a hostname-routing surface gives no
/// reach a direct connection would not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxiedRequest {
    /// Both declarations admit: forward to this upstream.
    Forward(SocketAddr),
    /// Refused before the proxy dialed anything, in the relay's drop-line
    /// vocabulary, so a proxied refusal and a direct one log as the same
    /// violation of the same rule (NET-069).
    Refused(Refusal),
}

/// Why a proxied request was refused: which declaration was violated, under
/// which rule, and the other side's address — the facts a proxied refusal's
/// warn line carries beside the proxy's own (host, session, port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The relay's rule name for this refusal (R2.7's `rule_matched`): an
    /// `egress::DropReason` rule for an egress refusal,
    /// [`NO_INGRESS_MAPPING_RULE`] for an ingress one.
    pub rule: &'static str,
    /// Which declaration refused it: the caller's egress or the target's
    /// ingress.
    pub direction: Direction,
    /// The other side of the refused connection: the target for an egress
    /// refusal, the caller for an ingress one. `None` when the proxy cannot
    /// name it (a host-side caller, which is no box at all).
    pub other: Option<SocketAddr>,
}

/// Decides one proxied request (NET-069, NET-070, NET-071). `caller` is the
/// live session the request's peer address names — `None` when it names no
/// live box, which is what a host-side client (the developer's browser, the
/// daemon's own lanes) is: no box's egress declaration to honour, so only the
/// target's ingress half decides. `route` is the target the request resolved
/// to and `port` the port its authority carried.
///
/// The caller's declaration comes first, in the order a direct connection
/// meets the two: its frame clears the caller's own egress gate before the
/// target's ingress gate ever sees it (NET-070). The target's declaration is
/// the port gate [`Route::upstream`](crate::net::dns::Route::upstream) already
/// applies — a port its ingress does not publish routes nowhere.
#[must_use]
pub fn proxied_request_verdict(
    caller: Option<&crate::net::dns::Caller>,
    route: &crate::net::dns::Route,
    port: u16,
) -> ProxiedRequest {
    let target = route.address();
    if let Some(caller) = caller
        && let FrameVerdict::Drop(reason) = direct_connection_verdict(caller.egress(), target, port)
    {
        return ProxiedRequest::Refused(Refusal {
            rule: reason.rule(),
            direction: Direction::Egress,
            other: Some(SocketAddr::V4(SocketAddrV4::new(target, port))),
        });
    }
    match route.upstream(port) {
        Some(upstream) => ProxiedRequest::Forward(upstream),
        None => ProxiedRequest::Refused(Refusal {
            rule: NO_INGRESS_MAPPING_RULE,
            direction: Direction::Ingress,
            other: caller.map(|caller| SocketAddr::V4(SocketAddrV4::new(caller.lease(), port))),
        }),
    }
}

/// The L4 addressing of a TCP/UDP-over-IPv4 frame, as extracted by
/// [`parse_ipv4_l4`]. `tcp_flags` is meaningful only when `proto == IPPROTO_TCP`.
/// `pub(crate)`: the DNS gate's tests read the addressing of the replies the
/// relay synthesizes.
pub(crate) struct L4Packet {
    /// Source `ip:port`.
    pub(crate) src: SocketAddrV4,
    /// Destination `ip:port`.
    pub(crate) dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub(crate) proto: u8,
    /// TCP flags byte; `0` for UDP.
    pub(crate) tcp_flags: u8,
    /// TCP sequence number; `0` for UDP. Read for the resets the gate
    /// synthesizes (NET-014, NET-121), which ride the observed packet's own
    /// sequence/acknowledgement pair.
    pub(crate) seq: u32,
    /// TCP acknowledgement number; `0` for UDP and for a packet with no ACK
    /// set (where the field is unspecified by the sender).
    pub(crate) ack: u32,
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
    let (seq, ack) = if proto == IPPROTO_TCP {
        (
            u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
            u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]),
        )
    } else {
        (0, 0)
    };
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
        seq,
        ack,
    })
}

/// Returns `Some((dst_port, src))` iff `frame` is a bare TCP SYN (SYN set, ACK
/// clear) to a port neither half of the gate's admission set holds — not
/// declared (`allowed`) and not published by a listener ([`listen_published`],
/// NET-016) — the one TCP case the ingress gate drops. `None` (pass) for
/// non-TCP, admitted ports, and any ACK-set segment (SYN-ACK, established,
/// egress return).
fn blocked_syn(
    frame: &[u8],
    allowed: &HashSet<u16>,
    listen_published: &HashSet<u16>,
) -> Option<(u16, SocketAddrV4)> {
    let pkt = parse_ipv4_l4(frame)?;
    if pkt.proto != IPPROTO_TCP {
        return None;
    }
    let (syn, ack) = (pkt.tcp_flags & 0x02 != 0, pkt.tcp_flags & 0x10 != 0);
    if !syn
        || ack
        || allowed.contains(&pkt.dst.port())
        || listen_published.contains(&pkt.dst.port())
    {
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

/// TTL for a tracked inbound TCP flow's tail — the state a revocation resets
/// the flow from (NET-121). Long enough to cover a quiet connection's ordinary
/// idle gaps; a flow whose tail has expired is still refused on its next
/// packet, so expiry only loses the revocation's first reset, never the
/// termination.
const INBOUND_FLOW_TTL: Duration = Duration::from_secs(300);
/// Sweep expired tails once the table crosses this many entries, bounding
/// memory under a burst of distinct flows without a background timer.
const INBOUND_FLOW_SWEEP_AT: usize = 4096;

/// TTL for the tail of a flow a revocation terminated — the state the gate
/// answers the ended connection's own stragglers from (see
/// [`SessionGate::refuse_tcp_segment`]). The window only has to outlive the
/// packets a connection's peer sends after the reset — retransmits and
/// keepalives, seconds at most — and past it the flow is held by nothing, so
/// its segments join the silent drop.
const TERMINATED_FLOW_TTL: Duration = Duration::from_secs(60);
/// Sweep expired terminated tails once the table crosses this many entries,
/// bounding memory the same way [`INBOUND_FLOW_SWEEP_AT`] does.
const TERMINATED_FLOW_SWEEP_AT: usize = 4096;

/// Capacity of the channel the gate hands its resets to the switch-side writer
/// on. It is **bounded** on purpose: the channel is fed by packets other
/// boxes send, so an unbounded one lets a single box grow the daemon's memory
/// by making the gate refuse a flood. Past the bound a reset is dropped, never
/// queued — the flooder degrades to a timeout, nobody else does, and a
/// well-behaved revocation is one reset per held flow, far under the cap.
const RESET_CHANNEL_CAPACITY: usize = 256;

/// How long one window of the per-source reset budget ([`ResetBudget`]) lasts.
/// A source that has spent its window's refusals waits for the next window,
/// so the budget is a rate, not a lifetime quota.
const RESET_WINDOW: Duration = Duration::from_secs(1);

/// How many refusals one source may spend per [`RESET_WINDOW`] before the gate
/// stops answering it until the window rolls: far above what a peer with a
/// real reason to reconnect needs, far below what a flood spends.
const RESET_PER_WINDOW: u32 = 16;

/// The per-source budget the gate's refusals are drawn against (NET-014,
/// NET-121): a map of source address to the window it is spending in. A source
/// that has spent [`RESET_PER_WINDOW`] refusals in the current window gets no
/// more until the window rolls — one box's flood cannot spend the gate's
/// resets on itself — and the first refusal a window refuses is logged once,
/// as the audit line that names the flooder. Swept like [`UdpConntrack`]:
/// only once the table crosses [`RESET_BUDGET_SWEEP_AT`], so the steady state
/// costs one map lookup per refusal.
#[derive(Debug)]
struct ResetBudget {
    /// How long one window lasts: [`RESET_WINDOW`] in production, shrunk by
    /// the proofs that cannot wait a second to watch a window roll.
    window: Duration,
    spent: Mutex<HashMap<Ipv4Addr, (Instant, u32, bool)>>,
}

/// Sweep exhausted per-source windows once the budget table crosses this many
/// entries, bounding memory under a burst of spoofed sources.
const RESET_BUDGET_SWEEP_AT: usize = 4096;

impl Default for ResetBudget {
    fn default() -> Self {
        Self {
            window: RESET_WINDOW,
            spent: Mutex::new(HashMap::new()),
        }
    }
}

impl ResetBudget {
    /// Narrows the window — the test hook for the proofs that need a window
    /// to roll inside a test, the DNS gate's admission-window hook's twin.
    #[cfg(test)]
    fn shrink_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// Whether the gate may spend one more refusal on `source` this window.
    /// `label` names the session the gate belongs to, so the audit line names
    /// the flooder's target too.
    fn admit(&self, source: Ipv4Addr, label: &str) -> bool {
        let now = Instant::now();
        let window = self.window;
        let mut spent = self.spent.lock().expect("ResetBudget mutex poisoned");
        if spent.len() > RESET_BUDGET_SWEEP_AT {
            spent.retain(|_, (seen, _, _)| now.duration_since(*seen) < window);
        }
        let (_, count, warned) = {
            let entry = spent.entry(source).or_insert((now, 0, false));
            // A fresh window for a source the table already holds: its old
            // spend lapses, and with it the suppression line's
            // once-per-window.
            if now.duration_since(entry.0) >= window {
                *entry = (now, 0, false);
            }
            entry
        };
        if *count >= RESET_PER_WINDOW {
            if !*warned {
                *warned = true;
                tracing::warn!(
                    source = %source,
                    session = label,
                    limit = RESET_PER_WINDOW,
                    window_ms = window.as_millis() as u64,
                    "stopping TCP resets for a source that spent its window's refusals"
                );
            }
            return false;
        }
        *count += 1;
        true
    }
}

/// The identity of a tracked inbound TCP flow: source address and port, and
/// the destination port it was admitted to. The destination address is the
/// relay's own lease, fixed for every flow it carries.
type InboundFlowKey = (Ipv4Addr, u16, u16);

/// The tail of a tracked inbound TCP flow: what the gate last saw of it —
/// its addressing (with the Ethernet addresses the packet rode), its
/// sequence and acknowledgement numbers, its flags and the payload length it
/// actually carried. A revocation builds the flow's terminating reset from
/// exactly these numbers, so the reset rides the flow's own pair and a
/// quiet peer reads it in-window. All plain values, so `Copy` — a revocation
/// moves its flows' tails into the terminated table without cloning ceremony.
#[derive(Clone, Copy)]
struct InboundFlowTail {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    payload_len: u16,
}

/// The TCP payload length `frame` actually carries — what arrived past the
/// Ethernet, IPv4 and TCP headers, bounded by the frame's own length rather
/// than the IP header's claimed total, so a lying header reads the bytes
/// that exist.
fn tcp_payload_len(frame: &[u8]) -> u16 {
    let ihl = usize::from(frame.get(ETH_HDR).copied().unwrap_or(0x45) & 0x0f) * 4;
    let tcp_hdr = usize::from(frame.get(ETH_HDR + ihl + 12).copied().unwrap_or(0x50) >> 4) * 4;
    (frame.len().saturating_sub(ETH_HDR + ihl + tcp_hdr)) as u16
}

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
    /// remote) so its reply may return. The caller passes only a datagram it is
    /// forwarding: one the relay answered itself never reaches the remote, so
    /// no reply is coming and a window keyed to it would admit unsolicited
    /// inbound traffic for the TTL.
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

/// The UDP datagram one Ethernet frame carries — its L4 addressing plus the
/// datagram's payload — or `None` for anything that is not an
/// IPv4+UDP frame, or whose claimed lengths do not bound its own payload.
///
/// [`parse_ipv4_l4`] decides the addressing and [`udp_payload`] the length
/// arithmetic, because the DNS gate reads the datagram's payload and a
/// hostile frame yields `None` — never an out-of-bounds slice, and never a
/// slice padded out to the Ethernet frame's end: the datagram is `total`
/// bytes, whatever the frame around it claims to be.
pub(crate) fn udp_datagram(frame: &[u8]) -> Option<(L4Packet, &[u8])> {
    let pkt = parse_ipv4_l4(frame).filter(|pkt| pkt.proto == IPPROTO_UDP)?;
    let payload = udp_payload(frame, &pkt)?;
    Some((pkt, payload))
}

/// The payload of the UDP datagram one frame carries, for a caller already
/// holding that frame's own [`parse_ipv4_l4`] result — the egress leg, whose
/// conntrack window and DNS-gate interception share one parse instead of a
/// parse each. The length contract is [`udp_datagram`]'s: a claimed length
/// that does not bound a payload yields `None`, so a mismatched `pkt` can
/// only cost a parse, never panic.
fn udp_payload<'a>(frame: &'a [u8], pkt: &L4Packet) -> Option<&'a [u8]> {
    if pkt.proto != IPPROTO_UDP {
        return None;
    }
    let ip = frame.get(ETH_HDR..)?;
    let ihl = ((ip.first()? & 0x0f) as usize) * 4;
    // The IPv4 total length bounds the datagram; a total shorter than its
    // own headers (including the `0` an offload'd frame carries) is not a
    // datagram this relay reads.
    let total = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
    if total < ihl + 8 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    // A UDP length shorter than its own header is malformed; a longer one is
    // trimmed to the IP total, which is the datagram's real bound.
    let udp_len = u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]) as usize;
    if udp_len < 8 {
        return None;
    }
    let end = total.min(ip.len());
    let payload_end = (ihl + udp_len).min(end);
    udp.get(8..payload_end - ihl)
}

/// Whether an Ethernet frame's IPv4 protocol byte says UDP — a pre-check, not
/// a parse: the EtherType and the one protocol byte, nothing else, so the
/// relay's inbound hot path — mostly a peer's TCP frames, which the DNS gate
/// can never observe — spends three comparisons per frame instead of the full
/// [`udp_datagram`] parse. A frame that says UDP here is still parsed and
/// length-checked before the gate reads a word of it. Both reads are
/// bounds-checked with `get`, the way [`udp_payload`] reads its headers, so a
/// frame shorter than either field is "not UDP" rather than a panic.
fn is_ipv4_udp(frame: &[u8]) -> bool {
    frame
        .get(12..14)
        .is_some_and(|ether| *ether == ETHERTYPE_IPV4.to_be_bytes())
        && frame
            .get(ETH_HDR + 9)
            .is_some_and(|proto| *proto == IPPROTO_UDP)
}

/// The ones' complement sum of `bytes`, read as big-endian 16-bit words with an
/// odd trailing byte padded into the high half.
fn ones_sum(bytes: &[u8]) -> u32 {
    let mut sum: u32 = bytes
        .chunks_exact(2)
        .map(|word| {
            u32::from(u16::from_be_bytes(
                // `chunks_exact(2)` yields two-byte words by definition, so
                // this conversion cannot fail.
                word.try_into().expect("chunks_exact(2) yields two bytes"),
            ))
        })
        .sum();
    if let Some(tail) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(*tail) << 8;
    }
    sum
}

/// Folds a ones' complement `sum` into the 16-bit checksum that carries it:
/// the carries added back in, then the complement.
fn ones_complement(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 header checksum of `header` (a whole header, the checksum field
/// zeroed): the ones' complement of the ones' complement sum of its 16-bit
/// words. The box's kernel verifies it on every received frame, so the
/// replies the relay synthesizes must carry an honest one.
fn ipv4_checksum(header: &[u8]) -> u16 {
    ones_complement(ones_sum(header))
}

/// The TCP checksum of `segment` carried from `src` to `dst`: the IPv4
/// pseudo-header (source, destination, protocol, TCP length) folded into the
/// segment's own ones' complement sum. Unlike UDP, TCP has no zero-checksum
/// option, and both ends of the resets the gate synthesizes verify it — the
/// box's kernel on the way in, the switch's stack on the way out — so the
/// frames must carry an honest one.
fn tcp_checksum(segment: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let mut sum = ones_sum(src.octets().as_slice());
    sum += ones_sum(dst.octets().as_slice());
    // The pseudo-header's remaining words: the `[zero][protocol]` word and
    // the TCP length. The word is big-endian `[0x00][0x06]` (RFC 793 §3.1),
    // so the protocol contributes *itself*, unshifted — parking it in the
    // zero byte's place yields a checksum no TCP stack verifies, and every
    // reset this module builds would be dropped where it is meant to end a
    // connection.
    sum += u32::from(IPPROTO_TCP);
    sum += u32::from(u16::try_from(segment.len()).unwrap_or(u16::MAX));
    sum += ones_sum(segment);
    ones_complement(sum)
}

/// Builds the Ethernet + IPv4 + TCP reset the gate answers a refused packet
/// with (NET-014, NET-121): from `src` — the refused packet's destination, the
/// box whose gate speaks for it here — back to `dst`, the packet's source, with
/// the observed packet's Ethernet addresses swapped (`eth_dst` is the reset's
/// destination, the packet's source). `seq`/`ack` follow the kernel's own reset
/// rule: a packet with ACK set is answered with a reset riding its own
/// ack/seq pair — the receiver of the reset has already told the sender what it
/// expects next, so the reset rides an in-window sequence for an established
/// connection — while a bare SYN is answered with a reset acknowledging it
/// (its sequence + the SYN flag), which a connecting peer's half-open socket
/// reads as the refusal it is.
fn rst_frame(
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    const TCP_HDR: usize = 20;
    const RST_ACK: u8 = 0x14;
    let mut frame = Vec::with_capacity(ETH_HDR + 2 * TCP_HDR);
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&eth_src);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4, IHL 5: the box's address as the source, the refused packet's
    // source as the destination; the checksum covers the header the box's
    // kernel verifies.
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&((TCP_HDR + TCP_HDR) as u16).to_be_bytes());
    header[8] = 64;
    header[9] = IPPROTO_TCP;
    header[12..16].copy_from_slice(&src.ip().octets());
    header[16..20].copy_from_slice(&dst.ip().octets());
    let checksum = ipv4_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&header);
    // TCP: no payload, so the checksum is taken over the header alone, from
    // the reset's source to its destination through the pseudo-header.
    let mut tcp = [0u8; TCP_HDR];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // data offset 5, reserved
    tcp[13] = RST_ACK;
    let checksum = tcp_checksum(&tcp, *src.ip(), *dst.ip());
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&tcp);
    frame
}

/// The acknowledgement a reset to a packet of `payload_len` bytes at `seq`
/// with `flags` gives: everything the packet carried, plus the SYN and FIN
/// flags' sequence weight.
fn rst_ack(seq: u32, payload_len: u16, flags: u8) -> u32 {
    seq.wrapping_add(u32::from(payload_len))
        .wrapping_add(u32::from(flags & 0x02 != 0))
        .wrapping_add(u32::from(flags & 0x01 != 0))
}

/// The reset [`rst_frame`] builds for one observed TCP packet `pkt` carried in
/// `frame`: `None` for a frame too short to carry both Ethernet addresses —
/// a shape [`parse_ipv4_l4`] never admits a packet from, so callers that
/// parsed `pkt` cannot hit it.
fn rst_reply_frame(frame: &[u8], pkt: &L4Packet) -> Option<Vec<u8>> {
    let (eth_dst, rest) = frame.split_first_chunk::<6>()?;
    let (eth_src, _) = rest.split_first_chunk::<6>()?;
    // The segment's payload, bounded by what the frame actually carries: the
    // reset's acknowledgement says the sender's data was seen, and a lie in
    // either direction costs only a retransmission it was going to make.
    let carried = tcp_payload_len(frame);
    let (seq, ack) = if pkt.tcp_flags & 0x10 != 0 {
        (pkt.ack, rst_ack(pkt.seq, carried, pkt.tcp_flags))
    } else {
        (0, rst_ack(pkt.seq, 0, pkt.tcp_flags))
    };
    // The reset's destination is the packet's *source* — the peer the
    // refusal is for — so the Ethernet addresses hand over swapped.
    Some(rst_frame(*eth_src, *eth_dst, pkt.dst, pkt.src, seq, ack))
}

/// The reset [`rst_frame`] builds for a flow the gate recorded — the one a
/// revoked port's connections are terminated with (NET-121), built from the
/// last packet the gate saw of the flow so it rides that packet's own
/// ack/seq pair. The Ethernet addresses are the observed packet's, swapped;
/// the box's address is the flow's destination.
fn rst_from_flow(tail: &InboundFlowTail) -> Vec<u8> {
    let (seq, ack) = if tail.flags & 0x10 != 0 {
        (tail.ack, rst_ack(tail.seq, tail.payload_len, tail.flags))
    } else {
        (0, rst_ack(tail.seq, 0, tail.flags))
    };
    rst_frame(tail.src_mac, tail.dst_mac, tail.dst, tail.src, seq, ack)
}

/// The reset [`rst_frame`] builds for a flow the gate recorded, written the
/// other way — into the tap, toward the box (NET-121): a revoked port's
/// connections end at both ends, and the box's half ends with a reset that
/// arrives from the peer's address at the peer's **next** sequence — the
/// sequence the box's socket is windowed to receive, so the connection it
/// holds into a forwarder that no longer exists ends at once. The Ethernet
/// addresses stay as observed — the box's MAC is still the destination —
/// and the acknowledgement is the peer's own latest one.
fn rst_toward_box_from_flow(tail: &InboundFlowTail) -> Vec<u8> {
    let seq = rst_ack(tail.seq, tail.payload_len, tail.flags);
    let ack = if tail.flags & 0x10 != 0 { tail.ack } else { 0 };
    rst_frame(tail.dst_mac, tail.src_mac, tail.src, tail.dst, seq, ack)
}

/// Builds the Ethernet + IPv4 + UDP frame the relay writes back toward the
/// box, answering the DNS `request` frame whose L4 addressing was `pkt` with
/// `payload` from the resolver the box asked — the request's destination —
/// back to the request's own source, port for port.
///
/// For the NODATA answers of NET-136: the box's resolver stack sees its
/// question answered by the resolver it asked. The IPv4 header checksum is
/// computed; the UDP checksum is left zero, a legal "no checksum" for IPv4,
/// so the reply needs no pseudo-header arithmetic of its own.
fn udp_reply_frame(request: &[u8], pkt: &L4Packet, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut frame = Vec::with_capacity(ETH_HDR + total);
    // Ethernet: the reply's destination is the request's source and vice
    // versa, the way any answer looks to the box. A request that parsed far
    // enough to yield `pkt` carries the whole header, so both MACs are here.
    let (requested_dst, rest) = request
        .split_first_chunk::<6>()
        .expect("a parsed datagram carries an Ethernet header");
    let (requested_src, _) = rest
        .split_first_chunk::<6>()
        .expect("an Ethernet header carries a source MAC too");
    frame.extend_from_slice(requested_src);
    frame.extend_from_slice(requested_dst);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4, IHL 5: the resolver the box asked is the source, the box the
    // destination; the checksum covers the header the box's kernel verifies.
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    header[8] = 64;
    header[9] = IPPROTO_UDP;
    header[12..16].copy_from_slice(&pkt.dst.ip().octets());
    header[16..20].copy_from_slice(&pkt.src.ip().octets());
    let checksum = ipv4_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&header);
    // UDP: the resolver's :53 back to the query's source port, no checksum.
    let udp_len = 8 + payload.len();
    frame.extend_from_slice(&pkt.dst.port().to_be_bytes());
    frame.extend_from_slice(&pkt.src.port().to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// switch → tap: read a 2-byte LE length, then that many bytes of Ethernet
/// frame, apply the inbound ingress gate (finding #2), and write the frame to the
/// tap device.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the explicit `n > frame.len()` rejection above"
)]
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
        // The frame's TCP addressing, parsed once for both of this leg's new
        // consumers below — the revoked-port refusal (NET-121) and the
        // unpublished-port reset (NET-014) — and the inbound-flow record
        // (NET-121) further down. A frame that is not IPv4+TCP — most inbound
        // traffic — reaches neither, and costs no parse.
        let tcp = parse_ipv4_l4(&frame[..n]).filter(|pkt| pkt.proto == IPPROTO_TCP);
        // NET-121: an ingress port the policy revoked is refused on the spot —
        // the gate answers with a reset and forwards nothing, whether the
        // forwarder's listener still stands or not. A new connection gets the
        // kernel's refusal shape; a segment of one the gate had to end is
        // answered from the flow the gate tracked, and a segment of a flow it
        // holds nothing for — a spoofed one — is answered with no reset at all
        // ([`SessionGate::refuse_tcp_segment`]). A reset that lands
        // out-of-window is answered by the peer with a challenge ACK, and the
        // next segment that connection sends yields an in-window reset, so the
        // termination is self-healing.
        if let Some(gate) = &gate
            && let Some(pkt) = &tcp
            && gate.port_revoked(pkt.dst.port())
        {
            gate.refuse_tcp_segment(&frame[..n], pkt);
            gate.limiter.warn(
                &gate.label,
                Direction::Ingress,
                Some(SocketAddr::V4(pkt.src)),
                Proto::from_ipv4_number(pkt.proto),
                Some(pkt.dst.port()),
                REVOKED_INGRESS_PORT_RULE,
            );
            continue;
        }
        // Inbound ingress gate (finding #2): drop a new TCP connection or an
        // unsolicited UDP datagram to a port the target PTask did not declare, so a
        // peer session or the daemon tap cannot reach undeclared listeners on the
        // shared switch. Replies to the PTask's own egress pass (TCP: ACK set; UDP:
        // matched by the conntrack).
        //
        // NET-014 turns the TCP half of that drop into a refusal: a SYN to a
        // port nothing is listening on is answered with a reset — the peer's
        // connect fails at once with connection refused instead of hanging to
        // its timeout. A UDP datagram is not a connection and stays a drop.
        //
        // NET-073 goes first, on the connection event itself: a bare SYN from
        // another box is judged by the source box's own egress rules beside
        // this target's ingress ones — the conjunction the box-zone
        // resolution rides on. A refused connection never reaches the
        // ingress gate below; an allowed one is decided by it, unchanged.
        if let Some(gate) = &gate
            && gate.refuse_zone_connect(&frame[..n])
        {
            continue;
        }
        if let Some(gate) = &gate
            && let Some((proto, dst_port, src)) = gate.inbound_drop(&frame[..n])
        {
            if proto == sessions::IpProto::Tcp
                && let Some(pkt) = &tcp
            {
                gate.refuse_tcp_segment(&frame[..n], pkt);
            }
            gate.limiter.warn(
                &gate.label,
                Direction::Ingress,
                Some(SocketAddr::V4(src)),
                Proto::from_ipproto(proto),
                Some(dst_port),
                NO_INGRESS_MAPPING_RULE,
            );
            continue;
        }
        // NET-066/NET-067: a DNS reply from this switch's own resolver is
        // the one thing that can add to what the box may reach. The egress
        // leg drops every destination the box did not declare; observing
        // the reply admits the addresses the box's allowed names resolved
        // to — each intersected with the box's denies and the
        // infrastructure deny set at resolution time, so a refused answer
        // (logged once per rule per minute, with its name and the answer)
        // is never admitted at all. The reply itself always passes on to
        // the box below: resolution is honest, only the connection to a
        // refused address is not admitted.
        //
        // Before it parses anything, the gate reads the two header bytes
        // that decide whether the frame can be one of its own at all: only
        // an IPv4+UDP frame can carry a resolver reply, and most inbound
        // traffic — a peer's TCP — is not one, so the full [`udp_datagram`]
        // parse is spent on UDP frames alone.
        if let Some(gate) = &gate
            && is_ipv4_udp(&frame[..n])
            && let Some((pkt, payload)) = udp_datagram(&frame[..n])
        {
            gate.dns.observe_response(&pkt.src, payload, Instant::now());
        }
        // NET-121: a TCP segment the gate admits toward a declared port is
        // recorded as its inbound flow's tail — the state a later revocation
        // builds the connection's terminating reset from. Only admitted
        // segments are recorded: the refusals above never forward their frame.
        if let Some(gate) = &gate
            && let Some(pkt) = &tcp
        {
            gate.record_inbound(pkt, &frame[..n]);
        }
        write_tap_frame(&tap, &frame[..n]).await?;
    }
}

/// Writes one Ethernet frame to the tap: readiness-guarded, one
/// non-blocking write per try. Used by both the ingress leg (frames from
/// the switch) and the DNS gate's NODATA answers on the egress leg.
///
/// One non-blocking write per try_io call: write_all could issue several
/// syscalls and, on a partial write then EAGAIN, restart the whole frame
/// from byte 0 — re-emitting the already-written prefix. A tap write is
/// frame-atomic, so a single write delivers the whole frame; a short count
/// would mean a malformed write we surface.
async fn write_tap_frame(tap: &Arc<AsyncFd<std::fs::File>>, frame: &[u8]) -> io::Result<()> {
    loop {
        let mut guard = tap.writable().await?;
        match guard.try_io(|inner| inner.get_ref().write(frame)) {
            Ok(result) => {
                let written = result?;
                if written != frame.len() {
                    tracing::warn!(
                        written,
                        n = frame.len(),
                        "short tap write; frame may be truncated"
                    );
                }
                return Ok(());
            }
            Err(_would_block) => continue,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // `pub(crate)`: `net::dns_gate`'s tests drive the same relay harness —
    // its sessions stand in front of the same relay legs this module proves —
    // so the harness items below are shared rather than copied.
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

    /// TCP SYN. `pub(crate)`: the DNS gate's retention proof builds segments
    /// that open, ride and close a flow.
    pub(crate) const SYN: u8 = 0x02;
    /// TCP ACK, likewise shared with the DNS gate's proofs.
    pub(crate) const ACK: u8 = 0x10;
    /// TCP RST — the one flag this box's own answers never carry in reply.
    const RST: u8 = 0x04;
    const SRC: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);

    #[test]
    fn gate_drops_syn_to_undeclared_port() {
        let allowed = HashSet::from([80]);
        let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999);
        let hit = blocked_syn(&frame, &allowed, &none_published())
            .expect("a SYN to :9999 must be blocked");
        assert_eq!(hit.0, 9999);
        assert_eq!(*hit.1.ip(), SRC);
        assert_eq!(hit.1.port(), 40000);
    }

    #[test]
    fn gate_passes_syn_to_declared_port() {
        let allowed = HashSet::from([80]);
        let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 80);
        assert!(blocked_syn(&frame, &allowed, &none_published()).is_none());
    }

    #[test]
    fn gate_passes_established_and_return_traffic() {
        let allowed = HashSet::new();
        // SYN-ACK and a pure ACK to an undeclared port are return/established
        // traffic (egress replies) and must never be dropped.
        for flags in [SYN | ACK, ACK] {
            let frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, flags, SRC, 9999);
            assert!(
                blocked_syn(&frame, &allowed, &none_published()).is_none(),
                "flags {flags:#x} must pass"
            );
        }
    }

    #[test]
    fn gate_passes_non_tcp_and_non_ipv4() {
        let allowed = HashSet::new();
        // ARP and IPv6 EtherTypes.
        for et in [0x0806u16, 0x86DD] {
            assert!(
                blocked_syn(
                    &tcp_frame(et, IPPROTO_TCP, SYN, SRC, 9999),
                    &allowed,
                    &none_published()
                )
                .is_none()
            );
        }
        // UDP (proto 17) and ICMP (proto 1) are not gated by the TCP-SYN check.
        for proto in [17u8, 1] {
            assert!(
                blocked_syn(
                    &tcp_frame(ETHERTYPE_IPV4, proto, SYN, SRC, 9999),
                    &allowed,
                    &none_published()
                )
                .is_none()
            )
        }
    }

    #[test]
    fn gate_passes_truncated_frames() {
        let allowed = HashSet::new();
        let full = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999);
        // A prefix shorter than eth(14) + ip(20) + tcp-through-flags(14) = 48
        // bytes cannot yield the TCP flags/port and must pass rather than misread.
        for cut in [0, 14, 20, 33, 40, 47] {
            assert!(
                blocked_syn(&full[..cut], &allowed, &none_published()).is_none(),
                "len {cut}"
            );
        }
        // A one-byte-truncated frame (byte 53) still carries a full TCP header
        // through the flags/port, so it is correctly still classified.
        assert!(blocked_syn(&full[..full.len() - 1], &allowed, &none_published()).is_some());
    }

    /// The empty listen-published set: the shape of every gate before the
    /// box's watcher publishes anything (NET-016).
    fn none_published() -> HashSet<u16> {
        HashSet::new()
    }

    /// NET-016/NET-017's gate half: a port a box's process published by
    /// listening is admitted for its listener's lifetime and withdrawn —
    /// connections and all — when the listener closes, while a declared
    /// port's admission is the declaration's and never moves. The watcher's
    /// own end-to-end proofs live in [`super::listeners`]; this is the
    /// admission-set half they observe from outside.
    #[test]
    fn gate_admits_and_withdraws_a_listen_published_port() {
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                }],
                // A permit range with no stance permits nothing, so this
                // gate's own rules would refuse 9999 — publishing is the
                // watcher's decision to apply, not the gate's to re-derive.
                dynamic_allowed_range: Some((3000, 3010)),
                dynamic_ingress: None,
            }),
            egress: None,
        };
        let gate = SessionGate::for_session(
            "100.64.0.9".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            &policy,
            SwitchSubnet::default(),
        );
        assert!(!gate.admits_tcp(9999), "nothing is published yet");
        // The declared port is admitted by its declaration alone.
        assert!(gate.admits_tcp(80));
        assert_eq!(
            gate.listen_verdict(sessions::IpProto::Tcp, 9999),
            ListenVerdict::Deny
        );
        assert_eq!(
            gate.listen_verdict(sessions::IpProto::Tcp, 80),
            ListenVerdict::Declared
        );
        assert_eq!(
            gate.listen_verdict(sessions::IpProto::Tcp, 3005),
            ListenVerdict::Deny,
            "no stance: the range alone publishes nothing"
        );

        // The watcher publishes 9999: the runtime-published half admits it,
        // beside the declared set.
        gate.admit_published(9999);
        assert!(gate.admits_tcp(9999));
        assert!(
            blocked_syn(
                &tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999),
                &gate.allowed,
                &gate.listen_published.lock().unwrap(),
            )
            .is_none(),
            "a new inbound connection to a published port passes the SYN gate"
        );
        assert!(
            !gate.admits_direct_tcp(9999),
            "the proxy's declared-port gate is untouched by a publication"
        );

        // The listener closes: the admission goes with it, the declared
        // port's stays.
        assert_eq!(gate.withdraw_published(9999), 0, "no connection was held");
        assert!(!gate.admits_tcp(9999));
        assert!(gate.admits_tcp(80), "the declaration's port is still held");
        // Withdrawing something never published is a no-op, and withdrawing
        // a declared port changes nothing: its admission is not the
        // watcher's to take (NET-081's sub-requirement).
        assert_eq!(gate.withdraw_published(1234), 0);
        assert_eq!(gate.withdraw_published(80), 0);
        assert!(gate.admits_tcp(80));
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
                dynamic_ingress: None,
            }),
            egress: None,
        };
        let gate = SessionGate::for_session(
            "100.64.0.9".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            &policy,
            SwitchSubnet::default(),
        );
        assert!(gate.allowed.contains(&80)); // TCP internal port
        assert!(!gate.allowed.contains(&53)); // the UDP mapping is not a TCP port
        assert!(!gate.allowed.contains(&18080)); // external port is not the listener
        assert!(gate.udp_allowed.contains(&53)); // UDP internal port
        assert!(!gate.udp_allowed.contains(&80)); // the TCP mapping is not a UDP port
        // A no-ingress own-IP session denies every new inbound connection/datagram.
        let empty = SessionGate::for_session(
            "x".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            &sessions::SessionPolicy::default(),
            SwitchSubnet::default(),
        );
        assert!(empty.allowed.is_empty() && empty.udp_allowed.is_empty());
    }

    /// The synthesized frame the proxy's verdict reads names the connection's
    /// destination port: `tcp_frame_summary` writes it at the offset
    /// `egress::summarize` extracts it from (`ip[ihl + 2..ihl + 4]`, the two
    /// bytes after the IPv4 header), not the L4 source-port slot inside it, so
    /// the summary a proxied request is put to and the one a direct
    /// connection's frame carries are the same at the port level (NET-070,
    /// NET-071) and a port-shaped rule the egress verdict ever grows sees the
    /// port the request named. Its source is the lease the rules carry, so the
    /// verdict's lease check (NET-084) reads the frame as the box's own.
    #[test]
    fn tcp_frame_summary_names_the_destination_port() {
        let lease = Ipv4Addr::new(100, 64, 0, 9);
        let dst = Ipv4Addr::new(100, 64, 0, 5);
        for port in [1u16, 53, 1024, 8080, u16::MAX] {
            assert_eq!(
                tcp_frame_summary(lease, dst, port).destination_port(),
                port,
                "the summary must carry destination port {port}"
            );
        }
        // The rest of the summary is the frame's own: the source and address
        // the verdict decides by — the lease it was compiled with and the
        // destination it was asked about — and no port to read when there is
        // none.
        let summary = tcp_frame_summary(lease, dst, 8080);
        assert_eq!(summary.source(), Some(lease.octets()));
        assert_eq!(summary.destination(), Some(dst.octets()));
        assert_eq!(summary.protocol(), Some(IPPROTO_TCP));
        assert_eq!(tcp_frame_summary(lease, dst, 0).destination_port(), 0);
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

    /// The box's own switch IP, the lease every egress frame below carries —
    /// shared with the DNS gate's tests.
    pub(crate) const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
    /// The second peer of the per-source-budget proofs: a source the
    /// flooding peer beside it must not silence.
    const OTHER_PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 6);

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

    /// The DNS gate's inbound pre-check reads the EtherType and the IPv4
    /// protocol byte and nothing else, so the relay's hot path spends three
    /// comparisons on a peer's TCP frames rather than a full parse — and it
    /// only ever *narrows*: every frame it rejects is one `udp_datagram` could
    /// not have read anyway, and every frame it admits is still parsed and
    /// length-checked before the gate reads a word of it.
    #[test]
    fn udp_precheck_narrows_without_losing_datagrams() {
        // A UDP frame passes the pre-check and parses as a datagram.
        let udp = udp_frame(PEER, 33333, LEASE, 53);
        assert!(is_ipv4_udp(&udp));
        assert!(udp_datagram(&udp).is_some());

        // A peer's TCP, ARP, and IPv6: the traffic that dominates the
        // inbound leg, none of it a datagram the gate could observe.
        for frame in [
            &tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, SRC, 9999)[..],
            &arp_frame(LEASE)[..],
            &ipv6_frame()[..],
        ] {
            assert!(!is_ipv4_udp(frame), "rejected: {frame:02x?}");
            assert!(udp_datagram(frame).is_none());
        }

        // A frame too short to carry the bytes the pre-check reads: the same
        // `None` the parse would give, never a misclassification.
        for cut in [0, 14, 20, 23] {
            assert!(!is_ipv4_udp(&udp[..cut]), "len {cut}");
            assert!(udp_datagram(&udp[..cut]).is_none(), "len {cut}");
        }
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
                dynamic_ingress: None,
            }),
            egress: None,
        };
        let gate =
            SessionGate::for_session(LEASE.to_string(), LEASE, &policy, SwitchSubnet::default());
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
    pub(crate) struct RelayHarness {
        /// The "box" end of the socketpair: frames written here are the
        /// box's egress; frames the relay writes back would be its answers.
        pub(crate) box_end: std::fs::File,
        /// The gvproxy side of the duplex: the relay's framed output.
        pub(crate) switch: tokio::io::DuplexStream,
        /// Keeps the relay's legs alive for the harness's lifetime.
        _relay: SwitchRelay,
    }

    /// Spawns a gated relay for a box at [`LEASE`] on the default switch
    /// subnet (whose gateway is the resolver the carve-out is keyed to),
    /// under `policy`.
    pub(crate) fn spawn_test_relay(policy: &sessions::SessionPolicy) -> RelayHarness {
        spawn_test_relay_with(policy, |_| {})
    }

    /// [`spawn_test_relay`] with the session gate handed to `configure`
    /// before the relay takes it: the DNS-gate proofs are the callers, for
    /// the things a policy cannot say — the admission window and the flow
    /// idle cap, shrunk short enough that their expiry is observable inside
    /// a test.
    pub(crate) fn spawn_test_relay_with(
        policy: &sessions::SessionPolicy,
        configure: impl FnOnce(&mut SessionGate),
    ) -> RelayHarness {
        spawn_relay_for(LEASE, Some(policy), configure)
    }

    /// Spawns the daemon's own relay shape: no gate, the daemon's address as
    /// its lease — what the guest's root egress attach runs (`guest.rs`).
    fn spawn_daemon_relay(lease: Ipv4Addr) -> RelayHarness {
        spawn_relay_for(lease, None, |_| {})
    }

    /// The relay both harnesses share: a box's gated relay under `policy`, or
    /// the daemon's own ungated one (`policy` is `None`), attached with
    /// `lease` on the default switch subnet. The gate, when there is one, is
    /// handed to `configure` before the relay takes it — the DNS-gate proofs
    /// are the callers, for the things a policy cannot say.
    fn spawn_relay_for(
        lease: Ipv4Addr,
        policy: Option<&sessions::SessionPolicy>,
        configure: impl FnOnce(&mut SessionGate),
    ) -> RelayHarness {
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
        let gate = policy
            .map(|policy| {
                SessionGate::for_session(lease.to_string(), lease, policy, SwitchSubnet::default())
            })
            .map(|mut gate| {
                configure(&mut gate);
                Arc::new(gate)
            });
        let relay = spawn_relay(
            tap_fd,
            sock_rx,
            sock_tx,
            gate,
            lease,
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
    pub(crate) async fn read_framed(switch: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        switch.read_exact(&mut len_buf).await?;
        let n = u16::from_le_bytes(len_buf) as usize;
        let mut frame = vec![0u8; n];
        switch.read_exact(&mut frame).await?;
        Ok(frame)
    }

    /// An ARP frame from `spa`: address resolution, a declared path for every
    /// box from its own source — the sentinel that says "everything before me
    /// has been decided". The payload is a full Ethernet/IPv4 ARP request,
    /// whose sender protocol address is the source the lease check (NET-084)
    /// reads.
    pub(crate) fn arp_frame(spa: Ipv4Addr) -> Vec<u8> {
        arp_frame_of_ptype(spa, 0x0800)
    }

    /// An ARP frame from `spa` claiming `ptype` as its protocol type —
    /// everything else matches [`arp_frame`]. The lease check reads the
    /// sender protocol address slot whatever the frame claims it speaks, so
    /// a foreign protocol type is no way to announce an address unchecked.
    fn arp_frame_of_ptype(spa: Ipv4Addr, ptype: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst MAC: broadcast
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        f.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        f.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        f.extend_from_slice(&ptype.to_be_bytes()); // ptype: as claimed
        f.push(6); // hlen
        f.push(4); // plen
        f.extend_from_slice(&1u16.to_be_bytes()); // oper: request
        f.extend_from_slice(&[0x52, 0x54, 0x00, 0x40, 0x00, 0x09]); // sender MAC
        f.extend_from_slice(&spa.octets()); // sender protocol address
        f.extend_from_slice(&[0; 6]); // target MAC (unread in a request)
        f.extend_from_slice(&Ipv4Addr::new(100, 64, 0, 1).octets()); // target protocol address
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

    /// An Ethernet II + IPv4 + TCP frame the box sends to `dst`:`dst_port`
    /// from a fixed ephemeral source port — a new connection (SYN).
    pub(crate) fn egress_tcp_frame(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        egress_tcp_segment(src, 40000, dst, dst_port, SYN)
    }

    /// An Ethernet II + IPv4 + TCP segment the box sends to
    /// `dst`:`dst_port` from `src_port` with `flags` — [`egress_tcp_frame`]
    /// with the source port and the flags the DNS gate's retention proof
    /// varies: a flow opens on a SYN, rides on an ACK and ends on a FIN or
    /// RST, and the flow a second SYN belongs to is told apart by its source
    /// port.
    pub(crate) fn egress_tcp_segment(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
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
        f.extend_from_slice(&src_port.to_be_bytes());
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
        let sentinel = arp_frame(LEASE);
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
        let sentinel = arp_frame(LEASE);
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
        let sentinel = arp_frame(LEASE);
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

    /// NET-014: a SYN to a port the box's ingress declaration does not name is
    /// answered with a reset on the switch side instead of a silent drop — the
    /// connecting peer's `connect` fails at once with connection refused, not
    /// at its timeout — and the box end stays silent: the gate refuses what it
    /// has no mapping for, and the box's kernel never sees a connection it
    /// cannot answer. A port the declaration *does* name is forwarded as
    /// before, so the refusal is the port's, not the peer's.
    #[tokio::test]
    async fn unpublished_port_connection_refused() {
        use crate::net::dns_gate::tests::read_box_frame;

        let capture = crate::test_harness::captured_log();
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
        };
        let mut harness = spawn_test_relay(&policy);

        // The refused connection: a peer's bare SYN on the switch, aimed at a
        // port the declaration does not name.
        let syn = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 9999);
        let mut framed = Vec::with_capacity(2 + syn.len());
        framed.extend_from_slice(&(syn.len() as u16).to_le_bytes());
        framed.extend_from_slice(&syn);
        harness.switch.write_all(&framed).await.unwrap();

        // The answer is a reset built from the SYN: the tuple swapped (the
        // box's address as the source), RST|ACK set, and the acknowledgement
        // the kernel's own refusal carries — the SYN's sequence plus the SYN
        // flag's weight — under a checksum the box's kernel verifies.
        let reset = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("an unpublished port is refused, not timed out")
            .expect("the switch side stays open");
        assert_reset_refuses(&reset, &syn);

        // The box end stays silent: nothing is forwarded, and the box's
        // kernel never sees the connection to refuse itself.
        set_nonblocking(harness.box_end.as_raw_fd()).unwrap();
        let mut probe = [0u8; 1];
        let read = harness.box_end.read(&mut probe);
        assert!(
            matches!(read, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock),
            "nothing is forwarded to the box: got {read:?}"
        );

        // A port the declaration *does* name (its internal side) is still
        // forwarded, so the refusal is the port's, not the peer's.
        let declared = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 80);
        let mut framed = Vec::with_capacity(2 + declared.len());
        framed.extend_from_slice(&(declared.len() as u16).to_le_bytes());
        framed.extend_from_slice(&declared);
        harness.switch.write_all(&framed).await.unwrap();
        let forwarded = read_box_frame(&harness)
            .await
            .expect("the relay keeps forwarding what it admits");
        assert_eq!(
            forwarded, declared,
            "a declared port is forwarded, refusal or no refusal"
        );

        // The refusal says its line, under the ingress leg's own rule, naming
        // the peer and the port it came to (the diagnostics bundle's tail).
        let logged = capture.contents();
        for expected in [
            "network policy violation",
            "session_id=\"100.64.0.9\"",
            "direction=ingress",
            "remote_addr=100.64.0.5:40000",
            "dst_port=9999",
            "rule_matched=\"no ingress mapping\"",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }
    }

    /// Verifies `frame`'s TCP checksum the way the receiving kernel does —
    /// the wire's own test, not the builder's arithmetic recomputed: the
    /// pseudo-header assembled *as bytes* (source, destination,
    /// `[zero][protocol]`, the big-endian TCP length; RFC 793 §3.1) summed
    /// with the segment's own bytes, checksum field left in place, must fold
    /// to `0xffff` (RFC 1071).
    ///
    /// Deliberately independent of [`tcp_checksum`]: a check that recomputes
    /// with the builder's own function inherits whatever byte-order mistake
    /// the builder made, so a wrong pseudo-header passes. Here the byte
    /// order is an explicit construction the reader can hold against the
    /// RFC's layout.
    pub(crate) fn assert_tcp_checksum_verifies_on_the_wire(frame: &[u8]) {
        assert_eq!(frame.len(), 14 + 20 + 20, "an Ethernet + IPv4 + TCP frame");
        let mut summed: Vec<u8> = Vec::with_capacity(12 + 20);
        summed.extend_from_slice(&frame[26..30]); // source
        summed.extend_from_slice(&frame[30..34]); // destination
        summed.push(0); // the pseudo-header's reserved byte
        summed.push(frame[23]); // the transport — TCP
        summed.extend_from_slice(&20u16.to_be_bytes()); // the TCP length
        summed.extend_from_slice(&frame[34..54]); // the segment, checksum in place
        let mut sum: u32 = 0;
        for word in summed.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(
            sum, 0xffff,
            "the checksum folds to 0xffff on the wire — one a receiving kernel \
             verifies, not a reset the peer silently drops: frame {frame:02x?}"
        );
    }

    /// [`tcp_checksum`] matches the wire definition on a fixed vector: the
    /// reset the NET-014 proof's refusal carries — `100.64.0.9:9999 →
    /// 100.64.0.5:40000`, sequence zero, acknowledging a bare SYN (its
    /// sequence plus the SYN flag's weight), data offset `0x50`, RST|ACK —
    /// has checksum `0x23f2` under the RFC's own pseudo-header. The value
    /// is computed off-tree, from a textbook RFC 1071 sum over RFC 793
    /// §3.1's pseudo-header bytes: it pins the word's byte order in a way a
    /// self-recomputed expectation cannot, because a builder that parks the
    /// protocol in the zero byte's place recomputes its own mistake.
    #[test]
    fn tcp_checksum_matches_the_wire_definition() {
        let mut segment = [0u8; 20];
        segment[0..2].copy_from_slice(&9999u16.to_be_bytes());
        segment[2..4].copy_from_slice(&40000u16.to_be_bytes());
        segment[4..8].copy_from_slice(&0u32.to_be_bytes()); // sequence zero
        segment[8..12].copy_from_slice(&1u32.to_be_bytes()); // ack: SYN + its weight
        segment[12] = 0x50; // data offset 5
        segment[13] = 0x14; // RST|ACK
        assert_eq!(
            tcp_checksum(&segment, LEASE, PEER),
            0x23f2,
            "the wire's checksum for this reset, per RFC 793's pseudo-header"
        );
    }

    /// Asserts `reset` is the reset that refuses `syn`: the Ethernet
    /// addresses swapped, the IPv4 and TCP tuples swapped (the box's address
    /// as the source), RST|ACK set, sequence zero, and the acknowledgement
    /// the kernel's own refusal carries — the SYN's sequence plus the SYN
    /// flag's weight — with a checksum the box's kernel verifies (a broken
    /// one would make NET-014 a timeout again).
    fn assert_reset_refuses(reset: &[u8], syn: &[u8]) {
        assert_eq!(reset.len(), 14 + 20 + 20, "an Ethernet + IPv4 + TCP reset");
        assert_eq!(
            &reset[..6],
            &syn[6..12],
            "the reset goes back to the peer that connected"
        );
        assert_eq!(
            &reset[6..12],
            &syn[..6],
            "from the box's own Ethernet identity"
        );
        assert_eq!(&reset[12..14], &syn[12..14], "EtherType IPv4");
        assert_eq!(reset[14] & 0x0f, 5, "IPv4 IHL 5");
        assert_eq!(reset[23], IPPROTO_TCP, "the refused transport");
        let (src, dst) = (
            Ipv4Addr::new(reset[26], reset[27], reset[28], reset[29]),
            Ipv4Addr::new(reset[30], reset[31], reset[32], reset[33]),
        );
        assert_eq!(src, LEASE, "the box's own address as the source");
        assert_eq!(dst, PEER, "the peer as the destination");
        let (sport, dport) = (
            u16::from_be_bytes([reset[34], reset[35]]),
            u16::from_be_bytes([reset[36], reset[37]]),
        );
        assert_eq!(sport, 9999, "the refused port as the reset's source");
        assert_eq!(dport, 40000, "the peer's port as the reset's destination");
        let (seq, ack) = (
            u32::from_be_bytes([reset[38], reset[39], reset[40], reset[41]]),
            u32::from_be_bytes([reset[42], reset[43], reset[44], reset[45]]),
        );
        assert_eq!(seq, 0, "a refusal to a bare SYN resets from zero");
        assert_eq!(
            ack, 1,
            "the acknowledgement rides the SYN: its sequence plus the SYN flag"
        );
        assert_eq!(reset[46], 0x50, "TCP data offset 5");
        assert_eq!(reset[47], 0x14, "RST|ACK: a refusal, not an acceptance");
        // The checksum, verified the way the box's kernel verifies it: the
        // wire's own fold over the pseudo-header and the segment — not the
        // builder's arithmetic recomputed, which would inherit any
        // byte-order mistake the builder made.
        assert_tcp_checksum_verifies_on_the_wire(reset);
    }

    /// [`tcp_frame`] with the sequence and acknowledgement numbers an
    /// established flow's segments carry — the numbers the gate's recorded
    /// tail reads, and the ones the revocation's terminating reset rides.
    fn tcp_segment_with_numbers(
        flags: u8,
        src: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, flags, src, dst_port);
        frame[38..42].copy_from_slice(&seq.to_be_bytes());
        frame[42..46].copy_from_slice(&ack.to_be_bytes());
        frame
    }

    /// The one declared ingress of the reset-shape and revocation proofs:
    /// host `:8080` forwarding to the box's `:80`.
    fn declared_ingress_80() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 8080,
                    internal_port: 80,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
        }
    }

    /// Asserts `reset` is the termination of the flow the gate recorded a
    /// tail for — `(PEER, 40000) → (LEASE, 80)` — riding that tail's own
    /// sequence pair (`seq` what the flow's peer expects next of the box,
    /// `ack` what the box acknowledged of the peer's stream), with the tuple
    /// swapped so the reset is addressed to the segment's source and a
    /// checksum the receiver's kernel verifies.
    fn assert_reset_terminates_flow(reset: &[u8], seq: u32, ack: u32) {
        assert_eq!(reset.len(), 14 + 20 + 20, "an Ethernet + IPv4 + TCP reset");
        assert_eq!(
            &reset[12..14],
            &ETHERTYPE_IPV4.to_be_bytes(),
            "EtherType IPv4"
        );
        assert_eq!(reset[23], IPPROTO_TCP, "the refused transport");
        let source = (
            Ipv4Addr::new(reset[26], reset[27], reset[28], reset[29]),
            u16::from_be_bytes([reset[34], reset[35]]),
        );
        let destination = (
            Ipv4Addr::new(reset[30], reset[31], reset[32], reset[33]),
            u16::from_be_bytes([reset[36], reset[37]]),
        );
        assert_eq!(source, (LEASE, 80), "the reset speaks for the box's port");
        assert_eq!(
            destination,
            (PEER, 40000),
            "the reset is addressed to the segment's source"
        );
        assert_eq!(
            u32::from_be_bytes([reset[38], reset[39], reset[40], reset[41]]),
            seq,
            "the reset rides the sequence pair the gate tracked"
        );
        assert_eq!(
            u32::from_be_bytes([reset[42], reset[43], reset[44], reset[45]]),
            ack,
            "the reset acknowledges what the gate tracked"
        );
        assert_eq!(reset[47], 0x14, "RST|ACK: a termination");
        assert_tcp_checksum_verifies_on_the_wire(reset);
    }

    /// Asserts `reset` is the termination a revocation writes **into the
    /// tap**, toward the box — the other end of the flow whose last packet
    /// was `observed`: the Ethernet and IPv4 tuples stay as the flow's own
    /// (the peer is still the source, the box still the destination), the
    /// reset rides the **peer's** sequence (`seq`, the peer's next sequence
    /// the box is windowed to receive) and acknowledges what the peer last
    /// acknowledged (`ack`), with a checksum the box's kernel verifies.
    fn assert_reset_toward_box_terminates_flow(reset: &[u8], observed: &[u8], seq: u32, ack: u32) {
        assert_eq!(reset.len(), 14 + 20 + 20, "an Ethernet + IPv4 + TCP reset");
        assert_eq!(&reset[..6], &observed[..6], "still to the box's own MAC");
        assert_eq!(&reset[6..12], &observed[6..12], "still from the peer's MAC");
        assert_eq!(
            &reset[12..14],
            &ETHERTYPE_IPV4.to_be_bytes(),
            "EtherType IPv4"
        );
        assert_eq!(reset[23], IPPROTO_TCP, "the refused transport");
        let source = (
            Ipv4Addr::new(reset[26], reset[27], reset[28], reset[29]),
            u16::from_be_bytes([reset[34], reset[35]]),
        );
        let destination = (
            Ipv4Addr::new(reset[30], reset[31], reset[32], reset[33]),
            u16::from_be_bytes([reset[36], reset[37]]),
        );
        assert_eq!(
            source,
            (PEER, 40000),
            "the reset arrives speaking for the peer"
        );
        assert_eq!(
            destination,
            (LEASE, 80),
            "addressed to the box's own port, into the tap"
        );
        assert_eq!(
            u32::from_be_bytes([reset[38], reset[39], reset[40], reset[41]]),
            seq,
            "at the peer's next sequence, the one the box is windowed to receive"
        );
        assert_eq!(
            u32::from_be_bytes([reset[42], reset[43], reset[44], reset[45]]),
            ack,
            "acknowledging what the peer last acknowledged"
        );
        assert_eq!(reset[47], 0x14, "RST|ACK: a termination");
        assert_tcp_checksum_verifies_on_the_wire(reset);
    }

    /// The gate's two reset shapes (NET-014, NET-121, RFC 793 §3.4), and the
    /// one non-shape a spoofing peer must find: a reset is built only from
    /// state the gate holds. A bare SYN is refused the way a kernel refuses a
    /// connection — RST|ACK from sequence zero, acknowledging the SYN — a
    /// connection the gate ended is reset from the sequence pair the gate
    /// tracked for it, in the peer's window by construction, and a segment of
    /// a flow the gate holds nothing for is answered with no reset at all:
    /// its own numbers are its sender's claim, never this box's answer.
    #[test]
    fn refused_resets_carry_the_two_shapes_and_only_held_flows() {
        let gate = SessionGate::for_session(
            LEASE.to_string(),
            LEASE,
            &declared_ingress_80(),
            SwitchSubnet::default(),
        );
        let mut resets = gate
            .take_resets()
            .expect("a gate's reset channel is taken exactly once");
        let mut box_resets = gate
            .take_box_resets()
            .expect("a gate's box-directed reset channel is taken exactly once");

        // Shape one: a bare SYN to an unpublished port, answered with the
        // kernel's own connection-refused shape, addressed to the SYN's
        // source.
        let syn = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 9999);
        let syn_pkt = parse_ipv4_l4(&syn).expect("the SYN parses");
        assert!(gate.refuse_tcp_segment(&syn, &syn_pkt));
        let refused = resets
            .try_recv()
            .expect("the refused SYN is answered at once");
        assert_reset_refuses(&refused, &syn);

        // The flow the gate will hold a tail for: an established connection
        // to the declared port, recorded the way the relay records every
        // admitted segment.
        let established = tcp_segment_with_numbers(ACK, PEER, 80, 1001, 5001);
        let established_pkt = parse_ipv4_l4(&established).expect("the segment parses");
        gate.record_inbound(&established_pkt, &established);

        // Shape two: the revocation terminates that flow with a reset riding
        // the sequence pair the gate tracked for it.
        assert_eq!(gate.revoke_port(80), 1, "the recorded flow is terminated");
        let terminated = resets
            .try_recv()
            .expect("the revocation answers the flow it held");
        assert_reset_terminates_flow(&terminated, 5001, 1001);
        // The same revocation ends the box's half of the flow: a reset written
        // into the tap, from the peer's address at the peer's next sequence —
        // the sequence the box's socket is windowed to receive.
        let toward_box = box_resets
            .try_recv()
            .expect("the revocation ends the box's half too");
        assert_reset_toward_box_terminates_flow(&toward_box, &established, 1001, 5001);

        // The ended connection's own straggler — a segment carrying numbers
        // the gate never tracked — is answered from the same tail, so the
        // self-healing reset stays in the window the gate watched.
        let straggler = tcp_segment_with_numbers(ACK, PEER, 80, 2001, 6001);
        let straggler_pkt = parse_ipv4_l4(&straggler).expect("the straggler parses");
        assert!(gate.refuse_tcp_segment(&straggler, &straggler_pkt));
        let healed = resets
            .try_recv()
            .expect("the ended connection's straggler is answered");
        assert_eq!(
            healed, terminated,
            "the self-healing reset rides the tracked tail, never the straggler's numbers"
        );
        assert!(
            box_resets.try_recv().is_err(),
            "the box's half was ended once, by the revocation: a straggler heals \
             toward the peer only"
        );

        // A segment of a flow the gate holds nothing for — the spoofed
        // straggler — is answered with no reset at all, so this box can never
        // be made to emit a reset carrying a spoofed sequence to a victim.
        let spoofed = tcp_segment_with_numbers(ACK, OTHER_PEER, 80, 0xdead_beef, 0xfeed_face);
        let spoofed_pkt = parse_ipv4_l4(&spoofed).expect("the segment parses");
        assert!(!gate.refuse_tcp_segment(&spoofed, &spoofed_pkt));
        assert!(
            resets.try_recv().is_err(),
            "no reset is built for a flow the gate holds nothing for"
        );
    }

    /// RFC 793's one forbidden exchange: a reset is never answered with a
    /// reset — the ended connection's own RST|ACK stragglers get no reply at
    /// all, and charge no refusal budget either, so an ended connection
    /// cannot spend its peer's window on answers that cannot exist (a
    /// peer-side flood of RSTs still leaves the source its full budget for
    /// the SYN it might send next).
    #[test]
    fn a_reset_is_never_answered_with_a_reset_and_spends_no_budget() {
        let capture = crate::test_harness::captured_log();
        let gate = SessionGate::for_session(
            LEASE.to_string(),
            LEASE,
            &declared_ingress_80(),
            SwitchSubnet::default(),
        );
        let mut resets = gate
            .take_resets()
            .expect("a gate's reset channel is taken exactly once");
        let mut box_resets = gate
            .take_box_resets()
            .expect("a gate's box-directed reset channel is taken exactly once");

        // The flow the gate will end: an established connection to the
        // declared port, recorded the way the relay records every admitted
        // segment, then revoked — so the segment below arrives for a flow in
        // `terminated_flows`, the one shape the gate could answer.
        let established = tcp_segment_with_numbers(ACK, PEER, 80, 1001, 5001);
        let established_pkt = parse_ipv4_l4(&established).expect("the segment parses");
        gate.record_inbound(&established_pkt, &established);
        assert_eq!(gate.revoke_port(80), 1, "the recorded flow is terminated");
        let _ = resets.try_recv();
        let _ = box_resets.try_recv();

        // The reset the ended connection's peer sends: RST|ACK, on the very
        // flow the gate terminated. It is answered with nothing — not with
        // the reset RFC 793 forbids replying to.
        let straggler = tcp_segment_with_numbers(RST | ACK, PEER, 80, 1001, 5001);
        let straggler_pkt = parse_ipv4_l4(&straggler).expect("the reset parses");
        assert!(
            !gate.refuse_tcp_segment(&straggler, &straggler_pkt),
            "a reset is never answered with a reset"
        );
        assert!(
            resets.try_recv().is_err(),
            "the reset gets no reply on the switch side"
        );
        assert!(box_resets.try_recv().is_err(), "and none toward the box");

        // And it charges no budget: the same source's resets arrive in
        // numbers no window would answer, and the source is still owed every
        // refusal it had — the next SYN is answered, and no budget line was
        // ever spent on the resets that came first.
        for seq in 0..RESET_PER_WINDOW + 8 {
            let flood = tcp_segment_with_numbers(RST | ACK, PEER, 80, 1001 + seq, 5001);
            let flood_pkt = parse_ipv4_l4(&flood).expect("the reset parses");
            assert!(!gate.refuse_tcp_segment(&flood, &flood_pkt));
        }
        assert!(
            resets.try_recv().is_err(),
            "not one of the resets was answered"
        );
        let syn = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 9999);
        let syn_pkt = parse_ipv4_l4(&syn).expect("the SYN parses");
        assert!(
            gate.refuse_tcp_segment(&syn, &syn_pkt),
            "the resets charged no budget: the source is still answered"
        );
        assert!(
            resets.try_recv().is_ok(),
            "the SYN's refusal is the reset it was owed"
        );
        assert!(
            !capture.contents().contains("stopping TCP resets"),
            "no budget was ever spent on the resets: {}",
            capture.contents()
        );
    }

    /// The reset channel is bounded: a gate whose switch-side writer is not
    /// draining still answers — the send past the bound is dropped, never
    /// queued, never blocking — so no box's flood can grow the daemon's
    /// memory through it. Exactly the channel's capacity arrives; the excess
    /// is gone.
    #[test]
    fn the_reset_channel_is_bounded_and_the_excess_is_dropped() {
        let gate = SessionGate::for_session(
            LEASE.to_string(),
            LEASE,
            &declared_ingress_80(),
            SwitchSubnet::default(),
        );
        let mut resets = gate
            .take_resets()
            .expect("a gate's reset channel is taken exactly once");

        for _ in 0..RESET_CHANNEL_CAPACITY + 32 {
            gate.send_reset(vec![0u8; 54]);
        }
        let mut held = 0;
        while resets.try_recv().is_ok() {
            held += 1;
        }
        assert_eq!(
            held, RESET_CHANNEL_CAPACITY,
            "the channel holds its bound and drops the rest"
        );
    }

    /// The per-source refusal budget: one source spends its window's refusals
    /// and then waits for the window to roll — degrading alone, while a
    /// second source in the same window is still answered — and the first
    /// refused-over attempt says one audited line per window, not one per
    /// refusal.
    #[test]
    fn the_reset_budget_spends_per_source_and_says_one_line_per_window() {
        let capture = crate::test_harness::captured_log();
        let mut budget = ResetBudget::default();
        // A window short enough to watch it roll inside a test.
        budget.shrink_window(Duration::from_millis(50));
        let flooder = Ipv4Addr::new(100, 64, 0, 77);
        let quiet = Ipv4Addr::new(100, 64, 0, 78);

        for _ in 0..RESET_PER_WINDOW {
            assert!(budget.admit(flooder, "box"), "the window opens with budget");
        }
        // Past the cap the flooder is refused its resets until the window
        // rolls — and the refusal says one line per window, not one per
        // refused attempt.
        for _ in 0..4 {
            assert!(
                !budget.admit(flooder, "box"),
                "the flooder has spent its window's refusals"
            );
        }
        assert_eq!(
            capture.contents().matches("stopping TCP resets").count(),
            1,
            "one audited line per source per window: {}",
            capture.contents()
        );

        // Nobody else pays for the flood: a second source in the same window
        // is still answered.
        assert!(budget.admit(quiet, "box"), "the flooder degrades alone");

        // The window rolls and the flooder's budget returns with it.
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            budget.admit(flooder, "box"),
            "a new window opens the flooder's budget again"
        );
    }

    /// NET-014's refusal, bounded end to end: a peer that floods the box's
    /// unpublished ports is answered until its window's refusals are spent
    /// and then degrades to the timeout the reset replaced — while another
    /// peer's connection in the same window is still refused at once, so the
    /// flood costs its source alone. The flood's own line says it once.
    #[tokio::test]
    async fn refused_resets_are_budgeted_per_source() {
        let capture = crate::test_harness::captured_log();
        let mut harness = spawn_test_relay_with(&declared_ingress_80(), |gate| {
            gate.reset_budget.shrink_window(Duration::from_millis(120));
        });

        // The flood: one more refused SYN than the window pays for, then a
        // second peer's connection behind it — answered only if the budget
        // is the source's, not the box's. Every frame rides the relay's own
        // framing, one length prefix per frame.
        let flood = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, PEER, 9999);
        let other = tcp_frame(ETHERTYPE_IPV4, IPPROTO_TCP, SYN, OTHER_PEER, 9999);
        let mut framed = Vec::with_capacity((2 + flood.len()) * (RESET_PER_WINDOW as usize + 4));
        for _ in 0..RESET_PER_WINDOW + 3 {
            framed.extend_from_slice(&(flood.len() as u16).to_le_bytes());
            framed.extend_from_slice(&flood);
        }
        framed.extend_from_slice(&(other.len() as u16).to_le_bytes());
        framed.extend_from_slice(&other);
        harness.switch.write_all(&framed).await.unwrap();

        // Read the relay's answers until the second peer's reset arrives: the
        // flood's answers all precede it on the wire, so what came before it
        // is everything the flood was ever owed.
        let mut flood_resets = 0usize;
        let mut other_reset = None;
        for _ in 0..RESET_PER_WINDOW + 8 {
            let frame =
                tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                    .await
                    .expect("the relay answers within the test's bound")
                    .expect("the switch side stays open");
            let destination = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
            if destination == PEER {
                flood_resets += 1;
            } else if destination == OTHER_PEER {
                other_reset = Some(frame);
                break;
            }
        }
        assert!(
            other_reset.is_some(),
            "another peer's refused connection is still answered behind the flood"
        );
        assert_eq!(
            flood_resets, RESET_PER_WINDOW as usize,
            "the flooder spent exactly its window's refusals, then degraded to a timeout"
        );
        assert_eq!(
            capture.contents().matches("stopping TCP resets").count(),
            1,
            "the flood is audited once: {}",
            capture.contents()
        );
    }

    /// The denied source box of the box-zone connection proof: TCP declared,
    /// every destination refused — the reach this box can ever hold is the
    /// one its own `allow_subnets` names, and a zone name's resolution (which
    /// asks for no entry, NET-072) grants it nothing: the answer pins no
    /// address, so its half of the connect-time conjunction is decided by the
    /// subnets it declared alone.
    fn zone_source_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        }
    }

    /// The declared source box of the same proof: the sibling's lease, and it
    /// alone, named by a CIDR entry — the one spelling a sibling is reached
    /// by, where the denied box above resolves the very same name and is
    /// refused, so the pair says the reach is the entry's, never the
    /// resolution's.
    fn zone_declared_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(vec![format!("{ZONE_TARGET}/32")]),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        }
    }

    /// The target box of the same proof: one published TCP port at its own
    /// number — the internal port a direct connection terminates on — so its
    /// ingress gate admits that port alone and every other port is a refusal
    /// the source's half cannot lift.
    fn zone_target_policy() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: None,
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: ZONE_TARGET_PORT,
                    internal_port: ZONE_TARGET_PORT,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
        }
    }

    /// The three boxes the box-zone proofs connect, and the port the target
    /// publishes. Leases no other proof uses: each caller's gate is looked up
    /// by lease in [`LIVE_GATES`], which is process-wide under the libtest
    /// target's shared process.
    const ZONE_SOURCE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 10);
    const ZONE_DECLARED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 12);
    const ZONE_TARGET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 11);
    const ZONE_TARGET_PORT: u16 = 8080;

    /// NET-073 end to end, across live boxes' relays — with NET-072's
    /// resolution riding in front of it: a box resolves its sibling's zone
    /// name with no allowlist entry for it, and the connection that follows
    /// succeeds only when both boxes' rules allow it. The connection is
    /// decided at the target's relay, on the SYN itself, against both
    /// policies at once — the target's ingress gate beside the source's own
    /// egress verdict — and the source's half is its declared subnets alone:
    /// a sibling is reached by the CIDR entry that names its lease (the
    /// declared caller below) and never by a name-scoped grant (the caller
    /// whose rules omit the lease, whose resolution pinned nothing), which is
    /// the same pair the landed NET-070 e2e proof makes with a dropped SYN.
    /// Each decision is said in one debug line carrying the source box, the
    /// target box and each side's verdict, while each refusal is also a warn
    /// line through the shared limiter, so the daemon log (the diagnostics
    /// bundle's tail) names both boxes and the refusing rule for every
    /// refused box-zone connection.
    #[tokio::test]
    async fn box_zone_connection_enforced_at_connect() {
        use crate::net::dns_gate::tests::{
            RESOLVER, dns_query, dns_response, read_box_frame, udp_payload_frame, wire_frame,
        };
        use hickory_proto::rr::RecordType;

        // The debug line is the test's window on the connect-time decision,
        // so the capture reads at DEBUG — the harness's global capture reads
        // at INFO and would never see it.
        let capture = crate::test_harness::CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // Three live boxes: the two callers — one whose `allow_subnets`
        // names the target's lease, one whose rules omit it — and the target
        // between them. Each caller's half is looked up by lease in
        // [`LIVE_GATES`], so both relays must be live for their verdicts to
        // be consulted at all.
        let mut declared = spawn_relay_for(ZONE_DECLARED, Some(&zone_declared_egress()), |_| {});
        let mut source = spawn_relay_for(ZONE_SOURCE, Some(&zone_source_egress()), |_| {});
        let mut target = spawn_relay_for(ZONE_TARGET, Some(&zone_target_policy()), |_| {});
        // A new connection from either caller to the target, and the ARP
        // sentinel that stands behind a refused one: whatever has reached the
        // target's box end when the sentinel does is everything the relay
        // admitted.
        let connect =
            |src: Ipv4Addr, port: u16| egress_tcp_segment(src, 40000, ZONE_TARGET, port, SYN);
        let sentinel = arp_frame(ZONE_SOURCE);

        // Case 1 — the declared caller reaches the sibling by CIDR: its
        // `allow_subnets` names the target's lease and the target published
        // the port. The caller's own leg forwards the SYN — the CIDR entry is
        // what carries the connection out of its box — and the target's
        // relay, reading the same verdict on the SYN itself, admits both
        // halves, so the SYN reaches the box exactly as the switch sent it.
        let allowed = connect(ZONE_DECLARED, ZONE_TARGET_PORT);
        declared.box_end.write_all(&allowed).unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut declared.switch))
                .await
                .expect("the declared caller's own leg forwards the SYN")
                .expect("the switch side stays open");
        assert_eq!(
            forwarded, allowed,
            "the CIDR entry carries the connection out of the caller's own box"
        );
        target
            .switch
            .write_all(&wire_frame(&allowed))
            .await
            .unwrap();
        let reached = read_box_frame(&target)
            .await
            .expect("both halves allow: the SYN reaches the target box");
        assert_eq!(
            reached, allowed,
            "a connection both boxes' rules allow reaches the target box"
        );
        // Both halves are said, and nothing is logged against it.
        let logged = capture.contents();
        for expected in [
            "box-zone connection decided at connect",
            "source=100.64.0.12",
            "target=100.64.0.11",
            "source_pass=true",
            "target_pass=true",
            "port=8080",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }
        assert_eq!(
            logged.matches("network policy violation").count(),
            0,
            "an allowed box-zone connection is not a violation: {logged}"
        );

        // Case 2 — the caller with no CIDR grant is refused even after
        // resolving the name. NET-072 rides in first, honestly: the query
        // needs no allowlist entry and the reply is never kept from the box.
        let query = udp_payload_frame(
            ZONE_SOURCE,
            40000,
            RESOLVER,
            53,
            &dns_query("box-b.min.internal.", RecordType::A),
        );
        source.box_end.write_all(&query).unwrap();
        let forwarded_query =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut source.switch))
                .await
                .expect("the query is forwarded")
                .expect("the switch side stays open");
        assert_eq!(
            forwarded_query, query,
            "a zone name needs no allowlist entry"
        );
        let response = udp_payload_frame(
            RESOLVER,
            53,
            ZONE_SOURCE,
            40000,
            &dns_response("box-b.min.internal.", &[ZONE_TARGET]),
        );
        source
            .switch
            .write_all(&wire_frame(&response))
            .await
            .unwrap();
        let passed = read_box_frame(&source)
            .await
            .expect("the reply itself passes through");
        assert_eq!(passed, response, "resolution is honest, reach is governed");

        // The connection is refused on the SYN, at the target's relay: the
        // source's half reads its declared subnets — which name no subnet —
        // so the answer's address is an undeclared destination and the SYN
        // never reaches the box, even though the port it names is one the
        // target publishes (the source's half is decided first, and a
        // refused connection is never put to the target's ingress gate).
        let refused = connect(ZONE_SOURCE, ZONE_TARGET_PORT);
        target
            .switch
            .write_all(&wire_frame(&refused))
            .await
            .unwrap();
        target
            .switch
            .write_all(&wire_frame(&sentinel))
            .await
            .unwrap();
        let reached = read_box_frame(&target)
            .await
            .expect("the relay keeps admitting what its rules allow");
        assert_eq!(
            reached, sentinel,
            "a connection the source's rules refuse never reaches the target box"
        );
        // The refusal is the source's own, named under the source's own
        // label, through the source's own limiter — the very line its egress
        // leg would have said had the frame come from the box instead, which
        // is why the leg's refusal of the same frame below adds no second
        // line: one refusal is one line, whichever leg said it.
        let logged = capture.contents();
        for expected in [
            "source=100.64.0.10",
            "target=100.64.0.11",
            "source_pass=false",
            "target_pass=true",
            "port=8080",
            "network policy violation",
            "session_id=\"100.64.0.10\"",
            "direction=egress",
            "remote_addr=100.64.0.11:8080",
            "rule_matched=\"egress-undeclared-subnet\"",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }

        // The same connection is refused by the source's own leg too: its
        // egress verdict is the conjunction's source half, so the frame never
        // leaves the box in the first place — the unit-level shape of the
        // e2e pair whose denied caller's direct connect is a dropped SYN.
        source.box_end.write_all(&refused).unwrap();
        source.box_end.write_all(&sentinel).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut source.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(
            out, sentinel,
            "the source's own leg refuses the connection its rules deny"
        );
        // The leg's refusal says no second line for it: both legs warn
        // through the source's own limiter, so the same (box, rule) refusal
        // is rate-limited as one, whichever leg saw the frame — the R2.7
        // contract, held across the connect-time half and the leg's own.
        assert_eq!(
            capture
                .contents()
                .matches("network policy violation")
                .count(),
            1,
            "one refusal is one line, whichever leg said it: {}",
            capture.contents()
        );

        // The conjunction is real: a port the target did not declare is
        // refused by the target's own ingress gate even though the source's
        // half admits the address — the declared caller's CIDR names a box,
        // not a right to every port on it.
        let undeclared = connect(ZONE_DECLARED, 9999);
        target
            .switch
            .write_all(&wire_frame(&undeclared))
            .await
            .unwrap();
        target
            .switch
            .write_all(&wire_frame(&sentinel))
            .await
            .unwrap();
        let next = read_box_frame(&target)
            .await
            .expect("the relay keeps admitting what its rules allow");
        assert_eq!(
            next, sentinel,
            "an undeclared port is refused, source's half or no source's half"
        );
        let logged = capture.contents();
        for expected in [
            "source_pass=true",
            "target_pass=false",
            "port=9999",
            // The refusal is the target's own, under the target's own label,
            // naming the source box that came (`remote_addr` is the peer on
            // an ingress line) and the port it came to.
            "session_id=\"100.64.0.11\"",
            "direction=ingress",
            "remote_addr=100.64.0.12:40000",
            "dst_port=9999",
            "rule_matched=\"no ingress mapping\"",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }

        // A source that is not a live box on this daemon's switch — the
        // resolver itself, here — finds no gate and keeps the target's own
        // ingress decision alone: the fabric's traffic is never put to a
        // box's egress rules, and no connect-time line is said for it.
        let fabric = egress_tcp_segment(RESOLVER, 53, ZONE_TARGET, ZONE_TARGET_PORT, SYN);
        target.switch.write_all(&wire_frame(&fabric)).await.unwrap();
        let last = read_box_frame(&target)
            .await
            .expect("the target's own ingress decides fabric traffic");
        assert_eq!(last, fabric);
        let logged = capture.contents();
        assert_eq!(
            logged
                .matches("box-zone connection decided at connect")
                .count(),
            3,
            "one debug line per box-zone connection, and none for the fabric's: {logged}"
        );
        // Each refusal says its own line and nothing else does: the
        // connect-time one under the source's label — the source's own leg
        // refused the same frame above and said no second line for it, one
        // refusal being one line through the limiter the two share — and the
        // target's ingress one.
        assert_eq!(
            logged.matches("network policy violation").count(),
            2,
            "each refusal says its own line, and nothing else does: {logged}"
        );
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
            Ipv4Addr::new(100, 64, 0, 9),
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
                Ipv4Addr::new(10, 0, 0, 9),
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
            Ipv4Addr::new(100, 64, 0, 10),
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

    /// NET-084: a frame whose source is not the relay's lease never reaches
    /// the switch — an IPv4 frame sent from another box's address, or an ARP
    /// frame announcing one as its sender protocol address, whatever
    /// protocol type the ARP claims — and the
    /// rejection says so, once per lease per minute, naming the session, the
    /// lease and the source the frame carried. Frames from the lease itself
    /// are untouched, and a rejected frame opens no conntrack window (its
    /// "reply" is unsolicited inbound and is refused too).
    #[tokio::test]
    async fn relay_rejects_non_lease_source() {
        let capture = crate::test_harness::captured_log();
        // No egress declared: allow-all, so the only rule that can drop a
        // frame below is the source check — the destination is not what
        // fires.
        let mut harness = spawn_test_relay(&sessions::SessionPolicy::default());

        // An IPv4 frame sent from another box's address, then the sentinel.
        let spoofed = egress_tcp_frame(PEER, Ipv4Addr::new(203, 0, 113, 7), 443);
        let sentinel = arp_frame(LEASE);
        harness.box_end.write_all(&spoofed).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(
            first, sentinel,
            "the frame from a foreign source never reached the switch"
        );

        // An ARP frame announcing the foreign address as its sender is
        // rejected the same way: the sender protocol address is a source.
        harness.box_end.write_all(&arp_frame(PEER)).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(
            next, sentinel,
            "the foreign ARP sender never reached the switch"
        );

        // An ARP claiming a protocol type other than IPv4 is no way around
        // the check either: the sender protocol address slot is the source
        // whatever the frame claims to speak, so announcing the peer's
        // address under another protocol is rejected the same way.
        harness
            .box_end
            .write_all(&arp_frame_of_ptype(PEER, 0x1234))
            .unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(
            next, sentinel,
            "the foreign ARP sender under another protocol type never \
             reached the switch"
        );

        // The rejection line names the session, the lease and the source,
        // and is rate-limited: a flood of spoofed frames says one line.
        for _ in 0..3 {
            harness.box_end.write_all(&spoofed).unwrap();
        }
        harness.box_end.write_all(&sentinel).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        let logged = capture.contents();
        assert_eq!(
            logged
                .matches("rule_matched=\"egress-foreign-source\"")
                .count(),
            1,
            "a flood of foreign-source rejections says one line: {logged}"
        );
        for expected in [
            "session_id=\"100.64.0.9\"",
            "lease=100.64.0.9",
            "source=100.64.0.5",
        ] {
            assert!(
                logged.contains(expected),
                "missing {expected:?} in: {logged}"
            );
        }

        // A rejected frame opened no conntrack window: the spoofed datagram
        // below is refused at the source check before the record runs, so
        // its "reply" is unsolicited inbound UDP to an undeclared port and
        // must not reach the box either.
        let own = egress_tcp_frame(LEASE, Ipv4Addr::new(10, 1, 2, 3), 80);
        harness.box_end.write_all(&own).unwrap();
        let own_frame =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                .await
                .expect("the relay forwards the lease's own frame")
                .expect("the switch side stays open");
        assert_eq!(own_frame, own, "the lease's own frames are untouched");

        let spoofed_udp = udp_frame(PEER, 40000, Ipv4Addr::new(1, 1, 1, 1), 53);
        harness.box_end.write_all(&spoofed_udp).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let after = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the sentinel")
            .expect("the switch side stays open");
        assert_eq!(
            after, sentinel,
            "the spoofed datagram never reached the switch"
        );

        // ...and its would-be reply is refused inbound too.
        let reply = udp_frame(Ipv4Addr::new(1, 1, 1, 1), 53, LEASE, 40000);
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
            "a rejected frame must not open a reply window: got {read:?}"
        );
    }

    /// NET-084 at the daemon's own relay: the guest's root egress relay
    /// carries no gate but still rejects a frame whose source is not the
    /// address the daemon attached with — its own — whatever the frame
    /// dresses its source up as, and forwards its own frames untouched.
    #[tokio::test]
    async fn daemon_relay_rejects_foreign_source_too() {
        // The daemon's address on the default switch subnet — the lease its
        // own relay attaches with (`guest.rs`).
        const DAEMON_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 255, 253);
        let mut harness = spawn_daemon_relay(DAEMON_IP);

        let spoofed = egress_tcp_frame(PEER, Ipv4Addr::new(203, 0, 113, 7), 443);
        let odd_arp = arp_frame_of_ptype(PEER, 0x1234);
        let own = egress_tcp_frame(DAEMON_IP, Ipv4Addr::new(10, 1, 2, 3), 80);
        harness.box_end.write_all(&spoofed).unwrap();
        harness.box_end.write_all(&odd_arp).unwrap();
        harness.box_end.write_all(&own).unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay forwards the daemon's own frame")
            .expect("the switch side stays open");
        assert_eq!(
            first, own,
            "the ungated daemon relay still rejects a foreign source — \
             an IPv4 header source and an ARP sender address alike, \
             whatever protocol the ARP claims — and forwards its own frames"
        );
    }
}
