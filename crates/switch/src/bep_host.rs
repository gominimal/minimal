//! The Box Egress Proxy's host leg (`bep_host`): the userspace TCP/IP stack
//! the proxy's listener stands on, over the switch (NET-132).
//!
//! A box with a credentialed lane reaches the proxy by connecting to the
//! leg's address on the switch's plan (NET-134); the connection arrives as
//! Ethernet frames over the switch's L2 lane, whose bytes cross the shuttle
//! length-framed (the 2-byte little-endian prefix the switch socket speaks —
//! the framing `minvmd`'s egress gate relays). The host kernel knows nothing
//! of the switch subnet, so the leg terminates those frames itself: one smoltcp
//! [`Interface`] over a channel-backed [`Device`] that answers ARP for the
//! leg's address, resets TCP to unlistened ports, and answers
//! port-unreachable for UDP with no socket — smoltcp's own answers, not
//! hand-rolled ones, since the leg now holds sockets of its own and every
//! frame it accepts goes through the interface.
//!
//! Those sockets are the proxy's listener pool, this task's work: a pool of
//! listening TCP sockets at [`PROXY_PORT`] on the leg's address, partitioned
//! per registered box ([`BepBoxSource`]) so each box's share is
//! [`BepWire::per_source_cap`] sockets — added when its row registers,
//! withdrawn when the row goes. An accepted socket's remote endpoint names
//! the box that connected; a connection from a source at or past its share's
//! cap is aborted, so one box's exhaustion can never take a sibling's
//! sockets: the pool's total is the sum of the shares, and every live
//! connection counts against its own box alone.
//!
//! Each connection the cap admits is delivered to the proxy's acceptor on
//! its unix socket ([`BepWire::proxy_sock`]): one dial per flow, never
//! reused, carrying the per-boot token ([`TOKEN_LEN`] bytes) and then one
//! fixed header ([`DeliveryHeader`]) ahead of any flow byte — the proxy
//! learns which box's connection this is from the header, and the bytes
//! pump both ways under the socket's own window: the smoltcp receive buffer
//! is the TCP window the box sees, the channel to the acceptor is bounded,
//! and when either side stops reading the window closes on the sender. An
//! acceptor that is down — no listener, or a listener that closes before
//! the head is written — aborts the socket, so the box sees a reset rather
//! than a hang.
//!
//! [`BepDevice`] is that [`Device`]: a pair of unbounded tokio channels, one
//! raw Ethernet frame per message on each, plus the queue
//! [`BepHost::poll`] fills from the inbound channel so the interface's
//! `receive` can hand frames back one at a time. [`BepDevice::pair`] hands
//! the caller the [`BepDeviceEnds`] to feed frames in through and take frames
//! out of; the length framing between those edges and the byte stream is the
//! stream reader's and writer's job, as it is in the egress gate's relay.
//! [`BepHost`] builds the interface over it: the leg's address on a
//! [`SwitchSubnet`], its MAC derived the switch's way
//! ([`MacAddr::for_switch_ip`]), stepped with [`BepHost::poll`].
//! [`BepStack`] adds the pool and the delivery on top; [`BepPeer`] runs the
//! stack over the switch socket: it dials it once, upgrades the connection
//! with the HyperKit `/connect` request, and runs the whole peer — the stack,
//! its reader and writer pumps, and every per-flow delivery task — on one
//! dedicated runtime that is woken by inbound frames, by the pumps, and by a
//! periodic `poll_delay`, and dies with the peer.
//!
//! The module is behind the `stack-peer` cargo feature, off by default: it
//! lives in this crate so that both daemons can link it, but the in-VM
//! `minimald` build, which links the crate for the configuration renderer,
//! pulls in neither smoltcp nor tokio for it. `minvmd` enables the feature
//! and wires the peer beside the switch; wiring it natively into `minimald`
//! is a later task (NET-133's native case). The `test-util` feature adds
//! [`test_util`]'s box-side client and channel-wired lane for this crate's
//! and `minvmd`'s tests.
//!
//! The peer is silent until spoken to. It originates no frame except in
//! answer to one that addressed it — the ARP reply, the TCP reset for an
//! unlistened port, the ICMP port-unreachable — and each of those goes to
//! the box that asked and to no other destination: no gratuitous ARP at
//! attach, no ARP probe, nothing on an idle lane, and no socket at all
//! until a registered box's share puts one there. The smoltcp feature set
//! this crate builds with excludes `proto-ipv6`, so the stack cannot emit
//! neighbour solicitation, router solicitation or MLD either.
//! `idle_peer_emits_no_frames` pins the silence and `peer_binds_no_socket`
//! pins the empty set.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::{DEFAULT_MTU, MacAddr, SwitchSubnet};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::socket::tcp::SocketBuffer;
use smoltcp::time::Duration as StackDuration;
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};

/// The HTTP upgrade request that turns a gvproxy control socket connection
/// into a raw Ethernet frame stream (the same head the guest shuttle uses).
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// Maximum interval between stack polls even when no traffic arrives, so smoltcp
/// TCP timers still advance.
const POLL_DELAY: Duration = Duration::from_millis(100);

/// The port the proxy's listener answers on, on the leg's address: the port
/// a box's credentialed traffic is steered to (NET-134) and the one the
/// pool's sockets listen at. A proposed working value, recorded beside the
/// per-source cap in the spec and tuned by the integration run.
pub const PROXY_PORT: u16 = 8118;

/// The per-boot token's length in bytes: the shared secret the host daemon
/// mints per boot and hands to the peer (in-process) and to the proxy's
/// acceptor (over its start-up channel in `minvmd`'s stand-in). A delivery
/// that does not carry this boot's token is not a box's connection.
pub const TOKEN_LEN: usize = 32;

/// The delivery header's wire version, the first byte of the fixed header
/// ahead of every delivered flow's bytes. A peer that speaks another version
/// is a peer this acceptor does not understand, and vice versa.
pub const DELIVERY_HEADER_VERSION: u8 = 1;

/// The delivery header's length in bytes: one version byte, the 16-byte box
/// id, and the two endpoints' address and port each — 29 bytes total, fixed,
/// so the acceptor reads exactly this many before any flow byte.
pub const DELIVERY_HEADER_LEN: usize = 1 + 16 + 4 + 2 + 4 + 2;

/// The per-source connection cap: the share each registered box's row holds
/// in the listener pool, and the number of connections a box may hold at
/// once before the pool aborts the next. A proposed working value (16), the
/// one the spec records with the pool partition, tuned by the integration
/// run.
pub const DEFAULT_PER_SOURCE_CAP: usize = 16;

/// The receive and transmit buffer length of every pool socket. The receive
/// buffer is the TCP window the box sees — the brake the flow runs under
/// when the acceptor stops reading.
const POOL_BUFFER_LEN: usize = 4096;

/// How many chunks each flow's channel to the acceptor may hold: the second
/// bound the delivery runs under. With the socket buffers it means a box
/// can run a bounded distance ahead of a stalled acceptor and no further.
const FLOW_CHANNEL_CAP: usize = 4;

/// The largest chunk one pump moves per read or socket take.
const FLOW_CHUNK_LEN: usize = 4096;

/// One warn line per class per interval, carrying how many events it
/// swallowed: a cap storm or an acceptor outage is one line per second in a
/// daemon log tail, with the count it suppressed.
const WARN_INTERVAL: StackDuration = StackDuration::from_secs(1);

/// A box's identity in a delivery: 16 opaque bytes, all-zero until the
/// box-id task (T44) fills them from the registry's rows.
pub type BoxId = [u8; 16];

/// The delivery header ahead of a flow's bytes: what tells the proxy which
/// box's connection this is before any flow byte crosses (NET-132).
///
/// One fixed layout, [`DELIVERY_HEADER_LEN`] bytes:
///
/// - byte 0: the wire version, [`DELIVERY_HEADER_VERSION`] (1)
/// - bytes 1..17: the box id, all-zero until T44 fills it
/// - bytes 17..21: the box's switch address, the source the flow is
///   presented from
/// - bytes 21..23: the box's source port
/// - bytes 23..27: the destination address
/// - bytes 27..29: the destination port
///
/// Addresses and ports go out in network byte order, the way the boxes write
/// them on the wire themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryHeader {
    /// The flow's box, all-zero until T44 fills it.
    pub box_id: BoxId,
    /// The source the flow is presented from: the box's own switch address.
    pub source: IpEndpoint,
    /// The destination the box's connection asked for.
    pub destination: IpEndpoint,
}

impl DeliveryHeader {
    /// The header for a flow the pool accepted from `source` to
    /// `destination`. The box id is all-zero until T44 fills it.
    #[must_use]
    pub fn for_flow(source: IpEndpoint, destination: IpEndpoint) -> Self {
        Self {
            box_id: [0; 16],
            source,
            destination,
        }
    }

    /// Append the header to `buf`, version byte first — the exact bytes the
    /// peer writes after the per-boot token.
    pub fn emit_into(&self, buf: &mut Vec<u8>) {
        buf.push(DELIVERY_HEADER_VERSION);
        buf.extend_from_slice(&self.box_id);
        buf.extend_from_slice(&v4_octets(self.source.addr));
        buf.extend_from_slice(&self.source.port.to_be_bytes());
        buf.extend_from_slice(&v4_octets(self.destination.addr));
        buf.extend_from_slice(&self.destination.port.to_be_bytes());
    }

    /// Parse the header from the exact [`DELIVERY_HEADER_LEN`] bytes a peer
    /// sends after the token, or `None` if the slice is not that long. The
    /// version byte is the caller's to check — a refused version is the
    /// acceptor's audit reason, not a parse failure.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() != DELIVERY_HEADER_LEN {
            return None;
        }
        let box_id: BoxId = buf[1..17].try_into().ok()?;
        let source = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Addr::new(buf[17], buf[18], buf[19], buf[20])),
            port: u16::from_be_bytes(buf[21..23].try_into().ok()?),
        };
        let destination = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Addr::new(buf[23], buf[24], buf[25], buf[26])),
            port: u16::from_be_bytes(buf[27..29].try_into().ok()?),
        };
        Some(Self {
            box_id,
            source,
            destination,
        })
    }
}

/// The leg's stack is IPv4-only (this crate builds smoltcp without
/// `proto-ipv6`, so `IpAddress` has the one variant), and every endpoint a
/// socket ever carries is one.
fn v4_octets(addr: IpAddress) -> [u8; 4] {
    match addr {
        IpAddress::Ipv4(ip) => ip.octets(),
    }
}

/// The registered boxes a peer's pool is partitioned by: the rows a host
/// holds outside the VM, each one a box whose share of the listener pool
/// appears at registration and leaves with the row (NET-138's table is
/// `minvmd`'s). The source is polled every stack turn, so a row that goes
/// takes its sockets with it within a turn.
///
/// Implemented over the registry's read-only view in `minvmd`; the tests
/// stand in with a mutable vec.
pub trait BepBoxSource: Send + Sync {
    /// The switch addresses of every row currently registered, in row
    /// order.
    fn box_switch_addresses(&self) -> Vec<Ipv4Addr>;
}

/// A channel-backed smoltcp [`Device`] over the switch's Ethernet lane.
///
/// One unbounded channel in (frames arriving from the lane), one out (frames
/// the stack transmits), one raw Ethernet frame per message on each, never a
/// length-prefixed stream chunk — the framing lives at the stream edges that
/// fill and drain these channels (see the module docs). Frames the channel
/// delivers wait on the device's queue until the interface's poll takes
/// them, one per `receive`.
#[derive(Debug)]
pub struct BepDevice {
    rx: UnboundedReceiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
    /// Frames the channel delivered, waiting for the interface's `receive`.
    pending: VecDeque<Vec<u8>>,
}

/// The peer ends of a [`BepDevice`]'s channels: what feeds the stack and what
/// drains it.
#[derive(Debug)]
pub struct BepDeviceEnds {
    /// Feed the device the frames that arrived from the switch lane, one raw
    /// Ethernet frame per message.
    pub inbound: UnboundedSender<Vec<u8>>,
    /// Take the frames the stack transmits onto the lane, one raw Ethernet
    /// frame per message.
    pub outbound: UnboundedReceiver<Vec<u8>>,
}

impl BepDevice {
    /// Pair a device with the ends that drive it: frames arrive through
    /// [`BepDeviceEnds::inbound`], the stack's frames leave through
    /// [`BepDeviceEnds::outbound`].
    #[must_use]
    pub fn pair() -> (Self, BepDeviceEnds) {
        let (inbound_tx, inbound_rx) = unbounded_channel();
        let (outbound_tx, outbound_rx) = unbounded_channel();
        (
            Self {
                rx: inbound_rx,
                tx: outbound_tx,
                pending: VecDeque::new(),
            },
            BepDeviceEnds {
                inbound: inbound_tx,
                outbound: outbound_rx,
            },
        )
    }

    /// Queue `frame` for the interface's next poll — the path the channel
    /// drain takes, and the one the test boxes enqueue their ARP requests
    /// through.
    fn enqueue(&mut self, frame: Vec<u8>) {
        self.pending.push_back(frame);
    }
}

impl Device for BepDevice {
    type RxToken<'a>
        = BepRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = BepTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.pending.pop_front().map(|frame| {
            (
                BepRxToken { frame },
                BepTxToken {
                    tx: self.tx.clone(),
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // The outbound channel is unbounded, so a transmit slot is always
        // available; a send later fails only when the leg's lane is gone.
        Some(BepTxToken {
            tx: self.tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        // The lane is Ethernet at the switch's MTU, with no checksum or
        // segmentation offload to claim: smoltcp computes and verifies in
        // software, which is also what the test asserts against.
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = usize::from(DEFAULT_MTU);
        let mut checksum_caps = ChecksumCapabilities::default();
        checksum_caps.ipv4 = Checksum::Both;
        checksum_caps.tcp = Checksum::Both;
        checksum_caps.udp = Checksum::Both;
        checksum_caps.icmpv4 = Checksum::Both;
        caps.checksum = checksum_caps;
        caps
    }
}

/// One received frame, handed to the interface's poll as a receive token.
pub struct BepRxToken {
    frame: Vec<u8>,
}

impl smoltcp::phy::RxToken for BepRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

/// One transmit slot; the interface writes the frame into the token's buffer
/// and the token sends it out the device's outbound channel.
pub struct BepTxToken {
    tx: UnboundedSender<Vec<u8>>,
}

impl smoltcp::phy::TxToken for BepTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        self.send_out(frame);
        result
    }
}

impl BepTxToken {
    fn send_out(&self, frame: Vec<u8>) {
        let _ = self.tx.send(frame);
    }
}

/// The host leg's stack: one smoltcp [`Interface`] over a channel-backed
/// [`BepDevice`], holding the leg's address on the switch's plan.
///
/// Built by [`BepHost::new`], stepped by [`BepHost::poll`]: one call takes
/// every frame the lane delivered off the channel, hands them all to the
/// interface — whose own answers (ARP replies, resets for unlistened ports,
/// port-unreachable for datagrams with no socket) go out the same turn —
/// and lets every socket on the set dispatch what the turn queued. The
/// listener pool's sockets live on this set; a bare host holds none, and the
/// pool that adds them is [`BepStack`]'s.
pub struct BepHost {
    device: BepDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    ip: Ipv4Address,
    mac: EthernetAddress,
}

impl fmt::Debug for BepHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BepHost")
            .field("ip", &self.ip)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

impl BepHost {
    /// Build the leg's stack over `device`, holding `ip` on `subnet`'s plan.
    ///
    /// The MAC is derived the switch's way ([`MacAddr::for_switch_ip`]), so
    /// the switch's static-lease table can carry the leg the same way it
    /// carries every PTask, without a round trip.
    #[must_use]
    pub fn new(device: BepDevice, subnet: SwitchSubnet, ip: Ipv4Addr) -> Self {
        let mac = EthernetAddress(MacAddr::for_switch_ip(ip).0);
        let mut device = device;
        let mut iface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ethernet(mac)),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(ip), subnet.prefix()))
                .expect("the leg holds one address and the interface's address capacity is four");
        });
        // any_ip stays off: the interface owns this address and nothing else.
        debug_assert!(!iface.any_ip());
        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            ip,
            mac,
        }
    }

    /// The leg's address on the switch's plan.
    #[must_use]
    pub fn ip(&self) -> Ipv4Address {
        self.ip
    }

    /// The leg's MAC, as the stack presents it.
    #[must_use]
    pub fn mac(&self) -> EthernetAddress {
        self.mac
    }

    /// Step the stack at `now`: take every inbound frame off the device's
    /// channel onto its queue, then let the interface process all of them and
    /// dispatch everything its sockets have queued. One call is one full
    /// turn of the stack; the pool's service runs between two of them.
    pub fn poll(&mut self, now: Instant) {
        while let Ok(frame) = self.device.rx.try_recv() {
            self.device.enqueue(frame);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    /// Whether the lane feeding the stack has closed: every inbound sender
    /// is gone, so no frame will ever arrive and the stack has nothing left
    /// to serve.
    fn lane_closed(&self) -> bool {
        self.device.rx.is_closed()
    }
}

/// The delivery wiring a peer needs: where the proxy's acceptor listens, the
/// per-boot token every delivered connection presents, and the per-source
/// cap each registered box's share holds.
///
/// `minvmd`'s supervisor mints the token per boot, derives the acceptor
/// socket beside the switch socket, and names the cap; the peer carries all
/// three (NET-132).
#[derive(Debug, Clone)]
pub struct BepWire {
    proxy_sock: PathBuf,
    token: [u8; TOKEN_LEN],
    per_source_cap: usize,
}

impl BepWire {
    /// The wiring for a peer delivering to the acceptor at `proxy_sock` with
    /// `token`, each registered box holding [`DEFAULT_PER_SOURCE_CAP`]
    /// connections.
    #[must_use]
    pub fn new(proxy_sock: PathBuf, token: [u8; TOKEN_LEN]) -> Self {
        Self {
            proxy_sock,
            token,
            per_source_cap: DEFAULT_PER_SOURCE_CAP,
        }
    }

    /// The wiring with each box's share at `cap` instead of the default —
    /// the tests drive small caps, the supervisor names the recorded default.
    #[must_use]
    pub fn with_per_source_cap(mut self, cap: usize) -> Self {
        self.per_source_cap = cap;
        self
    }

    /// The acceptor's unix socket: where every delivered flow dials.
    #[must_use]
    pub fn proxy_sock(&self) -> &Path {
        &self.proxy_sock
    }

    /// The per-source cap: the share each registered box holds.
    #[must_use]
    pub fn per_source_cap(&self) -> usize {
        self.per_source_cap
    }
}

/// One slot the pool owns: its socket in the set, the flow the socket
/// carries if any, and the arrival stamp the slot took that flow in — the
/// order a cap hit aborts against.
struct Slot {
    handle: SocketHandle,
    /// `Some` from the turn the socket took a connection to the turn the
    /// flow ends; `None` while the slot listens.
    activated: Option<u64>,
    flow: Flow,
}

/// What a pool slot is doing.
#[derive(Debug)]
enum Flow {
    /// Listening for the next connection: no flow, no identity.
    Listening,
    /// The connection was accepted and passed its cap; the dial to the
    /// acceptor is in flight, matched to its answer by `ticket`.
    Dialing {
        ticket: u64,
        remote: IpEndpoint,
        local: IpEndpoint,
    },
    /// The acceptor answered; the two pumps move the flow's bytes. The
    /// endpoints were logged at delivery and live in the acceptor's
    /// connection now — the stack's own part in the flow is the pipes.
    Live { pipes: FlowPipes },
    /// The socket was aborted — past its box's cap, its box's row
    /// withdrawn, or its dial refused by an acceptor that is down — and is
    /// waiting in the set for its reset to be dispatched. The slot returns
    /// to the pool, with a fresh listening socket, on the service pass
    /// after that dispatch: removing the socket now would drop its
    /// undelivered reset on the floor, and the box would be left holding a
    /// half-open connection that no one will ever answer.
    Resetting,
}

/// A live flow's channel ends, and the bytes the socket's transmit buffer
/// could not take yet.
#[derive(Debug, Default)]
struct FlowPipes {
    /// The box's bytes out to the acceptor, dropped when the box's half
    /// closes so the pump hands the acceptor EOF.
    to_proxy: Option<Sender<Vec<u8>>>,
    /// The acceptor's bytes in to the box, dropped when the acceptor's half
    /// closes so the stack half-closes the box.
    from_proxy: Option<Receiver<Vec<u8>>>,
    /// Bytes the socket's window would not take this turn.
    backlog: Vec<u8>,
}

/// A dial's answer, from the delivery task to the stack.
struct DialDone {
    ticket: u64,
    result: io::Result<FlowEnds>,
}

/// What a successful dial hands the stack.
struct FlowEnds {
    to_proxy: Sender<Vec<u8>>,
    from_proxy: Receiver<Vec<u8>>,
}

/// The leg's listener pool and the delivery behind it (NET-132): one
/// [`BepHost`] whose socket set holds the pool, partitioned per registered
/// box so each box's share is the per-source cap, added at registration and
/// withdrawn with its row.
///
/// [`BepStack::poll`] is one full turn: the stack's frames, the partition
/// reconciled against [`BepBoxSource`], the caps enforced on every active
/// connection, new connections delivered, live flows' bytes moved under
/// their windows, finished flows' slots returned to the pool. The stack
/// itself is not `Send` (the interface and socket set are not), so the peer
/// runs it on a dedicated runtime and the tests drive it turn by turn;
/// every per-flow delivery task it spawns lands on whatever runtime is
/// current when [`BepStack::poll`] runs.
pub struct BepStack {
    host: BepHost,
    /// Every socket the pool owns, each either listening or carrying one
    /// flow.
    slots: Vec<Slot>,
    /// The partition as last reconciled: the registered boxes' switch
    /// addresses, in row order.
    partition: Vec<Ipv4Address>,
    wire: BepWire,
    boxes: Arc<dyn BepBoxSource>,
    /// Dial answers from the delivery tasks.
    done_rx: UnboundedReceiver<DialDone>,
    done_tx: UnboundedSender<DialDone>,
    /// Wakes the peer's poll loop when a dial answers or a pump hands a live
    /// flow bytes.
    notify: Arc<Notify>,
    next_ticket: u64,
    next_activation: u64,
    cap_warns: WarnThrottle,
    down_warns: WarnThrottle,
}

impl BepStack {
    /// The stack for `subnet.box_egress_proxy_address()`, delivering to the
    /// acceptor `wire` names, partitioned by the rows `boxes` holds.
    ///
    /// Must be built inside a tokio runtime context: the per-flow delivery
    /// tasks spawn when [`BepStack::poll`] runs.
    #[must_use]
    pub fn new(
        device: BepDevice,
        subnet: SwitchSubnet,
        wire: BepWire,
        boxes: Arc<dyn BepBoxSource>,
    ) -> Self {
        let (done_tx, done_rx) = unbounded_channel();
        Self {
            host: BepHost::new(device, subnet, subnet.box_egress_proxy_address()),
            slots: Vec::new(),
            partition: Vec::new(),
            wire,
            boxes,
            done_rx,
            done_tx,
            notify: Arc::new(Notify::new()),
            next_ticket: 0,
            next_activation: 0,
            cap_warns: WarnThrottle::default(),
            down_warns: WarnThrottle::default(),
        }
    }

    /// The wake source every delivery task and pump notifies: the peer's
    /// poll loop selects on it between turns.
    #[must_use]
    pub fn waker(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// How many sockets the pool owns — listening or carrying. The
    /// registered boxes' shares: each row is [`BepWire::per_source_cap`]
    /// sockets, and nothing else.
    #[must_use]
    pub fn pool_len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the lane feeding the stack has closed: every inbound sender
    /// is gone, so no frame will ever arrive and the stack has nothing left
    /// to serve.
    #[must_use]
    pub fn lane_closed(&self) -> bool {
        self.host.lane_closed()
    }

    /// One full turn of the pool at `now`. The order is the choreography:
    ///
    /// 1. the stack's frames in, its answers out;
    /// 2. the partition reconciled against the box source — shares added
    ///    and withdrawn, a withdrawn row's live flows aborted;
    /// 3. the dial answers taken: a live flow gets its pipes, a failed
    ///    dial aborts the socket — an acceptor that is down resets the
    ///    box's connection;
    /// 4. the caps enforced on every active connection — a box past its
    ///    share loses the connection it opened last;
    /// 5. the stack polled again, so every abort the turn issued sends
    ///    its reset while the aborted socket is still in the set;
    /// 6. the per-slot service: new connections dialed to the acceptor,
    ///    live flows' bytes moved under their windows, and every finished
    ///    flow — closed by either side or aborted — returning its slot to
    ///    the pool with a fresh listening socket;
    /// 7. the stack polled once more so everything the service queued
    ///    leaves inside the turn.
    pub fn poll(&mut self, now: Instant) {
        self.host.poll(now);
        self.reconcile();
        self.dispatch_dials(now);
        self.enforce_caps(now);
        self.host.poll(now);
        self.service();
        self.host.poll(now);
    }

    /// Reconcile the pool against the box source: a new row adds its share
    /// of listening sockets, a withdrawn row's live flows are aborted —
    /// their reset leaves this turn — and the pool is then trimmed to the
    /// registered shares, idle listeners first, because a slot is anonymous
    /// once it is in the pool: the total is the sum of the shares, and
    /// which box's connection a slot carries is written on the connection,
    /// not the slot. A connection from a source with no row is the cap
    /// pass's to answer: a source with no row holds nothing.
    fn reconcile(&mut self) {
        let desired: Vec<Ipv4Address> = self.boxes.box_switch_addresses();
        let cap = self.wire.per_source_cap;
        for addr in &desired {
            if !self.partition.contains(addr) {
                for _ in 0..cap {
                    let handle = self.add_listening();
                    self.slots.push(Slot {
                        handle,
                        activated: None,
                        flow: Flow::Listening,
                    });
                }
                tracing::debug!(
                    box_addr = %addr,
                    slots = cap,
                    "box egress proxy pool: a registered box's share was added"
                );
            }
        }
        let withdrawn: Vec<Ipv4Address> = self
            .partition
            .iter()
            .copied()
            .filter(|addr| !desired.contains(addr))
            .collect();
        for addr in &withdrawn {
            self.abort_their_flows(*addr);
            tracing::debug!(
                box_addr = %addr,
                "box egress proxy pool: a withdrawn box's share was removed"
            );
        }
        self.partition = desired;
        let target = self.partition.len() * cap;
        while self.slots.len() > target {
            let Some(idx) = (0..self.slots.len()).find(|&idx| {
                matches!(self.slots[idx].flow, Flow::Listening) && self.slot_is_listening(idx)
            }) else {
                break;
            };
            let handle = self.slots[idx].handle;
            self.host.sockets.remove(handle);
            self.slots.remove(idx);
        }
    }

    /// Abort every live flow a withdrawn box holds: its reset leaves this
    /// turn, and its slot returns to the pool on the service pass after
    /// that. Slots already waiting to reset are left alone.
    fn abort_their_flows(&mut self, addr: Ipv4Address) {
        for idx in 0..self.slots.len() {
            if matches!(self.slots[idx].flow, Flow::Resetting) {
                continue;
            }
            let is_its_flow = self
                .slot_remote(idx)
                .is_some_and(|remote| remote.addr == IpAddress::Ipv4(addr));
            if is_its_flow {
                self.abort_slot(idx);
            }
        }
    }

    /// Take the dial answers that arrived: a live flow gets its pipes, a
    /// failed dial aborts the socket — an acceptor that is down resets the
    /// box's connection rather than hanging it.
    fn dispatch_dials(&mut self, now: Instant) {
        while let Ok(done) = self.done_rx.try_recv() {
            let Some(idx) = self.slots.iter().position(
                |slot| matches!(&slot.flow, Flow::Dialing { ticket, .. } if *ticket == done.ticket),
            ) else {
                // The flow ended before the dial answered — say a box's FIN
                // or a withdrawal raced it. The pipes the dial won are
                // dropped here, which ends the pumps and closes the
                // acceptor's connection: one connection per flow, never
                // reused, not even for a flow that is already gone.
                continue;
            };
            match done.result {
                Ok(ends) => {
                    if let Flow::Dialing { remote, local, .. } = self.slots[idx].flow {
                        tracing::debug!(
                            source = %remote,
                            destination = %local,
                            acceptor = %self.wire.proxy_sock().display(),
                            "box egress proxy: connection delivered to the acceptor"
                        );
                        self.slots[idx].flow = Flow::Live {
                            pipes: FlowPipes {
                                to_proxy: Some(ends.to_proxy),
                                from_proxy: Some(ends.from_proxy),
                                backlog: Vec::new(),
                            },
                        };
                    }
                }
                Err(error) => {
                    let source = self
                        .slot_remote(idx)
                        .map(|remote| remote.to_string())
                        .unwrap_or_else(|| "an unconnected socket".to_owned());
                    self.down_warns.hit(now, |suppressed| {
                        tracing::warn!(
                            source = %source,
                            acceptor = %self.wire.proxy_sock().display(),
                            error = %error,
                            suppressed,
                            "box egress proxy: the acceptor is down; the box's \
                             connection was reset"
                        );
                    });
                    self.abort_slot(idx);
                }
            }
        }
    }

    /// Enforce the per-source cap across every active slot: a box keeps the
    /// first `cap` connections it opened — by arrival stamp, so a flow the
    /// acceptor already took is never the one reset — and every later one is
    /// aborted. A source with no row at all holds nothing.
    fn enforce_caps(&mut self, now: Instant) {
        // Facts first: the socket set's borrow does not survive the aborts
        // the pass may issue.
        let mut facts: Vec<Option<IpEndpoint>> = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let socket = self.host.sockets.get::<tcp::Socket>(slot.handle);
            let fact = if socket.is_open() && socket.state() != tcp::State::Listen {
                socket.remote_endpoint()
            } else {
                None
            };
            facts.push(fact);
        }
        // Stamp every newly active slot with its arrival order.
        for (slot, fact) in self.slots.iter_mut().zip(&facts) {
            if fact.is_some() && slot.activated.is_none() {
                slot.activated = Some(self.next_activation);
                self.next_activation += 1;
            }
        }
        // Group the active slots by source address; a box keeps its first
        // `cap` arrivals and the rest are aborted.
        let mut by_source: std::collections::BTreeMap<Ipv4Address, Vec<(u64, usize)>> =
            std::collections::BTreeMap::new();
        for ((idx, slot), fact) in self.slots.iter().enumerate().zip(&facts) {
            let (Some(activated), Some(remote)) = (slot.activated, fact) else {
                continue;
            };
            // The leg's stack is IPv4-only: the address is the one variant.
            let IpAddress::Ipv4(addr) = remote.addr;
            by_source.entry(addr).or_default().push((activated, idx));
        }
        let mut to_abort: Vec<(Ipv4Address, usize, usize)> = Vec::new();
        for (addr, mut group) in by_source {
            let cap = if self.partition.contains(&addr) {
                self.wire.per_source_cap
            } else {
                0
            };
            group.sort_unstable();
            let live = group.len();
            for (position, (_, idx)) in group.into_iter().enumerate() {
                if position >= cap {
                    to_abort.push((addr, live, idx));
                }
            }
        }
        for (addr, live, idx) in to_abort {
            self.cap_warns.hit(now, |suppressed| {
                tracing::warn!(
                    source = %addr,
                    live,
                    cap = self.wire.per_source_cap,
                    suppressed,
                    "box egress proxy: reset a connection at the per-source cap"
                );
            });
            self.abort_slot(idx);
        }
    }

    /// The pool's per-slot service: newly accepted connections dial, live
    /// flows' bytes move, finished flows' slots return to the pool.
    fn service(&mut self) {
        for idx in 0..self.slots.len() {
            self.service_slot(idx);
        }
    }

    /// Service one slot. An aborted flow's socket, whose reset left in the
    /// dispatch poll before this one, gives its slot back to the pool; so
    /// does a flow whose socket closed on either side; a listening slot
    /// that took a connection hands it to the dialer once the handshake
    /// completes; a live flow moves what its windows allow.
    fn service_slot(&mut self, idx: usize) {
        let handle = self.slots[idx].handle;
        let (state, is_open) = {
            let socket = self.host.sockets.get::<tcp::Socket>(handle);
            (socket.state(), socket.is_open())
        };
        // An aborted flow's socket waited in the set for its reset to
        // leave; now closed, its slot returns to the pool.
        if matches!(self.slots[idx].flow, Flow::Resetting) {
            if !is_open {
                self.retire_slot(idx);
            }
            return;
        }
        let is_listening_flow = matches!(self.slots[idx].flow, Flow::Listening);
        // A flow that ended — its socket closed by either side — gives its
        // slot back to the pool: the share stays whole for the next
        // connection.
        if !is_listening_flow && !is_open {
            self.retire_slot(idx);
            return;
        }
        if is_listening_flow && matches!(state, tcp::State::Established | tcp::State::CloseWait) {
            // The cap pass has already counted this connection (and aborted
            // it if it was past its box's share); a slot that is still
            // carrying it is delivered. CloseWait is included because a
            // handshake can complete straight into it: smoltcp folds a FIN
            // that arrives with the handshake's ACK — and the box's FIN
            // always lands before the service pass, these turns being a
            // hundred times slower than a kernel's — past `Established`
            // without a stop. A box that finished sending as it connected
            // still owns a connection: it can still receive the answer.
            let remote = self
                .slot_remote(idx)
                .expect("an accepted socket names the box it came from");
            let local = self
                .slot_local(idx)
                .expect("an accepted socket names the address it arrived at");
            self.request_dial(idx, remote, local);
            return;
        }
        if let Flow::Live { pipes } = &mut self.slots[idx].flow {
            let socket = self.host.sockets.get_mut::<tcp::Socket>(handle);
            move_live_bytes(socket, pipes);
        }
    }

    /// Deliver the slot's connection: spawn the dial that connects to the
    /// acceptor, writes the per-boot token and the fixed header, and starts
    /// the two pumps. The dial's answer comes back on the stack's channel
    /// and wakes its turn.
    fn request_dial(&mut self, idx: usize, remote: IpEndpoint, local: IpEndpoint) {
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        self.slots[idx].flow = Flow::Dialing {
            ticket,
            remote,
            local,
        };
        let done_tx = self.done_tx.clone();
        let wire = self.wire.clone();
        let notify = self.waker();
        tokio::spawn(async move {
            let result = dial_acceptor(&wire, remote, local, Arc::clone(&notify)).await;
            let _ = done_tx.send(DialDone { ticket, result });
            // The dial's answer is on the channel; the poll loop takes it on
            // the next turn, so wake it now.
            notify.notify_one();
        });
    }

    /// One slot's socket's remote endpoint, if it is carrying a connection.
    fn slot_remote(&self, idx: usize) -> Option<IpEndpoint> {
        self.host
            .sockets
            .get::<tcp::Socket>(self.slots[idx].handle)
            .remote_endpoint()
    }

    /// One slot's socket's local endpoint, if it is carrying a connection.
    fn slot_local(&self, idx: usize) -> Option<IpEndpoint> {
        self.host
            .sockets
            .get::<tcp::Socket>(self.slots[idx].handle)
            .local_endpoint()
    }

    /// Whether one slot's socket is listening for a connection.
    fn slot_is_listening(&self, idx: usize) -> bool {
        self.host
            .sockets
            .get::<tcp::Socket>(self.slots[idx].handle)
            .is_listening()
    }

    /// Add a fresh listening socket at the proxy port and return its handle.
    fn add_listening(&mut self) -> SocketHandle {
        let mut socket = tcp::Socket::new(
            SocketBuffer::new(vec![0u8; POOL_BUFFER_LEN]),
            SocketBuffer::new(vec![0u8; POOL_BUFFER_LEN]),
        );
        socket
            .listen(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(self.host.ip())),
                port: PROXY_PORT,
            })
            .expect("the proxy port is a fixed, nonzero port on the leg's own address");
        self.host.sockets.add(socket)
    }

    /// Abort the slot's socket and hold the slot for the reset: the aborted
    /// socket stays in the set until its reset has been dispatched — the
    /// stack poll after this pass, in the same turn — and only then does
    /// the slot return to the pool, with a fresh listening socket, on the
    /// next service pass. Removing the socket here would drop its
    /// undelivered reset on the floor, and the box would be left holding a
    /// half-open connection that no one will ever answer.
    fn abort_slot(&mut self, idx: usize) {
        self.host
            .sockets
            .get_mut::<tcp::Socket>(self.slots[idx].handle)
            .abort();
        self.slots[idx].flow = Flow::Resetting;
    }

    /// Return a finished slot to the pool with a fresh listening socket. The
    /// socket's connection already ended — its reset, if it sent one, left
    /// in the dispatch poll before this pass — and its slot belongs back in
    /// the share as a listener.
    fn retire_slot(&mut self, idx: usize) {
        self.refresh_slot(idx);
    }

    /// Replace the slot's socket in the set with a fresh listening one.
    fn refresh_slot(&mut self, idx: usize) {
        let handle = self.slots[idx].handle;
        self.host.sockets.remove(handle);
        self.slots[idx] = Slot {
            handle: self.add_listening(),
            activated: None,
            flow: Flow::Listening,
        };
    }
}

/// Move one live flow's bytes for one turn: the box's bytes out of the
/// socket and into the flow's channel while the channel has room, the
/// acceptor's bytes the other way while the socket's transmit buffer does.
///
/// Full on either side means stop, not spin: the data stays where it is and
/// the window it sits behind closes on the sender — the smoltcp receive
/// buffer is the TCP window the box sees, the bounded channel the acceptor
/// does. A closed channel half ends the flow's other half: the box's FIN
/// drops the sender (the pump hands the acceptor EOF), the acceptor's EOF
/// half-closes the box.
fn move_live_bytes(socket: &mut tcp::Socket, pipes: &mut FlowPipes) {
    // box -> acceptor, while the acceptor's read half is open.
    if let Some(to_proxy) = pipes.to_proxy.as_mut() {
        let mut drop_sender = false;
        let mut brake = false;
        while !brake && socket.can_recv() {
            // Reserve the channel's slot before taking the bytes off the
            // socket: `recv_slice` removes them from the receive buffer, which
            // is the TCP window the box sees — taking them with nowhere to
            // put them would reopen the window and drop the bytes, a slow
            // acceptor would turn into an open drain. Holding the slot first
            // means the window only advances as far as the channel leads.
            let permit = match to_proxy.try_reserve() {
                Ok(permit) => permit,
                // The channel is full: leave the bytes in the socket's
                // buffer, where they hold the box's window shut.
                Err(TrySendError::Full(())) => break,
                // The acceptor's connection is gone: nothing more the box
                // sends can be delivered.
                Err(TrySendError::Closed(())) => {
                    drop_sender = true;
                    break;
                }
            };
            let mut chunk = [0u8; FLOW_CHUNK_LEN];
            match socket.recv_slice(&mut chunk) {
                Ok(0) | Err(_) => brake = true,
                Ok(n) => {
                    // The slot is held: the send cannot fail.
                    permit.send(chunk[..n].to_vec());
                }
            }
        }
        if drop_sender {
            pipes.to_proxy = None;
        }
    }
    // The box closed its half (its FIN answered, nothing left to receive):
    // the acceptor gets its EOF.
    if pipes.to_proxy.is_some() && socket.state() == tcp::State::CloseWait && !socket.can_recv() {
        pipes.to_proxy = None;
    }
    // acceptor -> box: the backlog first, then whatever the channel holds
    // while the socket's transmit buffer takes it.
    while !pipes.backlog.is_empty() && socket.can_send() {
        match socket.send_slice(&pipes.backlog) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                pipes.backlog.drain(..n);
            }
        }
    }
    if !pipes.backlog.is_empty() {
        // The box's transmit window is full: leave the channel be until the
        // window opens.
        return;
    }
    if let Some(from_proxy) = pipes.from_proxy.as_mut() {
        let mut half_close = false;
        while socket.can_send() {
            match from_proxy.try_recv() {
                Ok(chunk) => {
                    let n = socket.send_slice(&chunk).unwrap_or(0);
                    if n < chunk.len() {
                        // The window took only part of the chunk; the rest
                        // waits in the backlog for the next turn.
                        pipes.backlog.extend_from_slice(&chunk[n..]);
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    half_close = true;
                    break;
                }
            }
        }
        if half_close {
            // The acceptor closed its half: half-close the box's connection.
            socket.close();
            pipes.from_proxy = None;
        }
    }
}

/// Dial the acceptor for one flow and start its two pumps: one connection
/// per flow, never reused — a dead flow's connection closes with it.
///
/// The dial carries the per-boot token and then the fixed header ahead of
/// any flow byte, so the acceptor learns the box's source before the flow's
/// data starts. A connect failure or a refused head is the caller's abort:
/// an acceptor that is down resets the box's connection.
async fn dial_acceptor(
    wire: &BepWire,
    remote: IpEndpoint,
    local: IpEndpoint,
    notify: Arc<Notify>,
) -> io::Result<FlowEnds> {
    let mut stream = UnixStream::connect(wire.proxy_sock()).await?;
    let mut head = Vec::with_capacity(TOKEN_LEN + DELIVERY_HEADER_LEN);
    head.extend_from_slice(&wire.token);
    DeliveryHeader::for_flow(remote, local).emit_into(&mut head);
    stream.write_all(&head).await?;
    let (read_half, write_half) = stream.into_split();
    let (to_proxy, to_proxy_rx) = channel::<Vec<u8>>(FLOW_CHANNEL_CAP);
    let (from_proxy_tx, from_proxy) = channel::<Vec<u8>>(FLOW_CHANNEL_CAP);
    tokio::spawn(pump_to_acceptor(to_proxy_rx, write_half));
    tokio::spawn(pump_from_acceptor(read_half, from_proxy_tx, notify));
    Ok(FlowEnds {
        to_proxy,
        from_proxy,
    })
}

/// Move the box's bytes to the acceptor. The channel closing is the box's
/// half-close: the acceptor gets EOF. A write failure ends the pump — the
/// stack learns the acceptor's half is gone when its channel send fails.
async fn pump_to_acceptor(
    mut from_stack: Receiver<Vec<u8>>,
    mut stream: tokio::net::unix::OwnedWriteHalf,
) {
    while let Some(chunk) = from_stack.recv().await {
        if chunk.is_empty() {
            continue;
        }
        if stream.write_all(&chunk).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
    let _ = stream.shutdown().await;
}

/// Move the acceptor's bytes to the stack, waking it after every chunk. EOF
/// or error ends the pump — dropping the sender is how the stack learns the
/// acceptor's half is done. The channel is bounded, so a slow stack brakes
/// the acceptor's writes instead of buffering them without end.
async fn pump_from_acceptor(
    mut stream: tokio::net::unix::OwnedReadHalf,
    to_stack: Sender<Vec<u8>>,
    notify: Arc<Notify>,
) {
    let mut buf = vec![0u8; FLOW_CHUNK_LEN];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to_stack.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
                notify.notify_one();
            }
        }
    }
}

/// One warn per interval per class, carrying how many events it swallowed:
/// a cap storm or an acceptor outage leaves one line per second in a daemon
/// log tail, with the count it suppressed — the diagnostics the bundle's
/// log tail carries. The interval runs on the stack's own clock, which the
/// peer advances from the wall clock and the tests step by hand.
#[derive(Debug, Default)]
struct WarnThrottle {
    next: Option<Instant>,
    suppressed: u64,
}

impl WarnThrottle {
    /// Record one event at the stack's `now`: `emit` runs with the number of
    /// events swallowed since the last line, at most once per
    /// [`WARN_INTERVAL`] on the stack's clock.
    fn hit(&mut self, now: Instant, emit: impl FnOnce(u64)) {
        match self.next {
            Some(next) if now < next => self.suppressed += 1,
            _ => {
                emit(self.suppressed);
                self.suppressed = 0;
                self.next = Some(now + WARN_INTERVAL);
            }
        }
    }
}

/// A running Box Egress Proxy host peer.
///
/// It owns the upstream switch socket connection (the `POST /connect`
/// upgrade), the channel-backed [`BepDevice`] that talks to the smoltcp
/// stack, and the dedicated runtime everything runs on: the stack's poll
/// loop, the two frame pumps between socket and device channels, and every
/// per-flow delivery task. Dropping the handle stops the poll loop, the
/// runtime drops with it, and the socket and every flow close.
#[derive(Debug)]
#[must_use = "dropping BepPeer stops the host-side proxy stack"]
pub struct BepPeer {
    /// The peer's runtime thread. It runs a blocking task, which `abort`
    /// cannot stop, so the loop watches `stop` and returns when the sender
    /// drops.
    poll_task: tokio::task::JoinHandle<()>,
    /// Dropped by `Drop`: the poll loop exits when this closes. Without it the
    /// runtime that spawned the peer waits forever for the blocking task at
    /// shutdown, which is how the switch runtime hung at stop.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for BepPeer {
    fn drop(&mut self) {
        drop(self.stop.take());
        self.poll_task.abort();
    }
}

impl BepPeer {
    /// Start a peer for `subnet.box_egress_proxy_address()` on the switch
    /// socket at `switch_sock`, delivering the connections its pool accepts
    /// to the acceptor `wire` names, partitioned by the rows `boxes` holds.
    ///
    /// The peer dials the switch, upgrades the connection with the HyperKit
    /// `/connect` request, announces nothing, and then runs everything on
    /// one dedicated current-thread runtime, started inside a blocking task
    /// so the non-`Send` stack can live across awaits:
    ///
    /// - the stack's poll loop, stepped by [`BepStack::poll`] whenever
    ///   anything wakes it — an inbound frame, a drained outbound pump, a
    ///   dial answer, a delivered chunk — and at least every
    ///   [`POLL_DELAY`];
    /// - a socket reader that reads length-framed Ethernet frames from the
    ///   switch and feeds them into the stack's inbound channel;
    /// - a socket writer that reads from the stack's outbound channel and
    ///   writes length-framed Ethernet frames onto the switch;
    /// - a delivery task per accepted flow, each dialing the acceptor and
    ///   pumping its bytes both ways.
    ///
    /// Must be called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the switch socket cannot be connected to.
    pub async fn spawn(
        switch_sock: &Path,
        subnet: SwitchSubnet,
        wire: BepWire,
        boxes: Arc<dyn BepBoxSource>,
    ) -> io::Result<Self> {
        let proxy_ip = subnet.box_egress_proxy_address();
        let proxy_mac = MacAddr::for_switch_ip(proxy_ip);

        let mut stream = UnixStream::connect(switch_sock).await?;
        stream.write_all(CONNECT_REQUEST).await?;
        stream.flush().await?;

        tracing::info!(
            switch_socket = %switch_sock.display(),
            proxy_ip = %proxy_ip,
            proxy_mac = %proxy_mac,
            acceptor = %wire.proxy_sock().display(),
            per_source_cap = wire.per_source_cap(),
            "box egress proxy peer attached"
        );

        // The socket is split so the reader and writer can run independently;
        // the stack poll task cannot own the `UnixStream` because the smoltcp
        // `Interface` is not `Send`.
        let (read_half, write_half) = stream.into_split();

        // Channel-backed device: raw Ethernet frames in both directions. The
        // reader/writer tasks are `Send`; the `BepStack` built around the
        // device lives in the local poll task.
        let (device, ends) = BepDevice::pair();

        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let poll_task = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime for BepStack");
            rt.block_on(async move {
                let mut stack = BepStack::new(device, subnet, wire, boxes);
                let notify = stack.waker();
                stack.poll(Instant::from_millis(0));

                // The frame pumps run on this runtime with the stack: it
                // keeps the whole peer on one lifeline — the switch's — and
                // the runtime's drop stops them all together.
                let inbound_tx = ends.inbound;
                let reader_notify = Arc::clone(&notify);
                tokio::spawn(async move {
                    let mut read_half = read_half;
                    let mut len_buf = [0u8; 2];
                    loop {
                        // The prefix may arrive one byte at a time on a healthy
                        // stream; only a clean end of stream ends the pump.
                        // Every return below ends the peer for the rest of the
                        // switch's life (nothing restarts it), so each one says why.
                        match read_half.read_exact(&mut len_buf).await {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                                tracing::warn!(
                                    reason = "eof",
                                    "box egress proxy peer: switch socket closed; reader pump stopped"
                                );
                                return;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "box egress proxy peer: switch socket read failed");
                                return;
                            }
                        }
                        let len = u16::from_le_bytes(len_buf) as usize;
                        if len == 0 || len > usize::from(DEFAULT_MTU) + 14 + 4 {
                            // Malformed length; drop the connection.
                            tracing::warn!(
                                len,
                                "box egress proxy peer: frame length outside 1..=MTU+18; reader pump stopped"
                            );
                            return;
                        }
                        let mut frame = vec![0u8; len];
                        if let Err(e) = read_half.read_exact(&mut frame).await {
                            tracing::warn!(
                                error = %e,
                                len,
                                "box egress proxy peer: frame body read failed; reader pump stopped"
                            );
                            return;
                        }
                        if inbound_tx.send(frame).is_err() {
                            // The poll task is gone.
                            return;
                        }
                        reader_notify.notify_one();
                    }
                });

                let mut outbound_rx = ends.outbound;
                let writer_notify = Arc::clone(&notify);
                tokio::spawn(async move {
                    let mut stream = write_half;
                    while let Some(frame) = outbound_rx.recv().await {
                        let len = frame.len() as u16;
                        if len == 0 {
                            continue;
                        }
                        let mut buf = Vec::with_capacity(2 + frame.len());
                        buf.extend_from_slice(&len.to_le_bytes());
                        buf.extend_from_slice(&frame);
                        if stream.write_all(&buf).await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                        writer_notify.notify_one();
                    }
                });

                let start = tokio::time::Instant::now();
                let mut interval = tokio::time::interval(POLL_DELAY);
                loop {
                    tokio::select! {
                        _ = notify.notified() => {}
                        _ = interval.tick() => {}
                        // The peer was dropped: leave the loop so this runtime
                        // shuts down with every pump and flow it hosts.
                        _ = &mut stop_rx => break,
                    }
                    // `poll` is the one consumer of the inbound channel: it
                    // takes the frames the reader pump enqueued. Draining
                    // the channel here would starve it.
                    let elapsed = start.elapsed().as_millis() as i64;
                    stack.poll(Instant::from_millis(elapsed));
                    if stack.lane_closed() {
                        // The reader pump is gone and no frame will ever
                        // arrive: the interface has nothing left to serve.
                        return;
                    }
                }
            });
        });

        Ok(Self {
            poll_task,
            stop: Some(stop_tx),
        })
    }
}

/// Test scaffolding for the leg: a box-side smoltcp client and a
/// channel-wired lane that drives it against a [`BepStack`] turn by turn.
///
/// The [`TestBox`] is what a box kernel does over the lane: holds its lease,
/// answers nothing, ARPs for the address it wants to reach, opens TCP
/// connections, sends and reads. The [`TestLane`] cross-wires boxes and
/// stack so each turn moves one round of frames between them and services
/// the pool once — deterministic, no clock but the one the test steps.
///
/// Enabled by the `test-util` cargo feature — this crate's own tests compile
/// it under `cfg(test)` — so `minvmd`'s tests can exercise the delivery
/// against the registry and the stand-in acceptor without duplicating a
/// second TCP client.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use super::*;
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol};

    /// The first source port a [`TestBox`] connects from; each further
    /// flow's port is one higher. Known to the tests, so an acceptor can
    /// pick one flow to stall by the endpoint it presented.
    pub const FIRST_CLIENT_PORT: u16 = 40_000;

    /// One box-side stack: a [`BepHost`] holding the box's lease on the
    /// plan, speaking raw frames through its device's channel ends.
    ///
    /// Built over the same device the leg uses, because a box is a peer on
    /// the same lane: an interface at an address, sockets it connects
    /// outward with. Not a stand-in for anything production ships — the
    /// guest's kernel is the production client — but the honest shape of
    /// one for tests that must drive the lane deterministically.
    pub struct TestBox {
        host: BepHost,
        flows: Vec<SocketHandle>,
    }

    impl TestBox {
        /// A box at `ip` on `subnet`, with the channel ends its frames move
        /// through: feed [`BepDeviceEnds::inbound`] the frames the lane
        /// sends it, take its own off [`BepDeviceEnds::outbound`].
        #[must_use]
        pub fn new(subnet: SwitchSubnet, ip: Ipv4Addr) -> (Self, BepDeviceEnds) {
            let (device, ends) = BepDevice::pair();
            (
                Self {
                    host: BepHost::new(device, subnet, ip),
                    flows: Vec::new(),
                },
                ends,
            )
        }

        /// Step the box's stack at `now`: frames in, its answers and data
        /// out.
        pub fn poll(&mut self, now: Instant) {
            self.host.poll(now);
        }

        /// Queue an ARP request for `target`, the way a box kernel resolves
        /// the address before it connects. The request leaves on the next
        /// [`poll`](Self::poll).
        pub fn arp_for(&mut self, target: Ipv4Addr) {
            let ip = self.host.ip();
            let mac = self.host.mac();
            let repr = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: mac,
                source_protocol_addr: ip,
                target_hardware_addr: EthernetAddress::default(),
                target_protocol_addr: target,
            };
            let len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len());
            let mut buf = vec![0u8; len];
            let mut frame = EthernetFrame::new_unchecked(&mut buf);
            frame.set_dst_addr(EthernetAddress::BROADCAST);
            frame.set_src_addr(mac);
            frame.set_ethertype(EthernetProtocol::Arp);
            let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
            repr.emit(&mut packet);
            self.host.device.enqueue(buf);
        }

        /// Open a connection to `dst:dst_port` and return the flow's index.
        /// The SYN leaves on the next [`poll`](Self::poll) once the box has
        /// the neighbour (ARP it first); watch the flow with
        /// [`flow_state`](Self::flow_state) until it is established or reset.
        pub fn connect(&mut self, dst: Ipv4Addr, dst_port: u16) -> usize {
            let flow = self.flows.len();
            let local_port =
                FIRST_CLIENT_PORT + u16::try_from(flow).expect("a test opens few flows");
            let remote = IpEndpoint {
                addr: IpAddress::Ipv4(dst),
                port: dst_port,
            };
            let local = IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(self.host.ip())),
                port: local_port,
            };
            let mut socket = tcp::Socket::new(
                SocketBuffer::new(vec![0u8; POOL_BUFFER_LEN]),
                SocketBuffer::new(vec![0u8; POOL_BUFFER_LEN]),
            );
            socket
                .connect(self.host.iface.context(), remote, local)
                .expect("a well-formed remote and local endpoint");
            self.flows.push(self.host.sockets.add(socket));
            flow
        }

        /// The flow's TCP state: `Established` once the handshake completes,
        /// `Closed` after a reset or once the connection fully ends,
        /// `CloseWait` after the peer's FIN.
        #[must_use]
        pub fn flow_state(&self, flow: usize) -> tcp::State {
            self.flows
                .get(flow)
                .map(|handle| self.host.sockets.get::<tcp::Socket>(*handle).state())
                .unwrap_or(tcp::State::Closed)
        }

        /// Send `bytes` on the flow, returning how many the flow took:
        /// however much the socket's transmit buffer has room for, zero
        /// when it is full — the brake the tests assert a stalled acceptor
        /// reaches — and zero when the flow is closed.
        pub fn send(&mut self, flow: usize, bytes: &[u8]) -> usize {
            let Some(handle) = self.flows.get(flow) else {
                return 0;
            };
            let socket = self.host.sockets.get_mut::<tcp::Socket>(*handle);
            socket.send_slice(bytes).unwrap_or(0)
        }

        /// Read whatever the flow has received into `buf`, returning how
        /// many bytes moved. Zero is an empty buffer, not necessarily an
        /// end: [`flow_state`](Self::flow_state) says which.
        pub fn recv(&mut self, flow: usize, buf: &mut [u8]) -> usize {
            let Some(handle) = self.flows.get(flow) else {
                return 0;
            };
            let socket = self.host.sockets.get_mut::<tcp::Socket>(*handle);
            socket.recv_slice(buf).unwrap_or(0)
        }

        /// Finish sending on the flow: a FIN leaves on the next
        /// [`poll`](Self::poll). This is the shape of a client that asked
        /// its whole question with the connect and shut its write side
        /// down, still listening for the answer — a probe that half-closes
        /// as it connects.
        pub fn close(&mut self, flow: usize) {
            let Some(handle) = self.flows.get(flow) else {
                return;
            };
            self.host.sockets.get_mut::<tcp::Socket>(*handle).close();
        }
    }

    /// The leg's stack wired to [`TestBox`]es over channels, driven turn by
    /// turn: one [`step`](Self::step) moves one round of frames both ways
    /// and services the pool once, stepping 10 ms of stack time — enough
    /// for every handshake round, never enough for a retransmit timer to
    /// fire and muddle what the test meant to see.
    ///
    /// The lane fans every frame out to every box, the way a hub would;
    /// the boxes' interfaces drop frames not addressed to them, so only
    /// the addressed box processes what it sees.
    pub struct TestLane {
        stack: BepStack,
        /// Frames into the stack, fed by every box.
        stack_in: UnboundedSender<Vec<u8>>,
        /// Frames out of the stack, fanned to every box.
        stack_out: UnboundedReceiver<Vec<u8>>,
        boxes: Vec<TestBox>,
        /// Frames into each box.
        box_in: Vec<UnboundedSender<Vec<u8>>>,
        /// Frames out of each box.
        box_out: Vec<UnboundedReceiver<Vec<u8>>>,
        subnet: SwitchSubnet,
        clock_millis: i64,
    }

    impl TestLane {
        /// The lane for `subnet`, delivering through `wire`, partitioned by
        /// `boxes`. No box rides it until [`add_box`](Self::add_box).
        ///
        /// Must be built inside a tokio runtime context: the per-flow
        /// delivery tasks spawn when the lane's turns run.
        #[must_use]
        pub fn new(subnet: SwitchSubnet, wire: BepWire, boxes: Arc<dyn BepBoxSource>) -> Self {
            let (device, ends) = BepDevice::pair();
            Self {
                stack: BepStack::new(device, subnet, wire, boxes),
                stack_in: ends.inbound,
                stack_out: ends.outbound,
                boxes: Vec::new(),
                box_in: Vec::new(),
                box_out: Vec::new(),
                subnet,
                clock_millis: 0,
            }
        }

        /// Add a box at `ip`, connected to the lane.
        pub fn add_box(&mut self, ip: Ipv4Addr) {
            let (b, ends) = TestBox::new(self.subnet, ip);
            self.boxes.push(b);
            self.box_in.push(ends.inbound);
            self.box_out.push(ends.outbound);
        }

        /// The boxes riding the lane.
        #[must_use]
        pub fn boxes(&self) -> &[TestBox] {
            &self.boxes
        }

        /// The boxes riding the lane, mutably.
        pub fn boxes_mut(&mut self) -> &mut [TestBox] {
            &mut self.boxes
        }

        /// The pool's socket count: the registered boxes' shares.
        #[must_use]
        pub fn pool_len(&self) -> usize {
            self.stack.pool_len()
        }

        /// The instant the next [`turn`](Self::turn) polls the stack at, so
        /// a test can poll a box between turns without leaving the lane's
        /// clock.
        #[must_use]
        pub fn now(&self) -> Instant {
            Instant::from_millis(self.clock_millis)
        }

        /// One turn: the boxes' queued frames to the stack, the stack's one
        /// poll — ingress, delivery, service, egress — its answers fanned
        /// to the boxes, each box's one poll.
        pub fn turn(&mut self) {
            for out in &mut self.box_out {
                while let Ok(frame) = out.try_recv() {
                    let _ = self.stack_in.send(frame);
                }
            }
            self.stack.poll(Instant::from_millis(self.clock_millis));
            self.clock_millis += 10;
            while let Ok(frame) = self.stack_out.try_recv() {
                for b_in in &self.box_in {
                    let _ = b_in.send(frame.clone());
                }
            }
            for b in &mut self.boxes {
                b.poll(Instant::from_millis(self.clock_millis));
            }
        }

        /// One turn, plus the yield the stack's delivery tasks need to run:
        /// a dial, a pump, an answer. Await this between the assertions that
        /// depend on one.
        pub async fn step(&mut self) {
            self.turn();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::socket::tcp::State;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, Icmpv4Packet,
        IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
        UdpRepr,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    /// One ARP request frame, as a box on the plan would send it: broadcast,
    /// from the asker's switch-derived MAC, asking who has `target_ip`.
    fn arp_request(
        sender_mac: EthernetAddress,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: sender_mac,
            source_protocol_addr: sender_ip,
            target_hardware_addr: EthernetAddress::default(),
            target_protocol_addr: target_ip,
        };
        let mut buf = vec![0u8; EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len())];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(EthernetAddress::BROADCAST);
        frame.set_src_addr(sender_mac);
        frame.set_ethertype(EthernetProtocol::Arp);
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);
        buf
    }

    /// Build a minimal IPv4 frame carrying the given ethertype payload.
    fn ip_frame(
        src_mac: EthernetAddress,
        dst_mac: EthernetAddress,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: IpProtocol,
        payload: &[u8],
    ) -> Vec<u8> {
        let ip_repr = Ipv4Repr {
            src_addr: src_ip,
            dst_addr: dst_ip,
            next_header: protocol,
            payload_len: payload.len(),
            hop_limit: 64,
        };
        let mut buf =
            vec![0u8; EthernetFrame::<&[u8]>::buffer_len(ip_repr.buffer_len() + payload.len())];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_mac);
        frame.set_src_addr(src_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::ignored());
        // Fill IP header checksum explicitly since ignored caps skipped it.
        ip_packet.fill_checksum();
        ip_packet.payload_mut().copy_from_slice(payload);
        buf
    }

    /// Build a TCP SYN from `src:src_port` to `dst:dst_port`.
    fn tcp_syn(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let src_mac = EthernetAddress(MacAddr::for_switch_ip(src_ip).0);
        let dst_mac = EthernetAddress(MacAddr::for_switch_ip(dst_ip).0);
        let repr = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1_000_000),
            ack_number: None,
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let mut tcp_buf = vec![0u8; repr.buffer_len()];
        let mut tcp = TcpPacket::new_unchecked(&mut tcp_buf);
        repr.emit(
            &mut tcp,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            &ChecksumCapabilities::default(),
        );
        ip_frame(src_mac, dst_mac, src_ip, dst_ip, IpProtocol::Tcp, &tcp_buf)
    }

    /// Build a TCP segment carrying RST, with or without ACK, from
    /// `src:src_port` to `dst:dst_port`.
    fn tcp_rst(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        with_ack: bool,
    ) -> Vec<u8> {
        let src_mac = EthernetAddress(MacAddr::for_switch_ip(src_ip).0);
        let dst_mac = EthernetAddress(MacAddr::for_switch_ip(dst_ip).0);
        let repr = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(1_000_000),
            ack_number: with_ack.then_some(TcpSeqNumber(2_000_000)),
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let mut tcp_buf = vec![0u8; repr.buffer_len()];
        let mut tcp = TcpPacket::new_unchecked(&mut tcp_buf);
        repr.emit(
            &mut tcp,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            &ChecksumCapabilities::default(),
        );
        ip_frame(src_mac, dst_mac, src_ip, dst_ip, IpProtocol::Tcp, &tcp_buf)
    }

    /// Build a UDP datagram from `src:src_port` to `dst:dst_port`.
    fn udp_datagram(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_mac = EthernetAddress(MacAddr::for_switch_ip(src_ip).0);
        let dst_mac = EthernetAddress(MacAddr::for_switch_ip(dst_ip).0);
        let repr = UdpRepr { src_port, dst_port };
        let mut udp_buf = vec![0u8; 8 + payload.len()];
        let mut udp = UdpPacket::new_unchecked(&mut udp_buf);
        repr.emit(
            &mut udp,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        ip_frame(src_mac, dst_mac, src_ip, dst_ip, IpProtocol::Udp, &udp_buf)
    }

    fn expect_one_arp_reply(
        ends: &mut BepDeviceEnds,
        host_mac: EthernetAddress,
        host_ip: Ipv4Addr,
        peer_mac: EthernetAddress,
        peer_ip: Ipv4Addr,
    ) {
        let reply = ends.outbound.try_recv().expect("expected an ARP reply");
        let frame = EthernetFrame::new_checked(&reply).expect("reply is ethernet");
        assert_eq!(frame.dst_addr(), peer_mac);
        assert_eq!(frame.src_addr(), host_mac);
        assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
        let arp = ArpPacket::new_checked(frame.payload()).unwrap();
        assert_eq!(
            ArpRepr::parse(&arp).unwrap(),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: host_mac,
                source_protocol_addr: host_ip,
                target_hardware_addr: peer_mac,
                target_protocol_addr: peer_ip,
            }
        );
    }

    /// A box ARPs before it connects — the exchange that also teaches the
    /// stack the neighbour it answers back through (smoltcp fills its
    /// neighbour cache from any ARP packet aimed at it, requests included).
    fn arp_exchange(
        host: &mut BepHost,
        ends: &mut BepDeviceEnds,
        peer_ip: Ipv4Addr,
        host_ip: Ipv4Addr,
    ) {
        let peer_mac = EthernetAddress(MacAddr::for_switch_ip(peer_ip).0);
        ends.inbound
            .send(arp_request(peer_mac, peer_ip, host_ip))
            .expect("send the ARP request into the device");
        host.poll(Instant::from_millis(0));
        expect_one_arp_reply(ends, host.mac(), host_ip, peer_mac, peer_ip);
    }

    #[test]
    fn proxy_address_answers_arp_from_the_host_stack() {
        let subnet = SwitchSubnet::default();
        let ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        let peer_mac = EthernetAddress(MacAddr::for_switch_ip(peer_ip).0);
        ends.inbound
            .send(arp_request(peer_mac, peer_ip, ip))
            .expect("send the ARP request into the device");
        host.poll(Instant::from_millis(0));

        expect_one_arp_reply(&mut ends, host.mac(), ip, peer_mac, peer_ip);
        assert!(matches!(
            ends.outbound.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn host_stack_answers_arp_for_its_address() {
        let subnet = SwitchSubnet::default();
        let ip = subnet.gateway();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        let peer_mac = EthernetAddress(MacAddr::for_switch_ip(peer_ip).0);
        ends.inbound
            .send(arp_request(peer_mac, peer_ip, ip))
            .expect("send the ARP request into the device");
        host.poll(Instant::from_millis(0));

        expect_one_arp_reply(&mut ends, host.mac(), ip, peer_mac, peer_ip);
    }

    #[test]
    fn tcp_to_unlistened_proxy_port_is_reset() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        arp_exchange(&mut host, &mut ends, peer_ip, proxy_ip);

        ends.inbound
            .send(tcp_syn(peer_ip, proxy_ip, 1234, 443))
            .expect("send TCP SYN");
        host.poll(Instant::from_millis(0));

        let reply = ends.outbound.try_recv().expect("expected a TCP reset");
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.src_addr(), host.mac());
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert_eq!(ip.src_addr(), proxy_ip);
        assert_eq!(ip.dst_addr(), peer_ip);
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.rst());
        assert_eq!(tcp.dst_port(), 1234);
        assert_eq!(tcp.src_port(), 443);
    }

    /// RFC 9293 section 3.5.2: a segment carrying RST is never answered with
    /// a reset, with or without ACK alongside it.
    #[test]
    fn incoming_rst_gets_no_reply() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        for with_ack in [false, true] {
            ends.inbound
                .send(tcp_rst(peer_ip, proxy_ip, 1234, 443, with_ack))
                .expect("send TCP RST");
            host.poll(Instant::from_millis(0));
            assert!(
                matches!(
                    ends.outbound.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "a RST (ack={with_ack}) must not be answered"
            );
        }
    }

    #[test]
    fn udp_to_proxy_address_gets_port_unreachable() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        arp_exchange(&mut host, &mut ends, peer_ip, proxy_ip);

        ends.inbound
            .send(udp_datagram(peer_ip, proxy_ip, 1234, 53, b"query"))
            .expect("send UDP datagram");
        host.poll(Instant::from_millis(0));

        let reply = ends.outbound.try_recv().expect("expected an ICMP reply");
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.src_addr(), host.mac());
        let ip = Ipv4Packet::new_checked(frame.payload()).unwrap();
        assert_eq!(ip.src_addr(), proxy_ip);
        assert_eq!(ip.dst_addr(), peer_ip);
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(
            icmp.msg_type(),
            smoltcp::wire::Icmpv4Message::DstUnreachable
        );
        assert_eq!(icmp.msg_code(), 3); // port unreachable
        assert!(icmp.verify_checksum());
        // The returned data must carry the original IP header + UDP header.
        let returned = icmp.data();
        assert!(returned.len() >= 28);
        let expected_dst = u32::from(proxy_ip).to_be_bytes();
        assert_eq!(&returned[16..20], &expected_dst);
        let expected_src_port = 1234u16.to_be_bytes();
        let expected_dst_port = 53u16.to_be_bytes();
        assert_eq!(&returned[20..22], &expected_src_port);
        assert_eq!(&returned[22..24], &expected_dst_port);
    }

    #[test]
    fn stack_peer_originates_frames_only_to_the_box_that_addressed_it() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);

        let peer_a_ip = Ipv4Addr::from(subnet.first_ptask());
        let peer_a_mac = EthernetAddress(MacAddr::for_switch_ip(peer_a_ip).0);
        let peer_b_ip = Ipv4Addr::from(subnet.first_ptask() + 1);
        let peer_b_mac = EthernetAddress(MacAddr::for_switch_ip(peer_b_ip).0);

        // A asks for proxy ARP.
        ends.inbound
            .send(arp_request(peer_a_mac, peer_a_ip, proxy_ip))
            .unwrap();
        host.poll(Instant::from_millis(0));
        let reply = ends.outbound.try_recv().unwrap();
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.dst_addr(), peer_a_mac);
        assert!(frame.ethertype() == EthernetProtocol::Arp);

        // B asks for proxy ARP.
        ends.inbound
            .send(arp_request(peer_b_mac, peer_b_ip, proxy_ip))
            .unwrap();
        host.poll(Instant::from_millis(0));
        let reply = ends.outbound.try_recv().unwrap();
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.dst_addr(), peer_b_mac);
        assert!(frame.ethertype() == EthernetProtocol::Arp);

        // A sends a TCP SYN; the reply goes back to A, not B.
        ends.inbound
            .send(tcp_syn(peer_a_ip, proxy_ip, 1000, 80))
            .unwrap();
        host.poll(Instant::from_millis(0));
        let reply = ends.outbound.try_recv().unwrap();
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.dst_addr(), peer_a_mac);
        assert!(frame.ethertype() == EthernetProtocol::Ipv4);

        // A UDP from B to the proxy address goes back to B.
        ends.inbound
            .send(udp_datagram(peer_b_ip, proxy_ip, 1000, 53, b"x"))
            .unwrap();
        host.poll(Instant::from_millis(0));
        let reply = ends.outbound.try_recv().unwrap();
        let frame = EthernetFrame::new_checked(&reply).unwrap();
        assert_eq!(frame.dst_addr(), peer_b_mac);
        assert!(
            matches!(
                ends.outbound.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "no extra broadcast frames should be emitted"
        );
    }

    /// NET-132/T69: the pool's sockets exist only for registered boxes. A
    /// bare stack — no row registered — binds no socket at build time and
    /// stays socketless across a turn that reset a segment and answered a
    /// datagram: those answers are the stack's own, not a socket's, and the
    /// sockets that may bind appear with a box's row and leave with it (the
    /// lane tests below pin that).
    #[test]
    fn peer_binds_no_socket() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);
        assert_eq!(host.sockets.iter().count(), 0, "no socket at build time");

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
        arp_exchange(&mut host, &mut ends, peer_ip, proxy_ip);
        ends.inbound
            .send(tcp_syn(peer_ip, proxy_ip, 1234, 443))
            .unwrap();
        ends.inbound
            .send(udp_datagram(peer_ip, proxy_ip, 1234, 53, b"query"))
            .unwrap();
        host.poll(Instant::from_millis(0));
        assert_eq!(
            host.sockets.iter().count(),
            0,
            "answering traffic binds no socket"
        );
        // Two answers went out — the reset and the port-unreachable — and
        // nothing else. The ARP reply is accounted inside `arp_exchange`,
        // which consumed it while teaching the stack its neighbour.
        for expected in ["reset", "port unreachable"] {
            assert!(
                ends.outbound.try_recv().is_ok(),
                "expected the {expected} to leave"
            );
        }
        assert!(matches!(
            ends.outbound.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    /// NET-132: the host-side stack peer starts when the switch socket is ready
    /// and its drop aborts the socket connection and the poll task. We stand in
    /// for gvproxy with a bound listener that accepts the connect upgrade; the
    /// peer dials it, sends the upgrade head, and then runs until dropped.
    #[tokio::test]
    async fn stack_peer_stops_with_the_switch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("switch.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind stand-in switch socket");

        // Accept the peer's connection on a separate task so `spawn` completes.
        let accept_fut = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("peer connected");
            // The peer must send the HyperKit upgrade head verbatim.
            let mut head = vec![0u8; super::CONNECT_REQUEST.len()];
            stream
                .read_exact(&mut head)
                .await
                .expect("read upgrade head");
            assert_eq!(&head, super::CONNECT_REQUEST);
            stream
        });

        let subnet = SwitchSubnet::default();
        let wire = BepWire::new(dir.path().join("proxy.sock"), [0u8; TOKEN_LEN]);
        let peer = BepPeer::spawn(&sock, subnet, wire, Arc::new(EmptyBoxes))
            .await
            .expect("peer spawns against a listening switch socket");

        // Wait for the acceptor to confirm the upgrade head was received; once it
        // has, the connection is live from the peer's side. Dropping the peer
        // must then close that connection, which the acceptor observes as EOF.
        let mut accepted = accept_fut.await.expect("acceptor task completed");

        drop(peer);

        // Give the peer tasks a moment to be aborted and the socket closed.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A read on the still-open accepted socket must now return EOF because
        // the peer's side has gone away.
        let mut buf = [0u8; 1];
        let n = accepted
            .read(&mut buf)
            .await
            .expect("read after peer drop should not error");
        assert_eq!(n, 0, "peer socket must close when the peer is dropped");
    }

    /// A stand-in for the switch's `-listen` socket: bound at `sock`, it
    /// accepts the peer's one connection, checks the upgrade head and hands
    /// back the raw frame stream the switch would carry.
    async fn stand_in_switch(sock: &Path) -> tokio::task::JoinHandle<tokio::net::UnixStream> {
        let listener = tokio::net::UnixListener::bind(sock).expect("bind stand-in switch socket");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("peer connected");
            let mut head = vec![0u8; super::CONNECT_REQUEST.len()];
            stream
                .read_exact(&mut head)
                .await
                .expect("read upgrade head");
            assert_eq!(&head, super::CONNECT_REQUEST);
            stream
        })
    }

    /// Read one length-framed Ethernet frame off the stand-in switch stream.
    async fn read_framed(stream: &mut tokio::net::UnixStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .expect("read the length prefix");
        let mut frame = vec![0u8; usize::from(u16::from_le_bytes(len_buf))];
        stream.read_exact(&mut frame).await.expect("read the frame");
        frame
    }

    /// NET-132: the peer is silent until addressed. Across an interval that
    /// covers several poll periods, an idle peer writes nothing onto the
    /// switch socket: no gratuitous ARP at attach, no probe, nothing — and
    /// with no registered box, no socket either.
    #[tokio::test]
    async fn idle_peer_emits_no_frames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("switch.sock");
        let accept_fut = stand_in_switch(&sock).await;

        let peer = BepPeer::spawn(
            &sock,
            SwitchSubnet::default(),
            BepWire::new(dir.path().join("proxy.sock"), [0u8; TOKEN_LEN]),
            Arc::new(EmptyBoxes),
        )
        .await
        .expect("peer spawns against a listening switch socket");
        let mut switch = accept_fut.await.expect("acceptor task completed");

        // Five poll periods: long enough for any announcement or probe the
        // stack might schedule at attach to have been written.
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(POLL_DELAY * 5, switch.read(&mut buf)).await;
        assert!(
            read.is_err(),
            "the idle peer wrote {:?} onto the switch socket",
            read.map(|n| n.map(|n| buf[..n].to_vec()))
        );
        drop(peer);
    }

    /// NET-132 over the production path: the real [`BepPeer`] — reader pump,
    /// poll task, writer pump — answers an ARP request for the proxy address
    /// that arrives length-framed on the switch socket, and the reply comes
    /// back length-framed on the same socket, addressed to the asking box.
    /// The length prefix is written one byte at a time so a short read of it
    /// cannot end the peer.
    #[tokio::test]
    async fn spawned_peer_answers_arp_over_the_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("switch.sock");
        let accept_fut = stand_in_switch(&sock).await;

        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let proxy_mac = EthernetAddress(MacAddr::for_switch_ip(proxy_ip).0);
        let peer = BepPeer::spawn(
            &sock,
            subnet,
            BepWire::new(dir.path().join("proxy.sock"), [0u8; TOKEN_LEN]),
            Arc::new(EmptyBoxes),
        )
        .await
        .expect("peer spawns against a listening switch socket");
        let mut switch = accept_fut.await.expect("acceptor task completed");

        let box_ip = Ipv4Addr::from(subnet.first_ptask());
        let box_mac = EthernetAddress(MacAddr::for_switch_ip(box_ip).0);
        let request = arp_request(box_mac, box_ip, proxy_ip);
        let len = u16::try_from(request.len()).unwrap().to_le_bytes();
        switch.write_all(&len[..1]).await.unwrap();
        switch.flush().await.unwrap();
        tokio::time::sleep(POLL_DELAY).await;
        switch.write_all(&len[1..]).await.unwrap();
        switch.write_all(&request).await.unwrap();
        switch.flush().await.unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut switch))
            .await
            .expect("the peer answered within five seconds");
        let frame = EthernetFrame::new_checked(&reply).expect("reply is ethernet");
        assert_eq!(frame.dst_addr(), box_mac);
        assert_eq!(frame.src_addr(), proxy_mac);
        assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
        let arp = ArpPacket::new_checked(frame.payload()).unwrap();
        assert_eq!(
            ArpRepr::parse(&arp).unwrap(),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: proxy_mac,
                source_protocol_addr: proxy_ip,
                target_hardware_addr: box_mac,
                target_protocol_addr: box_ip,
            }
        );
        drop(peer);
    }

    // ── The listener pool and the delivery (T69, NET-132) ─────────────────────
    //
    // The proofs below drive one `BepStack` against one stand-in acceptor
    // over a real unix socket, with the boxes speaking through the
    // `test_util` lane: the delivery's dial, header and pumps run exactly as
    // they do behind a spawned peer, only the switch lane is channel-wired
    // so the tests own every turn.

    /// A mutable stand-in for the registry's rows: what the pool
    /// partitions by, driven by hand in the tests the way `minvmd`'s table
    /// is driven by its control socket.
    #[derive(Clone, Default)]
    struct TestBoxes(StdArc<StdMutex<Vec<Ipv4Addr>>>);

    impl TestBoxes {
        fn register(&self, ip: Ipv4Addr) {
            self.0.lock().unwrap().push(ip);
        }

        fn withdraw(&self, ip: Ipv4Addr) {
            self.0.lock().unwrap().retain(|row| *row != ip);
        }
    }

    impl BepBoxSource for TestBoxes {
        fn box_switch_addresses(&self) -> Vec<Ipv4Addr> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A box source with no rows: the pool holds nothing.
    struct EmptyBoxes;

    impl BepBoxSource for EmptyBoxes {
        fn box_switch_addresses(&self) -> Vec<Ipv4Addr> {
            Vec::new()
        }
    }

    /// What one stand-in acceptor took: the header a delivery presented.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Accepted {
        box_id: BoxId,
        source: IpEndpoint,
        destination: IpEndpoint,
    }

    /// The one connection the stand-in acceptor holds instead of serving:
    /// identified by the endpoint its header presented — the pool's slots
    /// are not a queue, so an order number would lie about which flow it is.
    #[derive(Debug, Clone, Copy)]
    enum Stall {
        None,
        Source(IpEndpoint),
    }

    /// A stand-in for the proxy's acceptor: one connection per flow, the
    /// per-boot token and then the fixed header ahead of any flow byte, and
    /// one answer line back for each connection it takes. What it took is
    /// recorded for the assertions.
    struct TestAcceptor {
        accepted: StdArc<StdMutex<Vec<Accepted>>>,
        connections: StdArc<AtomicUsize>,
    }

    impl TestAcceptor {
        async fn start(sock: &Path, token: [u8; TOKEN_LEN], stall: Stall) -> std::io::Result<Self> {
            let listener = tokio::net::UnixListener::bind(sock)?;
            let accepted = StdArc::new(StdMutex::new(Vec::new()));
            let connections = StdArc::new(AtomicUsize::new(0));
            let accepted_task = StdArc::clone(&accepted);
            let connections_task = StdArc::clone(&connections);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    connections_task.fetch_add(1, Ordering::Relaxed);
                    let accepted_task = StdArc::clone(&accepted_task);
                    tokio::spawn(async move {
                        serve_acceptor_connection(stream, token, stall, accepted_task).await;
                    });
                }
            });
            Ok(Self {
                accepted,
                connections,
            })
        }

        /// The headers the deliveries presented, in the order the acceptor
        /// took them.
        fn accepted(&self) -> Vec<Accepted> {
            self.accepted.lock().unwrap().clone()
        }

        /// How many connections the acceptor took, stalled ones included.
        fn connections(&self) -> usize {
            self.connections.load(Ordering::Relaxed)
        }
    }

    /// Serve one delivered connection the way the proxy's acceptor is
    /// promised it: token first, then the fixed header, then one answer
    /// line naming the source, then the flow's bytes — held open until the
    /// box closes, the way a live acceptor holds its connections.
    async fn serve_acceptor_connection(
        mut stream: tokio::net::UnixStream,
        token: [u8; TOKEN_LEN],
        stall: Stall,
        accepted: StdArc<StdMutex<Vec<Accepted>>>,
    ) {
        let mut token_buf = [0u8; TOKEN_LEN];
        stream
            .read_exact(&mut token_buf)
            .await
            .expect("a delivery writes the per-boot token first");
        assert_eq!(
            token_buf, token,
            "the peer presented this boot's per-boot token"
        );
        let mut head = [0u8; DELIVERY_HEADER_LEN];
        stream
            .read_exact(&mut head)
            .await
            .expect("a delivery writes its fixed header after the token");
        assert_eq!(
            head[0], DELIVERY_HEADER_VERSION,
            "the delivery header is the peer's wire version"
        );
        let header = DeliveryHeader::parse(&head).expect("the header parses");
        if let Stall::Source(stalled) = stall
            && header.source == stalled
        {
            // The slow acceptor: the connection is taken and held — never
            // read again, never answered, never closed — the way a live
            // acceptor that stopped reading holds its connection. Holding
            // it is the whole point: dropping the stream here would close
            // the connection, and the stall would be a close.
            std::future::pending::<()>().await;
        }
        accepted.lock().unwrap().push(Accepted {
            box_id: header.box_id,
            source: header.source,
            destination: header.destination,
        });
        let line = format!(
            "source={} destination={}\n",
            header.source, header.destination
        );
        if stream.write_all(line.as_bytes()).await.is_err() {
            return;
        }
        let mut sink = [0u8; FLOW_CHUNK_LEN];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }

    /// Drive the lane for `rounds` turns, letting the delivery tasks run
    /// between them.
    async fn drive(lane: &mut test_util::TestLane, rounds: usize) {
        for _ in 0..rounds {
            lane.step().await;
        }
    }

    /// Read what a flow has received so far, driving the lane while it stays
    /// empty.
    async fn read_flow(
        lane: &mut test_util::TestLane,
        box_idx: usize,
        flow: usize,
        rounds: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..rounds {
            {
                let box_stack = &mut lane.boxes_mut()[box_idx];
                let mut buf = [0u8; 4096];
                loop {
                    let n = box_stack.recv(flow, &mut buf);
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
            lane.step().await;
        }
        out
    }

    /// The lane, the boxes and the acceptor the pool tests share. The
    /// acceptor binds its socket in the harness's tempdir, which must
    /// outlive the test: a unix socket's file leaving before the flows dial
    /// turns every delivery into a refusal.
    struct PoolHarness {
        lane: test_util::TestLane,
        boxes: TestBoxes,
        acceptor: Option<TestAcceptor>,
        _dir: tempfile::TempDir,
    }

    /// Build the pool at `caps` per registered box, with the acceptor up (or
    /// not) and one flow pre-picked to stall.
    async fn harness(
        caps: usize,
        stall: Stall,
        acceptor_up: bool,
    ) -> (PoolHarness, PathBuf, [u8; TOKEN_LEN]) {
        let subnet = SwitchSubnet::default();
        let dir = tempfile::tempdir().expect("tempdir");
        let proxy_sock = dir.path().join("proxy.sock");
        let token = [0x5au8; TOKEN_LEN];
        let acceptor = if acceptor_up {
            Some(
                TestAcceptor::start(&proxy_sock, token, stall)
                    .await
                    .expect("bind the stand-in acceptor"),
            )
        } else {
            None
        };
        let boxes = TestBoxes::default();
        let wire = BepWire::new(proxy_sock.clone(), token).with_per_source_cap(caps);
        let lane = test_util::TestLane::new(subnet, wire, Arc::new(boxes.clone()));
        (
            PoolHarness {
                lane,
                boxes,
                acceptor,
                _dir: dir,
            },
            proxy_sock,
            token,
        )
    }

    /// Register two boxes, add them to the lane, ARP the proxy, and drive the
    /// handshakes: the shape every pool test starts from.
    async fn bring_up_two_boxes(h: &mut PoolHarness) {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_a = Ipv4Addr::from(subnet.first_ptask());
        let box_b = Ipv4Addr::from(subnet.first_ptask() + 1);
        h.boxes.register(box_a);
        h.boxes.register(box_b);
        drive(&mut h.lane, 2).await;
        h.lane.add_box(box_a);
        h.lane.add_box(box_b);
        drive(&mut h.lane, 1).await;
        h.lane.boxes_mut()[0].arp_for(proxy_ip);
        h.lane.boxes_mut()[1].arp_for(proxy_ip);
        drive(&mut h.lane, 3).await;
    }

    /// NET-132/T69: a box may hold its cap's worth of connections; the next
    /// one is reset, and the ones it holds stand. The two delivered
    /// connections arrive at the acceptor from the box's own switch address
    /// — the delivery header's source — with the per-boot token and the
    /// fixed header ahead of any flow byte, and one connection each.
    #[tokio::test]
    async fn connections_past_the_per_source_cap_are_reset() {
        let cap = 2;
        let (mut h, _proxy_sock, _token) = harness(cap, Stall::None, true).await;
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());

        // No row registered: the pool holds nothing.
        assert_eq!(h.lane.pool_len(), 0, "no registered box: no share");
        // The row lands: its share is the cap.
        h.boxes.register(box_ip);
        drive(&mut h.lane, 2).await;
        assert_eq!(
            h.lane.pool_len(),
            cap,
            "one registered box: its share is the per-source cap"
        );

        h.lane.add_box(box_ip);
        drive(&mut h.lane, 1).await;
        h.lane.boxes_mut()[0].arp_for(proxy_ip);
        drive(&mut h.lane, 3).await;

        let box_stack = &mut h.lane.boxes_mut()[0];
        let within = box_stack.connect(proxy_ip, PROXY_PORT);
        let within2 = box_stack.connect(proxy_ip, PROXY_PORT);
        let past = box_stack.connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 40).await;

        // The two within the cap stand and were delivered: the acceptor took
        // both, one connection each, from the box's own address.
        let accepted = h.acceptor.as_ref().expect("acceptor").accepted();
        assert_eq!(accepted.len(), cap, "one connection per admitted flow");
        for header in &accepted {
            assert_eq!(header.source.addr, IpAddress::Ipv4(box_ip));
            assert_eq!(header.destination.addr, IpAddress::Ipv4(proxy_ip));
            assert_eq!(header.destination.port, PROXY_PORT);
            assert_eq!(header.box_id, [0u8; 16], "the box id stays zero until T44");
        }
        // ... and both answers came back to the box.
        for flow in [within, within2] {
            let answer = read_flow(&mut h.lane, 0, flow, 8).await;
            assert!(
                answer.starts_with(b"source="),
                "the acceptor's answer arrived: {:?}",
                String::from_utf8_lossy(&answer)
            );
            assert_eq!(
                h.lane.boxes()[0].flow_state(flow),
                State::Established,
                "an admitted connection stands"
            );
        }
        // The connection past the cap was reset.
        assert_eq!(
            h.lane.boxes()[0].flow_state(past),
            State::Closed,
            "the connection past the per-source cap was reset"
        );
        // The pool still holds exactly the one box's share.
        assert_eq!(h.lane.pool_len(), cap);
    }

    /// NET-132/T69: one box's exhaustion never starves a sibling. Box A
    /// holds its cap's worth; its next connection is aborted — never
    /// dialed, the slot it took returns to the pool — so box B's connection
    /// is still delivered. The pool's total is the sum of the shares: A's
    /// exhaustion costs A alone.
    #[tokio::test]
    async fn one_boxs_exhaustion_never_starves_a_sibling() {
        let (mut h, _proxy_sock, _token) = harness(1, Stall::None, true).await;
        bring_up_two_boxes(&mut h).await;
        assert_eq!(
            h.lane.pool_len(),
            2,
            "two registered boxes: two shares of one"
        );
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_a = Ipv4Addr::from(subnet.first_ptask());
        let box_b = Ipv4Addr::from(subnet.first_ptask() + 1);

        let a_first = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 20).await;
        let a_second = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 20).await;
        let b_first = h.lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 30).await;

        // A holds its one connection; the answer came back to it.
        let answer = read_flow(&mut h.lane, 0, a_first, 8).await;
        assert!(
            answer.starts_with(b"source="),
            "A's admitted connection was delivered and answered"
        );
        // A's second — past its cap — was reset.
        assert_eq!(
            h.lane.boxes()[0].flow_state(a_second),
            State::Closed,
            "A's connection past its share was reset"
        );
        // B's connection still went through, from its own address.
        let answer_b = read_flow(&mut h.lane, 1, b_first, 8).await;
        assert!(
            answer_b.starts_with(b"source="),
            "B's connection was delivered and answered"
        );
        let accepted = h.acceptor.as_ref().expect("acceptor").accepted();
        assert_eq!(accepted.len(), 2, "one connection per admitted flow");
        assert_eq!(accepted[0].source.addr, IpAddress::Ipv4(box_a));
        assert_eq!(accepted[1].source.addr, IpAddress::Ipv4(box_b));
        assert_eq!(h.lane.pool_len(), 2, "the shares stand");
    }

    /// NET-132/T69: a slow acceptor stalls one flow, not the stack. The
    /// acceptor takes one of A's connections and never reads it; A's other
    /// flow and B's flow are still delivered and answered while the stalled
    /// one sits. Push past every buffer the path holds and the box's own
    /// window is the brake — it can send no more — while the sibling's
    /// fresh flow still round-trips: the stack never waited on the one
    /// stalled connection.
    #[tokio::test]
    async fn a_slow_acceptor_stalls_one_flow_not_the_stack() {
        let cap = 2;
        // Stall the flow from box A's first client port.
        let subnet = SwitchSubnet::default();
        let box_a = Ipv4Addr::from(subnet.first_ptask());
        let stalled_source = IpEndpoint {
            addr: IpAddress::Ipv4(box_a),
            port: test_util::FIRST_CLIENT_PORT,
        };
        let (mut h, _proxy_sock, _token) = harness(cap, Stall::Source(stalled_source), true).await;
        bring_up_two_boxes(&mut h).await;
        let proxy_ip = subnet.box_egress_proxy_address();

        let a_stalled = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        let a_moving = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        let b_moving = h.lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 40).await;

        // All three were delivered — the acceptor took all three — but only
        // the two it reads answer.
        assert_eq!(h.acceptor.as_ref().expect("acceptor").connections(), 3);
        for (box_idx, flow) in [(0, a_moving), (1, b_moving)] {
            let answer = read_flow(&mut h.lane, box_idx, flow, 8).await;
            assert!(
                answer.starts_with(b"source="),
                "a flow beside the stalled one still round-trips"
            );
        }
        let stalled_answer = read_flow(&mut h.lane, 0, a_stalled, 10).await;
        assert!(
            stalled_answer.is_empty(),
            "the stalled flow got no answer while its siblings did"
        );

        // Push into the stalled flow until the box's own window is the
        // brake: with the acceptor holding its read side, the only space
        // left is the buffers the path holds, and past those the socket's
        // window closes on the box — it can send no more.
        let chunk = vec![0u8; 1024];
        let mut stalled_turns = 0;
        for _ in 0..800 {
            let mut pushed = 0;
            loop {
                let n = h.lane.boxes_mut()[0].send(a_stalled, &chunk);
                if n == 0 {
                    break;
                }
                pushed += n;
            }
            h.lane.step().await;
            if pushed > 0 {
                stalled_turns = 0;
            } else {
                stalled_turns += 1;
                if stalled_turns >= 5 {
                    break;
                }
            }
        }
        assert!(
            stalled_turns >= 5,
            "the stalled flow's window closed on the box: it cannot send"
        );

        // And the stack kept moving the whole time: B's next connection —
        // fresh, beside the stalled one — is delivered and answered.
        let b_fresh = h.lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 30).await;
        let answer = read_flow(&mut h.lane, 1, b_fresh, 8).await;
        assert!(
            answer.starts_with(b"source="),
            "a fresh flow still round-trips while one is stalled"
        );
        assert_eq!(
            h.acceptor.as_ref().expect("acceptor").connections(),
            4,
            "every dial was its own connection"
        );
    }

    /// NET-132/T69: an acceptor that is down resets the box's connection.
    /// No listener sits at the proxy socket, so the dial fails and the
    /// pool's socket aborts: the box's client sees its connection reset,
    /// and the slot returns to its share — the next connection is reset the
    /// same way, and the share never leaks away.
    #[tokio::test]
    async fn a_down_acceptor_resets_the_boxs_connection() {
        let (mut h, _proxy_sock, _token) = harness(1, Stall::None, false).await;
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());

        h.boxes.register(box_ip);
        drive(&mut h.lane, 2).await;
        assert_eq!(h.lane.pool_len(), 1, "the box's share");

        h.lane.add_box(box_ip);
        drive(&mut h.lane, 1).await;
        h.lane.boxes_mut()[0].arp_for(proxy_ip);
        drive(&mut h.lane, 3).await;

        let first = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 30).await;
        assert_eq!(
            h.lane.boxes()[0].flow_state(first),
            State::Closed,
            "the dial found no acceptor: the connection was reset"
        );
        assert_eq!(h.lane.pool_len(), 1, "the slot returned to its share");

        // The next connection meets the same acceptor and the same reset.
        let second = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 30).await;
        assert_eq!(
            h.lane.boxes()[0].flow_state(second),
            State::Closed,
            "the recycled slot's next connection was reset too"
        );
        assert_eq!(h.lane.pool_len(), 1, "the share never leaks away");
    }

    /// NET-132/T69: a withdrawn row takes its share with it — its live
    /// flows are aborted, the listening slots are removed, and the pool
    /// holds the rows that remain.
    #[tokio::test]
    async fn a_withdrawn_boxs_share_is_withdrawn() {
        let (mut h, _proxy_sock, _token) = harness(1, Stall::None, true).await;
        bring_up_two_boxes(&mut h).await;
        assert_eq!(h.lane.pool_len(), 2);
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_a = Ipv4Addr::from(subnet.first_ptask());

        let a_flow = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 25).await;
        assert_eq!(h.lane.boxes()[0].flow_state(a_flow), State::Established);

        // Box A's row goes: its share goes with it, and its live connection
        // is aborted. B's share and B's connections are untouched.
        h.boxes.withdraw(box_a);
        drive(&mut h.lane, 10).await;
        assert_eq!(h.lane.pool_len(), 1, "only B's share remains");
        assert_eq!(
            h.lane.boxes()[0].flow_state(a_flow),
            State::Closed,
            "the withdrawn box's connection was aborted"
        );
        let b_flow = h.lane.boxes_mut()[1].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 30).await;
        let answer = read_flow(&mut h.lane, 1, b_flow, 8).await;
        assert!(
            answer.starts_with(b"source="),
            "B still connects through its share"
        );
    }

    /// NET-132/T69: a box that finished sending as it connected still owns
    /// a connection. A FIN that arrives with — or right behind — the
    /// handshake's ACK takes the pool's socket straight past `Established`
    /// into `CloseWait`, and such a connection is still delivered: the
    /// acceptor takes it from the box's own switch address, and the answer
    /// still reaches a box that can only listen.
    #[tokio::test]
    async fn a_half_closed_connection_is_still_delivered() {
        let (mut h, _proxy_sock, _token) = harness(1, Stall::None, true).await;
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());

        h.boxes.register(box_ip);
        drive(&mut h.lane, 2).await;
        h.lane.add_box(box_ip);
        drive(&mut h.lane, 1).await;
        h.lane.boxes_mut()[0].arp_for(proxy_ip);
        drive(&mut h.lane, 3).await;

        // Three turns in: the SYN across, the stack asking for the box's
        // address on the way, the SYN-ACK back, the box established — its
        // ACK still queued on the box's side of the lane, so the stack's
        // socket is not established yet and nothing has been delivered.
        let flow = h.lane.boxes_mut()[0].connect(proxy_ip, PROXY_PORT);
        drive(&mut h.lane, 3).await;
        assert_eq!(h.lane.boxes()[0].flow_state(flow), State::Established);
        assert_eq!(
            h.acceptor.as_ref().expect("acceptor").connections(),
            0,
            "the handshake has not reached the stack's service pass yet"
        );

        // The box finished sending with the connect, the way the e2e probe
        // does: its FIN joins the handshake's ACK in the box's queue, so the
        // stack's one poll takes the connection straight to CloseWait — a
        // handshake the service pass never sees as established.
        let now = h.lane.now();
        {
            let b = &mut h.lane.boxes_mut()[0];
            b.close(flow);
            b.poll(now);
        }
        drive(&mut h.lane, 8).await;

        // The connection was delivered anyway: the acceptor took it once,
        // from the box's own switch address, at the proxy's port.
        let accepted = h.acceptor.as_ref().expect("acceptor").accepted();
        assert_eq!(
            accepted.len(),
            1,
            "a connection the box half-closed at connect was still delivered"
        );
        assert_eq!(accepted[0].source.addr, IpAddress::Ipv4(box_ip));
        assert_eq!(accepted[0].destination.addr, IpAddress::Ipv4(proxy_ip));
        assert_eq!(accepted[0].destination.port, PROXY_PORT);
        // And the answer reached the box, which only ever listens.
        let answer = read_flow(&mut h.lane, 0, flow, 8).await;
        assert!(
            answer.starts_with(b"source="),
            "the answer reached a box that half-closed at connect: {:?}",
            String::from_utf8_lossy(&answer)
        );
    }

    /// The delivery header is exactly the fixed layout the acceptor reads:
    /// version, box id, source, destination — network byte order.
    #[test]
    fn delivery_header_round_trips() {
        let source = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Addr::new(100, 64, 0, 9)),
            port: 41_234,
        };
        let destination = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Addr::new(100, 64, 255, 252)),
            port: PROXY_PORT,
        };
        let header = DeliveryHeader::for_flow(source, destination);
        let mut buf = Vec::new();
        header.emit_into(&mut buf);
        assert_eq!(buf.len(), DELIVERY_HEADER_LEN);
        assert_eq!(buf[0], DELIVERY_HEADER_VERSION);
        assert_eq!(&buf[1..17], &[0u8; 16]);
        assert_eq!(&buf[17..21], &[100, 64, 0, 9]);
        assert_eq!(&buf[21..23], &41_234u16.to_be_bytes());
        assert_eq!(&buf[23..27], &[100, 64, 255, 252]);
        assert_eq!(&buf[27..29], &PROXY_PORT.to_be_bytes());
        assert_eq!(DeliveryHeader::parse(&buf), Some(header));
        assert_eq!(DeliveryHeader::parse(&buf[..buf.len() - 1]), None);
        assert_eq!(header.box_id, [0u8; 16]);
    }
}
