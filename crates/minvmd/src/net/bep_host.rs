//! The Box Egress Proxy's host leg (`bep_host`): a host-side stack peer of
//! the switch, owning the proxy's switch address (NET-132).
//!
//! A box with a credentialed lane reaches the proxy by connecting to the
//! proxy's address on the switch's plan (NET-134). The switch steers frames
//! addressed to that address's derived MAC to whichever of its clients
//! announced the MAC — never to itself: the rendered switch configuration
//! keeps the address out of `gatewayVirtualIPs` and out of `nat`, so the
//! switch neither answers ARP for it nor translates it. The announcer is this
//! leg: a userspace TCP/IP stack on the host, dialing the switch's `-listen`
//! socket as a client the way the egress gate relays for the guest.
//!
//! The host kernel knows nothing of the switch subnet, so the leg terminates
//! those frames itself: one smoltcp [`Interface`] over a channel-backed
//! [`Device`]. The interface owns the proxy address and nothing else — no
//! route, no translation, no second address — and `any_ip` stays off, so it
//! never answers for an address it does not hold. It originates nothing but
//! the frames the leg owes: its ARP reply, a gratuitous ARP announcement at
//! attach — which is what teaches the switch the MAC-to-connection binding
//! the steering rests on — a reset for any TCP segment no socket holds, and a
//! port-unreachable for UDP at the address, each of them only to the box
//! that addressed it. The answers ride the stack's own machinery: a box that
//! has never asked for the proxy's address in this leg's lifetime — one
//! addressing the leg off a stale ARP entry, against the round trip every
//! first frame to the leg makes — costs its answer one ARP request for that
//! box, and the answer follows on the box's next frame.
//!
//! [`BepDevice`] is that [`Device`]: a pair of unbounded tokio channels, one
//! raw Ethernet frame per message on each. [`BepDevice::pair`] hands the
//! caller the [`BepDeviceEnds`] to feed frames in through and take frames out
//! of; the length framing between those edges and the byte stream is the
//! stream reader's and writer's job, as it is in [`egress_gate`]'s relay.
//! [`BepHost`] builds the interface over it, holding the proxy's address
//! derived from the switch's plan and the MAC the switch derives for it
//! ([`MacAddr::for_switch_ip`]).
//!
//! [`run_stack_peer`] wires the three together: one dial of the switch
//! socket, one upgrade to its length-framed Ethernet stream, and one
//! dedicated task running the stack — woken by frames on the switch lane, by
//! the flow pumps ([`BepHost::flow_pumps`], the wake the proxy's own
//! per-flow pumps use once the proxy's sockets land) and by the stack's own
//! timers ([`BepHost::poll_delay`]). The switch runtime starts the peer once
//! the switch socket is up and stops it with the switch.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    HardwareAddress, Icmpv4DstUnreachable, Icmpv4Message, Icmpv4Packet, Ipv4Packet, Ipv4Repr,
    IpAddress, IpCidr, IpProtocol, TcpControl, TcpPacket, TcpRepr, UdpPacket,
};
use switch::{DEFAULT_MTU, MacAddr, SwitchSubnet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::Notify;

/// A channel-backed smoltcp [`Device`] over the switch's Ethernet lane.
///
/// One unbounded channel in (frames arriving from the lane), one out (frames
/// the stack transmits); one raw Ethernet frame per message on each, never a
/// length-prefixed stream chunk — the framing lives at the stream edges that
/// fill and drain these channels (see the module docs).
#[derive(Debug)]
pub struct BepDevice {
    rx: UnboundedReceiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
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
            },
            BepDeviceEnds {
                inbound: inbound_tx,
                outbound: outbound_rx,
            },
        )
    }

    /// Writes one raw frame straight onto the device's egress, past the
    /// stack. The attach announcement the peer owes the switch is a
    /// link-layer frame the interface did not originate, and it rides the
    /// same egress channel as everything the interface does emit, so the
    /// peer drains one lane for both.
    fn emit_raw(&self, frame: Vec<u8>) {
        // A failed send means the device's drain end is gone — it lives in
        // the same [`BepHost`] — so the send cannot fail while the host does.
        drop(self.tx.send(frame));
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
        // No buffered frame: nothing for the interface to process this poll.
        let frame = self.rx.try_recv().ok()?;
        Some((
            BepRxToken { frame },
            BepTxToken {
                tx: self.tx.clone(),
            },
        ))
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
        caps
    }
}

/// One received frame, handed to the interface's poll as a receive token.
pub struct BepRxToken {
    frame: Vec<u8>,
}

impl RxToken for BepRxToken {
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

impl TxToken for BepTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        // A failed send means the leg's peer end is gone — the lane is closed
        // and the frame has nowhere to go. Drop it rather than fail the poll;
        // the lane's teardown is the leg's wiring's to log.
        drop(self.tx.send(frame));
        result
    }
}

/// The wake the proxy's per-flow pumps use to push the peer's poll task
/// along. A pump that has handed the stack work wakes the task through it, so
/// the stack turns the work into segments without waiting for the next frame
/// from the switch or for a stack timer to come due.
#[derive(Clone)]
pub struct FlowPumps {
    notify: Arc<Notify>,
}

impl FlowPumps {
    /// Wake the peer's poll task. `notify_one` parks a permit when no poll
    /// turn is in flight, so a wake ahead of the loop is never lost.
    pub fn wake(&self) {
        self.notify.notify_one();
    }

    /// The future the peer's poll loop parks on between turns.
    pub fn wait(&self) -> impl Future<Output = ()> {
        let notify = Arc::clone(&self.notify);
        async move { notify.notified().await }
    }
}

/// The host leg's stack: one smoltcp [`Interface`] over a channel-backed
/// [`BepDevice`], owning the proxy's address on the switch's plan.
///
/// Built by [`BepHost::new`], stepped by [`BepHost::poll`]. The sockets the
/// proxy terminates come later, when the proxy's own work adds them; the set
/// exists here so the interface has something to poll against from the first
/// frame on, and a segment no socket holds earns its reset and a datagram no
/// socket holds its port-unreachable from the interface's own fallbacks.
pub struct BepHost {
    device: BepDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// The feed the stack's frames arrive through: [`BepHost::receive`]
    /// writes into it, the device's receive side reads it.
    inbound: UnboundedSender<Vec<u8>>,
    /// The drain the stack's frames leave through: the device's egress writes
    /// into it, [`BepHost::drain_transmitted`] reads it.
    outbound: UnboundedReceiver<Vec<u8>>,
    ip: Ipv4Addr,
    mac: EthernetAddress,
    flow_notify: Arc<Notify>,
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
    /// Build the leg's stack over `device`, owning the proxy's address on
    /// `subnet`'s plan: the address above the lease pool the switch steers to
    /// this leg, with its MAC derived the switch's way
    /// ([`MacAddr::for_switch_ip`]).
    ///
    /// The interface holds that one address and nothing else — no route, no
    /// translation, no second address — and `any_ip` stays off, so a frame
    /// not addressed to the proxy's address is answered by nothing.
    #[must_use]
    pub fn new(device: BepDevice, ends: BepDeviceEnds, subnet: SwitchSubnet) -> Self {
        let ip = subnet.box_egress_proxy_address();
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
        // The proxy's address is the leg's own address on the switch's plan,
        // not an alias the leg answers for off-plan: any_ip stays off, so the
        // interface never answers for an address it does not hold.
        iface.set_any_ip(false);
        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            inbound: ends.inbound,
            outbound: ends.outbound,
            ip,
            mac,
            flow_notify: Arc::new(Notify::new()),
        }
    }

    /// The proxy's address on the switch's plan.
    #[must_use]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// The MAC the switch derives for the proxy's address.
    #[must_use]
    pub fn mac(&self) -> EthernetAddress {
        self.mac
    }

    /// The handle the proxy's per-flow pumps wake the poll task through.
    #[must_use]
    pub fn flow_pumps(&self) -> FlowPumps {
        FlowPumps {
            notify: Arc::clone(&self.flow_notify),
        }
    }

    /// Feed the stack one frame that arrived from the switch lane. The next
    /// [`BepHost::poll`] processes it.
    pub fn receive(&mut self, frame: Vec<u8>) {
        // A failed send would mean the device's receive side is gone — it
        // lives in `self` — so the send cannot fail while the host does.
        drop(self.inbound.send(frame));
    }

    /// Step the stack at `now`: process every buffered inbound frame, then
    /// emit whatever the interface has to send. Both drain to quiescence, so
    /// one call is one full turn of the stack.
    pub fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    /// How long the stack wants between this turn and its next, from the
    /// timers its sockets and neighbor state carry.
    pub fn poll_delay(&mut self, now: Instant) -> Option<smoltcp::time::Duration> {
        self.iface.poll_delay(now, &self.sockets)
    }

    /// Take every frame the stack has emitted since the last drain — its
    /// replies and its error answers — one raw Ethernet frame per message.
    pub fn drain_transmitted(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Ok(frame) = self.outbound.try_recv() {
            frames.push(frame);
        }
        frames
    }

    /// Announce the leg at attach: one gratuitous ARP, broadcast, carrying
    /// the proxy's address and its derived MAC as both sender and target.
    /// The switch learns the MAC-to-connection binding the steering of
    /// frames for that MAC rests on from it, and the boxes on the plan see
    /// the address as taken.
    pub fn announce_attach(&mut self) {
        let frame = gratuitous_arp_frame(self.ip, self.mac);
        self.device.emit_raw(frame);
    }
}

/// Builds the attach announcement: one broadcast Ethernet frame carrying an
/// ARP request whose sender and target are both the leg.
fn gratuitous_arp_frame(ip: Ipv4Addr, mac: EthernetAddress) -> Vec<u8> {
    let repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: mac,
        source_protocol_addr: ip,
        target_hardware_addr: mac,
        target_protocol_addr: ip,
    };
    let mut buf = vec![0u8; EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len())];
    let mut frame = EthernetFrame::new_unchecked(&mut buf);
    frame.set_dst_addr(EthernetAddress::BROADCAST);
    frame.set_src_addr(mac);
    frame.set_ethertype(EthernetProtocol::Arp);
    repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    buf
}

/// The connect upgrade the peer speaks on the switch socket: the same head
/// the egress gate relays for the guest, spoken from the host side. gvproxy
/// hijacks the connection on it and writes no response, leaving a
/// length-framed Ethernet stream in both directions.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// How long the peer waits between its upgrade head and its first frame.
///
/// gvproxy hijacks the connection on the upgrade and discards whatever of the
/// request it had already buffered past the head — a frame written in the
/// same instant as the head can land in that buffer and vanish without
/// arriving anywhere. The pace keeps the attach announcement out of that
/// window.
const ATTACH_PACE: Duration = Duration::from_millis(100);

/// Largest frame the peer reads off the switch lane: MTU + 14-byte header +
/// 4-byte 802.1Q VLAN tag — the same bound the egress gate reads the guest's
/// lane to, so both of the switch's host-side clients agree on what a frame
/// may weigh.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + 14 + 4
}

/// Run the host leg as one dedicated task: dial the switch socket, upgrade
/// it, announce the leg, and then drive the stack — one turn per wake, woken
/// by a frame on the lane, by the flow pumps or by the stack's own timer —
/// until the switch closes the lane.
///
/// The task's end is its caller's business: the switch runtime starts it once
/// the switch socket is up and takes it down with the switch.
///
/// # Errors
///
/// Returns the I/O error when the switch socket cannot be reached, the lane
/// carries a frame longer than [`max_frame`], or a read or write on the lane
/// fails for any other reason than the switch closing it.
pub async fn run_stack_peer(switch_sock: PathBuf, subnet: SwitchSubnet) -> io::Result<()> {
    match run_lane(&switch_sock, subnet).await {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(
                %error,
                switch_socket = %switch_sock.display(),
                "the box-egress-proxy stack peer's lane ended on an error"
            );
            Err(error)
        }
    }
}

/// The peer's lane: dial, upgrade, announce, and the poll loop.
async fn run_lane(switch_sock: &PathBuf, subnet: SwitchSubnet) -> io::Result<()> {
    // Fail closed before anything else: with no switch to speak to there is
    // no leg either way, and the error says which socket was not there.
    let mut switch = match UnixStream::connect(switch_sock).await {
        Ok(switch) => switch,
        Err(error) => {
            tracing::warn!(
                %error,
                switch_socket = %switch_sock.display(),
                "the box-egress-proxy stack peer could not reach the switch"
            );
            return Err(error);
        }
    };
    if let Err(error) = switch.write_all(CONNECT_REQUEST).await {
        tracing::warn!(
            %error,
            switch_socket = %switch_sock.display(),
            "the box-egress-proxy stack peer could not send its connect upgrade"
        );
        return Err(error);
    }
    // The hijack's buffer: the pace after the upgrade keeps the attach
    // announcement out of the window the switch discards.
    tokio::time::sleep(ATTACH_PACE).await;
    let (mut switch_rx, mut switch_tx) = switch.into_split();

    let (device, ends) = BepDevice::pair();
    let mut host = BepHost::new(device, ends, subnet);
    let ip = host.ip();
    let mac = host.mac();
    // The one line the diagnostics owe at start: the address the leg answers
    // for and the MAC the switch steers its frames by.
    tracing::info!(
        address = %ip,
        mac = %mac,
        "box-egress-proxy stack peer attached to the switch"
    );
    // The attach announcement is the leg's first frame: before it, the switch
    // knows no binding for the proxy's MAC and steers nothing here.
    host.announce_attach();

    let flow_pumps = host.flow_pumps();
    let limiter = AnswerLimiter::default();
    let mut len_buf = [0u8; 2];
    let mut frame_buf = vec![0u8; max_frame()];
    write_frames(&mut switch_tx, host.drain_transmitted()).await?;

    loop {
        let now = Instant::from(std::time::Instant::now());
        let delay = host.poll_delay(now);
        tokio::select! {
            readable = switch_rx.readable() => {
                readable?;
                match read_frame(&mut switch_rx, &mut len_buf, &mut frame_buf).await? {
                    // A clean close of the lane: the switch is gone, and with
                    // it everything the leg was for.
                    None => {
                        tracing::debug!("the switch closed the box-egress-proxy stack peer's lane");
                        return Ok(());
                    }
                    Some(frame) => {
                        // A zero-length claim carries no frame; skip it.
                        if !frame.is_empty() {
                            host.receive(frame);
                        }
                    }
                }
            }
            _ = flow_pumps.wait() => {
                // A flow pump handed the stack work; the turn below lets it
                // out onto the lane.
            }
            _ = sleep_until_due(delay) => {
                // The stack's timer came due: the turn below runs it.
            }
        }
        // One turn of the stack per wake: everything buffered in, everything
        // owed out — replies and error answers to the boxes that addressed
        // the leg, announced through the rate-limited answer lines.
        let now = Instant::from(std::time::Instant::now());
        host.poll(now);
        let emitted = host.drain_transmitted();
        for frame in &emitted {
            let Some(answered) = classify_answer(frame, ip) else {
                continue;
            };
            if limiter.should_log(answered.source, answered.kind, std::time::Instant::now()) {
                match answered.kind {
                    AnswerKind::TcpReset => tracing::debug!(
                        source = %answered.source,
                        port = answered.port,
                        "answered a TCP segment no socket holds with a reset",
                    ),
                    AnswerKind::UdpPortUnreachable => tracing::debug!(
                        source = %answered.source,
                        port = answered.port,
                        "answered a UDP datagram at the proxy address with an ICMP port-unreachable",
                    ),
                }
            }
        }
        write_frames(&mut switch_tx, emitted).await?;
    }
}

/// Sleeps for `delay` when one is due and never wakes when none is.
async fn sleep_until_due(delay: Option<smoltcp::time::Duration>) {
    match delay {
        Some(delay) => tokio::time::sleep(std::time::Duration::from(delay)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Reads one length-framed frame off the switch lane — the same 2-byte
/// little-endian framing the switch socket speaks on both sides — into
/// `frame_buf`. `Ok(None)` on a clean close of the lane; a zero-length claim
/// comes back as an empty frame for the caller to skip.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame_buf[..n]` is bounded by the `n > frame_buf.len()` rejection above"
)]
async fn read_frame(
    switch_rx: &mut OwnedReadHalf,
    len_buf: &mut [u8; 2],
    frame_buf: &mut [u8],
) -> io::Result<Option<Vec<u8>>> {
    match switch_rx.read_exact(len_buf).await {
        // The count is the buffer's length by construction; only the error
        // half carries information.
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u16::from_le_bytes(*len_buf) as usize;
    if n == 0 {
        return Ok(Some(Vec::new()));
    }
    // Trust nothing the switch claims about length: a frame past the
    // MTU-derived maximum would overrun the buffer and points at a malformed
    // or hostile peer, so refuse it rather than size an allocation to it. The
    // lane comes down — the leg fails closed, never forwards.
    if n > frame_buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("switch frame length {n} exceeds max {}", frame_buf.len()),
        ));
    }
    switch_rx.read_exact(&mut frame_buf[..n]).await?;
    Ok(Some(frame_buf[..n].to_vec()))
}

/// Writes the stack's frames onto the switch lane, one length prefix and one
/// frame per write, each combined so the pair cannot be split by a close
/// between two writes.
async fn write_frames(switch_tx: &mut OwnedWriteHalf, frames: Vec<Vec<u8>>) -> io::Result<()> {
    for frame in frames {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(&frame);
        switch_tx.write_all(&framed).await?;
    }
    Ok(())
}

/// What a frame the stack emitted says it was answering: the classifier the
/// peer reads each egress frame through, so the answer lines name the box
/// each answer went to and the proxy port it addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AnswerKind {
    /// A TCP reset for a segment no socket holds.
    TcpReset,
    /// An ICMP port-unreachable for a UDP datagram at the proxy address.
    UdpPortUnreachable,
}

#[derive(Debug)]
struct Answered {
    kind: AnswerKind,
    /// The box the answer went to — the box that addressed the leg.
    source: Ipv4Addr,
    /// The proxy port the box addressed.
    port: u16,
}

/// Classifies one emitted frame as one of the answers the leg owes, naming
/// the box it went to and the proxy port it addressed. Anything else — the
/// ARP replies, the attach announcement, a frame the interface emitted for
/// another reason — is not an answer and is left unclassified.
fn classify_answer(frame: &[u8], proxy_ip: Ipv4Addr) -> Option<Answered> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ip_packet = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ip_packet.src_addr() != proxy_ip {
        return None;
    }
    let ip_repr = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default()).ok()?;
    match ip_repr.next_header {
        IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).ok()?;
            let repr = TcpRepr::parse(
                &tcp_packet,
                &IpAddress::Ipv4(ip_repr.src_addr),
                &IpAddress::Ipv4(ip_repr.dst_addr),
                &ChecksumCapabilities::default(),
            )
            .ok()?;
            if repr.control != TcpControl::Rst {
                return None;
            }
            Some(Answered {
                kind: AnswerKind::TcpReset,
                source: ip_repr.dst_addr,
                // The reset speaks from the proxy port the segment addressed.
                port: repr.src_port,
            })
        }
        IpProtocol::Icmp => {
            let icmp_packet = Icmpv4Packet::new_checked(ip_packet.payload()).ok()?;
            if icmp_packet.msg_type() != Icmpv4Message::DstUnreachable
                || icmp_packet.msg_code() != u8::from(Icmpv4DstUnreachable::PortUnreachable)
            {
                return None;
            }
            // The unreachable embeds the datagram it is answering, and the
            // datagram's own header names the proxy port the box addressed.
            let embedded = Ipv4Packet::new_checked(icmp_packet.data()).ok()?;
            if embedded.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp_packet = UdpPacket::new_checked(embedded.payload()).ok()?;
            Some(Answered {
                kind: AnswerKind::UdpPortUnreachable,
                source: ip_repr.dst_addr,
                port: udp_packet.dst_port(),
            })
        }
        _ => None,
    }
}

/// One answer line per source per kind per interval — the cadence the
/// daemon's policy warnings and the egress gate's drop lines use, so a
/// host's log speaks with one voice. A flood of segments to closed proxy
/// ports from one box produces a steady, readable account of what the leg
/// answered, not a log flood.
const ANSWER_LOG_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// How many distinct `(source, kind)` pairs the limiter keeps a window for —
/// the leg's memory bound on the lines it writes, the same bound the
/// egress gate's drop limiter carries.
const ANSWER_LOG_TABLE_CAP: usize = 64;

/// The rate limiter behind the answer lines.
#[derive(Default)]
struct AnswerLimiter {
    last: Mutex<HashMap<(Ipv4Addr, AnswerKind), std::time::Instant>>,
}

impl AnswerLimiter {
    /// Whether an answer to `source` of `kind` earns its line at `now`: one
    /// per source per kind per interval, the window refreshed by the line.
    fn should_log(&self, source: Ipv4Addr, kind: AnswerKind, now: std::time::Instant) -> bool {
        let mut last = self.last.lock().expect("the answer limiter's map");
        // A long run of distinct sources must not grow the table without
        // end: past the cap, stale windows go before a new one is taken.
        if last.len() >= ANSWER_LOG_TABLE_CAP && !last.contains_key(&(source, kind)) {
            last.retain(|_, at| now.duration_since(*at) < ANSWER_LOG_MIN_INTERVAL);
        }
        match last.get(&(source, kind)) {
            Some(at) if now.duration_since(*at) < ANSWER_LOG_MIN_INTERVAL => false,
            _ => {
                last.insert((source, kind), now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol, TcpSeqNumber};

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

    /// One TCP segment frame, as a box on the plan would send it: addressed
    /// to the target's switch-derived MAC, from the box's own.
    fn tcp_segment(
        sender_mac: EthernetAddress,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        repr: &TcpRepr<'_>,
    ) -> Vec<u8> {
        let target_mac = EthernetAddress(MacAddr::for_switch_ip(target_ip).0);
        let ip_repr = Ipv4Repr {
            src_addr: sender_ip,
            dst_addr: target_ip,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; EthernetFrame::<&[u8]>::buffer_len(
            ip_repr.buffer_len() + repr.buffer_len(),
        )];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(target_mac);
        frame.set_src_addr(sender_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
        let mut tcp_packet = TcpPacket::new_unchecked(ip_packet.payload_mut());
        repr.emit(
            &mut tcp_packet,
            &IpAddress::Ipv4(sender_ip),
            &IpAddress::Ipv4(target_ip),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    /// A bare SYN from a box to `target_port` on the leg.
    fn tcp_syn(sender_ip: Ipv4Addr, target_ip: Ipv4Addr, target_port: u16, seq: i32) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: 40444,
            dst_port: target_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(seq),
            ack_number: None,
            window_len: 1024,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        tcp_segment(
            EthernetAddress(MacAddr::for_switch_ip(sender_ip).0),
            sender_ip,
            target_ip,
            &repr,
        )
    }

    /// One UDP datagram frame, as a box on the plan would send it.
    fn udp_datagram(
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        target_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let repr = smoltcp::wire::UdpRepr {
            src_port: 53333,
            dst_port: target_port,
        };
        let sender_mac = EthernetAddress(MacAddr::for_switch_ip(sender_ip).0);
        let target_mac = EthernetAddress(MacAddr::for_switch_ip(target_ip).0);
        let ip_repr = Ipv4Repr {
            src_addr: sender_ip,
            dst_addr: target_ip,
            next_header: IpProtocol::Udp,
            payload_len: repr.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; EthernetFrame::<&[u8]>::buffer_len(
            ip_repr.buffer_len() + repr.header_len() + payload.len(),
        )];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(target_mac);
        frame.set_src_addr(sender_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);
        let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
        let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
        repr.emit(
            &mut udp_packet,
            &IpAddress::Ipv4(sender_ip),
            &IpAddress::Ipv4(target_ip),
            payload.len(),
            |out| out[..payload.len()].copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    /// Parses one emitted frame into its Ethernet, IPv4 and L4 payload
    /// parts, checking the MAC and address ends the leg's answers carry.
    struct Emitted<'a> {
        eth: EthernetFrame<&'a [u8]>,
        ip_repr: Ipv4Repr,
        l4_payload: &'a [u8],
    }

    impl<'a> Emitted<'a> {
        fn parse(frame: &'a [u8], from: Ipv4Addr, to: Ipv4Addr) -> Self {
            let eth = EthernetFrame::new_checked(frame).expect("the frame is Ethernet");
            assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
            let ip_packet = Ipv4Packet::new_checked(eth.payload()).expect("the frame carries IPv4");
            let ip_repr = Ipv4Repr::parse(&ip_packet, &ChecksumCapabilities::default())
                .expect("the header parses");
            assert_eq!(ip_repr.src_addr, from, "the answer speaks from the leg");
            assert_eq!(ip_repr.dst_addr, to, "the answer goes to the box");
            let l4_payload = ip_packet.payload();
            Self {
                eth,
                ip_repr,
                l4_payload,
            }
        }
    }

    /// The skeleton's first proof, now the leg's own: a box on the switch's
    /// plan asks who has the proxy's address; the host stack answers for it,
    /// from the switch-derived MAC, pointed back at the asker — and at
    /// nothing else.
    #[test]
    fn proxy_address_answers_arp_from_the_host_stack() {
        let subnet = SwitchSubnet::default();
        let (device, ends) = BepDevice::pair();
        let mut host = BepHost::new(device, ends, subnet);

        // The address the leg owns is the proxy's, above the lease pool —
        // not the gateway's, and not anything the switch answers for itself.
        let bep = host.ip();
        assert_eq!(bep, subnet.box_egress_proxy_address());
        let box_ip = Ipv4Addr::from(subnet.first_ptask());
        let box_mac = EthernetAddress(MacAddr::for_switch_ip(box_ip).0);

        host.receive(arp_request(box_mac, box_ip, bep));
        host.poll(Instant::from_millis(0));

        let frames = host.drain_transmitted();
        assert_eq!(frames.len(), 1, "one reply, nothing else: {frames:?}");
        let frame = EthernetFrame::new_checked(&frames[0]).expect("the reply is an Ethernet frame");
        assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
        assert_eq!(frame.src_addr(), host.mac());
        assert_eq!(frame.dst_addr(), box_mac, "the reply goes to the asker");
        let arp = ArpPacket::new_checked(frame.payload()).expect("the reply carries ARP");
        assert_eq!(
            ArpRepr::parse(&arp).expect("the reply parses as ARP"),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: host.mac(),
                source_protocol_addr: bep,
                target_hardware_addr: box_mac,
                target_protocol_addr: box_ip,
            }
        );
        // One request, one reply: the stack emitted nothing else.
        assert!(
            host.drain_transmitted().is_empty(),
            "the stack emitted nothing further"
        );
    }

    /// A TCP segment addressed to the proxy's address on a port nothing
    /// listens on is reset at once, back to the box that sent it, following
    /// the RST convention the stack's own replies use: the reset speaks from
    /// the port the segment addressed, sequence zero where the segment
    /// carried no acknowledgement, and acknowledges the SYN's sequence
    /// space.
    #[test]
    fn tcp_to_unlistened_proxy_port_is_reset() {
        let subnet = SwitchSubnet::default();
        let (device, ends) = BepDevice::pair();
        let mut host = BepHost::new(device, ends, subnet);
        let bep = host.ip();
        let bep_mac = host.mac();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());
        let box_mac = EthernetAddress(MacAddr::for_switch_ip(box_ip).0);

        // The box resolved the proxy's MAC first — the ARP round trip every
        // box makes before its first frame, and the one that teaches the
        // stack which MAC the reset goes to.
        host.receive(arp_request(box_mac, box_ip, bep));
        host.poll(Instant::from_millis(0));
        host.drain_transmitted();

        host.receive(tcp_syn(box_ip, bep, 8080, 7));
        host.poll(Instant::from_millis(1));

        let frames = host.drain_transmitted();
        assert_eq!(frames.len(), 1, "one answer, nothing else: {frames:?}");
        let emitted = Emitted::parse(&frames[0], bep, box_ip);
        assert_eq!(emitted.eth.src_addr(), bep_mac);
        assert_eq!(emitted.eth.dst_addr(), box_mac, "the reset goes to the box");
        let tcp_packet = TcpPacket::new_checked(emitted.l4_payload).expect("the frame carries TCP");
        let repr = TcpRepr::parse(
            &tcp_packet,
            &IpAddress::Ipv4(bep),
            &IpAddress::Ipv4(box_ip),
            &ChecksumCapabilities::default(),
        )
        .expect("the reset parses as TCP");
        assert_eq!(repr.control, TcpControl::Rst);
        assert_eq!(repr.src_port, 8080, "the reset speaks from the port hit");
        assert_eq!(repr.dst_port, 40444, "the reset goes to the segment's source port");
        // The bare SYN carried no acknowledgement: the reset's sequence is
        // zero and it acknowledges the SYN's sequence space (7, plus the
        // SYN's one).
        assert_eq!(repr.seq_number, TcpSeqNumber(0));
        assert_eq!(repr.ack_number, Some(TcpSeqNumber(8)));
        assert!(repr.payload.is_empty(), "a reset carries no payload");
    }

    /// A UDP datagram addressed to the proxy's address is answered with an
    /// ICMP port-unreachable, back to the box that sent it, embedding the
    /// original datagram's header — which is what names the port the box
    /// addressed — and the head of its payload.
    #[test]
    fn udp_to_proxy_address_gets_port_unreachable() {
        let subnet = SwitchSubnet::default();
        let (device, ends) = BepDevice::pair();
        let mut host = BepHost::new(device, ends, subnet);
        let bep = host.ip();
        let bep_mac = host.mac();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());
        let box_mac = EthernetAddress(MacAddr::for_switch_ip(box_ip).0);

        host.receive(arp_request(box_mac, box_ip, bep));
        host.poll(Instant::from_millis(0));
        host.drain_transmitted();

        host.receive(udp_datagram(box_ip, bep, 5353, b"whoami"));
        host.poll(Instant::from_millis(1));

        let frames = host.drain_transmitted();
        assert_eq!(frames.len(), 1, "one answer, nothing else: {frames:?}");
        let emitted = Emitted::parse(&frames[0], bep, box_ip);
        assert_eq!(emitted.eth.src_addr(), bep_mac);
        assert_eq!(emitted.eth.dst_addr(), box_mac, "the answer goes to the box");
        assert_eq!(emitted.ip_repr.next_header, IpProtocol::Icmp);
        let icmp_packet =
            Icmpv4Packet::new_checked(emitted.l4_payload).expect("the frame carries ICMP");
        assert_eq!(icmp_packet.msg_type(), Icmpv4Message::DstUnreachable);
        assert_eq!(
            icmp_packet.msg_code(),
            u8::from(Icmpv4DstUnreachable::PortUnreachable),
        );
        // The embedded datagram: the original header, unchanged, naming the
        // proxy port, followed by the head of the datagram's payload.
        let embedded =
            Ipv4Packet::new_checked(icmp_packet.data()).expect("the answer embeds the datagram");
        assert_eq!(embedded.src_addr(), box_ip);
        assert_eq!(embedded.dst_addr(), bep);
        assert_eq!(embedded.next_header(), IpProtocol::Udp);
        let udp_packet = UdpPacket::new_checked(embedded.payload())
            .expect("the embedded datagram carries UDP");
        assert_eq!(udp_packet.dst_port(), 5353, "the answer names the port hit");
        assert_eq!(udp_packet.src_port(), 53333);
        assert_eq!(udp_packet.payload(), b"whoami");
    }

    /// The leg originates nothing to any destination but the box that
    /// addressed it. Frames addressed elsewhere — an ARP request for another
    /// address, a TCP segment and a UDP datagram for another IP — earn no
    /// frame at all; the frames the leg does owe go only to the box that
    /// asked; and the attach announcement is the one broadcast it ever
    /// emits, once, at attach.
    #[test]
    fn stack_peer_originates_frames_only_to_the_box_that_addressed_it() {
        let subnet = SwitchSubnet::default();
        let (device, ends) = BepDevice::pair();
        let mut host = BepHost::new(device, ends, subnet);
        let bep = host.ip();

        // The attach announcement: the one broadcast, once, at attach.
        host.announce_attach();
        let announcement = host.drain_transmitted();
        assert_eq!(announcement.len(), 1, "one announcement at attach");
        let frame =
            EthernetFrame::new_checked(&announcement[0]).expect("the announcement is Ethernet");
        assert_eq!(frame.dst_addr(), EthernetAddress::BROADCAST);
        let arp = ArpPacket::new_checked(frame.payload()).expect("the announcement carries ARP");
        let announcement_repr = ArpRepr::parse(&arp).expect("the announcement parses as ARP");
        let expected = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: host.mac(),
            source_protocol_addr: bep,
            target_hardware_addr: host.mac(),
            target_protocol_addr: bep,
        };
        assert_eq!(announcement_repr, expected);

        // Three boxes on the plan, and frames addressed elsewhere.
        let a = Ipv4Addr::from(subnet.first_ptask());
        let b = Ipv4Addr::from(subnet.first_ptask() + 1);
        let c = Ipv4Addr::from(subnet.first_ptask() + 2);
        let other_ip = Ipv4Addr::from(subnet.first_ptask() + 3);
        let mac_of = |ip: Ipv4Addr| EthernetAddress(MacAddr::for_switch_ip(ip).0);

        // An ARP request for an address the leg does not hold: no answer.
        host.receive(arp_request(mac_of(a), a, other_ip));
        // A TCP segment for an IP the leg does not hold: no answer — the
        // interface answers only for the address it owns.
        host.receive(tcp_syn(a, other_ip, 8080, 7));
        // A UDP datagram for an IP the leg does not hold: no answer.
        host.receive(udp_datagram(a, other_ip, 5353, b"whoami"));
        // The frames the leg does owe: an ARP request for its address from
        // box B, a SYN to its port from box B, a datagram to its address
        // from box C. Boxes B and C each make the ARP round trip their first
        // frame to the leg rests on — the request that teaches the stack
        // which MAC the answer goes back to.
        host.receive(arp_request(mac_of(b), b, bep));
        host.receive(tcp_syn(b, bep, 8080, 7));
        host.receive(arp_request(mac_of(c), c, bep));
        host.receive(udp_datagram(c, bep, 5353, b"whoami"));
        host.poll(Instant::from_millis(0));

        let frames = host.drain_transmitted();
        assert_eq!(frames.len(), 4, "the four answers, nothing else: {frames:?}");

        // The ARP reply goes to box B, and to box B alone.
        let reply_frame =
            EthernetFrame::new_checked(&frames[0]).expect("the first answer is Ethernet");
        assert_eq!(reply_frame.ethertype(), EthernetProtocol::Arp);
        assert_eq!(reply_frame.dst_addr(), mac_of(b));
        let reply_arp = ArpPacket::new_checked(reply_frame.payload()).expect("carries ARP");
        assert_eq!(
            ArpRepr::parse(&reply_arp).expect("parses as ARP"),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: host.mac(),
                source_protocol_addr: bep,
                target_hardware_addr: mac_of(b),
                target_protocol_addr: b,
            }
        );

        // The reset goes to box B; box C's ARP round trip earns its own
        // reply, and the port-unreachable to box C follows it — each answer
        // carrying its own box's address as the destination, never another
        // box's and never a broadcast.
        let reset = Emitted::parse(&frames[1], bep, b);
        assert_eq!(reset.eth.dst_addr(), mac_of(b));
        let reply_to_c = EthernetFrame::new_checked(&frames[2]).expect("carries ARP");
        assert_eq!(reply_to_c.dst_addr(), mac_of(c));
        let unreachable = Emitted::parse(&frames[3], bep, c);
        assert_eq!(unreachable.eth.dst_addr(), mac_of(c));

        // And nothing further: the leg does not announce again.
        host.announce_attach();
        assert_eq!(host.drain_transmitted().len(), 1, "an explicit announcement only");
    }

    /// The answer classifier reads the leg's two answers and nothing else:
    /// a reset names the box and the port hit, a port-unreachable embeds
    /// the datagram whose header names the port, and the leg's other frames
    /// classify as none.
    #[test]
    fn classify_answer_names_the_box_and_the_port_hit() {
        let subnet = SwitchSubnet::default();
        let (device, ends) = BepDevice::pair();
        let mut host = BepHost::new(device, ends, subnet);
        let bep = host.ip();
        let box_ip = Ipv4Addr::from(subnet.first_ptask());
        let box_mac = EthernetAddress(MacAddr::for_switch_ip(box_ip).0);

        // The attach announcement is not an answer.
        host.announce_attach();
        let announcement = host.drain_transmitted();
        assert!(
            classify_answer(&announcement[0], bep).is_none(),
            "the attach announcement is not an answer"
        );
        // An ARP reply is not an answer.
        host.receive(arp_request(box_mac, box_ip, bep));
        host.poll(Instant::from_millis(0));
        let reply = host.drain_transmitted();
        assert!(
            classify_answer(&reply[0], bep).is_none(),
            "an ARP reply is not an answer"
        );

        // A reset classifies with the box and the port hit.
        host.receive(tcp_syn(box_ip, bep, 8080, 7));
        host.poll(Instant::from_millis(1));
        let reset = host.drain_transmitted();
        let answered = classify_answer(&reset[0], bep).expect("the reset is an answer");
        assert_eq!(answered.source, box_ip);
        assert_eq!(answered.port, 8080);
        assert!(matches!(answered.kind, AnswerKind::TcpReset));

        // A port-unreachable classifies the same way.
        host.receive(udp_datagram(box_ip, bep, 5353, b"whoami"));
        host.poll(Instant::from_millis(2));
        let unreachable = host.drain_transmitted();
        let answered = classify_answer(&unreachable[0], bep).expect("the answer is classified");
        assert_eq!(answered.source, box_ip);
        assert_eq!(answered.port, 5353);
        assert!(matches!(answered.kind, AnswerKind::UdpPortUnreachable));
    }

    /// The answer limiter holds one line per source per kind per interval:
    /// the first earns its line, the repeats inside the window do not, and a
    /// different source or kind is not held back by another's window.
    #[test]
    fn answer_limiter_holds_one_line_per_source_per_interval() {
        let limiter = AnswerLimiter::default();
        let a = Ipv4Addr::from(SwitchSubnet::default().first_ptask());
        let b = Ipv4Addr::new(10, 0, 0, 9);
        let start = std::time::Instant::now();

        assert!(limiter.should_log(a, AnswerKind::TcpReset, start));
        assert!(
            !limiter.should_log(a, AnswerKind::TcpReset, start + Duration::from_secs(1)),
            "a repeat inside the window is held"
        );
        assert!(
            limiter.should_log(a, AnswerKind::UdpPortUnreachable, start + Duration::from_secs(2)),
            "a different kind from the same source earns its own line"
        );
        assert!(
            limiter.should_log(b, AnswerKind::TcpReset, start + Duration::from_secs(3)),
            "a different source earns its own line"
        );
        assert!(
            limiter.should_log(a, AnswerKind::TcpReset, start + ANSWER_LOG_MIN_INTERVAL),
            "the window opens again at the interval"
        );
    }

    /// The attach announcement is the exact frame the switch steers by: one
    /// broadcast Ethernet frame carrying the proxy's address and derived MAC
    /// as both ARP sender and target.
    #[test]
    fn attach_announcement_carrying_the_proxy_address_and_mac() {
        let subnet = SwitchSubnet::default();
        let ip = subnet.box_egress_proxy_address();
        let mac = EthernetAddress(MacAddr::for_switch_ip(ip).0);
        let frame = gratuitous_arp_frame(ip, mac);
        let eth = EthernetFrame::new_checked(&frame).expect("the announcement is Ethernet");
        assert_eq!(eth.dst_addr(), EthernetAddress::BROADCAST);
        assert_eq!(eth.src_addr(), mac);
        let arp = ArpPacket::new_checked(eth.payload()).expect("carries ARP");
        assert_eq!(
            ArpRepr::parse(&arp).expect("parses as ARP"),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: mac,
                source_protocol_addr: ip,
                target_hardware_addr: mac,
                target_protocol_addr: ip,
            }
        );
    }
}
