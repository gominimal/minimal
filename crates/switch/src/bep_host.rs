//! The Box Egress Proxy's host leg (`bep_host`): the userspace TCP/IP stack
//! the proxy's listener stands on, over the switch (NET-132).
//!
//! A box with a credentialed lane reaches the proxy by connecting to the
//! leg's address on the switch's plan (NET-134); the connection arrives as
//! Ethernet frames over the switch's L2 lane, whose bytes cross the shuttle
//! length-framed (the 2-byte little-endian prefix the switch socket speaks —
//! the framing `minvmd`'s egress gate relays). The host kernel knows nothing
//! of the switch subnet, so the leg terminates those frames itself: one smoltcp
//! [`Interface`] over a channel-backed [`Device`], answering ARP for the leg's
//! address, resetting TCP to unlistened proxy ports, and sending ICMP
//! port-unreachable for UDP at the address.
//!
//! [`BepDevice`] is that [`Device`]: a pair of unbounded tokio channels, one
//! raw Ethernet frame per message on each. [`BepDevice::pair`] hands the
//! caller the [`BepDeviceEnds`] to feed frames in through and take frames out
//! of; the length framing between those edges and the byte stream is the
//! stream reader's and writer's job, as it is in the egress gate's relay.
//! [`BepHost`] builds the interface over it: the leg's address on a
//! [`SwitchSubnet`], its MAC derived the switch's way
//! ([`MacAddr::for_switch_ip`]), stepped with [`BepHost::poll`].
//!
//! [`BepPeer`] dials the switch `-listen` socket once, upgrades the connection
//! with the HyperKit `/connect` request, and runs the stack in a dedicated
//! local task that is woken by inbound frames, by the outbound pump, and by a
//! periodic `poll_delay`.
//!
//! The module is behind the `stack-peer` cargo feature, off by default: it
//! lives in this crate so that both daemons can link it, but the in-VM
//! `minimald` build, which links the crate for the configuration renderer,
//! pulls in neither smoltcp nor tokio for it. `minvmd` enables the feature
//! and wires the peer beside the switch; wiring it natively into `minimald`
//! is a later task (NET-133's native case).
//!
//! The peer is silent until spoken to. It originates no frame except in
//! answer to one that addressed it — the ARP reply, the TCP reset, the ICMP
//! port-unreachable — and each of those goes to the box that asked and to no
//! other destination: no gratuitous ARP at attach, no ARP probe, nothing on
//! an idle lane. The smoltcp feature set this crate builds with excludes
//! `proto-ipv6`, so the stack cannot emit neighbour solicitation, router
//! solicitation or MLD either. `idle_peer_emits_no_frames` pins the silence.
//!
//! The peer terminates nothing above the network layer here: no smoltcp TCP,
//! UDP or ICMP socket is bound on its [`SocketSet`] (`peer_binds_no_socket`
//! pins that), so every segment to the proxy address is reset and every
//! datagram is answered port-unreachable. The task that puts the proxy's
//! listener on this address (T69) is the only one that may bind a socket on
//! the peer, and it carries the per-source caps and the gate rule before it
//! does.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::{DEFAULT_MTU, MacAddr, SwitchSubnet};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    HardwareAddress, IPV4_HEADER_LEN, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet,
    Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinSet;

/// The HTTP upgrade request that turns a gvproxy control socket connection
/// into a raw Ethernet frame stream (the same head the guest shuttle uses).
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// Maximum interval between stack polls even when no traffic arrives, so smoltcp
/// TCP timers still advance.
const POLL_DELAY: Duration = Duration::from_millis(100);

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

    fn send_out(&self, frame: Vec<u8>) {
        // A failed send means the leg's peer end is gone — the lane is closed
        // and the frame has nowhere to go. Drop it rather than fail the poll;
        // the lane's teardown is the leg's wiring's to log.
        let _ = self.tx.send(frame);
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
        // Inbound frames take one path: [`BepHost::poll`] drains the channel
        // and answers each frame itself, so the interface has no socket to
        // deliver to and nothing to receive. The task that binds the proxy's
        // listener (T69) is the one that hands frames to the interface.
        None
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
        let _ = self.tx.send(frame);
        result
    }
}

/// The host leg's stack: one smoltcp [`Interface`] over a channel-backed
/// [`BepDevice`], holding the leg's address on the switch's plan.
///
/// Built by [`BepHost::new`], stepped by [`BepHost::poll`]. The sockets the
/// proxy terminates come later, when the proxy's own work adds them; the set
/// exists here so the interface has something to poll against from the first
/// frame on.
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
    /// channel and answer it, then emit whatever the interface has to send.
    /// Both drain to quiescence, so one call is one full turn of the stack.
    /// This is the only consumer of the inbound channel: the peer's poll task
    /// calls it and never drains the channel itself.
    pub fn poll(&mut self, now: Instant) {
        while let Ok(frame) = self.device.rx.try_recv() {
            self.handle_frame(&frame);
        }
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    /// Whether the lane feeding the device has closed: every inbound sender
    /// is gone, so no frame will ever arrive and the stack has nothing left
    /// to serve.
    fn lane_closed(&self) -> bool {
        self.device.rx.is_closed()
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let eth = match EthernetFrame::new_checked(frame) {
            Ok(eth) => eth,
            Err(_) => return,
        };
        let dst = eth.dst_addr();
        if dst != self.mac && dst != EthernetAddress::BROADCAST {
            return;
        }

        match eth.ethertype() {
            EthernetProtocol::Arp => {
                if let Ok(arp) = ArpPacket::new_checked(eth.payload())
                    && let Ok(repr) = ArpRepr::parse(&arp)
                {
                    self.handle_arp(repr);
                }
            }
            EthernetProtocol::Ipv4 => {
                if let Ok(ip) = Ipv4Packet::new_checked(eth.payload())
                    && let Ok(repr) = Ipv4Repr::parse(&ip, &ChecksumCapabilities::ignored())
                {
                    if repr.dst_addr != self.ip {
                        // any_ip is off: traffic not for the proxy address
                        // is dropped without a reply.
                        return;
                    }
                    let src_mac = eth.src_addr();
                    match repr.next_header {
                        IpProtocol::Tcp => self.handle_tcp(src_mac, repr, ip.payload()),
                        IpProtocol::Udp => self.handle_udp(src_mac, repr, ip.payload()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_arp(&self, repr: ArpRepr) {
        let (operation, target_protocol_addr, source_hardware_addr, source_protocol_addr) =
            match repr {
                ArpRepr::EthernetIpv4 {
                    operation,
                    target_protocol_addr,
                    source_hardware_addr,
                    source_protocol_addr,
                    ..
                } => (
                    operation,
                    target_protocol_addr,
                    source_hardware_addr,
                    source_protocol_addr,
                ),
                _ => return,
            };
        if operation != ArpOperation::Request || target_protocol_addr != self.ip {
            return;
        }
        let reply = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Reply,
            source_hardware_addr: self.mac,
            source_protocol_addr: self.ip,
            target_hardware_addr: source_hardware_addr,
            target_protocol_addr: source_protocol_addr,
        };
        self.send_arp(reply, source_hardware_addr);
    }

    fn handle_tcp(&self, src_mac: EthernetAddress, ip_repr: Ipv4Repr, tcp_payload: &[u8]) {
        let tcp = match TcpPacket::new_checked(tcp_payload) {
            Ok(tcp) => tcp,
            Err(_) => return,
        };
        let seq = tcp.seq_number();
        let ack = tcp.ack_number();
        let (rst_seq, rst_ack, rst_ack_set) = if tcp.ack() {
            (ack, TcpSeqNumber(0), false)
        } else {
            let len = tcp.payload().len() + if tcp.syn() || tcp.fin() { 1 } else { 0 };
            (
                TcpSeqNumber(0),
                TcpSeqNumber(seq.0.wrapping_add(len as i32)),
                true,
            )
        };
        let rst = TcpRepr {
            src_port: tcp.dst_port(),
            dst_port: tcp.src_port(),
            control: TcpControl::Rst,
            seq_number: rst_seq,
            ack_number: if rst_ack_set { Some(rst_ack) } else { None },
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        self.send_ip_packet(
            src_mac,
            ip_repr.src_addr,
            IpProtocol::Tcp,
            rst.header_len(),
            |tcp_buf| {
                let mut tcp_packet = TcpPacket::new_unchecked(tcp_buf);
                rst.emit(
                    &mut tcp_packet,
                    &IpAddress::Ipv4(self.ip),
                    &IpAddress::Ipv4(ip_repr.src_addr),
                    &self.device.capabilities().checksum,
                );
            },
        );
        tracing::debug!(
            src = %Ipv4Addr::from(u32::from_be_bytes(ip_repr.src_addr.octets())),
            dst_port = tcp.dst_port(),
            "sent TCP reset for unlistened proxy port"
        );
    }

    fn handle_udp(&self, src_mac: EthernetAddress, ip_repr: Ipv4Repr, udp_payload: &[u8]) {
        let udp = match UdpPacket::new_checked(udp_payload) {
            Ok(udp) => udp,
            Err(_) => return,
        };
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();
        let original_ip_header_len = 20_usize;
        let original_total_len = (original_ip_header_len + udp.len() as usize) as u16;
        let original_src = ip_repr.src_addr;
        let original_dst = self.ip;

        // ICMP port-unreachable payload: original IPv4 header + first 8 bytes
        // of the original datagram (the UDP header).
        let returned_len = original_ip_header_len + 8;
        self.send_ip_packet(
            src_mac,
            original_src,
            IpProtocol::Icmp,
            8 + returned_len,
            |icmp_buf| {
                // Type 3, code 3, checksum, unused = 4 zero bytes.
                icmp_buf[0] = 3; // Destination Unreachable
                icmp_buf[1] = 3; // Port Unreachable
                icmp_buf[2] = 0;
                icmp_buf[3] = 0;
                icmp_buf[4..8].fill(0);

                // Copy original IP header.
                let mut orig_header = [0u8; 20];
                {
                    let mut orig_ip = Ipv4Packet::new_unchecked(&mut orig_header[..]);
                    orig_ip.set_version(4);
                    orig_ip.set_header_len(20);
                    orig_ip.set_dscp(0);
                    orig_ip.set_ecn(0);
                    orig_ip.set_total_len(original_total_len);
                    orig_ip.set_ident(0);
                    orig_ip.clear_flags();
                    orig_ip.set_more_frags(false);
                    orig_ip.set_dont_frag(true);
                    orig_ip.set_frag_offset(0);
                    orig_ip.set_hop_limit(64);
                    orig_ip.set_next_header(IpProtocol::Udp);
                    orig_ip.set_src_addr(original_src);
                    orig_ip.set_dst_addr(original_dst);
                    orig_ip.fill_checksum();
                }
                icmp_buf[8..28].copy_from_slice(&orig_header);
                // Copy first 8 bytes of original UDP datagram (the UDP header).
                let udp_header_len = core::cmp::min(8, udp_payload.len());
                icmp_buf[28..28 + udp_header_len].copy_from_slice(&udp_payload[..udp_header_len]);

                // Compute ICMP checksum over the ICMP message.
                let checksum = smoltcp::wire::checksum::data(icmp_buf);
                let checksum = !checksum;
                icmp_buf[2..4].copy_from_slice(&checksum.to_be_bytes());
            },
        );
        tracing::debug!(
            src = %Ipv4Addr::from(u32::from_be_bytes(original_src.octets())),
            src_port,
            dst_port,
            "sent ICMP port-unreachable for UDP to proxy address"
        );
    }

    fn send_arp(&self, repr: ArpRepr, dst_mac: EthernetAddress) {
        let len = EthernetFrame::<&[u8]>::buffer_len(repr.buffer_len());
        let mut buf = vec![0u8; len];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_mac);
        frame.set_src_addr(self.mac);
        frame.set_ethertype(EthernetProtocol::Arp);
        let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
        repr.emit(&mut packet);
        self.device.send_out(buf);
    }

    fn send_ip_packet<F>(
        &self,
        dst_mac: EthernetAddress,
        dst_ip: Ipv4Address,
        protocol: IpProtocol,
        payload_len: usize,
        mut build_payload: F,
    ) where
        F: FnMut(&mut [u8]),
    {
        // Largest buffer we'll need for the payloads this peer emits.
        let mut buf = vec![0u8; 14 + IPV4_HEADER_LEN + payload_len];
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_mac);
        frame.set_src_addr(self.mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);

        let ip_repr = Ipv4Repr {
            src_addr: self.ip,
            dst_addr: dst_ip,
            next_header: protocol,
            payload_len,
            hop_limit: 64,
        };
        {
            let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
            ip_repr.emit(&mut ip_packet, &self.device.capabilities().checksum);
        }
        build_payload(&mut frame.payload_mut()[IPV4_HEADER_LEN..]);
        self.device.send_out(buf);
    }
}

/// A running Box Egress Proxy host peer.
///
/// It owns the upstream switch socket connection (the `POST /connect`
/// upgrade), the channel-backed [`BepDevice`] that talks to the smoltcp
/// [`BepHost`], the two flow pumps that move framed Ethernet between the socket
/// and the device channels, and the dedicated local task that polls the stack.
/// Dropping the handle aborts those tasks and closes the socket.
#[derive(Debug)]
#[must_use = "dropping BepPeer stops the host-side proxy stack"]
pub struct BepPeer {
    /// The stack poll task. It runs on a blocking thread, which `abort` cannot
    /// stop, so the loop watches `stop` and returns when the sender drops.
    poll_task: tokio::task::JoinHandle<()>,
    /// Dropped by `Drop`: the poll loop exits when this closes. Without it the
    /// runtime that spawned the peer waits forever for the blocking task at
    /// shutdown, which is how the switch runtime hung at stop.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// Pump tasks moving frames between socket and device channels.
    pumps: JoinSet<()>,
}

impl Drop for BepPeer {
    fn drop(&mut self) {
        self.pumps.abort_all();
        drop(self.stop.take());
        self.poll_task.abort();
    }
}

impl BepPeer {
    /// Start a peer for `subnet.box_egress_proxy_address()` on the switch
    /// socket at `switch_sock`.
    ///
    /// The peer dials the switch, upgrades the connection with the HyperKit
    /// `/connect` request, announces nothing, and then runs three
    /// cooperating tasks:
    ///
    /// - a socket reader that reads length-framed Ethernet frames from the
    ///   switch and feeds them into the stack's inbound channel;
    /// - a socket writer that reads from the stack's outbound channel and
    ///   writes length-framed Ethernet frames onto the switch;
    /// - a dedicated local task that owns the smoltcp [`BepHost`] and polls it
    ///   whenever inbound frames arrive, whenever the outbound pump has
    ///   drained, and at least every [`POLL_DELAY`].
    ///
    /// Must be called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the switch socket cannot be connected to.
    pub async fn spawn(switch_sock: &Path, subnet: SwitchSubnet) -> io::Result<Self> {
        let proxy_ip = subnet.box_egress_proxy_address();
        let proxy_mac = MacAddr::for_switch_ip(proxy_ip);

        let mut stream = UnixStream::connect(switch_sock).await?;
        stream.write_all(CONNECT_REQUEST).await?;
        stream.flush().await?;

        tracing::info!(
            switch_socket = %switch_sock.display(),
            proxy_ip = %proxy_ip,
            proxy_mac = %proxy_mac,
            "box egress proxy peer attached"
        );

        // The socket is split so the reader and writer can run independently;
        // the stack poll task cannot own the `UnixStream` because the smoltcp
        // `Interface` is not `Send`.
        let (mut read_half, write_half) = stream.into_split();

        // Channel-backed device: raw Ethernet frames in both directions. The
        // reader/reader tasks are `Send`; the `BepHost` built around the device
        // lives in the local poll task.
        let (device, ends) = BepDevice::pair();
        let inbound_tx = ends.inbound;
        let mut outbound_rx = ends.outbound;

        // Shared wake source: the reader calls `notify_one` after every frame
        // it enqueues, and the writer calls `notify_one` whenever it drains a
        // frame so the stack can make progress while the outbound channel has
        // capacity. Because the channels are unbounded, the writer waking the
        // poll task is the back-pressure substitute the spec asks for.
        let notify = Arc::new(Notify::new());

        let mut pumps = JoinSet::new();

        // Pump 1: switch socket -> stack. Reads a 2-byte little-endian length,
        // then that many frame bytes, and feeds the device.
        let reader_notify = Arc::clone(&notify);
        pumps.spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                // The prefix may arrive one byte at a time on a healthy
                // stream; only a clean end of stream ends the pump.
                match read_half.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "box egress proxy peer: switch socket read failed");
                        return;
                    }
                }
                let len = u16::from_le_bytes(len_buf) as usize;
                if len == 0 || len > usize::from(DEFAULT_MTU) + 14 + 4 {
                    // Malformed length; drop the connection.
                    return;
                }
                let mut frame = vec![0u8; len];
                if read_half.read_exact(&mut frame).await.is_err() {
                    return;
                }
                if inbound_tx.send(frame).is_err() {
                    // The poll task is gone.
                    return;
                }
                reader_notify.notify_one();
            }
        });

        // Pump 2: stack -> switch socket. Reads outbound frames, prefixes them
        // with a 2-byte little-endian length, and writes them.
        let writer_notify = Arc::clone(&notify);
        pumps.spawn(async move {
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

        // Poll task: the only task that owns the smoltcp `Interface`. It runs
        // on the current-thread runtime so `BepHost` (which is not `Send`) can
        // be held across `.await` points. We block_in_place in an async task
        // that is itself `Send`, and pass frames through channels.
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let poll_task = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime for BepHost");
            rt.block_on(async move {
                let mut host = BepHost::new(device, subnet, proxy_ip);
                host.poll(Instant::from_millis(0));

                let start = tokio::time::Instant::now();
                let mut interval = tokio::time::interval(POLL_DELAY);
                loop {
                    tokio::select! {
                        _ = notify.notified() => {}
                        _ = interval.tick() => {}
                        // The peer was dropped: leave the loop so the runtime
                        // that spawned this blocking task can shut down.
                        _ = &mut stop_rx => break,
                    }
                    // `poll` is the one consumer of the inbound channel: it
                    // takes the frames the reader pump enqueued and answers
                    // them. Draining the channel here would starve it.
                    let elapsed = start.elapsed().as_millis() as i64;
                    host.poll(Instant::from_millis(elapsed));
                    if host.lane_closed() {
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
            pumps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, EthernetFrame, EthernetProtocol, Icmpv4Packet, UdpRepr,
    };

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
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
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
            &ChecksumCapabilities::ignored(),
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
            &ChecksumCapabilities::ignored(),
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

    #[test]
    fn udp_to_proxy_address_gets_port_unreachable() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
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
        let peer = BepPeer::spawn(&sock, subnet)
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

    /// NET-132: no socket is bound on the peer in this task. The stack's
    /// socket set is empty at build time and stays empty across a turn that
    /// answered a segment and a datagram: a TCP segment is reset and a UDP
    /// datagram gets port-unreachable because nothing listens, not because a
    /// socket refused them. T69 is the only task that may bind one.
    #[test]
    fn peer_binds_no_socket() {
        let subnet = SwitchSubnet::default();
        let proxy_ip = subnet.box_egress_proxy_address();
        let (device, mut ends) = BepDevice::pair();
        let mut host = BepHost::new(device, subnet, proxy_ip);
        assert_eq!(host.sockets.iter().count(), 0, "no socket at build time");

        let peer_ip = Ipv4Addr::from(subnet.first_ptask());
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
        // Both answers went out, from the one path that handles frames.
        assert!(ends.outbound.try_recv().is_ok());
        assert!(ends.outbound.try_recv().is_ok());
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
    /// switch socket: no gratuitous ARP at attach, no probe, nothing.
    #[tokio::test]
    async fn idle_peer_emits_no_frames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("switch.sock");
        let accept_fut = stand_in_switch(&sock).await;

        let peer = BepPeer::spawn(&sock, SwitchSubnet::default())
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
        let peer = BepPeer::spawn(&sock, subnet)
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
}
