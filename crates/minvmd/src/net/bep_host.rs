//! The Box Egress Proxy's host leg (`bep_host`): the userspace TCP/IP stack
//! the proxy's listener stands on, over the switch (NET-132).
//!
//! A box with a credentialed lane reaches the proxy by connecting to the
//! leg's address on the switch's plan (NET-134); the connection arrives as
//! Ethernet frames over the switch's L2 lane, whose bytes cross the shuttle
//! length-framed (the 2-byte little-endian prefix the switch socket speaks —
//! see [`egress_gate`]'s relay). The host kernel knows nothing of the switch
//! subnet, so the leg terminates those frames itself: one smoltcp
//! [`Interface`] over a channel-backed [`Device`], answering ARP for the leg's
//! address (the proof the first test pins) and carrying the proxy's sockets
//! once the proxy's own work lands.
//!
//! [`BepDevice`] is that [`Device`]: a pair of unbounded tokio channels, one
//! raw Ethernet frame per message on each. [`BepDevice::pair`] hands the
//! caller the [`BepDeviceEnds`] to feed frames in through and take frames out
//! of; the length framing between those edges and the byte stream is the
//! stream reader's and writer's job, as it is in [`egress_gate`]'s relay.
//! [`BepHost`] builds the interface over it: the leg's address on a
//! [`SwitchSubnet`], its MAC derived the switch's way
//! ([`MacAddr::for_switch_ip`]), stepped with [`BepHost::poll`].

use std::fmt;
use std::net::Ipv4Addr;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use switch::{DEFAULT_MTU, MacAddr, SwitchSubnet};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

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

    /// Step the stack at `now`: process every buffered inbound frame, then
    /// emit whatever the interface has to send. Both drain to quiescence, so
    /// one call is one full turn of the stack.
    pub fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{ArpOperation, ArpPacket, ArpRepr, EthernetFrame, EthernetProtocol};

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

    /// The skeleton's first proof: build an interface over an in-process
    /// device and read its ARP reply. A box on the switch's plan asks who has
    /// the leg's address; the stack answers for the address it was given,
    /// from the switch-derived MAC, pointed back at the asker.
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

        let reply = ends.outbound.try_recv().expect("the stack answered");
        let frame = EthernetFrame::new_checked(&reply).expect("the reply is an Ethernet frame");
        assert_eq!(frame.ethertype(), EthernetProtocol::Arp);
        assert_eq!(frame.src_addr(), host.mac());
        assert_eq!(frame.dst_addr(), peer_mac);
        let arp = ArpPacket::new_checked(frame.payload()).expect("the reply carries ARP");
        assert_eq!(
            ArpRepr::parse(&arp).expect("the reply parses as ARP"),
            ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Reply,
                source_hardware_addr: host.mac(),
                source_protocol_addr: ip,
                target_hardware_addr: peer_mac,
                target_protocol_addr: peer_ip,
            }
        );
        // One request, one reply: the stack emitted nothing else.
        assert!(matches!(
            ends.outbound.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}
