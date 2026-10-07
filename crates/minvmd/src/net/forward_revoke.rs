//! Host-side ingress revocation at box end (design §7.1, NET-121, NET-017).
//!
//! On a VM-backed host every forward a box publishes is a listener the host
//! switch binds on the host loopback. A declared port's forward is the
//! host's to hold for the box's lifetime: the egress gate refuses any
//! withdrawal of it the guest asks for (NET-081's withdrawal rule), because
//! nothing inside the VM may unbind it. So when the box ends, the host
//! unbinds it. The egress gate subscribes to row withdrawals
//! ([`crate::box_registry::BoxTable::subscribe_row_withdrawals`]), and for
//! each withdrawn row it does two things:
//!
//! 1. It asks the switch to unexpose every forward its ledger holds at the
//!    row's switch address ([`unexpose`]). From then on a host connect to
//!    the published address is refused, rather than accepted by a listener
//!    with nothing behind it.
//! 2. It terminates the connections those forwards still carry. The
//!    switch's unexpose closes the listener only, and an established
//!    connection's switch-side endpoint would otherwise wait out its TCP
//!    timeouts against a box that is gone. The gate writes a reset to the
//!    switch for each connection it tracked ([`ForwardedFlows`],
//!    [`reset_frames`], [`inject`]). The reset comes from the box's address,
//!    at the sequence number the switch expects next. A reset at any other
//!    in-window number draws a challenge ACK (RFC 5961) carrying the exact
//!    number, and the gate answers that with one more reset, once per
//!    connection. The resets go out only once the switch has answered a
//!    probe on that connection ([`arp_probe`]): gvproxy hijacks the
//!    connection out of its HTTP server, and every byte the server read
//!    ahead of the hijack is dropped with the server's buffer, so a reset
//!    written in the same breath as the upgrade never reaches the switch.
//!
//! The long-term home for the second step is the switch itself: gvproxy's
//! forwarder should close the connections it accepted on a listener when
//! that listener is unexposed. That is an upstream change. Until it lands,
//! the gate's reset injection stands in for it.
//!
//! This module holds the pieces that do not read the gate's ledger: the
//! per-connection tracking, the reset frames, and the two switch exchanges.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sessions::core::egress::{IPPROTO_TCP, IPPROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Ethernet II header length.
const ETH_HDR: usize = 14;

/// EtherType for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// EtherType for ARP.
const ETHERTYPE_ARP: u16 = 0x0806;

/// An ARP request's operation code.
const ARP_REQUEST: u16 = 1;

/// An ARP reply's operation code.
const ARP_REPLY: u16 = 2;

/// How long one frame connection is given to answer the gate's probe before
/// the gate drops it and dials again. gVisor's stack answers an ARP request
/// for its own address at once, so a connection that stays silent this long
/// lost the probe to the hijack ([`dial_frames`]).
const PROBE_WINDOW: Duration = Duration::from_millis(250);

/// How long the gate waits after writing the upgrade before it writes the
/// probe, on the first dial. Each later dial waits one step longer, so a
/// switch slow to hijack is given more room every time.
const UPGRADE_SETTLE: Duration = Duration::from_millis(10);

/// The bound on one switch exchange made at box end: an unexpose, or the
/// write of the resets. A switch that accepts the connection and then
/// stalls must not hold the revocation of the next withdrawn box.
pub(crate) const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many forwarded connections the gate tracks across every box. Each
/// entry is a handful of bytes. At the bound the entry seen longest ago is
/// evicted, which can only leave that one connection to its TCP timeouts
/// at box end.
const FORWARDED_FLOWS_TRACKED: usize = 4096;

/// The cap on bytes read from one switch answer to an unexpose. gvproxy's
/// answers are a status line and a short body.
const MAX_ANSWER: usize = 64 * 1024;

/// How long the gate listens on its reset connection for a challenge ACK
/// (RFC 5961) after writing the resets. gVisor's stack answers an in-window
/// reset at the wrong sequence number at once, so a short window is enough.
pub(crate) const CHALLENGE_WINDOW: Duration = Duration::from_millis(500);

/// The body gvproxy answers an unexpose with when no forward is bound at the
/// listener (`PortsForwarder::Unexpose`, as an HTTP 500): the goal state
/// already holds.
const NOT_BOUND_BODY: &str = "proxy not found";

/// One forwarded TCP connection, keyed from the box's side: the box's
/// address and port, then the peer's address and port. The peer is the
/// switch's own stack, which dials the box for the host-side listener.
pub(crate) type FlowKey = ([u8; 4], u16, [u8; 4], u16);

/// What a reset for a tracked connection is built from: both ends'
/// hardware addresses, and the two readings of the sequence number the
/// switch expects next from the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlowTail {
    /// The box's hardware address, the destination of the switch's frames.
    box_mac: [u8; 6],
    /// The switch stack's hardware address, the source of its frames.
    peer_mac: [u8; 6],
    /// The acknowledgement number the switch last sent toward the box.
    peer_ack: Option<u32>,
    /// The sequence number just past the box's last segment.
    box_next: Option<u32>,
    /// When either side was last seen, for the eviction order.
    seen: Instant,
}

/// The TCP header fields a reset is built from, read off one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpSegment {
    pub(crate) dst_mac: [u8; 6],
    pub(crate) src_mac: [u8; 6],
    pub(crate) src: [u8; 4],
    pub(crate) dst: [u8; 4],
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    /// Payload bytes, plus one each for SYN and FIN: how far the segment
    /// advances its sender's sequence number.
    pub(crate) advance: u32,
}

/// Reads an Ethernet II + IPv4 + TCP frame's addressing and sequence state.
/// `None` for anything else, for a fragment, and for a short or malformed
/// frame. A hostile frame yields `None`, never an out-of-bounds read.
pub(crate) fn parse_tcp_segment(frame: &[u8]) -> Option<TcpSegment> {
    let eth = frame.get(..ETH_HDR)?;
    if u16::from_be_bytes([*eth.get(12)?, *eth.get(13)?]) != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(ETH_HDR..)?;
    let ihl = usize::from(*ip.first()? & 0x0f) * 4;
    if ihl < 20 || *ip.get(9)? != IPPROTO_TCP {
        return None;
    }
    // A fragment carries no whole TCP header to read.
    let fragment = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    let tcp = ip.get(ihl..total.min(ip.len()))?;
    let data_offset = usize::from(*tcp.get(12)? >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(tcp.get(at..at + 4)?.try_into().ok()?))
    };
    let flags = *tcp.get(13)?;
    let payload = u32::try_from(tcp.len() - data_offset).ok()?;
    let advance = payload + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
    Some(TcpSegment {
        dst_mac: eth.get(0..6)?.try_into().ok()?,
        src_mac: eth.get(6..12)?.try_into().ok()?,
        src: ip.get(12..16)?.try_into().ok()?,
        dst: ip.get(16..20)?.try_into().ok()?,
        src_port: u16::from_be_bytes([*tcp.first()?, *tcp.get(1)?]),
        dst_port: u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]),
        seq: word(4)?,
        ack: word(8)?,
        flags,
        advance,
    })
}

/// The forwarded connections the gate has seen, each with the state a reset
/// for it is built from. An entry is opened only by a frame the gate
/// delivered toward a box at a port one of its applied publishes dials, so
/// only a connection through a published forward is ever tracked. The box's
/// own frames update an entry and never open one. A reset seen either way
/// closes it, and the box's end takes every entry at its address
/// ([`Self::take_at`]).
#[derive(Debug, Default)]
pub(crate) struct ForwardedFlows {
    flows: Mutex<BTreeMap<FlowKey, FlowTail>>,
}

impl ForwardedFlows {
    /// Notes a frame the gate is delivering from the switch toward a box,
    /// at a port one of the box's applied publishes dials.
    pub(crate) fn observe_toward_box(&self, segment: &TcpSegment, now: Instant) {
        let key = (segment.dst, segment.dst_port, segment.src, segment.src_port);
        let mut flows = self.lock();
        if segment.flags & TCP_RST != 0 {
            flows.remove(&key);
            return;
        }
        if !flows.contains_key(&key) && flows.len() >= FORWARDED_FLOWS_TRACKED {
            let oldest = flows
                .iter()
                .min_by_key(|(_, tail)| tail.seen)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                flows.remove(&oldest);
            }
        }
        let tail = flows.entry(key).or_insert(FlowTail {
            box_mac: segment.dst_mac,
            peer_mac: segment.src_mac,
            peer_ack: None,
            box_next: None,
            seen: now,
        });
        tail.box_mac = segment.dst_mac;
        tail.peer_mac = segment.src_mac;
        if segment.flags & TCP_ACK != 0 {
            tail.peer_ack = Some(segment.ack);
        }
        tail.seen = now;
    }

    /// Notes a frame the gate admitted from a box toward the switch. Only an
    /// entry the switch's side opened is updated.
    pub(crate) fn observe_from_box(&self, segment: &TcpSegment, now: Instant) {
        let key = (segment.src, segment.src_port, segment.dst, segment.dst_port);
        let mut flows = self.lock();
        if segment.flags & TCP_RST != 0 {
            flows.remove(&key);
            return;
        }
        if let Some(tail) = flows.get_mut(&key) {
            tail.box_next = Some(segment.seq.wrapping_add(segment.advance));
            tail.seen = now;
        }
    }

    /// Takes every connection tracked at the box address `addr`, leaving
    /// none behind: the box has ended, and these are the connections its
    /// forwards still carry.
    pub(crate) fn take_at(&self, addr: [u8; 4]) -> Vec<(FlowKey, FlowTail)> {
        let mut flows = self.lock();
        let taken: Vec<FlowKey> = flows
            .keys()
            .filter(|(box_addr, _, _, _)| *box_addr == addr)
            .copied()
            .collect();
        taken
            .into_iter()
            .filter_map(|key| flows.remove(&key).map(|tail| (key, tail)))
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<FlowKey, FlowTail>> {
        self.flows
            .lock()
            .expect("the forwarded-flow table's lock is held only across one update")
    }
}

/// The resets that end one tracked connection at the switch: from the box's
/// address and port, toward the switch stack's. The switch accepts a reset
/// only at the exact sequence number it expects next, so one reset goes out
/// at each reading the gate holds of that number: past the box's last
/// segment, and the switch's own last acknowledgement. When they agree, one
/// reset is enough. A reset at a reading that is stale is ignored by the
/// switch or answered with an acknowledgement toward an address no box
/// holds any more. Either way nothing is reset that should not be.
pub(crate) fn reset_frames(key: &FlowKey, tail: &FlowTail) -> Vec<Vec<u8>> {
    let mut seqs: Vec<u32> = tail.box_next.into_iter().chain(tail.peer_ack).collect();
    seqs.dedup();
    seqs.into_iter()
        .map(|seq| rst_frame(key, tail, seq))
        .collect()
}

/// The reset that answers a challenge ACK, when `frame` is one: a bare ACK
/// from the switch's stack toward the box, on one of `flows`, that `answered`
/// has not answered yet. gVisor follows RFC 5961: a reset inside the receive
/// window but not at the exact next sequence number draws an ACK whose
/// acknowledgement number is that exact number. A reset at it closes the
/// connection. One answer per connection, so a peer that keeps acknowledging
/// cannot turn the gate into a reset loop.
pub(crate) fn challenge_reset(
    frame: &[u8],
    flows: &[(FlowKey, FlowTail)],
    answered: &mut BTreeSet<FlowKey>,
) -> Option<Vec<u8>> {
    let segment = parse_tcp_segment(frame)?;
    if segment.flags & TCP_ACK == 0 || segment.flags & (TCP_RST | TCP_SYN) != 0 {
        return None;
    }
    let key = (segment.dst, segment.dst_port, segment.src, segment.src_port);
    let (_, tail) = flows.iter().find(|(tracked, _)| *tracked == key)?;
    if !answered.insert(key) {
        return None;
    }
    let tail = FlowTail {
        box_mac: segment.dst_mac,
        peer_mac: segment.src_mac,
        ..*tail
    };
    Some(rst_frame(&key, &tail, segment.ack))
}

/// One reset segment, as a whole Ethernet frame with both checksums.
fn rst_frame(key: &FlowKey, tail: &FlowTail, seq: u32) -> Vec<u8> {
    let (box_addr, box_port, peer_addr, peer_port) = *key;
    let mut ip = Vec::with_capacity(40);
    ip.push(0x45); // IPv4, IHL 5
    ip.push(0x00);
    ip.extend_from_slice(&40u16.to_be_bytes()); // total length
    ip.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip.push(64); // TTL
    ip.push(IPPROTO_TCP);
    ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum, below
    ip.extend_from_slice(&box_addr);
    ip.extend_from_slice(&peer_addr);
    let ip_sum = checksum(&ip, 0).to_be_bytes();
    if let Some(slot) = ip.get_mut(10..12) {
        slot.copy_from_slice(&ip_sum);
    }

    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&box_port.to_be_bytes());
    tcp.extend_from_slice(&peer_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement: none
    tcp.push(0x50); // data offset: 5 words
    tcp.push(TCP_RST);
    tcp.extend_from_slice(&0u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, below
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    let pseudo = pseudo_header_sum(box_addr, peer_addr, 20);
    let tcp_sum = checksum(&tcp, pseudo).to_be_bytes();
    if let Some(slot) = tcp.get_mut(16..18) {
        slot.copy_from_slice(&tcp_sum);
    }

    let mut frame = Vec::with_capacity(ETH_HDR + 40);
    frame.extend_from_slice(&tail.peer_mac);
    frame.extend_from_slice(&tail.box_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// The TCP pseudo-header's contribution to the checksum, unfolded.
fn pseudo_header_sum(src: [u8; 4], dst: [u8; 4], tcp_len: u16) -> u32 {
    let words = |addr: [u8; 4]| {
        u32::from(u16::from_be_bytes([addr[0], addr[1]]))
            + u32::from(u16::from_be_bytes([addr[2], addr[3]]))
    };
    words(src) + words(dst) + u32::from(IPPROTO_TCP) + u32::from(tcp_len)
}

/// The Internet checksum of `bytes`, seeded with `initial`.
fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => u32::from(u16::from_be_bytes([*high, *low])),
            [high] => u32::from(u16::from_be_bytes([*high, 0])),
            _ => 0,
        })
        .fold(initial, u32::wrapping_add);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("the fold leaves at most sixteen bits")
}

/// The switch's wire spelling of a ledger protocol number. `None` for a
/// number the daemon's client never publishes.
pub(crate) fn protocol_name(proto: u8) -> Option<&'static str> {
    match proto {
        IPPROTO_TCP => Some("tcp"),
        IPPROTO_UDP => Some("udp"),
        _ => None,
    }
}

/// The `local` an unexpose names for a ledger listener: the dotted quad and
/// the port, spelled as the daemon's client spells its expose. The gate
/// summarizes an expose only in that spelling, so the switch keys the
/// forward by exactly this string.
pub(crate) fn listener_local(addr: [u8; 4], port: u16) -> String {
    format!("{}:{port}", Ipv4Addr::from(addr))
}

/// The unexpose body, in the shape the daemon's own client sends.
#[derive(serde::Serialize)]
struct UnexposeBody<'a> {
    local: &'a str,
    protocol: &'a str,
}

/// What an unexpose the switch accepted came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unexposed {
    /// The switch closed the listener.
    Unbound,
    /// The switch held no forward at the listener: it was already unbound,
    /// by an earlier try whose answer was lost or by the guest's own
    /// retraction. The goal state holds, so a retry counts this as done.
    NotBound,
}

/// Asks the switch at `switch_sock` to unexpose the forward bound at
/// `local`, bounded by `bound`. The exchange is the one the daemon's own
/// client makes: an HTTP/1.1 keep-alive request framed by `Content-Length`,
/// answered by a status line. A 2xx status is [`Unexposed::Unbound`].
/// gvproxy's 500 whose body says no proxy is bound there is
/// [`Unexposed::NotBound`].
///
/// # Errors
///
/// The connect, write or read error, a timeout past `bound`, or any other
/// status outside 2xx.
pub(crate) async fn unexpose(
    switch_sock: &Path,
    local: &str,
    protocol: &str,
    bound: Duration,
) -> io::Result<Unexposed> {
    let body =
        serde_json_lenient::to_vec(&UnexposeBody { local, protocol }).map_err(io::Error::other)?;
    let mut request = format!(
        "POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    let (status, body) = tokio::time::timeout(bound, async {
        let mut switch = UnixStream::connect(switch_sock).await?;
        switch.write_all(&request).await?;
        read_answer(&mut switch).await
    })
    .await
    .map_err(|_elapsed| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the switch did not answer an unexpose within {bound:?}"),
        )
    })??;
    let body = String::from_utf8_lossy(&body);
    if (200..300).contains(&status) {
        Ok(Unexposed::Unbound)
    } else if status == 500 && body.trim() == NOT_BOUND_BODY {
        Ok(Unexposed::NotBound)
    } else {
        Err(io::Error::other(format!(
            "the switch answered the unexpose with HTTP {status}: {:?}",
            body.trim()
        )))
    }
}

/// Reads an HTTP answer and returns its status code and its body, as much
/// of the body as its `Content-Length` names, within [`MAX_ANSWER`].
async fn read_answer(switch: &mut UnixStream) -> io::Result<(u16, Vec<u8>)> {
    let mut answer = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    let head_end = loop {
        if let Some(at) = answer.windows(4).position(|window| window == b"\r\n\r\n") {
            break Some(at + 4);
        }
        if answer.len() >= MAX_ANSWER {
            return Err(io::Error::other(
                "the switch's answer exceeded the size cap before its head ended",
            ));
        }
        let n = switch.read(&mut chunk).await?;
        if n == 0 {
            break None;
        }
        answer.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    let line = answer
        .split(|&byte| byte == b'\r' || byte == b'\n')
        .next()
        .unwrap_or_default();
    let status = std::str::from_utf8(line)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::other(format!(
                "malformed switch status line: {:?}",
                String::from_utf8_lossy(line)
            ))
        })?;
    let Some(head_end) = head_end else {
        return Ok((status, Vec::new()));
    };
    let length = content_length(answer.get(..head_end).unwrap_or_default())
        .unwrap_or(0)
        .min(MAX_ANSWER);
    let body_end = head_end + length;
    while answer.len() < body_end {
        let n = switch.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        answer.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    let body = answer
        .get(head_end..body_end.min(answer.len()))
        .unwrap_or_default()
        .to_vec();
    Ok((status, body))
}

/// The `Content-Length` an HTTP head declares, when it declares one.
fn content_length(head: &[u8]) -> Option<usize> {
    std::str::from_utf8(head).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// Appends each of `frames` to `stream` behind its little-endian length.
fn frame_onto(stream: &mut Vec<u8>, frames: &[Vec<u8>]) -> io::Result<()> {
    for frame in frames {
        let len = u16::try_from(frame.len()).map_err(io::Error::other)?;
        stream.extend_from_slice(&len.to_le_bytes());
        stream.extend_from_slice(frame);
    }
    Ok(())
}

/// Takes one whole length-framed frame off the front of `buf`, when `buf`
/// holds one.
fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let len = usize::from(u16::from_le_bytes([*buf.first()?, *buf.get(1)?]));
    let frame = buf.get(2..2 + len)?.to_vec();
    buf.drain(..2 + len);
    Some(frame)
}

/// The probe that proves a frame connection reaches the switch: an ARP
/// request from the box's hardware and network address for the address of
/// the switch's stack. The stack answers it toward the box's hardware
/// address, which the switch has just learned on this connection, so the
/// answer comes back here ([`is_probe_answer`]). It teaches the switch
/// nothing the resets would not: they come from the same hardware address.
pub(crate) fn arp_probe(key: &FlowKey, tail: &FlowTail) -> Vec<u8> {
    let (box_addr, _, peer_addr, _) = *key;
    let mut frame = Vec::with_capacity(ETH_HDR + 28);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&tail.box_mac);
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes()); // hardware: Ethernet
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&[6, 4]); // address lengths
    frame.extend_from_slice(&ARP_REQUEST.to_be_bytes());
    frame.extend_from_slice(&tail.box_mac);
    frame.extend_from_slice(&box_addr);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&peer_addr);
    frame
}

/// Whether `frame` answers [`arp_probe`] for `key` and `tail`: an ARP reply
/// from the switch stack's address, to the box's hardware address.
pub(crate) fn is_probe_answer(frame: &[u8], key: &FlowKey, tail: &FlowTail) -> bool {
    let (_, _, peer_addr, _) = *key;
    frame.get(12..14) == Some(&ETHERTYPE_ARP.to_be_bytes()[..])
        && frame.get(ETH_HDR + 6..ETH_HDR + 8) == Some(&ARP_REPLY.to_be_bytes()[..])
        && frame.get(ETH_HDR + 14..ETH_HDR + 18) == Some(&peer_addr[..])
        && frame.get(ETH_HDR + 18..ETH_HDR + 24) == Some(&tail.box_mac[..])
}

/// Dials the switch at `switch_sock` until a frame connection answers the
/// probe for `probe_flow` ([`arp_probe`]), and returns that connection with
/// whatever it read past the answer. gvproxy upgrades a connection by
/// hijacking it out of its HTTP server and writes nothing back, and the
/// bytes its server read ahead of the hijack are dropped with the server's
/// buffer. So the gate writes the upgrade alone, waits, writes the probe,
/// and takes an answer within [`PROBE_WINDOW`] as proof that its frames now
/// reach the switch whole. A connection that stays silent lost the probe,
/// or part of it, to the hijack, and is dropped for a fresh one that waits
/// longer before its probe.
async fn dial_frames(
    switch_sock: &Path,
    connect_request: &[u8],
    probe_flow: &(FlowKey, FlowTail),
) -> io::Result<(UnixStream, Vec<u8>)> {
    let (key, tail) = probe_flow;
    let mut probe = Vec::new();
    frame_onto(&mut probe, &[arp_probe(key, tail)])?;
    let mut settle = UPGRADE_SETTLE;
    loop {
        let mut switch = UnixStream::connect(switch_sock).await?;
        switch.write_all(connect_request).await?;
        tokio::time::sleep(settle).await;
        switch.write_all(&probe).await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        let window_end = tokio::time::Instant::now() + PROBE_WINDOW;
        while let Ok(read) = tokio::time::timeout_at(window_end, switch.read(&mut chunk)).await {
            let n = read?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            while let Some(frame) = take_frame(&mut buf) {
                if is_probe_answer(&frame, key, tail) {
                    return Ok((switch, buf));
                }
            }
        }
        settle += UPGRADE_SETTLE;
    }
}

/// Ends the tracked connections `flows` at the switch at `switch_sock`,
/// over a frame connection of the gate's own, bounded by `bound`. It writes
/// the `connect_request` upgrade and waits for the switch to answer a probe
/// on it ([`dial_frames`]), then writes each connection's resets
/// ([`reset_frames`]), each frame behind its little-endian length. Then it
/// listens for `challenge_window` and answers each challenge ACK with one
/// reset at the number the ACK carries ([`challenge_reset`]), at most once
/// per connection. The switch learns the box's hardware address from the
/// probe, so it sends the challenge ACKs back over this connection. The
/// gate then closes its side. Returns how many challenge ACKs it answered.
///
/// # Errors
///
/// The connect, read or write error, or a timeout past `bound`.
pub(crate) async fn inject(
    switch_sock: &Path,
    connect_request: &[u8],
    flows: &[(FlowKey, FlowTail)],
    bound: Duration,
    challenge_window: Duration,
) -> io::Result<usize> {
    let Some(probe_flow) = flows.first() else {
        return Ok(0);
    };
    let resets: Vec<Vec<u8>> = flows
        .iter()
        .flat_map(|(key, tail)| reset_frames(key, tail))
        .collect();
    let mut stream = Vec::new();
    frame_onto(&mut stream, &resets)?;
    tokio::time::timeout(bound, async {
        let (mut switch, mut buf) = dial_frames(switch_sock, connect_request, probe_flow).await?;
        switch.write_all(&stream).await?;
        let mut answered = BTreeSet::new();
        let mut chunk = [0u8; 2048];
        let window_end = tokio::time::Instant::now() + challenge_window;
        while answered.len() < flows.len() {
            let Ok(read) = tokio::time::timeout_at(window_end, switch.read(&mut chunk)).await
            else {
                break;
            };
            let n = read?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            while let Some(frame) = take_frame(&mut buf) {
                if let Some(reset) = challenge_reset(&frame, flows, &mut answered) {
                    let mut framed = Vec::new();
                    frame_onto(&mut framed, &[reset])?;
                    switch.write_all(&framed).await?;
                }
            }
        }
        switch.shutdown().await?;
        Ok(answered.len())
    })
    .await
    .map_err(|_elapsed| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the switch did not take the resets within {bound:?}"),
        )
    })?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const BOX: [u8; 4] = [100, 64, 0, 9];
    const PEER: [u8; 4] = [100, 64, 0, 1];
    const BOX_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    const PEER_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd];

    /// The answer the switch's stack gives `request`, an ARP request, from
    /// the address it asks for; `None` for any other frame.
    fn arp_answer(request: &[u8]) -> Option<Vec<u8>> {
        let asked = request.get(ETH_HDR..ETH_HDR + 28)?;
        if request.get(12..14)? != ETHERTYPE_ARP.to_be_bytes()
            || asked.get(6..8)? != ARP_REQUEST.to_be_bytes()
        {
            return None;
        }
        let (requester_mac, requester) = (asked.get(8..14)?, asked.get(14..18)?);
        let mut answer = Vec::new();
        answer.extend_from_slice(requester_mac);
        answer.extend_from_slice(&PEER_MAC);
        answer.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        answer.extend_from_slice(asked.get(..6)?);
        answer.extend_from_slice(&ARP_REPLY.to_be_bytes());
        answer.extend_from_slice(&PEER_MAC);
        answer.extend_from_slice(asked.get(24..28)?);
        answer.extend_from_slice(requester_mac);
        answer.extend_from_slice(requester);
        Some(answer)
    }

    /// Stands in for the switch on a frame connection the gate dialed, up to
    /// its resets: reads the upgrade `connect_request`, then the gate's
    /// probe, and answers the probe as the switch's stack does.
    pub(crate) async fn answer_the_probe(switch: &mut UnixStream, connect_request: &[u8]) {
        let mut head = vec![0u8; connect_request.len()];
        switch
            .read_exact(&mut head)
            .await
            .expect("reading the upgrade");
        assert_eq!(head, connect_request, "the upgrade comes first, alone");
        let mut len = [0u8; 2];
        switch
            .read_exact(&mut len)
            .await
            .expect("reading the probe's length");
        let mut probe = vec![0u8; usize::from(u16::from_le_bytes(len))];
        switch
            .read_exact(&mut probe)
            .await
            .expect("reading the probe");
        let answer = arp_answer(&probe).expect("the probe is an ARP request");
        let mut framed = Vec::new();
        frame_onto(&mut framed, &[answer]).expect("framing the answer");
        switch
            .write_all(&framed)
            .await
            .expect("answering the probe");
    }

    /// Stands in for gvproxy's switch socket as its HTTP server hands a
    /// connection to the switch: the server reads the upgrade together with
    /// whatever arrived behind it, the hijack drops all of that with the
    /// server's buffer, and only the bytes read after it reach the switch.
    /// Each ARP request that reaches it is answered as the switch's stack
    /// answers it, and each reset is sent on `resets`.
    async fn hijacking_switch(
        listener: tokio::net::UnixListener,
        resets: tokio::sync::mpsc::UnboundedSender<TcpSegment>,
    ) {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return;
            };
            let resets = resets.clone();
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                let mut head = Vec::new();
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match conn.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let mut buf = Vec::new();
                while let Ok(n) = conn.read(&mut chunk).await {
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(frame) = take_frame(&mut buf) {
                        if let Some(answer) = arp_answer(&frame) {
                            let mut framed = Vec::new();
                            frame_onto(&mut framed, &[answer]).expect("framing the answer");
                            if conn.write_all(&framed).await.is_err() {
                                return;
                            }
                        } else if let Some(segment) = parse_tcp_segment(&frame)
                            && segment.flags & TCP_RST != 0
                        {
                            let _ = resets.send(segment);
                        }
                    }
                }
            });
        }
    }

    /// A TCP frame with sequence state and `payload` bytes of data.
    fn segment(
        (src_mac, src, src_port): ([u8; 6], [u8; 4], u16),
        (dst_mac, dst, dst_port): ([u8; 6], [u8; 4], u16),
        (seq, ack, flags): (u32, u32, u8),
        payload: usize,
    ) -> Vec<u8> {
        let total = u16::try_from(40 + payload).unwrap();
        let mut f = Vec::new();
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let [total_high, total_low] = total.to_be_bytes();
        f.extend_from_slice(&[
            0x45,
            0,
            total_high,
            total_low,
            0,
            0,
            0x40,
            0,
            64,
            IPPROTO_TCP,
            0,
            0,
        ]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ack.to_be_bytes());
        f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend(std::iter::repeat_n(0xab, payload));
        f
    }

    fn toward_box(seq: u32, ack: u32, flags: u8, payload: usize) -> TcpSegment {
        parse_tcp_segment(&segment(
            (PEER_MAC, PEER, 40000),
            (BOX_MAC, BOX, 8080),
            (seq, ack, flags),
            payload,
        ))
        .expect("a well-formed segment parses")
    }

    fn from_box(seq: u32, ack: u32, flags: u8, payload: usize) -> TcpSegment {
        parse_tcp_segment(&segment(
            (BOX_MAC, BOX, 8080),
            (PEER_MAC, PEER, 40000),
            (seq, ack, flags),
            payload,
        ))
        .expect("a well-formed segment parses")
    }

    #[test]
    fn a_segment_parses_its_addressing_and_sequence_state() {
        let parsed = from_box(1000, 7, TCP_ACK | TCP_FIN, 5);
        assert_eq!(parsed.src, BOX);
        assert_eq!(parsed.dst, PEER);
        assert_eq!((parsed.src_port, parsed.dst_port), (8080, 40000));
        assert_eq!((parsed.seq, parsed.ack), (1000, 7));
        assert_eq!(parsed.advance, 6, "five payload bytes and the FIN");
        assert_eq!((parsed.src_mac, parsed.dst_mac), (BOX_MAC, PEER_MAC));
    }

    #[test]
    fn short_and_non_tcp_frames_do_not_parse() {
        let frame = segment(
            (BOX_MAC, BOX, 8080),
            (PEER_MAC, PEER, 40000),
            (1, 1, TCP_ACK),
            0,
        );
        assert!(parse_tcp_segment(&frame[..30]).is_none());
        let mut udp = frame.clone();
        udp[ETH_HDR + 9] = IPPROTO_UDP;
        assert!(parse_tcp_segment(&udp).is_none());
        let mut fragment = frame;
        fragment[ETH_HDR + 7] = 8;
        assert!(parse_tcp_segment(&fragment).is_none());
    }

    /// The switch opens an entry, the box's segments advance it, and the
    /// resets go out at the box's next sequence number and the switch's
    /// last acknowledgement, from the box toward the switch, with valid
    /// checksums.
    #[test]
    fn a_tracked_connection_is_reset_at_the_sequence_the_switch_expects() {
        let flows = ForwardedFlows::default();
        let now = Instant::now();
        // The box's frame first: it opens nothing.
        flows.observe_from_box(&from_box(500, 1, TCP_ACK, 10), now);
        assert!(flows.take_at(BOX).is_empty());
        flows.observe_toward_box(&toward_box(1, 0, TCP_SYN, 0), now);
        flows.observe_from_box(&from_box(500, 2, TCP_SYN | TCP_ACK, 0), now);
        flows.observe_toward_box(&toward_box(2, 501, TCP_ACK, 3), now);
        flows.observe_from_box(&from_box(501, 5, TCP_ACK, 100), now);

        let taken = flows.take_at(BOX);
        assert_eq!(taken.len(), 1);
        assert!(
            flows.take_at(BOX).is_empty(),
            "the box's end takes them all"
        );
        let (key, tail) = taken.first().unwrap();
        assert_eq!(*key, (BOX, 8080, PEER, 40000));

        let resets = reset_frames(key, tail);
        assert_eq!(resets.len(), 2, "one per distinct reading: 601 and 501");
        let parsed: Vec<TcpSegment> = resets
            .iter()
            .map(|frame| parse_tcp_segment(frame).expect("a reset parses"))
            .collect();
        assert_eq!(
            parsed.iter().map(|reset| reset.seq).collect::<Vec<_>>(),
            [601, 501]
        );
        for (frame, reset) in resets.iter().zip(&parsed) {
            assert_eq!(reset.flags, TCP_RST);
            assert_eq!((reset.src, reset.src_port), (BOX, 8080));
            assert_eq!((reset.dst, reset.dst_port), (PEER, 40000));
            assert_eq!((reset.src_mac, reset.dst_mac), (BOX_MAC, PEER_MAC));
            let ip = &frame[ETH_HDR..ETH_HDR + 20];
            assert_eq!(checksum(ip, 0), 0, "the IPv4 header checksum verifies");
            let tcp = &frame[ETH_HDR + 20..];
            assert_eq!(
                checksum(tcp, pseudo_header_sum(BOX, PEER, 20)),
                0,
                "the TCP checksum verifies"
            );
        }
    }

    #[test]
    fn a_reset_either_way_ends_the_tracking() {
        let flows = ForwardedFlows::default();
        let now = Instant::now();
        flows.observe_toward_box(&toward_box(1, 0, TCP_SYN, 0), now);
        flows.observe_toward_box(&toward_box(2, 0, TCP_RST, 0), now);
        assert!(flows.take_at(BOX).is_empty());
        flows.observe_toward_box(&toward_box(1, 0, TCP_SYN, 0), now);
        flows.observe_from_box(&from_box(9, 0, TCP_RST, 0), now);
        assert!(flows.take_at(BOX).is_empty());
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_oldest() {
        let flows = ForwardedFlows::default();
        let start = Instant::now();
        let peer_ports = (0..=u16::try_from(FORWARDED_FLOWS_TRACKED).unwrap()).map(|n| n + 1000);
        for (offset, port) in peer_ports.enumerate() {
            let mut seg = toward_box(1, 0, TCP_SYN, 0);
            seg.src_port = port;
            flows.observe_toward_box(
                &seg,
                start + Duration::from_millis(u64::try_from(offset).unwrap()),
            );
        }
        let taken = flows.take_at(BOX);
        assert_eq!(taken.len(), FORWARDED_FLOWS_TRACKED);
        assert!(
            taken.iter().all(|((_, _, _, port), _)| *port != 1000),
            "the connection seen longest ago was the one evicted"
        );
    }

    /// Design §7.1 against the switch as gvproxy hands it a connection: its
    /// HTTP server reads the upgrade with whatever arrived behind it, and
    /// the hijack drops all of that. Resets written in the same breath as
    /// the upgrade were dropped every time, so a connection held through a
    /// forward outlived its box. The gate holds its resets until the switch
    /// has answered its probe, and they arrive, at both readings of the
    /// sequence number the switch expects.
    #[tokio::test]
    async fn the_resets_reach_a_switch_that_drops_what_was_read_before_its_hijack() {
        let dir = tempfile::TempDir::new().expect("a tempdir");
        let sock = dir.path().join("switch.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("binding the stand-in switch");
        let (resets_tx, mut resets_rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio::spawn(hijacking_switch(listener, resets_tx));
        let flows = ForwardedFlows::default();
        let now = Instant::now();
        flows.observe_toward_box(&toward_box(1, 0, TCP_SYN, 0), now);
        flows.observe_from_box(&from_box(500, 2, TCP_SYN | TCP_ACK, 0), now);
        flows.observe_toward_box(&toward_box(2, 501, TCP_ACK, 3), now);
        flows.observe_from_box(&from_box(501, 5, TCP_ACK, 100), now);
        let taken = flows.take_at(BOX);

        let answered = inject(
            &sock,
            b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n",
            &taken,
            Duration::from_secs(5),
            Duration::from_millis(100),
        )
        .await
        .expect("the inject");
        assert_eq!(answered, 0, "no challenge ACK was drawn");

        let mut seqs = Vec::new();
        while seqs.len() < 2 {
            let reset = tokio::time::timeout(Duration::from_secs(5), resets_rx.recv())
                .await
                .expect("the gate's resets reach the switch")
                .expect("the stand-in switch is up");
            assert_eq!((reset.src, reset.src_port), (BOX, 8080));
            assert_eq!((reset.dst, reset.dst_port), (PEER, 40000));
            seqs.push(reset.seq);
        }
        assert_eq!(seqs, [601, 501]);
        switch.abort();
    }

    /// The frames in `bytes`, each behind its little-endian length.
    fn frames_in(mut bytes: Vec<u8>) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(frame) = take_frame(&mut bytes) {
            frames.push(frame);
        }
        assert!(bytes.is_empty(), "a partial frame was left over");
        frames
    }

    /// C1, RFC 5961 at the switch's stack: a reset at an in-window number
    /// other than the exact next one draws a challenge ACK whose
    /// acknowledgement number is the exact one. The gate answers it with one
    /// reset at that number, from the box toward the switch's stack. It
    /// answers at most once per connection, and never answers an ACK on a
    /// connection it is not ending.
    #[tokio::test]
    async fn a_challenge_ack_is_answered_once_with_a_reset_at_its_number() {
        let dir = tempfile::TempDir::new().expect("a tempdir");
        let sock = dir.path().join("switch.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("binding the stand-in switch");
        let flows = ForwardedFlows::default();
        let now = Instant::now();
        flows.observe_toward_box(&toward_box(1, 0, TCP_SYN, 0), now);
        flows.observe_from_box(&from_box(500, 2, TCP_SYN | TCP_ACK, 0), now);
        flows.observe_toward_box(&toward_box(2, 501, TCP_ACK, 3), now);
        flows.observe_from_box(&from_box(501, 5, TCP_ACK, 100), now);
        let taken = flows.take_at(BOX);
        let connect: &'static [u8] = b"POST /connect HTTP/1.1\r\n\r\n";
        let injecting = tokio::spawn(async move {
            inject(
                &sock,
                connect,
                &taken,
                Duration::from_secs(5),
                Duration::from_secs(2),
            )
            .await
        });

        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        answer_the_probe(&mut switch, connect).await;
        // The two first resets: past the box's last segment, and at the
        // switch's last acknowledgement.
        let mut first = vec![0u8; 2 * (2 + ETH_HDR + 40)];
        switch
            .read_exact(&mut first)
            .await
            .expect("reading the first resets");
        let seqs: Vec<u32> = frames_in(first)
            .iter()
            .map(|frame| parse_tcp_segment(frame).expect("a reset parses").seq)
            .collect();
        assert_eq!(seqs, [601, 501]);

        // An ACK on a connection the gate is not ending, then two challenge
        // ACKs on the one it is, carrying the exact number 777.
        let stranger = segment(
            (PEER_MAC, PEER, 40001),
            (BOX_MAC, BOX, 8080),
            (2, 900, TCP_ACK),
            0,
        );
        let challenge = segment(
            (PEER_MAC, PEER, 40000),
            (BOX_MAC, BOX, 8080),
            (2, 777, TCP_ACK),
            0,
        );
        let mut written = Vec::new();
        frame_onto(&mut written, &[stranger, challenge.clone(), challenge])
            .expect("framing the ACKs");
        switch.write_all(&written).await.expect("writing the ACKs");

        let mut rest = Vec::new();
        switch
            .read_to_end(&mut rest)
            .await
            .expect("reading to the gate's close");
        let answers = frames_in(rest);
        assert_eq!(
            answers.len(),
            1,
            "one answer, to the tracked connection only"
        );
        let answer = parse_tcp_segment(answers.first().expect("one answer")).expect("it parses");
        assert_eq!(answer.flags, TCP_RST);
        assert_eq!(
            answer.seq, 777,
            "the reset is at the number the challenge ACK carries"
        );
        assert_eq!((answer.src, answer.src_port), (BOX, 8080));
        assert_eq!((answer.dst, answer.dst_port), (PEER, 40000));
        assert_eq!(
            injecting
                .await
                .expect("the inject task")
                .expect("the inject"),
            1,
            "one challenge answered"
        );
    }

    #[test]
    fn a_listener_is_spelled_as_the_client_spells_it() {
        assert_eq!(listener_local([127, 0, 64, 9], 18096), "127.0.64.9:18096");
        assert_eq!(protocol_name(IPPROTO_TCP), Some("tcp"));
        assert_eq!(protocol_name(IPPROTO_UDP), Some("udp"));
        assert_eq!(protocol_name(1), None);
    }
}
