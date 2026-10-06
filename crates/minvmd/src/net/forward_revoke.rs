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
//!    at the sequence number the switch expects next.
//!
//! This module holds the pieces that do not read the gate's ledger: the
//! per-connection tracking, the reset frames, and the two switch exchanges.

use std::collections::BTreeMap;
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

/// Asks the switch at `switch_sock` to unexpose the forward bound at
/// `local`, bounded by `bound`. The exchange is the one the daemon's own
/// client makes: an HTTP/1.1 keep-alive request framed by `Content-Length`,
/// answered by a status line. A 2xx status is success.
///
/// # Errors
///
/// The connect, write or read error, a timeout past `bound`, or a status
/// outside 2xx.
pub(crate) async fn unexpose(
    switch_sock: &Path,
    local: &str,
    protocol: &str,
    bound: Duration,
) -> io::Result<()> {
    let body =
        serde_json_lenient::to_vec(&UnexposeBody { local, protocol }).map_err(io::Error::other)?;
    let mut request = format!(
        "POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    let status = tokio::time::timeout(bound, async {
        let mut switch = UnixStream::connect(switch_sock).await?;
        switch.write_all(&request).await?;
        read_status(&mut switch).await
    })
    .await
    .map_err(|_elapsed| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the switch did not answer an unexpose within {bound:?}"),
        )
    })??;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the switch answered the unexpose with HTTP {status}"
        )))
    }
}

/// Reads an HTTP answer's head and returns its status code. The body is not
/// needed and is left unread.
async fn read_status(switch: &mut UnixStream) -> io::Result<u16> {
    let mut answer = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    while !answer.windows(4).any(|window| window == b"\r\n\r\n") {
        if answer.len() >= MAX_ANSWER {
            return Err(io::Error::other(
                "the switch's answer exceeded the size cap before its head ended",
            ));
        }
        let n = switch.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        answer.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    let line = answer
        .split(|&byte| byte == b'\r' || byte == b'\n')
        .next()
        .unwrap_or_default();
    std::str::from_utf8(line)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::other(format!(
                "malformed switch status line: {:?}",
                String::from_utf8_lossy(line)
            ))
        })
}

/// Writes `frames` into the switch at `switch_sock` over a frame connection
/// of its own, bounded by `bound`: the `connect_request` upgrade, then each
/// frame behind its little-endian length, then the gate's side closed.
/// The switch hijacks the connection and answers nothing.
///
/// # Errors
///
/// The connect or write error, or a timeout past `bound`.
pub(crate) async fn inject(
    switch_sock: &Path,
    connect_request: &[u8],
    frames: &[Vec<u8>],
    bound: Duration,
) -> io::Result<()> {
    let mut stream = connect_request.to_vec();
    for frame in frames {
        let len = u16::try_from(frame.len()).map_err(io::Error::other)?;
        stream.extend_from_slice(&len.to_le_bytes());
        stream.extend_from_slice(frame);
    }
    tokio::time::timeout(bound, async {
        let mut switch = UnixStream::connect(switch_sock).await?;
        switch.write_all(&stream).await?;
        switch.shutdown().await
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
mod tests {
    use super::*;

    const BOX: [u8; 4] = [100, 64, 0, 9];
    const PEER: [u8; 4] = [100, 64, 0, 1];
    const BOX_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    const PEER_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd];

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

    #[test]
    fn a_listener_is_spelled_as_the_client_spells_it() {
        assert_eq!(listener_local([127, 0, 64, 9], 18096), "127.0.64.9:18096");
        assert_eq!(protocol_name(IPPROTO_TCP), Some("tcp"));
        assert_eq!(protocol_name(IPPROTO_UDP), Some("udp"));
        assert_eq!(protocol_name(1), None);
    }
}
