//! The one shape of a refused connection's answer (NET-014, NET-081).
//!
//! Three callers refuse connections — the daemon's switch relay, whose
//! native and in-guest attach legs hold the same per-session gate, and the
//! box egress proxy's stack peer — and this module is the only place any of
//! them builds the reply or says the audit line. Everything here is bytes
//! and arithmetic on an arriving frame: the crate carries no runtime and no
//! feature the rest of the workspace must match, so the in-guest daemon and
//! the host daemon link the same definitions and a refusal shaped on one leg
//! reads identically in a bundle's log tail whichever leg refused it.
//!
//! - [`classify`] reads one frame into a [`Segment`] — the one parser, so
//!   every leg agrees on what a frame *is* before any of them answers it.
//! - [`refused_tcp_reset`] builds the reply a refusal writes (RFC 793 §3.4):
//!   the one shape, whether the refusing side is a relay leg answering a
//!   port nothing is published on or the stack peer refusing a SYN its
//!   pre-screen turned away.
//! - [`RefusalEmitter`] bounds and rates every refusal per source, renders
//!   the one audit line ([`Outcome::Emit`]), and — driven by its caller —
//!   says a window's final count at the window it belongs to when no
//!   further refusal comes to carry it on the next window's opening line.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Ethernet II header length in bytes.
const ETH_HDR: usize = 14;
/// The EtherType the classifier admits: IPv4 only.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number of TCP.
const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number of UDP.
const IPPROTO_UDP: u8 = 17;

/// The TCP flag bits the classifier reads and the reset builder writes
/// (RFC 9293 §3.1). Exposed because a gate's *policy* is stated in their
/// terms — "a bare SYN", "a segment that is itself a reset" — and the
/// callers that state one should not re-derive the bits to check it.
pub const TCP_FIN: u8 = 0x01;
/// SYN: a connection's first packet, one sequence number of weight.
pub const TCP_SYN: u8 = 0x02;
/// RST: the reset itself.
pub const TCP_RST: u8 = 0x04;
/// ACK: an acknowledgement rides along.
pub const TCP_ACK: u8 = 0x10;

/// The L4 addressing and TCP control state of one IPv4 frame, as [`classify`]
/// extracts it: the source and destination `ip:port`, the protocol, and —
/// for TCP — the flags byte, the sequence/acknowledgement pair, and the
/// payload length the reply's acknowledgement must count (RFC 793 §3.4: a
/// reply acknowledges everything the segment carried, data included).
/// `tcp_flags`, `seq`, `ack` and `payload_len` are `0` for UDP, which no
/// reply here is built for yet.
///
/// The one shape every leg reads a frame into, so a segment a gate parsed
/// means the same thing on every leg that refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Source `ip:port`.
    pub src: SocketAddrV4,
    /// Destination `ip:port`.
    pub dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub proto: u8,
    /// TCP flags byte; `0` for UDP.
    pub tcp_flags: u8,
    /// TCP sequence number; `0` for UDP.
    pub seq: u32,
    /// TCP acknowledgement number; `0` for UDP and for a segment with no
    /// ACK set, where the sender leaves the field unspecified.
    pub ack: u32,
    /// The TCP payload's length in bytes: the IPv4 total length less both
    /// headers, bounded by the bytes the frame actually carries, so a
    /// length a hostile frame lies about buys no acknowledgement for bytes
    /// it never sent. `0` for UDP.
    pub payload_len: u16,
}

impl Segment {
    /// Whether this is a TCP segment.
    pub fn is_tcp(&self) -> bool {
        self.proto == IPPROTO_TCP
    }

    /// Whether this is a UDP datagram.
    pub fn is_udp(&self) -> bool {
        self.proto == IPPROTO_UDP
    }

    /// Whether the segment is itself a reset — the one segment every
    /// refusal answers with *nothing* (RFC 793 §3.4, RFC 9293 §3.5.2: a
    /// reset answered with a reset is the loop that never ends, and an
    /// ended connection's stragglers are exactly resets, ACKs and FINs).
    pub fn carries_reset(&self) -> bool {
        self.is_tcp() && self.tcp_flags & TCP_RST != 0
    }

    /// Whether the segment carries an ACK — established or teardown traffic.
    pub fn carries_ack(&self) -> bool {
        self.is_tcp() && self.tcp_flags & TCP_ACK != 0
    }

    /// Whether the segment is a bare SYN — a connection's first packet, SYN
    /// set and ACK clear. A SYN-ACK, established traffic and teardown all
    /// carry ACK and are not this.
    pub fn is_bare_syn(&self) -> bool {
        self.is_tcp() && self.tcp_flags & TCP_SYN != 0 && self.tcp_flags & TCP_ACK == 0
    }

    /// Whether the segment is a *first packet* — a connection the refusing
    /// side holds no state for: a bare TCP SYN, or any UDP datagram, which
    /// has no handshake and so is every datagram a first one. This is the
    /// predicate a stateless refusal turns on; the segments that answer it
    /// (`carries_reset`, `carries_ack`) are the ones it must not.
    pub fn is_first_packet(&self) -> bool {
        self.is_bare_syn() || self.is_udp()
    }
}

/// Parses an Ethernet II + IPv4 + TCP/UDP frame into its [`Segment`], or
/// `None` for non-IPv4 (ARP/IPv6/VLAN), non-TCP/UDP, IP fragments, and
/// short or malformed frames. Length-checked at every step and
/// allocation-free, so a truncated or hostile frame yields `None` rather
/// than an out-of-bounds read. The one parser: a leg that classifies with
/// this knows what the frame carries, and a leg that does not has no
/// business refusing it.
pub fn classify(frame: &[u8]) -> Option<Segment> {
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
    // A non-zero fragment offset (low 13 bits of bytes 6–7) is a later
    // fragment with no L4 header at `ihl`; refuse rather than misparse.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
        return None;
    }
    let l4 = &ip[ihl..];
    // TCP needs through the flags byte (offset 13); UDP only its 8-byte
    // header. Both carry src/dst ports in the first four bytes.
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
    // The payload a reply must acknowledge: what the IPv4 total length
    // vouches for less both headers, bounded by the bytes the frame
    // actually carries past them — a total length that overstates its
    // frame buys no acknowledgement for bytes that never arrived, and one
    // that understates it loses the tail it did send.
    let payload_len = if proto == IPPROTO_TCP {
        // The TCP data offset (high nibble of byte 12) is the header's
        // own length in 32-bit words.
        let data_offset = ((l4[12] >> 4) as usize) * 4;
        let claimed = (u16::from_be_bytes([ip[2], ip[3]]) as usize)
            .saturating_sub(ihl)
            .saturating_sub(data_offset);
        let present = ip.len().saturating_sub(ihl).saturating_sub(data_offset);
        claimed.min(present)
    } else {
        0
    };
    Some(Segment {
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
        payload_len: u16::try_from(payload_len).unwrap_or(u16::MAX),
    })
}

/// The ones' complement sum of `bytes` as 16-bit big-endian words (RFC 1071):
/// the accumulator widened so the carries survive to be folded back in.
pub fn ones_sum(bytes: &[u8]) -> u32 {
    let sum: u32 = bytes
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    // A trailing odd byte counts as the high half of a final word.
    if let Some(tail) = bytes.chunks_exact(2).remainder().first() {
        sum + (u32::from(*tail) << 8)
    } else {
        sum
    }
}

/// Folds a ones' complement `sum` into the 16-bit checksum that carries it:
/// the carries added back in, then the complement.
pub fn ones_complement(sum: u32) -> u16 {
    let mut sum = sum;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 header checksum of `header` (a whole header, the checksum field
/// zeroed). Every kernel on the path verifies it, so a frame the builders
/// here synthesize must carry an honest one.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    ones_complement(ones_sum(header))
}

/// The TCP checksum of `segment` carried from `src` to `dst`: the IPv4
/// pseudo-header (source, destination, protocol, TCP length) folded into
/// the segment's own ones' complement sum. Unlike UDP, TCP has no
/// zero-checksum option, and both ends of a reset verify it — the refused
/// peer's kernel on the way in, the switch's stack on the way out — so the
/// frames must carry an honest one.
pub fn tcp_checksum(segment: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
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

/// The acknowledgement a reply to a segment of `payload_len` bytes at `seq`
/// with `flags` gives: everything the segment carried plus the SYN and FIN
/// flags' sequence weight (each consumes one sequence number, RFC 793 §2.7).
/// Wrapping, because sequence numbers live on a circle.
pub fn seq_acknowledging(seq: u32, payload_len: u16, flags: u8) -> u32 {
    seq.wrapping_add(u32::from(payload_len))
        .wrapping_add(u32::from(flags & TCP_SYN != 0))
        .wrapping_add(u32::from(flags & TCP_FIN != 0))
}

/// Assembles the Ethernet + IPv4 + TCP reset every caller writes: from
/// `src` — the refusing address — back to `dst`, the refused connection's
/// peer, with the reply's link addresses handed in directly (`eth_dst` is
/// the reset's destination MAC, the peer's). The only place reset bytes are
/// laid out, so a reset's shape has one definition across the daemon's
/// relay legs and the box egress proxy's stack peer.
///
/// `acknowledges` picks the flag byte RFC 793 §3.4 pairs with the numbers:
/// a reply that acknowledges the refused segment carries RST|ACK; a reply
/// riding the segment's own acknowledgement number carries RST alone.
pub fn tcp_reset_frame(
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    acknowledges: bool,
) -> Vec<u8> {
    const TCP_HDR: usize = 20;
    const RST_ACK: u8 = TCP_RST | TCP_ACK;
    let mut frame = Vec::with_capacity(ETH_HDR + 2 * TCP_HDR);
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&eth_src);
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // IPv4, IHL 5: the refusing address as the source, the refused
    // connection's peer as the destination; the checksum covers the header
    // the peer's kernel verifies.
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&((2 * TCP_HDR) as u16).to_be_bytes());
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
    tcp[13] = if acknowledges { RST_ACK } else { TCP_RST };
    let checksum = tcp_checksum(&tcp, *src.ip(), *dst.ip());
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&tcp);
    frame
}

/// The reset that refuses one TCP `segment` carried in `frame` (RFC 793
/// §3.4), written from `leg_mac` — the refusing link's own MAC, never one
/// read off the frame it refuses. A SYN a pre-screen rules on names the leg
/// in its IP destination, but its Ethernet destination does not have to
/// agree: a SYN sent to the broadcast reaches the leg too, and a reset
/// whose *source* is the broadcast's MAC is a frame no switch would
/// forward. The reset is still addressed to the segment's own source MAC,
/// so a refusal can never be steered at a third party.
///
/// `None` — nothing written — for a frame too short to carry both Ethernet
/// addresses, and for a segment that is itself a reset, the one exchange
/// RFC 793 forbids outright.
///
/// The two shapes, taken from the observed segment alone — never from
/// numbers a gate holds nothing for:
///
/// - a segment that carries an ACK is answered with its own acknowledgement
///   as the reset's sequence and **RST alone**: the peer's ACK is the one
///   sequence number it has already vouched for, so the reset lands
///   in-window for a connection that exists.
/// - any other segment — a bare SYN in practice, the one shape a stateless
///   gate refuses — is answered from sequence zero with **RST|ACK**,
///   acknowledging it: the segment's own sequence, plus the data it
///   carried, plus one (RFC 793 §3.4 counts both, and a client that opened
///   with its whole question must not read the refusal as a hole in it). A
///   connecting peer's half-open socket reads that pair as the
///   connection-refused it is, the same answer a kernel gives a SYN nobody
///   listens for.
pub fn refused_tcp_reset_from(
    leg_mac: [u8; 6],
    frame: &[u8],
    segment: &Segment,
) -> Option<Vec<u8>> {
    if segment.carries_reset() {
        return None;
    }
    let (_, rest) = frame.split_first_chunk::<6>()?;
    let (peer_mac, _) = rest.split_first_chunk::<6>()?;
    let (seq, ack, acknowledges) = if segment.carries_ack() {
        (segment.ack, 0, false)
    } else {
        // The data the segment carried counts in what its acknowledgement
        // covers, alongside the SYN's own one sequence number of weight,
        // which [`seq_acknowledging`] adds.
        (
            0,
            seq_acknowledging(segment.seq, segment.payload_len, segment.tcp_flags),
            true,
        )
    };
    Some(tcp_reset_frame(
        *peer_mac,
        leg_mac,
        segment.dst,
        segment.src,
        seq,
        ack,
        acknowledges,
    ))
}

/// The relay legs' shape of [`refused_tcp_reset_from`]: the frame arrived
/// addressed to the refusing box — the switch steers a segment to it by
/// addressing it there — so the MAC the frame arrived at is the box's own,
/// and the one the reset is written from.
pub fn refused_tcp_reset(frame: &[u8], segment: &Segment) -> Option<Vec<u8>> {
    let (leg_mac, _) = frame.split_first_chunk::<6>()?;
    refused_tcp_reset_from(*leg_mac, frame, segment)
}

/// Rule text for a segment to a port the target's declaration does not
/// publish (NET-014): no listener is mapped to the port.
pub const NO_INGRESS_MAPPING_RULE: &str = "no ingress mapping";

/// Rule text for a segment to a port whose published ingress was revoked
/// (NET-121).
pub const REVOKED_INGRESS_PORT_RULE: &str = "revoked ingress port";

/// Rule text for the box egress proxy's pre-screen refusing a connection from
/// a source no registered row holds (NET-134): no row, no share, no socket.
pub const NO_REGISTERED_ROW_RULE: &str = "no registered row";

/// Rule text for the box egress proxy's pre-screen refusing a connection
/// whose frame's source MAC is not the address's switch-derived MAC — the
/// host-side leg of the same anti-spoof line the switch's static leases hold.
pub const FOREIGN_SOURCE_MAC_RULE: &str = "foreign source mac";

/// Rule text for the box egress proxy's pre-screen refusing a connection from
/// a source already holding its share's cap of the listener pool.
pub const SHARE_SPENT_RULE: &str = "per-source share spent";

/// Rule text for the box egress proxy's pool aborting an accepted
/// connection from a source whose box holds no attachment (NET-133): no
/// attachment, no delivery.
pub const NO_ATTACHMENT_RULE: &str = "no box attachment";

/// What a refusal answers for: the audit line's rule and its reason. A
/// `Copy` pair of `&'static str`s — the vocabulary is the codebase's rule
/// constants, which is also what bounds the emitter's overflow buckets
/// (keyed by rule alone) by construction: no refusal can grow them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    /// The rule the verdict matched, as the audit line names it.
    pub rule: &'static str,
    /// Why the rule refused, as the audit line names it.
    pub reason: &'static str,
}

/// A connection to a port the target publishes no listener for.
pub const UNPUBLISHED_PORT: Class = Class {
    rule: NO_INGRESS_MAPPING_RULE,
    reason: "no listener is published for the port",
};

/// A connection to a port whose published ingress was revoked (NET-121).
pub const REVOKED_PORT: Class = Class {
    rule: REVOKED_INGRESS_PORT_RULE,
    reason: "the port's published ingress was revoked",
};

/// A connection the box egress proxy's pre-screen refused because no
/// registered row holds its source: no row, no share, no socket.
pub const NO_REGISTERED_ROW: Class = Class {
    rule: NO_REGISTERED_ROW_RULE,
    reason: "the source's box has no registered row",
};

/// A connection the box egress proxy's pre-screen refused because its frame
/// arrived from a MAC the switch would never lease to the source address.
pub const FOREIGN_SOURCE_MAC: Class = Class {
    rule: FOREIGN_SOURCE_MAC_RULE,
    reason: "the source MAC is not the address's switch-derived MAC",
};

/// A connection the box egress proxy's pre-screen refused because its source
/// already holds its share's cap of the listener pool.
pub const SHARE_SPENT: Class = Class {
    rule: SHARE_SPENT_RULE,
    reason: "the source already holds its share of the pool",
};

/// An accepted connection the box egress proxy's pool aborted because its
/// source's box holds no attachment (NET-133): the row bought the share the
/// connection took, but nothing names the box to attribute a delivery to,
/// so nothing is presented from it.
pub const NO_ATTACHMENT: Class = Class {
    rule: NO_ATTACHMENT_RULE,
    reason: "the source's box holds no proxy attachment",
};

/// What the refused connection reached for, as the audit line names it: the
/// port it addressed, or — where the refusal is for a name the target
/// answered for rather than an address — the name itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum About {
    /// The destination port the refused connection addressed.
    Port(u16),
    /// The name the refused connection reached for.
    Name(String),
}

/// One refused connection, as the emitter records it and the audit line
/// names it: the class it was refused under, the source that was refused,
/// the address that refused it, and what it reached for.
pub struct Refusal {
    /// What the refusal answers for: its rule and reason.
    pub class: Class,
    /// The refused connection's source — the per-source bound's key, and
    /// the line's `source=`.
    pub source: Ipv4Addr,
    /// The address that refused the connection — the line's `address=`.
    pub address: Ipv4Addr,
    /// What the connection reached for: its port, or the name it was for.
    pub about: About,
}

/// What the emitter says about one refusal — write the reply or not, and
/// say the audit line or not.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Log `line`, and write the reply when the caller has one: the one
    /// audit line this window says for the source, at the window's first
    /// refusal — never one per reply. The count the line carries is the
    /// refusals counted since the last line said for the source: one for a
    /// source's first refusal, and at a window's roll the total the closed
    /// window saw, answered and suppressed alike.
    Emit(String),
    /// Write the reply, and say nothing: the middle of a source's window,
    /// where a line per reply would be the flood the rate exists to
    /// prevent.
    Quiet,
    /// Write nothing at all, and say nothing: the source has spent this
    /// window's quota, and the refusals it loses are its own — a sibling's
    /// are untouched.
    Suppressed,
}

/// How many per-(source, rule) rows the production emitter holds: enough
/// that every live box on a switch holds a row of its own, few enough that
/// the limiter's memory is bounded no matter how many sources refuse.
pub const REFUSAL_ROWS: usize = 512;

/// How many replies one source is written per window before it is
/// suppressed: a bound a well-behaved source's refused connections never
/// reach, and one a flood spends on itself.
pub const REFUSALS_PER_WINDOW: u32 = 16;

/// How long one window of the per-source quota lasts.
pub const REFUSAL_WINDOW: Duration = Duration::from_secs(1);

/// One window's counters — the state every row and every overflow bucket
/// holds a copy of, so both are accounted identically.
struct Window {
    /// When this window started.
    started: Instant,
    /// Replies written through this window — the quota's counter.
    written: u32,
    /// Refusals counted since the last line said through this window: the
    /// running total its line reports, kept across the roll so the next
    /// window's opening line carries the closed one's real count — and
    /// cleared with it by the flushes ([`RefusalEmitter::flush_expired`],
    /// [`RefusalEmitter::flush_pending`]), which say that same count at the
    /// window it belongs to when no further refusal comes to carry it, so
    /// no count is ever said twice.
    since_line: u32,
    /// Whether this window's line has been said: once, at the window's
    /// first refusal, and never per reply.
    said: bool,
    /// What a line this window owes at its end is said about, kept from the
    /// last refusal it counted. A window that ends holding a count no line
    /// has said still says it — at its own end, not borrowed by the next
    /// window's opening line — and this, with the count, is every field
    /// that line names.
    owed: Option<Owed>,
}

/// What a window's owed line is said about: every field the one audit line
/// names but the count, kept from the last refusal the window counted so a
/// line said at the window's end names a connection that actually reached
/// it — never one a closed window inherited.
struct Owed {
    /// The rule the verdict matched, and why it refused.
    class: Class,
    /// The refused connection's source — the line's `source=`.
    source: Ipv4Addr,
    /// The address that refused the connection — the line's `address=`.
    address: Ipv4Addr,
    /// What the connection reached for: its port, or the name it was for.
    about: About,
}

/// One per-(source, rule) limiter row: the replies this window has been
/// written to one source under one rule. A source that refuses under two
/// rules holds two rows — a rule-specific flood spends neither rule's row
/// for the other.
struct Row {
    /// The row's identity: the refused source and the rule it was refused
    /// under.
    key: (Ipv4Addr, &'static str),
    /// The row's window.
    window: Window,
    /// The row's recency, updated on every refusal — the eviction order
    /// among rows whose windows have expired.
    last: Instant,
}

/// The bucket a refusal collapses into when no row holds its source and no
/// expired row can be evicted for it: keyed by rule alone, one window and
/// one quota shared by every source it holds, with each refusal's own
/// source named in whatever line it says.
struct Overflow {
    /// The bucket's window.
    window: Window,
}

/// The limiter's state under one lock: the rows and the overflow buckets.
struct Limiter {
    /// The per-(source, rule) rows — never longer than the emitter's `rows`
    /// bound, the fixed size of the key space.
    rows: Vec<Row>,
    /// One bucket per rule for the sources no row holds.
    overflow: HashMap<&'static str, Overflow>,
    /// Lines evicted rows owed before a new source took their place: counts
    /// no line has said, held for the flushes to drain. Bounded by the
    /// emitter's own `rows`, at which bound the newest line is the one
    /// dropped — an emitter no caller flushes cannot grow it without end,
    /// and one a caller does still writes the oldest first.
    owed: Vec<String>,
}

/// The bounded, rate-limited refusal audit every refusal goes through —
/// the stack peer's as much as the relay's.
///
/// Two bounds, one per axis:
///
/// - **per source** ([`REFUSALS_PER_WINDOW`] per [`REFUSAL_WINDOW`]): each
///   (source, rule) row is its own quota, so a box that floods refusals
///   spends its own and degrades to a timeout; no sibling's row, and no
///   shared channel a single box can fill, is ever touched.
/// - **per key space** ([`REFUSAL_ROWS`] rows, [`new`]'s `rows` argument):
///   the row table is fixed-size. A new (source, rule) takes a free slot,
///   then the least-recently-used row *whose window has already expired* —
///   never a live one, or a flood of distinct sources would take live
///   siblings' rows one by one. When every row is live, the refusal
///   collapses into one bucket keyed by rule alone, with the source in the
///   line: the last pressure valve, and the only refusals a flood can spend
///   for anybody.
///
/// The lines it says are the one audit format ([`Self::refuse`]'s
/// [`Outcome::Emit`]): one rate-limited warn per (source, rule) per window,
/// said at the window's first refusal and carrying the refusals that window
/// has seen from the source — never one per reply. A window's count reaches
/// its line one of two ways: the next window's opening line carries it when
/// a further refusal comes, and when none does, [`Self::flush_expired`]
/// says it at the window it belongs to — so a source that refuses through a
/// window and then falls silent still has that window's count said, and the
/// last window's count is never lost to the silence that ended it. The
/// caller drives both flushes; the emitter is bytes and arithmetic, and
/// says nothing itself ([`Self::flush_pending`] is the teardown half, for
/// the emitter's own drop).
pub struct RefusalEmitter {
    state: Mutex<Limiter>,
    rows: usize,
    per_window: u32,
    window: Duration,
}

impl RefusalEmitter {
    /// An emitter holding `rows` per-(source, rule) rows, writing at most
    /// `per_window` replies per source per `window`.
    pub fn new(rows: usize, per_window: u32, window: Duration) -> Self {
        Self {
            state: Mutex::new(Limiter {
                rows: Vec::new(),
                overflow: HashMap::new(),
                owed: Vec::new(),
            }),
            rows,
            per_window,
            window,
        }
    }

    /// Records one refusal at `now` and decides what the caller writes and
    /// says. Callers pass `Instant::now()`; tests pass what they like — the
    /// window is the emitter's arithmetic, not the clock's.
    ///
    /// `answered` says whether the refusing side has a reply to write for
    /// this one: a reset for a first packet, nothing for a segment no
    /// honest builder answers — a spoofed ACK no held flow matches. An
    /// unanswered refusal still counts toward its window and still says its
    /// line, but spends none of the source's reply quota: no source can
    /// spend another's refusals, and the log is never bought with resets a
    /// lie manufactured.
    pub fn refuse(&self, refusal: &Refusal, answered: bool, now: Instant) -> Outcome {
        let mut limiter = self.state.lock().expect("refusal emitter lock poisoned");
        let rule = refusal.class.rule;
        // The row this source holds under this rule.
        if let Some(row) = limiter
            .rows
            .iter_mut()
            .find(|row| row.key == (refusal.source, rule))
        {
            row.last = now;
            return self.account(&mut row.window, refusal, answered, now);
        }
        // No row: a free slot first, then the least-recently-used row whose
        // window has already expired. A row whose window is still live is
        // never evicted.
        let slot = if limiter.rows.len() < self.rows {
            limiter.rows.push(Row {
                key: (refusal.source, rule),
                window: Window {
                    started: now,
                    written: 0,
                    since_line: 0,
                    said: false,
                    owed: None,
                },
                last: now,
            });
            limiter.rows.last_mut().expect("the row was just pushed")
        } else if let Some(index) = expired_lru_index(&limiter.rows, now, self.window) {
            // The row this refusal takes may still owe a line — a count no
            // line has said, stranded if the row simply goes. Hold it for
            // the flushes to drain, bounded like the rows themselves.
            if let Some(line) = self.take_owed(&mut limiter.rows[index].window) {
                self.hold(&mut limiter, line);
            }
            limiter.rows[index] = Row {
                key: (refusal.source, rule),
                window: Window {
                    started: now,
                    written: 0,
                    since_line: 0,
                    said: false,
                    owed: None,
                },
                last: now,
            };
            &mut limiter.rows[index]
        } else {
            // The table is full of live rows: collapse into the rule's
            // bucket, with this refusal's source in whatever line it says.
            let bucket = limiter.overflow.entry(rule).or_insert(Overflow {
                window: Window {
                    started: now,
                    written: 0,
                    since_line: 0,
                    said: false,
                    owed: None,
                },
            });
            return self.account(&mut bucket.window, refusal, answered, now);
        };
        self.account(&mut slot.window, refusal, answered, now)
    }

    /// Charges one refusal against one window and decides what the caller
    /// says: the window's first refusal says its line — carrying the
    /// refusals counted since the last line said through the window, the
    /// closed window's total when it rolls — the rest of the window writes
    /// quietly while the source's quota has room, and past the quota
    /// nothing is written at all. An unanswered refusal counts and says,
    /// but spends none of the quota.
    fn account(
        &self,
        window: &mut Window,
        refusal: &Refusal,
        answered: bool,
        now: Instant,
    ) -> Outcome {
        if now.saturating_duration_since(window.started) >= self.window {
            window.started = now;
            window.written = 0;
            window.said = false;
            // The closed window's count rides the line this refusal says —
            // rendered from this refusal, below — so what it was said about
            // goes with it: the new window owes nothing yet.
            window.owed = None;
        }
        // What a line this window owes at its end is said about: this
        // refusal, the last one counted through it.
        window.owed = Some(Owed {
            class: refusal.class,
            source: refusal.source,
            address: refusal.address,
            about: refusal.about.clone(),
        });
        // The window's one line, at its first refusal. The count it carries
        // is every refusal counted since the last line — which, because
        // every window opens with one, is the closed window's total when
        // the window has rolled, and one for a window that opens fresh.
        if !window.said {
            window.said = true;
            let refusals = window.since_line + 1;
            window.since_line = 0;
            let line = self.line(refusal, refusals);
            if answered && window.written < self.per_window {
                window.written += 1;
            }
            return Outcome::Emit(line);
        }
        // The rest of the window counts toward the next line, and writes
        // quietly while the quota has room.
        window.since_line += 1;
        if !answered {
            return Outcome::Quiet;
        }
        if window.written >= self.per_window {
            return Outcome::Suppressed;
        }
        window.written += 1;
        Outcome::Quiet
    }

    /// Renders the one audit line every leg's log tail carries: the rule
    /// the verdict matched, the address that refused, what the connection
    /// reached for — its port, or the name it was for — the reason, the
    /// refused source, and the count of refusals that source's window has
    /// seen.
    fn line(&self, refusal: &Refusal, refusals: u32) -> String {
        format!(
            "rule_matched=\"{rule}\" address={address} {about} reason=\"{reason}\" source={source} refusals={refusals}",
            rule = refusal.class.rule,
            address = refusal.address,
            about = match &refusal.about {
                About::Port(port) => format!("port={port}"),
                About::Name(name) => format!("name=\"{name}\""),
            },
            reason = refusal.class.reason,
            source = refusal.source,
        )
    }

    /// The limiter's state, poison-tolerated: a flush says a line, it never
    /// refuses a connection, so a lock another thread's panic poisoned is
    /// drained rather than propagated — a flush at teardown must not take
    /// the teardown with it.
    fn limiter(&self) -> MutexGuard<'_, Limiter> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Takes the line a window owes when it ends holding a count no line
    /// has said — the count its next line would carry, said at the window it
    /// belongs to, in the one audit format — clearing the count with the
    /// line so it can never be said twice. `None` while the window holds
    /// nothing unsaid, and for a window whose every refusal its opening line
    /// already said.
    fn take_owed(&self, window: &mut Window) -> Option<String> {
        if window.since_line == 0 {
            return None;
        }
        let count = window.since_line + 1;
        window.since_line = 0;
        let owed = window.owed.take()?;
        let refusal = Refusal {
            class: owed.class,
            source: owed.source,
            address: owed.address,
            about: owed.about,
        };
        Some(self.line(&refusal, count))
    }

    /// Holds one line an evicted row owed, at the bound the rows themselves
    /// carry: the newest is dropped at the cap, so the oldest — the line a
    /// drain would write first — is the one that survives.
    fn hold(&self, limiter: &mut Limiter, line: String) {
        if limiter.owed.len() < self.rows {
            limiter.owed.push(line);
        }
    }

    /// Takes every line the limiter's windows owe: the eviction queue drained
    /// first, so a count a row owed before its eviction is said before the
    /// ones the still-standing rows hold. `expired_at` is [`Some`] for the
    /// expiry flush, which says only a window whose time is out — the count
    /// belongs to the window that ended, and a live one may still say its
    /// own — and [`None`] for teardown, which says every count it holds,
    /// live window or not, because nothing after it exists to carry one.
    fn drain(&self, limiter: &mut Limiter, expired_at: Option<Instant>) -> Vec<String> {
        let mut lines = std::mem::take(&mut limiter.owed);
        let windows = limiter.rows.iter_mut().map(|row| &mut row.window).chain(
            limiter
                .overflow
                .values_mut()
                .map(|bucket| &mut bucket.window),
        );
        for window in windows {
            if expired_at
                .is_some_and(|now| now.saturating_duration_since(window.started) < self.window)
            {
                continue;
            }
            if let Some(line) = self.take_owed(window) {
                lines.push(line);
            }
        }
        lines
    }

    /// The lines windows that ended holding a count no line has said now
    /// owe, taken for the caller to write: every row and every overflow
    /// bucket whose window has expired at `now`, plus whatever evictions
    /// queued since the last flush. This is the one that keeps the last
    /// window's count from being lost to the silence that ended it — the
    /// count a further refusal would have carried on the next window's
    /// opening line, said once at the window it belongs to instead. The
    /// caller drives it; the emitter says nothing itself. A caller calls it
    /// before every refusal, so a rolled window's own count is said rather
    /// than folded into the next window's opening line, and a caller with a
    /// cadence of its own — the stack peer's turn — calls it there too, so
    /// a source that stops flooding does not need to send one more refusal
    /// to have its last window's count said.
    pub fn flush_expired(&self, now: Instant) -> Vec<String> {
        let mut limiter = self.limiter();
        self.drain(&mut limiter, Some(now))
    }

    /// Every line any window still holds unsaid, live or ended: the teardown
    /// flush. An emitter going away says every count it holds, because
    /// nothing after it exists to carry one — the count a closed session's
    /// gate was still holding would otherwise be the audit's one silent
    /// loss, dropped with the gate that counted it.
    pub fn flush_pending(&self) -> Vec<String> {
        let mut limiter = self.limiter();
        self.drain(&mut limiter, None)
    }
}

impl Default for RefusalEmitter {
    /// The production emitter: [`REFUSAL_ROWS`] rows, [`REFUSALS_PER_WINDOW`]
    /// replies per source per [`REFUSAL_WINDOW`].
    fn default() -> Self {
        Self::new(REFUSAL_ROWS, REFUSALS_PER_WINDOW, REFUSAL_WINDOW)
    }
}

/// The index of the least-recently-used row whose window has expired, if any
/// has. Expired rows hold a window that has already rolled — evicting one
/// loses a source nothing it still counts on.
fn expired_lru_index(rows: &[Row], now: Instant, window: Duration) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| now.saturating_duration_since(row.window.started) >= window)
        .min_by_key(|(_, row)| row.last)
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
    const OTHER_PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 6);

    /// The MAC each test address carries on the switch: the crate's own
    /// derivation, so the frames the builders answer look like the ones the
    /// switch segment carries.
    fn mac_of(ip: Ipv4Addr) -> [u8; 6] {
        crate::MacAddr::for_switch_ip(ip).0
    }

    /// An Ethernet II + IPv4 (IHL 5, honest checksum) + L4 frame.
    fn eth_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETH_HDR + 20 + l4.len());
        frame.extend_from_slice(&mac_of(dst));
        frame.extend_from_slice(&mac_of(src));
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&(20 + l4.len() as u16).to_be_bytes());
        header[8] = 64;
        header[9] = proto;
        header[12..16].copy_from_slice(&src.octets());
        header[16..20].copy_from_slice(&dst.octets());
        let checksum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(l4);
        frame
    }

    /// A TCP segment with the flags, sequence and acknowledgement the
    /// refusal builders read, over an honest pseudo-header checksum.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fields are exactly what the refusal builders read"
    )]
    fn tcp_segment(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = vec![0u8; 20 + payload.len()];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[20..].copy_from_slice(payload);
        let checksum = tcp_checksum(&tcp, src, dst);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        eth_ipv4(src, dst, IPPROTO_TCP, &tcp)
    }

    /// The RFC 1071 checksum of `bytes`, written from the definition rather
    /// than the builder's helper, so a wrong checksum in a built frame is
    /// caught by construction.
    fn rfc1071(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .chunks_exact(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        if let Some(tail) = bytes.chunks_exact(2).remainder().first() {
            sum += u32::from(*tail) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Asserts a frame's IPv4 header and TCP segment carry checksums the
    /// wire definition verifies, recomputed from the RFC texts rather than
    /// the builders' own helpers.
    fn assert_checksums_verify_on_the_wire(frame: &[u8]) {
        assert_eq!(
            rfc1071(&frame[ETH_HDR..ETH_HDR + 20]),
            0,
            "the IPv4 header checksum must verify"
        );
        let src = &frame[ETH_HDR + 12..ETH_HDR + 16];
        let dst = &frame[ETH_HDR + 16..ETH_HDR + 20];
        let segment = &frame[ETH_HDR + 20..];
        let mut covered = Vec::with_capacity(12 + segment.len());
        covered.extend_from_slice(src);
        covered.extend_from_slice(dst);
        covered.push(0);
        covered.push(IPPROTO_TCP);
        covered.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        covered.extend_from_slice(segment);
        assert_eq!(
            rfc1071(&covered),
            0,
            "the TCP checksum must verify on the wire"
        );
    }

    /// The TCP header of a frame the builders produce (Ethernet + 20-byte
    /// IPv4, the only shape they emit).
    fn tcp_of(frame: &[u8]) -> &[u8] {
        &frame[ETH_HDR + 20..]
    }

    #[test]
    fn refusal_rst_carries_rfc_seq_ack() {
        // A bare SYN is answered from sequence zero, acknowledging it, with
        // RST|ACK — the kernel's own connection-refused shape.
        let syn = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, 0, 0, &[]);
        let segment = classify(&syn).expect("a TCP frame classifies");
        assert!(segment.is_bare_syn());
        let reset = refused_tcp_reset(&syn, &segment).expect("a SYN is answered");
        // The reset travels to the SYN's own MAC and addresses: a refusal is
        // addressed to the peer it refuses, never steered at a third party.
        assert_eq!(&reset[0..6], &syn[6..12]);
        assert_eq!(&reset[6..12], &syn[0..6]);
        assert_eq!(
            &reset[ETH_HDR + 12..ETH_HDR + 16],
            LEASE.octets().as_slice()
        );
        assert_eq!(&reset[ETH_HDR + 16..ETH_HDR + 20], PEER.octets().as_slice());
        let tcp = tcp_of(&reset);
        assert_eq!(&tcp[0..2], 9999u16.to_be_bytes());
        assert_eq!(&tcp[2..4], 40000u16.to_be_bytes());
        assert_eq!(tcp[4..8], 0u32.to_be_bytes());
        assert_eq!(tcp[8..12], 1u32.to_be_bytes());
        assert_eq!(tcp[13], TCP_RST | TCP_ACK);
        assert_eq!(reset.len(), ETH_HDR + 40);
        assert_checksums_verify_on_the_wire(&reset);

        // The acknowledgement wraps: a SYN at the top of the sequence
        // circle is acknowledged by the circle's start.
        let syn = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, u32::MAX, 0, &[]);
        let segment = classify(&syn).expect("a TCP frame classifies");
        let reset = refused_tcp_reset(&syn, &segment).expect("a SYN is answered");
        assert_eq!(tcp_of(&reset)[8..12], 0u32.to_be_bytes());
        assert_checksums_verify_on_the_wire(&reset);

        // A segment carrying ACK is answered with its own acknowledgement as
        // the reset's sequence and RST alone: the one sequence number the
        // peer has already vouched for.
        let established = tcp_segment(PEER, LEASE, 40000, 9999, TCP_ACK, 5000, 7777, b"data");
        let segment = classify(&established).expect("a TCP frame classifies");
        assert!(!segment.is_bare_syn());
        let reset = refused_tcp_reset(&established, &segment).expect("an ACK is answered");
        let tcp = tcp_of(&reset);
        assert_eq!(tcp[4..8], 7777u32.to_be_bytes());
        assert_eq!(tcp[8..12], 0u32.to_be_bytes());
        assert_eq!(tcp[13], TCP_RST);
        assert_checksums_verify_on_the_wire(&reset);

        // A reset is never answered with a reset (RFC 793 §3.4, RFC 9293
        // §3.5.2) — and a frame too short to hand over both Ethernet
        // addresses is answered with nothing.
        let rst = tcp_segment(PEER, LEASE, 40000, 9999, TCP_RST | TCP_ACK, 1, 1, &[]);
        let segment = classify(&rst).expect("a TCP frame classifies");
        assert!(segment.carries_reset());
        assert_eq!(refused_tcp_reset(&rst, &segment), None);
        assert_eq!(refused_tcp_reset(&[], &segment), None);

        // A frame that does not classify is not a segment the builders
        // speak for.
        let arp = [0u8; 20];
        assert_eq!(classify(&arp), None);
    }

    #[test]
    fn refusal_rst_acks_a_syn_carrying_data() {
        // A SYN that carries data is acknowledged past the data (RFC 793
        // §3.4): a client that opened with its whole question must not read
        // the refusal as a hole in it.
        let syn = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, 1000, 0, b"0123456789");
        let segment = classify(&syn).expect("a TCP frame classifies");
        assert_eq!(segment.payload_len, 10);
        let reset = refused_tcp_reset(&syn, &segment).expect("a SYN is answered");
        let tcp = tcp_of(&reset);
        assert_eq!(tcp[13], TCP_RST | TCP_ACK);
        // The sequence plus the ten data bytes plus the SYN's own weight.
        assert_eq!(tcp[8..12], 1011u32.to_be_bytes());
        assert_checksums_verify_on_the_wire(&reset);

        // A total length that overstates its frame cannot buy a bigger
        // acknowledgement: the count is bounded by the bytes the frame
        // actually carries.
        let mut lie = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, 7000, 0, b"abcd");
        lie[ETH_HDR + 2..ETH_HDR + 4].copy_from_slice(&80u16.to_be_bytes());
        let segment = classify(&lie).expect("a TCP frame classifies");
        assert_eq!(segment.payload_len, 4);
        let reset = refused_tcp_reset(&lie, &segment).expect("a SYN is answered");
        assert_eq!(tcp_of(&reset)[8..12], 7005u32.to_be_bytes());
        assert_checksums_verify_on_the_wire(&reset);

        // A leg other than the link the frame was addressed to writes its
        // own MAC as the reset's source — the shape a pre-screen needs,
        // where the SYN may have been sent to the broadcast.
        let mut to_broadcast = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, 42, 0, b"");
        to_broadcast[0..6].copy_from_slice(&[0xff; 6]);
        let leg_mac = mac_of(LEASE);
        let segment = classify(&to_broadcast).expect("a TCP frame classifies");
        let reset =
            refused_tcp_reset_from(leg_mac, &to_broadcast, &segment).expect("a SYN is answered");
        assert_eq!(&reset[0..6], &to_broadcast[6..12]);
        assert_eq!(reset[6..12], leg_mac);
        assert_eq!(tcp_of(&reset)[8..12], 43u32.to_be_bytes());
        assert_checksums_verify_on_the_wire(&reset);
        // The relay legs' shape of the same builder writes from the MAC the
        // frame arrived addressed to — the box's own.
        let reset = refused_tcp_reset(&to_broadcast, &segment).expect("a SYN is answered");
        assert_eq!(&reset[6..12], &[0xff; 6]);
    }

    /// One refused SYN, for the emitter tests.
    fn refusal_from(source: Ipv4Addr) -> Refusal {
        Refusal {
            class: UNPUBLISHED_PORT,
            source,
            address: LEASE,
            about: About::Port(9999),
        }
    }

    #[test]
    fn refusal_emitter_is_bounded_and_rate_limited() {
        // A small emitter so the window arithmetic is legible: four replies
        // per source per 50ms window.
        let emitter = RefusalEmitter::new(8, 4, Duration::from_millis(50));
        let t0 = Instant::now();
        // The first refusal of a window says the line, with its count.
        match emitter.refuse(&refusal_from(PEER), true, t0) {
            Outcome::Emit(line) => {
                assert!(line.contains("rule_matched=\"no ingress mapping\""));
                assert!(line.contains("source=100.64.0.5"));
                assert!(line.ends_with("refusals=1"));
            }
            _ => panic!("the first refusal of a window says its line"),
        }
        // The rest of the window writes and says nothing: no line per
        // reply, not even for the reply that spends the quota.
        assert_eq!(
            emitter.refuse(&refusal_from(PEER), true, t0),
            Outcome::Quiet
        );
        assert_eq!(
            emitter.refuse(&refusal_from(PEER), true, t0),
            Outcome::Quiet
        );
        assert_eq!(
            emitter.refuse(&refusal_from(PEER), true, t0),
            Outcome::Quiet
        );
        // Past the quota: nothing written, nothing said — the flooder's own
        // refusals only.
        for _ in 0..10 {
            assert_eq!(
                emitter.refuse(&refusal_from(PEER), true, t0),
                Outcome::Suppressed
            );
        }
        // A sibling is untouched: its own row, its own quota, its own line.
        match emitter.refuse(&refusal_from(OTHER_PEER), true, t0) {
            Outcome::Emit(line) => {
                assert!(line.contains("source=100.64.0.6"));
                assert!(line.ends_with("refusals=1"));
            }
            _ => panic!("a sibling's first refusal says its own line"),
        }
        // Two rules are two rows: a source's flood under one rule spends
        // nothing of its quota under the other.
        let revoked = Refusal {
            class: REVOKED_PORT,
            ..refusal_from(PEER)
        };
        match emitter.refuse(&revoked, true, t0) {
            Outcome::Emit(line) => {
                assert!(line.contains("rule_matched=\"revoked ingress port\""))
            }
            _ => panic!("a second rule is a second row"),
        }
        // The window rolls and the spent source is answered again — and the
        // line the new window opens with reports what the closed one saw:
        // fourteen refusals, of which four were answered.
        let t1 = t0 + Duration::from_millis(60);
        match emitter.refuse(&refusal_from(PEER), true, t1) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=14")),
            _ => panic!("a rolled window answers the source again"),
        }
    }

    #[test]
    fn refusal_limiter_key_space_is_bounded() {
        // Two rows: the limiter's whole key space.
        let emitter = RefusalEmitter::new(2, 3, Duration::from_millis(50));
        let t0 = Instant::now();
        let a = Ipv4Addr::new(100, 64, 0, 1);
        let b = Ipv4Addr::new(100, 64, 0, 2);
        let c = Ipv4Addr::new(100, 64, 0, 3);
        let d = Ipv4Addr::new(100, 64, 0, 4);
        assert!(matches!(
            emitter.refuse(&refusal_from(a), true, t0),
            Outcome::Emit(_)
        ));
        assert!(matches!(
            emitter.refuse(&refusal_from(b), true, t0),
            Outcome::Emit(_)
        ));
        // The table is full and both rows are live: a third source collapses
        // into the rule's bucket — still answered, its own source in its
        // line.
        match emitter.refuse(&refusal_from(c), true, t0) {
            Outcome::Emit(line) => assert!(line.contains("source=100.64.0.3")),
            _ => panic!("a source no row holds collapses into the rule's bucket"),
        }
        // The bucket is keyed by rule alone, so its quota is shared: D's
        // refusals are the bucket's, and past its quota nothing is written.
        assert_eq!(emitter.refuse(&refusal_from(d), true, t0), Outcome::Quiet);
        assert_eq!(emitter.refuse(&refusal_from(d), true, t0), Outcome::Quiet);
        assert_eq!(
            emitter.refuse(&refusal_from(d), true, t0),
            Outcome::Suppressed
        );
        assert_eq!(
            emitter.refuse(&refusal_from(c), true, t0),
            Outcome::Suppressed
        );
        // The rows are untouched: A and B answer within quotas of their own.
        assert_eq!(emitter.refuse(&refusal_from(a), true, t0), Outcome::Quiet);
        assert_eq!(emitter.refuse(&refusal_from(b), true, t0), Outcome::Quiet);

        // The rows' windows expire. A's refusal at t1 makes A the most
        // recently used row, so the LRU — B's — is the one evicted for a new
        // source, which then holds a row of its own: evidenced by C's quota
        // being its own, not the bucket's.
        let t1 = t0 + Duration::from_millis(60);
        assert!(matches!(
            emitter.refuse(&refusal_from(a), true, t1),
            Outcome::Emit(_)
        ));
        assert!(matches!(
            emitter.refuse(&refusal_from(c), true, t1),
            Outcome::Emit(_)
        ));
        assert_eq!(emitter.refuse(&refusal_from(c), true, t1), Outcome::Quiet);
        assert_eq!(emitter.refuse(&refusal_from(c), true, t1), Outcome::Quiet);
        // B, evicted, collapses into the overflow bucket — whose window has
        // rolled too, so B is answered again, its own source in its line.
        match emitter.refuse(&refusal_from(b), true, t1) {
            Outcome::Emit(line) => assert!(line.contains("source=100.64.0.2")),
            _ => panic!("an evicted source is answered through the bucket"),
        }

        // A flood of distinct sources cannot grow the key space past its
        // bound: two rows and one bucket is everything it can be spent on,
        // so a window answers at most the rows' quotas plus the bucket's.
        let flood = RefusalEmitter::new(2, 3, Duration::from_millis(50));
        let mut answered = 0;
        let mut suppressed = 0;
        for last in 5u8..40 {
            match flood.refuse(&refusal_from(Ipv4Addr::new(100, 64, 0, last)), true, t0) {
                Outcome::Emit(_) | Outcome::Quiet => answered += 1,
                Outcome::Suppressed => suppressed += 1,
            }
        }
        assert_eq!(answered, 2 + 3);
        assert_eq!(suppressed, 30);
    }

    #[test]
    fn refusal_audit_line_names_rule_address_port_and_reason() {
        let emitter = RefusalEmitter::default();
        let line = match emitter.refuse(&refusal_from(PEER), true, Instant::now()) {
            Outcome::Emit(line) => line,
            _ => panic!("the first refusal of a window says its line"),
        };
        assert_eq!(
            line,
            "rule_matched=\"no ingress mapping\" address=100.64.0.9 port=9999 \
             reason=\"no listener is published for the port\" source=100.64.0.5 refusals=1"
        );
        // A refusal that is for a name the target answered for names the
        // name where a port-named refusal names its port.
        let named = Refusal {
            class: REVOKED_PORT,
            source: OTHER_PEER,
            address: LEASE,
            about: About::Name("web".to_owned()),
        };
        let line = match emitter.refuse(&named, true, Instant::now()) {
            Outcome::Emit(line) => line,
            _ => panic!("a new source's first refusal says its line"),
        };
        assert_eq!(
            line,
            "rule_matched=\"revoked ingress port\" address=100.64.0.9 name=\"web\" \
             reason=\"the port's published ingress was revoked\" source=100.64.0.6 refusals=1"
        );
    }

    #[test]
    fn refusal_line_carries_the_window_count() {
        // A window sized for the production quota: the count the line
        // carries must be the refusals the window saw, not the replies that
        // were written.
        let emitter = RefusalEmitter::new(8, REFUSALS_PER_WINDOW, Duration::from_millis(50));
        let t0 = Instant::now();
        // The window opens with one line, saying one.
        match emitter.refuse(&refusal_from(PEER), true, t0) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=1")),
            _ => panic!("the first refusal of a window says its line"),
        }
        // Thirty refusals more, from the same source, inside the same
        // window: the first fifteen are answered, the rest suppressed — and
        // none of them says another line.
        for _ in 0..30 {
            assert!(matches!(
                emitter.refuse(&refusal_from(PEER), true, t0),
                Outcome::Quiet | Outcome::Suppressed
            ));
        }
        // The next window opens with the real count: the thirty-one
        // refusals the closed window saw, not the sixteen replies it wrote.
        let t1 = t0 + Duration::from_millis(60);
        match emitter.refuse(&refusal_from(PEER), true, t1) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=31")),
            _ => panic!("the next window opens with the closed one's count"),
        }

        // A source whose refusals are never answered still counts: the
        // gate's spoofed-ACK refusals build no reset to write, and the line
        // the next window opens with reports them anyway — said once, at
        // the window's first refusal, suppressed never.
        for _ in 0..7 {
            assert!(matches!(
                emitter.refuse(&refusal_from(OTHER_PEER), false, t0),
                Outcome::Emit(_) | Outcome::Quiet
            ));
        }
        match emitter.refuse(
            &refusal_from(OTHER_PEER),
            false,
            t0 + Duration::from_millis(60),
        ) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=7")),
            _ => panic!("an unanswered refusal still counts in its window's line"),
        }
    }

    /// The final window's count, said when no further refusal comes to
    /// carry it ([`RefusalEmitter::flush_expired`]): a source refuses N
    /// times through one window, then falls silent past it, and the count
    /// the window holds — which a further refusal would have carried on the
    /// next window's opening line — is said once, in the one audit format,
    /// at the window it belongs to. The clock is the caller's, so the
    /// expiry is forced with arithmetic, never a sleep.
    #[test]
    fn refusal_final_window_count_emitted_on_expiry() {
        // Two rows and a 50ms window: small enough that the arithmetic is
        // legible, and one row's count is the only thing any flush can say.
        let emitter = RefusalEmitter::new(2, 4, Duration::from_millis(50));
        let t0 = Instant::now();
        // The window opens with its line, saying one...
        match emitter.refuse(&refusal_from(PEER), true, t0) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=1")),
            _ => panic!("the window's first refusal says its line"),
        }
        // ...and eight more count silently through it: nine refusals the
        // window saw, one line said — answered while the source's quota has
        // room, suppressed past it, saying nothing either way.
        for _ in 0..8 {
            assert!(matches!(
                emitter.refuse(&refusal_from(PEER), true, t0),
                Outcome::Quiet | Outcome::Suppressed
            ));
        }
        // Then silence, past the window — and the count is said: exactly
        // one line, reading the nine refusals the window counted, in the
        // one audit format every leg's log tail carries.
        let t1 = t0 + Duration::from_millis(60);
        let flushed = emitter.flush_expired(t1);
        assert_eq!(
            flushed.len(),
            1,
            "the one window that ended holding a count says its one line"
        );
        assert_eq!(
            flushed[0],
            "rule_matched=\"no ingress mapping\" address=100.64.0.9 port=9999 \
             reason=\"no listener is published for the port\" source=100.64.0.5 refusals=9"
        );
        // And once only: the flush cleared the count, so a further refusal
        // opens the next window with that window's own count, and no flush
        // after it says the closed window's again.
        assert!(
            emitter.flush_expired(t1).is_empty(),
            "the window's count is said once, never twice"
        );
        let t2 = t1 + Duration::from_millis(10);
        match emitter.refuse(&refusal_from(PEER), true, t2) {
            Outcome::Emit(line) => assert!(
                line.ends_with("refusals=1"),
                "the next window's opening line carries its own count: {line}"
            ),
            _ => panic!("a further refusal opens the next window with its own count"),
        }
        assert!(
            emitter.flush_pending().is_empty(),
            "and nothing after it still holds an unsaid count"
        );
    }

    /// A count an evicted row still owed is not lost with the row
    /// ([`RefusalEmitter::refuse`]'s eviction): the expired row a new source
    /// takes may hold refusals no line has said, and the line for them is
    /// held for the flush to drain — while a row that said everything it
    /// counted owes nothing, and its eviction is silent. The queue the
    /// evictions fill is bounded by the emitter's own rows, and the line
    /// the bound drops is the newest's.
    #[test]
    fn refusal_pending_count_emitted_on_eviction() {
        // Two rows — the limiter's whole key space — and a 50ms window.
        let emitter = RefusalEmitter::new(2, 4, Duration::from_millis(50));
        let t0 = Instant::now();
        let a = Ipv4Addr::new(100, 64, 0, 1);
        let b = Ipv4Addr::new(100, 64, 0, 2);
        let c = Ipv4Addr::new(100, 64, 0, 3);
        // A's window: its opening line, then four refusals no line has said
        // — a count the row will owe at its eviction.
        match emitter.refuse(&refusal_from(a), true, t0) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=1")),
            _ => panic!("A's window opens with its line"),
        }
        for _ in 0..4 {
            assert!(matches!(
                emitter.refuse(&refusal_from(a), true, t0),
                Outcome::Quiet | Outcome::Suppressed
            ));
        }
        // B's window, ten milliseconds later: one refusal, said by its
        // opening line — a clean row that will owe its eviction nothing.
        let t1 = t0 + Duration::from_millis(10);
        assert!(matches!(
            emitter.refuse(&refusal_from(b), true, t1),
            Outcome::Emit(_)
        ));
        // Past both windows, a new source takes the least recently used of
        // the two expired rows — A's, the older — and A's count is held for
        // the flush, not lost with the row. C's own line opens C's window.
        let t2 = t0 + Duration::from_millis(60);
        match emitter.refuse(&refusal_from(c), true, t2) {
            Outcome::Emit(line) => {
                assert!(line.contains("source=100.64.0.3"));
                assert!(line.ends_with("refusals=1"));
            }
            _ => panic!("the new source's refusal opens its own row's line"),
        }
        // The flush drains the eviction's line: A's five refusals, and
        // nothing beside it — B's window said everything it counted, and
        // B's and C's rows are still standing.
        let flushed = emitter.flush_expired(t2);
        assert_eq!(
            flushed.len(),
            1,
            "the evicted row's owed count, and the clean rows' nothing: {flushed:?}"
        );
        assert_eq!(
            flushed[0],
            "rule_matched=\"no ingress mapping\" address=100.64.0.9 port=9999 \
             reason=\"no listener is published for the port\" source=100.64.0.1 refusals=5"
        );
        assert!(
            emitter.flush_pending().is_empty(),
            "the owed count is said once, never twice"
        );

        // The queue evictions fill is bounded by the emitter's own rows,
        // and the line the bound drops is the newest's. One row — the whole
        // key space, so every new source past the window is an eviction.
        let flood = RefusalEmitter::new(1, 4, Duration::from_millis(50));
        let held = Ipv4Addr::new(100, 64, 0, 11);
        let dropped = Ipv4Addr::new(100, 64, 0, 12);
        let t = Instant::now();
        // Held's window: its opening line, then a second refusal no line has
        // said — the count its row will owe at its eviction.
        assert!(matches!(
            flood.refuse(&refusal_from(held), true, t),
            Outcome::Emit(_)
        ));
        assert_eq!(flood.refuse(&refusal_from(held), true, t), Outcome::Quiet);
        // Past held's window, dropped's refusal takes its row, and the
        // count held's window held is queued — one line, the queue's whole
        // bound.
        let t1 = t + Duration::from_millis(60);
        assert!(matches!(
            flood.refuse(&refusal_from(dropped), true, t1),
            Outcome::Emit(_)
        ));
        assert_eq!(
            flood.refuse(&refusal_from(dropped), true, t1),
            Outcome::Quiet
        );
        // Past dropped's, held's refusal takes its row the same way — and
        // the queue is full, so dropped's count is the one the bound drops:
        // the oldest line is the one a drain writes first.
        let t2 = t1 + Duration::from_millis(60);
        assert!(matches!(
            flood.refuse(&refusal_from(held), true, t2),
            Outcome::Emit(_)
        ));
        let drained = flood.flush_expired(t2);
        assert_eq!(
            drained.len(),
            1,
            "the queue's one bound, and the expiry's nothing beside it: {drained:?}"
        );
        assert!(
            drained[0].contains("source=100.64.0.11"),
            "the oldest line is the one the drain writes: {drained:?}"
        );
        assert!(
            drained
                .iter()
                .all(|line| !line.contains("source=100.64.0.12")),
            "the dropped row's count is the one the bound drops: {drained:?}"
        );
    }
}
