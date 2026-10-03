//! The one shape of a refused connection's answer (NET-014, NET-081).
//!
//! Four callers refuse connections — the daemon's switch relay, its
//! per-session gate, the VM host's egress gate, and the box egress proxy's
//! stack peer — and this module is the only place any of them builds the
//! reply or says the audit line. Everything here is bytes and arithmetic on
//! an arriving frame: the crate carries no runtime and no feature the rest
//! of the workspace must match, so the in-guest daemon and the host daemon
//! link the same definitions and a refusal shaped on one leg reads
//! identically in a bundle's log tail whichever leg refused it.
//!
//! - [`classify`] reads one frame into a [`Segment`] — the one parser, so
//!   every leg agrees on what a frame *is* before any of them answers it.
//! - [`refused_tcp_reset`] and [`refused_udp_port_unreachable`] build the
//!   two replies a refusal writes (RFC 793 §3.4; RFC 792 type 3 code 3).
//! - [`RefusalEmitter`] bounds and rates every refusal per source, and
//!   renders the one audit line ([`Outcome::Emit`]).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ethernet II header length in bytes.
const ETH_HDR: usize = 14;
/// The EtherType the classifier admits: IPv4 only.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number of ICMP.
const IPPROTO_ICMP: u8 = 1;
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
/// for TCP — the flags byte and the sequence/acknowledgement pair the reply
/// builders need. `tcp_flags`, `seq` and `ack` are `0` for UDP.
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
/// peer, with the observed frame's Ethernet addresses handed over swapped
/// (`eth_dst` is the reset's destination MAC, the peer's). The only place
/// reset bytes are laid out, so a reset's shape has one definition across
/// the daemon's relay, its gate, and the VM host's gate.
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

/// The reset that refuses one TCP `segment` carried in `frame`
/// (RFC 793 §3.4), addressed to the segment's source so a refusal can never
/// be steered at a third party. `None` — nothing written — for a frame too
/// short to carry both Ethernet addresses, and for a segment that is itself
/// a reset, the one exchange RFC 793 forbids outright.
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
///   acknowledging it: the segment's own sequence plus one. A connecting
///   peer's half-open socket reads that pair as the connection-refused it
///   is, the same answer a kernel gives a SYN nobody listens for.
pub fn refused_tcp_reset(frame: &[u8], segment: &Segment) -> Option<Vec<u8>> {
    if segment.carries_reset() {
        return None;
    }
    let (eth_dst, rest) = frame.split_first_chunk::<6>()?;
    let (eth_src, _) = rest.split_first_chunk::<6>()?;
    let (seq, ack, acknowledges) = if segment.carries_ack() {
        (segment.ack, 0, false)
    } else {
        // A bare SYN carries no payload worth counting: its one sequence
        // number of weight is the flag's own, which
        // [`seq_acknowledging`] adds.
        (0, seq_acknowledging(segment.seq, 0, segment.tcp_flags), true)
    };
    Some(tcp_reset_frame(
        *eth_src,
        *eth_dst,
        segment.dst,
        segment.src,
        seq,
        ack,
        acknowledges,
    ))
}

/// The ICMP port-unreachable that refuses one UDP `datagram` carried in
/// `frame` (RFC 792 type 3, code 3): from the refusing `segment.dst` back to
/// the datagram's source, quoting the datagram's own IPv4 header and the
/// first eight bytes of what follows it — the UDP header, which is what
/// tells the sender *which* datagram was refused. `None` — nothing written
/// — for a segment that is not UDP, and for a frame too short to carry both
/// Ethernet addresses.
pub fn refused_udp_port_unreachable(frame: &[u8], segment: &Segment) -> Option<Vec<u8>> {
    if !segment.is_udp() || frame.len() < ETH_HDR {
        return None;
    }
    let (eth_dst, rest) = frame.split_first_chunk::<6>()?;
    let (eth_src, _) = rest.split_first_chunk::<6>()?;
    // The quote: the datagram's own IPv4 header plus the first eight bytes
    // of its payload, bounded by what the frame actually carries — a
    // kernel quoting a truncated datagram truncates the quote the same way.
    let ihl = (frame[ETH_HDR] & 0x0f) as usize * 4;
    let quote_end = (ETH_HDR + ihl + 8).min(frame.len());
    let quote = &frame[ETH_HDR..quote_end];
    const ICMP_HDR: usize = 8;
    let mut icmp = vec![0u8; ICMP_HDR + quote.len()];
    icmp[0] = 3; // destination unreachable
    icmp[1] = 3; // port unreachable
    icmp[8..].copy_from_slice(quote);
    let checksum = ones_complement(ones_sum(&icmp));
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    // IPv4, IHL 5: the refusing address as the source, the datagram's
    // source as the destination.
    let total_len = u16::try_from(20 + icmp.len()).unwrap_or(u16::MAX);
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    header[8] = 64;
    header[9] = IPPROTO_ICMP;
    header[12..16].copy_from_slice(&segment.dst.ip().octets());
    header[16..20].copy_from_slice(&segment.src.ip().octets());
    let checksum = ipv4_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    let mut reply = Vec::with_capacity(ETH_HDR + 20 + icmp.len());
    // Handed over swapped, like the reset's: the reply travels to the
    // datagram's source MAC, from the MAC it was addressed to.
    reply.extend_from_slice(eth_src);
    reply.extend_from_slice(eth_dst);
    reply.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    reply.extend_from_slice(&header);
    reply.extend_from_slice(&icmp);
    Some(reply)
}

/// Rule text for a segment to a port the target's declaration does not
/// publish (NET-014): no listener is mapped to the port.
pub const NO_INGRESS_MAPPING_RULE: &str = "no ingress mapping";

/// Rule text for a segment to a port whose published ingress was revoked
/// (NET-121).
pub const REVOKED_INGRESS_PORT_RULE: &str = "revoked ingress port";

/// Rule text for a segment to the box egress proxy's address at a port no
/// socket of the peer's listens on.
pub const UNLISTENED_PROXY_PORT_RULE: &str = "unlistened proxy port";

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

/// A connection to the box egress proxy's address at a port no socket of
/// the peer's listens on.
pub const UNLISTENED_PROXY_PORT: Class = Class {
    rule: UNLISTENED_PROXY_PORT_RULE,
    reason: "no socket is listening on the port",
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
    /// Write the reply, and log `line`: the one audit line this window says
    /// for the source — the first refusal of the window, and the one that
    /// spends the source's quota — carrying the count of replies written to
    /// that source this window.
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

/// One per-(source, rule) limiter row: the replies this window has been
/// written to one source under one rule. A source that refuses under two
/// rules holds two rows — a rule-specific flood spends neither rule's row
/// for the other.
struct Row {
    /// The row's identity: the refused source and the rule it was refused
    /// under.
    key: (Ipv4Addr, &'static str),
    /// When this window started; `resets` counts from it.
    window_started: Instant,
    /// Replies written to the source this window.
    resets: u32,
    /// The row's recency, updated on every refusal — the eviction order
    /// among rows whose windows have expired.
    last: Instant,
}

/// The bucket a refusal collapses into when no row holds its source and no
/// expired row can be evicted for it: keyed by rule alone, one window and
/// one quota shared by every source it holds, with each refusal's own
/// source named in whatever line it says.
struct Overflow {
    /// When this window started; `resets` counts from it.
    window_started: Instant,
    /// Replies written through the bucket this window.
    resets: u32,
}

/// The limiter's state under one lock: the rows and the overflow buckets.
struct Limiter {
    /// The per-(source, rule) rows — never longer than the emitter's `rows`
    /// bound, the fixed size of the key space.
    rows: Vec<Row>,
    /// One bucket per rule for the sources no row holds.
    overflow: HashMap<&'static str, Overflow>,
}

/// The bounded, rate-limited refusal audit every refusal goes through —
/// the fourth caller's as much as the first's.
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
/// [`Outcome::Emit`]): a rate-limited warn per refusal class per source,
/// never one per reply.
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
            }),
            rows,
            per_window,
            window,
        }
    }

    /// Records one refusal at `now` and decides what the caller writes and
    /// says. Callers pass `Instant::now()`; tests pass what they like — the
    /// window is the emitter's arithmetic, not the clock's.
    pub fn refuse(&self, refusal: &Refusal, now: Instant) -> Outcome {
        let mut limiter = self.state.lock().expect("refusal emitter lock poisoned");
        let rule = refusal.class.rule;
        // The row this source holds under this rule.
        if let Some(row) = limiter
            .rows
            .iter_mut()
            .find(|row| row.key == (refusal.source, rule))
        {
            row.last = now;
            return self.account(&mut row.window_started, &mut row.resets, refusal, now);
        }
        // No row: a free slot first, then the least-recently-used row whose
        // window has already expired. A row whose window is still live is
        // never evicted.
        let slot = if limiter.rows.len() < self.rows {
            limiter.rows.push(Row {
                key: (refusal.source, rule),
                window_started: now,
                resets: 0,
                last: now,
            });
            limiter.rows.last_mut().expect("the row was just pushed")
        } else if let Some(index) = expired_lru_index(&limiter.rows, now, self.window) {
            limiter.rows[index] = Row {
                key: (refusal.source, rule),
                window_started: now,
                resets: 0,
                last: now,
            };
            &mut limiter.rows[index]
        } else {
            // The table is full of live rows: collapse into the rule's
            // bucket, with this refusal's source in whatever line it says.
            let bucket = limiter
                .overflow
                .entry(rule)
                .or_insert(Overflow {
                    window_started: now,
                    resets: 0,
                });
            return self.account(&mut bucket.window_started, &mut bucket.resets, refusal, now);
        };
        self.account(&mut slot.window_started, &mut slot.resets, refusal, now)
    }

    /// Charges one refusal against one window and decides what the caller
    /// says: the first reply of a window says its line, the one that spends
    /// the quota says its line, the middle says nothing, and past the quota
    /// nothing is written at all.
    fn account(
        &self,
        window_started: &mut Instant,
        resets: &mut u32,
        refusal: &Refusal,
        now: Instant,
    ) -> Outcome {
        if now.saturating_duration_since(*window_started) >= self.window {
            *window_started = now;
            *resets = 0;
        }
        if *resets >= self.per_window {
            return Outcome::Suppressed;
        }
        *resets += 1;
        if *resets == 1 || *resets == self.per_window {
            return Outcome::Emit(self.line(refusal, *resets));
        }
        Outcome::Quiet
    }

    /// Renders the one audit line every leg's log tail carries: the rule
    /// the verdict matched, the address that refused, what the connection
    /// reached for — its port, or the name it was for — the reason, the
    /// refused source, and the count of replies written to that source this
    /// window.
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
        .filter(|(_, row)| now.saturating_duration_since(row.window_started) >= window)
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

    /// A UDP datagram with the ports the port-unreachable quotes.
    fn udp_datagram(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut udp = vec![0u8; 8 + payload.len()];
        udp[0..2].copy_from_slice(&sport.to_be_bytes());
        udp[2..4].copy_from_slice(&dport.to_be_bytes());
        udp[4..6].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        eth_ipv4(src, dst, IPPROTO_UDP, &udp)
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
        assert_eq!(rfc1071(&frame[ETH_HDR..ETH_HDR + 20]), 0, "the IPv4 header checksum must verify");
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
        assert_eq!(rfc1071(&covered), 0, "the TCP checksum must verify on the wire");
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
        assert_eq!(&reset[ETH_HDR + 12..ETH_HDR + 16], LEASE.octets().as_slice());
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
    fn refusal_icmp_port_unreachable_quotes_the_datagram() {
        let payload: &[u8] = &[0xab; 64];
        let datagram = udp_datagram(PEER, LEASE, 40000, 9999, payload);
        let segment = classify(&datagram).expect("a UDP frame classifies");
        assert!(segment.is_udp());
        assert!(segment.is_first_packet());
        let reply = refused_udp_port_unreachable(&datagram, &segment)
            .expect("a datagram is answered");
        // Addressed back to the datagram's source, from the address that
        // refused it, with the observed addresses swapped.
        assert_eq!(&reply[0..6], &datagram[6..12]);
        assert_eq!(&reply[6..12], &datagram[0..6]);
        assert_eq!(reply[ETH_HDR + 9], IPPROTO_ICMP);
        assert_eq!(&reply[ETH_HDR + 12..ETH_HDR + 16], LEASE.octets().as_slice());
        assert_eq!(&reply[ETH_HDR + 16..ETH_HDR + 20], PEER.octets().as_slice());
        let icmp = &reply[ETH_HDR + 20..];
        // Destination unreachable, port unreachable — the datagram itself
        // says which listener was missing.
        assert_eq!(icmp[0], 3);
        assert_eq!(icmp[1], 3);
        assert_eq!(
            u16::from_be_bytes([reply[ETH_HDR + 2], reply[ETH_HDR + 3]]),
            (20 + icmp.len()) as u16
        );
        // The quote is the datagram's own IPv4 header plus the first eight
        // bytes of its payload — the UDP header, which names the refused
        // datagram — and nothing past them.
        let ihl = (datagram[ETH_HDR] & 0x0f) as usize * 4;
        assert_eq!(icmp.len(), 8 + ihl + 8);
        assert_eq!(&icmp[8..8 + ihl], &datagram[ETH_HDR..ETH_HDR + ihl]);
        assert_eq!(
            &icmp[8 + ihl..8 + ihl + 8],
            &datagram[ETH_HDR + ihl..ETH_HDR + ihl + 8]
        );
        assert!(!icmp.contains(&0xab));
        // The ICMP checksum covers the message the datagram's kernel
        // verifies.
        assert_eq!(rfc1071(icmp), 0, "the ICMP checksum must verify on the wire");
        assert_eq!(rfc1071(&reply[ETH_HDR..ETH_HDR + 20]), 0, "the IPv4 header checksum must verify");

        // A TCP segment is not answered with a port-unreachable, and a
        // frame too short for the quote's start is answered with nothing.
        let syn = tcp_segment(PEER, LEASE, 40000, 9999, TCP_SYN, 0, 0, &[]);
        let segment = classify(&syn).expect("a TCP frame classifies");
        assert_eq!(refused_udp_port_unreachable(&syn, &segment), None);
        assert_eq!(refused_udp_port_unreachable(&[], &segment), None);
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
        match emitter.refuse(&refusal_from(PEER), t0) {
            Outcome::Emit(line) => {
                assert!(line.contains("rule_matched=\"no ingress mapping\""));
                assert!(line.contains("source=100.64.0.5"));
                assert!(line.ends_with("refusals=1"));
            }
            _ => panic!("the first refusal of a window says its line"),
        }
        // The middle of the window writes and says nothing: no line per
        // reply.
        assert_eq!(emitter.refuse(&refusal_from(PEER), t0), Outcome::Quiet);
        assert_eq!(emitter.refuse(&refusal_from(PEER), t0), Outcome::Quiet);
        // The reply that spends the quota still writes, and says the count
        // it spent.
        match emitter.refuse(&refusal_from(PEER), t0) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=4")),
            _ => panic!("the refusal that spends the quota says its line"),
        }
        // Past the quota: nothing written, nothing said — the flooder's own
        // refusals only.
        for _ in 0..10 {
            assert_eq!(emitter.refuse(&refusal_from(PEER), t0), Outcome::Suppressed);
        }
        // A sibling is untouched: its own row, its own quota, its own line.
        match emitter.refuse(&refusal_from(OTHER_PEER), t0) {
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
        match emitter.refuse(&revoked, t0) {
            Outcome::Emit(line) => assert!(line.contains("rule_matched=\"revoked ingress port\"")),
            _ => panic!("a second rule is a second row"),
        }
        // The window rolls and the spent source is answered again.
        let t1 = t0 + Duration::from_millis(60);
        match emitter.refuse(&refusal_from(PEER), t1) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=1")),
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
        assert!(matches!(emitter.refuse(&refusal_from(a), t0), Outcome::Emit(_)));
        assert!(matches!(emitter.refuse(&refusal_from(b), t0), Outcome::Emit(_)));
        // The table is full and both rows are live: a third source collapses
        // into the rule's bucket — still answered, its own source in its
        // line.
        match emitter.refuse(&refusal_from(c), t0) {
            Outcome::Emit(line) => assert!(line.contains("source=100.64.0.3")),
            _ => panic!("a source no row holds collapses into the rule's bucket"),
        }
        // The bucket is keyed by rule alone, so its quota is shared: D's
        // refusals are the bucket's, and past its quota nothing is written.
        assert_eq!(emitter.refuse(&refusal_from(d), t0), Outcome::Quiet);
        match emitter.refuse(&refusal_from(d), t0) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=3")),
            _ => panic!("the refusal that spends the bucket's quota says its line"),
        }
        assert_eq!(emitter.refuse(&refusal_from(c), t0), Outcome::Suppressed);
        // The rows are untouched: A and B answer within quotas of their own.
        assert_eq!(emitter.refuse(&refusal_from(a), t0), Outcome::Quiet);
        assert_eq!(emitter.refuse(&refusal_from(b), t0), Outcome::Quiet);

        // The rows' windows expire. A's refusal at t1 makes A the most
        // recently used row, so the LRU — B's — is the one evicted for a new
        // source, which then holds a row of its own: evidenced by C's quota
        // being its own, not the bucket's.
        let t1 = t0 + Duration::from_millis(60);
        assert!(matches!(emitter.refuse(&refusal_from(a), t1), Outcome::Emit(_)));
        assert!(matches!(emitter.refuse(&refusal_from(c), t1), Outcome::Emit(_)));
        assert_eq!(emitter.refuse(&refusal_from(c), t1), Outcome::Quiet);
        match emitter.refuse(&refusal_from(c), t1) {
            Outcome::Emit(line) => assert!(line.ends_with("refusals=3")),
            _ => panic!("a row of C's own spends a quota of C's own"),
        }
        // B, evicted, collapses into the overflow bucket — whose window has
        // rolled too, so B is answered again, its own source in its line.
        match emitter.refuse(&refusal_from(b), t1) {
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
            match flood.refuse(&refusal_from(Ipv4Addr::new(100, 64, 0, last)), t0) {
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
        let line = match emitter.refuse(&refusal_from(PEER), Instant::now()) {
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
        let line = match emitter.refuse(&named, Instant::now()) {
            Outcome::Emit(line) => line,
            _ => panic!("a new source's first refusal says its line"),
        };
        assert_eq!(
            line,
            "rule_matched=\"revoked ingress port\" address=100.64.0.9 name=\"web\" \
             reason=\"the port's published ingress was revoked\" source=100.64.0.6 refusals=1"
        );
    }
}
