//! Frame facts: what one Ethernet II frame carries, read once.
//!
//! Layer 2 of the crate, a reader of bytes a guest chose. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! THEOREM P2: every fact [`parse_frame`] reports is a fact of
//! the IPv4 datagram (RFC 791) or the Ethernet/IPv4 ARP packet (RFC 826) a
//! receiver acts on. Bytes after the IPv4 total length are padding and are
//! never read. A port is reported only inside [`L4::Tcp`] and [`L4::Udp`].
//! Of any other frame it says only that it is neither: the reason it gives
//! for that is outside the theorem, and no decision reads it.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The Ethernet II header: destination, source, EtherType.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ETH_HDR: usize = 14;
/// An Ethernet/IPv4 ARP packet: 8 bytes fixed, two 6-byte and two 4-byte addresses.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const ARP_LEN: usize = 28;

#[cfg_attr(verus_keep_ghost, verus_verify)]
const ETHERTYPE_IPV4: u16 = 0x0800;
#[cfg_attr(verus_keep_ghost, verus_verify)]
const ETHERTYPE_ARP: u16 = 0x0806;
#[cfg_attr(verus_keep_ghost, verus_verify)]
const ETHERTYPE_VLAN: u16 = 0x8100;
#[cfg_attr(verus_keep_ghost, verus_verify)]
const ETHERTYPE_IPV6: u16 = 0x86dd;
#[cfg_attr(verus_keep_ghost, verus_verify)]
const IPPROTO_TCP: u8 = 6;
#[cfg_attr(verus_keep_ghost, verus_verify)]
const IPPROTO_UDP: u8 = 17;

/// Why a frame carries nothing the gate decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Reason {
    /// Shorter than the header its EtherType needs.
    Short,
    Ipv6,
    /// 802.1Q. A tagged IPv4 frame is not an IPv4 frame here.
    Vlan,
    OtherEtherType,
    /// ARP that is not Ethernet hardware, IPv4 protocol, 6 and 4 byte addresses.
    ArpShape,
    /// IPv4 EtherType with a version nibble other than 4.
    BadVersion,
    /// A header length below 20 bytes.
    BadHeaderLength,
    /// A total length shorter than the header or longer than the frame.
    BadTotalLength,
}

/// The transport facts of an IPv4 datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum L4 {
    /// A whole TCP header on a first fragment.
    Tcp {
        sport: u16,
        dport: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        /// Bytes after the TCP header and inside the total length.
        payload_len: u16,
    },
    /// A whole UDP header on a first fragment. `payload_len` is what this
    /// datagram or fragment carries after it.
    Udp {
        sport: u16,
        dport: u16,
        /// Where the UDP payload starts in the frame.
        payload_at: u16,
        payload_len: u16,
    },
    /// A first fragment of a protocol with no ports here (ICMP, GRE, anything else).
    NoPorts,
    /// A fragment that is not the first: no transport header at all.
    LaterFragment,
    /// TCP or UDP on a first fragment without a whole, well-formed header
    /// inside the total length.
    ShortHeader,
}

/// The facts of an IPv4 datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Ipv4Facts {
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub dscp: u8,
    /// The more-fragments flag. A first fragment with it set is not the whole datagram.
    pub more_fragments: bool,
    pub l4: L4,
}

/// What one frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Facts {
    /// An Ethernet/IPv4 ARP packet.
    Arp {
        eth_dst: [u8; 6],
        eth_src: [u8; 6],
        /// The sender hardware address inside the packet.
        sender_mac: [u8; 6],
        /// The sender protocol address.
        sender: u32,
    },
    V4(Ipv4Facts),
    Other(Reason),
}

#[cfg(verus_keep_ghost)]
verus! {

#[verifier::opaque]
pub open spec fn spec_be16(f: Seq<u8>, i: int) -> u16 {
    ((f[i] as u16) << 8) | (f[i + 1] as u16)
}

#[verifier::opaque]
pub open spec fn spec_be32(f: Seq<u8>, i: int) -> u32 {
    ((f[i] as u32) << 24) | ((f[i + 1] as u32) << 16) | ((f[i + 2] as u32) << 8) | (f[i + 3] as u32)
}

/// `m` is the six bytes of `f` starting at `i`.
pub open spec fn mac_at(m: [u8; 6], f: Seq<u8>, i: int) -> bool {
    &&& m@[0] == f[i]
    &&& m@[1] == f[i + 1]
    &&& m@[2] == f[i + 2]
    &&& m@[3] == f[i + 3]
    &&& m@[4] == f[i + 4]
    &&& m@[5] == f[i + 5]
}

pub open spec fn is_v4(r: Facts) -> bool {
    match r {
        Facts::V4(_) => true,
        _ => false,
    }
}

pub open spec fn is_arp(r: Facts) -> bool {
    match r {
        Facts::Arp { .. } => true,
        _ => false,
    }
}

/// The IPv4 header length in bytes.
pub open spec fn spec_ihl(f: Seq<u8>) -> int {
    ((f[14] & 0x0f) as int) * 4
}

/// The IPv4 total length.
pub open spec fn spec_total(f: Seq<u8>) -> int {
    spec_be16(f, 16) as int
}

/// The TCP data offset in bytes, for a frame whose TCP header starts at `at`.
pub open spec fn spec_doff(f: Seq<u8>, at: int) -> int {
    ((f[at + 12] >> 4) as int) * 4
}

/// RFC 791: the frame carries a version-4 datagram whose header is 20 bytes
/// or more and whose total length covers the header and fits the frame.
#[verifier::opaque]
pub open spec fn is_v4_datagram(f: Seq<u8>) -> bool {
    &&& f.len() >= 34
    &&& f[12] == 0x08
    &&& f[13] == 0x00
    &&& (f[14] >> 4) == 4
    &&& 20 <= spec_ihl(f)
    &&& spec_ihl(f) <= spec_total(f)
    &&& 14 + spec_total(f) <= f.len()
}

/// RFC 826, Ethernet hardware and IPv4 protocol only.
pub open spec fn is_arp_packet(f: Seq<u8>) -> bool {
    &&& f.len() >= 42
    &&& f[12] == 0x08
    &&& f[13] == 0x06
    &&& spec_be16(f, 14) == 1
    &&& spec_be16(f, 16) == 0x0800
    &&& f[18] == 6
    &&& f[19] == 4
}

/// A whole TCP header inside the total length, starting at `at`.
pub open spec fn tcp_header_fits(f: Seq<u8>, at: int) -> bool {
    &&& spec_ihl(f) + 20 <= spec_total(f)
    &&& 20 <= spec_doff(f, at)
    &&& spec_ihl(f) + spec_doff(f, at) <= spec_total(f)
}

/// More fragments of the datagram follow this one.
pub open spec fn more_follow(f: Seq<u8>) -> bool {
    (spec_be16(f, 20) & 0x2000) != 0
}

/// A whole UDP header inside the total length, and a UDP length of at least
/// the header that is inside the total length too, unless more fragments
/// follow: the UDP length counts the whole datagram, fragments to come
/// included.
pub open spec fn udp_header_fits(f: Seq<u8>, at: int) -> bool {
    &&& spec_ihl(f) + 8 <= spec_total(f)
    &&& 8 <= spec_be16(f, at + 4)
    &&& more_follow(f) || spec_ihl(f) + (spec_be16(f, at + 4) as int) <= spec_total(f)
}

/// The UDP payload bytes this datagram or fragment carries: what the UDP
/// length says, or what is inside the total length when that is less.
pub open spec fn udp_inside(f: Seq<u8>, at: int) -> int {
    if spec_ihl(f) + (spec_be16(f, at + 4) as int) <= spec_total(f) {
        (spec_be16(f, at + 4) as int) - 8
    } else {
        spec_total(f) - spec_ihl(f) - 8
    }
}

/// P2 for the transport facts of a datagram. Exactly one variant is sound
/// for any datagram, so this fixes the parser's answer.
#[verifier::opaque]
pub open spec fn l4_sound(f: Seq<u8>, l4: L4) -> bool {
    let at = 14 + spec_ihl(f);
    let first = (spec_be16(f, 20) & 0x1fff) == 0;
    let proto = f[23];
    match l4 {
        L4::LaterFragment => !first,
        L4::NoPorts => first && proto != 6 && proto != 17,
        L4::ShortHeader => first && ((proto == 6 && !tcp_header_fits(f, at)) || (proto == 17
            && !udp_header_fits(f, at))),
        L4::Tcp { sport, dport, flags, seq, ack, payload_len } => {
            &&& first
            &&& proto == 6
            &&& tcp_header_fits(f, at)
            &&& sport == spec_be16(f, at)
            &&& dport == spec_be16(f, at + 2)
            &&& seq == spec_be32(f, at + 4)
            &&& ack == spec_be32(f, at + 8)
            &&& flags == f[at + 13]
            &&& payload_len as int == spec_total(f) - spec_ihl(f) - spec_doff(f, at)
        },
        L4::Udp { sport, dport, payload_at, payload_len } => {
            &&& first
            &&& proto == 17
            &&& udp_header_fits(f, at)
            &&& sport == spec_be16(f, at)
            &&& dport == spec_be16(f, at + 2)
            &&& payload_at as int == at + 8
            &&& payload_len as int == udp_inside(f, at)
        },
    }
}

/// P2: what a result may claim about the frame it was read from.
pub open spec fn facts_sound(f: Seq<u8>, r: Facts) -> bool {
    match r {
        Facts::Other(_) => true,
        Facts::Arp { eth_dst, eth_src, sender_mac, sender } => {
            &&& is_arp_packet(f)
            &&& mac_at(eth_dst, f, 0)
            &&& mac_at(eth_src, f, 6)
            &&& mac_at(sender_mac, f, 22)
            &&& sender == spec_be32(f, 28)
        },
        Facts::V4(v) => {
            &&& is_v4_datagram(f)
            &&& mac_at(v.eth_dst, f, 0)
            &&& mac_at(v.eth_src, f, 6)
            &&& v.src == spec_be32(f, 26)
            &&& v.dst == spec_be32(f, 30)
            &&& v.proto == f[23]
            &&& v.dscp == f[15] >> 2
            &&& v.more_fragments == ((spec_be16(f, 20) & 0x2000) != 0)
            &&& l4_sound(f, v.l4)
        },
    }
}

/// The bounds `parse_l4` needs from `is_v4_datagram` (opaque), as linear facts.
pub proof fn lemma_l4_bounds(f: Seq<u8>)
    requires
        is_v4_datagram(f),
    ensures
        20 <= spec_ihl(f) <= 60,
        spec_ihl(f) <= spec_total(f) <= 0xffff,
        14 + spec_total(f) <= f.len(),
{
    reveal(is_v4_datagram);
    let b = f[14];
    assert(b & 0x0f <= 15) by (bit_vector);
}

/// A non-negative int below 2^17 is its own `usize` value on every target.
/// Stated once per index so the parser's query need not reason about the
/// symbolic width of `usize` at every bound and overflow check.
pub proof fn lemma_small_usize(x: int)
    requires
        0 <= x < 0x2_0000,
    ensures
        x as usize == x,
{
}

// One lemma per return shape of `parse_l4`, so the body of `l4_sound`
// (opaque) is unfolded once per shape, outside the parser's own query.
pub proof fn lemma_l4_later(f: Seq<u8>)
    requires
        (spec_be16(f, 20) & 0x1fff) != 0,
    ensures
        l4_sound(f, L4::LaterFragment),
{
    reveal(l4_sound);
}

pub proof fn lemma_l4_no_ports(f: Seq<u8>)
    requires
        (spec_be16(f, 20) & 0x1fff) == 0,
        f[23] != 6,
        f[23] != 17,
    ensures
        l4_sound(f, L4::NoPorts),
{
    reveal(l4_sound);
}

pub proof fn lemma_l4_short_tcp(f: Seq<u8>, ihl: int, total: int, doff: int)
    requires
        (spec_be16(f, 20) & 0x1fff) == 0,
        f[23] == 6,
        ihl == spec_ihl(f),
        total == spec_total(f),
        ihl + 20 > total || (doff == spec_doff(f, 14 + ihl) && (doff < 20 || ihl + doff > total)),
    ensures
        l4_sound(f, L4::ShortHeader),
{
    reveal(l4_sound);
}

pub proof fn lemma_l4_short_udp(f: Seq<u8>, ihl: int, total: int, udp_len: int)
    requires
        (spec_be16(f, 20) & 0x1fff) == 0,
        f[23] == 17,
        ihl == spec_ihl(f),
        total == spec_total(f),
        ihl + 8 > total || (udp_len == spec_be16(f, 14 + ihl + 4) as int && (udp_len < 8 || (ihl
            + udp_len > total && !more_follow(f)))),
    ensures
        l4_sound(f, L4::ShortHeader),
{
    reveal(l4_sound);
}

pub proof fn lemma_l4_tcp(frame: &[u8], ihl: usize, total: usize, doff: usize, at: usize)
    requires
        is_v4_datagram(frame@),
        ihl as int == spec_ihl(frame@),
        total as int == spec_total(frame@),
        (spec_be16(frame@, 20) & 0x1fff) == 0,
        frame@[23] == 6,
        at == (ETH_HDR + ihl) as usize,
        !((ihl + 20) as usize > total),
        doff == (((frame@[(at + 12) as usize as int] >> 4) as usize) * 4) as usize,
        !(doff < 20),
        !((ihl + doff) as usize > total),
    ensures
        at + 13 < frame@.len(),
        l4_sound(frame@, L4::Tcp {
            sport: spec_be16(frame@, at as int),
            dport: spec_be16(frame@, (at + 2) as usize as int),
            flags: frame@[(at + 13) as usize as int],
            seq: spec_be32(frame@, (at + 4) as usize as int),
            ack: spec_be32(frame@, (at + 8) as usize as int),
            payload_len: (((total - ihl) as usize - doff) as usize) as u16,
        }),
{
    reveal(l4_sound);
    reveal(is_v4_datagram);
}

pub proof fn lemma_l4_udp(frame: &[u8], ihl: usize, total: usize, udp_len: usize, at: usize, inside: usize)
    requires
        is_v4_datagram(frame@),
        ihl as int == spec_ihl(frame@),
        total as int == spec_total(frame@),
        (spec_be16(frame@, 20) & 0x1fff) == 0,
        frame@[23] == 17,
        at == (ETH_HDR + ihl) as usize,
        !((ihl + 8) as usize > total),
        udp_len == spec_be16(frame@, (at + 4) as usize as int) as usize,
        !(udp_len < 8),
        (ihl + udp_len) as usize > total ==> more_follow(frame@),
        inside == (if (ihl + udp_len) as usize > total { (total - ihl - 8) as usize } else { (udp_len - 8) as usize }),
    ensures
        at + 5 < frame@.len(),
        l4_sound(frame@, L4::Udp {
            sport: spec_be16(frame@, at as int),
            dport: spec_be16(frame@, (at + 2) as usize as int),
            payload_at: ((at + 8) as usize) as u16,
            payload_len: inside as u16,
        }),
{
    // `at + 8` fits a u16: the header length is at most 60 bytes.
    reveal(is_v4_datagram);
    let b = frame@[14];
    assert(b & 0x0f <= 15) by (bit_vector);
    reveal(l4_sound);
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        i + 1 < frame.len(),
    ensures
        r == spec_be16(frame@, i as int),
))]
fn be16(frame: &[u8], i: usize) -> u16 {
    #[cfg(verus_keep_ghost)]
    proof! { reveal(spec_be16); }
    ((frame[i] as u16) << 8) | (frame[i + 1] as u16)
}

#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        i + 3 < frame.len(),
    ensures
        r == spec_be32(frame@, i as int),
))]
fn be32(frame: &[u8], i: usize) -> u32 {
    #[cfg(verus_keep_ghost)]
    proof! { reveal(spec_be32); }
    ((frame[i] as u32) << 24)
        | ((frame[i + 1] as u32) << 16)
        | ((frame[i + 2] as u32) << 8)
        | (frame[i + 3] as u32)
}

#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        i + 5 < frame.len(),
    ensures
        mac_at(r, frame@, i as int),
))]
fn mac(frame: &[u8], i: usize) -> [u8; 6] {
    [
        frame[i],
        frame[i + 1],
        frame[i + 2],
        frame[i + 3],
        frame[i + 4],
        frame[i + 5],
    ]
}

/// The transport facts of a UDP datagram or first fragment. `more` says more
/// fragments follow.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        is_v4_datagram(frame@),
        ihl as int == spec_ihl(frame@),
        total as int == spec_total(frame@),
        (spec_be16(frame@, 20) & 0x1fff) == 0,
        frame@[23] == 17,
        more == more_follow(frame@),
    ensures
        l4_sound(frame@, r),
))]
fn parse_udp(frame: &[u8], ihl: usize, total: usize, more: bool) -> L4 {
    #[cfg(verus_keep_ghost)]
    proof! { lemma_l4_bounds(frame@); }
    let at = ETH_HDR + ihl;
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_small_usize(ihl + 8);
        lemma_small_usize(at + 2);
        lemma_small_usize(at + 4);
        lemma_small_usize(at + 8);
    }
    if ihl + 8 > total {
        #[cfg(verus_keep_ghost)]
        proof! { lemma_l4_short_udp(frame@, ihl as int, total as int, 0); }
        return L4::ShortHeader;
    }
    let udp_len = be16(frame, at + 4) as usize;
    if udp_len < 8 || (ihl + udp_len > total && !more) {
        #[cfg(verus_keep_ghost)]
        proof! { lemma_l4_short_udp(frame@, ihl as int, total as int, udp_len as int); }
        return L4::ShortHeader;
    }
    // What this datagram or fragment carries after the header.
    let inside = if ihl + udp_len > total {
        total - ihl - 8
    } else {
        udp_len - 8
    };
    // `at + 8` fits a u16: the header length is at most 60 bytes.
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_small_usize(inside as int);
        lemma_l4_udp(frame, ihl, total, udp_len, at, inside);
    }
    L4::Udp {
        sport: be16(frame, at),
        dport: be16(frame, at + 2),
        payload_at: (at + 8) as u16,
        payload_len: inside as u16,
    }
}

/// The transport facts of a datagram [`parse_frame`] has already bounded.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        is_v4_datagram(frame@),
        ihl as int == spec_ihl(frame@),
        total as int == spec_total(frame@),
    ensures
        l4_sound(frame@, r),
))]
fn parse_l4(frame: &[u8], ihl: usize, total: usize) -> L4 {
    #[cfg(verus_keep_ghost)]
    proof! { lemma_l4_bounds(frame@); }
    let fragment = be16(frame, 20);
    if fragment & 0x1fff != 0 {
        #[cfg(verus_keep_ghost)]
        proof! { lemma_l4_later(frame@); }
        return L4::LaterFragment;
    }
    let proto = frame[23];
    let at = ETH_HDR + ihl;
    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_small_usize(ihl + 20);
        lemma_small_usize(ihl + 8);
        lemma_small_usize(at + 2);
        lemma_small_usize(at + 4);
        lemma_small_usize(at + 8);
        lemma_small_usize(at + 12);
        lemma_small_usize(at + 13);
    }
    if proto == IPPROTO_TCP {
        if ihl + 20 > total {
            #[cfg(verus_keep_ghost)]
            proof! { lemma_l4_short_tcp(frame@, ihl as int, total as int, 0); }
            return L4::ShortHeader;
        }
        let doff = ((frame[at + 12] >> 4) as usize) * 4;
        if doff < 20 || ihl + doff > total {
            #[cfg(verus_keep_ghost)]
            proof! { lemma_l4_short_tcp(frame@, ihl as int, total as int, doff as int); }
            return L4::ShortHeader;
        }
        #[cfg(verus_keep_ghost)]
        proof! { lemma_l4_tcp(frame, ihl, total, doff, at); }
        return L4::Tcp {
            sport: be16(frame, at),
            dport: be16(frame, at + 2),
            flags: frame[at + 13],
            seq: be32(frame, at + 4),
            ack: be32(frame, at + 8),
            payload_len: (total - ihl - doff) as u16,
        };
    }
    if proto == IPPROTO_UDP {
        return parse_udp(frame, ihl, total, fragment & 0x2000 != 0);
    }
    #[cfg(verus_keep_ghost)]
    proof! { lemma_l4_no_ports(frame@); }
    L4::NoPorts
}

/// Reads what one Ethernet II frame carries. Total: every byte string has an answer.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        facts_sound(frame@, r),
        is_v4_datagram(frame@) ==> is_v4(r),
        is_arp_packet(frame@) ==> is_arp(r),
))]
pub fn parse_frame(frame: &[u8]) -> Facts {
    #[cfg(verus_keep_ghost)]
    proof! { reveal(is_v4_datagram); }
    if frame.len() < ETH_HDR {
        return Facts::Other(Reason::Short);
    }
    let ethertype = be16(frame, 12);
    // The EtherType equals a constant exactly when its two bytes do.
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(spec_be16);
        let a = frame[12];
        let b = frame[13];
        assert((((a as u16) << 8) | (b as u16)) == 0x0806u16 <==> (a == 0x08u8 && b == 0x06u8)) by (bit_vector);
        assert((((a as u16) << 8) | (b as u16)) == 0x0800u16 <==> (a == 0x08u8 && b == 0x00u8)) by (bit_vector);
    }
    if ethertype == ETHERTYPE_ARP {
        if frame.len() < ETH_HDR + ARP_LEN {
            return Facts::Other(Reason::Short);
        }
        if be16(frame, 14) != 1 || be16(frame, 16) != 0x0800 || frame[18] != 6 || frame[19] != 4 {
            return Facts::Other(Reason::ArpShape);
        }
        return Facts::Arp {
            eth_dst: mac(frame, 0),
            eth_src: mac(frame, 6),
            sender_mac: mac(frame, 22),
            sender: be32(frame, 28),
        };
    }
    if ethertype == ETHERTYPE_IPV6 {
        return Facts::Other(Reason::Ipv6);
    }
    if ethertype == ETHERTYPE_VLAN {
        return Facts::Other(Reason::Vlan);
    }
    if ethertype != ETHERTYPE_IPV4 {
        return Facts::Other(Reason::OtherEtherType);
    }
    if frame.len() < ETH_HDR + 20 {
        return Facts::Other(Reason::Short);
    }
    if frame[14] >> 4 != 4 {
        return Facts::Other(Reason::BadVersion);
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Facts::Other(Reason::BadHeaderLength);
    }
    let total = be16(frame, 16) as usize;
    if total < ihl || ETH_HDR + total > frame.len() {
        return Facts::Other(Reason::BadTotalLength);
    }
    let fragment = be16(frame, 20);
    Facts::V4(Ipv4Facts {
        eth_dst: mac(frame, 0),
        eth_src: mac(frame, 6),
        src: be32(frame, 26),
        dst: be32(frame, 30),
        proto: frame[23],
        dscp: frame[15] >> 2,
        more_fragments: fragment & 0x2000 != 0,
        l4: parse_l4(frame, ihl, total),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd, 2, 0, 0, 0, 0, 2];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    fn ipv4(proto: u8, total: u16, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = eth(0x0800);
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&fragment.to_be_bytes());
        f.extend_from_slice(&[64, proto, 0, 0, 100, 64, 0, 10, 100, 64, 0, 1]);
        f.extend_from_slice(payload);
        f
    }

    fn l4_of(frame: &[u8]) -> L4 {
        match parse_frame(frame) {
            Facts::V4(v) => v.l4,
            other => panic!("not IPv4: {other:?}"),
        }
    }

    #[test]
    fn udp_query_reports_its_ports() {
        let udp = [0x9c, 0x40, 0, 53, 0, 12, 0, 0, b'a', b'b', b'c', b'd'];
        let l4 = l4_of(&ipv4(17, 32, 0, &udp));
        assert_eq!(
            l4,
            L4::Udp {
                sport: 40000,
                dport: 53,
                payload_at: 42,
                payload_len: 4
            }
        );
    }

    // Four frames in which no port may be read.
    #[test]
    fn padding_after_the_datagram_is_not_a_port() {
        assert_eq!(l4_of(&ipv4(17, 20, 0, &[0, 53, 0, 53])), L4::ShortHeader);
    }

    #[test]
    fn icmp_has_no_ports() {
        assert_eq!(
            l4_of(&ipv4(1, 28, 0, &[8, 0, 0x12, 0x34, 0, 1, 0, 1])),
            L4::NoPorts
        );
    }

    #[test]
    fn version_six_under_the_ipv4_ethertype_is_refused() {
        let mut f = ipv4(17, 28, 0, &[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
        f[14] = 0x65;
        assert_eq!(parse_frame(&f), Facts::Other(Reason::BadVersion));
    }

    #[test]
    fn eight_bytes_of_tcp_is_not_a_tcp_header() {
        let tcp = [
            0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ];
        assert_eq!(l4_of(&ipv4(6, 28, 0x2000, &tcp)), L4::ShortHeader);
    }

    #[test]
    fn a_udp_first_fragment_has_ports_and_the_payload_it_carries() {
        // A UDP length of 1,480 in a fragment of twelve bytes.
        let udp = [0x9c, 0x40, 0, 53, 0x05, 0xc8, 0, 0, 1, 2, 3, 4];
        assert_eq!(
            l4_of(&ipv4(17, 32, 0x2000, &udp)),
            L4::Udp {
                sport: 0x9c40,
                dport: 53,
                payload_at: 42,
                payload_len: 4,
            }
        );
        // The same bytes with no fragment to follow.
        assert_eq!(l4_of(&ipv4(17, 32, 0, &udp)), L4::ShortHeader);
        // A UDP length below the header is short either way.
        let short = [0x9c, 0x40, 0, 53, 0, 7, 0, 0, 1, 2, 3, 4];
        assert_eq!(l4_of(&ipv4(17, 32, 0x2000, &short)), L4::ShortHeader);
    }

    #[test]
    fn a_tagged_frame_is_not_ipv4() {
        assert_eq!(parse_frame(&eth(0x8100)), Facts::Other(Reason::Vlan));
    }
}

/// Bit-level check of P1, P2 and P2c against a reader written from the RFCs
/// that shares no code with [`parse_frame`]. The frame is long enough for a
/// 60-byte IPv4 header and a 60-byte TCP header.
#[cfg(kani)]
mod proofs {
    use super::*;

    const BOUND: usize = 14 + 60 + 60;

    struct Reference {
        proto: u8,
        first: bool,
        ihl: usize,
        total: usize,
        more: bool,
    }

    fn reference(f: &[u8]) -> Option<Reference> {
        if f.len() < 34 || f[12] != 0x08 || f[13] != 0x00 {
            return None;
        }
        if f[14] / 16 != 4 {
            return None;
        }
        let ihl = usize::from(f[14] % 16) * 4;
        let total = usize::from(f[16]) * 256 + usize::from(f[17]);
        if ihl < 20 || total < ihl || 14 + total > f.len() {
            return None;
        }
        let offset = (usize::from(f[20]) % 32) * 256 + usize::from(f[21]);
        Some(Reference {
            proto: f[23],
            first: offset == 0,
            ihl,
            total,
            more: (f[20] / 32) % 2 == 1,
        })
    }

    /// The destination port a receiver would read, if the datagram has one.
    fn reference_dport(f: &[u8], r: &Reference) -> Option<u16> {
        if !r.first {
            return None;
        }
        let at = 14 + r.ihl;
        let inside = r.total - r.ihl;
        match r.proto {
            17 => {
                if inside < 8 {
                    return None;
                }
                let udp_len = usize::from(f[at + 4]) * 256 + usize::from(f[at + 5]);
                if udp_len < 8 || (udp_len > inside && !r.more) {
                    return None;
                }
            }
            6 => {
                if inside < 20 {
                    return None;
                }
                let doff = usize::from(f[at + 12] / 16) * 4;
                if doff < 20 || doff > inside {
                    return None;
                }
            }
            _ => return None,
        }
        Some(u16::from(f[at + 2]) * 256 + u16::from(f[at + 3]))
    }

    #[kani::proof]
    fn kani_parse_frame_matches_the_reference() {
        let bytes: [u8; BOUND] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= BOUND);
        let frame = &bytes[..len];

        let facts = parse_frame(frame);
        let reference = reference(frame);

        match (&facts, &reference) {
            (Facts::V4(v), Some(r)) => {
                assert!(v.proto == r.proto);
                let reported = match v.l4 {
                    L4::Tcp { dport, .. } | L4::Udp { dport, .. } => Some(dport),
                    L4::NoPorts | L4::LaterFragment | L4::ShortHeader => None,
                };
                assert!(reported == reference_dport(frame, r));
            }
            // P2: no IPv4 facts without a datagram. P2c: no datagram without facts.
            (Facts::V4(_), None) | (Facts::Arp { .. } | Facts::Other(_), Some(_)) => {
                assert!(false);
            }
            (Facts::Arp { .. } | Facts::Other(_), None) => {}
        }
    }
}
