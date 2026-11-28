//! The kernel's reading of a frame, in the shapes the gate's own tables
//! take.
//!
//! The gate reads no frame itself: `netcore` reads it once and these
//! functions hand the reading on. They decide nothing.

use std::net::{Ipv4Addr, SocketAddrV4};

use netcore::frame::{Facts, Ipv4Facts, L4};

use crate::net::dns_pins::L4Packet;
use crate::net::forward_revoke::TcpSegment;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;

/// The IPv4 facts of a frame, when it carries a datagram.
fn v4(facts: &Facts) -> Option<&Ipv4Facts> {
    match facts {
        Facts::V4(v) => Some(v),
        Facts::Arp { .. } | Facts::Other(_) => None,
    }
}

/// The L4 addressing of a TCP or UDP datagram with a whole transport
/// header on a first fragment, as the flow and DNS tables read it. `None`
/// for anything else.
pub(crate) fn l4_packet(facts: &Facts) -> Option<L4Packet> {
    let v = v4(facts)?;
    let src = Ipv4Addr::from(v.src);
    let dst = Ipv4Addr::from(v.dst);
    match v.l4 {
        L4::Tcp {
            sport,
            dport,
            flags,
            seq,
            ack,
            payload_len,
        } => Some(L4Packet {
            src: SocketAddrV4::new(src, sport),
            dst: SocketAddrV4::new(dst, dport),
            proto: IPPROTO_TCP,
            tcp_flags: flags,
            tcp_seq: seq,
            tcp_ack: ack,
            tcp_payload_len: payload_len,
        }),
        L4::Udp { sport, dport, .. } => Some(L4Packet {
            src: SocketAddrV4::new(src, sport),
            dst: SocketAddrV4::new(dst, dport),
            proto: IPPROTO_UDP,
            tcp_flags: 0,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_payload_len: 0,
        }),
        L4::NoPorts | L4::LaterFragment | L4::ShortHeader => None,
    }
}

/// The UDP payload of a whole datagram `frame` carries, with its L4
/// addressing: what the DNS tables read a question or an answer from, on both
/// legs. `None` for a first fragment with more to follow, whose payload is not
/// the whole datagram, and for anything else: the gate reads DNS only from
/// whole datagrams, and a fragment is decided and delivered as any frame is.
pub(crate) fn udp_datagram<'a>(frame: &'a [u8], facts: &Facts) -> Option<(L4Packet, &'a [u8])> {
    let v = v4(facts)?;
    if v.more_fragments {
        return None;
    }
    let L4::Udp {
        payload_at,
        payload_len,
        ..
    } = v.l4
    else {
        return None;
    };
    let at = usize::from(payload_at);
    let payload = frame.get(at..at + usize::from(payload_len))?;
    Some((l4_packet(facts)?, payload))
}

/// The TCP header fields a reset is built from. `None` for anything but a
/// whole TCP segment in an unfragmented datagram.
pub(crate) fn tcp_segment(facts: &Facts) -> Option<TcpSegment> {
    let v = v4(facts)?;
    if v.more_fragments {
        return None;
    }
    let L4::Tcp {
        sport,
        dport,
        flags,
        seq,
        ack,
        payload_len,
    } = v.l4
    else {
        return None;
    };
    let advance =
        u32::from(payload_len) + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
    Some(TcpSegment {
        dst_mac: v.eth_dst,
        src_mac: v.eth_src,
        src: v.src.to_be_bytes(),
        dst: v.dst.to_be_bytes(),
        src_port: sport,
        dst_port: dport,
        seq,
        ack,
        flags,
        advance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netcore::frame::parse_frame;

    /// An Ethernet II frame carrying one IPv4 datagram with this protocol,
    /// fragment field and transport bytes.
    fn frame(proto: u8, fragment: u16, transport: &[u8]) -> Vec<u8> {
        let mut f = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
        let total = u16::try_from(20 + transport.len()).unwrap();
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&fragment.to_be_bytes());
        f.extend_from_slice(&[64, proto, 0, 0, 100, 64, 0, 7, 203, 0, 113, 7]);
        f.extend_from_slice(transport);
        f
    }

    fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0x9c, 0x40, 0x01, 0xbb];
        t.extend_from_slice(&7u32.to_be_bytes());
        t.extend_from_slice(&9u32.to_be_bytes());
        t.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(payload);
        t
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0x9c, 0x40, 0, 53];
        u.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    #[test]
    fn a_tcp_segment_gives_its_addressing_and_how_far_it_advances() {
        let bytes = frame(IPPROTO_TCP, 0, &tcp(TCP_SYN, b"abc"));
        let facts = parse_frame(&bytes);
        let l4 = l4_packet(&facts).unwrap();
        assert_eq!(
            l4.src,
            SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 7), 40000)
        );
        assert_eq!(
            l4.dst,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443)
        );
        assert_eq!(
            (l4.proto, l4.tcp_flags, l4.tcp_seq, l4.tcp_ack),
            (6, TCP_SYN, 7, 9)
        );
        assert_eq!(l4.tcp_payload_len, 3);
        let segment = tcp_segment(&facts).unwrap();
        assert_eq!(segment.dst_mac, [2, 0, 0, 0, 0, 1]);
        assert_eq!(segment.src_mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(segment.advance, 4);
    }

    #[test]
    fn a_whole_udp_datagram_gives_its_payload_and_a_first_fragment_gives_none() {
        let bytes = frame(IPPROTO_UDP, 0, &udp(b"query"));
        let facts = parse_frame(&bytes);
        let (l4, payload) = udp_datagram(&bytes, &facts).unwrap();
        assert_eq!(payload, b"query");
        assert_eq!((l4.proto, l4.dst.port(), l4.tcp_payload_len), (17, 53, 0));
        // More fragments to follow: the payload is not the whole datagram.
        let first = frame(IPPROTO_UDP, 0x2000, &udp(b"query"));
        let facts = parse_frame(&first);
        assert!(udp_datagram(&first, &facts).is_none());
    }

    #[test]
    fn what_has_no_whole_transport_header_gives_nothing() {
        // A fragment that is not the first.
        let later = frame(IPPROTO_TCP, 0x0001, &tcp(0x10, b""));
        assert!(l4_packet(&parse_frame(&later)).is_none());
        // A protocol without ports.
        let icmp = frame(1, 0, &[8, 0, 0, 0, 0, 0, 0, 0]);
        assert!(l4_packet(&parse_frame(&icmp)).is_none());
        // A first fragment of TCP with more to follow builds no segment.
        let first = frame(IPPROTO_TCP, 0x2000, &tcp(0x10, b"abc"));
        let facts = parse_frame(&first);
        assert!(tcp_segment(&facts).is_none());
        // Bytes that are no frame.
        assert!(l4_packet(&parse_frame(&[0u8; 5])).is_none());
        assert!(tcp_segment(&parse_frame(&[0u8; 5])).is_none());
    }
}
