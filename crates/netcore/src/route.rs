//! Which decision a frame goes to.
//!
//! Layer 4 of the crate, a decision. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The host gate decides a guest's frame in two steps: its source picks the
//! decision, then the decision reads the rest. This is the first step. A
//! frame from the cohort, the node or a registered row goes to that
//! decision ([`crate::cohort`], [`crate::node`], [`crate::judge`]). A frame
//! from any other source is refused here, and the refusal has one of three
//! names.
//!
//! THEOREM RT1, for every set of sources and every frame:
//!   (a) `route` returns exactly one route, determined by the frame's source
//!       address, its family and mark, the plan, the rows, and for a refused
//!       frame whether it is a non-DNS frame to the gateway;
//!   (b) `Row(i)` names the first row holding the source address;
//!   (c) a frame whose source is not the cohort, the node or a registered row
//!       gets one of the three refusals: there is no route from an
//!       unregistered or unknown source to a decision that can admit.
//!
//! The control surface is named first for a refused source because the gate
//! tests it before it looks the source up: a stray source probing the gateway
//! is logged as that, not as an unregistered lease.
//!
//! Before either step the frame's facts become a [`Frame`], or do not
//! ([`frame_of`]). TCP or UDP on a first fragment without a whole header is
//! never a `Frame`: it is refused for what it is, whatever its source, and
//! no decision and no table sees it.
//!
//! THEOREM RT2, for every byte string and the facts read from it:
//!   (a) a frame that carries ports took them from a whole TCP or UDP header
//!       on a first fragment;
//!   (b) a TCP or UDP frame without ports is a fragment that is not the
//!       first;
//!   (c) [`Said::ShortHeader`] is said exactly of an IPv4 first fragment of
//!       TCP or UDP whose header is not whole.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

use crate::frame::{Facts, L4};
#[cfg(verus_keep_ghost)]
use crate::frame::{facts_sound, l4_sound, spec_be16, spec_ihl, tcp_header_fits, udp_header_fits};
#[cfg(verus_keep_ghost)]
use crate::judge::dest_of_sent;
use crate::judge::{Sent, SentKind, SentL4};
use crate::origin::{Origin, Sources};
#[cfg(verus_keep_ghost)]
use crate::origin::{
    allocatable, first_at, is_cohort, is_node, plan_of, registered, rows_of, sinv,
};
#[cfg(verus_keep_ghost)]
use crate::plan::{Plan, spec_gateway};
use crate::row::{DNS_PORT, PROTO_TCP, PROTO_UDP};
#[cfg(verus_keep_ghost)]
use crate::row::{Dest, dns_at};

/// A frame a guest sent, as far as routing and the decisions read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Frame {
    pub sent: Sent,
    /// The IPv4 DSCP field; 0 for ARP. Read only of an IPv4 datagram.
    pub dscp: u8,
}

/// What the facts of a frame a guest sent come to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Said {
    /// A frame for routing and the decisions.
    Frame(Frame),
    /// Drop, before routing: TCP or UDP on a first fragment without a whole
    /// header.
    ShortHeader,
    /// Drop: neither an IPv4 datagram nor an ARP packet.
    NotAFrame,
}

/// Where a frame goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Route {
    /// To the cohort's decision.
    Cohort,
    /// To the node's decision.
    Node,
    /// To the decision of the registered row at this index.
    Row(usize),
    /// Drop: not from a registered source, and a non-DNS frame to the gateway.
    ControlSurface,
    /// Drop: from an address the plan could lease that no row holds.
    Unregistered,
    /// Drop: from any other address.
    Unknown,
}

#[cfg(verus_keep_ghost)]
verus! {

/// A frame to the gateway that is not TCP or UDP to port 53.
pub open spec fn at_control_surface(plan: Plan, d: Dest) -> bool {
    match d {
        Dest::Arp => false,
        Dest::V4 { dst, proto, port } => dst as int == spec_gateway(plan) && !dns_at(proto, port),
    }
}

/// What the decisions read of a transport header: none for a protocol
/// without ports, a later fragment or a short header; for UDP, no flags and
/// no sequence numbers.
pub open spec fn l4_of(l: L4) -> Option<SentL4> {
    match l {
        L4::Tcp { sport, dport, flags, seq, ack, payload_len } => Some(SentL4 { sport, dport, flags, seq, ack, payload_len }),
        L4::Udp { sport, dport, payload_at, payload_len } => Some(SentL4 { sport, dport, flags: 0, seq: 0, ack: 0, payload_len }),
        L4::NoPorts => None,
        L4::LaterFragment => None,
        L4::ShortHeader => None,
    }
}

/// The frame a guest sent, as its facts give it: the sender of an ARP
/// packet, or the addresses, protocol, mark and transport of a datagram.
pub open spec fn frame_spec(facts: Facts) -> Said {
    match facts {
        Facts::Arp { eth_dst, eth_src, sender_mac, sender } => Said::Frame(Frame {
            sent: Sent { src: sender, kind: SentKind::Arp },
            dscp: 0,
        }),
        Facts::V4(v) => if v.l4 == L4::ShortHeader {
            Said::ShortHeader
        } else {
            Said::Frame(Frame {
                sent: Sent { src: v.src, kind: SentKind::V4 { dst: v.dst, proto: v.proto, l4: l4_of(v.l4) } },
                dscp: v.dscp,
            })
        },
        Facts::Other(_) => Said::NotAFrame,
    }
}

/// The fragment offset of the datagram in `b` is zero.
pub open spec fn first_fragment(b: Seq<u8>) -> bool {
    (spec_be16(b, 20) & 0x1fff) == 0
}

/// TCP or UDP with its whole header inside the datagram in `b`.
pub open spec fn whole_header(b: Seq<u8>, proto: u8) -> bool {
    ||| proto == PROTO_TCP && tcp_header_fits(b, 14 + spec_ihl(b))
    ||| proto == PROTO_UDP && udp_header_fits(b, 14 + spec_ihl(b))
}

/// RT2.
pub proof fn theorem_rt2_ports_come_from_a_whole_header(b: Seq<u8>, facts: Facts)
    requires
        facts_sound(b, facts),
    ensures
        match frame_spec(facts) {
            Said::Frame(f) => match f.sent.kind {
                SentKind::Arp => true,
                SentKind::V4 { dst, proto, l4 } => {
                    &&& l4 is Some ==> first_fragment(b) && whole_header(b, proto)
                    &&& l4 is None && (proto == PROTO_TCP || proto == PROTO_UDP) ==> !first_fragment(b)
                },
            },
            Said::ShortHeader => {
                &&& facts is V4
                &&& first_fragment(b)
                &&& b[23] == PROTO_TCP || b[23] == PROTO_UDP
                &&& !whole_header(b, b[23])
            },
            Said::NotAFrame => true,
        },
{
    reveal(l4_sound);
}

/// The frame is an IPv4 datagram, by its own kind.
pub open spec fn v4(f: Frame) -> bool {
    match f.sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => true,
    }
}

/// The source is not one any decision is held for.
pub open spec fn stray(s: Sources, f: Frame) -> bool {
    &&& !is_cohort(s, f.sent.src, v4(f), f.dscp)
    &&& !is_node(s, f.sent.src, v4(f), f.dscp)
    &&& !registered(rows_of(s), f.sent.src)
}

} // verus!

/// The frame facts as a [`Frame`], or why there is none. A frame that
/// carries no IPv4 datagram and no ARP packet has no source; TCP or UDP on a
/// first fragment without a whole header has no ports to decide by. Both are
/// dropped for what they are. RT2.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == frame_spec(*facts),
))]
pub fn frame_of(facts: &Facts) -> Said {
    match facts {
        Facts::Arp { sender, .. } => Said::Frame(Frame {
            sent: Sent {
                src: *sender,
                kind: SentKind::Arp,
            },
            dscp: 0,
        }),
        Facts::V4(v) => {
            let l4 = match v.l4 {
                L4::Tcp {
                    sport,
                    dport,
                    flags,
                    seq,
                    ack,
                    payload_len,
                } => Some(SentL4 {
                    sport,
                    dport,
                    flags,
                    seq,
                    ack,
                    payload_len,
                }),
                L4::Udp {
                    sport,
                    dport,
                    payload_len,
                    ..
                } => Some(SentL4 {
                    sport,
                    dport,
                    flags: 0,
                    seq: 0,
                    ack: 0,
                    payload_len,
                }),
                L4::NoPorts => None,
                L4::LaterFragment => None,
                L4::ShortHeader => {
                    return Said::ShortHeader;
                }
            };
            Said::Frame(Frame {
                sent: Sent {
                    src: v.src,
                    kind: SentKind::V4 {
                        dst: v.dst,
                        proto: v.proto,
                        l4,
                    },
                },
                dscp: v.dscp,
            })
        }
        Facts::Other(_) => Said::NotAFrame,
    }
}

/// Routes a frame by its source. RT1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    requires
        sinv(*sources),
    ensures
        match r {
            Route::Cohort => is_cohort(*sources, f.sent.src, v4(f), f.dscp),
            Route::Node => is_node(*sources, f.sent.src, v4(f), f.dscp),
            Route::Row(i) => {
                &&& !is_cohort(*sources, f.sent.src, v4(f), f.dscp)
                &&& !is_node(*sources, f.sent.src, v4(f), f.dscp)
                &&& i < rows_of(*sources).len()
                &&& rows_of(*sources)[i as int] == f.sent.src
                &&& first_at(rows_of(*sources), f.sent.src, i as int)
            },
            Route::ControlSurface => {
                &&& stray(*sources, f)
                &&& at_control_surface(plan_of(*sources), dest_of_sent(f.sent))
            },
            Route::Unregistered => {
                &&& stray(*sources, f)
                &&& !at_control_surface(plan_of(*sources), dest_of_sent(f.sent))
                &&& allocatable(*sources, f.sent.src)
            },
            Route::Unknown => {
                &&& stray(*sources, f)
                &&& !at_control_surface(plan_of(*sources), dest_of_sent(f.sent))
                &&& !allocatable(*sources, f.sent.src)
            },
        },
))]
pub fn route(sources: &Sources, f: Frame) -> Route {
    let is_v4 = match f.sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { .. } => true,
    };
    let origin = sources.origin(Some(f.sent.src), is_v4, f.dscp);
    let leasable = match origin {
        Origin::Cohort => return Route::Cohort,
        Origin::Node => return Route::Node,
        Origin::Row(i) => return Route::Row(i),
        Origin::Unregistered => true,
        Origin::Unknown => false,
        Origin::NoSource => false,
    };
    let surface = match f.sent.kind {
        SentKind::Arp => false,
        SentKind::V4 { dst, proto, l4 } => {
            let port = match l4 {
                Some(x) => x.dport,
                None => 0,
            };
            let dns = (proto == PROTO_TCP || proto == PROTO_UDP) && port == DNS_PORT;
            dst == sources.plan().gateway() && !dns
        }
    };
    if surface {
        Route::ControlSurface
    } else if leasable {
        Route::Unregistered
    } else {
        Route::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::parse_frame;
    use crate::origin::{BOX_COHORT_DSCP, CohortSpelling};
    use crate::plan::Plan;

    // 100.64.0.0/24: gateway .1, leases .2 to .250, node .253.
    const NET: u32 = 0x6440_0000;
    const GW: u32 = NET + 1;
    const NODE: u32 = NET + 253;

    fn sources() -> Sources {
        let plan = Plan::new(NET, 24).unwrap();
        Sources::new(
            plan,
            vec![NET + 7, NODE],
            true,
            CohortSpelling::NodeWithMark,
        )
        .unwrap()
    }

    fn tcp(src: u32, dst: u32, dport: u16, dscp: u8) -> Frame {
        Frame {
            sent: Sent {
                src,
                kind: SentKind::V4 {
                    dst,
                    proto: 6,
                    l4: Some(SentL4 {
                        sport: 50000,
                        dport,
                        flags: 0x02,
                        seq: 0,
                        ack: 0,
                        payload_len: 0,
                    }),
                },
            },
            dscp,
        }
    }

    #[test]
    fn the_three_decisions_are_reached_by_source_alone() {
        let s = sources();
        assert_eq!(route(&s, tcp(NET + 7, GW, 80, 0)), Route::Row(0));
        assert_eq!(route(&s, tcp(NODE, GW, 80, 0)), Route::Node);
        assert_eq!(route(&s, tcp(NODE, GW, 80, BOX_COHORT_DSCP)), Route::Cohort);
    }

    #[test]
    fn a_stray_source_is_refused_and_the_control_surface_is_named_first() {
        let s = sources();
        assert_eq!(
            route(&s, tcp(NET + 8, 0xcb00_7107, 443, 0)),
            Route::Unregistered
        );
        assert_eq!(route(&s, tcp(NET + 8, GW, 80, 0)), Route::ControlSurface);
        assert_eq!(route(&s, tcp(NET + 8, GW, 53, 0)), Route::Unregistered);
        assert_eq!(
            route(&s, tcp(0x0a00_0001, 0xcb00_7107, 443, 0)),
            Route::Unknown
        );
        assert_eq!(
            route(&s, tcp(0x0a00_0001, GW, 80, 0)),
            Route::ControlSurface
        );
    }

    #[test]
    fn holds_agrees_with_the_rows() {
        let s = sources();
        assert!(s.holds(NET + 7) && s.holds(NODE));
        assert!(!s.holds(NET + 8));
    }

    #[test]
    fn a_frame_with_no_datagram_has_no_frame() {
        assert_eq!(frame_of(&parse_frame(&[0u8; 10])), Said::NotAFrame);
    }

    #[test]
    fn an_arp_packet_is_routed_by_its_sender() {
        // Ethernet/IPv4 ARP request from 100.64.0.7.
        let mut f = vec![0u8; 42];
        f[12] = 0x08;
        f[13] = 0x06;
        f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        f[28..32].copy_from_slice(&(NET + 7).to_be_bytes());
        let frame = match frame_of(&parse_frame(&f)) {
            Said::Frame(frame) => frame,
            Said::ShortHeader => panic!("an ARP packet is a frame"),
            Said::NotAFrame => panic!("an ARP packet is a frame"),
        };
        assert_eq!(frame.sent.kind, SentKind::Arp);
        assert_eq!(route(&sources(), frame), Route::Row(0));
    }

    /// An IPv4 datagram from 100.64.0.7 of `proto`, with `l4` bytes after a
    /// twenty-byte header and the given fragment field.
    fn datagram(proto: u8, frag: u16, l4: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 34];
        f[12] = 0x08;
        f[14] = 0x45;
        let total = (20 + l4.len()) as u16;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f[20..22].copy_from_slice(&frag.to_be_bytes());
        f[23] = proto;
        f[26..30].copy_from_slice(&(NET + 7).to_be_bytes());
        f[30..34].copy_from_slice(&GW.to_be_bytes());
        f.extend_from_slice(l4);
        f
    }

    #[test]
    fn a_short_header_is_no_frame() {
        // Four bytes where a UDP header needs eight, and where TCP needs twenty.
        assert_eq!(
            frame_of(&parse_frame(&datagram(17, 0, &[0, 53, 0, 53]))),
            Said::ShortHeader
        );
        assert_eq!(
            frame_of(&parse_frame(&datagram(6, 0, &[0, 80, 0, 80]))),
            Said::ShortHeader
        );
    }

    #[test]
    fn a_later_fragment_and_a_portless_protocol_are_frames_without_ports() {
        for (proto, frag) in [(17u8, 1u16), (6, 1), (1, 0)] {
            let frame = match frame_of(&parse_frame(&datagram(proto, frag, &[0, 53, 0, 53]))) {
                Said::Frame(frame) => frame,
                Said::ShortHeader => panic!("a frame without ports"),
                Said::NotAFrame => panic!("a frame without ports"),
            };
            assert_eq!(
                frame.sent.kind,
                SentKind::V4 {
                    dst: GW,
                    proto,
                    l4: None
                }
            );
        }
    }
}
