//! What a frame toward a box does to that box's tables, and the two cases in
//! which it is not delivered.
//!
//! Layer 5 of the crate, composition: it decides nothing the layers below did not. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The host gate delivers almost everything the switch sends toward a guest:
//! the port gate is the in-VM relay's. What the host gate does on the way is
//! record. A frame to a published port opens or refreshes a reply record; a
//! connect to a port nothing publishes is noted so its refusal can be
//! answered. Two frames are dropped: an opening packet from the egress
//! proxy's address toward a published port, and a new flow the reply table
//! has no room for.
//!
//! THEOREM IG1, for every box's tables and every frame toward it:
//!   (a) a frame is dropped only as a proxy opening toward a published port,
//!       as a flow refused at the reply table's capacity (G6 (e)), or as a
//!       frame for another box given to these tables (which
//!       [`crate::gate::Gate::ingress`] never does); a dropped frame changes
//!       no record, and at most the reply table's sweep instant;
//!   (b) a frame from the proxy's address never opens a record and is never
//!       noted;
//!   (c) a reply record is touched only for a published port, a note only
//!       for an unpublished one, and only TCP is noted;
//!   (d) each result changes at most one table, with that table's own
//!       guarantee (`inbound_post`, `noted_post`); the DNS tables are never
//!       changed here;
//!   (e) the tables still belong to the same box.
//!
//! THEOREM IG2, for every byte string and the facts read from it: a frame
//! reaches these tables only as a TCP or UDP first fragment with a whole
//! header ([`Heard::Transport`]); such a fragment without a whole header is
//! dropped and nothing is recorded ([`Heard::ShortHeader`]); every other
//! frame is delivered and nothing is recorded.
//!
//! Whether the port is published is an input here: [`crate::gate::Gate::ingress`]
//! reads it from its ledger of forwards. Reading DNS replies on the way
//! in stays in the shell and feeds [`crate::pins`].

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::flow::inbound_post;
use crate::flow::{ACK, Conversation, Inbound, SYN, TCP};
use crate::frame::{Facts, L4, Reason};
use crate::judge::{BoxTables, SentL4};
#[cfg(verus_keep_ghost)]
use crate::judge::{flows_same, notes_same, owners_same, pins_same, tinv};
#[cfg(verus_keep_ghost)]
use crate::notes::noted_post;
use crate::notes::{Noted, Segment};
use crate::time::Instant;

/// A TCP or UDP first fragment the switch sent toward a box. `l4.sport` is
/// the client's port and `l4.dport` the box's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Received {
    /// The client: the frame's source address.
    pub src: u32,
    /// The box: the frame's destination address.
    pub dst: u32,
    pub proto: u8,
    pub l4: SentL4,
}

/// What the facts of a frame toward a guest come to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Heard {
    /// A TCP or UDP first fragment with a whole header: for the tables.
    Transport(Received),
    /// Drop; nothing recorded: TCP or UDP on a first fragment without a
    /// whole header.
    ShortHeader,
    /// Deliver; nothing recorded: a fragment that is not the first.
    LaterFragment,
    /// Deliver; nothing recorded: a first fragment of a protocol without
    /// ports.
    NoPorts,
    /// Deliver; nothing recorded: not an IPv4 datagram, and not bytes that
    /// claim to be one: an ARP packet, IPv6, a VLAN tag, another EtherType.
    NotV4,
    /// Drop; nothing recorded: bytes too short for their header, an ARP
    /// packet of another shape, or an IPv4 header with a bad version, header
    /// length or total length. What is no frame leaving a guest is none
    /// toward one.
    Malformed(Reason),
}

/// What a frame toward a box did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum Seen {
    /// Deliver; nothing recorded: from the proxy's address, or not TCP at a
    /// port nothing publishes.
    Passed,
    /// Drop: an opening packet from the proxy's address toward a published
    /// port.
    ProxyOpening,
    /// Deliver: a port nothing publishes; the connect was noted or not, as
    /// the result says.
    Noted(Noted),
    /// A published port: deliver unless the result is a refusal for room.
    Flow(Inbound),
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn conv_in(r: Received) -> Conversation {
    Conversation { proto: r.proto, client: r.src, client_port: r.l4.sport, box_addr: r.dst, box_port: r.l4.dport }
}

pub open spec fn seg_in(r: Received) -> Segment {
    Segment {
        client: r.src,
        client_port: r.l4.sport,
        box_addr: r.dst,
        box_port: r.l4.dport,
        flags: r.l4.flags,
        seq: r.l4.seq,
        ack: r.l4.ack,
        payload_len: r.l4.payload_len,
    }
}

/// A TCP SYN without ACK.
pub open spec fn tcp_opening(r: Received) -> bool {
    r.proto == TCP && r.l4.flags & SYN != 0 && r.l4.flags & ACK == 0
}

/// Whether the frame is delivered.
pub open spec fn delivers(s: Seen) -> bool {
    match s {
        Seen::Passed => true,
        Seen::ProxyOpening => false,
        Seen::Noted(_) => true,
        Seen::Flow(x) => x != Inbound::TableFull && x != Inbound::NotThisBox,
    }
}

/// What `observe` promises of its result and of the tables before and after.
#[verifier::opaque]
pub open spec fn seen_post(proxy: int, before: BoxTables, after: BoxTables, r: Received, published: bool, now_ms: u64, s: Seen) -> bool {
    match s {
        Seen::Passed => {
            &&& r.src as int == proxy || (!published && r.proto != TCP)
            &&& !(r.src as int == proxy && published && tcp_opening(r))
            &&& flows_same(after.flows, before.flows)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Seen::ProxyOpening => {
            &&& r.src as int == proxy
            &&& published
            &&& tcp_opening(r)
            &&& flows_same(after.flows, before.flows)
            &&& notes_same(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Seen::Noted(n) => {
            &&& r.src as int != proxy
            &&& !published
            &&& r.proto == TCP
            &&& noted_post(before.notes, after.notes, seg_in(r), now_ms, n)
            &&& flows_same(after.flows, before.flows)
            &&& crate::notes::same_frame(after.notes, before.notes)
            &&& pins_same(after.pins, before.pins)
        },
        Seen::Flow(x) => {
            &&& r.src as int != proxy
            &&& published
            &&& inbound_post(before.flows, after.flows, conv_in(r), r.l4.flags, now_ms, x)
            &&& crate::flow::inbound_stamp(before.flows, after.flows, conv_in(r), r.l4.flags, now_ms)
            &&& notes_same(after.notes, before.notes)
            &&& crate::flow::same_frame(after.flows, before.flows)
            &&& pins_same(after.pins, before.pins)
        },
    }
}

/// The frame toward a guest, as its facts give it: for the tables only with
/// a transport header the decisions read.
pub open spec fn received_spec(facts: Facts) -> Heard {
    match facts {
        Facts::V4(v) => match v.l4 {
            L4::Tcp { sport, dport, flags, seq, ack, payload_len } => Heard::Transport(
                Received { src: v.src, dst: v.dst, proto: v.proto, l4: SentL4 { sport, dport, flags, seq, ack, payload_len } },
            ),
            L4::Udp { sport, dport, payload_at, payload_len } => Heard::Transport(
                Received { src: v.src, dst: v.dst, proto: v.proto, l4: SentL4 { sport, dport, flags: 0, seq: 0, ack: 0, payload_len } },
            ),
            L4::NoPorts => Heard::NoPorts,
            L4::LaterFragment => Heard::LaterFragment,
            L4::ShortHeader => Heard::ShortHeader,
        },
        Facts::Arp { eth_dst, eth_src, sender_mac, sender } => Heard::NotV4,
        Facts::Other(why) => if malformed(why) { Heard::Malformed(why) } else { Heard::NotV4 },
    }
}

/// The reader's reasons for bytes that claim a header and do not carry it:
/// every reason but the three that name another kind of frame.
pub open spec fn malformed(why: Reason) -> bool {
    why != Reason::Ipv6 && why != Reason::Vlan && why != Reason::OtherEtherType
}

/// Whether a frame the tables are not given is delivered. Of a frame for
/// the tables it says nothing: `delivers` does, of what the tables did.
pub open spec fn heard_delivers(h: Heard) -> bool {
    h != Heard::ShortHeader && !(h is Malformed)
}

/// IG2.
pub proof fn theorem_ig2_the_tables_see_whole_headers(b: Seq<u8>, facts: Facts)
    requires
        crate::frame::facts_sound(b, facts),
    ensures
        match received_spec(facts) {
            Heard::Transport(r) => crate::route::first_fragment(b) && crate::route::whole_header(b, r.proto),
            Heard::ShortHeader => {
                &&& facts is V4
                &&& crate::route::first_fragment(b)
                &&& b[23] == TCP || b[23] == crate::flow::UDP
                &&& !crate::route::whole_header(b, b[23])
            },
            Heard::LaterFragment => facts is V4 && !crate::route::first_fragment(b),
            Heard::NoPorts => facts is V4 && crate::route::first_fragment(b) && b[23] != TCP && b[23] != crate::flow::UDP,
            Heard::NotV4 => !(facts is V4) && !(facts matches Facts::Other(why) && malformed(why)),
            Heard::Malformed(why) => facts == Facts::Other(why) && malformed(why),
        },
{
    reveal(crate::frame::l4_sound);
}

/// IG3: what is no frame leaving a guest is none toward one. For every
/// reason the reader gives, the bytes are dropped toward a guest exactly when
/// they are reported leaving one under the rule for bytes that are no frame
/// (`report::TRUNCATED_IPV4`); IPv6, a VLAN tag and another EtherType, which
/// leaving a guest are dropped under rules of their own, are delivered toward
/// one and recorded nowhere.
pub proof fn theorem_ig3_no_frame_both_ways(why: Reason)
    ensures
        malformed(why) == (crate::report::reason_rule(why) == crate::report::TRUNCATED_IPV4),
        heard_delivers(received_spec(Facts::Other(why))) == !malformed(why),
        malformed(why) ==> received_spec(Facts::Other(why)) == Heard::Malformed(why),
        !malformed(why) ==> received_spec(Facts::Other(why)) == Heard::NotV4,
{
}

/// IG1 (d): whatever a frame toward a box did, the box's DNS tables and the
/// settings of its other two tables are as they were.
pub proof fn lemma_seen_post_keeps_the_rest(proxy: int, before: BoxTables, after: BoxTables, r: Received, published: bool, now_ms: u64, s: Seen)
    requires
        seen_post(proxy, before, after, r, published, now_ms, s),
    ensures
        pins_same(after.pins, before.pins),
        crate::flow::same_frame(after.flows, before.flows),
        crate::notes::same_frame(after.notes, before.notes),
{
    reveal(seen_post);
}

/// No table turned the frame away as another box's.
pub open spec fn for_this_box(s: Seen) -> bool {
    s != Seen::Flow(Inbound::NotThisBox) && s != Seen::Noted(Noted::NotThisBox)
}

/// A frame toward the address its tables belong to is not turned away as
/// another box's. Proof text: `seen_post` is opaque, and this is the one fact
/// the gate reads out of it.
pub proof fn lemma_seen_post_this_box(proxy: int, before: BoxTables, after: BoxTables, r: Received, published: bool, now_ms: u64, s: Seen)
    requires
        seen_post(proxy, before, after, r, published, now_ms, s),
        crate::flow::box_of(before.flows) == r.dst,
        crate::notes::box_of(before.notes) == r.dst,
    ensures
        for_this_box(s),
{
    reveal(seen_post);
}

} // verus!

/// The frame facts as a [`Heard`]: a [`Received`] for a TCP or UDP first
/// fragment with a whole header, and for anything else what is done with it.
/// IG2.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == received_spec(*facts),
))]
pub fn received_of(facts: &Facts) -> Heard {
    match facts {
        Facts::V4(v) => match v.l4 {
            L4::Tcp {
                sport,
                dport,
                flags,
                seq,
                ack,
                payload_len,
            } => Heard::Transport(Received {
                src: v.src,
                dst: v.dst,
                proto: v.proto,
                l4: SentL4 {
                    sport,
                    dport,
                    flags,
                    seq,
                    ack,
                    payload_len,
                },
            }),
            L4::Udp {
                sport,
                dport,
                payload_len,
                ..
            } => Heard::Transport(Received {
                src: v.src,
                dst: v.dst,
                proto: v.proto,
                l4: SentL4 {
                    sport,
                    dport,
                    flags: 0,
                    seq: 0,
                    ack: 0,
                    payload_len,
                },
            }),
            L4::NoPorts => Heard::NoPorts,
            L4::LaterFragment => Heard::LaterFragment,
            L4::ShortHeader => Heard::ShortHeader,
        },
        Facts::Arp { .. } => Heard::NotV4,
        Facts::Other(why) => match why {
            Reason::Ipv6 | Reason::Vlan | Reason::OtherEtherType => Heard::NotV4,
            Reason::Short
            | Reason::ArpShape
            | Reason::BadVersion
            | Reason::BadHeaderLength
            | Reason::BadTotalLength => Heard::Malformed(*why),
        },
    }
}

/// Records what a frame toward a box does to that box's tables. `proxy` is
/// the egress proxy's address; `published` says the gate's ledger holds a
/// forward to this box at the frame's destination port. IG1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(s =>
    requires
        tinv(*old(t)),
    ensures
        tinv(*final(t)),
        owners_same(*final(t), *old(t)),
        pins_same(final(t).pins, old(t).pins),
        seen_post(proxy as int, *old(t), *final(t), r, published, now.ms, s),
))]
pub fn observe(proxy: u32, t: &mut BoxTables, r: Received, published: bool, now: Instant) -> Seen {
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(seen_post);
    }
    if r.src == proxy {
        if published && r.proto == TCP && r.l4.flags & SYN != 0 && r.l4.flags & ACK == 0 {
            return Seen::ProxyOpening;
        }
        return Seen::Passed;
    }
    if !published {
        if r.proto != TCP {
            return Seen::Passed;
        }
        let s = Segment {
            client: r.src,
            client_port: r.l4.sport,
            box_addr: r.dst,
            box_port: r.l4.dport,
            flags: r.l4.flags,
            seq: r.l4.seq,
            ack: r.l4.ack,
            payload_len: r.l4.payload_len,
        };
        return Seen::Noted(t.notes.note_connect(s, now));
    }
    let c = Conversation {
        proto: r.proto,
        client: r.src,
        client_port: r.l4.sport,
        box_addr: r.dst,
        box_port: r.l4.dport,
    };
    Seen::Flow(t.flows.inbound(c, r.l4.flags, now))
}

/// Whether a result delivers the frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == delivers(s),
))]
pub fn seen_delivers(s: Seen) -> bool {
    match s {
        Seen::Passed => true,
        Seen::ProxyOpening => false,
        Seen::Noted(_) => true,
        Seen::Flow(x) => match x {
            Inbound::TableFull => false,
            Inbound::NotThisBox => false,
            Inbound::Opened => true,
            Inbound::Refreshed { .. } => true,
            Inbound::Ended => true,
            Inbound::Untracked => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Flows, RST, Windows};
    use crate::judge::{BoxNameRule, Judged, Lifts, Sent, SentKind, judge_row};
    use crate::notes::Notes;
    use crate::pins::{Limits, Pins};
    use crate::plan::Plan;
    use crate::policy::{Abilities, Declared, Enforced, Net, Rules, Section, effective};
    use crate::row::{Cidr, RowArm, RowRules};
    use crate::time::Span;

    // 100.64.0.0/24: gateway .1, proxy .252.
    const NET: u32 = 0x6440_0000;
    const GW: u32 = NET + 1;
    const BOX: u32 = NET + 7;
    const PROXY: u32 = NET + 252;

    fn tables() -> BoxTables {
        let windows = Windows {
            tcp_idle_ms: 300_000,
            tcp_closing_ms: 120_000,
            tcp_closed_ms: 5_000,
            udp_unreplied_ms: 30_000,
            udp_replied_ms: 300_000,
            evict_after_ms: None,
        };
        let limits = Limits {
            asked_cap: 4,
            asked_per_name: 2,
            admitted_cap: 8,
            admitted_per_name: 2,
            flows_cap: 2,
            flows_per_destination: 2,
            query_ms: 30_000,
            window_ms: 300_000,
            idle_ms: 86_400_000,
        };
        BoxTables {
            flows: Flows::new(BOX, 2, windows, Span { ms: 1_000 }).unwrap(),
            notes: Notes::new(BOX, 4, 2, Span { ms: 5_000 }).unwrap(),
            pins: Pins::new(BOX, limits).unwrap(),
        }
    }

    fn rcv(src: u32, proto: u8, sport: u16, flags: u8) -> Received {
        Received {
            src,
            dst: BOX,
            proto,
            l4: SentL4 {
                sport,
                dport: 8080,
                flags,
                seq: 100,
                ack: 0,
                payload_len: 0,
            },
        }
    }

    /// Rules through the one road: a declaration, enforced whole.
    fn made(r: RowRules) -> Rules {
        let net = |c: &Cidr| Net::V4(*c);
        let d = Declared {
            allow_subnets: match &r.allow_subnets {
                None => Section::Listed(vec![Net::V4(Cidr { addr: 0, prefix: 0 })]),
                Some(v) => Section::Listed(v.iter().map(net).collect()),
            },
            deny_subnets: Section::Listed(r.deny.iter().map(net).collect()),
            allow_protocols: match &r.allow_protocols {
                None => Section::Absent,
                Some(v) => Section::Listed(v.clone()),
            },
            laned: r.laned,
            host_address: false,
        };
        let host = Abilities {
            per_box_host_address: true,
        };
        match effective(&d, &host).enforced() {
            Enforced::Whole(e) => e.rules(),
            Enforced::Part(_) => panic!("every block is kept"),
        }
    }

    #[test]
    fn a_published_port_records_the_flow_and_an_unpublished_one_notes_the_connect() {
        let mut t = tables();
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(GW, TCP, 40000, SYN),
                true,
                Instant { ms: 0 }
            ),
            Seen::Flow(Inbound::Opened)
        );
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(GW, TCP, 40001, SYN),
                false,
                Instant { ms: 0 }
            ),
            Seen::Noted(Noted::Noted)
        );
        assert_eq!(t.flows.len(), 1);
    }

    #[test]
    fn the_proxy_never_opens_a_record_and_its_opening_at_a_published_port_is_dropped() {
        let mut t = tables();
        let opening = observe(
            PROXY,
            &mut t,
            rcv(PROXY, TCP, 40000, SYN),
            true,
            Instant { ms: 0 },
        );
        assert_eq!(opening, Seen::ProxyOpening);
        assert!(!seen_delivers(opening));
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(PROXY, TCP, 40000, SYN | ACK),
                true,
                Instant { ms: 0 }
            ),
            Seen::Passed
        );
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(PROXY, TCP, 40000, SYN),
                false,
                Instant { ms: 0 }
            ),
            Seen::Passed
        );
        assert_eq!(t.flows.len(), 0);
    }

    #[test]
    fn a_flow_the_table_has_no_room_for_is_not_delivered() {
        let mut t = tables();
        assert_eq!(
            observe(PROXY, &mut t, rcv(GW, TCP, 1, SYN), true, Instant { ms: 0 }),
            Seen::Flow(Inbound::Opened)
        );
        assert_eq!(
            observe(PROXY, &mut t, rcv(GW, TCP, 2, SYN), true, Instant { ms: 0 }),
            Seen::Flow(Inbound::Opened)
        );
        let third = observe(PROXY, &mut t, rcv(GW, TCP, 3, SYN), true, Instant { ms: 0 });
        assert!(matches!(third, Seen::Flow(Inbound::TableFull)));
        assert!(!seen_delivers(third));
        // An established flow keeps refreshing at the cap.
        assert_eq!(
            observe(PROXY, &mut t, rcv(GW, TCP, 1, ACK), true, Instant { ms: 1 }),
            Seen::Flow(Inbound::Refreshed { replied: false })
        );
    }

    #[test]
    fn only_tcp_is_noted_and_only_a_bare_syn() {
        let mut t = tables();
        assert_eq!(
            observe(PROXY, &mut t, rcv(GW, 17, 1, 0), false, Instant { ms: 0 }),
            Seen::Passed
        );
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(GW, TCP, 1, ACK),
                false,
                Instant { ms: 0 }
            ),
            Seen::Noted(Noted::NotAConnect)
        );
    }

    #[test]
    fn ingress_and_egress_meet_a_noted_connect_is_refused_by_the_box_once() {
        let plan = Plan::new(NET, 24).unwrap();
        let rules = made(RowRules {
            allow_protocols: None,
            deny: Vec::new(),
            allow_subnets: Some(Vec::new()),
            laned: false,
        });
        let quiet = Lifts {
            resolves_names: false,
            alias_by_name: false,
            box_name: BoxNameRule::Silent,
            box_name_dst: 0,
        };
        let mut t = tables();
        assert_eq!(
            observe(
                PROXY,
                &mut t,
                rcv(GW, TCP, 40000, SYN),
                false,
                Instant { ms: 0 }
            ),
            Seen::Noted(Noted::Noted)
        );
        let reset = Sent {
            src: BOX,
            kind: SentKind::V4 {
                dst: GW,
                proto: TCP,
                l4: Some(SentL4 {
                    sport: 8080,
                    dport: 40000,
                    flags: RST | ACK,
                    seq: 0,
                    ack: 101,
                    payload_len: 0,
                }),
            },
        };
        assert_eq!(
            judge_row(
                &plan,
                &rules,
                quiet,
                false,
                &mut t,
                reset,
                Instant { ms: 1 }
            ),
            Judged::Refusal
        );
        assert_eq!(
            judge_row(
                &plan,
                &rules,
                quiet,
                false,
                &mut t,
                reset,
                Instant { ms: 2 }
            ),
            Judged::Row(RowArm::ControlSurface)
        );
    }

    #[test]
    fn only_a_whole_header_is_for_the_tables() {
        use crate::frame::parse_frame;
        // An IPv4 datagram of `proto` with `l4` after a twenty-byte header.
        let datagram = |proto: u8, frag: u16, l4: &[u8]| {
            let mut f = vec![0u8; 34];
            f[12] = 0x08;
            f[14] = 0x45;
            f[16..18].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
            f[20..22].copy_from_slice(&frag.to_be_bytes());
            f[23] = proto;
            f.extend_from_slice(l4);
            f
        };
        let udp = [0xc3, 0x50, 0, 53, 0, 8, 0, 0];
        assert!(matches!(
            received_of(&parse_frame(&datagram(17, 0, &udp))),
            Heard::Transport(r) if r.l4.dport == 53
        ));
        assert_eq!(
            received_of(&parse_frame(&datagram(17, 0, &udp[..4]))),
            Heard::ShortHeader
        );
        assert_eq!(
            received_of(&parse_frame(&datagram(6, 0, &udp))),
            Heard::ShortHeader
        );
        assert_eq!(
            received_of(&parse_frame(&datagram(17, 1, &udp))),
            Heard::LaterFragment
        );
        assert_eq!(
            received_of(&parse_frame(&datagram(1, 0, &udp))),
            Heard::NoPorts
        );
        // Bytes too short for a header are no frame and are dropped.
        assert_eq!(
            received_of(&parse_frame(&[0u8; 10])),
            Heard::Malformed(Reason::Short)
        );
        // Another kind of frame is delivered, and nothing is recorded: IPv6,
        // and an EtherType the reader does not know.
        let mut v6 = vec![0u8; 54];
        v6[12] = 0x86;
        v6[13] = 0xdd;
        assert_eq!(received_of(&parse_frame(&v6)), Heard::NotV4);
        let mut other = vec![0u8; 60];
        other[12] = 0x88;
        other[13] = 0xcc;
        assert_eq!(received_of(&parse_frame(&other)), Heard::NotV4);
    }
}
