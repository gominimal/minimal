//! The host-side DNS reading the gate keeps beside the network kernel's
//! tables, which decide: the library's reading of a question's name and id
//! ([`question_of`]), which the kernel does not read itself, the normal form
//! names are matched in ([`normalized`]), the deny-all drop line's reading
//! of a refused datagram ([`deny_all_line`], NET-141), the L4 addressing the
//! forwarded-flow table and the lines take ([`L4Packet`]), and the test
//! builders other modules' tests share.
//!
//! A row that declared `egress.allow_dns_hosts` has its undeclared
//! destinations decided by the kernel's DNS tables, which the registry
//! holds: the gate records the box's own questions there and offers them
//! the answers the switch returns toward the box, and the lines about both
//! are said from what the tables did.
//!
//! ## A deny-all box's queries (NET-141)
//!
//! A row that declares no subnet and no DNS host pins nothing, but the
//! resolver's port still takes its UDP queries, and a forwarded query
//! carries data out in the name it asks. The network kernel decides what
//! such a row may send the resolver: a whole standard query whose every
//! question is for a name below the box zone's apex, which the switch's
//! resolver answers without asking upstream. Anything else is dropped by the
//! relay before it reaches the switch, silently toward the guest and with a
//! rate-limited line naming the box and the name, which this module reads
//! for the line alone ([`deny_all_line`]). The in-VM gate answers the same
//! queries REFUSED first, as the precision copy honest clients meet; this
//! is the deciding copy, outside the VM.

use std::net::SocketAddrV4;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};

use crate::box_registry::BoxRecord;

/// IPv4 protocol number for TCP.
#[cfg(test)]
const IPPROTO_TCP: u8 = 6;
/// Largest DNS datagram the gate reads a question or an answer's lines from
/// — the answerer's bound: a DNS message fits far below it, and a larger
/// datagram is ignored rather than buffered unbounded.
pub(crate) const MAX_DATAGRAM: usize = 4096;

/// The L4 addressing of a TCP/UDP-over-IPv4 frame, built from the network
/// kernel's reading of it ([`crate::net::kernel_facts::l4_packet`]): the
/// ports, the TCP flags and the sequence numbers, in the shape the gate's
/// lines and checks take.
pub(crate) struct L4Packet {
    /// Source `ip:port` — the box's own lease and its ephemeral port.
    pub(crate) src: SocketAddrV4,
    /// Destination `ip:port`.
    pub(crate) dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub(crate) proto: u8,
    /// TCP flags byte; `0` for UDP.
    pub(crate) tcp_flags: u8,
    /// TCP sequence number; `0` for UDP.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no product code reads it: the kernel's reply tables take the frame's TCP \
                      fields from the kernel's own reading of the frame"
        )
    )]
    pub(crate) tcp_seq: u32,
    /// TCP acknowledgement number; `0` for UDP.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no product code reads it: the kernel's reply tables take the frame's TCP \
                      fields from the kernel's own reading of the frame"
        )
    )]
    pub(crate) tcp_ack: u32,
    /// TCP payload length in bytes — the IPv4 total length less both
    /// headers, bounded by the bytes the frame carries; `0` for UDP and for
    /// a TCP header too short to say.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no product code reads it: the kernel's reply tables take the frame's TCP \
                      fields from the kernel's own reading of the frame"
        )
    )]
    pub(crate) tcp_payload_len: u16,
}

/// The first question's name of a DNS query `datagram`, read by the
/// resolver library and normalized as the rows' names are matched, with the
/// query's id from the header's first two bytes; `None` when the library
/// reads no question.
pub(crate) fn question_of(datagram: &[u8]) -> Option<(String, u16)> {
    let id = u16::from_be_bytes([*datagram.first()?, *datagram.get(1)?]);
    let message = Message::from_vec(datagram).ok()?;
    let question = message.queries.first()?;
    Some((normalized(&question.name().to_lowercase().to_string()), id))
}

/// A DNS wire name in the form the row's declared names are matched in:
/// ASCII-lowercased, with the root dot stripped — `github.com` for
/// `GitHub.com.`. The same normalization the in-VM gate matches by.
pub(crate) fn normalized(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

/// Whether `name` is a name the drop line counts as inside the box zone: at
/// least one label below the apex, whose last two labels are exactly the
/// lowercase bytes of `min.internal`. For the line alone: it decides nothing.
fn names_in_zone(name: &Name) -> bool {
    let mut labels = name.iter();
    boxes::core::zone_answer::ZONE_APEX
        .rsplit('.')
        .all(|apex_label| labels.next_back() == Some(apex_label.as_bytes()))
        && labels.next_back().is_some()
}

/// What the drop line names for one DNS datagram the network kernel refused
/// from a row, or the cohort, that names nothing ([`deny_all_line`]).
pub(crate) struct DenyAllRefusal {
    /// The row the datagram's source resolved to.
    pub(crate) record: Arc<BoxRecord>,
    /// The datagram's first question, normalized the way names are matched
    /// here, or a placeholder in angle brackets when the datagram carried no
    /// question to name (unparseable, not a standard query, or no question
    /// at all).
    pub(crate) name: String,
    /// That question's record type, when it had one.
    pub(crate) query_type: Option<RecordType>,
    /// Whether the question named is for a name outside the box zone. When
    /// it is not, the datagram was refused for another reason (its class, a
    /// pointer, a fragment, a part that cannot be read), and the line says so.
    pub(crate) outside_zone: bool,
}

/// What the drop line names for a DNS datagram the network kernel already
/// refused: the first question for a name outside the box zone, or the
/// first question when every one is inside it, and its type, read for the
/// line alone. This decides nothing and is never asked before the kernel's
/// arm: whatever it reads, the datagram stays refused. `payload` is the UDP
/// payload the kernel's reading gave, `None` when there was none to take.
pub(crate) fn deny_all_line(record: Arc<BoxRecord>, payload: Option<&[u8]>) -> DenyAllRefusal {
    let (name, query_type, outside_zone) = deny_all_question(payload);
    DenyAllRefusal {
        record,
        name,
        query_type,
        outside_zone,
    }
}

/// The name and type a deny-all drop line names for a refused datagram's
/// `payload`, read for the line alone, with no row: the first question for
/// a name outside the box zone, else the first question, else a
/// placeholder in angle brackets; and whether the question named is for a
/// name outside the zone. [`deny_all_line`] for a row's refusal; the
/// cohort's line takes it bare, naming no box.
pub(crate) fn deny_all_question(payload: Option<&[u8]>) -> (String, Option<RecordType>, bool) {
    let placeholder = |name: &str| (name.to_string(), None, false);
    let Some(Ok(message)) = payload.map(Message::from_vec) else {
        return placeholder("<unparseable>");
    };
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
    {
        return placeholder("<not a standard query>");
    }
    let outside = message
        .queries
        .iter()
        .find(|question| !names_in_zone(question.name()));
    match outside.or_else(|| message.queries.first()) {
        Some(question) => (
            normalized(&question.name().to_lowercase().to_string()),
            Some(question.query_type()),
            outside.is_some(),
        ),
        None => placeholder("<no question>"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! The deny-all line's proofs (NET-141), plus the DNS wire builders the
    //! gate's relay-level proofs share: the datagrams a test answers a box's
    //! lookup with are built with the same resolver-stack encoder
    //! (`hickory_proto`) the gate reads them with, honest IPv4 and UDP
    //! lengths throughout, because the kernel's reading refuses any frame
    //! whose claimed lengths do not bound its payload.

    use std::net::Ipv4Addr;

    use boxes::EgressPolicy;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use switch::SwitchSubnet;

    use super::{IPPROTO_TCP, deny_all_line};
    use crate::box_registry::{BoxRegistration, BoxRegistry};

    /// IPv4 protocol number for UDP, for the frames the builders below write.
    const IPPROTO_UDP: u8 = 17;

    /// The address plan every registry below is built for — the same plan the
    /// rows were compiled against and the table's entries are keyed within.
    pub(crate) const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// The lease the published box below holds.
    pub(crate) const LEASE: [u8; 4] = [100, 64, 0, 9];

    /// The Ethernet header prefix the frames below share (the table reads
    /// only the EtherType and the IPv4 region).
    pub(crate) const ETH_FRAME_PREFIX: &[u8] = &[
        0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst MAC
        0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src MAC
        0x08, 0x00, // EtherType: IPv4
    ];

    /// An Ethernet II + IPv4 + UDP frame carrying `payload` from
    /// `src`:`src_port` to `dst`:`dst_port`, with honest total lengths — the
    /// shape [`udp_datagram`] reads.
    pub(crate) fn udp_payload_frame(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut f = Vec::with_capacity(ETH_FRAME_PREFIX.len() + total);
        f.extend_from_slice(ETH_FRAME_PREFIX);
        f.push(0x45); // IPv4, IHL 5
        f.push(0x00);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(IPPROTO_UDP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum: none
        f.extend_from_slice(payload);
        f
    }

    /// An Ethernet II + IPv4 + TCP frame from `src`:`src_port` to
    /// `dst`:`dst_port` with `flags` in its TCP header — the shape the flow
    /// retention reads a flow's identity and a flow's end from. Honest
    /// total length, a full 20-byte TCP header, no payload.
    pub(crate) fn tcp_frame(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let total = 20 + 20;
        let mut f = Vec::with_capacity(ETH_FRAME_PREFIX.len() + total);
        f.extend_from_slice(ETH_FRAME_PREFIX);
        f.push(0x45); // IPv4, IHL 5
        f.push(0x00);
        f.extend_from_slice(&(total as u16).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
        f.push(64); // TTL
        f.push(IPPROTO_TCP);
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // sequence
        f.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement
        f.push(0x50); // data offset: 5 words
        f.push(flags); // flags — the byte the flow retention reads
        f.extend_from_slice(&0u16.to_be_bytes()); // window
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum: none
        f.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        f
    }

    /// A standard DNS query datagram for `name`, carrying the id of the
    /// exchange its reply below answers (the same wire a resolver stack
    /// sends, built with the parser the table reads it with): the reply
    /// matching reads the id, so a query and the reply it expects share
    /// one.
    pub(crate) fn dns_query(name: &str) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("query name parses");
        let mut msg = Message::new(0x522a, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(qname, RecordType::A));
        msg.to_vec().expect("query encodes")
    }

    /// A DNS query datagram asking every one of `questions` in one message,
    /// in order — the multi-question shape a zone name in front could try
    /// to carry a second name past a first-question check in.
    pub(crate) fn dns_query_of(questions: &[(Name, RecordType)]) -> Vec<u8> {
        let mut msg = Message::new(0x522a, MessageType::Query, OpCode::Query);
        for (name, rtype) in questions {
            msg.add_query(Query::query(name.clone(), *rtype));
        }
        msg.to_vec().expect("query encodes")
    }

    /// `name` parsed as a query name.
    pub(crate) fn qname(name: &str) -> Name {
        Name::from_utf8(name).expect("query name parses")
    }

    /// A DNS reply datagram from the resolver: the id of a real exchange, the
    /// question echoed, and one A record per `answer`.
    pub(crate) fn dns_response(name: &str, answers: &[Ipv4Addr]) -> Vec<u8> {
        dns_response_with(0x522a, name, answers)
    }

    /// A DNS reply datagram like [`dns_response`], carrying `id` as the
    /// exchange's — the one field a reply that does not answer the box's own
    /// question gets wrong.
    pub(crate) fn dns_response_with(id: u16, name: &str, answers: &[Ipv4Addr]) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("the query name parses");
        let mut response = Message::response(id, OpCode::Query);
        response.metadata.message_type = MessageType::Response;
        response.add_query(Query::query(qname.clone(), RecordType::A));
        for address in answers {
            response.add_answer(Record::from_rdata(qname.clone(), 60, RData::A(A(*address))));
        }
        response.to_vec().expect("the reply encodes")
    }

    /// The box every pure proof below is decided for: `namespace`'s names
    /// beside an empty `allow_subnets` — every destination outside the
    /// answers is an undeclared one, so the table alone decides the box's
    /// reach — with a denied range subtracted from every answer.
    fn dns_box(
        registry: &BoxRegistry,
        namespace: &str,
        lease: [u8; 4],
        names: Vec<String>,
        deny: Vec<String>,
    ) {
        registry.register(
            BoxRegistration::new(namespace, Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![boxes::IpProto::Tcp]),
                    allow_subnets: Some(Vec::new()),
                    allow_dns_hosts: Some(names),
                    deny_subnets: (!deny.is_empty()).then_some(deny),
                }),
        );
    }

    /// The deny-all box: every `allow_*` dimension present and empty, the
    /// section `boxes::EgressPolicy::deny_all` materializes.
    fn deny_all_box(registry: &BoxRegistry, namespace: &str, lease: [u8; 4]) {
        registry.register(
            BoxRegistration::new(namespace, Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy::deny_all()),
        );
    }

    /// What the network kernel decides for `payload` sent from `lease` to the
    /// plan's resolver at DNS's port, by the configuration `registry` keeps:
    /// `Some((name, type))`, what the drop line names, when its arm refuses
    /// the query as from a row that names nothing; `None` otherwise.
    #[expect(
        clippy::unwrap_in_result,
        reason = "a test helper: a refused row the registry does not hold is the test's bug"
    )]
    fn deny_all_decision(
        registry: &BoxRegistry,
        lease: [u8; 4],
        payload: &[u8],
    ) -> Option<(String, Option<RecordType>)> {
        let frame = udp_payload_frame(
            Ipv4Addr::from(lease),
            40000,
            SUBNET.dns_server(),
            53,
            payload,
        );
        let first = registry
            .kernel_for_tests()
            .config()
            .egress_first(&frame, crate::net::kernel_config::ZONE_APEX_WIRE);
        let netcore::split::First::Frame {
            arm: netcore::split::Arm::RowDns(_),
            facts,
            ..
        } = first
        else {
            return None;
        };
        let record = registry
            .table()
            .by_source(lease)
            .expect("a refused row is registered");
        let payload = crate::net::kernel_facts::udp_datagram(&frame, &facts).map(|(_, p)| p);
        let line = deny_all_line(record, payload);
        Some((line.name, line.query_type))
    }

    /// NET-141's deny-all case, decided host-side by the network kernel for
    /// an own-address row that names nothing: a query passes only when every
    /// question is for a box-zone name below the apex, of any type (the
    /// resolver answers the zone itself), and is dropped otherwise: a name
    /// outside the zone in any record type, a datagram that is not a
    /// standard query, and a multi-question query hiding an outside name
    /// behind a zone name in front. The drop line names the first outside
    /// name, or the placeholder for what carries none.
    #[test]
    fn deny_all_row_passes_only_zone_lookups() {
        let registry = BoxRegistry::new(SUBNET);
        deny_all_box(&registry, "sealed", LEASE);
        let decide = |payload: &[u8]| deny_all_decision(&registry, LEASE, payload);

        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
        ] {
            assert_eq!(
                decide(&dns_query_of(&[(qname("example.com."), rtype)])),
                Some(("example.com".to_string(), Some(rtype))),
                "a {rtype:?} lookup outside the zone is dropped, naming the name"
            );
        }
        // A lookalike of the zone is outside it, and so is a name whose
        // labels only spell the zone through an escaped dot: the match is
        // label by label, not by string suffix.
        assert!(
            decide(&dns_query_of(&[(
                qname("web.min.internal.example.com."),
                RecordType::A
            )]))
            .is_some(),
            "a lookalike of the zone is outside it"
        );
        let escaped = Name::from_labels(vec![b"evil.min" as &[u8], b"internal"])
            .expect("a label may carry a dot");
        assert!(
            decide(&dns_query_of(&[(escaped, RecordType::A)])).is_some(),
            "a label holding an escaped dot is not a zone name"
        );

        // The case-bearing names below are built with `from_ascii`, which
        // keeps the case as the guest would put it on the wire; `qname`
        // (`from_utf8`) folds it to lowercase.
        let cased = |name: &str| Name::from_ascii(name).expect("query name parses");

        // Zone A lookups pass: a sibling and the host row (NET-003), the
        // root dot and the case of the labels below the apex notwithstanding.
        for name in [
            "web.min.internal.",
            "host.min.internal.",
            "host.min.internal",
            "X.min.internal.",
            "HOST.min.internal",
        ] {
            assert_eq!(
                decide(&dns_query_of(&[(cased(name), RecordType::A)])),
                None,
                "an A lookup of {name} passes"
            );
        }
        // The switch's resolver matches the zone by a case-sensitive
        // `.min.internal.` suffix, so it forwards upstream an A lookup that
        // spells the apex in any other case, and the apex itself: both drop.
        for name in [
            "x.MIN.INTERNAL.",
            "x.Min.Internal.",
            "x.min.INTERNAL.",
            "HOST.Min.Internal",
            "min.internal.",
            "MIN.INTERNAL.",
        ] {
            assert!(
                decide(&dns_query_of(&[(cased(name), RecordType::A)])).is_some(),
                "an A lookup of {name} is dropped"
            );
        }
        // Questions written out by hand, plain labels, class IN: the
        // header of a standard query with `questions.len()` questions, then
        // each name on the wire with its type.
        let by_hand = |questions: &[(&[u8], u16)]| {
            let count = u16::try_from(questions.len()).expect("a few questions");
            let mut payload = vec![0x52, 0x2a, 0x01, 0x00];
            payload.extend_from_slice(&count.to_be_bytes());
            payload.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            for (name, rtype) in questions {
                payload.extend_from_slice(name);
                payload.extend_from_slice(&rtype.to_be_bytes());
                payload.extend_from_slice(&[0, 1]);
            }
            payload
        };
        const WEB: &[u8] = b"\x03web\x03min\x08internal\x00";
        const DB: &[u8] = b"\x02db\x03min\x08internal\x00";
        const X: &[u8] = b"\x01x\x03min\x08internal\x00";

        // Two zone A questions written out with no pointer pass together:
        // every counted question is read, and each is a zone name.
        assert_eq!(
            decide(&by_hand(&[(WEB, 1), (DB, 1)])),
            None,
            "every question a plain zone A lookup passes"
        );
        // A multi-question zone query written by a
        // standard encoder carries a compression pointer, and is refused.
        // The switch's resolver rejects any query whose question count is
        // not one in any case, so no answer is lost.
        let encoded = dns_query_of(&[
            (qname("web.min.internal."), RecordType::A),
            (qname("db.min.internal."), RecordType::A),
        ]);
        let second = 12 + WEB.len() + 4;
        assert!(
            encoded[second..].contains(&0xc0),
            "the encoder writes the second question's suffix as a pointer"
        );
        assert_eq!(
            decide(&encoded),
            Some(("web.min.internal".to_string(), Some(RecordType::A))),
            "the encoded pair is refused for its pointer"
        );

        // A zone name asked for any type passes: the type is not read
        // (the resolver answers the zone itself).
        for name in ["x.min.internal.", "host.min.internal."] {
            for rtype in [
                RecordType::TXT,
                RecordType::MX,
                RecordType::SRV,
                RecordType::AAAA,
            ] {
                assert_eq!(
                    decide(&dns_query_of(&[(qname(name), rtype)])),
                    None,
                    "{rtype:?} for {name} passes"
                );
            }
        }

        // Every question is read: a zone name in front carries no outside
        // name past the check.
        assert_eq!(
            decide(&dns_query_of(&[
                (qname("web.min.internal."), RecordType::A),
                (qname("leak.example.com."), RecordType::A),
            ])),
            Some(("leak.example.com".to_string(), Some(RecordType::A))),
            "an outside name behind a zone A is dropped"
        );
        // Written out with no pointer, every question is a
        // plain zone question in class IN, and the type is not read.
        assert_eq!(
            decide(&by_hand(&[(X, 1), (X, 16)])),
            None,
            "a zone TXT behind a zone A passes"
        );
        // The same pair as a standard encoder writes it
        // carries a compression pointer (the second name is all pointer), and
        // is refused. The switch's resolver rejects any query whose question
        // count is not one in any case, so no answer is lost.
        let encoded = dns_query_of(&[
            (qname("x.min.internal."), RecordType::A),
            (qname("x.min.internal."), RecordType::TXT),
        ]);
        assert_eq!(encoded[12 + X.len() + 4], 0xc0);
        assert!(decide(&encoded).is_some(), "the encoded pair is refused");

        // Nothing that is not a standard query with a question passes: an
        // unparseable datagram, a reply-shaped one, and a query with no
        // question all fail closed.
        assert_eq!(
            decide(&[0xde, 0xad, 0xbe, 0xef, 0x00]),
            Some(("<unparseable>".to_string(), None)),
            "an unparseable datagram is dropped"
        );
        assert_eq!(
            decide(&dns_response(
                "example.com",
                &[Ipv4Addr::new(93, 184, 216, 34)]
            )),
            Some(("<not a standard query>".to_string(), None)),
            "a reply-shaped datagram is dropped"
        );
        assert_eq!(
            decide(&dns_query_of(&[])),
            Some(("<no question>".to_string(), None)),
            "a query with no question is dropped"
        );
    }

    /// The deny-all gate decides deny-all rows and nothing else: an
    /// allow-list row, a row with no egress declaration, a row whose names
    /// are closed but whose subnets are not, the node namespace (which every
    /// host-address box's frames ride) and an unregistered source are all
    /// left to the verdict and the pins, whatever their queries name.
    #[test]
    fn non_deny_all_rows_are_not_decided() {
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let open = [100, 64, 0, 10];
        registry.register(BoxRegistration::new(
            "open",
            Ipv4Addr::from(open),
            Ipv4Addr::LOCALHOST,
        ));
        let closed_names = [100, 64, 0, 11];
        registry.register(
            BoxRegistration::new(
                "closed-names",
                Ipv4Addr::from(closed_names),
                Ipv4Addr::LOCALHOST,
            )
            .with_egress_policy(EgressPolicy {
                allow_protocols: Some(Vec::new()),
                allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                allow_dns_hosts: Some(Vec::new()),
                deny_subnets: None,
            }),
        );
        let node = registry.register_node_namespace(7655);

        for (lease, row) in [
            (LEASE, "an allow-list row"),
            (open, "a row with no egress declaration"),
            (closed_names, "a row with closed names but open subnets"),
            (node.switch_addr().octets(), "the node namespace"),
            ([100, 64, 0, 12], "an unregistered source"),
        ] {
            for payload in [
                dns_query_of(&[(qname("example.com."), RecordType::A)]),
                dns_query_of(&[(qname("x.min.internal."), RecordType::TXT)]),
                vec![0xde, 0xad],
            ] {
                assert_eq!(
                    deny_all_decision(&registry, lease, &payload),
                    None,
                    "{row} is not decided by the deny-all gate"
                );
            }
        }
    }
}
