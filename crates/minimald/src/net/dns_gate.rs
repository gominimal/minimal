//! DNS-pinned egress admission at the relay (NET-066, NET-067, NET-136).
//!
//! The relay ([`super::switch`]) is the one place every one of a box's
//! frames passes, so it is the one place a name rule can be enforced as
//! *addresses*: the frame verdict already decides by destination, and this
//! gate is what turns "the box allows `github.com`" into "the box reaches
//! the addresses `github.com` resolved to, and nothing else".
//!
//! Three jobs, one per requirement:
//!
//! * **Pinning** (NET-066) — every DNS reply from the box's own resolver
//!   (the switch gateway, NET-079's carve-out address) that answers a query
//!   for a name the box's `egress.allow_dns_hosts` declared is split by the
//!   pure rebinding intersection ([`sessions::core::egress`]): the answers
//!   that survive the box's denies and the infrastructure deny set are
//!   admitted into a per-box table for [`ADMISSION_WINDOW`], and the relay's
//!   egress leg accepts a frame to an admitted address it would otherwise
//!   drop as an undeclared destination. A pin lifts only that one drop: the
//!   protocol rules keep governing pinned addresses, and a denied range
//!   stays refused whatever resolved into it.
//! * **Refusing denied ranges** (NET-067) — an answer the intersection
//!   refuses never enters the table, and each refusal says so through the
//!   session's rate limiter with the name and the answer, once per rule per
//!   minute — the same budget and the same log the frame drops share.
//! * **NODATA for the record types v1 does not carry** (NET-136) — AAAA,
//!   HTTPS (65) and SVCB (64) queries toward this box's resolver are
//!   answered empty by the relay itself and never written on to the switch,
//!   so the box has no IPv6 or alternative-endpoints path to chase (guest
//!   IPv6 has no admission path, NET-082) and nothing upstream can answer
//!   them differently.
//!
//! What the gate deliberately is not: a DNS server. Only the resolver
//! Minimal owns for the box is watched, only standard queries to it are
//! intercepted, and every reply — including one whose every answer was
//! refused — passes through to the box: resolution is honest; it is the
//! *connection* to a refused address that is not admitted.
//!
//! Two boundaries worth naming:
//!
//! * An undeclared `allow_dns_hosts` (`None`) pins nothing. The field's
//!   schema doc calls `None` "allow-all hosts", and for the *address*
//!   dimensions that is exactly right — but a name grant is the one thing in
//!   the egress policy that can lift another dimension's declared deny (an
//!   empty `allow_subnets`), so it is earned only by an entry. Reading it
//!   the other way would turn every deny-all box into a resolve-anything
//!   box, which is the opposite of what NET-063 established.
//! * A forged reply from the resolver's address — hairpinned through the
//!   switch by a peer — could pin an attacker-chosen address. The defense is
//!   the relay's own source-address check (NET-084), which is what stops
//!   any non-lease source from imitating the resolver; until it is in
//!   force, this gate inherits that hole rather than widening it, since it
//!   admits nothing the box could not already have reached by resolving
//!   through the real resolver.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::{RData, RecordType};

use super::policy::PolicyWarnLimiter;
use sessions::core::egress::{self, EgressRules, InfrastructureDenySet};

/// The port DNS is served on: the resolver's destination port on the query
/// leg and its source port on the reply leg.
const DNS_PORT: u16 = 53;

/// The `component` field every DNS-gate log line carries, matching the
/// answerer's `zone-answerer` convention.
const COMPONENT: &str = "dns-gate";

/// The admission window NET-066 admits one resolution's addresses for.
///
/// The window is not the rebinding defense — the intersection is: a denied
/// range is refused the moment it is answered, whenever that happens. The
/// window only bounds *staleness*, and its shape follows from what the box's
/// own resolver stack does: the box's libc holds no DNS cache of its own, so
/// every `getaddrinfo` rides the relay again and re-admits the addresses it
/// connects to. What the window has to cover on its own is the gap between
/// a resolution and the connection that uses it — a real toolchain's
/// resolve-then-connect (and the retry of a dropped idle connection) fits
/// comfortably inside five minutes, the system's other short-expiry window
/// (BEP-007's renewal boundary), without keeping a box's long-dead
/// resolutions reachable for the rest of its uptime.
pub(crate) const ADMISSION_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Sweep expired admissions once the table crosses this many entries,
/// bounding memory under a burst of distinct answers without a background
/// timer (the conntrack's pattern).
const ADMISSION_SWEEP_AT: usize = 4096;

/// Largest DNS datagram the gate reads — the answerer's bound: a DNS message
/// fits far below it, and a larger datagram is ignored rather than buffered
/// unbounded.
const MAX_DATAGRAM: usize = 4096;

/// One box's DNS-pinned admission state, built at attach and shared between
/// the relay's two legs through the [`super::switch::SessionGate`]: the
/// egress leg asks it what an undeclared-destination drop may be lifted for
/// and hands it the box's queries, the ingress leg hands it the resolver's
/// replies.
pub(crate) struct DnsGate {
    /// The names the box's `egress.allow_dns_hosts` declared, normalized to
    /// the form DNS names are matched in; `None` when the box declared no
    /// names, which pins nothing (see the module doc).
    names: Option<HashSet<String>>,
    /// The box's compiled egress rules: the subnet dimensions the
    /// intersection reads, and the resolver's address both legs gate on.
    rules: EgressRules,
    /// The infrastructure deny set the intersection subtracts from every
    /// answer (design §5.3, NET-067).
    infrastructure: InfrastructureDenySet,
    /// The addresses admitted by resolution, each with the instant its
    /// window ends.
    admitted: Mutex<HashMap<[u8; 4], Instant>>,
    /// The box's switch IP, the `session_id` of every log line and the
    /// limiter's key.
    label: String,
    /// The session's rate limiter, shared with the frame-drop warnings so
    /// every refusal line costs from the same per-box-per-rule budget.
    limiter: Arc<PolicyWarnLimiter>,
}

/// A DNS wire name in the form the allowlist matches: ASCII-lowercased,
/// with the root dot stripped — `github.com` for `GitHub.com.`.
fn normalized(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

impl DnsGate {
    /// Builds one box's gate at attach: the names its policy declared
    /// (normalized), the compiled egress rules the intersection reads, the
    /// switch's infrastructure deny set, and the session's shared limiter.
    pub(crate) fn new(
        label: &str,
        policy: Option<&sessions::EgressPolicy>,
        rules: EgressRules,
        infrastructure: InfrastructureDenySet,
        limiter: Arc<PolicyWarnLimiter>,
    ) -> Self {
        Self {
            names: policy
                .and_then(|policy| policy.allow_dns_hosts.as_ref())
                .map(|hosts| hosts.iter().map(|host| normalized(host)).collect()),
            rules,
            infrastructure,
            admitted: Mutex::new(HashMap::new()),
            label: label.to_string(),
            limiter,
        }
    }

    /// Whether `name` is one the box's policy allowed — the trigger for
    /// pinning. An undeclared allowlist allows no name.
    fn allows_name(&self, name: &str) -> bool {
        self.names
            .as_ref()
            .is_some_and(|names| names.contains(name))
    }

    /// The egress leg, NET-136: whether the datagram the box sent to `dst`
    /// is an AAAA, HTTPS or SVCB query to this box's resolver, and if so the
    /// NODATA reply to write back toward the box instead of forwarding the
    /// query — `None` means "not mine; forward".
    ///
    /// `None` is also the answer for anything that does not parse as a
    /// standard query: forwarding stays the default on every failure, so a
    /// malformed or truncated datagram is decided by the resolver it was
    /// addressed to, not invented an answer for here.
    pub(crate) fn intercept_query(&self, dst: &SocketAddrV4, datagram: &[u8]) -> Option<Vec<u8>> {
        if dst.ip().octets() != self.rules.resolver() || dst.port() != DNS_PORT {
            return None;
        }
        if datagram.len() > MAX_DATAGRAM {
            tracing::debug!(
                component = COMPONENT,
                session_id = %self.label,
                n = datagram.len(),
                "ignoring an oversized DNS query at the relay"
            );
            return None;
        }
        let query = match Message::from_vec(datagram) {
            Ok(query) => query,
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    session_id = %self.label,
                    %error,
                    "forwarding an unparseable DNS query"
                );
                return None;
            }
        };
        if query.metadata.message_type != MessageType::Query {
            return None;
        }
        let question = query.queries.first().cloned()?;
        let rtype = question.query_type();
        let name = normalized(&question.name().to_lowercase().to_string());
        if !matches!(
            rtype,
            RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
        ) {
            return None;
        }
        // NODATA (NET-136): NOERROR, the question echoed back, no answers —
        // the same id, so the box's resolver stack matches the reply to its
        // own query.
        let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&query.metadata);
        reply.metadata.response_code = ResponseCode::NoError;
        reply.add_query(question);
        tracing::debug!(
            component = COMPONENT,
            session_id = %self.label,
            name,
            query_type = ?rtype,
            answer = "nodata",
            "answered an empty-records lookup at the relay"
        );
        reply.to_vec().ok()
    }

    /// The ingress leg, NET-066 and NET-067: observes a datagram from `src`,
    /// and when it is a reply from this box's own resolver answering a query
    /// for a name the box allowed, splits its A answers by the rebinding
    /// intersection — the survivors are admitted for the window, and each
    /// refusal logs the name and the answer through the limiter.
    ///
    /// Every failure mode is quiet by design: a datagram that is not from
    /// the resolver, not a reply, not parseable, or carrying no question
    /// (there is no name to match) pins nothing, and the reply itself is
    /// never kept from the box.
    pub(crate) fn observe_response(&self, src: &SocketAddrV4, datagram: &[u8], now: Instant) {
        if src.ip().octets() != self.rules.resolver() || src.port() != DNS_PORT {
            return;
        }
        if datagram.len() > MAX_DATAGRAM {
            tracing::debug!(
                component = COMPONENT,
                session_id = %self.label,
                n = datagram.len(),
                "ignoring an oversized DNS reply at the relay"
            );
            return;
        }
        let message = match Message::from_vec(datagram) {
            Ok(message) => message,
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    session_id = %self.label,
                    %error,
                    "passing an unparseable DNS reply through unpinned"
                );
                return;
            }
        };
        if message.metadata.message_type != MessageType::Response {
            return;
        }
        // The question is the name the box asked for — the one thing a
        // reply can be matched to its policy by. A reply with no question
        // (some resolvers elide it, RFC 7858) fails closed: no name, no
        // pin. Matching the question rather than the answer records' own
        // names is also what makes a CNAME chain work (its A records carry
        // the chain target's name) while a forged record *owner* admits
        // nothing.
        let Some(question) = message.queries.first() else {
            return;
        };
        let asked = normalized(&question.name().to_lowercase().to_string());
        if !self.allows_name(&asked) {
            return;
        }
        // The addresses the name resolved to: every A record in the answer
        // section, whatever record owns them.
        let answers: Vec<[u8; 4]> = message
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(address.0.octets()),
                _ => None,
            })
            .collect();
        let split = egress::rebinding_intersection(
            &answers,
            self.rules.allow_subnets(),
            self.rules.deny_subnets(),
            &self.infrastructure,
        );
        self.admit(&asked, &split.admitted, now);
        for (address, refusal) in split.refused {
            self.limiter.warn_dns_refusal(
                &self.label,
                &asked,
                Ipv4Addr::from(address),
                refusal.rule(),
            );
        }
    }

    /// Admits `addresses` — one name's surviving answers — until
    /// `now` + [`ADMISSION_WINDOW`], with the window's one debug line: the
    /// name, the addresses, and how long they hold (the bundle's daemon log
    /// tail carries every admission this way).
    fn admit(&self, name: &str, addresses: &[[u8; 4]], now: Instant) {
        if addresses.is_empty() {
            return;
        }
        let expires = now + ADMISSION_WINDOW;
        let mut admitted = self
            .admitted
            .lock()
            .expect("DNS admission table mutex poisoned");
        for address in addresses {
            admitted.insert(*address, expires);
        }
        if admitted.len() > ADMISSION_SWEEP_AT {
            admitted.retain(|_, expiry| now < *expiry);
        }
        let addresses: Vec<Ipv4Addr> = addresses.iter().copied().map(Ipv4Addr::from).collect();
        tracing::debug!(
            component = COMPONENT,
            session_id = %self.label,
            name,
            ?addresses,
            window_secs = ADMISSION_WINDOW.as_secs(),
            "admitted a resolved name's addresses for the window"
        );
    }

    /// Whether `dst` is an address this box resolved from an allowed name
    /// and whose window still holds at `now` — the relay's one reason to
    /// lift an undeclared-destination drop (NET-066).
    pub(crate) fn admits_destination(&self, dst: [u8; 4], now: Instant) -> bool {
        let admitted = self
            .admitted
            .lock()
            .expect("DNS admission table mutex poisoned");
        admitted.get(&dst).is_some_and(|expires| now < *expires)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::switch::tests::{
        LEASE, RelayHarness, arp_frame, egress_tcp_frame, read_framed, spawn_test_relay,
    };
    use crate::net::switch::udp_datagram;
    use crate::test_harness::captured_log;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::io;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use tokio::io::AsyncWriteExt;

    /// The default switch subnet's gateway: the resolver every rule set and
    /// frame below is keyed to, the one the carve-out admits and this gate
    /// watches (100.64.0.1).
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

    /// The box that allows `github.com` and, by address, nothing else: TCP
    /// declared, no subnets, the one name — the proof sentence's box.
    fn github_only_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: Some(vec!["github.com".to_string()]),
                deny_subnets: None,
            }),
            ingress: None,
        }
    }

    /// The box that allows `example.com` and denies `10.9.9.0/24`: the
    /// denied-range refusal's box (NET-067).
    fn denied_range_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: Some(vec!["example.com".to_string()]),
                deny_subnets: Some(vec!["10.9.9.0/24".to_string()]),
            }),
            ingress: None,
        }
    }

    /// An Ethernet II + IPv4 + UDP frame carrying `payload` from
    /// `src`:`src_port` to `dst`:`dst_port`, with honest total lengths — the
    /// shape [`udp_datagram`] reads.
    fn udp_payload_frame(
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
        f.push(crate::net::switch::IPPROTO_UDP);
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

    /// The Ethernet header prefix the frames above share (the verdict reads
    /// only the EtherType and the IPv4 region).
    const ETH_FRAME_PREFIX: &[u8] = &[
        0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst MAC
        0x52, 0x54, 0x00, 0x00, 0x00, 0x02, // src MAC
        0x08, 0x00, // EtherType: IPv4
    ];

    /// A standard DNS query datagram for `name` of `rtype` (the answerer's
    /// encoder, so the gate reads exactly what a real resolver stack sends).
    fn dns_query(name: &str, rtype: RecordType) -> Vec<u8> {
        crate::net::answerer::encode_query(name, rtype)
    }

    /// A DNS reply datagram from the resolver: the id of a real exchange, the
    /// question echoed, and one A record per `answer`.
    fn dns_response(name: &str, answers: &[Ipv4Addr]) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("the query name parses");
        let mut response = Message::response(0x522a, OpCode::Query);
        response.metadata.message_type = MessageType::Response;
        response.add_query(Query::query(qname.clone(), RecordType::A));
        for address in answers {
            response.add_answer(Record::from_rdata(qname.clone(), 60, RData::A(A(*address))));
        }
        response.to_vec().expect("the reply encodes")
    }

    /// One frame as the switch side of the relay carries it: the 2-byte LE
    /// length prefix the ingress leg reads.
    fn wire_frame(frame: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(2 + frame.len());
        wire.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        wire.extend_from_slice(frame);
        wire
    }

    /// Reads one frame the relay wrote back toward the box, polling the
    /// nonblocking box end until it arrives: the test runtime is
    /// current-thread, so the box end is never blocked on, only polled
    /// between yields.
    async fn read_box_frame(harness: &RelayHarness) -> io::Result<Vec<u8>> {
        crate::net::switch::set_nonblocking(harness.box_end.as_raw_fd())?;
        let mut buf = vec![0u8; 1600];
        for _ in 0..500 {
            match (&harness.box_end).read(&mut buf) {
                Ok(n) if n > 0 => return Ok(buf[..n].to_vec()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no frame arrived from the relay",
        ))
    }

    /// A fresh gate over the `github_only_egress` policy, for the unit tests
    /// that drive the gate directly.
    fn test_gate() -> DnsGate {
        let policy = github_only_egress();
        let label = LEASE.to_string();
        DnsGate::new(
            &label,
            policy.egress.as_ref(),
            sessions::core::egress::EgressRules::from_policy(
                policy.egress.as_ref(),
                RESOLVER.octets(),
            ),
            InfrastructureDenySet::new(RESOLVER.octets(), [100, 64, 0, 254]),
            Arc::new(PolicyWarnLimiter::new()),
        )
    }

    /// The resolver's reply to a resolved name pins its addresses, so the
    /// box reaches them for the admission window and nothing else (NET-066,
    /// the proof sentence): forwarded verbatim when pinned, dropped when not,
    /// and the pin expires with the window.
    #[tokio::test]
    async fn dns_pinned_admission_window() {
        let mut harness = spawn_test_relay(&github_only_egress());

        // The box resolves github.com: the query rides the resolver
        // carve-out and reaches the switch verbatim.
        let query = udp_payload_frame(
            LEASE,
            40000,
            RESOLVER,
            53,
            &dns_query("github.com.", RecordType::A),
        );
        harness.box_end.write_all(&query).unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                .await
                .expect("the query is forwarded")
                .expect("the switch side stays open");
        assert_eq!(
            forwarded, query,
            "a query to the resolver is forwarded verbatim"
        );

        // The resolver answers with two addresses. The reply passes through
        // to the box, and the relay pins both.
        let response = dns_response(
            "github.com.",
            &[
                Ipv4Addr::new(140, 82, 121, 3),
                Ipv4Addr::new(140, 82, 121, 4),
            ],
        );
        let response_frame = udp_payload_frame(RESOLVER, 53, LEASE, 40000, &response);
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let passed = read_box_frame(&harness)
            .await
            .expect("the reply itself passes through to the box");
        assert_eq!(passed, response_frame, "a reply is never kept from the box");

        // Both pinned addresses are reachable, although the box declared no
        // subnet for either — the pin is the only thing that lifts the drop.
        for pinned in [
            Ipv4Addr::new(140, 82, 121, 3),
            Ipv4Addr::new(140, 82, 121, 4),
        ] {
            let connect = egress_tcp_frame(LEASE, pinned, 443);
            harness.box_end.write_all(&connect).unwrap();
            let out =
                tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                    .await
                    .expect("a pinned address is reachable for the window")
                    .expect("the switch side stays open");
            assert_eq!(out, connect, "{pinned} is a pinned address");
        }

        // Nothing else is: an address the name never resolved to stays
        // dropped, the sentinel standing in for everything decided before
        // it.
        let other = egress_tcp_frame(LEASE, Ipv4Addr::new(198, 51, 100, 7), 443);
        let sentinel = arp_frame();
        harness.box_end.write_all(&other).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(next, sentinel, "an unpinned address is refused");

        // The window is bounded: an admission holds exactly
        // [`ADMISSION_WINDOW`], checked against the injected clock the relay
        // does not share (the relay pins with `Instant::now()`).
        let gate = test_gate();
        let t0 = Instant::now();
        gate.admit("github.com", &[[140, 82, 121, 3]], t0);
        assert!(
            gate.admits_destination(
                [140, 82, 121, 3],
                t0 + ADMISSION_WINDOW - Duration::from_nanos(1)
            ),
            "the admission holds through the window"
        );
        assert!(
            !gate.admits_destination([140, 82, 121, 3], t0 + ADMISSION_WINDOW),
            "the admission expires with the window"
        );
        assert!(
            !gate.admits_destination([198, 51, 100, 7], t0),
            "an address the box never resolved is not admitted"
        );
    }

    /// An allowed name that resolves into a denied range is refused: the
    /// answer is never pinned, so the connection to it is never admitted —
    /// whether the range is the box's own `deny_subnets` or the
    /// infrastructure deny set — while the clean answers of the same reply
    /// are pinned and reachable (NET-067).
    #[tokio::test]
    async fn denied_range_resolution_refused() {
        let mut harness = spawn_test_relay(&denied_range_egress());

        let query = udp_payload_frame(
            LEASE,
            40000,
            RESOLVER,
            53,
            &dns_query("example.com.", RecordType::A),
        );
        harness.box_end.write_all(&query).unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                .await
                .expect("the query is forwarded")
                .expect("the switch side stays open");
        assert_eq!(forwarded, query);

        // One reply carrying three answers: the box's denied range, the
        // infrastructure's link-local metadata address, and a clean public
        // address.
        let response = dns_response(
            "example.com.",
            &[
                Ipv4Addr::new(140, 82, 121, 3),    // clean: pinned
                Ipv4Addr::new(10, 9, 9, 9),        // the box's deny_subnets: refused
                Ipv4Addr::new(169, 254, 169, 254), // infrastructure: refused
            ],
        );
        let response_frame = udp_payload_frame(RESOLVER, 53, LEASE, 40000, &response);
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let passed = read_box_frame(&harness)
            .await
            .expect("the reply itself passes through");
        assert_eq!(passed, response_frame);

        // The clean answer is pinned and reachable.
        let clean = egress_tcp_frame(LEASE, Ipv4Addr::new(140, 82, 121, 3), 443);
        harness.box_end.write_all(&clean).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the clean answer is reachable")
            .expect("the switch side stays open");
        assert_eq!(out, clean);

        // The denied answer is refused: the connection never reaches the
        // switch (the sentinel stands in for it).
        let denied = egress_tcp_frame(LEASE, Ipv4Addr::new(10, 9, 9, 9), 443);
        let sentinel = arp_frame();
        harness.box_end.write_all(&denied).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(next, sentinel, "a denied range is refused, name or no name");

        // And so is the infrastructure answer: had the intersection not
        // refused it, the pin would have lifted the undeclared-destination
        // drop and put the metadata address within reach.
        let metadata = egress_tcp_frame(LEASE, Ipv4Addr::new(169, 254, 169, 254), 443);
        harness.box_end.write_all(&metadata).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let last = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(last, sentinel, "the infrastructure deny set is refused");
    }

    /// NET-067's log: each refused answer says the name and the address, in
    /// one rate-limited warn line per rule per minute through the same
    /// limiter the frame drops use — a burst of the same refusals is one
    /// line per rule, not one per answer.
    #[tokio::test]
    async fn denied_range_resolution_logged() {
        let capture = captured_log();
        let mut harness = spawn_test_relay(&denied_range_egress());

        let query = udp_payload_frame(
            LEASE,
            40000,
            RESOLVER,
            53,
            &dns_query("example.com.", RecordType::A),
        );
        harness.box_end.write_all(&query).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the query is forwarded");

        let response = dns_response(
            "example.com.",
            &[
                Ipv4Addr::new(10, 9, 9, 9),
                Ipv4Addr::new(169, 254, 169, 254),
            ],
        );
        let response_frame = udp_payload_frame(RESOLVER, 53, LEASE, 40000, &response);
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the reply itself passes through");

        let logged = capture.contents();
        for expected in [
            "an allowed name resolved into a refused range",
            "name=\"example.com\"",
            "answer=10.9.9.9",
            "rule_matched=\"dns-rebinding-denied-subnet\"",
            "answer=169.254.169.254",
            "rule_matched=\"dns-rebinding-infrastructure\"",
            "session_id=\"100.64.0.9\"",
        ] {
            assert!(
                logged.contains(expected),
                "the refusal line must carry {expected:?}: {logged}"
            );
        }

        // The same refusals again, inside the minute: suppressed, one line
        // per rule stands.
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the second reply passes through too");
        assert_eq!(
            capture
                .contents()
                .matches("an allowed name resolved into a refused range")
                .count(),
            2,
            "one rate-limited line per rule, not one per answer: {}",
            capture.contents()
        );
    }

    /// NET-136: AAAA, HTTPS (65) and SVCB (64) queries toward this box's
    /// resolver are answered NODATA by the relay itself — a DNS reply with
    /// no answers — and never reach the switch, while an A query is
    /// forwarded, so the box can resolve at all.
    #[tokio::test]
    async fn aaaa_https_and_svcb_queries_are_nodata() {
        let mut harness = spawn_test_relay(&github_only_egress());

        for rtype in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let query =
                udp_payload_frame(LEASE, 40000, RESOLVER, 53, &dns_query("github.com.", rtype));
            harness.box_end.write_all(&query).unwrap();

            // The box gets its answer from the relay, not the resolver: the
            // reply comes from the resolver's address, to the query's source
            // port, and parses as a NODATA response to the same question.
            let reply_frame = read_box_frame(&harness)
                .await
                .expect("the relay answers the empty-records lookup");
            let (pkt, payload) = udp_datagram(&reply_frame)
                .unwrap_or_else(|| panic!("the reply is a UDP frame: {rtype:?}"));
            assert_eq!(
                pkt.src,
                SocketAddrV4::new(RESOLVER, 53),
                "from the resolver"
            );
            assert_eq!(
                pkt.dst,
                SocketAddrV4::new(LEASE, 40000),
                "to the query's source"
            );
            let reply = Message::from_vec(payload).expect("the reply is a DNS message");
            assert_eq!(
                reply.metadata.message_type,
                MessageType::Response,
                "the reply is a response"
            );
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "NODATA is NOERROR, not an error"
            );
            assert!(reply.answers.is_empty(), "NODATA answers nothing");
            assert_eq!(
                reply
                    .queries
                    .first()
                    .map(|q| (q.name().to_string(), q.query_type())),
                Some(("github.com.".to_string(), rtype)),
                "the question is echoed back"
            );

            // And the query never reached the switch: the sentinel written
            // after it is the next thing the switch sees.
            let sentinel = arp_frame();
            harness.box_end.write_all(&sentinel).unwrap();
            let next =
                tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                    .await
                    .expect("the relay keeps forwarding")
                    .expect("the switch side stays open");
            assert_eq!(
                next, sentinel,
                "the {rtype:?} query never reached the switch"
            );
        }

        // An A query is forwarded, not intercepted — resolution is the one
        // path no box can be denied (NET-079).
        let a_query = udp_payload_frame(
            LEASE,
            40001,
            RESOLVER,
            53,
            &dns_query("github.com.", RecordType::A),
        );
        harness.box_end.write_all(&a_query).unwrap();
        let forwarded =
            tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
                .await
                .expect("an A query is forwarded")
                .expect("the switch side stays open");
        assert_eq!(
            forwarded, a_query,
            "only the empty-records types are intercepted"
        );
    }

    /// The NODATA reply carries the question's own id, so the box's resolver
    /// stack matches it to its query — and a datagram to anywhere else, or
    /// of any other type, is left for the resolver to answer.
    #[test]
    fn nodata_reply_keeps_the_id_and_leaves_the_rest_alone() {
        let gate = test_gate();

        let query = dns_query("github.com.", RecordType::HTTPS);
        let id = Message::from_vec(&query).unwrap().metadata.id;
        let reply = gate
            .intercept_query(&SocketAddrV4::new(RESOLVER, 53), &query)
            .expect("an HTTPS query to the resolver is intercepted");
        let message = Message::from_vec(&reply).expect("the synthesized reply parses");
        assert_eq!(message.metadata.id, id, "the reply echoes the query's id");
        assert!(message.answers.is_empty());
        assert_eq!(
            message.queries.first().unwrap().query_type(),
            RecordType::HTTPS
        );

        // Not the resolver's address: not this gate's traffic.
        assert!(
            gate.intercept_query(&SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53), &query)
                .is_none(),
            "a query to another resolver is forwarded"
        );
        // Not port 53: not DNS.
        assert!(
            gate.intercept_query(&SocketAddrV4::new(RESOLVER, 5353), &query)
                .is_none(),
            "a query to another port is forwarded"
        );
        // An A query: forwarded, so resolution works.
        assert!(
            gate.intercept_query(
                &SocketAddrV4::new(RESOLVER, 53),
                &dns_query("github.com.", RecordType::A)
            )
            .is_none(),
            "an A query is forwarded"
        );
        // A response datagram to the gate's leg: nothing to intercept.
        assert!(
            gate.intercept_query(
                &SocketAddrV4::new(RESOLVER, 53),
                &dns_response("github.com.", &[Ipv4Addr::new(140, 82, 121, 3)])
            )
            .is_none(),
            "a response is never intercepted as a query"
        );
    }

    /// An undeclared `allow_dns_hosts` pins nothing — the deny-all-by-subnet
    /// box that declared no names gains no addresses by resolving — and a
    /// name outside the declared set pins nothing either.
    #[tokio::test]
    async fn undeclared_names_and_hosts_pin_nothing() {
        // The address-deny-all declaration of the existing egress proofs,
        // with no name list: resolving must not open it.
        let policy = sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: None,
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: None,
                deny_subnets: None,
            }),
            ingress: None,
        };
        let mut harness = spawn_test_relay(&policy);

        let query = udp_payload_frame(
            LEASE,
            40000,
            RESOLVER,
            53,
            &dns_query("anything.example.", RecordType::A),
        );
        harness.box_end.write_all(&query).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the query is forwarded");
        let response = dns_response("anything.example.", &[Ipv4Addr::new(203, 0, 113, 20)]);
        let response_frame = udp_payload_frame(RESOLVER, 53, LEASE, 40000, &response);
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the reply passes through");

        let connect = egress_tcp_frame(LEASE, Ipv4Addr::new(203, 0, 113, 20), 443);
        let sentinel = arp_frame();
        harness.box_end.write_all(&connect).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(
            next, sentinel,
            "a box that declared no names gains no addresses by resolving"
        );

        // And the named box pins nothing for a name it did not declare:
        // the intersection trigger is the declared name, not any name.
        let gate = test_gate();
        let now = Instant::now();
        gate.observe_response(
            &SocketAddrV4::new(RESOLVER, 53),
            &dns_response("not-declared.example.", &[Ipv4Addr::new(198, 51, 100, 9)]),
            now,
        );
        assert!(
            !gate.admits_destination([198, 51, 100, 9], now),
            "a name outside the declared set pins nothing"
        );
    }

    /// The reply from anywhere but the resolver is not observed, and a reply
    /// with no question section to match pins nothing (fail closed).
    #[test]
    fn only_the_resolver_and_only_named_replies_pin() {
        let gate = test_gate();
        let now = Instant::now();

        // A reply from another source: not this gate's business.
        let response = dns_response("github.com.", &[Ipv4Addr::new(198, 51, 100, 9)]);
        gate.observe_response(
            &SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53),
            &response,
            now,
        );
        assert!(
            !gate.admits_destination([198, 51, 100, 9], now),
            "a reply from a foreign source pins nothing"
        );

        // A reply with no question: no name to match, so nothing is pinned.
        let mut questionless = Message::response(0x522b, OpCode::Query);
        questionless.metadata.message_type = MessageType::Response;
        questionless.add_answer(Record::from_rdata(
            Name::from_utf8("github.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
        ));
        let bytes = questionless.to_vec().expect("the reply encodes");
        gate.observe_response(&SocketAddrV4::new(RESOLVER, 53), &bytes, now);
        assert!(
            !gate.admits_destination([198, 51, 100, 9], now),
            "a reply with no question to match pins nothing"
        );
    }
}
