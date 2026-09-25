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
//!   admitted into a per-box table for [`ADMISSION_WINDOW`], capped at
//!   [`MAX_ADDRESSES_PER_NAME`] addresses per name per family (design
//!   §5.3), and the relay's egress leg accepts a frame to an admitted
//!   address it would otherwise drop as an undeclared destination. A pin
//!   lifts only that one drop: the protocol rules keep governing pinned
//!   addresses, and a denied range stays refused whatever resolved into it.
//!
//!   A pin the box *used* outlives its window. The first frame a pin
//!   admits establishes its flow, and an established flow keeps its
//!   admitted destination past window expiry until the flow ends (design
//!   §5.3's conntrack-aware retention): a `git clone` or a long keep-alive
//!   to an allowed name is not severed at the window's edge, while a *new*
//!   connection to the same address after the window is refused until the
//!   box re-resolves ([`admits_flow`]).
//! * **Refusing denied ranges** (NET-067) — an answer the intersection
//!   refuses never enters the table, and each refusal says so through the
//!   session's rate limiter with the name and the answer, once per name per
//!   rule per minute — the same budget and the same log the frame drops
//!   share.
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
//! An undeclared `allow_dns_hosts` (`None`) pins nothing. The field's
//! schema doc calls `None` "allow-all hosts", and for the *address*
//! dimensions that is exactly right — but a name grant is the one thing in
//! the egress policy that can lift another dimension's declared deny (an
//! empty `allow_subnets`), so it is earned only by an entry. Reading it the
//! other way would turn every deny-all box into a resolve-anything box,
//! which is the opposite of what NET-063 established.
//!
//! ## The window, and the one place this gate departs from design §5.3
//!
//! §5.3 defines the admission window as TTL-bounded — an answer holds for
//! its own TTL, floored at 600 s and capped at 24 h — where that cap is a
//! proposal in the design text. This gate ships a fixed
//! [`ADMISSION_WINDOW`] instead, as a deliberate deviation toward the tight
//! side, and names its reason:
//!
//! * A TTL-bounded window hands the *duration* of the box's grant to the
//!   upstream zone's TTL — a value the box's policy does not control and a
//!   rebinding-controlled zone can set to the cap. The fixed window keeps
//!   the duration in the box host, whatever the answer says about itself.
//! * §5.3's floor alone would double the reach every answer holds here.
//! * What the floor buys — covering the gap between resolution and use,
//!   and an application-level resolver cache outliving the box's own — is
//!   covered for established flows by the retention above, and for new
//!   connections by re-resolution: the box's libc holds no DNS cache, so
//!   every new `getaddrinfo` rides the relay again and re-admits. The one
//!   case the floor covers that this gate does not is an application that
//!   caches an answer for longer than five minutes and then opens a new
//!   connection to it; that connection is refused the way every undeclared
//!   destination is, and the application's retry re-resolves.
//!
//! ## Known loose ends, named so nobody has to re-derive them
//!
//! * The forward NODATA of NET-136 carries no SOA in its authority section,
//!   deliberately. An SOA is a statement by the zone's authority, and this
//!   gate is authoritative for no forward zone — there is no record it
//!   could honestly carry. The same crate's box-zone answerer does add one
//!   to every negative ([`super::answerer`], NET-124), because *it* owns
//!   its zone and because the host resolver it serves must cache the
//!   negative; the gate's empty answer serves the box's own resolver
//!   stack, which holds no cache to warm (the same fact the window's
//!   rationale rests on), so the omission costs one more relay ride per
//!   lookup and asserts no authority the gate lacks.
//! * Reply matching is loose, and the source check is the whole defence:
//!   the gate reads a reply's first question for the name and nothing
//!   else — not the query id, not the qtype, and not whether the box ever
//!   asked the question. A forged reply from the resolver's address —
//!   hairpinned through the switch by a peer — could pin an
//!   attacker-chosen address, and that defence is the relay's own
//!   source-address check (NET-084), which is what stops any non-lease
//!   source from imitating the resolver; until it is in force, this gate
//!   inherits that hole rather than widening it, since it admits nothing
//!   the box could not already have reached by resolving through the real
//!   resolver. Matching the id would need per-query state on the egress leg
//!   for a check that does not change what the box can reach.
//! * DNS over TCP is not carried. A deny-all box's TCP to the resolver is
//!   dropped by the frame verdict, so a `TC=1` answer cannot be retried
//!   over TCP and that resolution fails. Not a rebinding vector — the gate
//!   admits nothing on the TCP path — but a resolution failure this module
//!   records rather than fixes: the UDP datagram is the only DNS path v1
//!   carries, and the one the gate knows how to read.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::{RData, RecordType};

use super::policy::PolicyWarnLimiter;
use super::switch::L4Packet;
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
///
/// It is a *fixed* window where design §5.3's is TTL-bounded (floored at
/// 600 s, capped at 24 h); the module doc states that departure and its
/// reason. An established flow does not depend on it at all — see
/// [`admits_flow`].
pub(crate) const ADMISSION_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Design §5.3's cap on a name's admitted addresses: at most this many per
/// name per family, fail closed. A reply whose A records run past the cap
/// has its tail refused, so a hostile or pathological answer cannot grow
/// the box's grant one address at a time; the cap is what keeps the table
/// proportionate to the box's declared names rather than to what its
/// resolver chose to say. Only IPv4 addresses are ever admitted here (AAAA
/// is answered NODATA, NET-136), so the family half of the cap is the IPv4
/// half alone.
const MAX_ADDRESSES_PER_NAME: usize = 32;

/// Sweep expired admissions once the table crosses this many entries — the
/// per-box backstop behind the per-name cap, bounding memory without a
/// background timer (the conntrack's pattern).
const ADMISSION_SWEEP_AT: usize = 4096;

/// TCP FIN: the box's half-close, the end of its outbound use of a flow.
const TCP_FIN: u8 = 0x01;
/// TCP RST: an abortive end of a flow.
const TCP_RST: u8 = 0x04;

/// How long an established flow keeps its pinned destination with no frame
/// riding it (design §5.3): the retention's one memory bound. A day is
/// past any live transport's keep-alive interval and past every
/// retransmission schedule, so an idle day is a flow that ended without a
/// FIN — the bound exists so a flow the box leaked cannot hold its pin for
/// the rest of the box's uptime, which ends the whole table anyway.
const FLOW_IDLE_CAP: Duration = Duration::from_secs(24 * 60 * 60);

/// Sweep idle flows once the table crosses this many entries, bounding
/// memory under a box that opens more flows than it closes (the conntrack's
/// pattern again).
const FLOW_SWEEP_AT: usize = 4096;

/// Largest DNS datagram the gate reads — the answerer's bound: a DNS message
/// fits far below it, and a larger datagram is ignored rather than buffered
/// unbounded.
const MAX_DATAGRAM: usize = 4096;

/// One admitted address: the name whose resolution admitted it — §5.3's
/// cap is per name, so the owner is what the cap counts — and the instant
/// its window ends.
struct Admission {
    name: Arc<str>,
    expires: Instant,
}

/// The identity of one flow the box opened through a pin: the transport,
/// the destination, and the two ports. The source address is the box's own
/// lease — the one address the relay moves for it — so the ports are what
/// tells two flows to the same destination apart.
#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    /// The flow's IPv4 protocol number.
    proto: u8,
    /// The flow's source port, `0` when the transport has none.
    src_port: u16,
    /// The destination the pin admitted.
    dst: [u8; 4],
    /// The flow's destination port, `0` when the transport has none.
    dst_port: u16,
}

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
    /// The addresses admitted by resolution, each with the name that
    /// admitted it — §5.3's cap is per name, so the owner is what the cap
    /// counts — and the instant its window ends.
    admitted: Mutex<HashMap<[u8; 4], Admission>>,
    /// The flows the box opened through a pin — established while the
    /// window held, retained past it until the flow ends — each with the
    /// instant its last frame rode it (the idle bound's clock).
    flows: Mutex<HashMap<FlowKey, Instant>>,
    /// The admission window, [`ADMISSION_WINDOW`] in production. A field so
    /// the relay-level proof of the retention can shrink it: expiry cannot
    /// be observed in a test that would have to wait five minutes.
    window: Duration,
    /// The box's switch IP, the `session_id` of every log line and the
    /// limiter's key.
    label: String,
    /// The session's rate limiter, shared with the frame-drop warnings so
    /// every refusal line costs from the same per-box budget.
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
            flows: Mutex::new(HashMap::new()),
            window: ADMISSION_WINDOW,
            label: label.to_string(),
            limiter,
        }
    }

    /// Shrinks the admission window. A test hook for the one proof that
    /// needs it: the relay-level proof that an established flow outlives
    /// the window cannot be written against a five-minute window.
    #[cfg(test)]
    pub(crate) fn shrink_window(&mut self, window: Duration) {
        self.window = window;
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
    /// `now` + the admission window, with the window's one debug line: the
    /// name, the addresses, and how long they hold (the bundle's daemon log
    /// tail carries every admission this way).
    ///
    /// §5.3's cap is enforced here: a name holds at most
    /// [`MAX_ADDRESSES_PER_NAME`] addresses at once, counted over the whole
    /// table, so answers past the cap are refused (fail closed) and the
    /// table stays proportionate to the box's declared names rather than to
    /// what its resolver chose to say. An address a *different* allowed name
    /// already admitted keeps its first owner: it is one address either way,
    /// and re-owning it would let a second name's burst evict the first's.
    fn admit(&self, name: &str, addresses: &[[u8; 4]], now: Instant) {
        if addresses.is_empty() {
            return;
        }
        let expires = now + self.window;
        let mut admitted = self
            .admitted
            .lock()
            .expect("DNS admission table mutex poisoned");
        // How many addresses this name already holds — §5.3's per-name cap,
        // counted where it is spent. One scan per observed reply, on a table
        // the cap itself keeps small.
        let mut held = admitted
            .values()
            .filter(|admission| &*admission.name == name)
            .count();
        let mut admitted_now = Vec::new();
        let mut over_cap = Vec::new();
        for address in addresses {
            if let Some(existing) = admitted.get_mut(address) {
                // The name answered again: refresh the window it holds for,
                // under whichever owner first admitted the address.
                existing.expires = expires;
                admitted_now.push(*address);
                continue;
            }
            if held >= MAX_ADDRESSES_PER_NAME {
                over_cap.push(Ipv4Addr::from(*address));
                continue;
            }
            held += 1;
            admitted.insert(
                *address,
                Admission {
                    name: Arc::from(name),
                    expires,
                },
            );
            admitted_now.push(*address);
        }
        if admitted.len() > ADMISSION_SWEEP_AT {
            admitted.retain(|_, admission| now < admission.expires);
        }
        if !over_cap.is_empty() {
            tracing::debug!(
                component = COMPONENT,
                session_id = %self.label,
                name,
                ?over_cap,
                cap = MAX_ADDRESSES_PER_NAME,
                "refused a resolved name's answers past the per-name cap"
            );
        }
        let addresses: Vec<Ipv4Addr> = admitted_now.iter().copied().map(Ipv4Addr::from).collect();
        tracing::debug!(
            component = COMPONENT,
            session_id = %self.label,
            name,
            ?addresses,
            window_secs = self.window.as_secs(),
            "admitted a resolved name's addresses for the window"
        );
    }

    /// Whether `dst` is an address this box resolved from an allowed name
    /// and whose window still holds at `now` — the relay's one reason to
    /// lift an undeclared-destination drop for a *new* flow (NET-066).
    pub(crate) fn admits_destination(&self, dst: [u8; 4], now: Instant) -> bool {
        let admitted = self
            .admitted
            .lock()
            .expect("DNS admission table mutex poisoned");
        admitted
            .get(&dst)
            .is_some_and(|admission| now < admission.expires)
    }

    /// Whether the egress leg may lift an undeclared-destination drop for
    /// the frame whose L4 addressing was `pkt` and whose destination is
    /// `dst` (NET-066): the destination is inside its admission window, or
    /// the frame belongs to a flow a pin already established — design §5.3's
    /// conntrack-aware retention, which is what keeps an established flow's
    /// admitted destination past window expiry until the flow ends, so a
    /// `git clone` or a long keep-alive to an allowed name is not severed at
    /// the window's edge while a *new* connection to the same address is.
    ///
    /// The first frame a pin admits establishes its flow — the window's work
    /// is done at the first segment and the flow carries itself from there —
    /// and every later frame refreshes it. The flow ends when the box sends
    /// a FIN or RST on it, whose own segment is admitted as the flow's last
    /// frame, or when [`FLOW_IDLE_CAP`] reclaims a flow nothing has ridden
    /// for a day. `pkt` is `None` for a frame with no L4 header to read: no
    /// ports, no flow identity, so only the window can admit it.
    pub(crate) fn admits_flow(&self, dst: [u8; 4], pkt: Option<&L4Packet>, now: Instant) -> bool {
        let Some(pkt) = pkt else {
            return self.admits_destination(dst, now);
        };
        let key = FlowKey {
            proto: pkt.proto,
            src_port: pkt.src.port(),
            dst,
            dst_port: pkt.dst.port(),
        };
        // The flags byte is TCP's only (`parse_ipv4_l4` zeroes it for every
        // other transport), so a FIN or RST is a close exactly where one can
        // be signalled.
        let ends = pkt.tcp_flags & (TCP_FIN | TCP_RST) != 0;
        {
            let mut flows = self.flows.lock().expect("DNS flow table mutex poisoned");
            if flows.get(&key).is_some() {
                if ends {
                    flows.remove(&key);
                } else {
                    flows.insert(key, now);
                }
                return true;
            }
        }
        if !self.admits_destination(dst, now) {
            return false;
        }
        if ends {
            // A closing segment with no flow to end: nothing to retain, and
            // the window admits the frame itself.
            return true;
        }
        let mut flows = self.flows.lock().expect("DNS flow table mutex poisoned");
        flows.insert(key, now);
        if flows.len() > FLOW_SWEEP_AT {
            flows.retain(|_, seen| now.duration_since(*seen) < FLOW_IDLE_CAP);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::switch::tests::{
        ACK, LEASE, RelayHarness, SYN, arp_frame, egress_tcp_frame, egress_tcp_segment,
        read_framed, spawn_test_relay, spawn_test_relay_with,
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

    /// The box that allows two names and denies `10.9.9.0/24`: the
    /// denied-range refusal's box (NET-067). Two names, because the refusal
    /// log's requirement is the *name* and the answer — the log proof
    /// refuses each of them inside the limiter's interval and must hear both.
    fn denied_range_egress() -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: Some(vec!["example.com".to_string(), "other.example".to_string()]),
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

    /// A fresh gate over `policy`, on the default switch's resolver and
    /// infrastructure set, for the unit tests that drive the gate directly.
    fn gate_for(policy: &sessions::SessionPolicy) -> DnsGate {
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

    /// A fresh gate over the `github_only_egress` policy, for the unit tests
    /// that drive the gate directly.
    fn test_gate() -> DnsGate {
        gate_for(&github_only_egress())
    }

    /// Design §5.3's per-name cap: a name holds at most
    /// [`MAX_ADDRESSES_PER_NAME`] admitted addresses at once, so the tail of
    /// a reply past the cap is refused, fail closed — and a second name's
    /// addresses are admitted beside the first's, because the cap is per
    /// name, not per box. An address the table already holds is refreshed
    /// rather than counted again, so an ordinary re-resolution never pays
    /// the cap.
    #[test]
    fn admitted_addresses_are_capped_per_name() {
        let two_names = sessions::SessionPolicy {
            egress: Some(sessions::EgressPolicy {
                allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                allow_subnets: Some(Vec::new()),
                allow_dns_hosts: Some(vec!["github.com".to_string(), "second.example".to_string()]),
                deny_subnets: None,
            }),
            ingress: None,
        };
        let gate = gate_for(&two_names);
        let now = Instant::now();

        // One reply carrying more answers than the cap.
        let burst: Vec<[u8; 4]> = (0..MAX_ADDRESSES_PER_NAME + 4)
            .map(|host| [198, 51, 100, host as u8])
            .collect();
        gate.admit("github.com", &burst, now);
        for (index, address) in burst.iter().enumerate() {
            assert_eq!(
                gate.admits_destination(*address, now),
                index < MAX_ADDRESSES_PER_NAME,
                "the cap decides answer {index}, not the window"
            );
        }

        // Re-resolving the same name refreshes what it holds — nothing is
        // counted twice — and its over-cap tail stays refused.
        let later = now + Duration::from_secs(1);
        gate.admit("github.com", &burst, later);
        assert!(
            gate.admits_destination(burst[0], later),
            "an address the table already holds is refreshed, not re-counted"
        );
        assert!(
            !gate.admits_destination(burst[MAX_ADDRESSES_PER_NAME], later),
            "the over-cap tail stays refused"
        );

        // The cap is per name: a second name's addresses are admitted
        // beside the first name's full set.
        let second: Vec<[u8; 4]> = (0..4).map(|host| [203, 0, 113, host as u8]).collect();
        gate.admit("second.example", &second, later);
        for address in &second {
            assert!(
                gate.admits_destination(*address, later),
                "the cap bounds each name, not the box"
            );
        }
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

    /// Design §5.3's conntrack-aware retention, with NET-066's window as its
    /// bound: a flow the box opened through a pin while the window held
    /// keeps passing frames after the window has passed, until the box ends
    /// it — a `git clone` or a long keep-alive to an allowed name is not
    /// severed at the window's edge — while a *new* flow to the same
    /// destination after the window is refused until the box re-resolves,
    /// and the retained flow's end releases the destination.
    ///
    /// The window is the gate's own production constant, so the relay is
    /// spawned with a window short enough for its expiry to happen inside
    /// the test; the retention being proved is the part that does not
    /// depend on the window's length.
    #[tokio::test]
    async fn established_flow_keeps_its_pin_past_the_window() {
        const PINNED: Ipv4Addr = Ipv4Addr::new(140, 82, 121, 3);
        let mut harness = spawn_test_relay_with(&github_only_egress(), |gate| {
            gate.shrink_admission_window(Duration::from_secs(1));
        });

        // The box resolves github.com and the reply admits its address.
        let query = udp_payload_frame(
            LEASE,
            40000,
            RESOLVER,
            53,
            &dns_query("github.com.", RecordType::A),
        );
        harness.box_end.write_all(&query).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the query is forwarded");
        let response = dns_response("github.com.", &[PINNED]);
        let response_frame = udp_payload_frame(RESOLVER, 53, LEASE, 40000, &response);
        harness
            .switch
            .write_all(&wire_frame(&response_frame))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the reply itself passes through");

        // The connection opens inside the window: the SYN is admitted by
        // the pin, and the flow it opens is established.
        let syn = egress_tcp_segment(LEASE, 40000, PINNED, 443, SYN);
        harness.box_end.write_all(&syn).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the pinned connection opens")
            .expect("the switch side stays open");
        assert_eq!(out, syn, "the SYN is admitted inside the window");

        // The window passes, and with it the address it admitted.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // The established flow still passes its frames: the retention
        // belongs to the flow, and the flow has not ended.
        let data = egress_tcp_segment(LEASE, 40000, PINNED, 443, ACK);
        harness.box_end.write_all(&data).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("an established flow keeps its destination")
            .expect("the switch side stays open");
        assert_eq!(
            out, data,
            "an established flow passes frames past the window"
        );

        // A new flow to the same destination is not retained: only the flow
        // the pin established holds, so a fresh connection — from another
        // source port — is refused until the box re-resolves the name.
        let fresh = egress_tcp_segment(LEASE, 40001, PINNED, 443, SYN);
        let sentinel = arp_frame();
        harness.box_end.write_all(&fresh).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(next, sentinel, "a new flow after the window is refused");

        // The box ends the retained flow: the RST is the flow's own last
        // frame, so it is admitted with it.
        let rst = egress_tcp_segment(LEASE, 40000, PINNED, 443, TCP_RST);
        harness.box_end.write_all(&rst).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the flow's closing segment is admitted")
            .expect("the switch side stays open");
        assert_eq!(out, rst, "the RST that ends the flow rides it out");

        // And with the flow ended, the destination is not retained any
        // further: the same flow's next frame is refused as any other
        // undeclared destination.
        let after = egress_tcp_segment(LEASE, 40000, PINNED, 443, ACK);
        harness.box_end.write_all(&after).unwrap();
        harness.box_end.write_all(&sentinel).unwrap();
        let last = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the relay keeps deciding")
            .expect("the switch side stays open");
        assert_eq!(last, sentinel, "an ended flow releases its destination");

        // The window's expiry did not end the *pin's* honesty: re-resolving
        // the name admits the address again, and a new flow opens.
        let requery = udp_payload_frame(
            LEASE,
            40002,
            RESOLVER,
            53,
            &dns_query("github.com.", RecordType::A),
        );
        harness.box_end.write_all(&requery).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("the re-query is forwarded");
        harness
            .switch
            .write_all(&wire_frame(&udp_payload_frame(
                RESOLVER,
                53,
                LEASE,
                40002,
                &dns_response("github.com.", &[PINNED]),
            )))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the re-resolution reaches the box");
        let reopen = egress_tcp_segment(LEASE, 40003, PINNED, 443, SYN);
        harness.box_end.write_all(&reopen).unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), read_framed(&mut harness.switch))
            .await
            .expect("a re-resolved name opens a new flow")
            .expect("the switch side stays open");
        assert_eq!(out, reopen, "re-resolution admits the address again");
    }

    /// An allowed name that resolves into a denied range is refused: the
    /// answer is never pinned, so the connection to it is never admitted —
    /// whether the range is the box's own `deny_subnets` or the
    /// infrastructure deny set — while the clean answers of the same reply
    /// are pinned and reachable (NET-067).
    ///
    /// Of the two denied halves, only the infrastructure one is proved by
    /// the frame drops here, and that is inherent rather than an accident of
    /// the fixtures: the box's own `deny_subnets` is compiled into the frame
    /// verdict as well, so a frame to `10.9.9.9` would be dropped as a
    /// `DeniedSubnet` even had the intersection admitted it, while
    /// `169.254.169.254` is decided by no rule the verdict reads and is
    /// refused *only* because the pin was never granted. The intersection's
    /// refusal of the box's own deny range is proved where its effect lives,
    /// by the log line `denied_range_resolution_logged` asserts carries
    /// `dns-rebinding-denied-subnet`, and by the pure intersection's own
    /// proofs in `sessions::core::egress`.
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
    /// one rate-limited warn line per name per rule per minute through the
    /// same limiter the frame drops use — a burst of the same name's
    /// refusals is one line per rule, not one per answer, while a *second*
    /// refused name inside the interval is heard on its own line, because
    /// the requirement is the name and the answer per refusal.
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
            "one rate-limited line per name and rule, not one per answer: {}",
            capture.contents()
        );

        // A second refused *name*, inside the same interval and under the
        // same rule, is its own line: the rate limit keys on the name, so
        // the first name's burst cannot silence it (the requirement is the
        // name and the answer per refusal).
        let second = udp_payload_frame(
            RESOLVER,
            53,
            LEASE,
            40000,
            &dns_response("other.example.", &[Ipv4Addr::new(10, 9, 9, 10)]),
        );
        harness
            .switch
            .write_all(&wire_frame(&second))
            .await
            .unwrap();
        let _ = read_box_frame(&harness)
            .await
            .expect("the second name's reply passes through too");
        let logged = capture.contents();
        assert_eq!(
            logged
                .matches("an allowed name resolved into a refused range")
                .count(),
            3,
            "a second refused name is heard inside the interval: {logged}"
        );
        assert!(
            logged.contains("name=\"other.example\"") && logged.contains("answer=10.9.9.10"),
            "the second name's line carries its own name and answer: {logged}"
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
