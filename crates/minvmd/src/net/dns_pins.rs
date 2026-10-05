//! The host-side DNS admission table: NET-081's deciding copy of the
//! DNS-pinned egress admission (NET-066, NET-067).
//!
//! A row that declared `egress.allow_dns_hosts` has destinations its
//! compiled frame rules cannot carry — a name is not an address — and this
//! is the table that decides them, on the host, between the guest's vsock
//! shuttle and the switch: one entry per registered box, holding the
//! addresses that box's own lookups resolved to, and admitting the frame the
//! row would otherwise drop as an undeclared destination exactly when a live
//! pin names the frame's destination.
//!
//! Every pin is an answer the box's own query received, and nothing else.
//! The gate's ingress leg hands the table each DNS reply *on its way to the
//! guest* — a frame from the resolver Minimal owns for the box, toward the
//! box's switch address — and that is the one entrance: a reply-shaped frame
//! on the guest→switch leg is decided as any other frame and pins nothing,
//! whatever address it wears. Three conditions then decide a reply at that
//! entrance. It must be from the row's *own* resolver, asserted once at the
//! row's intake ([`DnsPins::entry`]): the resolver is a plan-derived
//! constant, so a row naming any other one — an in-guest address, an
//! upstream reached through NAT, or nothing but a drift between the table's
//! plan and the registry's — is refused its entry and logged, and no reply
//! can ever pin for it. It must answer one of the box's own outstanding
//! queries: the egress leg records each question the switch received — its
//! name, transaction id and source port, bounded by the shared cap and
//! expiry — and a reply matches by all three and then consumes its entry,
//! so an unsolicited or mismatched reply passes through unpinned, and a
//! replay of a matched one pins nothing more. And only the answer chain
//! pins: the chain starts at the question name, follows the CNAME records
//! in the answer section, and takes the A records whose owner is on it —
//! the authority and additional sections, a record owned by a name off the
//! chain, and every type but A (AAAA never pins in v1) are read past. The
//! table never resolves anything itself: a pin exists because the box asked
//! and something answered, which is what makes the pinned set the box's own
//! answers and nothing wider — whatever a relay replaced inside the VM
//! would do with the frames behind it, the destinations they may ride are
//! the ones the box's own answers named.
//!
//! The answers pass the rebinding intersection
//! ([`egress::rebinding_intersection`]) before they enter: each one is
//! subtracted against the row's `deny_subnets` and the infrastructure deny
//! set (NET-067), a refused answer never becomes a pin and each says so
//! through the gate's rate limiter in the shared refusal format, and the
//! survivors hold for the shared admission window, under the shared per-name
//! cap, with the shared used-pin retention past the window — the numbers
//! read from [`sessions::core::egress`], the one place both admission tables
//! hold them, so neither leg can drift from the other.
//!
//! ## Which copy decides
//!
//! On a VM-backed host this is the deciding copy: the box's frames reach it
//! before anything inside the VM can touch them, so a destination the box
//! did not declare is dropped here whatever the in-VM relay would say about
//! it. The in-VM gate (`minimald::net::dns_gate`) stays as the precision
//! copy — it intercepts the box's queries, answers the record types v1
//! does not carry (NET-136) itself, and pins from the same replies under the
//! same rules — so the decision is exact at the relay for the path the box
//! actually rides, and what the box may reach is decided outside the VM.
//!
//! ## Lifetime
//!
//! An entry is born from its row, keyed by the row's switch address, and
//! dies with it: the relay retires the boxes whose traffic it carried when
//! the connection ends ([`DnsPins::retire`], beside the withdrawal report
//! that ends their rows, NET-133), and a re-registered row starts a fresh
//! entry — fail closed, until the box's own lookups pin again — so no
//! declaration's answers can survive the row that declared them. The table
//! is bounded per box by the shared per-name cap, the shared flow cap and
//! the sweeps below, and per host by the plan's address run, the set of
//! addresses a row can exist at.
//!
//! ## What the host deliberately does not carry
//!
//! Two things the in-VM gate holds are the resolution's own and stay there.
//! The box-zone carve-out (NET-072) is one: a zone answer is validated by
//! the intersection there and never pinned anywhere, so a row that declares
//! a zone name in `allow_dns_hosts` gets the same reach here — none, reach
//! to a sibling being the connect-time conjunction's to decide (NET-073) —
//! with a refusal line saying what the answer resolved into. And the zone's
//! host row (`host.min.internal`, NET-003) is the other: the in-VM gate
//! passes its reply through unwarned because the daemon resolves it for the
//! box, where here a row that declared the name is asking for its grant, and
//! the refusal the mandated answer earns is a true one.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use sessions::core::egress::{
    self, DNS_ADMISSION_WINDOW, DNS_FLOW_IDLE_CAP, DNS_MAX_ADDRESSES_PER_NAME,
    DNS_MAX_FLOWS_PER_BOX, DNS_OUTSTANDING_QUERY_CAP, DNS_QUERY_EXPIRY, InfrastructureDenySet,
};
use switch::SwitchSubnet;

use crate::box_registry::{BoxRecord, BoxTable};
use crate::net::egress_gate::DropLimiter;

/// Ethernet II header length: destination MAC (6) + source MAC (6) +
/// `EtherType` (2).
const ETH_HDR: usize = 14;
/// `EtherType` for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// The port DNS is served on: the resolver the table watches answers at.
const DNS_PORT: u16 = 53;
/// TCP FIN: the box's half-close, the end of its outbound use of a flow.
const TCP_FIN: u8 = 0x01;
/// TCP RST: an abortive end of a flow.
const TCP_RST: u8 = 0x04;
/// Largest DNS datagram the table reads — the answerer's bound: a DNS
/// message fits far below it, and a larger datagram is ignored rather than
/// buffered unbounded.
const MAX_DATAGRAM: usize = 4096;
/// Sweep expired admissions once the table crosses this many entries —
/// this table's own memory bound behind the shared per-name cap, the same
/// bound the in-VM gate keeps (the conntrack's pattern, bounding memory
/// without a background timer). What reaches it is the entries of names
/// that stopped resolving: `admit` already releases a name's own expired
/// entries when it counts that name's cap.
const ADMISSION_SWEEP_AT: usize = 4096;
/// The least time between two sweeps of one box's flow table at its cap:
/// the sweep walks every entry the table holds, and at the shared cap's size
/// that costs tens of microseconds, so it runs at most once per second per
/// box, never once per frame — under attack the table is full of live flows
/// and every sweep reclaims nothing, so the frames between two sweeps are
/// saved the walk without the bound narrowing.
const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// The least time between two at-cap `info` lines for one box: the line
/// names the box, the cap and how many frames the cap has admitted without
/// retention, and while the cap holds it says so at most once per minute —
/// minvmd's default filter is `info`, so the state reads in a bundle's log
/// tail without a line per frame spending the log on one hostile box.
const AT_CAP_LINE_INTERVAL: Duration = Duration::from_secs(60);

/// The L4 addressing of a TCP/UDP-over-IPv4 frame, as extracted by
/// [`parse_ipv4_l4`] — the one read the shared frame summary does not carry
/// (it holds the destination and its port, not the source port or the TCP
/// flags the flow retention reads), so the table parses its own, in the same
/// shape and with the same bounds checks as the in-VM relay's
/// (`minimald::net::switch::parse_ipv4_l4`): one parse per frame,
/// allocation-free, everything length-checked before it happens.
pub(crate) struct L4Packet {
    /// Source `ip:port` — the box's own lease and its ephemeral port.
    pub(crate) src: SocketAddrV4,
    /// Destination `ip:port`.
    pub(crate) dst: SocketAddrV4,
    /// IPv4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub(crate) proto: u8,
    /// TCP flags byte; `0` for UDP.
    pub(crate) tcp_flags: u8,
}

/// Parses an Ethernet II + IPv4 + TCP/UDP frame into its L4 addressing, or
/// `None` for non-IPv4 (ARP/IPv6/VLAN), non-TCP/UDP, IP fragments, and
/// short/malformed frames — a truncated or hostile frame yields `None`, never
/// an out-of-bounds read.
pub(crate) fn parse_ipv4_l4(frame: &[u8]) -> Option<L4Packet> {
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
    // fragment with no L4 header at `ihl`; pass rather than misparse.
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
    Some(L4Packet {
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
    })
}

/// Whether an Ethernet frame's IPv4 protocol byte says UDP — a pre-check,
/// not a parse: the EtherType and the one protocol byte, nothing else, so
/// the relay's ingress hot path — mostly a peer's TCP frames, which this
/// table can never observe — spends three comparisons per frame instead of
/// the full [`udp_datagram`] parse. A frame that says UDP here is still
/// parsed and length-checked before the table reads a word of it.
pub(crate) fn is_ipv4_udp(frame: &[u8]) -> bool {
    frame
        .get(12..14)
        .is_some_and(|ether| *ether == ETHERTYPE_IPV4.to_be_bytes())
        && frame
            .get(ETH_HDR + 9)
            .is_some_and(|proto| *proto == IPPROTO_UDP)
}

/// The UDP datagram one Ethernet frame carries — its L4 addressing plus the
/// datagram's payload — or `None` for anything that is not an IPv4+UDP
/// frame, or whose claimed lengths do not bound its own payload. The IPv4
/// total length bounds the datagram and the UDP length bounds the header it
/// names, so a hostile frame yields `None` — never an out-of-bounds slice,
/// and never a slice padded out to the Ethernet frame's end: the datagram
/// is `total` bytes, whatever the frame around it claims to be.
pub(crate) fn udp_datagram(frame: &[u8]) -> Option<(L4Packet, &[u8])> {
    let pkt = parse_ipv4_l4(frame).filter(|pkt| pkt.proto == IPPROTO_UDP)?;
    let payload = udp_payload(frame, &pkt)?;
    Some((pkt, payload))
}

/// The payload of the UDP datagram one frame carries, for a caller already
/// holding that frame's own [`parse_ipv4_l4`] result. The length contract is
/// [`udp_datagram`]'s: a claimed length that does not bound a payload yields
/// `None`, so a mismatched `pkt` can only cost a parse, never panic.
fn udp_payload<'a>(frame: &'a [u8], pkt: &L4Packet) -> Option<&'a [u8]> {
    if pkt.proto != IPPROTO_UDP {
        return None;
    }
    let ip = frame.get(ETH_HDR..)?;
    let ihl = ((ip.first()? & 0x0f) as usize) * 4;
    // The IPv4 total length bounds the datagram; a total shorter than its
    // own headers (including the `0` an offload'd frame carries) is not a
    // datagram this table reads.
    let total = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
    if total < ihl + 8 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    // A UDP length shorter than its own header is malformed; a longer one is
    // trimmed to the IP total, which is the datagram's real bound.
    let udp_len = u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]) as usize;
    if udp_len < 8 {
        return None;
    }
    let end = total.min(ip.len());
    let payload_end = (ihl + udp_len).min(end);
    udp.get(8..payload_end - ihl)
}

/// One admitted address: the name whose resolution admitted it — the
/// per-name cap counts by its owner — and the instant its window ends.
struct Admission {
    name: Arc<str>,
    expires: Instant,
}

/// The identity of one flow the box opened through a pin: the transport, the
/// destination, and the two ports. The source address is the box's own lease
/// — the one address the frame's row holds — so the ports are what tells two
/// flows to the same destination apart.
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

/// The box's flow table: the flows its pins established beside the two
/// instants their bounds spend — the sweep's and the at-cap line's, both
/// rate limiters on work the cap would otherwise redo per frame. One
/// mutex's worth of state, so the insert path reads and spends them under
/// the lock it already holds ([`BoxPins::flows`]).
#[derive(Default)]
struct FlowTable {
    /// The flows the box opened through a pin — established while the window
    /// held, retained past it until the flow ends — each with the instant its
    /// last frame rode it (the idle bound's clock).
    flows: HashMap<FlowKey, Instant>,
    /// The instant of the last sweep, `None` before the first: a sweep runs
    /// at most once per [`FLOW_SWEEP_INTERVAL`] per box, never once per
    /// frame.
    last_sweep: Option<Instant>,
    /// The instant of the last at-cap `info` line, `None` before the first:
    /// the line is written at most once per [`AT_CAP_LINE_INTERVAL`] per box.
    last_at_cap_line: Option<Instant>,
}

impl FlowTable {
    /// An empty table, before any flow was opened through a pin.
    fn new() -> Self {
        Self::default()
    }

    /// Whether the cap's sweep may run at `now`: at most once per second per
    /// box, never once per frame — the sweep walks every entry the table
    /// holds, and at the shared cap's size that costs tens of microseconds a
    /// frame would otherwise pay to reclaim nothing, since under attack the
    /// table is full of live flows.
    fn sweep_due(&self, now: Instant) -> bool {
        self.last_sweep
            .is_none_or(|at| now.duration_since(at) >= FLOW_SWEEP_INTERVAL)
    }

    /// Reclaims the flows idle past the shared idle cap — the entries no
    /// frame has come back to look up, so the cap is spent on live flows —
    /// and records the instant, which is what holds the sweep to once per
    /// second per box.
    fn sweep(&mut self, now: Instant) {
        self.flows
            .retain(|_, seen| now.duration_since(*seen) < DNS_FLOW_IDLE_CAP);
        self.last_sweep = Some(now);
    }

    /// Claims the at-cap `info` line for `now`: `true` exactly when no line
    /// was written inside the last [`AT_CAP_LINE_INTERVAL`], recording this
    /// instant either way — the check-and-spend happens under the flow
    /// table's lock, so two frames racing at the cap still write at most one
    /// line per box per interval.
    fn claim_at_cap_line(&mut self, now: Instant) -> bool {
        let due = self
            .last_at_cap_line
            .is_none_or(|at| now.duration_since(at) >= AT_CAP_LINE_INTERVAL);
        if due {
            self.last_at_cap_line = Some(now);
        }
        due
    }
}

/// The identity of one of the box's outstanding DNS queries — the three
/// things a reply must answer to pin: the transaction id of the exchange, the
/// port the query left from (which the reply's destination port must name),
/// and the question, normalized as the declared names are. The box's own
/// lease is the one address the entry holds, so the id and the port pair are
/// what tells two lookups apart.
#[derive(Hash, PartialEq, Eq)]
struct QueryKey {
    /// The DNS transaction id: the one field of an exchange a reply echoes.
    txid: u16,
    /// The query's source port, which its reply's destination port names.
    src_port: u16,
    /// The question the box asked, in the form the declared names match in.
    name: String,
}

/// One box's host-side admission state, built from its row and keyed by the
/// row's switch address: the names the row declared (normalized to the form
/// DNS names are matched in), the infrastructure deny set its answers are
/// intersected with, the box's outstanding questions a reply must answer, and
/// the admitted addresses and flows themselves. Holds
/// the row it was built from, both to read its rules without a second table
/// and to prove it is still the row the table holds — a re-registration
/// replaces the entry rather than trusting a newer declaration with an older
/// declaration's pins.
struct BoxPins {
    /// The row this entry was built from — the declaration every pin it
    /// holds was granted by.
    record: Arc<BoxRecord>,
    /// The names the row's `egress.allow_dns_hosts` declared, normalized to
    /// the form DNS names are matched in. A reply answering anything else
    /// pins nothing here: the grant is the declaration's own, and an
    /// undeclared `allow_dns_hosts` (an empty list in the row) earns no
    /// entry at all.
    names: HashSet<String>,
    /// The infrastructure deny set the intersection subtracts from every
    /// answer (design §5.3, NET-067), built from the row's own resolver and
    /// the subnet's host alias the way the in-VM gate builds its own. The
    /// host alias the set carries is what a `host.min.internal` reply
    /// resolves into: a row that declared the name is asking for its
    /// grant, and the refusal its answer earns is this table's to say,
    /// once, rate-limited (see the module doc).
    infrastructure: InfrastructureDenySet,
    /// The box's outstanding DNS queries to its resolver — the questions the
    /// switch received, each with the instant it was asked for the shared
    /// expiry — which a reply must answer to pin ([`QueryKey`]). Bounded by
    /// the shared cap: past it a question is not recorded and its reply
    /// pins nothing, fail closed, and expired entries are swept at the
    /// insert that would share their map, the same no-timer discipline the
    /// admitted addresses keep.
    outstanding: Mutex<HashMap<QueryKey, Instant>>,
    /// The addresses admitted by resolution, each with the name that
    /// admitted it — the per-name cap counts by owner — and the instant its
    /// window ends.
    admitted: Mutex<HashMap<[u8; 4], Admission>>,
    /// The box's flow table: the flows it opened through a pin — established
    /// while the window held, retained past it until the flow ends, each
    /// with the instant its last frame rode it (the idle bound's clock) —
    /// beside the sweep's and the at-cap line's rate-limit instants
    /// ([`FlowTable`]), so the cap's work is bounded per second and per
    /// minute, never per frame. Bounded by the shared per-box cap: a new
    /// flow that finds the table full is admitted by the window alone and
    /// not retained, fail closed at the window's edge, so a hostile relay
    /// holding one pin cannot grow the host daemon's memory one flow at a
    /// time.
    flows: Mutex<FlowTable>,
    /// How many frames the cap admitted by the window alone, without
    /// retention (the at-cap state's counter: the number the box's at-cap
    /// `info` line carries, the state a status surface would read once a
    /// control verb exists — a follow-up). An `AtomicU64` for the same
    /// reason every counter below is one: the entry is shared behind an
    /// `Arc` and `admits` takes `&self`.
    at_cap_admitted: AtomicU64,
    /// How many sweeps the flow table's cap has run. Test-facing, like the
    /// table's own counters: maintained at the sweep in every build, and the
    /// reader exists so a test can assert the cap sweeps at most once per
    /// second per box, never once per frame.
    sweeps: AtomicU64,
    /// Whether the box's first-pin line has been written: the one `info`
    /// line per box the diagnostics read a DNS box's host-side decision by,
    /// at the first answer that landed, never again. An `AtomicBool` because
    /// the entry it belongs to is shared behind an `Arc`: `admit` takes
    /// `&self`, like every method on it, and the swap below is the write —
    /// returning whether this admission was the first, so two replies
    /// racing in the same window still write the line exactly once.
    logged_first_pin: AtomicBool,
}

/// A DNS wire name in the form the row's declared names are matched in:
/// ASCII-lowercased, with the root dot stripped — `github.com` for
/// `GitHub.com.`. The same normalization the in-VM gate matches by.
fn normalized(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

impl BoxPins {
    /// Builds one box's admission state from its row and the switch's
    /// address plan — the names the row declared, the infrastructure set the
    /// intersection subtracts, and the tables the replies fill.
    fn built(record: &Arc<BoxRecord>, subnet: SwitchSubnet) -> Self {
        Self {
            record: Arc::clone(record),
            names: record
                .allow_dns_hosts()
                .iter()
                .map(|host| normalized(host))
                .collect(),
            infrastructure: InfrastructureDenySet::new(
                record.egress().resolver(),
                subnet.host_alias().octets(),
            ),
            outstanding: Mutex::new(HashMap::new()),
            admitted: Mutex::new(HashMap::new()),
            flows: Mutex::new(FlowTable::new()),
            at_cap_admitted: AtomicU64::new(0),
            sweeps: AtomicU64::new(0),
            logged_first_pin: AtomicBool::new(false),
        }
    }

    /// The egress leg's half of the reply matching: one DNS query the box
    /// sent its resolver — a datagram the switch received, or the reply it
    /// answers pins nothing — held outstanding under its [`QueryKey`] with
    /// the instant it was observed, for the shared expiry.
    ///
    /// The bounds are the table's own, read from [`sessions::core::egress`]
    /// with the rest of the numbers: an expired entry is swept here, at the
    /// insert that would share its map — the same no-timer discipline the
    /// admitted addresses keep — and past the shared cap a new question is
    /// not recorded, fail closed, so no reply can ever match it and a box
    /// cannot grow the table one question at a time. A question re-sent — a
    /// resolver stack's retry, the same key — refreshes its own window
    /// rather than spending the cap a second time.
    ///
    /// Quiet by design, like the reply half: a datagram that is not a
    /// query, not parseable, or carrying no question is not recorded — no
    /// question, nothing to answer.
    fn record_query(&self, pkt: &L4Packet, datagram: &[u8], now: Instant) {
        if datagram.len() > MAX_DATAGRAM {
            tracing::debug!(
                switch_addr = %self.record.switch_addr(),
                namespace = %self.record.name(),
                n = datagram.len(),
                "ignoring an oversized DNS query at the host-side admission table"
            );
            return;
        }
        let message = match Message::from_vec(datagram) {
            Ok(message) => message,
            Err(error) => {
                tracing::debug!(
                    switch_addr = %self.record.switch_addr(),
                    namespace = %self.record.name(),
                    %error,
                    "passing an unparseable DNS query through unrecorded on the host"
                );
                return;
            }
        };
        if message.metadata.message_type != MessageType::Query {
            return;
        }
        let Some(question) = message.queries.first() else {
            return;
        };
        let key = QueryKey {
            txid: message.metadata.id,
            src_port: pkt.src.port(),
            name: normalized(&question.name().to_lowercase().to_string()),
        };
        let mut outstanding = self
            .outstanding
            .lock()
            .expect("the outstanding-query table's lock is held only across this update");
        outstanding.retain(|_, at| now.duration_since(*at) < DNS_QUERY_EXPIRY);
        if outstanding.len() >= DNS_OUTSTANDING_QUERY_CAP && !outstanding.contains_key(&key) {
            tracing::debug!(
                switch_addr = %self.record.switch_addr(),
                namespace = %self.record.name(),
                name = %key.name,
                cap = DNS_OUTSTANDING_QUERY_CAP,
                "not recording a question past the outstanding-query cap; its reply pins nothing"
            );
            return;
        }
        outstanding.insert(key, now);
    }

    /// The ingress side, NET-066 and NET-067: observes one DNS reply the
    /// switch returned toward this box, and when it is a reply from the
    /// box's own resolver answering one of the box's own outstanding
    /// queries for a name the row declared, splits its answer chain's A
    /// records by the rebinding intersection — the survivors are admitted
    /// for the window, each refusal logs the name and the answer through
    /// the gate's limiter in the shared refusal format.
    ///
    /// The reply must answer an outstanding query — the same transaction
    /// id, the port the query left from, the same question ([`QueryKey`])
    /// — and the match consumes its entry, so a replay of a matched reply
    /// answers nothing and pins nothing more, while an unsolicited or
    /// mismatched reply passes through to the box unpinned. And only the
    /// answer chain pins: the chain starts at the question name and follows
    /// the CNAME records in the answer section, so an A record pins exactly
    /// when its owner is a name on that chain — the sections the chain
    /// never walks (authority, additional) and the types v1 never admits
    /// (AAAA, SVCB, HTTPS) are read past.
    ///
    /// Every failure mode is quiet by design: a datagram that is not from
    /// the resolver, not a reply, not parseable, not answering the box's
    /// own question, or carrying no question (there is no name to match)
    /// pins nothing, and the reply itself is
    /// never kept from the box — resolution is honest; it is the *connection*
    /// to a refused address that is not admitted.
    fn observe(&self, pkt: &L4Packet, datagram: &[u8], limiter: &DropLimiter, now: Instant) {
        if pkt.src.ip().octets() != self.record.egress().resolver() || pkt.src.port() != DNS_PORT {
            return;
        }
        if datagram.len() > MAX_DATAGRAM {
            tracing::debug!(
                switch_addr = %self.record.switch_addr(),
                namespace = %self.record.name(),
                n = datagram.len(),
                "ignoring an oversized DNS reply at the host-side admission table"
            );
            return;
        }
        let message = match Message::from_vec(datagram) {
            Ok(message) => message,
            Err(error) => {
                tracing::debug!(
                    switch_addr = %self.record.switch_addr(),
                    namespace = %self.record.name(),
                    %error,
                    "passing an unparseable DNS reply through unpinned on the host"
                );
                return;
            }
        };
        if message.metadata.message_type != MessageType::Response {
            return;
        }
        // The question is the name the box asked for — the one thing a reply
        // can be matched to its row by. A reply with no question (some
        // resolvers elide it, RFC 7858) fails closed: no name, no pin.
        // Matching the question rather than the answer records' own names is
        // also what makes a CNAME chain work (its A records carry the chain
        // target's name) while a forged record *owner* admits nothing.
        let Some(question) = message.queries.first() else {
            return;
        };
        let asked = normalized(&question.name().to_lowercase().to_string());
        if !self.names.contains(&asked) {
            return;
        }
        // The box's own question, answered: the reply must match an
        // outstanding entry by all three of its identity's facts, and the
        // match consumes the entry — so a second copy of the same reply
        // answers nothing, and a reply to a question the box never asked,
        // or asked long enough ago that its window passed, passes through
        // unpinned like any unsolicited one.
        let key = QueryKey {
            txid: message.metadata.id,
            src_port: pkt.dst.port(),
            name: asked.clone(),
        };
        let answered = self
            .outstanding
            .lock()
            .expect("the outstanding-query table's lock is held only across this match")
            .remove(&key)
            .is_some_and(|at| now.duration_since(at) < DNS_QUERY_EXPIRY);
        if !answered {
            return;
        }
        // Only the answer chain pins: the chain starts at the question name
        // and follows the CNAME records in the answer section — a target is
        // on the chain when the record naming it is owned by a name already
        // on it — and an A record pins exactly when its owner is on the
        // chain, walked in the order the reply carried it. Everything else
        // in the reply is read past: a record owned by a name off the chain,
        // the authority and additional sections (never walked), and every
        // type but A — AAAA never pins in v1 (NET-136), and SVCB and HTTPS
        // name alternative endpoints, which are not the answer the box
        // asked for.
        let mut chain = HashSet::with_capacity(1 + message.answers.len());
        chain.insert(asked.clone());
        let answers: Vec<[u8; 4]> = message
            .answers
            .iter()
            .filter_map(|record| {
                let owner = normalized(&record.name.to_lowercase().to_string());
                match &record.data {
                    RData::A(address) if chain.contains(&owner) => Some(address.0.octets()),
                    RData::CNAME(cname) if chain.contains(&owner) => {
                        chain.insert(normalized(&cname.0.to_lowercase().to_string()));
                        None
                    }
                    _ => None,
                }
            })
            .collect();
        // A zone name here is a declaration the in-VM gate treats as the
        // resolution's own (NET-072): it validates the answer and pins
        // nothing, wherever reach to the lease it named is decided by the
        // connecting box's declared subnets. This table holds no box-zone
        // carve-out — an ordinary name is the only kind that can pin here —
        // so the same answer is refused like any other that resolved into
        // the plane, and the reach is the same: none.
        let split = egress::rebinding_intersection(
            &answers,
            false,
            self.record.egress().allow_subnets(),
            self.record.egress().deny_subnets(),
            &self.infrastructure,
        );
        self.admit(&asked, &split.admitted, now);
        for (address, refusal) in split.refused {
            limiter.warn_dns_refusal(
                self.record.switch_addr().octets(),
                &asked,
                Ipv4Addr::from(address),
                refusal.rule(),
            );
        }
    }

    /// Admits `addresses` — one name's surviving answers — until
    /// `now` + the shared admission window, with the first-pin line at the
    /// first answer that ever landed and the window's one debug line beside
    /// it: the name, the addresses, and how long they hold.
    ///
    /// The shared per-name cap is enforced here: a name holds at most
    /// [`DNS_MAX_ADDRESSES_PER_NAME`] addresses at once, counted over the
    /// *live* admissions it owns — the ones whose window has passed are
    /// released below, before the cap is spent — so answers past the cap are
    /// refused (fail closed), a name whose resolved address set rotates
    /// keeps its grant, and the table stays proportionate to the box's
    /// declared names rather than to what its resolver chose to say. An
    /// address a *different* declared name already admitted keeps its first
    /// owner: it is one address either way, and re-owning it would let a
    /// second name's burst evict the first's.
    fn admit(&self, name: &str, addresses: &[[u8; 4]], now: Instant) {
        if addresses.is_empty() {
            return;
        }
        let expires = now + DNS_ADMISSION_WINDOW;
        let mut admitted = self
            .admitted
            .lock()
            .expect("the DNS admission table's lock is held only across this update");
        // Release this name's expired admissions before its cap is spent: an
        // expired window admits nothing — `admits_destination` has already
        // stopped answering for it — so it must not hold the cap's room
        // either. Without this, a name whose resolved address set rotates
        // fills its cap with addresses it can no longer reach and every
        // later disjoint answer is refused as over-cap.
        admitted.retain(|_, admission| &*admission.name != name || now < admission.expires);
        // How many addresses this name still holds — the shared per-name cap,
        // counted where it is spent.
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
            if held >= DNS_MAX_ADDRESSES_PER_NAME {
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
                switch_addr = %self.record.switch_addr(),
                namespace = %self.record.name(),
                name,
                ?over_cap,
                cap = DNS_MAX_ADDRESSES_PER_NAME,
                "refused a resolved name's answers past the per-name cap on the host"
            );
        }
        // The one line per box the bundle's daemon log tail reads a DNS
        // box's host-side decision by: at the first answer that landed, once
        // per box per connection, naming the box and the name. Later
        // admissions carry their own debug line below, so the table's every
        // pin is legible in a bundle without a line per answer at `info`.
        if admitted_now.is_empty() {
            return;
        }
        if !self.logged_first_pin.swap(true, Ordering::Relaxed) {
            tracing::info!(
                switch_addr = %self.record.switch_addr(),
                namespace = %self.record.name(),
                name,
                "filled the box's host-side DNS admission table; its undeclared \
                 destinations are decided on the host, against the answers its own \
                 lookups received"
            );
        }
        let addresses: Vec<Ipv4Addr> = admitted_now.iter().copied().map(Ipv4Addr::from).collect();
        tracing::debug!(
            switch_addr = %self.record.switch_addr(),
            namespace = %self.record.name(),
            name,
            ?addresses,
            window_secs = DNS_ADMISSION_WINDOW.as_secs(),
            "admitted a resolved name's addresses for the window on the host"
        );
    }

    /// Whether `dst` is an address this box's own lookups resolved to and
    /// whose window still holds at `now`.
    fn admits_destination(&self, dst: [u8; 4], now: Instant) -> bool {
        let admitted = self
            .admitted
            .lock()
            .expect("the DNS admission table's lock is held only across this lookup");
        admitted
            .get(&dst)
            .is_some_and(|admission| now < admission.expires)
    }

    /// Whether the gate may lift the row's undeclared-destination drop for
    /// the frame whose L4 addressing was `pkt` and whose destination is
    /// `dst`: the destination is inside its admission window, or the frame
    /// belongs to a flow a pin already established — the shared used-pin
    /// retention, which is what keeps an established flow's admitted
    /// destination past window expiry until the flow ends, so a long
    /// `git clone` or keep-alive to an allowed name is not severed at the
    /// window's edge while a *new* connection to the same address is.
    ///
    /// The first frame a pin admits establishes its flow, and every later
    /// frame refreshes it. The flow ends when the box sends a FIN or RST on
    /// it — whose own segment is admitted as the flow's last frame — or when
    /// the shared idle cap reclaims it at the lookup of the first frame to
    /// ride it after a day idle, which is the only release a UDP flow, which
    /// carries no close signal to read, ever gets. `pkt` is `None` for a
    /// frame with no L4 header to read: no ports, no flow identity, so only
    /// the window can admit it.
    ///
    /// The flows a box holds are bounded by the shared per-box cap: at it,
    /// the entries idle past the shared idle cap are swept — at most once
    /// per second per box, never once per frame ([`FlowTable::sweep_due`]),
    /// so a hostile relay holding one pin cannot buy the sweep's walk with
    /// every frame it sends — and a new flow that still finds the table
    /// full is admitted by the window its first frame is inside and not
    /// retained — fail closed at the window's edge, the only place the
    /// refusal bites — so a hostile relay holding one pin cannot grow the
    /// host daemon's memory one flow at a time, while every flow already
    /// recorded keeps its retention. The at-cap state is visible rather
    /// than silent, and bounded rather than per frame: the box's counter of
    /// unretained admissions and one `info` line per box per minute while
    /// the cap holds, so a box whose table is full reads so in a bundle.
    fn admits(&self, dst: [u8; 4], pkt: Option<&L4Packet>, now: Instant) -> bool {
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
            let mut table = self
                .flows
                .lock()
                .expect("the DNS flow table's lock is held only across this lookup");
            match table.flows.get(&key).copied() {
                // A live flow: the retention carries this frame, and the
                // frame refreshes the clock the idle bound reads.
                Some(seen) if now.duration_since(seen) < DNS_FLOW_IDLE_CAP => {
                    if ends {
                        table.flows.remove(&key);
                    } else {
                        table.flows.insert(key, now);
                    }
                    return true;
                }
                // Idle past the cap: the flow is reclaimed here, at the
                // lookup of the frame that would have ridden it — not by
                // the sweep at the table's cap alone, which runs only once
                // the box has filled it — and the frame falls through to
                // the window, which is what decides whether the box may
                // open this flow again.
                Some(_) => {
                    table.flows.remove(&key);
                }
                None => {}
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
        let mut table = self
            .flows
            .lock()
            .expect("the DNS flow table's lock is held only across this insert");
        // The retention bound's memory half, run at the cap: the entries no
        // frame has come back to look up are reclaimed first, so the cap is
        // spent on live flows — at most once per second per box, never once
        // per frame, so a hostile relay holding one pin cannot buy the
        // sweep's walk with every frame it sends.
        if table.flows.len() >= DNS_MAX_FLOWS_PER_BOX && table.sweep_due(now) {
            table.sweep(now);
            self.sweeps.fetch_add(1, Ordering::Relaxed);
        }
        if table.flows.len() >= DNS_MAX_FLOWS_PER_BOX {
            // Still at the cap: the frame rides the window it is inside, and
            // its flow is not retained — fail closed at the window's edge,
            // the only place the refusal bites, since past the window the
            // destination is refused where a recorded flow's retention would
            // have carried it. The state is visible rather than silent, and
            // bounded rather than per frame: the per-box counter below is
            // what a status surface would read (its control verb is a
            // follow-up), and the `info` line says the cap at most once per
            // box per minute, at minvmd's default filter, so the box whose
            // table is full reads in a bundle's log tail.
            let admitted_at_cap = self.at_cap_admitted.fetch_add(1, Ordering::Relaxed) + 1;
            if table.claim_at_cap_line(now) {
                tracing::info!(
                    switch_addr = %self.record.switch_addr(),
                    namespace = %self.record.name(),
                    cap = DNS_MAX_FLOWS_PER_BOX,
                    admitted_at_cap,
                    "the box's flow table is at its cap; its frames ride the \
                     admission window alone and no flow is retained for them"
                );
            }
            return true;
        }
        table.flows.insert(key, now);
        true
    }
}

/// The host-side DNS admission table: one [`BoxPins`] entry per registered
/// box that declared DNS hosts, filled from the DNS replies the gate's
/// ingress leg observes on their way to the box and consulted by the frame
/// verdict's pin arm for exactly one drop class — the undeclared destination
/// of a row that resolves names. Cheap to clone: every clone shares the same
/// entries and counters, and the handle the gate holds is the one its two
/// legs and its verdict all read.
#[derive(Clone)]
pub(crate) struct DnsPins {
    inner: Arc<Inner>,
}

/// The shared state behind every [`DnsPins`] clone.
struct Inner {
    /// The switch's address plan: the source of each entry's infrastructure
    /// deny set and host-alias address, the same plan the rows were
    /// compiled against.
    subnet: SwitchSubnet,
    /// One entry per registered box that declared DNS hosts, keyed by the
    /// row's switch address — the same key the gate resolves a frame's
    /// source through. Bounded by the plan's address run: an entry exists
    /// only for an address a row was published at, and only while that row
    /// is the one the entry was built from.
    boxes: Mutex<HashMap<[u8; 4], Arc<BoxPins>>>,
    /// The rows whose resolver mismatch has been said, keyed by the row's
    /// switch address and holding the record the refusal was logged for —
    /// the dedupe behind "log the refusal", so a row refused its entry says
    /// so once, however many frames and replies arrive for it, while a
    /// *replacement* row at the same address — a new record — is judged and
    /// logged again. Cleared beside the entries at [`DnsPins::retire`],
    /// the same lifetime.
    refused: Mutex<HashMap<[u8; 4], Arc<BoxRecord>>>,
    /// How many frames the gate admitted because a live pin named the
    /// destination (the observability counter: what the host-side decision
    /// passed).
    admitted_by_pin: AtomicU64,
    /// How many frames the gate refused for want of a pin (the same
    /// counter's other half: what the host-side decision dropped where the
    /// deferral this table replaced would have passed it).
    refused_for_want_of_pin: AtomicU64,
}

impl DnsPins {
    /// An empty table for a switch serving `subnet`: the plan each entry's
    /// infrastructure deny set and host-alias address are built from, the
    /// same plan the registry's rows were compiled against.
    #[must_use]
    pub(crate) fn new(subnet: SwitchSubnet) -> Self {
        Self {
            inner: Arc::new(Inner {
                subnet,
                boxes: Mutex::new(HashMap::new()),
                refused: Mutex::new(HashMap::new()),
                admitted_by_pin: AtomicU64::new(0),
                refused_for_want_of_pin: AtomicU64::new(0),
            }),
        }
    }

    /// The entry for `record`, built from it on first sight: `None` for a
    /// row that declared no names — no reply can ever pin anything for it,
    /// so it holds no entry — and a fresh entry for a row this table last saw
    /// under another declaration, because a re-registration can widen a row
    /// as readily as narrow it and the newest declaration's answers are the
    /// only ones that may pin for it.
    ///
    /// The entrance's own guard comes first (the architecture review's
    /// condition): a row's resolver is the plan's — the registry compiles it
    /// from the subnet it was built for, so a row naming any other one, an
    /// in-guest address or an upstream reached through NAT, can only be a
    /// drift between this table's plan and the registry's — and such a row
    /// is refused its entry and logged ([`Self::refuse_resolver`]), so
    /// nothing can ever pin for it and its undeclared destinations stay the
    /// host's drops. Without the assertion the `src == row.resolver` check
    /// [`BoxPins::observe`] decides by would be a grant the row's own bytes
    /// make, and a forged reply wearing whatever address the row named
    /// would pin through it.
    fn entry(&self, record: &Arc<BoxRecord>) -> Option<Arc<BoxPins>> {
        if record.allow_dns_hosts().is_empty() {
            return None;
        }
        let plan_resolver = self.inner.subnet.dns_server().octets();
        if record.egress().resolver() != plan_resolver {
            self.refuse_resolver(record, plan_resolver);
            return None;
        }
        let key = record.switch_addr().octets();
        let mut boxes = self
            .inner
            .boxes
            .lock()
            .expect("the admission table's lock is held only across this lookup");
        match boxes.get(&key) {
            Some(entry) if Arc::ptr_eq(&entry.record, record) => Some(Arc::clone(entry)),
            _ => {
                let entry = Arc::new(BoxPins::built(record, self.inner.subnet));
                boxes.insert(key, Arc::clone(&entry));
                Some(entry)
            }
        }
    }

    /// Says a refused row's resolver mismatch, once per row: the row whose
    /// resolver is not the plan's own is logged the first time the table sees
    /// it, naming the box, the resolver the row names and the plan's own —
    /// the line a host reads to learn the admission table and the registry
    /// were built for different plans, the only way a row can name a foreign
    /// resolver — and every later sight of the same row is silent. A new
    /// record at the same address is a new row and says so again.
    fn refuse_resolver(&self, record: &Arc<BoxRecord>, plan_resolver: [u8; 4]) {
        let key = record.switch_addr().octets();
        let mut refused = self
            .inner
            .refused
            .lock()
            .expect("the refused-row table's lock is held only across this update");
        if refused
            .get(&key)
            .is_some_and(|seen| Arc::ptr_eq(seen, record))
        {
            return;
        }
        refused.insert(key, Arc::clone(record));
        tracing::warn!(
            source = %record.switch_addr(),
            namespace = %record.name(),
            resolver = %Ipv4Addr::from(record.egress().resolver()),
            plan_resolver = %Ipv4Addr::from(plan_resolver),
            "refused a DNS admission entry for a row whose resolver is not the \
             plan's own; its undeclared destinations stay the host's drops",
        );
    }

    /// The ingress leg's half of the table: one DNS reply the switch
    /// returned toward a box — a frame the relay has already parsed as an
    /// IPv4+UDP datagram — observed on its way to the guest, so the pins it
    /// sets are the answers the box's own lookup received. A datagram
    /// addressed to an address no row holds pins nothing, and neither does
    /// one for a row that declared no names or one whose resolver the table
    /// refused: there is no entry to fill.
    ///
    /// The pre-check is the port the reply was served from: ingress UDP is
    /// mostly not DNS — the answers to a box's own datagrams arrive from
    /// whatever port they were sent to — so a datagram from any port but
    /// [`DNS_PORT`] is refused **here**, before the row is looked up and
    /// before the table's lock is taken, and non-DNS ingress never pays
    /// either. It is the same fact [`BoxPins::observe`] decides the reply's
    /// source by, read once more where it is cheapest; the resolver's
    /// address and every other check stay where they were.
    pub(crate) fn observe_reply(
        &self,
        table: &BoxTable,
        pkt: &L4Packet,
        datagram: &[u8],
        limiter: &DropLimiter,
        now: Instant,
    ) {
        if pkt.src.port() != DNS_PORT {
            return;
        }
        let Some(record) = table.by_source(pkt.dst.ip().octets()) else {
            return;
        };
        let Some(entry) = self.entry(&record) else {
            return;
        };
        entry.observe(pkt, datagram, limiter, now);
    }

    /// The egress leg's half of the table: one DNS query a box sent its
    /// resolver — a frame the relay has already parsed as an IPv4+UDP
    /// datagram and the gate has already admitted to the switch — recorded
    /// as that box's outstanding question, so the reply that answers it is
    /// the only kind that can ever pin. A datagram addressed anywhere but
    /// the plan's resolver at the DNS port is ignored **here**, before the
    /// row is looked up: the reply-matching state holds the box's own
    /// lookups and nothing else's, the same cheap pre-check the ingress
    /// leg keeps. A query over TCP is never recorded — the UDP datagram is
    /// the one DNS path v1 carries and the one a reply can pin by — and a
    /// query from a source no row holds records nothing either.
    pub(crate) fn observe_query(
        &self,
        table: &BoxTable,
        pkt: &L4Packet,
        datagram: &[u8],
        now: Instant,
    ) {
        if pkt.proto != IPPROTO_UDP
            || pkt.dst.port() != DNS_PORT
            || pkt.dst.ip().octets() != table.gateway()
        {
            return;
        }
        let Some(record) = table.by_source(pkt.src.ip().octets()) else {
            return;
        };
        let Some(entry) = self.entry(&record) else {
            return;
        };
        entry.record_query(pkt, datagram, now);
    }

    /// The verdict's pin arm: whether the gate may lift the row's
    /// undeclared-destination drop for the frame whose destination is `dst`
    /// and whose L4 addressing was `pkt` — a live pin names the destination,
    /// or the flow it established still holds it; nothing else does. The
    /// observability counters are read here, at the decision: one for every
    /// frame this table admitted, one for every frame it refused.
    pub(crate) fn admits_frame(
        &self,
        record: &Arc<BoxRecord>,
        dst: [u8; 4],
        pkt: Option<&L4Packet>,
        now: Instant,
    ) -> bool {
        let admitted = self
            .entry(record)
            .is_some_and(|entry| entry.admits(dst, pkt, now));
        if admitted {
            self.inner.admitted_by_pin.fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner
                .refused_for_want_of_pin
                .fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    /// Retires the entries of the boxes whose traffic the relay that ended
    /// carried: the same event that withdraws their rows (the relay's
    /// attribution, filed beside the withdrawal report, NET-133) retires
    /// their pins, so an entry never outlives the connection its box's
    /// answers rode — and the rows the table refused their entries, whose
    /// mismatch was said once, go with them, so a row that arrives at the
    /// address next says so again rather than inheriting its predecessor's
    /// silence. A re-attachment re-registers the row, and the next
    /// reply rebuilds the entry — fail closed, until the box's own lookups
    /// pin again: nothing inside the VM can hand the box its old grants
    /// back.
    pub(crate) fn retire(&self, sources: &[[u8; 4]]) {
        let mut boxes = self
            .inner
            .boxes
            .lock()
            .expect("the admission table's lock is held only across this retire");
        let mut refused = self
            .inner
            .refused
            .lock()
            .expect("the refused-row table's lock is held only across this retire");
        for src in sources {
            boxes.remove(src);
            refused.remove(src);
        }
    }

    /// How many frames the gate admitted because a live pin named the
    /// destination.
    ///
    /// Test-facing, like the in-VM gate's window-shrinkers: the counter is
    /// the table's own state, maintained at the decision in every build,
    /// and these two readers exist so a test can assert what the decision
    /// counted — nothing in the daemon's log or control surface reads a
    /// running total yet.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn admitted_by_pin(&self) -> u64 {
        self.inner.admitted_by_pin.load(Ordering::Relaxed)
    }

    /// How many frames the gate refused for want of a pin — the same
    /// counter's other half: what the host-side decision dropped where the
    /// deferral this table replaced would have passed the frame on.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn refused_for_want_of_pin(&self) -> u64 {
        self.inner.refused_for_want_of_pin.load(Ordering::Relaxed)
    }

    /// How many frames `record`'s cap admitted by the window alone, without
    /// retention — the at-cap state's per-box counter, the number the box's
    /// at-cap `info` line carries.
    ///
    /// Test-facing, like [`Self::admitted_by_pin`]: the counter is the box's
    /// own state, maintained at the decision in every build, and the reader
    /// exists so a test can assert what the cap did — the status surface
    /// that would read it needs a control verb, a follow-up.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn at_cap_admissions_of(&self, record: &Arc<BoxRecord>) -> u64 {
        self.entry(record).map_or(0, |box_pins| {
            box_pins.at_cap_admitted.load(Ordering::Relaxed)
        })
    }

    /// How many times the flow-table sweep ran for `record`'s box — the
    /// proof of the once-per-second bound, which no frame's own verdict
    /// can show: a sweep that reclaims nothing leaves no trace but the
    /// instant it ran.
    ///
    /// Test-facing, like [`Self::admitted_by_pin`]: maintained at the sweep
    /// in every build, read here alone.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn sweeps_of(&self, record: &Arc<BoxRecord>) -> u64 {
        self.entry(record)
            .map_or(0, |box_pins| box_pins.sweeps.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //! The host-side table's own proofs (NET-081 deciding NET-066/067), plus
    //! the DNS wire builders the gate's relay-level proofs share: the reply
    //! datagrams a test answers a box's lookup with are built with the same
    //! resolver-stack encoder (`hickory_proto`) the table reads them with,
    //! honest IPv4 and UDP lengths throughout, because [`udp_datagram`]
    //! refuses any frame whose claimed lengths do not bound its payload.

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, SVCB};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use sessions::EgressPolicy;
    use sessions::core::egress::{DNS_ADMISSION_WINDOW, DNS_FLOW_IDLE_CAP, DNS_MAX_FLOWS_PER_BOX};
    use switch::SwitchSubnet;

    use super::{DnsPins, IPPROTO_TCP, TCP_FIN, udp_datagram};
    use crate::box_registry::{BoxRegistration, BoxRegistry, BoxTable};
    use crate::net::egress_gate::DropLimiter;

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
        f.push(super::IPPROTO_UDP);
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

    /// A DNS reply datagram from the resolver: the id of a real exchange, the
    /// question echoed, and one A record per `answer`.
    pub(crate) fn dns_response(name: &str, answers: &[Ipv4Addr]) -> Vec<u8> {
        dns_response_with(0x522a, name, answers)
    }

    /// A DNS reply datagram like [`dns_response`], carrying `id` as the
    /// exchange's — the one field a reply that does not answer the box's own
    /// question gets wrong.
    fn dns_response_with(id: u16, name: &str, answers: &[Ipv4Addr]) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("the query name parses");
        let mut response = Message::response(id, OpCode::Query);
        response.metadata.message_type = MessageType::Response;
        response.add_query(Query::query(qname.clone(), RecordType::A));
        for address in answers {
            response.add_answer(Record::from_rdata(qname.clone(), 60, RData::A(A(*address))));
        }
        response.to_vec().expect("the reply encodes")
    }

    /// A DNS reply datagram from the resolver, with the records the test
    /// built — owners, sections and types its own — the shape the answer
    /// chain is read from. The question is echoed for `qname`, `answers` go
    /// in the answer section and `additionals` in the additional section.
    fn dns_reply(qname: &str, answers: Vec<Record>, additionals: Vec<Record>) -> Vec<u8> {
        let qname = Name::from_utf8(qname).expect("the query name parses");
        let mut response = Message::response(0x522a, OpCode::Query);
        response.metadata.message_type = MessageType::Response;
        response.add_query(Query::query(qname, RecordType::A));
        for record in answers {
            response.add_answer(record);
        }
        for record in additionals {
            response.add_additional(record);
        }
        response.to_vec().expect("the reply encodes")
    }

    /// One A record for `owner`, the answer a chain walk pins by.
    fn a_record(owner: &str, address: Ipv4Addr) -> Record {
        Record::from_rdata(
            Name::from_utf8(owner).expect("the record's owner parses"),
            60,
            RData::A(A(address)),
        )
    }

    /// One CNAME record: `owner` names `target`, the link the chain walk
    /// follows.
    fn cname_record(owner: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_utf8(owner).expect("the record's owner parses"),
            60,
            RData::CNAME(CNAME(
                Name::from_utf8(target).expect("the record's target parses"),
            )),
        )
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
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(Vec::new()),
                    allow_dns_hosts: Some(names),
                    deny_subnets: (!deny.is_empty()).then_some(deny),
                }),
        );
    }

    /// Records one query the box sent its resolver for `name` — the egress
    /// leg's half, driven directly so the reply matching is testable with no
    /// sockets: from the box, on its lookup's own source port, to the plan's
    /// resolver, in the datagram shape the relay hands the table.
    fn lookup(pins: &DnsPins, table: &BoxTable, lease: [u8; 4], name: &str, now: Instant) {
        let query = udp_payload_frame(
            Ipv4Addr::from(lease),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_query(name),
        );
        let (pkt, datagram) = udp_datagram(&query)
            .expect("the test's query frame parses as the egress leg parses it");
        pins.observe_query(table, &pkt, datagram, now);
    }

    /// Observes one reply the switch returned toward `lease`, answering
    /// `name` with `answers` — the ingress leg's half, driven directly so the
    /// table's decisions are testable with no sockets: from the plan's
    /// resolver, to the box, in the datagram shape the relay hands the table.
    fn observe(
        pins: &DnsPins,
        table: &BoxTable,
        lease: [u8; 4],
        name: &str,
        answers: &[Ipv4Addr],
        limiter: &DropLimiter,
        now: Instant,
    ) {
        let reply = udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(lease),
            40000,
            &dns_response(name, answers),
        );
        let (pkt, datagram) = udp_datagram(&reply)
            .expect("the test's reply frame parses as the relay's ingress leg parses it");
        pins.observe_reply(table, &pkt, datagram, limiter, now);
    }

    /// Drives one full exchange — the box's own question recorded on the
    /// egress leg, then the reply the resolver returned, observed on the
    /// ingress leg — so the tests that prove what a reply pins stand on the
    /// same two legs the relay drives.
    fn resolve(
        pins: &DnsPins,
        table: &BoxTable,
        lease: [u8; 4],
        name: &str,
        answers: &[Ipv4Addr],
        limiter: &DropLimiter,
        now: Instant,
    ) {
        lookup(pins, table, lease, name, now);
        observe(pins, table, lease, name, answers, limiter, now);
    }

    /// Observes one reply the resolver returned toward `lease` — the raw
    /// datagram the test built — on the ingress leg: for the replies whose
    /// records the stock helpers cannot spell.
    fn observe_datagram(
        pins: &DnsPins,
        table: &BoxTable,
        lease: [u8; 4],
        reply: &[u8],
        limiter: &DropLimiter,
        now: Instant,
    ) {
        let frame = udp_payload_frame(SUBNET.dns_server(), 53, Ipv4Addr::from(lease), 40000, reply);
        let (pkt, datagram) = udp_datagram(&frame)
            .expect("the test's reply frame parses as the relay's ingress leg parses it");
        pins.observe_reply(table, &pkt, datagram, limiter, now);
    }

    /// Drives one exchange whose reply the test built itself — the query
    /// recorded on the egress leg, then the raw reply datagram observed on
    /// the ingress leg.
    fn resolve_reply(
        pins: &DnsPins,
        table: &BoxTable,
        lease: [u8; 4],
        name: &str,
        reply: &[u8],
        limiter: &DropLimiter,
        now: Instant,
    ) {
        lookup(pins, table, lease, name, now);
        observe_datagram(pins, table, lease, reply, limiter, now);
    }

    /// The table admits exactly the answers the box's own lookup received,
    /// and nothing else. Before any reply nothing admits; after one, the
    /// answers do — and only they: an address the answer did not name is
    /// refused, whatever its neighbourhood, a name the row did not declare
    /// pins nothing for it, a reply not from the resolver pins nothing at
    /// all, a reply toward another box pins only that box's, and the shared
    /// per-name cap refuses the answers past it. The first answer a box ever
    /// received says so once at `info`, naming the box and the name.
    #[test]
    fn host_pins_are_the_answers_the_box_received() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string(), "cap.example".to_string()],
            Vec::new(),
        );
        // A second box, whose declared name is spelled in the case and form
        // DNS names are matched in: the normalization is part of the grant,
        // and its pins stay its own.
        let other = [100, 64, 0, 10];
        dns_box(
            &registry,
            "other",
            other,
            vec!["Other.Example.".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let other_record = table.by_source(other).expect("the other box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();

        // Nothing has been resolved: no pin exists to name any destination,
        // so the box's undeclared reach is none — the posture a hostile relay
        // inside the VM meets before the box has looked anything up.
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        assert!(
            !pins.admits_frame(&record, answer.octets(), None, now),
            "before any reply, no destination admits"
        );
        assert_eq!(
            pins.refused_for_want_of_pin(),
            1,
            "the refused frame is counted"
        );
        assert_eq!(pins.admitted_by_pin(), 0, "nothing has been admitted yet");

        // The box's own lookup: the query is the box's, and the reply is the
        // one it received — two addresses, both public.
        let second = Ipv4Addr::new(93, 184, 216, 35);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer, second],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, answer.octets(), None, now),
            "an answer the box received admits"
        );
        assert!(
            pins.admits_frame(&record, second.octets(), None, now),
            "the second answer of the same reply admits too"
        );

        // Exactly the answers: the sibling address in the same /24 the reply
        // did not name is refused — the pinned set is the box's own answers,
        // not their neighbourhood.
        let sibling = Ipv4Addr::new(93, 184, 216, 36);
        assert!(
            !pins.admits_frame(&record, sibling.octets(), None, now),
            "an address the answer did not name is refused, however close"
        );

        // A reply answering a name the row did not declare pins nothing for
        // it: the grant is the declaration's own.
        let undeclared = Ipv4Addr::new(192, 0, 2, 9);
        resolve(
            &pins,
            &table,
            LEASE,
            "undeclared.example",
            &[undeclared],
            &limiter,
            now,
        );
        assert!(
            !pins.admits_frame(&record, undeclared.octets(), None, now),
            "a reply for a name the row did not declare pins nothing"
        );

        // A reply not from the resolver pins nothing at all: it is the box's
        // own traffic, not its resolution.
        let stranger = Ipv4Addr::new(203, 0, 113, 99);
        let off_resolver = udp_payload_frame(
            stranger,
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_response("example.com", &[Ipv4Addr::new(198, 51, 100, 9)]),
        );
        let (pkt, datagram) = udp_datagram(&off_resolver)
            .expect("the test's off-resolver reply parses as the ingress leg parses it");
        pins.observe_reply(&table, &pkt, datagram, &limiter, now);
        assert!(
            !pins.admits_frame(&record, [198, 51, 100, 9], None, now),
            "a reply not from the resolver pins nothing"
        );

        // A reply toward another box pins that box — under the normalized form
        // of its own declaration — and only it.
        let others_answer = Ipv4Addr::new(192, 0, 2, 10);
        resolve(
            &pins,
            &table,
            other,
            "other.example",
            &[others_answer],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&other_record, others_answer.octets(), None, now),
            "the second box's own answer admits for it, under its normalized name"
        );
        assert!(
            !pins.admits_frame(&record, others_answer.octets(), None, now),
            "another box's answer pins nothing for the first"
        );

        // The shared per-name cap, observed on a name with no pins yet so the
        // count is the reply's own: the first 32 answers admit, the 33rd is
        // refused, fail closed — the answers past the cap are the resolver's,
        // not the box's reach.
        let burst: Vec<Ipv4Addr> = (0..33u8)
            .map(|i| Ipv4Addr::new(198, 51, 100, 100 + i))
            .collect();
        resolve(&pins, &table, LEASE, "cap.example", &burst, &limiter, now);
        assert!(
            pins.admits_frame(
                &record,
                Ipv4Addr::new(198, 51, 100, 131).octets(),
                None,
                now
            ),
            "the 32nd answer of the name admits: the cap is the shared one"
        );
        assert!(
            !pins.admits_frame(
                &record,
                Ipv4Addr::new(198, 51, 100, 132).octets(),
                None,
                now
            ),
            "the answer past the per-name cap is refused"
        );

        // The one line per box the diagnostics read the host-side decision
        // by: the first answer each box received said so once, naming the
        // box's address, its namespace and the name; a later answer adds no
        // second line for the same box, and the second box has its own.
        let logged = log.contents();
        let first_pin = "filled the box's host-side DNS admission table";
        assert!(
            logged.contains(first_pin)
                && logged.contains("switch_addr=100.64.0.9")
                && logged.contains("namespace=weather")
                && logged.contains("name=\"example.com\""),
            "the first pin says so at info, naming the box and the name, got: {logged}"
        );
        assert_eq!(
            logged.matches(first_pin).count(),
            2,
            "one first-pin line per box, once per box — not one per answer or per name: {logged}"
        );
        assert!(
            logged.contains("switch_addr=100.64.0.10") && logged.contains("name=\"other.example\""),
            "the second box's first pin names it and its name, got: {logged}"
        );
        assert!(
            pins.admitted_by_pin() > 0 && pins.refused_for_want_of_pin() > 1,
            "the counters read what the decisions did: admitted {}, refused {}",
            pins.admitted_by_pin(),
            pins.refused_for_want_of_pin(),
        );
    }

    /// The answers pass the rebinding intersection before they enter
    /// (NET-067): a denied range and the infrastructure deny set —
    /// link-local with its metadata services, loopback, and RFC 1918 space
    /// the row's empty `allow_subnets` does not cover — are refused, each
    /// with the name and the answer in the shared refusal format,
    /// rate-limited per box per name per rule; the survivors hold for the
    /// shared window, an established flow rides past the window's edge until
    /// the flow ends, and a new flow to the same address does not.
    #[test]
    fn host_window_refuses_denied_and_infrastructure_ranges() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        // Two names, because the refusal line's key is the name: two names
        // refusing under one rule each say so. The denied range is the
        // declaration's own subtraction.
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string(), "other.example".to_string()],
            vec!["10.9.9.0/24".to_string()],
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();

        // One reply, one name, four answers: the public one survives; the
        // denied one and two infrastructure ones never become pins.
        let admitted = Ipv4Addr::new(93, 184, 216, 34);
        let denied = Ipv4Addr::new(10, 9, 9, 7);
        let metadata = Ipv4Addr::new(169, 254, 169, 254);
        let loopback = Ipv4Addr::new(127, 0, 0, 1);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[admitted, denied, metadata, loopback],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, admitted.octets(), None, now),
            "the answer outside every refused range admits"
        );
        for refused in [denied, metadata, loopback] {
            assert!(
                !pins.admits_frame(&record, refused.octets(), None, now),
                "an answer inside a refused range never became a pin"
            );
        }

        // Each refusal says so in the shared format — the name, the answer
        // and the rule — once per box per name per rule per interval, the
        // in-VM gate's own bucket (the answer is the line's field, never
        // part of its key, so a hostile resolver cannot spend the limit one
        // address at a time): the loopback answer here shares the metadata
        // answer's key and is silent, the burst below shares the denied
        // range's and is silent under it, and the second name's own refusal
        // is heard because its key is its own.
        let denied_again = Ipv4Addr::new(10, 9, 9, 8);
        for _ in 0..3 {
            resolve(
                &pins,
                &table,
                LEASE,
                "example.com",
                &[denied_again],
                &limiter,
                now,
            );
        }
        let others_denied = Ipv4Addr::new(10, 9, 9, 9);
        resolve(
            &pins,
            &table,
            LEASE,
            "other.example",
            &[others_denied],
            &limiter,
            now,
        );
        let logged = log.contents();
        // Each refusal names the name, the answer and the rule, in the shared
        // format — one line each, per box per name per rule.
        for expected in [
            "an allowed name resolved into a refused range",
            "source=100.64.0.9",
            "name=\"example.com\"",
            "answer=10.9.9.7",
            "rule_matched=\"dns-rebinding-denied-subnet\"",
            "answer=169.254.169.254",
            "rule_matched=\"dns-rebinding-infrastructure\"",
            "name=\"other.example\"",
        ] {
            assert!(
                logged.contains(expected),
                "the refusal line must carry {expected:?}: {logged}"
            );
        }
        assert_eq!(
            logged.matches("answer=127.0.0.1").count(),
            0,
            "the loopback refusal shares the metadata answer's key — one name, one rule, \
             inside the interval — so it is silent, not a second line: {logged}"
        );
        assert_eq!(
            logged.matches("answer=10.9.9.8").count(),
            0,
            "the repeated burst adds no line under the key the first refusal already \
             spent: one rate-limited line per name per rule, not one per answer: {logged}"
        );
        assert_eq!(
            logged
                .matches("an allowed name resolved into a refused range")
                .count(),
            3,
            "one line per name and rule — the denied range, the infrastructure range, \
             and the second name's own — and no more: {logged}"
        );
        assert!(
            logged.contains("answer=10.9.9.9"),
            "the second name's refusal names its own answer: {logged}"
        );

        // The window: the admitted answer holds for it, and no longer. A
        // frame with no L4 header to read is decided by the window alone.
        let past = now + DNS_ADMISSION_WINDOW + Duration::from_secs(1);
        assert!(
            !pins.admits_frame(&record, admitted.octets(), None, past),
            "past the window the pin admits nothing"
        );

        // The used-pin retention: an established flow rides past the
        // window's edge — the long connection an allowed name deserves —
        // and the flow's own end, the box's FIN, releases it: a new flow to
        // the same address past the window is refused, where the old one was
        // carried until it closed.
        let flow = l4_of(&tcp_frame(
            Ipv4Addr::from(LEASE),
            40000,
            admitted,
            443,
            0x02, // SYN: a flow's opening segment
        ));
        assert!(
            pins.admits_frame(&record, admitted.octets(), Some(&flow), now),
            "a frame inside the window establishes its flow"
        );
        assert!(
            pins.admits_frame(&record, admitted.octets(), Some(&flow), past),
            "the established flow rides past the window's edge"
        );
        let fin = l4_of(&tcp_frame(
            Ipv4Addr::from(LEASE),
            40000,
            admitted,
            443,
            TCP_FIN,
        ));
        assert!(
            pins.admits_frame(&record, admitted.octets(), Some(&fin), past),
            "the flow's closing frame is the flow's last"
        );
        let new_flow = l4_of(&tcp_frame(
            Ipv4Addr::from(LEASE),
            40001,
            admitted,
            443,
            0x02,
        ));
        assert!(
            !pins.admits_frame(&record, admitted.octets(), Some(&new_flow), past),
            "a new flow past the window is refused, the used pin notwithstanding"
        );
    }

    /// An entry dies with the row it was built from, and a replacement row
    /// registered at the same switch address — a new [`BoxRecord`], the
    /// shape a re-attachment's re-registration takes — starts from a fresh
    /// one: none of the pins or the established flows the replaced row's own
    /// lookups earned admit for the row that took the address, until its own
    /// lookup pins again. The guard is the entry's identity check
    /// ([`DnsPins::entry`]): the entry a row's answers fill is kept only
    /// while the row the table holds *is* the row it was built from, so a
    /// newer declaration at the same address never inherits an older one's
    /// grants — and the replaced row's record, should anything consult it,
    /// holds nothing either.
    #[test]
    fn a_replacement_row_inherits_neither_pins_nor_flows() {
        let registry = BoxRegistry::new(SUBNET);
        let names = vec!["example.com".to_string()];
        dns_box(&registry, "weather", LEASE, names.clone(), Vec::new());
        let table = registry.table();
        let first = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();

        // The box's own lookup, and the flow it opened through the answer:
        // a pin inside the window, and a flow that rides past it — the
        // retention the row earned by using what its answer named.
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        let flow = l4_of(&tcp_frame(
            Ipv4Addr::from(LEASE),
            40000,
            answer,
            443,
            0x02, // SYN: a flow's opening segment
        ));
        assert!(
            pins.admits_frame(&first, answer.octets(), None, now),
            "the box's own answer admits for the row that asked"
        );
        assert!(
            pins.admits_frame(&first, answer.octets(), Some(&flow), now),
            "the flow the box opened through its pin is established"
        );
        let past = now + DNS_ADMISSION_WINDOW + Duration::from_secs(1);
        assert!(
            pins.admits_frame(&first, answer.octets(), Some(&flow), past),
            "the established flow rides past the window's edge for the row \
             that opened it"
        );

        // The replacement row: the same switch address, the same declared
        // names, a new record — a re-registration's shape. It holds none of
        // the replaced row's grants: not the window pin, and not the flow
        // that rode past the window either, even inside the retention that
        // carried it for the row that opened it.
        dns_box(&registry, "weather", LEASE, names, Vec::new());
        let second = table
            .by_source(LEASE)
            .expect("the re-registered box's row is held");
        assert!(
            !Arc::ptr_eq(&first, &second),
            "the re-registration is a new record at the same address"
        );
        assert!(
            !pins.admits_frame(&second, answer.octets(), None, now),
            "the replacement row inherits none of the replaced row's pins"
        );
        assert!(
            !pins.admits_frame(&second, answer.octets(), Some(&flow), past),
            "the replacement row inherits none of the replaced row's \
             established flows, however long the retention carried them"
        );
        assert!(
            !pins.admits_frame(&first, answer.octets(), None, now),
            "the replaced row's record admits nothing either: the entry it \
             filled is not kept for it behind the row that replaced it"
        );

        // Until its own lookup pins again: the replacement row's own answer
        // admits for it — the same address, the same flow, both earned
        // rather than inherited.
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&second, answer.octets(), None, now),
            "the replacement row's own lookup earns its pin again"
        );
        assert!(
            pins.admits_frame(&second, answer.octets(), Some(&flow), now),
            "and its own use of the answer establishes its own flow"
        );
        assert!(
            pins.admits_frame(&second, answer.octets(), Some(&flow), past),
            "the flow the replacement row established rides past its window, \
             as the replaced row's did for it"
        );
    }

    /// The flow table is bounded per box (the architecture review's
    /// condition): a box holds at most [`DNS_MAX_FLOWS_PER_BOX`] flows open
    /// through its pins at once, so a hostile relay holding one pin cannot
    /// grow the host daemon's memory one flow at a time. At the cap a new
    /// flow's first frame is still admitted inside the window — bounding the
    /// table narrows no frame the pin already grants — but the flow is not
    /// retained: fail closed at the window's edge, past which its
    /// destination is refused, where a recorded flow's retention would have
    /// carried it. The flows recorded before the cap cost nothing of what
    /// they earned: one of them still rides past the window, idle inside the
    /// shared cap.
    ///
    /// The bound is each box's own, and the at-cap state is visible: a
    /// second box at another lease, resolving the same name, opens and
    /// keeps its own flow after the first box has filled its cap; the frames
    /// the first box's cap admitted without retention are counted per box,
    /// and the `info` line says the cap at most once per box per minute —
    /// two at-cap frames in the same minute log one line, and the line after
    /// the minute says the counter the minute spent.
    #[test]
    fn the_flow_table_is_bounded_per_box() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        // A second DNS box at another lease, declaring the same name: the
        // cap below is spent on the first box's flows alone, and its own
        // table keeps all its room — the bound is per box, not per host.
        let other_lease = [100, 64, 0, 10];
        dns_box(
            &registry,
            "other",
            other_lease,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let other_record = table
            .by_source(other_lease)
            .expect("the second box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        resolve(
            &pins,
            &table,
            other_lease,
            "example.com",
            &[answer],
            &limiter,
            now,
        );

        // The flow recorded before the cap — the retention the box earned by
        // using what its answer named — and the rest of the cap spent on
        // distinct flows to the same pinned address: one SYN per source
        // port, each its own flow identity.
        let flow = |lease: [u8; 4], src_port: u16| {
            l4_of(&tcp_frame(
                Ipv4Addr::from(lease),
                src_port,
                answer,
                443,
                0x02, // SYN: a flow's opening segment
            ))
        };
        let first = flow(LEASE, 40_000);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&first), now),
            "the first flow through the pin is established"
        );
        for port in 1..DNS_MAX_FLOWS_PER_BOX {
            let port = u16::try_from(40_000 + port).expect("the test's source port fits a u16");
            assert!(
                pins.admits_frame(&record, answer.octets(), Some(&flow(LEASE, port)), now),
                "each distinct flow through the pin is established and recorded"
            );
        }

        // The cap is spent. The next new flow's first frame is still admitted
        // — the window holds — but the flow is not retained, so past the
        // window its destination is refused where a recorded flow's
        // retention would have carried it.
        let past_cap_port =
            u16::try_from(40_000 + DNS_MAX_FLOWS_PER_BOX).expect("the port fits a u16");
        let past_cap = flow(LEASE, past_cap_port);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&past_cap), now),
            "at the cap a new flow's first frame is still admitted inside \
             the window"
        );
        // A second frame the cap admits the same way, inside the same
        // minute: the counter the state reads moves per frame, while the
        // line stays one per box per minute.
        let past_cap_again = flow(LEASE, past_cap_port + 1);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&past_cap_again), now),
            "a second at-cap frame rides the window the same way"
        );
        assert_eq!(
            pins.at_cap_admissions_of(&record),
            2,
            "both at-cap frames are counted, each admitted without retention"
        );
        assert_eq!(
            pins.at_cap_admissions_of(&other_record),
            0,
            "the counter is per box: the second box's table never reached \
             the cap"
        );
        let at_cap_line = "the box's flow table is at its cap";
        let logged = log.contents();
        assert!(
            logged.contains(at_cap_line)
                && logged.contains("switch_addr=100.64.0.9")
                && logged.contains("namespace=weather")
                && logged.contains(&format!("cap={DNS_MAX_FLOWS_PER_BOX}"))
                && logged.contains("admitted_at_cap=1"),
            "the at-cap line names the box, the cap and the counter's \
             value, at the daemon's own info filter, got: {logged}"
        );
        assert_eq!(
            logged.matches(at_cap_line).count(),
            1,
            "two at-cap frames in the same minute say so in one line, not \
             one per frame: {logged}"
        );

        // The second box's own flow, opened after the first box filled its
        // cap: its table has its own room, so the flow is established and
        // retained — the bound is per box, and one box at its cap narrows
        // nothing of a sibling's grant.
        let other_flow = flow(other_lease, 40_000);
        assert!(
            pins.admits_frame(&other_record, answer.octets(), Some(&other_flow), now),
            "a second box's flow is established beside a box at its cap"
        );

        // Past the line's minute, the next at-cap frame says so again — the
        // rate limiter bounds the line to the minute, it does not silence
        // the state after the first one — and the line it writes carries
        // the counter the minute spent.
        let minute = now + super::AT_CAP_LINE_INTERVAL;
        let past_cap_later = flow(LEASE, past_cap_port + 2);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&past_cap_later), minute),
            "the at-cap frame past the minute rides the window the same way"
        );
        assert_eq!(
            pins.at_cap_admissions_of(&record),
            3,
            "the at-cap frame past the minute is counted too"
        );
        let logged = log.contents();
        assert_eq!(
            logged.matches(at_cap_line).count(),
            2,
            "the line is rate-limited per box per minute, not said once \
             ever: {logged}"
        );
        assert!(
            logged.contains("admitted_at_cap=3"),
            "the second line carries the counter's value at it, got: {logged}"
        );
        let past = now + DNS_ADMISSION_WINDOW + Duration::from_secs(1);
        assert!(
            !pins.admits_frame(&record, answer.octets(), Some(&past_cap), past),
            "the flow the cap refused to retain ends with the window: past \
             its edge the destination is refused"
        );
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&first), past),
            "a flow recorded before the cap keeps its retention: the box's \
             established flow still rides past the window"
        );
        assert!(
            pins.admits_frame(&other_record, answer.octets(), Some(&other_flow), past),
            "the second box's flow keeps its retention past the window: the \
             cap is the first box's own"
        );
    }

    /// At the cap the sweep runs at most once per second per box, never once
    /// per frame (the architecture review's condition): a sweep walks every
    /// entry the table holds, and at the shared cap's size that costs tens
    /// of microseconds a frame would otherwise pay to reclaim nothing — the
    /// frames inside the second go straight to the window, unretained. What
    /// a sweep reclaims, a new flow gets: one recorded flow aged past the
    /// shared idle cap is reclaimed by the next second's sweep, and the new
    /// flow that arrives for the freed slot is retained — it rides past the
    /// window's edge, where the frame the same second at the cap does not.
    #[test]
    fn at_the_cap_one_sweep_per_second_reclaims_the_idle_flows() {
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        let flow = |src_port: u16| {
            l4_of(&tcp_frame(
                Ipv4Addr::from(LEASE),
                src_port,
                answer,
                443,
                0x02, // SYN: a flow's opening segment
            ))
        };

        // One flow recorded early — the one the shared idle cap will have
        // aged past once the box is at its cap — and the rest of the cap
        // spent two seconds later, on flows that stay live at the sweep.
        let aged = flow(40_000);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&aged), now),
            "the flow the idle cap will age past is recorded early"
        );
        let fill = now + Duration::from_secs(2);
        for port in 1..DNS_MAX_FLOWS_PER_BOX {
            let port = u16::try_from(40_000 + port).expect("the test's source port fits a u16");
            assert!(
                pins.admits_frame(&record, answer.octets(), Some(&flow(port)), fill),
                "each distinct flow through the pin is established and recorded"
            );
        }

        // A day and a second on: the early flow is idle past the shared cap,
        // the rest for two seconds less — and the window the box's first
        // lookup earned has long passed, so the box resolves again and the
        // flows below are decided by a live window.
        let late = now + DNS_FLOW_IDLE_CAP + Duration::from_secs(1);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            late,
        );

        // The next new flow, more than a second after the last sweep — none
        // has run yet, so the first is due: the sweep reclaims the aged
        // flow, and the freed slot retains the new flow.
        let fresh_port =
            u16::try_from(40_000 + DNS_MAX_FLOWS_PER_BOX).expect("the port fits a u16");
        let fresh = flow(fresh_port);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&fresh), late),
            "the new flow at the cap is admitted through the slot the sweep \
             freed"
        );
        assert_eq!(
            pins.sweeps_of(&record),
            1,
            "the first at-cap frame swept the idle flow the cap reclaimed"
        );

        // A second at-cap frame inside the same second: no sweep — the
        // once-per-second bound is what keeps the sweep's walk from being
        // bought per frame — and the frame rides the window unretained.
        let within = late + Duration::from_millis(500);
        let inner = flow(fresh_port + 1);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&inner), within),
            "the at-cap frame inside the second still rides the window"
        );
        assert_eq!(
            pins.sweeps_of(&record),
            1,
            "no second sweep inside the same second: at most one per box \
             per second, never one per frame"
        );

        // Past the window's edge: the flow the sweep's freed slot retained
        // rides on, where the frame the same second at the cap — admitted
        // by the window alone, retained nowhere — is refused.
        let past = late + DNS_ADMISSION_WINDOW + Duration::from_secs(1);
        assert!(
            pins.admits_frame(&record, answer.octets(), Some(&fresh), past),
            "the flow that took the sweep's freed slot is retained: it rides \
             past the window, where the cap's unretained frames end"
        );
        assert!(
            !pins.admits_frame(&record, answer.octets(), Some(&inner), past),
            "the frame the second at the cap admitted by the window alone \
             retained no flow: past the window it is refused"
        );
    }

    /// The entrance's own guard (the architecture review's condition): a row
    /// whose resolver is not the plan the table was built for can only be a
    /// drift — the registry compiles every row's resolver from its own
    /// subnet, so a row naming another one, an in-guest address or an
    /// upstream reached through NAT, was built for a different plan — and
    /// such a row is refused its entry and says so once, naming the box, the
    /// resolver the row names and the plan's own. Nothing can ever pin for
    /// it: without the guard the `src == row.resolver` check the reply's pin
    /// decides by would be a grant the row's own bytes make, and a forged
    /// reply wearing the address the row named would pin through it.
    #[test]
    fn a_row_whose_resolver_is_not_the_plans_own_is_refused() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        // The registry a drifted row can only come from: built for another
        // plan, it compiles this row's resolver from that plan's own
        // address, while the box the row holds sits in the table's plan.
        let foreign = SwitchSubnet::new(Ipv4Addr::new(100, 65, 0, 0), 24)
            .expect("the test's second plan is a valid prefix");
        let registry = BoxRegistry::new(foreign);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the drifted row is held by the registry that built it");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();
        let answer = Ipv4Addr::new(93, 184, 216, 34);

        // The full exchange the row's own bytes would answer, on both legs:
        // the row never earns its entry — the reply leg's sight of it is the
        // refusal — so nothing is recorded for it and nothing pins.
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        assert!(
            !pins.admits_frame(&record, answer.octets(), None, now),
            "a row whose resolver is not the plan's own pins nothing"
        );
        let refused = "refused a DNS admission entry for a row whose resolver is not the \
                      plan's own";
        let logged = log.contents();
        assert!(
            logged.contains(refused)
                && logged.contains("source=100.64.0.9")
                && logged.contains("namespace=weather")
                && logged.contains("resolver=100.65.0.1")
                && logged.contains("plan_resolver=100.64.0.1"),
            "the refusal names the box, the resolver the row names and the \
             plan's own, got: {logged}"
        );

        // A later sight of the same row is silent — the refusal is said once
        // per row, not once per reply — while a row the plan does own, in the
        // same table, still pins for its own answers: the guard refuses the
        // drift and nothing else.
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        let home = BoxRegistry::new(SUBNET);
        let other = [100, 64, 0, 10];
        dns_box(
            &home,
            "other",
            other,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let home_table = home.table();
        let home_record = home_table
            .by_source(other)
            .expect("the plan's own row is held");
        resolve(
            &pins,
            &home_table,
            other,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&home_record, answer.octets(), None, now),
            "a row whose resolver is the plan's own still pins"
        );
        let logged = log.contents();
        assert_eq!(
            logged.matches(refused).count(),
            1,
            "the refusal is said once per row, not once per sight: {logged}"
        );
    }

    /// The reply matching (the architecture review's condition): only a reply
    /// that answers one of the box's own outstanding queries pins — the same
    /// question, the same transaction id, and the port the query left from —
    /// and the match consumes its entry, so a replay of a matched reply
    /// answers nothing. A well-formed reply the box never asked for, and one
    /// that gets the id wrong, pass through to the box unpinned — and spend
    /// nothing: the question they failed to answer stays answered by the
    /// reply that eventually does.
    #[test]
    fn only_a_reply_to_the_boxs_own_outstanding_query_pins() {
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();
        let answer = Ipv4Addr::new(93, 184, 216, 34);

        // A well-formed reply for a declared name, from the resolver, with no
        // query outstanding: the box never asked, so it pins nothing — the
        // reply still reaches the box, and it is the connection to the answer
        // that stays unadmitted.
        observe(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        assert!(
            !pins.admits_frame(&record, answer.octets(), None, now),
            "a reply the box never asked for pins nothing"
        );

        // The box's own question, recorded on the egress leg: a reply that
        // gets the transaction id wrong answers nothing — and does not spend
        // the question either, which the reply that gets it right still
        // answers.
        lookup(&pins, &table, LEASE, "example.com", now);
        let mismatched = udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_response_with(0x522b, "example.com", &[answer]),
        );
        let (pkt, datagram) = udp_datagram(&mismatched)
            .expect("the test's mismatched reply parses as the ingress leg parses it");
        pins.observe_reply(&table, &pkt, datagram, &limiter, now);
        assert!(
            !pins.admits_frame(&record, answer.octets(), None, now),
            "a reply with a mismatched transaction id pins nothing"
        );
        observe(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, answer.octets(), None, now),
            "the mismatched reply spent nothing: the reply that answers the \
             question pins"
        );

        // The match consumes the question: a replay of the same reply answers
        // nothing and refreshes nothing — the window the first reply opened is
        // the only one the address holds, and past its edge the pin is gone,
        // where a replay that pinned would have opened a fresh one. The
        // replay arrives while the question is still outstanding — inside the
        // shared query expiry — so it would match and pin again if the first
        // match had not consumed the entry; replayed past the expiry, the
        // assertion would pass refused by the expiry rather than by the
        // consume, and prove nothing.
        let replayed_at = now + Duration::from_secs(10);
        observe(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[answer],
            &limiter,
            replayed_at,
        );
        let past = now + DNS_ADMISSION_WINDOW + Duration::from_secs(1);
        assert!(
            !pins.admits_frame(&record, answer.octets(), None, past),
            "a replay of the same reply pins nothing more: the window it \
             would have refreshed ended"
        );
    }

    /// Only the answer chain pins (the architecture review's condition): the
    /// chain starts at the question name and follows the CNAME records in
    /// the answer section, and an A record pins exactly when its owner is a
    /// name on it. Everything else in the reply is read past — a record
    /// owned by a name off the chain, the sections the chain never walks
    /// (authority, additional), and every type but A: an AAAA never pins in
    /// v1 (NET-136), and SVCB and HTTPS name alternative endpoints, whose
    /// hints are not the answer the box asked for.
    #[test]
    fn only_the_answers_chain_pins() {
        let registry = BoxRegistry::new(SUBNET);
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec![
                "example.com".to_string(),
                "chain.example".to_string(),
                "unaffiliated.example".to_string(),
                "extra.example".to_string(),
                "typed.example".to_string(),
            ],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();

        // The real answer beside a record no chain reaches: an A owned by a
        // name the reply never linked to the question pins nothing, however
        // public its address — the box's answers are its own, not a
        // neighbour's.
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let unrelated = Ipv4Addr::new(1, 2, 3, 4);
        resolve_reply(
            &pins,
            &table,
            LEASE,
            "example.com",
            &dns_reply(
                "example.com",
                vec![
                    a_record("example.com", answer),
                    a_record("evil.example", unrelated),
                ],
                Vec::new(),
            ),
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, answer.octets(), None, now),
            "the answer owned by the name the box asked for pins"
        );
        assert!(
            !pins.admits_frame(&record, unrelated.octets(), None, now),
            "an A record owned by a name off the answer chain pins nothing"
        );

        // A CNAME chain: the question's name aliases to another, and the A
        // record that answers the alias is the answer the box received — the
        // chain walk follows the link, and the A pins.
        let aliased = Ipv4Addr::new(198, 51, 100, 7);
        resolve_reply(
            &pins,
            &table,
            LEASE,
            "chain.example",
            &dns_reply(
                "chain.example",
                vec![
                    cname_record("chain.example", "alias.example"),
                    a_record("alias.example", aliased),
                ],
                Vec::new(),
            ),
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, aliased.octets(), None, now),
            "the A record at the end of a CNAME chain pins: the chain walked \
             the link to it"
        );

        // A reply whose only A record is owned by a name off the chain pins
        // nothing at all: the chain never reached the owner, so the record is
        // read past — fail closed.
        let stray = Ipv4Addr::new(203, 0, 113, 77);
        resolve_reply(
            &pins,
            &table,
            LEASE,
            "unaffiliated.example",
            &dns_reply(
                "unaffiliated.example",
                vec![a_record("evil.example", stray)],
                Vec::new(),
            ),
            &limiter,
            now,
        );
        assert!(
            !pins.admits_frame(&record, stray.octets(), None, now),
            "a reply whose every A record is off the chain pins nothing"
        );

        // The additional section never enters the chain: its records are
        // read past beside a real answer, and the address one carries —
        // glue, or the smuggle — never becomes a pin.
        let extra = Ipv4Addr::new(198, 51, 100, 23);
        let smuggled = Ipv4Addr::new(192, 0, 2, 66);
        resolve_reply(
            &pins,
            &table,
            LEASE,
            "extra.example",
            &dns_reply(
                "extra.example",
                vec![a_record("extra.example", extra)],
                vec![a_record("smuggled.example", smuggled)],
            ),
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, extra.octets(), None, now),
            "the answer in the answer section pins"
        );
        assert!(
            !pins.admits_frame(&record, smuggled.octets(), None, now),
            "an A record in the additional section pins nothing"
        );

        // The types v1 never admits: an AAAA record — here in the v4-mapped
        // form, the only shape whose address a pin could even hold — and an
        // SVCB and an HTTPS record, each carrying an ipv4hint, the v4
        // address an alternative endpoint is reached at. The real answer
        // beside them still pins; none of the typed records' addresses ever
        // does.
        let typed = Name::from_utf8("typed.example").expect("the typed owner parses");
        let endpoint = Name::from_utf8("svc.example").expect("the svcb target parses");
        let svcb = RData::SVCB(SVCB::new(
            1,
            endpoint.clone(),
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(5, 6, 7, 8))])),
            )],
        ));
        let https = RData::HTTPS(HTTPS(SVCB::new(
            1,
            endpoint,
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::new(6, 7, 8, 9))])),
            )],
        )));
        let hinted = Record::from_rdata(typed.clone(), 60, svcb);
        let secure = Record::from_rdata(typed.clone(), 60, https);
        let v6_mapped = Record::from_rdata(
            typed.clone(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304))),
        );
        let typed_answer = Ipv4Addr::new(198, 51, 100, 67);
        resolve_reply(
            &pins,
            &table,
            LEASE,
            "typed.example",
            &dns_reply(
                "typed.example",
                vec![
                    a_record("typed.example", typed_answer),
                    hinted,
                    secure,
                    v6_mapped,
                ],
                Vec::new(),
            ),
            &limiter,
            now,
        );
        assert!(
            pins.admits_frame(&record, typed_answer.octets(), None, now),
            "the real answer beside the typed records still pins"
        );
        for refused in [
            Ipv4Addr::new(1, 2, 3, 4), // the AAAA record's v4-mapped address
            Ipv4Addr::new(5, 6, 7, 8), // the SVCB record's ipv4hint
            Ipv4Addr::new(6, 7, 8, 9), // the HTTPS record's ipv4hint
        ] {
            assert!(
                !pins.admits_frame(&record, refused.octets(), None, now),
                "a typed record's address never pins: the chain walk admits A \
                 records only"
            );
        }
    }

    /// The completed infrastructure deny set (the architecture review's
    /// condition, on NET-067's own): an answer that names this host's space
    /// — `0.0.0.0` means the host itself — a multicast group, the broadcast
    /// address or the reserved block it ends in is refused, whatever allowed
    /// name asked for it, and each refusal is said in the shared format
    /// under its own key: the name, the answer and the rule.
    #[test]
    fn host_window_refuses_this_host_multicast_broadcast_and_reserved_answers() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        // Two names, because the refusal line's key is the name: this host's
        // own address and a multicast group, each refused under its own.
        dns_box(
            &registry,
            "weather",
            LEASE,
            vec!["example.com".to_string(), "other.example".to_string()],
            Vec::new(),
        );
        let table = registry.table();
        let record = table
            .by_source(LEASE)
            .expect("the published box's row is held");
        let pins = DnsPins::new(SUBNET);
        let limiter = DropLimiter::new();
        let now = Instant::now();

        let this_host = Ipv4Addr::UNSPECIFIED;
        let multicast = Ipv4Addr::new(224, 0, 0, 1);
        resolve(
            &pins,
            &table,
            LEASE,
            "example.com",
            &[this_host],
            &limiter,
            now,
        );
        resolve(
            &pins,
            &table,
            LEASE,
            "other.example",
            &[multicast],
            &limiter,
            now,
        );
        for refused in [this_host, multicast] {
            assert!(
                !pins.admits_frame(&record, refused.octets(), None, now),
                "an answer inside the completed infrastructure set never \
                 became a pin"
            );
        }
        let logged = log.contents();
        for expected in [
            "an allowed name resolved into a refused range",
            "name=\"example.com\"",
            "answer=0.0.0.0",
            "rule_matched=\"dns-rebinding-infrastructure\"",
            "name=\"other.example\"",
            "answer=224.0.0.1",
        ] {
            assert!(
                logged.contains(expected),
                "the refusal names {expected}, got: {logged}"
            );
        }

        // The rest of the completed set — the reserved block and broadcast
        // itself — refuses as quietly, on the same leg.
        for (name, refused) in [
            ("example.com", Ipv4Addr::new(240, 0, 0, 1)),
            ("other.example", Ipv4Addr::new(255, 255, 255, 255)),
        ] {
            resolve(&pins, &table, LEASE, name, &[refused], &limiter, now);
            assert!(
                !pins.admits_frame(&record, refused.octets(), None, now),
                "the {name} answer inside the completed infrastructure set \
                 never became a pin"
            );
        }
    }

    /// The L4 addressing of one of the frames above, as the gate's egress leg
    /// would parse it — the identity the flow retention reads.
    fn l4_of(frame: &[u8]) -> super::L4Packet {
        super::parse_ipv4_l4(frame).expect("the test's frame parses as the relay parses it")
    }
}
