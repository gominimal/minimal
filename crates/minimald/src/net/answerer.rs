//! The box-zone answerer: the always-on loopback DNS server that answers
//! `*.min.internal` for the host OS (design §7.1, NET-009).
//!
//! The hostname proxy ([`super::proxy`]) routes by `Host:` header; this is
//! the other half of resolution — the DNS reply the host's own resolver gets
//! when a process looks a box name up, no proxy variable involved.
//! `server::start_host_proxies` binds it beside the proxy and, in a microVM,
//! publishes it on the host loopback through the gvproxy forwarder's UDP
//! path, so the host resolver's one address (`127.0.0.1:[`ANSWERER_PORT`]`,
//! non-privileged, which is what the macOS resolver hook's `port` directive
//! names) reaches it in every deployment.
//!
//! Answer semantics, all gated on the lookup originating on this machine
//! (NET-006 — the zone leaves the machine with *nothing*, not even a refusal,
//! which would tell a scanner a DNS server is here):
//!
//! | Lookup | Reply |
//! |---|---|
//! | A, held with a host-answerable address | that address (NET-127) |
//! | A, held without one (a box's switch lease) | NODATA (NET-124, NET-128) |
//! | any other type, held name | NODATA (NET-124) |
//! | anything, name nothing holds | NXDOMAIN (NET-125) |
//! | a name outside the box zone | REFUSED |
//! | anything but a standard query | NOTIMP |
//!
//! Every negative — NODATA and NXDOMAIN — carries the zone's SOA in the
//! authority section with a 15 s `minimum` (RFC 2308), so the host resolver
//! can cache it (NET-124): an uncacheable negative stalls every lookup on a
//! macOS host, not only the zone's. Every record the answerer emits, those
//! answers and that SOA, holds a TTL of at most 15 s (NET-126).
//!
//! Nothing here issues certificates or writes audit records, and the records
//! it can ever emit are A answers and the zone's own SOA (NET-007: see
//! [`super::dns::HostnameRegistry::zone_table`] for the state-dump half).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use super::SwitchSubnet;
use super::dns::{ANSWER_TTL_SECS, HOSTNAME_SUFFIX, HostnameRegistry, ZoneEntry};
use super::proxy::BindFailure;

/// Port the box-zone answerer listens on: the next one after the egress
/// (`:7654`) and mTLS (`:7655`) proxies. Non-privileged by design — the
/// resolver hook that routes the zone here names it with a `port` directive
/// (design §7.1), and an unprivileged daemon must still be able to bind it.
pub const ANSWERER_PORT: u16 = 7656;

/// The `component` field every answerer log line carries, matching the
/// proxies' `dns-proxy`/`https-proxy` convention.
const COMPONENT: &str = "zone-answerer";

/// Largest datagram the answerer reads: a DNS query fits far below this
/// (queries are tens of bytes), and a larger datagram is dropped rather than
/// buffered unbounded.
const MAX_DATAGRAM: usize = 4096;

/// The box-zone lookup the answerer performs for each in-zone query, factored
/// like [`super::proxy::HostRoute`] so the answering core is decoupled from
/// how the table is shared (the sessions manager owns the live registry) and
/// testable against a bare registry.
pub trait Zone: Send + Sync + 'static {
    /// What the box zone holds for a full `<name>.min.internal` name: held
    /// (with or without a host-answerable A address) or absent — the
    /// NODATA/NXDOMAIN distinction ([`super::dns::ZoneEntry`]).
    fn zone_entry(&self, host: &str, node: &[Ipv4Addr]) -> ZoneEntry;
}

impl Zone for HostnameRegistry {
    fn zone_entry(&self, host: &str, node: &[Ipv4Addr]) -> ZoneEntry {
        HostnameRegistry::zone_entry(self, host, node)
    }
}

// The daemon shares its live registry behind an `RwLock` (the sessions manager
// mutates it; the answerer only reads it, synchronously, with no `.await`
// held). Poison recovery matches the routing proxies' read of the same lock:
// the registry is two HashMaps with no cross-field invariant a panicked writer
// could half-break, and silently answering `Absent` would NXDOMAIN every live
// box name forever, with no signal.
impl Zone for std::sync::RwLock<HostnameRegistry> {
    fn zone_entry(&self, host: &str, node: &[Ipv4Addr]) -> ZoneEntry {
        match self.read() {
            Ok(guard) => guard.zone_entry(host, node),
            Err(poisoned) => poisoned.into_inner().zone_entry(host, node),
        }
    }
}

/// Which datagram sources the answerer serves (NET-006): the zone leaves the
/// machine with no answer, not even a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerScope {
    /// A native host (DM2): the listener binds host loopback, so only
    /// loopback peers reach it at all. The source is still checked per
    /// datagram, so a misbound socket can never serve the zone to the
    /// network.
    Native,
    /// Inside a microVM (DM1/3/4): the listener binds in-guest (the host
    /// reaches it only through the gvproxy forwarder publishing the port on
    /// the host loopback), and the guest's only fabric is the host-local
    /// switch, so loopback and the switch's own subnet are both on-machine.
    /// Anything outside them — off the fabric the forwarder rides — is
    /// off-host and gets nothing.
    Microvm { subnet: SwitchSubnet },
}

impl AnswerScope {
    /// Whether a datagram from `peer` originated on this machine (NET-006).
    fn allows(&self, peer: SocketAddr) -> bool {
        match peer.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => true,
            IpAddr::V4(ip) => match self {
                Self::Native => false,
                Self::Microvm { subnet } => (u32::from(subnet.network())
                    ..=u32::from(subnet.broadcast()))
                    .contains(&u32::from(ip)),
            },
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }
}

/// The box-zone answerer: one [`Zone`] table behind the answer semantics the
/// module docs table. Built once at daemon start and served for the daemon's
/// lifetime ([`serve`]).
pub struct ZoneAnswerer<T: Zone = HostnameRegistry> {
    /// The shared registry the sessions manager registers boxes into.
    zone: Arc<T>,
    /// Which datagram sources this answerer serves (NET-006).
    scope: AnswerScope,
    /// The zone's SOA, carried by every negative (NET-124), built once.
    soa: Record,
}

// Cloning shares the registry (the table is the daemon's one) and copies the
// two built-once values. The startup driver spawns a clone into its serve
// loop while it keeps driving the host publish with the original.
impl<T: Zone> Clone for ZoneAnswerer<T> {
    fn clone(&self) -> Self {
        Self {
            zone: Arc::clone(&self.zone),
            scope: self.scope.clone(),
            soa: self.soa.clone(),
        }
    }
}

impl<T: Zone> ZoneAnswerer<T> {
    /// Builds an answerer over the shared `zone` table, serving the sources
    /// `scope` allows.
    #[must_use]
    pub fn new(zone: Arc<T>, scope: AnswerScope) -> Self {
        Self {
            zone,
            scope,
            soa: zone_soa(),
        }
    }

    /// The reply bytes for one datagram, or `None` to send nothing.
    ///
    /// `None` is a decision, not a failure: a source that did not originate
    /// on this machine gets nothing at all (NET-006), and so does a datagram
    /// that is not a standard query — no question section to answer, no id to
    /// echo an error to, and a response reflected back at a sender is a
    /// reflection loop, not an answer.
    ///
    /// This is the answerer's whole contract as a pure function of `(source,
    /// datagram)`, so the on-machine rule and every answer class are testable
    /// without a socket.
    #[must_use]
    pub fn respond(&self, peer: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
        let request = match Message::from_vec(datagram) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %peer,
                    %error,
                    "dropping an unparseable box-zone datagram"
                );
                return None;
            }
        };
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        let query = request.queries.first().cloned()?;
        let qname = query.name().clone();
        let qtype = query.query_type();
        let asked = qname.to_lowercase().to_string();
        let asked = asked.strip_suffix('.').unwrap_or(&asked);

        // Off-host: no reply, one warn line (the only per-lookup warn there
        // is; every answered lookup gets its own debug line below).
        if !self.scope.allows(peer) {
            tracing::warn!(
                component = COMPONENT,
                %peer,
                name = asked,
                query_type = ?qtype,
                "refused an off-host box-zone lookup; the zone answers only this machine"
            );
            return None;
        }

        // Not a standard query: answered, with the code that says so.
        if request.metadata.op_code != OpCode::Query {
            let reply = Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::NotImp,
            );
            tracing::debug!(
                component = COMPONENT,
                name = asked,
                query_type = ?qtype,
                answer = "notimp",
                "answered a box-zone lookup"
            );
            return reply.to_vec().ok();
        }

        // Out of zone: this answerer is authoritative for `min.internal` and
        // nothing else, so a name that strayed in (a too-broad resolver
        // routing domain) is REFUSED — visibly, so the misconfiguration names
        // itself — with no authority section: the zone's SOA certifies our own
        // negatives, never someone else's namespace.
        let Some(zone_name) = in_zone(&qname) else {
            let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
            reply.metadata = Metadata::response_from_request(&request.metadata);
            reply.metadata.response_code = ResponseCode::Refused;
            reply.add_query(query);
            tracing::debug!(
                component = COMPONENT,
                name = asked,
                query_type = ?qtype,
                answer = "refused",
                "answered an out-of-zone lookup"
            );
            return reply.to_vec().ok();
        };

        // In-zone. The apex itself is held by the answerer: it carries the
        // SOA every negative cites, so an apex query is NODATA, never
        // NXDOMAIN — answering that the zone does not exist while citing its
        // SOA in the same reply would contradict itself.
        let entry = if zone_name == HOSTNAME_SUFFIX {
            ZoneEntry::Held {
                owner: HOSTNAME_SUFFIX.to_string(),
                address: None,
            }
        } else {
            self.zone
                // The node's own addresses travel empty today (see
                // [`super::dns::is_host_answerable`]).
                .zone_entry(&zone_name, &[])
        };
        let (rcode, answer, class) = match (&entry, qtype) {
            (ZoneEntry::Absent, _) => (ResponseCode::NXDomain, None, "nxdomain"),
            (ZoneEntry::Held { address: None, .. }, _) => (ResponseCode::NoError, None, "nodata"),
            (
                ZoneEntry::Held {
                    address: Some(address),
                    ..
                },
                RecordType::A,
            ) => {
                let record = Record::from_rdata(qname, ANSWER_TTL_SECS, RData::A(A(*address)));
                (ResponseCode::NoError, Some(record), "a")
            }
            (
                ZoneEntry::Held {
                    address: Some(_), ..
                },
                _,
            ) => (ResponseCode::NoError, None, "nodata"),
        };

        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&request.metadata);
        // Authoritative for the zone, and for nothing else (REFUSED above
        // never sets it).
        reply.metadata.authoritative = true;
        reply.metadata.response_code = rcode;
        reply.add_query(query);
        if let Some(record) = answer {
            reply.add_answer(record);
        }
        // Every negative carries the zone's SOA (NET-124): the record the
        // host resolver needs to cache the negative at all.
        if rcode != ResponseCode::NoError || reply.answers.is_empty() {
            reply.add_authority(self.soa.clone());
        }
        tracing::debug!(
            component = COMPONENT,
            name = asked,
            query_type = ?qtype,
            answer = class,
            "answered a box-zone lookup"
        );
        reply.to_vec().ok()
    }
}

/// The in-zone name a query carries, or `None` when it is outside the box
/// zone: `web.min.internal` for `Web.Min.Internal.`, the apex `min.internal`
/// for itself, `None` for `example.com.`. Returned in the registry's key form
/// (lower-cased, no root dot), including the deprecated three-label form
/// unchanged — [`HostnameRegistry::zone_entry`] maps that (NET-002).
fn in_zone(qname: &Name) -> Option<String> {
    // Wire names are FQDNs and render with the root dot: `Web.Min.Internal.`.
    let rendered = qname.to_lowercase().to_string();
    let without_root = rendered.strip_suffix('.')?;
    if without_root == HOSTNAME_SUFFIX {
        return Some(HOSTNAME_SUFFIX.to_string());
    }
    without_root
        .strip_suffix(&format!(".{HOSTNAME_SUFFIX}"))
        .map(|_| without_root.to_string())
}

/// One standard DNS query for `name` of `rtype`, encoded as the wire carries
/// it (FQDN, root dot included) — what `serve` hands [`ZoneAnswerer::respond`].
/// Test scaffolding shared with `server`'s tests, which drive the real startup
/// path through a socket.
#[cfg(test)]
pub(crate) fn encode_query(name: &str, rtype: RecordType) -> Vec<u8> {
    use hickory_proto::op::Query;

    let qname = Name::from_utf8(name).expect("query name parses");
    let mut msg = Message::query();
    msg.add_query(Query::query(qname, rtype));
    msg.to_vec().expect("query encodes")
}

/// The zone's SOA record, built once per answerer: the record every negative
/// answer carries in its authority section (NET-124), so the host resolver can
/// cache it — RFC 2308's negative TTL is this record's TTL capped by its
/// `minimum`. The zone has no secondaries, so every field but `minimum` is
/// inert; all of them carry the same 15 s so no number the answerer emits
/// exceeds NET-126's ceiling.
fn zone_soa() -> Record {
    let apex = Name::from_utf8(format!("{HOSTNAME_SUFFIX}.")).expect("the zone apex parses");
    let mname = Name::from_utf8(format!("ns.{HOSTNAME_SUFFIX}.")).expect("the SOA mname parses");
    let rname =
        Name::from_utf8(format!("hostmaster.{HOSTNAME_SUFFIX}.")).expect("the SOA rname parses");
    // `SOA` is `#[non_exhaustive]`, so the constructor is the only way in.
    let soa = SOA::new(
        mname,
        rname,
        1,
        ANSWER_TTL_SECS as i32,
        ANSWER_TTL_SECS as i32,
        ANSWER_TTL_SECS as i32,
        ANSWER_TTL_SECS,
    );
    Record::from_rdata(apex, ANSWER_TTL_SECS, RData::SOA(soa))
}

/// Binds the box-zone answerer's UDP socket at `addr`, returning it on
/// success. On a bind failure it returns a [`BindFailure`] carrying the reason
/// and the remedy and logs nothing — the caller owns the failure's log line,
/// because only it knows the retry schedule that line reports;
/// `server::start_host_proxies` retries with backoff until the bind succeeds
/// (NET-021's rule, applied to the answerer the same way). The success event
/// reports the address as `reachable` for the same reason
/// [`super::proxy::bind_listener`] does: binding only proves the address was
/// free, and [`serve`] is what makes it answer.
///
/// # Errors
///
/// Returns a [`BindFailure`] when the address cannot be bound; the OS error is
/// carried inside the failure's reason, and its kind beside it
/// ([`BindFailure::kind`]).
pub async fn bind_answerer(addr: SocketAddr) -> Result<UdpSocket, BindFailure> {
    match UdpSocket::bind(addr).await {
        Ok(socket) => {
            tracing::info!(
                component = COMPONENT,
                %addr,
                status = "reachable",
                "box-zone answerer listen address is bindable"
            );
            Ok(socket)
        }
        Err(error) => Err(BindFailure {
            reason: format!("the daemon could not bind {addr}: {error}"),
            remedy: format!(
                "free the listen address; `lsof -nP -iUDP:{}` names the holder",
                addr.port()
            ),
            kind: error.kind(),
        }),
    }
}

/// Serves the box zone on a bound socket, for the daemon's lifetime: one
/// datagram per turn, each either answered ([`ZoneAnswerer::respond`]) or
/// silently dropped — an off-host source, or something that is not a standard
/// query. A reply that cannot be sent is logged and skipped: a peer that
/// vanished mid-exchange must not take the answerer down.
///
/// # Errors
///
/// Returns the socket's error when the receive loop fails; the daemon logs it
/// and the answerer is gone until the daemon restarts (the same contract the
/// proxies' serve loops hold).
pub async fn serve<T: Zone>(socket: UdpSocket, answerer: ZoneAnswerer<T>) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        if let Some(reply) = answerer.respond(peer, &buf[..len])
            && let Err(error) = socket.send_to(&reply, peer).await
        {
            tracing::debug!(
                component = COMPONENT,
                %peer,
                %error,
                "could not send a box-zone reply"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use sessions::SessionId;

    use super::super::DEFAULT_SUBNET;
    use super::super::dns::{DEFAULT_HOST_ID, is_host_answerable};
    use super::*;

    /// A `MakeWriter` accumulating everything written into a shared buffer, so
    /// a test can assert on the structured fields a `tracing` event emitted.
    /// Same helper as `proxy`'s tests: log capture is per-module scaffolding.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// A registry the way the daemon fills it: a `HostNet` box `web` (its name
    /// routes to host loopback, R3.6) and an `OwnIp` box `api` attached at a
    /// switch lease (on a VM host its name routes straight to the lease,
    /// NET-001; on a native host it keeps the published-loopback model).
    fn registry(on_switch: bool) -> HostnameRegistry {
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, on_switch);
        reg.register_host_net(SessionId::nil(), "web");
        reg.report_own_address(
            SessionId::nil(),
            "api",
            Ipv4Addr::new(100, 64, 0, 7),
            BTreeMap::new(),
        );
        reg
    }

    /// The answerer over a fresh registry, sharing it the way the daemon does
    /// (behind the same `RwLock` the sessions manager hands out).
    fn answerer(
        reg: HostnameRegistry,
        scope: AnswerScope,
    ) -> ZoneAnswerer<std::sync::RwLock<HostnameRegistry>> {
        ZoneAnswerer::new(Arc::new(std::sync::RwLock::new(reg)), scope)
    }

    /// A source on this machine: a host resolver's datagram, from loopback.
    fn on_host() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)
    }

    /// A source from another host: TEST-NET-3, never assigned to a real
    /// interface.
    fn off_host() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 5353)
    }

    /// A source inside a microVM's switch fabric: an `OwnIp` box's lease, one
    /// more L2 client on the host-local switch.
    fn on_fabric() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), 5353)
    }

    /// Sends `datagram` to `answerer` as if from `peer` and decodes the reply
    /// it produced, if any.
    fn exchange<T: Zone>(
        answ: &ZoneAnswerer<T>,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Option<Message> {
        let reply = answ.respond(peer, datagram)?;
        Some(Message::from_vec(&reply).expect("the answerer's reply decodes"))
    }

    /// NET-006: the zone answers only lookups that originate on this machine.
    /// A datagram from another host gets nothing at all — not even a REFUSED,
    /// which would tell a scanner a DNS server is here — and one warn line per
    /// refusal names the source and the name it asked for. Natively the
    /// listener binds loopback, so the per-datagram check is defense in depth;
    /// inside a microVM the listener binds in-guest and the host-local switch
    /// fabric is the fabric the gvproxy forwarder rides, so a fabric peer is
    /// on-machine while an off-fabric one still gets nothing.
    #[test]
    fn min_internal_zone_not_served_off_host() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let native = answerer(registry(false), AnswerScope::Native);
        let lookup = encode_query("web.min.internal.", RecordType::A);

        // A lookup from this machine is answered.
        let reply = exchange(&native, on_host(), &lookup).expect("an on-host lookup is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            !reply.answers.is_empty(),
            "the held name answers its address"
        );

        // A lookup from another host gets nothing.
        assert!(
            exchange(&native, off_host(), &lookup).is_none(),
            "an off-host lookup must get no reply at all"
        );

        // ...and one warn line per refusal, naming where it came from and what
        // it asked for.
        let log = buf.contents();
        assert!(
            log.contains("web.min.internal"),
            "the refusal must name the lookup, got: {log}"
        );
        assert!(
            log.contains("203.0.113.7"),
            "the refusal must name the off-host source, got: {log}"
        );
        assert!(
            log.contains("off-host"),
            "the refusal must say why, got: {log}"
        );

        // In a microVM the listener binds in-guest: the host-local switch
        // fabric is on-machine (the gvproxy forwarder rides it), and a source
        // off that fabric is off-host all the same.
        let vm = answerer(
            registry(true),
            AnswerScope::Microvm {
                subnet: DEFAULT_SUBNET,
            },
        );
        assert!(
            exchange(&vm, on_fabric(), &lookup).is_some(),
            "a fabric peer is on this machine"
        );
        assert!(
            exchange(&vm, off_host(), &lookup).is_none(),
            "a source off the fabric is off-host"
        );
    }

    /// NET-007: no certificate and no audit record names a `*.min.internal`
    /// name. What this task adds to the system is the answerer and the zone
    /// table, and this proves both carry no certificate material: every
    /// certificate-bearing or name-carrying query type — CERT, TLSA, HTTPS,
    /// SVCB, TXT, NULL — is answered NODATA with no record of that type (the
    /// only record types an answer ever holds are A in the answers and the
    /// zone's own SOA in the authority), and a zone-table row serializes to
    /// exactly the name, its address, and its owner — there is no field for
    /// anything else to ride in.
    ///
    /// The rest of the requirement already holds outside this change: the
    /// only certificate authority in the daemon is the mTLS proxy's (feature
    /// `networking-proxy`), which mints `localhost`-SAN certificates and is
    /// untouched here, and the tree writes no audit log for the answerer to
    /// reach for.
    #[test]
    fn min_internal_absent_from_certs_and_audit() {
        let answ = answerer(registry(false), AnswerScope::Native);
        for rtype in [
            RecordType::AAAA,
            RecordType::CERT,
            RecordType::TLSA,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::NULL,
            RecordType::ANY,
        ] {
            let reply = exchange(&answ, on_host(), &encode_query("web.min.internal.", rtype))
                .expect("a held name answers every type");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "a held name is NODATA for {rtype:?}, never NXDOMAIN"
            );
            assert!(
                reply.answers.is_empty(),
                "NODATA carries no {rtype:?} record"
            );
            for record in reply.answers.iter().chain(&reply.authorities) {
                assert!(
                    matches!(&record.data, RData::SOA(_)),
                    "only the zone's own SOA appears, got {:?} for {rtype:?}",
                    record.record_type()
                );
            }
        }

        // The zone table the state dump gains: name, address, owner — nothing
        // else.
        let mut rows = registry(false).zone_table(&[]);
        let row = rows.pop().expect("the registered box has a row");
        assert_eq!(row.name, "web.min.internal");
        let json = serde_json_lenient::to_vec(&row).expect("the row serializes");
        let fields: BTreeMap<String, serde_json_lenient::Value> =
            serde_json_lenient::from_slice(&json).expect("a row is a JSON object");
        assert_eq!(
            fields.len(),
            3,
            "a row carries only the name, its address, and its owner: {fields:?}"
        );
        assert_eq!(fields["name"].as_str(), Some("web.min.internal"));
        assert_eq!(fields["address"].as_str(), Some("127.0.0.1"));
        assert_eq!(fields["owner"].as_str(), Some("web"));
    }

    /// NET-124: a lookup for any record type other than A on a name a box
    /// holds answers NODATA — an empty NOERROR, authoritative — never
    /// NXDOMAIN: negative caching is name-wide, browsers pair A lookups with
    /// HTTPS-type ones, and NXDOMAIN would poison the live box's name. A name
    /// held at an address the host may not be told answers the same way for
    /// A itself: the box exists, so its name is never negatively poisoned. So
    /// does the zone's own apex — it is held by the answerer, which cites the
    /// zone's SOA in every negative.
    #[test]
    fn non_a_in_zone_query_is_nodata() {
        let native = answerer(registry(false), AnswerScope::Native);
        for rtype in [
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
        ] {
            let reply = exchange(
                &native,
                on_host(),
                &encode_query("web.min.internal.", rtype),
            )
            .expect("a held name answers every type");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "NODATA for {rtype:?}"
            );
            assert!(
                reply.metadata.authoritative,
                "the answerer is authoritative for the zone"
            );
            assert!(reply.answers.is_empty(), "NODATA carries no records");
            assert_eq!(
                reply.authorities.len(),
                1,
                "a negative carries the zone's SOA"
            );
        }

        // A name held at a switch lease (an `OwnIp` box on a VM host): even an
        // A lookup is NODATA, not NXDOMAIN — held-without-A is not absent.
        let vm = answerer(
            registry(true),
            AnswerScope::Microvm {
                subnet: DEFAULT_SUBNET,
            },
        );
        let reply = exchange(
            &vm,
            on_host(),
            &encode_query("api.min.internal.", RecordType::A),
        )
        .expect("a held name is answered");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "held-without-A is NODATA, never NXDOMAIN"
        );
        assert!(reply.answers.is_empty());

        // The zone's own apex: held by the answerer, so NODATA.
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("min.internal.", RecordType::A),
        )
        .expect("the apex is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
    }

    /// NET-124's sub-requirement: every negative — NODATA and NXDOMAIN —
    /// carries the zone's SOA record in the authority section, so the host
    /// resolver can cache it: RFC 2308's negative TTL is that record's TTL
    /// capped by its `minimum`, and an uncacheable negative stalls every
    /// lookup on a macOS host, not only the zone's.
    #[test]
    fn negative_answers_carry_zone_authority() {
        let native = answerer(registry(false), AnswerScope::Native);
        let negatives = [
            ("web.min.internal.", RecordType::AAAA), // NODATA: non-A on a held name
            ("min.internal.", RecordType::A),        // NODATA: the apex
            ("ghost.min.internal.", RecordType::A),  // NXDOMAIN: nothing holds it
        ];
        for (name, rtype) in negatives {
            let reply = exchange(&native, on_host(), &encode_query(name, rtype))
                .expect("an in-zone lookup is answered");
            let [soa] = &reply.authorities[..] else {
                panic!("the negative for {name} must carry exactly the zone's SOA")
            };
            assert_eq!(soa.record_type(), RecordType::SOA, "for {name}");
            assert_eq!(
                soa.name,
                Name::from_utf8("min.internal.").unwrap(),
                "the SOA's owner is the zone apex"
            );
            let RData::SOA(soa) = &soa.data else {
                panic!("the authority record is the SOA")
            };
            assert_eq!(
                soa.minimum, ANSWER_TTL_SECS,
                "the negative TTL must be cacheable: {name}"
            );
        }

        // Held-without-A (an `OwnIp` box on a VM host) is a negative the same
        // way: its NODATA carries the SOA too.
        let vm = answerer(
            registry(true),
            AnswerScope::Microvm {
                subnet: DEFAULT_SUBNET,
            },
        );
        let reply = exchange(
            &vm,
            on_host(),
            &encode_query("api.min.internal.", RecordType::A),
        )
        .expect("a held name is answered");
        assert_eq!(reply.authorities.len(), 1, "NODATA carries the zone's SOA");
    }

    /// NET-125: a lookup for an in-zone name that no box or node holds answers
    /// NXDOMAIN — authoritative, no answers, the zone's SOA so the negative
    /// caches. A name outside the box zone is not NXDOMAIN (this answerer is
    /// authoritative for `min.internal` and nothing else): it is REFUSED, so a
    /// too-broad resolver routing domain names itself rather than this
    /// answerer fabricating an NXDOMAIN for someone else's namespace.
    #[test]
    fn unknown_in_zone_name_is_nxdomain() {
        let native = answerer(registry(false), AnswerScope::Native);

        let reply = exchange(
            &native,
            on_host(),
            &encode_query("ghost.min.internal.", RecordType::A),
        )
        .expect("an in-zone name is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            reply.metadata.authoritative,
            "in-zone answers are authoritative"
        );
        assert!(reply.answers.is_empty(), "NXDOMAIN carries no answers");
        assert_eq!(
            reply.authorities.len(),
            1,
            "NXDOMAIN carries the zone's SOA"
        );

        // The deprecated three-label form of an unknown name is unknown too.
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("ghost.local.min.internal.", RecordType::A),
        )
        .expect("the legacy form is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);

        // A withdrawn name is unknown again once its session ends.
        let shared = Arc::new(std::sync::RwLock::new(registry(false)));
        shared.write().unwrap().deregister("web");
        let answ = ZoneAnswerer::new(Arc::clone(&shared), AnswerScope::Native);
        let reply = exchange(
            &answ,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the zone still answers");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a withdrawn name is held by nothing"
        );

        // Out of zone is REFUSED, not NXDOMAIN.
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("example.com.", RecordType::A),
        )
        .expect("the answerer refuses rather than ignoring");
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(!reply.metadata.authoritative, "not our zone");
        assert!(
            reply.authorities.is_empty(),
            "the zone's SOA certifies our negatives only"
        );
    }

    /// NET-126: every record the answerer emits — A answers, and the SOA every
    /// negative carries — holds a TTL of at most 15 s, so a box published a
    /// moment ago is found without reloading the host resolver and no cached
    /// answer outlives the registry's next change.
    #[test]
    fn zone_answers_carry_short_ttl() {
        let native = answerer(registry(false), AnswerScope::Native);
        for (name, rtype) in [
            ("web.min.internal.", RecordType::A),     // a positive A answer
            ("web.min.internal.", RecordType::HTTPS), // NODATA
            ("ghost.min.internal.", RecordType::A),   // NXDOMAIN
        ] {
            let reply = exchange(&native, on_host(), &encode_query(name, rtype))
                .expect("an in-zone lookup is answered");
            for record in reply.answers.iter().chain(&reply.authorities) {
                assert!(
                    record.ttl <= ANSWER_TTL_SECS,
                    "{} in the reply for {name} {rtype:?} carries a {}s TTL",
                    record.name,
                    record.ttl
                );
            }
        }

        // The A answer itself: exactly the cap.
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the held name answers");
        assert_eq!(reply.answers[0].ttl, ANSWER_TTL_SECS);
    }

    /// NET-127: an A lookup answered for the host OS carries only an address in
    /// the reserved local range, the node's own addresses, or `127.0.0.1`.
    /// The guard is the gate: any other address a route might hold — a box's
    /// switch lease, an address another host owns — answers NODATA instead of
    /// leaking, and NODATA rather than NXDOMAIN because the box exists.
    #[test]
    fn host_zone_a_answers_confined_to_local_addresses() {
        // The guard: the three permitted classes answer, everything else does
        // not.
        let node = [Ipv4Addr::new(192, 168, 1, 20)];
        assert!(
            is_host_answerable(Ipv4Addr::LOCALHOST, &node),
            "127.0.0.1 answers"
        );
        assert!(
            is_host_answerable(Ipv4Addr::new(127, 64, 0, 1), &node),
            "the reserved local range answers"
        );
        assert!(
            !is_host_answerable(Ipv4Addr::new(127, 64, 1, 0), &node),
            "the reserved range is a /24; past it, nothing answers"
        );
        assert!(
            is_host_answerable(node[0], &node),
            "one of the node's own addresses answers"
        );
        assert!(
            !is_host_answerable(Ipv4Addr::new(100, 64, 0, 7), &[]),
            "a box's switch lease does not answer the host"
        );
        assert!(
            !is_host_answerable(Ipv4Addr::new(10, 9, 9, 9), &[]),
            "an address another host holds does not answer"
        );

        // Through the answerer: a `HostNet` box answers the host loopback...
        let native = answerer(registry(false), AnswerScope::Native);
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the held name answers");
        let [answer] = &reply.answers[..] else {
            panic!("an A lookup on a held-with-A name answers once")
        };
        assert_eq!(answer.record_type(), RecordType::A);
        let RData::A(A(addr)) = &answer.data else {
            panic!("the answer is an A record")
        };
        assert_eq!(*addr, Ipv4Addr::LOCALHOST);

        // ...and so does an `OwnIp` box on a native host, whose name keeps the
        // published-loopback model.
        let reply = exchange(
            &native,
            on_host(),
            &encode_query("api.min.internal.", RecordType::A),
        )
        .expect("the published-loopback name answers");
        let RData::A(A(addr)) = &reply.answers[0].data else {
            panic!("the answer is an A record")
        };
        assert_eq!(*addr, Ipv4Addr::LOCALHOST);

        // The same `OwnIp` box on a VM host routes at its lease inside the
        // fabric; the host is told nothing — no A answer, and the zone table
        // reports the name held without an address, not absent.
        let vm = answerer(
            registry(true),
            AnswerScope::Microvm {
                subnet: DEFAULT_SUBNET,
            },
        );
        let reply = exchange(
            &vm,
            on_host(),
            &encode_query("api.min.internal.", RecordType::A),
        )
        .expect("the held name is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.answers.is_empty(),
            "a box's switch lease must not leak to the host"
        );
        let api = registry(true)
            .zone_table(&[])
            .into_iter()
            .find(|row| row.name == "api.min.internal")
            .expect("a held name has a zone-table row");
        assert_eq!(api.address, None, "held-without-A, not absent");
        assert_eq!(api.owner, "api");
    }
}
