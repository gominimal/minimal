//! The box-zone answerer: the always-on loopback DNS server that answers
//! `*.min.internal` for the host OS (design §7.1, NET-009).
//!
//! The hostname proxy ([`super::proxy`]) routes by `Host:` header; this is
//! the other half of resolution — the DNS reply the host's own resolver gets
//! when a process looks a box name up, no proxy variable involved. On a
//! native host the zone is answered by the machine's *one* answerer
//! (NET-122): the root-installed `min-answerer` service the manager holds
//! when the host is hooked, and until then the interim this daemon itself
//! hosts. The acquisition below decides which — publish-or-host, never both
//! — over the machine-global channel (`acquire`), the same machine contract
//! the VM host daemon's answerer (`minvmd`) keeps; a daemon running inside a
//! microVM starts no answerer at all, and this module is the *native*
//! deployment's half of the same semantics. The semantics are not
//! per-deployment either way: they live in the shared decision
//! ([`sessions::core::zone_answer`]), and what this module owns is the DNS
//! wire — decoding a query, encoding the reply the decision's verdict
//! names, and the SOA its negatives cite — plus the channel wire its rows
//! publish over.
//!
//! Answer semantics, all decided by the shared core, and all gated on the
//! lookup originating on this machine (NET-006 — the zone leaves the machine
//! with *nothing*, not even a refusal, which would tell a scanner a DNS
//! server is here):
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use sessions::core::zone_answer;

use super::SwitchSubnet;
use super::dns::{HOSTNAME_SUFFIX, HostnameRegistry, ZoneEntry};
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
    /// Inside a microVM (DM1/3/4): loopback and the host-local switch's own
    /// subnet are both on-machine — the guest's only fabric is the switch —
    /// and anything outside them is off-host and gets nothing.
    ///
    /// Since the VM host daemon took over the zone for a VM-backed host, no
    /// production daemon serves under this scope: `start_host_proxies` starts
    /// the answerer only on a native host, and the in-VM daemon answers
    /// nothing (`minvmd`'s host answerer answers the zone from the host's
    /// table instead). The variant stays the scope's complete answer — the
    /// on-machine rule it states is the one the shared decision's origin
    /// input carries, and the tests below still prove it.
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

    /// The shared decision's origin for a datagram from `peer`: on this
    /// machine, or off it (NET-006) — the one input the decision is gated on
    /// that does not come off the query itself.
    fn origin_for(&self, peer: SocketAddr) -> zone_answer::Origin {
        if self.allows(peer) {
            zone_answer::Origin::OnMachine
        } else {
            zone_answer::Origin::OffMachine
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

        // The lookup and the view, both resolved from this answerer's own
        // halves, then the shared decision over them: where the datagram came
        // from and what the registry holds for the name are this module's to
        // say; which answer class that lookup gets is the core's.
        let lookup = zone_answer::Lookup {
            name: asked.to_string(),
            record: if qtype == RecordType::A {
                zone_answer::RecordType::A
            } else {
                zone_answer::RecordType::Other
            },
            origin: self.scope.origin_for(peer),
        };
        let view = self.zone_view(asked);
        match zone_answer::decide(&lookup, &view) {
            // Off-host: no reply, one warn line (the only per-lookup warn
            // there is; every answered lookup gets its own debug line below).
            zone_answer::Verdict::Silent => {
                tracing::warn!(
                    component = COMPONENT,
                    %peer,
                    name = asked,
                    query_type = ?qtype,
                    "refused an off-host box-zone lookup; the zone answers only this machine"
                );
                None
            }
            // Not a standard query: answered, with the code that says so — but
            // only where the decision answers at all: an off-host datagram
            // already got its silence above, whatever it carried.
            _ if request.metadata.op_code != OpCode::Query => {
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
                reply.to_vec().ok()
            }
            // Out of zone: this answerer is authoritative for the box zone
            // and nothing else, so a name that strayed in (a too-broad
            // resolver routing domain) is REFUSED — visibly, so the
            // misconfiguration names itself — with no authority section: the
            // zone's SOA certifies our own negatives, never someone else's
            // namespace.
            zone_answer::Verdict::Refused => {
                let reply = self.reply(&request, query, ResponseCode::Refused, None, false);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "refused",
                    "answered an out-of-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Nodata => {
                let reply = self.reply(&request, query, ResponseCode::NoError, None, true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "nodata",
                    "answered a box-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Nxdomain => {
                let reply = self.reply(&request, query, ResponseCode::NXDomain, None, true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "nxdomain",
                    "answered a box-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Address(address) => {
                let record =
                    Record::from_rdata(qname, zone_answer::ANSWER_TTL_SECS, RData::A(A(address)));
                let reply = self.reply(&request, query, ResponseCode::NoError, Some(record), true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "a",
                    "answered a box-zone lookup"
                );
                reply
            }
        }
    }

    /// The zone view the decision answers from: the registry's own resolution
    /// of the asked name, as the one row it holds for it. The registry stays
    /// the name authority — it maps the deprecated three-label form
    /// (NET-002), and the address it gives is already the answer the zone
    /// means to give, with the host-answerable gate (NET-127) and the
    /// stopped-shared-address fold (NET-128) applied — so its row *is* this
    /// lookup's view: held, with the address to tell or without one, and live,
    /// because everything this registry knows about a stopped namespace it
    /// has already folded into that address.
    fn zone_view(&self, asked: &str) -> zone_answer::ZoneView {
        let mut view = zone_answer::ZoneView::new();
        if let ZoneEntry::Held { address, .. } = self
            .zone
            // The node's own addresses travel empty today (see
            // [`super::dns::is_host_answerable`]).
            .zone_entry(asked, &[])
        {
            view.hold(
                asked.to_string(),
                zone_answer::ZoneRow {
                    address,
                    live: true,
                },
            );
        }
        view
    }

    /// The reply bytes for one answered lookup: the envelope every verdict's
    /// reply shares — the query echoed, the rcode named, and the answer
    /// record in the answer section when there is one — authoritative for the
    /// zone and for nothing else (the REFUSED reply is not, so it never cites
    /// our SOA over someone else's namespace). The negatives the zone
    /// certifies are its own — an authoritative reply with no answer records,
    /// NODATA and NXDOMAIN — and every one of them carries the zone's SOA in
    /// the authority section (NET-124): the record the host resolver needs to
    /// cache the negative at all.
    fn reply(
        &self,
        request: &Message,
        query: hickory_proto::op::Query,
        rcode: ResponseCode,
        answer: Option<Record>,
        authoritative: bool,
    ) -> Option<Vec<u8>> {
        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&request.metadata);
        reply.metadata.authoritative = authoritative;
        reply.metadata.response_code = rcode;
        reply.add_query(query);
        if let Some(record) = answer {
            reply.add_answer(record);
        }
        if authoritative && reply.answers.is_empty() {
            reply.add_authority(self.soa.clone());
        }
        reply.to_vec().ok()
    }
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
/// inert; all of them carry the shared decision's TTL ceiling
/// ([`zone_answer::ANSWER_TTL_SECS`]) so no number the answerer emits exceeds
/// NET-126's bound.
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
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS,
    );
    Record::from_rdata(apex, zone_answer::ANSWER_TTL_SECS, RData::SOA(soa))
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

// ── the acquisition: publish-or-host over the machine-global channel ─────────
//
// NET-122's host half: on a hooked host the zone is answered by the one
// root-installed `min-answerer` service the service manager holds, and this
// daemon is that answerer's *client* — it connects to the machine-global
// channel, says its node id, and keeps its zone rows published there for as
// long as the connection lives. Until the host is hooked, nothing serves
// that channel, and the daemon hosts the interim answerer itself: the same
// socket this module's serve loop always answered, now recorded as the
// single-operator interim the installer's release handover takes over. The
// two states are mutually exclusive — publish when the channel answers,
// host only when the channel path is absent and the hook port is free —
// and a channel that is present but refuses or times out is a surfaced
// error, never a reason to host: an operator who installed the service
// wants the service, and a corpse at the channel path is a fault to name,
// not a seat to take. The wire is `minvmd`'s channel protocol, spoken by
// the copy of it the node-side half of that crate owns; both copies must
// stay serde-compatible, and the version the hello carries is what the
// serving side gates on.

/// The channel protocol version this daemon speaks, and the installed
/// service gates on: one number for the whole wire — the hello's fields,
/// the publish's, the reply's. The service a NET-122 step installs answers
/// it; a future wire bumps both sides together.
const CHANNEL_PROTOCOL_VERSION: u32 = 3;

/// The machine-global channel socket the installed answerer service's unit
/// holds (NET-122's host service): one per host, whatever this daemon's
/// state dir. The same path `minvmd`'s channel protocol resolves, so a
/// native daemon and a VM host daemon on one machine are clients of one
/// answerer.
pub const GLOBAL_CHANNEL_SOCK: &str = "/run/minimal/answerer.sock";

/// The installed service's marker: the socket unit file whose presence —
/// and only whose presence — says the answerer service is installed on
/// this host. The channel socket's path existing never says so: a stale
/// socket file with no marker beside it is a leftover, not a service.
pub const INSTALL_MARKER: &str = "/etc/systemd/system/dev.minimal.zone-answerer.socket";

/// The variable that overrides [`GLOBAL_CHANNEL_SOCK`] — read only by test
/// and debug builds (the e2e harness's), never by a release build, so no
/// production configuration can point this daemon at another channel.
pub const CHANNEL_SOCK_ENV: &str = "MINIMAL_ANSWERER_CHANNEL_SOCK";

/// The variable that overrides [`INSTALL_MARKER`], under the same rule as
/// [`CHANNEL_SOCK_ENV`].
pub const INSTALL_MARKER_ENV: &str = "MINIMAL_ANSWERER_INSTALL_MARKER";

/// The largest line either side of the channel will read: a publish carries
/// one row per published namespace; anything past this bound is not one.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// How long the acquisition waits between wake slices while its publish is
/// held: the table-diff poll's cadence, the bound on a channel death going
/// unnoticed (the peek below reads the held connection each slice), and the
/// release window's poll — the one number that keeps every wait in this
/// module short.
const CONNECTION_POLL: Duration = Duration::from_millis(250);

/// How long the acquisition waits before re-deciding the answerer when
/// nothing woke it — a full re-publish, or a fresh publish-or-host pass:
/// long enough that a live answerer sees no chatter, short enough that a
/// channel that came up while the daemon idled is found within half a
/// minute.
const PORT_RECHECK: Duration = Duration::from_secs(30);

/// The first backoff after a channel that is present but did not answer:
/// doubled per retry, capped at [`PORT_RECHECK`], the same schedule the
/// hostname proxy's startup retries on.
const CHANNEL_RETRY: Duration = Duration::from_millis(250);

/// How long a released interim waits for the installed service's channel
/// before it re-binds itself (NET-122's bounded handover): the window the
/// installer's release-then-start step fits its `systemctl start` inside.
const RELEASE_WINDOW: Duration = Duration::from_secs(15);

/// How long the release window polls for the service's channel and its
/// commands ([`CONNECTION_POLL`]'s cadence).
const RELEASE_POLL: Duration = CONNECTION_POLL;

/// How long any one channel exchange — a hello's reply, a publish's ack —
/// may take before the attempt counts as a refusal: a present channel that
/// does not answer within it is an error, never a reason to host.
const CHANNEL_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Who answered the hello, as the reply's `holder` field names it: the
/// installed service the manager holds. The other holder a channel can
/// name is `minvmd`'s interim — a state a native host never publishes into
/// (its interim channel is the per-user one, not this machine-global
/// socket), but the word is the wire's, and the status maps both.
const SERVICE_HOLDER: &str = "service";

/// The other holder a hello can name: a daemon hosting the interim.
const DAEMON_HOLDER: &str = "daemon";

/// A path override from `var`, honoured only in test and debug builds.
fn debug_path_override(var: &str) -> Option<PathBuf> {
    #[cfg(any(test, debug_assertions))]
    {
        std::env::var_os(var)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(any(test, debug_assertions)))]
    {
        let _ = var;
        None
    }
}

/// Resolve the machine-global answerer channel's path: the one channel the
/// installed service holds ([`GLOBAL_CHANNEL_SOCK`]), the same for every
/// daemon of the operator on the host whatever its state dir.
#[must_use]
pub fn resolve_channel_sock() -> PathBuf {
    debug_path_override(CHANNEL_SOCK_ENV).unwrap_or_else(|| PathBuf::from(GLOBAL_CHANNEL_SOCK))
}

/// Resolve the installed service's marker ([`INSTALL_MARKER`]).
#[must_use]
pub fn resolve_install_marker() -> PathBuf {
    debug_path_override(INSTALL_MARKER_ENV).unwrap_or_else(|| PathBuf::from(INSTALL_MARKER))
}

/// The paths one acquisition decides over: the machine-global channel, the
/// install marker that says whether the service is installed, and the
/// release window a handover waits. A test names all three; production
/// reads them from the machine ([`acquire`]).
#[derive(Debug, Clone)]
pub(crate) struct AnswererPaths {
    /// The installed service's machine-global channel.
    channel: PathBuf,
    /// The installed service's marker file.
    marker: PathBuf,
    /// How long a released interim waits for the service's channel before
    /// it re-binds ([`RELEASE_WINDOW`] in production).
    release_window: Duration,
}

/// The bind the manager-held answerer is recorded at: the socket unit's
/// own `ListenDatagram` (127.0.0.1 at [`ANSWERER_PORT`]), the address and
/// port the loaded table's carve-out names and the live-answerer cell takes
/// while this daemon publishes — the one bind the installer records, so a
/// deny-all box's launch check keeps reading the answerer actually serving
/// (T75's cell, fed here by the publish that reached it).
fn recorded_service_bind() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, ANSWERER_PORT))
}

// ── the channel's wire ──────────────────────────────────────────────────────

/// One row of a registration: the zone name (`<name>.min.internal`), the
/// host-answerable address a lookup may be told, and the row's liveness —
/// the registry's own zone row ([`HostnameRegistry::zone_table`]), on the
/// wire. The registry built the row (NET-138: a registered row is
/// host-authored by the daemon that owns the table it came from); the
/// holder re-applies the address gate as it folds the row in, so no
/// registration can put an address in the zone the host may not be told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisteredRow {
    /// The full zone name, as the registry holds it.
    name: String,
    /// The address an A lookup gets, if there is one to tell.
    address: Option<Ipv4Addr>,
    /// Whether the namespace the name names is running. The registry's
    /// zone row has already folded everything it knows about a stopped
    /// namespace into the address, so a live row whose address is `None`
    /// is a held name with nothing to tell (NODATA), not a dead one.
    live: bool,
}

/// The first line a node sends on the channel: who is connecting, and which
/// protocol its copy speaks. The node id is the daemon's canonical identity
/// dir ([`node_id`]); the version is [`CHANNEL_PROTOCOL_VERSION`] as this
/// copy holds it, and a mismatch is the one reason a healthy channel
/// refuses a node outright.
#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    /// The connecting node's id.
    node: String,
    /// The channel protocol version the connecting copy speaks.
    version: u32,
}

/// One publish over the channel: a whole table's zone rows, one line. The
/// *message*, not the publish itself — that is the node's held connection
/// ([`Registration`]), which outlives the line it arrived by for exactly as
/// long as its rows are held.
#[derive(Debug, Serialize, Deserialize)]
struct PublishRequest {
    /// The sender's zone rows, in the registry's name order.
    rows: Vec<RegisteredRow>,
}

/// One row the serving side refused to hold, with the reason it named: the
/// reply a publish carries names every row it did not take, so the daemon
/// that sent it can warn about the name it lost — and about the address
/// the host may not be told — at the moment it happens, not at the first
/// lookup that finds the row absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RefusedRow {
    /// The refused row's zone name.
    name: String,
    /// Why the serving side refused it.
    reason: String,
}

/// The serving side's one-line reply to a hello or a publish: the ack a
/// node waits for, so it knows its rows are answering before it stops
/// trying — or the reason it is not — and, on a hello, which kind of
/// answerer is holding the port (the installed service, or the interim
/// holder daemon), the fact this daemon's own start line names.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationReply {
    /// Whether the line was held.
    ok: bool,
    /// The reason a line was refused, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The rows a publish carried that were not held, with their reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refused: Vec<RefusedRow>,
    /// Who answered a hello: `service` (the installed host service) or
    /// `daemon` (the interim holder). Absent on a publish's reply, and on
    /// old wires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holder: Option<String>,
}

/// Writes one line of the channel's wire: `message` serialized, one `\n`.
/// Every message on the channel is a single line, so the read on the other
/// side answers a whole message per call.
async fn write_line<T: ?Sized + Serialize>(
    stream: &mut tokio::net::UnixStream,
    message: &T,
) -> io::Result<()> {
    let mut line = serde_json_lenient::to_string(message).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("channel line did not serialize: {error}"),
        )
    })?;
    line.push('\n');
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

/// Reads one bounded reply line: the whole line inside
/// [`CHANNEL_REPLY_TIMEOUT`], or the error that says it did not come. A
/// reply is a single write on the other side, and a channel that is
/// present but does not answer is an error here, never a silent pass.
async fn read_reply_line(stream: &mut tokio::net::UnixStream) -> io::Result<Option<String>> {
    use tokio::io::AsyncReadExt as _;

    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&line).into_owned()))
            };
        }
        if let Some(newline) = buf[..read].iter().position(|byte| *byte == b'\n') {
            line.extend_from_slice(&buf[..newline]);
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        line.extend_from_slice(&buf[..read]);
        if line.len() > MAX_REQUEST_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("channel line exceeded {MAX_REQUEST_LINE} bytes without a newline"),
            ));
        }
    }
}

/// This daemon's publish, held by the connection it arrived on: dropping
/// this retires the rows — the connection's end is the whole withdrawal,
/// so a daemon that exits never leaves names answering behind it — and
/// [`send`](Self::send) re-publishes over the same connection,
/// idempotently: the same table again replaces the same rows and changes
/// nothing.
struct Registration {
    /// The held connection: this publish's lifetime.
    stream: tokio::net::UnixStream,
}

impl Registration {
    /// Re-publishes `rows` over the held connection, waiting for the
    /// answerer's ack: a publish that did not land is not held, and the
    /// error tells the caller to connect again. The refused rows come
    /// back with the ack, so the caller can warn about a name it lost —
    /// and about an address the host may not be told — when it happens,
    /// not at the first lookup that finds the row absent.
    async fn send(&mut self, rows: Vec<RegisteredRow>) -> io::Result<Vec<RefusedRow>> {
        write_line(&mut self.stream, &PublishRequest { rows }).await?;
        let reply_line =
            tokio::time::timeout(CHANNEL_REPLY_TIMEOUT, read_reply_line(&mut self.stream))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the answerer did not acknowledge the publish in time",
                    )
                })??;
        let Some(reply_line) = reply_line else {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "the answerer's end of the channel closed before it acknowledged the publish",
            ));
        };
        let reply: RegistrationReply =
            serde_json_lenient::from_str(&reply_line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the answerer's reply did not parse: {error}"),
                )
            })?;
        if !reply.ok {
            return Err(io::Error::new(
                // PermissionDenied, not ConnectionRefused: the answerer is
                // there and answered no — ConnectionRefused is reserved
                // for the connect itself, the marker of a channel socket
                // file with no listener behind it.
                io::ErrorKind::PermissionDenied,
                reply
                    .error
                    .unwrap_or_else(|| "the answerer refused the publish".to_string()),
            ));
        }
        Ok(reply.refused)
    }

    /// Whether the answerer's end of the held connection is still there:
    /// one peeked byte, never consumed, so a reply the next publish waits
    /// for stays its next read's. `Ok(false)` — the end closed (a service
    /// restart): the rows this connection held are gone with it, and the
    /// next pass reconnects and re-publishes. `Err` for anything the
    /// socket could not say, read as the same loss.
    fn answerer_alive(&self) -> io::Result<bool> {
        use std::os::fd::AsRawFd as _;

        let mut probe = 0u8;
        // SAFETY: recv writes at most one byte into `probe`, whose length is
        // passed alongside it; the fd is the stream's own and stays valid
        // for the borrow's life. MSG_PEEK never consumes, MSG_DONTWAIT
        // never blocks.
        let seen = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                std::ptr::addr_of_mut!(probe).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if seen < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
            {
                // Nothing waiting: the answerer's end has said nothing —
                // which a live one that has nothing to say is exactly how.
                return Ok(true);
            }
            return Err(error);
        }
        Ok(seen != 0)
    }
}

/// What a first publish learned: the held connection, which kind of
/// answerer holds the port (as its hello ack named it — the installed
/// service, or the interim holder daemon; the fact this daemon's own
/// start line repeats), and the rows the answerer refused.
struct Published {
    /// The held connection: this publish's lifetime.
    registration: Registration,
    /// Which kind of answerer the rows went to.
    holder: String,
    /// The rows the answerer refused, with their reasons.
    refused: Vec<RefusedRow>,
}

/// Connects to the channel at `channel` and publishes `rows` over it: the
/// hello with this node's id and protocol version, then the one publish
/// the connection is held for. The error kinds the acquisition decides
/// over: `NotFound` (no channel at the path), `ConnectionRefused` (a
/// socket file with no listener behind it — a corpse), and every other
/// failure a present channel that did not answer.
async fn connect_and_publish(
    channel: &std::path::Path,
    node: &str,
    rows: Vec<RegisteredRow>,
) -> io::Result<Published> {
    let mut stream = tokio::net::UnixStream::connect(channel).await?;
    write_line(
        &mut stream,
        &Hello {
            node: node.to_string(),
            version: CHANNEL_PROTOCOL_VERSION,
        },
    )
    .await?;
    let reply_line = tokio::time::timeout(CHANNEL_REPLY_TIMEOUT, read_reply_line(&mut stream))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "the answerer service did not answer the hello in time",
            )
        })??;
    let Some(reply_line) = reply_line else {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "the answerer's end of the channel closed before its hello reply",
        ));
    };
    let reply: RegistrationReply = serde_json_lenient::from_str(&reply_line).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the answerer's hello reply did not parse: {error}"),
        )
    })?;
    if !reply.ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            reply
                .error
                .unwrap_or_else(|| "the answerer refused this node's hello".to_string()),
        ));
    }
    let holder = reply.holder.unwrap_or(DAEMON_HOLDER.to_string());
    let mut registration = Registration { stream };
    let refused = registration.send(rows).await?;
    Ok(Published {
        registration,
        holder,
        refused,
    })
}

/// The registry's whole zone table as the channel's rows: the same rows
/// the serving decision would answer a lookup from, address gate and
/// stopped-shared fold already applied by
/// [`HostnameRegistry::zone_table`] — the node's own addresses travel
/// empty today, exactly as [`ZoneAnswerer::zone_view`] passes them, so
/// what publishes is what answers. Read from behind the daemon's
/// `RwLock`, poison recovery matching the serving side's read of the same
/// lock: a panicked writer's half-state is answered as it stands, never
/// silently retired.
fn zone_rows_of(registry: &Arc<std::sync::RwLock<HostnameRegistry>>) -> Vec<RegisteredRow> {
    let rows = match registry.read() {
        Ok(guard) => guard.zone_table(&[]),
        Err(poisoned) => poisoned.into_inner().zone_table(&[]),
    };
    rows.into_iter()
        .map(|row| RegisteredRow {
            name: row.name,
            address: row.address,
            live: true,
        })
        .collect()
}

/// This daemon's node id: the canonical identity dir the daemon runs under
/// (its provider instance dir), so the id is the same across restarts and
/// across symlinked spellings of one dir, and no two instances of the
/// daemon on one machine share one. The `#native` tail is the wire's shape
/// — a node's id is a dir and what it runs as, the way a VM host daemon's
/// is a dir and its VM's name.
fn node_id(identity_dir: &std::path::Path) -> String {
    let canonical =
        std::fs::canonicalize(identity_dir).unwrap_or_else(|_| identity_dir.to_path_buf());
    format!("{}#native", canonical.display())
}

// ── the status the control surface answers from ──────────────────────────────

/// The answer to a release or a cancel: whether it changed anything, and
/// the sentence the daemon logged for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseReply {
    /// Whether the request changed anything.
    pub acted: bool,
    /// What the daemon did.
    pub detail: String,
}

impl ReleaseReply {
    fn acted(detail: impl Into<String>) -> Self {
        Self {
            acted: true,
            detail: detail.into(),
        }
    }

    fn no_op(detail: impl Into<String>) -> Self {
        Self {
            acted: false,
            detail: detail.into(),
        }
    }
}

/// One handover request, carrying where its answer goes.
#[derive(Debug)]
pub(crate) enum HandoverCommand {
    /// Stop the interim and free the port; wait for the service's channel.
    Release(oneshot::Sender<ReleaseReply>),
    /// Re-bind the interim at once.
    Cancel(oneshot::Sender<ReleaseReply>),
}

/// What the acquisition and the control surface share: the status cell, and
/// the handover's door — whether this daemon hosts the interim (the only
/// state a release or a cancel can act on), and the sender the
/// acquisition listens on for both.
#[derive(Debug)]
struct AnswererShared {
    status: std::sync::Mutex<minimald_rpc::ZoneAnswererStatus>,
    hosting: std::sync::atomic::AtomicBool,
    commands: std::sync::Mutex<Option<mpsc::Sender<HandoverCommand>>>,
}

/// The acquisition's state as the surfaces read it
/// ([`minimald_rpc::ZoneAnswererStatus`]) and the door its handover verbs
/// knock on: a cloneable cell the acquisition writes from its own task and
/// the daemon's control socket answers `answerer_status`, `release` and
/// `release_cancel` from, exactly the shape `minvmd`'s control socket
/// serves on a VM-backed host.
#[derive(Debug, Clone)]
pub(crate) struct AnswererStatus(Arc<AnswererShared>);

impl AnswererStatus {
    /// A status whose acquisition has not run yet.
    #[must_use]
    pub(crate) fn starting() -> Self {
        Self(Arc::new(AnswererShared {
            status: std::sync::Mutex::new(minimald_rpc::ZoneAnswererStatus::Starting),
            hosting: std::sync::atomic::AtomicBool::new(false),
            commands: std::sync::Mutex::new(None),
        }))
    }

    /// The state the acquisition last wrote.
    #[must_use]
    pub(crate) fn get(&self) -> minimald_rpc::ZoneAnswererStatus {
        self.0
            .status
            .lock()
            .expect("the answerer status lock is never held across a panic")
            .clone()
    }

    /// The acquisition's own writer: called at every pass, with the state
    /// that pass left the machine's answerer in.
    pub(crate) fn set(&self, status: minimald_rpc::ZoneAnswererStatus) {
        *self
            .0
            .status
            .lock()
            .expect("the answerer status lock is never held across a panic") = status;
    }

    /// Marks whether this daemon hosts the interim (or is inside a release
    /// window it may re-bind from).
    pub(crate) fn set_hosting(&self, hosting: bool) {
        self.0
            .hosting
            .store(hosting, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether this daemon hosts the interim right now.
    #[must_use]
    pub(crate) fn hosting(&self) -> bool {
        self.0.hosting.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The acquisition's end of the handover door: every release and cancel
    /// from now on reaches the returned receiver.
    pub(crate) fn attach_commands(&self) -> mpsc::Receiver<HandoverCommand> {
        let (sender, receiver) = mpsc::channel(8);
        *self
            .0
            .commands
            .lock()
            .expect("the answerer command lock is never held across a panic") = Some(sender);
        receiver
    }

    /// Asks the acquisition to release its interim answerer (NET-122's
    /// handover): answered once the port is free, or as a no-op by a
    /// daemon that hosts no interim.
    #[must_use]
    pub(crate) async fn release(&self) -> ReleaseReply {
        self.ask(HandoverCommand::Release, "nothing to release")
            .await
    }

    /// Asks the acquisition to cancel a release and re-bind its interim at
    /// once; a no-op where no release is pending.
    #[must_use]
    pub(crate) async fn release_cancel(&self) -> ReleaseReply {
        self.ask(HandoverCommand::Cancel, "nothing to re-bind")
            .await
    }

    async fn ask(
        &self,
        command: fn(oneshot::Sender<ReleaseReply>) -> HandoverCommand,
        nothing: &str,
    ) -> ReleaseReply {
        if !self.hosting() {
            return ReleaseReply::no_op(format!(
                "this native daemon hosts no interim answerer; {nothing}"
            ));
        }
        let Some(sender) = self.sender() else {
            return ReleaseReply::no_op(format!(
                "this native daemon hosts no interim answerer; {nothing}"
            ));
        };
        let (reply_to, reply) = oneshot::channel();
        if sender.send(command(reply_to)).await.is_err() {
            return ReleaseReply::no_op(format!(
                "this native daemon hosts no interim answerer; {nothing}"
            ));
        }
        match tokio::time::timeout(CHANNEL_REPLY_TIMEOUT + RELEASE_WINDOW, reply).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) | Err(_) => ReleaseReply::no_op("the acquisition did not answer in time"),
        }
    }

    /// The acquisition's side of the handover door, cloned for one ask.
    fn sender(&self) -> Option<mpsc::Sender<HandoverCommand>> {
        self.0
            .commands
            .lock()
            .expect("the answerer command lock is never held across a panic")
            .clone()
    }
}

/// Answers a command the current state cannot serve: a handover request
/// against a daemon that hosts no interim is a no-op, whatever it asked.
fn refuse_command(command: HandoverCommand) {
    match command {
        HandoverCommand::Release(reply) | HandoverCommand::Cancel(reply) => {
            let _ = reply.send(ReleaseReply::no_op(
                "this native daemon hosts no interim answerer",
            ));
        }
    }
}

/// The status a daemon that published its rows reports, by the holder its
/// hello ack named: the manager-held service, or another daemon hosting
/// the single-operator interim. The port it carries is the machine's
/// answerer port this daemon knows — the hook port, where the service the
/// installer records its `ListenDatagram` at serves in the default world.
fn registered_status(holder: &str, port: u16) -> minimald_rpc::ZoneAnswererStatus {
    if holder == SERVICE_HOLDER {
        minimald_rpc::ZoneAnswererStatus::ManagerHeld { port }
    } else {
        minimald_rpc::ZoneAnswererStatus::Registered { port }
    }
}

/// The one info line at this daemon's first publish, the diagnostics
/// contract's: publish-or-host, the hook port, the channel path — and which
/// answerer holds the port, as its hello ack named it.
fn announce_publish(holder: &str, port: u16, channel: &std::path::Path, node: &str) {
    let whose = match holder {
        SERVICE_HOLDER => "the manager-held answerer service",
        _ => "another daemon holding the port (the single-operator interim)",
    };
    tracing::info!(
        component = COMPONENT,
        holder = %holder,
        port,
        node = %node,
        channel = %channel.display(),
        "the zone answerer is held by {whose}; registered this table's zone rows with it \
         over the machine-global channel at {} and hosts nothing here",
        channel.display()
    );
}

/// Warns the rows a publish lost, with the reasons the answerer named.
fn warn_refused(node: &str, refused: &[RefusedRow]) {
    for row in refused {
        tracing::warn!(
            component = COMPONENT,
            node = %node,
            name = %row.name,
            reason = %row.reason,
            "the answerer refused to hold a zone row; the name does not answer through it"
        );
    }
}

/// Surfaces a channel that is present but did not answer, or a hook port
/// some other process holds: the status names the port
/// (`PortHeldNoChannel`, the state its readers spell "this host's names
/// are not answered") and one first-entry warn carries `why`, because the
/// same fault re-decided every pass needs one line, not a wall of them.
fn surface_error(status: &AnswererStatus, port: u16, erroring: &mut bool, why: &str) {
    if !*erroring {
        *erroring = true;
        tracing::warn!(
            component = COMPONENT,
            port,
            why,
            "the zone answerer is not serving this daemon's names; retrying"
        );
    }
    status.set(minimald_rpc::ZoneAnswererStatus::PortHeldNoChannel { port });
}

// ── T75's residual: re-check the carve-out of live deny-all boxes ────────────

/// Re-runs the stale carve-out check (NET-079, the one T75 ran at plan time
/// only) for the live deny-all boxes a bind change or clear leaves behind:
/// a box that launched while the table's recorded carve-out named the live
/// bind keeps its resolver pointed at that bind for its whole life, and
/// the table — root's, loaded by the step — is not this daemon's to move,
/// so when the live bind moves or clears the honest act left is to name
/// every such box in this daemon's log, with the remedy the launch
/// refusal names. The acquisition's reconnect keeps the state short: a
/// channel loss re-hosts the interim at the hook port, and the re-check
/// that follows a restored bind says the recovery at info.
///
/// `live` is the bind the caller just wrote to the live-answerer cell (or
/// `None`, having just cleared it); `said` is the last refusal this
/// re-check logged, so the same stale state is named once, not once per
/// pass, and the return to a matching bind is the one info line it owes.
async fn recheck_live_carve_outs(
    manager: &crate::sessions::ManagerHandle,
    live: Option<SocketAddr>,
    said: &mut Option<String>,
) {
    // Only a host that decides a host-address box's verdict per box has
    // boxes whose carve-out is a fact the table enforces; on any other host
    // there is nothing to re-check and nothing a bind change could break.
    if !crate::session_host::host_ip_enforcement_fact().can_decide_per_box() {
        return;
    }
    // The recorded half of the comparison, read the same way a launch
    // reads it — the record the step wrote beside its marker, re-read now
    // because the table's target is the one thing that cannot have moved
    // with the bind.
    let decision = crate::net::classifier::decide_now(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        sandbox2::classifier::own_mountinfo().as_deref(),
        false,
    );
    let refusal = crate::net::classifier::stale_carve_out_refusal(decision.carve_out(), live);
    match refusal {
        Some(why) => {
            // Name every live deny-all box the change leaves behind: the
            // boxes whose launch placed them in a leaf of their own (the
            // record's `per_box`), over this host's addresses (HostNet),
            // with a declaration that decides to deny.
            let infos = match manager.list().await {
                Ok(infos) => infos,
                Err(error) => {
                    tracing::warn!(
                        component = COMPONENT,
                        %error,
                        "could not enumerate the sessions for a carve-out re-check"
                    );
                    return;
                }
            };
            for info in infos {
                let Some(record) = manager
                    .get_record(crate::sessions::SessionKeyPredicate::Id(info.id))
                    .await
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                let placed = info.attrs.as_ref().is_some_and(|attrs| {
                    attrs.host_ip_enforcement == Some(minimald_rpc::HostIpEnforcement::PerBox)
                });
                if !placed
                    || record.network != sessions::NetworkMode::HostNet
                    || crate::net::classifier::verdict_of(record.policy.egress.as_ref())
                        != sandbox2::config::Verdict::Deny
                {
                    continue;
                }
                tracing::error!(
                    component = COMPONENT,
                    session = %info.name.clone().unwrap_or_else(|| info.id.to_string()),
                    live_bind = ?live,
                    refusal = %why,
                    "a live deny-all box's resolver carve-out no longer names the answerer \
                     actually serving; its lookups reach the recorded bind until the table \
                     is reinstalled at the live one"
                );
            }
            *said = Some(why);
        }
        None => {
            if said.is_some() {
                *said = None;
                tracing::info!(
                    component = COMPONENT,
                    live_bind = ?live,
                    "the live answerer bind matches the table's recorded carve-out again; \
                     a deny-all box's lookups reach the answerer actually serving"
                );
            }
        }
    }
}

// ── the acquisition loop ─────────────────────────────────────────────────────

/// Drives the publish-or-host acquisition on a native host, over the
/// machine's own channel paths, for as long as `state`'s daemon lives
/// (`state`'s shutdown token ends it). Started by
/// `server::start_host_proxies` beside the hostname proxy.
pub(crate) async fn acquire(
    state: crate::server::ServerStateHandle,
    hook_port: u16,
    status: AnswererStatus,
) {
    let shutdown = state.shutdown_token().await;
    acquire_at(
        state,
        hook_port,
        status,
        AnswererPaths {
            channel: resolve_channel_sock(),
            marker: resolve_install_marker(),
            release_window: RELEASE_WINDOW,
        },
        shutdown,
    )
    .await;
}

/// [`acquire`] over paths the caller names — the tests' entry, on
/// temporary channel paths and a bounded release window.
async fn acquire_at(
    state: crate::server::ServerStateHandle,
    hook_port: u16,
    status: AnswererStatus,
    paths: AnswererPaths,
    shutdown: CancellationToken,
) {
    let manager = state.sessions_manager().await;
    let registry = manager.hostnames();
    let identity_dir = match state.daemon_identity_dir().await {
        Some(dir) => std::path::PathBuf::from(dir.as_str()),
        None => std::path::PathBuf::from(state.minimal_state_dir().await.as_str()),
    };
    let node = node_id(&identity_dir);
    let mut commands = status.attach_commands();
    let mut retry = CHANNEL_RETRY;
    let mut erroring = false;
    let mut published_once = false;
    let mut stale_global_once = false;
    let mut stale_once = false;
    let mut carve_out_said: Option<String> = None;

    loop {
        if shutdown.is_cancelled() {
            return;
        }
        // ── the publish arm, fresh. The installed service first, decided
        // by its marker: its channel or nothing.
        let installed = paths.marker.exists();
        let channel = &paths.channel;
        if !installed && !stale_global_once && std::fs::symlink_metadata(channel).is_ok() {
            stale_global_once = true;
            tracing::info!(
                component = COMPONENT,
                channel = %channel.display(),
                marker = %paths.marker.display(),
                "a socket sits at the machine-global answerer channel path but no answerer \
                 service is installed (no install marker); treating the path as absent"
            );
        }
        let rows = zone_rows_of(&registry);
        match connect_and_publish(channel, &node, rows).await {
            Ok(published) => {
                retry = CHANNEL_RETRY;
                erroring = false;
                status.set(registered_status(&published.holder, hook_port));
                warn_refused(&node, &published.refused);
                if !published_once {
                    published_once = true;
                    announce_publish(&published.holder, hook_port, channel, &node);
                }
                // While this daemon publishes, the live bind a deny-all
                // box's carve-out must name is the manager-held answerer's
                // recorded one — the bind the publish reached, and the
                // cell the plan-time check reads. The zone answerer's
                // port answerer keeps reporting the machine's hook port,
                // where the installed service records its bind.
                state.set_zone_answerer_port(hook_port).await;
                crate::net::classifier::set_live_answerer(recorded_service_bind());
                recheck_live_carve_outs(
                    &manager,
                    Some(recorded_service_bind()),
                    &mut carve_out_said,
                )
                .await;
                if !hold_the_publish(
                    &registry,
                    &mut commands,
                    published.registration,
                    &status,
                    hook_port,
                    &node,
                    &mut erroring,
                    &shutdown,
                )
                .await
                {
                    // The connection's end is the whole withdrawal: the
                    // cell this publish fed clears with it.
                    crate::net::classifier::clear_live_answerer();
                    recheck_live_carve_outs(&manager, None, &mut carve_out_said).await;
                }
                continue;
            }
            // The service is installed and its channel did not answer: an
            // error, never a reason to host.
            Err(error) if installed => {
                surface_error(
                    &status,
                    hook_port,
                    &mut erroring,
                    &format!(
                        "the answerer service is installed ({}) but its channel {} did not \
                         answer: {error}",
                        paths.marker.display(),
                        channel.display()
                    ),
                );
                wait_out_commands(&mut commands, retry, &shutdown).await;
                retry = (retry * 2).min(PORT_RECHECK);
                continue;
            }
            // The channel's path is absent: the answerer is nobody's, and
            // the host arm below decides this daemon's.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            // A refused connect names a corpse: a socket file with no
            // listener behind it, the leftover of a service that died
            // with its sockets unmanaged. The host arm takes the zone
            // answerer from here; the corpse's socket file is the service
            // manager's own path to manage, not this daemon's to remove.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                if !stale_once {
                    stale_once = true;
                    tracing::info!(
                        component = COMPONENT,
                        channel = %channel.display(),
                        "the answerer channel socket file is a dead holder's leftover: nothing \
                         listens behind it, so this daemon takes the zone answerer from here"
                    );
                }
            }
            // A live channel that refuses or times out is an error, never
            // a reason to host. Retried with backoff.
            Err(error) => {
                surface_error(
                    &status,
                    hook_port,
                    &mut erroring,
                    &format!("the answerer channel is present but did not answer: {error}"),
                );
                wait_out_commands(&mut commands, retry, &shutdown).await;
                retry = (retry * 2).min(PORT_RECHECK);
                continue;
            }
        }
        // ── the host arm: no service, no channel — this daemon hosts the
        // answerer itself, when the hook port is free.
        match tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, hook_port)).await {
            Ok(socket) => {
                host_the_interim(
                    &state,
                    &manager,
                    &registry,
                    &mut commands,
                    socket,
                    hook_port,
                    &paths,
                    &node,
                    &status,
                    &mut erroring,
                    &mut carve_out_said,
                    &shutdown,
                )
                .await;
            }
            // No answerer channel and the hook port held: the holder is no
            // client of this machine's channel (a native minimald never
            // holds the port while another's channel answers — it
            // publishes), so the holder is a foreign process or a daemon
            // of another operator, and nothing here can answer. A loud
            // error naming the port, its holder and the remedy, retried on
            // the recheck cadence until the port frees.
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let why = channelless_holder_error(hook_port, hook_port_holder(hook_port));
                surface_error(&status, hook_port, &mut erroring, &why);
                wait_out_commands(&mut commands, PORT_RECHECK, &shutdown).await;
            }
            Err(error) => {
                let why = format!(
                    "could not bind the zone answerer's hook port 127.0.0.1:{hook_port}: \
                     {error}; free port {hook_port} or set the answerer's port"
                );
                surface_error(&status, hook_port, &mut erroring, &why);
                wait_out_commands(&mut commands, PORT_RECHECK, &shutdown).await;
            }
        }
    }
}

/// Waits out a backoff slice while refusing every handover command that
/// arrives: a daemon with no answerer to release is a no-op to ask, and a
/// command is answered now rather than queued for the next pass.
async fn wait_out_commands(
    commands: &mut mpsc::Receiver<HandoverCommand>,
    bound: Duration,
    shutdown: &CancellationToken,
) {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || shutdown.is_cancelled() {
            return;
        }
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return };
                refuse_command(command);
            }
            _ = tokio::time::sleep(remaining) => return,
        }
    }
}

/// Keeps one publish held: the connection's end (peeked per wake slice), a
/// table change (diff-poll on the [`CONNECTION_POLL`] cadence, since the
/// registry has no change ping and the diff is one small read), the
/// [`PORT_RECHECK`] bound (a full re-publish), a handover command (a
/// no-op while publishing — there is no interim to release), or the
/// shutdown. Returns whether the connection is still held — `false` is the
/// withdrawal, and the registration drops with the return: the
/// connection's end is the whole withdrawal.
#[expect(clippy::too_many_arguments, reason = "the loop's own state, threaded")]
async fn hold_the_publish(
    registry: &Arc<std::sync::RwLock<HostnameRegistry>>,
    commands: &mut mpsc::Receiver<HandoverCommand>,
    mut registration: Registration,
    status: &AnswererStatus,
    hook_port: u16,
    node: &str,
    erroring: &mut bool,
    shutdown: &CancellationToken,
) -> bool {
    let mut last = zone_rows_of(registry);
    let mut recheck_at = tokio::time::Instant::now() + PORT_RECHECK;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                return false;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    return false;
                };
                refuse_command(command);
            }
            _ = tokio::time::sleep_until(recheck_at) => {
                let rows = zone_rows_of(registry);
                match registration.send(rows.clone()).await {
                    Ok(refused) => {
                        warn_refused(node, &refused);
                        last = rows;
                        recheck_at = tokio::time::Instant::now() + PORT_RECHECK;
                    }
                    Err(error) => {
                        surface_error(
                            status,
                            hook_port,
                            erroring,
                            &format!(
                                "the answerer's end of the channel closed while holding the \
                                 publish (a service restart): {error}"
                            ),
                        );
                        return false;
                    }
                }
            }
            _ = tokio::time::sleep(CONNECTION_POLL) => {
                // One peeked byte per slice: the connection's end is
                // known at the slice, not at the next full republish,
                // which is what keeps a service restart a short absence.
                // Anything the peek could not say reads as the same loss.
                if !registration.answerer_alive().unwrap_or(false) {
                    surface_error(
                        status,
                        hook_port,
                        erroring,
                        "the answerer's end of the channel closed (a service restart)",
                    );
                    return false;
                }
                let rows = zone_rows_of(registry);
                if rows != last {
                    if let Err(error) = registration.send(rows.clone()).await {
                        surface_error(
                            status,
                            hook_port,
                            erroring,
                            &format!(
                                "the answerer's end of the channel closed while holding the \
                                 publish (a service restart): {error}"
                            ),
                        );
                        return false;
                    }
                    last = rows;
                }
            }
        }
    }
}

/// How a release window ended.
enum WindowEnd {
    /// The service's channel took this daemon's publish.
    Switched(Published),
    /// A cancel arrived: re-bind now, answering it once bound.
    Cancelled(oneshot::Sender<ReleaseReply>),
    /// The window ran out with no channel and no cancel.
    TimedOut,
}

/// Hosts the interim answerer on `socket` (NET-138's recorded interim, on
/// a native host) until a release hands the port to the installed service
/// and this daemon's publish lands on the service's channel — or the
/// window the release opened runs out or is cancelled, and the interim
/// re-binds itself. Never returns otherwise: the answerer serves from
/// this host-authored table for the daemon's life, and a re-bind that
/// finds the port taken is the caller's next pass to surface.
#[expect(clippy::too_many_arguments, reason = "the loop's own state, threaded")]
async fn host_the_interim(
    state: &crate::server::ServerStateHandle,
    manager: &crate::sessions::ManagerHandle,
    registry: &Arc<std::sync::RwLock<HostnameRegistry>>,
    commands: &mut mpsc::Receiver<HandoverCommand>,
    socket: tokio::net::UdpSocket,
    hook_port: u16,
    paths: &AnswererPaths,
    node: &str,
    status: &AnswererStatus,
    erroring: &mut bool,
    carve_out_said: &mut Option<String>,
    shutdown: &CancellationToken,
) {
    let mut socket = Some(socket);
    let mut rebound: Option<oneshot::Sender<ReleaseReply>> = None;
    let mut serve_stop;
    let mut serve_task: Option<tokio::task::JoinHandle<()>>;
    loop {
        let addr = socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
            .map_or_else(|| format!("127.0.0.1:{hook_port}"), |addr| addr.to_string());
        status.set(minimald_rpc::ZoneAnswererStatus::Holder { port: hook_port });
        status.set_hosting(true);
        tracing::info!(
            component = COMPONENT,
            listener = %addr,
            port = hook_port,
            channel = %paths.channel.display(),
            status = "serving",
            "no answerer service is installed and the machine-global channel is absent; this \
             native daemon holds the host loopback answerer port itself as the \
             single-operator interim: the box zone answers here, from this \
             host-authored table, until the service's install releases it"
        );
        // The interim serves the daemon's own registry — the same answerer
        // this module always served, stopped by its token when a release
        // frees the port.
        let answerer = ZoneAnswerer::new(Arc::clone(registry), AnswerScope::Native);
        serve_stop = CancellationToken::new();
        let stop = serve_stop.clone();
        // The socket this pass serves is the one the caller bound (the
        // first pass) or the re-bind opened (every later one); None only
        // between the take and the assignment, never at the take itself.
        let serve_socket = socket
            .take()
            .expect("every pass enters with a bound socket");
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = stop.cancelled() => {}
                served = serve(serve_socket, answerer) => {
                    if let Err(error) = served {
                        tracing::error!(
                            component = COMPONENT,
                            %error,
                            "box-zone answerer receive loop exited"
                        );
                    }
                }
            }
            // The answerer no longer serves: a carve-out that named its
            // bind now names nothing (NET-079).
            crate::net::classifier::clear_live_answerer();
        });
        serve_task = Some(task);
        // The interim's own bind is the live one while it serves.
        let bound = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), hook_port);
        state.set_zone_answerer_port(hook_port).await;
        crate::net::classifier::set_live_answerer(bound);
        recheck_live_carve_outs(manager, Some(bound), carve_out_said).await;
        crate::rpc::log_live_name_surface(state, hook_port).await;
        if let Some(reply_to) = rebound.take() {
            let _ = reply_to.send(ReleaseReply::acted(format!(
                "re-bound the interim answerer at 127.0.0.1:{hook_port}"
            )));
        }
        // ── serve, and wait for the handover.
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    serve_stop.cancel();
                    if let Some(task) = serve_task.take() {
                        let _ = task.await;
                    }
                    status.set_hosting(false);
                    return;
                }
                command = commands.recv() => {
                    let Some(command) = command else { continue };
                    match command {
                        HandoverCommand::Cancel(reply_to) => {
                            let _ = reply_to.send(ReleaseReply::no_op(
                                "no release is pending; the interim answerer is serving",
                            ));
                        }
                        HandoverCommand::Release(reply_to) => {
                            // Stop the serve, free the port, answer the
                            // release once free, and open the window.
                            serve_stop.cancel();
                            if let Some(task) = serve_task.take() {
                                let _ = task.await;
                            }
                            status.set(minimald_rpc::ZoneAnswererStatus::Starting);
                            let detail = format!(
                                "released the interim answerer: 127.0.0.1:{hook_port} is free; \
                                 waiting up to {} s for the answerer service's channel at {}",
                                paths.release_window.as_secs(),
                                paths.channel.display(),
                            );
                            tracing::info!(
                                component = COMPONENT,
                                port = hook_port,
                                channel = %paths.channel.display(),
                                window = ?paths.release_window,
                                status = "released",
                                "released the interim answerer: 127.0.0.1:{hook_port} is free; \
                                 waiting up to {} s for the answerer service's channel at {}",
                                paths.release_window.as_secs(),
                                paths.channel.display()
                            );
                            let _ = reply_to.send(ReleaseReply::acted(detail));
                            match release_window(paths, registry, node, commands, shutdown)
                                .await
                            {
                                WindowEnd::Switched(published) => {
                                    // The service took the port and this
                                    // daemon's publish landed there: from
                                    // now on this daemon is a channel
                                    // client.
                                    *erroring = false;
                                    status.set_hosting(false);
                                    status.set(registered_status(
                                        &published.holder,
                                        hook_port,
                                    ));
                                    warn_refused(node, &published.refused);
                                    announce_publish(
                                        &published.holder,
                                        hook_port,
                                        &paths.channel,
                                        node,
                                    );
                                    state.set_zone_answerer_port(hook_port).await;
                                    crate::net::classifier::set_live_answerer(
                                        recorded_service_bind(),
                                    );
                                    recheck_live_carve_outs(
                                        manager,
                                        Some(recorded_service_bind()),
                                        carve_out_said,
                                    )
                                    .await;
                                    if !hold_the_publish(
                                        registry,
                                        commands,
                                        published.registration,
                                        status,
                                        hook_port,
                                        node,
                                        erroring,
                                        shutdown,
                                    )
                                    .await
                                    {
                                        crate::net::classifier::clear_live_answerer();
                                        recheck_live_carve_outs(manager, None, carve_out_said)
                                            .await;
                                    }
                                    return;
                                }
                                WindowEnd::Cancelled(reply_to) => {
                                    tracing::info!(
                                        component = COMPONENT,
                                        port = hook_port,
                                        "the release was cancelled; re-binding the interim \
                                         answerer"
                                    );
                                    rebound = Some(reply_to);
                                }
                                WindowEnd::TimedOut => {
                                    tracing::info!(
                                        component = COMPONENT,
                                        port = hook_port,
                                        window = ?paths.release_window,
                                        "no answerer service channel came within {} s of the \
                                         release; re-binding the interim answerer",
                                        paths.release_window.as_secs()
                                    );
                                }
                            }
                            // Re-bind: the cancel and the timeout both end
                            // here, the interim serving again.
                            match tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, hook_port))
                                .await
                            {
                                Ok(bound_again) => {
                                    socket = Some(bound_again);
                                    break;
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        component = COMPONENT,
                                        %error,
                                        port = hook_port,
                                        "could not re-bind the interim answerer; the hook \
                                         port stayed taken"
                                    );
                                    if let Some(reply_to) = rebound.take() {
                                        let _ = reply_to.send(ReleaseReply::no_op(
                                            "the interim answerer could not re-bind: the hook \
                                             port stayed taken",
                                        ));
                                    }
                                    status.set_hosting(false);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The window a release opens: the service's channel is polled for, its
/// commands are answered, and the window itself bounds the wait
/// ([`RELEASE_WINDOW`]). Ended by the channel's publish landing
/// ([`WindowEnd::Switched`]), a cancel ([`WindowEnd::Cancelled`]), or the
/// deadline ([`WindowEnd::TimedOut`]).
async fn release_window(
    paths: &AnswererPaths,
    registry: &Arc<std::sync::RwLock<HostnameRegistry>>,
    node: &str,
    commands: &mut mpsc::Receiver<HandoverCommand>,
    shutdown: &CancellationToken,
) -> WindowEnd {
    let deadline = tokio::time::Instant::now() + paths.release_window;
    loop {
        if shutdown.is_cancelled() {
            return WindowEnd::TimedOut;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return WindowEnd::TimedOut;
        }
        // The channel is tried every poll, but only once the service's
        // install marker says the service is there: a channel that answers
        // with no marker is a corpse or a foreign program, not the service
        // this window waits for.
        if paths.marker.exists()
            && let Ok(published) =
                connect_and_publish(&paths.channel, node, zone_rows_of(registry)).await
        {
            return WindowEnd::Switched(published);
        }
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    tokio::time::sleep(remaining.min(RELEASE_POLL)).await;
                    continue;
                };
                match command {
                    HandoverCommand::Cancel(reply_to) => {
                        return WindowEnd::Cancelled(reply_to);
                    }
                    HandoverCommand::Release(reply_to) => {
                        let _ = reply_to.send(ReleaseReply::no_op(
                            "already released: the interim answerer is waiting for the \
                             service's channel",
                        ));
                    }
                }
            }
            _ = tokio::time::sleep(remaining.min(RELEASE_POLL)) => {}
        }
    }
}

/// The process holding UDP `127.0.0.1:port`, as its pid and executable,
/// when this process can see it: on Linux by the socket's inode in
/// `/proc/net/udp` and the fd that names it. `None` when it is not
/// knowable (another user's process, a foreign kernel table).
fn hook_port_holder(port: u16) -> Option<(u32, String)> {
    let wanted = [
        format!("0100007F:{port:04X}"),
        format!("00000000:{port:04X}"),
    ];
    let table = std::fs::read_to_string("/proc/net/udp").ok()?;
    let inode = table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.len() > 9 && wanted.iter().any(|want| fields[1] == want))
            .then(|| fields[9].to_string())
    })?;
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        if fds.flatten().any(|fd| {
            std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
        }) {
            let exe = std::fs::read_link(entry.path().join("exe")).map_or_else(
                |_| "an unreadable executable".to_string(),
                |exe| exe.display().to_string(),
            );
            return Some((pid, exe));
        }
    }
    None
}

/// The error a channelless holder surfaces: the hook port is held and no
/// channel answers, so this daemon's names answer nowhere and its boxes'
/// registrations cannot publish. Names the port, the holder (when this
/// process can see one) and the remedy.
fn channelless_holder_error(port: u16, holder: Option<(u32, String)>) -> String {
    match holder {
        Some((pid, exe)) => format!(
            "the zone answerer's hook port 127.0.0.1:{port} is held by pid {pid} ({exe}) and \
             no answerer channel answers: this daemon can neither host the answerer nor \
             publish its rows; free the port or install the answerer service"
        ),
        None => format!(
            "the zone answerer's hook port 127.0.0.1:{port} is held by a process this \
             daemon cannot see and no answerer channel answers: this daemon can neither \
             host the answerer nor publish its rows; free the port or install the answerer \
             service"
        ),
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
    /// NET-001; on a native host it keeps the published-loopback model at the
    /// address its creator handed — the host loopback, used exactly as
    /// handed).
    fn registry(on_switch: bool) -> HostnameRegistry {
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, on_switch);
        reg.register_host_net(SessionId::nil(), "web");
        if !on_switch {
            reg.publish_own_address(
                SessionId::nil(),
                "api",
                Ipv4Addr::LOCALHOST,
                std::collections::BTreeSet::new(),
            );
        }
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
                soa.minimum,
                zone_answer::ANSWER_TTL_SECS,
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
                    record.ttl <= zone_answer::ANSWER_TTL_SECS,
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
        assert_eq!(reply.answers[0].ttl, zone_answer::ANSWER_TTL_SECS);
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
            is_host_answerable(Ipv4Addr::new(127, 0, 64, 1), &node),
            "the reserved local range answers"
        );
        assert!(
            !is_host_answerable(Ipv4Addr::new(127, 0, 65, 0), &node),
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
    // ── the acquisition's tests (NET-122): publish-or-host over the
    // machine-global channel, its bounds and its handover ──────────────────

    /// A UDP port free right now, drawn the way every test in this tree
    /// draws one: bind, read, drop. The acquisition (or the service the
    /// test stands in for it) binds it next.
    fn free_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a probe binds");
        socket
            .local_addr()
            .expect("a probe reads its own port")
            .port()
    }

    /// Binds a UDP probe at `port`, proving it free. `Err` is the reason it
    /// is not (a holder's refusal to name).
    fn probe_udp_port(port: u16) -> std::io::Result<()> {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).map(|_| ())
    }

    /// Drives one acquisition as the daemon's start does, on a detached
    /// thread of its own — a whole runtime on one OS thread, so the
    /// thread-local log capture in `buf` sees every line the acquisition
    /// writes (the start line, the host arm's, the release window's) and
    /// the assertions read them: a task free to migrate across a test
    /// runtime's workers would leave its lines on threads the capture
    /// never covered.
    fn drive(
        state: crate::server::ServerStateHandle,
        hook_port: u16,
        status: AnswererStatus,
        paths: AnswererPaths,
        shutdown: CancellationToken,
        buf: CaptureWriter,
    ) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("the acquisition".to_string())
            .spawn(move || {
                let subscriber = tracing_subscriber::fmt()
                    .with_writer(buf)
                    .with_ansi(false)
                    .finish();
                let _guard = tracing::subscriber::set_default(subscriber);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("the acquisition's own runtime builds");
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    acquire_at(state, hook_port, status, paths, shutdown).await
                });
            })
            .expect("the acquisition's thread spawns")
    }

    /// Ends a driven acquisition (cancels its token, then joins its thread),
    /// so the port and paths it held are free for what the test does next.
    fn end(task: std::thread::JoinHandle<()>, shutdown: &CancellationToken) {
        shutdown.cancel();
        task.join()
            .expect("the acquisition thread ends once its token is cancelled");
    }

    /// Polls the status cell until it reads `wanted` — the same bounds
    /// `minvmd`'s answerer tests give their status: a 10 s deadline in 50 ms
    /// steps, so a settled acquisition is seen at once and a stuck one
    /// names where it stopped.
    async fn await_status_is(
        status: &AnswererStatus,
        wanted: minimald_rpc::ZoneAnswererStatus,
        what: &str,
    ) -> minimald_rpc::ZoneAnswererStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = status.get();
            if seen == wanted {
                return seen;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the acquisition never reached {what}: still {seen:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Sends one A query for `name` to the answerer serving at
    /// 127.0.0.1:port and returns the decoded reply — the proof the tests
    /// read, a real datagram answered by a real serve loop.
    async fn query_udp(port: u16, name: &str) -> Message {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("a client socket binds");
        let lookup = encode_query(name, RecordType::A);
        socket
            .send_to(&lookup, (Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the lookup is sent");
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("the answerer replies within 2 s")
            .expect("a reply datagram arrives");
        Message::from_vec(&buf[..len]).expect("the answerer's reply decodes")
    }

    /// The manager-held answerer's channel half, as a test stands in for
    /// the installed service: it holds no UDP port (the test's daemon
    /// hosts nothing, and the hook port staying free is the proof),
    /// answers the hello with `service` as the holder, and acks and
    /// records every publish it is sent — the witness the publish
    /// contract's assertions read.
    struct FakeServiceHandle {
        /// The row sets the service was published, in the order they came.
        publishes: Arc<Mutex<Vec<Vec<RegisteredRow>>>>,
        /// Stops the service's accept loop (its connections close with it).
        stop: CancellationToken,
    }

    impl FakeServiceHandle {
        /// The row sets the service was published, in the order they came.
        fn publishes(&self) -> Vec<Vec<RegisteredRow>> {
            self.publishes.lock().unwrap().clone()
        }

        /// Stops standing in for the service.
        fn stop(&self) {
            self.stop.cancel();
        }
    }

    /// Stands in for the installed answerer service at `channel`: binds the
    /// channel's listener on the calling task (so the daemon's first
    /// connect finds it there, never racing the service up), then serves
    /// hellos and publishes forever.
    fn fake_manager_held_service(channel: std::path::PathBuf) -> FakeServiceHandle {
        let listener =
            tokio::net::UnixListener::bind(&channel).expect("the service's channel listener binds");
        let publishes: Arc<Mutex<Vec<Vec<RegisteredRow>>>> = Arc::new(Mutex::new(Vec::new()));
        let publishes_loop = Arc::clone(&publishes);
        let stop = CancellationToken::new();
        let stop_task = stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_task.cancelled() => return,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { return };
                        let publishes = Arc::clone(&publishes_loop);
                        tokio::spawn(async move {
                            let mut stream = stream;
                            let mut saw_hello = false;
                            loop {
                                let Ok(Some(line)) = read_reply_line(&mut stream).await else {
                                    return;
                                };
                                if !saw_hello {
                                    saw_hello = true;
                                    let hello: Hello = serde_json_lenient::from_str(&line)
                                        .expect("the daemon's hello parses");
                                    assert_eq!(
                                        hello.version, CHANNEL_PROTOCOL_VERSION,
                                        "the daemon speaks the channel's protocol version"
                                    );
                                    assert!(
                                        hello.node.contains("#native"),
                                        "the daemon's node id names what it runs as: {}",
                                        hello.node
                                    );
                                    let _ = write_line(
                                        &mut stream,
                                        &RegistrationReply {
                                            ok: true,
                                            error: None,
                                            refused: Vec::new(),
                                            holder: Some(SERVICE_HOLDER.to_string()),
                                        },
                                    )
                                    .await;
                                    continue;
                                }
                                let request: PublishRequest = serde_json_lenient::from_str(&line)
                                    .expect("the daemon's publish parses");
                                publishes.lock().unwrap().push(request.rows);
                                let _ = write_line(
                                    &mut stream,
                                    &RegistrationReply {
                                        ok: true,
                                        error: None,
                                        refused: Vec::new(),
                                        holder: None,
                                    },
                                )
                                .await;
                            }
                        });
                    }
                }
            }
        });
        FakeServiceHandle { publishes, stop }
    }

    /// Asks the control socket at `sock` one `verb` and reads the one reply
    /// the door answers with — the wire the install step's ask travels on,
    /// read back as the reply the daemon's log also named.
    async fn ask_control(
        sock: &std::path::Path,
        request: minimald_rpc::BoxControlRequest,
    ) -> (bool, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut stream = tokio::net::UnixStream::connect(sock)
            .await
            .expect("the control socket accepts");
        let line = serde_json_lenient::to_string(&request).expect("the request serializes");
        stream
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("the request is sent");
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
            .await
            .expect("the control socket answers within 5 s")
            .expect("the reply reads to its end");
        let reply: minimald_rpc::BoxControlReply = serde_json_lenient::from_slice(&buf)
            .unwrap_or_else(|error| panic!("the control reply decodes: {error}: {buf:?}"));
        match reply {
            minimald_rpc::BoxControlReply::AnswererRelease { acted, detail } => (acted, detail),
            other => panic!("the control reply was a release answer, got {other:?}"),
        }
    }

    /// NET-122's publish arm: with the answerer service installed and its
    /// channel answering, the native daemon publishes its zone rows there
    /// with its node id and hosts nothing — the hook port stays free, the
    /// status says the manager holds the answerer, the live-answerer cell
    /// takes the service's recorded bind (the one the loaded table's
    /// carve-out names, T75's cell fed by the publish that reached it),
    /// and the one start line names publish-or-host, the hook port and the
    /// channel path. The held publish also keeps following the table: a
    /// second registration's row reaches the service without the daemon
    /// doing anything but diffing its registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_daemon_publishes_into_the_held_answerer() {
        let buf = CaptureWriter::default();
        let server = crate::test_harness::TestServer::new().await;
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .expect("the registry lock is held")
            .register_host_net(SessionId::nil(), "web");
        let dir = tempfile::tempdir().expect("a tempdir for the channel and the marker");
        let channel = dir.path().join("answerer.sock");
        let marker = dir.path().join("dev.minimal.zone-answerer.socket");
        std::fs::write(&marker, b"[Unit]\n").expect("the install marker is written");
        let service = fake_manager_held_service(channel.clone());

        let status = AnswererStatus::starting();
        let shutdown = CancellationToken::new();
        let hook_port = free_udp_port();
        let task = drive(
            server.state.clone(),
            hook_port,
            status.clone(),
            AnswererPaths {
                channel: channel.clone(),
                marker,
                release_window: RELEASE_WINDOW,
            },
            shutdown.clone(),
            buf.clone(),
        );
        await_status_is(
            &status,
            minimald_rpc::ZoneAnswererStatus::ManagerHeld { port: hook_port },
            "published into the manager-held answerer",
        )
        .await;

        // The service saw the registry's rows: the box's name, live.
        let first = service.publishes();
        assert!(
            first
                .first()
                .is_some_and(|rows| rows.iter().any(|row| row.name == "web.min.internal")),
            "the first publish carries the registry's zone rows, got {first:?}"
        );

        // Hosts nothing: the hook port the daemon would have hosted on is
        // still free — the manager-held service is the answerer, and this
        // daemon is its client.
        probe_udp_port(hook_port).expect("the hook port stays free while the daemon publishes");

        // The live-answerer cell: the manager-held answerer's recorded bind,
        // the address and port the loaded table's carve-out names, so the
        // plan-time check reads the answerer actually serving (T75).
        assert_eq!(
            crate::net::classifier::live_answerer(),
            Some(recorded_service_bind()),
            "the cell takes the service's recorded bind while the publish is held"
        );

        // The one start line: publish-or-host said publish, naming the hook
        // port and the channel path.
        let log = buf.contents();
        assert!(
            log.contains("registered this table's zone rows"),
            "the start line names the publish, got: {log}"
        );
        assert!(
            log.contains("the manager-held answerer service"),
            "the start line names who holds the answerer, got: {log}"
        );
        assert!(
            log.contains(&channel.display().to_string()),
            "the start line names the channel path, got: {log}"
        );

        // The held publish follows the table: a second registration's row
        // reaches the service over the same connection, without a restart
        // and without a full re-publish coming first.
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .expect("the registry lock is held")
            .register_host_net(SessionId::nil(), "api");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if service
                .publishes()
                .iter()
                .any(|rows| rows.iter().any(|row| row.name == "api.min.internal"))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the diff poll never re-published the second box's row"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        service.stop();
        end(task, &shutdown);
    }

    /// NET-122's host arm and its bound: with no install marker and no
    /// channel, the daemon hosts the interim answerer itself on the hook
    /// port — the single-operator interim — and the zone answers its own
    /// table over real UDP. But the host arm is the absent-channel arm
    /// only: a channel that is present and answers no is a surfaced error,
    /// never a reason to host, and the hook port stays free while the
    /// daemon retries it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_daemon_hosts_only_when_the_channel_is_absent() {
        // ── no channel at all: host the interim.
        let buf = CaptureWriter::default();
        let server = crate::test_harness::TestServer::new().await;
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .expect("the registry lock is held")
            .register_host_net(SessionId::nil(), "web");
        let dir = tempfile::tempdir().expect("a tempdir for the absent channel and marker");
        let hook_port = free_udp_port();
        let status = AnswererStatus::starting();
        let shutdown = CancellationToken::new();
        let task = drive(
            server.state.clone(),
            hook_port,
            status.clone(),
            AnswererPaths {
                channel: dir.path().join("answerer.sock"),
                marker: dir.path().join("dev.minimal.zone-answerer.socket"),
                release_window: RELEASE_WINDOW,
            },
            shutdown.clone(),
            buf.clone(),
        );
        await_status_is(
            &status,
            minimald_rpc::ZoneAnswererStatus::Holder { port: hook_port },
            "hosted the interim with no channel",
        )
        .await;

        // The zone answers from the daemon's own table, over real UDP.
        let reply = query_udp(hook_port, "web.min.internal.").await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            !reply.answers.is_empty(),
            "the held name answers its address from the interim"
        );

        // The start line names the interim and the port it holds.
        let log = buf.contents();
        assert!(
            log.contains("holds the host loopback answerer port itself"),
            "the start line names the interim hosting, got: {log}"
        );
        assert!(
            log.contains(&format!("127.0.0.1:{hook_port}")),
            "the start line names the hook port, got: {log}"
        );

        // The cell is the interim's own bind while it serves.
        assert_eq!(
            crate::net::classifier::live_answerer(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), hook_port)),
            "the cell takes the interim's own bind while it serves"
        );

        end(task, &shutdown);

        // ── a channel that is present and answers no: a surfaced error,
        // never a reason to host.
        let buf = CaptureWriter::default();
        let server = crate::test_harness::TestServer::new().await;
        let channel = dir.path().join("refusing.sock");
        let listener = tokio::net::UnixListener::bind(&channel)
            .expect("the refusing channel's listener binds");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // The hello is read and answered no: a present channel, a
                // refusal — the state the host arm must not take as its
                // own.
                let _ = read_reply_line(&mut stream).await;
                let _ = write_line(
                    &mut stream,
                    &RegistrationReply {
                        ok: false,
                        error: Some("refused: this test's channel answers no".to_string()),
                        refused: Vec::new(),
                        holder: None,
                    },
                )
                .await;
            }
        });
        let status = AnswererStatus::starting();
        let shutdown = CancellationToken::new();
        let task = drive(
            server.state.clone(),
            hook_port,
            status.clone(),
            AnswererPaths {
                channel,
                marker: dir.path().join("refusing-marker.socket"),
                release_window: RELEASE_WINDOW,
            },
            shutdown.clone(),
            buf.clone(),
        );
        await_status_is(
            &status,
            minimald_rpc::ZoneAnswererStatus::PortHeldNoChannel { port: hook_port },
            "surfaced the channel that answered no",
        )
        .await;
        probe_udp_port(hook_port)
            .expect("a present channel that answers no is never a reason to host");
        let log = buf.contents();
        assert!(
            log.contains("present but did not answer"),
            "the surfaced error names what the channel did, got: {log}"
        );

        end(task, &shutdown);
    }

    /// NET-122's bounded handover: the native control socket answers the
    /// release request (the answerer service's install step is the one
    /// asker) by stopping the interim, freeing the hook port, and waiting
    /// the bounded window for the service's channel; with no channel ever
    /// coming, the daemon re-binds the interim on its own and the zone
    /// answers again — and a cancel with no release pending is the no-op
    /// its answer says it is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_release_rebinds_the_interim_when_the_channel_never_comes() {
        let buf = CaptureWriter::default();
        let server = crate::test_harness::TestServer::new().await;
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .write()
            .expect("the registry lock is held")
            .register_host_net(SessionId::nil(), "web");
        let dir = tempfile::tempdir().expect("a tempdir for the channel that never comes");
        let hook_port = free_udp_port();
        let status = AnswererStatus::starting();
        let shutdown = CancellationToken::new();

        // The real control surface, the door the install step knocks on:
        // beside the acquisition, as the daemon's start starts them.
        crate::rpc::spawn_answerer_control(&server.state, status.clone())
            .await
            .expect("the answerer control socket binds");
        let sock = std::path::PathBuf::from(server.state.minimal_state_dir().await.as_str())
            .join(crate::rpc::ANSWERER_CONTROL_SOCK_FILE);

        let task = drive(
            server.state.clone(),
            hook_port,
            status.clone(),
            AnswererPaths {
                channel: dir.path().join("answerer.sock"),
                marker: dir.path().join("dev.minimal.zone-answerer.socket"),
                release_window: Duration::from_secs(1),
            },
            shutdown.clone(),
            buf.clone(),
        );
        await_status_is(
            &status,
            minimald_rpc::ZoneAnswererStatus::Holder { port: hook_port },
            "hosted the interim before the release",
        )
        .await;
        let reply = query_udp(hook_port, "web.min.internal.").await;
        assert!(
            !reply.answers.is_empty(),
            "the interim answers before the release"
        );

        // A cancel with no release pending is a no-op.
        let (acted, detail) = ask_control(
            &sock,
            minimald_rpc::BoxControlRequest::ReleaseAnswererCancel,
        )
        .await;
        assert!(
            !acted,
            "a cancel with no release pending answers a no-op: {detail}"
        );

        // The release: answered once the port is free, with the sentence
        // the log also said.
        let (acted, detail) =
            ask_control(&sock, minimald_rpc::BoxControlRequest::ReleaseAnswerer).await;
        assert!(acted, "the release is answered as acted on: {detail}");
        assert!(
            detail.contains("released the interim answerer"),
            "the release's answer says what happened, got: {detail}"
        );
        probe_udp_port(hook_port).expect("the hook port is free while the window waits");

        // No channel comes: the window runs out and the daemon re-binds its
        // interim on its own, logging both. The probe above dropped at once,
        // so the re-bind is the one that takes the port.
        await_status_is(
            &status,
            minimald_rpc::ZoneAnswererStatus::Holder { port: hook_port },
            "re-bound the interim after the window ran out",
        )
        .await;
        let log = buf.contents();
        assert!(
            log.contains("no answerer service channel came within 1 s of the release"),
            "the timeout names the window that ran out, got: {log}"
        );
        assert!(
            log.contains("re-binding the interim answerer"),
            "the timeout says the interim re-bound, got: {log}"
        );
        let reply = query_udp(hook_port, "web.min.internal.").await;
        assert!(
            !reply.answers.is_empty(),
            "the re-bound interim answers again"
        );

        end(task, &shutdown);
    }
}
