//! The VM host daemon's zone answerer: the box zone (`*.min.internal`),
//! answered on the host loopback from the host-authored table (NET-138) —
//! the answering half a VM-backed host has on the *host*, which is the
//! whole point of the split: the table this daemon fills outside the VM
//! ([`crate::box_registry`]) is the one the zone must answer from, and the
//! in-VM daemon no longer answers at all (`minimald` starts no answerer in
//! a microVM; the host answerer owns the zone on this host).
//!
//! The answer *semantics* are not this module's to invent: they are the
//! shared decision ([`sessions::core::zone_answer`]) — the same one the
//! native daemon's answerer calls — and what this module owns beside it is
//! the DNS wire (decoding a query, encoding the reply the decision's
//! verdict names, the SOA its negatives cite), the host loopback listener,
//! and one machine-shaped rule below.
//!
//! That rule is the **holder**. The answerer port is the machine's, so on a
//! host running more than one VM host daemon — one per named VM — exactly
//! one of them can bind it. The one that does is the holder: it serves the
//! zone from its own table *merged with every other daemon's registered
//! rows*, which arrive over the answerer channel, a unix socket beside the
//! daemon's state — a name two sources both hold is kept by the first
//! writer and refused of the later, one warn per clash. A daemon that
//! finds the port held connects, sends its
//! table's zone rows as one line, keeps the connection open, and answers
//! nothing itself — its rows answer through the holder. The connection is
//! the registration's lifetime: when it drops, the holder retires its rows,
//! so a daemon that exits never leaves names answering behind it, and a
//! table that changes re-registers (the registry pings every change
//! ([`BoxRegistry::subscribe_table_pings`])). A holder that exits frees
//! the port, and the next daemon's re-check takes it, so the zone is never
//! orphaned on a host whose first daemon went away.
//!
//! Answer semantics, decided by the shared core and gated on the lookup
//! originating on this machine (NET-006 — the zone leaves the machine with
//! *nothing*, not even a refusal):
//!
//! | Lookup | Reply |
//! |---|---|
//! | A, held with a host-answerable address | that address (NET-127) |
//! | A, held without one (a box's switch lease) | NODATA (NET-124) |
//! | any other type, held name | NODATA (NET-124) |
//! | held, stopped namespace | NODATA, never NXDOMAIN (NET-128) |
//! | anything, name nothing holds | NXDOMAIN (NET-125) |
//! | a name outside the box zone | REFUSED |
//! | anything but a standard query | NOTIMP |
//!
//! Every negative carries the zone's SOA with a 15 s `minimum` (NET-124),
//! and every record the answerer emits holds a TTL of at most 15 s
//! (NET-126) — the constants are the shared decision's.
//!
//! The observability contract, as the phase's diagnostics state it: one
//! debug line per answered lookup naming the name, the type, and the answer
//! class; one info line at start naming the listener this daemon holds or
//! the holder it registered with.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use minimald_rpc::ZoneAnswererStatus;
use serde::{Deserialize, Serialize};

use sessions::core::zone_answer::{self, ZoneRow, ZoneView};

use crate::box_registry::{BoxRegistry, is_host_answerable};

/// The `component` field every answerer log line carries — the same one the
/// native daemon's answerer logs under, because it is the same zone service
/// either daemon hosts, and a bundle's daemon log names whichever host holds
/// it.
const COMPONENT: &str = "zone-answerer";

/// The machine's answerer port: the next one after the egress (`:7654`) and
/// mTLS (`:7655`) proxies, mirroring the native daemon's own default
/// (`ANSWERER_PORT` in minimald's `net/answerer.rs`) — `minvmd` does not
/// depend on the daemon, so the value is pinned here beside the one it
/// mirrors, and the e2e lane names it in the resolver command it builds.
///
/// This is a rendezvous, not the node's handed pair: a daemon that finds it
/// held registers with the holder at it, so it is never probed away to an
/// OS-assigned port no resolver would be told about (the guest's handed
/// answerer port — which the guest now binds nothing on — still is).
pub const DEFAULT_ANSWERER_PORT: u16 = 7656;

/// The answerer channel socket's file name inside the machine's shared
/// provider-instance dir. Deliberately beside [`crate::control`]'s
/// `control.sock` rather than in the `paths` crate: this name only means
/// something where two VM host daemons share a machine.
pub const CHANNEL_SOCK_FILE: &str = "answerer.sock";

/// Largest datagram the answerer reads: a DNS query fits far below this
/// (queries are tens of bytes), and a larger datagram is dropped rather than
/// buffered unbounded.
const MAX_DATAGRAM: usize = 4096;

/// How long the holder waits for a registering daemon's first line before
/// dropping the connection: a connection that never speaks is a stray
/// connect, not a registrant, and must not pin the per-connection slot.
const REGISTER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest line either side of the channel will read: a registration
/// carries one row per published namespace; anything past this bound is not
/// one.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// How long a daemon that does not hold the answerer port waits before
/// trying it again: long enough that a live holder sees no chatter, short
/// enough that a holder that exited is replaced within half a minute — the
/// zone is never orphaned on a host whose first daemon went away.
const PORT_RECHECK: Duration = Duration::from_secs(30);

/// Resolve the answerer channel socket's path — machine-global: the
/// provider-instance dir every VM this host supervises shares
/// (`<state>/providers/local-minvmd0/`, not the per-VM dir a named VM's
/// files live under), so the daemon holding the answerer port and every
/// daemon that does not resolve one path by the same rule.
#[must_use]
pub fn resolve_channel_sock() -> PathBuf {
    paths::provider_instance_dir(
        &crate::state::state_base_dir(),
        paths::ProviderKind::Minvmd,
        0,
    )
    .as_utf8_path()
    .as_std_path()
    .join(CHANNEL_SOCK_FILE)
}

// ── the channel's wire ───────────────────────────────────────────────────────

/// One row of a registration: the zone name (`<name>.min.internal`), the
/// host-answerable address a lookup may be told, and the row's liveness —
/// the [`ZoneRow`] the sender's view holds, on the wire. The sender's
/// registry built the row (NET-138: a registered row is host-authored by
/// the daemon that owns the table it came from); the holder re-applies the
/// address gate as it folds the row in, so no registration can put an
/// address in the zone the host may not be told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisteredRow {
    /// The full zone name, as the sender's view held it.
    name: String,
    /// The address an A lookup gets, if there is one to tell.
    address: Option<Ipv4Addr>,
    /// Whether the namespace the name names is running.
    live: bool,
}

/// One registration over the channel: a whole table's zone rows, one line.
/// The *message*, not the registration itself — that is the registrant's
/// held connection ([`Registration`]), which outlives the line it arrived
/// by for exactly as long as its rows are held.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationRequest {
    /// The sender's zone rows, in the sender's name order.
    rows: Vec<RegisteredRow>,
}

/// The holder's one-line reply to a registration: the ack a registrant waits
/// for, so it knows its rows are answering before it stops trying, or the
/// reason it is not.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationReply {
    /// Whether the registration is held.
    ok: bool,
    /// The reason a registration was refused, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl RegistrationReply {
    /// The ack.
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    /// A refusal carrying `reason`.
    fn refused(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(reason.into()),
        }
    }
}

// ── the holder's registered tables ───────────────────────────────────────────

/// The rows other VM host daemons registered over the channel, keyed by the
/// connection that filed them: a registration is held while its connection
/// lives, replaced by the connection's next line, and retired with the
/// connection's end. Shared between the channel's serving threads (which
/// install and retire) and the answerer (which answers), so a lookup and
/// the channel never see different tables.
#[derive(Debug, Default)]
struct RegisteredTables {
    rows: Mutex<BTreeMap<u64, Vec<RegisteredRow>>>,
}

impl RegisteredTables {
    /// No registered tables: a holder whose machine runs one daemon.
    fn new() -> Self {
        Self::default()
    }

    /// Holds `rows` as the registration `connection` filed, replacing
    /// whatever it held before — a re-registration is the whole table
    /// again, so a row that went is gone in the same line.
    fn install(&self, connection: u64, rows: Vec<RegisteredRow>) {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .insert(connection, rows);
    }

    /// Retires the registration `connection` filed: the connection is over,
    /// so its names answer nothing here anymore.
    fn remove(&self, connection: u64) {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .remove(&connection);
    }

    /// Every registered row with the connection that filed it, flattened
    /// across them in connection order — the earlier connection is the
    /// earlier writer, which is the order the answerer's clash rule keeps
    /// names in. The connection rides along so a refused row can be logged
    /// naming the source that holds the name and the one that lost it.
    fn rows(&self) -> Vec<(u64, RegisteredRow)> {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .iter()
            .flat_map(|(connection, rows)| rows.iter().map(|row| (*connection, row.clone())))
            .collect()
    }
}

// ── the answerer ──────────────────────────────────────────────────────────────

/// The host answerer: this daemon's own host-authored table, merged with the
/// rows other VM host daemons registered over the channel, behind the
/// shared answer decision. Built once when the port is held and served for
/// the daemon's lifetime ([`serve`]).
struct HostAnswerer {
    /// This daemon's own table (NET-138): the registry `run` fills.
    own: BoxRegistry,
    /// The rows other VM host daemons registered with this one.
    registered: Arc<RegisteredTables>,
    /// The zone's SOA, carried by every negative (NET-124), built once.
    soa: Record,
    /// The refused name clashes a warn has already named: one warn per clash,
    /// not one per lookup, and a clash that clears is warnable again if it
    /// comes back (see [`Self::zone_view`]).
    warned: Mutex<BTreeSet<String>>,
}

impl HostAnswerer {
    /// An answerer over `own`, answering the registered `rows` beside it.
    fn new(own: BoxRegistry, registered: Arc<RegisteredTables>) -> Self {
        Self {
            own,
            registered,
            soa: zone_soa(),
            warned: Mutex::new(BTreeSet::new()),
        }
    }

    /// The reply bytes for one datagram, or `None` to send nothing.
    ///
    /// `None` is a decision, not a failure: a source that did not originate
    /// on this machine gets nothing at all (NET-006), and so does a datagram
    /// that is not a standard query — no question section to answer, no id
    /// to echo an error to, and a response reflected back at a sender is a
    /// reflection loop, not an answer. This is the answerer's whole
    /// contract as a pure function of `(source, datagram)`, so the machine
    /// rule and every answer class are testable without a socket.
    fn respond(&self, peer: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
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
        // halves, then the shared decision over them: where the datagram
        // came from and what the tables hold for the name are this module's
        // to say; which answer class that lookup gets is the core's.
        let lookup = zone_answer::Lookup {
            name: asked.to_string(),
            record: if qtype == RecordType::A {
                zone_answer::RecordType::A
            } else {
                zone_answer::RecordType::Other
            },
            origin: origin_for(peer),
        };
        let view = self.zone_view();
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
            // misconfiguration names itself — with no authority section.
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

    /// The zone view this answerer answers from: this daemon's own
    /// host-authored table (NET-138) — filed first, so a name both tables
    /// hold is answered by this host's own row — the host's own name beside
    /// it ([`HOST_NAME`], held by the answerer itself), and the rows other
    /// VM host daemons registered over the channel folded in on top, the
    /// registered address re-gated so no registration can put an address
    /// in the zone the host may not be told (NET-127).
    ///
    /// A name two sources both hold is **not** folded twice: the first
    /// writer keeps it and the later one is refused, so a clashing name's
    /// answer is one fact, decided by the fold's order — this host's own
    /// table, then the registrations in the order their connections filed
    /// — and never by which row arrived last. The shared decision's
    /// [`ZoneView::hold`] replaces, which is the behaviour a builder wants
    /// over rows it knows are its own; here the rows come from daemons
    /// this one does not control, so the fold refuses instead. Each
    /// refusal is logged once per clash, at warn, naming the name and both
    /// its sources — the keeper and the refused writer — because a name
    /// two daemons both published is an operator's problem to see, not a
    /// fact to settle by accident of arrival.
    fn zone_view(&self) -> ZoneView {
        let mut view = self.own.zone_view();
        // The source each folded name came from: the keeper a later writer
        // is refused against, and the source the warn names.
        let mut held: BTreeMap<String, String> = view
            .rows()
            .map(|(name, _)| (name.to_string(), OWN_TABLE.to_string()))
            .collect();
        // The host's own name (NET-003's host half): `host.min.internal` at
        // the host loopback, held by the answerer itself, because it is the
        // host's name, not a namespace any table publishes, and the shared
        // decision holds no special case for it. Held after the own table,
        // so a box named `host` cannot take the host's name — the row the
        // answerer answers is the host's — and before the fold, so a
        // registration for it from any node is refused like every name the
        // answerer holds first.
        held.insert(HOST_NAME.to_string(), HOST_ROW.to_string());
        view.hold(
            HOST_NAME,
            ZoneRow {
                address: Some(Ipv4Addr::LOCALHOST),
                live: true,
            },
        );
        let mut refused: BTreeSet<String> = BTreeSet::new();
        for (connection, row) in self.registered.rows() {
            let name = canonical(&row.name);
            if let Some(kept_by) = held.get(&name) {
                refused.insert(name.clone());
                // One warn per standing clash, not one per lookup that
                // meets it: the set keeps the clashes already named, and a
                // clash that cleared is forgotten below so a returning one
                // warns again. `insert` returns whether this pass is the
                // first to see the clash, and that pass is the one that
                // warns.
                if self
                    .warned
                    .lock()
                    .expect(
                        "the clash set's lock is never held across a panic, so it cannot \
                         be poisoned",
                    )
                    .insert(name.clone())
                {
                    tracing::warn!(
                        component = COMPONENT,
                        name = %name,
                        kept_by = %kept_by,
                        refused = %registration(connection),
                        "refused a registered zone row for a name another source holds; \
                         the first writer keeps the name, the later one answers nothing \
                         here"
                    );
                }
                continue;
            }
            held.insert(name.clone(), registration(connection));
            view.hold(
                name,
                ZoneRow {
                    address: row.address.filter(|address| is_host_answerable(*address)),
                    live: row.live,
                },
            );
        }
        // A clash that cleared is warnable again if it comes back.
        self.warned
            .lock()
            .expect(
                "the clash set's lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .retain(|name| refused.contains(name));
        view
    }

    /// The reply bytes for one answered lookup: the envelope every
    /// verdict's reply shares — the query echoed, the rcode named, and the
    /// answer record in the answer section when there is one —
    /// authoritative for the zone and for nothing else (the REFUSED reply
    /// is not, so it never cites our SOA over someone else's namespace).
    /// The negatives the zone certifies are its own — an authoritative
    /// reply with no answer records, NODATA and NXDOMAIN — and every one of
    /// them carries the zone's SOA in the authority section (NET-124): the
    /// record the host resolver needs to cache the negative at all.
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

/// The source a name this host's own table holds is named by in the clash
/// warn — this host-authored table, the fold's first writer.
const OWN_TABLE: &str = "this host's own table";

/// The host's own name under the zone, as the answerer holds it (NET-003's
/// host half): the name a lookup of the host itself gets, at the host
/// loopback. Not a namespace any table publishes, and the shared decision
/// holds no special case for it, so the row is the answerer's to hold — and
/// the one the host-side facts read: the CLI's liveness query (the A query
/// for this name at the reported port that proves the answerer serves) and
/// the session e2e's dig both read it. A registration for it from any node
/// is refused, like every name the answerer holds first.
///
/// Public so the CLI's query asks for the name this answerer holds — one
/// definition, so the question and the answer cannot drift apart.
pub const HOST_NAME: &str = "host.min.internal";

/// The source the answerer's own [`HOST_NAME`] row keeps its name under in
/// the fold: the keeper a refused registration's warn names.
const HOST_ROW: &str = "the host's own row";

/// The source a name the registration `connection` filed is named by in
/// the clash warn: which co-resident daemon's connection it rode, the only
/// handle the holder has on a registrant that is not its own process.
fn registration(connection: u64) -> String {
    format!("zone registration {connection}")
}

/// The canonical form of a registered row's name, mirroring the shared
/// decision's own normalization (lower-case, no root dot) — the one form the
/// view holds names in, so the fold's clash rule compares in it and no
/// registrant can slip a case variant of a held name past the rule and take
/// a name another source keeps.
fn canonical(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

/// Where a datagram from `peer` originated (NET-006): the listener binds
/// the host loopback, so only loopback peers reach it at all — the source
/// is still checked per datagram, so a misbound socket can never serve the
/// zone to the network.
fn origin_for(peer: SocketAddr) -> zone_answer::Origin {
    let on_machine = match peer.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if on_machine {
        zone_answer::Origin::OnMachine
    } else {
        zone_answer::Origin::OffMachine
    }
}

/// The zone's SOA record, built once per answerer: the record every
/// negative answer carries in its authority section (NET-124), so the host
/// resolver can cache it — RFC 2308's negative TTL is this record's TTL
/// capped by its `minimum`. The zone has no secondaries, so every field
/// but `minimum` is inert; all of them carry the shared decision's TTL
/// ceiling so no number the answerer emits exceeds NET-126's bound.
fn zone_soa() -> Record {
    let apex =
        Name::from_utf8(format!("{}.", zone_answer::ZONE_APEX)).expect("the zone apex parses");
    let mname =
        Name::from_utf8(format!("ns.{}.", zone_answer::ZONE_APEX)).expect("the SOA mname parses");
    let rname = Name::from_utf8(format!("hostmaster.{}.", zone_answer::ZONE_APEX))
        .expect("the SOA rname parses");
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

// ── the channel's line codec ──────────────────────────────────────────────────

/// Read one line (terminated by `\n`) from one side of the channel. A
/// connection that closes before sending a line reads as no request; a
/// line past [`MAX_REQUEST_LINE`] is refused. Bounded by the caller's read
/// timeout, whatever it is: the holder bounds the first line only, and a
/// registrant bounds the reply it waits for.
#[expect(
    clippy::indexing_slicing,
    reason = "cut at `read`, the byte count `read()` reported, or at `newline`, an index `position` found inside `buf[..read]`"
)]
fn read_line(stream: &mut UnixStream) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                // A partial line at EOF — a peer that died mid-write.
                // Still answerable with a refusal, so hand what arrived
                // back rather than hanging the slot on a timeout.
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

/// Parses one registration line. A line that does not parse is refused, not
/// fatal: the holder answers with the reason and drops the connection.
fn parse_registration(line: &str) -> Result<RegistrationRequest, String> {
    serde_json_lenient::from_str(line).map_err(|error| error.to_string())
}

/// Writes one reply line.
fn write_reply(stream: &mut UnixStream, reply: &RegistrationReply) -> io::Result<()> {
    let mut line = serde_json_lenient::to_string(reply).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("channel reply did not serialize: {error}"),
        )
    })?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

// ── the holder: the channel listener ──────────────────────────────────────────

/// Binds the answerer channel's listener beside the answerer's socket and
/// serves registrations on a dedicated thread: one connection per
/// co-resident VM host daemon, each connection's rows held while the
/// connection lives. The bind happens on the calling thread so its failure
/// surfaces where the answerer is started ([`acquire_loop`] warns and
/// serves on); the socket gets the bridge socket's posture — path-length
/// check, a 0700 parent dir, a stale socket removed, 0600 on the socket —
/// so only the same user may register rows, the same trust the control
/// socket rests on.
fn hold_channel(sock: &Path, registered: Arc<RegisteredTables>) -> io::Result<()> {
    crate::sock::check_uds_path_len(sock)?;
    crate::sock::prepare_socket_dir(sock)?;
    crate::sock::remove_stale_socket(sock)?;
    let listener = UnixListener::bind(sock)?;
    crate::sock::enforce_socket_permissions(sock)?;
    std::thread::Builder::new()
        .name("minvmd-zone-channel".to_string())
        .spawn(move || accept_registrations(listener, registered))
        .map(|_| ())
}

/// Accepts registrations until the daemon exits. One thread per connection:
/// a registration's rows must retire the moment its connection ends, which
/// is a read per connection, so one hung connection holds its own rows and
/// nothing else.
fn accept_registrations(listener: UnixListener, registered: Arc<RegisteredTables>) {
    let mut next: u64 = 0;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let connection = next;
                next += 1;
                let registered = Arc::clone(&registered);
                let spawned = std::thread::Builder::new()
                    .name("minvmd-zone-registration".to_string())
                    .spawn(move || serve_registration(connection, stream, registered));
                if let Err(error) = spawned {
                    tracing::warn!(
                        component = COMPONENT,
                        %error,
                        "could not serve a zone registration; that daemon's names will \
                         not answer here"
                    );
                }
            }
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "answerer channel accept failed"
                );
            }
        }
    }
}

/// Serves one registration connection. The first line — the registration
/// itself — is bounded, because a connection that never speaks is a stray
/// connect, not a registrant; once it has registered, the connection holds
/// its rows for as long as it lives, and re-registrations arrive only when
/// the peer's table changes, so the wait between them is unbounded and the
/// peer's exit — the one event that retires its rows — is the read's own
/// EOF.
fn serve_registration(connection: u64, mut stream: UnixStream, registered: Arc<RegisteredTables>) {
    if let Err(error) = stream.set_read_timeout(Some(REGISTER_READ_TIMEOUT)) {
        tracing::debug!(
            component = COMPONENT,
            %error,
            "zone registration connection could not set its read timeout"
        );
        return;
    }
    let first = match read_line(&mut stream) {
        Ok(Some(line)) => line,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(
                component = COMPONENT,
                %error,
                "zone registration connection went before it registered"
            );
            return;
        }
    };
    if !accept_line(&mut stream, connection, &first, &registered) {
        return;
    }
    // Registered: the connection's rows live with it now, and every later
    // line replaces them — the ping shape the peer re-registers by.
    let _ = stream.set_read_timeout(None);
    loop {
        match read_line(&mut stream) {
            Ok(Some(line)) => {
                if !accept_line(&mut stream, connection, &line, &registered) {
                    return;
                }
            }
            Ok(None) | Err(_) => {
                registered.remove(connection);
                tracing::debug!(
                    component = COMPONENT,
                    "a zone registration ended; its names answer here no more"
                );
                return;
            }
        }
    }
}

/// Holds or refuses one registration line, answering it. Returns whether
/// the connection may carry on: a refused line ends it, and its rows go.
fn accept_line(
    stream: &mut UnixStream,
    connection: u64,
    line: &str,
    registered: &RegisteredTables,
) -> bool {
    let outcome = match parse_registration(line) {
        Ok(registration) => {
            let rows = registration.rows.len();
            registered.install(connection, registration.rows);
            tracing::debug!(
                component = COMPONENT,
                rows = rows,
                "holds a zone registration"
            );
            write_reply(stream, &RegistrationReply::ok())
        }
        Err(error) => write_reply(stream, &RegistrationReply::refused(error)),
    };
    match outcome {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(component = COMPONENT, %error, "zone registration reply failed");
            registered.remove(connection);
            false
        }
    }
}

// ── the registrant ───────────────────────────────────────────────────────────

/// One daemon's registration with the zone answerer's holder: the
/// connection its rows are held by. Dropping it retires them — the
/// connection's end is the whole withdrawal, so a daemon that exits never
/// leaves names answering behind it — and [`send`](Self::send) re-registers
/// over the same connection, which is the ping shape [`acquire_loop`]
/// re-registers by.
struct Registration {
    /// The held connection: this registration's lifetime.
    stream: UnixStream,
}

impl Registration {
    /// Re-registers `rows` over the held connection, waiting for the
    /// holder's ack: a registration that did not land is not held, and the
    /// error tells the caller to connect again.
    fn send(&mut self, rows: Vec<RegisteredRow>) -> io::Result<()> {
        let mut line =
            serde_json_lenient::to_string(&RegistrationRequest { rows }).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("zone registration did not serialize: {error}"),
                )
            })?;
        line.push('\n');
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        let _ = self.stream.set_read_timeout(Some(REGISTER_READ_TIMEOUT));
        let reply_line = read_line(&mut self.stream)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the holder closed"))?;
        let reply: RegistrationReply =
            serde_json_lenient::from_str(reply_line.trim()).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the holder's reply did not parse: {error}"),
                )
            })?;
        if reply.ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                reply
                    .error
                    .unwrap_or_else(|| "the holder refused the registration".to_string()),
            ))
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Closing the connection is the whole withdrawal: the holder
        // retires this registration's rows when its read ends.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Registers `rows` with the daemon holding the answerer port: one
/// connection, one registration line, one ack. The returned
/// [`Registration`] holds the connection open, which is the registration's
/// lifetime.
fn register_rows(sock: &Path, rows: Vec<RegisteredRow>) -> io::Result<Registration> {
    let mut registration = Registration {
        stream: UnixStream::connect(sock)?,
    };
    registration.send(rows)?;
    Ok(registration)
}

/// The zone rows of `registry`'s table, as the registration wire carries
/// them: the same view the holder's own answers come from, encoded — one
/// row per published namespace, its name under the zone, its
/// host-answerable address, and its liveness — minus the node namespace's
/// row, which never travels the channel: every VM host daemon's table holds
/// the same name (`minimald.min.internal`), so the holder answers its own
/// node row and a second VM's registration of it would only be refused as a
/// clash — the by-construction clash-warn this exclusion takes out. The
/// host's own name is in no table's view (the answerer holds it itself), so
/// nothing else needs excluding here.
fn zone_rows(registry: &BoxRegistry) -> Vec<RegisteredRow> {
    let node = crate::box_registry::node_zone_name();
    registry
        .zone_view()
        .rows()
        .filter(|(name, _)| **name != node)
        .map(|(name, row)| RegisteredRow {
            name: name.to_string(),
            address: row.address,
            live: row.live,
        })
        .collect()
}

// ── the start ────────────────────────────────────────────────────────────────

/// The answerer's state as the control socket's status read serves it
/// (NET-138's interim surfaced at session start and on `min ls`): what the
/// acquisition loop last decided the machine's answerer is — this daemon
/// holding the port, another VM host daemon holding it with this table's
/// rows registered with it, or the port held by a process with no channel —
/// written by the loop at every pass and read where the CLI asks for it.
///
/// The status says where to look and who holds the port; whether the
/// answerer is *live* at the named port is the client's own A query for
/// `host.min.internal` to prove — the row the answerer itself holds —
/// because a host fact the host's client reads itself is the only one
/// inside the escape boundary's trust. The state before the loop's first
/// pass is [`ZoneAnswererStatus::Starting`]: the daemon has not said which
/// it is, and a read that lands there prints nothing, the arm that cannot
/// misreport.
#[derive(Debug, Clone)]
pub struct AnswererStatus(Arc<Mutex<ZoneAnswererStatus>>);

impl AnswererStatus {
    /// A status whose acquisition loop has not run yet.
    #[must_use]
    pub fn starting() -> Self {
        Self(Arc::new(Mutex::new(ZoneAnswererStatus::Starting)))
    }

    /// The state the acquisition loop last wrote.
    #[must_use]
    pub fn get(&self) -> ZoneAnswererStatus {
        *self
            .0
            .lock()
            .expect("the answerer status lock is never held across a panic")
    }

    /// The acquisition loop's own writer: called at every pass, with the
    /// state that pass left the machine's answerer in.
    pub(crate) fn set(&self, status: ZoneAnswererStatus) {
        *self
            .0
            .lock()
            .expect("the answerer status lock is never held across a panic") = status;
    }
}

/// Starts the host answerer: binds the machine's answerer port on the host
/// loopback and serves the zone from `registry`'s table, or — when the port
/// is held by another VM host daemon on this machine — registers
/// `registry`'s zone rows with that holder over the answerer channel and
/// answers nothing itself. Every pass the acquisition takes writes the
/// state it left the machine in to `status`, the one place the control
/// socket's status read serves it from. One background thread, for the
/// daemon's lifetime, the way the control socket serves; a thread the host
/// could not spare is the only failure returned, because a held port is
/// the normal multi-VM case, not an error to fail a boot over.
///
/// # Errors
///
/// Returns the OS error when the thread cannot be spawned.
pub fn spawn(
    registry: BoxRegistry,
    port: u16,
    status: AnswererStatus,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("minvmd-zone-answerer".to_string())
        .spawn(move || acquire_loop(registry, port, status))
}

/// Acquires the machine's answerer port and serves it, or registers with
/// the daemon that holds it, for this daemon's lifetime.
///
/// The holder is whichever daemon bound the port first, and a lone daemon
/// is one at start: the bind is attempted before any wait, so the port is
/// held the moment the daemon starts rather than after the first box
/// registration or the [`PORT_RECHECK`] cadence. A daemon that finds the
/// port held registers its rows and then re-checks it on the registry's
/// change pings — a changed table re-registers with the holder, so a box
/// published after this daemon started answers through the holder too —
/// and on the [`PORT_RECHECK`] cadence, so a holder that exited is replaced
/// within it and the zone is never orphaned. A port held by something that
/// is not a holder — a native daemon, or a foreign process with no channel
/// socket — is warned once and retried at the same cadence: the zone
/// answers from that holder alone, and this daemon answers nothing.
fn acquire_loop(registry: BoxRegistry, port: u16, status: AnswererStatus) {
    acquire_loop_at(registry, port, resolve_channel_sock(), status);
}

/// The acquisition over a named channel socket, so the whole holder and
/// registrant machinery is drivable where the channel is not the machine's
/// own (the test below runs two daemons on one temporary channel).
fn acquire_loop_at(registry: BoxRegistry, port: u16, channel: PathBuf, status: AnswererStatus) {
    // Subscribed before the first bind attempt, so no change lands unpinged
    // in the window before the port is decided. The holder drops it: its
    // own table answers live, so it has nothing to re-register, and the
    // next ping prunes the dead sender.
    let pings = registry.subscribe_table_pings();
    let mut held: Option<Registration> = None;
    // Two once-only lines, each on a flag of its own: the warn that the port
    // is held by something the channel cannot reach, and the info line that
    // names the holder this table's rows first registered with. A pass that
    // warned must not take the info line with it — a daemon that boots
    // against a native minimald's hold and registers with the VM host daemon
    // that takes the port after it would otherwise name its holder neither
    // at a listener nor at a registration, and the diagnostics contract and
    // the e2e's log greps read the info line.
    let mut warned = false;
    let mut registered_once = false;
    loop {
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(socket) => {
                drop(held);
                let addr = socket
                    .local_addr()
                    .map_or_else(|_| format!("127.0.0.1:{port}"), |addr| addr.to_string());
                status.set(ZoneAnswererStatus::Holder { port });
                tracing::info!(
                    component = COMPONENT,
                    listener = %addr,
                    status = "serving",
                    "the zone answerer holds the host loopback: the box zone answers here, \
                     from this host-authored table"
                );
                // One table of registered rows, shared by the answers and
                // the channel that fills them: a row another daemon
                // registers must be the row a lookup is answered by, which
                // two tables could never promise.
                let registered = Arc::new(RegisteredTables::new());
                let answerer = HostAnswerer::new(registry.clone(), Arc::clone(&registered));
                // The channel is how other VM host daemons' tables reach
                // these answers; a bind failure is warned and served
                // around — the zone still answers, from this table alone.
                if let Err(error) = hold_channel(&channel, registered) {
                    tracing::warn!(
                        component = COMPONENT,
                        %error,
                        "could not bind the answerer channel socket; other VM host daemons \
                         cannot register their names with this answerer"
                    );
                }
                drop(pings);
                serve(socket, answerer);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                // The port is held: this daemon's rows answer through the
                // holder. A held connection re-registers; a lost one is
                // dropped here and the next pass connects again.
                let rows = zone_rows(&registry);
                let outcome = match held.take() {
                    Some(mut registration) => {
                        let sent = registration.send(rows.clone());
                        if sent.is_ok() {
                            held = Some(registration);
                        }
                        sent
                    }
                    None => register_rows(&channel, rows.clone()).map(|registration| {
                        held = Some(registration);
                    }),
                };
                let first = held.is_some() && !registered_once;
                match outcome {
                    Ok(()) => {
                        status.set(ZoneAnswererStatus::Registered { port });
                        if first {
                            registered_once = true;
                            tracing::info!(
                                component = COMPONENT,
                                holder = %channel.display(),
                                rows = rows.len(),
                                "the zone answerer's port is held by another VM host daemon; \
                                 registered this table's zone rows with it and answer nothing here"
                            );
                        } else {
                            tracing::debug!(
                                component = COMPONENT,
                                holder = %channel.display(),
                                rows = rows.len(),
                                "re-registered this table's zone rows with the holder"
                            );
                        }
                    }
                    Err(error) => {
                        status.set(ZoneAnswererStatus::PortHeldNoChannel { port });
                        if !warned {
                            warned = true;
                            tracing::warn!(
                                component = COMPONENT,
                                port,
                                %error,
                                channel = %channel.display(),
                                "the zone answerer's port is held and the holder's channel did \
                                 not answer (a native minimald or a foreign process holds it); \
                                 this VM's box names are not answered on the host"
                            );
                        } else {
                            tracing::debug!(
                                component = COMPONENT,
                                %error,
                                "the holder's channel still did not answer"
                            );
                        }
                    }
                }
                // The wait belongs at the end of a pass that did not take
                // the port: a change ping re-registers through the next
                // pass, a cadence wake just re-checks the port — and the
                // holder does not live forever, so a daemon that outlives
                // one takes the port.
                let _ = pings.recv_timeout(PORT_RECHECK);
            }
            Err(error) => {
                tracing::warn!(
                    component = COMPONENT,
                    %error,
                    "could not bind the zone answerer's port; the box zone answers only \
                     from another VM host daemon's table"
                );
                let _ = pings.recv_timeout(PORT_RECHECK);
            }
        }
    }
}

/// Serves the box zone on a bound socket, for the daemon's lifetime: one
/// datagram per turn, each either answered ([`HostAnswerer::respond`]) or
/// silently dropped — an off-host source, or something that is not a
/// standard query. A reply that cannot be sent is logged and skipped: a
/// peer that vanished mid-exchange must not take the answerer down.
fn serve(socket: UdpSocket, answerer: HostAnswerer) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if let Some(reply) = answerer.respond(peer, &buf[..len])
                    && let Err(error) = socket.send_to(&reply, peer)
                {
                    tracing::debug!(
                        component = COMPONENT,
                        %peer,
                        %error,
                        "could not send a box-zone reply"
                    );
                }
            }
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "box-zone receive failed; continuing"
                );
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hickory_proto::op::Query;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::box_registry::BoxRegistration;

    use super::*;

    /// A `MakeWriter` accumulating everything written into a shared buffer, so
    /// a test can assert on the structured fields a `tracing` event emitted —
    /// the same scaffolding the native daemon's answerer tests build, because
    /// the two answerers prove the same log lines.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for CaptureWriter {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the lock is never poisoned: the capture's only other \
                      holder unwraps it too, and a test that panics there \
                      has already failed"
        )]
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

    /// The plan's default subnet: the one the daemon's own registry is
    /// built with, so a test registry's rows sit at the addresses
    /// production's do.
    const SUBNET: switch::SwitchSubnet = switch::DEFAULT_SUBNET;

    /// One query datagram, the wire form the answerer reads: `name` as an
    /// FQDN (root dot included) at `rtype` — the same scaffolding the native
    /// daemon's answerer tests drive, so the two prove the same wire.
    fn encode_query(name: &str, rtype: RecordType) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("query name parses");
        let mut msg = Message::query();
        msg.add_query(Query::query(qname, rtype));
        msg.to_vec().expect("query encodes")
    }

    /// A registry holding one published box, `web`, at an address from the
    /// reserved local range, beside the node's own namespace — the table the
    /// daemon's start path fills. Returns the registry and the box's
    /// published loopback address, the address its name must answer with.
    fn web_registry() -> (BoxRegistry, Ipv4Addr) {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        let web = Ipv4Addr::new(127, 0, 64, 9);
        registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            web,
        ));
        (registry, web)
    }

    /// The answerer over `own`, with its registered tables filled by
    /// `install` — the rows a co-resident daemon would have filed over the
    /// channel.
    fn answerer_over(own: BoxRegistry, install: impl FnOnce(&RegisteredTables)) -> HostAnswerer {
        let registered = Arc::new(RegisteredTables::new());
        install(&registered);
        HostAnswerer::new(own, registered)
    }

    /// The answerer over `own` alone — the lone-daemon shape, holding the
    /// port and answering from its own table only.
    fn answerer(own: BoxRegistry) -> HostAnswerer {
        answerer_over(own, |_| {})
    }

    /// A source on this machine: a host resolver's datagram, from loopback.
    fn on_host() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)
    }

    /// Sends `datagram` to `answerer` as if from `peer`, and decodes the
    /// reply it produced, if any.
    fn exchange(answerer: &HostAnswerer, peer: SocketAddr, datagram: &[u8]) -> Option<Message> {
        let reply = answerer.respond(peer, datagram)?;
        Some(Message::from_vec(&reply).expect("the answerer's reply decodes"))
    }

    /// One real query-exchange against the answerer listening on `port`:
    /// a datagram from this machine's loopback, the reply decoded. `None`
    /// when nothing answered inside the read window.
    fn query(port: u16, name: &str, rtype: RecordType) -> Option<Message> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("the probe sets its read timeout");
        socket
            .send_to(&encode_query(name, rtype), (Ipv4Addr::LOCALHOST, port))
            .expect("the probe sends on loopback");
        let mut buf = vec![0u8; MAX_DATAGRAM];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => Some(Message::from_vec(&buf[..len]).expect("the reply decodes")),
            Err(_) => None,
        }
    }

    /// Waits until `probe` — one `query` attempt per try — returns `Some`,
    /// failing the test on `what` when the deadline passes. The holder's
    /// serve loop and a registrant's EOF are the two genuinely asynchronous
    /// turns these tests wait on; everything else is already decided when
    /// the call that made it so returns.
    fn await_answer(probe: impl Fn() -> Option<Message>, what: &str) -> Message {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(reply) = probe() {
                return reply;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: nothing answered within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until `probe` — one status read per try — reports a state the
    /// acquisition has decided, failing the test on `what` when the deadline
    /// passes. The acquisition's first pass is asynchronous from the thread
    /// spawn that starts it; every state after it is already decided when
    /// the call that made it so returns.
    fn await_status(probe: impl Fn() -> ZoneAnswererStatus, what: &str) -> ZoneAnswererStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = probe();
            if status != ZoneAnswererStatus::Starting {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the status never left `starting` within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The A record a reply answered with, when it answered with one.
    fn a_answer(reply: &Message) -> Ipv4Addr {
        let [record] = &reply.answers[..] else {
            panic!("an A answer holds exactly one record");
        };
        assert_eq!(
            record.record_type(),
            RecordType::A,
            "the answer is an A record"
        );
        let RData::A(A(address)) = &record.data else {
            panic!("the answer is an A record");
        };
        *address
    }

    /// The zone's SOA, which every negative reply carries in its authority
    /// section (NET-124) — the record a host resolver needs to cache the
    /// negative at all.
    fn soa_of(reply: &Message) -> &Record {
        let [record] = &reply.authorities[..] else {
            panic!("a negative carries exactly the zone's SOA");
        };
        assert_eq!(record.record_type(), RecordType::SOA);
        assert_eq!(
            record.name,
            Name::from_utf8(format!("{}.", zone_answer::ZONE_APEX)).expect("the apex parses"),
            "the SOA is the zone's own"
        );
        record
    }

    /// The holder answers the zone from the host-authored table (NET-138):
    /// a published box's name answers its published loopback address, the
    /// node's own namespace — a row like any other — answers the shared
    /// loopback address, and the host's own name answers the host loopback
    /// (NET-003's host half), the row the answerer itself holds. The same
    /// decision the native daemon's answerer answers over, from a table
    /// this daemon authored on the host.
    #[test]
    fn host_answerer_answers_zone_from_table() {
        let (registry, web) = web_registry();
        let answerer = answerer(registry);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("a held live name answers an A lookup");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.metadata.authoritative,
            "the zone is authoritative for its own names"
        );
        assert_eq!(
            a_answer(&reply),
            web,
            "the name answers the row's published loopback address"
        );

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("minimald.min.internal.", RecordType::A),
        )
        .expect("the node's own namespace is a held row");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the node row answers the shared loopback address"
        );

        // NET-003's host half, held by the answerer itself: the host's own
        // name answers the host loopback, the row the CLI's liveness query
        // reads at the reported port and the session e2e digs — the proof
        // the answerer serves, not a row any table published.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("host.min.internal.", RecordType::A),
        )
        .expect("the host's own name is a held row");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.metadata.authoritative,
            "the host's own name is the zone's to answer"
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the host's own name answers the host loopback"
        );
    }

    /// A record type other than A is NODATA on a held name (NET-124) — never
    /// NXDOMAIN, which negative-caches the name away, and never an address
    /// the type did not ask for — and the NODATA carries the zone's SOA so
    /// the host resolver can cache it.
    #[test]
    fn host_answerer_non_a_is_nodata() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry);

        for rtype in [RecordType::AAAA, RecordType::HTTPS, RecordType::TXT] {
            let reply = exchange(
                &answerer,
                on_host(),
                &encode_query("web.min.internal.", rtype),
            )
            .expect("a held name answers every type");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "a {rtype:?} lookup on a held name is NODATA, never NXDOMAIN"
            );
            assert!(
                reply.answers.is_empty(),
                "NODATA carries no {rtype:?} record"
            );
            soa_of(&reply);
        }
    }

    /// An in-zone name nothing holds is NXDOMAIN (NET-125), authoritative
    /// and carrying the zone's SOA — a negative the host resolver can cache.
    #[test]
    fn host_answerer_unknown_name_is_nxdomain() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("gone.min.internal.", RecordType::A),
        )
        .expect("an in-zone lookup is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            reply.answers.is_empty(),
            "NXDOMAIN carries no answer record"
        );
        assert!(
            reply.metadata.authoritative,
            "the zone's own negative is authoritative"
        );
        soa_of(&reply);

        // A name outside the zone is none of this answerer's to answer:
        // REFUSED, and no SOA of ours certifying someone else's namespace.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("example.com.", RecordType::A),
        )
        .expect("an out-of-zone lookup is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(
            reply.authorities.is_empty(),
            "REFUSED cites no SOA over another namespace"
        );
    }

    /// Every record the answerer emits holds a TTL of at most 15 s
    /// (NET-126) — the A answers, and the SOA its negatives carry, minimum
    /// included, which is the negative's own TTL — and a registered row is
    /// re-gated on arrival: an address the host may not be told answers
    /// NODATA (NET-127), not the address, while one it may answers.
    #[test]
    fn host_answerer_short_ttl_and_local_addresses_only() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry.clone());

        // The TTL ceiling, on every record of a positive answer...
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the held name answers");
        for record in reply.answers.iter().chain(&reply.authorities) {
            assert!(
                record.ttl <= zone_answer::ANSWER_TTL_SECS,
                "{} carries a {}s TTL, past the {}s ceiling",
                record.name,
                record.ttl,
                zone_answer::ANSWER_TTL_SECS
            );
        }

        // ...and on every record of a negative, whose SOA's `minimum` is the
        // negative's own TTL (RFC 2308).
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("gone.min.internal.", RecordType::A),
        )
        .expect("an unknown name is answered");
        let soa = soa_of(&reply);
        assert!(
            soa.ttl <= zone_answer::ANSWER_TTL_SECS,
            "the SOA carries a {}s TTL, past the ceiling",
            soa.ttl
        );
        let RData::SOA(rdata) = &soa.data else {
            panic!("the negative carries the zone's SOA");
        };
        assert!(
            rdata.minimum <= zone_answer::ANSWER_TTL_SECS,
            "the SOA's {}s minimum is the negative's TTL, past the ceiling",
            rdata.minimum
        );

        // The registered rows, as a co-resident daemon would file them: one
        // at an address the host may not be told — a box's switch lease,
        // inside the guest's fabric — and one at an address it may.
        let answerer = answerer_over(registry, |registered| {
            registered.install(
                0,
                vec![
                    RegisteredRow {
                        name: "lease.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(100, 64, 0, 10)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "peer.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 10)),
                        live: true,
                    },
                ],
            );
        });

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("lease.min.internal.", RecordType::A),
        )
        .expect("a registered name is held");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "a name held at an address the host may not be told answers NODATA (NET-127)"
        );
        assert!(
            reply.answers.is_empty(),
            "the registered switch lease never reaches the host's zone"
        );
        soa_of(&reply);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("peer.min.internal.", RecordType::A),
        )
        .expect("a registered name is held");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "a registered row at a host-answerable address answers it"
        );
    }

    /// A row withdrawn from the table takes its name with it: the name is
    /// held by nothing and answers NXDOMAIN (NET-125) — never a name held
    /// forever, and never an address nothing is answering on.
    #[test]
    fn host_answerer_withdrawn_row_is_nxdomain() {
        let (registry, web) = web_registry();
        let answerer = answerer(registry.clone());

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the published box's name is held");
        assert_eq!(a_answer(&reply), web);

        assert!(
            registry.withdraw(Ipv4Addr::new(100, 64, 0, 9)).is_some(),
            "the box was published at its lease"
        );
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the withdrawn name is still an in-zone lookup");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a withdrawn namespace's name is held by nothing"
        );
        assert!(reply.answers.is_empty());
        soa_of(&reply);
    }

    /// A name two sources both hold is the first writer's: this host's own
    /// table is filed first, so a registered row for a name it already holds
    /// is refused and never overwrites it — the answer stays the host's own
    /// row — and the host's own name is refused from any node the same way,
    /// because the answerer holds it before the fold. The registrant's rows
    /// beside the refused ones still answer.
    #[test]
    fn registered_row_does_not_take_a_held_name() {
        let (registry, web) = web_registry();
        let answerer = answerer_over(registry, |registered| {
            registered.install(
                0,
                vec![
                    RegisteredRow {
                        name: "web.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 99)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "host.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 98)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "peer.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 10)),
                        live: true,
                    },
                ],
            );
        });

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the clashing name is answered by its keeper");
        assert_eq!(
            a_answer(&reply),
            web,
            "the first writer keeps the name; a registrant does not overwrite it"
        );

        // The host's own name is refused from any node through the channel:
        // the answerer holds it itself (NET-003's host half), and no
        // registration — whatever address it carried — moves it.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("host.min.internal.", RecordType::A),
        )
        .expect("the host's own name is answered");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "a registration for the host's own name is refused; the host row keeps it"
        );

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("peer.min.internal.", RecordType::A),
        )
        .expect("the registration's other row is held");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "the refusal is per name, not per registration"
        );
    }

    /// Two VM host daemons on one machine: the one that holds the answerer
    /// port answers for both, because the other registers its table's zone
    /// rows with it over the channel — its box names with no row refused,
    /// its node row never sent (every VM's node row is the same name, so
    /// the channel would refuse it by construction) — and the
    /// registration's lifetime is its connection, so a daemon that exits
    /// never leaves names answering behind it. Driven through a real UDP
    /// socket and a real channel socket, the way the two daemons run: the
    /// holder through its own acquisition loop, the registrant through the
    /// registration that loop performs.
    #[test]
    fn second_vm_host_daemon_registers_names_with_holder() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // A free loopback port: reserved only to learn a free number, then
        // released for the holder to bind.
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);

        // The holder: its acquisition loop takes the port, holds the channel
        // beside it, and serves the zone from its own table. Its status cell
        // stays observable here — a clone rides into the thread, this one is
        // asserted on below.
        let (holder_registry, holder_web) = web_registry();
        let holder_channel = channel.clone();
        let holder_status = AnswererStatus::starting();
        let holder_status_probe = holder_status.clone();
        std::thread::Builder::new()
            .name("test-zone-holder".to_string())
            .spawn(move || acquire_loop_at(holder_registry, port, holder_channel, holder_status))
            .expect("the holder's thread spawns");

        // The channel is bound before the serve loop starts, so the first
        // answer implies the registration can land.
        let reply = await_answer(
            || query(port, "web.min.internal.", RecordType::A),
            "the holder never answered its own table",
        );
        assert_eq!(
            a_answer(&reply),
            holder_web,
            "the holder answers its own table's name"
        );

        // The second daemon's table, registered the way its own acquisition
        // loop would: one connection, one registration line, one ack — and
        // the rows are held before the ack is written, so they answer by the
        // time this returns. Its table holds the node row every VM host
        // daemon's does (`minimald.min.internal`), the very row the channel
        // must not carry: one name for every VM means the second VM's
        // registration of it would be refused as a clash by construction —
        // the holder answers its own, and a second VM's box names register
        // with no refusal at all.
        let second = BoxRegistry::new(SUBNET);
        second.register_node_namespace(7654);
        let second_web = Ipv4Addr::new(127, 0, 64, 11);
        second.register(BoxRegistration::new(
            "peer",
            Ipv4Addr::new(100, 64, 0, 11),
            second_web,
        ));
        let rows = zone_rows(&second);
        assert_eq!(
            rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
            ["peer.min.internal"],
            "the registration carries the second VM's box names and never the \
             node row: every VM's node row is the same name, so the channel \
             would only refuse it"
        );
        let registration =
            register_rows(&channel, rows.clone()).expect("the holder accepts the table");

        // Both VMs' box names are registered and no row is refused: every
        // row the second daemon sent answers through the holder at the
        // address it sent — a refused row would answer with its keeper's
        // address or nothing, and the sent set is the whole second table.
        for row in &rows {
            let reply = query(port, &format!("{}.", row.name), RecordType::A)
                .unwrap_or_else(|| panic!("the holder answers {}", row.name));
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{} registered with the holder",
                row.name
            );
            assert_eq!(
                a_answer(&reply),
                row.address.expect("the sent rows hold addresses"),
                "{} answers at the address the second daemon's table holds for it",
                row.name
            );
        }

        let reply = query(port, "peer.min.internal.", RecordType::A).expect("the holder answers");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "a registered row answers through the holder"
        );
        assert_eq!(
            a_answer(&reply),
            second_web,
            "the second daemon's name answers at its own address, through the first's socket"
        );

        // The node's name the channel did not carry still answers — the
        // holder's own node row, the one the zone answers host-side; inside
        // the guest the second VM's own DNS layer answers its own.
        let reply = query(port, "minimald.min.internal.", RecordType::A)
            .expect("the node's name is answered by the holder's own row");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the node's name answers the holder's own row host-side"
        );

        // The connection is the registration's lifetime: dropped, the
        // holder retires its rows and the name it held answers NXDOMAIN.
        drop(registration);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let answered = query(port, "peer.min.internal.", RecordType::A)
                .expect("an in-zone lookup is still answered");
            if answered.metadata.response_code == ResponseCode::NXDomain {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the retired registration's name still answers: {:?}",
                answered.metadata.response_code
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // The holder's own table is untouched by the registrant's exit.
        let reply = query(port, "web.min.internal.", RecordType::A).expect("the holder answers");
        assert_eq!(
            a_answer(&reply),
            holder_web,
            "the holder's own table still answers after a registrant exited"
        );

        // The holder's own status cell says what its loop decided the
        // machine's answerer is: this daemon, holding the port — the state
        // the control socket serves to the verbs that surface it.
        assert_eq!(
            holder_status_probe.get(),
            ZoneAnswererStatus::Holder { port },
            "the holder reports itself holding the machine's answerer port"
        );

        // And the second daemon's own acquisition loop — the way `run`
        // starts it, not the manual registration above — reports the state
        // it finds the machine in: another VM host daemon holds the port and
        // this table's rows answer through it. Its own registration keeps
        // the second VM's box name answering after the manual one exited,
        // which is the re-registration the loop's change pings ride.
        let second_channel = channel.clone();
        let second_status = AnswererStatus::starting();
        let second_status_probe = second_status.clone();
        std::thread::Builder::new()
            .name("test-zone-registrant".to_string())
            .spawn(move || acquire_loop_at(second, port, second_channel, second_status))
            .expect("the second daemon's thread spawns");
        assert_eq!(
            await_status(
                || second_status_probe.get(),
                "the second daemon never said what the machine's answerer is"
            ),
            ZoneAnswererStatus::Registered { port },
            "a daemon whose port is held by another VM host daemon reports its \
             rows answering through the holder"
        );
        let reply = query(port, "peer.min.internal.", RecordType::A)
            .expect("the second daemon's own registration answers");
        assert_eq!(
            a_answer(&reply),
            second_web,
            "the second daemon's own registration keeps its box name answering"
        );
    }

    /// A port held by a process with no channel — a native minimald, a
    /// foreign process — is the state the acquisition must name rather than
    /// paper over: the status says the port is held with nothing this VM's
    /// names answer through, which is what the CLI surfaces as "this VM's
    /// names are not answered on the host; the proxy remains the surface".
    #[test]
    fn a_port_held_with_no_channel_reports_it() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        // The channel is never bound: nothing answers a registration, the
        // shape of a native daemon's or a foreign process's hold.
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // The machine's answerer port, held by this test and nothing else.
        let held = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the hold binds loopback");
        let port = held.local_addr().expect("the hold names its port").port();
        let (registry, _) = web_registry();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        std::thread::Builder::new()
            .name("test-zone-answerer-no-channel".to_string())
            .spawn(move || acquire_loop_at(registry, port, channel, status))
            .expect("the answerer's thread spawns");
        assert_eq!(
            await_status(
                || probe.get(),
                "the answerer never said why this VM's names answer nothing"
            ),
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "a port held by a process with no channel is named as exactly that"
        );
    }

    /// The first registration still names its holder at info when an earlier
    /// pass warned: a daemon that boots against a port held by a process with
    /// no channel — a native minimald, a foreign squatter — and later finds a
    /// holder must announce that registration, because the diagnostics
    /// contract's one info line is this daemon's or its listener's, and the
    /// e2e's log greps read the info level. The warn's own once-only gate must
    /// not take the registration's with it. Driven without racing the port
    /// between two daemons: the foreign hold stays for the whole test, and it
    /// is the channel that comes up beside it — the holder's half is all a
    /// registration needs, so the daemon's next pass can only register, never
    /// bind.
    #[test]
    fn a_warned_daemon_announces_its_first_registration() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        // The global default, not the thread-local one the crate's other
        // captures use: the acquisition loop logs from its own thread. The
        // default `fmt` filter is info, so the registration's info line is
        // captured while the re-registration's debug line is not — the level
        // split this test is about.
        tracing::subscriber::set_global_default(subscriber)
            .expect("the capturing subscriber installs once per test process");

        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // A foreign hold on the answerer port — a plain socket, no channel
        // answering beside it — kept for the whole test, so every pass the
        // daemon makes finds the port held.
        let held = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the hold binds loopback");
        let port = held.local_addr().expect("the hold names its port").port();
        let (registry, _) = web_registry();
        // A clone shares the table and its change pings — the way a daemon's
        // other threads reach the one registry its answerer holds — so a
        // registration from here is a table change the loop is pinged for,
        // exactly the way a live daemon's own callers wake it.
        let pinger = registry.clone();
        let daemon_channel = channel.clone();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        std::thread::Builder::new()
            .name("test-zone-answerer-late-holder".to_string())
            .spawn(move || acquire_loop_at(registry, port, daemon_channel, status))
            .expect("the answerer's thread spawns");
        assert_eq!(
            await_status(
                || probe.get(),
                "the answerer never said why this VM's names answer nothing"
            ),
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "the first pass against a hold with no channel warns, exactly once"
        );

        // The holder comes up beside the hold: the channel alone, the half a
        // registration needs, while the foreign socket keeps the port.
        hold_channel(&channel, Arc::new(RegisteredTables::new()))
            .expect("the holder's channel binds beside the foreign hold");
        // A table change wakes the loop now, at its ping, rather than at the
        // port-recheck cadence — the way a live daemon's box registration
        // reaches the answerer — so the registration this test is about
        // happens inside the wait below, not the next half minute.
        pinger.register(BoxRegistration::new(
            "late",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::new(127, 0, 64, 11),
        ));

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let decided = probe.get();
            if decided == (ZoneAnswererStatus::Registered { port }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never registered with the holder that came up \
                 beside the hold (status: {decided:?})"
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // The registration that got through is the first, so it is the info
        // line naming the holder — on a line that names this test's channel,
        // so a co-resident test's own registration cannot speak for it — and
        // not the re-registration's debug line a warn-suppressed first
        // registration would have been left with.
        let log = buf.contents();
        assert!(
            log.lines().any(|line| {
                line.contains("registered this table's zone rows with it")
                    && line.contains(channel.to_string_lossy().as_ref())
            }),
            "the first registration after a warn must still name its holder \
             at info, got: {log}"
        );
    }
}
