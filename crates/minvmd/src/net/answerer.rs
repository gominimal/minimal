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
    /// hold is answered by this host's own row — and the rows other VM
    /// host daemons registered over the channel folded in on top, the
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
    let apex = Name::from_utf8(format!("{}.", zone_answer::ZONE_APEX))
        .expect("the zone apex parses");
    let mname = Name::from_utf8(format!("ns.{}.", zone_answer::ZONE_APEX))
        .expect("the SOA mname parses");
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
        let mut line = serde_json_lenient::to_string(&RegistrationRequest { rows }).map_err(|error| {
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
        let reply: RegistrationReply = serde_json_lenient::from_str(reply_line.trim()).map_err(
            |error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the holder's reply did not parse: {error}"),
                )
            },
        )?;
        if reply.ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                reply.error.unwrap_or_else(|| "the holder refused the registration".to_string()),
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
/// host-answerable address, and its liveness.
fn zone_rows(registry: &BoxRegistry) -> Vec<RegisteredRow> {
    registry
        .zone_view()
        .rows()
        .map(|(name, row)| RegisteredRow {
            name: name.to_string(),
            address: row.address,
            live: row.live,
        })
        .collect()
}

// ── the start ────────────────────────────────────────────────────────────────

/// Starts the host answerer: binds the machine's answerer port on the host
/// loopback and serves the zone from `registry`'s table, or — when the port
/// is held by another VM host daemon on this machine — registers
/// `registry`'s zone rows with that holder over the answerer channel and
/// answers nothing itself. One background thread, for the daemon's
/// lifetime, the way the control socket serves; a thread the host could not
/// spare is the only failure returned, because a held port is the normal
/// multi-VM case, not an error to fail a boot over.
///
/// # Errors
///
/// Returns the OS error when the thread cannot be spawned.
pub fn spawn(registry: BoxRegistry, port: u16) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("minvmd-zone-answerer".to_string())
        .spawn(move || acquire_loop(registry, port))
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
fn acquire_loop(registry: BoxRegistry, port: u16) {
    acquire_loop_at(registry, port, resolve_channel_sock());
}

/// The acquisition over a named channel socket, so the whole holder and
/// registrant machinery is drivable where the channel is not the machine's
/// own (the test below runs two daemons on one temporary channel).
fn acquire_loop_at(registry: BoxRegistry, port: u16, channel: PathBuf) {
    // Subscribed before the first bind attempt, so no change lands unpinged
    // in the window before the port is decided. The holder drops it: its
    // own table answers live, so it has nothing to re-register, and the
    // next ping prunes the dead sender.
    let pings = registry.subscribe_table_pings();
    let mut held: Option<Registration> = None;
    let mut warned = false;
    loop {
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(socket) => {
                drop(held);
                let addr = socket
                    .local_addr()
                    .map_or_else(|_| format!("127.0.0.1:{port}"), |addr| addr.to_string());
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
                let answerer =
                    HostAnswerer::new(registry.clone(), Arc::clone(&registered));
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
                let first = held.is_some() && !warned;
                match outcome {
                    Ok(()) if first => {
                        warned = true;
                        tracing::info!(
                            component = COMPONENT,
                            holder = %channel.display(),
                            rows = rows.len(),
                            "the zone answerer's port is held by another VM host daemon; \
                             registered this table's zone rows with it and answer nothing here"
                        );
                    }
                    Ok(()) => {
                        tracing::debug!(
                            component = COMPONENT,
                            holder = %channel.display(),
                            rows = rows.len(),
                            "re-registered this table's zone rows with the holder"
                        );
                    }
                    Err(error) if !warned => {
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
                    }
                    Err(error) => {
                        tracing::debug!(
                            component = COMPONENT,
                            %error,
                            "the holder's channel still did not answer"
                        );
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
