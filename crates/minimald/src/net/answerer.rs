//! The box-zone answerer: an always-on loopback DNS server for `min.internal`.
//!
//! The host OS routes the box zone to this answerer (an `/etc/resolver` file
//! with a `port` directive on macOS, a systemd-resolved routing domain on
//! Linux), so a browser or `curl` on the machine resolves `<box>.min.internal`
//! natively. The answerer holds only the zone — the live
//! [`PublishTable`](super::publish::PublishTable) the session actors publish
//! boxes into from finalize to destroy — and forwards nothing upstream: a
//! name outside the zone is `REFUSED`, never looked up.
//!
//! ## Answer semantics
//!
//! The rules the macOS loopback spike measured against `mDNSResponder`
//! (`docs/spikes/2026-09-22-macos-loopback-alias.md` §9):
//!
//! - An `A` lookup of a held name answers its address with [`ZONE_TTL`]
//!   (NET-126), and only a loopback address (NET-127): a box whose registered
//!   address is not local is answered NODATA rather than leaked.
//! - Any other type for a held name (`AAAA`, `HTTPS`, `SVCB`, …) is NODATA: an
//!   empty `NOERROR` (NET-124). Never NXDOMAIN, since negative caching is
//!   name-wide and browsers pair an `A` query with an `HTTPS` one.
//! - A held name whose box answers no address right now — a shared-address
//!   box that is not running (NET-128) — is NODATA too: the name stays in
//!   the zone, so the resolver caches no name-wide negative for it.
//! - A name in the zone that nothing holds is NXDOMAIN (NET-125), which is
//!   what a destroyed box's name answers from then on (NET-012).
//! - Every negative carries the zone's SOA in its authority section (RFC 2308).
//!   The spike found that an answerer whose negatives lack it stalls every
//!   lookup on a macOS host, scoped or not, for the resolver's timeout per
//!   query, and a resolver reload does not clear it.
//! - The resolver's discovery probe (`_dns.resolver.arpa`, RFC 9462) is
//!   answered NODATA like any other non-`A` lookup, so the probe resolves at
//!   once instead of timing out.
//!
//! ## Who is answered
//!
//! Only lookups from the machine itself (NET-006). The socket is bound to
//! loopback when the answerer binds it, and a lookup whose peer is not a
//! loopback address is dropped unanswered either way, so a socket inherited
//! from the service manager with a wider bind still serves nothing off-host.
//!
//! ## Host resolution state
//!
//! Whether the host actually routes the zone here is the host's business,
//! not the answerer's, but the answerer is where the daemon reads it
//! ([`HostResolution`]): the resolver hook's presence (the dedicated
//! systemd-resolved link on Linux) and NET-123's bind probe over the reserved
//! local range (`127.0.64.0/24`). A session start reports both to the client
//! as the resolver advisory (NET-122); while the range is absent boxes are
//! published at the `127.0.0.1` interim ([`interim_address`]).
//!
//! ## Zone dump
//!
//! The answerer mirrors the zone to `<state>/net/zone.json` (see
//! [`zone_dump_path`]) on start and after every change to the table: every
//! name, its address and lease state, its published ports with collisions
//! marked, the daemon that owns it, the listener's socket, and the host
//! resolution state above. The `min bug` bundle carries that file.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{BorrowedFd, FromRawFd as _, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use minimald_rpc::ResolverAdvisory;
use serde::Serialize;
use tokio::net::UdpSocket;

use sessions::SessionId;

use super::dns::HOSTNAME_SUFFIX;
use super::policy::BoxZone;
use super::publish::{AddressKind, Lookup, PortCollision, PublishTable, Zone};

/// The port the box zone is answered on, the one the host resolver hook names
/// (`port 15353` in the macOS resolver file the spike installed). The wire
/// crate holds the number, since the client's setup command writes it.
pub const ANSWERER_PORT: u16 = minimald_rpc::ANSWERER_PORT;

/// Where the answerer binds when the service manager did not hand it a socket:
/// loopback only, so nothing off the host can reach it (NET-006).
pub const BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ANSWERER_PORT);

/// TTL on every record the zone answers, and the negative-cache TTL its SOA
/// advertises (NET-126: at most 15 s). Short so a destroyed box's name stops
/// resolving promptly and a re-published address is picked up.
pub const ZONE_TTL: u32 = 15;

/// The zone apex: the suffix every box name carries.
pub const ZONE_APEX: &str = HOSTNAME_SUFFIX;

/// The resolver discovery name (RFC 9462) the macOS resolver probes a
/// configured server with, before and alongside the zone's own lookups.
const DDR_PROBE: &str = "_dns.resolver.arpa";

/// Largest datagram read off the socket. A DNS query with EDNS fits in far
/// less; anything longer is not a query this zone answers.
const MAX_MESSAGE: usize = 4096;
const HEADER_LEN: usize = 12;
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 253;

/// `A` record type.
pub const TYPE_A: u16 = 1;
/// `SOA` record type.
pub const TYPE_SOA: u16 = 6;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

const FLAG_QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const FLAG_AA: u16 = 0x0400;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

/// The SOA the zone advertises. The names are nominal (nothing serves the
/// zone by NS); the timers matter only to a secondary, which the zone has
/// none of; `minimum` is the negative-cache TTL.
const SOA_MNAME: &str = "ns.min.internal";
const SOA_RNAME: &str = "hostmaster.min.internal";
const SOA_SERIAL: u32 = 1;
const SOA_REFRESH: u32 = 3600;
const SOA_RETRY: u32 = 600;
const SOA_EXPIRE: u32 = 86400;

/// The systemd socket-activation convention: inherited sockets start at fd 3
/// (`sd_listen_fds(3)`).
const SD_LISTEN_FDS_START: RawFd = 3;

/// The class of answer a lookup got: the per-lookup log field, and the
/// response code it maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A record was answered: an `A` for a held name, or the apex `SOA`.
    Answer,
    /// The name exists but holds no record of the asked type (NET-124), or
    /// its box answers no address while it is not running (NET-128): an
    /// empty `NOERROR` with the zone's SOA in the authority section.
    NoData,
    /// No box or node holds the name: `NXDOMAIN` with the zone's SOA in the
    /// authority section (NET-125).
    NxDomain,
    /// The name is outside the zone, or the class is not `IN`: `REFUSED`, and
    /// nothing is forwarded.
    Refused,
    /// An opcode other than a standard query.
    NotImplemented,
    /// The message could not be parsed as a single-question query.
    FormErr,
}

impl Verdict {
    fn rcode(self) -> u16 {
        match self {
            Self::Answer | Self::NoData => 0,
            Self::FormErr => 1,
            Self::NxDomain => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
        }
    }
}

/// A reply the answerer built for one query: the wire bytes to send back and
/// what they say, for the per-lookup log line.
#[derive(Debug)]
pub struct Reply {
    pub bytes: Vec<u8>,
    /// The queried name, lower-cased, without the trailing dot. Empty when the
    /// question could not be parsed.
    pub name: String,
    pub qtype: u16,
    pub verdict: Verdict,
}

/// What goes after the question in a reply.
#[derive(Debug, Clone, Copy)]
enum Body {
    /// No answer and no authority: `REFUSED`, `NOTIMP`, `FORMERR`.
    Empty,
    /// One `A` record for the queried name.
    A(Ipv4Addr),
    /// The zone's SOA as the answer (an `SOA` lookup of the apex).
    ApexSoa,
    /// The zone's SOA in the authority section (NODATA and NXDOMAIN).
    NegativeSoa,
}

/// The one question a query carries.
struct Question<'a> {
    id: u16,
    flags: u16,
    name: String,
    qtype: u16,
    qclass: u16,
    /// The question section verbatim, echoed into the reply.
    wire: &'a [u8],
}

/// Why a message yielded no [`Question`].
#[derive(Clone, Copy)]
enum Malformed {
    /// Not a query at all (too short, or a response): nothing to reply to.
    Drop,
    /// A query whose question cannot be read: answered `FORMERR` so the
    /// resolver does not wait on it.
    FormErr { id: u16, flags: u16 },
}

fn be16(msg: &[u8], at: usize) -> Option<u16> {
    let bytes = msg.get(at..at + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_question(msg: &[u8]) -> Result<Question<'_>, Malformed> {
    if msg.len() < HEADER_LEN {
        return Err(Malformed::Drop);
    }
    let id = be16(msg, 0).ok_or(Malformed::Drop)?;
    let flags = be16(msg, 2).ok_or(Malformed::Drop)?;
    if flags & FLAG_QR != 0 {
        return Err(Malformed::Drop);
    }
    let formerr = Malformed::FormErr { id, flags };
    if be16(msg, 4) != Some(1) {
        return Err(formerr);
    }
    let mut off = HEADER_LEN;
    let mut name = String::new();
    loop {
        let len = usize::from(*msg.get(off).ok_or(formerr)?);
        off += 1;
        if len == 0 {
            break;
        }
        // Also rejects compression pointers (0xC0..), which a question never
        // legitimately carries.
        if len > MAX_LABEL {
            return Err(formerr);
        }
        let label = msg.get(off..off + len).ok_or(formerr)?;
        off += len;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&b| char::from(b).to_ascii_lowercase()));
        if name.len() > MAX_NAME {
            return Err(formerr);
        }
    }
    let qtype = be16(msg, off).ok_or(formerr)?;
    let qclass = be16(msg, off + 2).ok_or(formerr)?;
    Ok(Question {
        id,
        flags,
        name,
        qtype,
        qclass,
        wire: &msg[HEADER_LEN..off + 4],
    })
}

/// Whether `name` (lower-cased, no trailing dot) is under the zone apex.
fn in_zone(name: &str) -> bool {
    name.strip_suffix(ZONE_APEX)
        .is_some_and(|head| head.ends_with('.'))
}

fn is_ddr_probe(name: &str) -> bool {
    name == DDR_PROBE || name.ends_with("._dns.resolver.arpa")
}

/// NET-127: the host answerer gives out loopback addresses only — `127.0.0.1`,
/// the reserved local range, and a node's allocated address are all loopback.
/// Anything else a zone carries (a switch address, an IPv6 target) is
/// withheld, and the name answers NODATA instead.
fn local_answer(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => Some(v4),
        _ => None,
    }
}

fn decide(zone: &impl Zone, q: &Question<'_>) -> (Verdict, Body) {
    if q.flags & OPCODE_MASK != 0 {
        return (Verdict::NotImplemented, Body::Empty);
    }
    if q.qclass != CLASS_IN && q.qclass != CLASS_ANY {
        return (Verdict::Refused, Body::Empty);
    }
    let name = q.name.as_str();
    if name == ZONE_APEX {
        return if q.qtype == TYPE_SOA {
            (Verdict::Answer, Body::ApexSoa)
        } else {
            (Verdict::NoData, Body::NegativeSoa)
        };
    }
    if is_ddr_probe(name) {
        return (Verdict::NoData, Body::NegativeSoa);
    }
    if !in_zone(name) {
        return (Verdict::Refused, Body::Empty);
    }
    match zone.lookup(name) {
        Lookup::Unknown => (Verdict::NxDomain, Body::NegativeSoa),
        Lookup::Address(ip) if q.qtype == TYPE_A => match local_answer(ip) {
            Some(v4) => (Verdict::Answer, Body::A(v4)),
            None => (Verdict::NoData, Body::NegativeSoa),
        },
        Lookup::Address(_) | Lookup::Held => (Verdict::NoData, Body::NegativeSoa),
    }
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes `name` in wire form (length-prefixed labels, root terminator).
fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        // Every name pushed here is a compile-time constant under MAX_LABEL.
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Writes an SOA record's type, class, TTL and rdata after an owner name.
fn push_soa(out: &mut Vec<u8>) {
    push_u16(out, TYPE_SOA);
    push_u16(out, CLASS_IN);
    push_u32(out, ZONE_TTL);
    let rdlength_at = out.len();
    push_u16(out, 0);
    push_name(out, SOA_MNAME);
    push_name(out, SOA_RNAME);
    push_u32(out, SOA_SERIAL);
    push_u32(out, SOA_REFRESH);
    push_u32(out, SOA_RETRY);
    push_u32(out, SOA_EXPIRE);
    push_u32(out, ZONE_TTL);
    let rdlength = (out.len() - rdlength_at - 2) as u16;
    out[rdlength_at..rdlength_at + 2].copy_from_slice(&rdlength.to_be_bytes());
}

fn encode(id: u16, query_flags: u16, question: &[u8], verdict: Verdict, body: Body) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + 96);
    // QR|AA, RD copied from the query, RA set: the flag set the spike measured
    // `mDNSResponder` against; the answerer recurses for nothing regardless.
    let flags = FLAG_QR | FLAG_AA | FLAG_RA | (query_flags & FLAG_RD) | verdict.rcode();
    let (ancount, nscount) = match body {
        Body::Empty => (0, 0),
        Body::A(_) | Body::ApexSoa => (1, 0),
        Body::NegativeSoa => (0, 1),
    };
    push_u16(&mut out, id);
    push_u16(&mut out, flags);
    push_u16(&mut out, u16::from(!question.is_empty()));
    push_u16(&mut out, ancount);
    push_u16(&mut out, nscount);
    push_u16(&mut out, 0);
    out.extend_from_slice(question);
    match body {
        Body::Empty => {}
        Body::A(v4) => {
            // Owner: a pointer to the question name at offset 12.
            out.extend_from_slice(&[0xC0, 0x0C]);
            push_u16(&mut out, TYPE_A);
            push_u16(&mut out, CLASS_IN);
            push_u32(&mut out, ZONE_TTL);
            push_u16(&mut out, 4);
            out.extend_from_slice(&v4.octets());
        }
        Body::ApexSoa => {
            // The question name is the apex, so the pointer names it.
            out.extend_from_slice(&[0xC0, 0x0C]);
            push_soa(&mut out);
        }
        Body::NegativeSoa => {
            push_name(&mut out, ZONE_APEX);
            push_soa(&mut out);
        }
    }
    out
}

/// Answers one query datagram from the zone, or `None` when `msg` is not a
/// query to answer at all (too short, or itself a response). Pure over the
/// zone: the socket path and the tests both call this.
#[must_use]
pub fn answer(zone: &impl Zone, msg: &[u8]) -> Option<Reply> {
    let q = match parse_question(msg) {
        Ok(q) => q,
        Err(Malformed::Drop) => return None,
        Err(Malformed::FormErr { id, flags }) => {
            return Some(Reply {
                bytes: encode(id, flags, &[], Verdict::FormErr, Body::Empty),
                name: String::new(),
                qtype: 0,
                verdict: Verdict::FormErr,
            });
        }
    };
    let (verdict, body) = decide(zone, &q);
    Some(Reply {
        bytes: encode(q.id, q.flags, q.wire, verdict, body),
        name: q.name,
        qtype: q.qtype,
        verdict,
    })
}

/// NET-006: whether a lookup's peer is on this machine. A dual-stack socket
/// reports a loopback IPv4 peer as an IPv4-mapped IPv6 address.
#[must_use]
pub fn on_host(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// The reserved local range's prefix: `127.0.64.0/24`
/// ([`minimald_rpc::RESERVED_RANGE`], design §7.1).
const RESERVED_RANGE_PREFIX: [u8; 3] = [127, 0, 64];

/// Every address a box can be published at from the reserved local range:
/// `127.0.64.1` to `127.0.64.254`.
pub fn reserved_range() -> impl Iterator<Item = Ipv4Addr> {
    let [a, b, c] = RESERVED_RANGE_PREFIX;
    (1..=254).map(move |host| Ipv4Addr::new(a, b, c, host))
}

/// What the bind probe found of the reserved local range (NET-123).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RangeProbe {
    /// Every address in the range bound.
    Present,
    /// An address did not bind: the range is not on the host's loopback, in
    /// full or in part.
    Absent { address: Ipv4Addr, error: String },
}

impl RangeProbe {
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present)
    }

    /// The gap the advisory names: `<address>: <error>`.
    #[must_use]
    pub fn gap(&self) -> Option<String> {
        match self {
            Self::Present => None,
            Self::Absent { address, error } => Some(format!("{address}: {error}")),
        }
    }
}

/// NET-123's bind probe: binds an ephemeral TCP port on each address in turn
/// and reports the first that refuses. Every address is probed rather than a
/// sample — a partial alias set would otherwise let a box be published at an
/// address that hangs — and it is cheap: an absent alias fails `bind` with
/// `EADDRNOTAVAIL` in microseconds (the loopback spike measured 2.5 ms for
/// the whole range). Each listener is dropped before the next bind, so
/// nothing is held.
pub fn probe_range(addrs: impl IntoIterator<Item = Ipv4Addr>) -> RangeProbe {
    for address in addrs {
        if let Err(error) = std::net::TcpListener::bind((address, 0)) {
            return RangeProbe::Absent {
                address,
                error: error.to_string(),
            };
        }
    }
    RangeProbe::Present
}

/// The bind probe over the whole reserved local range.
#[must_use]
pub fn probe_reserved_range() -> RangeProbe {
    probe_range(reserved_range())
}

/// The address a box is published at while the reserved range is absent
/// (NET-123's failure case): `127.0.0.1`, the one loopback address every
/// host has. `None` while the range is present, when a box takes an address
/// of its own from it.
#[must_use]
pub fn interim_address(probe: &RangeProbe) -> Option<Ipv4Addr> {
    match probe {
        RangeProbe::Present => None,
        RangeProbe::Absent { .. } => Some(Ipv4Addr::LOCALHOST),
    }
}

/// Where the Linux resolver hook shows: the dedicated link the advisory's
/// command creates and systemd-resolved routes the zone on
/// ([`minimald_rpc::RESOLVER_LINK`]) appears here once it exists.
const SYSFS_NET: &str = "/sys/class/net";

/// Whether the host resolver routes the box zone to this answerer.
#[must_use]
pub fn resolver_hook_configured() -> bool {
    resolver_hook_configured_in(Path::new(SYSFS_NET))
}

fn resolver_hook_configured_in(sysfs_net: &Path) -> bool {
    sysfs_net.join(minimald_rpc::RESOLVER_LINK).exists()
}

/// What the box host knows of native resolution: read at every session start
/// (NET-122, NET-123) and written into the zone dump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostResolution {
    /// Whether the host resolver routes the zone to the answerer.
    pub resolver_configured: bool,
    /// The bind probe's result over the reserved local range.
    pub range: RangeProbe,
}

impl HostResolution {
    /// Reads both halves from the host now.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            resolver_configured: resolver_hook_configured(),
            range: probe_reserved_range(),
        }
    }

    /// The surface boxes are published on under this state, for the log.
    #[must_use]
    pub fn surface(&self) -> &'static str {
        if self.range.is_present() {
            "reserved range"
        } else {
            "127.0.0.1 (interim)"
        }
    }

    /// The advisory a session start reply carries: present whenever either
    /// half is missing, every time it is asked — a host still on the
    /// interim is told again at each start, there is no once-only latch —
    /// and nothing when native resolution is in place.
    #[must_use]
    pub fn advisory(&self) -> Option<ResolverAdvisory> {
        let range_present = self.range.is_present();
        (!self.resolver_configured || !range_present).then(|| ResolverAdvisory {
            resolver_configured: self.resolver_configured,
            range_present,
            range_gap: self.range.gap(),
        })
    }
}

/// Where the answerer's socket came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SocketSource {
    /// Inherited from the service manager (systemd socket activation).
    ServiceManager,
    /// Bound by the daemon at [`BIND_ADDR`].
    Bound,
}

/// The answerer's socket and where it came from.
#[derive(Debug)]
pub struct Listener {
    pub socket: UdpSocket,
    pub source: SocketSource,
}

/// The datagram socket the service manager passed to this process, if any:
/// `LISTEN_PID` names this process and `LISTEN_FDS` counts fds from 3
/// (`sd_listen_fds(3)`). A first fd that is not a datagram socket is left
/// alone for whatever it was meant for.
fn inherited_socket() -> Option<std::net::UdpSocket> {
    let pid = std::env::var("LISTEN_PID").ok()?;
    if pid.trim().parse::<u32>().ok() != Some(std::process::id()) {
        return None;
    }
    let fds: u32 = std::env::var("LISTEN_FDS").ok()?.trim().parse().ok()?;
    if fds == 0 {
        return None;
    }
    let fd = SD_LISTEN_FDS_START;
    // SAFETY: the service manager handed fd 3 to this process (LISTEN_PID
    // matched) and it stays open for the lifetime of this borrow.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    match nix::sys::socket::getsockopt(&borrowed, nix::sys::socket::sockopt::SockType) {
        Ok(nix::sys::socket::SockType::Datagram) => {}
        Ok(kind) => {
            tracing::warn!(
                ?kind,
                "inherited fd 3 is not a datagram socket; binding instead"
            );
            return None;
        }
        Err(error) => {
            tracing::warn!(%error, "inherited fd 3 is not a socket; binding instead");
            return None;
        }
    }
    // SAFETY: fd 3 is a datagram socket this process owns, claimed exactly
    // once here.
    Some(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

/// The answerer's socket: the service manager's when it passed one, else a
/// fresh loopback bind at [`BIND_ADDR`].
pub async fn listen() -> io::Result<Listener> {
    if let Some(socket) = inherited_socket() {
        socket.set_nonblocking(true)?;
        return Ok(Listener {
            socket: UdpSocket::from_std(socket)?,
            source: SocketSource::ServiceManager,
        });
    }
    Ok(Listener {
        socket: UdpSocket::bind(BIND_ADDR).await?,
        source: SocketSource::Bound,
    })
}

/// Where the zone dump lives under the daemon's state dir.
#[must_use]
pub fn zone_dump_path(state_dir: &Path) -> PathBuf {
    state_dir.join("net").join("zone.json")
}

/// The zone as the answerer serves it, written for the diagnostics bundle.
#[derive(Debug, Serialize)]
struct ZoneDump {
    zone: &'static str,
    ttl_secs: u32,
    listener: ListenerInfo,
    /// The resolver hook and the range probe as the bundle should see them.
    host: HostResolution,
    names: Vec<ZoneEntry>,
    /// The in-guest half of the same zone: what the node's DNS layer answers a
    /// box with for a sibling (NET-072). Switch leases, so none of them is an
    /// address this answerer would give a lookup on the host (NET-127) — the
    /// two halves answer one name differently on purpose, and a box-to-box
    /// refusal is read against these entries, not the host's.
    in_guest: Vec<GuestEntry>,
}

#[derive(Debug, Serialize)]
struct ListenerInfo {
    address: IpAddr,
    port: u16,
    socket: SocketSource,
}

#[derive(Debug, Serialize)]
struct ZoneEntry {
    name: String,
    address: Ipv4Addr,
    /// The daemon that published the name.
    owner: String,
    session_id: SessionId,
    /// Whether the address is the box's own lease or the node's shared one.
    kind: AddressKind,
    /// The lease state: a shared-address box answers only while running.
    running: bool,
    /// The box's own port numbers, published untranslated.
    ports: Vec<u16>,
    /// The ports another box on the same shared address also publishes.
    collisions: Vec<PortCollision>,
}

/// One in-guest box-zone entry: the switch lease a sibling's name resolves to
/// inside boxes, and the ports that box's ingress declares — the target half of
/// a box-to-box verdict (NET-073), so a refused connection can be read here.
#[derive(Debug, Serialize)]
struct GuestEntry {
    name: String,
    address: Ipv4Addr,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
}

fn snapshot(
    zone: &RwLock<PublishTable>,
    box_zone: &BoxZone,
    daemon_id: &str,
    local: SocketAddr,
    source: SocketSource,
) -> ZoneDump {
    let guard = zone.read().unwrap_or_else(PoisonError::into_inner);
    let names: Vec<ZoneEntry> = guard
        .entries()
        .into_iter()
        .map(|b| ZoneEntry {
            name: b.hostname,
            address: b.address,
            owner: daemon_id.to_string(),
            session_id: b.session_id,
            kind: b.kind,
            running: b.running,
            ports: b.ports,
            collisions: b.collisions,
        })
        .collect();
    let in_guest = box_zone
        .entries()
        .into_iter()
        .map(|entry| GuestEntry {
            name: entry.name(),
            address: entry.lease,
            tcp_ports: entry.tcp_ports.into_iter().collect(),
            udp_ports: entry.udp_ports.into_iter().collect(),
        })
        .collect();
    ZoneDump {
        zone: ZONE_APEX,
        ttl_secs: ZONE_TTL,
        listener: ListenerInfo {
            address: local.ip(),
            port: local.port(),
            socket: source,
        },
        host: HostResolution::probe(),
        names,
        in_guest,
    }
}

/// Writes the dump atomically (temp file + rename) so a bundle never reads a
/// half-written one.
async fn write_dump(path: &Path, dump: &ZoneDump) -> io::Result<()> {
    let json = serde_json_lenient::to_vec_pretty(dump).map_err(io::Error::other)?;
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, json).await?;
    tokio::fs::rename(&tmp, path).await
}

async fn refresh_dump(
    zone: &RwLock<PublishTable>,
    box_zone: &BoxZone,
    daemon_id: &str,
    local: SocketAddr,
    source: SocketSource,
    path: &Path,
) {
    let dump = snapshot(zone, box_zone, daemon_id, local, source);
    if let Err(error) = write_dump(path, &dump).await {
        tracing::warn!(%error, path = %path.display(), "could not write the zone dump");
    }
}

/// Serves the zone on `listener` until the socket errors: answers each on-host
/// lookup from `zone`, drops off-host ones unanswered, and keeps the zone dump
/// at `dump_path` current.
///
/// `box_zone` is not answered from — a lookup on the host is answered from the
/// published table alone, and only with a local address (NET-127) — but it is
/// dumped beside it, so a bundle shows what a box resolves a sibling to as well
/// as what the host does.
pub async fn serve(
    listener: Listener,
    zone: Arc<RwLock<PublishTable>>,
    box_zone: Arc<BoxZone>,
    daemon_id: String,
    dump_path: PathBuf,
) -> io::Result<()> {
    let Listener { socket, source } = listener;
    let local = socket.local_addr()?;
    let changes = zone
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .changes();
    tracing::info!(address = %local, socket = ?source, "box-zone answerer listening");
    refresh_dump(&zone, &box_zone, &daemon_id, local, source, &dump_path).await;

    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        tokio::select! {
            () = changes.notified() => {
                refresh_dump(&zone, &box_zone, &daemon_id, local, source, &dump_path).await;
            }
            received = socket.recv_from(&mut buf) => {
                let (len, peer) = received?;
                if !on_host(peer.ip()) {
                    tracing::warn!(%peer, "refused a box-zone lookup from off the host");
                    continue;
                }
                let Some(reply) = answer(&*zone, &buf[..len]) else {
                    continue;
                };
                tracing::debug!(
                    %peer,
                    name = %reply.name,
                    qtype = reply.qtype,
                    verdict = ?reply.verdict,
                    "answered a box-zone lookup"
                );
                if let Err(error) = socket.send_to(&reply.bytes, peer).await {
                    tracing::warn!(%error, %peer, "could not send a box-zone reply");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use sessions::NetworkMode;

    use super::*;

    const TYPE_TXT: u16 = 16;
    const TYPE_AAAA: u16 = 28;
    const TYPE_SVCB: u16 = 64;
    const TYPE_HTTPS: u16 = 65;
    const TYPE_ANY: u16 = 255;
    const RCODE_MASK: u16 = 0x000F;

    /// A zone holding `<session>.min.internal` for each box, published in
    /// the given mode and running: a host-address box at `127.0.0.1`, an
    /// own-address box at the next free address of the reserved range.
    fn zone(boxes: &[(&str, NetworkMode)]) -> Arc<RwLock<PublishTable>> {
        let mut table = PublishTable::default();
        for (session, mode) in boxes {
            table
                .publish(SessionId::nil(), session, *mode, &[])
                .unwrap();
            table.set_running(session, true);
        }
        Arc::new(RwLock::new(table))
    }

    /// A zone answering fixed addresses, including ones the table can never
    /// hold, for the answerer's own confinement rule.
    struct FixedZone(HashMap<String, IpAddr>);

    impl Zone for FixedZone {
        fn lookup(&self, name: &str) -> Lookup {
            self.0
                .get(name)
                .map_or(Lookup::Unknown, |ip| Lookup::Address(*ip))
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// A standard query (RD set) for `name`/`qtype` in class IN.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        query_in_class(name, qtype, CLASS_IN)
    }

    fn query_in_class(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut out = Vec::new();
        push_u16(&mut out, 0x1234);
        push_u16(&mut out, FLAG_RD);
        push_u16(&mut out, 1);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_name(&mut out, name);
        push_u16(&mut out, qtype);
        push_u16(&mut out, qclass);
        out
    }

    #[derive(Debug)]
    struct Rr {
        name: String,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    }

    #[derive(Debug)]
    struct Parsed {
        id: u16,
        flags: u16,
        question: Option<(String, u16, u16)>,
        answers: Vec<Rr>,
        authority: Vec<Rr>,
        additional: u16,
    }

    impl Parsed {
        fn rcode(&self) -> u16 {
            self.flags & RCODE_MASK
        }
    }

    /// Reads a possibly-compressed name at `off`; returns it and the offset
    /// just past it in the containing section.
    fn read_name(msg: &[u8], mut off: usize) -> (String, usize) {
        let mut labels = Vec::new();
        let mut end = None;
        loop {
            let len = msg[off];
            if len & 0xC0 == 0xC0 {
                let ptr = usize::from(u16::from_be_bytes([len & 0x3F, msg[off + 1]]));
                end.get_or_insert(off + 2);
                off = ptr;
                continue;
            }
            off += 1;
            if len == 0 {
                break;
            }
            let len = usize::from(len);
            labels.push(String::from_utf8(msg[off..off + len].to_vec()).unwrap());
            off += len;
        }
        (labels.join("."), end.unwrap_or(off))
    }

    fn read_rrs(msg: &[u8], mut off: usize, count: u16) -> (Vec<Rr>, usize) {
        let mut rrs = Vec::new();
        for _ in 0..count {
            let (name, next) = read_name(msg, off);
            off = next;
            let rtype = be16(msg, off).unwrap();
            let class = be16(msg, off + 2).unwrap();
            let ttl = u32::from_be_bytes(msg[off + 4..off + 8].try_into().unwrap());
            let rdlength = usize::from(be16(msg, off + 8).unwrap());
            off += 10;
            let rdata = msg[off..off + rdlength].to_vec();
            off += rdlength;
            rrs.push(Rr {
                name,
                rtype,
                class,
                ttl,
                rdata,
            });
        }
        (rrs, off)
    }

    fn parse_reply(msg: &[u8]) -> Parsed {
        let id = be16(msg, 0).unwrap();
        let flags = be16(msg, 2).unwrap();
        let qdcount = be16(msg, 4).unwrap();
        let ancount = be16(msg, 6).unwrap();
        let nscount = be16(msg, 8).unwrap();
        let additional = be16(msg, 10).unwrap();
        let mut off = HEADER_LEN;
        let mut question = None;
        if qdcount == 1 {
            let (name, next) = read_name(msg, off);
            question = Some((name, be16(msg, next).unwrap(), be16(msg, next + 2).unwrap()));
            off = next + 4;
        }
        let (answers, off) = read_rrs(msg, off, ancount);
        let (authority, off) = read_rrs(msg, off, nscount);
        assert_eq!(off, msg.len(), "reply has trailing bytes: {msg:02x?}");
        Parsed {
            id,
            flags,
            question,
            answers,
            authority,
            additional,
        }
    }

    /// The SOA rdata's `minimum` field: the negative-cache TTL.
    fn soa_minimum(rdata: &[u8]) -> u32 {
        let (_, off) = read_name(rdata, 0);
        let (_, off) = read_name(rdata, off);
        u32::from_be_bytes(rdata[off + 16..off + 20].try_into().unwrap())
    }

    fn reply(zone: &RwLock<PublishTable>, name: &str, qtype: u16) -> Parsed {
        let reply = answer(zone, &query(name, qtype)).expect("a query is answered");
        parse_reply(&reply.bytes)
    }

    /// Asserts `parsed` is a negative with exactly the zone's SOA as its
    /// authority and nothing else.
    fn assert_zone_authority(parsed: &Parsed, what: &str) {
        assert!(
            parsed.answers.is_empty(),
            "{what}: answers {:?}",
            parsed.answers
        );
        assert_eq!(
            parsed.authority.len(),
            1,
            "{what}: authority {:?}",
            parsed.authority
        );
        let soa = &parsed.authority[0];
        assert_eq!(soa.name, ZONE_APEX, "{what}: SOA owner");
        assert_eq!(soa.rtype, TYPE_SOA, "{what}: SOA type");
        assert_eq!(soa.class, CLASS_IN, "{what}: SOA class");
        let (mname, off) = read_name(&soa.rdata, 0);
        let (rname, _) = read_name(&soa.rdata, off);
        assert_eq!(mname, SOA_MNAME, "{what}: SOA mname");
        assert_eq!(rname, SOA_RNAME, "{what}: SOA rname");
        assert_eq!(parsed.additional, 0, "{what}: additional");
    }

    /// Sends `query` to a serving answerer over loopback and returns the reply.
    async fn ask(server: SocketAddr, query: &[u8]) -> Vec<u8> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(query, server).await.unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE];
        let len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("the answerer replies")
            .unwrap();
        buf.truncate(len);
        buf
    }

    /// Starts `serve` on an ephemeral loopback port with `zone`, the in-guest
    /// `box_zone` it dumps beside it, and a dump under `state`; returns the
    /// address to query once the answerer has answered a probe, which it does
    /// only after writing its first dump.
    async fn spawn_answerer(
        zone: Arc<RwLock<PublishTable>>,
        box_zone: Arc<BoxZone>,
        state: &Path,
    ) -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(socket).unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = Listener {
            socket,
            source: SocketSource::Bound,
        };
        tokio::spawn(serve(
            listener,
            zone,
            box_zone,
            "d0".to_string(),
            zone_dump_path(state),
        ));
        let _ = ask(addr, &query("min.internal", TYPE_SOA)).await;
        addr
    }

    async fn read_dump(path: &Path) -> serde_json_lenient::Value {
        let text = tokio::fs::read_to_string(path).await.unwrap();
        serde_json_lenient::from_str(&text).unwrap()
    }

    /// NET-006: only lookups that originate on the machine are answered. The
    /// bind target is loopback, a peer off the host is refused before any
    /// answer is built, and a loopback peer is served over a real socket.
    #[tokio::test]
    async fn min_internal_zone_not_served_off_host() {
        assert!(BIND_ADDR.ip().is_loopback(), "the answerer binds loopback");

        for peer in [
            v4(127, 0, 0, 1),
            v4(127, 0, 64, 10),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ] {
            assert!(on_host(peer), "{peer} is on the host");
        }
        for peer in [
            v4(10, 0, 0, 5),
            v4(192, 168, 1, 2),
            v4(100, 64, 0, 1),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped()),
        ] {
            assert!(!on_host(peer), "{peer} is off the host and gets nothing");
        }

        let state = tempfile::TempDir::new().unwrap();
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        let server = spawn_answerer(zone, Arc::new(BoxZone::default()), state.path()).await;
        let parsed = parse_reply(&ask(server, &query("web.min.internal", TYPE_A)).await);
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.rcode(), 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rdata, Ipv4Addr::LOCALHOST.octets());
    }

    /// NET-007: nothing the answerer emits or writes names a box-zone name in
    /// a certificate or an audit record. Over a full lookup mix its only
    /// artefact on disk is the zone dump, and nothing it produces carries
    /// certificate material; the daemon mints no certificate of its own.
    #[tokio::test]
    async fn min_internal_absent_from_certs_and_audit() {
        let state = tempfile::TempDir::new().unwrap();
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        let server = spawn_answerer(zone, Arc::new(BoxZone::default()), state.path()).await;
        let mut replies = Vec::new();
        for (name, qtype) in [
            ("web.min.internal", TYPE_A),
            ("web.min.internal", TYPE_AAAA),
            ("web.min.internal", TYPE_HTTPS),
            ("ghost.min.internal", TYPE_A),
            ("min.internal", TYPE_SOA),
            ("example.com", TYPE_A),
        ] {
            replies.extend(ask(server, &query(name, qtype)).await);
        }
        // Wait for the last reply's dump write to settle, then inventory.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut written = Vec::new();
        for entry in walkdir::WalkDir::new(state.path()) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                written.push(
                    entry
                        .path()
                        .strip_prefix(state.path())
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        assert_eq!(
            written,
            vec!["net/zone.json".to_string()],
            "the answerer writes the zone dump and no audit record"
        );
        let dump = std::fs::read_to_string(state.path().join("net/zone.json")).unwrap();
        for text in [dump.as_str(), &String::from_utf8_lossy(&replies)] {
            assert!(
                !text.contains("-----BEGIN") && !text.contains("CERTIFICATE"),
                "no certificate material in what the answerer produces"
            );
        }
    }

    /// NET-124: a held name asked for anything but `A` is NODATA — an empty
    /// NOERROR with the zone's SOA — never NXDOMAIN, whatever the type.
    #[test]
    fn non_a_in_zone_query_is_nodata() {
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        for qtype in [
            TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB, TYPE_TXT, TYPE_ANY, TYPE_SOA,
        ] {
            let parsed = reply(&zone, "web.min.internal", qtype);
            assert_eq!(parsed.rcode(), 0, "type {qtype}: NOERROR");
            assert_zone_authority(&parsed, &format!("type {qtype}"));
        }
        // The A lookup of the same name still answers, so NODATA above was
        // about the type and not the name.
        let parsed = reply(&zone, "web.min.internal", TYPE_A);
        assert_eq!(parsed.answers.len(), 1);
    }

    /// NET-125: a name in the zone that no box holds is NXDOMAIN, including a
    /// name whose box has since been withdrawn.
    #[test]
    fn unknown_in_zone_name_is_nxdomain() {
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        for name in [
            "ghost.min.internal",
            "web.other.min.internal",
            "deep.web.min.internal",
        ] {
            let parsed = reply(&zone, name, TYPE_A);
            assert_eq!(parsed.rcode(), 3, "{name}: NXDOMAIN");
            assert_zone_authority(&parsed, name);
        }
        assert_eq!(reply(&zone, "Web.MIN.internal", TYPE_A).rcode(), 0);

        zone.write().unwrap().withdraw("web");
        let parsed = reply(&zone, "web.min.internal", TYPE_A);
        assert_eq!(parsed.rcode(), 3, "a withdrawn name is NXDOMAIN");
        assert_zone_authority(&parsed, "withdrawn");
    }

    /// NET-126: every record the zone answers, and the negative-cache TTL its
    /// SOA advertises, is at most 15 s.
    #[test]
    fn zone_answers_carry_short_ttl() {
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        let a = reply(&zone, "web.min.internal", TYPE_A);
        let nodata = reply(&zone, "web.min.internal", TYPE_AAAA);
        let nxdomain = reply(&zone, "ghost.min.internal", TYPE_A);
        let soa = reply(&zone, "min.internal", TYPE_SOA);
        assert_eq!(soa.answers.len(), 1, "the apex answers its SOA");

        let mut seen = 0;
        for parsed in [&a, &nodata, &nxdomain, &soa] {
            for rr in parsed.answers.iter().chain(&parsed.authority) {
                seen += 1;
                assert!(rr.ttl <= 15, "{rr:?} outlives 15 s");
                if rr.rtype == TYPE_SOA {
                    assert!(soa_minimum(&rr.rdata) <= 15, "negative TTL {rr:?}");
                }
            }
        }
        assert_eq!(seen, 4, "one record per reply was checked");
    }

    /// NET-127: on the host an `A` answer carries a loopback address only.
    /// A name held at a switch or IPv6 address is answered NODATA rather
    /// than leaking an address the host cannot reach.
    #[test]
    fn host_zone_a_answers_confined_to_local_addresses() {
        let zone = FixedZone(HashMap::from([
            ("web.min.internal".to_string(), v4(127, 0, 0, 1)),
            ("box.min.internal".to_string(), v4(127, 0, 64, 10)),
            ("switch.min.internal".to_string(), v4(10, 0, 2, 15)),
            (
                "six.min.internal".to_string(),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ),
        ]));
        let mut answered = Vec::new();
        for name in ["web", "box", "switch", "six"] {
            let reply = answer(&zone, &query(&format!("{name}.min.internal"), TYPE_A)).unwrap();
            let parsed = parse_reply(&reply.bytes);
            assert_eq!(parsed.rcode(), 0, "{name}: in zone, NOERROR");
            for rr in &parsed.answers {
                assert_eq!(rr.rtype, TYPE_A);
                let octets: [u8; 4] = rr.rdata.as_slice().try_into().unwrap();
                let ip = Ipv4Addr::from(octets);
                assert!(ip.is_loopback(), "{name} answered {ip}");
                answered.push((name, ip));
            }
            if parsed.answers.is_empty() {
                assert_zone_authority(&parsed, name);
            }
        }
        assert_eq!(
            answered,
            vec![
                ("web", Ipv4Addr::LOCALHOST),
                ("box", Ipv4Addr::new(127, 0, 64, 10)),
            ]
        );
    }

    /// Every negative — NODATA, NXDOMAIN, the apex without its SOA, the
    /// resolver's discovery probe — carries the zone's SOA in its authority
    /// section, the record the spike found the macOS resolver needs to cache
    /// it. Out of zone is REFUSED and forwarded nowhere.
    #[test]
    fn negative_answers_carry_zone_authority() {
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        let negatives = [
            ("web.min.internal", TYPE_AAAA, 0),
            ("web.min.internal", TYPE_HTTPS, 0),
            ("ghost.min.internal", TYPE_A, 3),
            ("ghost.min.internal", TYPE_HTTPS, 3),
            ("min.internal", TYPE_A, 0),
            (DDR_PROBE, TYPE_SVCB, 0),
            ("_dns.resolver.arpa", TYPE_A, 0),
        ];
        for (name, qtype, rcode) in negatives {
            let parsed = reply(&zone, name, qtype);
            assert_eq!(parsed.rcode(), rcode, "{name}/{qtype}");
            assert_eq!(
                parsed.question.as_ref().map(|q| q.0.as_str()),
                Some(name),
                "the question is echoed"
            );
            assert_ne!(parsed.flags & FLAG_AA, 0, "{name}: authoritative");
            assert_zone_authority(&parsed, &format!("{name}/{qtype}"));
        }

        for name in ["example.com", "internal", "min.internal.example.com"] {
            let parsed = reply(&zone, name, TYPE_A);
            assert_eq!(parsed.rcode(), 5, "{name}: REFUSED");
            assert!(parsed.answers.is_empty() && parsed.authority.is_empty());
        }
        let parsed = parse_reply(
            &answer(&*zone, &query_in_class("web.min.internal", TYPE_A, 3))
                .unwrap()
                .bytes,
        );
        assert_eq!(parsed.rcode(), 5, "class CH: REFUSED");
    }

    /// A query the answerer cannot read is answered FORMERR rather than left
    /// hanging, and a response datagram is dropped, not answered.
    #[test]
    fn unreadable_queries_are_formerr_and_responses_are_dropped() {
        let zone = zone(&[]);
        let truncated = &query("web.min.internal", TYPE_A)[..20];
        let reply = answer(&*zone, truncated).unwrap();
        assert_eq!(reply.verdict, Verdict::FormErr);
        let parsed = parse_reply(&reply.bytes);
        assert_eq!(parsed.rcode(), 1);
        assert_eq!(parsed.id, 0x1234);
        assert!(parsed.question.is_none());

        let mut response = query("web.min.internal", TYPE_A);
        response[2] |= 0x80;
        assert!(answer(&*zone, &response).is_none());
        assert!(answer(&*zone, &[0u8; 5]).is_none());
    }

    /// NET-123's failure case: with the reserved range absent the probe says
    /// so at once, the box is published at `127.0.0.1` and answers there, and
    /// the advisory is surfaced again at every session start — a configured
    /// resolver does not silence it and there is no once-only latch. Nothing
    /// prompts and nothing hangs.
    #[test]
    fn absent_range_publishes_interim_and_readvises() {
        // TEST-NET-1 is on no host's loopback, so binding it meets exactly
        // what a stock macOS host shows for `127.0.64.x`: an immediate
        // refusal. `127.0.0.1` after it proves the probe stops at the first
        // gap rather than reporting the last address.
        let missing = Ipv4Addr::new(192, 0, 2, 1);
        let started = std::time::Instant::now();
        let probe = probe_range([missing, Ipv4Addr::LOCALHOST]);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the probe neither prompts nor hangs"
        );
        let RangeProbe::Absent { address, error } = &probe else {
            panic!("{missing} is not bindable, so the range is absent: {probe:?}");
        };
        assert_eq!(*address, missing);
        assert!(!error.is_empty(), "the gap carries the bind error");
        assert_eq!(
            probe.gap().as_deref(),
            Some(format!("{missing}: {error}").as_str())
        );
        assert_eq!(probe_range([Ipv4Addr::LOCALHOST]), RangeProbe::Present);

        // The interim: an own-address box is published at 127.0.0.1 as a
        // shared-address box, nothing is leased from the range, and the zone
        // answers it there while it runs.
        assert_eq!(interim_address(&probe), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(interim_address(&RangeProbe::Present), None);
        let zone = zone(&[]);
        let published = zone.write().unwrap().publish_interim(
            SessionId::nil(),
            "web",
            interim_address(&probe).unwrap(),
            &[3000],
        );
        assert_eq!(published.address, Ipv4Addr::LOCALHOST);
        assert_eq!(published.kind, AddressKind::Shared);
        zone.write().unwrap().set_running("web", true);
        let parsed = reply(&zone, "web.min.internal", TYPE_A);
        assert_eq!(parsed.rcode(), 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rdata, Ipv4Addr::LOCALHOST.octets());

        // Re-advised at each start, resolver configured or not.
        let host = HostResolution {
            resolver_configured: true,
            range: probe.clone(),
        };
        assert_eq!(host.surface(), "127.0.0.1 (interim)");
        for start in 1..=2 {
            let advisory = host
                .advisory()
                .unwrap_or_else(|| panic!("session start {start} is advised"));
            assert!(advisory.resolver_configured);
            assert!(!advisory.range_present);
            assert_eq!(advisory.range_gap, probe.gap());
        }
        let unhooked = HostResolution {
            resolver_configured: false,
            range: RangeProbe::Present,
        };
        assert_eq!(unhooked.surface(), "reserved range");
        let advisory = unhooked.advisory().expect("a missing hook is advised");
        assert!(!advisory.resolver_configured && advisory.range_present);
        assert_eq!(advisory.range_gap, None);
        let in_place = HostResolution {
            resolver_configured: true,
            range: RangeProbe::Present,
        };
        assert_eq!(in_place.advisory(), None, "nothing to advise");

        // The hook check is the link's presence in sysfs.
        let sysfs = tempfile::TempDir::new().unwrap();
        assert!(!resolver_hook_configured_in(sysfs.path()));
        std::fs::create_dir(sysfs.path().join(minimald_rpc::RESOLVER_LINK)).unwrap();
        assert!(resolver_hook_configured_in(sysfs.path()));
    }

    /// The zone dump names every entry with its address and lease state, its
    /// published ports with collisions marked, its owner and the listener,
    /// and follows the table: written on start, rewritten on change. Beside
    /// the host's half it carries the in-guest one — the sibling entries a box
    /// resolves, with their switch leases and declared ports (NET-072,
    /// NET-073) — which the host's own answers never give out (NET-127).
    #[tokio::test]
    async fn zone_dump_follows_the_registry() {
        let state = tempfile::TempDir::new().unwrap();
        let zone = zone(&[("web", NetworkMode::HostNet)]);
        let box_zone = Arc::new(BoxZone::default());
        box_zone.register(
            "api",
            Ipv4Addr::new(100, 64, 0, 5),
            Some(&sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 18080,
                    internal_port: 8080,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
            }),
        );
        let server = spawn_answerer(Arc::clone(&zone), Arc::clone(&box_zone), state.path()).await;
        let path = zone_dump_path(state.path());

        let dump = read_dump(&path).await;
        assert_eq!(dump["zone"], "min.internal");
        assert_eq!(dump["ttl_secs"], 15);
        assert_eq!(dump["listener"]["address"], "127.0.0.1");
        assert_eq!(dump["listener"]["port"], u64::from(server.port()));
        assert_eq!(dump["listener"]["socket"], "bound");
        // The host resolution state the bundle reads (NET-122/NET-123).
        assert!(dump["host"]["resolver_configured"].is_boolean());
        assert!(dump["host"]["range"]["state"].is_string());
        assert_eq!(dump["names"][0]["name"], "web.min.internal");
        assert_eq!(dump["names"][0]["address"], "127.0.0.1");
        assert_eq!(dump["names"][0]["owner"], "d0");
        assert_eq!(dump["names"][0]["kind"], "shared");
        assert_eq!(dump["names"][0]["running"], true);
        assert_eq!(dump["in_guest"][0]["name"], "api.min.internal");
        assert_eq!(dump["in_guest"][0]["address"], "100.64.0.5");
        assert_eq!(dump["in_guest"][0]["tcp_ports"][0], 8080);
        assert!(
            dump["in_guest"][0]["udp_ports"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        {
            let mut table = zone.write().unwrap();
            table
                .publish(SessionId::nil(), "api", NetworkMode::OwnIp, &[3000])
                .unwrap();
            table
                .publish(SessionId::nil(), "peer", NetworkMode::HostNet, &[8080])
                .unwrap();
            table
                .publish(SessionId::nil(), "web", NetworkMode::HostNet, &[8080])
                .unwrap();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let dump = read_dump(&path).await;
            let names = dump["names"].as_array().unwrap();
            if names.len() == 3
                && names[2]["collisions"]
                    .as_array()
                    .is_some_and(|c| !c.is_empty())
            {
                assert_eq!(names[0]["name"], "api.min.internal");
                assert_eq!(names[0]["address"], "127.0.64.1");
                assert_eq!(names[0]["kind"], "own");
                assert_eq!(names[0]["running"], false);
                assert_eq!(names[0]["ports"][0], 3000);
                assert_eq!(names[0]["collisions"].as_array().unwrap().len(), 0);
                assert_eq!(names[2]["name"], "web.min.internal");
                assert_eq!(names[2]["collisions"][0]["port"], 8080);
                assert_eq!(names[2]["collisions"][0]["with"], "peer.min.internal");
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "dump not rewritten");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
