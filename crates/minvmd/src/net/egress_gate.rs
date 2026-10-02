//! The host-side egress gate (NET-081): per-box, source-addressed egress
//! rules applied **outside the VM**, by the host, before the switch sees a
//! frame.
//!
//! On a VM-backed host the guest's per-tap shuttle relays raw Ethernet frames
//! over the vsock bridge [`crate::vm`] registers. Before this module that
//! bridge pointed straight at gvproxy's switch socket, so the first host-side
//! thing a frame met was the switch itself — a pure L2 datapath that forwards
//! by destination and believes whatever source address a frame carries. The
//! in-guest relay already applies the shared frame verdict, but it runs
//! **inside** the escape boundary: a process that breaks out of a box into the
//! VM controls the daemon that applies it. NET-081 moves the decision outside
//! — the shuttle's vsock port is pointed at the gate's socket instead
//! ([`crate::net::shuttle::resolve_gate_sock`]), and the gate sits between the
//! guest and the switch, deciding every frame against the host-side table of
//! published namespaces ([`crate::box_registry`], NET-138) before anything is
//! written on to the switch.
//!
//! ```text
//!  guest                        libkrun                          host
//!  ┌────────┐   AF_VSOCK   ┌──────────┐    UDS      ┌─────────────┐   UDS   ┌─────────┐
//!  │ shuttle│── CID 2 ───▶ │ vsock    │───────────▶│ egress gate │───────▶│ gvproxy │
//!  └────────┘   raw L2     │ bridge   │  gate sock  │  (NET-081)  │ switch │  (NAT)  │
//!                          └──────────┘             └─────────────┘  sock  └─────────┘
//! ```
//!
//! The gate is not a second TCP/IP stack. It parses nothing above the
//! Ethernet header, and that only to summarize a frame for the shared verdict
//! (`sessions::core::egress` — the same pure decision the in-guest relay
//! applies, made here where nothing inside the VM can change it). It forwards
//! the gvproxy upgrade head verbatim, then relays both ways: guest → switch
//! through the verdict, per source address; switch → guest untouched, since
//! ingress policy is the *target* box's and is decided in the guest — NET-081
//! is an egress requirement.
//!
//! The socket is not the shuttle's alone. gvproxy's switch socket is one
//! listener carrying two protocols, and the guest daemon uses both over the
//! bridged vsock port: the shuttle's `/connect` upgrade, and the plain
//! HTTP/1.1 control verbs (`/services/forwarder/expose`,
//! `/services/forwarder/unexpose`, `/services/dns/add`) it drives its
//! publishes and its zone with — request/response, framed by
//! `Content-Length`, never a frame on the wire. The gate reads the first
//! request head either way and classifies it by its request line's target
//! against an allow-list, refusing anything else **before forwarding** —
//! because gvproxy hijacks on more than the connect path (`/tunnel` dials
//! an address inside the virtual network and relays bytes), so a head the
//! gate has not classified is a reach, not plumbing. What the classification
//! admits is then treated by what the head asked for, and the two halves
//! differ exactly where their reach does: the frame stream is relayed through
//! the per-source verdict, while a control request is **decided before any
//! of it is written on** — its body is read by the `Content-Length` its head
//! declared, summarized into the request it asks the switch to publish, and
//! decided against the host-side table
//! ([`sessions::core::switch_request`]): a publish of a port or a name is
//! applied only where a published namespace holds the address it names and
//! admits the record, and every other request — an off-list target, a body
//! the gate cannot frame or parse, a publish the table refuses — is refused
//! with nothing written on, one rate-limited line naming the address, the
//! port or name, and the reason. A control connection carries exactly
//! **one** request, and the first further guest byte after it — refused
//! before or past an admitted one — tears the connection down without being
//! written on. gvproxy hijacks a hijacking request however late in the
//! connection's life it arrives, so there being no second request to read is
//! what keeps the gate the only way a frame ever reaches the switch.
//!
//! Fail-closed is the posture. A frame whose source address no published
//! namespace holds is NET-081's failure case, and its fate is the phase
//! constant's ([`UNREGISTERED_SOURCE_PHASE`]): once the per-box default is in
//! force it never leaves the VM, whatever the plan could have done with its
//! address; the interim this build ships admits one class of it — an address
//! inside the plan's lease block, the set an own-address box's lease is
//! minted into by the in-VM daemon, which no host-side process can name until
//! the creator-side registration (T66, #1711) supplies the rows. So the
//! guarantee "a frame whose source address belongs to no box never leaves the
//! VM" binds today **outside the plan's lease block only**, and everywhere
//! the moment T66 flips the constant: under the interim a compromised in-VM
//! process can still put any in-plan address on the wire, the reach the gate
//! exists to contain, which is why the interim needs its rows and why every
//! admit under it warns. The publish half of the gate decides by the same
//! cutover: under the interim a publish at an in-plan address no row holds is
//! applied — the reach the guest daemon's own publishes had before the gate
//! existed — and refused everywhere else, so a compromise in the VM cannot
//! point a forwarder or a zone name at the plan's infrastructure or anywhere
//! outside the plan; once the default binds, only a published namespace's
//! own records publish at all. A frame a published box did not declare is dropped
//! where it stands, silently — a drop is not a reset (NET-062) — with one
//! rate-limited warn line per source address per rule, so a diagnostic
//! bundle's daemon log tail carries what the host is dropping and why without
//! a flood's noise. The table those lines are keyed in is bounded, because
//! the source address a frame is keyed by is the frame's own bytes: a guest
//! flooding distinct spoofed addresses cannot turn the throttling into
//! host-memory growth.
//!
//! Two destinations are refused before any row's rules are read, for every
//! row and in every phase: the switch's own address, a control surface and
//! not a destination a box's rules decide (`egress-switch-control-surface`,
//! [`SWITCH_CONTROL_RULE`]), and the §5.3 infrastructure deny set — link-local
//! and the metadata services in it, loopback, the fabric plane outside the
//! node's own block, and RFC 1918 space the row's `allow_subnets` does not
//! cover (`egress-infrastructure-destination`, [`INFRASTRUCTURE_RULE`]). The
//! set applies to every box-plane packet, CIDR-admitted direct-IP flows
//! included, so a row that declared DNS hosts — whose undeclared-destination
//! drop the gate defers to the in-guest gate, where the resolution-time pins
//! are — has no deferral here: the infrastructure drop is the host's own,
//! whatever the row.
//!
//! Fail-closed faces the guest; the gate itself is what the host is left
//! holding, so it stays up where it can. An accept failure the host can ride
//! out — a momentary fd or memory shortage, a connection that died before it
//! was handed over — is backed off from and retried, rate-limited, because a
//! gate that dies takes every live relay and every box's egress with it, for
//! the rest of the VM's life; only a listener that is genuinely gone stops
//! it. And a guest's connections are counted: each live relay costs the host
//! a socket, a switch dial and a task — two host sockets and a task where the
//! pre-gate splice cost one — so past a bound the gate refuses a connection
//! rather than let one guest pin host resources without one.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use sessions::EgressDefaultPhase;
use sessions::core::egress::{self, DropReason, FrameFamily, FrameSummary, FrameVerdict, Ipv4Cidr};
use sessions::core::switch_request::{
    self, Applied, MAX_REQUEST_RECORDS, Record, Refusal, SwitchRequest, SwitchRow, SwitchTable,
    SwitchVerb,
};
use switch::{DEFAULT_MTU, RESERVED_LOCAL_RANGE, SwitchSubnet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::box_registry::{BoxRecord, BoxTable};

use super::baseline::{NodeBaselinePhase, NodePlaneBaseline};

/// The HTTP request that upgrades a control-socket connection into a raw
/// frame stream. The guest shuttle writes this head before its first frame;
/// gvproxy hijacks the connection and writes no response. The gate forwards
/// it verbatim — the upgrade is the guest's, and what gvproxy accepts is
/// gvproxy's word.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// The request path that turns a connection into a raw frame stream. The
/// switch socket is one listener with two protocols on it — the HTTP
/// request/response verbs the guest daemon drives, and the upgrade that
/// hijacks the connection into the shuttle's length-framed L2 stream — and
/// gvproxy hijacks on this path, whatever the method and however late in the
/// connection's life the request arrives
/// (`crates/minimald/src/net/policy.rs` for the verbs,
/// `crates/minimald/src/net/switch.rs` for the upgrade). It is the one
/// hijacking path the gate relays, and it relays it only as a first request:
/// on a frame connection the frames behind it go through the verdict, and on
/// a control connection there is no second request to hide one in.
///
/// The path is the whole of the classification, read off the head's request
/// line: a first request for it is a frame stream, a first request for a verb
/// in [`CONTROL_VERBS`] is a control exchange, and any other first request is
/// refused before forwarding ([`GuestSpeak::of_head`]).
const CONNECT_PATH: &[u8] = b"/connect";

/// The control verbs the gate relays, each with the path it is spoken at:
/// the guest daemon's own plumbing — the publish and unpublish of a declared
/// ingress port, and the zone-add that gives a box its `*.min.internal` name
/// — and nothing else. gvproxy's switch socket carries other verbs on the
/// same listener, its forwarder listings and its lease, CAM and stats reads
/// among them, and one more hijacking verb beside the connect path:
/// `/tunnel?ip=&port=`, which dials an address inside the virtual network
/// and relays bytes — host-originated TCP to any switch address, with no
/// rule consulted and no frame ever through the gate. None of it is a box's
/// declared traffic, so none of it is forwarded. The list is the daemon's
/// own verbs verbatim, matched exactly on the request line's target: the
/// daemon never speaks another, so a head naming something else is not the
/// daemon, and the guest daemon is the only speaker the gate owes anything
/// to here. Each verb carries its path so the parse that summarizes the
/// request knows which shape of body to expect.
const CONTROL_VERBS: [(ControlVerb, &[u8]); 3] = [
    (ControlVerb::Expose, b"/services/forwarder/expose"),
    (ControlVerb::Unexpose, b"/services/forwarder/unexpose"),
    (ControlVerb::DnsAdd, b"/services/dns/add"),
];

/// Which of the daemon's own publish verbs a control request speaks — the
/// key to the body shape the gate parses, and the verb the decision decides
/// by: an expose and a zone-add publish *at* an address the request names,
/// while a retraction names only the listener it retracts, and the address
/// it is decided at is the gate's attribution — the one the publish it
/// retracts was applied at ([`PublishedForwards`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlVerb {
    /// `POST /services/forwarder/expose`: publish a host-port forwarder.
    Expose,
    /// `POST /services/forwarder/unexpose`: retract one.
    Unexpose,
    /// `POST /services/dns/add`: publish the zone records' names.
    DnsAdd,
}

/// How much of a control connection's body one read of the splice takes.
/// Control bodies are a few hundred bytes of JSON; the size sets only how
/// many writes the body is read and relayed in, never what is admitted — the
/// count the gate reads is the head's `Content-Length`, exactly, and the
/// head's count itself is bounded by [`MAX_CONTROL_BODY`].
const CONTROL_READ: usize = 4 * 1024;

/// The largest control body the gate will read: the daemon's own client's
/// bodies — an expose's three fields, a zone-add's records — are a few
/// hundred bytes, so a head declaring more than this is not one of them, and
/// the request is refused as the shape it is ([`UNDECLARED_VERB_RULE`])
/// before any of its body is read. The bound sits far past the honest need
/// and bounds the gate's read the way [`MAX_HEAD`] bounds its head read: a
/// guest declaring a megabyte body does not buy a megabyte of host memory,
/// because the count is checked before the first body byte is.
const MAX_CONTROL_BODY: usize = 8 * 1024;

/// Where the upgrade head ends and the frames begin.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Bound on the bytes read looking for the first request head's end. The heads
/// the gate sees — the shuttle's upgrade and the daemon's control verbs — are
/// a few dozen constant bytes, so a guest still talking past this without
/// ending one is malformed or hostile, and is refused rather than buffered.
const MAX_HEAD: usize = 4 * 1024;

/// How many bytes one read of the first request head takes. The head is read
/// into a fixed-size scratch, not into a buffer a read can grow: a growable
/// read doubles its reserve read by read, so a guest talking past [`MAX_HEAD`]
/// without ending a head pushes each read's own allocation up with it, and the
/// bound is checked only after the growth it drove. The chunk fixes the read's
/// size — the head buffer's high-water mark is the bound plus one chunk,
/// whatever the guest writes, the same deliberate cap every other guest-scaled
/// cost on this path carries.
const HEAD_READ_CHUNK: usize = 512;

/// Bound on the gate's half of the handshake: dialing the switch it fronts,
/// reading the upgrade head off the guest, and forwarding it. A healthy
/// shuttle writes the head the moment it connects, so one still unfinished
/// this far in is a peer that is wedged, silent, or hostile — and the peer
/// the head comes from lives **inside** the escape boundary this gate exists
/// for, so the host does not wait on it. Bounding the handshake is what
/// releases the host switch connection the dial opened and the relay task
/// holding it, instead of letting a silent guest keep both for the gate's
/// lifetime — the same fail-fast the native relay's `VSOCK_CONNECT_TIMEOUT`
/// gives the connect + `/connect` upgrade from the guest's side
/// (`crates/minimald/src/net/switch.rs`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the accept loop backs off before retrying an accept that failed
/// transiently. Long enough that a sustained shortage is a bounded number of
/// retries a second and not a spin; short enough that a guest connecting
/// while the host was briefly out of fds waits a tenth of a second and gets
/// its relay. The retry is what keeps the gate — and with it every live relay
/// and every box's egress — alive through a hiccup that is not the
/// listener's own end.
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// How many live guest connections the gate will hold a relay for at once.
/// The bound exists because of what a relay costs the host: a socket for the
/// guest's connection, a dial of the switch, and a task — two host sockets
/// and a task where the pre-gate splice cost one — and the peer that decides
/// how many of those to open lives inside the escape boundary this gate
/// exists to contain. A guest that connects, completes the upgrade and then
/// sits idle holds all three for as long as it likes; past this bound the
/// next connection is refused instead, closed rather than hung, so the
/// amplification is bounded without the guest being told why by any byte it
/// can read.
///
/// A cap, not an idle timeout: an idle frame relay is the honest case, not
/// the hostile one — the guest's shuttle opens one connection per box and
/// holds it for the box's lifetime (`attach_to_switch_vsock` in the guest's
/// relay, which does not reconnect), so a box that makes no egress for
/// minutes would lose its relay to a timeout and never get it back. The bound
/// sits far past the honest need — the daemon's own client holds one control
/// connection at a time — and costs a hostile guest nothing an honest one
/// ever reaches.
const MAX_LIVE_RELAYS: usize = 64;

/// Largest Ethernet frame the gate relays: MTU + 14-byte header + 4-byte
/// 802.1Q VLAN tag — the same bound the in-guest relay reads to, so the two
/// halves of the path agree on what a frame may weigh.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + 14 + 4
}

/// One drop warning per source address per rule per interval — the cadence the
/// daemon's policy warnings use, so a host's log speaks with one voice.
const DROP_WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// How many distinct `(source, rule)` pairs the limiter keeps a window for —
/// the gate's memory bound on the lines it writes, a drop's and the interim
/// admit's alike. The source address a line is keyed by is the frame's own
/// bytes, read off the wire, and the guest chooses those: flooding the shuttle
/// with frames from ever-different spoofed addresses would otherwise grow host
/// memory one entry per frame, an amplification against the very path the gate
/// exists to protect. Past the cap, a pair the table holds no window for
/// shares one line per rule ([`DropKey::Overflow`]), so a flood costs at most
/// one line per rule per interval and no memory at all.
///
/// The cap sits far past any honest host's need: the pairs that exist
/// legitimately are the published boxes' few addresses under a closed
/// handful of rules, while more distinct sources writing within one
/// interval than this is a spoofed flood by shape. Stale windows are pruned
/// before the fallback is taken, so a flood that has ended restores
/// per-source lines within one interval.
const DROP_WARN_MAX_TRACKED_PAIRS: usize = 1024;

/// The rule name for NET-081's failure case: a frame whose source address no
/// published namespace holds and the phase leaves nothing to admit — an
/// address outside the plan's lease block while the interim is announced, and
/// any address at all once the per-box default binds. Its own rule, not the
/// lease check's, because the host table has no lease to name — the address
/// simply is not one the host published.
const UNKNOWN_SOURCE_RULE: &str = "egress-unknown-source";

/// The rule name for a frame headed to the switch's own address — the plan's
/// gateway — that is not a resolver query: TCP or UDP to the resolver's port
/// is the one carve-out the frame rules admit there, and everything else —
/// any other port, any other protocol, ICMP included — points at the switch
/// itself. The switch's control surface is not a destination a box's egress
/// rules decide (design §4.1, §7.1): whatever a box's rules allow, nothing at
/// the gateway answers a box but its resolver — a box's admitted ports are
/// its own ingress, reached on its own address, never a flow to the gateway —
/// so the frame is refused before any row or phase is consulted, in force in
/// every phase, and no interim and no row can ever admit it.
const SWITCH_CONTROL_RULE: &str = "egress-switch-control-surface";

/// The port the resolver carve-out is keyed to at the gateway (NET-079):
/// DNS, over UDP or TCP (a query falls back to TCP on truncation, so the
/// carve-out is by address and port, not protocol). The switch's
/// control-surface refusal excepts the resolver's port and nothing else: a
/// frame that falls past the exception is still decided by the row or the
/// phase behind it, so the exception admits nothing on its own — a deny-all
/// box's resolver frame to the gateway is refused by its row as it would be
/// anywhere else.
const RESOLVER_PORT: u16 = 53;

/// The two IPv4 protocols a resolver query travels over: UDP, and TCP when
/// the answer is truncated. A frame to the gateway in any other protocol has
/// no resolver to be headed for, whatever its L4 bytes say.
const RESOLVER_PROTOCOLS: [u8; 2] = [6, 17];

/// The rule name for a frame headed into the infrastructure deny set (design
/// §5.3, NET-067) as a host frame rule: the set applies to every box-plane
/// packet, CIDR-admitted direct-IP flows included, so it is decided for every
/// row, before the row's own rules and before the deferral a name-declaring
/// row earns — no row, no `allow_subnets` entry, and no in-guest pin ever
/// admits a frame here. The ranges are [`INFRASTRUCTURE_RANGES`]'; the one
/// exemption is RFC 1918 under the row's `allow_subnets`, and the one
/// carve-out is the node's own switch block ([`infrastructure_destination`]).
const INFRASTRUCTURE_RULE: &str = "egress-infrastructure-destination";

/// The ranges the host-side infrastructure rule refuses — the host frame
/// rule's own copy of the §5.3 set, built beside the sessions crate's
/// [`egress::InfrastructureDenySet`] rather than from it, because the two
/// decide different things and the rebinding intersection relies on its own
/// shape: that set names the gateway's two addresses as `/32`s (here the
/// gateway is the control-surface rule's, [`SWITCH_CONTROL_RULE`], and the
/// host alias is local reach inside the node's own block), refuses or admits
/// the whole fabric plane by whether the name is a box-zone name (a frame has
/// no name, and the plane's one admitted slice is the node's own block), and
/// keeps its ranges private. The constants are the same, spelled as ranges.
struct InfrastructureRanges {
    /// Refused under every row: link-local and the metadata services living
    /// in it, and loopback space.
    fixed: [Ipv4Cidr; 2],
    /// The plane the switch fabric draws its subnets from: refused outside
    /// the node's own block, where another node's boxes, gateway, and daemon
    /// live.
    plane: Ipv4Cidr,
    /// RFC 1918 space, refused unless the row's `allow_subnets` covers the
    /// destination.
    rfc1918: [Ipv4Cidr; 3],
}

/// The host-side infrastructure ranges, parsed once: the rule is on the
/// per-frame path, and the ranges are constants.
static INFRASTRUCTURE_RANGES: LazyLock<InfrastructureRanges> = LazyLock::new(|| {
    // Every constant parses; the parses exist so the set's contents are
    // spelled as ranges, not as byte arrays.
    let cidr = |s: &'static str| Ipv4Cidr::parse(s).expect("a constant CIDR parses");
    InfrastructureRanges {
        fixed: [cidr("169.254.0.0/16"), cidr("127.0.0.0/8")],
        plane: cidr("100.64.0.0/10"),
        rfc1918: [
            cidr("10.0.0.0/8"),
            cidr("172.16.0.0/12"),
            cidr("192.168.0.0/16"),
        ],
    }
});

/// Whether `dst` lies in the infrastructure deny set as the host frame rule
/// holds it ([`INFRASTRUCTURE_RULE`]): a fixed range; the fabric plane
/// outside `own_block`, the subnet the gate's rows live in — a frame to a
/// sibling, to the host alias, or to the daemon inside the node's own block
/// is local reach, decided by the row's CIDR rules and the target's ingress,
/// never by this rule, and the gateway inside it is the control-surface
/// rule's; or RFC 1918 space the row's `allow_subnets` does not cover.
///
/// `allow` is the row's compiled `allow_subnets`, `None` when the dimension
/// is undeclared — allow-all, the shipped default (03-spec R2.1) — which
/// counts as covering the destination, as the rebinding intersection's
/// exemption holds it ([`egress::rebinding_admits`]): the two allow-all
/// spellings, an undeclared dimension and `0.0.0.0/0`, compile to the same
/// reach everywhere else in the verdict, and the host's rule must not split
/// them, or veto a private address the guest's own gate pins for the same
/// declaration. A declared list that does not cover the destination is the
/// refusal: a developer who wants a box to reach the LAN says so by allowing
/// the range, so neither a name rule nor the deferral can become a way
/// around leaving it undeclared.
fn infrastructure_destination(
    dst: [u8; 4],
    own_block: SwitchSubnet,
    allow: Option<&[Ipv4Cidr]>,
) -> bool {
    let ranges = &*INFRASTRUCTURE_RANGES;
    if ranges.fixed.iter().any(|cidr| cidr.contains(dst)) {
        return true;
    }
    let in_own_block = (u32::from_be_bytes(dst) & u32::from(own_block.netmask()))
        == u32::from(own_block.network());
    if ranges.plane.contains(dst) && !in_own_block {
        return true;
    }
    ranges.rfc1918.iter().any(|cidr| cidr.contains(dst))
        && !allow.is_none_or(|list| list.iter().any(|cidr| cidr.contains(dst)))
}

/// The rule name for the interim's admitted-unregistered source: a frame
/// whose source is an address the plan could hand to a box but no published
/// namespace holds, admitted by the announced interim
/// ([`UNREGISTERED_SOURCE_PHASE`]) rather than dropped. It is a rule name —
/// and a warn, not an info — because this admit is the one frame the gate
/// passes whose reach no row bounds, and a host running the interim must be
/// able to see it in the log: the line names T66 (#1711), the creator-side
/// registration whose rows end the interim.
const UNREGISTERED_SOURCE_RULE: &str = "egress-unregistered-source";

/// The rule name for a request head the gate refuses to relay. Three shapes
/// share it: a request-target outside the gate's allow-list — gvproxy's
/// switch socket carries other verbs there, the `/tunnel` hijack among them —
/// a control head whose body the gate cannot frame, chunked or split across
/// two disagreeing `Content-Length`s, and a control head whose declared body
/// the guest then withholds past the bound ([`relay_control`]). None is the
/// daemon's own client's shape, so the head is refused before anything of it
/// is written on, and the refusal is rate-limited like a frame drop: a guest
/// can attempt it on a fresh connection as cheaply as it can send a frame.
const UNDECLARED_VERB_RULE: &str = "egress-undeclared-verb";

/// The rule name for the publish half's interim admission: a switch publish
/// applied at an address the plan could lease but no published namespace
/// holds — the same class of reach the frame half's
/// [`UNREGISTERED_SOURCE_RULE`] line says, read off a control request
/// instead of a frame. It is a warn, not an info, for the same reason: this
/// is the one publish the gate applies whose reach no row bounds, and a host
/// running the interim must see it in the log. The line names T66 (#1711),
/// the creator-side registration whose rows end the interim.
const UNREGISTERED_PUBLISH_RULE: &str = "egress-unregistered-publish";

/// The rule name for a publish refused because no published namespace holds
/// the address it names: outside the plan's lease block under the interim,
/// anywhere at all once the per-box default binds. The host's forwarders and
/// zone names are the host's own; an address no namespace holds never gains
/// a publication.
const UNKNOWN_PUBLISH_ADDRESS_RULE: &str = "egress-unknown-publish-address";

/// The rule name for a publish refused because the namespace holding its
/// address does not admit the record it asks for — a port the row's
/// declaration does not name, a name it does not declare. The guest's say
/// over which of the host's ports forward into the VM, and over which names
/// resolve where, stops at what the host published.
const UNDECLARED_PUBLISH_RECORD_RULE: &str = "egress-undeclared-publish-record";

/// The rule name for a retraction the decision is applied by nothing at: a
/// listener no applied publish names — keyed at the unspecified address the
/// ledger's absence keys it at, and no row holds that — or a listener the
/// row at its attributed address never published at runtime: a declared
/// port's forward among them, which the host holds for the session's
/// lifetime and no guest request withdraws (design §7.1, NET-121). In both
/// there is nothing the guest's to retract at the address the retraction is
/// decided by. Under the interim a retraction keyed at an in-plan address no
/// row holds is still applied — the teardowns of publications whose rows are
/// still to come are the ones that must work — and refused here only after
/// the flip.
const UNDECLARED_RETRACT_RULE: &str = "egress-undeclared-retract";

/// The rule name for a control request whose body is not the JSON shape the
/// daemon's own client sends for its verb: unparsable JSON, a field the
/// wrong shape, ports that are not ports, a zone-add whose records disagree
/// about the address they publish at, more records than one decision
/// summarizes. Nothing of it is written on and nothing is answered — the
/// guest's connection simply ends — because a body the gate cannot
/// summarize is not a request the gate can decide, and deciding it would be
/// guessing.
const MALFORMED_PUBLISH_RULE: &str = "egress-malformed-publish";

/// The rule name for a control connection spoken past the one request it was
/// allowed — the one reach a control exchange could otherwise buy, since
/// gvproxy hijacks a hijacking request however late in the connection's life
/// it arrives. The gate reads no second request at all: the first byte past
/// the body is refused unread and the connection comes down. Emitted at the
/// same cadence as the frame drops: a guest can attempt it on a fresh
/// connection as cheaply as it can send a frame, and the refusal must not
/// become the flood the frame drops are rate-limited against.
const CONTROL_UPGRADE_RULE: &str = "egress-control-upgrade";

/// The rule name for a guest connection refused because the gate is already
/// holding [`MAX_LIVE_RELAYS`] relays: not a frame the verdict decided, but
/// the same class of refusal — a guest taking host resources it was not
/// given — and it is emitted at the frame drops' cadence for the same reason
/// a drop is: a guest can attempt it as cheaply as it can send a frame, and
/// the refusal must not become the flood.
const CONNECTION_CAP_RULE: &str = "egress-connection-cap";

/// The rule name for an accept failure the gate is riding out rather than
/// dying on. It is the limiter's key, not a verdict — no frame was decided —
/// but it names what a drop line names: what the host refused and why, once
/// per interval, for as long as the condition lasts.
const ACCEPT_RETRY_RULE: &str = "egress-accept-failed";

/// What the guest's first request head says it came for: gvproxy's switch
/// socket speaks two protocols on one listener, and the head's request line
/// is where they part ways — or does not, which is itself an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestSpeak {
    /// The connect upgrade: a hijacked connection carrying length-framed
    /// Ethernet frames — the traffic NET-081 exists to gate.
    Frames,
    /// One control request: plain HTTP/1.1 request/response, framed by
    /// `Content-Length`, never a frame on the wire. Neither head nor body is
    /// relayed until the whole request has been read and decided; the body
    /// is the only thing a control connection may say after the head at all.
    Control {
        /// Which of the daemon's publish verbs the request speaks — the key
        /// to the body shape the gate parses it as.
        verb: ControlVerb,
        /// The request's body length in bytes, read from the head's
        /// `Content-Length`: exactly this many bytes are read, decided on,
        /// and relayed with the head, and the first one after them is
        /// refused.
        body: usize,
    },
}

/// A first request head the gate refuses to relay, and what the refusal line
/// names: `target` is the first line's request-target — or the line's own
/// start, when the line never reached one — so the log can say what was
/// refused, even when it is the guest daemon's own verb with a framing the
/// gate cannot follow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefusedHead {
    /// The request-target the refusal names, truncated to
    /// [`MAX_NAMED_TARGET`].
    target: Vec<u8>,
}

/// How much of a refused request's first line the refusal line names: the
/// verbs the gate relays are under thirty bytes, so anything past this is not
/// one of them, and a rate-limited warning is no place to echo a hostile
/// head.
const MAX_NAMED_TARGET: usize = 64;

impl RefusedHead {
    /// Refuses `what` — a request-target, or the line that never reached one.
    fn new(what: &[u8]) -> Self {
        Self {
            target: what.iter().copied().take(MAX_NAMED_TARGET).collect(),
        }
    }
}

impl GuestSpeak {
    /// Classifies a first request head by its request line's target against
    /// the gate's allow-list: [`CONNECT_PATH`] is the frame stream, a verb in
    /// [`CONTROL_VERBS`] is one control request, and anything else — a target
    /// gvproxy can do more with than the gate has classified, a line the gate
    /// cannot read a target from, or a control head with no single numeric
    /// `Content-Length` to relay a body by — is refused **before forwarding**,
    /// because a head the gate has not classified is a reach, not plumbing.
    ///
    /// The target is matched on its path alone: gvproxy hijacks the connect
    /// path whatever the method and whatever the query, so neither is read —
    /// but nothing else about the target is forgiven either. An absolute-form
    /// target, a path with anything before or after the connect path, and a
    /// first line that is not `METHOD SP target SP version` are all refused:
    /// the gate never writes on a head it has not classified, so gvproxy
    /// never holds bytes it can reinterpret.
    fn of_head(head: &[u8]) -> Result<Self, RefusedHead> {
        // The request line is the head's first line, CRLF-framed as the head
        // itself is (the head ends where it does because it carries
        // [`HEAD_END`]), so reading it by LF loses the framing CR, not the
        // line.
        let line = strip_cr(head.split(|&b| b == b'\n').next().unwrap_or(&[]));
        // `METHOD SP request-target SP HTTP-version`: three tokens. The
        // split always yields the first, so the method is stepped over
        // unread — gvproxy ignores it on the connect path, and the daemon's
        // verbs are the target's to name.
        let mut words = line.split(|&b| b == b' ');
        words.next();
        let Some(target) = words.next() else {
            return Err(RefusedHead::new(line));
        };
        if words.next().is_none() || words.next().is_some() {
            // No version, or a fourth word: not a request line the gate can
            // read a target from.
            return Err(RefusedHead::new(line));
        }
        // The query is not part of what gvproxy routes by; the path is.
        let path = target.split(|&b| b == b'?').next().unwrap_or(target);
        if path == CONNECT_PATH {
            return Ok(Self::Frames);
        }
        let Some(verb) = CONTROL_VERBS
            .iter()
            .find_map(|(verb, verb_path)| (*verb_path == path).then_some(*verb))
        else {
            return Err(RefusedHead::new(target));
        };
        // A control request is `Content-Length`-framed and the gate reads
        // exactly that many body bytes before it decides anything, so the
        // head must frame one body it can read the end of, and one it is
        // willing to hold in host memory at all. The daemon's client always
        // sends one count for a body of a few hundred bytes; a head that
        // frames its body any other way — chunked, in two disagreeing
        // counts, or past the body bound — is not a request the gate can
        // read whole.
        match framed_body(head) {
            Some(body) if body <= MAX_CONTROL_BODY => Ok(Self::Control { verb, body }),
            _ => Err(RefusedHead::new(target)),
        }
    }
}

/// The body byte count the head frames its request by, or nothing when the
/// gate cannot frame it: the `Content-Length` the daemon's client sends on
/// every control request (`post_json`, `crates/minimald/src/net/policy.rs`),
/// with an absent count reading as no body the way HTTP itself reads it. A
/// `Transfer-Encoding`, a count that is not one plain decimal number, and two
/// counts that disagree are each a request whose end the gate cannot pin,
/// and each is refused rather than guessed at: the count decides where the
/// request ends and where the bytes the gate must never write on begin.
fn framed_body(head: &[u8]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = strip_cr(line);
        if line.is_empty() {
            // The head's terminator: the headers are done.
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // Not a header the gate reads; gvproxy's own parse of the head
            // decides what it means, and the head was already classified by
            // its target.
            continue;
        };
        let (name, rest) = line.split_at(colon);
        if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            // Chunked framing is the smuggling shape: the gate relays by a
            // byte count, so a request that will not say one is refused.
            return None;
        }
        if !name.eq_ignore_ascii_case(b"Content-Length") {
            continue;
        }
        let value = rest.strip_prefix(b":")?;
        let count = std::str::from_utf8(value.trim_ascii())
            .ok()?
            .parse::<usize>()
            .ok()?;
        if found.replace(count).is_some() {
            // Two `Content-Length` headers is a smuggling shape, not
            // plumbing: the gate refuses rather than pick one.
            return None;
        }
    }
    // No count named is HTTP's own reading of no body, not a malformed head.
    found.or(Some(0))
}

/// A head line's bytes without the CR its CRLF framing left on it: the gate
/// reads the head's lines by LF, which keeps the framing.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((&b'\r', rest)) => rest,
        _ => line,
    }
}

/// How a control connection's guest → switch leg ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlEnd {
    /// The guest's side is done — it closed the connection, or errored —
    /// having said nothing past its one request's body.
    GuestClosed,
    /// The guest spoke past its one request's body. The bytes are refused
    /// unread — the gate parses no second request, because gvproxy hijacks a
    /// hijacking request however late in the connection's life it arrives
    /// and the only safe number of further bytes to relay is none.
    SpokePastRequest,
    /// The guest spoke its one request's body and then said nothing for the
    /// whole drain bound. Its silence is its normal posture — it is waiting
    /// for the answer — so the gate does not read it as a close, but it does
    /// not hold the leg past the bound either: the leg ends so the exchange
    /// can finish bounded whichever peer has gone quiet.
    GuestSilent,
}

/// A running host-side egress gate: the accept loop on the gate socket, plus
/// one relay task per live guest connection, all on the tokio runtime the
/// gate was started on. Dropping the handle stops them — the gate lives and
/// dies with the switch runtime it was started on ([`crate::net`]).
///
/// What stops the gate is decided, not assumed: an accept failure that is the
/// listener's own end stops it ([`AcceptFailure::Fatal`]); one the host can
/// ride out does not ([`AcceptFailure::RideOut`]), because a gate that dies
/// takes every box's egress with it and a momentary fd or memory shortage is
/// not that. See [`accept_loop`].
#[derive(Debug)]
#[must_use = "dropping the handle stops the gate and every live relay"]
pub struct EgressGate {
    /// The accept loop; aborting it drops its [`JoinSet`], which aborts every
    /// live relay with it.
    accept: JoinHandle<()>,
}

impl EgressGate {
    /// Binds `gate_sock` and starts deciding every frame the guest's shuttle
    /// sends, against `table`, relaying the admitted ones to the switch
    /// listening on `switch_sock`. Must be called within a tokio runtime.
    ///
    /// The gate socket is the path [`crate::vm`] points the shuttle's vsock
    /// port at; a stale socket file from a previous run must be removed by the
    /// caller first, or the bind fails.
    ///
    /// The unregistered-source phase is the build's own
    /// ([`UNREGISTERED_SOURCE_PHASE`]) — no production caller chooses it. A
    /// test that needs the phase's other arm builds its gate with
    /// [`spawn_with_phase`](Self::spawn_with_phase), which is also where the
    /// real work is.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the gate socket cannot be bound.
    pub fn spawn(
        gate_sock: PathBuf,
        switch_sock: PathBuf,
        table: BoxTable,
        baseline: NodePlaneBaseline,
    ) -> io::Result<Self> {
        Self::spawn_with_phase(
            gate_sock,
            switch_sock,
            table,
            baseline,
            UNREGISTERED_SOURCE_PHASE,
        )
    }

    /// [`spawn`](Self::spawn) with the unregistered-source phase named: the
    /// parameter that lets a test build the gate under the phase's other arm
    /// ([`UnregisteredSourcePhase::InForce`], the one T66, #1711, flips the
    /// shipped constant onto) and pin the per-box default at relay level, so
    /// the flip has behaviour to turn green rather than tests to rewrite. The
    /// relay threads the phase down to [`gate_verdict`]; the start-up line
    /// logs the phase the gate was actually built with.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the gate socket cannot be bound.
    pub(crate) fn spawn_with_phase(
        gate_sock: PathBuf,
        switch_sock: PathBuf,
        table: BoxTable,
        baseline: NodePlaneBaseline,
        phase: UnregisteredSourcePhase,
    ) -> io::Result<Self> {
        let listener = UnixListener::bind(&gate_sock)?;
        // The posture for in-plan sources no row holds, stated at the moment
        // the gate starts, is the closest this host process comes to surfacing
        // the interim at all: the warns below say it again, once per source
        // per interval, for as long as any box's frames pass under it.
        tracing::info!(
            gate_socket = %gate_sock.display(),
            switch_socket = %switch_sock.display(),
            unregistered_in_plan_sources = phase.as_str(),
            "host-side egress gate listening",
        );
        // The node-plane baseline set the gate decides the in-VM daemon's own
        // frames by, named at VM start with each entry's category: the line a
        // bundle's daemon log tail holds to see which categories the node
        // plane may reach and under which posture the gate decides them
        // (NET-130).
        tracing::info!(
            baseline = %baseline.render(),
            node_addr = %Ipv4Addr::from(baseline.node_addr()),
            node_baseline_phase = baseline.phase().as_str(),
            "node-plane baseline set at the gate",
        );
        // One limiter for the whole gate: a guest that reconnects must not
        // reset the rate window its drops are counted in.
        let limiter = Arc::new(DropLimiter::new());
        // One publish ledger for the whole gate, beside the limiter: the
        // address a listener's publish was applied at is a fact of the gate,
        // not of the connection that carried it — the publish and the
        // teardown that retracts it arrive on different connections.
        let forwards = Arc::new(PublishedForwards::new());
        Ok(Self {
            accept: tokio::spawn(accept_loop(
                listener,
                switch_sock,
                table,
                baseline,
                limiter,
                forwards,
                HANDSHAKE_TIMEOUT,
                phase,
            )),
        })
    }
}

impl Drop for EgressGate {
    fn drop(&mut self) {
        // A gate that is gone must not keep deciding frames. Aborting the
        // accept loop drops its JoinSet, which aborts every live relay.
        self.accept.abort();
    }
}

/// The one thing the accept loop needs from the socket it accepts on, as a
/// trait so the loop's failure handling can be driven by a test without first
/// having to hit a real process fd limit: the only production implementation
/// is [`UnixListener`]'s, unchanged.
trait GuestSource {
    /// Accepts the next guest connection, or the error that failed the
    /// accept.
    fn accept(&mut self) -> impl Future<Output = io::Result<UnixStream>> + Send;
}

impl GuestSource for UnixListener {
    #[expect(
        clippy::manual_async_fn,
        reason = "an `async fn` in a trait returns a future that is not known `Send`, and this \
                  loop is spawned on the tokio runtime, which needs the Send"
    )]
    fn accept(&mut self) -> impl Future<Output = io::Result<UnixStream>> + Send {
        async { UnixListener::accept(self).await.map(|(guest, _)| guest) }
    }
}

/// What an accept failure means for the gate: a condition the host can ride
/// out, or the listener's own end. The distinction is the whole fix for the
/// failure mode a long-lived host daemon meets — an accept error is *not*
/// necessarily a gate that has stopped deciding frames, and treating every
/// one as if it were severs every box's egress for the rest of the VM's life
/// over a condition that clears on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptFailure {
    /// The host's own momentary shortage — the process is briefly out of
    /// descriptors, memory, or the per-connection buffers — or the death of
    /// one connection before it was handed over. Neither says anything about
    /// the listener, so the gate backs off and keeps accepting.
    RideOut,
    /// The listener itself is gone. The gate stops, fail-closed.
    Fatal,
}

impl AcceptFailure {
    /// Classifies one accept error.
    ///
    /// The ride-out set is the accept(2) errors that are per-attempt rather
    /// than per-listener — the fd-limit and memory shortages a host daemon
    /// holding a socket and a dial per live relay can be pushed into, and the
    /// aborted or malformed connection, which says nothing about the next
    /// one. `std` leaves the fd-limit errors uncategorized
    /// (`io::ErrorKind::Uncategorized`), so they are read off the raw errno
    /// and not off the kind; the kind check catches the same two conditions
    /// in an error with no errno behind it. Everything else — a bad
    /// descriptor, a listener no longer willing to accept — is fatal: the
    /// guest's next connect fails, and a gate that cannot accept must not
    /// keep deciding frames either.
    fn of(error: &io::Error) -> Self {
        if matches!(
            error.raw_os_error(),
            Some(
                libc::EMFILE
                    | libc::ENFILE
                    | libc::ENOMEM
                    | libc::ENOBUFS
                    | libc::ECONNABORTED
                    | libc::EPROTO
            )
        ) || matches!(
            error.kind(),
            io::ErrorKind::OutOfMemory | io::ErrorKind::ConnectionAborted
        ) {
            return Self::RideOut;
        }
        Self::Fatal
    }
}

/// Accepts guest connections on the bound listener and gives each one a relay
/// task, held in a [`JoinSet`] this loop owns: aborting the loop — what the
/// [`EgressGate`] handle's `Drop` does — aborts every relay with it.
///
/// Two things here would otherwise cost the VM every box's egress for the
/// rest of its life, so neither is allowed to. An accept failure is
/// classified rather than assumed ([`AcceptFailure`]): the transient ones are
/// backed off from and retried, and said so at the gate's own cadence, so a
/// momentary resource shortage costs a tenth of a second and a line a minute
/// — not the gate, its live relays, and the next guest's connect. And the
/// live relays are counted against [`MAX_LIVE_RELAYS`], so a guest that opens
/// connections and then sits idle — precisely the peer this gate exists to
/// contain — cannot pin host sockets and tasks without bound.
///
/// `handshake_timeout` is the bound every connection is served under
/// ([`serve_connection`]); it is a parameter only so a test can shrink it,
/// and the one caller outside this module's tests passes
/// [`HANDSHAKE_TIMEOUT`].
#[expect(
    clippy::too_many_arguments,
    reason = "the source, the switch socket, the table, the baseline, the limiter, the \
              publish ledger, the bound and the phase are each a distinct input to \
              every relay the loop spawns; grouping them would name the bundle \
              without naming the members"
)]
async fn accept_loop<A: GuestSource>(
    mut source: A,
    switch_sock: PathBuf,
    table: BoxTable,
    baseline: NodePlaneBaseline,
    limiter: Arc<DropLimiter>,
    forwards: Arc<PublishedForwards>,
    handshake_timeout: Duration,
    phase: UnregisteredSourcePhase,
) {
    let mut relays = JoinSet::new();
    loop {
        let guest = match source.accept().await {
            Ok(guest) => guest,
            Err(error) => match AcceptFailure::of(&error) {
                AcceptFailure::RideOut => {
                    // Ride it out, and say so at the frame drops' cadence: the
                    // error repeats once per backoff for as long as the
                    // shortage lasts, which on a long-lived host daemon is a
                    // line a minute rather than one a tenth of a second.
                    if limiter.should_warn_at(None, ACCEPT_RETRY_RULE, Instant::now())
                        != WarnDecision::Silent
                    {
                        tracing::warn!(
                            %error,
                            rule_matched = ACCEPT_RETRY_RULE,
                            retry_backoff = ?ACCEPT_RETRY_BACKOFF,
                            "egress gate accept failed transiently; the gate is retrying",
                        );
                    }
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                    continue;
                }
                AcceptFailure::Fatal => {
                    // Fail closed, and say so: a gate that cannot accept
                    // cannot be bypassed — the guest's connect fails and its
                    // relay reports no egress, the same posture as a host
                    // gvproxy that never came up.
                    tracing::warn!(%error, "egress gate accept failed; the gate has stopped");
                    return;
                }
            },
        };
        // Reap the finished so a long-lived gate accumulates no handles for
        // connections long gone — and so the bound below counts only the
        // relays that are live, not the ones already ended.
        while relays.try_join_next().is_some() {}
        if relays.len() >= MAX_LIVE_RELAYS {
            // Refused, closed rather than hung, at the frame drops' cadence:
            // the guest's end is dropped here, so it sees a connection that
            // failed instead of one that never answers. Nothing of it is
            // dialed into the switch, so past the bound a guest buys no host
            // socket, no relay task, and no frame through the gate.
            if limiter.should_warn_at(None, CONNECTION_CAP_RULE, Instant::now())
                != WarnDecision::Silent
            {
                tracing::warn!(
                    live = relays.len(),
                    max = MAX_LIVE_RELAYS,
                    rule_matched = CONNECTION_CAP_RULE,
                    "refused a guest connection past the egress gate's live-relay bound",
                );
            }
            continue;
        }
        relays.spawn(serve_connection(
            guest,
            switch_sock.clone(),
            table.clone(),
            baseline.clone(),
            Arc::clone(&limiter),
            Arc::clone(&forwards),
            handshake_timeout,
            phase,
        ));
    }
}

/// Serves one guest connection end to end: dial the switch this gate fronts,
/// classify the request head the guest wrote, forward the head if — and only
/// if — the gate relays what it asks for, then relay by what that head asked
/// for: frames through the verdict, a control request read whole, decided,
/// and written on only when the table admits it, for as long as the
/// connection lives, until the guest or the switch goes away.
///
/// `handshake_timeout` bounds everything up to and including the head the
/// frame stream's relay starts from, and, on a control connection, the read
/// of the body the head declared, the wait on a guest gone silent past its
/// request and the drain of the answer that follows the request's end. It is
/// a parameter only so a test can shrink it; every caller outside this
/// module's tests reaches a connection through [`accept_loop`], which passes
/// the bound it was given — [`HANDSHAKE_TIMEOUT`] from
/// [`EgressGate::spawn_with_phase`].
#[expect(
    clippy::too_many_arguments,
    reason = "the two sockets, the table, the baseline, the limiter, the publish \
              ledger, the drain bound and the phase are each a distinct input to \
              what one connection does; grouping them would name the bundle \
              without naming the members"
)]
async fn serve_connection(
    mut guest: UnixStream,
    switch_sock: PathBuf,
    table: BoxTable,
    baseline: NodePlaneBaseline,
    limiter: Arc<DropLimiter>,
    forwards: Arc<PublishedForwards>,
    handshake_timeout: Duration,
    phase: UnregisteredSourcePhase,
) {
    // The handshake is bounded front to back: the guest is the untrusted side
    // here, so a peer that connects and then sends nothing — or a head it
    // never ends — is refused within the bound and the host switch connection
    // the dial opened comes down with it, rather than either being held for
    // the gate's lifetime.
    let handshake = async {
        // Fail closed before anything else: with no switch to relay into
        // there is no egress either way, but the guest gets a closed
        // connection rather than a silent one.
        let mut switch = match UnixStream::connect(&switch_sock).await {
            Ok(switch) => switch,
            Err(error) => {
                tracing::warn!(
                    %error,
                    switch_socket = %switch_sock.display(),
                    "egress gate could not reach the switch; refusing the guest connection"
                );
                return Err(());
            }
        };
        let (head, carry) = match read_request_head(&mut guest).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "egress gate could not read the request head from the guest"
                );
                return Err(());
            }
        };
        // The head is classified before a byte of it is written on: a target
        // the gate has not classified — the `/tunnel` hijack, a listing, a
        // shape the gate cannot frame — never reaches the switch at all.
        let speak = match GuestSpeak::of_head(&head) {
            Ok(speak) => speak,
            Err(refused) => {
                refuse_head(&limiter, &refused);
                return Err(());
            }
        };
        // The frame stream's head is forwarded here — gvproxy hijacks on the
        // head itself, so it is the last byte of the guest's that reaches the
        // switch un-decided, and the handshake bound covers the write as it
        // covers every step before it. A control request's head is **not**
        // forwarded: what the gate decides the request to be decides whether
        // any of it is written on, and the head goes out only with the
        // admitted request, from [`relay_control`].
        if matches!(speak, GuestSpeak::Frames)
            && let Err(error) = switch.write_all(&head).await
        {
            tracing::warn!(%error, "egress gate could not forward the request head");
            return Err(());
        }
        Ok((switch, head, carry, speak))
    };
    let (switch, head, carry, speak) =
        match tokio::time::timeout(handshake_timeout, handshake).await {
            Ok(Ok(quadruple)) => quadruple,
            // Whichever step failed has already said why; the connection is
            // refused either way.
            Ok(Err(())) => return,
            Err(_) => {
                tracing::warn!(
                    handshake_timeout = ?handshake_timeout,
                    "egress gate handshake timed out; refusing the guest connection"
                );
                return;
            }
        };
    let (switch_rx, switch_tx) = switch.into_split();
    let (guest_rx, guest_tx) = guest.into_split();
    match speak {
        GuestSpeak::Frames => {
            relay_frames(
                Prefixed::new(carry, guest_rx),
                switch_tx,
                switch_rx,
                guest_tx,
                table,
                baseline,
                limiter,
                phase,
            )
            .await;
        }
        GuestSpeak::Control { verb, body } => {
            relay_control(
                Prefixed::new(carry, guest_rx),
                switch_tx,
                switch_rx,
                guest_tx,
                head,
                verb,
                body,
                table,
                limiter,
                &forwards,
                handshake_timeout,
                phase,
            )
            .await;
        }
    }
}

/// Refuses a first request head, at the frame drops' cadence: a guest can
/// attempt an off-list request on a fresh connection as cheaply as it can
/// send a frame, so the refusal must not become a flood. Nothing of the head
/// is written on — gvproxy never sees the request — and the connection's
/// halves come down with the return.
fn refuse_head(limiter: &DropLimiter, refused: &RefusedHead) {
    if limiter.should_warn_at(None, UNDECLARED_VERB_RULE, Instant::now()) != WarnDecision::Silent {
        tracing::warn!(
            rule_matched = UNDECLARED_VERB_RULE,
            request_target = %String::from_utf8_lossy(&refused.target),
            "refused a request head the egress gate does not relay",
        );
    }
}

/// guest ↔ switch on an upgraded connection: egress (guest → switch) through
/// the frame verdict, per source address; ingress (switch → guest) untouched
/// and un-parsed — the gate's job is the egress direction, and what a box may
/// receive is the target's ingress policy, decided in the guest where its
/// declarations are enforced.
#[expect(
    clippy::too_many_arguments,
    reason = "the relay's full state in one place: both directions' halves, the \
              deciding table and the node-plane baseline set, the limiter, and \
              the phase — splitting it would hide one of them"
)]
async fn relay_frames(
    guest: Prefixed<OwnedReadHalf>,
    switch_tx: OwnedWriteHalf,
    switch_rx: OwnedReadHalf,
    guest_tx: OwnedWriteHalf,
    table: BoxTable,
    baseline: NodePlaneBaseline,
    limiter: Arc<DropLimiter>,
    phase: UnregisteredSourcePhase,
) {
    let mut ingress = tokio::spawn(copy_switch_to_guest(switch_rx, guest_tx));
    let egress = relay_guest_to_switch(guest, switch_tx, table, baseline, limiter, phase);
    tokio::pin!(egress);
    // The two legs race, because neither can see the other's end. The egress
    // leg blocks on the guest, which has no reason to speak while it is idle,
    // so it has no way to learn the switch hung up this one connection's end
    // — the per-connection close a switch makes without the process exit the
    // supervisor catches — and would otherwise hold the relay task, the gate's
    // dial, and the switch write half open until the guest's next frame came
    // and failed to write. The ingress leg ending is the only thing on this
    // side that knows, so whichever leg ends first takes the relay down with
    // it.
    tokio::select! {
        result = &mut egress => match result {
            // The guest closed its side: the shuttle reconnects per boot and
            // drops the connection at teardown.
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => {
                tracing::warn!(%error, "egress gate relay ended on an error");
            }
        },
        result = &mut ingress => match result {
            // The switch closed its side of the connection while the guest was
            // still on it: the guest's egress is down, so say so — the guest
            // has nothing else to tell it why — before the relay comes off.
            Ok(Ok(())) => tracing::warn!(
                "the switch closed its side of the connection; the egress gate \
                 relay is down for it"
            ),
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "egress gate ingress leg ended on an error");
            }
            Err(error) => {
                tracing::warn!(%error, "egress gate ingress leg ended");
            }
        },
    }
    // The leg that lost the race is torn down with the relay, not left to
    // hold what the guest or the switch end of it was holding.
    ingress.abort();
}

/// One control request on a connection, decided before any of it is written
/// on. The head arrived with the handshake but was **not** forwarded: the
/// gate reads the `Content-Length` body — `body` bytes, however many reads
/// they arrive in — summarizes the request the verb and the body ask the
/// switch for, and decides it against the host-side table. An admitted
/// request's head and body go on together, verbatim, and the exchange
/// finishes as a control exchange always finished: the switch answers, the
/// answer is drained to the guest, bounded. Anything else — a body the guest
/// never finished, a publish the table refuses, a body that is not the
/// verb's own JSON shape — is refused with **nothing** written on: gvproxy
/// never sees the request, no answer is owed, and the connection comes down.
/// The daemon's own client speaks one request per connection and closes from
/// its side once the answer is read (`post_json`,
/// `crates/minimald/src/net/policy.rs`), so one request is all the gate ever
/// relays, and the first guest byte past the body is refused unread rather
/// than parsed: gvproxy hijacks a hijacking request however late in a
/// connection's life it arrives, and there being no second request to read
/// is what leaves nothing for an upgrade to hide in.
///
/// The decision is [`decide_control_request`]'s, the application is this
/// loop's, and the interim's admission is said so here — the one publish the
/// gate applies whose reach no row bounds, warned at the frame drops'
/// cadence, naming T66 (#1711).
///
/// The legs race, because neither can see the other's end. The request leg
/// blocks on the guest, which has no reason to speak while it is idle
/// waiting for the response, so it has no way to learn the switch hung up
/// this one connection's end — the per-connection close a keep-alive control
/// channel makes without the process exit the supervisor catches, the same
/// close [`relay_frames`] races its legs for — and would otherwise hold the
/// relay task, the gate's dial, and both socket halves open until the guest
/// next spoke. The response leg ending is the only thing on this side that
/// knows, so whichever leg ends first takes the relay down with it.
///
/// The request leg's own waits are bounded, the body's read and the wait
/// past it both. Past the body the guest's silence is at its widest: it has
/// no reason to speak while it waits for the answer, so the probe that ends
/// the leg on a byte past the request runs under `drain_timeout` as well,
/// and the body's read runs under the same bound, so a guest that declares a
/// body and withholds it is refused like one that closed mid-body rather
/// than holding the relay and its [`MAX_LIVE_RELAYS`] slot. A guest that
/// spoke its one request and then waits — its normal posture — no longer
/// holds the relay, the dial and the socket halves for the gate's lifetime
/// on a switch that neither answers nor hangs up: the leg ends at the bound,
/// and the release runs through the same bounded drain [`finish_control`]
/// gives every other end.
///
/// Whichever way the request leg ends, the exchange's answer is still owed:
/// the switch's side is half-closed, so gvproxy sees the request's end and
/// answers the one request it was given — refused or not, the guest made a
/// request the gate relayed, and dropping its answer in flight would punish
/// nothing but the guest's own daemon — and the response is drained before
/// the relay comes off, bounded by `drain_timeout` — the same bound the
/// handshake reads under — so a switch that will neither answer nor die
/// holds no gate task and no socket past it.
#[expect(
    clippy::too_many_arguments,
    reason = "the four socket halves, the framed request, the table, the limiter, the \
              publish ledger and the drain bound are each a distinct input to one leg; \
              grouping them would name the bundle without naming the members"
)]
async fn relay_control(
    mut guest: Prefixed<OwnedReadHalf>,
    mut switch: OwnedWriteHalf,
    switch_rx: OwnedReadHalf,
    guest_tx: OwnedWriteHalf,
    head: Vec<u8>,
    verb: ControlVerb,
    body: usize,
    table: BoxTable,
    limiter: Arc<DropLimiter>,
    forwards: &PublishedForwards,
    drain_timeout: Duration,
    phase: UnregisteredSourcePhase,
) {
    // The request is read whole before anything is decided: the head framed
    // its body by count, so the body is read exactly — and a guest that
    // never finished it has published nothing to decide. The read runs under
    // `drain_timeout`, the bound this leg already gives a guest gone quiet
    // past its request: the head was read under the handshake's bound and the
    // body is the same peer's next bytes, so a guest that declares a body and
    // then withholds it is the silent guest again, this time holding the
    // relay task, the gate's dial, both socket halves and one of the
    // [`MAX_LIVE_RELAYS`] slots — and enough of those closes the gate to every
    // guest connection after. The bound is what returns the slot.
    let request =
        match tokio::time::timeout(drain_timeout, read_control_body(&mut guest, body)).await {
            Ok(Some(request)) => request,
            Ok(None) => {
                // The guest's side ended mid-body. Nothing was written on —
                // the head went out with no request behind it — so gvproxy
                // holds no request to answer, and the relay comes down
                // without the drain a finished request owes.
                return;
            }
            Err(_) => {
                // Withheld past the bound: refused exactly as a guest that
                // closed mid-body is — nothing was written on, gvproxy holds
                // no request to answer, the relay comes down with the return
                // — and said so under the rule a head the gate cannot frame is
                // refused under, at the frame drops' cadence: a guest can
                // attempt it on a fresh connection as cheaply as it can send
                // a frame, and the refusal must not become the flood.
                if limiter.should_warn_at(None, UNDECLARED_VERB_RULE, Instant::now())
                    != WarnDecision::Silent
                {
                    tracing::warn!(
                        rule_matched = UNDECLARED_VERB_RULE,
                        declared_body = body,
                        read_timeout = ?drain_timeout,
                        "a control body was withheld past the bound; \
                         the egress gate refused the request",
                    );
                }
                return;
            }
        };
    let decision = match decide_control_request(verb, &request, &table, phase, forwards) {
        Ok(decision) => decision,
        Err(refused) => {
            // Refused, and said so at the frame drops' cadence: a guest can
            // attempt a publish on a fresh connection as cheaply as it can
            // send a frame, and the refusal must not become the flood. The
            // connection's halves come down with the return — nothing was
            // written on, so gvproxy never saw the request, and the guest's
            // read of its own side ends it.
            refuse_request(&limiter, &refused);
            return;
        }
    };
    // Admitted: the head and body are forwarded together, in one write, so
    // the request gvproxy sees is exactly the request the guest sent and
    // exactly the request the table admitted.
    let mut spoken = head;
    spoken.extend_from_slice(&request);
    if let Err(error) = switch.write_all(&spoken).await {
        tracing::warn!(%error, "egress gate could not forward an admitted control request");
        return;
    }
    if decision.applied == Applied::Interim {
        // The interim's admission is the one publish the gate applies whose
        // reach no row bounds, and the host must be able to see it pass.
        warn_interim_publish(&limiter, &decision);
    }
    // The applied request is filed with the publish ledger: a forwarder's
    // listener and the address its publish was applied at are what a later
    // retraction of it is keyed by, and an applied retraction's listener
    // leaves the ledger with it — the publication is gone. The note is taken
    // after the write: a forward the gate could not deliver published
    // nothing, and attributes nothing.
    match (verb, forward_listener(verb, &request)) {
        (ControlVerb::Expose, Some(listener)) => {
            forwards.note_published(listener, decision.request.switch_addr());
        }
        (ControlVerb::Unexpose, Some(listener)) => forwards.note_retracted(listener),
        _ => {}
    }
    let mut response = tokio::spawn(copy_switch_to_guest(switch_rx, guest_tx));
    // The legs race, as the frame relay's do: the switch's side can end under
    // an idle guest — the per-connection close a keep-alive control channel
    // makes while the guest waits on the answer — and only the response leg
    // can see it, so whichever leg ends first takes the relay down with it.
    // On the response leg's end the relay comes off at once: the answer the
    // request leg was waiting on is not coming, and holding the dial and both
    // socket halves past it would be holding a dead exchange.
    let end = tokio::select! {
        result = &mut response => {
            match result {
                // The switch closed its side of the connection while the guest
                // was still on it: say so — the line a bundle's daemon log
                // tail carries for a control connection the host closed under
                // an idle guest — before the relay comes off.
                Ok(Ok(())) => {
                    tracing::warn!(
                        "the switch closed its side of the control connection; \
                         the egress gate relay is down for it"
                    );
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "egress gate control response leg ended on an error");
                }
                Err(error) => {
                    tracing::warn!(%error, "egress gate control response leg ended");
                }
            }
            return;
        }
        end = control_request_probe(&mut guest, drain_timeout) => end,
    };
    match end {
        // A guest that closed, and one that spoke its request and then said
        // nothing for the whole bound — its silence is its normal posture
        // while it waits on the answer — both leave the request leg done.
        // The answer is owed either way: the switch's side is half-closed, so
        // gvproxy sees the request's end and answers it, and the drain that
        // delivers it is bounded.
        ControlEnd::GuestClosed | ControlEnd::GuestSilent => {
            finish_control(&mut response, &mut switch, drain_timeout).await;
        }
        ControlEnd::SpokePastRequest => {
            // Refused, at the frame drops' cadence: a guest can attempt this
            // on a fresh connection as cheaply as it can send a frame, and
            // the refusal must not become the flood.
            if limiter.should_warn_at(None, CONTROL_UPGRADE_RULE, Instant::now())
                != WarnDecision::Silent
            {
                tracing::warn!(
                    rule_matched = CONTROL_UPGRADE_RULE,
                    "a control connection was spoken past its one request; \
                     the egress gate tore it down",
                );
            }
            // The answer to the request that *was* relayed is still drained:
            // half-close the switch's side and let gvproxy finish, rather
            // than aborting the response leg and dropping an answer
            // mid-flight.
            finish_control(&mut response, &mut switch, drain_timeout).await;
        }
    }
}

/// Ends a control connection whose request leg finished: half-close the
/// switch's side, so gvproxy sees the request's end and answers the one
/// request it was given, then drain the answer to the guest, bounded by
/// `drain_timeout`. The bound is what releases the gate's task and the socket
/// halves it holds when a switch will neither answer nor die: the daemon is
/// unaffected either way, but the gate must not outlive the connection on a
/// switch that is not going to speak again.
async fn finish_control(
    response: &mut JoinHandle<io::Result<()>>,
    switch: &mut OwnedWriteHalf,
    drain_timeout: Duration,
) {
    if let Err(error) = switch.shutdown().await {
        tracing::warn!(
            %error,
            "egress gate could not close the switch's side of a control connection"
        );
    }
    match tokio::time::timeout(drain_timeout, &mut *response).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "egress gate control response leg ended on an error");
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "egress gate control response leg ended");
        }
        Err(_) => {
            // The switch took the request and said nothing back for the
            // whole bound: stop waiting on it, so the relay — and the dial
            // and both socket halves it holds — comes down now.
            response.abort();
            tracing::warn!(
                drain_timeout = ?drain_timeout,
                "gvproxy did not answer a control request within the bound; \
                 the egress gate relay is down for it"
            );
        }
    }
}

/// Reads exactly `body` bytes — the head's `Content-Length` — however many
/// reads they arrive in, returning them together for the gate to decide on.
/// A guest that closes or errors mid-body ends the relay: the request was
/// never whole, so it was never a request, and `None` says so — the caller
/// writes nothing on and owes no answer. The read takes at most
/// [`CONTROL_READ`] bytes per read, bounded by what the body still owes, so
/// no read ever holds a byte past the body: the first byte after it is not
/// the gate's to read here.
///
/// The count itself was bounded at the head ([`MAX_CONTROL_BODY`]), so the
/// buffer is sized to a request the gate was willing to read at all.
#[expect(
    clippy::indexing_slicing,
    reason = "each `chunk[..want]` / `chunk[..n]` is bounded by `want` and the read's own `n`"
)]
async fn read_control_body(guest: &mut Prefixed<OwnedReadHalf>, body: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(body);
    let mut chunk = vec![0u8; CONTROL_READ];
    while bytes.len() < body {
        let want = (body - bytes.len()).min(chunk.len());
        match guest.read(&mut chunk[..want]).await {
            // The guest's side is done mid-body: nothing was written on, so
            // there is nothing left to flush and nothing left to decide.
            Ok(0) => return None,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(error) => {
                tracing::warn!(%error, "egress gate control leg ended on an error");
                return None;
            }
        }
    }
    Some(bytes)
}

/// The one-byte probe a control request's request leg ends on: the gate
/// parses no second request, because gvproxy hijacks a hijacking request
/// however late in the connection's life it arrives, so the next byte after
/// the request — whatever it would say — ends the leg as spoken-past and is
/// never written on ([`ControlEnd::SpokePastRequest`]); a close ends it as
/// done ([`ControlEnd::GuestClosed`]).
///
/// The probe is bounded by the drain bound, because the guest's silence past
/// its request is its normal posture — it is waiting for the answer — and an
/// unbounded wait here would hold this leg, and with it the relay task, the
/// gate's dial and both socket halves, for the gate's lifetime on a switch
/// that neither answers nor closes. Past the bound the leg ends
/// ([`ControlEnd::GuestSilent`]) and the caller gives the switch the same
/// bound to answer through the drain it already runs, so the exchange ends
/// bounded whichever peer has gone quiet.
async fn control_request_probe(
    guest: &mut Prefixed<OwnedReadHalf>,
    drain_timeout: Duration,
) -> ControlEnd {
    let mut probe = [0u8; 1];
    match tokio::time::timeout(drain_timeout, guest.read(&mut probe)).await {
        Ok(Ok(0)) => ControlEnd::GuestClosed,
        Ok(Ok(_)) => ControlEnd::SpokePastRequest,
        Ok(Err(error)) => {
            tracing::warn!(%error, "egress gate control leg ended on an error");
            ControlEnd::GuestClosed
        }
        // No byte came and no close either: the guest is only waiting, and
        // the bound is what releases the leg.
        Err(_) => ControlEnd::GuestSilent,
    }
}

/// A control request the gate refused, as its warn line names it: the rule
/// that refused it, the switch address it published at or the retraction is
/// keyed at (`None` only when the body never parsed far enough to name one —
/// a retraction's is always present, the attribution or the unspecified
/// address its absence keys at), the port or name the refusal is about when
/// one is nameable, and the reason. Built by [`decide_control_request`],
/// rendered by [`refuse_request`].
struct RefusedRequest {
    rule: &'static str,
    addr: Option<[u8; 4]>,
    what: Option<String>,
    reason: String,
}

/// What deciding one control request came to: the applied-by it was admitted
/// by, and the request summary plus the decision's name dictionary the
/// admission's line is rendered from.
struct ControlDecision {
    applied: Applied,
    request: SwitchRequest,
    dictionary: Vec<String>,
}

/// The listener ports whose publishes the gate has applied, each with the
/// switch address it was applied at: the ledger a retraction is attributed
/// by. The unexpose body names only the loopback listener it retracts — the
/// wire carries no switch address — but the decision is keyed per address
/// (`switch_request::applied` decides a retract by the row at the request's
/// own address, against the ports that row's runtime published), so the
/// gate supplies the address from the one place it is a host-side fact: the
/// publish the listener's forward came from. A retraction for a listener no
/// applied publish names is keyed at the unspecified address, which no row
/// holds, and refused — a guest cannot retract a publication the gate never
/// admitted by naming a port some row happens to declare.
///
/// The ledger is shared by the gate's connections: the publish and its
/// teardown arrive on different ones — the daemon's client speaks one
/// request per connection — so a per-connection ledger would refuse every
/// honest teardown. The lock is held only across a lookup or an update,
/// never across an await.
///
/// The table is bounded like the limiter's window table
/// ([`DROP_WARN_MAX_TRACKED_PAIRS`]): the honest guest's forwards are a
/// handful per box, and a guest that fills the bound is not rewarded — the
/// oldest attribution is evicted, which can only turn a later retraction of
/// that listener into a refusal.
#[derive(Debug, Default)]
struct PublishedForwards {
    applied: Mutex<Vec<(Listener, [u8; 4])>>,
}

/// A forwarder listener: its loopback address and port.
type Listener = ([u8; 4], u16);

/// How many applied publishes' attributions the ledger keeps.
const PUBLISHED_FORWARDS_TRACKED: usize = 1024;

impl PublishedForwards {
    /// A ledger with no applied publishes in it.
    fn new() -> Self {
        Self {
            applied: Mutex::new(Vec::new()),
        }
    }

    /// Notes the address an applied publish's listener was applied at. The
    /// listener is keyed first — gvproxy binds one forwarder per loopback
    /// listener, so a second publish for a held listener never becomes live —
    /// and the ledger is bounded oldest-first, so the honest handful never
    /// reaches the bound.
    fn note_published(&self, listener: Listener, addr: [u8; 4]) {
        let mut applied = self.lock();
        if applied.iter().any(|(held, _)| *held == listener) {
            return;
        }
        if applied.len() >= PUBLISHED_FORWARDS_TRACKED {
            applied.remove(0);
        }
        applied.push((listener, addr));
    }

    /// Drops the attribution an applied retraction's listener carried: the
    /// publication is gone, and a later retraction of the same listener has
    /// nothing left to name.
    fn note_retracted(&self, listener: Listener) {
        self.lock().retain(|(held, _)| *held != listener);
    }

    /// The address the applied publish of `listener` was applied at, when
    /// one is in the ledger.
    fn address_of(&self, listener: Listener) -> Option<[u8; 4]> {
        self.lock()
            .iter()
            .find(|(held, _)| *held == listener)
            .map(|(_, addr)| *addr)
    }

    fn lock(&self) -> MutexGuard<'_, Vec<(Listener, [u8; 4])>> {
        self.applied.lock().expect(
            "the ledger's lock is held only across a lookup or an update, never across a panic",
        )
    }
}

/// Decides one control request against the host-side table (NET-081's
/// publish half, applied at relay level): summarize the request the verb and
/// body ask the switch for, decide it with the pure decision
/// ([`sessions::core::switch_request::applied`]) against a table built from
/// this gate's rows, and hand the relay either the admission or the refusal
/// its warn line is rendered from. The parsing is per-verb — the three body
/// shapes the daemon's own client sends — and every shape failure is the
/// [`MALFORMED_PUBLISH_RULE`] refusal, because a body the gate cannot
/// summarize is not a request the gate can decide.
///
/// The name records are indices into the dictionary this decision builds:
/// the rows' own names — the session name each row was registered under —
/// and declared names interned first, in switch-address order, then the
/// request's own — a name no row holds gets a fresh index no row holds, so
/// the decision refuses it without a second code path. The
/// dictionary is per decision, bounded by [`MAX_REQUEST_NAME_INDEX`]: a
/// decision with more distinct names in play than an index can name is
/// refused rather than wrapped, because an index that wraps is a different
/// record than the one the guest named.
///
/// A retraction's summary is keyed at the address the gate's ledger holds
/// for the listener it names — the one the publish it retracts was applied
/// at ([`PublishedForwards`]) — or at the unspecified one when no applied
/// publish names that listener, which no row holds and nothing applies.
fn decide_control_request(
    verb: ControlVerb,
    body: &[u8],
    table: &BoxTable,
    phase: UnregisteredSourcePhase,
    forwards: &PublishedForwards,
) -> Result<ControlDecision, RefusedRequest> {
    let mut dictionary = Vec::new();
    let rows = table.rows();
    let Some(switch_rows) = switch_rows_of(&rows, &mut dictionary) else {
        return Err(RefusedRequest {
            rule: MALFORMED_PUBLISH_RULE,
            addr: None,
            what: None,
            reason: "the published rows carry more distinct names than one \
                     decision can index"
                .to_string(),
        });
    };
    let (first_ptask, last_ptask) = table.ptask_run();
    let switch_table = SwitchTable::of(switch_rows, first_ptask, last_ptask);
    let request = match verb {
        ControlVerb::Expose => summarize_expose(body)?,
        ControlVerb::Unexpose => summarize_unexpose(body, forwards)?,
        ControlVerb::DnsAdd => summarize_dns_add(body, &mut dictionary)?,
    };
    let applied = switch_request::applied(&request, &switch_table, phase.into_sessions_phase());
    match applied {
        Ok(applied) => Ok(ControlDecision {
            applied,
            request,
            dictionary,
        }),
        Err(refusal) => {
            let (rule, addr, what) = match &refusal {
                Refusal::UnknownAddress { addr } => {
                    (UNKNOWN_PUBLISH_ADDRESS_RULE, Some(*addr), None)
                }
                Refusal::Undeclared { addr, record } => (
                    UNDECLARED_PUBLISH_RECORD_RULE,
                    Some(*addr),
                    Some(render_record(*record, &dictionary)),
                ),
                Refusal::Unheld { addr, record } => (
                    UNDECLARED_RETRACT_RULE,
                    Some(*addr),
                    record.map(|record| render_record(record, &dictionary)),
                ),
            };
            Err(RefusedRequest {
                rule,
                addr,
                what,
                // The reason is the decision's own sentence, not a paraphrase
                // of it: one place says why, and both the log line and the
                // decision's docs read it there.
                reason: refusal.to_string(),
            })
        }
    }
}

/// The published rows, as the pure decision's table: one [`SwitchRow`] per
/// published namespace, carrying the ports and names the publish decision
/// admits records by. The name indices come out of `dictionary`, which this
/// seeds with the rows' own names — the session name the row was registered
/// under, lowercased as the daemon's client spells its zone records, the one
/// name the daemon publishes for its box without any declaration carrying it
/// — and then the rows' declared names, in switch-address order; `None` when
/// the rows carry more distinct names than a `u8` index can name — a shape
/// the honest registry cannot reach, refused closed.
fn switch_rows_of(rows: &[Arc<BoxRecord>], dictionary: &mut Vec<String>) -> Option<Vec<SwitchRow>> {
    let mut seen: HashMap<String, u8> = HashMap::new();
    let mut switch_rows = Vec::with_capacity(rows.len());
    for record in rows {
        let own = record.name().to_ascii_lowercase();
        let mut names = Vec::with_capacity(record.declared_names().len() + 1);
        for name in
            std::iter::once(own.as_str()).chain(record.declared_names().iter().map(String::as_str))
        {
            let index = match seen.get(name) {
                Some(&index) => index,
                None => {
                    let index = u8::try_from(dictionary.len()).ok()?;
                    seen.insert(name.to_string(), index);
                    dictionary.push(name.to_string());
                    index
                }
            };
            names.push(index);
        }
        // The row's runtime-published set — the ports the box's own listens
        // published, the only ones a retraction at its address is applied
        // for — is empty until listen-publishing (NET-016, NET-017) lands:
        // today no guest retraction at a held address is applied, and a
        // declared port's forward never is.
        switch_rows.push(SwitchRow::of(
            record.switch_addr().octets(),
            record.admitted_ports().to_vec(),
            names,
        ));
    }
    Some(switch_rows)
}

/// Renders one record for a warn line: the port as a port, the name as the
/// name the decision's dictionary held — truncated to the bound a refused
/// head's target is named at, so a hostile name cannot shout a line long.
/// The cut lands on a char boundary: the name is a guest's bytes, and a
/// multi-byte character straddling the bound must not panic the warn path.
fn render_record(record: Record, dictionary: &[String]) -> String {
    match record {
        Record::Port(port) => format!("port {port}"),
        Record::Name(index) => dictionary.get(usize::from(index)).map_or_else(
            || format!("name #{index}"),
            |name| {
                let mut named = format!("name {name:?}");
                if named.len() > MAX_NAMED_TARGET {
                    named.truncate(named.floor_char_boundary(MAX_NAMED_TARGET));
                }
                named
            },
        ),
    }
}

/// Emits the interim's line for one admitted request: the same rate limit a
/// drop's line answers to — one per address per interval — because a box
/// whose row no creator has supplied yet publishes on every daemon boot, and
/// the point of the line is that a host running the interim can see it, not
/// that it can be flooded by it. The line is marked `interim`, so a bundle's
/// log tail tells an applied interim from a refusal under the same rule.
/// Returns whether a line was written.
fn warn_interim_publish(limiter: &DropLimiter, decision: &ControlDecision) -> bool {
    let request = &decision.request;
    let addr = request.switch_addr();
    let what = request
        .records()
        .next()
        .map(|record| render_record(record, &decision.dictionary));
    match limiter.should_warn_at(Some(addr), UNREGISTERED_PUBLISH_RULE, Instant::now()) {
        WarnDecision::Silent => false,
        WarnDecision::Named => {
            tracing::warn!(
                interim = true,
                source = %Ipv4Addr::from(addr),
                port_or_name = %what.as_deref().unwrap_or("none"),
                rule_matched = UNREGISTERED_PUBLISH_RULE,
                "applied a switch request at an in-plan address no published \
                 namespace holds; the row that bounds it is T66 (#1711), the \
                 creator-side registration that supplies it",
            );
            true
        }
        WarnDecision::Overflow => {
            tracing::warn!(
                interim = true,
                rule_matched = UNREGISTERED_PUBLISH_RULE,
                "applying switch requests from more distinct unregistered \
                 addresses than the gate keeps a window per source for; the \
                 row that bounds them is T66 (#1711)",
            );
            true
        }
    }
}

/// Emits the refusal line for one refused control request, at the frame
/// drops' cadence: the address, the port or name, and the reason — the three
/// things NET-081's observability asks a refusal to say, and the three a
/// diagnostic bundle's log tail is read for. Returns whether a line was
/// written.
fn refuse_request(limiter: &DropLimiter, refused: &RefusedRequest) -> bool {
    let what = refused.what.as_deref().unwrap_or("none");
    match limiter.should_warn_at(refused.addr, refused.rule, Instant::now()) {
        WarnDecision::Silent => false,
        WarnDecision::Named => {
            tracing::warn!(
                source = %refused.addr.map_or_else(
                    || "none".to_string(),
                    |addr| Ipv4Addr::from(addr).to_string()
                ),
                port_or_name = %what,
                reason = %refused.reason,
                rule_matched = refused.rule,
                "refused a switch publish at the host-side egress gate",
            );
            true
        }
        WarnDecision::Overflow => {
            tracing::warn!(
                rule_matched = refused.rule,
                "refusing publishes from more distinct addresses than the gate \
                 keeps a window per source for; one line per rule covers the rest",
            );
            true
        }
    }
}

/// The per-decision name dictionary's bound: name records are `u8` indices,
/// so a decision with more distinct names in play than this has none — the
/// honest registry's rows and the daemon's zone-adds are a handful of names,
/// and a guest able to grow a decision's dictionary past an index's range is
/// refused rather than wrapped.
const MAX_REQUEST_NAME_INDEX: usize = u8::MAX as usize;

/// The body shape the daemon's own client sends for an expose
/// (`publish_listener_on_control`,
/// `crates/minimald/src/net/policy.rs`): the loopback listener it asks the
/// host to bind and the switch address:port it asks the forwarder to dial.
#[derive(Debug, serde::Deserialize)]
struct ExposeBody {
    local: String,
    remote: String,
    protocol: String,
}

/// The body shape for a retraction: the loopback listener it retracts. The
/// wire carries no address — the gate attributes the retraction to the
/// address its listener's publish was applied at ([`PublishedForwards`]) —
/// and the protocol is checked as the client's shape and nothing more.
#[derive(Debug, serde::Deserialize)]
struct UnexposeBody {
    local: String,
    protocol: String,
}

/// The body shape for a zone-add (`dns_add_body`,
/// `crates/minimald/src/net/policy.rs`): the zone's name and the records
/// that name it. The zone's own name is the daemon's plumbing — it names
/// which zone the records land in, and the decision is about what the
/// records publish and at what address — so it is not read here; the
/// records are.
#[derive(Debug, serde::Deserialize)]
struct DnsAddBody {
    records: Vec<DnsRecordBody>,
}

/// One zone-add record: the name it publishes and the address it publishes
/// it at.
#[derive(Debug, serde::Deserialize)]
struct DnsRecordBody {
    name: String,
    ip: String,
}

/// How many records a zone-add the decision summarizes may carry: the
/// daemon's own client sends two — the bare name and the host-qualified one
/// — and a request wider than the summary holds is refused rather than
/// truncated, because a truncated request is a different request.
const MAX_ZONE_RECORDS: usize = MAX_REQUEST_RECORDS;

/// Summarizes an expose request into a [`SwitchRequest`]: the remote is the
/// switch address the forwarder dials and the address the publish is at; the
/// record is the host-side listener's port — the end the registration wire
/// carries (`RegisterBoxRequest::ingress_ports` names each declared
/// mapping's external port) and so the one the row's publish dimension
/// admits by. The mapping's inside end is not a record of the publish: it is
/// the port the forwarder dials on the target namespace, governed by that
/// namespace's own ingress declaration inside the VM — the in-guest relay
/// admits exactly the internal ports its box declared, and drops the rest —
/// and no row here can admit or refuse it, because the declaration the row
/// is compiled from never carried it. Demanding the inside end of the row
/// would refuse every mapping whose two ends differ, which is most of them.
/// The local must be the loopback the daemon's client binds on and the
/// protocol one the client spells; anything else is a body the gate does not
/// summarize.
fn summarize_expose(body: &[u8]) -> Result<SwitchRequest, RefusedRequest> {
    let malformed = |what: Option<String>| RefusedRequest {
        rule: MALFORMED_PUBLISH_RULE,
        addr: None,
        what,
        reason: "the body is not the JSON shape the daemon's own client sends \
                 for an expose"
            .to_string(),
    };
    let Ok(parsed) = serde_json_lenient::from_slice::<ExposeBody>(body) else {
        return Err(malformed(None));
    };
    let Ok(local_port) = loopback_port(&parsed.local) else {
        return Err(malformed(Some(parsed.local)));
    };
    let Some((remote_addr, _)) = host_port(&parsed.remote) else {
        return Err(malformed(Some(parsed.remote)));
    };
    if !is_client_protocol(&parsed.protocol) {
        return Err(malformed(Some(parsed.protocol)));
    }
    SwitchRequest::of(
        SwitchVerb::Publish,
        remote_addr,
        &[Record::Port(local_port)],
    )
    .ok_or_else(|| malformed(None))
}

/// Summarizes a retraction: the listener it names, keyed at the address the
/// gate's ledger holds for that listener — the one the publish it retracts
/// was applied at ([`PublishedForwards`]) — or, when no applied publish
/// names the listener, at the unspecified one, which no row holds and
/// nothing applies. The wire carries no address; the attribution is the
/// gate's, from where the publication happened and nowhere else.
fn summarize_unexpose(
    body: &[u8],
    forwards: &PublishedForwards,
) -> Result<SwitchRequest, RefusedRequest> {
    let malformed = |what: Option<String>| RefusedRequest {
        rule: MALFORMED_PUBLISH_RULE,
        addr: None,
        what,
        reason: "the body is not the JSON shape the daemon's own client sends \
                 for an unexpose"
            .to_string(),
    };
    let Ok(parsed) = serde_json_lenient::from_slice::<UnexposeBody>(body) else {
        return Err(malformed(None));
    };
    let Ok(listener) = loopback_listener(&parsed.local) else {
        return Err(malformed(Some(parsed.local)));
    };
    let (_, local_port) = listener;
    if !is_client_protocol(&parsed.protocol) {
        return Err(malformed(Some(parsed.protocol)));
    }
    let published_at = forwards.address_of(listener);
    SwitchRequest::of(
        SwitchVerb::Retract,
        published_at.unwrap_or([0, 0, 0, 0]),
        &[Record::Port(local_port)],
    )
    .ok_or_else(|| malformed(None))
}

/// Summarizes a zone-add: every record's address is the address the publish
/// is at, and every record's name becomes a name record — interned into the
/// decision's dictionary, where a name no published row declares gets a
/// fresh index no row holds and the decision refuses it on its own terms.
/// Records that disagree about the address do not summarize: a publish is
/// at one address, and a request asking for two is not the daemon's shape.
fn summarize_dns_add(
    body: &[u8],
    dictionary: &mut Vec<String>,
) -> Result<SwitchRequest, RefusedRequest> {
    let malformed = |what: Option<String>| RefusedRequest {
        rule: MALFORMED_PUBLISH_RULE,
        addr: None,
        what,
        reason: "the body is not the JSON shape the daemon's own client sends \
                 for a zone-add"
            .to_string(),
    };
    let Ok(parsed) = serde_json_lenient::from_slice::<DnsAddBody>(body) else {
        return Err(malformed(None));
    };
    if parsed.records.is_empty() || parsed.records.len() > MAX_ZONE_RECORDS {
        return Err(malformed(None));
    }
    let mut records = Vec::with_capacity(parsed.records.len());
    let mut addr: Option<[u8; 4]> = None;
    for record in &parsed.records {
        let record_addr = Ipv4Addr::from_str(&record.ip)
            .map(|ip| ip.octets())
            .map_err(|_| malformed(Some(record.ip.clone())))?;
        match addr {
            Some(seen) if seen != record_addr => {
                return Err(malformed(Some(record.ip.clone())));
            }
            _ => addr = Some(record_addr),
        }
        if dictionary.len() >= MAX_REQUEST_NAME_INDEX {
            return Err(malformed(Some(record.name.clone())));
        }
        // A record a row already holds a name for is that row's own: the
        // bare form exact-matches, and the host-qualified form the daemon
        // publishes beside it (`<name>.<host-id>`, NET-002) dot-extends it —
        // the host ids a shared switch answers for are every co-resident
        // daemon's, unbounded, so no declaration can carry the qualified form
        // and the publish maps it onto the held name's index instead. The
        // dot anchors the match at the name's boundary, so `web` does not
        // swallow `webmail`; and the decision's address keying keeps the
        // mapping the owner's — the row that decides the publish is the row
        // at the records' common address, and only that row's held index
        // applies it. A name neither held nor extending one is fresh, a
        // fresh index no row holds, and the decision refuses it.
        let index = dictionary
            .iter()
            .position(|held| held == &record.name)
            .or_else(|| {
                dictionary.iter().position(|held| {
                    record
                        .name
                        .strip_prefix(held.as_str())
                        .is_some_and(|rest| rest.starts_with('.'))
                })
            })
            .unwrap_or_else(|| {
                dictionary.push(record.name.clone());
                dictionary.len() - 1
            });
        records.push(Record::Name(
            u8::try_from(index).expect("the dictionary is bounded below the index's range"),
        ));
    }
    let addr = addr.unwrap_or([0, 0, 0, 0]);
    SwitchRequest::of(SwitchVerb::PublishName, addr, &records).ok_or_else(|| malformed(None))
}

/// The loopback listener a control body's `local` field carries, as the
/// daemon's own client builds it — in either of its two spellings.
/// `127.0.0.1:<port>`: the daemon's own proxy and answerer listeners
/// (`publish_listener_on_control`), and a box publishing on the
/// shared-address interim (NET-123). `<lease>:<port>` on an address of the
/// reserved local range: the box's own granted publish address (NET-010) —
/// the spelling every own-address box's ingress exposes and teardowns
/// carry — the address a VM node's shared one is granted from (NET-129),
/// and the address each round of the forwarder range probe walks
/// (NET-123). The `local` is shape, never decision: the request it
/// summarizes is keyed at the *remote* switch address and decided by the
/// port record, and the local only names where the host-side forwarder
/// binds — loopback, both spellings, never the LAN. Anything else — a
/// loopback spelling outside both, a non-loopback host, no port — is not a
/// body the gate summarizes: the host binds forwarders on the loopback the
/// daemon names, and only the daemon's own client names these two.
fn loopback_port(local: &str) -> Result<u16, ()> {
    loopback_listener(local).map(|(_, port)| port)
}

/// The forwarder listener a `local` names: its loopback address, in either
/// of [`loopback_port`]'s two spellings, and its port. A listener is the
/// pair, not the port: two boxes publishing one port at their own leased
/// addresses are two listeners, and the publish ledger keys them apart
/// ([`PublishedForwards`]).
fn loopback_listener(local: &str) -> Result<Listener, ()> {
    let (host, port) = local.rsplit_once(':').ok_or(())?;
    let addr = Ipv4Addr::from_str(host).map_err(|_| ())?;
    if addr != Ipv4Addr::LOCALHOST && !in_reserved_local_range(addr) {
        return Err(());
    }
    Ok((addr.octets(), port.parse::<u16>().map_err(|_| ())?))
}

/// The listener a forward-carrying control body names, for the publish
/// ledger: the expose's or unexpose's `local`. `None` for a zone-add, and
/// for a body that does not parse (one the decision already refused).
fn forward_listener(verb: ControlVerb, body: &[u8]) -> Option<Listener> {
    let local = match verb {
        ControlVerb::Expose => {
            serde_json_lenient::from_slice::<ExposeBody>(body)
                .ok()?
                .local
        }
        ControlVerb::Unexpose => {
            serde_json_lenient::from_slice::<UnexposeBody>(body)
                .ok()?
                .local
        }
        ControlVerb::DnsAdd => return None,
    };
    loopback_listener(&local).ok()
}

/// Whether `addr` falls in [`RESERVED_LOCAL_RANGE`] — the block published
/// addresses are granted from, read from the switch crate so the number
/// every component shares stays the one number. The same membership rule
/// the daemon's own answerer applies to a zone record
/// (`minimald::net::dns::in_reserved_local_range`).
fn in_reserved_local_range(addr: Ipv4Addr) -> bool {
    let (network, prefix) = RESERVED_LOCAL_RANGE;
    let host_bits = 32 - u32::from(prefix);
    // A /0 range would mean "every address"; the shift below needs a network
    // part to keep.
    if host_bits >= 32 {
        return true;
    }
    let mask = u32::MAX << host_bits;
    u32::from(network) & mask == u32::from(addr) & mask
}

/// A `<host>:<port>` pair with a dotted-quad host, as a forwarder's remote
/// carries it. Anything else — a bare port, a name, a bracketed IPv6 — is
/// not a switch address the gate publishes at.
fn host_port(remote: &str) -> Option<([u8; 4], u16)> {
    let (host, port) = remote.rsplit_once(':')?;
    let addr = Ipv4Addr::from_str(host).ok()?;
    let port = port.parse::<u16>().ok()?;
    Some((addr.octets(), port))
}

/// The protocol spellings the daemon's own client sends — the wire spellings
/// of `IpProto::Tcp` and `IpProto::Udp`, lowercased. The publish decision is
/// deliberately proto-blind (it decides by ports and names), so the
/// protocol is checked as shape — one of the client's own two spellings —
/// and nothing more.
fn is_client_protocol(protocol: &str) -> bool {
    matches!(protocol, "tcp" | "udp")
}

/// switch → guest, untouched. The gate applies no ingress policy and parses
/// nothing on this leg — bytes flow as they came, frames included.
async fn copy_switch_to_guest(
    mut switch: OwnedReadHalf,
    mut guest: OwnedWriteHalf,
) -> io::Result<()> {
    tokio::io::copy(&mut switch, &mut guest).await.map(|_| ())
}

/// guest → switch: the frame relay plus its end-of-connection attribution.
/// The loop itself is [`relay_frames_to_switch`]; what this wrapper owns is
/// the relay's exit: whichever way the relay ended — the guest's clean
/// close, an error on either end, or a frame claim the gate refused — the
/// addresses it carried go to the table as a withdrawal report, and the
/// relay's outcome is passed through.
async fn relay_guest_to_switch(
    mut guest: Prefixed<OwnedReadHalf>,
    mut switch: OwnedWriteHalf,
    table: BoxTable,
    baseline: NodePlaneBaseline,
    limiter: Arc<DropLimiter>,
    phase: UnregisteredSourcePhase,
) -> io::Result<()> {
    // Every admitted frame's source, deduplicated: the attribution this
    // relay files at its end. Bounded by the plan — a lease run is 254
    // addresses wide and the interim admits only inside it — so the vector
    // is bounded by the plan, not by what a guest could push through it.
    let mut attributed: Vec<[u8; 4]> = Vec::new();
    let outcome = relay_frames_to_switch(
        &mut guest,
        &mut switch,
        &table,
        &baseline,
        &limiter,
        phase,
        &mut attributed,
    )
    .await;
    // The relay is over, whichever way it ended — the guest's clean close, an
    // error on either end, or a frame claim the gate refused. What it
    // relayed is what it attributes: the rows whose traffic this connection
    // carried are withdrawn now that nothing is left carrying it. The guest
    // relay never reconnects a closed shuttle connection
    // (`attach_to_switch_vsock` in the guest's relay), so egress at those
    // addresses is already down; the withdrawal is what makes that true of
    // the table too, so a re-attachment starts from a registration and not
    // from a row whose connection is gone (NET-133: a box's row goes with
    // its shuttle connection). A control connection files no report at all:
    // one fresh connection per control request is the daemon's own client's
    // shape, and constant churn is not box end.
    table.report_withdrawals(std::mem::take(&mut attributed));
    outcome
}

/// The frame relay's loop, inside [`relay_guest_to_switch`]'s attribution:
/// read one length-framed Ethernet frame, decide it against the host-side
/// table ([`gate_verdict`]), and write the frame on only when it is
/// admitted. A dropped frame is simply not written on — nothing is sent back
/// toward the guest either; a drop is not a reset (NET-062) — and its class
/// says so once per source address per rule per interval, so a flood inside
/// the VM produces a steady, readable account of what the host is dropping
/// rather than a log flood.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the `n > frame.len()` rejection above"
)]
async fn relay_frames_to_switch(
    guest: &mut Prefixed<OwnedReadHalf>,
    switch: &mut OwnedWriteHalf,
    table: &BoxTable,
    baseline: &NodePlaneBaseline,
    limiter: &DropLimiter,
    phase: UnregisteredSourcePhase,
    attributed: &mut Vec<[u8; 4]>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; max_frame()];
    loop {
        match guest.read_exact(&mut len_buf).await {
            // The count is the buffer's length by construction; only the
            // error half carries information.
            Ok(_) => {}
            // A clean close of the guest ends the relay without error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        if n == 0 {
            // A zero-length claim carries no frame to decide; skip the claim
            // rather than read past it.
            continue;
        }
        // Trust nothing the guest claims about length: a frame past the
        // MTU-derived maximum would overrun the buffer and points at a
        // malformed or hostile peer, so refuse it rather than size an
        // allocation to it. The connection comes down — the gate fails
        // closed, never forward.
        if n > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest frame length {n} exceeds max {}", frame.len()),
            ));
        }
        guest.read_exact(&mut frame[..n]).await?;
        let summary = egress::summarize(&frame[..n]);
        let admitted = match gate_verdict(&summary, table, baseline, phase) {
            Ok(admitted) => admitted,
            Err(GateDrop::SwitchControlSurface { src, dst_port }) => {
                limiter.warn_switch_surface(src, dst_port);
                continue;
            }
            Err(GateDrop::Infrastructure { src, dst, dst_port }) => {
                limiter.warn_infrastructure(src, dst, dst_port);
                continue;
            }
            Err(dropped) => {
                limiter.emit(summary.source(), dropped.rule());
                continue;
            }
        };
        // The interim's admit is the one admission that owes a line: no row
        // bounded this frame, and the host must be able to see that it passed.
        if let GateAdmit::Unregistered { src } = admitted {
            limiter.warn_unregistered(src);
        }
        // Whatever admitted the frame — the baseline set, a row's own rules
        // or the interim — the address it came from was live traffic on this
        // connection, and this connection's end retires it. The node plane's
        // own address is the one exception: the row that decides its frames
        // is the host's own registration for the VM's lifetime
        // ([`BoxRegistry::register_node_namespace`], filed once at boot),
        // not a box's row that goes with its shuttle connection (NET-133),
        // and nothing would ever give the address its reach back — the
        // announced interim reaches lease-run addresses only, and the plan
        // keeps the node's address outside that run. So the drainer must
        // never see it: one relay's end retiring the node's row would leave
        // the daemon frameless and unpublishable for the rest of the VM's
        // life, over a shuttle close its control path rode out.
        let src = match admitted {
            GateAdmit::Baseline | GateAdmit::Row => summary.source(),
            GateAdmit::Unregistered { src } => Some(src),
        };
        if let Some(src) = src
            && src != baseline.node_addr()
            && !attributed.contains(&src)
        {
            attributed.push(src);
        }
        // One combined write keeps the length prefix and the frame together
        // even if the switch closes between two writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&frame[..n]);
        switch.write_all(&framed).await?;
    }
}

/// The phase the per-box default for unregistered sources is at — the same
/// cutover shape the guest's own egress-default rollout
/// ([`sessions::EGRESS_DEFAULT_PHASE`]) models: a named phase, read by the
/// decision, flipped by one constant.
///
/// NET-081's per-box rules are decided by rows the host-side creator supplies
/// (design §7.1: facts delivered before a box's first connection, withdrawn at
/// box end) — and no creator supplies them yet. The registration path that
/// carries a client's box declarations into the host table is T66's (#1711),
/// and the lease an own-address box holds is minted *inside* the VM, by the
/// guest daemon's own allocator, so until that lands no host-side process can
/// name a box's address. An own-address box's lease is, today, a source no
/// row holds.
///
/// [`UnregisteredSourcePhase::InForce`] is the conforming default: no row, no
/// egress — NET-081's failure case, held to every address the table does not
/// publish. [`UnregisteredSourcePhase::Announced`] is the interim that keeps
/// those boxes on the wire in the meantime: a source inside the plan's lease
/// block is admitted — the reach the box had before the gate existed, which
/// the in-guest relay still bounds by the box's own declared rules — and every
/// admit says so, rate-limited, naming T66. Sources outside the lease block
/// are rule 0's under either phase: the plan never hands them out, so no row
/// will ever hold them, and they are refused before any interim is consulted.
///
/// Two bounds the interim's admits carry, the same for as long as the
/// announced arm is shipped: the phase is read once per build — one constant,
/// [`UNREGISTERED_SOURCE_PHASE`] — and never changes while a VM runs, so a
/// flip is the next release's boot and a bundle's logs read one posture per
/// daemon lifetime; and the interim admits lease-run addresses only — the
/// plan's ptask lease run is what in-plan means — never the node plane's own
/// address and never the plan's reserved pair, the infrastructure the plan
/// keeps for itself, which no lease run hands out and which are refused under
/// either phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnregisteredSourcePhase {
    /// The per-box default is announced, not yet binding: an unregistered
    /// source inside the plan's lease block is admitted under the shipped
    /// allow-all default, and every admit warns, naming T66 (#1711).
    Announced,
    /// The per-box default binds: a source no row holds is dropped, whatever
    /// the plan could have done with its address.
    ///
    /// Constructed today only by the tests that pin the phase's other arm —
    /// the pure decision below, and the relay-level gate built with
    /// [`EgressGate::spawn_with_phase`] — the arm T66 (#1711) flips
    /// [`UNREGISTERED_SOURCE_PHASE`] onto, which is when this expectation goes
    /// unfulfilled and asks for its removal. After that flip the dead variant
    /// in non-test builds is [`UnregisteredSourcePhase::Announced`] instead,
    /// and this expectation moves to it: the mirror of the cutover, named
    /// here so T66's handoff has it in one place.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "constructed today only by the tests that pin the phase's other arm; \
                      T66 (#1711) makes the shipped constant this variant, which unfulfills \
                      this expectation and asks for its removal"
        )
    )]
    InForce,
}

impl UnregisteredSourcePhase {
    /// The phase as the value the gate's start-up line logs: a host reads its
    /// own posture off the one line every boot writes, so a host running the
    /// interim can tell it is.
    fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "admitted-in-plan (per-box with T66, #1711)",
            Self::InForce => "dropped (per-box default in force)",
        }
    }

    /// The same cutover, as the pure publish decision's own phase shape
    /// ([`EgressDefaultPhase`]): the frame half and the publish half read
    /// one phase, so T66's flip of [`UNREGISTERED_SOURCE_PHASE`] moves both
    /// at once and neither can drift ahead of the other.
    fn into_sessions_phase(self) -> EgressDefaultPhase {
        match self {
            Self::Announced => EgressDefaultPhase::Announced,
            Self::InForce => EgressDefaultPhase::InForce,
        }
    }
}

/// The phase this build ships: announced, because the rows the default needs
/// are not here to bind to. T66 (#1711) — the creator-side registration that
/// supplies each box's row before its first frame — is the change that flips
/// this constant, and this constant is the whole cutover: the decision reads
/// it ([`gate_verdict`]), the start-up line logs it, and the tests pin both of
/// its arms, so the flip is one line and nothing else. Two things the flip
/// does not touch: what production can build — a production caller reaches
/// [`EgressGate::spawn`] and no other constructor, so the phase a shipped
/// gate runs is the phase this build ships — and the relay-level test that
/// pins the in-force arm through [`EgressGate::spawn_with_phase`], which is
/// green before the flip and proves the shipped gate's default-deny after it,
/// so T66's flip has its proof already standing rather than tests to rewrite.
pub(crate) const UNREGISTERED_SOURCE_PHASE: UnregisteredSourcePhase =
    UnregisteredSourcePhase::Announced;

/// What the gate decided one frame's admission by: which of the three ways in —
/// the node-plane baseline set, a published namespace's own rules, or the
/// announced interim's default for a source the plan could have leased but no
/// row holds. The relay that feeds on this distinguishes the interim's admit
/// for the one thing only it needs: a line that says it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateAdmit {
    /// The node-plane baseline's compiled set admitted the frame: its source
    /// is the in-VM daemon's own address and the destination is inside the
    /// helper's enumeration of the categories the node plane may reach
    /// (NET-130) — the decision the boxes' rows cannot make for it, and the
    /// one a deny-all box's row must not override.
    Baseline,
    /// A published namespace's row admitted the frame under its own rules —
    /// the same decision the in-guest relay makes, now made outside; the one
    /// drop class the row defers to the guest's decision is the
    /// undeclared-destination one for a row that declared DNS hosts, whose
    /// name-based admission the host's rules cannot carry.
    Row,
    /// The announced interim admitted the frame: its source is an address the
    /// plan could hand to a box but no published namespace holds, so no rules
    /// were consulted and no lease was checked. The relay warns, naming T66
    /// (#1711), and writes the frame on.
    Unregistered {
        /// The source address no row holds.
        src: [u8; 4],
    },
}

/// The gate's admit-or-drop decision for one frame summary against the
/// host-side table (NET-081): pure — a function of the summary, the table,
/// the baseline set, and the phase, nothing else — and deliberately separate
/// from the relay loop that applies it, the same discipline the shared
/// verdict keeps.
///
/// The frame's source address is the whole of the routing: the node plane's
/// own address is decided by the baseline set ([`NodePlaneBaseline`], the
/// helper's enumeration of the categories the in-VM daemon's traffic may
/// reach, NET-130), the published namespace that holds any other source
/// supplies the rules its frames are decided by, and an address neither
/// covers is the phase's to decide — [`UnregisteredSourcePhase`] carries what
/// that means and why. The node plane is decided before the table because the
/// run path's row for the daemon's address is the allow-all interim the
/// enumeration replaces: consulted first, it would make the enumeration
/// decorative. Families that carry no readable source address (IPv6,
/// undeclared ethertypes, truncated frames) never reach the table: the shared
/// verdict's own family drops decide them, under any rules, fail-closed.
///
/// Two destinations no row decides either, in every phase. The switch's own
/// address ([`SWITCH_CONTROL_RULE`]) is refused for everything but TCP or UDP
/// to the resolver's port, before the row's decision and the interim. And the
/// §5.3 infrastructure deny set ([`INFRASTRUCTURE_RULE`]) is refused for
/// every row, between the source's routing and the row's own rules: the set
/// applies to every box-plane packet, CIDR-admitted direct-IP flows included,
/// so a row's `allow_subnets` admits nothing in it — RFC 1918 under an
/// explicit allowance excepted — and the deferral a name-declaring row earns
/// for its undeclared destinations never reaches it. The order is the
/// contract: control surface, then the source (a baseline-decided node
/// frame, a row, or the phase's unknown-source decision), then the
/// infrastructure set, then the row's rules, then the deferral arm.
fn gate_verdict(
    summary: &FrameSummary,
    table: &BoxTable,
    baseline: &NodePlaneBaseline,
    phase: UnregisteredSourcePhase,
) -> Result<GateAdmit, GateDrop> {
    let Some(src) = summary.source() else {
        return Err(GateDrop::Verdict(family_drop(summary.family())));
    };
    // The node plane's own frames, when the baseline is in force: the shared
    // verdict against the enumeration's compiled set — the lease it is keyed
    // to is the daemon's own address, so the check above and the lease agree
    // on who may wear it. Announced, the interim node row keeps deciding the
    // node plane, and the fall-through reaches it below.
    if baseline.phase() == NodeBaselinePhase::InForce && src == baseline.node_addr() {
        return match egress::verdict(summary, baseline.rules()) {
            FrameVerdict::Admit => Ok(GateAdmit::Baseline),
            FrameVerdict::Drop(reason) => Err(GateDrop::Verdict(reason)),
        };
    }
    // The switch's own address is a control surface, not a destination a
    // box's egress rules decide (design §4.1, §7.1). Every frame from a box
    // to the gateway — the address the resolver answers at, and the one
    // gvproxy's API listens on — is refused unless it is TCP or UDP to the
    // resolver's port, whatever the rows and the phase would say about the
    // rest of the frame: any other port, and any other protocol (ICMP has no
    // port to carve out by), points at the switch itself. A row's admitted
    // ports are no exception — they are the box's own ingress, what others
    // reach on the box's address through the switch's forwarders, and no
    // box-to-gateway flow at them exists. The check sits before the row's
    // decision and before the interim, so no allow-all row and no announced
    // concession can admit a frame at the switch's own address, and it reads
    // no phase at all, so it binds unchanged when the per-box default binds.
    // The resolver carve-out falls through to the decision behind this check
    // — the row's own rules or the phase — which still decides it, so the
    // carve-out admits exactly what it admitted before, and the refusal adds
    // a ceiling without moving any floor.
    if summary.destination() == Some(table.gateway()) {
        let dst_port = summary.destination_port();
        let resolver_query = summary
            .protocol()
            .is_some_and(|proto| RESOLVER_PROTOCOLS.contains(&proto))
            && dst_port == RESOLVER_PORT;
        if !resolver_query {
            return Err(GateDrop::SwitchControlSurface { src, dst_port });
        }
    }
    // No namespace holds the source. Inside the plan's lease block the
    // announced interim admits it — an own-address box's lease is minted
    // inside the VM, and the creator-side registration that will publish its
    // row (T66, #1711) is the only thing that ever will — and the relay says
    // so on every admit. Outside that block, or once the default binds,
    // NET-081's failure case: an address no namespace holds never leaves the
    // VM.
    let record = table.by_source(src);
    if record.is_none()
        && !(phase == UnregisteredSourcePhase::Announced && table.is_allocatable(src))
    {
        return Err(GateDrop::UnknownSource { src });
    }
    // The infrastructure deny set, decided for every row before the row's
    // own rules (design §5.3, NET-067): the host and the fabric, not
    // destinations — link-local and the metadata services in it, loopback,
    // the plane outside the node's own block, and RFC 1918 space the row's
    // `allow_subnets` does not cover. Decided here, between the source's
    // routing and the row's rules, so that no row admits it — an allow-all
    // row's `0.0.0.0/0` included, the CIDR-admitted direct-IP flow the set
    // names — and so that the deferral below never sees it: an undeclared
    // destination inside the set is this drop, not the guest's to lift. A
    // source the announced interim admits without a row takes it too, as
    // allow-all for RFC 1918 space: the set applies to every box-plane
    // packet, and the interim concedes a row's absence, not the fabric.
    if let Some(dst) = summary.destination()
        && infrastructure_destination(
            dst,
            table.subnet(),
            record.as_ref().and_then(|row| row.egress().allow_subnets()),
        )
    {
        return Err(GateDrop::Infrastructure {
            src,
            dst,
            dst_port: summary.destination_port(),
        });
    }
    let Some(record) = record else {
        return Ok(GateAdmit::Unregistered { src });
    };
    // The namespace that holds the source decides its frames by its own
    // compiled rules — the shared verdict, unchanged, now made outside where
    // nothing inside can change it. One drop class defers to the in-guest
    // decision instead of being made here: a row that declared DNS hosts has
    // a name-based admission its frame rules cannot carry (NET-066 lives in
    // the guest's gate, resolution-time pins the host never sees), so the
    // guest lifts an undeclared-destination drop when its box's gate holds a
    // pin for the destination — the same frame, decided by the same
    // declaration, where the pins actually are. Deferring it here is the only
    // way the two halves agree; making it here would drop every pinned frame
    // the guest admitted, a host-side veto over an admission the box's own
    // declaration granted. Everything else stays host-made: a denied
    // destination, an infrastructure destination (decided above, before this
    // arm can see it), an undeclared protocol, a foreign source, a family the
    // verdict reads no source from — a pin governs none of those, and the
    // guest lifts none of them either, so the host refusing them is parity,
    // not pre-emption.
    match egress::verdict(summary, record.egress()) {
        FrameVerdict::Admit => Ok(GateAdmit::Row),
        FrameVerdict::Drop(reason)
            if matches!(reason, DropReason::UndeclaredSubnet { .. }) && record.resolves_names() =>
        {
            Ok(GateAdmit::Row)
        }
        FrameVerdict::Drop(reason) => Err(GateDrop::Verdict(reason)),
    }
}

/// Why the gate dropped a frame: the shared verdict's reason, or one of the
/// three classes the host table adds — a source address no published
/// namespace holds (NET-081's failure case), a frame the switch's own address
/// would have received on a port nothing published answers, and a frame
/// headed into the infrastructure deny set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateDrop {
    /// The shared frame verdict dropped it: the namespace's own rules, its
    /// lease check, or its family.
    Verdict(DropReason),
    /// The frame's source address belongs to no published namespace.
    UnknownSource {
        /// The source address no namespace holds.
        src: [u8; 4],
    },
    /// The frame named the switch's own address and was not a TCP or UDP
    /// query to the resolver's port: the switch's control surface is not a
    /// destination a box's egress rules decide ([`SWITCH_CONTROL_RULE`]).
    SwitchControlSurface {
        /// The source address the frame wore.
        src: [u8; 4],
        /// The port the frame named at the gateway.
        dst_port: u16,
    },
    /// The frame named a destination in the infrastructure deny set — the
    /// host and the fabric, not a destination any row's rules admit
    /// ([`INFRASTRUCTURE_RULE`]).
    Infrastructure {
        /// The source address the frame wore.
        src: [u8; 4],
        /// The destination inside the set.
        dst: [u8; 4],
        /// The port the frame named there, `0` when it carried none.
        dst_port: u16,
    },
}

impl GateDrop {
    /// The rule that dropped the frame: the rate-limit key and the warning's
    /// `rule_matched` field.
    fn rule(&self) -> &'static str {
        match self {
            Self::Verdict(reason) => reason.rule(),
            Self::Infrastructure { .. } => INFRASTRUCTURE_RULE,
            Self::UnknownSource { .. } => UNKNOWN_SOURCE_RULE,
            Self::SwitchControlSurface { .. } => SWITCH_CONTROL_RULE,
        }
    }
}

/// The shared verdict's family drop for a frame that carries no readable
/// source: the families decided without rules, and the fail-closed answer for
/// an arm the summarizer's contract makes unreachable (an ARP or IPv4 frame
/// always carries a source, so one without is truncated).
fn family_drop(family: FrameFamily) -> DropReason {
    match family {
        FrameFamily::Ipv6 => DropReason::Ipv6,
        FrameFamily::UndeclaredFamily(ethertype) => DropReason::UndeclaredFamily(ethertype),
        FrameFamily::Truncated | FrameFamily::Arp | FrameFamily::Ipv4 => DropReason::Truncated,
    }
}

/// The rate-limit key: a dropped frame's source address under the rule that
/// dropped it — `None` for a frame with no readable source — or, past
/// [`DROP_WARN_MAX_TRACKED_PAIRS`], the rule alone.
#[derive(Debug, Hash, PartialEq, Eq)]
enum DropKey {
    /// One source address under one rule: the two things the drop line names.
    Source(Option<[u8; 4]>, &'static str),
    /// The rule's shared window, which every pair the table held no room for
    /// is folded into.
    Overflow(&'static str),
}

/// What the limiter decided for one dropped frame: whether a warning fires,
/// and which window it fires under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarnDecision {
    /// The pair's own window fired: emit the line naming its source.
    Named,
    /// The pair table is full of live windows, so the rule's shared window
    /// fired instead: emit the flood line, naming no source.
    Overflow,
    /// A window fired inside the interval: emit nothing.
    Silent,
}

/// The gate's rate limiter: one warning per source address per rule per
/// [`DROP_WARN_MIN_INTERVAL`], keyed by the two things the line names — a
/// drop's, or the interim admit's. Keyed per source and per rule both, so one
/// address's flood neither silences another's single line nor merges two rules
/// into one.
///
/// The window table is bounded at [`DROP_WARN_MAX_TRACKED_PAIRS`] — the
/// source address it keys by is the frame's own bytes, chosen by the guest,
/// and the guest is the side this gate exists to contain — so the throttling
/// cannot be turned into host-memory growth.
#[derive(Debug, Default)]
struct DropLimiter {
    last: Mutex<HashMap<DropKey, Instant>>,
}

impl DropLimiter {
    /// A fresh limiter that has never emitted for any source or rule.
    fn new() -> Self {
        Self::default()
    }

    /// Whether the drop of `src` under `rule` warns at `now`, and which
    /// window the warning comes under, recording `now` in that window when
    /// one fires. Split from [`emit`](Self::emit) so the rate-limit decision
    /// is testable without a clock or a `tracing` subscriber.
    fn should_warn_at(
        &self,
        src: Option<[u8; 4]>,
        rule: &'static str,
        now: Instant,
    ) -> WarnDecision {
        let mut last = self
            .last
            .lock()
            .expect("the limiter's lock is held only across this lookup, never across a panic");
        let key = DropKey::Source(src, rule);
        if let Some(prev) = last.get(&key)
            && now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL
        {
            return WarnDecision::Silent;
        }
        if last.len() >= DROP_WARN_MAX_TRACKED_PAIRS {
            // The table is at its bound. Drop the windows that have gone
            // stale — their pairs would fire afresh on re-insertion anyway —
            // before folding this one into a shared line: a flood that has
            // ended must not leave honest sources unnamed forever after.
            last.retain(|_, at| now.duration_since(*at) < DROP_WARN_MIN_INTERVAL);
        }
        if last.len() < DROP_WARN_MAX_TRACKED_PAIRS {
            last.insert(key, now);
            return WarnDecision::Named;
        }
        // Still full: every window is live, so more distinct sources are
        // dropping within this interval than the table holds — a spoofed
        // flood by shape. One shared window per rule, so the flood costs no
        // memory and at most one line per rule per interval.
        match last.get(&DropKey::Overflow(rule)) {
            Some(prev) if now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL => {
                WarnDecision::Silent
            }
            _ => {
                last.insert(DropKey::Overflow(rule), now);
                WarnDecision::Overflow
            }
        }
    }

    /// Emits the drop warning for one dropped frame if the rate limit allows:
    /// the source address the frame carried — `none` when the frame carried
    /// none to read, as for an IPv6 or truncated drop — and the rule that
    /// dropped it, the two fields NET-081's observability asks for; or, when
    /// more distinct sources are dropping than the table keeps windows for,
    /// one line per rule naming the flood instead. Returns whether a line
    /// was written.
    fn emit(&self, src: Option<[u8; 4]>, rule: &'static str) -> bool {
        match self.should_warn_at(src, rule, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                let source =
                    src.map_or_else(|| "none".to_string(), |src| Ipv4Addr::from(src).to_string());
                tracing::warn!(
                    source = %source,
                    rule_matched = rule,
                    "dropped a frame leaving the VM at the host-side egress gate",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = rule,
                    "dropped frames from more distinct source addresses than the gate \
                     keeps a window per source for; one line per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the warning for one frame the switch's own address would have
    /// received: the same rate limit a drop's line answers to, keyed by the
    /// source and the rule, and naming the port the frame gave the gateway —
    /// the line a host reads to learn which port of the switch's control
    /// surface a box was reaching for. Returns whether a line was written.
    fn warn_switch_surface(&self, src: [u8; 4], dst_port: u16) -> bool {
        match self.should_warn_at(Some(src), SWITCH_CONTROL_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    port = dst_port,
                    rule_matched = SWITCH_CONTROL_RULE,
                    "dropped a frame to the switch's own address; its control surface is not \
                     a destination a box's egress rules decide, and nothing answers a box \
                     there but its resolver",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = SWITCH_CONTROL_RULE,
                    "dropped frames to the switch's own address from more distinct source \
                     addresses than the gate keeps a window per source for; one line per \
                     rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the warning for one frame headed into the infrastructure deny
    /// set: the same rate limit a drop's line answers to, keyed by the source
    /// and the rule, and naming the destination and the port the frame gave
    /// it — the line a host reads to learn which piece of the host or the
    /// fabric a box was reaching for. Returns whether a line was written.
    fn warn_infrastructure(&self, src: [u8; 4], dst: [u8; 4], dst_port: u16) -> bool {
        match self.should_warn_at(Some(src), INFRASTRUCTURE_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    destination = %Ipv4Addr::from(dst),
                    port = dst_port,
                    rule_matched = INFRASTRUCTURE_RULE,
                    "dropped a frame to an infrastructure destination; the host and the \
                     fabric are not destinations a box's egress rules admit",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = INFRASTRUCTURE_RULE,
                    "dropped frames to infrastructure destinations from more distinct \
                     source addresses than the gate keeps a window per source for; one \
                     line per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the interim's line for one admitted-unregistered source: the same
    /// rate limit a drop's line answers to — one per source per interval —
    /// because a box whose lease no row holds admits on every frame it sends,
    /// and the point of the line is that a host running the interim can see
    /// it, not that it can be flooded by it. Returns whether a line was
    /// written.
    fn warn_unregistered(&self, src: [u8; 4]) -> bool {
        match self.should_warn_at(Some(src), UNREGISTERED_SOURCE_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    rule_matched = UNREGISTERED_SOURCE_RULE,
                    "admitted a frame leaving the VM from an in-plan address no published \
                     namespace holds; per-box enforcement of it is T66 (#1711), the \
                     creator-side registration that supplies the row",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = UNREGISTERED_SOURCE_RULE,
                    "admitting frames from more distinct unregistered addresses than the \
                     gate keeps a window per source for; per-box enforcement is T66 (#1711)",
                );
                true
            }
        }
    }
}

/// Reads the head of the guest's first request — through the first
/// [`HEAD_END`] — returning it and any bytes read past it: one `read` can
/// carry the head and what follows it together, and those bytes belong to
/// whichever protocol the head names — the upgrade's first frames, or a
/// control request's body — so the relay must not lose them.
///
/// The head is read for both protocols the switch socket speaks, not only the
/// upgrade: what it asks for is what picks the relay ([`GuestSpeak`]) — and
/// decides whether the gate forwards it at all. Each read takes at most
/// [`HEAD_READ_CHUNK`] bytes, from a fixed-size scratch, so the head's buffer
/// grows by bounded steps and its high-water mark is [`MAX_HEAD`] plus one
/// chunk — the bound is checked after each read, but the growth a read can
/// drive is no longer the read's own to choose.
///
/// # Errors
///
/// Returns the I/O error if the guest closes before the head ends, or
/// [`io::ErrorKind::InvalidData`] when the head exceeds [`MAX_HEAD`] without
/// ending — a guest that never ends its first request is refused, not
/// buffered.
async fn read_request_head(guest: &mut UnixStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(CONNECT_REQUEST.len());
    let mut chunk = [0u8; HEAD_READ_CHUNK];
    loop {
        let n = guest.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "guest closed the connection before the switch upgrade head ended",
            ));
        }
        head.extend(chunk.iter().take(n).copied());
        if let Some(end) = find_subslice(&head, HEAD_END) {
            let carry = head.split_off(end + HEAD_END.len());
            return Ok((head, carry));
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switch upgrade head exceeded {MAX_HEAD} bytes without ending"),
            ));
        }
    }
}

/// Where `needle` first appears in `hay`, if it does: a small `windows` scan,
/// run once per connection over a head the protocol keeps at a few dozen
/// bytes.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    // An empty needle has no position, and `windows` takes a non-zero size.
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len())
        .position(|window| window == needle)
}

/// A reader that yields `carry` first, then the wrapped stream: the bytes a
/// single `read` returned past the end of the first request head — the start of
/// the frame stream on an upgraded connection, or of the request's body on a
/// control one — replayed before the socket is read, so nothing is lost to the
/// head's read.
struct Prefixed<R> {
    carry: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> Prefixed<R> {
    fn new(carry: Vec<u8>, inner: R) -> Self {
        Self {
            carry,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.carry.len() {
            let n = (this.carry.len() - this.pos).min(buf.remaining());
            #[expect(
                clippy::indexing_slicing,
                reason = "n is the smaller of the carry's remainder and the buffer's spare capacity"
            )]
            buf.put_slice(&this.carry[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// The stand-in guest + switch harness the NET-081 and NET-138 proof tests
/// share: one gate over a stand-in switch, with a "guest" end to write frames
/// from and the switch's accepted end to read only what the gate let through.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tracing_subscriber::fmt::MakeWriter;

    use super::{CONNECT_REQUEST, EgressGate, UnregisteredSourcePhase};
    use crate::box_registry::BoxRegistry;
    use crate::net::baseline::NodePlaneBaseline;

    /// How long the harness waits for a frame or a log line before calling
    /// the test failed: far past any healthy gate decision on a local socket,
    /// short of nextest's slow-timeout.
    pub(crate) const DEADLINE: Duration = Duration::from_secs(5);
    /// How long the switch end must then stay silent for a test to call a
    /// frame dropped: the gate decides in order, so bytes arriving after this
    /// mean something did slip through.
    pub(crate) const QUIET: Duration = Duration::from_millis(150);

    /// A `MakeWriter` accumulating everything written into a shared buffer,
    /// so a test can assert on the drop lines the gate emits.
    #[derive(Clone, Default)]
    pub(crate) struct CaptureWriter(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        /// The captured log so far.
        pub(crate) fn contents(&self) -> String {
            let captured = self
                .0
                .lock()
                .expect("the capture's lock is held only across this read")
                .clone();
            String::from_utf8(captured).expect("tracing writes UTF-8")
        }
    }

    impl io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture's lock is held only across this append")
                .extend_from_slice(buf);
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

    /// Installs the thread-local capture the gate's own tests assert through,
    /// returning it with the guard that keeps it installed: the gate's tasks
    /// run on this thread's current-thread runtime, so the thread-local
    /// default applies to them too. Split from [`gate_connected`] so a test
    /// that drives [`super::accept_loop`] itself — rather than a gate it
    /// spawned — sees the same lines.
    pub(crate) fn capture_log() -> (CaptureWriter, tracing::subscriber::DefaultGuard) {
        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (log, guard)
    }

    /// One gate over a stand-in switch. `guest` is the end that plays the
    /// guest shuttle — frames written here are decided by the gate;
    /// `switch` is the stand-in switch's accepted end, which reads only what
    /// the gate admitted; `log` captures what the gate has said; `table` is
    /// the gate's own view of the registry.
    pub(crate) struct GateHarness {
        /// The gate under test. Declared first so it drops first, before the
        /// sockets' directory below it goes away. Underscore-named: it is
        /// held for its lifetime, never read.
        pub(crate) _gate: EgressGate,
        /// The guest-shuttle stand-in.
        pub(crate) guest: UnixStream,
        /// The switch stand-in: reads only what the gate admitted.
        pub(crate) switch: UnixStream,
        /// The captured `tracing` output of this test's thread.
        pub(crate) log: CaptureWriter,
        /// The gate's own view of the registry: the read-only lookup surface.
        pub(crate) table: crate::box_registry::BoxTable,
        /// The gate's socket path, for a test that opens a second guest
        /// connection on the same gate ([`connect_over`]).
        pub(crate) gate_sock: std::path::PathBuf,
        /// The stand-in switch's listener, kept alive past the first
        /// connection so the gate's later dials have something to reach
        /// ([`connect_over`]). Held for its lifetime, not read: a listener is
        /// accepted *from*.
        pub(crate) switch_listener: UnixListener,
        /// Keeps the sockets' directory alive for the gate's lifetime.
        /// Underscore-named: held for its `Drop`, never read.
        pub(crate) _dir: TempDir,
        /// Keeps the thread-local `tracing` capture installed for the gate's
        /// lifetime. Underscore-named: held for its `Drop`, never read.
        pub(crate) _guard: tracing::subscriber::DefaultGuard,
    }

    /// Brings up one gate over a stand-in switch with the guest's connection
    /// accepted and the gate's dial of the switch taken off the accept queue,
    /// but the upgrade head not yet spoken: the harness every test that drives
    /// the handshake itself builds on. [`gate_over`] and [`gate_over_with`]
    /// complete the handshake before returning; a test that refuses a guest
    /// **mid**-handshake — a head that never ends — starts here instead,
    /// because no head is ever forwarded for the switch end to read back.
    ///
    /// The guest's connect plays libkrun's vsock bridge dialing the gate's
    /// socket, so what the guest writes next meets a gate already holding the
    /// switch connection it will relay into.
    pub(crate) async fn gate_connected(registry: BoxRegistry) -> GateHarness {
        gate_connected_with_phase(registry, super::UNREGISTERED_SOURCE_PHASE).await
    }

    /// [`gate_connected`] with the gate's unregistered-source phase named: the
    /// harness the phase's other arm ([`InForce`]) is pinned at relay level
    /// through, so the per-box default's drops are watched on a live gate, not
    /// only through the pure decision.
    pub(crate) async fn gate_connected_with_phase(
        registry: BoxRegistry,
        phase: UnregisteredSourcePhase,
    ) -> GateHarness {
        let baseline = crate::net::baseline::NodePlaneBaseline::built_in(registry.subnet());
        gate_connected_with_node_baseline(registry, phase, baseline).await
    }

    /// [`gate_connected_with_phase`] with the node-plane baseline set named:
    /// the harness the baseline's other arm ([`NodeBaselinePhase::InForce`],
    /// built with [`NodePlaneBaseline::in_force`]) is pinned at relay level
    /// through, so the node plane's own admissions are watched on a live gate,
    /// not only through the pure decision.
    pub(crate) async fn gate_connected_with_node_baseline(
        registry: BoxRegistry,
        phase: UnregisteredSourcePhase,
        baseline: NodePlaneBaseline,
    ) -> GateHarness {
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let gate_sock = dir.path().join("gvproxy-gate.sock");
        // The stand-in switch: a listener the gate's connection task dials,
        // kept alive for the harness's lifetime so a later guest connection
        // on the same gate has something to dial.
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // Capture this thread's tracing output before the gate starts, so its
        // drop lines are assertable. The gate runs on this test's
        // current-thread runtime, so the thread-local default applies to its
        // tasks too.
        let (log, _guard) = capture_log();

        let gate = EgressGate::spawn_with_phase(
            gate_sock.clone(),
            switch_sock.clone(),
            registry.table(),
            baseline,
            phase,
        )
        .expect("spawning the egress gate");

        // The guest's connect: the shuttle's vsock connection, arrived…
        let guest = UnixStream::connect(&gate_sock)
            .await
            .expect("connecting the guest end");
        // …and the gate's dial of the switch it fronts, accepted before the
        // guest speaks, so what it writes next is decided by a gate whose
        // switch connection is already up.
        let (switch, _) = listener.accept().await.expect("accepting the gate's dial");

        GateHarness {
            _gate: gate,
            guest,
            switch,
            log,
            table: registry.table(),
            gate_sock,
            switch_listener: listener,
            _dir: dir,
            _guard,
        }
    }

    /// Brings up one gate over a stand-in switch, deciding by `registry`'s
    /// table, with the guest sending the plain upgrade head first.
    pub(crate) async fn gate_over(registry: BoxRegistry) -> GateHarness {
        gate_over_with_phase(registry, super::UNREGISTERED_SOURCE_PHASE).await
    }

    /// [`gate_over`] on a gate built with `phase`: the upgrade-completed
    /// harness the in-force arm's relay-level pins run through
    /// ([`EgressGate::spawn_with_phase`] for how the phase reaches the gate).
    pub(crate) async fn gate_over_with_phase(
        registry: BoxRegistry,
        phase: UnregisteredSourcePhase,
    ) -> GateHarness {
        forward_upgrade_head(gate_connected_with_phase(registry, phase).await).await
    }

    /// [`gate_over_with_phase`] with the node-plane baseline set named: the
    /// upgrade-completed harness the baseline's in-force arm's relay-level
    /// pins run through.
    pub(crate) async fn gate_over_with_node_baseline(
        registry: BoxRegistry,
        phase: UnregisteredSourcePhase,
        baseline: NodePlaneBaseline,
    ) -> GateHarness {
        forward_upgrade_head(gate_connected_with_node_baseline(registry, phase, baseline).await)
            .await
    }

    /// [`gate_over`]'s handshake completion: the guest's first write — the
    /// upgrade head, alone — and the head forwarded verbatim and read back off
    /// the switch end, so the frame stream begins at a known point.
    async fn forward_upgrade_head(mut harness: GateHarness) -> GateHarness {
        harness
            .guest
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the guest's first bytes");
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        harness
            .switch
            .read_exact(&mut head)
            .await
            .expect("reading the forwarded head");
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the switch upgrade head verbatim"
        );
        harness
    }

    /// [`gate_over`] with the guest's first write supplied by the caller, so a
    /// test can pipeline frames behind the upgrade head in a single write and
    /// exercise the gate's carry-over of the bytes its head-read read past the
    /// head's end.
    ///
    /// The forwarded head is read back off the switch end and asserted
    /// verbatim, so every harness built this way proves the upgrade passes
    /// through untouched before the frame stream begins.
    pub(crate) async fn gate_over_with(registry: BoxRegistry, first_write: Vec<u8>) -> GateHarness {
        let mut harness = gate_connected(registry).await;
        // The guest's first write — the upgrade head, alone or with frames
        // pipelined behind it.
        harness
            .guest
            .write_all(&first_write)
            .await
            .expect("writing the guest's first bytes");
        // The upgrade head, forwarded verbatim and read back off the switch
        // end, so the frame stream begins at a known point.
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        harness
            .switch
            .read_exact(&mut head)
            .await
            .expect("reading the forwarded head");
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the switch upgrade head verbatim"
        );
        harness
    }

    /// Brings up one gate and has the guest speak a control request: gvproxy's
    /// switch socket carries the daemon's HTTP verbs on the same vsock port as
    /// the shuttle's upgrade, so a control exchange is the other half of what
    /// the gate must relay. The gate decides the request before any of it is
    /// written on, so this harness speaks an **admitted** one — built with
    /// [`gate_connected`]'s shipped registry table — and reads the head and
    /// body back off the switch end together, asserted verbatim: the request
    /// the switch holds is exactly the request the guest sent, and the test
    /// observes the exchange from that known point. A test of a **refused**
    /// request builds on [`gate_connected`] instead and reads nothing, because
    /// no byte of a refused request is ever written on.
    pub(crate) async fn gate_over_control(registry: BoxRegistry, request: Vec<u8>) -> GateHarness {
        let mut harness = gate_connected(registry).await;
        harness
            .guest
            .write_all(&request)
            .await
            .expect("writing the control request");
        let mut spoken = vec![0u8; request.len()];
        read_within(&mut harness.switch, &mut spoken).await;
        assert_eq!(
            spoken, request,
            "the gate forwards an admitted control request verbatim, head and body together"
        );
        harness
    }

    /// Opens one more guest connection on the harness's gate and completes the
    /// upgrade on it, returning the guest's end and the switch end the gate
    /// dialed for it: the shape [`gate_over`] builds for a gate's first
    /// connection, opened again for the tests that need several live ones on
    /// the same gate. The forwarded head is read back off the switch end and
    /// asserted verbatim, so every connection built this way proves its
    /// upgrade passed through before the test goes on.
    pub(crate) async fn connect_over(harness: &GateHarness) -> (UnixStream, UnixStream) {
        let mut guest = UnixStream::connect(&harness.gate_sock)
            .await
            .expect("connecting another guest");
        // The gate's dial of the switch it fronts, accepted before the guest
        // speaks, exactly as the first connection's is.
        let (mut switch, _) = harness
            .switch_listener
            .accept()
            .await
            .expect("accepting the gate's dial");
        guest
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the upgrade head");
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        read_within(&mut switch, &mut head).await;
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the switch upgrade head verbatim"
        );
        (guest, switch)
    }

    /// Opens one more connection on the harness's gate for a control request,
    /// and nothing else: the guest's end and the switch end the gate dialed
    /// for it, with no byte written on either. A control connection speaks
    /// its one request — verb, head and body in one write — where a frame
    /// connection's upgrade head would go, and the gate decides that request
    /// before any of it is written on, so what a test reads off the switch
    /// end next is either the whole request or nothing.
    pub(crate) async fn connect_control(harness: &GateHarness) -> (UnixStream, UnixStream) {
        let guest = UnixStream::connect(&harness.gate_sock)
            .await
            .expect("connecting another guest");
        // The gate's dial of the switch it fronts, accepted before the guest
        // speaks, exactly as every connection's is.
        let (switch, _) = harness
            .switch_listener
            .accept()
            .await
            .expect("accepting the gate's dial");
        (guest, switch)
    }

    /// Writes one length-framed frame from the guest end.
    pub(crate) async fn send_frame(guest: &mut UnixStream, frame: &[u8]) {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(frame);
        guest
            .write_all(&framed)
            .await
            .expect("writing the framed frame");
    }

    /// Reads one length-framed frame from the switch end within [`DEADLINE`],
    /// failing the test when the timeout passes first.
    pub(crate) async fn expect_frame(switch: &mut UnixStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        read_within(switch, &mut len_buf).await;
        let n = u16::from_le_bytes(len_buf) as usize;
        assert!(n > 0, "a zero-length frame claim is not a frame");
        let mut frame = vec![0u8; n];
        read_within(switch, &mut frame).await;
        frame
    }

    /// Reads exactly `buf` from `stream` within [`DEADLINE`], failing the
    /// test when the timeout passes first.
    pub(crate) async fn read_within(stream: &mut UnixStream, buf: &mut [u8]) {
        match tokio::time::timeout(DEADLINE, stream.read_exact(buf)).await {
            Ok(read) => {
                read.expect("reading the stream");
            }
            Err(_) => panic!("expected the bytes to arrive within {DEADLINE:?}, got none"),
        }
    }

    /// Polls the captured log until it contains `needle`, failing with the
    /// log's contents once [`DEADLINE`] passes.
    pub(crate) async fn wait_for_log(log: &CaptureWriter, needle: &str) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let logged = log.contents();
            if logged.contains(needle) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected {needle:?} in the captured log within {DEADLINE:?}, got: {logged}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// After a marker frame has proved the gate decided everything before it,
    /// asserts nothing else arrived at the switch: a frame the gate dropped is
    /// not merely late, it is absent.
    pub(crate) async fn expect_silence(switch: &mut UnixStream) {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(QUIET, switch.read(&mut buf)).await {
            Ok(Ok(0)) => panic!("the switch end closed; the gate's relay is down"),
            Ok(Ok(n)) => panic!(
                "{n} byte(s) arrived at the switch after the marker: a dropped frame slipped through"
            ),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            // Quiet for the window: nothing else was written on.
            Err(_) => {}
        }
    }

    /// Asserts the guest's side of a refused connection is down — that no
    /// further byte will ever arrive on it — without insisting on which
    /// signal the teardown left behind. A well-behaved guest, one that sent
    /// only what its request declared, reads clean EOF; a guest whose bytes
    /// the gate refused to read finds the socket reset, the OS's report that
    /// its data was discarded. Both mean the gate closed its side, and
    /// neither leaves a further byte for the guest to read.
    pub(crate) async fn expect_teardown(guest: &mut UnixStream) {
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("the gate left the refused connection hanging"),
        }
    }

    /// An Ethernet II frame carrying an IPv4 `proto` packet from `src` to
    /// `dst`:`port` — the shape the shared verdict reads: a 14-byte Ethernet
    /// header, the fixed 20-byte IPv4 header (TTL 64, the protocol byte, a
    /// zeroed checksum — neither is read), and 4 bytes of L4 ports. `6` is
    /// TCP, `17` UDP.
    pub(crate) fn ipv4_frame(src: [u8; 4], proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 24);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        frame.extend_from_slice(&[0x45, 0, 0, 0]); // version 4, IHL 5, TOS, length (unchecked)
        frame.extend_from_slice(&[0; 4]); // id, flags+offset: 0
        frame.push(64); // TTL
        frame.push(proto); // protocol
        frame.extend_from_slice(&[0; 2]); // checksum (unchecked)
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&40000u16.to_be_bytes()); // source port
        frame.extend_from_slice(&port.to_be_bytes()); // destination port
        frame
    }

    /// An Ethernet II ARP frame announcing `spa` as its sender protocol
    /// address — the address an ARP frame's source is read from.
    pub(crate) fn arp_frame(spa: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 28);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        frame.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // oper: request
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x40, 0x00, 0x09]); // sender MAC
        frame.extend_from_slice(&spa); // sender protocol address
        frame.extend_from_slice(&[0; 6]); // target MAC
        frame.extend_from_slice(&[100, 64, 0, 1]); // target protocol address
        frame
    }

    /// An Ethernet II frame carrying an IPv6 payload — the family no v1
    /// admission path exists for, dropped as a family under any rules.
    pub(crate) fn ipv6_frame() -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 40);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x86DDu16.to_be_bytes()); // EtherType: IPv6
        frame.extend_from_slice(&[0; 40]);
        frame
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use sessions::EgressPolicy;
    use sessions::core::egress::{DropReason, FrameFamily, FrameVerdict, Ipv4Cidr};
    use switch::SwitchSubnet;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use super::test_support::{
        CaptureWriter, DEADLINE, arp_frame, capture_log, connect_control, connect_over,
        expect_frame, expect_silence, expect_teardown, gate_connected, gate_connected_with_phase,
        gate_over, gate_over_control, gate_over_with, gate_over_with_node_baseline,
        gate_over_with_phase, ipv4_frame, ipv6_frame, read_within, send_frame, wait_for_log,
    };
    use super::{
        AcceptFailure, CONNECT_REQUEST, CONTROL_VERBS, ControlVerb, DROP_WARN_MAX_TRACKED_PAIRS,
        DROP_WARN_MIN_INTERVAL, DropLimiter, EgressGate, GateAdmit, GateDrop, GuestSource,
        GuestSpeak, HANDSHAKE_TIMEOUT, MALFORMED_PUBLISH_RULE, MAX_HEAD, MAX_LIVE_RELAYS,
        MAX_NAMED_TARGET, PublishedForwards, Record, UNDECLARED_PUBLISH_RECORD_RULE,
        UNDECLARED_RETRACT_RULE, UNREGISTERED_PUBLISH_RULE, UNREGISTERED_SOURCE_PHASE,
        UNREGISTERED_SOURCE_RULE, UnregisteredSourcePhase, WarnDecision, accept_loop, gate_verdict,
        max_frame, render_record, serve_connection,
    };
    use crate::box_registry::{BoxRegistration, BoxRegistry, BoxTable};
    use crate::net::baseline::{BaselineCategory, NodeBaselinePhase, NodePlaneBaseline};

    /// The default switch subnet, the plan every registry below is built for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// The lease of the one published box below: the one source its frames
    /// may carry.
    const LEASE: [u8; 4] = [100, 64, 0, 9];

    /// A box that may reach `10.0.0.0/8` over TCP and nothing else — the
    /// declaration the host-side rules below are compiled from.
    fn tcp_lan_box(registry: &BoxRegistry, lease: [u8; 4]) {
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
    }

    /// NET-081: on a VM-backed host a box's rules are applied **outside** the
    /// VM, by the host, before the switch sees anything. A frame the box
    /// declared arrives at the switch exactly as it was sent; a frame it did
    /// not declare never does — the gate drops it where it stands — and the
    /// drop says so, rate-limited, naming the source address and the rule.
    #[tokio::test]
    async fn host_side_rules_applied_outside_vm() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // Declared: TCP to the allowed subnet reaches the switch, untouched —
        // the same frame, byte for byte, that left the guest.
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &declared).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, declared,
            "a declared frame reaches the switch as it was sent"
        );

        // Undeclared: TCP to an address outside the allowed subnet is dropped
        // before the switch. The marker sent after it proves the drop — the
        // gate decides in order, so a marker that arrives means everything
        // before it was decided, and this frame did not pass.
        let undeclared = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        let marker = ipv4_frame(LEASE, 6, [10, 9, 9, 9], 80);
        send_frame(&mut h.guest, &undeclared).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the undeclared frame never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // The drop says so, naming the source address and the rule — the line
        // a diagnostic bundle's daemon log tail carries.
        wait_for_log(&h.log, "egress-undeclared-subnet").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("source=100.64.0.9"),
            "the drop line carries the source address, got: {logged}"
        );
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-subnet\""),
            "the drop line carries the rule, got: {logged}"
        );

        // And only once: a second drop of the same class, decided for the same
        // box, adds no second line inside the interval.
        let second = ipv4_frame(LEASE, 6, [203, 0, 113, 8], 443);
        send_frame(&mut h.guest, &second).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the marker still arrives; the drop is not a reset"
        );
        expect_silence(&mut h.switch).await;
        assert_eq!(
            h.log.contents().matches("egress-undeclared-subnet").count(),
            1,
            "one drop line per source address per rule per interval, got: {}",
            h.log.contents()
        );
    }

    /// The switch's own address is a control surface, not a destination a
    /// box's egress rules decide (design §4.1, §7.1): a frame from a box to
    /// the gateway that is not a TCP or UDP query to the resolver's port is
    /// dropped at the host-side gate, whatever the box's rules allow — an
    /// absent `egress` section's allow-all program and a declared allow-all
    /// section both — and the drop says so, rate-limited, naming the box's
    /// address and the port. The resolver's port still answers, over UDP and
    /// over TCP alike: DNS to the gateway reaches the switch for both boxes.
    /// A protocol with no port — ICMP — is refused with the rest. The check
    /// binds under the shipped announced phase and is not gated on a row: an
    /// unregistered in-plan source's frame at the gateway is refused too,
    /// where the interim would admit it anywhere else.
    ///
    /// The port the refusals name is the shape of the switch's control
    /// surface as a box would reach for it — gvproxy's API listens on the
    /// gateway address, so the refusal is keyed to the address and every
    /// port but the resolver's; the test's port stands for whichever port
    /// the API could ever be probed on.
    #[tokio::test]
    async fn box_cannot_reach_switch_api() {
        // Two boxes whose rules allow everything: one whose declaration
        // carries no `egress` section — the allow-all program
        // [`sessions::core::egress::EgressRules::from_policy`] compiles for
        // an absent one — and one whose `egress` section allows all
        // explicitly. Neither row admits the gateway; the admitted ports are
        // each box's own ingress, which the gateway refusal never consults.
        let registry = BoxRegistry::new(SUBNET);
        let bare = [100, 64, 0, 9];
        let open = [100, 64, 0, 10];
        let unregistered = [100, 64, 0, 99];
        registry.register(
            BoxRegistration::new("bare", Ipv4Addr::from(bare), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        registry.register(
            BoxRegistration::new("open", Ipv4Addr::from(open), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([9999])
                .with_egress_policy(EgressPolicy::default()),
        );
        let mut h = gate_over(registry).await;

        // Each box reaches for the switch's control surface at the gateway;
        // a marker from the first box proves the gate decided all three
        // frames before it, and none of the three arrived.
        let api_port = 443;
        let bare_probe = ipv4_frame(bare, 6, SUBNET.gateway().octets(), api_port);
        let open_probe = ipv4_frame(open, 6, SUBNET.gateway().octets(), api_port);
        let unregistered_probe = ipv4_frame(unregistered, 6, SUBNET.gateway().octets(), api_port);
        let marker = ipv4_frame(bare, 6, [10, 9, 9, 9], 80);
        send_frame(&mut h.guest, &bare_probe).await;
        send_frame(&mut h.guest, &open_probe).await;
        send_frame(&mut h.guest, &unregistered_probe).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the marker arrives; the three gateway probes do not"
        );
        expect_silence(&mut h.switch).await;

        // The resolver's port still answers, for a box with no egress
        // section and for a box with an allow-all one alike, over UDP and
        // over the TCP a truncated answer falls back to.
        let bare_dns = ipv4_frame(bare, 17, SUBNET.gateway().octets(), 53);
        let open_dns = ipv4_frame(open, 17, SUBNET.gateway().octets(), 53);
        let bare_dns_tcp = ipv4_frame(bare, 6, SUBNET.gateway().octets(), 53);
        let open_dns_tcp = ipv4_frame(open, 6, SUBNET.gateway().octets(), 53);
        send_frame(&mut h.guest, &bare_dns).await;
        send_frame(&mut h.guest, &open_dns).await;
        send_frame(&mut h.guest, &bare_dns_tcp).await;
        send_frame(&mut h.guest, &open_dns_tcp).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            bare_dns,
            "the no-egress-section box's resolver frame reaches the switch"
        );
        assert_eq!(
            expect_frame(&mut h.switch).await,
            open_dns,
            "the allow-all box's resolver frame reaches the switch"
        );
        assert_eq!(
            expect_frame(&mut h.switch).await,
            bare_dns_tcp,
            "the no-egress-section box's TCP resolver frame reaches the switch"
        );
        assert_eq!(
            expect_frame(&mut h.switch).await,
            open_dns_tcp,
            "the allow-all box's TCP resolver frame reaches the switch"
        );

        // A protocol with no port to carve out by is refused with the rest:
        // ICMP from a registered allow-all box to the gateway never arrives,
        // and the marker behind it does.
        let icmp_probe = ipv4_frame(bare, 1, SUBNET.gateway().octets(), 0);
        send_frame(&mut h.guest, &icmp_probe).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the ICMP probe at the gateway is refused"
        );
        expect_silence(&mut h.switch).await;

        // One rate-limited line per refusing source, naming the box's
        // address and the port.
        wait_for_log(&h.log, "egress-switch-control-surface").await;
        let logged = h.log.contents();
        for source in ["100.64.0.9", "100.64.0.10", "100.64.0.99"] {
            assert!(
                logged.contains(&format!("source={source}")),
                "the drop line carries {source}'s address, got: {logged}"
            );
        }
        assert!(
            logged.contains("port=443"),
            "the drop line carries the port the frame named, got: {logged}"
        );
    }

    /// The one drop class a row defers to the guest's decision: a namespace
    /// that declared DNS hosts carries a name-based admission its frame rules
    /// cannot (NET-066's admission lives in the in-guest gate, resolution-time
    /// pins the host never sees), so the host-side verdict passes the
    /// undeclared-destination frame on for the guest's gate to admit or drop
    /// by the pin its box holds. The classes no pin governs are still
    /// decided here: a denied destination, whose answers the guest's own gate
    /// refuses (NET-067), is refused by the host's own rules. A namespace
    /// that declared an *empty* name list lifts nothing in the guest either,
    /// so its undeclared frames are refused here, like a no-names row's.
    #[tokio::test]
    async fn a_row_that_resolves_names_defers_the_undeclared_destination_drop() {
        let registry = BoxRegistry::new(SUBNET);
        // The declared box's own shape: a narrow allowed subnet, names
        // beside it, and a denied range the same declaration subtracts.
        registry.register(
            BoxRegistration::new("weather", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: Some(vec!["198.51.100.0/24".to_string()]),
                }),
        );
        // The edge of the deferral's condition: names *declared empty* —
        // `Some(vec![])` — is not a namespace whose guest lifts anything,
        // because its gate allows no names to resolve, so no defer.
        let empty = [100, 64, 0, 10];
        registry.register(
            BoxRegistration::new("closed-names", Ipv4Addr::from(empty), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                    allow_dns_hosts: Some(Vec::new()),
                    deny_subnets: None,
                }),
        );
        let mut h = gate_over(registry).await;

        // Undeclared destination of the name-declaring row — the shape a
        // resolved name's address has: deferred, so it reaches the switch and
        // the in-guest decision owns it.
        let pinned = ipv4_frame(LEASE, 6, [93, 184, 216, 34], 443);
        send_frame(&mut h.guest, &pinned).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, pinned,
            "the undeclared destination of a name-declaring row defers to the guest's gate"
        );

        // Denied destination of the same row: no pin governs a denied range
        // and the guest refuses it too, so the host's own verdict stands.
        let denied = ipv4_frame(LEASE, 6, [198, 51, 100, 9], 443);
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &denied).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the denied range is still the host's own drop; the marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "egress-denied-subnet").await;
        let logged = h.log.contents();
        assert!(
            !logged.contains("egress-undeclared-subnet"),
            "a deferred drop is not a host-side drop: no undeclared line, got: {logged}"
        );

        // The empty-names row's undeclared frame: refused here, as its guest
        // would refuse it too.
        let undeclared = ipv4_frame(empty, 6, [93, 184, 216, 34], 443);
        let marker = ipv4_frame(empty, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &undeclared).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "an empty name list is no defer: the undeclared frame is the host's drop"
        );
        expect_silence(&mut h.switch).await;
    }

    /// The deferral's edge, from the other side: a name-declaring row defers
    /// the undeclared-destination drop and nothing else. For the same row
    /// shape — names declared beside a narrow allowed subnet — every other
    /// drop the host-side gate decides is still made here, before the
    /// switch: a destination inside its own `deny_subnets`, the switch's own
    /// address (the one piece of the plan's infrastructure the gate refuses
    /// as a frame rule, before any row is consulted), a protocol its rules
    /// do not allow — aimed at the very destination the deferral lifts over
    /// TCP — and a source no row holds. The DNS rebinding intersection's
    /// wider infrastructure deny set (NET-067) is the host's own frame rule
    /// too, decided for every row before this one's rules are read; it is
    /// pinned on its own, with the rows it is decided for, by
    /// [`infrastructure_destinations_drop_on_the_host_for_every_row`].
    ///
    /// The registration itself says what is deferred, once, where the row
    /// enters the table (#1808 is the task that moves the decision
    /// host-side): the line names the box's switch address and is written
    /// at registration — before the gate is up — so a capture installed
    /// ahead of the registry catches it, and a no-names row adds none.
    #[tokio::test]
    async fn a_row_that_resolves_names_still_takes_every_other_drop_on_the_host() {
        let (registration_log, registration_guard) = capture_log();
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("weather", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: Some(vec!["198.51.100.0/24".to_string()]),
                }),
        );
        tcp_lan_box(&registry, [100, 64, 0, 10]);
        drop(registration_guard);
        let logged = registration_log.contents();
        assert!(
            logged.contains("deferred to the guest's gate") && logged.contains("INFO"),
            "the registration says the destination rule is deferred, got: {logged}"
        );
        assert!(
            logged.contains("switch_addr=100.64.0.9"),
            "the registration line names the box's switch address, got: {logged}"
        );
        assert_eq!(
            logged.matches("deferred to the guest's gate").count(),
            1,
            "one line per name-declaring row; the no-names row adds none, got: {logged}"
        );
        let mut h = gate_over(registry).await;

        // The deferred class, as the baseline: the undeclared destination
        // reaches the switch over the allowed protocol.
        let pinned = ipv4_frame(LEASE, 6, [93, 184, 216, 34], 443);
        send_frame(&mut h.guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            pinned,
            "the undeclared destination still defers to the guest's gate"
        );

        // Four drops the deferral does not lift, then the marker that proves
        // all four were decided before it and none passed.
        let denied = ipv4_frame(LEASE, 6, [198, 51, 100, 9], 443);
        let gateway = SUBNET.dns_server().octets();
        let switch_api = ipv4_frame(LEASE, 6, gateway, 443);
        let udp_to_pinned = ipv4_frame(LEASE, 17, [93, 184, 216, 34], 443);
        let stranger = [203, 0, 113, 7];
        let from_stranger = ipv4_frame(stranger, 6, [93, 184, 216, 34], 443);
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        for frame in [&denied, &switch_api, &udp_to_pinned, &from_stranger] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the four frames never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // Each drop is the host's own, named under its rule; no
        // undeclared-destination line, because that class was deferred.
        for rule in [
            "egress-denied-subnet",
            "egress-switch-control-surface",
            "egress-undeclared-protocol",
            "egress-unknown-source",
        ] {
            wait_for_log(&h.log, rule).await;
        }
        let logged = h.log.contents();
        assert!(
            logged.contains("source=100.64.0.9") && logged.contains("source=203.0.113.7"),
            "the drop lines name the row's address and the stranger's, got: {logged}"
        );
        assert!(
            !logged.contains("egress-undeclared-subnet"),
            "a deferred drop is not a host-side drop: no undeclared line, got: {logged}"
        );
    }

    /// The §5.3 infrastructure deny set as a host frame rule
    /// ([`INFRASTRUCTURE_RULE`]), decided for every row before the row's own
    /// rules and before the deferral: a name-declaring row and a CIDR row
    /// that allows `0.0.0.0/0` are both refused to the metadata service
    /// (link-local) and to a box in another node's block of the fabric
    /// plane, whatever their rules admit — the deferral lifts nothing here,
    /// and neither does the widest allowance. The node's own block is the
    /// carve-out: the same CIDR row reaches a sibling and the host alias,
    /// local reach the row's rules and the target's ingress decide. RFC 1918
    /// is the one exemption: a `10.0.0.0/8` destination is refused for the
    /// name-declaring row, whose declared `allow_subnets` does not cover it
    /// — the frame its deferral would otherwise have passed to the guest —
    /// and admitted for a row whose `allow_subnets` names the range, for the
    /// `0.0.0.0/0` row, and for a row with no `egress` section at all, whose
    /// undeclared dimension is the shipped allow-all and covers it the way
    /// the rebinding intersection's exemption holds it. Each drop names its
    /// destination and port under the rule, rate-limited per source, so the
    /// first refused frame of each source is the one whose line is read.
    /// A source the announced interim admits without a row takes the same
    /// rule: refused to the metadata service, admitted to private space as
    /// the allow-all the interim concedes.
    #[tokio::test]
    async fn infrastructure_destinations_drop_on_the_host_for_every_row() {
        let registry = BoxRegistry::new(SUBNET);
        let open = [100, 64, 0, 10];
        let lan = [100, 64, 0, 11];
        let bare = [100, 64, 0, 12];
        // Held by no row: the announced interim's source.
        let unregistered = [100, 64, 0, 13];
        registry.register(
            BoxRegistration::new("weather", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: None,
                }),
        );
        registry.register(
            BoxRegistration::new("open", Ipv4Addr::from(open), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        tcp_lan_box(&registry, lan);
        registry.register(
            BoxRegistration::new("bare", Ipv4Addr::from(bare), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let mut h = gate_over(registry).await;

        // Local reach inside the node's own block, and RFC 1918 under an
        // allowance: all admitted, each read back as sent.
        let host_alias = SUBNET.host_alias().octets();
        let admitted = [
            ipv4_frame(open, 6, LEASE, 8080),
            ipv4_frame(open, 6, host_alias, 80),
            ipv4_frame(open, 6, [10, 1, 2, 3], 80),
            ipv4_frame(lan, 6, [10, 1, 2, 3], 80),
            ipv4_frame(bare, 6, [10, 1, 2, 3], 80),
            ipv4_frame(unregistered, 6, [10, 1, 2, 3], 80),
        ];
        for frame in &admitted {
            send_frame(&mut h.guest, frame).await;
            assert_eq!(
                &expect_frame(&mut h.switch).await,
                frame,
                "own-block and allowed-private destinations reach the switch"
            );
        }

        // The refusals, the first of each source naming a different range,
        // then every other pair; the marker after them proves all were
        // decided before it and none passed.
        let metadata = [169, 254, 169, 254];
        let other_block = [100, 65, 0, 9];
        let refused = [
            ipv4_frame(LEASE, 6, [10, 1, 2, 3], 443),
            ipv4_frame(open, 6, metadata, 80),
            ipv4_frame(bare, 6, other_block, 80),
            ipv4_frame(LEASE, 6, metadata, 80),
            ipv4_frame(LEASE, 6, other_block, 80),
            ipv4_frame(open, 6, other_block, 80),
            ipv4_frame(bare, 6, metadata, 80),
            ipv4_frame(lan, 6, metadata, 80),
            ipv4_frame(lan, 6, other_block, 80),
            ipv4_frame(unregistered, 6, metadata, 80),
        ];
        for frame in &refused {
            send_frame(&mut h.guest, frame).await;
        }
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "no infrastructure-bound frame reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // The drops say so under the rule, naming the destination and the
        // port, one line per source: the first refused frame of each.
        wait_for_log(&h.log, "egress-infrastructure-destination").await;
        let logged = h.log.contents();
        for needle in [
            "source=100.64.0.9",
            "destination=10.1.2.3",
            "port=443",
            "source=100.64.0.10",
            "destination=169.254.169.254",
            "source=100.64.0.12",
            "destination=100.65.0.9",
            "source=100.64.0.13",
            "port=80",
            "rule_matched=\"egress-infrastructure-destination\"",
        ] {
            assert!(
                logged.contains(needle),
                "the drop lines carry {needle}, got: {logged}"
            );
        }
        assert!(
            !logged.contains("egress-undeclared-subnet"),
            "the name-declaring row's private destination is the infrastructure drop, not \
             a deferred one, got: {logged}"
        );
    }

    /// NET-081's failure case, as the phase this build ships holds it: a frame
    /// whose source address the plan could never hand to a box never leaves
    /// the VM, and a frame whose source the plan *could* hand out but no
    /// namespace holds is the interim's — admitted, under the announced
    /// default, with a line that names the source and T66 on every admit —
    /// until the creator-side registration (T66, #1711) supplies the rows the
    /// per-box default binds to. Flipping `UNREGISTERED_SOURCE_PHASE` is what
    /// T66 does, and this test is one of the ones that flip with it: the
    /// admits below become drops, the interim's lines become rule 0's, and
    /// nothing else moves. The in-force arm's own pins — what the shipped
    /// gate decides once that flip has landed — are carried at relay level by
    /// [`unregistered_sources_dropped_when_default_in_force`], built through
    /// the phase parameter rather than waiting on the constant.
    #[tokio::test]
    async fn unknown_source_default_deny() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A namespace that was published and then withdrawn: its address is
        // held by no row any more, and no rules are decided by it.
        let withdrawn = [100, 64, 0, 10];
        let retired = registry.register(BoxRegistration::new(
            "gone",
            Ipv4Addr::from(withdrawn),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(registry.withdraw(retired.switch_addr()).is_some());
        let mut h = gate_over(registry).await;

        // Four frames whose source the plan could never hand out: the gateway
        // the resolver carve-out is keyed to (the plan's own infrastructure,
        // not a lease), an address from a subnet the plan does not serve, an
        // ARP announcing the gateway's address — address resolution is no way
        // to smuggle one past the table — and an IPv6 frame, the family with
        // no source to read and no admission path either. The marker after
        // them is the one published box's, so its arrival proves all four
        // were decided and none passed.
        let gateway = SUBNET.dns_server().octets();
        let foreign = [203, 0, 113, 7];
        let outside_plan = ipv4_frame(gateway, 6, [10, 1, 2, 3], 80);
        let beyond_subnet = ipv4_frame(foreign, 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame(gateway);
        let v6 = ipv6_frame();
        for frame in [&outside_plan, &beyond_subnet, &foreign_arp, &v6] {
            send_frame(&mut h.guest, frame).await;
        }

        // Two frames whose source the plan could hand out but no row holds: a
        // made-up lease, and the withdrawn namespace's — withdrawal inside the
        // plan's lease block costs an address no reach until the per-box
        // default binds, because the interim exists to keep exactly these
        // addresses' boxes on the wire. Both are admitted, and both say so.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let from_retired = ipv4_frame(withdrawn, 6, [10, 1, 2, 3], 80);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        for frame in [&made_up, &from_retired] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, made_up,
            "the made-up lease is admitted by the announced interim, not dropped"
        );
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, from_retired,
            "the withdrawn namespace's frames are the interim's until the default binds"
        );
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the published box's frame passes; no other frame did"
        );
        expect_silence(&mut h.switch).await;

        // The drops are named: the out-of-plan sources under NET-081's own
        // rule — the gateway's IPv4 frame and its ARP share one line, the
        // foreign subnet's has its own — and the IPv6 family under its own,
        // with no source to name.
        wait_for_log(&h.log, "egress-unknown-source").await;
        wait_for_log(&h.log, "egress-ipv6").await;
        let logged = h.log.contents();
        for src in [gateway, foreign] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "a drop line names the source address {src:?}, got: {logged}"
            );
        }
        assert!(
            logged.contains("source=none"),
            "the family drop names no source rather than inventing one, got: {logged}"
        );
        assert_eq!(
            logged.matches("egress-unknown-source").count(),
            2,
            "three out-of-plan frames make two lines (the gateway's two share one), \
             got: {logged}"
        );
        assert_eq!(
            logged.matches("egress-ipv6").count(),
            1,
            "the family drop has its own line, got: {logged}"
        );

        // The interim's admits are named too — one line per unregistered
        // source, each naming the address and the task that ends the interim.
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
        let logged = h.log.contents();
        for src in [stranger, withdrawn] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "the interim's line names the source address {src:?}, got: {logged}"
            );
        }
        assert!(
            logged.contains("T66 (#1711)"),
            "the interim's line names the registration path that ends it, got: {logged}"
        );
        assert_eq!(
            logged.matches(UNREGISTERED_SOURCE_RULE).count(),
            2,
            "one interim line per unregistered source, got: {logged}"
        );

        // And only one per source per interval: a second frame from the same
        // made-up lease admits and adds no second line inside the window.
        send_frame(&mut h.guest, &made_up).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, made_up,
            "the interim's admit is not a reset: the same source's next frame passes"
        );
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the marker still arrives after the repeat admit"
        );
        expect_silence(&mut h.switch).await;
        assert_eq!(
            h.log.contents().matches(UNREGISTERED_SOURCE_RULE).count(),
            2,
            "one interim line per source per interval, got: {}",
            h.log.contents()
        );

        // What the admits did not do: publish. The made-up lease and the
        // withdrawn namespace still hold no row — the table is filled on the
        // host, never from the guest's wire, an admit included — and the one
        // published box is still held.
        assert!(
            h.table.by_source(stranger).is_none(),
            "the guest's made-up address published no row"
        );
        assert!(
            h.table.by_source(withdrawn).is_none(),
            "an admit under the interim is not a re-registration"
        );
        assert!(
            h.table.by_source(LEASE).is_some(),
            "the one published box is still held"
        );
    }

    /// NET-081's failure case as the per-box default holds it — the phase's
    /// in-force arm, pinned **at relay level** on a live gate built through
    /// [`EgressGate::spawn_with_phase`], the injection point the pure decision
    /// alone never had: a frame whose source the plan could hand out but no
    /// row holds is dropped, the interim's admit lines are absent, and the
    /// drops are named, once per source, under [`UNKNOWN_SOURCE_RULE`]. The
    /// pins the announced interim's test had to relax stand here, so T66's
    /// (#1711) flip of [`UNREGISTERED_SOURCE_PHASE`] turns the shipped gate
    /// into what this test already watches and nothing has to be rewritten
    /// green: the made-up lease, the withdrawn namespace's address, and an
    /// ARP announcing an unpublished in-plan address — the sender address an
    /// ARP frame's source is read from, so resolution is no way in — all
    /// drop, while the published box's frames are still decided by its row.
    #[tokio::test]
    async fn unregistered_sources_dropped_when_default_in_force() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A namespace that was published and then withdrawn: its address is
        // held by no row any more, and no rules are decided by it.
        let withdrawn = [100, 64, 0, 10];
        let retired = registry.register(BoxRegistration::new(
            "gone",
            Ipv4Addr::from(withdrawn),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(registry.withdraw(retired.switch_addr()).is_some());
        let mut h = gate_over_with_phase(registry, UnregisteredSourcePhase::InForce).await;

        // Three frames whose source the plan could hand out but no row holds:
        // a made-up lease, the withdrawn namespace's, and an ARP announcing
        // the made-up lease — an unpublished in-plan address smuggled in as a
        // sender protocol address. The marker after them is the one published
        // box's, so its arrival proves all three were decided and none passed.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let from_retired = ipv4_frame(withdrawn, 6, [10, 1, 2, 3], 80);
        let unpublished_arp = arp_frame(stranger);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        for frame in [&made_up, &from_retired, &unpublished_arp] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the published box's frame is the only one that passed: every \
             unregistered source was dropped before the switch"
        );
        expect_silence(&mut h.switch).await;

        // The drops are named: one line per source under NET-081's own rule —
        // the ARP announcing the made-up lease shares its source's window —
        // and no interim line at all, because nothing was admitted.
        wait_for_log(&h.log, "egress-unknown-source").await;
        let logged = h.log.contents();
        for src in [stranger, withdrawn] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "a drop line names the source address {src:?}, got: {logged}"
            );
        }
        assert_eq!(
            logged.matches("egress-unknown-source").count(),
            2,
            "three unregistered-source frames make two lines (the ARP shares its \
             source's window), got: {logged}"
        );
        assert!(
            !logged.contains(UNREGISTERED_SOURCE_RULE),
            "the in-force gate admits nothing unregistered, so the interim's \
             line never fires, got: {logged}"
        );
        assert!(
            !logged.contains("T66 (#1711)"),
            "nothing here is waiting on the registration path any more, got: {logged}"
        );

        // And what the drops did not do: touch the table. The made-up lease
        // and the withdrawn namespace hold no row — the gate decided and
        // dropped, it never published.
        assert!(
            h.table.by_source(stranger).is_none(),
            "a dropped frame published no row"
        );
        assert!(
            h.table.by_source(withdrawn).is_none(),
            "the withdrawn namespace stays withdrawn"
        );
        assert!(
            h.table.by_source(LEASE).is_some(),
            "the one published box is still held"
        );
    }

    /// The relay's framing and head handling: the upgrade head is forwarded
    /// verbatim (asserted by every harness), and the frames a guest writes
    /// past it in the same `read` — pipelined behind the head, as a fast
    /// shuttle can — are relayed as frames, not lost to the head's read.
    #[tokio::test]
    async fn frames_pipelined_behind_the_upgrade_head_are_relayed() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(LEASE),
            Ipv4Addr::LOCALHOST,
        ));
        // The head plus two frames in one write, both declared; the harness
        // has read the forwarded head back off the switch end already.
        let first = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        let second = ipv4_frame(LEASE, 17, [100, 64, 0, 1], 53);
        let mut pipelined = CONNECT_REQUEST.to_vec();
        for frame in [&first, &second] {
            pipelined.extend_from_slice(&(frame.len() as u16).to_le_bytes());
            pipelined.extend_from_slice(frame);
        }
        let mut h = gate_over_with(registry, pipelined).await;

        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, first, "the first pipelined frame arrived");
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, second, "and the second after it");
    }

    /// The vsock port this gate sits on carries gvproxy's control verbs too,
    /// not only the shuttle's upgrade: the guest daemon drives its publishes and
    /// its DNS zone over the same bridged socket, speaking plain HTTP/1.1 with a
    /// `Content-Length` body and no frame ever on the wire. An **admitted**
    /// exchange passes through untouched — head, body and response, verbatim —
    /// or the daemon's zone never comes up and every publish reads as a
    /// malformed status line, the shape the macOS and KVM lanes were red on.
    /// This one is admitted under the announced interim: the record's address
    /// is an in-plan lease no published row holds, the reach the interim keeps
    /// alive until the creator-side rows land.
    #[tokio::test]
    async fn control_requests_are_spliced_verbatim() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // The request the guest's own control client writes: head and body in
        // one write, framed by `Content-Length`, the way `post_json` builds
        // it — publishing the zone name at a lease the plan could hand out.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_over_control(registry, request).await;

        // The head and body arrived (the harness read them back verbatim);
        // nothing more may follow, and the response comes back the same way,
        // so the guest's exchange completes as though the gate were not
        // there.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(response)
            .await
            .expect("writing gvproxy's response");
        let mut seen = vec![0u8; response.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen, response,
            "the control response reaches the guest verbatim"
        );

        // The exchange was decided, and admitted under the interim — which
        // says so, once, marked as the interim's own line and naming the
        // address the publish went out at. Nothing was dropped: a control
        // exchange is not a frame, and no frame verdict ran on it.
        wait_for_log(&h.log, "egress-unregistered-publish").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("interim=true"),
            "an applied interim says so on its own line, got: {logged}"
        );
        assert!(
            logged.contains("source=100.64.0.10"),
            "the interim's line names the address the publish went out at, got: {logged}"
        );
        assert!(
            !logged.contains("dropped"),
            "no frame was decided on this connection, got: {logged}"
        );
    }

    /// A published row publishes its **own** name — the session name it was
    /// registered under — both forms the daemon's zone-add carries: the bare
    /// two-label name (NET-001) and the deprecated host-qualified one beside
    /// it (NET-002), whose host ids are every co-resident daemon's on the
    /// shared switch, unbounded, so no declaration can carry the qualified
    /// form and the decision maps it onto the held name's index instead. The
    /// name a row does not hold — another session's, or a label that merely
    /// extends the row's own past the dot boundary — is refused at the same
    /// address: the publish's records are the owner's own, and nobody else's
    /// row decides them.
    #[tokio::test]
    async fn a_row_publishes_its_own_name_bare_and_host_qualified() {
        let registry = BoxRegistry::new(SUBNET);
        // The row registered as `web` at its lease, no declared names: the
        // registration wire carries none — the box's name is the row's own.
        tcp_lan_box(&registry, LEASE);
        // The daemon's own zone-add for this box: two records, both at the
        // box's lease — the bare name, and the qualified form under a
        // co-resident daemon's host id.
        let body = br#"{"name":"min.internal.","records":[
            {"name":"web","ip":"100.64.0.9"},{"name":"web.host-a1b2","ip":"100.64.0.9"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the zone-add");
        let mut spoken = vec![0u8; request.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken, request,
            "the row's own name, both forms, reached the switch whole"
        );
    }

    /// The same publish's refusal: a zone-add whose record names another
    /// session — or a label that merely extends the row's own past the dot
    /// boundary, `webmail` beside `web` — is refused at the row's own
    /// address, before a byte of it reaches the switch, and the refusal names
    /// the record it was refused for.
    #[tokio::test]
    async fn a_zone_add_of_a_foreign_name_at_a_rows_address_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let body = br#"{"name":"min.internal.","records":[
            {"name":"webmail","ip":"100.64.0.9"},{"name":"other","ip":"100.64.0.9"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the zone-add");

        // Refused, and named: the rule is its own class, the address is the
        // one the publish was at, and the record is the first one the row
        // does not hold — the dot-boundary case, `webmail` beside `web`.
        wait_for_log(&h.log, UNDECLARED_PUBLISH_RECORD_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-publish-record\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("source=100.64.0.9"),
            "the refusal names the address it was at, got: {logged}"
        );
        assert!(
            logged.contains("port_or_name="),
            "the refusal names the record it was refused for, got: {logged}"
        );
        assert!(
            logged.contains("does not admit"),
            "the refusal names the reason, got: {logged}"
        );

        // Nothing of it reached the switch, and the guest's side comes down.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a refused zone-add reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        expect_teardown(&mut h.guest).await;
    }

    /// A control body's bytes are never scanned for the connect path: the
    /// zone-add request carries the session's name, and a session name may
    /// legally hold those bytes (`fix/connection-leak`), so a relay that
    /// grepped the stream for them would tear a perfectly legitimate control
    /// exchange down. The gate parses the body as the verb's own JSON shape
    /// and never as a byte scan, so a body carrying the path verbatim — in
    /// the zone name it carries — is summarized as the request its shape says
    /// it is, admitted under the interim like any other in-plan publish, and
    /// answered.
    #[tokio::test]
    async fn a_body_carrying_the_connect_path_passes_verbatim() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // The request the guest's own control client writes, with a session
        // named after a branch — the legitimate body a content watch would
        // have torn this exchange down over.
        let body =
            br#"{"name":"fix/connection-leak","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the control request");

        // The request the gate admitted arrives whole — head and body
        // together — exactly as the guest sent it, so what gvproxy holds is
        // the request the table decided on.
        let mut spoken = vec![0u8; request.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken, request,
            "the gate forwards the admitted control request verbatim, head and body together"
        );

        // The body arrives exactly as written, connect path and all: the
        // path is what a request *line* says, and this connection's one
        // request line was already spoken.
        assert_eq!(
            &spoken[request.len() - body.len()..],
            &body[..],
            "a body carrying the connect path reaches gvproxy exactly as the guest sent it"
        );

        // And the exchange completes as though the gate were not there.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(response)
            .await
            .expect("writing gvproxy's response");
        let mut seen = vec![0u8; response.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen, response,
            "the control response reaches the guest verbatim"
        );

        // Nothing was refused and nothing was scanned: the body was parsed as
        // the request its shape said it was, and the parse never met a
        // request line.
        let logged = h.log.contents();
        assert!(
            !logged.contains("egress-control-upgrade"),
            "a body carrying the connect path was refused as an upgrade, got: {logged}"
        );
        assert!(
            !logged.contains("dropped"),
            "a control exchange is not a frame, got: {logged}"
        );
    }

    /// A control connection carries exactly one request, and the first guest
    /// byte past that request's `Content-Length` body tears the connection
    /// down without being written on. gvproxy hijacks a hijacking request
    /// however late in the connection's life it arrives, so a guest that has
    /// spoken a control verb and then writes a second request on the same
    /// connection — with frames from a source no box holds pipelined behind
    /// it — is one hijack from the ungated egress NET-081 exists to prevent.
    /// Nothing reaches the switch, both sides come down after the answer the
    /// gate owes the request it did relay, and the refusal says so under its
    /// own rule.
    #[tokio::test]
    async fn a_second_request_after_the_body_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // One ordinary control exchange — an honest body at an in-plan lease
        // the interim admits — answered, so the connection is live as control
        // traffic and the guest is still on it: the state a smuggled second
        // request arrives in, however long the guest waits.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let answer: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut h = gate_over_control(registry, request).await;

        // The second request: a whole control head the gate never reads as
        // one, because this connection's one request is already spoken. With
        // a frame from a source no box holds pipelined behind it, for the
        // ungated egress the hijack would buy.
        let second =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n";
        h.guest
            .write_all(second)
            .await
            .expect("writing the smuggled second request");
        let frame = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &frame).await;

        // Refused unread, and said so at the gate's own cadence — before the
        // switch end below closes, so the refusal is what ended the relay.
        wait_for_log(&h.log, "spoken past its one request").await;
        // Not one byte of the second request — and none of the frame behind
        // it — reached the switch: its end sees the half-close that ends the
        // exchange, and nothing before it.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the smuggled request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // The request that *was* relayed is still owed its answer: answer it
        // and close the switch end, so the drain of the answer completes.
        h.switch
            .write_all(answer)
            .await
            .expect("answering the control request");
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");
        // Not one byte of the second request — and none of the frame behind
        // it — reached the switch: its end sees the half-close that ends the
        // exchange, and nothing before it.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the smuggled request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // And the guest's side comes down with it — after the answer to the
        // request it legitimately made, which the gate owes it, and with no
        // byte of the stream it tried to steal behind it.
        let mut answered = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut answered).await;
        assert_eq!(
            answered, answer,
            "the refused guest got the answer it was owed, and only that"
        );
        // The connection is down with no further byte for the guest — a
        // smuggler's unread bytes were discarded, so its side reads the
        // teardown as a reset rather than a clean end.
        expect_teardown(&mut h.guest).await;
        // The refusal is its own class, not a frame drop: no frame was ever
        // parsed, so no source address was read and no box's rule fired.
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-control-upgrade\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "no frame behind the refused request was parsed or dropped, got: {logged}"
        );
    }

    /// The same refusal when the smuggled request shares one write with the
    /// request it trails — head, body, a second request and a frame, all
    /// pipelined the way a fast guest puts them on the wire. The body is
    /// relayed by its `Content-Length` alone, so no read ever takes a byte of
    /// what follows it, whatever write the bytes arrived in: the last body
    /// byte is the gate's to relay and the one after it is not.
    #[tokio::test]
    async fn a_request_pipelined_behind_the_body_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A real request with a real body — an honest zone-add at an in-plan
        // lease the interim admits — so the count the gate relays is a
        // `Content-Length` it read out of the head and a body it decided on,
        // not the empty body of a hand-built one.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        // The boundary the switch end's read is pinned to: the one request the
        // head declared, everything behind it being the gate's to refuse.
        let spoken_len = request.len();
        // Pipelined behind it in the same write: a whole second request, and
        // a frame from a source no box holds.
        request.extend_from_slice(
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n",
        );
        let frame = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        request.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        request.extend_from_slice(&frame);
        // Written by hand rather than through [`gate_over_control`]: the
        // pipelined bytes behind the first request are the gate's to refuse,
        // so the switch end reads only the first request back.
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the pipelined request");

        // The one request the head declared arrives whole — head and body —
        // and not one byte more.
        let mut spoken = vec![0u8; spoken_len];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken,
            &request[..spoken_len],
            "the one request the head declared arrived whole, and alone"
        );
        // The smuggled request was refused unread: the gate relays exactly
        // what the `Content-Length` declared and no byte past it.
        wait_for_log(&h.log, "spoken past its one request").await;
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the pipelined request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // The request that *was* relayed is still owed its answer: answer it
        // and close the switch end, so the drain of the answer completes.
        let answer: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(answer)
            .await
            .expect("answering the control request");
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");
        // The guest got the answer it was owed for the request it did make,
        // then the connection came down — with no byte of the smuggled
        // request or the frame behind it for anyone to read.
        let mut answered = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut answered).await;
        assert_eq!(
            answered, answer,
            "the refused guest got the answer it was owed"
        );
        // And the connection came down — with no byte of the smuggled request
        // or the frame behind it for anyone to read; the smuggler's own
        // unread bytes were discarded with the teardown.
        expect_teardown(&mut h.guest).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-control-upgrade\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "no frame behind the refused request was parsed or dropped, got: {logged}"
        );
    }

    /// The first head picks the relay, and the choice is deliberately narrow:
    /// the frame stream is exactly the connect path, because gvproxy hijacks
    /// on the path alone, whatever the method or query; the control relay is
    /// exactly the three verbs the daemon's own client speaks, each with one
    /// `Content-Length`-framed body; and everything else — the `/tunnel`
    /// hijack, the verbs the gate does not relay, a target it has never
    /// classified, a head too malformed to frame — is refused **before
    /// forwarding**. The two ways to be wrong fail differently, and only one
    /// of them widens reach: reading an upgrade as control would splice it to
    /// the switch ungated, while reading a control request as frames fails
    /// closed at its first length claim.
    #[test]
    fn the_first_head_picks_the_relay() {
        // The frame stream: the connect path, however it is asked for.
        assert_eq!(GuestSpeak::of_head(CONNECT_REQUEST), Ok(GuestSpeak::Frames));
        assert_eq!(
            GuestSpeak::of_head(b"GET /connect HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Ok(GuestSpeak::Frames),
            "gvproxy hijacks on the path alone, not on the method"
        );
        assert_eq!(
            GuestSpeak::of_head(b"POST /connect?guest=1 HTTP/1.1\r\n\r\n"),
            Ok(GuestSpeak::Frames),
            "a query on the path is still the path"
        );

        // The control verbs: one request each, named by the verb its path
        // picks — the key to the body shape the gate reads it as. An absent
        // count is HTTP's own no-body, not a refusal — the body the gate
        // reads is the one the count names.
        for (verb, path) in CONTROL_VERBS {
            let path = String::from_utf8_lossy(path);
            let head =
                format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{{}}");
            assert_eq!(
                GuestSpeak::of_head(head.as_bytes()),
                Ok(GuestSpeak::Control { verb, body: 2 }),
                "{path} is the control relay for {verb:?}",
            );
        }
        assert_eq!(
            GuestSpeak::of_head(b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Ok(GuestSpeak::Control {
                verb: ControlVerb::DnsAdd,
                body: 0,
            }),
            "a control request with no Content-Length has no body to read"
        );

        // Everything else is refused, and the refusal names what was asked
        // for — the bytes a diagnostic reads off the line.
        let refused = |head: &[u8]| GuestSpeak::of_head(head).unwrap_err().target;
        // The other hijacking verb gvproxy serves on this socket: it dials an
        // address inside the virtual network and relays bytes, so it is not
        // the gate's to splice.
        assert_eq!(
            refused(b"TUNNEL /tunnel?ip=100.64.0.9&port=22 HTTP/1.1\r\n\r\n"),
            b"/tunnel?ip=100.64.0.9&port=22",
            "the tunnel hijack is refused, not spliced ungated"
        );
        // A verb the daemon never speaks — the listing gvproxy serves the
        // host, not the guest.
        assert_eq!(
            refused(b"GET /services/forwarder/all HTTP/1.1\r\n\r\n"),
            b"/services/forwarder/all",
            "a verb the daemon does not speak is refused"
        );
        // A target one byte past the connect path is not it.
        assert_eq!(
            refused(b"POST /connectx HTTP/1.1\r\n\r\n"),
            b"/connectx",
            "an exact path is an exact match: /connectx is not /connect"
        );
        // The absolute form is not the origin form the gate relays.
        assert_eq!(
            refused(b"GET http://localhost/connect HTTP/1.1\r\n\r\n"),
            b"http://localhost/connect",
            "an absolute-form target is not the connect path"
        );
        // A body the gate cannot frame the end of: chunked, or two counts
        // disagreeing.
        assert_eq!(
            refused(
                b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            b"/services/dns/add",
            "a chunked control request is refused: the gate relays by a byte count"
        );
        assert_eq!(
            refused(
                b"POST /services/dns/add HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 4\r\n\r\n"
            ),
            b"/services/dns/add",
            "a split body count is the smuggling shape, and is refused"
        );
        assert_eq!(
            refused(b"POST /services/dns/add HTTP/1.1\r\nContent-Length: 0x2\r\n\r\n"),
            b"/services/dns/add",
            "a body count that is not a plain decimal number is refused"
        );
        // And a head too malformed to read a request line from, which names
        // nothing rather than guess at bytes.
        assert_eq!(
            refused(b"\r\nHost: localhost\r\n\r\n"),
            b"",
            "a head with no request line is refused, naming nothing"
        );
        // The refusal is a warn line, so it does not echo a hostile head back:
        // a target past the naming bound is named to the bound and no further.
        let long = vec![b'x'; MAX_HEAD];
        let mut shouted = b"GET /".to_vec();
        shouted.extend_from_slice(&long);
        shouted.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let named = GuestSpeak::of_head(&shouted).unwrap_err().target;
        assert!(
            named.len() <= MAX_NAMED_TARGET,
            "a refused head names at most a bounded prefix of its target, got {} bytes",
            named.len()
        );

        // What the gate classifies by is the request line's target — not the
        // bytes anywhere else in the head, and not the body's content: a
        // control verb whose header block carries the connect path is still
        // the control request its own line says it is.
        assert_eq!(
            GuestSpeak::of_head(
                b"POST /services/dns/add HTTP/1.1\r\nHost: fix/connection-leak\r\nContent-Length: 0\r\n\r\n"
            ),
            Ok(GuestSpeak::Control {
                verb: ControlVerb::DnsAdd,
                body: 0,
            }),
            "the connect path in a header does not make a control request an upgrade"
        );
    }

    /// A request head the gate has not classified is refused before it is
    /// forwarded, because gvproxy's switch socket serves more than the
    /// shuttle's upgrade and the daemon's three verbs: `/tunnel` dials an
    /// address inside the virtual network and relays bytes to it, and what a
    /// hijacked request may do is nothing the reach rules get a say in. The
    /// hijack arriving as a first head — the way the guest's own client
    /// arrives — is refused unread: gvproxy never holds the request, both
    /// ends come down, and the refusal names the target under its own rule.
    #[tokio::test]
    async fn a_request_outside_the_allow_list_is_refused_before_forwarding() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let head = b"TUNNEL /tunnel?ip=100.64.0.9&port=22 HTTP/1.1\r\n\r\n";
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(head)
            .await
            .expect("writing the tunnel hijack");

        // Refused before forwarding, and said so at the frame drops' cadence:
        // the refusal names the target — the bytes a diagnostic reads off the
        // line — under the head's own rule.
        wait_for_log(&h.log, "egress-undeclared-verb").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-verb\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("request_target=/tunnel?ip=100.64.0.9&port=22"),
            "the refusal names the target it refused, got: {logged}"
        );
        // Nothing of it reached the switch — the head was never written on,
        // so gvproxy never held a request to hijack — and its end comes down
        // rather than hanging.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a refused head reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // And the guest's side comes down with it, not left hanging.
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("the gate left the refused connection hanging"),
        }
    }

    /// Refused heads are rate-limited the way frame drops are, and across
    /// connections: a guest that connects fresh for every attempt — exactly as
    /// cheap as sending a frame — must not buy a warn line each time. The
    /// window is keyed by the rule alone, because a refused head names no
    /// source address, so two connections refused in the same interval make
    /// one line, not two.
    #[tokio::test]
    async fn refused_request_heads_share_one_rate_window_across_connections() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let gate_sock = dir.path().join("gvproxy-gate.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let _gate = EgressGate::spawn(
            gate_sock.clone(),
            switch_sock.clone(),
            registry.table(),
            NodePlaneBaseline::built_in(SUBNET),
        )
        .expect("spawning the egress gate");

        // Two connections, each refused on its head — the guest's own
        // client's shape: connect, speak a head the gate does not relay, and
        // take the teardown.
        let head = b"GET /services/forwarder/all HTTP/1.1\r\n\r\n";
        for _ in 0..2 {
            let mut guest = UnixStream::connect(&gate_sock)
                .await
                .expect("connecting the guest end");
            let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
            guest
                .write_all(head)
                .await
                .expect("writing the refused head");
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a refused head reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("the gate left the switch side hanging"),
            }
            match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
                Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
                Err(_) => panic!("the gate left the refused connection hanging"),
            }
        }

        // One warn line for the pair, not one per connection.
        wait_for_log(&log, "egress-undeclared-verb").await;
        assert_eq!(
            log.contents().matches("egress-undeclared-verb").count(),
            1,
            "two refused connections inside one interval make one line, got: {}",
            log.contents()
        );
    }

    /// A guest that never ends an upgrade head is refused, not buffered, and
    /// nothing of it ever reaches the switch. The head read is bounded at
    /// [`MAX_HEAD`] bytes, so a peer that talks past the bound without ever
    /// writing the head's end — a peer that is speaking, not silent, so the
    /// handshake timeout is not what catches it — is failed closed on at the
    /// bound itself.
    #[tokio::test]
    async fn a_head_that_never_ends_refuses_the_connection() {
        // No namespace needs publishing: a peer refused at the head is refused
        // before any frame is read, whatever the table holds.
        let registry = BoxRegistry::new(SUBNET);
        // The guest's first write is the noise itself — no head is spoken, so
        // the bytes the head reader sees have no end to find.
        let mut h = gate_connected(registry).await;

        // `MAX_HEAD + 1` bytes with no `\r\n\r\n` anywhere in them.
        let noise = vec![b'x'; MAX_HEAD + 1];
        h.guest
            .write_all(&noise)
            .await
            .expect("writing the endless head");

        // Refused on the head's own bound: the log names the over-long head,
        // so the byte-count check is what refused the connection, not the
        // handshake timeout waiting out a silent peer.
        wait_for_log(&h.log, &format!("exceeded {MAX_HEAD} bytes without ending")).await;
        // The gate must close the guest's side rather than leave it hanging…
        let mut probe = [0u8; 1];
        let refused = tokio::time::timeout(DEADLINE, h.guest.read_exact(&mut probe))
            .await
            .expect("the gate refuses within the deadline")
            .is_err();
        assert!(refused, "the guest connection is closed, not left hanging");
        // …and tear the switch side down with it: the stand-in switch reads
        // EOF, not an endless head.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of an endless head reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
    }

    /// A frame the guest claims is past the largest frame the gate relays is
    /// refused, not sized to: the length prefix is the guest's own bytes, so a
    /// claim past the MTU-derived maximum is a malformed or hostile peer's,
    /// and the connection comes down rather than the gate either allocating
    /// to the claim or forwarding what it carried.
    #[tokio::test]
    async fn a_frame_claimed_past_the_maximum_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // A two-byte prefix claiming a frame past `max_frame()`, with no body
        // behind it: the claim alone is the refusal.
        assert!(
            usize::from(u16::MAX) > max_frame(),
            "the claim must be past the largest frame the gate relays"
        );
        h.guest
            .write_all(&u16::MAX.to_le_bytes())
            .await
            .expect("writing the oversized claim");

        // The refusal says so: the relay ended on the claim's length, and…
        wait_for_log(&h.log, &format!("exceeds max {}", max_frame())).await;
        // …the gate closes the guest's side rather than leave it hanging.
        let mut probe = [0u8; 1];
        let refused = tokio::time::timeout(DEADLINE, h.guest.read_exact(&mut probe))
            .await
            .expect("the gate refuses within the deadline")
            .is_err();
        assert!(refused, "the guest connection is closed, not left hanging");
        // The switch side comes down with it, and nothing arrived there past
        // the forwarded head: the claim was never read into a frame.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) arrived at the switch past the head"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
    }

    /// The relay ends when either leg ends, not only when the guest goes away:
    /// a switch that closes this one connection's end — without the whole
    /// gvproxy process exiting behind it, which the supervisor catches and
    /// tears the gate down for — must not leave the egress leg waiting on a
    /// guest that is idle and has nothing more to send. The ingress leg's
    /// completion is raced against the egress leg, so the relay, the gate's
    /// dial, and the switch write half come down at once, with a line saying
    /// which leg ended, instead of lingering until the guest's next frame.
    #[tokio::test]
    async fn a_switch_that_hangs_up_takes_the_relay_down_with_it() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // The switch hangs up while the guest is on the connection and idle:
        // no frame is in flight, so nothing but this close can end the relay.
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");

        // The gate says which leg ended — the line a bundle's daemon log tail
        // carries for a box whose egress went dark with the guest still there.
        wait_for_log(&h.log, "the switch closed its side of the connection").await;
        // And the guest's side comes down with the relay, promptly, rather
        // than hanging on until its next frame finds nowhere to write.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a hung-up-on guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a hung-up switch left the relay up past {DEADLINE:?}"),
        }
    }

    /// The control relay comes down with a switch that hangs up on an idle
    /// control connection — the same per-connection close the frame relay
    /// races its legs for. gvproxy closes this one connection's end while the
    /// guest is still on it, idle, waiting for the answer to the request it
    /// already spoke: a keep-alive control channel's normal event, not a
    /// process exit the supervisor catches. A relay that watched only its
    /// request leg would never learn of it and hold the splice, the gate's
    /// dial and both socket halves open until the guest next spoke or closed.
    #[tokio::test]
    async fn a_switch_that_hangs_up_takes_the_control_relay_down_with_it() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // One live control exchange — an honest zone-add at an in-plan lease
        // the interim admits — so the connection really is relaying control
        // traffic and the guest is on it, idle, waiting.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_over_control(registry, request).await;

        // The switch hangs up while the guest is idle: no request is in
        // flight, so nothing but this close can end the exchange.
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");

        // The gate says which leg ended — the line a bundle's daemon log tail
        // carries for a control connection the host closed under an idle guest.
        wait_for_log(
            &h.log,
            "the switch closed its side of the control connection",
        )
        .await;
        // And the guest's side comes down with the relay, promptly, rather than
        // hanging on until a guest with nothing more to say speaks again.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a hung-up-on guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a hung-up switch left the control relay up past {DEADLINE:?}"),
        }
    }

    /// A switch that takes a control request and then says nothing — neither
    /// answering nor closing, the shape a wedged gvproxy would wear —
    /// releases the relay at the drain bound, the same bound the handshake
    /// reads under. The drain after the guest's request ends is bounded
    /// because it is the only thing left holding the relay, the gate's dial
    /// and both socket halves: without the bound they would hang on a switch
    /// that is never going to speak again, for as long as the gate lives.
    #[tokio::test]
    async fn a_switch_that_never_answers_releases_the_control_relay_at_the_drain_bound() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one every real
        // connection reads and drains under — so the release is watched in
        // milliseconds rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the release must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        tokio::spawn(serve_connection(
            gate_end,
            switch_sock.clone(),
            table,
            NodePlaneBaseline::built_in(SUBNET),
            Arc::new(DropLimiter::new()),
            Arc::new(PublishedForwards::new()),
            bound,
            UNREGISTERED_SOURCE_PHASE,
        ));
        // One control request, spoken whole, answered by nothing: an honest
        // zone-add at an in-plan lease the interim admits.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        guest
            .write_all(&request)
            .await
            .expect("writing the control request");
        // The gate's dial is accepted and the request arrives at the switch…
        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        let mut seen = vec![0u8; request.len()];
        read_within(&mut switch, &mut seen).await;
        assert_eq!(seen, request, "the one request reached the switch");
        // …and the guest ends its side of it — the daemon's own client does
        // the same once its answer is read — which is the state whose drain
        // is the bounded one.
        guest.shutdown().await.expect("closing the guest's end");

        // The drain gives the switch its bound, then gives up on it with a
        // line naming the bound it waited out.
        wait_for_log(&log, "did not answer a control request within the bound").await;
        let logged = log.contents();
        assert!(
            logged.contains(&format!("drain_timeout={bound:?}")),
            "the release names the bound it waited out, got: {logged}"
        );
        // And the guest's side comes down with the relay, promptly, rather
        // than hanging on until the switch might have spoken.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a drained guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a switch that never answered held the relay past {DEADLINE:?}"),
        }
    }

    /// A guest that speaks its control request and then stays connected
    /// releases the relay at the drain bound when the switch neither answers
    /// nor closes — the shape the bound was added for that a guest-close does
    /// not reach: the guest is in its normal posture, waiting for the answer,
    /// so it neither closes nor speaks past its request, and a wedged
    /// gvproxy neither answers nor hangs up. Neither leg of the exchange then
    /// has anything to end it, and the relay task, the gate's dial and both
    /// socket halves would hang for the gate's lifetime; the probe read
    /// running under the same bound the drain runs under is what ends the
    /// request leg at the bound and hands the release to the drain.
    #[tokio::test]
    async fn a_guest_silent_after_its_request_releases_the_control_relay_at_the_drain_bound() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one every real
        // connection reads and drains under — so the release is watched in
        // milliseconds rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the release must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        tokio::spawn(serve_connection(
            gate_end,
            switch_sock.clone(),
            table,
            NodePlaneBaseline::built_in(SUBNET),
            Arc::new(DropLimiter::new()),
            Arc::new(PublishedForwards::new()),
            bound,
            UNREGISTERED_SOURCE_PHASE,
        ));
        // One control request, spoken whole, and then the guest stays on the
        // connection: no close, nothing more to say — the posture it waits
        // an answer in, which is why neither leg can end the exchange. An
        // honest zone-add at an in-plan lease the interim admits.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        guest
            .write_all(&request)
            .await
            .expect("writing the control request");
        // The gate's dial is accepted and the request arrives at the switch,
        // where the stand-in switch reads it and says nothing back, closing
        // nothing: the wedged switch, byte for byte.
        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        let mut seen = vec![0u8; request.len()];
        read_within(&mut switch, &mut seen).await;
        assert_eq!(seen, request, "the one request reached the switch");

        // The bound ends the guest's silent wait, and the release runs
        // through the drain: the line naming the bound the gate waited out,
        // with the guest still on the connection — the state whose release
        // no leg could otherwise supply.
        wait_for_log(&log, "did not answer a control request within the bound").await;
        let logged = log.contents();
        assert!(
            logged.contains(&format!("drain_timeout={bound:?}")),
            "the release names the bound it waited out, got: {logged}"
        );
        // And the guest's side comes down with the relay, promptly, rather
        // than hanging on a guest that is only waiting for its answer.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a waiting guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => {
                panic!("a silent guest on a wedged switch held the relay past {DEADLINE:?}")
            }
        }
    }

    /// The peer the gate's handshake reads from lives inside the escape
    /// boundary NET-081 exists for, so the handshake is bounded: a guest that
    /// connects and then stays silent — saying nothing at all, or starting a
    /// head it never ends — is refused within the bound, and the host switch
    /// connection the gate's dial opened comes down with it, with nothing of
    /// the guest ever written on. Without the bound a silent guest would hold
    /// a host switch connection and a relay task for the gate's lifetime.
    #[tokio::test]
    async fn a_silent_guest_is_refused_within_the_handshake_bound() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one `accept_loop`
        // passes every real connection — so the refusal is watched in
        // milliseconds rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the refusal must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        // The stand-in switch: a listener the gate's handshake dials.
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // The two shapes of a silent peer: a guest that says nothing at all,
        // and one that starts a head and never ends it. Both are refused the
        // same way.
        for first_write in [Vec::new(), b"POST /connec".to_vec()] {
            let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
            tokio::spawn(serve_connection(
                gate_end,
                switch_sock.clone(),
                table.clone(),
                NodePlaneBaseline::built_in(SUBNET),
                Arc::new(DropLimiter::new()),
                Arc::new(PublishedForwards::new()),
                bound,
                UNREGISTERED_SOURCE_PHASE,
            ));
            if !first_write.is_empty() {
                guest
                    .write_all(&first_write)
                    .await
                    .expect("writing the never-ended head");
            }
            // The gate dials the switch first, so a silent guest is holding a
            // live host switch connection at this point — the thing the bound
            // exists to release.
            let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");

            // The switch side comes down within the deadline, and nothing of
            // the guest was written on before it did.
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a silent guest reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("a silent guest held the switch connection past {DEADLINE:?}"),
            }
            // And the guest's side is closed too, not left hanging.
            match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a silent guest to read"),
                Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
                Err(_) => panic!("the gate left the silent guest's connection hanging"),
            }
        }
    }

    /// The guest source a test scripts by hand: the connections and the accept
    /// failures to hand [`accept_loop`], in the order the test says and no
    /// sooner, so the loop's failure handling can be driven without first
    /// having to hit a real process fd limit. A script that runs out is a test
    /// bug, so it panics rather than answer an accept silently.
    struct ScriptedGuests(mpsc::UnboundedReceiver<io::Result<UnixStream>>);

    impl GuestSource for ScriptedGuests {
        #[expect(
            clippy::manual_async_fn,
            reason = "an `async fn` in a trait returns a future that is not known `Send`, and the \
                      loop this feeds is spawned on the tokio runtime"
        )]
        fn accept(&mut self) -> impl Future<Output = io::Result<UnixStream>> + Send {
            async {
                self.0
                    .recv()
                    .await
                    .expect("the script ran out before the test was done accepting")
            }
        }
    }

    /// The guest connections and accept failures the accept-loop tests share:
    /// a stand-in switch behind `switch_sock`, the gate's log captured, and
    /// the loop started on a scripted source with a ready-made channel to feed
    /// it through.
    async fn loop_over_script(
        switch_sock: &std::path::Path,
        table: &super::BoxTable,
    ) -> (
        mpsc::UnboundedSender<io::Result<UnixStream>>,
        tokio::task::JoinHandle<()>,
        CaptureWriter,
        tracing::subscriber::DefaultGuard,
    ) {
        let (log, guard) = capture_log();
        let (feed, script) = mpsc::unbounded_channel();
        let accept = tokio::spawn(accept_loop(
            ScriptedGuests(script),
            switch_sock.to_path_buf(),
            table.clone(),
            NodePlaneBaseline::built_in(SUBNET),
            Arc::new(DropLimiter::new()),
            Arc::new(PublishedForwards::new()),
            HANDSHAKE_TIMEOUT,
            UNREGISTERED_SOURCE_PHASE,
        ));
        (feed, accept, log, guard)
    }

    /// An accept failure the host can ride out is ridden out: a momentary fd
    /// or memory shortage — the failure a long-lived host daemon holding a
    /// socket and a dial per live relay can be pushed into, and one this loop
    /// used to read as the listener's own end — costs a backoff and one line,
    /// not the gate, every live relay, and every box's egress for the rest of
    /// the VM's life. The connection already relayed still relays, and the
    /// next one is served.
    #[tokio::test]
    async fn a_transient_accept_failure_is_ridden_out_and_keeps_the_gate_serving() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        // The stand-in switch: a listener the gate's handshake dials.
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // The gate's first connection: a real one, already connected, so what
        // happens to a live relay across the failure is observable.
        let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        let (feed, accept, log, _guard) = loop_over_script(&switch_sock, &table).await;
        feed.send(Ok(gate_end))
            .expect("queueing the first connection");

        // Complete the first connection's upgrade: the gate dials, the guest
        // speaks, the head is forwarded verbatim.
        let (mut switch_one, _) = listener.accept().await.expect("accepting the gate's dial");
        guest
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the upgrade head");
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        read_within(&mut switch_one, &mut head).await;
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the upgrade head verbatim"
        );

        // Now the transient failure: the process fd limit, which `std` leaves
        // uncategorized and which the gate must not read as a dead listener.
        feed.send(Err(io::Error::from_raw_os_error(libc::EMFILE)))
            .expect("queueing the transient failure");
        wait_for_log(&log, "accept failed transiently").await;
        let logged = log.contents();
        assert!(
            logged.contains("the gate is retrying"),
            "the retry line says the gate is staying up, got: {logged}"
        );
        assert!(
            logged.contains("rule_matched=\"egress-accept-failed\""),
            "the retry line names its own class, got: {logged}"
        );
        assert!(
            !logged.contains("the gate has stopped"),
            "a transient failure is not the listener's own end, got: {logged}"
        );

        // The live relay is untouched: while the gate is backing off, a frame
        // the box declared still goes through, decided by the table.
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &declared).await;
        let seen = expect_frame(&mut switch_one).await;
        assert_eq!(
            seen, declared,
            "a live relay still relays through the gate's transient failure"
        );

        // And the connection after the failure is served: accepted past the
        // backoff, dialed for, and its head forwarded.
        let (mut guest_two, gate_end_two) = UnixStream::pair().expect("pairing a second guest");
        feed.send(Ok(gate_end_two))
            .expect("queueing the post-failure connection");
        let (mut switch_two, _) = listener
            .accept()
            .await
            .expect("accepting the gate's second dial");
        guest_two
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the second upgrade head");
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        read_within(&mut switch_two, &mut head).await;
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate serves the connection that arrives after the failure"
        );
        accept.abort();
    }

    /// An accept failure that really is the listener's own end stops the gate,
    /// fail-closed: its relays are aborted with it — the guest's ends see the
    /// close rather than a gate that stopped deciding frames silently — and
    /// the loop's task ends, which is the other half of the distinction: a
    /// gate that stops must actually stop.
    #[tokio::test]
    async fn a_fatal_accept_failure_stops_the_gate_and_its_live_relays() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // One live connection, upgraded, so the relay the gate is holding is
        // observable coming down with it.
        let (guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        let (feed, mut accept, log, _guard) = loop_over_script(&switch_sock, &table).await;
        feed.send(Ok(gate_end)).expect("queueing the connection");
        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        let mut guest = guest;
        guest
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the upgrade head");
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        read_within(&mut switch, &mut head).await;
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the upgrade head verbatim"
        );

        // The fatal failure: a descriptor no retry will bring back.
        feed.send(Err(io::Error::from_raw_os_error(libc::EBADF)))
            .expect("queueing the fatal failure");
        wait_for_log(&log, "the gate has stopped").await;

        // The live relay is down with the gate: the switch end sees the close,
        // because the relay the loop owned was aborted when the loop ended.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a relay it aborted"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left a live relay past its own stop"),
        }
        // And the loop itself has ended: the task is no longer accepting, and
        // a task that is no longer accepting is what "stopped" means here.
        match tokio::time::timeout(DEADLINE, &mut accept).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("the accept loop joined on an error: {error}"),
            Err(_) => panic!("the accept loop outlived the failure that stopped it"),
        }
    }

    /// The relays a guest can pin are bounded: each live connection costs the
    /// host a socket, a dial of the switch and a task — two host sockets and a
    /// task where the pre-gate splice cost one — so a guest that connects,
    /// completes the upgrade and then sits idle is refused past the bound,
    /// closed rather than hung, and said so at the gate's own cadence. The
    /// bound costs the guest that hits it and nobody else: a connection freed
    /// up makes room for the next one.
    #[tokio::test]
    async fn a_guest_past_the_live_connection_bound_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // One live connection arrives with the harness; the rest are opened
        // the same way, upgraded and then left idle.
        let h = gate_over(registry).await;
        let mut idle: Vec<(UnixStream, UnixStream)> = Vec::with_capacity(MAX_LIVE_RELAYS);
        while idle.len() + 1 < MAX_LIVE_RELAYS {
            idle.push(connect_over(&h).await);
        }

        // Past the bound the next connection is refused: closed, not hung, and
        // nothing of it dialed into the switch.
        let mut extra = UnixStream::connect(&h.gate_sock)
            .await
            .expect("connecting past the bound");
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, extra.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused connection to read"),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(Err(e)) => panic!("reading a refused connection failed: {e}"),
            Err(_) => panic!("the gate left a connection past its live-relay bound hanging"),
        }
        wait_for_log(&h.log, "egress-connection-cap").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("refused a guest connection past the egress gate's live-relay bound"),
            "the refusal says what it refused, got: {logged}"
        );

        // Free two connections, and watch the gate's side of them come down —
        // the proof their relays are done — before asking for another.
        for (guest, mut switch) in idle.drain(..2) {
            drop(guest);
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) arrived at the switch of a closed guest"),
                Ok(Err(e)) => panic!("reading a freed connection's switch end failed: {e}"),
                Err(_) => panic!("the gate held a relay for a closed guest past {DEADLINE:?}"),
            }
        }

        // Room again: the next connection is served, and it relays — the
        // bound refuses a guest, not egress.
        let (mut guest, mut switch) = connect_over(&h).await;
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &declared).await;
        let seen = expect_frame(&mut switch).await;
        assert_eq!(
            seen, declared,
            "a connection past a freed one is relayed again"
        );
    }

    /// A guest that sends a control head declaring a body and then withholds
    /// the body is refused at the bound, and its relay slot comes back. The
    /// head is read under the handshake's bound, but the body is the same
    /// untrusted peer's next bytes: unbounded, the read would hold the relay
    /// task, the gate's dial, both socket halves and one of the
    /// [`MAX_LIVE_RELAYS`] slots for the gate's lifetime, and enough such
    /// connections would have the accept loop refuse every guest connection
    /// after them, frame relays included. So the whole cap is filled with
    /// withheld bodies: each is closed within the bound with nothing written
    /// on the switch, and the next guest connection — one past what the cap
    /// would have refused — is served and relays.
    #[tokio::test]
    async fn withheld_control_body_releases_the_relay_slot() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one every real
        // connection reads under — so the release is watched in milliseconds
        // rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the release must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");
        let (log, _guard) = capture_log();
        let (feed, _accept) = {
            let (feed, script) = mpsc::unbounded_channel();
            let accept = tokio::spawn(accept_loop(
                ScriptedGuests(script),
                switch_sock.clone(),
                table,
                NodePlaneBaseline::built_in(SUBNET),
                Arc::new(DropLimiter::new()),
                Arc::new(PublishedForwards::new()),
                bound,
                UNREGISTERED_SOURCE_PHASE,
            ));
            (feed, accept)
        };

        // Every slot the gate has, taken by a guest that declares a body and
        // sends none of it: a valid control head, a `Content-Length` the gate
        // is willing to read, and then silence.
        let head =
            b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n";
        let mut withheld = Vec::with_capacity(MAX_LIVE_RELAYS);
        for _ in 0..MAX_LIVE_RELAYS {
            let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
            feed.send(Ok(gate_end))
                .expect("the accept loop is listening");
            guest
                .write_all(head)
                .await
                .expect("writing the control head");
            let (switch, _) = listener.accept().await.expect("accepting the gate's dial");
            withheld.push((guest, switch));
        }

        // Within the bound every one of them is refused: the switch side sees
        // the dial closed with nothing written on it, and the guest's side is
        // closed too, not left hanging.
        for (mut guest, mut switch) in withheld {
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a withheld-body request reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("a withheld control body held the relay past {DEADLINE:?}"),
            }
            match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
                Err(_) => panic!("the gate left a withheld-body guest's connection hanging"),
            }
        }
        // Said so, once, under the rule a head the gate cannot frame is
        // refused under — the same line for all of them, at the frame drops'
        // cadence.
        wait_for_log(&log, "a control body was withheld past the bound").await;
        let logged = log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-verb\"")
                && logged.contains(&format!("read_timeout={bound:?}")),
            "the refusal names its rule and the bound it waited out, got: {logged}"
        );
        assert_eq!(
            logged
                .matches("a control body was withheld past the bound")
                .count(),
            1,
            "the refusal is rate-limited to one line, got: {logged}"
        );

        // The slots came back: a connection past what the cap would have
        // refused is served — the gate dials the switch for it, forwards its
        // upgrade head, and relays its frame.
        let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        feed.send(Ok(gate_end))
            .expect("the accept loop is listening");
        guest
            .write_all(CONNECT_REQUEST)
            .await
            .expect("writing the upgrade head");
        let (mut switch, _) = match tokio::time::timeout(DEADLINE, listener.accept()).await {
            Ok(accepted) => accepted.expect("accepting the gate's dial"),
            Err(_) => {
                panic!("the gate refused a connection after the withheld bodies were released")
            }
        };
        let mut seen = vec![0u8; CONNECT_REQUEST.len()];
        read_within(&mut switch, &mut seen).await;
        assert_eq!(
            seen, CONNECT_REQUEST,
            "the upgrade head is forwarded verbatim"
        );
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &declared).await;
        let relayed = expect_frame(&mut switch).await;
        assert_eq!(
            relayed, declared,
            "a connection past the released slots relays"
        );
        assert!(
            !log.contents().contains("egress-connection-cap"),
            "no connection was refused at the cap, got: {}",
            log.contents()
        );
    }

    /// The accept loop's one decision, apart from the loop: which errors the
    /// gate rides out and which stop it. The fd and memory shortages a
    /// long-lived host daemon holding a socket and a dial per live relay can
    /// be pushed into, and the death of one connection before it was handed
    /// over, are per-attempt — they clear on their own, and a gate that died
    /// on one would take every box's egress down with it. The errors that say
    /// the listener itself is gone are fatal, because no retry will clear
    /// them: the guest's next connect fails rather than reaching a gate that
    /// has quietly stopped deciding frames.
    #[test]
    fn accept_failures_split_transient_from_fatal() {
        let ride_out = [
            libc::EMFILE,       // the process's fd limit
            libc::ENFILE,       // the system's
            libc::ENOMEM,       // no memory for the new connection
            libc::ENOBUFS,      // no buffers for it
            libc::ECONNABORTED, // it died before the gate was handed it
            libc::EPROTO,
        ];
        for errno in ride_out {
            assert_eq!(
                AcceptFailure::of(&io::Error::from_raw_os_error(errno)),
                AcceptFailure::RideOut,
                "{errno} is a per-attempt failure, not the listener's end"
            );
        }
        let fatal = [
            libc::EBADF,    // the listener's descriptor is gone
            libc::EINVAL,   // it is no longer willing to accept
            libc::ENOTSOCK, // it was never a listener
        ];
        for errno in fatal {
            assert_eq!(
                AcceptFailure::of(&io::Error::from_raw_os_error(errno)),
                AcceptFailure::Fatal,
                "{errno} is the listener's own end"
            );
        }
        // The same two per-attempt conditions in an error with no errno behind
        // it — the shape `std` itself constructs — are read off the kind, and
        // anything else is fatal.
        assert_eq!(
            AcceptFailure::of(&io::Error::new(io::ErrorKind::OutOfMemory, "no memory")),
            AcceptFailure::RideOut,
            "an out-of-memory accept is a per-attempt failure"
        );
        assert_eq!(
            AcceptFailure::of(&io::Error::new(io::ErrorKind::ConnectionAborted, "aborted")),
            AcceptFailure::RideOut,
            "a connection that died before it was handed over is per-attempt"
        );
        assert_eq!(
            AcceptFailure::of(&io::Error::new(io::ErrorKind::Unsupported, "not a socket")),
            AcceptFailure::Fatal,
            "an error that says nothing about the next attempt is fatal"
        );
    }

    /// The pure decision, apart from the relay: the families that carry no
    /// readable source never reach the table — the shared verdict's own
    /// family drops decide them, whatever the rows hold — a held source is
    /// decided by its namespace's own rules, the shared verdict unchanged,
    /// and a source no row holds is the phase's to decide, both of the
    /// phase's arms pinned here so T66's flip of the constant is the whole
    /// cutover. The node plane's own address is the baseline set's to decide
    /// beside the rows: its shipped arm is pinned by
    /// [`node_plane_source_decided_by_the_node_row_while_announced`], its
    /// in-force arm at relay level by
    /// [`unenrolled_baseline_set_from_helper_enumeration`].
    #[test]
    fn gate_verdict_decides_by_source_and_rules() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let summarize = sessions::core::egress::summarize;

        // A held source is decided by its rules: the same frame that the
        // relay test watches pass and drop, decided here with no sockets.
        let declared = summarize(&ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80));
        assert!(matches!(
            gate_verdict(&declared, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Ok(GateAdmit::Row)
        ));
        let rules = table
            .by_source(LEASE)
            .expect("the published box's row is held")
            .egress()
            .clone();
        assert!(
            matches!(
                sessions::core::egress::verdict(&declared, &rules),
                FrameVerdict::Admit
            ),
            "the shared verdict admits what the gate admits"
        );
        let undeclared = summarize(&ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443));
        assert_eq!(
            gate_verdict(&undeclared, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Err(GateDrop::Verdict(DropReason::UndeclaredSubnet {
                dst: [203, 0, 113, 7],
                proto: 6,
            }))
        );

        // The switch's own address is not a row's or the phase's to decide:
        // a frame to the gateway that is not a resolver query is refused
        // under either phase, whatever the rows hold — the gateway is a
        // control surface, and the interim that would admit this source
        // anywhere else never sees the frame.
        let surface = summarize(&ipv4_frame(LEASE, 6, SUBNET.gateway().octets(), 443));
        assert_eq!(
            gate_verdict(&surface, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 443
            })
        );
        assert_eq!(
            gate_verdict(
                &surface,
                &table,
                &baseline,
                UnregisteredSourcePhase::InForce
            ),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 443
            })
        );
        // An unregistered in-plan source would be the interim's to admit, but
        // not at the gateway: the refusal is not gated on the row, so the
        // announced concession never reaches a frame naming the switch's own
        // address on a port nothing published answers.
        let unregistered_surface = summarize(&ipv4_frame(
            [100, 64, 0, 99],
            6,
            SUBNET.gateway().octets(),
            443,
        ));
        assert_eq!(
            gate_verdict(
                &unregistered_surface,
                &table,
                &baseline,
                UNREGISTERED_SOURCE_PHASE
            ),
            Err(GateDrop::SwitchControlSurface {
                src: [100, 64, 0, 99],
                dst_port: 443
            })
        );
        // The resolver's port is the one carve-out: DNS to the gateway passes
        // the refusal and is decided behind it, admitted by the carve-out
        // whatever the row's protocols allow.
        let resolver = summarize(&ipv4_frame(LEASE, 17, SUBNET.gateway().octets(), 53));
        assert!(matches!(
            gate_verdict(&resolver, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Ok(GateAdmit::Row)
        ));
        // A row's admitted ports are no carve-out: they are the box's own
        // ingress, reached on its own address, and a frame to the gateway at
        // one of them (this row admits 8080) is refused like any other port
        // there — the row is never consulted.
        let ingress_port = summarize(&ipv4_frame(LEASE, 6, SUBNET.gateway().octets(), 8080));
        assert_eq!(
            gate_verdict(&ingress_port, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 8080
            })
        );

        // A source no row holds is the phase's to decide, and the plan decides
        // where the interim can reach: an address the plan could hand to a box
        // is admitted as the announced interim's — its source named, so the
        // relay can warn — and dropped under the per-box default that replaces
        // the interim, the arm T66 (#1711) flips the constant onto.
        let unknown = summarize(&ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80));
        assert_eq!(
            gate_verdict(
                &unknown,
                &table,
                &baseline,
                UnregisteredSourcePhase::Announced
            ),
            Ok(GateAdmit::Unregistered {
                src: [100, 64, 0, 99]
            })
        );
        assert_eq!(
            gate_verdict(
                &unknown,
                &table,
                &baseline,
                UnregisteredSourcePhase::InForce
            ),
            Err(GateDrop::UnknownSource {
                src: [100, 64, 0, 99]
            })
        );

        // The interim never reaches past the plan's lease block, under either
        // phase: the gateway the resolver carve-out is keyed to is the plan's
        // own infrastructure, and an ARP announcing it is no way to smuggle
        // one past — in-guest, ARP is a declared path for every box, so the
        // address it announces is the thing that has to be refused.
        let gateway = summarize(&ipv4_frame(
            SUBNET.dns_server().octets(),
            6,
            [10, 1, 2, 3],
            80,
        ));
        assert_eq!(
            gate_verdict(
                &gateway,
                &table,
                &baseline,
                UnregisteredSourcePhase::Announced
            ),
            Err(GateDrop::UnknownSource {
                src: SUBNET.dns_server().octets()
            })
        );
        let foreign_arp = summarize(&arp_frame([203, 0, 113, 7]));
        assert_eq!(
            gate_verdict(
                &foreign_arp,
                &table,
                &baseline,
                UnregisteredSourcePhase::Announced
            ),
            Err(GateDrop::UnknownSource {
                src: [203, 0, 113, 7]
            })
        );

        // Families with no readable source are the shared verdict's own drops,
        // under any table — an empty one included.
        let empty = BoxRegistry::new(SUBNET).table();
        assert!(empty.is_empty());
        let v6 = summarize(&ipv6_frame());
        assert_eq!(
            gate_verdict(&v6, &empty, &baseline, UNREGISTERED_SOURCE_PHASE),
            Err(GateDrop::Verdict(DropReason::Ipv6))
        );
        let truncated = summarize(&[0u8; 13]);
        assert_eq!(
            gate_verdict(&truncated, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Err(GateDrop::Verdict(DropReason::Truncated))
        );
        // The summaries agree with the families the frames were built as.
        assert_eq!(v6.family(), FrameFamily::Ipv6);
        assert_eq!(truncated.family(), FrameFamily::Truncated);
    }

    /// NET-085's bound at the decision that makes it: a root process inside
    /// the VM spoofs another resident box's address, and the gate bounds the
    /// spoofer to the spoofed box's own reach — the frame is decided by the
    /// row that holds the spoofed source, that box's own declaration, never
    /// the union (design §4.3 rule 2). The resident union of design §8 is
    /// not what one spoof buys: it is what an attacker assembles by choosing
    /// sources, one row's reach per spoofed source, plus the node plane's
    /// baseline set (design §5.1).
    ///
    /// The table is the union's membership as T66 (#1711) will publish it:
    /// `web` and `db` with disjoint declared subnets, `locked` declaring
    /// nothing, and the run path's own node row. Every spoofed attempt is
    /// recorded — source, destination, protocol, port, the phase, and the
    /// verdict — and the record is printed one line per attempt, grouped by
    /// spoofed source, in the gate's drop-line shape, so the bound a spoof
    /// bought can be read straight off the output.
    ///
    /// Where the shipped posture differs from the bound's shape the test
    /// pins both arms, the way the relay tests do: while announced the node
    /// row is allow-all and an in-plan source no row holds is admitted with
    /// no rules at all — the gaps the baseline phase's flip (#1786) and
    /// T66's flip (#1711) close, and the comments below name the in-force
    /// arm each such admit becomes.
    #[test]
    fn spoofed_source_bounded_to_resident_union() {
        /// One spoofed attempt as the record holds it: the frame wore, and
        /// what the gate decided, tagged by the decision's own source — a
        /// box's row, the node row, the baseline set, the announced interim,
        /// or a drop's rule.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Attempt {
            src: [u8; 4],
            dst: [u8; 4],
            proto: u8,
            port: u16,
            phase: UnregisteredSourcePhase,
            verdict: Verdict,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Verdict {
            /// A resident box's row admitted the frame under its own rules.
            AdmittedByRow,
            /// The run path's allow-all interim node row admitted the frame:
            /// the shipped arm, unbounded until the baseline phase's flip
            /// (#1786).
            AdmittedByNodeRow,
            /// The node-plane baseline set admitted the frame, decided
            /// beside the boxes' rows.
            AdmittedByBaseline,
            /// The announced interim admitted the frame without consulting
            /// any rules: the shipped arm, until T66's flip (#1711).
            AdmittedByInterim,
            /// The gate dropped the frame, by the rule whose name the drop
            /// warning carries.
            Dropped(&'static str),
        }

        /// A resident box whose declaration admits the given subnets over
        /// TCP and nothing else.
        fn tcp_box(registry: &BoxRegistry, name: &str, lease: [u8; 4], subnets: Vec<String>) {
            registry.register(
                BoxRegistration::new(name, Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                    .with_egress_policy(EgressPolicy {
                        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                        allow_subnets: Some(subnets),
                        allow_dns_hosts: None,
                        deny_subnets: None,
                    }),
            );
        }

        fn proto_of(proto: u8) -> &'static str {
            if proto == 6 { "tcp" } else { "udp" }
        }

        /// One spoofed attempt: summarizes the frame exactly as the gate's
        /// relay would hand it over, decides it with [`gate_verdict`], and
        /// records the verdict under the decision's own name.
        fn decide(
            table: &BoxTable,
            baseline: &NodePlaneBaseline,
            phase: UnregisteredSourcePhase,
            src: [u8; 4],
            proto: u8,
            dst: [u8; 4],
            port: u16,
        ) -> Attempt {
            let frame = sessions::core::egress::summarize(&ipv4_frame(src, proto, dst, port));
            let verdict = match gate_verdict(&frame, table, baseline, phase) {
                Ok(GateAdmit::Baseline) => Verdict::AdmittedByBaseline,
                Ok(GateAdmit::Row) if src == baseline.node_addr() => Verdict::AdmittedByNodeRow,
                Ok(GateAdmit::Row) => Verdict::AdmittedByRow,
                Ok(GateAdmit::Unregistered { .. }) => Verdict::AdmittedByInterim,
                Err(drop) => Verdict::Dropped(drop.rule()),
            };
            Attempt {
                src,
                dst,
                proto,
                port,
                phase,
                verdict,
            }
        }

        // The union's membership: three resident boxes plus the node row, as
        // the run path registers the node and T66 will register the boxes.
        let registry = BoxRegistry::new(SUBNET);
        tcp_box(&registry, "web", LEASE, vec!["10.0.0.0/8".to_string()]);
        // db's subnet is TEST-NET-1: a second declared range the union must
        // hold beside web's, spelled outside RFC 1918 so the host's
        // infrastructure rule — which refuses private space a row's own
        // allowance does not cover — never decides a spoof aimed at it
        // before the row's rules do.
        tcp_box(
            &registry,
            "db",
            [100, 64, 0, 10],
            vec!["192.0.2.0/24".to_string()],
        );
        // The deny-all box: no declared subnets, so its row admits nothing
        // but the resolver carve-out — the box a spoof must not unseal.
        tcp_box(&registry, "locked", [100, 64, 0, 11], vec![]);
        registry.register_node_namespace(7654, 7656);
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let node = baseline.node_addr();
        let shipped = UNREGISTERED_SOURCE_PHASE;
        let resolver = SUBNET.dns_server().octets();
        let web_only = [10, 1, 2, 3];
        let db_only = [192, 0, 2, 5];
        let outside = [203, 0, 113, 7];
        let stray = [100, 64, 0, 99];
        // The out-of-plan source keeps a literal of its own: `outside` above
        // is a destination, this is a source, and the two share nothing but a
        // TEST-NET spelling — one is not where the other goes.
        let out_of_plan_src = [198, 51, 100, 7];
        // The node plane's own endpoint, read off the enumeration the way the
        // helper spells it (`a.b.c.d/n`), not hardcoded: the in-force bound's
        // admitted destination is the set's, not this test's.
        let baseline_endpoint = baseline
            .entries()
            .iter()
            .find(|entry| entry.category() == BaselineCategory::Registry)
            .expect("the enumeration carries the registry")
            .endpoints()
            .first()
            .expect("the registry carries an endpoint")
            .split_once('/')
            .expect("an endpoint is spelled `a.b.c.d/n`")
            .0
            .parse::<Ipv4Addr>()
            .expect("an endpoint's address parses")
            .octets();

        // Every spoofed attempt, decided and recorded: the tuples are
        // (phase, source, protocol, destination, port), and each is
        // summarized, decided by [`gate_verdict`], and recorded exactly as
        // the gate's relay would hand the frame over. The in-force world is
        // the one both flips create — the compiled baseline set binding
        // beside the per-box default — built here so the in-force arms have
        // their proof before the flips land.
        let baseline_in_force = baseline.clone().in_force();
        let shipped_attempts: Vec<Attempt> = [
            // web's address, spoofed: decided by web's own row — the lab
            // subnet over TCP, the resolver carve-out — and nowhere else, not
            // even where only another box declares. The protocol dimension
            // binds the same way, and the carve-out needs UDP: TCP to the
            // resolver is as undeclared as anywhere else.
            (shipped, LEASE, 6, web_only, 80),
            (shipped, LEASE, 17, web_only, 80),
            (shipped, LEASE, 6, db_only, 5432),
            (shipped, LEASE, 6, outside, 443),
            (shipped, LEASE, 17, resolver, 53),
            // db's address, spoofed: db's own subnet is admitted — the
            // flip-stable arm, the one a spoofer keeps after the flips — and
            // web's is not, though the union contains it.
            (shipped, [100, 64, 0, 10], 6, db_only, 5432),
            (shipped, [100, 64, 0, 10], 6, web_only, 80),
            (shipped, [100, 64, 0, 10], 6, outside, 443),
            (shipped, [100, 64, 0, 10], 17, resolver, 53),
            // locked's address, spoofed: the deny-all box's row admits
            // nothing but the carve-out, so a spoof of it unseals nothing.
            (shipped, [100, 64, 0, 11], 6, web_only, 80),
            (shipped, [100, 64, 0, 11], 17, resolver, 53),
            (shipped, [100, 64, 0, 11], 6, resolver, 53),
            // The node plane's own address, shipped: the allow-all interim
            // node row admits even the outside destination — the gap the
            // baseline phase's flip (#1786) closes, into the in-force arm
            // the in-force list pins. The node row stands in for the
            // `host_ip` cohort's identity today (NET-078: outside the box
            // host the cohort is one source), so a spoof of it exercises the
            // row a cohort-wide identity will be decided by; once the cohort
            // address exists (design §4.1) this table gains attempt rows
            // asserting the cohort's any-admits rule across the live
            // `host_ip` members, and that a revoked member's destinations no
            // longer admit.
            (shipped, node, 6, outside, 443),
            // An in-plan address no row holds: announced, admitted with no
            // rules at all — the gap T66's flip (#1711) closes, into the
            // unknown-source drop the in-force list pins. An address outside
            // the plan's lease block is refused under both phases: outside
            // the plan there is no lease to spoof.
            (shipped, stray, 6, web_only, 80),
            (shipped, out_of_plan_src, 6, web_only, 80),
        ]
        .into_iter()
        .map(|(phase, src, proto, dst, port)| {
            decide(&table, &baseline, phase, src, proto, dst, port)
        })
        .collect();
        let in_force_attempts: Vec<Attempt> = [
            // The node plane's own address, under the in-force baseline set:
            // bounded by the enumeration, decided beside the boxes' rows, and
            // so a spoof of the daemon's address buys the set, not a box's
            // row.
            (
                UnregisteredSourcePhase::InForce,
                node,
                6,
                baseline_endpoint,
                443,
            ),
            (UnregisteredSourcePhase::InForce, node, 6, web_only, 80),
            (UnregisteredSourcePhase::InForce, node, 6, outside, 443),
            // The unrowed in-plan source under the per-box default: dropped
            // as an unknown source, whatever the plan could have done with
            // its address.
            (UnregisteredSourcePhase::InForce, stray, 6, web_only, 80),
            (
                UnregisteredSourcePhase::InForce,
                out_of_plan_src,
                6,
                web_only,
                80,
            ),
        ]
        .into_iter()
        .map(|(phase, src, proto, dst, port)| {
            decide(&table, &baseline_in_force, phase, src, proto, dst, port)
        })
        .collect();
        let attempts: Vec<Attempt> = shipped_attempts
            .into_iter()
            .chain(in_force_attempts)
            .collect();

        // The record, one line per attempt, grouped by spoofed source, in
        // the gate's drop-line shape: what the frame wore, where it was
        // headed, and what the gate decided. `cargo nextest run --no-capture`
        // spells the whole bound out.
        let mut groups: Vec<([u8; 4], Vec<&Attempt>)> = Vec::new();
        for attempt in &attempts {
            match groups.iter_mut().find(|(src, _)| *src == attempt.src) {
                Some((_, group)) => group.push(attempt),
                None => groups.push((attempt.src, vec![attempt])),
            }
        }
        for (src, group) in &groups {
            println!("source={}", Ipv4Addr::from(*src));
            for attempt in group {
                match attempt.verdict {
                    Verdict::Dropped(rule) => println!(
                        "  destination={}:{}({}) phase={} action=drop rule_matched=\"{rule}\"",
                        Ipv4Addr::from(attempt.dst),
                        attempt.port,
                        proto_of(attempt.proto),
                        attempt.phase.as_str(),
                    ),
                    verdict => println!(
                        "  destination={}:{}({}) phase={} action=admit decision={verdict:?}",
                        Ipv4Addr::from(attempt.dst),
                        attempt.port,
                        proto_of(attempt.proto),
                        attempt.phase.as_str(),
                    ),
                }
            }
        }

        // The bound, read off the record: every admit a box's row gave a
        // spoofed frame lands inside the union — a resident box's declared
        // subnet over its declared protocol, or the resolver carve-out every
        // row and the baseline set share — and the baseline set's admit is
        // inside the enumeration's endpoints (or the same carve-out). The
        // two interim arms are the documented gaps, asserted as such below,
        // so they are not bound here but named.
        let in_union = |dst: [u8; 4], proto: u8, port: u16| {
            let web = Ipv4Cidr::parse("10.0.0.0/8").expect("web's subnet parses");
            let db = Ipv4Cidr::parse("192.0.2.0/24").expect("db's subnet parses");
            (proto == 6 && (web.contains(dst) || db.contains(dst)))
                || (proto == 17 && dst == resolver && port == 53)
        };
        let baseline_set: Vec<Ipv4Cidr> = baseline
            .entries()
            .iter()
            .flat_map(|entry| entry.endpoints().iter())
            .map(|endpoint| Ipv4Cidr::parse(endpoint).expect("a baseline endpoint parses"))
            .collect();
        for attempt in &attempts {
            match attempt.verdict {
                Verdict::AdmittedByRow => assert!(
                    in_union(attempt.dst, attempt.proto, attempt.port),
                    "a spoof wearing {} reached {}:{} outside the union",
                    Ipv4Addr::from(attempt.src),
                    Ipv4Addr::from(attempt.dst),
                    attempt.port,
                ),
                Verdict::AdmittedByBaseline => assert!(
                    baseline_set.iter().any(|cidr| cidr.contains(attempt.dst))
                        || (attempt.proto == 17 && attempt.dst == resolver && attempt.port == 53),
                    "a spoof wearing the node's address reached {}:{} outside the baseline set",
                    Ipv4Addr::from(attempt.dst),
                    attempt.port,
                ),
                // The shipped interim's admits are the gaps, each pinned to
                // its in-force replacement by the verdict lookups below.
                Verdict::AdmittedByNodeRow | Verdict::AdmittedByInterim | Verdict::Dropped(_) => {}
            }
        }

        // The universal the table makes cheap, beside the membership loop
        // above — NET-085 as a bound, not a list. Two halves:
        //
        // - no attempt decided against the in-force baseline set carries an
        //   interim arm's verdict: with the per-box default and the compiled
        //   baseline binding there is no allow-all node row and no rules-free
        //   admit to fall through to, whichever way a future edit reorders
        //   the decision;
        // - every admit any phase gave a frame is the row that holds the
        //   source's own doing: the row `table.by_source(src)` holds is the
        //   row whose rules admit the destination, never another box's row
        //   and never a union read out of the table. The per-pair pins below
        //   name the destinations; this binds the shape over the whole
        //   record, so a future attempt is covered without being pinned.
        for attempt in &attempts {
            if attempt.phase == UnregisteredSourcePhase::InForce {
                assert!(
                    !matches!(
                        attempt.verdict,
                        Verdict::AdmittedByNodeRow | Verdict::AdmittedByInterim
                    ),
                    "an in-force attempt of {} carries an interim arm's verdict \
                     ({:?}); the in-force decision has no interim arm",
                    Ipv4Addr::from(attempt.src),
                    attempt.verdict,
                );
            }
            if attempt.verdict == Verdict::AdmittedByRow {
                let record = table.by_source(attempt.src).unwrap_or_else(|| {
                    panic!(
                        "the admit of {}:{} was not decided by a row: no row \
                         holds the source {}",
                        Ipv4Addr::from(attempt.dst),
                        attempt.port,
                        Ipv4Addr::from(attempt.src),
                    )
                });
                let summary = sessions::core::egress::summarize(&ipv4_frame(
                    attempt.src,
                    attempt.proto,
                    attempt.dst,
                    attempt.port,
                ));
                assert!(
                    matches!(
                        sessions::core::egress::verdict(&summary, record.egress()),
                        FrameVerdict::Admit
                    ),
                    "the admit of {}:{} from {} is not the source's own row's \
                     decision: {}'s row does not admit it",
                    Ipv4Addr::from(attempt.dst),
                    attempt.port,
                    Ipv4Addr::from(attempt.src),
                    record.name(),
                );
            }
        }

        // The strong half, pinned per attempt: the decision is the spoofed
        // box's own rules, never the union. A row-held spoof reaches the
        // row's declared subnet and the resolver carve-out and nothing else —
        // dropped where only another box declares, dropped on the protocol
        // dimension, and the deny-all row unsealing nothing. The lookup keys
        // the whole record — phase, source, protocol, destination, and port —
        // so a later attempt sharing any prefix cannot answer for another's
        // verdict.
        let verdict_of = |phase, src, proto, dst, port| {
            attempts
                .iter()
                .find(|a| {
                    a.phase == phase
                        && a.src == src
                        && a.proto == proto
                        && a.dst == dst
                        && a.port == port
                })
                .expect("every pinned attempt is in the record")
                .verdict
        };
        assert_eq!(
            verdict_of(shipped, LEASE, 6, web_only, 80),
            Verdict::AdmittedByRow
        );
        assert_eq!(
            verdict_of(shipped, LEASE, 17, web_only, 80),
            Verdict::Dropped("egress-undeclared-protocol"),
        );
        assert_eq!(
            verdict_of(shipped, LEASE, 6, db_only, 5432),
            Verdict::Dropped("egress-undeclared-subnet"),
        );
        assert_eq!(
            verdict_of(shipped, LEASE, 6, outside, 443),
            Verdict::Dropped("egress-undeclared-subnet"),
        );
        assert_eq!(
            verdict_of(shipped, LEASE, 17, resolver, 53),
            Verdict::AdmittedByRow
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 10], 6, db_only, 5432),
            Verdict::AdmittedByRow,
        );
        // web's subnet is private space: a spoof wearing another row's
        // address and aimed there is refused by the host's infrastructure
        // rule, decided for every row before its own rules — the row's
        // allowance does not cover the range, so the drop names that rule
        // rather than the undeclared-subnet one. Dropped either way; the
        // bound is what the pin keeps.
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 10], 6, web_only, 80),
            Verdict::Dropped("egress-infrastructure-destination"),
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 10], 6, outside, 443),
            Verdict::Dropped("egress-undeclared-subnet"),
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 10], 17, resolver, 53),
            Verdict::AdmittedByRow,
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 11], 6, web_only, 80),
            Verdict::Dropped("egress-infrastructure-destination"),
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 11], 17, resolver, 53),
            Verdict::AdmittedByRow,
        );
        assert_eq!(
            verdict_of(shipped, [100, 64, 0, 11], 6, resolver, 53),
            Verdict::Dropped("egress-undeclared-subnet"),
        );

        // The node plane's own address, under the in-force set: the
        // enumeration's endpoint admitted, everything else dropped — the
        // bound a spoof of the daemon's address buys, beside the boxes' rows.
        assert_eq!(
            verdict_of(
                UnregisteredSourcePhase::InForce,
                node,
                6,
                baseline_endpoint,
                443
            ),
            Verdict::AdmittedByBaseline,
        );
        assert_eq!(
            verdict_of(UnregisteredSourcePhase::InForce, node, 6, web_only, 80),
            Verdict::Dropped("egress-undeclared-subnet"),
        );
        assert_eq!(
            verdict_of(UnregisteredSourcePhase::InForce, node, 6, outside, 443),
            Verdict::Dropped("egress-undeclared-subnet"),
        );

        // The shipped interim's arms, with the in-force arms they become:
        // the allow-all node row admits the outside destination today, and
        // the baseline phase's flip (#1786) turns it into the drop above;
        // the unrowed in-plan source is admitted with no rules today, and
        // T66's flip (#1711) turns it into the unknown-source drop beside
        // it. The out-of-plan source is refused under both phases, so the
        // interim can never borrow the plan's infrastructure as a source.
        assert_eq!(
            verdict_of(shipped, node, 6, outside, 443),
            Verdict::AdmittedByNodeRow,
        );
        assert_eq!(
            verdict_of(shipped, stray, 6, web_only, 80),
            Verdict::AdmittedByInterim,
        );
        assert_eq!(
            verdict_of(UnregisteredSourcePhase::InForce, stray, 6, web_only, 80),
            Verdict::Dropped("egress-unknown-source"),
        );
        assert_eq!(
            verdict_of(shipped, out_of_plan_src, 6, web_only, 80),
            Verdict::Dropped("egress-unknown-source"),
        );
        assert_eq!(
            verdict_of(
                UnregisteredSourcePhase::InForce,
                out_of_plan_src,
                6,
                web_only,
                80
            ),
            Verdict::Dropped("egress-unknown-source"),
        );

        // ARP is a declared path for every box, decided per frame with no
        // destination to bound: a spoofed announcement wearing web's address
        // is admitted by web's row the same as any resolution web's own
        // traffic would carry. It buys no reach — the flow frames behind it
        // are what the rows bound, each on its own.
        let spoofed_arp = sessions::core::egress::summarize(&arp_frame(LEASE));
        assert!(matches!(
            gate_verdict(&spoofed_arp, &table, &baseline, shipped),
            Ok(GateAdmit::Row)
        ));
    }

    /// The shipped arm of the node-plane decision: the phase this build
    /// ships is announced, and a frame wearing the in-VM daemon's own
    /// address is decided by the run path's allow-all interim node row —
    /// the row [`BoxRegistry::register_node_namespace`] publishes, the way
    /// the run path registers it at boot — yielding [`GateAdmit::Row`] from
    /// that row, never [`GateAdmit::Baseline`]. The baseline set's arm is
    /// the store-surface configuration's to switch on (#1786), and the
    /// in-force arm's proof is
    /// [`unenrolled_baseline_set_from_helper_enumeration`]'s.
    #[test]
    fn node_plane_source_decided_by_the_node_row_while_announced() {
        let registry = BoxRegistry::new(SUBNET);
        // The run path's own registration: the allow-all interim node row at
        // the daemon's address, registered at VM boot (cmd/run.rs) with the
        // two ports the boot line hands the guest daemon.
        registry.register_node_namespace(7654, 7656);
        let table = registry.table();
        // Built without [`NodePlaneBaseline::in_force`], so this is the
        // phase the build ships.
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        assert_eq!(
            baseline.phase(),
            NodeBaselinePhase::Announced,
            "the shipped posture is announced, the arm this test pins"
        );

        // A node-plane frame to a destination no category of the enumeration
        // names — the public store the shipped cache URL resolves to. The
        // interim node row decides it, and the row allows all, so the frame
        // is admitted by [`GateAdmit::Row`]: the enumeration's compiled set,
        // which admits no such destination, decided nothing here.
        let summarize = sessions::core::egress::summarize;
        let node_frame = summarize(&ipv4_frame(
            SUBNET.daemon_ip().octets(),
            6,
            [8, 8, 8, 8],
            443,
        ));
        assert_eq!(
            gate_verdict(&node_frame, &table, &baseline, UNREGISTERED_SOURCE_PHASE),
            Ok(GateAdmit::Row),
            "announced, the interim node row decides the node plane's frames — \
             never the baseline set"
        );
    }

    /// NET-130, un-enrolled, at the gate: the node-plane baseline set comes
    /// from the helper's enumeration, and the gate decides the daemon's own
    /// frames by it **beside** the boxes' rows — a deny-all box's row does not
    /// clip the daemon's own registry and cache fetches (NET-080), decided
    /// before the table is consulted — and a destination the enumeration does
    /// not name is dropped: the gap the announced phase covers until the
    /// node plane's store surfaces are configured (`NodeBaselinePhase`).
    #[tokio::test]
    async fn unenrolled_baseline_set_from_helper_enumeration() {
        let registry = BoxRegistry::new(SUBNET);
        // A deny-all box: no declared subnets, so nothing but the resolver
        // carve-out passes its row — the box the node plane's own fetches
        // must not be bound by.
        registry.register(
            BoxRegistration::new("locked", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let baseline = NodePlaneBaseline::built_in(SUBNET).in_force();
        let node_addr = baseline.node_addr();
        let registry_endpoint = baseline
            .entries()
            .iter()
            .find(|entry| entry.category() == BaselineCategory::Registry)
            .expect("the enumeration carries the registry")
            .endpoints()
            .first()
            .expect("the registry carries an endpoint")
            .split_once('/')
            .expect("an endpoint is spelled `a.b.c.d/n`")
            .0
            .parse::<Ipv4Addr>()
            .expect("an endpoint's address parses")
            .octets();
        let mut h =
            gate_over_with_node_baseline(registry, UNREGISTERED_SOURCE_PHASE, baseline).await;

        // VM start says what the node plane may reach, one term per category:
        // the line a diagnostic bundle's daemon log tail carries.
        wait_for_log(&h.log, "node-plane baseline set").await;
        let logged = h.log.contents();
        for category in ["registry=", "cache="] {
            assert!(
                logged.contains(category),
                "the start-up line names the baseline entries by category, got: {logged}"
            );
        }
        assert!(
            logged.contains("node_addr=100.64.255.253"),
            "the start-up line names the in-VM daemon's own address, got: {logged}"
        );

        // The box's own frame, to somewhere its deny-all declaration does not
        // name: dropped, where it stands. The marker behind it is the one
        // frame a deny-all row admits — the resolver carve-out — so the
        // arrival of the marker is the proof the drop happened.
        let undeclared = ipv4_frame(LEASE, 6, [1, 2, 3, 4], 80);
        let marker = ipv4_frame(LEASE, 17, SUBNET.dns_server().octets(), 53);
        send_frame(&mut h.guest, &undeclared).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the deny-all box's undeclared frame never reached the switch; the marker did"
        );

        // The node plane's own frame, to the enumeration's registry endpoint:
        // decided by the baseline set beside the box's row — admitted, and
        // the switch sees it exactly as it was sent.
        let node_frame = ipv4_frame(node_addr, 6, registry_endpoint, 443);
        send_frame(&mut h.guest, &node_frame).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, node_frame,
            "the daemon's own fetch reaches the switch as it was sent"
        );

        // To an address no category names — the public store the guest
        // daemon's shipped cache URL resolves to, whose serving addresses no
        // subnet list this tree can name — the set says no.
        let out_of_set = ipv4_frame(node_addr, 6, [8, 8, 8, 8], 443);
        let node_marker = ipv4_frame(node_addr, 6, registry_endpoint, 444);
        send_frame(&mut h.guest, &out_of_set).await;
        send_frame(&mut h.guest, &node_marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, node_marker,
            "the daemon's out-of-set frame never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;
    }

    /// One drop line per source address per rule per interval: the first
    /// emission fires, a repeat within the interval does not, a different
    /// source or a different rule keeps its own line, and the interval
    /// elapsing fires again. A frame with no readable source is a key of its
    /// own, so the family drops share no window with a box's.
    #[test]
    fn drop_limiter_rate_limits_per_source_and_rule() {
        let limiter = DropLimiter::new();
        let t0 = Instant::now();
        let src = [100, 64, 0, 9];

        assert_eq!(
            limiter.should_warn_at(Some(src), "egress-undeclared-subnet", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(
                Some(src),
                "egress-undeclared-subnet",
                t0 + Duration::from_millis(10)
            ),
            WarnDecision::Silent
        );
        // A different source under the same rule keeps its own line…
        assert_eq!(
            limiter.should_warn_at(Some([100, 64, 0, 10]), "egress-undeclared-subnet", t0),
            WarnDecision::Named
        );
        // …and the same source under a different rule keeps its own.
        assert_eq!(
            limiter.should_warn_at(Some(src), "egress-foreign-source", t0),
            WarnDecision::Named
        );
        // A sourceless frame is a key of its own, and so are two family rules
        // between themselves.
        assert_eq!(
            limiter.should_warn_at(None, "egress-ipv6", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(None, "egress-undeclared-ethertype", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(None, "egress-ipv6", t0 + Duration::from_millis(10)),
            WarnDecision::Silent
        );
        // Once the interval has elapsed, the line fires again.
        assert_eq!(
            limiter.should_warn_at(
                Some(src),
                "egress-undeclared-subnet",
                t0 + DROP_WARN_MIN_INTERVAL
            ),
            WarnDecision::Named
        );
    }

    /// The limiter's window table is bounded, because the source address it
    /// keys by is the dropped frame's own bytes and a hostile guest chooses
    /// those: flooding distinct spoofed addresses must not grow host memory
    /// one entry per frame. Past the cap a new pair shares one line per rule,
    /// a pair the table already holds keeps its own window, and stale
    /// windows make room again — so the fold is a flood's shape, not a
    /// permanent state.
    #[test]
    fn drop_limiter_bounds_its_source_table() {
        let limiter = DropLimiter::new();
        let t0 = Instant::now();
        let rule = "egress-unknown-source";
        // A source address per index: distinct bytes, so distinct keys.
        let source = |i: usize| u32::try_from(i).expect("an index fits a u32").to_be_bytes();

        // Fill the table to its cap, one window per distinct pair.
        for i in 0..DROP_WARN_MAX_TRACKED_PAIRS {
            assert_eq!(
                limiter.should_warn_at(Some(source(i)), rule, t0),
                WarnDecision::Named,
                "pair {i} takes a window of its own while the table has room"
            );
        }
        // At the cap, a pair the table holds no window for no longer gets
        // one: it falls to the rule's shared line…
        assert_eq!(
            limiter.should_warn_at(Some(source(DROP_WARN_MAX_TRACKED_PAIRS)), rule, t0),
            WarnDecision::Overflow,
            "past the cap a new pair folds into the rule's shared line"
        );
        // …and so does every distinct source after it, at the shared line's
        // own cadence — no window per frame.
        assert_eq!(
            limiter.should_warn_at(Some(source(DROP_WARN_MAX_TRACKED_PAIRS + 1)), rule, t0),
            WarnDecision::Silent,
            "the rule's shared line is rate-limited like any other"
        );
        let windows = || {
            limiter
                .last
                .lock()
                .expect("the limiter's lock is held only across this read")
                .len()
        };
        assert!(
            windows() <= DROP_WARN_MAX_TRACKED_PAIRS + 1,
            "a flood of distinct sources added no window per frame: {} windows",
            windows()
        );
        // A pair the table already holds keeps its own window, full or not.
        assert_eq!(
            limiter.should_warn_at(Some(source(0)), rule, t0 + Duration::from_millis(10)),
            WarnDecision::Silent,
            "a held pair is still rate-limited by its own window"
        );
        // Once every window has gone stale, the flood is over by shape: the
        // prune frees the table and an honest source is named per line again.
        assert_eq!(
            limiter.should_warn_at(
                Some(source(DROP_WARN_MAX_TRACKED_PAIRS + 2)),
                rule,
                t0 + DROP_WARN_MIN_INTERVAL
            ),
            WarnDecision::Named,
            "stale windows make room; a new source gets its own line again"
        );
        assert_eq!(windows(), 1, "the stale windows were pruned, not kept");
    }

    /// A rendered name is cut to the naming bound on a char boundary: the
    /// dictionary's name is a guest's bytes, and a cut that lands inside a
    /// multi-byte character would panic the warn path on exactly the name a
    /// hostile guest would choose. Every run length is tried, so the bound
    /// falls on every byte of the trailing character at least once.
    #[test]
    fn render_record_cuts_names_on_a_char_boundary() {
        let dictionary = |name: String| vec![name];
        // The two shapes a reviewer would reach for first: 63 ASCII bytes
        // then a 3-byte character, and exactly 64 bytes of 2-byte characters.
        let mut names = vec![format!("{}日", "x".repeat(63)), "é".repeat(32)];
        // And every ASCII run length up to the bound, so some run puts the
        // cut inside the 3-byte character whatever the render's prefix adds.
        names.extend((0..=MAX_NAMED_TARGET).map(|run| format!("{}日", "x".repeat(run))));
        names.extend((1..=MAX_NAMED_TARGET).map(|run| "é".repeat(run)));
        for name in names {
            let bytes = name.len();
            let named = render_record(Record::Name(0), &dictionary(name));
            assert!(
                named.len() <= MAX_NAMED_TARGET,
                "a {bytes}-byte name renders to at most the bound, got {} bytes",
                named.len()
            );
            assert!(
                named.starts_with("name \""),
                "the render keeps the name's prefix: {named:?}"
            );
            assert!(
                std::str::from_utf8(named.as_bytes()).is_ok(),
                "a cut render is valid UTF-8: {named:?}"
            );
        }
    }

    /// NET-081's publish half, refused and said so: an expose at a published
    /// namespace's address for a port its declaration does not name is
    /// refused before a byte of it is written on — gvproxy never sees the
    /// request, no answer is owed, the guest's connection ends — and the
    /// refusal is a rate-limited warn line naming the address, the port, and
    /// the reason: the three things a diagnostic bundle's log tail is read
    /// for, and the shape the task's diagnostics ask the gate to show when a
    /// publish goes wrong.
    #[tokio::test]
    async fn switch_request_refused_and_logged() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // An honest-shaped expose — the loopback listener the daemon's own
        // client binds on, the address and port spelling its client builds —
        // publishing a 9999 listener at the row's own address: the publish's
        // record is the listener it binds, and 9999 is a port the row does
        // not declare. The mapping's inside end (8080) decides nothing here:
        // the inside is the target's own, decided by its in-guest ingress
        // rules, so a refusal turns on the listener alone. The publish stops
        // at what the host published.
        let body = br#"{"local":"127.0.0.1:9999","remote":"100.64.0.9:8080","protocol":"tcp"}"#;
        let mut request =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the expose");

        // Refused, and named: the rule is its own class, the address is the
        // one the publish was at, the port is the record it was refused for,
        // and the reason says the namespace does not admit it.
        wait_for_log(&h.log, UNDECLARED_PUBLISH_RECORD_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-publish-record\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("source=100.64.0.9"),
            "the refusal names the address it was at, got: {logged}"
        );
        assert!(
            logged.contains("port_or_name=port 9999"),
            "the refusal names the port it was refused for, got: {logged}"
        );
        assert!(
            logged.contains("does not admit"),
            "the refusal names the reason, got: {logged}"
        );
        assert!(
            !logged.contains(UNREGISTERED_PUBLISH_RULE),
            "a refusal is not an interim admission, got: {logged}"
        );

        // Nothing of it reached the switch — the request was decided before
        // any of it was written on, so gvproxy never held it — and its end
        // comes down rather than hanging.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a refused publish reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // And the guest's side comes down with it: a refused caller's
        // connection ends, it is not answered.
        expect_teardown(&mut h.guest).await;
    }

    /// The publish decision's record is the host-side listener, so a mapping
    /// whose two ends differ publishes when the row declares the listener —
    /// the shape every own-address box's ingress mapping has (an external
    /// port on the host, an internal one in the box), and the one the
    /// both-ends reading refused: the row carries what the registration wire
    /// carried, the external ports, and the inside end is the target's own,
    /// decided by its in-guest ingress rules and never by a row here. The
    /// exposed mapping reaching the switch whole is the proof the publish was
    /// applied, not merely answered.
    #[tokio::test]
    async fn a_mapping_whose_ends_differ_publishes_when_the_listener_is_declared() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // 8080 on the host, dialing 18080 inside the box: the listener end is
        // the row's, the inside one no row carries.
        let body = br#"{"local":"127.0.0.1:8080","remote":"100.64.0.9:18080","protocol":"tcp"}"#;
        let mut request =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the expose");
        let mut spoken = vec![0u8; request.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken, request,
            "the declared listener's publish reached the switch whole"
        );
    }

    /// An own-address box's ingress exposes are named at the box's **own**
    /// leased loopback address (NET-010), not `127.0.0.1`: the daemon's
    /// client builds `local` from the grant the answerer's record holds for
    /// it, the address the box's name answers at (NET-011), and the host
    /// binds the forwarder there. The gate summarizes that spelling like
    /// the interim's own — the publish decided by its switch address and
    /// its port record — so the box's declared mapping publishes, and its
    /// teardown, which carries the same `local`, is *decided*: keyed at
    /// the address its publication was applied at and refused as the
    /// retraction it is, never refused as a body the gate cannot parse.
    #[tokio::test]
    async fn an_expose_on_the_boxs_leased_loopback_publishes_when_the_listener_is_declared() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // The box's own granted address out of the reserved local range, at
        // a port the row declares, with the inside end different as a
        // mapping's is: the exact shape `expose_request` builds for an
        // own-address box's declaration
        // (`crates/minimald/src/net/policy.rs`).
        let body = br#"{"local":"127.0.64.9:8080","remote":"100.64.0.9:18080","protocol":"tcp"}"#;
        let mut expose =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        expose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        expose.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&expose)
            .await
            .expect("writing the expose");
        let mut spoken = vec![0u8; expose.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken, expose,
            "the publish on the box's leased loopback reached the switch whole"
        );

        // Answered, as the daemon's client reads its publishes back, so the
        // gate's attribution is in place before the teardown is spoken.
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(answer)
            .await
            .expect("writing gvproxy's answer");
        let mut seen = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen, answer,
            "the publish's answer reaches the guest verbatim"
        );

        // The teardown carries the same `local` and is decided, not
        // discarded: the refusal names the row's own address — the one the
        // publish was applied at — and the listener, and its own class, the
        // retraction's, not the malformed body's.
        let body = br#"{"local":"127.0.64.9:8080","protocol":"tcp"}"#;
        let mut unexpose =
            b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        unexpose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        unexpose.extend_from_slice(body);
        let (mut guest, mut switch) = connect_control(&h).await;
        guest
            .write_all(&unexpose)
            .await
            .expect("writing the retraction");
        wait_for_log(&h.log, UNDECLARED_RETRACT_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-retract\"")
                && logged.contains("source=100.64.0.9")
                && logged.contains("port_or_name=port 8080"),
            "the teardown on the leased loopback is decided at its address, got: {logged}"
        );
        assert!(
            !logged.contains(MALFORMED_PUBLISH_RULE),
            "neither the publish nor its teardown was refused as malformed, got: {logged}"
        );
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a refused retraction reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        expect_teardown(&mut guest).await;
    }

    /// The two accepted spellings are the daemon's own, and a `local`
    /// outside both is refused as a body the gate does not summarize —
    /// before any decision the row could have made about its port, which is
    /// why the refusal comes for a port the row *does* declare: the
    /// host-side forwarder binds where the daemon's client says, and only
    /// its two spellings say anywhere.
    #[tokio::test]
    async fn a_local_outside_the_daemons_two_loopback_spellings_is_refused_as_malformed() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // `127.0.0.2`: loopback, but neither the interim's `127.0.0.1` nor
        // an address of the reserved local range — a spelling no client of
        // the daemon builds, carrying a declared port at the row's own
        // address, so the refusal that comes is the parser's alone.
        let body = br#"{"local":"127.0.0.2:8080","remote":"100.64.0.9:8080","protocol":"tcp"}"#;
        let mut request =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(&request)
            .await
            .expect("writing the expose");

        // Refused as malformed, and named: the rule is the malformed
        // publish's own class, and the listener is the spelling it refused.
        wait_for_log(&h.log, MALFORMED_PUBLISH_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-malformed-publish\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("port_or_name=127.0.0.2:8080"),
            "the refusal names the local it refused, got: {logged}"
        );
        assert!(
            !logged.contains(UNDECLARED_PUBLISH_RECORD_RULE),
            "a malformed body never reaches the decision, got: {logged}"
        );

        // Nothing of it reached the switch, and the caller's end comes down.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a malformed publish reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        expect_teardown(&mut h.guest).await;
    }

    /// A retraction is decided by the row at the address the gate attributes
    /// it to: the ledger keeps every applied publish's listener → address
    /// pair, so the daemon's teardown — whose body names only the listener,
    /// the wire carrying no switch address — is keyed at the publication's
    /// own address and decided by the row that holds it, and a retraction
    /// for a listener no applied publish names is keyed at the unspecified
    /// address no row holds. Both are refused today — the row's runtime
    /// has published nothing a guest may withdraw, and the unspecified
    /// address is nobody's — and the attribution is what tells them apart:
    /// each refusal line names the source the retraction was keyed at, the
    /// row's own address for the one and `0.0.0.0` for the other. Before
    /// the keying the same stray request was applied table-wide — any row
    /// holding the port applied it — so a fabricated retraction of a port
    /// some row declared travelled to the switch.
    #[tokio::test]
    async fn a_retraction_is_keyed_at_the_address_its_publication_was_applied_at() {
        for phase in [
            UnregisteredSourcePhase::Announced,
            UnregisteredSourcePhase::InForce,
        ] {
            let registry = BoxRegistry::new(SUBNET);
            tcp_lan_box(&registry, LEASE);
            let mut h = gate_connected_with_phase(registry, phase).await;

            // An honest expose at the row's own address — the shape the
            // daemon's client sends, its listener a port the row declares —
            // admitted by the row under either phase. The inside end here
            // happens to be the listener's port too, but it decides nothing:
            // the record is the listener alone.
            let body = br#"{"local":"127.0.0.1:8080","remote":"100.64.0.9:8080","protocol":"tcp"}"#;
            let mut expose =
                b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
            expose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            expose.extend_from_slice(body);
            h.guest
                .write_all(&expose)
                .await
                .expect("writing the expose");
            let mut spoken = vec![0u8; expose.len()];
            read_within(&mut h.switch, &mut spoken).await;
            assert_eq!(spoken, expose, "the admitted expose reached the switch");

            // The publish is answered, and the answer read back off the
            // guest's end: gvproxy's answer passing the gate proves the relay
            // got past its ledger note, so the attribution is in place before
            // the teardown is spoken.
            let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            h.switch
                .write_all(answer)
                .await
                .expect("writing gvproxy's answer");
            let mut seen = vec![0u8; answer.len()];
            read_within(&mut h.guest, &mut seen).await;
            assert_eq!(
                seen, answer,
                "the publish's answer reaches the guest verbatim"
            );

            // The teardown, on its own connection as the daemon's client
            // speaks it — one request per connection, the body naming only
            // the listener. The gate keys it at the address the publish was
            // applied at, the row's own: the refusal names that source, not
            // the unspecified one, which is the attribution made visible.
            let body = br#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#;
            let mut unexpose =
                b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
            unexpose
                .extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            unexpose.extend_from_slice(body);
            let (mut guest, mut switch) = connect_control(&h).await;
            guest
                .write_all(&unexpose)
                .await
                .expect("writing the retraction");
            wait_for_log(&h.log, UNDECLARED_RETRACT_RULE).await;
            let logged = h.log.contents();
            assert!(
                logged.contains("rule_matched=\"egress-undeclared-retract\"")
                    && logged.contains("source=100.64.0.9")
                    && logged.contains("port_or_name=port 8080"),
                "a retraction is keyed at the address its publication was applied at, got: \
                 {logged}"
            );
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a refused retraction reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("the gate left the switch side hanging"),
            }
            expect_teardown(&mut guest).await;

            // A retraction for a listener no applied publish names: keyed at
            // the unspecified address, refused before a byte of it is written
            // on — gvproxy never sees it — and the refusal is the retraction's
            // own rule, naming the unspecified source, the port, and the
            // reason.
            let body = br#"{"local":"127.0.0.1:9999","protocol":"tcp"}"#;
            let mut stray =
                b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
            stray.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            stray.extend_from_slice(body);
            let (mut guest, mut switch) = connect_control(&h).await;
            guest
                .write_all(&stray)
                .await
                .expect("writing the stray retraction");
            wait_for_log(&h.log, "source=0.0.0.0").await;
            let logged = h.log.contents();
            assert!(
                logged.contains("rule_matched=\"egress-undeclared-retract\""),
                "the refusal names its own class, got: {logged}"
            );
            assert!(
                logged.contains("source=0.0.0.0"),
                "a retraction no publish attributes is keyed at the unspecified \
                 address, got: {logged}"
            );
            assert!(
                logged.contains("port_or_name=port 9999"),
                "the refusal names the listener it was refused for, got: {logged}"
            );
            assert!(
                logged.contains("nothing published at its address admits what it retracts"),
                "the refusal says no publication is there to retract, got: {logged}"
            );
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a refused retraction reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("the gate left the switch side hanging"),
            }
            expect_teardown(&mut guest).await;
        }
    }

    /// A forwarder listener is its loopback address and port, not the port:
    /// two boxes publishing one port at their own reserved-range leases are
    /// two listeners, and the ledger attributes each one's retraction to the
    /// address its own publish was applied at. Keyed by port alone, the
    /// second publish was dropped as a duplicate and the second box's
    /// retraction was attributed to the first box.
    #[test]
    fn two_boxes_publishing_one_port_keep_their_own_attribution() {
        let (network, _) = switch::RESERVED_LOCAL_RANGE;
        let base = u32::from(network);
        let first = Ipv4Addr::from(base + 9);
        let second = Ipv4Addr::from(base + 10);
        let expose = |host: Ipv4Addr| {
            format!(r#"{{"local":"{host}:8080","remote":"100.64.0.9:8080","protocol":"tcp"}}"#)
        };
        let unexpose = |host: Ipv4Addr| format!(r#"{{"local":"{host}:8080","protocol":"tcp"}}"#);

        let a = super::forward_listener(super::ControlVerb::Expose, expose(first).as_bytes())
            .expect("the first box's listener parses");
        let b = super::forward_listener(super::ControlVerb::Expose, expose(second).as_bytes())
            .expect("the second box's listener parses");
        assert_ne!(a, b, "one port at two leases is two listeners");
        assert_eq!(
            super::forward_listener(super::ControlVerb::Unexpose, unexpose(second).as_bytes()),
            Some(b),
            "a teardown names the listener its publish named"
        );

        let ledger = super::PublishedForwards::new();
        ledger.note_published(a, [100, 64, 0, 9]);
        ledger.note_published(b, [100, 64, 0, 10]);
        assert_eq!(ledger.address_of(a), Some([100, 64, 0, 9]));
        assert_eq!(
            ledger.address_of(b),
            Some([100, 64, 0, 10]),
            "the second box's publish is its own, not a duplicate of the first"
        );

        ledger.note_retracted(b);
        assert_eq!(
            ledger.address_of(b),
            None,
            "the second box's publish is gone"
        );
        assert_eq!(
            ledger.address_of(a),
            Some([100, 64, 0, 9]),
            "retracting one box's listener leaves the other box's attribution"
        );
    }

    /// A declared port's forward is the host's for the session's lifetime:
    /// bound at publish, unbound only by host-side ingress revocation
    /// (design §7.1, NET-121), never by a guest request. A box whose row
    /// admits `8080` publishes its forward and then asks, on the shuttle,
    /// to unexpose it — the one shape under which the gate attributes the
    /// retraction to the row's own address — and the gate refuses it before
    /// a byte reaches the switch, says so on the retraction's own rule
    /// naming the box's address and the port, and the row still admits
    /// `8080`: the table is untouched, and the same forward publishes again.
    /// The row's runtime-published set — what a retraction at its address is
    /// applied for — is empty until listen-publishing lands, and a declared
    /// port is never in it. Both phases refuse: the row holds the address,
    /// so no interim is consulted.
    #[tokio::test]
    async fn retract_of_declared_port_refused() {
        for phase in [
            UnregisteredSourcePhase::Announced,
            UnregisteredSourcePhase::InForce,
        ] {
            let registry = BoxRegistry::new(SUBNET);
            tcp_lan_box(&registry, LEASE);
            let mut h = gate_connected_with_phase(registry, phase).await;

            // The declared forward's publish, applied by the row, and its
            // answer read back so the ledger's attribution is in place.
            let body = br#"{"local":"127.0.0.1:8080","remote":"100.64.0.9:8080","protocol":"tcp"}"#;
            let mut expose =
                b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
            expose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            expose.extend_from_slice(body);
            h.guest
                .write_all(&expose)
                .await
                .expect("writing the expose");
            let mut spoken = vec![0u8; expose.len()];
            read_within(&mut h.switch, &mut spoken).await;
            assert_eq!(
                spoken, expose,
                "the declared forward's publish reached the switch"
            );
            let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            h.switch
                .write_all(answer)
                .await
                .expect("writing gvproxy's answer");
            let mut seen = vec![0u8; answer.len()];
            read_within(&mut h.guest, &mut seen).await;
            assert_eq!(seen, answer, "the publish's answer reaches the guest");

            // The guest's withdrawal of the declared forward: keyed at the
            // row's own address, where the row declares the port and its
            // runtime published nothing — refused, and never written on.
            let body = br#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#;
            let mut unexpose =
                b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
            unexpose
                .extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            unexpose.extend_from_slice(body);
            let (mut guest, mut switch) = connect_control(&h).await;
            guest
                .write_all(&unexpose)
                .await
                .expect("writing the retraction");
            wait_for_log(&h.log, UNDECLARED_RETRACT_RULE).await;
            let logged = h.log.contents();
            assert!(
                logged.contains("rule_matched=\"egress-undeclared-retract\""),
                "the refusal is the retraction's own rule, got: {logged}"
            );
            assert!(
                logged.contains("source=100.64.0.9"),
                "the refusal names the box whose declared forward was asked for, got: {logged}"
            );
            assert!(
                logged.contains("port_or_name=port 8080"),
                "the refusal names the declared port, got: {logged}"
            );
            assert!(
                logged.contains("nothing published at its address admits what it retracts"),
                "the refusal says the row's runtime published nothing to withdraw, got: \
                 {logged}"
            );
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => {
                    panic!("{n} byte(s) of a declared port's retraction reached the switch")
                }
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("the gate left the switch side hanging"),
            }
            expect_teardown(&mut guest).await;

            // The row keeps the port: the table still admits 8080 at the
            // box's address, and the same declared forward publishes again,
            // applied by the row exactly as before.
            let row = h
                .table
                .by_source(LEASE)
                .expect("the box's row is still published");
            assert_eq!(
                row.admitted_ports(),
                [8080],
                "a refused retraction leaves the row's declared port in place"
            );
            let (mut guest, mut switch) = connect_control(&h).await;
            guest
                .write_all(&expose)
                .await
                .expect("writing the second expose");
            let mut spoken = vec![0u8; expose.len()];
            read_within(&mut switch, &mut spoken).await;
            assert_eq!(
                spoken, expose,
                "the declared forward still publishes after its refused withdrawal"
            );
        }
    }

    /// The interim's own teardowns keep working: a publish the interim
    /// applied — at an in-plan lease no published row holds — leaves its
    /// listener in the ledger, and the retraction of it is keyed at that
    /// lease, where no row holds it and the announced interim applies it.
    /// The teardown the flip refuses is the same one whose publish the flip
    /// refuses: once the default binds, nothing is attributed, so nothing is
    /// left to retract.
    #[tokio::test]
    async fn an_interim_publications_teardown_is_keyed_at_its_own_address() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_connected_with_phase(registry, UnregisteredSourcePhase::Announced).await;

        // The interim's publish: the daemon's expose shape, at an in-plan
        // lease the plan could hand out and no row holds. Applied — and said
        // so, marked as the interim's own line, naming the address.
        let body = br#"{"local":"127.0.0.1:8080","remote":"100.64.0.10:8080","protocol":"tcp"}"#;
        let mut expose =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        expose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        expose.extend_from_slice(body);
        h.guest
            .write_all(&expose)
            .await
            .expect("writing the expose");
        let mut spoken = vec![0u8; expose.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(spoken, expose, "the interim's publish reached the switch");
        wait_for_log(&h.log, UNREGISTERED_PUBLISH_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("interim=true"),
            "an applied interim says so on its own line, got: {logged}"
        );
        assert!(
            logged.contains("source=100.64.0.10"),
            "the interim's line names the address the publish went out at, got: {logged}"
        );

        // And the teardown of it works the same way: keyed at the lease the
        // publish went out at, where no row holds it and the announced
        // interim applies it — the publications whose rows are still to come
        // are the ones whose teardowns must work.
        let body = br#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#;
        let mut unexpose =
            b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        unexpose.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        unexpose.extend_from_slice(body);
        let (mut guest, mut switch) = connect_control(&h).await;
        guest
            .write_all(&unexpose)
            .await
            .expect("writing the retraction");
        let mut spoken = vec![0u8; unexpose.len()];
        read_within(&mut switch, &mut spoken).await;
        assert_eq!(
            spoken, unexpose,
            "the interim publication's teardown reaches the switch"
        );
    }

    /// NET-133, at the table: a box's row is withdrawn within the
    /// requirement's bound of its end. The bound's name is the box's end; the
    /// event the table keys the withdrawal to is the box's own shuttle
    /// connection — the one the guest's relay opens per box and never
    /// reopens — ending, and creator-driven withdrawal at destroy is T66's
    /// (#1711), landing with it. The gate attributes every admitted frame's
    /// source to the connection that carried it and files the report at the
    /// relay's end — whatever ended it — and the registry's drainer withdraws
    /// a row per reported address, so the namespace whose connection closed
    /// holds no row after. Here that is immediate: the report rides the same
    /// close that ended the traffic, far inside the bound the requirement
    /// names. A re-attachment starts from a registration, not from a row
    /// whose connection is gone; and the guest relay never reconnects a
    /// closed shuttle connection, so the traffic was already down.
    #[tokio::test]
    async fn host_table_row_withdrawn_within_60s_of_box_end() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        registry.spawn_withdrawal_drainer();
        let mut h = gate_over(registry).await;

        // The box's declared frame, admitted by its row: the traffic the
        // connection will attribute.
        let frame = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &frame).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, frame, "the declared frame reaches the switch");

        // The box's connection ends: the guest closes its side.
        h.guest.shutdown().await.expect("closing the guest's side");

        // The row goes with it. The withdrawal is polled rather than
        // asserted once: the report rides a close the relay has to notice
        // first, and the honest path is immediate — the poll bounds it at
        // the harness's deadline, nowhere near the requirement's own.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while h.table.by_source(LEASE).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the row outlived its shuttle connection past {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The node's own row outlives every relay that carried its frames. A
    /// relay's end withdraws the rows of the boxes its connection carried —
    /// a box's row goes with its shuttle connection (NET-133) — but the node
    /// plane's row is the host's own registration for the VM's lifetime,
    /// filed once at boot and never by a connection, so its end files no
    /// report for it. Nothing would give the address its reach back if it
    /// went: the announced interim reaches lease-run addresses only, and the
    /// plan keeps the node's address outside that run — one relay's end
    /// retiring it would leave the in-VM daemon frameless and unpublishable
    /// for the rest of the VM's life, over a shuttle close its control path
    /// rode out.
    #[tokio::test]
    async fn node_row_survives_the_relay_that_carried_its_frames() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let node = registry.register_node_namespace(7654, 7656);
        registry.spawn_withdrawal_drainer();
        let mut h = gate_over(registry).await;

        // Node-plane traffic on the relay — the in-VM daemon's own frames,
        // admitted by the node's row — beside the box's declared frame, the
        // traffic the same connection attributes to it.
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &node_frame).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            node_frame,
            "the node's frame reaches the switch by its row"
        );
        let box_frame = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &box_frame).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            box_frame,
            "the box's frame reaches the switch by its row"
        );

        // The relay ends, whichever way a shuttle connection does.
        h.guest.shutdown().await.expect("closing the guest's side");

        // The box's row goes with its connection — the drainer withdrew it —
        // and the node's row stands: its frames attributed nothing, so no
        // report ever named its address.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while h.table.by_source(LEASE).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the box's row outlived its shuttle connection past {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            h.table.by_source(node.switch_addr().octets()).is_some(),
            "the node's row stands after the relay that carried its frames ended"
        );

        // And the reach survives: the node's next connection carries its
        // frames again, admitted by the row no report retired.
        let (mut guest, mut switch) = connect_over(&h).await;
        send_frame(&mut guest, &node_frame).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            node_frame,
            "the node's frames still pass after the earlier relay's end"
        );
    }

    /// The withdrawal report itself, watched: one relay carries a
    /// node-sourced frame and a lease-run frame, ends, and the report it
    /// files names the lease-run address only — the node's address is not in
    /// it, because the node's row is the host's own registration, filed once
    /// at boot and never by a connection ([`BoxRegistry::register_node_namespace`]),
    /// and a report that named it would retire the row that decides the
    /// in-VM daemon's frames and publishes for it for the rest of the VM's
    /// life. The report is read off the channel the drainer would consume,
    /// so the assertion is the host's own words about what ended, not just
    /// the rows left standing after it.
    #[tokio::test]
    async fn node_row_survives_relay_end() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let node = registry.register_node_namespace(7654, 7656);
        // The reports, read directly: the drainer is not started, so the
        // report's content is the test's to assert on.
        let reports = registry
            .take_withdrawal_reports()
            .expect("the withdrawal reports' receiver is taken once");

        let mut h = gate_over(registry).await;

        // One node-sourced frame, one lease-run frame, both admitted — the
        // traffic the relay attributes to the connection that carried it.
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &node_frame).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            node_frame,
            "the node's frame reaches the switch by its row"
        );
        let box_frame = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &box_frame).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            box_frame,
            "the box's frame reaches the switch by its row"
        );

        // The connection ends.
        h.guest.shutdown().await.expect("closing the guest's side");

        // The report names the lease-run address only, and the node's row
        // stands: the exclusion is the fix the round-6 review asked for,
        // pinned here at the report the drainer acts on. The report is filed
        // by the gate's task on this runtime, so the read polls around
        // yields instead of blocking the thread the filing runs on.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        let report = loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the withdrawal report is not filed within {DEADLINE:?}"
            );
            match reports.try_recv() {
                Ok(report) => break report,
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("the withdrawal channel is down; nothing will file a report")
                }
            }
        };
        assert_eq!(
            report,
            vec![LEASE],
            "the withdrawal report names only the lease-run address"
        );
        assert!(
            h.table.by_source(node.switch_addr().octets()).is_some(),
            "the node's row survives the relay's end"
        );
    }
}
