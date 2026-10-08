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
//! through the verdict, per source address; switch → guest applied to nothing
//! — ingress policy is the *target* box's and is decided in the guest, so
//! NET-081 is an egress requirement — but *read* on the way through for one
//! class of frame: a DNS reply the switch returned toward a box, which the
//! host-side DNS admission table ([`crate::net::dns_pins`]) pins from, so the
//! answers that decide a DNS box's undeclared destinations are the ones the
//! box's own lookups received. Every frame still flows onward verbatim;
//! observation is a read, never a hold.
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
//! Fail-closed is the posture, at the frame level unconditionally (NET-085):
//! a frame whose source address no published namespace holds is NET-081's
//! failure case, and it never leaves the VM, toward every destination alike —
//! the baseline set included — whatever the plan could have done with the
//! address. Two classes of it take two rules, so a host reading its log can
//! tell them apart: an address outside the plan's lease block is nobody's to
//! wear and drops under [`UNKNOWN_SOURCE_RULE`], while an address inside the
//! run the plan hands leases from — the set an own-address box's lease is
//! minted into by the in-VM daemon's own allocator, which no host-side
//! process can name until the creator-side registration (T66, #1711)
//! supplies the rows — drops under [`UNREGISTERED_SOURCE_RULE`], with the
//! one remedy the host can offer spelled beside it: a source the gate's
//! ledger holds an applied publish for is a live lease a namespace inside
//! the VM is holding and serving through ([`PublishedForwards`]), a box
//! that predates host registration, so its line says to restart it
//! ([`UNREGISTERED_LIVE_LEASE_RULE`]). The publish half of the gate decides
//! by the phase constant ([`UNREGISTERED_SOURCE_PHASE`]), which names the
//! egress default's rollout and nothing at the frame level: under the
//! announced interim this build ships a publish at an in-plan address no
//! row holds is applied — the reach the guest daemon's own publishes had
//! before the gate existed — and refused everywhere else, so a compromise
//! in the VM cannot point a forwarder or a zone name at the plan's
//! infrastructure or anywhere outside the plan; once the default binds,
//! only a published namespace's own records publish at all. That is the
//! egress default's phase, and its frame half — the gate's handling of a row
//! with no egress section, an absent section still allowing all — is decided
//! by the compiled row, so the two halves stay coupled through
//! [`UnregisteredSourcePhase::into_sessions_phase`] and move together when
//! T66 flips the constant. A frame a published
//! box did not declare is dropped
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
//! included, so a row that declared DNS hosts — whose undeclared destinations
//! the DNS admission table decides against the answers its own lookups
//! received — reaches none of it by name either: the answers are refused
//! before they can become pins, and the infrastructure drop is the host's
//! own, whatever the row.
//!
//! The Box Egress Proxy's listener is the third destination no row's rules
//! decide (NET-134): the proxy is a **credentialed lane's** infrastructure —
//! the one host-side listener a box reaches by declaring the upstream, not by
//! allowing an address — so the listener, and the listener alone — TCP to
//! [`switch::bep_host::PROXY_PORT`] at the proxy's address, one of §5.3's
//! port-scoped openings — is admitted for a row that declared one, and every
//! other frame to the proxy's address is refused for everything else, a
//! deny-all row included
//! (`egress-uncredentialed-proxy-destination`, [`PROXY_LANE_RULE`]). The
//! decision reads the row's own declaration, never its rules: a lane is not
//! an egress dimension, and nothing a box says inside the VM can grant one —
//! the declaration travelled the host's registration, reduced to a fact in
//! the row ([`BoxRecord::declares_credentialed_upstream`]), and the node
//! plane's baseline set admits the proxy's address for no category at all.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
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

use crate::box_registry::{BoxRecord, BoxTable, RowWithdrawal};

use super::baseline::{NodeBaselinePhase, NodePlaneBaseline};
use super::dns_pins;
use super::forward_revoke::{self, ForwardedFlows};

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

/// The rule name for one inbound flow the gate refused at a box's reply-flow
/// cap (NET-040's answer half): the flow is refused *at ingress* — the
/// opening frame is never delivered toward the box, so the client's connect
/// fails rather than the box's session — while the flows the table already
/// recorded keep refreshing and keep their replies admitted. Its own rule,
/// not the switch-control or the row verdict's, because what it names is a
/// bound the host keeps on the flows a published box's ingress can earn
/// records for, not a destination any rules decided.
const INBOUND_FLOW_CAP_RULE: &str = "egress-inbound-flow-cap";

/// The rule name for a deny-all box's DNS datagram the host drops rather
/// than write on to the switch (NET-141's deny-all case, decided host-side
/// for own-address rows): anything but a standard query whose every
/// question is an A lookup of a box-zone name
/// ([`dns_pins::deny_all_refusal`]). Its own rule, not the row verdict's:
/// the verdict admitted the frame under the resolver carve-out, and what
/// this names is the name the carve-out may not carry out.
const DENY_ALL_DNS_RULE: &str = "egress-deny-all-dns-query";

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
/// row, before the row's own rules and before the pin arm a name-declaring
/// row earns — no row, no `allow_subnets` entry, and no DNS pin ever admits
/// a frame here. The ranges are [`INFRASTRUCTURE_RANGES`]'; the one
/// exemption is RFC 1918 under the row's `allow_subnets`, and the one
/// carve-out is the node's own switch block ([`infrastructure_destination`]).
const INFRASTRUCTURE_RULE: &str = "egress-infrastructure-destination";

/// The ranges the host-side infrastructure rule refuses — the host frame
/// rule's own copy of the §5.3 set, built beside the sessions crate's
/// [`egress::InfrastructureDenySet`] rather than from it, because the two
/// decide different things and the rebinding intersection relies on its own
/// shape: that set names the gateway's two addresses as `/32`s (here the
/// gateway is the control-surface rule's, [`SWITCH_CONTROL_RULE`], and the
/// host alias is default-deny under this rule for a box row), refuses or admits
/// the whole fabric plane by whether the name is a box-zone name (a frame has
/// no name, and the plane's one admitted slice is the node's own block), and
/// keeps its ranges private. The constants overlap without coinciding: the
/// answer side's set carries the four ranges that complete it — this-host
/// space, multicast, broadcast, and the reserved block the broadcast address
/// ends in — for answers alone, where the frame rule refuses a frame by its
/// own facts (a multicast or this-host destination is already outside the
/// row's declared reach, and the plane and RFC 1918 arms decide the rest).
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
/// holds it ([`INFRASTRUCTURE_RULE`]): a fixed range; the host alias, which
/// is default-deny at every port for a box row (design §7.1, NET-062) when
/// `refuse_host_alias` says so; the fabric plane
/// outside `own_block`, the subnet the gate's rows live in — a frame to a
/// sibling or to the daemon inside the node's own block is local reach,
/// decided by the row's CIDR rules and the target's ingress, never by this
/// rule, and the gateway inside it is the control-surface rule's; or RFC
/// 1918 space the row's `allow_subnets` does not cover.
///
/// `allow` is the row's compiled `allow_subnets`, `None` when the dimension
/// is undeclared — allow-all, the shipped default (03-spec R2.1) — which
/// counts as covering the destination, as the rebinding intersection's
/// exemption holds it ([`egress::rebinding_admits`]): the two allow-all
/// spellings, an undeclared dimension and `0.0.0.0/0`, compile to the same
/// reach everywhere else in the verdict, and the host's rule must not split
/// them, or veto a private address the host's own admission table pins for
/// the same declaration. A declared list that does not cover the destination
/// is the refusal: a developer who wants a box to reach the LAN says so by
/// allowing the range, so neither a name rule nor a pin can become a way
/// around leaving it undeclared.
///
/// `refuse_host_alias` is `false` for the node namespace's row alone: the
/// interim node row, keyed to the daemon's own address, carries the frames
/// of every box that shares the guest root namespace (a host-address box,
/// the default network mode), and those reach the host alias as own-block
/// local reach until the in-force baseline, which names the alias as its
/// registry and cache endpoint, decides the node plane instead. This
/// mirrors the shared verdict, whose own-address refusal is attached to box
/// relays only, never to the daemon relay.
fn infrastructure_destination(
    dst: [u8; 4],
    own_block: SwitchSubnet,
    allow: Option<&[Ipv4Cidr]>,
    refuse_host_alias: bool,
) -> bool {
    let ranges = &*INFRASTRUCTURE_RANGES;
    if ranges.fixed.iter().any(|cidr| cidr.contains(dst)) {
        return true;
    }
    // The host alias is default-deny (design §7.1, NET-062): a box reaches
    // the host only through a declared exposure, never by addressing the
    // alias directly, so the alias is refused under this rule at every port
    // whatever the row's rules would say about it.
    if refuse_host_alias && dst == own_block.host_alias().octets() {
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

/// The rule name for a frame headed to the Box Egress Proxy's address that
/// the lane does not admit (NET-134): the proxy's listener is a credentialed
/// lane's infrastructure — the one host-side destination a box reaches by
/// *declaring* the upstream, never by allowing its address — and it is the
/// listener the declaration opens, TCP to [`switch::bep_host::PROXY_PORT`],
/// one of §5.3's port-scoped openings, not the address. So the frame is
/// refused for every source that carries no lane — a row whose declaration
/// named none, whatever its rules would say about the address; an
/// unregistered source the announced interim admits, which concedes a row's
/// absence and never the fabric; and the node plane, whose baseline set
/// admits the address for no category at all — and for the one source that
/// carries a lane, every frame at the address that is not the listener:
/// another port, another protocol, either way past the box-to-host
/// default-deny the lane never lifted. A row that declares the upstream is
/// the one exception, admitted at the listener as infrastructure, beside its
/// rules ([`GateAdmit::ProxyLane`]).
const PROXY_LANE_RULE: &str = "egress-uncredentialed-proxy-destination";

/// The rule name for the ingress drop of an opening TCP packet (SYN set, ACK
/// clear) sourced from the Box Egress Proxy's address toward a box's
/// published inside port (NET-134's ingress arm): the proxy only answers a
/// credentialed box's dial and never opens toward a box, so such a packet has
/// no legitimate origin. Its own rule, not [`PROXY_LANE_RULE`]'s: that one
/// names a box reaching for the proxy, this one the proxy's address reaching
/// for a box. The proxy's answers (SYN-ACK, ACK, data, FIN, RST) are never
/// dropped under it.
const PROXY_OPENING_RULE: &str = "egress-proxy-opening-toward-box";

/// The rule name for the drop of an in-plan source no published namespace
/// holds (NET-085): a frame whose source is an address the plan could hand
/// to a box but no row does. It carries its own rule — beside rule 0's
/// [`UNKNOWN_SOURCE_RULE`], the out-of-plan class it was folded into while
/// the announced interim admitted these frames — because the two classes ask
/// a host reading its log different questions: an out-of-plan source is
/// nobody's to wear, while an in-plan one is a lease the guest daemon's own
/// allocator could have minted — an own-address box's, or a task sandbox's —
/// whose row the creator-side registration (T66, #1711) is the only thing
/// that ever publishes. A warn, not an info, because the drop is the gate's
/// containment working and a host must be able to see it in the log.
const UNREGISTERED_SOURCE_RULE: &str = "egress-unregistered-source";

/// The rule name for the drop of a live lease on the switch no published
/// namespace holds: an address the gate's own ledger ([`PublishedForwards`])
/// carries an applied publish for — a forwarder gvproxy holds for it, the
/// one host-observable fact that a namespace inside the VM holds the lease
/// and is serving through it — while no row names the box. Its line is the
/// one drop the gate can name a remedy for: the box predates host
/// registration, so restarting it registers it, and the line says so beside
/// the lease it names. The publish informs the line and nothing else — the
/// gate never registers a box from what the guest says it holds — so the
/// frame drops exactly as the generic rule's does, whatever the line.
const UNREGISTERED_LIVE_LEASE_RULE: &str = "egress-unregistered-live-lease";

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

/// The rule name for a publish refused because a withdrawn box's revocation
/// still holds the address it names (design §7.1): the gate is unbinding
/// that box's forwards, and a forward published there now would be taken
/// for the old box's and unbound with them.
const REVOKING_ADDRESS_RULE: &str = "egress-publish-at-revoking-address";

/// The rule name for a publish refused because the gate's publish ledger is
/// at its bound ([`PUBLISHED_FORWARDS_TRACKED`]): a forward the ledger
/// cannot hold could never be unbound at its box's end, so it is never
/// bound.
const PUBLISH_LEDGER_FULL_RULE: &str = "egress-publish-ledger-full";

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
    /// The box-end revoker ([`revoke_on_row_withdrawal`]): unbinds a
    /// withdrawn box's forwards and terminates their connections.
    revoker: JoinHandle<()>,
}

impl EgressGate {
    /// Binds `gate_sock` and starts deciding every frame the guest's shuttle
    /// sends, against `table`, relaying the admitted ones to the switch
    /// listening on `switch_sock`. Must be called within a tokio runtime.
    ///
    /// `pins` is the host-side DNS admission table ([`crate::net::dns_pins`])
    /// the gate's two legs and its verdict share: filled by the replies the
    /// ingress leg observes toward a box, read by the verdict's pin arm for
    /// the one drop class a row that declared DNS hosts takes, and retired
    /// box by box beside the withdrawal report that ends each box's row. It
    /// arrives built for the switch's own address plan — the same plan the
    /// table's rows were compiled against — and empty, because pins exist
    /// only from replies a box received.
    ///
    /// The gate socket is the path [`crate::vm`] points the shuttle's vsock
    /// port at; a stale socket file from a previous run must be removed by the
    /// caller first, or the bind fails.
    ///
    /// The egress default's phase is the build's own
    /// ([`UNREGISTERED_SOURCE_PHASE`]) — no production caller chooses it, and
    /// it decides the publish half alone. A test that needs the phase's other
    /// arm builds its gate with
    /// [`spawn_with_phase`](Self::spawn_with_phase), which is also where the
    /// real work is.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the gate socket cannot be bound.
    pub(crate) fn spawn(
        gate_sock: PathBuf,
        switch_sock: PathBuf,
        table: BoxTable,
        pins: dns_pins::DnsPins,
        baseline: NodePlaneBaseline,
    ) -> io::Result<Self> {
        // One reply-flow table for the whole gate, empty at boot: a record
        // exists only once the gate's own ingress leg has delivered an
        // opening packet toward a published box (NET-040's answer half), so a
        // gate that has relayed nothing holds nothing.
        Self::spawn_with_phase(
            gate_sock,
            switch_sock,
            table,
            pins,
            ReplyTables::new(),
            baseline,
            UNREGISTERED_SOURCE_PHASE,
        )
    }

    /// [`spawn`](Self::spawn) with the egress default's phase named: the
    /// parameter that lets a test build the gate under the phase's other arm
    /// ([`UnregisteredSourcePhase::InForce`], the one T66, #1711, flips the
    /// shipped constant onto) and pin the publish decision's in-force arm at
    /// relay level, so the flip has behaviour to turn green rather than tests
    /// to rewrite. The frame half needs no phase from here: the drop of an
    /// unregistered source is unconditional ([`gate_verdict`] reads no phase),
    /// and the start-up line logs the phase the gate was actually built with.
    ///
    /// `replies` is the gate's own reply-flow table (NET-040's answer half)
    /// beside the DNS admission table: one shared per-box table of the
    /// inbound flows the gate's ingress leg delivered toward a published box,
    /// whose exact reverse the verdict admits ahead of every rule the row
    /// holds — so a deny-all box still answers the connections its published
    /// port received. It arrives empty and filled only by the ingress leg, and
    /// the two halves that read it share the one clone they are handed here.
    /// It is a parameter for the same reason `pins` is: a test that pins the
    /// records' life at relay level needs to hold the very table the gate's
    /// relays decide by, and `spawn` — the production entry — builds its own.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the gate socket cannot be bound.
    pub(crate) fn spawn_with_phase(
        gate_sock: PathBuf,
        switch_sock: PathBuf,
        table: BoxTable,
        pins: dns_pins::DnsPins,
        replies: ReplyTables,
        baseline: NodePlaneBaseline,
        phase: UnregisteredSourcePhase,
    ) -> io::Result<Self> {
        let listener = UnixListener::bind(&gate_sock)?;
        // The two postures the gate starts under, named as the two fields they
        // are and never one combined string, so a bundle's reader reads each
        // off the one line every boot writes: the frame-level drop of a source
        // no row holds — unconditional (NET-085), no phase gates it, and the
        // warns below say it again once per source per interval — and the
        // egress default's phase, which decides the publish half and a row
        // with no egress section, never a frame's source.
        tracing::info!(
            gate_socket = %gate_sock.display(),
            switch_socket = %switch_sock.display(),
            unregistered_sources = "dropped",
            undeclared_box_default = phase.as_str(),
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
        // Subscribed before the accept loop starts, so no row withdrawn
        // while the gate serves escapes the revoker.
        let withdrawn = table.subscribe_row_withdrawals();
        let revoker = tokio::spawn(revoke_on_row_withdrawal(
            withdrawn,
            switch_sock.clone(),
            Arc::clone(&forwards),
            replies.clone(),
        ));
        Ok(Self {
            revoker,
            accept: tokio::spawn(accept_loop(
                listener,
                switch_sock,
                table,
                pins,
                replies,
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
        self.revoker.abort();
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
    reason = "the source, the switch socket, the table, the DNS admission table, the \
              reply-flow tables, the baseline, the limiter, the publish ledger, the \
              bound and the phase are each a distinct input to every relay the loop \
              spawns; grouping them would name the bundle without naming the members"
)]
async fn accept_loop<A: GuestSource>(
    mut source: A,
    switch_sock: PathBuf,
    table: BoxTable,
    pins: dns_pins::DnsPins,
    replies: ReplyTables,
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
            pins.clone(),
            replies.clone(),
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
    reason = "the two sockets, the table, the DNS admission table, the reply-flow \
              tables, the baseline, the limiter, the publish ledger, the drain bound \
              and the phase are each a distinct input to what one connection does; \
              grouping them would name the bundle without naming the members"
)]
async fn serve_connection(
    mut guest: UnixStream,
    switch_sock: PathBuf,
    table: BoxTable,
    pins: dns_pins::DnsPins,
    replies: ReplyTables,
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
                pins,
                replies,
                baseline,
                limiter,
                forwards,
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
                replies,
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
/// the frame verdict, per source address; ingress (switch → guest) applied to
/// nothing — the gate's job is the egress direction, and what a box may
/// receive is the target's ingress policy, decided in the guest where its
/// declarations are enforced — but read on the way through for the one frame
/// class the host's own decision is made from: the DNS replies the switch
/// returns toward a box, which [`crate::net::dns_pins`] pins from
/// ([`relay_switch_frames_to_guest`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the relay's full state in one place: both directions' halves, the \
              deciding table, the DNS admission table, the reply-flow tables and the \
              node-plane baseline set, the limiter and the publish ledger — splitting \
              it would hide one of them"
)]
async fn relay_frames(
    mut guest: Prefixed<OwnedReadHalf>,
    mut switch_tx: OwnedWriteHalf,
    switch_rx: OwnedReadHalf,
    guest_tx: OwnedWriteHalf,
    table: BoxTable,
    pins: dns_pins::DnsPins,
    replies: ReplyTables,
    baseline: NodePlaneBaseline,
    limiter: Arc<DropLimiter>,
    forwards: Arc<PublishedForwards>,
) {
    let mut ingress = tokio::spawn(relay_switch_frames_to_guest(
        switch_rx,
        guest_tx,
        table.clone(),
        pins.clone(),
        replies.clone(),
        Arc::clone(&limiter),
        Arc::clone(&forwards),
    ));
    // Every admitted frame's source, deduplicated: the attribution this relay
    // files at its end. Filled by the egress leg's loop below but owned here,
    // so it outlives whichever leg loses the race and is filed on every exit.
    // Bounded by the table, not by the guest — only a row the registry holds
    // admits a frame now, the node's own address excepted out in the loop, so
    // the vector is bounded by the rows, never by what a guest could push
    // through it.
    let mut attributed: Vec<[u8; 4]> = Vec::new();
    {
        let egress = relay_frames_to_switch(
            &mut guest,
            &mut switch_tx,
            &table,
            &pins,
            &replies,
            &baseline,
            &limiter,
            &forwards,
            &mut attributed,
        );
        tokio::pin!(egress);
        // The two legs race, because neither can see the other's end. The
        // egress leg blocks on the guest, which has no reason to speak while
        // it is idle, so it has no way to learn the switch hung up this one
        // connection's end — the per-connection close a switch makes without
        // the process exit the supervisor catches — and would otherwise hold
        // the relay task, the gate's dial, and the switch write half open
        // until the guest's next frame came and failed to write. The ingress
        // leg ending is the only thing on this side that knows, so whichever
        // leg ends first takes the relay down with it.
        tokio::select! {
            result = &mut egress => match result {
                // The guest closed its side: the shuttle reconnects per boot
                // and drops the connection at teardown.
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(error) => {
                    tracing::warn!(%error, "egress gate relay ended on an error");
                }
            },
            result = &mut ingress => match result {
                // The switch closed its side of the connection while the
                // guest was still on it: the guest's egress is down, so say
                // so — the guest has nothing else to tell it why — before the
                // relay comes off.
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
    }
    // The relay is over, whichever way it ended — the guest's clean close, an
    // error on either end, a frame claim the gate refused, or the switch
    // closing its side while the guest was still on it. What it relayed is
    // what it attributes: the rows whose traffic this connection carried are
    // withdrawn now that nothing is left carrying it. The guest relay never
    // reconnects a closed shuttle connection (`attach_to_switch_vsock` in the
    // guest's relay), so egress at those addresses is already down; the
    // withdrawal is what makes that true of the table too, so a re-attachment
    // starts from a registration and not from a row whose connection is gone
    // (NET-133: a box's row goes with its shuttle connection). The same event
    // retires the pins: the admission entries those boxes' own lookups filled
    // go with the rows that declared the names, so nothing inside the VM can
    // hand a box its old grants back — a re-attachment starts fail-closed,
    // until its own lookups pin again. A control connection files no report
    // at all: one fresh connection per control request is the daemon's own
    // client's shape, and constant churn is not box end. The reply-flow
    // records go with them, on the same event: a record is an admission the
    // box's published port earned while its traffic could reach the switch,
    // so it goes with the connection that carried it, and a re-attachment
    // answers only what its own ingress admits again. The report runs here,
    // after the select, rather than inside the egress leg, so the ingress
    // leg's win still files it: a leg dropped un-polled never reached its own
    // tail.
    //
    // The leg that lost the race is torn down with the relay, not left to
    // hold what the guest or the switch end of it was holding — and torn
    // down before the retires, not after: abort only asks, so an ingress leg
    // left running could still pin a DNS reply or record a reply flow for a
    // source the retires below have already cleared. Awaiting it makes it
    // gone first. A leg that already finished has had its output taken (or
    // is done with nothing left to pin), so it is not polled again.
    if !ingress.is_finished() {
        ingress.abort();
        let _ = (&mut ingress).await;
    }
    pins.retire(&attributed);
    replies.retire(&attributed);
    table.report_withdrawals(std::mem::take(&mut attributed));
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
              reply-flow tables, the publish ledger and the drain bound are each a \
              distinct input to one leg; grouping them would name the bundle without \
              naming the members"
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
    replies: ReplyTables,
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
    // A publish's two ends go to the ledger before the request is written
    // on: the listener it is applied at, for a later retraction's
    // attribution and for its unbind at the box's end, and the inside port
    // its forward dials — the port the box's declaration listens on and
    // every client's dial toward the box arrives at — for the reply-flow
    // recording's bound ([`PublishedForwards::inside_published`], NET-040's
    // answer half). The protocol is noted with them: the records the inside
    // port earns are keyed by it, so a later retraction ends them under the
    // protocol they were opened at, whatever its own body spells. A body
    // whose remote does not parse is left unnoted, which records nothing
    // for it: fail closed, the same posture an unapplied publish has.
    //
    // Noting first is what lets a full ledger refuse the publish
    // ([`PUBLISH_LEDGER_FULL_RULE`]): a forward the ledger cannot hold
    // could never be unbound at its box's end, so it is never bound. A
    // write that fails takes its note back out: a forward the gate could
    // not deliver published nothing. So does a publish the switch answers
    // with a status outside 2xx: it bound nothing, and a note nothing
    // releases would count against the bound for the gate's lifetime.
    let noted = match (verb, forward_listener(verb, &request)) {
        (ControlVerb::Expose, Some(listener)) => {
            match (published_inside(&request), published_protocol(&request)) {
                (Some(inside), Some(proto)) => match forwards.note_published(
                    listener,
                    decision.request.switch_addr(),
                    inside,
                    proto,
                    decision.applied,
                ) {
                    Ok(noted) => noted.then_some(listener),
                    Err(full) => {
                        refuse_request(
                            &limiter,
                            &RefusedRequest {
                                rule: PUBLISH_LEDGER_FULL_RULE,
                                addr: Some(decision.request.switch_addr()),
                                what: Some(format!("port {}", listener.1)),
                                reason: full.to_string(),
                            },
                        );
                        return;
                    }
                },
                _ => None,
            }
        }
        _ => None,
    };
    // Admitted: the head and body are forwarded together, in one write, so
    // the request gvproxy sees is exactly the request the guest sent and
    // exactly the request the table admitted.
    let mut spoken = head;
    spoken.extend_from_slice(&request);
    if let Err(error) = switch.write_all(&spoken).await {
        tracing::warn!(%error, "egress gate could not forward an admitted control request");
        if let Some(listener) = noted {
            let _unpublished = forwards.note_retracted(listener);
        }
        return;
    }
    if decision.applied == Applied::Interim {
        // The interim's admission is the one publish the gate applies whose
        // reach no row bounds, and the host must be able to see it pass.
        warn_interim_publish(&limiter, &decision);
        // And the lease it named is one the guest daemon vouched for while
        // no row held it, whatever the request published: the fact the
        // live-lease drop line reads ([`PublishedForwards::lease_live_at`]).
        forwards.note_vouched(decision.request.switch_addr());
    }
    // An applied retraction's listener leaves the publish ledger with it —
    // the publication is gone. The note is taken after the write: a
    // retraction the gate could not deliver withdrew nothing. Its note is
    // read back, not dropped: the attribution it carried names the box
    // whose records the publication earned, which end with the publication
    // (below).
    if let (ControlVerb::Unexpose, Some(listener)) = (verb, forward_listener(verb, &request)) {
        // The retraction takes the publication's records with it: the
        // records a publish's inside port earned are admissions *of*
        // that publish, so they end in the same step the ledger drops
        // the publish's attribution — the next frame the box sends back
        // on one of them is decided by the rules, not by the record a
        // publication that no longer stands opened. The records at the
        // box's other published ports stay standing: a retraction ends
        // a publication, never the box. The attribution and the protocol
        // both come from the ledger, which noted them at the publish the
        // records were opened under — never from the retraction's own
        // spelling, which could name a protocol the publish did not —
        // and which held them for exactly this: a retraction
        // the ledger could not attribute was already refused, and a
        // row the retraction ends nothing of simply has no entry to
        // end. Two listeners can dial one inside port, and the records
        // are keyed by protocol and inside port, not by listener: while
        // another applied publish still dials the same port in the same
        // protocol, the records are that publication's too, so they stay.
        if let Some((addr, inside, proto)) = forwards.note_retracted(listener)
            && !forwards.still_published(addr, inside, proto)
        {
            replies.end_port_at(addr, proto, inside);
        }
    }
    let answered = Arc::new(OnceLock::new());
    let mut response = tokio::spawn(copy_switch_to_guest(
        switch_rx,
        guest_tx,
        Arc::clone(&answered),
    ));
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
            None
        }
        end = control_request_probe(&mut guest, drain_timeout) => Some(end),
    };
    match end {
        None => {}
        // A guest that closed, and one that spoke its request and then said
        // nothing for the whole bound — its silence is its normal posture
        // while it waits on the answer — both leave the request leg done.
        // The answer is owed either way: the switch's side is half-closed, so
        // gvproxy sees the request's end and answers it, and the drain that
        // delivers it is bounded.
        Some(ControlEnd::GuestClosed | ControlEnd::GuestSilent) => {
            finish_control(&mut response, &mut switch, drain_timeout).await;
        }
        Some(ControlEnd::SpokePastRequest) => {
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
    // A publish the switch refused bound nothing: its note comes back out,
    // with any records it opened. A publish left unanswered keeps its note,
    // since the switch may have bound it, and the box's end unbinds it; an
    // unexpose of a forward that is not bound counts as done there.
    if let (Some(listener), Some(&status)) = (noted, answered.get())
        && !(200..300).contains(&status)
        && let Some((addr, inside, proto)) = forwards.note_retracted(listener)
    {
        tracing::info!(
            status,
            switch_addr = %Ipv4Addr::from(addr),
            local = %forward_revoke::listener_local(listener.0, listener.1),
            "the switch refused a publish; the egress gate's ledger released its note"
        );
        if !forwards.still_published(addr, inside, proto) {
            replies.end_port_at(addr, proto, inside);
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
/// switch address it was applied at and the inside port its forward dials:
/// the ledger a retraction is attributed by, and the record of what a
/// published mapping's two ends are on the host. The unexpose body names only
/// the loopback listener it retracts — the wire carries no switch address —
/// but the decision is keyed per address (`switch_request::applied` decides a
/// retract by the row at the request's own address, against the ports that
/// row's runtime published), so the gate supplies the address from the one
/// place it is a host-side fact: the publish the listener's forward came
/// from. A retraction for a listener no applied publish names is keyed at the
/// unspecified address, which no row holds, and refused — a guest cannot
/// retract a publication the gate never admitted by naming a port some row
/// happens to declare.
///
/// The inside port is the other half of the same fact, and the one no row
/// carries: a mapping's inside end is the port every client's dial toward the
/// box arrives at — the forwarder's dial, the hostname proxy's, a sibling's —
/// because it is the port the box's own declaration listens on, and it is
/// never the port the registration wire carried ([`BoxRecord`]'s
/// `admitted_ports` are the external ends, the host-side listeners). The
/// reply-flow recording ([`ReplyTables::observe_delivered`], NET-040's answer
/// half) is bounded by it: only a frame the ingress leg delivers at a port
/// one of the box's applied publishes dials opens a record, so a record
/// exists only for a flow toward a port the box published, exactly the bound
/// the in-guest relay applies to the same declaration's inside ends. The
/// ledger entry — address and inside port together — is what the host reads
/// that bound from, the same single source the retraction's attribution comes
/// from.
///
/// The ledger is shared by the gate's connections: the publish and its
/// teardown arrive on different ones — the daemon's client speaks one
/// request per connection — so a per-connection ledger would refuse every
/// honest teardown, and the frame connections' ingress legs read the inside
/// ports a control connection noted. The lock is held only across a lookup
/// or an update, never across an await.
///
/// The row-held publishes are bounded at [`PUBLISHED_FORWARDS_TRACKED`]. At
/// the bound a new one is refused ([`PUBLISH_LEDGER_FULL_RULE`]) rather than
/// an old attribution evicted: an evicted entry would be a forward still
/// bound on the host that its box's end could no longer name, so it would
/// never be unbound. A box's runtime ports can reach the bound (a wide
/// dynamic range and a busy box), so the refusal is real, typed and logged.
///
/// The interim's publishes ([`Applied::Interim`]) are counted apart, against
/// [`INTERIM_PUBLISHES_TRACKED`], and at that bound the oldest of them is
/// evicted. No row's withdrawal ever names their address, so the host never
/// unbinds them at a box's end and refusing to evict one protects nothing;
/// counted with the row-held ones, enough of them would refuse every box's
/// publish until the gate restarts.
#[derive(Debug, Default)]
struct PublishedForwards {
    applied: Mutex<Vec<AppliedPublish>>,
    /// The rowless addresses an applied switch request named as the box's
    /// own — a port publish, a zone name, a retraction alike — oldest first,
    /// bounded at [`LEASES_VOUCHED_TRACKED`]. Each is a lease the guest
    /// daemon vouched for while no row held it ([`Self::lease_live_at`]).
    vouched: Mutex<Vec<[u8; 4]>>,
    /// The TCP connections the applied publishes' forwards carry, each with
    /// the state a reset for it is built from: what the box's end terminates
    /// once its forwards are unbound ([`revoke_box_forwards`], design §7.1).
    flows: ForwardedFlows,
}

/// A forwarder listener: its loopback address and port.
type Listener = ([u8; 4], u16);

/// One applied publish in the ledger: its listener, the address it was
/// applied at, the inside port its forward dials, the protocol it named, and
/// whether a row or the interim applied it.
type AppliedPublish = (Listener, [u8; 4], u16, u8, Applied);

/// How many row-held publishes' attributions the ledger keeps. A row-held
/// publish past the bound is refused ([`LedgerFull`]).
const PUBLISHED_FORWARDS_TRACKED: usize = 1024;

/// How many of the interim's publishes' attributions the ledger keeps, apart
/// from the row-held ones. Past the bound the oldest interim one is evicted.
const INTERIM_PUBLISHES_TRACKED: usize = 1024;

/// A publish refused because the ledger holds [`PUBLISHED_FORWARDS_TRACKED`]
/// forwards already: the gate could not unbind one more at its box's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the egress gate's publish ledger holds {PUBLISHED_FORWARDS_TRACKED} forwards, its bound; \
     a forward the ledger cannot hold could never be unbound at its box's end"
)]
struct LedgerFull;

/// The waits between a withdrawn box's unbind attempts, one per retry: a
/// forward whose unexpose failed is retried after each, and the bound on
/// the retries is this list's length. Past the last, the forwards still
/// bound are left bound and said so, and their addresses stay held against
/// reuse for the gate's lifetime.
static UNBIND_RETRY_BACKOFF: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// How many vouched rowless leases the ledger keeps.
const LEASES_VOUCHED_TRACKED: usize = 1024;

impl PublishedForwards {
    /// A ledger with no applied publishes in it.
    fn new() -> Self {
        Self {
            applied: Mutex::new(Vec::new()),
            vouched: Mutex::new(Vec::new()),
            flows: ForwardedFlows::default(),
        }
    }

    /// Every applied publish at the box address `addr`: what the box's end
    /// unbinds ([`revoke_box_forwards`]). Each stays in the ledger until its
    /// unbind succeeds, so a forward whose unexpose failed is still the
    /// gate's to retry, and still attributed.
    fn published_at(&self, addr: [u8; 4]) -> Vec<(Listener, u16, u8)> {
        self.lock()
            .iter()
            .filter(|(_, at, _, _, _)| *at == addr)
            .map(|(listener, _, inside, proto, _)| (*listener, *inside, *proto))
            .collect()
    }

    /// Drops the attribution of `listener` when it is still the one applied
    /// at `addr`: the box's end unbound it. Returns whether it was.
    fn note_unbound_at(&self, listener: Listener, addr: [u8; 4]) -> bool {
        let mut applied = self.lock();
        let Some(at) = applied
            .iter()
            .position(|(held, at, _, _, _)| *held == listener && *at == addr)
        else {
            return false;
        };
        applied.remove(at);
        true
    }

    /// Notes a publish the gate is about to apply: the address its listener
    /// is applied at, the inside port its forward dials, the protocol it
    /// publishes and what applied it. The listener is keyed first — gvproxy
    /// binds one forwarder per loopback listener, so a second publish for a
    /// held listener never becomes live — and `Ok(false)` says the listener
    /// was already held, so nothing new was noted.
    ///
    /// An interim publish at [`INTERIM_PUBLISHES_TRACKED`] evicts the oldest
    /// interim attribution, and never counts against the row-held bound.
    ///
    /// # Errors
    ///
    /// [`LedgerFull`] for a row-held publish at
    /// [`PUBLISHED_FORWARDS_TRACKED`]: the publish is refused, never an older
    /// row-held attribution evicted.
    fn note_published(
        &self,
        listener: Listener,
        addr: [u8; 4],
        inside: u16,
        proto: u8,
        by: Applied,
    ) -> Result<bool, LedgerFull> {
        let mut applied = self.lock();
        if applied.iter().any(|(held, _, _, _, _)| *held == listener) {
            return Ok(false);
        }
        let held_by = applied.iter().filter(|entry| entry.4 == by).count();
        match by {
            Applied::Row if held_by >= PUBLISHED_FORWARDS_TRACKED => return Err(LedgerFull),
            Applied::Interim if held_by >= INTERIM_PUBLISHES_TRACKED => {
                if let Some(oldest) = applied.iter().position(|entry| entry.4 == Applied::Interim) {
                    let ((ip, port), at, _, _, _) = applied.remove(oldest);
                    tracing::warn!(
                        listener = %std::net::SocketAddrV4::new(ip.into(), port),
                        addr = %Ipv4Addr::from(at),
                        "the egress gate's ledger evicted its oldest interim publish at its bound; \
                         a guest retraction of that forward is now unattributed",
                    );
                }
            }
            Applied::Row | Applied::Interim => {}
        }
        applied.push((listener, addr, inside, proto, by));
        Ok(true)
    }

    /// Drops the attribution an applied retraction's listener carried, and
    /// hands it back: the publication is gone — its inside port stops
    /// opening reply-flow records with it, and the ones it already opened
    /// end with it ([`ReplyTables::end_port_at`], from [`relay_control`]) —
    /// and a later retraction of the same listener has nothing left to
    /// name. The listener is unique in the ledger ([`Self::note_published`]
    /// holds one attribution per listener), so the one removal is the whole
    /// retraction; `None` is a retraction the ledger had no attribution for,
    /// which the decision already refused as unattributed.
    fn note_retracted(&self, listener: Listener) -> Option<([u8; 4], u16, u8)> {
        let mut applied = self.lock();
        applied
            .iter()
            .position(|(held, _, _, _, _)| *held == listener)
            .map(|at| {
                let (_, addr, inside, proto, _) = applied.remove(at);
                (addr, inside, proto)
            })
    }

    /// The address the applied publish of `listener` was applied at, when
    /// one is in the ledger.
    fn address_of(&self, listener: Listener) -> Option<[u8; 4]> {
        self.lock()
            .iter()
            .find(|(held, _, _, _, _)| *held == listener)
            .map(|(_, addr, _, _, _)| *addr)
    }

    /// The protocol the applied publish of `listener` was published in,
    /// when one is in the ledger.
    fn protocol_of(&self, listener: Listener) -> Option<u8> {
        self.lock()
            .iter()
            .find(|(held, _, _, _, _)| *held == listener)
            .map(|(_, _, _, proto, _)| *proto)
    }

    /// Whether an applied publish's forward dials `addr` at `port`: the
    /// inside end of one of that box's live published mappings, the port
    /// every client's dial toward the box arrives at and the bound the
    /// reply-flow recording reads ([`ReplyTables::observe_delivered`],
    /// NET-040's answer half). A port no publish names — an external end the
    /// registration wire carried, an ephemeral port of the box's own egress,
    /// a port nothing published — opens nothing, so a record exists only for
    /// a flow toward a port the box's own ingress published, the same bound
    /// the in-guest relay applies to the same declaration's inside ends.
    fn inside_published(&self, addr: [u8; 4], port: u16) -> bool {
        self.lock()
            .iter()
            .any(|(_, at, inside, _, _)| *at == addr && *inside == port)
    }

    /// Whether an applied publish still dials `addr` at `inside` in
    /// `proto`: a retraction's records stay while another listener's
    /// publication stands at the same inside port, because they are its
    /// records too ([`relay_control`]).
    fn still_published(&self, addr: [u8; 4], inside: u16, proto: u8) -> bool {
        self.lock()
            .iter()
            .any(|(_, at, port, p, _)| *at == addr && *port == inside && *p == proto)
    }

    /// Notes a rowless address an applied switch request named as the
    /// box's own: the interim applied it, so the guest daemon vouched for
    /// the lease while no row held it. Whatever the request carried — a
    /// port publish, a zone name, a retraction — counts the same.
    fn note_vouched(&self, addr: [u8; 4]) {
        let mut vouched = self
            .vouched
            .lock()
            .expect("the vouched set's lock is held only across a lookup or an update");
        if vouched.contains(&addr) {
            return;
        }
        if vouched.len() >= LEASES_VOUCHED_TRACKED {
            vouched.remove(0);
        }
        vouched.push(addr);
    }

    /// Whether `addr` is a live guest lease: an applied switch request
    /// named it as a box's own, whatever it published — a rowless address
    /// the interim applied a port publish, a zone name or a retraction at,
    /// or one an applied publish still stands at. This is the
    /// host-observable fact that a live namespace holds the address, and
    /// the only one: an ARP claim the guest sends for it is itself a frame
    /// from a source no row holds, so it never reaches the switch to make a
    /// lease live there. A lease that has spoken no switch request at all is
    /// indistinguishable at the gate from a made-up one. The one drop line
    /// it informs is the unregistered source's
    /// ([`DropLimiter::warn_live_lease`]): a frame from such an address is
    /// a live lease no published namespace holds — its box predates host
    /// registration (T66, #1711) — and the line says so instead of the
    /// generic one. It informs the line only, never the verdict: the frame
    /// drops either way, and the gate registers no box from what the guest
    /// says it holds.
    fn lease_live_at(&self, addr: [u8; 4]) -> bool {
        let vouched = self
            .vouched
            .lock()
            .expect("the vouched set's lock is held only across a lookup or an update")
            .contains(&addr);
        vouched || self.lock().iter().any(|(_, at, _, _, _)| *at == addr)
    }

    fn lock(&self) -> MutexGuard<'_, Vec<AppliedPublish>> {
        self.applied.lock().expect(
            "the ledger's lock is held only across a lookup or an update, never across a panic",
        )
    }
}

/// The gate's half of host-side ingress revocation (design §7.1, NET-121,
/// NET-017): for every row the registry withdraws, whichever path withdrew
/// it, the box has ended, so its forwards are unbound and their connections
/// terminated ([`revoke_box_forwards`]). Each withdrawal is revoked on a
/// task of its own, so one box's retries never delay another's. A
/// revocation that gives up hands its withdrawal back, and the loop keeps it
/// for the gate's lifetime: the addresses it holds stay unregistrable while
/// a forward is still bound there. The loop ends when the registry is gone.
async fn revoke_on_row_withdrawal(
    mut withdrawn: tokio::sync::mpsc::UnboundedReceiver<RowWithdrawal>,
    switch_sock: PathBuf,
    forwards: Arc<PublishedForwards>,
    replies: ReplyTables,
) {
    let mut revocations = JoinSet::new();
    let mut stranded: Vec<RowWithdrawal> = Vec::new();
    loop {
        tokio::select! {
            next = withdrawn.recv() => {
                let Some(withdrawal) = next else {
                    break;
                };
                revocations.spawn(revoke_box_forwards(
                    switch_sock.clone(),
                    Arc::clone(&forwards),
                    replies.clone(),
                    withdrawal,
                    &UNBIND_RETRY_BACKOFF,
                ));
            }
            Some(done) = revocations.join_next(), if !revocations.is_empty() => {
                if let Ok(Some(held)) = done {
                    stranded.push(held);
                }
            }
        }
    }
    while let Some(done) = revocations.join_next().await {
        if let Ok(Some(held)) = done {
            stranded.push(held);
        }
    }
}

/// Unbinds every forward the gate applied at the withdrawn box's switch
/// address, then terminates the connections they still carry. Returns the
/// withdrawal when it gave up with a forward still bound, so the caller can
/// keep holding its addresses; `None` once every forward is unbound.
///
/// A declared port's forward is the host's to hold until the box stops:
/// the gate refuses any withdrawal of it the guest asks for (NET-081's
/// withdrawal rule), so the host unbinds it here, at box end. A runtime
/// publish the guest did not retract before the box ended comes down the
/// same way. Each unbind ends the reply-flow records its publication
/// opened, as an applied retraction does in [`relay_control`].
///
/// An unexpose that fails leaves its forward in the ledger, and the next
/// pass retries it after the next wait in `backoff`. A switch that answers
/// it was not bound counts as unbound: the goal state holds. The
/// withdrawal, and with it the hold on the box's addresses, is kept until
/// every forward is unbound ([`RowWithdrawal`]), so no new box is
/// registered at an address an old forward still serves.
///
/// The order is the one the in-guest revocation keeps, turned around for
/// the host's side of it: the listeners close first, so no new connection
/// arrives after the snapshot of the connections to end. Then each tracked
/// connection gets a reset from the box's address, written into the switch
/// over a frame connection of the gate's own ([`terminate_flows`]).
///
/// Every step logs one line, so a bundle's daemon log tail shows each
/// forward's unbind beside its bind.
async fn revoke_box_forwards(
    switch_sock: PathBuf,
    forwards: Arc<PublishedForwards>,
    replies: ReplyTables,
    withdrawal: RowWithdrawal,
    backoff: &'static [Duration],
) -> Option<RowWithdrawal> {
    let switch_addr = withdrawal.switch_addr();
    let addr = switch_addr.octets();
    let mut retries = backoff.iter();
    let mut attempt = 1usize;
    loop {
        unbind_pass(&switch_sock, &forwards, &replies, addr, attempt).await;
        let flows = forwards.flows.take_at(addr);
        let still_bound = forwards.published_at(addr);
        if still_bound.is_empty() {
            // Every forward is unbound: the addresses are free for a new box
            // before the resets go out, which reuse no longer depends on.
            drop(withdrawal);
            terminate_flows(&switch_sock, switch_addr, &flows).await;
            return None;
        }
        terminate_flows(&switch_sock, switch_addr, &flows).await;
        let Some(wait) = retries.next() else {
            for (listener, _, _) in &still_bound {
                tracing::error!(
                    %switch_addr,
                    local = %forward_revoke::listener_local(listener.0, listener.1),
                    attempts = attempt,
                    "gave up unbinding the box's forwarder at its row's withdrawal; it stays \
                     bound, and its addresses stay held against reuse"
                );
            }
            return Some(withdrawal);
        };
        tokio::time::sleep(*wait).await;
        attempt += 1;
    }
}

/// One pass over the forwards the ledger still holds at `addr`: an unexpose
/// each, and the ledger entry and the reply-flow records dropped for each
/// that is no longer bound. A failure is logged and left for the next pass.
async fn unbind_pass(
    switch_sock: &std::path::Path,
    forwards: &PublishedForwards,
    replies: &ReplyTables,
    addr: [u8; 4],
    attempt: usize,
) {
    let switch_addr = Ipv4Addr::from(addr);
    for (listener, inside, proto) in forwards.published_at(addr) {
        let local = forward_revoke::listener_local(listener.0, listener.1);
        let outcome = match forward_revoke::protocol_name(proto) {
            Some(protocol) => {
                forward_revoke::unexpose(
                    switch_sock,
                    &local,
                    protocol,
                    forward_revoke::REVOKE_TIMEOUT,
                )
                .await
            }
            // A protocol the switch has no spelling for was never bound.
            None => Ok(forward_revoke::Unexposed::NotBound),
        };
        match outcome {
            Ok(unexposed) => {
                if forwards.note_unbound_at(listener, addr)
                    && !forwards.still_published(addr, inside, proto)
                {
                    replies.end_port_at(addr, proto, inside);
                }
                tracing::info!(
                    %switch_addr,
                    %local,
                    proto,
                    attempt,
                    already_unbound = unexposed == forward_revoke::Unexposed::NotBound,
                    reason = "box ended",
                    "unbound the box's forwarder at its row's withdrawal"
                );
            }
            Err(error) => tracing::warn!(
                %switch_addr,
                %local,
                proto,
                attempt,
                %error,
                "unbinding the box's forwarder at its row's withdrawal failed; it stays in \
                 the ledger for a retry"
            ),
        }
    }
}

/// Resets `flows`, the connections the withdrawn box's forwards carried,
/// at the switch ([`forward_revoke::inject`]), and logs the outcome.
async fn terminate_flows(
    switch_sock: &std::path::Path,
    switch_addr: Ipv4Addr,
    flows: &[(forward_revoke::FlowKey, forward_revoke::FlowTail)],
) {
    if flows.is_empty() {
        return;
    }
    match forward_revoke::inject(
        switch_sock,
        CONNECT_REQUEST,
        flows,
        forward_revoke::REVOKE_TIMEOUT,
        forward_revoke::CHALLENGE_WINDOW,
    )
    .await
    {
        Ok(challenges_answered) => tracing::info!(
            %switch_addr,
            terminated = flows.len(),
            challenges_answered,
            reason = "box ended",
            "terminated the connections the box's forwarders carried"
        ),
        Err(error) => tracing::warn!(
            %switch_addr,
            connections = flows.len(),
            %error,
            "terminating the connections the box's forwarders carried failed"
        ),
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
    // The protocol the request publishes or retracts in: the runtime half
    // of each row is keyed on (port, protocol), so only the runtime ports
    // recorded under this protocol admit it. A zone-add carries no port.
    let request_proto = match verb {
        ControlVerb::Expose => published_protocol(body),
        ControlVerb::Unexpose => retracted_protocol(body, forwards),
        ControlVerb::DnsAdd => None,
    };
    let Some(switch_rows) = switch_rows_of(&rows, request_proto, &mut dictionary) else {
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
    // A publish at an address a withdrawn box's revocation still holds is
    // refused before it is decided: the revocation unbinds every forward
    // the ledger holds at that address, so a forward bound there now would
    // be unbound with the old box's. A retraction is still decided: it
    // takes a forward away, never adds one.
    if !matches!(verb, ControlVerb::Unexpose) && table.revocation_pending(request.switch_addr()) {
        return Err(RefusedRequest {
            rule: REVOKING_ADDRESS_RULE,
            addr: Some(request.switch_addr()),
            what: None,
            reason: "a withdrawn box's revocation still holds this address; the host is \
                     unbinding that box's forwards"
                .to_string(),
        });
    }
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
///
/// The runtime half of each row is the runtime ports recorded under
/// `request_proto` (NET-138): the row records (port, protocol) pairs, and
/// the decision's records carry port numbers only, so the protocol is
/// applied here — a port admitted for udp never admits a tcp publish at the
/// same number. `None` (a zone-add, or a protocol the client does not spell)
/// carries no runtime port.
fn switch_rows_of(
    rows: &[Arc<BoxRecord>],
    request_proto: Option<u8>,
    dictionary: &mut Vec<String>,
) -> Option<Vec<SwitchRow>> {
    let mut seen: HashMap<String, u8> = HashMap::new();
    let mut switch_rows = Vec::with_capacity(rows.len());
    for record in rows {
        let own = crate::net::answerer::canonical_box_name(record.name());
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
        // The row's admitted set for the publish decision (NET-138): the
        // ports its declaration named plus the runtime ports the grant
        // recorded — the set a publish at its address is admitted by, so a
        // port the in-VM daemon reported inside the grant reaches the box
        // through the gate for as long as the row holds it. The runtime
        // half rides beside as the retraction's own set: a retraction of a
        // runtime-published port is applied, while a declared port's
        // forward never is (the declaration is not the box's runtime fact
        // to retract).
        let runtime = match request_proto {
            Some(egress::IPPROTO_TCP) => record.runtime_port_numbers_in(sessions::IpProto::Tcp),
            Some(egress::IPPROTO_UDP) => record.runtime_port_numbers_in(sessions::IpProto::Udp),
            _ => Vec::new(),
        };
        let mut ports = record.admitted_ports().to_vec();
        ports.extend(runtime.iter().copied());
        switch_rows.push(
            SwitchRow::of(record.switch_addr().octets(), ports, names).with_published(runtime),
        );
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
                 creator-side registration that supplies it. No row's withdrawal \
                 names this address, so a forward published here is never unbound \
                 by the host at its box's end: it stays bound until the switch \
                 restarts (a known leak of the interim)",
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
/// The gate still reads the inside end, at the application rather than the
/// decision ([`published_inside`], filed per applied publish in the ledger):
/// it is the port every client's dial toward the box arrives at, so it is
/// the one the reply-flow recording is bounded by — the same inside ends the
/// in-guest relay's own recording decides by, held where the host can read
/// them without a wire change.
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
    let Ok(port) = port.parse::<u16>() else {
        return Err(());
    };
    // Only the client's own spelling: the switch keys a forward by the
    // `local` string, and the box's end unexposes by the spelling the
    // ledger renders ([`forward_revoke::listener_local`]). A padded port
    // would publish a forward that spelling cannot name, and so one the
    // box's end could not unbind.
    if forward_revoke::listener_local(addr.octets(), port) != local {
        return Err(());
    }
    Ok((addr.octets(), port))
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

/// The inside port an expose's forward dials — its `remote`'s port — for the
/// publish ledger's other half: the end of the mapping no registration wire
/// carries, the port the box's own declaration listens on and every client's
/// dial toward the box arrives at, read from the same body the decision
/// admitted the listener of ([`summarize_expose`] parses it for the address it
/// keys the publish at; the port is the reply-flow recording's bound, named
/// per applied publish in [`PublishedForwards::note_published`]). `None` for
/// a body that does not parse — one the decision already refused, which is
/// never applied and never noted.
fn published_inside(body: &[u8]) -> Option<u16> {
    host_port(
        &serde_json_lenient::from_slice::<ExposeBody>(body)
            .ok()?
            .remote,
    )
    .map(|(_, port)| port)
}

/// The protocol a publish names — the client's own two spellings, as the
/// numbers the reply-flow records are keyed by — read from the same body the
/// decision admitted, and noted in the ledger beside the publish's
/// attribution ([`PublishedForwards::note_published`]): the records are keyed
/// by protocol and port together, so the retraction ends
/// ([`ReplyTables::end_port_at`]) the pair the publish opened them at, under
/// the protocol the ledger holds rather than the one the retraction spells.
/// `None` for a body that does not parse or a protocol the client does not
/// spell — one the decision already refused, which is never applied.
fn published_protocol(body: &[u8]) -> Option<u8> {
    let protocol = serde_json_lenient::from_slice::<ExposeBody>(body)
        .ok()?
        .protocol;
    match protocol.as_str() {
        "tcp" => Some(egress::IPPROTO_TCP),
        "udp" => Some(egress::IPPROTO_UDP),
        _ => None,
    }
}

/// The protocol a retraction withdraws in: the one the ledger noted for the
/// publish of the listener the retraction names — the protocol the
/// publication was applied under, not the one the retraction spells. `None`
/// for a body that does not parse or a listener no applied publish names —
/// a retraction the decision refuses on its own terms.
fn retracted_protocol(body: &[u8], forwards: &PublishedForwards) -> Option<u8> {
    let parsed = serde_json_lenient::from_slice::<UnexposeBody>(body).ok()?;
    let listener = loopback_listener(&parsed.local).ok()?;
    forwards.protocol_of(listener)
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

/// switch → guest on a control connection, untouched: the gate applies no
/// policy on this leg — bytes flow as they came. It reads one thing on the
/// way through, the answer's status code, into `status`: a publish the
/// switch refused takes its ledger note back ([`relay_control`]). A frame
/// connection does not use it: its ingress is [`relay_switch_frames_to_guest`],
/// which reads the DNS replies through, and everything else about the two
/// legs is the same — nothing is decided, nothing is held back.
async fn copy_switch_to_guest(
    mut switch: OwnedReadHalf,
    mut guest: OwnedWriteHalf,
    status: Arc<OnceLock<u16>>,
) -> io::Result<()> {
    let mut head = Vec::new();
    let mut chunk = [0u8; CONTROL_READ];
    loop {
        let n = switch.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        let read = chunk.get(..n).unwrap_or_default();
        if status.get().is_none() && head.len() < MAX_STATUS_LINE {
            head.extend_from_slice(read);
            if let Some(code) = status_code(&head) {
                let _set = status.set(code);
            }
        }
        guest.write_all(read).await?;
    }
}

/// How much of the switch's answer the control relay reads for its status
/// line ([`copy_switch_to_guest`]).
const MAX_STATUS_LINE: usize = 256;

/// The status code of an HTTP answer's head, once its status line is whole.
fn status_code(head: &[u8]) -> Option<u16> {
    let end = head.iter().position(|&byte| byte == b'\n')?;
    std::str::from_utf8(head.get(..end)?)
        .ok()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// switch → guest on an upgraded connection, framed and observed. Ingress is
/// not this gate's decision — what a box may receive is the target's ingress
/// policy, decided in the guest — so every frame flows onward verbatim, but
/// one class is read on the way through: a DNS reply the switch returned
/// toward a box, which the host-side DNS admission table ([`dns_pins`]) pins
/// from, so that the pins which decide that box's undeclared destinations are
/// the answers its own lookups received. The read never holds: a reply that
/// pins nothing — not from the box's resolver, not a name the row declared,
/// refused by the rebinding intersection — still reaches the box in full.
///
/// One class is *written*, not only read: the reply-flow records
/// ([`ReplyTables`], NET-040's answer half). A frame this leg delivers toward
/// a registered box, at the inside port one of the box's applied publishes
/// dials — the port every client's dial toward the box arrives at, the end no
/// registration wire carries — is recorded as that box's inbound flow, the
/// one thing that lets the box answer it back through the gate, and at the
/// box's cap the new flow is refused, the one ingress refusal this gate
/// makes: the frame is not written on and the client's connect fails, while
/// the recorded flows keep refreshing.
///
/// The framing mirrors the egress leg's ([`relay_frames_to_switch`]): the
/// same two-byte little-endian length claim, the same zero-length skip, and
/// the same refusal of a claim past the maximum — the switch is the side
/// this gate fronts, not the side it contains, but a claim that would overrun
/// the buffer still points at a peer that cannot be trusted to frame
/// honestly, so the leg ends rather than read past it.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the `n > frame.len()` rejection above"
)]
async fn relay_switch_frames_to_guest(
    mut switch: OwnedReadHalf,
    mut guest: OwnedWriteHalf,
    table: BoxTable,
    pins: dns_pins::DnsPins,
    replies: ReplyTables,
    limiter: Arc<DropLimiter>,
    forwards: Arc<PublishedForwards>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; max_frame()];
    loop {
        match switch.read_exact(&mut len_buf).await {
            // The count is the buffer's length by construction; only the
            // error half carries information.
            Ok(_) => {}
            // A clean close of the switch ends the leg without error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        if n == 0 {
            // A zero-length claim carries no frame; skip the claim rather
            // than read past it.
            continue;
        }
        if n > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switch frame length {n} exceeds max {}", frame.len()),
            ));
        }
        switch.read_exact(&mut frame[..n]).await?;
        // NET-040's answer half, this gate's recording half: one frame this
        // leg is about to deliver toward a registered box, at the inside
        // port one of the box's applied publishes dials, is the one thing
        // that opens a reply-flow record for it — a bare SYN over TCP, the
        // first datagram over UDP, never a mid-stream segment, and never a
        // frame the box sent (the egress leg's lookup never inserts) — and
        // at the box's cap the new flow is refused here, toward the client:
        // the frame is not written on, the connect fails, the refusal is
        // counted and said, and the flows already recorded keep refreshing.
        //
        // The port is the publish's inside end, not the row's: the row's
        // declared ports are the external ones, the host-side listeners its
        // registration named, and no frame ever arrives at the box carrying
        // one — a client's dial reads the mapping the other way, at the
        // internal port the box listens on, the end the registration wire
        // never carried. Bounding the recording by the row's ports is what
        // dropped a published port's answers on this gate's own lane: no
        // frame matched, so no flow recorded, so the box's reply fell to its
        // egress rules and died there. The ledger the gate itself applied
        // the publish through holds both ends, and the ingress leg reads the
        // bound from it — a port a live publish dials is one the box's
        // ingress published, the same fact the in-guest relay's recording
        // decides by.
        //
        // The parse is the egress leg's own shape — the same allocation-free,
        // bounds-checked header read — and the row and port checks narrow
        // before the table's lock is taken, so only a frame delivered to a
        // published port of a registered box costs the table a word. It sits
        // ahead of the DNS observation below because a frame the gate refuses
        // is not delivered, and nothing that was not delivered may be
        // observed as though it had been.
        //
        // A TCP frame delivered there is also noted in the forwarded-flow
        // table: the connection it belongs to rides one of the box's
        // forwards, and the box's end resets it ([`revoke_box_forwards`]).
        if let Some(pkt) = dns_pins::parse_ipv4_l4(&frame[..n])
            && let Some(record) = table.by_source(pkt.dst.ip().octets())
            && forwards.inside_published(record.switch_addr().octets(), pkt.dst.port())
        {
            // NET-134's ingress arm: the box egress proxy answers and never
            // opens toward a box, so a bare SYN from its address to a
            // published inside port has no legitimate origin. Dropping the
            // opening packet here — before any observation or delivery —
            // keeps the proxy's address from planting an inbound flow toward
            // a box at all. Only opening packets are dropped: SYN-ACKs and
            // ACKs the proxy sends back to the box on a credentialed dial
            // still reach it untouched.
            let proxy = table.subnet().box_egress_proxy_address().octets();
            if pkt.src.ip().octets() == proxy
                && pkt.proto == egress::IPPROTO_TCP
                && pkt.tcp_flags & egress::TCP_SYN != 0
                && pkt.tcp_flags & egress::TCP_ACK == 0
            {
                limiter.warn_proxy_opening(
                    record.switch_addr().octets(),
                    record.name(),
                    pkt.dst.port(),
                );
                continue;
            }
            let now = Instant::now();
            if matches!(
                replies.observe_delivered(&record, &pkt, &limiter, table.subnet(), now),
                Some(egress::InboundFlow::RefusedAtCap)
            ) {
                continue;
            }
            if let Some(segment) = forward_revoke::parse_tcp_segment(&frame[..n]) {
                forwards.flows.observe_toward_box(&segment, now);
            }
        }
        // The pre-check is three comparisons; the parse it guards is the one
        // that bounds-checks the datagram before the table reads a word of it.
        if dns_pins::is_ipv4_udp(&frame[..n])
            && let Some((pkt, datagram)) = dns_pins::udp_datagram(&frame[..n])
        {
            pins.observe_reply(&table, &pkt, datagram, &limiter, Instant::now());
        }
        // One combined write keeps the length prefix and the frame together
        // even if the guest closes between two writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&frame[..n]);
        guest.write_all(&framed).await?;
    }
}

/// guest → switch: the frame relay's loop, fed by the relay's attribution,
/// which its caller ([`relay_frames`]) files after whichever relay leg ends
/// first: read one length-framed Ethernet frame, decide it against the
/// host-side table ([`gate_verdict`]), and write the frame on only when it is
/// admitted. A dropped frame is simply not written on — nothing is sent back
/// toward the guest either; a drop is not a reset (NET-062) — and its class
/// says so once per source address per rule per interval, so a flood inside
/// the VM produces a steady, readable account of what the host is dropping
/// rather than a log flood.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the `n > frame.len()` rejection above"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the two socket halves, the table, the DNS admission table, the reply-flow \
              tables, the baseline, the limiter, the publish ledger and the attribution \
              are each a distinct input to every frame the loop decides; grouping them \
              would name the bundle without naming the members"
)]
async fn relay_frames_to_switch(
    guest: &mut Prefixed<OwnedReadHalf>,
    switch: &mut OwnedWriteHalf,
    table: &BoxTable,
    pins: &dns_pins::DnsPins,
    replies: &ReplyTables,
    baseline: &NodePlaneBaseline,
    limiter: &DropLimiter,
    forwards: &PublishedForwards,
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
        // The frame's own L4 addressing, for the pin arm's flow retention: the
        // shared summary carries the destination and its port, not the source
        // port or the TCP flags a flow's identity and end are read from, so
        // the table's parse supplies them — the same allocation-free,
        // bounds-checked read the in-VM relay's is.
        let l4 = dns_pins::parse_ipv4_l4(&frame[..n]);
        let admitted = match gate_verdict(&summary, l4.as_ref(), table, baseline, pins, replies) {
            Ok(admitted) => admitted,
            Err(GateDrop::SwitchControlSurface { src, dst_port }) => {
                limiter.warn_switch_surface(src, dst_port);
                continue;
            }
            Err(GateDrop::Infrastructure { src, dst, dst_port }) => {
                limiter.warn_infrastructure(src, dst, dst_port);
                continue;
            }
            Err(GateDrop::ProxyLane { src, dst, dst_port }) => {
                // The plan's diagnostics line wants the refusal to name the
                // box, not only its address: the row the frame's source
                // resolved to carries the name, when one did. The binding
                // keeps the row alive for the borrow — and with no row, the
                // address the line already names is all the identity there
                // is.
                let record = table.by_source(src);
                let name = record.as_deref().map(BoxRecord::name);
                limiter.warn_proxy_lane(src, dst, dst_port, name);
                continue;
            }
            Err(GateDrop::UnregisteredSource { src }) => {
                // The one drop whose line the gate's own ledger can point a
                // host at a remedy through: an applied switch request that
                // named the address — a port publish or only a zone name — is
                // the host-observable fact that a live namespace holds the
                // lease — the box predates host registration, so its line
                // says to restart it. A source no request named takes the
                // generic line, and both drop the frame exactly the same
                // way: the request informs the line, never the verdict,
                // and the gate registers no box from what the guest says it
                // holds.
                if forwards.lease_live_at(src) {
                    limiter.warn_live_lease(src);
                } else {
                    limiter.warn_unregistered(src);
                }
                continue;
            }
            Err(GateDrop::Verdict(reason @ DropReason::UndeclaredSubnet { dst, .. })) => {
                // The row's own rules refused the destination, and the line
                // names it beside the source and the rule: the destination
                // address and the port the frame gave it, read off the frame
                // the reason's own shape refuses — so a bundle's reader learns
                // which reach was refused without cross-reading the rows.
                limiter.warn_undeclared_subnet(
                    summary.source(),
                    dst,
                    summary.destination_port(),
                    reason.rule(),
                );
                continue;
            }
            Err(dropped) => {
                limiter.emit(summary.source(), dropped.rule());
                continue;
            }
        };
        // Whatever admitted the frame — the baseline set, a row's own rules
        // or a declared lane — the address it came from was live traffic on
        // this connection, and this connection's end retires it. The node
        // plane's own address is the one exception: the row that decides its
        // frames is the host's own registration for the VM's lifetime
        // ([`BoxRegistry::register_node_namespace`], filed once at boot),
        // not a box's row that goes with its shuttle connection (NET-133),
        // and nothing would ever give the address its reach back — the plan
        // keeps the node's address outside the lease run the gate drops
        // unregistered sources in. So the drainer must never see it: one
        // relay's end retiring the node's row would leave the daemon
        // frameless and unpublishable for the rest of the VM's life, over a
        // shuttle close its control path rode out.
        let src = match admitted {
            GateAdmit::Baseline | GateAdmit::Row | GateAdmit::ProxyLane => summary.source(),
        };
        if let Some(src) = src
            && src != baseline.node_addr()
            && !attributed.contains(&src)
        {
            // The row's switch address is quarantined at its withdrawal
            // from here on: this connection may now key state by it.
            table.mark_attributed(src);
            attributed.push(src);
        }
        // The box's DNS datagram, read once for both checks below: only for
        // a UDP frame headed to DNS's port — UDP is most of a box's traffic
        // and DNS a sliver of it — and only for a frame the gate admitted.
        let dns = if dns_pins::is_ipv4_udp(&frame[..n])
            && l4.as_ref().is_some_and(|l4| l4.dst.port() == RESOLVER_PORT)
        {
            dns_pins::udp_datagram(&frame[..n])
        } else {
            None
        };
        // NET-141's deny-all case, decided here for own-address rows: a
        // deny-all box's query that names anything outside the box zone (or
        // asks a zone name for anything but A, or does not parse as a
        // standard query) is dropped by not being written on — silently
        // toward the guest, like every drop here — and said once per box per
        // name per interval. Before the write, so no resolver beyond the box
        // ever sees the name.
        if let Some((query, datagram)) = &dns
            && let Some(refusal) = dns_pins::deny_all_refusal(table, query, datagram)
        {
            limiter.warn_deny_all_query(&refusal);
            continue;
        }
        // One combined write keeps the length prefix and the frame together
        // even if the switch closes between two writes.
        let mut framed = Vec::with_capacity(2 + n);
        framed.extend_from_slice(&(n as u16).to_le_bytes());
        framed.extend_from_slice(&frame[..n]);
        switch.write_all(&framed).await?;
        // A box's segment on a connection one of its forwards carries moves
        // the sequence number a reset at its end is built at. The table
        // updates only a connection the switch's side opened, so any other
        // TCP frame costs one lookup and records nothing.
        if l4
            .as_ref()
            .is_some_and(|l4| l4.proto == egress::IPPROTO_TCP)
            && let Some(segment) = forward_revoke::parse_tcp_segment(&frame[..n])
        {
            forwards.flows.observe_from_box(&segment, Instant::now());
        }
        // The reply matching's other half: the box's own DNS query, one the
        // gate just admitted to the switch, is recorded as that box's
        // outstanding question, so the reply that answers it is the only kind
        // that can ever pin (the question, the id and the port the query left
        // from — [`dns_pins::DnsPins::observe_query`]). The pre-check is the
        // ingress leg's own shape: UDP is most of a box's traffic and DNS a
        // sliver of it, so the datagram is read only for a frame headed to
        // the resolver's port — and only for a frame the gate admitted, which
        // is why this sits after the write.
        if let Some((query, datagram)) = dns {
            pins.observe_query(table, &query, datagram, Instant::now());
        }
    }
}

/// The phase the egress default's rollout is at — the same cutover shape the
/// guest's own egress-default rollout
/// ([`sessions::EGRESS_DEFAULT_PHASE`]) models: a named phase, read by the
/// decision, flipped by one constant.
///
/// Two postures this module carries, one unconditional and one phased, and
/// the phase governs only the second: the frame-level drop of a source no row
/// holds is unconditional (NET-085, T89 #1925) — no phase reaches
/// [`gate_verdict`], so a source the table does not publish never leaves the
/// VM whatever this constant says — while a box's *declared* egress is the
/// phased thing: an undeclared own-address box's default, the gate's handling
/// of a row with no egress section (an absent section still allows all while
/// announced) and the publish decision a control request is decided by
/// through [`Self::into_sessions_phase`], are both the egress default's, and
/// the two halves read this one constant so neither can drift ahead of the
/// other. T66 (#1711) — the creator-side registration that supplies each
/// box's row before its first frame — is the change that flips it.
///
/// The named half it still governs: under [`UnregisteredSourcePhase::Announced`],
/// the arm this build ships, a publish at an in-plan address no row holds is
/// applied as the interim's — the teardowns of publications whose rows are
/// still to come are the ones that must work — while
/// [`UnregisteredSourcePhase::InForce`] binds the deny-all default: only a
/// published namespace's own records publish at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnregisteredSourcePhase {
    /// The coming default is announced, not yet binding: an undeclared box's
    /// absent egress section still allows all, and a publish at an in-plan
    /// address no row holds is applied under the interim, named on its own
    /// rate-limited line.
    Announced,
    /// The default binds: a row with no egress section reaches nothing
    /// outside itself, and only a published namespace's own records
    /// publish.
    ///
    /// Constructed today only by the tests that pin the phase's other arm —
    /// the publish decision's, and the relay-level gate built with
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
    /// The phase as the value the gate's start-up line logs under
    /// `undeclared_box_default`: a host reads the egress default's own
    /// posture off the one line every boot writes, beside the unconditional
    /// `unregistered_sources` field, so a host running the interim can tell
    /// it is.
    fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::InForce => "in force",
        }
    }

    /// The same cutover, as the pure publish decision's own phase shape
    /// ([`EgressDefaultPhase`]): the publish half and the undeclared-row
    /// half read one phase, so T66's flip of [`UNREGISTERED_SOURCE_PHASE`]
    /// moves both at once and neither can drift ahead of the other.
    pub(crate) fn into_sessions_phase(self) -> EgressDefaultPhase {
        match self {
            Self::Announced => EgressDefaultPhase::Announced,
            Self::InForce => EgressDefaultPhase::InForce,
        }
    }
}

/// The phase this build ships: announced, because the rows the default needs
/// are not here to bind to. T66 (#1711) — the creator-side registration that
/// supplies each box's row before its first frame — is the change that flips
/// this constant, and this constant is the whole cutover: the publish
/// decision reads it
/// ([`UnregisteredSourcePhase::into_sessions_phase`]), the start-up line logs
/// it, and the tests pin both of its arms, so the flip is one line and
/// nothing else. Three things the flip does not touch: the frame-level drop
/// of an unregistered source, which reads no phase at all (NET-085, T89
/// #1925); what production can build — a production caller reaches
/// [`EgressGate::spawn`] and no other constructor, so the phase a shipped
/// gate runs is the phase this build ships — and the relay-level tests that
/// pin the in-force arm's publishes through [`EgressGate::spawn_with_phase`],
/// which are green before the flip and stay green after it, so T66's flip
/// has its proofs already standing rather than tests to rewrite.
pub(crate) const UNREGISTERED_SOURCE_PHASE: UnregisteredSourcePhase =
    UnregisteredSourcePhase::Announced;

// The host gate's phase and the guest daemon's (`sessions::EGRESS_DEFAULT_PHASE`)
// are one rollout: an undeclared own-address box is compiled under this
// constant on the host and under the guest's on its boot line. If only one
// flipped, the host could allow what the guest denies, and after an escape
// only the host side holds. The build refuses that split.
const _: () = assert!(
    matches!(
        (UNREGISTERED_SOURCE_PHASE, sessions::EGRESS_DEFAULT_PHASE),
        (
            UnregisteredSourcePhase::Announced,
            sessions::EgressDefaultPhase::Announced
        ) | (
            UnregisteredSourcePhase::InForce,
            sessions::EgressDefaultPhase::InForce
        )
    ),
    "flip both constants together: minvmd's UNREGISTERED_SOURCE_PHASE and \
     sessions::EGRESS_DEFAULT_PHASE are one egress-default rollout"
);

/// What the gate decided one frame's admission by: which of the three ways in
/// — the node-plane baseline set, a published namespace's own rules, or a
/// row's declared credentialed lane. A source the plan could have leased but
/// no row holds is none of these: it is dropped, unconditionally (NET-085),
/// and the relay says so on its own line.
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
    /// drop class the row's address rules cannot carry, the
    /// undeclared-destination one for a row that declared DNS hosts, is
    /// decided beside them by the host-side DNS admission table
    /// ([`crate::net::dns_pins`]), whose pins are the answers the box's own
    /// lookups received. The row's *ingress* earns admissions too: a frame
    /// whose five-tuple exactly reverses a live inbound flow this gate
    /// recorded at one of the box's published ports is the row's as well,
    /// decided by the reply-flow table ([`ReplyTables`]) ahead of every rule
    /// the row holds.
    Row,
    /// The frame named the Box Egress Proxy's listener — TCP to
    /// `bep_host::PROXY_PORT` at the proxy's address — and the source's row
    /// declared a credentialed upstream (NET-134): the one admission the
    /// row's compiled rules never made, because the proxy's listener is the
    /// lane's own infrastructure — reached by declaring the upstream, not by
    /// allowing an address — so a deny-all row's frame to the listener passes
    /// where the same frame anywhere else on the host does not. The lane is
    /// the row's own fact; nothing the guest says grants one, and nothing in
    /// it opens the address's other ports or protocols.
    ProxyLane,
}

/// The gate's reply-flow records (NET-040's answer half): one [`BoxReplies`]
/// entry per registered box the gate's ingress leg has delivered an opening
/// packet to, keyed by the row's switch address — the same key the gate
/// resolves every frame's source and destination through. Cheap to clone:
/// every clone shares the same entries, and the handle the gate holds is the
/// one its two legs and its verdict all read.
///
/// The two halves of the rule, both of them the shared [`egress::ReplyFlows`]
/// decision — the same type, timers and per-box cap the in-guest relay's table
/// holds, read from one place, so both gates hold one number:
///
/// * [`Self::observe_delivered`], the ingress leg's half, is the one place a
///   record is opened — run on a frame the leg is about to deliver toward a
///   registered box, at the inside port one of the box's applied publishes
///   dials ([`PublishedForwards::inside_published`], the end no registration
///   wire carries), so only a packet the host itself passed to the box, at
///   a port the box's own ingress published, can ever mint the admission a
///   reply rides on. A frame the box sent never reaches it, and the box's
///   own egress is a lookup, never an insertion.
/// * [`Self::reply_admits`], the verdict's half, admits a frame whose
///   five-tuple exactly reverses a live record — decided ahead of the
///   control-surface check and of every rule the row holds, so a box whose
///   egress declares nothing still answers the connections its published
///   port received, and the forwarder a host-published port rides, whose
///   dials arrive at the box NAT'd from the switch's own address, still
///   gets its answers back.
///
/// Entries go with the row's traffic, on the same event the DNS admission
/// table's do ([`Self::retire`], beside the withdrawal report that ends the
/// row, NET-133), so a re-attachment answers only the flows its own ingress
/// admits again — fail closed, until a client connects once more.
#[derive(Clone)]
pub(crate) struct ReplyTables {
    /// The shared state behind every [`ReplyTables`] clone.
    inner: Arc<ReplyInner>,
}

/// The per-gate state behind every [`ReplyTables`] clone.
struct ReplyInner {
    /// One entry per registered box the gate has recorded for, keyed by the
    /// row's switch address. Bounded by the plan's address run — an entry
    /// exists only for an address a row was published at — and bounded
    /// within by the shared per-box cap ([`egress::REPLY_MAX_FLOWS_PER_BOX`]),
    /// which is where a flood of inbound flows toward one box stops.
    boxes: Mutex<HashMap<[u8; 4], Arc<BoxReplies>>>,
}

/// One box's reply-flow records, and the once-per-box lines' state beside
/// them.
struct BoxReplies {
    /// The row the entry was built from: the registered box whose published
    /// ports the recorded flows arrived at. Held so a re-registration at the
    /// same address — a new record, a new declaration — is told apart from
    /// the entry the address holds, and judged against the declaration the
    /// flows' ports were published under.
    record: Arc<BoxRecord>,
    /// The box's reply-flow records: the shared table, with its windows and
    /// its per-box cap, behind the one lock a single decision takes.
    flows: Mutex<egress::ReplyFlows>,
    /// Whether the box's first-record line has been said.
    first_record: AtomicBool,
    /// Whether the table-filled line has been said.
    table_filled: AtomicBool,
}

impl BoxReplies {
    /// The entry for `record`: the shared table at the plan's own windows
    /// and cap, and both once-per-box lines still unsaid.
    fn new(record: &Arc<BoxRecord>) -> Self {
        Self {
            record: Arc::clone(record),
            flows: Mutex::new(egress::ReplyFlows::new()),
            first_record: AtomicBool::new(false),
            table_filled: AtomicBool::new(false),
        }
    }

    /// Claims the first-record line: `true` exactly once per box.
    fn claim_first_record(&self) -> bool {
        !self.first_record.swap(true, Ordering::Relaxed)
    }

    /// Claims the table-first-filled line: `true` exactly once per box, the
    /// first time an insert takes the table to its cap.
    fn claim_table_filled(&self) -> bool {
        !self.table_filled.swap(true, Ordering::Relaxed)
    }
}

impl ReplyTables {
    /// An empty table: entries appear when the ingress leg first delivers an
    /// opening packet toward a published box, and go when the row's shuttle
    /// connection ends.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ReplyInner {
                boxes: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The entry the row's address holds, read-only: `None` for a box no
    /// delivered packet has recorded for yet — the lookup the egress leg's
    /// half runs on every frame a row holds, which must never mint an entry
    /// of its own.
    fn entry_of(&self, src: [u8; 4]) -> Option<Arc<BoxReplies>> {
        self.inner
            .boxes
            .lock()
            .expect("the reply-flow table's lock is held only across one decision")
            .get(&src)
            .cloned()
    }

    /// The entry the row's address holds, built from `record` on first sight
    /// — the one place an entry is created, on a frame the gate is about to
    /// deliver — and rebuilt when a re-registration put a different record
    /// at the same address: the flows the old entry held belong to the ports
    /// the old declaration published, and the flows the new declaration may
    /// earn are not open yet.
    fn entry(&self, record: &Arc<BoxRecord>) -> Arc<BoxReplies> {
        let key = record.switch_addr().octets();
        let mut boxes = self
            .inner
            .boxes
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        if let Some(entry) = boxes.get(&key)
            && Arc::ptr_eq(&entry.record, record)
        {
            return Arc::clone(entry);
        }
        let entry = Arc::new(BoxReplies::new(record));
        boxes.insert(key, Arc::clone(&entry));
        entry
    }

    /// The ingress leg's half: what one frame the leg is about to deliver
    /// toward `record`'s box did to its reply-flow records. The leg calls
    /// this only for a frame at the inside port one of the box's applied
    /// publishes dials — the recording's bound, read from the publish
    /// ledger, the port every client's dial toward the box arrives at — so
    /// the frame that reaches here is one the box's own ingress published,
    /// and what opens, refreshes or refuses a record is the shared
    /// decision's alone. `Some(outcome)` is that classification, and of it
    /// only [`egress::InboundFlow::RefusedAtCap`] tells the caller not to
    /// deliver: the box's table is at its cap, the flow is refused *at
    /// ingress* — the frame is not written on, the client's connect fails —
    /// the refusal is counted and said, and the flows already recorded keep
    /// refreshing.
    ///
    /// The two lines a box's first record and first fill say — one per box,
    /// naming the box, its published port and its cap — are emitted here, at
    /// the table's own transitions, so a diagnostic bundle's daemon log tail
    /// reads a box whose replies were or were not being admitted (R2.7).
    ///
    /// A frame sourced from the switch subnet's Box Egress Proxy address
    /// records nothing: the decline comes before any record is consulted or
    /// minted. Of such frames the ingress leg never hands this an opening TCP
    /// packet (SYN set, ACK clear) — it drops that one before calling here
    /// ([`PROXY_OPENING_RULE`]) — while every other proxy-sourced frame, the
    /// proxy's answers to a box's dial included, is still delivered with only
    /// the reply-flow recording declined.
    /// A box on a credentialed lane does dial the proxy's listener
    /// (NET-134), but the proxy only answers: it never opens a connection
    /// toward a box, so a proxy-sourced opening packet at a box's published
    /// port has no legitimate origin, and the stream it
    /// would open must never become a reply flow the box could reverse-answer
    /// ([`gate_verdict`]'s reply-flow admit). Defense in depth — the
    /// reply-flow admit in [`gate_verdict`] itself never admits a frame to
    /// the proxy's address, whatever record exists, and leaves it to the
    /// lane arm; this decline keeps such a record from being minted at all.
    pub(crate) fn observe_delivered(
        &self,
        record: &Arc<BoxRecord>,
        pkt: &dns_pins::L4Packet,
        limiter: &DropLimiter,
        subnet: SwitchSubnet,
        now: Instant,
    ) -> Option<egress::InboundFlow> {
        if pkt.src.ip().octets() == subnet.box_egress_proxy_address().octets() {
            return None;
        }
        let entry = self.entry(record);
        let mut flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        let before = flows.len();
        let outcome = flows.observe_inbound(reply_tuple_of(pkt), pkt.tcp_flags, now);
        let recorded = usize::from(matches!(outcome, egress::InboundFlow::Recorded { .. }));
        note_flows_ended(
            record,
            before + recorded - flows.len(),
            "expired or closed by the client",
        );
        match outcome {
            egress::InboundFlow::Recorded { filled } => {
                tracing::debug!(
                    switch_addr = %record.switch_addr(),
                    namespace = %record.name(),
                    port = pkt.dst.port(),
                    client = %pkt.src,
                    live = flows.len(),
                    "recorded an inbound flow at the box's published port"
                );
                if entry.claim_first_record() {
                    tracing::info!(
                        switch_addr = %record.switch_addr(),
                        namespace = %record.name(),
                        port = pkt.dst.port(),
                        client = %pkt.src,
                        "recorded the box's first inbound flow at its published port"
                    );
                }
                if filled && entry.claim_table_filled() {
                    tracing::info!(
                        switch_addr = %record.switch_addr(),
                        namespace = %record.name(),
                        cap = flows.cap(),
                        "the box's reply-flow table has filled; new inbound flows are refused at the cap"
                    );
                }
            }
            egress::InboundFlow::RefusedAtCap => {
                limiter.warn_inbound_flow_refused(
                    record.switch_addr().octets(),
                    record.name(),
                    *pkt.src.ip(),
                );
            }
            egress::InboundFlow::Refreshed
            | egress::InboundFlow::Ended
            | egress::InboundFlow::Untracked => {}
        }
        Some(outcome)
    }

    /// The verdict's half: whether one frame `record`'s box sent reverses a
    /// live inbound flow this gate recorded — the exact-reverse rule, with
    /// the record's own end (a FIN or RST on the flow) read here too. `None`
    /// for an entry, or an entry built from another record at the same
    /// address, admits nothing: the frame stays with the row's own rules.
    pub(crate) fn reply_admits(
        &self,
        record: &Arc<BoxRecord>,
        pkt: &dns_pins::L4Packet,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.entry_of(record.switch_addr().octets()) else {
            return false;
        };
        if !Arc::ptr_eq(&entry.record, record) {
            return false;
        }
        let mut flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        let before = flows.len();
        let admits = flows.reply_admits(reply_tuple_of(pkt), pkt.tcp_flags, now);
        note_flows_ended(record, before - flows.len(), "expired or closed by the box");
        admits
    }

    /// Retires the entries of the boxes whose traffic the relay that ended
    /// carried — the same event that withdraws their rows and retires their
    /// DNS admission entries (the relay's attribution, filed beside the
    /// withdrawal report, NET-133), so a reply-flow record never outlives
    /// the connection its box's ingress rode. A re-attachment answers only
    /// what its own ingress admits again, fail closed until a client
    /// connects.
    pub(crate) fn retire(&self, sources: &[[u8; 4]]) {
        let mut boxes = self
            .inner
            .boxes
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        for src in sources {
            if let Some(entry) = boxes.remove(src) {
                let ended = entry
                    .flows
                    .lock()
                    .expect("the reply-flow table's lock is held only across one decision")
                    .len();
                note_flows_ended(&entry.record, ended, "the box's row was withdrawn");
            }
        }
    }

    /// Ends the box's records at one protocol and port — the records a
    /// publication's retraction takes with its publication
    /// ([`relay_control`]): they were opened only because the publish's
    /// forward dialed that port, so they end now, in the same step the
    /// ledger drops the publish's attribution, and not at the next sweep or
    /// the row's next end — the next frame the box sends back on one of them
    /// is decided by the rules, not by the record a publication that no
    /// longer stands opened. The retracted publish's inside port is the
    /// records' destination half, so the box's other published ports keep
    /// theirs ([`egress::ReplyFlows::end_port`], the shared decision, retains
    /// the records whose protocol or port differ), and a box no entry holds
    /// has nothing to end.
    pub(crate) fn end_port_at(&self, src: [u8; 4], proto: u8, port: u16) {
        let Some(entry) = self.entry_of(src) else {
            return;
        };
        let mut flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        let before = flows.len();
        flows.end_port(proto, port);
        note_flows_ended(
            &entry.record,
            before - flows.len(),
            "its publication was retracted",
        );
    }

    /// How many inbound flows the gate holds records for, across every box —
    /// the live-flow gauge a status surface reads beside the drop counters.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the status surface that reads it is a follow-up outside this gate; the \
                      count is the tables' own length, live in every build"
        )
    )]
    pub(crate) fn live_flows(&self) -> usize {
        let boxes: Vec<_> = self
            .inner
            .boxes
            .lock()
            .expect("the reply-flow table's lock is held only across one decision")
            .values()
            .cloned()
            .collect();
        boxes
            .iter()
            .map(|entry| {
                entry
                    .flows
                    .lock()
                    .expect("the reply-flow table's lock is held only across one decision")
                    .len()
            })
            .sum()
    }

    /// How many of the box's inbound flows have been refused at its
    /// reply-flow cap — the per-box counter a status surface reads, so a
    /// box whose clients' connects were refused reads so in the host
    /// daemon's own report. `None` for a box whose ingress has not been
    /// delivered to at all: there is no entry to read.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the status surface that reads it is a follow-up outside this gate; the \
                      counter is entry state, maintained at the refusal in every build"
        )
    )]
    pub(crate) fn refused_at_cap_of(&self, src: [u8; 4]) -> Option<u64> {
        let entry = self.entry_of(src)?;
        let flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        Some(flows.refused_at_cap())
    }

    /// How many inbound flows the box currently holds records for — the
    /// relay-level proofs' window onto the table, and nothing more: an entry
    /// exists only for a box the gate's ingress leg has delivered to, so
    /// `None` is itself an answer, the one the never-opened proofs read.
    #[cfg(test)]
    pub(crate) fn record_count_of(&self, src: [u8; 4]) -> Option<usize> {
        let entry = self.entry_of(src)?;
        let flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        Some(flows.len())
    }

    /// Shrinks the box's per-box cap — the window hook's twin, for the
    /// relay-level proof that a flood of inbound flows stops at the cap
    /// without holding a thousand records first.
    #[cfg(test)]
    pub(crate) fn shrink_cap_of(&self, record: &Arc<BoxRecord>, cap: usize) {
        let entry = self.entry(record);
        let mut flows = entry
            .flows
            .lock()
            .expect("the reply-flow table's lock is held only across one decision");
        flows.shrink_cap(cap);
    }
}

/// The debug line for `ended` of the box's inbound-flow records leaving its
/// table — a window that passed, a close, or a retraction — so a daemon log
/// at debug reads each recorded flow's end beside its recording.
fn note_flows_ended(record: &BoxRecord, ended: usize, why: &str) {
    if ended > 0 {
        tracing::debug!(
            switch_addr = %record.switch_addr(),
            namespace = %record.name(),
            ended,
            why,
            "ended inbound-flow records"
        );
    }
}

/// The reply-flow identity one L4 packet's addressing spells, in the
/// direction the packet itself traveled — the same key the in-guest relay's
/// table builds, so the shared decision's reverse lookup means the same thing
/// on both gates.
fn reply_tuple_of(pkt: &dns_pins::L4Packet) -> egress::FlowTuple {
    egress::FlowTuple::new(
        pkt.proto,
        pkt.src.ip().octets(),
        pkt.src.port(),
        pkt.dst.ip().octets(),
        pkt.dst.port(),
    )
}

/// The gate's admit-or-drop decision for one frame summary against the
/// host-side table (NET-081): pure — a function of the summary, the table,
/// the baseline set, the phase, the DNS admission table and the reply-flow
/// tables, nothing else — and deliberately separate from the relay loop that
/// applies it, the same discipline the shared verdict keeps.
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
/// explicit allowance excepted — and the pin arm a name-declaring row earns
/// for its undeclared destinations never reaches it. The order is the
/// contract: the reply-flow record, then the control surface, then the
/// source's attribution (a baseline-decided node frame, a row, or the phase's
/// unknown-source decision), then the infrastructure set, then the proxy
/// lane, then the row's rules, then the pin arm.
/// The reply-flow record never admits a frame to the proxy's address: such
/// a frame skips it and goes on down the order to the proxy lane arm, which
/// decides it by the row's lane declaration (NET-134).
///
/// The reply-flow record goes ahead of the control-surface check because the
/// answer to a host-published port's connection is a frame *to the gateway*:
/// the forwarder dials the box from the switch's own address, so the box's
/// answer names the switch as its destination — the very address the
/// control-surface rule refuses. The record is the one thing that tells the
/// two apart: it exists only for a flow this gate itself delivered toward a
/// port one of the box's applied publishes dials, and it admits only its
/// exact reverse, so a box reaching for the switch's API ports still finds
/// them refused, whatever it dials. Nothing else moves — the lease check the
/// shared verdict carries still governs every frame, and a destination no
/// record names keeps every drop it ever took.
///
/// One destination is decided beside the rules instead of refused outright:
/// the Box Egress Proxy's listener (NET-134), the third thing the frame's
/// destination is checked against after the source's routing. The proxy's
/// listener is a credentialed lane's infrastructure — a box reaches it by
/// declaring the upstream, not by allowing its address — so the listener,
/// TCP to `bep_host::PROXY_PORT`, is admitted for the one row that declared
/// the lane, whatever its compiled rules say about the frame
/// ([`GateAdmit::ProxyLane`]), and every other frame to the proxy's address
/// is refused under [`PROXY_LANE_RULE`], whatever the source: a row that
/// declared no upstream, a row that declared the lane but sent another
/// port or another protocol, neither of which the declaration ever opened,
/// and the node plane's baseline set, which holds the address for no
/// category. The lane arm sits after the attribution on purpose: it reads
/// the row the frame's source resolved to, so a frame wearing a source the
/// table does not hold is one of the two source refusals', and a frame to
/// the listener from an address no row owns never rides a lane it never
/// declared.
fn gate_verdict(
    summary: &FrameSummary,
    l4: Option<&dns_pins::L4Packet>,
    table: &BoxTable,
    baseline: &NodePlaneBaseline,
    pins: &dns_pins::DnsPins,
    replies: &ReplyTables,
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
    // NET-040's answer half: a frame whose five-tuple exactly reverses a live
    // inbound flow this gate's ingress leg recorded — the connection a
    // published port received, delivered by this gate itself — passes
    // without a single rule being consulted, the row's `deny_subnets` and
    // the infrastructure set included, because a destination the box's rules
    // refuse is what a reply to a published port *is*. The record admits its
    // exact reverse and nothing else: the box's next connection finds no
    // record, and no frame the box sends can open one, so a box cannot mint
    // this admission — it can only answer a flow a client's packet earned.
    // A frame no record admits stays exactly where it was, with every check
    // below deciding it as it always has.
    // A frame to the Box Egress Proxy's address is never a record's to
    // admit: the proxy only answers a lane's dial and never opens a flow
    // toward a box (NET-134), so no record can legitimately reverse to it,
    // and the frame goes on down the order to the lane arm below, which
    // decides it by the row's lane declaration.
    if let Some(pkt) = l4
        && summary.destination() != Some(table.subnet().box_egress_proxy_address().octets())
        && let Some(record) = table.by_source(src)
        && replies.reply_admits(&record, pkt, Instant::now())
    {
        return Ok(GateAdmit::Row);
    }
    // The switch's own address is a control surface, not a destination a
    // box's egress rules decide (design §4.1, §7.1). Every frame from a box
    // to the gateway — the address the resolver answers at, and the one
    // gvproxy's API listens on — is refused unless it is TCP or UDP to the
    // resolver's port, whatever the rows would say about the rest of the
    // frame: any other port, and any other protocol (ICMP has no
    // port to carve out by), points at the switch itself. A row's admitted
    // ports are no exception — they are the box's own ingress, what others
    // reach on the box's address through the switch's forwarders, and no
    // box-to-gateway flow at them exists. The check sits before the row's
    // decision, so no allow-all row can admit a frame at the switch's own
    // address, and it reads no phase at all, so it binds unchanged whatever
    // the egress default's rollout does.
    // The one frame this check never sees is the reply the record above
    // admitted: a forwarder's dial arrives at the box from the switch's own
    // address, so the box's answer to it names the gateway — and that
    // answer, the exact reverse of a flow this gate delivered toward the
    // box's published port, is not a reach for the control surface but the
    // half of a connection the host itself opened. The resolver carve-out
    // falls through to the decision behind this check — the row's own
    // rules — which still decides it, so the carve-out admits
    // exactly what it admitted before, and the refusal adds a ceiling
    // without moving any floor.
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
    // No namespace holds the source — NET-081's failure case, held
    // unconditionally, under no phase (NET-085, T89 #1925): an address no
    // namespace holds never leaves the VM, toward every destination alike,
    // the baseline set included, because nothing on the host bounds the
    // reach a frame from it would carry. Two classes, two rules, so a host
    // reading its log can tell them apart: an address outside the plan's
    // lease block is nobody's to wear — the plan never hands one out, so no
    // row will ever hold it — and stays rule 0's
    // ([`UNKNOWN_SOURCE_RULE`]); an address inside the run the plan hands
    // leases from is a lease the guest daemon's own allocator could have
    // minted — an own-address box's, whose row the creator-side registration
    // (T66, #1711) is the only thing that ever publishes, or a task
    // sandbox's, or an escapee's made-up one — and drops under its own rule
    // ([`UNREGISTERED_SOURCE_RULE`]), whose line can even name the remedy
    // when an applied switch request named the address as a box's own
    // ([`PublishedForwards::lease_live_at`], a live lease whose box
    // predates host registration). The relay picks the line; the drop is
    // the same either way, and no phase the gate was built under reaches it.
    let record = match table.by_source(src) {
        Some(record) => record,
        None if table.is_allocatable(src) => {
            return Err(GateDrop::UnregisteredSource { src });
        }
        None => return Err(GateDrop::UnknownSource { src }),
    };
    // The infrastructure deny set, decided for every row before the row's
    // own rules (design §5.3, NET-067): the host and the fabric, not
    // destinations — link-local and the metadata services in it, loopback,
    // the plane outside the node's own block, and RFC 1918 space the row's
    // `allow_subnets` does not cover. Decided here, between the source's
    // routing and the row's rules, so that no row admits it — an allow-all
    // row's `0.0.0.0/0` included, the CIDR-admitted direct-IP flow the set
    // names — and so that the pin arm below never sees it: an undeclared
    // destination inside the set is this drop, and no answer resolving into
    // it ever becomes a pin. Only a row the registry holds reaches this arm
    // now — the source check above returns before any other source — so the
    // set applies to every box-plane packet, and no row's rules concede the
    // fabric.
    // The host-alias refusal is a box row's alone: the node namespace's
    // row, keyed to the daemon's own address, carries the host-address
    // boxes' frames, whose `host.min.internal` resolves to the alias, and
    // keeps own-block local reach to it until the in-force baseline (which
    // returned above) decides the node plane.
    let box_row = src != table.subnet().daemon_ip().octets();
    if let Some(dst) = summary.destination()
        && infrastructure_destination(
            dst,
            table.subnet(),
            record.egress().allow_subnets(),
            box_row,
        )
    {
        return Err(GateDrop::Infrastructure {
            src,
            dst,
            dst_port: summary.destination_port(),
        });
    }
    // The Box Egress Proxy's listener, decided beside every rule (NET-134):
    // the proxy is a credentialed lane's infrastructure — the one host-side
    // listener a box reaches by declaring the upstream, never by allowing
    // its address — so this is the one destination whose admission the
    // frame rules cannot carry, decided from the row's own declaration the
    // way the DNS name dimension is. What the declaration opens is the
    // listener, one of §5.3's port-scoped openings: TCP to
    // `bep_host::PROXY_PORT`, the port the proxy's acceptor listens at read
    // from the stack that runs it, so the gate cannot drift from the
    // listener it guards, over the protocol of the acceptor the relay leg
    // pins too (`egress::PROXY_LISTENER_PROTOCOL`) — and the predicate
    // itself is the one function the relay leg decides the same
    // destination by (`egress::proxy_lane_admits`, handed the listener as
    // `egress::ProxyListener::at` builds it), so the two legs admit the
    // same frame or refuse it together by construction rather than by
    // parallel spellings of one triple. A row that declared the lane
    // is admitted here, whatever its rules would say about the address: a
    // deny-all row included, because the credentials the proxy redeems are
    // the lane's own and no egress rule of the box's says anything about
    // them. Everything else at the address is refused under the
    // box-to-host default-deny — a row that declared nothing (whatever its
    // rules would have allowed at the address: a declared allowance is not
    // a lane, the same way a `0.0.0.0/0` row admits no metadata service),
    // a row that declared the lane but sent another port or another
    // protocol, neither of which the declaration ever opened, and the node
    // row under the announced baseline, which is the allow-all the in-force
    // enumeration replaces.
    // The in-force baseline set needs no arm of its own: it never admits
    // the address for any category, so its compiled rules refuse the frame
    // where they refuse any undeclared destination.
    if let Some(dst) = summary.destination()
        && dst == table.subnet().box_egress_proxy_address().octets()
    {
        // minvmd is the one crate that sees both spellings of the listener's port.
        const _: () = assert!(egress::PROXY_LISTENER_PORT == switch::bep_host::PROXY_PORT);
        let listener = egress::ProxyListener::at(dst);
        if egress::proxy_lane_admits(record.declares_credentialed_upstream(), listener, summary) {
            return Ok(GateAdmit::ProxyLane);
        }
        return Err(GateDrop::ProxyLane {
            src,
            dst,
            dst_port: summary.destination_port(),
        });
    }
    // The namespace that holds the source decides its frames by its own
    // compiled rules — the shared verdict, unchanged, now made outside where
    // nothing inside can change it. One drop class the address rules cannot
    // carry is decided beside them, by the host-side DNS admission table
    // ([`crate::net::dns_pins`], the deciding copy NET-081 names): a row that
    // declared DNS hosts has a name-based admission no set of subnets
    // expresses, so the undeclared-destination drop such a row takes is
    // decided on the host against the answers the box's own lookups received
    // — admitted when a live pin names the frame's destination, or the flow
    // a pin established still holds it, and dropped when nothing does, under
    // the same window, cap and retention the in-VM precision copy applies
    // (both read them from one place). Deciding it here is the point of the
    // gate: the in-VM relay is whatever runs inside the VM, and the box still
    // reaches only the addresses its own answers named. Everything else
    // stays host-made, and a pin governs none of it: a denied destination,
    // an infrastructure destination (decided above, before this arm can see
    // it), an undeclared protocol, a foreign source, a family the verdict
    // reads no source from — the guest lifts none of those either, so the
    // host refusing them is parity, not pre-emption.
    match egress::verdict(summary, record.egress()) {
        FrameVerdict::Admit => Ok(GateAdmit::Row),
        FrameVerdict::Drop(reason)
            if matches!(reason, DropReason::UndeclaredSubnet { .. })
                && record.resolves_names()
                && pins.admits_frame(
                    &record,
                    summary.destination().unwrap_or_default(),
                    l4,
                    Instant::now(),
                ) =>
        {
            Ok(GateAdmit::Row)
        }
        FrameVerdict::Drop(reason) => Err(GateDrop::Verdict(reason)),
    }
}

/// Why the gate dropped a frame: the shared verdict's reason, or one of the
/// five classes the host table adds — a source address outside the plan's
/// lease block that no published namespace could ever hold (NET-081's
/// failure case), a source address inside the block no published namespace
/// holds (NET-085), a frame the switch's own address would have received on
/// a port nothing published answers, a frame headed into the infrastructure
/// deny set, and a frame headed to the Box Egress Proxy's address the lane
/// does not admit (NET-134).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateDrop {
    /// The shared frame verdict dropped it: the namespace's own rules, its
    /// lease check, or its family.
    Verdict(DropReason),
    /// The frame's source address belongs to no published namespace, and the
    /// plan never hands one out either: outside the run its address plan
    /// allocates leases from, so no row will ever be keyed by it
    /// ([`UNKNOWN_SOURCE_RULE`], rule 0's).
    UnknownSource {
        /// The source address no namespace holds.
        src: [u8; 4],
    },
    /// The frame's source address belongs to no published namespace but sits
    /// inside the run the plan allocates PTask leases from (NET-085): a lease
    /// the guest daemon's own allocator could have minted — an own-address
    /// box's, a task sandbox's, an escapee's made-up one — whose row the
    /// creator-side registration (T66, #1711) is the only thing that ever
    /// publishes. Dropped unconditionally, toward every destination, the
    /// baseline set included, whatever the egress default's phase
    /// ([`UNREGISTERED_SOURCE_RULE`]; a live lease at the address drops under
    /// [`UNREGISTERED_LIVE_LEASE_RULE`] instead).
    UnregisteredSource {
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
    /// The frame named the Box Egress Proxy's address and the lane does not
    /// admit it (NET-134): its source carries no credentialed lane, or the
    /// frame is headed somewhere at the address the declaration never
    /// opened — another port, another protocol. The listener alone is the
    /// lane's own, and it is not a destination any rules — rows' or the
    /// baseline set's — admit without one
    /// ([`PROXY_LANE_RULE`]).
    ProxyLane {
        /// The source address the frame wore.
        src: [u8; 4],
        /// The proxy's address on the switch, the destination refused.
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
            Self::UnregisteredSource { .. } => UNREGISTERED_SOURCE_RULE,
            Self::SwitchControlSurface { .. } => SWITCH_CONTROL_RULE,
            Self::ProxyLane { .. } => PROXY_LANE_RULE,
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
/// dropped it — `None` for a frame with no readable source — a DNS
/// refusal's source, rule and name, or, past
/// [`DROP_WARN_MAX_TRACKED_PAIRS`], the rule alone.
#[derive(Debug, Hash, PartialEq, Eq)]
enum DropKey {
    /// One source address under one rule: the two things the drop line names.
    Source(Option<[u8; 4]>, &'static str),
    /// One DNS refusal: the box whose resolution refused, the rule that
    /// refused the answer, and the name the box asked for — the three things
    /// the refusal line names, so one name's burst of refused answers is one
    /// line per rule while two names refusing under the same rule say so
    /// separately.
    Refusal([u8; 4], &'static str, String),
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
/// [`DROP_WARN_MIN_INTERVAL`], keyed by the things the line names — a
/// drop's two, the interim admit's, or a DNS refusal's three. Keyed per
/// source and per rule both, so one address's flood neither silences
/// another's single line nor merges two rules into one.
///
/// The window table is bounded at [`DROP_WARN_MAX_TRACKED_PAIRS`] — the
/// source address it keys by is the frame's own bytes, chosen by the guest,
/// and the guest is the side this gate exists to contain — so the throttling
/// cannot be turned into host-memory growth.
#[derive(Debug, Default)]
pub(crate) struct DropLimiter {
    last: Mutex<HashMap<DropKey, Instant>>,
}

impl DropLimiter {
    /// A fresh limiter that has never emitted for any source or rule.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The decision every line this limiter gates answers to, under whatever
    /// key names it: one window per key per interval, the same table, the
    /// same bound and the same flood fallback for drop, admit and refusal
    /// lines alike.
    fn decide(&self, key: DropKey, rule: &'static str, now: Instant) -> WarnDecision {
        let mut last = self
            .last
            .lock()
            .expect("the limiter's lock is held only across this lookup, never across a panic");
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
        self.decide(DropKey::Source(src, rule), rule, now)
    }

    /// The refusal arm of [`should_warn_at`](Self::should_warn_at): the same
    /// decision under the key that names the refused name — one line per box
    /// per name per rule per interval, so a box's one name refusing many
    /// answers says so once while two names refusing under one rule each say
    /// so. Split from [`warn_dns_refusal`](Self::warn_dns_refusal) for the
    /// same testability.
    fn should_warn_refusal_at(
        &self,
        src: [u8; 4],
        name: &str,
        rule: &'static str,
        now: Instant,
    ) -> WarnDecision {
        self.decide(DropKey::Refusal(src, rule, name.to_string()), rule, now)
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

    /// Emits the warning for one frame headed to the Box Egress Proxy's
    /// address that the lane does not admit (NET-134) — a source that
    /// carries no credentialed lane, or a frame at the address that is not
    /// the listener a lane opens: the same rate limit a drop's line answers
    /// to, keyed by the source and the rule, and naming the destination and
    /// the port the frame gave it — the line a host reads to learn which box
    /// was reaching for the proxy, the box named by the row that holds its
    /// source when one does, and the reason by the rule. Returns whether a
    /// line was written.
    fn warn_proxy_lane(
        &self,
        src: [u8; 4],
        dst: [u8; 4],
        dst_port: u16,
        box_name: Option<&str>,
    ) -> bool {
        match self.should_warn_at(Some(src), PROXY_LANE_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    destination = %Ipv4Addr::from(dst),
                    port = dst_port,
                    box = box_name,
                    rule_matched = PROXY_LANE_RULE,
                    "dropped a frame to the box egress proxy's address; the proxy's \
                     listener is a credentialed lane's infrastructure, and this box's \
                     declaration did not admit this frame",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = PROXY_LANE_RULE,
                    "dropped frames to the box egress proxy's address from more distinct \
                     source addresses than the gate keeps a window per source for; one line \
                     per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the drop's line for one frame whose source is an in-plan address
    /// no published namespace holds (NET-085): the same rate limit every
    /// drop's line answers to — one per source per interval — because a
    /// source no row holds drops on every frame it sends, and the point of
    /// the line is that a host can see the drop, not that it can be flooded
    /// by it. The line names the source and the rule, the two fields
    /// NET-081's observability asks of every drop line, so a host reads which
    /// in-plan address a namespace-less frame wore. Returns whether a line
    /// was written.
    fn warn_unregistered(&self, src: [u8; 4]) -> bool {
        match self.should_warn_at(Some(src), UNREGISTERED_SOURCE_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    rule_matched = UNREGISTERED_SOURCE_RULE,
                    "dropped a frame leaving the VM from an in-plan address no published \
                     namespace holds; nothing on the host bounds the reach a frame from \
                     it would carry",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = UNREGISTERED_SOURCE_RULE,
                    "dropped frames from more distinct unregistered addresses than the \
                     gate keeps a window per source for; one line per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the drop's line for one live lease no published namespace
    /// holds: a source an applied switch request named as a box's own
    /// ([`PublishedForwards::lease_live_at`]), so a namespace the guest
    /// daemon vouched for holds it, alive, while no row the registry holds
    /// is keyed by it — its box predates host registration (T66, #1711). The
    /// one unregistered source a host can do something about, and the line
    /// says so, naming the lease and the remedy, where the generic line
    /// ([`Self::warn_unregistered`]) names only the address. The same rate
    /// limit every drop's line answers to, keyed by the source and its own
    /// rule, so one address's two lines say their own things. Returns
    /// whether a line was written.
    fn warn_live_lease(&self, src: [u8; 4]) -> bool {
        match self.should_warn_at(Some(src), UNREGISTERED_LIVE_LEASE_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    rule_matched = UNREGISTERED_LIVE_LEASE_RULE,
                    "dropped a frame leaving the VM from a live lease no published \
                     namespace holds; the box predates host registration, so restarting \
                     it registers it (T66, #1711)",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = UNREGISTERED_LIVE_LEASE_RULE,
                    "dropped frames from more distinct live leases than the gate keeps a \
                     window per source for; one line per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the drop's line for one frame the row's own rules refused toward
    /// an undeclared subnet: the same rate limit every drop's line answers
    /// to, and naming the destination address and the port the frame gave
    /// it, beside the source and the rule — the line a host reads to learn
    /// which address a box reached for that its row never declared, and at
    /// which port, the way the infrastructure line names its destination.
    /// Returns whether a line was written.
    fn warn_undeclared_subnet(
        &self,
        src: Option<[u8; 4]>,
        dst: [u8; 4],
        dst_port: u16,
        rule: &'static str,
    ) -> bool {
        match self.should_warn_at(src, rule, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                let source =
                    src.map_or_else(|| "none".to_string(), |src| Ipv4Addr::from(src).to_string());
                tracing::warn!(
                    source = %source,
                    destination = %Ipv4Addr::from(dst),
                    // The frame summary reads 0 when the protocol carries no
                    // L4 port (ICMP, say): name that rather than a port 0.
                    port = %if dst_port == 0 { "none".to_string() } else { dst_port.to_string() },
                    rule_matched = rule,
                    "dropped a frame leaving the VM toward a subnet its rules do not \
                     declare",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = rule,
                    "dropped frames toward undeclared subnets from more distinct source \
                     addresses than the gate keeps a window per source for; one line per \
                     rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the mandated refusal for one DNS answer that resolved into a
    /// range the box may not reach (NET-067: the name and the answer say so):
    /// the same rate limit a drop's line answers to, keyed by the box, the
    /// name and the rule, in the shared refusal format — the same message and
    /// fields the in-VM gate's refusal line carries (`PolicyWarnLimiter`'s
    /// `warn_dns_refusal`), with `source` naming the box whose resolution
    /// refused, the way the drop lines here name the frame's source. One
    /// rate-limited line per refused answer is what the diagnostics ask for:
    /// a DNS box whose destination was refused reads so in a bundle.
    /// Returns whether a line was written.
    pub(crate) fn warn_dns_refusal(
        &self,
        src: [u8; 4],
        name: &str,
        answer: Ipv4Addr,
        rule: &'static str,
    ) -> bool {
        match self.should_warn_refusal_at(src, name, rule, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    name,
                    %answer,
                    rule_matched = rule,
                    "an allowed name resolved into a refused range",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = rule,
                    "allowed names resolving into refused ranges from more distinct boxes \
                     and names than the gate keeps a window for; one line per rule covers \
                     the rest",
                );
                true
            }
        }
    }

    /// Emits the warning for one deny-all box's DNS datagram the gate
    /// dropped ([`dns_pins::deny_all_refusal`]): the same rate limit a DNS
    /// refusal's line answers to, keyed by the box, the rule and the name,
    /// so one name's burst says so once per interval while two names each
    /// get their line — and a flood of distinct names folds into the rule's
    /// one shared line, at no memory past the limiter's bound. The line
    /// names the box (its address and namespace) and the name it asked.
    /// Returns whether a line was written.
    pub(crate) fn warn_deny_all_query(&self, refusal: &dns_pins::DenyAllRefusal) -> bool {
        let src = refusal.record.switch_addr().octets();
        match self.should_warn_refusal_at(src, &refusal.name, DENY_ALL_DNS_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                let query_type = refusal
                    .query_type
                    .map_or_else(|| "none".to_string(), |rtype| rtype.to_string());
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    namespace = refusal.record.name(),
                    name = refusal.name.as_str(),
                    query_type,
                    rule_matched = DENY_ALL_DNS_RULE,
                    "dropped a deny-all box's DNS query naming something outside the box \
                     zone at the host-side egress gate",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = DENY_ALL_DNS_RULE,
                    "dropped deny-all boxes' DNS queries for more distinct boxes and names \
                     than the gate keeps a window for; one line per rule covers the rest",
                );
                true
            }
        }
    }

    /// Emits the mandated refusal for one inbound flow the gate refused at a
    /// box's reply-flow cap (NET-040's answer half): the same rate limit a
    /// drop's line answers to, keyed by the box, the client whose connect was
    /// refused and the rule, so one client's burst of refused connects says so
    /// once while two clients refused under the same rule each get their line.
    ///
    /// What the line names is the half of the refusal a host reads a bundle
    /// for: which published box's port stopped admitting new flows and which
    /// client's connect failed at it — refused *at ingress*, so the client's
    /// connect fails rather than the box's session, while the flows already
    /// recorded keep refreshing and keep their replies admitted.
    /// Returns whether a line was written.
    fn warn_inbound_flow_refused(&self, src: [u8; 4], namespace: &str, client: Ipv4Addr) -> bool {
        let refused = client.to_string();
        match self.should_warn_refusal_at(src, &refused, INBOUND_FLOW_CAP_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    source = %Ipv4Addr::from(src),
                    namespace,
                    client = %client,
                    rule_matched = INBOUND_FLOW_CAP_RULE,
                    "refused an inbound flow at the box's reply-flow cap; the client's \
                     connect fails rather than the box's session",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = INBOUND_FLOW_CAP_RULE,
                    "refusing inbound flows at the reply-flow cap for more distinct clients \
                     and boxes than the gate keeps a window for; one line per rule covers \
                     the rest",
                );
                true
            }
        }
    }

    /// Emits the drop's line for one opening TCP packet from the Box Egress
    /// Proxy's address toward a box's published inside port
    /// ([`PROXY_OPENING_RULE`]): the same rate limit a drop's line answers
    /// to, keyed by the box's address and the rule — the source is always
    /// the proxy, so keying by it would fold every box into one window —
    /// and naming the box and the port. Returns whether a line was written.
    fn warn_proxy_opening(&self, box_addr: [u8; 4], namespace: &str, port: u16) -> bool {
        match self.should_warn_at(Some(box_addr), PROXY_OPENING_RULE, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                tracing::warn!(
                    destination = %Ipv4Addr::from(box_addr),
                    namespace,
                    port,
                    rule_matched = PROXY_OPENING_RULE,
                    "dropped an opening TCP packet from the box egress proxy's address \
                     toward a box's published port; the proxy only answers and never \
                     opens toward a box",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = PROXY_OPENING_RULE,
                    "dropped opening TCP packets from the box egress proxy's address toward \
                     more distinct boxes than the gate keeps a window per address for; one \
                     line per rule covers the rest",
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

    use super::{CONNECT_REQUEST, EgressGate, ReplyTables, UnregisteredSourcePhase};
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
    /// the gate admitted — and from which a test answers a box's DNS lookup,
    /// because the frames written here are what the gate's ingress leg
    /// observes; `log` captures what the gate has said; `table` is the gate's
    /// own view of the registry; `pins` is the gate's DNS admission table, the
    /// same instance the gate decides by.
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
        /// The gate's DNS admission table: the deciding copy of the one drop
        /// class a DNS-declaring row's address rules cannot carry. The same
        /// clone the gate holds, so a test reads its counters and the frame
        /// stream's decisions answer to the same pins.
        pub(crate) pins: crate::net::dns_pins::DnsPins,
        /// The gate's reply-flow tables (NET-040's answer half): the same
        /// clone the gate's relays decide by, so the reply proofs read the
        /// records the ingress leg holds and the counter the cap keeps,
        /// through the tables the frame stream itself decides by.
        pub(crate) replies: ReplyTables,
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

        // The gate's DNS admission table, built for the same plan the
        // registry's rows were compiled against — the same construction the
        // production gate is handed in [`crate::net`].
        let pins = crate::net::dns_pins::DnsPins::new(registry.subnet());
        // The gate's reply-flow tables, built the same way — empty, and
        // handed to the gate beside the pins so the reply proofs read the
        // very tables its relays decide by.
        let replies = ReplyTables::new();

        let gate = EgressGate::spawn_with_phase(
            gate_sock.clone(),
            switch_sock.clone(),
            registry.table(),
            pins.clone(),
            replies.clone(),
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
            pins,
            replies,
            gate_sock,
            switch_listener: listener,
            _dir: dir,
            _guard,
        }
    }

    /// [`gate_connected`] on a gate built through the production entry,
    /// [`EgressGate::spawn`]: the entry `crate::net` calls, which builds its
    /// own reply-flow tables and takes its phase from the shipped constant —
    /// so the frame stream this harness backs is decided by a gate no test
    /// parameter shaped, the entry a VM host actually runs. The harness's
    /// `replies` is an empty stand-in rather than the tables the gate's
    /// relays decide by, because `spawn` builds its own; a test that reads
    /// the gate's reply records builds with
    /// [`gate_connected_with_phase`] instead.
    pub(crate) async fn gate_connected_shipped(registry: BoxRegistry) -> GateHarness {
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

        // The gate's DNS admission table, built for the same plan the
        // registry's rows were compiled against — the same construction the
        // production gate is handed in [`crate::net`].
        let pins = crate::net::dns_pins::DnsPins::new(registry.subnet());

        let gate = EgressGate::spawn(
            gate_sock.clone(),
            switch_sock.clone(),
            registry.table(),
            pins.clone(),
            crate::net::baseline::NodePlaneBaseline::built_in(registry.subnet()),
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
            pins,
            // The production entry built its own; this one is the harness's
            // empty stand-in, consulted by nothing.
            replies: ReplyTables::new(),
            gate_sock,
            switch_listener: listener,
            _dir: dir,
            _guard,
        }
    }

    /// Brings up one gate over a stand-in switch, deciding by `registry`'s
    /// table, at the shipped posture — the frame half no longer varies by
    /// phase (NET-085), and the publish half the shipped constant governs —
    /// with the guest sending the plain upgrade head first.
    pub(crate) async fn gate_over(registry: BoxRegistry) -> GateHarness {
        forward_upgrade_head(
            gate_connected_with_phase(registry, super::UNREGISTERED_SOURCE_PHASE).await,
        )
        .await
    }

    /// [`gate_connected_shipped`]'s upgrade-completed harness: the frame
    /// stream begins at a known point, decided by the gate the production
    /// entry built.
    pub(crate) async fn gate_over_shipped(registry: BoxRegistry) -> GateHarness {
        forward_upgrade_head(gate_connected_shipped(registry).await).await
    }

    /// [`gate_over`] with the node-plane baseline set named: the
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

    /// Builds the forwarder's expose request the daemon's client speaks — the
    /// verb the gate's own control leg decides — naming both of the mapping's
    /// ends the way the shipped client spells them: `local` the external
    /// listener the switch binds, `remote` the box's address at the inside
    /// port its forwards dial. The tests that publish before they dial model
    /// the ends as different ports when the shape they pin is which of the
    /// two the recording is bounded by ([`super::PublishedForwards`] holds
    /// the inside one), and as equal when it is not.
    pub(crate) fn expose_request(local: &str, remote: &str, protocol: &str) -> Vec<u8> {
        let body = format!(r#"{{"local":"{local}","remote":"{remote}","protocol":"{protocol}"}}"#);
        let mut request =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body.as_bytes());
        request
    }

    /// The forwarder's retraction verb, spelled as the CLI the guest runs
    /// spells it. The body carries the listener being closed — the host
    /// side's own "local" end — and the protocol that listener bound,
    /// which is the number the reply-flow records below are keyed by.
    pub(crate) fn unexpose_request(local: &str, protocol: &str) -> Vec<u8> {
        let body = format!(r#"{{"local":"{local}","protocol":"{protocol}"}}"#);
        let mut request =
            b"POST /services/forwarder/unexpose HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body.as_bytes());
        request
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
    use sessions::core::egress::{DropReason, FrameFamily, FrameVerdict, InboundFlow, Ipv4Cidr};
    use switch::SwitchSubnet;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use super::test_support::{
        CaptureWriter, DEADLINE, arp_frame, capture_log, connect_control, connect_over,
        expect_frame, expect_silence, expect_teardown, expose_request, gate_connected,
        gate_connected_with_phase, gate_over, gate_over_control, gate_over_shipped, gate_over_with,
        gate_over_with_node_baseline, ipv4_frame, ipv6_frame, read_within, send_frame,
        unexpose_request, wait_for_log,
    };
    use super::{
        AcceptFailure, CONNECT_REQUEST, CONTROL_VERBS, ControlVerb, DROP_WARN_MAX_TRACKED_PAIRS,
        DROP_WARN_MIN_INTERVAL, DropLimiter, EgressGate, GateAdmit, GateDrop, GuestSource,
        GuestSpeak, HANDSHAKE_TIMEOUT, MALFORMED_PUBLISH_RULE, MAX_HEAD, MAX_LIVE_RELAYS,
        MAX_NAMED_TARGET, PROXY_LANE_RULE, PublishedForwards, Record, ReplyTables,
        UNDECLARED_PUBLISH_RECORD_RULE, UNDECLARED_RETRACT_RULE, UNREGISTERED_LIVE_LEASE_RULE,
        UNREGISTERED_PUBLISH_RULE, UNREGISTERED_SOURCE_PHASE, UNREGISTERED_SOURCE_RULE,
        UnregisteredSourcePhase, WarnDecision, accept_loop, dns_pins, gate_verdict, max_frame,
        render_record, serve_connection,
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

    /// A DNS box's undeclared destinations are decided on the host (NET-081
    /// deciding NET-066/067): a namespace that declared DNS hosts gets a
    /// host-side admission table, filled from the DNS replies the switch
    /// returns toward it, and the frame class its address rules cannot carry
    /// — an undeclared destination — is decided against it, here, before the
    /// switch. Before any lookup nothing admits, so the shape a resolved
    /// name's address has is the host's drop; after the box's own lookup the
    /// destinations its answers named — and only they, not their
    /// neighbourhood — pass; the classes no pin governs are unchanged: a
    /// denied destination is refused by the host's own rules, and a row that
    /// declared an *empty* name list holds no entry at all, so nothing can
    /// ever pin for it. The bundle's daemon log reads the decision: the
    /// one-per-box line at the table's first fill, naming the box and the
    /// name.
    #[tokio::test]
    async fn dns_box_undeclared_destination_decided_on_host() {
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
        // The edge of the decision's condition: names *declared empty* —
        // `Some(vec![])` — is not a row whose undeclared destinations the
        // host decides by pins, because no reply can ever pin anything for
        // it, so its undeclared frames are refused like a no-names row's.
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

        // Before any lookup the box holds no pins, so the shape a resolved
        // name's address has — public, undeclared — is dropped on the host,
        // by the very arm that will admit it once the box's own lookup has
        // named it.
        let resolved = ipv4_frame(LEASE, 6, [93, 184, 216, 34], 443);
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &resolved).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "with no pin yet, the undeclared destination is the host's drop; the marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "egress-undeclared-subnet").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("source=100.64.0.9")
                && logged.contains("rule_matched=\"egress-undeclared-subnet\""),
            "the drop is the host's own, named under its rule: {logged}"
        );

        // The box's own lookup: the query reaches the switch — the
        // resolver's carve-out is still the host's own decision — and the
        // reply the switch returns reaches the box in full, read on its way
        // by the ingress leg.
        let query = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        send_frame(&mut h.guest, &query).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            query,
            "the box's own query reaches the switch, byte for byte"
        );
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[Ipv4Addr::new(93, 184, 216, 34)]),
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full, read on its way and held back by nothing"
        );

        // The one line per box the diagnostics read the host-side decision
        // by: written at the table's first fill, naming the box and the
        // name its own lookup resolved.
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("switch_addr=100.64.0.9")
                && logged.contains("namespace=weather")
                && logged.contains("name=\"example.com\""),
            "the first-fill line names the box and the name, got: {logged}"
        );
        assert_eq!(
            logged
                .matches("filled the box's host-side DNS admission table")
                .count(),
            1,
            "one line per box, not one per answer or per lookup: {logged}"
        );

        // The same frame the host dropped a moment ago — admitted now, by
        // the pin the box's own answer set.
        send_frame(&mut h.guest, &resolved).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            resolved,
            "the destination the box's own answer named reaches the switch now"
        );

        // Its sibling in the same /24 — the address the reply did not name —
        // is still the host's drop: the pinned set is the answers, not their
        // neighbourhood.
        let sibling = ipv4_frame(LEASE, 6, [93, 184, 216, 36], 443);
        send_frame(&mut h.guest, &sibling).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the sibling the answer did not name never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // Denied destination of the same row: no pin governs a denied range,
        // so the host's own verdict stands.
        let denied = ipv4_frame(LEASE, 6, [198, 51, 100, 9], 443);
        send_frame(&mut h.guest, &denied).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the denied range is the host's own drop, pin or no pin; the marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "egress-denied-subnet").await;

        // The empty-names row's undeclared frame: refused here, because no
        // reply can ever pin anything for it.
        let undeclared = ipv4_frame(empty, 6, [93, 184, 216, 34], 443);
        let empty_marker = ipv4_frame(empty, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &undeclared).await;
        send_frame(&mut h.guest, &empty_marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            empty_marker,
            "an empty name list is no grant: the undeclared frame is the host's drop"
        );
        expect_silence(&mut h.switch).await;

        // The observability counters read the decision: one frame admitted
        // by a pin — the destination the answer named — and two refused for
        // want of one, the pre-lookup frame and the sibling. The empty-names
        // row's frame was refused by its row, never reaching the pin arm.
        assert_eq!(
            h.pins.admitted_by_pin(),
            1,
            "one frame admitted by a pin: {}",
            h.log.contents()
        );
        assert_eq!(
            h.pins.refused_for_want_of_pin(),
            2,
            "the frames refused for want of a pin are counted, by the arm that refused them: {}",
            h.log.contents()
        );
    }

    /// The decision's edge, from the other side: a name-declaring row's
    /// undeclared destinations are decided by its pins, and nothing else is.
    /// For the same row shape — names declared beside a narrow allowed
    /// subnet, the destination pinned by the box's own lookup first — every
    /// other drop the host-side gate decides is still made here, before the
    /// switch: a destination inside its own `deny_subnets`, the switch's own
    /// address (the one piece of the plan's infrastructure the gate refuses
    /// as a frame rule, before any row is consulted), a protocol its rules do
    /// not allow — aimed at the very destination the pin admits over TCP —
    /// and a source no row holds. The DNS rebinding intersection's wider
    /// infrastructure deny set (NET-067) is the host's own frame rule too,
    /// decided for every row before this one's rules are read; it is pinned
    /// on its own, with the rows it is decided for, by
    /// [`infrastructure_destinations_drop_on_the_host_for_every_row`].
    #[tokio::test]
    async fn a_row_that_resolves_names_still_takes_every_other_drop_on_the_host() {
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
        let mut h = gate_over(registry).await;

        // The pin first, so the drops below are decided against a live one:
        // the box's own lookup, the reply it received, the line that says
        // the host-side table filled.
        let query = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        send_frame(&mut h.guest, &query).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            query,
            "the box's own query reaches the switch, byte for byte"
        );
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[Ipv4Addr::new(93, 184, 216, 34)]),
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full"
        );
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;

        // The lifted class, as the baseline: the destination the box's own
        // answer named reaches the switch over the allowed protocol.
        let pinned = ipv4_frame(LEASE, 6, [93, 184, 216, 34], 443);
        send_frame(&mut h.guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            pinned,
            "the pinned destination is admitted over TCP"
        );

        // Four drops the pin does not lift, then the marker that proves all
        // four were decided before it and none passed.
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

        // Each drop is the host's own, named under its rule.
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
    }

    /// The pin table's single entrance (the architecture review's condition):
    /// a reply-shaped frame on the guest→switch leg pins nothing. The
    /// egress leg is the gate's, and every frame the relay inside the VM
    /// writes is decided like any other — so the forge a subverted relay
    /// would try, a reply wearing the resolver's own address and port, is
    /// the host's drop before the switch ever sees it: the plan never leases
    /// the gateway, so no row holds the address the frame claims. The box's
    /// answers can only enter through the ingress leg — the replies the
    /// switch itself returned toward it — and the reach the forge would
    /// have bought is not there.
    #[tokio::test]
    async fn a_reply_forged_on_the_guest_side_pins_nothing() {
        let registry = BoxRegistry::new(SUBNET);
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
        let mut h = gate_over(registry).await;

        // The box's own lookup first, so the forge is proven against a table
        // that does pin: the query reaches the switch, the reply reaches the
        // box, and the answer becomes the box's pin.
        let query = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        send_frame(&mut h.guest, &query).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            query,
            "the box's own query reaches the switch, byte for byte"
        );
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[answer]),
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full"
        );
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;

        // The forge: a reply the relay inside the VM writes itself, wearing
        // the resolver's address and port, answering the box's declared name
        // with a public address nothing else would let it reach. It never
        // reaches the switch — the source it claims is the plan's own
        // gateway, an address no row holds, so the gate drops it as an
        // unknown source's frame — and a frame the switch never received
        // pins nothing.
        let forged_answer = Ipv4Addr::new(192, 0, 2, 50);
        let forged = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[forged_answer]),
        );
        send_frame(&mut h.guest, &forged).await;
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the forged reply never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "egress-unknown-source").await;

        // And the forge bought no reach: the address it named is still the
        // host's drop, under the arm a real answer would have lifted it by —
        // the pin the forge would have written is not there.
        let to_forged = ipv4_frame(LEASE, 6, forged_answer.octets(), 443);
        send_frame(&mut h.guest, &to_forged).await;
        let second_marker = ipv4_frame(LEASE, 6, [203, 0, 113, 8], 443);
        send_frame(&mut h.guest, &second_marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            second_marker,
            "the address the forged reply named stays the host's drop; the \
             second marker did"
        );
        wait_for_log(&h.log, "egress-undeclared-subnet").await;
        assert_eq!(
            h.pins.refused_for_want_of_pin(),
            1,
            "the frame to the forged answer consulted the pin arm and was \
             refused: no pin was ever written for it"
        );
        assert_eq!(
            h.pins.admitted_by_pin(),
            0,
            "nothing was admitted by a pin in this exchange: the box's own \
             answer was never used"
        );
    }

    /// The proof of the decision's whole point, against the adversary it is
    /// for, per registered row: the relay inside the VM subverted to carry a
    /// box's frames to any destination it likes, on a row the host holds. The
    /// guest end here plays that hostile relay — it writes whatever frames it
    /// chooses — and the host gate still drops every destination the box's
    /// own answers did not pin, whatever neighbourhood they live in, while
    /// the pinned destination passes; an answer that resolved into the row's
    /// deny set or the infrastructure set is refused before it can become one
    /// (NET-067, in the shared refusal format, at the host), and the reply it
    /// came in still reaches the box — resolution is honest, the
    /// *connection* is not admitted. The row is registered, which is what
    /// scopes the proof: the box's frames carry a source a published row
    /// holds. A relay sourcing from an address no row holds is the
    /// unregistered-source case, #1790's, not this task's — there the interim
    /// phase (`Announced`) still admits in-plan lease-run sources, and the
    /// row-less reach it leaves is what that task retires.
    #[tokio::test]
    async fn hostile_relay_reaches_only_the_pinned_answers() {
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
        let mut h = gate_over(registry).await;

        // The box's own lookup, and the reply that answered it: one public
        // address, which becomes the box's one pin.
        let query = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        send_frame(&mut h.guest, &query).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            query,
            "the box's own query reaches the switch, byte for byte"
        );
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[answer]),
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full"
        );
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;

        // The same name resolves again — the box's own retransmission, a
        // fresh question the egress leg records — because a reply can only
        // pin as the answer to one of the box's own outstanding queries: the
        // first reply consumed the first question, and without a second one
        // there would be nothing outstanding for the refused answers to
        // answer, and nothing to refuse.
        send_frame(&mut h.guest, &query).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            query,
            "the box's retransmitted query reaches the switch too"
        );

        // The retransmitted question resolves into refused ranges — the
        // row's own deny set, and the metadata service — and the host refuses
        // each answer before it can become a pin, in the shared refusal
        // format; the reply itself is not held back: the box heard its
        // resolution, and the connection to it is the part that was not
        // admitted.
        let hostile_reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response(
                "example.com",
                &[
                    Ipv4Addr::new(198, 51, 100, 50),
                    Ipv4Addr::new(169, 254, 169, 254),
                ],
            ),
        );
        send_frame(&mut h.switch, &hostile_reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            hostile_reply,
            "a reply whose answers were refused still reaches the box in full"
        );
        wait_for_log(&h.log, "an allowed name resolved into a refused range").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"dns-rebinding-denied-subnet\"")
                && logged.contains("rule_matched=\"dns-rebinding-infrastructure\"")
                && logged.contains("name=\"example.com\"")
                && logged.contains("answer=198.51.100.50")
                && logged.contains("answer=169.254.169.254"),
            "each refused answer says so in the shared refusal format, got: {logged}"
        );

        // The pinned destination passes — the one address the box's own
        // answer named.
        let pinned = ipv4_frame(LEASE, 6, answer.octets(), 443);
        send_frame(&mut h.guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            pinned,
            "the pinned destination is the one that reaches the switch"
        );

        // And nothing else does: the sibling in the answer's own /24, the
        // private and metadata ranges the hostile relay carries the box to,
        // the row's denied range, and a public address no answer named —
        // every class the host decides, each refused under its own rule.
        let sibling = ipv4_frame(LEASE, 6, [93, 184, 216, 36], 443);
        let private = ipv4_frame(LEASE, 6, [10, 9, 9, 9], 443);
        let metadata = ipv4_frame(LEASE, 6, [169, 254, 169, 254], 443);
        let denied = ipv4_frame(LEASE, 6, [198, 51, 100, 9], 443);
        let other_public = ipv4_frame(LEASE, 6, [192, 0, 2, 99], 443);
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        for frame in [&sibling, &private, &metadata, &denied, &other_public] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "none of the hostile frames reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // Each class is the host's own drop, named under its rule — the
        // undeclared two under one rate-limited line, the infrastructure two
        // under another, the denied one its own.
        for rule in [
            "egress-undeclared-subnet",
            "egress-infrastructure-destination",
            "egress-denied-subnet",
        ] {
            wait_for_log(&h.log, rule).await;
        }
        let logged = h.log.contents();
        assert_eq!(
            logged.matches("egress-undeclared-subnet").count(),
            1,
            "one rate-limited line for the two frames no pin names: {logged}"
        );
        assert_eq!(
            logged.matches("egress-infrastructure-destination").count(),
            1,
            "one rate-limited line for the two infrastructure destinations: {logged}"
        );

        // The counters read what the host decided: one frame admitted by a
        // pin, the pinned destination; two refused for want of one, the
        // sibling and the public address no answer named — the private,
        // metadata and denied frames were refused by the host's own frame
        // rules before the pin arm was ever consulted.
        assert_eq!(
            h.pins.admitted_by_pin(),
            1,
            "the pinned destination is the one frame the pins admitted: {logged}"
        );
        assert_eq!(
            h.pins.refused_for_want_of_pin(),
            2,
            "the frames no pin names are counted, by the arm that refused them: {logged}"
        );
    }

    /// The admission table's other lifetime: the entry a box's answers fill
    /// is dropped with the row that declared them **and** with the relay
    /// connection whose lookups filled it. The relay retires the boxes whose
    /// traffic it carried at its end, beside the withdrawal report that ends
    /// their rows, and the two retirements do not ride together: the report
    /// waits on the drainer, and the pins do not, so a shuttle connection's
    /// close leaves the box's old grants dead however the row's own
    /// retirement races.
    ///
    /// The drainer is deliberately not running here, so the closed
    /// connection's row is still the published one when the next connection
    /// arrives — the sharpest shape of the retire, and the one a hostile
    /// relay would try first: close the connection, keep the row, and hope
    /// the pin outlives the close. It does not; and the row a re-attachment
    /// re-registers at the same address starts fail-closed too, until its
    /// own lookups pin again — nothing inside the VM can hand the box its
    /// old grants back across a reconnect.
    #[tokio::test]
    async fn a_closed_relay_connection_retires_the_pins_it_filled() {
        let registry = BoxRegistry::new(SUBNET);
        // The DNS box of the other proofs: names beside a narrow allowed
        // subnet, so the pinned destination is the one thing the pin arm
        // lifts for it.
        let weather_box =
            BoxRegistration::new("weather", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["203.0.113.0/24".to_string()]),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: None,
                });
        registry.register(weather_box.clone());
        // No drainer, and the reports the test's to read: the row the
        // connection carries stays published once the connection ends, so
        // the retire is watched on the record the entry was built from, not
        // on the row's absence.
        let reports = registry
            .take_withdrawal_reports()
            .expect("the withdrawal reports' receiver is taken once");
        let mut h = gate_over(registry.clone()).await;

        // The box's own lookup and the reply it received: the entry for its
        // row holds its pin, and the pinned destination is admitted while
        // the connection that carried the lookup lives. One declared frame
        // first, so the connection has the box's traffic to attribute.
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the box's declared frame reaches the switch"
        );
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let lookup = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[answer]),
        );
        send_frame(&mut h.guest, &lookup).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            lookup,
            "the box's own query reaches the switch, byte for byte"
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full"
        );
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;
        let pinned = ipv4_frame(LEASE, 6, answer.octets(), 443);
        send_frame(&mut h.guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            pinned,
            "the pinned destination is admitted while the connection lives"
        );

        // The retire itself, driven directly — the table's own answer to
        // the connection's end, for the same row: after it, the address
        // the box's own answer pinned is refused.
        let record = h.table.by_source(LEASE).expect("the box's row is held");
        assert!(
            h.pins
                .admits_frame(&record, answer.octets(), None, Instant::now()),
            "before the retire, the box's own answer admits for its row"
        );
        h.pins.retire(&[LEASE]);
        assert!(
            !h.pins
                .admits_frame(&record, answer.octets(), None, Instant::now()),
            "the retire leaves the pinned address refused for the same row"
        );

        // And the same retire as the relay performs it, at the connection's
        // end: the box looks up again — so the entry holds a live pin at the
        // moment the connection ends — and the connection closes.
        send_frame(&mut h.guest, &lookup).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            lookup,
            "the box's second lookup reaches the switch"
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the second reply reaches the box in full"
        );
        send_frame(&mut h.guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            pinned,
            "the re-pinned destination is admitted while the connection lives"
        );
        h.guest.shutdown().await.expect("closing the guest's side");

        // The report is the relay's own word that its end ran — the retire
        // happens beside it, before it — so waiting for it is waiting for
        // the retire, and the report names the box whose traffic the
        // connection carried.
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
            "the closed relay's report names the box whose traffic it carried"
        );

        // The same row, still published — no drainer has acted on the
        // report — and its address is refused: the entry the closed
        // connection's lookups filled decides nothing now. A hostile relay
        // that closed and reopened the connection, keeping the row, holds
        // none of the box's old grants on the new one.
        let (mut guest, mut switch) = connect_over(&h).await;
        send_frame(&mut guest, &pinned).await;
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the closed connection's pins retired with it: the pinned address \
             is refused for the very row it was pinned for; the marker did"
        );
        expect_silence(&mut switch).await;

        // And the row a re-attachment re-registers at the same address —
        // the newest declaration, same names — starts fail-closed too: its
        // pins are its own lookups' to earn, and nothing hands them back.
        registry.register(weather_box);
        send_frame(&mut guest, &pinned).await;
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the re-registered row inherits nothing: fail-closed until its \
             own lookups pin again; the marker did"
        );
        expect_silence(&mut switch).await;

        // Until its own lookup pins again — over the new connection, whose
        // replies fill the new row's entry.
        send_frame(&mut guest, &lookup).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            lookup,
            "the re-registered row's own lookup reaches the switch"
        );
        send_frame(&mut switch, &reply).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            reply,
            "its reply reaches the box in full"
        );
        send_frame(&mut guest, &pinned).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            pinned,
            "the re-registered row's own answer pins its destination again"
        );
    }

    /// NET-040's answer half, read on the host gate ([`ReplyTables`]): a box
    /// whose egress is deny-all — the declaration every own-address proof
    /// pins a published port against — still answers the connections its
    /// published port received, because the gate's own ingress leg recorded
    /// each one when it delivered the opening packet, and the box's answers
    /// pass the same shared reverse-tuple decision the in-VM gate's answers
    /// pass ([`crate::net::egress_gate`] holds one table, the core owns the
    /// rule). The dials that earn the records are the shape every client's
    /// dial toward the box is on this gate: at the mapping's *inside* port —
    /// 18080 and 18081 here, the ends the box listens on — never at the
    /// external ports the registration wire carried (8080 and 8081, the
    /// listeners the switch binds), which no frame arrives at. So the
    /// publishes come first, spoken through the gate's own control leg the
    /// way the daemon's client spells them, and the recording is bounded by
    /// what the applied publishes dial — a bound a dial at the external
    /// port does not meet, pinned below.
    ///
    /// The forwarder's dial is the sharpest client: it arrives NAT'd
    /// from the switch's own address, so the box's answer to it names the
    /// gateway — the one destination the control-surface rule refuses for
    /// everything but the resolver — and it passes anyway, because the
    /// record is consulted ahead of that check. A sibling's direct dial
    /// records the same way over UDP. And the record admits its exact
    /// reverse and nothing else: a reply to a client port no recorded
    /// flow opened, a reply to a dial at the mapping's external end, and
    /// the box's own fresh connect to the same peer, all stay drops —
    /// silent ones, named once under the row's own rule (NET-062).
    ///
    /// The bound is read here too: the box's cap, shrunk to the flows it
    /// already holds, refuses the next client's connect at ingress — the
    /// frame is never delivered, so the client's connect fails rather than
    /// the box's session — and the refusal is counted per box and said
    /// once, while the recorded flows keep refreshing and keep answering.
    #[tokio::test]
    async fn host_gate_passes_replies_on_admitted_inbound_flows() {
        let registry = BoxRegistry::new(SUBNET);
        // Deny-all by destination, every protocol allowed as a dimension: the
        // drop every one of this box's own frames takes is the
        // undeclared-subnet one, so a reply-flow record is the only thing that
        // can lift an answer.
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080, 8081])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        // The two mappings published, as the daemon's own client spells them:
        // the external ends the row declares (the host-side listeners the
        // switch binds) and the inside ends their forwards dial (the ports the
        // box listens on). The gate applies both and notes their inside ends,
        // which is the whole of what bounds the recording below.
        let tcp_publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let udp_publish = expose_request("127.0.0.1:8081", "100.64.0.9:18081", "udp");
        let h = gate_over_control(registry, tcp_publish).await;
        let (mut control_guest, mut control_switch) = connect_control(&h).await;
        control_guest
            .write_all(&udp_publish)
            .await
            .expect("writing the UDP mapping's publish");
        let mut spoken = vec![0u8; udp_publish.len()];
        read_within(&mut control_switch, &mut spoken).await;
        assert_eq!(
            spoken, udp_publish,
            "the gate forwards the UDP mapping's publish verbatim"
        );

        // The frame connection the dials and answers ride.
        let (mut guest, mut switch) = connect_over(&h).await;

        // The two clients a published port's connections come from on this
        // host: the forwarder, whose dial arrives NAT'd from the switch's own
        // address, and a sibling box, dialing directly from its own lease.
        let forwarder = SUBNET.gateway();
        let sibling = Ipv4Addr::new(100, 64, 0, 10);

        // The forwarder's connect: a bare SYN toward the mapping's inside
        // port, the port its forward dials. The gate delivers it — ingress is
        // the target's policy, decided inside — and records the flow it
        // delivered, which is the one thing that will let the box answer it
        // back.
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            dial,
            "the gate delivers the forwarder's dial toward the box's published port"
        );
        wait_for_log(
            &h.log,
            "recorded the box's first inbound flow at its published port",
        )
        .await;
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(1),
            "the delivered dial is the one flow the box holds a record for"
        );

        // The box's answer — the exact reverse of the recorded flow, and a
        // frame whose destination is the gateway itself — passes: the row's
        // empty allow list would drop it and the control-surface rule would
        // refuse it, and the record lifts it ahead of both.
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            answer,
            "the box's answer to the forwarder passes the host gate, byte for byte"
        );

        // The sibling's datagram, at the other mapping's inside port: a first
        // datagram is UDP's opening packet, and it records the same way.
        let query = dns_pins::tests::udp_payload_frame(
            sibling,
            40001,
            Ipv4Addr::from(LEASE),
            18081,
            b"knock knock",
        );
        send_frame(&mut switch, &query).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            query,
            "the gate delivers the sibling's datagram toward the other published port"
        );
        let reply = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            18081,
            sibling,
            40001,
            b"who is there",
        );
        send_frame(&mut guest, &reply).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            reply,
            "the box's datagram answer passes the same shared reverse-tuple decision"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(2),
            "one record per admitted inbound flow, TCP and UDP alike"
        );
        assert_eq!(
            h.replies.live_flows(),
            2,
            "the live-flow gauge counts the same records across the gate's boxes"
        );

        // The recording's bound, pinned from the outside: a dial at the
        // mapping's *external* end — the port the row declares, and the only
        // one the registration wire carried — is delivered like any ingress
        // frame, but no applied publish dials it, so it opens no record.
        // Were the bound the declared ports instead of the published ones,
        // this dial would mint the admission the box needs to answer at a
        // port no publish stands at.
        let external_client = Ipv4Addr::new(100, 64, 0, 12);
        let external_dial = dns_pins::tests::tcp_frame(
            external_client,
            40003,
            Ipv4Addr::from(LEASE),
            8080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &external_dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            external_dial,
            "the gate delivers the external-end dial like any ingress frame"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(2),
            "a dial at the mapping's external end opens no record: no publish dials it"
        );

        // The record admits its exact reverse and nothing else: the box's
        // answer to a client port no recorded flow opened, its answer to the
        // external-end dial a moment ago, and its own fresh connect to the
        // same sibling — egress no record covers, dropped exactly as the
        // deny-all row says.
        let unopened = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            sibling,
            40002,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let from_external = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            8080,
            external_client,
            40003,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let own_connect = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            40000,
            sibling,
            443,
            sessions::core::egress::TCP_SYN,
        );
        for frame in [&unopened, &from_external, &own_connect] {
            send_frame(&mut guest, frame).await;
        }
        // The marker the row does admit — an ARP announcement from the box's
        // own lease — proves the gate decided every frame before it.
        let marker = arp_frame(LEASE);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "no frame a recorded flow reverses reached the switch; the marker did"
        );
        expect_silence(&mut switch).await;
        wait_for_log(&h.log, "egress-undeclared-subnet").await;

        // The bound, at the two flows the box already holds: a third client's
        // connect is refused at the box's cap, toward the client — the frame
        // is not delivered, so the connect fails rather than the box's
        // session — and the refusal is counted per box and said once, while
        // the recorded flows keep refreshing and keep answering.
        let row = h
            .table
            .by_source(LEASE)
            .expect("the box's row is registered");
        h.replies.shrink_cap_of(&row, 2);
        let flood = dns_pins::tests::tcp_frame(
            Ipv4Addr::new(100, 64, 0, 11),
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &flood).await;
        // An ARP frame on the same leg is delivered — ingress relays
        // everything it is not told to refuse — so the refused dial was
        // decided, not lost.
        let noise = arp_frame(forwarder.octets());
        send_frame(&mut switch, &noise).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            noise,
            "the refused dial never reached the box; the frame behind it did"
        );
        wait_for_log(
            &h.log,
            "refused an inbound flow at the box's reply-flow cap",
        )
        .await;
        assert_eq!(
            h.replies.refused_at_cap_of(LEASE),
            Some(1),
            "the refusal at the cap is the per-box counter a status surface reads"
        );
        // The recorded flows are the ones the cap protects: the sibling's
        // conversation still refreshes on its own inbound leg…
        send_frame(&mut switch, &query).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            query,
            "a recorded flow's inbound traffic still refreshes at the cap"
        );
        // …and the box's answer to it still passes.
        send_frame(&mut guest, &reply).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            reply,
            "a recorded flow's answer still passes at the cap"
        );
    }

    /// The other half of the same rule, read on the host gate: no frame the
    /// box sends opens a reply-flow record ([`ReplyTables::observe_delivered`]
    /// is the ingress leg's alone; the egress leg's lookup is read-only), so
    /// a box cannot mint the admission that answers a published port's
    /// connections — it can only answer a flow a client's packet earned.
    ///
    /// Three shapes try and fail. A forged answer — the exact reverse of a
    /// connect that never happened — drops under the row's own rules and
    /// records nothing. A self-connect — the box wearing the client's
    /// address on the guest end, the very frame that would have recorded had
    /// it arrived on the switch end — is a source no namespace holds, and
    /// records nothing. And a mid-stream segment at the published port, or a
    /// SYN at a port no applied publish dials, arriving on the switch end
    /// and delivered in full, opens nothing either: a record is opened only
    /// by an *opening* packet at a port one of the box's own publishes
    /// dials. Then the client's bare SYN at that port arrives, records, and
    /// the same answer that dropped a moment before passes — the only thing
    /// that changed is that the gate delivered the opening of the flow it is
    /// the answer to.
    #[tokio::test]
    async fn host_gate_reply_record_never_opened_by_the_box() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        // The one publish the box stands at, spoken through the gate's own
        // control leg: its two ends equal, the port is both the declared
        // external one and the inside one its forwards dial. The gate's
        // ledger is what bounds the recording below, so the publish comes
        // first.
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:8080", "tcp");
        let h = gate_over_control(registry, publish).await;
        let (mut guest, mut switch) = connect_over(&h).await;
        // A host client outside the plan's address block: the address the
        // announced interim would not admit, so the box's forged frames are
        // refused by the gate itself, not merely by the row's rules.
        let client = Ipv4Addr::new(203, 0, 113, 50);

        // The forged answer: the exact reverse of a connect that never
        // happened, from the box's published port to the client's ephemeral
        // one. The self-connect: the frame that would have recorded, had it
        // arrived on the switch end — worn by the box on the guest end
        // instead.
        let forged = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            8080,
            client,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let self_connect = dns_pins::tests::tcp_frame(
            client,
            40000,
            Ipv4Addr::from(LEASE),
            8080,
            sessions::core::egress::TCP_SYN,
        );
        for frame in [&forged, &self_connect] {
            send_frame(&mut guest, frame).await;
        }
        let marker = arp_frame(LEASE);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "neither the forged answer nor the self-connect reached the switch; the marker did"
        );
        expect_silence(&mut switch).await;
        assert_eq!(
            h.replies.record_count_of(LEASE),
            None,
            "nothing the box sent opened a record: the egress leg's lookup is read-only"
        );

        // The client's mid-stream segment at the published port — an ACK for a
        // connect that never happened — is delivered in full, ingress being
        // the target's policy, and opens nothing…
        let midstream = dns_pins::tests::tcp_frame(
            client,
            40000,
            Ipv4Addr::from(LEASE),
            8080,
            sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut switch, &midstream).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            midstream,
            "the mid-stream segment is delivered like any other inbound frame"
        );
        // …and a SYN at a port no publish dials is delivered too, and
        // records nothing either.
        let unpublished = dns_pins::tests::tcp_frame(
            client,
            40000,
            Ipv4Addr::from(LEASE),
            9999,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &unpublished).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            unpublished,
            "the gate delivers a SYN at an unpublished port; the box's ingress is its own"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(0),
            "the delivered frames minted the box's entry and opened no flow: only an \
             opening packet at a port a publish dials records"
        );

        // So the box's answers to both still drop — the forged answer, now
        // for the second time, and the answer to the unpublished port.
        let from_unpublished = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            9999,
            client,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        for frame in [&forged, &from_unpublished] {
            send_frame(&mut guest, frame).await;
        }
        let marker = arp_frame(LEASE);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the box's answers to the flows nothing recorded still drop; the marker passed"
        );
        expect_silence(&mut switch).await;

        // Then the one thing that opens: the client's bare SYN at the port the
        // box's publish dials, delivered by the gate's own ingress leg.
        let connect = dns_pins::tests::tcp_frame(
            client,
            40000,
            Ipv4Addr::from(LEASE),
            8080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &connect).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            connect,
            "the gate delivers the client's connect at the published port"
        );
        wait_for_log(
            &h.log,
            "recorded the box's first inbound flow at its published port",
        )
        .await;
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(1),
            "the delivered opening packet is the one thing that records"
        );

        // And the answer that dropped twice before passes now: the record the
        // client's own packet earned is the only difference.
        send_frame(&mut guest, &forged).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            forged,
            "the same answer passes once the flow it reverses was recorded"
        );
    }

    /// NET-059's forwarder path, pinned at the decision itself: the
    /// reply-flow record's admission runs ahead of every other check the
    /// egress leg makes, so the box's answer to a connection the switch's
    /// forwarder opened is admitted as a row's admit — flat, no rule
    /// consulted — where the same frame without the record is refused twice
    /// over. The forwarder's dial arrives NAT'd from the switch's own
    /// address, so the answer names the gateway, the control-surface rule's
    /// own target, and the row below is deny-all by destination besides:
    /// only the record — opened by the dial the gate delivered toward the
    /// mapping's inside port, the one port the publish's note bounds the
    /// recording to ([`ReplyTables::observe_delivered`], the same shared
    /// table every other inbound flow rides) — can carry it. The record
    /// admits its exact reverse and nothing else: an answer to a client
    /// port no recorded flow opened, and the box's answer from the
    /// mapping's *external* end, both fall to the control-surface refusal
    /// the row's rules never reach.
    #[test]
    fn gate_verdict_admits_forwarder_reply_from_admitted_port() {
        let registry = BoxRegistry::new(SUBNET);
        // Deny-all by destination, every protocol allowed as a dimension:
        // no rule of this row's can admit the answer below, so the admit
        // that carries it is the record's and nothing else's.
        let record = registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        // The publish's note, taken as the applied publish takes it: the
        // listener the switch binds and the inside port its forward dials —
        // the port the recording is bounded by, pinned from the outside.
        let forwards = PublishedForwards::new();
        forwards
            .note_published(
                ([127, 0, 0, 1], 8080),
                LEASE,
                18080,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row,
            )
            .expect("an empty ledger has room for one publish");
        assert!(
            forwards.inside_published(LEASE, 18080),
            "the mapping's inside port is the port the recording is bounded by"
        );

        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let replies = ReplyTables::new();
        let limiter = Arc::new(DropLimiter::new());

        // One frame decided as the egress leg decides it: summarized and
        // parsed exactly as the relay hands them over, against whichever
        // table the attempt names — the one the dial filled, or the empty
        // one a box's ingress never reached.
        let decide = |replies: &ReplyTables, frame: &[u8]| {
            let l4 = dns_pins::parse_ipv4_l4(frame)
                .expect("the frame builder's IPv4 header always parses");
            let summary = sessions::core::egress::summarize(frame);
            gate_verdict(&summary, Some(&l4), &table, &baseline, &pins, replies)
        };

        // The forwarder's dial: a bare SYN from the gateway — the source
        // the forwarder's connections arrive NAT'd under — at the mapping's
        // inside port. The ingress leg delivered it, and the shared table
        // records the flow it delivered, by the same decision any other
        // client's dial is recorded by.
        let forwarder = SUBNET.gateway();
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let dial_l4 =
            dns_pins::parse_ipv4_l4(&dial).expect("the frame builder's IPv4 header always parses");
        assert!(
            matches!(
                replies.observe_delivered(&record, &dial_l4, &limiter, SUBNET, Instant::now()),
                Some(InboundFlow::Recorded { filled: false })
            ),
            "the forwarder's opening dial is the frame that records the flow"
        );

        // The box's answer — the exact reverse of the recorded flow — is
        // admitted as the row's, though neither the row's deny-all nor the
        // control-surface check is ever reached: the record answers first.
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &answer),
            Ok(GateAdmit::Row),
            "the record admits the box's answer to the forwarder ahead of \
             every other check, as a row's admit"
        );

        // The same frame with no record behind it is the control-surface
        // refusal: the answer names the gateway, and no row's rules are
        // consulted for it — the ceiling the record alone lifts.
        assert_eq!(
            decide(&ReplyTables::new(), &answer),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 40000
            }),
            "without the record the same answer is refused at the switch's \
             own address, before the row's deny-all is ever read"
        );

        // The record admits its exact reverse and nothing else: the box's
        // answer to a client port no recorded flow opened, and its answer
        // from the mapping's external end — the port the row declares,
        // which no applied publish dials — are both refused the same way.
        let unopened = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            39999,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &unopened),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 39999
            }),
            "an answer to a client port no recorded flow opened is not the \
             record's reverse"
        );
        let from_external = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            8080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &from_external),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 40000
            }),
            "an answer from the mapping's external end reverses no recorded \
             flow: no publish dials that port"
        );
    }

    /// A frame the ingress leg is about to deliver that is *sourced from* the
    /// Box Egress Proxy's address records nothing: a box on a credentialed
    /// lane dials the proxy's listener (NET-134), but the proxy only answers
    /// and never opens a connection toward a box, so a proxy-sourced opening
    /// packet at a published port has no legitimate origin and must never
    /// open a reply flow the box could reverse-answer. The decline is defense
    /// in depth — the verdict's reply-flow admit never admits a frame to the
    /// proxy's address either — and it precedes the
    /// record itself, so a proxy-sourced dial mints no entry
    /// ([`ReplyTables::record_count_of`] is `None`, not `Some(0)`) and the
    /// box's answer to it is refused as the proxy-lane drop, the record's
    /// admit never consulted.
    #[test]
    fn proxy_sourced_dial_records_no_reply_flow() {
        let registry = BoxRegistry::new(SUBNET);
        let record = registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let forwards = PublishedForwards::new();
        forwards
            .note_published(
                ([127, 0, 0, 1], 8080),
                LEASE,
                18080,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row,
            )
            .expect("an empty ledger has room for one publish");
        assert!(
            forwards.inside_published(LEASE, 18080),
            "the mapping's inside port is the port the recording is bounded by"
        );

        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let replies = ReplyTables::new();
        let limiter = Arc::new(DropLimiter::new());
        let decide = |replies: &ReplyTables, frame: &[u8]| {
            let l4 = dns_pins::parse_ipv4_l4(frame)
                .expect("the frame builder's IPv4 header always parses");
            let summary = sessions::core::egress::summarize(frame);
            gate_verdict(&summary, Some(&l4), &table, &baseline, &pins, replies)
        };

        // The proxy-sourced dial: a bare SYN from the proxy's address at the
        // mapping's inside port. The ingress leg declines it before any
        // record is consulted, and mints no entry.
        let proxy = SUBNET.box_egress_proxy_address();
        let dial = dns_pins::tests::tcp_frame(
            proxy,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let dial_l4 =
            dns_pins::parse_ipv4_l4(&dial).expect("the frame builder's IPv4 header always parses");
        assert!(
            replies
                .observe_delivered(&record, &dial_l4, &limiter, SUBNET, Instant::now())
                .is_none(),
            "a proxy-sourced dial records no reply flow"
        );
        assert_eq!(
            replies.record_count_of(LEASE),
            None,
            "the decline precedes the record: no entry is minted for the box"
        );

        // The box's answer to the proxy — the frame a recorded flow would
        // have admitted — is refused as the proxy-lane drop, beside every
        // rule, because no record admits it.
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            proxy,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &answer),
            Err(GateDrop::ProxyLane {
                src: LEASE,
                dst: proxy.octets(),
                dst_port: 40000
            }),
            "the box's answer to the proxy is the proxy-lane refusal, no \
             record notwithstanding"
        );
    }

    /// The verdict's reply-flow admit never admits a frame to the Box Egress
    /// Proxy's address, whatever record exists: a record whose reverse
    /// targets the proxy is minted here directly on the box's entry — the
    /// entry's flow table `observe_inbound`, the call
    /// [`ReplyTables::observe_delivered`] makes after its proxy-source
    /// decline, so this bypasses that decline — and the box's answer to the
    /// proxy from a row with no lane is still the proxy-lane drop.
    #[test]
    fn reply_flow_record_never_admits_a_frame_to_the_proxy() {
        let registry = BoxRegistry::new(SUBNET);
        let record = registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let replies = ReplyTables::new();

        let proxy = SUBNET.box_egress_proxy_address();
        let dial = dns_pins::tests::tcp_frame(
            proxy,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let dial_l4 =
            dns_pins::parse_ipv4_l4(&dial).expect("the frame builder's IPv4 header always parses");
        let outcome = replies
            .entry(&record)
            .flows
            .lock()
            .expect("the reply-flow table's lock is uncontended in the test")
            .observe_inbound(
                super::reply_tuple_of(&dial_l4),
                dial_l4.tcp_flags,
                Instant::now(),
            );
        assert!(
            matches!(outcome, InboundFlow::Recorded { .. }),
            "the direct insertion records the proxy-sourced flow"
        );

        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            proxy,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let answer_l4 = dns_pins::parse_ipv4_l4(&answer)
            .expect("the frame builder's IPv4 header always parses");
        let summary = sessions::core::egress::summarize(&answer);
        assert_eq!(
            gate_verdict(
                &summary,
                Some(&answer_l4),
                &table,
                &baseline,
                &pins,
                &replies
            ),
            Err(GateDrop::ProxyLane {
                src: LEASE,
                dst: proxy.octets(),
                dst_port: 40000
            }),
            "a record reversing to the proxy admits nothing: the lane arm decides"
        );
    }

    /// The forwarder's reach is one-directional on the node row too: the
    /// node proxy's published port answers the connections the switch's
    /// forwarder opens, and the node's own connects toward the gateway are
    /// refused whatever the table holds. The node row is allow-all — the
    /// widest rules there are — so the control-surface rule is the only
    /// floor beneath the proxy's answer to the gateway, and the record the
    /// only thing that lifts it: the same frame, from the same proxy port,
    /// is refused without a flow behind it, and so is a frame from the
    /// answerer port the record's tuple never named. The resolver carve-out
    /// is unchanged — a UDP query to the resolver's port still falls through
    /// to the row's rules and passes, whatever the table holds.
    #[test]
    fn gate_verdict_refuses_gateway_dial_from_admitted_port_without_inbound_flow() {
        let registry = BoxRegistry::new(SUBNET);
        // The node row, as the run path registers it: allow-all, at the
        // node's own address, with the proxy port admitted.
        let node = registry.register_node_namespace(7654);
        let node_addr = node.switch_addr().octets();
        // The publish's note for the proxy port, taken as the applied
        // publish takes it.
        let forwards = PublishedForwards::new();
        forwards
            .note_published(
                ([127, 0, 0, 1], 7654),
                node_addr,
                7654,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row,
            )
            .expect("an empty ledger has room for one publish");
        assert!(
            forwards.inside_published(node_addr, 7654),
            "the proxy port is the port the node's recording is bounded by"
        );

        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let replies = ReplyTables::new();
        let limiter = Arc::new(DropLimiter::new());
        let decide = |replies: &ReplyTables, frame: &[u8]| {
            let l4 = dns_pins::parse_ipv4_l4(frame)
                .expect("the frame builder's IPv4 header always parses");
            let summary = sessions::core::egress::summarize(frame);
            gate_verdict(&summary, Some(&l4), &table, &baseline, &pins, replies)
        };

        // The node's own connect toward the gateway, from the proxy port
        // itself: refused under the control-surface rule, and the table
        // holds no entry — the node's own egress records nothing.
        let own_connect = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            SUBNET.gateway(),
            50000,
            sessions::core::egress::TCP_SYN,
        );
        assert_eq!(
            decide(&replies, &own_connect),
            Err(GateDrop::SwitchControlSurface {
                src: node_addr,
                dst_port: 50000
            }),
            "the node's own connect to the gateway is refused, no record \
             notwithstanding"
        );
        assert_eq!(
            replies.record_count_of(node_addr),
            None,
            "a box's own egress records nothing: only the ingress leg records"
        );

        // The forwarder's dial at the proxy port — the connect a host
        // request through the node's published proxy takes — records, and
        // the proxy's answer passes as the row's admit.
        let dial = dns_pins::tests::tcp_frame(
            SUBNET.gateway(),
            51000,
            Ipv4Addr::from(node_addr),
            7654,
            sessions::core::egress::TCP_SYN,
        );
        let dial_l4 =
            dns_pins::parse_ipv4_l4(&dial).expect("the frame builder's IPv4 header always parses");
        assert!(
            matches!(
                replies.observe_delivered(&node, &dial_l4, &limiter, SUBNET, Instant::now()),
                Some(InboundFlow::Recorded { filled: false })
            ),
            "the forwarder's dial at the proxy port is the frame that records"
        );
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            SUBNET.gateway(),
            51000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &answer),
            Ok(GateAdmit::Row),
            "the node proxy's answer to the forwarder is the record's admit, \
             flat past the row's own allow-all"
        );

        // Nothing else from the node toward the gateway passes: a fresh
        // connect from the proxy port to another port, and a frame from
        // the answerer port, are both refused — the record admits its exact
        // reverse and nothing else, the node's allow-all notwithstanding.
        let fresh_connect = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            SUBNET.gateway(),
            50001,
            sessions::core::egress::TCP_SYN,
        );
        assert_eq!(
            decide(&replies, &fresh_connect),
            Err(GateDrop::SwitchControlSurface {
                src: node_addr,
                dst_port: 50001
            }),
            "the record does not license the node's own reaches to other ports"
        );
        let from_answerer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7656,
            SUBNET.gateway(),
            51000,
            sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &from_answerer),
            Err(GateDrop::SwitchControlSurface {
                src: node_addr,
                dst_port: 51000
            }),
            "the answerer port is not the record's reverse: the record's \
             tuple names the proxy port"
        );

        // The resolver carve-out, unchanged: a UDP query to the gateway's
        // resolver port falls through the control-surface check to the
        // row's own rules and passes, whatever the table holds.
        let query = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(node_addr),
            40000,
            SUBNET.gateway(),
            53,
            b"resolve this",
        );
        assert_eq!(
            decide(&replies, &query),
            Ok(GateAdmit::Row),
            "the resolver carve-out falls through to the row's rules, as before"
        );
    }

    /// The forwarder's records live under the shared table's own windows —
    /// no window of the forwarder's own. A TCP record is refreshed by the
    /// last frame either way, and the record that goes quiet past the
    /// shared idle cap is removed by the very lookup that would have
    /// admitted it, so the answer that passed a moment ago is the
    /// control-surface refusal now — the honest consequence shown at the
    /// decision the gate itself runs, which reads the real clock and so
    /// cannot be handed one here. The bound is per flow, never per box:
    /// the forwarder's next dial records again. And the box's own end —
    /// the relay's connection end — retires the entry whole, so the next
    /// dial a re-attached box receives answers from nothing.
    #[test]
    fn forwarder_flow_expires_and_table_is_bounded() {
        let registry = BoxRegistry::new(SUBNET);
        let record = registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let forwards = PublishedForwards::new();
        forwards
            .note_published(
                ([127, 0, 0, 1], 8080),
                LEASE,
                18080,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row,
            )
            .expect("an empty ledger has room for one publish");
        assert!(
            forwards.inside_published(LEASE, 18080),
            "the mapping's inside port is the port the recording is bounded by"
        );

        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let replies = ReplyTables::new();
        let limiter = Arc::new(DropLimiter::new());
        let decide = |replies: &ReplyTables, frame: &[u8]| {
            let l4 = dns_pins::parse_ipv4_l4(frame)
                .expect("the frame builder's IPv4 header always parses");
            let summary = sessions::core::egress::summarize(frame);
            gate_verdict(&summary, Some(&l4), &table, &baseline, &pins, replies)
        };

        // The whole proof runs on one hand-held clock — the same decision,
        // the table's own, at the instants it would read — because the
        // expiry is a window, and five real minutes of a test is not a
        // proof.
        let t0 = Instant::now();
        let forwarder = SUBNET.gateway();
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let dial_l4 =
            dns_pins::parse_ipv4_l4(&dial).expect("the frame builder's IPv4 header always parses");
        assert!(
            matches!(
                replies.observe_delivered(&record, &dial_l4, &limiter, SUBNET, t0),
                Some(InboundFlow::Recorded { filled: false })
            ),
            "the forwarder's dial records under the shared windows"
        );

        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let answer_l4 = dns_pins::parse_ipv4_l4(&answer)
            .expect("the frame builder's IPv4 header always parses");
        // The conversation's first answer is admitted, and refreshes the
        // record: TCP's window runs from the last frame either way.
        let t1 = t0 + Duration::from_secs(1);
        assert!(
            replies.reply_admits(&record, &answer_l4, t1),
            "the answer admits and refreshes the record"
        );

        // The idle cap passes with no frame after t1: the next lookup
        // removes the expired record and admits nothing — the table is
        // bounded by the conversation it was opened for, and the record is
        // gone, not merely refused.
        let expired = t1 + sessions::core::egress::REPLY_TCP_IDLE_CAP + Duration::from_secs(1);
        assert!(
            !replies.reply_admits(&record, &answer_l4, expired),
            "the record is gone with the conversation that went quiet"
        );
        assert_eq!(
            replies.record_count_of(LEASE),
            Some(0),
            "the expired record is removed by the lookup that refused it"
        );

        // The honest consequence at the decision the gate runs, which reads
        // the real clock: the answer that passed a moment ago is refused
        // now, because the record really is gone.
        assert_eq!(
            decide(&replies, &answer),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 40000
            }),
            "the same answer is the control-surface refusal once its record \
             has expired"
        );

        // The bound is per flow, never per box: the forwarder's next dial
        // records again, and its answer passes again.
        let second_dial = dns_pins::tests::tcp_frame(
            forwarder,
            40001,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let second_dial_l4 = dns_pins::parse_ipv4_l4(&second_dial)
            .expect("the frame builder's IPv4 header always parses");
        assert!(
            matches!(
                replies.observe_delivered(
                    &record,
                    &second_dial_l4,
                    &limiter,
                    SUBNET,
                    Instant::now()
                ),
                Some(InboundFlow::Recorded { filled: false })
            ),
            "a fresh dial opens a fresh record: the box is not barred by its \
             quiet flow's expiry"
        );
        let second_answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40001,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        assert_eq!(
            decide(&replies, &second_answer),
            Ok(GateAdmit::Row),
            "the forwarder's next conversation answers as the first did"
        );

        // The box's own end retires the entry whole — the same event that
        // withdraws the row — so the next dial a re-attached box receives
        // answers from nothing.
        replies.retire(&[LEASE]);
        assert_eq!(
            replies.record_count_of(LEASE),
            None,
            "the relay's end retires the entry whole, records and all"
        );
    }

    /// The cap the shared table keeps fails closed on the forwarder path: a
    /// second forwarder dial at a box whose reply-flow table is full is
    /// refused *at ingress* — the connect fails, the frame never reaches
    /// the box — and the refusal is counted per box and said once, while
    /// the recorded flow keeps refreshing and keeps answering. Nothing is
    /// evicted to make room ([`egress::ReplyFlows`] refuses at the cap
    /// rather than evicting a live one), and the refused flow's answer is
    /// refused in turn: no record was opened for it to reverse.
    #[tokio::test]
    async fn forwarder_flow_table_full_refuses_new_flow() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let h = gate_over_control(registry, publish).await;
        let (mut guest, mut switch) = connect_over(&h).await;

        // The cap, shrunk to the one flow the box is about to hold: the
        // hook the relay proofs shrink by, so the proof does not hold a
        // thousand records first.
        let row = h
            .table
            .by_source(LEASE)
            .expect("the box's row is registered");
        h.replies.shrink_cap_of(&row, 1);

        // The first forwarder dial records and fills the table — the
        // once-per-box line says the transition — and its answer passes.
        let forwarder = SUBNET.gateway();
        let first = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &first).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            first,
            "the gate delivers the first forwarder dial toward the box's \
             published port"
        );
        wait_for_log(&h.log, "the box's reply-flow table has filled").await;
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(1),
            "the one flow the cap holds is the first forwarder's"
        );
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            answer,
            "the box's answer to the recorded flow passes at the cap"
        );

        // The second forwarder dial is refused at the cap: the frame is not
        // delivered — the client's connect fails rather than the box's
        // session — and the frame behind it on the same leg is, so the
        // refusal is a decision, not a loss. The refusal is the per-box
        // counter a status surface reads, and the live record is kept, not
        // evicted for the refused flow: the cap fails closed.
        let second = dns_pins::tests::tcp_frame(
            forwarder,
            40001,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &second).await;
        let noise = arp_frame(forwarder.octets());
        send_frame(&mut switch, &noise).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            noise,
            "the refused dial never reached the box; the frame behind it did"
        );
        wait_for_log(
            &h.log,
            "refused an inbound flow at the box's reply-flow cap",
        )
        .await;
        assert_eq!(
            h.replies.refused_at_cap_of(LEASE),
            Some(1),
            "the refusal at the cap is the per-box counter a status surface \
             reads"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(1),
            "the live record is kept, not evicted for the refused flow — the \
             cap fails closed"
        );

        // The refused flow's answer is refused in turn — no record was
        // opened for it — while the live flow's answer still passes: the
        // cap protects the recorded conversation, at the cost of the new
        // one.
        let refused_answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40001,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &refused_answer).await;
        send_frame(&mut guest, &answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            answer,
            "the refused flow's answer never arrived; the live flow's did"
        );
        expect_silence(&mut switch).await;
    }

    /// The retraction takes the publication's records with it. Two mappings
    /// published on one box, two forwarder dials recorded: the unexpose of
    /// the first mapping ends the records *its* publish's inside port
    /// earned, in the same step the ledger drops the publication's
    /// attribution, and the other mapping's record stands — the count is
    /// the purge's own evidence, read through the same table the frame
    /// stream decides by.
    ///
    /// Both mappings are runtime publishes the row recorded (NET-016,
    /// NET-138), so the retraction is applied at the live row: a withdrawal
    /// applies to the runtime-published set, and a declared port's would be
    /// refused. With the row still standing, the purge is visible at the
    /// frame level too: the box's next answer on the retracted port is
    /// decided by the row's rules, which refuse it.
    #[tokio::test]
    async fn forwarder_reply_dropped_after_admitted_port_withdrawn() {
        let registry = BoxRegistry::new(SUBNET);
        // The node's own row, filed once at boot the way the run path files
        // it: the source the final arm's marker wears.
        let node = registry.register_node_namespace(7654);
        let node_addr = node.switch_addr().octets();
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(sessions::DynamicIngress::Allow, Some((8080, 8081)))
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        // The in-VM daemon's two listen reports, inside the grant: the
        // row's runtime-published set the publishes and the retraction are
        // decided by.
        for port in [8080, 8081] {
            registry
                .admit_runtime_port(
                    Ipv4Addr::from(LEASE),
                    port,
                    sessions::IpProto::Tcp,
                    std::time::Instant::now(),
                )
                .expect("the report is inside the grant the row holds");
        }
        // Both mappings published, as the daemon's own client spells them:
        // the external ends the row admits and the inside ends their
        // forwards dial.
        let first_publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let h = gate_over_control(registry, first_publish).await;
        let (mut control_guest, mut control_switch) = connect_control(&h).await;
        let second_publish = expose_request("127.0.0.1:8081", "100.64.0.9:18081", "tcp");
        control_guest
            .write_all(&second_publish)
            .await
            .expect("writing the second mapping's publish");
        let mut spoken = vec![0u8; second_publish.len()];
        read_within(&mut control_switch, &mut spoken).await;
        assert_eq!(
            spoken, second_publish,
            "the gate forwards the second mapping's publish verbatim"
        );

        // The frame connection the dials and answers ride.
        let (mut guest, mut switch) = connect_over(&h).await;

        // Two forwarder dials, one at each mapping's inside port: two
        // records, one per admitted flow, and both answers pass while both
        // publications stand.
        let forwarder = SUBNET.gateway();
        let first_dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        let second_dial = dns_pins::tests::tcp_frame(
            forwarder,
            40001,
            Ipv4Addr::from(LEASE),
            18081,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &first_dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            first_dial,
            "the gate delivers the first mapping's dial"
        );
        send_frame(&mut switch, &second_dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            second_dial,
            "the gate delivers the second mapping's dial"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(2),
            "one record per published mapping the forwarder dialed"
        );
        let first_answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        let second_answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18081,
            forwarder,
            40001,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &first_answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            first_answer,
            "the first mapping's answer passes while its publication stands"
        );
        send_frame(&mut guest, &second_answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            second_answer,
            "the second mapping's answer passes while its publication stands"
        );

        // The retraction of the first mapping, spoken as the client spells
        // it: applied at the live row, whose runtime-published set holds the
        // port, and forwarded verbatim, and the records its publication
        // earned end in the same step.
        let (mut retract_guest, mut retract_switch) = connect_control(&h).await;
        let retraction = unexpose_request("127.0.0.1:8080", "tcp");
        retract_guest
            .write_all(&retraction)
            .await
            .expect("writing the first mapping's retraction");
        let mut spoken = vec![0u8; retraction.len()];
        read_within(&mut retract_switch, &mut spoken).await;
        assert_eq!(
            spoken, retraction,
            "the gate forwards the applied retraction verbatim"
        );

        // The purge, read through the table the frame stream decides by:
        // the retracted mapping's record is gone, the other mapping's
        // stands — a retraction ends a publication, never a box.
        tokio::time::timeout(DEADLINE, async {
            while h.replies.record_count_of(LEASE) != Some(1) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect(
            "the retraction ended the records its publication earned, and \
             retained the other mapping's",
        );

        // The next answer on the retracted port does not arrive: no record
        // admits it any more, and the row's own rules refuse a frame toward
        // the switch's address.
        send_frame(&mut guest, &first_answer).await;
        let marker = arp_frame(node_addr);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the answer on the retracted port never arrived; the marker did"
        );
        expect_silence(&mut switch).await;
    }

    /// Design §7.1 and NET-121 at box end: when a box's row is withdrawn,
    /// the gate itself unbinds the declared forward the guest can never
    /// retract, then terminates the connection that forward still carries.
    /// The unexpose reaches the switch spelled as the publish was, the
    /// reset reaches it over a frame connection of the gate's own, from the
    /// box's address and port toward the forwarder's, and the ledger no
    /// longer attributes the listener, so a later retraction of it is
    /// refused.
    #[tokio::test]
    async fn declared_forward_unbound_and_its_connections_reset_at_row_withdrawal() {
        let registry = BoxRegistry::new(SUBNET);
        let handle = registry.clone();
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        // The declared port's publish, applied.
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let h = gate_over_control(registry, publish).await;

        // One connection through the forward: the forwarder's SYN toward the
        // box's inside port, and the box's answer.
        let (mut guest, mut switch) = connect_over(&h).await;
        let forwarder = SUBNET.gateway();
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &dial).await;
        assert_eq!(expect_frame(&mut guest).await, dial);
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(expect_frame(&mut switch).await, answer);

        // The box ends: its row is withdrawn.
        assert!(handle.withdraw(Ipv4Addr::from(LEASE)).is_some());

        // First the unbind: the gate's unexpose of the declared listener,
        // answered as the switch answers it.
        let (mut unbind, _) = tokio::time::timeout(DEADLINE, h.switch_listener.accept())
            .await
            .expect("the gate dials the switch to unbind the forward")
            .expect("accepting the gate's unbind");
        let mut request = Vec::new();
        let mut chunk = [0u8; 512];
        while !String::from_utf8_lossy(&request).contains(r#""protocol":"tcp"}"#) {
            let n = tokio::time::timeout(DEADLINE, unbind.read(&mut chunk))
                .await
                .expect("the unexpose arrives within the deadline")
                .expect("reading the unexpose");
            assert!(n > 0, "the gate closed before its unexpose was whole");
            request.extend_from_slice(&chunk[..n]);
        }
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.starts_with("POST /services/forwarder/unexpose HTTP/1.1\r\n"),
            "the gate asks the switch to unexpose, got: {request}"
        );
        assert!(
            request.ends_with(r#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#),
            "the unexpose names the listener as the publish spelled it, got: {request}"
        );
        unbind
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("answering the unexpose");
        wait_for_log(
            &h.log,
            "unbound the box's forwarder at its row's withdrawal",
        )
        .await;

        // Then the termination: a frame connection of the gate's own,
        // carrying a reset from the box toward the forwarder.
        let (mut resets, _) = tokio::time::timeout(DEADLINE, h.switch_listener.accept())
            .await
            .expect("the gate dials the switch to write the resets")
            .expect("accepting the gate's reset connection");
        tokio::time::timeout(
            DEADLINE,
            super::forward_revoke::tests::answer_the_probe(&mut resets, CONNECT_REQUEST),
        )
        .await
        .expect("the reset connection is upgraded and probed first");
        let mut frames = Vec::new();
        tokio::time::timeout(DEADLINE, resets.read_to_end(&mut frames))
            .await
            .expect("the gate closes its reset connection")
            .expect("reading the resets");
        let len = usize::from(u16::from_le_bytes([frames[0], frames[1]]));
        let reset = super::forward_revoke::parse_tcp_segment(&frames[2..2 + len])
            .expect("the first frame is a TCP segment");
        assert_eq!(
            reset.flags,
            sessions::core::egress::TCP_RST,
            "the frame is a bare reset: {reset:?}"
        );
        assert_eq!(
            (reset.src, reset.src_port, reset.dst, reset.dst_port),
            (LEASE, 18080, forwarder.octets(), 40000),
            "the reset runs from the box's port to the forwarder's"
        );
        wait_for_log(
            &h.log,
            "terminated the connections the box's forwarders carried",
        )
        .await;

        // The listener is no longer the ledger's: a retraction of it now is
        // unattributed, and refused before the switch sees it.
        let (mut retract_guest, mut retract_switch) = connect_control(&h).await;
        retract_guest
            .write_all(&unexpose_request("127.0.0.1:8080", "tcp"))
            .await
            .expect("writing the late retraction");
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, retract_switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => {
                panic!("{n} byte(s) of a retraction the host already made reached the switch")
            }
            Ok(Err(error)) => panic!("reading the switch end failed: {error}"),
            Err(_) => panic!("the gate neither refused nor forwarded the late retraction"),
        }
    }

    /// A publish the switch answers with an error bound nothing, so its
    /// ledger note comes back out. Kept, it would count against the bound
    /// for the gate's lifetime, and the box's end would try to unbind a
    /// forward that was never bound, holding the address while it did.
    #[tokio::test]
    async fn a_publish_the_switch_refuses_leaves_no_ledger_entry() {
        let registry = BoxRegistry::new(SUBNET);
        let handle = registry.clone();
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let mut h = gate_over_control(registry, publish).await;

        let body = "listen tcp 127.0.0.1:8080: bind: address already in use";
        let refused = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        h.switch
            .write_all(refused.as_bytes())
            .await
            .expect("answering the expose with an error");
        let mut seen = vec![0u8; refused.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen,
            refused.as_bytes(),
            "the refusal reaches the guest verbatim"
        );
        h.guest.shutdown().await.expect("closing the guest's side");
        h.switch
            .shutdown()
            .await
            .expect("closing the switch's side");
        wait_for_log(&h.log, "the egress gate's ledger released its note").await;

        // The box ends. The ledger holds nothing at its address, so the
        // revocation unbinds nothing and the hold ends without a dial.
        assert!(handle.withdraw(Ipv4Addr::from(LEASE)).is_some());
        tokio::time::timeout(DEADLINE, async {
            while h.table.revocation_pending(LEASE) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the hold ends with nothing to unbind");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), h.switch_listener.accept())
                .await
                .is_err(),
            "the gate dialed the switch to unbind a forward that was never bound"
        );
    }

    /// A publish the switch answers as gvproxy does — `200 OK` with a
    /// `Date` header and an empty body, the client closing first, then the
    /// switch — keeps its ledger note: the box's end unbinds the forward
    /// and resets the connection it carries.
    #[tokio::test]
    async fn a_publish_the_switch_accepts_is_unbound_and_reset_at_box_end() {
        let registry = BoxRegistry::new(SUBNET);
        let handle = registry.clone();
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let mut h = gate_over_control(registry, publish).await;

        let accepted = b"HTTP/1.1 200 OK\r\nDate: Tue, 06 Oct 2026 04:50:01 GMT\r\n\
                         Content-Length: 0\r\n\r\n";
        h.switch
            .write_all(accepted)
            .await
            .expect("answering the expose");
        let mut seen = vec![0u8; accepted.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(seen, accepted, "the answer reaches the guest verbatim");
        // The daemon's client reads `Content-Length` bytes and drops its
        // stream; gvproxy closes once the gate half-closes its side.
        h.guest.shutdown().await.expect("closing the guest's side");
        let mut rest = Vec::new();
        tokio::time::timeout(DEADLINE, h.switch.read_to_end(&mut rest))
            .await
            .expect("the gate half-closes the switch's side")
            .expect("reading the switch's side to its end");
        h.switch
            .shutdown()
            .await
            .expect("closing the switch's side");

        // One connection through the forward.
        let (mut guest, mut switch) = connect_over(&h).await;
        let forwarder = SUBNET.gateway();
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &dial).await;
        assert_eq!(expect_frame(&mut guest).await, dial);
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(expect_frame(&mut switch).await, answer);

        // The box ends: the gate unbinds the forward it applied.
        assert!(handle.withdraw(Ipv4Addr::from(LEASE)).is_some());
        let (mut unbind, _) = tokio::time::timeout(DEADLINE, h.switch_listener.accept())
            .await
            .expect("the gate dials the switch to unbind the accepted publish")
            .expect("accepting the gate's unbind");
        let request = read_forwarder_request(&mut unbind).await;
        assert!(
            request.ends_with(r#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#),
            "the unexpose names the accepted publish's listener, got: {request}"
        );
        unbind
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("answering the unexpose");

        // Then the reset of the connection the forward carried.
        let (mut resets, _) = tokio::time::timeout(DEADLINE, h.switch_listener.accept())
            .await
            .expect("the gate dials the switch to write the resets")
            .expect("accepting the gate's reset connection");
        tokio::time::timeout(
            DEADLINE,
            super::forward_revoke::tests::answer_the_probe(&mut resets, CONNECT_REQUEST),
        )
        .await
        .expect("the reset connection is upgraded and probed first");
        let mut frames = Vec::new();
        tokio::time::timeout(DEADLINE, resets.read_to_end(&mut frames))
            .await
            .expect("the gate closes its reset connection")
            .expect("reading the resets");
        let len = usize::from(u16::from_le_bytes([frames[0], frames[1]]));
        let reset = super::forward_revoke::parse_tcp_segment(&frames[2..2 + len])
            .expect("the first frame is a TCP segment");
        assert_eq!(reset.flags, sessions::core::egress::TCP_RST);
        assert_eq!(
            (reset.src, reset.src_port, reset.dst, reset.dst_port),
            (LEASE, 18080, forwarder.octets(), 40000),
            "the reset runs from the box's port to the forwarder's"
        );
    }

    /// Reads one forwarder request off `stream` up to the end of its JSON
    /// body, for the tests that stand in for the switch's control surface.
    async fn read_forwarder_request(stream: &mut UnixStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0u8; 512];
        while !String::from_utf8_lossy(&request).ends_with('}') {
            let n = tokio::time::timeout(DEADLINE, stream.read(&mut chunk))
                .await
                .expect("the request arrives within the deadline")
                .expect("reading the request");
            assert!(n > 0, "the peer closed before its request was whole");
            request.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    /// B1, design §7.1 under address reuse, at the gate: while a withdrawn
    /// box's unbind is still in flight, its address is held. A new row at
    /// that address is refused, so it cannot receive the old box's
    /// forwarded connections. A publish there, as a new box at the same
    /// address would make it, is refused before the switch sees it, so the
    /// old box's revocation never unbinds the new box's forward. Once the
    /// old forward is unbound the address is free again.
    #[tokio::test]
    async fn a_withdrawn_address_is_held_until_its_forwards_are_unbound() {
        let registry = BoxRegistry::new(SUBNET);
        let handle = registry.clone();
        let declare = || {
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
        };
        registry.register(declare());
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let h = gate_over_control(registry, publish).await;

        assert!(handle.withdraw(Ipv4Addr::from(LEASE)).is_some());
        // The unbind is dialed and left unanswered: the revocation is in
        // flight.
        let (mut unbind, _) = tokio::time::timeout(DEADLINE, h.switch_listener.accept())
            .await
            .expect("the gate dials the switch to unbind the forward")
            .expect("accepting the gate's unbind");
        let asked = read_forwarder_request(&mut unbind).await;
        assert!(
            asked.ends_with(r#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#),
            "the unbind names the old box's listener, got: {asked}"
        );

        // A new row registered before the revocation ran: refused.
        assert_eq!(
            handle
                .try_register(declare())
                .map(|row| row.name().to_string()),
            Err(crate::box_registry::AllocationError::RevocationPending {
                addr: Ipv4Addr::from(LEASE)
            }),
        );
        // A new box publishing at the address before the revocation ran:
        // refused, never written on.
        let (mut guest, mut switch) = connect_control(&h).await;
        guest
            .write_all(&expose_request("127.0.0.1:8081", "100.64.0.9:18081", "tcp"))
            .await
            .expect("writing the racing publish");
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => {
                panic!("{n} byte(s) of a publish at a revoking address reached the switch")
            }
            Ok(Err(error)) => panic!("reading the switch end failed: {error}"),
            Err(_) => panic!("the gate neither refused nor forwarded the racing publish"),
        }
        wait_for_log(&h.log, super::REVOKING_ADDRESS_RULE).await;

        // The old forward is unbound: the hold ends, and the address takes a
        // row again.
        unbind
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("answering the unbind");
        tokio::time::timeout(DEADLINE, async {
            while h.table.revocation_pending(LEASE) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the hold ends once the forward is unbound");
        handle
            .try_register(declare())
            .expect("the address is free once the old box's forwards are unbound");
    }

    /// Stands in for the switch's forwarder surface at `path`: answers each
    /// unexpose with the next of `answers` (status line and body), the last
    /// one repeated, and hands each request to the returned receiver.
    fn forwarder_answering(
        path: &std::path::Path,
        answers: &'static [(&'static str, &'static str)],
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        let listener = UnixListener::bind(path).expect("binding the stand-in switch");
        let (asked, receiver) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut answers = answers.iter().peekable();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let request = read_forwarder_request(&mut stream).await;
                let _sent = asked.send(request);
                let (status, body) = if answers.len() > 1 {
                    *answers.next().expect("a scripted answer")
                } else {
                    **answers.peek().expect("the last answer repeats")
                };
                let answer = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _answered = stream.write_all(answer.as_bytes()).await;
            }
        });
        (server, receiver)
    }

    /// A ledger with one declared forward applied at `LEASE`, and the
    /// withdrawal of that box's row as the gate would receive it.
    fn withdrawn_with_one_forward() -> (
        BoxRegistry,
        Arc<PublishedForwards>,
        crate::box_registry::RowWithdrawal,
    ) {
        let registry = BoxRegistry::new(SUBNET);
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let forwards = Arc::new(PublishedForwards::new());
        assert_eq!(
            forwards.note_published(
                ([127, 0, 0, 1], 8080),
                LEASE,
                18080,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
        assert!(registry.withdraw(Ipv4Addr::from(LEASE)).is_some());
        let withdrawal = withdrawn.try_recv().expect("the withdrawal is delivered");
        (registry, forwards, withdrawal)
    }

    static TWO_QUICK_RETRIES: [Duration; 2] =
        [Duration::from_millis(10), Duration::from_millis(10)];

    /// B2: an unexpose that fails is not the end of the forward. Its ledger
    /// entry stays, the box's address stays held, and the unbind is retried
    /// after the backoff. Once a retry succeeds, the entry leaves the ledger
    /// and the hold ends.
    #[tokio::test]
    async fn a_failed_unbind_is_retried_and_holds_the_address_until_it_succeeds() {
        let dir = tempfile::TempDir::new().expect("a tempdir");
        let sock = dir.path().join("switch.sock");
        static ANSWERS: [(&str, &str); 2] =
            [("500 Internal Server Error", "transient"), ("200 OK", "")];
        let (server, mut asked) = forwarder_answering(&sock, &ANSWERS);
        let (registry, forwards, withdrawal) = withdrawn_with_one_forward();
        assert!(registry.table().revocation_pending(LEASE));

        let kept = super::revoke_box_forwards(
            sock,
            Arc::clone(&forwards),
            ReplyTables::new(),
            withdrawal,
            &TWO_QUICK_RETRIES,
        )
        .await;
        server.abort();

        assert!(kept.is_none(), "the retry unbound the forward");
        let mut tries = 0;
        while let Ok(request) = asked.try_recv() {
            assert!(request.ends_with(r#"{"local":"127.0.0.1:8080","protocol":"tcp"}"#));
            tries += 1;
        }
        assert_eq!(tries, 2, "one failed unexpose, then one retry");
        assert!(forwards.published_at(LEASE).is_empty());
        assert!(!registry.table().revocation_pending(LEASE));
    }

    /// B2's bound: a switch that keeps refusing gets the first try plus one
    /// retry per backoff step, and no more. The forward stays in the ledger,
    /// and the withdrawal comes back to the caller, which keeps it, so the
    /// address stays held while the forward is still bound.
    #[tokio::test]
    async fn an_unbind_that_keeps_failing_gives_up_and_keeps_the_address_held() {
        let dir = tempfile::TempDir::new().expect("a tempdir");
        let sock = dir.path().join("switch.sock");
        static ANSWERS: [(&str, &str); 1] = [("500 Internal Server Error", "stuck")];
        let (server, mut asked) = forwarder_answering(&sock, &ANSWERS);
        let (registry, forwards, withdrawal) = withdrawn_with_one_forward();

        let kept = super::revoke_box_forwards(
            sock,
            Arc::clone(&forwards),
            ReplyTables::new(),
            withdrawal,
            &TWO_QUICK_RETRIES,
        )
        .await;
        server.abort();

        let mut tries = 0;
        while asked.try_recv().is_ok() {
            tries += 1;
        }
        assert_eq!(tries, 3, "the first try and one retry per backoff step");
        assert_eq!(
            forwards.published_at(LEASE).len(),
            1,
            "still bound, still the gate's"
        );
        assert!(kept.is_some(), "the withdrawal is handed back to keep");
        assert!(registry.table().revocation_pending(LEASE));
        drop(kept);
        assert!(!registry.table().revocation_pending(LEASE));
    }

    /// gvproxy answers an unexpose of a listener it holds no forward at with
    /// a 500 saying so. The goal state holds, so the box's end counts it as
    /// unbound instead of retrying: an earlier try whose answer was lost
    /// must not hold the address for good.
    #[tokio::test]
    async fn an_unbind_the_switch_says_was_not_bound_counts_as_done() {
        let dir = tempfile::TempDir::new().expect("a tempdir");
        let sock = dir.path().join("switch.sock");
        static ANSWERS: [(&str, &str); 1] = [("500 Internal Server Error", "proxy not found\n")];
        let (server, mut asked) = forwarder_answering(&sock, &ANSWERS);
        let (registry, forwards, withdrawal) = withdrawn_with_one_forward();

        let kept = super::revoke_box_forwards(
            sock,
            Arc::clone(&forwards),
            ReplyTables::new(),
            withdrawal,
            &TWO_QUICK_RETRIES,
        )
        .await;
        server.abort();

        assert!(kept.is_none());
        let _asked_once = asked.try_recv().expect("the one unexpose was asked");
        assert_eq!(
            asked.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty),
            "no retry for a forward already gone"
        );
        assert!(forwards.published_at(LEASE).is_empty());
        assert!(!registry.table().revocation_pending(LEASE));
    }

    /// The SYN-only rule on the forwarder path: a record is opened only by
    /// an *opening* packet at the published inside port, so the gateway's
    /// mid-stream segment at that port — delivered, as all ingress the
    /// box's ingress admits is — opens nothing, and neither does a SYN at
    /// the mapping's external end, which no applied publish dials. The
    /// forwarder's own SYN records, its answer passes, and the flow's end
    /// is read on the answer side: the box's FIN is admitted *and* ends
    /// the record — the close is part of the conversation — so nothing
    /// the box sends on the flow after it is a reply the record admits.
    #[tokio::test]
    async fn forwarder_flow_not_adopted_mid_stream() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: None,
                    allow_subnets: Some(vec![]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let publish = expose_request("127.0.0.1:8080", "100.64.0.9:18080", "tcp");
        let h = gate_over_control(registry, publish).await;
        let (mut guest, mut switch) = connect_over(&h).await;

        let forwarder = SUBNET.gateway();
        // The gateway's mid-stream segment at the published inside port:
        // delivered like any ingress frame, and it opens nothing — only an
        // opening packet records, so no amount of traffic the box never
        // answered a connect of can mint the admission an answer needs.
        let mid_stream = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut switch, &mid_stream).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            mid_stream,
            "the mid-stream segment is delivered toward the box's published port"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(0),
            "a mid-stream segment opens no record: only an opening packet does"
        );

        // A SYN at the mapping's external end — the port the row declares,
        // which no applied publish dials — is delivered too, and records
        // nothing: the recording's bound is the publish's inside port.
        let external_dial = dns_pins::tests::tcp_frame(
            forwarder,
            40002,
            Ipv4Addr::from(LEASE),
            8080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &external_dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            external_dial,
            "the external-end dial is delivered like any ingress frame"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(0),
            "a dial at the mapping's external end opens no record: no publish \
             dials it"
        );

        // The forwarder's own SYN at the inside port records, and its
        // answer passes — the only thing that changed is that the gate
        // delivered the opening of the flow the answer reverses.
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            40000,
            Ipv4Addr::from(LEASE),
            18080,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            dial,
            "the forwarder's opening dial is delivered toward the box's \
             published port"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(1),
            "the bare SYN at the published inside port is the one frame that \
             records"
        );
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            answer,
            "the box's answer to the flow the SYN opened passes"
        );

        // The box's FIN on the flow is admitted and ends the record — the
        // close passes, and the frame behind it does not: the flow is
        // over, and the box's next frame on it is new traffic the rules
        // decide.
        let close = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(LEASE),
            18080,
            forwarder,
            40000,
            sessions::core::egress::TCP_FIN,
        );
        send_frame(&mut guest, &close).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            close,
            "the box's FIN on the recorded flow passes, and ends the record"
        );
        assert_eq!(
            h.replies.record_count_of(LEASE),
            Some(0),
            "the FIN ended the record it closed"
        );
        send_frame(&mut guest, &answer).await;
        let marker = arp_frame(LEASE);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the frame behind the FIN never arrived; the marker did"
        );
        expect_silence(&mut switch).await;
    }

    /// The e2e case's unit of behavior, at relay level: on a VM-backed host
    /// a host request through the node's published hostname proxy dials the
    /// proxy port, and the node proxy's answer to the forwarder reaches
    /// the switch — the record the dial earned, the same shared decision
    /// every other inbound flow rides. Nothing else from the node toward
    /// the gateway passes: the node's own connect from the proxy port is
    /// refused without a flow behind it, and so is a frame from the
    /// answerer port the record's tuple never named. The flow's close is
    /// admitted and ends the record, so the frame behind it is refused.
    #[tokio::test]
    async fn node_proxy_reply_to_forwarder_reaches_switch() {
        let registry = BoxRegistry::new(SUBNET);
        let node = registry.register_node_namespace(7654);
        let node_addr = node.switch_addr().octets();
        // The proxy port published at the node's own address, as the
        // daemon's client spells it: the row holds the port, so the publish
        // applies to it.
        let publish = expose_request(
            "127.0.0.1:7654",
            &format!("{}:7654", SUBNET.daemon_ip()),
            "tcp",
        );
        let h = gate_over_control(registry, publish).await;
        let (mut guest, mut switch) = connect_over(&h).await;

        // The forwarder's dial at the proxy port — the connect a host
        // request through the published proxy takes — is delivered toward
        // the node and records the flow it delivered.
        let forwarder = SUBNET.gateway();
        let dial = dns_pins::tests::tcp_frame(
            forwarder,
            51000,
            Ipv4Addr::from(node_addr),
            7654,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &dial).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            dial,
            "the gate delivers the forwarder's dial toward the node's proxy port"
        );
        assert_eq!(
            h.replies.record_count_of(node_addr),
            Some(1),
            "the forwarder's dial at the proxy port is the one flow the node \
             holds a record for"
        );

        // The node proxy's answer — the exact reverse, and a frame whose
        // destination is the gateway itself — reaches the switch: the
        // record lifts it ahead of the control-surface rule that would
        // otherwise refuse it.
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            forwarder,
            51000,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut guest, &answer).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            answer,
            "the node proxy's answer to the forwarder reaches the switch"
        );

        // Nothing else from the node toward the gateway passes: the node's
        // own connect from the proxy port — the very frame an
        // exfiltration would wear — and a frame from the answerer port are
        // both refused, the record notwithstanding.
        let own_connect = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            forwarder,
            50000,
            sessions::core::egress::TCP_SYN,
        );
        let from_answerer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7656,
            forwarder,
            51000,
            sessions::core::egress::TCP_ACK,
        );
        for frame in [&own_connect, &from_answerer] {
            send_frame(&mut guest, frame).await;
        }
        let marker = arp_frame(node_addr);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "no frame the record does not reverse reached the switch; the \
             marker did"
        );
        expect_silence(&mut switch).await;

        // The flow's close is admitted and ends the record, so the frame
        // behind it is refused.
        let close = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(node_addr),
            7654,
            forwarder,
            51000,
            sessions::core::egress::TCP_FIN,
        );
        send_frame(&mut guest, &close).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            close,
            "the node's FIN on the recorded flow passes, and ends the record"
        );
        assert_eq!(
            h.replies.record_count_of(node_addr),
            Some(0),
            "the FIN ended the record it closed"
        );
        send_frame(&mut guest, &answer).await;
        let marker = arp_frame(node_addr);
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the frame behind the FIN never arrived; the marker did"
        );
        expect_silence(&mut switch).await;
    }

    /// NET-134's ingress arm: a bare-SYN TCP frame from the Box Egress
    /// Proxy's address toward a box's published inside port has no
    /// legitimate origin — the proxy only answers (NET-134) and never opens
    /// toward a box — so the ingress relay drops it before it can open a
    /// reply-flow record or reach the box. The proxy's answers to a
    /// credentialed box's dial (SYN-ACK, ACK) are not opening packets and
    /// still pass, and a proxy-sourced bare SYN toward a port no publish
    /// names is out of the recording bound's reach, so it is not this rule's
    /// and continues to its normal decision.
    #[tokio::test]
    async fn box_egress_proxy_syn_to_published_port_dropped() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        let node_addr = SUBNET.daemon_ip().octets();
        let publish = expose_request(
            "127.0.0.1:7654",
            &format!("{}:7654", SUBNET.daemon_ip()),
            "tcp",
        );
        let h = gate_over_control(registry, publish).await;
        let (mut guest, mut switch) = connect_over(&h).await;
        let proxy = SUBNET.box_egress_proxy_address().octets();

        // The proxy's bare SYN toward the published inside port — the
        // opening packet no one legitimately sends — never reaches the
        // guest; the marker below proves it was decided.
        let opening = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(proxy),
            40000,
            Ipv4Addr::from(node_addr),
            7654,
            sessions::core::egress::TCP_SYN,
        );
        send_frame(&mut switch, &opening).await;
        // A SYN carrying other flags but no ACK is still an opening packet by
        // the reply-flow table's own shape, and is dropped the same way.
        let odd_opening = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(proxy),
            40001,
            Ipv4Addr::from(node_addr),
            7654,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_FIN,
        );
        send_frame(&mut switch, &odd_opening).await;

        // The proxy's answer to a credentialed box's dial — a SYN-ACK from
        // the proxy's address toward the published inside port — is not an
        // opening packet, so it is not dropped by this rule. Delivered
        // toward the guest, it is the exact frame this hardening must never
        // withhold.
        let answer = dns_pins::tests::tcp_frame(
            Ipv4Addr::from(proxy),
            40000,
            Ipv4Addr::from(node_addr),
            7654,
            sessions::core::egress::TCP_SYN | sessions::core::egress::TCP_ACK,
        );
        send_frame(&mut switch, &answer).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            answer,
            "the proxy's SYN-ACK answer reaches the guest"
        );

        // The marker after them proves the dropped bare SYN was decided, and
        // nothing but the answer reached the guest.
        let marker = arp_frame(node_addr);
        send_frame(&mut switch, &marker).await;
        assert_eq!(
            expect_frame(&mut guest).await,
            marker,
            "the bare SYN never arrived; only the answer and the marker did"
        );
        expect_silence(&mut guest).await;
    }

    /// The §5.3 infrastructure deny set as a host frame rule
    /// ([`INFRASTRUCTURE_RULE`]), decided for every row before the row's own
    /// rules and before the deferral: a name-declaring row and a CIDR row
    /// that allows `0.0.0.0/0` are both refused to the metadata service
    /// (link-local) and to a box in another node's block of the fabric
    /// plane, whatever their rules admit — the deferral lifts nothing here,
    /// and neither does the widest allowance. The node's own block is the
    /// carve-out for a sibling and the daemon: the same CIDR row reaches a
    /// sibling, local reach the row's rules and the target's ingress decide.
    /// The host alias is not local reach — it is default-deny at every port
    /// (design §7.1, NET-062), refused under this rule whatever the row's
    /// rules admit. RFC 1918
    /// is the one exemption: a `10.0.0.0/8` destination is refused for the
    /// name-declaring row, whose declared `allow_subnets` does not cover it
    /// — the frame its deferral would otherwise have passed to the guest —
    /// and admitted for a row whose `allow_subnets` names the range, for the
    /// `0.0.0.0/0` row, and for a row with no `egress` section at all, whose
    /// undeclared dimension is the shipped allow-all and covers it the way
    /// the rebinding intersection's exemption holds it. Each drop names its
    /// destination and port under the rule, rate-limited per source, so the
    /// first refused frame of each source is the one whose line is read.
    /// Only a row the registry holds reaches the infrastructure check now
    /// (NET-085): a source no namespace holds is the unregistered-source
    /// drop's before this arm can ever see it, so the rows here are every
    /// source that can take this rule.
    #[tokio::test]
    async fn infrastructure_destinations_drop_on_the_host_for_every_row() {
        let registry = BoxRegistry::new(SUBNET);
        let open = [100, 64, 0, 10];
        let lan = [100, 64, 0, 11];
        let bare = [100, 64, 0, 12];
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
        // allowance: all admitted, each read back as sent. The host alias is
        // not among them — it is default-deny, refused below.
        let host_alias = SUBNET.host_alias().octets();
        let admitted = [
            ipv4_frame(open, 6, LEASE, 8080),
            ipv4_frame(open, 6, [10, 1, 2, 3], 80),
            ipv4_frame(lan, 6, [10, 1, 2, 3], 80),
            ipv4_frame(bare, 6, [10, 1, 2, 3], 80),
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
            ipv4_frame(open, 6, host_alias, 80),
            ipv4_frame(open, 6, metadata, 80),
            ipv4_frame(bare, 6, other_block, 80),
            ipv4_frame(LEASE, 6, metadata, 80),
            ipv4_frame(LEASE, 6, other_block, 80),
            ipv4_frame(open, 6, other_block, 80),
            ipv4_frame(bare, 6, metadata, 80),
            ipv4_frame(lan, 6, metadata, 80),
            ipv4_frame(lan, 6, other_block, 80),
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
            "destination=100.64.255.254",
            "source=100.64.0.11",
            "destination=169.254.169.254",
            "source=100.64.0.12",
            "destination=100.65.0.9",
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

    /// NET-134: the Box Egress Proxy's listener is a credentialed lane's
    /// infrastructure — the one host-side destination a box reaches by
    /// declaring the upstream, never by allowing its address. A box whose
    /// rules deny everything reaches the proxy's address at the proxy's own
    /// port, admitted beside its rules, while the same rules hold the rest
    /// of the host: no other host-side address answers the deny-all box,
    /// and no outside destination does either. The lane adds reach at one
    /// address and nowhere else.
    #[tokio::test]
    async fn credentialed_box_reaches_proxy_address_under_deny_all() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("laned", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_credentialed_upstream(sessions::CredentialedUpstream::default())
                .with_egress_policy(EgressPolicy {
                    // Deny-all: every IPv4 destination is denied, the
                    // spelling the activating client's `--deny-subnets
                    // 0.0.0.0/0` compiles to. The lane is admitted beside
                    // these rules, so it must survive them.
                    allow_protocols: None,
                    allow_subnets: None,
                    allow_dns_hosts: None,
                    deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                }),
        );
        let mut h = gate_over(registry).await;

        // The proxy's address, at the port its listener binds: admitted,
        // whatever the deny-all rules say about it — the frame reaches the
        // switch exactly as it was sent, because the credentials the proxy
        // redeems are the lane's own and no egress rule of the box's says
        // anything about them.
        let proxy = SUBNET.box_egress_proxy_address().octets();
        let to_proxy = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &to_proxy).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            to_proxy,
            "the laned box reaches the proxy's address under a deny-all row"
        );

        // No other host port and no other host address: the same box's
        // frames to the host alias — at the proxy's port and at another —
        // and to an outside destination are held by its own deny-all rules,
        // exactly as they would be without the lane. The marker after them
        // proves all were decided, and none passed: the proxy's address is
        // the lane's whole reach.
        let host_alias = SUBNET.host_alias().octets();
        let refused = [
            ipv4_frame(LEASE, 6, host_alias, 8118),
            ipv4_frame(LEASE, 6, host_alias, 80),
            ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443),
        ];
        for frame in &refused {
            send_frame(&mut h.guest, frame).await;
        }
        let marker = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "only the proxy's address answers the laned box; the marker at it still does"
        );
        expect_silence(&mut h.switch).await;
        assert!(
            !h.log
                .contents()
                .contains("egress-uncredentialed-proxy-destination"),
            "a laned box's frame to the proxy is not a proxy-lane drop, got: {}",
            h.log.contents()
        );
    }

    /// NET-134's refusal: a box without a credentialed lane has every frame
    /// to the proxy's address dropped at the gate, whatever its rules would
    /// say about the address — an allow-all box included, so the drop is the
    /// lane's absence, never a rule's. The drop is not a reset (NET-062):
    /// nothing answers, and the warn line says so — one rate-limited line
    /// per source per rule per interval, naming the box, the proxy's
    /// address, the port and the reason. A sibling box that declared the
    /// lane reaches the same address at the same port under the same rules,
    /// which is the proof the lane is the only thing that moved.
    #[tokio::test]
    async fn uncredentialed_box_dropped_at_proxy_address() {
        let registry = BoxRegistry::new(SUBNET);
        // The uncredentialed box: no policy at all, the allow-all default —
        // the rules that would admit any address, so the proxy's address is
        // refused by the lane's absence alone.
        let bare = [100, 64, 0, 9];
        // The sibling on a credentialed lane: the same allow-all rules, so
        // the only difference between the two boxes is the declaration.
        let laned = [100, 64, 0, 10];
        registry.register(
            BoxRegistration::new("bare", Ipv4Addr::from(bare), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        registry.register(
            BoxRegistration::new("laned", Ipv4Addr::from(laned), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_credentialed_upstream(sessions::CredentialedUpstream::default()),
        );
        let mut h = gate_over(registry).await;
        let proxy = SUBNET.box_egress_proxy_address().octets();

        // The uncredentialed box's frames to the proxy's address — the
        // proxy's own port, and another port at the same address, over TCP
        // and UDP — never reach the switch. The marker after them proves
        // all were decided before it, and none passed.
        let refused = [
            ipv4_frame(bare, 6, proxy, 8118),
            ipv4_frame(bare, 6, proxy, 8080),
            ipv4_frame(bare, 17, proxy, 8118),
        ];
        for frame in &refused {
            send_frame(&mut h.guest, frame).await;
        }
        let marker = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 80);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "no frame of the uncredentialed box reached the proxy's address; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // The drop says so, one line per source per rule: the box — by its
        // row's name, the diagnostics line's own ask — its address, the
        // proxy's address, the port and the reason — the line a diagnostic
        // bundle's daemon log tail reads a refused frame to the proxy from.
        wait_for_log(&h.log, "egress-uncredentialed-proxy-destination").await;
        let logged = h.log.contents();
        for needle in [
            "source=100.64.0.9",
            "destination=100.64.255.252",
            "port=8118",
            "box=\"bare\"",
            "rule_matched=\"egress-uncredentialed-proxy-destination\"",
        ] {
            assert!(
                logged.contains(needle),
                "the proxy-lane drop line carries {needle}, got: {logged}"
            );
        }
        assert_eq!(
            logged
                .matches("egress-uncredentialed-proxy-destination")
                .count(),
            1,
            "one warn line per source address per rule per interval, got: {logged}"
        );

        // The sibling on a lane reaches the same address at the same port
        // under the same rules: the declaration is the whole difference.
        let reach = ipv4_frame(laned, 6, proxy, 8118);
        send_frame(&mut h.guest, &reach).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            reach,
            "the laned sibling reaches the proxy's address at the same port under the same rules"
        );
    }

    /// NET-134's other refusal, the one a box that *has* the lane meets: the
    /// declaration opens the proxy's listener, not the proxy's address, so a
    /// frame to another port at the address — and a frame in another protocol
    /// to the listener's own port — is not the listener the lane admitted.
    /// The lane arm drops these frames before the row's own rules run,
    /// whatever those rules are, under the same proxy rule the lane-less
    /// box's frames take: the lane added one listener and no address, so
    /// nothing else at the host-gateway side of the switch opened. The drop
    /// is not a reset (NET-062), and the warn line names the box by its row's
    /// name — the box is on a lane, and the lane is exactly what did not
    /// admit the frame.
    #[tokio::test]
    async fn credentialed_box_dropped_at_proxy_address_other_port() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("laned", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_credentialed_upstream(sessions::CredentialedUpstream::default())
                .with_egress_policy(EgressPolicy {
                    // Deny-all, the spelling the activating client's
                    // `--deny-subnets 0.0.0.0/0` compiles to: the listener is
                    // admitted beside these rules, and nothing else at the
                    // address is.
                    allow_protocols: None,
                    allow_subnets: None,
                    allow_dns_hosts: None,
                    deny_subnets: Some(vec!["0.0.0.0/0".to_string()]),
                }),
        );
        let mut h = gate_over(registry).await;
        let proxy = SUBNET.box_egress_proxy_address().octets();

        // The lane's own half, as the control the drops below are read
        // against: the listener is admitted beside the deny-all, so what the
        // refused frames lose is the lane's narrowing, not its absence.
        let to_listener = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &to_listener).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            to_listener,
            "the laned box reaches the proxy's listener under a deny-all row"
        );

        // TCP to another port at the proxy's address, and UDP to the
        // listener's own port: none of these is the listener, so none
        // reaches the switch. The marker after them, at the listener itself,
        // proves every one was decided before it and none passed.
        let refused = [
            ipv4_frame(LEASE, 6, proxy, 443),
            ipv4_frame(LEASE, 6, proxy, 8080),
            ipv4_frame(LEASE, 17, proxy, 8118),
        ];
        for frame in &refused {
            send_frame(&mut h.guest, frame).await;
        }
        let marker = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "no frame to another port at the proxy's address reached the switch; the marker \
             at the listener still did"
        );
        expect_silence(&mut h.switch).await;

        // The drop says so under the proxy rule, naming the box by its row's
        // name and the first refused frame's port — the line a host reads to
        // learn that a laned box's frame was the lane's to refuse, not its
        // rules'.
        wait_for_log(&h.log, "egress-uncredentialed-proxy-destination").await;
        let logged = h.log.contents();
        for needle in [
            "source=100.64.0.9",
            "destination=100.64.255.252",
            "port=443",
            "box=\"laned\"",
            "rule_matched=\"egress-uncredentialed-proxy-destination\"",
        ] {
            assert!(
                logged.contains(needle),
                "the proxy-lane drop line carries {needle}, got: {logged}"
            );
        }
    }

    /// NET-134's anti-spoof ordering, the second half of the two the lane
    /// arm must keep: it runs after source attribution, because it reads the
    /// row the frame's source resolved to, so a frame to the listener is
    /// admitted only when its source is the address a lane-declaring row
    /// holds. The same frame wearing any other source is dropped: a sibling
    /// row that declared no lane is refused at the listener; an in-plan
    /// address no namespace holds dies at the source check under its own
    /// rule (NET-085), never reaching the lane arm; and an address outside
    /// the plan's run never reaches the lane arm either — the
    /// unknown-source refusal took it first, the same place a spoofed lease
    /// would die on the relay leg. Only the laned box's own address rides
    /// its lane.
    #[tokio::test]
    async fn spoofed_source_to_proxy_listener_dropped() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("laned", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_credentialed_upstream(sessions::CredentialedUpstream::default()),
        );
        registry.register(
            BoxRegistration::new(
                "bare",
                Ipv4Addr::from([100, 64, 0, 10]),
                Ipv4Addr::LOCALHOST,
            )
            .with_admitted_ports([8080]),
        );
        let mut h = gate_over(registry).await;
        let proxy = SUBNET.box_egress_proxy_address().octets();

        // The lane's own half: the frame from the address the laned row
        // holds reaches the listener — the control the drops below are read
        // against.
        let own = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &own).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            own,
            "the frame from the laned box's own address reaches the listener"
        );

        // The same frame wearing each other source: the sibling's address —
        // a published row, but one that declared no lane — an in-plan
        // address the plan could lease that no namespace holds — and a
        // stranger's from outside the plan's run. None is the laned row's
        // address, so none rides its lane, whatever the row would have
        // admitted had the frame come from it; and neither the
        // namespace-less sources ever reach the lane arm at all. The marker
        // after them proves every one was decided before it, and none
        // passed.
        let sibling = [100, 64, 0, 10];
        let unregistered = [100, 64, 0, 99];
        let stranger = [203, 0, 113, 7];
        let refused = [
            ipv4_frame(sibling, 6, proxy, 8118),
            ipv4_frame(unregistered, 6, proxy, 8118),
            ipv4_frame(stranger, 6, proxy, 8118),
        ];
        for frame in &refused {
            send_frame(&mut h.guest, frame).await;
        }
        let marker = ipv4_frame(LEASE, 6, proxy, 8118);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "no frame wearing another source reached the listener; the laned box's own did"
        );
        expect_silence(&mut h.switch).await;

        // The drops say so, each under the rule that decided it: the
        // sibling's under the proxy rule, the stranger's under the
        // unknown-source rule and the in-plan namespace-less one's under the
        // unregistered-source rule — both of which run before the lane arm
        // can be reached at all.
        wait_for_log(&h.log, "egress-unknown-source").await;
        let logged = h.log.contents();
        for needle in [
            "source=100.64.0.10",
            "box=\"bare\"",
            "source=100.64.0.99",
            "rule_matched=\"egress-uncredentialed-proxy-destination\"",
            "source=203.0.113.7",
            "rule_matched=\"egress-unknown-source\"",
            "rule_matched=\"egress-unregistered-source\"",
        ] {
            assert!(
                logged.contains(needle),
                "the spoofed-source drops carry {needle}, got: {logged}"
            );
        }
    }

    /// NET-134's third refusal: the node plane's own reach. The proxy's
    /// address is a credentialed lane's infrastructure, and the node plane
    /// is on no lane — its baseline set is the enumeration of the categories
    /// NET-130 admits, and no category names the proxy. So the set never
    /// admits the address: with the baseline in force a node frame to the
    /// proxy is dropped by the compiled set like any other undeclared
    /// destination, and while the interim allow-all node row still decides
    /// the node plane, that row declares no lane either, so the proxy rule
    /// drops it there too — the shipped arm and the flip hold one posture.
    #[test]
    fn baseline_set_never_admits_the_proxy_address() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let proxy = SUBNET.box_egress_proxy_address().octets();
        let node = baseline.node_addr();

        // The set's own membership: no category of the enumeration names the
        // proxy's address, so a later category that points at it fails here
        // rather than silently buying the node plane a lane.
        for entry in baseline.entries() {
            for endpoint in entry.endpoints() {
                let address = endpoint
                    .split_once('/')
                    .expect("an endpoint is spelled `a.b.c.d/n`")
                    .0;
                assert_ne!(
                    address,
                    Ipv4Addr::from(proxy).to_string(),
                    "the {} category must not name the box egress proxy's address; it is \
                     not a destination the node plane buys by enumeration",
                    entry.category().as_str(),
                );
            }
        }

        // In force: the node's frame to the proxy is decided by the compiled
        // set — and refused, at the proxy's port and over UDP too, because
        // the address is inside no category's endpoints.
        let in_force = baseline.clone().in_force();
        for (proto, port) in [(6, 8118), (17, 8118)] {
            let frame = sessions::core::egress::summarize(&ipv4_frame(node, proto, proxy, port));
            match gate_verdict(&frame, None, &table, &in_force, &pins, &ReplyTables::new()) {
                Ok(GateAdmit::Baseline) => panic!(
                    "the baseline set admitted the proxy's address at proto {proto} port {port}"
                ),
                Ok(admitted) => panic!(
                    "the in-force gate admitted a node frame to the proxy by another way: \
                     {admitted:?}"
                ),
                Err(drop) => assert!(
                    drop.rule() != PROXY_LANE_RULE,
                    "the in-force set refuses the proxy's address as an undeclared \
                     destination, not by the lane rule, got {}",
                    drop.rule(),
                ),
            }
        }

        // Announced, the shipped interim: the node row — allow-all, and the
        // row that decides the node plane until the flip — declares no lane,
        // so the proxy rule drops the same frame. Either posture, no reach.
        let frame = sessions::core::egress::summarize(&ipv4_frame(node, 6, proxy, 8118));
        assert!(
            matches!(
                gate_verdict(&frame, None, &table, &baseline, &pins, &ReplyTables::new()),
                Err(GateDrop::ProxyLane { .. })
            ),
            "the interim node row carries no lane, so its frame to the proxy is the proxy \
             rule's drop"
        );
    }

    /// NET-081's failure case, held unconditionally: a frame whose source
    /// address the plan could never hand to a box never leaves the VM, and
    /// a frame whose source the plan *could* hand out but no namespace
    /// holds never leaves it either (NET-085, T89 #1925) — two classes, two
    /// rules, one posture, whatever the egress default's phase is. The
    /// out-of-plan class keeps rule 0's ([`UNKNOWN_SOURCE_RULE`]); the
    /// in-plan class drops under its own ([`UNREGISTERED_SOURCE_RULE`]),
    /// whose relay-level pins — the line naming the source, once per source
    /// per interval, the table left untouched, toward every destination —
    /// are carried by [`unregistered_sources_dropped`].
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
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        for frame in [&outside_plan, &beyond_subnet, &foreign_arp, &v6] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the published box's frame passes; no frame whose source the plan \
             could never hand out did"
        );
        expect_silence(&mut h.switch).await;

        // Two frames whose source the plan could hand out but no row holds:
        // a made-up lease, and the withdrawn namespace's — in-plan both, so
        // rule 0 is not theirs, and dropped toward a destination the one
        // published row would itself admit, because the class of the
        // source, not the destination, refuses them (NET-085). The marker
        // after them proves both were decided and neither passed.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let from_retired = ipv4_frame(withdrawn, 6, [10, 1, 2, 3], 80);
        for frame in [&made_up, &from_retired] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "an in-plan source no row holds is dropped like an out-of-plan one; \
             the published box's frame is the only one that passed"
        );
        expect_silence(&mut h.switch).await;

        // The drops are named, each under its own rule: the out-of-plan
        // sources under NET-081's own — the gateway's IPv4 frame and its ARP
        // share one line, the foreign subnet's has its own — the IPv6 family
        // under its own, with no source to name, and the in-plan pair under
        // the unregistered rule's line, one line per source.
        wait_for_log(&h.log, "egress-unknown-source").await;
        wait_for_log(&h.log, "egress-ipv6").await;
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
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
        for src in [stranger, withdrawn] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "the unregistered drop's line names the source address {src:?}, \
                 got: {logged}"
            );
        }
        assert_eq!(
            logged.matches(UNREGISTERED_SOURCE_RULE).count(),
            2,
            "one drop line per unregistered source, got: {logged}"
        );

        // And only one per source per interval: a second frame from the same
        // made-up lease drops again and adds no second line inside the
        // window.
        send_frame(&mut h.guest, &made_up).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the same unregistered source's repeat frame drops again, passing nothing"
        );
        expect_silence(&mut h.switch).await;
        assert_eq!(
            h.log.contents().matches(UNREGISTERED_SOURCE_RULE).count(),
            2,
            "one drop line per source per interval, got: {}",
            h.log.contents()
        );

        // What the drops did not do: publish. The made-up lease and the
        // withdrawn namespace still hold no row — the table is filled on the
        // host, never from the guest's wire, a drop included — and the one
        // published box is still held.
        assert!(
            h.table.by_source(stranger).is_none(),
            "the guest's made-up address published no row"
        );
        assert!(
            h.table.by_source(withdrawn).is_none(),
            "a drop at the gate is not a re-registration"
        );
        assert!(
            h.table.by_source(LEASE).is_some(),
            "the one published box is still held"
        );
    }

    /// NET-085, the in-plan half of NET-081's failure case, pinned **at relay
    /// level** on a live gate built under the shipped phase
    /// ([`gate_over`]; the production entry's own pin is
    /// [`shipped_gate_drops_unregistered_in_plan_source`]): a frame whose
    /// source the plan could hand out but no row holds
    /// is dropped toward every destination — a subnet the one published row
    /// declares, and the node plane's own baseline set, the categories the
    /// enumeration admits, included — whatever the egress default's phase
    /// is, because no phase reaches the frame half. A made-up lease, the
    /// withdrawn namespace's address, and an ARP announcing an unpublished
    /// in-plan address — the sender address an ARP frame's source is read
    /// from, so resolution is no way in — all drop, while the published
    /// box's frames are still decided by its row, and the drops are named,
    /// once per source, under [`UNREGISTERED_SOURCE_RULE`].
    #[tokio::test]
    async fn unregistered_sources_dropped() {
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

        // Five frames whose source the plan could hand out but no row holds:
        // a made-up lease and the withdrawn namespace's, each toward a
        // destination the published row itself declares; the same two toward
        // the baseline set's own destination, the host alias the node plane's
        // categories enumerate — the drop's reach is every destination, that
        // set included, because the class of the source refuses the frame
        // before any destination is consulted; and an ARP announcing the
        // made-up lease — an unpublished in-plan address smuggled in as a
        // sender protocol address. The marker after them is the one published
        // box's, so its arrival proves all five were decided and none
        // passed.
        let stranger = [100, 64, 0, 99];
        let host_alias = SUBNET.host_alias().octets();
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let from_retired = ipv4_frame(withdrawn, 6, [10, 1, 2, 3], 80);
        let made_up_baseline = ipv4_frame(stranger, 6, host_alias, 80);
        let retired_baseline = ipv4_frame(withdrawn, 6, host_alias, 80);
        let unpublished_arp = arp_frame(stranger);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        for frame in [
            &made_up,
            &from_retired,
            &made_up_baseline,
            &retired_baseline,
            &unpublished_arp,
        ] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the published box's frame is the only one that passed: every \
             unregistered source was dropped before the switch, toward its \
             declared destinations and the baseline set's alike"
        );
        expect_silence(&mut h.switch).await;

        // The drops are named: one line per source under the unregistered
        // rule — the four IPv4 frames of the two sources make two lines, and
        // the ARP announcing the made-up lease shares its source's window —
        // and no unknown-source line at all, because every source here is
        // in-plan.
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
        let logged = h.log.contents();
        for src in [stranger, withdrawn] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "a drop line names the source address {src:?}, got: {logged}"
            );
        }
        assert_eq!(
            logged.matches(UNREGISTERED_SOURCE_RULE).count(),
            2,
            "five unregistered-source frames make two lines (the ARP shares its \
             source's window), got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "every source here is inside the plan's lease run, so rule 0 is \
             not theirs to drop under, got: {logged}"
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

    /// The production entry pins the same drop: a gate built through
    /// [`EgressGate::spawn`] — the entry `crate::net` calls, whose gate takes
    /// its phase from the shipped constant and builds its own reply-flow
    /// tables, so no test parameter shapes the decision — drops a frame
    /// whose source is an in-plan address no row holds, toward a destination
    /// the one published row itself declares, and the drop's line is the
    /// unregistered rule's, naming the source. The entry takes no phase at
    /// all, so this is the proof that the gate a VM host runs drops such a
    /// frame by construction (NET-085).
    #[tokio::test]
    async fn shipped_gate_drops_unregistered_in_plan_source() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over_shipped(registry).await;

        // One frame from an in-plan lease no row holds, toward a destination
        // the published row itself declares, then the published row's own
        // frame as the marker: its arrival proves the first was decided and
        // dropped.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &made_up).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the gate the production entry built drops the in-plan source no \
             row holds; the published box's frame is the only one that passed"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
        assert!(
            h.log
                .contents()
                .contains(&format!("source={}", Ipv4Addr::from(stranger))),
            "the drop line names the made-up lease, got: {}",
            h.log.contents()
        );
        assert!(
            h.table.by_source(stranger).is_none(),
            "the gate registered nothing from what the guest said it held"
        );
    }

    /// The drop NET-085 adds governs the rowless source alone: a frame whose
    /// source a row holds is still decided by that row under the shipped
    /// phase — admitted where its rules admit, refused where they refuse,
    /// under its own rules' lines — while the same destinations reached from
    /// an in-plan source no row holds are the unregistered drop's. One
    /// destination, two sources, two verdicts: the row's and the source
    /// check's, and neither borrows the other's rule.
    #[tokio::test]
    async fn registered_box_decided_by_its_row_under_shipped_phase() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // The row's own verdicts hold: its declared egress reaches the
        // switch untouched, and its refusal of an undeclared protocol is its
        // own — under its own rule's line, not the unregistered one.
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        let undeclared_proto = ipv4_frame(LEASE, 17, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &declared).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            declared,
            "the row's declared egress still reaches the switch, untouched"
        );
        send_frame(&mut h.guest, &undeclared_proto).await;
        send_frame(&mut h.guest, &declared).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            declared,
            "the row's undeclared protocol is the row's own refusal, and the \
             declared frame after it still passes"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "egress-undeclared-protocol").await;
        assert!(
            !h.log.contents().contains(UNREGISTERED_SOURCE_RULE),
            "a registered box's refusals are its own rules', never the \
             unregistered drop's, got: {}",
            h.log.contents()
        );

        // The same declared destination from an in-plan source no row holds:
        // the unregistered drop's, under its own rule — the rowless source's
        // verdict, not the destination's and not the row's.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &made_up).await;
        send_frame(&mut h.guest, &declared).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            declared,
            "toward the same destination the row's frame passes where the \
             rowless source's dropped"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
    }

    /// The egress default's phase is untouched by the frame half's new drop
    /// (NET-085): a row the registry holds that declared no egress section
    /// still compiles to the shipped allow-all an absent section always did,
    /// so its frames reach whatever the shared verdict admits — and the
    /// publish decision still reads the shipped announced phase
    /// ([`UnregisteredSourcePhase::into_sessions_phase`]), applying a publish
    /// at an in-plan address no row holds and marking it interim. The
    /// unregistered drop governs only the source no row holds; a registered
    /// box keeps everything the section's absence conceded.
    #[tokio::test]
    async fn undeclared_own_ip_box_unchanged_by_unregistered_drop() {
        let registry = BoxRegistry::new(SUBNET);
        // A bare row: no egress section, the shipped allow-all an absent
        // section compiles to.
        let bare = [100, 64, 0, 10];
        registry.register(
            BoxRegistration::new("bare", Ipv4Addr::from(bare), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let mut h = gate_over(registry).await;

        // The bare row's frame still reaches whatever the allow-all admits —
        // the frame half's new drop took nothing a declared section's
        // absence ever conceded.
        let admitted = ipv4_frame(bare, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &admitted).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            admitted,
            "a registered box with no egress section keeps the shipped allow-all"
        );

        // While an in-plan source no row holds drops, under the new rule —
        // the frame half's drop and a declared section's absence are two
        // different things, and only the rowless source takes the new line.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &made_up).await;
        send_frame(&mut h.guest, &admitted).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            admitted,
            "the bare row's frame still passes where the rowless source's dropped"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;

        // And the publish half still reads the shipped announced phase: a
        // publish at an in-plan lease no row holds is applied, marked as the
        // interim's own line, under the unregistered publish rule. The
        // default the row's absent section compiles from is the phase's,
        // and NET-085's frame-level drop does not move it.
        let expose = expose_request("127.0.0.1:8080", "100.64.0.11:8080", "tcp");
        let (mut guest, mut switch) = connect_control(&h).await;
        guest.write_all(&expose).await.expect("writing the expose");
        let mut spoken = vec![0u8; expose.len()];
        read_within(&mut switch, &mut spoken).await;
        assert_eq!(spoken, expose, "the interim publish reached the switch");
        wait_for_log(&h.log, UNREGISTERED_PUBLISH_RULE).await;
        assert!(
            h.log.contents().contains("interim=true"),
            "an applied interim still says so on its own line, got: {}",
            h.log.contents()
        );
    }

    /// The one drop whose line the gate's own ledger can point a host at a
    /// remedy through: an applied publish standing at an address no row
    /// holds is the host-observable fact that a live namespace holds the
    /// lease — the guest daemon vouched for the address in the publish's
    /// own request — so a frame from it drops under the live-lease rule,
    /// whose line names the lease and the remedy (the box predates host
    /// registration, T66, #1711; restarting it registers it), while a
    /// rowless source with no applied publish takes the generic
    /// unregistered line. Both drop the frame exactly the same way, and
    /// neither mints a row: the gate registers no box from what the guest
    /// says it holds.
    #[tokio::test]
    async fn unregistered_live_lease_warns_box_predates_registration() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A gate whose first connection is the control leg, so the publish
        // stands before any frame is decided.
        let mut h = gate_connected(registry).await;

        // The box's own publish, at an in-plan lease the plan could hand out
        // and no row holds — the shape a box that predates host registration
        // speaks (T66, #1711 is the registration that will publish its row).
        // Applied, marked interim, so the gate's ledger holds an applied
        // publish at the address: the host-observable fact that a live
        // namespace holds the lease.
        let lease = [100, 64, 0, 10];
        let expose = expose_request("127.0.0.1:8080", "100.64.0.10:8080", "tcp");
        h.guest
            .write_all(&expose)
            .await
            .expect("writing the expose");
        let mut spoken = vec![0u8; expose.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(spoken, expose, "the box's publish reached the switch");
        wait_for_log(&h.log, UNREGISTERED_PUBLISH_RULE).await;

        // The box's frame from that lease: dropped — no row holds the
        // source — and the drop's line is the live lease's, not the generic
        // unregistered one, naming the lease and the remedy.
        let (mut guest, mut switch) = connect_over(&h).await;
        let from_lease = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &from_lease).await;
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the live lease's frame drops: the publish informs the line, never \
             the verdict"
        );
        expect_silence(&mut switch).await;
        wait_for_log(&h.log, UNREGISTERED_LIVE_LEASE_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains(&format!("source={}", Ipv4Addr::from(lease))),
            "the live-lease line names the lease, got: {logged}"
        );
        assert!(
            logged.contains("predates host registration"),
            "the live-lease line names the remedy — the box predates host \
             registration, so restarting it registers it — got: {logged}"
        );

        // A rowless source with no applied publish standing at it takes the
        // generic unregistered line, under its own rule: the ledger's entry
        // is what picks the line, and only the line — the drop is the same
        // either way.
        let stranger = [100, 64, 0, 99];
        let made_up = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &made_up).await;
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the rowless source without a publish drops exactly the same way"
        );
        expect_silence(&mut switch).await;
        wait_for_log(&h.log, UNREGISTERED_SOURCE_RULE).await;
        let logged = h.log.contents();
        assert_eq!(
            logged.matches(UNREGISTERED_LIVE_LEASE_RULE).count(),
            1,
            "one live-lease line for the one lease, got: {logged}"
        );
        assert_eq!(
            logged.matches(UNREGISTERED_SOURCE_RULE).count(),
            1,
            "one generic unregistered line for the publish-less source, got: {logged}"
        );
        assert!(
            logged.contains(&format!("source={}", Ipv4Addr::from(stranger))),
            "the generic unregistered line names the rowless source, got: {logged}"
        );

        // And neither drop minted a row: the publish informed a line, not a
        // registration — the gate never registers a box from what the guest
        // says it holds.
        assert!(
            h.table.by_source(lease).is_none(),
            "an applied publish registers no box at the lease it named"
        );
    }

    /// A guest lease that has published only its zone name — no port, so
    /// no forward stands at it — is still a live lease the guest daemon
    /// vouched for: the applied zone-name request named the address as the
    /// box's own. A frame from it drops like any rowless source, and the
    /// drop's line is the live lease's, naming the lease and the remedy,
    /// not the generic unregistered one. The request informs the line only:
    /// the frame drops, and no row is minted from it.
    #[tokio::test]
    async fn unregistered_lease_with_only_a_zone_name_warns() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_connected(registry).await;

        // The zone name alone, at an in-plan lease no row holds: the shape a
        // box that predates host registration speaks before it publishes
        // any port. Applied under the interim.
        let lease = [100, 64, 0, 10];
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.10"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        h.guest
            .write_all(&request)
            .await
            .expect("writing the zone-name request");
        let mut spoken = vec![0u8; request.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(spoken, request, "the zone-name request reached the switch");
        wait_for_log(&h.log, UNREGISTERED_PUBLISH_RULE).await;

        // The lease's frame: dropped, under the live lease's line.
        let (mut guest, mut switch) = connect_over(&h).await;
        let from_lease = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut guest, &from_lease).await;
        send_frame(&mut guest, &marker).await;
        assert_eq!(
            expect_frame(&mut switch).await,
            marker,
            "the zone-name-only lease's frame drops; the marker passes"
        );
        expect_silence(&mut switch).await;
        wait_for_log(&h.log, UNREGISTERED_LIVE_LEASE_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains(&format!("source={}", Ipv4Addr::from(lease))),
            "the live-lease line names the lease, got: {logged}"
        );
        assert!(
            logged.contains("predates host registration"),
            "the live-lease line names the remedy, got: {logged}"
        );
        assert!(
            !logged.contains(UNREGISTERED_SOURCE_RULE),
            "the zone-name-only lease takes the live-lease line, not the generic \
             one, got: {logged}"
        );
        assert!(
            h.table.by_source(lease).is_none(),
            "an applied zone name registers no box at the lease it named"
        );
    }

    /// The undeclared-subnet drop line carries what the frame named beside
    /// the source and the rule: the destination address and the port it
    /// refused, the way the infrastructure line does, so a host reads which
    /// address a box reached for that its row never declared — and at which
    /// port — from the line alone, without grepping the switch for the frame
    /// the gate dropped.
    #[tokio::test]
    async fn undeclared_subnet_drop_line_names_destination() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // The row's frame toward an address its declared subnet does not
        // name — TEST-NET-2, outside `10.0.0.0/8`, a plain destination the
        // row simply did not declare — then the marker, whose arrival proves
        // the first was decided and dropped.
        let frame = ipv4_frame(LEASE, 6, [198, 51, 100, 7], 443);
        send_frame(&mut h.guest, &frame).await;
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the undeclared destination's frame never reached the switch; the \
             marker after it did"
        );
        expect_silence(&mut h.switch).await;

        // The line names the four things the requirement asks for: the
        // source, the destination address it refused, the port the frame gave
        // it, and the rule.
        wait_for_log(&h.log, "egress-undeclared-subnet").await;
        let logged = h.log.contents();
        for needle in [
            "source=100.64.0.9",
            "destination=198.51.100.7",
            "port=443",
            "rule_matched=\"egress-undeclared-subnet\"",
        ] {
            assert!(
                logged.contains(needle),
                "the undeclared-subnet drop line carries {needle}, got: {logged}"
            );
        }
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
        // exchange is not a frame, and no frame verdict ran on it — no
        // frame-drop line exists, which is what the needle below reads:
        // the start-up line names the gate's postures (`unregistered_sources
        // = "dropped"`), so the bare word is the gate's own vocabulary and
        // the drop lines' opening words are the verdict's trace.
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
            !logged.contains("dropped a frame"),
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
        // request line. A frame verdict never ran on this connection, so
        // no frame-drop line exists — the needle reads the drop lines'
        // own words, not the bare word "dropped", which the start-up line
        // now uses to name the gate's unregistered-source posture.
        let logged = h.log.contents();
        assert!(
            !logged.contains("egress-control-upgrade"),
            "a body carrying the connect path was refused as an upgrade, got: {logged}"
        );
        assert!(
            !logged.contains("dropped a frame"),
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
            crate::net::dns_pins::DnsPins::new(SUBNET),
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
            dns_pins::DnsPins::new(SUBNET),
            ReplyTables::new(),
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
            dns_pins::DnsPins::new(SUBNET),
            ReplyTables::new(),
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
                dns_pins::DnsPins::new(SUBNET),
                ReplyTables::new(),
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
            dns_pins::DnsPins::new(SUBNET),
            ReplyTables::new(),
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
                dns_pins::DnsPins::new(SUBNET),
                ReplyTables::new(),
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
    /// and a source no row holds is nobody's to admit: outside the plan's
    /// lease block it is rule 0's refusal, inside it the unregistered drop's
    /// (NET-085), both pinned here as two rules because no phase reaches
    /// the frame half any more. The node plane's own address is the baseline
    /// set's to decide beside the rows: its shipped arm is pinned by
    /// [`node_plane_source_decided_by_the_node_row_while_announced`], its
    /// in-force arm at relay level by
    /// [`unenrolled_baseline_set_from_helper_enumeration`].
    #[test]
    fn gate_verdict_decides_by_source_and_rules() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        // The pin table this row's undeclared destinations would be decided
        // against: empty, because the row declared no names and no reply has
        // been observed — the arm below stays unreachable for it.
        let pins = dns_pins::DnsPins::new(SUBNET);
        let summarize = sessions::core::egress::summarize;

        // A held source is decided by its rules: the same frame that the
        // relay test watches pass and drop, decided here with no sockets.
        let declared = summarize(&ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80));
        assert!(matches!(
            gate_verdict(
                &declared,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
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
            gate_verdict(
                &undeclared,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Err(GateDrop::Verdict(DropReason::UndeclaredSubnet {
                dst: [203, 0, 113, 7],
                proto: 6,
            }))
        );

        // The switch's own address is not a row's to decide: a frame to the
        // gateway that is not a resolver query is refused, whatever the rows
        // hold — the gateway is a control surface, and the refusal sits ahead
        // of the row's decision, so no rules are ever read for it.
        let surface = summarize(&ipv4_frame(LEASE, 6, SUBNET.gateway().octets(), 443));
        assert_eq!(
            gate_verdict(
                &surface,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 443
            })
        );
        // An in-plan source no row holds naming the switch's own address is
        // the control surface's drop too, not the unregistered rule's: the
        // ceiling the control-surface refusal adds sits ahead of the source
        // routing as well, so a frame that names a port nothing published
        // answers is refused there whatever its source is.
        let unregistered_surface = summarize(&ipv4_frame(
            [100, 64, 0, 99],
            6,
            SUBNET.gateway().octets(),
            443,
        ));
        assert_eq!(
            gate_verdict(
                &unregistered_surface,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
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
            gate_verdict(
                &resolver,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Ok(GateAdmit::Row)
        ));
        // A row's admitted ports are no carve-out: they are the box's own
        // ingress, reached on its own address, and a frame to the gateway at
        // one of them (this row admits 8080) is refused like any other port
        // there — the row is never consulted.
        let ingress_port = summarize(&ipv4_frame(LEASE, 6, SUBNET.gateway().octets(), 8080));
        assert_eq!(
            gate_verdict(
                &ingress_port,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Err(GateDrop::SwitchControlSurface {
                src: LEASE,
                dst_port: 8080
            })
        );

        // A source no row holds is nobody's to admit (NET-085): an address
        // inside the run the plan allocates PTask leases from — the lease
        // the guest daemon's own allocator could have minted — drops under
        // the unregistered rule, toward every destination alike, whatever
        // the egress default's phase is, because no phase reaches the frame
        // half.
        let unknown = summarize(&ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80));
        assert_eq!(
            gate_verdict(
                &unknown,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Err(GateDrop::UnregisteredSource {
                src: [100, 64, 0, 99]
            })
        );

        // The unregistered drop never borrows the plan's infrastructure as a
        // source either: the gateway the resolver carve-out is keyed to is
        // the plan's own infrastructure, and an ARP announcing it is no way
        // to smuggle one past — in-guest, ARP is a declared path for every
        // box, so the address it announces is the thing that has to be
        // refused. Both are rule 0's, the refusal an out-of-plan source has
        // always taken.
        let gateway = summarize(&ipv4_frame(
            SUBNET.dns_server().octets(),
            6,
            [10, 1, 2, 3],
            80,
        ));
        assert_eq!(
            gate_verdict(
                &gateway,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Err(GateDrop::UnknownSource {
                src: SUBNET.dns_server().octets()
            })
        );
        let foreign_arp = summarize(&arp_frame([203, 0, 113, 7]));
        assert_eq!(
            gate_verdict(
                &foreign_arp,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
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
            gate_verdict(&v6, None, &empty, &baseline, &pins, &ReplyTables::new()),
            Err(GateDrop::Verdict(DropReason::Ipv6))
        );
        let truncated = summarize(&[0u8; 13]);
        assert_eq!(
            gate_verdict(
                &truncated,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
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
    /// recorded — source, destination, protocol, port, the baseline's
    /// phase, and the verdict — and the record is printed one line per
    /// attempt, grouped by spoofed source, in the gate's drop-line shape, so
    /// the bound a spoof bought can be read straight off the output.
    ///
    /// Where the shipped posture differs from the bound's shape the test
    /// pins both arms, the way the relay tests do: while the node baseline
    /// is announced the node row is allow-all — the gap the baseline
    /// phase's flip (#1786) closes. An in-plan source no row holds is not a
    /// posture any more (NET-085): it drops under the unregistered rule in
    /// every list, the frame half having no interim, so the record's two
    /// halves vary the baseline alone.
    #[test]
    fn spoofed_source_bounded_to_resident_union() {
        /// One spoofed attempt as the record holds it: the frame wore, and
        /// what the gate decided, tagged by the node baseline's phase the
        /// decision ran under — a box's row, the node row, the baseline
        /// set, or a drop's rule.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Attempt {
            src: [u8; 4],
            dst: [u8; 4],
            proto: u8,
            port: u16,
            phase: NodeBaselinePhase,
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
            /// The row's declared credentialed lane admitted the frame at
            /// the proxy's address (NET-134): the admission no rules made.
            AdmittedByProxyLane,
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
        /// records the verdict under the decision's own name, tagged by the
        /// baseline posture it ran under.
        fn decide(
            table: &BoxTable,
            baseline: &NodePlaneBaseline,
            pins: &dns_pins::DnsPins,
            src: [u8; 4],
            proto: u8,
            dst: [u8; 4],
            port: u16,
        ) -> Attempt {
            let frame = sessions::core::egress::summarize(&ipv4_frame(src, proto, dst, port));
            // No reply-flow records exist for any of these attempts — nothing
            // was ever delivered toward a box's published port — so the empty
            // table is the one the pure decision reads, and the frame's verdict
            // is the row's and the baseline's alone.
            let verdict =
                match gate_verdict(&frame, None, table, baseline, pins, &ReplyTables::new()) {
                    Ok(GateAdmit::Baseline) => Verdict::AdmittedByBaseline,
                    Ok(GateAdmit::Row) if src == baseline.node_addr() => Verdict::AdmittedByNodeRow,
                    Ok(GateAdmit::Row) => Verdict::AdmittedByRow,
                    Ok(GateAdmit::ProxyLane) => Verdict::AdmittedByProxyLane,
                    Err(drop) => Verdict::Dropped(drop.rule()),
                };
            Attempt {
                src,
                dst,
                proto,
                port,
                phase: baseline.phase(),
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
        registry.register_node_namespace(7654);
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        // The pin table the attempts are decided against: empty — no row
        // declared a name, so the pin arm is unreachable here and every
        // attempt is decided by the rows and the baseline set.
        let pins = dns_pins::DnsPins::new(SUBNET);
        let node = baseline.node_addr();
        // The node-baseline posture this build ships: announced, the
        // allow-all node row. The frame half's own posture has no arms
        // (NET-085) — an unregistered in-plan source drops in every list —
        // so the record's second list varies the baseline alone.
        let shipped = NodeBaselinePhase::Announced;
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
        // (baseline posture, source, protocol, destination, port), and each
        // is summarized, decided by [`gate_verdict`], and recorded exactly
        // as the gate's relay would hand the frame over. The in-force world
        // is the one the baseline flip creates — the compiled baseline set
        // binding beside the rows — built here so the in-force arms have
        // their proof before the flip lands.
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
            // An in-plan address no row holds: dropped under the
            // unregistered rule, under no phase — NET-085's drop is the
            // frame half's unconditional posture, so this list and the
            // in-force one pin the same verdict for it. An address outside
            // the plan's lease block is rule 0's under both baseline
            // postures: outside the plan there is no lease to spoof.
            (shipped, stray, 6, web_only, 80),
            (shipped, out_of_plan_src, 6, web_only, 80),
        ]
        .into_iter()
        .map(|(_, src, proto, dst, port)| decide(&table, &baseline, &pins, src, proto, dst, port))
        .collect();
        let in_force_attempts: Vec<Attempt> = [
            // The node plane's own address, under the in-force baseline set:
            // bounded by the enumeration, decided beside the boxes' rows, and
            // so a spoof of the daemon's address buys the set, not a box's
            // row.
            (NodeBaselinePhase::InForce, node, 6, baseline_endpoint, 443),
            (NodeBaselinePhase::InForce, node, 6, web_only, 80),
            (NodeBaselinePhase::InForce, node, 6, outside, 443),
            // The unrowed in-plan source under the in-force baseline: the
            // same unregistered drop the shipped list pins — the baseline's
            // phase does not reach the frame half either (NET-085).
            (NodeBaselinePhase::InForce, stray, 6, web_only, 80),
            (NodeBaselinePhase::InForce, out_of_plan_src, 6, web_only, 80),
        ]
        .into_iter()
        .map(|(_, src, proto, dst, port)| {
            decide(&table, &baseline_in_force, &pins, src, proto, dst, port)
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
                        "  destination={}:{}({}) baseline={} action=drop rule_matched=\"{rule}\"",
                        Ipv4Addr::from(attempt.dst),
                        attempt.port,
                        proto_of(attempt.proto),
                        attempt.phase.as_str(),
                    ),
                    verdict => println!(
                        "  destination={}:{}({}) baseline={} action=admit decision={verdict:?}",
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
                // The shipped allow-all node row's admits are the gap,
                // pinned to its in-force replacement by the verdict lookups
                // below. A proxy-lane admit is none of this test's attempts
                // — no attempt names the proxy's address — and the arm
                // keeps the match exhaustive for the ones that will.
                Verdict::AdmittedByNodeRow | Verdict::AdmittedByProxyLane | Verdict::Dropped(_) => {
                }
            }
        }

        // The universal the table makes cheap, beside the membership loop
        // above — NET-085 as a bound, not a list. Two halves:
        //
        // - no attempt decided against the in-force baseline set carries the
        //   allow-all node row's verdict: with the compiled baseline binding
        //   there is no interim node row to fall through to, whichever way a
        //   future edit reorders the decision;
        // - every admit a frame is given is the row that holds the source's
        //   own doing: the row `table.by_source(src)` holds is the row whose
        //   rules admit the destination, never another box's row and never a
        //   union read out of the table. The per-pair pins below name the
        //   destinations; this binds the shape over the whole record, so a
        //   future attempt is covered without being pinned.
        for attempt in &attempts {
            if attempt.phase == NodeBaselinePhase::InForce {
                assert!(
                    !matches!(attempt.verdict, Verdict::AdmittedByNodeRow),
                    "an in-force attempt of {} carries the announced node row's \
                     verdict ({:?}); the in-force decision has no allow-all node row",
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
            verdict_of(NodeBaselinePhase::InForce, node, 6, baseline_endpoint, 443),
            Verdict::AdmittedByBaseline,
        );
        assert_eq!(
            verdict_of(NodeBaselinePhase::InForce, node, 6, web_only, 80),
            Verdict::Dropped("egress-undeclared-subnet"),
        );
        assert_eq!(
            verdict_of(NodeBaselinePhase::InForce, node, 6, outside, 443),
            Verdict::Dropped("egress-undeclared-subnet"),
        );

        // The allow-all node row's arm, with the in-force arm it becomes: the
        // node row admits the outside destination today, and the baseline
        // phase's flip (#1786) turns it into the drop above. The unrowed
        // in-plan source drops under the unregistered rule under both
        // baseline postures — NET-085's drop is unconditional, so no arm
        // waits on a flip for it — and the out-of-plan source stays rule
        // 0's under both, so nothing borrows the plan's infrastructure as a
        // source.
        assert_eq!(
            verdict_of(shipped, node, 6, outside, 443),
            Verdict::AdmittedByNodeRow,
        );
        assert_eq!(
            verdict_of(shipped, stray, 6, web_only, 80),
            Verdict::Dropped("egress-unregistered-source"),
        );
        assert_eq!(
            verdict_of(NodeBaselinePhase::InForce, stray, 6, web_only, 80),
            Verdict::Dropped("egress-unregistered-source"),
        );
        assert_eq!(
            verdict_of(shipped, out_of_plan_src, 6, web_only, 80),
            Verdict::Dropped("egress-unknown-source"),
        );
        assert_eq!(
            verdict_of(NodeBaselinePhase::InForce, out_of_plan_src, 6, web_only, 80),
            Verdict::Dropped("egress-unknown-source"),
        );

        // ARP is a declared path for every box, decided per frame with no
        // destination to bound: a spoofed announcement wearing web's address
        // is admitted by web's row the same as any resolution web's own
        // traffic would carry. It buys no reach — the flow frames behind it
        // are what the rows bound, each on its own.
        let spoofed_arp = sessions::core::egress::summarize(&arp_frame(LEASE));
        assert!(matches!(
            gate_verdict(
                &spoofed_arp,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
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
        // proxy port the boot line hands the guest daemon.
        registry.register_node_namespace(7654);
        let table = registry.table();
        // Built without [`NodePlaneBaseline::in_force`], so this is the
        // phase the build ships.
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        assert_eq!(
            baseline.phase(),
            NodeBaselinePhase::Announced,
            "the shipped posture is announced, the arm this test pins"
        );
        // The pin table, empty as the run path hands it: the node row
        // declares no names.
        let pins = dns_pins::DnsPins::new(SUBNET);

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
            gate_verdict(
                &node_frame,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Ok(GateAdmit::Row),
            "announced, the interim node row decides the node plane's frames — \
             never the baseline set"
        );
    }

    /// The host alias's default-deny is a box row's alone (design §7.1,
    /// NET-062). Announced, the interim node row at the daemon's address
    /// carries the frames of every box sharing the guest root namespace — a
    /// host-address box, the default network mode, whose `host.min.internal`
    /// resolves to the alias — so a node-plane frame to the alias is
    /// own-block local reach the row admits, while the same frame from a box
    /// lease, even an allow-all one, is the infrastructure drop.
    #[test]
    fn host_alias_refused_for_box_rows_but_not_the_announced_node_row() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        registry.register(
            BoxRegistration::new("bare", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080]),
        );
        let table = registry.table();
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        assert_eq!(baseline.phase(), NodeBaselinePhase::Announced);
        let pins = dns_pins::DnsPins::new(SUBNET);
        let summarize = sessions::core::egress::summarize;
        let alias = SUBNET.host_alias().octets();

        let node_frame = summarize(&ipv4_frame(SUBNET.daemon_ip().octets(), 6, alias, 18081));
        assert_eq!(
            gate_verdict(
                &node_frame,
                None,
                &table,
                &baseline,
                &pins,
                &ReplyTables::new()
            ),
            Ok(GateAdmit::Row),
            "the announced node row keeps own-block reach to the host alias"
        );

        let box_frame = summarize(&ipv4_frame(LEASE, 6, alias, 18081));
        assert!(
            matches!(
                gate_verdict(
                    &box_frame,
                    None,
                    &table,
                    &baseline,
                    &pins,
                    &ReplyTables::new()
                ),
                Err(GateDrop::Infrastructure { dst, .. }) if dst == alias
            ),
            "a box row's frame to the host alias is the infrastructure drop"
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

    /// The proxy-opening drop's line answers to the drop cadence per box:
    /// one line for a box's first dropped opening packet, silence for the
    /// next within the interval, and its own line for another box.
    #[test]
    fn proxy_opening_drop_line_is_rate_limited_per_box() {
        let limiter = DropLimiter::new();
        assert!(limiter.warn_proxy_opening([100, 64, 0, 10], "web", 7654));
        assert!(!limiter.warn_proxy_opening([100, 64, 0, 10], "web", 7654));
        assert!(limiter.warn_proxy_opening([100, 64, 0, 11], "api", 7654));
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
    /// retraction was attributed to the first box. The entry carries the
    /// publish's inside end beside that address — the port the reply-flow
    /// recording is bounded by — so it goes where its address went.
    #[test]
    fn two_boxes_publishing_one_port_keep_their_own_attribution() {
        let (network, _) = switch::RESERVED_LOCAL_RANGE;
        let base = u32::from(network);
        let first = Ipv4Addr::from(base + 9);
        let second = Ipv4Addr::from(base + 10);
        let expose = |host: Ipv4Addr| {
            format!(r#"{{"local":"{host}:8080","remote":"100.64.0.9:18080","protocol":"tcp"}}"#)
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
        assert_eq!(
            ledger.note_published(
                a,
                [100, 64, 0, 9],
                18080,
                super::egress::IPPROTO_TCP,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
        assert_eq!(
            ledger.note_published(
                b,
                [100, 64, 0, 10],
                18081,
                super::egress::IPPROTO_UDP,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
        assert_eq!(ledger.address_of(a), Some([100, 64, 0, 9]));
        assert_eq!(
            ledger.address_of(b),
            Some([100, 64, 0, 10]),
            "the second box's publish is its own, not a duplicate of the first"
        );
        // The inside end is held per box and port together: what a dial at
        // the first box's published port is bounded by is its own entry, and
        // neither box's entry lifts a dial at a port its publish did not
        // name.
        assert!(ledger.inside_published([100, 64, 0, 9], 18080));
        assert!(ledger.inside_published([100, 64, 0, 10], 18081));
        assert!(
            !ledger.inside_published([100, 64, 0, 9], 18081),
            "one box's inside end does not answer for the other's publish"
        );
        assert!(
            !ledger.inside_published([100, 64, 0, 9], 8080),
            "the mapping's external port opens nothing: no publish dials it"
        );

        assert_eq!(
            ledger.note_retracted(b),
            Some(([100, 64, 0, 10], 18081, super::egress::IPPROTO_UDP)),
            "a retraction hands back the protocol its publish was noted under"
        );
        assert_eq!(
            ledger.address_of(b),
            None,
            "the second box's publish is gone"
        );
        assert!(
            !ledger.inside_published([100, 64, 0, 10], 18081),
            "retraction retires the recording's bound with the attribution"
        );
        assert_eq!(
            ledger.address_of(a),
            Some([100, 64, 0, 9]),
            "retracting one box's listener leaves the other box's attribution"
        );
    }

    /// At its bound the ledger refuses the next publish with a typed error
    /// instead of evicting the oldest one: an evicted entry would be a
    /// forward still bound that its box's end could no longer unbind. A
    /// listener already held is still answered as held, and a slot freed by
    /// a retraction takes a publish again.
    #[test]
    fn the_ledger_refuses_a_publish_at_its_bound_and_evicts_nothing() {
        let tcp = super::egress::IPPROTO_TCP;
        let addr = [100, 64, 0, 9];
        let ledger = super::PublishedForwards::new();
        let listener = |n: usize| -> super::Listener {
            let n = u16::try_from(n).expect("the bound fits a port range");
            ([127, 0, 64, 9], 10000 + n)
        };
        for n in 0..super::PUBLISHED_FORWARDS_TRACKED {
            assert_eq!(
                ledger.note_published(
                    listener(n),
                    addr,
                    18080,
                    tcp,
                    sessions::core::switch_request::Applied::Row
                ),
                Ok(true)
            );
        }
        let past = listener(super::PUBLISHED_FORWARDS_TRACKED);
        assert_eq!(
            ledger.note_published(
                past,
                addr,
                18080,
                tcp,
                sessions::core::switch_request::Applied::Row
            ),
            Err(super::LedgerFull),
            "the publish past the bound is refused"
        );
        assert_eq!(
            ledger.address_of(listener(0)),
            Some(addr),
            "the oldest forward is still attributed, so its box's end can still unbind it"
        );
        assert_eq!(
            ledger.published_at(addr).len(),
            super::PUBLISHED_FORWARDS_TRACKED
        );
        assert_eq!(
            ledger.note_published(
                listener(0),
                addr,
                18080,
                tcp,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(false),
            "a held listener is answered as held, not refused"
        );
        assert!(ledger.note_retracted(listener(0)).is_some());
        assert_eq!(
            ledger.note_published(
                past,
                addr,
                18080,
                tcp,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
    }

    /// The interim's publishes are counted apart from the row-held ones. No
    /// row's withdrawal names their address, so nothing but a guest
    /// retraction releases them; counted with the row-held ones they would
    /// fill the bound and refuse every box's publish. At their own bound the
    /// oldest interim one is evicted, and a row-held publish still lands. A
    /// full row-held side refuses only row-held publishes.
    #[test]
    fn interim_publishes_never_block_a_row_held_publish() {
        use sessions::core::switch_request::Applied;
        let tcp = super::egress::IPPROTO_TCP;
        let rowless = [100, 64, 0, 20];
        let row_addr = [100, 64, 0, 9];
        let listener = |base: u16, n: usize| -> super::Listener {
            let n = u16::try_from(n).expect("the bound fits a port range");
            ([127, 0, 0, 1], base + n)
        };
        let ledger = super::PublishedForwards::new();
        for n in 0..=super::INTERIM_PUBLISHES_TRACKED {
            assert_eq!(
                ledger.note_published(listener(10000, n), rowless, 18080, tcp, Applied::Interim),
                Ok(true),
                "an interim publish is never refused"
            );
        }
        assert_eq!(
            ledger.address_of(listener(10000, 0)),
            None,
            "the oldest interim publish was evicted at the interim bound"
        );
        assert_eq!(
            ledger.published_at(rowless).len(),
            super::INTERIM_PUBLISHES_TRACKED
        );
        for n in 0..super::PUBLISHED_FORWARDS_TRACKED {
            assert_eq!(
                ledger.note_published(listener(20000, n), row_addr, 18080, tcp, Applied::Row),
                Ok(true),
                "the interim publishes take none of the row-held bound"
            );
        }
        assert_eq!(
            ledger.note_published(([127, 0, 64, 9], 8080), row_addr, 18080, tcp, Applied::Row),
            Err(super::LedgerFull),
            "the row-held bound still refuses"
        );
        assert_eq!(
            ledger.address_of(listener(20000, 0)),
            Some(row_addr),
            "no row-held publish was evicted"
        );
        assert_eq!(
            ledger.note_published(listener(40000, 0), rowless, 18080, tcp, Applied::Interim),
            Ok(true),
            "a full row-held side does not refuse an interim publish"
        );
    }

    #[test]
    fn retraction_keeps_records_a_sibling_publish_still_dials() {
        // Two listeners dial one inside port: retracting one leaves the
        // other's publication standing, so the records it shares stay; the
        // last retraction at that port, in that protocol, ends them.
        let tcp = super::egress::IPPROTO_TCP;
        let addr = [100, 64, 0, 9];
        let ledger = super::PublishedForwards::new();
        assert_eq!(
            ledger.note_published(
                ([127, 0, 0, 1], 8080),
                addr,
                18080,
                tcp,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
        assert_eq!(
            ledger.note_published(
                ([127, 0, 0, 1], 8081),
                addr,
                18080,
                tcp,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );
        assert_eq!(
            ledger.note_published(
                ([127, 0, 0, 1], 8082),
                addr,
                18080,
                super::egress::IPPROTO_UDP,
                sessions::core::switch_request::Applied::Row
            ),
            Ok(true)
        );

        assert_eq!(
            ledger.note_retracted(([127, 0, 0, 1], 8080)),
            Some((addr, 18080, tcp))
        );
        assert!(
            ledger.still_published(addr, 18080, tcp),
            "the sibling listener's publication still dials the port"
        );
        assert_eq!(
            ledger.note_retracted(([127, 0, 0, 1], 8081)),
            Some((addr, 18080, tcp))
        );
        assert!(
            !ledger.still_published(addr, 18080, tcp),
            "a publication in another protocol does not keep the TCP records"
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

    /// NET-138: the gate's admitted set for a box is its declared ports
    /// plus the runtime ports its row recorded — the half that makes a
    /// port the in-VM daemon reported inside the grant reachable through
    /// the gate. The publish of a runtime-admitted port is applied by the
    /// row; a port inside the grant's range that no report recorded stays
    /// refused; and once the withdrawal report removes the port, the same
    /// publish is refused again — the admission lives exactly as long as
    /// the row holds it.
    #[tokio::test]
    async fn admitted_runtime_port_reaches_the_box_through_the_gate() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_dynamic_ingress(sessions::DynamicIngress::Allow, Some((3000, 3999))),
        );
        let mut h = gate_connected(registry.clone()).await;

        // The in-VM daemon's report, inside the grant the registration
        // holds — recorded by the host while the gate is already serving,
        // so the row the gate decides by carries the port as its live
        // runtime half.
        registry
            .admit_runtime_port(
                Ipv4Addr::from(LEASE),
                3000,
                sessions::IpProto::Tcp,
                std::time::Instant::now(),
            )
            .expect("the report is inside the grant the row holds");

        // The publish of the runtime-admitted port — the mapping that makes
        // it reachable — is applied: it reaches the switch whole, and the
        // switch's answer reaches the guest back.
        let expose = expose_request("127.0.0.1:3000", "100.64.0.9:3000", "tcp");
        h.guest
            .write_all(&expose)
            .await
            .expect("writing the runtime-admitted port's publish");
        let mut spoken = vec![0u8; expose.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(
            spoken, expose,
            "the runtime-admitted port's publish reached the switch"
        );
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(answer)
            .await
            .expect("writing gvproxy's answer");
        let mut seen = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(seen, answer, "the publish's answer reaches the guest");

        // A port inside the grant's range that no report recorded is not
        // admitted — the report is the only way a runtime port enters the
        // set — and its publish is refused at the row's address, before a
        // byte reaches the switch.
        let (mut guest, mut switch) = connect_control(&h).await;
        let unreported = expose_request("127.0.0.1:3500", "100.64.0.9:3500", "tcp");
        guest
            .write_all(&unreported)
            .await
            .expect("writing the unreported port's publish");
        wait_for_log(&h.log, "port_or_name=port 3500").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-publish-record\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("source=100.64.0.9"),
            "the refusal names the box whose row refused the record, got: {logged}"
        );
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the refused publish reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        expect_teardown(&mut guest).await;

        // The withdrawal report removes the port, and the same publish is
        // refused: the admission lives exactly as long as the row holds it.
        // The refusal itself is the second one this box and rule asked for
        // inside the drops' rate window, so its warn line is the window's to
        // keep — the proof is behavioural: nothing of the publish reaches
        // the switch, and the guest's side comes down.
        registry.withdraw_runtime_port(Ipv4Addr::from(LEASE), 3000, sessions::IpProto::Tcp);
        let row = h
            .table
            .by_source(LEASE)
            .expect("the box's row is still published");
        assert!(
            row.runtime_port_numbers().is_empty(),
            "the withdrawal report removed the row's runtime port: {:?}",
            row.runtime_port_numbers()
        );
        let (mut guest, mut switch) = connect_control(&h).await;
        guest
            .write_all(&expose)
            .await
            .expect("writing the withdrawn port's publish");
        expect_teardown(&mut guest).await;
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!(
                "{n} byte(s) of the withdrawn port's publish reached the switch; \
                 the admission outlived the row's hold on the port"
            ),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
    }

    /// NET-138: the gate keys a runtime admission on the (port, protocol)
    /// pair the report named. A row that recorded 3000/udp admits the udp
    /// publish of 3000 and refuses the tcp publish of the same number,
    /// before a byte of it reaches the switch.
    #[tokio::test]
    async fn admitted_runtime_udp_port_does_not_admit_tcp() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(sessions::DynamicIngress::Allow, Some((3000, 3999))),
        );
        let mut h = gate_connected(registry.clone()).await;
        registry
            .admit_runtime_port(
                Ipv4Addr::from(LEASE),
                3000,
                sessions::IpProto::Udp,
                std::time::Instant::now(),
            )
            .expect("the udp report is inside the grant the row holds");

        // The udp publish of the admitted pair reaches the switch.
        let udp = expose_request("127.0.0.1:3000", "100.64.0.9:3000", "udp");
        h.guest
            .write_all(&udp)
            .await
            .expect("writing the udp publish");
        let mut spoken = vec![0u8; udp.len()];
        read_within(&mut h.switch, &mut spoken).await;
        assert_eq!(spoken, udp, "the admitted udp publish reached the switch");

        // The tcp publish of the same number is refused at the row's
        // address: the udp admission is not a tcp one.
        let (mut guest, mut switch) = connect_control(&h).await;
        let tcp = expose_request("127.0.0.1:3000", "100.64.0.9:3000", "tcp");
        guest
            .write_all(&tcp)
            .await
            .expect("writing the tcp publish");
        wait_for_log(&h.log, "rule_matched=\"egress-undeclared-publish-record\"").await;
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!(
                "{n} byte(s) of the tcp publish reached the switch; a udp admission \
                 admitted tcp"
            ),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        expect_teardown(&mut guest).await;
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
        registry.spawn_withdrawal_drainer(|_| {});
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

    /// The row is withdrawn on the ingress-wins interleaving too: the switch
    /// closes its side while the guest is still on the connection, so the
    /// ingress leg ends first and the egress leg is dropped un-drained. The
    /// frame the connection carried reached the switch before the close, so
    /// its source was already attributed; the withdrawal must still be filed,
    /// not lost with the dropped leg (NET-133's inverse: a box's row goes
    /// with its shuttle connection, whichever side closed it).
    #[tokio::test]
    async fn host_table_row_withdrawn_when_the_switch_closes_first() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        registry.spawn_withdrawal_drainer(|_| {});
        let mut h = gate_over(registry).await;

        // The box's declared frame, admitted by its row and forwarded: the
        // traffic the connection attributes, before the close.
        let frame = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &frame).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, frame, "the declared frame reaches the switch");

        // The switch closes its side while the guest is still on it: the
        // ingress leg ends first, the egress leg is dropped un-drained.
        h.switch
            .shutdown()
            .await
            .expect("closing the switch's side");

        // The row goes with the connection regardless of which side closed
        // it. The withdrawal is polled, as in the guest-close path.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while h.table.by_source(LEASE).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the row outlived its shuttle connection past {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The pins retire on the ingress-wins interleaving too, beside the
    /// withdrawal report: the switch closes its side while the guest is still
    /// on the connection, and the entry the connection's lookups filled is
    /// dropped all the same. No drainer, so the row stays published and the
    /// retire is watched on the record the entry was built from, as in
    /// `a_closed_relay_connection_retires_the_pins_it_filled`.
    #[tokio::test]
    async fn pins_retired_when_the_switch_closes_first() {
        let registry = BoxRegistry::new(SUBNET);
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
        let reports = registry
            .take_withdrawal_reports()
            .expect("the withdrawal reports' receiver is taken once");
        let mut h = gate_over(registry).await;

        // The box's own lookup and its reply: the entry for its row holds a
        // live pin when the switch closes.
        let answer = Ipv4Addr::new(93, 184, 216, 34);
        let lookup = dns_pins::tests::udp_payload_frame(
            Ipv4Addr::from(LEASE),
            40000,
            SUBNET.dns_server(),
            53,
            &dns_pins::tests::dns_query("example.com"),
        );
        let reply = dns_pins::tests::udp_payload_frame(
            SUBNET.dns_server(),
            53,
            Ipv4Addr::from(LEASE),
            40000,
            &dns_pins::tests::dns_response("example.com", &[answer]),
        );
        send_frame(&mut h.guest, &lookup).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            lookup,
            "the box's own query reaches the switch"
        );
        send_frame(&mut h.switch, &reply).await;
        assert_eq!(
            expect_frame(&mut h.guest).await,
            reply,
            "the reply reaches the box in full"
        );
        wait_for_log(&h.log, "filled the box's host-side DNS admission table").await;
        let record = h.table.by_source(LEASE).expect("the box's row is held");
        assert!(
            h.pins
                .admits_frame(&record, answer.octets(), None, Instant::now()),
            "before the close, the box's own answer admits for its row"
        );

        // The switch closes its side while the guest is still on it.
        h.switch
            .shutdown()
            .await
            .expect("closing the switch's side");

        // The report is filed after the retire, so waiting for it is waiting
        // for the retire.
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
        assert_eq!(report, vec![LEASE], "the report names the box");
        assert!(
            !h.pins
                .admits_frame(&record, answer.octets(), None, Instant::now()),
            "the switch-side close retired the pins the connection filled"
        );
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
        let node = registry.register_node_namespace(7654);
        registry.spawn_withdrawal_drainer(|_| {});
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
        let node = registry.register_node_namespace(7654);
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

    /// NET-141's deny-all case, decided host-side for an own-address row: a
    /// deny-all box's query for a name outside the box zone is dropped at the
    /// relay — never written on to the switch, nothing written back toward
    /// the guest — with one rate-limited warn line naming the box and the
    /// name; zone A lookups (`host.min.internal` among them) pass byte for
    /// byte; a zone name asked for any other type, a multi-question query
    /// with a zone A in front, an unparseable datagram, and TCP to the
    /// resolver are all dropped; and an allow-list row's queries are left
    /// as they were.
    #[tokio::test]
    async fn deny_all_row_query_outside_zone_dropped_host_side() {
        use hickory_proto::rr::RecordType;

        use super::DENY_ALL_DNS_RULE;
        use crate::net::dns_pins::tests::{dns_query_of, qname, udp_payload_frame};

        let registry = BoxRegistry::new(SUBNET);
        registry.register(
            BoxRegistration::new("sealed", Ipv4Addr::from(LEASE), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy::deny_all()),
        );
        let lister = [100, 64, 0, 10];
        registry.register(
            BoxRegistration::new("weather", Ipv4Addr::from(lister), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(Vec::new()),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: None,
                }),
        );
        let mut h = gate_over(registry).await;
        let query_from = |lease: [u8; 4], port: u16, payload: &[u8]| {
            udp_payload_frame(
                Ipv4Addr::from(lease),
                port,
                SUBNET.dns_server(),
                53,
                payload,
            )
        };
        // The marker every drop below is proved against: a zone A lookup,
        // the one query shape a deny-all box's resolver traffic may carry.
        let marker = query_from(
            LEASE,
            40100,
            &dns_query_of(&[(qname("web.min.internal."), RecordType::A)]),
        );

        // The same outside name twice: both dropped, one line said.
        let outside = query_from(
            LEASE,
            40000,
            &dns_query_of(&[(qname("example.com."), RecordType::A)]),
        );
        send_frame(&mut h.guest, &outside).await;
        send_frame(&mut h.guest, &outside).await;
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "the outside lookup never reached the switch; the zone A marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, DENY_ALL_DNS_RULE).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("source=100.64.0.9")
                && logged.contains("namespace=\"sealed\"")
                && logged.contains("name=\"example.com\""),
            "the drop line names the box and the name: {logged}"
        );
        assert_eq!(
            logged
                .matches(&format!("rule_matched=\"{DENY_ALL_DNS_RULE}\""))
                .count(),
            1,
            "one line for the name's burst, not one per drop: {logged}"
        );
        // Nothing was written back toward the guest: the drop is silent.
        expect_silence(&mut h.guest).await;

        // Zone A lookups pass byte for byte, the host row's included.
        for (port, name) in [(40001, "host.min.internal."), (40002, "db.min.internal.")] {
            let zone = query_from(LEASE, port, &dns_query_of(&[(qname(name), RecordType::A)]));
            send_frame(&mut h.guest, &zone).await;
            assert_eq!(
                expect_frame(&mut h.switch).await,
                zone,
                "an A lookup of {name} reaches the switch"
            );
        }

        // Everything else a deny-all box might send its resolver is dropped:
        // a zone name asked for another type, an outside name behind a zone A,
        // an unparseable datagram, and TCP to the resolver's port.
        let dropped = [
            query_from(
                LEASE,
                40003,
                &dns_query_of(&[(qname("host.min.internal."), RecordType::TXT)]),
            ),
            query_from(
                LEASE,
                40004,
                &dns_query_of(&[
                    (qname("web.min.internal."), RecordType::A),
                    (qname("leak.example.com."), RecordType::A),
                ]),
            ),
            query_from(LEASE, 40005, &[0xde, 0xad, 0xbe, 0xef]),
            ipv4_frame(LEASE, 6, SUBNET.dns_server().octets(), 53),
        ];
        for frame in &dropped {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        assert_eq!(
            expect_frame(&mut h.switch).await,
            marker,
            "none of the dropped shapes reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;
        wait_for_log(&h.log, "name=\"<unparseable>\"").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("name=\"host.min.internal\"")
                && logged.contains("query_type=\"TXT\"")
                && logged.contains("name=\"leak.example.com\""),
            "each dropped name says so: {logged}"
        );

        // A row that is not deny-all is untouched: the allow-list box's
        // lookup of its declared name, and of a name it did not declare,
        // both reach the switch as they always have.
        for (port, name) in [(40006, "example.com."), (40007, "other.example.")] {
            let query = query_from(lister, port, &dns_query_of(&[(qname(name), RecordType::A)]));
            send_frame(&mut h.guest, &query).await;
            assert_eq!(
                expect_frame(&mut h.switch).await,
                query,
                "an allow-list row's lookup of {name} is forwarded"
            );
        }
    }
}
