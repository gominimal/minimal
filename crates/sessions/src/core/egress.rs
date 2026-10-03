//! The frame-level egress verdict (NET-062, NET-063, NET-064, NET-084).
//!
//! One pure decision — admit or drop — over an owned frame summary and an
//! owned rule set, deliberately separate from the relay loop that applies
//! it (spec NET, Tiers): the daemon's relay summarizes each frame, asks for
//! the verdict, and on a drop simply does not write the frame on. Nothing
//! here knows about sockets, tasks, or clocks, which is what lets the Kani
//! harness below exhaust the decision.
//!
//! What the verdict encodes:
//!
//! * **The source must be the box's lease** — a frame whose source address
//!   (an IPv4 frame's IPv4 source, an ARP frame's sender protocol address)
//!   is not the lease the relay was attached with is rejected before any
//!   family or rule is consulted (NET-084). No box may speak from an
//!   address but its own.
//! * **ARP is admitted** — address resolution on the shared L2 switch is a
//!   declared path for every box; the gateway's MAC must be learnable for
//!   any egress at all to work. An ARP frame from the lease, that is: its
//!   sender address is a source like any other, and a foreign one is
//!   rejected by the lease check above.
//! * **IPv6 is dropped** — v1 declares no IPv6 admission path anywhere
//!   (guest IPv6 disabled, NET-082; AAAA answered NODATA, NET-136), so an
//!   IPv6 frame is dropped as a family rather than matched against rules.
//! * **Every other `EtherType` is dropped** — an undeclared family, VLAN tags
//!   included: admitting by default would hand any encapsulation a path
//!   around the rules.
//! * **IPv4 is decided by the box's rules** — `allow_protocols`, then
//!   `deny_subnets`, then `allow_subnets` (a `None` dimension allows all, a
//!   `Some([])` one allows nothing) — with one carve-out: a UDP datagram to
//!   the resolver Minimal owns for the box, at that resolver's address and
//!   port, is admitted under any declaration including deny-all (NET-079,
//!   NET-134), because a box that cannot resolve cannot use an allow list
//!   of names either.
//!
//! The rules are compiled once per box at attach
//! ([`EgressRules::from_policy`]); the per-frame work is [`summarize`] plus
//! [`verdict`], both allocation-free.
//!
//! Beside the frame verdict sits its name-level counterpart, the DNS
//! rebinding intersection (NET-066, NET-067): the pure decision of which
//! addresses a name *resolved to* may ever be admitted for a box, once the
//! box's denies and the infrastructure deny set are subtracted. The
//! admission table itself is not here — it is relay state, and there are
//! two relays holding it, the host-side table that decides a box's
//! destinations outside the VM (NET-081) and the in-VM precision copy —
//! so the numbers both tables are bounded by live here, as constants,
//! that neither leg can drift from the other: the window, the per-name
//! address cap and the used-pin retention. The host table's own bounds —
//! the outstanding-query cap and expiry its reply matching holds — live
//! beside them, named where the cross-leg contract is, so a leg that adds
//! a copy reads the same numbers rather than inventing its own. What else
//! lives here is the
//! arithmetic the window stores the results of, kept pure and free of
//! resolver I/O so the NET-067 harness can exhaust it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{EgressPolicy, IpProto};

/// Ethernet II header length: destination MAC (6) + source MAC (6) + `EtherType` (2).
const ETH_HDR: usize = 14;
/// `EtherType` for ARP.
const ETHERTYPE_ARP: u16 = 0x0806;
/// `EtherType` for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// `EtherType` for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// IPv4 protocol number for UDP.
const IPPROTO_UDP: u8 = 17;
/// The port DNS is served on: the resolver carve-out's port (NET-079).
const DNS_PORT: u16 = 53;

/// How long an address a DNS reply admitted stays admitted, from the
/// instant of the reply the box's own lookup received. The two admission
/// tables — the host-side one that decides a DNS-resolving box's
/// destinations outside the VM (NET-081) and the in-VM precision copy
/// (NET-066) — both hold exactly this window, reading it here, so a pin
/// can never outlive its window on one leg while it lives on in the other.
///
/// It is a *fixed* window where design §5.3's is TTL-bounded — floored at
/// 600 s, capped at 24 h, a proposal in the design text — and the gates
/// record that departure at the constant's use site; what the floor buys
/// (covering the gap between resolution and use) is covered for
/// established flows by [`DNS_FLOW_IDLE_CAP`] below.
pub const DNS_ADMISSION_WINDOW: Duration = Duration::from_mins(5);

/// Design §5.3's cap on one name's admitted addresses, at most this many
/// at once, fail closed: a reply whose A records run past the cap has its
/// tail refused, so a hostile or pathological answer cannot grow the box's
/// grant one address at a time. The cap counts what a name *holds* — an
/// admission whose window has passed is released before the cap is spent —
/// so a name whose resolved address set rotates keeps its grant. Both
/// admission tables hold the same cap, reading it here.
pub const DNS_MAX_ADDRESSES_PER_NAME: usize = 32;

/// How long a pin the box *used* keeps its admitted destination past the
/// window: design §5.3's conntrack-aware retention, the one staleness
/// bound on an established flow. The first frame a pin admits establishes
/// the flow, and the flow keeps its destination until it ends — a FIN or
/// RST, or this cap reclaiming a flow nothing has ridden for a day — so a
/// long `git clone` or keep-alive to an allowed name is not severed at the
/// window's edge. It is also the only release a UDP flow ever gets, UDP
/// carrying no close signal to read. Both admission tables hold the same
/// cap, reading it here.
pub const DNS_FLOW_IDLE_CAP: Duration = Duration::from_hours(24);

/// How many flows one box holds open through its pins at once, fail closed
/// at the cap: a new flow that finds the table full is admitted by the
/// window its first frame is inside and not retained — so its retention
/// ends with the window rather than past it, and the flows already
/// recorded keep refreshing as they do. Idle entries are swept before the
/// cap is spent, so what it bounds is live flows. The bound is the
/// host-side table's alone — its entries are the host daemon's memory,
/// which a hostile relay holding one pin must not grow one flow at a time,
/// where the in-VM precision copy's growth is contained by the VM an
/// escapee already controls.
pub const DNS_MAX_FLOWS_PER_BOX: usize = 4096;

/// How many of one box's DNS queries the host-side admission table holds
/// outstanding at once, fail closed: a query past the cap is not recorded,
/// so no reply can ever match it, and no answer of the box's can pin. The
/// bound is the table's own memory bound on the reply-matching state below
/// — the same discipline the per-name cap keeps for admitted addresses —
/// and it sits far past what a real resolver stack keeps in flight: one
/// lookup's parallel pair, and a handful of concurrent lookups at most.
pub const DNS_OUTSTANDING_QUERY_CAP: usize = 16;

/// How long the host-side admission table holds one of a box's outstanding
/// queries: a DNS exchange is seconds in practice, and a resolver stack's
/// whole retransmission budget — 5 s an attempt, a few attempts — fits
/// inside this with room to spare. The entry exists only to pair a reply
/// with the question it answers, so it has nothing to outlive: past the
/// expiry a reply is one the box never asked for, and it passes through
/// unpinned, exactly as an unsolicited one does.
pub const DNS_QUERY_EXPIRY: Duration = Duration::from_secs(30);

/// The reply-flow record's second protocol — TCP, beside the UDP the
/// resolver carve-out reads, for the gates' record and reply arms.
pub const IPPROTO_TCP: u8 = 6;

/// TCP control flags, read from the L4 header the two gates parse: the
/// opening-packet test reads SYN and ACK (a connect is a bare SYN; every
/// mid-stream segment carries ACK), and the record's end reads FIN and RST —
/// a flow ends when either end sends either.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

/// How long a UDP inbound flow's record admits the box's answer before the
/// box has answered on it (NET-040's answer half). A UDP datagram carries no
/// close to read, so the record's life is a window: the first datagram the
/// gate delivers to an admitted port opens it, and if the box sends nothing
/// back before the window passes, the conversation it came from is over as
/// far as the record is concerned — a later answer the box volunteers is a
/// new connection the box's own rules must admit. Both gates hold the same
/// window, reading it here, so a record never dies on one gate while its
/// reply still passes on the other.
///
/// It is a working value, the same way the DNS numbers above are: the record
/// is the *one* thing that admits a frame the box's rules do not, so its
/// timers stay deliberately short, and the working values live here as
/// constants so the two gates that read them can never drift apart.
pub const REPLY_UDP_UNREPLIED_WINDOW: Duration = Duration::from_secs(30);

/// How long a UDP inbound flow's record keeps admitting the box's answer
/// after the box has answered on it: a conversation the box took part in
/// outlives the unreplied window, because an exchange of datagrams is the
/// one signal UDP gives that the flow is live, and severing it mid-answer
/// would turn a deny-all box's working published port into a one-shot. The
/// first answer moves the record onto this window and every later answer
/// refreshes it, so the box's own traffic is what keeps its own replies
/// admitted.
pub const REPLY_UDP_REPLIED_WINDOW: Duration = Duration::from_mins(5);

/// How long a TCP inbound flow's record keeps admitting after anything —
/// the working-value idle cap for an established flow, since a TCP record's
/// own end is read from the wire: a FIN or RST from either end ends it, and
/// only a flow nothing has ridden for this long is reclaimed in its absence.
/// Every segment in either direction refreshes it, so a long-lived
/// connection stays admitted for as long as it stays live.
pub const REPLY_TCP_IDLE_CAP: Duration = Duration::from_mins(5);

/// How many inbound flows one box holds records for at once, fail closed at
/// the cap: a new inbound flow that finds the table full is refused at
/// ingress — the opening frame is not delivered, so the client's connect
/// fails — while the flows already recorded keep refreshing and keep their
/// replies admitted. Expired records are swept before the cap is spent, at
/// most once per [`REPLY_FLOW_SWEEP_INTERVAL`], so what it bounds is live
/// flows and the sweep's cost stays bounded. Both gates hold the same cap,
/// reading it here.
pub const REPLY_MAX_FLOWS_PER_BOX: usize = 1024;

/// How often a box's reply-flow table is swept for expired records when the
/// table is at its cap: a bounded sweep's cost is bounded by being rare, so
/// a flood of inbound flows past the cap cannot turn the sweep into the
/// relay's hot path — the refused flows are counted and said, the table is
/// swept at most this often, and nothing else pays.
pub const REPLY_FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Which L2 family a frame belongs to — the first fact the verdict needs,
/// because three of the four families are decided without any rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFamily {
    /// ARP: address resolution, a declared path for every box.
    Arp,
    /// IPv4: the one family the rules decide.
    Ipv4,
    /// IPv6: no v1 admission path exists, so it is dropped as a family
    /// (NET-082, NET-136).
    Ipv6,
    /// An `EtherType` v1 declares no admission path for, carried raw — VLAN
    /// tags (0x8100) included, since a VLAN-tagged IPv4 frame is not an
    /// IPv4 frame to this header reader.
    UndeclaredFamily(u16),
    /// Too short to carry the header the family decision, the rule match or
    /// the lease check reads: below 14 bytes there is not even an
    /// `EtherType`, an IPv4-ethertype frame below 34 bytes has no readable
    /// IPv4 header, and an ARP frame too short to carry four bytes of
    /// sender protocol address at the `hlen` its header declares has no
    /// readable source. Never admitted — an unreadable frame
    /// cannot be a declared one, and an unattributable one cannot be the
    /// lease's (NET-084).
    Truncated,
}

/// The facts of one frame the egress verdict decides on, extracted by
/// [`summarize`] and owned outright: no borrow of the frame survives the
/// extraction, so the decision is a pure function of this value plus the
/// box's [`EgressRules`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSummary {
    family: FrameFamily,
    /// The source address the frame carries: an IPv4 frame's header
    /// source, or an ARP frame's sender protocol address — read whatever
    /// protocol type the frame claims for it — the address the lease check
    /// (NET-084) compares against the box's lease. `None` when the frame
    /// carries no readable one: IPv6, an undeclared family, or a frame too
    /// short to read.
    src: Option<[u8; 4]>,
    /// The IPv4 destination address, when the frame carries one.
    dst: Option<[u8; 4]>,
    /// The IPv4 protocol number, when the frame carries one.
    proto: Option<u8>,
    /// The L4 destination port, or `0` when there is none to read — a
    /// non-first fragment or a truncated L4 header. `0` can never equal
    /// [`DNS_PORT`], so the missing port fails the resolver carve-out
    /// closed rather than opening it.
    dst_port: u16,
}

impl FrameSummary {
    /// The frame's family.
    #[must_use]
    pub fn family(&self) -> FrameFamily {
        self.family
    }

    /// The source address the frame carries — an IPv4 frame's header
    /// source, or an ARP frame's sender protocol address, whatever
    /// protocol the frame claims for it (the address the lease check
    /// reads). `None` when the frame carries no readable one.
    #[must_use]
    pub fn source(&self) -> Option<[u8; 4]> {
        self.src
    }

    /// The IPv4 destination address, when the frame carries one.
    #[must_use]
    pub fn destination(&self) -> Option<[u8; 4]> {
        self.dst
    }

    /// The IPv4 protocol number, when the frame carries one.
    #[must_use]
    pub fn protocol(&self) -> Option<u8> {
        self.proto
    }

    /// The L4 destination port, `0` when the frame carries none readable.
    #[must_use]
    pub fn destination_port(&self) -> u16 {
        self.dst_port
    }
}

/// Extracts the verdict's inputs from one Ethernet II frame. Pure and
/// allocation-free: every read is bounds-checked before it happens, so a
/// truncated or hostile frame yields [`FrameFamily::Truncated`] (or a
/// family with no address) rather than an out-of-bounds read.
#[must_use]
pub fn summarize(frame: &[u8]) -> FrameSummary {
    let none = |family| FrameSummary {
        family,
        src: None,
        dst: None,
        proto: None,
        dst_port: 0,
    };
    if frame.len() < ETH_HDR {
        return none(FrameFamily::Truncated);
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let family = match ethertype {
        ETHERTYPE_ARP => {
            // ARP: the sender protocol address is the frame's source — the
            // address the lease check (NET-084) compares. It sits `hlen`
            // bytes of sender hardware into the ARP payload, behind 8 bytes
            // of fixed header, and the check reads four bytes of it, so the
            // offset is bounds-checked before it is used. The protocol type
            // the frame claims for the address is not consulted: an ARP
            // claiming a protocol other than IPv4 must be no way to
            // announce an address unchecked, so the slot is the source
            // whatever the frame claims to speak. A frame too short to
            // carry four bytes of sender address at its own `hlen` has no
            // readable source: it cannot be attributed to the lease, so it
            // is truncated rather than admitted.
            if frame.len() < ETH_HDR + 8 {
                return none(FrameFamily::Truncated);
            }
            let hlen = frame[ETH_HDR + 4] as usize;
            let spa = ETH_HDR + 8 + hlen;
            if frame.len() < spa + 4 {
                return none(FrameFamily::Truncated);
            }
            return FrameSummary {
                family: FrameFamily::Arp,
                src: Some([frame[spa], frame[spa + 1], frame[spa + 2], frame[spa + 3]]),
                dst: None,
                proto: None,
                dst_port: 0,
            };
        }
        ETHERTYPE_IPV6 => return none(FrameFamily::Ipv6),
        ETHERTYPE_IPV4 => FrameFamily::Ipv4,
        _ => return none(FrameFamily::UndeclaredFamily(ethertype)),
    };
    // IPv4: the fixed 20-byte header carries the source, destination and
    // protocol.
    let ip = &frame[ETH_HDR..];
    if ip.len() < 20 {
        return none(FrameFamily::Truncated);
    }
    // IHL is the header length in 32-bit words; the L4 destination port
    // sits at its end, on a first fragment only. Anything else means no
    // readable port, and `dst_port == 0` keeps the carve-out closed.
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let dst_port = if ihl >= 20 && frag_offset == 0 && ip.len() >= ihl + 4 {
        u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]])
    } else {
        0
    };
    FrameSummary {
        family,
        src: Some([ip[12], ip[13], ip[14], ip[15]]),
        dst: Some([ip[16], ip[17], ip[18], ip[19]]),
        proto: Some(ip[9]),
        dst_port,
    }
}

/// An IPv4 subnet as declared in an egress rule: an address and a prefix
/// length, both owned. Parsed from the same `a.b.c.d/n` spelling
/// [`EgressPolicy`] validates at launch, so every entry that reaches
/// [`EgressRules::from_policy`] parses.
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// The network address, in wire byte order.
    addr: [u8; 4],
    /// The prefix length, `0..=32`.
    prefix: u8,
}

impl Ipv4Cidr {
    /// Parses `a.b.c.d/n` (prefix at most `/32`). Returns `None` for
    /// anything else — a bare address, a too-long prefix, or an IPv6 CIDR,
    /// which can never match: IPv6 frames are dropped as a family before
    /// any rule is consulted.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.split_once('/')?;
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let addr = addr.parse::<std::net::Ipv4Addr>().ok()?;
        Some(Self {
            addr: addr.octets(),
            prefix,
        })
    }

    /// Whether `ip` falls inside this subnet. Panic-free for any `prefix`
    /// the type can hold — the shift is guarded at both ends — so an
    /// arbitrary (proof-symbolic) CIDR cannot fault the match.
    #[must_use]
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        let mask = match self.prefix {
            0 => 0,
            32.. => u32::MAX,
            p => u32::MAX << (32 - p),
        };
        (u32::from_be_bytes(ip) & mask) == (u32::from_be_bytes(self.addr) & mask)
    }

    /// The single-address `/32` of one address: the shape the infrastructure
    /// deny set holds a gateway's own addresses in, so they are named
    /// individually rather than only through the plane that contains them.
    #[must_use]
    pub fn exact(addr: [u8; 4]) -> Self {
        Self { addr, prefix: 32 }
    }
}

/// A box's compiled egress rules: the three declaration dimensions of an
/// [`EgressPolicy`], owned and matchable, plus the addresses the verdict is
/// keyed to — the resolver the carve-out admits, and the box's lease, the
/// one source its frames may carry.
///
/// Each dimension is `None` to allow all and `Some(list)` to allow exactly
/// the listed entries — so a deny-all declaration is `Some(vec![])` on
/// every dimension, and the carve-out is what keeps a deny-all box
/// resolving.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressRules {
    /// Allowed IPv4 protocol numbers; `None` allows all.
    allow_protocols: Option<Vec<u8>>,
    /// Allowed destination subnets; `None` allows all.
    allow_subnets: Option<Vec<Ipv4Cidr>>,
    /// Denied destination subnets, subtracted from the allowed set; `None`
    /// denies nothing.
    deny_subnets: Option<Vec<Ipv4Cidr>>,
    /// The address of the resolver Minimal owns for this box (the switch
    /// gateway), which the carve-out admits at [`DNS_PORT`] under any
    /// declaration.
    resolver: [u8; 4],
    /// The box's lease on the switch — the one source address its frames
    /// may carry, which the verdict rejects any other of (NET-084). Known
    /// when the box is attached, the same moment the policy is compiled.
    lease: [u8; 4],
}

impl EgressRules {
    /// Assembles a rule set from its dimensions. The shape the Kani proof
    /// and [`EgressRules::from_policy`] share.
    #[must_use]
    pub fn new(
        allow_protocols: Option<Vec<u8>>,
        allow_subnets: Option<Vec<Ipv4Cidr>>,
        deny_subnets: Option<Vec<Ipv4Cidr>>,
        resolver: [u8; 4],
        lease: [u8; 4],
    ) -> Self {
        Self {
            allow_protocols,
            allow_subnets,
            deny_subnets,
            resolver,
            lease,
        }
    }

    /// Compiles a session's egress policy into rules. An absent policy is
    /// allow-all on every dimension (the shipped default, 03-spec R2.1;
    /// NET-074 changes it once the deny-all default is in force), and a
    /// declared dimension keeps only the entries the launch-time validation
    /// already checked parse. `resolver` is the switch gateway's address,
    /// the resolver this box's carve-out is keyed to, and `lease` the box's
    /// own address on the switch — the source its frames must carry
    /// (NET-084).
    #[must_use]
    pub fn from_policy(policy: Option<&EgressPolicy>, resolver: [u8; 4], lease: [u8; 4]) -> Self {
        let Some(policy) = policy else {
            return Self::new(None, None, None, resolver, lease);
        };
        let allow_protocols: Option<Vec<u8>> = policy
            .allow_protocols
            .as_ref()
            .map(|list| list.iter().map(|proto| wire_number(*proto)).collect());
        let subnets = |entries: &Option<Vec<String>>| -> Option<Vec<Ipv4Cidr>> {
            entries.as_ref().map(|list| {
                list.iter()
                    .filter_map(|cidr| Ipv4Cidr::parse(cidr))
                    .collect()
            })
        };
        Self::new(
            allow_protocols,
            subnets(&policy.allow_subnets),
            subnets(&policy.deny_subnets),
            resolver,
            lease,
        )
    }

    /// The address of the resolver this box's carve-out is keyed to.
    #[must_use]
    pub fn resolver(&self) -> [u8; 4] {
        self.resolver
    }

    /// The compiled `allow_subnets`, `None` when the dimension allows all —
    /// the one dimension the rebinding intersection also reads, as the
    /// RFC 1918 exemption's signal (NET-067): private space is admitted for
    /// a name only where the box's own address declaration covers it.
    #[must_use]
    pub fn allow_subnets(&self) -> Option<&[Ipv4Cidr]> {
        self.allow_subnets.as_deref()
    }

    /// The compiled `deny_subnets`, `None` when nothing is denied — the
    /// deny half the rebinding intersection subtracts from every resolved
    /// answer before anything is admitted (NET-067).
    #[must_use]
    pub fn deny_subnets(&self) -> Option<&[Ipv4Cidr]> {
        self.deny_subnets.as_deref()
    }

    /// The box's lease — the one source address its frames may carry.
    #[must_use]
    pub fn lease(&self) -> [u8; 4] {
        self.lease
    }
}

/// An [`IpProto`]'s IPv4 wire number (TCP 6, UDP 17, ICMP 1). Exhaustive
/// on purpose: a future `IpProto` variant must name its own wire number
/// here — or fail to compile — rather than silently falling into an
/// allow list under a wrong number.
fn wire_number(proto: IpProto) -> u8 {
    match proto {
        IpProto::Tcp => 6,
        IpProto::Udp => IPPROTO_UDP,
        IpProto::Icmp => 1,
    }
}

/// The egress verdict for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVerdict {
    /// The frame is declared: write it on.
    Admit,
    /// The frame is not declared: drop it, without answering (NET-062 — a
    /// drop is not a reset).
    Drop(DropReason),
}

/// Why a frame was dropped, carrying what the rate-limited warning names
/// (the destination, the protocol, the rule) so the relay can log the drop
/// without re-deriving any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The frame's source is not the lease the relay was attached with — a
    /// spoofed or foreign source, rejected before any family or rule is
    /// consulted (NET-084).
    ForeignSource {
        /// The source address the frame carried.
        src: [u8; 4],
        /// The lease the frame's source had to be.
        lease: [u8; 4],
    },
    /// IPv6: dropped as a family, no v1 admission path (NET-082, NET-136).
    Ipv6,
    /// An `EtherType` no admission path is declared for, carried raw.
    UndeclaredFamily(u16),
    /// Too short to read the header a rule match needs. Never declared.
    Truncated,
    /// The L4 protocol is not among `allow_protocols`.
    UndeclaredProtocol {
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
    /// The destination is in `deny_subnets`.
    DeniedSubnet {
        /// The frame's IPv4 destination address.
        dst: [u8; 4],
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
    /// The destination is not in `allow_subnets`.
    UndeclaredSubnet {
        /// The frame's IPv4 destination address.
        dst: [u8; 4],
        /// The frame's IPv4 protocol number.
        proto: u8,
    },
}

impl DropReason {
    /// The rule that dropped the frame: the rate-limit key and the
    /// warning's `rule_matched` field (NET-062).
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::ForeignSource { .. } => "egress-foreign-source",
            Self::Ipv6 => "egress-ipv6",
            Self::UndeclaredFamily(_) => "egress-undeclared-ethertype",
            Self::Truncated => "egress-truncated-ipv4",
            Self::UndeclaredProtocol { .. } => "egress-undeclared-protocol",
            Self::DeniedSubnet { .. } => "egress-denied-subnet",
            Self::UndeclaredSubnet { .. } => "egress-undeclared-subnet",
        }
    }

    /// The frame's IPv4 destination address, when the drop carries one.
    #[must_use]
    pub fn destination(&self) -> Option<[u8; 4]> {
        match self {
            Self::ForeignSource { .. }
            | Self::Ipv6
            | Self::UndeclaredFamily(_)
            | Self::Truncated
            | Self::UndeclaredProtocol { .. } => None,
            Self::DeniedSubnet { dst, .. } | Self::UndeclaredSubnet { dst, .. } => Some(*dst),
        }
    }

    /// The frame's IPv4 protocol number, when the drop carries one.
    #[must_use]
    pub fn protocol(&self) -> Option<u8> {
        match self {
            Self::UndeclaredProtocol { proto }
            | Self::DeniedSubnet { proto, .. }
            | Self::UndeclaredSubnet { proto, .. } => Some(*proto),
            Self::ForeignSource { .. }
            | Self::Ipv6
            | Self::UndeclaredFamily(_)
            | Self::Truncated => None,
        }
    }
}

/// NET-084: whether a frame's source is foreign — an address other than the
/// `lease` the relay was attached with. `Some(reason)` when the frame must
/// be rejected; `None` when it carries the lease, or no readable source at
/// all — an IPv6 or undeclared-family frame, or a truncated one, none of
/// which `verdict` admits either way. An IPv4 frame's source is its header
/// source address; an ARP frame's is its sender protocol address, read
/// whatever protocol type the frame claims for it — so a foreign address
/// cannot be announced by address resolution either, least of all by an
/// ARP dressed up as another protocol.
#[must_use]
pub fn foreign_source(summary: &FrameSummary, lease: [u8; 4]) -> Option<DropReason> {
    let src = summary.src?;
    (src != lease).then_some(DropReason::ForeignSource { src, lease })
}

/// The admit-or-drop decision for one frame summary against one box's rules
/// — the pure function NET-062, NET-063, NET-064, and NET-084 all reduce
/// to, and the one the Kani harness exhausts.
///
/// Order of the checks is part of the contract: the lease check comes
/// first, so a frame from a foreign source is rejected whatever family or
/// destination it carries (NET-084); the resolver carve-out then comes
/// before the rules, so a box that denies the resolver's own subnet still
/// resolves (NET-079); `deny_subnets` then carves out of what the allows
/// admit; and a drop never depends on the rule lists being sorted.
#[must_use]
pub fn verdict(summary: &FrameSummary, rules: &EgressRules) -> FrameVerdict {
    if let Some(reason) = foreign_source(summary, rules.lease) {
        return FrameVerdict::Drop(reason);
    }
    match summary.family {
        FrameFamily::Arp => FrameVerdict::Admit,
        FrameFamily::Ipv6 => FrameVerdict::Drop(DropReason::Ipv6),
        FrameFamily::UndeclaredFamily(ethertype) => {
            FrameVerdict::Drop(DropReason::UndeclaredFamily(ethertype))
        }
        FrameFamily::Truncated => FrameVerdict::Drop(DropReason::Truncated),
        FrameFamily::Ipv4 => verdict_ipv4(summary, rules),
    }
}

/// The IPv4 half of the verdict: the carve-out, then the three declared
/// dimensions. `summary`'s address and protocol are read only after the
/// [`FrameFamily::Truncated`] case has been ruled out, so both are `Some`
/// here.
fn verdict_ipv4(summary: &FrameSummary, rules: &EgressRules) -> FrameVerdict {
    let Some(dst) = summary.dst else {
        return FrameVerdict::Drop(DropReason::Truncated);
    };
    let Some(proto) = summary.proto else {
        return FrameVerdict::Drop(DropReason::Truncated);
    };
    // NET-079 / NET-134: the resolver Minimal owns for the box is the one
    // carve-out from a deny-all verdict — at its address and port, whatever
    // the rules say, because no box can be denied its own resolution.
    if proto == IPPROTO_UDP && dst == rules.resolver && summary.dst_port == DNS_PORT {
        return FrameVerdict::Admit;
    }
    if let Some(allow) = &rules.allow_protocols
        && !allow.contains(&proto)
    {
        return FrameVerdict::Drop(DropReason::UndeclaredProtocol { proto });
    }
    if let Some(deny) = &rules.deny_subnets
        && deny.iter().any(|cidr| cidr.contains(dst))
    {
        return FrameVerdict::Drop(DropReason::DeniedSubnet { dst, proto });
    }
    if let Some(allow) = &rules.allow_subnets
        && !allow.iter().any(|cidr| cidr.contains(dst))
    {
        return FrameVerdict::Drop(DropReason::UndeclaredSubnet { dst, proto });
    }
    FrameVerdict::Admit
}

/// The infrastructure deny set of the DNS rebinding intersection (design
/// §5.3, NET-067): the ranges an answer may never be admitted into, whatever
/// the box's own rules say — the ranges that stand for the host and the
/// fabric, not destinations.
///
/// Three classes, because two of them are conditional:
///
/// * **Fixed** — link-local and the metadata services living in it, loopback
///   space, and the gateway's own two addresses: the answerer's (the
///   resolver the box's carve-out is keyed to, NET-079) and the helper's (the
///   deprecated host-alias literal, NET-004), each held as a `/32` so both
///   are named individually rather than only through the plane containing
///   them; and the four ranges that complete the set — this-host space
///   (`0.0.0.0/8`, where `0.0.0.0` names the host itself, so the range is
///   loopback's neighbour), multicast (`224.0.0.0/4`), broadcast
///   (`255.255.255.255/32`), and the reserved block the broadcast address
///   ends in (`240.0.0.0/4`) — none of them a destination a name may name.
///   Refused under every declaration, for every name — a box-zone
///   name included (NET-072): even a subverted zone answer must not become a
///   path to the metadata service or loopback, and `host.min.internal`
///   resolves for the box but is never pinned as reach.
/// * **The plane** — the whole `100.64.0.0/10` space the switch fabric draws
///   its subnets from. Refused for answers to names outside the box zone,
///   so no ordinary name can ever name a box, the gateway, or the daemon;
///   carved out for box-zone answers, where naming a sibling's lease is the
///   point (NET-072, NET-073).
/// * **RFC 1918** — private space, refused *unless the box's
///   `egress.allow_subnets` covers the answer*: a developer who wants a name
///   to reach the LAN says so by allowing the range, so a name rule cannot
///   become a way around leaving it undeclared.
///
/// Owned outright — no borrow of the policy survives the attach — which is
/// what keeps [`rebinding_admits`] a pure function over owned addresses and
/// CIDRs, separate from resolver I/O, as the NET-067 harness requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfrastructureDenySet {
    /// Ranges refused under every declaration, for every name.
    fixed: Vec<Ipv4Cidr>,
    /// The switch-fabric plane, the one range a box-zone answer is admitted
    /// in (NET-072): it refuses every answer outside the zone, and every
    /// zone answer outside it.
    plane: Ipv4Cidr,
    /// RFC 1918 space, refused unless `allow_subnets` covers the answer.
    rfc1918: Vec<Ipv4Cidr>,
}

impl InfrastructureDenySet {
    /// The set for one box's attach: the always-refused ranges, the fabric
    /// plane, and the gateway's `resolver` (where the box's own queries are
    /// answered) and `host_alias` (the helper's address) as `/32`s.
    ///
    /// Both gateway addresses lie inside the plane today; they are named
    /// individually so the set still refuses them if the plane is ever
    /// renumbered out from under them.
    ///
    /// # Panics
    ///
    /// Never: every range is a constant that parses.
    #[must_use]
    pub fn new(resolver: [u8; 4], host_alias: [u8; 4]) -> Self {
        // Every constant parses; the parses exist so the set's contents are
        // spelled as ranges, not as byte arrays.
        let cidr = |s: &'static str| Ipv4Cidr::parse(s).expect("a constant CIDR parses");
        Self {
            fixed: vec![
                // Link-local, and the metadata services living in it.
                cidr("169.254.0.0/16"),
                // Loopback space.
                cidr("127.0.0.0/8"),
                // This-host space: `0.0.0.0` names the host itself, so the
                // range is loopback's neighbour, refused for the same reason.
                cidr("0.0.0.0/8"),
                // Multicast: no destination a name may name.
                cidr("224.0.0.0/4"),
                // The reserved block, and the broadcast address ending it —
                // named on its own so the set still refuses it if the
                // reserved block is ever re-scoped.
                cidr("240.0.0.0/4"),
                cidr("255.255.255.255/32"),
                Ipv4Cidr::exact(resolver),
                Ipv4Cidr::exact(host_alias),
            ],
            // The plane the switch fabric draws subnets from.
            plane: cidr("100.64.0.0/10"),
            rfc1918: vec![
                cidr("10.0.0.0/8"),
                cidr("172.16.0.0/12"),
                cidr("192.168.0.0/16"),
            ],
        }
    }
}

/// The IPv6 half of the infrastructure deny set, as a record for the IPv6
/// epoch — kept beside the IPv4 set above so the two halves of one set
/// cannot be spelled apart when the epoch comes.
///
/// It decides nothing in v1, on purpose: no IPv6 admission path exists
/// anywhere (guest IPv6 is disabled, NET-082; AAAA is answered NODATA,
/// NET-136), so no IPv6 address is ever admitted and the rebinding
/// intersection above never sees one. It exists so the epoch that carries
/// IPv6 answers finds the set's IPv6 half already spelled: the unspecified
/// address (`::`, which names the host the way `0.0.0.0` does), loopback
/// (`::1`), and the IPv4-mapped space (`::ffff:0:0/96`, the addresses a
/// dual-stack host answers at — the one class a v6 epoch could reach v4
/// infrastructure through). The entries are `a::/n` strings rather than a
/// parsed type, because v1 has no IPv6 CIDR type to parse them into; the
/// test at the bottom of this file is the record's own proof that every
/// entry parses as an address and a prefix, so the epoch cannot inherit a
/// typo.
pub const IPV6_INFRASTRUCTURE_DENY_RANGES: &[&str] = &["::/128", "::1/128", "::ffff:0:0/96"];

/// Why the rebinding intersection refused one resolved address, carrying the
/// rule its rate-limited warning is keyed to (mirroring [`DropReason::rule`],
/// the frame verdict's naming discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebindingRefusal {
    /// The answer lies in the box's `deny_subnets`: a declared deny is
    /// subtractive from every admission path, a name rule included.
    DeniedSubnet,
    /// The answer lies in the infrastructure deny set: a fixed range, or
    /// RFC 1918 the box's `allow_subnets` does not cover.
    Infrastructure,
}

impl RebindingRefusal {
    /// The rule that refused the answer: the rate-limit key and the warning's
    /// `rule_matched` field (NET-067).
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::DeniedSubnet => "dns-rebinding-denied-subnet",
            Self::Infrastructure => "dns-rebinding-infrastructure",
        }
    }
}

/// The DNS rebinding intersection's decision for one resolved address
/// (NET-066, NET-067): admitted — `Ok(())` — exactly when nothing refuses
/// it, where RFC 1918 is the one infrastructure class an `allow_subnets`
/// entry exempts.
///
/// `box_zone` marks the answer as one to a name in the box zone
/// (`*.min.internal`, NET-072). Such an answer is expected to name a
/// sibling's switch lease, so the fabric plane is carved out for it and no
/// other range is — the one carve-out a zone name earns, and the reason a
/// box *resolves* a sibling's name with no `allow_dns_hosts` entry. The
/// carve-out is exact in both directions: a zone answer is admitted inside
/// the plane and nowhere else, so an answer to a zone name that names any
/// other address — RFC 1918, a public host — is refused as infrastructure
/// exactly as the plane's own addresses are for a name outside the zone,
/// whatever `allow_subnets` covers. Everything else the set refuses still
/// refuses a zone answer: the fixed ranges (the metadata service, loopback,
/// the gateway's own addresses) and the plane's own addresses when the name
/// is not a zone name.
///
/// Admitted here means *may be* admitted: the intersection only splits the
/// answer set, and whether a survivor becomes reach is the caller's. The
/// daemon's gate pins a declared name's answers and a zone answer never —
/// NET-072's carve-out is the resolution's alone, so the reach to the lease
/// a zone name answered with is decided by the connecting box's declared
/// subnets at connection time, never by the answer.
///
/// Pure over owned addresses and CIDRs, and deliberately separate from any
/// resolver: the daemon hands this function the addresses a resolver already
/// returned and learns which of them may ever be admitted, which is what
/// lets the Kani harness exhaust the decision without a socket in sight.
///
/// The order of the checks is part of the contract: the box's own denies
/// first — a declared deny outranks every allowance — then the fixed
/// infrastructure ranges, then the plane, which a zone name and any other
/// name answer from opposite sides — inside it for a zone name, outside it
/// for every other — then RFC 1918 under its `allow_subnets` exemption.
/// An undeclared `allow_subnets` (`None`, allow-all) counts as covering
/// the answer: the box's address dimension is open, so the name path opens
/// with it rather than refusing answers the box can already reach.
///
/// # Errors
///
/// [`RebindingRefusal`] — never an I/O or parse failure; the answer is
/// refused exactly when a deny or the infrastructure set names it.
pub fn rebinding_admits(
    answer: [u8; 4],
    box_zone: bool,
    allow: Option<&[Ipv4Cidr]>,
    deny: Option<&[Ipv4Cidr]>,
    infrastructure: &InfrastructureDenySet,
) -> Result<(), RebindingRefusal> {
    if let Some(denied) = deny
        && denied.iter().any(|cidr| cidr.contains(answer))
    {
        return Err(RebindingRefusal::DeniedSubnet);
    }
    if infrastructure
        .fixed
        .iter()
        .any(|cidr| cidr.contains(answer))
    {
        return Err(RebindingRefusal::Infrastructure);
    }
    // NET-072: outside the box zone the plane refuses every answer, so no
    // ordinary name can ever name a box, the gateway, or the daemon. Inside
    // the box zone the plane is the whole of the answer's reach: a zone
    // name names a sibling's lease, so an answer anywhere else is refused
    // as infrastructure, `allow_subnets` covering it or not.
    if box_zone != infrastructure.plane.contains(answer) {
        return Err(RebindingRefusal::Infrastructure);
    }
    if infrastructure
        .rfc1918
        .iter()
        .any(|cidr| cidr.contains(answer))
        && !allow.is_none_or(|list| list.iter().any(|cidr| cidr.contains(answer)))
    {
        return Err(RebindingRefusal::Infrastructure);
    }
    Ok(())
}

/// [`rebinding_intersection`]'s split of one name's resolved addresses:
/// which may be admitted, and which are refused with the reason to log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebindingSplit {
    /// The addresses that may be admitted for the admission window, in the
    /// order the answer carried them.
    pub admitted: Vec<[u8; 4]>,
    /// The refused addresses, each with the rule that refused it, in the
    /// order the answer carried them.
    pub refused: Vec<([u8; 4], RebindingRefusal)>,
}

/// Splits one name's resolved addresses by [`rebinding_admits`]: the
/// addresses that may be admitted for the admission window, and the
/// refusals to log — each refused address with its reason, in the order the
/// answer carried them. `box_zone` marks the name as a box-zone name
/// (NET-072) and passes through to [`rebinding_admits`]. This is the
/// set-shaped wrapper the daemon calls once per DNS reply; the decision
/// itself stays per-address, which is the shape the harness proves.
#[must_use]
pub fn rebinding_intersection(
    answers: &[[u8; 4]],
    box_zone: bool,
    allow: Option<&[Ipv4Cidr]>,
    deny: Option<&[Ipv4Cidr]>,
    infrastructure: &InfrastructureDenySet,
) -> RebindingSplit {
    let mut split = RebindingSplit {
        admitted: Vec::with_capacity(answers.len()),
        refused: Vec::with_capacity(answers.len()),
    };
    for answer in answers {
        match rebinding_admits(*answer, box_zone, allow, deny, infrastructure) {
            Ok(()) => split.admitted.push(*answer),
            Err(reason) => split.refused.push((*answer, reason)),
        }
    }
    split
}

/// One L4 flow identity: the protocol and both ends' address-and-port pairs,
/// in the direction the *client* spoke it — the key one box's inbound-flow
/// record is held under, and the exact thing a reply must reverse for the
/// shared decision ([`ReplyFlows::reply_admits`]) to admit it (NET-040's
/// answer half).
///
/// [`FrameSummary`] deliberately carries no source port and no TCP flags —
/// the verdict needs neither, and keeping the frame summary lean is what
/// keeps it allocation-free on the relay's hot path — so the record's key is
/// its own small type, built by each gate from the L4 header it parses
/// anyway (the same parse the DNS gates' flow retention reads), in one
/// direction only: the client's. A record answers exactly the conversation
/// it was opened for and nothing beside it, which is why the tuple is the
/// whole of the identity: no address is carved out, no port range, no
/// protocol — reversing the tuple is the one way a record admits a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    proto: u8,
    src: [u8; 4],
    src_port: u16,
    dst: [u8; 4],
    dst_port: u16,
}

impl FlowTuple {
    /// A flow identity in the direction the client spoke it: `src` the
    /// client, `dst` the box.
    #[must_use]
    pub fn new(proto: u8, src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Self {
        Self {
            proto,
            src,
            src_port,
            dst,
            dst_port,
        }
    }

    /// The same identity reversed — the box speaking back to the client —
    /// the key a box frame's tuple is looked up under, so that a frame the
    /// box sends either reverses a recorded flow exactly or matches nothing.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            proto: self.proto,
            src: self.dst,
            src_port: self.dst_port,
            dst: self.src,
            dst_port: self.src_port,
        }
    }

    /// The L4 protocol number.
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.proto
    }

    /// The client's address.
    #[must_use]
    pub fn source(&self) -> [u8; 4] {
        self.src
    }

    /// The client's port.
    #[must_use]
    pub fn source_port(&self) -> u16 {
        self.src_port
    }

    /// The box's address.
    #[must_use]
    pub fn destination(&self) -> [u8; 4] {
        self.dst
    }

    /// The box's port — the one the ingress declaration published.
    #[must_use]
    pub fn destination_port(&self) -> u16 {
        self.dst_port
    }
}

/// One recorded inbound flow: when its record dies, and whether the box has
/// answered on it — the one signal UDP gives that a conversation is live
/// past the unreplied window, and so the one thing a UDP record's window
/// selection reads ([`REPLY_UDP_UNREPLIED_WINDOW`] versus
/// [`REPLY_UDP_REPLIED_WINDOW`]). A TCP record's own end is read from the
/// wire — FIN or RST — so it needs no `replied` distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRecord {
    /// The instant past which the record is no longer live.
    deadline: Instant,
    /// Whether the box has answered on the flow.
    replied: bool,
}

impl ReplyRecord {
    /// When the record dies: past this instant the flow's replies are no
    /// longer admitted.
    #[must_use]
    pub fn expires_at(&self) -> Instant {
        self.deadline
    }

    /// Whether the box has answered on the flow.
    #[must_use]
    pub fn was_replied(&self) -> bool {
        self.replied
    }
}

/// What one delivered inbound frame did to the box's reply-flow record — the
/// four outcomes the recording gate's leg and its log lines read.
///
/// Recording is the ingress leg's alone (a record is opened only by an
/// opening packet the gate *delivered*, toward a port the box's declaration
/// published — never by a frame the box sent), so what an egress frame can
/// ever be is a *lookup*: [`ReplyFlows::reply_admits`] never returns any of
/// these arms, never opens a record, and never refreshes one but from the
/// reply side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundFlow {
    /// The frame opened a flow: its record now admits the box's reply on the
    /// reversed tuple. `filled` says this record took the table to its cap —
    /// the transition the once-per-box filled line reads, so the gate that
    /// owns the table says it once and not once per re-fill after a sweep.
    Recorded {
        /// Whether the table is now at its cap.
        filled: bool,
    },
    /// The frame belongs to a live record, which now runs longer — an
    /// established flow's segment or datagram, mid-conversation.
    Refreshed,
    /// The frame ended a live record: an inbound FIN or RST on a flow that
    /// was live. The frame itself is still delivered — the close is part of
    /// the conversation — but nothing the box sends on the flow after it is
    /// a reply this record admits.
    Ended,
    /// The frame opens no record: a mid-stream TCP segment (only a bare SYN
    /// opens a TCP record, never a mid-stream ACK) or a protocol with no
    /// flow to read. Delivered, and nothing recorded.
    Untracked,
    /// The box's table is at its cap and the sweep freed nothing: the flow
    /// is refused at ingress — the frame is **not** delivered, the client's
    /// connect fails — and the refusal is counted
    /// ([`ReplyFlows::refused_at_cap`]). The flows already recorded keep
    /// refreshing and keep their replies admitted.
    RefusedAtCap,
}

/// One box's table of inbound flows the gate delivered to its published
/// ports — the record a reply is admitted against, so that a box whose
/// ingress declared a port can answer the connections that port receives
/// even when its own egress rules would refuse the answer's destination
/// (NET-040's answer half, decided by the same reverse-tuple rule on both
/// gates).
///
/// The table is relay state, the same way the DNS admission tables are, and
/// lives here for the same reason they keep their numbers here: the timers
/// and the cap are the cross-gate contract — both gates hold one table per
/// box, and both must be holding *the same* bounds or the two gates a
/// VM-backed box's reply crosses would disagree about whether the reply is
/// one — so the working values are the constants above, and the two gates
/// read them from one place.
///
/// What the record admits is deliberately narrow, and the narrowness is the
/// security posture: a record is opened only by an opening packet the
/// recording gate itself delivered toward a port the box's declaration
/// published — an inbound bare SYN for TCP, the first datagram for UDP —
/// and it admits exactly the frame that reverses that packet's five-tuple,
/// nothing else. Not the client's address at any other port, not any other
/// client's address, not the box's next connection to anywhere. The gates
/// that own a table never consult it for a frame they did not deliver the
/// opening of, and the egress lookup below cannot open, refresh or extend a
/// record at all — the record type's whole surface is what a *reply* can
/// read of it.
///
/// Pure over the table's own state and a caller-supplied `Instant`, exactly
/// the way the frame verdict is pure over its summary: nothing here knows
/// about sockets, tasks or clocks, which is what lets the relay-level proofs
/// drive a record's whole life with a hand-held clock.
#[derive(Debug, Clone)]
pub struct ReplyFlows {
    /// The live records, keyed by the client's five-tuple.
    flows: HashMap<FlowTuple, ReplyRecord>,
    /// The working values the record's timers read, held as fields so the
    /// relay-level proofs can shrink them for a hand-held clock.
    udp_unreplied_window: Duration,
    udp_replied_window: Duration,
    tcp_idle_cap: Duration,
    /// The per-box cap on live records.
    cap: usize,
    /// How rarely the sweep runs once the table is at its cap.
    sweep_interval: Duration,
    /// When the last sweep ran, so a flood past the cap buys at most one
    /// sweep per interval.
    last_sweep: Option<Instant>,
    /// How many inbound flows this box has had refused at the cap — the
    /// counter the gate's status surface reads, so a box whose connections
    /// were refused reads so in a bundle.
    refused_at_cap: u64,
}

impl ReplyFlows {
    /// An empty table holding the working values above.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            udp_unreplied_window: REPLY_UDP_UNREPLIED_WINDOW,
            udp_replied_window: REPLY_UDP_REPLIED_WINDOW,
            tcp_idle_cap: REPLY_TCP_IDLE_CAP,
            cap: REPLY_MAX_FLOWS_PER_BOX,
            sweep_interval: REPLY_FLOW_SWEEP_INTERVAL,
            last_sweep: None,
            refused_at_cap: 0,
        }
    }

    /// Shrinks the record's timers — a harness hook, plain so both gates'
    /// proof modules can reach it: a record's life cannot be asserted
    /// against a five-minute window, and the relay-level proofs that drive
    /// one open, answered, idle and expired need a clock the harness can
    /// out-wait. Shrinking the replied window past the unreplied one is a
    /// contradiction of the record's design, so the caller keeps the pair
    /// ordered; a shrink of either past the caller's step size collapses
    /// the record into an expiry test, which is what the harness wanted.
    pub fn shrink_windows(&mut self, unreplied: Duration, replied: Duration, tcp_idle: Duration) {
        self.udp_unreplied_window = unreplied;
        self.udp_replied_window = replied;
        self.tcp_idle_cap = tcp_idle;
    }

    /// Shrinks the per-box cap — the window hook's twin, for the
    /// relay-level proof that a flood of inbound flows stops at the cap
    /// without holding a thousand records first.
    pub fn shrink_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// The shared reply decision both gates call ahead of their egress
    /// verdict: whether `tuple` — a frame the *box* sent, so
    /// `src` the box, `dst` the client — reverses a live record exactly.
    ///
    /// Admitted means the frame passes without the egress rules being
    /// consulted at all — the box's `deny_subnets` and the infrastructure
    /// set included — which is the point: the destination being one the
    /// box's rules refuse is what a reply *is*, for a box that published a
    /// port and answered the client that connected to it. The record that
    /// admits it was opened by an opening packet the gate delivered toward
    /// a published port, so the client's address was on the wire as the
    /// source of a frame the gate itself passed, and the reply goes back to
    /// that same conversation, port for port.
    ///
    /// Every other box frame falls through to the rules: one that reverses
    /// no live record, one whose record has expired, one whose record the
    /// client's FIN or RST already ended. A TCP FIN or RST on a live flow
    /// is admitted *and* ends it — the close is part of the conversation,
    /// and what the box sends after it is new traffic the rules decide. A
    /// UDP answer moves the record onto the replied window and refreshes
    /// it; a TCP answer refreshes the idle cap. Either way the frame's own
    /// conversation keeps the record live, and only the record's timers or
    /// its close can end it.
    ///
    /// This is the only arm an egress frame reaches, and it is read-only in
    /// the direction that matters: it never opens a record, so no frame a
    /// box sends can ever hand the box an admission — a record exists only
    /// for a flow the recording gate delivered the opening of.
    #[must_use = "a reply decision's true half is the frame's only admission; dropping the result admits nothing"]
    pub fn reply_admits(&mut self, tuple: FlowTuple, flags: u8, now: Instant) -> bool {
        let reply = tuple.reversed();
        let Some(record) = self.flows.get_mut(&reply) else {
            return false;
        };
        if record.deadline <= now {
            // The record's window has passed: the conversation it was opened
            // for is over, and the box volunteering a frame on it now is new
            // traffic the rules decide.
            self.flows.remove(&reply);
            return false;
        }
        if tuple.proto == IPPROTO_TCP {
            if flags & (TCP_FIN | TCP_RST) != 0 {
                // The close passes — and ends the record, so nothing after it
                // is a reply this flow admits.
                self.flows.remove(&reply);
                return true;
            }
            record.deadline = now + self.tcp_idle_cap;
        } else {
            // The first answer is what a UDP record was waiting for: it
            // moves the record onto the replied window, and every later
            // answer refreshes it.
            record.replied = true;
            record.deadline = now + self.udp_replied_window;
        }
        true
    }

    /// The recording half, the ingress leg's alone: what one *delivered*
    /// inbound frame did to the box's record — opened a flow, refreshed one,
    /// ended one, opened nothing, or was refused at the cap.
    ///
    /// Only an opening packet opens a record: a bare SYN for TCP (a
    /// mid-stream segment — every ACK-bearing one — opens nothing, so no
    /// flow the box did not first accept a connect on is ever recorded),
    /// and any datagram for UDP, where every datagram is the conversation's
    /// first. The caller has already decided the frame is one it is
    /// delivering toward a port the box's declaration published, which is
    /// what makes the record's opening honest: the gate records a flow only
    /// for a packet the box's own ingress admitted.
    ///
    /// A live record's inbound traffic refreshes it — the conversation is
    /// still live while the client is still speaking — and an inbound FIN or
    /// RST ends it from the client's side. At the cap the *new* flow is
    /// refused, counted, and the caller is told not to deliver it, while
    /// existing flows keep refreshing: a box under a connection flood keeps
    /// its established conversations, and only the flood pays.
    #[must_use = "the flow outcome's RefusedAtCap half is the only refusal signal the caller gets"]
    pub fn observe_inbound(&mut self, tuple: FlowTuple, flags: u8, now: Instant) -> InboundFlow {
        // A live record first — and a close from the client's own side ends
        // it, delivered though the closing frame still is.
        if let Some(record) = self.flows.get_mut(&tuple) {
            if record.deadline <= now {
                self.flows.remove(&tuple);
            } else if tuple.proto == IPPROTO_TCP && flags & (TCP_FIN | TCP_RST) != 0 {
                self.flows.remove(&tuple);
                return InboundFlow::Ended;
            } else {
                let window = if tuple.proto == IPPROTO_TCP {
                    self.tcp_idle_cap
                } else {
                    self.udp_unreplied_window
                };
                record.deadline = now + window;
                return InboundFlow::Refreshed;
            }
        }
        // The opening packet: a bare SYN for TCP, any datagram for UDP,
        // nothing for any other shape or protocol.
        let opening = tuple.proto == IPPROTO_UDP
            || (tuple.proto == IPPROTO_TCP && flags & TCP_SYN != 0 && flags & TCP_ACK == 0);
        if !opening {
            return InboundFlow::Untracked;
        }
        // At the cap, sweep the expired once per interval before spending
        // anything: the bound is on live records, so the sweep is what keeps
        // it a bound on live ones, and its cost is what the interval bounds.
        if self.flows.len() >= self.cap && !self.sweep(now) {
            self.refused_at_cap = self.refused_at_cap.saturating_add(1);
            return InboundFlow::RefusedAtCap;
        }
        self.flows.insert(
            tuple,
            ReplyRecord {
                deadline: now
                    + if tuple.proto == IPPROTO_TCP {
                        self.tcp_idle_cap
                    } else {
                        self.udp_unreplied_window
                    },
                replied: false,
            },
        );
        InboundFlow::Recorded {
            filled: self.flows.len() >= self.cap,
        }
    }

    /// Sweeps the expired records, at most once per
    /// [`REPLY_FLOW_SWEEP_INTERVAL`] and only when the table is at its cap —
    /// a healthy table pays nothing and a flooded one pays at most one sweep
    /// per interval. Whether space was freed is the caller's answer: only a
    /// sweep that freed room admits a new flow past the cap.
    fn sweep(&mut self, now: Instant) -> bool {
        if self
            .last_sweep
            .is_some_and(|at| now.duration_since(at) < self.sweep_interval)
        {
            return false;
        }
        self.last_sweep = Some(now);
        let before = self.flows.len();
        self.flows.retain(|_, record| record.deadline > now);
        before > self.flows.len()
    }

    /// Ends every recorded flow — ingress revocation and session stop both
    /// land here. A record is an admission the box's ingress earned, so it
    /// must not outlive the thing that earned it: when the session stops, or
    /// the ingress that admitted the flow is revoked, the box's records go
    /// with it, and a reply the box still owes is new traffic its own rules
    /// decide. The at-cap counter is the box's history and stays: a box
    /// whose flows were refused reads so in a bundle even after it stops.
    pub fn clear(&mut self) {
        self.flows.clear();
    }

    /// How many live records the box holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether the box holds no live record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// The per-box cap the table refuses new inbound flows at — the number a
    /// status surface or a filled line names, read from the table so a
    /// harness-shrunk cap says the cap the table actually holds.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// The record a client's five-tuple is held under, when one is live —
    /// the shape a status surface or a proof reads of the table without
    /// driving a reply.
    #[must_use]
    pub fn record_of(&self, tuple: FlowTuple) -> Option<ReplyRecord> {
        self.flows.get(&tuple).copied()
    }

    /// How many of this box's inbound flows have been refused at the cap —
    /// the counter each gate's status surface reads, one per box, so a box
    /// whose replies were or were not admitted reads so in a bundle.
    #[must_use]
    pub fn refused_at_cap(&self) -> u64 {
        self.refused_at_cap
    }
}

impl Default for ReplyFlows {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The switch gateway's address, the resolver every rule set below is
    /// keyed to (the default switch subnet's gateway).
    const RESOLVER: [u8; 4] = [100, 64, 0, 1];

    /// The lease every rule set below is compiled with — the one source
    /// address the frames below may carry (NET-084).
    const LEASE: [u8; 4] = [100, 64, 0, 9];

    /// IPv4 protocol number for TCP, for the frames below.
    const IPPROTO_TCP: u8 = 6;

    /// A deny-all rule set: every dimension declared, nothing listed.
    fn deny_all() -> EgressRules {
        EgressRules::new(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(Vec::new()),
            RESOLVER,
            LEASE,
        )
    }

    /// An Ethernet II frame carrying `ethertype` and `payload`.
    fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETH_HDR + payload.len());
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// An ARP payload for `spa`: a full Ethernet/IPv4 ARP request, whose
    /// sender protocol address is the source the lease check reads.
    fn arp_payload(spa: [u8; 4]) -> Vec<u8> {
        let mut arp = Vec::with_capacity(28);
        arp.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        arp.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype: IPv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&1u16.to_be_bytes()); // oper: request
        arp.extend_from_slice(&[0x52, 0x54, 0x00, 0x40, 0x00, 0x09]); // sender MAC
        arp.extend_from_slice(&spa); // sender protocol address
        arp.extend_from_slice(&[0; 6]); // target MAC (unread)
        arp.extend_from_slice(&RESOLVER); // target protocol address
        arp
    }

    /// An IPv4 packet payload: a header for `proto` carrying `frag_offset`
    ///'s low 13 bits, followed by `l4`.
    fn ip_payload(proto: u8, src: [u8; 4], dst: [u8; 4], frag_offset: u16, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20 + l4.len()];
        ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
        ip[6..8].copy_from_slice(&frag_offset.to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        ip[20..].copy_from_slice(l4);
        ip
    }

    /// An L4 header whose destination port is `port` (the source port is a
    /// fixed ephemeral).
    fn l4(port: u16) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&40000u16.to_be_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out
    }

    /// An IPv4 frame for `proto` from the lease to `dst`:`port`.
    fn ipv4_frame(proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        ipv4_frame_from(LEASE, proto, dst, port)
    }

    /// An IPv4 frame for `proto` from `src` to `dst`:`port`.
    fn ipv4_frame_from(src: [u8; 4], proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        eth_frame(ETHERTYPE_IPV4, &ip_payload(proto, src, dst, 0, &l4(port)))
    }

    fn admits(frame: &[u8], rules: &EgressRules) -> bool {
        matches!(verdict(&summarize(frame), rules), FrameVerdict::Admit)
    }

    /// NET-062's property from the family side: the three families decided
    /// without rules behave identically under allow-all and deny-all.
    #[test]
    fn families_decided_without_rules() {
        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE));
        assert!(
            admits(&arp, &allow_all) && admits(&arp, &deny_all()),
            "ARP is a declared path for every box"
        );
        let ipv6 = eth_frame(ETHERTYPE_IPV6, &[0u8; 40]);
        assert!(
            !admits(&ipv6, &allow_all) && !admits(&ipv6, &deny_all()),
            "IPv6 has no admission path under any declaration"
        );
        for ethertype in [0x8100, 0x88A2, 0x0000] {
            let undeclared = eth_frame(ethertype, &[0u8; 8]);
            let why = match verdict(&summarize(&undeclared), &allow_all) {
                FrameVerdict::Drop(DropReason::UndeclaredFamily(et)) => et,
                other => panic!("expected an undeclared family, got {other:?}"),
            };
            assert_eq!(why, ethertype);
            assert!(
                !admits(&undeclared, &allow_all),
                "ethertype {ethertype:#06x} is not a declared path"
            );
        }
        // Below the Ethernet header there is not even a family to read.
        assert_eq!(
            summarize(&[0u8; 13]).family,
            FrameFamily::Truncated,
            "a frame shorter than an Ethernet header is truncated"
        );
    }

    /// NET-084: a frame whose source is not the box's lease is rejected —
    /// an IPv4 frame carrying another address in its header, or an ARP frame
    /// whose sender protocol address is another box's — whatever family,
    /// destination or declaration it carries; the same frame from the lease
    /// is admitted; and an ARP frame too short to carry its sender address
    /// has no readable source and is truncated rather than admitted.
    #[test]
    fn foreign_source_is_rejected_whatever_it_carries() {
        // Under a declaration that allows everything, the destination is
        // not what drops this frame: the source is.
        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let spoofed = ipv4_frame_from([203, 0, 113, 7], IPPROTO_TCP, [10, 1, 2, 3], 443);
        assert_eq!(
            verdict(&summarize(&spoofed), &allow_all),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );
        // The same frame from the lease is the declared thing it looks like.
        assert!(admits(
            &ipv4_frame(IPPROTO_TCP, [10, 1, 2, 3], 443),
            &allow_all
        ));

        // The resolver carve-out does not rescue a foreign source either:
        // deny-all admits DNS to the resolver, from the lease only.
        let dns = ipv4_frame_from([203, 0, 113, 7], IPPROTO_UDP, RESOLVER, DNS_PORT);
        assert_eq!(
            verdict(&summarize(&dns), &deny_all()),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );
        assert!(admits(
            &ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT),
            &deny_all()
        ));

        // ARP is a declared path — from the lease. A frame announcing
        // another box's address as its sender is a foreign source too.
        let arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE));
        assert!(admits(&arp, &deny_all()), "the lease's own ARP resolves");
        assert_eq!(summarize(&arp).source(), Some(LEASE));
        let arp_spoof = eth_frame(ETHERTYPE_ARP, &arp_payload([203, 0, 113, 7]));
        assert_eq!(
            verdict(&summarize(&arp_spoof), &deny_all()),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: [203, 0, 113, 7],
                lease: LEASE,
            })
        );

        // An ARP frame too short to carry its sender protocol address has
        // no readable source: it cannot be attributed to the lease, so it
        // is truncated — never admitted. (The sender address sits 14 bytes
        // into the ARP payload, behind the 8-byte fixed header and the
        // 6-byte sender hardware address; 14 payload bytes stop short of
        // it.)
        let short_arp = eth_frame(ETHERTYPE_ARP, &arp_payload(LEASE)[..14]);
        assert_eq!(summarize(&short_arp).family, FrameFamily::Truncated);
        assert!(!admits(&short_arp, &allow_all));
    }

    /// The sender protocol address slot is an ARP frame's source whatever
    /// protocol the frame claims for it (NET-084): an ARP announcing a
    /// foreign address under a protocol type other than IPv4 — or under an
    /// unexpected `hlen` or `plen` — is a foreign source like any other,
    /// rejected and named the same way; an ARP whose slot carries the lease
    /// is the declared family whatever it claims; and one too short to
    /// carry four bytes of sender address at its own `hlen` is truncated,
    /// never admitted.
    #[test]
    fn arp_source_is_read_whatever_protocol_the_frame_claims() {
        /// An ARP payload claiming `ptype`, `hlen` and `plen`, whose sender
        /// protocol address is `spa` — sitting `hlen` bytes of sender
        /// hardware into the payload, and the `hlen` hardware bytes are
        /// emitted so the address really is where the header says.
        fn arp_claiming(ptype: u16, hlen: u8, plen: u8, spa: &[u8]) -> Vec<u8> {
            let mut arp = Vec::new();
            arp.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
            arp.extend_from_slice(&ptype.to_be_bytes()); // ptype: as claimed
            arp.push(hlen);
            arp.push(plen);
            arp.extend_from_slice(&1u16.to_be_bytes()); // oper: request
            let mac = [0x52u8, 0x54, 0x00, 0x40, 0x00, 0x09];
            arp.extend(mac.iter().cycle().take(usize::from(hlen))); // sender hardware address
            arp.extend_from_slice(spa); // sender protocol address
            arp
        }

        let allow_all = EgressRules::from_policy(None, RESOLVER, LEASE);
        let foreign = [203, 0, 113, 7];

        // An ARP claiming a protocol type other than IPv4, carrying a
        // foreign address in its sender protocol address slot, is a
        // foreign source like any other: the slot is the source whatever
        // the frame claims to speak.
        let odd = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 6, 4, &foreign));
        assert_eq!(summarize(&odd).family, FrameFamily::Arp);
        assert_eq!(summarize(&odd).source(), Some(foreign));
        assert_eq!(
            verdict(&summarize(&odd), &allow_all),
            FrameVerdict::Drop(DropReason::ForeignSource {
                src: foreign,
                lease: LEASE,
            })
        );

        // An unexpected `hlen` moves the slot, and the read follows it.
        let shifted = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 8, 4, &foreign));
        assert_eq!(summarize(&shifted).source(), Some(foreign));

        // A `plen` other than four hides nothing either: the four bytes the
        // lease check reads are the first four of the slot the frame
        // declares.
        let wide = eth_frame(
            ETHERTYPE_ARP,
            &arp_claiming(
                0x1234,
                6,
                6,
                &[foreign[0], foreign[1], foreign[2], foreign[3], 9, 9],
            ),
        );
        assert_eq!(summarize(&wide).source(), Some(foreign));

        // An ARP whose slot carries the lease is the declared family
        // whatever protocol it claims: it announces the box's own address,
        // which is what its ordinary ARP announces anyway.
        let own = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x1234, 6, 4, &LEASE));
        assert!(
            admits(&own, &deny_all()),
            "the lease's own ARP resolves under a foreign protocol type too"
        );

        // Too short to carry four bytes of sender address at its own
        // `hlen`: no readable source, so truncated rather than admitted.
        let long_hlen = eth_frame(ETHERTYPE_ARP, &arp_claiming(0x0800, 200, 4, &[]));
        assert_eq!(summarize(&long_hlen).family, FrameFamily::Truncated);
        assert!(!admits(&long_hlen, &allow_all));
    }

    /// NET-079's carve-out: a deny-all box still reaches the resolver
    /// Minimal owns for it, at that resolver's address and port — and
    /// nothing else, not even the resolver on another port.
    #[test]
    fn deny_all_still_reaches_the_resolver() {
        let rules = deny_all();
        assert!(
            admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT), &rules),
            "DNS to the resolver is the one carve-out from a deny-all verdict"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, 54), &rules),
            "the carve-out is by port too"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_TCP, RESOLVER, DNS_PORT), &rules),
            "and by protocol"
        );
        assert!(
            !admits(&ipv4_frame(IPPROTO_UDP, [100, 64, 0, 2], DNS_PORT), &rules),
            "a neighbouring address is not the resolver"
        );
        // The carve-out precedes the deny: a box that denies the resolver's
        // own subnet still resolves.
        let denied_subnet = EgressRules::new(
            Some(Vec::new()),
            Some(Vec::new()),
            Some(vec![Ipv4Cidr {
                addr: [100, 64, 0, 0],
                prefix: 16,
            }]),
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT), &denied_subnet),
            "the carve-out comes before the deny rules"
        );
    }

    /// NET-064: UDP is dropped when only TCP is allowed — and TCP to a
    /// declared subnet still completes (NET-063).
    #[test]
    fn udp_is_dropped_when_only_tcp_is_allowed() {
        let rules = EgressRules::new(
            Some(vec![IPPROTO_TCP]),
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            None,
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_TCP, [10, 1, 2, 3], 80), &rules),
            "TCP to a declared subnet is admitted"
        );
        let udp = ipv4_frame(IPPROTO_UDP, [10, 1, 2, 3], 53);
        assert!(!admits(&udp, &rules));
        assert_eq!(
            verdict(&summarize(&udp), &rules),
            FrameVerdict::Drop(DropReason::UndeclaredProtocol { proto: IPPROTO_UDP })
        );
        // ICMP is undeclared here too: "only TCP" means only TCP.
        assert!(!admits(&ipv4_frame(1, [10, 1, 2, 3], 0), &rules));
    }

    /// NET-062: a destination the rules do not allow is dropped, and the
    /// drop names the rule that fired.
    #[test]
    fn undeclared_destination_drops_with_its_rule() {
        let rules = EgressRules::new(
            None,
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            None,
            RESOLVER,
            LEASE,
        );
        let denied = ipv4_frame(IPPROTO_TCP, [203, 0, 113, 7], 443);
        assert_eq!(
            verdict(&summarize(&denied), &rules),
            FrameVerdict::Drop(DropReason::UndeclaredSubnet {
                dst: [203, 0, 113, 7],
                proto: 6,
            })
        );
        // A deny rule subtracts from the allow: the same box, denied one
        // /24 inside its allowed /8, drops inside that /24 only.
        let subtractive = EgressRules::new(
            None,
            Some(vec![Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            }]),
            Some(vec![Ipv4Cidr {
                addr: [10, 6, 6, 0],
                prefix: 24,
            }]),
            RESOLVER,
            LEASE,
        );
        assert!(
            admits(&ipv4_frame(IPPROTO_TCP, [10, 7, 7, 7], 80), &subtractive),
            "the allow holds outside the denied /24"
        );
        let inside = ipv4_frame(IPPROTO_TCP, [10, 6, 6, 7], 80);
        assert_eq!(
            verdict(&summarize(&inside), &subtractive),
            FrameVerdict::Drop(DropReason::DeniedSubnet {
                dst: [10, 6, 6, 7],
                proto: 6,
            })
        );
    }

    /// The absent-policy default (03-spec R2.1): no rules declared means
    /// everything is admitted — the posture NET-074 replaces when the
    /// deny-all default comes into force.
    #[test]
    fn absent_policy_allows_all() {
        let rules = EgressRules::from_policy(None, RESOLVER, LEASE);
        assert!(admits(
            &ipv4_frame(IPPROTO_UDP, [203, 0, 113, 7], 9999),
            &rules
        ));
        assert!(admits(&ipv4_frame(IPPROTO_TCP, [192, 0, 2, 1], 80), &rules));
    }

    /// `from_policy` compiles each declared dimension and keeps the absent
    /// ones allow-all; `allow_dns_hosts` is not a frame-level rule (it is
    /// the proxy's, NET-066) and compiles to nothing here. The lease is
    /// carried beside the rules: the box's own address on the switch, the
    /// source the verdict checks every frame against (NET-084).
    #[test]
    fn from_policy_compiles_the_declared_dimensions() {
        let policy = EgressPolicy {
            allow_protocols: Some(vec![IpProto::Tcp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: Some(vec!["github.com".to_string()]),
            deny_subnets: None,
        };
        let rules = EgressRules::from_policy(Some(&policy), RESOLVER, LEASE);
        assert_eq!(
            rules,
            EgressRules::new(
                Some(vec![IPPROTO_TCP]),
                Some(vec![Ipv4Cidr {
                    addr: [10, 0, 0, 0],
                    prefix: 8,
                }]),
                None,
                RESOLVER,
                LEASE,
            )
        );
        assert_eq!(rules.resolver(), RESOLVER);
        assert_eq!(rules.lease(), LEASE);
    }

    /// `Ipv4Cidr::parse` accepts exactly the spelling the launch-time
    /// validation accepts for IPv4, and nothing an IPv4 rule can never
    /// match.
    #[test]
    fn cidr_parse_accepts_the_validated_spelling() {
        assert_eq!(
            Ipv4Cidr::parse("10.0.0.0/8"),
            Some(Ipv4Cidr {
                addr: [10, 0, 0, 0],
                prefix: 8,
            })
        );
        assert!(
            Ipv4Cidr::parse("10.0.0.0/33").is_none(),
            "prefix beyond /32"
        );
        assert!(
            Ipv4Cidr::parse("10.0.0.0").is_none(),
            "a bare address is not a CIDR"
        );
        assert!(
            Ipv4Cidr::parse("fe80::/64").is_none(),
            "IPv6 never reaches a rule match"
        );
        assert!(Ipv4Cidr::parse("10.0.0.0/x").is_none());
    }

    /// The prefix match: a CIDR contains its whole prefix and nothing else,
    /// and the degenerate prefixes behave (/0 everything, /32 one address).
    #[test]
    fn cidr_contains_covers_the_prefix() {
        let eight = Ipv4Cidr {
            addr: [10, 0, 0, 0],
            prefix: 8,
        };
        assert!(eight.contains([10, 255, 1, 2]));
        assert!(!eight.contains([11, 0, 0, 0]));
        let everything = Ipv4Cidr {
            addr: [0, 0, 0, 0],
            prefix: 0,
        };
        assert!(everything.contains([203, 0, 113, 7]));
        let one = Ipv4Cidr {
            addr: [10, 1, 2, 3],
            prefix: 32,
        };
        assert!(one.contains([10, 1, 2, 3]));
        assert!(!one.contains([10, 1, 2, 4]));
        // Host bits in the declared address are ignored, as validation
        // normalizing would expect.
        let sloppy = Ipv4Cidr {
            addr: [10, 6, 6, 7],
            prefix: 24,
        };
        assert!(sloppy.contains([10, 6, 6, 200]));
    }

    /// The summary a frame yields: the port is read from the L4 header a
    /// first fragment carries, and only then.
    #[test]
    fn summarize_reads_the_port_only_from_a_first_fragment() {
        let first = ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT);
        assert_eq!(summarize(&first).destination_port(), DNS_PORT);
        assert_eq!(summarize(&first).protocol(), Some(IPPROTO_UDP));
        assert_eq!(summarize(&first).destination(), Some(RESOLVER));
        assert_eq!(summarize(&first).source(), Some(LEASE));

        // A later fragment: the offset bits are set, so there is no L4
        // header to read — and the missing port keeps the carve-out closed.
        let mut later = ipv4_frame(IPPROTO_UDP, RESOLVER, DNS_PORT);
        later[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());
        let summary = summarize(&later);
        assert_eq!(summary.destination_port(), 0);
        assert!(
            !admits(&later, &deny_all()),
            "a fragment with no readable port is not DNS"
        );

        // An L4 header shorter than its ports cannot be read either.
        let short_l4 = eth_frame(
            ETHERTYPE_IPV4,
            &ip_payload(IPPROTO_UDP, LEASE, RESOLVER, 0, &[0u8; 2]),
        );
        assert_eq!(summarize(&short_l4).destination_port(), 0);

        // An IPv4-ethertype frame too short for its IPv4 header.
        let short_ip = eth_frame(ETHERTYPE_IPV4, &[0u8; 10]);
        assert_eq!(summarize(&short_ip).family, FrameFamily::Truncated);
    }

    /// The default switch's host alias, the helper's address the
    /// infrastructure deny set holds beside the resolver.
    const HOST_ALIAS: [u8; 4] = [100, 64, 255, 254];

    /// Compiles a CIDR list, the way [`EgressRules::from_policy`] does, for
    /// the intersection tests below.
    fn cidrs(entries: &[&str]) -> Vec<Ipv4Cidr> {
        entries
            .iter()
            .map(|cidr| Ipv4Cidr::parse(cidr).expect("a declared CIDR parses"))
            .collect()
    }

    /// NET-066/NET-067: the intersection admits exactly the resolved
    /// addresses that no deny and no infrastructure range refuses — a
    /// declared deny first, the fixed ranges under every declaration, and
    /// RFC 1918 only where the box's own `allow_subnets` covers the answer.
    /// Every answer below comes for a name outside the box zone
    /// (`box_zone: false`); the zone carve-out is NET-072's own test.
    #[test]
    fn rebinding_intersection_admits_only_clean_answers() {
        let infrastructure = InfrastructureDenySet::new(RESOLVER, HOST_ALIAS);
        let admit = |answer: [u8; 4], allow: Option<&[Ipv4Cidr]>, deny: Option<&[Ipv4Cidr]>| {
            rebinding_admits(answer, false, allow, deny, &infrastructure)
        };

        // A public answer is admitted with no declarations at all (NET-066).
        admit([140, 82, 121, 3], None, None).unwrap();

        // The box's own denies are subtracted from every name (NET-067).
        let deny = cidrs(&["203.0.113.0/24"]);
        assert_eq!(
            admit([203, 0, 113, 7], None, Some(deny.as_slice())),
            Err(RebindingRefusal::DeniedSubnet)
        );

        // The infrastructure ranges are refused under every declaration —
        // link-local and the metadata services in it, loopback, the completed
        // four (this host, multicast, broadcast, reserved), the plane, and
        // the gateway's own two addresses.
        for refused in [
            [169, 254, 169, 254], // metadata, in link-local
            [127, 0, 0, 1],       // loopback
            [0, 0, 0, 0],         // this host: 0.0.0.0 names the host itself
            [0, 1, 2, 3],         // the rest of this-host space
            [224, 0, 0, 1],       // multicast
            [239, 255, 255, 254], // multicast's last address
            [240, 0, 0, 1],       // reserved
            [255, 255, 255, 255], // broadcast, reserved space's last address
            [100, 64, 0, 9],      // the plane (a box's lease)
            RESOLVER,             // the answerer's own address
            HOST_ALIAS,           // the helper's own address
        ] {
            assert_eq!(
                admit(refused, None, None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} is infrastructure, refused under every declaration"
            );
            // And an explicit allow does not exempt them: the exemption is
            // RFC 1918's alone.
            let allow_all = cidrs(&["0.0.0.0/0"]);
            assert_eq!(
                admit(refused, Some(allow_all.as_slice()), None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} stays refused even where allow_subnets covers it"
            );
        }

        // RFC 1918 is admitted only where `allow_subnets` covers the answer:
        // an open dimension covers it (the address dimension is open, so the
        // name path opens with it), an allow-all entry covers it, an empty
        // one does not, and a different private range does not.
        let private = [10, 1, 2, 3];
        admit(private, None, None).unwrap();
        let allow_all = cidrs(&["0.0.0.0/0"]);
        admit(private, Some(allow_all.as_slice()), None).unwrap();
        let allow_lan = cidrs(&["10.0.0.0/8"]);
        admit(private, Some(allow_lan.as_slice()), None).unwrap();
        let allow_none = cidrs(&[]);
        assert_eq!(
            admit(private, Some(allow_none.as_slice()), None),
            Err(RebindingRefusal::Infrastructure),
            "a deny-all address declaration refuses private answers"
        );
        let allow_other_private = cidrs(&["192.168.0.0/16"]);
        assert_eq!(
            admit(private, Some(allow_other_private.as_slice()), None),
            Err(RebindingRefusal::Infrastructure),
            "a different private range is not a covering"
        );
    }

    /// The IPv6 half of the deny set — the record the IPv6 epoch reads — is
    /// spelled as ranges that parse: an IPv6 address and a prefix length,
    /// every entry of it, so the epoch that builds a set from
    /// [`IPV6_INFRASTRUCTURE_DENY_RANGES`] inherits a set and not a typo.
    #[test]
    fn ipv6_infrastructure_ranges_are_spelled_as_ranges() {
        assert!(
            !IPV6_INFRASTRUCTURE_DENY_RANGES.is_empty(),
            "the record must name the ranges it exists to hold"
        );
        for range in IPV6_INFRASTRUCTURE_DENY_RANGES {
            let (address, prefix) = range.split_once('/').unwrap_or_else(|| {
                panic!("the IPv6 record's entry {range:?} must be spelled as `address/prefix`")
            });
            let prefix = prefix.parse::<u8>().unwrap_or_else(|_| {
                panic!("the IPv6 record's entry {range:?} must carry a numeric prefix")
            });
            assert!(
                prefix <= 128,
                "the IPv6 record's entry {range:?} must carry an IPv6 prefix"
            );
            assert!(
                address.parse::<std::net::Ipv6Addr>().is_ok(),
                "the IPv6 record's entry {range:?} must carry an IPv6 address"
            );
        }
    }

    /// NET-072: a box-zone answer is carved out of the fabric plane — a
    /// sibling's lease is admitted for a zone name with no `allow_dns_hosts`
    /// entry — and the plane is the whole of the carve-out: a zone answer
    /// anywhere else is refused as infrastructure like any other, while
    /// everything else the infrastructure set refuses still refuses a zone
    /// answer, and the box's own deny still outranks the zone.
    #[test]
    fn box_zone_answers_carved_out_of_infrastructure_deny() {
        let infrastructure = InfrastructureDenySet::new(RESOLVER, HOST_ALIAS);
        let admit = |answer: [u8; 4], allow: Option<&[Ipv4Cidr]>, deny: Option<&[Ipv4Cidr]>| {
            rebinding_admits(answer, true, allow, deny, &infrastructure)
        };

        // A sibling's lease — the plane address a zone name must resolve to
        // — is admitted with no declarations at all (NET-072), and the
        // admission holds across the plane's whole span, from its first
        // address to its last, whatever the box declares.
        let allow_all = cidrs(&["0.0.0.0/0"]);
        for lease in [[100, 64, 0, 5], [100, 100, 0, 1], [100, 127, 255, 255]] {
            admit(lease, None, None).unwrap();
            admit(lease, Some(allow_all.as_slice()), None).unwrap();
        }

        // The carve-out is the plane's alone: the fixed ranges still refuse
        // a zone answer under every declaration — the metadata service,
        // loopback, and the gateway's own two addresses.
        for refused in [
            [169, 254, 169, 254], // metadata, in link-local
            [127, 0, 0, 1],       // loopback
            RESOLVER,             // the answerer's own address
            HOST_ALIAS,           // the helper's own address
        ] {
            assert_eq!(
                admit(refused, None, None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} is infrastructure, refused for a zone answer too"
            );
            // And an explicit allow does not exempt them: the exemption is
            // RFC 1918's alone.
            assert_eq!(
                admit(refused, Some(allow_all.as_slice()), None),
                Err(RebindingRefusal::Infrastructure),
                "{refused:?} stays refused even where allow_subnets covers it"
            );
        }

        // And the plane is the carve-out's whole width: a zone answer
        // outside it is refused as infrastructure under every declaration —
        // RFC 1918, where `allow_subnets` exempts an ordinary name's answer,
        // as much as a public address — so a zone answer may name nothing
        // but a sibling's lease.
        let allow_lan = cidrs(&["10.0.0.0/8"]);
        let allow_none = cidrs(&[]);
        for (answer, allow, because) in [
            (
                [10, 1, 2, 3],
                None,
                "an open address dimension exempts nothing",
            ),
            (
                [10, 1, 2, 3],
                Some(allow_lan.as_slice()),
                "a covering allow entry exempts nothing",
            ),
            (
                [10, 1, 2, 3],
                Some(allow_none.as_slice()),
                "a deny-all declaration refuses it outright",
            ),
            (
                [203, 0, 113, 9],
                None,
                "a public answer is refused the same",
            ),
        ] {
            assert_eq!(
                admit(answer, allow, None),
                Err(RebindingRefusal::Infrastructure),
                "{because}: no zone answer is admitted outside the plane"
            );
        }

        // The box's own deny still outranks the zone: a declared deny
        // refuses a zone answer pointing at the denied range.
        let deny = cidrs(&["100.64.0.0/16"]);
        assert_eq!(
            admit([100, 64, 0, 5], None, Some(deny.as_slice())),
            Err(RebindingRefusal::DeniedSubnet),
            "a declared deny refuses a zone answer like any other"
        );
    }

    /// [`rebinding_intersection`] — the set-shaped wrapper the relay calls per
    /// reply: it splits the answer set exactly (nothing dropped, nothing
    /// duplicated, order preserved), each refusal carrying its reason.
    #[test]
    fn rebinding_intersection_splits_the_answer_set() {
        let infrastructure = InfrastructureDenySet::new(RESOLVER, HOST_ALIAS);
        let answers = [
            [140, 82, 121, 3], // admitted: public
            [203, 0, 113, 7],  // refused: the box's deny
            [10, 1, 2, 3],     // refused: RFC 1918, uncovered
            [169, 254, 1, 1],  // refused: fixed infrastructure
            [140, 82, 121, 4], // admitted: public
        ];
        let allow = cidrs(&[]);
        let deny = cidrs(&["203.0.113.0/24"]);
        let split = rebinding_intersection(
            &answers,
            false,
            Some(allow.as_slice()),
            Some(deny.as_slice()),
            &infrastructure,
        );
        assert_eq!(
            split.admitted,
            [[140, 82, 121, 3], [140, 82, 121, 4]],
            "the admitted addresses, in the order the answer carried them"
        );
        assert_eq!(
            split.refused,
            [
                ([203, 0, 113, 7], RebindingRefusal::DeniedSubnet),
                ([10, 1, 2, 3], RebindingRefusal::Infrastructure),
                ([169, 254, 1, 1], RebindingRefusal::Infrastructure),
            ]
        );
    }

    /// The subnet accessors the rebinding intersection reads: they surface
    /// the compiled dimensions of the policy, and stay `None` where the
    /// policy left the dimension open.
    #[test]
    fn subnet_accessors_expose_the_compiled_dimensions() {
        let policy = EgressPolicy {
            allow_protocols: None,
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
        };
        let rules = EgressRules::from_policy(Some(&policy), RESOLVER, LEASE);
        let allow = rules.allow_subnets().expect("allow_subnets compiled");
        assert_eq!(allow.len(), 1);
        assert!(allow[0].contains([10, 200, 0, 1]));
        assert!(!allow[0].contains([192, 168, 0, 1]));
        let deny = rules.deny_subnets().expect("deny_subnets compiled");
        assert_eq!(deny.len(), 1);
        assert!(deny[0].contains([192, 168, 0, 1]));

        let open = EgressRules::from_policy(None, RESOLVER, LEASE);
        assert!(open.allow_subnets().is_none() && open.deny_subnets().is_none());
    }

    /// An L4 header carrying both ports — the reply-flow record's frames are
    /// the one place a frame's *source* port is the fact under test.
    fn l4_pair(src_port: u16, dst_port: u16) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out
    }

    /// An IPv4 frame for `proto` from `src`:`src_port` to `dst`:`dst_port`.
    fn ipv4_frame_pair(
        src: [u8; 4],
        src_port: u16,
        proto: u8,
        dst: [u8; 4],
        dst_port: u16,
    ) -> Vec<u8> {
        eth_frame(
            ETHERTYPE_IPV4,
            &ip_payload(proto, src, dst, 0, &l4_pair(src_port, dst_port)),
        )
    }

    /// NET-040's answer half, the shared decision's own proof: a box frame
    /// whose five-tuple exactly reverses a live inbound-flow record is
    /// admitted ahead of the egress rules — deny-all's own dimensions
    /// included, the `deny_subnets` a row's rules carry and the
    /// infrastructure set the host gate refuses by — and no other box frame
    /// is admitted by the record: not the client's address at another port,
    /// not another client's address, not another protocol, not the box
    /// speaking from its own connecting port. The record ends at its close
    /// (FIN, from either end), at its window, and at revocation — and the
    /// egress arm can open none of it back up.
    #[test]
    fn reply_on_admitted_inbound_flow_passes_egress() {
        let t0 = Instant::now();
        let client = [203, 0, 113, 7];
        let rules = deny_all();
        // The conversation the record is about: the client's bare SYN to the
        // box's published port, and the box's answer back — the frame a
        // deny-all box's own rules refuse.
        let opening = FlowTuple::new(IPPROTO_TCP, client, 51000, LEASE, 8080);
        let answer = ipv4_frame_pair(LEASE, 8080, IPPROTO_TCP, client, 51000);
        assert!(
            !admits(&answer, &rules),
            "a deny-all box's answer is not a frame its own rules admit"
        );
        let mut flows = ReplyFlows::new();
        // The gate delivered the opening packet, so the flow is recorded —
        // and only that is what makes the answer pass.
        assert_eq!(
            flows.observe_inbound(opening, TCP_SYN, t0),
            InboundFlow::Recorded { filled: false }
        );
        assert!(
            flows.reply_admits(opening.reversed(), TCP_ACK, t0),
            "the reply on a live record passes, ahead of the rules"
        );
        // Nothing beside the exact reverse passes: another port at the same
        // client, another client, another protocol, and the box speaking
        // from its own connecting port rather than the published one.
        for near in [
            FlowTuple::new(IPPROTO_TCP, LEASE, 8080, client, 51001),
            FlowTuple::new(IPPROTO_TCP, LEASE, 8080, [203, 0, 113, 8], 51000),
            FlowTuple::new(IPPROTO_UDP, LEASE, 8080, client, 51000),
            FlowTuple::new(IPPROTO_TCP, LEASE, 40000, client, 51000),
        ] {
            assert!(
                !flows.reply_admits(near, TCP_ACK, t0),
                "a frame that reverses no live record passes: {near:?}"
            );
        }
        // The box's FIN passes — the close is part of the conversation — and
        // ends the record, so nothing after it is a reply this flow admits.
        assert!(flows.reply_admits(opening.reversed(), TCP_FIN, t0));
        assert_eq!(flows.record_of(opening), None);
        assert!(
            !flows.reply_admits(opening.reversed(), TCP_ACK, t0),
            "a record the box's FIN ended admits nothing after it"
        );
        // The client's FIN ends it from its own side, delivered though the
        // closing frame still is.
        assert_eq!(
            flows.observe_inbound(opening, TCP_SYN, t0),
            InboundFlow::Recorded { filled: false }
        );
        assert_eq!(
            flows.observe_inbound(opening, TCP_FIN, t0),
            InboundFlow::Ended
        );
        assert!(!flows.reply_admits(opening.reversed(), TCP_ACK, t0));
        // Revocation and session stop end every record without reading the
        // wire at all.
        assert_eq!(
            flows.observe_inbound(opening, TCP_SYN, t0),
            InboundFlow::Recorded { filled: false }
        );
        flows.clear();
        assert!(!flows.reply_admits(opening.reversed(), TCP_ACK, t0));
        // UDP: the first answer moves the record onto the replied window, so
        // an answered conversation outlives the unreplied one — and dies one
        // replied window after its last answer — while an unanswered one
        // dies at the unreplied window.
        let datagram = FlowTuple::new(IPPROTO_UDP, client, 53000, LEASE, 8080);
        assert_eq!(
            flows.observe_inbound(datagram, 0, t0),
            InboundFlow::Recorded { filled: false }
        );
        assert!(flows.reply_admits(datagram.reversed(), 0, t0));
        assert!(
            flows
                .record_of(datagram)
                .is_some_and(|record| record.was_replied())
        );
        assert!(flows.reply_admits(datagram.reversed(), 0, t0 + REPLY_UDP_UNREPLIED_WINDOW));
        assert!(!flows.reply_admits(
            datagram.reversed(),
            0,
            t0 + REPLY_UDP_UNREPLIED_WINDOW + REPLY_UDP_REPLIED_WINDOW
        ));
        let quiet = FlowTuple::new(IPPROTO_UDP, client, 53001, LEASE, 8080);
        assert_eq!(
            flows.observe_inbound(quiet, 0, t0),
            InboundFlow::Recorded { filled: false }
        );
        assert!(
            !flows.reply_admits(quiet.reversed(), 0, t0 + REPLY_UDP_UNREPLIED_WINDOW),
            "a UDP record the box never answered dies at the unreplied window"
        );
        // An expired record is gone, not limp: the next delivered opening
        // packet opens a fresh one.
        assert_eq!(
            flows.observe_inbound(quiet, 0, t0 + REPLY_UDP_UNREPLIED_WINDOW),
            InboundFlow::Recorded { filled: false }
        );
    }

    /// The record's other face: no frame a box sends can open one. The
    /// egress arm is a lookup and nothing else — it never inserts, and never
    /// mints the admission a box would need to reach a destination its rules
    /// refuse — so a box cannot talk itself into an inbound flow, whatever
    /// shape it sends, and only a delivered opening packet ever opens a
    /// record.
    #[test]
    fn box_frame_never_opens_a_reply_record() {
        let t0 = Instant::now();
        let client = [203, 0, 113, 7];
        let mut flows = ReplyFlows::new();
        // Box frames against an empty table: the reply shape, a connect the
        // box initiates, a datagram, and a frame to itself. None finds a
        // record, and none creates one.
        for sent in [
            FlowTuple::new(IPPROTO_TCP, LEASE, 8080, client, 51000),
            FlowTuple::new(IPPROTO_TCP, LEASE, 40000, client, 443),
            FlowTuple::new(IPPROTO_UDP, LEASE, 8080, client, 51000),
            FlowTuple::new(IPPROTO_TCP, LEASE, 8080, LEASE, 8080),
        ] {
            assert!(
                !flows.reply_admits(sent, TCP_SYN, t0),
                "no box frame is admitted with no record to reverse: {sent:?}"
            );
        }
        assert_eq!(flows.len(), 0, "no box frame opened a record");
        // With a live record the box's reply refreshes it — and still opens
        // nothing, on this tuple or any other.
        let opening = FlowTuple::new(IPPROTO_TCP, client, 51000, LEASE, 8080);
        assert_eq!(
            flows.observe_inbound(opening, TCP_SYN, t0),
            InboundFlow::Recorded { filled: false }
        );
        assert_eq!(
            flows.len(),
            1,
            "the delivered opening packet is what opened the record"
        );
        assert!(flows.reply_admits(opening.reversed(), TCP_ACK, t0));
        assert_eq!(
            flows.len(),
            1,
            "the box's reply refreshed its record, no more"
        );
        for sent in [
            // A SYN the box sends — a connect it initiates toward the very
            // client whose record is live — reverses no live record and
            // mints none.
            FlowTuple::new(IPPROTO_TCP, LEASE, 40000, client, 51000),
            FlowTuple::new(IPPROTO_TCP, LEASE, 40000, client, 8080),
        ] {
            assert!(
                !flows.reply_admits(sent, TCP_SYN, t0),
                "a connect the box initiates is not a reply: {sent:?}"
            );
            assert_eq!(flows.len(), 1, "no box frame opened a record");
        }
        // And a mid-stream inbound segment opens nothing either — only a
        // delivered opening packet does, which is what keeps a record an
        // admission the box's *ingress* earned.
        let stray_ack = FlowTuple::new(IPPROTO_TCP, client, 59000, LEASE, 8080);
        assert_eq!(
            flows.observe_inbound(stray_ack, TCP_ACK, t0),
            InboundFlow::Untracked
        );
        assert_eq!(
            flows.observe_inbound(stray_ack, TCP_SYN | TCP_ACK, t0),
            InboundFlow::Untracked
        );
        assert_eq!(flows.len(), 1, "no mid-stream segment opened a record");
    }
}

/// The frame-level admit-or-drop harness NET-016, NET-062, NET-064,
/// NET-069, NET-070, NET-081's failure case and NET-084 share (spec NET,
/// Tiers): exhaustive over every value the decision reads — the fragment
/// offset, the source, the protocol, the destination and the L4 destination
/// port of an IPv4 frame, plus the lease the source must be — under rule
/// lists of zero or two rules per dimension, at an unwind bound of 6 (the
/// `[u8; 4]` address comparisons lower to a 4-trip `memcmp` loop; see the
/// harness).
///
/// The module also carries the rebinding intersection's harness (NET-067,
/// [`kani_rebinding_intersection_admits_no_denied_address`]), which shares
/// [`two_cidrs`] and its pinning rationale and runs at the tighter bound 4
/// its own doc explains.
///
/// The scope is deliberate. This module's first form was exhaustive over a
/// fully symbolic 40-byte header and rule lists of symbolic *length*, and
/// its solve outlived the CI lane — one 60-minute job timeout, then two
/// runs cancelled nine minutes in (gominimal/minimal#1700) — because CBMC
/// unwound each rule scan without being able to see it end. The harness
/// below pins what the decision never reads and keeps every list at a
/// concrete length; what is pinned, and why each pin is sound, is
/// documented there.
///
/// Run: `cargo kani -p sessions` (or `./scripts/kani.sh`). Kani pinned at
/// 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use super::{
        DNS_PORT, ETH_HDR, ETHERTYPE_IPV4, EgressRules, FrameFamily, FrameVerdict, IPPROTO_UDP,
        InfrastructureDenySet, Ipv4Cidr, rebinding_admits, rebinding_intersection, summarize,
        verdict,
    };

    /// One dimension's rules under every declaration the compile can
    /// produce: `None` (the dimension is undeclared, so it allows all),
    /// `Some(vec![])` (declared empty, so it allows nothing — the deny-all
    /// box the resolver carve-out must still resolve), or `Some` of two
    /// fully symbolic rules.
    ///
    /// Every arm carries a CONCRETE length, and that is the point: a list
    /// of symbolic element count is what made this proof unaffordable (see
    /// the module doc), because CBMC unwound each scan without being able
    /// to read its trip count off the code. Two rules is what catches a
    /// scan that reads only one element or stops one short of the end; a
    /// third adds no failure shape.
    fn two_protocols() -> Option<Vec<u8>> {
        match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, _) => None,
            (true, false) => Some(Vec::new()),
            (true, true) => Some(Vec::from([kani::any::<u8>(), kani::any::<u8>()])),
        }
    }

    /// [`two_protocols`] for a CIDR dimension: subnets fully symbolic,
    /// prefix lengths included, so the proof also covers the out-of-range
    /// prefixes [`Ipv4Cidr::contains`] must survive — its shift is guarded
    /// at both ends.
    fn two_cidrs() -> Option<Vec<Ipv4Cidr>> {
        match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, _) => None,
            (true, false) => Some(Vec::new()),
            (true, true) => Some(Vec::from([
                kani::any::<Ipv4Cidr>(),
                kani::any::<Ipv4Cidr>(),
            ])),
        }
    }

    /// A frame is admitted exactly when it is declared: stated as an iff so
    /// neither arm can silently become unreachable (the rcache harness
    /// pattern). The declared half is restated over the same summary and
    /// rules — the lease first (NET-084: the source is the lease), then the
    /// resolver carve-out (NET-079), then the three declared dimensions
    /// conjunctively — so a verdict that checks in a different order, or
    /// that reads `None` as deny-all, fails here.
    ///
    /// The unwind bound is 6, with one loop to spare over the longest
    /// this proof unwinds: comparing `[u8; 4]` addresses lowers to
    /// CBMC's builtin `memcmp`, a 4-trip loop, so a bound of 4 fails an
    /// unwinding assertion even though every loop the harness itself
    /// writes (the rule scans in `verdict` and below, over lists of at
    /// most two rules) has exited by its third check. The bound has to
    /// clear every trip the compiler generates, not only the ones the
    /// source shows; the lease check's source comparison is one more of
    /// those `memcmp`s, not a longer one.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_frame_verdict_admits_nothing_undeclared() {
        // One 54-byte Ethernet frame — a 14-byte header and a 40-byte IPv4
        // region, 20 bytes of IPv4 header plus 20 of L4 — the shape the
        // relay hands the verdict for every IPv4 packet it forwards.
        //
        // Symbolic: the fragment offset, the source, the protocol, the
        // destination and the L4 destination port — every value the
        // decision reads — and the lease, beside the rules, that the source
        // is checked against (NET-084's property is over every frame and
        // every lease).
        //
        // Pinned to constants: the EtherType (IPv4, the one family the
        // rules decide; the families decided without rules each have their
        // own pinned-frame unit test) and the version/IHL (4/5, the
        // 20-byte header every real guest emits, which is what puts the
        // L4 port at a readable offset). A fragment with no readable port
        // — the case that must keep the carve-out closed — is still in the
        // proof, via the symbolic fragment offset.
        //
        // Pinned to zero: the two MACs and every byte of the L4 around the
        // port, which the decision never reads and CBMC would otherwise
        // pay for bit by bit.
        let frag: u16 = kani::any();
        let proto: u8 = kani::any();
        let src: [u8; 4] = kani::any();
        let dst: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let mut frame = [0u8; ETH_HDR + 40];
        let ethertype = ETHERTYPE_IPV4.to_be_bytes();
        frame[12] = ethertype[0];
        frame[13] = ethertype[1];
        let ip = ETH_HDR;
        frame[ip] = 0x45; // version 4, IHL 5
        let frag_bytes = frag.to_be_bytes();
        frame[ip + 6] = frag_bytes[0]; // flags + fragment offset
        frame[ip + 7] = frag_bytes[1];
        frame[ip + 9] = proto;
        frame[ip + 12] = src[0]; // the IPv4 source address
        frame[ip + 13] = src[1];
        frame[ip + 14] = src[2];
        frame[ip + 15] = src[3];
        frame[ip + 16] = dst[0];
        frame[ip + 17] = dst[1];
        frame[ip + 18] = dst[2];
        frame[ip + 19] = dst[3];
        let port_bytes = port.to_be_bytes();
        frame[ip + 22] = port_bytes[0]; // the L4 destination port
        frame[ip + 23] = port_bytes[1];

        let summary = summarize(&frame);
        assert!(matches!(summary.family(), FrameFamily::Ipv4));

        let resolver: [u8; 4] = kani::any();
        let lease: [u8; 4] = kani::any();
        let rules = EgressRules::new(two_protocols(), two_cidrs(), two_cidrs(), resolver, lease);

        let admitted = matches!(verdict(&summary, &rules), FrameVerdict::Admit);

        let declared = match (summary.source(), summary.destination(), summary.protocol()) {
            (Some(src), Some(dst), Some(proto)) => {
                let lease = src == rules.lease();
                let resolver = proto == IPPROTO_UDP
                    && dst == rules.resolver()
                    && summary.destination_port() == DNS_PORT;
                let protocols = rules
                    .allow_protocols
                    .as_ref()
                    .is_none_or(|list| list.contains(&proto));
                let denied = rules
                    .deny_subnets
                    .as_ref()
                    .is_some_and(|list| list.iter().any(|cidr| cidr.contains(dst)));
                let allowed = rules
                    .allow_subnets
                    .as_ref()
                    .is_none_or(|list| list.iter().any(|cidr| cidr.contains(dst)));
                lease && (resolver || (protocols && !denied && allowed))
            }
            // No readable IPv4 header is never a declared frame.
            _ => false,
        };
        assert_eq!(admitted, declared);
    }

    /// NET-067's property, the rebinding half: **for every resolved answer
    /// set and every allow, deny, and infrastructure-deny CIDR set, the
    /// admitted set contains no denied address** — proved in two parts that
    /// share one set of rule lists:
    ///
    /// * the per-address decision, restated as an iff over one fully
    ///   symbolic answer so neither arm can silently become unreachable (the
    ///   rcache harness pattern) — this is the exhaustive half, over every
    ///   IPv4 answer there is;
    /// * the set-shaped wrapper, over an answer set of two symbolic
    ///   addresses, asserting the split loses nothing (the counts match the
    ///   oracle) and that every address the wrapper admitted passes the
    ///   oracle — so no cross-answer coupling (admit one because another is
    ///   clean) and no loss can hide.
    ///
    /// Every CIDR set rides [`two_cidrs`]: `None`, empty, or two symbolic
    /// rules — **two** per set, one tighter than the tier text's "at most
    /// 4", for the same reason [`two_protocols`] pins two: two rules is
    /// what catches a scan that reads only one element or stops one short
    /// of the end, and a third adds no failure shape while it multiplies
    /// CBMC's search. Both list-shaped halves of the infrastructure set
    /// ride it too, so a set-shaped hole that only opens at three or more
    /// rules is outside this proof's bound — stated here rather than left
    /// to be read off the tier text. The plane rides one symbolic CIDR,
    /// which is exactly what the set holds it as.
    ///
    /// The unwind bound is 4. No loop this proof unwinds runs past its third
    /// check: the set scans walk lists of at most two CIDRs, the answer-set
    /// loop walks two answers, and — unlike the frame-verdict harness, whose
    /// `[u8; 4]` comparisons lower to a 4-trip `memcmp` — every comparison
    /// here is [`Ipv4Cidr::contains`]'s u32 mask arithmetic, so there is no
    /// address-equality loop to buy extra trips for. (The wrapper's `Vec`s
    /// are pre-sized to the answer count, so no growth copy enters the proof
    /// either.)
    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_rebinding_intersection_admits_no_denied_address() {
        let allow = two_cidrs();
        let deny = two_cidrs();
        let infrastructure = InfrastructureDenySet {
            fixed: two_cidrs().unwrap_or_default(),
            plane: kani::any(),
            rfc1918: two_cidrs().unwrap_or_default(),
        };
        // Whether the answers below come for a box-zone name (NET-072) —
        // the one fact that decides which side of the fabric plane an
        // answer is admitted on.
        let box_zone: bool = kani::any();
        // The oracle's one question, restated over CIDR math alone: may this
        // answer be admitted — not denied by the box, not in a fixed
        // infrastructure range, on the plane's zone-answering side (inside
        // for a zone name, outside for any other), and not in RFC 1918 that
        // `allow_subnets` does not cover?
        let admissible = |answer: [u8; 4]| {
            let denied = deny
                .as_deref()
                .is_some_and(|list| list.iter().any(|cidr| cidr.contains(answer)));
            let fixed = infrastructure
                .fixed
                .iter()
                .any(|cidr| cidr.contains(answer));
            let plane = box_zone != infrastructure.plane.contains(answer);
            let rfc1918 = infrastructure
                .rfc1918
                .iter()
                .any(|cidr| cidr.contains(answer));
            let covers = allow
                .as_deref()
                .is_none_or(|list| list.iter().any(|cidr| cidr.contains(answer)));
            !denied && !fixed && !plane && (!rfc1918 || covers)
        };

        // Part one: the per-address decision, iff the oracle, over every
        // IPv4 answer.
        let answer: [u8; 4] = kani::any();
        let admitted = rebinding_admits(
            answer,
            box_zone,
            allow.as_deref(),
            deny.as_deref(),
            &infrastructure,
        )
        .is_ok();
        assert_eq!(admitted, admissible(answer));

        // Part two: the wrapper over a two-answer set — the split is exact,
        // and everything it admitted passes the oracle.
        let answers = [kani::any::<[u8; 4]>(), kani::any::<[u8; 4]>()];
        let split = rebinding_intersection(
            &answers,
            box_zone,
            allow.as_deref(),
            deny.as_deref(),
            &infrastructure,
        );
        let expected: usize = answers.iter().filter(|a| admissible(**a)).count();
        assert_eq!(split.admitted.len(), expected);
        assert_eq!(split.refused.len(), answers.len() - expected);
        for address in &split.admitted {
            assert!(
                admissible(*address),
                "the admitted set holds an address the oracle denies"
            );
        }
        for (address, _) in &split.refused {
            assert!(!admissible(*address), "an admissible answer was refused");
        }
    }
}
