//! Static ingress port-mapping via gvproxy's forwarder API (R2.3, R2.4-static)
//! and rate-limited policy-violation warning plumbing (R2.7).
//!
//! The gvproxy v0.8.9 spike (`docs/spikes/2026-06-21-gvproxy-attachment.md` §5)
//! pinned two load-bearing facts this module is built on:
//!
//! * The forwarder / management API is reachable **only** on the host-side
//!   control socket (the same unix socket [`switch`](super::switch) connects to
//!   for `POST /connect`), **not** the in-PTask gateway IP. So minimald drives
//!   ingress from the daemon side, where it already holds the control socket.
//! * gvproxy exposes `POST /services/forwarder/expose` and
//!   `POST /services/forwarder/unexpose` there to add and remove static port
//!   forwards.
//!
//! The same spike established that gvproxy v0.8.9 has **no per-client egress
//! ACL API**, so egress *enforcement* (R2.2) lives in the relay — the
//! [`switch`](super::switch) module's `EgressGate`, deciding each frame with
//! `sessions`' pure verdict — not here. What R2.7 needs from this module is
//! the warning plumbing ([`PolicyWarnLimiter`] and [`KeyedWarnLimiter`]).

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_vsock::{VsockAddr, VsockStream};

use sessions::core::net_verdict::{
    DropRule, EgressRules, IPPROTO_TCP, IngressRules, ProxiedRequest, Verdict, proxied_verdict,
};
use sessions::{IngressPolicy, IpProto, PortMapping};

use super::SwitchSubnet;

/// The forwarder-expose request body gvproxy's `POST /services/forwarder/expose`
/// expects: a host-side `local` listen address and the PTask-side `remote` it
/// forwards to, plus the transport `protocol`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExposeRequest {
    /// Host-side listen address, `host:port` (e.g. `127.0.0.1:8080`).
    pub local: String,
    /// PTask-side destination, `ip:port`.
    pub remote: String,
    /// Transport protocol (`tcp` / `udp`).
    pub protocol: String,
}

/// The `POST /services/forwarder/unexpose` body: the `local` address (and its
/// `protocol`) a prior [`ExposeRequest`] bound, identifying the forward to drop.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnexposeRequest {
    /// The host-side listen address the forward was exposed on.
    pub local: String,
    /// The transport protocol the forward was exposed with.
    pub protocol: String,
}

/// How minimald reaches gvproxy's control socket to drive the forwarder API.
///
/// On DM2 the gvproxy `minimald` spawned is local, so the control socket is a
/// unix path. On DM1/3/4 gvproxy runs on the host (`minvmd` owns it); the guest
/// reaches the same `-listen` control socket over the per-host vsock shuttle
/// (`minvmd` maps the shuttle port to it via `krun_add_vsock_port2`), so the
/// forwarder verbs ride the same channel as the L2 `POST /connect` relay.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ControlChannel {
    /// Local unix control socket (DM2).
    Unix(std::path::PathBuf),
    /// Host gvproxy reached over vsock (DM1/3/4): `cid` = host (2), `port` = the
    /// shuttle port `minvmd` bridged to the gvproxy control socket.
    Vsock { cid: u32, port: u32 },
}

/// gvproxy's wire spelling of an [`IpProto`] in a forwarder request.
fn protocol_str(proto: IpProto) -> &'static str {
    match proto {
        IpProto::Tcp => "tcp",
        IpProto::Udp => "udp",
        // gvproxy's forwarder only exposes TCP/UDP, and `Record::validate_policy`
        // rejects any other protocol before it reaches here. `IpProto` is also
        // `#[non_exhaustive]`, so the `_` arm cannot be eliminated; a
        // `debug_assert!` surfaces any future caller that bypasses validation in
        // test runs, while TCP — the forwarder's default transport — stays the
        // production fallback rather than a silently misrouted request.
        _ => {
            debug_assert!(
                false,
                "protocol_str reached its fallback with {proto:?}; validate_policy \
                 must reject every non-TCP/UDP ingress protocol before apply_ingress"
            );
            "tcp"
        }
    }
}

/// Builds the [`ExposeRequest`] that forwards `mapping`'s host-side
/// `external_port` to `ptask_ip:internal_port` on the switch.
///
/// The `local` host is `127.0.0.1` so the forward binds host loopback only: a
/// process *on the host* reaches the port (R2.3), while the spec's "no external
/// exposure by default" keeps it off the LAN. The `remote` targets the PTask's
/// allocated switch address.
#[must_use]
pub fn expose_request(mapping: &PortMapping, ptask_ip: Ipv4Addr) -> ExposeRequest {
    ExposeRequest {
        local: format!("127.0.0.1:{}", mapping.external_port),
        remote: format!("{ptask_ip}:{}", mapping.internal_port),
        protocol: protocol_str(mapping.proto).to_string(),
    }
}

/// A forward currently exposed on the switch, retained so it can be torn down
/// on PTask exit ([`remove_ingress`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedMapping {
    local: String,
    protocol: String,
}

/// Exposes every static port mapping in `ingress` on the switch's `control_sock`
/// forwarding to `ptask_ip`, returning a handle per exposed forward for teardown
/// (R2.3, R2.4-static). The dynamic range, if any, is not applied here — dynamic
/// port-mapping is split to #553.
///
/// On the first failure the already-exposed forwards are rolled back so a partial
/// apply does not leak forwards onto the switch, and the original error is
/// returned.
///
/// # Errors
///
/// Returns the I/O error from the first failing `expose` call (after rollback).
pub async fn apply_ingress(
    control: &ControlChannel,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
) -> io::Result<Vec<ExposedMapping>> {
    let mut exposed: Vec<ExposedMapping> = Vec::with_capacity(ingress.port_mappings.len());
    for mapping in &ingress.port_mappings {
        let req = expose_request(mapping, ptask_ip);
        match post_json(control, "/services/forwarder/expose", &req).await {
            Ok(()) => exposed.push(ExposedMapping {
                local: req.local,
                protocol: req.protocol,
            }),
            Err(e) => {
                // Roll back what we managed to expose so a half-applied policy
                // does not leave dangling forwards on the shared switch.
                remove_ingress(control, &exposed).await;
                return Err(e);
            }
        }
    }
    Ok(exposed)
}

/// Removes every forward in `exposed` from the switch's `control_sock` (R2.3
/// teardown on PTask exit). Best-effort: a failed unexpose is logged and the
/// rest still attempted, since teardown runs on the session-end path where there
/// is no caller left to propagate to.
pub async fn remove_ingress(control: &ControlChannel, exposed: &[ExposedMapping]) {
    for mapping in exposed {
        let req = UnexposeRequest {
            local: mapping.local.clone(),
            protocol: mapping.protocol.clone(),
        };
        if let Err(e) = post_json(control, "/services/forwarder/unexpose", &req).await {
            tracing::warn!(
                local = %mapping.local,
                error = %e,
                "removing ingress port mapping from switch on PTask exit"
            );
        }
    }
}

/// A gvproxy DNS zone-add request body for `POST /services/dns/add`
/// (gvproxy's `types.Zone`): registers `records` under the DNS zone `name`.
///
/// gvproxy merges on re-add with newest-first precedence and resolves to the
/// first matching record, so re-registering a name with a new IP makes the
/// newest win — how a rotated lease is picked up with no remove verb.
#[derive(Debug, Serialize)]
struct DnsZone {
    name: String,
    records: Vec<DnsRecord>,
}

/// A single `name → ip` answer within a [`DnsZone`].
#[derive(Debug, Serialize)]
struct DnsRecord {
    name: String,
    ip: String,
}

/// Registers `<session_name>` in gvproxy's `min.internal.` DNS zone, pointing at
/// the PTask's current switch lease (finding #3 / UC6). A box's name is
/// two-label (NET-001), so the record is the session name alone.
///
/// gvproxy's resolver is the switch gateway (`100.64.0.1`) that every own-IP
/// sandbox's `resolv.conf` already targets, so this makes a PTask's
/// `*.min.internal` hostname resolvable *from a peer session* — with no new
/// resolver process and no `resolv.conf` change. The zone `Name` carries the
/// trailing dot gvproxy matches DNS queries against; the record label is
/// lowercased (gvproxy matches labels case-sensitively).
///
/// # Errors
///
/// Returns the I/O error from the gvproxy control request (non-2xx or transport).
pub async fn register_dns_name(
    control: &ControlChannel,
    session_name: &str,
    lease_ip: Ipv4Addr,
) -> io::Result<()> {
    post_json(
        control,
        "/services/dns/add",
        &dns_add_body(session_name, lease_ip),
    )
    .await
}

/// Builds the `/services/dns/add` zone body for a PTask. Split out so the exact
/// wire shape (trailing-dot zone, lowercased label, dotted-quad IP) is unit-testable
/// without a live gvproxy.
fn dns_add_body(session_name: &str, lease_ip: Ipv4Addr) -> DnsZone {
    DnsZone {
        name: format!("{}.", crate::net::dns::HOSTNAME_SUFFIX),
        records: vec![DnsRecord {
            name: session_name.to_ascii_lowercase(),
            ip: lease_ip.to_string(),
        }],
    }
}

/// One box's place in the in-guest box zone: the lease the node's DNS layer
/// answers its name with, and the ports its own ingress rules declare.
///
/// Both halves travel together because a box-to-box connection is decided on
/// both (NET-073) — the source's egress rules on its own relay leg, the
/// target's ingress rules on the target's — so the leg that sees the frame
/// leave can name the box it is addressed to and the verdict waiting for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxZoneEntry {
    /// The box's session name: the single label its box-zone name carries
    /// (NET-001), lower-cased as the zone holds it.
    pub session: String,
    /// The switch lease `<session>.min.internal` resolves to inside boxes.
    pub lease: Ipv4Addr,
    /// The TCP ports its ingress declares — the internal ports of its TCP
    /// mappings, what a sibling dials. Empty accepts no new inbound connection.
    pub tcp_ports: BTreeSet<u16>,
    /// The UDP ports its ingress declares.
    pub udp_ports: BTreeSet<u16>,
}

impl BoxZoneEntry {
    /// The box's two-label name (NET-001).
    #[must_use]
    pub fn name(&self) -> String {
        format!("{}.{}", self.session, crate::net::dns::HOSTNAME_SUFFIX)
    }

    /// Whether the box's ingress rules declare `port` for `proto`. A transport
    /// its mappings cannot name declares nothing: ingress is stated per
    /// transport, and the target's gate gates exactly those two.
    fn declares(&self, proto: IpProto, port: u16) -> bool {
        match proto {
            IpProto::Tcp => self.tcp_ports.contains(&port),
            IpProto::Udp => self.udp_ports.contains(&port),
            _ => false,
        }
    }
}

/// What the target box's own ingress rules say about the port a sibling dialled
/// (NET-073): the half of the verdict decided on the target's relay leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressVerdict {
    /// The target declared the port; its ingress gate admits the connection.
    Declared,
    /// The target declared no such port; its ingress gate drops the connection.
    Undeclared,
}

impl IngressVerdict {
    /// The verdict as the box-zone connection line spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Undeclared => "undeclared",
        }
    }
}

impl fmt::Display for IngressVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The target side of a box-to-box connection: the box holding the address
/// dialled, and what its own ingress rules say about the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxZoneTarget {
    /// The target box's session name.
    pub session: String,
    /// Its ingress rules' verdict on the port dialled.
    pub ingress: IngressVerdict,
}

/// The in-guest box zone: the entries `minimald` registered with the node's DNS
/// layer ([`register_dns_name`]), one per live own-address box, shared by every
/// box's relay.
///
/// Resolution needs no `egress.allow_dns_hosts` entry (NET-072). A box's lookup
/// reaches the resolver Minimal owns for it through the deny-all carve-out
/// (design §4.1), and the answer comes from this zone — no box's allow list is
/// read on the path, so a box with a name allow list naming only `github.com`,
/// and a box with no reach at all, resolve a sibling's name alike.
///
/// Reach is the separate question, and stays with the two boxes' rules
/// (NET-073): the source's egress gate decides the frame leaving it and the
/// target's ingress gate decides it arriving, so a resolved name is an address
/// like any other. This table is what lets either side be named when it does.
#[derive(Debug, Default)]
pub struct BoxZone {
    /// Session name → what was registered for it.
    entries: Mutex<HashMap<String, BoxZoneEntry>>,
}

impl BoxZone {
    /// Records the entry registered for `session`: its `lease` and the ports
    /// `ingress` declares.
    ///
    /// Replaces any earlier entry for the name — a box that re-attaches takes a
    /// new lease, and gvproxy's newest-first merge means the newest record is
    /// the one that answers, so the table agrees with the zone.
    pub fn register(&self, session: &str, lease: Ipv4Addr, ingress: Option<&IngressPolicy>) {
        let ports = |proto: IpProto| -> BTreeSet<u16> {
            ingress
                .map(|i| {
                    i.port_mappings
                        .iter()
                        .filter(|m| m.proto == proto)
                        .map(|m| m.internal_port)
                        .collect()
                })
                .unwrap_or_default()
        };
        let session = session.to_ascii_lowercase();
        let entry = BoxZoneEntry {
            session: session.clone(),
            lease,
            tcp_ports: ports(IpProto::Tcp),
            udp_ports: ports(IpProto::Udp),
        };
        self.entries
            .lock()
            .expect("BoxZone mutex poisoned")
            .insert(session, entry);
    }

    /// Withdraws `session`'s entry as its box goes away, so the zone dump and
    /// the box-to-box verdicts name live boxes only.
    pub fn withdraw(&self, session: &str) {
        self.entries
            .lock()
            .expect("BoxZone mutex poisoned")
            .remove(&session.to_ascii_lowercase());
    }

    /// The lease `name` resolves to inside boxes, or `None` for a name outside
    /// the box zone or one no live box holds.
    ///
    /// No allow list is consulted (NET-072): the zone alone decides.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let label = name
            .strip_suffix(crate::net::dns::HOSTNAME_SUFFIX)?
            .strip_suffix('.')?;
        self.entries
            .lock()
            .expect("BoxZone mutex poisoned")
            .get(label)
            .map(|entry| entry.lease)
    }

    /// The box holding `address` and the verdict its ingress rules give `proto`
    /// port `port` (NET-073), or `None` when no live box holds the address.
    #[must_use]
    pub fn target_at(&self, address: Ipv4Addr, proto: IpProto, port: u16) -> Option<BoxZoneTarget> {
        let entries = self.entries.lock().expect("BoxZone mutex poisoned");
        let entry = entries.values().find(|entry| entry.lease == address)?;
        Some(BoxZoneTarget {
            session: entry.session.clone(),
            ingress: if entry.declares(proto, port) {
                IngressVerdict::Declared
            } else {
                IngressVerdict::Undeclared
            },
        })
    }

    /// Every live entry, in session-name order: the in-guest half of the zone
    /// dump the diagnostics bundle carries.
    #[must_use]
    pub fn entries(&self) -> Vec<BoxZoneEntry> {
        let mut entries: Vec<BoxZoneEntry> = self
            .entries
            .lock()
            .expect("BoxZone mutex poisoned")
            .values()
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.session.cmp(&b.session));
        entries
    }
}

/// The label `host.min.internal` carries inside the `min.internal.` zone.
pub const HOST_LABEL: &str = "host";

/// The name a box resolves to reach the host its node runs on (NET-003), and the
/// name a box still dialling the literal host address should use instead
/// (NET-004).
pub const HOST_HOSTNAME: &str =
    constcat::concat!(HOST_LABEL, ".", crate::net::dns::HOSTNAME_SUFFIX);

/// Where a box stands relative to the host whose loopback `host.min.internal`
/// names (NET-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReach {
    /// The box shares the host's own network namespace, so the host's loopback
    /// is the box's own.
    SharedNamespace,
    /// The box reaches the host across the switch — an own-address box, or any
    /// box inside a VM node — so the host's loopback sits behind the switch's
    /// host-gateway address, which gvproxy NATs to it.
    Switch,
}

/// The address `host.min.internal` answers a box with this reach: `127.0.0.1`
/// where the box shares the host's namespace, the switch's host-gateway address
/// where it stands on the switch (NET-003).
///
/// The one formula: the zone record [`register_host_name`] writes and the
/// per-mode answer [`net::provider`](super::provider) decides both come from
/// here, so a box cannot be promised one address and given another.
#[must_use]
pub fn host_reach_address(reach: HostReach, subnet: SwitchSubnet) -> Ipv4Addr {
    match reach {
        HostReach::SharedNamespace => Ipv4Addr::LOCALHOST,
        HostReach::Switch => subnet.host_alias(),
    }
}

/// Registers `host.min.internal` in gvproxy's `min.internal.` DNS zone, pointing
/// at the switch's host-gateway address, so every box on the switch resolves the
/// host it runs on (NET-003).
///
/// Idempotent by content — the record never varies for a subnet — and posted on
/// each switch bring-up rather than once per process, because a switch that
/// stopped with its last box took its zones with it.
///
/// # Errors
///
/// Returns the I/O error from the gvproxy control request (non-2xx or transport).
pub async fn register_host_name(control: &ControlChannel, subnet: SwitchSubnet) -> io::Result<()> {
    post_json(control, "/services/dns/add", &host_dns_body(subnet)).await
}

/// Builds the `/services/dns/add` zone body for `host.min.internal`. Split out so
/// the wire shape is unit-testable without a live gvproxy, alongside
/// [`dns_add_body`].
fn host_dns_body(subnet: SwitchSubnet) -> DnsZone {
    DnsZone {
        name: format!("{}.", crate::net::dns::HOSTNAME_SUFFIX),
        records: vec![DnsRecord {
            name: HOST_LABEL.to_string(),
            ip: host_reach_address(HostReach::Switch, subnet).to_string(),
        }],
    }
}

/// `POST`s `body` as JSON to `path` on gvproxy's control socket over a fresh
/// HTTP/1.1 keep-alive connection, succeeding on a 2xx status.
///
/// gvproxy's control socket speaks HTTP; the relay's `POST /connect` upgrade in
/// [`switch`](super::switch) is the data-plane verb, while the forwarder verbs
/// here are ordinary request/response. The exchange is framed by `Content-Length`
/// (not read-to-EOF) with **no** `Connection: close`, so the server never closes
/// the socket first — required for the response to survive the KVM vsock shuttle
/// (see [`exchange`] and the request-builder comment below for the G-N8 detail).
pub(crate) async fn post_json<T: Serialize>(
    control: &ControlChannel,
    path: &str,
    body: &T,
) -> io::Result<()> {
    let body = serde_json_lenient::to_vec(body).map_err(io::Error::other)?;
    let mut request = Vec::with_capacity(128 + body.len());
    // HTTP/1.1 keep-alive (no `Connection: close`): gvproxy must respond *without*
    // closing the connection. On the KVM libkrun `add_vsock_port2(listen=false)`
    // shuttle, a server-initiated close drops the still-buffered response bytes as
    // it propagates to the guest (the guest reads an immediate EOF → 0 bytes →
    // `malformed gvproxy status line: ""`, even though the forward *was* applied —
    // G-N8). Keeping the connection open lets the response drain to the guest,
    // which then reads exactly `Content-Length` bytes and closes from its side.
    request.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(b"Host: localhost\r\n");
    request.extend_from_slice(b"Content-Type: application/json\r\n");
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&body);

    // Bound the whole exchange: a gvproxy that accepts the socket and then
    // stalls must not hang the launch or teardown path indefinitely. The control
    // socket is local (DM2) or the host gvproxy over vsock (DM1/3/4); both speak
    // the same HTTP/1.0 request/response on a fresh connection.
    let response = tokio::time::timeout(GVPROXY_CONTROL_TIMEOUT, async {
        match control {
            ControlChannel::Unix(sock) => {
                exchange(UnixStream::connect(sock).await?, &request).await
            }
            ControlChannel::Vsock { cid, port } => {
                let stream = VsockStream::connect(VsockAddr::new(*cid, *port)).await?;
                exchange(stream, &request).await
            }
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("gvproxy {path} control request timed out after {GVPROXY_CONTROL_TIMEOUT:?}"),
        )
    })??;

    let status = parse_status_code(&response)?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "gvproxy {path} returned HTTP {status}: {}",
            String::from_utf8_lossy(body_after_headers(&response))
        )))
    }
}

/// Writes `request` to a freshly-connected control stream and reads the response
/// framed by its `Content-Length`. Transport-agnostic so the unix (DM2) and vsock
/// (DM1/3/4) control channels share one exchange.
///
/// We must **not** read to EOF: the request is HTTP/1.1 keep-alive (see
/// [`post_json`]), so gvproxy holds the connection open after responding and an
/// EOF-terminated read would block until the [`GVPROXY_CONTROL_TIMEOUT`]. Instead
/// we read the status line + headers, take `Content-Length` body bytes, and let
/// the caller drop the stream (closing from the *guest* side). This avoids the
/// server-initiated close that the KVM libkrun vsock splice mishandles by dropping
/// the buffered response (G-N8). We deliberately do not `shutdown()` the write
/// side for the same reason.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    stream.write_all(request).await?;

    // Read incrementally until the header terminator is in hand, capping total
    // buffered bytes: gvproxy's forwarder replies are tiny, so a stream that never
    // completes its headers within the bound is misbehaving.
    let mut response = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    let header_end = loop {
        if let Some(i) = find_header_end(&response) {
            break i;
        }
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            return Err(io::Error::other(
                "gvproxy control response exceeded the size cap before its headers ended",
            ));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // EOF before headers completed — the empty-reply symptom the
            // keep-alive framing is meant to avoid; surface it as-is.
            return Ok(response);
        }
        response.extend_from_slice(&buf[..n]);
    };

    // Body length from `Content-Length` (0 if absent). Read until the body is
    // fully buffered, so we never depend on a server close to signal completion.
    let want = content_length(&response[..header_end]).unwrap_or(0);
    let body_have = response.len() - header_end;
    let mut remaining = want.saturating_sub(body_have);
    while remaining > 0 {
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            break;
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        remaining = remaining.saturating_sub(n);
    }
    Ok(response)
}

/// Parses the numeric status code from an HTTP response's status line
/// (`HTTP/1.x <code> <reason>`).
fn parse_status_code(response: &[u8]) -> io::Result<u16> {
    let line_end = response
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(response.len());
    let line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| io::Error::other("gvproxy response status line was not UTF-8"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed gvproxy status line: {line:?}")))
}

/// Index just past the `\r\n\r\n` header terminator, or `None` if the headers are
/// not yet fully buffered.
fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// The `Content-Length` header value parsed from a response's header block, or
/// `None` if the header is absent or unparseable (treated as a zero-length body).
fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

/// Returns the body bytes following the blank line that ends the headers, or the
/// whole buffer if no header terminator is found (best-effort, for diagnostics).
fn body_after_headers(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(response, |i| &response[i + 4..])
}

/// Upper bound on a single gvproxy control request (expose/unexpose). The
/// control socket can accept the connection and then stall or never close;
/// without a bound, teardown's `remove_ingress` would block forever before the
/// switch `detach`, leaving the PTask attached and its forwards present.
const GVPROXY_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on bytes buffered from a single gvproxy control response. The
/// forwarder's replies are a status line plus a tiny body, so 64 KiB is far
/// above any legitimate response while capping memory if a misbehaving socket
/// streams without closing inside the [`GVPROXY_CONTROL_TIMEOUT`] window.
const MAX_CONTROL_RESPONSE: u64 = 64 * 1024;

/// Minimum gap between emitted policy-violation warnings: one minute, matching
/// R2.2's "first drop per PTask per rule per minute" rate-limit window, so a
/// flood of dropped frames cannot spam the log.
const WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Which direction a policy violation occurred in, for R2.7's `direction`
/// structured field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound traffic from the PTask (an egress-policy violation).
    Egress,
    /// Inbound traffic to the PTask (an ingress-policy violation).
    Ingress,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
        })
    }
}

/// Rate-limited emitter plumbing for policy-violation warnings (R2.7).
///
/// This carries the rate limiter so the egress-enforcement work (#553) only has
/// to call [`warn`](Self::warn) at the point it drops a frame; the limiter keeps
/// a per-violation-source `tracing::warn!` from firing more than once per
/// [`WARN_MIN_INTERVAL`]. It is intentionally unused on the policy-application
/// path that ships in this Unit — enforcement, and therefore the firing site,
/// is split to #553.
#[derive(Debug, Default)]
pub struct PolicyWarnLimiter {
    last: Mutex<Option<Instant>>,
}

impl PolicyWarnLimiter {
    /// A fresh limiter that has never emitted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether enough time has elapsed since the last emission to warn again at
    /// `now`, recording `now` as the last emission when it returns `true`.
    ///
    /// Split from [`warn`](Self::warn) so the rate-limit decision is testable
    /// without a real clock or a `tracing` subscriber.
    #[must_use]
    pub fn should_warn_at(&self, now: Instant) -> bool {
        let mut last = self.last.lock().expect("PolicyWarnLimiter mutex poisoned");
        match *last {
            Some(prev) if now.duration_since(prev) < WARN_MIN_INTERVAL => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    /// Emits a rate-limited `tracing::warn!` for a policy violation, carrying
    /// R2.7's required structured fields: the `session_id`, the `direction` of
    /// the offending traffic, the `remote_addr` it was to/from, its `proto`, and
    /// the `rule_matched`. Returns whether a warning was emitted (vs. suppressed
    /// by the rate limit).
    pub fn warn(
        &self,
        session_id: &str,
        direction: Direction,
        remote_addr: SocketAddr,
        proto: IpProto,
        rule_matched: &str,
    ) -> bool {
        if self.should_warn_at(Instant::now()) {
            tracing::warn!(
                session_id,
                %direction,
                %remote_addr,
                %proto,
                rule_matched,
                "network policy violation"
            );
            true
        } else {
            false
        }
    }
}

/// The per-key twin of [`PolicyWarnLimiter`]: R2.2's window is "first drop
/// per PTask per rule per minute", so the egress gate keys its limiter by the
/// rule a frame tripped, and a flood dropped by one rule cannot silence the
/// first drop by another. Keys are a small closed set (the rule names), so
/// the table never needs sweeping.
#[derive(Debug)]
pub struct KeyedWarnLimiter<K> {
    last: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash> Default for KeyedWarnLimiter<K> {
    fn default() -> Self {
        Self {
            last: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash> KeyedWarnLimiter<K> {
    /// A fresh limiter that has never emitted for any key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether enough time has elapsed since the last emission for `key` to
    /// warn again at `now`, recording `now` as that key's last emission when
    /// it returns `true`.
    #[must_use]
    pub fn should_warn_at(&self, key: K, now: Instant) -> bool {
        let mut last = self.last.lock().expect("KeyedWarnLimiter mutex poisoned");
        match last.get(&key) {
            Some(prev) if now.duration_since(*prev) < WARN_MIN_INTERVAL => false,
            _ => {
                last.insert(key, now);
                true
            }
        }
    }
}

/// The shortest admission window (NET-066): an answer with a shorter TTL, zero
/// included, still admits its addresses long enough for the connection that
/// follows the lookup to open.
pub const ADMISSION_WINDOW_MIN: Duration = Duration::from_secs(30);
/// The longest admission window: an answer with a longer TTL is re-admitted
/// by the next lookup, so a stale pin cannot outlive the name by more than
/// this.
pub const ADMISSION_WINDOW_MAX: Duration = Duration::from_secs(300);

/// The window an answer's addresses are admitted for: its TTL, held between
/// [`ADMISSION_WINDOW_MIN`] and [`ADMISSION_WINDOW_MAX`]. The working value
/// for design §5.3's admission window.
#[must_use]
pub fn admission_window(ttl_secs: u32) -> Duration {
    Duration::from_secs(u64::from(ttl_secs)).clamp(ADMISSION_WINDOW_MIN, ADMISSION_WINDOW_MAX)
}

/// One admitted address in a box's table: the name it was answered for, the
/// answer it arrived in, and when its window ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedAddress {
    /// The admitted address.
    pub address: Ipv4Addr,
    /// The allowed name it was answered for.
    pub name: String,
    /// Every address that answer carried, refused ones included.
    pub answer: Vec<Ipv4Addr>,
    /// When the admission window ends.
    pub expires: Instant,
}

/// A box's admitted-address table (NET-066): the addresses its allowed names
/// resolved to, each for its window. A later answer for the same address
/// replaces the entry, so the window is always the newest answer's. Expired
/// entries are dropped whenever the table is read or written, so it never
/// holds more than the live answers.
#[derive(Debug, Default)]
pub struct PinTable {
    entries: HashMap<Ipv4Addr, PinnedAddress>,
}

impl PinTable {
    /// Admits `addresses` for `name` until `now + window`, recording `answer`
    /// as their source.
    pub fn admit(
        &mut self,
        name: &str,
        addresses: &[Ipv4Addr],
        answer: &[Ipv4Addr],
        window: Duration,
        now: Instant,
    ) {
        self.entries.retain(|_, pin| pin.expires > now);
        for &address in addresses {
            self.entries.insert(
                address,
                PinnedAddress {
                    address,
                    name: name.to_string(),
                    answer: answer.to_vec(),
                    expires: now + window,
                },
            );
        }
    }

    /// Whether `address` is admitted at `now`.
    #[must_use]
    pub fn admits(&self, address: Ipv4Addr, now: Instant) -> bool {
        self.entries
            .get(&address)
            .is_some_and(|pin| pin.expires > now)
    }

    /// The live entries at `now`, in address order.
    #[must_use]
    pub fn live(&self, now: Instant) -> Vec<PinnedAddress> {
        let mut live: Vec<PinnedAddress> = self
            .entries
            .values()
            .filter(|pin| pin.expires > now)
            .cloned()
            .collect();
        live.sort_by_key(|pin| pin.address);
        live
    }
}

/// What one live box declared, as a surface routing by hostname needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxDeclaration {
    /// The box's own address: its switch lease when it has an address of its
    /// own, the switch's host alias when it carries the host's. What a direct
    /// connection to the box would dial, which is what the caller's egress
    /// rules are read against — not the address a routing surface forwards to.
    pub address: Ipv4Addr,
    /// The box's declared egress, where its address attributes traffic to this
    /// box alone (NET-084). `None` for a box carrying the host's address: that
    /// cohort shares one address (NET-078) and each box's own declaration is
    /// enforced inside it (NET-079), so no rules here are attributable to it.
    pub egress: Option<EgressRules>,
    /// The ports the box declared inbound.
    pub ingress: IngressRules,
}

impl BoxDeclaration {
    /// The declaration of a box with an address of its own: its lease, the
    /// rules its relay decides frames with, and its declared ports.
    #[must_use]
    pub fn for_own_address(
        lease: Ipv4Addr,
        egress: EgressRules,
        ingress: Option<&IngressPolicy>,
    ) -> Self {
        Self {
            address: lease,
            egress: Some(egress),
            ingress: IngressRules::for_own_address(ingress),
        }
    }

    /// The declaration of a box that carries the host's address on `subnet`:
    /// the address a box on the switch dials to reach the host it runs on
    /// ([`host_reach_address`]), and no ingress declaration of its own.
    #[must_use]
    pub fn for_host_address(subnet: SwitchSubnet) -> Self {
        Self {
            address: subnet.host_alias(),
            egress: None,
            ingress: IngressRules::for_host_address(),
        }
    }
}

/// Every live box's declarations, keyed by the session name its hostname is
/// minted from, so a surface that resolved a name to a box can decide the
/// request against what that box declared (NET-069 to NET-071).
///
/// Held behind an `RwLock` on the daemon-scoped switch client: the box's
/// network is where its address and its rules are both known, and the switch is
/// the one object every box's network and the daemon's hostname proxy already
/// share. Writers are the network providers (declare) and the session actor
/// (withdraw with the hostname route); the proxy only reads.
#[derive(Debug, Default)]
pub struct BoxAdmissions {
    boxes: HashMap<String, BoxDeclaration>,
}

impl BoxAdmissions {
    /// An empty table: no box has declared anything, so nothing is admitted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what the box named `session` declared, replacing any earlier
    /// declaration under that name (a relaunch leases a new address).
    pub fn declare(&mut self, session: &str, declaration: BoxDeclaration) {
        self.boxes.insert(session.to_string(), declaration);
    }

    /// Drops `session`'s declaration: the box is gone, and declares nothing.
    pub fn withdraw(&mut self, session: &str) {
        self.boxes.remove(session);
    }

    /// The verdict on one TCP request the hostname proxy is asked to carry from
    /// `caller` to the box named `session` on `port`, decided as the direct
    /// connection it stands in for (NET-069 to NET-071).
    ///
    /// A name with no declaration behind it — a box whose network never came
    /// up, or one that has gone — declared no port, so the request is refused:
    /// a routing surface admits only what a box declared.
    #[must_use]
    pub fn verdict(&self, caller: IpAddr, session: &str, port: u16) -> Verdict {
        let Some(target) = self.boxes.get(session) else {
            return Verdict::Drop(DropRule::UndeclaredPort);
        };
        let request = ProxiedRequest {
            caller: match caller {
                IpAddr::V4(v4) => v4,
                // No box holds an IPv6 address on the IPv4-only switch, so such
                // a caller is attributed to none and is decided by the target's
                // declaration alone.
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            target: target.address,
            port,
            proto: IPPROTO_TCP,
        };
        proxied_verdict(&request, self.caller(caller), &target.ingress)
    }

    /// The declared egress of the box that holds `caller`, or `None` when the
    /// address is not one box's: a process on the host, or the host-address
    /// cohort. Leases are never reused for the daemon's lifetime, so an address
    /// answers for at most one box.
    fn caller(&self, caller: IpAddr) -> Option<&EgressRules> {
        let IpAddr::V4(address) = caller else {
            return None;
        };
        self.boxes
            .values()
            .find(|b| b.address == address)
            .and_then(|b| b.egress.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table attributes a caller by the lease it sends from, and a
    /// withdrawn box declares nothing: neither as a target nor as a caller.
    #[test]
    fn admissions_attribute_a_caller_by_its_lease_until_it_is_withdrawn() {
        const CALLER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
        const TARGET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 6);
        let mut table = BoxAdmissions::new();
        // A caller allowed nothing outside its own loopback.
        table.declare(
            "caller",
            BoxDeclaration::for_own_address(
                CALLER,
                EgressRules::for_box(
                    CALLER,
                    Some(&sessions::EgressPolicy {
                        allow_subnets: Some(vec!["127.0.0.0/8".to_string()]),
                        ..sessions::EgressPolicy::default()
                    }),
                    None,
                ),
                None,
            ),
        );
        table.declare(
            "web",
            BoxDeclaration::for_own_address(
                TARGET,
                EgressRules::for_box(TARGET, None, None),
                Some(&IngressPolicy {
                    port_mappings: vec![PortMapping {
                        external_port: 18080,
                        internal_port: 8080,
                        proto: IpProto::Tcp,
                    }],
                    dynamic_allowed_range: None,
                }),
            ),
        );

        // The caller's own rules do not reach the target's address.
        assert_eq!(
            table.verdict(CALLER.into(), "web", 18080),
            Verdict::Drop(DropRule::Undeclared)
        );
        // A caller the table holds no rules for reaches the declared port.
        let host: IpAddr = Ipv4Addr::LOCALHOST.into();
        assert_eq!(table.verdict(host, "web", 18080), Verdict::Admit);
        assert_eq!(
            table.verdict(host, "web", 9999),
            Verdict::Drop(DropRule::UndeclaredPort)
        );
        // Withdrawn: the name declares no port, and the lease attributes nobody.
        table.withdraw("web");
        assert_eq!(
            table.verdict(host, "web", 18080),
            Verdict::Drop(DropRule::UndeclaredPort)
        );
        table.withdraw("caller");
        table.declare(
            "web",
            BoxDeclaration::for_host_address(SwitchSubnet::default()),
        );
        assert_eq!(table.verdict(CALLER.into(), "web", 18080), Verdict::Admit);
    }

    #[test]
    fn admission_window_is_the_ttl_held_between_the_bounds() {
        assert_eq!(admission_window(0), ADMISSION_WINDOW_MIN);
        assert_eq!(admission_window(60), Duration::from_secs(60));
        assert_eq!(admission_window(86400), ADMISSION_WINDOW_MAX);
    }

    #[test]
    fn pin_table_admits_for_the_window_and_the_newest_answer_wins() {
        let a = Ipv4Addr::new(140, 82, 112, 3);
        let b = Ipv4Addr::new(140, 82, 112, 4);
        let t0 = Instant::now();
        let mut table = PinTable::default();
        table.admit("github.com", &[a], &[a, b], Duration::from_secs(60), t0);
        assert!(table.admits(a, t0));
        assert!(!table.admits(b, t0));
        assert!(table.admits(a, t0 + Duration::from_secs(59)));
        assert!(!table.admits(a, t0 + Duration::from_secs(60)));

        // Re-answered at t0+50 with a fresh window: admitted past the first.
        table.admit(
            "github.com",
            &[a],
            &[a],
            Duration::from_secs(60),
            t0 + Duration::from_secs(50),
        );
        assert!(table.admits(a, t0 + Duration::from_secs(100)));
        let live = table.live(t0 + Duration::from_secs(100));
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "github.com");
        assert_eq!(live[0].answer, vec![a]);
        assert!(table.live(t0 + Duration::from_secs(110)).is_empty());
    }

    #[test]
    fn keyed_limiter_windows_each_key_on_its_own() {
        let limiter = KeyedWarnLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.should_warn_at("allow_subnets", t0));
        assert!(!limiter.should_warn_at("allow_subnets", t0 + Duration::from_secs(1)));
        // Another rule inside the first's window still gets its first warning.
        assert!(limiter.should_warn_at("source-not-lease", t0 + Duration::from_secs(1)));
        assert!(limiter.should_warn_at("allow_subnets", t0 + WARN_MIN_INTERVAL));
    }

    #[test]
    fn dns_add_body_matches_gvproxy_zone_shape() {
        // The zone Name carries a trailing dot (gvproxy matches DNS queries, which
        // are trailing-dotted, against it); the record label is lowercased
        // (gvproxy matches labels case-sensitively); the IP is dotted-quad.
        let body = dns_add_body("Web", Ipv4Addr::new(100, 64, 0, 5));
        let json = serde_json_lenient::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.5"}]}"#
        );
    }

    /// The in-guest zone table: a sibling's name resolves from the zone alone,
    /// each entry carries the ports that box's ingress declares, and a
    /// withdrawn box holds neither (NET-072, NET-073). Names are matched
    /// case-insensitively and only under the box zone's apex.
    #[test]
    fn box_zone_holds_each_live_box_s_lease_and_declared_ports() {
        let api = Ipv4Addr::new(100, 64, 0, 5);
        let zone = BoxZone::default();
        zone.register(
            "API",
            api,
            Some(&IngressPolicy {
                port_mappings: vec![
                    PortMapping {
                        external_port: 18080,
                        internal_port: 8080,
                        proto: IpProto::Tcp,
                    },
                    PortMapping {
                        external_port: 19999,
                        internal_port: 9999,
                        proto: IpProto::Udp,
                    },
                ],
                dynamic_allowed_range: None,
            }),
        );
        zone.register("web", Ipv4Addr::new(100, 64, 0, 9), None);

        assert_eq!(zone.resolve("Api.min.internal."), Some(api));
        assert_eq!(zone.resolve("api.min.internal"), Some(api));
        // Outside the zone, and a name no box holds.
        assert_eq!(zone.resolve("api.example.com"), None);
        assert_eq!(zone.resolve("min.internal"), None);
        assert_eq!(zone.resolve("gone.min.internal"), None);

        // The target's own ingress decides the port, per transport.
        let declared = |proto, port| {
            zone.target_at(api, proto, port)
                .expect("the sibling holds the address")
                .ingress
        };
        assert_eq!(declared(IpProto::Tcp, 8080), IngressVerdict::Declared);
        assert_eq!(declared(IpProto::Tcp, 9999), IngressVerdict::Undeclared);
        assert_eq!(declared(IpProto::Udp, 9999), IngressVerdict::Declared);
        assert_eq!(declared(IpProto::Icmp, 8080), IngressVerdict::Undeclared);
        // A box with no ingress section declares nothing.
        assert_eq!(
            zone.target_at(Ipv4Addr::new(100, 64, 0, 9), IpProto::Tcp, 8080)
                .map(|t| t.ingress),
            Some(IngressVerdict::Undeclared)
        );
        assert_eq!(
            zone.target_at(Ipv4Addr::new(93, 184, 216, 34), IpProto::Tcp, 443),
            None
        );

        let entries = zone.entries();
        assert_eq!(
            entries.iter().map(BoxZoneEntry::name).collect::<Vec<_>>(),
            vec!["api.min.internal", "web.min.internal"]
        );

        zone.withdraw("Api");
        assert_eq!(zone.resolve("api.min.internal"), None);
        assert_eq!(zone.target_at(api, IpProto::Tcp, 8080), None);
        assert_eq!(zone.entries().len(), 1);
    }

    /// NET-003. The address `host.min.internal` answers is decided per mode and
    /// per host — a box that shares the host's namespace gets the host's own
    /// loopback, a box standing on the switch gets the host-gateway address
    /// gvproxy NATs to it — and the zone record the switch is given carries
    /// exactly that address under exactly that name.
    #[test]
    fn host_min_internal_resolves_to_host_reach_address_per_mode() {
        use crate::net::provider::host_reach;
        use crate::net::{SwitchTransport, VSOCK_GVPROXY_SHUTTLE_PORT, VSOCK_HOST_CID};
        use sessions::NetworkMode;

        let subnet = SwitchSubnet::default();
        let native = SwitchTransport::LocalSpawn;
        let vm_backed = SwitchTransport::HostShuttle {
            cid: VSOCK_HOST_CID,
            port: VSOCK_GVPROXY_SHUTTLE_PORT,
        };
        let answer = |mode, transport| {
            host_reach(mode, transport).map(|reach| host_reach_address(reach, subnet))
        };

        // A host-address box on a native host shares the host's namespace, so
        // the host's loopback is its own.
        assert_eq!(
            answer(NetworkMode::HostNet, native),
            Some(Ipv4Addr::LOCALHOST)
        );
        // Inside a VM-backed host the same box reaches the host across the
        // switch, as an own-address box does on either host.
        assert_eq!(
            answer(NetworkMode::HostNet, vm_backed),
            Some(subnet.host_alias())
        );
        assert_eq!(
            answer(NetworkMode::OwnIp, native),
            Some(subnet.host_alias())
        );
        assert_eq!(
            answer(NetworkMode::OwnIp, vm_backed),
            Some(subnet.host_alias())
        );
        // A `none` box has an empty namespace and no route to the host at all;
        // NET-003 promises it nothing.
        assert_eq!(answer(NetworkMode::NoNet, native), None);

        // What the switch is actually told, so the promise and the answer cannot
        // drift: the zone every box on the switch resolves against.
        assert_eq!(HOST_HOSTNAME, "host.min.internal");
        assert_eq!(
            serde_json_lenient::to_string(&host_dns_body(subnet)).unwrap(),
            r#"{"name":"min.internal.","records":[{"name":"host","ip":"100.64.255.254"}]}"#
        );
    }

    #[test]
    fn expose_request_maps_host_port_to_ptask_ip() {
        // R2.3/R2.4-static: external_port forwards to the PTask's switch IP on
        // internal_port; the local host is loopback so only the host can connect.
        let mapping = PortMapping {
            external_port: 18080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let req = expose_request(&mapping, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(req.local, "127.0.0.1:18080");
        assert_eq!(req.remote, "100.64.0.2:80");
        assert_eq!(req.protocol, "tcp");
    }

    #[test]
    fn expose_request_serializes_to_gvproxy_fields() {
        let mapping = PortMapping {
            external_port: 5353,
            internal_port: 53,
            proto: IpProto::Udp,
        };
        let req = expose_request(&mapping, Ipv4Addr::new(100, 64, 0, 7));
        let json = serde_json_lenient::to_string(&req).unwrap();
        assert!(json.contains("\"local\":\"127.0.0.1:5353\""), "got: {json}");
        assert!(json.contains("\"remote\":\"100.64.0.7:53\""), "got: {json}");
        assert!(json.contains("\"protocol\":\"udp\""), "got: {json}");
    }

    #[test]
    fn parse_status_code_reads_the_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(), 200);
        assert_eq!(
            parse_status_code(b"HTTP/1.0 500 Internal Server Error\r\n").unwrap(),
            500
        );
    }

    #[test]
    fn parse_status_code_rejects_a_malformed_line() {
        assert!(parse_status_code(b"not http\r\n").is_err());
    }

    #[test]
    fn warn_limiter_suppresses_within_the_interval() {
        let limiter = PolicyWarnLimiter::new();
        let t0 = Instant::now();
        // First emission at t0 is allowed; a second within the interval is not.
        assert!(limiter.should_warn_at(t0));
        assert!(!limiter.should_warn_at(t0 + Duration::from_millis(10)));
        // Once the interval has elapsed it warns again.
        assert!(limiter.should_warn_at(t0 + WARN_MIN_INTERVAL));
    }

    #[test]
    fn direction_renders_the_r2_7_field_values() {
        // R2.7 spells the `direction` structured field `egress`/`ingress`.
        assert_eq!(Direction::Egress.to_string(), "egress");
        assert_eq!(Direction::Ingress.to_string(), "ingress");
    }

    #[test]
    fn content_length_parses_case_insensitively_or_absent() {
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"),
            Some(6)
        );
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\ncontent-length:  0\r\n\r\n"),
            Some(0)
        );
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn exchange_frames_by_content_length_without_a_server_close() {
        // Regression for G-N8: the response must be framed by `Content-Length`,
        // never by the server closing the socket. On the KVM libkrun vsock shuttle
        // a server-initiated close drops the still-buffered response, so `exchange`
        // must return the full reply from a peer that stays open. If it ever
        // reverts to read-to-EOF, this test hangs (the peer never closes).
        let (client, mut server) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            // Drain the request (headers + empty body arrive together here).
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nWEB_OK")
                .await
                .unwrap();
            // Hold the connection open — do NOT close — until the caller is done.
            server
        });

        let resp = exchange(
            client,
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("exchange returns the framed response without waiting for EOF");

        assert_eq!(parse_status_code(&resp).unwrap(), 200);
        assert_eq!(body_after_headers(&resp), b"WEB_OK");
        drop(server.await.unwrap());
    }
}
