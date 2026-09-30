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
//! ACL API**, so egress *enforcement* (R2.2, NET-062) lives in the relay
//! layer ([`switch`](super::switch)) — it inspects each frame against the
//! pure verdict in `sessions::core::egress` and drops what the box did not
//! declare. What this module carries for that enforcement is the warning
//! plumbing: [`PolicyWarnLimiter`], whose rate limit is keyed by box and
//! rule, and [`Proto`], the transport a dropped frame is logged under.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::collections::HashMap;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_vsock::{VsockAddr, VsockStream};

use sessions::{IngressPolicy, IpProto, PortMapping};

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
/// `external_port` — published at `published`, the host loopback address the
/// box's declaration is published on (NET-010) — to `ptask_ip:internal_port`
/// on the switch.
///
/// The `local` host is a loopback address so the forward binds host loopback
/// only: a process *on the host* reaches the port (R2.3), while the spec's "no
/// external exposure by default" keeps it off the LAN. It is the box's **own**
/// address, not `127.0.0.1`, wherever the reserved local range gave it one, so
/// two boxes naming the same port both publish — on their own addresses, at
/// their own port numbers (NET-010). A box that shares an address with another
/// and names a port it names too collides there; the collision is intrinsic to
/// the mode, so it is *reported* by the registry's publish — never translated
/// away here: neither port number is remapped (NET-129).
///
/// The `remote` targets the PTask's allocated switch address.
#[must_use]
pub fn expose_request(
    mapping: &PortMapping,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
) -> ExposeRequest {
    ExposeRequest {
        local: format!("{published}:{}", mapping.external_port),
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

impl ExposedMapping {
    /// The `host:port` the forward is bound on — the address the switch is
    /// actually holding, spelled exactly as its expose request named it. A
    /// caller reporting a publish (the per-mapping info line in
    /// `finish_own_ip_attach`) reads this instead of re-deriving the address
    /// from the request, so the report cannot claim a host a forward is not
    /// published on.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// [`Self::local`] split into the host address and port to report. `None`
    /// when `local` is not a `host:port` pair with a numeric port — a shape
    /// [`expose_request`], its only builder, never produces.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        let (host, port) = self.local.rsplit_once(':')?;
        Some((host, port.parse().ok()?))
    }
}

/// Exposes every static port mapping in `ingress` on the switch's `control_sock`
/// at `published` — the box's own host loopback address (NET-010) — forwarding
/// to `ptask_ip`, returning a handle per exposed forward for teardown
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
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
) -> io::Result<Vec<ExposedMapping>> {
    let mut exposed: Vec<ExposedMapping> = Vec::with_capacity(ingress.port_mappings.len());
    for mapping in &ingress.port_mappings {
        let req = expose_request(mapping, published, ptask_ip);
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

/// NET-123's bind probe, conducted through the forwarder that will publish:
/// the same whole-range walk as the local bind probe in `switch::loopback`,
/// one [`ExposeRequest`] per address of the reserved local range, each
/// released by its unexpose the moment it answers, classified exactly as the
/// local probe classifies its binds — every address bound reads the range
/// present; the first refusal names the first missing alias; anything that
/// is not a bind — a refused request, a stall, an unreachable control
/// channel — reads absent, never present.
///
/// Why a second probe beside the local one: an own-address box's declared
/// ports are bound by the **forwarder**, not by the daemon. On a native host
/// the daemon spawns that forwarder itself, so its own loopback is the
/// publish surface and the local probe is the honest one. On a microVM host
/// the forwarder is the host gvproxy `minvmd` owns, so the publish surface is
/// the *host's* loopback — a machine the daemon inside the guest cannot see,
/// and whose verdict its own `lo` would lie about, since a Linux guest
/// carries the whole `127/8` regardless of what the host carries. The only
/// thing that can measure a bind there is the bind itself, so the probe rides
/// the same control channel the publishes ride and asks the forwarder to do
/// the binding.
///
/// Side-effect-free in the same sense the local probe is: every round ends
/// with the unexpose that releases it, and the probe accepts no connection,
/// so its `remote` — never dialed — is a placeholder. Only the host's
/// loopback is asked anything, and only whether an address binds.
pub(crate) async fn probe_publish_surface(
    control: &ControlChannel,
) -> ::switch::loopback::RangeProbe {
    probe_publish_surface_within(control, RANGE_PROBE_BUDGET).await
}

/// [`probe_publish_surface`] with the walk's overall budget injected, so the
/// overrun arm is testable at a budget a test can afford.
async fn probe_publish_surface_within(
    control: &ControlChannel,
    budget: Duration,
) -> ::switch::loopback::RangeProbe {
    let mut probe = ::switch::loopback::RangeProbe::failed_to_run();
    let hosts: Vec<Ipv4Addr> = ::switch::loopback::range_hosts().collect();
    let walk = tokio::time::timeout(budget, async {
        for address in &hosts {
            probe.probed += 1;
            let expose = ExposeRequest {
                local: format!("{address}:{RANGE_PROBE_PORT}"),
                remote: format!("{}:1", Ipv4Addr::LOCALHOST),
                protocol: "tcp".to_string(),
            };
            match post_json(control, "/services/forwarder/expose", &expose).await {
                Ok(()) => {
                    probe.bound += 1;
                    let unexpose = UnexposeRequest {
                        local: expose.local,
                        protocol: expose.protocol,
                    };
                    if let Err(error) =
                        post_json(control, "/services/forwarder/unexpose", &unexpose).await
                    {
                        // Best-effort, like teardown's: a probe round left
                        // bound holds one obscure port at one address, while
                        // a walk that stopped here would leave the range
                        // unread — the worse leak by far.
                        tracing::warn!(
                            local = %unexpose.local,
                            error = %error,
                            "releasing the loopback range probe's forwarder bind failed",
                        );
                    }
                }
                Err(error) => {
                    probe.first_failure.get_or_insert((*address, error.kind()));
                    if error.kind() == io::ErrorKind::TimedOut {
                        // A control channel that does not answer is not a
                        // fact about the host's loopback at all, so the walk
                        // stops rather than spend the rest of its budget
                        // re-asking a dead one. The verdict is fixed either
                        // way: this round never bound, and one missing
                        // address is the whole range's answer.
                        break;
                    }
                }
            }
        }
    })
    .await;
    if walk.is_err() && probe.probed < hosts.len() {
        // The walk outran its budget mid-range: read it as the local probe
        // reads a partial alias set, never as present. Widening the probed
        // count to the whole range makes `present` demand every address it
        // never reached, and the address whose round the budget expired
        // inside is named as the record's first failure — where the vouching
        // stopped.
        let stuck = hosts
            .get(probe.probed.saturating_sub(1))
            .copied()
            .or_else(|| hosts.first().copied())
            .expect("the reserved range's usable-host list is never empty");
        probe.probed = hosts.len();
        probe
            .first_failure
            .get_or_insert((stuck, io::ErrorKind::TimedOut));
    }
    probe
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

/// Registers the PTask's box name `<session_name>` — with the deprecated
/// three-label form `<session_name>.<host_id>` beside it (NET-002) — in
/// gvproxy's `min.internal.` DNS zone, pointing at its current switch lease
/// (finding #3 / UC6).
///
/// gvproxy's resolver is the switch gateway (`100.64.0.1`) that every own-IP
/// sandbox's `resolv.conf` already targets, so this makes a PTask's
/// `*.min.internal` hostname resolvable *from a peer session* — with no new
/// resolver process and no `resolv.conf` change. The zone `Name` carries the
/// trailing dot gvproxy matches DNS queries against; the record labels are
/// lowercased (gvproxy matches labels case-sensitively).
///
/// # Errors
///
/// Returns the I/O error from the gvproxy control request (non-2xx or transport).
pub async fn register_dns_name(
    control: &ControlChannel,
    host_id: &str,
    session_name: &str,
    lease_ip: Ipv4Addr,
) -> io::Result<()> {
    post_json(
        control,
        "/services/dns/add",
        &dns_add_body(host_id, session_name, lease_ip),
    )
    .await
}

/// Builds the `/services/dns/add` zone body for a PTask. Split out so the exact
/// wire shape (trailing-dot zone, lowercased label, dotted-quad IP) is unit-testable
/// without a live gvproxy. It carries both names the zone answers for: the
/// two-label box name `<session>` (NET-001), and the deprecated three-label
/// form `<session>.<host-id>` beside it (NET-002, answered for one release) —
/// both pointing at the same lease.
fn dns_add_body(host_id: &str, session_name: &str, lease_ip: Ipv4Addr) -> DnsZone {
    DnsZone {
        name: format!("{}.", crate::net::dns::HOSTNAME_SUFFIX),
        records: vec![
            DnsRecord {
                name: session_name.to_ascii_lowercase(),
                ip: lease_ip.to_string(),
            },
            DnsRecord {
                name: format!("{session_name}.{host_id}").to_ascii_lowercase(),
                ip: lease_ip.to_string(),
            },
        ],
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

/// The port the forwarder-conducted range probe binds each address of the
/// reserved local range at while asking the host whether the range is
/// publishable (NET-123): fixed and deliberately obscure, so no box's
/// declaration is likely to name it, and released by the unexpose that ends
/// each probe round before the next address takes it. Exactly one daemon
/// probes a given forwarder — the one that publishes through it, and a host
/// gvproxy has one of those (the second-daemon-on-a-host shape is native,
/// where the local bind probe runs instead) — so no concurrent walk can
/// collide on it.
const RANGE_PROBE_PORT: u16 = 21064;

/// Upper bound on the whole forwarder-conducted range walk — the backstop for
/// the one pathology the per-request [`GVPROXY_CONTROL_TIMEOUT`] cannot
/// price: a forwarder that keeps answering, but slowly, once per address
/// across the range. A walk that outruns it is read exactly as it stopped:
/// the addresses it never reached are the ones it cannot vouch for, so the
/// range reads absent, the interim.
const RANGE_PROBE_BUDGET: Duration = Duration::from_secs(20);

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

/// The transport a policy-violating frame is logged under, for R2.7's `proto`
/// structured field.
///
/// Wider than [`IpProto`] because a dropped frame is not always an IP packet
/// whose protocol number is one of the three a policy can name: IPv6 is
/// dropped as a whole family (NET-082) with no single L4 protocol to name, a
/// truncated or non-IP frame has no header to read one from, and a policy can
/// be violated by a protocol Minimal does not model (any other IPv4 number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// `IpProto::Tcp` — IPv4 protocol 6.
    Tcp,
    /// `IpProto::Udp` — IPv4 protocol 17.
    Udp,
    /// `IpProto::Icmp` — IPv4 protocol 1.
    Icmp,
    /// Any other IPv4 protocol number, logged as `ip-<number>`.
    Other(u8),
    /// An IPv6 frame, dropped as a family (NET-082) before any L4 protocol is
    /// read.
    Ipv6,
    /// Nothing to name: a frame with no IPv4 header to read a protocol from
    /// (a truncated or non-IP frame), or a protocol Minimal does not model
    /// under a name.
    None,
}

impl Proto {
    /// The transport Minimal's policies name, for a frame whose protocol is
    /// one of the three declared ones. `IpProto` is `#[non_exhaustive]`, so a
    /// variant a later sessions adds has no rendering here yet and logs as
    /// `none` — the drop still names its rule.
    #[must_use]
    pub fn from_ipproto(proto: IpProto) -> Self {
        match proto {
            IpProto::Tcp => Self::Tcp,
            IpProto::Udp => Self::Udp,
            IpProto::Icmp => Self::Icmp,
            _ => Self::None,
        }
    }

    /// The transport of an IPv4 frame carrying protocol number `number`: the
    /// three declared protocols by name, any other number by number.
    #[must_use]
    pub fn from_ipv4_number(number: u8) -> Self {
        match number {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Other(n) => write!(f, "ip-{n}"),
            Self::Ipv6 => f.write_str("ipv6"),
            Self::None => f.write_str("none"),
        }
    }
}

/// Rate-limited emitter plumbing for policy-violation warnings (R2.7).
///
/// The rate limit is keyed by **box and rule** (NET-062: "first drop per
/// PTask per rule per minute"): one box's flood never silences another box's
/// single drop, and a box hitting several rules in the same minute is still
/// heard once per rule. The relay's egress enforcement
/// ([`switch`](super::switch)) and its ingress counterpart share one limiter
/// per session gate, each under its own rule key — with the one exception
/// that a DNS refusal adds the refused name to its key
/// ([`warn_dns_refusal`](Self::warn_dns_refusal)), because its requirement
/// is the name and the answer per refusal.
#[derive(Debug, Default)]
pub struct PolicyWarnLimiter {
    last: Mutex<HashMap<String, HashMap<String, Instant>>>,
}

impl PolicyWarnLimiter {
    /// A fresh limiter that has never emitted for any box or rule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether enough time has elapsed since the last emission for `session_id`
    /// under `rule` to warn again at `now`, recording `now` as that pair's last
    /// emission when it returns `true`.
    ///
    /// Split from [`warn`](Self::warn) so the rate-limit decision is testable
    /// without a real clock or a `tracing` subscriber.
    #[must_use]
    pub fn should_warn_at(&self, session_id: &str, rule: &str, now: Instant) -> bool {
        let mut last = self.last.lock().expect("PolicyWarnLimiter mutex poisoned");
        let Some(emit) = last.get_mut(session_id) else {
            last.entry(session_id.to_string())
                .or_default()
                .insert(rule.to_string(), now);
            return true;
        };
        match emit.get(rule) {
            Some(prev) if now.duration_since(*prev) < WARN_MIN_INTERVAL => false,
            _ => {
                emit.insert(rule.to_string(), now);
                true
            }
        }
    }

    /// Emits a rate-limited `tracing::warn!` for a policy violation, carrying
    /// R2.7's required structured fields: the `session_id`, the `direction` of
    /// the offending traffic, the `remote_addr` it was to/from (rendered as
    /// `none` when the frame had no IP destination to read, as for an IPv6 or
    /// truncated drop), its `proto`, the `dst_port` the traffic targeted
    /// (`None` when the drop is not about a port), and the `rule_matched`.
    /// The port is a structured field only, never part of `rule_matched`: it
    /// must not fragment the per-rule rate-limit key. Returns whether a warning
    /// was emitted (vs. suppressed by the rate limit).
    pub fn warn(
        &self,
        session_id: &str,
        direction: Direction,
        remote_addr: Option<SocketAddr>,
        proto: Proto,
        dst_port: Option<u16>,
        rule_matched: &str,
    ) -> bool {
        if self.should_warn_at(session_id, rule_matched, Instant::now()) {
            let remote_addr = remote_addr.map_or_else(|| "none".to_string(), |a| a.to_string());
            tracing::warn!(
                session_id,
                %direction,
                %remote_addr,
                %proto,
                dst_port,
                rule_matched,
                "network policy violation"
            );
            true
        } else {
            false
        }
    }

    /// Emits a rate-limited `tracing::warn!` for a DNS answer the rebinding
    /// intersection refused (NET-067): an address a name the box's policy
    /// allowed resolved into the box's `deny_subnets` or the infrastructure
    /// deny set, and so is never admitted — the name and the answer, the two
    /// things the spec requires the refusal to carry.
    ///
    /// Rate-limited per **box, name and rule**, not per box and rule like
    /// [`warn`](Self::warn): the requirement is the name and the answer per
    /// refusal, so a second refused name inside the interval is its own line
    /// rather than silenced by the first's, while a burst of the *same*
    /// name's refusals stays one line per rule. The limiter's key is built
    /// from both, and the `rule_matched` field it logs is the rule alone.
    pub fn warn_dns_refusal(
        &self,
        session_id: &str,
        name: &str,
        answer: Ipv4Addr,
        rule_matched: &str,
    ) -> bool {
        let key = format!("{rule_matched}:{name}");
        if self.should_warn_at(session_id, &key, Instant::now()) {
            tracing::warn!(
                session_id,
                name,
                %answer,
                rule_matched,
                "an allowed name resolved into a refused range"
            );
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_add_body_matches_gvproxy_zone_shape() {
        // The zone Name carries a trailing dot (gvproxy matches DNS queries, which
        // are trailing-dotted, against it); the record labels are lowercased
        // (gvproxy matches labels case-sensitively); the IP is dotted-quad. Both
        // the two-label box name and the deprecated three-label form are
        // registered, pointing at the same lease.
        let body = dns_add_body("Local", "Web", Ipv4Addr::new(100, 64, 0, 5));
        let json = serde_json_lenient::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.5"},{"name":"web.local","ip":"100.64.0.5"}]}"#
        );
    }

    #[test]
    fn expose_request_maps_host_port_to_ptask_ip() {
        // R2.3/R2.4-static: external_port forwards to the PTask's switch IP on
        // internal_port; the local host is the box's own loopback address
        // (NET-010) so only the host can connect.
        let mapping = PortMapping {
            external_port: 18080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let published = Ipv4Addr::new(127, 0, 64, 9);
        let req = expose_request(&mapping, published, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(req.local, "127.0.64.9:18080");
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
        // A box with no address of its own publishes on the node's shared
        // one, still at its own port numbers (NET-123's interim, NET-129).
        let req = expose_request(&mapping, Ipv4Addr::LOCALHOST, Ipv4Addr::new(100, 64, 0, 7));
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
        assert!(limiter.should_warn_at("box", "egress-undeclared-subnet", t0));
        assert!(!limiter.should_warn_at(
            "box",
            "egress-undeclared-subnet",
            t0 + Duration::from_millis(10)
        ));
        // Once the interval has elapsed it warns again.
        assert!(limiter.should_warn_at("box", "egress-undeclared-subnet", t0 + WARN_MIN_INTERVAL));
    }

    #[test]
    fn warn_limiter_keys_by_box_and_rule() {
        // NET-062 rate-limits "per PTask per rule": one box's flood never
        // silences another box's single drop, and a box hitting several rules in
        // the same minute is still heard once per rule.
        let limiter = PolicyWarnLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.should_warn_at("box-a", "rule-1", t0));
        // A different box under the same rule is not silenced by box-a's drop…
        assert!(limiter.should_warn_at("box-b", "rule-1", t0));
        // …and neither is the same box under a different rule.
        assert!(limiter.should_warn_at("box-a", "rule-2", t0));
        // But the same pair within the interval still is.
        assert!(!limiter.should_warn_at("box-a", "rule-1", t0 + Duration::from_secs(1)));
        assert!(!limiter.should_warn_at("box-b", "rule-1", t0 + Duration::from_secs(1)));
    }

    #[test]
    fn warn_limiter_keys_ingress_drops_by_rule_not_port() {
        // The destination port is a structured field, not part of the rule
        // key: a port scan against one box is one rule hit per minute, not one
        // emission per probed port.
        let limiter = PolicyWarnLimiter::new();
        let src = Some(SocketAddr::from(([100, 64, 0, 9], 40000)));
        let emitted = [80u16, 8080]
            .into_iter()
            .filter(|&dst_port| {
                limiter.warn(
                    "box",
                    Direction::Ingress,
                    src,
                    Proto::from_ipproto(IpProto::Tcp),
                    Some(dst_port),
                    "no ingress mapping",
                )
            })
            .count();
        assert_eq!(emitted, 1);
    }

    #[test]
    fn direction_renders_the_r2_7_field_values() {
        // R2.7 spells the `direction` structured field `egress`/`ingress`.
        assert_eq!(Direction::Egress.to_string(), "egress");
        assert_eq!(Direction::Ingress.to_string(), "ingress");
    }

    #[test]
    fn proto_renders_the_r2_7_field_values() {
        // R2.7 names the three declared protocols `tcp`/`udp`/`icmp`; anything
        // else a box can send is rendered as its IPv4 protocol number, and the
        // family/truncation drops (which carry no L4 protocol) as `ipv6`/`none`.
        assert_eq!(Proto::from_ipproto(IpProto::Tcp).to_string(), "tcp");
        assert_eq!(Proto::from_ipproto(IpProto::Udp).to_string(), "udp");
        assert_eq!(Proto::from_ipproto(IpProto::Icmp).to_string(), "icmp");
        assert_eq!(Proto::from_ipv4_number(47).to_string(), "ip-47");
        assert_eq!(Proto::Ipv6.to_string(), "ipv6");
        assert_eq!(Proto::None.to_string(), "none");
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

    // ---- NET-123's forwarder-conducted range probe -----------------------
    mod forwarder_probe {
        use std::collections::HashMap;
        use std::io;
        use std::net::Ipv4Addr;
        use std::path::PathBuf;
        use std::time::Duration;

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{UnixListener, UnixStream};
        use tokio::sync::mpsc;

        use super::super::{
            ControlChannel, RANGE_PROBE_PORT, UnexposeRequest, post_json, probe_publish_surface,
            probe_publish_surface_within,
        };

        /// Reads one control request off `sock`: its head up to the
        /// end-of-head marker, then exactly its `Content-Length` body — the
        /// mirror of `post_json`'s keep-alive framing, so the fake forwarder
        /// never blocks reading past what the probe sent.
        async fn read_request(sock: &mut UnixStream) -> Vec<u8> {
            let mut buf = Vec::with_capacity(256);
            let mut scratch = [0u8; 512];
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                    break i;
                }
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request head");
                assert!(n > 0, "the probe closed before sending its head");
                buf.extend_from_slice(&scratch[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request body");
                assert!(n > 0, "the probe closed mid-body");
                buf.extend_from_slice(&scratch[..n]);
            }
            buf[head_end..head_end + len].to_vec()
        }

        /// The `local` address a request body names, for the decide closure.
        fn local_of(body: &[u8]) -> String {
            let text = String::from_utf8_lossy(body);
            text.split("\"local\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default()
                .to_string()
        }

        /// Serves a gvproxy-shaped control channel at `path`: every request
        /// is read in full, then answered with the status `decide` picks for
        /// the `local` address its body names — the stand-in for the host
        /// gvproxy whose loopback carries only the aliases `decide` accepts,
        /// where a bind on a missing alias is answered `500` the way the real
        /// forwarder answers an `EADDRNOTAVAIL`. `delay` parks each answer,
        /// for the one test that needs a forwarder slower than its budget.
        /// Every round's `local` is handed to the returned receiver; the
        /// returned handle aborts the server when the test is done with it.
        fn spawn_forwarder_answering(
            path: PathBuf,
            delay: Duration,
            decide: impl Fn(&str) -> u16 + Send + Sync + 'static,
        ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<String>) {
            let listener = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel(512);
            let decide = std::sync::Arc::new(decide);
            let handle = tokio::spawn(async move {
                // Sequential on purpose: the probe is a walk, one request per
                // address, so one connection served at a time is its shape.
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = read_request(&mut sock).await;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let local = local_of(&body);
                    let status = decide(&local);
                    let reason = if status == 200 {
                        "OK"
                    } else {
                        "Internal Server Error"
                    };
                    sock.write_all(
                        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .expect("the fake forwarder must answer");
                    if tx.send(local).await.is_err() {
                        return;
                    }
                }
            });
            (handle, rx)
        }

        /// A host gvproxy that binds every address of the reserved range —
        /// the Linux host of the KVM lane, whose `lo` owns all of `127/8` —
        /// so the daemon behind it reads the range present and grants
        /// per-box addresses: the whole range walked, every round released
        /// behind the walk, every address asked at the probe's fixed port.
        #[tokio::test]
        async fn reads_the_range_present_when_every_expose_binds() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(
                probe.probed,
                254,
                "the walk covers every usable host: {}",
                probe.summary()
            );
            assert!(
                probe.present(),
                "a forwarder that binds every address vouches for the range: {}",
                probe.summary()
            );
            assert_eq!(probe.first_failure, None);
            assert_eq!(probe.surface(), "reserved-range");

            // One expose and one unexpose per address: the bind is released
            // the moment it answers, so the probe leaves nothing bound.
            let mut rounds: HashMap<String, usize> = HashMap::new();
            let mut requests = 0usize;
            while let Some(local) = asked.recv().await {
                requests += 1;
                *rounds.entry(local).or_default() += 1;
            }
            assert_eq!(
                rounds.len(),
                254,
                "every address of the range was asked, at the probe port: {requests} requests"
            );
            assert!(
                rounds.values().all(|&seen| seen == 2),
                "every bound round was released by its unexpose: {rounds:?}"
            );
            let round = |addr: std::net::Ipv4Addr| format!("{addr}:{RANGE_PROBE_PORT}");
            assert_eq!(rounds.get(&round(Ipv4Addr::new(127, 0, 64, 1))), Some(&2));
            assert_eq!(rounds.get(&round(Ipv4Addr::new(127, 0, 64, 254))), Some(&2));
            assert!(
                rounds
                    .keys()
                    .all(|local| local.ends_with(&format!(":{RANGE_PROBE_PORT}"))),
                "every round asked at the probe's fixed port: {rounds:?}"
            );
        }

        /// The stock macOS host's shape (`docs/spikes/2026-09-22-macos-loopback-alias.md`):
        /// every bind on the range refused, so every expose is answered `500`
        /// — the range reads absent and the daemon behind that forwarder
        /// publishes on the `127.0.0.1` interim, the state that keeps an
        /// own-address box's activate from failing on a host whose `lo0`
        /// carries no alias yet.
        #[tokio::test]
        async fn reads_the_range_absent_when_the_host_refuses_every_bind() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 500);
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 0);
            assert!(!probe.present());
            assert!(probe.interim());
            assert_eq!(probe.surface(), "127.0.0.1-interim");
            // The refused request comes back as gvproxy's folded error, whose
            // kind is `Other` — the address is the record's, never guessed.
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::Other))
            );
        }

        /// A *partial* alias set must read absent, exactly as the local
        /// probe's does: the addresses the allocator could still hand out are
        /// the missing ones, and a fetch aimed at one hangs rather than
        /// refusing.
        #[tokio::test]
        async fn reads_a_partial_range_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |local| {
                    if local.starts_with("127.0.64.100:") {
                        500
                    } else {
                        200
                    }
                });
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 253);
            assert!(!probe.present(), "one missing alias fails the whole range");
            assert!(
                probe.interim(),
                "a partially-aliased host publishes on the interim"
            );
            assert_eq!(
                probe.first_failure.map(|(addr, _)| addr),
                Some(Ipv4Addr::new(127, 0, 64, 100))
            );
        }

        /// A control channel with nothing listening — a shuttle bridged to
        /// a gvproxy that is not up — is not a fact about the host's loopback
        /// at all, and reads absent: an unreadable publish surface never
        /// vouches for an address.
        #[tokio::test]
        async fn reads_an_unreachable_forwarder_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let probe =
                probe_publish_surface(&ControlChannel::Unix(dir.path().join("absent.sock"))).await;

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 0);
            assert!(!probe.present());
            assert!(probe.interim());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::NotFound)),
                "the first refusal names the first address, never a made-up one"
            );
        }

        /// A walk that outruns its budget is read as it stopped: the addresses
        /// it never reached are the ones it cannot vouch for, so the probed
        /// count is widened to the whole range — `present` then demands every
        /// address — and the record names where the vouching stopped.
        #[tokio::test]
        async fn reads_a_walk_that_outran_its_budget_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            // A forwarder slower than the budget: every answer parks long
            // past it, so the walk cannot get past its first round.
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::from_millis(50), |_| 200);
            let probe =
                probe_publish_surface_within(&ControlChannel::Unix(sock), Duration::from_millis(1))
                    .await;
            forwarder.abort();

            assert_eq!(
                probe.probed, 254,
                "an overran walk is widened to the whole range, so `present` \
                 demands every address it never reached"
            );
            assert!(
                !probe.present(),
                "a walk that did not finish may not vouch for the range: {}",
                probe.summary()
            );
            assert!(probe.interim());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::TimedOut)),
                "the address whose round the budget expired inside is the record's"
            );
        }

        /// The probe's request shape is the forwarder's own: an expose whose
        /// `local` is the address under test at the probe port, and an
        /// unexpose naming exactly the bind it released — the same verbs the
        /// publishes ride, with a `remote` the probe never dials.
        #[tokio::test]
        async fn exposes_and_releases_the_probe_binds_over_the_control_channel() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            // One round only: bind the range's first address, release it.
            let expose = super::super::ExposeRequest {
                local: format!("127.0.64.1:{RANGE_PROBE_PORT}"),
                remote: "127.0.0.1:1".to_string(),
                protocol: "tcp".to_string(),
            };
            post_json(
                &ControlChannel::Unix(sock.clone()),
                "/services/forwarder/expose",
                &expose,
            )
            .await
            .expect("the fake forwarder must bind the probe address");
            let asked_expose = asked.recv().await.expect("the round's expose was recorded");
            let unexpose = UnexposeRequest {
                local: expose.local.clone(),
                protocol: expose.protocol,
            };
            post_json(
                &ControlChannel::Unix(sock),
                "/services/forwarder/unexpose",
                &unexpose,
            )
            .await
            .expect("the fake forwarder must release the probe bind");
            let asked_unexpose = asked
                .recv()
                .await
                .expect("the round's unexpose was recorded");
            forwarder.abort();

            assert_eq!(asked_expose, format!("127.0.64.1:{RANGE_PROBE_PORT}"));
            assert_eq!(asked_unexpose, asked_expose);
        }
    }
}
