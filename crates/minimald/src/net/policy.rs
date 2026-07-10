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
//! ACL API**, so egress *enforcement* (R2.2) is deliberately not implemented
//! here — it is split to #553 (relay-layer frame inspection). What R2.7 needs
//! from this Unit is the warning plumbing ([`PolicyWarnLimiter`]); the call
//! site that fires it on a real dropped frame lands with that enforcement.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Registers `<session_name>.<host_id>` in gvproxy's `min.internal.` DNS zone,
/// pointing at the PTask's current switch lease (finding #3 / UC6).
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
/// without a live gvproxy.
fn dns_add_body(host_id: &str, session_name: &str, lease_ip: Ipv4Addr) -> DnsZone {
    DnsZone {
        name: format!("{}.", crate::net::dns::HOSTNAME_SUFFIX),
        records: vec![DnsRecord {
            name: format!("{session_name}.{host_id}").to_ascii_lowercase(),
            ip: lease_ip.to_string(),
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
    let body = serde_json::to_vec(body).map_err(io::Error::other)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_add_body_matches_gvproxy_zone_shape() {
        // The zone Name carries a trailing dot (gvproxy matches DNS queries, which
        // are trailing-dotted, against it); the record label is lowercased
        // (gvproxy matches labels case-sensitively); the IP is dotted-quad.
        let body = dns_add_body("Local", "Web", Ipv4Addr::new(100, 64, 0, 5));
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"name":"min.internal.","records":[{"name":"web.local","ip":"100.64.0.5"}]}"#
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
        let json = serde_json::to_string(&req).unwrap();
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
