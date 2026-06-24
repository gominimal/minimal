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
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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
    control_sock: &Path,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
) -> io::Result<Vec<ExposedMapping>> {
    let mut exposed: Vec<ExposedMapping> = Vec::with_capacity(ingress.port_mappings.len());
    for mapping in &ingress.port_mappings {
        let req = expose_request(mapping, ptask_ip);
        match post_json(control_sock, "/services/forwarder/expose", &req).await {
            Ok(()) => exposed.push(ExposedMapping {
                local: req.local,
                protocol: req.protocol,
            }),
            Err(e) => {
                // Roll back what we managed to expose so a half-applied policy
                // does not leave dangling forwards on the shared switch.
                remove_ingress(control_sock, &exposed).await;
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
pub async fn remove_ingress(control_sock: &Path, exposed: &[ExposedMapping]) {
    for mapping in exposed {
        let req = UnexposeRequest {
            local: mapping.local.clone(),
            protocol: mapping.protocol.clone(),
        };
        if let Err(e) = post_json(control_sock, "/services/forwarder/unexpose", &req).await {
            tracing::warn!(
                local = %mapping.local,
                error = %e,
                "removing ingress port mapping from switch on PTask exit"
            );
        }
    }
}

/// `POST`s `body` as JSON to `path` on gvproxy's control socket over a fresh
/// HTTP/1.0 connection, succeeding on a 2xx status.
///
/// gvproxy's control socket speaks HTTP; the relay's `POST /connect` upgrade in
/// [`switch`](super::switch) is the data-plane verb, while the forwarder verbs
/// here are ordinary request/response. HTTP/1.0 with `Connection: close` keeps
/// the exchange to one write + read-to-EOF, with no need to parse chunked or
/// keep-alive framing.
async fn post_json<T: Serialize>(sock: &Path, path: &str, body: &T) -> io::Result<()> {
    let body = serde_json::to_vec(body).map_err(io::Error::other)?;
    let mut request = Vec::with_capacity(128 + body.len());
    request.extend_from_slice(format!("POST {path} HTTP/1.0\r\n").as_bytes());
    request.extend_from_slice(b"Host: localhost\r\n");
    request.extend_from_slice(b"Content-Type: application/json\r\n");
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    request.extend_from_slice(&body);

    // Bound the whole exchange: a gvproxy that accepts the socket and then
    // stalls must not hang the launch or teardown path indefinitely.
    let response = tokio::time::timeout(GVPROXY_CONTROL_TIMEOUT, async {
        let mut stream = UnixStream::connect(sock).await?;
        stream.write_all(&request).await?;
        // Half-close the write side so an HTTP/1.0 server knows the request is
        // complete and responds without waiting for more body bytes.
        stream.shutdown().await?;

        let mut response = Vec::with_capacity(256);
        stream.read_to_end(&mut response).await?;
        Ok::<_, io::Error>(response)
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
}
