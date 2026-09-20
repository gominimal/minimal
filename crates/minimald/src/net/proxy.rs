//! The B5 host-side egress proxy and its shared routing core.
//!
//! Unit 3 (UC2a) resolves PTask `*.min.internal` hostnames **host-side**: the host
//! resolver is never consulted, so the no-systemd sandbox (hakoniwa) and microVM
//! (libkrun) runtimes and the TLD choice are both irrelevant to correctness. A
//! client points `HTTP(S)_PROXY` (or a PAC file) at this proxy, which routes
//! each request by its `Host:` header — or a `CONNECT` request's authority — to
//! the target PTask via the in-memory
//! [`HostnameRegistry`](super::dns::HostnameRegistry): a `HostNet` PTask to
//! `127.0.0.1:<port>`, an `OwnIp` PTask to its gvproxy switch IP reached through
//! the switch relay ([`super::switch`]).
//!
//! [`Router`] is that routing core, factored so another listener can reuse the
//! same `Host:`-header → registry → target lookup rather than duplicating it.
//! The host-side `*.min.internal` decision supersedes spike #485's
//! systemd-resolved finding (spec Open Question 1).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use sessions::core::net_verdict::{DropRule, Verdict};

use super::dns::{HostnameRegistry, Route};
use super::policy::BoxAdmissions;

/// Port the B5 host-side egress/DNS proxy listens on (TC3). Clients reach it
/// via `HTTP(S)_PROXY`.
pub const EGRESS_PROXY_PORT: u16 = 7654;

/// Default address the egress proxy listens on: loopback, where every
/// `*.min.internal` name is reachable. Clients reach it via `HTTP(S)_PROXY`.
pub const DEFAULT_PROXY_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), EGRESS_PROXY_PORT);

/// Upstream port used when a routed authority carries no explicit `:port`.
const DEFAULT_UPSTREAM_PORT: u16 = 80;

/// Largest request head (request line + headers) the proxy buffers before
/// routing. A head exceeding this is rejected rather than buffered unbounded.
const MAX_HEAD: usize = 8 * 1024;

/// How long the proxy waits for a client to finish sending its request head
/// before abandoning the connection with a `408`. Bounds idle connections that
/// open the socket but never send the `\r\n\r\n` end-of-head marker, so a slow
/// or stalled client cannot tie up a connection task indefinitely.
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The host-side lookup the proxy performs for each request: a `Host:`-header
/// host (with any `:port` already stripped) to where its requests forward, or
/// `None` if no live box owns it. The host resolver is never consulted.
///
/// Factored as a trait so the routing core is decoupled from how the table is
/// shared: the sessions manager owns the live registry.
pub trait HostRoute: Send + Sync + 'static {
    /// Resolves a `Host:`-header host to where its requests forward.
    fn resolve_host(&self, host: &str) -> Option<Route>;
}

impl HostRoute for HostnameRegistry {
    fn resolve_host(&self, host: &str) -> Option<Route> {
        self.resolve(host)
    }
}

// The daemon shares its live registry behind an `RwLock` (the sessions manager
// mutates it under `&mut self`; the proxy only reads it, synchronously, with no
// `.await` held). This lets `Router::new(Arc<RwLock<HostnameRegistry>>)` route
// against the same table the manager registers PTasks into.
impl HostRoute for std::sync::RwLock<HostnameRegistry> {
    fn resolve_host(&self, host: &str) -> Option<Route> {
        // Recover from a poisoned lock rather than mapping it to `None`: the
        // registry is two HashMaps with no cross-field invariant a panicked
        // writer could half-break, and silently returning `None` would make
        // every `*.min.internal` request 502 forever with no signal.
        match self.read() {
            Ok(guard) => guard.resolve(host),
            Err(poisoned) => poisoned.into_inner().resolve(host),
        }
    }
}

/// The shared routing core: maps an HTTP authority (`host` or `host:port`) to
/// the upstream socket address a request forwards to, and decides whether the
/// box that authority resolved to admits the request at all.
pub struct Router<T> {
    table: Arc<T>,
    admissions: Arc<RwLock<BoxAdmissions>>,
}

// Manual `Clone` so a `Router` is cheap to hand to each connection task without
// requiring `T: Clone` (only the `Arc`s are cloned).
impl<T> Clone for Router<T> {
    fn clone(&self) -> Self {
        Self {
            table: Arc::clone(&self.table),
            admissions: Arc::clone(&self.admissions),
        }
    }
}

impl<T: HostRoute> Router<T> {
    /// Builds a router over a shared host-routing table and the live box
    /// declarations every routed request is decided against.
    #[must_use]
    pub fn new(table: Arc<T>, admissions: Arc<RwLock<BoxAdmissions>>) -> Self {
        Self { table, admissions }
    }

    /// The verdict on carrying one request from `caller` to the box named
    /// `session` on `port`: the verdict the direct connection would get
    /// (NET-069 to NET-071).
    ///
    /// A poisoned lock is recovered from rather than mapped to a refusal: the
    /// table is one map with no cross-field invariant a panicked writer could
    /// half-break, and refusing every request forever would take hostname
    /// routing down with no signal.
    #[must_use]
    fn verdict(&self, caller: IpAddr, session: &str, port: u16) -> Verdict {
        match self.admissions.read() {
            Ok(guard) => guard.verdict(caller, session, port),
            Err(poisoned) => poisoned.into_inner().verdict(caller, session, port),
        }
    }

    /// Routes an HTTP authority to its upstream, or `None` if no live box owns
    /// the host. The authority's optional `:port` selects the upstream port;
    /// absent, [`DEFAULT_UPSTREAM_PORT`] is used.
    ///
    /// The registry gates on the host, not the port: the upstream port comes
    /// entirely from the client-supplied authority, so a registered `HostNet`
    /// hostname can be routed to `127.0.0.1:<any-port>`. That is an accepted
    /// limitation of the current single-user threat model — the networking spec
    /// scopes `minimald` to a single tenant per host and defers multi-tenant
    /// policy isolation (including per-PTask loopback port restriction) to a
    /// follow-up. Where mutually-untrusted PTasks share loopback, this is a
    /// loopback-SSRF surface that the follow-up must close.
    #[must_use]
    pub fn route(&self, authority: &str) -> Option<Upstream> {
        let (host, port) = split_authority(authority);
        let route = self.table.resolve_host(host)?;
        Some(Upstream {
            addr: SocketAddr::new(route.target, port.unwrap_or(DEFAULT_UPSTREAM_PORT)),
            session: route.session,
        })
    }
}

/// Where a routed request forwards to: the upstream address, and the box the
/// authority resolved to. The session travels with the address so a refusal
/// taken after routing names the box it resolved to (NET-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The address the request forwards to.
    pub addr: SocketAddr,
    /// The session whose name the authority resolved to.
    pub session: String,
}

/// Splits an HTTP authority into its host and optional port, handling both the
/// common `host:port` form and the bracketed IPv6 literal form (`[::1]:8080`),
/// where the port follows the closing bracket rather than the first colon.
fn split_authority(authority: &str) -> (&str, Option<u16>) {
    let host = super::dns::host_component(authority);
    let port = authority[host.len()..]
        .strip_prefix(':')
        .and_then(|rest| rest.parse().ok());
    (host, port)
}

/// Binds the egress-proxy listener at `addr`, returning it on success. On a bind
/// failure it emits the `component = "dns-proxy"` reachability warning and
/// returns `None`: the proxy is unavailable and PTask hostnames will not route
/// until the address is free. This is the daemon-startup reachability check that
/// supersedes the former systemd-resolved probe (R3.4).
///
/// The returned listener is the caller's to either serve (via [`serve`]) or
/// drop. The success event reports the address as `reachable` rather than
/// `listening` because binding only proves the address was free — a caller that
/// drops the listener is not accepting requests. The daemon startup path does
/// serve it (see `server::start_host_proxies`); this said otherwise, and reading
/// it as a bind-and-drop probe is what made gominimal/inbox#560 look like a
/// false alarm on macOS.
pub async fn bind_listener(addr: SocketAddr) -> Option<TcpListener> {
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            tracing::info!(
                component = "dns-proxy",
                %addr,
                status = "reachable",
                "host-side egress proxy listen address is bindable"
            );
            Some(listener)
        }
        Err(error) => {
            tracing::warn!(
                component = "dns-proxy",
                %addr,
                status = "unavailable",
                error = %error,
                remedy = "free the listen address; PTask *.min.internal hostnames will not route until the egress proxy can bind",
                "host-side egress proxy could not bind its listener"
            );
            None
        }
    }
}

/// How the hostname proxy's listen port was decided, for the startup log line
/// and the port report `min` and the diagnostic bundle read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortChoice {
    /// The operator named the port (`minimald run --hostname-proxy-port`).
    Configured,
    /// No port was configured and [`EGRESS_PROXY_PORT`] was free.
    Default,
    /// No port was configured and the default was taken — by another daemon on
    /// this host — so the OS picked a free one.
    Selected,
}

impl PortChoice {
    /// Stable token for the log line, the wire, and the diagnostic bundle.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Default => "default",
            Self::Selected => "selected",
        }
    }
}

/// A bound hostname-proxy listener: the socket, the port it actually listens
/// on, and how that port was decided.
#[derive(Debug)]
pub struct ProxyListener {
    /// The bound listener, for the caller to [`serve`].
    pub listener: TcpListener,
    /// The port it listens on — the OS-assigned one when the port was selected,
    /// so nothing downstream has to re-read the socket to learn it.
    pub port: u16,
    /// How that port was decided.
    pub choice: PortChoice,
}

/// Binds the hostname proxy's listener on `bind_base`, honouring a configured
/// port and otherwise selecting a free one.
///
/// A configured port is bound and nothing else (NET-024): a port the operator
/// named is not silently swapped for another, so a held one returns `None` and
/// is reported and retried by the caller, exactly as before this choice
/// existed. With no port configured (NET-025) the default [`EGRESS_PROXY_PORT`]
/// is preferred — every recipe, `HTTP_PROXY` line and e2e case that names it
/// keeps working — and when another daemon on this host already holds it, the
/// OS picks a free port instead, so the second daemon to start keeps a working
/// hostname surface rather than losing routing (NET-027). `min` learns the port
/// from the daemon (NET-026), so nothing but the default itself is hardcoded.
pub async fn bind_proxy_listener(
    bind_base: IpAddr,
    configured: Option<u16>,
) -> Option<ProxyListener> {
    bind_proxy_listener_with_default(bind_base, configured, EGRESS_PROXY_PORT).await
}

/// [`bind_proxy_listener`] with the preferred default port spelled out, so a
/// test can drive both the "default is free" and "default is taken" paths
/// against a port it controls rather than against whatever holds
/// [`EGRESS_PROXY_PORT`] on the machine running the test.
async fn bind_proxy_listener_with_default(
    bind_base: IpAddr,
    configured: Option<u16>,
    default_port: u16,
) -> Option<ProxyListener> {
    let chosen = if let Some(port) = configured {
        let listener = bind_listener(SocketAddr::new(bind_base, port)).await?;
        ProxyListener {
            listener,
            port,
            choice: PortChoice::Configured,
        }
    } else if let Ok(listener) = TcpListener::bind(SocketAddr::new(bind_base, default_port)).await {
        ProxyListener {
            listener,
            port: default_port,
            choice: PortChoice::Default,
        }
    } else {
        // Port 0: the OS hands back a free port. Not `bind_listener` for the
        // default attempt above either — a taken default is the ordinary
        // two-daemon case, not the reachability fault its warning describes.
        let listener = bind_listener(SocketAddr::new(bind_base, ANY_PORT)).await?;
        let port = listener.local_addr().ok()?.port();
        ProxyListener {
            listener,
            port,
            choice: PortChoice::Selected,
        }
    };
    tracing::info!(
        component = "dns-proxy",
        port = chosen.port,
        chosen = chosen.choice.as_str(),
        default_port,
        "host-side egress proxy port decided"
    );
    Some(chosen)
}

/// Asks the OS for a free port.
const ANY_PORT: u16 = 0;

/// Delay before the first rebind attempt after a failed bind.
const REBIND_BASE_DELAY: Duration = Duration::from_millis(250);

/// Ceiling on the rebind delay. A held address is freed by a process on its own
/// schedule, so the backoff stops growing here and keeps probing at a fixed,
/// cheap interval instead of drifting into hours.
const REBIND_MAX_DELAY: Duration = Duration::from_secs(30);

/// Delay before the `attempt`-th rebind (1-based): [`REBIND_BASE_DELAY`]
/// doubling per attempt, capped at [`REBIND_MAX_DELAY`].
#[must_use]
pub fn rebind_delay(attempt: u32) -> Duration {
    // Clamp the shift well inside `u32`: the cap is reached by attempt 8, so a
    // large attempt count only needs to not overflow.
    let doublings = attempt.saturating_sub(1).min(16);
    REBIND_BASE_DELAY
        .saturating_mul(1u32 << doublings)
        .min(REBIND_MAX_DELAY)
}

/// Binds `addr`, retrying with backoff until it succeeds, and hands back the
/// bound listener.
///
/// The caller has already made (and reported) the first failed attempt via
/// [`bind_listener`], so this starts by waiting. It never gives up: the address
/// is held by another process, which exits on its own schedule, and a daemon
/// that stopped retrying would need a restart before `*.min.internal` hostnames
/// routed again (R3.4 recovery). Each attempt logs the delay before the next
/// one; the bind that finally succeeds logs the recovery.
pub async fn bind_listener_retrying(addr: SocketAddr) -> TcpListener {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let delay = rebind_delay(attempt);
        tracing::warn!(
            component = "dns-proxy",
            %addr,
            status = "unavailable",
            attempt,
            retry_in_ms = delay.as_millis() as u64,
            "retrying the host-side egress proxy bind"
        );
        tokio::time::sleep(delay).await;
        if let Some(listener) = bind_listener(addr).await {
            tracing::info!(
                component = "dns-proxy",
                %addr,
                status = "recovered",
                attempts = attempt,
                "host-side egress proxy listener recovered"
            );
            return listener;
        }
    }
}

/// Serves the egress proxy on `listener`, spawning a task per connection that
/// routes it through `router`. Runs until the listener errors.
///
/// # Errors
///
/// Returns the accept error if the listener fails.
pub async fn serve<T: HostRoute>(listener: TcpListener, router: Router<T>) -> io::Result<()> {
    loop {
        let (client, peer) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection_io(client, peer.ip(), &router).await {
                tracing::debug!(
                    component = "dns-proxy",
                    %peer,
                    %error,
                    "proxy connection closed with error"
                );
            }
        });
    }
}

/// One refused request: what the client is answered with, and why (NET-001).
///
/// `host`, `session` and `error` are absent where the request never got that
/// far — a head that timed out carries no authority, a name no box owns has no
/// session — and all three render as `-`, so every refusal line in the log
/// carries the same fields and one grep finds them all.
#[derive(Default)]
struct Refusal<'a> {
    /// The HTTP status the client is answered with.
    status: &'a str,
    /// A stable token naming why the request was refused.
    reason: &'a str,
    /// The authority the client asked for, when the head yielded one.
    host: Option<&'a str>,
    /// The box the authority resolved to, when it resolved to one.
    session: Option<&'a str>,
    /// The underlying error, when the refusal followed a failed connect.
    error: Option<&'a str>,
    /// The address the request came from, on a refusal the caller's own rules
    /// decided.
    caller: Option<&'a str>,
    /// The port asked for, once the authority yielded one.
    port: Option<u16>,
    /// The declared rule the request tripped, spelled as the relay's drop line
    /// spells the same rule (NET-069).
    rule: Option<&'a str>,
}

/// Refuses a request: logs the refusal with its reason (NET-001), then answers
/// the client with the refusal's status.
async fn refuse<C: AsyncWrite + Unpin>(client: &mut C, refusal: Refusal<'_>) -> io::Result<()> {
    // Rendered for a field this refusal has no value for.
    const ABSENT: &str = "-";

    tracing::warn!(
        component = "dns-proxy",
        host = refusal.host.unwrap_or(ABSENT),
        caller = refusal.caller.unwrap_or(ABSENT),
        port = %refusal.port.map_or_else(|| ABSENT.to_string(), |p| p.to_string()),
        reason = refusal.reason,
        rule = refusal.rule.unwrap_or(ABSENT),
        session = refusal.session.unwrap_or(ABSENT),
        error = refusal.error.unwrap_or(ABSENT),
        status = refusal.status,
        "refused a proxied request"
    );
    write_status(client, refusal.status).await
}

/// Whether the client opened a raw `CONNECT` tunnel or a plain forward request
/// whose buffered head must be replayed to the upstream.
#[derive(Debug, Clone, Copy)]
enum RequestKind {
    Connect,
    Forward,
}

/// The routing-relevant parts of a parsed request head.
struct ParsedRequest<'a> {
    kind: RequestKind,
    authority: &'a str,
}

/// Handles one client connection over any byte stream: read its request head,
/// route it by authority, decide it against what the target box declared, then
/// either refuse it or splice it to the upstream PTask. Generic over the client
/// transport so the same routing core serves any listener put in front of it,
/// not only the plain egress proxy's `TcpStream`.
///
/// `caller` is the address the request came from: what attributes it to a box,
/// and so what makes that box's own egress rules apply to it (NET-070).
async fn handle_connection_io<C, T>(
    mut client: C,
    caller: IpAddr,
    router: &Router<T>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: HostRoute,
{
    // Bound the head read so a client that connects but never sends a complete
    // head cannot occupy this task indefinitely.
    let head = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head(&mut client)).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return refuse(
                &mut client,
                Refusal {
                    status: "408 Request Timeout",
                    reason: "no-request-head-before-timeout",
                    ..Refusal::default()
                },
            )
            .await;
        }
    };
    let Some(request) = parse_request(&head) else {
        return refuse(
            &mut client,
            Refusal {
                status: "400 Bad Request",
                reason: "no-authority-in-request-head",
                ..Refusal::default()
            },
        )
        .await;
    };

    // No live box owns this name: a host-side proxy returns a clean gateway
    // error rather than leaking the lookup to the host resolver.
    let Some(routed) = router.route(request.authority) else {
        return refuse(
            &mut client,
            Refusal {
                status: "502 Bad Gateway",
                reason: "no-live-box-owns-the-name",
                host: Some(request.authority),
                ..Refusal::default()
            },
        )
        .await;
    };
    let kind = request.kind;

    // The request stands in for the direct connection the caller would open, so
    // it is refused wherever that connection would be: a port the target box
    // did not declare (NET-069), or a target the caller's own egress rules do
    // not allow (NET-070), on either network mode (NET-071). The rule named is
    // the rule the relay's drop line names.
    let port = routed.addr.port();
    if let Verdict::Drop(rule) = router.verdict(caller, &routed.session, port) {
        let caller = caller.to_string();
        return refuse(
            &mut client,
            Refusal {
                status: "403 Forbidden",
                reason: match rule {
                    DropRule::UndeclaredPort => "target-box-did-not-declare-the-port",
                    _ => "caller-rules-deny-the-target",
                },
                host: Some(request.authority),
                session: Some(&routed.session),
                caller: Some(&caller),
                port: Some(port),
                rule: Some(rule.as_str()),
                ..Refusal::default()
            },
        )
        .await;
    }

    let mut upstream = match TcpStream::connect(routed.addr).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let error = error.to_string();
            return refuse(
                &mut client,
                Refusal {
                    status: "502 Bad Gateway",
                    reason: "upstream-unreachable",
                    host: Some(request.authority),
                    session: Some(&routed.session),
                    error: Some(&error),
                    port: Some(port),
                    ..Refusal::default()
                },
            )
            .await;
        }
    };

    match kind {
        // Tunnel: acknowledge the CONNECT, then splice raw bytes both ways.
        RequestKind::Connect => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        // Forward proxy: replay the buffered head so the upstream sees the
        // original request, then splice the rest both ways.
        RequestKind::Forward => {
            upstream.write_all(&head).await?;
        }
    }

    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Parses the authority to route to out of a buffered HTTP request head. A
/// `CONNECT` request carries the authority in its request line; any other method
/// carries it in the `Host:` header (matched case-insensitively). Returns `None`
/// for a head with no usable authority.
fn parse_request(head: &[u8]) -> Option<ParsedRequest<'_>> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let authority = parts.next()?;
        return Some(ParsedRequest {
            kind: RequestKind::Connect,
            authority,
        });
    }

    let authority = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim())
    })?;
    Some(ParsedRequest {
        kind: RequestKind::Forward,
        authority,
    })
}

/// Reads from `client` up to and including the end-of-head marker (`\r\n\r\n`),
/// returning the buffered head.
///
/// # Errors
///
/// Errors if the head exceeds [`MAX_HEAD`] or the stream ends before the marker.
async fn read_head<C: AsyncRead + Unpin>(client: &mut C) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before end of request head",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeded the maximum size",
            ));
        }
    }
}

/// Writes a minimal HTTP/1.1 status response with an empty body and closes.
async fn write_status<C: AsyncWrite + Unpin>(client: &mut C, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, RwLock};

    use sessions::core::net_verdict::{
        EgressRules, IPPROTO_TCP, IngressRules, ProxiedRequest, direct_verdict, frame_verdict,
    };
    use sessions::{EgressPolicy, IngressPolicy, IpProto, PortMapping, SessionId};
    use tracing_subscriber::fmt::MakeWriter;

    use crate::net::SwitchSubnet;
    use crate::net::dns::DEFAULT_HOST_ID;
    use crate::net::policy::BoxDeclaration;

    /// A caller whose address is nobody's lease: a process on the host, which no
    /// box's egress rules answer for.
    const HOST_CALLER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// A declarations table holding one box, as the daemon's would.
    fn admissions(session: &str, declaration: BoxDeclaration) -> Arc<RwLock<BoxAdmissions>> {
        let table = Arc::new(RwLock::new(BoxAdmissions::new()));
        table.write().unwrap().declare(session, declaration);
        table
    }

    /// A table holding one box that carries the host's address: it declares no
    /// ports of its own, so every port a direct connection reaches routes
    /// (NET-071). What the routing tests want, which are about names, not rules.
    fn host_address(session: &str) -> Arc<RwLock<BoxAdmissions>> {
        admissions(
            session,
            BoxDeclaration::for_host_address(SwitchSubnet::default()),
        )
    }

    /// An ingress policy declaring each port over TCP, published at the port the
    /// box listens on.
    fn tcp_ports(ports: &[u16]) -> IngressPolicy {
        IngressPolicy {
            port_mappings: ports
                .iter()
                .map(|&port| PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto: IpProto::Tcp,
                })
                .collect(),
            dynamic_allowed_range: None,
        }
    }

    /// An egress policy allowing one subnet and nothing else.
    fn allow_only(subnet: &str) -> EgressPolicy {
        EgressPolicy {
            allow_subnets: Some(vec![subnet.to_string()]),
            ..EgressPolicy::default()
        }
    }

    /// The declaration of a box with an address of its own, leased `lease`,
    /// declaring `ports` inbound and reaching what `egress` allows (`None` for
    /// an absent section, which allows every destination).
    fn own_address(
        lease: Ipv4Addr,
        ports: &[u16],
        egress: Option<&EgressPolicy>,
    ) -> BoxDeclaration {
        BoxDeclaration::for_own_address(
            lease,
            EgressRules::for_box(lease, egress, None),
            Some(&tcp_ports(ports)),
        )
    }

    /// A `MakeWriter` accumulating everything written into a shared buffer, so a
    /// test can assert on the structured fields a `tracing` event emitted.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Spawns a one-shot loopback backend that answers every connection with a
    /// fixed `200 OK` and closes, returning the port it listens on.
    async fn spawn_backend() -> u16 {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    // `sock` drops here, closing the upstream side.
                });
            }
        });
        port
    }

    /// Drives the proxy with a `GET` carrying `Host: <authority>` and returns
    /// the raw response the client read back.
    async fn proxy_get(proxy_addr: SocketAddr, authority: &str) -> String {
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Drives one connection over an in-memory pipe and returns the raw response
    /// the client read back. Unlike [`proxy_get`] the connection is handled in
    /// the test's own task, so a thread-local `tracing` subscriber captures the
    /// events the request emits. The client half is shut down for writing right
    /// after the head, which is what lets a *routed* request's bidirectional
    /// splice finish instead of waiting on a client that never closes.
    async fn drive_connection<T: HostRoute>(
        router: &Router<T>,
        caller: IpAddr,
        request: &str,
    ) -> String {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        handle_connection_io(server, caller, router).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// A loopback port nothing is listening on: bound only to learn a port the
    /// OS had free, then dropped, so a bind to it succeeds and a connect to it
    /// is refused.
    async fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Installs a `tracing` subscriber capturing into `buf` for as long as the
    /// returned guard lives, so a test can read the fields a startup event
    /// emitted.
    fn capture_events(buf: &CaptureWriter) -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    /// NET-024: a daemon started with a configured hostname-proxy port listens
    /// on exactly that port — and a configured port that is held is reported
    /// (the caller's retry path) rather than silently swapped for another, which
    /// would leave `min` printing a port the operator never asked for.
    #[tokio::test]
    async fn proxy_listens_on_configured_port() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let configured = free_port().await;

        let bound = bind_proxy_listener(loopback, Some(configured))
            .await
            .expect("a free configured port must bind");
        assert_eq!(
            bound.port, configured,
            "the configured port is the one used"
        );
        assert_eq!(
            bound.listener.local_addr().unwrap().port(),
            configured,
            "the listener itself must be on the configured port"
        );
        assert_eq!(bound.choice, PortChoice::Configured);

        // Held by something else: no substitution, so the caller reports it.
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let held_port = held.local_addr().unwrap().port();
        assert!(
            bind_proxy_listener(loopback, Some(held_port))
                .await
                .is_none(),
            "a held configured port must be reported, never substituted"
        );
    }

    /// NET-025: with no hostname-proxy port configured the daemon selects a free
    /// port. The default is preferred while it is free — every recipe and e2e
    /// case naming `:7654` keeps working — and once another daemon on the host
    /// holds it, the OS picks a free port instead of the daemon losing its
    /// hostname surface. One info line at startup says which port and how it was
    /// chosen.
    #[tokio::test]
    async fn proxy_auto_selects_free_port() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Stands in for `EGRESS_PROXY_PORT`, which the machine running this test
        // may well have taken by a real daemon.
        let default_port = free_port().await;

        let buf = CaptureWriter::default();
        let guard = capture_events(&buf);
        let first = bind_proxy_listener_with_default(loopback, None, default_port)
            .await
            .expect("a free default port must bind");
        let second = bind_proxy_listener_with_default(loopback, None, default_port)
            .await
            .expect("a taken default must fall back to a free port");
        drop(guard);

        assert_eq!(
            first.port, default_port,
            "the default is preferred while it is free"
        );
        assert_eq!(first.choice, PortChoice::Default);

        assert_ne!(
            second.port, default_port,
            "the second daemon cannot have the port the first holds"
        );
        assert_ne!(second.port, ANY_PORT, "a selected port is a real port");
        assert_eq!(second.choice, PortChoice::Selected);
        assert_eq!(
            second.listener.local_addr().unwrap().port(),
            second.port,
            "the reported port must be the one bound"
        );

        let logged = buf.contents();
        assert!(
            logged.contains(&format!("port={} chosen=\"default\"", first.port)),
            "the default choice must be logged with its port, got: {logged}"
        );
        assert!(
            logged.contains(&format!("port={} chosen=\"selected\"", second.port)),
            "the selected port must be logged with how it was chosen, got: {logged}"
        );
    }

    /// NET-027: two daemons on one machine — a native one and a VM one, say —
    /// each keep their own hostname surface. The second to start takes a free
    /// port instead of the default the first holds, and both route their own
    /// boxes' names at the same time, each refusing the other's names because
    /// each serves its own registry.
    #[tokio::test]
    async fn two_daemons_route_hostnames_concurrently() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let default_port = free_port().await;

        // Daemon one: a box named `web`. Daemon two: a box named `api`.
        let first_registry = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        first_registry
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "web");
        let second_registry = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        second_registry
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "api");

        let first = bind_proxy_listener_with_default(loopback, None, default_port)
            .await
            .expect("the first daemon binds the default port");
        let second = bind_proxy_listener_with_default(loopback, None, default_port)
            .await
            .expect("the second daemon selects a free port");
        assert_ne!(
            first.port, second.port,
            "two daemons on one host must not share a listen port"
        );
        let first_addr = SocketAddr::new(loopback, first.port);
        let second_addr = SocketAddr::new(loopback, second.port);
        tokio::spawn(serve(
            first.listener,
            Router::new(first_registry, host_address("web")),
        ));
        tokio::spawn(serve(
            second.listener,
            Router::new(second_registry, host_address("api")),
        ));

        // Both surfaces are live at the same time: one request to each daemon
        // for its own box, in flight together.
        let backend = spawn_backend().await;
        let web_authority = format!("web.min.internal:{backend}");
        let api_authority = format!("api.min.internal:{backend}");
        let (web, api) = tokio::join!(
            proxy_get(first_addr, &web_authority),
            proxy_get(second_addr, &api_authority),
        );
        assert!(
            web.contains("200 OK"),
            "the first daemon must route its own box, got: {web}"
        );
        assert!(
            api.contains("200 OK"),
            "the second daemon must route its own box, got: {api}"
        );

        // Each daemon answers for its own boxes only — two surfaces, not one.
        let crossed = proxy_get(first_addr, &api_authority).await;
        assert!(
            crossed.contains("502 Bad Gateway"),
            "a daemon must not route the other daemon's names, got: {crossed}"
        );
    }

    /// NET-001: a box answers at its two-label `<name>.min.internal` name through
    /// the proxy that already ships, own-address sessions on a VM host included.
    ///
    /// On a VM-backed host `minimald` runs in the guest, so the proxy binds the
    /// unspecified address there (the DM1 bind base `server::start_host_proxies`
    /// uses) and is reached through the port gvproxy publishes on the host
    /// loopback; the box itself is reached through *its* published loopback port,
    /// which is why an own-address session registers to loopback. Both halves are
    /// exercised here: the listener is bound unspecified and reached on loopback,
    /// and the target is an `OwnIp` registration.
    #[tokio::test]
    async fn proxy_routes_min_internal_for_own_ip_session_on_vm_host() {
        let backend_port = spawn_backend().await;

        let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        let hostname = shared
            .write()
            .unwrap()
            .register_own_ip(SessionId::nil(), "web");
        assert_eq!(hostname.as_str(), "web.min.internal");
        // The box declares the port it publishes, so the name routes to it.
        let router = Router::new(
            Arc::clone(&shared),
            admissions(
                "web",
                own_address(Ipv4Addr::new(100, 64, 0, 9), &[backend_port], None),
            ),
        );

        let proxy = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        tokio::spawn(serve(proxy, router));
        let proxy_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port));

        let authority = format!("web.min.internal:{backend_port}");
        let routed = proxy_get(proxy_addr, &authority).await;
        assert!(
            routed.contains("200 OK"),
            "expected the two-label name to route, got: {routed}"
        );

        // The name is the session's: once the session is gone, so is the route.
        shared.write().unwrap().deregister("web");
        let withdrawn = proxy_get(proxy_addr, &authority).await;
        assert!(
            withdrawn.contains("502 Bad Gateway"),
            "expected a gateway error once the session is gone, got: {withdrawn}"
        );
    }

    /// NET-001 (unwanted case): every request the proxy refuses is logged with
    /// its reason — a name no live box owns, a name that resolved to a box whose
    /// address will not accept a connection (which also names the session it
    /// resolved to), and a head that never yielded an authority.
    #[tokio::test]
    async fn proxy_refusal_is_logged_with_reason() {
        let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        shared
            .write()
            .unwrap()
            .register_own_ip(SessionId::nil(), "web");

        // A loopback port with nothing on it: bound only to learn a port the OS
        // has free, then dropped, so the connect is refused rather than hanging.
        let closed_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        // Declared, so the request reaches the connect and fails there rather
        // than being refused by the declaration.
        let router = Router::new(
            shared,
            admissions(
                "web",
                own_address(Ipv4Addr::new(100, 64, 0, 9), &[closed_port], None),
            ),
        );

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let unowned = drive_connection(
            &router,
            HOST_CALLER,
            "GET / HTTP/1.1\r\nHost: ghost.min.internal:80\r\n\r\n",
        )
        .await;
        let unreachable = drive_connection(
            &router,
            HOST_CALLER,
            &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{closed_port}\r\n\r\n"),
        )
        .await;
        let headless = drive_connection(&router, HOST_CALLER, "not-a-request-line\r\n\r\n").await;
        drop(guard);

        assert!(
            unowned.contains("502 Bad Gateway"),
            "expected a gateway error for an unowned name, got: {unowned}"
        );
        assert!(
            unreachable.contains("502 Bad Gateway"),
            "expected a gateway error for a dead upstream, got: {unreachable}"
        );
        assert!(
            headless.contains("400 Bad Request"),
            "expected a bad request for an unusable head, got: {headless}"
        );

        let logged = buf.contents();
        // The name nobody owns: the host asked for, and why it was refused.
        assert!(
            logged.contains(r#"host="ghost.min.internal:80""#),
            "expected the refused host, got: {logged}"
        );
        assert!(
            logged.contains(r#"reason="no-live-box-owns-the-name""#),
            "expected a reason for the unowned name, got: {logged}"
        );
        // The name that resolved: the reason, plus the session it resolved to.
        assert!(
            logged.contains(r#"reason="upstream-unreachable""#),
            "expected a reason for the dead upstream, got: {logged}"
        );
        assert!(
            logged.contains(r#"session="web""#),
            "expected the session the name resolved to, got: {logged}"
        );
        // A head with no authority is refused with a reason of its own.
        assert!(
            logged.contains(r#"reason="no-authority-in-request-head""#),
            "expected a reason for the unusable head, got: {logged}"
        );
    }

    /// NET-002: a request in the deprecated `<name>.<host-id>.min.internal` zone
    /// routes as the two-label name, and the notice in the log names the
    /// two-label form to use instead.
    #[tokio::test]
    async fn legacy_local_zone_routes_with_deprecation() {
        let backend_port = spawn_backend().await;

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID);
        assert_eq!(
            reg.register_host_net(SessionId::nil(), "web").as_str(),
            "web.min.internal"
        );
        let router = Router::new(Arc::new(reg), host_address("web"));

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let routed = drive_connection(
            &router,
            HOST_CALLER,
            &format!("GET / HTTP/1.1\r\nHost: web.local.min.internal:{backend_port}\r\n\r\n"),
        )
        .await;
        drop(guard);

        assert!(
            routed.contains("200 OK"),
            "expected the deprecated name to route, got: {routed}"
        );
        let logged = buf.contents();
        assert!(
            logged.contains(r#"host="web.local.min.internal""#),
            "expected the deprecated name in the notice, got: {logged}"
        );
        assert!(
            logged.contains(r#"routed_as="web.min.internal""#),
            "expected the notice to name the two-label form, got: {logged}"
        );
        assert!(
            logged.contains("deprecated"),
            "expected a deprecation notice, got: {logged}"
        );
    }

    /// Proof artifact 1 (registry/proxy routing contract): a `HostNet` PTask's
    /// `Host:` header routes through the proxy to its registered target; after
    /// `deregister` the proxy returns a gateway error instead of a stale route.
    /// No `getaddrinfo`/host-resolver dependency — the proxy contract is
    /// asserted directly.
    #[tokio::test]
    async fn host_header_routes_through_proxy_then_not_found_after_deregister() {
        let backend_port = spawn_backend().await;

        // `myservice.min.internal` → 127.0.0.1 (HostNet, R3.6); the client's
        // `:port` selects the upstream port, so it reaches the backend.
        let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        shared
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "myservice");
        let router = Router::new(Arc::clone(&shared), host_address("myservice"));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let authority = format!("myservice.min.internal:{backend_port}");
        let routed = proxy_get(proxy_addr, &authority).await;
        assert!(
            routed.contains("200 OK"),
            "expected a routed 200, got: {routed}"
        );

        // After the session exits the route is withdrawn: the proxy no longer
        // forwards the hostname.
        shared.write().unwrap().deregister("myservice");
        let not_found = proxy_get(proxy_addr, &authority).await;
        assert!(
            not_found.contains("502 Bad Gateway"),
            "expected a gateway error after deregister, got: {not_found}"
        );
    }

    /// Proof artifact 2 (OwnIp routing): under the published-loopback model a
    /// registered `OwnIp` PTask routes to `127.0.0.1` (its gvproxy-published
    /// forwarder port), not to the switch IP — the daemon is never on the switch
    /// (`networking-with-diagrams.md` DM2 topology). The client selects the
    /// published external port in the authority.
    #[test]
    fn own_ip_routes_to_its_published_loopback_port() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID);
        reg.register_own_ip(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), host_address("web"));

        // The published external port (e.g. an ingress 18080:8080 forward) is
        // carried in the authority and reached on loopback.
        assert_eq!(
            router.route("web.min.internal:18080").map(|u| u.addr),
            Some(SocketAddr::new(loopback, 18080))
        );
        // Absent an explicit port the default upstream port is used.
        assert_eq!(
            router.route("web.min.internal").map(|u| u.addr),
            Some(SocketAddr::new(loopback, DEFAULT_UPSTREAM_PORT))
        );
        // The upstream names the session, so a refusal after routing can say
        // which box the authority resolved to.
        assert_eq!(
            router.route("web.min.internal").map(|u| u.session),
            Some("web".to_string())
        );
        // An unregistered host does not route.
        assert_eq!(router.route("ghost.min.internal"), None);
    }

    /// Proof artifact 3 (R3.4 supersession): when the listen address cannot be
    /// bound, the reachability check emits the `component = "dns-proxy"`
    /// `status = "unavailable"` warning and yields no listener.
    #[tokio::test]
    async fn bind_failure_warns_dns_proxy_unavailable() {
        // Hold the address so the reachability bind fails deterministically.
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = held.local_addr().unwrap();

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let listener = bind_listener(addr).await;
        drop(guard);

        assert!(listener.is_none(), "a bind to a held address must fail");
        let logged = buf.contents();
        assert!(
            logged.contains(r#"component="dns-proxy""#),
            "expected the dns-proxy component field, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="unavailable""#),
            "expected the unavailable status field, got: {logged}"
        );
    }

    /// A bind that fails does not stay failed: the daemon keeps retrying on a
    /// growing, capped delay and comes up on its own once the address is free,
    /// with no restart involved (NET-021).
    #[tokio::test(start_paused = true)]
    async fn listener_retries_with_backoff() {
        // The schedule doubles from the base delay and then holds at the cap.
        assert_eq!(rebind_delay(1), REBIND_BASE_DELAY);
        assert_eq!(rebind_delay(2), REBIND_BASE_DELAY * 2);
        assert_eq!(rebind_delay(3), REBIND_BASE_DELAY * 4);
        assert_eq!(rebind_delay(1_000), REBIND_MAX_DELAY);

        // Hold the address so every attempt fails until the holder lets go.
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = held.local_addr().unwrap();

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let started = tokio::time::Instant::now();
        let retrying = tokio::spawn(bind_listener_retrying(addr));

        // Paused time auto-advances while every task is sleeping, so crossing
        // the first backoff steps costs no real time.
        tokio::time::sleep(REBIND_BASE_DELAY * 8).await;
        assert!(
            !retrying.is_finished(),
            "must not report a listener while the address is held"
        );
        let logged = buf.contents();
        assert!(
            logged.contains("retry_in_ms=250") && logged.contains("retry_in_ms=500"),
            "expected a growing retry delay per attempt, got: {logged}"
        );

        drop(held);
        let bound = tokio::time::timeout(Duration::from_secs(120), retrying)
            .await
            .expect("the retry loop must bind once the address is free")
            .expect("the retry task must not panic");
        assert_eq!(bound.local_addr().unwrap(), addr);

        // It backed off between attempts rather than spinning: at least the
        // first three delays elapsed before the address came free.
        assert!(
            started.elapsed() >= rebind_delay(1) + rebind_delay(2) + rebind_delay(3),
            "expected the loop to sleep between attempts, elapsed {:?}",
            started.elapsed()
        );
        assert!(
            buf.contents().contains(r#"status="recovered""#),
            "recovery must be logged, got: {}",
            buf.contents()
        );
    }

    /// NET-069: a request through the proxy to a port the target box did not
    /// declare is refused, naming the rule the declaration is made of, while the
    /// port it did declare routes. A live backend sits behind the undeclared
    /// port, so the refusal is the declaration's and not a dead upstream's; and
    /// the port the proxy admits is the one the forwarder publishes for the same
    /// declaration, which is the port a direct connection from the host reaches.
    #[tokio::test]
    async fn proxy_undeclared_port_refused_like_direct() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        let declared_port = spawn_backend().await;
        let undeclared_port = spawn_backend().await;

        let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        shared
            .write()
            .unwrap()
            .register_own_ip(SessionId::nil(), "web");
        let router = Router::new(
            Arc::clone(&shared),
            admissions("web", own_address(LEASE, &[declared_port], None)),
        );

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let declared = drive_connection(
            &router,
            HOST_CALLER,
            &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{declared_port}\r\n\r\n"),
        )
        .await;
        let undeclared = drive_connection(
            &router,
            HOST_CALLER,
            &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{undeclared_port}\r\n\r\n"),
        )
        .await;
        drop(guard);

        assert!(
            declared.contains("200 OK"),
            "expected the declared port to route, got: {declared}"
        );
        assert!(
            undeclared.contains("403 Forbidden"),
            "expected an undeclared port to be refused, got: {undeclared}"
        );

        // The refusal names the caller, the box, the port and the rule.
        let logged = buf.contents();
        for field in [
            r#"reason="target-box-did-not-declare-the-port""#,
            r#"rule="ingress.port_mappings""#,
            r#"session="web""#,
            r#"caller="127.0.0.1""#,
        ] {
            assert!(logged.contains(field), "expected {field}, got: {logged}");
        }
        assert!(
            logged.contains(&format!("port={undeclared_port}")),
            "expected the refused port, got: {logged}"
        );

        // The one port the proxy admitted is the one the forwarder publishes on
        // host loopback for this declaration; the refused port has no forward,
        // so a direct connection to it reaches nothing either.
        let published = crate::net::policy::expose_request(
            &tcp_ports(&[declared_port]).port_mappings[0],
            LEASE,
        );
        assert_eq!(published.local, format!("127.0.0.1:{declared_port}"));
    }

    /// NET-070: a request from a box whose own egress rules do not allow the
    /// target is refused, with the rule a direct frame from that box would trip;
    /// widen the caller's rules and the same request routes.
    #[tokio::test]
    async fn proxy_caller_egress_denied() {
        const CALLER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
        const TARGET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        let port = spawn_backend().await;

        let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
        shared
            .write()
            .unwrap()
            .register_own_ip(SessionId::nil(), "web");
        let table = Arc::new(RwLock::new(BoxAdmissions::new()));
        {
            let mut declarations = table.write().unwrap();
            declarations.declare("web", own_address(TARGET, &[port], None));
            // The caller reaches 10.0.0.0/8 only — not the target's address.
            declarations.declare(
                "peer",
                own_address(CALLER, &[], Some(&allow_only("10.0.0.0/8"))),
            );
        }
        let router = Router::new(Arc::clone(&shared), Arc::clone(&table));

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let refused = drive_connection(
            &router,
            CALLER.into(),
            &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{port}\r\n\r\n"),
        )
        .await;
        drop(guard);

        assert!(
            refused.contains("403 Forbidden"),
            "expected a caller whose rules deny the target to be refused, got: {refused}"
        );
        let logged = buf.contents();
        for field in [
            r#"reason="caller-rules-deny-the-target""#,
            r#"rule="allow_subnets""#,
            r#"caller="100.64.0.5""#,
        ] {
            assert!(logged.contains(field), "expected {field}, got: {logged}");
        }

        // That rule is the one the relay's own frame verdict names for the
        // connection this request stands in for.
        let direct = ProxiedRequest {
            caller: CALLER,
            target: TARGET,
            port,
            proto: IPPROTO_TCP,
        }
        .as_frame();
        assert_eq!(
            frame_verdict(
                &direct,
                &EgressRules::for_box(CALLER, Some(&allow_only("10.0.0.0/8")), None)
            ),
            Verdict::Drop(DropRule::Undeclared)
        );

        // Allowed the switch, the same caller reaches the same declared port.
        table.write().unwrap().declare(
            "peer",
            own_address(CALLER, &[], Some(&allow_only("100.64.0.0/10"))),
        );
        let allowed = drive_connection(
            &router,
            CALLER.into(),
            &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{port}\r\n\r\n"),
        )
        .await;
        assert!(
            allowed.contains("200 OK"),
            "expected a caller allowed the target to route, got: {allowed}"
        );
    }

    /// NET-071: on a target with an address of its own and one carrying the
    /// host's address alike, the verdict the proxy reaches is the verdict the
    /// direct connection reaches — over declared and undeclared ports, and over
    /// a caller whose rules allow the target and one whose rules do not — and
    /// the answer on the wire follows that verdict in both modes.
    #[tokio::test]
    async fn proxy_parity_across_network_modes() {
        const CALLER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 5);
        const TARGET: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        let declared_port = spawn_backend().await;
        let undeclared_port = spawn_backend().await;
        let subnet = SwitchSubnet::default();

        for (mode, declaration, address, ingress) in [
            (
                "own address",
                own_address(TARGET, &[declared_port], None),
                TARGET,
                IngressRules::for_own_address(Some(&tcp_ports(&[declared_port]))),
            ),
            (
                "host address",
                BoxDeclaration::for_host_address(subnet),
                subnet.host_alias(),
                IngressRules::for_host_address(),
            ),
        ] {
            for (rules, reaches_the_target) in [
                (allow_only("100.64.0.0/10"), true),
                (allow_only("10.0.0.0/8"), false),
            ] {
                let table = Arc::new(RwLock::new(BoxAdmissions::new()));
                {
                    let mut declarations = table.write().unwrap();
                    declarations.declare("web", declaration.clone());
                    declarations.declare("peer", own_address(CALLER, &[], Some(&rules)));
                }
                let caller_rules = EgressRules::for_box(CALLER, Some(&rules), None);

                for port in [declared_port, undeclared_port] {
                    let direct = direct_verdict(
                        &ProxiedRequest {
                            caller: CALLER,
                            target: address,
                            port,
                            proto: IPPROTO_TCP,
                        }
                        .as_frame(),
                        Some(&caller_rules),
                        &ingress,
                    );
                    let proxied = table.read().unwrap().verdict(CALLER.into(), "web", port);
                    assert_eq!(
                        proxied, direct,
                        "{mode}: port {port}, caller reaches the target: {reaches_the_target}"
                    );
                }

                // And the answer on the wire is that verdict, not something the
                // surface decided for itself.
                let shared = Arc::new(RwLock::new(HostnameRegistry::new(DEFAULT_HOST_ID)));
                shared
                    .write()
                    .unwrap()
                    .register_own_ip(SessionId::nil(), "web");
                let router = Router::new(shared, table);
                let answer = drive_connection(
                    &router,
                    CALLER.into(),
                    &format!("GET / HTTP/1.1\r\nHost: web.min.internal:{declared_port}\r\n\r\n"),
                )
                .await;
                let expected = if reaches_the_target {
                    "200 OK"
                } else {
                    "403 Forbidden"
                };
                assert!(
                    answer.contains(expected),
                    "{mode}: expected {expected}, got: {answer}"
                );
            }
        }
    }

    /// `CONNECT` carries the authority in its request line; a plain method
    /// carries it in the `Host:` header. Both parse to the same authority.
    #[test]
    fn parse_request_reads_connect_and_host_authorities() {
        let connect = parse_request(b"CONNECT web.min.internal:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(matches!(connect.kind, RequestKind::Connect));
        assert_eq!(connect.authority, "web.min.internal:443");

        let forward =
            parse_request(b"GET / HTTP/1.1\r\nHost: web.min.internal:8080\r\n\r\n").unwrap();
        assert!(matches!(forward.kind, RequestKind::Forward));
        assert_eq!(forward.authority, "web.min.internal:8080");
    }

    /// A forward request from an `HTTP_PROXY`-configured client carries an
    /// absolute-form request target (`GET http://web.min.internal/path HTTP/1.1`).
    /// The proxy routes it by `Host:` header and replays the buffered head
    /// verbatim, so the upstream receives the absolute-form request line
    /// unchanged — RFC 9112 requires an origin server to accept it. Complements
    /// `host_header_routes_through_proxy_then_not_found_after_deregister`, which
    /// only exercises an origin-form (`GET /`) target.
    #[tokio::test]
    async fn forward_proxy_replays_absolute_form_target_to_upstream() {
        // A backend that records the request head it received, then answers 200.
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_bg = Arc::clone(&received);
        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            received_bg.lock().unwrap().extend_from_slice(&buf[..n]);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), host_address("web"));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let request_line = format!("GET http://web.min.internal:{backend_port}/path HTTP/1.1");
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("{request_line}\r\nHost: web.min.internal:{backend_port}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "expected the absolute-form request to route, got: {}",
            String::from_utf8_lossy(&response)
        );

        // The upstream saw the absolute-form request line replayed verbatim.
        let upstream_head = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        assert!(
            upstream_head.starts_with(&request_line),
            "expected absolute-form target replayed to upstream, got: {upstream_head}"
        );
    }
}
