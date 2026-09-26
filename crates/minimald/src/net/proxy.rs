//! The host-side egress proxy and its shared routing core.
//!
//! Unit 3 (UC2a) resolves PTask `*.min.internal` hostnames **host-side**: the host
//! resolver is never consulted, so the no-systemd sandbox (hakoniwa) and microVM
//! (libkrun) runtimes and the TLD choice are both irrelevant to correctness. A
//! client points `HTTP(S)_PROXY` (or a PAC file) at this proxy, which routes
//! each request by its `Host:` header — or a `CONNECT` request's authority — to
//! the target PTask via the in-memory
//! [`HostnameRegistry`](super::dns::HostnameRegistry): a `HostNet` PTask to
//! `127.0.0.1:<port>`, and an `OwnIp` PTask straight to its lease on a VM host
//! (the daemon sits on the switch) or to its published-loopback forwarder on a
//! native host. Every request the proxy refuses is logged with the host asked
//! for, the reason and the status sent (NET-001), so the daemon log — and the
//! diagnostics bundle's tail of it — names every refused request.
//!
//! A refusal the switch would make too is decided *here, before dialing*, by
//! the same verdict the relay's gates apply (NET-069, NET-070, NET-071): a
//! request to a port the target did not declare, or from a caller whose
//! egress rules deny the target, is refused with the same rule name a direct
//! connection's drop carries — the routing surface gives no reach a direct
//! connection would not. The verdict is a pure function shared with the relay
//! ([`super::switch::proxied_request_verdict`]), handed in by the daemon
//! startup that serves this proxy (`server::start_host_proxies`), so the two
//! surfaces cannot drift.
//!
//! The proxy serves plain HTTP/1.1 and `CONNECT` tunnels only: the HTTPS/mTLS
//! reverse proxy that once terminated TLS in front of this routing core is
//! retired (NET-109), so the daemon opens no listener but
//! [`DEFAULT_EGRESS_PROXY_PORT`] and issues no certificate — and a connection
//! that opens with the HTTP/2 prior-knowledge preface is closed at once, while
//! an `Upgrade: h2c` offer is stripped and the request routed as the HTTP/1.1
//! request it is (NET-135). The host-side `*.min.internal` decision supersedes
//! spike #485's systemd-resolved finding (spec Open Question 1).

use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::dns::HostnameRegistry;
use super::policy::Direction;
use super::switch::ProxiedRequest;

/// The port the host-side egress/DNS proxy listens on (TC3): the documented
/// default the recipes that export `HTTP(S)_PROXY` assume. A daemon started
/// without a configured port tries this one first, so those recipes keep
/// working on a quiet host; only when it is busy does it ask the OS for a
/// free port, publishing the port it got wherever clients need it
/// (NET-025). The one routing listener the daemon opens: the mTLS reverse
/// proxy that once took the next port up is retired (NET-109).
pub const DEFAULT_EGRESS_PROXY_PORT: u16 = 7654;

/// The address a pinned deployment's clients are told to point
/// `HTTP(S)_PROXY` at: loopback, where every `*.min.internal` name is
/// reachable, on [`DEFAULT_EGRESS_PROXY_PORT`].
pub const DEFAULT_PROXY_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_EGRESS_PROXY_PORT);

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
/// host (with any `:port` already stripped) to the route its requests forward
/// on, or `None` if no live PTask owns it. The host resolver is never consulted.
///
/// Beside the routing table itself, the lookup names a *caller*: the live
/// session a request's peer address resolves to, whose egress rules the
/// request is put to (NET-070).
///
/// Factored as a trait so the routing core is decoupled from how the table is
/// shared (the sessions manager owns the live registry).
pub trait HostRoute: Send + Sync + 'static {
    /// Resolves a `Host:`-header host to the route its requests forward on.
    fn resolve_host(&self, host: &str) -> Option<super::dns::Route>;

    /// The live caller at a switch lease (NET-070): the session whose box
    /// holds `lease`, with the compiled egress rules its own outbound frames
    /// are decided by — what a proxied request from that box is put to,
    /// exactly as a direct connection from it would be. `None` when no live
    /// box holds the lease, which is what a host-side peer is (the developer's
    /// browser, the daemon's own lanes).
    fn caller_at(&self, lease: Ipv4Addr) -> Option<super::dns::Caller>;
}

impl HostRoute for HostnameRegistry {
    fn resolve_host(&self, host: &str) -> Option<super::dns::Route> {
        self.resolve(host)
    }

    fn caller_at(&self, lease: Ipv4Addr) -> Option<super::dns::Caller> {
        self.caller_at(lease)
    }
}

// The daemon shares its live registry behind an `RwLock` (the sessions manager
// mutates it under `&mut self`; the proxy only reads it, synchronously, with no
// `.await` held). This lets `Router::new(Arc<RwLock<HostnameRegistry>>)` route
// against the same table the manager registers PTasks into.
impl HostRoute for std::sync::RwLock<HostnameRegistry> {
    fn resolve_host(&self, host: &str) -> Option<super::dns::Route> {
        // Recover from a poisoned lock rather than mapping it to `None`: the
        // registry is two HashMaps with no cross-field invariant a panicked
        // writer could half-break, and silently returning `None` would make
        // every `*.min.internal` request 502 forever with no signal.
        match self.read() {
            Ok(guard) => guard.resolve(host),
            Err(poisoned) => poisoned.into_inner().resolve(host),
        }
    }

    fn caller_at(&self, lease: Ipv4Addr) -> Option<super::dns::Caller> {
        match self.read() {
            Ok(guard) => guard.caller_at(lease),
            Err(poisoned) => poisoned.into_inner().caller_at(lease),
        }
    }
}

/// The admit-or-drop decision every proxied request is put to before the
/// proxy dials anything (NET-069, NET-070, NET-071) — the relay's own verdict,
/// [`super::switch::proxied_request_verdict`], so the hostname-routing surface
/// gives no reach a direct connection would not. Typed as a plain function so
/// the router stays a small `Clone` value handed to every connection task.
pub type SharedVerdict = fn(Option<&super::dns::Caller>, &super::dns::Route, u16) -> ProxiedRequest;

/// The shared routing core: maps an HTTP authority (`host` or `host:port`) to
/// the upstream socket address a request forwards to.
pub struct Router<T> {
    table: Arc<T>,
    /// The verdict each request is put to (see [`SharedVerdict`]), applied
    /// before the proxy dials the upstream.
    verdict: SharedVerdict,
}

// Manual `Clone` so a `Router` is cheap to hand to each connection task without
// requiring `T: Clone` (only the `Arc` is cloned).
impl<T> Clone for Router<T> {
    fn clone(&self) -> Self {
        Self {
            table: Arc::clone(&self.table),
            verdict: self.verdict,
        }
    }
}

impl<T: HostRoute> Router<T> {
    /// Builds a router over a shared host-routing table, deciding each request
    /// with `verdict` — the relay's own
    /// [`super::switch::proxied_request_verdict`] in every production caller.
    #[must_use]
    pub fn new(table: Arc<T>, verdict: SharedVerdict) -> Self {
        Self { table, verdict }
    }

    /// Routes an HTTP authority to its upstream socket address, or `None` if no
    /// live PTask owns the host or the host does not carry the requested port.
    /// The authority's optional `:port` selects the upstream port; absent,
    /// [`DEFAULT_UPSTREAM_PORT`] is used. An `OwnIp` box's request is gated by
    /// the ports its ingress declaration publishes on every host form — on a
    /// VM host through the external→internal translation, on a native host
    /// through the route's declared set (NET-069, NET-071) — and a port the
    /// declaration does not publish routes nowhere: the proxy refuses it,
    /// matching the ingress gate that denies an inbound SYN to any undeclared
    /// port on the switch (NET-001).
    ///
    /// A `HostNet` box's registry entry gates no port: a host-address box has
    /// no ingress declaration — launch validation rejects one on every network
    /// mode but `own_ip` — and a direct connection to it is ungated, so the
    /// proxy gates nothing either (NET-071). The upstream port comes entirely
    /// from the client-supplied authority, so its hostname can be routed to
    /// `127.0.0.1:<any-port>`. That is an accepted limitation of the current
    /// single-user threat model — the networking spec scopes `minimald` to a
    /// single tenant per host and defers multi-tenant policy isolation
    /// (including per-PTask loopback port restriction) to a follow-up. Where
    /// mutually-untrusted PTasks share loopback, this is a loopback-SSRF
    /// surface that the follow-up must close.
    #[must_use]
    pub fn route(&self, authority: &str) -> Option<SocketAddr> {
        let (host, port) = split_authority(authority);
        self.resolve(host)?
            .upstream(port.unwrap_or(DEFAULT_UPSTREAM_PORT))
    }

    /// The route the authority's host resolves to, or `None` if no live PTask
    /// owns it — what [`Self::route`] turns into a socket, and what a
    /// connection handler needs when it must name the session a request
    /// resolved to in its logs.
    fn resolve(&self, host: &str) -> Option<super::dns::Route> {
        self.table.resolve_host(host)
    }

    /// The live caller at a switch lease ([`HostRoute::caller_at`]) — who a
    /// proxied request from that address is, and whose egress rules it is put
    /// to (NET-070).
    fn caller_at(&self, lease: Ipv4Addr) -> Option<super::dns::Caller> {
        self.table.caller_at(lease)
    }
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

/// Why a host-side proxy listener could not bind its address, carrying the
/// reason and the one remedy that clears it.
///
/// The pair is authored once here so every surface reads the same text: the
/// startup retry's warning, the daemon's `proxy_unavailable` note the
/// `ListSessions` RPC serves, and the warning `min ls` and
/// `min session activate` print (NET-020).
#[derive(Debug, Clone)]
pub struct BindFailure {
    /// What failed, named for a human: the address and the OS error.
    pub reason: String,
    /// The remedy: free the listen address so the daemon's retry can bind it.
    pub remedy: String,
    /// The OS error's [`io::ErrorKind`], carried beside the rendered text so
    /// the busy-port predicate ([`Self::is_addr_in_use`]) matches the *kind*,
    /// never the text: the daemon runs under two libcs — glibc on a native
    /// host, musl in the guest the initramfs cross-builds — and they do not
    /// agree on how `EADDRINUSE` reads.
    pub kind: io::ErrorKind,
}

impl BindFailure {
    /// The reason and remedy as the one report the daemon's unavailable note
    /// and the CLI warning carry.
    #[must_use]
    pub fn reported(&self) -> String {
        format!("{}. Remedy: {}", self.reason, self.remedy)
    }

    /// Whether the listen address was busy — the one bind failure a
    /// default-then-select port policy relocates from (NET-025): any other
    /// failure (an address that cannot be assigned, a permission the daemon
    /// lacks) is not another daemon holding the port, and moving the listener
    /// would hide it, so the caller keeps retrying the address it named
    /// (NET-021).
    ///
    /// Compared on the carried [`io::ErrorKind`], never on the rendered text:
    /// the reason is a human-facing report and the OS error inside it is
    /// rendered by the libc, which differs — glibc spells `EADDRINUSE`
    /// "Address already in use", musl (the `*-linux-musl` guest build) "Address
    /// in use", so a text match never fires inside a microVM and a guest
    /// daemon whose default port is busy would loop on the retry instead of
    /// relocating. Both bind paths that build a failure ([`bind_listener`]
    /// and the answerer's UDP bind) hold the `io::Error` the kernel answered
    /// with, so its kind is the one fact both libcs agree on.
    #[must_use]
    pub fn is_addr_in_use(&self) -> bool {
        self.kind == io::ErrorKind::AddrInUse
    }
}

/// Binds the egress-proxy listener at `addr`, returning it on success. On a
/// bind failure it returns a [`BindFailure`] carrying the reason (the address
/// and the OS error) and the remedy that clears it, and logs nothing: the
/// caller owns the failure's log line, because only it knows the retry
/// schedule that line reports — `server::start_host_proxies` retries with
/// backoff until the bind succeeds (NET-021), so one failed bind is one
/// warning, not a silent fallback. This is the daemon-startup reachability
/// check that supersedes the former systemd-resolved probe (R3.4).
///
/// The returned listener is the caller's to either serve (via [`serve`]) or
/// drop. The success event reports the address as `reachable` rather than
/// `listening` because binding only proves the address was free — a caller that
/// drops the listener is not accepting requests. The daemon startup path does
/// serve it (see `server::start_host_proxies`); this said otherwise, and reading
/// it as a bind-and-drop probe is what made gominimal/inbox#560 look like a
/// false alarm on macOS.
///
/// # Errors
///
/// Returns a [`BindFailure`] when the address cannot be bound; the OS error is
/// carried inside the failure's reason, and its kind beside it
/// ([`BindFailure::kind`]).
pub async fn bind_listener(addr: SocketAddr) -> Result<TcpListener, BindFailure> {
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            tracing::info!(
                component = "dns-proxy",
                %addr,
                status = "reachable",
                "host-side egress proxy listen address is bindable"
            );
            Ok(listener)
        }
        Err(error) => Err(BindFailure {
            reason: format!("the daemon could not bind {addr}: {error}"),
            remedy: format!(
                "free the listen address; `lsof -nP -iTCP:{} -sTCP:LISTEN` names the holder",
                addr.port()
            ),
            kind: error.kind(),
        }),
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
            if let Err(error) = handle_connection_io(client, Some(peer), &router).await {
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
/// route it by authority, then either return a gateway error or splice it to
/// the upstream PTask. Generic over the client transport so the same routing
/// core serves the egress proxy's `TcpStream` and any other byte stream a
/// caller hands it. `peer` is the client's address when the transport has one
/// — what names the caller whose egress rules the request is put to (NET-070).
///
/// Every refusal — a head that never arrives, an unparseable head, a host no
/// live PTask owns, an upstream that will not accept the connection, a request
/// the switch's own gates would refuse too — is logged as a warn line
/// (NET-001) naming what is known about it, so the daemon log never swallows
/// a refused request.
async fn handle_connection_io<C, T>(
    mut client: C,
    peer: Option<SocketAddr>,
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
            log_refusal(
                None,
                "no complete request head within the read timeout",
                "408 Request Timeout",
            );
            return write_status(&mut client, "408 Request Timeout").await;
        }
    };

    // NET-135: a connection that opens with the HTTP/2 prior-knowledge preface
    // is an HTTP/2 connection, and this proxy routes HTTP/1.1 requests and
    // CONNECT tunnels only — there is no protocol switch behind it to offer,
    // and tunneling one would bypass the routing core's refusals entirely.
    // Close it at once: no status, no bytes, because there is no HTTP/1.1
    // exchange to answer inside (an h2 client reads a close as GOAWAY-shaped
    // failure and its library says so).
    if is_h2_prior_knowledge_preface(&head) {
        tracing::warn!(
            component = "dns-proxy",
            reason = "the proxy routes HTTP/1.1 requests and CONNECT tunnels only; \
                      closed an HTTP/2 prior-knowledge connection",
            "refused a proxied connection"
        );
        return Ok(());
    }

    let Some(request) = parse_request(&head) else {
        log_refusal(None, "unparseable request head", "400 Bad Request");
        return write_status(&mut client, "400 Bad Request").await;
    };

    let (host, port) = split_authority(request.authority);

    // No live PTask owns this hostname: a host-side proxy returns a clean
    // gateway error rather than leaking the lookup to the host resolver.
    let Some(route) = router.resolve(host) else {
        log_refusal(
            Some(host),
            "no live box owns this hostname",
            "502 Bad Gateway",
        );
        return write_status(&mut client, "502 Bad Gateway").await;
    };
    let kind = request.kind;
    let port = port.unwrap_or(DEFAULT_UPSTREAM_PORT);

    // Who the request came from (NET-070): a peer at a live box's switch lease
    // is that box, with the egress rules its own outbound frames are decided
    // by; any other peer — a host-side client, a box with no lease on the
    // switch — is no caller, and its egress is ungated here exactly as a
    // direct connection from it would be (NET-071).
    let caller = peer.and_then(|peer| match peer {
        SocketAddr::V4(v4) => router.caller_at(*v4.ip()),
        SocketAddr::V6(_) => None,
    });

    // The shared verdict, before the proxy dials anything: a request the
    // switch's own gates would refuse is refused here, where the host, the
    // session and the port are all in hand, rather than dialed into a gate
    // that would only drop the SYN — a dropped SYN is a silent connect hang,
    // not a refusal (NET-001, NET-014, NET-069, NET-070, NET-071).
    let upstream_addr = match (router.verdict)(caller.as_ref(), &route, port) {
        ProxiedRequest::Forward(upstream_addr) => upstream_addr,
        ProxiedRequest::Refused(refusal) => {
            let reason = match refusal.direction {
                Direction::Egress => "the caller's egress policy denies this target",
                Direction::Ingress => "the box has not published this port",
            };
            // One warn line per refusal (not rate-limited: a request is a
            // user action, not a frame flood), in the shape of the relay's
            // drop line — `direction`, `remote_addr`, `proto`, `dst_port`,
            // `rule_matched` — beside the proxy's own fields. `session` is
            // the target and `caller` the caller, the two boxes the relay's
            // `session_id`/`remote_addr` pair names for the same refusal.
            tracing::warn!(
                component = "dns-proxy",
                host,
                session = route.session(),
                caller = caller.as_ref().map_or("none", super::dns::Caller::name),
                port,
                direction = %refusal.direction,
                remote_addr = refusal
                    .other
                    .map_or_else(|| "none".to_string(), |addr| addr.to_string()),
                proto = "tcp",
                dst_port = port,
                rule_matched = refusal.rule,
                reason,
                status = "403 Forbidden",
                "network policy violation"
            );
            return write_status(&mut client, "403 Forbidden").await;
        }
    };

    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!(
                component = "dns-proxy",
                host = %host,
                session = route.session(),
                %error,
                reason = "the upstream box refused the connection",
                status = "502 Bad Gateway",
                "refused a proxied request"
            );
            return write_status(&mut client, "502 Bad Gateway").await;
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
        // original request, then splice the rest both ways. An h2c upgrade
        // offer is stripped first, so the request is routed as the HTTP/1.1
        // request it is and the upstream cannot answer a protocol switch the
        // proxy cannot splice (NET-135).
        RequestKind::Forward => {
            let head = strip_h2c_upgrade(&head);
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

/// Whether the buffered head opens with the HTTP/2 prior-knowledge preface's
/// request line (`PRI * HTTP/2.0`, RFC 9113 §3.4): the connection is an
/// HTTP/2 connection, which the proxy neither speaks nor tunnels (NET-135).
///
/// Matched on the request line alone because the end-of-head marker the
/// reader stops at is *inside* the preface — `read_head` returns as soon as it
/// sees the `\r\n\r\n` the preface's own first line ends with, so only that
/// much is buffered and the full 24-byte preface is not available to match.
fn is_h2_prior_knowledge_preface(head: &[u8]) -> bool {
    head.starts_with(b"PRI * HTTP/2.0")
}

/// Strips an h2c upgrade from a buffered request head (NET-135): the
/// `Upgrade: h2c` header, its `HTTP2-Settings` header, and the tokens naming
/// them in `Connection` go, so the request is routed as the HTTP/1.1 request
/// it is and the upstream cannot answer a protocol switch the proxy cannot
/// splice. Only an `Upgrade` header carrying the `h2c` token triggers the
/// strip; any other upgrade offer (a websocket) passes through verbatim, and
/// its `Connection: Upgrade` token is kept for it.
///
/// Bytes after the end-of-head marker — body bytes the head read may have
/// buffered — are preserved untouched and never scanned for headers: a body
/// can carry anything.
fn strip_h2c_upgrade(head: &[u8]) -> Cow<'_, [u8]> {
    let head_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |at| at + 4);
    let (headers, rest) = head.split_at(head_end);
    let lines = head_lines(headers);
    if !carries_h2c(&lines) {
        return Cow::Borrowed(head);
    }

    // Whether any upgrade offer survives the strip (an `Upgrade: h2c, websocket`
    // keeps the websocket): a surviving offer keeps its `Connection: Upgrade`
    // token, so the strip never breaks an upgrade that was not its to touch.
    let upgrades_survive = lines.iter().any(|line| {
        header_parts(line).is_some_and(|(name, value)| {
            is_header(name, b"upgrade") && value_tokens(value).any(|t| !is_token(t, b"h2c"))
        })
    });

    let mut out = Vec::with_capacity(head.len());
    for line in lines {
        let Some((name, value)) = header_parts(line) else {
            // The request line, the end-of-head line, a header with no colon:
            // not an h2c header, kept verbatim.
            out.extend_from_slice(line);
            continue;
        };
        if is_header(name, b"upgrade") {
            let offered: Vec<&[u8]> = value_tokens(value)
                .filter(|t| !is_token(t, b"h2c"))
                .collect();
            if offered.is_empty() {
                continue; // `Upgrade: h2c` alone: the whole header goes.
            }
            out.extend(rewritten_header(line, name, &offered));
            continue;
        }
        if is_header(name, b"http2-settings") {
            continue; // h2c-only: the header RFC 7540 §3.2 pairs with `h2c`.
        }
        if is_header(name, b"connection") {
            let kept: Vec<&[u8]> = value_tokens(value)
                .filter(|t| {
                    !is_token(t, b"http2-settings")
                        && !(is_token(t, b"upgrade") && !upgrades_survive)
                })
                .collect();
            if kept.is_empty() {
                continue; // The stripped headers were all it named.
            }
            out.extend(rewritten_header(line, name, &kept));
            continue;
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(rest);
    Cow::Owned(out)
}

/// The lines of a head's header block, each with its terminator, so a rebuilt
/// head is byte-for-byte the original except for what a strip removes. Line 0
/// is the request line; the last is the end-of-head marker's own `\r\n`.
fn head_lines(headers: &[u8]) -> Vec<&[u8]> {
    headers.split_inclusive(|&b| b == b'\n').collect()
}

/// The `(name, value)` of one header line, or `None` for the request line, the
/// end-of-head line, or anything else with no `:` to split a name from.
fn header_parts(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let line = line
        .strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .unwrap_or(line);
    let colon = line.iter().position(|&b| b == b':')?;
    Some((line[..colon].trim_ascii(), &line[colon + 1..]))
}

/// Whether `name` is the header `want`, case-insensitively (header names are).
fn is_header(name: &[u8], want: &[u8]) -> bool {
    name.eq_ignore_ascii_case(want)
}

/// Whether `token` is `want`, case-insensitively (a token that names a protocol
/// or a header, as `h2c`, `Upgrade` and `HTTP2-Settings` do, is ASCII).
fn is_token(token: &[u8], want: &[u8]) -> bool {
    token.eq_ignore_ascii_case(want)
}

/// The comma-separated tokens of a header value, whitespace-trimmed.
fn value_tokens(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|&b| b == b',').map(|t| t.trim_ascii())
}

/// Whether the head offers `h2c` (NET-135's trigger): any `Upgrade` header
/// whose token list carries `h2c`. The request line is not a header and is
/// not consulted.
fn carries_h2c(lines: &[&[u8]]) -> bool {
    lines.iter().skip(1).any(|line| {
        header_parts(line).is_some_and(|(name, value)| {
            is_header(name, b"upgrade") && value_tokens(value).any(|t| is_token(t, b"h2c"))
        })
    })
}

/// One header line rebuilt to carry only `tokens`, preserving the original
/// name's case and each token's own bytes, and the original line's terminator.
fn rewritten_header<'a>(line: &'a [u8], name: &'a [u8], tokens: &[&[u8]]) -> Vec<u8> {
    let body = line
        .strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .unwrap_or(line);
    let terminator = &line[body.len()..];
    let mut out = Vec::with_capacity(line.len());
    out.extend_from_slice(name);
    out.push(b':');
    out.push(b' ');
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(token);
    }
    out.extend_from_slice(terminator);
    out
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

/// Emits the refusal warn line (NET-001): every request the proxy refuses is
/// logged with the Host asked for — when the head carried one, which the
/// timeout and unparseable-head refusals cannot have — the reason, and the
/// status sent, so the daemon log (and the diagnostics bundle's tail of it)
/// names every refused request. A refusal whose host resolved but whose
/// request still cannot be forwarded — a policy verdict refused it, or its
/// upstream refused the connection — is logged by its own call site, which
/// adds the session it resolved to.
fn log_refusal(host: Option<&str>, reason: &str, status: &str) {
    match host {
        Some(host) => tracing::warn!(
            component = "dns-proxy",
            host,
            reason,
            status,
            "refused a proxied request"
        ),
        None => tracing::warn!(
            component = "dns-proxy",
            reason,
            status,
            "refused a proxied request"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::SocketAddrV4;
    use std::sync::{Mutex, RwLock};

    use sessions::core::egress::{self, FrameVerdict};
    use sessions::{EgressPolicy, IngressPolicy, IpProto, PortMapping, SessionId, SessionPolicy};
    use tokio::net::TcpSocket;

    use crate::net::SwitchSubnet;
    use crate::net::dns::DEFAULT_HOST_ID;
    use crate::net::policy::Direction;
    use crate::net::switch::{
        NO_INGRESS_MAPPING_RULE, ProxiedRequest, Refusal, SessionGate, declared_request_ports,
        proxied_request_verdict,
    };
    use crate::test_harness::CaptureWriter;

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
        let shared = Arc::new(RwLock::new(HostnameRegistry::new("dev", false)));
        shared
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "myservice");
        let router = Router::new(Arc::clone(&shared), proxied_request_verdict);

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

    /// NET-001, end to end: on a VM host the daemon sits on the gvproxy switch,
    /// so an own-address box's `<name>.min.internal` routes to the box itself —
    /// its lease, with the requested port translated through the ingress
    /// declaration's external→internal map — instead of the published guest
    /// loopback. The lease stand-in here is loopback so the test has a
    /// connectable upstream; what is under test is the routing form (lease +
    /// port map), not the address. A `HostNet` box on the same VM host still
    /// routes to host loopback at the raw requested port.
    #[tokio::test]
    async fn proxy_routes_min_internal_for_own_ip_session_on_vm_host() {
        // The box's internal listener (`spawn_backend` binds on demand), and
        // the published external port its ingress declaration forwards to it.
        let backend_port = spawn_backend().await;
        let lease = Ipv4Addr::LOCALHOST;
        let mut ports = BTreeMap::new();
        ports.insert(18080, backend_port);

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, true);
        reg.report_own_address(SessionId::nil(), "web", lease, ports);
        // A host-address box beside it: no lease, plain loopback.
        reg.register_host_net(SessionId::nil(), "static");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        // The URL's published port is translated to the internal one behind it;
        // the HostNet box's port is not translated.
        assert_eq!(
            router.route("web.min.internal:18080"),
            Some(SocketAddr::new(IpAddr::V4(lease), backend_port))
        );
        assert_eq!(
            router.route("static.min.internal:18080"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18080))
        );

        // Through the wire: a request naming the published port reaches the
        // box's internal listener.
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let routed = proxy_get(proxy_addr, "web.min.internal:18080").await;
        assert!(
            routed.contains("200 OK"),
            "expected the own-address box's published port to reach its internal listener, got: {routed}"
        );
    }

    /// A lease route carries only the ports the box's ingress declaration
    /// publishes (NET-001): a request naming any other port — an unrelated one
    /// or the internal port number behind the map — is refused with
    /// `403 Forbidden` and a warn line naming the host, the session, the port
    /// and the reason, instead of dialing a port the box's ingress gate would
    /// drop (a dropped SYN is a silent connect hang, not a refusal).
    #[tokio::test]
    async fn proxy_refuses_an_unpublished_port_and_logs_why() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, true);
        let mut ports = BTreeMap::new();
        ports.insert(18080, 8080);
        reg.report_own_address(SessionId::nil(), "web", Ipv4Addr::LOCALHOST, ports);
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        // The published external port routes; the internal number behind it and
        // an unrelated port route nowhere.
        assert_eq!(
            router.route("web.min.internal:18080"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );
        assert_eq!(
            router.route("web.min.internal:8080"),
            None,
            "the internal port behind the map is not itself addressable"
        );
        assert_eq!(router.route("web.min.internal:9000"), None);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let refused = proxy_get(proxy_addr, "web.min.internal:9000").await;
        assert!(
            refused.contains("403 Forbidden"),
            "expected the unpublished port to be refused, got: {refused}"
        );

        drop(_guard);
        let logged = buf.contents();
        assert!(
            logged.contains(r#"host="web.min.internal""#),
            "expected the refusal to name the host, got: {logged}"
        );
        assert!(
            logged.contains(r#"session="web""#),
            "expected the refusal to name the resolved session, got: {logged}"
        );
        assert!(
            logged.contains("port=9000"),
            "expected the refusal to name the blocked port, got: {logged}"
        );
        assert!(
            logged.contains("the box has not published this port"),
            "expected the unpublished-port reason, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="403 Forbidden""#),
            "expected the refusal to name the status it sent, got: {logged}"
        );
    }

    /// NET-002: the deprecated three-label name still routes to the same entry
    /// as the two-label one, and each request to it emits the deprecation info
    /// line naming the two-label form.
    #[test]
    fn legacy_local_zone_routes_with_deprecation() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        // The legacy form routes exactly as the two-label form does.
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(router.route("web.local.min.internal:8080"), Some(loopback));
        assert_eq!(router.route("web.min.internal:8080"), Some(loopback));

        drop(_guard);
        let logged = buf.contents();
        assert!(
            logged.contains(r#"two_label="web.min.internal""#),
            "expected the deprecation notice to name the two-label form, got: {logged}"
        );
        assert!(
            logged.contains("deprecated three-label hostname"),
            "expected the deprecation notice, got: {logged}"
        );
        assert!(
            !logged.contains(r#"two_label="web.local""#)
                && !logged.contains(r#"host="web.min.internal""#),
            "the notice is for the legacy request only, got: {logged}"
        );
    }

    /// NET-001: every refusal the proxy sends is logged with the host asked
    /// for (when the request carried one), the reason, and the status sent —
    /// so the daemon log, and the diagnostics bundle's tail of it, names every
    /// refused request. Covers the no-route, connect-failure and unparseable
    /// -head refusals; the head-timeout refusal shares the same helper and its
    /// 30-second bound makes it impractical to drive here.
    #[tokio::test]
    async fn proxy_refusal_is_logged_with_reason() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        // An address that was just released, so the connect refusal is
        // deterministic: the route resolves but nothing listens there anymore.
        let dead_port = {
            let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            held.local_addr().unwrap().port()
        };

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // Nothing owns the name: a no-route refusal.
        let no_route = proxy_get(proxy_addr, "ghost.min.internal").await;
        assert!(
            no_route.contains("502 Bad Gateway"),
            "expected a no-route gateway error, got: {no_route}"
        );

        // The box exists but nothing listens at the routed address: a
        // connect-failure refusal.
        let refused = proxy_get(proxy_addr, &format!("web.min.internal:{dead_port}")).await;
        assert!(
            refused.contains("502 Bad Gateway"),
            "expected a connect-failure gateway error, got: {refused}"
        );

        // A head no request can be parsed from: a bad-request refusal.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"this is not http\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let bad = String::from_utf8_lossy(&response).into_owned();
        assert!(
            bad.contains("400 Bad Request"),
            "expected a bad-request refusal, got: {bad}"
        );

        drop(_guard);
        let logged = buf.contents();

        // The no-route refusal names the host asked for and the reason.
        assert!(
            logged.contains(r#"host="ghost.min.internal""#),
            "expected the no-route refusal to name the host, got: {logged}"
        );
        assert!(
            logged.contains("no live box owns this hostname"),
            "expected the no-route reason, got: {logged}"
        );

        // The connect-failure refusal adds the session the host resolved to.
        assert!(
            logged.contains(r#"session="web""#),
            "expected the connect-failure refusal to name the resolved session, got: {logged}"
        );
        assert!(
            logged.contains("the upstream box refused the connection"),
            "expected the connect-failure reason, got: {logged}"
        );

        // The unparseable-head refusal carries its reason.
        assert!(
            logged.contains("unparseable request head"),
            "expected the bad-request reason, got: {logged}"
        );

        // Every refusal names the status it sent.
        assert!(
            logged.matches(r#"status="502 Bad Gateway""#).count() >= 2,
            "expected both gateway refusals to name the status, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="400 Bad Request""#),
            "expected the bad-request refusal to name the status, got: {logged}"
        );
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

        let failure = listener.expect_err("a bind to a held address must fail");
        assert!(
            failure.reported().contains("could not bind"),
            "the failure must name the bind failure, got: {}",
            failure.reported()
        );
        let logged = buf.contents();
        assert!(
            logged.is_empty(),
            "bind_listener must not log on failure; the caller owns the log line, got: {logged}"
        );
    }

    /// A real bind's failure carries its OS error's *kind*, so the busy-port
    /// predicate holds under both libcs this daemon runs as — glibc on a
    /// native host, musl in the `*-linux-musl` guest build, whose
    /// `EADDRINUSE` reads "Address in use" where glibc's reads "Address
    /// already in use". A predicate matching the rendered text never fires in
    /// a microVM, and a guest daemon whose default port is busy loops on the
    /// retry instead of relocating (NET-025).
    #[tokio::test]
    async fn busy_port_predicate_matches_the_error_kind_not_the_text() {
        // The two libcs' renderings of one `EADDRINUSE`: either must read as
        // busy, whatever text the daemon's libc put in the report.
        for text in ["Address already in use", "Address in use"] {
            let failure = BindFailure {
                reason: format!("the daemon could not bind 127.0.0.1:7654: {text}"),
                remedy: "free the listen address".to_owned(),
                kind: io::ErrorKind::AddrInUse,
            };
            assert!(
                failure.is_addr_in_use(),
                "an EADDRINUSE is busy whatever its libc renders, got: {text}"
            );
        }

        // And the other way round: a report whose text happens to carry the
        // busy phrase is not busy when the kernel said otherwise. An address
        // that cannot be assigned, or a permission the daemon lacks, is not
        // another daemon holding the port — moving the listener would hide it
        // (NET-021), so the failure must not read as busy.
        let not_busy = BindFailure {
            reason: "the daemon could not bind 192.0.2.1:7654: Cannot assign requested \
                 address — not Address already in use"
                .to_owned(),
            remedy: "free the listen address".to_owned(),
            kind: io::ErrorKind::AddrNotAvailable,
        };
        assert!(
            !not_busy.is_addr_in_use(),
            "a non-busy bind failure must not read as busy, whatever its text"
        );

        // The live path: a bind against a held address reports the kind the
        // kernel answered with, beside the text.
        let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = held.local_addr().unwrap();
        let failure = bind_listener(addr)
            .await
            .expect_err("a bind to a held address must fail");
        drop(held);
        assert_eq!(
            failure.kind,
            io::ErrorKind::AddrInUse,
            "a held listen address must report EADDRINUSE, got: {:?}",
            failure.kind
        );
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

    // -----------------------------------------------------------------------
    // Property test over the request-head parser. The first consumer of the
    // workspace's `proptest` dependency (the tiered spec's T1 lane): whatever
    // the method, path, header casing, or surrounding whitespace, the parser
    // reads back exactly the authority the head was built with — `CONNECT`
    // from its request line, any other method from its `Host:` header — and
    // classifies the kind to match.
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn property_check_runs(
            host in r"[a-z0-9-]{1,8}(\.[a-z0-9-]{1,8}){0,3}",
            port in any::<u16>(),
            method in prop::sample::select(vec![
                "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
            ]),
            path in r"/[!-~]{0,16}",
            header_name in prop::sample::select(vec!["Host", "host", "HOST", "hOsT"]),
            pad in prop::sample::select(vec!["", " ", "  ", "\t"]),
        ) {
            let authority = format!("{host}:{port}");

            let connect_head = format!("CONNECT {authority} HTTP/1.1\r\n\r\n");
            let connect = parse_request(connect_head.as_bytes())
                .expect("a CONNECT head carrying an authority must parse");
            prop_assert!(matches!(connect.kind, RequestKind::Connect));
            prop_assert_eq!(connect.authority, authority.as_str());

            let forward_head = format!(
                "{method} {path} HTTP/1.1\r\n{header_name}:{pad}{authority}{pad}\r\n\r\n"
            );
            let forward = parse_request(forward_head.as_bytes())
                .expect("a forward head carrying a Host header must parse");
            prop_assert!(matches!(forward.kind, RequestKind::Forward));
            prop_assert_eq!(forward.authority, authority);
        }
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

        let mut reg = HostnameRegistry::new("dev", false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

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

    // -----------------------------------------------------------------------
    // The proxy is plain HTTP only (NET-109): the HTTPS/mTLS reverse proxy
    // that once terminated TLS on the port above the egress proxy is retired,
    // so the one listener routes plain HTTP and answers a TLS handshake with
    // no TLS bytes at all — there is no certificate to present and no
    // termination behind the port in any build.
    // -----------------------------------------------------------------------

    /// A plain `GET` routes through `serve` to its PTask, and a TLS
    /// ClientHello to the same listener draws no response bytes: the proxy
    /// serves HTTP only, so no client can negotiate TLS with it (NET-109).
    #[tokio::test]
    async fn proxy_serves_http_only() {
        let backend_port = spawn_backend().await;
        let mut reg = HostnameRegistry::new("dev", false);
        reg.register_host_net(SessionId::nil(), "mysvc");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // HTTP: a plain request routes to the registered PTask and returns
        // its response.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let authority = format!("mysvc.min.internal:{backend_port}");
        client
            .write_all(format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("200 OK"),
            "expected the plain-HTTP request to route, got: {response_str}"
        );

        // No TLS: a ClientHello is just bytes that never end an HTTP head.
        // Half-close the write side so `read_head` hits EOF, and nothing may
        // come back — no ServerHello, no alert, not even a status line,
        // because no build puts a TLS terminator behind the port.
        let mut tls_client = TcpStream::connect(proxy_addr).await.unwrap();
        tls_client
            .write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
            .await
            .unwrap();
        tls_client.shutdown().await.unwrap();
        let mut tls_response = Vec::new();
        tls_client.read_to_end(&mut tls_response).await.unwrap();
        assert!(
            tls_response.is_empty(),
            "the proxy must serve plain HTTP only; a TLS handshake must draw no \
             response bytes, got: {:?}",
            String::from_utf8_lossy(&tls_response)
        );
    }

    // -----------------------------------------------------------------------
    // NET-135: the proxy routes HTTP/1.1 requests and CONNECT tunnels only.
    // -----------------------------------------------------------------------

    /// NET-135's verify line: a connection that opens with the HTTP/2
    /// prior-knowledge preface is closed at once — no response bytes, because
    /// there is no HTTP/1.1 exchange inside it to answer and tunneling one
    /// would bypass the routing core's refusals entirely — and the closure is
    /// logged as a refusal. A plain HTTP/1.1 request on the same listener
    /// still routes.
    #[tokio::test]
    async fn hostname_proxy_closes_h2_preface() {
        let backend_port = spawn_backend().await;
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let (buf, guard) = capture_logs();

        // The prior-knowledge preface (RFC 9113 §3.4), as one write: the head
        // the proxy buffers ends at the `\r\n\r\n` inside it.
        let mut h2 = TcpStream::connect(proxy_addr).await.unwrap();
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        h2.read_to_end(&mut response).await.unwrap();
        assert!(
            response.is_empty(),
            "an HTTP/2 prior-knowledge connection must draw no response bytes, got {:?}",
            String::from_utf8_lossy(&response)
        );

        drop(guard);
        let logged = buf.contents();
        assert!(
            logged.contains("the proxy routes HTTP/1.1 requests and CONNECT tunnels only"),
            "expected the h2 closure to be logged as a refusal, got: {logged}"
        );

        // The same listener still routes HTTP/1.1: the proxy serves 1.1, it
        // just neither speaks nor tunnels h2.
        let routed = proxy_get(proxy_addr, &format!("web.min.internal:{backend_port}")).await;
        assert!(
            routed.contains("200 OK"),
            "a plain HTTP/1.1 request must still route after an h2 preface, got: {routed}"
        );
    }

    /// NET-135's sub-requirement, end to end: a request offering `Upgrade: h2c`
    /// is routed as the HTTP/1.1 request it is — the `Upgrade: h2c` header, its
    /// `HTTP2-Settings` header, and the `Connection` tokens naming them are
    /// stripped before the head is replayed upstream, while every other header
    /// arrives verbatim. An upgrade the requirement does not name (a websocket)
    /// passes through untouched.
    #[tokio::test]
    async fn hostname_proxy_strips_h2c_upgrade() {
        let (h2c_port, h2c_received) = spawn_recording_backend().await;
        let (ws_port, ws_received) = spawn_recording_backend().await;

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // The h2c offer in RFC 7540 §3.2's wire shape, with an unrelated
        // header riding along.
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: web.min.internal:{h2c_port}\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAAA\r\n\
             X-Carried: along\r\n\
             \r\n"
        );
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "expected the stripped request to route, got: {}",
            String::from_utf8_lossy(&response)
        );

        let head = String::from_utf8(h2c_received.lock().unwrap().clone()).unwrap();
        assert!(
            head.contains("GET / HTTP/1.1\r\nHost: web.min.internal:"),
            "expected the request line and host header verbatim, got: {head}"
        );
        assert!(
            head.contains("X-Carried: along\r\n"),
            "expected the headers the requirement does not name to arrive verbatim, got: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("h2c"),
            "the h2c offer must not reach the upstream, got: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("http2-settings"),
            "the HTTP2-Settings header must not reach the upstream, got: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("connection"),
            "the Connection tokens naming the stripped headers must go with them, got: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("upgrade"),
            "the stripped upgrade must not be named anywhere in the head, got: {head}"
        );

        // An upgrade the requirement does not name: byte-for-byte passthrough.
        let request = format!(
            "GET /chat HTTP/1.1\r\n\
             Host: web.min.internal:{ws_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             \r\n"
        );
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "expected the websocket upgrade to route, got: {}",
            String::from_utf8_lossy(&response)
        );
        let passthrough = String::from_utf8(ws_received.lock().unwrap().clone()).unwrap();
        assert!(
            passthrough.contains("Upgrade: websocket\r\nConnection: Upgrade\r\n"),
            "an upgrade that is not h2c must pass through untouched, got: {passthrough}"
        );
        assert!(
            passthrough.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"),
            "expected the websocket headers verbatim, got: {passthrough}"
        );

        // An offer naming h2c beside another protocol keeps the other
        // protocol and the `Connection` tokens that are not h2c's: the strip
        // takes only what the requirement names.
        let mixed = strip_h2c_upgrade(
            b"GET / HTTP/1.1\r\nConnection: Upgrade, keep-alive\r\nUpgrade: websocket, h2c\r\n\r\n",
        );
        let mixed = String::from_utf8_lossy(&mixed);
        assert!(
            mixed.contains("Upgrade: websocket\r\n"),
            "expected the non-h2c offer to survive the strip, got: {mixed}"
        );
        assert!(
            mixed.contains("Connection: Upgrade, keep-alive\r\n"),
            "expected the surviving offer's Connection token to stay, got: {mixed}"
        );
        assert!(
            !mixed.to_ascii_lowercase().contains("h2c"),
            "the h2c token must go from a mixed offer, got: {mixed}"
        );

        // A head with no h2c is borrowed, not rebuilt: passthrough is
        // byte-for-byte.
        let plain = b"GET / HTTP/1.1\r\nHost: web\r\n\r\nextra";
        assert_eq!(strip_h2c_upgrade(plain).as_ref(), plain.as_slice());
    }

    // -----------------------------------------------------------------------
    // Refusals the switch would make too (NET-069 to NET-071): every request
    // is put to the verdict the relay's gates apply, before the proxy dials
    // anything — a hostname-routing surface with no reach a direct connection
    // would not have, whose refusals carry the same rule names a direct
    // connection's drops do.
    // -----------------------------------------------------------------------

    /// The caller's lease stand-in: a loopback address the test can bind a
    /// client connection from, distinct from the target's. On the switch the
    /// same move is a real lease — the address the peer of a proxied request
    /// is, and the key the registry's lease-to-session map names the caller
    /// by (NET-070).
    const CALLER_LEASE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    /// A second caller's lease stand-in.
    const OTHER_LEASE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

    /// NET-069's verify line: a proxied request to a port the target box did
    /// not declare is refused with the same refusal a direct connection gets.
    /// The two halves of the claim, from one declaration: the relay's own gate
    /// for it admits exactly the ports it publishes (the port a connection
    /// terminates on) and refuses anything else, and the proxy routes a
    /// request naming a published port to exactly such a port while refusing
    /// every other one with the same rule the gate's drop logs.
    #[tokio::test]
    async fn proxy_undeclared_port_refused_like_direct() {
        let backend_port = spawn_backend().await;

        // The target's declaration, as launch records it: one published TCP
        // port forwarding to the box's own port (the real listener here).
        let policy = SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy {
                port_mappings: vec![PortMapping {
                    external_port: 18080,
                    internal_port: backend_port,
                    proto: IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
        };

        // The registry, as the session actor and the attach path fill it: the
        // own-address box on a VM host reports its lease with the applied
        // external→internal map. Loopback stands in for the lease, as the
        // NET-001 test does.
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, true);
        reg.report_own_address(
            SessionId::nil(),
            "web",
            Ipv4Addr::LOCALHOST,
            BTreeMap::from([(18080, backend_port)]),
        );
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // The direct half: the relay's own gate for the same declaration —
        // the shared `declared_ingress_ports` derivation — admits the port
        // the declaration's connections terminate on, and refuses any other.
        let gate = SessionGate::for_session("web".to_string(), &policy, SwitchSubnet::default());
        assert!(
            gate.admits_direct_tcp(backend_port),
            "the declaration's own port is the one a direct connection terminates on"
        );
        assert!(
            !gate.admits_direct_tcp(9000),
            "the target's gate refuses a direct connection to an undeclared port"
        );

        let (buf, guard) = capture_logs();

        // The published port routes to the box's own port: the reach a direct
        // connection has.
        let routed = proxy_get(proxy_addr, "web.min.internal:18080").await;
        assert!(
            routed.contains("200 OK"),
            "expected the declared port to route, got: {routed}"
        );

        // The undeclared port is refused with the same refusal.
        let refused = proxy_get(proxy_addr, "web.min.internal:9000").await;
        assert!(
            refused.contains("403 Forbidden"),
            "expected the undeclared port to be refused, got: {refused}"
        );

        drop(guard);
        let logged = buf.contents();
        assert!(
            logged.contains(r#"session="web""#),
            "expected the refusal to name the target, got: {logged}"
        );
        assert!(
            logged.contains("port=9000"),
            "expected the refusal to name the undeclared port, got: {logged}"
        );
        assert!(
            logged.contains(&format!("rule_matched=\"{NO_INGRESS_MAPPING_RULE}\"")),
            "the proxied refusal must carry the same rule a direct connection's \
             drop logs, got: {logged}"
        );
        assert!(
            logged.contains("direction=ingress"),
            "expected the refusal to carry the ingress direction, got: {logged}"
        );
        assert!(
            logged.contains("the box has not published this port"),
            "expected the undeclared-port reason, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="403 Forbidden""#),
            "expected the refusal to name the status it sent, got: {logged}"
        );
    }

    /// NET-070's verify line: a request through the hostname proxy from a
    /// caller whose egress rules deny the target is refused — put to the same
    /// pure verdict the caller's own outbound frames meet on the relay,
    /// before the proxy dials anything. The denial is the caller's, not the
    /// request's: a caller whose rules admit the target sends the same
    /// request and routes.
    #[tokio::test]
    async fn proxy_caller_egress_denied() {
        let backend_port = spawn_backend().await;
        let subnet = SwitchSubnet::default();
        let web = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let client = SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let allowed = SessionId::parse_str("00000000-0000-0000-0000-000000000003").unwrap();

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, true);
        // The target: an own-address box publishing one port.
        reg.report_own_address(
            web,
            "web",
            Ipv4Addr::LOCALHOST,
            BTreeMap::from([(18080, backend_port)]),
        );
        // The callers, as the session actor records them and the attach path
        // joins them: compiled egress rules by stable id, then the lease that
        // names them.
        for (id, name, lease, egress) in [
            (client, "client", CALLER_LEASE, egress_denying_the_target()),
            (
                allowed,
                "allowed",
                OTHER_LEASE,
                egress_allowing_the_target(),
            ),
        ] {
            reg.register_caller(
                id,
                name,
                crate::net::switch::compiled_egress(Some(&egress), subnet),
            );
            reg.report_own_address(id, name, lease, BTreeMap::new());
        }
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let (buf, guard) = capture_logs();

        // The caller whose rules deny the target: refused before the proxy
        // dialed anything — no connect error is named, only the rule.
        let refused = proxy_get_from(proxy_addr, CALLER_LEASE, "web.min.internal:18080").await;
        assert!(
            refused.contains("403 Forbidden"),
            "expected the denied caller's request to be refused, got: {refused}"
        );

        // The caller whose rules admit the target: the same request routes.
        let routed = proxy_get_from(proxy_addr, OTHER_LEASE, "web.min.internal:18080").await;
        assert!(
            routed.contains("200 OK"),
            "expected the allowed caller's same request to route, got: {routed}"
        );

        drop(guard);
        let logged = buf.contents();
        assert!(
            logged.contains(r#"caller="client""#),
            "expected the refusal to name the caller, got: {logged}"
        );
        assert!(
            logged.contains(r#"session="web""#),
            "expected the refusal to name the target, got: {logged}"
        );
        assert!(
            logged.contains("port=18080"),
            "expected the refusal to name the requested port, got: {logged}"
        );
        assert!(
            logged.contains("rule_matched=\"egress-denied-subnet\""),
            "expected the refusal to carry the rule the caller's own egress drop \
             logs, got: {logged}"
        );
        assert!(
            logged.contains("direction=egress"),
            "expected the refusal to carry the egress direction, got: {logged}"
        );
        assert!(
            logged.contains("remote_addr=\"127.0.0.1:18080\""),
            "expected the refusal to name the refused target, got: {logged}"
        );
        assert!(
            logged.contains("the caller's egress policy denies this target"),
            "expected the caller-egress reason, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="403 Forbidden""#),
            "expected the refusal to name the status it sent, got: {logged}"
        );
        assert!(
            !logged.contains("the upstream box refused the connection"),
            "the refusal must happen before the dial, got: {logged}"
        );
    }

    // -----------------------------------------------------------------------
    // NET-071's property (T1): for every network mode, every rule set, and
    // every request, the hostname proxy's verdict equals the direct
    // connection's verdict — the caller's egress half decided by the same
    // pure frame verdict the relay applies (asked here about a real IPv4+TCP
    // frame built byte by byte), the target's ingress half by the relay's own
    // gate over the same declaration.
    // -----------------------------------------------------------------------

    /// The network modes a request's target can stand in (NET-071 ranges over
    /// host-address and own-address targets alike).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TargetMode {
        /// A `HostNet` box: no ingress declaration (launch validation rejects
        /// one on this mode), no gate, direct connections ungated.
        HostAddress,
        /// An `OwnIp` box on a VM host: the daemon is on the switch, so the
        /// name routes to the box's lease and the request's port is
        /// translated through the declaration's map.
        OwnAddressOnSwitch,
        /// An `OwnIp` box on a native host: the published-loopback model —
        /// the request's port is the published external one, and the
        /// session's own registration carries the declared set.
        OwnAddressNative,
    }

    /// The caller's egress stances the property ranges over: each is a
    /// distinct verdict the pure frame verdict returns for an IPv4 TCP frame
    /// to the target — two admits and the three drops such a frame can earn
    /// (every IPv4 drop a TCP frame can take).
    #[derive(Clone, Copy, Debug)]
    enum CallerStance {
        /// No egress section: allow-all.
        NoDeclaration,
        /// An allow list naming the target's address.
        AllowsTheTarget,
        /// A deny list naming the target's address.
        DeniesTheTarget,
        /// An allow list naming nothing.
        AllowsNothing,
        /// An allow list of protocols that names no TCP.
        DeclaresUdpOnly,
    }

    /// The egress policy of one stance, as launch records it.
    fn stance_egress(stance: CallerStance) -> EgressPolicy {
        let target = "127.0.0.1/32";
        match stance {
            CallerStance::NoDeclaration => EgressPolicy::default(),
            CallerStance::AllowsTheTarget => EgressPolicy {
                allow_subnets: Some(vec![target.to_string()]),
                ..EgressPolicy::default()
            },
            CallerStance::DeniesTheTarget => EgressPolicy {
                deny_subnets: Some(vec![target.to_string()]),
                ..EgressPolicy::default()
            },
            CallerStance::AllowsNothing => EgressPolicy {
                allow_subnets: Some(vec![]),
                ..EgressPolicy::default()
            },
            CallerStance::DeclaresUdpOnly => EgressPolicy {
                allow_protocols: Some(vec![IpProto::Udp]),
                ..EgressPolicy::default()
            },
        }
    }

    /// A minimal Ethernet II + IPv4 + TCP frame to `dst:port`, built byte by
    /// byte in the shape the relay's egress leg reads: 14-byte Ethernet
    /// header, EtherType 0x0800, minimum IPv4 header with protocol 6 and the
    /// destination at offset 16, and the L4 destination port behind it.
    fn tcp_frame_to(dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut frame = [0u8; 14 + 20 + 4];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[16..20].copy_from_slice(&dst.octets());
        ip[20..22].copy_from_slice(&port.to_be_bytes());
        frame.to_vec()
    }

    proptest! {
        /// NET-071's verify line: the proxy's verdict for a request equals
        /// the direct connection's verdict for it — the caller's egress rules
        /// applied to a frame to the target, then the target's declared
        /// ports — whatever the target's network mode, the caller's rule set,
        /// and the requested port are. The addresses are loopback stand-ins
        /// (the target's lease and the caller's, as the tests above use them);
        /// the verdicts are pure over them, so the property ranges over the
        /// modes, rule sets and requests the property names.
        #[test]
        fn proxy_parity_across_network_modes(
            mode in prop::sample::select(vec![
                TargetMode::HostAddress,
                TargetMode::OwnAddressOnSwitch,
                TargetMode::OwnAddressNative,
            ]),
            stance in prop::sample::select(vec![
                CallerStance::NoDeclaration,
                CallerStance::AllowsTheTarget,
                CallerStance::DeniesTheTarget,
                CallerStance::AllowsNothing,
                CallerStance::DeclaresUdpOnly,
            ]),
            // The target's published ports: bit i set publishes external
            // port 1024+i forwarding to internal port 8000+i.
            published in 0u8..=15,
            // Whether the request comes from a box — whose egress rules the
            // request is put to — or from a host-side peer, whose egress is
            // ungated here exactly as its direct connections are.
            from_a_box in prop::bool::ANY,
            // The requested port: one of the publishable externals, one of the
            // internal ports behind them, or an unrelated one.
            request_port in prop::sample::select(vec![
                1024u16, 1025, 1026, 1027, 8000, 8001, 8002, 8003, 9000,
            ]),
        ) {
            let subnet = SwitchSubnet::default();
            let mappings: Vec<PortMapping> = (0..4u8)
                .filter(|i| published & (1 << i) != 0)
                .map(|i| PortMapping {
                    external_port: 1024 + u16::from(i),
                    internal_port: 8000 + u16::from(i),
                    proto: IpProto::Tcp,
                })
                .collect();
            // The target's declaration. A host-address box cannot carry one;
            // an own-address box carries exactly its mappings (an empty one
            // is the deny-all default).
            let target_policy = SessionPolicy {
                egress: None,
                ingress: (mode != TargetMode::HostAddress).then(|| IngressPolicy {
                    port_mappings: mappings.clone(),
                    dynamic_allowed_range: None,
                    dynamic_ingress: None,
                }),
            };
            // The registry, as the session actor and the attach path fill it
            // for each mode. Loopback stands in for the target's lease.
            let target_lease = Ipv4Addr::LOCALHOST;
            let applied: BTreeMap<u16, u16> = mappings
                .iter()
                .map(|m| (m.external_port, m.internal_port))
                .collect();
            let target = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
            let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, mode == TargetMode::OwnAddressOnSwitch);
            match mode {
                TargetMode::HostAddress => {
                    reg.register_host_net(target, "web");
                }
                TargetMode::OwnAddressOnSwitch => {
                    reg.report_own_address(target, "web", target_lease, applied);
                }
                TargetMode::OwnAddressNative => {
                    reg.report_own_address(target, "web", target_lease, applied);
                    // The session's own registration carries the declared
                    // set, as `Session::register_hostname` passes it.
                    reg.register_own_ip(
                        target,
                        "web",
                        declared_request_ports(Some(&target_policy)),
                    );
                }
            }
            // The caller, when the request is a box's: its compiled egress
            // rules and its lease, as the session actor records them.
            let caller = from_a_box.then(|| {
                let client = SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
                let egress = crate::net::switch::compiled_egress(
                    Some(&SessionPolicy {
                        egress: Some(stance_egress(stance)),
                        ingress: None,
                    }),
                    subnet,
                );
                reg.register_caller(client, "client", egress);
                reg.report_own_address(client, "client", CALLER_LEASE, BTreeMap::new());
                reg.caller_at(CALLER_LEASE)
                    .expect("the reported lease names the registered caller")
            });

            let route = reg
                .resolve("web.min.internal")
                .expect("the target's name resolves");

            // The direct connection's verdict: the caller's egress half on a
            // real frame to the target, decided by the same pure verdict the
            // relay applies — over the caller's own compiled rules, the ones
            // the registry hands the proxy — then the target's ingress half
            // by its declared ports. A host-side caller has no egress half:
            // its direct connections are ungated, so its proxied requests
            // are too.
            let mut expected = None;
            if let Some(caller) = &caller {
                let frame = tcp_frame_to(route.address(), request_port);
                if let FrameVerdict::Drop(reason) =
                    egress::verdict(&egress::summarize(&frame), caller.egress())
                {
                    expected = Some(ProxiedRequest::Refused(Refusal {
                        rule: reason.rule(),
                        direction: Direction::Egress,
                        other: Some(SocketAddr::V4(SocketAddrV4::new(
                            route.address(),
                            request_port,
                        ))),
                    }));
                }
            }
            let expected = expected.unwrap_or_else(|| match route.upstream(request_port) {
                Some(upstream) => ProxiedRequest::Forward(upstream),
                None => ProxiedRequest::Refused(Refusal {
                    rule: NO_INGRESS_MAPPING_RULE,
                    direction: Direction::Ingress,
                    other: caller.as_ref().map(|caller| {
                        SocketAddr::V4(SocketAddrV4::new(caller.lease(), request_port))
                    }),
                }),
            });

            let observed = proxied_request_verdict(caller.as_ref(), &route, request_port);
            prop_assert_eq!(
                &observed, &expected,
                "the proxy's verdict must equal the direct connection's"
            );

            // No reach a direct connection would not have: where the target
            // has a gate, the port the forwarded connection terminates on is
            // one its own declaration admits.
            if mode != TargetMode::HostAddress
                && let ProxiedRequest::Forward(upstream) = &observed
                && let SocketAddr::V4(up) = upstream
            {
                let internal = match mode {
                    TargetMode::OwnAddressOnSwitch => up.port(),
                    TargetMode::OwnAddressNative => {
                        // The forwarder carries the published external port;
                        // the connection terminates on the internal one.
                        mappings
                            .iter()
                            .find(|m| m.external_port == up.port())
                            .map(|m| m.internal_port)
                            .expect("a forwarded request names a published port")
                    }
                    TargetMode::HostAddress => unreachable!("excluded above"),
                };
                let gate = SessionGate::for_session("web".to_string(), &target_policy, subnet);
                prop_assert!(
                    gate.admits_direct_tcp(internal),
                    "the proxy forwarded to port {internal}, which the target's gate refuses"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers.
    // -----------------------------------------------------------------------

    /// Installs a capturing log subscriber for the calling test, returning the
    /// buffer the lines land in. Drop the guard before reading it.
    fn capture_logs() -> (CaptureWriter, tracing::subscriber::DefaultGuard) {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }

    /// Spawns a loopback backend that records every request head it receives
    /// and answers each connection with `200 OK`, returning the port it
    /// listens on and the shared buffer the heads land in.
    async fn spawn_recording_backend() -> (u16, Arc<Mutex<Vec<u8>>>) {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = backend.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        (port, received)
    }

    /// Drives the proxy with a `GET` carrying `Host: <authority>`, the
    /// connection bound to `from` so the proxy sees that address as the
    /// request's caller — the loopback stand-in for a box's switch lease.
    async fn proxy_get_from(proxy_addr: SocketAddr, from: Ipv4Addr, authority: &str) -> String {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(IpAddr::V4(from), 0)).unwrap();
        let mut client = socket.connect(proxy_addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// A caller's egress declaration that denies exactly the target's address
    /// (the loopback stand-in the test's boxes live at).
    fn egress_denying_the_target() -> SessionPolicy {
        SessionPolicy {
            egress: Some(EgressPolicy {
                deny_subnets: Some(vec!["127.0.0.1/32".to_string()]),
                ..EgressPolicy::default()
            }),
            ingress: None,
        }
    }

    /// A caller's egress declaration that allows the target's address: an
    /// allow list naming it.
    fn egress_allowing_the_target() -> SessionPolicy {
        SessionPolicy {
            egress: Some(EgressPolicy {
                allow_subnets: Some(vec!["127.0.0.1/32".to_string()]),
                ..EgressPolicy::default()
            }),
            ingress: None,
        }
    }
}
