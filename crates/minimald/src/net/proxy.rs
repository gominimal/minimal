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

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
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

/// How long the proxy waits for the upstream box to accept the TCP dial before
/// answering `504`. A dead lease drops the SYN silently, so without this bound
/// the client would wait out the kernel's SYN retries (about two minutes).
const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

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
/// The bind is the platform default [`TcpListener::bind`] makes: `SO_REUSEADDR`
/// on Unix, and never `SO_REUSEPORT`. On Linux, `SO_REUSEADDR` never lets a
/// second socket listen on an address:port an active listener holds — a port
/// another daemon is bound and listening on is still refused with `EADDRINUSE`,
/// as the surfaced error the caller's report carries — so its one effect is
/// that a restart can rebind over the `TIME_WAIT` sockets the previous run's
/// accepted connections left, which is how a native daemon restarted in place
/// keeps [`DEFAULT_EGRESS_PROXY_PORT`], the documented port its recipes point
/// `HTTP(S)_PROXY` at, instead of failing the rebind and silently moving off
/// it. `SO_REUSEPORT` is the licence to answer beside a live holder and is never
/// asked for. The rule that two VMs never shadow one host port (NET-059) is
/// not this bind's to carry: a microVM daemon binds inside its guest's own
/// netns, where the two never meet, and the one port they do share — the
/// host-loopback publication the walk in `server::drive_proxy_until_serving`
/// takes — is minvmd's forwarded-port bind (#1814).
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

    // An absolute-form `https://` target asks the proxy to reach the origin
    // over TLS, but the upstream leg is a plain TCP connection: forwarding it
    // would send the request in plaintext to a port expecting TLS. Refused;
    // a client tunnels TLS through the proxy with `CONNECT` instead.
    if is_https_absolute_form(&head) {
        log_refusal(
            None,
            "absolute-form https:// target; use CONNECT to tunnel TLS",
            "400 Bad Request",
        );
        return write_status(&mut client, "400 Bad Request").await;
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
            return write_refusal_status(&mut client, "403 Forbidden", reason).await;
        }
    };

    let mut upstream = match tokio::time::timeout(
        UPSTREAM_DIAL_TIMEOUT,
        TcpStream::connect(upstream_addr),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(error)) => {
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
        Err(_elapsed) => {
            tracing::warn!(
                component = "dns-proxy",
                host = %host,
                session = route.session(),
                upstream = %upstream_addr,
                reason = "the upstream box did not answer within the dial timeout",
                status = "504 Gateway Timeout",
                "refused a proxied request"
            );
            return write_status(&mut client, "504 Gateway Timeout").await;
        }
    };

    match kind {
        // Tunnel: acknowledge the CONNECT, then splice raw bytes both ways.
        RequestKind::Connect => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        // Forward proxy: replay the buffered head so the upstream sees the
        // original request, then relay the exchange. An h2c upgrade offer is
        // stripped first, so the request is routed as the HTTP/1.1 request it
        // is and the upstream cannot answer a protocol switch the proxy cannot
        // splice (NET-135). An absolute-form request target is then rewritten
        // to origin-form, with `Host:` set to its authority (RFC 9112 §3.2.2):
        // the upstream is an origin server, and many reject the absolute URI
        // verbatim.
        //
        // The proxy routes one request per client connection: a keep-alive
        // connection spliced as raw bytes would carry every later request to
        // the first request's upstream, whatever box its `Host:` names, and
        // leak it (and the response) across boxes. So only this request's
        // head and its own body reach the upstream — the body delimited by
        // its framing, any bytes after it discarded — and both heads carry
        // `Connection: close`, so the client opens a new proxy connection for
        // its next request. An upgrade request (a websocket) keeps its
        // `Connection: Upgrade`, and becomes a raw tunnel to the box it named
        // only when that box answers `101 Switching Protocols`.
        RequestKind::Forward => {
            // A bare-LF line ending in the header block is refused: the proxy
            // ends the head at the first `\r\n\r\n`, and an upstream that
            // tolerates bare LF could end it earlier and read a second request
            // out of what the proxy took for one head.
            if has_bare_lf(head.get(..head_end(&head)).unwrap_or_default()) {
                log_refusal(
                    Some(host),
                    "the request head has a bare-LF line ending",
                    "400 Bad Request",
                );
                return write_status(&mut client, "400 Bad Request").await;
            }
            let stripped = strip_h2c_upgrade(&head);
            let rewritten = rewrite_absolute_form(&stripped);
            let lines = head_lines(rewritten.get(..head_end(&rewritten)).unwrap_or_default());
            let is_upgrade = carries_upgrade(&lines);
            let Some(body) = request_body(&lines) else {
                log_refusal(
                    Some(host),
                    "the request body's framing cannot be delimited",
                    "400 Bad Request",
                );
                return write_status(&mut client, "400 Bad Request").await;
            };
            let head = if is_upgrade {
                rewritten.into_owned()
            } else {
                set_connection_close(&rewritten).into_owned()
            };
            let (head, buffered) = head.split_at(head_end(&head));
            upstream.write_all(head).await?;
            relay_exchange(&mut client, &mut upstream, buffered, body, is_upgrade).await?;
        }
    }

    Ok(())
}

/// Parses the authority to route to out of a buffered HTTP request head. A
/// `CONNECT` request carries the authority in its request line; any other method
/// carries it in an absolute-form target's URI authority when it has one, and
/// otherwise in the `Host:` header (matched case-insensitively). Returns `None`
/// for a head with no usable authority. Only the head is decoded as text: body
/// bytes the head read buffered after the end-of-head marker can be anything.
fn parse_request(head: &[u8]) -> Option<ParsedRequest<'_>> {
    let head_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |at| at + 4);
    let text = std::str::from_utf8(head.get(..head_end)?).ok()?;
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

    // Absolute-form request target (RFC 9112 §3.2.2): the request line
    // carries a full URI (`GET http://host:port/path HTTP/1.1`). The URI
    // authority takes precedence over any `Host:` header (RFC 9112 §3.2.3).
    let path = parts.next()?;
    let authority = if let Some((auth, _)) = split_absolute_form(path) {
        auth
    } else {
        lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("host")
                .then(|| value.trim())
        })?
    };
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

/// Whether the request line carries an absolute-form `https://` target, which
/// the proxy refuses: its upstream leg is plain TCP, never TLS. The scheme
/// matches case-insensitively (RFC 3986 §3.1).
fn is_https_absolute_form(head: &[u8]) -> bool {
    const SCHEME: &str = "https://";
    head.split(|&b| b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|target| target.get(..SCHEME.len()))
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(SCHEME))
}

/// Splits an absolute-form request target (`http://authority/path?query`)
/// into its authority and the rest, or `None` for any other form. Only the
/// `http` scheme is split: an `https://` target is refused before routing
/// ([`is_https_absolute_form`]). The scheme matches case-insensitively
/// (RFC 3986 §3.1). The authority ends at the first
/// `/`, `?`, or `#` (RFC 3986 §3.2) and is returned as `host[:port]`, without
/// any `userinfo@`; the rest keeps the path and query, minus any fragment,
/// which is never sent.
fn split_absolute_form(target: &str) -> Option<(&str, &str)> {
    const SCHEME: &str = "http://";
    let rest = target
        .get(..SCHEME.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(SCHEME))
        .and_then(|_| target.get(SCHEME.len()..))?;
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, rest) = rest.split_at(authority_end);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    Some((authority, rest))
}

/// Rewrites an absolute-form request line to origin-form (RFC 9112 §3.2.2):
/// `GET http://host:port/path?query HTTP/1.1` becomes `GET /path?query HTTP/1.1`.
/// The scheme and authority are dropped from the line; the path (and any query)
/// is kept, so the upstream origin server receives the form it expects. The
/// received `Host:` header is replaced by one carrying the target's authority,
/// added when the request had none (RFC 9112 §3.2.2), so the upstream sees the
/// host the request was routed to. Every other header and any buffered body
/// bytes pass through verbatim; the connection's persistence is the forward
/// path's to set, not the rewrite's. A head with any other target is returned
/// as is.
fn rewrite_absolute_form(head: &[u8]) -> Cow<'_, [u8]> {
    let head_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |at| at + 4);
    let (headers, rest) = head.split_at(head_end);

    let Some(request_line_end) = headers.iter().position(|&b| b == b'\n') else {
        return Cow::Borrowed(head);
    };
    let request_line = &headers[..request_line_end + 1];

    // `METHOD SP http://authority/path?query SP HTTP/1.1`
    let Some(text) = std::str::from_utf8(request_line).ok() else {
        return Cow::Borrowed(head);
    };
    let mut parts = text.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Cow::Borrowed(head);
    };

    let Some((authority, origin_target)) = split_absolute_form(target) else {
        return Cow::Borrowed(head);
    };

    let mut out = Vec::with_capacity(head.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    // An empty path is sent as `/` (RFC 9112 §3.2.1), ahead of any query.
    if !origin_target.starts_with('/') {
        out.push(b'/');
    }
    out.extend_from_slice(origin_target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");
    for line in head_lines(&headers[request_line_end + 1..]) {
        if header_parts(line).is_some_and(|(name, _)| is_header(name, b"host")) {
            continue; // Replaced by the target's authority above.
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
///
/// Both slices are cut at `colon`, which `position` returned as an index inside
/// `line`, so neither range can be out of bounds.
#[expect(
    clippy::indexing_slicing,
    reason = "cut at `colon`, an index `position` found inside `line`"
)]
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

/// Whether the head carries any `Upgrade` header (a protocol upgrade request
/// such as a websocket). The request line is not a header and is not consulted.
fn carries_upgrade(lines: &[&[u8]]) -> bool {
    lines
        .iter()
        .skip(1)
        .any(|line| header_parts(line).is_some_and(|(name, _value)| is_header(name, b"upgrade")))
}

/// Rewrites a buffered HTTP head's `Connection` header to `close`: drops every
/// other token (`keep-alive` and any header-name tokens) and adds the header
/// when it is absent. Bytes after the end-of-head marker are preserved
/// untouched. The head is borrowed when no rewrite is needed (the `Connection`
/// header is already `close` alone).
fn set_connection_close(head: &[u8]) -> Cow<'_, [u8]> {
    let (headers, rest) = head.split_at(head_end(head));
    let lines = head_lines(headers);

    // Whether the head already carries `Connection: close` alone.
    let mut already_close = false;
    for line in &lines {
        if let Some((name, value)) = header_parts(line)
            && is_header(name, b"connection")
        {
            let tokens: Vec<&[u8]> = value_tokens(value).collect();
            if matches!(tokens.as_slice(), [only] if is_token(only, b"close")) {
                already_close = true;
            }
            break;
        }
    }
    if already_close {
        return Cow::Borrowed(head);
    }

    let mut out = Vec::with_capacity(head.len() + 32);
    let mut connection_written = false;
    for line in &lines {
        let Some((name, _value)) = header_parts(line) else {
            // The request/status line, the end-of-head line, a header with no
            // colon: kept verbatim.
            out.extend_from_slice(line);
            continue;
        };
        if is_header(name, b"connection") {
            out.extend(rewritten_header(line, name, &[b"close"]));
            connection_written = true;
            continue;
        }
        out.extend_from_slice(line);
    }
    if !connection_written {
        // Insert `Connection: close` before the end-of-head marker. The last
        // line is the `\r\n` that ends the head; insert before it.
        let last = out
            .len()
            .saturating_sub(lines.last().map_or(0, |l| l.len()));
        let inserted = b"Connection: close\r\n";
        out.splice(last..last, inserted.iter().copied());
    }
    out.extend_from_slice(rest);
    Cow::Owned(out)
}

/// Whether `headers` holds a `\n` not preceded by `\r` (a bare-LF line ending).
fn has_bare_lf(headers: &[u8]) -> bool {
    headers.first() == Some(&b'\n')
        || headers
            .windows(2)
            .any(|w| matches!(w, [prev, b'\n'] if *prev != b'\r'))
}

/// Where a buffered head ends: just past its `\r\n\r\n`, or its whole length
/// when the marker is absent.
fn head_end(head: &[u8]) -> usize {
    head.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(head.len(), |at| at + 4)
}

/// How a forwarded request's body is delimited (RFC 9112 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestBody {
    /// No `Transfer-Encoding` and no `Content-Length`: the request has no body.
    None,
    /// `Content-Length`: exactly this many bytes.
    Length(u64),
    /// `Transfer-Encoding` ending in `chunked`: chunks up to the last-chunk
    /// and its trailer section.
    Chunked,
}

/// The body framing a request head declares, or `None` when the proxy cannot
/// delimit the body the way the upstream would: a transfer coding that does
/// not end in `chunked`, a `Content-Length` that is not one decimal number,
/// or both headers at once (RFC 9112 §6.3 lets a server reject that, and the
/// proxy does, so it and the upstream never disagree on where the request
/// ends). The request line is not a header and is not consulted.
fn request_body(lines: &[&[u8]]) -> Option<RequestBody> {
    let mut transfer_encoded = false;
    let mut last_coding: Option<&[u8]> = None;
    let mut length: Option<u64> = None;
    for line in lines.iter().skip(1) {
        let Some((name, value)) = header_parts(line) else {
            continue;
        };
        if is_header(name, b"transfer-encoding") {
            transfer_encoded = true;
            last_coding = value_tokens(value).last();
        } else if is_header(name, b"content-length") {
            for token in value_tokens(value) {
                if token.is_empty() || !token.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                let declared: u64 = std::str::from_utf8(token).ok()?.parse().ok()?;
                if length.is_some_and(|seen| seen != declared) {
                    return None;
                }
                length = Some(declared);
            }
        }
    }
    match (transfer_encoded, length) {
        (true, Some(_)) => None,
        (true, None) => last_coding
            .is_some_and(|coding| is_token(coding, b"chunked"))
            .then_some(RequestBody::Chunked),
        (false, Some(length)) => Some(RequestBody::Length(length)),
        (false, None) => Some(RequestBody::None),
    }
}

/// Relays one forwarded request's exchange once its head has been replayed to
/// `upstream`. The request side forwards `buffered` (the bytes the head read
/// took past the head) and the client's further bytes only as far as `body`
/// delimits the request, while the response side relays the upstream's
/// answer, both at once so a body the upstream must read whole before it
/// answers never stalls the exchange.
///
/// Past the request's own body the client's bytes are discarded, never
/// forwarded: a pipelined or keep-alive request after it may name another
/// box, and this upstream is not that box. Only when `upgrade` is set and the
/// upstream answers `101 Switching Protocols` do the client's later bytes go
/// on to it, as the upgraded protocol's raw stream. The exchange ends when the
/// upstream's side does, so nothing the client sends after that is read.
///
/// Until the response head arrives, the client is not read past its body, so a
/// client that closes while the upstream is still working (a long-poll it gave
/// up on) is noticed only once the upstream answers or closes; both sockets are
/// held until then.
async fn relay_exchange<C: AsyncRead + AsyncWrite + Unpin>(
    client: &mut C,
    upstream: &mut TcpStream,
    buffered: &[u8],
    body: RequestBody,
    upgrade: bool,
) -> io::Result<()> {
    let (client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let (switched_tx, switched_rx) = tokio::sync::oneshot::channel::<bool>();

    let to_client = async {
        let switched = relay_response_head(&mut upstream_read, &mut client_write, upgrade).await?;
        #[expect(
            clippy::let_underscore_must_use,
            reason = "an error only means the request side has already ended"
        )]
        let _ = switched_tx.send(switched);
        tokio::io::copy(&mut upstream_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    let to_upstream = async {
        let mut reader = tokio::io::BufReader::new(AsyncReadExt::chain(buffered, client_read));
        forward_body(&mut reader, &mut upstream_write, body).await?;
        if switched_rx.await.unwrap_or(false) {
            tokio::io::copy(&mut reader, &mut upstream_write).await?;
        } else {
            tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?;
        }
        upstream_write.shutdown().await
    };

    tokio::pin!(to_client);
    tokio::select! {
        done = &mut to_client => done,
        sent = to_upstream => {
            sent?;
            to_client.await
        }
    }
}

/// Relays the upstream's response heads to `client` up to the final one, and
/// returns whether the exchange switched protocols. Each interim `1xx` head
/// (`100 Continue`, `103 Early Hints`) passes through as is; the final head's
/// `Connection` is set to `close`, so the client never reuses this connection
/// for a request this upstream must not see. A `101 Switching Protocols`
/// answer to an `upgrade` request passes through unchanged and switches.
/// Bytes buffered past the final head are written on untouched.
///
/// # Errors
///
/// Errors if a head exceeds [`MAX_HEAD`], or a read or a write to the client
/// fails.
async fn relay_response_head<U, C>(
    upstream: &mut U,
    client: &mut C,
    upgrade: bool,
) -> io::Result<bool>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    loop {
        // An upstream that ends before a whole `\r\n\r\n` head (one answering
        // with bare-LF line endings, say) has its bytes passed on unchanged:
        // the exchange ends with the upstream, so the client reuses nothing.
        if let Err(error) = fill_head(upstream, &mut buf).await {
            if error.kind() != io::ErrorKind::UnexpectedEof {
                return Err(error);
            }
            client.write_all(&buf).await?;
            return Ok(false);
        }
        let (head, rest) = buf.split_at(head_end(&buf));
        match response_status(head) {
            Some(101) if upgrade => {
                client.write_all(&buf).await?;
                return Ok(true);
            }
            Some(status) if (100..200).contains(&status) && status != 101 => {
                client.write_all(head).await?;
                buf = rest.to_vec();
            }
            _ => {
                client.write_all(&set_connection_close(head)).await?;
                client.write_all(rest).await?;
                return Ok(false);
            }
        }
    }
}

/// Reads from `stream` into `buf` until `buf` holds a whole head (its
/// `\r\n\r\n`); returns at once when it already does.
///
/// # Errors
///
/// Errors if the head exceeds [`MAX_HEAD`] or the stream ends before the marker.
async fn fill_head<R: AsyncRead + Unpin>(stream: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response head exceeded the maximum size",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before end of response head",
            ));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    Ok(())
}

/// The status code of a response head's status line (`HTTP/1.1 200 OK`), or
/// `None` when the line carries no three-digit code.
fn response_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let code = line.trim_ascii().split(|&b| b == b' ').nth(1)?;
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(code).ok()?.parse().ok()
}

/// The longest chunk-size or trailer line the proxy reads while delimiting a
/// chunked request body.
const MAX_BODY_LINE: u64 = 4 * 1024;

/// Forwards exactly the request body `body` delimits from `reader` to
/// `upstream`, and nothing past it.
///
/// # Errors
///
/// Errors if the client ends mid-body, a chunked body is malformed, or a write
/// to the upstream fails.
async fn forward_body<R, W>(reader: &mut R, upstream: &mut W, body: RequestBody) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        RequestBody::None => Ok(()),
        RequestBody::Length(length) => forward_exact(reader, upstream, length).await,
        RequestBody::Chunked => loop {
            let line = read_body_line(reader).await?;
            upstream.write_all(&line).await?;
            let size = chunk_size(&line)
                .ok_or_else(|| malformed_chunked("a malformed chunk-size line"))?;
            if size == 0 {
                // The trailer section, up to the empty line that ends it.
                loop {
                    let line = read_body_line(reader).await?;
                    upstream.write_all(&line).await?;
                    if line.trim_ascii().is_empty() {
                        return Ok(());
                    }
                }
            }
            forward_exact(reader, upstream, size).await?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
            if &crlf != b"\r\n" {
                return Err(malformed_chunked("chunk data not followed by CRLF"));
            }
            upstream.write_all(&crlf).await?;
        },
    }
}

/// Copies exactly `length` bytes from `reader` to `upstream`.
///
/// # Errors
///
/// Errors if the client ends before `length` bytes, or a write fails.
async fn forward_exact<R, W>(reader: &mut R, upstream: &mut W, length: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut (&mut *reader).take(length), upstream).await?;
    if copied < length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the client ended mid-body",
        ));
    }
    Ok(())
}

/// One line of a chunked body (a chunk-size line or a trailer), with its
/// terminator, bounded by [`MAX_BODY_LINE`].
///
/// # Errors
///
/// Errors if the line is unterminated within the bound, or the read fails.
async fn read_body_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    (&mut *reader)
        .take(MAX_BODY_LINE)
        .read_until(b'\n', &mut line)
        .await?;
    if !line.ends_with(b"\n") {
        return Err(malformed_chunked("an unterminated or overlong line"));
    }
    Ok(line)
}

/// The size a chunk-size line declares (hex digits, then any `;` extensions),
/// or `None` when it declares none.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let digits = line
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

/// The error a malformed chunked request body ends the exchange with.
fn malformed_chunked(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("chunked request body: {what}"),
    )
}

/// One header line rebuilt to carry only `tokens`, preserving the original
/// name's case and each token's own bytes, and the original line's terminator.
///
/// `body` is `line` with a suffix stripped, so its length is a valid start in
/// `line` and the terminator slice cannot be out of bounds.
#[expect(
    clippy::indexing_slicing,
    reason = "`body` is `line` less a suffix, so its length starts a valid slice"
)]
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

/// Writes the refusal's own answer: the status line, then a plain-text body
/// carrying the reason — the same wording the refusal's warn line records —
/// so a refused client reads *why* off the wire instead of inferring it from
/// the status. A port the box never published answers `403` with "the box
/// has not published this port", a different refusal from the declared
/// port's instant connection-refused while nothing listens on it yet
/// (NET-014: an answer, never a hang; NET-016: the refusal is "not
/// permitted", not "nothing listening").
async fn write_refusal_status<C: AsyncWrite + Unpin>(
    client: &mut C,
    status: &str,
    reason: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}",
        reason.len(),
    );
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

/// Spawns a one-shot loopback backend that answers every connection with a
/// fixed `200 OK` and closes, returning the port it listens on. Test-only:
/// this module's own tests use it for the routes a request names, and the
/// rpc module's tests use it to drive one request through the daemon's own
/// proxy (NET-019's daemon-side proof).
#[cfg(test)]
pub(crate) async fn spawn_backend() -> u16 {
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
/// the raw response the client read back. Test-only, shared with the rpc
/// module's tests for the reason [`spawn_backend`] is.
#[cfg(test)]
pub(crate) async fn proxy_get(proxy_addr: SocketAddr, authority: &str) -> String {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
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

    /// NET-019: supersession is a verdict about what a client *reports*, not
    /// about what the proxy does. Once the native condition holds — the
    /// answerer bound (the daemon's half, the one fact its replies carry)
    /// and the reserved local range present on this host — a request
    /// through the proxy still routes: a client that captured
    /// `HTTP(S)_PROXY` at activation keeps working, which is why the
    /// verdict never stops the proxy.
    ///
    /// The answerer half is the daemon's own driver, driven to serving the
    /// way startup drives it; the port it records on the state is the
    /// record the replies' `answerer_bound` projects. The range half is
    /// this host's real probe. The daemon-side test
    /// (`name_surface_reported_when_both_deployed` in `rpc`) drives both
    /// listeners through the daemon's RPC replies beside its own log line;
    /// this one isolates the other half: the proxy's real `serve` loop and
    /// a real route, after the condition has already come to hold.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_keeps_serving_after_supersession() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::time::Duration;

        use tempfile::TempDir;

        // A state the answerer's driver records its bind on, the way the
        // daemon's start path does.
        let dir = TempDir::new().unwrap();
        let state =
            crate::server::ServerStateHandle::new(crate::server::test_config(dir.path()), None)
                .await
                .unwrap();

        // The answerer's half: the daemon's own driver, serving the zone on
        // a free loopback port, its port recorded — the record the replies'
        // `answerer_bound` carries.
        let compressed =
            crate::server::RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20));
        crate::server::retry_zone_answerer_until_serving(
            state.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            compressed,
        )
        .await;
        let answerer_port = state
            .zone_answerer_port()
            .await
            .expect("the answerer's driver records the port it bound");
        assert_ne!(
            answerer_port, 0,
            "the recorded answerer port is the bind the replies report as bound"
        );

        // The published-address half: the real probe over the reserved
        // range, whose presence is what a native host's loopback carries.
        let range_present = crate::net::loopback::probe().present();
        assert!(
            range_present,
            "the reserved local range must be present on this host for the native condition \
             to hold here"
        );

        // And the proxy still serves beside it: the same route answers a
        // request naming the host, through the same serve loop it always ran.
        let backend_port = spawn_backend().await;
        let shared = Arc::new(RwLock::new(HostnameRegistry::new("dev", false)));
        shared
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::clone(&shared), proxied_request_verdict);
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let routed = proxy_get(proxy_addr, &format!("web.min.internal:{backend_port}")).await;
        assert!(
            routed.contains("200 OK"),
            "the native condition holds — answerer bound on {answerer_port}, range present — \
             and the proxy still routes: {routed}"
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
    /// `403 Forbidden`, the body saying the port is not published, and a warn
    /// line naming the host, the session, the port and the reason, instead of
    /// dialing a port the box's ingress gate would
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
        assert!(
            refused.contains("the box has not published this port"),
            "expected the refusal's body to say the port is not published, got: {refused}"
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

        // An absolute-form https:// target, which plain TCP cannot carry: a
        // bad-request refusal, never a plaintext forward.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET https://web.min.internal/ HTTP/1.1\r\nHost: web.min.internal\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let https = String::from_utf8_lossy(&response).into_owned();
        assert!(
            https.contains("400 Bad Request"),
            "expected an https absolute-form refusal, got: {https}"
        );

        drop(_guard);
        let logged = buf.contents();

        // The https absolute-form refusal carries its reason.
        assert!(
            logged.contains("absolute-form https:// target"),
            "expected the https refusal reason, got: {logged}"
        );

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

    /// An upstream that never completes the TCP handshake (a dead lease drops
    /// the SYN silently) is answered with `504 Gateway Timeout` once
    /// [`UPSTREAM_DIAL_TIMEOUT`] passes, instead of holding the client for the
    /// kernel's SYN retries. The stalled upstream is a loopback listener whose
    /// accept queue is already full, so Linux drops every further SYN.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn proxy_answers_504_when_the_upstream_dial_stalls() {
        let stalled = TcpSocket::new_v4().unwrap();
        stalled
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap();
        let stalled = stalled.listen(0).unwrap();
        let stalled_addr = stalled.local_addr().unwrap();

        // Fill the accept queue (nothing accepts) until a dial stalls. These
        // are blocking std dials on real time, untouched by the paused clock.
        let mut held = Vec::new();
        loop {
            match std::net::TcpStream::connect_timeout(&stalled_addr, Duration::from_millis(250)) {
                Ok(stream) => held.push(stream),
                Err(error) => {
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::TimedOut,
                        "expected a stalled dial once the accept queue is full"
                    );
                    break;
                }
            }
            assert!(held.len() < 64, "the accept queue never filled");
        }

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        // An in-memory client, so the only real socket the proxy waits on is
        // the stalled upstream dial.
        let (mut client, proxy_side) = tokio::io::duplex(1024);
        let request = format!(
            "GET / HTTP/1.1\r\nHost: web.min.internal:{}\r\n\r\n",
            stalled_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let started = tokio::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(60),
            handle_connection_io(proxy_side, None, &router),
        )
        .await
        .expect("the proxy must bound the upstream dial, not wait out the SYN retries")
        .unwrap();
        assert!(
            started.elapsed() >= UPSTREAM_DIAL_TIMEOUT,
            "the 504 must come from the dial timeout, after {:?}",
            started.elapsed()
        );

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.contains("504 Gateway Timeout"),
            "expected a gateway timeout for a stalled dial, got: {response}"
        );
        drop(held);
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

    /// The bind is the platform default: `SO_REUSEADDR` on Unix, never
    /// `SO_REUSEPORT`. A second bind to a port an active listener holds still
    /// fails with `EADDRINUSE` — on Linux, `SO_REUSEADDR` never licenses
    /// listening beside a live listener, only rebinding over the `TIME_WAIT`
    /// sockets a restart's own previous connections left — and the refusal is
    /// the loud failure the caller surfaces: a handed port's duplicate is the
    /// report `min session activate` and `min ls` print, never a silent
    /// neighbour. `SO_REUSEPORT`, the one option that would answer beside a
    /// live holder, is never set: it is read off the bound socket, because the
    /// kernel's own answer is the pin, on both platforms this daemon runs on.
    #[tokio::test]
    async fn proxy_bind_refuses_a_port_already_held_on_loopback() {
        use std::os::fd::AsRawFd as _;

        // A held port, the way another daemon holds a handed one: bound on the
        // host loopback and listening, before this daemon's bind runs.
        let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = held.local_addr().unwrap();
        let failure = bind_listener(addr)
            .await
            .expect_err("a held port must be refused, not shared");
        assert_eq!(
            failure.kind,
            io::ErrorKind::AddrInUse,
            "the refused bind must report the kernel's EADDRINUSE, got: {}",
            failure.reported()
        );
        assert!(
            failure.reported().contains("could not bind"),
            "the refusal must be the surfaced error the reports carry, got: {}",
            failure.reported()
        );
        drop(held);

        // And the listener it builds really carries the rule: a free port
        // binds with `SO_REUSEPORT` off. `SO_REUSEADDR` is the platform
        // default the bind keeps on purpose, so it is not pinned here;
        // `SO_REUSEPORT` is never asked for anywhere in the bind, and reading
        // it is the defence against a default that ever changes.
        let listener = bind_listener((IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into())
            .await
            .expect("a free loopback port binds");
        let value = socket_option(listener.as_raw_fd(), libc::SO_REUSEPORT);
        assert_eq!(
            value, 0,
            "the proxy's listener must never bind with SO_REUSEPORT, got {value}"
        );
    }

    /// The restart case the platform default is kept for: the previous run's
    /// accepted connections leave their sockets in `TIME_WAIT` on the
    /// documented port, and the fresh daemon must rebind the same port —
    /// `SO_REUSEADDR`'s one effect on Linux — instead of failing the bind with
    /// `EADDRINUSE` and moving off it, the failure that broke the native
    /// daemon e2e's restart (`native-daemon-e2e`, run 37035644090: the proxy
    /// stayed unbound on `127.0.0.1:7654` and the NET-001 curl exited 7).
    /// The control bind carries `SO_REUSEADDR` off — the hand-built socket the
    /// removed `bind_without_reuse` used to make, which std's and tokio's
    /// `TcpListener::bind` are not: both set the option on Unix — and is
    /// refused the port, which is what proves the `TIME_WAIT` tuple is really
    /// held and the rebind below is not just racing past it.
    #[tokio::test]
    async fn proxy_bind_rebinds_over_the_time_wait_a_restart_leaves() {
        // Build the leftover a restart meets: one accepted connection,
        // closed first by the listener's side, so its local tuple — the
        // listener's own address, the port the documented default binds — is
        // what lands in TIME_WAIT.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop(accepted);
        drop(client);
        drop(listener);

        // A bind with `SO_REUSEADDR` off is refused the port — the
        // `EADDRINUSE` the no-reuse bind turned the daemon's own restart
        // into. The kernel moves the closed socket into TIME_WAIT
        // asynchronously, so poll for the refusal rather than assuming it is
        // there yet.
        let mut refused = false;
        for _ in 0..100 {
            let socket = TcpSocket::new_v4().unwrap();
            socket.set_reuseaddr(false).unwrap();
            match socket.bind(addr) {
                Ok(()) => drop(socket),
                Err(error) => {
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::AddrInUse,
                        "the TIME_WAIT port must refuse a no-reuse bind with EADDRINUSE, \
                         got: {error}"
                    );
                    refused = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            refused,
            "a bind with SO_REUSEADDR off was never refused, so the TIME_WAIT \
             tuple never formed and the rebind below proves nothing"
        );

        // The daemon's bind is the platform default and rebinds the port: the
        // restart keeps the documented port its recipes point at, and the
        // socket carries the `SO_REUSEADDR` that made that possible.
        use std::os::fd::AsRawFd as _;
        let rebound = bind_listener(addr)
            .await
            .expect("a restart must rebind over the TIME_WAIT sockets its previous run left");
        let value = socket_option(rebound.as_raw_fd(), libc::SO_REUSEADDR);
        assert_eq!(
            value, 1,
            "the proxy's listener must bind with the platform-default SO_REUSEADDR on, \
             got {value}"
        );
    }

    /// Reads one `SOL_SOCKET` socket option off `fd`, as the kernel holds it.
    /// Returns `-1` when the read itself fails, so the assertion that follows
    /// names the unreadable option rather than panicking here.
    fn socket_option(fd: std::os::fd::RawFd, option: libc::c_int) -> libc::c_int {
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` is a live socket this test owns and holds for the call;
        // `value` and `len` are the buffers the kernel writes into, both
        // correctly sized for one `c_int`.
        let status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                std::ptr::addr_of_mut!(value).cast::<libc::c_void>(),
                std::ptr::addr_of_mut!(len),
            )
        };
        assert_eq!(status, 0, "reading the socket option must succeed");
        value
    }

    /// An absolute-form target's authority ends at its first `/` or `?`, and
    /// the rewrite keeps path and query, drops any fragment, and supplies the
    /// `/` an empty path needs, so a query-only target stays origin-form.
    #[test]
    fn absolute_form_targets_split_and_rewrite_to_origin_form() {
        let parsed =
            parse_request(b"GET http://web.min.internal?next=/a HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
        assert_eq!(parsed.authority, "web.min.internal");
        // The scheme matches case-insensitively, and userinfo is not routed on.
        let parsed =
            parse_request(b"GET HTTP://u:p@web.min.internal:81/p HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(parsed.authority, "web.min.internal:81");

        let rewrite =
            |head: &[u8]| String::from_utf8(rewrite_absolute_form(head).into_owned()).unwrap();
        assert_eq!(
            rewrite(
                b"GET http://web.min.internal:8080/p?q=1#frag HTTP/1.1\r\nA: 1\r\nhost: x\r\n\r\nbody"
            ),
            "GET /p?q=1 HTTP/1.1\r\nHost: web.min.internal:8080\r\nA: 1\r\n\r\nbody"
        );
        assert_eq!(
            rewrite(b"GET http://web.min.internal?next=/a HTTP/1.1\r\n\r\n"),
            "GET /?next=/a HTTP/1.1\r\nHost: web.min.internal\r\n\r\n"
        );
        assert_eq!(
            rewrite(b"GET Http://web.min.internal HTTP/1.0\r\n\r\n"),
            "GET / HTTP/1.0\r\nHost: web.min.internal\r\n\r\n"
        );
        assert_eq!(
            rewrite(b"GET /already HTTP/1.1\r\n\r\n"),
            "GET /already HTTP/1.1\r\n\r\n"
        );
        // The rewrite never touches `Connection` or `Upgrade`: whether the
        // connection closes is the forward path's to set, after the rewrite.
        assert_eq!(
            rewrite(
                b"GET http://web.min.internal/ws HTTP/1.1\r\n\
                  Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ),
            "GET /ws HTTP/1.1\r\nHost: web.min.internal\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
        assert_eq!(
            rewrite(
                b"GET http://web.min.internal/ws HTTP/1.1\r\n\
                  Upgrade: websocket\r\nconnection: keep-alive , UPGRADE\r\n\r\n"
            ),
            "GET /ws HTTP/1.1\r\nHost: web.min.internal\r\n\
             Upgrade: websocket\r\nconnection: keep-alive , UPGRADE\r\n\r\n"
        );
        assert_eq!(
            rewrite(
                b"GET http://web.min.internal/ws HTTP/1.1\r\n\
                  Upgrade: websocket\r\nConnection: keep-alive\r\n\r\n"
            ),
            "GET /ws HTTP/1.1\r\nHost: web.min.internal\r\n\
             Upgrade: websocket\r\nConnection: keep-alive\r\n\r\n"
        );
        assert_eq!(
            rewrite(b"GET http://web.min.internal/ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"),
            "GET /ws HTTP/1.1\r\nHost: web.min.internal\r\nUpgrade: websocket\r\n\r\n"
        );
    }

    /// Body bytes the head read buffered past the end-of-head marker are not
    /// decoded as text: a non-UTF-8 body still parses, and the rewrite
    /// forwards it byte for byte.
    #[test]
    fn absolute_form_with_non_utf8_buffered_body_parses_and_rewrites() {
        let head: &[u8] = b"POST http://web.min.internal/u HTTP/1.1\r\n\
              Content-Length: 3\r\n\r\n\xff\xfe\x00";
        let parsed = parse_request(head).expect("a non-UTF-8 body must not fail the parse");
        assert!(matches!(parsed.kind, RequestKind::Forward));
        assert_eq!(parsed.authority, "web.min.internal");
        let expected: &[u8] = b"POST /u HTTP/1.1\r\nHost: web.min.internal\r\n\
              Content-Length: 3\r\n\r\n\xff\xfe\x00";
        assert_eq!(rewrite_absolute_form(head).as_ref(), expected);
    }

    /// An absolute-form `https://` target is refused, whatever the scheme's
    /// case: the upstream leg is plain TCP. `http://` and `CONNECT` are not.
    #[test]
    fn https_absolute_form_is_detected_for_refusal() {
        assert!(is_https_absolute_form(
            b"GET https://web.min.internal/ HTTP/1.1\r\n\r\n"
        ));
        assert!(is_https_absolute_form(
            b"GET HTTPS://web.min.internal/ HTTP/1.1\r\n\r\n"
        ));
        assert!(!is_https_absolute_form(
            b"GET http://web.min.internal/ HTTP/1.1\r\n\r\n"
        ));
        assert!(!is_https_absolute_form(
            b"CONNECT web.min.internal:443 HTTP/1.1\r\n\r\n"
        ));
        assert!(!is_https_absolute_form(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(split_absolute_form("https://web.min.internal/").is_none());
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
    /// The proxy routes it by the URI authority and rewrites the request line
    /// to origin-form (`GET /path HTTP/1.1`) before forwarding, because the
    /// upstream is an origin server and many reject the absolute URI verbatim
    /// (RFC 9112 §3.2.2). Complements
    /// `host_header_routes_through_proxy_then_not_found_after_deregister`, which
    /// only exercises an origin-form (`GET /`) target.
    #[tokio::test]
    async fn forward_proxy_rewrites_absolute_form_target_to_origin_form() {
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

        // The upstream saw the request line rewritten to origin-form.
        let upstream_head = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        assert!(
            upstream_head.starts_with("GET /path HTTP/1.1"),
            "expected absolute-form target rewritten to origin-form, got: {upstream_head}"
        );
    }

    /// An absolute-form request whose URI authority differs from the `Host:`
    /// header routes by the URI authority (RFC 9112 §3.2.3). The `Host:`
    /// header is ignored for routing and replaced in the forwarded head by the
    /// URI authority, and the upstream receives the origin-form request line.
    #[tokio::test]
    async fn absolute_form_uri_authority_overrides_host_header() {
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
        // Register the host that appears in the URI authority, not the one in
        // the `Host:` header.
        reg.register_host_net(SessionId::nil(), "real");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // URI authority is `real.min.internal`, `Host:` header is a different
        // host that is not registered — the request must route by the URI.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://real.min.internal:{backend_port}/data HTTP/1.1\r\n\
                     Host: other.min.internal:{backend_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200 OK"),
            "expected the absolute-form request to route by URI authority, got: {}",
            String::from_utf8_lossy(&response)
        );

        // The upstream received the origin-form request line.
        let upstream_head = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        assert!(
            upstream_head.starts_with("GET /data HTTP/1.1"),
            "expected origin-form target, got: {upstream_head}"
        );
        assert!(
            upstream_head.contains(&format!("\r\nHost: real.min.internal:{backend_port}\r\n")),
            "expected Host: replaced by the URI authority, got: {upstream_head}"
        );
        assert!(
            !upstream_head.contains("other.min.internal"),
            "expected the received Host: dropped, got: {upstream_head}"
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
            head.to_ascii_lowercase().contains("connection: close"),
            "the proxy sets `Connection: close` on the stripped head so the upstream \
             closes after one response, got: {head}"
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
    // Connection-close routing (issue #812): the hostname proxy routes one
    // request per client connection — a keep-alive connection would send
    // every later request to the first request's upstream, leaking responses
    // across boxes. The proxy sets `Connection: close` on the replayed head
    // and on the upstream's response head (unless the request is a protocol
    // upgrade or the response is `101 Switching Protocols`), so the client
    // opens a new proxy connection for its next request and every request is
    // routed independently.
    // -----------------------------------------------------------------------

    /// Two requests for different hostnames on one client connection: the
    /// first gets its box's response with `Connection: close`, the connection
    /// ends, and the second request on a new connection reaches the other box.
    /// Each backend records the bytes it receives, so the test can tell which
    /// box a request reached.
    #[tokio::test]
    async fn proxy_closes_after_one_request_so_next_request_routes_independently() {
        // Two backends, each recording what it receives.
        let (box_a_port, box_a_received) = spawn_recording_backend().await;
        let (box_b_port, box_b_received) = spawn_recording_backend().await;

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "box-a");
        reg.register_host_net(SessionId::nil(), "box-b");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        // First request: box-a.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\nConnection: keep-alive\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let first = String::from_utf8_lossy(&response);
        assert!(
            first.contains("200 OK"),
            "expected the first request to route, got: {first}"
        );
        assert!(
            first.to_ascii_lowercase().contains("connection: close"),
            "expected the first response to carry `Connection: close`, got: {first}"
        );

        // The first request's head reached box-a, not box-b.
        let box_a_head = String::from_utf8(box_a_received.lock().unwrap().clone()).unwrap();
        assert!(
            box_a_head.contains("Host: box-a.min.internal:"),
            "expected the first request to reach box-a, got: {box_a_head}"
        );
        let box_b_head = String::from_utf8(box_b_received.lock().unwrap().clone()).unwrap();
        assert!(
            box_b_head.is_empty(),
            "box-b must not have received anything yet, got: {box_b_head}"
        );

        // The first connection is closed by the proxy; a second request on a
        // new connection reaches box-b.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: box-b.min.internal:{box_b_port}\r\nConnection: keep-alive\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let second = String::from_utf8_lossy(&response);
        assert!(
            second.contains("200 OK"),
            "expected the second request to route, got: {second}"
        );
        assert!(
            second.to_ascii_lowercase().contains("connection: close"),
            "expected the second response to carry `Connection: close`, got: {second}"
        );

        let box_b_head = String::from_utf8(box_b_received.lock().unwrap().clone()).unwrap();
        assert!(
            box_b_head.contains("Host: box-b.min.internal:"),
            "expected the second request to reach box-b, got: {box_b_head}"
        );
    }

    /// A request head with a bare-LF line ending is refused with 400 and
    /// nothing reaches the box: an upstream that tolerates bare LF could end
    /// the head at the `\n\n` and read the bytes after it as a second request
    /// naming another host.
    #[tokio::test]
    async fn bare_lf_request_head_is_refused_before_the_upstream_sees_it() {
        let (box_a_port, box_a_received) = spawn_recording_backend().await;

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "box-a");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET /a HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\nX: y\n\nGET /b HTTP/1.1\r\nHost: box-b.min.internal\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "expected a bare-LF head to be refused, got: {response}"
        );
        assert!(
            box_a_received.lock().unwrap().is_empty(),
            "the box must receive nothing of a refused head"
        );

        assert!(has_bare_lf(b"GET / HTTP/1.1\nHost: a\r\n\r\n"));
        assert!(has_bare_lf(b"\nGET / HTTP/1.1\r\n\r\n"));
        assert!(!has_bare_lf(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
    }

    /// An upstream that answers with bare-LF line endings never produces a
    /// `\r\n\r\n` head; when it closes, its bytes reach the client unchanged
    /// rather than the client getting an empty, reset connection.
    #[tokio::test]
    async fn bare_lf_response_is_passed_through_when_the_upstream_closes() {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\n\nhi").await;
        });

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: web.min.internal:{backend_port}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"HTTP/1.1 200 OK\n\nhi");
    }

    /// An upstream that answers without a `Connection` header still reaches
    /// the client with `Connection: close` — the proxy adds the header so the
    /// client knows the connection ends after this response.
    #[tokio::test]
    async fn proxy_adds_connection_close_when_upstream_omits_it() {
        // A backend that answers without a `Connection` header.
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: web.min.internal:{backend_port}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("200 OK"),
            "expected the request to route, got: {text}"
        );
        assert!(
            text.to_ascii_lowercase().contains("connection: close"),
            "expected the proxy to add `Connection: close` when the upstream omits it, got: {text}"
        );
    }

    /// An `Upgrade: websocket` request keeps its `Connection: Upgrade` and
    /// the upstream's `101 Switching Protocols` response passes through
    /// unchanged — the proxy splices the rest raw, the same as a CONNECT
    /// tunnel.
    #[tokio::test]
    async fn proxy_passes_websocket_upgrade_through() {
        // A backend that answers a websocket upgrade with `101` and then
        // echoes back whatever the client sends after the upgrade.
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 2048];
                    let n = sock.read(&mut scratch).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&scratch[..n]);
                    if head.contains("Upgrade: websocket") {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 101 Switching Protocols\r\n\
                                  Upgrade: websocket\r\n\
                                  Connection: Upgrade\r\n\
                                  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                                  \r\n",
                            )
                            .await;
                        // After the upgrade, echo back whatever the client
                        // sends — the test sends a frame and reads it back.
                        let mut frame = [0u8; 256];
                        let n = sock.read(&mut frame).await.unwrap_or(0);
                        let _ = sock.write_all(&frame[..n]).await;
                    }
                });
            }
        });

        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET /chat HTTP/1.1\r\n\
             Host: web.min.internal:{backend_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();

        // Read the response head — must be `101` with `Connection: Upgrade`,
        // not rewritten to `close`.
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        response.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("101 Switching Protocols"),
            "expected a 101 response, got: {text}"
        );
        assert!(
            text.contains("Connection: Upgrade"),
            "expected the 101 response to keep `Connection: Upgrade`, got: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("connection: close"),
            "the 101 response must not be rewritten to `Connection: close`, got: {text}"
        );

        // After the upgrade, the proxy splices raw bytes: send a frame and
        // read it back.
        let frame = b"\x82\x05hello";
        client.write_all(frame).await.unwrap();
        let mut echo = [0u8; 32];
        let n = client.read(&mut echo).await.unwrap();
        assert_eq!(
            &echo[..n],
            frame,
            "expected the websocket frame to echo back through the spliced tunnel"
        );
    }

    /// A backend that ignores `Connection: close` the way a careless or hostile
    /// box could: it records every byte it receives until the proxy closes its
    /// side, answers once what it has received ends with `answer_on` (with a
    /// `100 Continue` on its first read when `interim`), and keeps the
    /// connection alive. What it records is everything the proxy forwarded.
    async fn spawn_keepalive_backend(
        answer_on: &'static [u8],
        interim: bool,
    ) -> (u16, Arc<Mutex<Vec<u8>>>) {
        let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = backend.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut continued = !interim;
                    let mut answered = false;
                    loop {
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        let ends_on_answer = {
                            let mut seen = sink.lock().unwrap();
                            seen.extend_from_slice(&buf[..n]);
                            seen.ends_with(answer_on)
                        };
                        if !continued {
                            continued = true;
                            sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                                .await
                                .unwrap();
                        }
                        if !answered && ends_on_answer {
                            answered = true;
                            sock.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                                  Connection: keep-alive\r\n\r\nok",
                            )
                            .await
                            .unwrap();
                        }
                    }
                });
            }
        });
        (port, received)
    }

    /// Reads from `client` until what it has read ends with `marker`.
    async fn read_through(client: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(marker) {
            let n = client.read(&mut byte).await.unwrap();
            assert_ne!(n, 0, "the proxy closed before {marker:?}, got: {seen:?}");
            seen.push(byte[0]);
        }
        seen
    }

    /// A proxy on loopback routing `box-a` and `box-b`.
    async fn spawn_two_box_proxy() -> SocketAddr {
        let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, false);
        reg.register_host_net(SessionId::nil(), "box-a");
        reg.register_host_net(SessionId::nil(), "box-b");
        let router = Router::new(Arc::new(reg), proxied_request_verdict);
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));
        proxy_addr
    }

    /// A pipelined second request naming another box, sent in the same write
    /// as the first, never reaches the first box — even one that ignores
    /// `Connection: close` and keeps reading — and the client is told to close.
    #[tokio::test]
    async fn pipelined_request_for_another_box_never_reaches_the_first_box() {
        let (box_a_port, box_a_received) = spawn_keepalive_backend(b"\r\n\r\n", false).await;
        let (box_b_port, box_b_received) = spawn_recording_backend().await;
        let proxy_addr = spawn_two_box_proxy().await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let requests = format!(
            "GET /a HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\nConnection: keep-alive\r\n\r\n\
             GET /b HTTP/1.1\r\nHost: box-b.min.internal:{box_b_port}\r\nCookie: for-box-b\r\n\r\n"
        );
        client.write_all(requests.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(response.contains("200 ok"), "got: {response}");
        assert!(response.contains("connection: close"), "got: {response}");
        assert!(!response.contains("keep-alive"), "got: {response}");

        let box_a = String::from_utf8(box_a_received.lock().unwrap().clone()).unwrap();
        assert!(box_a.starts_with("GET /a "), "got: {box_a}");
        assert!(
            !box_a.contains("box-b") && !box_a.contains("GET /b"),
            "box-a must never see the request for box-b, got: {box_a}"
        );
        assert!(box_b_received.lock().unwrap().is_empty());
    }

    /// A keep-alive client that ignores the `Connection: close` it was sent and
    /// reuses the connection with another `Host:` after the first response
    /// never reaches the first box with it.
    #[tokio::test]
    async fn later_request_on_a_kept_connection_never_reaches_the_first_box() {
        let (box_a_port, box_a_received) = spawn_keepalive_backend(b"\r\n\r\n", false).await;
        let (box_b_port, box_b_received) = spawn_recording_backend().await;
        let proxy_addr = spawn_two_box_proxy().await;

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let first = format!("GET /a HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\n\r\n");
        client.write_all(first.as_bytes()).await.unwrap();
        let head = read_through(&mut client, b"\r\n\r\nok").await;
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        assert!(head.contains("connection: close"), "got: {head}");

        // The client ignores the close and sends a request for another box on
        // the same connection. The proxy may already have closed; the write's
        // fate is not what this test checks, where the bytes went is.
        let second = format!("GET /b HTTP/1.1\r\nHost: box-b.min.internal:{box_b_port}\r\n\r\n");
        drop(client.write_all(second.as_bytes()).await);
        drop(client.shutdown().await);
        let mut rest = Vec::new();
        drop(client.read_to_end(&mut rest).await);

        let box_a = String::from_utf8(box_a_received.lock().unwrap().clone()).unwrap();
        assert!(
            !box_a.contains("box-b") && !box_a.contains("GET /b"),
            "box-a must never see the request for box-b, got: {box_a}"
        );
        assert!(box_b_received.lock().unwrap().is_empty());
    }

    /// A `Content-Length` body far larger than the head read's buffer reaches
    /// the upstream whole while the proxy waits for the answer — an upstream
    /// that reads the whole body before it answers does not stall the
    /// exchange — and the bytes after it, a pipelined request for another
    /// box, do not.
    #[tokio::test]
    async fn content_length_body_is_forwarded_whole_and_nothing_after_it() {
        let proxy_addr = spawn_two_box_proxy().await;
        // The backend answers only once the whole body has arrived.
        let (box_a_port, box_a_received) = spawn_keepalive_backend(b"END", false).await;
        let body = format!("{}END", "x".repeat(64 * 1024));
        let first = format!(
            "POST /up HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\nConnection: close\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let second = "GET /b HTTP/1.1\r\nHost: box-b.min.internal\r\n\r\n";

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(first.as_bytes()).await.unwrap();
        client.write_all(second.as_bytes()).await.unwrap();
        let head = read_through(&mut client, b"\r\n\r\nok").await;
        assert!(String::from_utf8_lossy(&head).contains("200 OK"));
        client.shutdown().await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();

        let box_a = String::from_utf8(box_a_received.lock().unwrap().clone()).unwrap();
        assert_eq!(box_a.len(), first.len());
        assert!(
            box_a == first,
            "box-a must get the request and its body exactly"
        );
    }

    /// A chunked body reaches the upstream through its last chunk and trailer
    /// section, and the pipelined request after it does not.
    #[tokio::test]
    async fn chunked_body_is_forwarded_through_its_trailer_and_nothing_after_it() {
        let proxy_addr = spawn_two_box_proxy().await;
        let (box_a_port, box_a_received) = spawn_keepalive_backend(b"\r\n\r\n", false).await;
        let first = format!(
            "POST /up HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\nConnection: close\r\n\
             Transfer-Encoding: chunked\r\n\r\n\
             5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0\r\nX-Trailer: t\r\n\r\n"
        );
        let second = "GET /b HTTP/1.1\r\nHost: box-b.min.internal\r\n\r\n";

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(first.as_bytes()).await.unwrap();
        client.write_all(second.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("200 OK"));

        let box_a = String::from_utf8(box_a_received.lock().unwrap().clone()).unwrap();
        assert_eq!(box_a, first, "box-a must get the chunked request exactly");
    }

    /// An interim `100 Continue` passes through as is, and the final response
    /// after it still carries `Connection: close` — the close is set on the
    /// final head, not merely the first head the upstream sends.
    #[tokio::test]
    async fn final_response_after_100_continue_still_carries_close() {
        let proxy_addr = spawn_two_box_proxy().await;
        let (box_a_port, _received) = spawn_keepalive_backend(b"hello", true).await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let head = format!(
            "POST /up HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\n\
             Expect: 100-continue\r\nContent-Length: 5\r\n\r\n"
        );
        client.write_all(head.as_bytes()).await.unwrap();
        let interim = read_through(&mut client, b"\r\n\r\n").await;
        assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        client.write_all(b"hello").await.unwrap();
        let last = read_through(&mut client, b"\r\n\r\nok").await;
        let last = String::from_utf8_lossy(&last).to_ascii_lowercase();
        assert!(last.starts_with("http/1.1 200 ok"), "got: {last}");
        assert!(last.contains("connection: close"), "got: {last}");
        assert!(!last.contains("keep-alive"), "got: {last}");
        client.shutdown().await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
    }

    /// A request carrying both `Transfer-Encoding` and `Content-Length` is
    /// refused: the proxy will not guess where it ends.
    #[tokio::test]
    async fn request_with_both_body_framings_is_refused() {
        let proxy_addr = spawn_two_box_proxy().await;
        let (box_a_port, box_a_received) = spawn_recording_backend().await;
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: box-a.min.internal:{box_a_port}\r\n\
             Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400 Bad Request"),
            "got: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(box_a_received.lock().unwrap().is_empty());
    }

    /// The framings `request_body` reads, and the ones it refuses.
    #[test]
    fn request_body_framing() {
        let framing = |head: &[u8]| request_body(&head_lines(head));
        assert_eq!(
            framing(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Some(RequestBody::None)
        );
        assert_eq!(
            framing(b"POST / HTTP/1.1\r\ncontent-length: 12\r\n\r\n"),
            Some(RequestBody::Length(12))
        );
        assert_eq!(
            framing(b"POST / HTTP/1.1\r\nContent-Length: 3, 3\r\n\r\n"),
            Some(RequestBody::Length(3))
        );
        assert_eq!(
            framing(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n"),
            Some(RequestBody::Chunked)
        );
        for refused in [
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: \r\n\r\n",
        ] {
            assert_eq!(
                framing(refused),
                None,
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
        assert_eq!(chunk_size(b"1aF;name=value\r\n"), Some(0x1af));
        assert_eq!(chunk_size(b"0\r\n"), Some(0));
        assert_eq!(chunk_size(b"+5\r\n"), None);
        assert_eq!(chunk_size(b"\r\n"), None);
        assert_eq!(
            response_status(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            Some(101)
        );
        assert_eq!(response_status(b"HTTP/1.1 2000 Nope\r\n\r\n"), None);
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
            credentialed_upstream: None,
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
        let gate = SessionGate::for_session(
            "web".to_string(),
            Ipv4Addr::LOCALHOST,
            &policy,
            SwitchSubnet::default(),
            None,
        );
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
        // joins them: the egress declaration by stable id, then the lease
        // that names them — and the rules the proxy checks a request from that
        // lease against are built at the join, with the lease as their source.
        for (id, name, lease, policy) in [
            (client, "client", CALLER_LEASE, egress_denying_the_target()),
            (
                allowed,
                "allowed",
                OTHER_LEASE,
                egress_allowing_the_target(),
            ),
        ] {
            reg.register_caller(id, name, &policy, subnet, None);
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

    /// A minimal Ethernet II + IPv4 + TCP frame from `src` to `dst:port`, built
    /// byte by byte in the shape the relay's egress leg reads: 14-byte
    /// Ethernet header, EtherType 0x0800, minimum IPv4 header with protocol 6,
    /// the source at offset 12, the destination at offset 16, and the L4
    /// destination port behind the IPv4 header, at `ip[ihl + 2..ihl + 4]` —
    /// the same offsets `switch::tcp_frame_summary` writes and
    /// `egress::summarize` reads, so the parity property compares two frames
    /// that name the same source and port. `src` is the caller's lease, the
    /// one its compiled rules carry (NET-084).
    fn tcp_frame_to(src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut frame = [0u8; 14 + 20 + 4];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        ip[22..24].copy_from_slice(&port.to_be_bytes());
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
            // Whether an own-address target declares an ingress section at
            // all. `sessions::validate_policy` accepts an `OwnIp` record with
            // none, whose posture is deny-all — so the property ranges over
            // the absent declaration too, and every own-address path that
            // fills the registry must carry it as the empty set it is, never
            // as "no gate" (the value that means a host-address box).
            declares_ingress in prop::bool::ANY,
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
            // The target's declaration. A host-address box cannot carry one
            // (launch validation rejects it); an own-address box carries
            // exactly its mappings, or no section at all.
            let target_policy = SessionPolicy {
                egress: None,
                ingress: (mode != TargetMode::HostAddress && declares_ingress).then(|| {
                    IngressPolicy {
                        port_mappings: mappings.clone(),
                        dynamic_allowed_range: None,
                        dynamic_ingress: None,
                    }
                }),
                credentialed_upstream: None,
            };
            // The registry, as the session actor and the attach path fill it
            // for each mode. Loopback stands in for the target's lease.
            let target_lease = Ipv4Addr::LOCALHOST;
            // The applied external→internal map the attach path reports: the
            // declaration's own mappings, so a box with no ingress section
            // reports an empty map, exactly as the attach path derives it.
            let applied: BTreeMap<u16, u16> = mappings
                .iter()
                .filter(|_| declares_ingress)
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
                    // The creator's hand has published the box's address, as
                    // `Session::register_hostname` records it; the attach
                    // path's report and the session's own registration both
                    // follow it, and neither is a source of the address.
                    reg.publish_own_address(
                        target,
                        "web",
                        target_lease,
                        declared_request_ports(Some(&target_policy)),
                    );
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
            // The caller, when the request is a box's: its egress declaration
            // as the session actor records it, and its lease, which the join
            // compiles the rules with.
            let caller = from_a_box.then(|| {
                let client = SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
                reg.register_caller(
                    client,
                    "client",
                    &SessionPolicy {
                        egress: Some(stance_egress(stance)),
                        ingress: None,
                        credentialed_upstream: None,
                    },
                    subnet,
                    None,
                );
                reg.report_own_address(client, "client", CALLER_LEASE, BTreeMap::new());
                reg.caller_at(CALLER_LEASE)
                    .expect("the reported lease names the registered caller")
            });

            let route = reg
                .resolve("web.min.internal")
                .expect("the target's name resolves");

            // The direct connection's verdict: the caller's egress half on a
            // real frame to the target, from its own lease, decided by the
            // same pure verdict the relay applies — over the caller's own
            // compiled rules, the ones the registry hands the proxy — then
            // the target's ingress half by its declared ports. A host-side
            // caller has no egress half: its direct connections are ungated,
            // so its proxied requests are too.
            let mut expected = None;
            if let Some(caller) = &caller {
                let frame = tcp_frame_to(caller.lease(), route.address(), request_port);
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
            // one its own declaration admits. A host-address target has no
            // gate to compare with — a direct connection to it is ungated, so
            // its proxied requests are too — so only the two own-address
            // forms name a port to check.
            if let ProxiedRequest::Forward(upstream) = &observed
                && let SocketAddr::V4(up) = upstream
            {
                let terminated_on = match mode {
                    TargetMode::HostAddress => None,
                    TargetMode::OwnAddressOnSwitch => Some(up.port()),
                    TargetMode::OwnAddressNative => Some(
                        // The forwarder carries the published external port;
                        // the connection terminates on the internal one.
                        mappings
                            .iter()
                            .find(|m| m.external_port == up.port())
                            .map(|m| m.internal_port)
                            .expect("a forwarded request names a published port"),
                    ),
                };
                if let Some(internal) = terminated_on {
                    let gate = SessionGate::for_session(
                        "web".to_string(),
                        target_lease,
                        &target_policy,
                        subnet,
                        None,
                    );
                    prop_assert!(
                        gate.admits_direct_tcp(internal),
                        "the proxy forwarded to port {internal}, which the target's gate refuses"
                    );
                }
            }
        }
    }

    /// The own-address/absent-ingress case the NET-071 property ranges over
    /// and must never lose again: a box that declares no ingress — a
    /// configuration `sessions::validate_policy` accepts on `own_ip` — is
    /// deny-all on *every* host form, because `None` on a route is the
    /// *host-address* box's ungated route, and an own-address box with no
    /// declaration is not one. Both registry paths that build its route are
    /// checked: the applied external→internal map the attach path reports
    /// (empty when nothing is declared) and the session's own registration a
    /// rename or re-finalize re-registers through
    /// [`crate::net::switch::declared_request_ports`], which read the absent
    /// declaration as `None` — the host-address value — and so had a native
    /// host's proxy dial `127.0.0.1:<any port>` for a request the VM host's
    /// refused (NET-069, NET-071).
    #[test]
    fn own_ip_target_with_no_ingress_is_deny_all_on_every_host_form() {
        // The target's declaration: none, which launch accepts on `own_ip`.
        let policy = SessionPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None,
        };
        // The direct half: the relay's own gate for that declaration refuses
        // every new inbound connection — the own-IP default-block posture.
        let gate = SessionGate::for_session(
            "web".to_string(),
            Ipv4Addr::LOCALHOST,
            &policy,
            SwitchSubnet::default(),
            None,
        );
        assert!(
            !gate.admits_direct_tcp(18080),
            "a box that declares no ingress admits no direct connection"
        );

        let target = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let client = SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        for (on_switch, form) in [(true, "a VM host"), (false, "a native host")] {
            let mut reg = HostnameRegistry::new(DEFAULT_HOST_ID, on_switch);
            // A caller whose egress admits the target, so the ingress half is
            // the one that refuses: the refusal names the rule, not a verdict
            // another half got in first.
            reg.register_caller(
                client,
                "client",
                &egress_allowing_the_target(),
                SwitchSubnet::default(),
                None,
            );
            reg.report_own_address(client, "client", CALLER_LEASE, BTreeMap::new());
            let caller = reg
                .caller_at(CALLER_LEASE)
                .expect("the reported lease names the registered caller");

            // The creator's hand published the box's address; the attach
            // path's report — an applied map with no mappings — and then the
            // session actor's own registration, as a rename makes it, both
            // follow it: both must leave the route deny-all.
            reg.publish_own_address(
                target,
                "web",
                Ipv4Addr::LOCALHOST,
                declared_request_ports(Some(&policy)),
            );
            reg.report_own_address(target, "web", Ipv4Addr::LOCALHOST, BTreeMap::new());
            reg.register_own_ip(target, "web", declared_request_ports(Some(&policy)));
            let route = reg
                .resolve("web.min.internal")
                .expect("an own-address box's name routes");

            assert_eq!(
                route.declared_ports(),
                Some(&BTreeSet::new()),
                "{form}: a box with no ingress declaration is deny-all, not ungated"
            );
            assert_eq!(
                route.upstream(18080),
                None,
                "{form}: no port routes to a box that publishes none"
            );

            // The proxy's verdict is the same refusal for a host-side peer and
            // for a box whose egress admits the target: the ingress half
            // alone refuses it, with the rule a direct connection's drop
            // carries.
            for caller in [None, Some(caller)] {
                match proxied_request_verdict(caller.as_ref(), &route, 18080) {
                    ProxiedRequest::Forward(upstream) => panic!(
                        "{form}: the proxy forwarded to {upstream}, a port the \
                         target's own gate refuses"
                    ),
                    ProxiedRequest::Refused(refusal) => {
                        assert_eq!(
                            refusal.rule, NO_INGRESS_MAPPING_RULE,
                            "{form}: the refusal must name the ingress rule"
                        );
                        assert_eq!(
                            refusal.direction,
                            Direction::Ingress,
                            "{form}: the refusal must be the ingress half's"
                        );
                    }
                }
            }
        }
    }

    /// NET-059: two VMs on one host both route their box names through the
    /// host at the same time. On a VM boot, each VM's host ports come from
    /// minvmd's handed assignment — the boot-line tokens the guest daemon
    /// binds as pinned, one pair of its own per VM — so each publishes at
    /// exactly the numbers it was handed and the walk never runs
    /// (`two_vms_pinned_ports_route_concurrently` drives that shape). This
    /// test drives the boots the walk *does* cover: no handed port — an
    /// older minvmd, a native run, a host that handed `0` — where each
    /// daemon binds its own loopback at the same documented port, as two
    /// guests each hold their own netns, and the *publications* contend.
    /// The first VM's publication holds the default; the second's is
    /// refused there and takes the next rung, and its *listener* keeps the
    /// documented port its boxes share its loopback with. A host client
    /// dialing each VM's published port reaches that VM's boxes — and no
    /// other VM's — concurrently.
    ///
    /// Both halves of the host's hostname surface are driven: the routing
    /// proxies (`Host:`-dialled TCP) and the box-zone answerers (A queries),
    /// each VM's answerer taking the same two-gated startup its proxy takes
    /// and contending for the same host loopback through the same ledger, so
    /// a host resolver pointed at one VM's published answerer port gets that
    /// VM's zone — its own box held, the other VM's nobody's here — while
    /// the other VM's resolver does the mirror, at the same time.
    ///
    /// The gvproxy forwarder each publication goes through is played two
    /// ways: the *port* a publication lands on is arbitrated by
    /// [`crate::server::HostExpose::HeldPorts`], the stand-in that holds
    /// every host port it accepts, and the *forward* itself is wired by hand
    /// (`spawn_forward` for TCP, `spawn_udp_forward` for the answerer's
    /// datagrams), binding the published host port and relaying to the guest
    /// listener — what the real forwarder does with the exposure the driver
    /// asked it for, and the half of "through the host" that lives on the
    /// host rather than in this crate.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_vms_hostnames_route_concurrently() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use hickory_proto::op::ResponseCode;
        use tempfile::TempDir;

        use crate::server::{
            Config, HOST_PUBLISH_PORT_STRIDE, HostExpose, HostProxyStartup, ProxyPort,
            RetryBackoff, ServerStateHandle,
        };

        // The documented default each VM binds in its own guest: a free
        // port with a free rung above it — the walk's next proposal — probed
        // the way every other borrowed port in this suite is.
        let guest_port = loop {
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let Some(rung) = crate::server::next_host_publish_port(port) else {
                continue;
            };
            match std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, rung)) {
                Ok(rung_probe) => drop(rung_probe),
                Err(_) => continue,
            }
            break port;
        };
        let rung = guest_port + u16::try_from(HOST_PUBLISH_PORT_STRIDE).unwrap();

        // Two VM-shaped daemons: `in_microvm` is what routes an own-address
        // box to its lease, and each binds the same documented default on its
        // own loopback — two guests, two netns, one port number each.
        let vm_host = |dir: &TempDir| Config {
            in_microvm: true,
            ..crate::server::test_config(dir.path())
        };
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let a = ServerStateHandle::new(vm_host(&dir_a), None).await.unwrap();
        let b = ServerStateHandle::new(vm_host(&dir_b), None).await.unwrap();

        // The host port ledger both publications contend through: the
        // stand-in forwarder that holds every port it accepts — the
        // contention two VMs put on one host's loopback.
        let held = Arc::new(Mutex::new(HashSet::new()));

        // The first VM publishes on the default; the second is refused
        // there and walks to the rung. Both listeners keep the port they
        // bound, whatever the host did with the publication.
        let guest_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), guest_port);
        let guest_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), guest_port);
        crate::server::drive_proxy_until_serving(
            a.clone(),
            HostProxyStartup::Egress {
                bind_base: guest_a.ip(),
                port: ProxyPort::DefaultThenSelect {
                    default: guest_port,
                },
            },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let port_a = wait_for_proxy_port(&a).await;
        assert_eq!(
            port_a, guest_port,
            "the first VM's publication must hold the documented default"
        );
        crate::server::drive_proxy_until_serving(
            b.clone(),
            HostProxyStartup::Egress {
                bind_base: guest_b.ip(),
                port: ProxyPort::DefaultThenSelect {
                    default: guest_port,
                },
            },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let port_b = wait_for_proxy_port(&b).await;
        assert_eq!(
            port_b, rung,
            "the second VM's publication must take a host port of its own"
        );

        // Each VM's own box, on its own lease, at the one external port both
        // registries publish — the two leases the attach path would report.
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let box_port = probe.local_addr().unwrap().port();
        drop(probe);
        let lease_a = Ipv4Addr::new(127, 0, 0, 4);
        let lease_b = Ipv4Addr::new(127, 0, 0, 5);
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_a), box_port), "vm-a-web").await;
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_b), box_port), "vm-b-api").await;
        a.sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .report_own_address(
                SessionId::nil(),
                "web",
                lease_a,
                BTreeMap::from([(80, box_port)]),
            );
        b.sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .report_own_address(
                SessionId::nil(),
                "api",
                lease_b,
                BTreeMap::from([(80, box_port)]),
            );

        // The forwards the publications describe, played by hand: each VM's
        // published host port relays to that VM's proxy — the half of the
        // publication that lives on the host.
        let host_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
        let host_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
        spawn_forward(host_a, guest_a).await;
        spawn_forward(host_b, guest_b).await;

        // Both VMs' box names route through the host at the same time: each
        // published port reaches its own VM's box and refuses the other
        // VM's names, concurrently.
        let (a_web, a_api, b_api, b_web) = tokio::join!(
            proxy_get(host_a, "web.min.internal"),
            proxy_get(host_a, "api.min.internal"),
            proxy_get(host_b, "api.min.internal"),
            proxy_get(host_b, "web.min.internal"),
        );
        assert!(a_web.contains("vm-a-web"), "got: {a_web}");
        assert!(
            a_api.contains("502"),
            "VM A's proxy must refuse VM B's box, got: {a_api}"
        );
        assert!(b_api.contains("vm-b-api"), "got: {b_api}");
        assert!(
            b_web.contains("502"),
            "VM B's proxy must refuse VM A's box, got: {b_web}"
        );

        // And neither VM's listener moved: each still answers its own
        // loopback at the documented default its own boxes share with the
        // daemon — the port a refused publication must never relocate, and
        // the surface the boxes' fixed-port recipes depend on.
        let (a_direct, b_direct) = tokio::join!(
            proxy_get(guest_a, "web.min.internal"),
            proxy_get(guest_b, "api.min.internal"),
        );
        assert!(
            a_direct.contains("vm-a-web"),
            "VM A's listener must keep the documented default, got: {a_direct}"
        );
        assert!(
            b_direct.contains("vm-b-api"),
            "VM B's listener must keep the documented default, got: {b_direct}"
        );

        // The other half of the hostname surface: each VM's box-zone
        // answerer, the same two-gated startup its proxy takes, contending
        // for the same host loopback through the same ledger. Both VMs bind
        // the answerer's documented default on their own guest loopbacks —
        // so the host ports their *publications* contend for are the ones
        // that must differ, exactly as the proxies' did.
        let zone_port = loop {
            let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let Some(zone_rung) = crate::server::next_host_publish_port(port) else {
                continue;
            };
            if [guest_port, rung].contains(&port) || [guest_port, rung].contains(&zone_rung) {
                continue;
            }
            match std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, zone_rung)) {
                Ok(rung_probe) => drop(rung_probe),
                Err(_) => continue,
            }
            break port;
        };
        let zone_rung = zone_port + u16::try_from(HOST_PUBLISH_PORT_STRIDE).unwrap();

        let zone_scope = crate::net::answerer::AnswerScope::Microvm {
            subnet: crate::net::DEFAULT_SUBNET,
        };
        crate::server::drive_answerer_until_serving(
            a.clone(),
            crate::net::answerer::ZoneAnswerer::new(
                a.sessions_manager().await.hostnames(),
                zone_scope.clone(),
            ),
            guest_a.ip(),
            ProxyPort::DefaultThenSelect { default: zone_port },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let zone_port_a = wait_for_zone_port(&a).await;
        assert_eq!(
            zone_port_a, zone_port,
            "the first VM's answerer publication must hold its default's number"
        );
        crate::server::drive_answerer_until_serving(
            b.clone(),
            crate::net::answerer::ZoneAnswerer::new(
                b.sessions_manager().await.hostnames(),
                zone_scope,
            ),
            guest_b.ip(),
            ProxyPort::DefaultThenSelect { default: zone_port },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let zone_port_b = wait_for_zone_port(&b).await;
        assert_eq!(
            zone_port_b, zone_rung,
            "the second VM's answerer publication must take a host port of its own"
        );

        // The forwards those publications describe, played by hand: each
        // VM's published host port relays datagrams to that VM's answerer —
        // the UDP half of the forward a host resolver's packets ride.
        let zone_host_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), zone_port_a);
        let zone_host_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), zone_port_b);
        let zone_guest_a = SocketAddr::new(guest_a.ip(), zone_port);
        let zone_guest_b = SocketAddr::new(guest_b.ip(), zone_port);
        spawn_udp_forward(zone_host_a, zone_guest_a).await;
        spawn_udp_forward(zone_host_b, zone_guest_b).await;

        // Both VMs' box names answer through the host at the same time, each
        // through the answerer port its VM published: its own box is held in
        // its zone (NODATA at a lease the host may not be told — NET-127 —
        // but held, never a leak), and the other VM's box is nobody's here.
        let (a_web, a_api, b_api, b_web) = tokio::join!(
            zone_lookup(zone_host_a, "web.min.internal"),
            zone_lookup(zone_host_a, "api.min.internal"),
            zone_lookup(zone_host_b, "api.min.internal"),
            zone_lookup(zone_host_b, "web.min.internal"),
        );
        assert_eq!(
            a_web.metadata.response_code,
            ResponseCode::NoError,
            "VM A's zone must hold its own box"
        );
        assert_eq!(
            a_api.metadata.response_code,
            ResponseCode::NXDomain,
            "VM A's zone must not hold VM B's box"
        );
        assert_eq!(
            b_api.metadata.response_code,
            ResponseCode::NoError,
            "VM B's zone must hold its own box"
        );
        assert_eq!(
            b_web.metadata.response_code,
            ResponseCode::NXDomain,
            "VM B's zone must not hold VM A's box"
        );

        // And neither VM's answerer moved: each still serves its zone on its
        // own loopback at the documented default its own boxes query — the
        // in-guest surface a refused publication must never relocate.
        let (a_zone_direct, b_zone_direct) = tokio::join!(
            zone_lookup(zone_guest_a, "web.min.internal"),
            zone_lookup(zone_guest_b, "api.min.internal"),
        );
        assert_eq!(
            a_zone_direct.metadata.response_code,
            ResponseCode::NoError,
            "VM A's answerer must keep the documented default"
        );
        assert_eq!(
            b_zone_direct.metadata.response_code,
            ResponseCode::NoError,
            "VM B's answerer must keep the documented default"
        );
    }

    /// NET-059 as a VM boot really runs it since T63: minvmd assigns each
    /// VM its own distinct node ports on the host and hands them on the
    /// boot line, and each guest daemon binds them as [`ProxyPort::Pinned`]
    /// — so two VMs on one host publish their hostname proxies and zone
    /// answerers at exactly the numbers they were handed, and the
    /// publication walk never runs on this path
    /// (`two_vms_hostnames_route_concurrently` drives the boots with no
    /// handed port — an older minvmd, a native run, a host that handed `0`
    /// — that the walk covers). Both publish at their pinned numbers, no
    /// `relocated` line appears in either daemon's startup, and both VMs'
    /// box names route through the host at the same time: each through the
    /// port its VM was handed, reaching its own VM's box and refusing the
    /// other VM's, concurrently, on both halves of the host's hostname
    /// surface — the routing proxies (`Host:`-dialled TCP) and the
    /// box-zone answerers (A queries).
    ///
    /// The gvproxy forwarder each publication goes through is played two
    /// ways, as in the walking test: the *port* is arbitrated by
    /// [`crate::server::HostExpose::HeldPorts`] — the stand-in that holds
    /// every host port it accepts, the ledger minvmd's own assignment
    /// guarantees is never contended — and the *forward* itself is wired by
    /// hand (`spawn_forward` for TCP, `spawn_udp_forward` for the answerer's
    /// datagrams), binding the handed host port and relaying to the guest
    /// listener.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn two_vms_pinned_ports_route_concurrently() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use hickory_proto::op::ResponseCode;
        use tempfile::TempDir;

        use crate::server::{
            Config, HostExpose, HostProxyStartup, ProxyPort, RetryBackoff, ServerStateHandle,
        };

        // The handed pairs, the way minvmd's assignment makes them: one
        // proxy port and one answerer port per VM, all four distinct on the
        // host — the property two pinned publications rely on. Probed free
        // on the loopback, TCP for the proxies and UDP for the answerers,
        // the way every other borrowed port in this suite is.
        let free_tcp = |taken: &mut HashSet<u16>| -> u16 {
            loop {
                let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let port = probe.local_addr().unwrap().port();
                drop(probe);
                if taken.insert(port) {
                    break port;
                }
            }
        };
        let free_udp = |taken: &mut HashSet<u16>| -> u16 {
            loop {
                let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let port = probe.local_addr().unwrap().port();
                drop(probe);
                if taken.insert(port) {
                    break port;
                }
            }
        };
        let mut handed = HashSet::new();
        let proxy_a_port = free_tcp(&mut handed);
        let answerer_a_port = free_udp(&mut handed);
        let proxy_b_port = free_tcp(&mut handed);
        let answerer_b_port = free_udp(&mut handed);

        // Two VM-shaped daemons: `in_microvm` is what routes an own-address
        // box to its lease, and each binds the pair its VM was handed on its
        // own loopback — two guests, two netns, two numbers.
        let vm_host = |dir: &TempDir| Config {
            in_microvm: true,
            ..crate::server::test_config(dir.path())
        };
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let a = ServerStateHandle::new(vm_host(&dir_a), None).await.unwrap();
        let b = ServerStateHandle::new(vm_host(&dir_b), None).await.unwrap();

        // The host port ledger both publications go through: the stand-in
        // forwarder that holds every port it accepts, standing in for the
        // host gvproxy that holds the handed numbers.
        let held = Arc::new(Mutex::new(HashSet::new()));

        // The log the daemons' startup lines land in: the walk's own line
        // is what must never appear on this path.
        let (buf, guard) = capture_logs();

        // Each VM's proxy, pinned to the port its VM was handed: the
        // publication lands on the host at exactly that number, on the
        // first proposal — no rung, no refusal.
        let guest_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), proxy_a_port);
        let guest_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), proxy_b_port);
        crate::server::drive_proxy_until_serving(
            a.clone(),
            HostProxyStartup::Egress {
                bind_base: guest_a.ip(),
                port: ProxyPort::Pinned(proxy_a_port),
            },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let port_a = wait_for_proxy_port(&a).await;
        assert_eq!(
            port_a, proxy_a_port,
            "VM A's proxy must publish at exactly the number it was handed"
        );
        crate::server::drive_proxy_until_serving(
            b.clone(),
            HostProxyStartup::Egress {
                bind_base: guest_b.ip(),
                port: ProxyPort::Pinned(proxy_b_port),
            },
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let port_b = wait_for_proxy_port(&b).await;
        assert_eq!(
            port_b, proxy_b_port,
            "VM B's proxy must publish at exactly the number it was handed"
        );

        // Each VM's own box, on its own lease, at the one external port both
        // registries publish — the two leases the attach path would report.
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let box_port = probe.local_addr().unwrap().port();
        drop(probe);
        let lease_a = Ipv4Addr::new(127, 0, 0, 4);
        let lease_b = Ipv4Addr::new(127, 0, 0, 5);
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_a), box_port), "vm-a-web").await;
        spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_b), box_port), "vm-b-api").await;
        a.sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .report_own_address(
                SessionId::nil(),
                "web",
                lease_a,
                BTreeMap::from([(80, box_port)]),
            );
        b.sessions_manager()
            .await
            .hostnames()
            .write()
            .unwrap()
            .report_own_address(
                SessionId::nil(),
                "api",
                lease_b,
                BTreeMap::from([(80, box_port)]),
            );

        // The forwards those publications describe, played by hand: each
        // VM's handed host port relays to that VM's proxy — the half of the
        // publication that lives on the host.
        let host_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
        let host_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
        spawn_forward(host_a, guest_a).await;
        spawn_forward(host_b, guest_b).await;

        // Both VMs' box names route through the host at the same time: each
        // handed port reaches its own VM's box and refuses the other VM's
        // names, concurrently.
        let (a_web, a_api, b_api, b_web) = tokio::join!(
            proxy_get(host_a, "web.min.internal"),
            proxy_get(host_a, "api.min.internal"),
            proxy_get(host_b, "api.min.internal"),
            proxy_get(host_b, "web.min.internal"),
        );
        assert!(a_web.contains("vm-a-web"), "got: {a_web}");
        assert!(
            a_api.contains("502"),
            "VM A's proxy must refuse VM B's box, got: {a_api}"
        );
        assert!(b_api.contains("vm-b-api"), "got: {b_api}");
        assert!(
            b_web.contains("502"),
            "VM B's proxy must refuse VM A's box, got: {b_web}"
        );

        // The other half of the hostname surface, handed the same way: each
        // VM's box-zone answerer pinned to the port its VM was handed, the
        // same two-gated startup its proxy takes.
        let zone_scope = crate::net::answerer::AnswerScope::Microvm {
            subnet: crate::net::DEFAULT_SUBNET,
        };
        crate::server::drive_answerer_until_serving(
            a.clone(),
            crate::net::answerer::ZoneAnswerer::new(
                a.sessions_manager().await.hostnames(),
                zone_scope.clone(),
            ),
            guest_a.ip(),
            ProxyPort::Pinned(answerer_a_port),
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let zone_port_a = wait_for_zone_port(&a).await;
        assert_eq!(
            zone_port_a, answerer_a_port,
            "VM A's answerer must publish at exactly the number it was handed"
        );
        crate::server::drive_answerer_until_serving(
            b.clone(),
            crate::net::answerer::ZoneAnswerer::new(
                b.sessions_manager().await.hostnames(),
                zone_scope,
            ),
            guest_b.ip(),
            ProxyPort::Pinned(answerer_b_port),
            true,
            HostExpose::HeldPorts(Arc::clone(&held)),
            RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
        )
        .await;
        let zone_port_b = wait_for_zone_port(&b).await;
        assert_eq!(
            zone_port_b, answerer_b_port,
            "VM B's answerer must publish at exactly the number it was handed"
        );

        // The UDP forwards those publications describe, played by hand: each
        // VM's handed host port relays datagrams to that VM's answerer —
        // the half a host resolver's packets ride.
        let zone_host_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), zone_port_a);
        let zone_host_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), zone_port_b);
        let zone_guest_a = SocketAddr::new(guest_a.ip(), answerer_a_port);
        let zone_guest_b = SocketAddr::new(guest_b.ip(), answerer_b_port);
        spawn_udp_forward(zone_host_a, zone_guest_a).await;
        spawn_udp_forward(zone_host_b, zone_guest_b).await;

        // Both VMs' box names answer through the host at the same time, each
        // through the port its VM was handed: its own box is held in its
        // zone (NODATA at a lease the host may not be told — NET-127 — but
        // held, never a leak), and the other VM's box is nobody's here.
        let (a_web, a_api, b_api, b_web) = tokio::join!(
            zone_lookup(zone_host_a, "web.min.internal"),
            zone_lookup(zone_host_a, "api.min.internal"),
            zone_lookup(zone_host_b, "api.min.internal"),
            zone_lookup(zone_host_b, "web.min.internal"),
        );
        assert_eq!(
            a_web.metadata.response_code,
            ResponseCode::NoError,
            "VM A's zone must hold its own box"
        );
        assert_eq!(
            a_api.metadata.response_code,
            ResponseCode::NXDomain,
            "VM A's zone must not hold VM B's box"
        );
        assert_eq!(
            b_api.metadata.response_code,
            ResponseCode::NoError,
            "VM B's zone must hold its own box"
        );
        assert_eq!(
            b_web.metadata.response_code,
            ResponseCode::NXDomain,
            "VM B's zone must not hold VM A's box"
        );

        // And neither daemon's startup ever walked: no `relocated` line may
        // appear, because a handed publication that is refused keeps
        // proposing its port (the retry is the remedy) and these two never
        // refused each other anything.
        drop(guard);
        let logged = buf.contents();
        assert!(
            !logged.contains("relocated"),
            "a handed, pinned publication never walks to a rung, so the \
             walk's line must not appear in either VM's startup: {logged}"
        );
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
                    // The recorded head is what this backend exists for; a
                    // failed write just closes the connection the test then
                    // reads to its end, which is its success path.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the answer's fate is not what this backend records"
                    )]
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

    /// Spawns a one-shot backend on `addr` that answers every connection
    /// with a `200 OK` carrying `body`, closing when it has — the box each
    /// VM's name routes to, distinguishable by what it says.
    #[cfg(target_os = "linux")]
    async fn spawn_backend_on(addr: SocketAddr, body: &'static str) {
        let backend = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    // Neither the read's count nor the answer's fate is what
                    // this backend exists for; the drop that follows closes
                    // the connection the test then reads to its end, which is
                    // its success path.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the request is only read to be drained"
                    )]
                    let _ = sock.read(&mut scratch).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the answer's fate is not what this backend records"
                    )]
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
    }

    /// Binds `local` on the host loopback and relays every connection to
    /// `remote`: the forward a published port stands for, played by hand —
    /// the real gvproxy forwarder binds the host port and bridges it to the
    /// guest listener over the switch, and this is the same wiring with the
    /// switch replaced by a loopback dial, so a test's dials go through the
    /// host port the way a host client's do.
    #[cfg(target_os = "linux")]
    async fn spawn_forward(local: SocketAddr, remote: SocketAddr) {
        let listener = TcpListener::bind(local).await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut upstream) = TcpStream::connect(remote).await else {
                        return;
                    };
                    // The relay ends when either side closes; how it ended is
                    // the test's business, read from the response it got.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "a closed relay is its outcome, not its failure"
                    )]
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
                });
            }
        });
    }

    /// Waits until the state reports the host port its hostname proxy's
    /// publication landed on.
    #[cfg(target_os = "linux")]
    async fn wait_for_proxy_port(state: &crate::server::ServerStateHandle) -> u16 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(port) = state.hostname_proxy_port().await {
                    return port;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the hostname proxy must publish and report its port")
    }

    /// Waits until the state reports the host port its zone answerer's
    /// publication landed on — the answerer's own discovery field, carried
    /// beside the proxy's the same way the RPC reply serves both.
    #[cfg(target_os = "linux")]
    async fn wait_for_zone_port(state: &crate::server::ServerStateHandle) -> u16 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(port) = state.zone_answerer_port().await {
                    return port;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the zone answerer must publish and report its port")
    }

    /// Sends one A query for `name` to the answerer at `addr` and decodes the
    /// reply — the dial a host resolver makes, bounded because a test that
    /// never hears back must fail, not hang.
    #[cfg(target_os = "linux")]
    async fn zone_lookup(addr: SocketAddr, name: &str) -> hickory_proto::op::Message {
        use hickory_proto::op::Message;
        use hickory_proto::rr::RecordType;

        use crate::net::answerer::encode_query;

        let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let query = encode_query(name, RecordType::A);
        client.send_to(&query, addr).await.unwrap();
        let mut scratch = [0u8; 512];
        let (len, _) =
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut scratch))
                .await
                .expect("the answerer must answer its published host port")
                .expect("a datagram, not a timeout");
        Message::from_vec(&scratch[..len]).expect("the answerer's reply decodes")
    }

    /// Binds `local` on the host loopback and relays each datagram to
    /// `remote`, one upstream exchange at a time: the UDP half of the forward
    /// a published port stands for, played by hand — the real gvproxy
    /// forwarder binds the host port and bridges it to the guest socket over
    /// the switch, and this is the same wiring with the switch replaced by a
    /// loopback dial, so a test's resolver dials go through the host port the
    /// way a host resolver's datagrams do.
    #[cfg(target_os = "linux")]
    async fn spawn_udp_forward(local: SocketAddr, remote: SocketAddr) {
        let listener = tokio::net::UdpSocket::bind(local).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((len, reply_to)) = listener.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(upstream) = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await
                else {
                    return;
                };
                let Ok(()) = upstream.connect(remote).await else {
                    return;
                };
                if upstream.send(&buf[..len]).await.is_err() {
                    return;
                }
                let mut scratch = [0u8; 512];
                // One datagram, one exchange: a query that goes unanswered
                // upstream simply never comes back, and the test's own bound
                // is what notices.
                if let Ok(Ok((n, _))) = tokio::time::timeout(
                    Duration::from_millis(500),
                    upstream.recv_from(&mut scratch),
                )
                .await
                {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the reply's fate is the test's to read from what came back"
                    )]
                    let _ = listener.send_to(&scratch[..n], reply_to).await;
                }
            }
        });
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
            credentialed_upstream: None,
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
            credentialed_upstream: None,
        }
    }
}
