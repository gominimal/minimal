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
//! [`Router`] is that routing core, factored so #502 (the B8 HTTPS/mTLS reverse
//! proxy) extends it by terminating TLS in front of the same `Host:`-header →
//! registry → target lookup rather than duplicating it. The host-side
//! `*.min.internal` decision supersedes spike #485's systemd-resolved finding
//! (spec Open Question 1).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::dns::HostnameRegistry;

/// Default address the egress proxy listens on: loopback, where every
/// `*.min.internal` name is reachable. Clients reach it via `HTTP(S)_PROXY`.
pub const DEFAULT_PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7654);

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
/// host (with any `:port` already stripped) to the address its requests forward
/// to, or `None` if no live PTask owns it. The host resolver is never consulted.
///
/// Factored as a trait so the routing core is decoupled from how the table is
/// shared (the sessions manager owns the live registry) and so #502 can drive
/// the same lookup behind TLS termination.
pub trait HostRoute: Send + Sync + 'static {
    /// Resolves a `Host:`-header host to the address its requests forward to.
    fn resolve_host(&self, host: &str) -> Option<IpAddr>;
}

impl HostRoute for HostnameRegistry {
    fn resolve_host(&self, host: &str) -> Option<IpAddr> {
        self.resolve(host)
    }
}

/// The shared routing core: maps an HTTP authority (`host` or `host:port`) to
/// the upstream socket address a request forwards to. #502 extends this by
/// terminating TLS/mTLS in front of the same lookup.
pub struct Router<T> {
    table: Arc<T>,
}

// Manual `Clone` so a `Router` is cheap to hand to each connection task without
// requiring `T: Clone` (only the `Arc` is cloned).
impl<T> Clone for Router<T> {
    fn clone(&self) -> Self {
        Self {
            table: Arc::clone(&self.table),
        }
    }
}

impl<T: HostRoute> Router<T> {
    /// Builds a router over a shared host-routing table.
    #[must_use]
    pub fn new(table: Arc<T>) -> Self {
        Self { table }
    }

    /// Routes an HTTP authority to its upstream socket address, or `None` if no
    /// live PTask owns the host. The authority's optional `:port` selects the
    /// upstream port; absent, [`DEFAULT_UPSTREAM_PORT`] is used.
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
    pub fn route(&self, authority: &str) -> Option<SocketAddr> {
        let (host, port) = split_authority(authority);
        let ip = self.table.resolve_host(host)?;
        Some(SocketAddr::new(ip, port.unwrap_or(DEFAULT_UPSTREAM_PORT)))
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

/// Binds the egress-proxy listener at `addr`, returning it on success. On a bind
/// failure it emits the `component = "dns-proxy"` reachability warning and
/// returns `None`: the proxy is unavailable and PTask hostnames will not route
/// until the address is free. This is the daemon-startup reachability check that
/// supersedes the former systemd-resolved probe (R3.4).
///
/// The returned listener is the caller's to either serve (via [`serve`]) or
/// drop. The success event therefore reports the address as `reachable` rather
/// than `listening`: binding proves the address is free, but a caller that drops
/// the listener (the current startup check does) is not yet accepting requests.
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
            if let Err(error) = handle_connection(client, &router).await {
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

/// Handles one client connection: read its request head, route it by authority,
/// then either return a gateway error or splice it to the upstream PTask.
async fn handle_connection<T: HostRoute>(
    mut client: TcpStream,
    router: &Router<T>,
) -> io::Result<()> {
    // Bound the head read so a client that connects but never sends a complete
    // head cannot occupy this task indefinitely.
    let head = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head(&mut client)).await {
        Ok(result) => result?,
        Err(_elapsed) => return write_status(&mut client, "408 Request Timeout").await,
    };
    let Some(request) = parse_request(&head) else {
        return write_status(&mut client, "400 Bad Request").await;
    };

    // No live PTask owns this hostname: a host-side proxy returns a clean
    // gateway error rather than leaking the lookup to the host resolver.
    let Some(upstream_addr) = router.route(request.authority) else {
        return write_status(&mut client, "502 Bad Gateway").await;
    };
    let kind = request.kind;

    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(upstream) => upstream,
        Err(_) => return write_status(&mut client, "502 Bad Gateway").await,
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
async fn read_head(client: &mut TcpStream) -> io::Result<Vec<u8>> {
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
async fn write_status(client: &mut TcpStream, status: &str) -> io::Result<()> {
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, RwLock};

    use sessions::SessionId;
    use tracing_subscriber::fmt::MakeWriter;

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

    /// A registry behind an `RwLock` so a test can mutate it while the proxy
    /// serves. The proxy only ever reads it (synchronously, no `.await` held),
    /// so a plain `RwLock` is the right shared-read primitive.
    struct Shared(RwLock<HostnameRegistry>);

    impl HostRoute for Shared {
        fn resolve_host(&self, host: &str) -> Option<IpAddr> {
            self.0
                .read()
                .expect("registry lock is never held across a panic")
                .resolve(host)
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

    /// Proof artifact 1 (registry/proxy routing contract): a `HostNet` PTask's
    /// `Host:` header routes through the proxy to its registered target; after
    /// `deregister` the proxy returns a gateway error instead of a stale route.
    /// No `getaddrinfo`/host-resolver dependency — the proxy contract is
    /// asserted directly.
    #[tokio::test]
    async fn host_header_routes_through_proxy_then_not_found_after_deregister() {
        let backend_port = spawn_backend().await;

        // `myservice.dev.min.internal` → 127.0.0.1 (HostNet, R3.6); the client's
        // `:port` selects the upstream port, so it reaches the backend.
        let shared = Arc::new(Shared(RwLock::new(HostnameRegistry::new("dev"))));
        shared
            .0
            .write()
            .unwrap()
            .register_host_net(SessionId::nil(), "myservice");
        let router = Router::new(Arc::clone(&shared));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let authority = format!("myservice.dev.min.internal:{backend_port}");
        let routed = proxy_get(proxy_addr, &authority).await;
        assert!(
            routed.contains("200 OK"),
            "expected a routed 200, got: {routed}"
        );

        // After the session exits the route is withdrawn: the proxy no longer
        // forwards the hostname.
        shared.0.write().unwrap().deregister("myservice");
        let not_found = proxy_get(proxy_addr, &authority).await;
        assert!(
            not_found.contains("502 Bad Gateway"),
            "expected a gateway error after deregister, got: {not_found}"
        );
    }

    /// Proof artifact 2 (OwnIp routing): a registered `OwnIp` PTask routes
    /// through to its gvproxy switch IP. This is the routing-core contract the
    /// proxy reaches via the switch relay; the privileged netns leg defers to
    /// `ci-netns.yml`.
    #[test]
    fn own_ip_routes_to_its_switch_ip() {
        let switch_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5));
        let mut reg = HostnameRegistry::new("dev");
        reg.register(SessionId::nil(), "web", switch_ip);
        let router = Router::new(Arc::new(reg));

        assert_eq!(
            router.route("web.dev.min.internal:8080"),
            Some(SocketAddr::new(switch_ip, 8080))
        );
        // Absent an explicit port the default upstream port is used.
        assert_eq!(
            router.route("web.dev.min.internal"),
            Some(SocketAddr::new(switch_ip, DEFAULT_UPSTREAM_PORT))
        );
        // An unregistered host does not route.
        assert_eq!(router.route("ghost.dev.min.internal"), None);
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

    /// `CONNECT` carries the authority in its request line; a plain method
    /// carries it in the `Host:` header. Both parse to the same authority.
    #[test]
    fn parse_request_reads_connect_and_host_authorities() {
        let connect = parse_request(b"CONNECT web.dev.min.internal:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(matches!(connect.kind, RequestKind::Connect));
        assert_eq!(connect.authority, "web.dev.min.internal:443");

        let forward =
            parse_request(b"GET / HTTP/1.1\r\nHost: web.dev.min.internal:8080\r\n\r\n").unwrap();
        assert!(matches!(forward.kind, RequestKind::Forward));
        assert_eq!(forward.authority, "web.dev.min.internal:8080");
    }

    /// A forward request from an `HTTP_PROXY`-configured client carries an
    /// absolute-form request target (`GET http://web.dev.min.internal/path HTTP/1.1`).
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

        let mut reg = HostnameRegistry::new("dev");
        reg.register_host_net(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve(proxy, router));

        let request_line = format!("GET http://web.dev.min.internal:{backend_port}/path HTTP/1.1");
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("{request_line}\r\nHost: web.dev.min.internal:{backend_port}\r\n\r\n")
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
