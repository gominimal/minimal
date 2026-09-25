//! The B5 host-side egress proxy and its shared routing core.
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
//! [`Router`] is that routing core, factored so #502 (the B8 HTTPS/mTLS reverse
//! proxy) extends it by terminating TLS in front of the same `Host:`-header →
//! registry → target lookup rather than duplicating it. The host-side
//! `*.min.internal` decision supersedes spike #485's systemd-resolved finding
//! (spec Open Question 1).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::dns::HostnameRegistry;

/// The port the B5 host-side egress/DNS proxy listens on (TC3) when a
/// deployment pins one — the documented default the recipes that export
/// `HTTP(S)_PROXY` assume. A daemon that is started without a configured
/// port does not bind this: it asks the OS for a free port, and publishes
/// the port it got wherever clients need it (NET-025).
pub const DEFAULT_EGRESS_PROXY_PORT: u16 = 7654;

/// Port the B8 mTLS reverse proxy listens on (TC7).
pub const HTTPS_PROXY_PORT: u16 = 7655;

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
/// Factored as a trait so the routing core is decoupled from how the table is
/// shared (the sessions manager owns the live registry) and so #502 can drive
/// the same lookup behind TLS termination.
pub trait HostRoute: Send + Sync + 'static {
    /// Resolves a `Host:`-header host to the route its requests forward on.
    fn resolve_host(&self, host: &str) -> Option<super::dns::Route>;
}

impl HostRoute for HostnameRegistry {
    fn resolve_host(&self, host: &str) -> Option<super::dns::Route> {
        self.resolve(host)
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
    /// live PTask owns the host or the host does not carry the requested port.
    /// The authority's optional `:port` selects the upstream port; absent,
    /// [`DEFAULT_UPSTREAM_PORT`] is used. An `OwnIp` box on a VM host translates
    /// a published external port through its ingress declaration's
    /// external→internal map — the published port reaches the internal one
    /// behind it — and a port the declaration does not publish routes nowhere:
    /// the proxy refuses it, matching the ingress gate that denies an inbound
    /// SYN to any undeclared port on the switch (NET-001).
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
}

impl BindFailure {
    /// The reason and remedy as the one report the daemon's unavailable note
    /// and the CLI warning carry.
    #[must_use]
    pub fn reported(&self) -> String {
        format!("{}. Remedy: {}", self.reason, self.remedy)
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
/// carried inside the failure's reason.
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
            if let Err(error) = handle_connection_io(client, &router).await {
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
/// core serves both the plain egress proxy (`TcpStream`) and the TLS-terminated
/// HTTPS proxy (`TlsStream<TcpStream>`) added by the `networking-proxy` feature.
///
/// Every refusal — a head that never arrives, an unparseable head, a host no
/// live PTask owns, an upstream that will not accept the connection — is
/// logged as a warn line (NET-001) naming what is known about it, so the
/// daemon log never swallows a refused request.
async fn handle_connection_io<C, T>(mut client: C, router: &Router<T>) -> io::Result<()>
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

    // A lease route carries only the ports the box's ingress declaration
    // publishes; a request for any other port routes nowhere. Refuse it here,
    // where the host, the session and the port are all in hand, rather than
    // dialing a port the box's ingress gate would drop — a dropped SYN is a
    // silent connect hang, not a refusal (NET-001, NET-014).
    let Some(upstream_addr) = route.upstream(port) else {
        tracing::warn!(
            component = "dns-proxy",
            host,
            session = route.session(),
            port,
            reason = "the box has not published this port",
            status = "403 Forbidden",
            "refused a proxied request"
        );
        return write_status(&mut client, "403 Forbidden").await;
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

/// Emits the refusal warn line (NET-001): every request the proxy refuses is
/// logged with the Host asked for — when the head carried one, which the
/// timeout and unparseable-head refusals cannot have — the reason, and the
/// status sent, so the daemon log (and the diagnostics bundle's tail of it)
/// names every refused request. A refusal whose host resolved but whose
/// request still cannot be forwarded — the box has not published the port, or
/// its upstream refused the connection — is logged by its own call site, which
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

// ---------------------------------------------------------------------------
// TLS/mTLS termination extension (R4.4–R4.7, feature = "networking-proxy").
//
// Wraps the shared `Router` with a rustls TLS layer that requires clients to
// present a certificate signed by the daemon's internal CA. A missing or
// invalid client certificate is rejected at the application layer with a
// `401 Unauthorized` response whose body is empty (no PTask hostname, IP, or
// any internal topology — R4.5). This keeps the TLS handshake itself from
// revealing topology: only well-authenticated clients learn where their
// requests routed.
// ---------------------------------------------------------------------------

/// The daemon's self-signed certificate authority and the TLS server
/// certificate it issued. Manages the cryptographic material needed for the
/// HTTPS reverse proxy: signing new client certificates (for `minimal login`)
/// and terminating TLS for incoming connections.
#[cfg(feature = "networking-proxy")]
pub struct CertAuthority {
    /// CA certificate in DER format; handed to clients by `minimal login` so
    /// they can trust the daemon's server certificate.
    pub ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    /// CA certificate in PEM format; returned by the `IssueClientCert` RPC
    /// for use with `curl --cacert`.
    pub ca_cert_pem: String,
    /// Server certificate DER, presented to HTTPS clients during the
    /// TLS handshake.
    pub server_cert_der: rustls::pki_types::CertificateDer<'static>,
    /// Raw PKCS#8 bytes of the server's private key.
    server_key_bytes: Vec<u8>,
    /// The CA issuer (parameters plus key pair), kept for signing server and
    /// client certificates.
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

#[cfg(feature = "networking-proxy")]
impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("ca_cert_der_len", &self.ca_cert_der.len())
            .field("server_cert_der_len", &self.server_cert_der.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "networking-proxy")]
impl CertAuthority {
    /// Generates a fresh self-signed CA and a server certificate signed by it.
    ///
    /// The CA is ECDSA P-256 / SHA-256. Both the CA and the server cert are
    /// valid for the `localhost` SAN so a local curl can reach the proxy
    /// without specifying an SNI override.
    ///
    /// # Errors
    ///
    /// Returns an `rcgen::Error` if key-pair or cert generation fails.
    pub fn generate() -> Result<Self, rcgen::Error> {
        // CA — unconstrained so it can sign any cert.
        let ca_key = rcgen::KeyPair::generate()?;
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Minimal CA");
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_cert_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());
        let ca_cert_pem = ca_cert.pem();
        // Retain the CA as an issuer so it can sign server and client certs.
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        // Server certificate signed by the CA.
        let server_key = rcgen::KeyPair::generate()?;
        let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;
        let server_cert_der = rustls::pki_types::CertificateDer::from(server_cert.der().to_vec());
        let server_key_bytes = server_key.serialize_der();

        Ok(Self {
            ca_cert_der,
            ca_cert_pem,
            server_cert_der,
            server_key_bytes,
            issuer,
        })
    }

    /// Signs a new client certificate for the given subject common name,
    /// returning the cert PEM and key PEM. The key pair is generated
    /// server-side and handed to the client via `IssueClientCert` so the
    /// client can authenticate to the HTTPS proxy without a separate CSR
    /// exchange.
    ///
    /// Returns `(cert_pem, key_pem)`.
    ///
    /// # Errors
    ///
    /// Returns an `rcgen::Error` if key-pair or cert generation fails.
    pub fn sign_client_cert(&self, subject_cn: &str) -> Result<(String, String), rcgen::Error> {
        let client_key = rcgen::KeyPair::generate()?;
        // The login username can be non-ASCII; rcgen parses SANs as DNS names
        // and rejects those, which would break `minimal login`. The proxy
        // authenticates on CA-signed cert presence (not the SAN/CN), so use a
        // fixed ASCII SAN and carry the username in the subject CN instead.
        let mut client_params = rcgen::CertificateParams::new(vec!["minimal-client".to_string()])?;
        let mut client_dn = rcgen::DistinguishedName::new();
        client_dn.push(rcgen::DnType::CommonName, subject_cn);
        client_params.distinguished_name = client_dn;
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &self.issuer)?;
        Ok((client_cert.pem(), client_key.serialize_pem()))
    }

    /// Signs a new client certificate and also returns the cert in DER format
    /// for in-process TLS use (e.g., test clients). Returns
    /// `(cert_der, key_bytes, cert_pem, key_pem)`.
    ///
    /// # Errors
    ///
    /// Returns an `rcgen::Error` if key-pair or cert generation fails.
    #[allow(dead_code)]
    pub(crate) fn sign_client_cert_der(
        &self,
        subject_cn: &str,
    ) -> Result<(rustls::pki_types::CertificateDer<'static>, Vec<u8>), rcgen::Error> {
        let client_key = rcgen::KeyPair::generate()?;
        // The login username can be non-ASCII; rcgen parses SANs as DNS names
        // and rejects those, which would break `minimal login`. The proxy
        // authenticates on CA-signed cert presence (not the SAN/CN), so use a
        // fixed ASCII SAN and carry the username in the subject CN instead.
        let mut client_params = rcgen::CertificateParams::new(vec!["minimal-client".to_string()])?;
        let mut client_dn = rcgen::DistinguishedName::new();
        client_dn.push(rcgen::DnType::CommonName, subject_cn);
        client_params.distinguished_name = client_dn;
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &self.issuer)?;
        let cert_der = rustls::pki_types::CertificateDer::from(client_cert.der().to_vec());
        let key_bytes = client_key.serialize_der();
        Ok((cert_der, key_bytes))
    }

    /// Builds a rustls `ServerConfig` for the HTTPS proxy.
    ///
    /// The verifier uses `allow_unauthenticated()` so a TLS handshake
    /// succeeds even when no client certificate is presented — the
    /// application layer then returns `401 Unauthorized`. A presented
    /// certificate is validated against the CA trust store by rustls
    /// before the handshake completes; an invalid certificate causes a
    /// TLS-level failure (the client never gets an HTTP response).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the TLS configuration cannot be assembled
    /// (malformed cert/key or unsupported crypto).
    pub fn build_server_config(&self) -> io::Result<Arc<rustls::ServerConfig>> {
        // Install ring as the process-default CryptoProvider if not already set.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.ca_cert_der.clone())
            .map_err(io::Error::other)?;

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .map_err(io::Error::other)?;

        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(self.server_key_bytes.clone()),
        );

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![self.server_cert_der.clone()], server_key)
            .map_err(io::Error::other)?;

        Ok(Arc::new(config))
    }
}

/// Serves the HTTPS reverse proxy with mTLS on `listener`. Each accepted TCP
/// connection is TLS-terminated using `tls_config`, then routed via `router`
/// exactly as the plain proxy does — the shared routing core is reused
/// (scope-coordination comment on #502).
///
/// A connection that arrives **without** a client certificate is answered with
/// `401 Unauthorized` and an empty body (no PTask hostname or IP — R4.5). The
/// rejection is logged as a `tracing::warn!` event with structured fields.
///
/// A valid client certificate (signed by the daemon's CA) passes through to
/// the routing core.
///
/// # Errors
///
/// Returns the accept error if the listener fails.
#[cfg(feature = "networking-proxy")]
pub async fn serve_https<T: HostRoute>(
    listener: TcpListener,
    router: Router<T>,
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(error) => {
                    tracing::debug!(
                        component = "https-proxy",
                        %peer,
                        %error,
                        "TLS handshake failed"
                    );
                    return;
                }
            };

            // Check whether the client presented a certificate. The verifier
            // is configured with `allow_unauthenticated`, so a missing cert
            // does NOT fail the TLS handshake — it fails here at the HTTP
            // layer with a 401 that leaks no internal topology (R4.5).
            let has_cert = tls_stream.get_ref().1.peer_certificates().is_some();

            if !has_cert {
                tracing::warn!(
                    component = "https-proxy",
                    %peer,
                    reason = "no-client-cert",
                    "mTLS authentication failed: no client certificate presented"
                );
                let mut stream = tls_stream;
                // Body is intentionally empty — no PTask name or IP (R4.5).
                let _ = write_status(&mut stream, "401 Unauthorized").await;
                // Shut down cleanly so the peer receives the TLS close_notify
                // and the 401 response before the TCP connection closes.
                // Without this, the OS sends a TCP RST that can race with the
                // client still completing the TLS handshake, causing
                // ConnectionReset instead of the clean 401.
                let _ = stream.shutdown().await;
                return;
            }

            if let Err(error) = handle_connection_io(tls_stream, &router).await {
                tracing::debug!(
                    component = "https-proxy",
                    %peer,
                    %error,
                    "HTTPS proxy connection closed with error"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, RwLock};

    use sessions::SessionId;

    use crate::net::dns::DEFAULT_HOST_ID;
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
        let router = Router::new(Arc::clone(&shared));

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
        let router = Router::new(Arc::new(reg));

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
        let router = Router::new(Arc::new(reg));

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
        let router = Router::new(Arc::new(reg));

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
        let router = Router::new(Arc::new(reg));

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
        let router = Router::new(Arc::new(reg));

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
    // TLS / mTLS tests (feature = "networking-proxy").
    // These drive the full stack from TCP connection through TLS handshake to
    // the HTTP routing core, asserting the mTLS auth-failure and auth-success
    // contracts (R4.5, proof artifacts 2 and 3).
    // -----------------------------------------------------------------------

    /// Proof artifact 2 (R4.5 auth-failure non-disclosure): a connection that
    /// presents **no** client certificate is answered with `401 Unauthorized`
    /// and an empty body — no PTask hostname, IP, or any internal topology.
    #[cfg(feature = "networking-proxy")]
    #[tokio::test]
    async fn mtls_missing_cert_returns_401_with_no_topology() {
        use tokio_rustls::TlsConnector;

        let ca = CertAuthority::generate().expect("CA generation must not fail");
        let tls_config = ca.build_server_config().expect("server config must build");

        let backend_port = spawn_backend().await;
        let mut reg = HostnameRegistry::new("dev", false);
        reg.register_host_net(SessionId::nil(), "mysvc");
        let router = Router::new(Arc::new(reg));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_https(proxy, router, tls_config));

        // Build a TLS client that trusts the CA but presents no client cert.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca.ca_cert_der.clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tls = connector
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .expect("TLS handshake must succeed for anonymous connection");

        let authority = format!("mysvc.min.internal:{backend_port}");
        tls.write_all(format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("401"),
            "expected 401 Unauthorized for no-cert, got: {response_str}"
        );
        // The 401 body must not reveal PTask hostnames or switch IPs (R4.5).
        assert!(
            !response_str.contains("min.internal"),
            "response body must not contain a PTask hostname"
        );
        assert!(
            !response_str.contains("100.64"),
            "response body must not contain a switch IP"
        );
    }

    /// Proof artifact 3 (UC2b remote browser access): a connection that
    /// presents a **valid** client certificate signed by the daemon CA is
    /// routed to the target PTask and receives a `200 OK`.
    #[cfg(feature = "networking-proxy")]
    #[tokio::test]
    async fn mtls_valid_cert_routes_to_backend() {
        use tokio_rustls::TlsConnector;

        let ca = CertAuthority::generate().expect("CA generation must not fail");
        let tls_config = ca.build_server_config().expect("server config must build");
        let (client_cert_der, client_key_bytes) = ca
            .sign_client_cert_der("test-client")
            .expect("sign must succeed");

        let backend_port = spawn_backend().await;
        let mut reg = HostnameRegistry::new("dev", false);
        reg.register_host_net(SessionId::nil(), "mysvc");
        let router = Router::new(Arc::new(reg));

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_https(proxy, router, tls_config));

        // Build a TLS client with a valid client certificate.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca.ca_cert_der.clone()).unwrap();
        let client_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(client_key_bytes),
        );
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![client_cert_der], client_key)
            .expect("client auth config must build");
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tls = connector
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .expect("TLS handshake must succeed with valid client cert");

        let authority = format!("mysvc.min.internal:{backend_port}");
        tls.write_all(format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("200 OK"),
            "expected 200 OK from backend via authenticated mTLS proxy, got: {response_str}"
        );
    }
}
