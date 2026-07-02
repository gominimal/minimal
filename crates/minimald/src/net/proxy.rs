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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::dns::HostnameRegistry;

/// Port the B5 host-side egress/DNS proxy listens on (TC3). Clients reach it
/// via `HTTP(S)_PROXY`.
pub const EGRESS_PROXY_PORT: u16 = 7654;

/// Port the B8 mTLS reverse proxy listens on (TC7).
pub const HTTPS_PROXY_PORT: u16 = 7655;

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

// The daemon shares its live registry behind an `RwLock` (the sessions manager
// mutates it under `&mut self`; the proxy only reads it, synchronously, with no
// `.await` held). This lets `Router::new(Arc<RwLock<HostnameRegistry>>)` route
// against the same table the manager registers PTasks into.
impl HostRoute for std::sync::RwLock<HostnameRegistry> {
    fn resolve_host(&self, host: &str) -> Option<IpAddr> {
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
async fn handle_connection_io<C, T>(mut client: C, router: &Router<T>) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: HostRoute,
{
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
        let shared = Arc::new(RwLock::new(HostnameRegistry::new("dev")));
        shared
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
        let mut reg = HostnameRegistry::new("dev");
        reg.register_own_ip(SessionId::nil(), "web");
        let router = Router::new(Arc::new(reg));

        // The published external port (e.g. an ingress 18080:8080 forward) is
        // carried in the authority and reached on loopback.
        assert_eq!(
            router.route("web.dev.min.internal:18080"),
            Some(SocketAddr::new(loopback, 18080))
        );
        // Absent an explicit port the default upstream port is used.
        assert_eq!(
            router.route("web.dev.min.internal"),
            Some(SocketAddr::new(loopback, DEFAULT_UPSTREAM_PORT))
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
        let mut reg = HostnameRegistry::new("dev");
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

        let authority = format!("mysvc.dev.min.internal:{backend_port}");
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
        let mut reg = HostnameRegistry::new("dev");
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

        let authority = format!("mysvc.dev.min.internal:{backend_port}");
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
