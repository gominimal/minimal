//! The proxy's request shell: what a box's connection asks for, and the TLS
//! the proxy terminates for it (BEP-029, BEP-073, BEP-075).
//!
//! A box whose steering is `proxy_env` reaches the proxy as an HTTP proxy.
//! Its connection arrives through the listener ([`crate::listener`]), and
//! its first bytes are an HTTP/1.1 request head, which [`Proxy::serve`]
//! parses with the strict parser ([`crate::http::parse_request`]):
//!
//! - `CONNECT host:port` asks for a tunnel. When the authority is in the
//!   admitted set, the proxy opens a TLS connection to the upstream, answers
//!   `200`, and terminates the box's TLS inside the tunnel with a leaf for
//!   the host from the interception CA ([`crate::ca`]).
//! - An absolute-form request (`GET http://host/...`) is plain HTTP. No v1
//!   authority is plain HTTP, so the proxy refuses it: `upstream_not_tls`
//!   for a credentialed host, and `off_module` for any other host.
//! - Extended CONNECT and `connect-udp`, in either form, are refused with
//!   `501`. When the authority is outside the admitted set, the audit log
//!   also records it `off_module`. An origin-form request is refused too,
//!   because it is not a proxy request.
//! - A head that is not HTTP/1.1 is refused. A flow that opens with the
//!   HTTP/2 prior-knowledge preface is closed (BEP-074).
//!
//! The admitted set is the union of the configured modules' host sets and
//! the registered store authorities ([`Admission`]). A CONNECT or an
//! absolute-form request outside it is refused, and the audit log records
//! it `off_module` (BEP-029).
//!
//! Both TLS legs offer `http/1.1` alone in ALPN (BEP-073). A box's client
//! that offers `h2, http/1.1` gets HTTP/1.1. A client that requires `h2`
//! gets a handshake refusal. The upstream leg validates the upstream's chain
//! against the host trust store that [`Proxy::new`] takes.
//!
//! Inside the tunnel, the request half goes through
//! [`crate::http::forward_requests`], so the upstream gets the canonical
//! serialization of each head. The response half is copied to the box as
//! the upstream wrote it. The sealed-value redemption is not part of this
//! shell yet.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::Instrument as _;

use crate::audit::{AuditLog, Decision, Kind, Mapping, Outcome};
use crate::ca::{Ca, CaError, CaKey, Leaf};
use crate::http::{self, CloseReason, Parse};
use crate::listener::Delivery;
use crate::module::Module;

/// The one ALPN protocol both TLS legs offer.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// The audit marker of a request outside the admitted set.
pub const OFF_MODULE: &str = "off_module";

/// The audit marker of a plain HTTP request to a credentialed host.
pub const UPSTREAM_NOT_TLS: &str = "upstream_not_tls";

/// How long a box's connection has to send its first request head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the upstream connection (resolve, TCP connect and TLS
/// handshake) has, and how long the box's TLS handshake has.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a relayed flow can pass no bytes in either direction before the
/// proxy closes it.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How long the proxy reuses one leaf for a host. A leaf is valid for seven
/// days, so a reissue after one day keeps every served leaf well inside it.
const LEAF_REUSE: Duration = Duration::from_secs(24 * 60 * 60);

/// The authorities the proxy carries requests to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    modules: Vec<Module>,
    store: Vec<(String, u16)>,
}

impl Admission {
    /// The host sets of `modules`, and the `host:port` authorities that the
    /// store rules register.
    #[must_use]
    pub fn new<I, S>(modules: &[Module], store: I) -> Self
    where
        I: IntoIterator<Item = (S, u16)>,
        S: AsRef<str>,
    {
        Self {
            modules: modules.to_vec(),
            store: store
                .into_iter()
                .map(|(host, port)| (normal_host(host.as_ref()), port))
                .collect(),
        }
    }

    /// Whether `host:port` is in the admitted set.
    #[must_use]
    pub fn admits(&self, host: &str, port: u16) -> bool {
        let host = normal_host(host);
        self.modules
            .iter()
            .flat_map(|module| module.hosts)
            .any(|a| a.host == host && a.port == port)
            || self.store.iter().any(|(h, p)| *h == host && *p == port)
    }

    /// Whether `host` is a credentialed host, on any port.
    #[must_use]
    pub fn credentialed(&self, host: &str) -> bool {
        let host = normal_host(host);
        self.modules
            .iter()
            .flat_map(|module| module.hosts)
            .any(|a| a.host == host)
            || self.store.iter().any(|(h, _)| *h == host)
    }
}

fn normal_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Where the proxy gets a leaf certificate for a host.
pub trait LeafIssuer: Send + Sync {
    /// A leaf for `hostname`, valid at `now`.
    ///
    /// # Errors
    ///
    /// The CA's refusal.
    fn issue(&self, hostname: &str, now: SystemTime) -> Result<Leaf, CaError>;
}

impl<K: CaKey + Sync> LeafIssuer for Mutex<Ca<'static, K>> {
    fn issue(&self, hostname: &str, now: SystemTime) -> Result<Leaf, CaError> {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .issue_leaf(hostname, now)
    }
}

/// How the proxy finds an upstream's addresses.
pub trait Resolve: Send + Sync {
    /// The addresses of `host:port`.
    ///
    /// # Errors
    ///
    /// The resolver's error.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The host's own resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Where the proxy writes its audit records.
pub trait AuditWriter: Send + Sync {
    /// Appends one record. A failure is the writer's to log.
    fn write(&self, decision: &Decision);
}

impl AuditWriter for Mutex<AuditLog> {
    fn write(&self, decision: &Decision) {
        let mut log = self.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(err) = log.append(decision) {
            tracing::error!(
                path = %log.path().display(),
                box_id = %decision.box_id,
                marker = decision.marker.as_deref(),
                error = %err,
                "the audit record was not written"
            );
        }
    }
}

impl AuditWriter for Mutex<Vec<Decision>> {
    fn write(&self, decision: &Decision) {
        self.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(decision.clone());
    }
}

/// The host trust store: the platform's roots.
///
/// # Errors
///
/// When the platform gives no root at all.
pub fn native_roots() -> io::Result<RootCertStore> {
    let found = rustls_native_certs::load_native_certs();
    for err in &found.errors {
        tracing::warn!(error = %err, "a platform root certificate was not loaded");
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(found.certs);
    if ignored > 0 {
        tracing::warn!(ignored, "platform root certificates were not parsed");
    }
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the host trust store holds no root certificate",
        ));
    }
    Ok(roots)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// The proxy's request shell.
pub struct Proxy {
    admission: Admission,
    leaves: Arc<dyn LeafIssuer>,
    upstream_tls: TlsConnector,
    resolver: Arc<dyn Resolve>,
    audit: Arc<dyn AuditWriter>,
    servers: Mutex<HashMap<String, (Instant, Arc<ServerConfig>)>>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// A proxy that admits `admission`, issues leaves from `leaves`, and
    /// validates upstreams against `upstream_roots`.
    ///
    /// # Errors
    ///
    /// When rustls refuses its default protocol versions.
    pub fn new(
        admission: Admission,
        leaves: Arc<dyn LeafIssuer>,
        upstream_roots: RootCertStore,
        resolver: Arc<dyn Resolve>,
        audit: Arc<dyn AuditWriter>,
    ) -> Result<Self, rustls::Error> {
        let mut upstream = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        // BEP-073: the upstream leg is HTTP/1.1 too.
        upstream.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        Ok(Self {
            admission,
            leaves,
            upstream_tls: TlsConnector::from(Arc::new(upstream)),
            resolver,
            audit,
            servers: Mutex::new(HashMap::new()),
        })
    }

    /// Serves one admitted box connection. The span carries the box id, the
    /// authority the box asked for, and the outcome.
    pub async fn serve<S>(&self, delivery: Delivery, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let box_id = delivery.box_id_text();
        let span = tracing::info_span!(
            "box_connection",
            box_id = %box_id,
            source = %delivery.source,
            authority = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );
        async {
            let outcome = self.serve_inner(&box_id, stream).await;
            tracing::Span::current().record("outcome", outcome.word());
            tracing::debug!(outcome = outcome.word(), "box connection ended");
        }
        .instrument(span)
        .await;
    }

    async fn serve_inner<S>(&self, box_id: &str, mut stream: S) -> Ended
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (request, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream)).await
        {
            Err(_) => return Ended::Closed("head_timeout"),
            Ok(Err(reason)) => return self.refuse_head(&mut stream, &reason).await,
            Ok(Ok(head)) => head,
        };
        if let Some(word) = tunnel_refusal(&request) {
            // BEP-029: a tunnel request outside the admitted set is an
            // audited `off_module` refusal, though its answer stays `501`.
            let target = if request.method == "CONNECT" {
                split_authority(&request.target)
            } else {
                absolute_form(&request.target).map(|(_, host, port)| (host, port))
            };
            if let Some((host, port)) = target {
                let authority = format!("{host}:{port}");
                tracing::Span::current().record("authority", authority.as_str());
                if !self.admission.admits(&host, port) {
                    self.audit_refusal(box_id, &authority, OFF_MODULE);
                }
            }
            respond(
                &mut stream,
                501,
                "Not Implemented",
                "The Box Egress Proxy does not carry UDP tunnels or Extended CONNECT requests.",
            )
            .await;
            return Ended::Refused(word);
        }
        if request.method == "CONNECT" {
            return self.connect(box_id, stream, &request.target, rest).await;
        }
        if let Some((scheme, host, port)) = absolute_form(&request.target) {
            return self
                .absolute(box_id, &mut stream, scheme, &host, port)
                .await;
        }
        respond(
            &mut stream,
            400,
            "Bad Request",
            "The Box Egress Proxy takes CONNECT requests and absolute-form http:// requests only.",
        )
        .await;
        Ended::Refused("origin_form")
    }

    async fn refuse_head<S>(&self, stream: &mut S, reason: &CloseReason) -> Ended
    where
        S: AsyncWrite + Unpin,
    {
        match reason {
            CloseReason::Malformed("http_version") => {
                respond(
                    stream,
                    505,
                    "HTTP Version Not Supported",
                    "The Box Egress Proxy takes HTTP/1.1 requests only.",
                )
                .await;
                Ended::Refused("http_version")
            }
            CloseReason::Malformed(_)
            | CloseReason::FramingAmbiguous(_)
            | CloseReason::HeadTooLarge => {
                respond(
                    stream,
                    400,
                    "Bad Request",
                    "The Box Egress Proxy did not read the request, because its head is not valid HTTP/1.1.",
                )
                .await;
                Ended::Refused(reason.rule())
            }
            // BEP-074: the preface, a closed or a failed read end the
            // connection with no answer.
            _ => Ended::Closed(reason.rule()),
        }
    }

    /// A refusal outside the admitted set, or of plain HTTP to a
    /// credentialed host, with its audit record.
    fn audit_refusal(&self, box_id: &str, authority: &str, marker: &str) {
        self.audit.write(&Decision {
            kind: Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            identifier: None,
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: Some(marker.to_owned()),
        });
    }

    async fn absolute<S>(
        &self,
        box_id: &str,
        stream: &mut S,
        scheme: &'static str,
        host: &str,
        port: u16,
    ) -> Ended
    where
        S: AsyncWrite + Unpin,
    {
        let authority = format!("{host}:{port}");
        tracing::Span::current().record("authority", authority.as_str());
        if self.admission.credentialed(host) {
            // BEP-055: no v1 authority is plain HTTP, so a credentialed host
            // never rides a plaintext leg.
            self.audit_refusal(box_id, &authority, UPSTREAM_NOT_TLS);
            respond(
                stream,
                403,
                "Forbidden",
                &if scheme == "https" {
                    format!(
                        "The Box Egress Proxy refused the https:// request to {host}. It carries https to {host} through CONNECT only."
                    )
                } else {
                    format!(
                        "The Box Egress Proxy refused the {scheme}:// request to {host}. It sends requests to {host} over HTTPS only. Use https://{host}/ in place of {scheme}://{host}/."
                    )
                },
            )
            .await;
            return Ended::Refused(UPSTREAM_NOT_TLS);
        }
        self.off_module(box_id, stream, &authority).await
    }

    async fn off_module<S>(&self, box_id: &str, stream: &mut S, authority: &str) -> Ended
    where
        S: AsyncWrite + Unpin,
    {
        self.audit_refusal(box_id, authority, OFF_MODULE);
        respond(
            stream,
            403,
            "Forbidden",
            &format!(
                "The Box Egress Proxy refused the request to {authority}. It carries requests to credentialed hosts only, and {authority} is not one."
            ),
        )
        .await;
        Ended::Refused(OFF_MODULE)
    }

    async fn connect<S>(&self, box_id: &str, mut stream: S, target: &str, rest: Vec<u8>) -> Ended
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tracing::Span::current().record("authority", target);
        let Some((host, port)) = split_authority(target) else {
            respond(
                &mut stream,
                400,
                "Bad Request",
                "The Box Egress Proxy did not read the CONNECT target. Give it as host:port.",
            )
            .await;
            return Ended::Refused("connect_target");
        };
        let authority = format!("{host}:{port}");
        // BEP-029, and BEP-031's port discipline: the authority is admitted
        // only as `host:port`.
        if !self.admission.admits(&host, port) {
            return self.off_module(box_id, &mut stream, &authority).await;
        }
        let server = match self.server_config(&host) {
            Ok(server) => server,
            Err(err) => {
                tracing::warn!(host, error = %err, "no leaf certificate for an admitted host");
                respond(
                    &mut stream,
                    502,
                    "Bad Gateway",
                    &format!("The Box Egress Proxy did not get a certificate for {host}."),
                )
                .await;
                return Ended::Refused("leaf");
            }
        };
        let dialed = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.dial_upstream(&host, port))
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the connection timed out",
                ))
            });
        let upstream = match dialed {
            Ok(upstream) => upstream,
            Err(err) => {
                tracing::warn!(authority, error = %err, "the upstream connection failed");
                respond(
                    &mut stream,
                    502,
                    "Bad Gateway",
                    &format!("The Box Egress Proxy did not connect to {authority}: {err}."),
                )
                .await;
                return Ended::Refused("upstream_connect");
            }
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return Ended::Closed("box_closed");
        }
        // BEP-073: the box's leg offers `http/1.1` alone.
        let accepted = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            TlsAcceptor::from(server).accept(Prefixed::new(rest, stream)),
        )
        .await;
        let boxed = match accepted {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => {
                tracing::info!(authority, error = %err, "the box's TLS handshake failed");
                return Ended::Refused("box_tls_handshake");
            }
            Err(_) => {
                tracing::info!(authority, "the box's TLS handshake timed out");
                return Ended::Closed("box_tls_timeout");
            }
        };
        relay(
            box_id,
            boxed,
            upstream,
            &authority,
            Arc::clone(&self.audit),
            IDLE_TIMEOUT,
        )
        .await;
        Ended::Relayed
    }

    async fn dial_upstream(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let resolver = Arc::clone(&self.resolver);
        let name = host.to_owned();
        let addrs = tokio::task::spawn_blocking(move || resolver.resolve(&name, port))
            .await
            .map_err(io::Error::other)??;
        let tcp = TcpStream::connect(&addrs[..]).await?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        self.upstream_tls.connect(server_name, tcp).await
    }

    /// The TLS server side for `host`, with a leaf the CA issued for it. A
    /// leaf is reused for [`LEAF_REUSE`].
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((issued, config)) = servers.get(host)
            && issued.elapsed() < LEAF_REUSE
        {
            return Ok(Arc::clone(config));
        }
        let leaf = self
            .leaves
            .issue(host, SystemTime::now())
            .map_err(|err| err.to_string())?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.to_vec()));
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|err| err.to_string())?
            .with_no_client_auth()
            .with_single_cert(leaf.chain, key)
            .map_err(|err| err.to_string())?;
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let config = Arc::new(config);
        servers.insert(host.to_owned(), (Instant::now(), Arc::clone(&config)));
        Ok(config)
    }
}

/// How one box connection ended, for the span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Both TLS legs came up and the flow was relayed.
    Relayed,
    /// The proxy answered a refusal.
    Refused(&'static str),
    /// The connection closed with no answer.
    Closed(&'static str),
}

impl Ended {
    fn word(self) -> &'static str {
        match self {
            Self::Relayed => "relayed",
            Self::Refused(word) | Self::Closed(word) => word,
        }
    }
}

/// The word of a refused tunnel request: Extended CONNECT, or `connect-udp`
/// as an upgrade or by its well-known path.
fn tunnel_refusal(request: &http::Request) -> Option<&'static str> {
    let upgrades: Vec<&[u8]> = request.header_values("upgrade").collect();
    if upgrades.iter().any(|v| {
        v.split(|&b| b == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"connect-udp"))
    }) || request
        .target
        .to_ascii_lowercase()
        .contains("/.well-known/masque/udp/")
    {
        return Some("connect_udp");
    }
    if request.method == "CONNECT"
        && (!upgrades.is_empty() || request.header_values("protocol").next().is_some())
    {
        return Some("extended_connect");
    }
    None
}

/// Reads one request head. Returns the head and the bytes read after it.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(http::Request, Vec<u8>), CloseReason> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        match http::parse_request(&buf)? {
            Parse::Complete { head, head_len } => return Ok((head, buf.split_off(head_len))),
            Parse::Partial => {}
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|err| CloseReason::Io(err.kind()))?;
        if n == 0 {
            return Err(if buf.is_empty() {
                CloseReason::ClientClosed
            } else {
                CloseReason::Eof
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Writes one refusal and closes the write half.
async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, reason: &str, body: &str) {
    let body = format!("{body}\n");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// `host:port`, with the host in lowercase. `None` when the port is absent
/// or not a number, or the host is empty.
fn split_authority(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (normal_host(host), port))
}

/// The scheme, host and port of an absolute-form target. The port defaults
/// to the scheme's.
fn absolute_form(target: &str) -> Option<(&'static str, String, u16)> {
    let lower = target
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let (scheme, rest, default) = if lower.starts_with("http://") {
        ("http", &target[7..], 80)
    } else if lower.starts_with("https://") {
        ("https", &target[8..], 443)
    } else {
        return None;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    match split_authority(authority) {
        Some((host, port)) => Some((scheme, host, port)),
        None if !authority.is_empty() && !authority.contains(':') => {
            Some((scheme, normal_host(authority), default))
        }
        None => None,
    }
}

/// The audit sink for the heads inside a tunnel: a refused head is a
/// decision record with its marker.
struct HeadAudit {
    audit: Arc<dyn AuditWriter>,
    authority: String,
}

impl http::AuditSink for HeadAudit {
    fn record(&mut self, event: http::AuditEvent) {
        self.audit.write(&Decision {
            kind: Kind::Decision,
            box_id: event.box_id,
            authority: self.authority.clone(),
            identifier: None,
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: Some(event.marker.to_owned()),
        });
    }
}

/// Relays one terminated flow: the request half through the strict
/// forwarder, the response half as the upstream wrote it.
///
/// The flow ends when it passes no bytes in either direction for `idle`.
/// It also ends when the upstream closes: the request half then reads end
/// of file from the box, so its blocking thread returns at once.
///
/// This forwards every request head with no per-request decision, no handle
/// redemption and no admit audit record. Gatehouse §6.10 requires all three.
/// `bep serve` must not reach this function until the redemption decision is
/// wired into it, which is T11
/// (<https://github.com/gominimal/minimal/issues/2272>). Today only the
/// `NoSigningKey` issuer in `bep serve` keeps it off this path. A signing
/// Keychain key (<https://github.com/gominimal/minimal/issues/2440>) alone
/// does not lift that interim.
async fn relay<B, U>(
    box_id: &str,
    boxed: B,
    upstream: U,
    authority: &str,
    audit: Arc<dyn AuditWriter>,
    idle: Duration,
) where
    B: AsyncRead + AsyncWrite + Send + 'static,
    U: AsyncRead + AsyncWrite + Send + 'static,
{
    let (box_read, mut box_write) = tokio::io::split(boxed);
    let (up_read, up_write) = tokio::io::split(upstream);
    let activity = Activity::new();
    let done = tokio_util::sync::CancellationToken::new();
    let box_read = Watched::new(box_read, &activity, &done, idle);
    let mut up_read = Watched::new(up_read, &activity, &done, idle);
    let id = box_id.to_owned();
    let mut sink = HeadAudit {
        audit,
        authority: authority.to_owned(),
    };
    let requests = tokio::task::spawn_blocking(move || {
        let mut client = tokio_util::io::SyncIoBridge::new(box_read);
        let mut upstream = tokio_util::io::SyncIoBridge::new(up_write);
        let reason = http::forward_requests(&id, &mut client, &mut upstream, &mut sink);
        let _ = upstream.shutdown();
        reason
    });
    let responses = async {
        let copied = tokio::io::copy(&mut up_read, &mut box_write).await;
        if let Err(err) = copied
            && err.kind() == io::ErrorKind::TimedOut
        {
            tracing::info!("the relayed flow was idle too long");
        }
        let _ = box_write.shutdown().await;
        done.cancel();
    };
    let (reason, ()) = tokio::join!(requests, responses);
    if let Ok(reason) = reason {
        tracing::debug!(rule = reason.rule(), "the request half ended");
    }
}

/// The time of the last byte a relayed flow passed, in milliseconds since
/// the flow started.
#[derive(Clone)]
struct Activity {
    start: tokio::time::Instant,
    last: Arc<std::sync::atomic::AtomicU64>,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            last: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
    }

    fn deadline(&self, idle: Duration) -> tokio::time::Instant {
        let last = self.last.load(std::sync::atomic::Ordering::Relaxed);
        self.start + Duration::from_millis(last) + idle
    }
}

/// One read half of a relayed flow. A read records activity. A read fails
/// with `TimedOut` when the flow passed no bytes for `idle`, and reads end
/// of file once `done` is cancelled.
struct Watched<R> {
    inner: R,
    activity: Activity,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    done: Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
}

impl<R> Watched<R> {
    fn new(
        inner: R,
        activity: &Activity,
        done: &tokio_util::sync::CancellationToken,
        idle: Duration,
    ) -> Self {
        Self {
            inner,
            activity: activity.clone(),
            idle,
            sleep: Box::pin(tokio::time::sleep_until(activity.deadline(idle))),
            done: Box::pin(done.clone().cancelled_owned()),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Watched<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.done.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    self.activity.touch();
                }
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => {}
        }
        loop {
            if self.sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let deadline = self.activity.deadline(self.idle);
            if deadline <= tokio::time::Instant::now() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the flow was idle too long",
                )));
            }
            self.sleep.as_mut().reset(deadline);
        }
    }
}

/// A stream that yields `prefix` before the inner stream's bytes: the bytes
/// a box sent after its CONNECT head, such as an early ClientHello.
struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            at: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.at);
            let at = self.at;
            buf.put_slice(&self.prefix[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SigningKey as _};
    use rustls::pki_types::CertificateDer;
    use tokio::net::{TcpListener, UnixStream};
    use tokio_rustls::LazyConfigAcceptor;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit::{LogReader, segment_name};
    use crate::ca::Union;
    use crate::keys::{HeldKey, KeyError, Role};
    use crate::listener::{Listener, PeerAttested, TOKEN_LEN};
    use crate::module::GITHUB;
    use crate::seal::ProxyPublicKey;

    /// A software key in place of a keychain key.
    struct TestKey {
        role: Role,
        pair: KeyPair,
    }

    impl HeldKey for TestKey {
        fn role(&self) -> Role {
            self.role
        }
        fn public(&self) -> ProxyPublicKey {
            ProxyPublicKey::from_sec1_bytes(self.pair.public_key_raw()).unwrap()
        }
        fn exportable(&self) -> bool {
            false
        }
        fn agree(&self, _peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            Err(KeyError::Store {
                role: self.role,
                detail: "a CA test key does no key agreement".into(),
            })
        }
        fn probe(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    impl CaKey for TestKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.pair.sign(msg).map_err(|err| KeyError::Store {
                role: self.role,
                detail: err.to_string(),
            })
        }
    }

    fn test_key(role: Role) -> &'static TestKey {
        Box::leak(Box::new(TestKey {
            role,
            pair: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        }))
    }

    /// The interception CA, and its root for the box's trust store.
    fn interception_ca() -> (Arc<dyn LeafIssuer>, CertificateDer<'static>) {
        let ca = Ca::new(
            test_key(Role::Root),
            test_key(Role::Signing),
            Union::new(&[GITHUB], [""; 0]),
            SystemTime::now(),
        )
        .unwrap();
        let root = ca.root().clone();
        (Arc::new(Mutex::new(ca)), root)
    }

    /// A stand-in for `api.github.com`: a TLS server under a test CA that
    /// offers `h2` and `http/1.1`. It records the ALPN list each client
    /// offered and the protocol it negotiated, and answers each request
    /// head with `200` and the body `ok`.
    struct Upstream {
        addr: SocketAddr,
        roots: RootCertStore,
        offered: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
        negotiated: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
        heads: Arc<Mutex<Vec<String>>>,
    }

    async fn upstream() -> Upstream {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = CertificateParams::new(vec!["api.github.com".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), ALPN_HTTP11.to_vec()];
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let negotiated = Arc::new(Mutex::new(Vec::new()));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let (o, n, h) = (offered.clone(), negotiated.clone(), heads.clone());
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (config, o, n, h) = (config.clone(), o.clone(), n.clone(), h.clone());
                tokio::spawn(async move {
                    let acceptor = rustls::server::Acceptor::default();
                    let Ok(start) = LazyConfigAcceptor::new(acceptor, tcp).await else {
                        return;
                    };
                    let alpn = start
                        .client_hello()
                        .alpn()
                        .map(|list| list.map(<[u8]>::to_vec).collect())
                        .unwrap_or_default();
                    o.lock().unwrap().push(alpn);
                    let Ok(mut tls) = start.into_stream(config).await else {
                        return;
                    };
                    n.lock()
                        .unwrap()
                        .push(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
                    if let Ok((head, _)) = read_head(&mut tls).await {
                        h.lock()
                            .unwrap()
                            .push(String::from_utf8(head.serialize()).unwrap());
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                            .await;
                    }
                    let _ = tls.shutdown().await;
                });
            }
        });
        Upstream {
            addr,
            roots,
            offered,
            negotiated,
            heads,
        }
    }

    /// Every upstream name resolves to one address, and the calls are
    /// counted.
    struct To(SocketAddr, AtomicUsize);

    impl Resolve for To {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(vec![self.0])
        }
    }

    const BOX: [u8; 16] = [0x42; 16];

    fn delivery() -> Delivery {
        Delivery {
            box_id: BOX,
            source: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 7), 40_000),
            destination: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 3), 8118),
        }
    }

    struct Harness {
        proxy: Arc<Proxy>,
        root: CertificateDer<'static>,
        upstream: Upstream,
        resolver: Arc<To>,
        audit: Arc<Mutex<Vec<Decision>>>,
    }

    async fn harness_with(audit: Arc<dyn AuditWriter>) -> (Harness, Arc<dyn AuditWriter>) {
        let upstream = upstream().await;
        let (leaves, root) = interception_ca();
        let resolver = Arc::new(To(upstream.addr, AtomicUsize::new(0)));
        let proxy = Proxy::new(
            Admission::new(&[GITHUB], [("vault.example.com", 443)]),
            leaves,
            upstream.roots.clone(),
            resolver.clone(),
            Arc::clone(&audit),
        )
        .unwrap();
        (
            Harness {
                proxy: Arc::new(proxy),
                root,
                upstream,
                resolver,
                audit: Arc::new(Mutex::new(Vec::new())),
            },
            audit,
        )
    }

    async fn harness() -> Harness {
        let audit = Arc::new(Mutex::new(Vec::<Decision>::new()));
        let (mut h, _) = harness_with(audit.clone()).await;
        h.audit = audit;
        h
    }

    /// A box connection to the proxy, already admitted by the listener.
    fn box_connection(proxy: &Arc<Proxy>) -> tokio::io::DuplexStream {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let proxy = Arc::clone(proxy);
        tokio::spawn(async move { proxy.serve(delivery(), theirs).await });
        ours
    }

    /// Everything the proxy answers to `bytes` before it closes.
    async fn exchange(proxy: &Arc<Proxy>, bytes: &[u8]) -> String {
        let mut stream = box_connection(proxy);
        stream.write_all(bytes).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Reads a response head, byte by byte, so no TLS byte after it is taken.
    async fn response_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    fn box_tls(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> tokio_rustls::TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    const CONNECT_GITHUB: &[u8] =
        b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n";

    // BEP-073: through the listener, a box's CONNECT to a GitHub host
    // completes TLS with HTTP/1.1, the upstream is offered `http/1.1` alone,
    // and a client that requires `h2` is refused at the handshake.
    #[tokio::test]
    async fn proxy_offers_http11_only_on_both_legs() {
        let h = harness().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("listener.sock");
        let token = [0x5a; TOKEN_LEN];
        let listener = Listener::bind(&path, token, Arc::new(PeerAttested)).unwrap();
        let proxy = Arc::clone(&h.proxy);
        tokio::spawn(listener.run(move |delivery, stream| {
            let proxy = Arc::clone(&proxy);
            async move { proxy.serve(delivery, stream).await }
        }));

        // The switch peer's delivery, then the box's own bytes.
        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(&token).await.unwrap();
        stream.write_all(&delivery().emit()).await.unwrap();
        stream.write_all(CONNECT_GITHUB).await.unwrap();
        let head = response_head(&mut stream).await;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");

        // The box offers `h2, http/1.1`, as curl and most clients do.
        let name = ServerName::try_from("api.github.com").unwrap();
        let mut tls = box_tls(&h.root, &[b"h2", ALPN_HTTP11])
            .connect(name.clone(), stream)
            .await
            .expect("the box's TLS completes under the interception root");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ALPN_HTTP11));
        tls.write_all(b"GET /zen HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();
        let answer = response_head(&mut tls).await;
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");

        // The upstream leg offered `http/1.1` alone, and got it.
        assert_eq!(
            *h.upstream.offered.lock().unwrap(),
            [vec![ALPN_HTTP11.to_vec()]]
        );
        assert_eq!(
            *h.upstream.negotiated.lock().unwrap(),
            [Some(ALPN_HTTP11.to_vec())]
        );
        assert_eq!(
            *h.upstream.heads.lock().unwrap(),
            ["GET /zen HTTP/1.1\r\nhost: api.github.com\r\n\r\n"]
        );

        // A client that requires `h2` gets a handshake refusal.
        let mut stream = box_connection(&h.proxy);
        stream.write_all(CONNECT_GITHUB).await.unwrap();
        assert!(
            response_head(&mut stream)
                .await
                .starts_with("HTTP/1.1 200 ")
        );
        let refused = box_tls(&h.root, &[b"h2"]).connect(name, stream).await;
        assert!(refused.is_err(), "an h2-only client completed TLS");
    }

    // BEP-029: a CONNECT or an absolute-form request outside the modules'
    // host sets and the registered store authorities is refused, nothing
    // is dialed, and the audit log records it `off_module` for the box.
    #[tokio::test]
    async fn request_outside_modules_is_refused_off_module() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path().join(segment_name(0))).unwrap();
        let (h, _) = harness_with(Arc::new(Mutex::new(log))).await;

        let requests: [&[u8]; 3] = [
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            // A module host on a port outside its authority.
            b"CONNECT api.github.com:8443 HTTP/1.1\r\nHost: api.github.com:8443\r\n\r\n",
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ];
        for request in requests {
            let answer = exchange(&h.proxy, request).await;
            assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
            assert!(answer.contains("is not one"), "{answer}");
        }
        assert_eq!(h.resolver.1.load(Ordering::SeqCst), 0);

        // What `min box audit <box>` reads.
        let entries = LogReader::new(dir.path()).read_new().unwrap().entries;
        let records: Vec<_> = entries
            .iter()
            .map(|e| {
                (
                    e.record.subject.as_str(),
                    e.record.upstream.as_str(),
                    e.record.decision,
                    e.record.marker.as_deref(),
                )
            })
            .collect();
        let subject = "42".repeat(16);
        assert_eq!(
            records,
            [
                (
                    subject.as_str(),
                    "example.com:443",
                    Outcome::Refuse,
                    Some(OFF_MODULE)
                ),
                (
                    subject.as_str(),
                    "api.github.com:8443",
                    Outcome::Refuse,
                    Some(OFF_MODULE)
                ),
                (
                    subject.as_str(),
                    "example.com:80",
                    Outcome::Refuse,
                    Some(OFF_MODULE)
                ),
            ]
        );

        // The admitted set is the module host sets and the store authorities.
        let admission = Admission::new(&[GITHUB], [("Vault.Example.com.", 443)]);
        assert!(admission.admits("api.github.com", 443));
        assert!(admission.admits("vault.example.com", 443));
        assert!(!admission.admits("vault.example.com", 8443));
        assert!(!admission.admits("example.com", 443));
    }

    // BEP-075: CONNECT and absolute-form requests are taken over HTTP/1.1
    // only, and Extended CONNECT and `connect-udp` are refused in either
    // form.
    #[tokio::test]
    async fn connect_and_absolute_form_accepted_over_http11_only() {
        let h = harness().await;

        let mut stream = box_connection(&h.proxy);
        stream.write_all(CONNECT_GITHUB).await.unwrap();
        let head = response_head(&mut stream).await;
        assert_eq!(head, "HTTP/1.1 200 Connection Established\r\n\r\n");
        drop(stream);

        // An absolute-form request is read and decided: plain HTTP to a
        // credentialed host is refused `upstream_not_tls`.
        let answer = exchange(
            &h.proxy,
            b"GET http://api.github.com/zen HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
        assert!(answer.contains("Use https://api.github.com/"), "{answer}");
        assert_eq!(
            h.audit.lock().unwrap().last().unwrap().marker.as_deref(),
            Some(UPSTREAM_NOT_TLS)
        );

        // An https:// absolute-form target is refused the same way, and the
        // message names CONNECT, not the URL the box already used.
        let answer = exchange(
            &h.proxy,
            b"GET https://api.github.com/zen HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden"), "{answer}");
        assert!(
            answer.contains("It carries https to api.github.com through CONNECT only."),
            "{answer}"
        );
        assert!(!answer.contains("in place of"), "{answer}");
        assert_eq!(
            h.audit.lock().unwrap().last().unwrap().marker.as_deref(),
            Some(UPSTREAM_NOT_TLS)
        );

        // HTTP/1.1 only, in both forms.
        for request in [
            &b"CONNECT api.github.com:443 HTTP/1.0\r\nHost: api.github.com:443\r\n\r\n"[..],
            b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n",
        ] {
            let answer = exchange(&h.proxy, request).await;
            assert!(answer.starts_with("HTTP/1.1 505 "), "{answer}");
        }
        // The HTTP/2 prior-knowledge preface is closed with no answer.
        assert_eq!(exchange(&h.proxy, H2_PREFACE_FULL).await, "");

        // Extended CONNECT and `connect-udp`, in either form. A request to
        // an admitted authority leaves no record. One outside the admitted
        // set is also audited `off_module`.
        let off_module = |authority: &str| {
            let audit = h.audit.lock().unwrap();
            let last = audit.last().unwrap();
            assert_eq!(last.authority, authority);
            assert_eq!(last.outcome, Outcome::Refuse);
            assert_eq!(last.marker.as_deref(), Some(OFF_MODULE));
        };
        for (request, record) in [
            (&b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nProtocol: websocket\r\n\r\n"[..], None),
            (b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nUpgrade: connect-udp\r\n\r\n", None),
            (b"GET /.well-known/masque/udp/192.0.2.6/443/ HTTP/1.1\r\nHost: proxy\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n", None),
            (b"GET http://example.com/.well-known/masque/udp/192.0.2.6/443/ HTTP/1.1\r\nHost: example.com\r\n\r\n", Some("example.com:80")),
            (b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProtocol: websocket\r\n\r\n", Some("example.com:443")),
        ] {
            let before = h.audit.lock().unwrap().len();
            let answer = exchange(&h.proxy, request).await;
            assert!(answer.starts_with("HTTP/1.1 501 "), "{answer}");
            match record {
                None => assert_eq!(h.audit.lock().unwrap().len(), before, "{answer}"),
                Some(authority) => {
                    assert_eq!(h.audit.lock().unwrap().len(), before + 1, "{answer}");
                    off_module(authority);
                }
            }
        }

        // An origin-form request is not a proxy request.
        let answer = exchange(&h.proxy, b"GET / HTTP/1.1\r\nHost: proxy\r\n\r\n").await;
        assert!(answer.starts_with("HTTP/1.1 400 "), "{answer}");
    }

    const H2_PREFACE_FULL: &[u8] = http::H2_PREFACE;

    #[tokio::test]
    async fn relay_ends_an_idle_flow_and_an_upstream_close() {
        let audit: Arc<dyn AuditWriter> = Arc::new(Mutex::new(Vec::<Decision>::new()));
        // Neither side sends: the idle limit ends the flow.
        let (boxed, _box_peer) = tokio::io::duplex(1024);
        let (upstream, _up_peer) = tokio::io::duplex(1024);
        tokio::time::timeout(
            Duration::from_secs(10),
            relay(
                "b",
                boxed,
                upstream,
                "github.com:443",
                Arc::clone(&audit),
                Duration::from_millis(200),
            ),
        )
        .await
        .expect("an idle flow ends at its idle limit");
        // The upstream closes while the box stays open and silent: the
        // request half ends with it, long before the idle limit.
        let (boxed, _box_peer) = tokio::io::duplex(1024);
        let (upstream, up_peer) = tokio::io::duplex(1024);
        drop(up_peer);
        tokio::time::timeout(
            Duration::from_secs(10),
            relay(
                "b",
                boxed,
                upstream,
                "github.com:443",
                audit,
                Duration::from_secs(3600),
            ),
        )
        .await
        .expect("the flow ends when the upstream closes");
    }
}
