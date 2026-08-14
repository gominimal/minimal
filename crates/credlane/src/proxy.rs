//! The broker's box-facing request path: authenticate, rewrite, re-originate.
//!
//! There is no HTTP server library anywhere in this workspace, so the shape is
//! the one `crates/minimald/src/net/proxy.rs` already uses: a bounded head read
//! over a raw `tokio` stream, a hand-rolled HTTP/1.1 head parse, then
//! [`tokio::io::copy_bidirectional`]. Responses are never parsed, which is what
//! makes a server-sent-event stream arrive incrementally instead of at
//! end-of-response.
//!
//! Three things depart from that proxy, and each is load-bearing:
//!
//! - It **rewrites** the head rather than replaying it, so it must know where
//!   the head ended. `read_head` there returns one buffer and no split offset —
//!   correct for a verbatim replay, silently body-dropping for a rewrite.
//! - It **terminates and re-originates**. The box's leg is plaintext HTTP/1.1
//!   to loopback; the upstream leg is TLS the broker originates and verifies.
//! - It forces `Connection: close`, because a head parsed once and then spliced
//!   injects on request 1 only, and the primary workload — MCP Streamable HTTP —
//!   posts `initialize` and `notifications/initialized` on one socket.
//!
//! Every refusal is one identical response. See
//! `docs/specs/12-spec-credential-lane/12-spec-credential-lane.md`.

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls_platform_verifier::ConfigVerifierExt as _;
use sessions::core::primitives::validate_credential_lane_name;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::lane::Lane;
use crate::token::Refused;

/// The header a box presents its token in.
///
/// Deliberately not `Authorization`: a lane may inject into `Authorization`
/// itself, and the token header is *removed* on the way out while the lane's
/// header is *replaced*. One header cannot be both.
pub const TOKEN_HEADER: &str = "X-Minimal-Credential-Token";

/// Structured-log component for everything on this path.
const COMPONENT: &str = "credential-broker";

/// End-of-head marker.
const MARKER: &[u8; 4] = b"\r\n\r\n";

/// Largest request head buffered before rewriting. Matches the egress proxy's
/// cap; a head over it is refused rather than buffered unbounded.
const MAX_HEAD: usize = 8 * 1024;

/// How long a client has to finish sending its head before the connection is
/// abandoned, so a socket that opens and never speaks cannot hold a task.
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The one response the box-facing path ever produces on failure.
///
/// An unknown lane, a lane outside the token's scope, a malformed selector, a
/// missing or expired token, an unparseable head, and an upstream that will not
/// connect are all these exact bytes. A refusal that varies enumerates what
/// exists, and the box has nothing to do differently with the distinction.
const REFUSAL: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Headers scoped to a single hop, never relayed.
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
];

/// Headers an inbound `Connection:` token may not name away. A box that could
/// list its own framing there would strip it on the way out, and two hops would
/// then read different requests out of one byte stream.
const UNREMOVABLE: [&str; 3] = ["host", "content-length", "transfer-encoding"];

/// The broker's authorisation and lane lookup, as the request path needs it.
///
/// One method rather than an authenticate step and a lookup step: two failure
/// points are two refusals to keep indistinguishable, and the second one would
/// answer "does this lane exist" for free.
pub trait LaneTable: Send + Sync + 'static {
    /// Resolves `lane` for the box presenting `token`.
    ///
    /// # Errors
    ///
    /// [`Refused`], identically for an unknown or expired token, a lane outside
    /// that token's scope, and a lane the broker does not hold. Implementations
    /// must not narrow it.
    fn resolve(&self, token: &str, lane: &str, now: Instant) -> Result<Lane, Refused>;
}

/// Opens the upstream leg of one client connection.
///
/// A trait because the behavioural tests drive a hand-rolled [`TcpListener`]
/// backend that cannot speak TLS, while a production `upstream` is `https://`
/// by parse-time constraint. Production binds [`TlsUpstream`] and nothing else.
pub trait Connector: Send + Sync + 'static {
    /// The upstream leg's stream.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Connects to `upstream`. Called once per client connection and never
    /// pooled: a pooled connection would carry one token's credential onto
    /// another's request.
    ///
    /// # Errors
    ///
    /// Any connection or TLS failure. The caller turns it into [`REFUSAL`], so
    /// a verification failure is a refusal and never a downgrade.
    fn connect(&self, upstream: &Url) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Originates TLS to the bound upstream, verifying its certificate against the
/// OS trust store.
///
/// Client-side origination has no precedent in this tree — the egress proxy
/// only *terminates* TLS — so the root store comes from
/// `rustls-platform-verifier` rather than a hand-assembled one. There is no
/// plaintext fallback on this path at all: a verification failure fails the
/// connection and the caller refuses.
pub struct TlsUpstream {
    config: Arc<rustls::ClientConfig>,
}

impl TlsUpstream {
    /// Builds the client configuration once, for reuse across connections. The
    /// configuration is shared; the connection never is.
    ///
    /// # Errors
    ///
    /// Returns the `rustls` error if the platform verifier is unavailable.
    pub fn new() -> Result<Self, rustls::Error> {
        // A `ClientConfig` needs a process-default crypto provider. Installing
        // fails when one is already there, which is the outcome we want: the
        // daemon may have installed one for its own TLS, and whichever landed
        // first is the one the whole process uses.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Ok(Self {
            config: Arc::new(rustls::ClientConfig::with_platform_verifier()?),
        })
    }
}

impl Connector for TlsUpstream {
    type Stream = tokio_rustls::client::TlsStream<TcpStream>;

    async fn connect(&self, upstream: &Url) -> io::Result<Self::Stream> {
        let host = upstream
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream has no host"))?;
        let port = upstream
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upstream has no port"))?;
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tcp = TcpStream::connect((host, port)).await?;
        tokio_rustls::TlsConnector::from(Arc::clone(&self.config))
            .connect(name, tcp)
            .await
    }
}

/// Serves the box-facing listener, one task per connection.
///
/// # Errors
///
/// Returns the accept error if the listener fails.
pub async fn serve<T: LaneTable, U: Connector>(
    listener: TcpListener,
    lanes: Arc<T>,
    connector: Arc<U>,
) -> io::Result<()> {
    loop {
        let (client, peer) = listener.accept().await?;
        let lanes = Arc::clone(&lanes);
        let connector = Arc::clone(&connector);
        tokio::spawn(async move {
            if let Err(error) = handle(client, lanes.as_ref(), connector.as_ref()).await {
                // Source address identifies nothing — gvproxy NATs every box
                // connection to loopback — so this is operator context only.
                tracing::debug!(component = COMPONENT, %peer, %error, "connection closed with error");
            }
        });
    }
}

/// Handles one client connection end to end.
async fn handle<C, T, U>(mut client: C, lanes: &T, connector: &U) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: LaneTable,
    U: Connector,
{
    let buffered = match tokio::time::timeout(HEAD_READ_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(buffered)) => buffered,
        Ok(Err(error)) => {
            tracing::debug!(component = COMPONENT, %error, "request head not read");
            return refuse(&mut client).await;
        }
        Err(_elapsed) => return refuse(&mut client).await,
    };

    let Ok(forward) = plan(&buffered, lanes, Instant::now()) else {
        return refuse(&mut client).await;
    };

    let mut upstream = match connector.connect(&forward.upstream).await {
        Ok(upstream) => upstream,
        Err(error) => {
            // Reached only after the token authorised the lane, so it cannot
            // enumerate anything. The operator needs the reason; the box does
            // not get it.
            tracing::warn!(
                component = COMPONENT,
                lane = %forward.lane,
                %error,
                "upstream connection failed"
            );
            return refuse(&mut client).await;
        }
    };

    // The rewritten head *and* the body bytes the head read already took. Writing
    // only the head drops the first chunk of every request whose client sent both
    // in one packet, which is most of them.
    upstream.write_all(forward.head.as_bytes()).await?;
    upstream.write_all(buffered.body()).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// One planned forward.
///
/// `head` carries the injected credential in plaintext, so this type has no
/// `Debug` and must never reach a log or an error message.
struct Forward {
    lane: String,
    upstream: Url,
    head: String,
}

/// Authenticates a buffered request and plans its forward: authenticate, remove
/// the token header, strip the lane's header, inject.
fn plan<T: LaneTable>(buffered: &Buffered, lanes: &T, now: Instant) -> Result<Forward, Refused> {
    let head = parse_head(buffered.head()).ok_or(Refused)?;
    if !head.framing_is_unambiguous() {
        return Err(Refused);
    }
    let selector = Selector::parse(head.target)?;
    let token = head.value(TOKEN_HEADER).ok_or(Refused)?;
    let lane = lanes.resolve(token, selector.lane, now)?;
    let target = selector.upstream_target(lane.upstream());
    Ok(Forward {
        head: rewrite(&head, &lane, &target)?,
        lane: lane.name().to_owned(),
        upstream: lane.upstream().clone(),
    })
}

/// A buffered request head and the body bytes the same read already took.
struct Buffered {
    bytes: Vec<u8>,
    head_end: usize,
}

impl Buffered {
    fn head(&self) -> &[u8] {
        &self.bytes[..self.head_end]
    }

    fn body(&self) -> &[u8] {
        &self.bytes[self.head_end + MARKER.len()..]
    }
}

/// Reads up to and including the end-of-head marker, recording where it is.
///
/// The offset is the whole difference from the egress proxy's `read_head`,
/// which returns a buffer and no split because it replays the head verbatim. A
/// broker that rewrites the head must forward the body bytes this same read
/// already consumed.
///
/// # Errors
///
/// Errors if the head exceeds [`MAX_HEAD`] or the stream ends before the marker.
async fn read_head<C: AsyncRead + Unpin>(client: &mut C) -> io::Result<Buffered> {
    let mut bytes = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before end of request head",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(head_end) = bytes.windows(MARKER.len()).position(|w| w == MARKER) {
            return Ok(Buffered { bytes, head_end });
        }
        if bytes.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeded the maximum size",
            ));
        }
    }
}

/// Writes the single refusal.
async fn refuse<C: AsyncWrite + Unpin>(client: &mut C) -> io::Result<()> {
    client.write_all(REFUSAL).await
}

/// The parsed request head, borrowing the buffer it came from.
struct Head<'a> {
    method: &'a str,
    target: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> Head<'a> {
    /// Every value under `name`, matched case-insensitively.
    fn all(&self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    /// The first value under `name`.
    fn value(&self, name: &'a str) -> Option<&'a str> {
        self.all(name).next()
    }

    /// Whether the head frames its body one way only. Both `Content-Length` and
    /// `Transfer-Encoding`, or two disagreeing lengths, let the broker and the
    /// upstream read different requests out of one stream.
    fn framing_is_unambiguous(&self) -> bool {
        let lengths: BTreeSet<&str> = self.all("content-length").collect();
        if self.all("transfer-encoding").next().is_some() {
            lengths.is_empty()
        } else {
            lengths.len() <= 1
        }
    }

    /// Every header name that dies with this hop: the fixed set plus every
    /// token the inbound `Connection` names.
    fn hop_by_hop(&self) -> Vec<String> {
        let named = self
            .all("connection")
            .flat_map(|value| value.split(','))
            .map(|token| token.trim().to_ascii_lowercase())
            .filter(|token| !UNREMOVABLE.contains(&token.as_str()));
        HOP_BY_HOP
            .iter()
            .map(|name| (*name).to_owned())
            .chain(named)
            .collect()
    }
}

/// Parses a request head, or `None` for anything this broker will not forward.
fn parse_head(bytes: &[u8]) -> Option<Head<'_>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    // HTTP/1.1 only, per the spec's non-goals: no HTTP/2, no prior-knowledge
    // upgrade, and no trailing junk on the request line.
    if parts.next().is_some() || version != "HTTP/1.1" {
        return None;
    }
    // Splitting on `\r\n` leaves a *lone* CR inside a line, and the method and
    // the target's query are the two pieces relayed byte for byte. A lenient
    // upstream that treats a bare CR as a line break would read a second
    // request out of one; a method and a URI are visible ASCII either way.
    if !(is_visible(method) && is_visible(target)) {
        return None;
    }
    let headers = lines.map(parse_header).collect::<Option<Vec<_>>>()?;
    Some(Head {
        method,
        target,
        headers,
    })
}

/// One header line, or `None` for anything that could forge a second line in
/// the rewritten head: an obs-fold continuation, a missing colon, a name that
/// is not a token, or a bare CR or LF that survived the `\r\n` split.
fn parse_header(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    let value = value.trim_matches([' ', '\t']);
    let named = !name.is_empty() && is_visible(name);
    let clean = value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f));
    (named && clean).then_some((name, value))
}

/// Whether every byte is visible ASCII: no space, no control, no DEL, and in
/// particular no bare CR or LF.
fn is_visible(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_graphic())
}

/// What the box's request target selects.
struct Selector<'a> {
    lane: &'a str,
    /// The rest of the path, still percent-encoded. The decode below is a
    /// validation, not a rewrite: the upstream is entitled to the bytes the box
    /// sent, and re-encoding them would change the request it meant to make.
    remainder: Vec<&'a str>,
    query: Option<&'a str>,
}

impl<'a> Selector<'a> {
    /// Reads the lane and its remainder out of a request target.
    fn parse(target: &'a str) -> Result<Self, Refused> {
        let path_and_query = origin_form(target).ok_or(Refused)?;
        let (path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        let mut segments = path.strip_prefix('/').ok_or(Refused)?.split('/');
        let lane = segments.next().ok_or(Refused)?;
        // The grammar is the same one the lane name was parsed against, so a
        // percent-encoded or otherwise dressed-up selector never matches.
        validate_credential_lane_name(lane).map_err(|_| Refused)?;
        let remainder = segments
            .map(checked_segment)
            .collect::<Result<Vec<_>, Refused>>()?;
        Ok(Self {
            lane,
            remainder,
            query,
        })
    }

    /// The request target sent upstream: the bound upstream's own path with the
    /// validated remainder appended, so the result is always under it.
    fn upstream_target(&self, upstream: &Url) -> String {
        let mut target = if self.remainder.is_empty() {
            upstream.path().to_owned()
        } else {
            let mut base = upstream.path().trim_end_matches('/').to_owned();
            for segment in &self.remainder {
                base.push('/');
                base.push_str(segment);
            }
            base
        };
        if target.is_empty() {
            target.push('/');
        }
        if let Some(query) = self.query.or_else(|| upstream.query()) {
            target.push('?');
            target.push_str(query);
        }
        target
    }
}

/// The path-and-query of a request target in either the origin form a direct
/// client sends (`/lane/rest`) or the absolute form a proxy-configured one does
/// (`http://anything/lane/rest`).
///
/// The absolute form's authority is discarded rather than consulted. A
/// box-supplied selector is permitted and validated; a box-supplied upstream is
/// never honoured.
fn origin_form(target: &str) -> Option<&str> {
    if target.starts_with('/') {
        return Some(target);
    }
    let (_, authority_and_path) = target.split_once("://")?;
    Some(&authority_and_path[authority_and_path.find('/')?..])
}

/// A remainder segment that cannot escape the bound upstream's path.
///
/// Decoding is what makes `%2e%2e` the same refusal as `..`; rejecting a
/// decoded `/` is what stops one segment smuggling two past that check.
fn checked_segment(segment: &str) -> Result<&str, Refused> {
    let decoded = percent_decode(segment)?;
    let escapes = decoded.as_slice() == b"."
        || decoded.as_slice() == b".."
        || decoded
            .iter()
            .any(|b| matches!(b, b'/' | b'\\') || b.is_ascii_control());
    if escapes { Err(Refused) } else { Ok(segment) }
}

/// Percent-decodes one path segment.
///
/// A malformed escape is a refusal rather than a literal `%`: an upstream that
/// decoded it differently to this check is exactly the disagreement a traversal
/// needs.
fn percent_decode(segment: &str) -> Result<Vec<u8>, Refused> {
    let mut decoded = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let escape = [bytes.next().ok_or(Refused)?, bytes.next().ok_or(Refused)?];
        if !escape.iter().all(u8::is_ascii_hexdigit) {
            return Err(Refused);
        }
        let text = std::str::from_utf8(&escape).map_err(|_| Refused)?;
        decoded.push(u8::from_str_radix(text, 16).map_err(|_| Refused)?);
    }
    Ok(decoded)
}

/// Builds the head sent upstream.
///
/// The return value carries the credential in plaintext; it is written to the
/// upstream socket and nowhere else.
///
/// # Errors
///
/// [`Refused`] if the resolved credential could forge a header line. The
/// declaration's prefix is checked where it is parsed, but the value is
/// whatever a resolver read — and a secret file with a trailing newline is the
/// ordinary case, not the adversarial one.
fn rewrite(head: &Head<'_>, lane: &Lane, target: &str) -> Result<String, Refused> {
    let value = lane.inject().header_value(lane.secret());
    if !value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
    {
        tracing::warn!(
            component = COMPONENT,
            lane = %lane.name(),
            remedy = "strip the trailing newline or control characters from the bound source",
            "the resolved credential cannot be injected as a header value"
        );
        return Err(Refused);
    }
    let hop_by_hop = head.hop_by_hop();
    let injected = lane.inject().header();
    let mut out = format!(
        "{} {target} HTTP/1.1\r\nHost: {}\r\n",
        head.method,
        authority(lane.upstream())
    );
    for (name, value) in &head.headers {
        let lowered = name.to_ascii_lowercase();
        let relayed = lowered != "host"
            && !hop_by_hop.contains(&lowered)
            && !name.eq_ignore_ascii_case(TOKEN_HEADER)
            && !name.eq_ignore_ascii_case(injected);
        if relayed {
            push_header(&mut out, name, value);
        }
    }
    push_header(&mut out, injected, &value);
    // Not merely stripping the inbound `Connection`: HTTP/1.1 is persistent by
    // default, so stripping keep-alive is a no-op and request 2 on a pooled
    // socket would reach the upstream with no credential at all.
    out.push_str("Connection: close\r\n\r\n");
    Ok(out)
}

/// Appends one header line. Both halves were validated as CR/LF-free where
/// they were parsed, so this cannot forge a second line.
fn push_header(head: &mut String, name: &str, value: &str) {
    head.push_str(name);
    head.push_str(": ");
    head.push_str(value);
    head.push_str("\r\n");
}

/// The `Host:` value for an upstream: host and non-default port, never the
/// userinfo `Url::authority` would include.
fn authority(upstream: &Url) -> String {
    let host = upstream.host_str().unwrap_or_default();
    match upstream.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;

    use tokio::sync::oneshot;

    use super::*;
    use crate::lane::{Inject, Secret};
    use crate::token::{Token, TokenStore};

    /// Every request a hand-rolled backend was sent, in arrival order.
    type Recorder = Arc<Mutex<Vec<Vec<u8>>>>;

    const SECRET: &str = "sk-live-hunter2";
    const TTL: Duration = Duration::from_mins(1);
    /// Long enough that a broker which buffered a stream, or dropped a body,
    /// fails the test instead of hanging it.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// The shape Unit 5's registry will have: a token store plus the lanes the
    /// client registered, resolved in one step so refusals cannot diverge.
    struct TestTable {
        store: TokenStore,
        lanes: HashMap<String, Lane>,
    }

    impl LaneTable for TestTable {
        fn resolve(&self, token: &str, lane: &str, now: Instant) -> Result<Lane, Refused> {
            self.store.authorize(token, lane, now)?;
            self.lanes.get(lane).cloned().ok_or(Refused)
        }
    }

    /// The plaintext upstream leg. `#[cfg(test)]` on purpose: production
    /// upstreams are `https://` by parse-time constraint, and a plaintext
    /// connector reachable from the daemon would be a downgrade waiting to be
    /// wired up.
    struct PlaintextUpstream;

    impl Connector for PlaintextUpstream {
        type Stream = TcpStream;

        async fn connect(&self, upstream: &Url) -> io::Result<Self::Stream> {
            let host = upstream.host_str().unwrap_or("127.0.0.1").to_owned();
            let port = upstream.port_or_known_default().unwrap_or(80);
            TcpStream::connect((host, port)).await
        }
    }

    fn lane(name: &str, upstream: &str, header: &str) -> Lane {
        Lane::new(
            name,
            Url::parse(upstream).unwrap(),
            Inject::new(header, ""),
            Secret::new(SECRET),
        )
    }

    /// Starts a broker holding `lanes`, with a token scoped to `scope`.
    async fn spawn_broker(lanes: Vec<Lane>, scope: &[&str]) -> (SocketAddr, Token) {
        let mut store = TokenStore::new();
        let (token, _) = store.mint(
            scope.iter().map(|name| (*name).to_owned()),
            Instant::now(),
            TTL,
        );
        let table = TestTable {
            store,
            lanes: lanes
                .into_iter()
                .map(|lane| (lane.name().to_owned(), lane))
                .collect(),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            Arc::new(table),
            Arc::new(PlaintextUpstream),
        ));
        (addr, token)
    }

    /// Reads one whole request: the head, plus a `Content-Length` body when the
    /// head declares one. Without the body wait, a dropped body would look like
    /// a well-formed request rather than a failure.
    async fn read_request(sock: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        // A reset connection ends the record; the assertions read what arrived,
        // and a short record is the failure the test reports.
        while let Ok(read) = sock.read(&mut chunk).await {
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            let Some(end) = buf.windows(4).position(|w| w == MARKER) else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let declared = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + MARKER.len() + declared {
                break;
            }
        }
        buf
    }

    /// A hand-rolled upstream recording every request it is sent, answering
    /// `200` and closing. Returns its URL and the shared record.
    async fn spawn_backend() -> (String, Recorder) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let recorder = Arc::clone(&recorder);
                tokio::spawn(async move {
                    let request = read_request(&mut sock).await;
                    recorder.lock().unwrap().push(request);
                    // The record is the assertion; a client that hung up before
                    // the answer is not this backend's problem.
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}/base/"), seen)
    }

    /// The single request the backend received, as text.
    fn sole_request(seen: &Recorder) -> String {
        let recorded = seen.lock().unwrap();
        assert_eq!(recorded.len(), 1, "expected exactly one upstream request");
        String::from_utf8_lossy(&recorded[0]).into_owned()
    }

    fn get(target: &str, token: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: broker.invalid\r\n{TOKEN_HEADER}: {token}\r\n\r\n")
    }

    /// Sends `request`, half-closes, and reads the whole response. The
    /// half-close is what lets a backend waiting on a body see end-of-stream
    /// rather than deadlocking the test.
    async fn round_trip(broker: SocketAddr, request: &str) -> String {
        let exchange = async {
            let mut client = TcpStream::connect(broker).await.unwrap();
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            // A refused connection can be reset once the refusal is written;
            // what arrived before that is exactly what the assertions read.
            let _ = client.read_to_end(&mut response).await;
            String::from_utf8_lossy(&response).into_owned()
        };
        tokio::time::timeout(PATIENCE, exchange)
            .await
            .expect("the broker must answer every request")
    }

    /// Reads until `marker` appears, failing rather than hanging if it never
    /// does.
    async fn read_until(stream: &mut TcpStream, marker: &str) -> String {
        let accumulate = async {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "stream ended before {marker:?}");
                buf.extend_from_slice(&chunk[..read]);
                if String::from_utf8_lossy(&buf).contains(marker) {
                    return String::from_utf8_lossy(&buf).into_owned();
                }
            }
        };
        tokio::time::timeout(PATIENCE, accumulate)
            .await
            .unwrap_or_else(|_| panic!("{marker:?} never arrived"))
    }

    #[tokio::test]
    async fn the_lane_header_is_replaced_with_the_injected_credential() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        let response = round_trip(broker, &get("/anthropic/v1/messages", token.expose())).await;

        assert!(response.contains("200 OK"), "{response}");
        let forwarded = sole_request(&seen);
        assert!(
            forwarded.contains(&format!("x-api-key: {SECRET}")),
            "{forwarded}"
        );
        assert!(
            forwarded.starts_with("GET /base/v1/messages HTTP/1.1\r\n"),
            "the remainder must land under the bound upstream's path: {forwarded}"
        );
        assert!(
            forwarded.contains("Host: 127.0.0.1:"),
            "Host: must be the upstream authority, not the broker's: {forwarded}"
        );
    }

    #[tokio::test]
    async fn a_box_supplied_lane_header_never_reaches_the_upstream() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        // Two occurrences, neither in the configured casing: a strip that is
        // case-sensitive or first-match-only lets one through.
        let request = format!(
            "GET /anthropic/v1 HTTP/1.1\r\nHost: broker.invalid\r\n\
             {TOKEN_HEADER}: {}\r\nX-API-Key: box-shadow\r\nx-api-KEY: box-echo\r\n\r\n",
            token.expose()
        );
        round_trip(broker, &request).await;

        let forwarded = sole_request(&seen);
        assert!(!forwarded.contains("box-shadow"), "{forwarded}");
        assert!(!forwarded.contains("box-echo"), "{forwarded}");
        assert_eq!(
            forwarded.to_ascii_lowercase().matches("x-api-key:").count(),
            1,
            "exactly one injected header must survive: {forwarded}"
        );
    }

    #[tokio::test]
    async fn the_capability_token_is_not_forwarded_to_the_upstream() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "authorization")],
            &["anthropic"],
        )
        .await;

        round_trip(broker, &get("/anthropic/v1", token.expose())).await;

        let forwarded = sole_request(&seen);
        assert!(
            !forwarded.contains(token.expose()),
            "the box's token must not reach the upstream: {forwarded}"
        );
        assert!(
            !forwarded
                .to_ascii_lowercase()
                .contains(&TOKEN_HEADER.to_ascii_lowercase()),
            "{forwarded}"
        );
    }

    #[tokio::test]
    async fn a_second_request_on_one_socket_is_never_forwarded_bare() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        let mut client = TcpStream::connect(broker).await.unwrap();
        let keep_alive = format!(
            "GET /anthropic/one HTTP/1.1\r\nHost: broker.invalid\r\n\
             {TOKEN_HEADER}: {}\r\nConnection: keep-alive\r\n\r\n",
            token.expose()
        );
        client.write_all(keep_alive.as_bytes()).await.unwrap();
        read_until(&mut client, "200 OK").await;
        client
            .write_all(get("/anthropic/two", token.expose()).as_bytes())
            .await
            .unwrap();
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(PATIENCE, client.read_to_end(&mut rest)).await;

        let forwarded = sole_request(&seen);
        assert!(
            forwarded.contains("Connection: close\r\n"),
            "the upstream must be told to close, or request two goes bare: {forwarded}"
        );
        assert!(
            !forwarded.to_ascii_lowercase().contains("keep-alive"),
            "{forwarded}"
        );
    }

    #[tokio::test]
    async fn a_body_sent_with_the_head_arrives_at_the_upstream_intact() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        // One write, so the head read buffers the body too — the case where a
        // rewrite that forgets the split offset silently drops it.
        let body = r#"{"hello":"world"}"#;
        let request = format!(
            "POST /anthropic/v1/messages HTTP/1.1\r\nHost: broker.invalid\r\n\
             {TOKEN_HEADER}: {}\r\nContent-Length: {}\r\n\r\n{body}",
            token.expose(),
            body.len()
        );
        round_trip(broker, &request).await;

        let forwarded = sole_request(&seen);
        assert!(
            forwarded.ends_with(body),
            "the buffered body must be forwarded: {forwarded}"
        );
    }

    #[tokio::test]
    async fn a_response_reaches_the_box_before_the_upstream_has_finished_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release, released) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            read_request(&mut sock).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: one\n\n",
            )
            .await
            .unwrap();
            // Nothing more until the test says it saw the first event, so a
            // broker that buffered the response deadlocks and the read times
            // out rather than passing.
            released.await.unwrap();
            sock.write_all(b"data: two\n\n").await.unwrap();
        });

        let upstream = format!("http://127.0.0.1:{port}/base/");
        let (broker, token) =
            spawn_broker(vec![lane("sink", &upstream, "x-api-key")], &["sink"]).await;

        let mut client = TcpStream::connect(broker).await.unwrap();
        client
            .write_all(get("/sink/events", token.expose()).as_bytes())
            .await
            .unwrap();
        let first = read_until(&mut client, "data: one").await;
        assert!(!first.contains("data: two"), "{first}");

        release.send(()).unwrap();
        let second = read_until(&mut client, "data: two").await;
        assert!(second.contains("data: two"), "{second}");
    }

    #[tokio::test]
    async fn a_traversal_in_the_selector_remainder_is_refused() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        let baseline = round_trip(broker, &get("/anthropic/v1", "not-a-token")).await;
        for target in [
            "/anthropic/../v1/admin",
            "/anthropic/%2e%2e/v1/admin",
            "/anthropic/%2E%2e/v1/admin",
            "/anthropic/a%2Fb",
            "/anthropic/%zz",
        ] {
            assert_eq!(
                round_trip(broker, &get(target, token.expose())).await,
                baseline,
                "{target} must be refused exactly as an unknown token is"
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "no traversal attempt may reach the upstream"
        );
    }

    #[tokio::test]
    async fn an_out_of_scope_lane_is_refused_byte_identically_to_an_unknown_token() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![
                lane("anthropic", &upstream, "x-api-key"),
                lane("github-mcp", &upstream, "authorization"),
            ],
            &["anthropic"],
        )
        .await;

        let out_of_scope = round_trip(broker, &get("/github-mcp/v1", token.expose())).await;
        let unknown_token = round_trip(broker, &get("/anthropic/v1", "deadbeef")).await;
        let unknown_lane = round_trip(broker, &get("/nosuchlane/v1", token.expose())).await;

        assert!(!out_of_scope.is_empty());
        assert_eq!(out_of_scope, unknown_token);
        assert_eq!(out_of_scope, unknown_lane);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_credential_that_would_forge_a_header_line_is_refused_not_injected() {
        let (upstream, seen) = spawn_backend().await;
        let newline_terminated = Lane::new(
            "anthropic",
            Url::parse(&upstream).unwrap(),
            Inject::new("x-api-key", ""),
            // What a resolver gets from `cat ~/.secrets/token` without care.
            Secret::new("sk-live-hunter2\nX-Injected: yes"),
        );
        let (broker, token) = spawn_broker(vec![newline_terminated], &["anthropic"]).await;

        let refused = round_trip(broker, &get("/anthropic/v1", token.expose())).await;
        let baseline = round_trip(broker, &get("/anthropic/v1", "not-a-token")).await;

        assert_eq!(refused, baseline);
        assert!(seen.lock().unwrap().is_empty(), "nothing may be forwarded");
    }

    #[tokio::test]
    async fn an_absolute_form_target_selects_a_lane_but_never_an_upstream() {
        let (upstream, seen) = spawn_backend().await;
        let (broker, token) = spawn_broker(
            vec![lane("anthropic", &upstream, "x-api-key")],
            &["anthropic"],
        )
        .await;

        let request = format!(
            "GET http://evil.example/anthropic/v1 HTTP/1.1\r\nHost: evil.example\r\n\
             {TOKEN_HEADER}: {}\r\n\r\n",
            token.expose()
        );
        round_trip(broker, &request).await;

        let forwarded = sole_request(&seen);
        assert!(
            forwarded.starts_with("GET /base/v1 HTTP/1.1\r\n"),
            "{forwarded}"
        );
        assert!(!forwarded.contains("evil.example"), "{forwarded}");
    }

    #[test]
    fn a_connection_token_cannot_name_away_the_bodys_framing() {
        let head = parse_head(
            b"POST /anthropic/v1 HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: content-length, x-trace",
        )
        .unwrap();
        let dropped = head.hop_by_hop();
        assert!(dropped.contains(&"x-trace".to_owned()));
        assert!(!dropped.contains(&"content-length".to_owned()));
    }

    #[test]
    fn a_head_that_could_forge_a_line_or_frame_two_requests_does_not_parse() {
        assert!(parse_head(b"GET /a HTTP/2.0\r\nHost: x").is_none());
        assert!(parse_head(b"PRI * HTTP/2.0\r\n\r\nSM").is_none());
        assert!(parse_head(b"GET /a HTTP/1.1\r\n\tfolded: yes").is_none());
        assert!(parse_head(b"GET /a HTTP/1.1\r\nX: a\nEvil: b").is_none());
        // A bare CR survives the `\r\n` split, so it must not survive the parse.
        assert!(parse_head(b"GET /a?x=1\rHost:evil HTTP/1.1\r\nHost: x").is_none());
        assert!(parse_head(b"GE\rT /a HTTP/1.1\r\nHost: x").is_none());
        assert!(
            !parse_head(b"POST /a HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked")
                .unwrap()
                .framing_is_unambiguous()
        );
        assert!(
            !parse_head(b"POST /a HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4")
                .unwrap()
                .framing_is_unambiguous()
        );
    }

    #[test]
    fn the_remainder_lands_under_the_bound_upstreams_path_whatever_its_shape() {
        let cases = [
            ("https://api.example.com/mcp/", "/lane/a/b", "/mcp/a/b"),
            ("https://api.example.com/mcp", "/lane/a", "/mcp/a"),
            ("https://api.example.com/mcp/", "/lane", "/mcp/"),
            ("https://api.example.com/", "/lane/v1", "/v1"),
            ("https://api.example.com", "/lane", "/"),
            ("https://api.example.com/mcp/", "/lane/a?x=1", "/mcp/a?x=1"),
        ];
        for (upstream, target, expected) in cases {
            let upstream = Url::parse(upstream).unwrap();
            let selector = Selector::parse(target).unwrap();
            assert_eq!(selector.lane, "lane");
            assert_eq!(selector.upstream_target(&upstream), expected, "{target}");
        }
    }
}
