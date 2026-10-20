//! The strict HTTP/1.1 head parser and the canonical re-serializer
//! (BEP-074, BEP-076, BEP-077).
//!
//! The proxy never forwards the head bytes a box wrote. It parses the head
//! under strict rules, and it writes the canonical serialization of the
//! parsed request upstream. A box that authors ambiguous framing can then
//! not desync the proxy's parser from the upstream's parser.
//!
//! The parser closes the connection, with a [`CloseReason`], when:
//!
//! - the flow opens with the HTTP/2 prior-knowledge preface (BEP-074),
//! - the framing is ambiguous (BEP-077): `Content-Length` together with
//!   `Transfer-Encoding`, more than one `Content-Length` value, an obsolete
//!   line fold, or a transfer coding other than one final `chunked`,
//! - the head is malformed or too large.
//!
//! A request that asks for `Upgrade: h2c` stays HTTP/1.1. The parser removes
//! the `h2c` upgrade token, its `Connection` token and `HTTP2-Settings`
//! (BEP-074). On the response side, [`relay_response_head`] removes every
//! `Alt-Svc` header (BEP-076).
//!
//! [`relay_request_body`] relays the body under the framing that the parsed
//! head declares. It copies exactly `Content-Length` bytes, or it parses the
//! chunked framing from the box and writes canonical chunks upstream. Raw
//! chunked bytes from the box never reach the upstream. [`forward_requests`]
//! is the request half of one box connection: it forwards heads and bodies
//! until the connection closes, and it logs the rule that closed it. It
//! stops at a request that switches protocol (`Upgrade` or `CONNECT`), and
//! it never parses the bytes after that request as HTTP.
//!
//! The canonical form is: `METHOD SP target SP HTTP/1.1 CRLF`, then one
//! `name: value CRLF` line for each header, in the order received, with the
//! name in lowercase and the value with no leading or trailing whitespace,
//! then `CRLF`.

use std::fmt;
use std::io::{self, Read, Write};

/// The HTTP/2 prior-knowledge connection preface (RFC 9113 §3.4).
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The largest request or response head the proxy reads, in bytes.
pub const MAX_HEAD_LEN: usize = 64 * 1024;

/// The audit marker of a request refused for its framing (BEP-077).
pub const FRAMING_AMBIGUOUS: &str = "framing_ambiguous";

/// The longest chunk-size line or trailer line the proxy reads, in bytes.
pub const MAX_CHUNK_LINE_LEN: usize = 4096;

/// The request line of the HTTP/2 preface.
const H2_PREFACE_LINE: &[u8] = b"PRI * HTTP/2.0";

/// One header field: the name in lowercase and the trimmed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The field name, in lowercase.
    pub name: String,
    /// The field value, with no leading or trailing whitespace.
    pub value: Vec<u8>,
}

/// How the request body is framed, after the strict checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body.
    None,
    /// A body of exactly this many bytes.
    ContentLength(u64),
    /// A chunked body.
    Chunked,
}

/// A parsed HTTP/1.1 request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method token.
    pub method: String,
    /// The request target, as received.
    pub target: String,
    /// The header fields, in the order received.
    pub headers: Vec<Header>,
    /// The body framing that the headers declare.
    pub body: BodyFraming,
}

impl Request {
    /// The canonical serialization of this request head. The proxy forwards
    /// these bytes, and never the bytes the box wrote (BEP-077).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.headers.len() * 32);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        write_headers(&mut out, &self.headers);
        out
    }

    /// Whether the request asks to leave HTTP/1.1: the `CONNECT` method, or
    /// an `Upgrade` header that the h2c strip left.
    #[must_use]
    pub fn switches_protocol(&self) -> bool {
        self.method == "CONNECT" || self.headers.iter().any(|h| h.name == "upgrade")
    }

    /// The values of every header named `name`, in order.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        values(&self.headers, name)
    }
}

/// A parsed HTTP/1.x response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The minor version: `1` for HTTP/1.1, `0` for HTTP/1.0.
    pub minor_version: u8,
    /// The three-digit status code.
    pub status: u16,
    /// The reason phrase, as received.
    pub reason: Vec<u8>,
    /// The header fields, in the order received.
    pub headers: Vec<Header>,
}

impl Response {
    /// The canonical serialization of this response head.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.headers.len() * 32);
        out.extend_from_slice(
            format!("HTTP/1.{} {:03} ", self.minor_version, self.status).as_bytes(),
        );
        out.extend_from_slice(&self.reason);
        out.extend_from_slice(b"\r\n");
        write_headers(&mut out, &self.headers);
        out
    }

    /// Remove every `Alt-Svc` header (BEP-076).
    pub fn strip_alt_svc(&mut self) {
        self.headers.retain(|h| h.name != "alt-svc");
    }
}

/// The framing rule that makes a request head ambiguous (BEP-077).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambiguity {
    /// `Content-Length` and `Transfer-Encoding` together.
    ContentLengthWithTransferEncoding,
    /// More than one `Content-Length` value, equal or not.
    DuplicateContentLength,
    /// A `Content-Length` value that is not one decimal number.
    InvalidContentLength,
    /// A header line continued on the next line (obs-fold).
    ObsoleteLineFold,
    /// A transfer coding other than one final `chunked`.
    TransferCodingNotFinalChunked,
    /// A `Connection` option that names `Content-Length` or
    /// `Transfer-Encoding`. A later hop that honours it removes the framing
    /// header and reads the body in a different way.
    ConnectionNamesFramingHeader,
}

impl Ambiguity {
    /// The rule name, for the audit detail and the debug log.
    #[must_use]
    pub fn rule(self) -> &'static str {
        match self {
            Self::ContentLengthWithTransferEncoding => "content_length_with_transfer_encoding",
            Self::DuplicateContentLength => "duplicate_content_length",
            Self::InvalidContentLength => "invalid_content_length",
            Self::ObsoleteLineFold => "obsolete_line_fold",
            Self::TransferCodingNotFinalChunked => "transfer_coding_not_final_chunked",
            Self::ConnectionNamesFramingHeader => "connection_names_framing_header",
        }
    }
}

/// Why the proxy closed a connection while it read a head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// The flow opened with the HTTP/2 prior-knowledge preface (BEP-074).
    H2Preface,
    /// The framing of the request is ambiguous (BEP-077).
    FramingAmbiguous(Ambiguity),
    /// The head breaks the HTTP/1.1 grammar. The text names the rule.
    Malformed(&'static str),
    /// The head is longer than [`MAX_HEAD_LEN`].
    HeadTooLarge,
    /// The peer closed the connection before the head was complete.
    Eof,
    /// The box closed the connection before the body was complete.
    BodyEof,
    /// The box closed the connection cleanly, between two requests.
    ClientClosed,
    /// The read or the write failed.
    Io(io::ErrorKind),
    /// The request asked to leave HTTP/1.1, with an `Upgrade` header or the
    /// `CONNECT` method. The request half stops parsing, because the bytes
    /// after the switch are not HTTP. `rest` holds the bytes already read
    /// after the request. The caller relays `rest` and the rest of the box's
    /// bytes unparsed only when the upstream accepts the switch: `101` to an
    /// upgrade, or `2xx` to a `CONNECT`. Otherwise it closes the connection.
    /// It never gives this upstream connection back to the pool.
    ProtocolSwitch {
        /// The bytes read from the box after the request.
        rest: Vec<u8>,
    },
}

impl CloseReason {
    /// The audit marker of this close, when the close is an audited
    /// refusal.
    #[must_use]
    pub fn audit_marker(&self) -> Option<&'static str> {
        match self {
            Self::FramingAmbiguous(_) => Some(FRAMING_AMBIGUOUS),
            _ => None,
        }
    }

    /// The framing rule that closed the connection, for the one debug log
    /// line the caller writes for each closed connection.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::H2Preface => "h2_prior_knowledge_preface",
            Self::FramingAmbiguous(a) => a.rule(),
            Self::Malformed(rule) => rule,
            Self::HeadTooLarge => "head_too_large",
            Self::Eof => "eof_before_head_end",
            Self::BodyEof => "eof_before_body_end",
            Self::ClientClosed => "client_closed",
            Self::Io(_) => "io_error",
            Self::ProtocolSwitch { .. } => "protocol_switch_requested",
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FramingAmbiguous(_) => write!(f, "{FRAMING_AMBIGUOUS}: {}", self.rule()),
            Self::Io(kind) => write!(f, "io_error: {kind}"),
            _ => f.write_str(self.rule()),
        }
    }
}

impl std::error::Error for CloseReason {}

/// The result of one parse attempt on a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parse<T> {
    /// The head is complete. `head_len` is the length of the head in the
    /// buffer, its final empty line included.
    Complete {
        /// The parsed head.
        head: T,
        /// The number of buffer bytes the head used.
        head_len: usize,
    },
    /// The buffer does not hold a complete head yet.
    Partial,
}

/// An audit event that a refused head records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The box that sent the head.
    pub box_id: String,
    /// The audit marker, for example [`FRAMING_AMBIGUOUS`].
    pub marker: &'static str,
    /// The rule that the head broke.
    pub rule: &'static str,
}

/// Where the proxy records audit events.
pub trait AuditSink {
    /// Record one event.
    fn record(&mut self, event: AuditEvent);
}

impl AuditSink for Vec<AuditEvent> {
    fn record(&mut self, event: AuditEvent) {
        self.push(event);
    }
}

/// A request head that the proxy forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    /// The parsed request. Its [`Request::serialize`] bytes went upstream.
    pub request: Request,
    /// The bytes read after the head: the start of the body, or the next
    /// request.
    pub rest: Vec<u8>,
}

/// Parse one request head from the start of `buf`.
///
/// # Errors
///
/// Returns the [`CloseReason`] when the proxy must close the connection.
pub fn parse_request(buf: &[u8]) -> Result<Parse<Request>, CloseReason> {
    if is_h2_preface_start(buf) {
        return Err(CloseReason::H2Preface);
    }
    let Some(head_len) = head_end(buf)? else {
        return Ok(Parse::Partial);
    };
    let mut lines = head_lines(&buf[..head_len - 4]);
    let first = lines.next().unwrap_or(Ok(&[]))?;
    if first == H2_PREFACE_LINE {
        return Err(CloseReason::H2Preface);
    }
    let (method, target) = parse_request_line(first)?;
    let headers = parse_headers(lines)?;
    // RFC 9112 §3.2: a request with more than one Host field is invalid. Two
    // hosts leave the authority that the proxy checks open to doubt.
    if headers.iter().filter(|h| h.name == "host").count() > 1 {
        return Err(CloseReason::Malformed("duplicate_host"));
    }
    let body = framing(&headers)?;
    // RFC 9112 §3.2: an HTTP/1.1 request carries exactly one Host. An
    // absolute-form target names the authority too, and the two must agree,
    // so that the upstream and the policy see one authority.
    let Some(host) = values(&headers, "host").next() else {
        return Err(CloseReason::Malformed("missing_host"));
    };
    // RFC 9112 §3.2: Host is `uri-host [ ":" port ]`. A value that is not a
    // plain host and port can be read one way here and another upstream.
    if !is_host_authority(host) {
        return Err(CloseReason::Malformed("invalid_host"));
    }
    if let Some((scheme, authority)) = absolute_form_authority(target.as_bytes())
        && !same_authority(scheme, authority, host)
    {
        return Err(CloseReason::Malformed("target_host_mismatch"));
    }
    // RFC 9110 §9.3.6: a CONNECT target is authority-form, `host:port`. The
    // tunnel goes to that authority, so it must agree with Host as an
    // absolute-form target does. Port 443 equals no port in Host.
    if method == "CONNECT"
        && !(is_connect_authority(target.as_bytes())
            && same_authority("https", target.as_bytes(), host))
    {
        return Err(CloseReason::Malformed("target_host_mismatch"));
    }
    if list_elements(values(&headers, "connection")).any(|t| t.eq_ignore_ascii_case(b"host")) {
        return Err(CloseReason::Malformed("connection_names_host"));
    }
    let mut request = Request {
        method,
        target,
        headers,
        body,
    };
    strip_h2c(&mut request.headers);
    Ok(Parse::Complete {
        head: request,
        head_len,
    })
}

/// Parse one response head from the start of `buf`.
///
/// The response gets the same strict framing rules as a request, on
/// purpose. A hostile upstream must not desync the box's connection, and
/// the proxy reads no response framing that it cannot check. So a
/// response that HTTP/1.1 permits but that these rules refuse closes the
/// connection as framing ambiguous. Examples are `Transfer-Encoding:
/// gzip, chunked`, a repeated equal `Content-Length`, or a `Connection`
/// option that names a framing header. The framing result is not kept:
/// the head parser does not know the request method, so the caller
/// decides the body of a reply to `HEAD` or of a `1xx`, `204` or `304`.
///
/// # Errors
///
/// Returns the [`CloseReason`] when the head breaks the grammar or the
/// framing rules.
pub fn parse_response(buf: &[u8]) -> Result<Parse<Response>, CloseReason> {
    let Some(head_len) = head_end(buf)? else {
        return Ok(Parse::Partial);
    };
    let mut lines = head_lines(&buf[..head_len - 4]);
    let first = lines.next().unwrap_or(Ok(&[]))?;
    let (minor_version, status, reason) = parse_status_line(first)?;
    let headers = parse_headers(lines)?;
    // The same framing rules as for a request, so that a hostile upstream
    // cannot desync the box's connection.
    framing(&headers)?;
    Ok(Parse::Complete {
        head: Response {
            minor_version,
            status,
            reason,
            headers,
        },
        head_len,
    })
}

/// Read one request head from `client`, and write its canonical
/// serialization to `upstream`.
///
/// On a refusal nothing reaches `upstream`. A refusal for framing records a
/// [`FRAMING_AMBIGUOUS`] event for `box_id` in `audit`. The caller then
/// drops the connection and logs [`CloseReason::rule`].
///
/// # Errors
///
/// Returns the [`CloseReason`] when the proxy must close the connection.
pub fn forward_request_head<R: Read, W: Write>(
    box_id: &str,
    client: &mut R,
    upstream: &mut W,
    audit: &mut dyn AuditSink,
) -> Result<Forwarded, CloseReason> {
    forward_head(box_id, Vec::new(), client, upstream, audit)
}

/// [`forward_request_head`], with `pending` bytes already read from the box.
fn forward_head<R: Read, W: Write>(
    box_id: &str,
    pending: Vec<u8>,
    client: &mut R,
    upstream: &mut W,
    audit: &mut dyn AuditSink,
) -> Result<Forwarded, CloseReason> {
    let result = read_head(pending, client, parse_request).and_then(|(request, rest)| {
        upstream
            .write_all(&request.serialize())
            .map_err(|e| CloseReason::Io(e.kind()))?;
        // Flush now: the box can hold its body until the upstream answers
        // `Expect: 100-continue`, so the head must not wait in a buffer.
        upstream.flush().map_err(|e| CloseReason::Io(e.kind()))?;
        Ok(Forwarded { request, rest })
    });
    if let Err(reason) = &result
        && let Some(marker) = reason.audit_marker()
    {
        audit.record(AuditEvent {
            box_id: box_id.to_owned(),
            marker,
            rule: reason.rule(),
        });
    }
    result
}

/// Read one response head from `upstream`, remove every `Alt-Svc` header
/// (BEP-076), and write the canonical serialization to `client`.
///
/// Returns the response as relayed and the bytes read after its head.
///
/// # Errors
///
/// Returns the [`CloseReason`] when the proxy must close the connection.
pub fn relay_response_head<R: Read, W: Write>(
    upstream: &mut R,
    client: &mut W,
) -> Result<(Response, Vec<u8>), CloseReason> {
    let (mut response, rest) = read_head(Vec::new(), upstream, parse_response)?;
    response.strip_alt_svc();
    client
        .write_all(&response.serialize())
        .map_err(|e| CloseReason::Io(e.kind()))?;
    Ok((response, rest))
}

/// Relay the body of a forwarded request from `client` to `upstream`, under
/// the framing that its parsed head declares.
///
/// A `Content-Length` body is copied as exactly that many bytes, starting
/// with [`Forwarded::rest`]. A chunked body is parsed chunk by chunk, and
/// each chunk goes upstream in the canonical form `size-in-hex CRLF data
/// CRLF`. Chunk extensions and trailer fields are dropped, and the body ends
/// with `0 CRLF CRLF`.
///
/// Returns the bytes read after the body: the start of the next request.
///
/// On an error, part of the body can already be upstream. The caller then
/// drops both connections, and never gives the upstream one back.
///
/// # Errors
///
/// Returns the [`CloseReason`] when the proxy must close the connection.
pub fn relay_request_body<R: Read, W: Write>(
    forwarded: Forwarded,
    client: &mut R,
    upstream: &mut W,
) -> Result<Vec<u8>, CloseReason> {
    let mut input = BodyInput {
        buf: forwarded.rest,
        pos: 0,
        reader: client,
    };
    match forwarded.request.body {
        BodyFraming::None => {}
        BodyFraming::ContentLength(n) => input.copy(n, upstream)?,
        BodyFraming::Chunked => relay_chunked(&mut input, upstream)?,
    }
    upstream.flush().map_err(|e| CloseReason::Io(e.kind()))?;
    Ok(input.buf.split_off(input.pos))
}

/// Forward the requests of one box connection to `upstream`, head and body,
/// until the connection closes. This is the request half of the
/// connection. The responses go back to the box on the other half.
///
/// After a request that switches protocol, the loop stops and returns
/// [`CloseReason::ProtocolSwitch`] with the bytes it read after the
/// request. It never parses those bytes as HTTP.
///
/// The head goes upstream before the loop reads the body, and `Expect`
/// goes with it unchanged. A box that sends `Expect: 100-continue` holds
/// its body until it sees `100 Continue`, and only the upstream sends
/// that interim response. So the caller must run the response half
/// concurrently with this loop, and relay each interim `1xx` head to the
/// box as it arrives. A caller that runs the two halves in turn stalls
/// such a box until the box's own expect timeout.
///
/// Writes one debug log line for the close, with the box id and
/// [`CloseReason::rule`], and returns the reason.
pub fn forward_requests<R: Read, W: Write>(
    box_id: &str,
    client: &mut R,
    upstream: &mut W,
    audit: &mut dyn AuditSink,
) -> CloseReason {
    let mut pending = Vec::new();
    let reason = loop {
        let forwarded = match forward_head(box_id, pending, client, upstream, audit) {
            Ok(forwarded) => forwarded,
            Err(reason) => break reason,
        };
        let switches = forwarded.request.switches_protocol();
        pending = match relay_request_body(forwarded, client, upstream) {
            Ok(rest) => rest,
            Err(reason) => break reason,
        };
        if switches {
            break CloseReason::ProtocolSwitch { rest: pending };
        }
    };
    tracing::debug!(box_id, rule = reason.rule(), "box connection closed");
    reason
}

/// The bytes of a body: those already read, then the reader.
struct BodyInput<'r, R> {
    buf: Vec<u8>,
    pos: usize,
    reader: &'r mut R,
}

impl<R: Read> BodyInput<'_, R> {
    /// Read more bytes into the buffer.
    fn fill(&mut self) -> Result<(), CloseReason> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let mut chunk = [0u8; 8192];
        loop {
            match self.reader.read(&mut chunk) {
                Ok(0) => return Err(CloseReason::BodyEof),
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(CloseReason::Io(e.kind())),
            }
        }
    }

    /// Copy exactly `n` bytes to `out`.
    fn copy<W: Write>(&mut self, mut n: u64, out: &mut W) -> Result<(), CloseReason> {
        while n > 0 {
            if self.pos == self.buf.len() {
                self.fill()?;
            }
            let available = &self.buf[self.pos..];
            let take = usize::try_from(n).map_or(available.len(), |n| n.min(available.len()));
            out.write_all(&available[..take])
                .map_err(|e| CloseReason::Io(e.kind()))?;
            self.pos += take;
            n -= take as u64;
        }
        Ok(())
    }

    /// One line, without its CRLF. A bare CR or a bare LF is malformed.
    fn line(&mut self) -> Result<Vec<u8>, CloseReason> {
        loop {
            let available = &self.buf[self.pos..];
            if let Some(end) = available.windows(2).position(|w| w == b"\r\n") {
                if end > MAX_CHUNK_LINE_LEN {
                    return Err(CloseReason::Malformed("chunk_line_too_long"));
                }
                let line = available[..end].to_vec();
                self.pos += end + 2;
                if line.iter().any(|&b| b == b'\r' || b == b'\n') {
                    return Err(CloseReason::Malformed("bare_cr_or_lf"));
                }
                return Ok(line);
            }
            if available.len() > MAX_CHUNK_LINE_LEN {
                return Err(CloseReason::Malformed("chunk_line_too_long"));
            }
            self.fill()?;
        }
    }
}

/// Parse a chunked body from `input`, and write it canonically to
/// `upstream` (RFC 9112 §7.1).
fn relay_chunked<R: Read, W: Write>(
    input: &mut BodyInput<'_, R>,
    upstream: &mut W,
) -> Result<(), CloseReason> {
    let io_err = |e: io::Error| CloseReason::Io(e.kind());
    loop {
        let size = parse_chunk_size(&input.line()?)?;
        if size == 0 {
            break;
        }
        upstream
            .write_all(format!("{size:x}\r\n").as_bytes())
            .map_err(io_err)?;
        input.copy(size, upstream)?;
        if !input.line()?.is_empty() {
            return Err(CloseReason::Malformed("chunk_data_crlf"));
        }
        upstream.write_all(b"\r\n").map_err(io_err)?;
    }
    // The trailer section is read to its end and dropped.
    let mut trailer_len = 0;
    loop {
        let line = input.line()?;
        if line.is_empty() {
            break;
        }
        trailer_len += line.len() + 2;
        if trailer_len > MAX_HEAD_LEN {
            return Err(CloseReason::Malformed("trailer_too_large"));
        }
    }
    upstream.write_all(b"0\r\n\r\n").map_err(io_err)
}

/// The size of a chunk-size line: hex digits, then an optional extension
/// after `;`, which is dropped.
fn parse_chunk_size(line: &[u8]) -> Result<u64, CloseReason> {
    let malformed = CloseReason::Malformed("chunk_size");
    let (digits, extension) = match line.iter().position(|&b| b == b';') {
        Some(semi) => (&line[..semi], &line[semi + 1..]),
        None => (line, &[][..]),
    };
    if !extension.iter().all(|&b| is_field_byte(b)) {
        return Err(malformed);
    }
    if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(malformed);
    }
    // The digits are ASCII hex, from the check above.
    u64::from_str_radix(&String::from_utf8_lossy(digits), 16).map_err(|_| malformed)
}

fn read_head<R: Read, T>(
    mut buf: Vec<u8>,
    reader: &mut R,
    parse: fn(&[u8]) -> Result<Parse<T>, CloseReason>,
) -> Result<(T, Vec<u8>), CloseReason> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Parse::Complete { head, head_len } = parse(&buf)? {
            return Ok((head, buf.split_off(head_len)));
        }
        let n = match reader.read(&mut chunk) {
            Ok(0) if buf.is_empty() => return Err(CloseReason::ClientClosed),
            Ok(0) => return Err(CloseReason::Eof),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CloseReason::Io(e.kind())),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn is_h2_preface_start(buf: &[u8]) -> bool {
    // The first line of the preface is enough to know it, so the proxy
    // closes before it waits for the rest of the preface.
    let line = H2_PREFACE.len().min(H2_PREFACE_LINE.len() + 2);
    buf.len() >= line && buf.starts_with(&H2_PREFACE[..line])
}

/// The length of the head, `\r\n\r\n` included, when it is complete.
fn head_end(buf: &[u8]) -> Result<Option<usize>, CloseReason> {
    let limit = buf.len().min(MAX_HEAD_LEN);
    match buf[..limit].windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => Ok(Some(pos + 4)),
        None if buf.len() >= MAX_HEAD_LEN => Err(CloseReason::HeadTooLarge),
        None => Ok(None),
    }
}

/// The lines of a head, split at CRLF. A bare CR or a bare LF in a line is
/// malformed.
fn head_lines(head: &[u8]) -> impl Iterator<Item = Result<&[u8], CloseReason>> {
    let mut rest = Some(head);
    std::iter::from_fn(move || {
        let current = rest?;
        let (line, next) = match current.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => (&current[..pos], Some(&current[pos + 2..])),
            None => (current, None),
        };
        rest = next;
        Some(if line.iter().any(|&b| b == b'\r' || b == b'\n') {
            Err(CloseReason::Malformed("bare_cr_or_lf"))
        } else {
            Ok(line)
        })
    })
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), CloseReason> {
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CloseReason::Malformed("request_line"));
    };
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(CloseReason::Malformed("method"));
    }
    if target.is_empty() || !target.iter().all(|&b| b.is_ascii_graphic()) {
        return Err(CloseReason::Malformed("request_target"));
    }
    if version != b"HTTP/1.1" {
        return Err(CloseReason::Malformed("http_version"));
    }
    // Both parts are ASCII, from the checks above.
    Ok((
        String::from_utf8_lossy(method).into_owned(),
        String::from_utf8_lossy(target).into_owned(),
    ))
}

fn parse_status_line(line: &[u8]) -> Result<(u8, u16, Vec<u8>), CloseReason> {
    let malformed = CloseReason::Malformed("status_line");
    let minor = match line.get(..9) {
        Some(b"HTTP/1.1 ") => 1,
        Some(b"HTTP/1.0 ") => 0,
        _ => return Err(malformed),
    };
    let code = line.get(9..12).ok_or_else(|| malformed.clone())?;
    if !code.iter().all(u8::is_ascii_digit) {
        return Err(malformed);
    }
    let status = code
        .iter()
        .fold(0u16, |acc, &d| acc * 10 + u16::from(d - b'0'));
    let reason = match line.get(12..) {
        None | Some([]) => Vec::new(),
        Some([b' ', rest @ ..]) if rest.iter().all(|&b| is_field_byte(b)) => rest.to_vec(),
        Some(_) => return Err(malformed),
    };
    Ok((minor, status, reason))
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = Result<&'a [u8], CloseReason>>,
) -> Result<Vec<Header>, CloseReason> {
    let mut headers = Vec::new();
    for line in lines {
        let line = line?;
        if matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(CloseReason::FramingAmbiguous(Ambiguity::ObsoleteLineFold));
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(CloseReason::Malformed("header_without_colon"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            // Whitespace before the colon is refused here too (RFC 9112 §5.1).
            return Err(CloseReason::Malformed("header_name"));
        }
        let value = trim_ows(&line[colon + 1..]);
        if !value.iter().all(|&b| is_field_byte(b)) {
            return Err(CloseReason::Malformed("header_value"));
        }
        headers.push(Header {
            name: String::from_utf8_lossy(name).to_ascii_lowercase(),
            value: value.to_vec(),
        });
    }
    Ok(headers)
}

/// The body framing, under the strict rules of BEP-077.
fn framing(headers: &[Header]) -> Result<BodyFraming, CloseReason> {
    let ambiguous = |a| Err(CloseReason::FramingAmbiguous(a));
    let lengths: Vec<&[u8]> = list_elements(values(headers, "content-length")).collect();
    let has_length_header = headers.iter().any(|h| h.name == "content-length");
    let has_te = headers.iter().any(|h| h.name == "transfer-encoding");
    let names_framing = list_elements(values(headers, "connection")).any(|t| {
        t.eq_ignore_ascii_case(b"content-length") || t.eq_ignore_ascii_case(b"transfer-encoding")
    });
    if names_framing {
        return ambiguous(Ambiguity::ConnectionNamesFramingHeader);
    }
    if has_length_header && has_te {
        return ambiguous(Ambiguity::ContentLengthWithTransferEncoding);
    }
    // The canonical head carries the value as received. An empty list
    // element, as in `5,` or `chunked,`, then reaches the upstream, which
    // can read it in a different way from this check. Refuse it.
    if has_empty_element(headers, "content-length") {
        return ambiguous(Ambiguity::InvalidContentLength);
    }
    if has_empty_element(headers, "transfer-encoding") {
        return ambiguous(Ambiguity::TransferCodingNotFinalChunked);
    }
    if has_te {
        let codings: Vec<&[u8]> = list_elements(values(headers, "transfer-encoding")).collect();
        return match codings.as_slice() {
            [only] if only.eq_ignore_ascii_case(b"chunked") => Ok(BodyFraming::Chunked),
            _ => ambiguous(Ambiguity::TransferCodingNotFinalChunked),
        };
    }
    if !has_length_header {
        return Ok(BodyFraming::None);
    }
    match lengths.as_slice() {
        [one] => {
            parse_length(one)
                .map(BodyFraming::ContentLength)
                .ok_or(CloseReason::FramingAmbiguous(
                    Ambiguity::InvalidContentLength,
                ))
        }
        [] => ambiguous(Ambiguity::InvalidContentLength),
        _ => ambiguous(Ambiguity::DuplicateContentLength),
    }
}

fn parse_length(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        acc.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

/// The scheme and authority of an absolute-form target, `scheme://authority`.
fn absolute_form_authority(target: &[u8]) -> Option<(&'static str, &[u8])> {
    let (scheme, rest) = if target.len() > 7 && target[..7].eq_ignore_ascii_case(b"http://") {
        ("http", &target[7..])
    } else if target.len() > 8 && target[..8].eq_ignore_ascii_case(b"https://") {
        ("https", &target[8..])
    } else {
        return None;
    };
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    Some((scheme, &rest[..end]))
}

/// Whether a CONNECT target is authority-form: a host and an explicit port.
fn is_connect_authority(target: &[u8]) -> bool {
    let host_end = if target.first() == Some(&b'[') {
        target.iter().position(|&b| b == b']').map_or(0, |i| i + 1)
    } else {
        target
            .iter()
            .position(|&b| b == b':')
            .unwrap_or(target.len())
    };
    target.get(host_end) == Some(&b':') && is_host_authority(target)
}

/// Whether an absolute-form authority and a Host value name the same
/// authority. Case does not count, and the scheme's default port equals no
/// port. An authority with user info never matches.
fn same_authority(scheme: &str, authority: &[u8], host: &[u8]) -> bool {
    let default_port: &[u8] = if scheme == "https" { b":443" } else { b":80" };
    let normal = |a: &[u8]| -> Vec<u8> {
        let a = a.strip_suffix(default_port).unwrap_or(a);
        a.to_ascii_lowercase()
    };
    !authority.contains(&b'@') && !authority.is_empty() && normal(authority) == normal(host)
}

/// Whether a Host value is a host with an optional port: a name or IPv4
/// address of letters, digits, `-`, `.`, `_` and `~`, or a bracketed IPv6
/// literal, then `:` and 1 to 5 digits up to 65535. An empty value, user
/// info, a path, a comma or a space never match.
fn is_host_authority(value: &[u8]) -> bool {
    let port = if value.first() == Some(&b'[') {
        let Some(close) = value.iter().position(|&b| b == b']') else {
            return false;
        };
        let literal = &value[1..close];
        if literal.is_empty()
            || !literal
                .iter()
                .all(|&b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        {
            return false;
        }
        &value[close + 1..]
    } else {
        let end = value.iter().position(|&b| b == b':').unwrap_or(value.len());
        let host = &value[..end];
        if host.is_empty()
            || !host
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return false;
        }
        &value[end..]
    };
    match port {
        [] => true,
        [b':', digits @ ..] => {
            digits.len() <= 5 && parse_length(digits).is_some_and(|p| p <= 65535)
        }
        _ => false,
    }
}

/// Remove an `h2c` upgrade, its `Connection` tokens and `HTTP2-Settings`
/// (BEP-074). The request stays HTTP/1.1.
fn strip_h2c(headers: &mut Vec<Header>) {
    let asks_h2c =
        list_elements(values(headers, "upgrade")).any(|t| t.eq_ignore_ascii_case(b"h2c"));
    if !asks_h2c {
        return;
    }
    let mut upgrade_left = false;
    for header in headers.iter_mut().filter(|h| h.name == "upgrade") {
        header.value = join_without(&header.value, &[b"h2c"]);
        upgrade_left |= !header.value.is_empty();
    }
    let mut dropped: Vec<&[u8]> = vec![b"http2-settings"];
    if !upgrade_left {
        dropped.push(b"upgrade");
    }
    for header in headers.iter_mut().filter(|h| h.name == "connection") {
        header.value = join_without(&header.value, &dropped);
    }
    headers.retain(|h| {
        h.name != "http2-settings"
            && !(matches!(h.name.as_str(), "upgrade" | "connection") && h.value.is_empty())
    });
}

/// The comma-separated list `value`, without the tokens in `drop`, compared
/// in any case, joined with `", "`.
fn join_without(value: &[u8], drop: &[&[u8]]) -> Vec<u8> {
    let kept: Vec<&[u8]> = list_elements(std::iter::once(value))
        .filter(|t| !drop.iter().any(|d| t.eq_ignore_ascii_case(d)))
        .collect();
    kept.join(&b", "[..])
}

fn values<'a>(headers: &'a [Header], name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers
        .iter()
        .filter(move |h| h.name == name)
        .map(|h| h.value.as_slice())
}

/// Whether a value of a header named `name` holds an empty list element.
fn has_empty_element(headers: &[Header], name: &str) -> bool {
    values(headers, name).any(|v| v.split(|&b| b == b',').any(|e| trim_ows(e).is_empty()))
}

/// The non-empty elements of comma-separated list values, trimmed.
fn list_elements<'a>(values: impl Iterator<Item = &'a [u8]>) -> impl Iterator<Item = &'a [u8]> {
    values
        .flat_map(|v| v.split(|&b| b == b','))
        .map(trim_ows)
        .filter(|e| !e.is_empty())
}

fn write_headers(out: &mut Vec<u8>, headers: &[Header]) {
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// A `tchar` of RFC 9110 §5.6.2.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A byte allowed inside a field value: visible ASCII, SP, HTAB and
/// obs-text.
fn is_field_byte(b: u8) -> bool {
    b == b' ' || b == b'\t' || b.is_ascii_graphic() || b >= 0x80
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use proptest::prelude::*;

    use super::*;

    fn parse_ok(raw: &[u8]) -> Request {
        match parse_request(raw) {
            Ok(Parse::Complete { head, head_len }) => {
                assert_eq!(head_len, raw.len(), "the whole input is one head");
                head
            }
            other => panic!("expected a complete head, got {other:?}"),
        }
    }

    // BEP-074: the h2 prior-knowledge preface closes the connection, and
    // nothing reaches the upstream.
    #[test]
    fn h2_prior_knowledge_preface_is_closed() {
        assert_eq!(parse_request(H2_PREFACE), Err(CloseReason::H2Preface));
        assert_eq!(
            parse_request(b"PRI * HTTP/2.0\r\n"),
            Err(CloseReason::H2Preface),
            "the first line of the preface is enough"
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut upstream = Vec::new();
            let mut audit = Vec::new();
            let result = forward_request_head("box-a", &mut conn, &mut upstream, &mut audit);
            drop(conn);
            (result, upstream, audit)
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(H2_PREFACE).unwrap();
        let mut buf = Vec::new();
        match client.read_to_end(&mut buf) {
            Ok(_) => assert!(buf.is_empty(), "the proxy sends nothing back"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
        }
        let (result, upstream, audit) = server.join().unwrap();
        assert_eq!(result, Err(CloseReason::H2Preface));
        assert_eq!(result.unwrap_err().rule(), "h2_prior_knowledge_preface");
        assert!(upstream.is_empty(), "no byte reaches the upstream");
        assert!(audit.is_empty());
    }

    // BEP-074: `Upgrade: h2c`, its `Connection` tokens and `HTTP2-Settings`
    // go, and the request stays HTTP/1.1.
    #[test]
    fn h2c_upgrade_is_stripped() {
        let req = parse_ok(
            b"GET / HTTP/1.1\r\nHost: github.com\r\nConnection: Upgrade, HTTP2-Settings\r\n\
              Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
        );
        assert_eq!(
            req.serialize(),
            b"GET / HTTP/1.1\r\nhost: github.com\r\n\r\n".to_vec()
        );

        // Another upgrade and another connection option stay.
        let req = parse_ok(
            b"GET / HTTP/1.1\r\nHost: github.com\r\nConnection: keep-alive, Upgrade, HTTP2-Settings\r\n\
              Upgrade: H2C, websocket\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
        );
        assert_eq!(
            req.serialize(),
            b"GET / HTTP/1.1\r\nhost: github.com\r\nconnection: keep-alive, Upgrade\r\nupgrade: websocket\r\n\r\n"
                .to_vec()
        );

        // A request with no h2c upgrade keeps its headers.
        let req = parse_ok(b"GET / HTTP/1.1\r\nHost: a\r\nHTTP2-Settings: x\r\n\r\n");
        assert_eq!(req.headers.len(), 2);
    }

    // BEP-076: every `Alt-Svc` header leaves the relayed response.
    #[test]
    fn alt_svc_is_stripped_from_responses() {
        let raw: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
            Alt-Svc: h3=\":443\"; ma=86400\r\nContent-Length: 2\r\nalt-svc: clear\r\n\
            ALT-SVC: h3-29=\":443\"\r\n\r\nok";
        let mut client = Vec::new();
        let (response, rest) = relay_response_head(&mut &raw[..], &mut client).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(rest, b"ok");
        assert!(response.headers.iter().all(|h| h.name != "alt-svc"));
        assert_eq!(
            client,
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\n".to_vec()
        );
        let lower = String::from_utf8_lossy(&client).to_ascii_lowercase();
        assert!(!lower.contains("alt-svc"));
    }

    fn name_case(name: &str, mask: u64) -> String {
        name.chars()
            .enumerate()
            .map(|(i, c)| {
                if mask >> (i % 64) & 1 == 1 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    }

    fn ows() -> impl Strategy<Value = &'static str> {
        prop_oneof![Just(""), Just(" "), Just("  "), Just("\t"), Just(" \t ")]
    }

    fn header_line() -> impl Strategy<Value = (String, String, String, String, u64)> {
        (
            "x-[a-z0-9-]{1,12}",
            "[!-~]([ !-~]{0,20}[!-~])?",
            ows(),
            ows(),
            any::<u64>(),
        )
            .prop_map(|(n, v, a, b, m)| (n, v, a.to_owned(), b.to_owned(), m))
    }

    // BEP-077: the forwarded head is the canonical serialization of the
    // parsed request, never the box's bytes, and it parses back the same.
    proptest! {
        #[test]
        fn prop_forwarded_head_is_canonical(
            method in "[A-Z]{1,10}",
            target in "/[!-~]{0,40}",
            host_mask in any::<u64>(),
            headers in prop::collection::vec(header_line(), 0..8),
            body in prop_oneof![
                Just(None),
                (0u64..1_000_000).prop_map(|n| Some(format!("Content-Length: {n}"))),
                Just(Some("Transfer-Encoding: chunked".to_owned())),
            ],
        ) {
            let mut raw = format!("{method} {target} HTTP/1.1\r\n{}: github.com\r\n", name_case("host", host_mask));
            let mut expected = format!("{method} {target} HTTP/1.1\r\nhost: github.com\r\n");
            for (name, value, pre, post, mask) in &headers {
                raw.push_str(&format!("{}:{pre}{value}{post}\r\n", name_case(name, *mask)));
                expected.push_str(&format!("{name}: {value}\r\n"));
            }
            if let Some(line) = &body {
                raw.push_str(&format!("{line}\r\n"));
                let (n, v) = line.split_once(": ").unwrap();
                expected.push_str(&format!("{}: {v}\r\n", n.to_ascii_lowercase()));
            }
            raw.push_str("\r\n");
            expected.push_str("\r\n");
            let mut input = raw.clone().into_bytes();
            input.extend_from_slice(b"body-bytes");

            let mut upstream = Vec::new();
            let mut audit = Vec::new();
            let forwarded = forward_request_head("box-a", &mut &input[..], &mut upstream, &mut audit)
                .expect("an unambiguous head is forwarded");
            prop_assert_eq!(&upstream, &forwarded.request.serialize());
            prop_assert_eq!(String::from_utf8(upstream.clone()).unwrap(), expected);
            prop_assert_eq!(forwarded.rest, b"body-bytes".to_vec());
            prop_assert!(audit.is_empty());

            let again = parse_ok(&upstream);
            prop_assert_eq!(&again, &forwarded.request);
            prop_assert_eq!(again.serialize(), upstream);
        }
    }

    #[derive(Debug, Clone)]
    enum FramingLine {
        Length(String),
        Te(&'static str),
        Fold,
    }

    fn framing_line() -> impl Strategy<Value = FramingLine> {
        prop_oneof![
            (0u64..100_000).prop_map(|n| FramingLine::Length(n.to_string())),
            Just(FramingLine::Length("5, 5".to_owned())),
            Just(FramingLine::Length("5, 6".to_owned())),
            Just(FramingLine::Length("+5".to_owned())),
            Just(FramingLine::Length("0x5".to_owned())),
            Just(FramingLine::Length("5,".to_owned())),
            Just(FramingLine::Length(", 5".to_owned())),
            Just(FramingLine::Te("chunked")),
            Just(FramingLine::Te("Chunked")),
            Just(FramingLine::Te("gzip")),
            Just(FramingLine::Te("gzip, chunked")),
            Just(FramingLine::Te("chunked, gzip")),
            Just(FramingLine::Te("chunked, chunked")),
            Just(FramingLine::Te("identity")),
            Just(FramingLine::Te("chunked,")),
            Just(FramingLine::Te(", chunked")),
            Just(FramingLine::Fold),
        ]
    }

    /// The oracle: whether a head with these framing lines is ambiguous
    /// under BEP-077's rules.
    fn oracle_ambiguous(lines: &[FramingLine]) -> bool {
        let mut lengths = Vec::new();
        let mut codings = Vec::new();
        let mut has_te = false;
        let mut fold = false;
        for line in lines {
            match line {
                FramingLine::Length(v) => lengths.extend(v.split(',').map(|s| s.trim().to_owned())),
                FramingLine::Te(v) => {
                    has_te = true;
                    codings.extend(v.split(',').map(|s| s.trim().to_ascii_lowercase()));
                }
                FramingLine::Fold => fold = true,
            }
        }
        let invalid_length = lengths
            .iter()
            .any(|l| l.parse::<u64>().is_err() || l.starts_with('+'));
        fold || (has_te && !lengths.is_empty())
            || lengths.len() > 1
            || invalid_length
            || (has_te && codings != ["chunked"])
    }

    // BEP-077: a head is forwarded only when its framing is unambiguous, and
    // otherwise the connection closes and the refusal is audited.
    proptest! {
        #[test]
        fn prop_ambiguous_framing_is_refused(
            lines in prop::collection::vec(framing_line(), 0..4),
            name_mask in any::<u64>(),
        ) {
            let mut raw = String::from("POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: github.com\r\n");
            for line in &lines {
                match line {
                    FramingLine::Length(v) => raw.push_str(&format!("{}: {v}\r\n", name_case("content-length", name_mask))),
                    FramingLine::Te(v) => raw.push_str(&format!("{}: {v}\r\n", name_case("transfer-encoding", name_mask))),
                    FramingLine::Fold => raw.push_str("X-Note: a\r\n folded\r\n"),
                }
            }
            raw.push_str("\r\n");

            let mut upstream = Vec::new();
            let mut audit = Vec::new();
            let result = forward_request_head("box-a", &mut raw.as_bytes(), &mut upstream, &mut audit);
            if oracle_ambiguous(&lines) {
                let reason = result.expect_err("an ambiguous head is refused");
                prop_assert!(matches!(reason, CloseReason::FramingAmbiguous(_)), "{reason:?}");
                prop_assert!(upstream.is_empty(), "no byte reaches the upstream");
                prop_assert_eq!(audit.len(), 1);
                prop_assert_eq!(audit[0].marker, FRAMING_AMBIGUOUS);
                prop_assert_eq!(audit[0].box_id.as_str(), "box-a");
                prop_assert_eq!(audit[0].rule, reason.rule());
            } else {
                let forwarded = result.expect("an unambiguous head is forwarded");
                prop_assert_eq!(upstream, forwarded.request.serialize());
                prop_assert!(audit.is_empty());
            }
        }
    }

    #[test]
    fn framing_rules_name_the_rule() {
        let cases: [(&[u8], Ambiguity); 5] = [
            (
                b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
                Ambiguity::ContentLengthWithTransferEncoding,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
                Ambiguity::DuplicateContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: -3\r\n\r\n",
                Ambiguity::InvalidContentLength,
            ),
            (
                b"POST / HTTP/1.1\r\nX-A: b\r\n\tc\r\n\r\n",
                Ambiguity::ObsoleteLineFold,
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
                Ambiguity::TransferCodingNotFinalChunked,
            ),
        ];
        for (raw, rule) in cases {
            let reason = parse_request(raw).unwrap_err();
            assert_eq!(reason, CloseReason::FramingAmbiguous(rule));
            assert_eq!(reason.audit_marker(), Some(FRAMING_AMBIGUOUS));
        }
    }

    #[test]
    fn malformed_heads_close_without_framing_audit() {
        for raw in [
            &b"GET / HTTP/1.0\r\n\r\n"[..],
            b"GET  / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
        ] {
            let reason = parse_request(raw).unwrap_err();
            assert!(matches!(reason, CloseReason::Malformed(_)), "{reason:?}");
            assert_eq!(reason.audit_marker(), None);
        }
        assert_eq!(parse_request(b"GET / HTTP/1.1\r\n"), Ok(Parse::Partial));
        assert_eq!(
            parse_request(&vec![b'a'; MAX_HEAD_LEN]),
            Err(CloseReason::HeadTooLarge)
        );
    }

    /// A reader that returns at most three bytes at a time, so that every
    /// boundary falls inside a read.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.len().min(buf.len()).min(3);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn forward_all(input: &[u8]) -> (CloseReason, Vec<u8>, Vec<AuditEvent>) {
        let mut upstream = Vec::new();
        let mut audit = Vec::new();
        let reason = forward_requests("box-a", &mut Trickle(input), &mut upstream, &mut audit);
        (reason, upstream, audit)
    }

    // BEP-077: the loop stops at a protocol switch, and the bytes after the
    // request are never parsed as HTTP.
    #[test]
    fn protocol_switch_stops_the_request_loop() {
        let frames: &[u8] = b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58";
        for head in [
            &b"GET /ws HTTP/1.1\r\nHost: github.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"[..],
            &b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"[..],
        ] {
            let input = [head, frames].concat();
            let mut client = &input[..];
            let mut upstream = Vec::new();
            let mut audit = Vec::new();
            let reason = forward_requests("box-a", &mut client, &mut upstream, &mut audit);
            assert_eq!(reason.rule(), "protocol_switch_requested");
            let CloseReason::ProtocolSwitch { rest } = reason else {
                panic!("{reason:?}");
            };
            assert_eq!([&rest[..], client].concat(), frames);
            let Parse::Complete { head: request, .. } = parse_request(head).unwrap() else {
                panic!("the head is complete");
            };
            assert_eq!(upstream, request.serialize());
            assert!(audit.is_empty());
        }
    }

    // BEP-077: a CONNECT target names the tunnel's authority, so it must
    // agree with Host, or the policy and the upstream see two authorities.
    #[test]
    fn connect_target_must_match_host() {
        for (head, ok) in [
            (
                &b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"[..],
                true,
            ),
            (
                &b"CONNECT GitHub.com:443 HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                true,
            ),
            (
                &b"CONNECT evil.example:443 HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                false,
            ),
            (
                &b"CONNECT evil.example:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n"[..],
                false,
            ),
            (
                &b"CONNECT github.com:8443 HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                false,
            ),
            (
                &b"CONNECT github.com HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                false,
            ),
            (
                &b"CONNECT user@github.com:443 HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                false,
            ),
            (
                &b"CONNECT /x HTTP/1.1\r\nHost: github.com\r\n\r\n"[..],
                false,
            ),
        ] {
            let result = parse_request(head);
            if ok {
                assert!(matches!(result, Ok(Parse::Complete { .. })), "{result:?}");
            } else {
                assert_eq!(
                    result,
                    Err(CloseReason::Malformed("target_host_mismatch")),
                    "{}",
                    String::from_utf8_lossy(head)
                );
            }
        }
    }

    // BEP-077: a Content-Length body goes upstream as exactly that many
    // bytes, and the bytes after it are the next request.
    #[test]
    fn expect_continue_is_forwarded_before_the_body() {
        // The upstream answers `Expect`, so the head carries it unchanged
        // and reaches the upstream before the loop waits for the body.
        let raw = b"POST /x HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        let mut client: &[u8] = raw;
        let mut upstream = Vec::new();
        let mut audit: Vec<AuditEvent> = Vec::new();
        let forwarded = forward_request_head("box-a", &mut client, &mut upstream, &mut audit)
            .expect("an unambiguous head is forwarded");
        assert_eq!(forwarded.request.body, BodyFraming::ContentLength(3));
        assert_eq!(
            String::from_utf8(upstream).unwrap(),
            "POST /x HTTP/1.1\r\nhost: github.com\r\nexpect: 100-continue\r\ncontent-length: 3\r\n\r\n"
        );
        assert!(audit.is_empty());
    }

    // The head is flushed before the loop reads the body, so a buffered
    // upstream writer cannot hold it while the box waits for `100 Continue`.
    #[test]
    fn expect_continue_head_is_flushed_before_the_body() {
        let raw = b"POST /x HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
        let mut client: &[u8] = raw;
        let mut upstream = io::BufWriter::new(Vec::new());
        let mut audit: Vec<AuditEvent> = Vec::new();
        forward_request_head("box-a", &mut client, &mut upstream, &mut audit)
            .expect("an unambiguous head is forwarded");
        assert!(upstream.buffer().is_empty());
        assert!(upstream.get_ref().starts_with(b"POST /x HTTP/1.1\r\n"));
    }

    #[test]
    fn content_length_body_is_relayed_exactly() {
        let (reason, upstream, audit) = forward_all(
            b"POST /a HTTP/1.1\r\nHost: github.com\r\nContent-Length:  11\r\n\r\nhello worldGET /b HTTP/1.1\r\nHOST: github.com\r\n\r\n",
        );
        assert_eq!(reason, CloseReason::ClientClosed);
        assert_eq!(reason.rule(), "client_closed");
        assert_eq!(
            String::from_utf8(upstream).unwrap(),
            "POST /a HTTP/1.1\r\nhost: github.com\r\ncontent-length: 11\r\n\r\nhello world\
             GET /b HTTP/1.1\r\nhost: github.com\r\n\r\n"
        );
        assert!(audit.is_empty());
    }

    // BEP-077: a chunked body is parsed and written upstream as canonical
    // chunks. The box's chunk bytes never go upstream as they are.
    #[test]
    fn chunked_body_is_reframed() {
        let (reason, upstream, _) = forward_all(
            b"POST /a HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: Chunked\r\n\r\n\
              005;name=value\r\nhello\r\nA\r\n0123456789\r\n0000;last\r\nX-Trailer: t\r\n\r\n\
              GET /b HTTP/1.1\r\nHost: github.com\r\n\r\n",
        );
        assert_eq!(reason, CloseReason::ClientClosed);
        assert_eq!(
            String::from_utf8(upstream).unwrap(),
            "POST /a HTTP/1.1\r\nhost: github.com\r\ntransfer-encoding: Chunked\r\n\r\n\
             5\r\nhello\r\na\r\n0123456789\r\n0\r\n\r\n\
             GET /b HTTP/1.1\r\nhost: github.com\r\n\r\n"
        );

        let head = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
        for (body, rule) in [
            ("5\r\nhelloXX\r\n0\r\n\r\n", "chunk_data_crlf"),
            ("zz\r\n", "chunk_size"),
            (" 5\r\nhello\r\n0\r\n\r\n", "chunk_size"),
            ("-1\r\n", "chunk_size"),
            ("11111111111111111\r\n", "chunk_size"),
            ("5\nhello\r\n0\r\n\r\n", "bare_cr_or_lf"),
        ] {
            let (reason, upstream, _) = forward_all(format!("{head}{body}").as_bytes());
            assert_eq!(reason.rule(), rule, "{body:?}");
            assert!(!String::from_utf8_lossy(&upstream).contains(body));
        }
        let long = format!("{head}{}", "1".repeat(MAX_CHUNK_LINE_LEN + 8));
        assert_eq!(forward_all(long.as_bytes()).0.rule(), "chunk_line_too_long");
    }

    // A chunk line that is already buffered with its CRLF is held to the
    // same limit as one that arrives in pieces.
    #[test]
    fn buffered_chunk_line_over_limit_is_refused() {
        let line = |len: usize| {
            let mut buf = format!("1;{}", "e".repeat(len - 2)).into_bytes();
            buf.extend_from_slice(b"\r\nrest");
            let mut empty: &[u8] = &[];
            let mut input = BodyInput {
                buf,
                pos: 0,
                reader: &mut empty,
            };
            input.line().map(|l| l.len())
        };
        assert_eq!(line(MAX_CHUNK_LINE_LEN), Ok(MAX_CHUNK_LINE_LEN));
        assert_eq!(
            line(MAX_CHUNK_LINE_LEN + 1),
            Err(CloseReason::Malformed("chunk_line_too_long"))
        );
    }

    // A box that closes mid-body closes the connection with its own rule.
    // The caller drops the upstream connection, so the partial body ends
    // nothing that a later request reuses.
    #[test]
    fn client_closing_mid_body_closes() {
        let (reason, upstream, _) =
            forward_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc");
        assert_eq!(reason, CloseReason::BodyEof);
        assert_eq!(reason.rule(), "eof_before_body_end");
        assert!(upstream.ends_with(b"\r\n\r\nabc"));

        for body in ["5\r\nhel", "5\r\nhello\r\n", "0\r\nX-T: a\r\n", "5"] {
            let input =
                format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
            assert_eq!(
                forward_all(input.as_bytes()).0,
                CloseReason::BodyEof,
                "{body:?}"
            );
        }

        assert_eq!(
            forward_all(b"GET / HTTP/1.1\r\nHost: a\r\n").0,
            CloseReason::Eof
        );
    }

    // A Connection option that names a framing header is ambiguous framing,
    // and one that names Host is refused too.
    #[test]
    fn connection_naming_framing_header_is_refused() {
        for raw in [
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nConnection: keep-alive, Content-Length\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: transfer-encoding\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: content-length\r\n\r\n",
        ] {
            assert_eq!(
                parse_request(raw),
                Err(CloseReason::FramingAmbiguous(
                    Ambiguity::ConnectionNamesFramingHeader
                ))
            );
        }
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Host\r\n\r\n"),
            Err(CloseReason::Malformed("connection_names_host"))
        );
    }

    // One Host is required, and an absolute-form target must name the same
    // authority.
    #[test]
    fn host_and_absolute_target_must_agree() {
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nX: y\r\n\r\n"),
            Err(CloseReason::Malformed("missing_host"))
        );
        for raw in [
            &b"GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n"[..],
            b"GET https://a.example:8443/x HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"GET http://u@a.example/ HTTP/1.1\r\nHost: u.example\r\n\r\n",
            b"GET http:///x HTTP/1.1\r\nHost: a.example\r\n\r\n",
        ] {
            assert_eq!(
                parse_request(raw),
                Err(CloseReason::Malformed("target_host_mismatch")),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        for raw in [
            &b"GET http://A.example/x HTTP/1.1\r\nHost: a.EXAMPLE\r\n\r\n"[..],
            b"GET https://a.example:443?q HTTP/1.1\r\nHost: a.example\r\n\r\n",
            b"GET http://a.example HTTP/1.1\r\nHost: a.example:80\r\n\r\n",
        ] {
            parse_ok(raw);
        }
    }

    // Host must be a host with an optional port, and nothing else.
    #[test]
    fn host_must_be_a_host_and_port() {
        for host in [
            "",
            "a b",
            "a,b",
            "a/b",
            "u@a.example",
            "a.example:",
            "a.example:x",
            "a.example:65536",
            "a.example:443:443",
            "[::1",
            "[]",
            "[::1]x",
            "[::1]:",
            ":443",
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(
                parse_request(raw.as_bytes()),
                Err(CloseReason::Malformed("invalid_host")),
                "{host:?}"
            );
        }
        for host in [
            "github.com",
            "a.example:8443",
            "127.0.0.1:65535",
            "[::1]",
            "[2001:db8::1]:443",
            "a_b-c~d",
        ] {
            parse_ok(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes());
        }
    }

    // A response with ambiguous framing is refused before any byte of it
    // reaches the box.
    #[test]
    fn ambiguous_response_framing_is_refused() {
        for (raw, rule) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                Ambiguity::ContentLengthWithTransferEncoding,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n",
                Ambiguity::DuplicateContentLength,
            ),
        ] {
            let mut client = Vec::new();
            assert_eq!(
                relay_response_head(&mut &raw[..], &mut client).unwrap_err(),
                CloseReason::FramingAmbiguous(rule)
            );
            assert!(client.is_empty());
        }
    }
}
