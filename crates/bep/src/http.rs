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
    /// The read or the write failed.
    Io(io::ErrorKind),
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
            Self::Io(_) => "io_error",
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
    let body = framing(&headers)?;
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
/// # Errors
///
/// Returns the [`CloseReason`] when the head breaks the grammar.
pub fn parse_response(buf: &[u8]) -> Result<Parse<Response>, CloseReason> {
    let Some(head_len) = head_end(buf)? else {
        return Ok(Parse::Partial);
    };
    let mut lines = head_lines(&buf[..head_len - 4]);
    let first = lines.next().unwrap_or(Ok(&[]))?;
    let (minor_version, status, reason) = parse_status_line(first)?;
    let headers = parse_headers(lines)?;
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
    let result = read_head(client, parse_request).and_then(|(request, rest)| {
        upstream
            .write_all(&request.serialize())
            .map_err(|e| CloseReason::Io(e.kind()))?;
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
    let (mut response, rest) = read_head(upstream, parse_response)?;
    response.strip_alt_svc();
    client
        .write_all(&response.serialize())
        .map_err(|e| CloseReason::Io(e.kind()))?;
    Ok((response, rest))
}

fn read_head<R: Read, T>(
    reader: &mut R,
    parse: fn(&[u8]) -> Result<Parse<T>, CloseReason>,
) -> Result<(T, Vec<u8>), CloseReason> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Parse::Complete { head, head_len } = parse(&buf)? {
            return Ok((head, buf.split_off(head_len)));
        }
        let n = match reader.read(&mut chunk) {
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
    if has_length_header && has_te {
        return ambiguous(Ambiguity::ContentLengthWithTransferEncoding);
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
            Just(FramingLine::Te("chunked")),
            Just(FramingLine::Te("Chunked")),
            Just(FramingLine::Te("gzip")),
            Just(FramingLine::Te("gzip, chunked")),
            Just(FramingLine::Te("chunked, gzip")),
            Just(FramingLine::Te("chunked, chunked")),
            Just(FramingLine::Te("identity")),
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
}
