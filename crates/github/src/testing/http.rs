//! A tiny, hand-rolled HTTP/1.1 transport for the mock GitHub server.
//!
//! This is deliberately minimal and dependency-light: it parses one request per
//! connection and writes one response, always closing the connection
//! afterwards (`Connection: close`). That is enough for every client the mock
//! serves — a `reqwest` OAuth/REST caller and the `git` HTTP smart protocol —
//! because both tolerate connection-per-request, and it keeps the parser free of
//! keep-alive/pipelining edge cases (fail-simple, not fail-clever).
//!
//! The parser understands `Content-Length` and `Transfer-Encoding: chunked`
//! request bodies. Responses always carry a server-computed `Content-Length`, so
//! callers never set framing headers themselves.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// A parsed HTTP request.
pub struct Request {
    /// The request method, verbatim (`GET`, `POST`, …).
    pub method: String,
    /// The request-target path, with any `?query` stripped off.
    pub path: String,
    /// The raw query string (without the leading `?`); empty when absent.
    pub query: String,
    /// Header `(name, value)` pairs in wire order; names are matched
    /// case-insensitively via [`Request::header`].
    pub headers: Vec<(String, String)>,
    /// The decoded request body (empty for bodyless requests).
    pub body: Vec<u8>,
}

impl Request {
    /// The first header value matching `name` (case-insensitive), if any.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body decoded as UTF-8, lossily (for form/JSON payloads).
    #[must_use]
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The path split into non-empty segments, percent-encoding left intact.
    #[must_use]
    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }
}

/// An HTTP response to serialize back to the client.
pub struct Response {
    /// The numeric status code.
    pub status: u16,
    /// Header `(name, value)` pairs; `Content-Length` and `Connection` are added
    /// by [`Response::write_to`] and must not be set here.
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with the given status and no body or headers yet.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a header, returning `self` (builder style).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the `Content-Type` and body, returning `self`.
    #[must_use]
    pub fn with_body(mut self, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body = body.into();
        self
    }

    /// A `text/plain` response.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Response::new(status).with_body("text/plain; charset=utf-8", body.into().into_bytes())
    }

    /// An `application/json` response serialized from a [`serde_json::Value`].
    #[must_use]
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Response::new(status).with_body("application/json; charset=utf-8", body)
    }

    /// Serializes the response to `w`, computing `Content-Length` and forcing
    /// `Connection: close`.
    async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason_phrase(self.status)
        );
        for (name, value) in &self.headers {
            // Framing headers are owned by this function; ignore any a handler set.
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        head.push_str("Connection: close\r\n\r\n");
        w.write_all(head.as_bytes()).await?;
        w.write_all(&self.body).await?;
        w.flush().await?;
        Ok(())
    }
}

/// A request handler: given a parsed request, produce a response.
pub trait Handler: Send + Sync + 'static {
    /// Handle one request. Implementations must not panic on client input.
    fn handle(&self, req: Request) -> impl std::future::Future<Output = Response> + Send;
}

/// Runs the accept loop against `listener`, dispatching each connection to
/// `handler`. Returns only when the listener errors (e.g. it was closed).
pub async fn serve<H: Handler>(listener: TcpListener, handler: Arc<H>) {
    // Loop ends when `accept` errors (e.g. the listener was closed on drop).
    while let Ok((stream, _peer)) = listener.accept().await {
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            // Per-connection errors (client hangups, malformed input) are
            // expected in a mock and are swallowed rather than logged.
            let _ = handle_connection(stream, handler).await;
        });
    }
}

async fn handle_connection<H: Handler>(stream: TcpStream, handler: Arc<H>) -> io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    if let Some(req) = read_request(&mut reader).await? {
        let resp = handler.handle(req).await;
        resp.write_to(&mut wr).await?;
    }
    let _ = wr.shutdown().await;
    Ok(())
}

/// Reads and parses a single request, or `Ok(None)` if the peer closed before
/// sending anything.
async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> io::Result<Option<Request>> {
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line).await? == 0 {
        return Ok(None);
    }
    let request_line = String::from_utf8_lossy(trim_crlf(&line)).into_owned();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let mut headers = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        let trimmed = trim_crlf(&line);
        if trimmed.is_empty() {
            break;
        }
        let header = String::from_utf8_lossy(trimmed);
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    let body = read_body(reader, &headers).await?;
    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body,
    }))
}

async fn read_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    headers: &[(String, String)],
) -> io::Result<Vec<u8>> {
    if let Some(te) = header_value(headers, "transfer-encoding")
        && te.eq_ignore_ascii_case("chunked")
    {
        return read_chunked(reader).await;
    }
    if let Some(cl) = header_value(headers, "content-length") {
        let len: usize = cl.trim().parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid content-length header")
        })?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        return Ok(buf);
    }
    Ok(Vec::new())
}

async fn read_chunked<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = Vec::new();
        if reader.read_until(b'\n', &mut size_line).await? == 0 {
            break;
        }
        let size_text = String::from_utf8_lossy(trim_crlf(&size_line));
        // A chunk size may carry `;ext` parameters after the hex length.
        let hex = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if size == 0 {
            // Consume any trailer headers up to the terminating blank line.
            loop {
                let mut trailer = Vec::new();
                if reader.read_until(b'\n', &mut trailer).await? == 0 {
                    break;
                }
                if trim_crlf(&trailer).is_empty() {
                    break;
                }
            }
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        // Each chunk is followed by a bare CRLF.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
    }
    Ok(body)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}
