//! EXPERIMENTAL, a spike for networking §12 item 10 (h2 termination): an
//! HTTP/2 relay for a terminated box flow. It is off unless `bep serve`
//! runs with [`ENV`] set, and it is not BEP-073 conformant: BEP-073 says
//! both legs offer `http/1.1` alone.
//!
//! With the flag set, the box's TLS leg offers `h2, http/1.1`. A box client
//! that picks `h2` (gRPC requires it) gets this relay instead of
//! [`crate::forward::forward_requests`]. The relay dials its own upstream
//! leg offering `h2` alone, validated as every leg is (BEP-055), and then
//! carries each stream on its own:
//!
//! 1. The stream's head becomes the proxy's [`Request`]: the method, the
//!    `:path` as the target, the headers, and `:authority` as `Host`. The
//!    `h2` crate has already decoded HPACK, so the head is plain fields.
//! 2. [`Flow::decide`] decides it: the same egress and authority checks,
//!    the same redemption and store injection, and the same audit record
//!    as an HTTP/1.1 request on the same flow.
//! 3. A refused stream is answered `403` with the audit marker, and nothing
//!    of it goes upstream. An admitted head goes upstream with the
//!    decision's headers, so a substituted credential is in it.
//! 4. The body and the trailers go each way as they arrive, and the relay
//!    waits for the peer's flow-control window before it sends, so it
//!    holds at most one DATA frame per direction per stream. `Alt-Svc` is
//!    stripped from responses (§5.7).
//!
//! What the spike leaves out, and a real implementation owes: an idle
//! timeout, limits on concurrent streams and header size beyond the `h2`
//! crate's defaults, zeroizing the injected header after it is written,
//! per-stream spans, and the h2 request-smuggling rules (a `content-length`
//! that disagrees with the DATA frames, for one).

use std::sync::Arc;

use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream};
use http::header::{ALT_SVC, CONTENT_TYPE, HOST};
use http::{HeaderName, HeaderValue, Method};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Instrument as _;

use crate::forward::Flow;
use crate::http::{BodyFraming, Header, Request};

/// The ALPN protocol id of HTTP/2 over TLS.
pub const ALPN_H2: &[u8] = b"h2";

/// The environment variable that turns the relay on for `bep serve`.
pub const ENV: &str = "BEP_EXPERIMENTAL_H2";

/// Whether [`ENV`] asks for the relay.
#[must_use]
pub fn enabled() -> bool {
    std::env::var_os(ENV).is_some_and(|value| !value.is_empty() && value != "0")
}

/// Relays one terminated box connection that negotiated `h2` to an upstream
/// leg that negotiated `h2` and validated.
pub(crate) async fn relay<B, U>(flow: Flow, boxed: B, upstream: U)
where
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let flow = Arc::new(flow);
    let (client, connection) = match h2::client::handshake(upstream).await {
        Ok(handshake) => handshake,
        Err(err) => {
            tracing::warn!(error = %err, "the upstream h2 handshake failed");
            return;
        }
    };
    let upstream_connection = tokio::spawn(
        async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %err, "the upstream h2 connection ended");
            }
        }
        .in_current_span(),
    );
    let mut server = match h2::server::handshake(boxed).await {
        Ok(server) => server,
        Err(err) => {
            tracing::info!(error = %err, "the box's h2 handshake failed");
            upstream_connection.abort();
            return;
        }
    };
    let mut streams = tokio::task::JoinSet::new();
    // `accept` also drives the box's connection, so the streams spawned
    // below make progress only while this loop runs.
    while let Some(next) = server.accept().await {
        match next {
            Ok((request, respond)) => {
                streams.spawn(
                    stream(Arc::clone(&flow), client.clone(), request, respond).in_current_span(),
                );
            }
            Err(err) => {
                tracing::debug!(error = %err, "the box's h2 connection ended");
                break;
            }
        }
    }
    streams.abort_all();
    upstream_connection.abort();
}

/// One stream: decide its head, then relay it both ways.
async fn stream(
    flow: Arc<Flow>,
    client: h2::client::SendRequest<Bytes>,
    request: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    let (parts, body) = request.into_parts();
    // Extended CONNECT (RFC 8441) would open a tunnel the decision never
    // sees; §5.7 refuses it on every surface.
    if parts.method == Method::CONNECT {
        refuse(&mut respond, 501, "extended_connect");
        return;
    }
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    let mut head = Request {
        method: parts.method.as_str().to_owned(),
        target: path.clone(),
        headers: Vec::with_capacity(parts.headers.len() + 1),
        body: BodyFraming::None,
    };
    // HTTP/2 carries the authority as a pseudo-header. The decision reads
    // it from `Host`, the way an HTTP/1.1 head carries it (RFC 9113 §8.3.1).
    let authority = parts.uri.authority().map(|a| a.as_str().to_owned());
    if !parts.headers.contains_key(HOST)
        && let Some(authority) = &authority
    {
        head.headers.push(Header {
            name: HOST.as_str().to_owned(),
            value: authority.as_bytes().to_vec(),
        });
    }
    for (name, value) in &parts.headers {
        head.headers.push(Header {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        });
    }
    // The decision can block: a redemption waits on the control socket and
    // a store read on the keychain.
    let decided = {
        let flow = Arc::clone(&flow);
        tokio::task::spawn_blocking(move || {
            let decision = flow.decide(&mut head);
            (decision, head)
        })
        .await
    };
    let (head, decision) = match decided {
        Ok((decision, head)) => (head, decision),
        Err(err) => {
            tracing::warn!(error = %err, "the decision task failed");
            respond.send_reset(Reason::INTERNAL_ERROR);
            return;
        }
    };
    if let Err(marker) = decision {
        refuse(&mut respond, 403, marker);
        return;
    }
    let Some(authority) = authority.or_else(|| {
        head.header_values("host")
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
            .map(str::to_owned)
    }) else {
        refuse(&mut respond, 400, "no_authority");
        return;
    };
    let uri = match http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
    {
        Ok(uri) => uri,
        Err(_) => {
            refuse(&mut respond, 400, "request_target");
            return;
        }
    };
    let mut upstream = http::Request::new(());
    *upstream.method_mut() = parts.method;
    *upstream.uri_mut() = uri;
    *upstream.version_mut() = http::Version::HTTP_2;
    for header in &head.headers {
        if header.name == HOST.as_str() {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name.as_bytes()),
            HeaderValue::from_bytes(&header.value),
        ) else {
            refuse(&mut respond, 400, "header_field");
            return;
        };
        upstream.headers_mut().append(name, value);
    }
    drop(head);
    let mut client = match client.ready().await {
        Ok(client) => client,
        Err(err) => {
            tracing::info!(error = %err, "the upstream h2 connection is gone");
            respond.send_reset(Reason::REFUSED_STREAM);
            return;
        }
    };
    let request_ends = body.is_end_stream();
    let (response, mut send_body) = match client.send_request(upstream, request_ends) {
        Ok(sent) => sent,
        Err(err) => {
            tracing::info!(error = %err, "the upstream refused the stream");
            respond.send_reset(err.reason().unwrap_or(Reason::INTERNAL_ERROR));
            return;
        }
    };
    let request_half = async move {
        if !request_ends && let Err(err) = pump(body, &mut send_body).await {
            send_body.send_reset(err.reason().unwrap_or(Reason::CANCEL));
        }
    };
    let response_half = async move {
        let response = match response.await {
            Ok(response) => response,
            Err(err) => {
                tracing::info!(error = %err, "the upstream response failed");
                respond.send_reset(err.reason().unwrap_or(Reason::INTERNAL_ERROR));
                return;
            }
        };
        let (mut parts, body) = response.into_parts();
        // §5.7: no h3 discovery through the proxy.
        parts.headers.remove(ALT_SVC);
        let response_ends = body.is_end_stream();
        let out = http::Response::from_parts(parts, ());
        match respond.send_response(out, response_ends) {
            Ok(mut send) => {
                if !response_ends && let Err(err) = pump(body, &mut send).await {
                    send.send_reset(err.reason().unwrap_or(Reason::CANCEL));
                }
            }
            Err(err) => tracing::debug!(error = %err, "the box reset the stream"),
        }
    };
    tokio::join!(request_half, response_half);
}

/// Copies DATA frames and then the trailers from `from` to `to`. It sends
/// only into the peer's window, and returns each frame's window to its
/// sender once the frame is on its way.
async fn pump(mut from: RecvStream, to: &mut SendStream<Bytes>) -> Result<(), h2::Error> {
    while let Some(chunk) = from.data().await {
        let mut chunk = chunk?;
        let received = chunk.len();
        while !chunk.is_empty() {
            to.reserve_capacity(chunk.len());
            let window = match std::future::poll_fn(|cx| to.poll_capacity(cx)).await {
                Some(window) => window?,
                None => return Err(h2::Error::from(Reason::CANCEL)),
            };
            if window == 0 {
                continue;
            }
            let piece = chunk.split_to(window.min(chunk.len()));
            to.send_data(piece, false)?;
        }
        from.flow_control().release_capacity(received)?;
    }
    match from.trailers().await? {
        Some(trailers) => to.send_trailers(trailers),
        None => to.send_data(Bytes::new(), true),
    }
}

/// Answers a stream the relay will not carry, with its marker as the body.
/// The decision has already written the audit record of a refused request.
fn refuse(respond: &mut h2::server::SendResponse<Bytes>, status: u16, marker: &str) {
    let Ok(response) = http::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(())
    else {
        respond.send_reset(Reason::INTERNAL_ERROR);
        return;
    };
    let text = format!("The Box Egress Proxy refused this request: {marker}.\n");
    match respond.send_response(response, false) {
        Ok(mut send) => {
            let _ = send.send_data(Bytes::from(text), true);
        }
        Err(err) => tracing::debug!(error = %err, "the box reset a refused stream"),
    }
}
